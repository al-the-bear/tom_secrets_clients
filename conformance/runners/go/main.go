// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The conformance runner of the Go client (module
// github.com/al-the-bear/tom_secrets_clients/clients/go).
//
// It reads one case per line on standard input,
//
//	{"case": name, "runtimeDir": dir, "action": {...}}
//
// runs its action with the library against the service in runtimeDir, and
// writes one canonical result line per case on standard output,
//
//	{"case": name, "result": {...}}
//
// (keys sorted, compact). conformance/README.md defines the actions and the
// result shapes every runner writes. concurrent actions run on goroutines,
// overlapping on the client's one connection.
//
// It has no go.mod: runner.json builds it inside the client's module
// (go -C ../clients/go build ... this file), so it imports the library as
// it is in the repository.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	tsm "github.com/al-the-bear/tom_secrets_clients/clients/go"
)

type object = map[string]any

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var request object
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&request); err != nil {
			fmt.Fprintln(os.Stderr, "runner: bad case line:", err)
			os.Exit(2)
		}
		result := runCase(request["runtimeDir"].(string), request["action"].(object))
		out.WriteString(canonical(object{"case": request["case"], "result": result}) + "\n")
		out.Flush()
	}
}

func runCase(runtimeDir string, action object) object {
	environment := map[string]string{}
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 {
			environment[kv[:i]] = kv[i+1:]
		}
	}
	environment["TSM_RUNTIME_DIR"] = runtimeDir
	options := []tsm.Option{
		tsm.WithClientName("conformance-runner"),
		tsm.WithEnvironment(environment),
		tsm.WithConnectTimeout(5 * time.Second),
	}
	if client, ok := action["client"].(object); ok {
		if token, ok := client["clientToken"].(string); ok {
			options = append(options, tsm.WithClientToken(token))
		}
	}
	c := tsm.New(options...)
	defer c.Close()
	return run(c, action)
}

func run(c *tsm.Client, action object) object {
	ctx := context.Background()
	switch action["do"] {
	case "parse":
		r, err := tsm.ParseReference(action["ref"].(string))
		if err != nil {
			return errorResult(err)
		}
		return object{"parsed": shape(r), "canonical": r.Canonical()}
	case "format":
		formatted, err := tsm.FormatReference(fromShape(action["parsed"].(object)))
		if err != nil {
			return errorResult(err)
		}
		return object{"formatted": formatted}
	case "connect":
		if err := c.Open(ctx); err != nil {
			return errorResult(err)
		}
		w := c.Welcome()
		features := append([]string{}, w.Features...)
		return object{"welcome": object{"host": w.Host, "platform": w.Platform, "features": features}}
	case "get":
		var progress progressLog
		options := waiting(action, &progress)
		if field, ok := action["field"].(string); ok {
			options = append(options, tsm.WithField(field))
		}
		if dimensions, ok := action["dimensions"].(object); ok {
			options = append(options, tsm.WithDimensions(stringMap(dimensions)))
		}
		if action["wantClientToken"] == true {
			options = append(options, tsm.WithClientTokenRequest())
		}
		if action["waitOnRateLimit"] == true {
			options = append(options, tsm.WaitOnRateLimit())
		}
		v, err := c.Get(ctx, action["ref"].(string), options...)
		result := object{}
		if err != nil {
			result = errorResult(err)
		} else {
			result["value"] = valueShape(v)
		}
		return progress.addTo(result)
	case "getMany":
		var progress progressLog
		var requests []tsm.Request
		for _, raw := range action["refs"].([]any) {
			r := raw.(object)
			request := tsm.Request{Ref: r["ref"].(string)}
			if field, ok := r["field"].(string); ok {
				request.Field = field
			}
			if dimensions, ok := r["dimensions"].(object); ok {
				request.Dimensions = stringMap(dimensions)
			}
			requests = append(requests, request)
		}
		results, err := c.GetMany(ctx, requests, waiting(action, &progress)...)
		result := object{}
		if err != nil {
			result = errorResult(err)
		} else {
			list := []any{}
			for _, r := range results {
				if r.Err != nil {
					list = append(list, object{"error": errorShape(r.Err)})
				} else {
					list = append(list, object{"value": valueShape(r.Value)})
				}
			}
			result["results"] = list
		}
		return progress.addTo(result)
	case "getFile":
		var options []tsm.RequestOption
		if field, ok := action["field"].(string); ok {
			options = append(options, tsm.WithField(field))
		}
		f, err := c.GetFile(ctx, action["ref"].(string), options...)
		if err != nil {
			return errorResult(err)
		}
		defer f.Close()
		data, _ := f.Bytes()
		return object{"file": object{
			"name": f.Name, "size": f.Size(),
			"base64": base64.StdEncoding.EncodeToString(data),
		}}
	case "concurrent":
		actions := action["actions"].([]any)
		results := make([]any, len(actions))
		var wg sync.WaitGroup
		for i, a := range actions {
			wg.Add(1)
			go func(i int, a object) {
				defer wg.Done()
				results[i] = run(c, a)
			}(i, a.(object))
		}
		wg.Wait()
		return object{"results": results}
	case "sequence":
		steps := []any{}
		for _, raw := range action["actions"].([]any) {
			step := raw.(object)
			if step["do"] == "pause" {
				ms, _ := step["ms"].(json.Number).Int64()
				time.Sleep(time.Duration(ms) * time.Millisecond)
				continue
			}
			steps = append(steps, run(c, step))
		}
		return object{"steps": steps}
	}
	return object{"unsupportedAction": action["do"]}
}

// waiting are the options wait and timeoutMs of an action, and the
// progress notices collected into progress.
func waiting(action object, progress *progressLog) []tsm.RequestOption {
	options := []tsm.RequestOption{tsm.WithProgress(progress.add)}
	if action["wait"] == false {
		options = append(options, tsm.NoWait())
	}
	if ms, ok := action["timeoutMs"].(json.Number); ok {
		n, _ := ms.Int64()
		options = append(options, tsm.WithTimeout(time.Duration(n)*time.Millisecond))
	}
	return options
}

type progressLog struct {
	mu      sync.Mutex
	entries []any
}

func (l *progressLog) add(p tsm.Progress) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := object{"pending": p.Pending}
	if p.ApprovalCode != "" {
		entry["approvalCode"] = p.ApprovalCode
	}
	l.entries = append(l.entries, entry)
}

func (l *progressLog) addTo(result object) object {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) > 0 {
		result["progress"] = l.entries
	}
	return result
}

func stringMap(m object) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v.(string)
	}
	return out
}

func errorResult(err error) object { return object{"error": errorShape(err)} }

func errorShape(err error) object {
	var e *tsm.Error
	if !errors.As(err, &e) {
		// Not the library's error type: a runner bug or a plain error.
		return object{"kind": "runner", "reason": err.Error()}
	}
	out := object{"kind": string(e.Kind)}
	if r := e.Reason(); r != "" {
		out["reason"] = r
	}
	return out
}

func valueShape(v *tsm.Value) object {
	text, err := v.Text()
	refused := errors.Is(err, tsm.ErrBinary)
	data, _ := v.Bytes()
	jsonForm, _ := json.Marshal(v)
	printed := []string{
		fmt.Sprint(v), fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v),
		fmt.Sprintf("%s", v), fmt.Sprintf("%q", v), fmt.Sprintf("%x", v), v.String(),
		string(jsonForm),
	}
	// Every printable form shows *** and never the value (README, Results);
	// a value that occurs in the reference cannot be told apart.
	masked := true
	for _, p := range printed {
		if !strings.Contains(p, "***") ||
			(!refused && !strings.Contains(v.Reference, text) && strings.Contains(p, text)) {
			masked = false
		}
	}
	bound := object{}
	for k, b := range v.Bound {
		bound[k] = b
	}
	out := object{
		"encoding": v.Encoding,
		"base64":   base64.StdEncoding.EncodeToString(data),
		"entry": object{
			"store":       v.Entry.Store,
			"uuid":        v.Entry.UUID,
			"source":      v.Entry.Source,
			"fetchedAtMs": v.Entry.FetchedAt.UnixMilli(),
		},
		"bound": bound,
		"version": object{
			"modifiedMs": v.Version.Modified.UnixMilli(),
			"revision":   v.Version.Revision,
		},
		"masked": masked,
	}
	if refused {
		out["textRefused"] = true
	} else {
		out["text"] = text
	}
	if v.Expires != nil {
		out["expiresMs"] = v.Expires.UnixMilli()
	}
	if v.ClientToken != "" {
		out["clientToken"] = v.ClientToken
	}
	v.Close()
	return out
}

func shape(r tsm.Reference) object {
	var target object
	switch r.Target.Kind {
	case tsm.TargetKey:
		target = object{"kind": "key", "key": r.Target.Key}
	case tsm.TargetUUID:
		target = object{"kind": "uuid", "store": r.Target.Store, "uuid": r.Target.UUID}
	default:
		segments := append([]string{}, r.Target.Segments...)
		target = object{"kind": "path", "store": r.Target.Store, "segments": segments}
	}
	qualifiers := []any{}
	for _, q := range r.Qualifiers {
		qualifiers = append(qualifiers, object{"dimension": q.Dimension, "value": q.Value})
	}
	return object{"qualifiers": qualifiers, "target": target, "field": r.Field, "fieldGiven": r.FieldGiven}
}

func fromShape(m object) tsm.Reference {
	t := m["target"].(object)
	var target tsm.Target
	switch t["kind"] {
	case "key":
		target = tsm.Target{Kind: tsm.TargetKey, Key: t["key"].(string)}
	case "uuid":
		target = tsm.Target{Kind: tsm.TargetUUID, Store: t["store"].(string), UUID: t["uuid"].(string)}
	default:
		var segments []string
		for _, s := range t["segments"].([]any) {
			segments = append(segments, s.(string))
		}
		target = tsm.Target{Kind: tsm.TargetPath, Store: t["store"].(string), Segments: segments}
	}
	var qualifiers []tsm.Binding
	for _, raw := range m["qualifiers"].([]any) {
		q := raw.(object)
		qualifiers = append(qualifiers, tsm.Binding{Dimension: q["dimension"].(string), Value: q["value"].(string)})
	}
	field, _ := m["field"].(string)
	if field == "" {
		field = tsm.DefaultField
	}
	return tsm.Reference{Target: target, Qualifiers: qualifiers, Field: field}
}

func canonical(value any) string {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		panic(err)
	}
	return strings.TrimSuffix(b.String(), "\n")
}
