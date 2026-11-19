// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package tsm

// The library against every vector of protocol/vectors/ that a client
// computes: references (parse, canonical form, malformed reasons,
// formatting), discovery and port files, and the frames of the client
// endpoint.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type object = map[string]any

func vectors(t *testing.T, name string) object {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "protocol", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	var v object
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// normal is v through JSON, so shapes built here compare with the vectors'.
func normal(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func shapeOf(r Reference) object {
	var target object
	switch r.Target.Kind {
	case TargetKey:
		target = object{"kind": "key", "key": r.Target.Key}
	case TargetUUID:
		target = object{"kind": "uuid", "store": r.Target.Store, "uuid": r.Target.UUID}
	default:
		target = object{"kind": "path", "store": r.Target.Store, "segments": append([]string{}, r.Target.Segments...)}
	}
	qualifiers := []any{}
	for _, q := range r.Qualifiers {
		qualifiers = append(qualifiers, object{"dimension": q.Dimension, "value": q.Value})
	}
	return object{"qualifiers": qualifiers, "target": target, "field": r.Field, "fieldGiven": r.FieldGiven}
}

func referenceOf(m object) Reference {
	t := m["target"].(object)
	var target Target
	switch t["kind"] {
	case "key":
		target = Target{Kind: TargetKey, Key: t["key"].(string)}
	case "uuid":
		target = Target{Kind: TargetUUID, Store: t["store"].(string), UUID: t["uuid"].(string)}
	default:
		var segments []string
		for _, s := range t["segments"].([]any) {
			segments = append(segments, s.(string))
		}
		target = Target{Kind: TargetPath, Store: t["store"].(string), Segments: segments}
	}
	var qualifiers []Binding
	for _, raw := range m["qualifiers"].([]any) {
		q := raw.(object)
		qualifiers = append(qualifiers, Binding{q["dimension"].(string), q["value"].(string)})
	}
	field, _ := m["field"].(string)
	return Reference{Target: target, Qualifiers: qualifiers, Field: field}
}

func TestReferences(t *testing.T) {
	v := vectors(t, "references.json")
	if int(v["maxReferenceBytes"].(float64)) != MaxReferenceBytes {
		t.Fatalf("maxReferenceBytes %v", v["maxReferenceBytes"])
	}
	for _, raw := range v["valid"].([]any) {
		c := raw.(object)
		input := c["input"].(string)
		r, err := ParseReference(input)
		if err != nil {
			t.Errorf("%q: %v", input, err)
			continue
		}
		if got := normal(t, shapeOf(r)); !reflect.DeepEqual(got, c["parsed"]) {
			t.Errorf("%q parsed %v, want %v", input, got, c["parsed"])
		}
		if r.Canonical() != c["canonical"] {
			t.Errorf("%q canonical %q, want %q", input, r.Canonical(), c["canonical"])
		}
		again, err := ParseReference(r.Canonical())
		if err != nil || again.Canonical() != r.Canonical() {
			t.Errorf("%q: the canonical form does not reparse to itself", input)
		}
	}
	for _, raw := range v["invalid"].([]any) {
		c := raw.(object)
		input := c["input"].(string)
		_, err := ParseReference(input)
		e, ok := err.(*Error)
		if !ok || e.Kind != KindMalformed || e.Reason() != c["reason"] {
			t.Errorf("%q: %v, want malformed %v", input, err, c["reason"])
		}
	}
	for _, raw := range v["format"].([]any) {
		c := raw.(object)
		formatted, err := FormatReference(referenceOf(c["parsed"].(object)))
		if err != nil || formatted != c["formatted"] {
			t.Errorf("formatted %q (%v), want %q", formatted, err, c["formatted"])
			continue
		}
		r, err := ParseReference(formatted)
		if err != nil || !reflect.DeepEqual(normal(t, shapeOf(r)), c["reparsed"]) {
			t.Errorf("%q reparsed %v (%v), want %v", formatted, shapeOf(r), err, c["reparsed"])
		}
	}
}

func TestDiscovery(t *testing.T) {
	v := vectors(t, "discovery.json")
	for _, raw := range v["cases"].([]any) {
		c := raw.(object)
		environment := map[string]string{}
		for k, value := range c["env"].(object) {
			environment[k] = value.(string)
		}
		uid := 0
		if u, ok := c["uid"].(float64); ok {
			uid = int(u)
		}
		endpoints, ok := Discover(c["os"].(string), environment, func() int { return uid })
		expect := c["expect"].(object)
		if !ok {
			if expect["notRunning"] != "no_runtime_directory" {
				t.Errorf("%v %v: not running, want %v", c["os"], c["env"], expect)
			}
			continue
		}
		client, admin := expect["client"].(object), expect["admin"].(object)
		str := func(m object, key string) string { s, _ := m[key].(string); return s }
		want := Endpoints{
			Directory:       expect["directory"].(string),
			ClientSocket:    str(client, "socket"),
			ClientPortFile:  str(client, "portFile"),
			ClientTokenFile: str(client, "tokenFile"),
			AdminSocket:     str(admin, "socket"),
			AdminPortFile:   str(admin, "portFile"),
		}
		if endpoints != want {
			t.Errorf("%v %v: %+v, want %+v", c["os"], c["env"], endpoints, want)
		}
	}
	for _, raw := range v["portFiles"].([]any) {
		c := raw.(object)
		port, ok := ReadPortFile(c["text"].(string))
		if c["port"] == nil {
			if ok {
				t.Errorf("%q: port %d, want none", c["text"], port)
			}
		} else if !ok || port != int(c["port"].(float64)) {
			t.Errorf("%q: port %d %v, want %v", c["text"], port, ok, c["port"])
		}
	}
}

func TestFrames(t *testing.T) {
	v := vectors(t, "frames.json")
	if int(v["protocol"].(float64)) != ProtocolVersion {
		t.Fatalf("protocol %v", v["protocol"])
	}
	for _, raw := range v["frames"].([]any) {
		c := raw.(object)
		data, _ := hex.DecodeString(c["hex"].(string))
		name := c["name"].(string)
		if int(c["type"].(float64)) == frameJSON {
			reader := frameReader{maxPayload: MaxAnswerPayload}
			frames, err := reader.add(data)
			if err != nil || len(frames) != 1 {
				t.Errorf("%s: %v %d frames", name, err, len(frames))
				continue
			}
			m, err := decodePayload(frames[0].payload)
			if err != nil || !reflect.DeepEqual(normal(t, m), c["json"]) {
				t.Errorf("%s: %v %v", name, m, err)
			}
			// Written again, it reads as the same message (member order is
			// free in JSON).
			payload, err := jsonPayload(m)
			if err != nil {
				t.Fatal(err)
			}
			back, err := decodePayload(payload)
			if err != nil || !reflect.DeepEqual(normal(t, back), c["json"]) {
				t.Errorf("%s: written again %s", name, payload)
			}
			continue
		}
		reader := frameReader{maxPayload: MaxAnswerPayload}
		if _, err := reader.add(data); err == nil {
			t.Errorf("%s: a binary frame read before binary was negotiated", name)
		}
		negotiated := frameReader{maxPayload: MaxAnswerPayload, binaryAllowed: true}
		frames, err := negotiated.add(data)
		if err != nil || len(frames) != 1 {
			t.Errorf("%s: %v", name, err)
			continue
		}
		p := frames[0].payload
		id := int64(0)
		for _, b := range p[:8] {
			id = id<<8 | int64(b)
		}
		if id != int64(c["requestId"].(float64)) || hex.EncodeToString(p[8:]) != c["chunkHex"] {
			t.Errorf("%s: id %d chunk %x", name, id, p[8:])
		}
	}
	for _, raw := range v["invalid"].([]any) {
		c := raw.(object)
		name := c["name"].(string)
		data, _ := hex.DecodeString(c["hex"].(string))
		max := MaxAnswerPayload
		if c["direction"] == "to service" {
			max = MaxRequestPayload
		}
		reader := frameReader{maxPayload: max}
		frames, err := reader.add(data)
		switch c["outcome"] {
		case "close":
			if err == nil {
				t.Errorf("%s: read", name)
			}
		case "read":
			if err != nil || len(frames) != 0 {
				t.Errorf("%s: %v %d frames", name, err, len(frames))
			}
		default: // malformed_close
			if err != nil || len(frames) != 1 {
				t.Errorf("%s: %v", name, err)
				continue
			}
			_, derr := decodePayload(frames[0].payload)
			if name == "a first frame that is not hello" {
				// Well-formed JSON: the order of frames is wrong, which
				// the service checks.
				if derr != nil {
					t.Errorf("%s: %v", name, derr)
				}
			} else if derr == nil {
				t.Errorf("%s: decoded", name)
			}
		}
	}
}

func TestSplitReads(t *testing.T) {
	data := encodeFrame(frameJSON, []byte(`{"op":"x"}`))
	reader := frameReader{maxPayload: MaxRequestPayload}
	if f, _ := reader.add(data[:3]); len(f) != 0 {
		t.Fatal("a frame from 3 bytes")
	}
	if f, _ := reader.add(data[3:8]); len(f) != 0 {
		t.Fatal("a frame from 8 bytes")
	}
	f, err := reader.add(append(append([]byte{}, data[8:]...), data...))
	if err != nil || len(f) != 2 {
		t.Fatalf("%v %d", err, len(f))
	}
}

func TestStrictJSON(t *testing.T) {
	for _, bad := range []string{
		"\xEF\xBB\xBF" + `{"op":"x"}`, `{"op":"x","op":"y"}`, `{"op":"x"} {}`,
		`{"op":"x","n":1e999}`, `{"op":1}`, `[]`, `{"op":"x","a":{"b":1,"b":2}}`,
	} {
		if _, err := decodePayload([]byte(bad)); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
}
