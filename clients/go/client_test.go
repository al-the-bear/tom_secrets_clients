// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package tsm

// The client against a small service in the test, on a Unix socket: hello
// and welcome, get with progress and a rate limit, getMany, getFile over
// binary frames, a cancelled context, a dropped connection, values that
// never print. The full behaviour is the conformance suite's
// (conformance/README.md).

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeService struct {
	t        *testing.T
	dir      string
	listener net.Listener
	features []string

	mu      sync.Mutex
	hellos  []object
	limited int
	conns   []net.Conn
}

func newFakeService(t *testing.T, features ...string) *fakeService {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the Windows endpoint is TCP")
	}
	// The system's temporary folder: a Unix socket's path is short.
	dir, err := os.MkdirTemp("", "tsm-test-")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(dir, "client.sock"))
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeService{t: t, dir: dir, listener: listener, features: features}
	t.Cleanup(func() {
		listener.Close()
		s.dropAll()
		os.RemoveAll(dir)
	})
	go s.accept()
	return s
}

func (s *fakeService) client(options ...Option) *Client {
	options = append([]Option{WithClientName("unit-test"),
		WithEnvironment(map[string]string{"TSM_RUNTIME_DIR": s.dir})}, options...)
	c := New(options...)
	s.t.Cleanup(func() { c.Close() })
	return c
}

func (s *fakeService) dropAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = nil
}

func (s *fakeService) accept() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()
		go s.serve(conn)
	}
}

func (s *fakeService) serve(conn net.Conn) {
	var writeMu sync.Mutex
	send := func(frameType byte, payload []byte) {
		writeMu.Lock()
		defer writeMu.Unlock()
		conn.Write(encodeFrame(frameType, payload))
	}
	sendJSON := func(m object) {
		payload, _ := json.Marshal(m)
		send(frameJSON, payload)
	}
	reader := frameReader{maxPayload: MaxRequestPayload}
	buffer := make([]byte, 65536)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}
		frames, err := reader.add(buffer[:n])
		if err != nil {
			conn.Close()
			return
		}
		for _, f := range frames {
			m, err := decodePayload(f.payload)
			if err != nil {
				conn.Close()
				return
			}
			go s.answer(m, sendJSON, send)
		}
	}
}

func valueMessage(id any, value string) object {
	return object{
		"op": "value", "id": id, "value": value,
		"entry":   object{"store": "demo", "uuid": "8f1c0f0e000040008000000000000002", "source": "file", "fetchedAt": "2026-11-19T10:00:00Z"},
		"bound":   object{"env": "prod"},
		"version": object{"modified": "2026-11-19T09:00:00.250+01:00", "revision": "r1"},
	}
}

func (s *fakeService) answer(m message, sendJSON func(object), send func(byte, []byte)) {
	id := m["id"]
	switch m["op"] {
	case "hello":
		s.mu.Lock()
		s.hellos = append(s.hellos, m)
		s.mu.Unlock()
		sendJSON(object{"op": "welcome", "protocol": 1, "service": object{"version": "0.0.0-test"},
			"features": s.features, "host": "testhost", "platform": "macos"})
	case "get":
		switch ref := m["ref"].(string); ref {
		case "missing.entry":
			sendJSON(object{"op": "error", "id": id, "kind": "not_found", "message": "no entry",
				"details": object{"reason": "no_entry"}})
		case "slow.entry":
			sendJSON(object{"op": "progress", "id": id, "pending": "approval", "approvalCode": "123-456"})
			time.Sleep(20 * time.Millisecond)
			sendJSON(valueMessage(id, "slow-secret"))
		case "limited.entry":
			s.mu.Lock()
			s.limited++
			first := s.limited == 1
			s.mu.Unlock()
			if first {
				sendJSON(object{"op": "error", "id": id, "kind": "rate_limited", "message": "slow down",
					"details": object{"retryAfterMs": 10}})
				return
			}
			sendJSON(valueMessage(id, "limited-secret"))
		case "hang.entry":
			// never answered
		case "drop.entry":
			s.dropAll()
		default:
			v := valueMessage(id, "secret-of-"+ref)
			if field, ok := m["field"].(string); ok {
				v["value"] = "secret-of-" + ref + "#" + field
			}
			sendJSON(v)
		}
	case "getMany":
		results := []any{}
		for _, raw := range m["refs"].([]any) {
			ref := raw.(map[string]any)["ref"].(string)
			if ref == "missing.entry" {
				results = append(results, object{"op": "error", "kind": "not_found", "message": "no entry"})
			} else {
				v := valueMessage(nil, "secret-of-"+ref)
				delete(v, "id")
				results = append(results, v)
			}
		}
		sendJSON(object{"op": "values", "id": id, "results": results})
	case "getFile":
		content := []byte("-----BEGIN DEMO KEY-----\nnot a real key\n-----END DEMO KEY-----\n")
		number, _ := intOf(id)
		sendJSON(object{"op": "file", "id": id, "name": "demo.pem", "size": len(content)})
		for start := 0; start < len(content); start += 16 {
			chunk := make([]byte, 8, 8+16)
			binary.BigEndian.PutUint64(chunk, uint64(number))
			chunk = append(chunk, content[start:min(start+16, len(content))]...)
			send(frameBinary, chunk)
		}
		sum := sha256.Sum256(content)
		sendJSON(object{"op": "end", "id": id, "sha256": hex.EncodeToString(sum[:])})
	}
}

func TestGetAndHello(t *testing.T) {
	s := newFakeService(t)
	c := s.client()
	ctx := context.Background()
	v, err := c.Get(ctx, "db.main", WithField("UserName"))
	if err != nil {
		t.Fatal(err)
	}
	text, _ := v.Text()
	if text != "secret-of-db.main#UserName" || v.Entry.Source != "file" || v.Bound["env"] != "prod" {
		t.Errorf("%q %+v %v", text, v.Entry, v.Bound)
	}
	if want := time.Date(2026, 11, 19, 8, 0, 0, 250e6, time.UTC); !v.Version.Modified.Equal(want) {
		t.Errorf("modified %v", v.Version.Modified)
	}
	if w := c.Welcome(); w == nil || w.Host != "testhost" || w.ServiceVersion != "0.0.0-test" {
		t.Errorf("welcome %+v", w)
	}
	s.mu.Lock()
	hello := s.hellos[0]
	s.mu.Unlock()
	client := hello["client"].(map[string]any)
	if client["name"] != "unit-test" || client["language"] != "go" || client["version"] != ClientVersion {
		t.Errorf("hello %v", hello)
	}
	if fmt.Sprint(hello["features"]) != "[binary getFile]" {
		t.Errorf("features %v", hello["features"])
	}
}

func TestConcurrentGets(t *testing.T) {
	s := newFakeService(t)
	c := s.client()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ref := fmt.Sprintf("k%d.entry", i)
			v, err := c.Get(context.Background(), ref)
			if err != nil {
				errs <- err
				return
			}
			if text, _ := v.Text(); text != "secret-of-"+ref {
				errs <- fmt.Errorf("%s got %q", ref, text)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hellos) != 1 {
		t.Errorf("%d connections, want 1", len(s.hellos))
	}
}

func TestProgressAndRateLimit(t *testing.T) {
	s := newFakeService(t)
	c := s.client()
	var progress []Progress
	v, err := c.Get(context.Background(), "slow.entry", WithProgress(func(p Progress) { progress = append(progress, p) }))
	if err != nil {
		t.Fatal(err)
	}
	if len(progress) != 1 || progress[0] != (Progress{"approval", "123-456"}) {
		t.Errorf("progress %v", progress)
	}
	v.Close()
	if _, err := c.Get(context.Background(), "limited.entry"); KindOf(err) != KindRateLimited {
		t.Errorf("without WaitOnRateLimit: %v", err)
	}
	v, err = c.Get(context.Background(), "limited.entry", WaitOnRateLimit())
	if err != nil {
		t.Fatal(err)
	}
	if text, _ := v.Text(); text != "limited-secret" {
		t.Errorf("%q", text)
	}
}

func TestErrors(t *testing.T) {
	s := newFakeService(t)
	c := s.client()
	_, err := c.Get(context.Background(), "missing.entry")
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindNotFound || e.Reason() != "no_entry" {
		t.Errorf("%v", err)
	}
	// Refused locally, without a round trip.
	_, err = c.Get(context.Background(), "Bad Key")
	if KindOf(err) != KindMalformed {
		t.Errorf("%v", err)
	}
	_, err = c.Get(context.Background(), "fleet/Db/Main#UserName", WithField("Password"))
	if !errors.As(err, &e) || e.Reason() != "field_twice" {
		t.Errorf("%v", err)
	}
	_, err = c.Get(context.Background(), "db.main", WithDimensions(map[string]string{"env": strings.Repeat("x", MaxRequestPayload)}))
	if !errors.As(err, &e) || e.Reason() != "frame" {
		t.Errorf("%v", err)
	}
}

func TestGetMany(t *testing.T) {
	s := newFakeService(t)
	c := s.client()
	results, err := c.GetMany(context.Background(), []Request{{Ref: "a.entry"}, {Ref: "missing.entry"}})
	if err != nil {
		t.Fatal(err)
	}
	if text, _ := results[0].Value.Text(); text != "secret-of-a.entry" || KindOf(results[1].Err) != KindNotFound {
		t.Errorf("%v", results)
	}
	if _, err := c.GetMany(context.Background(), nil); err == nil || KindOf(err) != "" {
		t.Errorf("no references: %v", err)
	}
	if _, err := c.GetMany(context.Background(), []Request{{Ref: "a.entry"}}, WithField("x")); err == nil {
		t.Error("WithField on GetMany taken")
	}
}

func TestGetFile(t *testing.T) {
	s := newFakeService(t, "binary", "getFile")
	c := s.client()
	f, err := c.GetFile(context.Background(), "fleet/Ssh/Deploy#demo.pem")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := f.Bytes()
	if f.Name != "demo.pem" || !strings.Contains(string(data), "not a real key") {
		t.Errorf("%s %q", f.Name, data)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %s", f, f, f), "real key") {
		t.Error("the file's bytes printed")
	}
	f.Close()
	if _, err := f.Bytes(); !errors.Is(err, ErrClosed) {
		t.Errorf("%v", err)
	}
	for _, b := range data {
		if b != 0 {
			t.Fatal("Close left the bytes")
		}
	}

	plain := newFakeService(t)
	_, err = plain.client().GetFile(context.Background(), "fleet/Ssh/Deploy#demo.pem")
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindUnsupported || fmt.Sprint(e.Details["features"]) != "[binary getFile]" {
		t.Errorf("%v %v", err, e)
	}
}

func TestCancelledContext(t *testing.T) {
	s := newFakeService(t)
	c := s.client()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := c.Get(ctx, "hang.entry"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("%v", err)
	}
	// The connection stays usable.
	if _, err := c.Get(context.Background(), "after.entry"); err != nil {
		t.Error(err)
	}
}

func TestDroppedConnection(t *testing.T) {
	s := newFakeService(t)
	c := s.client()
	if _, err := c.Get(context.Background(), "drop.entry"); KindOf(err) != KindNotRunning {
		t.Errorf("%v", err)
	}
	// The next call connects again.
	if _, err := c.Get(context.Background(), "again.entry"); err != nil {
		t.Error(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hellos) != 2 {
		t.Errorf("%d hellos", len(s.hellos))
	}
}

func TestNotRunning(t *testing.T) {
	dir := t.TempDir()
	c := New(WithEnvironment(map[string]string{"TSM_RUNTIME_DIR": dir}), WithOperatingSystem("linux"))
	if _, err := Connect(context.Background(), WithEnvironment(map[string]string{"TSM_RUNTIME_DIR": dir})); KindOf(err) != KindNotRunning {
		t.Errorf("%v", err)
	}
	if _, err := c.Get(context.Background(), "db.main"); KindOf(err) != KindNotRunning {
		t.Errorf("%v", err)
	}
	empty := New(WithOperatingSystem("windows"), WithEnvironment(map[string]string{}))
	if err := empty.Open(context.Background()); KindOf(err) != KindNotRunning {
		t.Errorf("%v", err)
	}
}
