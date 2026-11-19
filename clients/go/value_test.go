// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package tsm

// Value: what a value message becomes, that no printable form shows the
// secret, and that Close overwrites the buffer.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func demoValue(t *testing.T, overrides object) *Value {
	t.Helper()
	m := valueMessage(nil, "demo-password")
	for k, v := range overrides {
		m[k] = v
	}
	v, err := valueFromMessage("db.main", normal(t, m).(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValueNeverPrinted(t *testing.T) {
	v := demoValue(t, nil)
	jsonForm, _ := json.Marshal(v)
	wrapped, _ := json.Marshal(object{"v": v})
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("read", "secret", v)
	for _, printed := range []string{
		fmt.Sprint(v), fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%d", v, v, v, v, v, v, v),
		string(jsonForm), string(wrapped), logged.String(),
	} {
		if !strings.Contains(printed, "***") || strings.Contains(printed, "demo-password") {
			t.Errorf("printed %s", printed)
		}
	}
}

func TestValueClose(t *testing.T) {
	v := demoValue(t, nil)
	data, _ := v.Bytes()
	if string(data) != "demo-password" {
		t.Fatalf("%q", data)
	}
	v.Close()
	if !v.Closed() {
		t.Error("not closed")
	}
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Error("Close left the buffer")
	}
	if _, err := v.Text(); !errors.Is(err, ErrClosed) {
		t.Errorf("%v", err)
	}
}

func TestBinaryValue(t *testing.T) {
	v := demoValue(t, object{"encoding": "base64", "value": "AAEC/w=="})
	data, _ := v.Bytes()
	if !bytes.Equal(data, []byte{0, 1, 2, 0xff}) {
		t.Errorf("%x", data)
	}
	if _, err := v.Text(); !errors.Is(err, ErrBinary) {
		t.Errorf("%v", err)
	}
}

func TestValueFields(t *testing.T) {
	v := demoValue(t, object{"expires": "2027-01-01T00:00:00+01:00", "clientToken": "demo-token"})
	if v.Expires == nil || v.Expires.Year() != 2026 || v.ClientToken != "demo-token" {
		t.Errorf("%v %q", v.Expires, v.ClientToken)
	}
	unknown := demoValue(t, object{"entry": object{"store": "s", "uuid": "u", "source": "relay", "fetchedAt": "2026-11-19T10:00:00Z"}})
	if unknown.Entry.Source != "cache" {
		t.Errorf("source %q", unknown.Entry.Source)
	}
}

func TestBadValueIsInternal(t *testing.T) {
	m := normal(t, valueMessage(nil, "x")).(map[string]any)
	m["version"] = nil
	_, err := valueFromMessage("x", m)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindInternal || e.Details["code"] != "bad_value" {
		t.Errorf("%v", err)
	}
}

func TestErrorKinds(t *testing.T) {
	if ErrorKindFromWire("brand_new") != KindInternal || ErrorKindFromWire("not_running") != KindInternal ||
		ErrorKindFromWire("denied") != KindDenied || ErrorKindFromWire(3) != KindInternal {
		t.Error("kinds")
	}
	wrapped := fmt.Errorf("reading: %w", &Error{Kind: KindLocked, Message: "locked"})
	if KindOf(wrapped) != KindLocked || KindOf(errors.New("x")) != "" {
		t.Error("KindOf")
	}
}
