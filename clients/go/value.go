// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package tsm

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"
)

// Entry is the entry a value was read from: its store and KDBX UUID, where
// the service read it ("github", "file" or "cache"), and the last
// successful fetch of the store.
type Entry struct {
	Store     string
	UUID      string
	Source    string
	FetchedAt time.Time
}

// Version is the entry's last modification and the store file revision it
// was read from; a caller caching a value compares it to see a change.
type Version struct {
	Modified time.Time
	Revision string
}

// Value is a secret (protocol.md 5.2). No printable form shows it: fmt's
// verbs, encoding/json and log/slog give "SecretValue(<ref>: ***)". Close
// overwrites its buffer. A string the caller takes out with Text is an
// immutable Go string the library cannot overwrite: the caller handles it.
type Value struct {
	// Reference is the reference the value was asked for, as given.
	Reference string
	// Encoding is how the service sent it: "utf8" (text) or "base64"
	// (bytes).
	Encoding string
	// Entry is the entry it was read from.
	Entry Entry
	// Bound are the bindings the winning entry carries, dimension → value.
	Bound map[string]string
	// Version is the entry's version.
	Version Version
	// Expires is the entry's expiry, or nil.
	Expires *time.Time
	// ClientToken is the client token the service granted when one was
	// asked for, else "": the caller's to keep (7.4); the library never
	// stores it.
	ClientToken string

	mu     sync.Mutex
	data   []byte
	closed bool
}

// ErrClosed is returned by reading a [Value] or [File] after Close.
var ErrClosed = errors.New("tsm: the secret was closed")

// ErrBinary is returned by [Value.Text] for a binary value: read it with
// Bytes rather than decode it into a corrupt string.
var ErrBinary = errors.New("tsm: the value is binary: read it with Bytes, not Text")

var (
	base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	timePattern   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$`)
)

// parseTime reads an RFC 3339 time (fractions and offsets allowed) as UTC.
func parseTime(v any) (time.Time, error) {
	s, ok := v.(string)
	if !ok || !timePattern.MatchString(s) {
		return time.Time{}, errors.New("not a date")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// sourceFromWire is the source a protocol source names; an unknown one is
// "cache" (section 8: the most general one known, no claim to be fresh).
func sourceFromWire(v any) string {
	if s, _ := v.(string); s == "github" || s == "file" {
		return s
	}
	return "cache"
}

func badValue() *Error {
	return &Error{KindInternal, "the service sent a value message this library cannot read",
		map[string]any{"code": "bad_value"}}
}

// valueFromMessage is the value of a value message (or a values result).
func valueFromMessage(reference string, m message) (*Value, error) {
	raw, ok := m["value"].(string)
	entry, ok2 := m["entry"].(map[string]any)
	version, ok3 := m["version"].(map[string]any)
	if !ok || !ok2 || !ok3 {
		return nil, badValue()
	}
	v := &Value{Reference: reference, Encoding: "utf8", Bound: map[string]string{}}
	if bound, isMap := m["bound"].(map[string]any); isMap {
		for k, b := range bound {
			s, isString := b.(string)
			if !isString {
				return nil, badValue()
			}
			v.Bound[k] = s
		}
	}
	if m["encoding"] == "base64" {
		v.Encoding = "base64"
		if !base64Pattern.MatchString(raw) {
			return nil, badValue()
		}
		data, err := base64.RawStdEncoding.DecodeString(stripPadding(raw))
		if err != nil {
			return nil, badValue()
		}
		v.data = data
	} else {
		v.data = []byte(raw)
	}
	store, ok := entry["store"].(string)
	uuid, ok2 := entry["uuid"].(string)
	revision, ok3 := version["revision"].(string)
	fetched, err := parseTime(entry["fetchedAt"])
	modified, err2 := parseTime(version["modified"])
	if !ok || !ok2 || !ok3 || err != nil || err2 != nil {
		return nil, badValue()
	}
	v.Entry = Entry{store, uuid, sourceFromWire(entry["source"]), fetched}
	v.Version = Version{modified, revision}
	if expires, isString := m["expires"].(string); isString {
		t, err := parseTime(expires)
		if err != nil {
			return nil, badValue()
		}
		v.Expires = &t
	}
	if token, isString := m["clientToken"].(string); isString {
		v.ClientToken = token
	}
	return v, nil
}

func stripPadding(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}

// Text is the value as text; [ErrBinary] for a binary value, [ErrClosed]
// after Close.
func (v *Value) Text() (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return "", ErrClosed
	}
	if v.Encoding == "base64" {
		return "", ErrBinary
	}
	return string(v.data), nil
}

// Bytes is the value as bytes (text as its UTF-8): the buffer itself, which
// Close overwrites; copy it to keep it. [ErrClosed] after Close.
func (v *Value) Bytes() ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, ErrClosed
	}
	return v.data, nil
}

// Close overwrites the buffer with zeros; the value cannot be read
// afterwards. It always returns nil.
func (v *Value) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(v.data)
	v.closed = true
	return nil
}

// Closed says whether Close was called.
func (v *Value) Closed() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.closed
}

// String is "SecretValue(<ref>: ***)", never the secret.
func (v *Value) String() string { return fmt.Sprintf("SecretValue(%s: ***)", v.Reference) }

// GoString masks %#v as String does.
func (v *Value) GoString() string { return v.String() }

// Format masks every fmt verb (%v, %+v, %s, %q, %x, ...).
func (v *Value) Format(f fmt.State, verb rune) { maskedFormat(f, verb, v.String()) }

// MarshalJSON writes the masked string, never the secret.
func (v *Value) MarshalJSON() ([]byte, error) { return marshalString(v.String()) }

// LogValue masks the value in log/slog.
func (v *Value) LogValue() slog.Value { return slog.StringValue(v.String()) }

// File is an attachment or a typed key read with GetFile (5.5): its name
// and bytes. Its printable forms never show the bytes, and Close
// overwrites them.
type File struct {
	// Reference is the reference the file was asked for, as given.
	Reference string
	// Name is the field's name (an attachment's file name).
	Name string

	mu     sync.Mutex
	data   []byte
	closed bool
}

// Size is the size in bytes.
func (f *File) Size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.data)
}

// Bytes is the file's bytes: the buffer itself, which Close overwrites.
// [ErrClosed] after Close.
func (f *File) Bytes() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, ErrClosed
	}
	return f.data, nil
}

// Close overwrites the bytes with zeros. It always returns nil.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	clear(f.data)
	f.closed = true
	return nil
}

// String names the file and its size, never its bytes.
func (f *File) String() string {
	return fmt.Sprintf("SecretFile(%s: %s, %d bytes)", f.Reference, f.Name, f.Size())
}

// GoString masks %#v as String does.
func (f *File) GoString() string { return f.String() }

// Format masks every fmt verb.
func (f *File) Format(s fmt.State, verb rune) { maskedFormat(s, verb, f.String()) }

// MarshalJSON writes the masked string, never the bytes.
func (f *File) MarshalJSON() ([]byte, error) { return marshalString(f.String()) }

// LogValue masks the file in log/slog.
func (f *File) LogValue() slog.Value { return slog.StringValue(f.String()) }

func maskedFormat(f fmt.State, verb rune, masked string) {
	if verb == 'q' {
		fmt.Fprintf(f, "%q", masked)
		return
	}
	fmt.Fprint(f, masked)
}

func marshalString(s string) ([]byte, error) { return json.Marshal(s) }

// Progress is a progress notice (5.4): why a request waits, "unlock" (the
// service is locked and an admin was told) or "approval" (the request went
// to approval), with the one-time approval code on a host with no approver
// connected (7.5), else "".
type Progress struct {
	Pending      string
	ApprovalCode string
}

// Request is one reference of a GetMany: the reference, the field when the
// reference names none, and values for dimensions beside it.
type Request struct {
	Ref        string
	Field      string
	Dimensions map[string]string
}

// Result is one result of a GetMany, in request order: a Value or an Err
// (an [*Error]).
type Result struct {
	Value *Value
	Err   error
}
