// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package tsm

import (
	"errors"
	"fmt"
)

// ErrorKind says what went wrong: the protocol's kinds (protocol.md
// section 10) plus [KindNotRunning], which the library reports when it
// finds no service or loses the connection.
type ErrorKind string

// The error kinds.
const (
	KindLocked       ErrorKind = "locked"
	KindDenied       ErrorKind = "denied"
	KindNotFound     ErrorKind = "not_found"
	KindAmbiguous    ErrorKind = "ambiguous"
	KindNeedsUnlock  ErrorKind = "needs_unlock"
	KindUnavailable  ErrorKind = "unavailable"
	KindOffline      ErrorKind = "offline"
	KindTokenExpired ErrorKind = "token_expired"
	KindMalformed    ErrorKind = "malformed"
	KindTimeout      ErrorKind = "timeout"
	KindRateLimited  ErrorKind = "rate_limited"
	KindUnsupported  ErrorKind = "unsupported"
	KindInternal     ErrorKind = "internal"
	KindNotRunning   ErrorKind = "not_running"
)

var wireKinds = map[ErrorKind]bool{
	KindLocked: true, KindDenied: true, KindNotFound: true,
	KindAmbiguous: true, KindNeedsUnlock: true, KindUnavailable: true,
	KindOffline: true, KindTokenExpired: true, KindMalformed: true,
	KindTimeout: true, KindRateLimited: true, KindUnsupported: true,
	KindInternal: true,
}

// ErrorKindFromWire maps the kind an error message names: an unknown kind
// (from a later service) is [KindInternal]; not_running is never the
// service's to send.
func ErrorKindFromWire(kind any) ErrorKind {
	if s, ok := kind.(string); ok && wireKinds[ErrorKind(s)] {
		return ErrorKind(s)
	}
	return KindInternal
}

// Error is every failure the library reports from the service or about it.
// Use it with [errors.As]:
//
//	var e *tsm.Error
//	if errors.As(err, &e) && e.Kind == tsm.KindLocked { ... }
//
// The message never holds a value, token or key. A cancelled or expired
// context is reported as the context's own error instead, and a call the
// program gets wrong (a GetMany of no references) as a plain error.
type Error struct {
	// Kind says what went wrong.
	Kind ErrorKind
	// Message is for people.
	Message string
	// Details are the error's details (reason, candidates, retryAfterMs,
	// ...); numbers in them are json.Number.
	Details map[string]any
}

// Error implements error.
func (e *Error) Error() string {
	if r := e.Reason(); r != "" {
		return fmt.Sprintf("tsm: %s (%s): %s", e.Kind, r, e.Message)
	}
	return fmt.Sprintf("tsm: %s: %s", e.Kind, e.Message)
}

// Reason is details.reason, or "" when there is none.
func (e *Error) Reason() string {
	r, _ := e.Details["reason"].(string)
	return r
}

// KindOf is the kind of err when it is (or wraps) an [*Error], else "".
func KindOf(err error) ErrorKind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

func errorFromMessage(m map[string]any) *Error {
	details, _ := m["details"].(map[string]any)
	if details == nil {
		details = map[string]any{}
	}
	message, _ := m["message"].(string)
	return &Error{ErrorKindFromWire(m["kind"]), message, details}
}

func notRunning(why string) *Error {
	return &Error{KindNotRunning, "the secrets service is not running: " + why, map[string]any{}}
}

func protocolError(why string) *Error {
	return &Error{KindInternal, "the service broke the protocol: " + why, map[string]any{"code": "protocol"}}
}

func malformed(reason, message string) *Error {
	return &Error{KindMalformed, message, map[string]any{"reason": reason}}
}
