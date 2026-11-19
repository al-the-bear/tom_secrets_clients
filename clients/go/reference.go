// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package tsm

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The reference grammar (protocol.md section 4).
const (
	// DefaultField is the field a reference without #field names.
	DefaultField = "Password"
	// MaxReferenceBytes is the longest reference, in bytes of UTF-8.
	MaxReferenceBytes = 1024
)

const reservedCharacters = "/#[],:%"

var (
	namePattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	storePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	uuidPattern  = regexp.MustCompile(`^~[0-9A-Fa-f]{32}$`)
)

// TargetKind says what a reference names.
type TargetKind string

// The target kinds.
const (
	// TargetKey is a key: the value of an entry's tsm.key field
	// (telegram.bot_token).
	TargetKey TargetKind = "key"
	// TargetPath is a store, the group path below its root group and the
	// entry title, each segment unescaped.
	TargetPath TargetKind = "path"
	// TargetUUID is an entry of a store by its KDBX UUID (lower case).
	TargetUUID TargetKind = "uuid"
)

// Target is what a reference names: Key for [TargetKey], Store and Segments
// for [TargetPath], Store and UUID for [TargetUUID].
type Target struct {
	Kind     TargetKind
	Key      string
	Store    string
	Segments []string
	UUID     string
}

// Binding is one binding <dimension>:<value> of a reference's qualifiers.
type Binding struct {
	Dimension string
	Value     string
}

// Reference is a parsed reference. [ParseReference] refuses a malformed one
// with an [*Error] of [KindMalformed] whose Reason is the rule of
// protocol.md 4.6 it broke; [FormatReference] gives the canonical form
// (4.5).
type Reference struct {
	Target Target
	// Qualifiers are the bindings in the order written.
	Qualifiers []Binding
	// Field is the effective field: [DefaultField] when none is written.
	Field string
	// FieldGiven says whether a field was written.
	FieldGiven bool
}

// Canonical is the canonical form, or "" for a reference that cannot be
// formatted (see [FormatReference]).
func (r Reference) Canonical() string {
	s, err := FormatReference(r)
	if err != nil {
		return ""
	}
	return s
}

// String is the canonical form.
func (r Reference) String() string { return r.Canonical() }

func refMalformed(reason, detail string) *Error {
	message := "the reference is malformed: " + reason
	if detail != "" {
		message += " (" + detail + ")"
	}
	return malformed(reason, message)
}

// ParseReference parses a reference (protocol.md 4.1-4.4, 4.6).
func ParseReference(reference string) (Reference, error) {
	if len(reference) > MaxReferenceBytes {
		return Reference{}, refMalformed("too_long", "")
	}
	if reference == "" {
		return Reference{}, refMalformed("empty", "")
	}
	rest := reference
	var qualifiers []Binding
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return Reference{}, refMalformed("unclosed_qualifiers", "")
		}
		body := rest[1:end]
		rest = rest[end+1:]
		if body == "" {
			return Reference{}, refMalformed("empty_segment", "[]")
		}
		seen := map[string]bool{}
		for _, binding := range strings.Split(body, ",") {
			parts := strings.Split(binding, ":")
			if len(parts) != 2 {
				return Reference{}, refMalformed("bad_binding", binding)
			}
			name := parts[0]
			if !namePattern.MatchString(name) {
				return Reference{}, refMalformed("bad_dimension", name)
			}
			if seen[name] {
				return Reference{}, refMalformed("duplicate_dimension", name)
			}
			seen[name] = true
			value, err := decodeSegment(parts[1])
			if err != nil {
				return Reference{}, err
			}
			qualifiers = append(qualifiers, Binding{name, value})
		}
	}
	if strings.Count(rest, "#") > 1 {
		return Reference{}, refMalformed("reserved_character", "#")
	}
	hashAt := strings.IndexByte(rest, '#')
	fieldGiven := hashAt >= 0
	targetText, field := rest, DefaultField
	if fieldGiven {
		targetText = rest[:hashAt]
	}
	if targetText == "" {
		return Reference{}, refMalformed("empty_target", "")
	}
	if fieldGiven {
		var err error
		if field, err = decodeSegment(rest[hashAt+1:]); err != nil {
			return Reference{}, err
		}
	}
	var target Target
	if !strings.Contains(targetText, "/") {
		for _, part := range strings.Split(targetText, ".") {
			if !namePattern.MatchString(part) {
				return Reference{}, refMalformed("bad_key", targetText)
			}
		}
		target = Target{Kind: TargetKey, Key: targetText}
	} else {
		parts := strings.Split(targetText, "/")
		store, raw := parts[0], parts[1:]
		if !storePattern.MatchString(store) {
			return Reference{}, refMalformed("bad_store", store)
		}
		if len(raw) == 1 && strings.HasPrefix(raw[0], "~") {
			if !uuidPattern.MatchString(raw[0]) {
				return Reference{}, refMalformed("bad_uuid", raw[0])
			}
			target = Target{Kind: TargetUUID, Store: store, UUID: strings.ToLower(raw[0][1:])}
		} else {
			segments := make([]string, 0, len(raw))
			for _, segment := range raw {
				if segment == "" {
					return Reference{}, refMalformed("empty_segment", "")
				}
				if segment[0] == '@' || segment[0] == '~' {
					return Reference{}, refMalformed("reserved_prefix", segment[:1])
				}
				decoded, err := decodeSegment(segment)
				if err != nil {
					return Reference{}, err
				}
				segments = append(segments, decoded)
			}
			target = Target{Kind: TargetPath, Store: store, Segments: segments}
		}
	}
	return Reference{target, qualifiers, field, fieldGiven}, nil
}

// FormatReference is the canonical text of r: bindings sorted by dimension
// name (by UTF-8 bytes), every segment escaped in exactly what it must be,
// the uuid in lower case, the field omitted when it is [DefaultField]. A
// reference that has no canonical text (a dimension bound twice, an empty
// segment, an unknown target kind) is an error.
func FormatReference(r Reference) (string, error) {
	var out strings.Builder
	if len(r.Qualifiers) > 0 {
		bindings := append([]Binding(nil), r.Qualifiers...)
		sort.SliceStable(bindings, func(i, j int) bool { return bindings[i].Dimension < bindings[j].Dimension })
		parts := make([]string, len(bindings))
		for i, b := range bindings {
			if i > 0 && bindings[i-1].Dimension == b.Dimension {
				return "", errors.New("tsm: a dimension is bound once")
			}
			value, err := encodeSegment(b.Value, false)
			if err != nil {
				return "", err
			}
			parts[i] = b.Dimension + ":" + value
		}
		out.WriteString("[" + strings.Join(parts, ",") + "]")
	}
	switch r.Target.Kind {
	case TargetKey:
		out.WriteString(r.Target.Key)
	case TargetUUID:
		out.WriteString(r.Target.Store + "/~" + strings.ToLower(r.Target.UUID))
	case TargetPath:
		out.WriteString(r.Target.Store)
		for _, s := range r.Target.Segments {
			segment, err := encodeSegment(s, true)
			if err != nil {
				return "", err
			}
			out.WriteString("/" + segment)
		}
	default:
		return "", fmt.Errorf("tsm: unknown target kind %q", r.Target.Kind)
	}
	field := r.Field
	if field == "" {
		field = DefaultField
	}
	if field != DefaultField {
		segment, err := encodeSegment(field, false)
		if err != nil {
			return "", err
		}
		out.WriteString("#" + segment)
	}
	return out.String(), nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7F }

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func decodeSegment(raw string) (string, error) {
	if raw == "" {
		return "", refMalformed("empty_segment", "")
	}
	data := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		if raw[i] == '%' {
			if i+2 >= len(raw) || !isHex(raw[i+1]) || !isHex(raw[i+2]) {
				return "", refMalformed("bad_escape", raw[i:min(i+3, len(raw))])
			}
			b, _ := strconv.ParseUint(raw[i+1:i+3], 16, 8)
			data = append(data, byte(b))
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(raw[i:])
		if strings.ContainsRune(reservedCharacters, r) {
			return "", refMalformed("reserved_character", string(r))
		}
		if isControl(r) {
			return "", refMalformed("control_character", fmt.Sprintf("U+%04X", r))
		}
		data = append(data, raw[i:i+size]...)
		i += size
	}
	if !utf8.Valid(data) {
		return "", refMalformed("bad_utf8", "")
	}
	return string(data), nil
}

func encodeSegment(text string, path bool) (string, error) {
	if text == "" {
		return "", errors.New("tsm: a segment is never empty")
	}
	var out strings.Builder
	for index, r := range text {
		escape := strings.ContainsRune(reservedCharacters, r) || isControl(r) ||
			(path && index == 0 && (r == '@' || r == '~'))
		if !escape {
			out.WriteRune(r)
			continue
		}
		var buf [utf8.UTFMax]byte
		n := utf8.EncodeRune(buf[:], r)
		for _, b := range buf[:n] {
			fmt.Fprintf(&out, "%%%02X", b)
		}
	}
	return out.String(), nil
}
