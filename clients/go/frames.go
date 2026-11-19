// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package tsm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf8"
)

// Frames and JSON payloads (protocol.md section 2).
const (
	frameJSON   = 0
	frameBinary = 1
	// MaxRequestPayload is the largest payload of a frame sent to the
	// service.
	MaxRequestPayload = 64 * 1024
	// MaxAnswerPayload is the largest payload of a frame the service sends.
	MaxAnswerPayload = 1024 * 1024
	maxJSONDepth     = 512
)

type message = map[string]any

// frameError is a frame or payload that breaks section 2; the connection is
// closed on it.
type frameError struct{ why string }

func (e *frameError) Error() string { return e.why }

// jsonPayload is the compact UTF-8 JSON of m (no HTML escaping).
func jsonPayload(m message) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// encodeFrame is a frame: the payload length (4 bytes big-endian), the
// type, the payload.
func encodeFrame(frameType byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	out[4] = frameType
	copy(out[5:], payload)
	return out
}

// decodePayload is the message of a JSON payload: malformed when it is
// empty, not UTF-8, starts with a byte order mark, is not strict JSON (one
// value, no duplicate member names, numbers in range), is not an object or
// has no string op.
func decodePayload(payload []byte) (message, error) {
	if len(payload) == 0 {
		return nil, &frameError{"empty payload"}
	}
	if !utf8.Valid(payload) {
		return nil, &frameError{"payload is not UTF-8"}
	}
	if bytes.HasPrefix(payload, []byte("\xEF\xBB\xBF")) {
		return nil, &frameError{"payload starts with a byte order mark"}
	}
	value, err := parseStrictJSON(payload)
	if err != nil {
		return nil, &frameError{"payload is not JSON: " + err.Error()}
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, &frameError{"payload is not a JSON object"}
	}
	if _, ok := m["op"].(string); !ok {
		return nil, &frameError{"payload has no op"}
	}
	return m, nil
}

// parseStrictJSON parses one JSON value, refusing duplicate member names
// and numbers outside float64 (encoding/json alone takes the last of two
// members of one name). Numbers come back as json.Number.
func parseStrictJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := strictValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the value")
	}
	return value, nil
}

func strictValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errors.New("nested too deeply")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			object := map[string]any{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("member name is no string")
				}
				if _, seen := object[key]; seen {
					return nil, fmt.Errorf("duplicate member %q", key)
				}
				v, err := strictValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return object, nil
		case '[':
			array := []any{}
			for dec.More() {
				v, err := strictValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return array, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil || math.IsInf(f, 0) {
			return nil, errors.New("number out of range")
		}
		return t, nil
	default:
		return t, nil
	}
}

// frameReader splits a byte stream into frames, checking each length
// against maxPayload before its payload is read and refusing a frame type
// that is neither JSON nor (once negotiated) binary.
type frameReader struct {
	maxPayload    int
	binaryAllowed bool
	pending       []byte
}

type frame struct {
	frameType byte
	payload   []byte
}

func (r *frameReader) add(data []byte) ([]frame, error) {
	r.pending = append(r.pending, data...)
	var frames []frame
	offset := 0
	for len(r.pending)-offset >= 5 {
		length := int(binary.BigEndian.Uint32(r.pending[offset:]))
		frameType := r.pending[offset+4]
		if length > r.maxPayload {
			return nil, &frameError{fmt.Sprintf("frame of %d bytes over %d", length, r.maxPayload)}
		}
		if frameType != frameJSON && !(frameType == frameBinary && r.binaryAllowed) {
			return nil, &frameError{fmt.Sprintf("frame type %d", frameType)}
		}
		if len(r.pending)-offset-5 < length {
			break
		}
		payload := make([]byte, length)
		copy(payload, r.pending[offset+5:offset+5+length])
		frames = append(frames, frame{frameType, payload})
		offset += 5 + length
	}
	rest := copy(r.pending, r.pending[offset:])
	// The bytes behind the rest held frames already handed out (values
	// among them): overwritten, not left for the garbage collector.
	clear(r.pending[rest:])
	r.pending = r.pending[:rest]
	return frames, nil
}

// intOf is the integer a JSON number holds, when it is one.
func intOf(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil
}
