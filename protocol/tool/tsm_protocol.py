# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""Reference implementation of the parts of protocol.md that can be computed:
the reference grammar (parse and format), framing, the admin challenge and the
runtime-directory discovery.

It writes the test vectors (gen_vectors.py) and re-checks them
(check_protocol.py). It is not a client library: it exists so that the
document, the vectors and the libraries have one definition to agree with.
Standard library only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re

# --------------------------------------------------------------------------
# References (protocol.md section 4)
# --------------------------------------------------------------------------

MAX_REFERENCE_BYTES = 1024
RESERVED = frozenset('/#[],:%')
NAME = re.compile(r'[a-z][a-z0-9_-]*\Z')
STORE = re.compile(r'[a-z0-9][a-z0-9_-]*\Z')
UUID = re.compile(r'~[0-9A-Fa-f]{32}\Z')
DEFAULT_FIELD = 'Password'


class Malformed(Exception):
    """A reference that does not parse; `reason` is a code of section 4.6."""

    def __init__(self, reason: str, detail: str = ''):
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason


def _is_control(ch: str) -> bool:
    return ord(ch) < 0x20 or ord(ch) == 0x7F


def decode_segment(raw: str) -> str:
    """The text of one escaped segment (a group, title, field or value)."""
    if raw == '':
        raise Malformed('empty_segment')
    out = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == '%':
            pair = raw[i + 1:i + 3]
            if len(pair) != 2 or not all(c in '0123456789abcdefABCDEF' for c in pair):
                raise Malformed('bad_escape', raw[i:i + 3])
            out.append(int(pair, 16))
            i += 3
            continue
        if ch in RESERVED:
            raise Malformed('reserved_character', ch)
        if _is_control(ch):
            raise Malformed('control_character', f'U+{ord(ch):04X}')
        out.extend(ch.encode('utf-8'))
        i += 1
    try:
        return out.decode('utf-8', errors='strict')
    except UnicodeDecodeError as e:
        raise Malformed('bad_utf8', str(e)) from None


def encode_segment(text: str, *, path_segment: bool = False) -> str:
    """The canonical escaped form of one segment: the reserved characters and
    the control characters percent-encoded (upper-case hex, per UTF-8 byte),
    and in a path segment a leading `@` or `~` as well."""
    if text == '':
        raise ValueError('a segment is never empty')
    out = []
    for index, ch in enumerate(text):
        if ch in RESERVED or _is_control(ch) or (
                path_segment and index == 0 and ch in '@~'):
            out.append(''.join(f'%{b:02X}' for b in ch.encode('utf-8')))
        else:
            out.append(ch)
    return ''.join(out)


def parse(reference: str) -> dict:
    """The parse result of `reference`, or Malformed.

    {qualifiers: [{dimension, value}] (in the order written),
     target: {kind: key, key} | {kind: path, store, segments}
             | {kind: uuid, store, uuid},
     field (the effective field), fieldGiven, canonical}
    """
    if len(reference.encode('utf-8')) > MAX_REFERENCE_BYTES:
        raise Malformed('too_long')
    if reference == '':
        raise Malformed('empty')
    rest = reference
    qualifiers = []
    if rest.startswith('['):
        end = rest.find(']')
        if end < 0:
            raise Malformed('unclosed_qualifiers')
        body, rest = rest[1:end], rest[end + 1:]
        if body == '':
            raise Malformed('empty_segment', '[]')
        seen = set()
        for binding in body.split(','):
            parts = binding.split(':')
            if len(parts) != 2:
                raise Malformed('bad_binding', binding)
            name, value = parts
            if not NAME.match(name):
                raise Malformed('bad_dimension', name)
            if name in seen:
                raise Malformed('duplicate_dimension', name)
            seen.add(name)
            qualifiers.append({'dimension': name, 'value': decode_segment(value)})
    if rest.count('#') > 1:
        raise Malformed('reserved_character', '#')
    target_text, _, field_text = rest.partition('#')
    field_given = '#' in rest
    if target_text == '':
        raise Malformed('empty_target')
    if field_given:
        field = decode_segment(field_text)
    else:
        field = DEFAULT_FIELD
    if '/' not in target_text:
        names = target_text.split('.')
        if not all(NAME.match(n) for n in names):
            raise Malformed('bad_key', target_text)
        target = {'kind': 'key', 'key': target_text}
    else:
        parts = target_text.split('/')
        store = parts[0]
        if not STORE.match(store):
            raise Malformed('bad_store', store)
        segments_raw = parts[1:]
        if len(segments_raw) == 1 and segments_raw[0].startswith('~'):
            if not UUID.match(segments_raw[0]):
                raise Malformed('bad_uuid', segments_raw[0])
            target = {'kind': 'uuid', 'store': store,
                      'uuid': segments_raw[0][1:].lower()}
        else:
            segments = []
            for raw in segments_raw:
                if raw == '':
                    raise Malformed('empty_segment')
                if raw[0] in '@~':
                    raise Malformed('reserved_prefix', raw[0])
                segments.append(decode_segment(raw))
            target = {'kind': 'path', 'store': store, 'segments': segments}
    result = {
        'qualifiers': qualifiers,
        'target': target,
        'field': field,
        'fieldGiven': field_given,
    }
    result['canonical'] = format_reference(result)
    return result


def format_reference(parsed: dict) -> str:
    """The canonical text of a parsed reference: bindings sorted by dimension
    name, every segment in its canonical escaping, the uuid in lower case, and
    the field omitted when it is `Password`."""
    out = []
    qualifiers = sorted(parsed['qualifiers'], key=lambda q: q['dimension'])
    if qualifiers:
        names = [q['dimension'] for q in qualifiers]
        if len(set(names)) != len(names):
            raise ValueError('a dimension is bound once')
        out.append('[' + ','.join(
            f"{q['dimension']}:{encode_segment(q['value'])}" for q in qualifiers) + ']')
    target = parsed['target']
    if target['kind'] == 'key':
        out.append(target['key'])
    elif target['kind'] == 'uuid':
        out.append(f"{target['store']}/~{target['uuid'].lower()}")
    else:
        out.append(target['store'] + '/' + '/'.join(
            encode_segment(s, path_segment=True) for s in target['segments']))
    field = parsed.get('field', DEFAULT_FIELD)
    if field != DEFAULT_FIELD:
        out.append('#' + encode_segment(field))
    return ''.join(out)


# --------------------------------------------------------------------------
# Framing (protocol.md section 2)
# --------------------------------------------------------------------------

FRAME_JSON = 0
FRAME_BINARY = 1
MAX_REQUEST_PAYLOAD = 64 * 1024
MAX_ANSWER_PAYLOAD = 1024 * 1024


def json_payload(message: dict) -> bytes:
    """The compact UTF-8 JSON the vectors use (any valid JSON is accepted)."""
    return json.dumps(message, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def encode_frame(frame_type: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(4, 'big') + bytes([frame_type]) + payload


def decode_frame(data: bytes) -> tuple[int, bytes]:
    if len(data) < 5:
        raise ValueError('short frame')
    length = int.from_bytes(data[:4], 'big')
    if len(data) != 5 + length:
        raise ValueError(f'length {length} but {len(data) - 5} payload bytes')
    return data[4], data[5:]


def binary_chunk(request_id: int, chunk: bytes) -> bytes:
    """The payload of a binary frame: the request id, 8 bytes big-endian, then
    the chunk."""
    return request_id.to_bytes(8, 'big') + chunk


# --------------------------------------------------------------------------
# The admin challenge (protocol.md section 6.1)
# --------------------------------------------------------------------------

def admin_mac(label: str, admin_key: bytes, service_nonce: bytes,
              admin_nonce: bytes, service_start: int) -> bytes:
    """HMAC-SHA256(adminKey, label || serviceNonce || adminNonce ||
    serviceStart as 8 bytes big-endian)."""
    if len(admin_key) != 32 or len(service_nonce) != 32 or len(admin_nonce) != 32:
        raise ValueError('the key and both nonces are 32 bytes')
    message = (label.encode('ascii') + service_nonce + admin_nonce +
               service_start.to_bytes(8, 'big'))
    return hmac.new(admin_key, message, hashlib.sha256).digest()


# --------------------------------------------------------------------------
# Finding the service (protocol.md section 3)
# --------------------------------------------------------------------------

def _strip(path: str, sep: str) -> str:
    stripped = path.rstrip('/\\' if sep == '\\' else '/')
    return stripped or path


def discover(os_name: str, env: dict, uid: int | None = None) -> dict:
    """Where the service's endpoints are, or {notRunning: reason}."""
    sep = '\\' if os_name == 'windows' else '/'
    override = env.get('TSM_RUNTIME_DIR', '')
    if override:
        directory = _strip(override, sep)
    elif os_name == 'linux':
        xdg = env.get('XDG_RUNTIME_DIR', '')
        directory = (_strip(xdg, '/') + '/tsm') if xdg.startswith('/') else f'/tmp/tsm-{uid}'
    elif os_name == 'macos':
        tmp = env.get('TMPDIR', '')
        directory = (_strip(tmp, '/') + '/tsm') if tmp.startswith('/') else f'/tmp/tsm-{uid}'
    elif os_name == 'windows':
        local = env.get('LOCALAPPDATA', '')
        profile = env.get('USERPROFILE', '')
        if local:
            base = _strip(local, '\\')
        elif profile:
            base = _strip(profile, '\\') + '\\AppData\\Local'
        else:
            return {'notRunning': 'no_runtime_directory'}
        directory = base + '\\TomSecretsManager\\run'
    else:
        raise ValueError(os_name)
    if os_name == 'windows':
        return {
            'directory': directory,
            'client': {'portFile': directory + '\\client.port',
                       'tokenFile': directory + '\\client.token'},
            'admin': {'portFile': directory + '\\admin.port'},
        }
    return {
        'directory': directory,
        'client': {'socket': directory + '/client.sock'},
        'admin': {'socket': directory + '/admin.sock'},
    }


def read_port_file(text: str) -> int:
    """A port file: decimal digits, 1 to 65535, optionally one trailing
    newline (LF or CRLF)."""
    body = text[:-2] if text.endswith('\r\n') else text[:-1] if text.endswith('\n') else text
    if not re.fullmatch(r'[1-9][0-9]{0,4}', body) or int(body) > 65535:
        raise ValueError(f'not a port file: {text!r}')
    return int(body)
