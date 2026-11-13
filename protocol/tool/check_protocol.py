#!/usr/bin/env python3
# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""Checks that protocol.md, the schemas and the vectors agree.

    protocol/tool/check_protocol.py

- every schema is a valid draft 2020-12 schema, and protocol.md names every
  message, every error kind and every malformed reason;
- every frame of frames.json decodes to its JSON and validates against the
  schema its op names, and every message schema has a frame;
- references.json, hmac.json and discovery.json are what the reference
  implementation computes, and every vector file is what gen_vectors.py
  writes now.

Run by hand (needs jsonschema and referencing). Exit 0 when everything holds.
"""
from __future__ import annotations

import base64
import json
import pathlib
import re
import sys

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

import gen_vectors
import tsm_protocol as tp

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / 'schema'
VECTORS = ROOT / 'vectors'

MALFORMED_REASONS = [
    'empty', 'too_long', 'empty_segment', 'unclosed_qualifiers', 'empty_target', 'bad_binding',
    'bad_dimension', 'duplicate_dimension', 'bad_key', 'bad_store', 'bad_uuid',
    'reserved_prefix', 'reserved_character', 'bad_escape', 'bad_utf8', 'control_character',
]

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def load(name: str):
    return json.loads((VECTORS / name).read_text())


def main() -> int:
    doc = (ROOT / 'protocol.md').read_text()

    schemas = {p.stem: json.loads(p.read_text()) for p in SCHEMAS.glob('*.json')}
    registry = Registry().with_resources(
        (s['$id'], Resource.from_contents(s)) for s in schemas.values())
    for name, schema in schemas.items():
        Draft202012Validator.check_schema(schema)
    ops = sorted(n for n in schemas if n != 'common')
    for op in ops:
        # A code span that is the op or starts with it, `op` or `op {members}`.
        named = re.search('`' + re.escape(op) + '[` ]', doc)
        check(named is not None, f'protocol.md does not name the message `{op}`')
    for kind in schemas['common']['$defs']['errorKind']['enum']:
        check(f'`{kind}`' in doc, f'protocol.md does not name the error kind `{kind}`')
    for reason in MALFORMED_REASONS:
        check(f'`{reason}`' in doc, f'protocol.md does not name the malformed reason `{reason}`')

    frames = load('frames.json')
    covered = set()
    for case in frames['frames']:
        data = bytes.fromhex(case['hex'])
        frame_type, payload = tp.decode_frame(data)
        check(frame_type == case['type'], f"{case['name']}: type")
        if frame_type == tp.FRAME_JSON:
            message = json.loads(payload.decode('utf-8'))
            check(message == case['json'], f"{case['name']}: payload is not its json")
            check(payload == tp.json_payload(case['json']), f"{case['name']}: not compact")
            op = message['op']
            covered.add(op)
            if op not in schemas:
                failures.append(f"{case['name']}: no schema for op {op}")
                continue
            validator = Draft202012Validator(schemas[op], registry=registry)
            for error in validator.iter_errors(message):
                failures.append(f"{case['name']}: {error.json_path}: {error.message}")
            limit = tp.MAX_REQUEST_PAYLOAD if schemas[op]['x-tsm']['direction'] in (
                'c2s', 'a2s') else tp.MAX_ANSWER_PAYLOAD
            check(len(payload) <= limit, f"{case['name']}: over its frame limit")
        else:
            check(payload[:8] == case['requestId'].to_bytes(8, 'big'), f"{case['name']}: id")
            check(payload[8:].hex() == case['chunkHex'], f"{case['name']}: chunk")
    for op in ops:
        check(op in covered, f'frames.json has no frame for `{op}`')

    for case in frames['invalid']:
        data = bytes.fromhex(case['hex'])
        length = int.from_bytes(data[:4], 'big')
        if case['outcome'] == 'close' and data[4] in (0, 1) and len(data) == 5:
            limit = tp.MAX_REQUEST_PAYLOAD if case['direction'] == 'to service' else tp.MAX_ANSWER_PAYLOAD
            check(length > limit, f"{case['name']}: not over the limit")

    refs = load('references.json')
    for case in refs['valid']:
        result = tp.parse(case['input'])
        canonical = result.pop('canonical')
        check(result == case['parsed'], f"reference {case['input']!r}: parse result")
        check(canonical == case['canonical'], f"reference {case['input']!r}: canonical")
        check(tp.parse(canonical)['canonical'] == canonical, f'{canonical!r} is not a fixpoint')
    for case in refs['invalid']:
        try:
            tp.parse(case['input'])
            failures.append(f"reference {case['input']!r} parses")
        except tp.Malformed as e:
            check(e.reason == case['reason'], f"reference {case['input']!r}: {e.reason}")
    for case in refs['format']:
        check(tp.format_reference(case['parsed']) == case['formatted'], 'format case')
    seen = {c['reason'] for c in refs['invalid']}
    for reason in MALFORMED_REASONS:
        check(reason in seen, f'references.json has no case for `{reason}`')

    for case in load('hmac.json')['cases']:
        key, sn, an = (base64.b64decode(case[k]) for k in ('adminKey', 'serviceNonce', 'adminNonce'))
        start = case['serviceStart']
        check(base64.b64encode(tp.admin_mac('tsm-admin-v1', key, sn, an, start)).decode() ==
              case['mac'], f"hmac {case['name']}: mac")
        check(base64.b64encode(tp.admin_mac('tsm-service-v1', key, sn, an, start)).decode() ==
              case['mac2'], f"hmac {case['name']}: mac2")

    disc = load('discovery.json')
    for case in disc['cases']:
        check(tp.discover(case['os'], case['env'], case['uid']) == case['expect'],
              f"discovery {case['os']} {case['env']}")

    regenerated = {
        'frames.json': gen_vectors.frames(), 'references.json': gen_vectors.references(),
        'hmac.json': gen_vectors.hmac_vectors(), 'discovery.json': gen_vectors.discovery(),
    }
    for name, data in regenerated.items():
        check(load(name) == json.loads(json.dumps(data)),
              f'{name} is not what gen_vectors.py writes now')

    claimed = re.findall(r'(\d+) message schemas', doc)
    check(str(len(ops)) in claimed, f'protocol.md does not state {len(ops)} message schemas')

    for f in failures:
        print('FAIL', f)
    print(f'{len(ops)} messages, {len(frames["frames"])} frames, {len(refs["valid"])} valid and '
          f'{len(refs["invalid"])} invalid references, {len(disc["cases"])} discovery cases: '
          f'{"OK" if not failures else f"{len(failures)} failure(s)"}')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
