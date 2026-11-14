#!/usr/bin/env python3
# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""Checks that protocol.md, the schemas and the vectors agree.

    protocol/tool/check_protocol.py

- every schema is a valid draft 2020-12 schema, and protocol.md names every
  message, every error kind and every malformed reason;
- every frame of frames.json decodes to its JSON and validates against the
  schema its op names, and every message schema has a frame;
- references.json, hmac.json, discovery.json and approval_codes.json are what
  the reference implementation computes, and every vector file gen_vectors.py
  writes is what it writes now;
- signatures.json: the signed bytes and key ids are what the reference
  implementation computes from the objects (the signatures themselves are
  checked by tool/vectors_dart's tests and, independently, by
  tool/vectors_go);
- link_handshake.json: every transport frame's plaintext is its JSON, valid
  against its schema, a message allowed on the approval link from its side,
  within the link's frame limit; every link message has a frame.

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

LINK_FRAME_LIMIT = 1024 * 1024

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
    service_ops = [op for op in ops if schemas[op]['x-tsm']['endpoint'] != 'link']
    for op in service_ops:
        check(op in covered, f'frames.json has no frame for `{op}`')
    for op in covered:
        check(op in schemas and schemas[op]['x-tsm']['endpoint'] != 'link',
              f'frames.json carries the link message `{op}`')

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

    codes = load('approval_codes.json')
    for case in codes['codes']:
        check(tp.request_digest(case['identity'], case['refs']).hex() == case['requestDigestHex'],
              f"approval code {case['name']}: request digest")
        check(tp.approval_code(case['host'], case['approvalId'], case['identity'], case['refs'])
              == case['code'], f"approval code {case['name']}: code")
        check(re.fullmatch('[A-Z2-7]{10}', case['code']) is not None, 'code alphabet')
    for case in codes['tokens']:
        token = tp.code_token(base64.b64decode(case['tokenKey']), case['host'], case['code'],
                              case['decision'])
        check(token == case['token'], f"token {case['code']} {case['decision']}")
        check(re.fullmatch('[A-Z2-7]{26}', token) is not None, 'token alphabet')
    red = codes['redeem']
    for case in red['cases']:
        found = tp.redeem(case['token'], red['waiting'],
                          [base64.b64decode(k) for k in red['tokenKeys']], red['host'])
        check((list(found) if found else None) == case['outcome'], f"redeem {case['name']}")

    sig = load('signatures.json')
    keys = sig['keys']
    for name, k in keys.items():
        check(tp.key_id(base64.b64decode(k['ed25519Public']), base64.b64decode(k['mlDsa65Public']))
              == k['keyId'], f'signatures.json key {name}: keyId')
    defs = schemas['common']['$defs']
    object_def = {'tsm-grant-v1': 'grant', 'tsm-revoke-v1': 'revocation',
                  'tsm-approval-v1': 'approvalRecord', 'tsm-keychange-v1': 'keyChange'}
    for case in sig['accepted']:
        obj = case['object']
        check(tp.signed_bytes(case['label'], obj).hex() == case['signedBytesHex'],
              f"signatures.json {case['name']}: signed bytes")
        validator = Draft202012Validator(
            {'$id': 'https://raw.githubusercontent.com/al-the-bear/tom_secrets_clients/main/protocol/schema/x.json',
             '$ref': f"common.json#/$defs/{object_def[case['label']]}"}, registry=registry)
        for error in validator.iter_errors(obj):
            failures.append(f"signatures.json {case['name']}: {error.json_path}: {error.message}")
        algs = {(s['keyId'], s['alg']) for s in obj['signatures']}
        check(all((kid, a) in algs for kid in {s['keyId'] for s in obj['signatures']}
                  for a in ('ed25519', 'ml-dsa-65')),
              f"signatures.json {case['name']}: a key without both signatures")
    record = next(c['object'] for c in sig['accepted'] if c['label'] == 'tsm-approval-v1')
    check(record['code'] == codes['codes'][0]['code'] and record['host'] == codes['codes'][0]['host'],
          'the approval record is not for the code of approval_codes.json')
    check(next(c['object'] for c in sig['accepted'] if c['name'] == 'grant') ==
          next(f['json'] for f in frames['frames'] if f['json'].get('op') == 'grantList')['grants'][0],
          'the grant of frames.json is not the signed grant')

    link = load('link_handshake.json')
    check(link['protocolName'] == 'tsm-link-v1_KK-hybrid_25519+MLKEM768_ChaChaPoly_SHA256',
          'link protocol name')
    check(f"`{link['protocolName']}`" in doc, 'protocol.md does not name the link protocol name')
    check(len(bytes.fromhex(link['message1Hex'])) == 32 + 1184 + 1088 +
          len(link['payload1Text'].encode()) + 16, 'message 1 length')
    check(len(bytes.fromhex(link['message2Hex'])) == 32 + 1088 + 1088 +
          len(link['payload2Text'].encode()) + 16, 'message 2 length')
    link_ops = set()
    counters = {'approver': 0, 'host': 0}
    for i, f in enumerate(link['transport']):
        message = json.loads(f['plaintext'])
        check(message == f['json'], f'link frame {i}: plaintext is not its json')
        check(f['n'] == counters[f['from']], f'link frame {i}: counter')
        counters[f['from']] += 1
        cipher = bytes.fromhex(f['ciphertextHex'])
        check(len(cipher) == len(f['plaintext'].encode()) + 16, f'link frame {i}: length')
        check(bytes.fromhex(f['frameHex']) == len(cipher).to_bytes(4, 'big') + cipher,
              f'link frame {i}: frame')
        check(len(cipher) <= LINK_FRAME_LIMIT, f'link frame {i}: over the link frame limit')
        op = message['op']
        link_ops.add(op)
        if op not in schemas:
            failures.append(f'link frame {i}: no schema for op {op}')
            continue
        meta = schemas[op]['x-tsm']
        on_link = meta['endpoint'] == 'link' or 'link' in meta.get('alsoOn', []) or \
            meta['endpoint'] == 'any'
        if meta['endpoint'] == 'link':
            sides = {'a2h': {'approver'}, 'h2a': {'host'}, 'both': {'approver', 'host'}}
            allowed = f['from'] in sides[meta['direction']]
        else:
            allowed = (meta['direction'] in ('a2s', 'c2s')) == (f['from'] == 'approver')
        check(on_link and allowed, f'link frame {i}: `{op}` is not sent on the link by the '
              f"{f['from']}")
        validator = Draft202012Validator(schemas[op], registry=registry)
        for error in validator.iter_errors(message):
            failures.append(f'link frame {i}: {error.json_path}: {error.message}')
    check(link['transport'][0]['json'] == {'op': 'ready'} and
          link['transport'][0]['from'] == 'approver', 'the first link frame is not ready')
    for op in ops:
        meta = schemas[op]['x-tsm']
        if meta['endpoint'] == 'link' or 'link' in meta.get('alsoOn', []):
            check(op in link_ops, f'link_handshake.json has no frame for `{op}`')

    regenerated = {
        'frames.json': gen_vectors.frames(), 'references.json': gen_vectors.references(),
        'hmac.json': gen_vectors.hmac_vectors(), 'discovery.json': gen_vectors.discovery(),
        'approval_codes.json': gen_vectors.approval_codes(),
    }
    for name, data in regenerated.items():
        check(load(name) == json.loads(json.dumps(data)),
              f'{name} is not what gen_vectors.py writes now')

    claimed = re.findall(r'(\d+) message schemas', doc)
    check(str(len(ops)) in claimed, f'protocol.md does not state {len(ops)} message schemas')

    for f in failures:
        print('FAIL', f)
    print(f'{len(ops)} messages, {len(frames["frames"])} frames, {len(refs["valid"])} valid and '
          f'{len(refs["invalid"])} invalid references, {len(disc["cases"])} discovery cases, '
          f'{len(codes["codes"])} approval codes, {len(codes["tokens"])} tokens, '
          f'{len(sig["accepted"]) + len(sig["rejected"])} signature cases, '
          f'{len(link["transport"])} link frames: '
          f'{"OK" if not failures else f"{len(failures)} failure(s)"}')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
