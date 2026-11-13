#!/usr/bin/env python3
# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""Writes protocol/vectors/: frames.json, references.json, hmac.json and
discovery.json, from the reference implementation in tsm_protocol.py and the
inputs written below (no randomness: every byte is derived from a label).

    protocol/tool/gen_vectors.py

Run by hand after changing the document; check_protocol.py re-checks the
files. The values are demo data under demo keys; no real secret is in them.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import tsm_protocol as tp

VECTORS = pathlib.Path(__file__).resolve().parent.parent / 'vectors'


def derive(label: str, n: int = 32) -> bytes:
    out = b''
    block = 0
    while len(out) < n:
        out += hashlib.sha256(f'tsm protocol vector {label} {block}'.encode()).digest()
        block += 1
    return out[:n]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def write(name: str, data: dict) -> None:
    (VECTORS / name).write_text(json.dumps(data, indent=1, ensure_ascii=False) + '\n')


# --------------------------------------------------------------------------
# frames.json
# --------------------------------------------------------------------------

UUID = '0f3c2a1b4d5e6f708192a3b4c5d6e7f8'
CLIENT = {'name': 'deploy.sh', 'version': '0.1.0', 'language': 'dart'}
IDENTITY = {'kind': 'script', 'exe': '/usr/bin/bash', 'interpreter': '/usr/bin/bash',
            'script': '/home/demo/deploy.sh', 'args': ['bash', 'deploy.sh'],
            'cwd': '/home/demo', 'parent': {'exe': '/usr/bin/sshd'}, 'uid': 1000}
GRANT = {'id': 'g-0001', 'host': 'bigbeast', 'subject': 'script /usr/bin/bash /home/demo/deploy.sh',
         'secret': '[env:prod]db.main', 'decision': 'allow', 'created': '2026-11-13T09:00:00Z',
         'pin': 'hash', 'approver': 'mbp',
         'signatures': [{'alg': 'ed25519', 'keyId': 'mbp-approver-1',
                         'sig': b64(derive('demo signature', 64))}]}
VALUE = {'value': 'demo-password-1', 'encoding': 'utf8',
         'entry': {'store': 'prod', 'uuid': UUID, 'source': 'github',
                   'fetchedAt': '2026-11-13T08:59:30Z'},
         'bound': {'env': 'prod'},
         'version': {'modified': '2026-11-01T12:00:00Z', 'revision': 'b1946ac92492d2347c62'}}

FRAMES = [
    # client endpoint
    ('hello', 'client', {'op': 'hello', 'protocol': 1, 'client': CLIENT}),
    ('hello on Windows, with the token and a client token', 'client',
     {'op': 'hello', 'protocol': 1, 'client': CLIENT, 'token': b64(derive('client.token')),
      'clientToken': b64(derive('client token'))}),
    ('welcome', 'client', {'op': 'welcome', 'protocol': 1, 'service': {'version': '0.1.0'},
                           'features': [], 'host': 'bigbeast', 'platform': 'linux'}),
    ('get with qualifiers and a field', 'client',
     {'op': 'get', 'id': 1, 'ref': '[env:prod]db.main#UserName'}),
    ('get with dimensions beside the reference, no wait', 'client',
     {'op': 'get', 'id': 2, 'ref': 'db.main', 'dimensions': {'env': 'prod'}, 'field': 'UserName',
      'wait': False}),
    ('get with a timeout, asking for a client token', 'client',
     {'op': 'get', 'id': 3, 'ref': 'telegram.bot_token', 'timeoutMs': 30000,
      'wantClientToken': True}),
    ('value', 'client', {'op': 'value', 'id': 1, **VALUE}),
    ('value from the offline cache, binary, with an expiry and a client token', 'client',
     {'op': 'value', 'id': 3, 'value': b64(b'\x00\x01demo\xff'), 'encoding': 'base64',
      'entry': {'store': 'fleet', 'uuid': UUID, 'source': 'cache',
                'fetchedAt': '2026-11-12T22:10:00Z'},
      'bound': {}, 'version': {'modified': '2026-10-01T00:00:00Z', 'revision': '9e107d9d372bb682'},
      'expires': '2027-01-01T00:00:00Z', 'clientToken': b64(derive('client token'))}),
    ('getMany', 'client', {'op': 'getMany', 'id': 4,
                           'refs': [{'ref': 'db.main'}, {'ref': 'db.main', 'field': 'UserName'},
                                    {'ref': 'telegram.bot_token'}],
                           'wait': True, 'timeoutMs': 60000}),
    ('values: a value and an error in request order', 'client',
     {'op': 'values', 'id': 4,
      'results': [{'op': 'value', **VALUE},
                  {'op': 'error', 'kind': 'not_found', 'message': 'no entry for telegram.bot_token',
                   'details': {'dimensions': {'env': 'prod', 'host': 'bigbeast'}}}]}),
    ('progress: waiting for an unlock', 'client', {'op': 'progress', 'id': 1, 'pending': 'unlock'}),
    ('progress: waiting for approval, with an approval code', 'client',
     {'op': 'progress', 'id': 4, 'pending': 'approval', 'approvalCode': 'K7Q2MZ4XWA'}),
    ('error: not_found naming the dimensions', 'client',
     {'op': 'error', 'id': 1, 'kind': 'not_found', 'message': 'no candidate for db.main',
      'details': {'dimensions': {'env': 'staging'}}}),
    ('error: ambiguous naming the candidates', 'client',
     {'op': 'error', 'id': 2, 'kind': 'ambiguous', 'message': 'two candidates rank equal',
      'details': {'candidates': [
          {'store': 'dev', 'path': 'Db/Main', 'uuid': UUID},
          {'store': 'dev', 'path': 'Legacy/Db', 'uuid': '1' * 32}]}}),
    ('error: denied, no approver', 'client',
     {'op': 'error', 'id': 3, 'kind': 'denied', 'message': 'no approver answered',
      'details': {'reason': 'no_approver'}}),
    ('error: rate_limited', 'client',
     {'op': 'error', 'id': 5, 'kind': 'rate_limited', 'message': 'slow down',
      'details': {'retryAfterMs': 10000}}),
    ('error: malformed reference', 'client',
     {'op': 'error', 'id': 6, 'kind': 'malformed', 'message': 'empty segment',
      'details': {'reason': 'empty_segment'}}),
    ('error without an id: unsupported protocol, then the connection closes', 'client',
     {'op': 'error', 'kind': 'unsupported', 'message': 'protocol 2 is not spoken here',
      'details': {'protocols': [1]}}),
    ('error: unknown op, the connection stays open', 'client',
     {'op': 'error', 'id': 7, 'kind': 'unsupported', 'message': 'unknown op',
      'details': {'op': 'getEverything'}}),
    ('getFile (phase B)', 'client', {'op': 'getFile', 'id': 8,
                                     'ref': 'fleet/Ssh/bigbeast#attachment%3Aid_ed25519'}),
    ('file (phase B)', 'client', {'op': 'file', 'id': 8, 'name': 'id_ed25519', 'size': 6}),
    ('end (phase B)', 'client', {'op': 'end', 'id': 8,
                                 'sha256': hashlib.sha256(b'demo-k').hexdigest()}),
    ('match (phase B)', 'client', {'op': 'match', 'id': 9, 'url': 'https://example.org/login'}),
    ('matches (phase B)', 'client',
     {'op': 'matches', 'id': 9, 'candidates': [
         {'entryId': f'fleet/~{UUID}', 'title': 'Example', 'userName': 'demo',
          'matchedUrl': 'https://example.org', 'hasTotp': True}]}),
    ('propose (phase B)', 'client', {'op': 'propose', 'id': 10, 'url': 'https://example.org',
                                     'userName': 'demo', 'password': 'demo-password-2'}),
    ('accepted (phase B)', 'client', {'op': 'accepted', 'id': 10}),
    # admin endpoint
    ('challenge', 'admin', {'op': 'challenge', 'serviceNonce': b64(derive('service nonce')),
                            'serviceStart': 1794560400000, 'protocol': 1,
                            'service': {'version': '0.1.0'}}),
    ('auth', 'admin', {'op': 'auth', 'adminNonce': b64(derive('admin nonce')),
                       'mac': None, 'client': {'name': 'tom_secrets_app', 'version': '0.1.0',
                                               'language': 'dart'}}),
    ('authed', 'admin', {'op': 'authed', 'mac2': None}),
    ('claim', 'admin', {'op': 'claim', 'password': 'demo master password',
                        'client': {'name': 'tsm', 'version': '0.1.0', 'language': 'dart'}}),
    ('claimed', 'admin', {'op': 'claimed', 'adminKey': b64(derive('new admin key'))}),
    ('unlock', 'admin', {'op': 'unlock', 'id': 1, 'password': 'demo master password',
                         'keyFile': b64(derive('demo key file', 64))}),
    ('unlock with a sealed bundle (phase B)', 'admin',
     {'op': 'unlock', 'id': 2, 'vault': 'primary',
      'bundle': {'nonce': b64(derive('bundle nonce', 12)), 'ciphertext': b64(derive('bundle', 80))}}),
    ('unlockStore', 'admin', {'op': 'unlockStore', 'id': 3, 'store': 'prod',
                              'password': 'demo store password'}),
    ('ok', 'admin', {'op': 'ok', 'id': 1}),
    ('lock', 'admin', {'op': 'lock', 'id': 4}),
    ('shutdown', 'admin', {'op': 'shutdown', 'id': 5}),
    ('status', 'admin', {'op': 'status', 'id': 6}),
    ('statusReport', 'admin',
     {'op': 'statusReport', 'id': 6, 'locked': False, 'lockMode': 'a', 'protocol': 1,
      'service': {'version': '0.1.0', 'start': 1794560400000},
      'stores': [{'name': 'fleet', 'state': 'current', 'source': 'github',
                  'fetchedAt': '2026-11-13T08:59:30Z', 'notPushed': 0},
                 {'name': 'prod', 'state': 'offline', 'source': 'cache',
                  'fetchedAt': '2026-11-12T22:10:00Z', 'notPushed': 1}],
      'admins': 1, 'hardening': {'mlock': True, 'noCoreDumps': True}}),
    ('reload', 'admin', {'op': 'reload', 'id': 7}),
    ('error: reload offline', 'admin',
     {'op': 'error', 'id': 7, 'kind': 'offline', 'message': 'GitHub unreachable',
      'details': {'stores': ['fleet', 'prod']}}),
    ('vaultKeys', 'admin', {'op': 'vaultKeys', 'id': 8}),
    ('vaultKeySet', 'admin', {'op': 'vaultKeySet', 'id': 8, 'stores': [
        {'store': 'fleet', 'location': 'github:al-the-bear/demo-vault/fleet.tsmx', 'keys': {}}]}),
    ('save', 'admin', {'op': 'save', 'id': 9, 'store': 'fleet', 'bytes': b64(derive('vault file', 96)),
                       'baseRevision': 'b1946ac92492d2347c62'}),
    ('subscribe', 'admin', {'op': 'subscribe', 'id': 10}),
    ('approve', 'admin', {'op': 'approve', 'id': 11, 'approvalId': 'a-17', 'decision': 'always',
                          'secret': 'ref', 'pin': 'hash'}),
    ('approve a folder, pin relaxed', 'admin',
     {'op': 'approve', 'id': 12, 'approvalId': 'a-18', 'decision': 'folder', 'secret': 'store',
      'folder': '/home/demo/Code', 'pin': {'relaxedUntil': '2026-11-20T00:00:00Z'}}),
    ('approval.redeem', 'admin', {'op': 'approval.redeem', 'id': 13,
                                  'token': 'MZXW6YTBOJRGC4TCMFZGKYLSMQ'}),
    ('approval.issue', 'admin', {'op': 'approval.issue', 'id': 14, 'code': 'K7Q2MZ4XWA',
                                 'decision': 'once', 'secret': 'ref'}),
    ('approvalToken', 'admin', {'op': 'approvalToken', 'id': 14,
                                'token': 'MZXW6YTBOJRGC4TCMFZGKYLSMQ'}),
    ('grants.list', 'admin', {'op': 'grants.list', 'id': 15, 'host': 'bigbeast'}),
    ('grantList', 'admin', {'op': 'grantList', 'id': 15, 'grants': [GRANT]}),
    ('grants.add', 'admin', {'op': 'grants.add', 'id': 16, 'grant': {
        'host': 'bigbeast', 'subject': 'exe /usr/local/bin/backup', 'secret': 'store fleet',
        'decision': 'allow', 'pin': 'off'}}),
    ('grants.revoke', 'admin', {'op': 'grants.revoke', 'id': 17, 'host': 'bigbeast',
                                'grantId': 'g-0001'}),
    ('approvers.cliSwitch', 'admin', {'op': 'approvers.cliSwitch', 'id': 18, 'on': False}),
    ('audit.query', 'admin', {'op': 'audit.query', 'id': 19, 'from': '2026-11-13T00:00:00Z',
                              'to': '2026-11-14T00:00:00Z', 'ref': 'db.main'}),
    ('auditRecords', 'admin', {'op': 'auditRecords', 'id': 19, 'records': [
        {'time': '2026-11-13T09:00:01Z', 'host': 'bigbeast', 'identity': IDENTITY,
         'refs': ['[env:prod]db.main'], 'outcome': 'allowed', 'grantId': 'g-0001'}]}),
    ('event unlock_needed', 'admin', {'op': 'unlock_needed', 'identity': IDENTITY}),
    ('event approval_needed', 'admin',
     {'op': 'approval_needed', 'approvalId': 'a-17', 'host': 'bigbeast', 'identity': IDENTITY,
      'refs': ['[env:prod]db.main'],
      'resolved': [{'store': 'prod', 'path': 'Db/Main', 'kind': 'login'}],
      'hostHint': 'bigbeast (Linux, over SSH from mbp)', 'approvalCode': 'K7Q2MZ4XWA'}),
    ('event approval_closed', 'admin', {'op': 'approval_closed', 'approvalId': 'a-17',
                                        'outcome': 'approved'}),
    ('event locked', 'admin', {'op': 'locked'}),
    ('event unlocked', 'admin', {'op': 'unlocked'}),
    ('event store_changed', 'admin', {'op': 'store_changed', 'store': 'fleet',
                                      'revision': '9e107d9d372bb682'}),
    ('event store_state', 'admin',
     {'op': 'store_state', 'store': 'prod', 'state': 'token_expired', 'source': 'cache',
      'fetchedAt': '2026-11-12T22:10:00Z', 'notPushed': 0}),
    ('event key_expiry', 'admin', {'op': 'key_expiry', 'key': 'github token',
                                   'expiresAt': '2026-12-01T00:00:00Z', 'daysLeft': 18}),
    ('event rate_limited', 'admin', {'op': 'rate_limited', 'identity': IDENTITY,
                                     'until': '2026-11-13T09:10:00Z'}),
    ('event proposal (phase B)', 'admin', {'op': 'proposal', 'url': 'https://example.org',
                                           'userName': 'demo', 'password': 'demo-password-2'}),
]


def admin_example() -> dict:
    key = derive('admin key')
    service_nonce = derive('service nonce')
    admin_nonce = derive('admin nonce')
    start = 1794560400000
    return {
        'adminKey': key, 'serviceNonce': service_nonce, 'adminNonce': admin_nonce,
        'serviceStart': start,
        'mac': tp.admin_mac('tsm-admin-v1', key, service_nonce, admin_nonce, start),
        'mac2': tp.admin_mac('tsm-service-v1', key, service_nonce, admin_nonce, start),
    }


def frames() -> dict:
    example = admin_example()
    cases = []
    for name, endpoint, message in FRAMES:
        message = dict(message)
        if message['op'] == 'auth':
            message['mac'] = b64(example['mac'])
        if message['op'] == 'authed':
            message['mac2'] = b64(example['mac2'])
        payload = tp.json_payload(message)
        cases.append({'name': name, 'endpoint': endpoint, 'type': tp.FRAME_JSON,
                      'json': message, 'hex': tp.encode_frame(tp.FRAME_JSON, payload).hex()})
    chunk = tp.binary_chunk(8, b'demo-k')
    cases.append({'name': 'binary chunk of getFile 8 (phase B)', 'endpoint': 'client',
                  'type': tp.FRAME_BINARY, 'requestId': 8, 'chunkHex': b'demo-k'.hex(),
                  'hex': tp.encode_frame(tp.FRAME_BINARY, chunk).hex()})
    invalid = [
        {'name': 'request over 64 KiB: the header alone closes the connection',
         'endpoint': 'client', 'direction': 'to service',
         'hex': ((tp.MAX_REQUEST_PAYLOAD + 1).to_bytes(4, 'big') + b'\x00').hex(),
         'outcome': 'close'},
        {'name': 'a request of exactly 64 KiB is allowed by its length',
         'endpoint': 'client', 'direction': 'to service',
         'hex': (tp.MAX_REQUEST_PAYLOAD.to_bytes(4, 'big') + b'\x00').hex(),
         'outcome': 'read'},
        {'name': 'answer over 1 MiB: the header alone closes the connection',
         'endpoint': 'client', 'direction': 'to client',
         'hex': ((tp.MAX_ANSWER_PAYLOAD + 1).to_bytes(4, 'big') + b'\x00').hex(),
         'outcome': 'close'},
        {'name': 'unknown frame type 2', 'endpoint': 'client', 'direction': 'to service',
         'hex': tp.encode_frame(2, b'{}').hex(), 'outcome': 'close'},
        {'name': 'a binary frame where the peer does not speak binary', 'endpoint': 'client',
         'direction': 'to service', 'hex': tp.encode_frame(1, tp.binary_chunk(1, b'x')).hex(),
         'outcome': 'close'},
        {'name': 'empty payload', 'endpoint': 'client', 'direction': 'to service',
         'hex': tp.encode_frame(0, b'').hex(), 'outcome': 'malformed_close'},
        {'name': 'payload not UTF-8', 'endpoint': 'client', 'direction': 'to service',
         'hex': tp.encode_frame(0, b'{"op":"get","id":1,"ref":"\xff"}').hex(),
         'outcome': 'malformed_close'},
        {'name': 'payload is JSON but not an object', 'endpoint': 'client',
         'direction': 'to service', 'hex': tp.encode_frame(0, b'[1,2]').hex(),
         'outcome': 'malformed_close'},
        {'name': 'object without op', 'endpoint': 'client', 'direction': 'to service',
         'hex': tp.encode_frame(0, b'{"id":1}').hex(), 'outcome': 'malformed_close'},
        {'name': 'duplicate member', 'endpoint': 'client', 'direction': 'to service',
         'hex': tp.encode_frame(0, b'{"op":"get","id":1,"id":2,"ref":"x"}').hex(),
         'outcome': 'malformed_close'},
        {'name': 'a first frame that is not hello', 'endpoint': 'client',
         'direction': 'to service',
         'hex': tp.encode_frame(0, tp.json_payload({'op': 'get', 'id': 1, 'ref': 'x'})).hex(),
         'outcome': 'malformed_close'},
    ]
    return {'note': 'Every frame as hex with its decoded payload. The JSON in the hex is '
                    'compact, keys in the order shown; a reader accepts any valid JSON. '
                    'Invalid frames name what the receiver does (protocol.md section 2.4).',
            'protocol': 1, 'frames': cases, 'invalid': invalid}


# --------------------------------------------------------------------------
# references.json
# --------------------------------------------------------------------------

VALID_REFERENCES = [
    'telegram.bot_token', 'db.main', 'a', 'a1.b_2.c-3',
    '[env:prod]db.main#UserName', '[env:prod,host:bomber]fleet/Cloud/AWS/root',
    '[host:bomber,env:prod]fleet/Cloud/AWS/root', '[env:default]db.main',
    'fleet/Cloud/AWS/root', 'fleet/Cloud/AWS/root#Password', 'fleet/Cloud/AWS/root#URL',
    'fleet/Mail/a%2Fb%23c', 'fleet/Mail/a%2fb', 'fleet/%40host%3Abomber',
    'fleet/%7Etilde', 'fleet/a~b/c@d', 'fleet/~0f3c2a1b4d5e6f708192a3b4c5d6e7f8',
    'fleet/~0F3C2A1B4D5E6F708192A3B4C5D6E7F8#totp', '0store/x', 'fleet/Ssh/k#attachment%3Aid_ed25519',
    'fleet/Grüße/Café', 'fleet/Gr%C3%BC%C3%9Fe', 'fleet/with space/and tab%09', 'fleet/%25',
    '[env:pr%2Cod]db.main', '[region:eu-west_1,env:prod]x.y', 'fleet/Mail/a.b.c#Notes',
    'fleet/a%5Bb%5D%2Cc', 'k#Password', 'k#password', 'fleet/😀/x',
    'store-1/A' + '/b' * 400,
]

INVALID_REFERENCES = [
    ('', 'empty'), ('x' * 1025, 'too_long'), ('fleet/' + 'é' * 510, 'too_long'),
    ('fleet//X', 'empty_segment'), ('fleet/', 'empty_segment'), ('[env:]x', 'empty_segment'),
    ('[]x', 'empty_segment'), ('x#', 'empty_segment'), ('[env:prod', 'unclosed_qualifiers'),
    ('[env:prod]', 'empty_target'), ('#UserName', 'empty_target'),
    ('[env]x', 'bad_binding'), ('[env:a:b]x', 'bad_binding'), ('[Env:prod]x', 'bad_dimension'),
    ('[1env:prod]x', 'bad_dimension'), ('[env:a,env:b]x', 'duplicate_dimension'),
    ('Db.main', 'bad_key'), ('db..main', 'bad_key'), ('db.main.', 'bad_key'), ('-db', 'bad_key'),
    ('db main', 'bad_key'), ('db%2Emain', 'bad_key'), ('Fleet/x', 'bad_store'),
    ('_fleet/x', 'bad_store'), ('fleet/~abc', 'bad_uuid'),
    ('fleet/~0f3c2a1b4d5e6f708192a3b4c5d6e7fz', 'bad_uuid'), ('fleet/@host:bomber/x', 'reserved_prefix'),
    ('fleet/@x', 'reserved_prefix'), ('fleet/a/~b', 'reserved_prefix'),
    ('fleet/~0f3c2a1b4d5e6f708192a3b4c5d6e7f8/x', 'reserved_prefix'),
    ('a.b#c#d', 'reserved_character'), ('fleet/a:b', 'reserved_character'),
    ('fleet/a,b', 'reserved_character'), ('fleet/a[b', 'reserved_character'),
    ('fleet/a]b', 'reserved_character'), ('[env:prod]x]', 'bad_key'),
    ('fleet/a%zz', 'bad_escape'), ('fleet/a%2', 'bad_escape'), ('fleet/a%', 'bad_escape'),
    ('fleet/a%C3', 'bad_utf8'), ('fleet/%C0%AF', 'bad_utf8'), ('fleet/%ED%A0%80', 'bad_utf8'),
    ('fleet/a\tb', 'control_character'), ('fleet/a\x7fb', 'control_character'),
]

FORMAT_CASES = [
    {'qualifiers': [{'dimension': 'host', 'value': 'bomber'}, {'dimension': 'env', 'value': 'prod'}],
     'target': {'kind': 'path', 'store': 'fleet', 'segments': ['Cloud', 'AWS', 'root']},
     'field': 'Password'},
    {'qualifiers': [], 'target': {'kind': 'path', 'store': 'fleet',
                                  'segments': ['@host:bomber', 'Telegram/Bot', 'a#b', '~x', '100%']},
     'field': 'attachment:id_ed25519'},
    {'qualifiers': [{'dimension': 'env', 'value': 'a,b:c'}], 'target': {'kind': 'key', 'key': 'db.main'},
     'field': 'UserName'},
    {'qualifiers': [], 'target': {'kind': 'uuid', 'store': 'fleet',
                                  'uuid': '0F3C2A1B4D5E6F708192A3B4C5D6E7F8'},
     'field': 'totp'},
    {'qualifiers': [], 'target': {'kind': 'path', 'store': 'fleet', 'segments': ['tab\there', 'ok @ mid']},
     'field': 'Notes'},
]


def references() -> dict:
    valid = []
    for text in VALID_REFERENCES:
        result = tp.parse(text)
        canonical = result.pop('canonical')
        assert tp.parse(canonical)['canonical'] == canonical, text
        valid.append({'input': text, 'parsed': result, 'canonical': canonical})
    invalid = []
    for text, reason in INVALID_REFERENCES:
        try:
            tp.parse(text)
        except tp.Malformed as e:
            assert e.reason == reason, (text, e.reason, reason)
            invalid.append({'input': text, 'reason': reason})
            continue
        raise AssertionError(f'{text!r} parsed')
    formats = []
    for parsed in FORMAT_CASES:
        text = tp.format_reference(parsed)
        back = tp.parse(text)
        formats.append({'parsed': parsed, 'formatted': text, 'reparsed': {
            k: back[k] for k in ('qualifiers', 'target', 'field', 'fieldGiven')}})
    return {'note': 'Each valid input with its parse result and canonical form (section 4.5); '
                    'each invalid input with its malformed reason (section 4.6); and formatting '
                    'cases from a parse result. A library must agree on all three.',
            'maxReferenceBytes': tp.MAX_REFERENCE_BYTES,
            'valid': valid, 'invalid': invalid, 'format': formats}


# --------------------------------------------------------------------------
# hmac.json
# --------------------------------------------------------------------------

def hmac_vectors() -> dict:
    cases = []
    example = admin_example()
    cases.append({'name': 'the challenge of frames.json', **{
        k: b64(v) if isinstance(v, bytes) else v for k, v in example.items()}})
    for i, start in enumerate([0, 1, 2 ** 53 - 1, 1794560400123]):
        key = derive(f'admin key {i}')
        sn = derive(f'service nonce {i}')
        an = derive(f'admin nonce {i}')
        cases.append({'name': f'case {i}', 'adminKey': b64(key), 'serviceNonce': b64(sn),
                      'adminNonce': b64(an), 'serviceStart': start,
                      'macInputHex': (b'tsm-admin-v1' + sn + an + start.to_bytes(8, 'big')).hex(),
                      'mac': b64(tp.admin_mac('tsm-admin-v1', key, sn, an, start)),
                      'mac2': b64(tp.admin_mac('tsm-service-v1', key, sn, an, start))})
    return {'note': 'The admin challenge of section 6.1: mac = HMAC-SHA256(adminKey, '
                    '"tsm-admin-v1" || serviceNonce || adminNonce || serviceStart as 8 bytes '
                    'big-endian), mac2 the same under "tsm-service-v1". Keys and nonces are '
                    'demo values derived from labels.', 'cases': cases}


# --------------------------------------------------------------------------
# discovery.json
# --------------------------------------------------------------------------

DISCOVERY = [
    ('linux', {'XDG_RUNTIME_DIR': '/run/user/1000'}, 1000),
    ('linux', {'XDG_RUNTIME_DIR': '/run/user/1000/'}, 1000),
    ('linux', {}, 1000),
    ('linux', {'XDG_RUNTIME_DIR': ''}, 1001),
    ('linux', {'XDG_RUNTIME_DIR': 'relative/dir'}, 1000),
    ('linux', {'XDG_RUNTIME_DIR': '/run/user/1000', 'TSM_RUNTIME_DIR': '/srv/tsm-test/'}, 1000),
    ('macos', {'TMPDIR': '/var/folders/zz/abc123/T/'}, 501),
    ('macos', {}, 501),
    ('macos', {'TMPDIR': '/var/folders/zz/abc123/T/', 'TSM_RUNTIME_DIR': '/Users/demo/tsm'}, 501),
    ('windows', {'LOCALAPPDATA': 'C:\\Users\\demo\\AppData\\Local'}, None),
    ('windows', {'LOCALAPPDATA': 'C:\\Users\\demo\\AppData\\Local\\'}, None),
    ('windows', {'USERPROFILE': 'C:\\Users\\demo'}, None),
    ('windows', {}, None),
    ('windows', {'LOCALAPPDATA': 'C:\\Users\\demo\\AppData\\Local', 'TSM_RUNTIME_DIR': 'D:\\tsm'}, None),
]

PORT_FILES = ['49152', '49152\n', '49152\r\n', '1', '65535', '0', '65536', '+80', ' 80', '080',
              '49152\n\n', '', 'abc']


def discovery() -> dict:
    cases = [{'os': os_name, 'env': env, 'uid': uid, 'expect': tp.discover(os_name, env, uid)}
             for os_name, env, uid in DISCOVERY]
    ports = []
    for text in PORT_FILES:
        try:
            ports.append({'text': text, 'port': tp.read_port_file(text)})
        except ValueError:
            ports.append({'text': text, 'port': None})
    return {'note': 'Where a library looks for the service (section 3): per OS, environment '
                    'and uid. A missing socket or port file there is not_running. Port files '
                    'with the port each yields, or null when the file is unreadable '
                    '(not_running).', 'cases': cases, 'portFiles': ports}


def main() -> None:
    VECTORS.mkdir(exist_ok=True)
    write('frames.json', frames())
    write('references.json', references())
    write('hmac.json', hmac_vectors())
    write('discovery.json', discovery())
    print(f'{VECTORS}: frames.json, references.json, hmac.json, discovery.json')


if __name__ == '__main__':
    main()
