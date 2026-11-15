#!/usr/bin/env python3
# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""Writes protocol/schema/: one JSON Schema (draft 2020-12) per message of
protocol.md, plus common.json with the shared definitions.

    protocol/tool/gen_schemas.py

The schemas are generated so that every message is written once, here, in
the order of protocol.md; check_protocol.py validates every vector frame
against the schema its `op` names. Run by hand after changing a message.
"""
from __future__ import annotations

import json
import pathlib

SCHEMA_DIR = pathlib.Path(__file__).resolve().parent.parent / 'schema'
BASE = 'https://raw.githubusercontent.com/al-the-bear/tom_secrets_clients/main/protocol/schema/'
DRAFT = 'https://json-schema.org/draft/2020-12/schema'


def ref(name: str) -> dict:
    return {'$ref': f'common.json#/$defs/{name}'}


STR = {'type': 'string'}
BOOL = {'type': 'boolean'}
INT0 = {'type': 'integer', 'minimum': 0}

COMMON = {
    'id': {'description': 'A request id, chosen by the client, unique among its open requests.',
           'type': 'integer', 'minimum': 1, 'maximum': 9007199254740991},
    'base64': {'type': 'string', 'pattern': r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'},
    'base64_32': {'description': '32 bytes, standard base64 with padding.',
                  'type': 'string', 'pattern': r'^[A-Za-z0-9+/]{43}=$'},
    'timestamp': {'description': 'RFC 3339 date-time in UTC with a Z.',
                  'type': 'string',
                  'pattern': r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$'},
    'epochMs': {'description': 'Milliseconds since the Unix epoch.', 'type': 'integer', 'minimum': 0},
    'storeName': {'type': 'string', 'pattern': r'^[a-z0-9][a-z0-9_-]*$', 'maxLength': 64},
    'dimensionName': {'type': 'string', 'pattern': r'^[a-z][a-z0-9_-]*$', 'maxLength': 64},
    'uuid': {'description': 'A KDBX entry UUID, 32 lower-case hex digits.',
             'type': 'string', 'pattern': r'^[0-9a-f]{32}$'},
    'reference': {'description': 'A reference (section 4), at most 1 KiB of UTF-8.',
                  'type': 'string', 'minLength': 1, 'maxLength': 1024},
    'dimensions': {'description': 'Dimension values passed beside a reference.',
                   'type': 'object',
                   'propertyNames': {'$ref': '#/$defs/dimensionName'},
                   'additionalProperties': {'type': 'string', 'minLength': 1}},
    'platform': {'enum': ['macos', 'linux', 'windows', 'ios', 'android']},
    'clientInfo': {'type': 'object', 'required': ['name', 'version', 'language'],
                   'properties': {'name': {'type': 'string', 'maxLength': 256},
                                  'version': {'type': 'string', 'maxLength': 64},
                                  'language': {'type': 'string', 'maxLength': 32}}},
    'errorKind': {'enum': ['locked', 'denied', 'not_found', 'ambiguous', 'needs_unlock',
                           'unavailable', 'offline', 'token_expired', 'malformed', 'timeout',
                           'rate_limited', 'unsupported', 'internal']},
    'entryLocation': {'type': 'object', 'required': ['store', 'path', 'uuid'],
                      'properties': {'store': {'$ref': '#/$defs/storeName'}, 'path': STR,
                                     'uuid': {'$ref': '#/$defs/uuid'}}},
    'storeState': {'enum': ['current', 'offline', 'token_expired', 'needs_unlock', 'unavailable']},
    'source': {'enum': ['github', 'file', 'cache']},
    'decision': {'enum': ['once', 'always', 'folder', 'never']},
    'secretScope': {'description': 'What a decision covers: the reference, its store, or all.',
                    'enum': ['ref', 'store', 'all']},
    'pin': {'description': 'hash: pinned; off: by path; relaxed: accept changes until relaxedUntil.',
            'oneOf': [{'enum': ['hash', 'off']},
                      {'type': 'object', 'required': ['relaxedUntil'],
                       'properties': {'relaxedUntil': {'$ref': '#/$defs/timestamp'}},
                       'additionalProperties': False}]},
    'identity': {'description': 'The measured identity of a peer process (section 7.1).',
                 'type': 'object', 'required': ['kind', 'exe', 'args', 'cwd', 'uid'],
                 'properties': {
                     'kind': {'enum': ['exe', 'script', 'interpreter']},
                     'exe': STR, 'exeHash': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
                     'interpreter': STR, 'script': STR,
                     'scriptHash': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
                     'packageRoot': STR, 'args': {'type': 'array', 'items': STR}, 'cwd': STR,
                     'parent': {'type': 'object', 'required': ['exe'],
                                'properties': {'exe': STR, 'args': {'type': 'array', 'items': STR}}},
                     'uid': {'type': ['integer', 'string']}}},
    'keyId': {'description': 'An approver key id (section 9.2): 16 bytes in lower-case hex.',
              'type': 'string', 'pattern': '^[0-9a-f]{32}$'},
    'signature': {'description': 'One item of a signature list (section 9.3); an item of an '
                                 'unknown alg is ignored.',
                  'type': 'object', 'required': ['alg', 'keyId', 'sig'],
                  'properties': {'alg': STR, 'keyId': {'$ref': '#/$defs/keyId'},
                                 'sig': {'$ref': '#/$defs/base64'}}},
    'signatures': {'description': 'A signature list: for a recorded approver key, an ed25519 '
                                  'and an ml-dsa-65 item (section 9.3).',
                   'type': 'array', 'minItems': 2, 'items': {'$ref': '#/$defs/signature'}},
    'grant': {'description': 'A grant of the allow list (section 7.3).',
              'type': 'object',
              'required': ['id', 'host', 'subject', 'secret', 'decision', 'created', 'pin',
                           'approver', 'signatures'],
              'properties': {
                  'id': STR, 'host': STR, 'subject': STR,
                  'secret': {'description': 'A canonical reference, "store <name>" or "all".', **STR},
                  'decision': {'enum': ['allow', 'never']},
                  'created': {'$ref': '#/$defs/timestamp'},
                  'lastUsed': {'$ref': '#/$defs/timestamp'},
                  'pin': {'$ref': '#/$defs/pin'}, 'approver': STR,
                  'signatures': {'$ref': '#/$defs/signatures'}}},
    'revocation': {'description': 'A signed revocation (section 9.4).',
                   'type': 'object',
                   'required': ['host', 'grantId', 'revoked', 'approver', 'signatures'],
                   'properties': {'host': STR, 'grantId': STR,
                                  'revoked': {'$ref': '#/$defs/timestamp'}, 'approver': STR,
                                  'signatures': {'$ref': '#/$defs/signatures'}}},
    'approvalRecord': {'description': 'A signed approval record in tsm.grants/<host>: the '
                                      'answer to a waiting approval code (section 9.4).',
                       'type': 'object',
                       'required': ['host', 'code', 'decision', 'approver', 'created',
                                    'signatures'],
                       'properties': {'host': STR,
                                      'code': {'type': 'string', 'pattern': '^[A-Z2-7]{10}$'},
                                      'decision': {'$ref': '#/$defs/decision'}, 'approver': STR,
                                      'created': {'$ref': '#/$defs/timestamp'},
                                      'signatures': {'$ref': '#/$defs/signatures'}}},
    'keyChange': {'description': 'A key-change statement, signed by the old and the new '
                                 'approver key (section 9.4).',
                  'type': 'object',
                  'required': ['device', 'oldKeyId', 'newKeyId', 'newEd25519', 'newMlDsa65',
                               'time', 'signatures'],
                  'properties': {'device': STR, 'oldKeyId': {'$ref': '#/$defs/keyId'},
                                 'newKeyId': {'$ref': '#/$defs/keyId'},
                                 'newEd25519': {'$ref': '#/$defs/base64_32'},
                                 'newMlDsa65': {'$ref': '#/$defs/base64'},
                                 'time': {'$ref': '#/$defs/timestamp'},
                                 'signatures': {'type': 'array', 'minItems': 4,
                                                'items': {'$ref': '#/$defs/signature'}}}},
}

# (op, endpoint, direction, phase, description, required, properties)
# direction: c2s client to service, s2c service to client, a2s admin to
# service, s2a service to admin; on the approval link (section 9.7) a2h approver
# to host, h2a host to approver, both either side. `also` names further
# endpoints a message is used on with the same members.
MESSAGES = []


def message(op, endpoint, direction, phase, description, required=(), also=(), **properties):
    MESSAGES.append((op, endpoint, direction, phase, description, list(required), list(also),
                     properties))


# ---- client endpoint (section 5) ----------------------------------------
message('hello', 'client', 'c2s', 'A', 'The first frame of a client connection.',
        ['protocol', 'client'],
        protocol={'type': 'integer', 'minimum': 1}, client=ref('clientInfo'),
        token={'description': 'Windows: the text of client.token.', **ref('base64_32')},
        clientToken=ref('base64_32'),
        features={'description': '[B] The optional features the client takes (section 8).',
                  'type': 'array', 'items': STR, 'uniqueItems': True})
message('welcome', 'client', 's2c', 'A', 'The answer to hello.',
        ['protocol', 'service', 'features', 'host', 'platform'],
        protocol={'type': 'integer', 'minimum': 1},
        service={'type': 'object', 'required': ['version'], 'properties': {'version': STR}},
        features={'type': 'array', 'items': STR, 'uniqueItems': True},
        host=STR, platform=ref('platform'))
GET_FIELDS = dict(ref=ref('reference'), dimensions=ref('dimensions'),
                  field={'type': 'string', 'minLength': 1})
message('get', 'client', 'c2s', 'A', 'Read one secret.', ['id', 'ref'],
        id=ref('id'), **GET_FIELDS, wait=BOOL, timeoutMs=INT0, wantClientToken=BOOL)
VALUE_FIELDS = dict(
    value=STR, encoding={'enum': ['utf8', 'base64']},
    entry={'type': 'object', 'required': ['store', 'uuid', 'source', 'fetchedAt'],
           'properties': {'store': ref('storeName'), 'uuid': ref('uuid'),
                          'source': ref('source'), 'fetchedAt': ref('timestamp')}},
    bound={'type': 'object', 'propertyNames': ref('dimensionName'),
           'additionalProperties': STR},
    version={'type': 'object', 'required': ['modified', 'revision'],
             'properties': {'modified': ref('timestamp'), 'revision': STR}},
    expires=ref('timestamp'), clientToken=ref('base64_32'))
VALUE_REQUIRED = ['value', 'encoding', 'entry', 'bound', 'version']
message('value', 'client', 's2c', 'A', 'The answer to get: the value and where it came from.',
        ['id', *VALUE_REQUIRED], id=ref('id'), **VALUE_FIELDS)
message('getMany', 'client', 'c2s', 'A', 'Read several secrets under one approval.',
        ['id', 'refs'], id=ref('id'),
        refs={'type': 'array', 'minItems': 1, 'maxItems': 256,
              'items': {'type': 'object', 'required': ['ref'], 'properties': GET_FIELDS}},
        wait=BOOL, timeoutMs=INT0)
ERROR_FIELDS = dict(kind=ref('errorKind'), message={'type': 'string', 'maxLength': 1024},
                    details={'type': 'object'})
message('values', 'client', 's2c', 'A', 'The answer to getMany, results in request order.',
        ['id', 'results'], id=ref('id'),
        results={'type': 'array', 'items': {'oneOf': [
            {'type': 'object', 'required': ['op', *VALUE_REQUIRED],
             'properties': {'op': {'const': 'value'}, **VALUE_FIELDS}},
            {'type': 'object', 'required': ['op', 'kind', 'message'],
             'properties': {'op': {'const': 'error'}, **ERROR_FIELDS}}]}})
message('progress', 'client', 's2c', 'A', 'A request started waiting.', ['id', 'pending'],
        id=ref('id'), pending={'enum': ['unlock', 'approval']},
        approvalCode={'type': 'string', 'pattern': '^[A-Z2-7]{10}$'})
message('error', 'any', 's2c', 'A', 'A request failed, or a connection is refused.',
        ['kind', 'message'], id=ref('id'), **ERROR_FIELDS)
message('getFile', 'client', 'c2s', 'B', 'Read an attachment or typed key as binary chunks.',
        ['id', 'ref'], id=ref('id'), **GET_FIELDS, wait=BOOL, timeoutMs=INT0)
message('file', 'client', 's2c', 'B', 'The start of a getFile answer.', ['id', 'name', 'size'],
        id=ref('id'), name=STR, size=INT0)
message('end', 'client', 's2c', 'B', 'The end of a getFile answer, after its binary chunks.',
        ['id', 'sha256'], id=ref('id'), sha256={'type': 'string', 'pattern': '^[0-9a-f]{64}$'})
message('match', 'client', 'c2s', 'B', 'Logins matching a page (browser host, helpers).',
        ['id', 'url'], id=ref('id'), url=STR, frameUrl=STR)
message('matches', 'client', 's2c', 'B', 'The answer to match: candidates, never a value.',
        ['id', 'candidates'], id=ref('id'),
        candidates={'type': 'array', 'items': {
            'type': 'object', 'required': ['entryId', 'title', 'userName', 'matchedUrl', 'hasTotp'],
            'properties': {'entryId': STR, 'title': STR, 'userName': STR, 'matchedUrl': STR,
                           'hasTotp': BOOL}}})
message('propose', 'client', 'c2s', 'B', 'A login for the app to save (browser host).',
        ['id', 'url', 'userName', 'password'], id=ref('id'), url=STR, title=STR,
        userName=STR, password=STR)
message('accepted', 'client', 's2c', 'B', 'The answer to propose.', ['id'], id=ref('id'))

# ---- admin endpoint (section 6) -----------------------------------------
message('challenge', 'admin', 's2a', 'A', 'The first frame of an admin connection.',
        ['serviceNonce', 'serviceStart', 'protocol', 'service'],
        serviceNonce=ref('base64_32'), serviceStart=ref('epochMs'),
        protocol={'type': 'integer', 'minimum': 1},
        service={'type': 'object', 'required': ['version'], 'properties': {'version': STR}})
message('auth', 'admin', 'a2s', 'A', 'The admin proves it holds the admin key.',
        ['adminNonce', 'mac', 'client'], adminNonce=ref('base64_32'), mac=ref('base64_32'),
        client=ref('clientInfo'))
message('authed', 'admin', 's2a', 'A', 'The service proves it holds the admin key.',
        ['mac2'], mac2=ref('base64_32'))
message('claim', 'admin', 'a2s', 'A', 'Sent instead of auth by an admin without the key.',
        ['password', 'client'], password=STR, keyFile=ref('base64'), client=ref('clientInfo'))
message('claimed', 'admin', 's2a', 'A', 'The new admin key after a successful claim.',
        ['adminKey'], adminKey=ref('base64_32'))
message('ok', 'admin', 's2a', 'A', 'An admin request succeeded and has nothing to return.',
        ['id'], also=['link'], id=ref('id'))
message('unlock', 'admin', 'a2s', 'A', 'Open the primary file and the stores (phase A), or '
        'a vault with a sealed key bundle (phase B).', ['id'], id=ref('id'),
        password=STR, keyFile=ref('base64'), vault=STR,
        bundle={'type': 'object', 'required': ['nonce', 'ciphertext'],
                'properties': {'nonce': ref('base64'), 'ciphertext': ref('base64')}})
message('unlockStore', 'admin', 'a2s', 'A', 'Open a store that has its own password.',
        ['id', 'store', 'password'], id=ref('id'), store=ref('storeName'), password=STR,
        keyFile=ref('base64'))
message('lock', 'admin', 'a2s', 'A', 'Lock: clear every secret from memory.', ['id'], id=ref('id'))
message('shutdown', 'admin', 'a2s', 'A', 'Lock and stop the service.', ['id'], id=ref('id'))
REWRITTEN = {'description': 'The branch was rewritten without a compaction: the head of the '
             'rewritten branch, until the manager app answers with history.resolve (section 6.4).',
             'type': 'object', 'required': ['head'], 'properties': {'head': STR}}
STORE_STATUS = {'type': 'object', 'required': ['name', 'state', 'source', 'notPushed'],
                'properties': {'name': ref('storeName'), 'state': ref('storeState'),
                               'source': ref('source'), 'fetchedAt': ref('timestamp'),
                               'notPushed': INT0, 'rewritten': REWRITTEN}}
EXPIRING_KEY = {'type': 'object', 'required': ['kind', 'key', 'expiresAt', 'daysLeft'],
                'properties': {'kind': {'enum': ['github_token', 'vault_keys',
                                                 'approver_key', 'link_key']},
                               'key': STR, 'vault': ref('storeName'),
                               'expiresAt': ref('timestamp'),
                               'daysLeft': {'type': 'integer'}}}
message('status', 'admin', 'a2s', 'A', 'Ask for the service state.', ['id'], id=ref('id'))
message('statusReport', 'admin', 's2a', 'A', 'The answer to status.',
        ['id', 'locked', 'lockMode', 'protocol', 'service', 'stores', 'admins', 'hardening'],
        id=ref('id'), locked=BOOL, lockMode={'enum': ['a', 'b', 'c']},
        protocol={'type': 'integer', 'minimum': 1},
        service={'type': 'object', 'required': ['version', 'start'],
                 'properties': {'version': STR, 'start': ref('epochMs')}},
        stores={'type': 'array', 'items': STORE_STATUS}, admins=INT0,
        hardening={'type': 'object', 'additionalProperties': BOOL},
        expiring={'type': 'array', 'items': EXPIRING_KEY})
message('reload', 'admin', 'a2s', 'A', 'Fetch and reopen the stores now.', ['id'], id=ref('id'))
message('vaultKeys', 'admin', 'a2s', 'A', 'Get the keys of the open vaults for editing.',
        ['id'], id=ref('id'), stores={'type': 'array', 'items': ref('storeName')})
message('vaultKeySet', 'admin', 's2a', 'A', 'The answer to vaultKeys.', ['id', 'stores'],
        id=ref('id'),
        unserved={'description': 'The further vaults the primary lists that this machine does '
                  'not serve (section 6.4): editable by name, never served to clients.',
                  'type': 'array', 'items': {
                      'type': 'object', 'required': ['store', 'location'],
                      'properties': {'store': ref('storeName'), 'location': STR}}},
        stores={'type': 'array', 'items': {
            'type': 'object', 'required': ['store', 'location', 'keys'],
            'properties': {'store': ref('storeName'), 'location': STR,
                           'served': {'description': 'false for a vault this machine does '
                                      'not serve, opened for editing only (section 6.4).',
                                      'type': 'boolean'},
                           'keys': {'description': 'The store key material (section 6.4): '
                                    'its master password, key file and repository outer key, '
                                    'each when the store has one.',
                                    'type': 'object',
                                    'properties': {'password': STR,
                                                   'keyFile': ref('base64'),
                                                   'outerKey': ref('base64')}}}}})
message('vaultFile', 'admin', 'a2s', 'A', 'Get the copy of a store the service holds, for editing: an open store, or a vault the primary lists that this machine does not serve.',
        ['id', 'store'], id=ref('id'), store=ref('storeName'))
message('vaultFileData', 'admin', 's2a', 'A', 'The answer to vaultFile.',
        ['id', 'store', 'location', 'revision', 'bytes'], id=ref('id'), store=ref('storeName'),
        location=STR, revision=STR, bytes=ref('base64'),
        served={'description': 'false for a vault this machine does not serve (section 6.4).',
                'type': 'boolean'})
message('save', 'admin', 'a2s', 'A', 'Hand an edited store file to the service to write.',
        ['id', 'store', 'bytes'], id=ref('id'), store=ref('storeName'), bytes=ref('base64'),
        baseRevision=STR,
        keys={'description': 'The primary\'s new keys when its file is re-keyed (section 6.4).',
              'type': 'object', 'required': ['password'],
              'properties': {'password': STR, 'keyFile': ref('base64'),
                             'outerKey': ref('base64')}})
message('vault.move', 'admin', 'a2s', 'A',
        'Add or remove a store\'s outer encryption, moving it (the manager app only).',
        ['id', 'store', 'location', 'bytes', 'keys'], id=ref('id'), store=ref('storeName'),
        location=STR, bytes=ref('base64'), baseRevision=STR,
        keys={'type': 'object', 'required': ['password'],
              'properties': {'password': STR, 'keyFile': ref('base64'),
                             'outerKey': ref('base64')}})
message('subscribe', 'admin', 'a2s', 'A', 'Start the event stream on this connection.',
        ['id'], id=ref('id'))
message('approve', 'admin', 'a2s', 'A', 'The answer to an approval prompt.',
        ['id', 'approvalId', 'decision', 'secret'], also=['link'], id=ref('id'), approvalId=STR,
        decision=ref('decision'), secret=ref('secretScope'), folder=STR, pin=ref('pin'),
        clientToken=ref('base64'))
message('approval.redeem', 'admin', 'a2s', 'A', 'Redeem a one-time approval token.',
        ['id', 'token'], id=ref('id'),
        token={'type': 'string', 'pattern': '^[A-Z2-7]{26}$'})
message('approval.issue', 'admin', 'a2s', 'A', 'Have the approver key make a token for a code.',
        ['id', 'host', 'code', 'decision', 'secret'], id=ref('id'), host=STR,
        code={'type': 'string', 'pattern': '^[A-Z2-7]{10}$'}, decision=ref('decision'),
        secret=ref('secretScope'), pin=ref('pin'))
message('approvalToken', 'admin', 's2a', 'A', 'The answer to approval.issue.',
        ['id', 'token'], id=ref('id'), token={'type': 'string', 'pattern': '^[A-Z2-7]{26}$'})
message('grants.list', 'admin', 'a2s', 'A', 'List the allow list, of one host or all.',
        ['id'], id=ref('id'), host=STR)
message('grantList', 'admin', 's2a', 'A', 'The answer to grants.list.', ['id', 'grants'],
        id=ref('id'), grants={'type': 'array', 'items': ref('grant')})
message('grants.add', 'admin', 'a2s', 'A', 'Add a grant (a pre-approval for another host).',
        ['id', 'grant'], id=ref('id'),
        grant={'description': 'The grant without id, created, approver and signatures, '
               'which the service fills in and signs.',
               'type': 'object', 'required': ['host', 'subject', 'secret', 'decision'],
               'properties': {'host': STR, 'subject': STR, 'secret': STR,
                              'decision': {'enum': ['allow', 'never']}, 'pin': ref('pin')}})
message('grants.revoke', 'admin', 'a2s', 'A', 'Revoke a grant of any host.',
        ['id', 'host', 'grantId'], id=ref('id'), host=STR, grantId=STR)
message('approvers.cliSwitch', 'admin', 'a2s', 'A', 'Switch command-line approvals on or off.',
        ['id', 'on'], id=ref('id'), on=BOOL)
message('approvals.list', 'admin', 'a2s', 'A', 'List the requests waiting on this host.',
        ['id'], id=ref('id'))
message('approvalList', 'admin', 's2a', 'A', 'The answer to approvals.list.',
        ['id', 'approvals'], id=ref('id'),
        approvals={'type': 'array', 'items': {
            'type': 'object', 'required': ['approvalId', 'host', 'identity', 'refs'],
            'properties': {'approvalId': STR, 'host': STR, 'identity': ref('identity'),
                           'refs': {'type': 'array', 'items': ref('reference')},
                           'approvalCode': STR}}})
message('keys', 'admin', 'a2s', 'A', 'List every key with its due date.', ['id'], id=ref('id'))
message('keyList', 'admin', 's2a', 'A', 'The answer to keys.', ['id', 'keys'], id=ref('id'),
        keys={'type': 'array', 'items': {
            'type': 'object',
            'required': ['kind', 'key', 'expiresAt', 'daysLeft', 'reminding'],
            'properties': {**EXPIRING_KEY['properties'], 'reminding': BOOL,
                           'own': BOOL}}})
message('keys.rotate', 'admin', 'a2s', 'A',
        'Rotate this device\'s own key pairs (the manager app only).',
        ['id'], id=ref('id'), approver=BOOL, link=BOOL)
message('keysRotated', 'admin', 's2a', 'A', 'The answer to keys.rotate.',
        ['id', 'resigned', 'delivered', 'pending'], id=ref('id'), approverKeyId=STR,
        resigned=INT0, delivered={'type': 'array', 'items': STR},
        pending={'type': 'array', 'items': STR})
message('compact', 'admin', 'a2s', 'A', 'Cut the history of a vault repository now.',
        ['id', 'repository'], id=ref('id'),
        repository={'type': 'string', 'pattern': '^[^/\\s]+/[^/\\s]+$'},
        retentionDays={'description': 'Replaces the repository\'s retention: 0 after a key '
                       'change (section 6.4).', **INT0})
message('compacted', 'admin', 's2a', 'A', 'The answer to compact.',
        ['id', 'repository', 'compacted', 'oldHead', 'newHead', 'kept'], id=ref('id'),
        repository=STR, compacted=BOOL, oldHead=STR, newHead=STR, kept=INT0)
message('history.resolve', 'admin', 'a2s', 'A',
        'Answer a branch rewritten without a compaction (the manager app only).',
        ['id', 'store', 'take'], id=ref('id'), store=ref('storeName'),
        take={'enum': ['remote', 'merge']})
message('token.set', 'admin', 'a2s', 'A',
        'Renew the GitHub token of a vault repository (the manager app only).',
        ['id', 'repository', 'token'], id=ref('id'),
        repository={'type': 'string', 'pattern': '^[^/\\s]+/[^/\\s]+$'}, token=STR)
message('tokenSet', 'admin', 's2a', 'A', 'The answer to token.set.',
        ['id', 'repository', 'where'], id=ref('id'), repository=STR,
        where={'enum': ['keychain', 'primary']}, expiresAt=STR)
message('settings.get', 'admin', 'a2s', 'A', 'Read the device settings.', ['id'],
        id=ref('id'))
message('deviceSettings', 'admin', 's2a', 'A', 'The answer to settings.get.',
        ['id', 'device', 'cliApprovals', 'stores'], id=ref('id'),
        device={'description': 'The device settings (section 6.3), each member when set.',
                'type': 'object'},
        cliApprovals=BOOL,
        stores={'type': 'array', 'items': ref('storeName')})
message('settings.set', 'admin', 'a2s', 'A', 'Write the device settings (the manager app only).',
        ['id', 'device'], id=ref('id'),
        device={'description': 'The whole device settings (section 6.3).', 'type': 'object'})
message('audit.query', 'admin', 'a2s', 'A', 'Read the audit log.', ['id', 'from', 'to'],
        id=ref('id'), **{'from': ref('timestamp')}, to=ref('timestamp'), subject=STR,
        ref=ref('reference'))
message('auditRecords', 'admin', 's2a', 'A', 'The answer to audit.query.', ['id', 'records'],
        id=ref('id'),
        records={'type': 'array', 'items': {
            'type': 'object', 'required': ['time', 'host', 'identity', 'refs', 'outcome'],
            'properties': {'time': ref('timestamp'), 'host': STR, 'identity': ref('identity'),
                           'refs': {'type': 'array', 'items': ref('reference')},
                           'outcome': {'enum': ['allowed', 'denied', 'not_found', 'ambiguous',
                                                'locked', 'timeout', 'abandoned',
                                                'rate_limited', 'unavailable', 'malformed']},
                           'grantId': STR, 'approver': STR}}})
# events, pushed after subscribe (section 6.5)
message('unlock_needed', 'admin', 's2a', 'A', 'A client waits for an unlock.', [],
        identity=ref('identity'))
message('approval_needed', 'admin', 's2a', 'A', 'A request needs an approval.',
        ['approvalId', 'host', 'identity', 'refs', 'resolved'], also=['link'], approvalId=STR, host=STR,
        identity=ref('identity'), refs={'type': 'array', 'items': ref('reference')},
        resolved={'type': 'array', 'items': {
            'type': 'object', 'required': ['store', 'path', 'kind'],
            'properties': {'store': ref('storeName'), 'path': STR, 'kind': STR}}},
        hostHint=STR, approvalCode={'type': 'string', 'pattern': '^[A-Z2-7]{10}$'},
        wantClientToken=BOOL)
message('approval_closed', 'admin', 's2a', 'A', 'A prompt was answered or ended elsewhere.',
        ['approvalId', 'outcome'], also=['link'], approvalId=STR,
        outcome={'enum': ['approved', 'denied', 'timeout', 'abandoned', 'no_approver']})
message('locked', 'admin', 's2a', 'A', 'The service locked.')
message('unlocked', 'admin', 's2a', 'A', 'The service unlocked.')
message('store_changed', 'admin', 's2a', 'A', 'A store was reopened with new content.',
        ['store'], store=ref('storeName'), revision=STR)
message('store_state', 'admin', 's2a', 'A', 'A store changed state.',
        ['store', 'state', 'source', 'notPushed'], store=ref('storeName'),
        state=ref('storeState'), source=ref('source'), fetchedAt=ref('timestamp'),
        notPushed=INT0, rewritten=REWRITTEN)
message('key_expiry', 'admin', 's2a', 'A', 'A key the product rotates expires soon.',
        ['key', 'expiresAt', 'daysLeft'], key=STR, expiresAt=ref('timestamp'),
        daysLeft={'type': 'integer'})
message('rate_limited', 'admin', 's2a', 'A', 'An identity is held back.',
        ['identity', 'until'], identity=ref('identity'), until=ref('timestamp'))
message('proposal', 'admin', 's2a', 'B', 'A login the browser host proposed.',
        ['url', 'userName', 'password'], url=STR, title=STR, userName=STR, password=STR)

# ---- the approval link (section 9.7) -------------------------------------
message('ready', 'link', 'a2h', 'A', 'The approver\'s first transport frame; confirms the '
        'handshake.')
message('rekey', 'link', 'both', 'A', 'The sender renews its sending key after this frame.')
message('grant', 'link', 'a2h', 'A', 'A signed grant for the host to apply at once; with '
        'approvalId it answers that waiting request, with clientToken it brings the token of '
        'its exe-token subject (section 7.4).',
        ['id', 'grant'], id=ref('id'), grant=ref('grant'), clientToken=ref('base64'),
        approvalId=STR)
message('revoke', 'link', 'a2h', 'A', 'A signed revocation for the host to apply at once.',
        ['id', 'host', 'grantId', 'revoked', 'approver', 'signatures'], id=ref('id'), host=STR,
        grantId=STR, revoked=ref('timestamp'), approver=STR, signatures=ref('signatures'))
message('keychange', 'link', 'a2h', 'A', 'A key-change statement of the approver key.',
        ['id', 'statement'], id=ref('id'), statement=ref('keyChange'))
message('linkKey', 'link', 'both', 'A', 'The sender\'s new approval-link public key.',
        ['id', 'device', 'x25519', 'mlKem768'], id=ref('id'), device=STR,
        x25519=ref('base64_32'),
        mlKem768={'description': '1,184 bytes, standard base64.', **ref('base64')})


def schema_for(op, endpoint, direction, phase, description, required, also, properties):
    props = {'op': {'const': op}, **properties}
    return {
        '$schema': DRAFT,
        '$id': BASE + f'{op}.json',
        'title': op,
        'description': f'{description} Endpoint: {endpoint}'
                       f'{"".join(", " + a for a in also)}; direction: {direction}; '
                       f'phase {phase}. Unknown members are ignored by the reader '
                       '(protocol.md section 8).',
        'type': 'object',
        'required': ['op', *required],
        'properties': props,
        'x-tsm': {'endpoint': endpoint, 'direction': direction, 'phase': phase,
                  **({'alsoOn': also} if also else {})},
    }


def main() -> None:
    SCHEMA_DIR.mkdir(exist_ok=True)
    for old in SCHEMA_DIR.glob('*.json'):
        old.unlink()
    common = {'$schema': DRAFT, '$id': BASE + 'common.json', 'title': 'common',
              'description': 'Definitions shared by the message schemas.', '$defs': COMMON}
    (SCHEMA_DIR / 'common.json').write_text(json.dumps(common, indent=2) + '\n')
    for m in MESSAGES:
        (SCHEMA_DIR / f'{m[0]}.json').write_text(json.dumps(schema_for(*m), indent=2) + '\n')
    print(f'{SCHEMA_DIR}: common.json and {len(MESSAGES)} message schemas')


if __name__ == '__main__':
    main()
