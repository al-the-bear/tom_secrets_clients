// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// SecretValue: read from a value message, masked in every printable form,
// binary refused as text, overwritten by dispose. Demo data only.

import * as assert from 'node:assert/strict';
import { test } from 'node:test';
import { inspect } from 'node:util';

import { SecretsError, SecretValue, errorKindFromWire } from '../src/index';

const message = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  op: 'value',
  id: 1,
  encoding: 'utf8',
  value: 'demo-secret-value',
  entry: { store: 'fleet', uuid: '0123456789abcdef0123456789abcdef', source: 'github', fetchedAt: '2026-11-10T12:00:00.000Z' },
  bound: { env: 'prod' },
  version: { modified: '2026-11-01T08:30:00+01:00', revision: 'r42' },
  ...over,
});

test('a value message is read with its entry, bindings and version', () => {
  const v = SecretValue.fromMessage('fleet/Db/Main', message({ expires: '2027-01-01T00:00:00Z', clientToken: 'ct' }));
  assert.equal(v.text, 'demo-secret-value');
  assert.equal(v.encoding, 'utf8');
  assert.equal(v.entry.store, 'fleet');
  assert.equal(v.entry.source, 'github');
  assert.equal(v.entry.fetchedAt.getTime(), Date.UTC(2026, 10, 10, 12));
  assert.deepEqual({ ...v.bound }, { env: 'prod' });
  assert.equal(v.version.modified.getTime(), Date.UTC(2026, 10, 1, 7, 30));
  assert.equal(v.version.revision, 'r42');
  assert.equal(v.expires?.getTime(), Date.UTC(2027, 0, 1));
  assert.equal(v.clientToken, 'ct');
});

test('every printable form shows *** and never the value', () => {
  const v = SecretValue.fromMessage('fleet/Db/Main', message());
  for (const printed of [String(v), `${v}`, JSON.stringify(v), inspect(v), inspect({ nested: v })]) {
    assert.ok(printed.includes('***'), printed);
    assert.ok(!printed.includes('demo-secret-value'), printed);
  }
});

test('a binary value is refused as text and read as bytes', () => {
  const v = SecretValue.fromMessage('fleet/Key', message({ encoding: 'base64', value: Buffer.from([0, 255, 1]).toString('base64') }));
  assert.throws(() => v.text, /binary/);
  assert.deepEqual([...v.bytes], [0, 255, 1]);
});

test('dispose overwrites the buffer; the value cannot be read afterwards', () => {
  const v = SecretValue.fromMessage('fleet/Db/Main', message());
  const view = v.bytes;
  v.dispose();
  assert.ok(v.isDisposed);
  assert.ok(view.every((b) => b === 0));
  assert.throws(() => v.text, /disposed/);
  assert.throws(() => v.bytes, /disposed/);
});

test('an unknown source is cache; a message missing members is internal', () => {
  const v = SecretValue.fromMessage('r', message({ entry: { store: 's', uuid: 'u', source: 'later', fetchedAt: '2026-11-10T12:00:00Z' } }));
  assert.equal(v.entry.source, 'cache');
  assert.throws(
    () => SecretValue.fromMessage('r', message({ version: undefined })),
    (e: unknown) => e instanceof SecretsError && e.kind === 'internal',
  );
  assert.throws(
    () => SecretValue.fromMessage('r', message({ encoding: 'base64', value: 'not base64!' })),
    (e: unknown) => e instanceof SecretsError && e.kind === 'internal',
  );
});

test('error kinds: an unknown kind is internal, not_running is never the service\'s', () => {
  assert.equal(errorKindFromWire('locked'), 'locked');
  assert.equal(errorKindFromWire('later_kind'), 'internal');
  assert.equal(errorKindFromWire('not_running'), 'internal');
  const e = SecretsError.fromError({ op: 'error', kind: 'malformed', message: 'm', details: { reason: 'bad_key' } });
  assert.equal(e.reason, 'bad_key');
  assert.ok(e instanceof Error);
});
