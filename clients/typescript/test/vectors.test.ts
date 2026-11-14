// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The library against every vector of protocol/vectors/ that a client
// computes: references (parse, canonical form, malformed reasons,
// formatting), discovery and port files, and the frames of the client
// endpoint.

import * as assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';

import {
  decodePayload,
  FrameError,
  FrameReader,
  frameBinary,
  frameJson,
  jsonFrame,
  maxAnswerPayload,
  maxRequestPayload,
  type Message,
} from '../src/frames';
import {
  discover,
  maxReferenceBytes,
  protocolVersion,
  readPortFile,
  SecretReference,
  SecretsError,
  type SecretTarget,
} from '../src/index';

type Json = Record<string, unknown>;

// Compiled to build/test/: the package root is two levels up.
const root = join(__dirname, '..', '..');

function vectors(name: string): Json {
  return JSON.parse(readFileSync(join(root, '..', '..', 'protocol', 'vectors', name), 'utf8')) as Json;
}

const hex = (text: string): Buffer => Buffer.from(text, 'hex');

function shape(r: SecretReference): Json {
  return {
    qualifiers: r.qualifiers.map((q) => ({ dimension: q.dimension, value: q.value })),
    target: r.target,
    field: r.field,
    fieldGiven: r.fieldGiven,
  };
}

function fromShape(m: Json): SecretReference {
  const t = m['target'] as Json;
  const target: SecretTarget =
    t['kind'] === 'key'
      ? { kind: 'key', key: t['key'] as string }
      : t['kind'] === 'uuid'
        ? { kind: 'uuid', store: t['store'] as string, uuid: t['uuid'] as string }
        : { kind: 'path', store: t['store'] as string, segments: t['segments'] as string[] };
  return new SecretReference({
    qualifiers: (m['qualifiers'] as Json[]).map((q) => ({
      dimension: q['dimension'] as string,
      value: q['value'] as string,
    })),
    target,
    ...(typeof m['field'] === 'string' ? { field: m['field'] } : {}),
  });
}

/** [value] as plain JSON data (frozen arrays and objects compare equal). */
const plain = (value: unknown): unknown => JSON.parse(JSON.stringify(value));

const label = (input: string): string =>
  JSON.stringify(input.length > 40 ? `${input.substring(0, 40)}…` : input);

describe('references.json', () => {
  const v = vectors('references.json');

  test('the reference limit', () => {
    assert.equal(v['maxReferenceBytes'], maxReferenceBytes);
  });

  for (const c of v['valid'] as Json[]) {
    const input = c['input'] as string;
    test(`parses ${label(input)}`, () => {
      const parsed = SecretReference.parse(input);
      assert.deepEqual(plain(shape(parsed)), c['parsed']);
      assert.equal(parsed.canonical, c['canonical']);
      assert.equal(SecretReference.parse(parsed.canonical).canonical, parsed.canonical);
    });
  }

  for (const c of v['invalid'] as Json[]) {
    const input = c['input'] as string;
    test(`refuses ${label(input)} as ${String(c['reason'])}`, () => {
      assert.throws(
        () => SecretReference.parse(input),
        (e: unknown) =>
          e instanceof SecretsError && e.kind === 'malformed' && e.reason === c['reason'],
      );
    });
  }

  for (const c of v['format'] as Json[]) {
    test(`formats to ${String(c['formatted'])}`, () => {
      assert.equal(SecretReference.format(fromShape(c['parsed'] as Json)), c['formatted']);
      assert.deepEqual(plain(shape(SecretReference.parse(c['formatted'] as string))), c['reparsed']);
    });
  }
});

describe('discovery.json', () => {
  const v = vectors('discovery.json');
  for (const c of v['cases'] as Json[]) {
    test(`${String(c['os'])} ${JSON.stringify(c['env'])}`, () => {
      const location = discover(
        c['os'] as string,
        c['env'] as Record<string, string>,
        () => (typeof c['uid'] === 'number' ? c['uid'] : undefined),
      );
      const expected = c['expect'] as Json;
      if (location.kind === 'noRuntimeDirectory') {
        assert.deepEqual({ notRunning: location.reason }, expected);
        return;
      }
      const client = expected['client'] as Json;
      const admin = expected['admin'] as Json;
      assert.equal(location.directory, expected['directory']);
      assert.equal(location.clientSocket, client['socket']);
      assert.equal(location.clientPortFile, client['portFile']);
      assert.equal(location.clientTokenFile, client['tokenFile']);
      assert.equal(location.adminSocket, admin['socket']);
      assert.equal(location.adminPortFile, admin['portFile']);
    });
  }
  for (const c of v['portFiles'] as Json[]) {
    test(`port file ${JSON.stringify(c['text'])}`, () => {
      assert.equal(readPortFile(c['text'] as string), c['port'] ?? undefined);
    });
  }
});

describe('frames.json', () => {
  const v = vectors('frames.json');
  const frames = v['frames'] as Json[];

  test('the protocol version', () => {
    assert.equal(v['protocol'], protocolVersion);
  });

  for (const c of frames.filter((f) => f['type'] === frameJson)) {
    test(`JSON frame: ${String(c['name'])}`, () => {
      const read = new FrameReader(maxAnswerPayload).add(hex(c['hex'] as string));
      assert.equal(read.length, 1);
      assert.deepEqual(decodePayload(read[0]!.payload), c['json']);
      assert.equal(jsonFrame(c['json'] as Message).toString('hex'), c['hex']);
    });
  }

  for (const c of frames.filter((f) => f['type'] === frameBinary)) {
    test(`binary frame: ${String(c['name'])}`, () => {
      assert.throws(
        () => new FrameReader(maxAnswerPayload).add(hex(c['hex'] as string)),
        FrameError,
        'binary frames only once negotiated',
      );
      const negotiated = new FrameReader(maxAnswerPayload);
      negotiated.binaryAllowed = true;
      const read = negotiated.add(hex(c['hex'] as string));
      assert.equal(read.length, 1);
      assert.equal(read[0]!.payload.readBigUInt64BE(0), BigInt(c['requestId'] as number));
      assert.equal(read[0]!.payload.subarray(8).toString('hex'), c['chunkHex']);
    });
  }

  test('a frame split across reads is put together', () => {
    const bytes = hex(frames[0]!['hex'] as string);
    const reader = new FrameReader(maxRequestPayload);
    assert.deepEqual(reader.add(bytes.subarray(0, 3)), []);
    assert.deepEqual(reader.add(bytes.subarray(3, 20)), []);
    assert.equal(reader.add(Buffer.concat([bytes.subarray(20), bytes])).length, 2);
  });

  for (const c of v['invalid'] as Json[]) {
    test(`invalid: ${String(c['name'])}`, () => {
      const bytes = hex(c['hex'] as string);
      const reader = new FrameReader(
        c['direction'] === 'to service' ? maxRequestPayload : maxAnswerPayload,
      );
      switch (c['outcome']) {
        case 'close':
          assert.throws(() => reader.add(bytes), FrameError);
          break;
        case 'read':
          // The length passes; the payload is still to come.
          assert.deepEqual(reader.add(bytes), []);
          break;
        case 'malformed_close': {
          const read = reader.add(bytes);
          assert.equal(read.length, 1);
          if (c['name'] === 'a first frame that is not hello') {
            // Well-formed JSON; it is the order of frames that is wrong,
            // which the service checks (a client's first frame is hello).
            assert.equal(decodePayload(read[0]!.payload)['op'], 'get');
          } else {
            assert.throws(() => decodePayload(read[0]!.payload), FrameError);
          }
          break;
        }
        default:
          assert.fail(`unknown outcome ${String(c['outcome'])}`);
      }
    });
  }

  test('a payload with a byte order mark is malformed', () => {
    assert.throws(() => decodePayload(Buffer.from('﻿{"op":"x"}', 'utf8')), FrameError);
  });
});

test('the version sent in hello is the package.json version', async () => {
  const { clientVersion } = await import('../src/version');
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as Json;
  assert.equal(clientVersion, pkg['version']);
});
