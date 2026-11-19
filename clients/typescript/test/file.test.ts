// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// [B] getFile against a small service in this process: the file message,
// the binary chunks (protocol.md 2.5) and the end with its SHA-256; the
// checks of size and digest, the features it needs, a chunk the client did
// not ask for, and SecretFile's masking and dispose. Demo data only.

import * as assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import * as net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { inspect } from 'node:util';

import {
  decodePayload,
  encodeFrame,
  frameBinary,
  FrameReader,
  jsonFrame,
  maxRequestPayload,
  type Message,
} from '../src/frames';
import { SecretFile, SecretsClient, SecretsError } from '../src/index';

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** 3000 demo bytes, sent in chunks of 1024. */
const content = Buffer.from(Array.from({ length: 3000 }, (_, i) => i % 251));

/** How the service answers a getFile. */
type Mode = 'good' | 'bad-sha256' | 'bad-size' | 'chunk-without-file' | 'error-after-file';

function chunk(id: number, bytes: Buffer): Buffer {
  const payload = Buffer.alloc(8 + bytes.length);
  payload.writeBigUInt64BE(BigInt(id), 0);
  bytes.copy(payload, 8);
  return encodeFrame(frameBinary, payload);
}

/** A service offering [features] and answering every getFile by [mode]. */
async function serve(
  features: string[],
  mode: Mode,
): Promise<{ client: SecretsClient; received: Message[]; close: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), 'tsmtf'));
  dirs.push(dir);
  const received: Message[] = [];
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => undefined);
    const reader = new FrameReader(maxRequestPayload);
    socket.on('data', (bytes) => {
      for (const frame of reader.add(bytes)) {
        const m = decodePayload(frame.payload);
        received.push(m);
        const id = m['id'] as number;
        if (m['op'] === 'hello') {
          socket.write(jsonFrame({ op: 'welcome', protocol: 1, service: { version: '0.1.0' }, features, host: 'demo-host', platform: 'linux' }));
        } else if (m['op'] === 'getFile') {
          if (mode === 'chunk-without-file') {
            socket.write(chunk(id, content.subarray(0, 10)));
            continue;
          }
          const size = mode === 'bad-size' ? content.length + 1 : content.length;
          socket.write(jsonFrame({ op: 'file', id, name: 'id_ed25519', size }));
          for (let o = 0; o < content.length; o += 1024) {
            socket.write(chunk(id, content.subarray(o, o + 1024)));
          }
          if (mode === 'error-after-file') {
            socket.write(jsonFrame({ op: 'error', id, kind: 'unavailable', message: 'the store went away' }));
            continue;
          }
          const sha256 = mode === 'bad-sha256'
            ? '0'.repeat(64)
            : createHash('sha256').update(content).digest('hex');
          socket.write(jsonFrame({ op: 'end', id, sha256 }));
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen({ path: join(dir, 'client.sock') }, resolve));
  const client = new SecretsClient({ clientName: 'demo', environment: { TSM_RUNTIME_DIR: dir }, operatingSystem: 'linux' });
  return {
    client,
    received,
    close: () => {
      client.close();
      for (const s of sockets) s.destroy();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

const unix = { skip: process.platform === 'win32' };
const both = ['binary', 'getFile'];
const ref = 'fleet/SSH/bomber#attachment%3Aid_ed25519';

test('getFile: the chunks joined, checked against size and sha256; the request as sent', unix, async () => {
  const s = await serve(both, 'good');
  try {
    const f = await s.client.getFile(ref, { timeoutMs: 5000 });
    assert.ok(f instanceof SecretFile);
    assert.equal(f.name, 'id_ed25519');
    assert.equal(f.size, 3000);
    assert.ok(Buffer.isBuffer(f.bytes));
    assert.ok(f.bytes.equals(content));
    assert.deepEqual(s.received[1], { op: 'getFile', ref, timeoutMs: 5000, id: 1 });
    // The connection goes on: a second getFile on it.
    const g = await s.client.getFile('fleet/SSH/bomber', { field: 'attachment:id_ed25519', wait: false });
    assert.ok(g.bytes.equals(content));
    assert.deepEqual(s.received[2], { op: 'getFile', ref: 'fleet/SSH/bomber', field: 'attachment:id_ed25519', wait: false, id: 2 });
  } finally {
    await s.close();
  }
});

test('getFile: a digest or size that does not match is internal', unix, async () => {
  for (const mode of ['bad-sha256', 'bad-size'] as const) {
    const s = await serve(both, mode);
    try {
      await assert.rejects(s.client.getFile(ref), (e: unknown) =>
        e instanceof SecretsError && e.kind === 'internal' && e.reason === undefined && e.details['code'] === 'protocol');
    } finally {
      await s.close();
    }
  }
});

test('getFile: a service without both features is unsupported, nothing sent', unix, async () => {
  for (const features of [[], ['binary'], ['getFile']]) {
    const s = await serve(features, 'good');
    try {
      await assert.rejects(s.client.getFile(ref), (e: unknown) =>
        e instanceof SecretsError && e.kind === 'unsupported'
        && JSON.stringify(e.details['features']) === JSON.stringify(both.filter((f) => !features.includes(f))));
      assert.equal(s.received.filter((m) => m['op'] === 'getFile').length, 0);
    } finally {
      await s.close();
    }
  }
});

test('getFile: a malformed reference fails locally', async () => {
  const client = new SecretsClient({ environment: { TSM_RUNTIME_DIR: '/nonexistent-tsm' }, operatingSystem: 'linux' });
  await assert.rejects(client.getFile('a//b'), (e: unknown) => e instanceof SecretsError && e.reason === 'empty_segment');
});

test('getFile: an error after the file is the error; a chunk without file breaks the protocol', unix, async () => {
  const e1 = await serve(both, 'error-after-file');
  try {
    await assert.rejects(e1.client.getFile(ref), (e: unknown) => e instanceof SecretsError && e.kind === 'unavailable');
  } finally {
    await e1.close();
  }
  const e2 = await serve(both, 'chunk-without-file');
  try {
    await assert.rejects(e2.client.getFile(ref), (e: unknown) => e instanceof SecretsError && e.kind === 'internal');
    assert.equal(e2.client.welcome, undefined); // the connection was closed
  } finally {
    await e2.close();
  }
});

test('SecretFile: masked when printed, its bytes overwritten by dispose', () => {
  const bytes = Buffer.from('-----BEGIN OPENSSH PRIVATE KEY----- demo');
  const f = new SecretFile('fleet/SSH/demo', 'id_demo', bytes);
  const shown = `${String(f)} ${inspect(f)} ${JSON.stringify(f)} ${inspect({ f })}`;
  assert.ok(!shown.includes('OPENSSH'));
  assert.equal(String(f), 'SecretFile(fleet/SSH/demo: id_demo, 40 bytes)');
  assert.deepEqual(JSON.parse(JSON.stringify(f)), { reference: 'fleet/SSH/demo', name: 'id_demo', size: 40 });
  f.dispose();
  assert.ok(f.isDisposed);
  assert.ok(bytes.every((b) => b === 0));
  assert.throws(() => f.bytes, /disposed/);
});
