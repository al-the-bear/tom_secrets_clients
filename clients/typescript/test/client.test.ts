// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// SecretsClient against a small service in this process: the Unix socket
// (Linux, macOS) and the port and token files (Windows, tested here on every
// OS through `operatingSystem`), the hello it sends, a reconnect after a
// drop, and the local refusals. The conformance suite covers the protocol
// in full; demo data only.

import * as assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { decodePayload, FrameReader, jsonFrame, maxRequestPayload, type Message } from '../src/frames';
import { SecretsClient, SecretsError } from '../src/index';

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function scratch(): string {
  // The system's temporary directory: a Unix socket path is limited to about
  // 100 bytes.
  const d = mkdtempSync(join(tmpdir(), 'tsmts'));
  dirs.push(d);
  return d;
}

/**
 * A service answering `get` with a fixed value (`demo/Hold/It` is never
 * answered); it records what it got.
 */
class DemoService {
  readonly received: Message[] = [];
  readonly sockets = new Set<net.Socket>();
  readonly server: net.Server;

  constructor() {
    this.server = net.createServer((socket) => {
      this.sockets.add(socket);
      socket.on('close', () => this.sockets.delete(socket));
      socket.on('error', () => undefined);
      const reader = new FrameReader(maxRequestPayload);
      socket.on('data', (bytes) => {
        for (const frame of reader.add(bytes)) {
          const m = decodePayload(frame.payload);
          this.received.push(m);
          if (m['op'] === 'hello') {
            socket.write(jsonFrame({ op: 'welcome', protocol: 1, service: { version: '0.1.0' }, features: [], host: 'demo-host', platform: 'linux' }));
          } else if (m['op'] === 'get' && m['ref'] !== 'demo/Hold/It') {
            socket.write(jsonFrame({
              op: 'value',
              id: m['id'],
              encoding: 'utf8',
              value: 'demo-value',
              entry: { store: 'demo', uuid: '00000000000000000000000000000001', source: 'file', fetchedAt: '2026-11-14T10:00:00Z' },
              bound: {},
              version: { modified: '2026-11-14T09:00:00Z', revision: 'r1' },
            }));
          }
        }
      });
    });
  }

  listen(target: net.ListenOptions): Promise<void> {
    return new Promise((resolve) => this.server.listen(target, resolve));
  }

  /** Drops every connection, as a service that stopped. */
  drop(): void {
    for (const s of this.sockets) s.destroy();
  }

  close(): Promise<void> {
    this.drop();
    return new Promise((resolve) => this.server.close(() => resolve()));
  }
}

test('Unix socket: hello names the client; get reads; a drop is not_running and the next call reconnects', { skip: process.platform === 'win32' }, async () => {
  const dir = scratch();
  const service = new DemoService();
  await service.listen({ path: join(dir, 'client.sock') });
  const client = new SecretsClient({ clientName: 'demo', environment: { TSM_RUNTIME_DIR: dir }, operatingSystem: 'linux' });
  try {
    const v = await client.get('demo/App/Login', { field: 'UserName' });
    assert.equal(v.text, 'demo-value');
    assert.equal(client.welcome?.host, 'demo-host');
    const hello = service.received[0]!;
    assert.deepEqual(hello['client'], { name: 'demo', version: '0.1.0', language: 'typescript' });
    assert.deepEqual(hello['features'], ['binary', 'getFile']);
    assert.equal(hello['token'], undefined);
    assert.deepEqual(service.received[1], { op: 'get', ref: 'demo/App/Login', field: 'UserName', id: 1 });

    const waiting = client.get('demo/Hold/It');
    await new Promise((r) => setTimeout(r, 50));
    service.drop();
    await assert.rejects(waiting, (e: unknown) => e instanceof SecretsError && e.kind === 'not_running');
    assert.equal((await client.get('demo/App/Login')).text, 'demo-value');
    assert.equal(service.received.filter((m) => m['op'] === 'hello').length, 2);
  } finally {
    client.close();
    await service.close();
  }
});

test('Windows: the port and token files, re-read at every connect', async () => {
  const dir = scratch();
  const service = new DemoService();
  await service.listen({ host: '127.0.0.1', port: 0 });
  const port = (service.server.address() as net.AddressInfo).port;
  // The rules join with a backslash, which on Linux and macOS is a file
  // name character: the files are named as the rules write them.
  const portFile = `${dir}\\client.port`;
  const tokenFile = `${dir}\\client.token`;
  writeFileSync(portFile, `${port}\r\n`);
  writeFileSync(tokenFile, 'demo-token-1\n');
  const client = new SecretsClient({
    clientName: 'demo',
    environment: { TSM_RUNTIME_DIR: dir },
    operatingSystem: 'windows',
  });
  try {
    await client.open();
    assert.equal(service.received[0]!['token'], 'demo-token-1');
    service.drop();
    await new Promise((r) => setTimeout(r, 50));
    writeFileSync(tokenFile, 'demo-token-2');
    await client.get('demo.key');
    assert.equal(service.received.filter((m) => m['op'] === 'hello')[1]!['token'], 'demo-token-2');
  } finally {
    client.close();
    await service.close();
  }
});

test('no service: not_running; local refusals never reach a service', async () => {
  const dir = scratch();
  const client = new SecretsClient({ environment: { TSM_RUNTIME_DIR: dir }, operatingSystem: 'linux' });
  await assert.rejects(client.get('demo.key'), (e: unknown) => e instanceof SecretsError && e.kind === 'not_running');
  await assert.rejects(client.get('a//b'), (e: unknown) => e instanceof SecretsError && e.kind === 'malformed' && e.reason === 'empty_segment');
  await assert.rejects(
    client.get('demo/A#UserName', { field: 'Password' }),
    (e: unknown) => e instanceof SecretsError && e.reason === 'field_twice',
  );
  await assert.rejects(client.getMany([]), RangeError);
  const windows = new SecretsClient({ environment: {}, operatingSystem: 'windows' });
  await assert.rejects(windows.get('demo.key'), (e: unknown) => e instanceof SecretsError && e.kind === 'not_running');
});
