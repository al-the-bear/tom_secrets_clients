// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/**
 * The client endpoint (protocol.md section 5): the connection, `hello`,
 * `get`, `getMany` and [B] `getFile`.
 */

import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';

import { currentOperatingSystem, discover, readPortFile, stripLineEnd } from './discovery';
import { SecretsError } from './errors';
import {
  decodePayload,
  encodeFrame,
  frameBinary,
  frameJson,
  FrameError,
  FrameReader,
  jsonPayload,
  maxAnswerPayload,
  maxRequestPayload,
  type Message,
} from './frames';
import { SecretReference } from './reference';
import {
  type Progress,
  type ProgressCallback,
  type SecretRequest,
  type SecretResult,
  SecretFile,
  SecretValue,
} from './value';
import { clientVersion } from './version';

/** The protocol version this library speaks. */
export const protocolVersion = 1;

/** The most references one `getMany` carries. */
export const maxGetMany = 256;

/**
 * The optional features this library takes (section 8), named in every
 * `hello`: binary frames and `getFile`.
 */
export const clientFeatures: readonly string[] = Object.freeze(['binary', 'getFile']);

/** What the service said in `welcome`. */
export interface Welcome {
  /** The protocol version spoken on this connection. */
  readonly protocol: number;
  /** The service's version. */
  readonly serviceVersion: string;
  /** The optional features the service offers (section 8). */
  readonly features: ReadonlySet<string>;
  /** The service's host name (the current value of the `host` dimension). */
  readonly host: string;
  /** `macos`, `linux`, `windows`, `ios` or `android`. */
  readonly platform: string;
}

/** How a client is made. */
export interface ClientOptions {
  /** Shown in approval prompts, never trusted; default the script's name. */
  clientName?: string;
  /**
   * A client token the program was given before (7.4), sent in every
   * `hello`; the library never stores one itself.
   */
  clientToken?: string;
  /**
   * The environment the service is looked for with (default the process's;
   * `TSM_RUNTIME_DIR` names the directory for containers and tests).
   */
  environment?: Readonly<Record<string, string | undefined>>;
  /** `linux`, `macos` or `windows` (default this process's). */
  operatingSystem?: string;
  /** How long connecting and the `welcome` may take, in ms (default 10000). */
  connectTimeoutMs?: number;
}

/** The options of a `get` or a `getMany`. */
export interface RequestOptions {
  /**
   * Wait for an unlock or an approval (default true), up to `timeoutMs`
   * (capped by the service).
   */
  wait?: boolean;
  /** How long the service may wait, in ms. */
  timeoutMs?: number;
  /** Hears why the request waits, with the approval code when there is one. */
  onProgress?: ProgressCallback;
  /**
   * Wait out a `rate_limited` answer and send the request again; `denied`,
   * `ambiguous` and `not_found` are never retried.
   */
  waitOnRateLimit?: boolean;
}

/** The options of a `getFile`. */
export interface GetFileOptions extends RequestOptions {
  /** The field, when the reference names none (`attachment:<name>`). */
  field?: string;
  /** Values for dimensions, beside the reference. */
  dimensions?: Readonly<Record<string, string>>;
}

/** The options of a `get`. */
export interface GetOptions extends GetFileOptions {
  /** Ask for a client token with an "always" approval. */
  wantClientToken?: boolean;
}

function notRunning(why: string): SecretsError {
  return new SecretsError('not_running', `the secrets service is not running: ${why}`);
}

function protocolError(why: string): SecretsError {
  return new SecretsError('internal', `the service broke the protocol: ${why}`, {
    code: 'protocol',
  });
}

function scriptName(): string {
  const script = process.argv[1];
  if (script === undefined || script === '') return 'node';
  return path.basename(script).replace(/\.(c|m)?(j|t)s$/i, '');
}

function readText(file: string): string | undefined {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return undefined;
  }
}

/**
 * A client of the Tom Secrets Manager's secrets service.
 *
 * One connection, opened by the first call (or `open`); after `not_running`
 * or a dropped connection the next call connects again. Calls may overlap.
 * The library logs nothing: no value, token or payload.
 */
export class SecretsClient {
  /** The name `hello` gives the program. */
  readonly clientName: string;
  /** The client token sent in every `hello`, when the program has one. */
  readonly clientToken: string | undefined;
  /** How long connecting and the `welcome` may take, in ms. */
  readonly connectTimeoutMs: number;

  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #operatingSystem: string;
  #connection: Connection | undefined;
  #connecting: Promise<Connection> | undefined;

  static #shared: SecretsClient | undefined;

  /** A client that connects on its first call. */
  constructor(options: ClientOptions = {}) {
    this.clientName = options.clientName ?? scriptName();
    this.clientToken = options.clientToken;
    this.connectTimeoutMs = options.connectTimeoutMs ?? 10000;
    this.#environment = options.environment ?? process.env;
    this.#operatingSystem = options.operatingSystem ?? currentOperatingSystem();
  }

  /** Creates a client and connects it, so a missing service shows at once (`not_running`). */
  static async connect(options: ClientOptions = {}): Promise<SecretsClient> {
    const client = new SecretsClient(options);
    await client.open();
    return client;
  }

  /** The process's shared client, created on first use with the defaults. */
  static get shared(): SecretsClient {
    return (SecretsClient.#shared ??= new SecretsClient());
  }

  /** The `welcome` of the current connection, or undefined when not connected. */
  get welcome(): Welcome | undefined {
    const c = this.#connection;
    return c === undefined || c.closed ? undefined : c.welcome;
  }

  /** Connects, unless a connection is open. */
  async open(): Promise<void> {
    await this.#ensureConnection();
  }

  /** Closes the connection; a later call connects again. */
  close(): void {
    const connection = this.#connection;
    this.#connection = undefined;
    connection?.close();
  }

  /**
   * Reads one secret.
   *
   * [ref] is parsed locally first; a malformed one fails as `malformed`
   * without a round trip. `field` names the field when the reference names
   * none (the same field in both is sent once; two different ones are
   * `malformed`, reason `field_twice`).
   */
  async get(ref: string, options: GetOptions = {}): Promise<SecretValue> {
    const item = requestItem(ref, options.field, options.dimensions);
    const request: Message = { op: 'get', ...item };
    if (options.wait === false) request['wait'] = false;
    if (options.timeoutMs !== undefined) request['timeoutMs'] = options.timeoutMs;
    if (options.wantClientToken === true) request['wantClientToken'] = true;
    const answer = await this.#request(request, options);
    return valueOf(ref, answer);
  }

  /**
   * Reads several secrets under one approval prompt (1 to 256); the results
   * come in request order, each a value or an error. Every reference is
   * parsed locally first.
   */
  async getMany(
    requests: readonly SecretRequest[],
    options: RequestOptions = {},
  ): Promise<SecretResult[]> {
    if (requests.length === 0 || requests.length > maxGetMany) {
      throw new RangeError(`a getMany carries 1 to ${maxGetMany} references, not ${requests.length}`);
    }
    const items = requests.map((r) => requestItem(r.ref, r.field, r.dimensions));
    const request: Message = { op: 'getMany', refs: items };
    if (options.wait === false) request['wait'] = false;
    if (options.timeoutMs !== undefined) request['timeoutMs'] = options.timeoutMs;
    const answer = await this.#request(request, options);
    const results = answer['results'];
    if (answer['op'] !== 'values' || !Array.isArray(results)) {
      throw protocolError(`getMany was answered ${String(answer['op'])}`);
    }
    if (results.length !== requests.length) {
      throw protocolError(`getMany got ${results.length} results`);
    }
    return results.map((r: unknown, i): SecretResult => {
      if (r === null || typeof r !== 'object' || Array.isArray(r)) {
        throw protocolError('a getMany result is no object');
      }
      const m = r as Message;
      if (m['op'] === 'error') return { error: SecretsError.fromError(m) };
      return { value: valueOf(requests[i]!.ref, m) };
    });
  }

  /**
   * [B] Reads an attachment or a typed key as bytes, over binary frames,
   * checked against its size and SHA-256 (5.5). Fails as `unsupported`
   * (`details.features`, the ones missing) without sending anything when the
   * service does not offer the features `binary` and `getFile`. The
   * reference is parsed locally first, as for `get`.
   */
  async getFile(ref: string, options: GetFileOptions = {}): Promise<SecretFile> {
    const item = requestItem(ref, options.field, options.dimensions);
    const connection = await this.#ensureConnection();
    const missing = clientFeatures.filter((f) => !connection.welcome.features.has(f));
    if (missing.length > 0) {
      throw new SecretsError(
        'unsupported',
        `the service does not offer getFile (features ${missing.join(', ')})`,
        { features: missing },
      );
    }
    const request: Message = { op: 'getFile', ...item };
    if (options.wait === false) request['wait'] = false;
    if (options.timeoutMs !== undefined) request['timeoutMs'] = options.timeoutMs;
    const answer = await this.#request(request, options);
    const received = receivedFiles.get(answer);
    if (answer['op'] !== 'end' || received === undefined) {
      throw protocolError(`getFile was answered ${String(answer['op'])}`);
    }
    const { file, bytes } = received;
    const name = file['name'];
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    if (file['size'] !== bytes.length || answer['sha256'] !== sha256 || typeof name !== 'string') {
      bytes.fill(0);
      throw protocolError('the file does not match its size or sha256');
    }
    return new SecretFile(ref, name, bytes);
  }

  async #request(request: Message, options: RequestOptions): Promise<Message> {
    for (;;) {
      const connection = await this.#ensureConnection();
      const answer = await connection.send(request, options.onProgress);
      if (answer['op'] !== 'error') return answer;
      const error = SecretsError.fromError(answer);
      if (error.kind === 'rate_limited' && options.waitOnRateLimit === true) {
        const ms = error.details['retryAfterMs'];
        await new Promise((resolve) =>
          setTimeout(resolve, typeof ms === 'number' && Number.isInteger(ms) && ms > 0 ? ms : 1000),
        );
        continue;
      }
      throw error;
    }
  }

  #ensureConnection(): Promise<Connection> {
    const open = this.#connection;
    if (open !== undefined && !open.closed) return Promise.resolve(open);
    this.#connecting ??= this.#connect().finally(() => {
      this.#connecting = undefined;
    });
    return this.#connecting;
  }

  async #connect(): Promise<Connection> {
    const location = discover(this.#operatingSystem, this.#environment);
    if (location.kind !== 'endpoints') {
      throw notRunning('no runtime directory can be named');
    }
    let socket: net.Socket;
    let token: string | undefined;
    if (this.#operatingSystem === 'windows') {
      const port = readText(location.clientPortFile!);
      const number = port === undefined ? undefined : readPortFile(port);
      if (number === undefined) throw notRunning('no readable client.port');
      const raw = readText(location.clientTokenFile!);
      if (raw === undefined) throw notRunning('no client.token');
      token = stripLineEnd(raw);
      socket = await this.#open({ host: '127.0.0.1', port: number });
    } else {
      const file = location.clientSocket!;
      try {
        statSync(file);
      } catch {
        throw notRunning(`no client.sock in ${location.directory}`);
      }
      socket = await this.#open({ path: file });
    }
    const connection = new Connection(socket);
    const hello: Message = {
      op: 'hello',
      protocol: protocolVersion,
      client: { name: this.clientName, version: clientVersion, language: 'typescript' },
      features: [...clientFeatures],
    };
    if (token !== undefined) hello['token'] = token;
    if (this.clientToken !== undefined) hello['clientToken'] = this.clientToken;
    try {
      connection.sendFrame(hello);
      await withTimeout(connection.welcomed, this.connectTimeoutMs, () =>
        notRunning(`no welcome within ${this.connectTimeoutMs} ms`),
      );
    } catch (e) {
      connection.close();
      throw e;
    }
    this.#connection = connection;
    return connection;
  }

  #open(target: net.NetConnectOpts): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const socket = net.connect(target);
      const timer = setTimeout(() => {
        socket.destroy();
        reject(notRunning('the connection timed out'));
      }, this.connectTimeoutMs);
      socket.once('connect', () => {
        clearTimeout(timer);
        socket.removeAllListeners('error');
        resolve(socket);
      });
      socket.once('error', () => {
        clearTimeout(timer);
        socket.destroy();
        reject(notRunning('the connection was refused'));
      });
    });
  }
}

function requestItem(
  ref: string,
  field: string | undefined,
  dimensions: Readonly<Record<string, string>> | undefined,
): Message {
  const parsed = SecretReference.parse(ref);
  if (field !== undefined && parsed.fieldGiven && field !== parsed.field) {
    throw new SecretsError('malformed', 'the field is named in the reference and as field', {
      reason: 'field_twice',
    });
  }
  const item: Message = { ref };
  if (dimensions !== undefined && Object.keys(dimensions).length > 0) {
    item['dimensions'] = { ...dimensions };
  }
  if (field !== undefined && !parsed.fieldGiven) item['field'] = field;
  return item;
}

function valueOf(ref: string, answer: Message): SecretValue {
  if (answer['op'] !== 'value') {
    throw protocolError(`get was answered ${String(answer['op'])}`);
  }
  return SecretValue.fromMessage(ref, answer);
}

function withTimeout<T>(promise: Promise<T>, ms: number, error: () => Error): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(error()), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e: unknown) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

interface PendingRequest {
  readonly onProgress: ProgressCallback | undefined;
  readonly resolve: (message: Message) => void;
  readonly reject: (error: SecretsError) => void;
  /** A `getFile`'s `file` message, once it came. */
  file?: Message;
  /** The binary chunks received after `file`, in order. */
  chunks?: Buffer[];
}

/** The file each `getFile`'s `end` message closes, put together by its connection. */
const receivedFiles = new WeakMap<Message, ReceivedFile>();

/** A `getFile` answer put together: its `file` message and all chunks joined. */
interface ReceivedFile {
  readonly file: Message;
  readonly bytes: Buffer;
}

function wipe(chunks: readonly Buffer[] | undefined): void {
  for (const chunk of chunks ?? []) chunk.fill(0);
}

/** One connection: frames in and out, the open requests by id. */
class Connection {
  closed = false;
  welcome!: Welcome;
  readonly welcomed: Promise<void>;

  readonly #socket: net.Socket;
  readonly #reader = new FrameReader(maxAnswerPayload);
  readonly #pending = new Map<number, PendingRequest>();
  #nextId = 1;
  #isWelcomed = false;
  #welcome!: { resolve: () => void; reject: (e: SecretsError) => void };

  constructor(socket: net.Socket) {
    this.#socket = socket;
    this.welcomed = new Promise<void>((resolve, reject) => {
      this.#welcome = { resolve, reject };
    });
    // A failed connect before the welcome is reported by the caller's await;
    // this keeps an unawaited rejection from being unhandled.
    this.welcomed.catch(() => undefined);
    socket.on('data', (bytes: Buffer) => this.#onData(bytes));
    socket.on('error', () => this.#fail(dropped()));
    socket.on('close', () => this.#fail(dropped()));
  }

  sendFrame(message: Message): void {
    const payload = jsonPayload(message);
    if (payload.length > maxRequestPayload) {
      throw new SecretsError(
        'malformed',
        `the request is ${payload.length} bytes, over ${maxRequestPayload}`,
        { reason: 'frame' },
      );
    }
    this.#socket.write(encodeFrame(frameJson, payload));
  }

  send(request: Message, onProgress: ProgressCallback | undefined): Promise<Message> {
    if (this.closed) return Promise.reject(dropped());
    const id = this.#nextId++;
    return new Promise<Message>((resolve, reject) => {
      this.sendFrame({ ...request, id });
      this.#pending.set(id, { onProgress, resolve, reject });
    });
  }

  #onData(bytes: Buffer): void {
    try {
      for (const frame of this.#reader.add(bytes)) {
        // The reader refuses a binary frame unless the welcome named `binary`.
        if (frame.type === frameBinary) this.#onChunk(frame.payload);
        else this.#onMessage(decodePayload(frame.payload));
        if (this.closed) return;
      }
    } catch (e) {
      if (e instanceof FrameError) this.#fail(protocolError(e.message));
      else if (e instanceof SecretsError) this.#fail(e);
      else this.#fail(protocolError(String(e)));
    }
  }

  #onMessage(message: Message): void {
    const op = message['op'];
    const id = message['id'];
    if (!this.#isWelcomed) {
      if (op === 'welcome') {
        this.welcome = welcomeOf(message);
        this.#reader.binaryAllowed = this.welcome.features.has('binary');
        this.#isWelcomed = true;
        this.#welcome.resolve();
      } else if (op === 'error' && id === undefined) {
        this.#fail(SecretsError.fromError(message));
      } else {
        this.#fail(protocolError(`the first frame is ${String(op)}, not welcome`));
      }
      return;
    }
    if (op === 'error' && id === undefined) {
      this.#fail(SecretsError.fromError(message));
      return;
    }
    const pending = typeof id === 'number' ? this.#pending.get(id) : undefined;
    if (pending === undefined) return; // an answer nobody waits for; ignored
    switch (op) {
      case 'progress': {
        const progress: Progress = {
          pending: message['pending'] === 'unlock' ? 'unlock' : 'approval',
          ...(typeof message['approvalCode'] === 'string'
            ? { approvalCode: message['approvalCode'] }
            : {}),
        };
        pending.onProgress?.(progress);
        break;
      }
      case 'file':
        pending.file = message;
        pending.chunks = [];
        break;
      case 'end': {
        if (pending.file === undefined || pending.chunks === undefined) {
          throw new FrameError('end without file');
        }
        const chunks = pending.chunks;
        receivedFiles.set(message, { file: pending.file, bytes: Buffer.concat(chunks) });
        wipe(chunks);
        this.#pending.delete(id as number);
        pending.resolve(message);
        break;
      }
      case 'value':
      case 'values':
      case 'error':
        wipe(pending.chunks); // an error may end a getFile after its file
        this.#pending.delete(id as number);
        pending.resolve(message);
        break;
      default:
        // An answer this library does not know; section 8 says ignore it.
        break;
    }
  }

  /** A binary chunk (2.5): the request id as 8 bytes big-endian, then the bytes. */
  #onChunk(payload: Buffer): void {
    if (payload.length < 8) throw new FrameError('a binary chunk without id');
    const id = payload.readBigUInt64BE(0);
    const pending = id <= BigInt(Number.MAX_SAFE_INTEGER)
      ? this.#pending.get(Number(id))
      : undefined;
    if (pending?.chunks === undefined) throw new FrameError('a chunk without file');
    pending.chunks.push(payload.subarray(8));
  }

  #fail(error: SecretsError): void {
    if (this.closed) return;
    this.closed = true;
    if (!this.#isWelcomed) this.#welcome.reject(error);
    for (const pending of this.#pending.values()) {
      wipe(pending.chunks);
      pending.reject(error);
    }
    this.#pending.clear();
    this.#socket.destroy();
  }

  close(): void {
    this.#fail(notRunning('the client closed the connection'));
  }
}

function dropped(): SecretsError {
  return notRunning('the connection to the service dropped');
}

function welcomeOf(m: Message): Welcome {
  const protocol = m['protocol'];
  if (protocol !== protocolVersion) {
    throw new SecretsError('unsupported', `the service speaks protocol ${String(protocol)}`, {
      protocols: [protocol],
    });
  }
  const service = m['service'];
  const features = m['features'];
  return {
    protocol: protocolVersion,
    serviceVersion:
      service !== null && typeof service === 'object' && !Array.isArray(service)
        ? String((service as Message)['version'])
        : '',
    features: new Set(
      Array.isArray(features) ? features.filter((f): f is string => typeof f === 'string') : [],
    ),
    host: typeof m['host'] === 'string' ? m['host'] : '',
    platform: typeof m['platform'] === 'string' ? m['platform'] : '',
  };
}
