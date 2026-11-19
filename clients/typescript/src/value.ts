// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/** What a `get` answers (protocol.md 5.2). */

import { inspect } from 'node:util';

import { SecretsError } from './errors';

/** How the service sent a value: text, or bytes (base64 on the wire). */
export type SecretEncoding = 'utf8' | 'base64';

/**
 * Where a value came from: `github` when its store was fetched from GitHub
 * in this refresh cycle, `file` when it was read from a `file:` vault on the
 * local disk in this cycle, `cache` when the service serves its offline copy.
 */
export type SecretSource = 'github' | 'file' | 'cache';

/**
 * The source a protocol `source` names; an unknown one is `cache`
 * (section 8: the most general one known, no claim to be fresh).
 */
export function sourceFromWire(name: unknown): SecretSource {
  return name === 'github' || name === 'file' ? name : 'cache';
}

/** The entry a value was read from. */
export interface SecretEntry {
  /** The store holding it. */
  readonly store: string;
  /** Its KDBX UUID. */
  readonly uuid: string;
  /** Where the service read it from. */
  readonly source: SecretSource;
  /** The last successful fetch of the store. */
  readonly fetchedAt: Date;
}

/**
 * The entry's last modification and the store file revision it was read
 * from; a caller caching a value compares it to see a change.
 */
export interface SecretVersion {
  readonly modified: Date;
  readonly revision: string;
}

function date(value: unknown): Date {
  if (typeof value !== 'string') throw new TypeError('not a date');
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) throw new TypeError('not a date');
  return d;
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('not an object');
  }
  return value as Record<string, unknown>;
}

function text(value: unknown): string {
  if (typeof value !== 'string') throw new TypeError('not a string');
  return value;
}

const utf8Strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * A secret. Its printable forms (`toString`, `toJSON`, `util.inspect`) never
 * show it, and `dispose` overwrites its buffer. A `text` the caller takes out
 * is an immutable JavaScript string the library cannot overwrite: the caller
 * handles it.
 */
export class SecretValue {
  /** The reference the value was asked for, as given. */
  readonly reference: string;
  /** How the service sent it. */
  readonly encoding: SecretEncoding;
  /** The entry it was read from. */
  readonly entry: SecretEntry;
  /** The bindings the winning entry carries, `{dimension: value}`. */
  readonly bound: Readonly<Record<string, string>>;
  /** The entry's version. */
  readonly version: SecretVersion;
  /** The entry's expiry, when it has one. */
  readonly expires: Date | undefined;
  /**
   * The client token the service granted, when one was asked for: the
   * caller's to keep (7.4); the library never stores it.
   */
  readonly clientToken: string | undefined;

  readonly #bytes: Buffer;
  #disposed = false;

  private constructor(parts: {
    reference: string;
    bytes: Buffer;
    encoding: SecretEncoding;
    entry: SecretEntry;
    bound: Record<string, string>;
    version: SecretVersion;
    expires: Date | undefined;
    clientToken: string | undefined;
  }) {
    this.reference = parts.reference;
    this.#bytes = parts.bytes;
    this.encoding = parts.encoding;
    this.entry = Object.freeze(parts.entry);
    this.bound = Object.freeze(parts.bound);
    this.version = Object.freeze(parts.version);
    this.expires = parts.expires;
    this.clientToken = parts.clientToken;
  }

  /** The value of a `value` message (or a `values` result) for [reference]. */
  static fromMessage(reference: string, m: Record<string, unknown>): SecretValue {
    try {
      const encoding: SecretEncoding = m['encoding'] === 'base64' ? 'base64' : 'utf8';
      const raw = text(m['value']);
      const entry = record(m['entry']);
      const version = record(m['version']);
      const bound: Record<string, string> = {};
      if (m['bound'] !== null && typeof m['bound'] === 'object' && !Array.isArray(m['bound'])) {
        for (const [k, v] of Object.entries(m['bound'] as Record<string, unknown>)) {
          bound[k] = text(v);
        }
      }
      if (encoding === 'base64' && !/^[A-Za-z0-9+/]*={0,2}$/.test(raw)) {
        throw new TypeError('not base64');
      }
      return new SecretValue({
        reference,
        bytes: encoding === 'base64' ? Buffer.from(raw, 'base64') : Buffer.from(raw, 'utf8'),
        encoding,
        entry: {
          store: text(entry['store']),
          uuid: text(entry['uuid']),
          source: sourceFromWire(entry['source']),
          fetchedAt: date(entry['fetchedAt']),
        },
        bound,
        version: { modified: date(version['modified']), revision: text(version['revision']) },
        expires: typeof m['expires'] === 'string' ? date(m['expires']) : undefined,
        clientToken: typeof m['clientToken'] === 'string' ? m['clientToken'] : undefined,
      });
    } catch (e) {
      if (e instanceof SecretsError) throw e;
      throw new SecretsError(
        'internal',
        'the service sent a value message this library cannot read',
        { code: 'bad_value' },
      );
    }
  }

  /** Whether `dispose` was called. */
  get isDisposed(): boolean {
    return this.#disposed;
  }

  /**
   * The value as text. A binary value (`base64`) is refused with an `Error`
   * rather than decoded into a corrupt string.
   */
  get text(): string {
    this.#check();
    if (this.encoding === 'base64') {
      throw new Error(`the value of ${this.reference} is binary: read it with bytes, not text`);
    }
    return utf8Strict.decode(this.#bytes);
  }

  /**
   * The value as bytes (text as its UTF-8). A view of the buffer that
   * `dispose` overwrites; copy it to keep it.
   */
  get bytes(): Uint8Array {
    this.#check();
    return new Uint8Array(this.#bytes.buffer, this.#bytes.byteOffset, this.#bytes.length);
  }

  /** Overwrites the buffer with zeros; the value cannot be read afterwards. */
  dispose(): void {
    this.#bytes.fill(0);
    this.#disposed = true;
  }

  #check(): void {
    if (this.#disposed) throw new Error(`the value of ${this.reference} was disposed`);
  }

  toString(): string {
    return `SecretValue(${this.reference}: ***)`;
  }

  /** What `JSON.stringify` writes: the reference and its entry, not the value. */
  toJSON(): Record<string, unknown> {
    return { reference: this.reference, value: '***', entry: this.entry };
  }

  [inspect.custom](): string {
    return this.toString();
  }
}

/**
 * [B] An attachment or a typed key read with `getFile` (5.5): its name and
 * bytes, checked against the size and SHA-256 the service sent. Its
 * printable forms (`toString`, `toJSON`, `util.inspect`) never show the
 * bytes, and `dispose` overwrites them.
 */
export class SecretFile {
  /** The reference the file was asked for, as given. */
  readonly reference: string;
  /** The field's name (an attachment's file name, without `attachment:`). */
  readonly name: string;

  readonly #bytes: Buffer;
  #disposed = false;

  /** A file of [bytes]; the file owns the buffer and `dispose` zeroes it. */
  constructor(reference: string, name: string, bytes: Buffer) {
    this.reference = reference;
    this.name = name;
    this.#bytes = bytes;
  }

  /** The size in bytes. */
  get size(): number {
    return this.#bytes.length;
  }

  /** Whether `dispose` was called. */
  get isDisposed(): boolean {
    return this.#disposed;
  }

  /** The bytes: the buffer `dispose` overwrites; copy it to keep it. */
  get bytes(): Buffer {
    if (this.#disposed) throw new Error(`the file of ${this.reference} was disposed`);
    return this.#bytes;
  }

  /** Overwrites the bytes with zeros; the file cannot be read afterwards. */
  dispose(): void {
    this.#bytes.fill(0);
    this.#disposed = true;
  }

  toString(): string {
    return `SecretFile(${this.reference}: ${this.name}, ${this.size} bytes)`;
  }

  /** What `JSON.stringify` writes: the reference, name and size, not the bytes. */
  toJSON(): Record<string, unknown> {
    return { reference: this.reference, name: this.name, size: this.size };
  }

  [inspect.custom](): string {
    return this.toString();
  }
}

/**
 * Why a request waits (`progress`, 5.4): `unlock` (the service is locked and
 * an admin was told) or `approval` (the request went to approval).
 */
export type Pending = 'unlock' | 'approval';

/** A progress notice: passed to a call's `onProgress`. */
export interface Progress {
  /** Why it waits. */
  readonly pending: Pending;
  /**
   * The one-time approval code, on a host with no approver connected (7.5);
   * show it so the user can approve it on a trusted device.
   */
  readonly approvalCode?: string;
}

/** Receives the progress notices of a waiting request. */
export type ProgressCallback = (progress: Progress) => void;

/** One reference of a `getMany`. */
export interface SecretRequest {
  /** The reference. */
  readonly ref: string;
  /** The field, when the reference names none. */
  readonly field?: string;
  /** Values for dimensions, beside the reference. */
  readonly dimensions?: Readonly<Record<string, string>>;
}

/** One result of a `getMany`, in request order: a value or an error. */
export type SecretResult =
  | { readonly value: SecretValue; readonly error?: undefined }
  | { readonly value?: undefined; readonly error: SecretsError };
