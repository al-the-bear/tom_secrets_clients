// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/** Frames and JSON payloads (protocol.md section 2). */

import { parseStrictJson } from './json';

/** Frame type of a JSON payload. */
export const frameJson = 0;

/** Frame type of a binary chunk ([B], 2.5). */
export const frameBinary = 1;

/** The largest payload of a frame sent to the service. */
export const maxRequestPayload = 64 * 1024;

/** The largest payload of a frame sent by the service. */
export const maxAnswerPayload = 1024 * 1024;

/** A frame or payload that breaks section 2; the connection is closed. */
export class FrameError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FrameError';
  }
}

/** A message: a JSON object with an `op`. */
export type Message = Record<string, unknown>;

/** The compact UTF-8 JSON of [message], as the vectors write it. */
export function jsonPayload(message: Message): Buffer {
  return Buffer.from(JSON.stringify(message), 'utf8');
}

/** A frame: the payload length (4 bytes big-endian), the type, the payload. */
export function encodeFrame(type: number, payload: Uint8Array): Buffer {
  const out = Buffer.alloc(5 + payload.length);
  out.writeUInt32BE(payload.length, 0);
  out[4] = type;
  out.set(payload, 5);
  return out;
}

/** The JSON frame of [message]. */
export function jsonFrame(message: Message): Buffer {
  return encodeFrame(frameJson, jsonPayload(message));
}

const utf8Strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * The message of a JSON payload; a `FrameError` when it is malformed (2.2):
 * empty, not UTF-8, starting with a byte order mark, not JSON, not an object,
 * an object with a duplicate member name, or without a string `op`.
 */
export function decodePayload(payload: Uint8Array): Message {
  if (payload.length === 0) throw new FrameError('empty payload');
  let text: string;
  try {
    text = utf8Strict.decode(payload);
  } catch {
    throw new FrameError('payload is not UTF-8');
  }
  if (text.startsWith('﻿')) {
    throw new FrameError('payload starts with a byte order mark');
  }
  let value: unknown;
  try {
    value = parseStrictJson(text);
  } catch (e) {
    throw new FrameError(`payload is not JSON: ${(e as Error).message}`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new FrameError('payload is not a JSON object');
  }
  const message = value as Message;
  if (typeof message['op'] !== 'string') {
    throw new FrameError('payload has no op');
  }
  return message;
}

/** One frame read from a connection. */
export interface Frame {
  /** `frameJson` or `frameBinary`. */
  readonly type: number;
  /** The payload bytes. */
  readonly payload: Buffer;
}

/**
 * Splits a byte stream into frames, checking every length against
 * `maxPayload` before the payload is read and refusing a frame type that is
 * neither JSON nor (with `binaryAllowed`) binary.
 */
export class FrameReader {
  /** Whether binary frames were negotiated (both sides named `binary`). */
  binaryAllowed = false;

  private pending: Buffer = Buffer.alloc(0);

  constructor(readonly maxPayload: number) {}

  /** Adds [bytes] and returns the frames now complete; throws `FrameError`. */
  add(bytes: Uint8Array): Frame[] {
    const data = this.pending.length === 0
      ? Buffer.from(bytes)
      : Buffer.concat([this.pending, bytes]);
    const frames: Frame[] = [];
    let offset = 0;
    while (data.length - offset >= 5) {
      const length = data.readUInt32BE(offset);
      const type = data[offset + 4]!;
      if (length > this.maxPayload) {
        throw new FrameError(`frame of ${length} bytes over ${this.maxPayload}`);
      }
      if (type !== frameJson && !(type === frameBinary && this.binaryAllowed)) {
        throw new FrameError(`frame type ${type}`);
      }
      if (data.length - offset - 5 < length) break;
      frames.push({
        type,
        payload: Buffer.from(data.subarray(offset + 5, offset + 5 + length)),
      });
      offset += 5 + length;
    }
    this.pending = Buffer.from(data.subarray(offset));
    return frames;
  }
}
