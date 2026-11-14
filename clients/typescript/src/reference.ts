// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/** The reference grammar (protocol.md section 4): parse and format. */

import { SecretsError } from './errors';

/** The field a reference without `#field` names. */
export const defaultField = 'Password';

/** The longest reference, in bytes of UTF-8 as sent. */
export const maxReferenceBytes = 1024;

const reserved = '/#[],:%';
const namePattern = /^[a-z][a-z0-9_-]*$/;
const storePattern = /^[a-z0-9][a-z0-9_-]*$/;
const uuidPattern = /^~[0-9A-Fa-f]{32}$/;
const hexPair = /^[0-9a-fA-F]{2}$/;
const utf8Strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

const isControl = (rune: number): boolean => rune < 0x20 || rune === 0x7f;

function malformed(reason: string, detail = ''): SecretsError {
  return new SecretsError(
    'malformed',
    detail === ''
      ? `the reference is malformed: ${reason}`
      : `the reference is malformed: ${reason} (${detail})`,
    { reason },
  );
}

/** A key: the value of an entry's `tsm.key` field (`telegram.bot_token`). */
export interface KeyTarget {
  readonly kind: 'key';
  readonly key: string;
}

/**
 * A path: a store, the group path below its root group and the entry title,
 * each segment unescaped.
 */
export interface PathTarget {
  readonly kind: 'path';
  readonly store: string;
  readonly segments: readonly string[];
}

/** A uuid reference: an entry of a store by its KDBX UUID (lower case). */
export interface UuidTarget {
  readonly kind: 'uuid';
  readonly store: string;
  readonly uuid: string;
}

/** What a reference names. */
export type SecretTarget = KeyTarget | PathTarget | UuidTarget;

/** One binding `<dimension>:<value>` of a reference's qualifiers. */
export interface SecretBinding {
  readonly dimension: string;
  /** Its value, unescaped. */
  readonly value: string;
}

/**
 * A parsed reference. `SecretReference.parse` refuses a malformed one with a
 * `SecretsError` of kind `malformed` whose `reason` is the rule of
 * protocol.md 4.6 it broke; `SecretReference.format` gives the canonical
 * form (4.5).
 */
export class SecretReference {
  /** The bindings in the order written. */
  readonly qualifiers: readonly SecretBinding[];
  /** What the reference names. */
  readonly target: SecretTarget;
  /** The effective field: the one written, else `Password`. */
  readonly field: string;
  /** Whether the reference wrote `#field`. */
  readonly fieldGiven: boolean;

  constructor(parts: {
    qualifiers?: readonly SecretBinding[];
    target: SecretTarget;
    field?: string;
    fieldGiven?: boolean;
  }) {
    this.qualifiers = Object.freeze([...(parts.qualifiers ?? [])]);
    this.target = parts.target;
    this.field = parts.field ?? defaultField;
    this.fieldGiven = parts.fieldGiven ?? false;
  }

  /** The canonical form. */
  get canonical(): string {
    return SecretReference.format(this);
  }

  /** Parses [reference] (protocol.md 4.1-4.4, 4.6). */
  static parse(reference: string): SecretReference {
    if (Buffer.byteLength(reference, 'utf8') > maxReferenceBytes) {
      throw malformed('too_long');
    }
    if (reference === '') throw malformed('empty');
    let rest = reference;
    const qualifiers: SecretBinding[] = [];
    if (rest.startsWith('[')) {
      const end = rest.indexOf(']');
      if (end < 0) throw malformed('unclosed_qualifiers');
      const body = rest.substring(1, end);
      rest = rest.substring(end + 1);
      if (body === '') throw malformed('empty_segment', '[]');
      const seen = new Set<string>();
      for (const binding of body.split(',')) {
        const parts = binding.split(':');
        if (parts.length !== 2) throw malformed('bad_binding', binding);
        const [name, value] = parts as [string, string];
        if (!namePattern.test(name)) throw malformed('bad_dimension', name);
        if (seen.has(name)) throw malformed('duplicate_dimension', name);
        seen.add(name);
        qualifiers.push({ dimension: name, value: decodeSegment(value) });
      }
    }
    if (rest.split('#').length > 2) throw malformed('reserved_character', '#');
    const hash = rest.indexOf('#');
    const fieldGiven = hash >= 0;
    const targetText = fieldGiven ? rest.substring(0, hash) : rest;
    if (targetText === '') throw malformed('empty_target');
    const field = fieldGiven ? decodeSegment(rest.substring(hash + 1)) : defaultField;
    let target: SecretTarget;
    if (!targetText.includes('/')) {
      if (!targetText.split('.').every((p) => namePattern.test(p))) {
        throw malformed('bad_key', targetText);
      }
      target = { kind: 'key', key: targetText };
    } else {
      const parts = targetText.split('/');
      const store = parts[0]!;
      if (!storePattern.test(store)) throw malformed('bad_store', store);
      const raw = parts.slice(1);
      if (raw.length === 1 && raw[0]!.startsWith('~')) {
        if (!uuidPattern.test(raw[0]!)) throw malformed('bad_uuid', raw[0]);
        target = { kind: 'uuid', store, uuid: raw[0]!.substring(1).toLowerCase() };
      } else {
        const segments: string[] = [];
        for (const segment of raw) {
          if (segment === '') throw malformed('empty_segment');
          if (segment.startsWith('@') || segment.startsWith('~')) {
            throw malformed('reserved_prefix', segment[0]);
          }
          segments.push(decodeSegment(segment));
        }
        target = { kind: 'path', store, segments: Object.freeze(segments) };
      }
    }
    return new SecretReference({ qualifiers, target, field, fieldGiven });
  }

  /**
   * The canonical text of [reference]: bindings sorted by dimension name
   * (by UTF-8 bytes), every segment escaped in exactly what it must be, the
   * uuid in lower case, the field omitted when it is `Password`.
   */
  static format(reference: SecretReference): string {
    let out = '';
    const bindings = [...reference.qualifiers].sort((a, b) =>
      Buffer.compare(Buffer.from(a.dimension, 'utf8'), Buffer.from(b.dimension, 'utf8')),
    );
    if (bindings.length > 0) {
      if (new Set(bindings.map((b) => b.dimension)).size !== bindings.length) {
        throw new RangeError('a dimension is bound once');
      }
      out += `[${bindings.map((b) => `${b.dimension}:${encodeSegment(b.value)}`).join(',')}]`;
    }
    const target = reference.target;
    switch (target.kind) {
      case 'key':
        out += target.key;
        break;
      case 'uuid':
        out += `${target.store}/~${target.uuid.toLowerCase()}`;
        break;
      case 'path':
        out += `${target.store}/${target.segments.map((s) => encodeSegment(s, true)).join('/')}`;
        break;
    }
    if (reference.field !== defaultField) out += `#${encodeSegment(reference.field)}`;
    return out;
  }

  toString(): string {
    return this.canonical;
  }
}

function decodeSegment(raw: string): string {
  if (raw === '') throw malformed('empty_segment');
  const bytes: number[] = [];
  const runes = Array.from(raw);
  for (let i = 0; i < runes.length; i++) {
    const ch = runes[i]!;
    const rune = ch.codePointAt(0)!;
    if (rune === 0x25) {
      const pair = runes.slice(i + 1, i + 3).join('');
      if (!hexPair.test(pair)) throw malformed('bad_escape', `%${pair}`);
      bytes.push(Number.parseInt(pair, 16));
      i += 2;
      continue;
    }
    if (reserved.includes(ch)) throw malformed('reserved_character', ch);
    if (isControl(rune)) {
      throw malformed(
        'control_character',
        `U+${rune.toString(16).toUpperCase().padStart(4, '0')}`,
      );
    }
    for (const b of Buffer.from(ch, 'utf8')) bytes.push(b);
  }
  try {
    return utf8Strict.decode(Uint8Array.from(bytes));
  } catch (e) {
    throw malformed('bad_utf8', (e as Error).message);
  }
}

function encodeSegment(text: string, path = false): string {
  if (text === '') throw new RangeError('a segment is never empty');
  let out = '';
  let first = true;
  for (const ch of text) {
    const rune = ch.codePointAt(0)!;
    if (reserved.includes(ch) || isControl(rune) || (path && first && (ch === '@' || ch === '~'))) {
      for (const b of Buffer.from(ch, 'utf8')) {
        out += `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
      }
    } else {
      out += ch;
    }
    first = false;
  }
  return out;
}
