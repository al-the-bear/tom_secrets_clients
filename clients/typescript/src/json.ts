// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/**
 * The strict JSON a frame's payload must be (protocol.md 2.3): one value,
 * no duplicate member names (which `JSON.parse` would take silently, the
 * last one winning).
 */

/** Parses [text] strictly; throws a `SyntaxError` naming what is wrong. */
export function parseStrictJson(text: string): unknown {
  let i = 0;
  const fail = (what: string): never => {
    throw new SyntaxError(`${what} at ${i}`);
  };
  const ws = (): void => {
    while (i < text.length && ' \t\n\r'.includes(text[i]!)) i++;
  };
  const peek = (ch: string): boolean => {
    if (i < text.length && text[i] === ch) {
      i++;
      return true;
    }
    return false;
  };
  const expect = (ch: string): void => {
    if (!peek(ch)) fail(`"${ch}" expected`);
  };
  const string = (): string => {
    const start = i;
    i++;
    while (i < text.length && text[i] !== '"') {
      if (text[i] === '\\') i++;
      i++;
    }
    if (i >= text.length) fail('unclosed string');
    i++;
    return JSON.parse(text.substring(start, i)) as string;
  };
  const scalar = (): unknown => {
    const start = i;
    while (i < text.length && !',]} \t\n\r'.includes(text[i]!)) i++;
    const token = text.substring(start, i);
    let value: unknown;
    try {
      value = JSON.parse(token);
    } catch {
      return fail('bad value');
    }
    if (value !== null && typeof value === 'object') fail('bad value');
    if (typeof value === 'string') fail('bad value');
    return value;
  };
  const object = (): Record<string, unknown> => {
    const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    i++;
    ws();
    if (peek('}')) return { ...out };
    for (;;) {
      ws();
      if (i >= text.length || text[i] !== '"') fail('member name expected');
      const name = string();
      if (Object.prototype.hasOwnProperty.call(out, name)) {
        fail(`duplicate member "${name}"`);
      }
      ws();
      expect(':');
      out[name] = value();
      ws();
      if (peek('}')) return { ...out };
      expect(',');
    }
  };
  const array = (): unknown[] => {
    const out: unknown[] = [];
    i++;
    ws();
    if (peek(']')) return out;
    for (;;) {
      out.push(value());
      ws();
      if (peek(']')) return out;
      expect(',');
    }
  };
  const value = (): unknown => {
    ws();
    if (i >= text.length) fail('unexpected end');
    switch (text[i]) {
      case '{':
        return object();
      case '[':
        return array();
      case '"':
        return string();
      default:
        return scalar();
    }
  };
  const result = value();
  ws();
  if (i !== text.length) fail('trailing text');
  return result;
}
