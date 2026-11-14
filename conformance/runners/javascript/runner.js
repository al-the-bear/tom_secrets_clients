// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The conformance runner of the JavaScript client: the compiled package
// @al-the-bear/tom-secrets-client used from plain JavaScript (CommonJS), as
// a JavaScript program uses it (DP-21: one package for both languages).
//
// Reads one case per line on standard input,
//   {"case": name, "runtimeDir": dir, "action": {...}}
// runs its action with the library against the service in runtimeDir, and
// writes one canonical result line per case on standard output,
//   {"case": name, "result": {...}}
// (keys sorted, compact). conformance/README.md defines the actions and the
// result shapes every runner writes.

'use strict';

const { createInterface } = require('node:readline');
const { inspect } = require('node:util');

const { SecretReference, SecretsClient, SecretsError } = require('../../../clients/typescript');

async function main() {
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    if (line.trim() === '') continue;
    const request = JSON.parse(line);
    const result = await runCase(request.runtimeDir, request.action);
    process.stdout.write(`${canonical({ case: request.case, result })}\n`);
  }
}

async function runCase(runtimeDir, action) {
  const options = action.client || {};
  const client = new SecretsClient({
    clientName: 'conformance-runner',
    clientToken: options.clientToken ?? undefined,
    environment: { ...process.env, TSM_RUNTIME_DIR: runtimeDir },
    connectTimeoutMs: 5000,
  });
  try {
    return await run(client, action);
  } finally {
    client.close();
  }
}

async function run(client, action) {
  switch (action.do) {
    case 'parse':
      return guard(async () => {
        const r = SecretReference.parse(action.ref);
        return { parsed: shape(r), canonical: r.canonical };
      });
    case 'format':
      return guard(async () => ({ formatted: SecretReference.format(fromShape(action.parsed)) }));
    case 'connect':
      return guard(async () => {
        await client.open();
        const w = client.welcome;
        return { welcome: { host: w.host, platform: w.platform, features: [...w.features].sort() } };
      });
    case 'get': {
      const progress = [];
      const result = await guard(async () => {
        const v = await client.get(action.ref, {
          field: action.field ?? undefined,
          dimensions: action.dimensions ?? undefined,
          wait: action.wait ?? undefined,
          timeoutMs: action.timeoutMs ?? undefined,
          wantClientToken: action.wantClientToken ?? undefined,
          waitOnRateLimit: action.waitOnRateLimit ?? undefined,
          onProgress: (p) => progress.push(progressShape(p)),
        });
        return { value: valueShape(v) };
      });
      return progress.length > 0 ? { ...result, progress } : result;
    }
    case 'getMany': {
      const progress = [];
      const result = await guard(async () => {
        const results = await client.getMany(
          action.refs.map((r) => ({
            ref: r.ref,
            field: r.field ?? undefined,
            dimensions: r.dimensions ?? undefined,
          })),
          {
            wait: action.wait ?? undefined,
            timeoutMs: action.timeoutMs ?? undefined,
            onProgress: (p) => progress.push(progressShape(p)),
          },
        );
        return {
          results: results.map((r) =>
            r.value !== undefined ? { value: valueShape(r.value) } : { error: errorShape(r.error) },
          ),
        };
      });
      return progress.length > 0 ? { ...result, progress } : result;
    }
    case 'concurrent':
      return { results: await Promise.all(action.actions.map((a) => run(client, a))) };
    case 'sequence': {
      const steps = [];
      for (const step of action.actions) {
        if (step.do === 'pause') {
          await new Promise((resolve) => setTimeout(resolve, step.ms));
          continue;
        }
        steps.push(await run(client, step));
      }
      return { steps };
    }
    default:
      return { unsupportedAction: action.do };
  }
}

async function guard(body) {
  try {
    return await body();
  } catch (e) {
    if (e instanceof SecretsError) return { error: errorShape(e) };
    throw e;
  }
}

function errorShape(e) {
  return e.reason === undefined ? { kind: e.kind } : { kind: e.kind, reason: e.reason };
}

function progressShape(p) {
  return p.approvalCode === undefined
    ? { pending: p.pending }
    : { pending: p.pending, approvalCode: p.approvalCode };
}

function valueShape(v) {
  let text;
  let textRefused = false;
  try {
    text = v.text;
  } catch {
    textRefused = true;
  }
  const printed = [String(v), `${v}`, JSON.stringify(v), inspect(v)];
  const out = {
    encoding: v.encoding,
    base64: Buffer.from(v.bytes).toString('base64'),
    entry: {
      store: v.entry.store,
      uuid: v.entry.uuid,
      source: v.entry.source,
      fetchedAtMs: v.entry.fetchedAt.getTime(),
    },
    bound: v.bound,
    version: { modifiedMs: v.version.modified.getTime(), revision: v.version.revision },
    // Every printable form shows *** and never the value (README, Results);
    // a value that occurs in the reference itself cannot be told apart.
    masked: printed.every(
      (p) =>
        p.includes('***') &&
        (text === undefined || v.reference.includes(text) || !p.includes(text)),
    ),
  };
  if (text !== undefined) out.text = text;
  if (textRefused) out.textRefused = true;
  if (v.expires !== undefined) out.expiresMs = v.expires.getTime();
  if (v.clientToken !== undefined) out.clientToken = v.clientToken;
  v.dispose();
  return out;
}

function shape(r) {
  return {
    qualifiers: r.qualifiers.map((q) => ({ dimension: q.dimension, value: q.value })),
    target: r.target,
    field: r.field,
    fieldGiven: r.fieldGiven,
  };
}

function fromShape(m) {
  const t = m.target;
  const target =
    t.kind === 'key'
      ? { kind: 'key', key: t.key }
      : t.kind === 'uuid'
        ? { kind: 'uuid', store: t.store, uuid: t.uuid }
        : { kind: 'path', store: t.store, segments: t.segments };
  return new SecretReference({
    qualifiers: m.qualifiers.map((q) => ({ dimension: q.dimension, value: q.value })),
    target,
    field: m.field ?? undefined,
  });
}

/** Compact JSON with every object's keys sorted. */
function canonical(value) {
  return JSON.stringify(sorted(value));
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sorted(value[k])]));
  }
  return value;
}

main().catch((e) => {
  process.stderr.write(`${String(e)}\n`);
  process.exit(1);
});
