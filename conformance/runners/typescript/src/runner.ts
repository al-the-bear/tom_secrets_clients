// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The conformance runner of the TypeScript client
// (@al-the-bear/tom-secrets-client), written in TypeScript against its
// declarations.
//
// Reads one case per line on standard input,
//   {"case": name, "runtimeDir": dir, "action": {...}}
// runs its action with the library against the service in runtimeDir, and
// writes one canonical result line per case on standard output,
//   {"case": name, "result": {...}}
// (keys sorted, compact). conformance/README.md defines the actions and the
// result shapes every runner writes.

import { createInterface } from 'node:readline';
import { inspect } from 'node:util';

import {
  SecretReference,
  SecretsClient,
  SecretsError,
  type Progress,
  type SecretTarget,
  type SecretValue,
} from '../../../../clients/typescript';

type Json = Record<string, unknown>;

async function main(): Promise<void> {
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    if (line.trim() === '') continue;
    const request = JSON.parse(line) as Json;
    const result = await runCase(request['runtimeDir'] as string, request['action'] as Json);
    process.stdout.write(`${canonical({ case: request['case'], result })}\n`);
  }
}

async function runCase(runtimeDir: string, action: Json): Promise<Json> {
  const options = (action['client'] ?? {}) as Json;
  const clientToken = options['clientToken'];
  const client = new SecretsClient({
    clientName: 'conformance-runner',
    ...(typeof clientToken === 'string' ? { clientToken } : {}),
    environment: { ...process.env, TSM_RUNTIME_DIR: runtimeDir },
    connectTimeoutMs: 5000,
  });
  try {
    return await run(client, action);
  } finally {
    client.close();
  }
}

async function run(client: SecretsClient, action: Json): Promise<Json> {
  switch (action['do']) {
    case 'parse':
      return guard(async () => {
        const r = SecretReference.parse(action['ref'] as string);
        return { parsed: shape(r), canonical: r.canonical };
      });
    case 'format':
      return guard(async () => ({
        formatted: SecretReference.format(fromShape(action['parsed'] as Json)),
      }));
    case 'connect':
      return guard(async () => {
        await client.open();
        const w = client.welcome!;
        return { welcome: { host: w.host, platform: w.platform, features: [...w.features].sort() } };
      });
    case 'get': {
      const progress: Json[] = [];
      const result = await guard(async () => {
        const v = await client.get(action['ref'] as string, {
          ...optional('field', action['field']),
          ...optional('dimensions', action['dimensions']),
          ...optional('wait', action['wait']),
          ...optional('timeoutMs', action['timeoutMs']),
          ...optional('wantClientToken', action['wantClientToken']),
          ...optional('waitOnRateLimit', action['waitOnRateLimit']),
          onProgress: (p) => progress.push(progressShape(p)),
        });
        return { value: valueShape(v) };
      });
      return progress.length > 0 ? { ...result, progress } : result;
    }
    case 'getMany': {
      const progress: Json[] = [];
      const result = await guard(async () => {
        const refs = (action['refs'] as Json[]).map((r) => ({
          ref: r['ref'] as string,
          ...optional('field', r['field']),
          ...optional('dimensions', r['dimensions']),
        }));
        const results = await client.getMany(refs, {
          ...optional('wait', action['wait']),
          ...optional('timeoutMs', action['timeoutMs']),
          onProgress: (p) => progress.push(progressShape(p)),
        });
        return {
          results: results.map((r) =>
            r.value !== undefined ? { value: valueShape(r.value) } : { error: errorShape(r.error) },
          ),
        };
      });
      return progress.length > 0 ? { ...result, progress } : result;
    }
    case 'concurrent':
      return {
        results: await Promise.all((action['actions'] as Json[]).map((a) => run(client, a))),
      };
    case 'sequence': {
      const steps: Json[] = [];
      for (const step of action['actions'] as Json[]) {
        if (step['do'] === 'pause') {
          await new Promise((resolve) => setTimeout(resolve, step['ms'] as number));
          continue;
        }
        steps.push(await run(client, step));
      }
      return { steps };
    }
    default:
      return { unsupportedAction: action['do'] };
  }
}

/**
 * `{[name]: value}` when the case gives it, else nothing; the case's JSON is
 * the library's options as they are (`any`: the tables are trusted input).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function optional(name: string, value: unknown): Record<string, any> {
  return value === undefined || value === null ? {} : { [name]: value };
}

async function guard(body: () => Promise<Json>): Promise<Json> {
  try {
    return await body();
  } catch (e) {
    if (e instanceof SecretsError) return { error: errorShape(e) };
    throw e;
  }
}

function errorShape(e: SecretsError): Json {
  return e.reason === undefined ? { kind: e.kind } : { kind: e.kind, reason: e.reason };
}

function progressShape(p: Progress): Json {
  return p.approvalCode === undefined
    ? { pending: p.pending }
    : { pending: p.pending, approvalCode: p.approvalCode };
}

function valueShape(v: SecretValue): Json {
  let text: string | undefined;
  let textRefused = false;
  try {
    text = v.text;
  } catch {
    textRefused = true;
  }
  const printed = [String(v), `${v}`, JSON.stringify(v), inspect(v)];
  const out: Json = {
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
  if (text !== undefined) out['text'] = text;
  if (textRefused) out['textRefused'] = true;
  if (v.expires !== undefined) out['expiresMs'] = v.expires.getTime();
  if (v.clientToken !== undefined) out['clientToken'] = v.clientToken;
  v.dispose();
  return out;
}

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
  let target: SecretTarget;
  switch (t['kind']) {
    case 'key':
      target = { kind: 'key', key: t['key'] as string };
      break;
    case 'uuid':
      target = { kind: 'uuid', store: t['store'] as string, uuid: t['uuid'] as string };
      break;
    default:
      target = { kind: 'path', store: t['store'] as string, segments: t['segments'] as string[] };
  }
  return new SecretReference({
    qualifiers: (m['qualifiers'] as Json[]).map((q) => ({
      dimension: q['dimension'] as string,
      value: q['value'] as string,
    })),
    target,
    ...optional('field', m['field']),
  });
}

/** Compact JSON with every object's keys sorted. */
function canonical(value: unknown): string {
  return JSON.stringify(sorted(value));
}

function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === 'object') {
    const m = value as Json;
    return Object.fromEntries(Object.keys(m).sort().map((k) => [k, sorted(m[k])]));
  }
  return value;
}

main().catch((e: unknown) => {
  process.stderr.write(`${String(e)}\n`);
  process.exit(1);
});
