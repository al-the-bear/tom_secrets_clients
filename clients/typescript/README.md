# Tom Secrets Client for TypeScript and JavaScript

The TypeScript and JavaScript client of the Tom Secrets Manager, for Node.js.
A program reads its secrets from the secrets service running on the same
machine: the library finds the service, speaks its client protocol and parses
and formats secret references. It never opens a vault and never resolves a
reference; the service does both.

One package serves both languages: it is written in TypeScript and ships as
CommonJS with its type declarations, so TypeScript, plain JavaScript
(`require`) and ES modules (`import`) use the same code. It has no runtime
dependencies; it uses Node's `net` and `fs`.

```ts
import { SecretsClient } from '@al-the-bear/tom-secrets-client';

const client = await SecretsClient.connect();
const value = await client.get('[env:prod]db.main', {
  field: 'UserName',
  onProgress: (p) =>
    console.error(`waiting for ${p.pending}${p.approvalCode ? ` (code ${p.approvalCode})` : ''}`),
});
console.log(value.entry.store);
useSecret(value.text);
value.dispose();
client.close();
```

```js
const { SecretsClient } = require('@al-the-bear/tom-secrets-client');

const token = await SecretsClient.shared.get('telegram.bot_token');
```

## Installing

```text
npm install @al-the-bear/tom-secrets-client
```

Node.js 18 or later.

## Finding the service

The library looks in the runtime directory of the OS user (protocol section
3):

| OS | Where |
| --- | --- |
| any | `$TSM_RUNTIME_DIR` when set (containers, tests) |
| Linux | `$XDG_RUNTIME_DIR/tsm/`, else `/tmp/tsm-<uid>/` |
| macOS | `$TMPDIR/tsm/`, else `/tmp/tsm-<uid>/` |
| Windows | `%LOCALAPPDATA%\TomSecretsManager\run\` (`client.port`, `client.token`) |

No socket or port file, an unreadable port file or a refused connection is
`not_running`. On Linux and macOS the endpoint is a Unix socket, whose path
the OS limits to about 100 bytes: a `TSM_RUNTIME_DIR` may be relative to the
working directory to stay under it. On Windows the client token is re-read at
every connect, because it changes with every service start.

## Calls

- `SecretsClient.connect(options)` connects at once; `new
  SecretsClient(options)` connects on its first call; `SecretsClient.shared`
  is one per process. The options are `clientName` (shown in approval
  prompts, default the script's name), `clientToken`, `environment`,
  `operatingSystem` and `connectTimeoutMs`. After `not_running` or a dropped
  connection the next call connects again. Calls may overlap on the one
  connection.
- `get(ref, {field, dimensions, wait, timeoutMs, wantClientToken, onProgress,
  waitOnRateLimit})` reads one secret. `wait` defaults to true: the service
  waits for an unlock or an approval up to `timeoutMs` (capped by the
  service), and `onProgress` hears why it waits, with the approval code when
  no approver is connected.
- `getMany([{ref, field, dimensions}, ...], {wait, timeoutMs, onProgress,
  waitOnRateLimit})` reads up to 256 secrets under one approval prompt; the
  results come in request order, each `{value}` or `{error}`.
- `close()` closes the connection; a later call connects again.
- `SecretReference.parse` / `SecretReference.format` handle the reference
  grammar (percent-encoding, qualifiers, the canonical form). A malformed
  reference fails locally as `malformed`, with `reason` naming the rule it
  broke, without a round trip. So do two different fields (`field_twice`) and
  a request over 64 KiB (`frame`).

`getFile` (attachments and typed keys as bytes) comes with phase B of the
protocol.

## Values

A `SecretValue` carries the value as `text` or `bytes`, its `entry` (store,
UUID, source `github`, `file` or `cache`, fetch time), the `bound` dimensions,
the `version` (modification time and store revision: compare it to see a
change), `expires` and a granted `clientToken`.

- `text` throws for a binary value instead of corrupting it; read `bytes`.
- No printable form shows the secret: `String(value)`, `JSON.stringify` and
  `console.log` (`util.inspect`) give `SecretValue(db.main: ***)` or a
  masked object.
- `dispose()` overwrites the buffer with zeros. A `text` string you took out
  is an immutable JavaScript string the library cannot overwrite: it is yours
  to handle.
- A client token is yours to keep; pass it as `clientToken` to a later
  client. The library never stores one.

## Errors

Every failure is a `SecretsError` with a `kind` (`SecretsErrorKind`: the
protocol's kinds plus `not_running`), a message for people and `details`
(`reason`, `candidates`, `retryAfterMs`, ...). An unknown kind from a later
service is `internal`, and so is a service that breaks the protocol (an answer
frame over 1 MiB, an unknown frame type or a malformed payload closes the
connection). `denied`, `ambiguous` and `not_found` are never retried;
`rate_limited` is waited out only with `waitOnRateLimit: true`. The library
logs nothing: no value, token or payload.

## The protocol

The library follows the Tom Secrets Manager protocol document, version 1. Its
tests check it against every vector of the document that a client computes
(references, discovery, port files, frames), and the conformance suite
(`conformance/`, runners `typescript` and `javascript`) runs it against the
fake service.

## Developing

```text
npm ci
npm test        # compiles the library and the tests, runs them with node:test
npm run build   # dist/
```

## Licence

BSD-3-Clause (`LICENSE`).
