# @al-the-bear/tom-secrets-client

> Part of the Tom Secrets Manager by Peter Nicolai Alexis Kyaw.

The TypeScript and JavaScript client of the Tom Secrets Manager for Node.js:
finds the local secrets service, speaks its client protocol and parses and
formats secret references.

## Overview

The Tom Secrets Manager keeps secrets in KDBX vaults and serves them to the
programs of one machine through a local **secrets service**. A program reads a
secret by its **reference** (`telegram.bot_token`, `fleet/Db/Main#UserName`);
the service resolves it, asks an approver when no grant answers the request,
and returns the value.

This library is the program's side of that. It finds the service in the
runtime directory of the OS user, connects over a Unix socket (on Windows a
localhost port), and sends `get` and `getMany` requests. It never opens a
vault and never resolves a reference: the service does both.

One package serves both languages. It is written in TypeScript and ships as
CommonJS with its type declarations, so TypeScript, plain JavaScript
(`require`) and ES modules (`import`) use the same code. It has no runtime
dependencies; it uses Node's `net` and `fs`.

## Installation

```sh
npm install @al-the-bear/tom-secrets-client
```

Node.js 18 or later (`engines: node >=18`) on Linux, macOS or Windows. The
secrets service must run on the same machine, for the same OS user: the
manager app starts it on a desktop, `tsm start` on a server.

## Quick start

TypeScript (or an ES module):

```ts
import { SecretsClient } from '@al-the-bear/tom-secrets-client';

const client = await SecretsClient.connect();
const value = await client.get('[env:prod]db.main', {
  field: 'UserName',
  onProgress: (p) =>
    console.error(`waiting for ${p.pending}${p.approvalCode ? ` (code ${p.approvalCode})` : ''}`),
});
console.log(value.entry.store); // the store the value came from, e.g. fleet
connectToDatabase(value.text);
value.dispose();
client.close();
```

Plain JavaScript (CommonJS):

```js
const { SecretsClient } = require('@al-the-bear/tom-secrets-client');

async function main() {
  const value = await SecretsClient.shared.get('telegram.bot_token');
  startBot(value.text);
  value.dispose();
  SecretsClient.shared.close();
}

main().catch((e) => {
  console.error(String(e)); // e.g. SecretsError(not_running): the secrets service is not running: ...
  process.exit(1);
});
```

The first read of a secret by a program may wait for an approval: the manager
app (or a trusted device) asks the user. When no approver is connected,
`onProgress` hears the approval code to answer on a trusted device.

## API

Everything below is exported from the package root.

### `SecretsClient`

| Member | What it does |
| --- | --- |
| `new SecretsClient(options?)` | A client that connects on its first call. |
| `SecretsClient.connect(options?)` | Creates a client and connects it at once, so a missing service shows as `not_running` right away. |
| `SecretsClient.shared` | One client per process, created on first use with the defaults. |
| `get(ref, options?)` | Reads one secret; resolves to a `SecretValue`. |
| `getMany(requests, options?)` | Reads 1 to 256 secrets under one approval prompt; resolves to `SecretResult[]` in request order, each `{ value }` or `{ error }`. |
| `open()` | Connects, unless a connection is open. |
| `close()` | Closes the connection; a later call connects again. |
| `welcome` | The service's `welcome` on the current connection (`protocol`, `serviceVersion`, `features`, `host`, `platform`), or `undefined`. |
| `clientName`, `clientToken`, `connectTimeoutMs` | The options the client was made with. |

After `not_running` or a dropped connection, the next call connects again.
Calls may overlap on the one connection.

`ClientOptions`:

| Option | Default | Meaning |
| --- | --- | --- |
| `clientName` | the script's name | Shown in approval prompts; never trusted (the service measures the process). |
| `clientToken` | none | A client token the program was granted before, sent with every connection. |
| `environment` | `process.env` | Where `TSM_RUNTIME_DIR` and the OS variables are read from. |
| `operatingSystem` | this process's | `linux`, `macos` or `windows`. |
| `connectTimeoutMs` | `10000` | How long connecting and the service's `welcome` may take. |

`GetOptions` (for `get`) and `RequestOptions` (for `getMany`):

| Option | Meaning |
| --- | --- |
| `wait` | Wait for an unlock or an approval (default `true`); `false` answers at once (`locked` when locked). |
| `timeoutMs` | How long the service may wait, capped by the service. |
| `onProgress` | Called with a `Progress` (`pending`: `unlock` or `approval`, `approvalCode` when no approver is connected) while the request waits. |
| `waitOnRateLimit` | Wait out a `rate_limited` answer and send the request again (default off). |
| `field` (`get` only) | The field, when the reference names none. |
| `dimensions` (`get` only) | Values for dimensions, `{ env: 'prod' }`, beside the reference. |
| `wantClientToken` (`get` only) | Ask for a client token with an "always" approval. |

A `SecretRequest` for `getMany` is `{ ref, field?, dimensions? }`.

### `SecretValue`

| Member | Meaning |
| --- | --- |
| `text` | The value as a string; throws for a binary value instead of corrupting it. |
| `bytes` | The value as a `Uint8Array` view of the buffer (text as UTF-8); copy it to keep it. |
| `encoding` | `utf8` or `base64` (binary). |
| `reference` | The reference as asked for. |
| `entry` | `{ store, uuid, source, fetchedAt }`; `source` is `github`, `file` or `cache`. |
| `bound` | The dimension values the winning entry carries. |
| `version` | `{ modified, revision }`: compare it to see a change. |
| `expires` | The entry's expiry, or `undefined`. |
| `clientToken` | A client token the service granted, or `undefined`. |
| `dispose()`, `isDisposed` | Overwrites the buffer with zeros; the value cannot be read afterwards. |

- No printable form shows the secret: `String(value)`, `JSON.stringify` and
  `console.log` give `SecretValue(db.main: ***)` or a masked object.
- A `text` string taken out is an immutable JavaScript string the library
  cannot overwrite: it is yours to handle.
- A client token is yours to keep; pass it as `clientToken` to a later
  client. The library never stores one.

### `SecretReference`

| Member | What it does |
| --- | --- |
| `SecretReference.parse(text)` | Parses a reference; a malformed one throws a `SecretsError` of kind `malformed` whose `reason` names the rule it broke. |
| `SecretReference.format(ref)`, `ref.canonical`, `ref.toString()` | The canonical form. |
| `new SecretReference({ target, field?, fieldGiven?, qualifiers? })` | Builds a reference from its parts. |
| `target` | `{ kind: 'key', key }`, `{ kind: 'path', store, segments }` or `{ kind: 'uuid', store, uuid }`. |
| `field`, `fieldGiven` | The effective field (`Password` when none is written) and whether one was written. |
| `qualifiers` | The bindings, `{ dimension, value }`, in the order written. |

```js
const { SecretReference } = require('@al-the-bear/tom-secrets-client');

SecretReference.parse('[host:server1,env:prod]fleet/Db/Main#Password').canonical;
// '[env:prod,host:server1]fleet/Db/Main'
```

`get` and `getMany` parse every reference locally first: a malformed one
fails without a round trip, and so do a field named twice (`field_twice`) and
a request over 64 KiB (`frame`).

### Lower-level exports

| Export | What it is |
| --- | --- |
| `discover(operatingSystem, environment)` | The runtime directory and endpoint files the client looks for. |
| `currentOperatingSystem()` | `linux`, `macos` or `windows` for this process. |
| `readPortFile(text)` | The port of a Windows port file, or `undefined`. |
| `errorKindFromWire(kind)`, `sourceFromWire(name)` | Map protocol names to the library's types. |
| `defaultField`, `maxReferenceBytes`, `maxGetMany` | `Password`, 1024, 256. |
| `protocolVersion`, `clientVersion` | The protocol version spoken (1) and this library's version. |

## Errors

Every failure is a `SecretsError` (an `Error`) with:

- `kind`, a `SecretsErrorKind`: the protocol's kinds `locked`, `denied`,
  `not_found`, `ambiguous`, `needs_unlock`, `unavailable`, `offline`,
  `token_expired`, `malformed`, `timeout`, `rate_limited`, `unsupported`,
  `internal`, plus `not_running` (no service found, or the connection lost);
- `message`, for people; never a value, token or key;
- `details` (`reason`, `candidates`, `retryAfterMs`, ...) and the shortcut
  `reason`.

```ts
import { SecretsClient, SecretsError } from '@al-the-bear/tom-secrets-client';

try {
  const value = await SecretsClient.shared.get('db.main', { wait: false });
  useSecret(value.text);
  value.dispose();
} catch (e) {
  if (e instanceof SecretsError && e.kind === 'locked') {
    console.error('unlock the Tom Secrets Manager first');
  } else {
    throw e;
  }
}
```

An unknown kind from a later service is `internal`, and so is a service that
breaks the protocol (an answer frame over 1 MiB, an unknown frame type or a
malformed payload closes the connection). `denied`, `ambiguous` and
`not_found` are never retried; `rate_limited` is waited out only with
`waitOnRateLimit: true`. The library logs nothing: no value, token or
payload.

## Configuration

The library looks for the service in the runtime directory of the OS user:

| OS | Where |
| --- | --- |
| any | `$TSM_RUNTIME_DIR` when set (containers, tests) |
| Linux | `$XDG_RUNTIME_DIR/tsm/`, else `/tmp/tsm-<uid>/` |
| macOS | `$TMPDIR/tsm/`, else `/tmp/tsm-<uid>/` |
| Windows | `%LOCALAPPDATA%\TomSecretsManager\run\` (`client.port`, `client.token`) |

- No socket or port file, an unreadable port file or a refused connection is
  `not_running`.
- On Linux and macOS the endpoint is a Unix socket, whose path the OS limits
  to about 100 bytes: a `TSM_RUNTIME_DIR` may be relative to the working
  directory to stay under it.
- On Windows the client token is re-read at every connect, because it changes
  with every service start.
- Pass `environment` to the client to look elsewhere than `process.env`.

## Further documentation

| Document | What is there |
| --- | --- |
| [The protocol](../../protocol/protocol.md) | The reference grammar (section 4), the client endpoint (section 5), approvals and client tokens (section 7), the error kinds (section 10) |
| [Conformance suite](../../conformance/README.md) | The fake service and the cases every client runs (runners `typescript` and `javascript`) |
| [tsm](../dart/tsm/README.md) | The command line: secrets for shell scripts, and administering the service |
| [Dart client](../dart/tom_secrets_client/README.md) | The same client for Dart |
| [CHANGELOG](CHANGELOG.md) | The changes per version |

## Developing

```sh
npm ci
npm test        # compiles the library and the tests, runs them with node:test
npm run build   # dist/
```

## Status

Version 0.1.0, protocol version 1. The tests check the library against every
vector of the protocol document that a client computes (references,
discovery, port files, frames) and against a scripted service on a local socket;
the conformance suite runs it against the fake service. `getFile`
(attachments and typed keys as bytes) is not part of this version.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
