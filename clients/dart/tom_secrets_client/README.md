# Tom Secrets Client

The Dart client of the Tom Secrets Manager. A program reads its secrets from
the secrets service running on the same machine: the library finds the
service, speaks its client protocol and parses and formats secret
references. It never opens a vault and never resolves a reference; the
service does both.

```dart
import 'package:tom_secrets_client/tom_secrets_client.dart';

Future<void> main() async {
  final client = await TomSecretsClient.connect();
  final value = await client.get(
    '[env:prod]db.main',
    field: 'UserName',
    onProgress: (p) => print('waiting for ${p.pending.name}'
        '${p.approvalCode == null ? '' : ' (code ${p.approvalCode})'}'),
  );
  print(value.entry.store);
  useSecret(value.text);
  value.dispose();
  await client.close();
}
```

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
`TomSecretsErrorKind.notRunning`. On Linux and macOS the endpoint is a Unix
socket, whose path the OS limits to about 100 bytes: a `TSM_RUNTIME_DIR` may
be relative to the working directory to stay under it. On Windows the client
token is re-read at every connect, because it changes with every service
start.

## Calls

- `TomSecretsClient.connect()` connects at once; `TomSecretsClient()`
  connects on its first call; `TomSecretsClient.shared` is one per process.
  After `notRunning` or a dropped connection the next call connects again.
  Calls may overlap on the one connection.
- `get(reference, field:, dimensions:, wait:, timeout:, wantClientToken:,
  onProgress:, waitOnRateLimit:)` reads one secret. `wait` defaults to true:
  the service waits for an unlock or an approval up to `timeout` (sent as
  `timeoutMs`, capped by the service), and `onProgress` hears why it waits,
  with the approval code when no approver is connected.
- `getMany([TomSecretRequest(...)])` reads up to 256 secrets under one
  approval prompt; the results come in request order, each a value or an
  error.
- `getFile(reference)` **(phase B)** reads an attachment or a typed key as
  bytes; it needs a service that offers the features `binary` and `getFile`,
  else it fails as `unsupported`.
- `TomSecretReference.parse` / `format` handle the reference grammar
  (percent-encoding, qualifiers, the canonical form). A malformed reference
  fails locally as `malformed`, with `reason` naming the rule it broke,
  without a round trip.

## Values

A `TomSecretValue` carries the value as `text` or `bytes`, its `entry`
(store, UUID, `github` or `cache`, fetch time), the `bound` dimensions, the
`version` (modification time and store revision: compare it to see a
change), `expires` and a granted `clientToken`.

- `text` refuses a binary value (`StateError`) instead of corrupting it.
- `toString()` never shows the secret: `TomSecretValue(db.main: ***)`.
- `dispose()` overwrites the buffer with zeros. A `text` string you took out
  is an immutable Dart string the library cannot overwrite: it is yours to
  handle.
- A client token is yours to keep; pass it as `clientToken:` to a later
  client. The library never stores one.

## Errors

Every failure is a `TomSecretsClientException` with a `kind`
(`TomSecretsErrorKind`: the protocol's kinds plus `notRunning`), a message
for people and `details` (`reason`, `candidates`, `retryAfterMs`, ...). An
unknown kind from a later service is `internal`, and so is a service that
breaks the protocol (an oversized or malformed frame closes the connection).
`denied`, `ambiguous` and `notFound` are never retried; `rateLimited` is
waited out only with `waitOnRateLimit: true`. The library logs nothing: no
value, token or payload.

## The protocol

The library follows the Tom Secrets Manager protocol document, version 1, and
its tests check it against every vector of the document that a client
computes (references, discovery, port files, frames).

## Licence

BSD-3-Clause (`LICENSE`).
