# tom_secrets_client

The Dart client of the Tom Secrets Manager: finds the local secrets service,
speaks its client protocol (frames, hello, get, getMany, getFile) and parses
and formats secret references.

## Overview

A program reads its secrets from the secrets service running on the same
machine for the same OS user. This library finds that service through its
runtime directory, connects to its client endpoint (a Unix domain socket on
Linux and macOS, a localhost TCP port with a client token on Windows) and
asks for secrets by reference, such as `[env:prod]db.main#UserName`. The
service resolves the reference, asks for an unlock or an approval when it
must, and answers the value. The library never opens a vault and never
resolves a reference itself; it links no KDBX code and no native library.

The package has two libraries:

- `package:tom_secrets_client/tom_secrets_client.dart` is the client: what
  every program that reads secrets imports.
- `package:tom_secrets_client/admin.dart` is the admin side of the local
  protocol, for the manager app, the command line `tsm` and the service
  itself: the admin endpoint with its mutual challenge, the runtime
  directory, starting the service, the pairing mode, the data directory and
  the keychain names. A program that only reads secrets needs none of it.

## Installation

```bash
dart pub add tom_secrets_client
```

or in `pubspec.yaml`:

```yaml
dependencies:
  tom_secrets_client: ^0.2.1
```

Dart SDK `^3.10.0`. The only dependency is `crypto` (SHA-256 and
HMAC-SHA256). A secrets service must run on the machine for a call to
succeed; without one every call fails as `notRunning`.

## Features

### Reading secrets

| Feature | What it does |
| --- | --- |
| `get` | Reads one secret by reference, with an optional field and dimension values |
| `getMany` | Reads 1 to 256 secrets under one approval prompt; results in request order |
| `getFile` | Reads an attachment or a typed key as bytes over binary frames, checked against its SHA-256 (needs a service offering `binary` and `getFile`) |
| Waiting | The service waits for an unlock or an approval up to a timeout; progress notices say why, with the approval code when no approver is connected |
| Rate limits | `rateLimited` is waited out and the request sent again on request |
| Client tokens | A granted client token is handed to the caller, never stored |

### Protocol

| Feature | What it does |
| --- | --- |
| Discovery | Finds the runtime directory per OS, honouring `TSM_RUNTIME_DIR` |
| Frames | Length-prefixed frames with size limits checked before a payload is read |
| Strict JSON | Refuses empty, non-UTF-8, BOM-prefixed and duplicate-member payloads |
| Reconnect | One connection per client, opened on first use and again after a drop; calls may overlap |
| Version negotiation | `hello` / `welcome`; another protocol version is `unsupported` |

### Reference grammar

| Feature | What it does |
| --- | --- |
| Parsing | Key, path and uuid targets, qualifiers (`[dim:value,...]`), `#field`, percent-escapes |
| Canonical form | Bindings sorted, segments escaped exactly as needed, uuid lower case, `Password` omitted |
| Local refusal | A malformed reference fails as `malformed` with the rule it broke, without a round trip |

### Values

| Feature | What it does |
| --- | --- |
| Text or bytes | `text` refuses a binary value instead of corrupting it |
| Masked | `toString()` never shows the secret |
| Dispose | `dispose()` overwrites the buffer with zeros |
| Metadata | Entry (store, UUID, source, fetch time), bound dimensions, version, expiry |

### Admin library

| Feature | What it does |
| --- | --- |
| Admin client | The admin endpoint's mutual HMAC-SHA256 challenge, `claim` with the master password, requests by id, `unlock`, the event stream |
| Runtime directory | Creates and checks the user-only directory, the single-instance lock, `service.json`, the endpoint files |
| Starting the service | Starts the service detached and hands it the admin key on its standard input |
| Pairing mode | Drives the service's pairing mode, as `tsm pair` does on a headless machine |
| Keyring | Keeps the admin keys in the OS keychain with an index of their starts |
| Paths | The data directory, the bootstrap file and the distribution layout |

## Quick start

```dart
import 'package:tom_secrets_client/tom_secrets_client.dart';

Future<void> main() async {
  // References are parsed locally; no service is needed for this.
  final reference = TomSecretReference.parse('[env:prod]db.main#UserName');
  print(reference.canonical); // [env:prod]db.main#UserName

  final client = TomSecretsClient(clientName: 'quick_start');
  try {
    final value = await client.get('[env:prod]db.main', field: 'UserName');
    print(value); // TomSecretValue([env:prod]db.main: ***)
    print(value.entry.store); // the store that holds it
    value.dispose();
  } on TomSecretsClientException catch (e) {
    print(e.kind.wireName); // not_running, when no service runs
  } finally {
    await client.close();
  }
}
```

## Example projects

| Sample | Demonstrates |
| --- | --- |
| [`example/tom_secrets_client_example.dart`](example/tom_secrets_client_example.dart) | Parsing a reference from the command line, reading it with progress notices, printing where it came from but never the value |

## Usage

### Connecting

`TomSecretsClient()` connects on its first call; `TomSecretsClient.connect()`
connects at once, so a missing service shows immediately;
`TomSecretsClient.shared` is one client per process. After `notRunning` or
a dropped connection the next call connects again. `clientName` is shown in
approval prompts (default: the executable's name) and is never trusted for
identity; the service identifies a client by its executable.

```dart
final client = await TomSecretsClient.connect(clientName: 'billing_job');
print(client.welcome?.serviceVersion);
print(client.welcome?.features); // e.g. {binary, getFile}
await client.close();
```

### Reading a secret

```dart
final value = await client.get(
  'db.main', // a key; the field defaults to Password
  dimensions: {'env': 'staging'},
  timeout: const Duration(seconds: 30),
);
final password = value.text;
print(value.bound); // the dimensions the winning entry carries
print(value.version.revision); // compare to see a change
value.dispose();
```

A field named both in the reference and as `field:` is sent once when they
agree; two different ones fail as `malformed` (reason `field_twice`). With
`wait: false` a locked service answers `locked` at once. `text` is an
immutable Dart string the library cannot overwrite; `bytes` is a view of
the buffer `dispose()` clears.

### Reading several secrets

```dart
final results = await client.getMany([
  const TomSecretRequest('db.main', field: 'UserName'),
  const TomSecretRequest('db.main'),
  const TomSecretRequest('telegram.bot_token'),
]);
for (final result in results) {
  if (result.value case final value?) {
    print(value); // masked
    value.dispose();
  } else {
    print(result.error!.kind);
  }
}
```

One approval prompt lists every reference. A malformed reference among them
fails the whole call locally before anything is sent; an empty list or more
than 256 requests is an `ArgumentError`.

### References

```dart
final path = TomSecretReference.parse('team/Servers/web%2F01#Password');
print((path.target as TomSecretPathTarget).segments); // [Servers, web/01]
print(path.canonical); // team/Servers/web%2F01

final built = TomSecretReference(
  qualifiers: const [TomSecretBinding('env', 'prod')],
  target: const TomSecretKeyTarget('db.main'),
  field: 'UserName',
);
print(TomSecretReference.format(built)); // [env:prod]db.main#UserName
```

A target is a key (`db.main`, the value of an entry's `tsm.key` field), a
path (`store/group/.../title`) or a uuid reference (`store/~<32 hex>`). A
malformed reference throws `TomSecretsClientException` of kind `malformed`
whose `reason` names the broken rule (`empty`, `too_long`, `bad_key`,
`bad_store`, `bad_uuid`, `bad_escape`, `reserved_character`, ...).

### Waiting and progress

```dart
final value = await client.get(
  'db.main',
  timeout: const Duration(minutes: 2),
  onProgress: (p) => print(
    'waiting for ${p.pending.name}'
    '${p.approvalCode == null ? '' : ' - approval code ${p.approvalCode}'}',
  ),
  waitOnRateLimit: true,
);
value.dispose();
```

`pending` is `unlock` (the service is locked and an admin was told) or
`approval` (the request went to approval). On a host with no approver
connected the notice carries a one-time approval code: show it so the user
can approve on a trusted device. `timeout` is sent as `timeoutMs` and capped
by the service.

### Files

```dart
final file = await client.getFile('certs/Signing#key.p12');
print('${file.name}: ${file.size} bytes');
file.dispose();
```

`getFile` fails as `unsupported` when the service does not offer the
features `binary` and `getFile`.

### Errors

Every failure is a `TomSecretsClientException` with a `kind`, a `message`
for people and `details` (`reason`, `candidates`, `retryAfterMs`, ...).

| Kind | Meaning |
| --- | --- |
| `notRunning` | No service: no socket or port file, an unreadable port file, a refused or dropped connection |
| `locked` | The service is locked and no unlock came in time, or `wait` was false |
| `denied` | The client may not have this |
| `notFound` | No candidate, or the winning entry lacks the field |
| `ambiguous` | Several candidates rank equal (`details['candidates']`) |
| `needsUnlock` | The store could not be reopened since its key changed |
| `unavailable` | The store could not be fetched and has no offline copy |
| `malformed` | A reference, binding or request cannot be read (`reason`) |
| `timeout` | An approval was not answered in time |
| `rateLimited` | The identity is held back (`details['retryAfterMs']`) |
| `unsupported` | An unknown request or protocol, or a missing feature |
| `internal` | A failure of the service, a service that broke the protocol, or an unknown kind |
| `offline`, `tokenExpired` | Admin only: a fetch failed for a network reason, or GitHub refused the token |

`denied`, `ambiguous` and `notFound` are never retried; `rateLimited` is
waited out only with `waitOnRateLimit: true`. The library logs nothing: no
value, token or payload, and an exception never carries one.

### The admin library

```dart
import 'package:tom_secrets_client/admin.dart';
```

#### Starting the service

```dart
final result = await tomSecretsStartService(
  executable: '/opt/tsm/bin/tom_secrets_service',
  bootstrap: tomSecretsBootstrapPath(),
);
switch (result) {
  case TomSecretsStarted(:final adminKey):
    print('started; keep the ${adminKey.length}-byte admin key');
  case TomSecretsAlreadyStarted():
    print('already running: connect with the kept key, or claim');
  case TomSecretsStartFailed(:final code, :final message):
    print('failed ($code): $message');
}
```

The starter generates a fresh 32-byte admin key, starts the service detached
and hands it one JSON line on its standard input (`TomSecretsHandover`: the
key, the bootstrap file, the starter's PID). The key never touches a file.

#### The admin client

```dart
final runtime = TomSecretsRuntime.current();
final admin = await TomSecretsAdminClient.connect(runtime, adminKey);
await admin.unlock('demo-master-password');
final status = await admin.request('status');
print(status['locked']);
await admin.request('subscribe');
admin.events.listen((event) => print(event['op']));
```

`connect` runs the mutual challenge: both sides prove they hold the admin
key without sending it, and the service's proof is checked before anything
secret is sent (a wrong one throws `TomSecretsAdminException` of kind
`service_impostor`). `claim` takes the service over with the master password
when no admin key is held and answers the connection with a new admin key;
the service cannot prove itself there, so the caller warns the user first.
Failures are `TomSecretsAdminException` with the protocol's error kind, or
`closed` / `not_running`.

#### The runtime directory

`TomSecretsRuntime.current()` names the runtime directory as the client
finds it. `prepare()` creates it for the user alone (mode 0700; on Windows
only the user and SYSTEM) and `check()` refuses one that is not;
`acquire()` / `release()` hold the single-instance lock `service.lock`;
`writeInfo` / `readInfo` handle `service.json`, whose `start` names the
service start.

#### Keeping the admin key

```dart
final keyring = TomSecretsAdminKeyring(
  read: keychain.read,
  write: keychain.write,
  delete: keychain.delete,
);
await keyring.keep(serviceStart, adminKey);
await keyring.pruneOthers(serviceStart); // keys of services that are gone
```

The keyring wraps the OS keychain's own operations. Keys are kept under
`tsm.admin.<start>` in the keychain service `tom-secrets-manager`, with the
index of their starts under `tsm.admin.index`, because a keychain cannot be
listed. Whoever stops the service calls `forget(start)`.

#### The data directory

`tomSecretsDataDirectory()` is where the product keeps its data for one OS
user (see [Configuration](#configuration)); `tomSecretsBootstrapPath()` is
`bootstrap.yaml` in it.

#### The distribution layout

The manager app's distribution carries `tsm` and the service in a `tsm/bin`
folder:

| Platform | App executable | Tools |
| --- | --- | --- |
| macOS | `Tom Secrets Manager.app/Contents/MacOS/tom_secrets_app` | `Tom Secrets Manager.app/Contents/Resources/tsm/bin/` |
| Windows | `<folder>\tom_secrets_app.exe` | `<folder>\tsm\bin\` |
| Linux | `<folder>/tom_secrets_app` | `<folder>/tsm/bin/` |

`tomSecretsServiceCandidates` lists where the app looks for the service
(beside itself, then the tools folder); `tomSecretsDistributionApp` names
the app a service of the distribution admits as an admin.

#### The pairing mode

`tsm pair` sets a headless machine up by pairing without linking the core
itself: it starts the service executable attached and talks to it in JSON
lines.

```dart
final pairing = await TomSecretsServicePairing.start(
  executable: '/opt/tsm/bin/tom_secrets_service',
  handover: TomSecretsPairingHandover(
    dataDirectory: tomSecretsDataDirectory(),
    address: '10.0.0.5',
    port: 47100,
    code: '123-456',
    device: 'build-server',
  ),
);
try {
  final report = await pairing.received();
  print('${report.giver} gave ${report.vaults.length} vault(s)');
  final bootstrap = await pairing.setUp('demo-master-password');
  print('set up: $bootstrap');
} on TomSecretsPairingModeException catch (e) {
  print('${e.code}: ${e.message}');
} finally {
  await pairing.close();
}
```

`received()` answers what the other machine gave (vaults, the shared
configuration, the repositories it gave a token for; never a key or a
token). `setUp` sends the master password; after the code
`wrong_password` another may be sent, three in all. Then the caller starts
the service as usual and unlocks it.

## Configuration

| Variable | Used for |
| --- | --- |
| `TSM_RUNTIME_DIR` | The runtime directory, overriding the OS default (containers, tests); may be relative to stay under the Unix socket path limit |
| `XDG_RUNTIME_DIR` | Linux: the runtime directory is `$XDG_RUNTIME_DIR/tsm/` when it is an absolute path, else `/tmp/tsm-<uid>/` |
| `TMPDIR` | macOS: the runtime directory is `$TMPDIR/tsm/` when it is an absolute path, else `/tmp/tsm-<uid>/` |
| `LOCALAPPDATA`, `USERPROFILE` | Windows: the runtime directory is `%LOCALAPPDATA%\TomSecretsManager\run\` (`client.port`, `client.token`, `admin.port`) |
| `TSM_DATA_DIR` | The data directory, overriding the OS default |
| `HOME`, `XDG_DATA_HOME` | The default data directory: `~/Library/Application Support/TomSecretsManager` on macOS, `$XDG_DATA_HOME/tom-secrets-manager` or `~/.local/share/tom-secrets-manager` on Linux; `%LOCALAPPDATA%\TomSecretsManager` on Windows |

`TomSecretsClient`, `TomSecretsRuntime.current`, `tomSecretsDataDirectory`
and `tomSecretsBootstrapPath` take `environment` and `operatingSystem`
arguments, so a caller or a test can name them instead of the process's.
On Windows the client token is re-read at every connect, because it changes
with every service start.

## Limits

| Limit | Value |
| --- | --- |
| Request frame payload | 64 KiB (`tomSecretsMaxRequestPayload`); a larger request is refused locally as `malformed` |
| Answer frame payload | 1 MiB (`tomSecretsMaxAnswerPayload`); a larger one closes the connection unread |
| Reference length | 1024 bytes of UTF-8 (`tomSecretsMaxReferenceBytes`) |
| References per `getMany` | 1 to 256 (`tomSecretsMaxGetMany`) |
| Connect and `welcome` | 10 seconds by default (`connectTimeout`) |
| Unix socket path | About 100 bytes, set by the OS |
| Admin authentication delay | 0, then 1 s, 2 s, 4 s, ... up to 60 s after failed attempts (`tomSecretsAuthDelay`) |

## Architecture

```text
 program
    |
    v
 TomSecretsClient --- discoverTomSecrets ---> runtime directory
    |                                          (client.sock | client.port
    |  frames (TomSecretsFrameReader,           + client.token)
    |  tomSecretsJsonFrame)
    v
 client endpoint of the service
    |
    v
 TomSecretValue / TomSecretFile / TomSecretResult
    or TomSecretsClientException
```

The client keeps one connection with its open requests by id, so calls may
overlap and answers may come out of order. References are parsed and
checked by `TomSecretReference` before anything is sent.

| Type | Responsibility |
| --- | --- |
| `TomSecretsClient` | The connection to the client endpoint; `get`, `getMany`, `getFile` |
| `TomSecretsWelcome` | What the service said in `welcome`: protocol, version, features, host, platform |
| `TomSecretReference` | Parsing and formatting the reference grammar |
| `TomSecretTarget` | What a reference names: `TomSecretKeyTarget`, `TomSecretPathTarget`, `TomSecretUuidTarget` |
| `TomSecretValue` | A secret with its entry, bindings, version, expiry and client token; masked and disposable |
| `TomSecretFile` | An attachment or typed key as bytes |
| `TomSecretRequest` / `TomSecretResult` | One reference of a `getMany` and its value or error |
| `TomSecretsProgress` | A progress notice: why a request waits, with the approval code |
| `TomSecretsClientException` | Every failure, with its `TomSecretsErrorKind` |
| `TomSecretsLocation` | Where the service is: `TomSecretsEndpoints` or `TomSecretsNoRuntimeDirectory` |
| `TomSecretsFrameReader` | Splits a byte stream into frames, checking limits and types |
| `TomSecretsAdminClient` | The authenticated admin connection, its requests and events |
| `TomSecretsRuntime` | The runtime directory: its check, lock, `service.json` and endpoint files |
| `TomSecretsHandover` | The admin-key handover line read by a starting service |
| `TomSecretsStartResult` | What a start found: started, already running, or failed |
| `TomSecretsServicePairing` | The conversation with the service in its pairing mode |
| `TomSecretsAdminKeyring` | The admin keys in the OS keychain and the index of their starts |

## Ecosystem

```text
   your program        tsm (command line)        manager app
        |               |            |                |
        | client        | client     | admin.dart     | admin.dart
        v               v            v                v
   +-------------------------------------------------------+
   |               tom_secrets_client (Dart)                |
   +-------------------------------------------------------+
        |  client endpoint            |  admin endpoint
        v                             v
   +-------------------------------------------------------+
   |   tom_secrets_service  (on tom_secrets_core, KDBX)     |
   +-------------------------------------------------------+
        ^
        |  the same protocol
   @al-the-bear/tom-secrets-client (TypeScript / JavaScript)
```

Every client is written from the protocol document and imports no core
code; the conformance suite runs each of them against the same fake
service.

## Further documentation

| Document | What is there |
| --- | --- |
| [API summary index](doc/api/api_summary_index.md) | Every public type, function and constant of both libraries |
| [Protocol document](../../../protocol/protocol.md) | Framing, finding the service, the reference grammar, every client and admin message, the error kinds |
| [Conformance suite](../../../conformance/README.md) | The fake service and the shared cases every client library passes |
| [`tsm`](../tsm/README.md) | The command line built on this library |
| [TypeScript client](../../typescript/README.md) | The same client for Node.js |
| [`tom_secrets_service`](https://pub.dev/packages/tom_secrets_service) | The secrets service this library talks to |
| [`tom_secrets_core`](https://pub.dev/packages/tom_secrets_core) | The core the service is built on |
| [CHANGELOG](CHANGELOG.md) | What each release added |

## Status

Version 0.2.3, speaking protocol version 1. The suite runs from the package
folder with `testkit :test` (or `dart test`) and needs no running service:
the client tests talk to a scripted fake service over a Unix socket, or a
localhost port with a client token as on Windows; the vector tests check the
library against every vector of the protocol document a client computes
(references, discovery, port files, frames) and read them from the
repository's `protocol/vectors/`, so they run inside a checkout of the
repository; further tests cover the admin keyring, the distribution layout
and the pairing mode. A test keeps the version sent in `hello` equal to the
pubspec's. The repository's conformance suite runs this library through the
shared cases as well.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
