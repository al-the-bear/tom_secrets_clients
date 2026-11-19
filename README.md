# Tom Secrets Manager — clients

The protocol, the conformance suite, the client libraries and the command line
`tsm` of the Tom Secrets Manager.

> Part of the **Tom Secrets Manager** by al-the-bear.
> © 2026 Peter Nicolai Alexis Kyaw — BSD-3-Clause, see [LICENSE](LICENSE).

This document is the map of the repository `tom_secrets_clients`; each part
has its own README. A program reads its secrets from the secrets service that
runs for its user on the same machine; the client libraries find the service,
speak its protocol and parse and format secret references. Nothing here
reaches KDBX: the clients are written from the protocol document and import
no code of the service or the core.

**New here?** To read a secret from a shell or a script, start with
[`tsm`](clients/dart/tsm/README.md); from a Dart program, with
[`tom_secrets_client`](clients/dart/tom_secrets_client/README.md); from
Node.js, with [`@al-the-bear/tom-secrets-client`](clients/typescript/README.md);
from Python, with [`tom-secrets-client`](clients/python/README.md); from Go,
with the [Go client](clients/go/README.md); from Rust, with the
[`tom-secrets-client` crate](clients/rust/README.md); from Java, with
[`net.kyaw.tom:tom-secrets-client`](clients/java/README.md).
To write a client in another language, start with the
[protocol](protocol/README.md).

## What you can do with it

- Read a secret by its reference (`[env:prod]db.main`) from a program, and
  wait while the service is locked or an approver decides.
- Run a command with secrets in its environment (`tsm run`).
- Start, unlock, pair and administer the service from the command line, on a
  desktop or a headless machine.
- Implement a client in a new language against a fixed protocol, schemas,
  test vectors and a shared conformance suite.

## The product's repositories

| Repository | What it holds |
| --- | --- |
| [`al-the-bear/tom_secrets_manager`](https://github.com/al-the-bear/tom_secrets_manager) | the core library and the secrets service |
| `al-the-bear/tom_secrets_clients` (this one) | the protocol, the conformance suite, the client libraries and `tsm` |
| [`al-the-bear/tom_app_secrets_manager`](https://github.com/al-the-bear/tom_app_secrets_manager) | the desktop and mobile apps, the build, the install and first-run guide |

## Protocol and conformance

| Part | What it is |
| --- | --- |
| [`protocol/`](protocol/README.md) | the [protocol document](protocol/protocol.md) — framing, finding the service, the reference grammar, every client and admin message, the error kinds, versioning, the signed objects, the approval code and the approval link with its hybrid handshake — with a JSON Schema per message, the test vectors and the tools that write and check them (Python, Dart on `tom_pqc`, and a Go cross-check) |
| [`conformance/`](conformance/README.md) | the suite every client library runs: the fake service (Dart), the case tables, a runner per language, the driver with its coverage and parity gates |

## Client libraries and tools

| Package | What it is | Published | Binary |
| --- | --- | --- | --- |
| [`tom_secrets_client`](clients/dart/tom_secrets_client/README.md) | the Dart client: finding the service, frames, `get`, `getMany`, `getFile` (for a service that offers it), waiting for an unlock or an approval, the reference grammar; and its admin library (`admin.dart`): the admin client, the runtime and data directories, starting the service, the keychain names | pub.dev | — |
| [`tsm`](clients/dart/tsm/README.md) | the command line: `get`, `run`, `ref`, and the admin commands (`pair`, `start`, `unlock`, `status`, `approve`, `grants`, `audit`, …); its integration suite runs the real service | pub.dev, as `tom_secrets_tsm` | `tsm` |
| [`@al-the-bear/tom-secrets-client`](clients/typescript/README.md) | the TypeScript and JavaScript client for Node.js (one npm package, CommonJS with type declarations): finding the service, frames, `get`, `getMany`, waiting for an unlock or an approval, the reference grammar | npm | — |
| [`tom-secrets-client`](clients/python/README.md) (Python) | the Python client (import name `tsm`, standard library only): finding the service, frames, `get`, `getMany`, `getFile`, waiting for an unlock or an approval, the reference grammar; a blocking, thread-safe `tsm.Client` and `tsm.aio.Client` for asyncio | PyPI | — |
| [Go client](clients/go/README.md) (`clients/go`, package `tsm`) | the Go client (standard library only): finding the service, frames, `Get`, `GetMany`, `GetFile`, waiting for an unlock or an approval, the reference grammar; a `Client` safe for concurrent use, every call with a `context.Context`, `*tsm.Error` with `Kind` for `errors.As` | Go module path | — |
| [`tom-secrets-client`](clients/rust/README.md) (Rust crate) | the Rust client (no dependency without the `tokio` feature): finding the service, frames, `get`, `get_many`, `get_file`, waiting for an unlock or an approval, the reference grammar; a blocking `Client` that is `Send` and `Sync`, an async client with the feature `tokio`, `Error` with one variant per kind | crates.io | — |
| [`net.kyaw.tom:tom-secrets-client`](clients/java/README.md) (Java) | the Java client (Java 16+, no dependencies): finding the service, frames, `get`, `getMany`, `getFile`, waiting for an unlock or an approval, the reference grammar; a thread-safe `SecretsClient` (`AutoCloseable`), `SecretsException` with a `Kind` | Maven Central | — |

Client libraries for C and C++ are planned for a later phase. Each
will be written from the protocol document and released when its
conformance runner passes every table.

## Getting started

```sh
tsm get '[env:prod]db.main' --field UserName
tsm run --map DB_PASSWORD='[env:prod]db.main' -- ./deploy.sh
```

```dart
import 'package:tom_secrets_client/tom_secrets_client.dart';

Future<void> main() async {
  final client = await TomSecretsClient.connect();
  final value = await client.get('[env:prod]db.main', field: 'UserName');
  print(value.entry.store); // the store the entry came from
}
```

The service must be running and unlocked (`tsm start --unlock`), and the
program approved once; the first request waits for an approver.

## Checking

Run from the repository root, by hand:

```sh
python3 protocol/tool/check_protocol.py
(cd protocol/tool/vectors_dart && testkit :test)
(cd protocol/tool/vectors_go && go run .)
conformance/tool/run_all.sh
```

They check that the protocol document, the schemas and the vectors agree
(Python 3.9 or later with `jsonschema` and `referencing`); that the
signatures and the approval link verify and run both ways in Dart; that Go's
standard library computes the same signatures, codes, tokens and handshake
(Go 1.27 or later); and that every client library passes the conformance
suite. Each Dart package's own suite runs with `testkit :test` from its
folder; the TypeScript package's with `npm test`; the Python package's with
`PYTHONPATH=src python3 -m unittest discover -s tests` from its folder; the Go
module's with `go test -race ./...` and the Rust crate's with
`cargo test --all-features` from their folders; the Java client's with
`javac` and its `AllTests` (its README, Developing).

## Documentation

| Topic | Document |
| --- | --- |
| The protocol: wire format, references, approvals, the approval link | [protocol document](protocol/protocol.md) |
| Schemas, vectors and their tools; implementing a client | [protocol README](protocol/README.md) |
| The conformance suite and adding a runner | [conformance README](conformance/README.md) |
| The Dart client and its admin library | [`tom_secrets_client` README](clients/dart/tom_secrets_client/README.md) |
| The command line | [`tsm` README](clients/dart/tsm/README.md) |
| The TypeScript and JavaScript client | [TypeScript client README](clients/typescript/README.md) |
| The Python client | [Python client README](clients/python/README.md) |
| The Go client | [Go client README](clients/go/README.md) |
| The Rust client | [Rust client README](clients/rust/README.md) |
| The Java client | [Java client README](clients/java/README.md) |
| The service the clients talk to | [`tom_secrets_service` README](https://github.com/al-the-bear/tom_secrets_manager/blob/main/tom_secrets_service/README.md) |

The design decisions the code and documents cite (`DP-`, `BP-`, `TD-` and
`IDEA-` ids, the `part-…` sections) are recorded in the product's design
document, which is not published with the source; the protocol document is
the published contract.

## Repository layout

```text
tom_secrets_clients/
  protocol/
    protocol.md              the protocol document
    schema/                  one JSON Schema per message, common.json
    vectors/                 the test vectors (demo data)
    tool/                    the reference implementation, generators, checker,
                             vectors_dart/ and vectors_go/
  conformance/
    fake_service/            the fake service (Dart)
    cases/                   the case tables
    runners/                 one runner per language: dart, typescript,
                             javascript, python, go, rust, java
    tool/                    the driver, run_all.sh, parity_gate.sh
  clients/
    dart/tom_secrets_client/ the Dart client and its admin library
    dart/tsm/                the command line tsm
    typescript/              @al-the-bear/tom-secrets-client (TypeScript and JavaScript)
    python/                  tom-secrets-client (Python, import name tsm)
    go/                      the Go client (package tsm)
    rust/                    tom-secrets-client (Rust crate)
    java/                    net.kyaw.tom:tom-secrets-client (Java)
  _copilot_guidelines/       development notes for contributors
  LICENSE                    BSD-3-Clause
```

## Licence and boundaries

Every package here is BSD-3-Clause ([LICENSE](LICENSE)). No package depends
on `tom_secrets_core` or anything that reaches KDBX, and no dependency closure
holds a GPL-licensed package; the licence-boundary check of the product's
build (in `tom_app_secrets_manager`) holds that, for the npm package from its
`package-lock.json`. `tsm`'s tests take the service and the core as dev
dependencies, which are not linked into `tsm`.
