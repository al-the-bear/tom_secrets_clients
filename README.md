# Tom Secrets Manager — clients

The client side of the Tom Secrets Manager: the protocol document a process
uses to ask the secrets service for a secret, the conformance suite with its
fake service, and the client libraries — Dart, TypeScript and JavaScript (one npm package), and
from phase B C, C++, Go, Java, Python and Rust — plus the command line `tsm`.
Nothing here reaches KDBX: the clients are written from the protocol document
and import no core code.

GitHub: `al-the-bear/tom_secrets_clients`. The product's other two
repositories are `al-the-bear/tom_secrets_manager` (the core and the secrets
service) and `al-the-bear/tom_app_secrets_manager` (the apps, the manual CI
and the release build, with the install and first-run guide in its README).
On pub.dev: `tom_secrets_client` (the Dart client) and `tom_secrets_tsm`
(`tsm`); on npm: `@al-the-bear/tom-secrets-client`.

## Contents

| Package | Phase | What it holds |
| --- | --- | --- |
| [`protocol/`](protocol/protocol.md) | A | the protocol document: framing, finding the service, the reference grammar, every client and admin message, the error kinds, versioning, the signed objects, the approval code and the approval link with its hybrid handshake; a JSON Schema per message, the test vectors and the tools that write and check them (Python, Dart on `tom_pqc`, and a Go cross-check) |
| [`conformance/`](conformance/README.md) | A | the suite every client runs: the fake service (Dart), the case tables, a runner per language (Dart, TypeScript and JavaScript now), the driver with its coverage and parity gates |
| [`clients/dart/tom_secrets_client`](clients/dart/tom_secrets_client/README.md) | A | the Dart client: finding the service, frames, `get`, `getMany`, `getFile` (B), waiting for an unlock or an approval, the reference grammar; and its admin library (`admin.dart`): the admin client, the runtime directory, starting the service, the data directory, the keychain names |
| [`clients/dart/tsm`](clients/dart/tsm/README.md) | A | `tsm`, the command line (`get`, `run`, `ref`, and the admin commands), on `tom_build_base`; its integration suite runs the real service |
| [`clients/typescript`](clients/typescript/README.md) | A | `@al-the-bear/tom-secrets-client`, the TypeScript and JavaScript client for Node.js (one npm package, CommonJS with type declarations): finding the service, frames, `get`, `getMany`, waiting for an unlock or an approval, the reference grammar |
| the other six libraries | B | C, C++, Go, Java, Python, Rust |

The protocol document, the Dart client, `tsm`, the TypeScript client and the
conformance suite exist; the other packages follow in their phase.

## Checking the protocol

```text
python3 protocol/tool/check_protocol.py
(cd protocol/tool/vectors_dart && testkit :test)
(cd protocol/tool/vectors_go && go run .)
conformance/tool/run_all.sh
```

check that the document, the schemas and the vectors agree (Python 3.9 or
later with `jsonschema`), that the signatures and the approval link verify
and run both ways in Dart, and that Go's standard library computes the same
signatures, codes, tokens and handshake (Go 1.27 or later); and that every
client library passes the conformance suite (`conformance/README.md`).
Section 12 of the protocol document lists how the vectors are regenerated.

## Licence and boundaries

Every package here is BSD-3 (`LICENSE`). No package depends on
`tom_secrets_core` or anything that reaches KDBX, and no dependency closure may
hold a GPL-licensed package; the licence-boundary check of
`tom_secrets_build` (repository `tom_app_secrets_manager`) holds that, for the
npm package from its `package-lock.json`. `tsm`'s
tests take the service and the core as dev dependencies, which are not
linked.

## Design

The protocol document (`protocol/protocol.md`) is the published contract
between the service and its clients. The other design decisions the code
and documents cite (`DP-`, `BP-`, `TD-` and `IDEA-` ids, the `part-…`
sections) are recorded in the product's design document, which is not
published with the source.
