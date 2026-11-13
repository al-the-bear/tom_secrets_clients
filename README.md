# Tom Secrets Manager — clients

The client side of the Tom Secrets Manager: the protocol document a process
uses to ask the secrets service for a secret, the conformance suite with its
fake service, and the client libraries — Dart, TypeScript, and from phase B C,
C++, Go, Java, JavaScript, Python and Rust — plus the command line `tsm`.
Nothing here reaches KDBX: the clients are written from the protocol document
and import no core code.

In the workspace this repository is the submodule `tom_ai/secrets_clients`
(repository id `TSMC`, GitHub `al-the-bear/tom_secrets_clients`, private).

## Contents

| Package | Phase | What it holds |
| --- | --- | --- |
| [`protocol/`](protocol/protocol.md) | A | the protocol document: framing, finding the service, the reference grammar, every client and admin message, the error kinds, versioning, the signed objects, the approval code and the approval link with its hybrid handshake; a JSON Schema per message, the test vectors and the tools that write and check them (Python, Dart on `tom_pqc`, and a Go cross-check) |
| the conformance suite | A | the harness and its fake service (Dart) |
| [`clients/dart/tom_secrets_client`](clients/dart/tom_secrets_client/README.md) | A | the Dart client: finding the service, frames, `get`, `getMany`, `getFile` (B), waiting for an unlock or an approval, the reference grammar |
| `tsm` | A | the command line (`get`, `run`, the admin commands), on `tom_build_base` |
| the TypeScript client | A | the npm package |
| the other seven libraries | B | C, C++, Go, Java, JavaScript, Python, Rust |

The protocol document and the Dart client exist; the other packages are
created by the quest's todos of their phase.

## Checking the protocol

```text
python3 protocol/tool/check_protocol.py
(cd protocol/tool/vectors_dart && testkit :test)
(cd protocol/tool/vectors_go && go run .)
```

check that the document, the schemas and the vectors agree (Python 3.9 or
later with `jsonschema`), that the signatures and the approval link verify
and run both ways in Dart, and that Go's standard library computes the same
signatures, codes, tokens and handshake (Go 1.27 or later). Section 12 of
the protocol document lists how the vectors are regenerated.

## Licence and boundaries

Every package here is BSD-3 (`LICENSE`). No package depends on
`tom_secrets_core` or anything that reaches KDBX, and no dependency closure may
hold a GPL-licensed package; the licence-boundary test that comes with
`tom_secrets_client` holds that.

## Design

The design is the idea document of the tom_core quest,
`_ai/quests/tom_core/ideas/tom_secrets_manager/tom_secrets_manager.md`
(sections `part-repositories`, `part-protocol`, `part-clients`); the work is
tracked in the `tom_secrets_manager` quest.
