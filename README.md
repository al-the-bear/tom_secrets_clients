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
| [`protocol/`](protocol/protocol.md) | A | the protocol document: framing, finding the service, the reference grammar, every client and admin message, the error kinds, versioning; a JSON Schema per message, the test vectors and the tools that write and check them |
| the conformance suite | A | the harness and its fake service (Dart) |
| `tom_secrets_client` | A | the Dart client: frames, messages, the reference grammar |
| `tsm` | A | the command line (`get`, `run`, the admin commands), on `tom_build_base` |
| the TypeScript client | A | the npm package |
| the other seven libraries | B | C, C++, Go, Java, JavaScript, Python, Rust |

The protocol document exists (its second part, the signed objects and the
approval link, is still to come); the other packages are created by the
quest's todos of their phase.

## Checking the protocol

```text
python3 protocol/tool/check_protocol.py
```

checks that the document, the schemas and the vectors agree (Python 3.9 or
later with `jsonschema`).

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
