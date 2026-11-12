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
| the protocol document | A | framing, messages, the reference grammar and the test vectors |
| the conformance suite | A | the harness and its fake service (Dart) |
| `tom_secrets_client` | A | the Dart client: frames, messages, the reference grammar |
| `tsm` | A | the command line (`get`, `run`, the admin commands), on `tom_build_base` |
| the TypeScript client | A | the npm package |
| the other seven libraries | B | C, C++, Go, Java, JavaScript, Python, Rust |

They are created by the quest's todos of their phase; until then the
repository holds only its frame.

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
