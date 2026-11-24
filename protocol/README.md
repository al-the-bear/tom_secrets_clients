# Tom Secrets Manager protocol

> Part of the **Tom Secrets Manager** by al-the-bear.
> © 2026 Peter Nicolai Alexis Kyaw — BSD-3-Clause, see [LICENSE](../LICENSE).

The protocol between the Tom Secrets Manager's secrets service and the
programs that talk to it: the document that defines it, a JSON Schema per
message, test vectors, and the tools that write and check them.

## The protocol document

[`protocol.md`](protocol.md) is the authority. It specifies:

- the endpoints and how a client finds the service (the runtime directory
  per operating system, the socket and port files);
- the framing: length-prefixed JSON frames, their limits, invalid frames,
  request ids;
- the reference grammar (`[env:prod]db.main`): parts, escaping, the canonical
  form, the reasons a reference is malformed, dimensions in a request;
- every message of the client endpoint (`hello`, `get`, `getMany`,
  `progress`, …) and of the admin endpoint (the challenge, `claim`, the
  requests, the editing path, the events);
- approvals and grants: the measured identity, the approval flow, client
  tokens, approval codes;
- versioning and extension, the error kinds, the rate limits;
- the signed objects (grants, revocations, approval records, key-change
  statements), the approval code and its token, the approval link with its
  hybrid handshake, and pairing.

Parts marked **[B]** or **[C]** belong to a later phase: their wire format is
fixed already, and a phase-A implementation does not send them and refuses
them as the document's section 8 says. Where the schemas or the vectors
disagree with the document, the document wins.

## Contents

| Path | What it holds |
| --- | --- |
| [`protocol.md`](protocol.md) | the protocol document |
| [`schema/`](schema/) | one JSON Schema (draft 2020-12) per message, `<op>.json`, and `common.json` with the shared definitions; each schema's `x-tsm` names its endpoint, direction and phase |
| [`vectors/`](vectors/) | the test vectors: `frames.json`, `references.json`, `hmac.json`, `discovery.json`, `signatures.json`, `approval_codes.json`, `link_handshake.json`, `bundles.json` |
| [`tool/tsm_protocol.py`](tool/tsm_protocol.py) | the reference implementation of the computable parts: the reference grammar, framing, the admin challenge's MAC, discovery, and the signed bytes, key ids, approval codes and tokens (standard library only) |
| [`tool/gen_schemas.py`](tool/gen_schemas.py) | writes `schema/` |
| [`tool/gen_vectors.py`](tool/gen_vectors.py) | writes `frames.json`, `references.json`, `hmac.json`, `discovery.json` and `approval_codes.json` |
| [`tool/check_protocol.py`](tool/check_protocol.py) | checks that the document, the schemas and the vectors agree |
| [`tool/vectors_dart/`](tool/vectors_dart/) | writes `signatures.json`, `link_handshake.json` and `bundles.json` (the OS unlock's key bundle) (Ed25519, ML-DSA-65, X25519, ML-KEM-768 on `tom_pqc`) and tests both roles of the approval link against them |
| [`tool/vectors_go/`](tool/vectors_go/) | recomputes the signatures, approval codes, tokens and the link handshake with Go's standard library, independently of the Dart and Python tools |

Every value in the vectors is demo data under demo keys derived from labels;
no real secret is in them.

## Checking and regenerating

Run from the repository root, by hand. Checking needs Python 3.9 or later
with `jsonschema` and `referencing`; the Go cross-check needs Go 1.27 or
later.

```sh
python3 protocol/tool/check_protocol.py
(cd protocol/tool/vectors_dart && testkit :test)
(cd protocol/tool/vectors_go && go run .)
```

`check_protocol.py` exits 0 when every schema is a valid draft 2020-12
schema, the document names every message, error kind and malformed reason,
every frame of `frames.json` decodes to its JSON and validates against its
schema (and every message schema has a frame), the computed vectors are what
the reference implementation computes now, and every message of the
approval link's handshake vectors is valid and allowed on the link from its
side.

After changing the document, regenerate in this order (the Dart tool first:
`frames.json` carries its signed grant), then check:

```sh
python3 protocol/tool/gen_schemas.py
(cd protocol/tool/vectors_dart && dart run bin/gen_vectors.dart)
python3 protocol/tool/gen_vectors.py
python3 protocol/tool/check_protocol.py
```

`dart run bin/gen_vectors.dart --check` compares `signatures.json`,
`link_handshake.json` and `bundles.json` with a fresh generation instead of
writing them.

## Implementing a client

A client library is written from the document alone; it imports no code of
the service or the core.

1. Read sections 1 to 5 (endpoints, framing, finding the service, references,
   the client endpoint), 8 (versioning) and 10 (error kinds). A client that
   only reads secrets needs nothing else.
2. Validate what the library sends and receives against [`schema/`](schema/).
   Each schema's `$id` is its published URL under
   `https://raw.githubusercontent.com/al-the-bear/tom_secrets_clients/main/protocol/schema/`,
   so a validator resolves the `$ref`s into `common.json` from there.
3. Test the library's framing, reference parsing and formatting, and
   discovery against `frames.json`, `references.json` and `discovery.json`.
4. Add a runner to the [conformance suite](../conformance/README.md): it runs
   the same case tables against a fake service for every library, and a
   library is released only when its runner passes every table.

An admin client (an app or a command line that starts and unlocks the
service) also implements section 6 and is checked against `hmac.json`; a
device that approves for another implements section 9 and is checked against
`signatures.json`, `approval_codes.json` and `link_handshake.json`.

## Licence

BSD-3-Clause, see the repository's [LICENSE](../LICENSE).
