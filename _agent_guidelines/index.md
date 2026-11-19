# Tom Secrets Manager clients — development guidelines

Guidelines for the packages of this repository (the protocol
document, the conformance suite, the client libraries and `tsm`).

## Boundaries

- No package here depends on `tom_secrets_core`, `tom_kdbx_store` or anything
  else that reaches KDBX; the clients and the fake service are written from
  the protocol document.
- **The protocol document is the authority** (`protocol/protocol.md`). A
  change to a message, the grammar or a vector starts there; then
  `protocol/tool/gen_schemas.py`, `vectors_dart/bin/gen_vectors.dart` (the
  signatures and the approval link) and `gen_vectors.py` regenerate the
  schemas and vectors, in that order, and `check_protocol.py`, the
  `vectors_dart` tests and the `vectors_go` cross-check must pass (protocol.md
  section 12). The wire formats are fixed
  in phase A: a later change is a new protocol version or a feature
  (section 8), never an edit of a version-1 message.
- Every client library passes the conformance suite against the fake service
  (`conformance/tool/run_all.sh`; a new library adds `conformance/runners/<lang>/`
  with its `runner.json`, conformance/README.md), and agrees with every case of
  `protocol/vectors/`. After the protocol's `references.json` changes,
  `python3 conformance/tool/conformance.py gen` regenerates the reference table.
- The published packages (`tom_secrets_client`, `tsm`, the TypeScript client)
  name no private repository as their `repository:`.

## Rules for every package

- **BSD-3.** Every package carries the BSD-3 licence and copyright notice of
  the repository's `LICENSE`; no package's dependency closure may hold a
  GPL-licensed or other copyleft package.
- **Quality per change:** `dart analyze` clean (no Problems pane issue), tests
  run with `testkit` (or `dart test`) from the package root, and the manual
  CI `tom_secrets_build/ci.sh :all` of `tom_app_secrets_manager`, which
  covers this repository too.
- **CLI tools** are built on `tom_build_base`.
- **Locks:** a library keeps its `pubspec.lock` ignored; an application
  package (a tracked `bin/*.dart`, or a Flutter app) tracks it with an
  anchored `!/pubspec.lock` in its own `.gitignore`.
- **No CI on GitHub.** Actions is switched off for this repository; builds,
  tests and checks are started by a person from the clone.
- **Real secrets never enter the repository or a test.** Tests and corpora use
  demo data under demo keys.
- **New packages** are listed in this repository's README (and in the
  project register of the maintainers' workspace).
- **Standalone.** Nothing shipped names the maintainers' workspace: no path
  dependency into another repository, no `pubspec_overrides.yaml`, no
  workspace path in code or documents (`tom_secrets_build/ci.sh :standalone`).

The maintainers' workspace-wide guidelines apply as well. The design
document the code cites is not published with the source.

## Documents

| Document | Purpose |
| -------- | ------- |
| [index.md](index.md) | This index: the repository's rules and its guideline documents |
