# Tom Secrets Manager clients — development guidelines

Guidelines for the packages in `tom_ai/secrets_clients` (the protocol
document, the conformance suite, the client libraries and `tsm`).

## Boundaries

- No package here depends on `tom_secrets_core`, `tom_kdbx_store` or anything
  else that reaches KDBX; the clients and the fake service are written from
  the protocol document.
- Every client library passes the conformance suite against the fake service.
- The published packages (`tom_secrets_client`, `tsm`, the TypeScript client)
  name no private repository as their `repository:`.

## Rules for every package

- **BSD-3.** Every package carries the BSD-3 licence and copyright notice of
  the repository's `LICENSE`; no package's dependency closure may hold a
  GPL-licensed or other copyleft package.
- **Quality per change:** `dart analyze` clean (no Problems pane issue), tests
  run with `testkit` from the package root, and the manual CI
  `app_secrets_manager/tom_secrets_build/ci.sh :all`, which covers this
  repository too.
- **CLI tools** are built on `tom_build_base`.
- **Locks:** a library keeps its `pubspec.lock` ignored; an application
  package (a tracked `bin/*.dart`, or a Flutter app) tracks it with an
  anchored `!/pubspec.lock` in its own `.gitignore` (`/tom_app_locks`).
- **No CI on GitHub.** Actions is switched off for this repository; builds,
  tests and checks are started by a person from the clone.
- **Real secrets never enter the repository or a test.** Tests and corpora use
  demo data under demo keys.
- **New packages** are registered in the workspace's
  `_copilot_guidelines/projects_and_repos.md` and listed in this repository's
  README.

The workspace-wide guidelines in the container's `_copilot_guidelines/` apply
as well. The design is the idea document
`_ai/quests/tom_core/ideas/tom_secrets_manager/tom_secrets_manager.md`.

## Documents

| Document | Purpose |
| -------- | ------- |
| [index.md](index.md) | This index: the repository's rules and its guideline documents |
