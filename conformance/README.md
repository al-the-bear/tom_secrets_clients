# Conformance suite

> Part of the **Tom Secrets Manager** by al-the-bear.
> © 2026 Peter Nicolai Alexis Kyaw — BSD-3-Clause, see [LICENSE](../LICENSE).

Every client library of the Tom Secrets Manager runs the same case tables
against the same fake service. The fake service proves that a library keeps
to the [protocol document](../protocol/protocol.md): what it sends, frame by
frame, and what it makes of every answer, error and broken frame. That the
real service keeps to it is proved by `tsm`'s integration suite, which runs
the real [`tom_secrets_service`](https://github.com/al-the-bear/tom_secrets_manager/blob/main/tom_secrets_service/README.md).
A library is released only when its runner passes every table.

## What it checks

- the connection: finding the service in the runtime directory, `hello` and
  `welcome`, the Windows client token, a service that restarts or drops the
  connection;
- `get`, `getMany` and `getFile`: the frames the library sends, the values,
  `progress` while it waits for an unlock or an approval, client tokens,
  rate limits, every error kind;
- the reference grammar: parsing and formatting against the protocol's
  reference vectors;
- concurrency and sequences on one client;
- what every library must report when the service breaks the protocol.

```text
conformance/
  fake_service/          the fake service (Dart): speaks the client endpoint from a script
  cases/*.json           the case tables; references.json is generated from the vectors
  runners/<lang>/        one thin runner per language, with its runner.json:
                         dart, typescript (the npm package from TypeScript),
                         javascript (the same compiled package from plain
                         JavaScript: one package serves both languages),
                         python (tom-secrets-client, blocking client),
                         go (built inside the client's module),
                         rust (a crate with a path dependency on the client),
                         java (compiled with the client's sources)
  tool/conformance.py    the driver: run, gen, coverage, parity, all
  tool/run_all.sh        self-test, reference table, coverage gate, every runner
  tool/parity_gate.sh    breaks an expectation and an input; every runner must go red
  tool/test_conformance.py  the driver's self-test
```

## Running it

```text
conformance/tool/run_all.sh                 # every runner; --strict: missing toolchains fail
conformance/tool/run_all.sh --runner dart -v
conformance/tool/parity_gate.sh
python3 conformance/tool/conformance.py run --table get --case 'error locked becomes its kind'
python3 conformance/tool/conformance.py gen # after the protocol's references.json changed
python3 conformance/tool/conformance.py all # self-test, gen --check, coverage, run --strict
(cd conformance/fake_service && testkit :test)  # the fake service's own tests
```

Run from the repository root.

It needs Dart (the fake service is Dart), Python 3.9+ with `jsonschema` and
`referencing`, and each runner's toolchain (Node.js 18+ with npm for
`typescript` and `javascript`, whose build runs `npm ci` and the package's
build in `clients/typescript`; Python 3.9+ for `python`, which runs the
library from `clients/python/src`; Go for `go`, whose build runs `go vet`
and `go build` in `clients/go`; Rust with `cargo` for `rust`; a JDK 16+ for
`java`). A runner whose toolchain is missing is reported **NOT MEASURED**, never passed; `--strict` (and the
`:conformance` stage of the product's build in
[`tom_app_secrets_manager`](https://github.com/al-the-bear/tom_app_secrets_manager))
makes that a failure. Scratch goes to `conformance/ztmp/` (the compiled fake
service and runners in `ztmp/bin/`, one runtime directory per case in
`ztmp/rt/`).

## How a case runs

For each case the driver:

1. makes a fresh runtime directory `ztmp/rt/<n>`, relative to `conformance/`
   (a Unix socket path may not be much longer than 100 bytes), and starts the
   fake service in it with the case's `script` (unless `noService`), waiting
   for its `ready` line;
2. writes the case to the runner's standard input as one line,
   `{"case": name, "runtimeDir": "ztmp/rt/<n>", "action": {...}}`;
3. reads the runner's result line, `{"case": name, "result": {...}}`;
4. closes the fake service's standard input; it writes every frame it
   received to its record file and exits;
5. compares the result with `expect.result` (exactly, as canonical JSON), the
   recorded frames with `expect.sent`, `expect.notSent` and
   `expect.connections`, and validates every recorded frame against the
   protocol's JSON Schemas (a client message, valid by its `op`'s schema).

The driver, not the runner, starts the fake service, so a runner is only a
loop over its standard input: a few hundred lines in any language. The
runners and the fake service run with `conformance/` as the working
directory, so the runtime directory is short.

## Case tables

A table is `{"note": "...", "cases": [case...]}`. A case:

| Member | Content |
| --- | --- |
| `name` | unique in its table |
| `script` | the fake service's script (below); `{}` is a service that only welcomes |
| `noService` | `true`: no service runs (`not_running`, or a local action) |
| `platforms` | only on these (`linux`, `macos`, `windows`), e.g. the Windows token |
| `transport` | `unix` or `tcp` for the fake service; default `tcp` on Windows, else `unix` |
| `action` | what the runner does (below) |
| `expect.result` | the result line's `result`, exactly |
| `expect.sent` | the frames the client sent, in order and as many: each a pattern (below) |
| `expect.notSent` | ops the client must not have sent (a local refusal, whether or not the library connected first) |
| `expect.connections` | how many connections the fake service accepted |

A pattern matches a recorded message when each of its members matches:
objects by member, lists element by element and of equal length; `"$any"`
matches anything, `"$absent"` requires the member to be missing, and
`{"$includes": [...]}` a list holding at least those elements, in any order.
So a `hello` pattern names `client.name` (every runner uses
`conformance-runner`) and leaves `version` and `language` to the library,
and a `getFile` case asks only that `features` names `binary` and
`getFile`.

### The fake service's script

| Member | Content |
| --- | --- |
| `welcome` | members merged into the default `welcome` (`protocol` 1, `host` `conformance-host`, `platform` `linux`, no features) |
| `hello` | steps sent instead of the `welcome` (an `error`, then `close`) |
| `rules` | `{match: {op, ref?}, times?, holdUntil?, reply: [step]}`; the first rule that matches and has `times` left answers; `holdUntil: n` holds requests until `n` arrived and answers them in reverse order; an unmatched request is answered `error` `internal` (`details.code` `no_rule`) |

A step is one of: `{send: message}`, where `"$id"` becomes the request's id
and `"$ref"` its reference; `{raw: hex}`, bytes as they are; `{delayMs: n}`;
`{close: true}`, this connection; `{restart: true}`, every connection dropped,
a new socket or port and a new client token, as at a service start; `{file:
{name, contentHex, chunkSize?, sha256?}}`, a `getFile` answer (`file`, binary
chunks when both sides named `binary`, `end` with the SHA-256 of the content
unless `sha256` overrides it). On TCP the client token of start `n` is the
base64 of the 32 bytes `(31·n + 7·i) mod 256`.

### Actions

| `do` | Members | Result |
| --- | --- | --- |
| `connect` | `client?` | `{welcome: {host, platform, features (sorted)}}` |
| `get` | `ref`, `field?`, `dimensions?`, `wait?`, `timeoutMs?`, `wantClientToken?`, `waitOnRateLimit?`, `client?` | `{value: V}` or `{error: E}`, plus `progress` when any came |
| `getMany` | `refs: [{ref, field?, dimensions?}]`, `wait?`, `timeoutMs?` | `{results: [{value: V} or {error: E}]}` or `{error: E}`, plus `progress` |
| `getFile` | `ref`, `field?` | `{file: {name, size, base64}}` or `{error: E}` |
| `parse` | `ref` | `{parsed, canonical}` (the vectors' shape) or `{error: E}` |
| `format` | `parsed` | `{formatted}` |
| `concurrent` | `actions` | `{results: [...]}`, the actions started together, results in their order |
| `sequence` | `actions` (and `{do: pause, ms}`) | `{steps: [...]}` on one client |

`client` is `{clientToken?}`, the client's options. Every runner names its
client `conformance-runner`.

### Results

- **V** (a value): `encoding`; `base64` (the bytes); `text` for a `utf8`
  value; `textRefused: true` for a `base64` value whose text access the
  library refused; `entry` `{store, uuid, source, fetchedAtMs}`; `bound`;
  `version` `{modifiedMs, revision}`; `expiresMs` and `clientToken` when
  present; `masked`: the value's printable form shows `***` and not the value
  (unless the value occurs in the reference itself). Times are milliseconds
  since the epoch, so no language's date formatting matters.
- **E** (an error): `kind` (the protocol's kinds plus `not_running`) and
  `reason` when `details.reason` has one.

What every library reports, beyond what the protocol states: a service that
breaks the protocol (an answer frame over 1 MiB, an unknown frame type, a
malformed payload, an `error` without `id`, a file failing its SHA-256) is
`internal`; a reference that does not parse, two different fields, and a
request over 64 KiB are refused locally as `malformed` with the reasons
`<rule of 4.6>`, `field_twice` and `frame`; a dropped connection is
`not_running`.

## Gates

- **Coverage** (`conformance.py coverage`): every error kind (the schema's
  `errorKind` and `not_running`) is expected by some case; every message of
  the client endpoint is sent by a client or served by a script in some case,
  except `match`, `matches`, `propose` and `accepted` (phase B, asked only by
  the browser host and the helpers, which build on the Dart library; its own
  tests cover them); every action is used.
- **Parity** (`parity_gate.sh`): an expected value changed, then the value the
  fake service sends changed: every runner must go red both times.
- **Schemas**: every frame the fake service records is validated against
  `../protocol/schema/`.
- **References**: `cases/references.json` is what `gen` writes from
  `../protocol/vectors/references.json`.

## Adding a runner

A new client library joins the suite with a runner of its own:

1. Write the runner in the library's language, in `runners/<lang>/`. It reads
   one case per line on its standard input,
   `{"case": name, "runtimeDir": dir, "action": {...}}`, runs the action with
   the library against the service in `runtimeDir` (by setting
   `TSM_RUNTIME_DIR` for the library, or the library's own option), names its
   client `conformance-runner`, and writes one result line per case,
   `{"case": name, "result": {...}}`, as canonical JSON (keys sorted,
   compact). The actions and result shapes are the tables above; the runners
   of [`dart`](runners/dart/bin/runner.dart),
   [`typescript`](runners/typescript/src/runner.ts),
   [`javascript`](runners/javascript/runner.js),
   [`python`](runners/python/runner.py),
   [`go`](runners/go/main.go),
   [`rust`](runners/rust/src/main.rs) and
   [`java`](runners/java/Runner.java) are the models.
2. Describe it in `runners/<lang>/runner.json`:

   ```json
   {
     "language": "<lang>",
     "toolchain": ["<cmd>", "--version"],
     "build": [["<cmd>", "..."]],
     "run": ["<cmd>", "..."],
     "actions": ["connect", "get", "getMany", "parse", "format", "concurrent", "sequence"]
   }
   ```

   `toolchain` is the command whose failure makes the runner NOT MEASURED;
   `build` the commands that build the library and the runner; `run` the
   command that starts it; `actions` the actions the library offers. Commands
   run in `conformance/`; `{exe}` becomes `.exe` on Windows,
   `{python}` the interpreter running the driver. Build output goes
   to `ztmp/bin/`.
3. Run `conformance/tool/run_all.sh --runner <lang> -v` until every table
   passes, then `conformance/tool/parity_gate.sh --runner <lang>`, which must
   turn it red.

The driver finds every `runners/*/runner.json` by itself; nothing else is
registered. A case whose action the library does not offer (`getFile` before
phase B) is reported as not offered, apart from passes and failures.

## Licence

BSD-3-Clause, see the repository's [LICENSE](../LICENSE).
