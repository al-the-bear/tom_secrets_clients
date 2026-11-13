# Conformance suite

Every client library of the Tom Secrets Manager runs the same case tables
against the same fake service. The fake service proves that a library keeps
to the protocol document (`../protocol/protocol.md`); the integration suite
against the real service (with `tom_secrets_service`) proves the service
does. A library is released only when its runner passes every table.

```text
conformance/
  fake_service/          the fake service (Dart): speaks the client endpoint from a script
  cases/*.json           the case tables; references.json is generated from the vectors
  runners/<lang>/        one thin runner per language, with its runner.json
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
```

It needs Dart (the fake service is Dart), Python 3.9+ with `jsonschema` and
`referencing`, and each runner's toolchain. A runner whose toolchain is
missing is reported **NOT MEASURED**, never passed; `--strict` (and the CI's
`:conformance` stage, `app_secrets_manager/tom_secrets_build`) makes that a
failure. Scratch goes to `conformance/ztmp/` (the compiled fake service and
runners in `ztmp/bin/`, one runtime directory per case in `ztmp/rt/`).

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
matches anything and `"$absent"` requires the member to be missing. So a
`hello` pattern names `client.name` (every runner uses
`conformance-runner`) and leaves `version` and `language` to the library.

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
  the browser host and the helpers, no library call); every action is used.
- **Parity** (`parity_gate.sh`): an expected value changed, then the value the
  fake service sends changed: every runner must go red both times.
- **Schemas**: every frame the fake service records is validated against
  `../protocol/schema/`.
- **References**: `cases/references.json` is what `gen` writes from
  `../protocol/vectors/references.json`.

## Adding a runner

`runners/<lang>/runner.json`:

```json
{
  "language": "<lang>",
  "toolchain": ["<cmd>", "--version"],
  "build": [["<cmd>", "..."]],
  "run": ["<cmd>", "..."],
  "actions": ["connect", "get", "getMany", "parse", "format", "concurrent", "sequence"]
}
```

Commands run in `conformance/`; `{exe}` becomes `.exe` on Windows. A case
whose action the library does not offer (`getFile` before phase B) is
reported as not offered, apart from passes and failures.
