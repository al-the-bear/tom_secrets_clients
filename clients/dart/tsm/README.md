# tsm

`tsm` is the Tom Secrets Manager on the command line. It reads secrets from
the local secrets service, and it starts, unlocks and administers the
service. On a headless machine it is the only way in. It is a native
executable: the service identifies a client by its executable, and
`dart run` would show up as the Dart VM.

## Reading

```text
tsm get <ref> [--field F] [--dim name=value]… [--no-wait] [--timeout S] [--base64] [-n]
tsm run [--map VAR=ref]… [--env-file FILE] [--dim name=value]… -- <command> [args…]
tsm ref parse <ref>
tsm ref format (--key K | --store S --path SEG… | --store S --uuid ~HEX) [--field F] [--qualifier name:value]…
```

- `get` prints the value to standard output as it is. There is no trailing
  line break unless `-n` is given. It refuses to print a binary value without
  `--base64`. While the request waits, `get` says so on standard error; on a
  host without an approver attached, that message includes the approval code.
- `run` fetches every reference with one `getMany`, so one approval prompt
  lists them all. Then it starts the command with the variables added to its
  environment:
  - it passes standard input, output and error through;
  - it forwards SIGINT and SIGTERM (on Windows, Ctrl-C and Ctrl-Break);
  - it exits with the command's exit code.

  If any reference fails, the command is not started. An `--env-file` holds
  lines `VAR=<reference>`. It contains no secrets, so it may be committed
  beside a project. `--file` (a value in a temporary file) comes in phase B.
- `ref` prints the parse result as JSON, or a reference's canonical form, for
  scripts and debugging.

## Administering

```text
tsm pair <host:port> <code> [--device NAME] [--device-key MODE] [--service EXE]
tsm start [--unlock] [--bootstrap FILE] [--service EXE] [--key-file F]
tsm unlock [--key-file F] | lock | stop | reload
tsm status [--json] | keys [--json] | approvals [--json]
tsm approve <token> | approve - | approve
tsm approve-code <code> --host H [--decision once|always|never] [--secret ref|store|all]
tsm grants [list] [--host H] [--json] | grants revoke <host> <grantId>
tsm allow <host> <subject> <ref|all> [--never] [--pin P]
tsm audit [--since T] [--until T] [--subject S] [--ref R] [--json]
tsm compact <owner/name>
```

- `pair` sets a new machine (a headless one: bigbeast, bomber) up by
  pairing with a desktop whose Pairing screen shows the address and the
  code.
  - tsm runs the service executable in its pairing mode, which receives
    the pairing; tsm links no core and no KDBX itself. It prints what the
    other machine gave (the vaults, the shared configuration, the GitHub
    tokens pasted for this machine), then asks for the master password
    (three tries; one with `--password-stdin`).
  - The service sets the machine up from what it received: the keys and
    tokens in the keychain, the device settings container with this
    machine's approval keys and the other machine recorded, and
    `bootstrap.yaml` in the data directory. Then tsm starts the service and
    unlocks it.
  - `--device` names this machine (default: its host name); `--device-key`
    says where the device settings container's key is kept (`auto`,
    `keychain`, `vault`, `keyfile`). A machine set up already (a
    `bootstrap.yaml` there) is refused.
- `start` starts the service.
  - The bootstrap file is `bootstrap.yaml` in the data directory:
    `TSM_DATA_DIR`, else `~/Library/Application Support/TomSecretsManager` on
    macOS, `%LOCALAPPDATA%\TomSecretsManager` on Windows, and
    `~/.local/share/tom-secrets-manager` elsewhere.
  - The service executable is `TSM_SERVICE`, else `tom_secrets_service` beside
    tsm.
  - The admin key the service is handed goes into the OS keychain, under
    `tsm.admin.<start>`, recorded in `tsm.admin.index`; keeping or using a
    key removes those of services that are gone, and `tsm stop` removes the
    stopped service's.
- `status` shows the service and each store with its state and source. It
  shows how old the copy is, and why a store runs on it ("GitHub not
  reachable", "token expired: enter a new one"); after 7 days the copy is
  flagged as old. It also lists the keys a reminder is due for.
- `keys` lists every key with its due date and marks with `*` those a
  reminder is due for.
- `approvals` lists the requests waiting on this host with their approval
  codes. tsm cannot answer a prompt.
- `approve <token>` redeems the one-time token (26 base32 characters) that
  the app on a trusted device issued for a waiting request. Spaces and dashes
  are ignored and lower case is accepted. `approve -` reads the token from
  standard input. `approve` without a token has the service take the approval
  records written to the primary vault.
- `allow` (a pre-approval) and `approve-code` (prints the token for a code)
  run only where the app has switched command-line approvals on.
- `compact` cuts the history of a `github:` vault repository now, keeping the
  repository's own retention.

Passwords are read from the terminal without echo, never from an argument.
`--password-stdin` reads the password from the first line of standard input
instead; it is meant for automation and carries that risk. Between
invocations the admin key stays in the OS keychain. Where no keychain answers
(an SSH session on Linux), each admin command asks for the master password
and claims the service, which issues a new key.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success (for `run`, the command's own code) |
| 2 | usage |
| 3 | `not_running` |
| 4 | `locked` |
| 5 | `denied` |
| 6 | `not_found` |
| 7 | `ambiguous` |
| 8 | `malformed` |
| 9 | `timeout` or `rate_limited` |
| 10 | `unsupported` |
| 11 | `internal`, `needs_unlock`, `unavailable`, `offline`, `token_expired` |

Values go to standard output only. Messages, prompts and progress go to
standard error.

## Installing

`tsm` runs as a native executable beside the service: the service takes admin
commands only from the `tsm` (and the manager app) in its own folder, or from
an executable its bootstrap names in `admin_executables`. The releases of
the Tom Secrets Manager (GitHub, `al-the-bear/tom_binaries`, tag
`tom_secrets_manager-v<version>`) carry `tsm` with the service: inside the
manager app (its `tsm/bin` folder) and, for a server without a desktop, as
`tom_secrets_tsm-<version>-<platform>` alone. Or build it (below).

The package is on pub.dev as `tom_secrets_tsm`.
`dart pub global activate tom_secrets_tsm` gives a `tsm` that runs in the
Dart VM: it reads secrets (`get`, `run`, `ref`), approved like any other
interpreted client, but the service refuses its admin commands.

## Building

```text
dart compile exe bin/tsm.dart -o build/tsm
```

One file, no native library beside it: tsm links neither the core nor
`tom_pqc`, so it has no build hook (the service is a `dart build cli` bundle).

The command line is a `tom_build_base` tool (`prefixlessCommands`, `--` for
`run`'s command).

## Testing

```text
testkit :test                              # tsm against the service in-process
dart test --tags integration               # the integration suite
```

The integration suite builds the service binary (`dart build cli`). It starts
the binary through `tsm start` on demo vaults in a scratch data directory,
with the default approvals in force. Then it reads with tsm and the Dart
client, waits on a locked service, runs a real child process, stops the
service and starts it again. It also sets a machine up with `tsm pair`
through the binary's pairing mode against a pairing window on loopback,
which then starts and unlocks. `tom_secrets_build :integration` runs it;
`:test` leaves it out. The tests take the service and the core as dev
dependencies, which are not linked.

## Licence

BSD-3-Clause (`LICENSE`).
