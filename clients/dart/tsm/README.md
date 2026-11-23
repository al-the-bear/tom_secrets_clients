# tom_secrets_tsm

> Part of the Tom Secrets Manager by Peter Nicolai Alexis Kyaw.

`tsm`, the Tom Secrets Manager on the command line: reads secrets from the
local secrets service (`get`, `run`) and starts, unlocks and administers it.

## Overview

The Tom Secrets Manager keeps secrets in KDBX vaults and serves them to the
programs of one machine through a local **secrets service**. A program asks
the service for a secret by a **reference** (`telegram.bot_token`,
`fleet/Db/Main#UserName`); the service resolves it, asks for an approval when
no grant answers the request, and returns the value. `tsm` is the command line
for both sides of that:

- **Reading.** `tsm get` prints one value, `tsm run` starts a command with
  secrets in its environment. Shell scripts, deployment scripts and programs
  without a client library read their secrets this way.
- **Administering.** `tsm pair` sets a new machine up, `tsm start` and
  `tsm unlock` bring the service up, `tsm status`, `tsm keys`, `tsm audit`
  show what it does, and `tsm approve` answers approvals by approval code. On
  a headless machine, without the desktop app, `tsm` is the only way in.

`tsm` never opens a vault itself and links neither the core nor the KDBX
layer: it speaks the client protocol to the service, and the admin protocol
for the administering commands. It is a native executable, because the
service identifies a client by its executable: a `tsm` run by `dart run`
shows up as the Dart VM.

## Installation

### From a release

Each release of the Tom Secrets Manager is a release of the GitHub repository
`al-the-bear/tom_binaries` (tag `tom_secrets_manager-v<version>`):

| Archive | Use | Where `tsm` is |
| --- | --- | --- |
| `tom_secrets_manager-<version>-<platform>` | a desktop: the manager app with the service and `tsm` inside it | the app's `tsm/bin` folder (on macOS `Tom Secrets Manager.app/Contents/Resources/tsm/bin`) |
| `tom_secrets_tsm-<version>-<platform>` | a server without a desktop: `tsm` and the service alone | `bin/`, beside `tom_secrets_service` |

To use `tsm` from a shell, link it onto your `PATH`, for example on macOS:

```sh
ln -s "/Applications/Tom Secrets Manager.app/Contents/Resources/tsm/bin/tsm" /usr/local/bin/tsm
```

The service takes admin commands only from the `tsm` (and the manager app) in
its own folder, or from an executable its bootstrap file names in
`admin_executables`. Use the `tsm` of the release for administering.

### From pub.dev

```sh
dart pub global activate tom_secrets_tsm
```

This `tsm` runs in the Dart VM (Dart SDK 3.10 or later). It reads secrets
(`get`, `run`, `ref`) and is approved like any other interpreted client, but
the service refuses its admin commands (`denied`, reason
`wrong_executable`).

### Building it

```sh
dart compile exe bin/tsm.dart -o build/tsm
```

The result is one file with no native library beside it: `tsm` links neither
the core nor `tom_pqc`, so it has no build hook. Place it beside the service
executable, or name it in the bootstrap's `admin_executables`.

## Quick start

On a machine that is set up (by the desktop app's First run, or by
`tsm pair`, see the [user guide](doc/tsm_user_guide.md)):

```sh
tsm start --unlock          # asks "Master password:"; prints started, unlocked
tsm get telegram.bot_token -n
tsm run --map BOT_TOKEN=telegram.bot_token -- ./bot
tsm status
```

- `tsm get` prints the value to standard output; `-n` adds a line break.
- `tsm run` fetches the reference, starts `./bot` with `BOT_TOKEN` in its
  environment and exits with the bot's exit code.
- If the request needs an approval and an approver is connected (the desktop
  app, or a trusted device over the approval link), the approver is asked.
  Otherwise `tsm` prints an approval code on standard error; see
  [Approvals](doc/tsm_user_guide.md#approvals-on-a-headless-machine).

## Commands

`tsm <command> [arguments] [options]`; `tsm --help` and
`tsm help <command>` describe each one, `tsm --version` prints the version.

### Reading

| Command | What it does |
| --- | --- |
| `get <ref> [--field F] [--dim name=value]… [--no-wait] [--timeout S] [--base64] [-n]` | Prints the value of the reference's field to standard output, as it is, without a trailing line break unless `-n` (`--newline`). A binary value is printed only with `--base64`. `--no-wait` answers at once instead of waiting for an unlock or an approval; `--timeout` waits at most that many whole seconds. |
| `run [--map VAR=ref]… [--file VAR=ref]… [--env-file FILE] [--dim name=value]… -- <command> [args…]` | Fetches every reference with one `getMany`, so one approval prompt lists them all, then starts the command with the variables added to its environment; each `--file` value is written to a temporary file whose path is the variable. |
| `ref parse <ref>` | Prints the parse result as JSON (`canonical`, `target`, `field`, `fieldGiven`, `qualifiers`). |
| `ref format (--key K \| --store S --path SEG… \| --store S --uuid HEX) [--field F] [--qualifier name:value]…` | Prints the canonical form of a reference built from its parts; `--path` is repeated per segment, `--uuid` takes the entry UUID's 32 hex digits without the `~`. |

About `run`:

- Standard input, output and error are passed through; SIGINT and SIGTERM
  are forwarded (on Windows, Ctrl-C and Ctrl-Break); `tsm` exits with the
  command's exit code.
- If any reference fails, the command is not started and `tsm` exits with the
  first failure's code. A binary value cannot be an environment variable and
  fails as `malformed`.
- An `--env-file` holds lines `VAR=<reference>`; empty lines and lines
  starting with `#` are skipped. It contains no secrets, so it may be
  committed beside a project.
- `--dim` applies to every reference of the run.
- `--file VAR=ref` fetches the value with `getFile` and writes it to a
  temporary file only the user can read (mode 600, in a directory of mode
  700; on Windows under the user's own temporary folder), named after the
  field; `VAR` holds its path. Without a `#field`, a certificate entry
  gives its private key (`private-key.pem`, or its PKCS#12 bundle), a PGP
  key entry its secret key (`private-key.asc`), any other entry its
  Password. The files are overwritten with zeros and deleted when the
  command ends, also when it fails.

### Setting up and running the service

| Command | What it does |
| --- | --- |
| `pair [<host:port>] <code> [--relay RELAY [--token-env VAR] [--relay-api URL]] [--device NAME] [--device-key MODE] [--link ADDRESS:PORT] [--service EXE]` | Sets this machine up by pairing with a machine whose Pairing screen shows the address and the code; then asks for the master password, starts the service and unlocks it. With `--relay` the pairing goes through that relay (after the address, or alone): a GitHub repository (`github:OWNER/REPO`, with this machine's own token read from the variable `--token-env` names), a relay server (`tsm:URL`, its instance token optional) or a magic-wormhole server (`wormhole:URL`, no token). |
| `start [--unlock] [--bootstrap FILE] [--service EXE] [--key-file F]` | Starts the service (prints `started`, or `already running`); with `--unlock` it unlocks it too. |
| `unlock [--key-file F]` | Unlocks with the master password; `--key-file` gives the primary vault's key file when this machine's keychain does not hold it. |
| `lock` | Locks: drops every secret from memory. |
| `stop` | Locks and stops the service, and removes its admin key from the keychain. |
| `reload` | Fetches every store now. |

- `pair` runs the service executable in its pairing mode, which receives the
  pairing; `tsm` prints what the other machine gave (the vaults, the shared
  configuration, the GitHub tokens pasted for this machine), then asks for
  the master password (three tries; one with `--password-stdin`). The address
  is always given: `tsm` does not browse the network for the pairing window.
  `--device` names this machine (default: its host name). `--device-key`
  says where the device settings container's key is kept: `auto` (the
  keychain where one is available, else the primary vault; the default),
  `keychain`, `vault` or `keyfile`. A machine that is set up already (a
  `bootstrap.yaml` in its data directory) is refused.
- `start` reads the bootstrap file `bootstrap.yaml` in the data directory
  (see [Environment variables](#environment-variables)) unless
  `--bootstrap` names another. The service executable is `--service`, else
  `TSM_SERVICE`, else `tom_secrets_service` beside `tsm`.
- The admin key the service hands over at start goes into the OS keychain
  (under `tsm.admin.<start>`, recorded in `tsm.admin.index`). Keeping or using
  a key removes those of services that are gone; `stop` removes the stopped
  service's.

### Status and audit

| Command | What it does |
| --- | --- |
| `status [--json]` | The service (locked or unlocked, lock mode, version), each store with its state, source and the age of its copy, and the keys a reminder is due for. Prints `not running` and exits 3 when no service runs. |
| `keys [--json]` | Every key with its due date; `*` marks those a reminder is due for. |
| `audit [--since T] [--until T] [--subject S] [--ref R] [--json]` | The audit log: time, outcome, references and the client. Default: the last 7 days; times in ISO 8601. |

`status` explains why a store runs on its offline copy (`GitHub not
reachable`, `token expired: enter a new one`) and flags a copy older than
7 days.

### Approvals and grants

| Command | What it does |
| --- | --- |
| `approvals [--json]` | The requests waiting on this host, with their approval codes. `tsm` cannot answer a prompt. |
| `approve <token>` | Redeems the one-time approval token (26 base32 characters) that a trusted device issued for a waiting request. Spaces and dashes are ignored, lower case is accepted. |
| `approve -` | The same, the token read from standard input. |
| `approve` | Has the service reload the primary vault and take the approval records written there for waiting codes. |
| `approve-code <code> --host H [--decision once\|always\|never] [--secret ref\|store\|all]` | On a trusted device: prints the token for an approval code shown on host `H` (defaults `once`, `ref`). |
| `grants [list] [--host H] [--json]` | The grants of the allow list. |
| `grants revoke <host> <grantId>` | Revokes a grant. |
| `allow <host> <subject> <ref\|all> [--never] [--pin P]` | Pre-approves: a grant for `<host>`; `--never` makes it a never grant, `--pin` sets its pin (`hash` or `off`). |

`approve-code` and `allow` run only on a device whose manager app has
switched command-line approvals on.

### Vault repositories

| Command | What it does |
| --- | --- |
| `compact <owner/name>` | Cuts the history of a `github:` vault repository now, keeping the repository's own retention. |

### GitHub sign-in

| Command | What it does |
| --- | --- |
| `login [--client-id ID]` | Signs this machine in with the GitHub App: prints the code to enter at github.com/login/device (on any device) and waits; the service keeps the App's tokens and renews them. `--client-id` only while the primary vault (which names the App) cannot be read yet. |
| `logout` | Signs this machine out of the GitHub App; its pasted tokens are used again. |

### ssh and git

| Command | What it does |
| --- | --- |
| `integrations [status \| install <kind> \| uninstall <kind>] [--hosts PATTERNS] [--profile NAME --ref REF] [--registry HOST]… [--every-registry] [--json]` | Shows, writes or removes the ssh block (`IdentityAgent` of the service's agent in `~/.ssh/config`, for `Host *` or the `--hosts` patterns), the git block (`credential.helper tsm` in `~/.gitconfig`, with `git-credential-tsm` beside tsm), the aws block (`credential_process = tsm aws-credentials <ref>` per `--profile` in `~/.aws/config`) and Docker's `credHelpers` per `--registry` or `credsStore` (`--every-registry`) in `~/.docker/config.json`, with `docker-credential-tsm` beside tsm; each is a marked block (for Docker the product's own keys), nothing outside it changes. `uninstall aws --profile` and `uninstall docker --registry` remove one. |
| `git-credential-tsm get\|store\|erase` | tsm under its second name, run by git: `get` answers the login of git's host (picked once in the manager app), `store` proposes a new credential to the app, `erase` is ignored; nothing is answered when nothing matches or no service runs. |
| `docker-credential-tsm get\|list\|store\|erase\|version` | tsm under its third name, run by Docker: `get` answers the login of the registry (picked once in the manager app) as `{"ServerURL","Username","Secret"}`, else Docker's "credentials not found" (exit 1); `list` names the registries of `credHelpers` with their user names, never a secret; `store` proposes a new credential; `erase` is ignored. |
| `aws-credentials <ref>` | AWS's `credential_process`: prints an API token entry's access key id (UserName), secret (Password), SessionToken and Expires as `{"Version":1,"AccessKeyId",…}`, one approval. |
| `kube-credential <ref>` | kubectl's exec plugin: prints an `ExecCredential` (the `apiVersion` kubectl names in `KUBERNETES_EXEC_INFO`) with the entry's Password as the token, or a certificate entry's certificate and key, and its Expires. |

### Global options

| Option | What it does |
| --- | --- |
| `--password-stdin` | Reads the master password from the first line of standard input instead of the terminal. For automation: the password then passes through whatever feeds standard input, so keep that as safe as the password. |
| `--help`, `-h` | The help, also per command. |
| `--version` | The version. |
| `--completion=<shell>` | Prints a shell completion script (`bash`, `zsh` or `fish`). |

Passwords are read from the terminal without echo, never from an argument.
Without a terminal, the first line of standard input is read. Between
invocations the admin key stays in the OS keychain; where no keychain answers,
each admin command asks for the master password and claims the service,
which issues a new admin key.

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

Values and listings go to standard output only. Messages, prompts and progress
go to standard error, as `tsm: <kind>: <message>` with the reason, store or
stores the service named.

## Environment variables

| Variable | Used for |
| --- | --- |
| `TSM_RUNTIME_DIR` | The runtime directory, where the service's endpoints are (containers, tests). Default: `$XDG_RUNTIME_DIR/tsm/` on Linux, `$TMPDIR/tsm/` on macOS, else `/tmp/tsm-<uid>/`; on Windows `%LOCALAPPDATA%\TomSecretsManager\run\`. |
| `TSM_DATA_DIR` | The data directory, which holds `bootstrap.yaml`. Default: `~/Library/Application Support/TomSecretsManager` on macOS, `%LOCALAPPDATA%\TomSecretsManager` on Windows, `$XDG_DATA_HOME/tom-secrets-manager` (else `~/.local/share/tom-secrets-manager`) elsewhere. |
| `TSM_SERVICE` | The service executable `start` and `pair` run, unless `--service` names one. Default: `tom_secrets_service` beside `tsm`. |

`tsm` and the service must agree on the runtime directory: set
`TSM_RUNTIME_DIR` for both or for neither.

## Limits

- **No keychain over SSH.** Where no OS keychain answers (an SSH session on
  Linux without a desktop session), the admin key cannot be kept: every admin
  command asks for the master password and claims the service anew. Use
  `--password-stdin` in automation, with the care it needs.
- **Admin commands need the native `tsm` beside the service** (or named in
  `admin_executables`). The `tsm` of `dart pub global activate` reads secrets
  only.
- **`tsm` cannot answer an approval prompt.** It redeems approval tokens
  issued by a trusted device, or approval records written to the primary
  vault.
- **`pair` needs the address.** It does not browse by mDNS, so it works
  across a VPN; the other machine's Pairing screen shows the address.
- **No GitHub token command.** A store whose token expired keeps serving its
  offline copy; the new token is entered in the manager app.
- A `run` carries at most 256 references; a reference is at most 1,024 bytes.

## Further documentation

| Document | What is there |
| --- | --- |
| [tsm user guide](doc/tsm_user_guide.md) | Task by task: pairing a headless machine, starting and unlocking, secrets in scripts, references, approvals, status, compaction, troubleshooting |
| [The protocol](../../../protocol/protocol.md) | The reference grammar (section 4), approvals and grants (section 7), the error kinds (section 10) |
| [Tom Secrets Client](../tom_secrets_client/README.md) | The Dart client library `tsm` is built on |
| [TypeScript and JavaScript client](../../typescript/README.md) | The npm package for Node.js |
| [CHANGELOG](CHANGELOG.md) | The changes per version |

The manager app's install and first-run guide is the README of the GitHub
repository `al-the-bear/tom_app_secrets_manager`.

## Developing

The command line is a `tom_build_base` tool (prefixless commands, `--` for
`run`'s command).

```sh
testkit :test                  # tsm against the service in-process
dart test --tags integration   # the integration suite
```

The integration suite builds the service binary (`dart build cli`) and starts
it through `tsm start` on demo vaults in a scratch data directory, with the
default approvals in force. It reads with `tsm` and the Dart client, waits on
a locked service, runs a real child process, stops the service and starts it
again, and sets a machine up with `tsm pair` against a pairing window on
loopback. The tests take the service and the core as dev dependencies, which
are not linked into `tsm`.

## Status

Version 0.2.2. The unit suite runs `tsm` against the service in-process; the
integration suite (tag `integration`) runs the built service binary and is
left out of the default test run.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
