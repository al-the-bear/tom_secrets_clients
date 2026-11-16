# tsm user guide

`tsm` is the Tom Secrets Manager on the command line. This guide goes through
the tasks it is used for, on a desktop and on a headless machine. The
[README](../README.md) lists every command and option in one place.

## Contents

- [Before you start](#before-you-start)
- [Setting a headless machine up by pairing](#setting-a-headless-machine-up-by-pairing)
- [Starting and unlocking the service](#starting-and-unlocking-the-service)
- [Reading secrets in scripts](#reading-secrets-in-scripts)
- [References](#references)
- [Approvals on a headless machine](#approvals-on-a-headless-machine)
- [Status and key reminders](#status-and-key-reminders)
- [Compacting a vault repository](#compacting-a-vault-repository)
- [Troubleshooting](#troubleshooting)

## Before you start

- **Which `tsm`.** Use the `tsm` that comes with the service: in a desktop
  install, the manager app's `tsm/bin` folder; on a server,
  `tom_secrets_tsm-<version>-<platform>`, where `tsm` and
  `tom_secrets_service` are side by side in `bin/`. The service accepts admin
  commands only from that `tsm`. A `tsm` from `dart pub global activate
  tom_secrets_tsm` reads secrets but cannot administer.
- **Standard output carries values only.** Everything else (prompts,
  progress, messages) goes to standard error, so `$(tsm get ...)` captures
  the value and nothing else.
- **Every failure has its own exit code**, listed under
  [Troubleshooting](#troubleshooting).

## Setting a headless machine up by pairing

A machine that has no vaults yet is set up by **pairing** with a machine that
has them, typically your desktop. The desktop gives the new machine the vaults
you choose, the shared configuration and the GitHub tokens pasted for it; the
new machine records the desktop as its approver.

1. On the desktop, open the manager app's Pairing screen. It opens a pairing
   window for at most five minutes and shows an **address** (`host:port`) and
   a one-time **code** (`<number>-<word>-<word>`).
2. On the new machine, give both to `tsm pair`:

   ```sh
   tsm pair 10.0.0.5:47900 7-guitar-orbit --device server1
   ```

3. `tsm` prints what the desktop gave:

   ```text
   paired with desktop1; it gave:
     fleet (primary)  github:example-org/fleet-vault
     the shared configuration
     a GitHub token for example-org/fleet-vault
   ```

4. It asks for the master password (`Master password:`), with three tries.
   The service then writes the setup into the data directory, and `tsm`
   starts the service and unlocks it:

   ```text
   set up (/home/ops/.local/share/tom-secrets-manager/bootstrap.yaml)
   started
   unlocked
   ```

Options:

| Option | Meaning |
| --- | --- |
| `--device NAME` | This machine's name, as the other machines and the grants know it. Default: the host name. |
| `--device-key MODE` | Where the device settings container's key is kept: `auto` (the keychain where one is available, else the primary vault; the default), `keychain`, `vault` or `keyfile` (a key file beside the container). On a server without a keychain, `auto` keeps it in the primary vault. |
| `--service EXE` | The service executable, when it is not beside `tsm` (or set `TSM_SERVICE`). |

Notes:

- The address is always typed: `tsm` does not search the network for the
  window, so pairing works over a VPN, which mDNS does not cross.
- The window takes one attempt. A wrong code closes it; open a new one on the
  desktop.
- A machine that is set up already (a `bootstrap.yaml` in its data
  directory) is refused with exit code 5.
- With `--password-stdin`, the password is read once from standard input
  and there is no second try.

## Starting and unlocking the service

```sh
tsm start            # starts the service; prints started (or already running)
tsm unlock           # asks for the master password; prints unlocked
tsm start --unlock   # both in one go
```

- `start` reads `bootstrap.yaml` from the data directory (`TSM_DATA_DIR`
  names another, `--bootstrap FILE` another file). It runs `--service EXE`,
  else `TSM_SERVICE`, else `tom_secrets_service` beside `tsm`.
- When the primary vault is protected by a key file that this machine's
  keychain does not hold, give it with `--key-file F` to `unlock` (or to
  `start --unlock`).
- `lock` drops every secret from memory; the service keeps running, and
  requests wait for the next unlock. `stop` locks and ends the service.
- `reload` fetches every store now instead of waiting for the next refresh.

**The admin key.** At start, the service hands `tsm` an admin key, which
`tsm` keeps in the OS keychain; later admin commands use it without asking.
Where no keychain answers, for example in an SSH session on Linux, every admin
command asks for the master password and claims the service, which issues a
new admin key.

**Unattended start.** A start script that cannot type the password uses
`--password-stdin`, which reads the first line of standard input:

```sh
tsm start --unlock --password-stdin < /run/credentials/tsm-master
```

The password is then exactly as safe as the file or pipe it comes from.

## Reading secrets in scripts

### One value: `tsm get`

```sh
tsm get telegram.bot_token                     # the Password field, no line break
tsm get fleet/Db/Main --field UserName -n      # another field, with a line break
tsm get '[env:prod]db.main'                    # a dimension in the reference
tsm get db.main --dim env=prod                 # the same, as an option
tsm get 'fleet/Certs/Server#attachment%3Akey.pem' --base64
```

In a shell script:

```sh
#!/bin/sh
set -e
DB_PASSWORD="$(tsm get fleet/Db/Main)"
export DB_PASSWORD
exec ./migrate
```

- `get` waits for an unlock or an approval, and says so on standard error.
  `--no-wait` answers at once instead (exit 4 when locked), `--timeout S`
  waits at most `S` seconds.
- A binary value (an attachment, a key file) is printed only with
  `--base64`; without it, `get` refuses it with exit code 2.

### Several values for a command: `tsm run`

`tsm run` fetches every reference in one request, so the approver sees one
prompt for all of them, then starts the command with the values in its
environment:

```sh
tsm run --map DB_USER=fleet/Db/Main#UserName \
        --map DB_PASSWORD=fleet/Db/Main \
        -- ./server --port 8080
```

The values exist only in the environment of `./server`; nothing is written to
disk. `tsm` passes standard input and output through, forwards Ctrl-C and
SIGTERM, and exits with the command's exit code. If any reference fails, the
command is not started.

### An environment file: `--env-file`

An env file maps variables to references. It holds no secrets, so it can be
committed beside the project:

```text
# deploy.tsm.env: variables and the references they are read from
DB_USER=fleet/Db/Main#UserName
DB_PASSWORD=fleet/Db/Main
BOT_TOKEN=[env:prod]telegram.bot_token
```

```sh
tsm run --env-file deploy.tsm.env -- ./deploy.sh
tsm run --env-file deploy.tsm.env --map EXTRA=fleet/Misc/Extra -- ./deploy.sh
```

- One `VAR=reference` per line; empty lines and lines starting with `#` are
  skipped. Variable names are letters, digits and `_`, not starting with a
  digit.
- `--map` and `--env-file` combine; `--dim name=value` applies to every
  reference.
- A binary value cannot be an environment variable: it fails as `malformed`
  (exit 8).

## References

A reference names a secret: an entry, one of its fields and, optionally,
values for dimensions. The three forms of an entry:

| Form | Example | Names |
| --- | --- | --- |
| key | `telegram.bot_token` | the entry whose `tsm.key` field is that key, in any store the service serves |
| path | `fleet/Cloud/AWS/root` | store `fleet`, group path `Cloud/AWS`, entry title `root` |
| uuid | `fleet/~0123456789abcdef0123456789abcdef` | the entry with that UUID in store `fleet`; survives renames and moves |

Around it:

- `#field` picks the field: `Title`, `UserName`, `Password`, `URL`, `Notes`,
  a custom field, `attachment%3A<name>` for an attachment, or `totp` for the
  current one-time code. Without it the field is `Password`.
- `[dimension:value,...]` in front sets dimensions for this request:
  `[env:prod]db.main`, `[env:prod,host:server1]db.main`.
- The reserved characters `/ # [ ] , : %` inside a name are written as `%`
  and two hex digits: a title `a/b` is `a%2Fb`. Quote references in the
  shell: `[` and `#` mean something to it.

`tsm ref` checks and builds references without asking the service:

```sh
tsm ref parse '[env:prod]fleet/Db/Main#UserName'   # the parts as JSON
tsm ref format --store fleet --path Db --path Main --field UserName --qualifier env:prod
# [env:prod]fleet/Db/Main#UserName
tsm ref format --store fleet --uuid 0123456789ABCDEF0123456789ABCDEF
# fleet/~0123456789abcdef0123456789abcdef
```

`ref format` prints the **canonical form**, the form grants, the audit log
and approval prompts use. The full grammar, the escaping rules and every
reason a reference is refused are in
[the protocol, section 4](../../../../protocol/protocol.md#4-references).

## Approvals on a headless machine

The first time a program reads a secret, the service asks an approver. On a
desktop that is the manager app. A headless machine paired with your desktop
asks the desktop's app over the approval link while the desktop's service is
unlocked. When no approver is connected, the request waits with an
**approval code**, ten characters such as `K7QX2MBR4D`:

```text
tsm: waiting for approval: approve code K7QX2MBR4D on a trusted device, then run `tsm approve <token>` here
```

### Answering with a token

1. See what waits, from another shell on the headless machine:

   ```sh
   tsm approvals
   # K7QX2MBR4D  fleet/Db/Main  /opt/app/bin/server
   ```

2. On a trusted device (one paired as an approver), turn the code into a
   **token**: in the manager app, or, where the app has switched command-line
   approvals on, with `tsm approve-code`:

   ```sh
   tsm approve-code K7QX2MBR4D --host server1
   # MFRGGZDFMZTWQ2LKNNWG23TPOB
   ```

   `--decision` is `once` (the default: this request only), `always` or
   `never`; `--secret` is `ref` (the default: this reference), `store` or
   `all`.

3. Type the token on the waiting machine. Spaces, dashes and lower case are
   accepted; `-` reads it from standard input:

   ```sh
   tsm approve MFRG-GZDF-MZTW-Q2LK-NNWG-23TP-OB
   echo MFRGGZDFMZTWQ2LKNNWG23TPOB | tsm approve -
   ```

The token is single-use and expires with its code. The waiting `get` or
`run` then goes on.

### Answering through the vault

Instead of carrying a token over, the app on a trusted device can write a
signed approval record for the code into the primary vault. On the waiting
machine, `tsm approve` without a token has the service reload the primary and
take the records for its waiting codes:

```sh
tsm approve
# reloaded: approvals recorded in the primary are taken
```

### Pre-approving with `tsm allow`

A grant made in advance avoids the prompt. On a trusted device where
command-line approvals are switched on:

```sh
tsm allow server1 'exe /opt/app/bin/server' fleet/Db/Main
tsm allow server1 'exe /opt/app/bin/server' 'store fleet'
tsm allow server1 'exe /usr/bin/curl' all --never
```

- The host is the machine the grant holds on; the subject is the program, as
  `exe <path>`, `script <interpreter> <path>`, `interpreter <path>` or
  `folder <path> [interpreter]`.
- The secret is a reference in canonical form (`tsm ref format` prints it),
  `store <name>` or `all`.
- `--never` makes it a never grant; `--pin hash` binds it to the program's
  hash, `--pin off` does not.

`tsm grants` lists the grants (`--host H` for one host, `--json`), and
`tsm grants revoke <host> <grantId>` revokes one. The approval flow is
described in
[the protocol, section 7](../../../../protocol/protocol.md#7-approvals-and-grants).

## Status and key reminders

```sh
tsm status
```

```text
service  running, unlocked, lock mode idle, version 0.11.1
store    fleet  current  github  fetched 12 min ago
store    infra  offline  cache  fetched 9 days ago  (GitHub not reachable; offline copy older than 7 days)
```

- Each store shows its state, where its copy comes from (`github`, `file`,
  `cache`) and how old the copy is. A store on its offline copy says why:
  `GitHub not reachable`, or `token expired: enter a new one`. A copy older
  than 7 days is flagged.
- Lines starting with `expiring` name the keys a reminder is due for, with
  their expiry date.
- `tsm status` exits 3 and prints `not running` when no service runs, so a
  script can check it.

```sh
tsm keys                     # every key with its due date; * marks the reminders due
tsm audit --since 2026-11-01 --ref fleet/Db/Main
tsm audit --subject 'exe /opt/app/bin/server' --json
```

`status`, `keys`, `approvals`, `grants` and `audit` take `--json` for
scripts. `audit` covers the last 7 days unless `--since` / `--until` (ISO
8601) say otherwise.

## Compacting a vault repository

A vault kept in a GitHub repository (`github:` locator) gains a commit with
every save. The repository keeps a retention of its own; `tsm compact` cuts
the history to it now:

```sh
tsm compact example-org/fleet-vault
# compacted example-org/fleet-vault: 20 commits kept (3f2a9c1 -> 8b7e410)
```

When there is nothing to cut, it prints `nothing to cut in
example-org/fleet-vault`.

## Troubleshooting

`tsm` writes `tsm: <kind>: <message>` to standard error, with the reason or
the store the service named, and exits with the code of the kind:

| Code | Kind | What to do |
| --- | --- | --- |
| 2 | usage | A missing argument or a wrong option; `tsm help <command>` shows the usage. Also a binary value without `--base64`. |
| 3 | `not_running` | No service answers in the runtime directory. Start it (`tsm start`); check that `tsm` and the service see the same `TSM_RUNTIME_DIR`. |
| 4 | `locked` | The service is locked and no unlock came in time (or `--no-wait` was given). Run `tsm unlock`. |
| 5 | `denied` | The reason says why: `never` (a never grant), `refused` (refused at the prompt), `no_approver` (no approver and no token in time), `bad_token` (the token matches no waiting request), `bad_password`, `wrong_executable` (an admin command from a `tsm` the service does not accept, see [Before you start](#before-you-start)). |
| 6 | `not_found` | No entry matches, or it lacks the field. Check the reference, `--field` and `--dim`. |
| 7 | `ambiguous` | Several entries match equally. Name the store (a path) or the dimension. |
| 8 | `malformed` | The reference does not parse (`tsm ref parse` shows the reason), or a binary value was mapped by `tsm run`. |
| 9 | `timeout`, `rate_limited` | No approval came in time, or the client is being held back; try again later. |
| 10 | `unsupported` | The service does not offer this (for example `run --file`). |
| 11 | `offline`, `token_expired` | `tsm reload` could not fetch: the network, or GitHub refused the token. The store keeps serving its offline copy; a new token is entered in the manager app. `tsm status` shows the state. |
| 11 | `needs_unlock` | A store's key changed since the unlock. `tsm lock` and `tsm unlock` reopen the stores whose keys the primary holds; a store with a password of its own is opened in the manager app. |
| 11 | `unavailable` | The store could not be fetched and has no offline copy. Check the network and run `tsm reload`. |
| 11 | `internal` | A failure of the service; its log is in the data directory. |

Common situations:

- **`get` hangs.** It waits for an unlock or an approval; standard error says
  which. Unlock the service, or answer the approval code. Add `--no-wait` or
  `--timeout` in scripts that must not wait.
- **Every admin command asks for the password.** No keychain answers (an SSH
  session). Expected; use `--password-stdin` in automation.
- **The pairing fails.** The code is burnt after one attempt and the window
  closes after five minutes; open a new one on the desktop and check that the
  address is reachable from the new machine.

The error kinds and their details are listed in
[the protocol, section 10](../../../../protocol/protocol.md#10-error-kinds).
