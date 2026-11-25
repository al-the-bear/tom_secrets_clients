# tom_secrets_provider

The Tom Secrets Manager as a secrets provider for Tom servers: a configuration
value written as `secret:local:<reference>#<field>` is read from the secrets
service on the same machine. `TomLocalSecretsProvider` implements
[`tom_core_server`](https://pub.dev/packages/tom_core_server)'s
`TomSecretsProvider`; a server that wants it adds this package and registers
the provider. The other secret stores (AWS Secrets Manager, Azure Key Vault,
HashiCorp Vault) are in
[`tom_core_secrets`](https://pub.dev/packages/tom_core_secrets).

> **Attribution.** The Tom Secrets Manager is developed by Peter Nicolai Alexis
> Kyaw. This package is BSD-3-Clause licensed and published on pub.dev.

## Installation

```yaml
dependencies:
  tom_core_server: ^1.5.1
  tom_secrets_provider: ^0.1.0
```

Dart SDK `^3.10.0`.

## Overview

The Tom Secrets Manager keeps a machine's secrets in KDBX vaults and serves
them to the processes on that machine through its **secrets service**. This
package is the provider for it: `TomLocalSecretsProvider`, registered as
`local`, so a configuration value reads a secret from the service on the same
machine:

```yaml
databasePassword: "secret:local:[env:prod]db.main"
databaseUser: "secret:local:[env:prod]db.main#UserName"
```

The server resolves every reference once at boot, before it builds its
configuration object, and again on each refresh. The provider asks the service
for exactly the field a reference names; the service resolves the reference
(store, overlays, the host's dimensions) and decides, by the approvals it
keeps, whether this process may read it. The provider talks to the service with
[`tom_secrets_client`](https://pub.dev/packages/tom_secrets_client) over the
Tom Secrets Manager's
[client protocol](https://github.com/al-the-bear/tom_secrets_clients/blob/main/protocol/protocol.md);
there is no KDBX code in this package.

## Features

| Type | What it does |
| ---- | ------------ |
| `TomLocalSecretsProvider` | The `TomSecretsProvider` over the secrets service: `fetch` sends `get` for the reference's field with the configured dimensions, waits for an unlock or an approval when asked, and answers the value with the entry's version (its last modification and the store revision) as the payload version, so a rotated secret reaches a watcher on refresh. `fromConfiguration` builds one from `secrets.local`. `close` closes the connection; the next `fetch` opens a new one. |

## The reference

```text
secret:local:<tsm reference>[#<field>]
```

What follows `secret:local:` is a Tom Secrets Manager reference as `tsm get`
takes it — a key, a path in a store, an entry's UUID, with qualifiers in front
— and `#<field>` names a field of the entry, `Password` when none is named:

| Reference | Reads |
| --------- | ----- |
| `secret:local:telegram.bot_token` | the entry whose key is `telegram.bot_token`, field `Password` |
| `secret:local:demo/Cloud/AWS/root#UserName` | the entry `root` in group `Cloud/AWS` of the store `demo`, field `UserName` |
| `secret:local:[env:prod]db.main` | the key `db.main` with the dimension `env` bound to `prod` |
| `secret:local:demo/~0f3c2a1b4d5e6f708192a3b4c5d6e7f8#totp` | an entry by its UUID, which survives renames and moves, field `totp` |

A reference splits provider from path at the **first** colon, so the colons
inside the brackets stay in the path, and takes the field after the **last**
`#`. A reserved character inside a name is percent-encoded as `tsm` writes it
(`demo/Mail/a%2Fb%23c`).

## Quick start

```dart
import 'package:tom_secrets_provider/tom_secrets_provider.dart';
import 'package:tom_core_server/tom_core_server.dart';

Future<void> main(List<String> args) async {
  TomSecrets.register(TomLocalSecretsProvider.fromConfiguration());
  await TomSecrets.load(TomBaseServerConfiguration.collectSources(args));
  print(TomSecrets.current('secret:local:[env:prod]db.main#UserName'));
}
```

The service must be running on the machine (a locked one is waited for until
it is unlocked), and the first request of a new program goes to approval (see [The service and
approvals](#the-service-and-approvals)); afterwards the service answers it from
the grant.

## Example

| Example | Demonstrates |
| ------- | ------------ |
| [`example/tom_secrets_provider_example.dart`](example/tom_secrets_provider_example.dart) | Building the provider from configuration, loading two fields of one entry, a rotation reaching a watcher on refresh, and the version kept with the value — against an in-process stand-in for the secrets service, so it runs anywhere |

```bash
dart run example/tom_secrets_provider_example.dart
```

`test/example_test.dart` runs it and requires a clean exit.

## Configuration

A Tom server registers the provider at boot, before `TomSecrets.load`:

```dart
import 'package:tom_secrets_provider/tom_secrets_provider.dart';
import 'package:tom_core_server/tom_core_server.dart';

void registerSecrets() {
  TomSecrets.register(TomLocalSecretsProvider.fromConfiguration());
}
```

`TomLocalSecretsProvider.fromConfiguration` reads the `secrets.local` key of
the server's configuration; every setting is optional:

```yaml
secrets:
  local:
    clientName: billing-server   # shown in the approval prompt
    dimensions:                  # sent with every request
      env: prod
    timeoutSeconds: 30           # how long a request may wait
    waitForUnlock: true          # false: answer `locked` at once
```

| Setting | Meaning |
| ------- | ------- |
| `clientName` | The name shown in the approval prompt (default the executable's name). Shown, never trusted: the service identifies the process itself. |
| `dimensions` | Dimension values sent with every request, for example `{env: prod}` for the deployment. A reference that binds the same dimension to another value is refused (kind `malformed`, reason `conflicting_dimension`). |
| `timeoutSeconds` | How long a request may wait for an unlock or an approval; the service caps it. |
| `waitForUnlock` | `false` answers a locked service at once (`secrets.fetch.failed`, kind `locked`) instead of waiting. Default `true`. |

A setting of the wrong type is refused with `secrets.local.config.malformed`.
The constructor takes the same settings (`clientName`, `dimensions`, `wait`,
`timeout`), the registration `name` (default `local`), the `environment` the
service is looked for in, and a `client` of its own.

## The service and approvals

The provider reads from a running secrets service; it never starts one. On a
desktop the Tom Secrets Manager app runs it; on a headless host `tsm start`
starts it and `tsm unlock` unlocks it (`tsm` is the
[`tom_secrets_tsm`](https://pub.dev/packages/tom_secrets_tsm) command-line
tool). The service is found in the runtime directory of the OS user the server
runs as:

| OS | Where |
| --- | --- |
| any | `TSM_RUNTIME_DIR` when set (containers, tests) |
| Linux | `$XDG_RUNTIME_DIR/tsm/`, else `/tmp/tsm-<uid>/` |
| macOS | `$TMPDIR/tsm/`, else `/tmp/tsm-<uid>/` |
| Windows | `%LOCALAPPDATA%\TomSecretsManager\run\` (a localhost port and a client token) |

The service measures each connecting process itself — its executable, or for
`dart run` the interpreter and the script — and refuses a process of another
OS user. A server it holds no grant for goes to approval on its first request:
the desktop app prompts, or on a headless host the request waits with an
approval code (`tsm approvals` lists it): the app on a trusted device turns the
code into a one-time token, which `tsm approve <token>` on the host redeems. With
`waitForUnlock: true` and a `timeoutSeconds` long enough, the boot waits
through the unlock and the approval; once approved with "always", later starts
are answered from the grant. A server whose boot must not wait sets
`waitForUnlock: false`.

## Errors

A failed fetch throws `tom_core_server`'s `TomSecretsException`. At boot
`TomSecrets.load` throws it on the first reference it cannot resolve, so the
server does not start without its secrets; `TomSecrets.refresh` keeps the
value a reference had and reports the reference as failed.

| Key | When |
| --- | ---- |
| `secrets.fetch.not_found` | The service holds no entry or field for the reference. |
| `secrets.fetch.failed` | Any other refusal or failure; the parameters name the `provider`, the tsm `reference`, the `kind` — `not_running` (no service), `locked`, `denied`, `ambiguous`, `malformed`, `timeout`, `rate_limited`, ... — and the `reason` when the service gave one. |
| `secrets.local.binary_not_text` | The value is binary; a configuration value is text. |
| `secrets.local.config.malformed` | A `secrets.local` setting has the wrong type; `setting` names it. |

No message or parameter carries a secret value.

## Limits

- **One machine.** The provider reads the service of the machine the server
  runs on; a server elsewhere uses a cloud store.
- **Text only.** A binary value is refused (`secrets.local.binary_not_text`).
- **One request per field.** Each reference is fetched on its own, because the
  service answers one field per `get`: two fields of one entry are two
  requests.

## Further documentation

| Document | Covers |
| -------- | ------ |
| [doc/tom_secrets_provider.md](doc/tom_secrets_provider.md) | The reference syntax, configuration, approvals, versions and rotation, the error keys |
| [doc/api/api_summary_tom_secrets_provider.md](doc/api/api_summary_tom_secrets_provider.md) | Every public type and member |
| [`tom_secrets_client`](https://pub.dev/packages/tom_secrets_client) | The Dart client the provider uses: finding the service, `get`, the reference grammar |
| [`tom_secrets_tsm`](https://pub.dev/packages/tom_secrets_tsm) | `tsm`: starting, unlocking and administering the service, approvals |
| [Client protocol](https://github.com/al-the-bear/tom_secrets_clients/blob/main/protocol/protocol.md) | The protocol the service speaks: finding it, references (section 4), `get`, approvals and grants (section 7), error kinds |

## Dependencies

| Dependency | Kind | For |
| ---------- | ---- | --- |
| `tom_core_server` | runtime | `TomSecretsProvider`, `TomSecretPayload`, `TomSecretsException`, `TomSecretReference`, the configuration the provider is built from |
| `tom_secrets_client` | runtime | the secrets service's client protocol: finding the service, `get`, the frames; BSD-3, it reaches no KDBX |
| `test`, `lints` | dev | the suites |

## Status

Version **0.1.0**. `dart test` runs the provider against an in-process
stand-in for the secrets service (a Unix socket, or on Windows a localhost
port with the client token) and the example.
