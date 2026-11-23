# Tom Secrets Client API Reference: Admin Module

<!-- markdownlint-configure-file { "MD024": { "siblings_only": true } } -->

## Table of Contents

- [Overview](#overview)
- [Class Hierarchy](#class-hierarchy)
- [Classes](#classes)
  - [TomSecretsAdminClient](#tomsecretsadminclient)
  - [TomSecretsAdminException](#tomsecretsadminexception)
  - [TomSecretsAdminKeyring](#tomsecretsadminkeyring)
  - [TomSecretsRuntime](#tomsecretsruntime)
  - [TomSecretsRuntimeException](#tomsecretsruntimeexception)
  - [TomSecretsAlreadyRunning](#tomsecretsalreadyrunning)
  - [TomSecretsHandover](#tomsecretshandover)
  - [TomSecretsStartResult](#tomsecretsstartresult)
  - [TomSecretsStarted](#tomsecretsstarted)
  - [TomSecretsAlreadyStarted](#tomsecretsalreadystarted)
  - [TomSecretsStartFailed](#tomsecretsstartfailed)
  - [TomSecretsPairingHandover](#tomsecretspairinghandover)
  - [TomSecretsPairingReport](#tomsecretspairingreport)
  - [TomSecretsPairingModeException](#tomsecretspairingmodeexception)
  - [TomSecretsServicePairing](#tomsecretsservicepairing)
  - [TomSecretsUnlockBundle](#tomsecretsunlockbundle)
  - [TomSecretsBundleException](#tomsecretsbundleexception)
  - [TomSecretsBrowserHosts](#tomsecretsbrowserhosts)
  - [TomSecretsBrowserHostState](#tomsecretsbrowserhoststate)
  - [TomSecretsRegistry](#tomsecretsregistry)
  - [TomSecretsIntegrationState](#tomsecretsintegrationstate)
  - [TomSecretsIntegrations](#tomsecretsintegrations)
- [Enums](#enums)
  - [TomSecretsTransport](#tomsecretstransport)
  - [TomSecretsBrowser](#tomsecretsbrowser)
  - [TomSecretsIntegration](#tomsecretsintegration)
- [Typedefs](#typedefs)
- [Global Functions and Constants](#global-functions-and-constants)

---

## Overview

The admin module is `package:tom_secrets_client/admin.dart`: the admin side
of the Tom Secrets Manager's local protocol, used by the manager app, `tsm`
and the service itself. It holds the admin client with its mutual challenge
and `claim`, the runtime directory, starting the service with its admin-key
handover, the service's pairing mode, the admin keys in the OS keychain,
where the product keeps its data, the keychain names and the layout of the
app's distribution. A program that only reads secrets needs none of it.

---

## Class Hierarchy

```text
Object
├── TomSecretsAdminClient
├── TomSecretsAdminKeyring
├── TomSecretsRuntime
├── TomSecretsHandover
├── TomSecretsStartResult (sealed)
│   ├── TomSecretsStarted
│   ├── TomSecretsAlreadyStarted
│   └── TomSecretsStartFailed
├── TomSecretsPairingHandover
├── TomSecretsPairingReport
├── TomSecretsServicePairing
├── TomSecretsUnlockBundle
└── (implements Exception)
    ├── TomSecretsAdminException
    ├── TomSecretsRuntimeException
    ├── TomSecretsAlreadyRunning
    ├── TomSecretsPairingModeException
    └── TomSecretsBundleException
```

---

## Classes

### TomSecretsAdminClient

An authenticated admin connection: requests by id and the pushed events.

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `connect(TomSecretsRuntime runtime, List<int> adminKey, {Map<String, Object?> client = const {'name': 'tsm'}})` | `Future<TomSecretsAdminClient>` | Connects to the admin endpoint and runs the mutual challenge; throws `service_impostor` when the service's proof is wrong, `denied` when the service refuses the key, `not_running` when no service answers |
| `claim(TomSecretsRuntime runtime, {required String password, List<int>? keyFile, Map<String, Object?> client = const {'name': 'tsm'}})` | `Future<(TomSecretsAdminClient, Uint8List)>` | Takes the service over with the master password; answers the connection and the new admin key. The service cannot prove itself here, so the caller warns the user first |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `serviceStart` | `int` | The service's start time (0 on a connection that claimed the service) |
| `events` | `Stream<Map<String, Object?>>` | The pushed events, after a `subscribe` request |
| `isClosed` | `bool` | Whether the connection has ended |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `request(String op, [Map<String, Object?> fields = const {}])` | `Future<Map<String, Object?>>` | Sends an admin request with an id; answers the answer, or throws `TomSecretsAdminException` for an `error` |
| `unlock(String password, {List<int>? keyFile})` | `Future<void>` | Unlocks with the master password (and key file) |
| `unlockWithBundle(String vault, TomSecretsUnlockBundle bundle)` | `Future<void>` | Unlocks a store (the primary: the service) with the OS unlock's key bundle, sealed under this connection's bundle key (protocol.md 6.4); `unsupported` on a connection that claimed the service |
| `close()` | `Future<void>` | Ends the connection |

---

### TomSecretsAdminException

The admin endpoint refused or broke the conversation.

**Implements:** `Exception`

#### Constructors

```dart
TomSecretsAdminException(
  String kind,
  String message, {
  Map<String, Object?> details = const {},
})
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `kind` | `String` | The error kind (`denied`, `locked`, ...) or `closed`, `not_running`, `service_impostor` |
| `message` | `String` | What happened |
| `details` | `Map<String, Object?>` | The error's details |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toString()` | `String` | `TomSecretsAdminException(<kind>): <message>` |

---

### TomSecretsAdminKeyring

The admin keys the app and `tsm` keep in the OS keychain, one per start of
the service, and the index of the starts they were kept for. An OS keychain
cannot be listed, so the index is what lets a key whose service is gone be
found and removed. The keychain's own failures pass through.

#### Constructors

```dart
TomSecretsAdminKeyring({
  required Future<String?> Function(String handle) read,
  required Future<void> Function(String handle, String value) write,
  required Future<void> Function(String handle) delete,
})
```

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `keyOf(int start)` | `Future<Uint8List?>` | The admin key kept for the service started at `start`, or null |
| `keep(int start, Uint8List key)` | `Future<void>` | Keeps the key and records the start in the index |
| `forget(int start)` | `Future<void>` | Removes the key of a stopped service and its index entry |
| `pruneOthers(int? running)` | `Future<List<int>>` | Removes every recorded key but the running service's (null: every key); answers the starts whose key was removed |
| `recorded()` | `Future<Set<int>>` | The starts the index records |

---

### TomSecretsRuntime

The runtime directory of this OS user: its check, the single-instance lock
`service.lock`, `service.json` and the endpoint files.

#### Constructors

```dart
TomSecretsRuntime(
  String directory, {
  required TomSecretsTransport transport,
  String? separator,
})
```

#### Factory Constructors

```dart
factory TomSecretsRuntime.current({
  Map<String, String>? environment,
  String? operatingSystem,
})
```

The runtime directory the client discovery names for this process (or the
given environment and OS); Unix sockets except on Windows, and the paths
joined with the separator of the OS asked for (`\` for `windows`, else
`/`), whatever OS computes them. Throws
`TomSecretsRuntimeException` when no directory can be named.

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `directory` | `String` | The directory |
| `transport` | `TomSecretsTransport` | How the endpoints are offered |
| `separator` | `String` | The path separator the files are joined with (default this platform's) |
| `clientSocket` | `String` | `client.sock` |
| `adminSocket` | `String` | `admin.sock` |
| `agentSocket` | `String` | `agent.sock`, the ssh-agent's Unix domain socket (Linux, macOS): what `SSH_AUTH_SOCK` or `IdentityAgent` names |
| `agentPipe` | `String` (static) | The ssh-agent's named pipe on Windows, `\\.\pipe\tsm-ssh-agent` |
| `agentEndpoint` | `String` | Where `ssh` finds the agent on this runtime's OS: the pipe on Windows, else the socket |
| `clientPortFile` | `String` | `client.port` |
| `clientTokenFile` | `String` | `client.token` |
| `adminPortFile` | `String` | `admin.port` |
| `lockFile` | `String` | `service.lock` |
| `infoFile` | `String` | `service.json` |
| `endpointFiles` | `List<String>` | The endpoint files of the transport, every one a start writes |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `prepare()` | `Future<void>` | Makes the directory the user's alone when missing (mode 0700; on Windows only the user and SYSTEM), then checks it |
| `check()` | `Future<void>` | Checks owner and mode; a directory of someone else, or one others can read, is refused |
| `acquire()` | `Future<void>` | Takes the exclusive single-instance lock; throws `TomSecretsAlreadyRunning` when another service holds it |
| `release()` | `Future<void>` | Releases the lock |
| `removeStaleEndpoints()` | `Future<void>` | Deletes the endpoint files a dead instance left (only after `acquire`) |
| `removeEndpoints()` | `Future<void>` | Deletes the endpoint files and `service.json` (a stop) |
| `writeInfo({required int start, required Map<String, Object?> client, required Map<String, Object?> admin})` | `Future<void>` | Writes `service.json`: PID, start, protocol, the endpoints; no secret |
| `readInfo()` | `Future<Map<String, Object?>?>` | `service.json`, or null |
| `writePort(String path, int port)` | `Future<void>` | Writes a port file |
| `writeToken(String token)` | `Future<void>` | Writes the client token |

---

### TomSecretsRuntimeException

A runtime directory that is not the user's alone, or cannot be made.

**Implements:** `Exception`

#### Constructors

```dart
TomSecretsRuntimeException(String message)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What is wrong |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toString()` | `String` | `TomSecretsRuntimeException: <message>` |

---

### TomSecretsAlreadyRunning

Another service already holds the lock: the starter attaches to it.

**Implements:** `Exception`

#### Constructors

```dart
TomSecretsAlreadyRunning(Map<String, Object?>? info)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `info` | `Map<String, Object?>?` | `service.json` of the running service, or null |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toString()` | `String` | `TomSecretsAlreadyRunning` |

---

### TomSecretsHandover

The handover line a starting service reads from its standard input: the
admin key, the bootstrap file, the starter's PID.

#### Constructors

```dart
const TomSecretsHandover({
  required Uint8List adminKey,
  required String bootstrap,
  required int starterPid,
})
```

#### Factory Constructors

```dart
factory TomSecretsHandover.parse(String line)
```

From the JSON line; throws `FormatException` when it lacks `adminKey` or
`bootstrap`, or the key is not 32 bytes.

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `adminKey` | `Uint8List` | The admin key |
| `bootstrap` | `String` | The bootstrap file's path |
| `starterPid` | `int` | The starter's PID |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toLine()` | `String` | The JSON line |

---

### TomSecretsStartResult

What `tomSecretsStartService` found. Sealed: `TomSecretsStarted`,
`TomSecretsAlreadyStarted` or `TomSecretsStartFailed`.

---

### TomSecretsStarted

A new service runs with the admin key.

**Extends:** `TomSecretsStartResult`

#### Constructors

```dart
const TomSecretsStarted(Uint8List adminKey)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `adminKey` | `Uint8List` | The admin key the starter keeps |

---

### TomSecretsAlreadyStarted

A service was already running: attach to it, with the key held or by
`claim`.

**Extends:** `TomSecretsStartResult`

#### Constructors

```dart
const TomSecretsAlreadyStarted()
```

---

### TomSecretsStartFailed

The service could not start.

**Extends:** `TomSecretsStartResult`

#### Constructors

```dart
const TomSecretsStartFailed(String code, String message)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `code` | `String` | The failure's code (`runtime`, `device_key`, `handover`, `no_answer`, ...) |
| `message` | `String` | What happened (no secret) |

---

### TomSecretsPairingHandover

The pairing mode's handover line: set the machine up in a data directory by
receiving the pairing at an address and port with the code the giving
machine shows, or **[C]** through a relay (after the address, or alone): a
relay server (`tsm:<url>`), or a GitHub repository with this machine's own
token for it.

#### Constructors

```dart
const TomSecretsPairingHandover({
  required String dataDirectory,
  String? address,
  int? port,
  required String code,
  required String device,
  String? deviceKey,
  String? approvalLink,
  String? relay,
  String? relayToken,
  String? relayApi,
})
```

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `fromJson(Object? json)` | `TomSecretsPairingHandover?` | The handover in the JSON, or null when it is not a pairing handover; throws `FormatException` for one that misses a member, names neither an address and port nor a relay, a relay that is neither `tsm:` nor `github:`, a GitHub relay without its token, or an `approvalLink` that is no approval link |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `dataDirectory` | `String` | The data directory the machine is set up in |
| `address` | `String?` | The giving machine's address, or null (a relay only) |
| `port` | `int?` | Its pairing window's port, or null (a relay only) |
| `code` | `String` | The code its Pairing screen shows |
| `device` | `String` | This machine's name |
| `deviceKey` | `String?` | Where the device settings container's key is kept, or null (`auto`) |
| `approvalLink` | `String?` | The address this machine's approval link listens on (`address:port`), or null: it goes into the device settings, and the giving machine records it so its service opens the link at once |
| `relay` | `String?` | **[C]** The relay the pairing also goes through, tried after the address: a relay server (`tsm:<url>`) or a GitHub repository (`github:<owner>/<repo>`), or null |
| `relayToken` | `String?` | **[C]** This machine's own token for the relay: a GitHub repository's (it also opens the primary when that is there), or a relay server's instance token (optional). Never a command-line argument |
| `relayApi` | `String?` | **[C]** The GitHub API's URL for the relay, or null (`https://api.github.com`) |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toLine()` | `String` | The JSON line |

---

### TomSecretsPairingReport

What a pairing gave, as the pairing mode reports it (no key, no token).

#### Constructors

```dart
const TomSecretsPairingReport({
  required String giver,
  required List<TomSecretsPairedVault> vaults,
  required bool config,
  required List<String> tokens,
})
```

#### Factory Constructors

```dart
factory TomSecretsPairingReport.fromJson(Map<String, Object?> json)
```

From the `received` line.

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `giver` | `String` | The giving device's name |
| `vaults` | `List<TomSecretsPairedVault>` | The vaults it gave |
| `config` | `bool` | Whether it gave the shared configuration |
| `tokens` | `List<String>` | The repositories it gave a token for |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The `received` line |

---

### TomSecretsPairingModeException

The pairing mode answered an error.

**Implements:** `Exception`

#### Constructors

```dart
const TomSecretsPairingModeException(
  String code,
  String message, {
  String? failure,
})
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `code` | `String` | The error's code (`pairing`, `wrong_password`, `setup`, `handover`, `ended`) |
| `message` | `String` | What happened, for the user |
| `failure` | `String?` | The pairing's failure (`wrongCode`, `refused`, ...) when `code` is `pairing` |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toString()` | `String` | `TomSecretsPairingModeException(<code>): <message>` |

---

### TomSecretsServicePairing

A conversation with the service in its pairing mode, as `tsm pair` drives
it: the service executable runs attached and talks in JSON lines.

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `start({required String executable, List<String> arguments = const [], required TomSecretsPairingHandover handover, Map<String, String>? environment})` | `Future<TomSecretsServicePairing>` | Starts the executable and hands it the handover |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `received()` | `Future<TomSecretsPairingReport>` | Waits for the pairing: what it gave; throws `TomSecretsPairingModeException` (the service has ended then) |
| `setUp(String password)` | `Future<String>` | Sets the machine up with the master password; answers the bootstrap file written. After `wrong_password` another password may be sent |
| `close()` | `Future<int>` | Ends the conversation and the service; answers its exit code |

### TomSecretsUnlockBundle

The key material of one vault's OS unlock (protocol.md 6.4): its composite
key and, for a vault with the outer encryption, its repository key; never
the password text.

| Constructor | Description |
| --- | --- |
| `TomSecretsUnlockBundle({required List<int> compositeKey, String? outerKey})` | A bundle of a 32-byte composite key (a copy is kept) and a repository key |
| `TomSecretsUnlockBundle.decode(List<int> bytes)` | Reads the plaintext `{"v": 1, "compositeKey", "outerKey"?}`; throws `TomSecretsBundleException` |

| Member | Type | Description |
| --- | --- | --- |
| `compositeKey` | `Uint8List` | The composite key |
| `outerKey` | `String?` | The repository key, or null |
| `encode()` | `Uint8List` | The plaintext bytes; the caller wipes them |
| `dispose()` | `void` | Overwrites the composite key |

### TomSecretsBundleException

A sealed bundle did not open, or its plaintext is no bundle; carries no key
material. `message` says what failed.

### TomSecretsBrowserHosts

The browsers' native-messaging manifests of the browser host
`tsm-browser-host` (part-browser), installed per user by the manager app and
checked at every start: `net.tom.secrets.json` in each browser's folder, on
Windows kept under `%LOCALAPPDATA%\TomSecretsManager\NativeMessagingHosts\`
and named by the registry key's default value.

| Constructor | Description |
| --- | --- |
| `TomSecretsBrowserHosts({required String home, required String hostExecutable, String? operatingSystem, Map<String, String>? environment, TomSecretsRegistry? registry})` | The manifests in [home] naming [hostExecutable]; Windows' `LOCALAPPDATA` and `APPDATA` from [environment]; the registry through `reg.exe` by default |

| Member | Type | Description |
| --- | --- | --- |
| `profileFolder(TomSecretsBrowser b)` | `String` | The browser's profile folder, whose presence offers it |
| `manifestFolder(TomSecretsBrowser b)` | `String` | The folder the browser reads the manifest from |
| `manifestPath(TomSecretsBrowser b)` | `String` | The manifest file |
| `registryKey(TomSecretsBrowser b)` | `String?` | The Windows registry key (`HKCU\Software\…\NativeMessagingHosts\net.tom.secrets`), null elsewhere |
| `manifest(TomSecretsBrowser b)` | `Map<String, Object?>` | `name`, `description`, `path`, `type: stdio`, `allowed_origins` (Chromium) or `allowed_extensions` (Firefox) |
| `state(TomSecretsBrowser b)` | `Future<TomSecretsBrowserHostState>` | Where the host stands for the browser |
| `states()` | `Future<List<TomSecretsBrowserHostState>>` | Every browser's |
| `install(TomSecretsBrowser b)` | `Future<void>` | Writes the manifest (and the registry value); `StateError` for a Flatpak or Snap browser |
| `remove(TomSecretsBrowser b)` | `Future<void>` | Removes the manifest (and the registry key) |
| `repair()` | `Future<List<TomSecretsBrowser>>` | Rewrites each installed manifest that names another host; answers those |

### TomSecretsBrowserHostState

Where the host stands for one browser: `browser`, `present` (its profile
folder exists), `installed`, `current` (names this host and the product's
extensions), `manifest` (the file), `sandboxed` (why a Flatpak or Snap
browser cannot start it, or null), `problems`; `toJson()`.

### TomSecretsRegistry

The Windows registry as far as the manifests need it: `read(key)` (the
default value, or null), `write(key, value)`, `delete(key)`.
`TomSecretsRegExe` implements it with `reg.exe`.

### TomSecretsIntegrationState

The state of one developer-tool integration (`tsm integrations`, the app's
Settings › Integrations): `integration`, `installed` (its block is in the
tool's file), `current` (it names this machine's own agent endpoint and
helper), `file`, `problems` (in words), `hosts` (the ssh block's host
patterns), **[C]** `profiles` (the AWS block's profile name → reference),
`registries` (the Docker registries `credHelpers` names the helper for)
and `everyRegistry` (`credsStore`); `toJson()` as
`tsm integrations status --json` prints it.

### TomSecretsIntegrations

The integrations of one user on this machine, each written in a marked
block of the tool's file and removed again (nothing outside the block
changes); Docker's JSON has no comments, so its block is the product's own
keys (`credHelpers` entries `tsm`, `credsStore` `tsm`).

#### Constructors

```dart
TomSecretsIntegrations({
  required String home,
  String? agentEndpoint,
  String? tsmExecutable,
  String? operatingSystem,
  String? path,
})
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `home` | `String` | The user's home folder |
| `agentEndpoint` | `String?` | Where the service's agent listens (`statusReport.agent`) |
| `tsmExecutable` | `String?` | `tsm`'s executable |
| `operatingSystem` | `String` | The OS the files are for |
| `path` | `String` | The `PATH` git looks for the helper on |
| `sshConfig` | `String` | `~/.ssh/config` |
| `gitConfig` | `String` | `~/.gitconfig` |
| `awsConfig` | `String` | **[C]** `~/.aws/config` |
| `dockerConfig` | `String` | **[C]** `~/.docker/config.json` |
| `helperLink` | `String?` | `git-credential-tsm` beside `tsm` |
| `gitBlock` | `List<String>` (static) | The git block: `[credential]`, `helper = tsm` |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `fileOf(integration)` | `String` | The file of an integration |
| `sshBlock({hosts})` | `List<String>` | The ssh block for the host patterns (`Host *` by default) |
| `awsBlock(profiles)` | `List<String>` | **[C]** The AWS block: per profile its section (`[default]` for the default one) and `credential_process = <tsm> aws-credentials <ref>`, each word quoted as botocore splits it (shlex; the Windows rules on Windows) |
| `helperLinkOf(name)` | `String?` | **[C]** The helper `name` (`git-credential-tsm`, `docker-credential-tsm`) beside `tsm` |
| `status(integration)` | `Future<TomSecretsIntegrationState>` | The state of an integration |
| `install(integration, {hosts, awsProfiles, dockerRegistries, dockerEveryRegistry})` | `Future<TomSecretsIntegrationState>` | Writes its block (and for git and Docker the helper link): **[C]** the AWS profiles added to those the block has, the Docker registries to `credHelpers` and with `dockerEveryRegistry` `credsStore`; `StateError` when the endpoint or `tsm` is not known, when AWS has no profile or one is defined outside the block, when Docker has nothing to name or its file is no JSON object |
| `uninstall(integration, {awsProfile, dockerRegistry})` | `Future<TomSecretsIntegrationState>` | Removes its block (and for git and Docker the helper link); **[C]** with `awsProfile` or `dockerRegistry` only that one (the link stays while something is left) |
| `repair()` | `Future<List<TomSecretsIntegration>>` | Installs again every installed integration that no longer names this machine's agent, helper or tsm, with the hosts, profiles and registries it has; answers those it repaired |

---

## Enums

### TomSecretsTransport

How the endpoints are offered.

#### Values

| Value | Description |
| --- | --- |
| `unix` | Unix domain sockets: `client.sock`, `admin.sock` (Linux, macOS) |
| `tcp` | Localhost TCP ports with a client token: `client.port` + `client.token`, `admin.port` (Windows) |

### TomSecretsBrowser

A browser the host can be installed for: `chrome`, `chromium`, `edge`,
`brave`, `firefox`; `label` (its name), `isFirefox`.

### TomSecretsIntegration

A developer tool the product configures: `ssh` (the service's agent as
`IdentityAgent` in `~/.ssh/config`), `git` (the credential helper
`git-credential-tsm`, `credential.helper tsm` in `~/.gitconfig`), **[C]**
`aws` (`credential_process = tsm aws-credentials <ref>` per profile in
`~/.aws/config`), `docker` (the credential helper `docker-credential-tsm`,
`credHelpers` or `credsStore` in `~/.docker/config.json`).

---

## Typedefs

| Typedef | Definition | Description |
| --- | --- | --- |
| `TomSecretsPairedVault` | `({String name, String locator, bool primary})` | One vault a pairing gave |

---

## Global Functions and Constants

### Constants

| Constant | Type | Description |
| --- | --- | --- |
| `tomSecretsAdminLabel` | `String` | The admin's challenge label, `tsm-admin-v1` |
| `tomSecretsServiceLabel` | `String` | The service's challenge label, `tsm-service-v1` |
| `tomSecretsKeyBytes` | `int` | The length of an admin key and of a nonce (32) |
| `tomSecretsAdminKeyIndexHandle` | `String` | The keychain handle of the index of kept starts, `tsm.admin.index` |
| `tomSecretsKeychainService` | `String` | The service name of the product's items in the OS keychain, `tom-secrets-manager` |
| `tomSecretsToolsFolder` | `String` | The folder of the distribution holding the command-line tools, `tsm` |
| `tomSecretsAppExecutable` | `String` | The manager app's executable name without `.exe`, `tom_secrets_app` |
| `tomSecretsServiceExecutable` | `String` | The service's executable name without `.exe`, `tom_secrets_service` |
| `tomSecretsBrowserHostId` | `String` | The native-messaging host's name, `net.tom.secrets` |
| `tomSecretsFirefoxExtensionId` | `String` | The Firefox extension's id, `tom-secrets@enterprise-flutter.dev` |
| `tomSecretsChromiumDevelopmentKey` | `String` | The Chromium development build's public key (the manifest's `key`) |
| `tomSecretsChromiumDevelopmentId` | `String` | The development build's extension id, fixed by that key |
| `tomSecretsChromiumExtensionIds` | `List<String>` | The Chromium extension ids the host serves; `tomSecretsChromiumExtensionOrigins` their origins |
| `tomSecretsPairingWrongPassword` | `String` | The code of a wrong master password, `wrong_password` |
| `tomSecretsPairingPasswordTries` | `int` | How many master passwords the pairing mode takes (3) |
| `tomSecretsBlockBegin` | `String` | The first line of a block the product writes, `# >>> tom secrets >>>` |
| `tomSecretsGitHelperName` | `String` | The name git runs the helper under: `git-credential-tsm` |
| `tomSecretsDockerHelperName` | `String` | **[C]** The name Docker runs the helper under: `docker-credential-tsm` |
| `tomSecretsBlockEnd` | `String` | The last line of a block the product writes, `# <<< tom secrets <<<` |
| `tomSecretsBundleInfo` | `String` | The HKDF info of the bundle key, `tsm-bundle-v1` |
| `tomSecretsBundleNonceBytes` | `int` | The length of a sealed bundle's nonce (12) |
| `tomSecretsCompositeKeyBytes` | `int` | The length of a composite key (32) |

### Functions

| Function | Signature | Description |
| --- | --- | --- |
| `tomSecretsChallengeInput` | `Uint8List tomSecretsChallengeInput(String label, List<int> serviceNonce, List<int> adminNonce, int serviceStart)` | The MAC input: the label's ASCII, both 32-byte nonces, the service start as 8 bytes big-endian |
| `tomSecretsChallengeMac` | `Uint8List tomSecretsChallengeMac(List<int> adminKey, String label, List<int> serviceNonce, List<int> adminNonce, int serviceStart)` | HMAC-SHA256 of the challenge input under the admin key |
| `tomSecretsConstantTimeEquals` | `bool tomSecretsConstantTimeEquals(List<int> a, List<int> b)` | Equality in time independent of where the lists differ |
| `tomSecretsRandomBytes` | `Uint8List tomSecretsRandomBytes([int count = tomSecretsKeyBytes])` | Bytes from the OS's secure generator |
| `tomSecretsAuthDelay` | `Duration tomSecretsAuthDelay(int failures)` | The delay before the next authentication: 0, then 1 s, 2 s, 4 s, ... up to 60 s |
| `tomSecretsAdminKeyHandle` | `String tomSecretsAdminKeyHandle(int serviceStart)` | The keychain handle of the admin key of a service start, `tsm.admin.<start>` |
| `tomSecretsBundleKey` | `Uint8List tomSecretsBundleKey(List<int> adminKey, List<int> serviceNonce, List<int> adminNonce)` | The bundle key of one admin connection: HKDF-SHA256 of the admin key, salted with both nonces, info `tsm-bundle-v1` |
| `tomSecretsBundleAad` | `Uint8List tomSecretsBundleAad(String vault, int serviceStart)` | A sealed bundle's associated data: the vault's name and the service start as 8 bytes big-endian |
| `tomSecretsSealBundle` | `Future<Map<String, String>> tomSecretsSealBundle({required List<int> bundleKey, required String vault, required int serviceStart, required List<int> plaintext, List<int>? nonce})` | The `bundle` object of `unlock`: AES-256-GCM with a random 12-byte nonce, the tag appended |
| `tomSecretsOpenBundle` | `Future<Uint8List> tomSecretsOpenBundle({required List<int> bundleKey, required String vault, required int serviceStart, required Map<String, Object?> bundle})` | The plaintext of a sealed bundle; throws `TomSecretsBundleException` when it does not open |
| `tomSecretsBrowserHostBeside` | `String tomSecretsBrowserHostBeside(String serviceExecutable, {required String operatingSystem})` | The browser host beside the service, where the service recognises it |
| `tomSecretsDataDirectory` | `String tomSecretsDataDirectory({Map<String, String>? environment, String? operatingSystem})` | The data directory: `TSM_DATA_DIR`, else the OS's application-data folder; throws `StateError` when its variables are not set |
| `tomSecretsBootstrapPath` | `String tomSecretsBootstrapPath({Map<String, String>? environment, String? operatingSystem})` | The default bootstrap file, `bootstrap.yaml` in the data directory |
| `tomSecretsServiceCandidates` | `List<String> tomSecretsServiceCandidates(String appDirectory, {required String operatingSystem})` | Where the app looks for the service, in order: beside itself, then the distribution's tools folder |
| `tomSecretsDistributionApp` | `String tomSecretsDistributionApp(String serviceDirectory, {required String operatingSystem})` | The app executable of the distribution around a service in `.../tsm/bin`, which the service admits as an admin |
| `tomSecretsApprovalLinkProblem` | `String? tomSecretsApprovalLinkProblem(String text, {bool anyPort = false})` | Why a text cannot be the device setting `approvalLink`, or null: `host:port` (an IPv6 address in brackets), a port 1–65535 (with `anyPort` also 0), never every interface (`0.0.0.0`, `::`) |
| `tomSecretsStartService` | `Future<TomSecretsStartResult> tomSecretsStartService({required String executable, List<String> arguments = const [], required String bootstrap, Map<String, String>? environment, Duration timeout = const Duration(seconds: 60)})` | Starts the service detached with a fresh admin key handed on its standard input; waits for its answer line |
| `tomSecretsBlockOf` | `List<String>? tomSecretsBlockOf(String text)` | The lines between the marks of a text's block, or null when it has none |
| `tomSecretsWithBlock` | `String tomSecretsWithBlock(String text, List<String>? block, {bool atTop = false})` | The text with its block's lines replaced (marks added), or the block removed when `block` is null; a new block at the top or the end, every other line kept |
