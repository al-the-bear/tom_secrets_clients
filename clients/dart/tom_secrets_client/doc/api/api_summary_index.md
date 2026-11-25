# Tom Secrets Client API Reference: Index

<!-- markdownlint-configure-file { "MD024": { "siblings_only": true } } -->

The public API of `tom_secrets_client`: the client library that reads
secrets from the local secrets service, and the admin library used by the
manager app, `tsm` and the service.

## Table of Contents

- [Quick Navigation](#quick-navigation)
- [Client Module](#client-module)
- [Admin Module](#admin-module)
- [Alphabetical Type Index](#alphabetical-type-index)
- [Alphabetical Function Index](#alphabetical-function-index)
- [Alphabetical Constant Index](#alphabetical-constant-index)

---

## Quick Navigation

| Module Reference | Module Guide | Description |
| --- | --- | --- |
| [Client](api_summary_client.md) | [README](../../README.md) | `package:tom_secrets_client/tom_secrets_client.dart`: reading secrets from the local service, references, frames, discovery |
| [Admin](api_summary_admin.md) | [README](../../README.md) | `package:tom_secrets_client/admin.dart`: admin client, runtime directory, starting the service, pairing mode, keyring, paths |

---

## Client Module

### Types

| Type | Description | Link |
| --- | --- | --- |
| `TomSecretsClient` | A client of the secrets service. | [→](api_summary_client.md#tomsecretsclient) |
| `TomSecretsWelcome` | What the service said in `welcome`. | [→](api_summary_client.md#tomsecretswelcome) |
| `TomSecretReference` | A parsed reference. | [→](api_summary_client.md#tomsecretreference) |
| `TomSecretTarget` | What a reference names: a key, a path or a uuid reference. | [→](api_summary_client.md#tomsecrettarget) |
| `TomSecretKeyTarget` | A key: the value of an entry's `tsm.key` field (`telegram.bot_token`). | [→](api_summary_client.md#tomsecretkeytarget) |
| `TomSecretPathTarget` | A path: a store, the group path below its root group and the entry title, each segment unescaped. | [→](api_summary_client.md#tomsecretpathtarget) |
| `TomSecretUuidTarget` | A uuid reference: an entry of a store by its KDBX UUID. | [→](api_summary_client.md#tomsecretuuidtarget) |
| `TomSecretBinding` | One binding `<dimension>:<value>` of a reference's qualifiers. | [→](api_summary_client.md#tomsecretbinding) |
| `TomSecretValue` | A secret. | [→](api_summary_client.md#tomsecretvalue) |
| `TomSecretEntry` | The entry a value was read from. | [→](api_summary_client.md#tomsecretentry) |
| `TomSecretVersion` | The entry's last modification and the store file revision it was read from; a caller caching a value compares it to see a change. | [→](api_summary_client.md#tomsecretversion) |
| `TomSecretFile` | What a `getFile` answers: an attachment or a typed key as bytes. | [→](api_summary_client.md#tomsecretfile) |
| `TomSecretsLoginCandidate` | A login entry `match` found for a page: never a value. | [→](api_summary_client.md#tomsecretslogincandidate) |
| `TomSecretsPasskeyCandidate` | A passkey of a page: its entry, names and credential id, never its key. | [→](api_summary_client.md#tomsecretspasskeycandidate) |
| `TomSecretsPasskeySignature` | A sign-in signed with a passkey. | [→](api_summary_client.md#tomsecretspasskeysignature) |
| `TomSecretsPasskeyCreated` | A passkey just made and kept. | [→](api_summary_client.md#tomsecretspasskeycreated) |
| `TomSecretRequest` | One reference of a `getMany`. | [→](api_summary_client.md#tomsecretrequest) |
| `TomSecretResult` | One result of a `getMany`, in request order: a value or an error. | [→](api_summary_client.md#tomsecretresult) |
| `TomSecretsProgress` | A progress notice, passed to a call's `onProgress`. | [→](api_summary_client.md#tomsecretsprogress) |
| `TomSecretsClientException` | A call that failed. | [→](api_summary_client.md#tomsecretsclientexception) |
| `TomSecretsLocation` | Where the service's endpoints are. | [→](api_summary_client.md#tomsecretslocation) |
| `TomSecretsEndpoints` | The runtime directory and its endpoint files. | [→](api_summary_client.md#tomsecretsendpoints) |
| `TomSecretsNoRuntimeDirectory` | No runtime directory can be named (Windows without `LOCALAPPDATA` and `USERPROFILE`): the service is `notRunning`. | [→](api_summary_client.md#tomsecretsnoruntimedirectory) |
| `TomSecretsFrame` | One frame read from a connection. | [→](api_summary_client.md#tomsecretsframe) |
| `TomSecretsFrameReader` | Splits a byte stream into frames, checking every length against `maxPayload` before the payload is read and refusing a frame type that is neither JSON nor (with `binaryAllowed`) binary. | [→](api_summary_client.md#tomsecretsframereader) |
| `TomSecretsFrameException` | A frame or payload that breaks the framing rules; the connection is closed. | [→](api_summary_client.md#tomsecretsframeexception) |
| `TomSecretsErrorKind` | What went wrong: the protocol's error kinds plus `notRunning`. | [→](api_summary_client.md#tomsecretserrorkind) |
| `TomSecretEncoding` | How the service sent a value. | [→](api_summary_client.md#tomsecretencoding) |
| `TomSecretSource` | Where a value came from. | [→](api_summary_client.md#tomsecretsource) |
| `TomSecretsPending` | Why a request waits. | [→](api_summary_client.md#tomsecretspending) |

### Functions

| Function | Signature | Description | Link |
| --- | --- | --- | --- |
| `discoverTomSecrets` | `TomSecretsLocation discoverTomSecrets({required String operatingSystem, required Map<String, String> environment, int? Function()? uid})` | The location of the service for an OS (`linux`, `macos`, `windows`; others as `linux`) and environment; `uid` is needed only for the `/tmp/tsm-<uid>` fallback | [→](api_summary_client.md#functions) |
| `readTomSecretsPortFile` | `int? readTomSecretsPortFile(String text)` | The port of a port file's text (decimal 1-65535, at most one trailing LF or CR LF), or null when unreadable | [→](api_summary_client.md#functions) |
| `currentUid` | `int? currentUid()` | The numeric id of the process's user (POSIX `getuid`); null on Windows | [→](api_summary_client.md#functions) |
| `tomSecretsJsonPayload` | `Uint8List tomSecretsJsonPayload(Map<String, Object?> message)` | The compact UTF-8 JSON of a message | [→](api_summary_client.md#functions) |
| `tomSecretsEncodeFrame` | `Uint8List tomSecretsEncodeFrame(int type, List<int> payload)` | A frame: payload length (4 bytes big-endian), type, payload | [→](api_summary_client.md#functions) |
| `tomSecretsJsonFrame` | `Uint8List tomSecretsJsonFrame(Map<String, Object?> message)` | The JSON frame of a message | [→](api_summary_client.md#functions) |
| `tomSecretsDecodePayload` | `Map<String, Object?> tomSecretsDecodePayload(List<int> payload)` | The message of a JSON payload; throws `TomSecretsFrameException` when it is empty, not UTF-8, BOM-prefixed, not JSON, not an object, has a duplicate member or no string `op` | [→](api_summary_client.md#functions) |

### Constants

| Constant | Type | Description | Link |
| --- | --- | --- | --- |
| `tomSecretsClientVersion` | `String` | The library's version, sent in `hello` | [→](api_summary_client.md#constants) |
| `tomSecretsProtocol` | `int` | The protocol version this library speaks (1) | [→](api_summary_client.md#constants) |
| `tomSecretsClientFeatures` | `List<String>` | The features this library takes: `binary`, `getFile`, `match`, `propose`, `passkey` | [→](api_summary_client.md#constants) |
| `tomSecretsMaxGetMany` | `int` | The most references one `getMany` carries (256) | [→](api_summary_client.md#constants) |
| `tomSecretsDefaultField` | `String` | The field a reference without `#field` names (`Password`) | [→](api_summary_client.md#constants) |
| `tomSecretsMaxReferenceBytes` | `int` | The longest reference, in bytes of UTF-8 (1024) | [→](api_summary_client.md#constants) |
| `tomSecretsFrameJson` | `int` | Frame type of a JSON payload (0) | [→](api_summary_client.md#constants) |
| `tomSecretsFrameBinary` | `int` | Frame type of a binary chunk (1) | [→](api_summary_client.md#constants) |
| `tomSecretsMaxRequestPayload` | `int` | The largest payload of a frame sent to the service (64 KiB) | [→](api_summary_client.md#constants) |
| `tomSecretsMaxAnswerPayload` | `int` | The largest payload of a frame sent by the service (1 MiB) | [→](api_summary_client.md#constants) |

---

## Admin Module

### Types

| Type | Description | Link |
| --- | --- | --- |
| `TomSecretsAdminClient` | An authenticated admin connection: requests by id and the pushed events. | [→](api_summary_admin.md#tomsecretsadminclient) |
| `TomSecretsUnlockBundle` | The OS unlock's key material of one vault: its composite key and repository key. | [→](api_summary_admin.md#tomsecretsunlockbundle) |
| `TomSecretsBundleException` | A sealed bundle did not open, or is no bundle. | [→](api_summary_admin.md#tomsecretsbundleexception) |
| `TomSecretsAdminException` | The admin endpoint refused or broke the conversation. | [→](api_summary_admin.md#tomsecretsadminexception) |
| `TomSecretsServiceTrust` | The check an admin connection runs before it sends anything: the endpoint's files are the user's alone, the process answering runs as the user and is the service expected. | [→](api_summary_admin.md#tomsecretsservicetrust) |
| `TomSecretsIdentityTrust`, `TomSecretsServicePins`, `TomSecretsPinFile`, `TomSecretsIdentityCrypto`, `TomSecretsIdentityHelper`, `TomSecretsServiceIdentity` | The service's identity key: the pins, the primitives and what a service presented. | [→](api_summary_admin.md#the-services-identity) |
| `TomSecretsEndpointFacts` | What was measured of an endpoint. | [→](api_summary_admin.md#tomsecretsendpointfacts) |
| `TomSecretsServicePeer` | The process at the other end of the admin connection. | [→](api_summary_admin.md#tomsecretsservicepeer) |
| `TomSecretsEndpointInspector` | Reads the facts of an endpoint; `TomSecretsSystemEndpointInspector` is this OS's. | [→](api_summary_admin.md#tomsecretsendpointinspector) |
| `TomSecretsAdminKeyring` | The admin keys the app and `tsm` keep in the OS keychain, one per start of the service, and the index of the starts they were kept for. | [→](api_summary_admin.md#tomsecretsadminkeyring) |
| `TomSecretsRuntime` | The runtime directory of this OS user: its check, the single-instance lock `service.lock`, `service.json` and the endpoint files. | [→](api_summary_admin.md#tomsecretsruntime) |
| `TomSecretsRuntimeException` | A runtime directory that is not the user's alone, or cannot be made. | [→](api_summary_admin.md#tomsecretsruntimeexception) |
| `TomSecretsAlreadyRunning` | Another service already holds the lock: the starter attaches to it. | [→](api_summary_admin.md#tomsecretsalreadyrunning) |
| `TomSecretsHandover` | The handover line a starting service reads from its standard input: the admin key, the bootstrap file, the starter's PID. | [→](api_summary_admin.md#tomsecretshandover) |
| `TomSecretsStartResult` | What `tomSecretsStartService` found. | [→](api_summary_admin.md#tomsecretsstartresult) |
| `TomSecretsStarted` | A new service runs with the admin key. | [→](api_summary_admin.md#tomsecretsstarted) |
| `TomSecretsAlreadyStarted` | A service was already running: attach to it, with the key held or by `claim`. | [→](api_summary_admin.md#tomsecretsalreadystarted) |
| `TomSecretsStartFailed` | The service could not start. | [→](api_summary_admin.md#tomsecretsstartfailed) |
| `TomSecretsPairingHandover` | The pairing mode's handover line: set the machine up in a data directory by receiving the pairing at an address and port, or through a GitHub relay, with the code the giving machine shows. | [→](api_summary_admin.md#tomsecretspairinghandover) |
| `TomSecretsPairingReport` | What a pairing gave, as the pairing mode reports it (no key, no token). | [→](api_summary_admin.md#tomsecretspairingreport) |
| `TomSecretsPairingModeException` | The pairing mode answered an error. | [→](api_summary_admin.md#tomsecretspairingmodeexception) |
| `TomSecretsServicePairing` | A conversation with the service in its pairing mode, as `tsm pair` drives it: the service executable runs attached and talks in JSON lines. | [→](api_summary_admin.md#tomsecretsservicepairing) |
| `TomSecretsTransport` | How the endpoints are offered. | [→](api_summary_admin.md#tomsecretstransport) |
| `TomSecretsIntegration` | A developer tool the product configures: `ssh`, `git`. | [→](api_summary_admin.md#tomsecretsintegration) |
| `TomSecretsIntegrationState` | The state of one developer-tool integration. | [→](api_summary_admin.md#tomsecretsintegrationstate) |
| `TomSecretsIntegrations` | The integrations of one user on this machine, in marked blocks of the tools' files. | [→](api_summary_admin.md#tomsecretsintegrations) |

### Functions

| Function | Signature | Description | Link |
| --- | --- | --- | --- |
| `tomSecretsChallengeInput` | `Uint8List tomSecretsChallengeInput(String label, List<int> serviceNonce, List<int> adminNonce, int serviceStart)` | The MAC input: the label's ASCII, both 32-byte nonces, the service start as 8 bytes big-endian | [→](api_summary_admin.md#functions) |
| `tomSecretsChallengeMac` | `Uint8List tomSecretsChallengeMac(List<int> adminKey, String label, List<int> serviceNonce, List<int> adminNonce, int serviceStart)` | HMAC-SHA256 of the challenge input under the admin key | [→](api_summary_admin.md#functions) |
| `tomSecretsConstantTimeEquals` | `bool tomSecretsConstantTimeEquals(List<int> a, List<int> b)` | Equality in time independent of where the lists differ | [→](api_summary_admin.md#functions) |
| `tomSecretsRandomBytes` | `Uint8List tomSecretsRandomBytes([int count = tomSecretsKeyBytes])` | Bytes from the OS's secure generator | [→](api_summary_admin.md#functions) |
| `tomSecretsAuthDelay` | `Duration tomSecretsAuthDelay(int failures)` | The delay before the next authentication: 0, then 1 s, 2 s, 4 s, ... up to 60 s | [→](api_summary_admin.md#functions) |
| `tomSecretsAdminKeyHandle` | `String tomSecretsAdminKeyHandle(int serviceStart)` | The keychain handle of the admin key of a service start, `tsm.admin.<start>` | [→](api_summary_admin.md#functions) |
| `tomSecretsBundleKey` | `Uint8List tomSecretsBundleKey(List<int> adminKey, List<int> serviceNonce, List<int> adminNonce)` | The bundle key of one admin connection (HKDF-SHA256) | [→](api_summary_admin.md#functions) |
| `tomSecretsSealBundle` | `Future<Map<String, String>> tomSecretsSealBundle({...})` | Seals the OS unlock's key bundle (AES-256-GCM) | [→](api_summary_admin.md#functions) |
| `tomSecretsOpenBundle` | `Future<Uint8List> tomSecretsOpenBundle({...})` | Opens a sealed key bundle | [→](api_summary_admin.md#functions) |
| `tomSecretsDataDirectory` | `String tomSecretsDataDirectory({Map<String, String>? environment, String? operatingSystem})` | The data directory: `TSM_DATA_DIR`, else the OS's application-data folder; throws `StateError` when its variables are not set | [→](api_summary_admin.md#functions) |
| `tomSecretsBootstrapPath` | `String tomSecretsBootstrapPath({Map<String, String>? environment, String? operatingSystem})` | The default bootstrap file, `bootstrap.yaml` in the data directory | [→](api_summary_admin.md#functions) |
| `tomSecretsPrepareDataDirectory` | `Future<TomSecretsDataDirectoryState> tomSecretsPrepareDataDirectory(String path)` | Makes the data directory the user's alone (0700, files 0600; Windows the user-only ACL), tightening a looser one | [→](api_summary_admin.md#functions) |
| `tomSecretsServiceCandidates` | `List<String> tomSecretsServiceCandidates(String appDirectory, {required String operatingSystem})` | Where the app looks for the service, in order: beside itself, then the distribution's tools folder | [→](api_summary_admin.md#functions) |
| `tomSecretsDistributionApp` | `String tomSecretsDistributionApp(String serviceDirectory, {required String operatingSystem})` | The app executable of the distribution around a service in `.../tsm/bin`, which the service admits as an admin | [→](api_summary_admin.md#functions) |
| `tomSecretsStartService` | `Future<TomSecretsStartResult> tomSecretsStartService({required String executable, List<String> arguments = const [], required String bootstrap, Map<String, String>? environment, Duration timeout = const Duration(seconds: 60)})` | Starts the service detached with a fresh admin key handed on its standard input; waits for its answer line | [→](api_summary_admin.md#functions) |
| `tomSecretsBlockOf` | `List<String>? tomSecretsBlockOf(String text)` | The lines between the marks of a text's block, or null when it has none | [→](api_summary_admin.md#functions) |
| `tomSecretsWithBlock` | `String tomSecretsWithBlock(String text, List<String>? block, {bool atTop = false})` | The text with its block's lines replaced (marks added), or the block removed when `block` is null; a new block at the top or the end, every other line kept | [→](api_summary_admin.md#functions) |

### Constants

| Constant | Type | Description | Link |
| --- | --- | --- | --- |
| `tomSecretsAdminLabel` | `String` | The admin's challenge label, `tsm-admin-v1` | [→](api_summary_admin.md#constants) |
| `tomSecretsServiceLabel` | `String` | The service's challenge label, `tsm-service-v1` | [→](api_summary_admin.md#constants) |
| `tomSecretsKeyBytes` | `int` | The length of an admin key and of a nonce (32) | [→](api_summary_admin.md#constants) |
| `tomSecretsAdminKeyIndexHandle` | `String` | The keychain handle of the index of kept starts, `tsm.admin.index` | [→](api_summary_admin.md#constants) |
| `tomSecretsKeychainService` | `String` | The service name of the product's items in the OS keychain, `tom-secrets-manager` | [→](api_summary_admin.md#constants) |
| `tomSecretsToolsFolder` | `String` | The folder of the distribution holding the command-line tools, `tsm` | [→](api_summary_admin.md#constants) |
| `tomSecretsAppExecutable` | `String` | The manager app's executable name without `.exe`, `tom_secrets_app` | [→](api_summary_admin.md#constants) |
| `tomSecretsServiceExecutable` | `String` | The service's executable name without `.exe`, `tom_secrets_service` | [→](api_summary_admin.md#constants) |
| `tomSecretsPairingWrongPassword` | `String` | The code of a wrong master password, `wrong_password` | [→](api_summary_admin.md#constants) |
| `tomSecretsPairingPasswordTries` | `int` | How many master passwords the pairing mode takes (3) | [→](api_summary_admin.md#constants) |
| `tomSecretsBlockBegin` | `String` | The first line of a block the product writes, `# >>> tom secrets >>>` | [→](api_summary_admin.md#constants) |
| `tomSecretsGitHelperName` | `String` | The name git runs the helper under | [→](api_summary_admin.md#constants) |
| `tomSecretsDockerHelperName` | `String` | The name Docker runs the helper under | [→](api_summary_admin.md#constants) |
| `tomSecretsBlockEnd` | `String` | The last line of a block the product writes, `# <<< tom secrets <<<` | [→](api_summary_admin.md#constants) |
| `tomSecretsBundleInfo` | `String` | The HKDF info of the bundle key, `tsm-bundle-v1` | [→](api_summary_admin.md#constants) |
| `tomSecretsBundleNonceBytes` | `int` | The length of a sealed bundle's nonce (12) | [→](api_summary_admin.md#constants) |
| `tomSecretsCompositeKeyBytes` | `int` | The length of a composite key (32) | [→](api_summary_admin.md#constants) |

---

## Alphabetical Type Index

| Type | Module | Link |
| `TomSecretsIntegration` | Admin | [→](api_summary_admin.md#tomsecretsintegration) |
| `TomSecretsIntegrations` | Admin | [→](api_summary_admin.md#tomsecretsintegrations) |
| `TomSecretsIntegrationState` | Admin | [→](api_summary_admin.md#tomsecretsintegrationstate) |
| --- | --- | --- |
| `TomSecretBinding` | Client | [→](api_summary_client.md#tomsecretbinding) |
| `TomSecretEncoding` | Client | [→](api_summary_client.md#tomsecretencoding) |
| `TomSecretEntry` | Client | [→](api_summary_client.md#tomsecretentry) |
| `TomSecretFile` | Client | [→](api_summary_client.md#tomsecretfile) |
| `TomSecretKeyTarget` | Client | [→](api_summary_client.md#tomsecretkeytarget) |
| `TomSecretPathTarget` | Client | [→](api_summary_client.md#tomsecretpathtarget) |
| `TomSecretReference` | Client | [→](api_summary_client.md#tomsecretreference) |
| `TomSecretRequest` | Client | [→](api_summary_client.md#tomsecretrequest) |
| `TomSecretResult` | Client | [→](api_summary_client.md#tomsecretresult) |
| `TomSecretsAdminClient` | Admin | [→](api_summary_admin.md#tomsecretsadminclient) |
| `TomSecretsUnlockBundle` | Admin | [→](api_summary_admin.md#tomsecretsunlockbundle) |
| `TomSecretsBundleException` | Admin | [→](api_summary_admin.md#tomsecretsbundleexception) |
| `TomSecretsAdminException` | Admin | [→](api_summary_admin.md#tomsecretsadminexception) |
| `TomSecretsAdminKeyring` | Admin | [→](api_summary_admin.md#tomsecretsadminkeyring) |
| `TomSecretsAlreadyRunning` | Admin | [→](api_summary_admin.md#tomsecretsalreadyrunning) |
| `TomSecretsAlreadyStarted` | Admin | [→](api_summary_admin.md#tomsecretsalreadystarted) |
| `TomSecretsClient` | Client | [→](api_summary_client.md#tomsecretsclient) |
| `TomSecretsClientException` | Client | [→](api_summary_client.md#tomsecretsclientexception) |
| `TomSecretsEndpoints` | Client | [→](api_summary_client.md#tomsecretsendpoints) |
| `TomSecretsErrorKind` | Client | [→](api_summary_client.md#tomsecretserrorkind) |
| `TomSecretsFrame` | Client | [→](api_summary_client.md#tomsecretsframe) |
| `TomSecretsFrameException` | Client | [→](api_summary_client.md#tomsecretsframeexception) |
| `TomSecretsFrameReader` | Client | [→](api_summary_client.md#tomsecretsframereader) |
| `TomSecretsHandover` | Admin | [→](api_summary_admin.md#tomsecretshandover) |
| `TomSecretsLocation` | Client | [→](api_summary_client.md#tomsecretslocation) |
| `TomSecretsNoRuntimeDirectory` | Client | [→](api_summary_client.md#tomsecretsnoruntimedirectory) |
| `TomSecretSource` | Client | [→](api_summary_client.md#tomsecretsource) |
| `TomSecretsPairingHandover` | Admin | [→](api_summary_admin.md#tomsecretspairinghandover) |
| `TomSecretsPairingModeException` | Admin | [→](api_summary_admin.md#tomsecretspairingmodeexception) |
| `TomSecretsPairingReport` | Admin | [→](api_summary_admin.md#tomsecretspairingreport) |
| `TomSecretsPending` | Client | [→](api_summary_client.md#tomsecretspending) |
| `TomSecretsProgress` | Client | [→](api_summary_client.md#tomsecretsprogress) |
| `TomSecretsRuntime` | Admin | [→](api_summary_admin.md#tomsecretsruntime) |
| `TomSecretsRuntimeException` | Admin | [→](api_summary_admin.md#tomsecretsruntimeexception) |
| `TomSecretsServicePairing` | Admin | [→](api_summary_admin.md#tomsecretsservicepairing) |
| `TomSecretsStarted` | Admin | [→](api_summary_admin.md#tomsecretsstarted) |
| `TomSecretsStartFailed` | Admin | [→](api_summary_admin.md#tomsecretsstartfailed) |
| `TomSecretsStartResult` | Admin | [→](api_summary_admin.md#tomsecretsstartresult) |
| `TomSecretsTransport` | Admin | [→](api_summary_admin.md#tomsecretstransport) |
| `TomSecretsWelcome` | Client | [→](api_summary_client.md#tomsecretswelcome) |
| `TomSecretTarget` | Client | [→](api_summary_client.md#tomsecrettarget) |
| `TomSecretUuidTarget` | Client | [→](api_summary_client.md#tomsecretuuidtarget) |
| `TomSecretValue` | Client | [→](api_summary_client.md#tomsecretvalue) |
| `TomSecretVersion` | Client | [→](api_summary_client.md#tomsecretversion) |

---

## Alphabetical Function Index

| Function | Module | Link |
| `tomSecretsBlockOf` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsWithBlock` | Admin | [→](api_summary_admin.md#functions) |
| --- | --- | --- |
| `currentUid` | Client | [→](api_summary_client.md#functions) |
| `discoverTomSecrets` | Client | [→](api_summary_client.md#functions) |
| `readTomSecretsPortFile` | Client | [→](api_summary_client.md#functions) |
| `tomSecretsAdminKeyHandle` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsAuthDelay` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsBootstrapPath` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsPrepareDataDirectory` | Admin | [→](api_summary_admin.md#functions) |
| `TomSecretsDataDirectoryState` | Admin | [→](api_summary_admin.md#tomsecretsdatadirectorystate) |
| `TomSecretsDataDirectoryException` | Admin | [→](api_summary_admin.md#tomsecretsdatadirectoryexception) |
| `tomSecretsChallengeInput` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsChallengeMac` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsConstantTimeEquals` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsDataDirectory` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsDecodePayload` | Client | [→](api_summary_client.md#functions) |
| `tomSecretsDistributionApp` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsEncodeFrame` | Client | [→](api_summary_client.md#functions) |
| `tomSecretsJsonFrame` | Client | [→](api_summary_client.md#functions) |
| `tomSecretsJsonPayload` | Client | [→](api_summary_client.md#functions) |
| `tomSecretsRandomBytes` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsServiceCandidates` | Admin | [→](api_summary_admin.md#functions) |
| `tomSecretsStartService` | Admin | [→](api_summary_admin.md#functions) |

---

## Alphabetical Constant Index

| Constant | Module | Link |
| `tomSecretsBlockBegin` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsBlockEnd` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsBundleInfo` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsBundleNonceBytes` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsCompositeKeyBytes` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsDockerHelperName` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsGitHelperName` | Admin | [→](api_summary_admin.md#constants) |
| --- | --- | --- |
| `tomSecretsAdminKeyIndexHandle` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsAdminLabel` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsAppExecutable` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsClientFeatures` | Client | [→](api_summary_client.md#constants) |
| `tomSecretsClientVersion` | Client | [→](api_summary_client.md#constants) |
| `tomSecretsDefaultField` | Client | [→](api_summary_client.md#constants) |
| `tomSecretsFrameBinary` | Client | [→](api_summary_client.md#constants) |
| `tomSecretsFrameJson` | Client | [→](api_summary_client.md#constants) |
| `tomSecretsKeyBytes` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsKeychainService` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsMaxAnswerPayload` | Client | [→](api_summary_client.md#constants) |
| `tomSecretsMaxGetMany` | Client | [→](api_summary_client.md#constants) |
| `tomSecretsMaxReferenceBytes` | Client | [→](api_summary_client.md#constants) |
| `tomSecretsMaxRequestPayload` | Client | [→](api_summary_client.md#constants) |
| `tomSecretsPairingPasswordTries` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsPairingWrongPassword` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsProtocol` | Client | [→](api_summary_client.md#constants) |
| `tomSecretsServiceExecutable` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsServiceLabel` | Admin | [→](api_summary_admin.md#constants) |
| `tomSecretsToolsFolder` | Admin | [→](api_summary_admin.md#constants) |
