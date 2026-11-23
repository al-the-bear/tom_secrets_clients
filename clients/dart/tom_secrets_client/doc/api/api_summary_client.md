# Tom Secrets Client API Reference: Client Module

<!-- markdownlint-configure-file { "MD024": { "siblings_only": true } } -->

## Table of Contents

- [Overview](#overview)
- [Class Hierarchy](#class-hierarchy)
- [Classes](#classes)
  - [TomSecretsClient](#tomsecretsclient)
  - [TomSecretsWelcome](#tomsecretswelcome)
  - [TomSecretReference](#tomsecretreference)
  - [TomSecretTarget](#tomsecrettarget)
  - [TomSecretKeyTarget](#tomsecretkeytarget)
  - [TomSecretPathTarget](#tomsecretpathtarget)
  - [TomSecretUuidTarget](#tomsecretuuidtarget)
  - [TomSecretBinding](#tomsecretbinding)
  - [TomSecretValue](#tomsecretvalue)
  - [TomSecretEntry](#tomsecretentry)
  - [TomSecretVersion](#tomsecretversion)
  - [TomSecretFile](#tomsecretfile)
  - [TomSecretsLoginCandidate](#tomsecretslogincandidate)
  - [TomSecretsPasskeyCandidate](#tomsecretspasskeycandidate)
  - [TomSecretsPasskeyAssertion](#tomsecretspasskeyassertion)
  - [TomSecretsPasskeyCreated](#tomsecretspasskeycreated)
  - [TomSecretRequest](#tomsecretrequest)
  - [TomSecretResult](#tomsecretresult)
  - [TomSecretsProgress](#tomsecretsprogress)
  - [TomSecretsClientException](#tomsecretsclientexception)
  - [TomSecretsLocation](#tomsecretslocation)
  - [TomSecretsEndpoints](#tomsecretsendpoints)
  - [TomSecretsNoRuntimeDirectory](#tomsecretsnoruntimedirectory)
  - [TomSecretsFrame](#tomsecretsframe)
  - [TomSecretsFrameReader](#tomsecretsframereader)
  - [TomSecretsFrameException](#tomsecretsframeexception)
- [Enums](#enums)
  - [TomSecretsErrorKind](#tomsecretserrorkind)
  - [TomSecretEncoding](#tomsecretencoding)
  - [TomSecretSource](#tomsecretsource)
  - [TomSecretsPending](#tomsecretspending)
- [Typedefs](#typedefs)
- [Global Functions and Constants](#global-functions-and-constants)

---

## Overview

The client module is `package:tom_secrets_client/tom_secrets_client.dart`:
what a program imports to read secrets from the local secrets service. It
finds the service (`discoverTomSecrets`), speaks the client endpoint of the
protocol over length-prefixed frames, reads secrets with `get`, `getMany`
and `getFile`, and parses and formats secret references. Every failure is a
`TomSecretsClientException` with a `TomSecretsErrorKind`.

---

## Class Hierarchy

```text
Object
├── TomSecretsClient
├── TomSecretsWelcome
├── TomSecretReference
├── TomSecretTarget (sealed)
│   ├── TomSecretKeyTarget
│   ├── TomSecretPathTarget
│   └── TomSecretUuidTarget
├── TomSecretBinding
├── TomSecretValue
├── TomSecretEntry
├── TomSecretVersion
├── TomSecretFile
├── TomSecretsLoginCandidate
├── TomSecretsPasskeyCandidate
├── TomSecretsPasskeyAssertion
├── TomSecretsPasskeyCreated
├── TomSecretRequest
├── TomSecretResult
├── TomSecretsProgress
├── TomSecretsLocation (sealed)
│   ├── TomSecretsEndpoints
│   └── TomSecretsNoRuntimeDirectory
├── TomSecretsFrame
├── TomSecretsFrameReader
└── (implements Exception)
    ├── TomSecretsClientException
    └── TomSecretsFrameException
```

---

## Classes

### TomSecretsClient

A client of the secrets service. One connection, opened by the first call
(or `open`); after `notRunning` or a dropped connection the next call
connects again. Calls may overlap on the connection. The library logs
nothing.

#### Constructors

```dart
TomSecretsClient({
  String? clientName,
  String? clientToken,
  Map<String, String>? environment,
  String? operatingSystem,
  Duration connectTimeout = const Duration(seconds: 10),
})
```

- `clientName`: shown in approval prompts, never trusted; default the
  executable's name.
- `clientToken`: a client token the program was given before, sent in
  every `hello`.
- `environment`, `operatingSystem`: where the service is looked for
  (default the process's).

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `shared` | `TomSecretsClient` | The process's shared client, created on first use with the defaults |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `connect({String? clientName, String? clientToken, Map<String, String>? environment, String? operatingSystem, Duration connectTimeout})` | `Future<TomSecretsClient>` | Creates a client and connects it, so a missing service shows at once (`notRunning`) |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `clientName` | `String` | The name `hello` gives the program |
| `clientToken` | `String?` | The client token sent in every `hello` |
| `connectTimeout` | `Duration` | How long connecting and the `welcome` may take |
| `welcome` | `TomSecretsWelcome?` | The `welcome` of the current connection, or null when not connected |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `open()` | `Future<void>` | Connects, unless a connection is open |
| `close()` | `Future<void>` | Closes the connection; a later call connects again |
| `get(String reference, {String? field, Map<String, String>? dimensions, bool wait = true, Duration? timeout, bool wantClientToken = false, TomSecretsProgressCallback? onProgress, bool waitOnRateLimit = false})` | `Future<TomSecretValue>` | Reads one secret; the reference is parsed locally first; `timeout` is sent as `timeoutMs`; `wantClientToken` asks for a client token with an "always" approval; `waitOnRateLimit` waits out `rateLimited` and sends again |
| `getMany(List<TomSecretRequest> requests, {bool wait = true, Duration? timeout, TomSecretsProgressCallback? onProgress, bool waitOnRateLimit = false})` | `Future<List<TomSecretResult>>` | Reads 1 to 256 secrets under one approval prompt; results in request order; an empty or too long list is an `ArgumentError` |
| `getFile(String reference, {String? field, Map<String, String>? dimensions, bool wait = true, Duration? timeout, TomSecretsProgressCallback? onProgress})` | `Future<TomSecretFile>` | Reads an attachment or a typed key as bytes over binary frames, checked against its SHA-256; `unsupported` when the service lacks the features `binary` and `getFile` |
| `match(String url, {String? frameUrl, bool wait = true, Duration? timeout})` | `Future<List<TomSecretsLoginCandidate>>` | The login entries of a web page this client's grants cover, never a value (protocol.md 5.5); only for the browser host and the helpers (`denied`, `not_allowed_op` otherwise); `unsupported` when the service lacks the feature `match` |
| `propose({required String url, required String userName, required String password, String? title})` | `Future<void>` | A login for the user to save in the manager app (protocol.md 5.5); only for the browser host with a grant; `unavailable` (`no_app`) with no app attached; `unsupported` when the service lacks the feature `propose` |
| `passkeys(String url, String rpId, {List<String>? allowCredentials, bool wait = true, Duration? timeout, TomSecretsProgressCallback? onProgress})` | `Future<List<TomSecretsPasskeyCandidate>>` | **[C]** The passkeys of `rpId` for the page `url` this client may use, by name and credential id, never a key (protocol.md 5.8); the browser host only (`denied`, `not_allowed_op` otherwise), a relying party the page may not use `denied` (`rp_id`); `unsupported` when the service lacks the feature `passkey` |
| `passkeyGet({required String url, required String rpId, required String entryId, required List<int> clientDataHash})` | `Future<TomSecretsPasskeyAssertion>` | **[C]** A sign-in signed by the service with the passkey `entryId` the user picked; `denied` (`not_matched`) for one that is no passkey of the page |
| `passkeyCreate({required String url, required String rpId, required List<int> userId, required String userName, String? displayName, required List<int> algorithms, List<String>? excludeCredentials, Duration? timeout, TomSecretsProgressCallback? onProgress})` | `Future<TomSecretsPasskeyCreated>` | **[C]** A new passkey once the user confirms it in the app, ES256 or Ed25519 by the site's order, kept in a vault before it answers; `denied` (`excluded`, `refused`, `timeout`, `no_approver`), `unsupported` (`algorithm`), `unavailable` (no vault written) |

---

### TomSecretsWelcome

What the service said in `welcome`.

#### Constructors

```dart
const TomSecretsWelcome({
  required int protocol,
  required String serviceVersion,
  required Set<String> features,
  required String host,
  required String platform,
})
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `protocol` | `int` | The protocol version spoken on this connection |
| `serviceVersion` | `String` | The service's version |
| `features` | `Set<String>` | The optional features the service offers |
| `host` | `String` | The service's host name (the current value of the `host` dimension) |
| `platform` | `String` | `macos`, `linux`, `windows`, `ios` or `android` |

---

### TomSecretReference

A parsed reference. `parse` refuses a malformed one with a
`TomSecretsClientException` of kind `malformed` whose `reason` names the
broken rule; `format` gives the canonical form.

#### Constructors

```dart
TomSecretReference({
  List<TomSecretBinding> qualifiers = const [],
  required TomSecretTarget target,
  String field = tomSecretsDefaultField,
  bool fieldGiven = false,
})
```

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `parse(String reference)` | `TomSecretReference` | Parses a reference; throws `malformed` with a `reason` (`empty`, `too_long`, `unclosed_qualifiers`, `bad_binding`, `bad_dimension`, `duplicate_dimension`, `empty_target`, `empty_segment`, `bad_key`, `bad_store`, `bad_uuid`, `reserved_prefix`, `reserved_character`, `control_character`, `bad_escape`, `bad_utf8`) |
| `format(TomSecretReference reference)` | `String` | The canonical text: bindings sorted by dimension name, segments escaped exactly as needed, the uuid in lower case, the field omitted when it is `Password` |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `qualifiers` | `List<TomSecretBinding>` | The bindings in the order written |
| `target` | `TomSecretTarget` | What the reference names |
| `field` | `String` | The effective field: the one written, else `Password` |
| `fieldGiven` | `bool` | Whether the reference wrote `#field` |
| `canonical` | `String` | The canonical form (`format`) |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toString()` | `String` | The canonical form |

#### Operators

| Operator | Return Type | Description |
| --- | --- | --- |
| `operator ==(Object other)` | `bool` | Equal qualifiers, target, field and `fieldGiven` |

---

### TomSecretTarget

What a reference names: a key, a path or a uuid reference. Sealed; the
subclasses below are the only ones.

---

### TomSecretKeyTarget

A key: the value of an entry's `tsm.key` field (`telegram.bot_token`).

**Extends:** `TomSecretTarget`

#### Constructors

```dart
const TomSecretKeyTarget(String key)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `key` | `String` | The dotted key |

#### Operators

| Operator | Return Type | Description |
| --- | --- | --- |
| `operator ==(Object other)` | `bool` | Equal keys |

---

### TomSecretPathTarget

A path: a store, the group path below its root group and the entry title,
each segment unescaped.

**Extends:** `TomSecretTarget`

#### Constructors

```dart
TomSecretPathTarget(String store, List<String> segments)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `store` | `String` | The store name |
| `segments` | `List<String>` | The groups below the root group, then the entry title, unescaped |

#### Operators

| Operator | Return Type | Description |
| --- | --- | --- |
| `operator ==(Object other)` | `bool` | Equal store and segments |

---

### TomSecretUuidTarget

A uuid reference: an entry of a store by its KDBX UUID.

**Extends:** `TomSecretTarget`

#### Constructors

```dart
const TomSecretUuidTarget(String store, String uuid)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `store` | `String` | The store name |
| `uuid` | `String` | 32 lower-case hex digits |

#### Operators

| Operator | Return Type | Description |
| --- | --- | --- |
| `operator ==(Object other)` | `bool` | Equal store and uuid |

---

### TomSecretBinding

One binding `<dimension>:<value>` of a reference's qualifiers.

#### Constructors

```dart
const TomSecretBinding(String dimension, String value)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `dimension` | `String` | The dimension name |
| `value` | `String` | Its value, unescaped |

#### Operators

| Operator | Return Type | Description |
| --- | --- | --- |
| `operator ==(Object other)` | `bool` | Equal dimension and value |

---

### TomSecretValue

A secret. Its `toString` never shows it, and `dispose` overwrites its
buffer. A `text` taken out is an immutable Dart string the library cannot
overwrite.

#### Factory Constructors

```dart
factory TomSecretValue.fromMessage(String reference, Map<String, Object?> m)
```

The value of a `value` message (or a `values` result); a message it cannot
read is `internal`.

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `reference` | `String` | The reference the value was asked for, as given |
| `encoding` | `TomSecretEncoding` | How the service sent it |
| `entry` | `TomSecretEntry` | The entry it was read from |
| `bound` | `Map<String, String>` | The bindings the winning entry carries |
| `version` | `TomSecretVersion` | The entry's version |
| `expires` | `DateTime?` | The entry's expiry, when it has one |
| `clientToken` | `String?` | The client token the service granted; the caller's to keep |
| `isDisposed` | `bool` | Whether `dispose` was called |
| `text` | `String` | The value as text; a binary value is refused with a `StateError` |
| `bytes` | `Uint8List` | The value as bytes: a view of the buffer `dispose` overwrites |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `dispose()` | `void` | Overwrites the buffer with zeros; the value cannot be read afterwards |
| `toString()` | `String` | `TomSecretValue(<reference>: ***)` |

---

### TomSecretEntry

The entry a value was read from.

#### Constructors

```dart
const TomSecretEntry({
  required String store,
  required String uuid,
  required TomSecretSource source,
  required DateTime fetchedAt,
})
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `store` | `String` | The store holding it |
| `uuid` | `String` | Its KDBX UUID |
| `source` | `TomSecretSource` | Where the service read it from |
| `fetchedAt` | `DateTime` | The last successful fetch of the store |

---

### TomSecretVersion

The entry's last modification and the store file revision it was read
from; a caller caching a value compares it to see a change.

#### Constructors

```dart
const TomSecretVersion({required DateTime modified, required String revision})
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `modified` | `DateTime` | The entry's last modification |
| `revision` | `String` | The store file revision it was read from |

#### Operators

| Operator | Return Type | Description |
| --- | --- | --- |
| `operator ==(Object other)` | `bool` | Equal modification time and revision |

---

### TomSecretsLoginCandidate

A login entry `match` found for a page: never a value.

#### Constructors

```dart
const TomSecretsLoginCandidate({required String entryId, required String title, required String userName, required String matchedUrl, required bool hasTotp})
factory TomSecretsLoginCandidate.fromJson(Map<String, Object?> json)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `entryId` | `String` | The entry as a uuid reference (`store/~<32 hex>`): what a fill reads with `get` |
| `title` | `String` | The entry's title |
| `userName` | `String` | Its user name |
| `matchedUrl` | `String` | The entry URL that matched, as written |
| `hasTotp` | `bool` | Whether it carries a TOTP secret |

---

### TomSecretsPasskeyCandidate

**[C]** A passkey of a page (`passkeyCandidates`): its entry, names and credential id; never its key.

#### Constructors

```dart
const TomSecretsPasskeyCandidate({required String entryId, required String title, required String userName, required String credentialId})
factory TomSecretsPasskeyCandidate.fromJson(Map<String, Object?> json)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `entryId` | `String` | The entry as a uuid reference (`store/~<32 hex>`): what `passkeyGet` names |
| `title` | `String` | The entry's title |
| `userName` | `String` | The passkey's user name |
| `credentialId` | `String` | The credential id (base64url, no padding) |

---

### TomSecretsPasskeyAssertion

**[C]** A sign-in signed with a passkey (`passkeyAssertion`); every byte value base64url without padding.

#### Constructors

```dart
const TomSecretsPasskeyAssertion({required String credentialId, required String authenticatorData, required String signature, String? userHandle})
factory TomSecretsPasskeyAssertion.fromJson(Map<String, Object?> json)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `credentialId` | `String` | The credential id |
| `authenticatorData` | `String` | The authenticator data |
| `signature` | `String` | The signature over the authenticator data and the client data hash |
| `userHandle` | `String?` | The user handle, when the passkey has one |

---

### TomSecretsPasskeyCreated

**[C]** A passkey just made and kept (`passkeyCreated`); every byte value base64url without padding.

#### Constructors

```dart
const TomSecretsPasskeyCreated({required String credentialId, required String authenticatorData, required String attestationObject, required String publicKey, required int publicKeyAlgorithm})
factory TomSecretsPasskeyCreated.fromJson(Map<String, Object?> json)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `credentialId` | `String` | The credential id |
| `authenticatorData` | `String` | The authenticator data with the attested credential |
| `attestationObject` | `String` | The `none` attestation object |
| `publicKey` | `String` | The public key as DER SubjectPublicKeyInfo |
| `publicKeyAlgorithm` | `int` | Its COSE algorithm (`-7` ES256, `-8` Ed25519) |

---

### TomSecretFile

What a `getFile` answers: an attachment or a typed key as bytes.

#### Constructors

```dart
TomSecretFile(String reference, String name, Uint8List bytes)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `reference` | `String` | The reference it was asked for |
| `name` | `String` | The attachment's name |
| `size` | `int` | Its size in bytes |
| `bytes` | `Uint8List` | A view of the buffer `dispose` overwrites |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `dispose()` | `void` | Overwrites the buffer with zeros |
| `toString()` | `String` | `TomSecretFile(<reference>, <name>: ***)` |

---

### TomSecretRequest

One reference of a `getMany`.

#### Constructors

```dart
const TomSecretRequest(
  String reference, {
  String? field,
  Map<String, String>? dimensions,
})
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `reference` | `String` | The reference |
| `field` | `String?` | The field, when the reference names none |
| `dimensions` | `Map<String, String>?` | Values for dimensions, beside the reference |

---

### TomSecretResult

One result of a `getMany`, in request order: a value or an error.

#### Constructors

```dart
const TomSecretResult.value(TomSecretValue value)
const TomSecretResult.error(TomSecretsClientException error)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `value` | `TomSecretValue?` | The value, or null |
| `error` | `TomSecretsClientException?` | The error, or null |

---

### TomSecretsProgress

A progress notice, passed to a call's `onProgress`.

#### Constructors

```dart
const TomSecretsProgress(TomSecretsPending pending, {String? approvalCode})
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `pending` | `TomSecretsPending` | Why the request waits |
| `approvalCode` | `String?` | The one-time approval code, on a host with no approver connected |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toString()` | `String` | `TomSecretsProgress(<pending>[, <code>])` |

---

### TomSecretsClientException

A call that failed. Never carries a value or a token.

**Implements:** `Exception`

#### Constructors

```dart
TomSecretsClientException(
  TomSecretsErrorKind kind,
  String message, {
  Map<String, Object?>? details,
})
```

#### Factory Constructors

```dart
factory TomSecretsClientException.fromError(Map<String, Object?> error)
```

The exception of a protocol `error` message (or a `values` result).

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `kind` | `TomSecretsErrorKind` | What went wrong |
| `message` | `String` | For people; never a value, a token or a key |
| `details` | `Map<String, Object?>` | `reason`, `candidates`, `retryAfterMs`, `dimensions`, ... |
| `reason` | `String?` | `details['reason']`, when there is one |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toString()` | `String` | `TomSecretsClientException(<kind>[, <reason>]): <message>` |

---

### TomSecretsLocation

Where the service's endpoints are. Sealed: `TomSecretsEndpoints` or
`TomSecretsNoRuntimeDirectory`.

---

### TomSecretsEndpoints

The runtime directory and its endpoint files.

**Extends:** `TomSecretsLocation`

#### Constructors

```dart
const TomSecretsEndpoints({
  required String directory,
  String? clientSocket,
  String? adminSocket,
  String? clientPortFile,
  String? clientTokenFile,
  String? adminPortFile,
})
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `directory` | `String` | The runtime directory |
| `clientSocket` | `String?` | Linux and macOS: the client endpoint's Unix domain socket |
| `adminSocket` | `String?` | Linux and macOS: the admin endpoint's Unix domain socket |
| `clientPortFile` | `String?` | Windows: the client endpoint's port file |
| `clientTokenFile` | `String?` | Windows: the client token of this service start |
| `adminPortFile` | `String?` | Windows: the admin endpoint's port file |

---

### TomSecretsNoRuntimeDirectory

No runtime directory can be named (Windows without `LOCALAPPDATA` and
`USERPROFILE`): the service is `notRunning`.

**Extends:** `TomSecretsLocation`

#### Constructors

```dart
const TomSecretsNoRuntimeDirectory(String reason)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `reason` | `String` | `no_runtime_directory` |

---

### TomSecretsFrame

One frame read from a connection.

#### Constructors

```dart
TomSecretsFrame(int type, Uint8List payload)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `type` | `int` | `tomSecretsFrameJson` or `tomSecretsFrameBinary` |
| `payload` | `Uint8List` | The payload bytes |

---

### TomSecretsFrameReader

Splits a byte stream into frames, checking every length against
`maxPayload` before the payload is read and refusing a frame type that is
neither JSON nor (with `binaryAllowed`) binary.

#### Constructors

```dart
TomSecretsFrameReader({required int maxPayload})
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `maxPayload` | `int` | The largest payload accepted |
| `binaryAllowed` | `bool` | Whether binary frames were negotiated (both sides named `binary`); settable |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `add(List<int> bytes)` | `List<TomSecretsFrame>` | Adds bytes and returns the frames now complete; throws `TomSecretsFrameException` on an oversized length or a bad type |

---

### TomSecretsFrameException

A frame or payload that breaks the framing rules; the connection is closed.

**Implements:** `Exception`

#### Constructors

```dart
TomSecretsFrameException(String message)
```

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What broke the framing rules |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toString()` | `String` | `TomSecretsFrameException: <message>` |

---

## Enums

### TomSecretsErrorKind

What went wrong: the protocol's error kinds plus `notRunning`.

#### Values

| Value | Description |
| --- | --- |
| `locked` | The service is locked and no unlock came in time, or `wait` was false |
| `denied` | The client may not have this, or the connection was refused |
| `notFound` | No candidate, or the winning entry lacks the field |
| `ambiguous` | Several candidates rank equal (`details['candidates']`) |
| `needsUnlock` | The store holding the answer could not be reopened since its key changed |
| `unavailable` | The store could not be fetched and has no offline copy |
| `offline` | Admin only: a fetch failed for a network reason |
| `tokenExpired` | Admin only: GitHub refused the token |
| `malformed` | A frame, reference, binding or request cannot be read (`details['reason']`) |
| `timeout` | An approval was not answered in time |
| `rateLimited` | The identity is held back (`details['retryAfterMs']`) |
| `unsupported` | An unknown request or protocol, or a feature the service does not offer |
| `internal` | A failure of the service, a service that broke the protocol, or an unknown kind |
| `notRunning` | No service: no socket or port file, an unreadable port file, a refused or dropped connection; sent by nobody |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `wireName` | `String` | The kind as the protocol writes it (`not_found`, `rate_limited`, ...) |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `fromWire(Object? kind)` | `TomSecretsErrorKind` | The kind of a protocol `kind`; an unknown one is `internal` |

---

### TomSecretEncoding

How the service sent a value.

#### Values

| Value | Description |
| --- | --- |
| `utf8` | Text |
| `base64` | Bytes (base64 on the wire) |

---

### TomSecretSource

Where a value came from.

#### Values

| Value | Description |
| --- | --- |
| `github` | Fetched from GitHub in this refresh cycle |
| `file` | Read from a `file:` vault on the local disk in this refresh cycle |
| `cache` | The service's offline copy |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `fromWire(Object? name)` | `TomSecretSource` | The source a protocol `source` names; an unknown one is `cache` |

---

### TomSecretsPending

Why a request waits.

#### Values

| Value | Description |
| --- | --- |
| `unlock` | The service is locked and an admin was told |
| `approval` | The request went to approval |

---

## Typedefs

| Typedef | Definition | Description |
| --- | --- | --- |
| `TomSecretsProgressCallback` | `void Function(TomSecretsProgress progress)` | Receives the progress notices of a waiting request |

---

## Global Functions and Constants

### Constants

| Constant | Type | Description |
| --- | --- | --- |
| `tomSecretsClientVersion` | `String` | The library's version, sent in `hello` |
| `tomSecretsProtocol` | `int` | The protocol version this library speaks (1) |
| `tomSecretsClientFeatures` | `List<String>` | The features this library takes: `binary`, `getFile`, `match`, `propose`, `passkey` |
| `tomSecretsMaxGetMany` | `int` | The most references one `getMany` carries (256) |
| `tomSecretsDefaultField` | `String` | The field a reference without `#field` names (`Password`) |
| `tomSecretsMaxReferenceBytes` | `int` | The longest reference, in bytes of UTF-8 (1024) |
| `tomSecretsFrameJson` | `int` | Frame type of a JSON payload (0) |
| `tomSecretsFrameBinary` | `int` | Frame type of a binary chunk (1) |
| `tomSecretsMaxRequestPayload` | `int` | The largest payload of a frame sent to the service (64 KiB) |
| `tomSecretsMaxAnswerPayload` | `int` | The largest payload of a frame sent by the service (1 MiB) |

### Functions

| Function | Signature | Description |
| --- | --- | --- |
| `discoverTomSecrets` | `TomSecretsLocation discoverTomSecrets({required String operatingSystem, required Map<String, String> environment, int? Function()? uid})` | The location of the service for an OS (`linux`, `macos`, `windows`; others as `linux`) and environment; `uid` is needed only for the `/tmp/tsm-<uid>` fallback |
| `readTomSecretsPortFile` | `int? readTomSecretsPortFile(String text)` | The port of a port file's text (decimal 1-65535, at most one trailing LF or CR LF), or null when unreadable |
| `currentUid` | `int? currentUid()` | The numeric id of the process's user (POSIX `getuid`); null on Windows |
| `tomSecretsJsonPayload` | `Uint8List tomSecretsJsonPayload(Map<String, Object?> message)` | The compact UTF-8 JSON of a message |
| `tomSecretsEncodeFrame` | `Uint8List tomSecretsEncodeFrame(int type, List<int> payload)` | A frame: payload length (4 bytes big-endian), type, payload |
| `tomSecretsJsonFrame` | `Uint8List tomSecretsJsonFrame(Map<String, Object?> message)` | The JSON frame of a message |
| `tomSecretsDecodePayload` | `Map<String, Object?> tomSecretsDecodePayload(List<int> payload)` | The message of a JSON payload; throws `TomSecretsFrameException` when it is empty, not UTF-8, BOM-prefixed, not JSON, not an object, has a duplicate member or no string `op` |
