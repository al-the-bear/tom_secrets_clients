# Changelog

## 0.2.3

- `TomSecretsRuntime` joins its files with the separator of the OS it is
  made for (`separator`; `TomSecretsRuntime.current` takes the given
  `operatingSystem`'s), so Windows paths computed elsewhere use a backslash.
- `getMany`'s argument error for an empty or over-long list is documented
  as the caller's mistake, raised before anything is sent.

## 0.2.2

- The README rewritten as the package's manual; API summaries of the client and the admin library in `doc/api/`.
- `tomSecretsStartService`: a status line that is not JSON or not an object is a failed start (`no_answer`), not an exception.

## 0.2.1

- `pairing_mode.dart` in the admin library: the service's pairing mode as
  `tsm pair` drives it — the handover (`TomSecretsPairingHandover`), what
  the pairing gave (`TomSecretsPairingReport`) and the conversation
  (`TomSecretsServicePairing`: `received`, `setUp`, `close`).

## 0.2.0

- `distribution.dart` in the admin library: the layout of the manager app's
  distribution, which carries `tsm` and the service in its `tsm/bin` folder
  (`tomSecretsServiceCandidates`, `tomSecretsDistributionApp`).
- `TomSecretsAdminKeyring` in the admin library: the admin keys in the
  keychain with the index of their starts (`tsm.admin.index`); `keep`,
  `forget`, `pruneOthers`.

## 0.1.0

- The admin side, in its own library `package:tom_secrets_client/admin.dart`
  for the manager app, `tsm` and the service: `TomSecretsAdminClient` (the
  mutual challenge and `claim`), `TomSecretsRuntime` (the runtime directory),
  `tomSecretsStartService` with the admin-key handover,
  `tomSecretsDataDirectory` / `tomSecretsBootstrapPath` (`TSM_DATA_DIR`, else
  the OS's application-data folder), and the keychain names
  (`tomSecretsKeychainService`, `tomSecretsAdminKeyHandle`).
- The client endpoint of the Tom Secrets Manager protocol, version 1: finding
  the service (runtime directory, Unix socket, or on Windows the localhost
  port and the client token re-read at every connect), frames with their
  limits and strict JSON payloads, `hello` / `welcome`, `get`, `getMany` and
  (phase B) `getFile` over binary chunks with its SHA-256 check.
- Waiting for an unlock or an approval: `wait`, `timeout` as `timeoutMs`,
  progress notices with the approval code.
- `TomSecretReference.parse` / `format`: the reference grammar, its canonical
  form and the malformed reasons, refused locally.
- `TomSecretValue`: text or bytes, entry (source `github`, `file` or `cache`),
  bindings, version, expiry, client token; masked `toString`, `dispose`
  overwrites the buffer.
- `TomSecretsClientException` with `TomSecretsErrorKind`: the protocol's kinds
  plus `notRunning`; `rateLimited` waited out on request.
