# Changelog

## 0.2.14

- `tomSecretsClientVersion` (sent in `hello`) is the package's version
  again; 0.2.13 sent 0.2.12.

## 0.2.13

- The pairing handover's relay may be a relay server (`tsm:<url>`) too,
  which needs no token to pair; a GitHub relay still needs this machine's
  token for its repository.

## 0.2.12

- The pairing mode's handover through a relay (part-relay): `address` and
  `port` are optional; `relay` (a `github:<owner>/<repo>` repository the
  pairing also goes through, after the address or alone), `relayToken`
  (this machine's own token for it) and `relayApi` (the GitHub API's URL).
- The API summary documents the developer-tool integrations, the unlock
  bundle's constants and the runtime's ssh-agent endpoint.

## 0.2.11

- 0.2.10 exported `tomSecretsBrowserHostName`, which `tom_secrets_service`
  defines too and exports beside this library, so every importer of the
  service failed to compile: the client no longer exports it
  (`tomSecretsBrowserHostBeside` keeps the name).

## 0.2.10

- The browsers' native-messaging manifests of `tsm-browser-host`
  (part-browser): `TomSecretsBrowserHosts` (Chrome, Chromium, Edge, Brave
  and Firefox on macOS, Linux and Windows: the manifest's folder, on
  Windows the registry value through `reg.exe`; install, remove, the start
  check; a Flatpak or Snap browser named), `TomSecretsBrowserHostState`,
  `TomSecretsRegistry`; the extension ids the host serves
  (`tomSecretsChromiumExtensionIds`, the development build's key and id,
  `tomSecretsFirefoxExtensionId`); `tomSecretsBrowserHostBeside`.

## 0.2.9

- The OS unlock's key bundle (protocol.md 6.4, part-os-unlock):
  `TomSecretsUnlockBundle` (the composite key and the repository key),
  `tomSecretsBundleKey` (HKDF-SHA256 per admin connection),
  `tomSecretsSealBundle` / `tomSecretsOpenBundle` (AES-256-GCM, checked
  against `protocol/vectors/bundles.json`), and
  `TomSecretsAdminClient.unlockWithBundle`. New dependency: `cryptography`.
- `TomSecretsAdminClient.serviceStart` now answers the service's start (it
  answered 0).

## 0.2.8

- `TomSecretsIntegrations` reads and writes its (small) files synchronously
  behind its `Future` API, so the manager app's widget tests, which run on
  fake time, see them written.

## 0.2.7

- `match` takes `userName` (only that user's logins), `pick` (the helpers:
  one login of the host, the one the grants decide or the one the user
  picks in the app) and `onProgress`; `propose` answers whether the vaults
  hold the credential already (a helper's `store`, DP-52).
- The developer-tool integrations (`TomSecretsIntegrations`, admin
  library): the ssh block (`IdentityAgent` of the service's agent, at the
  top of `~/.ssh/config`, its `Host` patterns editable; on Windows the
  pipe's backslashes doubled, as ssh's config reader takes them) and the git
  block (`credential.helper tsm` in `~/.gitconfig`, `git-credential-tsm`
  beside `tsm`), installed, checked (`status`: still this machine's agent
  and helper), repaired and removed; `tomSecretsWithBlock` /
  `tomSecretsBlockOf` keep everything outside the marked block.

## 0.2.6

- The ssh-agent's endpoint in the runtime directory [B]:
  `TomSecretsRuntime.agentSocket` (`agent.sock` on Linux and macOS),
  `TomSecretsRuntime.agentPipe` (`\\.\pipe\tsm-ssh-agent` on Windows) and
  `agentEndpoint`, the one of the runtime's OS; `agent.sock` is an endpoint
  file (removed with the others); `writeInfo` takes the agent's endpoint
  for `service.json`.

## 0.2.5

- `match` and `propose` [B] (protocol.md 5.5) for the browser host and the
  developer-tool helpers: the login entries of a page the client's grants
  cover (`TomSecretsLoginCandidate`, never a value), and a login proposed
  for the manager app; each fails as `unsupported` when the service does
  not offer its feature.
- `hello.features` names `binary`, `getFile`, `match` and `propose`;
  `getFile` checks only its own two features.

## 0.2.4

- The pairing mode's handover carries `approvalLink`
  (`TomSecretsPairingHandover.approvalLink`): the address the new machine's
  approval link listens on, which goes into its device settings and is
  told to the giving machine.
- `tomSecretsApprovalLinkProblem`: the check of an approval link address
  (`host:port`, never every interface), shared by `tsm`, the service and
  the app.

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
