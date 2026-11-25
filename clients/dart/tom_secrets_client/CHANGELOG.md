# Changelog

## 0.2.23

- `tomSecretsUntrustedAdvice('mode')` names the fix that needs no admin
  command: `chmod 700` on the runtime directory and `chmod 600` on its
  sockets (a service older than 0.25.7 left its sockets open inside its
  closed directory, and `tsm stop` is an admin command too).

## 0.2.22

- The admin client checks who answers before it sends anything
  (protocol.md 6.0, `TomSecretsServiceTrust`): `connect` and `claim` go on
  only when the runtime directory and the admin socket are this user's
  alone (0700 / 0600; on Windows the directory's access list), the process
  answering runs as this user, and it is the service executable expected
  (beside the admin or in its distribution, the one `TSM_SERVICE` names, or
  one handed in). Otherwise they throw `service_untrusted` with
  `details.reason` `owner`, `mode`, `peer_user` or `peer_executable`, and
  nothing was sent: a `claim` no longer hands the master password to
  whatever answers. `TomSecretsAdminClient.checkService` runs the check
  alone, before the password is asked for; `tomSecretsUntrustedAdvice`
  says what to do about each reason.
- `TomSecretsRuntime.check` judges the runtime directory itself, never what
  a link there points to: a directory or link another user left in `/tmp`
  is refused, never used.
- New dependency: `ffi`.

## 0.2.21

- `tomSecretsPrepareDataDirectory` runs its `stat`, `chmod` and `icacls`
  synchronously: a caller in a zone that pumps only its own microtasks (a
  widget test driving the First run) never saw the asynchronous processes
  finish.
- The version sent in `hello` is the package's again (0.2.20 sent 0.2.19).

## 0.2.20

- `tomSecretsPrepareDataDirectory` (admin library): the data directory is
  the user's alone, as the runtime directory is. A missing one is created
  0700 (Windows: the inheritance cut, only the user and SYSTEM, inherited by
  what is inside); an existing one others can reach is tightened (POSIX
  `chmod -R go=`: files 0600, folders 0700, the user's own bits kept;
  Windows: the ACL replaced, other accounts removed), and the count is
  answered (`TomSecretsDataDirectoryState`). One of another user, or a path
  that is no folder, is refused (`TomSecretsDataDirectoryException`).
- The runtime directory's Windows ACL code is shared with it; restricting a
  runtime directory now also removes accounts granted explicitly.

## 0.2.19

- Chunked members on the admin endpoint (protocol.md 2.7, feature
  `chunked`): `TomSecretsAdminClient` offers the feature in `auth` and
  `claim`, sends a request over the 64 KiB request limit (a `save` of a
  large vault) with its large members as binary frames when the service
  offers it, and reads a chunked answer (a `vaultFileData` over 1 MiB) back
  as one message. `tomSecretsChunkedFrames` and `TomSecretsChunkAssembler`
  are the shared implementation the service uses too.
- A request on an admin connection that has ended fails at once with
  `closed`; it no longer waits for an answer that can never come.

## 0.2.18

- The answer of `passkeyGet` is `TomSecretsPasskeySignature`: 0.2.17's
  name `TomSecretsPasskeyAssertion` is `tom_secrets_core`'s authenticator
  type too, and a library importing both could not name either.

## 0.2.17

- Passkeys for the browser host (protocol.md 5.8, feature `passkey`):
  `TomSecretsClient.passkeys` (a page's passkeys by name and credential id,
  `TomSecretsPasskeyCandidate`), `passkeyGet` (a sign-in the service signs,
  `TomSecretsPasskeyAssertion`) and `passkeyCreate` (a new passkey the user
  confirms in the app, `TomSecretsPasskeyCreated`); `hello` names
  `passkey`.

## 0.2.16

- `TomSecretsIntegrations` configures AWS and Docker too
  (part-os-integration): `TomSecretsIntegration.aws` writes per profile
  `credential_process = <tsm> aws-credentials <ref>` into the marked block
  of `~/.aws/config` (`awsBlock`, the words quoted as botocore splits
  them; a profile also defined outside the block refused);
  `TomSecretsIntegration.docker` names `tsm` in `~/.docker/config.json`'s
  `credHelpers` per registry or as `credsStore`, keeping every other key,
  with `docker-credential-tsm` beside tsm (`helperLinkOf`,
  `tomSecretsDockerHelperName`). `install` takes `awsProfiles`,
  `dockerRegistries`, `dockerEveryRegistry`; `uninstall` takes
  `awsProfile`, `dockerRegistry` to remove one; the state names
  `profiles`, `registries`, `everyRegistry`; `repair` covers both.

## 0.2.15

- `TomSecretsPairingHandover`'s `relay` may be a magic-wormhole mailbox
  server (`wormhole:ws(s)://…`), which takes no token.

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
