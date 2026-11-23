# Changelog

## 0.2.13

- The phase-C developer-tool helpers (part-os-integration):
  `tsm aws-credentials <ref>` as AWS's `credential_process` (an API token
  entry's UserName, Password, SessionToken and Expires as
  `{"Version":1,"AccessKeyId",…}`, one approval); `tsm kube-credential
  <ref>` as kubectl's exec plugin (the Password as the token, or a
  certificate entry's certificate and key, the `apiVersion` kubectl names,
  Expires as `expirationTimestamp`); `docker-credential-tsm`, a third name
  of tsm (`get` the registry's login picked once in the app, `list`
  without secrets, `store` proposing an unknown credential, `erase`
  ignored, Docker's "credentials not found" when none).
- `tsm integrations install aws --profile NAME --ref REF` and
  `install docker --registry HOST… | --every-registry` (with `uninstall`
  of one profile or registry), on `tom_secrets_client` 0.2.16.

## 0.2.12

- `tsm pair --relay wormhole:ws(s)://…`: a pairing through a magic-wormhole
  mailbox server (the public one or a self-hosted one), which takes no token
  (`--token-env` and `--relay-api` are refused with it).

## 0.2.11

- `tsm pair --relay tsm:<url> --token-env <VAR>`: the relay server's
  instance token, handed to the service, which keeps it in the keychain for
  the approval link through the relay (part-relay); still optional.

## 0.2.10

- `tsm --version` names the package's version again; 0.2.9 named 0.2.8.

## 0.2.9

- `tsm pair --relay tsm:<url>` pairs through a relay server
  (`tom_secrets_relay`), with no token.

## 0.2.8

- `tsm pair` through a GitHub relay (part-relay): `--relay
  github:<owner>/<repo>` with `--token-env <VAR>` (this machine's own token
  for the repository, read from that variable, handed to the service on its
  standard input, never an argument) and `--relay-api <URL>`; the code
  alone, or after an address (tried first). Needs `tom_secrets_service`
  0.23.0 and `tom_secrets_client` 0.2.12.

## 0.2.7

- `tsm run --file VAR=ref`: the value fetched with `getFile` is written to a
  temporary file only the user reads (600 in a 700 directory), `VAR` its
  path; overwritten and deleted when the command ends. Without a field a
  certificate entry gives its private key and a PGP key entry its secret
  key (BP-33). `tsm status` and `tsm keys` list the certificates' and PGP
  keys' expiry. Tested with `tom_secrets_service` 0.21.0.

## 0.2.6

- `tsm login [--client-id ID]`: "Sign in with GitHub" on a headless
  machine; prints the GitHub App's device code and the page to enter it on,
  waits, and says who is signed in (the service keeps and renews the
  tokens). `tsm logout` signs the machine out; its pasted tokens are used
  again (part-key-rotation §3, DP-83). Needs `tom_secrets_service` 0.14.0.

## 0.2.5

- `git-credential-tsm`, a second name of `tsm` (multi-call: the name it is
  started under): `get` answers the login of git's host the service's
  `match` with `pick` gives (the user picks it once in the app), `store`
  proposes a credential the vaults do not hold, `erase` is ignored; nothing
  is answered when no service runs or nothing matches (DP-52, DP-53).
- `tsm integrations [status | install <ssh|git> | uninstall <ssh|git>]
  [--hosts PATTERNS] [--json]`: the ssh block (`IdentityAgent` of the
  agent) and the git block (`credential.helper tsm`, `git-credential-tsm`
  beside tsm), marked blocks with nothing outside them changed. Needs
  `tom_secrets_client` 0.2.7.

## 0.2.4

- `tsm status` shows the ssh-agent's endpoint (`agent`, what
  `SSH_AUTH_SOCK` or `IdentityAgent` names); `tsm approvals` names an agent
  prompt's SSH key and destination host. Needs `tom_secrets_client` 0.2.6.

## 0.2.3

- `tsm pair --link ADDRESS:PORT`: where this machine's approval link
  listens (the device setting `approvalLink`, checked: `host:port`, never
  every interface); the giving machine is told it, so its service opens the
  link and its app answers this machine's prompts. Needs
  `tom_secrets_client` 0.2.4.

## 0.2.2

- The README rewritten and a user guide, `doc/tsm_user_guide.md`; the help of `ref format --uuid` (the 32 hex digits) and `allow --pin` (`hash` or `off`) says what they take.

## 0.2.1

- `tsm pair <host:port> <code>`: sets a new machine up by pairing, through
  the service executable's pairing mode (tsm links no core); then the
  master password, and the service is started and unlocked.

## 0.2.0

- The admin keys in the keychain are recorded (`tsm.admin.index`): keeping or
  using a key removes those of services that are gone, and `tsm stop`
  removes the stopped service's.

## 0.1.0

- `tsm get`, `tsm run` (one `getMany`, the command after `--`, signals
  forwarded, its exit code), `tsm ref parse|format`.
- `tsm start [--unlock]` (the admin-key handover, the key kept in the OS
  keychain), `unlock`, `lock`, `stop`, `reload`, `status` (stores with their
  state, source and the age of their copy; the keys due a reminder), `keys`,
  `approvals`, `approve <token>|-`, `approve-code`, `grants`, `allow`,
  `audit`, `compact`.
- The admin key between invocations in the keychain, else a `claim` with the
  master password (DP-22); `--password-stdin`.
- The exit codes of part-clients.
