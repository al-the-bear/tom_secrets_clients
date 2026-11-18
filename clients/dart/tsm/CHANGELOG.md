# Changelog

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
