# Changelog

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
