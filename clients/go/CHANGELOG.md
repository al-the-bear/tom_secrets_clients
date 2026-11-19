# Changelog

## 0.1.0

- The client endpoint of the Tom Secrets Manager protocol, version 1, for
  Go 1.22 and later: finding the service (runtime directory, Unix socket, or
  on Windows the localhost port and the client token re-read at every
  connect), frames with their limits and strict JSON payloads (no duplicate
  member names), `hello` / `welcome`, `Get` and `GetMany`.
- `GetFile` for a service that offers the features `binary` and `getFile`:
  the attachment's chunks, checked against its size and SHA-256.
- Waiting for an unlock or an approval: `NoWait`, `WithTimeout`,
  `WithProgress` with the approval code; `rate_limited` waited out with
  `WaitOnRateLimit`; every call takes a `context.Context`.
- `ParseReference` / `FormatReference`: the reference grammar, its canonical
  form and the malformed reasons, refused locally.
- `Value`, masked in every `fmt` verb, `encoding/json` and `log/slog`, its
  buffer overwritten by `Close`.
- `*tsm.Error` with `Kind` for `errors.As`; a `Client` safe for concurrent
  use; the standard library only, no logging.
