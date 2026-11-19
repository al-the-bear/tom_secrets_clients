# Changelog

## 0.1.0

- The client endpoint of the Tom Secrets Manager protocol, version 1, for
  Rust 1.70 and later: finding the service (runtime directory, Unix socket,
  or on Windows the localhost port and the client token re-read at every
  connect), frames with their limits and strict JSON payloads, `hello` /
  `welcome`, `get` and `get_many`.
- `get_file` for a service that offers the features `binary` and `getFile`:
  the attachment's chunks, checked against its size and SHA-256.
- Waiting for an unlock or an approval: `no_wait`, `timeout`, `on_progress`
  with the approval code; `rate_limited` waited out with
  `wait_on_rate_limit`.
- `Reference::parse` / `format`: the reference grammar, its canonical form
  and the malformed reasons, refused locally.
- `Value`, masked in `Display` and `Debug`, its buffer overwritten on drop.
- `Error`, one variant per kind; a blocking `Client` that is `Send` and
  `Sync`; the feature `tokio` with an async client over tokio's blocking
  pool. No dependency without that feature, no logging.
