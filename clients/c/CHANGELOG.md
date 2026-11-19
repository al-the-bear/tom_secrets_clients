# Changelog

## 0.1.0

- The client endpoint of the Tom Secrets Manager protocol, version 1, in
  C99 with CMake: finding the service (runtime directory, Unix socket, or on
  Windows the localhost port and the client token re-read at every connect),
  frames with their limits and strict JSON payloads, `hello` / `welcome`,
  `tsm_get` and `tsm_get_many`.
- `tsm_get_file` for a service that offers the features `binary` and
  `getFile`: the attachment's chunks, checked against its size and SHA-256.
- Waiting for an unlock or an approval: `no_wait`, `timeout_ms`,
  `on_progress` with the approval code; rate limits waited out with
  `wait_on_rate_limit`.
- `tsm_reference_parse` / `tsm_reference_format`: the reference grammar, its
  canonical form and the malformed reasons, refused locally.
- `tsm_value`, overwritten by `tsm_value_free`; no function prints one.
- `tsm_error_kind` codes and `tsm_last_error`; a thread-safe client; no
  dependencies beyond the C library, threads and sockets; no logging.
