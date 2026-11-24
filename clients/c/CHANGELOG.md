# Changelog

## 0.2.0

- The passkey requests of protocol.md 5.8 (feature `passkey`), for the
  clients the service admits to them (the browser host and the Windows
  passkey plugin): `tsm_passkeys` lists a page's passkeys by name and
  credential id, `tsm_passkey_get` answers the service's signature,
  `tsm_passkey_create` makes a passkey once the user confirms it in the
  app; never a key. `TSM_ERR_UNSUPPORTED` from a service without the
  feature.
- `tsm_base64url_encode` and `tsm_base64url_decode`.

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
