# Changelog

## 0.1.0

- The client endpoint of the Tom Secrets Manager protocol, version 1: finding
  the service (runtime directory, Unix socket, or on Windows the localhost
  port and the client token re-read at every connect), frames with their
  limits and strict JSON payloads, `hello` / `welcome`, `get`, `getMany` and
  (phase B) `getFile` over binary chunks with its SHA-256 check.
- Waiting for an unlock or an approval: `wait`, `timeout` as `timeoutMs`,
  progress notices with the approval code.
- `TomSecretReference.parse` / `format`: the reference grammar, its canonical
  form and the malformed reasons, refused locally.
- `TomSecretValue`: text or bytes, entry, bindings, version, expiry, client
  token; masked `toString`, `dispose` overwrites the buffer.
- `TomSecretsClientException` with `TomSecretsErrorKind`: the protocol's kinds
  plus `notRunning`; `rateLimited` waited out on request.
