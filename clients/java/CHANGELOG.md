# Changelog

## 0.1.0

- The client endpoint of the Tom Secrets Manager protocol, version 1, for
  Java 16 and later: finding the service (runtime directory, Unix socket
  through `UnixDomainSocketAddress`, or on Windows the localhost port and the
  client token re-read at every connect), frames with their limits and
  strict JSON payloads, `hello` / `welcome`, `get` and `getMany`.
- `getFile` for a service that offers the features `binary` and `getFile`:
  the attachment's chunks, checked against its size and SHA-256.
- Waiting for an unlock or an approval: `noWait`, `timeout`, `onProgress`
  with the approval code; `RATE_LIMITED` waited out with `waitOnRateLimit`.
- `SecretReference.parse` / `format`: the reference grammar, its canonical
  form and the malformed reasons, refused locally.
- `SecretValue`, masked in `toString`, its buffer overwritten by `close`.
- `SecretsException` with `Kind`; a thread-safe `SecretsClient`; no
  dependencies, no logging.
