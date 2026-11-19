# Changelog

## 0.1.0

- The client endpoint of the Tom Secrets Manager protocol, version 1, for
  Python 3.9 and later: finding the service (runtime directory, Unix
  socket, or on Windows the localhost port and the client token re-read at
  every connect), frames with their limits and strict JSON payloads,
  `hello` / `welcome`, `get` and `getMany`.
- `get_file` for a service that offers the features `binary` and
  `getFile`: the attachment's chunks, checked against its size and SHA-256.
- Waiting for an unlock or an approval: `wait`, `timeout_ms`, progress
  notices with the approval code; `rate_limited` waited out on request.
- `SecretReference.parse` / `format`: the reference grammar, its canonical
  form and the malformed reasons, refused locally.
- `SecretValue`, masked in every printable form, its buffer overwritten by
  `close`.
- `tsm.Client` (blocking, thread-safe, a connection of its own after
  `os.fork`) and `tsm.aio.Client` (asyncio); no dependencies, no logging.
