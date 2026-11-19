# Changelog

## 0.1.0

- The client endpoint of the Tom Secrets Manager protocol, version 1, for
  Node.js 18 and later: finding the service (runtime directory, Unix socket,
  or on Windows the localhost port and the client token re-read at every
  connect), frames with their limits and strict JSON payloads, `hello` /
  `welcome`, `get` and `getMany`.
- `getFile`: an attachment or a typed key as bytes over binary frames
  (features `binary` and `getFile`, named in every `hello`), checked against
  its size and SHA-256; `unsupported` when the service does not offer both.
  `SecretFile`, masked in every printable form, with `dispose`.
- Waiting for an unlock or an approval: `wait`, `timeoutMs`, progress
  notices with the approval code; `rate_limited` waited out on request.
- `SecretReference.parse` / `format`: the reference grammar, its canonical
  form and the malformed reasons, refused locally.
- `SecretValue`, masked in every printable form, with `dispose`.
- One package for TypeScript and JavaScript: CommonJS with type
  declarations, no runtime dependencies.
