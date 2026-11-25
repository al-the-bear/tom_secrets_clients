# Changelog

## 0.1.0

- `TomLocalSecretsProvider`, the Tom Secrets Manager as a `TomSecretsProvider`
  for Tom servers (`secret:local:<reference>#<field>`), moved here from
  `tom_core_secrets` 0.3.1's `local.dart` unchanged: tom_core depends on no
  Tom Secrets Manager package; a server that wants the provider adds this
  package. The import is `package:tom_secrets_provider/tom_secrets_provider.dart`.
