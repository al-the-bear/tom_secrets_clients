# Changelog

## 0.1.0

- The C++17 client of the Tom Secrets Manager, header-only (`tsm/tsm.hpp`,
  CMake target `tsm::cpp`) over the C client 0.1.0: `Client` (move-only,
  thread-safe, `connect`, `get`, `get_many`, `get_file`, `welcome`),
  `GetOptions` / `RequestOptions` as aggregates (C++20 designated
  initializers work), progress through `std::function`, rate limits waited
  out on request.
- `tsm::Error` (a `std::runtime_error`) with `kind()`, `reason()` and
  `retry_after()`.
- `Value` and `File`: move-only, overwritten by their destructors, masked by
  `operator<<`.
- `Reference::parse` / `format`.
- `hello` names the language `cpp` (the C client's new `client_language`
  option).
