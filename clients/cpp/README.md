# C++ client (`clients/cpp`)

> Part of the Tom Secrets Manager by Peter Nicolai Alexis Kyaw.

The C++ client of the Tom Secrets Manager: finds the local secrets service,
speaks its client protocol and parses and formats secret references.

## Overview

The Tom Secrets Manager keeps secrets in KDBX vaults and serves them to the
programs of one machine through a local **secrets service**. A program reads
a secret by its **reference** (`telegram.bot_token`,
`fleet/Db/Main#UserName`); the service resolves it, asks an approver when no
grant answers the request, and returns the value.

This library is the program's side of that, for C++17: RAII and exceptions
over the [C client](../c/README.md), which finds the service, speaks the
protocol and keeps the connection. It is header-only (`tsm/tsm.hpp`, CMake
target `tsm::cpp`, which brings the C library `tsm::tsm`), distributed as
source with CMake, and logs nothing. `hello` names it `cpp`.

## Installation

```cmake
add_subdirectory(path/to/clients/cpp tsm_cpp)
target_link_libraries(my_program PRIVATE tsm::cpp)
```

CMake 3.16 or later, a C++17 compiler and a C99 compiler, on Linux, macOS
or Windows. The secrets service must run on the same machine, for the same
OS user: the manager app starts it on a desktop, `tsm start` on a server.

## Quick start

```cpp
#include <iostream>
#include <tsm/tsm.hpp>

int main() {
    try {
        auto c = tsm::Client::connect();
        tsm::GetOptions o;
        o.field = "UserName";
        o.on_progress = [](const tsm::Progress &p) { std::cerr << "waiting for " << p.pending << "\n"; };
        auto v = c.get("[env:prod]db.main", o);
        std::cout << "connecting as " << *v.text() << "\n";
    } catch (const tsm::Error &e) {
        if (e.kind() == tsm::ErrorKind::Locked) {
            std::cerr << "unlock the Tom Secrets Manager first\n";
        } else {
            std::cerr << e.what() << "\n";
        }
        return 1;
    }
    return 0;
}
```

With C++20 the options can be written in place:
`c.get("[env:prod]db.main", {.field = "UserName"})`.

The first read of a secret by a program may wait for an approval: the
manager app (or a trusted device) asks the user. When no approver is
connected, `on_progress` hears the approval code to answer on a trusted
device.

## API

Everything is in namespace `tsm`.

### `Client`

| Member | What it does |
| --- | --- |
| `Client(options)` | A client that connects on its first call (`ClientOptions`, default `{}`). |
| `Client::connect(options)` | A client connected at once, so a missing service shows as `NotRunning` right away. |
| `get(ref, options)` | Reads one secret; returns a `Value`. |
| `get_many(requests, options)` | Reads 1 to 256 secrets under one approval prompt; returns `std::vector<Result>` in request order, each with `value` or `error`. |
| `get_file(ref, options)` | Reads an attachment or a typed key as bytes, checked against its size and SHA-256; returns a `File`. `Unsupported` when the service does not offer the features `binary` and `getFile`. |
| `open()`, `close()` | Connects unless connected; closes the connection (a later call connects again). |
| `welcome()` | The service's `welcome` on the current connection (`protocol`, `service_version`, `host`, `platform`, `features`), or `std::nullopt`. |

- A `Client` is move-only; its destructor closes the connection.
- It is thread-safe: calls from several threads overlap on its one
  connection.
- After `NotRunning` or a dropped connection, the next call connects again.

`ClientOptions` (every member optional): `client_name` (default the
program's name), `client_token`, `runtime_dir` (instead of the
environment's), `operating_system` (`linux`, `macos`, `windows`),
`connect_timeout` (default 10 s).

`GetOptions` (an aggregate):

| Member | Meaning |
| --- | --- |
| `field` | The field, when the reference names none. |
| `dimensions` | Values for dimensions beside the reference: `{{"env", "prod"}}`. |
| `no_wait` | Answer at once instead of waiting for an unlock or an approval (`Locked` when locked). |
| `timeout` | How long the service may wait, capped by the service. |
| `on_progress` | Called with a `Progress` (`pending`: `unlock` or `approval`; `approval_code` when no approver is connected) while the request waits; called on the connection's reader thread, so it must return quickly. An exception it throws is caught and dropped. |
| `want_client_token` | Ask for a client token with an "always" approval (`get` only). |
| `wait_on_rate_limit` | Wait out a `RateLimited` answer (its `retryAfterMs`, else one second) and send the request again. |

`RequestOptions` for `get_many` has `no_wait`, `timeout`, `on_progress` and
`wait_on_rate_limit`; each `Request` carries `ref`, `field` and
`dimensions`.

### `Value` and `File`

| Member | Meaning |
| --- | --- |
| `text()` | The value as `std::string_view`; `std::nullopt` for a binary value (read it with `data()`). |
| `data()`, `size()` | The value's bytes (text as UTF-8). |
| `encoding()` | `utf8` or `base64` (binary). |
| `reference()` | The reference as asked for. |
| `entry()` | `Entry{store, uuid, source, fetched_at}`; `source` is `github`, `file` or `cache`. |
| `version()` | `Version{modified, revision}`: compare it to see a change. |
| `bound()` | The dimension values the winning entry carries. |
| `expires()` | The entry's expiry, or `std::nullopt`. |
| `client_token()` | A client token the service granted, or `std::nullopt`. |

- A `Value` is move-only; its destructor overwrites the buffer with zeros.
- `operator<<` writes `SecretValue(db.main: ***)`, never the secret.
- A `std::string` made from `text()` is yours to handle.
- A client token is yours to keep; pass it as `client_token` to a later
  client. The library never stores one.
- A `File` has `name()`, `reference()`, `data()`, `size()` and a masked
  `operator<<` the same way.

### `Reference`

| Member | What it does |
| --- | --- |
| `Reference::parse(text)` | Parses a reference (`kind`, `key`, `store`, `segments`, `uuid`, `qualifiers`, `field`, `field_given`); a malformed one throws an `Error` of kind `Malformed` whose `reason()` names the rule it broke. |
| `format()`, `canonical()` | The canonical form; `format()` throws `InvalidArgument` for a reference that has none, `canonical()` gives `""`. |

```cpp
tsm::Reference::parse("[host:server1,env:prod]fleet/Db/Main#Password").format();
// "[env:prod,host:server1]fleet/Db/Main"
```

`get`, `get_many` and `get_file` parse every reference locally first: a
malformed one fails without a round trip, and so do a field named twice
(`field_twice`) and a request over 64 KiB (`frame`).

## Errors

Every failure is a `tsm::Error` (a `std::runtime_error`) with:

- `kind()`, an `ErrorKind`: the protocol's kinds `Locked`, `Denied`,
  `NotFound`, `Ambiguous`, `NeedsUnlock`, `Unavailable`, `Offline`,
  `TokenExpired`, `Malformed`, `Timeout`, `RateLimited`, `Unsupported`,
  `Internal`, plus `NotRunning` (no service found, or the connection lost)
  and the library's own `InvalidArgument` and `NoMemory`; `to_string(kind)`
  gives the protocol's name (`not_found`);
- `what()`, for people; never a value, token or key;
- `reason()` (details.reason) and `retry_after()` (a rate limit's
  `retryAfterMs`).

An unknown kind from a later service is `Internal`, and so is a service that
breaks the protocol. `Denied`, `Ambiguous` and `NotFound` are never retried;
`RateLimited` is waited out only with `wait_on_rate_limit`. Where the service
is looked for (`TSM_RUNTIME_DIR`, the runtime directories, the Windows port
and token) is the C client's: see its [README](../c/README.md#configuration).

## Further documentation

| Document | What is there |
| --- | --- |
| [C client](../c/README.md) | The library under this one: configuration, the C API |
| [The protocol](../../protocol/protocol.md) | The reference grammar (section 4), the client endpoint (section 5), approvals and client tokens (section 7), the error kinds (section 10) |
| [Conformance suite](../../conformance/README.md) | The fake service and the cases every client runs (runner `cpp`) |
| [CHANGELOG](CHANGELOG.md) | The changes per version |

## Developing

From this folder:

```sh
cmake -S . -B build -DTSM_WERROR=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

The tests read `../../protocol/vectors` (ctest runs them from this folder);
one of them is compiled as C++20 to check the designated-initializer call.

## Status

Version 0.1.0, over the C client 0.1.0 (protocol version 1, features
`binary` and `getFile`). The tests check the reference vectors through
`tsm::Reference`, the error mapping, and the client against a small service
on a local socket (values, `get_many`, `get_file`, progress, rate limits,
moves, concurrency); they also pass under AddressSanitizer, UBSan and
ThreadSanitizer. The conformance suite runs it against the fake service.
It builds with warnings as errors and passes its tests and every
conformance table on macOS (Apple clang), Linux (gcc 13 and clang 18) and
Windows (MSVC 2022, `/W4 /WX`; the conformance case for the Windows endpoint
included), its tests also under AddressSanitizer and UBSan on Linux.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
