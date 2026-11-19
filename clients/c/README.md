# C client (`clients/c`)

> Part of the Tom Secrets Manager by Peter Nicolai Alexis Kyaw.

The C client of the Tom Secrets Manager: finds the local secrets service,
speaks its client protocol and parses and formats secret references.

## Overview

The Tom Secrets Manager keeps secrets in KDBX vaults and serves them to the
programs of one machine through a local **secrets service**. A program reads
a secret by its **reference** (`telegram.bot_token`,
`fleet/Db/Main#UserName`); the service resolves it, asks an approver when no
grant answers the request, and returns the value.

This library is the program's side of that. It finds the service in the
runtime directory of the OS user, connects over a Unix socket (on Windows a
localhost port, through Winsock), and sends `get`, `getMany` and `getFile`
requests. It never opens a vault and never resolves a reference: the service
does both.

It is C99, distributed as source with CMake: the static library `tsm`
(target `tsm::tsm`), header `tsm/tsm.h`. It links only the C library,
threads (pthreads; Windows threads) and sockets (`ws2_32` on Windows); its
strict JSON, SHA-256 and RFC 3339 times are its own. It logs nothing.

## Installation

Add it to a CMake build:

```cmake
add_subdirectory(path/to/clients/c tsm)
target_link_libraries(my_program PRIVATE tsm::tsm)
```

or build and install it (`cmake -S clients/c -B build`, `cmake --build
build`, `cmake --install build --prefix /usr/local`) and find it with
`find_package(tsm)`, then link `tsm::tsm`. CMake 3.16 or later and a C99 compiler, on
Linux, macOS or Windows. The secrets service must run on the same machine,
for the same OS user: the manager app starts it on a desktop, `tsm start` on
a server.

## Quick start

```c
#include <stdio.h>
#include <tsm/tsm.h>

static void waiting(const tsm_progress *p, void *context) {
    (void)context;
    fprintf(stderr, "waiting for %s\n", p->pending);
}

int main(void) {
    tsm_client *c;
    tsm_get_options opts = TSM_GET_OPTIONS_INIT;
    tsm_value *v;
    int rc;

    if (tsm_connect(&c, NULL) != TSM_OK) {
        fprintf(stderr, "%s\n", tsm_last_error(NULL)->message);
        return 1;
    }
    opts.field = "UserName";
    opts.on_progress = waiting;
    rc = tsm_get(c, "[env:prod]db.main", &opts, &v);
    if (rc == TSM_ERR_LOCKED) {
        fprintf(stderr, "unlock the Tom Secrets Manager first\n");
    } else if (rc != TSM_OK) {
        fprintf(stderr, "%s\n", tsm_last_error(c)->message);
    } else {
        printf("connecting as %s\n", tsm_value_text(v));
        tsm_value_free(v);
    }
    tsm_client_free(c);
    return rc == TSM_OK ? 0 : 1;
}
```

The first read of a secret by a program may wait for an approval: the
manager app (or a trusted device) asks the user. When no approver is
connected, `on_progress` hears the approval code to answer on a trusted
device.

## API

Every call that can fail returns a `tsm_error_kind` (`TSM_OK` on success).

### The client

| Function | What it does |
| --- | --- |
| `tsm_client_new(&c, options)` | A client that connects on its first call; `options` may be NULL. |
| `tsm_connect(&c, options)` | A client connected at once, so a missing service shows as `TSM_ERR_NOT_RUNNING` right away. |
| `tsm_get(c, ref, options, &v)` | Reads one secret into a `tsm_value`; `options` may be NULL. |
| `tsm_get_many(c, requests, count, options, &results)` | Reads 1 to 256 secrets under one approval prompt; `results` is an array of `count` `tsm_result`s in request order (`value`, or `kind`, `message`, `reason`); free it with `tsm_results_free`. |
| `tsm_get_file(c, ref, options, &f)` | Reads an attachment or a typed key as bytes, checked against its size and SHA-256. `TSM_ERR_UNSUPPORTED` when the service does not offer the features `binary` and `getFile`. |
| `tsm_open(c)` | Connects, unless a connection is open. |
| `tsm_close(c)` | Closes the connection; a later call connects again. |
| `tsm_client_free(c)` | Closes and frees the client; no call may run on it then. |
| `tsm_welcome_get(c, &w)` | The service's `welcome` on the current connection (`protocol`, `service_version`, `host`, `platform`, `features`, `feature_count`); 0 when there is none. |

- A client is thread-safe: calls from several threads overlap on its one
  connection (a reader thread takes the answers).
- After `TSM_ERR_NOT_RUNNING` or a dropped connection, the next call
  connects again.

`tsm_client_options` (start from `TSM_CLIENT_OPTIONS_INIT`):

| Field | Default | Meaning |
| --- | --- | --- |
| `client_name` | the program's name | Shown in approval prompts; never trusted (the service measures the process). |
| `client_token` | none | A client token the program was granted before, sent with every connection. |
| `runtime_dir` | none | The runtime directory instead of the environment's (as `TSM_RUNTIME_DIR` names one). |
| `operating_system` | this platform's | `linux`, `macos` or `windows`. |
| `connect_timeout_ms` | 10000 | How long connecting and the service's `welcome` may take. |

`tsm_get_options` (start from `TSM_GET_OPTIONS_INIT`):

| Field | Meaning |
| --- | --- |
| `field` | The field, when the reference names none. |
| `dimensions` | Values for dimensions beside the reference: `{"env", "prod", NULL}`. |
| `no_wait` | Answer at once instead of waiting for an unlock or an approval (`TSM_ERR_LOCKED` when locked). |
| `timeout_ms` | How long the service may wait, capped by the service; -1 (the default) sends none. |
| `on_progress`, `progress_context` | Called with a `tsm_progress` (`pending`: `unlock` or `approval`; `approval_code` when no approver is connected) while the request waits; called on the connection's reader thread, so it must return quickly. |
| `want_client_token` | Ask for a client token with an "always" approval (`tsm_get` only). |
| `wait_on_rate_limit` | Wait out a `TSM_ERR_RATE_LIMITED` answer (its `retryAfterMs`, else one second) and send the request again. |

`tsm_request_options` (`TSM_REQUEST_OPTIONS_INIT`) for `tsm_get_many` has
`no_wait`, `timeout_ms`, `on_progress`, `progress_context` and
`wait_on_rate_limit`; each `tsm_request` carries `ref`, `field` and
`dimensions`.

### Values and files

| Function | Meaning |
| --- | --- |
| `tsm_value_text(v)` | The value as a NUL-terminated string; NULL for a binary value (read it with `tsm_value_bytes`). A value holding a NUL byte reads up to it here. |
| `tsm_value_bytes(v, &size)` | The value's bytes (text as UTF-8) and their count. |
| `tsm_value_encoding(v)` | `utf8` or `base64` (binary). |
| `tsm_value_reference(v)` | The reference as asked for. |
| `tsm_value_entry_store/uuid/source(v)`, `tsm_value_entry_fetched_at_ms(v)` | The entry it was read from; `source` is `github`, `file` or `cache`. |
| `tsm_value_version_modified_ms(v)`, `tsm_value_version_revision(v)` | The entry's version: compare it to see a change. |
| `tsm_value_expires_ms(v, &ms)` | 1 and the expiry when the entry has one. |
| `tsm_value_client_token(v)` | A client token the service granted, or NULL. |
| `tsm_value_bound_count(v)`, `tsm_value_bound_dimension/value(v, i)` | The dimension values the winning entry carries, sorted. |
| `tsm_value_free(v)` | Overwrites the buffer with zeros and frees the value. |

- There is no function that prints a value: nothing in the library shows a
  secret. The library overwrites the frames it read a value from once it has
  decoded them, and the client token on free.
- A string you copy out of `tsm_value_text` is yours to handle.
- A client token is yours to keep; pass it as `client_token` to a later
  client. The library never stores one.
- A `tsm_file` has `tsm_file_name`, `tsm_file_bytes`, `tsm_file_reference`
  and `tsm_file_free` (which overwrites the bytes).

### References

| Function | What it does |
| --- | --- |
| `tsm_reference_parse(text, &r)` | Parses a reference into a `tsm_reference` (`kind`, `key`, `store`, `segments`, `uuid`, `dimensions`/`values`, `field`, `field_given`); a malformed one is `TSM_ERR_MALFORMED` whose `reason` names the rule it broke. |
| `tsm_reference_format(r, &text)` | The canonical form (free it with `tsm_free`); `TSM_ERR_INVALID_ARGUMENT` for a reference that has none. |
| `tsm_reference_free(r)` | Frees a parsed reference. |

```c
tsm_reference *r;
char *text;
tsm_reference_parse("[host:server1,env:prod]fleet/Db/Main#Password", &r);
tsm_reference_format(r, &text); /* "[env:prod,host:server1]fleet/Db/Main" */
tsm_free(text);
tsm_reference_free(r);
```

`tsm_get`, `tsm_get_many` and `tsm_get_file` parse every reference locally
first: a malformed one fails without a round trip, and so do a field named
twice (`field_twice`) and a request over 64 KiB (`frame`).

### Lower-level functions

| Function | What it is |
| --- | --- |
| `tsm_discover(os, getenv_fn, context, uid, &endpoints)` | The runtime directory and endpoint files the client looks for; `TSM_ERR_NOT_RUNNING` when none can be named. |
| `tsm_current_operating_system()` | `linux`, `macos` or `windows` for this platform. |
| `tsm_read_port_file(text)` | The port of a Windows port file, or 0. |
| `tsm_error_kind_name(kind)`, `tsm_error_kind_from_wire(name)` | The protocol's name of a kind, and back. |
| `TSM_DEFAULT_FIELD`, `TSM_MAX_REFERENCE_BYTES`, `TSM_MAX_GET_MANY` | `Password`, 1024, 256. |
| `TSM_PROTOCOL_VERSION`, `TSM_CLIENT_VERSION` | The protocol version spoken (1) and this library's version. |

## Errors

A failing call returns its `tsm_error_kind`: the protocol's kinds
`TSM_ERR_LOCKED`, `TSM_ERR_DENIED`, `TSM_ERR_NOT_FOUND`, `TSM_ERR_AMBIGUOUS`,
`TSM_ERR_NEEDS_UNLOCK`, `TSM_ERR_UNAVAILABLE`, `TSM_ERR_OFFLINE`,
`TSM_ERR_TOKEN_EXPIRED`, `TSM_ERR_MALFORMED`, `TSM_ERR_TIMEOUT`,
`TSM_ERR_RATE_LIMITED`, `TSM_ERR_UNSUPPORTED`, `TSM_ERR_INTERNAL`, plus
`TSM_ERR_NOT_RUNNING` (no service found, or the connection lost) and the
library's own `TSM_ERR_INVALID_ARGUMENT` and `TSM_ERR_NO_MEMORY`.

`tsm_last_error(c)` gives the calling thread's last error (of any client;
`c` may be NULL): `kind`, `message` (for people; never a value, token or
key), `reason` (or NULL) and `retry_after_ms` (or -1). It stays valid until
the thread's next failing call.

An unknown kind from a later service is `TSM_ERR_INTERNAL`, and so is a
service that breaks the protocol (an answer frame over 1 MiB, an unknown
frame type or a malformed payload closes the connection). Denied, ambiguous
and not found are never retried; rate limits are waited out only with
`wait_on_rate_limit`.

## Configuration

The library looks for the service in the runtime directory of the OS user:

| OS | Where |
| --- | --- |
| any | `$TSM_RUNTIME_DIR` when set (containers, tests), or the `runtime_dir` option |
| Linux | `$XDG_RUNTIME_DIR/tsm/`, else `/tmp/tsm-<uid>/` |
| macOS | `$TMPDIR/tsm/`, else `/tmp/tsm-<uid>/` |
| Windows | `%LOCALAPPDATA%\TomSecretsManager\run\` (`client.port`, `client.token`) |

- No socket or port file, an unreadable port file or a refused connection is
  `TSM_ERR_NOT_RUNNING`.
- On Linux and macOS the endpoint is a Unix socket, whose path the OS limits
  to about 100 bytes: a `TSM_RUNTIME_DIR` may be relative to the working
  directory to stay under it.
- On Windows the client token is re-read at every connect, because it
  changes with every service start.

## Further documentation

| Document | What is there |
| --- | --- |
| [The protocol](../../protocol/protocol.md) | The reference grammar (section 4), the client endpoint (section 5), approvals and client tokens (section 7), the optional features (section 8), the error kinds (section 10) |
| [Conformance suite](../../conformance/README.md) | The fake service and the cases every client runs (runner `c`) |
| [tsm](../dart/tsm/README.md) | The command line: secrets for shell scripts, and administering the service |
| [Java client](../java/README.md) | The same client for Java |
| [CHANGELOG](CHANGELOG.md) | The changes per version |

## Developing

From this folder:

```sh
cmake -S . -B build -DTSM_WERROR=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

The tests run from this folder (they read `../../protocol/vectors`); `ctest`
sets that. On Windows, MSBuild refuses paths over 260 characters: a clone
deep in the file system, with a build folder below it, can exceed that
(enable long paths in Windows, or clone to a shorter path).

## Status

Version 0.1.0, protocol version 1 with the features `binary` and `getFile`.
The tests check the library against every vector of the protocol document
that a client computes (references, discovery, port files, frames) and
against a small service on a local socket; the conformance suite runs it
against the fake service. It builds with warnings as errors and passes its
tests and every conformance table on macOS (Apple clang), Linux (gcc 13 and
clang 18) and Windows (MSVC 2022, `/W4 /WX`; the conformance case for the
Windows endpoint included). The tests also pass under AddressSanitizer and
UBSan (with LeakSanitizer on Linux) and ThreadSanitizer, and the
conformance tables under AddressSanitizer and UBSan.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
