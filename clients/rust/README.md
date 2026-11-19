# tom-secrets-client (Rust)

> Part of the Tom Secrets Manager by Peter Nicolai Alexis Kyaw.

The Rust client of the Tom Secrets Manager: finds the local secrets service,
speaks its client protocol and parses and formats secret references.

## Overview

The Tom Secrets Manager keeps secrets in KDBX vaults and serves them to the
programs of one machine through a local **secrets service**. A program reads
a secret by its **reference** (`telegram.bot_token`,
`fleet/Db/Main#UserName`); the service resolves it, asks an approver when no
grant answers the request, and returns the value.

This crate is the program's side of that. It finds the service in the
runtime directory of the OS user, connects over a Unix socket (on Windows a
localhost port), and sends `get`, `getMany` and `getFile` requests. It never
opens a vault and never resolves a reference: the service does both.

The crate is `tom-secrets-client`; its library is `tom_secrets_client`. The
client blocks; the feature `tokio` adds an async client. Without that
feature the crate has no dependencies (its strict JSON, SHA-256 and RFC 3339
times are its own), and it logs nothing.

## Installation

```toml
[dependencies]
tom-secrets-client = "0.1"
# or, for the async client:
tom-secrets-client = { version = "0.1", features = ["tokio"] }
```

Rust 1.70 or later on Linux, macOS or Windows; the `tokio` feature needs the
Rust version tokio needs (1.85 for tokio 1.54). The secrets service must run
on the same machine, for the same OS user: the manager app starts it on a
desktop, `tsm start` on a server.

## Quick start

```rust,no_run
use tom_secrets_client::{Client, Error, GetOptions};

fn main() -> Result<(), Error> {
    let c = Client::connect()?;
    let v = match c.get(
        "[env:prod]db.main",
        GetOptions::default()
            .field("UserName")
            .on_progress(|p| eprintln!("waiting for {}", p.pending)),
    ) {
        Err(Error::Locked(_)) => {
            eprintln!("unlock the Tom Secrets Manager first");
            std::process::exit(1);
        }
        other => other?,
    };
    connect_to_database(v.text().unwrap_or_default());
    Ok(())
}

fn connect_to_database(user_name: &str) {
    println!("connecting as {user_name}");
}
```

With tokio (feature `tokio`):

```rust,ignore
let c = tom_secrets_client::tokio::Client::connect().await?;
let v = c.get("telegram.bot_token", GetOptions::default()).await?;
```

The first read of a secret by a program may wait for an approval: the
manager app (or a trusted device) asks the user. When no approver is
connected, `on_progress` hears the approval code to answer on a trusted
device.

## API

### `Client`

| Member | What it does |
| --- | --- |
| `Client::new(options)` | A client that connects on its first call. |
| `Client::connect()`, `Client::connect_with(options)` | A client connected at once, so a missing service shows as `NotRunning` right away. |
| `get(reference, GetOptions)` | Reads one secret; returns a `Value`. |
| `get_many(&[Request], RequestOptions)` | Reads 1 to 256 secrets under one approval prompt; returns `Vec<Result<Value>>` in request order. |
| `get_file(reference, GetOptions)` | Reads an attachment or a typed key as bytes, checked against its size and SHA-256; returns a `File`. Needs a service that offers the features `binary` and `getFile` (else `Unsupported`, `details["features"]` naming the missing ones). |
| `open()` | Connects, unless a connection is open. |
| `close()` | Closes the connection; a later call connects again. Dropping the client closes it too. |
| `welcome()` | The service's `welcome` on the current connection (`protocol`, `service_version`, `features`, `host`, `platform`, `offers(feature)`), or None. |
| `client_name()` | The name `hello` gives the program. |

- A `Client` is `Send` and `Sync`: calls from several threads overlap on its
  one connection.
- After `NotRunning` or a dropped connection, the next call connects again.

`ClientOptions` (every field optional):

| Field | Default | Meaning |
| --- | --- | --- |
| `client_name` | the executable's name | Shown in approval prompts; never trusted (the service measures the process). |
| `client_token` | none | A client token the program was granted before, sent with every connection. |
| `environment` | the process's environment | Where `TSM_RUNTIME_DIR` and the OS variables are read from. |
| `operating_system` | this process's | `linux`, `macos` or `windows`. |
| `connect_timeout` | 10 s | How long connecting and the service's `welcome` may take. |

`GetOptions` (fields, or the builder methods of the same names):

| Field | Meaning |
| --- | --- |
| `field` | The field, when the reference names none. |
| `dimensions` (`dimension(k, v)`) | Values for dimensions, `env` → `prod`, beside the reference. |
| `no_wait` | Answer at once instead of waiting for an unlock or an approval (`Locked` when locked). |
| `timeout` | How long the service may wait, in whole milliseconds, capped by the service. |
| `on_progress` | Called with a `Progress` (`pending`: `unlock` or `approval`; `approval_code` when no approver is connected) while the request waits; called on the connection's reader thread, so it must return quickly. |
| `want_client_token` | Ask for a client token with an "always" approval (`get` only; `get_file` does not send it). |
| `wait_on_rate_limit` | Wait out a `RateLimited` answer (its `retryAfterMs`, else one second) and send the request again. |

`RequestOptions` for `get_many` has `no_wait`, `timeout`, `on_progress` and
`wait_on_rate_limit`; each `Request` (`Request::new(reference)`, `.field()`,
`.dimension()`) carries its field and dimensions.

### `Value` and `File`

| Member | Meaning |
| --- | --- |
| `text()` | The value as `&str`; None for a binary value instead of corrupting it. |
| `bytes()` | The value as bytes (text as UTF-8). |
| `encoding` | `utf8` or `base64` (binary). |
| `reference` | The reference as asked for. |
| `entry` | `Entry { store, uuid, source, fetched_at }`; `source` is `github`, `file` or `cache`. |
| `bound` | The dimension values the winning entry carries. |
| `version` | `Version { modified, revision }`: compare it to see a change. |
| `expires` | The entry's expiry, or None. |
| `client_token` | A client token the service granted, or None. |

- Dropping a `Value` overwrites its buffer with zeros.
- No printable form shows the secret: `Display` and `Debug` give
  `SecretValue(db.main: ***)`.
- A `String` copied out of `text()` is yours to handle. The library
  overwrites the frames it read a value from once it has decoded them.
- A client token is yours to keep; pass it as `client_token` to a later
  client. The library never stores one.
- A `File` has `name`, `size()` and `bytes()` the same way, and is
  overwritten on drop.

### `Reference`

| Member | What it does |
| --- | --- |
| `Reference::parse(text)` | Parses a reference; a malformed one is an `Error::Malformed` whose `reason()` names the rule it broke. |
| `format()`, `canonical()`, `to_string()` | The canonical form. |
| `target` | `Target::Key(key)`, `Target::Path { store, segments }` or `Target::Uuid { store, uuid }`. |
| `field`, `field_given` | The effective field (`Password` when none is written) and whether one was written. |
| `qualifiers` | The bindings, `Binding { dimension, value }`, in the order written. |

```rust
use tom_secrets_client::Reference;

fn main() -> Result<(), tom_secrets_client::Error> {
    let r = Reference::parse("[host:server1,env:prod]fleet/Db/Main#Password")?;
    assert_eq!(r.canonical(), "[env:prod,host:server1]fleet/Db/Main");
    Ok(())
}
```

`get`, `get_many` and `get_file` parse every reference locally first: a
malformed one fails without a round trip, and so do a field named twice
(`field_twice`) and a request over 64 KiB (`frame`).

### Lower-level exports

| Export | What it is |
| --- | --- |
| `discover(os, environment, uid)` | The runtime directory and endpoint files the client looks for (`Endpoints`), or None. |
| `current_operating_system()` | `linux`, `macos` or `windows` for this process. |
| `read_port_file(text)` | The port of a Windows port file. |
| `json` | The strict JSON reader and the compact writer the crate uses. |
| `frames` | Frame encoding and the frame reader. |
| `DEFAULT_FIELD`, `MAX_REFERENCE_BYTES`, `MAX_GET_MANY` | `Password`, 1024, 256. |
| `PROTOCOL_VERSION`, `CLIENT_FEATURES`, `CLIENT_VERSION` | The protocol version spoken (1), the features `hello` offers, and this crate's version. |

### `tokio::Client` (feature `tokio`)

The same calls as `async fn`s (`connect`, `connect_with`, `open`, `get`,
`get_many`, `get_file`; `close`, `welcome`, `blocking()`), running the
blocking client on tokio's blocking pool, so a call never blocks a runtime
worker. Cloning it shares the one connection. Dropping a call's future does
not stop the request: it runs to its end and its answer is dropped; bound
the service's wait with `GetOptions::timeout` instead.

## Errors

Every failure is an `Error`, one variant per kind, each holding an
`ErrorInfo { message, details }`: `Locked`, `Denied`, `NotFound`,
`Ambiguous`, `NeedsUnlock`, `Unavailable`, `Offline`, `TokenExpired`,
`Malformed`, `Timeout`, `RateLimited`, `Unsupported`, `Internal`, and
`NotRunning` (no service found, or the connection lost). A call the program
gets wrong (a `get_many` of no references) is `Error::InvalidArgument`.

- `kind()` gives the `ErrorKind` (`as_str()` is the protocol's name,
  `not_found`), `info()` the message and details, `reason()` the shortcut
  for `details.reason`.
- The message is for people; it never holds a value, token or key.
- An unknown kind from a later service is `Internal`, and so is a service
  that breaks the protocol (an answer frame over 1 MiB, an unknown frame
  type or a malformed payload closes the connection).
- `Denied`, `Ambiguous` and `NotFound` are never retried; `RateLimited` is
  waited out only with `wait_on_rate_limit`.

## Configuration

The library looks for the service in the runtime directory of the OS user:

| OS | Where |
| --- | --- |
| any | `$TSM_RUNTIME_DIR` when set (containers, tests) |
| Linux | `$XDG_RUNTIME_DIR/tsm/`, else `/tmp/tsm-<uid>/` |
| macOS | `$TMPDIR/tsm/`, else `/tmp/tsm-<uid>/` |
| Windows | `%LOCALAPPDATA%\TomSecretsManager\run\` (`client.port`, `client.token`) |

- No socket or port file, an unreadable port file or a refused connection is
  `NotRunning`.
- On Linux and macOS the endpoint is a Unix socket, whose path the OS limits
  to about 100 bytes: a `TSM_RUNTIME_DIR` may be relative to the working
  directory to stay under it.
- On Windows the client token is re-read at every connect, because it
  changes with every service start.
- Pass `environment` to look elsewhere than the process's environment.

## Further documentation

| Document | What is there |
| --- | --- |
| [The protocol](../../protocol/protocol.md) | The reference grammar (section 4), the client endpoint (section 5), approvals and client tokens (section 7), the optional features (section 8), the error kinds (section 10) |
| [Conformance suite](../../conformance/README.md) | The fake service and the cases every client runs (runner `rust`) |
| [tsm](../dart/tsm/README.md) | The command line: secrets for shell scripts, and administering the service |
| [Go client](../go/README.md) | The same client for Go |
| [CHANGELOG](CHANGELOG.md) | The changes per version |

## Developing

```sh
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features
```

## Status

Version 0.1.0, protocol version 1 with the features `binary` and `getFile`.
The tests check the library against every vector of the protocol document
that a client computes (references, discovery, port files, frames) and
against a small service on a local socket, the tokio client included; the
conformance suite runs it against the fake service.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
