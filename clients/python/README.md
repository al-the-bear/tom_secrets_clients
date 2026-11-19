# tom-secrets-client

> Part of the Tom Secrets Manager by Peter Nicolai Alexis Kyaw.

The Python client of the Tom Secrets Manager: finds the local secrets
service, speaks its client protocol and parses and formats secret
references.

## Overview

The Tom Secrets Manager keeps secrets in KDBX vaults and serves them to the
programs of one machine through a local **secrets service**. A program reads
a secret by its **reference** (`telegram.bot_token`,
`fleet/Db/Main#UserName`); the service resolves it, asks an approver when no
grant answers the request, and returns the value.

This library is the program's side of that. It finds the service in the
runtime directory of the OS user, connects over a Unix socket (on Windows a
localhost port), and sends `get`, `getMany` and `getFile` requests. It never
opens a vault and never resolves a reference: the service does both.

The package is `tom-secrets-client`; its import name is `tsm`. It has no
dependencies (the standard library only) and logs nothing.

## Installation

```sh
pip install tom-secrets-client
```

Python 3.9 or later on Linux, macOS or Windows. The secrets service must run
on the same machine, for the same OS user: the manager app starts it on a
desktop, `tsm start` on a server.

## Quick start

```python
import tsm

with tsm.Client() as c:
    with c.get("[env:prod]db.main", field="UserName") as v:
        connect_to_database(v.text)
```

With asyncio:

```python
import asyncio
import tsm

async def main():
    async with tsm.aio.Client() as c:
        v = await c.get(
            "telegram.bot_token",
            on_progress=lambda p: print("waiting for", p.pending),
        )
        start_bot(v.text)
        v.close()

asyncio.run(main())
```

The first read of a secret by a program may wait for an approval: the
manager app (or a trusted device) asks the user. When no approver is
connected, `on_progress` hears the approval code to answer on a trusted
device.

## API

Everything below is exported from `tsm`.

### `Client` and `aio.Client`

`tsm.Client` blocks; `tsm.aio.Client` has the same options and calls as
coroutines. Both connect on their first call.

| Member | What it does |
| --- | --- |
| `Client(**options)` | A client that connects on its first call. |
| `Client.connect(**options)` | Creates a client and connects it at once, so a missing service shows as `not_running` right away (`await aio.Client.connect()`). |
| `get(ref, **options)` | Reads one secret; returns a `SecretValue`. |
| `get_many(requests, **options)` | Reads 1 to 256 secrets under one approval prompt; returns `SecretResult`s in request order, each with `value` or `error`. |
| `get_file(ref, **options)` | Reads an attachment or a typed key as bytes; returns a `SecretFile`. Needs a service that offers the features `binary` and `getFile` (else `unsupported`). |
| `open()` | Connects, unless a connection is open. |
| `close()` | Closes the connection; a later call connects again. A `with` (`async with`) block closes it. |
| `welcome` | The service's `welcome` on the current connection (`protocol`, `service_version`, `features`, `host`, `platform`), or `None`. |

- After `not_running` or a dropped connection, the next call connects again.
- Calls may overlap on the one connection: `tsm.Client` is thread-safe, and
  `aio.Client` calls may run together under `asyncio.gather`.
- `tsm.Client` runs its connection on a thread of its own. After `os.fork`
  the child opens a connection of its own; the parent's socket is never
  shared.

Client options (keyword-only):

| Option | Default | Meaning |
| --- | --- | --- |
| `client_name` | the script's name | Shown in approval prompts; never trusted (the service measures the process). |
| `client_token` | none | A client token the program was granted before, sent with every connection. |
| `environment` | `os.environ` | Where `TSM_RUNTIME_DIR` and the OS variables are read from. |
| `operating_system` | this process's | `linux`, `macos` or `windows`. |
| `connect_timeout` | `10.0` | Seconds connecting and the service's `welcome` may take. |

Request options (keyword-only):

| Option | Meaning |
| --- | --- |
| `wait` | Wait for an unlock or an approval (default `True`); `False` answers at once (`locked` when locked). |
| `timeout_ms` | How long the service may wait, capped by the service. |
| `on_progress` | Called with a `Progress` (`pending`: `unlock` or `approval`, `approval_code` when no approver is connected) while the request waits; with `tsm.Client`, on the client's thread. |
| `wait_on_rate_limit` | Wait out a `rate_limited` answer and send the request again (default off; not for `get_file`). |
| `field` (`get`, `get_file`) | The field, when the reference names none. |
| `dimensions` (`get`, `get_file`) | Values for dimensions, `{"env": "prod"}`, beside the reference. |
| `want_client_token` (`get` only) | Ask for a client token with an "always" approval. |

A `SecretRequest` for `get_many` is `SecretRequest(ref, field, dimensions)`.

### `SecretValue` and `SecretFile`

| Member | Meaning |
| --- | --- |
| `text` | The value as a string; raises `ValueError` for a binary value instead of corrupting it. |
| `data` | The value as a `memoryview` of the buffer (text as UTF-8); copy it to keep it. |
| `encoding` | `utf8` or `base64` (binary). |
| `reference` | The reference as asked for. |
| `entry` | `SecretEntry(store, uuid, source, fetched_at)`; `source` is `github`, `file` or `cache`. |
| `bound` | The dimension values the winning entry carries. |
| `version` | `SecretVersion(modified, revision)`: compare it to see a change. |
| `expires` | The entry's expiry (an aware `datetime`), or `None`. |
| `client_token` | A client token the service granted, or `None`. |
| `close()`, `closed` | Overwrites the buffer with zeros; the value cannot be read afterwards. A `with` block closes it. |

- No printable form shows the secret: `str`, `repr`, f-strings and `%s` give
  `SecretValue(db.main: ***)`.
- A `text` string taken out is an immutable Python string the library cannot
  overwrite: it is yours to handle.
- A client token is yours to keep; pass it as `client_token` to a later
  client. The library never stores one.
- A `SecretFile` has `name`, `size`, `data` and `close()` the same way.

### `SecretReference`

| Member | What it does |
| --- | --- |
| `SecretReference.parse(text)` | Parses a reference; a malformed one raises a `SecretsError` of kind `MALFORMED` whose `reason` names the rule it broke. |
| `SecretReference.format(ref)`, `ref.canonical`, `str(ref)` | The canonical form. |
| `SecretReference(target, qualifiers, field)` | Builds a reference from its parts. |
| `target` | `KeyTarget(key)`, `PathTarget(store, segments)` or `UuidTarget(store, uuid)`. |
| `field`, `field_given` | The effective field (`Password` when none is written) and whether one was written. |
| `qualifiers` | The bindings, `SecretBinding(dimension, value)`, in the order written. |

```python
tsm.SecretReference.parse("[host:server1,env:prod]fleet/Db/Main#Password").canonical
# '[env:prod,host:server1]fleet/Db/Main'
```

`get`, `get_many` and `get_file` parse every reference locally first: a
malformed one fails without a round trip, and so do a field named twice
(`field_twice`) and a request over 64 KiB (`frame`).

### Lower-level exports

| Export | What it is |
| --- | --- |
| `discover(operating_system, environment, uid)` | The runtime directory and endpoint files the client looks for (`Endpoints`, or `NoRuntimeDirectory`). |
| `DEFAULT_FIELD`, `MAX_GET_MANY` | `Password`, 256. |
| `PROTOCOL_VERSION`, `CLIENT_FEATURES`, `__version__` | The protocol version spoken (1), the features `hello` offers, and this library's version. |

## Errors

Every failure is a `SecretsError` (an `Exception`) with:

- `kind`, an `ErrorKind`: the protocol's kinds `LOCKED`, `DENIED`,
  `NOT_FOUND`, `AMBIGUOUS`, `NEEDS_UNLOCK`, `UNAVAILABLE`, `OFFLINE`,
  `TOKEN_EXPIRED`, `MALFORMED`, `TIMEOUT`, `RATE_LIMITED`, `UNSUPPORTED`,
  `INTERNAL`, plus `NOT_RUNNING` (no service found, or the connection lost);
  `kind.value` is the protocol's name (`not_found`);
- `message`, for people; never a value, token or key;
- `details` (`reason`, `candidates`, `retryAfterMs`, ...) and the shortcut
  `reason`.

```python
try:
    with tsm.Client() as c, c.get("db.main", wait=False) as v:
        use_secret(v.text)
except tsm.SecretsError as e:
    if e.kind is tsm.ErrorKind.LOCKED:
        print("unlock the Tom Secrets Manager first")
    else:
        raise
```

An unknown kind from a later service is `INTERNAL`, and so is a service that
breaks the protocol (an answer frame over 1 MiB, an unknown frame type or a
malformed payload closes the connection). `DENIED`, `AMBIGUOUS` and
`NOT_FOUND` are never retried; `RATE_LIMITED` is waited out only with
`wait_on_rate_limit=True`.

## Configuration

The library looks for the service in the runtime directory of the OS user:

| OS | Where |
| --- | --- |
| any | `$TSM_RUNTIME_DIR` when set (containers, tests) |
| Linux | `$XDG_RUNTIME_DIR/tsm/`, else `/tmp/tsm-<uid>/` |
| macOS | `$TMPDIR/tsm/`, else `/tmp/tsm-<uid>/` |
| Windows | `%LOCALAPPDATA%\TomSecretsManager\run\` (`client.port`, `client.token`) |

- No socket or port file, an unreadable port file or a refused connection is
  `NOT_RUNNING`.
- On Linux and macOS the endpoint is a Unix socket, whose path the OS limits
  to about 100 bytes: a `TSM_RUNTIME_DIR` may be relative to the working
  directory to stay under it.
- On Windows the client token is re-read at every connect, because it
  changes with every service start.
- Pass `environment` to the client to look elsewhere than `os.environ`.

## Further documentation

| Document | What is there |
| --- | --- |
| [The protocol](../../protocol/protocol.md) | The reference grammar (section 4), the client endpoint (section 5), approvals and client tokens (section 7), the optional features (section 8), the error kinds (section 10) |
| [Conformance suite](../../conformance/README.md) | The fake service and the cases every client runs (runner `python`) |
| [tsm](../dart/tsm/README.md) | The command line: secrets for shell scripts, and administering the service |
| [TypeScript client](../typescript/README.md) | The same client for Node.js |
| [CHANGELOG](CHANGELOG.md) | The changes per version |

## Developing

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Status

Version 0.1.0, protocol version 1 with the features `binary` and `getFile`.
The tests check the library against every vector of the protocol document
that a client computes (references, discovery, port files, frames) and
against a small service on a local socket, a fork included; the conformance
suite runs it against the fake service.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
