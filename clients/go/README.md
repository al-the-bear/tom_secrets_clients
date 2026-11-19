# Go client (`clients/go`)

> Part of the Tom Secrets Manager by Peter Nicolai Alexis Kyaw.

The Go client of the Tom Secrets Manager: finds the local secrets service,
speaks its client protocol and parses and formats secret references.

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

The module is `github.com/al-the-bear/tom_secrets_clients/clients/go`; its
package is `tsm`. It uses the standard library only and logs nothing.

## Installation

```sh
go get github.com/al-the-bear/tom_secrets_clients/clients/go
```

Go 1.22 or later on Linux, macOS or Windows. The secrets service must run on
the same machine, for the same OS user: the manager app starts it on a
desktop, `tsm start` on a server.

## Quick start

```go
package main

import (
	"context"
	"errors"
	"log"

	tsm "github.com/al-the-bear/tom_secrets_clients/clients/go"
)

func main() {
	ctx := context.Background()
	c, err := tsm.Connect(ctx)
	if err != nil {
		log.Fatal(err) // tsm: not_running: the secrets service is not running: ...
	}
	defer c.Close()

	v, err := c.Get(ctx, "[env:prod]db.main", tsm.WithField("UserName"),
		tsm.WithProgress(func(p tsm.Progress) { log.Println("waiting for", p.Pending) }))
	var e *tsm.Error
	if errors.As(err, &e) && e.Kind == tsm.KindLocked {
		log.Fatal("unlock the Tom Secrets Manager first")
	} else if err != nil {
		log.Fatal(err)
	}
	defer v.Close()
	name, _ := v.Text()
	connectToDatabase(name)
}
```

The first read of a secret by a program may wait for an approval: the
manager app (or a trusted device) asks the user. When no approver is
connected, `WithProgress` hears the approval code to answer on a trusted
device.

## API

### `Client`

| Member | What it does |
| --- | --- |
| `New(options...)` | A client that connects on its first call. |
| `Connect(ctx, options...)` | Creates a client and connects it at once, so a missing service shows as `not_running` right away. |
| `Get(ctx, ref, options...)` | Reads one secret; returns a `*Value`. |
| `GetMany(ctx, requests, options...)` | Reads 1 to 256 secrets under one approval prompt; returns `[]Result` in request order, each with `Value` or `Err`. |
| `GetFile(ctx, ref, options...)` | Reads an attachment or a typed key as bytes, checked against its size and SHA-256; returns a `*File`. Needs a service that offers the features `binary` and `getFile` (else `unsupported`, `Details["features"]` naming the missing ones). |
| `Open(ctx)` | Connects, unless a connection is open. |
| `Close()` | Closes the connection; a later call connects again. |
| `Welcome()` | The service's `welcome` on the current connection (`Protocol`, `ServiceVersion`, `Features`, `Host`, `Platform`, `Offers(feature)`), or nil. |
| `ClientName()` | The name `hello` gives the program. |

- A `Client` is safe for concurrent use; calls from several goroutines
  overlap on its one connection.
- After `not_running` or a dropped connection, the next call connects again.
- A cancelled or expired `ctx` ends the call with `ctx.Err()`; the
  connection stays open, and the late answer is dropped.

Client options:

| Option | Default | Meaning |
| --- | --- | --- |
| `WithClientName(name)` | the executable's name | Shown in approval prompts; never trusted (the service measures the process). |
| `WithClientToken(token)` | none | A client token the program was granted before, sent with every connection. |
| `WithEnvironment(map)` | the process's environment | Where `TSM_RUNTIME_DIR` and the OS variables are read from. |
| `WithOperatingSystem(name)` | this process's | `linux`, `macos` or `windows`. |
| `WithConnectTimeout(d)` | 10 s | How long connecting and the service's `welcome` may take. |

Request options:

| Option | Meaning |
| --- | --- |
| `NoWait()` | Answer at once instead of waiting for an unlock or an approval (`locked` when locked). |
| `WithTimeout(d)` | How long the service may wait, in whole milliseconds, capped by the service. |
| `WithProgress(f)` | Called with a `Progress` (`Pending`: `unlock` or `approval`; `ApprovalCode` when no approver is connected) while the request waits; called on the connection's reader goroutine, so it must return quickly. |
| `WaitOnRateLimit()` | Wait out a `rate_limited` answer (its `retryAfterMs`, else one second) and send the request again. |
| `WithField(field)` (`Get`, `GetFile`) | The field, when the reference names none. |
| `WithDimensions(map)` (`Get`, `GetFile`) | Values for dimensions, `{"env": "prod"}`, beside the reference. |
| `WithClientTokenRequest()` (`Get` only) | Ask for a client token with an "always" approval. |

A `Request` for `GetMany` is `{Ref, Field, Dimensions}`. Options that do not
apply to a call, and a `GetMany` of no or more than 256 references, are a
plain error (not an `*Error`).

### `Value` and `File`

| Member | Meaning |
| --- | --- |
| `Text()` | The value as a string; `ErrBinary` for a binary value instead of corrupting it, `ErrClosed` after `Close`. |
| `Bytes()` | The value as bytes (text as UTF-8): the buffer itself, which `Close` overwrites; copy it to keep it. |
| `Encoding` | `utf8` or `base64` (binary). |
| `Reference` | The reference as asked for. |
| `Entry` | `{Store, UUID, Source, FetchedAt}`; `Source` is `github`, `file` or `cache`. |
| `Bound` | The dimension values the winning entry carries. |
| `Version` | `{Modified, Revision}`: compare it to see a change. |
| `Expires` | The entry's expiry, or nil. |
| `ClientToken` | A client token the service granted, or `""`. |
| `Close()`, `Closed()` | Overwrites the buffer with zeros; the value cannot be read afterwards. |

- No printable form shows the secret: every `fmt` verb (`%v`, `%+v`, `%#v`,
  `%s`, `%q`, `%x`, ...), `encoding/json` and `log/slog` give
  `SecretValue(db.main: ***)`. Pass a `*Value`, never a copy of the struct.
- A string taken out with `Text` is an immutable Go string the library cannot
  overwrite: it is yours to handle. The library overwrites the frames it read
  a value from once it has decoded them.
- A client token is yours to keep; pass it as `WithClientToken` to a later
  client. The library never stores one.
- A `File` has `Name`, `Size()`, `Bytes()` and `Close()` the same way.

### `Reference`

| Member | What it does |
| --- | --- |
| `ParseReference(text)` | Parses a reference; a malformed one is an `*Error` of kind `KindMalformed` whose `Reason()` names the rule it broke. |
| `FormatReference(ref)`, `ref.Canonical()`, `ref.String()` | The canonical form. |
| `Target` | `{Kind, Key}` (`TargetKey`), `{Kind, Store, Segments}` (`TargetPath`) or `{Kind, Store, UUID}` (`TargetUUID`). |
| `Field`, `FieldGiven` | The effective field (`Password` when none is written) and whether one was written. |
| `Qualifiers` | The bindings, `Binding{Dimension, Value}`, in the order written. |

```go
r, _ := tsm.ParseReference("[host:server1,env:prod]fleet/Db/Main#Password")
r.Canonical() // "[env:prod,host:server1]fleet/Db/Main"
```

`Get`, `GetMany` and `GetFile` parse every reference locally first: a
malformed one fails without a round trip, and so do a field named twice
(`field_twice`) and a request over 64 KiB (`frame`).

### Lower-level exports

| Export | What it is |
| --- | --- |
| `Discover(os, environment, uid)` | The runtime directory and endpoint files the client looks for (`Endpoints`), or `ok == false`. |
| `CurrentOperatingSystem()` | `linux`, `macos` or `windows` for this process. |
| `ReadPortFile(text)` | The port of a Windows port file. |
| `ErrorKindFromWire(kind)`, `KindOf(err)` | Map a protocol name to its kind; the kind of an error. |
| `DefaultField`, `MaxReferenceBytes`, `MaxGetMany` | `Password`, 1024, 256. |
| `ProtocolVersion`, `ClientFeatures`, `ClientVersion` | The protocol version spoken (1), the features `hello` offers, and this library's version. |

## Errors

Every failure from the service or about it is an `*Error` with:

- `Kind`, an `ErrorKind`: the protocol's kinds `KindLocked`, `KindDenied`,
  `KindNotFound`, `KindAmbiguous`, `KindNeedsUnlock`, `KindUnavailable`,
  `KindOffline`, `KindTokenExpired`, `KindMalformed`, `KindTimeout`,
  `KindRateLimited`, `KindUnsupported`, `KindInternal`, plus `KindNotRunning`
  (no service found, or the connection lost); its value is the protocol's
  name (`not_found`);
- `Message`, for people; never a value, token or key;
- `Details` (`reason`, `candidates`, `retryAfterMs`, ...; numbers as
  `json.Number`) and the shortcut `Reason()`.

Use it with `errors.As`, or `tsm.KindOf(err)`. An unknown kind from a later
service is `KindInternal`, and so is a service that breaks the protocol (an
answer frame over 1 MiB, an unknown frame type or a malformed payload closes
the connection). `KindDenied`, `KindAmbiguous` and `KindNotFound` are never
retried; `KindRateLimited` is waited out only with `WaitOnRateLimit()`.

## Configuration

The library looks for the service in the runtime directory of the OS user:

| OS | Where |
| --- | --- |
| any | `$TSM_RUNTIME_DIR` when set (containers, tests) |
| Linux | `$XDG_RUNTIME_DIR/tsm/`, else `/tmp/tsm-<uid>/` |
| macOS | `$TMPDIR/tsm/`, else `/tmp/tsm-<uid>/` |
| Windows | `%LOCALAPPDATA%\TomSecretsManager\run\` (`client.port`, `client.token`) |

- No socket or port file, an unreadable port file or a refused connection is
  `KindNotRunning`.
- On Linux and macOS the endpoint is a Unix socket, whose path the OS limits
  to about 100 bytes: a `TSM_RUNTIME_DIR` may be relative to the working
  directory to stay under it.
- On Windows the client token is re-read at every connect, because it
  changes with every service start.
- Pass `WithEnvironment` to look elsewhere than the process's environment.

## Further documentation

| Document | What is there |
| --- | --- |
| [The protocol](../../protocol/protocol.md) | The reference grammar (section 4), the client endpoint (section 5), approvals and client tokens (section 7), the optional features (section 8), the error kinds (section 10) |
| [Conformance suite](../../conformance/README.md) | The fake service and the cases every client runs (runner `go`) |
| [tsm](../dart/tsm/README.md) | The command line: secrets for shell scripts, and administering the service |
| [Python client](../python/README.md) | The same client for Python |
| [CHANGELOG](CHANGELOG.md) | The changes per version |

## Developing

```sh
go vet ./...
go test -race ./...
```

## Status

Version 0.1.0, protocol version 1 with the features `binary` and `getFile`.
The tests check the library against every vector of the protocol document
that a client computes (references, discovery, port files, frames) and
against a small service on a local socket, under the race detector; the
conformance suite runs it against the fake service.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
