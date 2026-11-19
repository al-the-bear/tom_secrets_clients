# tom-secrets-client (Java)

> Part of the Tom Secrets Manager by Peter Nicolai Alexis Kyaw.

The Java client of the Tom Secrets Manager: finds the local secrets service,
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

The artifact is `net.kyaw.tom:tom-secrets-client`; its package is
`net.kyaw.tom.secrets` (automatic module name the same). It has no
dependencies, its strict JSON included, and logs nothing.

## Installation

```xml
<dependency>
  <groupId>net.kyaw.tom</groupId>
  <artifactId>tom-secrets-client</artifactId>
  <version>0.1.0</version>
</dependency>
```

Java 16 or later (for `UnixDomainSocketAddress`) on Linux, macOS or Windows.
The secrets service must run on the same machine, for the same OS user: the
manager app starts it on a desktop, `tsm start` on a server.

## Quick start

```java
import net.kyaw.tom.secrets.GetOptions;
import net.kyaw.tom.secrets.SecretValue;
import net.kyaw.tom.secrets.SecretsClient;
import net.kyaw.tom.secrets.SecretsException;

public final class Deploy {
    public static void main(String[] args) throws SecretsException {
        try (var c = SecretsClient.connect()) {
            var options = GetOptions.builder()
                    .field("UserName")
                    .onProgress(p -> System.err.println("waiting for " + p.pending()))
                    .build();
            try (SecretValue v = c.get("[env:prod]db.main", options)) {
                connectToDatabase(v.text());
            }
        } catch (SecretsException e) {
            if (e.kind() == SecretsException.Kind.LOCKED) {
                System.err.println("unlock the Tom Secrets Manager first");
            } else {
                throw e;
            }
        }
    }

    static void connectToDatabase(String userName) {
        System.out.println("connecting as " + userName);
    }
}
```

The first read of a secret by a program may wait for an approval: the
manager app (or a trusted device) asks the user. When no approver is
connected, `onProgress` hears the approval code to answer on a trusted
device.

## API

### `SecretsClient`

| Member | What it does |
| --- | --- |
| `new SecretsClient(options)` | A client that connects on its first call. |
| `SecretsClient.connect()`, `connect(options)` | A client connected at once, so a missing service shows as `NOT_RUNNING` right away. |
| `get(ref)`, `get(ref, GetOptions)` | Reads one secret; returns a `SecretValue`. |
| `getMany(List<SecretRequest>, RequestOptions)` | Reads 1 to 256 secrets under one approval prompt; returns `SecretResult`s in request order, each with `value()` or `error()`. |
| `getFile(ref, GetOptions)` | Reads an attachment or a typed key as bytes, checked against its size and SHA-256; returns a `SecretFile`. Needs a service that offers the features `binary` and `getFile` (else `UNSUPPORTED`, `details().get("features")` naming the missing ones). |
| `open()` | Connects, unless a connection is open. |
| `close()` | Closes the connection; a later call connects again (the client is `AutoCloseable`). |
| `welcome()` | The service's `welcome` on the current connection (`protocol`, `serviceVersion`, `features`, `host`, `platform`, `offers(feature)`), or null. |
| `clientName()` | The name `hello` gives the program. |

- A `SecretsClient` is thread-safe: calls from several threads overlap on
  its one connection.
- After `NOT_RUNNING` or a dropped connection, the next call connects again.

`ClientOptions.builder()`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `clientName(name)` | the main class's simple name (a jar's file name) | Shown in approval prompts; never trusted (the service measures the process). |
| `clientToken(token)` | none | A client token the program was granted before, sent with every connection. |
| `environment(map)` | `System.getenv()` | Where `TSM_RUNTIME_DIR` and the OS variables are read from. |
| `operatingSystem(name)` | this process's | `linux`, `macos` or `windows`. |
| `connectTimeout(duration)` | 10 s | How long connecting and the service's `welcome` may take. |

`GetOptions.builder()`:

| Setting | Meaning |
| --- | --- |
| `field(name)` | The field, when the reference names none. |
| `dimension(name, value)`, `dimensions(map)` | Values for dimensions, `env` = `prod`, beside the reference. |
| `noWait()` | Answer at once instead of waiting for an unlock or an approval (`LOCKED` when locked). |
| `timeout(duration)` | How long the service may wait, in whole milliseconds, capped by the service. |
| `onProgress(consumer)` | Called with a `Progress` (`pending()`: `unlock` or `approval`; `approvalCode()` when no approver is connected) while the request waits; called on the connection's reader thread, so it must return quickly. |
| `wantClientToken()` | Ask for a client token with an "always" approval (`get` only; `getFile` does not send it). |
| `waitOnRateLimit()` | Wait out a `RATE_LIMITED` answer (its `retryAfterMs`, else one second) and send the request again. |

`RequestOptions.builder()` for `getMany` has `noWait()`, `timeout()`,
`onProgress()` and `waitOnRateLimit()`; each `SecretRequest(ref, field,
dimensions)` (or `SecretRequest.of(ref)`) carries its field and dimensions.

### `SecretValue` and `SecretFile`

| Member | Meaning |
| --- | --- |
| `text()` | The value as a `String`; `IllegalStateException` for a binary value instead of corrupting it, and after `close()`. |
| `bytes()` | The value as bytes (text as UTF-8): the buffer itself, which `close()` overwrites; copy it to keep it. |
| `encoding()`, `isBinary()` | `utf8` or `base64` (binary). |
| `reference()` | The reference as asked for. |
| `entry()` | `SecretEntry(store, uuid, source, fetchedAt)`; `source` is `github`, `file` or `cache`. |
| `bound()` | The dimension values the winning entry carries. |
| `version()` | `SecretVersion(modified, revision)`: compare it to see a change. |
| `expires()` | The entry's expiry, or null. |
| `clientToken()` | A client token the service granted, or null. |
| `close()`, `isClosed()` | Overwrites the buffer with zeros; the value cannot be read afterwards. |

- `toString()` never shows the secret: `SecretValue(db.main: ***)`.
- A `String` taken out with `text()` is an immutable Java string the library
  cannot overwrite: it is yours to handle. The library overwrites the frames
  it read a value from once it has decoded them.
- A client token is yours to keep; pass it as `clientToken` to a later
  client. The library never stores one.
- A `SecretFile` has `name()`, `size()`, `bytes()` and `close()` the same
  way.

### `SecretReference`

| Member | What it does |
| --- | --- |
| `SecretReference.parse(text)` | Parses a reference; a malformed one is a `SecretsException` of kind `MALFORMED` whose `reason()` names the rule it broke. |
| `SecretReference.format(ref)`, `canonical()`, `toString()` | The canonical form. |
| `target()` | `Target.key(key)`, `Target.path(store, segments)` or `Target.uuid(store, uuid)` (`kind()` says which). |
| `field()`, `fieldGiven()` | The effective field (`Password` when none is written) and whether one was written. |
| `qualifiers()` | The bindings, `Binding(dimension, value)`, in the order written. |

```java
SecretReference.parse("[host:server1,env:prod]fleet/Db/Main#Password").canonical();
// "[env:prod,host:server1]fleet/Db/Main"
```

`get`, `getMany` and `getFile` parse every reference locally first: a
malformed one fails without a round trip, and so do a field named twice
(`field_twice`) and a request over 64 KiB (`frame`).

### Lower-level exports

| Export | What it is |
| --- | --- |
| `Discovery.discover(os, environment, uid)` | The runtime directory and endpoint files the client looks for (`Endpoints`), or empty. |
| `Discovery.currentOperatingSystem()` | `linux`, `macos` or `windows` for this process. |
| `Discovery.readPortFile(text)` | The port of a Windows port file. |
| `Json` | The strict JSON reader and the compact writer the library uses. |
| `SecretReference.DEFAULT_FIELD`, `MAX_REFERENCE_BYTES`, `SecretsClient.MAX_GET_MANY` | `Password`, 1024, 256. |
| `SecretsClient.PROTOCOL_VERSION`, `CLIENT_FEATURES`, `CLIENT_VERSION` | The protocol version spoken (1), the features `hello` offers, and this library's version. |

## Errors

Every failure from the service or about it is a `SecretsException` (a
checked exception) with:

- `kind()`, a `SecretsException.Kind`: the protocol's kinds `LOCKED`,
  `DENIED`, `NOT_FOUND`, `AMBIGUOUS`, `NEEDS_UNLOCK`, `UNAVAILABLE`,
  `OFFLINE`, `TOKEN_EXPIRED`, `MALFORMED`, `TIMEOUT`, `RATE_LIMITED`,
  `UNSUPPORTED`, `INTERNAL`, plus `NOT_RUNNING` (no service found, or the
  connection lost); `wireName()` is the protocol's name (`not_found`);
- `getMessage()`, for people; never a value, token or key;
- `details()` (`reason`, `candidates`, `retryAfterMs`, ...) and the shortcut
  `reason()`.

A call the program gets wrong (a `getMany` of no references) is an
`IllegalArgumentException`. An unknown kind from a later service is
`INTERNAL`, and so is a service that breaks the protocol (an answer frame
over 1 MiB, an unknown frame type or a malformed payload closes the
connection). `DENIED`, `AMBIGUOUS` and `NOT_FOUND` are never retried;
`RATE_LIMITED` is waited out only with `waitOnRateLimit()`.

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
- Pass `environment` to look elsewhere than the process's environment.

## Further documentation

| Document | What is there |
| --- | --- |
| [The protocol](../../protocol/protocol.md) | The reference grammar (section 4), the client endpoint (section 5), approvals and client tokens (section 7), the optional features (section 8), the error kinds (section 10) |
| [Conformance suite](../../conformance/README.md) | The fake service and the cases every client runs (runner `java`) |
| [tsm](../dart/tsm/README.md) | The command line: secrets for shell scripts, and administering the service |
| [Rust client](../rust/README.md) | The same client for Rust |
| [CHANGELOG](CHANGELOG.md) | The changes per version |

## Developing

The library and its tests need nothing but a JDK. From this folder:

```sh
javac --release 16 -Xlint:all -Werror -d build/test-classes $(find src -name '*.java')
java -cp build/test-classes net.kyaw.tom.secrets.AllTests
```

`AllTests` is a plain main class (no test framework) and exits 1 when a test
fails. The `pom.xml` describes the artifact for Maven Central; its build
skips the tests, which the product's CI runs as above.

## Status

Version 0.1.0, protocol version 1 with the features `binary` and `getFile`.
The tests check the library against every vector of the protocol document
that a client computes (references, discovery, port files, frames) and
against a small service on a local socket; the conformance suite runs it
against the fake service. It is built and tested with `javac --release 16`
on a JDK 17; the Maven build of the `pom.xml` is not run here yet (its
release to Maven Central is to come).

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
