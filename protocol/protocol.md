# Tom Secrets Manager protocol, version 1

This document is the authority for how programs talk to the Tom Secrets
Manager's secrets service: how a client finds the service, the frames on a
connection, the reference grammar, every message of the client and the admin
endpoint, the error kinds and versioning. The JSON Schemas in
[`schema/`](schema/) and the test vectors in [`vectors/`](vectors/) are
derived from it and checked against it by `tool/check_protocol.py`; where
they disagree with this text, this text wins and they are wrong.

Every part is **phase A** unless marked **[B]** or **[C]**. A phase-B part is
specified here already, so that its wire format is fixed from the start; a
phase-A implementation does not send it and refuses it as section 8 says.

Section 9 specifies the signed objects (grants, revocations, approval records
and key-change statements), the approval code and its token, and the approval
link with its handshake.

## 1. Endpoints

The service offers two local endpoints, kept apart so that a client library
can never reach an admin operation by mistake:

| Endpoint | Who | Messages |
| --- | --- | --- |
| client | any program of the service's OS user | `hello`, `get`, `getMany`; **[B]** `getFile`, `match`, `propose` |
| admin | the manager app and `tsm` | the challenge (`challenge`, `auth`, `authed`, `claim`), then the admin requests of section 6 |

A third, the **approval link** between a host's service and the manager apps
of the user's other devices, runs over its own handshake (section 9).

**[B]** The service also serves an **ssh-agent** endpoint that speaks the SSH
agent protocol (draft-miller-ssh-agent), not these frames: `agent.sock` in the
runtime directory on Linux and macOS, the named pipe `\\.\pipe\tsm-ssh-agent`
on Windows. `ssh` finds it through `SSH_AUTH_SOCK` or `IdentityAgent`. What it
answers and how its signatures are approved is 7.6.

Clients only read. Nothing on the client endpoint changes a store.

## 2. Framing

### 2.1 Frames

A connection carries frames in both directions. A frame is:

| Bytes | Content |
| --- | --- |
| 4 | the payload length `n`, unsigned, big-endian; the length counts the payload only, not this field or the type |
| 1 | the frame type |
| `n` | the payload |

| Type | Payload |
| --- | --- |
| `0` | one UTF-8 JSON object (2.2) |
| `1` | **[B]** a binary chunk (2.5) |
| other | reserved; a receiver closes the connection |

### 2.2 JSON payloads

- The payload is exactly one JSON object (RFC 8259) in UTF-8, without a byte
  order mark. Any whitespace and member order is accepted; the vectors use the
  compact form.
- An object with a duplicate member name, or a payload that is empty, not
  UTF-8, not JSON or not an object, is **malformed** (2.4).
- Every object has the member `op`, a string naming the message. Its other
  members are listed in sections 5 and 6 and in the message's schema.
- A receiver ignores members it does not know (section 8).
- Byte strings (keys, nonces, MACs, binary values, files) are standard base64
  with padding (RFC 4648 section 4). Times are RFC 3339 date-times in UTC
  ending in `Z` (`2026-11-13T09:00:00Z`, fractional seconds allowed), except
  `serviceStart` and `service.start`, which are integers of milliseconds since
  the Unix epoch.

### 2.3 Limits

| What | Limit |
| --- | --- |
| a frame sent to the service (a request) | payload at most 64 KiB (65,536 bytes) |
| a frame sent by the service (an answer, a progress notice, an event) | payload at most 1 MiB (1,048,576 bytes) |
| a reference | at most 1 KiB (1,024 bytes) of UTF-8, as sent |

A receiver checks the length field before reading the payload: a frame over
its limit closes the connection without the payload being read. Content
larger than an answer frame is sent as binary chunks **[B]**.

### 2.4 Invalid frames

| Received | What the receiver does |
| --- | --- |
| a length over the limit | closes the connection |
| an unknown frame type, or type `1` where binary frames were not negotiated (section 8) | closes the connection |
| a malformed JSON payload (2.2) | the service answers `error` with kind `malformed` (no `id`) and closes the connection; a client closes the connection |
| a client's first frame that is not `hello`, or an admin's first frame that is neither `auth` nor `claim` | as a malformed payload |

`vectors/frames.json` lists these cases (`invalid`) with the outcome
expected.

### 2.5 Binary chunks [B]

A binary frame (type `1`) carries part of a `getFile` answer. Its payload is
the request `id` as 8 bytes, unsigned, big-endian, followed by the chunk
(at most 1 MiB minus 8 bytes). The chunks of one answer follow its `file`
message in order and are ended by its `end` message, whose `sha256` is the
SHA-256 of all chunks joined. Binary frames are sent only on a connection
where both sides announced the feature `binary` (section 8).

### 2.6 Requests, answers and ids

- Every request after the first frame carries `id`: a JSON integer from 1 to
  2^53 − 1, chosen by the client and unique among that client's requests that
  are still open on the connection. Its answer, any `progress` notice for it
  and an error about it repeat the `id`.
- Requests on one connection may overlap: a `get` waiting for an unlock does
  not block a second `get`, and answers may come in any order. A request whose
  `id` equals an open request's is answered `error` `malformed` (reason
  `duplicate_id`) and the open request goes on.
- `hello`, `welcome`, the challenge messages and the admin events have no
  `id`. An `error` without an `id` concerns the connection and is followed by
  the connection closing.
- A connection stays open for as long as the client likes. A library keeps
  one per process and reconnects after a dropped connection or `not_running`.

## 3. Finding the service

### 3.1 The runtime directory

A client looks for the service in the **runtime directory** of its OS user:

| OS | Runtime directory |
| --- | --- |
| any | `$TSM_RUNTIME_DIR`, when it is set and not empty (containers and tests) |
| Linux | `$XDG_RUNTIME_DIR/tsm/` when `$XDG_RUNTIME_DIR` is set to an absolute path, else `/tmp/tsm-<uid>/` |
| macOS | `$TMPDIR/tsm/` when `$TMPDIR` is set to an absolute path (the per-user `/var/folders/…/T/`), else `/tmp/tsm-<uid>/` |
| Windows | `%LOCALAPPDATA%\TomSecretsManager\run\` when `LOCALAPPDATA` is set, else `%USERPROFILE%\AppData\Local\TomSecretsManager\run\`; with neither, the service is `not_running` |

Trailing separators of an environment value are dropped before the name is
joined. `<uid>` is the user's numeric id.

### 3.2 What is in it

| File | OS | Content |
| --- | --- | --- |
| `client.sock` | Linux, macOS | the client endpoint, a Unix domain socket |
| `admin.sock` | Linux, macOS | the admin endpoint, a Unix domain socket |
| `client.port` | Windows | the client endpoint's localhost TCP port |
| `client.token` | Windows | the client token of this service start |
| `admin.port` | Windows | the admin endpoint's localhost TCP port |
| `agent.sock` | Linux, macOS | **[B]** the ssh-agent endpoint, a Unix domain socket (7.6); on Windows the agent is the named pipe `\\.\pipe\tsm-ssh-agent`, whose ACL admits only the service's user and SYSTEM |
| `service.lock` | all | the single-instance lock (not for clients) |
| `service.json` | all | `{pid, start, protocol, client, admin, agent?}`: the service's PID, its start (milliseconds since the epoch), the protocol version and the endpoints (`{socket}` or `{port}`; **[B]** the ssh-agent's `{socket}` or `{pipe}` while it runs); no secret, for diagnostics |

- A **port file** holds the port in decimal, 1 to 65535, without a sign or
  leading zeros, optionally followed by one line end (LF or CR LF).
- **`client.token`** holds 32 random bytes in base64 (44 characters),
  optionally followed by one line end. It changes with every service start,
  so a library re-reads it at every connect and sends it as `hello.token`.
- The directory is the user's alone (mode 0700; on Windows an ACL of the user
  and SYSTEM). The service checks its owner and mode at every start.

A library that finds no socket or port file, finds an unreadable port file,
or has its connection refused reports **`not_running`**. `not_running` is not
a message: no one sends it.

`vectors/discovery.json` pins the directory per OS and environment, and the
port files with the port each yields.

## 4. References

A reference names a secret: an entry and one of its fields, optionally with
dimension values. Every component that handles references — the service, the
client libraries, `tsm`, the editor, the `tom_core_secrets` provider — parses
and formats them by this section. A client never resolves a reference; it
sends it and the service answers.

### 4.1 Grammar

```ebnf
reference   = [ qualifiers ] , target , [ "#" , field ] ;
qualifiers  = "[" , binding , { "," , binding } , "]" ;
binding     = name , ":" , value ;
target      = key | path | uuid-ref ;
key         = name , { "." , name } ;              (* no "/" : a key *)
path        = store , "/" , segment , { "/" , segment } ;
uuid-ref    = store , "/~" , 32 * hexdigit ;       (* the entry's UUID *)
store       = ( lower | digit ) , { lower | digit | "_" | "-" } ;
field       = segment ;
name        = lower , { lower | digit | "_" | "-" } ;
value       = segment ;
segment     = char , { char } ;
char        = any character except the reserved and the control characters
            | escape ;
reserved    = "/" | "#" | "[" | "]" | "," | ":" | "%" ;
escape      = "%" , hexdigit , hexdigit ;          (* one UTF-8 byte *)
lower       = "a" … "z" ;
digit       = "0" … "9" ;
hexdigit    = digit | "a" … "f" | "A" … "F" ;
```

- The control characters are U+0000 to U+001F and U+007F; they appear only
  escaped.
- A target without an unescaped `/` is a key; with one, a path (or a uuid
  reference). A path always names its store.
- The escapes of a segment, taken together with its other characters as
  UTF-8, must decode as well-formed UTF-8 (no overlong forms, no surrogates).
- A reference is at most 1,024 bytes of UTF-8, counted as sent (escapes
  count as three bytes).

### 4.2 What the parts mean

- A **key** is the value of an entry's `tsm.key` field (`telegram.bot_token`);
  the service looks it up in every store it serves.
- A **path** is a store name, the group path below the store's root group and
  the entry title: `fleet/Cloud/AWS/root`.
- A **uuid reference** names an entry by its KDBX UUID: `fleet/~<32 hex>`. It
  survives renames and moves.
- A **field** is a KDBX string field (`Title`, `UserName`, `Password`, `URL`,
  `Notes`, or a custom one), an attachment (`attachment:<name>`, written
  `attachment%3A<name>` because `:` is reserved), or the virtual field `totp`
  (the current code). Without `#field` the field is `Password`. Field names
  match case-sensitively.
- A **binding** `<dimension>:<value>` gives a dimension a value for this
  request: `[env:prod]db.main`.

### 4.3 Escaping

A reserved character inside a group name, title, field or value is written
as `%` and the two hex digits of each of its UTF-8 bytes: `/` `%2F`, `#`
`%23`, `[` `%5B`, `]` `%5D`, `,` `%2C`, `:` `%3A`, `%` `%25`. Percent-encoding
rather than a backslash keeps a reference splittable at its last `#` by
`tom_core_secrets`. Any other character may also be escaped; the canonical
form (4.5) escapes only what it must.

### 4.4 Reserved prefixes

A path segment whose first character is an unescaped `@` or `~` is
malformed, except the single segment of a uuid reference (`~` and exactly 32
hex digits, nothing after it). `@` begins the overlay groups that the service
resolves itself, so they are never addressed by path, and `~` begins a uuid
reference. A group or entry whose name begins with `@` or `~` is written
`%40…` or `%7E…`.

### 4.5 The canonical form

Formatting a parsed reference gives its **canonical form**, which grants,
the audit log and approval prompts use:

- the bindings sorted by dimension name (byte order of their UTF-8);
- every segment escaped in exactly the reserved characters, the control
  characters and, in a path segment, a leading `@` or `~`, with upper-case hex
  digits;
- the uuid in lower case;
- the field omitted when it is `Password`.

So `[host:bomber,env:prod]fleet/Cloud/AWS/root#Password` and
`[env:prod,host:bomber]fleet/Cloud/AWS/root` are the same reference. Parsing a
canonical form and formatting it again gives the same text.

### 4.6 Malformed references

A reference that does not parse is refused with kind `malformed`, and
`details.reason` names the first rule it broke:

| Reason | The reference |
| --- | --- |
| `empty` | is empty |
| `too_long` | is over 1,024 bytes |
| `empty_segment` | has an empty segment, binding value, field or bracket pair (`fleet//X`, `[env:]x`, `[]x`, `x#`) |
| `unclosed_qualifiers` | opens `[` without a closing `]` |
| `empty_target` | has no target (`[env:prod]`, `#UserName`) |
| `bad_binding` | has a binding that is not one `name:value` pair |
| `bad_dimension` | binds a name that is not a dimension name |
| `duplicate_dimension` | binds the same dimension twice |
| `bad_key` | has a key that is not dotted names (`Db.main`, `db..main`) |
| `bad_store` | has a path whose store is not a store name |
| `bad_uuid` | has a `~` segment that is not 32 hex digits |
| `reserved_prefix` | has a path segment beginning with an unescaped `@` or `~` (4.4) |
| `reserved_character` | has an unescaped reserved character where none may stand (a second `#`, a `:` in a segment) |
| `bad_escape` | has a `%` not followed by two hex digits |
| `bad_utf8` | has escapes that do not decode as well-formed UTF-8 |
| `control_character` | has an unescaped control character |

A library refuses such a reference locally, without a round trip.
`vectors/references.json` pins every valid input with its parse result and
canonical form, every reason with inputs, and formatting from parse results.

### 4.7 Dimensions in a request

The service, not the client, decides a request's value per dimension: a
binding in the brackets, else a value in the request's `dimensions`, else the
machine's current value, else the configured default, else `default`. These
are refused by the service as `malformed` (they need the service's
configuration, so a library cannot check them):

| Reason | The request |
| --- | --- |
| `conflicting_dimension` | binds a dimension in the brackets and gives it another value in `dimensions` |
| `undeclared_dimension` | names a dimension the shared configuration does not declare |
| `field_twice` | names a field both in the reference and in `field` |

How the service then finds and ranks candidates is the resolution of the
idea document's part-structure (overlays, ranking, `fallback_to_default`).

## 5. The client endpoint

### 5.1 `hello` and `welcome`

The client's first frame is `hello`:

| Member | Content |
| --- | --- |
| `protocol` | the protocol version the client speaks, `1` |
| `client` | `{name, version, language}`: the program's name (default its executable's), the library's version and language; shown in prompts, never trusted |
| `token` | Windows: the text of `client.token` (3.2); a wrong or missing token is `denied` |
| `clientToken` | a client token the program was given before (7.4), when it has one |
| `features` | **[B]** the optional features the client takes (section 8), e.g. `["binary","getFile"]`; absent is none |

The service answers `welcome`:

| Member | Content |
| --- | --- |
| `protocol` | the version it will speak on this connection, `1` |
| `service` | `{version}` |
| `features` | the optional features it offers (section 8): a phase-B service offers `binary`, `getFile`, `match` and `propose`; a phase-A service none |
| `host` | its host name (the current value of the `host` dimension) |
| `platform` | `macos`, `linux`, `windows`, `ios` or `android` |

When it does not speak the client's protocol it answers `error` `unsupported`
with `details.protocols` (the versions it speaks) and closes the connection; a
wrong Windows token is answered `error` `denied` (reason `bad_token`) and the
connection closed.

### 5.2 `get` and `value`

`get` reads one secret:

| Member | Content |
| --- | --- |
| `id` | the request id |
| `ref` | the reference (section 4) |
| `dimensions` | values for dimensions, beside the reference: `{"env": "prod"}` |
| `field` | the field, when the reference names none |
| `wait` | whether to wait for an unlock or an approval, default `true` |
| `timeoutMs` | how long to wait, capped by the service's approval timeout |
| `wantClientToken` | ask for a client token with an "always" approval (7.4) |

The answer is `value`:

| Member | Content |
| --- | --- |
| `id` | the request id |
| `value` | the value: the text, or the bytes in base64 |
| `encoding` | `utf8` for text, `base64` for bytes; a library refuses text access to a `base64` value |
| `entry` | `{store, uuid, source, fetchedAt}`: the entry's store and UUID; `source` is `github` when the store was fetched from GitHub in this refresh cycle, `file` when it is a `file:` vault read from the local disk in this cycle, and `cache` when the service serves its offline copy of a GitHub store; `fetchedAt` the last successful fetch or read |
| `bound` | the bindings the winning entry carries, `{dimension: value}` |
| `version` | `{modified, revision}`: the entry's last modification time and the store file revision it was read from; a client caching the value compares it to see a change |
| `expires` | the entry's expiry time, when it has one |
| `clientToken` | the client token, when one was asked for and granted |

or an `error` (section 10). The service serves its offline cache without an
age limit; a client that needs the latest value checks `entry.source` itself.

### 5.3 `getMany` and `values`

`getMany` reads several secrets under one approval prompt (`tsm run` uses
it): `refs` is a list (1 to 256) of `{ref, dimensions?, field?}`; `wait` and
`timeoutMs` apply to the whole request. The answer `values` carries
`results`, one per reference in request order, each a `value` or an `error`
object without `id`.

### 5.4 `progress`

When a request starts waiting, the service sends `progress` once, with
`pending`: `unlock` (the service is locked and an admin was told) or
`approval` (the request went to approval). On a host where no approver is
connected it carries `approvalCode`, the one-time approval code (7.5), so a
command line can show it.

### 5.5 Phase-B messages

| Request | Answer | What |
| --- | --- | --- |
| **[B]** `getFile {id, ref, dimensions?, field?, wait?, timeoutMs?}` | `file {id, name, size}`, binary chunks (2.5), `end {id, sha256}` | an attachment or a typed key as bytes, for the ssh-agent and `tsm run --file` |
| **[B]** `match {id, url, frameUrl?, userName?, pick?, wait?, timeoutMs?}` | `matches {id, candidates[{entryId, title, userName, matchedUrl, hasTotp}]}` | the login entries matching a page, never a value; only for the browser host and the helpers, others get `denied` (reason `not_allowed_op`); `pick` (the helpers) asks for one login of the host; audited |
| **[B]** `propose {id, url, title?, userName, password, wait?, timeoutMs?}` | `accepted {id, known?}` | a login for the app to save, passed to the attached app as the event `proposal`; with no app attached `unavailable` (reason `no_app`); only for the browser host or a helper holding a grant; a helper's credential the vaults hold already is not passed on (`known`) |

**`getFile`** is checked and decided as `get` is (5.6) and answered with the
value as bytes: `file` names the field (an attachment field
`attachment:<name>` without its prefix) and gives its size, the binary
chunks follow in order (2.5), and `end` carries the SHA-256 of all of them
in lower-case hex. A refusal is an `error` as for `get`. A connection whose
`hello.features` does not name both `binary` and `getFile` is answered
`unsupported` with `details.features`, the ones missing.

**Who `match` and `propose` answer.** The service tells them by the
client's measured executable (7.1), never by what `hello` says:

- the **browser host** is the product's native-messaging host
  `tsm-browser-host` (`.exe` on Windows) beside the service's executable
  (its real path); it may send `match` and `propose`;
- the **helpers** are `tsm` beside the service, under any of its names
  (`git-credential-tsm`, `docker-credential-tsm`: links or copies of it);
  they may send `match` (also with `pick`) and `propose`.

Any other client is answered `denied` (reason `not_allowed_op`), which
counts as a refusal (section 11).

**`match`** answers the login entries (type `login`, no overlay entries)
of the open stores whose URLs match `url` by 5.7, among the entries an
`allow` grant of the client covers: for an entry, the grants whose subject
names the client (7.3) are ranked as for a value (subject, then secret: a
reference naming that entry, its store, `all`), and the entry is covered
when the best of them is `allow` (`never` beats `allow` at equal rank). No
prompt is raised; an entry no grant covers is left out. The browser host
is never given an entry of a system vault (the vault's kind, its metadata
`tsm.kind`). `url` and `frameUrl` are strings of at most 4 KiB (else
`malformed`, reason `url`). With `frameUrl` (a login form in a frame) the
frame is matched instead of the page, and only when it is the same site as
the page (its host, or its registrable domain); a frame of another site
matches nothing. A candidate carries `entryId`, the entry as a uuid
reference (`<store>/~<32 hex>`, section 4) the browser host reads with `get`
for a fill, the title, the user name, the entry's URL that matched as
written, and `hasTotp` (the entry carries a TOTP secret); never a password
or another value. Every `match` is audited (`refs` `match <host>`, the
outcome and the candidates' entries). A locked service waits for an unlock
as `get` does. With `userName` (a string) only that user's logins are
answered.

**`match` with `pick`** (the helpers only, else `denied`; git's credential
lookup, part-os-integration) answers one login of the host, by the host
rule (only entries whose URL's host is the page's):

1. the one login the client's grants cover; of several covered, the one an
   `allow` grant names by its reference (a remembered pick);
2. else, when the vaults hold logins of the host (covered or not; of
   several covered, those), the approvers pick one at a prompt
   (`approval_needed` with `pick`, the logins as `{entryId, title,
   userName, matchedUrl}`, and `url`; `progress` `pending` `approval`):
   `approve` with `decision` `once` or `always` and `pick`, the `entryId`
   picked, or `never`. `always` writes a grant for the picked entry's
   reference, its subject the helper as started by its tool
   (`exe-from <tool> => <tsm>`, 7.3); `once` lets this connection read that
   entry once with `get` without a prompt; `never` writes nothing;
3. refused, unanswered within the approval timeout, or with no approver
   connected (a pick has no approval code): no candidate.

**`propose`** carries `url`, `userName`, `password` and an optional
`title` (else `malformed`, reason `propose`). It is answered for the
browser host and the helpers only when an `allow` grant names the client
(any secret). A helper's proposal (git's `store`, DP-52) of a credential
a login of the vaults matching `url` (5.7) holds already, user name and
password, is answered `accepted` with `known` `true` and not passed on;
then passes the login to every attached manager app as the event
`proposal` (6.5), keeps nothing, and answers `accepted`; with no app
attached it answers `unavailable` (reason `no_app`). A locked service waits
for an unlock as `get` does. Every `propose` is audited without the values.

### 5.7 URL matching [B]

How an entry's URLs match a page (`match`, the OS autofill). An entry's URLs
are its `URL` field and every field whose name begins with `KP2A_URL`.

- **Normalising:** only `http` and `https` URLs are web URLs (others, such
  as `androidapp://`, never match); a text without a scheme is read as
  `https`; the host lower-case, a trailing dot dropped, every non-ASCII
  label as punycode (RFC 3492, `xn--`); a default port (443, 80) dropped.
- **The registrable domain** is the public suffix after the Public Suffix
  List (both its sections, the private one included) with one more label;
  a host that is itself a public suffix has none. The list is the one
  published at publicsuffix.org, as the implementation carries it.
- **The entry field `tsm.urlMatch`** chooses the rule:

  | Value | An entry URL matches when |
  | --- | --- |
  | `domain` (the default, also for an unknown value) | the host is the page's (exact host), or the registrable domains are equal (domain) |
  | `host` | the host is the page's |
  | `exact` | scheme, host and port are the page's and the page's path is the entry's path or below it |
  | `never` | never |

- An entry URL with `https` never matches an `http` page.
- An IP address or `localhost` (on either side) matches only by host and
  port exactly, whatever the rule.
- **Order:** the exact host before the domain, then the last used first (the
  entry's last access time, else its last modification), then by title.

### 5.6 What the service checks, in order

For a `get` (and each reference of a `getMany`):

1. **Frame and reference**: a malformed frame or reference costs nothing more.
2. **Rate limit** of the client's measured identity (section 11).
3. **Locked**: with `wait` set and an admin attached, the service sends the
   event `unlock_needed` and `progress` (`unlock`), and waits up to the
   timeout before answering `locked`; with no admin attached, `locked` at once.
4. **Resolve**: a missing or ambiguous reference is answered `not_found` or
   `ambiguous` without a prompt (names are not secret, values are); a passkey
   field (`KPEX_PASSKEY_*`) is `denied` (reason `reserved_field`) whatever the
   grants say; a store that could not be fetched and has no offline copy is
   `unavailable`.
5. **Allow list**: a matching grant answers at once, a `never` grant answers
   `denied` (reason `never`); otherwise the request goes to approval (7.2)
   and the client gets `progress` (`approval`).
6. **Answer**, and an audit record of the outcome.

## 6. The admin endpoint

### 6.1 The challenge

The admin endpoint answers nothing before both sides have proven they hold
the **admin key** (32 random bytes the service got from its starter):

1. The service sends `challenge {serviceNonce, serviceStart, protocol,
   service}`: 32 random bytes, its start time in milliseconds since the
   epoch, its protocol version and `{version}`.
2. The admin answers `auth {adminNonce, mac, client}`:
   `mac = HMAC-SHA256(adminKey, "tsm-admin-v1" || serviceNonce || adminNonce || serviceStart)`.
3. The service answers `authed {mac2}`: the same HMAC under the label
   `tsm-service-v1`.

The MAC input is the label's ASCII bytes, the two nonces' 32 raw bytes each,
and `serviceStart` as 8 bytes, unsigned, big-endian; no separators.
`vectors/hmac.json` pins inputs and outputs. The admin checks `mac2` before it
sends anything secret, so it never gives a master password to a process that
only pretends to be the service. A wrong `mac` is answered `error` `denied`
(reason `bad_mac`) and the connection closed; repeated failures are delayed,
1 s, 2 s, 4 s … up to 60 s. The admin's measured executable must also be the
manager app's or `tsm`'s (beside the service's executable, or named in its
bootstrap's `admin_executables`); a wrong one is refused even with the right
key (`denied`, reason `wrong_executable`), before the key is checked.

### 6.2 Claim

An admin without the admin key sends `claim {password, keyFile?, client}`
instead of `auth`. The service checks the master password (and key file)
against the primary file it has open, answers `claimed {adminKey}` with a new
admin key and revokes the old one. A wrong password is `denied` (reason
`bad_password`), logged, and counts as a failed authentication. The service
cannot prove itself to a claimant, which shares no key with it yet; the app
warns before it sends a master password in a claim.

### 6.3 Requests and answers

After `authed` (or `claimed`), every admin request carries an `id`. A request
that succeeds with nothing to return is answered `ok {id}`; a failure is
`error` (section 10).

| Request | Answer | What |
| --- | --- | --- |
| `unlock {id, password, keyFile?}` | `ok` | open the primary file and the stores it names; without `keyFile` the service takes the primary's key file from the device keychain (`tsm.key-file.<id>`), and a `.tsmx` primary's repository key always comes from there (`tsm.repository-key.<id>`; the ids are the first 16 hex digits of SHA-256 over the vault's or the repository's identity, part-stores) |
| **[B]** `unlock {id, vault, bundle{nonce, ciphertext}}` | `ok`, or `error` `denied` (reason `bad_bundle`: the bundle does not open on this connection, which counts as a failed authentication; `bad_password`: it opens, but its composite key no longer opens the vault, which was re-keyed), `not_found` (no such store; while locked: the primary the bundle opened has another name, and the service locks again), `unsupported` (sent on a connection that claimed the service) | open a vault with the key bundle the app read from the OS-gated store (6.4): `vault` is a store's name as `status` lists it; while the service is locked every bundle is taken as the primary's and unlocks the service as `unlock` with the password does; unlocked, a bundle opens the store it names as `unlockStore` does |
| `unlockStore {id, store, password, keyFile?}` | `ok` | open a store with a password of its own |
| `lock {id}` | `ok` | lock: clear every secret from memory |
| `shutdown {id}` | `ok`, then the connection closes | lock and stop |
| `status {id}` | `statusReport {id, locked, lockMode, protocol, service{version, start}, stores[{name, state, source, fetchedAt?, notPushed, rewritten?{head}}], admins, hardening, expiring?[{kind, key, vault?, expiresAt, daysLeft}], agent?, github?{state, login?}}` | the service's state; `lockMode` is the service's lock mode (DP-14): `a` never relocks, `b` relocks on idle, `c` (phase B) on idle or screen lock; a store's `state` is `current`, `offline`, `token_expired`, `needs_unlock` or `unavailable`; its `source` is as in 5.2 (`github`, `file` or `cache`); `notPushed` counts its changes not yet written to GitHub; `rewritten` names the head of a branch rewritten without a compaction awaiting `history.resolve` (6.4); `hardening` names the protections achieved at start, each `true` or `false`: `noCoreDumps` (no core file; on Windows the error mode against crash dumps), `notDumpable` (Linux: not dumpable, so no debugger of the same user attaches), `memoryAccessDenied` (Windows: the process DACL refuses `PROCESS_VM_READ` and `PROCESS_VM_WRITE` to all but SYSTEM); `expiring` lists the keys due for a reminder now (part-key-rotation), each with its `kind`, its `vault` when it has one, `expiresAt` and the whole `daysLeft` (negative once expired): `github_token` (key `github-token:<owner>/<repository>`, from the device setting's warning period, default 14 days, before the expiry GitHub reports for the token, or before the expiry recorded with the token when it was entered while GitHub has reported none), `vault_keys` (key `vault-keys:<vault>`, a vault's key file and repository key, from 30 days before their due date: for a further vault the Expires of its entry in the primary, for the primary its metadata's `tsm.keys-due`), `approver_key` and `link_key` (keys `approver-key:<device>` and `link-key:<device>`, this device's approver and approval-link key pairs and those of the peers it recorded, from 30 days before their rotation age of 24 months is over, counted from their creation, their recording at pairing, a key change or a new link key), **[B]** `github_app` (key `github-app:<device>`, this device's GitHub App sign-in, from the warning period of the GitHub token before its refresh token runs out unused); `tsm status` shows it where no app is attached; **[B]** `agent` is the ssh-agent's endpoint (`{socket}` or `{pipe}`) while it runs; **[B]** `github` is the GitHub App sign-in's `state` (as `github.app`) and the signed-in user's `login` |
| `reload {id}` | `ok`, or `error` `offline` / `token_expired` | fetch every store now and reopen those whose file moved; on a failed fetch the stores stay on the copy held or cached, and the error's `stores` names them (`token_expired` when GitHub refused a token, else `offline`) |
| `vaultKeys {id, stores?}` | `vaultKeySet {id, stores[{store, location, served?, keys}], unserved?[{store, location}]}` | the keys of the open vaults, for the app's editing path (6.4); **[B]** a vault the service opened with an OS unlock's bundle carries `keys.compositeKey` (base64) in place of `password` and `keyFile`; `stores` may also name a vault the primary lists that this machine does not serve (`served` false); `unserved` lists those vaults, without keys |
| `vaultFile {id, store}` | `vaultFileData {id, store, location, revision, served?, bytes}`, or `error` `not_found` (neither an open store nor a vault the primary lists), `needs_unlock` (a vault not served whose listed keys do not open it), `unavailable` (one that cannot be read), `offline` / `token_expired` (`stores`), `unsupported` reason `too_large` | the copy of a store the service holds, for the app's editing path (6.4): an open store, or a vault not served, which the service then reads and holds for editing |
| `save {id, store, bytes, baseRevision?, keys?{password, keyFile?, outerKey?}}` | `ok` | hand an edited store file to the service, which writes it (6.4); a re-keyed file is taken as 6.4 says, `keys` carrying the primary's own new keys (a further vault's save with `keys` is `malformed`, reason `keys`) |
| `vault.move {id, store, location, bytes, baseRevision?, keys{password, keyFile?, outerKey?}}` | `ok {id, location, revision}`, or `error` `malformed` (reason `location`: not the store's locator with `.tsmx` added or removed; `keys`: an outer-encrypted file without its repository key, or a plain one with one; `bytes`; `move`), `denied` (reason `stale_base`, `target_exists`, `branch_moving`, `wrong_executable`), `not_found` (no open store), `offline` / `token_expired` (`stores`) | add or remove a store's outer encryption, which moves it to its locator with `.kdbx.tsmx` or `.kdbx` (6.4); accepted only from the manager app's executable |
| `vault.create {id, store, location, bytes, keys{password, keyFile?, outerKey?}, githubToken?, keysDue?}` | `ok {id, store, location, revision}`, or `error` `malformed` (reason `store`: not a store name, or one the primary names already; `location`: not a vault locator, or the primary's or a listed vault's; `keys`: an outer-encrypted file without its repository key, or a plain one with one; `bytes`: no base64, or a file that does not open with `keys` or whose metadata cannot be read; `githubToken`: a token for a vault that is not a `github:` vault outside the primary's repository; `create`), `denied` (reason `target_exists`, `wrong_executable`), `offline` / `token_expired` (`stores`) | create a further vault beside the primary: the service writes the new file where it lives and lists it in the primary (6.4); accepted only from the manager app's executable |
| `pair.identity {id}` | `pairIdentity {id, device, approverKey{ed25519, mlDsa65}, linkKey{x25519, mlKem768}, linkAddress?}` | this device's public keys for a pairing (9.8); accepted only from the manager app's executable |
| `pair.record {id, device, tokenKey, approver?{approverKey, linkKey?}, host?{linkKey, address?}, record?{platform?, keyIds[]}}` | `ok`, or `error` `malformed` (reason `pair`: no approver and no host, a token key not 32 bytes, this device itself) | keep what a pairing gave (9.8): `approver` records the peer as an approver of this host (its grants and link handshakes are accepted, its approval-code tokens checked with `tokenKey`), `host` records it as a host this device approves for; every key is dated now; a device paired again replaces what was recorded; with `record` the device record goes into the primary (`.tom-secrets/devices`: platform, the time, the device that paired it, the key ids it received, its approver key id and key dates); accepted only from the manager app's executable |
| `pair.revoke {id, device}` | `ok`, or `error` `not_found` | revoke a paired device: what this device recorded of it goes, and its device record in the primary is marked revoked; accepted only from the manager app's executable |
| **[B]** `github.app {id}` | `githubApp {id, state, clientId?, signedInClientId?, login?, accessExpiresAt?, refreshExpiresAt?, userCode?, verificationUri?}` | the device's GitHub App sign-in (part-key-rotation §3, DP-83): `state` `not_configured` (the primary names no App and the device is not signed in), `signed_out`, `pending` (a device flow waits for its code; `userCode`, `verificationUri`), `signed_in`, `sign_in_again` (GitHub refused the refresh token: 6 months unused, or the App's authorization revoked); `clientId` the App the primary names; never a token |
| **[B]** `github.app.configure {id, clientId}` | `ok`, or `error` `malformed` (reason `clientId`), `denied` (reason `wrong_executable`), `locked` | write the client id of the user's GitHub App into the primary's metadata (`tsm.github-app-client-id`; `""` removes it); every device learns it with the primary; accepted only from the manager app's executable |
| **[B]** `github.signIn {id, clientId?}` | `deviceCode {id, userCode, verificationUri, expiresIn, interval}`, or `error` `not_found` (reason `no_github_app`: no App named), `unsupported` (reason `no_keychain`), `denied` (reason: GitHub's refusal), `offline` | "Sign in with GitHub" (DP-6, DP-83): the service starts the device flow with the App the primary names (`clientId` only while the primary is unread) and answers the code the user enters at `verificationUri`; it then polls GitHub and sends the event `github_sign_in`. On success it keeps the access and the refresh token in the device keychain (`tsm.github-app.session`) and uses them for every `github:` vault, the pasted tokens no more. The service is the tokens' single owner: it renews both before the access token's 8 hours run out and once at GitHub's first 401 (at most once a minute), writing them back before using them; a refresh token GitHub refuses leaves `sign_in_again`. A device-flow token needs no client secret, and no App private key exists |
| **[B]** `github.signOut {id}` | `ok` | the device's App tokens leave the keychain (a running device flow ends); the pasted tokens are used again. GitHub keeps the App's authorization: revoking it there signs every device out |
| `pair.list {id}` | `pairedDevices {id, devices[{device, platform?, paired, pairedBy?, keyIds, approverKeyId?, approverKeySince?, linkKeySince?, revoked?, githubAuth?, githubTokenExpires?}]}` | the device records of the primary (**[B]** `githubAuth`: how the device reaches GitHub, `app` signed in with the GitHub App or `token` a pasted token, and `githubTokenExpires` when that token expires, written by the device's own service); accepted only from the manager app's executable |
| `subscribe {id}` | `ok`, then events (6.5) | start the event stream on this connection |
| `approve {id, approvalId, decision, secret, folder?, pin?, clientToken?, sshHost?, withParent?, pick?}` | `ok` | answer a prompt (7.2); **[B]** `pick` the `entryId` picked at a helper's pick prompt (5.5); `clientToken` is the token the app made for an `always` of a request with `wantClientToken` (7.4); **[B]** `sshHost` limits a lasting ssh-agent grant to the request's destination host, `withParent` names the client with its parent (`exe-from`, 7.3); a confirmation (`confirmOnly`, 7.6) takes only `once` or `never` (else `malformed`) and writes nothing |
| `approval.redeem {id, token}` | `ok` | `tsm approve <token>`: redeem a one-time approval token (7.5) |
| `approval.issue {id, host, code, decision, secret, pin?}` | `approvalToken {id, token}` | have this device make the token for a code shown on `host` (7.5, 9.6); for a decision other than `once` its app also writes the signed grant |
| `grants.list {id, host?}` | `grantList {id, grants[]}` | the allow list of one host, or of every host (7.3) |
| `grants.add {id, grant{host, subject, secret, decision, pin?}}` | `ok` | add a grant, for another host a pre-approval; the service fills in `id`, `created` and `approver` and signs it |
| `grants.revoke {id, host, grantId}` | `ok` | revoke a grant of any host |
| `approvers.cliSwitch {id, on}` | `ok` | switch command-line approvals on this device on or off; accepted only from the manager app's executable |
| `history.resolve {id, store, take}` | `ok {id, revision, conflicts}`, or `error` `not_found` (no rewritten branch waits on that store), `offline` / `token_expired` (`stores`), `denied` (reason `history_rewritten` when rewritten again, `branch_moving`, or `wrong_executable`), `malformed` (reason `history`) | answer a branch rewritten without a compaction (6.4): `take` `remote` takes the remote file as it is and drops the refused edit; `merge` merges the held copy over the remote file (nothing taken as deleted) and commits it on top of the rewritten head, `conflicts` counting the records it wrote; accepted only from the manager app's executable |
| `token.set {id, repository, token}` | `tokenSet {id, repository, where, expiresAt?}`, or `error` `denied` (reason `token_refused` when GitHub answers 401, `token_no_access` when the token does not see the repository, `token_read_only` when it may not write there, `wrong_executable`), `not_found` (no vault in that repository), `offline` (GitHub could not be reached), `unsupported` (reason `no_keychain`: nowhere to keep the token of the primary's own repository), `malformed` (reason `token`) | renew the GitHub token of a vault repository (`owner/name`, part-key-rotation §3); accepted only from the manager app's executable. The service first checks the token: it reads the repository and its default branch, creates the branch `tsm-token-check-<12 hex digits>` at the default branch's head and deletes it again (a vault repository's only workflow runs on a schedule or by hand, so the branch starts nothing), and takes the expiry GitHub reports (`GitHub-Authentication-Token-Expiration`). Then it replaces the token where the old one lives — the device keychain (`tsm.github-token.<owner>:<repository>`, its expiry in `tsm.github-token-expiry.<owner>:<repository>`, `where` `keychain`), else the primary's vault entries that keep a token for that repository (never for the primary's own repository; `where` `primary`, the primary written) — and fetches every store again; a repository with no token yet takes the keychain, else the vault list. `expiresAt` is the expiry GitHub reported, absent for a token without one. The token is never logged |
| `settings.get {id}` | `deviceSettings {id, device, cliApprovals, stores[]}` | the device settings (`device`: `serviceLock{mode, idleSeconds, maxUnlockedSeconds?, lockOnSleep}` with `mode` `never` (a), `idle` (b) or **[B]** `osUnlock` (c), `appLock`, `defaultEnvironment?`, `servedStores?` (absent: every store), `refreshMinutes` (0: no refresh), `offlineCache`, `keyExpiryWarningDays`, `approvalTimeoutSeconds`, `codeTimeoutSeconds`, `approvalLink?`, and the rotation ages and reminder start of DP-85: `otherKeyWarningDays` (30), `keyPairAgeMonths` (24), `primaryKeyAgeMonths` (24), `vaultKeyAgeMonths` (12)), whether command-line approvals are on, and the stores the primary names (the primary first); `locked` while locked |
| `settings.set {id, device}` | `ok {id, nextUnlock[]}`, or `error` `malformed` (reason `settings`), `denied` (reason `wrong_executable`) | write the whole device settings; accepted only from the manager app's executable; the lock policy, the refresh, the timeouts, the cache and the reminder period apply at once, `nextUnlock` names those that apply at the next unlock (`servedStores`, `defaultEnvironment`, `approvalLink`) |
| `audit.query {id, from, to, subject?, ref?}` | `auditRecords {id, records[{time, host, identity, refs, outcome, grantId?, approver?, entries?, ssh?}]}` | the audit log; `outcome` is `allowed`, `denied:<reason>`, an error kind, or for a lookup `matched` / `proposed`; `entries` the UUIDs of the entries decided; **[B]** `ssh` an ssh-agent signature's `{key, keyType, title?, host?, hostNames?, forwarded, purpose, namespace?}` (7.6) |
| `approvals.list {id}` | `approvalList {id, approvals[]}` | the requests waiting on this host (`tsm approvals`), each as its `approval_needed` event reads without `op`: `approvalId`, `host`, `identity`, `refs`, `resolved`, `approvalCode?`, … (6.5, 7.2) |
| `keys {id}` | `keyList {id, keys[{kind, key, vault?, expiresAt, daysLeft, reminding, own?}]}` | every key the service knows a due date of (`tsm keys`), reminding or not: the keys of `statusReport.expiring` (same `kind` and `key`) with `reminding` true for those due a reminder now; `own` true marks this device's own approver and link key pairs, which `keys.rotate` rotates |
| `keys.rotate {id, approver?, link?}` | `keysRotated {id, approverKeyId?, resigned, delivered[], pending[]}`, or `error` `malformed` (reason `keys`: both false), `denied` (reason `wrong_executable`) | rotate this device's own key pairs by hand (part-key-rotation §4; both by default, as an approver device does); accepted only from the manager app's executable. `approver`: a new hybrid approver pair (Ed25519 + ML-DSA-65); every grant and revocation this device signed is signed again with it, in every host's group of the primary vault, and its key-change statement (9.4, signed by the old and the new pair) is written into the group of every host it approves for, where a host the link does not reach takes it at its next refresh (`resigned` counts the objects signed again). `link`: a new approval-link pair; the previous one stays in use for 14 days for the hosts the new key has not reached (this device connects to them with it) and for the approvers that connect here (this device's link answers them under it). Both are then sent to every recorded host with a link address over a session under the keys that host knows (`keychange`, `linkKey`, 9.7): `delivered` names the hosts that took them, `pending` those not reached; the new link key is sent to them again at each refresh, at most every 15 minutes |
| `compact {id, repository, retentionDays?}` | `compacted {id, repository, compacted, oldHead, newHead, kept}`, or `error` `not_found` (no open vault in it), `offline` / `token_expired` (`stores`), `denied` reason `branch_moving`, `malformed` reason `retentionDays` | cut the history of a `github:` vault repository (`owner/name`) now (`tsm compact`): the cut the compaction workflow makes, with the repository's own `.tsm/compaction.yaml` retention, or `retentionDays` instead (0 after a key change, 6.4), pushed by this device; `compacted` false when there was nothing to cut |

### 6.4 Editing and key material

The service owns every vault file and every write to GitHub on its device.
To edit, the app asks for `vaultKeys` and, per store, for `vaultFile`: the
copy the service holds, as the store keeps it (`bytes`, base64), with its
`location` and its `revision`. It opens the vaults in its own memory and
hands each saved file back with `save` (`bytes` the whole file,
`baseRevision` the `revision` it edited). Because the app edits the
service's own copy, it needs no access to the store itself (no GitHub token,
no clone) and edits the same copy the service serves, from its offline copy
too. A `vaultFileData` frame is an answer frame and holds at most 1 MiB
(2.3): a larger file is refused `unsupported` (reason `too_large`, `details.size`
its byte count) until phase B's binary chunks (2.5) carry it. A store's `keys` object carries what
opens it, each member when the store has one: `password` (its master
password), `keyFile` (the key file's bytes, base64) and `outerKey` (the
repository's outer key of a `.tsmx` file, base64). They travel only in
`vaultKeySet` over an authenticated admin connection; `location` is where
the store's file is (its locator).

**A vault this machine does not serve** (BP-15): the primary lists every
further vault with its keys, and the machine serves those its device
settings name. The others are edited through the same path: `vaultKeySet`
names them in `unserved` (store and location, no keys); `vaultKeys` naming
one answers its keys from the primary with `served` false; `vaultFile`
naming one makes the service read the file from its location, with the
listed keys and the repository's GitHub token as for a served store, and
hold the copy for editing until the lock (`served` false in the answer).
`save` writes it as below, a `github:` one as a commit by this device. Such
a vault is never resolved, never served to clients and not refreshed on its
own; `status` does not list it. A vault the primary does not list is
`not_found`: the service has no keys for it.

The service takes a `save` when `bytes` open with the store's keys
(otherwise `malformed`, reason `bytes`):

- the file is still at `baseRevision`, or `save` names none: it is written
  as it is;
- the file has moved, and `baseRevision` is the copy the service holds: the
  app's copy is merged three-way into the file as it is now, the held copy
  as the base (part-stores), and the merge is written;
- any other `baseRevision`: `denied`, reason `stale_base`; the app reads the
  file again and edits that.

A `github:` store is written as one commit on its branch, by this device
(`<device>@tsm.invalid`), through the vault unit: when the branch moved since
the copy the service holds, the new head is read and the app's copy merged
three-way with it, the held copy as the base, and the commit tried again; the
result goes into the offline cache. A branch rewritten without a compaction
refuses the save (`denied`, reason `history_rewritten`), and so does a branch
that moved during every attempt (reason `branch_moving`). After a refused save
on a rewritten branch the store reports the state (`statusReport.stores[]` and
`store_state` carry `rewritten: {head}`), the service holds the refused edit
and stops refreshing the store, and the manager app asks the user:
`history.resolve` with `take: remote` follows the rewritten branch (the edit is
dropped), with `take: merge` the held copy is merged over it and committed on
top. The state ends with the answer or the lock. A store served from
its offline copy, or whose remote cannot be reached or refuses the token
during the save, answers `offline` / `token_expired` with `stores`. The
service's own writes of the primary (grants, their last use) go the same
way; one that cannot be delivered stays in the held copy and is written by
the next refresh.

**A re-keyed file** (part-key-rotation). The app rotates a vault's keys by
writing the new keys into the primary first (the vault's entry; the primary's
own in its metadata and the save's `keys`) and then saving the vault re-keyed:

- a further vault's `bytes` that do not open with the keys the service holds
  but do with the keys the primary lists for it now are taken as re-keyed;
- the primary's re-keyed file carries its new keys in `keys` (`password`,
  `keyFile` base64, `outerKey` the repository key, base64); the service
  holds them from then on and keeps the new key file and repository key in
  the device keychain (`tsm.key-file.<id>`, `tsm.repository-key.<id>`),
  where the next `unlock` takes them;
- a re-keyed file is written as it is and never merged: `baseRevision` must
  be the copy the service holds (or none), and a file that has moved since
  is refused (`denied`, reason `stale_base`; nothing changes, the app reads
  it again and re-keys that);
- until the re-keyed file arrives, a vault whose listed keys do not open it
  while the keys held still do stays served with the keys held (a refresh
  does not take it to `needs_unlock`), and so does the copy of a vault not
  served, as long as its file has not moved. A failed re-keyed save can
  therefore be made again.

After a key change of a `github:` vault the app cuts the repository's
history with `compact` `retentionDays: 0`, so no commit keeps a file under
the old keys.

**A moved store** (`vault.move`, the outer encryption added or removed). The
outer layer is chosen by the file name, so adding it moves `v.kdbx` to
`v.kdbx.tsmx` and removing it moves it back; `location` must be the store's
locator with the suffix added or removed and nothing else. `bytes` is the
file as `location` keeps it and must open with `keys` (`outerKey` exactly
when `location` is a `.tsmx` file). The file at the old locator must still
be the copy the service holds (`stale_base` otherwise) and nothing may be at
the new one (`target_exists`). A `file:` store is written at the new path
and then the old file removed; a `github:` store moves in one commit that
adds the new file and removes the old one, put on the branch without force
(`branch_moving` when the branch moved meanwhile). A refused or failed move
leaves the old file in place. Then:

- a further vault's entry in the primary takes the new locator and keys,
  and the primary is written;
- the primary itself takes the new keys; the bootstrap file's `primary:`
  names the new locator, and the device keychain keeps its key file and,
  for a `.tsmx` primary, its repository key under the new locator's handles
  (the key file's handle names the vault's path). Other devices name the
  primary in their own bootstrap files and are told by hand or by pairing.

The store is served from the new place, and the app cuts the repository's
history (`compact` `retentionDays: 0`), so no commit keeps the file without
the outer layer.

The store is then reopened from what was written and `store_changed` names
the new revision. A store that is not open answers `not_found`,
`needs_unlock` or `unavailable` as a `get` would.

**A new store** (`vault.create`). The app makes the new vault: an empty
KDBX 4.1 file keyed through Argon2id, its metadata entry `.tom-secrets`
naming the store, its kind (`personal`, `system`, `shared`) and, for a
system vault, the binding it serves in (`env=prod`), and its entries if it
brings any. `bytes` is the file as `location` keeps it and must open with
`keys` (`outerKey` exactly when `location` is a `.tsmx` file). `store` is a
store name the primary does not name yet, `location` a vault locator that is
neither the primary's nor a listed vault's. The service writes the file
first, and nothing may be there yet (`target_exists`): a `file:` vault at
its path (its folder made when missing), a `github:` vault in one commit on
the branch, by this device. Only then does it list the vault in the primary
with `keys`, `githubToken` (the token of a `github:` vault outside the
primary's repository, which the keychain does not hold) and `keysDue` (the
entry's Expires, when its key file and repository key are due for rotation),
and writes the primary; a primary that cannot be reached keeps the entry in
its held copy until the next refresh writes it. A refused or failed write
lists nothing. The new vault is served from then on, unless this machine's
device settings name the stores it serves and not this one; then it is a
vault not served here, editable through `vaultKeys` and `vaultFile`.
`store_changed` names the primary and the new store.

**[B] The key bundle.** The OS unlock hands key material to the service only
sealed. The bundle is the vault's composite key (the 32 bytes KDBX derives
its key from: SHA-256 of the password's and the key file's hashes) and, for a
vault with the outer encryption, its repository key, never the password
text; its plaintext is the UTF-8 JSON object
`{"v": 1, "compositeKey": <base64, 32 bytes>, "outerKey"?: <the repository key as kept>}`.
The composite key opens the vault with or without a key file and stays valid
across saves; a re-keyed vault no longer opens with it. The service holds it
in place of the password, and hands it to the app's editing path as
`keys.compositeKey`.

- bundle key = HKDF-SHA256(ikm = adminKey, salt = serviceNonce || adminNonce,
  info = `tsm-bundle-v1`, 32 bytes), new for every admin connection;
- `bundle.ciphertext` is AES-256-GCM of the bundle under that key with the
  12-byte random `bundle.nonce`, the tag appended, and as associated data the
  vault id's UTF-8 bytes followed by `serviceStart` as 8 bytes big-endian;
- a bundle that does not open is refused like a wrong password (`denied`,
  reason `bad_bundle`) and counts as a failed authentication;
- vectors: `vectors/bundles.json` (the bundle key, the associated data, two
  sealed bundles, and four that must be refused: another vault, another
  service start, another connection, a changed tag).

### 6.5 Events

After `subscribe` the service pushes events on that connection (no `id`):

| Event | Members | When |
| --- | --- | --- |
| `unlock_needed` | `identity?` | a client waits for an unlock |
| `approval_needed` | `approvalId, host, identity, refs[], resolved[{store, path, kind}], hostHint?, approvalCode?, wantClientToken?, ssh?, confirmOnly?, pick?, url?` | a request needs an approval (7.2); `wantClientToken` when the client asked for a client token (7.4); **[B]** `ssh` and `confirmOnly` for an ssh-agent signature (7.6); `pick` and `url` for a helper's pick prompt (5.5) |
| `approval_closed` | `approvalId, outcome` (`approved`, `denied`, `timeout`, `abandoned`, `no_approver`) | a prompt was answered or ended elsewhere |
| `locked`, `unlocked` | — | the service locked or unlocked |
| `store_changed` | `store, revision?` | a store was reopened with new content |
| `store_state` | `store, state, source, fetchedAt?, notPushed, rewritten?{head}` | a store's state or source changed (at a refresh, a `reload`, an unlock of the store), or its branch was found rewritten without a compaction (`rewritten`, 6.4) or the rewrite answered |
| `key_expiry` | `key, expiresAt, daysLeft` | a key the product rotates expires soon (the GitHub tokens, the vaults' key files and repository keys, the approver and approval-link key pairs; the keys of `statusReport.expiring`): sent when it reaches a reminder step (the first day of its warning period, 7 days and 1 day before, and once a day once expired); an admin that subscribes gets the reminders due at that moment |
| `rate_limited` | `identity, until` | an identity is held back |
| **[B]** `proposal` | `url, title?, userName, password` | a login the browser host proposed |
| **[B]** `github_sign_in` | `outcome, login?` | a device flow ended (`signed_in` with the user's `login`, `denied`, `expired`, `device_flow_disabled`, `bad_client_id`, `failed`), or the device signed out (`signed_out`) |

## 7. Approvals and grants

### 7.1 The identity

The service measures each connecting process once, when the connection is
accepted, and never trusts what a client says about itself: the peer's PID
(`SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS, the owner of the
localhost TCP connection on Windows), then its executable, arguments,
working directory, start time and parent. A process of another OS user is
refused (`denied`, reason `other_user`), and so is one that cannot be
measured or changed under the measurement (`unidentifiable`): the service
answers the refusal and closes the connection once the client's first frame
has come. The **identity**
object shown, matched and audited is:

| Member | Content |
| --- | --- |
| `kind` | `exe`, `script` or `interpreter` |
| `exe` | the executable's real path |
| `exeHash` | its SHA-256 in hex, when computed (for a pinned grant) |
| `interpreter`, `script`, `scriptHash`, `packageRoot` | for an interpreted client: the interpreter, the script, its SHA-256 and the package root (`dart run`, `python -m`) |
| `args` | the arguments |
| `cwd` | the working directory |
| `parent` | `{exe, args?}` of the parent process |
| `uid` | the OS user (a number, or a SID string on Windows) |

### 7.2 The approval flow

A request that no grant answers goes to the approvers: the attached manager
app and, over the approval link, the connected apps of trusted devices get
`approval_needed`. The first `approve` wins and the others get
`approval_closed`. `decision` is `once` (answers this request only, or the
whole `getMany`), `always`, `folder` (with `folder`, covering everything below
it) or `never`; `secret` is `ref` (this reference, canonical), `store` (every
secret of the resolved store) or `all`; `pin` is `hash`, `off` or
`{relaxedUntil}`. For a decision other than `once`, the approving app writes a
signed grant (7.3).

**A paired host's prompts.** The service of an approver device keeps the
approval link (9.7) open to every paired host it approves for while it is
unlocked, as the initiator (it holds the private link and approver keys; the
app holds neither), and opens it again when it ends (after a pause doubling
from 5 s to 5 minutes). It passes the host's `approval_needed` and
`approval_closed` to its attached app with `approvalId` qualified as
`<host>/<approvalId>` (a host's own ids contain no `/`), and ends them
(`approval_closed`, `outcome` `unreachable` or `abandoned`) when the link ends
or it locks; the host sends what still waits when the link is open again.
The app answers with `approve` and the qualified id as for its own host's
prompts; the service carries it over the link: `once` as `approve`, a lasting
decision as grants it signs and writes into the host's group, sent as
`grant` to apply at once and followed by `approve`, an `always` with a
client token as its `exe-token` grant with `clientToken` and `approvalId`
(7.4), which answers the request. A host it cannot reach answers
`unavailable` with `host`. `approvals.list` stays this host's. Unanswered within the approval timeout the request ends
`timeout`; with no approver connected it falls back to the approval code
(7.5) and ends `denied` (reason `no_approver`) when no token comes in time.

### 7.3 Grants

A **grant** of the allow list:

| Member | Content |
| --- | --- |
| `id` | the grant's id |
| `host` | the host it holds on; a service applies only its own host's grants |
| `subject` | `exe <path>`, `script <interpreter> <path>`, `interpreter <path>`, `folder <path> [interpreter]`, `tsm-command <command line>`, `exe-token <path> <tokenId>`, or **[B]** `exe-from <parent path> => <path>` (the executable started by that parent: `ssh` started by `git`) |
| `secret` | a canonical reference (4.5), `store <name>` or `all`; **[B]** for the ssh-agent `ssh-key [host <fingerprint>[,<fingerprint>…]] [forward] <target>` (7.6) |
| `decision` | `allow` or `never` |
| `created`, `lastUsed` | times |
| `pin` | `hash`, `off` or `{relaxedUntil}` |
| `approver` | the trusted device that made it |
| `signatures` | the signature list, items `{alg, keyId, sig}` (section 9) |

Matching: the most specific subject wins (exe-from, then exe, script or
exe-token, then folder, then interpreter); for one subject a reference beats a
store and a store beats `all`; a `never` grant beats an `allow` grant of the
same specificity. A value request is decided only by value grants and an
ssh-agent request only by agent grants (`ssh-key …`, 7.6); a service that does
not know a subject or secret form never matches it. A service accepts a grant only when its signatures verify
against an approver key it recorded at pairing (section 9).

### 7.4 Client tokens

A client token tells apart programs one process hosts (an extension host
running many extensions), which the measured identity cannot. The
**approving device makes it**; the host never makes a token or a token id
for an approver to sign blind:

- A client asks with `wantClientToken`; its prompt says so
  (`approval_needed.wantClientToken`).
- The approver that answers **always** makes the token, 32 random bytes,
  and its **token id**, the first 16 bytes in lower-case hex of
  SHA-256(lps("tsm-client-token-v1") || token). The grant's subject is
  `exe-token <path> <tokenId>`, `<path>` the client's measured executable.
  - The attached app sends the token in `approve` (`clientToken`); its own
    service signs the grant.
  - A remote approver signs the grant itself and sends it with the token
    over the approval link: `grant {id, grant, clientToken, approvalId}`
    (9.7). The host checks that the subject names that token's id, and
    `approvalId` makes the grant answer the waiting request.
- The host keeps only the token's hash (in its device settings, never in the
  vault) and hands the token to the client in its `value` (`clientToken`).
- The client sends the token in every later `hello` (`clientToken`): a
  connection whose measured executable is the grant's and whose token's id
  is the subject's is that subject; without it the connection is the bare
  executable and gets no grant made for the token. The host records the
  measured identity each token first and last came with.
- Revoking the grant invalidates the token; a token no grant of the host
  names any more is forgotten.
- An approval code issues no token: a code's answer to a token request is
  the value alone.

A library hands the token to its caller and never stores it itself.

### 7.5 Approval codes and tokens

- An **approval code** is ten characters of the RFC 4648 base32 alphabet
  (`A`–`Z`, `2`–`7`), shown with a request waiting on a host without a
  connected approver (`progress.approvalCode`, `approval_needed.approvalCode`).
- An **approval token** is 26 characters of the same alphabet: a 128-bit tag a
  trusted device computes for a code (`approval.issue`), typed into the
  waiting host (`approval.redeem`). It is single-use and expires with its
  code.

The code's derivation is 9.5, the token's tag and its redemption 9.6. `tsm
approve` without a token takes a signed approval record for a waiting code
from the vault instead (9.4).

### 7.6 The ssh-agent [B]

The service's agent (1, part-os-integration) serves the vaults' `ssh-key`
entries (part-structure: the key an attachment, `KeeAgent.settings` beside
it). Private keys never leave the service.

- **Messages:** `REQUEST_IDENTITIES`; `SIGN_REQUEST` (an RSA key signs with
  `rsa-sha2-256` or `rsa-sha2-512` only, as the request's flags ask; a SHA-1
  request is refused); `EXTENSION session-bind@openssh.com` (OpenSSH 8.9+:
  the destination's host key, its signature of the session id, which must
  verify, and whether the connection is forwarded, recorded per connection).
  Everything else (`ADD_IDENTITY`, `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES`,
  `LOCK`, `UNLOCK`, other extensions) is answered `FAILURE`: keys are added in
  the app, and the agent locks with the service. A user authentication on a
  bound connection must name the last binding's session id (and, host-bound,
  its host key).
- **Peers** are measured as clients are (7.1); one that cannot be measured
  gets no key and no signature.
- **The keys listed:** unlocked, every `ssh-key` entry whose KeeAgent settings
  allow the agent and add the key when the vault opens, whose key the agent
  reads (Ed25519, ECDSA P-256 / P-384 / P-521, RSA; OpenSSH or PEM, a
  passphrase in the entry's `Password`), less those a `never` grant refuses
  the client; the comment is the entry's title. A forwarded connection sees
  only the keys an agent grant lets it use forwarded. Locked, the public keys
  the agent kept at the last unlock with the subjects of the `allow` grants
  that cover them, to the clients those subjects name (`agent_keys.json` in
  the service's data directory; public keys are no secrets).
- **An agent grant** (7.3) names the client, the keys (`<target>`: a canonical
  reference, here the entry's uuid reference `<store>/~<uuid>`; `store
  <name>`; `all`), optionally the destination hosts by their host keys'
  fingerprints (`host SHA256:…`; it decides only on a connection bound to one
  of them) and `forward`, which lets a forwarded connection use the key; a
  forwarding grant names one key and its hosts. Among the matching grants the
  most specific subject, then key, then one limited to hosts wins.
- **Deciding a signature:** a `never` grant refuses. A forwarded request
  (`ssh -A`, an earlier binding forwarded) without an agent grant that allows
  forwarding is refused without a prompt (DP-49). An `allow` grant signs, but
  a forwarded request, or a key whose KeeAgent settings ask for confirmation,
  or a key of a vault whose metadata sets `tsm.ssh-confirm`, is confirmed each
  time: `approval_needed` with `confirmOnly`, answered `once` or `never`,
  nothing written. Without a grant the approvers are asked (7.2): the request's
  `refs` are the entry's uuid reference, `ssh` is `{key, keyType, title?,
  host?, hostNames?, forwarded, purpose, namespace?}` — the key's fingerprint,
  the destination's host key fingerprint and its names in the user's
  `known_hosts`, `purpose` `userauth`, `sshsig` (with its `namespace`,
  `git` for a signed commit) or `other`; a lasting answer writes an agent
  grant, limited to the destination when `approve` says `sshHost`.
- **Locked:** a sign request sends `unlock_needed` and waits up to the
  approval timeout; still locked, it is answered `FAILURE` and `ssh` tries its
  next method.
- **Audit:** every decision is audited (6.3 `audit.query`) with `ssh`.

## 8. Versioning and extension

- `protocol` is an integer, `1` for this document. It is raised only for an
  incompatible change. `hello` and `challenge` carry it; a service that does
  not speak a client's version answers `unsupported` and closes.
- Additive changes are announced as **features** in `welcome.features`;
  both sides ignore members they do not know, so a new optional member needs
  no feature, and a new message or frame type does. Feature names defined so
  far:

  | Feature | What it adds |
  | --- | --- |
  | `binary` | **[B]** binary frames (2.5) |
  | `getFile` | **[B]** `getFile`, `file`, `end` |
  | `match` | **[B]** `match`, `matches` |
  | `propose` | **[B]** `propose`, `accepted`, and the admin event `proposal` |

  A client sends a feature's messages only when `welcome.features` names it,
  and names in `hello.features` the features it takes; the service sends
  binary frames only to a client whose `hello.features` names `binary`. A
  phase-A service ignores `hello.features` and offers none; a phase-B
  service offers all four. This is the version handshake: the integer
  `protocol` stays `1` for every additive change, and a client finds out
  what a service speaks from `welcome.features`. A client asking a
  phase-A service for a phase-B message gets `unsupported` (an unknown
  `op`), never a silent answer.
- An unknown `op` on an open connection is answered `error` `unsupported`
  with `details.op` and the connection stays open.
- A value of an enumerated member that a receiver does not know (a new error
  kind, a new store state) is treated as the most general one it knows: an
  unknown error kind as `internal`, an unknown state as `unavailable`, an
  unknown `source` as `cache` (no claim to be fresh).

## 9. Signed objects and the approval link

### 9.1 The length-prefixed encoding

Everything signed, tagged or digested in this section is a sequence of byte
strings, each written as `lp(x)`: the length of `x` as 4 bytes big-endian,
then `x`. A text is its UTF-8 (`lps(text)`), with no normalisation. A list is
its item count as 4 bytes big-endian, then `lp` of each item. No JSON is ever
signed, so nothing depends on how a writer orders or escapes JSON.

### 9.2 Approver keys

An **approver key** is an Ed25519 key and an ML-DSA-65 key (FIPS 204) used
together. Its **key id** is the first 16 bytes, as 32 lower-case hex digits,
of

```text
SHA-256(lps("tsm-approver-key-v1") || lp(Ed25519 public key, 32 bytes)
        || lp(ML-DSA-65 public key, 1,952 bytes))
```

A host's service records, at pairing, the public keys of each approver device
with their key id and the device's id; only those records make a device an
approver. A key id names a recorded key; it is never trusted on its own.

### 9.3 The signature list

A signed object carries `signatures`, a list of items `{alg, keyId, sig}`
(`sig` in base64). An approver key signs the object's signed bytes `m`
(9.4), made under the object's domain label `L`, twice:

| `alg` | `sig` |
| --- | --- |
| `ed25519` | the Ed25519 signature of `m` (RFC 8032, 64 bytes) |
| `ml-dsa-65` | the ML-DSA-65 signature of `m` with `L` as its context string (FIPS 204, 3,309 bytes), in the hedged mode |

A receiver **accepts** the object when, for one recorded approver key, the
list holds an `ed25519` item and an `ml-dsa-65` item with that key's id that
both verify (the ML-DSA-65 one under the context `L`). One algorithm alone is
never enough, so a forgery has to break Ed25519 and ML-DSA-65 alike. Items of
an `alg` the receiver does not know, and items of key ids it has not
recorded, are ignored; that is how a later algorithm is added (section 8).
The label in the signed bytes and in the ML-DSA context keeps a signature of
one kind of object from passing as another.

### 9.4 The signed objects

The signed bytes of an object are `lps(L)` followed by `lps(member)` for each
member below, in this order. An absent optional member is the empty string;
`pin` is written `hash`, `off` or `relaxed:<relaxedUntil>`.

| Object | Label `L` | Members, in order | Where it is |
| --- | --- | --- | --- |
| grant (7.3) | `tsm-grant-v1` | `id`, `host`, `subject`, `secret`, `decision`, `created`, `pin`, `approver` | `tsm.grants/<host>`; `grant` on the link; `grantList` |
| revocation | `tsm-revoke-v1` | `host`, `grantId`, `revoked`, `approver` | `tsm.grants/<host>`; `revoke` on the link |
| approval record | `tsm-approval-v1` | `host`, `code`, `decision`, `approver`, `created` | `tsm.grants/<host>` |
| key-change statement | `tsm-keychange-v1` | `device`, `oldKeyId`, `newKeyId`, `newEd25519`, `newMlDsa65`, `time` | `tsm.grants/<host>`; `keychange` on the link |

- A **grant** is accepted as 9.3 says; `lastUsed` is not signed (the service
  updates it). A service applies only the grants of its own `host`.
- A **revocation** `{host, grantId, revoked, approver, signatures}` removes
  the grant `grantId` of `host`. It is accepted like a grant.
- An **approval record** `{host, code, decision, approver, created,
  signatures}` answers the request waiting with approval code `code` on
  `host` (9.5), as a token would (9.6). It is what an approving app writes into
  the vault when the user approves a code; `tsm approve` without a token makes
  the service reload the primary vault and take the record for a waiting code.
  It answers that one request: a lasting decision comes only from a grant,
  written beside it.
- A **key-change statement** carries the device's new approver key: its id
  (`newKeyId`), its public keys in base64 (`newEd25519`, `newMlDsa65`) and the
  id of the key it replaces (`oldKeyId`). It is signed by the old key and by
  the new key, each with both algorithms: four items. A host records the new
  key only when `oldKeyId` is the id of the key it recorded for `device`,
  `newKeyId` is the id of the public keys in the statement (9.2), and the
  statement is accepted under the old key and under the new key.

### 9.5 The approval code

A request waiting on a host without a connected approver gets an approval code
(7.2, 7.5). The service chooses the request's `approvalId` (unique among the
service's requests since it started) and derives the code from it, the host and
the request:

```text
requestDigest = SHA-256(lps("tsm-approval-request-v1")
                || lps(kind) || lps(exe) || lps(interpreter) || lps(script)
                || lps(cwd) || lps(uid as text) || args as a list
                || the references, each in canonical form (4.5), as a list)
code = the first 10 characters of
       base32(SHA-256(lps("tsm-approval-code-v1") || lps(host)
                      || lps(approvalId) || requestDigest))
```

The identity members are those of 7.1 (`interpreter` and `script` empty when
absent; `uid` a decimal number or the SID). `base32` is RFC 4648's alphabet
`A`–`Z`, `2`–`7`, upper case, without padding; a reader takes a code in any
case and without the spaces a person may type. The code is shown, not secret:
it names the request, and the token proves the approval.

### 9.6 The approval-code token

Pairing gives each approver device and host an **approval-token key**, 32
bytes both keep in their device settings. For a code shown on `host`, the
approving device computes

```text
token = base32(the first 16 bytes of HMAC-SHA256(approvalTokenKey,
          lps("tsm-code-token-v1") || lps(host) || lps(code) || lps(decision))
```

26 characters (128 bits), where `decision` is `once`, `always`, `folder` or
`never` (`approval.issue` returns it as `approvalToken`). The approval id and
the request enter through the code, which is all the approving device is
given. For a decision other than `once`, the approving app also writes the
signed grant into the vault.

The service redeems a token (`approval.redeem`, `tsm approve <token>`):

1. It reads the token in any case, without spaces; anything that is not 26
   base32 characters is refused.
2. For every request waiting with a code, every recorded approval-token key
   and every decision, it recomputes the token and compares in constant time.
3. A match answers that request: allowed for `once`, `always` and `folder`,
   `denied` (reason `refused`) for `never`. A lasting decision is applied only
   from the signed grant (7.2), never from the token.
4. A token is single-use: the service records each redeemed token until its
   request has ended and refuses it again. It expires with its code, when the
   request ends (the code timeout, default 5 minutes); a token for an ended or
   unknown request matches nothing.
5. A token that matches nothing is answered `error` `denied` (reason
   `bad_token`), counts as a failed admin authentication and counts against
   every request waiting with a code; the third ends such a request `denied`
   (section 11).

### 9.7 The approval link

The approval link joins a host's service and the service of a paired
approver device, on behalf of its manager app (7.2). The approver connects; the host listens on its VPN or LAN address
only (phase A). The link runs over an `ApprovalChannel`, a bidirectional byte
stream (`incoming`, `send`, `close`) that a TCP connection implements in
phase A and the relay in phase C. On the channel every message is a **frame**:
its length as 4 bytes big-endian, then its bytes; a frame over 1 MiB closes
the link. The first two frames are the handshake, every later frame one
transport message.

**Keys.** Each side has a **link key**: an X25519 key and an ML-KEM-768 key
(FIPS 203, encapsulation key 1,184 bytes). Pairing records each side's public
link key at the other; they are the only trust anchor.

**The handshake** is the Noise pattern `KK`, with every Diffie-Hellman step
paired with an ML-KEM-768 encapsulation and both secrets mixed into the key
schedule, under the protocol name

`tsm-link-v1_KK-hybrid_25519+MLKEM768_ChaChaPoly_SHA256`

The symmetric state is Noise's with SHA-256: `h` = SHA-256(protocol name),
`ck` = `h`; `MixHash(x)`: `h` = SHA-256(`h` || `x`); `MixKey(x)`: (`ck`, `k`)
= HKDF(`ck`, `x`) with Noise's HKDF over HMAC-SHA256, and the nonce counter
`n` to 0; `EncryptAndHash(p)`: `c` = ChaCha20-Poly1305(`k`, `n`, ad `h`, `p`),
`n` + 1, `MixHash(c)`; `DecryptAndHash` the inverse. The nonce is 4 zero bytes
followed by `n` as 8 bytes little-endian. A DH output of all zeros, from a
low-order point, aborts the handshake. The approver is the initiator (`i`),
the host the responder (`r`); `s` is a static key, `e` an ephemeral one.

1. **Both** start with `MixHash` of `i`'s static X25519 public key, `i`'s
   static ML-KEM public key, `r`'s static X25519 public key and `r`'s static
   ML-KEM public key, in that order.
2. **Message 1**, approver to host: `e` (32 bytes) || `ek` (1,184) || `c0`
   (1,088) || the encrypted payload.
   - `e`: a fresh X25519 key, `MixHash(e)`; `ek`: a fresh ML-KEM-768 key,
     `MixHash(ek)`.
   - `MixKey(DH(e, rs))`, then `MixKey(DH(is, rs))`.
   - `c0`: an encapsulation to `r`'s static ML-KEM key; `MixHash(c0)`, then
     `MixKey` of its shared secret.
   - The payload `{"protocol":1,"device":<the approver's device id>}`, by
     `EncryptAndHash`.
3. **Message 2**, host to approver: `e` (32) || `c1` (1,088) || `c2` (1,088)
   || the encrypted payload.
   - `e`: a fresh X25519 key, `MixHash(e)`.
   - `MixKey(DH(re, ie))`, then `MixKey(DH(re, is))`.
   - `c1`: an encapsulation to the approver's `ek`; `c2`: one to its static
     ML-KEM key. For each: `MixHash`, then `MixKey` of its shared secret.
   - The payload `{"protocol":1,"host":<the host's name>}`, by
     `EncryptAndHash`.
4. **Split**: (`k1`, `k2`) = HKDF(`ck`, empty). `k1` encrypts approver to
   host, `k2` host to approver; the final `h` is the handshake hash. The
   ephemeral keys are dropped.

A payload that does not decrypt, a message of the wrong length or an unknown
protocol version closes the link before any transport message. A peer whose
static keys are not the recorded ones cannot produce a message that decrypts,
so an unknown peer is closed at message 1 (by the host) or message 2 (by the
approver). A device id that is not the paired one for the recorded keys closes
it too. Each side is authenticated by its static X25519 key and by its static
ML-KEM key, and the session keys depend on X25519 and ML-KEM-768 secrets alike.

**Transport.** Each direction has its key and counter `n` from 0: a transport
message is ChaCha20-Poly1305(`k`, `n`, empty ad, the message's JSON), `n` + 1.
A frame that does not decrypt (altered, replayed, dropped or reordered) closes
the link. The messages are the JSON messages of section 2.2, each with `op`:

| From | Message | Answer | Meaning |
| --- | --- | --- | --- |
| approver | `ready` | — | its first transport frame; the host sends nothing after message 2 before it has decrypted `ready`, which proves the approver holds its static ML-KEM key |
| host | `approval_needed` | — | as on the admin endpoint (7.2) |
| approver | `approve {id, approvalId, decision, secret, folder?, pin?}` | `ok` or `error` | the answer to a prompt; for a decision other than `once` the app also writes the signed grant |
| host | `approval_closed` | — | the prompt was answered or ended |
| approver | `grant {id, grant, clientToken?, approvalId?}` | `ok` or `error` | a signed grant (9.4) for the host to apply at once, before the vault copy arrives; with `approvalId` it answers that waiting request, with `clientToken` it brings the token its `exe-token` subject names (7.4) |
| approver | `revoke {id, host, grantId, revoked, approver, signatures}` | `ok` or `error` | a signed revocation (9.4), applied at once |
| approver | `keychange {id, statement}` | `ok` or `error` | a key-change statement (9.4); one the host took already (from the vault) is answered `ok` |
| either | `linkKey {id, device, x25519, mlKem768}` | `ok` or `error` | the sender's new link public key; the peer records it, authenticated by this session under the old keys, and accepts the old key for the migration period. A host that rotated its own link key and is reached by an approver under its previous key sends its new key first in that session (`id` `host-link-key`, before it answers anything); the approver records it for that host and answers `ok` (`error` when `device` is not the host it connected to) |
| either | `rekey` | — | after sending it the sender replaces its sending key `k` by Noise's REKEY (the first 32 bytes of ChaCha20-Poly1305(`k`, 2^64 − 1, empty ad, 32 zero bytes)); the receiver does the same to its receiving key after decrypting it. The counter goes on. Each side sends it after 2^20 frames or an hour |

The answers are `ok {id}` and `error {id, kind, message, details?}` of
sections 6 and 10 (`denied` for an object whose signatures are not accepted).
Any other message closes the link. A new connection makes a new handshake.

### 9.8 Pairing

Pairing brings a machine into the user's fleet (part-sharing, DP-60–DP-64,
DP-177). It runs between the two machines, not on the service's endpoints:
the giving side's app opens a pairing window, a TCP port bound to its LAN
and VPN addresses only (private IPv4, IPv6 unique local) for at most five
minutes, and shows a one-time code `<number>-<word>-<word>` (the number
1..999, the words from tom_secrets_core's fixed list of 256). While the
window is open the giving side announces it on the LAN by mDNS (DNS-SD) as
a service of type `_tsm-pair._tcp`, named by its device, with the TXT keys
`v` (`1`), `n` (the code's number) and `a` (the window's addresses, comma
separated); the receiving side browses and takes the one window whose
number the user typed, else (none or several, or over the VPN, which mDNS
does not cross) the user types the address. The receiving side connects. The window takes the first connection only and closes after
that one attempt, right or wrong. The frames are the approval link's (4-byte
length, at most 1 MiB, 9.7), so a phase-C relay carries them unchanged.

1. The receiving side (SPAKE2's A) sends `{"op":"hello","version":1,
   "device"}`; the giving side (B) answers `{"op":"hello","version":1,
   "device","message":pB}`; A then sends `{"op":"message","message":pA}`.
   SPAKE2 is RFC 9382's P256-SHA256-HKDF-HMAC with the RFC's M and N, the
   device names as the identities A and B, the AAD `tsm-pair-v1`, and w =
   HKDF-SHA-256(the code, salt `tsm-pair-code-v1`, 40 bytes) mod the group
   order. A point that is not an uncompressed point of P-256 is refused.
2. A sends `{"op":"confirm","mac":cA}`; B checks it and answers
   `{"op":"confirm","mac":cB}`, or `{"op":"error","reason":"wrong_code"}`
   and ends (the code is burnt).
3. Under the SPAKE2 key (HKDF-SHA-256(Ke, info `tsm-pair-channel-v1`)), A
   sends `{"op":"kem","encapsulationKey"}` (a fresh ML-KEM-768 key) and B
   answers `{"op":"kem","ciphertext"}`. The session key is HKDF-SHA-256 over
   Ke || the ML-KEM shared secret, salt SHA-256(TT || encapsulation key ||
   ciphertext), info `tsm-pair-session-v1`. A sends `{"op":"confirm","mac"}`
   = HMAC(session key, `tsm-pair-confirm-A` || that hash), B answers with
   `tsm-pair-confirm-B`.
4. The giving side shows the receiving device's name and what it may get;
   the user confirms. B sends `{"op":"bundle","bundle"}` or
   `{"op":"declined"}`. The bundle carries the vaults chosen (`name`,
   `locator`, `primary`, `keyFile`, `repositoryKey`), the shared
   configuration (`configYaml`), tokens pasted for this device
   (`repository`, `token`, `expires`), and the giving device's public keys
   (`giverKeys`: `approverKey`, `linkKey`, `linkAddress`). Never a private
   approver or link key, a master password, the allow list or the audit
   log.
5. A answers `{"op":"done","keys"}` with its own public keys (`linkKey`,
   `approverKey` when it approves, `linkAddress`: where its approval link
   listens, its device setting `approvalLink`, when it has one), or
   `{"op":"refused","reason"}` when it cannot take the bundle (a machine
   being set up needs the primary, and a `github:` primary its token); then
   both sides end and nothing is stored. Both derive the approval-token key,
   HKDF-SHA-256(session key, info `tsm-pair-token-key-v1`, 32 bytes).

The frames of steps 3 to 5 are XChaCha20-Poly1305 boxes (nonce, ciphertext,
tag) with the sender's role and a counter per role as associated data
(`A0`, `A1`, … / `B0`, …). The receiving side stores nothing before step 5
is done. The giving side then hands its service what it keeps
(`pair.record`, 6.3): the receiving device as a host it approves for (and
as an approver when it sent an approver key), with its device record in the
primary. A machine set up by the pairing (the First run, or `tsm pair`
through the service's pairing mode) writes its new trust material with
the giving device recorded as its approver and, when it approves too, as a
host it approves for; a running service records the same through
`pair.record`. A machine set up by pairing with an approval link (`tsm pair
--link`, or the First run wizard's "This machine's approval link") is set
up with that `approvalLink` and sends it as its `linkAddress`, so the
giving side records it with the host (`pair.record`'s `host.address`) and
its service opens the link as soon as the new machine's service listens.
An `approvalLink` is `host:port` of one VPN or LAN address (an IPv6
address in brackets), never every interface (`0.0.0.0`, `::`).

### 9.9 Test vectors

- [`vectors/signatures.json`](vectors/signatures.json): three approver keys
  from seeds, with their key ids; a grant, a grant with a relaxed pin, a
  revocation, an approval record and a key-change statement, each with its
  signed bytes and signatures, all accepted under the recorded key; and
  objects that must be refused: a changed member, one algorithm alone, an
  unrecorded key, a grant's signatures on a revocation, signatures of two
  different objects, a key change signed by the old key only, and one whose
  `newKeyId` is not its keys' id. ML-DSA-65 signs in its deterministic mode
  there (all-zero randomness), which verifies like the hedged mode.
- [`vectors/approval_codes.json`](vectors/approval_codes.json): requests with
  their request digests and codes; tokens for every decision with their HMAC
  input; redemption cases with their outcome.
- [`vectors/link_handshake.json`](vectors/link_handshake.json): both link keys
  and every random input of a handshake (ephemeral seeds, encapsulation
  coins); both messages and frames, the handshake hash after message 1 and at
  the end, the transport keys; transport frames with their plaintext,
  ciphertext and a rekey in each direction; and failures the receiver must
  detect.

## 10. Error kinds

An `error` has `kind`, `message` (for people; never a value, a token or a
key) and optional `details`. Every library maps the kinds to its own error
type and adds `not_running` (section 3).

| Kind | Meaning | `details` |
| --- | --- | --- |
| `locked` | the service is locked and no unlock came in time, or `wait` was `false` | — |
| `denied` | the client may not have this, or a connection is refused | `reason`: `never` (a never grant), `refused` (at the prompt), `no_approver`, `unidentifiable` (the identity could not be measured), `reserved_field` (a passkey field), `not_allowed_op` (`match` / `propose` from a client that is not the browser host or a helper, 5.5, or a `propose` without a grant), `bad_token` (Windows `hello.token`, or an approval token that matches no waiting request, 9.6), `bad_mac`, `bad_password`, `bad_bundle`, `wrong_executable` (admin), `other_user` (a peer of another OS user), `stale_base` (a `save` of a revision the file has moved past, 6.4), `history_rewritten` (a `save` to a branch rewritten without a compaction; the app decides, 6.4), `branch_moving` (a `save` whose branch moved during every attempt, or a `vault.move` whose branch moved meanwhile; save again), `target_exists` (a `vault.move` to a place a file is at already, 6.4), `token_refused`, `token_no_access`, `token_read_only` (a `token.set` whose token GitHub refuses, which does not see the repository, or which may not write there, 6.3) |
| `not_found` | no candidate, or the winning entry lacks the field | `dimensions` (the request's values), `entry` (`{store, path, uuid}`, when the field is missing), `field` |
| `ambiguous` | several candidates rank equal | `candidates`: `[{store, path, uuid}]`, never values |
| `needs_unlock` | the store holding the answer could not be reopened since its key changed | `store` |
| `unavailable` | the store holding the answer could not be fetched and has no offline copy; for `propose`, no app is attached | `store`, `reason` (`no_cache`, `no_app`) |
| `offline` | admin only: a `reload` whose fetch failed for a network reason, or a `save` that cannot be taken while offline | `stores` |
| `token_expired` | admin only: as `offline`, because GitHub answered 401 or 403 or the token is past its expiry | `stores` |
| `malformed` | a frame, a reference, a binding or a request cannot be read | `reason` (section 4.6, 4.7, or `duplicate_id`, `frame`; for admin requests the member that cannot be read, e.g. `password`, `stores`, and `bytes` for a `save` whose file is no base64 or does not open with the store's keys, 6.4) |
| `timeout` | an approval was not answered in time | — |
| `rate_limited` | the identity is held back (section 11) | `retryAfterMs`; `reason`: `requests` (the token bucket), `connections` (a connection over the caps, answered at its `hello` and closed), `held_back` (three refusals at prompts), `too_many_prompts` |
| `unsupported` | an unknown `op`, or a protocol the service does not speak; a `token.set` whose token has nowhere to be kept | `op`, or `protocols`; `reason` `no_keychain` |
| `internal` | a failure of the service | `code`, never a value |

## 11. Rate limits

Per measured identity, configurable in the service (the values below are the
defaults):

| What | Limit |
| --- | --- |
| `get`, `getMany` and **[B]** `getFile`, `match`, `propose` | a token bucket of 20 per second, bursts of 50 |
| refusals (`denied`, `not_found`, `ambiguous`) | ten in a minute make the identity wait 10 s per request for ten minutes |
| open connections | 16 per identity, 256 in all; one over is answered `rate_limited` at its `hello` and closed |
| pending prompts | one per identity and reference, at most three per identity; three refusals in ten minutes hold the identity back ten minutes |
| failed admin authentications | the growing delay of 6.1 |
| approval tokens | a token that fails counts as a failed authentication; three for one waiting request end it `denied` |

## 12. Schemas, vectors and tools

- [`schema/`](schema/): 90 message schemas, one per `op` (JSON Schema draft
  2020-12, file `<op>.json`), and `common.json` with the shared definitions,
  the signed objects of 9.4 among them. Each schema's `x-tsm` member names
  its endpoint (`link` for the approval link), direction (`a2h` approver to
  host, `h2a`, `both` on the link) and phase, and `alsoOn` the further
  endpoints a message is used on unchanged. A schema's `$id` is where it is published,
  `https://raw.githubusercontent.com/al-the-bear/tom_secrets_clients/main/protocol/schema/<op>.json`,
  so a validator resolves the `$ref`s into `common.json` from there.
- [`vectors/frames.json`](vectors/frames.json): a frame for every message, as
  hex with its decoded JSON, a phase-B binary chunk, and the invalid frames of
  2.4 with their outcome.
- [`vectors/references.json`](vectors/references.json): valid references with
  their parse results and canonical forms, invalid ones with their reason,
  and formatting cases.
- [`vectors/hmac.json`](vectors/hmac.json): the admin challenge's inputs and
  MACs.
- [`vectors/discovery.json`](vectors/discovery.json): the runtime directory
  per OS and environment, and port files.
- [`vectors/signatures.json`](vectors/signatures.json),
  [`vectors/approval_codes.json`](vectors/approval_codes.json) and
  [`vectors/link_handshake.json`](vectors/link_handshake.json): section 9's
  signed objects, approval codes and tokens, and the approval link (9.9).
- [`tool/`](tool/): `tsm_protocol.py`, the reference implementation of the
  computable parts (references, frames, the MAC, discovery);
  `gen_schemas.py` and `gen_vectors.py`, which write `schema/` and
  `vectors/`; and `check_protocol.py`, which checks that this document, the
  schemas and the vectors agree. Of section 9, `tsm_protocol.py` computes the
  signed bytes, key ids, codes and tokens; the signatures and the link need
  ML-DSA and ML-KEM:
  - `vectors_dart/` (Dart, on `tom_pqc`) writes `signatures.json` and
    `link_handshake.json` and tests both roles of the link against them;
  - `vectors_go/` recomputes every signature, handshake message, key and
    transport frame of those two files, and the codes and tokens of
    `approval_codes.json`, with Go's standard library (Go 1.27 or later),
    independently of the Dart and the Python tool.

  Run by hand (Python 3.9 or later, with `jsonschema` for the checker), the
  Dart tool first, since `frames.json` carries its signed grant:

  ```text
  python3 protocol/tool/gen_schemas.py
  (cd protocol/tool/vectors_dart && dart run bin/gen_vectors.dart)
  python3 protocol/tool/gen_vectors.py
  python3 protocol/tool/check_protocol.py
  (cd protocol/tool/vectors_dart && testkit :test)
  (cd protocol/tool/vectors_go && go run .)
  ```

Every value in the vectors is demo data under demo keys derived from labels;
no real secret is in them.

## 13. Decisions this document makes

The design (the idea document's part-protocol, part-structure and
part-service) leaves these open; this document fixes them:

1. The frame length counts the payload only; the limits apply to the payload.
2. Every JSON message names itself in `op`, answers included; the answers of
   admin requests are `ok` or a named result message.
3. A request `id` is an integer from 1 to 2^53 − 1; a duplicate open `id` is
   `malformed` (`duplicate_id`).
4. **Store names** follow part-structure's rule `[a-z0-9][a-z0-9_-]*` (a
   leading digit allowed), where the design's grammar wrote `store = name`
   (a leading letter); the grammar of 4.1 follows the rule.
5. Path segments may not begin with an unescaped `@` or `~` (4.4), so overlays
   and uuid references are never confused with paths.
6. Control characters appear in references only escaped; escapes must form
   well-formed UTF-8.
7. The canonical form (4.5) sorts bindings, escapes minimally with upper-case
   hex and omits `#Password`.
8. In `getMany`, `wait` and `timeoutMs` apply to the whole request and each
   item carries `ref`, `dimensions` and `field`; at most 256 items.
9. The admin MAC's input encodes `serviceStart` as 8 bytes big-endian
   milliseconds; `challenge` also carries the protocol version.
10. Port files and `client.token` allow one trailing line end; `client.token`
    is base64 of 32 bytes.
11. Discovery falls back to `/tmp/tsm-<uid>/` on macOS without `$TMPDIR`, and
    to `%USERPROFILE%\AppData\Local` on Windows without `LOCALAPPDATA`.
12. A binary chunk carries its request id in 8 bytes; a `getFile` answer ends
    with `end {id, sha256}`.
13. An unknown enumerated value is read as the most general known one.
14. Signatures are DP-160's list of separate Ed25519 and ML-DSA-65 items over
    length-prefixed bytes (9.1, 9.3), not a composite signature: a list lets a
    later algorithm be added beside them, and the ML-DSA context carries the
    object's label.
15. An approver key id is 16 bytes of a labelled SHA-256 of both public keys
    (9.2); a key-change statement names the old key by its id, which the host
    checks against the key it recorded.
16. The vault path of an approval code (`tsm approve` without a token) is a
    signed **approval record** (`tsm-approval-v1`, 9.4) answering the waiting
    code, beside the grant of a lasting decision.
17. The approval-code token's tag covers the host, the code and the decision
    (9.6); the approval id and the request enter through the code (9.5),
    because the approving device is given only the code. `approval.issue`
    therefore names the `host`. What a lasting decision covers is signed in the
    grant, so the tag carries no digest of it.
18. The request digest of the approval code covers the identity's kind, exe,
    interpreter, script, cwd, uid and arguments and the canonical references.
19. On the approval link (9.7): the static keys are mixed into `h` first, in
    the order initiator X25519, initiator ML-KEM, responder X25519, responder
    ML-KEM; the handshake payloads are `{"protocol":1,"device"}` and
    `{"protocol":1,"host"}`; a frame is at most 1 MiB; a `rekey` message
    announces each REKEY, so both sides switch at the same frame; a new link
    key is passed as `linkKey` inside a session under the old keys.
20. `hello` carries the client's `features` **[B]**, so that binary frames
    (2.5), which both sides must announce, can be announced by the client.
21. `source` (5.2, 6) has a third value, `file`, for a `file:` vault read from
    the local disk in this refresh cycle: neither `github` (it was not
    fetched from GitHub) nor `cache` (it is no offline copy) says what
    happened. A `file:` vault has no offline copy, so it answers `file` or is
    `unavailable`.
22. The editing path (6.4): a store's `keys` are `password`, `keyFile` and
    `outerKey`; a `save` must open with them; a moved file is merged when
    `baseRevision` is the service's held copy and refused (`stale_base`)
    otherwise; `statusReport.hardening` names `noCoreDumps`, `notDumpable`
    and `memoryAccessDenied`.
23. The peer identity (7.1): a peer of another OS user is refused with
    `other_user`, and a refused client gets its answer before the connection
    closes (after its first frame); an admin's executable is checked before
    its key, against `tsm` and the manager app beside the service and the
    bootstrap's `admin_executables`.
24. Approvals and grants (7.2, 7.3, 9):
    - a request's items are decided together, so a `getMany` gets one
      prompt; a repeat of a waiting prompt (the same identity and
      references) joins it;
    - an approver on the admin endpoint is a subscribed admin that is not
      `tsm`; with none attached and no link connected the request gets an
      approval code;
    - the service of the approving device signs what its app decides
      (`approve` with a lasting decision, `grants.add`, `grants.revoke`)
      with that device's approver key and writes it into `tsm.grants/<host>`;
    - a grant's signed members carry no hash: the hash a pinned grant holds
      is recorded by the host in its device settings, at the approval made
      there or at the first use of a grant that came from elsewhere, so no
      one who can write the vault can move a pin;
    - a `never` at a prompt also writes a `never` grant; `rate_limited`
      answers carry `retryAfterMs`; a request waiting when the service locks
      ends `locked` (`approval_closed` `abandoned`);
    - the approval link listens on the device setting `approvalLink`
      (`address:port`, a VPN or LAN address, never every interface);
    - the audit log keeps one record per resolved item:
      `{time, host, identity, refs, outcome, grantId?, approver?, entries}`,
      `outcome` being `allowed`, `denied:<reason>`, `timeout`,
      `rate_limited` or `locked`.
25. Client tokens (7.4, DP-20): the approving device makes the token and
    its id (derived from the token, so the host checks that a grant names
    the token it is sent); the attached app sends it in `approve`, a remote
    approver with its grant over the link (`grant {grant, clientToken,
    approvalId}`); `approval_needed` says `wantClientToken` and carries no
    token id; the host keeps the hash and the identities a token came with;
    an approval code issues no token.
26. The app edits the copy of a store the service holds (`vaultFile`, 6.4),
    not a copy it fetches itself: the `revision` it saves against is then
    always one the service accepts, the app needs no GitHub token or clone,
    and editing works while a store is served from its offline copy. Until
    phase B's binary chunks, such a file is limited to what one answer frame
    holds.
27. A key rotation (6.4) writes the new keys into the primary before the
    re-keyed vault, and the service takes a further vault's new keys from
    the primary rather than from the save: the primary is the one place a
    vault's keys are kept, a failed re-keyed save is made again with the
    keys listed, and the old keys stay in the primary entry's history.
    A re-keyed file is never merged, since a merge would need both key sets.
28. A renewed GitHub token (`token.set`, 6.3) is checked before it replaces
    the old one, by a write the vaults do not see: a branch created at the
    default branch's head and deleted again. A fine-grained token's
    permissions are not reported on the wire, and a token that can only read
    would otherwise be found out at the next save.
29. A device rotates its own key pairs together (`keys.rotate`, 6.3) and
    keeps its previous link key for 14 days, in both of its link roles: as
    the approver it connects with it to the hosts the new key has not
    reached, as a host it answers the approvers that still hold it and
    passes them its new key in that session (`linkKey`, 9.7). The
    key-change statement also goes into the vault, so a host the link does
    not reach takes it at its next refresh, and a host that took it there
    answers the same statement over the link `ok`.
30. Adding or removing a vault's outer encryption moves it (`vault.move`,
    6.4): the service writes the new file and only then removes the old one,
    a `github:` vault in one commit, so a failed move leaves the old file;
    the vault's entry in the primary, or for the primary its bootstrap file
    and keychain handles, follow on the device that moves it.
31. Pairing (9.8) runs between the two machines' apps over a pairing
    window, not on the service's endpoints; the services keep only its
    result (`pair.record`). The receiving side is SPAKE2's A because it
    connects; its SPAKE2 message follows the giving side's hello, since both
    identities enter the transcript.
32. A further vault is created through the service (`vault.create`, 6.4):
    the app makes the file, the service writes it where it lives and only
    then lists it in the primary, so a failed write lists nothing and a
    listed vault always has its file.
33. Phase B adds messages as features (`binary`, `getFile`, `match`,
    `propose`, section 8) under protocol `1`: nothing in it is incompatible,
    so the integer is not raised; `welcome.features` is the handshake.
34. `match` and `propose` know the browser host and the helpers by their
    measured executables beside the service (5.5), and `match` lists only
    the entries an `allow` grant of the client covers, without a prompt,
    never a system vault's to the browser host. URL matching (5.7) uses the
    Public Suffix List, so `example.github.io` and `other.github.io` are
    different sites.
35. The ssh-agent (7.6) speaks OpenSSH's agent protocol on an endpoint of
    its own, not these frames. Its grants are grants of 7.3, so they are
    signed, listed, revoked and re-signed as every grant is: what they cover
    is written into the signed `secret` (`ssh-key …`) and a parent-qualified
    client into `subject` (`exe-from`), forms a service that does not know
    them never matches. A confirmation (`confirmOnly`) is a prompt that
    writes nothing.
36. A helper asks for one credential (git's `get`), so `match` takes `pick`:
    the grants decide when they can, and otherwise the user picks the login
    at a prompt, as part-os-integration asks. The pick is remembered as a
    reference grant, which outranks a store grant that covers several
    logins; a `once` pick is a one-time read on the connection. The lookup
    uses the host rule, as git names one host.
37. The GitHub App's user tokens are kept and renewed by the service alone
    (`github.signIn`, part-key-rotation §3): two processes renewing one
    refresh token would spend it twice. A device signed in uses the App's
    token for every `github:` vault; the pasted token stays a choice per
    device (`github.signOut`), the one way to cut off a single device.
38. The OS unlock's bundle carries the composite key, not the password
    (part-os-unlock, DP-72, DP-73): the OS-gated store never holds the
    password text, Argon2 runs again at every unlock, and the key survives
    saves. A service unlocked by a bundle holds no password, so the app's
    editing path takes `keys.compositeKey`; a re-key needs the new password
    typed, and the next unlock writes a new bundle. Lock mode (c)
    (`osUnlock`) relocks the service like (b) on idle; the attached app,
    which senses the screen lock, sends `lock` then.
