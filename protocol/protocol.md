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
larger than an answer frame is sent as binary chunks **[B]**: a `getFile`
answer on the client endpoint (2.5), and on the admin endpoint any request
or answer over its limit, by chunked members (2.7).

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

### 2.7 Chunked members (admin endpoint)

A file crosses the admin endpoint inside a message: `save` and `vault.create`
carry a vault file, `vaultFileData` answers one (6.4). A message whose
payload would exceed its frame's limit (a request's 64 KiB, an answer's
1 MiB) carries its large string members as binary frames instead:

1. The JSON message goes first, without those members. Its `chunked` names
   them in order: `[{name, size, sha256}]`, each member's `size` and
   lowercase hex `sha256` taken over its UTF-8 bytes.
2. The members' UTF-8 bytes follow, joined in that order, as binary frames
   (type `1`) of the message's `id`: the id as 8 bytes, unsigned, big-endian,
   then a chunk of at most the frame's limit minus 8 bytes.
3. The receiver reads the message once all `size` bytes are in. It puts each
   member back as a string, and checks it against its `sha256`.

A sender moves the string members of at least 1,024 bytes; whatever is left
must fit one frame. All members of one message are at most 512 MiB. Chunked
members are used only on a connection where both sides announced the
feature `chunked`:

- the service in its `challenge` (`features`);
- the admin in `auth` or `claim` (`features`).

The service reads chunked requests only after the admin has authenticated,
so a peer that has not proved itself is never read past 64 KiB. A peer
without the feature is sent whole messages, and a `vaultFile` of a file over
the answer limit is refused to it (6.4).

Refused, and the connection closed:

- a chunk of an id with no message pending;
- more bytes than announced;
- a member whose SHA-256 differs;
- a chunked message on a connection without the feature.

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

**[C] The App Group container (macOS).** A sandboxed client reaches no
runtime directory in `$TMPDIR`. The Safari Web Extension's handler, and the
browser host it starts, are such clients. When the service runs from the
manager app's tools folder and the app names its App Group (`TSMAppGroup`
in the app's `Info.plist`, the team-signed build), the service also offers
its client endpoint at
`~/Library/Group Containers/<group>/tsm/client.sock` (the folder mode
0700). The handler sets `TSM_RUNTIME_DIR` to that folder for the host. It
is the same endpoint: the same messages, the same measurement of the peer
(7.1) and the same grants. Nothing else of 3.2 is there.

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
client libraries, `tsm`, the editor, the Tom servers' provider
(`tom_secrets_provider`) — parses and formats them by this section. A client never resolves a reference; it
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
`tom_core_server`'s secret references. Any other character may also be escaped; the canonical
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
| `features` | the optional features it offers (section 8): a phase-B service offers `binary`, `getFile`, `match` and `propose`, a phase-C service `passkey` too; a phase-A service none |
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

or an `error` (section 10). The service serves the copy it holds (in
memory, or its offline cache when the device keeps one) without an age
limit; a client that needs the latest value checks `entry.source` itself.

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
| **[B]** `match {id, url, frameUrl?, userName?, pick?, wait?, timeoutMs?}` | `matches {id, candidates[{entryId, title, userName, matchedUrl, hasTotp}]}` | the login entries matching a page, never a value; only for the browser host and the helpers, others get `denied` (reason `not_allowed_op`); `pick` (the helpers) asks for one login of the host; the browser host's match that no grant covers asks the approvers (a browser prompt); audited |
| **[B]** `propose {id, url, title?, userName, password, wait?, timeoutMs?}` | `accepted {id, known?}` | a login for the app to save, passed to the attached app as the event `proposal`; with no app attached `unavailable` (reason `no_app`); only for the browser host or a helper holding a grant; a helper's credential the vaults hold already is not passed on (`known`) |

**`getFile`** is checked and decided as `get` is (5.6) and answered with the
value as bytes: `file` names the field (an attachment field
`attachment:<name>` without its prefix) and gives its size, the binary
chunks follow in order (2.5), and `end` carries the SHA-256 of all of them
in lower-case hex. A refusal is an `error` as for `get`. A connection whose
`hello.features` does not name both `binary` and `getFile` is answered
`unsupported` with `details.features`, the ones missing.

**[C] A typed key without a field.** When neither `field` nor the
reference names a field, `getFile` of a typed key entry answers its key
material instead of `Password` (part-structure, BP-33): a `certificate`
entry its private key `attachment:private-key.pem`, else its PKCS#12
bundle `attachment:certificate.p12`, else its certificate
`attachment:certificate.pem`; a `pgp-key` entry its secret key
`attachment:private-key.asc`, else its public key
`attachment:public-key.asc`. Every other entry, and `get`, answer
`Password` as before; a field the request or the reference names always
wins.

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
when the best of them is `allow` (`never` beats `allow` at equal rank).
For a helper no prompt is raised (but see `pick` below); an entry no grant
covers is left out. The browser host is never given an entry of a system
vault (the vault's kind, its metadata `tsm.kind`), and never a system
vault's value either: its `get`, `getMany` and `getFile` of one are
answered `denied` (reason `system_vault`), whatever a grant says. `url`
and `frameUrl` are strings of at most 4 KiB (else
`malformed`, reason `url`). With `frameUrl` (a login form in a frame) the
frame is matched instead of the page, and only when it is the same site as
the page (its host, or its registrable domain); a frame of another site
matches nothing. A candidate carries `entryId`, the entry as a uuid
reference (`<store>/~<32 hex>`, section 4) the browser host reads for a
fill (a `match` again, then `getMany` of `UserName`, `Password` and, when
the form has a one-time-code field, `totp`), the title, the user name, the entry's URL that matched as
written, and `hasTotp` (the entry carries a TOTP secret); never a password
or another value. Every `match` is audited (`refs` `match <host>`, the
outcome and the candidates' entries). A locked service waits for an unlock
as `get` does. With `userName` (a string) only that user's logins are
answered.

**The browser prompt** (the browser host, DP-44): when the browser host's
`match` finds no login a grant covers, but the personal and shared vaults
hold logins of the page, the approvers are asked once for all of those
(`approval_needed` with `browser` `true` and `url`, the logins as `refs`
`<store>/~<32 hex>` and `resolved`; `progress` `pending` `approval`). Logins
a grant decides already are not asked about (a `never` keeps one out).

1. `always` writes the grants as for a value (7.2): the scope picked
   (these logins, their stores, or `all`), the subject always the browser
   host as started by its browser (`exe-from <browser> => <host>`, 7.3), so
   each browser gets its own grant; `never` writes `never` grants the same
   way; `folder` is refused (`malformed`). The logins allowed are answered.
2. `once` writes nothing; the browser host started by that browser may list
   those logins and read each once (all the fields of one `get` or
   `getMany`) for 10 minutes, from any of its connections (the
   extension's list and its fill are separate host processes). The lock
   forgets it.
3. Refused, unanswered within the approval timeout, or with no approver
   connected (a browser prompt has no approval code): no candidate.

A page whose logins are covered asks nothing, even when other logins of it
are not covered.

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

### 5.6 What the service checks, in order

For a `get` (and each reference of a `getMany`):

1. **Frame and reference**: a malformed frame or reference costs nothing more.
2. **Rate limit** of the client's measured identity (section 11).
3. **Locked**: with `wait` set and an admin subscribed to the events
   (`subscribe`), the service sends the event `unlock_needed` and `progress`
   (`unlock`), and waits up to the timeout before answering `locked`; with no
   subscribed admin, `locked` at once.
4. **Resolve**: a missing or ambiguous reference is answered `not_found` or
   `ambiguous` without a prompt (names are not secret, values are); a passkey
   field (`KPEX_PASSKEY_*`) is `denied` (reason `reserved_field`) whatever the
   grants say; a store that could not be fetched and has no offline copy is
   `unavailable`.
5. **Allow list**: a matching grant answers at once, a `never` grant answers
   `denied` (reason `never`); otherwise the request goes to approval (7.2)
   and the client gets `progress` (`approval`).
6. **Answer**, and an audit record of the outcome.

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

### 5.8 Passkeys [C]

The browser host takes over a page's WebAuthn calls (part-browser,
part-password-manager, DP-120), and on Windows 11 the passkey plugin
answers Windows' own passkey dialog (part-os-integration). The passkeys
stay in the vaults: the service lists them by their names and signs with
them. No answer carries a private key, and `get` keeps refusing the
`KPEX_PASSKEY_*` fields (`reserved_field`, 5.6). The messages are the
feature `passkey` (section 8), for these two clients only, each told by
its measured executable (7.1):

- the **browser host** of 5.5;
- the **passkey plugin** `tsm-passkey-plugin.exe` beside the service's
  executable (its real path; in the app's MSIX package). It may send
  only these three messages: `get`, `getMany`, `getFile`, `match` and
  `propose` are refused to it.

Any other client is answered `denied` (reason `not_allowed_op`). Byte
values are base64url without padding.

| Request | Answer | What |
| --- | --- | --- |
| **[C]** `passkeys {id, url, rpId, allowCredentials?, wait?, timeoutMs?}` | `passkeyCandidates {id, candidates[{entryId, title, userName, credentialId}]}` | the page's passkeys a grant covers, never a key |
| **[C]** `passkeyGet {id, url, rpId, entryId, clientDataHash}` | `passkeyAssertion {id, credentialId, authenticatorData, signature, userHandle?}` | a sign-in signed with the passkey picked |
| **[C]** `passkeyCreate {id, url, rpId, userId, userName, displayName?, algorithms, excludeCredentials?, wait?, timeoutMs?}` | `passkeyCreated {id, credentialId, authenticatorData, attestationObject, publicKey, publicKeyAlgorithm}` | a new passkey, once the user confirms, kept in a vault |

**The relying party.** `url` is the page (at most 4 KiB, else `malformed`,
reason `url`). `rpId` must be the page's host or a domain above it that is
not a public suffix (5.7's list); the page must be `https`, or `http` on
`localhost`. Anything else is `denied` (reason `rp_id`). The browser host
tells the page by the address the browser reports, never by what the page
says. The passkey plugin names `https://<rpId>/`: Windows checked the
caller's origin against the relying party and signed the request with
the plugin's operation-signing key, which the plugin verifies.

**`passkeys`** answers the passkeys (entries holding `KPEX_PASSKEY_*`
fields) of the personal and shared vaults whose relying party is `rpId`;
with `allowCredentials` (credential ids) only those. A candidate is covered
as a `match` candidate is: an `allow` grant of the browser host names the
entry, its store or `all`, or a `once` of the browser prompt holds it. When
none is covered but the vaults hold passkeys of `rpId`, the approvers are
asked once (the browser prompt of 5.5, with `passkey` `true`), with the same
answers and the same `exe-from` grants. A system vault's passkey is never
answered. Every `passkeys` is audited (`refs` `passkeys <rpId>`).

**`passkeyGet`** signs for the entry `entryId`, which must be a candidate
`passkeys` answers for the same `url` and `rpId` (else `denied`, reason
`not_matched`). `clientDataHash` is the SHA-256 of the client data the
browser host made (32 bytes, else `malformed`, reason `client_data`). The
authenticator data holds the relying party's hash, the flags user present,
user verified, backup eligible and backed up, and the counter 0, as a
synced passkey's do. `signature` is ES256 (DER) or Ed25519 by the key's
kind. `userHandle` is answered when the passkey has one. It needs no
prompt: the user picked the passkey in the extension's own list, or in
Windows' dialog, which the page cannot reach. Audited
(`passkey <rpId>`).

**`passkeyCreate`** asks the approvers whether to save a passkey for
`userName` at `rpId` (`approval_needed` with `passkeyCreate`
`{rpId, userName, url}` and `confirmOnly` `true`: answered `once` or
`never`, no grant written; `progress` `pending` `approval`). With no
approver connected it is `denied` (reason `no_approver`); refused or
unanswered, `denied` (reason `refused`, `timeout`).

1. `algorithms` lists COSE algorithms in the site's order; the first of
   ES256 (`-7`) and Ed25519 (`-8`) is made. Neither: `unsupported`
   (reason `algorithm`).
2. A passkey of the vaults whose credential id is in `excludeCredentials`
   (the site holds it already) is `denied` (reason `excluded`), before any
   prompt.
3. `userId` is the user handle, 1 to 64 bytes.
4. Once confirmed, the service makes the key pair and keeps the passkey in
   a personal or shared vault this machine serves and may write. It goes
   into the vault holding a passkey of that site and user, else one with a
   login of the site, else the first. In the vault it goes into the login
   entry of the site and user name, else a new login entry.
5. It writes the vault as an edit of the app is written. When no vault
   may take it, `unavailable` (reason `no_vault`); when the vault cannot
   be written now, `unavailable` (reason `offline`). Either way the site
   gets no credential the vaults do not hold.
6. The answer carries the `none` attestation object, the authenticator
   data, the public key as DER SubjectPublicKeyInfo and its COSE algorithm.
   Audited (`passkey-create <rpId>`).

## 6. The admin endpoint

### 6.1 The challenge

The admin endpoint answers nothing before both sides have proven they hold
the **admin key** (32 random bytes the service got from its starter):

1. The service sends `challenge {serviceNonce, serviceStart, protocol,
   service, features}`: 32 random bytes, its start time in milliseconds
   since the epoch, its protocol version, `{version}` and the admin features
   it offers (`chunked`, 2.7).
2. The admin answers `auth {adminNonce, mac, client, features}` (the
   features it takes of those offered):
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

An admin without the admin key sends `claim {password, keyFile?, client,
features}` instead of `auth`. The service checks the master password (and key file)
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
| `unlock {id, password, keyFile?}` | `ok` | open the primary file and the stores it names; without `keyFile` the service takes the primary's key file from the device keychain (`tsm.key-file.<id>`), and a `.tsmx` primary's repository key always comes from there (`tsm.repository-key.<id>`; the ids are the first 16 hex digits of SHA-256 over the vault's or the repository's identity, part-stores); a primary that cannot be fetched while the device keeps no copy of it (the offline cache off) is `offline` / `token_expired` with reason `no_copy`: the app waits for GitHub |
| **[B]** `unlock {id, vault, bundle{nonce, ciphertext}}` | `ok`, or `error` `denied` (reason `bad_bundle`: the bundle does not open on this connection, which counts as a failed authentication; `bad_password`: it opens, but its composite key no longer opens the vault, which was re-keyed), `not_found` (no such store; while locked: the primary the bundle opened has another name, and the service locks again), `unsupported` (sent on a connection that claimed the service) | open a vault with the key bundle the app read from the OS-gated store (6.4): `vault` is a store's name as `status` lists it; while the service is locked every bundle is taken as the primary's and unlocks the service as `unlock` with the password does; unlocked, a bundle opens the store it names as `unlockStore` does |
| `unlockStore {id, store, password, keyFile?}` | `ok` | open a store with a password of its own |
| `lock {id}` | `ok` | lock: clear every secret from memory |
| `shutdown {id}` | `ok`, then the connection closes | lock and stop |
| `status {id}` | `statusReport {id, locked, lockMode, protocol, service{version, start}, stores[{name, state, source, fetchedAt?, notPushed, rewritten?{head}, keyChanged?, reason?}], keepsUnwritten?, offlineCacheRemoved?, admins, hardening, expiring?[{kind, key, vault?, expiresAt, daysLeft}], links?[{device, role, state, via?, reason?}], agent?, github?{state, login?}}` | the service's state; `lockMode` is the service's lock mode (DP-14): `a` never relocks, `b` relocks on idle, `c` (phase B) on idle or screen lock; a store's `state` is `current`, `offline`, `token_expired`, `needs_unlock` or `unavailable`; its `source` is as in 5.2 (`github`, `file` or `cache`); `notPushed` counts its changes not yet written to GitHub; `rewritten` names the head of a branch rewritten without a compaction awaiting `history.resolve` (6.4); **[C]** `keyChanged` (with `needs_unlock`, `source` `cache`) marks a store served read-only from a copy under its old key, because another device re-keyed it and its new key is not listed here yet (6.4); a store's `reason` says why an `unavailable` store waits for its remote while no copy of it is held (`offline`, `token_expired`); `keepsUnwritten` (while unlocked) whether a save the remote cannot take waits in memory (6.4); `offlineCacheRemoved` when this start applied the in-memory default to device settings stored before it and deleted their offline cache (the app tells the user once); `hardening` names the protections achieved at start, each `true` or `false`: `noCoreDumps` (no core file; on Windows the error mode against crash dumps), `notDumpable` (Linux: not dumpable, so no debugger of the same user attaches), `privateFiles` (Linux and macOS: umask 077, every file the service writes 0600), `memoryAccessDenied` (Windows: the process DACL refuses `PROCESS_VM_READ` and `PROCESS_VM_WRITE` to all but SYSTEM); `expiring` lists the keys due for a reminder now (part-key-rotation), each with its `kind`, its `vault` when it has one, `expiresAt` and the whole `daysLeft` (negative once expired): `github_token` (key `github-token:<owner>/<repository>`, from the device setting's warning period, default 14 days, before the expiry GitHub reports for the token, or before the expiry recorded with the token when it was entered while GitHub has reported none), `vault_keys` (key `vault-keys:<vault>`, a vault's key file and repository key, from 30 days before their due date: for a further vault the Expires of its entry in the primary, for the primary its metadata's `tsm.keys-due`), `approver_key` and `link_key` (keys `approver-key:<device>` and `link-key:<device>`, this device's approver and approval-link key pairs and those of the peers it recorded, from 30 days before their rotation age of 24 months is over, counted from their creation, their recording at pairing, a key change or a new link key), **[B]** `github_app` (key `github-app:<device>`, this device's GitHub App sign-in, from the warning period of the GitHub token before its refresh token runs out unused); **[C]** `member_key` (key `member-key:<the first 16 characters of its fingerprint>`, the user's member key, from 30 days before its rotation age, `memberKeyAgeMonths`, default 24 months, counted from its entry's creation, is over); **[C]** `certificate` and `pgp_key` (keys `certificate:<vault>/<title>` and `pgp-key:<vault>/<title>`, with `vault`, a typed certificate or PGP key entry of an open vault whose Expires is set (a certificate's notAfter, a PGP key's own expiry), from 30 days before it); `tsm status` shows it where no app is attached; **[B]** `agent` is the ssh-agent's endpoint (`{socket}` or `{pipe}`) while it runs; **[B]** `github` is the GitHub App sign-in's `state` (as `github.app`) and the signed-in user's `login`; **[C]** `links` (while unlocked) are the approval links (9.7): `role` `host` for a host this device approves for, `approver` for an approver of this host; `state` `connected`, `waiting` (a relay channel open, the other side not there), `connecting` or `unreachable`; `via` `address` (the VPN or the LAN) or `relay`; `reason` what failed (a relay that refuses the link, e.g. without the instance token, reads as an unreachable link with the relay's reason) |
| `reload {id}` | `ok`, or `error` `offline` / `token_expired` | fetch every store now and reopen those whose file moved; on a failed fetch the stores stay on the copy held or cached, and the error's `stores` names them (`token_expired` when GitHub refused a token, else `offline`) |
| `vaultKeys {id, stores?}` | `vaultKeySet {id, stores[{store, location, served?, keys}], unserved?[{store, location}]}` | the keys of the open vaults, for the app's editing path (6.4); **[B]** a vault the service opened with an OS unlock's bundle carries `keys.compositeKey` (base64) in place of `password` and `keyFile`; **[C]** during a guided rotation's migration period `keys.previousOuterKey` (base64) names the old repository key the `.tsmx` file keeps a slot for, which every write keeps (6.4); `stores` may also name a vault the primary lists that this machine does not serve (`served` false); `unserved` lists those vaults, without keys |
| `vaultFile {id, store}` | `vaultFileData {id, store, location, revision, served?, bytes}`, or `error` `not_found` (neither an open store nor a vault the primary lists), `needs_unlock` (a vault not served whose listed keys do not open it), `unavailable` (one that cannot be read), `offline` / `token_expired` (`stores`), `unsupported` reason `too_large` | the copy of a store the service holds, for the app's editing path (6.4): an open store, or a vault not served, which the service then reads and holds for editing |
| `save {id, store, bytes, baseRevision?, keys?{password, keyFile?, outerKey?, previousOuterKey?}, recipients?}` | `ok` | hand an edited store file to the service, which writes it (6.4); a re-keyed file is taken as 6.4 says, `keys` carrying the primary's own new keys (a further vault's save with `keys` is `malformed`, reason `keys`); **[B]** after an OS unlock `keys` may carry the primary's `compositeKey` (base64, 32 bytes) in place of `password` and `keyFile`, with `keyFile` beside it for the keychain; **[C]** `recipients` (base64), a shared vault's recipients file written beside the re-keyed vault in the same commit (a member removed, 6.4); with a save that is not re-keyed `malformed` (reason `recipients`) |
| `vault.move {id, store, location, bytes, baseRevision?, keys{password, keyFile?, outerKey?}}` | `ok {id, location, revision}`, or `error` `malformed` (reason `location`: not the store's locator with `.tsmx` added or removed; `keys`: an outer-encrypted file without its repository key, or a plain one with one; `bytes`; `move`), `denied` (reason `stale_base`, `target_exists`, `branch_moving`, `wrong_executable`), `not_found` (no open store), `offline` / `token_expired` (`stores`) | add or remove a store's outer encryption, which moves it to its locator with `.kdbx.tsmx` or `.kdbx` (6.4); **[B]** the primary's `keys` may carry its `compositeKey` in place of `password` and `keyFile`, as for `save`; accepted only from the manager app's executable |
| `vault.create {id, store, location, bytes, keys{password?, keyFile?, outerKey?}, githubToken?, keysDue?, recipients?}` | `ok {id, store, location, revision}`, or `error` `malformed` (reason `store`: not a store name, or one the primary names already; `location`: not a vault locator, or the primary's or a listed vault's; `keys`: an outer-encrypted file without its repository key, or a plain one with one; `bytes`: no base64, or a file that does not open with `keys` or whose metadata cannot be read; `githubToken`: a token for a vault that is not a `github:` vault outside the primary's repository; `create`), `denied` (reason `target_exists`, `wrong_executable`), `offline` / `token_expired` (`stores`) | create a further vault beside the primary: the service writes the new file where it lives and lists it in the primary (6.4); **[C]** with `recipients` (base64) a shared vault: `keys` without `password`, the recipients file written beside it after it is listed (a failure there answers `offline` / `token_expired` reason `recipients` with the vault created; the app writes the file with `vault.recipients.set`); accepted only from the manager app's executable |
| **[C]** `vault.recipients {id, store?, location?, githubToken?}` | `recipientsData {id, store?, location, revision, bytes}`, or `error` `not_found` (no store of that name; reason `no_recipients`: the vault has no recipients file), `malformed` (reason `recipients`: neither or both of `store` and `location`; `location`), `denied` (reason `wrong_executable`), `offline` / `token_expired` | read a shared vault's recipients file beside it (6.4): of a store the service names, or of the vault at `location` not listed yet (joining it), read with `githubToken` for that repository when given, which the service uses for this read only; accepted only from the manager app's executable |
| **[C]** `vault.recipients.set {id, store, bytes, baseRevision?}` | `ok {id, revision}`, or `error` `not_found`, `denied` (reason `stale_base`: the file moved since `baseRevision`, or one is there when none was given; `branch_moving`; `wrong_executable`), `offline` / `token_expired` | write a shared vault's recipients file alone (a member added, 6.4); accepted only from the manager app's executable |
| **[C]** `inbox.list {id, store}` | `inbox {id, store, files[{member, name, revision}]}`, or `error` `not_found`, `malformed` (reason `inbox`), `denied` (reason `wrong_executable`), `offline` / `token_expired` | the packages in the inbox folders beside a shared vault (6.4): every file `inbox/<member>/<name>` whose `<member>` is a member id; accepted only from the manager app's executable |
| **[C]** `inbox.read {id, store, member, name}` | `inboxFile {id, store, member, name, revision, bytes}`, or `error` `not_found` (no store; reason `inbox`: the package is gone), `malformed` (reason `inbox`: not a member id or a package name), `denied` (reason `wrong_executable`), `offline` / `token_expired` | one package of an inbox (6.4); accepted only from the manager app's executable |
| **[C]** `inbox.put {id, store, members[], bytes}` | `ok {id, name}`, or `error` `not_found`, `malformed` (reason `inbox`), `denied` (reason `wrong_executable`, `stale_base`: a file of that name is there, `branch_moving`), `offline` / `token_expired` | put one package into the inbox of each member id in `members` under one new name `<date>-<random>.age` (6.4); a `github:` vault one commit per member; accepted only from the manager app's executable |
| **[C]** `inbox.delete {id, store, files[{member, name}]}` | `ok {id}`, or `error` `not_found`, `malformed` (reason `inbox`), `denied` (reason `wrong_executable`, `stale_base`, `branch_moving`), `offline` / `token_expired` | delete packages from the inbox folders (6.4): imported, declined, or past their 30 days; a `github:` vault in one commit, a package gone already skipped; accepted only from the manager app's executable |
| **[C]** `relay.revision {id, store, folder}` | `relayRevision {id, revision}` (null: nothing there), or `error` `not_found`, `malformed` (reason `relay`), `denied` (reason `wrong_executable`, `not_github`), `offline` / `token_expired` | the revision of a folder below `relay/` in the `github:` store's repository (6.4, part-relay): GitHub's, answered by a conditional request while the branch is unchanged; accepted only from the manager app's executable |
| **[C]** `relay.list {id, store, folder}` | `relayFiles {id, files{<path>: <revision>}}`, or `error` as `relay.revision` | the files below a folder below `relay/` (6.4), each path relative to the folder |
| **[C]** `relay.read {id, store, path}` | `relayFile {id, bytes}` (null: not there), or `error` as `relay.revision` | one file below `relay/` (6.4) |
| **[C]** `relay.create {id, store, path, bytes, message?}` | `ok {id}`, or `error` as `relay.revision`, `denied` (reason `exists`: the file is there already), `malformed` (a file over 1 MiB) | create one file below `relay/` in one commit, once (6.4); `message` is the commit message |
| **[C]** `relay.deleteFolder {id, store, folder}` / `relay.deleteFile {id, store, path}` | `ok {id}`, or `error` as `relay.revision` | delete a folder below `relay/` with its files in one commit, or one file; nothing there: nothing done (6.4) |
| `pair.identity {id, relay?}` | `pairIdentity {id, device, approverKey{ed25519, mlDsa65}, linkKey{x25519, mlKem768}, linkAddress?, linkRelay?, linkId?}` | this device's public keys for a pairing (9.8); **[C]** with `relay` (a relay server, `tsm:<url>`) they name it as `linkRelay` with a fresh `linkId`: the approval link may go through it; accepted only from the manager app's executable |
| `pair.record {id, device, tokenKey, approver?{approverKey, linkKey?}, host?{linkKey, address?}, record?{platform?, keyIds[]}, link?{relay, linkId}}` | `ok`, or `error` `malformed` (reason `pair`: no approver and no host, a token key not 32 bytes, this device itself, a `link` that is no relay server and link id) | keep what a pairing gave (9.8): `approver` records the peer as an approver of this host (its grants and link handshakes are accepted, its approval-code tokens checked with `tokenKey`), `host` records it as a host this device approves for; every key is dated now; a device paired again replaces what was recorded; with `record` the device record goes into the primary (`.tom-secrets/devices`: platform, the time, the device that paired it, the key ids it received, its approver key id and key dates); **[C]** `link` is the relay link both sides agreed on (9.8), kept with the host and the approver, a channel per direction; accepted only from the manager app's executable |
| **[C]** `relay.token.set {id, relay, token?}` | `ok`, or `error` `malformed` (reason `relay`: no relay server), `unavailable` (reason `no_keychain`, `keychain`) | keep `token` as the instance token of the relay server `relay` (`tsm:<url>`) in the OS keychain, for the approval link through it (9.8); no or an empty token removes it; the links through the relay are opened again; accepted only from the manager app's executable |
| **[C]** `relay.put {id, relay, members[], bytes}` | `relayPut {id, name}`, or `error` `malformed` (reason `relay`), `unavailable` (reason `relay`, `relay`: the relay refused it, e.g. without the instance token or past its limits, the message saying why) | put the share `bytes` (an `age` package) into the mailbox of each of `members` (member ids) on the relay server `relay`, under one new package name (`<date>-<random>.age`) kept 30 days, with the instance token the keychain keeps for the relay (part-relay: a shared vault whose mailbox relay, `tsm.mailbox-relay`, is a relay server); the recipients read, fetch and delete their items themselves with their member key's proof (the relay's API); accepted only from the manager app's executable |
| **[C]** `relay.token.list {id, relays[]}` | `relayTokens {id, relays{<relay>: bool}}` | which of `relays` have an instance token kept; a token is never answered; accepted only from the manager app's executable |
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
| `settings.get {id}` | `deviceSettings {id, device, cliApprovals, stores[]}` | the device settings (`device`: `serviceLock{mode, idleSeconds, maxUnlockedSeconds?, lockOnSleep}` with `mode` `never` (a), `idle` (b) or **[B]** `osUnlock` (c), `appLock`, `defaultEnvironment?`, `servedStores?` (absent: every store), `refreshMinutes` (0: no refresh), `offlineCache`, `keyExpiryWarningDays`, `approvalTimeoutSeconds`, `codeTimeoutSeconds`, `approvalLink?`, and the rotation ages and reminder start of DP-85: `otherKeyWarningDays` (30), `keyPairAgeMonths` (24), `primaryKeyAgeMonths` (24), `vaultKeyAgeMonths` (12), **[C]** `memberKeyAgeMonths` (24)), whether command-line approvals are on, and the stores the primary names (the primary first); `locked` while locked |
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
too. A file whose `vaultFileData` exceeds the answer limit (2.3) travels as
chunked members (2.7); an admin without the feature is refused it
(`unsupported`, reason `too_large`, `details.size` its byte count). A `save`
over the request limit is sent the same way. A store's `keys` object carries what
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
result goes into the offline cache when the device keeps one. A branch rewritten without a compaction
refuses the save (`denied`, reason `history_rewritten`), and so does a branch
that moved during every attempt (reason `branch_moving`). After a refused save
on a rewritten branch the store reports the state (`statusReport.stores[]` and
`store_state` carry `rewritten: {head}`), the service holds the refused edit
and stops refreshing the store, and the manager app asks the user:
`history.resolve` with `take: remote` follows the rewritten branch (the edit is
dropped), with `take: merge` the held copy is merged over it and committed on
top. The state ends with the answer or the lock. A store served from
its offline copy, or whose remote cannot be reached or refuses the token
during the save, answers `offline` / `token_expired` with `stores` while the
device keeps an offline cache. Without one (the device setting
`offlineCache` off, the default; and the phone) the save waits in memory
instead, once the file opens with the store's keys: `ok` answers it with
`pending: true`, the store counts it in `notPushed`, `vaultFile` answers it
(its `revision` the one it was made on), and the next refresh that reaches
the remote merges it onto the branch as it is then (the copy it was made on
as the base) and writes it; the lock and a stop drop it
(`statusReport.keepsUnwritten` tells the app). The service's own writes of
the primary (grants, their last use) go the same way; one that cannot be
delivered stays in the held copy and is written by the next refresh.

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

**[C] A shared vault's recipients file** (part-sharing). A shared vault is
opened by a key file alone, and, when outer encrypted, its repository key;
both are kept in `<vault>.keys.age` beside the vault file (`team.kdbx` and
`team.kdbx.tsmx` → `team.keys.age`), an `age` v1 file encrypted to every
member's hybrid recipient (`age1pq1…`, X25519 + ML-KEM-768). Its plaintext
is UTF-8 JSON
`{"format": "tsm-shared-vault-keys/1", "vault": <store>, "keyFile": <base64>, "repositoryKey"?: <base64>, "members": [{"name", "recipient"}]}`,
so any member can write it again. The service never opens it: the app
reads it (`vault.recipients`), decrypts it with the user's member key, and
lists the vault in the primary with those keys like any further vault; a
member's app that finds a listed shared vault no longer opening reads the
file again and lists the new keys. Writing:

- **created:** `vault.create` with `recipients`, written after the vault
  is listed (a second commit for a `github:` vault);
- **a member added:** `vault.recipients.set` writes the file alone over the
  revision read (`stale_base` when another member changed it meanwhile,
  who reads it again);
- **a member removed:** the app lists new keys for the vault in the primary,
  then `save`s the vault re-keyed with `recipients`: the re-keyed file and
  the recipients file in one commit on the branch, without force, refused
  (`stale_base`) when the branch moved since the copy re-keyed (a member
  who re-keyed at the same time; the app re-keys again on top). A `file:`
  vault writes the file, then the recipients file.

**[C] The guided rotation of the own vaults** (part-key-rotation, DP-84,
DP-85). The app rotates a vault's key file or repository key in three
steps, each a write of the primary, with the rotation record in
`.tom-secrets/rotations` (the lock, its migration period, who is pending):

- **prepare:** the new keys are written beside the old ones, in the
  vault's entry of the primary (`tsm.next-outer-key`, the attachment
  `next-keyfile`) or, for the primary's own keys, in the entry `primary`
  of `.tom-secrets/next-keys`. Nothing is re-encrypted. Every service takes
  them at its unlock and at each load of the primary: the primary's own
  next keys go into its keychain beside its keys (`<handle>.next`), and the
  ids of the keys it now holds (a key file's hash, a repository key's id,
  as pairing records them) into its device record in
  `.tom-secrets/devices`; it leaves the record's `pending`. The app lists
  the devices whose record lacks the new key id;
- **switch:** the vault is re-keyed under the new keys (a further vault's
  entry naming them first, the primary's own with `save`'s `keys`). A
  repository key rotated alone is written with two slots, the new key's
  first (`keys.previousOuterKey`, the entry's `tsm.previous-outer-key`, the
  `next-keys` entry's): a device holding only the old key still reads the
  file, its store reported with `keyChanged`, and its `save` is refused
  (`needs_unlock`, reason `key_changed`) as long as the file's first slot
  is for a key it does not hold; a device holding both writes both slots.
  A service whose primary no longer opens with its keys opens it with the
  next keys it took (at the refresh and at the unlock) and keeps them as
  its keys; a repository key rotated alone is taken up as soon as the file
  has a slot for the next one. A key file or master password change leaves
  a device without the new key on its copy under the old one, read-only;
- **finish:** after the migration period or at once ("finish now"): the
  old key leaves the entry (or the `next-keys` entry goes), the file is
  written again with the new key's slot only, and the GitHub history is
  compacted. A device that never took the new key is listed; it opens no
  later version. Before the switch a rotation can be cancelled: the next
  keys and the record go.

**[C] The inbox folders** (part-sharing). A shared vault may carry, in its
folder, `inbox/<member>/` folders, `<member>` a member key's fingerprint:
the mailbox of single-entry exports. A package is an `age` file (to the
member's key or under a passphrase) named `<date>-<random>.age`, the date
the day it was put in (UTC, `YYYY-MM-DD`), the random part 16 hex digits.
The service handles the files as bytes and never opens them: the app
encrypts a package and puts it into the recipients' folders (`inbox.put`),
lists the folders at its sync (`inbox.list`), reads its own packages
(`inbox.read`), and deletes what the user imported or declined, together
with every package of any folder more than 30 days old (`inbox.delete`).
The folder names show who receives packages and when, never what.

**[C] The relay folder** (part-relay: GitHub as the relay). A pairing the
app gives can also wait on a GitHub repository, for a new machine that
reaches the repository already but not this machine over the LAN or the
VPN. Its files live at the repository's root under `relay/pair/<nameplate>/`
(`<nameplate>` the pairing code's number): `offer` (a small JSON with the
time it was opened), the frames of each side numbered in order (`h-0001`,
… for the giving side, `j-0001`, … for the receiving side) and an end
marker per side (`h-end`, `j-end`). The app runs the pairing itself and
reaches the files through the `relay.*` requests of any `github:` store in
that repository; the receiving machine reaches them directly with its own
token. The service only stores and lists the bytes (the frames are the
pairing's own, which reveal nothing about the code and seal the bundle
under the hybrid session key), and it answers `relay.revision` from the
repository's branch snapshot, revalidated by a conditional request, so a
pairing's polls every 2 seconds cost no rate limit while nothing moves.
Each file is one commit; the side that ends second deletes the folder, and
folders older than an hour are deleted by the next pairing opened there.

**[C] A key changed on another device** (part-key-rotation, the migration
period). When the current file of a further vault no longer opens with the
keys this device holds (another device or member re-keyed it), the service
keeps serving the copy it holds, or, after a new unlock, the offline copy
that the held keys still open: read-only, `state` `needs_unlock`, `source`
`cache`, `keyChanged` true. Clients still read it (`get` answers as before);
a `save` is refused (`needs_unlock`, reason `key_changed`), so nothing is
ever written under the old key. Once the primary lists the new keys (the app
takes them up from a shared vault's recipients file, or by pairing), the next
refresh opens the current file and the store is current and writable again.

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
| `approval_needed` | `approvalId, host, identity, refs[], resolved[{store, path, kind}], hostHint?, approvalCode?, wantClientToken?, ssh?, confirmOnly?, pick?, url?, browser?, passkey?, passkeyCreate?` | a request needs an approval (7.2); `wantClientToken` when the client asked for a client token (7.4); **[B]** `ssh` and `confirmOnly` for an ssh-agent signature (7.6); `pick` and `url` for a helper's pick prompt (5.5); `browser` and `url` for a browser prompt (5.5); **[C]** `passkey` for a browser prompt of passkeys, `passkeyCreate` `{rpId, userName, url}` (with `confirmOnly`, no entries) for a new passkey (5.8) |
| `approval_closed` | `approvalId, outcome` (`approved`, `denied`, `timeout`, `abandoned`, `no_approver`) | a prompt was answered or ended elsewhere |
| `locked`, `unlocked` | — | the service locked or unlocked |
| `store_changed` | `store, revision?` | a store was reopened with new content |
| `store_state` | `store, state, source, fetchedAt?, notPushed, rewritten?{head}, keyChanged?` | a store's state or source changed (at a refresh, a `reload`, an unlock of the store), or its branch was found rewritten without a compaction (`rewritten`, 6.4) or the rewrite answered; **[C]** `keyChanged` as in `statusReport` |
| `key_expiry` | `key, expiresAt, daysLeft` | a key the product rotates or keeps expires soon (the GitHub tokens, the vaults' key files and repository keys, the approver and approval-link key pairs, **[C]** the certificates and PGP keys of the vaults; the keys of `statusReport.expiring`): sent when it reaches a reminder step (the first day of its warning period, 7 days and 1 day before, and once a day once expired); an admin that subscribes gets the reminders due at that moment |
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
| `parent` | `{exe, args?}` of the parent process; for the browser host started through `cmd.exe` (the Chromium browsers on Windows), the shell's parent, the browser |
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
  | `passkey` | **[C]** `passkeys`, `passkeyCandidates`, `passkeyGet`, `passkeyAssertion`, `passkeyCreate`, `passkeyCreated` |

  A client sends a feature's messages only when `welcome.features` names it,
  and names in `hello.features` the features it takes; the service sends
  binary frames only to a client whose `hello.features` names `binary`. A
  phase-A service ignores `hello.features` and offers none; a phase-B
  service offers the first four, a phase-C service `passkey` too. This is the version handshake: the integer
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
5. A answers `{"op":"done","keys","platform"}` with its own public keys
   (`linkKey`, `approverKey` when it approves, `linkAddress`: where its
   approval link listens, its device setting `approvalLink`, when it has
   one) and its platform (`macos`, `linux`, `windows`, `ios`, `android`;
   the giving side records it in the device record, `pair.record`'s
   `record.platform`, and leaves out one that is no lower-case name), or
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

**[C] Over the relay server.** The relay server (`tom_secrets_relay`,
`tsm:<url>`) carries the pairing's bytes unchanged: the giving side
allocates the nameplate (the code's number) with `POST /v1/pair`, both
sides open the WebSocket `/v1/pair/<nameplate>`, and every binary message
of one reaches the other. The relay sees only the frames above, never the
code. The same server carries the approval link's bytes on
`/v1/link/<link-id>` (with its instance token in token mode) and holds
mailbox items, `age` packages a recipient reads after proving its member
key; its API is in that package's README.

**[C] The approval link through a relay server.** A pairing may agree on
a relay server for the approval link, for two devices that do not reach
each other on the network or the VPN later. Each side's public keys may
name `linkRelay` (a relay server, `tsm:<url>`) and `linkId` (128 random
bits in base64url, `^[A-Za-z0-9_-]{8,128}$`): the giving side's when it
names them (the app passes its pairing relay to `pair.identity`), else the
receiving side's (the relay it paired through, when that is a relay
server). Both sides record the agreed relay and id with the host and the
approver (`pair.record`'s `link` on the giving side): each direction is its
own channel on the relay, `<linkId>-g` for the giving device as the host,
`<linkId>-r` for the receiving device. A host keeps the channel of each of
its approvers open while unlocked (`/v1/link/<channel>`); an approver
tries the host's address first and opens the channel when it does not
answer, or when the host has none. The handshake and the messages of 9.7
run over the channel unchanged. A relay in token mode refuses a link
without its instance token, which the app keeps per relay in the keychain
through the service (`relay.token.set`); `tsm pair --relay tsm:<url>
--token-env <VAR>` hands it to a machine set up by pairing. An older peer
names no relay link and pairs as before.

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
| `denied` | the client may not have this, or a connection is refused | `reason`: `never` (a never grant), `refused` (at the prompt), `no_approver`, `unidentifiable` (the identity could not be measured), `reserved_field` (a passkey field), `not_allowed_op` (`match` / `propose` from a client that is not the browser host or a helper, 5.5, or a `propose` without a grant; **[C]** a passkey request from a client that is neither the browser host nor the passkey plugin, or a `get` / `getMany` / `getFile` / `match` / `propose` from the passkey plugin, 5.8), `system_vault` (a system vault's value asked by the browser host, 5.5), `bad_token` (Windows `hello.token`, or an approval token that matches no waiting request, 9.6), `bad_mac`, `bad_password`, `bad_bundle`, `wrong_executable` (admin), `other_user` (a peer of another OS user), `stale_base` (a `save` of a revision the file has moved past, a re-keyed `save` whose branch moved, or **[C]** a `vault.recipients.set` over a recipients file that moved, 6.4), `history_rewritten` (a `save` to a branch rewritten without a compaction; the app decides, 6.4), `branch_moving` (a `save` whose branch moved during every attempt, or a `vault.move` whose branch moved meanwhile; save again), `target_exists` (a `vault.move` to a place a file is at already, 6.4), `token_refused`, `token_no_access`, `token_read_only` (a `token.set` whose token GitHub refuses, which does not see the repository, or which may not write there, 6.3); **[C]** `exists` (a `relay.create` of a file that is there, 6.4), `not_github` (a `relay.*` request for a store that is not in a GitHub repository, 6.4) |
| `not_found` | no candidate, or the winning entry lacks the field; for admin requests no store of that name | `dimensions` (the request's values), `entry` (`{store, path, uuid}`, when the field is missing), `field`; **[C]** `reason` `no_recipients` (a `vault.recipients` of a vault without a recipients file, 6.4), `inbox` (an `inbox.read` of a package that is gone, 6.4) |
| `ambiguous` | several candidates rank equal | `candidates`: `[{store, path, uuid}]`, never values |
| `needs_unlock` | the store holding the answer could not be reopened since its key changed | `store` |
| `unavailable` | the store holding the answer could not be fetched and has no offline copy; for `propose`, no app is attached | `store`, `reason` (`no_cache`, `no_app`) |
| `offline` | admin only: a `reload` whose fetch failed for a network reason, a `save` that cannot be taken while offline (6.4), or an `unlock` whose primary cannot be fetched while the device keeps no copy of it | `stores`; `reason` `no_copy` (the `unlock`) |
| `token_expired` | admin only: as `offline`, because GitHub answered 401 or 403 or the token is past its expiry | `stores` |
| `malformed` | a frame, a reference, a binding or a request cannot be read | `reason` (section 4.6, 4.7, or `duplicate_id`, `frame`; for admin requests the member that cannot be read, e.g. `password`, `stores`, and `bytes` for a `save` whose file is no base64 or does not open with the store's keys, 6.4; **[C]** `relay` for a `relay.*` request without a store or a path below `relay/`, or a file over 1 MiB) |
| `timeout` | an approval was not answered in time | — |
| `rate_limited` | the identity is held back (section 11) | `retryAfterMs`; `reason`: `requests` (the token bucket), `connections` (a connection over the caps, answered at its `hello` and closed), `held_back` (three refusals at prompts), `too_many_prompts` |
| `unsupported` | an unknown `op`, or a protocol the service does not speak; a `token.set` whose token has nowhere to be kept | `op`, or `protocols`; `reason` `no_keychain` |
| `internal` | a failure of the service | `code`, never a value |

## 11. Rate limits

Per measured identity, configurable in the service (the values below are the
defaults):

| What | Limit |
| --- | --- |
| `get`, `getMany` and **[B]** `getFile`, `match`, `propose` and **[C]** `passkeys`, `passkeyGet`, `passkeyCreate` | a token bucket of 20 per second, bursts of 50 |
| refusals (`denied`, `not_found`, `ambiguous`) | ten in a minute make the identity wait 10 s per request for ten minutes |
| open connections | 16 per identity, 256 in all; one over is answered `rate_limited` at its `hello` and closed |
| pending prompts | one per identity and reference, at most three per identity; three refusals in ten minutes hold the identity back ten minutes |
| failed admin authentications | the growing delay of 6.1 |
| approval tokens | a token that fails counts as a failed authentication; three for one waiting request end it `denied` |

## 12. Schemas, vectors and tools

- [`schema/`](schema/): 119 message schemas, one per `op` (JSON Schema draft
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
    otherwise; `statusReport.hardening` names `noCoreDumps`, `notDumpable`,
    `privateFiles` and `memoryAccessDenied`.
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
    the entries an `allow` grant of the client covers, never a system
    vault's to the browser host, which gets no system vault's value either.
    A helper's `match` raises no prompt but for `pick`; the browser host's
    raises the browser prompt when nothing is covered (decision 39). URL
    matching (5.7) uses the Public Suffix List, so `example.github.io` and
    `other.github.io` are different sites.
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
    saves. A service unlocked by a bundle holds no password: the app's
    editing path takes `keys.compositeKey` (with the key file the keychain
    holds beside it) and hands it back in the primary's `save` and
    `vault.move` keys; a re-key that keeps the password but changes the key
    file needs the password typed, and the next unlock writes a new bundle. Lock mode (c)
    (`osUnlock`) relocks the service like (b) on idle; the attached app,
    which senses the screen lock, sends `lock` then.
39. The browser host gets its grant by a prompt at its first `match` that
    nothing covers (DP-44): an extension can only ask by listing, and a
    grant made by hand or by switching the browser on in the app would not
    know which browser starts the host. The prompt's lasting answer names
    the measured browser (`exe-from`), so each browser is approved once and
    on its own; on Windows the measured parent is taken above `cmd.exe`,
    which the Chromium browsers start a host through. A `once` holds for
    the browser, not the connection, for 10 minutes, since the list and the
    fill run in separate host processes.
40. A shared vault's keys travel in an `age` file beside it, never through
    the service (part-sharing, DP-63, DP-177): only a member's app holds the
    member key that opens it, and the file opens with the `age` command line
    too. The service reads and writes the file as bytes, and a member
    removed re-keys the vault and rewrites the file in one commit, so no
    commit pairs a vault with a recipients file that does not open it.
41. A device whose keys no longer open a vault's current file keeps reading
    its copy under the old key, read-only, instead of losing the vault
    (part-key-rotation, the migration period): during a rotation the
    devices take up the new key one by one, and refusing every write keeps
    a device from committing a file under a key the others have left.
42. Single-entry exports travel in `inbox/<member>/` folders beside a
    shared vault as opaque `age` files (part-sharing, BP-34): the service
    lists, reads, writes and deletes them but never holds a key to them, a
    package is never merged or rewritten, and the date in its name lets any
    member's app expire it after 30 days without opening it.
43. The guided rotation of the own vaults keeps the next keys in the
    primary, which every device already reads, and lets each service take
    them on its own (part-key-rotation): no message carries a key between
    devices, the device records say who holds the new key, and a two-slot
    `.tsmx` lets a device that has not yet taken it keep reading while it
    writes nothing.
44. A typed key entry served as a file answers its key material when no
    field is named (BP-33): a program asking for a certificate or PGP key
    gets the key it needs to use it, `get` keeps answering `Password` (the
    key's passphrase), and naming a field always wins, so no reference
    changes its meaning.
45. A pairing through GitHub keeps its frames as files in the repository
    the receiving machine reaches with its own token (part-relay): no
    server of ours, the pairing protocol unchanged over the files, the
    service only a store of bytes for the app (`relay.*`, the `relay/`
    folder only, so no request reaches the vaults' files); every frame is
    a commit, which the conditional reads keep within GitHub's rate limit.
46. The relay server knows nothing of the protocols it carries (part-relay,
    DP-65): a pairing and an approval link are opaque bytes between two
    WebSockets, a mailbox item an `age` package; a recipient proves it holds
    the member key by reading a token the relay encrypted to it, so the
    relay needs no account, and only an instance token (in its default
    token mode) decides who may send.
47. The approval link through a relay server is agreed at pairing, not
    configured later (part-relay): the relay and a random link id travel
    with the public keys the pairing exchanges anyway, so no further message
    is needed and an older peer simply names none; each direction has its
    own channel, so a host's channel and its approver's never meet a third
    side; the address stays first and the relay is only the way when it
    does not answer; the instance token is the app's to keep, in the
    keychain through the service, never in a file or the primary.
48. The browser's passkeys are signed by the service, never handed over
    (part-browser, DP-120): the browser host gets names and credential ids
    to list and a signature for the one the user picked, so a page, an
    extension or a host process never holds a passkey's key. The
    extension's own list, which the page cannot reach, is the user's
    gesture for a sign-in; a new passkey is confirmed in the app, as it is
    written into a vault. Creating one is answered only once the vault is
    written, so a site never holds a credential the vaults lost. The
    Windows passkey plugin uses the same three messages: Windows'
    dialog is the gesture there, its grants are the plugin's
    (`exe-from` its activating process), and it holds no key either.
49. Files cross the admin endpoint as chunked members, not in larger
    frames: a vault of any size is saved and opened, while the frame limits
    stay the same for every peer and for the client endpoint. The chunks
    are generic (any large string member of any request or answer), so the
    handlers and the app's code are unchanged. They are read only after the
    admin has authenticated, so an unauthenticated peer can never make the
    service hold more than one 64 KiB frame.
50. The receiving device names its own platform in the pairing's `done`
    answer, so the device record says what each paired device is without a
    message of its own; the field is optional, so an older device simply
    names none and its record leaves the platform empty, and a value that
    is no lower-case name is dropped rather than recorded.
51. Vaults are kept in memory only by default: the device setting
    `offlineCache` is off unless the user turns it on, so a stolen or copied
    disk holds no vault file and old copies do not outlive a rotation; a
    restarted service fetches the vaults again, and while it runs it serves
    the copies it holds through an outage. Without a cache, a save the
    remote cannot take waits in memory and is merged and written at the
    next refresh that reaches it, as the phone does, at the price of losing
    it if the service stops first; the app says so. Settings stored before
    the default carry no marker and take it once.
