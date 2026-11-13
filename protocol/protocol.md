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

Section 9 (the signed bytes of grants, revocations, approval tokens and
key-change statements, the approval code's derivation, and the approval
link's handshake) is the second part of this document and is written
separately; the messages that carry those objects are specified here.

## 1. Endpoints

The service offers two local endpoints, kept apart so that a client library
can never reach an admin operation by mistake:

| Endpoint | Who | Messages |
| --- | --- | --- |
| client | any program of the service's OS user | `hello`, `get`, `getMany`; **[B]** `getFile`, `match`, `propose` |
| admin | the manager app and `tsm` | the challenge (`challenge`, `auth`, `authed`, `claim`), then the admin requests of section 6 |

A third, the **approval link** between a host's service and the manager apps
of the user's other devices, runs over its own handshake (section 9).

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
| `service.lock` | all | the single-instance lock (not for clients) |
| `service.json` | all | `{pid, start, protocol, client, admin}`: the service's PID, its start (milliseconds since the epoch), the protocol version and the endpoints (`{socket}` or `{port}`); no secret, for diagnostics |

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

The service answers `welcome`:

| Member | Content |
| --- | --- |
| `protocol` | the version it will speak on this connection, `1` |
| `service` | `{version}` |
| `features` | the optional features it offers (section 8); empty in phase A |
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
| `entry` | `{store, uuid, source, fetchedAt}`: the entry's store and UUID; `source` is `github` when the store was fetched in this refresh cycle and `cache` when the service serves its offline copy; `fetchedAt` the last successful fetch |
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
| **[B]** `match {id, url, frameUrl?}` | `matches {id, candidates[{entryId, title, userName, matchedUrl, hasTotp}]}` | the login entries matching a page, never a value; only for the browser host's and the helpers' grants, others get `denied` (reason `not_allowed_op`); audited |
| **[B]** `propose {id, url, title?, userName, password}` | `accepted {id}` | a login for the app to save, passed to the attached app as the event `proposal`; with no app attached `unavailable` (reason `no_app`); only for the browser host's grant |

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
manager app's or `tsm`'s; a wrong one is refused even with the right key.

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
| `unlock {id, password, keyFile?}` | `ok` | open the primary file and the stores it names |
| **[B]** `unlock {id, vault, bundle{nonce, ciphertext}}` | `ok` | open a vault with the key bundle the app read from the OS-gated store (6.4) |
| `unlockStore {id, store, password, keyFile?}` | `ok` | open a store with a password of its own |
| `lock {id}` | `ok` | lock: clear every secret from memory |
| `shutdown {id}` | `ok`, then the connection closes | lock and stop |
| `status {id}` | `statusReport {id, locked, lockMode, protocol, service{version, start}, stores[{name, state, source, fetchedAt?, notPushed}], admins, hardening}` | the service's state; a store's `state` is `current`, `offline`, `token_expired`, `needs_unlock` or `unavailable`; `notPushed` counts its changes not yet written to GitHub; `hardening` names the memory protections achieved |
| `reload {id}` | `ok`, or `error` `offline` / `token_expired` | fetch and reopen the stores now; on a failed fetch the stores stay on their cache |
| `vaultKeys {id, stores?}` | `vaultKeySet {id, stores[{store, location, keys}]}` | the keys of the open vaults, for the app's editing path (6.4) |
| `save {id, store, bytes, baseRevision?}` | `ok` | hand an edited store file to the service, which writes it (6.4) |
| `subscribe {id}` | `ok`, then events (6.5) | start the event stream on this connection |
| `approve {id, approvalId, decision, secret, folder?, pin?}` | `ok` | answer a prompt (7.2) |
| `approval.redeem {id, token}` | `ok` | `tsm approve <token>`: redeem a one-time approval token (7.5) |
| `approval.issue {id, code, decision, secret, pin?}` | `approvalToken {id, token}` | have this device's approver key make a token for a code (7.5) |
| `grants.list {id, host?}` | `grantList {id, grants[]}` | the allow list of one host, or of every host (7.3) |
| `grants.add {id, grant{host, subject, secret, decision, pin?}}` | `ok` | add a grant, for another host a pre-approval; the service fills in `id`, `created` and `approver` and signs it |
| `grants.revoke {id, host, grantId}` | `ok` | revoke a grant of any host |
| `approvers.cliSwitch {id, on}` | `ok` | switch command-line approvals on this device on or off; accepted only from the manager app's executable |
| `audit.query {id, from, to, subject?, ref?}` | `auditRecords {id, records[{time, host, identity, refs, outcome, grantId?, approver?}]}` | the audit log |

### 6.4 Editing and key material

The service owns every vault file and every write to GitHub on its device.
To edit, the app asks for `vaultKeys`, opens the vaults in its own memory and
hands each saved file back with `save` (`bytes` the whole file,
`baseRevision` the revision it edited). The members of a store's `keys`
object are defined with the store format (the outer encryption and its key
slots); this document fixes only that they travel in `vaultKeySet` over an
authenticated admin connection.

**[B] The key bundle.** The OS unlock hands key material to the service only
sealed:

- bundle key = HKDF-SHA256(ikm = adminKey, salt = serviceNonce || adminNonce,
  info = `tsm-bundle-v1`, 32 bytes), new for every admin connection;
- `bundle.ciphertext` is AES-256-GCM of the bundle under that key with the
  12-byte random `bundle.nonce`, the tag appended, and as associated data the
  vault id's UTF-8 bytes followed by `serviceStart` as 8 bytes big-endian;
- a bundle that does not open is refused like a wrong password (`denied`,
  reason `bad_bundle`) and counts as a failed authentication.

### 6.5 Events

After `subscribe` the service pushes events on that connection (no `id`):

| Event | Members | When |
| --- | --- | --- |
| `unlock_needed` | `identity?` | a client waits for an unlock |
| `approval_needed` | `approvalId, host, identity, refs[], resolved[{store, path, kind}], hostHint?, approvalCode?` | a request needs an approval (7.2) |
| `approval_closed` | `approvalId, outcome` (`approved`, `denied`, `timeout`, `abandoned`, `no_approver`) | a prompt was answered or ended elsewhere |
| `locked`, `unlocked` | — | the service locked or unlocked |
| `store_changed` | `store, revision?` | a store was reopened with new content |
| `store_state` | `store, state, source, fetchedAt?, notPushed` | a store's state changed |
| `key_expiry` | `key, expiresAt, daysLeft` | a key the product rotates expires soon (the GitHub token, key files, approver keys) |
| `rate_limited` | `identity, until` | an identity is held back |
| **[B]** `proposal` | `url, title?, userName, password` | a login the browser host proposed |

## 7. Approvals and grants

### 7.1 The identity

The service measures each connecting process once, when the connection is
accepted, and never trusts what a client says about itself. The **identity**
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
signed grant (7.3). Unanswered within the approval timeout the request ends
`timeout`; with no approver connected it falls back to the approval code
(7.5) and ends `denied` (reason `no_approver`) when no token comes in time.

### 7.3 Grants

A **grant** of the allow list:

| Member | Content |
| --- | --- |
| `id` | the grant's id |
| `host` | the host it holds on; a service applies only its own host's grants |
| `subject` | `exe <path>`, `script <interpreter> <path>`, `interpreter <path>`, `folder <path> [interpreter]`, `tsm-command <command line>` or `exe-token <path> <tokenId>` |
| `secret` | a canonical reference (4.5), `store <name>` or `all` |
| `decision` | `allow` or `never` |
| `created`, `lastUsed` | times |
| `pin` | `hash`, `off` or `{relaxedUntil}` |
| `approver` | the trusted device that made it |
| `signatures` | the signature list, items `{alg, keyId, sig}` (section 9) |

Matching: the most specific subject wins (exe, script or exe-token, then
folder, then interpreter); for one subject a reference beats a store and a
store beats `all`; a `never` grant beats an `allow` grant of the same
specificity. A service accepts a grant only when its signatures verify
against an approver key it recorded at pairing (section 9).

### 7.4 Client tokens

A client that asks with `wantClientToken` and is approved **always** gets
`clientToken` in the `value`: 32 random bytes in base64. The grant's subject
becomes `exe-token <path> <tokenId>`, and the service keeps only the token's
hash. The client sends the token in every later `hello` (`clientToken`);
without it the connection is the bare executable and gets no grant made for
the token. Revoking the grant invalidates the token. A library hands the
token to its caller and never stores it itself.

### 7.5 Approval codes and tokens

- An **approval code** is ten characters of the RFC 4648 base32 alphabet
  (`A`–`Z`, `2`–`7`), shown with a request waiting on a host without a
  connected approver (`progress.approvalCode`, `approval_needed.approvalCode`).
- An **approval token** is 26 characters of the same alphabet: a 128-bit tag a
  trusted device computes for a code (`approval.issue`), typed into the
  waiting host (`approval.redeem`). It is single-use and expires with its
  code.

How the code is derived and what the token's tag covers are specified in
section 9.

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

  A client sends a feature's messages only when `welcome.features` names it.
- An unknown `op` on an open connection is answered `error` `unsupported`
  with `details.op` and the connection stays open.
- A value of an enumerated member that a receiver does not know (a new error
  kind, a new store state) is treated as the most general one it knows: an
  unknown error kind as `internal`, an unknown state as `unavailable`.

## 9. Signed objects and the approval link

The second part of this document specifies:

- the signed bytes and the signature list of grants, revocations,
  approval tokens and key-change statements (Ed25519 and ML-DSA-65);
- the derivation of the approval code and the tag of the approval token;
- the approval link: its frames over the `ApprovalChannel`, its messages
  (`approval_needed`, `approve`, `approval_closed`, `grant`, `revoke`, key-change
  statements) and its hybrid handshake;
- their test vectors.

Until it is written, the messages of sections 6 and 7 that carry these
objects are fixed in their members, and their signature and tag contents are
not.

## 10. Error kinds

An `error` has `kind`, `message` (for people; never a value, a token or a
key) and optional `details`. Every library maps the kinds to its own error
type and adds `not_running` (section 3).

| Kind | Meaning | `details` |
| --- | --- | --- |
| `locked` | the service is locked and no unlock came in time, or `wait` was `false` | — |
| `denied` | the client may not have this, or a connection is refused | `reason`: `never` (a never grant), `refused` (at the prompt), `no_approver`, `unidentifiable` (the identity could not be measured), `reserved_field` (a passkey field), `not_allowed_op` (`match` / `propose` without the grant for it), `bad_token` (Windows `hello.token`), `bad_mac`, `bad_password`, `bad_bundle`, `wrong_executable` (admin) |
| `not_found` | no candidate, or the winning entry lacks the field | `dimensions` (the request's values), `entry` (`{store, path, uuid}`, when the field is missing), `field` |
| `ambiguous` | several candidates rank equal | `candidates`: `[{store, path, uuid}]`, never values |
| `needs_unlock` | the store holding the answer could not be reopened since its key changed | `store` |
| `unavailable` | the store holding the answer could not be fetched and has no offline copy; for `propose`, no app is attached | `store`, `reason` (`no_cache`, `no_app`) |
| `offline` | admin only: a `reload` whose fetch failed for a network reason, or a `save` that cannot be taken while offline | `stores` |
| `token_expired` | admin only: as `offline`, because GitHub answered 401 or 403 or the token is past its expiry | `stores` |
| `malformed` | a frame, a reference, a binding or a request cannot be read | `reason` (section 4.6, 4.7, or `duplicate_id`, `frame`) |
| `timeout` | an approval was not answered in time | — |
| `rate_limited` | the identity is held back (section 11) | `retryAfterMs` |
| `unsupported` | an unknown `op`, or a protocol the service does not speak | `op`, or `protocols` |
| `internal` | a failure of the service | `code`, never a value |

## 11. Rate limits

Per measured identity, configurable in the service:

| What | Limit |
| --- | --- |
| `get` and `getMany` | a token bucket of 20 per second, bursts of 50 |
| refusals (`denied`, `not_found`, `ambiguous`) | ten in a minute make the identity wait 10 s per request for ten minutes |
| open connections | 16 per identity, 256 in all |
| pending prompts | one per identity and reference, at most three per identity; three refusals in ten minutes hold the identity back ten minutes |
| failed admin authentications | the growing delay of 6.1 |
| approval tokens | a token that fails counts as a failed authentication; three for one waiting request end it `denied` |

## 12. Schemas, vectors and tools

- [`schema/`](schema/): 53 message schemas, one per `op` (JSON Schema draft
  2020-12, file `<op>.json`), and `common.json` with the shared definitions.
  Each schema's `x-tsm` member names its endpoint, direction and phase.
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
- [`tool/`](tool/): `tsm_protocol.py`, the reference implementation of the
  computable parts (references, frames, the MAC, discovery);
  `gen_schemas.py` and `gen_vectors.py`, which write `schema/` and
  `vectors/`; and `check_protocol.py`, which checks that this document, the
  schemas and the vectors agree. Run by hand (Python 3.9 or later, with
  `jsonschema` for the checker):

  ```text
  python3 protocol/tool/gen_schemas.py
  python3 protocol/tool/gen_vectors.py
  python3 protocol/tool/check_protocol.py
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
