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
| `features` | **[B]** the optional features the client takes (section 8), e.g. `["binary","getFile"]`; absent is none |

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
| **[B]** `unlock {id, vault, bundle{nonce, ciphertext}}` | `ok` | open a vault with the key bundle the app read from the OS-gated store (6.4) |
| `unlockStore {id, store, password, keyFile?}` | `ok` | open a store with a password of its own |
| `lock {id}` | `ok` | lock: clear every secret from memory |
| `shutdown {id}` | `ok`, then the connection closes | lock and stop |
| `status {id}` | `statusReport {id, locked, lockMode, protocol, service{version, start}, stores[{name, state, source, fetchedAt?, notPushed, rewritten?{head}}], admins, hardening, expiring?[{kind, key, vault?, expiresAt, daysLeft}]}` | the service's state; `lockMode` is the service's lock mode (DP-14): `a` never relocks, `b` relocks on idle, `c` (phase B) on idle or screen lock; a store's `state` is `current`, `offline`, `token_expired`, `needs_unlock` or `unavailable`; its `source` is as in 5.2 (`github`, `file` or `cache`); `notPushed` counts its changes not yet written to GitHub; `rewritten` names the head of a branch rewritten without a compaction awaiting `history.resolve` (6.4); `hardening` names the protections achieved at start, each `true` or `false`: `noCoreDumps` (no core file; on Windows the error mode against crash dumps), `notDumpable` (Linux: not dumpable, so no debugger of the same user attaches), `memoryAccessDenied` (Windows: the process DACL refuses `PROCESS_VM_READ` and `PROCESS_VM_WRITE` to all but SYSTEM); `expiring` lists the keys due for a reminder now (part-key-rotation), each with its `kind`, its `vault` when it has one, `expiresAt` and the whole `daysLeft` (negative once expired): `github_token` (key `github-token:<owner>/<repository>`, from the device setting's warning period, default 14 days, before the expiry GitHub reports for the token, or before the expiry recorded with the token when it was entered while GitHub has reported none), `vault_keys` (key `vault-keys:<vault>`, a vault's key file and repository key, from 30 days before their due date: for a further vault the Expires of its entry in the primary, for the primary its metadata's `tsm.keys-due`), `approver_key` and `link_key` (keys `approver-key:<device>` and `link-key:<device>`, this device's approver and approval-link key pairs and those of the peers it recorded, from 30 days before their rotation age of 24 months is over, counted from their creation, their recording at pairing, a key change or a new link key); `tsm status` shows it where no app is attached |
| `reload {id}` | `ok`, or `error` `offline` / `token_expired` | fetch every store now and reopen those whose file moved; on a failed fetch the stores stay on the copy held or cached, and the error's `stores` names them (`token_expired` when GitHub refused a token, else `offline`) |
| `vaultKeys {id, stores?}` | `vaultKeySet {id, stores[{store, location, served?, keys}], unserved?[{store, location}]}` | the keys of the open vaults, for the app's editing path (6.4); `stores` may also name a vault the primary lists that this machine does not serve (`served` false); `unserved` lists those vaults, without keys |
| `vaultFile {id, store}` | `vaultFileData {id, store, location, revision, served?, bytes}`, or `error` `not_found` (neither an open store nor a vault the primary lists), `needs_unlock` (a vault not served whose listed keys do not open it), `unavailable` (one that cannot be read), `offline` / `token_expired` (`stores`), `unsupported` reason `too_large` | the copy of a store the service holds, for the app's editing path (6.4): an open store, or a vault not served, which the service then reads and holds for editing |
| `save {id, store, bytes, baseRevision?}` | `ok` | hand an edited store file to the service, which writes it (6.4) |
| `subscribe {id}` | `ok`, then events (6.5) | start the event stream on this connection |
| `approve {id, approvalId, decision, secret, folder?, pin?, clientToken?}` | `ok` | answer a prompt (7.2); `clientToken` is the token the app made for an `always` of a request with `wantClientToken` (7.4) |
| `approval.redeem {id, token}` | `ok` | `tsm approve <token>`: redeem a one-time approval token (7.5) |
| `approval.issue {id, host, code, decision, secret, pin?}` | `approvalToken {id, token}` | have this device make the token for a code shown on `host` (7.5, 9.6); for a decision other than `once` its app also writes the signed grant |
| `grants.list {id, host?}` | `grantList {id, grants[]}` | the allow list of one host, or of every host (7.3) |
| `grants.add {id, grant{host, subject, secret, decision, pin?}}` | `ok` | add a grant, for another host a pre-approval; the service fills in `id`, `created` and `approver` and signs it |
| `grants.revoke {id, host, grantId}` | `ok` | revoke a grant of any host |
| `approvers.cliSwitch {id, on}` | `ok` | switch command-line approvals on this device on or off; accepted only from the manager app's executable |
| `history.resolve {id, store, take}` | `ok {id, revision, conflicts}`, or `error` `not_found` (no rewritten branch waits on that store), `offline` / `token_expired` (`stores`), `denied` (reason `history_rewritten` when rewritten again, `branch_moving`, or `wrong_executable`), `malformed` (reason `history`) | answer a branch rewritten without a compaction (6.4): `take` `remote` takes the remote file as it is and drops the refused edit; `merge` merges the held copy over the remote file (nothing taken as deleted) and commits it on top of the rewritten head, `conflicts` counting the records it wrote; accepted only from the manager app's executable |
| `settings.get {id}` | `deviceSettings {id, device, cliApprovals, stores[]}` | the device settings (`device`: `serviceLock{mode, idleSeconds, maxUnlockedSeconds?, lockOnSleep}`, `appLock`, `defaultEnvironment?`, `servedStores?` (absent: every store), `refreshMinutes` (0: no refresh), `offlineCache`, `keyExpiryWarningDays`, `approvalTimeoutSeconds`, `codeTimeoutSeconds`, `approvalLink?`, and the rotation ages and reminder start of DP-85: `otherKeyWarningDays` (30), `keyPairAgeMonths` (24), `primaryKeyAgeMonths` (24), `vaultKeyAgeMonths` (12)), whether command-line approvals are on, and the stores the primary names (the primary first); `locked` while locked |
| `settings.set {id, device}` | `ok {id, nextUnlock[]}`, or `error` `malformed` (reason `settings`), `denied` (reason `wrong_executable`) | write the whole device settings; accepted only from the manager app's executable; the lock policy, the refresh, the timeouts, the cache and the reminder period apply at once, `nextUnlock` names those that apply at the next unlock (`servedStores`, `defaultEnvironment`, `approvalLink`) |
| `audit.query {id, from, to, subject?, ref?}` | `auditRecords {id, records[{time, host, identity, refs, outcome, grantId?, approver?}]}` | the audit log |
| `approvals.list {id}` | `approvalList {id, approvals[]}` | the requests waiting on this host (`tsm approvals`), each as its `approval_needed` event reads without `op`: `approvalId`, `host`, `identity`, `refs`, `resolved`, `approvalCode?`, … (6.5, 7.2) |
| `keys {id}` | `keyList {id, keys[{kind, key, vault?, expiresAt, daysLeft, reminding}]}` | every key the service knows a due date of (`tsm keys`), reminding or not: the keys of `statusReport.expiring` (same `kind` and `key`) with `reminding` true for those due a reminder now |
| `compact {id, repository}` | `compacted {id, repository, compacted, oldHead, newHead, kept}`, or `error` `not_found` (no open vault in it), `offline` / `token_expired` (`stores`), `denied` reason `branch_moving` | cut the history of a `github:` vault repository (`owner/name`) now (`tsm compact`): the cut the compaction workflow makes, with the repository's own `.tsm/compaction.yaml` retention, pushed by this device; `compacted` false when there was nothing to cut |

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

The store is then reopened from what was written and `store_changed` names
the new revision. A store that is not open answers `not_found`,
`needs_unlock` or `unavailable` as a `get` would.

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
| `approval_needed` | `approvalId, host, identity, refs[], resolved[{store, path, kind}], hostHint?, approvalCode?, wantClientToken?` | a request needs an approval (7.2); `wantClientToken` when the client asked for a client token (7.4) |
| `approval_closed` | `approvalId, outcome` (`approved`, `denied`, `timeout`, `abandoned`, `no_approver`) | a prompt was answered or ended elsewhere |
| `locked`, `unlocked` | — | the service locked or unlocked |
| `store_changed` | `store, revision?` | a store was reopened with new content |
| `store_state` | `store, state, source, fetchedAt?, notPushed, rewritten?{head}` | a store's state or source changed (at a refresh, a `reload`, an unlock of the store), or its branch was found rewritten without a compaction (`rewritten`, 6.4) or the rewrite answered |
| `key_expiry` | `key, expiresAt, daysLeft` | a key the product rotates expires soon (the GitHub tokens, the vaults' key files and repository keys, the approver and approval-link key pairs; the keys of `statusReport.expiring`): sent when it reaches a reminder step (the first day of its warning period, 7 days and 1 day before, and once a day once expired); an admin that subscribes gets the reminders due at that moment |
| `rate_limited` | `identity, until` | an identity is held back |
| **[B]** `proposal` | `url, title?, userName, password` | a login the browser host proposed |

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
  phase-A service ignores `hello.features` and offers none.
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

The approval link joins a host's service and the manager app of a paired
approver device. The app connects; the host listens on its VPN or LAN address
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
| approver | `keychange {id, statement}` | `ok` or `error` | a key-change statement (9.4) |
| either | `linkKey {id, device, x25519, mlKem768}` | `ok` or `error` | the sender's new link public key; the peer records it, authenticated by this session under the old keys, and accepts the old key for the migration period |
| either | `rekey` | — | after sending it the sender replaces its sending key `k` by Noise's REKEY (the first 32 bytes of ChaCha20-Poly1305(`k`, 2^64 − 1, empty ad, 32 zero bytes)); the receiver does the same to its receiving key after decrypting it. The counter goes on. Each side sends it after 2^20 frames or an hour |

The answers are `ok {id}` and `error {id, kind, message, details?}` of
sections 6 and 10 (`denied` for an object whose signatures are not accepted).
Any other message closes the link. A new connection makes a new handshake.

### 9.8 Test vectors

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
| `denied` | the client may not have this, or a connection is refused | `reason`: `never` (a never grant), `refused` (at the prompt), `no_approver`, `unidentifiable` (the identity could not be measured), `reserved_field` (a passkey field), `not_allowed_op` (`match` / `propose` without the grant for it), `bad_token` (Windows `hello.token`, or an approval token that matches no waiting request, 9.6), `bad_mac`, `bad_password`, `bad_bundle`, `wrong_executable` (admin), `other_user` (a peer of another OS user), `stale_base` (a `save` of a revision the file has moved past, 6.4), `history_rewritten` (a `save` to a branch rewritten without a compaction; the app decides, 6.4), `branch_moving` (a `save` whose branch moved during every attempt; save again) |
| `not_found` | no candidate, or the winning entry lacks the field | `dimensions` (the request's values), `entry` (`{store, path, uuid}`, when the field is missing), `field` |
| `ambiguous` | several candidates rank equal | `candidates`: `[{store, path, uuid}]`, never values |
| `needs_unlock` | the store holding the answer could not be reopened since its key changed | `store` |
| `unavailable` | the store holding the answer could not be fetched and has no offline copy; for `propose`, no app is attached | `store`, `reason` (`no_cache`, `no_app`) |
| `offline` | admin only: a `reload` whose fetch failed for a network reason, or a `save` that cannot be taken while offline | `stores` |
| `token_expired` | admin only: as `offline`, because GitHub answered 401 or 403 or the token is past its expiry | `stores` |
| `malformed` | a frame, a reference, a binding or a request cannot be read | `reason` (section 4.6, 4.7, or `duplicate_id`, `frame`; for admin requests the member that cannot be read, e.g. `password`, `stores`, and `bytes` for a `save` whose file is no base64 or does not open with the store's keys, 6.4) |
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

- [`schema/`](schema/): 71 message schemas, one per `op` (JSON Schema draft
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
  signed objects, approval codes and tokens, and the approval link (9.8).
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
