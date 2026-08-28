# skepd wire protocol

The HTTP/JSON contract between `skepd` and its clients. This document is
written for a client author who will never read the Rust; it is also
executable documentation — every fenced JSON example annotated with a
`<!-- wire: … -->` marker is asserted byte-for-byte-canonically by
`skep/crates/skepd/tests/wire_doc.rs`, so an example that drifts from the
daemon fails the build. (Two exceptions: the commit-stream event example is
asserted structurally — its framing, not its illustrative position — and
the change-feed examples are asserted against live daemon bytes in
`tests/changes.rs` with the `time` values normalized, the one field a live
daemon cannot reproduce; the bare-entry example is byte-exact.)

## The model

One `skepd` process owns one world. Any number of local clients speak to it
concurrently; the daemon serializes writes internally and answers every read
from a consistent snapshot. Every response reports its position in the one
committed log: writes carry `at` (the commit that made them true), reads
carry `as_of` (the snapshot they were answered from). A write is
acknowledged only after it is durable on disk.

### Endpoints

| Method & path    | Purpose                                                    |
|------------------|------------------------------------------------------------|
| `POST /session`  | Bind a principal; returns an opaque session token.         |
| `POST /op`       | One operation frame in, one response document out.         |
| `POST /op-at`    | One **read** frame answered as of a committed position (§Reading history). |
| `GET /health`    | Liveness, current log position, and the head commit's time. |
| `GET /events`    | Server-sent stream of committed positions (§The commit stream). |
| `GET /changes`   | The pull delta feed of committed writes (§The change feed). |
| `GET /`          | The embedded authoring client, one HTML file (only in `client` builds — the feature is default-off). |
| `GET /dump`      | Deterministic world dump; `?at=N` for a committed position (only in `observe` builds). |

There are no other routes; every known path additionally answers `OPTIONS`
— the CORS preflight (§Cross-origin access). The daemon listens on
**127.0.0.1 only**.

### Transport

One request per connection: every response carries `Connection: close`, so
a client opens a fresh connection per call. `GET /events` is the one
long-lived response — a single unbounded body, ended by the daemon (clean
close) at shutdown. HTTP/1.0 and 1.1 are accepted; request bodies ride
with `Content-Length` (absent means empty; `Transfer-Encoding` is refused
with `400 malformed_http`); `Expect: 100-continue` is honored. Bodies are
capped at **8 MiB**: a larger declared `Content-Length` is refused with
`413 payload_too_large` before any body byte is read.

### Identity — a scope decision

Identity is **local trust**: a client names its own principal (a small
integer) at `POST /session`, with no credential and no cryptographic
authentication. Principal `0` is the bootstrap principal, which owns the
root of the namespace; any other principal must first be minted with a
`delegate` operation before its writes will be accepted by the stores. Each
distinct principal is its own account, so every write is attributed. This is
the deliberate v1 scope — the daemon binds only the loopback interface
precisely because this trust model does not survive a network. It is a
decision, not a TODO.

**Ownership** (v5.1): attribution now gates. A write into a document's
space — its content arrangement or its link subspace — is accepted only
from the document's owner: the principal whose account is **exactly** the
document's account (the nearest registered account prefix of its address —
never mere prefix containment, so a parent account does not own a
sub-delegated account's documents and a sub-account does not own its
parent's). Anything else is the `not_owner` rejection with the failing
address in `site.addr`. Reads remain principal-free. The sanctioned way to
build on someone else's document is `version` (fork it into your own
account, content shared) and `copy` (transclude their content into your own
document) — proposing a change is forking, never editing in place.

### Cross-origin access — a scope decision

Every response — every status, every endpoint, rejections and transport
errors included — carries `Access-Control-Allow-Origin: *`. `OPTIONS` on
any known path answers the preflight:

```
OPTIONS /op
→ 204
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Skepd-Session
Access-Control-Max-Age: 86400
```

(`OPTIONS` on an unknown path is the ordinary 404.) The `*` is deliberate:
the daemon is loopback-only under the local trust model above, so any
local page may read what any local process may read. Writes still require
a session token, and the token is not a browser credential — a page holds
one only if it opened the session itself. This decision is revisited when
authentication lands, not before.

### Sessions

```
POST /session
{"principal": 2}
→ 200
{"principal": 2, "session": "9f3a6c21d4b8e07a.1"}
```

The returned `session` string is an opaque token. Send it on subsequent
`/op` calls as the header:

```
Skepd-Session: 9f3a6c21d4b8e07a.1
```

The daemon echoes `principal` back so the client can name its own account
later via the `principal_prefix` operation.

Rules:

* Tokens are process-lifetime state. **After a daemon restart every token is
  dead**; requests carrying one behave exactly like requests carrying none
  (below). Re-open your session.
* A request with **no token, or an unknown/stale token**, still gets a full
  answer: read operations are principal-free and succeed normally; write
  operations are rejected with code `unauthenticated` (permanent). That
  rejection is your signal to (re)open a session.
* There is no close-session endpoint in v1: sessions are a map entry, they
  live until the process exits. (Scope decision.)
* A malformed session body gets `400` with a transport error (see below).

### Correlation and idempotency

The HTTP request/response exchange **is** the correlation envelope: the
answer to your `POST /op` is the response to that frame, and nothing else
rides in it. Responses never echo a request id.

The optional envelope field `"id"` is a **per-session idempotency key** (any
string, unique within your session). If a committed write's acknowledgment
is lost and you repeat the identical request with the same `id` on the same
session, the daemon returns the original acknowledgment instead of
re-executing. It is a best-effort hint: it does not survive a daemon
restart, it is never applied to reads or rejections (a `reorder`/`retry`
reissue always re-executes), and an `id` reused across different op kinds
misses.

### HTTP status codes

`POST /op` returns **`200` whenever the daemon produced an operation
response — including every rejection**. The response document, not the HTTP
status, is the operation protocol; clients dispatch on the `resp` field.
Non-200 statuses are transport-level failures with a body of the shape
`{"error": "<name>", "detail": "…"?}`:

| Status | `error`                     | When                                    |
|--------|-----------------------------|-----------------------------------------|
| 400    | `malformed_session_request` | `POST /session` body isn't `{"principal": n}` |
| 400    | `malformed_op_at`           | `POST /op-at` body isn't `{"at": n, "frame": {…}}` |
| 400    | `write_at_history`          | the `/op-at` frame is a write operation |
| 400    | `beyond_head`               | the position exceeds the committed head (carries `head`) |
| 400    | `not_a_position`            | the number is not a committed position (carries `nearest`) |
| 400    | `malformed_at`              | the `/dump` query isn't `at=<position>` |
| 400    | `malformed_changes`         | the `/changes` query isn't `since=<position>` with an optional in-range `limit` |
| 400    | `malformed_http`            | the request is not the HTTP subset skepd speaks (bad head, chunked body, a body cut short) |
| 404    | `no_such_endpoint`          | unknown path (including `/dump` on a build without `observe` and `/` on a build without `client`) |
| 405    | `method_not_allowed`        | known path, wrong method                |
| 413    | `payload_too_large`         | the declared `Content-Length` exceeds the 8 MiB request-body cap |
| 410    | `history_reclaimed`         | the position (`/op-at`) or the `since` fence (`/changes`) predates retained history (carries `floor` when known) |
| 503    | `history_busy`              | all historical-reconstruction permits (`/op-at`, `/dump?at`) are in use; retry shortly |
| 500    | `internal_panic`            | a handler bug; the daemon stays up      |
| 500    | `history_io` / `history_corrupt` | reading the journal for a historical position failed / found at-rest corruption |
| 500    | `no_journal`                | the daemon runs without a journal (in-memory mode); history is unavailable |

### Determinism

Response marshaling is canonical: object keys are emitted in sorted
(alphabetical) order, with no insignificant whitespace, and two marshals of
one response are byte-identical. Clients may hash or diff response bodies.
Request parsing is lenient about field order and accepts the documented
lenient forms (numbers for naturals, uppercase hex); the daemon's own output
always uses the canonical forms.

One pin rides beside the marshal: the **base determinism conditioning**
of the positioned reads. The byte-identity promises this document makes
— `/op-at` (same `at`, same frame), `GET /dump?at` (same `at`),
`GET /changes` (same `since`, same `limit`) — hold across repeats and
across daemon restarts **while the position, or the history behind the
fence, remains within retained history**. The reclaim floor advances
between repeats; a position that has aged out answers
`410 history_reclaimed`, never different bytes. That conditioning is the
wire's own base; rounds that widen this surface state any further
conditioning terms of theirs on top of it.

## Value encodings

**Tumblers and addresses** are dotted-decimal strings — `"1.1.0.1.0.2"` —
one decimal natural per component, zeros explicit, no leading zeros in
canonical form. An *address* is a tumbler that passes the address validator;
where a field is documented as an address, a non-address tumbler is a parse
failure.

**Naturals** (widths, V-position components) are unbounded, so they ride as
decimal **strings**: `"width": "3"`. On parse, a non-negative JSON integer
is also accepted; canonical output is always the string form.

**Machine-bounded integers** (`at`/`as_of` log positions, `slot`, `n`,
counts, principal ids) are plain JSON numbers. They are `u64` server-side;
values beyond 2^53 would lose precision in JavaScript-backed clients, but a
log position or principal count approaching 2^53 is unreachable in practice.

**Spans** are `{"start": "<tumbler>", "width": "<tumbler>"}` — half-open
intervals of the tumbler order. A zero-width span is invalid and rejected at
parse. A depth-2 content V-span looks like
`{"start": "1.1", "width": "0.5"}`: subspace 1 (content), ordinal 1, five
elements.

**Span sets and endsets** are JSON arrays of spans, order preserved
verbatim.

**V-positions** are `{"subspace": "<nat>", "ordinal": "<nat>"}` (subspace 1
= content, 2 = links; ordinals are 1-based).

**V-specs** (a span of some document's arrangement) are
`{"source": "<address>", "span": {…}}`. **Specs** for `retrieve_v` are
`{"doc": "<address>", "span": {…}}`. **Regions** are
`{"doc": "<address>", "spans": [{…}, …]}`.

**Content values** carry granularity explicitly (wire v2). The store holds
a sequence of *values*, each an opaque byte payload occupying **one
V-position**; a value's interior has no addresses of its own. The
substrate's text discipline is one single-byte value per position — the
granularity under which V-span widths measure exact bytes and any byte
range can be linked, partially transcluded, or compared. The wire defaults
to it and requires the coarse choice to be spelled out.

*Write forms* — each element of an `insert`'s `values` array is one of:

* `"str"` — one single-byte value per UTF-8 **byte** of the string.
  `"hello"` is five values at five positions; a two-byte character like `é`
  is two values.
* `{"hex": "<hex>"}` — one single-byte value per byte of the payload.
* `{"atom": "<str>"}` — a **single composite value** holding the string's
  UTF-8 bytes, at one position.
* `{"atom_hex": "<hex>"}` — a single composite value of those raw bytes, at
  one position.

Mixed arrays are legal and concatenate in order. `""` and `{"hex": ""}`
contribute zero values (vacuous in the array; an insert whose total is zero
values is still rejected by the store with `empty_content`). `{"atom": ""}`
and `{"atom_hex": ""}` are parse failures — a zero-byte atom is not
expressible. A one-byte atom is the same write as its per-byte form
(granularity distinguishes only multi-byte payloads) and canonicalizes to
it. Hex is lowercase canonically; uppercase parses.

**What a composite value does.** I-addresses are write-once, so a composite
value's interior bytes are **permanently unaddressable**: no link can ever
target inside it, no transclusion can carry part of it, and no compare can
align against its interior — for the value's whole lifetime, in every
document that ever transcludes it. That is the operation's meaning, not
advice; write an atom only for a payload that is indivisible in your data
model.

*Read form* (`delivery` items) — injective and canonical: two different
position-value sequences never render alike.

* A **maximal run of consecutive single-byte values** renders as ONE item —
  `{"content": "<str>"}` when the run's concatenated bytes are valid UTF-8
  (validity is judged on the whole run: per-byte values routinely
  concatenate into multi-byte UTF-8 characters), else `{"hex": "<hex>"}`.
* A **composite value** renders as its own item — `{"atom": "<str>"}` when
  its bytes are valid UTF-8, else `{"atom_hex": "<hex>"}` — exactly one
  value per item, never coalesced.
* A **link position** renders `{"ref": "<address>"}`.

(Routed, not yet in the protocol: the publication rounds add a fourth
item — `{"withheld": {"origin": "<address>", "width": "<nat>"}}`, a run
the reader may not read, emitted at its own position rather than
dropped. Its rendering is pinned now, beside the rules above: one item
per withheld RUN — two non-contiguous withheld runs, even from one
origin, are two items, never one coalesced item of the summed width.)

Count positions, not items: `{"content": "hello"}` spans five positions,
`{"atom": "hello"}` spans one.

The canonical *request* rendering (the form this document's examples are
asserted in) applies the same coalescing: maximal per-byte runs as one bare
string (or one `{"hex"}` when the run is not UTF-8), each composite value
as its atom form.

**Views** are `"audit"` (everything ever created), `"active"` (not
retracted), or `"default"`.

**Slot constraints** (in four-set queries) are `"any"` (unconstrained),
`"empty"` (constrained to nothing — annihilates the query), or a nonempty
span array. An empty array is the empty constraint and is read as
`"empty"`.

**Four-set descriptors** are `{"home": <slot>, "from": <slot>, "to":
<slot>, "ty": <slot>}` — all four required.

**Cursors** (windowed enumeration) are `null` (start) or a link address
(resume strictly past it). An absent `cur` field means `null`. The whole
continuation is the cursor value you hold; there is no server-side
iterator.

**Windows** are `{"batch": [addresses…], "exhausted": bool, "next":
cursor}` — `batch` in ascending address order; `exhausted: true` (a batch
shorter than `n`) is the terminal signal.

**Links** (read back raw) are `{"slots": [<endset>, …]}` — positional,
1-based on the wire: slot 1 = FROM, slot 2 = TO, slot 3 = TYPE.

**Runs** (V→I images) are `{"i_start": "<address>", "width": "<nat>"}` —
`width` consecutive permanent I-addresses starting at `i_start`.

## The request envelope

A frame is a single JSON object:

```
{"op": "<name>", "id": "<idempotency key>"?, …operation arguments…}
```

`op` is the snake_case operation name. Unknown `op` values and **unknown or
misspelled fields are parse failures** — the daemon never silently ignores
part of a frame. A frame that fails to parse still gets exactly one
response: the `unparseable` rejection (see §Rejections).

## The response envelope

Every response is a single JSON object tagged by `resp`. The shapes, each
with its tested example:

**`ack`** — delete / copy / rearrange succeeded; committed at `at`.

<!-- wire: response ack -->
```json
{"at":7,"resp":"ack"}
```

**`ack_addr`** — a write that minted (or found) an address:
create_new_document / insert (start address) / version / make_link / emit /
nullify / assert_sup / fork / delegate / register_node.

<!-- wire: response ack_addr -->
```json
{"addr":"1.0.1.0.1.0.1.1","at":7,"resp":"ack_addr"}
```

**`ack_edit`** — edit_link: the successor link and its supersession claim.

<!-- wire: response ack_edit -->
```json
{"at":7,"claim":"1.0.1.0.1.0.2.3","resp":"ack_edit","successor":"1.0.1.0.1.0.2.2"}
```

**`delivery`** — retrieve_v: items in submitted-spec order, granularity
intact (§Content values): a maximal run of single-byte values is one
`content` item (or `hex` when the run is not UTF-8), a composite value is
its own `atom`/`atom_hex` item, a link position is a `ref`. This example
delivers five per-byte positions and one link position:

<!-- wire: response delivery -->
```json
{"as_of":9,"items":[{"content":"hello"},{"ref":"1.0.1.0.1.0.2.1"}],"resp":"delivery"}
```

Two per-byte positions followed by one composite value — the atom is never
coalesced into the run beside it:

<!-- wire: response delivery_atom -->
```json
{"as_of":9,"items":[{"content":"hi"},{"atom":"chunk"}],"resp":"delivery"}
```

**`span_set`** — retrieve_doc_v_span / retrieve_doc_v_span_set / project.

<!-- wire: response span_set -->
```json
{"as_of":9,"resp":"span_set","set":[{"start":"1.0.1.0.1.0.1.1","width":"0.0.0.0.0.0.0.5"}]}
```

**`addrs`** — show_origin / find_docs_containing / find_links_v /
find_links_ftt.

<!-- wire: response addrs -->
```json
{"addrs":["1.0.1.0.1.0.2.1"],"as_of":9,"resp":"addrs"}
```

**`maybe_addr`** — next_account_prefix / principal_prefix. `addr` is always
present; `null` means absent/ineligible (not an error).

<!-- wire: response maybe_addr -->
```json
{"addr":"1.0.2","as_of":9,"resp":"maybe_addr"}
```

<!-- wire: response maybe_addr_none -->
```json
{"addr":null,"as_of":9,"resp":"maybe_addr"}
```

**`count`** — count_v / count_ftt.

<!-- wire: response count -->
```json
{"as_of":9,"n":2,"resp":"count"}
```

**`page`** — window_v / window_ftt.

<!-- wire: response page -->
```json
{"as_of":9,"resp":"page","window":{"batch":["1.0.1.0.1.0.2.1"],"exhausted":true,"next":"1.0.1.0.1.0.2.1"}}
```

**`endsets`** — retrieve_endsets: `(slot, endset)` pairs.

<!-- wire: response endsets -->
```json
{"as_of":9,"pairs":[{"endset":[{"start":"1.1","width":"0.5"}],"slot":1}],"resp":"endsets"}
```

**`runs`** — image: the V→I image of the region.

<!-- wire: response runs -->
```json
{"as_of":9,"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.1","width":"5"}]}
```

**`bool`** — discoverable_from.

<!-- wire: response bool -->
```json
{"as_of":9,"resp":"bool","val":true}
```

**`link_value`** — read_link. `link` is always present; `null` means no
link resides at that address.

<!-- wire: response link_value -->
```json
{"as_of":9,"link":{"slots":[[{"start":"1.0.1.0.1.0.1.1","width":"0.0.0.0.0.0.0.5"}],[{"start":"1.0.1.0.2.0.1.1","width":"0.0.0.0.0.0.0.6"}],[{"start":"1.0.1.0.3.0.1.1","width":"0.0.0.0.0.0.0.1"}]]},"resp":"link_value"}
```

<!-- wire: response link_value_null -->
```json
{"as_of":9,"link":null,"resp":"link_value"}
```

**`follow`** — follow_link. The result is in-band because "empty endset"
and "no such link/slot" are *different defined answers*: `{"ok": [spans…]}`
(possibly empty) versus `{"err": "invalid"}`.

<!-- wire: response follow -->
```json
{"as_of":9,"resp":"follow","result":{"ok":[{"start":"1.0.1.0.1.0.1.1","width":"0.0.0.0.0.0.0.5"}]}}
```

<!-- wire: response follow_invalid -->
```json
{"as_of":9,"resp":"follow","result":{"err":"invalid"}}
```

**`deletions`** — show_deletions: each half is the set of I-addresses
deleted from one document yet current in the other.

<!-- wire: response deletions -->
```json
{"as_of":9,"rep":{"a_with_b":["1.0.1.0.1.0.1.1"],"b_with_a":[]},"resp":"deletions"}
```

**`compare`** — compare: correspondences; each pair names a shared run of
`width` positions at `u1` in `d1` and `u2` in `d2`.

<!-- wire: response compare -->
```json
{"as_of":9,"pairs":[{"d1":"1.0.1.0.1","d2":"1.0.1.0.2","u1":{"ordinal":"1","subspace":"1"},"u2":{"ordinal":"3","subspace":"1"},"width":"5"}],"resp":"compare"}
```

**`orphans`** — delete_orphans: the links the proposed delete would orphan
in that document (a preview; nothing is written).

<!-- wire: response orphans -->
```json
{"as_of":9,"orphaned":["1.0.1.0.1.0.2.1"],"resp":"orphans"}
```

**`claims`** — in_claims / out_claims: supersession lineage records.

<!-- wire: response claims -->
```json
{"as_of":9,"claims":[{"active":true,"claim":"1.0.1.0.1.0.2.3","home":"1.0.1.0.1","new":"1.0.1.0.1.0.2.2","old":"1.0.1.0.1.0.2.1"}],"resp":"claims"}
```

## Rejections

Every failure of a parsed operation — and every unparseable frame — is the
`rejected` shape. **A client that cannot decode a rejection has been
silently failed; decode this first.**

<!-- wire: response rejected -->
```json
{"code":"unauthenticated","disposition":"permanent","op":"insert","resp":"rejected"}
```

Fields:

* `op` — the snake_case operation name the rejection answers, or
  `"unparseable"` when the frame never became an operation.
* `code` — the authoritative machine-readable cause (full list below).
* `disposition` — an **advisory** retry hint:
  * `"permanent"` — reissuing the same request cannot succeed;
  * `"reorder"` — a *future* committed state may satisfy the precondition
    (e.g. the document it names isn't registered *yet*); reissue after the
    state you're waiting on commits;
  * `"retry"` — transient (durability hiccup); the operation did nothing;
    reissue as-is;
  * `"halt"` — the kernel has stopped accepting writes (operator
    condition); reads still work.
  The code is authoritative; a client that knows its own context may
  reissue despite a conservative hint. Note `not_next_form`/`not_fresh` are
  `permanent` *by design*: recover by re-deriving a fresh prefix via
  `next_account_prefix` and issuing a *different* request.
* `site` — optional fault localization, present only when the store
  reported one: `{"operand": "first"|"second"?, "region": n?, "index": n?,
  "fault": "<span fault>"?, "addr": "<address>"?}`. `index`/`fault` localize
  a malformed span in a multi-span request; `operand`/`region` localize
  compare inputs; `addr` names the offending document in multi-document
  lookups — and, on a `not_owner` rejection, the document (or target link)
  that failed the ownership check. Span faults: `not_ordinal_level`,
  `not_level_uniform`, `start_not_zero_free`, `start_too_shallow`.
* `detail` — optional human-readable message (always present on
  `unparseable`, where it says what failed to parse). One exclusion is
  pinned ahead of its code: the publication rounds' planned `withheld`
  rejection carries no `detail`, ever — its whole diagnosis is `code`
  plus `site.addr` — so no daemon drifts into describing, one field
  over, the extent that code exists to withhold.

<!-- wire: response rejected_site -->
```json
{"code":"malformed_span","disposition":"permanent","op":"retrieve_v","resp":"rejected","site":{"fault":"not_ordinal_level","index":1}}
```

An unparseable frame (unknown op, bad JSON, unknown field, malformed
address…) is answered on the same channel:

<!-- wire: response rejected_unparseable -->
```json
{"code":"malformed","detail":"unknown op 'frobnicate'","disposition":"permanent","op":"unparseable","resp":"rejected"}
```

### Rejection codes

Transport/lifecycle: `unauthenticated`, `malformed`, `durability`,
`txn_over_budget` (the request's records all encode, but the transaction
as a whole exceeds the kernel's per-transaction byte budget — permanent;
split the request), `poisoned`.

Registration/residence: `home_not_registered`, `doc_not_registered`,
`source_not_registered`, `parent_not_registered`, `not_registered`,
`original_not_resident`, `endpoint_not_resident`.

Namespace/authority: `not_owner`, `not_an_account`, `gate`,
`delegator_unknown`, `duplicate_id`, `not_ancestor`, `not_authorized`,
`not_account_tier`, `not_top_down`, `not_next_form`, `not_valid`,
`not_node`, `too_deep`, `not_descendant_of_bootstrap`, `not_fresh`.

Arrangement: `bad_position`, `empty_content`, `content`, `empty_source`,
`bad_span`, `dangling_source`, `empty_result`, `not_arranged`,
`out_of_bounds`, `empty_width`, `bad_cut_count`, `not_ascending`,
`empty_content_subspace`, `not_a_principal`, `node_tier_cross_owner`,
`not_home_link`, `already_seated`, `not_content_subspace`.

Links: `ill_formed_spec`, `empty_type_resolution`, `shape_violation`,
`retraction_class`, `non_address_denoting_type`, `bad_target`,
`self_supersession`, `ill_formed_successor`, `dc_violation`.

Content/provenance reads: `no_such_subspace`, `empty_subspace`,
`depth_incompatible`, `range_not_present`, `malformed_span`.

Link-discovery reads: `not_a_link`, `bad_region`.

Routed, not yet in the protocol: the links family as built in M7's
third round also rejects an over-large slot (`SlotTooLarge`, its
MAX_SLOT_SPANS bound) and refuses through the supersession-class fence.
Neither has a wire code — the list above deliberately carries none;
codes are to be assigned when that links family ships on the wire.

## Operations

Arguments named `…address` must be T4-valid addresses; `…tumbler` fields
(delegation prefixes, node addresses) are raw tumblers. The principal
behind a write always comes from the session — it never appears in a frame.

### Namespace

**`create_new_document`** — mint a fresh empty document in `account` (your
account: resolve it once via `principal_prefix`). → `ack_addr`. The example
carries the optional idempotency `id`:

<!-- wire: request create_new_document -->
```json
{"account":"1.0.1","id":"req-1","op":"create_new_document"}
```

**`delegate`** — carve `new_prefix` off your account (or node) and register
principal `new_id` as its owner, atomically. Obtain `new_prefix` from
`next_account_prefix`; only the owner of the parent may delegate under it.
→ `ack_addr` (the minted account address).

<!-- wire: request delegate -->
```json
{"new_id":2,"new_prefix":"1.0.2","op":"delegate"}
```

**`register_node`** — admit a provisioned node address (bootstrap
provisioning; the address is supplied, not minted). A node address names a
provisioning path, so it is capped at 32 components — deeper is `too_deep`.
→ `ack_addr`.

<!-- wire: request register_node -->
```json
{"addr":"1.1","op":"register_node"}
```

**`fork`** — mint a fresh **empty** account-tier document in your own
account. Shares **no** content: the content-sharing fork is `version`.
→ `ack_addr`.

<!-- wire: request fork -->
```json
{"op":"fork"}
```

**`next_account_prefix`** — the next delegable prefix under `parent`
(what `delegate` demands). → `maybe_addr` (`null` = ineligible parent).

<!-- wire: request next_account_prefix -->
```json
{"op":"next_account_prefix","parent":"1"}
```

**`principal_prefix`** — any principal's account address (public,
immutable registry data). Pass your own principal number — the one echoed
at session open — to resolve your own account. The argument is named
`principal` on the wire (the envelope key `id` is the idempotency slot).
→ `maybe_addr` (`null` = unknown principal).

<!-- wire: request principal_prefix -->
```json
{"op":"principal_prefix","principal":2}
```

### Arrangement (document editing)

Ownership (v5.1): `insert`, `delete`, and `rearrange` require the session
principal to own `doc`; `copy` requires owning the **destination** `doc`
only — its source spans may read anyone's content (transclusion is
unrestricted). A non-owner gets `not_owner` (permanent) with the document
in `site.addr`. `version` is deliberately ungated: forking a foreign
document into your own account IS the sanctioned "propose a change" path.

**`insert`** — insert content into `doc` at V-position `at`; each element
of `values` is a §Content values write form. → `ack_addr` (the first
minted I-address). This example inserts **eleven single-byte values at
eleven positions** — the string form is per-byte:

<!-- wire: request insert -->
```json
{"at":{"ordinal":"1","subspace":"1"},"doc":"1.0.1.0.1","op":"insert","values":["hello, wire"]}
```

Granularity is said, never fallen into: the atom forms mint one composite
value whose interior is permanently unaddressable (§Content values). This
mixed example seats fourteen per-byte values, one composite, two raw
bytes, and one non-UTF-8 composite — eighteen positions:

<!-- wire: request insert -->
```json
{"at":{"ordinal":"1","subspace":"1"},"doc":"1.0.1.0.1","op":"insert","values":["per-byte text ",{"atom":"one indivisible value"},{"hex":"c328"},{"atom_hex":"00ff"}]}
```

**`delete`** — remove `width` positions of `doc` starting at `p`. → `ack`.

<!-- wire: request delete -->
```json
{"doc":"1.0.1.0.1","op":"delete","p":{"ordinal":"3","subspace":"1"},"width":"2"}
```

**`copy`** — transclude the given source spans into `doc` at `at` (shared
identity, not copied bytes). → `ack`.

<!-- wire: request copy -->
```json
{"at":{"ordinal":"6","subspace":"1"},"doc":"1.0.1.0.1","op":"copy","specs":[{"source":"1.0.1.0.2","span":{"start":"1.1","width":"0.5"}}]}
```

**`rearrange`** — pivot/swap `doc`'s content about the cut positions.
→ `ack`.

<!-- wire: request rearrange -->
```json
{"cuts":[{"ordinal":"1","subspace":"1"},{"ordinal":"3","subspace":"1"},{"ordinal":"6","subspace":"1"}],"doc":"1.0.1.0.1","op":"rearrange"}
```

**`version`** — the content-sharing, copy-on-write fork of `d_src`.
→ `ack_addr` (the new version's address).

<!-- wire: request version -->
```json
{"d_src":"1.0.1.0.1","op":"version"}
```

### Links (writes)

Ownership (v5.1): every deposit into a home document's link subspace
requires the session principal to own that home — `make_link`/`emit`/
`nullify`/`assert_sup` their `home`, `edit_link` **both** `d_s` (the
successor's home) and `d_a` (the claim's home). `nullify` additionally
requires owning the **target** link itself (the account of the link's own
address): self-retraction only in v1. Whether a document's owner should be
able to retract foreign links that touch it (territorial moderation), or
retraction should be open with viewer-side filtering, is a genuine
governance question for the lattice — explicitly deferred, not decided by
omission. Failures are `not_owner` (permanent) with the failing home or
target in `site.addr`.

**`make_link`** — create an open link homed in `home`. Each of `from`,
`to`, `ty` takes **one of two forms** (wire v5; no mixing within one slot):

* a **V-spec array** `[{"source": …, "span": …}, …]` — resolved against
  current arrangements; the recorded endset is the permanent I-spans (the
  original form, meaning unchanged);
* an **address form** `{"addrs": ["<address>", …]}` — the recorded endset
  is the NAMES verbatim, one unit subtree span per address, with **no
  resolution and no occupancy requirement**: matching is by address and the
  contents at the addresses are never examined, exactly as Literary
  Machines specifies for link types. Any T4-valid address may be named —
  a link, a document, or a *ghost* position that nothing will ever occupy.

The declared slot order — here and in `edit_link`'s successor — is
`from`, `to`, `ty`: the same positional order links read back in
(slot 1 = FROM, 2 = TO, 3 = TYPE). A pin or diagnostic that speaks of a
link write's slots "in declared order" means this order.

The type slot must be nonempty **as given** (an empty `addrs` list, like a
V-spec set resolving to nothing, rejects `empty_type_resolution`);
`from`/`to` may be empty in either form. → `ack_addr` (the link's
address).

<!-- wire: request make_link -->
```json
{"from":[{"source":"1.0.1.0.1","span":{"start":"1.1","width":"0.5"}}],"home":"1.0.1.0.1","op":"make_link","to":[{"source":"1.0.1.0.2","span":{"start":"1.1","width":"0.6"}}],"ty":[{"source":"1.0.1.0.3","span":{"start":"1.1","width":"0.1"}}]}
```

Typing by pure name: the `ty` below names position `3.6.1` of document
`1.0.1.0.3`'s (never-occupied) subspace 3 — a ghost. Every link naming the
same address is typed identically, and because names nest by tumbler
prefix, one `find_links_ftt` filter over the name — or over the `…3.6`
prefix's subtree — finds every link so typed. The `to` here is a
link-to-link reference: an address-form endset may name a link like any
other address.

<!-- wire: request make_link -->
```json
{"from":[{"source":"1.0.1.0.1","span":{"start":"1.1","width":"0.5"}}],"home":"1.0.1.0.1","op":"make_link","to":{"addrs":["1.0.1.0.1.0.2.1"]},"ty":{"addrs":["1.0.1.0.3.0.3.6.1"]}}
```

**`emit`** — gated typed-relation emission: a managed tuple of type `ty`
(the type key as an endset, usually unit subtree spans of type addresses)
from `from` to the `to` addresses, homed in `home`. Idempotent within a
type class: re-emitting an existing tuple acks the incumbent address.
→ `ack_addr`.

<!-- wire: request emit -->
```json
{"from":"1.0.1.0.1","home":"1.0.1.0.1","op":"emit","to":["1.0.1.0.2"],"ty":[{"start":"9.0.9.0.9.0.9.4","width":"0.0.0.0.0.0.0.1"}]}
```

**`nullify`** — the sole retraction path: retract `target` (a link) from
the active view, by a retraction homed in `home`. → `ack_addr` (the
retraction's address).

<!-- wire: request nullify -->
```json
{"home":"1.0.1.0.1","op":"nullify","target":"1.0.1.0.1.0.2.1"}
```

**`assert_sup`** — record "`old` is superseded by `new`". → `ack_addr`
(the claim's address).

<!-- wire: request assert_sup -->
```json
{"home":"1.0.1.0.1","new":"1.0.1.0.1.0.2.2","old":"1.0.1.0.1.0.2.1","op":"assert_sup"}
```

**`edit_link`** — one composite: create a successor of link `original`
(endsets given as content V-specs; the type slot either
`{"addrs": [addresses…]}` — the identical encoding of `make_link`'s
address form — or `{"resolve": [v-specs…]}`), homed in `d_s`, plus the
supersession claim homed in `d_a`. → `ack_edit`.

<!-- wire: request edit_link -->
```json
{"d_a":"1.0.1.0.1","d_s":"1.0.1.0.2","op":"edit_link","original":"1.0.1.0.1.0.2.1","successor":{"from":[{"source":"1.0.1.0.2","span":{"start":"1.1","width":"0.5"}}],"to":[{"source":"1.0.1.0.2","span":{"start":"1.6","width":"0.2"}}],"ty":{"addrs":["1.0.1.0.3.0.2.1"]}}}
```

### Links (raw reads)

**`read_link`** — the link value at `a`, verbatim. → `link_value`.

<!-- wire: request read_link -->
```json
{"a":"1.0.1.0.1.0.2.1","op":"read_link"}
```

**`follow_link`** — the coverage of slot `slot` of link `a` (1 = FROM,
2 = TO, 3 = TYPE). → `follow`.

<!-- wire: request follow_link -->
```json
{"a":"1.0.1.0.1.0.2.1","op":"follow_link","slot":2}
```

### Content & provenance reads

**`retrieve_v`** — deliver the content of the given (doc, span) specs, in
submitted order. → `delivery`.

<!-- wire: request retrieve_v -->
```json
{"op":"retrieve_v","specs":[{"doc":"1.0.1.0.1","span":{"start":"1.1","width":"0.11"}}]}
```

**`retrieve_doc_v_span`** — the single V-span covering `doc`'s
arrangement. → `span_set`.

<!-- wire: request retrieve_doc_v_span -->
```json
{"doc":"1.0.1.0.1","op":"retrieve_doc_v_span"}
```

**`retrieve_doc_v_span_set`** — `doc`'s exact per-subspace extents: one
span per occupied subspace (`[S,1]` with width = that subspace's position
count; content before links), empty for a registered-empty document.
→ `span_set`.

<!-- wire: request retrieve_doc_v_span_set -->
```json
{"doc":"1.0.1.0.1","op":"retrieve_doc_v_span_set"}
```

**`show_origin`** — the origin documents of the positions in `span` of
`doc`. → `addrs`.

<!-- wire: request show_origin -->
```json
{"doc":"1.0.1.0.1","op":"show_origin","span":{"start":"1.1","width":"0.5"}}
```

**`show_deletions`** — the deletions between two versions, both
directions. → `deletions`.

<!-- wire: request show_deletions -->
```json
{"d_a":"1.0.1.0.1","d_b":"1.0.1.0.2","op":"show_deletions"}
```

**`compare`** — the shared-content correspondence between two region sets.
→ `compare`.

<!-- wire: request compare -->
```json
{"op":"compare","rho1":[{"doc":"1.0.1.0.1","spans":[{"start":"1.1","width":"0.5"}]}],"rho2":[{"doc":"1.0.1.0.2","spans":[{"start":"1.1","width":"0.5"}]}]}
```

**`find_docs_containing`** — the documents whose arrangements contain the
given regions' content. → `addrs`.

<!-- wire: request find_docs_containing -->
```json
{"op":"find_docs_containing","regions":[{"doc":"1.0.1.0.1","spans":[{"start":"1.1","width":"0.5"}]}]}
```

### Link discovery reads

`region` arguments are arrays of depth-2 content V-spans in `d`.

**`image`** — the V→I image of the region (which permanent addresses sit
at those positions). → `runs`.

<!-- wire: request image -->
```json
{"d":"1.0.1.0.1","op":"image","region":[{"start":"1.1","width":"0.5"}]}
```

**`find_links_v`** — the active links whose endsets touch the region.
→ `addrs`.

<!-- wire: request find_links_v -->
```json
{"d":"1.0.1.0.1","op":"find_links_v","region":[{"start":"1.1","width":"0.5"}]}
```

**`find_links_ftt`** — four-set descriptor query. → `addrs`.

<!-- wire: request find_links_ftt -->
```json
{"op":"find_links_ftt","q":{"from":[{"start":"1.0.1.0.1.0.1.1","width":"0.0.0.0.0.0.0.5"}],"home":"any","to":"any","ty":"empty"}}
```

Routed, not yet in the protocol: a POSITION FENCE on this query —
answer only records committed past a caller-supplied position, so a
polling consumer fetches only what is new to it — is reserved as a
later round's delta. Its composition note is pinned with it: a fenced
read must be composed with a client-held honored set, held whole from
unfenced reads, since a record LEAVING that set appears in no fenced
answer — without the held set the departure face is underivable. No
fence field exists today (an unknown field is a parse failure, as
everywhere).

**`count_v`** / **`count_ftt`** — the census forms of the two queries.
→ `count`.

<!-- wire: request count_v -->
```json
{"d":"1.0.1.0.1","op":"count_v","region":[{"start":"1.1","width":"0.5"}]}
```

<!-- wire: request count_ftt -->
```json
{"op":"count_ftt","q":{"from":"any","home":"any","to":"any","ty":"any"}}
```

**`window_v`** / **`window_ftt`** — the windowed forms: up to `n`
addresses past cursor `cur`. → `page`.

<!-- wire: request window_v -->
```json
{"cur":null,"d":"1.0.1.0.1","n":16,"op":"window_v","region":[{"start":"1.1","width":"0.5"}]}
```

<!-- wire: request window_ftt -->
```json
{"cur":"1.0.1.0.1.0.2.1","n":16,"op":"window_ftt","q":{"from":"any","home":"any","to":"any","ty":"any"}}
```

**`retrieve_endsets`** — the endset fragments of active links falling in
the region, per slot. → `endsets`.

<!-- wire: request retrieve_endsets -->
```json
{"d":"1.0.1.0.1","op":"retrieve_endsets","region":[{"start":"1.1","width":"0.5"}]}
```

**`project`** — the I→V projection of link `a`'s slot `slot` into document
`d` (where that endset content sits in `d` now). → `span_set`.

<!-- wire: request project -->
```json
{"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.2","op":"project","slot":2}
```

**`discoverable_from`** — is link `a` arrangement-reachable AND active
from `d`? → `bool`.

<!-- wire: request discoverable_from -->
```json
{"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.1","op":"discoverable_from"}
```

**`delete_orphans`** — preview: which links would the delete of `width`
positions at `p` in `d` orphan? Nothing is written. → `orphans`.

<!-- wire: request delete_orphans -->
```json
{"d":"1.0.1.0.1","op":"delete_orphans","p":{"ordinal":"3","subspace":"1"},"width":"2"}
```

**`in_claims`** / **`out_claims`** — supersession lineage: claims whose
`old` is `y` / whose `new` is `x`, under the given view. → `claims`.

<!-- wire: request in_claims -->
```json
{"op":"in_claims","view":"active","y":"1.0.1.0.1.0.2.1"}
```

<!-- wire: request out_claims -->
```json
{"op":"out_claims","view":"audit","x":"1.0.1.0.1.0.2.2"}
```

## Reading history

Every response names where it sits in the one committed log — `at` on a
write acknowledgment, `as_of` on a read. Those numbers are **positions**:
durable coordinates of committed states, stable across daemon restarts.
`0` is the empty genesis state. A client that keeps the positions from its
own history can ask for any read to be answered as of any of them; history
comes from the substrate's journal itself, never from a client-side
reconstruction.

**`POST /op-at`** — body `{"at": <position>, "frame": {…}}`, where `frame`
is an ordinary `/op` frame (§Operations, same codec, no session needed —
reads are principal-free). The answer is the ordinary response document
for that operation, its `as_of` reporting `at`:

<!-- wire: op_at retrieve_v -->
```json
{"at":9,"frame":{"op":"retrieve_v","specs":[{"doc":"1.0.1.0.1","span":{"start":"1.1","width":"0.5"}}]}}
```

Rules:

* **Read operations only.** History is not a place you can act. A write
  frame is refused at the transport before anything runs:

  <!-- wire: error write_at_history -->
  ```json
  {"error":"write_at_history"}
  ```

* `at` must be a position you were given — a value some response's
  `at`/`as_of` carried, or `0`. A number beyond the committed head:

  <!-- wire: error beyond_head -->
  ```json
  {"error":"beyond_head","head":12}
  ```

  A number that falls *between* positions (inside a multi-record commit —
  such numbers never appear in responses):

  <!-- wire: error not_a_position -->
  ```json
  {"error":"not_a_position","nearest":7}
  ```

  `nearest` is the greatest position at or below the number you sent.

* **Rejections are history too.** A read that would have been rejected at
  that position is rejected the same way now: asking about a document at a
  position before its creation gets that position's own
  `doc_not_registered`. Read the rejection's `disposition` as describing
  that frozen state — a `reorder` cannot resolve by waiting; reissue at a
  later position instead.

* Envelope faults (missing or non-integer `at`, missing `frame`, unknown
  fields) are `400 {"error": "malformed_op_at", "detail": …}`. An
  unparseable `frame` is answered exactly as `/op` answers it: `200` with
  the `unparseable` rejection. An `id` inside the frame is accepted and
  ignored — reads are never memoized (§Correlation and idempotency).

**Determinism.** The same `at` with the same frame yields a byte-identical
response body — across repeats and across daemon restarts. A freshly
started daemon answers positions committed long before it started. `/op-at`
at the current head is byte-identical to the same frame on `/op`.

**Cost and retention.** Each historical read rebuilds the state at `at` by
folding the journal forward from the nearest on-disk checkpoint at or
below it — per request, uncached. This is an observation surface, not a
serving path: fine for history panes and diff tooling, wrong for a hot
loop. Reconstruction is bounded: at most **2** run concurrently, and a
call that finds every slot taken is refused at once with
`503 {"error": "history_busy"}` — a retry-class refusal, never a queue —
so historical reads cannot pin the whole worker pool. Live reads (`/op`,
plain `GET /dump`) are never gated. Retention is exactly what the journal
already provides: the daemon
retains recent checkpoints and reclaims journal segments below the oldest
retained one, so a sufficiently old position can stop being derivable.
Asking for one:

<!-- wire: error history_reclaimed -->
```json
{"error":"history_reclaimed","floor":2048}
```

`floor` (when known) is the oldest position still answerable. Nothing in
this surface extends retention.

**`GET /dump?at=<position>`** (only in `observe` builds) — the
deterministic world dump (§The other endpoints) of the state at that
position. Two calls with equal `at` are byte-equal; `at` = the current
head is byte-equal to plain `GET /dump`. Position errors are `/op-at`'s,
the reconstruction bound included (`503 history_busy`); a malformed query
is `400 {"error": "malformed_at", "detail": …}`.

## The commit stream

**`GET /events`** answers `200 Content-Type: text/event-stream` and never
ends on its own: it is the daemon's push channel for log movement, so
clients stop polling `/health`. No session is needed — like every read it
is principal-free. On connect the daemon immediately sends one event
carrying the current committed head; thereafter it sends an event whenever
the head advances. Every event has this framing (`data` is compact JSON,
the position alone):

<!-- wire: sse commit_event -->
```
event: commit
data: {"log_position":13}
```

A worked exchange — connect, receive the initial head (12), then a write
elsewhere commits at 13:

```
GET /events HTTP/1.1
Host: 127.0.0.1:8642

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: close

event: commit
data: {"log_position":12}

:ka

event: commit
data: {"log_position":13}
```

Rules:

* **Coalescing is expected.** Under load, several commits may collapse
  into one event: the promise is a strictly increasing sequence of
  positions whose last value converges on the true head — not one event
  per commit. A commit is reflected promptly (the daemon notifies on the
  write path rather than polling — well inside 250 ms). Coalescing is
  also the stream's stated wake-rate mitigation: every subscriber wakes
  on every event, board-wide, so a daemon may deliberately coalesce a
  burst to one wake per quiet interval rather than one per commit — an
  allowance this contract already grants (promptness as stated above),
  not a mechanism the current daemon adds.
* **No payload beyond the position in v1**: no op kinds, no document
  addresses, no per-document filtering. React to movement by re-querying
  what you care about — reads are cheap and principal-free.
* **Keepalive.** After 15 seconds of silence the daemon writes the comment
  line `:ka` (followed by a blank line). Treat a stream silent well past
  that as dead, and reconnect.
* **Client guidance:** on `commit`, re-read; on reconnect, treat the
  initial event as potentially having skipped history.
* The stream ends when the daemon shuts down — subscribers see a clean
  connection close. Reconnect on close.

## The change feed

**`GET /changes?since=N`** answers the committed **write** positions in
`(N, head]`, oldest first — what changed, where, and when — so clients
refresh what they display instead of re-walking the world on every
`/events` tick: standing queries become delta scans, and a document-history
view takes its revision positions from the substrate rather than
reconstructing them client-side.

Each entry:

* `at` — the committed position (the same coordinate `/op-at` accepts).
* `op` — the snake_case op kind of the write, or `null` (below).
* `docs` — the document(s) whose state that commit touched, or `null`:
  the write's target doc for `insert`/`delete`/`copy`/`rearrange`; a link
  write names its **home** (`edit_link` both its homes, successor's first);
  the **minted** document for `create_new_document`/`fork`/`version`;
  `delegate` and `register_node` touch no document and carry `[]`.
* `time` — the commit's wall-clock unix milliseconds, or `null` (below).

Only writes appear: reads are not in the journal and never enter the feed.
Rejected operations committed nothing and never appear. An idempotent
retry re-acknowledges the original commit — one entry per commit, ever.

**Timestamps are transport metadata, never substrate state.** They are the
daemon's testimony about when *it* committed each transaction — two
daemons replaying one journal still converge on byte-identical worlds,
and times ride beside the world, not in it. A position whose testimony
was lost answers `null`, never an invented value.

**Paging.** `limit` (default 256, maximum 4096; out-of-range values are
refused, not clamped) caps the page. The response carries `last` — the
final entry's position, or your `since` echoed when the page is empty —
and `more`; pass `last` as the next request's `since` to page. `since` is
a fence, not necessarily a position: any number works, and `since ≥ head`
answers the empty page. Determinism: the same `(since, limit)` against the
same journal answers byte-identically, across repeats and restarts.

The examples below are produced by this flow on a fresh world, asserted
against live daemon bytes (the `time` values are illustrative — the one
normalized field): `delegate` commits at position 2, `create_new_document`
at 3, a two-byte `insert` at 8, `make_link` at 11.

<!-- wire: changes feed -->
```json
{"changes":[{"at":2,"docs":[],"op":"delegate","time":1786838400000},{"at":3,"docs":["1.0.1.0.1"],"op":"create_new_document","time":1786838400012},{"at":8,"docs":["1.0.1.0.1"],"op":"insert","time":1786838400031},{"at":11,"docs":["1.0.1.0.1"],"op":"make_link","time":1786838400047}],"last":11,"more":false}
```

The first page of the same feed, `GET /changes?since=0&limit=2`:

<!-- wire: changes feed_page -->
```json
{"changes":[{"at":2,"docs":[],"op":"delegate","time":1786838400000},{"at":3,"docs":["1.0.1.0.1"],"op":"create_new_document","time":1786838400012}],"last":3,"more":true}
```

**Bare entries.** A position whose metadata the daemon never observed — a
data dir written before this feature existed, or a record lost to a crash
— still appears, reconstructed from the journal itself, with every
metadata field `null`. The same flow's first three writes on a pre-feature
dir (byte-exact):

<!-- wire: changes bare -->
```json
{"changes":[{"at":2,"docs":null,"op":null,"time":null},{"at":3,"docs":null,"op":null,"time":null},{"at":8,"docs":null,"op":null,"time":null}],"last":8,"more":false}
```

**Retention.** The feed's memory is the daemon's `commits.log` sidecar
plus what the journal can still reconstruct. When `since` reaches below
that — reclaimed or unreadable journal regions — the answer is the same
discipline as `/op-at`: `410 {"error": "history_reclaimed", "floor": F?}`,
`F` the oldest position that still has an entry. A malformed query
(missing `since`, a non-integer, an out-of-range `limit`, an unknown
parameter) is `400 {"error": "malformed_changes", "detail": …}`.

## The other endpoints

**`GET /health`** → `200 {"head_time": <ms>|null, "log_position": <n>,
"ok": true}`. `head_time` is the newest recorded commit's wall-clock unix
milliseconds (§The change feed's timestamp scope: transport metadata) —
`null` on a fresh world or when the head position's record is bare.

**`GET /`** (only in builds with the `client` feature — **default-off**,
the 2026-08-22 ruling (AUTH-4.57(e); R89, the client rule): the served
page ACTS — it generates keys and opens sessions — so the safe failure
is a notebook build that forgot the flag serving no UI, never a hosted
image serving a key-generating page by omission; notebook packagings
opt in deliberately) → `200 text/html`: the authoring client, one
self-contained HTML file embedded in the binary at build. There are no
other static routes and no asset pipeline — the client is one file by
design. Without the feature, `/` is an unknown path (the usual 404
shape).

**`GET /dump`** (only in builds with the `observe` feature; absent
otherwise, so a plain build answers 404) → `200 text/plain`: the engine's
deterministic world dump (`skep-world-dump v1` format), byte-comparable
across processes for run reconstruction. Two dumps of equal worlds are
byte-equal. `GET /dump?at=N` serves a historical position (§Reading
history).

## A first session, end to end

```
POST /session          {"principal": 0}                # bootstrap
POST /op   (session)   {"op": "next_account_prefix", "parent": "1"}
POST /op   (session)   {"op": "delegate", "new_prefix": <that>, "new_id": 1}
POST /session          {"principal": 1}                # your principal
POST /op   (session)   {"op": "create_new_document", "account": <delegated>}
POST /op   (session)   {"op": "insert", "doc": <doc>, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}
POST /op               {"op": "retrieve_v", "specs": [{"doc": <doc>, "span": {"start": "1.1", "width": "0.5"}}]}
```

The insert seats five single-byte values at positions 1..=5 (§Content
values), which is exactly why the retrieve's width is `"0.5"` and the
delivery is `[{"content": "hello"}]`.

## Changelog of wire decisions

v6.1 (routed documentation pins — the PUB sweeps' wire routes, landed
2026-08-28; no encoding, surface, or behavior change):

* The publication rounds' planned `withheld` rejection is pinned, ahead
  of its code, to carry NO `detail` — its whole diagnosis is `code`
  plus `site.addr` — so no conforming daemon grows an extent-describing
  payload before the code ships. [PUB sweep-10 pub-leak]
* The V-spec slot order for `make_link`/`edit_link` declared: `from`,
  `to`, `ty` — the read-back positional order (1/2/3), now stated for
  the write surface so ordering-consuming pins (`site.addr`'s "first …
  in declared order") have their order. [PUB sweep-9 pub-leak]
* The future `delivery` withheld item
  (`{"withheld": {"origin", "width"}}`) is pinned per-RUN: two
  non-contiguous withheld runs, one origin or not, are two items, never
  one coalesced item of the summed width. [PUB sweep-9 pub-leak]
* `/events` coalescing is named the stream's wake-rate mitigation — one
  wake per quiet interval rather than one per commit, an allowance the
  v4 contract already grants; no new mechanism claimed. [PUB sweep-9
  pub-performance]
* The base determinism conditioning stated as the wire's own pin: the
  positioned-read byte-identity promises hold while the position (or
  the history behind the fence) remains within RETENTION — reclaim
  answers `history_reclaimed`, never different bytes; later rounds
  state their own further terms on top. [PUB sweep-11 pub-permanence]
* Roadmap: a position fence on `find_links_ftt` (records past a
  caller-held position) is reserved for a later round, pinned beside
  its composition note (a fenced read composes with a client-held
  honored set or the departure face is underivable). Not in the
  protocol. [PUB sweep-11 pub-performance]
* Corrected: the `client` feature is DEFAULT-OFF (the 2026-08-22
  default-off ruling, AUTH-4.57(e); R89, the client rule) — v6's
  "default on" was true when v6 landed and is superseded; the endpoint
  descriptions now say so. [AUTH sessions sweeps 5 and 7,
  auth-substrate]
* Roadmap: M7's round-3 links family rejects an over-large slot
  (`SlotTooLarge`, MAX_SLOT_SPANS) and refuses through the
  supersession-class fence; the wire's code list carries no codes for
  either — to be assigned when that links family ships on the wire.
  [the M7 interface reconcile, 2026-08-28]

v6 (browser enablement: change feed, commit timestamps, served client —
the 2026-08-16 ruling):

* New `GET /changes?since=N[&limit=K]`: the pull delta feed of committed
  writes in `(N, head]`, oldest first — `{"at", "op", "docs", "time"}` per
  entry, `{"changes", "last", "more"}` around them; `limit` default 256,
  max 4096, out-of-range refused (`400 malformed_changes`); `since ≥ head`
  is the empty page with `last` echoing `since`; `since` below retained
  history is `/op-at`'s own `410 history_reclaimed` discipline. Writes
  only — reads never appear; rejections never appear; an idempotent retry
  never duplicates an entry.
* Affected-docs convention fixed: target doc for arrangement writes, home
  for link writes (`edit_link` both homes), the minted document for
  `create_new_document`/`fork`/`version`, `[]` for `delegate`/
  `register_node`.
* Commit timestamps enter the wire as **transport metadata, never
  substrate state** — the daemon's testimony about when it committed,
  riding beside the world (two daemons replaying one journal still
  converge byte-identically). Provenance: timestamps were a planned Nelson
  extension to Xanadu (owner's confirmation, 2026-08-16). Mechanism: the
  daemon-owned `commits.log` sidecar in the data dir, written at ack time,
  replayed on reopen; a torn tail truncates at the last whole record;
  lost or pre-feature positions are reconstructed from the journal as bare
  entries answering `"op": null, "docs": null, "time": null` — null over
  invention, always. Surfaced in `/changes` and as `/health`'s new
  `head_time`; deliberately NOT added to op responses (the live surface is
  unchanged).
* New `GET /` (feature `client`, default on — since ruled default-OFF,
  2026-08-22; see v6.1): the authoring client served
  as one embedded HTML file, `text/html`, same CORS posture as everything
  else; no other static routes, no asset pipeline. Without the feature,
  `/` stays a 404.

v5.1 (ownership gate on the write surface — the 2026-08-16 security
ruling; no encoding change, new rejection paths):

* Ownership, in one sentence: a caller owns a document iff its account is
  **exactly** the document's account — the nearest registered account
  prefix of the document's address, never mere prefix containment (so
  parent and sub-delegated accounts do not own each other's documents, in
  either direction).
* Ops that now reject `not_owner` (permanent, `site.addr` = the failing
  address), checked after registration and before all other validation:
  `insert`/`delete`/`rearrange` on `doc`; `copy` on its **destination**
  `doc` only (source spans stay unrestricted — transclusion of anyone's
  content is the point of the medium); `make_link`/`emit`/`assert_sup`/
  `nullify` on `home`; `edit_link` on both `d_s` and `d_a`; and `nullify`
  additionally on the **target** link's own address.
* Nullify target policy: self-retraction only. Territorial moderation
  (owner of a touched document may retract) versus open retraction with
  viewer-side filtering is an explicitly deferred scope decision.
* `version` of a foreign document remains ungated by design: it forks into
  the CALLER's account (denial-as-fork) and is the sanctioned
  "propose a change" path.
* Reads are unchanged: every read remains principal-free.

v5 (address-denoting endsets on the open link surface — the 2026-08-16
ruling; spec anchors ASN-0043 L4/L8/L9/L13, Literary Machines 4/44):

* `make_link`'s `from`/`to`/`ty` each accept a second form,
  `{"addrs": ["<address>", …]}`, beside the unchanged V-spec array: the
  recorded endset is the names verbatim — one unit subtree span per
  address, no resolution, no occupancy requirement, nothing beyond address
  validity (type matching is by address; contents are never examined, and
  ghost names are valid types). Per-slot either/or; a mixed need resolves
  first via the read surface and passes `addrs`.
* The type floor reads *as given*: an empty `addrs` list rejects
  `empty_type_resolution` exactly as an empty resolution always has;
  `from`/`to` may be empty in either form.
* The addrs-object encoding is byte-identical to `edit_link`'s successor
  `ty` addrs form, which already existed; the V-spec-array form is
  byte-identical to v4 (existing frames mean exactly what they meant).
* `udanax-green` precedent: its standard client marker types were always
  pure address names (vspans over never-created link-subspace positions of
  doc 1) — the open surface now says so first-class.

v4 (browser reads — CORS everywhere, the commit stream):

* Every response now carries `Access-Control-Allow-Origin: *`; `OPTIONS`
  on any known path answers `204` with
  `Access-Control-Allow-Methods: GET, POST, OPTIONS`,
  `Access-Control-Allow-Headers: Content-Type, Skepd-Session`, and
  `Access-Control-Max-Age: 86400`; unknown paths keep their 404. Scope
  decision: `*` is safe precisely because the daemon is loopback-only
  local trust — reads are public to local pages, writes still ride the
  session token, and the token is not a browser credential. Revisited when
  authentication lands.
* New `GET /events`: a `text/event-stream` of committed positions — one
  initial event carrying the current head at connect, then `event: commit`
  with `data: {"log_position":N}` (compact JSON, the position alone) as
  the head advances. Coalescing under load is promised behavior (a
  strictly increasing sequence converging on the head); `:ka` comment
  keepalives after each 15 s of silence; no payloads or filters in v1 —
  clients re-read on movement. Delivery is write-path notification, not
  polling, and event-stream subscribers never occupy the op workers.
* Reconnect guidance fixed: on `commit`, re-read; on reconnect, treat the
  initial event as potentially having skipped history.
* Transport made explicit: one request per connection (`Connection: close`
  on every response — connection reuse was never contractual); the event
  stream is the one unbounded response, ended by daemon shutdown with a
  clean close. `Expect: 100-continue` honored; `Transfer-Encoding` request
  bodies refused with the new `400 malformed_http`, which also answers an
  unparseable request head.

v3 (historical reads — read-at-position, served from the journal):

* New `POST /op-at`: `{"at": <position>, "frame": {<read op>}}` — the same
  codec and response documents as `/op`, `as_of` reporting `at`. Positions
  are the `at`/`as_of` values responses already carry (`0` = genesis);
  clients hold them from their own history.
* Read-only, enforced at the transport: a write frame is
  `400 {"error":"write_at_history"}` (ruling-fixed body); `at` beyond the
  head is `400 {"error":"beyond_head","head":n}` (ruling-fixed).
* A number inside a multi-record commit is not a position:
  `400 {"error":"not_a_position","nearest":p}` — refused rather than
  silently answered at a state that never observably existed.
* Rejections replay as history: a document queried before its creation
  gets that position's own `doc_not_registered`; dispositions describe the
  frozen state.
* Envelope faults: `400 malformed_op_at`; an unparseable frame stays on
  the op channel (`200` + `unparseable`), as on `/op`.
* `GET /dump?at=N` (observe builds): the deterministic dump of that
  position; equal `N` byte-equal; `N` = head equals plain `/dump`;
  malformed query `400 malformed_at`.
* Mechanism and cost stated: per-request bounded replay from the nearest
  checkpoint at or below `at`, uncached; deterministic across restarts.
  Retention is the journal's own — reclaimed positions answer
  `410 {"error":"history_reclaimed","floor":p?}`.
* The frame's `id` is accepted and ignored (reads are never memoized).

v2 (value granularity — one adjudicated defect, two faces; found by the
client-side smoke harness against the conformance record's per-byte text
discipline):

* **Write side.** `"str"` and `{"hex"}` now mint **one single-byte value
  per byte** — v1 read them as one composite value of all the bytes, which
  silently made the payload's interior permanently unaddressable. The
  composite reading survives only as the explicit `{"atom"}`/`{"atom_hex"}`
  forms: coarse granularity must be said, never fallen into.
* **Read side.** The delivery marshal is now injective: v1 rendered N
  per-byte positions and one N-byte value identically. v2 renders a maximal
  per-byte run as one `content`/`hex` item (UTF-8 judged on the whole run)
  and every composite value as its own `atom`/`atom_hex` item, never
  coalesced.
* Empty forms: `""`/`{"hex": ""}` are vacuous (zero values); `{"atom": ""}`
  and `{"atom_hex": ""}` are parse failures.
* The insert example `{"values": ["hello, wire"]}` is unchanged in bytes
  and changed in meaning: eleven values, eleven positions.
* Granularity is not enforced server-side — composite values are a
  legitimate store capability; the wire's job is making the choice explicit
  and lossless in both directions.

v1 (initial):

* Internally tagged request objects; snake_case op names; strict unknown-op
  and unknown-field rejection (never-silent applied to typos).
* Tumblers/addresses as dotted-decimal strings; unbounded naturals as
  decimal strings (lenient integer parse); bounded integers as JSON
  numbers.
* Spans as `{"start", "width"}` objects; endsets/span-sets as span arrays,
  order verbatim.
* Content values: UTF-8 as JSON strings, raw bytes as `{"hex": …}`, one
  value per array element (superseded by v2's granularity forms).
* Responses tagged by `resp`; payload options (`addr`, `link`, `next`)
  explicit `null`; diagnostic options (`site`, `detail`) omitted when
  absent.
* Deterministic canonical marshal: sorted keys, compact, byte-stable.
* `POST /op` always `200` once a response exists; rejections are response
  documents, not HTTP statuses; transport errors use `{"error": …}`.
* Sessions: opaque tokens in the `Skepd-Session` header; token → session
  binding lives in the daemon, so session identity never rides the wire;
  tokens die with the process; unknown/absent token = principal-free guest
  (reads served, writes `unauthenticated`); no close endpoint in v1.
* Identity: local trust, client-named principals, loopback bind only.
* `principal_prefix`'s argument is `"principal"` on the wire (envelope
  `"id"` is the idempotency key).
* Four-set slot constraints: `"any"` / `"empty"` / span array; `[]` reads
  as `"empty"`.
* Cursor: `null` or absent = start; the cursor is the whole continuation.
