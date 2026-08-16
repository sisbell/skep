# skepd wire protocol

The HTTP/JSON contract between `skepd` and its clients. This document is
written for a client author who will never read the Rust; it is also
executable documentation — every fenced JSON example annotated with a
`<!-- wire: … -->` marker is asserted byte-for-byte-canonically by
`skep/crates/skepd/tests/wire_doc.rs`, so an example that drifts from the
daemon fails the build.

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
| `GET /health`    | Liveness + current log position.                           |
| `GET /dump`      | Deterministic world dump; `?at=N` for a committed position (only in `observe` builds). |

There are no other routes. The daemon listens on **127.0.0.1 only**.

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
| 400    | `unreadable_body`           | the request body could not be read      |
| 400    | `malformed_op_at`           | `POST /op-at` body isn't `{"at": n, "frame": {…}}` |
| 400    | `write_at_history`          | the `/op-at` frame is a write operation |
| 400    | `beyond_head`               | the position exceeds the committed head (carries `head`) |
| 400    | `not_a_position`            | the number is not a committed position (carries `nearest`) |
| 400    | `malformed_at`              | the `/dump` query isn't `at=<position>` |
| 404    | `no_such_endpoint`          | unknown path (including `/dump` on a build without `observe`) |
| 405    | `method_not_allowed`        | known path, wrong method                |
| 410    | `history_reclaimed`         | the position predates the retained journal (carries `floor` when known) |
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
  lookups. Span faults: `not_ordinal_level`, `not_level_uniform`,
  `start_not_zero_free`, `start_too_shallow`.
* `detail` — optional human-readable message (always present on
  `unparseable`, where it says what failed to parse).

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
`poisoned`.

Registration/residence: `home_not_registered`, `doc_not_registered`,
`source_not_registered`, `parent_not_registered`, `not_registered`,
`original_not_resident`, `endpoint_not_resident`.

Namespace/authority: `not_owner`, `not_an_account`, `gate`,
`delegator_unknown`, `duplicate_id`, `not_ancestor`, `not_authorized`,
`not_account_tier`, `not_top_down`, `not_next_form`, `not_valid`,
`not_node`, `not_descendant_of_bootstrap`, `not_fresh`.

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
provisioning; the address is supplied, not minted). → `ack_addr`.

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

**`make_link`** — create an open content link homed in `home`; `from`,
`to`, `ty` are V-spec sets resolved against current arrangements (the
recorded endsets are permanent I-spans). The type slot must resolve
nonempty. → `ack_addr` (the link's address).

<!-- wire: request make_link -->
```json
{"from":[{"source":"1.0.1.0.1","span":{"start":"1.1","width":"0.5"}}],"home":"1.0.1.0.1","op":"make_link","to":[{"source":"1.0.1.0.2","span":{"start":"1.1","width":"0.6"}}],"ty":[{"source":"1.0.1.0.3","span":{"start":"1.1","width":"0.1"}}]}
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
`{"addrs": [addresses…]}` or `{"resolve": [v-specs…]}`), homed in `d_s`,
plus the supersession claim homed in `d_a`. → `ack_edit`.

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
loop. Retention is exactly what the journal already provides: the daemon
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
head is byte-equal to plain `GET /dump`. Position errors are `/op-at`'s;
a malformed query is `400 {"error": "malformed_at", "detail": …}`.

## The other endpoints

**`GET /health`** → `200 {"log_position": <n>, "ok": true}`.

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
