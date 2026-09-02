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
| `POST /session`  | Bind a principal — bare, or signed over a challenge; returns an opaque session token. |
| `GET /challenge` | Issue a signed-handshake nonce for a principal (§Sessions). |
| `POST /session/close` | End the presented session; idempotent `204` (§Sessions). |
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
capped per route — **8 MiB** on the frame routes (`/op`, `/op-at`),
**8 KiB** everywhere else (the session bodies ride the small cap): a
larger declared `Content-Length` is refused with `413 payload_too_large`
before any body byte is read.

### Identity — modes, principals, credentials

Identity has two layers. A **principal** (a small integer) is the account
system's actor: principal `0` is the bootstrap principal, which owns the
root of the namespace; any other principal must first be minted with a
`delegate` operation before its writes will be accepted by the stores.
Each distinct principal is its own account, so every write is attributed.
A **credential** is an Ed25519 public key enrolled for an account
(§The claim ceremony and credentials): keys ride the wire as 64 lowercase
hex of the raw key, and a key is named by its **fingerprint** — 64
lowercase hex of `SHA-256("skep-key-v1" ‖ be32-framed alg token ‖
be32-framed raw key)` — the flat form every identity surface below emits
(grouping is a client display convention).

The board is always in exactly one of three MODES, derived from two facts
`GET /health` publishes (`auth.claimant` and `auth.local_trust` — there
is deliberately no `mode` field; clients derive it from the pair):

* **UNCLAIMED** — no claimant yet. Bare sessions bind on loopback, and
  the write surface admits only the claim ceremony's own opening shape —
  everything else refuses `claim_first` (§Credential refusals). Reads
  are open throughout.
* **CLAIMED-PERMISSIVE** — claimed, `--local-trust` on (the default). A
  bare session still binds on loopback: any local party may write as any
  principal. That is the default's disclosed cost, and the daemon warns
  about it at startup and again at the claim flip. Credential deposits
  and bare writes landing in the published world still refuse
  (`signed_session_required`).
* **ENFORCING** — claimed, `--local-trust` off. Bare sessions are
  refused; only signed sessions write.

The signed session is cryptographic identity — a challenge signed by a
key enrolled for the principal's account (§Sessions). The bare session is
v1's **local trust**, retained as a mode rather than the whole model; the
daemon still binds **127.0.0.1 only**.

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
errors included — carries `Access-Control-Allow-Origin: *` and
`Access-Control-Expose-Headers: Skepd-Session` (the death signal below
is not a CORS-safelisted response header; without the exposure a page on
a configured non-loopback origin could never read it). `OPTIONS` on any
known path — the session endpoints included — answers the preflight:

```
OPTIONS /op
→ 204
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Skepd-Session
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Skepd-Session
Access-Control-Max-Age: 86400
```

(`OPTIONS` on an unknown path is the ordinary 404.) Authentication has
landed and the v4 decision was revisited as promised: `*` stays,
deliberately. Reads are guest-free, and neither credential is
browser-ambient — the signed session binds its origin inside the
signature (no cookies; §Sessions), the bare bind — the one ambient
credential retained — is refused server-side when the request's
`Origin` header is not one the bare origin set answers for, and the
session token is 128 bits of CSPRNG output a foreign page cannot guess.
A narrower ACAO was weighed and declined: the foreign page's POST is
fenced by the daemon, not by what the browser lets it read back, and
narrowing would break local pages that only read.

### Sessions

The token is **32 lowercase hex** — 128 bits of fresh OS-CSPRNG output
minted per session open, never derived from process state. Admission is
strict: a presented header value that is not exactly 32 lowercase hex IS
no token — the request runs as a guest, nothing is closed, no signal is
sent. (v1's `prefix.suffix` token shape is refused.) Send it on
subsequent calls as the header:

```
Skepd-Session: 9f3a6c21d4b8e07a5c1b2d4e6f708192
```

**`POST /session`** accepts exactly two body forms. Anything else — an
unknown field, a missing member of the signed triple, a malformed value
— is `400 malformed_session_request` with a `detail`, and a 400 never
spends a nonce: a syntax fault costs no re-challenge.

*Bare* — `{"principal": 2}`, v1's form unchanged. Honored only when ALL
of: the board is not ENFORCING (§Identity); the TCP peer is loopback;
and the request's `Origin` header, when present, parses as a canonical
origin in the **bare origin set** (§The claim ceremony and credentials;
`Origin: null` parses to nothing and refuses). Refusal is the one 401
below.

*Signed* — `{"principal": 2, "nonce": "<64 hex>", "origin":
"<origin>", "sig": "<128 hex>"}` — verified in every mode, UNCLAIMED
included. The fields are strict bytes: `origin` must arrive already
canonical (lowercase `scheme://host[:port]`, no path, no trailing
slash, the scheme's default port omitted), `nonce` is 64 LOWERCASE hex,
`sig` is 128 hex characters (case-free — it is decoded, never framed)
for exactly 64 signature bytes. The daemon canonicalizes nothing on
this path.

The handshake starts at the challenge:

```
GET /challenge?principal=7
→ 200
{"nonce":"<64 lowercase hex>","principal":7,"ttl_ms":60000}
```

A nonce is issued for ANY principal — nothing about issuance is secret;
the burn is the credential. It lives 60 seconds (`ttl_ms` is a byte pin
of that constant) and is **single-use**: verification removes it
whether or not the signature validates, so a failed signed attempt
costs a fresh challenge. At most 4096 nonces are live at once; past the
cap the oldest is evicted. A malformed query is
`400 malformed_challenge`.

The signed bytes are

```
"skep-session-v1" ‖ be32(|origin|)‖origin ‖ be32(|nonce|)‖nonce ‖ be32(|principal|)‖principal
```

over the body's OWN strings — `principal` as shortest ASCII decimal,
`be32` the 4-byte big-endian byte length. Sign with a private key whose
public key is enrolled for the principal's account: principal `0` signs
with the CLAIMANT account's keys (none exist while unclaimed), every
other principal with its own account's. Verification order: the origin
must be in the **signed origin set**; the nonce burns (unknown,
expired, wrong-principal and reused all die here, and the entry is gone
either way); the account's key set must be non-empty; then every
enrolled key is tried in fingerprint order (Ed25519 strict
verification) — no cutoff, ever.

**Every handshake failure — bare and signed alike — answers the ONE
auth transport error**, permanent, byte-identical across causes,
carrying no detail by design:

```
→ 401
{"error":"session_rejected"}
```

Success is the familiar answer — the token, and `principal` echoed so
the client can name its own account later via `principal_prefix`:

```
→ 200
{"principal":7,"session":"9f3a6c21d4b8e07a5c1b2d4e6f708192"}
```

Every successful `POST /session` mints a distinct session, principal
`0` included.

**`POST /session/close`** (token in `Skepd-Session`) → `204`,
idempotent. Closing a live session is a bare 204 — the close is the
caller's own act, so no signal rides it; presenting an unknown or
already-dead token answers 204 **with** the death signal below.

Rules:

* **Sessions can end before restart** — four ways: `POST
  /session/close`; a daemon restart (every token dies; a stale token
  then reads as unknown); **retirement** — a signed session dies when
  its establishing key leaves the account's enrolled set; and **mode**
  — a bare session's entry dies when the board is ENFORCING at
  presentation. Dead entries are evicted lazily, at the next
  presentation. There is no session TTL and no session cap.
* **The death signal.** When a token-accepting route is presented an
  UNKNOWN token, or a token whose entry is dead, the daemon closes the
  binding and the response carries the header `Skepd-Session: closed`
  — a read presenting a dead token is never silently a guest read. The
  token-accepting routes: `POST /op`, `POST /op-at`, `GET /changes`,
  `GET /dump`, `POST /session/close`, and `GET /events` — checked
  before the stream opens, the header written once on the stream head.
  `GET /health`, `GET /challenge`, `POST /session` and `GET /` are
  token-blind.
* **Refused-for-this-request is not death.** A LIVE bare session
  presented from a request whose `Origin` header falls outside the bare
  set (or from a non-loopback peer) runs that one request as a guest:
  the entry lives untouched and no header is sent.
* A request with **no token** (or an unparseable one) still gets a full
  answer: read operations are principal-free and succeed normally;
  write operations are rejected with code `unauthenticated`
  (permanent) — still the first gate in the write order, ahead of every
  credential token (§Credential refusals). That rejection is your
  signal to (re)open a session.
* The signal is additive: reads and writes are otherwise unchanged.

### The claim ceremony and credentials

Credential state is written THROUGH the ordinary link surface — no new
write op exists. A **credential deposit** is a `make_link` whose type
slot names one of three reserved credential type addresses — ghost
tumblers in subspace 3 of the same ghost document that carries the
reserved link classes; nothing is ever minted at them, and a resolved
content span can never equal them:

| Kind | Type address | Deposit shape |
|------|--------------|---------------|
| enroll | `1.1.0.1.0.1.0.3.1` | `from` = the record's positions (in the home's own space), `to` = the subject account (one address), homed in a **doc 1** — the subject's own for a holder act, its delegator's (the genesis registry) for the first seeding |
| retire | `1.1.0.1.0.1.0.3.2` | the same shape, homed in the subject's OWN doc 1 only — no ancestor retires a holder's keys |
| claim | `1.1.0.1.0.1.0.3.3` | `from` = the claiming account (one address), `to` = `[]`, no payload, homed in that account's doc 1 |

Deposit slots are **address-form only** (`{"addrs": […]}`): a V-spec
`from`/`to` refuses `resolved_from`, a credential-typed `emit` always
refuses `emit_not_make_link`, and a credential-typed `edit_link` always
refuses `resolved_from` (§Credential refusals). The home pin (RES-17):
a credential link homed in any document of its account other than
doc 1 refuses `not_doc_one`.

The records themselves are plain content. Write the record's bytes into
the home document first — the convention is ONE composite atom, so one
address names the whole record — then deposit a link whose `from` names
those positions (endset order, bytes concatenated; every named position
must be in the home's own space and occupied). A record is capped at
64 KiB and reads:

```
skep-enroll v1
anchor ed25519 <64 hex public key> <label…>
ed25519 <64 hex public key> <label…>
```

```
skep-retire v1
<64 hex fingerprint>
```

Line 1 is the header, byte-exact; one key (or fingerprint) per line;
the LEADING token `anchor` marks an anchor key, and the flag is fixed
for the fingerprint's lifetime; the label is everything after the hex,
verbatim; `sig …` lines are skipped (reserved); lines split on `\n`
alone; hex parses case-insensitively and is lowercase canonically. An
unparseable record makes the deposit permanently inert — the daemon
refuses it up front as `malformed_payload:<sub>` (§Credential
refusals).

**The ceremony** is the unclaimed board's one admitted write sequence
(worked end-to-end in §A first board): `delegate` from principal 0 →
the home mint (`create_new_document`, which becomes doc 1) → the record
`insert` into doc 1 → the genesis enroll deposit → the claim deposit.
The genesis deposit seeds the account's key set (the enrolled-set cap
does not bind it, and the anchor gate is exempt — the seeding hand
records the initial set, flags included); the claim deposit flips the
board claimed — first claim wins, permanently. Only a top-level
(bootstrap-delegated) account with a non-empty key set can claim. The
ceremony's convention signs the claim with a just-enrolled key, proving
custody before the flip; the unclaimed window itself admits the deposit
from a bare session too.

**Origins, and the claim-time drop.** Origins are configured at launch
(`--origin`, repeatable) and published verbatim by `GET /health`
(§The other endpoints); the canonical form is lowercase
`scheme://host[:port]`, no path, no trailing slash, the scheme's
default port omitted. Two sets derive from the config:

* the **bare set** — configured ∪ the three loopback defaults of the
  bound port (`http://127.0.0.1:P`, `http://[::1]:P`,
  `http://localhost:P`) — in every mode;
* the **signed set** — the bare set while unclaimed; **the configured
  origins alone** once claimed. The drop is the point: a signed
  handshake binds its origin inside the signature, and after the claim
  only origins the operator affirmatively configured are signable.

The empty-origins consequence: a board claimed with NO `--origin` has
an empty signed set, so **every signed session is refused** (the one
401) until the daemon is relaunched with an origin. The daemon says so
— at startup and again, unconditionally, at the claim flip it warns:
`board is claimed with no configured origin: signed_origins is empty
and every signed session will be refused`. Its two sibling warnings:
claimed with `--local-trust` still on (any loopback party may write as
any principal — CLAIMED-PERMISSIVE), and a configured loopback-host
origin naming a port the daemon is not bound to (keys enrolled under it
are stranded until the origin is re-issued for the bound port).

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
misses. One credential-path difference: a credential deposit (§The claim
ceremony and credentials) rides its own per-session memo with the same
contract — the original acknowledgment, byte-identical, no re-execution
— except the hit is KIND-BLIND (`id` already ran on this session) and
the memo dies with its session, close included.

### HTTP status codes

`POST /op` returns **`200` whenever the daemon produced an operation
response — including every rejection**. The response document, not the HTTP
status, is the operation protocol; clients dispatch on the `resp` field.
Non-200 statuses are transport-level failures with a body of the shape
`{"error": "<name>", "detail": "…"?}`:

| Status | `error`                     | When                                    |
|--------|-----------------------------|-----------------------------------------|
| 400    | `malformed_session_request` | `POST /session` body is neither session form (§Sessions); the nonce survives |
| 400    | `malformed_challenge`       | the `/challenge` query isn't `principal=<non-negative integer>` |
| 401    | `session_rejected`          | the `POST /session` handshake refused — one code for every cause, no detail (§Sessions) |
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

**`key_set`** — key_set: an account's credential table (§Identity
reads). `enrolled` and `retired` entries ride in fingerprint order;
`anchor` per entry is the flag the fingerprint was ENROLLED under,
retired entries included. A keyless account answers two empty arrays.
(The example is illustrative — this shape is asserted by the daemon's
auth suite against live bytes, not by the codec fixtures.)

```json
{"as_of":9,"enrolled":[{"alg":"ed25519","anchor":true,"fingerprint":"abababababababababababababababababababababababababababababababab","key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"}],"resp":"key_set","retired":[{"anchor":false,"fingerprint":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}]}
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
  reported one: `{"operand": "first"|"second"?, "region": n?, "slot": n?,
  "index": n?, "fault": "<span fault>"?, "addr": "<address>"?}`.
  `index`/`fault` localize a malformed span in a multi-span request;
  `operand`/`region` localize compare inputs; `slot` localizes an
  `edit_link` successor fault to one of its three slots, in the read-back
  slot numbering (`1` = from, `2` = to, `3` = ty), so the `index` beside it
  is a position *within* that slot; `addr` names the offending document in
  multi-document lookups — and, on a `not_owner` rejection, the document
  (or target link) that failed the ownership check. Span faults:
  `not_ordinal_level`, `not_level_uniform`, `start_not_zero_free`,
  `start_too_shallow`.
* `detail` — optional message (always present on `unparseable`, where
  it says what failed to parse). On `credential_refused` the field is a
  MACHINE token — the code:detail convention, one pinned token per
  refusal, e.g. `signed_session_required` — and the one place clients
  dispatch on `detail` (§Credential refusals). One exclusion is
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
`txn_unencodable` (a record the operation staged could not be encoded
into a journal frame at all — permanent; reissuing the same request
stages the same record), `txn_over_budget` (the request's records all
encode, but the transaction as a whole exceeds the kernel's
per-transaction byte budget — permanent; split the request), `poisoned`.

Credentials: `credential_refused` — the auth work's one new code,
always `permanent`, always carrying a machine `detail` token
(§Credential refusals below).

Registration/residence: `home_not_registered`, `doc_not_registered`,
`source_not_registered`, `parent_not_registered`, `not_registered`,
`original_not_resident`, `endpoint_not_resident`.

Namespace/authority: `not_owner`, `not_an_account`, `gate`,
`delegator_unknown`, `duplicate_id`, `not_ancestor`, `not_authorized`,
`not_account_tier`, `not_top_down`, `not_next_form`, `not_valid`,
`not_node`, `too_deep`, `not_descendant_of_bootstrap`, `not_fresh`.

Arrangement: `empty_content`, `content`, `empty_source`,
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

### Credential refusals

Every `credential_refused` is the ordinary `rejected` shape with
`disposition: "permanent"` uniformly and `detail` carrying exactly one
machine token — key client behavior on the token, never on prose. A
bare session depositing a credential on a claimed board, for example:

```json
{"code":"credential_refused","detail":"signed_session_required","disposition":"permanent","op":"make_link","resp":"rejected"}
```

The write order, as built. `unauthenticated` is slot 0 on every path: a
guest write (no token, unknown token, dead entry) answers M10's own
`unauthenticated` and never reaches a credential token. `not_owner`
stays `execute`'s own code — never a `credential_refused` detail — and
resolves AFTER every token below.

**Ordinary (non-deposit) writes** pass three gates, in order, after the
actor resolves:

1. `nullify_not_retraction` — a `nullify` whose target link is
   credential-typed: retraction never edits the key table. On a CLAIMED
   board the token reaches only the owner of the target's home; any
   other caller falls through and answers plain `not_owner`,
   indistinguishable from the non-credential answer (an entitlement
   scope, not a second rule).
2. `mint_home_first` — MINT-FIRST: a `fork` or `version` by a principal
   whose account's space has never held a document. Mint the home first
   (`create_new_document`, which becomes the account's doc 1). Where
   these committed before, they now refuse.
3. The board-state gate, one arm per mode:
   * claimed — `signed_session_required` (the publish class): a
     bare-session op whose write lands in the PUBLISHED world. The one
     born-published class this build computes is the mechanical home
     mint — each account's doc 1; flagless mints resolve draft. So: an
     `insert`/`delete`/`copy`/`rearrange` whose `doc` is a published
     document the caller owns, a link write homed in one (`edit_link`
     reads `d_s`), or a flagless `version` of a published source. A
     foreign or unregistered home answers `execute`'s own code instead
     (`not_owner`, `*_not_registered`). Signed sessions, draft writes,
     bare reads, `delegate` and the home mint itself are unchanged.
   * unclaimed — `claim_first`: an unclaimed daemon admits only the
     ceremony's own shape — `delegate` from principal 0, a
     `create_new_document` into an account holding no documents, an
     `insert` into the caller's own doc 1 — from bare and signed
     sessions alike; every other write refuses. Reads are untouched.

**Credential deposits** — a write whose TYPE slot names a credential
type (§The claim ceremony and credentials) — run a stricter order:

* Ahead of any lock, the shape slots: `emit_not_make_link` (every
  credential-typed `emit`, unconditionally — the emit path's dedup
  could phantom-ack an act `key_set` never shows) and `resolved_from`
  (a credential `make_link` whose `from` or `to` is the V-spec form —
  deposit slots are address-form — and every credential-typed
  `edit_link`).
* Under the credential write lock, the identity fold's own verdict —
  a deposit the fold would record but never honor is refused up front
  with the fold's token: `malformed_shape`; `not_doc_one` (the home
  pin: a credential link homed in a document of its account other than
  doc 1); `no_holder`; `not_genesis_registry`; `not_holder_retirement`;
  `would_empty` (a retirement naming the whole enrolled set);
  `nothing_changed`; `already_claimed`; `claimant_keyless`;
  `claimant_not_top_level`; `unpublished` (unreachable on this daemon —
  v1 wires publication constant-true); and the payload joins
  `malformed_payload:<sub>` with `<sub>` one of `too_large`,
  `foreign_content`, `missing_value`, `not_utf8`, `bad_header`,
  `bad_line:<n>`, `duplicate_key:<n>`, `empty` (`<n>` a 1-based line
  number, the record header being line 1).
* Then the daemon's own slots, in order: `undecodable_key` (valid-hex
  key bytes that decode to no Ed25519 point can never sign — refused at
  enrollment rather than discovered at a handshake);
  `too_many_enrolled` (the enrolled-set cap, **16** — daemon policy,
  raisable without format consequence; the enroll arm only, the
  ceremony's genesis exempt); `anchor_session_required` (an anchor
  retirement, or a post-genesis anchor-flagged enrollment, requires a
  session an ANCHOR key of that account established — a bare session
  never satisfies it; genesis exempt); and the two board-state arms
  again — claimed: `signed_session_required` for ANY bare-session
  deposit, genesis included; unclaimed: `claim_first` for any deposit
  other than the ceremony's own genesis and claim.

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

### Identity reads

**`key_set`** — the credential table of `account`: who can sign for it,
now and historically. Principal-free like every read — NO session is
needed; the auth work deliberately preserves the no-session read — and
served on `/op-at` too, as of any committed position (the same
dispatcher; a historical world's identity table is rebuilt from the
deposits committed by then, under the reconstruction budget like every
historical answer). A non-account address rejects with the existing
code `not_an_account` (`reorder`); a keyless account answers empty
lists; an `id` is accepted and ignored, as on every read. → `key_set`.

```json
{"account":"1.0.1","op":"key_set"}
```

### Arrangement (document editing)

Ownership (v5.1): `insert`, `delete`, and `rearrange` require the session
principal to own `doc`; `copy` requires owning the **destination** `doc`
only — its source spans may read anyone's content (transclusion is
unrestricted). A non-owner gets `not_owner` (permanent) with the document
in `site.addr`. `version` is deliberately un-owner-gated: forking a
foreign document into your own account IS the sanctioned "propose a
change" path. Since v7 that sentence carries two qualifications, neither
an ownership gate: `mint_home_first` (a principal whose account holds no
documents must mint its home before `fork`/`version`) and, on a claimed
board, `signed_session_required` for a flagless `version` of a PUBLISHED
source from a bare session (§Credential refusals).

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

Credential deposits (v7): a `make_link` whose `ty` names a credential
type address (§The claim ceremony and credentials) is a credential
DEPOSIT and runs the credential write sequence. Its `from` and `to`
must be the address form (`resolved_from` otherwise); a
credential-typed `emit` is always `emit_not_make_link`; a
credential-typed `edit_link` is always `resolved_from`; and a `nullify`
targeting a credential link is `nullify_not_retraction` — retraction
never edits the key table (§Credential refusals for all four, and for
the entitlement scope on the last).

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
→ `ack_addr`. The example retires `1.0.1.0.2` under the shipped Retired
class at its reserved ghost tumbler `1.1.0.1.0.1.0.1.3` (§Reserved type
addresses in the changelog): Unary, so `to` is empty.

<!-- wire: request emit -->
```json
{"from":"1.0.1.0.2","home":"1.0.1.0.1","op":"emit","to":[],"ty":[{"start":"1.1.0.1.0.1.0.1.3","width":"0.0.0.0.0.0.0.0.1"}]}
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

Routed, not yet in the protocol: an I-ADDRESSED value read as of a
position — the home's mint frontier at N plus the values under it, a
fact no arrangement-addressed read composes (an address minted and
later un-arranged answers like one never minted). Named here because
this document owns it when it lands; its consumers are the mirror fold
and realm verification. No such op exists today.

## The commit stream

**`GET /events`** answers `200 Content-Type: text/event-stream` and never
ends on its own: it is the daemon's push channel for log movement, so
clients stop polling `/health`. No session is needed — like every read it
is principal-free — but the route is token-accepting (§Sessions): a dead
or unknown token presented here meets `Skepd-Session: closed` on the
stream's own head, written once, at open. On connect the daemon
immediately sends one event
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
Access-Control-Expose-Headers: Skepd-Session
Connection: close
Content-Type: text/event-stream
Cache-Control: no-cache

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
* `key` (v7) — the write's AUTH testimony: the 64-hex fingerprint of the
  enrolled key whose signed session committed it; `"bare"` for a
  bare-session write; `null` ONLY for lost metadata (a bare entry, or a
  record written before testimony existed) — never for a bare write, and
  never invented. Forward rule, pinned now: on a feed served by a daemon
  that did not itself commit the entry (a future mirror), the field is
  ABSENT rather than null — a consumer written to the three values must
  not treat absence as a protocol violation.
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

The examples below are produced by this flow on a fresh board, asserted
against live daemon bytes (the `time` values are illustrative — the one
normalized field). A fresh board's first five commits are the claim
ceremony's own (§A first board): positions 2, 3, 6, 9, 12 — the
delegate, the home mint, the record insert, the genesis link, the claim
link. The flow behind the examples then runs on that base, from bare
sessions (CLAIMED-PERMISSIVE, so every `key` reads `"bare"`):
`delegate` commits at position 14, the home mint at 15, a second —
private — document at 16 (the account's doc 1 is born published, where
bare writes are gated by design, so the flow's content goes to a draft
document), a two-byte `insert` at 21, `make_link` at 24. The feed past
the ceremony, `GET /changes?since=12`:

<!-- wire: changes feed -->
```json
{"changes":[{"at":14,"docs":[],"key":"bare","op":"delegate","time":1786838400000},{"at":15,"docs":["1.0.2.0.1"],"key":"bare","op":"create_new_document","time":1786838400012},{"at":16,"docs":["1.0.2.0.2"],"key":"bare","op":"create_new_document","time":1786838400021},{"at":21,"docs":["1.0.2.0.2"],"key":"bare","op":"insert","time":1786838400033},{"at":24,"docs":["1.0.2.0.2"],"key":"bare","op":"make_link","time":1786838400047}],"last":24,"more":false}
```

The first page of the same feed, `GET /changes?since=12&limit=2`:

<!-- wire: changes feed_page -->
```json
{"changes":[{"at":14,"docs":[],"key":"bare","op":"delegate","time":1786838400000},{"at":15,"docs":["1.0.2.0.1"],"key":"bare","op":"create_new_document","time":1786838400012}],"last":15,"more":true}
```

**Bare entries.** A position whose metadata the daemon never observed — a
data dir written before this feature existed, or a record lost to a crash
— still appears, reconstructed from the journal itself, with every
metadata field `null`. A pre-feature data dir holding three writes (a
delegate at 2, a mint at 3, an insert at 8 — written by the engine
directly, before any daemon), byte-exact:

<!-- wire: changes bare -->
```json
{"changes":[{"at":2,"docs":null,"key":null,"op":null,"time":null},{"at":3,"docs":null,"key":null,"op":null,"time":null},{"at":8,"docs":null,"key":null,"op":null,"time":null}],"last":8,"more":false}
```

Routed, not yet in the protocol: `delegate` entries carrying the minted
`new_prefix` and `new_id` (equivalently serving, a
principal-enumeration read as of a position). Today a `delegate` entry
carries `docs: []` and names neither, so the span from `delegate` to
the first signed session is resumable from client state only — no
board-side read ties a new account to its principal id. Reserved as a
later round's delta.

**Retention.** The feed's memory is the daemon's `commits.log` sidecar
plus what the journal can still reconstruct. When `since` reaches below
that — reclaimed or unreadable journal regions — the answer is the same
discipline as `/op-at`: `410 {"error": "history_reclaimed", "floor": F?}`,
`F` the oldest position that still has an entry. A malformed query
(missing `since`, a non-integer, an out-of-range `limit`, an unknown
parameter) is `400 {"error": "malformed_changes", "detail": …}`.

## The other endpoints

**`GET /health`** → `200` with `ok`, `log_position`, `head_time`, and —
since v7 — the `auth` object. Token-blind. `head_time` is the newest
recorded commit's wall-clock unix milliseconds (§The change feed's
timestamp scope: transport metadata) — `null` on a fresh world or when
the head position's record is bare. A claimed board configured with one
origin answers, illustratively:

```json
{"auth":{"claimant":"1.0.1","local_trust":true,"origins":["http://127.0.0.1:8642","http://[::1]:8642","http://localhost:8642","https://board.example"],"signed_origins":["https://board.example"]},"head_time":1786838400047,"log_position":24,"ok":true}
```

`auth.claimant` is the claiming account's address, `null` while
unclaimed; `auth.local_trust` echoes the flag; and TWO origin lists ride
side by side, each published VERBATIM from its own arm's rule so a
refused handshake is diagnosable from the list its arm actually
consulted: `origins` is the BARE arm's set (configured ∪ the three
loopback defaults, in every mode), `signed_origins` the SIGNED arm's
(configured alone once claimed; the bare set before) — the two differ
exactly on a claimed board. There is deliberately NO `mode` field:
derive the mode from the `(claimant, local_trust)` pair (§Identity).

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
deterministic world dump — format **`skep-world-dump v3`**, the banner
the code emits. (The v2→v3 renumber rode the ghost-tumbler genesis
rework of 2026-08-30, not the auth delta; its design-side record lands
as an AUTH RES entry — citation pending, deliberately not invented
here.) Byte-comparable across processes for run reconstruction: two
dumps of equal worlds are byte-equal. As built the dump carries NO
dedicated identity section: the identity table is DERIVED state — a
pure function of the credential deposits, which are ordinary links
already in the dump's links slice — so byte-equal dumps imply equal
identity tables, and `key_set` (not the dump) is the identity read
surface. `GET /dump?at=N` serves a historical position (§Reading
history). The route is token-accepting (the death signal rides it); the
dump itself is principal-free.

## A first board, end to end

A fresh board is UNCLAIMED, and an unclaimed daemon admits only the
opening below — every other write refuses `claim_first` (§Credential
refusals); reads are open throughout. The claim ceremony, entirely in
ordinary wire ops:

```
POST /session          {"principal": 0}                # bootstrap, bare
POST /op   (session)   {"op": "next_account_prefix", "parent": "1"}
POST /op   (session)   {"op": "delegate", "new_prefix": <that>, "new_id": 900}
POST /session          {"principal": 900}              # the owner, bare
POST /op   (session)   {"op": "create_new_document", "account": <account>}    # doc 1 — the home mint
```

Compose the enrollment record (§The claim ceremony and credentials) and
seat it in doc 1 as ONE composite value — one position, so one address
names the whole record:

```
POST /op   (session)   {"op": "insert", "doc": <doc 1>, "at": {"subspace": "1", "ordinal": "1"},
                        "values": [{"atom": "skep-enroll v1\nanchor ed25519 <64 hex> paper\ned25519 <64 hex> notebook\n"}]}
```

Deposit it — the genesis enrollment, then (from a signed session,
proving custody before the flip) the claim:

```
POST /op   (session)   {"op": "make_link", "home": <doc 1>,
                        "from": {"addrs": ["<doc 1>.0.1.1"]},           # the record atom's position
                        "to":   {"addrs": ["<account>"]},
                        "ty":   {"addrs": ["1.1.0.1.0.1.0.3.1"]}}       # T_enroll
GET  /challenge?principal=900
POST /session          {"principal": 900, "nonce": <that>, "origin": <a configured origin>, "sig": <128 hex>}
POST /op   (signed)    {"op": "make_link", "home": <doc 1>,
                        "from": {"addrs": ["<account>"]}, "to": {"addrs": []},
                        "ty":   {"addrs": ["1.1.0.1.0.1.0.3.3"]}}       # T_claim — the board flips claimed
```

Then ordinary work — remembering that doc 1 is born published, so on
the claimed board its content takes a signed session; a bare session
(CLAIMED-PERMISSIVE) writes drafts:

```
POST /op   (session)   {"op": "create_new_document", "account": <account>}    # a draft document
POST /op   (session)   {"op": "insert", "doc": <doc>, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}
POST /op               {"op": "retrieve_v", "specs": [{"doc": <doc>, "span": {"start": "1.1", "width": "0.5"}}]}
```

The insert seats five single-byte values at positions 1..=5 (§Content
values), which is exactly why the retrieve's width is `"0.5"` and the
delivery is `[{"content": "hello"}]`.

## Changelog of wire decisions

v7 (the AUTH surface — sessions, credentials, the write gates; the AUTH
build of 2026-08-30, documented as built):

* Session tokens are 128-bit CSPRNG values, **32 lowercase hex**, strict
  admission — v1's `prefix.suffix` shape is refused, and an unparseable
  header value IS no token. `POST /session` accepts exactly two body
  forms — bare `{"principal"}` and signed
  `{"principal","nonce","origin","sig"}`, strict bytes — anything else
  `400 malformed_session_request`, and a syntax 400 never burns a
  nonce. New `GET /challenge?principal=N` →
  `{"nonce","principal","ttl_ms":60000}`: a 64-lowercase-hex
  single-use nonce (burned on verification whether or not it
  validates), 60 s TTL, 4096 live cap, issued for any principal. The
  signed bytes: `"skep-session-v1"` ‖ be32-framed origin · nonce ·
  principal-decimal, over the body's own strings; verification tries
  every enrolled key in fingerprint order (Ed25519 strict). EVERY
  handshake failure — bare and signed alike — is the one
  `401 {"error":"session_rejected"}`, no detail by design. New
  `POST /session/close` → idempotent `204`. Sessions now end before
  restart — close, key retirement, mode (a bare entry presented under
  ENFORCING) — evicted lazily at presentation; no TTL, no cap.
* The death signal: `Skepd-Session: closed` rides every response whose
  presented token is unknown or whose entry died — on `/op`, `/op-at`,
  `/changes`, `/dump`, `/session/close`, and `/events` (checked before
  the stream opens; written once on its head). A live entry refused for
  one request (bare, foreign `Origin`) gets no header — nothing died.
  `Access-Control-Expose-Headers: Skepd-Session` now rides EVERY
  response so a page can read the signal; the preflight covers the
  session endpoints (every known path already answered `OPTIONS`).
* Identity is a MODE, not the whole model: UNCLAIMED /
  CLAIMED-PERMISSIVE / ENFORCING, derived from `/health`'s new `auth`
  object — `{"claimant","local_trust","origins","signed_origins"}`,
  the TWO origin lists published verbatim per arm, deliberately no
  `mode` field. The bare bind is honored on loopback outside ENFORCING,
  and only when the request's `Origin` header (if present) is in the
  bare set. The claim-time drop: `signed_origins` = the configured
  origins alone once claimed — a board claimed with no `--origin`
  refuses every signed session, warned at startup and at the flip.
* The claim ceremony rides the ordinary surface: credential deposits
  are `make_link`s typed by three reserved ghost tumblers
  (`1.1.0.1.0.1.0.3.{1,2,3}` — enroll · retire · claim), address-form
  slots only, homed in doc 1, their payloads (`skep-enroll v1` /
  `skep-retire v1` records, 64 KiB cap) plain doc-1 content the `from`
  names. Genesis seeds the key set; the claim flips the board; first
  claim wins.
* New rejection family: `credential_refused`, always `permanent`,
  `detail` a single machine token (the code:detail convention —
  clients key on the token). The vocabulary and its order as built
  (§Credential refusals): the shape slots `emit_not_make_link` and
  `resolved_from`; the fold's inert tokens — `not_doc_one` (RES-17,
  the home pin) among them — and the `malformed_payload:<sub>` joins;
  `undecodable_key`; `too_many_enrolled` (the enrolled-set cap, 16 —
  daemon policy, RES-57); `anchor_session_required`; MINT-FIRST's
  `mint_home_first` (`fork`/`version` before the home mint — where
  they committed before, they now refuse); the publish class
  `signed_session_required` (RES-26: a bare-session write landing in
  the published world — today an account's doc 1 — refuses on a
  claimed board; credential deposits from bare sessions refuse there
  uniformly, genesis included); and pre-claim `claim_first`
  (RES-27/27a: an unclaimed daemon admits only the ceremony's shape).
  `unauthenticated` stays slot 0 ahead of them all; `not_owner` stays
  `execute`'s own and resolves after every token; RES-32 scopes
  `nullify_not_retraction` on a claimed board to the target-home owner
  (anyone else reads plain `not_owner`). v5.1's "`version` is
  deliberately ungated" is qualified twice (MINT-FIRST; the publish
  class) — un-OWNER-gated it remains.
* New read `key_set` → new response shape `key_set`: an account's
  enrolled and retired credentials, fingerprint order, anchor flags as
  enrolled; `not_an_account` (reorder) on a non-account; empty lists
  on a keyless account. Principal-free — the no-session read the auth
  work deliberately preserves — and served identically on `/op-at`
  (the identity table of a historical world is rebuilt from its
  deposits).
* `/changes` entries gain `key` — the committing session's testimony:
  an enrolled-key fingerprint, `"bare"` for a bare-session write,
  `null` only for lost metadata (never for a bare write, never
  invented); pinned ABSENT (not null) on a feed whose serving daemon
  did not commit the entry (a future mirror's case). The feed examples
  are re-pinned onto a claimed board's positions — the ceremony's five
  commits occupy 2–12 on a fresh board.
* The dump: the code emits `skep-world-dump v3` — docs and code agree;
  the v2→v3 renumber rode the ghost-tumbler rework (2026-08-30), and
  its design-side record lands as an AUTH RES entry (citation
  pending). As built the dump gains NO identity section: the identity
  table is derived state, a pure function of deposits the links slice
  already carries — the sealed spec's per-account dump section
  (AUTH-6.28) rides to the engine round with the build report, and
  `key_set` is the identity read surface meanwhile.
* CORS `*` reaffirmed post-auth — v4's "revisited when authentication
  lands" is resolved: reads are guest-free, the signed origin is bound
  inside the signature, the bare bind is origin-fenced daemon-side,
  the token is unguessable; a narrower ACAO was weighed and declined.

v6.2 (reserved type addresses are in-docuverse ghost tumblers; the genesis
configuration is retired — the two owner rulings of 2026-08-26, applied):

* The five reserved type addresses are GHOST TUMBLERS — compiled format
  constants at `1.1.0.1.0.1.0.1.x` for x = 1..5 (pred_def, pred_stable,
  retired, supersedes, retraction): content positions 1–5 of doc 1 of
  account 1 (the node operator's, by the claim-ceremony convention) of
  the registry node `1.1`. T4-valid, in-docuverse names at which nothing
  exists and nothing is ever minted — the allocator's compiled
  ghost-region floor is what makes "a reserved name can never equal an
  allocated address" true, replacing the abolished out-of-tree
  `9.0.9.0.9.0.9.k` namespace (no address space exists outside the
  docuverse). A type is a number: the daemon's semantics for the five
  shipped classes are compiled in; every other type means what its
  interpreting client says it means, and no document is semantically
  authoritative for a type.
* `GenesisConfig` and the app-declared types seam (`decls`) are RETIRED:
  the values are the format, not a sealed configuration, so the
  byte-identical-genesis caller contract and the reopened-under-
  different-config refusals are gone; the journal and checkpoint format
  stamps (`SKJ2`/`SKC2`) name the format that wrote them. The
  architecture's extension path is predicates (pdef content), not new
  compiled substrate classes.
* FORMAT CONSEQUENCE, accepted by the owner in the ruling (pre-release):
  journals and checkpoints written under the 9-space configuration DO
  NOT REOPEN under this format.

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
  "propose a change" path. (Since qualified twice at v7 — MINT-FIRST and
  the publish class; the OWNER gate it never had, it still has not.)
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
  (Superseded at v7: strict 32-hex tokens, a close endpoint, sessions
  ending before restart, the death signal.)
* Identity: local trust, client-named principals, loopback bind only.
  (Local trust became a MODE at v7; the loopback bind stands.)
* `principal_prefix`'s argument is `"principal"` on the wire (envelope
  `"id"` is the idempotency key).
* Four-set slot constraints: `"any"` / `"empty"` / span array; `[]` reads
  as `"empty"`.
* Cursor: `null` or absent = start; the cursor is the whole continuation.
