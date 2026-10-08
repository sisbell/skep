# skepd wire protocol

The HTTP/JSON contract between `skepd` and its clients. This document is
written for a client author who will never read the Rust; it is also
executable documentation — every fenced JSON example annotated with a
`<!-- wire: … -->` marker is asserted byte-for-byte-canonically by
`skep/crates/skepd/tests/it/wire_doc.rs`, so an example that drifts from the
daemon fails the build. (Two exceptions: the commit-stream event example is
asserted structurally — its framing, not its illustrative position — and
the change-feed examples are asserted against live daemon bytes in
`tests/it/changes.rs` with the `time` values normalized, the one field a live
daemon cannot reproduce; the bare-entry example is byte-exact.) The
keygen-from-seed rule (§The claim ceremony and credentials) — its formula,
recomputed from RFC 5869, and its two vectors — is asserted against the
KDF and each half's keygen by
`skep/crates/skep-signature/tests/it/golden.rs`.

The wire is in DEVELOPMENT: this document is the contract as it stands at
HEAD, and no compatibility with an earlier reading is promised.
Versioning begins at the first release.

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
| `GET /chain`     | The commit chain's value as of a committed position, `?at=N` (§Reading history). |
| `GET /events`    | Server-sent stream of committed positions (§The commit stream). |
| `GET /changes`   | The pull delta feed of committed writes, masked at the presented token's class (§The change feed). |
| `POST /blob/upload` | Create a blob upload — the PUT — declaring its length, with or without its first bytes; `GET` on the same path is the deposit read (§Media). |
| `PATCH /blob/upload/<id>` | Resume an upload from its offset; `GET` its progress; `DELETE` ends it (§Media). |
| `GET /blob?i=<address>` | THE FETCH — serve a picture's whole file by the I-address of its cell, gated as the read is; `HEAD` for the head alone (§Media). |
| `GET /`          | The embedded authoring client, one HTML file (only in `client` builds — the feature is default-off). |
| `GET /dump`      | Deterministic world dump; `?at=N` for a committed position (only in `observe` builds). |

There are no other routes; every known path additionally answers `OPTIONS`
— the CORS preflight (§Cross-origin access): the common one names `GET,
POST, OPTIONS`, the blob upload's family names its own four methods, and the
blob fetch `/blob` names its own two (`GET, HEAD, OPTIONS`). The daemon
listens on **127.0.0.1 only**.

### Transport

One request per connection: every response carries `Connection: close`, so
a client opens a fresh connection per call. `GET /events` is the one
long-lived response — a single unbounded body, ended by the daemon (clean
close) at shutdown. `GET /blob?i=` is the one response the daemon STREAMS —
a whole file written chunk by chunk, its `Content-Length` the file's size —
and the one it may end by a RESET (TCP `SO_LINGER` zero) short of that
length rather than a clean close: a stream whose requester is re-resolved
away mid-transfer, or whose idle or transfer bound fires, is cut so no
client reads a truncated file as the whole (§Media, THE FETCH). HTTP/1.0 and 1.1 are accepted; request bodies ride
with `Content-Length` (absent means empty; `Transfer-Encoding` is refused
with `400 malformed_http`); `Expect: 100-continue` is honored. Bodies are
capped per route — **8 MiB** on the frame routes (`/op`, `/op-at`),
**64 MiB** on the blob upload's two body-carrying methods (`POST
/blob/upload`, `PATCH /blob/upload/<id>` — the per-file cap, a body that
STREAMS to disk one 64 KiB chunk at a time and never sits whole in memory,
§Media), **16 KiB** everywhere else, the family's other methods included
(the session bodies ride the small cap: a signed body under the production
key kind is about 7 KB, its `sig` the hybrid blob in hex — §Sessions): a
larger declared `Content-Length` is refused with `413 payload_too_large`
before any body byte is read. A streamed body is bounded in time by an
idle bound of 30 s renewed by any byte and a transfer bound of 10 minutes;
a connection cut by either keeps its upload at the bytes it had received
(§Media).

### Identity — modes, principals, credentials

Identity has two layers. A **principal** (a small integer) is the account
system's actor: principal `0` is the bootstrap principal, which owns the
root of the namespace; any other principal must first be minted with a
`delegate` operation before its writes will be accepted by the stores.
Each distinct principal is its own account, so every write is attributed.
A **credential** is a public key enrolled for an account, of one of the
TWO `ALGS` kinds §The claim ceremony and credentials lists — the HYBRID
keys `mldsa65-ed25519` (ML-DSA-65 + Ed25519, 1,984 raw bytes; the
production kind) and `fndsa512-preview-ed25519` (FN-DSA-512 + Ed25519,
929 raw bytes; a preview) — each ONE key over one concatenated raw
value, the post-quantum key then the Ed25519 key. There is no classical
`ed25519` kind: every board is hybrid from its genesis, and tag `2`'s
token `fndsa512-ed25519` is reserved with no kind yet. Keys ride the wire
as lowercase hex of the raw key (3,968 and 1,858 hex), and a key is named
by its **fingerprint** — 64 lowercase hex of `SHA-256("skep-key-v1" ‖
be32-framed alg token ‖ be32-framed raw key)` — the flat form every
identity surface below emits (grouping is a client display convention).

The board is always in exactly one of three MODES, derived from two facts
`GET /health` publishes (`auth.claimant` and `auth.local_trust` — there
is deliberately no `mode` field; clients derive it from the pair):

* **UNCLAIMED** — no claimant yet. Bare sessions bind on loopback, and
  the write surface admits only the claim ceremony's own opening shape —
  everything else refuses `claim_first`, and the claim itself refuses
  `claim_residue` over a second top-level principal (§Credential
  refusals). Reads are open throughout.
* **CLAIMED-PERMISSIVE** — claimed, `--local-trust` on (the default). A
  bare session still binds on loopback: any local party may write as any
  principal. That is the default's disclosed cost, and the daemon warns
  about it at startup and again at the claim flip. Credential deposits
  and bare writes landing in the published world still refuse
  (`signed_session_required`).
* **ENFORCING** — claimed, `--local-trust` off. Bare sessions are
  refused; only signed sessions write.

The signed session is cryptographic identity — a challenge signed by a
key enrolled for the account the session authenticates against
(§Sessions). The bare session is **local trust**, a mode rather than the
whole model; the daemon binds **127.0.0.1 only**.

**Ownership**: attribution gates. A write into a document's
space — its content arrangement or its link subspace — is accepted only
from the document's owner: the principal whose account is **exactly** the
document's account (the nearest registered account prefix of its address —
never mere prefix containment, so a parent account does not own a
sub-delegated account's documents and a sub-account does not own its
parent's). Anything else is the `not_owner` rejection with the failing
address in `site.addr`. Reads answer through the read predicate (§The read
predicate). The sanctioned way to
build on someone else's document is `version` (fork it into your own
account, content shared) and `copy` (transclude their content into your own
document) — proposing a change is forking, never editing in place.

### The read predicate

**Reads are class-gated**: every read answers through ONE predicate —
`readable(doc, principal) =
published(doc) ∨ principal ∈ owner_subtree(doc) ∨ grant_exists(doc,
principal)` — evaluated against the one committed snapshot the read is
answered from. The reader classes: the GUEST (no token, or a dead one)
sees published documents alone; a session principal additionally sees
every document of its own account, of the accounts above it and of the
accounts beneath it — the subtree runs BOTH WAYS (PUB-1.32), two prefix
compares, so a sub-account reads its parent account's drafts and a
parent account reads its sub-accounts' drafts, each transitively; a read
and never ownership (§Identity: a parent account still owns none of a
sub-account's documents); org members are siblings to each other and
read nothing of each other's, and the node-tier principal 0 — seated at
the node, above every account — is excluded by name and reads no draft
by subtree, by grant alone; a GRANT-HOLDER sees
what a grant record opens to it. A grant is an ordinary `make_link` in
the owner's doc 1: `ty` the grants class `1.1.0.1.0.1.0.3.90`, `from`
the content-prefix (a document, or an account — covering every document
under it, those minted later included), `to` the grantee account, or
empty for EVERY bound principal. A grant never opens anything to the
guest. A later grant whose `from` names an earlier grant's own address
revokes it, and a record whose `from` is anything else but a document or
an account — a grant already revoked, a revoking record, a node, a
version, any other address — is neither a grant nor a revocation: it
opens nothing and lifts no revocation. A grant homed anywhere but the
issuer's own doc 1, or issued by anyone but the document's owner, opens
nothing. And a grant opens only where the state it REPLACES is its
KEY's current one (PUB-5.15 (iv)): the key is the issuer, the
content-prefix and the grantee; a grant written with no `replaces`
member names the EMPTY state and opens only where no record of that key
has ever stood — no grant, live or revoked, and no revocation, a
retracted one still counting — and a re-share, written with `replaces`
naming the revocation it follows (§Links, `make_link`), opens only where
that revocation is the key's latest record. So a share REPLAYED after
its revocation — the same request re-sent, signature and all — opens
nothing, and neither does the duplicate of a grant that stands, a
re-share naming a revocation a later one has passed, or the second of two
re-shares naming one revocation: each is deposited and acknowledged, and
honored for nothing. The grant a revocation withdrew is never re-opened;
a re-share is a fresh grant beside it.

How a masked read answers:

* **A document argument you may not read is the `withheld` rejection**
  (§Rejections): `disposition` reorder, `site.addr` the document, no
  `detail`, ever. Every document argument of a read is consulted, in
  declaration order, before the read runs. An UNREGISTERED address is
  never masked — it answers the store's own `doc_not_registered` — so a
  withheld answer is only ever a registered private document.
* **A result set is filtered** at your class: `find_links_v`,
  `find_links_ftt`, `count_v`, `count_ftt`, `window_v`, `window_ftt`,
  `retrieve_endsets`, `find_docs_containing` and `delete_orphans` answer
  the rows whose home you may read — the census counts the filtered set,
  the page turns over it.
* **A link address you may not read is absent**: `read_link` answers
  `link: null`, `follow_link` answers `{"err": "invalid"}`, `project` and
  `discoverable_from` answer `not_a_link` — exactly as a never-deposited
  address, never a distinct signal. Where a read carries both a document
  and a link address (`project`, `discoverable_from`), the document is
  consulted FIRST.
* **A delivery masks per run**: a published arrangement that windows a
  draft you may not read delivers the `withheld` item at that run's own
  position (§Value encodings); extents are never shrunk.
* The namespace reads (`next_account_prefix`, `principal_prefix`,
  `effective_owner`) are exempt — registry data, served to every class
  (AUTH-6.37) — and so is `key_set` (§Identity reads), which reads
  credential records alone, born published by law: PUB-6.50's rule, a
  surface exempt iff its answer is invariant across classes, and these
  four answer a guest and a bound principal byte-identically.
  `universal_grants` (§Grants) is NOT exempt and is no class scan either:
  it names no document and walks no link store, and it is gated by class
  at the door — every bound principal is answered the same rows, the
  guest `rows: []`, an answer and never a rejection (PUB-8.47,
  PUB-5.109). The lineage reads
  (`in_claims`, `out_claims`) are NOT: each takes the result-set filter
  at the claim's HOME (PUB-6.13) — a claim homed in a document you may
  not read is absent from the answer; `y`/`x` is a filter value, never
  a consulted address, and a shown claim's `old`/`new` are the addresses
  it names, as recorded.
* **The change feed is masked per entry** (§The change feed): an
  entry every one of whose `docs` you may not read is OMITTED from your
  page, and a shown entry's `docs` are REDUCED to the ones you may read;
  `limit`, `last` and `more` are computed over what you see. `/events` is
  untouched — positions are class-invariant.

The two publication reads take the consult too:
`doc_metadata`'s `doc` and `edition_claims`'s `target` are each a
document argument — unreadable is `withheld`, unregistered is
`doc_not_registered` — and `edition_claims` additionally filters its
result set at your class, dropping every claim whose HOME (the edition)
you may not read, so a draft edition's claim is invisible to a stranger
and listed for its owner (PUB-6.13).

The same predicate answers `/op-at` (against the HEAD's sets, §Reading
history) and the source gate of `publish` (§The publish shot and
head-float).

**Writes that READ a source take the same predicate** (PUB-6.23,
PUB-6.24): `copy`'s `specs[].source`, `version`'s
`d_src`, and every V-SPEC slot of `make_link` and of `edit_link`'s
successor are consulted at the write door, pre-dispatch, before any
content of the source is read. A source the session principal may not
read is the `withheld` rejection — `reorder`, `site.addr` the FIRST
unreadable source in declared order (`copy`'s specs by index; the link
writes' slots `from`, `to`, `ty`, specs by index within a slot), no
`detail`, ever. The gate is per ARGUMENT document and delivery stays per
ORIGIN: a principal MAY copy, fork or link from a PUBLIC document over runs
whose origin is a draft it cannot read, and the minted document holds
those I-positions withheld to it exactly as the source does. ADDRESS-FORM
slots are ungated — an address is not secret and needs no read to write.
`fork` reads no source and takes no gate. The consult stands BEHIND the
destination's `not_owner`, MINT-FIRST, the publish-class gate
(§Credential refusals) and the model's in-place refusal
(PUB-6.36 slot 5 ahead of slot 6): a `copy` from a source you may not
read INTO a published destination you own answers `published_target`,
the door pre-evaluating the destination's publication state, in the
store's own bytes, before it consults the source — a session refused the
write is never told whether it may read the source (the store's own
refusal stands behind the door's). The consult stands ahead of the
store's read of the source; registration stands ahead of it too — an
unregistered source answers the
store's own `source_not_registered`, never `withheld`. The link-address
rule reaches the write side too:
`edit_link`'s `original` and `assert_sup`'s `old`/`new` homed in a
document you may not read answer the op's own `original_not_resident` /
`endpoint_not_resident` — exactly as for a never-deposited address, never
a `withheld` that confirms a draft-homed link exists (§Links (writes)).
`nullify`'s `target` takes no such rule; its ω-first order stands.

**The serving bound** (PUB-8.43): the wire serves the subtree clause,
the read-surface sweep above, the routed write refusals
(`published_target` and its two siblings), the write side's source
consult, the audit-view edition-claim lookup
(`edition_claims`, PUB-8.46) and the doc-metadata read (`doc_metadata`,
PUB-8.12) the client's own admission test needs. That interval is
CLOSED.

### Cross-origin access — a scope decision

Every response — every status, every endpoint, rejections and transport
errors included — carries `Access-Control-Allow-Origin: *` and
`Access-Control-Expose-Headers: Skepd-Session` (the death signal below
is not a CORS-safelisted response header; without the exposure a page on
a configured non-loopback origin could never read it). The
CLASS-VARYING routes carry two more:
`Cache-Control: no-store` and `Vary: Skepd-Session` ride every answer of
`POST /op`, `POST /op-at`, `GET /changes` and `GET /dump`, the blob
upload's family and the blob fetch `GET /blob?i=` — each a function of the
presented token's class and so neither stored nor served to another
requester. The fetch's admitted answer carries two more still, inert ones
over the bytes it serves: `X-Content-Type-Options: nosniff`, so no browser
reads a type off bytes the daemon declared none for, and
`Content-Security-Policy: sandbox`, so a file navigated to directly runs
nothing and reaches nothing of the daemon's origin (§Media, THE FETCH).
`GET /health` is class-invariant and carries neither of the varying pair;
`GET /events` carries its own `Cache-Control:
no-cache` (§The commit stream). `OPTIONS` on any known path — the
session endpoints included — answers the preflight:

```
OPTIONS /op
→ 204
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Skepd-Session
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Skepd-Session
Access-Control-Max-Age: 86400
```

(`OPTIONS` on an unknown path is the ordinary 404.) The `*` is
deliberate, authentication notwithstanding. Reads are guest-free, and
neither credential is browser-ambient — the signed session binds its
origin inside the signature (no cookies; §Sessions), the bare bind — the
one ambient credential — is refused server-side when the request's
`Origin` header is not one the bare origin set answers for, and the
session token is 128 bits of CSPRNG output a foreign page cannot guess.
A narrower ACAO is declined: the foreign page's POST is fenced by the
daemon, not by what the browser lets it read back, and narrowing would
break local pages that only read.

### Sessions

The token is **32 lowercase hex** — 128 bits of fresh OS-CSPRNG output
minted per session open, never derived from process state. Admission is
strict: a presented header value that is not exactly 32 lowercase hex IS
no token — the request runs as a guest, nothing is closed, no signal is
sent. (A `prefix.suffix` token is refused.) Send it on
subsequent calls as the header:

```
Skepd-Session: 9f3a6c21d4b8e07a5c1b2d4e6f708192
```

**`POST /session`** accepts exactly three body forms. Anything else — an
unknown field, a missing member of the signed triple, a malformed value,
a `scope` that is not exactly `"content"` or that rides a bare body — is
`400 malformed_session_request` with a `detail`, and a 400 never spends a
nonce: a syntax fault costs no re-challenge.

*Bare* — `{"principal": 2}`. Honored only when ALL
of: the board is not ENFORCING (§Identity); the TCP peer is loopback;
and the request's `Origin` header, when present, parses as a canonical
origin in the **bare origin set** (§The claim ceremony and credentials;
`Origin: null` parses to nothing and refuses). Refusal is the one 401
below. A bare body carries no `scope`.

*Signed* — `{"principal": 2, "nonce": "<64 hex>", "origin":
"<origin>", "sig": "<6746 or 1460 hex>"}` — verified in every mode,
UNCLAIMED included. The fields are strict bytes: `origin` must arrive
already canonical (lowercase `scheme://host[:port]`, no path, no
trailing slash, the scheme's default port omitted), `nonce` is 64
LOWERCASE hex, and `sig` is THE HYBRID SIGNATURE BLOB in hex (case-free
— it is decoded, never framed): the post-quantum signature then the
Ed25519 signature, both over the signed bytes below, at exactly ONE of
the two key kinds' widths — **6,746 hex (3,373 bytes)** for an
`mldsa65-ed25519` key, **1,460 hex (730 bytes)** for an
`fndsa512-preview-ed25519` key. The width is the syntax check alone: a
`sig` of any other width — the 128 hex of a bare Ed25519 signature
included — is the 400 above with a `detail`, and the nonce survives.
The body carries NO `alg` member and names no key. The daemon
canonicalizes nothing on this path.

*Scoped signed* — `{"principal": 2, "nonce": "<64 hex>", "origin":
"<origin>", "scope": "content", "sig": "<6746 or 1460 hex>"}` — the signed form
carrying one more strict field. `scope` is OPTIONAL on the signed body
and takes exactly ONE value, the JSON string `"content"`: no other
value, no other type, no case variant, and no `full` spelling — a signed
body WITHOUT it is a FULL session, the form above byte for byte. It
opens a **content-scoped session**: a signed session of its principal
that reads, holds its draft visibility, writes content, publishes,
grants and closes exactly as a full session does, and CANNOT deposit,
retire or claim a credential — every credential-typed deposit from it
answers `credential_refused` with `content_session` (§Credential
refusals), whatever key opened it, an anchor key included. The scope is
the SIGNER's own declaration, inside the signed bytes (below), set once
at the opening and held for the session's life: the success answer does
not echo it (a client knows the scope it asked for), it is in no record,
and `GET /health` publishes nothing of it. A daemon that predates the
field answers a scoped body the 400 above, so a client asking for the
limit is never silently opened full.

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

The signed bytes are VERSIONED, never extended in place. An UNSCOPED
body signs the v1 layout

```
"skep-session-v1" ‖ be32(|origin|)‖origin ‖ be32(|nonce|)‖nonce ‖ be32(|principal|)‖principal
```

and a SCOPED body the v2 layout — the same three fields, then the scope:

```
"skep-session-v2" ‖ be32(|origin|)‖origin ‖ be32(|nonce|)‖nonce ‖ be32(|principal|)‖principal ‖ be32(|scope|)‖scope
```

each over the body's OWN strings — `principal` as shortest ASCII decimal,
`scope` the body's own `content` bytes, `be32` the 4-byte big-endian byte
length. The daemon verifies a scoped body under the v2 bytes ONLY and an
unscoped body under the v1 bytes ONLY: the tag names the grammar, so a v1
signature never opens a scoped session and a v2 signature never opens an
unscoped one — either is a signature failure, the one 401 below, its
nonce spent. (The scope sits INSIDE the signed bytes because a limit the
signer did not sign could be lifted on the path by dropping the field.)
The v2 layout binds the same signers as v1. Under EITHER name the
signature is the hybrid blob: BOTH halves of the key sign these same
bytes — the post-quantum half, then the Ed25519 half — and no half opens
a session alone; there is no `skep-session-v3` or `-v4`. Sign with a
private key whose public key is enrolled for the account that
principal's session
AUTHENTICATES AGAINST: principal `0` signs with the CLAIMANT account's
keys (none exist while unclaimed); every other principal with its own
account's — or, where its own account holds NO enrolled key, with the
keys of the NEAREST ACCOUNT ABOVE it that does (an unseeded sub-account
opens against its holder's set, at every depth, until a genesis hands it
away; `key_set` still answers such an account its own, empty lists —
read it at the account, then at each account above, and take the first
that is not empty). Verification order: the origin must be in the
**signed origin set**; the nonce burns (unknown, expired,
wrong-principal and reused all die here, and the entry is gone either
way); the principal must name an account; **the blocked-prefix test** —
the daemon's operator may supply a list of blocked prefixes, and a
principal whose OWN account sits at or under one is refused here, its
nonce spent, BEFORE any key set is read or signature verified (the 403
below); the authenticating account's key set must be non-empty; then
every enrolled key is tried in fingerprint order, EACH UNDER ITS OWN
KIND — both halves of the blob verified over the signed bytes, the
Ed25519 half by strict verification, either failing failing; a blob
whose width is not that kind's simply fails under it — no cutoff, ever.
A well-formed blob no enrolled key verifies is the one 401 below.

**Every handshake failure OF THE CREDENTIAL — bare and signed alike —
answers the ONE auth transport error**, permanent, byte-identical across
causes, carrying no detail by design:

```
→ 401
{"error":"session_rejected"}
```

**The one exception, by status.** A signed body naming a principal whose
account sits at or under a BLOCKED PREFIX answers

```
→ 403
{"error":"prefix_blocked","record":"1.0.1.0.7.1"}
```

— never the 401, which is every failure of the credential: this party's
credential is not read. It is refused for what it is — an account under
a prefix the board's operator has listed — on public facts, and `record`
is the one datum the answer carries: the version address of the takedown
record the covering entry cites (the LONGEST covering prefix's, where
more than one covers), in the registry's global form, so a client reads
the ground at the board that homes it. The test is of the session's OWN
account — never of the account whose keys open it — so a prefix over
`X.1` covers a session as `X.1` and never reaches one as `X`. The 403 is
permanent until the operator LIFTS the entry: the nonce is spent and no
re-challenge is owed, and a garbage `sig` answers the same 403, the
signature never being reached. The list is the operator's configuration,
supplied at every start and re-issued while the daemon runs; it is in no
record and `/health` publishes nothing of it. An entry that would cover
the operator's own account — or, where the operator's account is
off-board (not under the node prefix the daemon was launched with,
`--node-prefix` in §The claim ceremony and credentials; with none
supplied every operator reads as this board's own and the test is off),
the account that writes this board's bindings — is ignored: the block
never reaches the hand that lifts it. The bare form is not
tested at the handshake; a bare session under a listed prefix dies at
its first presentation (below).

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

* **Sessions can end before restart** — six ways: `POST
  /session/close`; a daemon restart (every token dies; a stale token
  then reads as unknown); **retirement** — a signed session dies when
  its establishing key leaves the enrolled set of the account it
  authenticated against; **a genesis** — a session opened against an
  account ABOVE its own (its own account holding no key) dies when the
  account it acts as is seeded, or any account between it and the one
  whose set it authenticated against, the giver's own sessions
  untouched; **a block** — a session, signed or bare, dies when the
  operator re-issues the blocked-prefix list with an entry covering its
  own account (a LIFT resurrects nothing: it admits the next handshake);
  and **mode** — a bare session's entry dies when the board is ENFORCING
  at presentation. Dead entries are evicted lazily, at the next
  presentation. There is no session TTL and no session cap.
* **The death signal.** When a token-accepting route is presented an
  UNKNOWN token, or a token whose entry is dead, the daemon closes the
  binding and the response carries the header `Skepd-Session: closed`
  — a read presenting a dead token is never silently a guest read. The
  token-accepting routes: `POST /op`, `POST /op-at`, `GET /changes`,
  `GET /dump`, `POST /session/close`, and `GET /events` — checked
  before the stream opens, the header written once on the stream head.
  `GET /health`, `GET /chain`, `GET /challenge`, `POST /session` and
  `GET /` are token-blind.
* **Refused-for-this-request is not death.** A LIVE bare session
  presented from a request whose `Origin` header falls outside the bare
  set (or from a non-loopback peer) runs that one request as a guest:
  the entry lives untouched and no header is sent.
* A request with **no token** (or an unparseable one) still gets a full
  answer: read operations run at GUEST class — a published document
  answers normally, a private draft is the `withheld` rejection (§The
  read predicate); write operations are rejected with code
  `unauthenticated` (permanent) — still the first gate in the write
  order, ahead of every credential token (§Credential refusals). That
  rejection is your signal to (re)open a session.
* The signal is additive: reads and writes are otherwise unchanged.

### The claim ceremony and credentials

Credential state is written THROUGH the ordinary link surface — no
write op of its own exists. A **credential deposit** is a `make_link` whose type
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
doc 1 refuses `not_doc_one`. The deposit class the insert door tests a
declared deposit's class type against holds enroll and retire beside
the registry's binding and endpoint — four members, stated once at
§Registry under §Operations, where the registry's own record grade is.

The records themselves are plain content. Write the record's bytes into
the home document first — the convention is ONE composite atom, so one
address names the whole record — then deposit a link whose `from` names
those positions (endset order, bytes concatenated; every named position
must be in the home's own space and occupied). A record is capped at
128 KiB and is ONE JSON OBJECT, admitted only in its canonical encoding:

```
{"type":"skep-enroll","keys":[{"alg":"mldsa65-ed25519","key":"<3968 hex public key>","anchor":true,"label":"<label>"},{"alg":"mldsa65-ed25519","key":"<3968 hex public key>","anchor":false}]}
```

```
{"type":"skep-retire","fingerprints":["<64 hex fingerprint>"]}
```

`type` is the record kind, byte-exact and keyed to the link's type slot;
`keys` (or `fingerprints`) is a non-empty array in the record's own
order; each key entry is `{alg, key, anchor, label?}` in that member
order — `anchor` a REQUIRED boolean marking an anchor key (the flag is
fixed for the fingerprint's lifetime), `label` OPTIONAL (present only
where a label exists, never empty, never containing a newline, and at
most 128 bytes of UTF-8, counted in bytes — a longer label is
`bad_record`, as any other grammar fault is). The
optional `sig` member, canonically LAST, is THE RECORD'S OWN SIGNATURE
(signed ops; the record grade, below): IGNORED by the fold whatever it
holds, and above the claim verified at the record's deposit — a record
carrying none is refused there. `alg` is an `ALGS` token, matched as bytes,
lowercase, and the token set is frozen (adding one is a coordinated
grammar upgrade): the two HYBRID tokens, each ONE entry over ONE
concatenated raw value — the post-quantum public key THEN the Ed25519
public key — with one fingerprint and one label per sheet:
`mldsa65-ed25519` (ML-DSA-65 + Ed25519, 1,952 + 32 = 1,984 bytes, 3,968
hex; the PRODUCTION kind, the marker tag `1`) and
`fndsa512-preview-ed25519` (FN-DSA-512 + Ed25519 under `fn-dsa` 0.4.0's
pre-standard format, 897 + 32 = 929 bytes, 1,858 hex; a PREVIEW, the
marker tag `3`, whose ENROLLMENT the daemon refuses unless launched with
`--allow-preview-keys` — §Credential refusals, `preview_key`). There is
no classical `ed25519` token: a record naming it is
`bad_record`; tag `2`'s token `fndsa512-ed25519` (the final FIPS 206 +
Ed25519) is RESERVED and has no kind yet. A hybrid entry opens sessions
(§Sessions) and signs entries (the `attest` member, §Operations) under
both halves; each tag names one exact, frozen verification rule and one
frozen keygen-from-seed rule, never edited — a change to what verifies,
or to what a seed derives, is a new tag and a new token. The canonical encoding pins members in schema order,
no whitespace outside strings, lowercase hex, the shortest JSON escapes
and no others, and no byte after the closing brace — a record is
admitted only where its bytes are that encoding of every member it
carries, `sig` included. An unparseable or non-canonical record makes
the deposit permanently inert — the daemon refuses it up front as
`malformed_payload:<sub>` (§Credential refusals).

**The record's own signature — the record grade** (signed ops, 2a).
ABOVE THE CLAIM on a claimed board, an enrolment or retirement record
carries in `sig` the hybrid signature blob in hex (the post-quantum
signature then the Ed25519 signature, as `attest` carries one; 6,746 hex
under tag `1`, 1,460 under tag `3` — the blob's width says the row, and
the record names no `alg` beside it), made by the WRITING HAND's key
over the entry frame under the `record` grammar:
`framed("skep-entry-v1", [alg, board, account, doc, "record", body])` —
`alg` the signing key's token, `board` the head document `H.1`'s
`(position, chain)` pair, `account` the HOME's account (the record's own
doc 1 belongs to it — the delegator's for a genesis, the subject's for a
holder act — never the acting session's), `doc` the home, `op` the token
`record` (a grammar token: no wire op spells it), and `body` FIVE rows in
this order: (1) the link's TYPE address as an address-form slot row of
one element; (2) the link's `to` slot as an address-form slot row — the
subject account, EMPTY at a targetless kind; (3) the `replaces` row —
one length-delimited group, EMPTY, since a credential deposit carries no
`replaces` member (below); (4) the LINEAGE row — the same form, EMPTY,
no lineage having forked; (5) the SIG-LESS CANONICAL RECORD — the record
with its `sig` member removed — as one length-delimited element. `from`
is no row: the atom's address does not exist when the `sig` is made. The
hand signs at THE GRADE THE ACT NEEDS: an ANCHOR of the set that opens
the home's account where the act is anchor-grade (an anchor retirement,
an anchor-flagged enrolment, a handoff — the `anchor_session_required`
cases, §Credential refusals), any enrolled key of that set otherwise.
Then the client inserts the atom (its `insert` takes no `attest`) and
deposits the `make_link` naming it, which carries no `attest` either:
the record's `sig` covers both positions, and the daemon VERIFIES it at
that `make_link` — the frame composed from the stored atom and the
link's own slots and address, the candidates the enrolled keys of the
set that opens the home's account as of the link's base, the anchors
alone at an anchor-grade act — refusing `attestation_required` where the
record carries no `sig` and `attestation_invalid:<cause>` where it
carries one no such key verifies (§Credential refusals). A record carried
into ANOTHER account's doc 1 on this board, or onto another board,
verifies under nothing: the frame names the home, its account and `H.1`.
A mirror composes the same bytes from the stored link and atom alone
(`read_link`, `retrieve_v`, `H.1`'s pair, `effective_owner` of the
home). At or below the claim nothing runs: the ceremony's own genesis
record carries no `sig`, and the claim deposit carries no record.

**The keygen-from-seed rule** each tag names, stated. ONE 32-byte seed —
the paper backup's 64 hex — derives both halves of a key, and neither
half is ever handed the seed itself: each half's own 32 bytes are

```
half_seed = HKDF-SHA-256(salt = "skep-kdf-v1", IKM = seed,
                         info = <alg token> ‖ 0x00 ‖ <half label>, L = 32)
```

with the half labels `ed25519` for the Ed25519 half and, for the
post-quantum half, `ml-dsa-65` under tag `1` and `fn-dsa-512` under tag
`3` — the token is in the `info`, so one seed derives different Ed25519
halves under the two tags. The Ed25519 half's 32 bytes are its private
key; the ML-DSA-65 half's are FIPS 204's ξ, its keygen
`ML-DSA.KeyGen_internal(ξ)`; the FN-DSA-512 half's are the one 32-byte
draw `fn-dsa` 0.4.0's keygen makes, and nothing else. The raw public key
is the post-quantum key THEN the Ed25519 key's 32 bytes; a signature blob
is the post-quantum signature THEN the Ed25519 signature's 64 bytes, both
over the same bytes, two fixed-width fields with no length prefix. The
vectors: the seed
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
derives, under tag `1` (`mldsa65-ed25519`), the key whose fingerprint is
`8c7d0b0e21969ffa5039ccebce2c857614740c3be9498ab8c697bc9320c30623`, and
under tag `3` (`fndsa512-preview-ed25519`), the key whose fingerprint is
`d38e5be29f0c62fe1a51cb09d00250ea18bfd2ba799536c0596077d1d1d65fca`.

**The ceremony** is the unclaimed board's one admitted write sequence
(worked end-to-end in §A first board): `delegate` from principal 0 →
the home mint (`create_new_document`, which becomes doc 1) → the record
`insert` into doc 1 (declared under the enroll type, `deposit:
"1.1.0.1.0.1.0.3.1"` — the home is published from birth, and a record
atom declared under its class's type is the deposit-class write it
admits, §Arrangement) → the genesis enroll deposit, its `ty` that same
type → the claim deposit.
The genesis deposit seeds the account's key set (the enrolled-set cap
does not bind it, and the anchor gate is exempt of THIS genesis — the
seeding hand records the initial set, flags included: a top-level
account's own genesis, with no keyed account above it; a genesis that
hands a SUB-account away is anchor-grade wherever the set that opens the
account holds an anchor, the hire, the spawn and a forked seat's
admission apart — AUTH-3.21, §Credential refusals); the claim deposit
flips the board claimed — first claim wins, permanently. Only a top-level
(bootstrap-delegated) account with a non-empty key set can claim. The
ceremony's convention signs the claim with a just-enrolled key, proving
custody before the flip; the unclaimed window itself admits the deposit
from a bare session too. THE CLAIM REFUSES OVER RESIDUE
(PUB-6.63): it is admitted only where the top-level account space holds
exactly one principal above the genesis floor — the one this ceremony's
own `delegate` minted — and refuses `claim_residue` otherwise
(§Credential refusals), so a board that a second hand's partial, or a
crashed ceremony's own retry, has left with two top-level principals is
claimable by nobody, and its one cure is re-genesis. A client can read
the same fact ahead of step 1 off `next_account_prefix` under node `1`,
which answers `1.0.1` on a board with no residue.

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
origin naming a port the daemon is not bound to (re-issue the origin for
the bound port; no key strands — a key is bound to no origin).

**The preview-key setting.** `--allow-preview-keys`, a DEV setting
beside `--local-trust` and off by default: with it the daemon admits the
ENROLLMENT of keys of the preview kind (`fndsa512-preview-ed25519`, the
marker tag `3`); without it every enrollment record naming one — a
genesis included — is refused `preview_key` (§Credential refusals). It
gates enrollment alone: verification of tag `3` stays compiled in, an
already-enrolled preview key opens sessions and signs entries as any
other, and the record grammar admits the token as syntax. A served board
is launched without it; the test fixtures run with it on. It is daemon
config, never board state, and `GET /health` publishes nothing of it.

**The node prefix.** `--node-prefix 1.N` (env `SKEPD_NODE_PREFIX`),
optional, names the board's full node prefix in the registry: a node
address under the root `1` — an org's `1.3`, a subnode's `1.3.2` —
never the root itself, and nothing under another first component. It
is EGRESS AND ASSERTION CONFIG (REG-1.69): per daemon, supplied at
launch as `--origin` is, in no record, journal, sidecar or fold, and
never a journaled genesis fact — a board carries on under a fresh
prefix by a reconfigure and restart (REG-1.70), the journal untouched.
What this daemon decides by it today is ONE thing: the blocked-prefix
list's off-board test (§Sessions) — whether the list's configured
operator account is an account of this board — runs against this
prefix and never against the local `1`, under which every address in
the registry's global form would read as this board's own. The
daemon's start-up log names the prefix in force or its absence; with
none supplied that test is off, every operator reads as on-board, and a
hosted board must supply one.

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
| 400    | `malformed_session_request` | `POST /session` body is none of the three session forms (§Sessions); the nonce survives |
| 400    | `malformed_challenge`       | the `/challenge` query isn't `principal=<non-negative integer>` |
| 401    | `session_rejected`          | the `POST /session` handshake refused — one code for every failure of the credential, no detail (§Sessions) |
| 403    | `prefix_blocked`            | the `POST /session` signed body names a principal whose account sits at or under a prefix the operator has blocked; carries `record` — the takedown record's version address — and no `detail`; the nonce is spent; permanent until a lift (§Sessions) |
| 400    | `malformed_op_at`           | `POST /op-at` body isn't `{"at": n, "frame": {…}}` |
| 400    | `write_at_history`          | the `/op-at` frame is a write operation |
| 400    | `beyond_head`               | the position exceeds the committed head (carries `head`) |
| 400    | `not_a_position`            | the number is not a committed position (carries `nearest`) |
| 400    | `malformed_at`              | the `/dump` or `/chain` query isn't `at=<position>` (`/chain` requires it) |
| 400    | `malformed_changes`         | the `/changes` query isn't `since=<position>` with an optional in-range `limit`, an optional dotted-decimal `under`, and an optional `drafts=true|false` — or its `limit` names a page that would pass the page byte budget (carries `budget` and `fits`, §The change feed) |
| 400    | `malformed_http`            | the request is not the HTTP subset skepd speaks (bad head, chunked body, a body cut short) |
| 404    | `no_such_endpoint`          | unknown path (including `/dump` on a build without `observe` and `/` on a build without `client`) |
| 405    | `method_not_allowed`        | known path, wrong method                |
| 413    | `payload_too_large`         | the declared `Content-Length` exceeds the route's request-body cap — 8 MiB on the frame routes, 64 MiB on the blob upload's body-carrying methods, 16 KiB everywhere else (§Transport); or a blob upload's declared `length` exceeds the per-file cap (§Media) |
| 400    | `malformed_blob`            | a blob upload request's query or identifier is not the documented shape — `length=<bytes>` at the creation, `offset=<bytes>` at a resume, 32 lowercase hex in the path (§Media) |
| 403    | `upload_refused`            | the blob upload's session-layer gate: `detail` is `unauthenticated` (no live session), `claim_first` (the board is unclaimed), or `node_tier` (principal 0 of a node, which owns no documents) — before any body byte (§Media) |
| 404    | `no_upload`                 | the identifier names no upload of the requester's own — expired, ended, another's, or never minted: one answer (§Media) |
| 409    | `upload_held`               | another stream holds the upload; retry once that connection ends (§Media) |
| 409    | `upload_offset`             | a resume stated an offset other than the record's; carries `offset`, the record's (§Media) |
| 400    | `upload_length`             | the request's bytes would pass the upload's declared length; nothing taken (§Media) |
| 507    | `deposit_refused`           | the media gate refused the deposit: `scope` names `own`, `venue`, `floor` or `standing`, `ended` whether the upload was ended (refused as the body was written) or kept (refused before it), `offset` the bytes received (§Media) |
| 500    | `blob_io`                   | the blob store refused I/O; the upload stands at its last durable point (§Media) |
| 503    | `index_rebuilding`          | the cell index is being rebuilt from the board after an open, and this request is one of its three readers — the blob upload's creation or resume, or the deposit read; retry shortly (§Media) |
| 404    | `no_value`                  | the blob fetch's `i` names an element position the document never minted (§Media, THE FETCH) |
| 404    | `not_a_cell`                | the fetch's `i` holds a value naming no media cell — prose, a def, a record of another kind (§Media, THE FETCH) |
| 404    | `unknown_cell_schema`       | the fetch's `i` holds a value naming a media kind under no schema this board reads — D13's halt (§Media, THE FETCH) |
| 404    | `blind_cell`                | the fetch's `i` holds a BLIND document's cell: its picture is its owner's, and this board holds no byte of it (§Media, THE FETCH) |
| 404    | `blob_missing`              | the fetch's cell names a hash the store has no file for; carries `hash` and `size`, the cell's (§Media, THE FETCH) |
| 404    | `blob_damaged`              | the fetch's file is not the deposit the cell names — the wrong length, or the wrong bytes under the right name; carries `hash` and `size` (§Media, THE FETCH) |
| 503    | `fetch_busy`                | all fetch permits are in use; retry shortly (§Media, THE FETCH) |
| 503    | `upload_busy`               | all upload permits are in use — the blob upload's creation or resume past the upload pool, before any body byte; retry shortly (§Media, THE PERMIT) |
| 410    | `history_reclaimed`         | the position (`/op-at`) or the `since` fence (`/changes`) predates retained history (carries `floor` when known) |
| 503    | `history_busy`              | all historical-reconstruction permits (`/op-at`, `/dump?at`, `/chain?at`) are in use; retry shortly |
| 503    | `scan_busy`                 | all class-scan permits are in use — a `find_links_ftt`/`count_ftt`/`window_ftt` on `/op` whose four-set constrains `ty` alone (§Link discovery reads); carries `op`; retry shortly |
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
fence, remains within retained history**. `GET /dump` conditions on one
term more (PUB-8.26): its bytes are a function of the world AND the
reader's class — the head's publication state, its grant state, and the
presented token's principal — so two dumps are byte-equal when those
agree, and a guest's dump differs from an owner's of the same world by
design. `GET /changes` takes the same term (PUB-8.26): a page is a
function of the journal, the sidecar, AND the reader's class — the head's
publication state (which only grows), its grant state, and the presented
token's principal — so two pages at one class agree byte for byte, across
repeats, restarts and daemons over one journal, and a guest's page
differs from an owner's of the same feed by design. The reclaim floor advances
between repeats; a position that has aged out answers
`410 history_reclaimed`, never different bytes. That conditioning is the
wire's own base; a surface that widens it states any further
conditioning terms of its own on top of it.

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
counts, principal ids) are plain JSON numbers. They are `u64` server-side,
and a value beyond 2^53 − 1 would lose precision in every
JavaScript-backed READER of the wire — the browser's guest reader among
them, which reads a number as a JSON number; the Rust frontend reads it
exactly. A log position or a count approaching that is unreachable in
practice: both are bounded by what a board has committed. A **principal
id** is not a count: it is a number a client CHOOSES (`delegate`'s
`new_id`), so the board bounds it where it is minted: `delegate` refuses a
`new_id` above 2^53 − 1 at the parse (§Namespace), and so registers no id a
client cannot read exactly.

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

**Content values** carry granularity explicitly. The store holds
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

* A **withheld run** renders `{"withheld": {"origin": "<address>",
  "width": "<nat>"}}`: a run the reading
  principal may not read, emitted at its OWN position rather than
  dropped — `origin` the run's origin DOCUMENT, `width` its position
  count. One item per withheld RUN: two non-contiguous withheld runs,
  even from one origin, are two items, never one coalesced item of the
  summed width. Only `retrieve_v` emits it (the extent forms deliver no
  positions); a masked run is the reader's, not the named document's —
  a document the reader may not read at all is a `withheld` REJECTION
  (§Rejections), never a delivery.

* **An item kind you do not know** is no fault of the delivery: a client
  MUST NOT fail the read on it. Keep the item at its own place in the
  sequence — never dropped, never coalesced into a neighbour, the items
  after it still read — and show it as not rendered. A later delta adds
  position-preserving item kinds beside `withheld` (PUB-8.38), and such a
  kind carries its `width`, as `withheld` does, so a client's position
  count runs past it. The daemon stays strict about what it is SENT
  (§The request envelope); this is what a client does with what it is
  HANDED.

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
create_new_document / insert (start address) / version / publish (the
member) / make_link / emit / nullify / assert_sup / fork / delegate /
register_node.

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

One readable per-byte position, then a RUN the reader may not read — a
withheld item at its own position, never coalesced:

<!-- wire: response delivery_withheld -->
```json
{"as_of":9,"items":[{"content":"a"},{"withheld":{"origin":"1.0.1.0.2","width":"3"}}],"resp":"delivery"}
```

**`i_delivery`** — retrieve_i (the read by identity): one item per
I-position asked, in span order, `at` the address and `value` the value
M4 holds there rendered as one delivery value (`content`/`hex` for a
per-byte value, `atom`/`atom_hex` for a composite) — or `null`, a position
the document never minted or a link position. Never coalesced across
positions: the items are the request's, one each. This example answers a
per-byte value at the first position and `null` at the second:

<!-- wire: response i_delivery -->
```json
{"as_of":9,"items":[{"at":"1.0.1.0.1.0.1.1","value":{"content":"h"}},{"at":"1.0.1.0.1.0.1.2","value":null}],"resp":"i_delivery"}
```

**`frontier`** — content_frontier: `next`, the next unminted content
ordinal under the document — its mint count plus one — a natural as every
count rides the wire.

<!-- wire: response frontier -->
```json
{"as_of":9,"next":"5","resp":"frontier"}
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

**`effective_owner`** — effective_owner (§Namespace): who owns the address
asked — `prefix` the LONGEST registered prefix containing it and
`principal` the principal seated there. Both are always present, carried
together, and `null` TOGETHER only where no registered principal's prefix
contains the address; the address is an allocated seat iff `prefix` equals
it (the row states the test).

<!-- wire: response effective_owner -->
```json
{"as_of":9,"prefix":"1.0.1","principal":900,"resp":"effective_owner"}
```

<!-- wire: response effective_owner_none -->
```json
{"as_of":9,"prefix":null,"principal":null,"resp":"effective_owner"}
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

**`doc_metadata`** — doc_metadata (§Namespace): the publication state a
client's own admission tests need, and the shot terms a verifier of a
member's entry signature needs. `doc` is the trunk document the
argument projects to (a version member answers its document's state);
`published` its publication bit; `owner` its owner account (always
present for a registered document); `birth` its birth version `D.1` and
`birth_extent` that version's BIRTH CONTENT — the content `D.1` was
minted with, the leading runs of its arrangement at the mint, counted; a
deposit is no part of it — both present together once the document has a
chain member and both `null` before it. `birth_extent` is FROZEN at the
mint (PUB-3.19): while `D.1` is still the chain's head a declared
deposit appends to its arrangement (`insert`, §Arrangement), so its
arranged content count grows and this value does not — the same at every
later position, on `/op-at` as on `/op` — and a client subtracts
nothing. A `publish` with NO runs journals its placing record all the
same, so a birth version born EMPTY that way answers `0` for good; no
conforming mint is empty.

`placed` and `base_extent` are THE SHOT TERMS OF THE ADDRESS NAMED
(signed ops; the design record's D25, arm (c′)): asked of a version
member the `publish` shot minted, `placed` is the number of content
positions the shot's client runs covered — positions `1` through
`placed` of the member are the client's runs, the base's carried tail
follows them — and `base_extent` is the shot's own `base_extent`, the
positions of its base the staged copy took; `base_extent` is `null` for
a member the birth shape minted (no base — the `null` IS the birth bit,
and there `placed` is the birth extent). Both are `null` where the
address named carries no terms: the trunk document itself, a birth
version an owned `version` minted, a member minted before the record
carried them. Journaled in the shot's own placing record, so they ride
the commit chain, every checkpoint and every replica. With the member's
runs and its address they are everything a reader needs to re-compose
the `publish` signature's frame (§Arrangement, `publish`): `base` is
derived from the member's address — a trunk member `D.k+1` was minted
against `D.k`, a daughter `X.m` against `X`, `D.1` against the memberless
document or, with `base_extent` `null`, against nothing. This example is
asked of the birth version `1.0.1.0.1.1`, which a shot placing five
positions minted from the memberless document taken at three:

<!-- wire: response doc_metadata -->
```json
{"as_of":9,"base_extent":"3","birth":"1.0.1.0.1.1","birth_extent":"5","doc":"1.0.1.0.1","owner":"1.0.1","placed":"5","published":true,"resp":"doc_metadata"}
```

<!-- wire: response doc_metadata_unborn -->
```json
{"as_of":9,"base_extent":null,"birth":null,"birth_extent":null,"doc":"1.0.1.0.2","owner":"1.0.1","placed":null,"published":false,"resp":"doc_metadata"}
```

**`edition_claims`** — edition_claims (§Link discovery reads): the
audit-view edition-claim lookup over `target`. Each row is one admitted,
unsuperseded claim of the edition class — `claim` the link's address,
`home` the edition it is homed in, `to` the endset it denotes, `active`
false when the home has retracted it (the audit view lists it either
way). Only rows whose home you may read are returned.

<!-- wire: response edition_claims -->
```json
{"as_of":9,"claims":[{"active":true,"claim":"1.0.1.0.5.0.2.1","home":"1.0.1.0.5","to":[{"start":"1.0.1.0.1","width":"0.0.0.0.1"}]}],"resp":"edition_claims"}
```

**`universal_grants`** — universal_grants (§Grants): the grant fold's live
any-principal set, as a bound principal may display it. `rows` is always
present: one row per COVERED content prefix — `prefix`, a document or an
account — with the `issuers` who granted it to every principal, in prefix
order, each issuer list in address order; `[]` for a guest, under this
same tag — an answer, never a rejection.

<!-- wire: response universal_grants -->
```json
{"as_of":9,"resp":"universal_grants","rows":[{"issuers":["1.0.1"],"prefix":"1.0.1.0.2"}]}
```

<!-- wire: response universal_grants_empty -->
```json
{"as_of":9,"resp":"universal_grants","rows":[]}
```

**`key_set`** — key_set: an account's credential table (§Identity
reads). `enrolled` and `retired` entries ride in fingerprint order;
`anchor` per entry is the flag the fingerprint was ENROLLED under,
retired entries included. A keyless account answers two empty arrays.
(The example is illustrative — this shape is asserted by the daemon's
auth suite against live bytes, not by the codec fixtures.)

```json
{"as_of":9,"enrolled":[{"alg":"mldsa65-ed25519","anchor":true,"fingerprint":"abababababababababababababababababababababababababababababababab","key":"<3968 hex — the ML-DSA-65 public key then the Ed25519 public key>"}],"resp":"key_set","retired":[{"anchor":false,"fingerprint":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}]}
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
  * `"retry"` — the operation did nothing. A transient fault may clear on
    reissue; but where the cause is the volume's room — `durability` at a
    full volume, below — NO reissue succeeds until the operator frees it,
    and the operator stream names it. The person's act is to tell the
    operator, never to reissue blindly;
  * `"halt"` — the board has stopped accepting writes (operator
    condition): its kernel halted, or the daemon's attest store failed a
    signature's line (`poisoned`, below); reads still work.
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
  multi-document lookups — on a `not_owner` rejection, the document
  (or target link) that failed the ownership check; on a `withheld`
  rejection, the origin DOCUMENT a `publish` shot may not read,
  or the document argument a READ may not — a read carrying
  several document arguments names the first, in declaration order.
  Span faults: `not_ordinal_level`, `not_level_uniform`,
  `start_not_zero_free`, `start_too_shallow`.
* `detail` — optional message (always present on `unparseable`, where
  it says what failed to parse). On `credential_refused` the field is a
  MACHINE token — the code:detail convention, one pinned token per
  refusal, e.g. `signed_session_required` — and the one place clients
  dispatch on `detail` (§Credential refusals). One exclusion is
  pinned: `withheld` carries no `detail`, ever — its whole diagnosis is
  `code` plus `site.addr` — so no daemon drifts into describing, one
  field over, the extent that code exists to withhold.

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

Transport/lifecycle: `unauthenticated`, `malformed`, `durability` (the
commit's durability barrier failed and the operation did nothing — retry
class, since the code is one many transient faults share; where the cause
is a FULL VOLUME the same request fails the same way until the operator
frees room, which the operator stream says, so the act is the operator's
and no retry succeeds before it), `txn_unencodable` (a record the operation staged could not be encoded
into a journal frame at all — permanent; reissuing the same request
stages the same record), `txn_over_budget` (the request's records all
encode, but the transaction as a whole exceeds the kernel's
per-transaction byte budget — permanent; split the request), `poisoned`
(the board has stopped accepting writes — halt: the kernel halted its
write paths, or the daemon's attest store (§The change feed) failed to
write or sync a signature's line, after which every write is refused
until a restart, whose open rebuilds the line from the journal — the
repeat of an acknowledged write included, unless a credential deposit's
own memo answers it; reads are served throughout).

Credentials: `credential_refused` — the auth work's one new code,
always carrying a machine `detail` token, and `permanent` at every token
but the two attestation tokens, which carry their own classes
(§Credential refusals below).

Media (lanes A and B): a value naming the picture cell's kind at a
published target answers `published_target` whatever the insert's
declaration; a shot re-inserting one from a draft the caller does not own
answers `not_owner` naming the draft; in a draft, and at the owner's own
shot, a cell is ADMITTED where its hash is one this principal deposited
under its own live lease and otherwise answers `credential_refused` with
one of the media door's four tokens — unbound cell, unknown cell schema,
and lease lapsed, `permanent` all three, and the rebuild window's index
rebuilding, retry-class — spelled and tabled in §Media under §Operations.

The registry: registry refused — the registry sequence's one code, the
credential family's shape under a code of its own, always carrying a
machine detail token, permanent at every token but the two attestation
tokens, which carry their own classes; a link write typed the registry's
binding or endpoint answers it, spelled and tabled in §Registry under
§Operations.

Registration/residence: `home_not_registered`, `doc_not_registered`,
`source_not_registered`, `parent_not_registered`, `not_registered`,
`original_not_resident`, `endpoint_not_resident`.

Namespace/authority: `not_owner`, `not_an_account`, `gate` (M3's inc
gate, which every op that mints an address lowers — create-new-document,
fork, insert, version, publish and the five link writes — with a fixed
`detail` naming an operator condition, a corrupted frontier: M3
documents the gate as defensive, so no well-formed request against a
healthy store reaches it), `delegator_unknown`, `duplicate_id`,
`not_ancestor`, `not_authorized`, `not_account_tier` (delegate: the new
prefix is not account-tier — its zero component must be exactly one),
`not_top_down` (delegate: a principal already sits strictly under the
new prefix), `not_next_form`, `not_valid` (delegate: the new prefix is
not T4-valid; register-node: the address is not), `not_node`,
`too_deep`, `not_descendant_of_bootstrap` (register-node: the address is
not a descendant of the bootstrap node, 1), `not_fresh`.

Arrangement: `empty_content`, `content` (insert and publish: M4 refused
the content write because a value is already stored at the address M3
just minted — an upstream invariant no sound store breaks, so, like
`gate`, a defence rather than a well-formed request's refusal),
`empty_source`, `not_ordinal_vspan`, `dangling_source`, `empty_result`
(copy: the net placement is empty once the specs are clipped),
`not_arranged` (delete: the position's ordinal names no arranged content
position), `out_of_bounds`, `empty_width`, `bad_cut_count`,
`not_ascending`, `empty_content_subspace` (rearrange: the document's
content subspace is empty), `not_a_principal` (version: the caller's id
names no principal), `node_tier_cross_owner` (version of a document the
caller does not own: a cross-owner version takes an account-tier forker,
never a node-tier one), `not_home_link`, `already_seated` (both
make-link's seat step, with `not_link_address` below: the link it seats
in the home's link subspace is not that home's own, or is seated there
already — defences on a link the same transaction just minted there,
never a well-formed request's refusal), `not_content_subspace`,
`published_target`, `private_version_of_published`,
`private_source_versionless` (the version-chain model's three write-path
refusals — §The version-chain refusals below), and the publish shot's
own (§The publish shot and head-float below): `withheld` — the
source gate, and every READ's document-argument consult
(§The read predicate); the one code of this family whose disposition is
reorder, carrying `site.addr` (the document) and never a `detail` —
`bad_run`, `base_not_in_chain`, `base_superseded`,
`base_extent_too_large`; and three more of M5's — `not_link_address`
(make-link's seat step, M5 §8: the address it is to seat is not a full
element position in the home's link subspace — with `not_home_link` and
`already_seated` above, a defence on the link the same transaction just
minted, never a well-formed request's refusal), `too_many_runs` (a
placement past M5's
`MAX_PLACED_RUNS` = 65536 runs, or a copy whose specs command more than
`MAX_COPY_RESOLVE_STEPS` = 1048576 run-list steps, each spec charged its
source's whole run count ahead of its walk, so a spec aimed past its
source's arranged end is refused for the work it would do while keeping
nothing — one code for both causes, told apart by the store's message;
permanent, a copy past either is split by its caller; the publish table
below carries the first) and `too_many_values` (a shot whose draft-native runs
re-insert more than M5's `MAX_REINSERTED_VALUES` = 131072 values, their
widths summed — arithmetic on the request, asked after the source gate
and ahead of existence; permanent, a shot cannot be split to meet it;
the publish table carries it too).

Links: `ill_formed_spec`, `empty_type_resolution`, `shape_violation`,
`retraction_class` (make-link and emit: the type resolves into the
retraction class, which only nullify writes — M7's K ≁ R fence),
`non_address_denoting_type`, `bad_target`,
`self_supersession`, `ill_formed_successor`, `dc_violation`,
`slot_too_large` (a slot past either of M7's two per-slot budgets: more
than `MAX_SLOT_SPANS` = 4096 spans, in either form — the three slots of a
make-link, the to- and type-slots of an emit, and the successor slots of
an edit-link, the last naming the slot in `site.slot` — or, for a
make-link slot in the V-spec form, specs commanding more than
`MAX_SLOT_RESOLVE_STEPS` = 262144 run-list steps, each spec charged its
source's whole run count ahead of its walk, so a spec aimed past its
source's arranged end is refused for the work it would do while keeping
no span; one code for both causes, told apart by the store's message;
permanent — no retry shrinks a slot).

Content/provenance reads: `no_such_subspace`, `empty_subspace`,
`depth_incompatible`, `range_not_present`, `malformed_span`, and M6's
four budget refusals — `too_many_blocks` (a compare operand passes
`MAX_COMPARE_OPERAND_BLOCKS` = 4096 on either of its two counts: more
spans handed to the arrangement, one resolution walk apiece whatever it
yields, or more blocks resolved; refused as the operand resolves, ρ₁
first, and before the join runs), `too_many_pairs` (the report would
exceed `MAX_COMPARE_PAIRS` = 65536 correspondences), `too_much_coverage`
(the find family's request passes `MAX_FIND_COVERAGE_SPANS` = 4096 on
either of its two counts: more region spans handed to the arrangement or
more coverage spans produced; refused as the request resolves, before
the candidate scan runs), `too_many_items` (a retrieve-v delivery would
exceed `MAX_DELIVERY_ITEMS` = 131072 items — one per delivered position,
one per withheld run; refused as the delivery is produced, a delivered
run's positions admitted as one batch, so a single spec naming a document
whose extent transclusion has multiplied is refused rather than built).
Each of the three operations also answers its own code — the compare
operand's `too_many_blocks`, the find request's `too_much_coverage`, the
retrieve-v spec-set's `too_many_items` — when the run-list walk its spans
may ask of the arrangement is priced past `MAX_COMPARE_OPERAND_BLOCKS`² =
16777216 steps: each span is priced, before the first is walked, at an
upper bound on its walk — up to the document's whole run count, for a
span opening past the arranged end, whatever it yields, and that whole
count for a span the arrangement's span reader declines (a
depth-incompatible one), though it resolves to nothing; so a request of
spans that each degrade to nothing can still be refused for its size.
All permanent — no retry shrinks the request.

Link-discovery reads: `not_a_link`, `bad_region`, `image_too_large` (a
read past M8's run budget `MAX_IMAGE_RUNS` = 4096, or past the product
its own join is held to — each read counting the runs its own work
multiplies: on the region family — image, find-links-v, count-v,
window-v, retrieve-endsets — the run-list walk the region asks of the
arrangement past `MAX_IMAGE_RUNS`² = 16777216 steps, held ahead of the
first pull, or the runs its spans resolve, summed across the spans and
counted as M5's lazy resolution pulls them — the run past the budget
refused as it is pulled, before the next is built, so no region
materializes a fragmented surface whole — past 4096; on the project
read, the reading surface's content runs past 4096,
or the coverage × run product — the answer's pre-normalization size —
past `MAX_ANSWER_SPANS` = 65536; on the discoverable-from read, the
reading surface's content and link runs past 4096, or the link's whole
coverage × run product past `MAX_IMAGE_RUNS`²; and on the delete-orphans
preview, the document's own runs as the range splits them — content and
link, plus a piece for each run an end of the range cuts — past 4096,
the preview's own refusal lowered to this code), `endsets_too_large` (a
retrieve-endsets answer would carry more than M8's `MAX_ANSWER_SPANS` =
65536 spans — the answer budget, priced on what the store hands back
rather than on what the request names; the project read's join product
is held at the same number and answers `image_too_large`).

The supersession-class fence — M7's `[K_sup]` sole-writer rule, a
make-link or emit whose resolved type lands in the supersession
class, which is written only by the two supersession ops (assert-sup
and edit-link, §Links) — has no code of its own and rides
`dc_violation`, the claim-schema code the edit-link DC guard names.

### The version-chain refusals

A document is either edited in place or versioned, never both: a
private document is a draft, edited in place and versionless; a
published document advances by versions and admits no edit in place.
Three refusals hold that line. They are the STORE's — typed
errors out of the arrangement's own transaction, evaluated in the one
slot after registration and ownership (PUB-6.36 slot 5, PUB-6.37) and
before the operation's own shape checks — so they answer from every
session the daemon's gates admit, signed sessions included, and the
daemon adds no gate of its own for them. (One qualification: the write
door pre-evaluates `published_target` on a `copy`'s
destination ahead of its source consult, in the store's own bytes, so
the model's refusal speaks ahead of `withheld` — PUB-6.36 slot 5 before
slot 6, §The read predicate; the store's own refusal stands behind
it.) A version member is judged as
the document it projects to (PUB-2.15): `1.0.1.0.1.2` refuses exactly as
`1.0.1.0.1`. All three are `permanent`, carry no `detail` and no `site`,
and a refused request commits nothing. The daemon's own publish-class
gate (`signed_session_required`, slot 4) stands ahead: a bare session
never reaches these codes on a published document.

| code | op | when |
| --- | --- | --- |
| `published_target` | `insert`, `copy`, `delete`, `rearrange` | `doc` is a PUBLISHED document (or a member of one) — the one exemption is a **declared deposit**, `insert` whose `deposit` names a type the deposit class holds, at fresh content positions past the arranged extent; a `deposit` naming any other type answers this code as an undeclared append does (§Arrangement) |
| `private_version_of_published` | `version` | you own `d_src`, `d_src` is PUBLISHED, and an explicit `published:false` asks for a private member |
| `private_source_versionless` | `version`, `publish` | you own `d_src` (or the shot's `doc`) and it is PRIVATE — whatever the flag; a private document has no chain to append to (on `publish` this is the flag-`true` face below) |

The faces, keyed on the code (PUB-6.7): the client renders them, the
wire carries the token. ⟨D⟩ is the document named.

* `published_target` — "⟨D⟩ is published — it advances by versions.
  Stage your change in a draft, then publish it as the next version."
* `private_version_of_published` — "⟨D⟩ is published — its versions are
  published. To keep a private copy of it, mint a sibling draft to hold
  it; the version chain is publication's own. To change what the world
  reads, stage your change in a draft, then publish it as the next
  version."
* `private_source_versionless` — ONE code; the face splits on the flag
  the client itself sent. Flag absent or `false`: "⟨D⟩ is private —
  private documents are versionless. Mint a sibling draft to hold the
  alternative; the version chain is publication's own." Flag `true`:
  "⟨D⟩ is private — publishing means minting a separate edition: select
  what to publish and it is minted published-born, your draft
  re-windowing it; private documents are versionless."

Neither `version` refusal reaches a document you do NOT own: the
cross-owner `version` mints a fresh document in YOUR account (the
source's state plus your flag, §Arrangement) and is refused by neither
rule.

### The publish shot and head-float

A published document advances by the **shot**: `publish`
(§Arrangement) appends the next member of `doc`'s
version chain, born published, in ONE commit, its arrangement taken
from the runs the client supplies (PUB-2.33, PUB-8.1) and from nothing
any draft holds at commit. The draft is the client's rendering surface;
what it holds when the shot lands is not read.

**Destination** (PUB-2.37, PUB-2.39, PUB-2.44, PUB-2.55): the next
member of the chain anchored at `base`, decided at commit. A base that
is still the trunk head yields the trunk's next member (`1.0.1.0.1.2`
after `1.0.1.0.1.1`); a base the trunk has moved past yields the base's
own DAUGHTER, in the nested form (`1.0.1.0.1.1.1`) — so two shots
staged off one head both land, the first on the trunk and the second
under it, and nothing is refused for want of a base. A memberless
document is its own base (`base` = `doc`), and `base` absent is that
same **birth version** (PUB-2.34): the chain's first member, `.1`,
either way. Once a member exists the memberless base and the birth
shape are superseded — the shot must name the member it was staged
from (`base_superseded`). A member address given as `doc` is the
document's shot.

**The member's arrangement** (PUB-2.40, PUB-2.41, PUB-2.42): `runs` is
the client's WHOLE rendered arrangement, in order, each run its
`origin`, its `i_start` and its `width`. A run is placed by its
origin's relation to `doc`: the document's own I-space (its own chain
or any member's) by reference; the staging `draft`'s RE-INSERTED as
fresh identity under the document's own I-space — one content mint
and one write per value, the bytes read at the draft's addresses — so
no address of the draft survives in the member; any OTHER document's
stays a window, answering its origin. `origin` must be the document
that minted the run's addresses (`bad_run` otherwise; a link element is
no content run). Then the composite APPENDS the base's positions past
`base_extent` — the extent the staged copy took: a published member
changes only by declared deposits at fresh positions (PUB-2.43), so
what lies past that extent is exactly the deposits the render
post-dates, carried unchanged after the client's runs (PUB-2.45,
PUB-2.67). That is how the whole-arrangement reading (PUB-2.33) and the
deposit cell (PUB-2.42) hold together: the client renders, the
composite appends what the client could not have seen; nothing is
positionally applied to an advanced head. `base` and `base_extent`
travel together — either both or neither. An empty `runs` lands an
empty member.

**Head-float** (PUB-2.49, PUB-2.50, PUB-2.53). Every arrangement reader
of a bare DOCUMENT address answers the document's trunk HEAD — the
latest trunk member — and never the pre-chain arrangement a shot
superseded: `retrieve_v`, `retrieve_doc_v_span`,
`retrieve_doc_v_span_set`, `show_origin`, `compare`, the whole region
family — `image`, `find_links_v`, `count_v`, `window_v`,
`retrieve_endsets` — and the pointwise pair, `project` and
`discoverable_from`, which read the link against the arrangement a
reader of `d` sees, so a projection's V-coordinates are the head's, as
`image`'s are; `version` of a bare address shares the head's
arrangement. Daughters never float: the bare address is the trunk's.
A VERSION address answers its own member, forever. A memberless
published document answers its own arrangement — the pin taken here:
until the first shot, the document's pre-chain arrangement (the home's
ceremony atom, say) IS its reading surface, and the birth version then
carries what the client re-supplies of it. A private document is
untouched: it has no chain, and a stamped member under one does not
move it. The registration check runs on the address named, ahead of
the float (PUB-6.37). NOT floated, pinned as the seam it is:
`show_deletions`, `find_docs_containing`, `delete_orphans`, and `copy`'s
source spans read the address named — a client comparing versions names
the members.

**The deposit cell** (PUB-2.65, PUB-2.66). A declared deposit into a
published chain — `insert` with `deposit` naming a deposit-class type
(§Arrangement), named by the bare address, by the head, or by a pinned
older member — lands in the HEAD member's arrangement and nowhere else,
judged fresh against the head's extent; the atom's identity is minted under the chain of the address
named (`1.0.1.0.1.0.1.4` for the bare address, `1.0.1.0.1.1.0.1.1` for
the member). A pinned member's arrangement never grows. The in-place
refusal (`published_target`) stands on every address of the chain.
The change feed's entry for the deposit names the address
written to (§The change feed).

**The source gate** (PUB-8.1's second constraint, PUB-8.4, PUB-8.5,
PUB-6.23, PUB-6.24). Every run's origin must be readable to the
session principal, consulted per DISTINCT origin in run order, after
ownership and before any existence answer: the FIRST unreadable
origin refuses `withheld` — disposition reorder (a later grant is the
one event that fills it), `site.addr` the origin's DOCUMENT, no
`detail` and no other site field, whether or not the run's addresses
exist. The document's own I-space needs no consult, and a run the base
already arranges is carried without one. The consult is the read
predicate (§The read predicate): an origin is readable when
published, or in the reader's subtree, or granted to the reader — a
sharing grant widens what the consult admits without changing this
shape.

The shot's refusals, in the order they answer — the table is in ANSWER
order, the store's door putting the destination's registration ahead of
its ownership (PUB-6.37) and PUB-6.36's slots following — every one
commits nothing:

| code | disposition | `site` | when |
| --- | --- | --- | --- |
| `doc_not_registered` | reorder | — | `doc` is not registered — answered ahead of ownership, so an unregistered address never discloses an ownership verdict |
| `not_owner` | permanent | `addr` = `doc` | the session principal does not own `doc` (PUB-6.36's slot 1, judged once `doc` is registered) |
| `source_not_registered` | reorder | — | `base`, `draft`, or a run's `origin` is not registered (in that order) |
| `bad_run` | permanent | — | a run's `origin` is not the document that minted its `i_start`, or `i_start` is not a content element |
| `private_source_versionless` | permanent | — | `doc` is PRIVATE — a private document has no chain (PUB-2.9's flag-`true` face) |
| `base_not_in_chain` | permanent | — | `base` is a document, or a member, outside `doc`'s chain |
| `base_superseded` | permanent | — | `doc` already has a member and the shot names the memberless base (or none) |
| `base_extent_too_large` | permanent | — | `base_extent` exceeds the base's arranged content count |
| `withheld` | reorder | `addr` = the origin's document | a run's origin is not readable to the session principal |
| `too_many_values` | permanent | — | the draft-native runs' widths, summed, exceed the shot's re-insert budget (M5's `MAX_REINSERTED_VALUES` = 131072 values) — arithmetic on the request, asked ahead of existence |
| `dangling_source` | permanent | — | an address a run names holds no value |
| `too_many_runs` | permanent | — | the placement exceeds the arrangement's run budget |

The daemon's own publish-class gate (`signed_session_required`, slot 4)
stands ahead of the store: a shot is publication's own act whatever
`doc`'s state, so from a bare session it is refused there even on a
private document. The faces (PUB-6.7), ⟨D⟩ the document named and ⟨O⟩
the origin withheld:

* `withheld` — "⟨O⟩ is not shared with you — the shot windows it.
  Remove that window, or wait for its owner's grant." Nothing about
  how much of ⟨O⟩ the shot named (PUB-8.5).
* `base_superseded` — "⟨D⟩ has versions now — name the version your
  draft was staged from as the base."
* `base_not_in_chain` — "the base is not a version of ⟨D⟩."
* `bad_run`, `base_extent_too_large` — the client's own arithmetic is
  wrong; there is no user-facing act to offer.
* `private_source_versionless` on `publish` — the flag-`true` face of
  §The version-chain refusals: "⟨D⟩ is private — publishing means
  minting a separate edition."

### Credential refusals

Every `credential_refused` is the ordinary `rejected` shape with
`disposition: "permanent"` uniformly — the two attestation codes below
excepted, each carrying its own class — and `detail` carrying exactly one
machine token — key client behavior on the token, never on prose. A
bare session depositing a credential on a claimed board, for example:

```json
{"code":"credential_refused","detail":"signed_session_required","disposition":"permanent","op":"make_link","resp":"rejected"}
```

**The two attestation codes** (signed ops; the write-path check, which
runs on every CLAIMED board, with no operator switch, on a dispatched
publish-class write of the TEN KINDS that have an entry frame —
`create_new_document`, `fork`, `version`, `insert`, `publish`,
`make_link`, `emit`, `nullify`, `assert_sup`, `edit_link` — ABOVE the
claim entry, from a signed session, BEFORE the transaction — beside the
publish-class gate below, after it, and ahead of the store's own gates
(`delete`, `copy` and `rearrange` have no frame: a published document
admits none of them, `published_target`); and, at THE RECORD GRADE, on
every credential deposit above the claim, over the record's own `sig` at
the deposit's `make_link` — §The claim ceremony and credentials):

* `attestation_required` — the write carries no `attest` member.
  Disposition REORDER: the answer is a different request, the same
  content signed and attached — under ATTACH WHEN IN DOUBT the ordinary
  path, since the publish class is the daemon's classification over the
  resolved publication state and not a property of an op kind. An
  `attest` on a write outside the class, or on the UNCLAIMED board, is
  DROPPED — never verified, never written, never refused. AND, at a
  credential deposit above the claim, THE RECORD CARRIES NO `sig` AT ALL —
  the record grade's fence, answered at the deposit's `make_link` (the
  record's `sig` member is its one carrier) — a fence with NO POPULATION
  on a conforming daemon: a record-kind atom carrying no `sig` is refused
  at its own `insert`, `record_sig_required` (below), and lands nowhere,
  so the only atom this reaches was deposited below the claim or past the
  check by the operator's hand; REORDER, the act that exists being a new
  record composed with its `sig`, inserted and linked.
* `attestation_invalid:<cause>` — the `attest` does not verify; the
  `detail` is the code joined to its cause: `signature` (no enrolled key
  of the algorithm verifies both halves over the frame the daemon
  composed — wrong bytes, a wrong `board` term, a body composed
  otherwise, a `publish` re-submitted over another base; PERMANENT: the
  same request is refused the same, and the client's next act is a
  different one, the frame re-composed and re-signed),
  `not_enrolled_at_position` (the set
  that opens the writer's account as of the write's base holds no key of
  the algorithm — an empty set included; PERMANENT, no retry under that
  key succeeds), `malformed` (the blob is not the tag's fixed width;
  PERMANENT, a re-compose), `board_unavailable` (the board has no `H.1`, so the frame's
  `board` term has no value — on a claimed board only for the ONE write
  after a refused `H.1`, whose own turn writes the head (§The other
  endpoints), or on a journal damaged below `H.1`; REORDER: the retry is
  admitted), `withheld` (a `publish` COPIES IN a run whose origin the
  writer may not read — a staging draft's run onto a draft the read
  predicate withholds from it — and the store would admit the shot, the
  base carrying the run: no frame is composed over a value its author may
  not read, so no signature is verified over one; REORDER, as the store's
  `withheld` is — re-compose without the run, or re-send once a grant lets
  you read its origin), `frame_too_large` (a `publish` whose entry-frame
  body — the values its copied runs name, read off the store — would pass
  the body budget, 8 MiB at parity with the frame routes' request cap;
  PERMANENT, as `too_many_values` is: a member is born whole, so publish
  in smaller parts). At a
  credential deposit above the claim the same causes over the record's
  `sig`, each with its class: `signature` (no key of the set that opens
  the record's HOME — the anchors alone where the act is anchor-grade —
  verifies it over the `record` frame the daemon composed: the record was
  signed over another home, another board, or by no key of that set),
  `not_enrolled_at_position` (that set, at that grade, holds no key of the
  blob's row), `malformed` (the `sig` is no hybrid blob's hex — an odd or
  non-hex string, or a width no row takes), `board_unavailable` (as for an
  entry).

**The entry frame's rows** (signed ops; the design record's one table,
stated by encoding). Every entry signature is made over
`framed("skep-entry-v1", [alg, board, account, doc, op, body])` — the tag,
then each member `be32(len) ‖ bytes`: `alg` the signing key's token;
`board` the head document `H.1`'s `(position, chain)` pair, `be64(position)
‖ chain` (§The other endpoints); `account` the writer's account in the
board's local form, dotted decimal; `doc` per op (below), one address in
dotted decimal — or, for `edit_link` alone, THE PAIR'S ROW, its two homes
as an address-list row of two: `0x01 ‖ be64(2) ‖ be32(len) ‖ d_s ‖ be32(len)
‖ d_a`, the successor's home then the claim's, no separator and no other
form byte; `op` the op-kind token as this document spells it; `body` per
op. The body's rows: THE SLOT ROW, a link slot AS THE STORE HOLDS IT — the
stored endset's spans, verbatim and in stored order — `0x03 ‖ be64(n) ‖ per
span: be32(len) ‖ start ‖ be32(len) ‖ width`, each tumbler in dotted
decimal; a slot given by ADDRESS stores as one unit span per address (the
address as the start, the unit at the address's own length as the width —
`1.0.1` is the span from `1.0.1` of width `0.0.1`), and a slot given as
V-SPECS stores as the I-extents the store resolves them to, which the
signer reads through `image` over each source before signing, against the
base the transaction will take, and which a later reader takes off
`read_link` or `find_links`; the EMPTY slot has one spelling, `0x03 ‖
be64(0)`; a slot signed over a resolution the base has since moved is
refused `attestation_invalid:signature`, re-composed and re-signed. THE
ADDRESS-LIST ROW, `0x01 ‖ be64(n) ‖ each address be32(len) ‖ dotted
decimal` — never a link slot's row: the `record` body's two slot rows (the
credential grade's, address-form by its own refusal), the one address an
optional row names, the base group's member, the pair's row. THE
OPTIONAL-ADDRESS ROW, one length-delimited group, EMPTY (`be32(0)`) where
no address is named, else the address as an address-list row of one. THE
VALUE-SEQUENCE ROW, `be64(count)` then each value `be32(len) ‖ bytes`. THE
EMPTY BODY, the three mints': the member PRESENT and empty, `be32(0)` in
the frame. Each op's `doc` and `body` are stated at the op: the mints'
(§Namespace, `version` under §Arrangement), `insert`'s and `publish`'s
(§Arrangement), the five link writes' (§Links (writes)), the record
grade's (§The claim ceremony and credentials). The armed set of
`attestation_invalid`'s causes above is the whole of it: the widening to
the ten kinds added no cause.

**Round 7's two refusals** (signed ops; `credential_refused`, PERMANENT
like the family's, each naming the act that exists):

* `record_sig_required` — an `insert` above the claim DECLARED under a
  credential kind whose one value PARSES as a record of that kind and
  carries no `sig` member. Refused at the `insert`, the earliest act the
  fault is decidable from: nothing lands, no orphan atom is minted. The
  act that exists is a different record — the same entries composed WITH
  their `sig` over the `record` frame (§The claim ceremony and
  credentials) — inserted and linked. Beside it, the check's reading of a
  declared deposit as a whole: an `insert` declared under a credential
  kind is EXEMPT from the entry signature only where its one value parses
  as a record of that kind, carries its `sig`, and lands in a doc 1 (the
  home a credential link can name); prose or any other bytes declared
  under the kind, and a signed record landed outside a doc 1, take the
  entry signature like any `insert` — `attestation_required` unsigned,
  committed SIGNED with `attest` otherwise.
* `system_account_keyless` — a credential deposit whose SUBJECT (the
  account the link's `to` names) or whose HOME's owner is the system
  account `1.1.0.1` (§The other endpoints, PUB-6.65): the system account
  holds no key and enrols none, ever. Refused ahead of the fold's own
  verdict on claimed and unclaimed boards alike, and — on the unclaimed
  board — a declared credential-kind `insert` into that account's doc 1 is
  refused the same at the pre-claim gate. The head writer's own rows are
  no credential deposits and never meet it. The act that exists is an
  enrolment under an account of your own.

**The media door's four tokens** (media lanes A and B; §Media under
§Operations): `unbound_cell`, `unknown_cell_schema` and `lease_lapsed`,
PERMANENT like the family's, and `index_rebuilding`, RETRY — the rebuild window's
answer while the cell index is rebuilt at open, in the binding's position
alone — answered at the write path's media step — behind every gate above
and ahead of the store — to a value naming the picture cell's kind in a
draft, or at the owner's own shot; stated with their faces and their
interim standing at their own section.

**The registry sequence's family** (§Registry under §Operations): a
`make_link` typed the registry's binding or endpoint takes a sequence of
its own, whose refusals ride the same `rejected` shape under a code of
its own, `registry_refused` — `claim_first`, `signed_session_required`,
`not_doc_one`, `registry_form`, `malformed_record:<cause>`,
`attestation_required` and `attestation_invalid:<cause>` — the tokens
that family shares with this one spelled alike and never renamed, and
tabled with their classes at that section. The registry record's ATOM
takes this family's `record_sig_required` at its `insert`, as a
credential record's does: a record of the declared kind carrying no `sig`
lands nowhere.

Every publish-class write of the ten kinds on a claimed board is judged;
the system account's own writes (the head document's, owned by
`1.1.0.1`) are exempt by ownership and never dispatched. Every other
write, and every write at or below the claim, is outside the check and
answers as it does without one. Every credential deposit above the claim
is judged at the record grade; the ceremony's own deposits, at or below
it, are not.

The write order, as built. `unauthenticated` is slot 0 on every path: a
guest write (no token, unknown token, dead entry) answers M10's own
`unauthenticated` and never reaches a credential token. `not_owner`
stays `execute`'s own code — never a `credential_refused` detail — and
resolves AFTER every token below.

**Ordinary (non-deposit) writes** pass four gates, in the built order
(PUB-6.36 as RES-195 places the `nullify` cells), after the actor resolves:

1. The MINT class:
   * `mint_home_first` — MINT-FIRST: a `fork` or `version` by a
     principal whose account's space has never held a document. Mint the
     home first (`create_new_document`, which becomes the account's
     doc 1).
   * `mint_home_public` — the first-mint publication door (PUB-8.20): an
     explicit `published:false` on the **first** `create_new_document`
     into an empty account you own. The home is public from birth;
     create it flagless (or `published:true`), then later documents may
     be private. A non-owner answers `not_owner` instead, and a later
     mint refuses nothing.
2. The `replaces` class — `replaces_not_standalone` (PUB-5.15; RES-309,
   RES-310): a link write whose OWN type slot names the `replaces` type
   `1.1.0.1.0.1.0.3.12` — a `make_link`'s `ty`, an `emit`'s, an
   `edit_link` successor's, alone or beside a subtype of its own. The
   type has ONE writer, `make_link`'s `replaces` member (§Links), which
   deposits the link beside its record in one transaction; nothing
   deposits one by itself. PERMANENT. It answers the owner of every home
   the write names; anyone else falls through to `execute`'s own
   `not_owner` (or `home_not_registered`), as for any link. Ahead of the
   board-state gate, so the owner is told before being asked to claim,
   to sign or to attach an `attest`.
3. The board-state gate, one arm per mode:
   * claimed — `signed_session_required` (the publish class): a
     bare-session op whose write lands in the PUBLISHED world. The
     inputs (PUB-6.43): an **explicit** `published:true` on any mint
     (`create`/`fork`/`version`) except the exempt content-empty home
     mint; a flagless `version` of a **published** source (the inherit
     resolving published); an `insert`/`delete`/`copy`/`rearrange`
     whose `doc` is a published document the caller owns — a version
     member reading as its document (PUB-2.15, §Arrangement); a link
     write homed in one (`edit_link` reads BOTH its deposits' homes
     — the successor's `d_s` and the supersession claim's `d_a` — a
     bare edit refused where either is published, registration and ω on
     both standing ahead); and — PUB-6.43's `nullify` row — a
     `nullify` whose record `home` OR whose
     `target` link's own home is published (a retraction LANDS at its
     target, so a draft-homed record against a published-homed link is a
     published write, while a draft-homed record against a draft-homed
     target stays a draft write). A foreign or unregistered argument
     answers `execute`'s own code instead (`not_owner`,
     `*_not_registered`) — for `nullify`, ω on BOTH the home and the
     target stands ahead of the gate, so a caller owning either alone
     answers `not_owner` and is never told what is published. Signed
     sessions, draft mints (flagless or `published:false`), draft writes,
     bare reads, `delegate` and the home mint itself are outside the gate.
   * unclaimed — `claim_first`: an unclaimed daemon admits only the
     ceremony's own shape — `delegate` from principal 0, a
     `create_new_document` into an account holding no documents, an
     `insert` into the caller's own doc 1 — from bare and signed
     sessions alike; every other write refuses. Reads are untouched.
4. The `nullify` CLASS — three cells, one for each class of target link
   the write path recognizes off its own type-recognition input (the
   credential kinds, the GRANTS class, and PUB-6.64's audit-view classes;
   a subtype by prefix is its class's member). Evaluated **behind** the
   board-state gate (PUB-6.36 slot 5 behind slot 4): a session that may
   not write here is never told what the target link is — so pre-claim
   any `nullify` answers `claim_first` (the unclaimed arm), and once
   claimed a BARE owner's retraction that lands in the published world
   answers `signed_session_required` (the gate's `nullify` row above),
   never a class token. Once claimed and admitted by the gate, the
   record's OWNER gets the token while any other caller falls through and
   answers plain `not_owner`, byte-identical to its answer on a plain link
   (an entitlement scope, not a second rule; PUB-6.9's ω-first order):
   * `nullify_not_retraction` — the target is CREDENTIAL-typed: retraction
     never edits the key table (PUB-6.10; the token reaches the owner of
     the home the record is filed in).
   * `nullify_not_revocation` (PUB-6.30) — the target is GRANT-typed
     (`1.1.0.1.0.1.0.3.90`, §The read predicate). The grant fold reads
     the audit view, so retraction is
     never a second revocation path — a share is withdrawn by REVOKING it
     (a superseding grant record naming the grant's address). The token
     reaches the owner of BOTH the record's home and the target.
   * `nullify_audit_view` (PUB-6.64) — the target is of a class whose
     honored state is read under the AUDIT view, so a landed retraction
     would drop the record
     from the active-view reads that serve it (`find_links_*`, `count_*`,
     `window_*`) while the record still counted: the succession pair —
     `successor-of` `1.1.0.1.0.1.0.3.59` and the delegator endorsement
     (`endorse`, `1.1.0.1.0.1.0.3.42`); the consumption marker
     (`1.1.0.1.0.1.0.3.91`) and the journal designation
     (`1.1.0.1.0.1.0.3.22`); the rail record (`1.1.0.1.0.1.0.3.60`);
     the steward's classification link (`1.1.0.1.0.1.0.3.61`) where the
     LINK's OWN HOME is published — draft-homed, it is an ordinary link
     and its owner's retraction lands; the `replaces` link a grant is
     deposited with (`1.1.0.1.0.1.0.3.12`, §The read predicate): its
     retraction would leave every active-view read of the pair naming the
     EMPTY state for a grant that named a revocation; and the registry's
     three classes (§Registry under §Operations) — the binding
     (`1.1.0.1.0.1.0.3.55`), the takedown record (`1.1.0.1.0.1.0.3.57`)
     and the policy link (`1.1.0.1.0.1.0.3.58`), each with its subtype
     rows by prefix — the endpoint (`1.1.0.1.0.1.0.3.56`) OUTSIDE by the
     same test, read on the active view with its org's own retraction
     landing. ONE code for the class list; a
     client splits the
     face by the target's type, which the owner can read. The classes are
     the members' list, never the boundary: the next audit-view class
     joins the list and inherits the code. The R20 edition claim
     (`…3.14`) is OUTSIDE by the same test — read under the ACTIVE view,
     so its owner's retraction clears the state its faces read and is
     admitted. The token reaches the owner of BOTH the record's home and
     the target.

**Credential deposits** — a write whose TYPE slot names a credential
type (§The claim ceremony and credentials) — run a stricter order:

* Ahead of any lock, the shape slots: `emit_not_make_link` (every
  credential-typed `emit`, unconditionally — the emit path's dedup
  could phantom-ack an act `key_set` never shows), `resolved_from`
  (a credential `make_link` whose `from` or `to` is the V-spec form —
  deposit slots are address-form — and every credential-typed
  `edit_link`), and `replaces_not_credential` (a credential-typed
  `make_link` carrying a `replaces` member: a credential deposit's
  `replaces` row is EMPTY by kind — the credential class's fold is a
  set — so the member names a state no credential record replaces, and
  the record's `sig`, made over the empty row, could cover no link it
  would deposit; PERMANENT, from every hand).
* Under the credential write lock, the identity fold's own verdict —
  a deposit the fold would record but never honor is refused up front
  with the fold's token: `malformed_shape`; `not_doc_one` (the home
  pin: a credential link homed in a document of its account other than
  doc 1); `no_holder`; `not_genesis_registry`; `not_holder_retirement`;
  `would_empty` (a retirement naming the whole enrolled set);
  `nothing_changed`; `already_claimed`; `claimant_keyless`;
  `claimant_not_top_level`; `unpublished` (the deposit's home is a DRAFT
  document — read off the journaled bit, ahead of the home pin and of the
  payload parse, so a draft-homed deposit answers it whatever its record
  says); and the payload joins
  `malformed_payload:<sub>` with `<sub>` one of `too_large`,
  `foreign_content`, `missing_value`, `not_utf8`, `bad_record`,
  `duplicate_key:<n>`, `empty` (`<n>` a 1-based ENTRY index into the
  record's `keys`/`fingerprints` array).
* Then the daemon's own slots, in order: ONE slot holding TWO tokens, in
  this order — `preview_key` FIRST (an enrollment record naming ANY key
  of the preview kind, `fndsa512-preview-ed25519`, on a daemon launched
  without `--allow-preview-keys` (§The claim ceremony and credentials) —
  EVERY enrollment record, a genesis included; the test reads the
  entry's `alg` and decodes nothing, so a preview key that also fails to
  decode answers this token; the face: "this is a PREVIEW key, and this
  board enrolls no preview keys — make a key with a released client and
  enroll that"), then `undecodable_key` (valid-hex key bytes ANY HALF of
  which does not decode — the Ed25519 half to no point, the post-quantum
  half to no key, the FN-DSA half's header byte among its checks — can
  never sign, no half carrying a signature alone; refused at enrollment
  rather than discovered at a handshake);
  `too_many_enrolled` (the enrolled-set cap, **16** — daemon policy,
  raisable without format consequence; the enroll arm only, the
  ceremony's genesis exempt); then ONE slot holding TWO tokens, in this
  order — `content_session` FIRST (ANY credential-typed deposit — an
  enrollment, a retirement or a claim — from a CONTENT-scoped session,
  §Sessions: whatever key opened the session and whether or not the act
  is an anchor act, so an anchor key's content session answers this and
  never the token behind it; the act needs a FULL session), and behind
  it `anchor_session_required` (an anchor retirement, or a post-genesis
  anchor-flagged enrollment, requires a session an ANCHOR key of that
  account established — a bare session never satisfies it. A genesis is
  exempt — the seeding hand records the initial set, flags included —
  EXCEPT AT A HANDOFF, which the daemon tells by ADDRESS and by nothing
  else: a genesis is measured at the nearest KEYED account above its
  address, the account whose keys open it. Beneath that account's agent
  space — a child of its first sub-account `X.1` — it is a HIRE's;
  beneath an AGENT — a keyed account itself standing at `P.1.n` beneath
  its own nearest keyed account `P` — a SPAWN's; into a direct child of
  a forked lineage's SEAT — the blocked-prefix list's binding-writing
  account where the operator's header names one that is not the
  claimant, that seat's own first sub-account apart — an ADMISSION's:
  each device-grade, committing from any signed session. ANYWHERE ELSE
  beneath a party's keys — that account's first sub-account ITSELF, the
  agents' home, included, wherever the fold honors the genesis at all: a
  bootstrap-delegated, top-level account's first sub-account takes none,
  the fold's own verdict above answering `not_genesis_registry` from
  every hand, an anchor session included, and standing ahead of this
  slot — it is that party's HANDOFF, and wherever the
  set that opens the account holds an anchor it requires a session an
  ANCHOR of THAT set established, a bare session never satisfying it;
  where that set holds no anchor the handoff stays device-grade. A
  top-level account's own genesis — the ceremony's, an invite's — has no
  keyed account above it and meets no gate here); and the two
  board-state arms again — claimed: `signed_session_required` for ANY
  bare-session deposit, genesis included, and then, still claimed, THE
  RECORD GRADE (signed ops, 2a; §The claim ceremony and credentials):
  `attestation_required` where the record carries no `sig`, and
  `attestation_invalid:<cause>` where it carries one that no key of the
  set that opens the record's home — the anchors alone where the act is
  anchor-grade — verifies over the `record` frame as of the deposit's
  base (`signature`, `not_enrolled_at_position`, `malformed`, above);
  unclaimed: `claim_first` for any deposit other than the ceremony's own
  genesis and claim. The tokens ahead of `content_session` stay ahead: a
  content session's retry of an act another session committed still
  answers the fold's own token (`nothing_changed`, `already_claimed`).
* Behind the unclaimed arm, the CLAIM's own admission — `claim_residue`
  (PUB-6.63, PUB-6.35 clause (b); AUTH RES-202; beside `claim_first` in
  the pre-claim tokens'
  convention): the claim deposit is admitted only where the top-level
  account space — the accounts delegated under the claimant's node —
  holds EXACTLY ONE principal above the genesis floor, the one this
  ceremony's own `delegate` minted, and is refused otherwise from every
  hand, bare and signed alike, the cure verbatim: "this board carries
  pre-claim residue — re-genesis before claiming." The residue is another
  hand's keyed partial (steps 1–4 by a stranger at an exposed port) or
  the operator's own abandoned partial beside its lost-state retry; the
  input is the same frontier `next_account_prefix` answers under the node
  (`1.0.1` on a board with no residue) — cardinality and never provenance
  (the latch, not the id's secrecy, is what makes the one counted
  principal claimable by its minter alone); the floor is what the
  daemon's own genesis seeded — no top-level account today, computed from
  the genesis rather than assumed. A refused claim commits nothing and
  the board stays unclaimed, claimable by nobody until re-genesis. The
  fold's own verdicts stand ahead of it: an `already_claimed`,
  `claimant_keyless` or `claimant_not_top_level` claim never reaches this
  token.

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

The optional `published` field is the three-valued publication flag:
`true`, `false`, or absent (absent and `null` alike). The wire
default is **private**. Absent resolves at the substrate: your account's
**first** document is born **published** — it is your home page, where the
board keeps your name and your keys — and every later flagless document is
private. `true` publishes, `false` keeps it private. One refusal is pinned:
an explicit `published:false` on the **first** mint into an empty account is
refused `credential_refused:mint_home_public` (permanent) — the home is
public from birth; create it first, then everything else is private by
default.

On a CLAIMED board a mint BORN PUBLISHED — an explicit `published:true`
into an account that already holds a document — carries the optional
top-level `attest` member (signed ops; §Credential refusals, the entry
frame's rows): the entry signature over the frame whose `doc` is the
PARENT ACCOUNT the document lands in — `account` itself, so the
signature attests that this principal performed this kind of act on this
board against this parent and nothing else — `op` `create_new_document`
and `body` EMPTY: the member present and empty, `be32(0)`. No minted
address enters the frame, so a client signs before the commit; two such
mints by one principal sign identical bytes, which the design accepts. A
later reader derives the parent account by `effective_owner` over the
minted document and composes the same frame. The account's first,
flagless mint — the home — is outside the publish class and takes no
`attest`.

**`delegate`** — carve `new_prefix` off your account (or node) and register
principal `new_id` as its owner, atomically. Obtain `new_prefix` from
`next_account_prefix`; only the owner of the parent may delegate under it. A
principal prefix names a delegation path, so it is capped at 64 components —
deeper is `too_deep`. → `ack_addr` (the minted account address). A
`new_prefix` that is not T4-valid is `not_valid`; one that is not
account-tier (its zero component must be exactly one) is
`not_account_tier`; one with a principal already registered strictly
under it, `not_top_down`.

`new_id` is bounded at the parse: a value above **2^53 − 1**
(`9007199254740991`) is refused as any malformed frame is — the
`unparseable` rejection, `malformed`, `permanent`; no code or token of its
own — and nothing commits. That is the largest integer a JSON number carries
exactly: past it every JavaScript-backed READER of the wire — the browser's
guest reader among them, which reads a principal as a JSON number — rounds,
and would show or link the WRONG account wherever it names one; the Rust
frontend reads the number exactly (the browser opens no session and signs
nothing). The bound is kept for the wire's JSON readers: an id such a reader
cannot say back is registered by no board. A client minting `new_id` at
random draws it inside the range — 53 random bits, never a full `u64`.

<!-- wire: request delegate -->
```json
{"new_id":2,"new_prefix":"1.0.2","op":"delegate"}
```

**`register_node`** — admit a provisioned node address (bootstrap
provisioning; the address is supplied, not minted). A node address names a
provisioning path, so it is capped at 32 components — deeper is `too_deep`.
→ `ack_addr`. An `addr` that is not T4-valid is `not_valid`; one that is
not a descendant of the bootstrap node `1` is
`not_descendant_of_bootstrap`.

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

`fork` takes the same optional `published` flag as `create_new_document`
(`true` | `false` | absent), resolved the same way at the substrate
(the store's own resolution, the same as the create path's) — a
first fork into an empty account is refused `mint_home_first` before the
flag matters, and a later fork is private by default. A forked draft is
the sibling draft the version-chain refusals point you to (§The
version-chain refusals): edited in place, and versionless until it is
published as an edition of its own. On a CLAIMED board a fork born
published (`published:true`) carries the optional top-level `attest`
member exactly as a mint born published does (`create_new_document`
above): `doc` the principal's own account, `op` `fork`, `body` EMPTY.

**`next_account_prefix`** — the next delegable prefix under `parent`
(what `delegate` demands). → `maybe_addr` (`null` = ineligible parent, or a
next slot past the 64-component depth cap).

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

**`effective_owner`** — who owns `addr`: the LONGEST registered prefix
containing `addr`, and the principal seated at it, from one walk of the
board's principal list. The one argument is `addr` — any address, in this
board's own local form (the form `delegate` takes and `principal_prefix`
answers); it need NOT be allocated, and there is no document argument.
→ `effective_owner`: `{prefix, principal}`, both always present, carried
together, and `null` TOGETHER only where no registered principal's prefix
contains `addr` (an address not under this board's node `1`).

An account is **allocated** — a seat of its own — **iff `prefix` equals
the address you asked**, and that equality is the one test to make. Any
other `prefix` names the nearest seat ABOVE `addr`: an unallocated first
sub-account `X.1` answers `X`'s own prefix and `X`'s own principal, never
nothing, so a non-null answer alone says nothing about allocation. This is
how a client resumes when its `delegate` of `X.1` answers `not_authorized`
because the address is already a seat: read `effective_owner` of `X.1`,
and take `principal` only where `prefix` is `X.1` itself.

Public, immutable registry data, like `principal_prefix`: NO session is
needed and nothing is withheld — a guest and a bound principal are answered
byte-identically — and it is served on `/op-at` too, as of any committed
position (the seat above at a position before the `delegate` that
allocated `addr`, the new seat from that position on).

In the example `1.0.1.1` is NOT allocated: the answer (§The response
envelope's `effective_owner` example) names `1.0.1`, the seat above it, and
that seat's principal.

<!-- wire: request effective_owner -->
```json
{"addr":"1.0.1.1","op":"effective_owner"}
```

**`doc_metadata`** — the publication metadata a client needs to run
PUB-3.19's admission test itself: whether `doc` is published, its
owner account, and its birth version with that
version's birth content (`birth_extent`) — a client images one edition's
content over positions `1` through `birth_extent` of the birth version
to decide admission, and reads nothing else here. That extent is what
the edition was BORN with: a deposit the edition took while its birth
version was still the head lies past it and is no part of what a claim
is compared against, so a deposited edition still matches. `doc` is
a document argument (unreadable → `withheld`; unregistered →
`doc_not_registered`); a version member answers its DOCUMENT's state.
→ `doc_metadata`.

<!-- wire: request doc_metadata -->
```json
{"doc":"1.0.1.0.1","op":"doc_metadata"}
```

### Identity reads

**`key_set`** — the credential table of `account`: who can sign for it,
now and historically. Principal-free — exempt from the read predicate
(§The read predicate; PUB-6.50: it reads credential records alone, born
published by law), so NO session is needed and a guest and a bound
principal are answered byte-identically; the no-session read is
deliberate — and served on `/op-at` too, as of any committed position
(the same
dispatcher; the identity table rides in the reconstructed world, folded by
the same replay in commit order, under the reconstruction budget like every
historical answer). A non-account address rejects with the code
`not_an_account` (`reorder`); a keyless account answers empty
lists; an `id` is accepted and ignored, as on every read. → `key_set`.

```json
{"account":"1.0.1","op":"key_set"}
```

### Arrangement (document editing)

Ownership: `insert`, `delete`, and `rearrange` require the session
principal to own `doc`; `copy` requires owning the **destination** `doc`
only — its source spans may read any content the principal may READ
(transclusion is unrestricted across the published docuverse and
qualified for drafts: a source you may not read is `withheld`, §The
read predicate); `publish` requires owning `doc`, and its runs'
origins must be READABLE to the principal (§The publish shot and
head-float). A non-owner gets `not_owner` (permanent) with the document
in `site.addr`. `version` is deliberately un-owner-gated: forking a
foreign document into your own account IS the sanctioned "propose a
change" path. That sentence carries qualifications, none an
ownership gate: `mint_home_first` (a principal whose account holds no
documents must mint its home before `fork`/`version`); on a claimed
board, `signed_session_required` for a flagless `version` of a PUBLISHED
source from a bare session (§Credential refusals); and the
source consult — a `d_src` you may not read is `withheld` (§The read
predicate).

Publication: a PUBLISHED `doc` — or a version member of one, which
is judged as its document (PUB-2.15) — refuses the four in-place edits
`published_target` (§The version-chain refusals), behind the ownership
check and ahead of every shape check, from signed sessions too. A draft
is edited in place. The one thing a published document admits
is the **declared deposit** below — and it advances by the **shot**,
`publish`. Once a shot has landed, a bare document address reads
as its trunk HEAD in every arrangement reader (head-float), and a
declared deposit into the chain lands in the head member's arrangement
(§The publish shot and head-float).

**`insert`** — insert content into `doc` at V-position `at`; each element
of `values` is a §Content values write form. → `ack_addr` (the first
minted I-address). `content` and `gate` are defences (§Rejection codes):
M4's no-overwrite and M3's inc gate, which no well-formed request
against a healthy store reaches. This example inserts **eleven
single-byte values at eleven positions** — the string form is per-byte:

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

The optional top-level `attest` member — `{"alg": <an ALGS token>,
"sig": <hex>}` — is THE ENTRY SIGNATURE (signed ops): on a CLAIMED
board an `insert` that lands in the published world must carry one,
made by a hybrid key enrolled on the writer's account as of the write's
base over the entry frame `framed("skep-entry-v1", [alg, board,
account, doc, op, body])` — `board` the head document `H.1`'s
`(position, chain)` pair (§The other endpoints), `account` the writer's
account, `doc` the document's trunk, `op` `insert`, `body` the declared
type and the values placed with their count — and the daemon verifies it
BEFORE the transaction (§Credential refusals: `attestation_required`,
`attestation_invalid`) and writes it into that commit's marker slot. A
declared deposit of a credential kind is the one `insert` this does not
reach: its signature is the record's own `sig` member, verified at the
`make_link` that deposits it (§The claim ceremony and credentials).
Below the claim the member is dropped unread; a daemon that predates it
refuses it as an unknown field.

The optional `deposit` field is the **deposit declaration**
(PUB-2.59, PUB-9.13), and ITS VALUE IS THE RECORD CLASS's TYPE (PUB-2.11,
PUB-2.64): a type ADDRESS string, saying this insert is a record atom of
that deposit class — a credential record, say — landing at fresh
positions past the document's arranged extent. It is the type the
`make_link` naming the atom then carries (PUB-2.63): the declaration is
the claim, and that link is where the pair bears it out. ABSENT is the
one spelling of "not a deposit"; a present field must be an address, so
`true`, `false`, `null` and any other non-address are a parse fault
(`malformed`), never read as either arm. The write path keys on the
declaration AND TESTS THE TYPE IT NAMES: a published document admits an
`insert` if and only if it is declared, the declared type is one the
deposit class holds, AND the insert is deposit-shaped — `at` a content
position past every arranged one, disturbing no arrangement. The types
held are the classes that deposit an ATOM — today the two credential
records, **enroll `1.1.0.1.0.1.0.3.1`** and **retire
`1.1.0.1.0.1.0.3.2`**, by exact address (a subtype beneath one is no
member); a class whose record is its typed link alone — the grant, the
edition claim, `successor-of`, `published-in-error`, the claim link —
deposits no atom and is never among them. An undeclared append on a
published head is an in-place edit and refuses `published_target`, and
so does an insert declared under any other type, wherever it lands, and
a declared insert at an arranged position or outside the content
subspace. A declared insert past the append boundary, under a type the
class holds, answers the arrangement's own `out_of_bounds`. The test is
of the TYPE alone — the daemon cannot tell a record from prose at the
`insert` — so bytes declared under a held type are admitted, a malformed
record of the class they name, honored for nothing (PUB-2.60). Into a
draft the declaration is inert, whatever it names. The canonical frame
carries the field only when the declaration is made, as the address it
named. This example deposits one enrollment record atom at the head's
second position:

<!-- wire: request insert -->
```json
{"at":{"ordinal":"2","subspace":"1"},"deposit":"1.1.0.1.0.1.0.3.1","doc":"1.0.1.0.1","op":"insert","values":[{"atom":"one credential record"}]}
```

**`delete`** — remove `width` positions of `doc` starting at `p`. → `ack`.
A `p` whose ordinal names no arranged content position is `not_arranged`.

<!-- wire: request delete -->
```json
{"doc":"1.0.1.0.1","op":"delete","p":{"ordinal":"3","subspace":"1"},"width":"2"}
```

**`copy`** — transclude the given source spans into `doc` at `at` (shared
identity, not copied bytes). → `ack`. A net placement that is empty once
the specs are clipped is `empty_result`.

<!-- wire: request copy -->
```json
{"at":{"ordinal":"6","subspace":"1"},"doc":"1.0.1.0.1","op":"copy","specs":[{"source":"1.0.1.0.2","span":{"start":"1.1","width":"0.5"}}]}
```

**`rearrange`** — pivot/swap `doc`'s content about the cut positions.
→ `ack`. A `doc` whose content subspace is empty is
`empty_content_subspace`.

<!-- wire: request rearrange -->
```json
{"cuts":[{"ordinal":"1","subspace":"1"},{"ordinal":"3","subspace":"1"},{"ordinal":"6","subspace":"1"}],"doc":"1.0.1.0.1","op":"rearrange"}
```

**`version`** — the content-sharing, copy-on-write fork of `d_src`.
→ `ack_addr` (the new version's address). A caller id that names no
principal is `not_a_principal`; a cross-owner `version` by a node-tier
principal is `node_tier_cross_owner` — an account-tier forker is
required.

<!-- wire: request version -->
```json
{"d_src":"1.0.1.0.1","op":"version"}
```

`version` takes the optional `published` flag (`true` | `false` | absent).
Absent means **inherit** `d_src`'s state: a version of a published document
is published, a version of a draft is a draft. `true` publishes, `false`
keeps the new version private. On a claimed board a bare session's `version`
that lands in the published world — an explicit `true`, or a flagless
version of a published source — is refused `signed_session_required`
(§Credential refusals), and a signed session's carries the optional
top-level `attest` member (signed ops; §Credential refusals, the entry
frame's rows): the entry signature over the frame whose `doc` is the
PARENT ACCOUNT the new member or the fresh document is minted under — the
acting principal's own account, at an owned and at a cross-owner `version`
alike, never the trunk of `d_src` — `op` `version` and `body` EMPTY
(`be32(0)`, the member present); `d_src` enters no row. A later reader
derives the account by `effective_owner` over the minted member or
document and composes the same frame.

Where you own `d_src`, the new version is a MEMBER of its chain —
`1.0.1.0.1.1`, `1.0.1.0.1.2`, … — and both the publish gate and the
store's refusals read the DOCUMENT a member projects to, never the
member's own bit (PUB-2.15): a write homed in `1.0.1.0.1.1` is judged
exactly as a write into `1.0.1.0.1`. The version chain is publication's
own (§The version-chain refusals): where you own `d_src` and it is
PRIVATE, `version` refuses `private_source_versionless` whatever the flag
— private documents are versionless; mint a sibling draft (`fork`,
`create_new_document`) to hold the alternative, or publish by minting a
separate edition. Where you own `d_src` and it is PUBLISHED, an explicit
`published:false` refuses `private_version_of_published` — every member
of a published chain is published, so no member's journaled bit ever
differs from its document's, and the dump's `publication.drafts` never
lists one. Where you do not own `d_src`, `version` is refused by neither
rule: it mints a fresh document in your own account — the source's state
where the flag is absent, your flag where it is not — gated and judged
by its own bit.

**`publish`** — the SHOT: append the next member of `doc`'s
version chain, born published, in one commit, its arrangement the
client's own `runs` (§The publish shot and head-float). `base` is the
member the draft was staged from — `doc` itself while the chain is
empty — with `base_extent` the number of content positions the staged
copy took, both present or neither (neither is the birth version);
`draft` names the staging draft whose runs are re-inserted as fresh
identity under `doc`'s own I-space; each run is `origin`, `i_start`,
`width`. Owner-gated, and the publish class's input from any session.
On a CLAIMED board the shot carries the optional top-level `attest`
member (signed ops; the object `insert` describes): the entry signature
over the frame whose `doc` is the trunk document, `op` `publish` and
`body` THE COUNT, THE RUNS THE CLIENT PLACED IN THE ADDRESS FORM, AND
THE BASE EXTENT (the design record's V, l6-A4 and D25 — the publish
signature binds its base extent, and the runs are signed as the MEMBER
holds them): first `be64(placed)`, the number of positions the runs
cover; then the runs in V-order as SEGMENTS, each opening with one class
byte — `0x02` a VALUE STRETCH, the maximal run of consecutive positions
the commit COPIES IN (a run of `doc`'s own I-space placed by reference,
and a run of the staging `draft` re-inserted as fresh identity — at the
member, one origin, the document's own), spelled `be64(count)` then each
value `be32(len) ‖ bytes`; `0x01` a WINDOW, one run onto ANOTHER
document's I-space, which the commit keeps as a reference, spelled
`be32(len) ‖ its i_start's dotted decimal ‖ be64(width)` — two I-adjacent
windows in a row being ONE segment, as the member's arrangement merges
them; then THE BASE GROUP, one length-delimited group — EMPTY (`be32(0)`)
where the shot has no base, else the base MEMBER's address as an
address-form slot row of one element (`0x01 ‖ be64(1) ‖ be32(len) ‖ the
dotted decimal`, the form the `record` body's optional rows take) followed
by `be64(base_extent)`. So the signature binds the base, member and
extent both: `base` is no member of the frame, but a verifier DERIVES it
from the minted member's address — a trunk member `D.k+1` was minted
against `D.k`, a daughter `X.m` against `X`, a birth version `D.1` against
the memberless `D` — and composes it INTO the preimage; the same signed
shot re-submitted naming another base, the trunk's current head say,
spells another group and is refused `attestation_invalid:signature`. A
window is signed by WHERE it quotes from and never by its bytes, so the
author attests a window it may no longer read; the origin's own entry
binds the bytes. The daemon composes the same body off its snapshot — the
values of the copied runs read there, the windows spelled from the
request, the base as the request names it — and verifies before the
transaction; a reader holding the member later composes it again from
the member's runs over its first `placed` positions, its `doc_metadata`
terms and its address, with no request in hand (§Namespace,
`doc_metadata`). A REPLAYED shot verifies as it did and names a `base`
its own commit left no longer the head, so the store's rule mints that
base's DAUGHTER, never the trunk's next: the document's current text does
not move.
→ `ack_addr` (the member's address). `content` and `gate` are defences,
as at `insert` (§Rejection codes). This example publishes a draft
staged off the second member: the edition's own three positions by
reference and the draft's two as fresh identity:

<!-- wire: request publish -->
```json
{"base":"1.0.1.0.1.2","base_extent":"3","doc":"1.0.1.0.1","draft":"1.0.1.0.7","op":"publish","runs":[{"i_start":"1.0.1.0.1.0.1.1","origin":"1.0.1.0.1","width":"3"},{"i_start":"1.0.1.0.7.0.1.1","origin":"1.0.1.0.7","width":"2"}]}
```

### Media — the reference cell and its door (lane A; the fence) and the upload (lane B)

A PICTURE is a document whose content is ONE REFERENCE CELL — a composite
value (`{"atom": "<str>"}`, §Value encodings) whose bytes are one JSON
object naming its kind (DOCTRINE D13): the cell's `type`, the `hash` of
the file's bytes and the file's `size`, and nothing else. What this
build carries is media's WRITE-PATH HALF, fenced before the first served
board (the media record's §The publication seam; STOP-2) — the daemon
PARSES the cell at every `insert` and every `publish`, by one parser
under one rule, and admits one only where its hash is a deposit of the
caller's own or a reference its own cells already make — THE UPLOAD: the
resumable PUT, the blob store under `blobs/` in the data dir (the files,
the partials, the upload records and the lease log), the gate's three
scopes, and the deposit read — and, beside them, THE CELL INDEX the base
and the pruner read, THE READINESS REFUSAL of its three readers, and THE
PRUNER's pass (each below) — and THE FETCH: `GET /blob?i=<address>` serves
a picture's whole file by the I-address of its cell, gated by the read's
own predicate, the file checked against the cell before its first byte
(below). A second cell kind rides beside the picture's: THE BLIND
DOCUMENT's cell, a commitment the board holds no byte of a file for, read
by the one classification the door and the fetch run for both (below).

**The cell's schema (v1).** ONE JSON object, three members in THIS
order, no whitespace, nothing else:

| member | JSON type | value |
| --- | --- | --- |
| `type` | string | the cell kind's address — INTERIM `1.1.0.1.0.1.0.3.89` (the pins below) |
| `hash` | string | BLAKE3's default hash of the file's bytes: 32 bytes, written as 64 LOWERCASE hexadecimal characters |
| `size` | number | the file's byte count: an integer, `0` to 2^53 − 1 |

The canonical form is exactly
`{"type":"1.1.0.1.0.1.0.3.89","hash":"<64 hex>","size":<count>}`, and
THE ONE RULE at every parser of a cell — the daemon's, the shell's, the
browser page's — is the record's own admission rule (§The claim ceremony
and credentials) applied to the cell: `parse(b)` answers a cell only
where `b == encode(parse(b))`. So a second `hash` member, a `size` as a
string, an `extent` member (the v1 cell carries none — the extent is
video-era), the members in any other order, uppercase hex, a hash of 63
or 65 characters, a space, a trailing byte — each is NO CELL, at every
parser alike, and a body past the cell's cap — 1024 bytes — is parsed by
no reader of a cell at all. The admitted and refused strings are ONE
VECTOR SET, `crates/skepd/tests/it/fixtures/media/cells.json`, which
every parser of the cell runs in its own gate; a parser is never derived
from another parser.

A value NAMES THE KIND when its `type` member is the kind's address,
whatever the rest of it holds — read by the parse within the cap and,
past it, by THE CANONICAL OPENING every schema's canonical form writes
first, `{"type":"<the kind's address>"`: the cap bounds the parse and
never the classification. A value naming the kind that is no v1 cell — a
second schema's form, a malformed one, the two-hash body, a body past the
cap that opens as the kind — is one the daemon HALTS on at a permanent
act, naming it (D13's carve-out), never one it admits as absent: admitted,
it would stand unbound the day a second schema is pinned, whatever cap a
later build pins. A value that does not name the kind — prose, a predicate
def, a record of another kind, a body past the cap that opens as no kind
— is an ordinary value and meets nothing here.

**The designation.** The cell's schema names its hash function
`blake3`, and the hash is FROZEN as an algorithm tag is: a change is a
second schema under the same kind, never an edit to this one. Where a
hash becomes a key — the blob store's `blobs/<designation>/<hex>`, the
lease, the index, from lane B — the designation and the hex are the key
together, so a second schema's hash of the same width is never read
under this one's rule.

**The blind document's cell (v1).** A SECOND KIND beside the picture's,
for a media document whose picture is kept on its OWNER's own machine: the
board holds a COMMITMENT to the file and never its bytes. ONE JSON object,
two members in THIS order, no whitespace, nothing else:

| member | JSON type | value |
| --- | --- | --- |
| `type` | string | the blind kind's address — INTERIM `1.1.0.1.0.1.0.3.88` (the pins below) |
| `commitment` | string | 32 bytes as 64 LOWERCASE hexadecimal characters — a keyed hash the owner's client computes, confirming nothing to a holder of a candidate file |

The blind cell carries NO `size` and NO `hash`: nothing in it names a file,
and nothing the board does for one reads a file, a lease or an index entry.
The canonical rule is the picture's — `parse(b)` answers a blind cell only
where `b == encode(parse(b))` — so a `size` member, a `hash` member, a
second `commitment`, the members reordered, uppercase hex, 63 or 65 hex
characters, a space, a trailing byte each is NO CELL, and a body past the
cap — the SAME 1024-byte cap, one for every media cell kind — is parsed by
no reader of a cell at all. The blind cell's own vector set,
`crates/skepd/tests/it/fixtures/media/blind-cells.json`, mirrors the
picture's and is run by every parser in its own gate.

ONE CLASSIFICATION reads both kinds: a value's `type` is read once, and the
named kind's own schema check follows — so two kinds cost one JSON tree,
under one cap. A value naming EITHER kind under no schema this build reads
is the halt below; a value naming neither kind is ordinary.

**The door.** ONE step of the write path, taken after the plain
sequence's admission — the mint class, the `replaces` fence, the
board-state gate and the write-path check (§Credential refusals) all
stand AHEAD of it — and before the store, on the locked snapshot the
commit will read, so the check that passed and the commit it guards are
one interval. It reads the op's values — an `insert`'s, and for a
`publish` the values of the staging draft's own runs, the ones the shot
would re-insert as fresh identity, read only where the shot passes the
store's own admission through its source gate, the draft is readable to
the caller, and the re-insert is within the shot's budget — and answers
every value naming the kind, in this order:

| code | op | disposition | when |
| --- | --- | --- | --- |
| `published_target` | `insert` | permanent | `doc` is a PUBLISHED document (or a member of one) the caller owns, WHATEVER the insert's `deposit` declaration: the declared deposit is M5's one door at a published target and it judges the TYPE, not the atom, so this arm is what refuses a cell declared under a deposit class — ahead of both refusals below, and the same code M5 answers an undeclared insert |
| `not_owner`, `site.addr` the draft | `publish` | permanent | a draft-native run of the shot holds a value naming the kind and the caller does not OWN the draft (ω, exact — the same test `not_owner` makes of `doc`): a grantee's, an ancestor's or a descendant's shot naming the owner's draft re-mints no cell |
| `credential_refused`, `detail` `unbound_cell` | `insert` into a draft; the owner's own `publish` | permanent | the value is a cell naming a hash this principal did not deposit under its own lease — THE BINDING's refusal (lane B), read off this principal's own lease record first and never off the file's presence: never deposited, lapsed past the horizon, another account's deposit of the same bytes, or a deposit whole on disk whose length the cell's `size` contradicts (the size check, at the same door); permanent for the request as sent — the act that exists is a PUT of the bytes, then the cell the PUT's answer spells |
| `credential_refused`, `detail` `unknown_cell_schema` | `insert` into a draft; the owner's own `publish` | permanent | the value names the kind and parses under no schema this board reads — D13's halt at a permanent act, so no second schema ever finds an unbound cell planted under this one; the same bytes are never admitted, and the act that exists is a cell in the form above |
| `credential_refused`, `detail` `lease_lapsed` | `insert` into a draft; the owner's own `publish` | permanent | the value is a cell naming a hash this principal DID deposit, and the deposit is gone: the lease lapsed within the horizon, or is live over a file that is not there or not whole — the binding's LAPSED arm, told apart from `unbound_cell` so a resume can be written against it; the act is a re-PUT of the bytes, which re-takes the lease |
| `credential_refused`, `detail` `index_rebuilding` | `insert` into a draft; the owner's own `publish` | retry | THE REBUILD WINDOW: the cell index's rebuild at open has not completed, and the lease arm alone would have answered `unbound_cell` or `lease_lapsed` — a verdict the index arm, unread, may overturn; the readiness token re-used in the binding's position, during the walk alone, retry-class as the readiness refusal is: the same request may be admitted once the walk completes. A cell the lease arm admits in the rebuild window is admitted |

A cell naming a hash this principal holds a LIVE lease on, over a whole
file whose length the cell's `size` names, is ADMITTED: the insert commits
and the draft holds the cell. THE BINDING READS THE CELL INDEX FIRST: a
hash the requester's OWN cells already name is a REFERENCE, kept by no
lease — admitted where the file is on disk whole at the cell's `size`,
`unbound_cell` where the file is whole at the size those cells name and
this cell contradicts it (the size check), `lease_lapsed` where the file
is absent or not whole (the deposit is gone; the act is the PUT) — and
only then the principal's own lease. The index arm is read at the
requester's OWN account's hashes and never at the per-hash list of cells,
so its answer and its time are the same whether or not another account's
cell names the hash. So the owner's own `publish` of a draft holding an
admitted cell is admitted after the lease lapsed, the cell's file
standing, and a re-PUT of a file the account's cells name is charged
nothing at its own scope. Until the index's rebuild at open completes
(THE READINESS REFUSAL, below) the index arm is skipped and the lease arm
alone ADMITS: the door is not one of the index's readers and never waits;
where that arm alone would refuse, the door answers THE REBUILD WINDOW's state —
`credential_refused` with `detail` `index_rebuilding`, `disposition`
`retry` — never a permanent token, so the owner's shot of a draft whose
lease lapsed, its file whole, made during the walk, is answered
retry-class and admitted after the walk with no re-PUT.

THE KIND COLUMN: the arms above are read PER KIND. The picture's cell meets
every arm. THE BLIND DOCUMENT's cell meets `published_target` and
`not_owner` and the halt as the picture's does — a blind cell into a
published target is `published_target`, a reader's shot of a draft holding
one is `not_owner`, a malformed blind body is `unknown_cell_schema` — and
NEVER `unbound_cell` or `lease_lapsed`: it is ADMITTED into a draft and at
the owner's own shot with no deposit consulted, the board holding no byte of
a blind picture and there being no hash to bind. The same door, the same
order, one classification ahead of it.

The faces (PUB-6.7), the client's to render, the wire carrying the token:

* `unbound_cell` — "no deposit of yours here is this picture's cell as
  written: upload the file, then place the cell its answer spells." The
  face says that NO DEPOSIT OF THE PERSON's HERE IS THE CELL AS WRITTEN,
  and never that none was made: it is the answer too to a person who did
  deposit — past the horizon, or at an operator's honest nulls, a lease
  store the remediation discarded or a restore brought back older than its
  files. (P10's fence-only face, "this board takes no uploads", is RETIRED
  with the store at this arm: the face now names the deposit the cell
  lacks; on a board whose uploads are CLOSED the client keys the fence face
  off `/health`'s echo before this face speaks — THE UPLOAD SETTING,
  below.)
* `unknown_cell_schema` — "this value names a media cell — a picture's or a
  blind document's — in a form this board does not read." (The door's and
  the fetch's, one face for both kinds.)
* `lease_lapsed` — "this picture's deposit is gone: upload the file again."
* `index_rebuilding` — the readiness face, retried: "this board is still
  rebuilding its picture index after a start; try again shortly."

Everything the store and the gates ahead already answer stands, each
BEFORE this door: a stranger's `insert` into the owner's draft is
`not_owner`, an unregistered `doc` `doc_not_registered`, a bare
session's write into a published document on a claimed board
`signed_session_required`, an unsigned shot `attestation_required`, a
shot naming a draft the caller may not read `withheld`
(`attestation_invalid:withheld` where the base carries the run) — and
the door reads no value of a draft the caller may not read. A refused
write commits nothing. `copy` and `version` share identity and mint no
cell, so they take no arm. This example inserts a cell into a draft —
refused `unbound_cell` where the caller holds no lease on its hash:

<!-- wire: request insert -->
```json
{"at":{"ordinal":"1","subspace":"1"},"doc":"1.0.1.0.2","op":"insert","values":[{"atom":"{\"type\":\"1.1.0.1.0.1.0.3.89\",\"hash\":\"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262\",\"size\":5}"}]}
```

```json
{"code":"credential_refused","detail":"unbound_cell","disposition":"permanent","op":"insert","resp":"rejected"}
```

**The upload — the PUT** (media lane B; the media record's Op inventory
1, "THE RESUMABLE UPLOAD IS THE STANDARD SHAPE, STATED ONCE" — the tus
protocol's SHAPE, its creation, offset resume, expiration and
termination, and no byte of its wire). One path family, `/blob/upload`,
every method of it TOKEN-ACCEPTING (the session token resolved as `/op`
resolves it, the death signal carried the same) and CLASS-VARYING
(`Cache-Control: no-store`, `Vary: Skepd-Session`), every answer on it a
JSON body or a transport refusal — the family runs no `Op`, commits
nothing to the journal and takes no `Serial`:

| method & path | the act | answers |
| --- | --- | --- |
| `POST /blob/upload?length=<N>` | THE CREATION: admitted under the upload permit pool (THE PERMIT, below) — past it, `503 upload_busy`, retry-class, before any body byte, and NO upload is made; then `length` the upload's declared total in bytes, held against the per-file cap and the own scope BEFORE any body byte; then, before the partial and the record, THE STANDING-UPLOADS BOUND — the principal's standing uploads counted off its own records, a creation past the bound refused `507 deposit_refused` with `scope` `standing`, its `detail` naming the end of one of them as the act — and THE FLOOR read on NO declared length: the volume's free space already below the floor refuses the creation `scope` `floor`, an empty upload's and a creation-and-end loop's alike, so no record no scope counts is appended under the floor; the identifier minted and the record written. The body is optional: empty, the two-step shape; the first `K ≤ N` bytes, the standard's creation-with-upload, the identifier riding the `100 Continue` as `Upload-Id` where the client asked `Expect: 100-continue`, so it reaches the uploader before the first body byte and is persisted before the bytes that spend it | `200 {"expires":<unix ms>,"length":N,"offset":K,"upload":"<32 hex>"}` — the record, where the body stops short of `N`; the finish's answer where it reaches it |
| `PATCH /blob/upload/<id>?offset=<K>` | THE RESUME: admitted under the upload permit pool — past it, `503 upload_busy`, retry-class, before any body byte, the upload KEPT where it stood; then the bytes from `K`, which must be the record's offset; `K` plus the body's length at most `N`; the own scope on what the upload leaves past `K` BEFORE the body (refused there, the upload is kept) | the record where the body stops short; the finish's answer — `200 {"designation":"blake3","hash":"<64 hex>","size":N}` — where the offset reaches the length, after the file is durable, the lease synced and the record retired |
| `GET /blob/upload/<id>` | THE PROGRESS: the upload's record — the offset a resume continues from | `200 {"expires":…,"length":N,"offset":K,"upload":"<id>"}` |
| `DELETE /blob/upload/<id>` | THE TERMINATION: the upload ended, nothing kept | `204` |
| `GET /blob/upload` | THE DEPOSIT READ — no surface of its own (m-Q10): the requester's own standing deposits (hash, size, expiry, and `lapsed` where a live lease stands over a file that is not there or not whole), its standing uploads (identifier, offset, length, expiry), its usage as two figures — the BASE, the cell index's number for its account (the distinct hashes its cells name, at their size), and its PENDING bytes (its live leases on hashes none of its cells names, and its uploads' bytes received) — the limits record's address as installed, and `per_account`, THE PER-ACCOUNT LIMIT IN FORCE in bytes whatever its source: the daemon's default where no record is installed, echoed as a written limit is, so a client reads the figure its own scope is held to before any refusal (R68); `null` only where a written record sets none; refused `503 index_rebuilding` until the index's rebuild at open completes | `200 {"base":<bytes>,"deposits":[…],"limits":null,"pending":<bytes>,"per_account":<bytes>,"uploads":[…]}` |

The seven clauses, as the wire keeps them: (1) THE IDENTIFIER — 128 bits
from the OS per upload, 32 lowercase hex, answered before any body byte
(the two-step's creation, or the interim `Upload-Id`), and answering to
the uploader alone: an identifier the requester's own records do not name
is `404 no_upload` whoever minted it, exactly as an expired one. (2) THE
PENDING QUOTA — the bytes received count in the uploader's pending bytes
beside its live leases, read off its own record. (3) ONE EXPIRY — fixed
from the last byte received, re-fixed by each byte and by nothing else; a
byte is received once it is durable in the partial, fsynced at the grain
below, the record's offset written after it, so the offset a resume
continues from, the `offset` the read answers and the byte the expiry is
fixed from are one figure. (4) REMOVED ON EXPIRY — past its expiry the
identifier answers `no_upload` and the bytes count nothing; the partial is
removed by the pruner's pass (below) and at the next open.
(5) A STREAM CLAIMS ITS UPLOAD FIRST — a request naming an upload another
stream holds is `409 upload_held` while it is held; a resume stating an
offset other than the record's is `409 upload_offset` carrying the
record's; a connection whose body stalls past the idle bound ends, its
upload kept. (6) REFUSED IS ENDED — a PUT refused AS THE BODY IS WRITTEN,
at its own scope, the venue's total or the floor, ends its upload and
keeps nothing (`507 deposit_refused` with `ended: true`, `scope` the one
that fired, `offset` the bytes it had taken — the venue total's priced
residue, ms4-E1); a refusal BEFORE a request's first body byte keeps the
upload (`ended: false`), resumable once there is room; its uploader may
end it. (7) FINISHED, THE LEASE TAKES OVER — the file renamed onto its
hash, the lease written and synced, the record retired, THEN the answer;
a finished upload whose `insert` never landed is kept by the lease until
its expiry. A finish cut BEFORE ITS RENAME — a failure there, a crash —
leaves the upload standing over its partial, cut back at the next open to
its record's offset, which the last byte received marked at the grain: an
ordinary resume at that offset finishes it, re-sending at most a grain,
and where the offset is already the length the progress read says so and
an EMPTY resume at it — `PATCH` with no body — finishes and binds, no byte
re-sent.

The family's refusals, each a transport refusal (no `Op` ran):

| status | error | when |
| --- | --- | --- |
| 400 | `malformed_blob` | the query, the identifier or the method's shape |
| 403 | `upload_refused` | `detail` `unauthenticated`, `claim_first`, `node_tier` or `uploads_closed` — the session-layer gate, then the upload setting (below), each before any body byte; `uploads_closed` at the creation and the resume alone, the upload kept where one stood |
| 404 | `no_upload` | an identifier the requester's own records do not name |
| 409 | `upload_held` | another stream holds the upload |
| 409 | `upload_offset` | the stated offset is not the record's; carries `offset` |
| 400 | `upload_length` | the request's bytes would pass the declared length |
| 413 | `payload_too_large` | the declared `length`, or a request's `Content-Length`, past the per-file cap |
| 507 | `deposit_refused` | the gate: `scope` — `own`, `venue`, `floor` or `standing` — `ended`, `offset`; at `standing` a `detail` naming the act |
| 500 | `blob_io` | the store refused I/O; the upload stands at its last durable point |
| 503 | `index_rebuilding` | the creation, the resume or the deposit read while the cell index is being rebuilt from the board after an open — retry-class, as `history_busy` is; the progress read, the termination and every other request are served meanwhile |
| 503 | `upload_busy` | the creation or the resume past the upload permit pool — every permit in use; retry-class, as `fetch_busy` and `history_busy` are, before any body byte: a creation makes no upload, a resume keeps its upload where it stood; the progress read, the deposit read, the termination and every other request are served meanwhile |

THE PERMIT — the fetch's step 5's twin (M-I5 (f): bounded by a pool, never
a queue; PATTERNS P29, P13): the creation and the resume, the two acts of
the family that take bytes and no other, are admitted at most the upload
permit pool at once, the permit taken after the session-layer gate, the
upload setting and the readiness — the cheaper refusals, which spend none
— and before the shape, the cap and every gate read, and held for the
request's whole life, the body's stream and the finish included. Past the
pool the answer is `503 upload_busy`, retry-class as `fetch_busy` and
`history_busy` are, before any body byte, any record and any partial: a
creation makes no upload and a resume keeps its upload where it stood; the
refusal names the retry and no headroom and no holder. The progress read,
the deposit read and the termination take no permit. What the pool bounds
is worker occupancy — an admitted stream holds its worker to its end, up
to the transfer bound, where a fetch's permit bounds the memory its whole
file takes — and it is counted into the daemon's worker minimum beside the
reconstruction, class-scan and fetch pools (the pins below), so a daemon
whose every pool is saturated still answers `/health`, `/session` and the
write path.

THE GATE's THREE SCOPES, in the order read — the requester's own record
first: THE OWN SCOPE, the principal's BASE plus its PENDING BYTES against
the per-account limit — the base the cell index's number for its account,
the pending bytes its live leases on hashes none of its cells names plus
its uploads' bytes received, so a hash a cell names moves from the pending
to the base and the scope is one number either way — refused on the
declared total before the body and re-checked as the body is written; THE
VENUE TOTAL, the sum of every account's own scope — every base, every
pending — record-derived and never the directory's bytes, enforced ONLY
as the body is written; THE FLOOR, the volume's free space held above the
floor below, read off the host and showing no figure — read AT THE
CREATION on no declared length, before the partial and the record
(`scope` `floor` AT THE CREATION, `ended: false`, no upload made), and per
chunk as the body is written, so every record, lease and retirement the
store appends descends from a creation or a body byte the floor admitted.
Beside the own scope, THE STANDING-UPLOADS BOUND: a principal holds at
most a pinned count of standing uploads (the pins below), counted off its
own records at the creation, a creation past it refused `scope` `standing`
before its partial and its record, its `detail` naming the end of one of
them as the act the person holds. The refusal names the scope and reports
no headroom. THE LIMITS RECORD — the per-account limit, the venue's total,
the lease interval, a per-file cap at or below the route's — is installed
by the serving layer as AUTH-4.70's list is; its kind, schema and channel
are AUTH's docket's (OWED). UNTIL A RECORD IS INSTALLED THE DAEMON's
DEFAULT STANDS, AND A PER-ACCOUNT LIMIT IS ALWAYS IN FORCE: the default
per-account limit is ONE EIGHTH OF THE VOLUME's CAPACITY, read once at the
daemon's start off the same read as the floor's, never below 256 MiB —
the floor alone on a host that answers no capacity; the venue total
unset; the lease interval below; the route's cap; no address. The deposit
read echoes the limit in force as `per_account`, whatever its source, and
the record's address or `null`; a written record overrides the default
whole; the startup log names the record in force, or the default and the
capacity it was read from.

**The upload setting.** A boundary setting of the daemon's, echoed as
`--local-trust` is: `--no-uploads` (`SKEPD_UPLOADS=false`) CLOSES the
upload family, and OPEN is the default, the default per-account limit in
force from start. `GET /health` echoes it as `media.uploads`, the `media`
object beside `auth` — `{"uploads": true}` — the setting's one read, which
a client makes BEFORE any face or statement that names an upload speaks: on a
closed board the faces that named an upload name the operator's pull
where they show a hole and elsewhere the acts that exist, or none. Where
CLOSED the creation and the resume answer `403 upload_refused` with
`detail` `uploads_closed` before any body byte, the upload kept where one
stood; the progress read, the termination, the deposit read, the door's
binding and the pruner's pass are served as before.

THE ORDER OF ONE FINISH (M-I5 (a)): the partial fsynced; where the name
already holds a file, that file LINKED ASIDE — a second name no hex
spells, `.retired-<hex>-<n>` in the same directory, so the rename below
frees no blocks; the partial RENAMED onto `blobs/<designation>/<hex>` —
REPLACE where the name exists, never a no-op, so a file holding the wrong
bytes under the right name is repaired by a re-PUT of the right ones —
that directory fsynced, `blobs/` itself where the designation directory
is new, THEN the lease appended and synced, THEN the record retired, THEN
the answer; under the credential lock's READ arm from the rename through
the lease's sync, and never `Serial`. THE ASIDE IS UNLINKED AFTER THE
ANSWER — the replaced instance's retirement is off the answer's path: the
transport unlinks it once the reply is written, the pruner's pass removes
one that step did not reach, and the next open removes every one a crash
left; nothing names an aside, so no reader of the directory sees it. NO
ANSWER OF THE UPLOAD SAYS WHETHER THE FILE WAS ALREADY HERE: the status,
the body and the completion are one whether or not the file existed, and
so is the time the answer takes — the time an answer takes is part of
what it says — and a resume is keyed to the identifier alone.

**The cell index.** ONE DERIVED INDEX SERVES THE BASE AND THE PRUNER's
REFERENCE TEST BOTH: per hash — the designation and the hex — the cells
naming it; per account — ω of the cell's document, the principal seated
at it — the DISTINCT hashes its cells name, each at its size, whose sum
is THE BASE: record-derived, replayable, one number on every open and
every mirror, a published picture's original and the cell its edition
re-inserts counting once, a transclusion counting nothing. Held in the
daemon's memory and in no store. ENTERED AT EVERY COMMIT THAT MINTS A
CELL, whichever op minted it — an `insert`'s values, the values a
`publish` re-inserts as fresh identity (`copy` and `version` mint none)
— under the commit's own serialization guard, before it drops, off the
post-commit snapshot. REBUILT WHOLE AT EVERY OPEN from the world replayed
there — every value, a checkpoint's below the retained journal among them
— and never from the retained journal alone: a thread walks an immutable
snapshot of the content store while every other request is served, each
value put through a cheap prefix test (the canonical opening,
`{"type":"<the kind's address>"`) before any parse. THE COMPOSITION
CLAUSE: the walk's entries are ADDED INTO THE ONE COPY the commits since
the open have entered their own into, and never installed in its place —
an entry is idempotent per cell address, a cell being permanent, so a
cell committed during the walk is in the index when the walk completes
and its file outlives its lease. THE HALT MARK: a value naming the kind
that parses under no schema this build pins is entered as a halt mark —
its address and the fault — and counts in no base; the door refuses such
a value at its own insert, so one stands only on a board another build
wrote, and while it stands the pruner's unlink pass halts, naming it, and
never reads it as absent (DOCTRINE D13's carve-out, ms5-T4).

**The readiness refusal** (ms5-R, the narrow reading): the daemon is NOT
READY FOR THE INDEX's THREE READERS AND FOR NOTHING ELSE. Until the walk
at open completes, the blob upload's creation and resume (their own scope
reads the base) and the deposit read (its `base`) are answered `503
{"error":"index_rebuilding","detail":"…"}` — retry-class, as
`history_busy` answers past its permit pool — and the pruner's pass does
not start; the progress read and the termination, every text read and
write, `/changes`, the door's own binding arm — every other request — is
served throughout (PATTERNS P22: a derived structure's loss is a slower
answer, never an outage). The readiness is monotone: once ready, ready
for the life of the process.

**The pruner.** THE PASS runs once the index is ready and then on a
cadence — one hour (the pin below) — and does, in order: (a) THE EXPIRED
PARTIALS — every upload record past its expiry and held by no stream is
retired and its partial removed, off the record's expiry and the hold,
reading no reference; (b) THE HALTS — a designation directory under
`blobs/` outside the set this build pins (`blake3` alone), or a halt mark
standing in the index, halts the unlink pass before its first unlink,
with one operator line naming the directory or the schema, the partials'
removal running regardless and the halt re-evaluated at the next pass;
(c) THE UNREFERENCED FILES — for each file at a hex name under the pinned
designation, UNDER THE CREDENTIAL LOCK's EXCLUSIVE ARM, ONE FILE PER
ACQUISITION: the index re-read (no cell names the hash, and no halt mark
stands), the lease log re-read (no key holds a live lease on it,
whoever deposited it), the file RENAMED ASIDE to `.retired-<hex>-<n>`,
the REPLACE's own aside name, the arm released — and the aside UNLINKED
AFTER, under no arm, where the file's blocks are freed. A file a cell
names or any live lease holds is KEPT (M-I5 (b): no housekeeping act
creates a hole; a crash between the rename and the unlink leaves an aside
the next open removes); the arm is held one re-read and one rename and
never across an unlink, so a retirement never queues behind a drain's
freeing (M-I5 (f)); a replace's aside the deferred step did not reach is
removed under the same arm at the pass's end. (d) THE COMPACTION — each
of the two logs, `uploads.log` and `leases.log`, rewritten to its current
records as open rewrites it, where its lines have passed the compaction
trigger (the pins below: a multiple of its current records, and never
under a minimum, so a small log is not rewritten per pass), under the
store's own lock on THAT log's appends alone and NO arm of the credential
lock: an append that arrives during the rewrite waits on that lock and
lands in the new file; a compaction that fails past its rename STOPS its
log — it takes no append until a compaction completes, the next pass's,
which rewrites a stopped log whatever its count — and the pass's line
names the stopped log. The pass never touches a partial whose upload
stands and reads no directory's bytes as a scope (M-I6: the scopes stay
record-derived).

**THE FETCH** (media lane D; the media record's Op inventory 3; the ruled
v1 cut — whole-file serving, the hash checked before the first byte):
`GET /blob?i=<address>`, with `HEAD /blob?i=<address>` for the head alone.
The one path beside the upload family, TOKEN-ACCEPTING (the session token
resolved as `/op` resolves it, the death signal carried the same) and
CLASS-VARYING; its answer the daemon's one streamed response. The query is
exactly `i=<address>`, the address dotted-decimal. The order, in full:

1. `i` names an ELEMENT position of some document, or `400 malformed_blob`.
2. THE GATE is the read by identity: `retrieve_i` of the one span `{i, 1}`,
   run as the presented session (the guest where none was). A rejection it
   answers rides M10's own envelope — the `{"resp":"rejected"}` document,
   the bytes `/op` would answer for the same read — under the HTTP status
   its class takes on this byte route: `403` for `withheld`, the one M10
   rejection the fetch's `{i, 1}` span reaches — the picture is one you may
   not read, named by its home. Nothing of a value you may not read is
   served (M-I2 (a): the fetch is gated by the same predicate as the read).
   An address the read holds no value at — unminted, or under a document
   the read minted nothing in — is `no_value` below, never a registration
   refusal: the gate is the read, which mints nothing.
3. THE VALUE at `i`, classified by the one classification (above):
   `404 no_value` where the document minted none; `404 not_a_cell` where it
   names no media kind; `404 unknown_cell_schema` where it names a media kind
   under no schema this build reads; `404 blind_cell` where it is a blind
   document's cell — its picture its owner's, no byte of it here, and no
   store asked; else the picture's cell, whose `hash` and `size` the file is
   held to.
4. THE WHOLE FILE, checked before its first byte: the store's file under the
   cell's hash, read whole, its length the cell's `size` and its BLAKE3 the
   cell's `hash`, or `404 blob_missing` (no file) / `404 blob_damaged` (the
   wrong length, or the wrong bytes under the right name) — each carrying
   `hash` and `size`, the cell's own, which the requester could read at the
   address already. One byte of a file the cell does not name is never
   served, nor one byte of this one before the check completes.
5. THE PERMIT: a fetch holds its whole file from the check to the last byte,
   so the route admits at most a POOL of answers at once — `503 fetch_busy`,
   retry-class as `history_busy` is, past the pool (M-I5 (f): bounded by a
   pool, never a queue). The pool is the route's memory bound, the per-file
   cap times the pool.

The admitted answer is `200` streaming the file: `Content-Type:
application/octet-stream` (the daemon reads no type off the bytes and
declares none it did not read; a page names the type from the cell's kind),
`Content-Length` the file's size, the two inert headers (§Cross-origin
access), and the body the file's bytes one chunk at a time. A `HEAD` is that
head and no body. The requester is RE-RESOLVED MID-STREAM (M-I2 (g)): between
chunks, at a byte interval or a time interval, whichever comes first, the
token is resolved against the head again and the gate re-run — a stream whose
requester died or whose gate now withholds is ended by a RESET, short of the
declared length, never a clean close (§Transport). A `HEAD`'s or a refusal's
body is JSON; only the `200` streams.

**INTERIM PINS** — the subsystem design's, carried by the build and each
confirmed at the media round (the board's sm-Q8):

* the cell kind's address, `1.1.0.1.0.1.0.3.89` — INTERIM, a TEST-ONLY
  address under the commons media range 3.80–3.89, which is unallocated;
  the allocation lands by one constant;
* the blind document's kind, `1.1.0.1.0.1.0.3.88` — INTERIM, TEST-ONLY,
  beside the picture's in the same range; and its `commitment`, 32 bytes as
  64 lowercase hex, the only member beside `type`;
* the designation, `blake3` — INTERIM in name, the hash itself ruled
  (BLAKE3-256, 32 bytes as 64 lowercase hex);
* the cell's cap, 1024 bytes — INTERIM; a canonical cell is under 140
  bytes, and the cap bounds the JSON tree a hostile body naming the kind
  can command before it is refused — one cap for every media cell kind;
* the four refusal tokens of the door — `unbound_cell`,
  `unknown_cell_schema` and `lease_lapsed`, PERMANENT for the request as
  sent, and `index_rebuilding` in the binding's position during the walk
  alone, RETRY — and the `unbound_cell` face's words;
* the fetch's spellings — the path `/blob?i=<address>`, its two methods
  (`GET`, `HEAD`), its query `i`, its seven refusal names with their
  statuses above, the content type `application/octet-stream`, and the two
  inert headers `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: sandbox`;
* the fetch pool, 2 — the most whole-file answers held at once, the memory
  bound the per-file cap times it (128 MiB); and the mid-stream re-check's
  two intervals, 1 MiB of bytes and 5 s on the media gate's clock,
  whichever comes first;
* the route's spellings — the family `/blob/upload`, its five method/path
  pairs, the queries `length` and `offset`, the interim header
  `Upload-Id`, the answers' members, and the ten refusal names with
  their statuses above;
* the upload pool, 4 (`MAX_CONCURRENT_UPLOADS`) — the most creations and
  resumes streaming a body at once, a bound on worker occupancy and not
  memory (a stream holds one chunk, where a fetch holds its whole file);
  counted into the worker minimum, `MIN_WORKERS`, 11 — one more than the
  four pools' slots together — and the default worker count,
  `DEFAULT_WORKERS`, 12, one above it;
* the per-file cap, 64 MiB — the route's own, a venue's below it; sized
  for v1's images (ms5-V1) and bounding disk and transfer, never memory;
* the chunk, 64 KiB — the streaming arm's one buffer per in-flight upload;
* the partial's fsync grain, 1 MiB — the most a dropped connection
  re-sends, against two fsyncs per grain;
* the identifier, 128 bits from the OS as 32 lowercase hex, and the
  partial's name, `.upload-<identifier>` in the target's own designation
  directory;
* the lease interval's default, seven days — the upload's expiry interval
  too; and the horizon, thirty days past a lease's expiry, within which a
  lapsed lease answers `lease_lapsed` and past which it answers as none;
* the idle bound, 30 s, and the transfer bound, 10 minutes, on a streamed
  body;
* the floor, 256 MiB of the volume's free space as its CONSTANT HALF, the
  floor IN FORCE the larger of that and twice the newest checkpoint's size
  plus one maximal segment (128 MiB, the journal's reader ceiling), re-read
  as each checkpoint lands — read once at the open off the newest checkpoint
  on disk, named on the startup line beside the default limit — at the
  creation on no length and per chunk; a guarantee that the journal stays
  writable through its next checkpoint beside the cadence's byte bound (a
  quarter of the newest checkpoint and no less than 24 MiB, with one window
  of grace), which the daemon carries;
* the default per-account limit, one eighth of the volume's capacity read
  once at start and never below 256 MiB, the venue total unset; the
  deposit read's `per_account`; the limits record's install channel
  (AUTH-4.70), owed;
* the standing-uploads bound, 8 per principal, its scope token `standing`
  and its face's act;
* the upload setting, `--no-uploads` (`SKEPD_UPLOADS=false`), open by
  default; its `/health` echo, the `media` object `{"uploads": <bool>}`;
  and the creation's and the resume's refusal on a closed board,
  `upload_refused` with `detail` `uploads_closed`;
* the readiness token, `index_rebuilding`, 503, retry-class — the one
  refusal of the cell index's three readers — re-used at the door for the
  rebuild window's answer;
* the pruner's cadence, one hour between passes, the first once the index
  is ready; the pinned designation set, `blake3` alone; the compaction
  trigger, four times a log's current records, and its minimum, 1,024
  lines;
* the aside name, `.retired-<hex>-<n>` in the designation directory — a
  replaced file's second name from the finish's link to the deferred
  unlink, and a pruned file's from the pass's rename to its unlink — never
  read by anything;
* the operator's tools' spellings — `skepd inventory --data-dir <dir> [--no-rehash]`
  and `skepd pull --data-dir <dir> [--hash <hex>] <file>` — and the
  inventory's object (below).

The set's second file, `crates/skepd/tests/it/fixtures/media/uploads.json`,
carries these pins, the refusals, and the seven clauses as vectors over the
wire — one set (PATTERNS P5), run by the daemon's suite and by a client's
implementation of the shape.

**The H1 rows** (the record's presence cells; the register M-I2 (e)): a
PUT of a file another account already holds answers byte-identically to a
PUT of a fresh file; the deposit read never lists another account's
deposit; an identifier another account's records name answers
`no_upload` as a never-minted one does; and the write door's answer to a
cell says nothing of whether another account deposited the file — a
stranger's cell over a deposited hash is `unbound_cell`, as over any
other, and over a hash another account's CELL names, that account's lease
lapsed, in the same time: the index arm is read at the requester's own
account's hashes and never at the per-hash list, and the timing row that
measures it is reported and never asserted; the door's answer to a blind
cell takes the same time with and without a file deposited under a lease
whose hex equals the commitment's, the binding never asked for the kind.
THE K2 RESIDUE: the time a PUT's answer takes at the common picture's
size carries the presence fact until the cause is found — the 1 MB gap
measured at +10.4 ms p50 and +64.0 ms p99 between a REPLACE and a create
— carried here as a named residue beside dedup's two, reported by the
timing row that measures it and never asserted.

**The operator's tools.** Two subcommands of the `skepd` binary, run over
a board DIRECTORY with no server — no port, no session, no `/health`, no
log line of the daemon's — and both the ORIGIN cell's: at a replica the
reference cells are foreign and their bytes a cache's, which neither
reads. Neither opens the store as the daemon does. `skepd inventory
--data-dir <dir> [--no-rehash]` — over a directory no daemon serves: a
stopped board, a backup, one moment's copy — opens the journal through
the engine's ordinary open (a directory a daemon serves is refused at the
kernel's exclusion lock; a torn tail is cut and a stray `checkpoint.tmp`
removed, as every open cuts and removes them, and nothing else of the
daemon's is written: no checkpoint, no commit, no head, no feed sidecar),
rebuilds the cell index in memory from the replayed world as the daemon's
open does, reads the blob store's four stores AS THEY STAND — the logs'
torn tails cut in memory alone, nothing reconciled, compacted, swept,
synced or created — and prints ONE JSON object to stdout, its members in
sorted order: `holes`, every reference
cell (the picture kind's; a blind cell is never a hole) whose file is
absent at its hex (`fault` `absent`), present at a length other than the
cell's `size` (`length`), or present and re-hashing to another hash
(`hash` — one whole read per file, skipped by `--no-rehash`), each with
its `hash`, `size`, `designation` and the `cells` naming it; `accounts`,
per account its `principal`, its `account` address, its `base` (the
index's number) and its `pending` bytes (its live leases on hashes none
of its cells names plus its standing uploads' bytes received);
`unattributed`, the bytes no account's scope holds — a live lease's or a
standing upload's whose key spells no principal of this build; and
`venue_total`, their sum with the unattributed bytes — the gate's own
figure, under the gate's own pending rule, which the limits record is
written against; `standing_uploads` and `expired_uploads` by count;
`halts`, the halt marks, each with `at`, `kind` and `fault`;
`foreign_designations`; `orphan_partials` and `asides`; `references`,
`cells` and `values_walked`; `journal`, the `log_position`, the
`start_point`, the `skipped_checkpoints` and `stray_checkpoint_removed`
(the bytes of a half-written checkpoint the open removed, or `null`); and
`rehashed`. It writes nothing under `blobs/` and RECORDS NO READ
anywhere (D9).
`skepd pull --data-dir <dir> [--hash
<hex>] <file>` takes a FILE, hashes it (BLAKE3) and INSTALLS it at
`blobs/blake3/<hex>` as the PUT's order installs one — the temp file in
the designation directory, named as a partial is so an open that meets
it mid-pull removes it as an orphan, fsynced, renamed onto the hash name,
REPLACE where a file stands, which ends any hole, the directory fsynced —
ONLY WHERE A COMMITTED REFERENCE CELL NAMES THAT HASH: a restore, never a
deposit, writing no lease, no record, no journal entry and no log line of
the daemon's. Without `--hash` the board's journal is read as the
inventory reads it and a file no committed cell names is REFUSED with one
line; with `--hash <hex>` — the inventory's listing — the file is held to
that hash, a file whose bytes hash to another refused with nothing
installed, and the journal left unopened: the form that runs BESIDE A
SERVING DAEMON holding none of its gates, the daemon's fetch serving the
restored file at its next read. The subcommands' spellings and the
inventory's object are INTERIM pins.

What this build does NOT carry, by name: the floor's scaling with the
newest checkpoint and the cadence's byte bound beside it, owed; the
video-era `extent` member (ms5-D2); and any media kind past the two. The
door's armed set, the fetch's and the upload family's are each whole, so
no later addition moves one state's answer from one code to another
(PATTERNS P6).

### Registry — the twelve rows, the two bodies and the record grade

The REGISTRY is a skep board under the account law: a registrar's console
binds a prefix to a node account by a signed deposit into the registrar's
own doc 1, and an org deposits its endpoint into its node account's doc 1
(REG-1.1, REG-1.9, REG-2.18). What this build carries is the registry's
STABLE CORE on the daemon's side — the twelve commons rows the registry
allocates, the binding's and the endpoint's bodies under one canonical
rule, the record grade for registry records at both of a deposit's
positions, the audit-view refusal for the registry's classes, and the
seeding check the daemon runs ahead of every genesis — the values of one
crate, `skep-registry`, which a resolver reads too. No resolve, no door,
no takedown and no fork stands here.

**The twelve rows** (REG-1.14, REG-1.15, REG-1.24; commons-map's table of
them): five kinds on the reserve's ordinals `3.55`–`3.59` of the ghost
document's type subspace `1.1.0.1.0.1.0.3` — where the credential kinds
sit at `3.1`–`3.3` — and seven subtype rows nested under their kinds by
prefix (REG-1.20), each subtype its own wire type at the type slot
(REG-1.21). A kind that reads ONE way carries its deposits on its bare
ordinal; a kind that reads more than one way carries NONE there, every
reading a row under it (REG-1.18). The rows are PINS — compiled addresses
the daemon keys on, as the credential types are — and genesis seeds no
record at any of them.

| Address | Row | Deposits |
| --- | --- | --- |
| `1.1.0.1.0.1.0.3.55` | the BINDING — the registration record | on the bare ordinal (one reading) |
| `1.1.0.1.0.1.0.3.56` | the ENDPOINT | on the bare ordinal (one reading); no subtype row |
| `1.1.0.1.0.1.0.3.57` | the TAKEDOWN RECORD — the kind | NONE on the bare ordinal (two readings) |
| `1.1.0.1.0.1.0.3.57.1` | the takedown record's own BASE reading | on this row |
| `1.1.0.1.0.1.0.3.57.2` | LIFTED | on this row |
| `1.1.0.1.0.1.0.3.58` | the POLICY LINK — the kind | NONE on the bare ordinal (five readings) |
| `1.1.0.1.0.1.0.3.58.1` | the policy link's OWN reading | on this row |
| `1.1.0.1.0.1.0.3.58.2` | the DISAVOWAL | on this row |
| `1.1.0.1.0.1.0.3.58.3` | an expulsion's GROUND RECORD | on this row |
| `1.1.0.1.0.1.0.3.58.4` | a succession's GROUND RECORD | on this row |
| `1.1.0.1.0.1.0.3.58.5` | the ORG-CHOSEN SUCCESSION POLICY | on this row |
| `1.1.0.1.0.1.0.3.59` | `successor-of` — the succession claim | on the bare ordinal (one reading) |

**The deposit class's four members.** The set the insert door tests a
declared deposit's class type against (§The claim ceremony and
credentials; §Arrangement) holds, in order: enroll `1.1.0.1.0.1.0.3.1`,
retire `1.1.0.1.0.1.0.3.2`, the binding `1.1.0.1.0.1.0.3.55` and the
endpoint `1.1.0.1.0.1.0.3.56` — the four atom-bearing kinds whose records
the daemon parses. A declared `insert` under any other registry row — the
five other body-bearing rows among them, until their schemas are pinned —
is refused `published_target` at the door, and the three link-alone rows
(`…3.57.2`, `…3.58.1`, `…3.59`) carry no body ever.

**The two bodies** (REG-1.86). A binding's and an endpoint's atom is ONE
JSON OBJECT naming its kind in `type`, the row's member beside it,
`replaces` where a later record names the deposit it replaces, `sig`
where signed, and NOTHING ELSE — under THE CANONICAL RULE, the credential
record's own admission rule applied to the flat object: `parse(b)`
answers a record only where `b == encode(parse(b))`. The canonical form
is `{"type":"<the row's string>"`, then the row's member, then `replaces`
where present, then `sig` where present, `}` — no whitespace outside
strings, the shortest JSON escapes and no others, no byte after the
brace. The members:

| row | `type` | members |
| --- | --- | --- |
| the binding | `"binding"` | `prefix` — a string, the prefix in address form, dotted decimal; `replaces` — a string, the link's address of the binding this one replaces at that prefix, ABSENT on an allocation |
| the endpoint | `"endpoint"` | `origins` — an array of strings, AT LEAST ONE, the org's origins in its own order; `replaces` — a string, the link's address of the endpoint deposit this one replaces, ABSENT on the org's first |

The daemon checks the FORM of every member and never its admissibility:
`type` is the string of the kind the link's type slot names, and a body
whose `type` is another kind's is no record of the slot's kind; NO member
is a JSON number, anywhere in the body; `prefix` and `replaces` parse as
addresses in their one spelling (no sign, no zero-padded component, the
whole T4-valid); `origins` is non-empty; `sig`, where present, is a
string. Whether an origin is https with a routable host is the resolver's
check, and whether `replaces` names the deposit current at the record's
position is the reader's currency rule — a later record naming one that
is no longer current COMMITS and is inert at every reader (REG-1.10,
REG-2.24). A body past the cap, 16 KiB with its `sig` inside it, is
refused before any parse. The two examples, in canonical form — 33 and
116 bytes:

```
{"type":"binding","prefix":"1.5"}
```

```
{"type":"endpoint","origins":["https://acme.example","https://acme.example.net","http://<acme's onion host>.onion"]}
```

The same two with a space after each colon and comma — the spelling a
specification prints them in — are what the parse REFUSES, as it refuses
a member twice, a member out of order, a `\/` escape and a trailing
newline: the admitted and refused bodies are ONE VECTOR SET,
`crates/skep-registry/tests/vectors/records.json`, which every parser of
the bodies runs in its own gate; a parser is never derived from another
parser.

**The record grade for registry records** (signed ops; REG-1.86 (e)). A
registry record is signed and never hashed: above the claim its `sig`
member carries the hybrid signature blob in hex, as a credential record's
does, made by the writing hand's key over the entry frame under the
`record` grammar — `board` `H.1`'s pair, `account` the HOME's account (ω
over the home: the claimant's for a binding in the registrar's doc 1, the
node account's for an endpoint in its own), `doc` the home, and the
body's five rows: the link's type address, its target as stored (the
account bound, or none), the `replaces` row EMPTY (the member rides
INSIDE the signed body for these kinds, and no `replaces` link is written
with them), the lineage row EMPTY, and the SIG-LESS CANONICAL PROJECTION
of the body. The record covers BOTH of the deposit's positions: the atom's
`insert`, declared under the kind's type, is exempt from the entry
signature where it parses as a record of that kind, carries its `sig` and
lands in a doc 1 — a record of the kind carrying none is refused at its
`insert`, `record_sig_required` — and its `make_link`, routed to THE
REGISTRY SEQUENCE, is where the `sig` is verified under THE SET THAT
OPENS THE HOME'S ACCOUNT, at device grade (no rule names an anchor grade
for a registry record), and commits with its marker slot EMPTY by route:
the link's row on `/changes` carries neither `key` nor `attest`, as a
credential deposit's does, and the atom's row carries `key`. The system
account's doc 1 admits no registry record: a registry-kind `insert` into
it is refused `system_account_keyless` as a credential-kind one is, and
no atom can be read there for a link to name.

**The registry sequence and its refusals.** A `make_link` whose type slot
names the binding or the endpoint takes the registry sequence — chosen
off the op's own type slot ahead of any lock, after the credential route
and before the plain one — under the serialization lock and the
credential lock's read arm, in this order: above the claim only
(`claim_first` on an unclaimed board) and from a signed session
(`signed_session_required`); the HOME PIN — the home is a doc 1, else
`not_doc_one`; THE FORM — an address-form `make_link` carrying no
`replaces` member, its `from` ONE atom in the home's own space, its `to`
EMPTY or ONE address, which for a binding is a registered account on this
board (a targetless binding being the one spelling of "no account") and
for an endpoint is none — else `registry_form`; THE RECORD VALUE — the
atom's bytes parsed by the kind the slot names, else
`malformed_record:<cause>` with the parser's cause joined (`wrong_type`,
`number`, `unknown_member`, `empty_origins`, `not_an_address:prefix`,
`not_canonical`, `past_cap` and the rest, as the vector set spells them);
NO `sig` → `attestation_required`; and THE TRIAL —
`attestation_invalid:<cause>` with the record grade's own causes
(`malformed`, `not_enrolled_at_position`, `signature`,
`board_unavailable`). Every refusal is the ordinary `rejected` shape
under ONE code of its own, `registry_refused`, with `detail` the token
and `disposition` the refusal's class — PERMANENT but for
`attestation_required` (REORDER) and `attestation_invalid`'s own classes
— so a client tells the registry's family from the credential's; the
tokens the two families share are spelled alike and never renamed:

| `detail` | disposition | when |
| --- | --- | --- |
| `claim_first` | permanent | the board is unclaimed |
| `signed_session_required` | permanent | a bare session |
| `not_doc_one` | permanent | the home is no doc 1 |
| `registry_form` | permanent | the shape, the `from`, the `to`, or a `replaces` member on the link |
| `malformed_record:<cause>` | permanent | the atom is no record of the slot's kind under the canonical rule |
| `attestation_required` | reorder | the record carries no `sig` |
| `attestation_invalid:<cause>` | the cause's | the `sig` does not verify under the set that opens the home |

```json
{"code":"registry_refused","detail":"registry_form","disposition":"permanent","op":"make_link","resp":"rejected"}
```

A refused link commits nothing; the atom it would have named stays an
orphan no link names, which a reader renders undeterminable.

**The audit-view refusal** (REG-1.44, REG-1.46). The write path's
`nullify_audit_view` class (§Credential refusals) gains three members and
no code: the binding `1.1.0.1.0.1.0.3.55`, the takedown record
`1.1.0.1.0.1.0.3.57` and the policy link `1.1.0.1.0.1.0.3.58`, each at
its kind's address so every subtype row under the last two is a member by
prefix; `successor-of` `1.1.0.1.0.1.0.3.59` was a member already. The
ENDPOINT is NOT a member: it is read on the active view and its org's own
`nullify` is EFFECTIVE — the deposit leaves the active view and the one
before it stands (REG-1.11).

**The seeding check** (REG-1.28 to REG-1.32). Ahead of every open — a
fresh data dir's genesis and a reopen alike — the daemon runs three arms
over the twelve rows and every other commons row the build holds (the
engine's pins, the credential types, the deposit class): DISJOINTNESS at
the subtree grain, COMPLETENESS against the kinds' home, and THE COUNT
against the registry range's five ordinals; a refusal is a genesis that
does not complete — the daemon does not open, naming the arm — so a served
board never holds a registry row that collides with another row or a
subtype without a row.

**INTERIM PINS** — confirmed at the registry's review round:

* the body cap, 16 KiB, the `sig` member inside it — a binding's members
  are under a hundred bytes and an endpoint's a few hundred, and the
  production row's `sig` is 6,746 bytes of hex on its own, so a signed
  body is near seven kilobytes;
* the two tokens' spellings, `registry_form` and
  `malformed_record:<cause>`, and the family's code `registry_refused`.

What this build does NOT carry, by name: the resolve from a root hint and
the prefix → binding index, which are a resolver's; the five other
body-bearing rows' schemas and their parse; every door, the queue and the
reply; the takedown record and its lift (the blocked-prefix list reads
the version address a takedown record would carry, and that record is
not written here); the fork and the realm. The checked set of the
write-path check is UNCHANGED: the ten kinds, a registry deposit's two
positions taking the record grade in their place.

### Links (writes)

Ownership: every deposit into a home document's link subspace
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

Readability (§The read predicate): a V-SPEC slot of `make_link`, or
of `edit_link`'s successor, that resolves a document the session
principal may not read is `withheld` naming it — address-form slots are
ungated; and a link named by ADDRESS whose home the principal may not
read — `edit_link`'s `original`, `assert_sup`'s `old` and `new` — answers
exactly as an address no link occupies: `original_not_resident` and
`endpoint_not_resident` (reorder), never `withheld`, never `not_owner`.
Both consults run after the ownership check on the homes you write and
before the store reads anything. `nullify`'s `target` takes neither: its
ω-first order stands as above.

Credential deposits: a `make_link` whose `ty` names a credential
type address (§The claim ceremony and credentials) is a credential
DEPOSIT and runs the credential write sequence. Its `from` and `to`
must be the address form (`resolved_from` otherwise); a
credential-typed `emit` is always `emit_not_make_link`; a
credential-typed `edit_link` is always `resolved_from`; and a `nullify`
targeting a credential link is `nullify_not_retraction` — retraction
never edits the key table (§Credential refusals for all four, and for
the entitlement scope on the last).

The `nullify` class: the same write path recognizes two more
classes of target off its own type-recognition input — a GRANT-typed
link is refused `nullify_not_revocation` (a share is withdrawn by
revoking it, never by retracting its record), and a link of a class the
publication spec reads under the AUDIT view (the succession pair, the
consumption marker, the journal designation, the rail record, the
steward's classification link with a published home, the `replaces` link
a grant is deposited with) is refused
`nullify_audit_view` — each to the record's owner alone, anyone else
answering plain `not_owner` (§Credential refusals, item 3). And the
publish-class gate reads a `nullify` (PUB-6.43's row): a retraction
lands at its TARGET, so on a claimed board a bare session's `nullify`
whose record home OR target home is published is
`signed_session_required`, ahead of every class cell.

**`make_link`** — create an open link homed in `home`. Each of `from`,
`to`, `ty` takes **one of two forms** (no mixing within one slot):

* a **V-spec array** `[{"source": …, "span": …}, …]` — resolved against
  current arrangements; the recorded endset is the permanent I-spans;
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
`from`/`to` may be empty in either form.

The optional **`replaces`** member (PUB-5.15) names the record whose STATE
this link replaces — an address. Present, ONE transaction deposits the
link and then, at the next address of `home`'s link subspace, a second
link: typed `replaces` (`1.1.0.1.0.1.0.3.12`), `from` the first link's
address, `to` the address named; the ack is still the FIRST link's
address, the second `read_link`-reachable and born unseated. Absent — the
field not sent — is the EMPTY state, and the one link is deposited as
ever; an explicit `null` is unparseable. The member NAMES a state and is
never checked: at the grants class it is how a share that follows a
withdrawal names the revocation it follows, and the grant fold decides
what that honors (§The read predicate). The `replaces` type has this ONE
writer: a `make_link` whose own `ty` is it, an `emit` of it and an
`edit_link` successor typed it refuse `replaces_not_standalone`
(§Credential refusals).

On a CLAIMED board a link write
into a published home carries the optional top-level `attest` member
(signed ops; the object `insert` describes; §Credential refusals, the
entry frame's rows): the entry signature over the frame whose `doc` is
`home`, `op` `make_link` and `body` the type slot, the `from` slot and
the `to` slot, each a SLOT ROW — the slot AS THE STORE WILL HOLD IT, its
spans verbatim under `0x03`: an address-form slot's one unit span per
name, a V-spec slot's I-extents, which the client resolves through
`image` over each source before signing, against the base the
transaction will take (a resolution the base has since moved is refused
`attestation_invalid:signature`: re-compose and re-sign); the EMPTY slot
`0x03 ‖ be64(0)` — and then the `replaces` row: ONE length-delimited
group, EMPTY (`be32(0)`) where the member is absent, else the named
address as an address-list row of one element, delimited. So the member
a signature covers is the one deposited, a member-less body is never the
three slots alone, and a later reader composes every row from the stored
link alone — `read_link` or `find_links`, which serve the resolved endset
verbatim — so the served `attest` tells a reader nothing about a private
source's V-positions. A credential-typed
`make_link` (the enroll, retire and claim kinds) takes the credential
path and carries no `attest` — the record's own `sig` covers it, and
above the claim the daemon verifies that `sig` at this very deposit
(§The claim ceremony and credentials) — and no `replaces` member
(`replaces_not_credential`, §Credential refusals).
→ `ack_addr` (the link's address). A `ty` that resolves into the
retraction class is `retraction_class` — retraction writes only through
`nullify`. The seat step's `not_link_address`, `not_home_link` and
`already_seated`, and M3's `gate`, are defences on the link the
transaction just minted, never a well-formed request's refusal
(§Rejection codes).

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

A RE-SHARE (§The read predicate): account `1.0.1` shares its draft
`1.0.1.0.2` with account `1.0.2` again after revoking an earlier share,
its `replaces` naming that revocation — the record at `1.0.1.0.1.0.2.9`
in its doc 1 — and so honored where the revocation is still that key's
latest record. Replayed after a later revocation, the same request is
honored for nothing.

<!-- wire: request make_link -->
```json
{"from":{"addrs":["1.0.1.0.2"]},"home":"1.0.1.0.1","op":"make_link","replaces":"1.0.1.0.1.0.2.9","to":{"addrs":["1.0.2"]},"ty":{"addrs":["1.1.0.1.0.1.0.3.90"]}}
```

**`emit`** — gated typed-relation emission: a managed tuple of type `ty`
(the type key as an endset, usually unit subtree spans of type addresses)
from `from` to the `to` addresses, homed in `home`. Idempotent within a
type class AT THE CALLER'S VISIBILITY CLASS (PUB-6.25, PUB-6.26):
re-emitting an existing tuple acks the EARLIEST incumbent the caller's
class can read — an incumbent homed in a document the caller may not
read is invisible to the gate, so the re-emit mints afresh, and
value-identical tuples may coexist across the visibility boundary.
→ `ack_addr`. A `ty` that resolves into the retraction class is
`retraction_class` — retraction writes only through `nullify`. The
example retires `1.0.1.0.2` under the shipped Retired
class at its reserved ghost tumbler `1.1.0.1.0.1.0.1.3`: Unary, so `to`
is empty. On a CLAIMED board an `emit` into a published home carries the
optional top-level `attest` member (signed ops): the entry signature over
the frame whose `doc` is `home`, `op` `emit` and `body` the `make_link`
body's four rows over the tuple THE STORE DEPOSITS — the type slot row
`ty`'s spans verbatim, the `from` slot row the one address's unit span,
the `to` slot row one unit span per address and EMPTY (`0x03 ‖ be64(0)`)
at a Unary class, the `replaces` row EMPTY (an `emit` carries no member)
— so a reader composes it from `read_link` alone. A re-emit that acks an
incumbent commits nothing and fills no slot.

The five reserved type addresses are GHOST TUMBLERS — compiled format
constants at `1.1.0.1.0.1.0.1.x` for x = 1..5 (pred_def, pred_stable,
retired, supersedes, retraction): content positions 1–5 of doc 1 of
account 1 of the registry node `1.1`, T4-valid names at which nothing
exists and nothing is ever minted, so a reserved name can never equal an
allocated address. A type is a number: the daemon's semantics for the
five shipped classes are compiled in; every other type means what its
interpreting client says it means, and no document is semantically
authoritative for a type.

<!-- wire: request emit -->
```json
{"from":"1.0.1.0.2","home":"1.0.1.0.1","op":"emit","to":[],"ty":[{"start":"1.1.0.1.0.1.0.1.3","width":"0.0.0.0.0.0.0.0.1"}]}
```

**`nullify`** — the sole retraction path: retract `target` (a link) from
the active view, by a retraction homed in `home`. → `ack_addr` (the
retraction's address). Retraction lands at its target: on a claimed
board a bare session's `nullify` whose `home` or whose target's home is
published is `signed_session_required`, and a target that is
credential-typed, grant-typed, or of an audit-view class is refused to
its owner with the class's token — retraction is not how those records
end (§Links (writes) above; §Credential refusals, item 3). A signed
session's carries the optional top-level `attest` member (signed ops),
judged by the write-path check AHEAD of the class tokens: the entry
signature over the frame whose `doc` is `home`, `op` `nullify` and
`body` the `make_link` body's four rows over the retraction the store
deposits — the type slot row the retraction class's one unit span, its
reserved ghost tumbler `1.1.0.1.0.1.0.1.5`; the `from` slot row `home`'s
unit span; the `to` slot row `target`'s; the `replaces` row EMPTY. A
re-retraction that acks the incumbent commits nothing and fills no slot.
On the change feed a retraction homed in a draft against a public link —
the straddle below — serves its `attest` to the classes that read its
home and withholds it from the rest (§The change feed).

<!-- wire: request nullify -->
```json
{"home":"1.0.1.0.1","op":"nullify","target":"1.0.1.0.1.0.2.1"}
```

**`assert_sup`** — record "`old` is superseded by `new`". → `ack_addr`
(the claim's address). On a CLAIMED board, into a published home, it
carries the optional top-level `attest` member (signed ops): the entry
signature over the frame whose `doc` is `home`, `op` `assert_sup` and
`body` the `make_link` body's four rows over the claim the store deposits
— the type slot row the supersedes class's one unit span, its reserved
ghost tumbler `1.1.0.1.0.1.0.1.4`; the `from` slot row `old`'s unit span;
the `to` slot row `new`'s; the `replaces` row EMPTY.

<!-- wire: request assert_sup -->
```json
{"home":"1.0.1.0.1","new":"1.0.1.0.1.0.2.2","old":"1.0.1.0.1.0.2.1","op":"assert_sup"}
```

**`edit_link`** — one composite: create a successor of link `original`
(endsets given as content V-specs; the type slot either
`{"addrs": [addresses…]}` — the identical encoding of `make_link`'s
address form — or `{"resolve": [v-specs…]}`), homed in `d_s`, plus the
supersession claim homed in `d_a`. → `ack_edit`. On a CLAIMED board,
where either home is published, it carries the optional top-level
`attest` member (signed ops): the entry signature over the frame whose
`doc` is THE PAIR'S ROW — `d_s` then `d_a`, the op's own order, as an
address-list row of two (§Credential refusals, the entry frame's rows) —
`op` `edit_link` and `body` FIVE rows: the successor as a `make_link`
body — its type, `from` and `to` slot rows AS STORED, the I-extents its
V-specs resolve to (resolved by the client through `image` before
signing) and its type as named or resolved, then the `replaces` row EMPTY
(a successor typed `replaces` is refused) — and THE FIFTH ROW, the
claim's `from` slot row: `original`'s one unit span. The claim's `to`
(the successor's address, minted inside the transaction) and its type
(the supersedes constant) are no rows. A reader composes the five rows
from `read_link` at the successor and at the claim, the two homes off
the two links' own addresses.

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
submitted order. → `delivery`. A delivery past `MAX_DELIVERY_ITEMS` =
131072 items is refused whole, never truncated (`too_many_items`,
§Rejection codes).

<!-- wire: request retrieve_v -->
```json
{"op":"retrieve_v","specs":[{"doc":"1.0.1.0.1","span":{"start":"1.1","width":"0.11"}}]}
```

**`retrieve_i`** — THE READ BY IDENTITY (AUTH-6.38–6.40): deliver the
values at the I-ADDRESSES the `spans` name, each `{start, width}` a run of
`width` content positions from the element address `start`, in span order.
`start` is a T4-valid ELEMENT address of a document's content subspace and
`width` a natural; a span whose `start` is any other level is
`not_content_subspace` and an empty `width` is `empty_width`, each by index
(§Rejection codes). → `i_delivery`, one item per position — the value M4
holds there, or `null` where the document minted none (a position never
minted, or a link position). The read is gated by the SAME predicate the
arrangement reads take (§The read predicate): each span's document is
DERIVED from its `start` and consulted before the read, so a span into a
document you may not read is `withheld` naming that document, and nothing
of a value you may not read is delivered. A delivery past
`MAX_DELIVERY_ITEMS` = 131072 items is refused whole (`too_many_items`).

<!-- wire: request retrieve_i -->
```json
{"op":"retrieve_i","spans":[{"start":"1.0.1.0.1.0.1.1","width":"5"}]}
```

**`content_frontier`** — the next unminted content ordinal under `doc` —
its mint count plus one, the home's content chain peeked and not advanced
(AUTH-6.38). `doc` is a document argument: unreadable is `withheld`,
unregistered is `doc_not_registered`. → `frontier`. Every value `doc` ever
minted — arranged, deleted, or never placed — lies below the frontier, so
the read says how many it minted and nothing of what they hold.

<!-- wire: request content_frontier -->
```json
{"doc":"1.0.1.0.1","op":"content_frontier"}
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

**The class-scan bound** (PUB-8.36, PUB-8.37).
A query whose four-set constrains `ty` and NO other slot — `home`, `from`
and `to` all `"any"` — enumerates a whole type class: the design's
directory shape, `{ty: T_grant, home/from/to: any}` (PUB-6.54) and its
siblings (PUB-6.55, PUB-6.56), where the daemon pays a per-candidate home
test over every link of the class. THE COST AS BUILT: constraining `home`
narrows none of that walk. A home-constrained `find_links_ftt`,
`count_ftt` or `window_ftt` is served by the same scan of the link
store's whole ACTIVE slice, driven by its link-slot constraints (`from`,
`to`, `ty`; none constrained is the whole slice), the `home` slot a
per-link residence post-filter behind it — so its cost is the board's
active links (the class's, where `ty` is constrained), never the home's.
No home-granular skip exists at this build — an index of links by home,
and the skip in the descriptor scan, is not built — and until one is, a
home-constrained query pays what the class scan pays while the bound
below counts the SHAPE alone. Such a request —
`ty` constrained, the rest `"any"` — is a CLASS SCAN, and it is a SHAPE,
not a type list: any class queried that way is one, and the all-`"any"`
query — the whole store — is one too, being that shape's superset. `/op`
admits at most
**`MAX_CONCURRENT_CLASS_SCANS` = 2** class scans at once, across
`find_links_ftt`, `count_ftt` and `window_ftt` alike, across every type
class, and across every session and the guest — one pool for the board,
no per-principal quota. A class scan that finds every permit taken is
refused at once with

```json
{"detail":"all class-scan permits are in use; retry shortly","error":"scan_busy","op":"find_links_ftt"}
```

at `503` — a retry-class refusal, never a queue, its `op` naming the
refused frame — and costs the parse alone; an admitted scan holds its
permit for the WHOLE answer and returns it on every exit, an answer the
read predicate filtered to empty or a rejection included. This is a
CONCURRENCY bound and NOT a rate statement (PUB-8.37): a refused scan may
be reissued at once, and an admitted scan's answer is byte-for-byte what
the same frame answers unbounded — the bound admits or refuses a request
and never alters an answer, and the stores are not told a query is
bounded. The pool is DISJOINT from the reconstruction pool (§Reading
history): a scan spends no reconstruction permit and a reconstruction
spends no scan permit, so history panes and mirror bootstraps are never
starved by directory scans, nor the reverse. A query constraining any
second slot is not a class scan and takes no permit — the narrowest-slot
pins bound it — and `/op-at` takes no scan permit: a historical scan is
bounded by the reconstruction permit its whole answer already holds. The
count is a daemon constant this document names; raising it is a
configuration question, not a change to this contract.

Routed, not yet in the protocol: a POSITION FENCE on this query —
answer only records committed past a caller-supplied position, so a
polling consumer fetches only what is new to it — is reserved as a
later delta. Its composition note is pinned with it: a fenced
read must be composed with a client-held honored set, held whole from
unfenced reads, since a record LEAVING that set appears in no fenced
answer — without the held set the departure face is underivable. No
fence field exists today (an unknown field is a parse failure, as
everywhere).

**`count_v`** / **`count_ftt`** — the census forms of the two queries.
→ `count`. `count_ftt` takes the class-scan bound above exactly as
`find_links_ftt` does: a `ty`-only (or all-`"any"`) four-set is a class
scan.

<!-- wire: request count_v -->
```json
{"d":"1.0.1.0.1","op":"count_v","region":[{"start":"1.1","width":"0.5"}]}
```

<!-- wire: request count_ftt -->
```json
{"op":"count_ftt","q":{"from":"any","home":"any","to":"any","ty":"any"}}
```

**`window_v`** / **`window_ftt`** — the windowed forms: up to `n`
addresses past cursor `cur`. → `page`. `window_ftt` takes the class-scan
bound above too — the cursor narrows the page, never the population, so
a `ty`-only (or all-`"any"`) four-set is a class scan whatever `cur` and
`n` say.

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

**`edition_claims`** — the audit-view edition-claim lookup
(PUB-8.46): every admitted, unsuperseded claim of the
edition class (`ty` under `1.1.0.1.0.1.0.3.14`, its descriptive subtypes
included) whose `to` slot denotes `target` — the document or a version
of it — WHETHER OR NOT RETRACTED, each with its home (the edition) and
its `active` flag. `target` is a document argument (unreadable →
`withheld`); rows are then filtered to those whose home you may read
(§The read predicate), so a draft edition's claim is invisible to a
stranger. Retraction is by the home's `nullify` of the claim; supersession
is by `assert_sup` in the managed class, which drops the superseded claim
from this answer. → `edition_claims`.

<!-- wire: request edition_claims -->
```json
{"op":"edition_claims","target":"1.0.1.0.1"}
```

### Grants

**`universal_grants`** — the any-principal discovery read (PUB-8.47): the
grant fold's LIVE universal set — every content prefix an admitted,
unrevoked grant with an EMPTY `to` names, a document or an account
(§The read predicate) — with the issuers who granted it, one row per
prefix in prefix order, each issuer list in address order. It takes no
argument: the set is a board population, not yours, and every bound
principal — a bare session or a signed one, the issuer or a stranger — is
answered the same rows. It is empty for a guest (`rows: []`, an answer and
never a rejection): a grant reaches principals alone, and this read hands
a guest nothing a guest could read.

Here the served prefix is the covered one, never the stored prefix: a row
is the fold's index entry narrowed to what the fold ANSWERS from — the
`from` prefix as deposited where it is the prefix the registry's
`effective_owner` answers the issuer for, or the issuer's own account where
the `from` is wider — so every issuer listed owns the prefix beside it. A
record whose `from` names a document under someone else's account is
admitted, stands in the fold (`/dump`'s `grants` section lists it) and is
NO row here: the two are disjoint. An agent `X.1`'s grant whose `from` is
its hirer's account `X` is served at `X.1`, the agent's own space, grouped
with every other share served there. A hirer's grant whose `from` lies
under its registered sub-account `X.1` is NO row: `X.1`'s documents are
`X.1`'s (§Namespace, `effective_owner`). What you are handed is
therefore the set the daemon's own read predicate answers from, never a
superset to render as a face; it decides what a client may DISPLAY — the
arrival face, the any-principal arm, a back-fill — and nothing about what
is served, the change feed applying the same live set itself (§The change
feed). Revocation is immediate: a withdrawn grant's row is gone at the next
read. It is served on `/op-at` too, as of any committed position — present
at a position before the revocation, gone from it on — bound or guest
exactly as `/op` answers. Its cost is the live set's own size plus one
registry walk per stored row (`effective_owner`), never a scan of the
grants class. → `universal_grants`.

<!-- wire: request universal_grants -->
```json
{"op":"universal_grants"}
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
is an ordinary `/op` frame (§Operations, same codec; the session token is
honored exactly as on `/op`, so present one to read as its principal —
without one the read runs as the guest). The answer is the ordinary
response document for that operation, its `as_of` reporting `at`:

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

* **The reader's class is the presented session's; the predicate is the
  HEAD's**. The content is the position's, but the sets that
  decide what you may read — publication and grants (§The read
  predicate) — are the CURRENT head's, never the position's: a grant made
  after the position opens the draft at every position it exists at, and
  a revocation closes it everywhere. A document argument you may not read
  at the head answers `withheld` before anything is rebuilt — ahead of
  `history_busy`, `history_reclaimed` and the position's own
  `doc_not_registered` — and consumes no reconstruction slot. A masked
  `withheld` is a reorder that CAN resolve by waiting: for a grant.

* Envelope faults (missing or non-integer `at`, missing `frame`, unknown
  fields) are `400 {"error": "malformed_op_at", "detail": …}`. An
  unparseable `frame` is answered exactly as `/op` answers it: `200` with
  the `unparseable` rejection. An `id` inside the frame is accepted and
  ignored — reads are never memoized (§Correlation and idempotency).

**Determinism.** The same `at` with the same frame, read at the same
class, yields a byte-identical response body — across repeats and across
daemon restarts (sessions are uptime-scoped; the same principal under a
fresh token is the same class). A freshly started daemon answers
positions committed long before it started. `/op-at` at the current head
is byte-identical to the same frame on `/op`.

**Cost and retention.** Each historical read rebuilds the state at `at` by
folding the journal forward from the nearest on-disk checkpoint at or
below it — per request, uncached. This is an observation surface, not a
serving path: fine for history panes and diff tooling, wrong for a hot
loop. Reconstruction is bounded: at most **2** run concurrently, and a
call that finds every slot taken is refused at once with
`503 {"error": "history_busy"}` — a retry-class refusal, never a queue —
so historical reads cannot pin the whole worker pool. Live reads (`/op`,
plain `GET /dump`) never take a reconstruction permit; the one bound on
`/op` is the class-scan pool (§Link discovery reads), a SEPARATE
pool of the same shape — a scan spends no reconstruction permit and a
reconstruction spends no scan permit, so neither surface can starve the
other, and a historical class scan (`/op-at` over a `ty`-only four-set)
is bounded by the reconstruction permit alone. Retention is exactly what
the journal already provides: the daemon
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
position, AT THE PRESENTED TOKEN'S CLASS. Two worlds ride it
(PUB-6.48, as on `/op-at`): the STATE dumped is the position's — its
content, arrangements, links, and its as-of-N publication slice — and
the PREDICATE it is filtered through is the HEAD's, so a grant committed
after `at` opens a draft's sections at `/dump?at=N` exactly as it
satisfies a read there. Two calls with equal `at` at one class are
byte-equal; `at` = the current head is byte-equal to plain `GET /dump`
at that class. Position errors are `/op-at`'s, the reconstruction bound
included (`503 history_busy`); a malformed query is `400 {"error":
"malformed_at", "detail": …}`.

**`GET /chain?at=<position>`** — the commit chain's value AS OF that
position: `200 {"at": N, "chain": "<64 lowercase hex>"}`, the value
`/health` serves as `chain_head` for the head (§The other endpoints), at
any committed position, RECOMPUTED by the kernel off its own journal
under the verification a historical read runs — every link from the
checkpoint it selects at or below `at` to the journal's END, so a
position below the newest checkpoint verifies the whole surviving
journal from the base it selects — with no world materialized.
Token-blind and class-invariant like `/health`: every link's preimage
carries a per-transaction SALT — thirty-two random bytes stored in the
commit marker (`SKJ4`) and served by no route — so a served chain value
confirms no guess at a transaction's bytes, even to a reader holding the
value before it and able to enumerate the transaction's candidates, and
`/health` already serves the head's value to everyone. Every link's
preimage also carries, last, a SHA-256 digest of the marker's SIGNATURE
SLOT exactly as the marker holds it — the tag, the blob's length prefix,
the blob; the empty slot's nine bytes at an unsigned transaction — so an
entry signature stripped from a committed marker, or altered in it, is a
chain break at that transaction: the board does not open, its history
reads refuse, and any saved pair contradicts it (signed ops; the design
record's r6-2c). At the current head it equals `chain_head` beside
`log_position`, at a retained checkpoint's own position it is that
checkpoint's header value, and at `0` it is the genesis seed. Position
errors are `/op-at`'s — `beyond_head`, `not_a_position`,
`history_reclaimed`, the reconstruction bound `503 history_busy` (it
rides the same permit pool, conservatively: the scan reads what a
reconstruction reads), `history_io` / `history_corrupt` — and a malformed
or ABSENT query is `400 {"error": "malformed_at", "detail": …}`. What it
is for: any `(position, chain)` pair a client holds — a `/health` reading
it saved, a published head's own members, a pair another peer relayed —
is checkable against the board's recomputation while the position is
above the reclaim floor. A journal re-chained after the fact — a
signature stripped and every later link re-chained included — answers
the forged value here, which the saved pair contradicts, where a stored
head record the forger left untouched still re-reads byte-equal; a tail
cut answers `beyond_head` or a different value. Below the floor nothing
answers, and the answer is the serving daemon's word, as every answer
here is.

The I-ADDRESSED value read lands here: `retrieve_i` (the read by identity)
and `content_frontier` (the home's mint frontier) are reads like any other,
so `/op-at` answers each as of a committed position — the frontier at N plus
the values under it, a fact no arrangement-addressed read composes (an
address minted and later un-arranged answers like one never minted). Their
consumers are the mirror fold and realm verification, and the blob fetch's
own gate (§Media). The live forms are on `/op` (§Content & provenance
reads).

## The commit stream

**`GET /events`** answers `200 Content-Type: text/event-stream` and never
ends on its own: it is the daemon's push channel for log movement, so
clients stop polling `/health`. No session is needed — the stream carries
positions alone, nothing the read predicate gates — but the route is
token-accepting (§Sessions): a dead
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
  what you care about — reads are cheap, and answer at your session's
  class.
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
  write names its **home** (`edit_link` both its homes, successor's first;
  `nullify` — PUB-6.46 — its home AND the target link's home, a
  SET with each document named once, so a same-home retraction carries
  one name); the **minted** document for
  `create_new_document`/`fork`/`version`,
  and the minted MEMBER for `publish` (`1.0.1.0.1.2`, whose
  trunk is the document it advances); `delegate` and `register_node`
  touch no document and carry `[]`. A declared deposit into a
  published chain names the address the `insert` was written to,
  though the arrangement it lands in is the chain's head member (§The
  publish shot and head-float) — a client refreshing the head re-reads
  the bare address, which floats. The list you see is REDUCED to the
  documents you may read (below).
* `key` — the write's AUTH testimony (AUTH-6.15), PRESENT IFF THE ENTRY IS
  UNSIGNED, with four values: the 64-hex fingerprint of the enrolled key
  whose signed session committed it; `"bare"` for a bare-session write;
  `"system"` for a write the board's own daemon makes in-process with no
  session, as the system account's principal — the published head
  document `H` and its staging draft, and no other write (§The other
  endpoints, PUB-6.65); `null` ONLY for lost metadata (a bare entry, or a
  record written before testimony existed) — never for a bare write, and
  never invented. ABSENT, never null, on a row whose entry carries a
  signature — in its marker slot (the row then carries `attest`, below) or
  in its record's own `sig` member (a credential record deposit's LINK
  row, the `make_link` naming the atom, where the record grade judged the
  `sig`; §The claim ceremony and credentials) — on every feed, the
  origin's own included: a signed entry has one authority for its hand,
  its own signature, and the daemon asserts no second beside it. PRESENT
  on the deposit's ATOM row, the `insert`: the daemon's testimony of the
  writing session, the one asserted hand an orphan atom keeps when every
  link naming it is refused. Served on every other row too — draft writes,
  `delegate`, `register_node`, the claim ceremony's own rows and the
  published head document's. Forward rule, pinned now: on a feed served by
  a daemon that did not itself commit the entry (a future mirror), the
  field is ABSENT on unsigned rows too — a consumer written to the four
  values must not treat absence as a protocol violation (AUTH-6.16).
* `time` — the commit's wall-clock unix milliseconds, or `null` (below).
* `attest` — the entry's signature as its commit marker holds it (signed
  ops): `{"alg": <an ALGS token>, "sig": <hex>}`, byte-equal to the `attest`
  the request presented (§Operations) — `alg` the token the request took,
  `sig` the blob as hex — on a row whose entry's marker slot is filled;
  `null` ONLY where the daemon recorded the marker filled and its store of
  slots (`feed-attest.log`, below) cannot answer — LOST, which a reader
  renders undeterminable and never as unsigned; ABSENT on every other row:
  an unsigned entry, a credential record deposit's two rows (the deposit's
  slot is empty; its signature is the record's own `sig`, fetched with the
  atom), the ceremony's rows, the head writer's `system` rows — and ABSENT
  on a row whose `docs` your class REDUCES (the straddle renderings
  above), the third absence: there the entry may well be signed, and its
  verdict is undeterminable from your feed alone. On the
  origin's own feed an absent `attest` above the claim on a row served
  WHOLE is a verdict — the entry is unsigned — so a party re-serving this
  feed carries the member as it received it and never drops it. On a bare
  entry the member is served wherever the store holds the slot: the slot
  is the journal's own fact, and the null testimony beside it stays lost.
* `new_prefix`, `new_id` — on a `delegate` row (AUTH-6.36): the minted
  account address in the board's local form — the `ack_addr` the op
  answered — and the principal id it seated, a JSON number in the wire's
  exactly-representable range (at most 2^53 − 1, held at the parse). A
  feed-only mirror builds the board's principal list Π from these rows
  alone, never from the node registry; `effective_owner` (§Operations)
  stays the board's own authority for ω. On a bare row, the JOURNAL's
  answer (below); absent on every other op's row.
* `link` — on a `make_link` row: the minted link's address, the `ack_addr`
  the op answered. For a replacing grant (§Links (writes), `replaces`) this
  is the RECORD's address; its `replaces` link sits at the next address in
  the same home, read by adjacency. The claim link's row therefore names
  the claim link's address, which is how a reader maps the link
  `find_links` answers to its commit position. On a bare row, the journal's
  answer (below); absent on every other op's row.
* `placed`, `base_extent` — on a `publish` row: the shot's two client terms
  exactly as `doc_metadata` serves them for the minted member (§Operations)
  — `placed` the count of positions the client placed (the sum of the
  shot's runs' widths, the count its signed body leads with), a decimal
  string; `base_extent` the extent of the base the staged copy took, a
  decimal string, or `null` in the birth shape (the shot carried no `base`;
  the absence is the birth bit). The base member itself is derived from
  the member's own address and composed into the signed base group beside
  this extent, so these two are what a verifier composing the entry frame
  from the feed alone still needs. On a bare row, the journal's answer
  (below); absent on every other op's row.

A client MUST ignore an entry member it does not know, and a member of
the page object likewise: an entry gains members by later deltas (the six
above joined the original five under this rule), and a consumer written to
today's eleven must not treat a twelfth as a protocol violation.

Only writes appear: reads are not in the journal and never enter the feed.
Rejected operations committed nothing and never appear. An idempotent
retry re-acknowledges the original commit — one entry per commit, ever.

**The feed is class-gated** (PUB-6.44–6.47).
The route accepts `Skepd-Session` like every read (an absent or dead token
is the GUEST), and every entry is classified over its `docs` — the target
for arrangement writes, the HOME for link writes, the MINTED document for
mints — never over sources read, against the read predicate (§The read
predicate) at the presented token's class, off the one head snapshot the
page is answered from:

* an entry whose `docs` is non-empty and none of them readable to you is
  MASKED — OMITTED from the page, never present with nulled fields (null
  is reserved for lost metadata, below); otherwise it is shown with
  `docs` REDUCED to the ones you may read, in the record's own order;
* `[]`-docs entries (`delegate`, `register_node`) are never masked;
* `limit`, `last` and `more` are computed over the VISIBLE stream: a
  page is never short of `limit` before the head, paging cannot stall on
  a masked run, and `last` is a visible position or your `since` echoed;
* a bare entry (lost testimony) classifies FROM THE JOURNAL — the daemon
  reconstructs the documents the commit touched (the drafts it minted,
  the homes of the links it deposited, the drafts whose arrangement it
  moved) and masks it exactly as it would the record — so a lost sidecar
  never unmasks a draft write; its testimony fields, `docs`, `key` and
  `time`, still read `null`. THE OP'S TERMS ARE THE JOURNAL'S TOO (signed
  ops, round 7): a bare row carries what the journal's own records
  answer, exactly as the recorded row would have — a `delegate`'s
  `new_prefix` and `new_id` with `op: "delegate"` (a principal seated),
  a `publish`'s `placed` and `base_extent` with `op: "publish"` (a member
  minted with its placing record; a member minted without one is a
  `version`), a replacing `make_link`'s `link` with its `op`, a `nullify`
  by its `op` alone, and `link` for the one link any other link write
  deposited, its `op` left `null` (a plain `make_link` and an `emit`
  deposit one link alike, so a bare `emit` row carries a `link` its
  recorded row did not). A member the journal rules out is ABSENT as on
  the recorded row; one it cannot decide — the op of an arrangement write
  or a document mint, a `delegate` under a node `register_node` admitted
  that no walk from the board's own nodes reaches, a `publish` under such
  a node — stays `null`. So a feed-only mirror's Π is whole across a bare
  span; where it is not — a bare span whose rows name no `delegate` where
  one was committed — Π is UNDETERMINABLE for every entry under it, and
  so is every verdict ω composes there: the mirror's rule, stated here and
  built nowhere;
* the two STRADDLE renderings, accepted residues (PUB-6.47): a
  draft-homed `nullify` of a public link in `T` is a `[D, T]` entry a
  guest sees as `{"op":"nullify","docs":["T"]}` — never omitted, and
  indistinguishable from a same-home retraction, which reduces to `[T]`
  identically; an `edit_link` with `d_s` public and `d_a` a draft
  reduces to `[P]` under `op: "edit_link"`. From either a guest learns
  that a draft-homed record EXISTS — its type, its target or public
  `new`, its commit position — never its home, `old`, or a byte; and
  NEVER ITS SIGNATURE: a row whose `docs` your class REDUCES carries no
  `attest` member — ABSENT, not `null` — the entry's signature being a
  function of the home the row withholds, which served would confirm a
  guess at that home; the row carries no `key` either, so its verdict is
  undeterminable from your feed, and whole on the owner's.

A principal's page is its SUPPLEMENT merged over the published stream:
its own account's draft writes, its ancestor accounts' and its
descendant accounts' — every owner account beneath its own (the subtree
clause runs both ways, PUB-7.24; principal 0, seated at the node, has
neither) — those of the drafts a grant to it names, and — for
every bound principal, never the guest — the drafts under a live
ANY-PRINCIPAL grant, derived at serve from the grant fold, so a
revocation leaves the next page with no restart. Each position appears
once.

**Timestamps are transport metadata, never substrate state.** They are the
daemon's testimony about when *it* committed each transaction — two
daemons replaying one journal still converge on byte-identical worlds,
and times ride beside the world, not in it. A position whose testimony
was lost answers `null`, never an invented value.

**Paging.** `limit` (default 256, maximum 4096; out-of-range values are
refused, not clamped) caps the page, and THE PAGE BYTE BUDGET caps its
bytes (signed ops, round 7; SO-I9): a page whose entries would marshal
past 2 MiB — 256 rows, the default page, × 8 KiB, the bound on a row the
wire admits, an attested row under tag 1 being ~6.9 KB of `sig` hex — is
REFUSED whole, `400 {"error": "malformed_changes", "budget": 2097152,
"fits": N, "detail": …}`, `fits` the largest `limit` whose page from the
same `since` fits the budget: re-ask with `limit=N` and the page is served
whole. Never a page shorter than `limit` before the head. The default
page of attested rows always fits; a reader of a signed feed pages at or
below ~300 rows. The response carries `last` — the
final entry's position, or your `since` echoed when the page is empty —
and `more`; pass `last` as the next request's `since` to page. `since` is
a fence, not necessarily a position: any number works, and `since ≥ head`
answers the empty page. Determinism is PER CLASS (§Determinism, PUB-8.26):
the same `(since, limit, under, drafts)` against the same journal, at the
same head publication and grant state and the same class, answers
byte-identically, across repeats and restarts.

**Narrowings** (PUB-7.31, PUB-7.35). `under=<address-or-prefix>` —
a dotted-decimal tumbler, an account prefix or a document — narrows the
feed to the entries whose REDUCED `docs` name a document at or under it,
masked exactly as the plain feed is: for a draft you cannot read the
page is empty, `last` your fence. One residue of lost testimony
(PUB-7.21): a bare entry re-derived from the journal for an arrangement
write or a mint into a PUBLISHED document names no document — the
journal enumerates the drafts and link homes a commit touched, never a
published document an arrangement write or a mint touched — and so is
absent from the plain `under=` narrowing: silent incompleteness, never a
wrong answer; the drafts-only form and the plain feed stay complete.
`drafts=true` narrows to the entries
whose reduced `docs` name a DRAFT you may read — your supplement alone,
empty for a guest by construction, the live universally-granted history
included and the revoked never. The two compose. Their consumers are the
client's own rules, stated once here: RESUME-BY-READ (PUB-8.32) —
`/changes?under=<own prefix>` from your last known position BEFORE any
re-mint, a minting op having no cross-restart memo; and the widening
triggers (PUB-7.36–7.38) — a grant naming you (or ANY-PRINCIPAL)
committed after your `since`, or a change of your own class (sign-in,
principal switch, session death), is your trigger to fetch
`drafts=true` per range the wider class adds (`under=` your own,
ancestor and descendant account prefixes — a descendant's lies under
your own, so your own prefix covers them all — and each grant's
prefix), from your own
last-held position per range and from the floor only where the range is
new to you, deduplicating by position with the wider rendering winning
(a straddle held as `[T]` re-arrives as `[D, T]`). Fetched entries are
history — place them by position, never surface them as new activity.

The examples below are produced by this flow on a fresh board, asserted
against live daemon bytes (the `time` values are illustrative — the one
normalized field). A fresh board's first five commits are the claim
ceremony's own (§A first board): positions 2, 3, 6, 9, 12 — the
delegate, the home mint, the record insert, the genesis link, the claim
link — and the claim's own step then writes the board's first head `H.1`
(§The other endpoints, the published head document): the system
account's staging-draft mint at 13, the head record's insert at 16, the
publish into `H` at 20 — the publish a public entry with `key: "system"`,
the two before it writes into the system account's private draft, masked
at every class but the system's. The flow behind the examples then runs
on that base, from bare sessions (CLAIMED-PERMISSIVE, so every `key`
reads `"bare"`, and no entry is signed, so no row carries `attest`):
`delegate` commits at position 22 — its row carrying the minted pair —,
the home mint at 23, a second — private — document at 24 (the account's
doc 1 is born published, where bare writes are gated by design, so the
flow's content goes to a draft document), a two-byte `insert` at 29,
`make_link` at 32 — its row carrying the minted link's address. The feed
past the ceremony and its head, `GET /changes?since=20`, read AS
PRINCIPAL 1 — the owner of the private document, whose class sees every
one of these:

<!-- wire: changes feed -->
```json
{"changes":[{"at":22,"docs":[],"key":"bare","new_id":1,"new_prefix":"1.0.2","op":"delegate","time":1786838400000},{"at":23,"docs":["1.0.2.0.1"],"key":"bare","op":"create_new_document","time":1786838400012},{"at":24,"docs":["1.0.2.0.2"],"key":"bare","op":"create_new_document","time":1786838400021},{"at":29,"docs":["1.0.2.0.2"],"key":"bare","op":"insert","time":1786838400033},{"at":32,"docs":["1.0.2.0.2"],"key":"bare","link":"1.0.2.0.2.0.2.1","op":"make_link","time":1786838400047}],"last":32,"more":false}
```

The first page of the same feed, `GET /changes?since=20&limit=2`:

<!-- wire: changes feed_page -->
```json
{"changes":[{"at":22,"docs":[],"key":"bare","new_id":1,"new_prefix":"1.0.2","op":"delegate","time":1786838400000},{"at":23,"docs":["1.0.2.0.1"],"key":"bare","op":"create_new_document","time":1786838400012}],"last":23,"more":true}
```

The same feed read as the GUEST (no token): the private document's
mint, insert and link are masked — omitted, with `last` the last visible
position and `more` false, since nothing visible remains:

<!-- wire: changes feed_guest -->
```json
{"changes":[{"at":22,"docs":[],"key":"bare","new_id":1,"new_prefix":"1.0.2","op":"delegate","time":1786838400000},{"at":23,"docs":["1.0.2.0.1"],"key":"bare","op":"create_new_document","time":1786838400012}],"last":23,"more":false}
```

A SIGNED entry's row, for contrast — a grant link deposited into the
claimant's published doc 1 from a signed session on a claimed board, its
`attest` the request's own, byte for byte, and no `key` (illustrative:
the blob is 6,746 hex characters under `mldsa65-ed25519`, elided here,
and the position and time are a board's own; the change-feed suite
asserts the row's members against live daemon bytes):

```json
{"at":21,"attest":{"alg":"mldsa65-ed25519","sig":"<6746 hex>"},"docs":["1.0.1.0.1"],"link":"1.0.1.0.1.0.2.3","op":"make_link","time":1786838400052}
```

**Bare entries.** A position whose metadata the daemon never observed — a
data dir written before this feature existed, or a record lost to a crash
— still appears, reconstructed from the journal itself, with every
metadata field `null` — the op's own terms included, its op being unknown
— (and masked at your class from what the journal shows it touched); its
`attest` is served where the store still holds the slot, and is otherwise
absent. A pre-feature data dir holding three writes (a delegate at 2, a
mint at 3, an insert at 8 — written by the engine directly, before any
daemon; all in the published world, so every class sees them), byte-exact:

<!-- wire: changes bare -->
```json
{"changes":[{"at":2,"docs":null,"key":null,"new_id":1,"new_prefix":"1.0.1","op":"delegate","time":null},{"at":3,"base_extent":null,"docs":null,"key":null,"link":null,"new_id":null,"new_prefix":null,"op":null,"placed":null,"time":null},{"at":8,"base_extent":null,"docs":null,"key":null,"link":null,"new_id":null,"new_prefix":null,"op":null,"placed":null,"time":null}],"last":8,"more":false}
```

**Retention.** The feed's memory is the daemon's `commits.log` sidecar
plus what the journal can still reconstruct. When `since` reaches below
that — reclaimed or unreadable journal regions — the answer is the same
discipline as `/op-at`: `410 {"error": "history_reclaimed", "floor": F?}`,
`F` the oldest position that still has an entry, the same for every class
(positions are class-invariant). A malformed query
(missing `since`, a non-integer, an out-of-range `limit`, an `under` that
is not a dotted-decimal tumbler, a `drafts` that is neither `true` nor
`false`, a repeated or unknown parameter) is `400 {"error":
"malformed_changes", "detail": …}` — as is a `limit` whose page would pass
the byte budget (Paging, above), that body carrying `budget` and `fits`.

**The feed's files.** Beside `commits.log` the daemon keeps four derived
sidecars in the data dir — `feed-index.log` (document → positions),
`feed-offsets.log` (position → byte offset into `commits.log`),
`feed-masked.log` (the positions masked at commit) and `feed-streams.log`
(position → the owner accounts whose drafts it names) — appended at
commit outside the journal transaction, tail-checked against the head at
open and rebuilt from `commits.log` and the journal on loss. The five are
COMPACTED to the journal's reclaim floor — their entries below it dropped
and each file rewritten whole — at open and, the floor moving at a
checkpoint and at no other moment, after each checkpoint the daemon's own
checkpoint thread lands, while serving; a rewrite that fails past its
rename there STOPS that file for the uptime, said once on the operator
stream, the next open re-deriving it, and fails no write. They persist
nothing about the world and decide nothing about what you may see: an
entry's class is the read predicate's, re-applied per rendered entry. A
fifth file in their shape has a class of its own: `feed-attest.log`, THE
ATTEST STORE (position → the marker slot's `alg` tag and `sig` hex, one
line per attested commit), appended at commit from the very value the
write-path check admitted and rebuilt from the journal's markers above
the reclaim floor. Below the floor — where `commits.log` and the four
drop their entries (Retention, above) — it KEEPS its lines: the
checkpoint holds no marker, so a line there is an entry signature's only
copy at the origin, primary state and not a projection, backed up with
the board directory as `blobs/` is; a line lost there is served as
`attest: null`. `commits.log` records only THAT an entry was signed and
by which carrier, never the signature itself; a bare line of it carries
the journal's answer for its row under one `journal` member, written by
the open that reconstructed the position, so the reconstruction is paid
once.

**Residues, named** (PUB-6.52): `/events` and `/health`'s `head_time`
move on masked commits too — board-wide draft-write cardinality and
timing, never which document — positions being durable coordinates that
are never renumbered per class; and the two straddle renderings above.

## The other endpoints

**`GET /health`** → `200` with `ok`, `log_position`, `head_time`,
`chain_head` and the `auth` object. Token-blind, and
class-invariant (§Cross-origin access: it carries neither cache header —
the one answer for every requester). `head_time` is the newest recorded
commit's wall-clock unix milliseconds (§The change feed's timestamp
scope: transport metadata) — `null` on a fresh world or when the head
position's record is bare. `chain_head` is the commit chain's value at
the COMMITTED HEAD: a string of 64 lowercase hex characters, the 32-byte
SHA-256 link
the kernel's journal computes at every commit over the previous link and
that transaction's canonical record frames and marker fields — its salt,
and a digest of its signature slot (§Reading history, `/chain`) — from a
genesis seed of thirty-two zero bytes. It is the kernel's value, served
as the journal holds it and never recomputed by the daemon; and it is
the chain OF THE `log_position` BESIDE IT — the two are read off ONE
kernel snapshot (the root carries the position and the chain together),
so the pair names one committed state: the value the
published head is to carry — not yet in the protocol — and what a peer
holding an older head will check a newer history extends. A fresh world
answers the seed, sixty-four `0`s at `log_position` 0 — never `null`; a
kernel running in-memory would answer the seed at every position, there
being no frames to hash, but this daemon always journals, its test
harness included. `head_time` and `auth` are separate reads under no
lock, so either may straddle one in-flight commit against the pair — a
`head_time` one position behind, or a claim visible in one field before
the other — and every such reading corrects itself on the next probe.
The forward rule the change feed states for its own members (§The change
feed: "a client MUST ignore an entry member it does not know … a consumer
written to today's members must not treat a later one as a protocol
violation") holds here too: a consumer written to these six members must
not treat a seventh as a violation. A claimed board configured with one
origin answers, illustratively:

```json
{"auth":{"claimant":"1.0.1","local_trust":true,"origins":["http://127.0.0.1:8642","http://[::1]:8642","http://localhost:8642","https://board.example"],"signed_origins":["https://board.example"]},"chain_head":"a65b74b44f6e7c4338342b8a6a8760b6d73e753b57492fc43b3ab2599f7b75b7","head_time":1786838400047,"log_position":24,"media":{"uploads":true},"ok":true}
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
`media` is the media resource's settings as the daemon was launched with,
daemon config like `auth.local_trust` and never board state:
`media.uploads` echoes the upload setting (§Media, THE UPLOAD SETTING —
`--no-uploads` closes the upload family), the one read a client makes
before any face that names an upload speaks.

**The published head document** — `1.1.0.1.0.2`, the version-chain document
`H` (PUB-6.65). The board's OWN daemon writes `H` as
a NEW PUBLISHED VERSION of itself on the write path's cadence, a `skep-head`
record: ONE JSON object whose members are, in this order and no other, `type`
(`"skep-head"`), `format` (the journal stamp the `chain` was computed under,
`"SKJ4"` today), `position`, `chain` (64 lowercase hex), `base` (the newest
retained checkpoint at or below `position` — `seq`, `chain`, `body_hash` — or
`null` before the first) and `prev` (the previous head's `position` and
`chain`, or `null` at the first). No timestamp (two heads of one board at one
position are byte-identical) and no `sig` — the head is UNSIGNED. THE CLAIM
WRITES `H.1`: the board's first head is committed by the daemon in the claim's
own serialized step, right after the claim link and before any later write is
admitted, naming the claim's own position — so a claimed board has the board
term every attested write's entry frame names (§Sessions,
`attestation_invalid`) from the claim's step, or from the write path's next
turn after a refused `H.1`: where the head writer's driver refuses it the
claim stands, the one attested write after it answers
`attestation_invalid:board_unavailable`, that write's own turn writes `H.1`
(the "claimed, no head" test runs at every turn of the write path, a refused
write's included, ahead of the cadence's triggers) and its retry is admitted
— and a daemon that opens a claimed board whose journal
holds no head (a crash between the claim and its head) writes `H.1` before it
serves; where the cadence below already wrote a head before or at the claim,
the claim writes none. Every later head is written when 64 commits that are
not the writer's own have landed since the last head, OR the newest retained
checkpoint moved, OR an hour has passed and the position moved — never on a
peer's request, never twice for one position.
`/health` is the LIVE pair (this instant, no address, uncopyable); `H` is the
DURABLE record — addressable, guest-readable (`retrieve_v` on the bare `H`,
no token, floats to the latest head; `H.k`, the k-th version member, is pinned
forever), versioned and mirror-carried, and it survives reclamation as
checkpoint state. It is what a peer holding an older head re-reads to check a
newer history EXTENDS it: re-read `H.k` byte-equal and the board still stands
by that `chain` at that `position`; different, gone, or superseded by an older
newest head, and it does not. And a saved pair — a head's own `(position,
chain)`, or a `/health` reading — is checked against the board's
RECOMPUTATION at `GET /chain?at=<position>` (§Reading history), which a
re-chained journal cannot pass while the byte compare of an untouched
`H.k` still does. Each head shows on `/changes` as one public
`publish` entry with `key: "system"`; the staging draft the record is composed
in is a private document of the system account, masked at every class.

**`GET /`** (only in builds with the `client` feature — **default-off**
by ruling (AUTH-4.57(e); R89, the client rule): a board-served page is
never an acting client — it is the GUEST READER, which generates no
key, opens no session and runs no ceremony; the acting client is the
holder's own installed frontend. So the safe failure is a notebook build
that forgot the flag serving no page, never a hosted image serving a
page by omission; notebook packagings opt in deliberately) → `200
text/html`: the embedded reader, one self-contained HTML file embedded
in the binary at build. It presents no token on any route it dials, so
it reads the published world as the guest — read frames to `POST /op`
and `POST /op-at`, the head off `GET /health` and `GET /events` — and
acts on nothing. There are no other static routes and no asset pipeline
— the reader is one file by design. Without the feature, `/` is an
unknown path (the usual 404 shape).

**`GET /dump`** (only in builds with the `observe` feature; absent
otherwise, so a plain build answers 404) → `200 text/plain`: the engine's
deterministic world dump — format **`skep-world-dump v5`**, the banner
the code emits — AT THE PRESENTED TOKEN'S CLASS. The hints section
carries `publication.drafts` (PUB-8.29/PUB-8.30), and the root a
`publication` SECTION — the authoritative draft slice, address-sorted,
the state the hint is a derived index over
— and a `grants` SECTION — the grant fold's operative set, each grant by
its link address with its home, issuer, content-prefix and grantee.
The dump is PER-CLASS: the GUEST (an absent, unparseable, unknown or
dead token) sees the published world alone — its `publication` slice
renders empty, and no draft's content lines, arrangement, link or hint
appears; a session principal additionally sees every draft its class
reads (its own subtree, and those a grant opens to it). A supersession
edge in `hints.supersession` is kept only where a CLAIM asserting it is
homed in a document the class reads (PUB-6.13, PUB-6.22): a
draft-homed `assert_sup` over two public links leaves the guest's dump
entirely, as it leaves `in_claims`. The identity
section (M3) and the `grants` section are kept whole for every class.
Byte-comparable across processes AND across equal classes for run
reconstruction: two dumps of equal worlds at one class are byte-equal.
As built the dump carries NO dedicated identity section: the identity
table is DERIVED state — a pure function of the credential deposits,
which are ordinary links already in the dump's links slice — so
byte-equal dumps imply equal identity tables, and `key_set` (not the
dump) is the identity read surface. `GET /dump?at=N` serves a historical
position at the head's class (§Reading history). The route is
token-accepting (the death signal rides it), and the dump is filtered at
the presented token's class.

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
                        "deposit": "1.1.0.1.0.1.0.3.1",                 # T_enroll — the record's class type
                        "values": [{"atom": "{\"type\":\"skep-enroll\",\"keys\":[{\"alg\":\"mldsa65-ed25519\",\"key\":\"<3968 hex>\",\"anchor\":true,\"label\":\"paper\"},{\"alg\":\"mldsa65-ed25519\",\"key\":\"<3968 hex>\",\"anchor\":false,\"label\":\"notebook\"}]}"}]}
```

The insert is DECLARED under the record's class type (`"deposit":
"1.1.0.1.0.1.0.3.1"`, T_enroll; §Arrangement): doc 1 is born published,
and a record atom declared under a type the deposit class holds is the
write a published document admits — an undeclared insert into it, or one
declared under any other type, is the in-place edit the store refuses
`published_target`. The store's test is session-blind, so this bare
pre-claim insert is admitted on it. The `make_link` below carries the
SAME type (PUB-2.63).

Deposit it — the genesis enrollment, then (from a signed session,
proving custody before the flip) the claim:

```
POST /op   (session)   {"op": "make_link", "home": <doc 1>,
                        "from": {"addrs": ["<doc 1>.0.1.1"]},           # the record atom's position
                        "to":   {"addrs": ["<account>"]},
                        "ty":   {"addrs": ["1.1.0.1.0.1.0.3.1"]}}       # T_enroll
GET  /challenge?principal=900
POST /session          {"principal": 900, "nonce": <that>, "origin": <a configured origin>, "sig": <6746 hex — the hybrid blob, both halves>}
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
