# Architecture

This document describes how skep is laid out: what each part owns, which
way the dependencies point, and the rules that hold across files. Read it
before changing code you did not write. It says what is true of the code;
the reasons behind the design live in the documents linked at the end.

## Bird's-eye view

skep is a document store in which nothing is ever overwritten. Content is
written once and addressed forever; documents are arrangements of that
content; links connect spans of it. Every change is a transaction appended
to a journal, and the whole state can be rebuilt from the journal.

A client talks to one process, the daemon `skepd`, over HTTP and JSON on
the loopback. A write arrives as an operation; the daemon checks who is
asking and whether they may do it, applies it to the world through one
serialized write path, records it, and announces it. A read is answered
against the current world, or against the world as it stood at an earlier
position in the journal.

## Code map

The workspace is sixteen crates under `crates/`. Dependencies point
downward in the list below: a crate may depend only on crates listed
above it.

**The foundation**
- `skep-address` — tumblers, addresses and span algebra. Pure values; it
  depends on no other skep crate.
- `skep-kernel` — transactions, the journal, checkpoints and recovery. It
  knows nothing of what a transaction means; the world it stores is a
  type parameter the engine supplies. Its modules and rules: §The kernel.

**The stores** — each owns one slice of the world and depends only on the
foundation and on the stores above it.
- `skep-namespace` — the name space: it mints every address and builds the
  lock keys the stores take; the entity and principal registries and
  ownership (ω); each document's publication bit. Its modules and rules:
  §The name space.
- `skep-content` — the write-once map from address to value.
- `skep-arrangement` — documents as arrangements of content, versions,
  provenance. Its modules and rules: §The arrangement.
- `skep-links` — typed links, supersession, retraction.
- `skep-retrieval` — content and provenance queries.
- `skep-discovery` — finding links, projection.
- `skep-coordination` — predicate definitions and the coordinator.
- `skep-identity` — credential records, key sets, the identity fold. Pure;
  of the skep crates it depends only on `skep-address`.
- `skep-signature` — the hybrid signature's frozen rules: the KDF, keygen
  and signing (behind its `sign` feature), the key and blob layouts, the
  verify. The one crate that links the signature libraries; skepd calls its
  verify. Of the skep crates it depends only on `skep-identity`.

**The surface and the assembler**
- `skep-febe` — the operation surface (`OperationSurface`): one front door
  that dispatches every operation to the stores, and the codec seam a
  transport fills. Its modules and rules: §The operation surface.
- `skep-engine` — the one assembler. It defines `World` from the stores'
  slices, genesis, recovery and reads at a past position. Nothing depends
  on it except `skepd`, the conformance harness and — as a dev-dependency,
  for the fixture its hazard, golden and chain suites share —
  `skep-kernel`.

**The programs**
- `skepd` — the daemon (below).
- `skep-mcp` — a stdio adapter for agent harnesses.
- `skep-conformance` — a differential harness against `udanax-green`'s
  goldens.

## The kernel, `skep-kernel`

The kernel owns one directory: the journal's segments (`seg-<n>.wal`), the
checkpoints (`checkpoint.<n>`, each written through `checkpoint.tmp`) and
the exclusion lock (`kernel.lock`). One applier lock serializes every
write; a write is appended, fsynced, and only then installed as the root
that lock-free readers load. The world is a type parameter: the kernel
folds records through `WorldState::apply` and never reads them. Its
modules are declared in `src/lib.rs` in dependency order, each with a line
saying what it holds.

Rules that hold across its files:

- **Durable before visible.** `Kernel::transact_attested` hands the
  journal an install closure, and only the journal runs it:
  `JournalWriter::commit_txn` appends, fsyncs, then installs, inside one
  call; the in-memory journal, which has no barrier, installs at the same
  point.
- **A halt cuts nothing.** Every refusal in `Kernel::open` precedes
  `journal::truncate_tail`, recovery's one destructive step.
- **One door to the write state.** `ApplierLock::acquire`, which refuses
  a nested acquisition, is the only way to the sequencer, the journal and
  the cadence; the lock's fields are private to `kernel/applier.rs`.
  `Kernel::checkpoint` never takes it: its own mutex may be taken under
  the applier lock, never the reverse.
- **A scan and its fold share a base.** Scans are reached through
  `replay::Base::scan`, never by a caller supplying `S_load`.
- **One skip rule.** `segment::scanned_above` decides which segments a
  scan reads; the scan walks it and the format probe opens its first.
- **One codec.** Every byte the kernel writes goes through
  `journal::codec`, checkpoint bodies included; `checkpoint.rs` borrows it
  and the directory fsync from `journal`.
- **Mode parity.** `Journal::commit_txn` judges the frame cap and the
  transaction budget above its durability-mode branch, so an in-memory
  kernel refuses what a journaled one refuses.
- **The formats are pinned.** `tests/golden/` holds the bytes the
  fixture's ops must reproduce; a moved byte is a format event and bumps
  the `SKJ` and `SKC` stamps — with one dev-time exception on record: on
  2026-09-29 the chain's preimage gained the signature slot's digest and
  M5's slice its shot terms, and the goldens were regenerated once under
  the unchanged `SKJ4`/`SKC4` by the owner's no-stamp ruling (no served
  board exists; dev boards regenerate).

Its integration suites are one binary, `tests/it/`: `kernel` (the public
surface's claims), `hazard` (dirty crashes, built through the engine),
`golden` (the byte pins) and `chain` (the commit chain's tamper matrix),
over the shared `fixture` and `mutilate`.

## The name space, `skep-namespace`

`skep-namespace` is the one minting authority. Every address a transaction
creates — account, document, version, content, link — comes off one of its
five mints, and every store that mints or writes under a chain
(`skep-content`, `skep-arrangement`, `skep-links`) holds a lock key M3
built. It also holds who exists, who owns what (ω, the longest seated
prefix) and each document's publication bit, all in one slice, `M3State`.
Node addresses come from provisioning and are only admitted. Its modules
are declared in `src/lib.rs` in dependency order, each with a line saying
what it holds. `state.rs` is the slice — its types, its journal delta,
genesis, the fold and the frontier arithmetic; beneath it, `state/mint.rs`
holds the lock keys and the five mints (§A) and `state/query.rs` the
queries (§C).

Rules that hold across its files:

- **A mint is a query, and its caller commits it.** A mint returns the next
  address with the one `M3Rec::Allocate` that realizes it. The caller takes
  the paired `*_lock_key` for the transaction, mints off that transaction's
  working state, and pushes the record in it before its next mint on the
  chain. That record is the only thing that advances a frontier. A mint
  whose record is dropped hands out the same address again, and nothing
  reports it; a record pushed anywhere else is stale and issues its address
  twice, refused only by a debug build's fold.
- **An account is minted only with its seat.** `delegate` is the only op
  that allocates an account: it stages the account's `M3Rec::Allocate` and
  its principal's `M3Rec::RegisterPrincipal` in one transaction, and genesis
  folds its one account the same way. So a registered account is owned at
  exactly its own prefix, and so is every document in it — the owner
  account `skep-engine` reads by one lookup (`M3State::account_seat`) and
  `skep-febe` and `skepd` read off ω. A second path that allocates an
  account owes the same seat.
- **A namespace has one spelling.** `NsKey`'s fields are private to
  `src/ns.rs`, so every frontier key, and every chain lock key encoded from
  one, is built there. The two registry keys are M3's own, crate-private.
- **No mint lands in the ghost region.** `skep-links` builds its reserved
  type addresses from `ghost_position`, and `src/ghost.rs`'s floor keeps the
  allocator past them on every board.
- **The slice's field order is its checkpoint format.** Fields are appended
  to `M3State`, never inserted.

Its integration suite is one binary, `tests/it/`: one file per surface over
the shared `common` world, and `heap`, the binary's byte-counting
allocator.

## The arrangement, `skep-arrangement`

`skep-arrangement` owns what a document holds: per document a content and a
link run-list (its arrangement), the provenance relation R (every content
address a document has ever held), and two per-member facts — the birth
extent and the shot terms — all in one slice, `M5State`. It is the one place
in the workspace where state is destroyed: `delete` removes positions and
`rearrange` reorders them, in place, and R keeps every address a delete
removed. Its modules are declared in `src/lib.rs` in dependency order, each
with a line saying what it holds; each names in code only the modules above
it, and `tests/it/tidy.rs` checks it. `ops.rs` is the `Vstream` handle and
what its operations share; beneath it, `ops/insert.rs`, `ops/publish.rs`,
`ops/copy.rs`, `ops/delete.rs`, `ops/rearrange.rs` and `ops/version.rs` each
hold one operation's `impl` block. Its `test-hooks` feature (default off)
compiles in `seat_link`, the test-only twin of the link seat;
`scripts/gate-full.sh` checks the library without it.

Rules that hold across its files:

- **One fold.** A committed `M5State` comes only from `apply_m5` over an
  `M5Rec`, and inside this crate only `state.rs` builds one: two of its
  fields are private there. The fold reaches an arrangement through
  `state.rs`'s own `arrangement_of` and calls nothing defined in `reads.rs`
  or `shot.rs`, the other two files holding `M5State`'s methods, so an edit
  to a read or to the address form cannot change what replay folds;
  `tests/it/tidy.rs` checks it.
- **One door for a run.** `Run::new` admits every run not built in this
  crate — the serde shadow and the `LinkSeat` fold go through it — and every
  in-crate literal starts at an address that already is a full element
  position: a resident run's start, an in-crate shift of one, or what M3's
  `mint_content` returned. `runlist::extend_or_push_run` is the one place a
  built run is widened and the one place a placement's runs are accumulated.
- **One allocation step.** Every fresh content address is minted and written
  by `ops::allocate_for_placement`, inside the transaction whose placement
  record places it.
- **The version chain is asked, never spelled.** Every trunk, head,
  publication and surface question in this crate goes through `chain.rs`,
  the one reader of M3's version frontier; the floating readers of
  `skep-retrieval` and `skep-discovery` ask its `reading_surface` rather than
  float by hand.
- **One front door.** Every gated op opens with `ownership::gate_write`.
- **The edition is append-only by the ops.** The fold does not check it;
  `Vstream`'s card lists the ops that keep it, and an op that writes a
  content arrangement joins that list.
- **The slice's shape is its format.** `M5State`'s fields and `M5Rec`'s
  variants are appended, never inserted or reordered: bincode writes fields
  in order and variants by index, and `skep-kernel`'s goldens pin the bytes.

Its integration suite is one binary, `tests/it/`: one file per surface over
the shared `common` world, and `tidy`, which checks the module order and the
first rule.

## The operation surface, `skep-febe`

`skep-febe` is the front door every client operation passes through.
`OperationSurface::execute` takes a parsed request and the caller's
session, hands the operation to the store or query module that owns it,
and answers only after that module returns: an acknowledged write carries
the position it committed at (`at`), a read answer the position of the
snapshot it answered from (`as_of`), and every failure is a typed
`Rejection`, never a silence. It holds no journaled state. Its one
authoritative fact is which principal each session speaks for, kept for
the uptime; its retry memo is a hint. It names no concrete `World`: what it
requires of the engine — the world it reads and the factory it writes
through — is its `world` module, which `skep-engine` implements.

Its modules are declared in `src/lib.rs` in dependency order, each with a
line saying what it holds; each names in code only the modules above it,
and `tests/it/tidy.rs` checks it. `operation.rs` is the lifecycle; beneath
it, `operation/door.rs` holds the readability door and
`operation/dispatch.rs` the two dispatch tables.

Rules that hold across its files:

- **One read predicate per request.** `OperationSurface::readable`, where a
  supplied `ReadPredicate` and the world's own predicate meet, is private
  to `operation/door.rs`. Everything else asks through `readable_by` — a
  request's predicate, bound once off the snapshot it answers from — or
  `visible_to`, the visibility class a write lends its store. The world's
  own `ReadableWorld::readable` is a supertrait method of `FebeWorld`,
  callable wherever a `W` is held, so `tests/it/tidy.rs` checks that only
  `operation/door.rs` asks it.
- **The read/write partition is written in three places** — `Op::is_read`
  and each dispatch table's complement arm — and
  `each_dispatch_table_rejects_exactly_the_other_half` holds them together.
  Every classifying method on `Op` — in `request.rs`, and the door's own in
  `operation/door.rs`, private to it — and on `Response` matches
  exhaustively with no `_` arm, so a new variant is classified everywhere
  before it compiles.
- **Every rejection is classified.** Each one the crate builds goes through
  `Rejection::classified`, which sets its disposition from
  `RejectCode::disposition`; every upstream store error reaches it through
  the `lower` table.
- **The retry memo holds `CommittedAck`s and nothing else** — the one
  shape an acknowledged write's `Response` yields — so no rejection and no
  read answer is ever replayed.

Its integration suite is one binary, `tests/it/`: one file per topic over
the shared `common` world; `reexports`, which checks from outside the crate
that a request is built and a response read through `skep_febe` alone; and
`tidy`, the module order and the check the first rule names.

## The daemon, `skepd`

`skepd` owns two decisions of its own: the session layer's gates (who may
act, and what a credential write may do) and the cadence of the published
head. Everything else it delegates to the stores through the engine.

Its modules form six layers. A module names only modules in its own layer
or below it, never above; `crates/skepd/tests/it/tidy.rs` checks it. A
write passes down through them in this order:

```
  HTTP request
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│ 1 TRANSPORT        server/listen.rs   server/http.rs    │
│                    accept · read request · write reply  │
│                    serve the event stream               │
├─────────────────────────────────────────────────────────┤
│ 2 ROUTES           server.rs (router) · actor.rs        │
│                    session_routes · read_routes · op    │
│                    hooks (test-hooks builds only)       │
│                    /op: resolve → check → commit →      │
│                         record → head writer's turn     │
├─────────────────────────────────────────────────────────┤
│ 3 VOCABULARY       server/reply.rs · request.rs ·       │
│                    scan.rs                              │
│                    replies & refusals · the request ·   │
│                    the class-scan pool                  │
├─────────────────────────────────────────────────────────┤
│ 4 SESSION LAYER    auth.rs · auth/                      │
│                    sessions · policy · identity fold ·  │
│                    signature check                      │
├─────────────────────────────────────────────────────────┤
│ 5 WRITE PATH       write_path.rs  (one write at a time) │
│                    ├── head.rs      the head writer     │
│                    ├── feed.rs      change feed, indexes│
│                    │                 the attest store    │
│                    ├── sidecar.rs   commits.log         │
│                    └── classify.rs  a commit's documents│
├─────────────────────────────────────────────────────────┤
│ 6 LEAVES           codec · history · permits · serial · │
│                    limits · notice                      │
└─────────────────────────────────────────────────────────┘
       │
       ▼
  skep-engine  →  the stores  →  skep-kernel (journal)

  Imports point DOWN or sideways within a layer. Never up.
```

A read skips the write path: a read route goes from the routes to
`history` and the engine. The engine sits below the daemon and knows
nothing of it.

1. **The transport** — `server/listen.rs` (sockets, worker threads, the
   event streams' loop and budget) and `server/http.rs` (the HTTP bytes:
   the request reader, the reply writer, the event framing). It hands each
   request to the router and knows nothing of what a request means.
2. **The routes** — `server.rs` (`Daemon` and the router) and the handler
   files beneath it, each an `impl Daemon` block: `server/actor.rs` (who
   the caller is), `server/session_routes.rs`, `server/read_routes.rs`,
   `server/op.rs`, and — in `test-hooks` builds only —
   `server/hooks.rs`. `/op` runs one of the two write sequences — the
   plain (AUTH-3.35) or the credential (AUTH-3.37), chosen off the op's
   own type slot before any lock is taken: resolve the caller, run the
   checks, commit, record, then give the head writer its turn.
3. **The daemon's vocabulary** — `server/reply.rs` (the reply and every
   transport refusal), `server/request.rs` (the request, and the rules its
   headers and query obey), `server/scan.rs` (the class-scan pool): what
   the routes and the transport both speak.
4. **The session layer** — `auth.rs` and the modules under `auth/`.
   Sessions and the signed handshake, the policy checks on every write
   (`auth/policy/`: the plain sequence's admission, the credential
   sequence's precheck with the record grade, and the write-path check —
   the entry signature, whose one exempt `insert` is a signed credential
   record into a doc 1), the identity fold, signature verification —
   `skep-signature` is the one crate that links the signature libraries;
   skepd calls its verify.
5. **The write path** — `write_path.rs`. The single point every write
   passes through, one at a time, and the head writer
   (`write_path/head.rs`, which commits through the write path's own
   door). Beneath it, and reachable only from it:
   - `write_path/feed.rs` — the change feed; beneath it,
     `write_path/feed/derived.rs` keeps the feed's derived index files and
     `write_path/feed/attest.rs` the attest store, the marker slot
     mirrored per attested commit;
   - `write_path/sidecar.rs` — `commits.log`, the daemon's record of what
     it committed, for whom, and whether the entry was signed — and, on a
     bare line, the journal's answer for the row's op and terms;
   - `write_path/classify.rs` — which documents a commit touched, and
     which of its op's terms the journal can name for a bare position —
     the one place the feed asks the world anything.
6. **The leaves** — `codec.rs` with `codec/marshal.rs` (the JSON wire
   format: parse, and marshal), `history.rs` (reading the world at an
   earlier position), `permits.rs` (the counting permit both bounded pools
   use), `serial.rs` (the write-serialization lock and its guard),
   `limits.rs` (request body caps), `notice.rs` (the operator's log line).
   None of these knows anything about the daemon; a leaf imports only
   leaves.

`lib.rs` declares the daemon's modules in layer order, then the fuzz
harness and the crate's public surface; `main.rs` is the binary.
`fuzz_support.rs` (in `test-hooks` builds only) serves the fuzz targets and
the tests: it stands above the transport, and nothing in the daemon
imports it.

### Features

| Feature | Default | Adds | Compiled by the gate |
|---|---|---|---|
| `observe` | on | `GET /dump`, the engine's world dump | every build; OFF in `scripts/gate-full.sh`'s `--no-default-features` checks |
| `client` | off | `GET /`, the embedded board — an ACTING client, so opted into (`Cargo.toml` carries the ruling) | `scripts/gate-full.sh`'s `--features client` check and `--all-features` run |
| `test-hooks` | off | `Daemon`'s `#[doc(hidden)]` test hooks, `fuzz_support`, the `Permit` re-export — nothing in another crate | every test build (the crate's self dev-dependency); `scripts/gate-full.sh` checks the library and binary without it |
| `skep-signature`'s `sign` | off — skepd depends with no feature, so the daemon's build holds no signer | the signer's half: the KDF, keygen from a seed, signing, the signer's OS draw | every test build (the suites' dev-dependencies); `scripts/gate-full.sh` checks the crate without it (the verify-only build a daemon links) and with it |
| `skep-signature`'s `test-hooks` | off | implies `sign`; the fixtures' hooks: the seeded RNG, `sign_with_rng`, the Ed25519 half's signing key, the KDF's half seeds (`derive_half_seeds`), the widths | every test build (its self dev-dependency, and skepd's dev-dependency on it) |

## Rules that hold across files

- **Crate dependencies point down.** The order in the code map is the
  order the compiler enforces between libraries; the dev-dependencies
  pointing back up are `skep-kernel`'s, whose integration suites build
  their shared fixture through `skep-engine` and the stores it assembles.
- **Inside `skepd`, imports point down.** A module names only modules in
  its own layer or below it, never above: the transport calls the router,
  and nothing below the router calls the transport; a leaf imports only
  leaves. Code names an in-crate item by its home module, never through
  the crate root's re-exports. `crates/skepd/tests/it/tidy.rs` checks all
  of it.
- **One write path.** Every write to the world goes through
  `write_path`, one at a time. Only the write path records to the feed and
  to `commits.log`.
- **The daemon writes only its own files.** The journal and checkpoints
  are the kernel's. The daemon's own files are `commits.log` — its
  testimony about what it committed, for whom, and whether the entry was
  signed — the feed's derived index files, projections of that testimony
  and the journal, rebuilt from them on loss, and `feed-attest.log`, the
  attest store: each attested commit's marker slot, mirrored at commit
  from the value the write path admitted, rebuilt from the journal above
  the reclaim floor, and the one daemon file that is not a projection —
  below the floor the checkpoint holds no marker, so its line there is
  the entry signature's only copy at the origin, kept and never compacted,
  backed up with the board directory as the kernel's own files are. It
  never writes anything about the world outside the kernel.
- **Nothing is overwritten.** Content, links and journal entries are
  append-only. A removal is a new record, not a deletion.
- **The wire is a contract.** `docs/wire.md` is what clients build
  against. A change to what the daemon answers is a change to that
  document in the same commit.
- **Tests live beside the code they test.** Unit tests are a `tests`
  child module; one of 200 lines or more lives in its own `tests.rs`
  beside the file. Integration tests live in each crate's `tests/it/`, one
  test binary per crate. See `AGENTS.md`.

## Where the reasons live

- `docs/wire.md` — the wire protocol, every route and refusal.
- The module designs (M1–M10), the composition contract and the AUTH and
  PUB specifications, in the design project — the reasoning behind each
  crate and each rule above.

This file changes when the layout changes: a new crate, a moved module, a
new cross-cutting rule. It does not record history.
