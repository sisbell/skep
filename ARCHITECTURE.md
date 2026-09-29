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

The workspace is fifteen crates under `crates/`. Dependencies point
downward in the list below: a crate may depend only on crates listed
above it.

**The foundation**
- `skep-address` — tumblers, addresses and span algebra. Pure values; it
  depends on no other skep crate.
- `skep-kernel` — transactions, the journal, checkpoints and recovery. It
  knows nothing of what a transaction means; the world it stores is a
  type parameter the engine supplies.

**The stores** — each owns one slice of the world and depends only on the
foundation and on the stores above it.
- `skep-namespace` — accounts, delegation, ownership.
- `skep-content` — the write-once map from address to value.
- `skep-arrangement` — documents as arrangements of content, versions,
  provenance.
- `skep-links` — typed links, supersession, retraction.
- `skep-retrieval` — content and provenance queries.
- `skep-discovery` — finding links, projection.
- `skep-coordination` — predicate definitions and the coordinator.
- `skep-identity` — credential records, key sets, the identity fold. Pure;
  of the skep crates it depends only on `skep-address`.

**The surface and the assembler**
- `skep-febe` — the operation surface (`OperationSurface`): one front door
  that dispatches every operation to the stores, and the codec seam a
  transport fills.
- `skep-engine` — the one assembler. It defines `World` from the stores'
  slices, genesis, recovery and reads at a past position. Nothing depends
  on it except `skepd`, the conformance harness and — as a dev-dependency,
  for its hazard suite's fixtures — `skep-kernel`.

**The programs**
- `skepd` — the daemon (below).
- `skep-mcp` — a stdio adapter for agent harnesses.
- `skep-conformance` — a differential harness against `udanax-green`'s
  goldens.

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
   Sessions and the signed handshake, the policy checks on every write,
   the identity fold, signature verification; `auth/hybrid.rs` is the one
   module that links a signature library.
5. **The write path** — `write_path.rs`. The single point every write
   passes through, one at a time, and the head writer
   (`write_path/head.rs`, which commits through the write path's own
   door). Beneath it, and reachable only from it:
   - `write_path/feed.rs` — the change feed; `write_path/feed/derived.rs`
     beneath it keeps the feed's derived index files;
   - `write_path/sidecar.rs` — `commits.log`, the daemon's record of what
     it committed and for whom;
   - `write_path/classify.rs` — which documents a commit touched, the one
     question the feed asks the world.
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
| `test-hooks` | off | `Daemon`'s `#[doc(hidden)]` test hooks, `hybrid`'s fixture hooks, `fuzz_support`, the `Permit` re-export | every test build (the crate's self dev-dependency); `scripts/gate-full.sh` checks the library and binary without it |

## Rules that hold across files

- **Crate dependencies point down.** The order in the code map is the
  order the compiler enforces between libraries; the dev-dependencies
  pointing back up are `skep-kernel`'s, whose hazard suite builds its
  fixtures through `skep-engine` and the stores it assembles.
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
  testimony about what it committed and for whom — and the feed's derived
  index files, projections of that testimony and the journal, rebuilt from
  them on loss. It never writes anything about the world outside the
  kernel.
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
