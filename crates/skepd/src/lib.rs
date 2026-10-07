//! # skepd — the skep daemon
//!
//! The one thing permitted to depend on the engine (Engine Composition
//! Contract): a long-running process owning ONE `World`, serving the full
//! M10 operation surface over HTTP/JSON to multiple concurrent local
//! clients. **skepd owns no semantics** — every decision worth making was
//! made in a store, save three the spec gives the daemon: the session layer's
//! gates, the PUBLISHED HEAD's cadence (PUB-6.65) — when the board's own
//! daemon writes the head document `H`, the one write it makes on its own
//! initiative — and the MEDIA DOOR (media lane A; `skep-media`'s, run by
//! this daemon's plain write sequence): whether a value a write carries is
//! a picture's reference cell, parsed by the one parser, and what a write
//! that would mint one is answered. This crate is the wire codec, the
//! session layer, the head writer, the media door's one caller, the
//! process, and the kernel's configuration:
//!
//! * [`JsonCodec`] — the one concrete `Codec` (M10's seam): JSON frames in,
//!   deterministic JSON responses out. The byte conventions are the
//!   cross-client contract in `skep/docs/wire.md`, whose examples the tests
//!   assert.
//! * `auth/` — the AUTH session layer (wire v7): the two origin sets, the
//!   challenge/response handshake, the sessions store and per-request
//!   resolution, the credential write lock and the ordered refusal
//!   producers it scopes, the signed-ops write-path check and the ENTRY
//!   frame it verifies a presented `attest` over (the hybrid signature's
//!   rules are `skep-signature`'s, the one crate that links the signature
//!   libraries; skepd calls its verify), and the readers of the World's
//!   identity slice — the key table the engine folds at each credential
//!   commit and checkpoints with the world (AUTH-2.79), which the daemon
//!   reads off the snapshot it holds and never rebuilds.
//! * `write_path/` — the ONE ordering every write rides (commit, record,
//!   announce, under one serialization guard) and, behind it, the
//!   PUBLISHED HEAD writer: `H` = `1.1.0.1.0.2` written as a new published
//!   version on the write path's own cadence, as the system account's
//!   principal with no session, its commits testifying `"system"` on
//!   `/changes` (wire.md §The other endpoints).
//! * `skep-media` — the MEDIA DOOR (lane A) and, beside the write path, the
//!   daemon's media resource (lane B), a crate of its own this daemon
//!   instantiates at its `World`: the blob store `skep-blobs` opened under
//!   `blobs/` in the data dir, the limits in force, the hold a stream has
//!   on its upload, the three scopes a deposit is refused on, and the
//!   binding the door asks — a cell is admitted only where its hash is one
//!   this principal deposited under its own live lease. The PUT's routes
//!   (`server/blob_routes.rs`, the family `/blob/upload`) stream a body one
//!   chunk at a time into the store, commit nothing to the journal
//!   (wire.md §Media), and serve the deposit read off the gate's reads. And
//!   THE FETCH (the crate's `serve.rs`): `GET /blob?i=<address>` serves a
//!   picture's whole file, gated by M10's read by identity, checked against
//!   its cell before its first byte, under a permit pool, the requester
//!   re-resolved mid-stream; the BLIND DOCUMENT's cell (the crate's
//!   `blind.rs`) is the second kind the door and the fetch classify beside
//!   the picture's, of which the board holds no byte.
//! * [`Daemon`] — the state and the socket-free router: `GET /challenge`,
//!   `POST /session`, `POST /session/close`, `POST /op`, `POST /op-at`
//!   (any READ frame answered as of a committed
//!   position, served from the journal via the engine's bounded replay),
//!   `GET /blob?i=` and `HEAD /blob?i=` (the fetch, a stream the accept
//!   path writes),
//!   `GET /health` (liveness, position, — wire v6 — `head_time`, — wire v7 —
//!   the `auth` object the board's mode derives from, and the kernel's
//!   `chain_head`, the chain AT the position served beside it),
//!   `GET /chain?at=N` (the commit chain's value as of a committed
//!   position, recomputed off the journal — what a saved head or `/health`
//!   pair is checked against),
//!   `GET /events` (the server-sent commit stream, wire v4),
//!   `GET /changes` (the pull delta feed of committed writes, wire v6, fed
//!   by the daemon's own commit-metadata sidecar `commits.log` and — wire
//!   v7.8 — masked at the presented token's class off the feed module's
//!   four derived sidecars), `GET /`
//!   (the embedded authoring client, `client` feature, default OFF — the
//!   client acts, so serving it is opted into; see the feature's note in
//!   `Cargo.toml`), the CORS preflight on every known path, and (behind
//!   the `observe` feature) `GET /dump`, with `?at=N` for the dump of a
//!   historical position.
//! * [`serve`]/[`Skepd`] — the synchronous accept loop: worker threads over
//!   one owned `TcpListener` speaking a written-out HTTP/1.1 subset (one
//!   request per connection, and [`UNIVERSAL_HEADERS`] on every response),
//!   bound to 127.0.0.1 (the bare bind is loopback-privileged, and that
//!   privilege does not survive a network). Event-stream subscribers run
//!   on dedicated threads off the op pool, fed by write-path notification
//!   — no polling anywhere.
//!
//! Durability lives in M2 and is *configured* here (`Durability::Fsync`;
//! checkpoints every 1024 commits or a byte bound — a quarter of the newest
//! checkpoint's size, never below 24 MiB, re-read as each lands —
//! whichever first, DEFERRED to the daemon's own checkpoint thread, which
//! runs them off the write path's guard, says a failure once, and compacts
//! the change feed's files after each landing; two retained): genesis on a
//! fresh data dir, recovery on an existing one. The only files this crate
//! writes itself are the change feed's: `commits.log` — the wire-v6
//! commit-metadata sidecar — its four derived sidecars (`feed-index.log`,
//! `feed-offsets.log`, `feed-masked.log`, `feed-streams.log`; wire v7.8,
//! PUB-7.19), the attest store `feed-attest.log` (wire v7.11; signed ops),
//! and, transiently while any of them is compacted, its `.compact` twin.
//! None persists anything about the WORLD (two daemons replaying one
//! journal still converge byte-identically): the sidecar is the daemon's
//! own testimony about when and for whom it committed, the same standing
//! as the kernel's lock file, and the four beside it are projections of
//! that testimony and the journal, rebuilt from them on loss. The attest
//! store is the one exception in class: it mirrors each attested commit's
//! marker slot — the entry signature the feed serves as `attest` — and
//! below the journal's reclaim floor, where the checkpoint holds no marker,
//! it is that signature's only copy at the origin, kept and never compacted
//! (`write_path/feed/attest.rs` states the class).

#![forbid(unsafe_code)]

// The layers, top to bottom. `ARCHITECTURE.md` §The daemon draws them and
// `tests/it/tidy.rs` checks them: a module names only its own layer and the
// layers below it.

// The transport, the routes and their vocabulary.
mod server;

// Beside the routes, at their layer: the operator's two tools over a board
// directory — the inventory and the pull — which run with no server, reading
// the media resource's index and the store's inspection and nothing above
// themselves.
pub mod tools;

// The session layer.
mod auth;

// The write path: every commit, one at a time, and the published head.
// Beside it, at its layer, THE MEDIA RESOURCE is `skep-media`'s — the media
// door, the one step the plain write sequence takes for a value naming the
// picture cell's kind; the gate the door and the PUT's routes read the blob
// store through; the index, the pruner and the fetch; and, leaves beneath
// them, the two cells — a crate below this one, generic over the world.
mod write_path;

// The leaves: none knows anything of the daemon. Two more leaves — the
// permit pool the four bounded pools are built on and the operator's notice
// line — and the codec's determinism helpers are `skep-util`'s, the support
// crate below this one, shared with the media crate.
mod codec;
mod history;
mod limits;
mod serial;

/// The shared fuzzing harness (hardening H2): the pure oracle and mutation
/// logic the tier-1 `#[test]`s and the nightly libFuzzer targets both drive.
/// Not a stable API — `#[doc(hidden)]`, std-only, and exempt from the wire
/// contract. It compiles under the `test-hooks` feature (not `#[cfg(test)]`
/// alone) so the out-of-workspace `skep/fuzz/` crate and the integration
/// tests — both external to this library — reach it by enabling that
/// feature, and a shipped build carries none of it.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub mod fuzz_support;

pub use auth::{AuthOptions, NodePrefix, NotANodePrefix, NotCanonical, Origin, PortAlreadyBound};
pub use codec::JsonCodec;
pub use server::{
    body_cap, serve, Body, Daemon, DaemonError, Fetch, HttpRequest, Peer, Reply, Routed,
    Skepd, DEFAULT_WORKERS, MIN_WORKERS, UNIVERSAL_HEADERS,
};

/// The engine types this crate's public surface hands out: the world
/// [`Daemon::world_at`] answers with, why it refused, the failure
/// [`Daemon::open`] reports, and the kernel refusal that failure carries —
/// the `OpenError` [`DaemonError::Engine`]'s contract tells a retrying
/// caller to match. Re-exported because skepd is the one thing permitted to
/// depend on the engine (Engine Composition Contract) — a caller that must
/// name any of the four would otherwise have to take that dependency itself,
/// the one dependency this crate exists to hold alone; and one that took it
/// at another version would hold a DIFFERENT `OpenError` from the one inside
/// [`EngineError`], and its match would not compile.
///
/// M10's operation vocabulary is deliberately NOT re-exported: `Request`,
/// `Response`, `Op` and the `Codec` trait belong to `skep-febe`, which any
/// client author already depends on to build an operation at all. The
/// foreign types left on this crate's public surface each ride a door the
/// caller already holds. `PrincipalId`, which [`Daemon::dump_visible_to`]
/// takes, `Address`, which [`NodePrefix::address`] answers, and
/// `Attestation`, which the doc-hidden test hook `Daemon::attestation_at`
/// answers, are `skep-namespace`'s, `skep-address`'s and `skep-kernel`'s,
/// and reach a client through `skep-febe`'s own re-exports. And
/// `serde_json::Value`, which [`tools::inventory`] answers, is
/// `serde_json`'s — the crate a caller reading the daemon's JSON already
/// holds, named at the major version this workspace pins. No signature
/// library's type is among them: `skep-signature` is the one crate that
/// links the signature libraries; skepd calls its verify.
pub use skep_engine::{EngineError, HistoryError, OpenError, World};

/// The media resource's configuration — the upload setting
/// [`Daemon::open_configured`] takes — `skep-media`'s own type, re-exported
/// so the daemon's callers keep the path they had when the media resource
/// was a module of this crate: the binary's `main.rs` and the suites name
/// `skepd::MediaOptions` and depend on no media crate for it.
pub use skep_media::MediaOptions;

/// The dump [`Daemon::dump_visible_to`] answers with, re-exported for the
/// reason the four above are and only where that method exists. Without
/// it the method's return type is nameable only by depending on
/// `skep-engine` — the dependency this crate holds alone — and only where
/// feature unification happens to have turned that crate's `dump` feature
/// on, which is what this crate's `observe` does.
#[cfg(feature = "observe")]
pub use skep_engine::dump::WorldDump;

/// A committed log position — what [`Daemon::log_position`] answers and what
/// [`Daemon::world_at`] takes, re-exported for the same reason the engine
/// types above are.
pub use skep_kernel::Seq;

/// The refusal [`DaemonError::Registry`] carries — the registry's seeding
/// check's, naming the arm that fired (REG-1.28 to REG-1.32) — re-exported
/// for the reason the engine types above are: a caller matching that arm, or
/// naming its payload in a signature of its own, would otherwise depend on
/// `skep-registry` itself, and one that took it at another version would hold
/// a DIFFERENT `SeedingRefusal` from the one inside the error. Its `arm()`
/// names the arm that fired; the row a completeness refusal names is
/// `skep-registry`'s own vocabulary (`RowOf`), which a caller matching that
/// far takes from that crate.
pub use skep_registry::SeedingRefusal;

/// The permit the daemon's four test hooks hand out — one slot of the
/// reconstruction pool, of the class-scan pool (wire v7.9), of the fetch
/// pool or of the upload pool (wire.md §Media), the same guard type for all
/// four — `skep-util`'s, the one type every pool mints. Public only because
/// those hooks' return type must be nameable; not a stable API.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub use skep_util::permits::Permit;

/// The auto-traits this crate promises without saying so. A caller running
/// the server on a thread it owns depends on `Skepd: Send`, and no signature
/// states it — so a private field that is not `Send` would revoke it with no
/// public name changing. This is where that fails to compile instead.
///
/// Every type this crate DEFINES and exports is listed. The ones it
/// re-exports — [`World`], [`Seq`], [`EngineError`], [`HistoryError`],
/// [`OpenError`], [`SeedingRefusal`], and (under `observe`) the world dump —
/// are not: those
/// promises are upstream's to keep, and `Daemon: Send + Sync` already pins
/// the ones this crate transitively rests on.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Skepd>();
    assert_send_sync::<Daemon>();
    assert_send_sync::<DaemonError>();
    assert_send_sync::<JsonCodec>();
    assert_send_sync::<Reply>();
    assert_send_sync::<Body>();
    assert_send_sync::<HttpRequest>();
    assert_send_sync::<Routed<'static>>();
    assert_send_sync::<Fetch<'static>>();
    #[cfg(any(test, feature = "test-hooks"))]
    assert_send_sync::<Permit<'static>>();
    // The AUTH round's arrivals. `AuthOptions` is the value a caller builds
    // and hands to `Daemon::open_with`, plausibly across a thread boundary;
    // the rest ride in and out of that surface.
    assert_send_sync::<AuthOptions>();
    assert_send_sync::<MediaOptions>();
    assert_send_sync::<Origin>();
    assert_send_sync::<NotCanonical>();
    assert_send_sync::<NodePrefix>();
    assert_send_sync::<NotANodePrefix>();
    assert_send_sync::<PortAlreadyBound>();
    assert_send_sync::<Peer>();
    // The operator's tools' surface: the inventory's check, what a pull
    // installed, and the refusal both tools share.
    assert_send_sync::<tools::HoleCheck>();
    assert_send_sync::<tools::Pulled>();
    assert_send_sync::<tools::ToolError>();
};
