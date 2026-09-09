//! # skepd — the skep daemon
//!
//! The one thing permitted to depend on the engine (Engine Composition
//! Contract): a long-running process owning ONE `World`, serving the full
//! M10 operation surface over HTTP/JSON to multiple concurrent local
//! clients. **skepd owns no semantics** — every decision worth making was
//! made in a store, save the session layer's own, whose gates are the
//! daemon's by spec; this crate is the wire codec, the session layer, the
//! process, and the kernel's configuration:
//!
//! * [`JsonCodec`] — the one concrete `Codec` (M10's seam): JSON frames in,
//!   deterministic JSON responses out. The byte conventions are the
//!   cross-client contract in `skep/docs/wire.md`, whose examples the tests
//!   assert.
//! * `auth/` — the AUTH session layer (wire v7): the two origin sets, the
//!   challenge/response handshake, the sessions store and per-request
//!   resolution, the credential write lock and the ordered refusal
//!   producers it scopes, and the identity fold this daemon composes
//!   BESIDE the engine (derived state, rebuilt at open, never persisted
//!   here).
//! * [`Daemon`] — the state and the socket-free router: `GET /challenge`,
//!   `POST /session`, `POST /session/close`, `POST /op`, `POST /op-at`
//!   (any READ frame answered as of a committed
//!   position, served from the journal via the engine's bounded replay),
//!   `GET /health` (liveness, position, — wire v6 — `head_time`, and —
//!   wire v7 — the `auth` object the board's mode derives from),
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
//! Durability lives in M2 and is *configured* here (`Durability::Fsync`,
//! every-1024-commits checkpoints, two retained): genesis on a fresh data
//! dir, recovery on an existing one. The only files this crate writes
//! itself are the change feed's: `commits.log` — the wire-v6
//! commit-metadata sidecar — its four derived sidecars (`feed-index.log`,
//! `feed-offsets.log`, `feed-masked.log`, `feed-streams.log`; wire v7.8,
//! PUB-7.19), and, transiently while any of them is compacted, its
//! `.compact` twin. None persists anything about the WORLD (two daemons
//! replaying one journal still converge byte-identically): the sidecar is
//! the daemon's own testimony about when and for whom it committed, the
//! same standing as the kernel's lock file, and the four beside it are
//! projections of that testimony and the journal, rebuilt from them on
//! loss.

#![forbid(unsafe_code)]

mod auth;
mod codec;
mod feed;
mod history;
mod server;
mod sidecar;
mod write_path;

/// The shared fuzzing harness (hardening H2): the pure oracle and mutation
/// logic the tier-1 `#[test]`s and the nightly libFuzzer targets both drive.
/// Not a stable API — `#[doc(hidden)]`, std-only, and exempt from the wire
/// contract. It is unconditionally compiled (not `#[cfg(test)]`) precisely so
/// the out-of-workspace `skep/fuzz/` crate and the integration tests — both
/// external to this library — can reach it under a plain build.
#[doc(hidden)]
pub mod fuzz_support;

pub use auth::{AuthOptions, NotCanonical, Origin, PortAlreadyBound};
pub use codec::JsonCodec;
pub use server::{
    body_cap, serve, Body, Daemon, DaemonError, HttpRequest, Peer, Reply, Routed, Skepd,
    DEFAULT_WORKERS, UNIVERSAL_HEADERS,
};

/// The engine types this crate's public surface hands out: the world
/// [`Daemon::world_at`] answers with, why it refused, and the failure
/// [`Daemon::open`] reports. Re-exported because skepd is the one thing
/// permitted to depend on the engine (Engine Composition Contract) — a
/// caller that must name any of the three would otherwise have to take that
/// dependency itself, the one dependency this crate exists to hold alone.
///
/// M10's operation vocabulary is deliberately NOT re-exported: `Request`,
/// `Response`, `Op` and the `Codec` trait belong to `skep-febe`, which any
/// client author already depends on to build an operation at all. The one
/// foreign type left on this crate's public surface rides that same door:
/// `PrincipalId`, which [`Daemon::dump_visible_to`] takes, is
/// `skep-namespace`'s and reaches a client through `skep-febe`'s own
/// re-export of it.
pub use skep_engine::{EngineError, HistoryError, World};

/// The dump [`Daemon::dump_visible_to`] answers with, re-exported for the
/// reason the three above are and only where that method exists. Without
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

/// The permit the daemon's two test hooks hand out — one slot of the
/// reconstruction pool or of the class-scan pool (wire v7.9), the same guard
/// type for both. Public only because those hooks' return type must be
/// nameable; not a stable API.
#[doc(hidden)]
pub use history::Permit;

/// The auto-traits this crate promises without saying so. A caller running
/// the server on a thread it owns depends on `Skepd: Send`, and no signature
/// states it — so a private field that is not `Send` would revoke it with no
/// public name changing. This is where that fails to compile instead.
///
/// Every type this crate DEFINES and exports is listed. The ones it
/// re-exports — [`World`], [`Seq`], [`EngineError`], [`HistoryError`], and
/// (under `observe`) the world dump — are not: those promises are
/// upstream's to keep, and `Daemon: Send + Sync` already pins the ones this
/// crate transitively rests on.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Skepd>();
    assert_send_sync::<Daemon>();
    assert_send_sync::<DaemonError>();
    assert_send_sync::<JsonCodec>();
    assert_send_sync::<Reply>();
    assert_send_sync::<Body>();
    assert_send_sync::<HttpRequest>();
    assert_send_sync::<Routed>();
    assert_send_sync::<Permit<'static>>();
    // The AUTH round's arrivals. `AuthOptions` is the value a caller builds
    // and hands to `Daemon::open_with`, plausibly across a thread boundary;
    // the rest ride in and out of that surface.
    assert_send_sync::<AuthOptions>();
    assert_send_sync::<Origin>();
    assert_send_sync::<NotCanonical>();
    assert_send_sync::<PortAlreadyBound>();
    assert_send_sync::<Peer>();
};
