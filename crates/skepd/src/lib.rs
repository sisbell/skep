//! # skepd — the skep daemon
//!
//! The one thing permitted to depend on the engine (Engine Composition
//! Contract): a long-running process owning ONE `World`, serving the full
//! M10 operation surface over HTTP/JSON to multiple concurrent local
//! clients. **skepd owns no semantics** — every decision worth making was
//! made in a store; this crate is the wire codec, the process, and the
//! kernel's configuration:
//!
//! * [`JsonCodec`] — the one concrete `Codec` (M10's seam): JSON frames in,
//!   deterministic JSON responses out. The byte conventions are the
//!   cross-client contract in `skep/docs/wire.md`, whose examples the tests
//!   assert.
//! * [`Daemon`] — the state and the socket-free router: `POST /session`,
//!   `POST /op`, `POST /op-at` (any READ frame answered as of a committed
//!   position, served from the journal via the engine's bounded replay),
//!   `GET /health` (liveness, position, and — wire v6 — `head_time`),
//!   `GET /events` (the server-sent commit stream, wire v4),
//!   `GET /changes` (the pull delta feed of committed writes, wire v6, fed
//!   by the daemon's own commit-metadata sidecar `commits.log`), `GET /`
//!   (the embedded authoring client, `client` feature, default OFF — the
//!   client acts, so serving it is opted into; see the feature's note in
//!   `Cargo.toml`), the CORS preflight on every known path, and (behind
//!   the `observe` feature) `GET /dump`, with `?at=N` for the dump of a
//!   historical position.
//! * [`serve`]/[`Skepd`] — the synchronous accept loop: worker threads over
//!   one owned `TcpListener` speaking a written-out HTTP/1.1 subset (one
//!   request per connection, `Connection: close` and
//!   `Access-Control-Allow-Origin: *` on every response), bound to
//!   127.0.0.1 (local trust does not survive a network). Event-stream
//!   subscribers run on dedicated threads off the op pool, fed by
//!   write-path notification — no polling anywhere.
//!
//! Durability lives in M2 and is *configured* here (`Durability::Fsync`,
//! every-1024-commits checkpoints, two retained): genesis on a fresh data
//! dir, recovery on an existing one. The one file this crate writes itself
//! is `commits.log` — the wire-v6 commit-metadata sidecar — which persists
//! nothing about the WORLD (two daemons replaying one journal still
//! converge byte-identically): it is the daemon's own testimony about when
//! and for whom it committed, the same standing as the kernel's lock file.

#![forbid(unsafe_code)]

mod codec;
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

pub use codec::JsonCodec;
pub use server::{
    body_cap, serve, Body, Daemon, DaemonError, HttpRequest, Reply, Routed, Skepd,
    UNIVERSAL_HEADERS,
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
/// client author already depends on to build an operation at all.
pub use skep_engine::{EngineError, HistoryError, World};

/// A committed log position — what [`Daemon::log_position`] answers and what
/// [`Daemon::world_at`] takes, re-exported for the same reason the engine
/// types above are.
pub use skep_kernel::Seq;

/// The reconstruction permit the daemon's test hook hands out — public only
/// because that hook's return type must be nameable; not a stable API.
#[doc(hidden)]
pub use history::ReconstructPermit;

/// The auto-traits this crate promises without saying so. A caller running
/// the server on a thread it owns depends on `Skepd: Send`, and no signature
/// states it — so a private field that is not `Send` would revoke it with no
/// public name changing. This is where that fails to compile instead.
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
    assert_send_sync::<ReconstructPermit<'static>>();
};
