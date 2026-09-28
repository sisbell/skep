//! # skepd — the skep daemon
//!
//! The one thing permitted to depend on the engine (Engine Composition
//! Contract): a long-running process owning ONE `World`, serving the full
//! M10 operation surface over HTTP/JSON to multiple concurrent local
//! clients. **skepd owns no semantics** — every decision worth making was
//! made in a store, save two the spec gives the daemon: the session layer's
//! gates, and the PUBLISHED HEAD's cadence (PUB-6.65) — when the board's own
//! daemon writes the head document `H`, the one write it makes on its own
//! initiative. This crate is the wire codec, the session layer, the head
//! writer, the process, and the kernel's configuration:
//!
//! * [`JsonCodec`] — the one concrete `Codec` (M10's seam): JSON frames in,
//!   deterministic JSON responses out. The byte conventions are the
//!   cross-client contract in `skep/docs/wire.md`, whose examples the tests
//!   assert.
//! * `auth/` — the AUTH session layer (wire v7): the two origin sets, the
//!   challenge/response handshake, the sessions store and per-request
//!   resolution, the credential write lock and the ordered refusal
//!   producers it scopes, the signed-ops write-path check and the ENTRY
//!   frame it verifies a presented `attest` over, the [`hybrid`]
//!   signature's rules (the one module here that links a signature
//!   library), and the identity fold this daemon composes BESIDE the
//!   engine (derived state, rebuilt at open, never persisted here).
//! * `write_path/` — the ONE ordering every write rides (commit, record,
//!   announce, under one serialization guard) and, behind it, the
//!   PUBLISHED HEAD writer: `H` = `1.1.0.1.0.2` written as a new published
//!   version on the write path's own cadence, as the system account's
//!   principal with no session, its commits testifying `"system"` on
//!   `/changes` (wire.md §The other endpoints).
//! * [`Daemon`] — the state and the socket-free router: `GET /challenge`,
//!   `POST /session`, `POST /session/close`, `POST /op`, `POST /op-at`
//!   (any READ frame answered as of a committed
//!   position, served from the journal via the engine's bounded replay),
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

// The layers, top to bottom. `ARCHITECTURE.md` §The daemon draws them and
// `tests/it/tidy.rs` checks them: a module names only its own layer and the
// layers below it.

// The transport, the routes and their vocabulary.
mod server;

// The session layer.
mod auth;

// The write path: every commit, one at a time, and the published head.
mod write_path;

// The leaves: none knows anything of the daemon.
mod codec;
mod history;
mod limits;
mod notice;
mod permits;
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

pub use auth::{
    AuthOptions, NodePrefix, NotANodePrefix, NotCanonical, Origin, PortAlreadyBound,
};
/// THE HYBRID ENTRY SIGNATURE's rules (signed ops): the KDF from one seed to
/// both halves, keygen and signing per marker tag — the test signer's and the
/// goldens' side — the verify the daemon's write-path check dispatches on,
/// and the all-halves decode ([`hybrid::key_decodes`]) the enrollment
/// courtesy runs beside that verify. Public because the signer's side lives
/// beside the verifier's in the one crate that links the signature libraries
/// (AUTH-2.2), and the suites and a future client reach it here.
pub use auth::hybrid;
pub use codec::JsonCodec;
pub use server::{
    body_cap, serve, Body, Daemon, DaemonError, HttpRequest, Peer, Reply, Routed, Skepd,
    DEFAULT_WORKERS, MIN_WORKERS, UNIVERSAL_HEADERS,
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
/// and reach a client through `skep-febe`'s own re-exports. `PublicKey` —
/// what a [`hybrid::HybridSigner`] answers for its key and what
/// [`hybrid::verify`] and [`hybrid::key_decodes`] take — is
/// `skep-identity`'s, which a client that holds keys depends on anyway to
/// compose the enrollment records that seat them. The signature libraries'
/// own types — `ed25519-dalek`'s signing key, `rand_core` 0.6's RNG traits —
/// appear only on `hybrid`'s test hooks, which compile only under
/// `test-hooks`, and so on no name a shipped build carries.
pub use skep_engine::{EngineError, HistoryError, OpenError, World};

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

/// The permit the daemon's two test hooks hand out — one slot of the
/// reconstruction pool or of the class-scan pool (wire v7.9), the same guard
/// type for both. Public only because those hooks' return type must be
/// nameable; not a stable API.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub use permits::Permit;

/// The auto-traits this crate promises without saying so. A caller running
/// the server on a thread it owns depends on `Skepd: Send`, and no signature
/// states it — so a private field that is not `Send` would revoke it with no
/// public name changing. This is where that fails to compile instead.
///
/// Every type this crate DEFINES and exports is listed. The ones it
/// re-exports — [`World`], [`Seq`], [`EngineError`], [`HistoryError`],
/// [`OpenError`], and (under `observe`) the world dump — are not: those
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
    assert_send_sync::<Routed>();
    #[cfg(any(test, feature = "test-hooks"))]
    assert_send_sync::<Permit<'static>>();
    // The AUTH round's arrivals. `AuthOptions` is the value a caller builds
    // and hands to `Daemon::open_with`, plausibly across a thread boundary;
    // the rest ride in and out of that surface.
    assert_send_sync::<AuthOptions>();
    assert_send_sync::<Origin>();
    assert_send_sync::<NotCanonical>();
    assert_send_sync::<NodePrefix>();
    assert_send_sync::<NotANodePrefix>();
    assert_send_sync::<PortAlreadyBound>();
    assert_send_sync::<Peer>();
    // The signed-ops arrivals (`hybrid`): the signer a client holds across
    // threads, the seeds it derives from, the verify's refusal, the
    // fixtures' seeded stream, and the widths the sizes pin reads.
    assert_send_sync::<hybrid::HybridSigner>();
    assert_send_sync::<hybrid::HalfSeeds>();
    assert_send_sync::<hybrid::HybridFault>();
    #[cfg(any(test, feature = "test-hooks"))]
    assert_send_sync::<hybrid::SeededRng06>();
    #[cfg(any(test, feature = "test-hooks"))]
    assert_send_sync::<hybrid::PqWidths>();
};
