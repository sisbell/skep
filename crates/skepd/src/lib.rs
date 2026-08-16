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
//!   `GET /health`, and (behind the `observe` feature) `GET /dump`, with
//!   `?at=N` for the dump of a historical position.
//! * [`serve`]/[`Skepd`] — the synchronous accept loop: worker threads over
//!   one shared listener, bound to 127.0.0.1 (local trust does not survive
//!   a network).
//!
//! Durability lives in M2 and is *configured* here (`Durability::Fsync`,
//! every-1024-commits checkpoints, two retained): genesis on a fresh data
//! dir, recovery on an existing one, and no file in this crate's own hand.

#![forbid(unsafe_code)]

mod codec;
mod server;

pub use codec::{tumbler_string, JsonCodec};
pub use server::{serve, Daemon, Reply, Skepd};
