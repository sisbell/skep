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
//!   (the embedded authoring client, `client` feature, default on), the
//!   CORS preflight on every known path, and (behind the `observe`
//!   feature) `GET /dump`, with `?at=N` for the dump of a historical
//!   position.
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
mod server;
mod sidecar;

pub use codec::{tumbler_string, JsonCodec};
pub use server::{serve, Daemon, DaemonError, Reply, Routed, Skepd};
