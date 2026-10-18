//! # skep-core — the daemon's core
//!
//! Who may act on a board (the session layer, [`auth`]), what every write
//! rides and leaves behind (the commits — the one door, the record, the
//! feed, the published head — [`commits`]) and the wire's JSON grammar
//! ([`codec`]): the collaborators `skepd` composes behind its router, and
//! nothing of the transport. The routes, the replies, the history service,
//! the operator's tools and the process are `skepd`'s, the crate over this
//! one. The daemon — that crate over this core — is what is permitted to
//! depend on the engine (Engine Composition Contract); the as-built list of
//! the engine's dependents is `skep-engine`'s crate doc.
//!
//! Its modules form three layers, which `ARCHITECTURE.md` §The daemon's
//! core draws and `tests/it/tidy.rs` checks: a module names only its own
//! layer and the layers below it. This root re-exports nothing — the
//! daemon's root re-exports what its callers name — so code names an
//! in-crate item by its home module.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// Layer 0 — the session layer: the two origin sets, the handshake, the
// sessions store and per-request resolution, the credential write lock and
// the refusal producers it scopes, the signed-ops check and the entry frame
// it verifies over, and the readers of the World's identity slice.
pub mod auth;
// Layer 1 — the commits: the one door every write rides (commit, record,
// announce, under one guard), the record `commits.log`, the change feed and
// its five files, the attest store, and the published head writer.
pub mod commits;
// Layer 2, the leaves — the wire codec: the JSON grammar, parse and marshal.
pub mod codec;
// The bounds this crate reads, each `pub`, two of them the daemon's too.
pub mod limits;
// The write-serialization lock, its guard and its takes.
pub mod serial;
