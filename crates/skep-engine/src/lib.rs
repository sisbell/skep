//! # skep-engine — the single assembler
//!
//! The one crate allowed to know everything (Engine Composition Contract,
//! §The model): it defines the one concrete [`World`] (every store's slice),
//! the one central [`Record`] enum (every store's delta), implements M2's
//! `WorldState` for `World` (dispatching `apply` into each store's fold),
//! implements every store's accessor trait, and supplies every `From`-lift.
//! No store crate names `World`/`Record`, so the lib graph stays a DAG by
//! construction (§Crate-graph consequence); what sits above it, as built, is
//! the daemon (`skepd`), the conformance harness (`skep-conformance`, a
//! library, not a binary), and — dev-only, the edge back through M2 that
//! cargo permits — M2's dirty-crash harness, which judges recovery against
//! this crate's world dump. Sizing a change to the public surface means
//! those three.
//!
//! **The engine adds no semantics.** Every function here is dispatch,
//! lifting, construction, or rendering; every guard, policy, and
//! computation lives in a store. Four obligations are the engine's alone:
//!
//! * **Genesis** ([`World::genesis`], [`Engine::open`]) — the initial world,
//!   a compiled constant (the reserved type set is format, not
//!   configuration — owner ruling, 2026-08-26). The type registry is M7's
//!   module constant rather than any slice's state, so genesis carries none
//!   of it: [`Engine::open`] clones that one `Arc<TypeRegistry>` and shares
//!   it out to M9 (and any other assembly-time consumer). The World leads
//!   its checkpoint bytes with a FORMAT STAMP, so a base written under any
//!   other layout — the pre-publication-bit layout above all (PUB-7.8) —
//!   fails to decode and M2's fallback chain takes over (PUB-7.9).
//! * **Recovery order** (`WorldState::rebuild_derived` for `World`) — the
//!   cross-store rebuild sequence at load, stated and pinned in one place.
//! * **The exception set** ([`World::published`], [`World::owner_account`];
//!   the `publication` module) — the derived membership index over M3's
//!   publication bit (PUB-7.5; owner ruling D1, 2026-09-05: ONE publication
//!   definition), seeded at load and folded on every document-minting
//!   record (PUB-7.7). The daemon's every publication read answers
//!   `doc ∉ exception_set` and nothing else.
//! * **The world dump** ([`dump`], behind the `dump` feature) — a
//!   deterministic, byte-comparable rendering of the authoritative observable
//!   state plus the recomputable hints (the exception set among them), for
//!   the conformance and crash harnesses.

#![forbid(unsafe_code)]

mod canon;
mod engine;
mod genesis;
mod publication;
mod world;

#[cfg(feature = "dump")]
pub mod dump;

pub use engine::{Engine, EngineError, EngineStores};
pub use world::{Record, World};

// The foreign types the engine's own signatures name, re-exported so a binary
// can drive `Engine::open`/`coordinator()` without spelling every store crate.
pub use skep_kernel::{HistoryError, KernelConfig, OpenError};
pub use skep_links::ReservedAddrs;
