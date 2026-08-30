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
//! computation lives in a store. Three obligations are the engine's alone:
//!
//! * **Genesis** ([`World::genesis`], [`Engine::open`]) — the initial world,
//!   a compiled constant (the reserved type set is format, not
//!   configuration — owner ruling, 2026-08-26), whose single
//!   `Arc<TypeRegistry>` M7's slice holds and the engine shares out to M9
//!   (and any other assembly-time consumer).
//! * **Recovery order** (`WorldState::rebuild_derived` for `World`) — the
//!   cross-store rebuild sequence at load, stated and pinned in one place.
//! * **The world dump** ([`dump`], behind the `dump` feature) — a
//!   deterministic, byte-comparable rendering of the authoritative observable
//!   state plus the recomputable hints, for the conformance and crash
//!   harnesses.

#![forbid(unsafe_code)]

mod engine;
mod genesis;
mod world;

#[cfg(feature = "dump")]
pub mod dump;

pub use engine::{Engine, EngineError, EngineStores};
pub use world::{Record, World};

// The foreign types the engine's own signatures name, re-exported so a binary
// can drive `Engine::open`/`coordinator()` without spelling every store crate.
pub use skep_kernel::{HistoryError, KernelConfig, OpenError};
pub use skep_links::ReservedAddrs;
