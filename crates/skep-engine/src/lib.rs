//! # skep-engine — the single assembler
//!
//! The one crate allowed to know everything (Engine Composition Contract,
//! §The model): it defines the one concrete [`World`] (every store's slice),
//! the one central [`Record`] enum (every store's delta), implements M2's
//! `WorldState` for `World` (dispatching `apply` into each store's fold),
//! implements every store's accessor trait, and supplies every `From`-lift.
//! Nothing depends on this crate except a binary; no store crate names
//! `World`/`Record`, so the crate graph stays a DAG by construction
//! (§Crate-graph consequence).
//!
//! **The engine adds no semantics.** Every function here is dispatch,
//! lifting, construction, or observation; every guard, policy, and
//! computation lives in a store. Three obligations are the engine's alone:
//!
//! * **Genesis** ([`GenesisConfig`], [`World::genesis`], [`Engine::open`]) —
//!   the initial world, with the one [`TypeConfig`] held in ONE place and
//!   validated once, into the single `Arc<TypeRegistry>` M7's slice holds and
//!   the engine shares out to M9 (and any other assembly-time consumer).
//! * **Recovery order** (`WorldState::rebuild_derived` for `World`) — the
//!   cross-store rebuild sequence at load, stated and pinned in one place.
//! * **The observation surface** ([`observe`], behind the `observe` feature)
//!   — a deterministic, byte-comparable rendering of the authoritative
//!   observable state plus the recomputable hints, for the conformance and
//!   crash harnesses.

#![forbid(unsafe_code)]

mod engine;
mod genesis;
mod world;

#[cfg(feature = "observe")]
pub mod observe;

pub use engine::{Engine, EngineError, EngineStores};
pub use genesis::GenesisConfig;
pub use world::{Record, World};

// The foreign types the engine's own signatures name, re-exported so a binary
// can drive `Engine::open`/`coordinator()` without spelling every store crate.
pub use skep_coordination::CatalogError;
pub use skep_kernel::{HistoryError, KernelConfig, OpenError};
pub use skep_links::{RegistryError, ReservedAddrs, TypeConfig, TypeDecl};
