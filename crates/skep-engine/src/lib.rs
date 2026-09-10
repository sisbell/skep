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
//! computation lives in a store. These obligations are the engine's alone,
//! one module apiece:
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
//!   `doc ∉ exception_set` and nothing else, and the set's one enumeration
//!   ([`World::drafts`]) hands its entries out as [`Draft`] rows.
//! * **The read predicate** ([`World::readable`]; the `readable` module) —
//!   the one function `readable(doc, principal) = published(doc) ∨ subtree ∨
//!   grant_exists` (PUB-1.31, lane 3.3, §1), composing the exception set's
//!   clause, M3's ω memo and the grant fold's probe. Every read surface —
//!   M6's deliveries and doc-argument consults, M8's result-set filters, the
//!   publish source gate — answers through this one predicate, threaded down
//!   as an opaque `Fn(&Address) -> bool` (PUB-6.39), and every write is gated
//!   at the class [`World::visible_to`] maps its caller to (PUB-6.25).
//! * **The grant fold** (the `grants` module) — the second derived index the
//!   predicate rests on: a fold over the LINK slice keyed grantee ×
//!   content-prefix, seeded at load and folded on every link deposit
//!   (PUB-7.7), with NO checkpoint slice. It also publishes its two feed
//!   enumerations ([`World::universal_grants`], [`World::issuers_for`]; lane
//!   3.6) — the live ANY-PRINCIPAL set and a grantee's issuers with their
//!   covered prefixes, as [`UniversalGrant`] and [`IssuerGrant`] rows — the
//!   key set the daemon's change feed resolves once per request (PUB-7.22,
//!   PUB-7.28).
//! * **The edition-claim lookup** ([`World::edition_claims`]; the `editions`
//!   module) — the audit-view `to`-range lookup over the R20 edition-claim
//!   class (PUB-8.46, lane 3.4, §2), composed from M7's own audit reads over
//!   a type address pinned beside the grants class; M10's
//!   `ReadableWorld::edition_claims` reaches it and applies the home rule.
//! * **The commons type pins** (the public [`types`] module) — every commons
//!   type address the engine or the daemon keys on as a VALUE, in one ledger:
//!   the grant and edition classes the two indexes above read, and the
//!   audit-view classes the daemon's write path refuses a `nullify` at
//!   (PUB-6.30, PUB-6.64; lane 3.5). None is a registered M7 type.
//! * **The world dump** ([`dump`], behind the `dump` feature) — a
//!   deterministic, byte-comparable rendering of the authoritative observable
//!   state (the publication slice and the grant fold's operative set as
//!   sections of their own since v5) plus the recomputable hints (the
//!   exception set among them), for the conformance and crash harnesses —
//!   and, since lane 3.4, the same tree post-filtered at a READER'S CLASS
//!   for the daemon's `/dump`.

#![forbid(unsafe_code)]

mod canon;
mod editions;
mod engine;
mod genesis;
mod grants;
mod publication;
mod readable;
pub mod types;
mod world;

#[cfg(feature = "dump")]
pub mod dump;

pub use engine::{Engine, EngineError, EngineStores};
pub use grants::{IssuerGrant, UniversalGrant};
pub use publication::Draft;
pub use world::{Record, World};

// The KERNEL types the engine's own signatures name, re-exported so a binary
// can drive `Engine::open`, `coordinator()` and `world_at` — the whole
// assembly surface — without naming M2 itself. The address and principal
// vocabulary the read surfaces speak (`Address`, `PrincipalId`, `Caller`)
// stays the stores' to export: a caller holding an argument for
// `World::readable` or `Engine::world_dump_visible_to` already built it out
// of the crate that owns it.
pub use skep_kernel::{HistoryError, KernelConfig, OpenError, Seq};
