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
//! **The engine re-decides nothing a store decides.** A store's guards,
//! policies and computations live in that store, and the engine reaches them
//! by dispatch, lifting, construction and rendering alone. What the engine
//! owns is what no single store can hold, one module apiece — and where one
//! of those obligations applies a rule of its own (the grant fold's
//! classification and admission, the read predicate's subtree clause, the
//! edition class's membership test, the dump's per-class reduction), the
//! module that applies it states it:
//!
//! * **Genesis** ([`World::genesis`], [`Engine::open`]) — the initial world,
//!   a compiled constant (the reserved type set is format, not
//!   configuration — owner ruling, 2026-08-26). The type registry is M7's
//!   module constant rather than any slice's state, so genesis carries none
//!   of it: every reader asks M7 for the one `Arc<TypeRegistry>`, and
//!   [`Engine::coordinator`] clones it for M9, which takes an owned one. The
//!   World leads its checkpoint bytes with a FORMAT STAMP, so a base written
//!   under any other format count — the pre-publication-bit layout above all
//!   (PUB-7.8) — fails to decode at its first word, the one older layout this
//!   count also names fails later by the arithmetic the stamp's card states,
//!   and either way M2's fallback chain takes over (PUB-7.9).
//! * **Recovery order** (`WorldState::rebuild_derived` for `World`) — the
//!   cross-store rebuild sequence at load, stated in one place, with its two
//!   engine edges pinned by the tests that method names.
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
//!   clause, the subtree clause the `readable` module writes over M3's ω memo
//!   and M3's seat, and the grant fold's probe. Every read surface —
//!   M6's deliveries and doc-argument consults, M8's result-set filters —
//!   answers through this one predicate, threaded down as an opaque
//!   `Fn(&Address) -> bool` (PUB-6.39), and a caller that asks it once per
//!   row binds one [`ReaderClass`] ([`World::reader_class`]), so the reader's
//!   seat in M3's principal registry is looked up once rather than per row;
//!   a write evaluates it over its own transaction's working world — the
//!   publish shot's source gate on each origin, and every link write at the
//!   visibility class [`World::visible_to`] maps its caller to (PUB-6.25).
//! * **The grant fold** (the `grants` module) — the second derived index the
//!   predicate rests on: a fold over the LINK slice keyed grantee ×
//!   content-prefix, seeded at load and folded on every link deposit
//!   (PUB-7.7), with NO checkpoint slice. It also publishes its two feed
//!   enumerations ([`World::universal_grants`], [`World::issuers_for`]; lane
//!   3.6) — the live ANY-PRINCIPAL set and a grantee's issuers with the
//!   prefixes their index entries name, as [`UniversalGrant`] and
//!   [`IssuerGrant`] rows — the key set the daemon's change feed resolves
//!   once per request (PUB-7.22, PUB-7.28); M10's any-principal discovery
//!   read (PUB-8.47) takes the first through
//!   `PublicationWorld::universal_grants`, raw, and narrows it itself. What
//!   they enumerate is the fold's STORED index, a superset of entitlement, and
//!   ENTRIES rather than grants: one per (issuer, prefix, grantee), which a
//!   revocation of either of two identical grants removes (the `grants`
//!   module states it).
//! * **The edition-claim lookup** ([`World::edition_claims`]; the `editions`
//!   module) — the audit-view `to`-range lookup over the R20 edition-claim
//!   class (PUB-8.46, lane 3.4, §2), composed from M7's own audit reads over
//!   a type address pinned beside the grants class; M10's
//!   `PublicationWorld::edition_claims` reaches it and applies the home rule.
//! * **The commons type pins** (the public [`types`] module) — every commons
//!   type address the engine or the daemon keys on as a VALUE, in one ledger:
//!   the grant and edition classes the two indexes above read, and the
//!   audit-view classes the daemon's write path refuses a `nullify` at
//!   (PUB-6.30, PUB-6.64; lane 3.5). None is a registered M7 type.
//! * **The world dump** ([`dump`], behind the `dump` feature) — a
//!   deterministic, byte-comparable rendering of the authoritative observable
//!   state (M3's publication map and the grant fold's operative set as
//!   sections of their own since v5) plus the recomputable hints (the
//!   exception set among them), for the conformance and crash harnesses —
//!   and, since lane 3.4, the same tree post-filtered at a READER'S CLASS
//!   for the daemon's `/dump`.

#![forbid(unsafe_code)]

// The canonicalizing transcode is the dump's, and its way back is how the
// engine's own tests build the shapes a checkpoint can carry and no op can
// produce — so it is compiled for either and for nothing else.
#[cfg(any(feature = "dump", test))]
mod canon;
mod editions;
mod engine;
mod genesis;
mod grants;
mod publication;
mod readable;
// The in-crate suites' shared fixtures: the in-memory engine, the delegated
// account and the address constructors they start from.
#[cfg(test)]
mod testkit;
pub mod types;
mod world;

#[cfg(feature = "dump")]
pub mod dump;

pub use engine::{Engine, EngineError, EngineStores};
pub use grants::{IssuerGrant, UniversalGrant};
pub use publication::Draft;
pub use readable::ReaderClass;
pub use world::{Record, World};

// The KERNEL types this crate's own public signatures name — `Kernel`,
// `KernelConfig`, `OpenError`, `HistoryError` and `Seq` — and the three a
// `KernelConfig` is built from, re-exported so a binary can open an engine,
// pair a reconstructed world with a kernel at `EngineStores::new`, and call
// `world_at` without naming M2 itself. The integration suite is a separate
// crate and builds its kernel configurations and its historical kernel
// through these names, so narrowing the set fails that build. What those
// types' own methods hand back (`Snapshot`, `CheckpointError`, the drivers'
// `TxnError`), and the `WorldState` trait `World` implements, are M2's
// surface and stay M2's to export. The address and principal vocabulary the
// read surfaces speak (`Address`, `PrincipalId`, `Caller`) stays the stores'
// to export: a caller holding an argument for `World::readable` or
// `Engine::world_dump_visible_to` already built it out of the crate that
// owns it.
pub use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, HistoryError, Kernel, KernelConfig, OpenError,
    Seq,
};
