//! # skep-links — M7: Link & Relation Store
//!
//! The **authoritative, append-only store of links and typed relations** —
//! every connection in the docuverse — keyed by the link's own permanent
//! address, together with the recomputable coverage indexes that answer
//! "which links touch this region". M7 is the single writer and single
//! source of truth for link values, and serves every read of structural
//! relation state that does not require V-resolution: the write surfaces
//! (MAKELINK \[ASN-0120\], Emit_K/Nullify \[ASN-0086/0126/0128\],
//! assert_sup/editlink \[ASN-0125\]), the raw reads (READLINK/FOLLOWLINK
//! \[ASN-0111/0114\]), the typed-relation observers (Observe + the behavior
//! atoms BH1–BH4 \[ASN-0128\]), the immutable type/shape registry, idempotent
//! de-duplication, and the spanfilade discovery primitives for M8.
//!
//! The Lampson spine (§Core data model): the journal (via M2) is truth; the
//! authoritative state is one append-only map plus the genesis type config;
//! everything else is a recomputable hint — lose any hint and replay rebuilds
//! it, never wrong. There is no update, no delete, no tombstone record.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * address minting and home-existence/ownership facts (M3 — M7 *calls*
//!   `mint_link`, reads `is_registered_document`);
//! * the V→I arrangement and home seating mechanism (M5 — M7 *calls* the
//!   semantics-blind `resolve`/`stage_seat_link`, never interpreting
//!   arrangement, never reading link semantics back);
//! * ordering/durability/recovery (M2);
//! * the provenance relation R (M5 — link placement is uncoupled from R,
//!   ASN-0047 J-LV: M7 appends none);
//! * non-transcludability enforcement (M5's content-side referential
//!   integrity — M7's only duty is keeping links in `s_L`);
//! * indexed discovery *presentation* — findlinks/count/pagination/
//!   projection/RETRIEVEENDSETS and archival in/out (M8, executing over M7's
//!   primitives across the `M8→M7` edge);
//! * no `coverage` function — coverage is the query-time `denotes`
//!   projection, never a stored value.
//!
//! ## Interface/design divergences realized here (surfaced, not papered over)
//!
//! The M7 interface and the M7 design disagree in places; per the authority
//! ladder the interface's signatures are followed and the design's semantics
//! are kept where expressible. Each site carries a `DEVIATION` note:
//! `EmitError::SupersessionClass` and the registry's two v1 serving-fence
//! variants are design-mandated additions to the interface's enums;
//! `stale`/`retract_stale` keep the interface shapes and realize the
//! design's NotBh4 fence as an empty result; `observe`/`is_k`/`is_filtered`
//! take the interface's `Address` probes (the design's T-wide `Tumbler`
//! domain is inexpressible under them); `is_in_chain` is caller-derived
//! (`chain(ty, addr).contains(target)`), per the interface's explicit note.
//!
//! ## Composition
//!
//! Per the Engine Composition Contract, M7 never names the concrete
//! `World`/`Record`: the engine implements [`HasLinks`] for its
//! `W: WorldState`, lifts M7's delta via `impl From<LinkRec> for W::Record`,
//! and dispatches its `Record::Links` variant into the fold
//! [`LinkState::apply_link`]; [`LinkState::rebuild_derived`] runs once at
//! load, before replay. M7's dedup `LockKey` draws the `Space::CoverageClass`
//! tag from M2's central enum; namespace alloc keys come from M3's
//! `link_lock_key`.

#![forbid(unsafe_code)]

mod endset;
mod error;
mod reads;
mod registry;
mod state;
mod store;

pub use endset::{coverage_class, enc, CoverageClass, Endset, Link};
pub use error::{
    AssertSupError, EditLinkError, EmitError, Invalid, MakeLinkError, NullifyError,
};
pub use reads::{CurrentMember, Tip, Tuple, View};
pub use registry::{
    Behavior, Registration, RegistryError, ReservedAddrs, Shape, ShippedType, TypeDecl,
    TypeRegistry,
};
pub use state::{LinkRec, LinkState};
pub use store::LinkStore;

use skep_address::Nat;

/// The engine's **read accessor** for M7's slice (Engine Composition
/// Contract): the engine implements this for its concrete world
/// (`W: WorldState + HasLinks`), and M7 — built before `W` exists — codes
/// against it, reaching its slice as `stg.working().links()` inside a
/// composite and `snapshot.world().links()` for a read. READ side only; the
/// write-side mirror is the engine's `impl From<LinkRec> for W::Record` lift.
pub trait HasLinks {
    /// M7's slice of the world state.
    fn links(&self) -> &LinkState;
}

// Subspace convention (ASN-0093/ASN-0047): s_C = 1 (content), s_L = 2 (link);
// slots are 1-based FROM = 1, TO = 2, TYPE = 3. Following the workspace
// precedent (M4/M5 define the axiom-pinned numerals crate-locally — the built
// skep-kernel carries no subspace constants), these live here as
// crate-private values; value-equality across the system holds because every
// producer derives them from the one ASN-0047 convention.

/// `s_C` = 1 — the content-subspace numeral.
pub(crate) fn s_c() -> Nat {
    Nat::from(1u32)
}

/// `s_L` = 2 — the link-subspace numeral.
pub(crate) fn s_l() -> Nat {
    Nat::from(2u32)
}

/// FROM = 1 (1-based standard slot).
pub(crate) const FROM: usize = 1;

/// TO = 2 (1-based standard slot).
pub(crate) const TO: usize = 2;
