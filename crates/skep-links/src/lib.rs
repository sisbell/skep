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
//! authoritative state is one append-only map; everything else is a
//! recomputable hint — lose any hint and replay rebuilds it, never wrong —
//! and the type registry is a compiled format constant, not state (the five
//! reserved classes are ghost tumblers, [`ReservedAddrs::format`]; owner
//! ruling, 2026-08-26). There is no update, no delete, no tombstone record.
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
//! * no `coverage` function — coverage is the query-time `covers`
//!   projection, never a stored value.
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

use skep_kernel::WorldState;
use skep_namespace::HasM3;

mod dedup;
mod endset;
mod error;
mod reads;
mod registry;
mod state;
mod writes;

pub use endset::{coverage_class, enc, CoverageClass, Endset, Link};
// The ONE caller-identity type of the write-surface ownership gate
// (as amended 2026-08-16) — defined beside M5's edit ops, re-exported here
// because M7's five deposit ops take it too.
pub use skep_arrangement::Caller;
pub use error::{
    AssertSupError, EditLinkError, EmitError, Invalid, MakeLinkError, NotBh4, NullifyError,
    RetractStaleError,
};
pub use reads::{CurrentMember, Pattern, Tip, Tuple, View};
pub use registry::{Behavior, Registration, ReservedAddrs, Shape, ShippedType, TypeRegistry};
pub use state::{LinkRec, LinkState};
pub use writes::{LinkWriter, SlotArg, MAX_SLOT_SPANS};

/// The auto traits M7's slice promises without saying. `WorldState` is
/// `Send + Sync + 'static`, so the engine's `impl WorldState for World` owes
/// those bounds of [`LinkState`] and [`LinkRec`] through types no signature
/// in this crate mentions — and they are kept by what the private fields
/// contain, so swapping this crate's `im` for the `Rc`-backed `im-rc` would
/// revoke them with nothing here failing to build. Asserted in the library
/// rather than the suite, because that is the build a manifest change is made
/// in, and it is this crate's manifest that names `im`.
const _: fn() = || {
    fn owed<T: Send + Sync + 'static>() {}
    owed::<LinkState>(); // the `WorldState` bound reaches this through the engine
    owed::<LinkRec>(); // and this through `WorldState::Record`
    owed::<TypeRegistry>();
    owed::<Endset>();
    owed::<Link>();
    owed::<CoverageClass>();
    owed::<Tuple>();
    owed::<CurrentMember>();
    // Every rejection too: a caller that boxes one meets
    // `Box<dyn Error + Send + Sync>`, which is the crossing form.
    owed::<MakeLinkError>();
    owed::<EmitError>();
    owed::<NullifyError>();
    owed::<AssertSupError>();
    owed::<EditLinkError>();
    owed::<NotBh4>();
    owed::<Invalid>();
    owed::<RetractStaleError>();
    // `LinkWriter` is deliberately absent: it borrows the kernel, so it is
    // not `'static` and cannot ride this helper.
};

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

/// The world M7 deposits into: M2's fold contract, M7's own slice, and M3's —
/// every write path reads the store to gate and calls the namespace to mint,
/// so the three travel together and are named once here. MAKELINK adds
/// `HasM5` on top, being the only op that seats. Blanket-implemented, so an
/// engine that implements the accessors gets this for free.
pub trait LinkWorld: WorldState + HasLinks + HasM3 {}
impl<W: WorldState + HasLinks + HasM3> LinkWorld for W {}

// The 1-based standard slot numerals (ASN-0043 L6: slot index is a
// primitive). M7 owns them — it is the store whose `Link` is a positional
// sequence — so they are named here and read by everyone who indexes a slot,
// M8's region and descriptor queries included. The subspace numerals `s_C`
// and `s_L` are M1's, named there as `content_subspace`/`link_subspace`.

/// FROM = 1 — the slot holding `e₁` ([`Link::from_slot`]).
pub const FROM: usize = 1;

/// TO = 2 — the slot holding `e₂` ([`Link::to_slot`]).
pub const TO: usize = 2;

/// TYPE = 3 — the slot holding `e₃` ([`Link::type_slot`]).
pub const TYPE: usize = 3;
