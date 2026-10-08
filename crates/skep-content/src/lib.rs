//! # skep-content — M4: Content Store (Istream)
//!
//! The **permascroll**: an append-only, write-once map from allocated
//! I-address to opaque content value, plus the two point queries over it —
//! *is content stored here?* ([`ContentStore::contains`]) and *what is
//! stored here?* ([`ContentStore::value_at`]). M4 owns the immutable,
//! never-GC'd half of the strand — ASN-0036's two-component state, the
//! content store and the arrangements — and does exactly that one thing:
//! **store an immutable value at an address forever, and look it up — never
//! mutate, never delete, never reclaim, never key on the value.** Addresses
//! arrive as parameters already minted and validated upstream (M3); M4
//! trusts them and stores bytes.
//!
//! Three surfaces (§Public interface):
//!
//! * **Engine plug** (§A) — the slice [`ContentStore`], the record
//!   [`ContentWrite`], the accessor [`HasContent`], and the fold
//!   [`ContentStore::apply_write`], per the Engine Composition Contract.
//! * **Read API** (§B) — [`ContentStore::contains`] (the S3
//!   referential-integrity oracle: content-presence, whether content is
//!   stored here — not "allocated", not "registered") and
//!   [`ContentStore::value_at`] (`C(a)`), point queries over a pinned
//!   snapshot slice; and [`ContentStore::iter`], the one enumeration, in no
//!   promised order, for whole-store work over a pinned snapshot such as the
//!   cell index's walk.
//! * **Write surface** (§C) — the pure step [`stage_write`] (the storage
//!   half of K.α, composed by M5's placement composite) and `write`, the
//!   `#[doc(hidden)]` standalone transact-wrapped form (M2 contract 3) —
//!   compiled only under the `test-hooks` feature.
//!
//! Spec traceability: each public item's doc-comment cites the labels it
//! realizes (ASN-0036 S0–S5/S3, ASN-0093 C0/C-fin, K.α, J0, and §§ of the
//! M4 design), so a reviewer can walk from code to design without the
//! documents open.
//!
//! ## Invariants
//!
//! **By construction:** S0(a) domain-persistence and S1 store monotonicity
//! (ASN-0093 C0's append-only half; insert-only fold, no removal op); S0(b)
//! value-preservation (no modify op exists, and the fold never replaces a
//! stored value — a record whose address already has a value stored leaves
//! the slice as it was); S4 origin-based identity (keyed by address, never
//! by value — two equal values at two addresses are two entries; no
//! value→address index); S5 unrestricted sharing (no refcount, no cap —
//! references live in M5); C-fin finiteness; and unconditional no-GC
//! permanence (orphan content persists; M4 does not even know about
//! references).
//!
//! **At the doors:** every key is T4-valid (ASN-0093 StoreT4Validity) and a
//! content-subspace element address (C1, L0 — M4's half of SD);
//! [`ContentStore`] names each invariant's gate, the two decode paths
//! included.
//!
//! **Diagnosed, not relied on:** a second write at one address.
//! [`stage_write`] refuses an address already stored in the slice it is
//! handed (`AlreadyStored`), so an address minted twice upstream becomes a
//! typed rejection instead of a write the fold drops; its doc says which
//! slice to hand it.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * minting or validating addresses (M3; M1's validator) — every key M4
//!   stores is the tumbler of an `Address`, taken as one at the write doors
//!   and re-checked through M1's `Address` door wherever a record or a slice
//!   is decoded;
//! * arranging, referencing, or routing content, and enforcing referential
//!   integrity (M5 — M4 only *answers* the check via `contains`; the
//!   strongest S3 timing is achieved by M2's atomicity around M5's
//!   composite, not by M4);
//! * V→I resolution, origin attribution, version comparison, and the
//!   registered-empty-vs-unallocated distinction (M6);
//! * link values — M7 is the parallel value-only store for `L`; the link
//!   layer (M7/M8) never reads M4 (store-disjointness SD:
//!   `dom(C) ∩ dom(L) = ∅`);
//! * journal, replay, snapshot, recovery (M2): [`ContentWrite`] is the
//!   authoritative delta M2 journals; the slice is its fold, fully
//!   serialized in checkpoints (M2's default `rebuild_derived` identity);
//! * modify, delete, GC, reclamation, refcounts — none exists, and no
//!   fixed-width counter that could cap or overflow is ever introduced;
//! * author/source/origin metadata — origin (S7) is established by M3's
//!   allocation discipline and computed structurally by M1's `document_of`
//!   (surfaced as SHOWORIGIN in M6); M4 stores only `address → Val`, so no
//!   redundant origin field can diverge;
//! * range, prefix-scan, max-under-prefix — the reads are point reads and the
//!   one enumeration, [`ContentStore::iter`]; no query is built on the map's
//!   order (its field in `store.rs` says what the order is for), and the
//!   allocator's max-under-prefix reads M3's own frontier, never M4;
//! * concurrency — none of M4's own: no locks, no threads, no interior
//!   mutability. Content writes ride M5's composite under the
//!   per-(document, content-subspace) lock key; every content address is
//!   written exactly once, so no two writers ever target the same address.
//!
//! ## Composition
//!
//! Per the Engine Composition Contract, M4 never names the concrete
//! `World`/`Record`: the engine implements [`HasContent`] for its
//! `W: WorldState` (the read accessor), lifts M4's delta via
//! `impl From<ContentWrite> for W::Record` (the write-side mirror), and
//! dispatches its `Record::Content` variant into the fold
//! [`ContentStore::apply_write`]. The engine only `From`-lifts and folds
//! the record; it never builds one. Anything that inspects a journaled
//! record reads it through [`ContentWrite::addr`] /
//! [`ContentWrite::val`] and its `Debug`, which the engine's
//! `Record: Debug` rests on and which renders a value as its length.

#![forbid(unsafe_code)]

// The opaque content value, `Val`.
mod value;
// The write surface's one typed rejection, `ContentError`.
mod error;
// The routing assertion (Open build decision #4), shared by `stage_write`
// and `write`.
mod routing;
// The slice — its fold, point queries, one enumeration and serialized form —
// the record, and `stage_write`, the record's one producer (`ContentWrite`'s
// fields are private to this file).
mod store;
// `write`, the standalone transact-wrapped twin of `stage_write` —
// `test-hooks` builds only.
#[cfg(feature = "test-hooks")]
mod ops;

pub use error::ContentError;
#[cfg(feature = "test-hooks")]
pub use ops::write;
pub use store::{stage_write, ContentStore, ContentWrite};
pub use value::Val;

/// The engine's **read accessor** for M4's slice (§A; Engine Composition
/// Contract). The engine implements it for its concrete world, and every
/// reader of M4 reaches the permascroll through it: M5's composites as
/// `stg.working().content()` — the slice they hand [`stage_write`], and ask
/// `contains` and `value_at` of — and every reader of a snapshot as
/// `snapshot.world().content()`. M4's library reads no world of its own;
/// only the test-only `write` bounds on this. READ side only; its write-side
/// mirror is the engine's `impl From<ContentWrite> for W::Record` lift,
/// through which the write paths stage deltas via `stg.push(rec.into())`.
///
/// IMPLEMENTORS OWE one fact the signature cannot carry: `content()` is the
/// very slice the world's `WorldState::apply` folds this crate's records
/// into, through [`ContentStore::apply_write`]. Two promises rest on it:
/// [`stage_write`]'s already-stored check sees only the slice it is handed,
/// so it refuses what the fold would drop only when
/// `stg.working().content()` is that slice; and a reader's
/// `snapshot.world().content()` holds every value the snapshot's placements
/// resolve to, which M6's RETRIEVEV `expect`s (S3★). An implementor that
/// answered any other `ContentStore` would void both, and nothing in this
/// crate can check it.
pub trait HasContent {
    /// M4's slice of the world state.
    fn content(&self) -> &ContentStore;
}

/// The auto traits M4's types promise without saying. `WorldState` is
/// `Send + Sync + 'static`, so the engine's `impl WorldState for World` owes
/// those bounds of [`ContentStore`], a field of its `World`, and of
/// [`ContentWrite`], the record its `Record::Content` carries, through types
/// no signature in this crate mentions; [`Val`] rides M10's `Request` across
/// the daemon's workers; and [`ContentError`] travels inside M5's
/// `InsertError` and `PublishError`. They are kept by what the private fields
/// contain — the `im` map, the `Arc` under `Val` — so a field that revoked
/// one (the `Rc`-backed `im-rc` for `im`, an `Rc` under `Val`) would compile
/// here and fail a crate away, never naming the field. Asserted in the
/// library rather than the suite, because that is the build a manifest change
/// is made in, and it is this crate's manifest that names `im`.
const _: fn() = || {
    fn owed<T: Send + Sync + 'static>() {}
    owed::<ContentStore>(); // the `WorldState` bound reaches this through the engine
    owed::<ContentWrite>(); // and this through `WorldState::Record`
    owed::<Val>();
    // The rejection too: a caller that boxes one meets
    // `Box<dyn Error + Send + Sync>`, which is the crossing form.
    owed::<ContentError>();
};
