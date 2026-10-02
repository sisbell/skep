//! # skep-content — M4: Content Store (Istream)
//!
//! The **permascroll**: an append-only, write-once map from allocated
//! I-address to opaque content value, plus the two point queries over it —
//! *is content stored here?* ([`ContentStore::contains`]) and *what is
//! stored here?* ([`ContentStore::value_at`]). M4 owns the immutable,
//! never-GC'd half of the two-layer state and does exactly that one thing:
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
//!   referential-integrity oracle: content-presence, not "allocated", not
//!   "registered") and [`ContentStore::value_at`] (`C(a)`), point queries
//!   over a pinned snapshot slice; and [`ContentStore::iter`], the one
//!   enumeration, for the daemon's cell-index rebuild alone.
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
//! **By construction:** S0(a) domain-persistence and S1/C0 growth
//! (insert-only fold, no removal op), the modify half of S0(b) (no modify
//! op exists), S4 origin-based identity (keyed by address, never by value —
//! two equal byte-runs at two addresses are two entries; no value→address
//! index), S5 unbounded sharing (no refcount, no cap — references live in
//! M5), C-fin finiteness, and unconditional no-GC permanence (orphan
//! content persists; M4 does not even know about references).
//!
//! **By active enforcement:** the no-overwrite half of S0(b), kept on both
//! sides of one call, as [`stage_write`] states: it refuses an address
//! already stored in the slice it is handed, and is the only way to stage a
//! [`ContentWrite`]; its caller hands it the slice the record will be folded
//! into — a half no type holds, which [`ContentStore::apply_write`]'s
//! `debug_assert!` nets.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * minting or validating addresses (M3) — every address M4 handles is
//!   T4-valid by M1's standing invariant;
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
//! * ordered iteration, range, prefix-scan, max-under-prefix — the reads
//!   rely only on `Eq + Hash`; `Tumbler`'s `Ord` is used once, by the
//!   serializer's sort (`store.rs`), whose output — M2's checkpoint body and
//!   the engine's world dump — is the only ordered whole-store enumeration
//!   M4 offers; the ordered-map rationale belongs to M3's frontier, not
//!   here. The ONE enumeration beside the point reads,
//!   [`ContentStore::iter`], is unordered and exists for one consumer: the
//!   daemon's cell-index rebuild, which walks every value once at open;
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
//! the record — it never constructs one (private fields), so assembly opens
//! no door beside `stage_write` and M2's replay. Anything that
//! inspects a journaled record reads it through [`ContentWrite::addr`] /
//! [`ContentWrite::val`] and the manual `Debug`, which the engine's
//! `Record: Debug` rests on.

#![forbid(unsafe_code)]

// The opaque payload, `Val`.
mod value;
// The write surface's one typed rejection, `ContentError`.
mod error;
// The `content-addr-guard` routing assertion (Open build decision #4),
// shared by `stage_write` and `write`.
#[cfg(feature = "content-addr-guard")]
mod guard;
// The slice, its fold and point queries, the record and `stage_write`.
// `ContentWrite`'s fields are private to this file, which leaves a record two
// doors — `stage_write`, and serde's `Deserialize` for M2's replay (S0(b)):
// the compiler keeps every other file out; review alone keeps a third door
// out of this one.
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
/// `contains` and `value_at` of — and M6's, M9's and the daemon's reads as
/// `snapshot.world().content()`. M4's library reads no world of its own;
/// only the test-only `write` bounds on this. READ side only; its write-side
/// mirror is the engine's `impl From<ContentWrite> for W::Record` lift,
/// through which the write paths stage deltas via `stg.push(rec.into())`.
pub trait HasContent {
    /// M4's slice of the world state.
    fn content(&self) -> &ContentStore;
}
