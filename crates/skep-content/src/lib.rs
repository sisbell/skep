//! skep-content — M4: Content Store (Istream).
//!
//! The **permascroll**: an append-only, write-once map from allocated
//! I-address to opaque content value, whose entries are one value or one
//! stretch of consecutive single-byte values written by one insert, plus the
//! two point queries over it — *is content stored here?*
//! ([`ContentStore::contains`]) and *what is stored here?*
//! ([`ContentStore::value_at`]) — the one run read, the pieces of an I-extent
//! ([`ContentStore::pieces`]), and its one enumeration, every entry once
//! ([`ContentStore::iter`]). M4 owns the immutable, never-GC'd half of the
//! strand — ASN-0036's two-component state, the content store and the
//! arrangements — and does exactly that one thing: **store an immutable
//! value at an address forever, and look it up — never mutate, never delete,
//! never reclaim, never key on the value.** Addresses arrive as parameters
//! already minted and validated upstream (M3); M4 trusts them and stores
//! bytes. A read inside a stretch finds the entry just below the address and
//! indexes into its bytes, so every address still answers by itself.
//!
//! Three surfaces (§Public interface):
//!
//! * **Engine plug** (§A) — the slice [`ContentStore`], the two records
//!   [`ContentWrite`] and [`ContentStretch`], the accessor [`HasContent`],
//!   and the two folds [`ContentStore::apply_write`] and
//!   [`ContentStore::apply_stretch`], per the Engine Composition Contract.
//! * **Read API** (§B) — [`ContentStore::contains`] (the
//!   referential-integrity oracle of S3★'s content clause: content-presence,
//!   whether an entry covers the address — not "allocated", not "registered")
//!   and [`ContentStore::value_at`] (`C(a)`), point queries over any slice, a
//!   reader's pinned snapshot or a composite's working slice alike
//!   ([`HasContent`] names both), `value_at` answering a borrowed [`Piece`];
//!   [`ContentStore::pieces`], the one run read — the [`Pieces`] of an
//!   I-extent, each one stored entry clipped to the window; and
//!   [`ContentStore::iter`], the one enumeration — an [`Iter`], the walk
//!   `&ContentStore` yields too — in no promised order, for whole-store work
//!   over a pinned snapshot such as the cell index's walk. The point queries
//!   and the one run read, `pieces`; no prefix read.
//! * **Write surface** (§C) — the pure steps [`stage_write`] (one value)
//!   and [`stage_stretch`] (a run of single-byte values), the storage half of
//!   K.α composed by M5's placement composite, and `write` and
//!   `write_stretch`, the `#[doc(hidden)]` standalone transact-wrapped forms
//!   (M2 contract 3) — compiled only under the `test-hooks` feature.
//!
//! Spec traceability: this crate doc and each public item's doc-comment cite
//! the labels the code realizes (ASN-0036 S0, S1, S4 and S5; ASN-0047 S3★
//! and J0; ASN-0093 C0, C-fin and K.α; and §§ of the M4 design), so a
//! reviewer can walk from code to design without the documents open.
//!
//! ## Invariants
//!
//! **By construction:** S0(a) domain-persistence and S1 store monotonicity
//! (ASN-0093 C0's append-only half; insert-only fold, no removal op); S0(b)
//! value-preservation (no modify op exists, and the fold never replaces a
//! stored value — a record whose address already has a value stored leaves
//! the slice as it was); S4 origin-based identity (keyed by address, never
//! by value — two equal values at two addresses are stored twice; no
//! value→address index); S5 unrestricted sharing (no refcount, no cap —
//! references live in M5); C-fin finiteness; and unconditional no-GC
//! permanence (orphan content persists; M4 does not even know about
//! references). These hold of every slice M4's own operations produce; a
//! world's slice keeps them across its commits and restarts by
//! [`HasContent`]'s implementor obligation.
//!
//! **At the doors:** every key is T4-valid (ASN-0093 StoreT4Validity), at
//! every door, the two decode paths included. Every key a correct caller
//! stages is also a content-subspace element address (C1, L0 — M4's half of
//! SD), checked in debug builds only and admitted as given at decode, so no
//! reader of M4's keys may assume it. [`ContentStore`] names each
//! invariant's gate.
//!
//! **Diagnosed, not relied on:** a second write at one address.
//! [`stage_write`] and [`stage_stretch`] refuse an address already covered
//! in the slice they are handed — a key, or an address inside a stored
//! stretch's reach (`AlreadyStored`), and a stretch whose window holds a
//! stored key (`Overlap`) — so an address minted twice upstream becomes a
//! typed rejection instead of a write a release build's fold drops; their
//! docs say which slice to hand them.
//!
//! ## Boundary — deliberately not owned here
//!
//! * minting or validating addresses (M3; M1's validator) — every key M4
//!   stores is an `Address`, taken as one at the write doors and decoded
//!   through M1's `Address` door wherever a record or a slice is decoded;
//! * arranging, referencing, or routing content, and enforcing referential
//!   integrity (M5 — M4 only *answers* the check, via `contains` and
//!   `pieces`; that S3★'s content clause holds at every committed state, the
//!   strongest timing, is achieved by M2's atomicity around M5's composite,
//!   not by M4);
//! * V→I resolution (M5's reads); origin attribution, version comparison,
//!   and the registered-empty-vs-unregistered distinction (M6);
//! * link values — M7 is the parallel value-only store for `L`; the link
//!   layer (M7/M8) never reads M4 (store-disjointness SD:
//!   `dom(C) ∩ dom(L) = ∅`);
//! * journal, replay, snapshot, recovery (M2) — M2 owns the files, and M4
//!   only its own bytes inside them: [`ContentWrite`] and [`ContentStretch`]
//!   are the authoritative deltas M2 journals, and the slice is their fold,
//!   fully serialized in checkpoints (M2's default `rebuild_derived`
//!   identity), all in this crate's serde form. Those bytes are formats —
//!   read by code no compiler check ties to their form — and what a change
//!   to each owes is said where it is spelled: on the two records, on
//!   `in_tumbler_order` (`store.rs`) for the slice, and on [`Val`];
//! * modify, delete, GC, reclamation, refcounts — none exists, and no
//!   fixed-width counter that could cap or overflow is ever introduced;
//! * author/source/origin metadata — origin (S7) is established by M3's
//!   allocation discipline and computed structurally by M1's `document_of`
//!   (surfaced as SHOWORIGIN in M6); M4 stores only `address → Val`, so no
//!   redundant origin field can diverge;
//! * prefix-scan, max-under-prefix — the reads are the two point queries,
//!   the one run read [`ContentStore::pieces`], the one enumeration,
//!   [`ContentStore::iter`], and the two diagnostics, `len` and `is_empty`;
//!   the point queries and the run read stand on the key order's predecessor
//!   lookup (its field in `store.rs` says what the order is for), and the
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
//! `W: WorldState` (the read accessor), lifts M4's deltas via
//! `impl From<ContentWrite> for W::Record` and `impl From<ContentStretch>
//! for W::Record` (the write-side mirror), and dispatches its
//! `Record::Content` and `Record::ContentStretch` variants into the folds
//! [`ContentStore::apply_write`] and [`ContentStore::apply_stretch`]. The
//! engine only `From`-lifts and folds a record; it never builds one.
//! Anything that inspects a journaled record reads it through
//! [`ContentWrite::addr`] / [`ContentWrite::val`], or
//! [`ContentStretch::addr`] / [`ContentStretch::bytes`] /
//! [`ContentStretch::len`], and its `Debug`, which the engine's
//! `Record: Debug` rests on and which renders a value or a stretch as its
//! length.

#![forbid(unsafe_code)]

// The opaque content value, `Val`.
mod value;
// The write surface's typed rejections, `ContentError`.
mod error;
// The routing assertion (Open build decision #4), shared by the stage doors
// and the standalone ops.
mod routing;
// The slice — its two folds, point queries, one run read (`Pieces`), one
// enumeration (`Iter`) and serialized form — the two records, the borrowed
// `Piece`, and `stage_write`/`stage_stretch`, the records' one producer each
// (the records' fields are private to this file).
mod store;
// `write` and `write_stretch`, the standalone transact-wrapped twins of the
// two stage doors — `test-hooks` builds only.
#[cfg(feature = "test-hooks")]
mod ops;

pub use error::ContentError;
#[cfg(feature = "test-hooks")]
pub use ops::{write, write_stretch};
pub use store::{
    stage_stretch, stage_write, ContentStore, ContentStretch, ContentWrite, Iter, Piece, Pieces,
};
pub use value::Val;

/// The engine's **read accessor** for M4's slice (§A).
///
/// Per the Engine Composition Contract, the engine implements it for its
/// concrete world, and every reader of M4 outside the engine reaches the
/// permascroll through it: M5's composites as `stg.working().content()` —
/// the slice they hand [`stage_write`] and [`stage_stretch`], and ask
/// `contains` and `pieces` of — and every reader of a snapshot as
/// `snapshot.world().content()`; the engine's own code reads the field
/// `content()` returns. M4's library reads no world of its own; only the
/// test-only `write` and `write_stretch` bound on this. Read side only; its
/// write-side mirror is the engine's `impl From<ContentWrite> for W::Record`
/// and `impl From<ContentStretch> for W::Record` lifts, through which the
/// write paths stage deltas via `stg.push(rec.into())`.
///
/// **Implementors owe** one fact the signature cannot carry: `content()` is
/// the very slice the world's `WorldState::apply` folds this crate's records
/// into, through the two folds [`ContentStore::apply_write`] and
/// [`ContentStore::apply_stretch`], once per record — and those folds are
/// the only things that move it. Every other record's fold carries the slice
/// through unchanged; a checkpoint carries it through this crate's own serde
/// form, neither skipped nor defaulted; and `rebuild_derived` hands it back
/// as it was decoded. Three promises rest on it: the two stage doors'
/// already-stored checks see only the slice they are handed, so they refuse
/// what a release build's folds would drop only when
/// `stg.working().content()` is that slice; a value stored in one `content()`
/// is in every later one, unchanged (S0) — the folds keep that only for a
/// slice nothing else replaces, and M5's publish shot `assert!`s it of the
/// working slice; and a reader's `snapshot.world().content()` holds a value
/// for every arranged content position the snapshot resolves, which M6's
/// RETRIEVEV `assert!`s (S3★). An implementor that answered any other
/// `ContentStore`, or moved this one by any other path, would void all three,
/// and nothing in this crate can check it.
pub trait HasContent {
    /// Returns M4's slice of the world state.
    fn content(&self) -> &ContentStore;
}

/// The auto traits M4's types promise without saying.
///
/// `WorldState` is `Send + Sync + 'static`, so the engine's
/// `impl WorldState for World` owes those bounds of [`ContentStore`], a field
/// of its `World`, and of [`ContentWrite`] and [`ContentStretch`], the
/// records its `Record::Content` and `Record::ContentStretch` carry, through
/// types no signature in this crate mentions; [`Val`] rides M10's `Request`
/// across the daemon's workers; and [`ContentError`] travels inside M5's
/// `InsertError` and `PublishError`. They are kept by what the private
/// fields contain — the `im` map, the `Arc` under each of its keys, under
/// `Val` and under a stretch's bytes — and, for `ContentError`, by the
/// tumblers its variants carry, so a field that revoked one (the
/// `Rc`-backed `im-rc` for `im`, an `Rc` under a key or under `Val`) would,
/// but for this assertion, compile here and fail a crate away, never naming
/// the field. Asserted in the library rather than the suite, because that is
/// the build a manifest change is made in, and it is this crate's manifest
/// that names `im`.
const _: fn() = || {
    fn owed<T: Send + Sync + 'static>() {}
    owed::<ContentStore>(); // the `WorldState` bound reaches this through the engine
    owed::<ContentWrite>(); // and this through `WorldState::Record`
    owed::<ContentStretch>(); // the second record, through the same bound
    owed::<Val>();
    // The rejection too: a caller that boxes one meets
    // `Box<dyn Error + Send + Sync>`, which is the crossing form.
    owed::<ContentError>();
};
