//! # skep-retrieval — M6: Content Retrieval & Query
//!
//! M6 is the system's **read-only observer surface over documents**. It owns
//! the seven content/provenance queries — RETRIEVEV [ASN-0115],
//! RETRIEVEDOCVSPAN [ASN-0112], RETRIEVEDOCVSPANSET [ASN-0113], SHOWORIGIN
//! (V-arity) [ASN-0077], SHOWDELETIONS [ASN-0075], COMPARE [ASN-0122],
//! FINDDOCSCONTAINING [ASN-0124] — and turns the authoritative state held
//! below it (M3's registry, M4's content, M5's arrangements and provenance
//! relation R) into delivered values, extents, origins, deletion sets,
//! correspondence reports, and containment answers. Every operation is a
//! **pure function of one consistent M2 snapshot**: it resolves through M5's
//! arrangements, fetches bytes from M4, projects origin via M1, reads R
//! through M5, and gates on M3's registry — and writes nothing, ever.
//!
//! One thing well: *observe documents over a single pinned snapshot —
//! resolve, fetch, project, classify, compose — never mutate.*
//!
//! ## The distinction every operation opens with
//!
//! M3's `is_registered_document` answers one bool, and M6 reads two answers
//! out of it: a REGISTERED-but-empty document is an ordinary success that
//! contributes the operation's empty form (`⟨⟩`, an empty delivery, an empty
//! half), while a NOT-REGISTERED one is that operation's typed
//! `*NotRegistered` failure (W-pre 0112/0113). Registered is the word
//! throughout, and it is narrower than M3's `is_allocated`, which is true of
//! account and element addresses no operation here will accept as a document.
//! Which of the two a given document is belongs to M3; which of the two
//! answers M6 gives back is M6's own, and it is the first thing each of the
//! seven operations decides.
//!
//! ## No state, no fold
//!
//! M6 owns **no authoritative and no derived-authoritative state**: no
//! `WorldState` slice, no journal record, no `apply`/`rebuild_derived` fold,
//! no lock-key space tag. It is a pure consumer of `HasM3 + HasM5` — and of
//! `HasContent` in RETRIEVEV alone, which is the only operation that delivers
//! bytes — generic over `W`, naming no concrete `World`/`Record`, so it
//! trivially satisfies the Engine Composition Contract. Its whole "data
//! model" is the borrowed [`Snapshot`], the returned value types, and
//! per-query transients dropped at return.
//!
//! ## What M6 refuses for size, and what it does not
//!
//! Six of the seven operations cost what their answer costs, or what the
//! documents they name cost, and M6 bounds neither: capping request size,
//! rate and concurrency for a route carrying a read is M10's, as the request
//! lifecycle's owner, and each operation whose cost outruns its answer says so
//! on its own card ([`Query::show_deletions`], [`Query::find_docs_containing`],
//! [`Query::retrieve_v`]).
//!
//! COMPARE is the exception, because its cost is SUPERLINEAR in its request:
//! the join is `|P|·|Q|` over two block lists the caller sizes independently,
//! so a byte cap on the request buys the square of what it bounds and no
//! upstream gate can price it. It therefore carries its own two budgets —
//! [`MAX_COMPARE_OPERAND_BLOCKS`] per operand and [`MAX_COMPARE_PAIRS`] per
//! report, both published so a caller sizes a request against the number
//! rather than transcribing it, and both refusals rather than truncations, so
//! every request COMPARE answers is answered completely.
//!
//! ## SHOWORIGIN's I-arity — de-scoped (ruling)
//!
//! Only the V-arity ships ([`Query::show_origin_v`]). The I-arity needs an
//! I-ordered enumeration of `dom(C)` over an interval, which M4's point-only
//! boundary (range/prefix scans forbidden) and M3's point-only registry
//! deliberately exclude; stateless M6 has no fold hook to grow its own index.
//! The I-arity is a recorded decomposition amendment (a future I-ordered
//! content index), settled by construction: M10 can marshal only what `Query`
//! exposes, and no I-arity method exists (§Conflicts resolved 2).
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * the R relation and its reverse index `docs_ever_containing` (M5 —
//!   co-located with R's authoritative state); content bytes (M4);
//!   arrangements (M5);
//! * authorization / owner resolution (`effective_owner`) — M10's; SHOWORIGIN
//!   reports origin *documents*, not owners;
//! * link-side discovery (M8); the request lifecycle, dispatch, and
//!   marshaling (M10);
//! * any write path — M6 exposes no `transact`/`Kernel` and has no
//!   commit-before-acknowledge obligation for reads.

#![forbid(unsafe_code)]

use std::fmt;

mod compare;
mod error;
mod query;
mod types;
mod vspan;

pub use compare::{MAX_COMPARE_OPERAND_BLOCKS, MAX_COMPARE_PAIRS};
pub use error::{
    CompareError, DeletionsError, ExtentError, FindError, Operand, OriginError, RetrieveError,
    SpanFault,
};
pub use types::{CompareReport, CorrPair, Deletions, Delivery, DeliveryItem, RegionSpec, Spec};

/// `CorrPair`/`CompareReport` carry M5's `VPos`; re-exported so M10's
/// marshaler names it through M6, not by reaching into M5's crate.
pub use skep_arrangement::VPos;

use skep_arrangement::HasM5;
use skep_kernel::{Seq, Snapshot, WorldState};
use skep_namespace::HasM3;

/// The world bound EVERY M6 observation reads under: the registry each one
/// gates on and the arrangements each one resolves through, and no slice of
/// its own (Engine Composition Contract — M6 contributes no slice, no record
/// variant, no accessor trait, no fold).
///
/// M4 is deliberately absent. Six of the seven operations answer from
/// addresses, counts and provenance without ever dereferencing a byte —
/// COMPARE's join is keyed on address equality, the extents are counts,
/// SHOWORIGIN projects, and SHOWDELETIONS and FINDDOCSCONTAINING read R — so a
/// content store is not among their collaborators, and under this bound it is
/// not in their scope either. RETRIEVEV is the one operation that delivers
/// bytes, and it declares `HasContent` on its own impl block, which is where
/// that obligation belongs.
pub trait RetrievalWorld: WorldState + HasM3 + HasM5 {}
impl<W: WorldState + HasM3 + HasM5> RetrievalWorld for W {}

/// Stateless reader over ONE pinned snapshot. Owns nothing; holds a borrow.
///
/// The caller (M10) takes the snapshot (`Kernel::snapshot()`) and constructs
/// the handle over it. The obligation is on the SNAPSHOT, not the handle: take
/// **one `Kernel::snapshot()` per logical query** and route every read of that
/// query through handles bound to it, so all of them observe one consistent
/// `(M, R)` root — the discharge of M2's clause 6 and the single-Σ requirement
/// of ASN-0075/0122/0124. Reads never commit and have no
/// commit-before-acknowledge obligation.
pub struct Query<'s, W: RetrievalWorld>(&'s Snapshot<W>);

impl<'s, W: RetrievalWorld> Query<'s, W> {
    /// Bind one pinned snapshot. No precondition: any `&Snapshot<W>` is
    /// admissible, and the single-Σ obligation is the caller's over the
    /// snapshot it takes (see the type's card), not over how many handles it
    /// builds on one.
    pub fn new(snap: &'s Snapshot<W>) -> Self {
        Query(snap)
    }

    /// The committed index this query reads (V1 retrospective).
    pub fn as_of(&self) -> Seq {
        self.0.seq()
    }
}

/// Renders the pinned coordinate, which is the whole of a `Query`'s
/// observable identity: the snapshot behind it has no `Debug` of its own, and
/// the world it holds is not a thing to print into a log. Hand-written
/// because a derive would demand `W: Debug` on an impl that never touches
/// `W`.
impl<W: RetrievalWorld> fmt::Debug for Query<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Query")
            .field("as_of", &self.as_of())
            .finish_non_exhaustive()
    }
}

/// A `Query` IS a borrow, so it copies like one — a copy reads the SAME
/// pinned `Snapshot`, which is why the single-Σ obligation is stated over the
/// snapshot rather than over the handles built on it. The charter above (no
/// slice, no fold, no state) is what keeps that safe to promise: the day this
/// holds a field of its own, it stops being a borrow and loses `Copy` with it.
///
/// Hand-written because the derives would put `W: Clone`/`W: Copy` on impls
/// that never touch `W`, and no `WorldState` is `Copy`.
impl<W: RetrievalWorld> Clone for Query<'_, W> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<W: RetrievalWorld> Copy for Query<'_, W> {}
