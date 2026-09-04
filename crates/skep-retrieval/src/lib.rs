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
//! half), while an UNALLOCATED one is that operation's typed `*NotRegistered`
//! failure (W-pre 0112/0113). Which of the two a given document is belongs to
//! M3; which of the two answers M6 gives back is M6's own, and it is the first
//! thing each of the seven operations decides.
//!
//! ## No state, no fold
//!
//! M6 owns **no authoritative and no derived-authoritative state**: no
//! `WorldState` slice, no journal record, no `apply`/`rebuild_derived` fold,
//! no lock-key space tag. It is a pure consumer of `HasM3 + HasContent +
//! HasM5`, generic over `W`, naming no concrete `World`/`Record` — so it
//! trivially satisfies the Engine Composition Contract. Its whole "data
//! model" is the borrowed [`Snapshot`], the returned value types, and
//! per-query transients dropped at return.
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

mod compare;
mod error;
mod helpers;
mod query;
mod types;

pub use error::{
    CompareError, DeletionsError, ExtentError, FindError, Operand, OriginError, RetrieveError,
    SpecFault,
};
pub use types::{CompareReport, CorrPair, Deletions, Delivery, DeliveryItem, Region, Spec};

/// `CorrPair`/`CompareReport` carry M5's `VPos`; re-exported so M10's
/// marshaler names it through M6, not by reaching into M5's crate.
pub use skep_arrangement::VPos;

use skep_arrangement::HasM5;
use skep_content::HasContent;
use skep_kernel::{Seq, Snapshot, WorldState};
use skep_namespace::HasM3;

/// The world bound M6 reads under: three upstream slices, none of its own
/// (Engine Composition Contract — M6 contributes no slice, no record variant,
/// no accessor trait, no fold).
pub trait M6World: WorldState + HasM3 + HasContent + HasM5 {}
impl<W: WorldState + HasM3 + HasContent + HasM5> M6World for W {}

/// Stateless reader over ONE pinned snapshot. Owns nothing; holds a borrow.
///
/// The caller (M10) takes the snapshot (`Kernel::snapshot()`) and constructs
/// the handle, one per logical query, so every read in that query observes
/// one consistent `(M, R)` root — the discharge of M2's clause 6 and the
/// single-Σ requirement of ASN-0075/0122/0124. Reads never commit and have no
/// commit-before-acknowledge obligation.
pub struct Query<'s, W: M6World>(&'s Snapshot<W>);

impl<'s, W: M6World> Query<'s, W> {
    /// Bind one pinned snapshot. Build **one `Query` per logical query**.
    pub fn new(snap: &'s Snapshot<W>) -> Self {
        Query(snap)
    }

    /// The committed index this query reads (V1 retrospective).
    pub fn as_of(&self) -> Seq {
        self.0.seq()
    }
}
