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
//! `*NotRegistered` failure (ASN-0113's W-pre; ASN-0112's precondition, the
//! `dom(M)` of V0). Registered is the word throughout, and it is narrower
//! than M3's `is_allocated`, which is true of account and element addresses
//! no operation here will accept as a document.
//! Which of the two a given document is belongs to M3; which of the two
//! answers M6 gives back is M6's own, and it is the first thing each of the
//! seven operations decides.
//!
//! SHOWORIGIN is the one exception, and it is the specification's: an
//! occupied subspace is WF_V(iii)'s own precondition, so the V-arity has no
//! empty form to contribute and answers a registered-empty document with
//! `EmptySubspace` — an inadmissible request, never an empty success. The
//! other six contribute `⟨⟩`, an empty delivery, empty halves, an empty
//! report or `[]`.
//!
//! ## Which arrangement an operation answers from
//!
//! An operation gates on the address the caller NAMED, and only then asks
//! which arrangement to read: M5's `reading_surface` of that address
//! (head-float — PUB-2.49, PUB-2.50, PUB-2.53). A version address answers
//! its own member, forever; a bare PUBLISHED address answers its trunk head,
//! and its own arrangement while it has no member yet; a private document
//! answers its own. The gate is what discharges `reading_surface`'s stated
//! contract (PUB-6.37: it is asked of registered documents alone), and the
//! answer is reported under the name the caller gave. The float is decided
//! in M5, in that one function; M6 re-derives nothing about trunks, heads or
//! publication — it asks, and reads the arrangement it is told.
//!
//! Five operations float: RETRIEVEV, both extent queries, SHOWORIGIN, and
//! COMPARE, whose feet still NAME the address asked about while the positions
//! they carry are the surface's. Two do not: SHOWDELETIONS and
//! FINDDOCSCONTAINING read R and the arrangement of the address named. So a
//! bare published address with a head answers RETRIEVEV from the head and
//! FINDDOCSCONTAINING from itself — the seam the PUB lane's report records,
//! and one each card states on its own side.
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
//! Five of the seven operations cost what their answer costs, or what the
//! documents they name cost, and M6 bounds neither: capping request size,
//! rate and concurrency for a route carrying a read is M10's, as the request
//! lifecycle's owner. Two of the five say so on their own cards, and they are
//! different cases: the one operation whose cost OUTRUNS its answer —
//! `|R↾d| log |R↾d|` paid in full to return two empty halves — is
//! [`Query::show_deletions`], and the one whose answer is itself a PRODUCT of
//! the request the operation may not narrow is [`Query::retrieve_v`].
//!
//! Two carry budgets of their own, each for a factor no upstream gate can
//! price. COMPARE's cost is SUPERLINEAR in its request — the join is `|P|·|Q|`
//! over two block lists the caller sizes independently, so a byte cap on the
//! request buys the square of what it bounds — and it carries
//! [`MAX_COMPARE_OPERAND_BLOCKS`] per operand and [`MAX_COMPARE_PAIRS`] per
//! report. FINDDOCSCONTAINING's request is the multiplier on two world-sized
//! scans, and the request-to-coverage step EXPANDS: a region set nests two
//! wire caps whose product only a body cap bounds, and one span over a
//! fragmented document resolves to many coverage spans from a single span on
//! the wire — so it carries [`MAX_FIND_COVERAGE_SPANS`]. Each operand-side
//! budget is counted twice, on the spans handed to M5 and on what they
//! produce; [`MAX_COMPARE_OPERAND_BLOCKS`]'s card says why.
//!
//! All three are published, so a caller sizes a request against the number
//! rather than transcribing it, and all three are refusals rather than
//! truncations, so every request either operation answers is answered
//! completely. What no number here bounds is the WORLD's own size — `|R|`, a
//! candidate's fragmentation, the provenance record behind a two-address
//! SHOWDELETIONS — which stays with rate and concurrency, M10's.
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
//! * authorization / owner resolution (`effective_owner`) — M10's. M6
//!   DECIDES no readability and APPLIES one: the predicate M10 threads into
//!   [`Query::retrieve_v_masked`] (per run, against the run's origin, withheld
//!   at the run's own position) and [`Query::find_docs_containing_filtered`]
//!   (per container, at its identity, dropped). The named documents' own
//!   readability is M10's pre-dispatch consult. The other five take no
//!   predicate and answer WHOLE for readable arguments (PUB-6.15) — the
//!   extents COUNT the positions a masked-origin run occupies and are never
//!   shrunk to the deliverable ones (PUB-6.41); SHOWORIGIN's origins,
//!   SHOWDELETIONS' halves and COMPARE's feet come back whole, material
//!   originating in an unreadable document INCLUDED — by the specification's
//!   decision, not by omission. SHOWORIGIN reports origin *documents*, not
//!   owners;
//! * link-side discovery (M8); the request lifecycle, dispatch, and
//!   marshaling (M10);
//! * any write path — M6 exposes no `transact`/`Kernel` and has no
//!   commit-before-acknowledge obligation for reads.
//!
//! [`Snapshot`]: skep_kernel::Snapshot

#![forbid(unsafe_code)]

// The modules, in dependency order, each with a line saying what it holds.
// Each names, in code, only modules above it, and an item by its home module
// rather than through the re-exports below; `tests/it/tidy.rs` checks all of
// it.

// The three request budgets and their argument: COMPARE's operand and pair
// budgets, FINDDOCSCONTAINING's coverage budget.
mod budget;
// The typed rejections, one enum per operation, and the two fault
// vocabularies they carry.
mod error;
// The request and result values every operation takes and returns.
mod types;
// How M6 reads one request V-span: `Subspace` and the span gate.
mod vspan;
// `Query` and what its operations share; one file per operation beneath.
mod query;

pub use budget::{MAX_COMPARE_OPERAND_BLOCKS, MAX_COMPARE_PAIRS, MAX_FIND_COVERAGE_SPANS};
pub use error::{
    CompareError, DeletionsError, ExtentError, FindError, Operand, OriginError, RetrieveError,
    SpanFault,
};
pub use query::{Query, RetrievalWorld};
pub use types::{CompareReport, CorrPair, Deletions, Delivery, DeliveryItem, RegionSpec, Spec};
