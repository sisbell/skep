//! §§A–C, D (SHOWDELETIONS), E — six of the seven operations (COMPARE lives
//! in `compare`). Every operation begins by reading its slices off the single
//! pinned snapshot, runs its gate (typed rejection), then composes upstream
//! primitives. Which arrangement it then reads — the named address's reading
//! surface, or the named address's own — is the crate doc's *Which
//! arrangement an operation answers from*, and each card here says which.

use num_traits::{One, Zero};
use skep_address::{document_of, Address, Nat, Span, SpanSet};
use skep_arrangement::{as_ordinal_vspan, ordinal_vspan, reading_surface, M5State, Run, VPos};
use skep_content::HasContent;

use crate::error::{DeletionsError, ExtentError, FindError, OriginError, RetrieveError};
use crate::types::{Deletions, Delivery, DeliveryItem, RegionSpec, Spec};
use crate::vspan::{gate_vspan, Subspace};
use crate::{Query, RetrievalWorld, MAX_COMPARE_OPERAND_BLOCKS};

/// The most I-coverage spans one FINDDOCSCONTAINING request may resolve to,
/// and the most spans it may hand to M5 — one budget on the request's
/// resolution, counted on the spans handed and on the coverage they produce
/// — and so the ceiling on the multiplier the REQUEST applies to the two
/// world-sized scans behind it.
///
/// ONE join-side budget, not a second. `docs_ever_containing` joins this
/// coverage against the whole of R, and `project` runs it against each
/// candidate's runs, so the coverage is one side of a join exactly as a
/// COMPARE operand is — and it takes that operand's budget BY DEFINITION,
/// counted the same two ways (the spans handed to M5's `image`, and the
/// coverage they produce) and priced on [`MAX_COMPARE_OPERAND_BLOCKS`]'s
/// card, which also says why the count is two, what each count refuses, and
/// what neither bounds within one span. Pricing the two apart is a
/// deliberate edit of this line, never a drift between two literals.
///
/// WHAT IT DOES NOT BOUND, and neither could any number here: `|R|` and
/// `#runs(d)` are the WORLD's, not the request's, so they stay with rate and
/// concurrency — M10's, exactly as [`Query::show_deletions`]' `|R↾d|` term
/// already is. This bounds the coverage the request materializes, and the
/// factor the request multiplies those scans by; it does not bound the scans.
pub const MAX_FIND_COVERAGE_SPANS: usize = MAX_COMPARE_OPERAND_BLOCKS;

/// `ext(d, S) = ([S, 1], [0, n_S])` — the per-subspace exact extent span
/// (ASN-0113 W2/W4: a count fixes an extent under sequential positions), or
/// `None` for an unoccupied subspace (`n_S = 0`), which has no extent — so
/// nothing in [`Query::doc_vspanset`]'s answer, which is `⟨⟩` when both
/// subspaces are unoccupied. The anchor `[S, 1]` — ASN-0113's `start_S` — is
/// written ONCE, here, never absorbed into a confluent summary, which is how
/// the hazard ASN-0112 OQ5 records against its bounding-span start `origin_d`
/// (a POSITION, not ASN-0077's origin) is designed out.
///
/// Built with M5's `ordinal_vspan`, so the extent M6 REPORTS is the shape M5's
/// `resolve` READS: the constructor and the recognizer every request span is
/// folded through are the two halves of one definition and cannot come apart
/// — and the unoccupied case is that constructor's own `None`, not a
/// precondition this function asks its caller to keep.
///
/// The subspace arrives CLASSIFIED rather than as a numeral, so the two
/// arguments have different types and `ext_span(count, subspace)` fails to
/// compile — the hazard M5 designs out of `ordinal_vspan` by taking a `VPos`,
/// since a swap here builds a well-formed span naming a subspace that selects
/// nothing and reports as emptiness far downstream.
fn ext_span(s: Subspace, n: &Nat) -> Option<Span> {
    ordinal_vspan(
        &VPos {
            subspace: s.numeral().clone(),
            ordinal: Nat::one(),
        },
        n,
    )
}

/// The enumeration of `CURRENT(·, d)` (ASN-0075's predicate; ASN-0124 calls
/// the set `ran_C(d)`) — every content I-address `d`'s arrangement currently
/// binds, in V order. M5's own `content_image` is the same set and is private,
/// so it is NOT called here.
///
/// Walking the CONTENT runs is not a narrowing of `CURRENT` but its whole
/// extent: ASN-0075 defines the predicate over `a ∈ dom(C)`, so
/// `{a : CURRENT(a, d)} = ran(M(d)) ∩ dom(C) = ran_C(d)` and no link run is
/// skipped — there is none to skip (D-SUBSP).
///
/// `CURRENT` is a set and this is an enumeration WITH MULTIPLICITY: an
/// address placed at two V-positions of `d` by intra-document transclusion is
/// yielded twice, so callers dedup.
///
/// LAZY, and that is the point rather than a style: `d`'s arrangement binds
/// one content position per byte the document was written with, and each
/// position enumerated is an OWNED `Address` — a `Vec<Nat>` of element
/// components, order hundreds of bytes and a handful of allocations. Handing
/// back a `Vec` would make the peak live heap of a two-document combine the
/// size of both documents, from a request naming two addresses and nothing
/// else; streaming makes it the size of the part the caller's filter keeps.
/// Each run's positions are enumerated by the run that owns them —
/// `Run::addrs`, over M5's lent run-list, so no run is cloned to be walked and
/// the stream holds one cursor into the snapshot's arrangement.
///
/// Enumerating the content runs alone therefore loses nothing AND needs no
/// filter behind it: `DELETED(a, d)` requires `(a, d) ∈ R`, and R is appended
/// only where content is placed — seating a link records nothing in it — so a
/// link position enumerated here could only be filtered away again.
fn current_content<'a>(m5: &'a M5State, d: &Address) -> impl Iterator<Item = Address> + 'a {
    m5.content_runs(d).flat_map(Run::addrs)
}

/// The ORIGIN of a run — the document that allocated its I-start, which by
/// block uniformity (ASN-0077 O2) is the origin of every position in it, so
/// one projection answers for the whole run. Asked of M1's `document_of`; the
/// `expect` is the one place M6 states that an element-level I-address has a
/// Document prefix. A link run's origin is its home document (CL-OWN), with
/// no special case.
fn run_origin(run: &Run) -> Address {
    document_of(run.i_start()).expect("an element-level I-address has a Document prefix")
}

/// A stream of addresses as the deduplicated, T1-SORTED set it denotes. Both
/// the dedup and the sort are published guarantees, not conveniences:
/// [`Query::show_origin_v`] answers "deduplicated origin documents in tumbler
/// order" and each half of [`Query::show_deletions`]' answer is a
/// deduplicated, T1-ascending listing, and this is the one place either is
/// established.
///
/// THE TWO GUARANTEES STAND ON DIFFERENT AUTHORITIES, and only one of them is
/// the corpus's. The DEDUP is the comprehension's: ASN-0075's
/// `DeletedFromAWithB` is `{a ∈ dom(C) : …}`, a set, and SHOWORIGIN_V's answer
/// is a set of origin documents. The ORDERING is M6's own presentation of that
/// set — D-ORD licenses it (each output half is a finite subset of
/// `dom(C) ⊆ T`, so T1-orderability is a property of the output addresses) and
/// does not require it (the operation "carries no ordering of its own"), which
/// is why fixing one is M6's to do and to state.
///
/// Identity and order are both `Address`'s own — its `Eq` is tumbler equality
/// (the level is a function of the tumbler) and its `Ord` IS the T1 tumbler
/// order — so sorting and deduplicating is exactly dedup-by-tumbler, with no
/// `.tumbler()` detour and no key clone.
///
/// Used for origin DOCUMENTS (SHOWORIGIN_V) and content I-ADDRESSES
/// (SHOWDELETIONS) alike — both are `Address`, so one neutral helper serves
/// either (the name says "addr", not "doc", because what the SHOWDELETIONS
/// site dedups is content addresses, not documents).
fn sorted_addr_set(it: impl IntoIterator<Item = Address>) -> Vec<Address> {
    let mut out: Vec<Address> = it.into_iter().collect();
    out.sort_unstable(); // T1 order; the dedup below makes stability unobservable
    out.dedup();
    out
}

/// D-SEQ★ defense-in-depth for the extent queries (open build decision,
/// documented default: trust `content_count`/`link_count` in release, assert
/// in debug).
///
/// D-SEQ★ (PerSubspaceSequentialPositions, ASN-0047) is the invariant the
/// counts stand on: an occupied subspace's V-positions are exactly the dense
/// prefix anchored at `[S, 1]`, `V_S(d) = {[S, k] : 1 ≤ k ≤ n_S}` — which is
/// what ASN-0113 W4 forces, and which ASN-0047 derives from contiguity D-CTG★
/// plus minimum-position D-MIN★. Its two ingredients are what the two assertions
/// check: each subspace's run widths sum to its count (density — a hole would
/// make the count over-report the extent), and an occupied subspace anchors
/// at ordinal 1 (D-MIN★ itself; ASN-0112 V8 origin permanence, append-only
/// link seating). The whole body is compiled out of release builds, which
/// read the counts directly.
fn debug_assert_sequential_positions(m5: &M5State, doc: &Address) {
    if cfg!(debug_assertions) {
        for sub in [Subspace::Content, Subspace::Link] {
            // Each subspace asks M5 for its OWN count and runs, so the two
            // reads compared below cannot be paired across subspaces.
            let (count, runs) = (sub.count(m5, doc), sub.runs(m5, doc));
            let width_sum: Nat = runs.map(Run::width).sum();
            debug_assert!(
                width_sum == count,
                "D-SEQ★: a subspace's run widths must sum to its count"
            );
            debug_assert!(
                count.is_zero()
                    || m5
                        .point(
                            doc,
                            &VPos {
                                subspace: sub.numeral().clone(),
                                ordinal: Nat::one(),
                            },
                        )
                        .is_some(),
                "D-MIN★: an occupied subspace must anchor at ordinal 1"
            );
        }
    }
}

/// RETRIEVEV alone opens M4, so RETRIEVEV alone names it: `HasContent` is
/// this impl block's bound and nowhere else's, which is what makes the other
/// six operations' value-blindness structural rather than a rule their cards
/// ask a maintainer to keep.
impl<W: RetrievalWorld + HasContent> Query<'_, W> {
    /// RETRIEVEV (ASN-0115) — resolve, then dereference, in order (the
    /// load-bearing two-phase factoring): resolve V-spans to I-addresses
    /// (M5), then fetch values (M4, content) or pass the address through
    /// (links — never reads M4).
    ///
    /// The arrangement resolved is each named document's READING SURFACE
    /// (crate doc, *Which arrangement an operation answers from*): the gate
    /// runs on the address named, the surface answers, and the delivery is
    /// reported under the name given.
    ///
    /// Rejects the WHOLE request on any malformed spec (well-formedness
    /// precondition); gaps / depth-incompatible (`#start ≥ 3`) / foreign or
    /// empty subspaces degrade to silent empty contributions, never an error
    /// (R6 — M5's defensive `resolve` returns fewer-or-zero runs). Empty
    /// spec-set ⇒ `Ok(empty)`. Delivery is one item per active V-position of
    /// every DELIVERED run (R3 exactness, R8 no-dedup) — and one
    /// [`DeliveryItem::Withheld`] per run whose origin is not a registered
    /// document, occupying that run's `width` positions (PUB-1.57): the one
    /// masking the identity predicate leaves, since the predicate is
    /// contracted to registered documents (PUB-6.37) and RES-162's unheld
    /// origin — a mirror that never held the draft a published window names —
    /// is a run this form can meet. Per-spec concatenation in submitted order
    /// (R5), ascending-V within, no merge, no global sort.
    ///
    /// WHICH REFUSAL SPEAKS. The gate walks the spec-set in SUBMITTED ORDER
    /// and reports the FIRST faulty spec, whatever the kind of its fault;
    /// within one spec the registry check precedes the span gate. So
    /// `MalformedSpec { index: i }` and `DocNotRegistered` both carry a
    /// promise about the specs before the offending one: a caller may rely on
    /// specs `0..i` being registered documents with well-formed spans, and
    /// repair a batch by walking forward rather than re-checking it whole.
    ///
    /// COST IS THE ANSWER'S SIZE, AND THE ANSWER'S SIZE IS A PRODUCT M6 MAY
    /// NOT NARROW. The delivery is `Σᵢ |σᵢ ∩ [1, n_Sᵢ]|` items, so `k` specs
    /// each naming a whole document deliver `k · n_C` items — one `Arc` clone
    /// per item, never a byte copy, but one item nonetheless — and `k` is the
    /// caller's. R3 forbids delivering fewer, R5 forbids reordering into
    /// something cheaper and R8 forbids collapsing the repeats, so no refusal
    /// M6 could add here would leave RETRIEVEV the operation ASN-0115
    /// specifies. The only cap that closes it is a spec-count or response-size
    /// cap on the route, which is M10's as the request lifecycle's owner.
    pub fn retrieve_v(&self, specs: &[Spec]) -> Result<Delivery, RetrieveError> {
        // The masked form under the all-true predicate: its only `Withheld`
        // items are unregistered-origin runs (PUB-6.37; RES-162). The daemon's
        // read surface calls [`Query::retrieve_v_masked`] with its per-request
        // predicate; this delegate serves the principal-free callers (the
        // engine's own lifecycle read, the suites) unchanged.
        self.retrieve_v_masked(specs, &|_| true)
    }

    /// RETRIEVEV with the source consult (PUB round 2, lane 3.3, §2/§4): the
    /// same delivery, but each RUN is tested per PUB-6.41 against its origin
    /// DOCUMENT (M1's `document_of` of the run's I-start, which block
    /// uniformity makes the origin of every position in it) through
    /// `readable`, and a masked run — its origin unreadable to the reading
    /// principal, OR unregistered — is emitted as [`DeliveryItem::Withheld`]
    /// AT ITS OWN POSITION rather than delivered (PUB-6.58: one item per run,
    /// never coalesced). The NAMED document's own readability is the caller's
    /// doc-argument consult (PUB-6.12), run pre-dispatch; this masks only the
    /// ORIGINS its runs window. M6 decides no readability here — it applies
    /// the predicate M10 threads in, at the run, which is the granularity the
    /// delivery has.
    ///
    /// THE PREDICATE'S OWN PRECONDITION IS DISCHARGED HERE. `readable` is
    /// contracted to REGISTERED documents (PUB-6.37, the rule
    /// `reading_surface` is under too), and the gate established that of the
    /// documents NAMED, not of the origins their runs window; so each origin
    /// is checked against the registry before the predicate is asked, and one
    /// that is not a registered document — reachable as RES-162's unheld
    /// origin, the mirror that never held the draft a published window names
    /// — takes the withheld arm directly, the predicate unconsulted. The
    /// predicate is consulted only after the gate has passed the whole
    /// request (a rejected request consults it of nothing), once per resolved
    /// run with a registered origin, of the origin document alone — which may
    /// be a version address — and never of the document named.
    pub fn retrieve_v_masked(
        &self,
        specs: &[Spec],
        readable: &dyn Fn(&Address) -> bool,
    ) -> Result<Delivery, RetrieveError> {
        let w = self.0.world();
        let (m3, m5, content) = (w.m3(), w.m5(), w.content());
        // Gate the whole request first — VSpec WELL-FORMEDNESS is the only
        // in-model failure (ASN-0115). A well-formed but depth-incompatible
        // (#start ≥ 3) spec is NOT rejected here (R6).
        for (index, spec) in specs.iter().enumerate() {
            if !m3.is_registered_document(&spec.doc) {
                return Err(RetrieveError::DocNotRegistered(spec.doc.clone()));
            }
            gate_vspan(&spec.span)
                .map_err(|fault| RetrieveError::MalformedSpec { index, fault })?;
        }
        let mut out = Vec::new();
        for spec in specs {
            // Concatenate per spec, IN ORDER (R5) — no global sort. Classify
            // ONCE per spec, because the answer is constant over the spec's
            // positions. Gated on the address named above; the surface
            // answers.
            let sub = Subspace::of_span(&spec.span);
            let surface = reading_surface(m3, &spec.doc);
            for run in m5.resolve(&surface, &spec.span) {
                // The per-run source consult (PUB-6.41): the run's origin
                // DOCUMENT, tested BEFORE the run is expanded. The registry
                // check first is the predicate's precondition (PUB-6.37:
                // registered documents only), M6's to discharge at this site
                // because the gate saw the named document and not the origin;
                // an unregistered origin (RES-162) is withheld without the
                // predicate being asked. Either way the WHOLE run is masked as
                // one withheld item at its own position — never coalesced with
                // a neighbour (PUB-6.58).
                let origin = run_origin(&run);
                if !m3.is_registered_document(&origin) || !readable(&origin) {
                    out.push(DeliveryItem::Withheld { origin, width: run.width().clone() });
                    continue;
                }
                // Per active position, ascending V (R3) — no dedup (R8); the
                // run answers for its own positions, in the owned form, since
                // `resolve` hands the run over and it outlives only this walk.
                for a in run.into_addrs() {
                    match sub {
                        // S3★ — an arranged content position has an M4 value
                        // — is kept on M5's WRITE path, and this read is
                        // where a regression in it would surface. The two
                        // sites that keep it: `insert` rides mint, write and
                        // place in one transaction, and `copy` places only
                        // runs its `SourceNotContentSubspace` (no link
                        // address at a content position) and per-run
                        // `DanglingSource` (M4 holds the run's start) guards
                        // admit. Widening either is what would put an
                        // address here that M4 never stored.
                        Some(Subspace::Content) => out.push(DeliveryItem::Content(
                            content
                                .value_at(a.tumbler())
                                .expect("S3★: an arranged content position has a stored value")
                                .clone(),
                        )),
                        // The link reference IS the address — never reads M4.
                        Some(Subspace::Link) => out.push(DeliveryItem::Ref(a)),
                        // UNREACHABLE for an ACTIVE position: S3★-aux
                        // confines every bound V-position to subspace ∈
                        // {s_C, s_L}, and `resolve` yields NO runs for any
                        // other start subspace, so executing here means
                        // upstream corruption. PANIC IN ALL PROFILES — one
                        // read-path policy with the S3★ `expect` above:
                        // silently dropping an active position would violate
                        // exactness (R3).
                        None => unreachable!(
                            "active V-position must be content or link subspace (S3★-aux)"
                        ),
                    }
                }
            }
        }
        Ok(Delivery(out)) // empty spec-set ⇒ Ok(Delivery(vec![]))
    }
}

impl<W: RetrievalWorld> Query<'_, W> {
    /// RETRIEVEDOCVSPAN (ASN-0112) — the whole-document bounding span:
    /// singleton `⟨σ_d⟩`, or `⟨⟩` for a registered-empty document; a document
    /// that is not registered ⇒ Err. Across subspaces it is a bounding box
    /// bridging the inter-subspace void.
    ///
    /// Answers from `doc`'s READING SURFACE (crate doc, *Which arrangement an
    /// operation answers from*), because it is the hull of
    /// [`Query::doc_vspanset`]'s answer and that is the arrangement the
    /// extents are read from; the gate runs on the address named.
    ///
    /// WHAT THE BOX CANNOT SHOW (V9). Being a function of the two EXTREMES
    /// alone, the cross-subspace box is fixed at `[[s_C, 1], [s_L, n_L + 1])`
    /// under any content edit that leaves `n_C ≥ 1`, while
    /// [`Query::doc_vspanset`]'s content extent moves with `n_C` — so a caller
    /// that must observe a CONTENT-COUNT change asks for the extents, not the
    /// box. Neither reports run structure: under D-SEQ★ both are functions of
    /// `n_C` and `n_L` alone, and a document's fragmentation is M5's
    /// `content_runs`, which is not part of M6's surface.
    ///
    /// σ_d IS the hull of the per-subspace extents [`Query::doc_vspanset`]
    /// reports: the first extent's start to the last extent's reach.
    pub fn doc_vspan(&self, doc: &Address) -> Result<SpanSet, ExtentError> {
        // Taken from `doc_vspanset` rather than derived a second time, so the
        // registry gate, the D-SEQ★ trust and the count-read all happen once,
        // in one place. Those extents are W13-normalized, so the FIRST
        // extent's start is the anchor `[s, 1]` of the lowest occupied
        // subspace and the LAST extent's reach is one ordinal step past the
        // highest occupied position.
        let extents = self.doc_vspanset(doc)?;
        let (Some(first), Some(last)) = (extents.iter().next(), extents.iter().next_back()) else {
            return Ok(SpanSet::empty()); // registered-empty ⇒ ⟨⟩
        };
        // `from_endpoints` is INFALLIBLE on that pair: both endpoints are
        // depth-2 (no `LevelMismatch`) and `first.start ≤ last.start <
        // last.reach` (no `NotIncreasing`); the stored width `reach ⊖ start`
        // round-trips exactly — `divergence(start, reach) ≤ #start` discharges
        // D1, INCLUDING the cross-subspace box — so the singleton is faithfully
        // ASN-0112's `σ_d = (origin_d, extent_d)`.
        Ok(SpanSet::singleton(
            Span::from_endpoints(first.start().clone(), &last.reach())
                .expect("first.start < last.reach at one depth-2 length"),
        ))
    }

    /// RETRIEVEDOCVSPANSET (ASN-0113) — the per-subspace exact extents, one
    /// per occupied subspace (content, then link), already W13-normalized;
    /// `⟨⟩` for a registered-empty document; a document that is not registered
    /// ⇒ Err.
    ///
    /// The extents are the READING SURFACE's (crate doc, *Which arrangement an
    /// operation answers from*): a bare published address with a head reports
    /// the head's counts, a version address its own member's, and a published
    /// address whose own arrangement is empty reports `⟨⟩` only while it has
    /// no head. The registry gate runs on the address named.
    ///
    /// No predicate is threaded and none belongs: the extents COUNT the
    /// positions a masked-origin run occupies and are never shrunk to the
    /// deliverable ones (PUB-6.15, PUB-6.41); [`Query::doc_vspan`] inherits
    /// this as the hull.
    ///
    /// The count-read core of both extent queries: exact because each
    /// subspace's occupied V-positions form the dense run anchored at
    /// `[S, 1]`, `[S, 1..n_S]` (D-SEQ★ — the sequential-position occupancy
    /// ASN-0113 W4 forces; M5's write-path property, trusted here and
    /// tripwired in debug), so M5's O(1) counts ARE the extents.
    pub fn doc_vspanset(&self, doc: &Address) -> Result<SpanSet, ExtentError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !m3.is_registered_document(doc) {
            return Err(ExtentError::DocNotRegistered); // not registered ⇒ fail
        }
        // Gated on the address named; the surface answers.
        let surface = reading_surface(m3, doc);
        debug_assert_sequential_positions(m5, &surface);
        // Each subspace asks M5 for its OWN count inside the one closure that
        // hands it to `ext_span` classified rather than as a numeral — so no
        // site pairs a subspace with another's count by hand,
        // `ext_span(count, subspace)` does not compile, and an unoccupied
        // subspace is `ext_span`'s own `None`. The occupied ones are
        // `collect`ed through M1's `FromIterator<Span>`, which collects AS
        // GIVEN — preserving the already-disjoint, content-before-link normal
        // form asserted below; no invented M1 constructor.
        let extents: SpanSet = [Subspace::Content, Subspace::Link]
            .into_iter()
            .filter_map(|s| ext_span(s, &s.count(m5, &surface)))
            .collect();
        debug_assert!(
            extents.is_normalized(),
            "W13: content-before-link, subspace-separated ⇒ already normal"
        );
        Ok(extents)
    }

    /// SHOWORIGIN over a V-span (ASN-0077, V-arity) — block-decompose, then
    /// project ONE origin per run (M1's `document_of` of each run's I-start):
    /// block uniformity (O2) means all addresses in one run share an origin,
    /// so this is O(runs), not O(positions). Returns
    /// deduplicated origin documents in tumbler order; for the link subspace
    /// the origin is the home document (CL-OWN) — handled uniformly, no
    /// special case. The I-arity is de-scoped (see the crate docs); only this
    /// V-arity exists.
    ///
    /// Projects over `doc`'s READING SURFACE (crate doc, *Which arrangement an
    /// operation answers from*): the gate and the span checks below run on
    /// the address named, and the surface's runs are the ones whose origins
    /// are reported.
    ///
    /// UNFILTERED (PUB-6.15): the origins come back whole for a readable
    /// argument, an unreadable origin's identity included; no predicate is
    /// threaded, the argument's consult being M10's pre-dispatch.
    ///
    /// A success is never empty: an admissible request has an occupied
    /// subspace (`n_s ≥ 1`), a depth-2 span, and a fully resolved width, so at
    /// least one run is projected and `Ok(vec![])` is not an answer this
    /// operation gives.
    ///
    /// Inadmissible (Err) — reject, never clip to the surviving sub-span as
    /// RETRIEVEV's R6 would (O13), and the listing below IS the precedence:
    /// the checks run in this order and the FIRST condition that holds is the
    /// one reported. A document that is not registered (WF_V i), a malformed
    /// span (ii/iv), a foreign subspace (`NoSuchSubspace`) or empty real
    /// subspace (`EmptySubspace`, iii), a
    /// depth-incompatible `#start ≥ 3` span (`DepthIncompatible`, WF_V v —
    /// kept distinct from the range case so a client can tell "wrong depth"
    /// from "unbound positions"), and a depth-2 span overrunning the bound
    /// prefix (`RangeNotPresent`, WF_V vi — fewer positions resolve than the
    /// span names). So a malformed span in a foreign subspace is
    /// `MalformedSpan`, and a deep span over an empty subspace is
    /// `EmptySubspace`.
    pub fn show_origin_v(&self, doc: &Address, span: &Span) -> Result<Vec<Address>, OriginError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !m3.is_registered_document(doc) {
            return Err(OriginError::DocNotRegistered); // WF_V (i)
        }
        gate_vspan(span).map_err(OriginError::MalformedSpan)?; // (ii)/(iv)
        // Gated on the address named; every arrangement read below is the
        // surface's.
        let surface = reading_surface(m3, doc);
        // The start's subspace, at any depth. Foreign (∉ {s_C, s_L}) is
        // distinct from real-but-empty.
        let Some(sub) = Subspace::of_span(span) else {
            return Err(OriginError::NoSuchSubspace);
        };
        if sub.count(m5, &surface).is_zero() {
            return Err(OriginError::EmptySubspace); // (iii)
        }
        // (v): depth must equal the subspace common depth m_S ≡ 2, asked as
        // "the shape `resolve` serves" — M5's own reader, so this refusal and
        // `resolve`'s silent ⟨⟩ can never name different spans. After
        // `gate_vspan` the only clause of M5's shape still open IS the depth
        // one: level-uniformity ties `#width` to `#start`, and ordinal-level
        // puts the width's only nonzero component last, so `#start == 2`
        // gives `width = [0, n≥1]` and every other gated span fails on depth
        // alone.
        let Some(shape) = as_ordinal_vspan(span) else {
            return Err(OriginError::DepthIncompatible);
        };
        // Span now depth-2 (≥ 3 rejected above); resolve may still be partial
        // if the span overruns the bound prefix.
        let runs = m5.resolve(&surface, span);
        let resolved_width: Nat = runs.iter().map(Run::width).sum();
        // `shape.count` is the span's NOMINAL EXTENT — ASN-0115's name for the
        // width's deepest component, the count the span names — read off M5's
        // reading rather than by index, the same part `resolve` read;
        // `resolved_width` is `|act|`, and (vi) is the corpus's nominal-extent
        // attainment failing: `|act| < ℓ_{#ℓ}`.
        if &resolved_width < shape.count {
            return Err(OriginError::RangeNotPresent); // (vi): reject, never clip (O13)
        }
        Ok(sorted_addr_set(runs.iter().map(run_origin)))
    }

    /// SHOWDELETIONS (ASN-0075) — gate, then membership-test the
    /// cross-document combine IN M6 from M5's per-document primitives:
    /// `DeletedFromAWithB = { a : CURRENT(a, d_b) ∧ DELETED(a, d_a) }` and its
    /// symmetric twin. Never opens M4; both halves read off the one pinned
    /// snapshot (single consistent `(M, R)` — no torn-read phantom deletion).
    ///
    /// Reads the arrangement and the provenance record of each address as
    /// NAMED, and does not float (crate doc, *Which arrangement an operation
    /// answers from*): `CURRENT` is enumerated from, and `DELETED` tested
    /// against, the two addresses given.
    ///
    /// Both documents must be registered (Err otherwise; `d_a` checked
    /// first); registered-empty is fine and yields empty halves. Each half is
    /// a set of the EXISTING I-addresses (D-IDENT — never copies), returned
    /// deduplicated and T1-ascending: the dedup is the comprehension's, the
    /// ordering M6's own presentation, which D-ORD licenses (T1-orderability
    /// is a property of the addresses) and does not require (the operation
    /// transports no ordering of its own).
    ///
    /// Whole for two readable arguments (PUB-6.15): no predicate; each half is
    /// the addresses themselves whatever their origins' readability, the two
    /// arguments' consult being M10's pre-dispatch.
    ///
    /// BOTH HALVES ARE CONTENT I-ADDRESSES BY DEFINITION (D-SUBSP): ASN-0075
    /// classifies `(a, d)` with `a ∈ dom(C)`, so `CURRENT` and `DELETED` are
    /// defined only there and both output sets are `{a ∈ dom(C) : …}` — every
    /// such `a` has `subspace_I(a) = s_C`, and `dom(C) ∩ dom(L) = ∅` (L14), so
    /// no link address can appear in either half whatever the enumeration does.
    /// The operation's domain is what confines it, not this implementation's
    /// choice of walk.
    ///
    /// TIME IS UNBOUNDED AND M6 DOES NOT BOUND IT — and unlike RETRIEVEV's,
    /// it is not bounded by the answer either. No span narrows the request, so
    /// both documents are enumerated WHOLE: the work is
    /// `|R↾d_a| log |R↾d_a| + |R↾d_b| log |R↾d_b|`, the two `M5State::deletions`
    /// calls that build the halves (each rebuilds and SORTS the document's
    /// whole provenance record — M5 states this cost where it is paid), plus
    /// `n_C(d_a)·|deletions(d_b)| + n_C(d_b)·|deletions(d_a)|` for the
    /// membership pass, all paid in full even when the two share nothing and
    /// both halves come back empty. THE FIRST TERM USUALLY DOMINATES, and it
    /// is the one a document's current size does not reveal: R never shrinks,
    /// so a document that has deleted far more than it holds carries a
    /// record far larger than its arrangement. M6 owns no admission control
    /// and no refusal for any of it: capping request rate and concurrency for
    /// a route carrying this read is M10's, as the request lifecycle's owner —
    /// and a request-size cap is no help here, this request being two
    /// addresses whatever the documents behind them hold.
    ///
    /// MEMORY IS THE ANSWER'S. The enumeration streams, so what is held live
    /// is the deduped halves and one address at a time, not a materialized
    /// copy of either document's position list. The worst case is therefore
    /// the honest one: two documents where each has deleted what the other
    /// still holds, whose answer genuinely is that many addresses.
    pub fn show_deletions(
        &self,
        d_a: &Address,
        d_b: &Address,
    ) -> Result<Deletions, DeletionsError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        for d in [d_a, d_b] {
            if !m3.is_registered_document(d) {
                return Err(DeletionsError::DocNotRegistered(d.clone()));
            }
        }
        let del_a = m5.deletions(d_a); // { a : DELETED(a, d_a) } as a per-level-class cover
        let del_b = m5.deletions(d_b); // { a : DELETED(a, d_b) }
        // CURRENT in the one document ∧ DELETED from the other, both ways.
        // CURRENT(·, d) is enumerated by `current_content`, which asks each
        // content run for its addresses exactly as RETRIEVEV does; DELETED(·, d)
        // is tested by membership in M5's per-document deleted cover
        // (`deletions(d).denotes(a)`) — exact UNCONDITIONALLY by
        // `difference_sets`' denotational contract
        // (`⟦deletions(d)⟧ = {x : DELETED(x, d)}` whatever the cover's internal
        // span packing), so there are no false positives.
        let deleted_from_a_with_b =
            sorted_addr_set(current_content(m5, d_b).filter(|a| del_a.denotes(a.tumbler())));
        let deleted_from_b_with_a =
            sorted_addr_set(current_content(m5, d_a).filter(|a| del_b.denotes(a.tumbler())));
        Ok(Deletions {
            deleted_from_a_with_b,
            deleted_from_b_with_a,
        })
    }

    /// FINDDOCSCONTAINING (ASN-0124 `finddocs`) — the documents that CURRENTLY
    /// hold some I-address the regions resolve to: sound (FD-SOUND — a present
    /// witness, never a historical one) and complete (FD-COMPLETE), as bare
    /// deduplicated identities in tumbler order — no positions, no counts (FD
    /// codomain; present-tense CONTAINERS, distinct from SHOWORIGIN's
    /// allocators).
    ///
    /// Reads the arrangement of each region's address as NAMED, and does not
    /// float (crate doc, *Which arrangement an operation answers from*): the
    /// coverage is the named address's own image, and a candidate is tested
    /// at its own identity.
    ///
    /// Every named document must be registered and every region span
    /// well-formed (Err otherwise — a malformed span would silently
    /// UNDER-resolve and drop containers, violating FD-COMPLETE); the gate
    /// does NOT restrict subspace — a link/foreign-subspace span passes and
    /// stays inert downstream (R⁻¹ indexes content provenance only, J-LV),
    /// and a depth-incompatible span resolves to empty coverage
    /// (consulting-state, like RETRIEVEV's R6). Registered-empty contributes
    /// nothing.
    ///
    /// WHICH REFUSAL SPEAKS. The gate walks the regions in submitted order and
    /// each region's spans in submitted order, reporting the FIRST fault
    /// whatever its kind; within one region the registry check precedes the
    /// span gate. It also completes over the WHOLE request before any `image`
    /// is taken, so a rejected request costs `O(spans)` and nothing upstream,
    /// `(region, index)` promises that every region and span before the named
    /// one is clean, and a gate fault always outranks the budget refusal below.
    ///
    /// COST, IN THREE FACTORS OF WHICH ONE IS THE REQUEST'S. The work is
    /// `|spans| · #runs(doc) + |candidates| · #runs(d) · |coverage|`: the
    /// coverage is the union of the region images, one `image` walk per span,
    /// each `Θ(#runs(doc))` whether or not it yields coverage; the candidate
    /// scan runs that coverage against the whole of M5's R⁻¹ index; and the
    /// filter is one `project` per candidate, each itself
    /// `#runs(d) · |coverage|` in the CANDIDATE's own fragmentation — a factor
    /// the request never names and M6 never sees. Each `project` is a cost in
    /// HEAP as well as in steps: it materializes and sorts one span per
    /// overlapping (run, cover) pair before M6 reads one bit off it, so the
    /// peak transient of the filter is that product in live heap and the
    /// operation asks for a whole footprint where it needs only its
    /// non-emptiness.
    ///
    /// Only `|spans|` and `|coverage|` are the request's, and both are capped
    /// at [`MAX_FIND_COVERAGE_SPANS`] (`TooMuchCoverage`, refused AS THE
    /// REQUEST RESOLVES — the span past the budget before its walk, the
    /// coverage past it as it is produced — so an over-budget request stops
    /// resolving rather than resolving whole and then being measured; why
    /// both are counted, and what neither count bounds within one span, are
    /// on the budget's card). That is a REFUSAL, never a truncation: a
    /// request past the budget gets a typed rejection and no answer, so
    /// FD-COMPLETE holds verbatim for every request this operation answers —
    /// a truncated coverage would silently drop containers, which is the
    /// hazard the operation names. A caller wanting more splits the request.
    ///
    /// `|R|` and `#runs(d)` are the WORLD's and no number here reaches them:
    /// they stay with request rate and concurrency, which are M10's as the
    /// request lifecycle's owner.
    pub fn find_docs_containing(&self, regions: &[RegionSpec]) -> Result<Vec<Address>, FindError> {
        // The UNFILTERED containers — every one readable. The daemon's read
        // surface calls [`Query::find_docs_containing_filtered`] with its
        // per-request predicate.
        self.find_docs_containing_filtered(regions, &|_| true)
    }

    /// FINDDOCSCONTAINING with the container filter (PUB round 2, lane 3.3,
    /// §3; PUB-6.13/6.19): the same answer, minus every CONTAINER the reading
    /// principal may not read. The filter is at container IDENTITY — a
    /// candidate document `readable` answers false for is dropped, exactly as a
    /// result-set link's unreadable home is. The region-spec DOCUMENTS are the
    /// caller's doc-argument consult (pre-dispatch), not filtered here. M6
    /// decides no readability here — it applies the predicate M10 threads in,
    /// at the container, which is the granularity the answer has.
    ///
    /// The predicate's registered-only precondition (PUB-6.37) holds at this
    /// door BY CONSTRUCTION — every candidate is a document R records a
    /// placement in, and R is appended only by M5's write path on a
    /// registered target — so no registry check precedes the predicate here,
    /// where RETRIEVEV's masked form needs one, and adding one would be a
    /// second check of a discharged obligation. The predicate is asked of
    /// each candidate FIRST, before `project` is paid (PUB-6.17), and only
    /// after the gate and both counts of the coverage budget have passed the
    /// whole request.
    pub fn find_docs_containing_filtered(
        &self,
        regions: &[RegionSpec],
        readable: &dyn Fn(&Address) -> bool,
    ) -> Result<Vec<Address>, FindError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        // The gate first, over the WHOLE request — the first fault wins, and
        // no upstream work is done for a request that will be rejected.
        for (region, r) in regions.iter().enumerate() {
            if !m3.is_registered_document(&r.doc) {
                return Err(FindError::DocNotRegistered(r.doc.clone()));
            }
            for (index, span) in r.spans.iter().enumerate() {
                gate_vspan(span).map_err(|fault| FindError::MalformedSpan {
                    region,
                    index,
                    fault,
                })?;
            }
        }
        // Phase 1: resolve to content I-coverage — the union of every region
        // span's `image`, raw and possibly mixed-length: M5's
        // `docs_ever_containing`/`project` apply the level-class discipline
        // INTERNALLY, so the raw union passes straight through and M6 owns no
        // level-class discipline anywhere. The union of the images IS their
        // concatenation, so they are gathered in submitted order and the
        // coverage is built from them once. Gathering rather than re-unioning
        // is what keeps the walk LINEAR in the coverage: `union` answers with
        // a fresh set, so an accumulator threaded through it copies the
        // coverage built so far at every span, and the budget below would
        // then bound a quantity that costs its own square to produce.
        let mut coverage_spans: Vec<Span> = Vec::new();
        let mut spans_handed = 0usize;
        for r in regions {
            for span in &r.spans {
                // The span count, taken as the span is handed and before its
                // walk; MAX_COMPARE_OPERAND_BLOCKS's card says why spans are
                // counted beside the coverage, and why a span M5 folds to
                // nothing at once counts all the same.
                if spans_handed >= MAX_FIND_COVERAGE_SPANS {
                    return Err(FindError::TooMuchCoverage); // refused before the walk
                }
                spans_handed += 1;
                coverage_spans.extend(m5.image(&r.doc, span));
                // The coverage budget, refused AS THE COVERAGE IS PRODUCED —
                // `>` and not `==`, because one span's image adds many
                // coverage spans at once.
                if coverage_spans.len() > MAX_FIND_COVERAGE_SPANS {
                    return Err(FindError::TooMuchCoverage);
                }
            }
        }
        let coverage: SpanSet = coverage_spans.into_iter().collect(); // collect AS GIVEN
        // Phase 2: the historical superset (tumbler-ordered, level-classes
        // handled inside M5), narrowed by the present-tense filter — one
        // `project` per candidate, non-empty iff the candidate holds some
        // covered address NOW. TWO narrowings separate that superset from the
        // live answer, and the filter discharges both at once — from
        // order-overlap to genuine ever-containment, M5's test admitting the
        // merely ADJACENT candidates whose recorded spans touch the coverage
        // without sharing a position, so the superset is coarser even than
        // FD-HIST's `finddocs_R`; and from ever to now, dropping FD-GHOST's
        // `ghosts` (`finddocs_R ∖ finddocs`), the documents that held the
        // queried material at some past boundary and hold none of it now.
        let candidates = m5.docs_ever_containing(&coverage);
        Ok(candidates
            .into_iter()
            // FD-SOUND — the present-tense containment filter — AND the
            // container consult (lane 3.3, §3): a container the reader may not
            // read is dropped at its identity, before it reaches the answer.
            // The predicate goes first (PUB-6.17): the cheap test ahead of the
            // one that materializes a footprint. Its registered-only
            // precondition (PUB-6.37) holds by construction — R records
            // placements in registered documents alone — so nothing is
            // re-checked here.
            // Emptiness is M1's `SpanSet::is_empty`, denotationally exact
            // because no algebra result carries a zero-width span (zero spans
            // ⇔ empty denotation).
            .filter(|d| readable(d) && !m5.project(d, &coverage).is_empty())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skep_address::{validate, Tumbler};

    fn a(comps: &[u32]) -> Address {
        let t =
            Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty");
        validate(t).expect("test addresses are T4-valid")
    }

    #[test]
    fn sorted_addr_set_is_deduped_and_t1_ordered() {
        let d2 = a(&[1, 0, 1, 0, 2]);
        let d1 = a(&[1, 0, 1, 0, 1]);
        let got = sorted_addr_set(vec![d2.clone(), d1.clone(), d2.clone(), d1.clone()]);
        assert_eq!(got, vec![d1, d2]);
        assert!(sorted_addr_set(std::iter::empty()).is_empty());
    }
}
