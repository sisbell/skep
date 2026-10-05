//! §E FINDDOCSCONTAINING (ASN-0124 `finddocs`): the documents that currently
//! hold some I-address a vspec-set resolves to, through both doors.

use skep_address::{Address, Span, SpanSet};

use super::{Query, RetrievalWorld};
use crate::budget::{Count, OverBudget, MAX_FIND_COVERAGE_SPANS};
use crate::error::FindError;
use crate::types::RegionSpec;
use crate::vspan::gate_vspan;

impl<W: RetrievalWorld> Query<'_, W> {
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
    /// span gate. It also completes over the WHOLE request before any span is
    /// handed to M5, so a rejected request costs `O(spans)` and nothing
    /// upstream, `(region, index)` promises that every region and span before
    /// the named one is clean, and a gate fault always outranks the budget
    /// refusal below.
    ///
    /// COST, IN THREE FACTORS OF WHICH ONE IS THE REQUEST'S. The work is
    /// `|spans| · #runs(doc) + |candidates| · #runs(d) · |coverage|`: the
    /// coverage is the union of the region images, one resolution walk per
    /// span, each `Θ(#runs(doc))` whether or not it yields coverage; the
    /// candidate scan runs that coverage against the whole of M5's R⁻¹ index;
    /// and the filter is one `arranges_any` per candidate, each at worst
    /// `#runs(d) · |coverage|` pair tests in the CANDIDATE's own fragmentation
    /// — a factor the request never names and M6 never sees — and each
    /// holding nothing.
    ///
    /// Only `|spans|` and `|coverage|` are the request's, and both are held to
    /// the coverage budget, [`MAX_FIND_COVERAGE_SPANS`] (`TooMuchCoverage`,
    /// refused AS THE REQUEST RESOLVES — the span past the budget before its
    /// walk, the coverage past it as it is produced — so an over-budget request
    /// stops resolving rather than resolving whole and then being measured; why
    /// both are counted, and what the counts stop within one span and what
    /// they do not, are on the budget's card). That is a REFUSAL, never a
    /// truncation: a request past the budget gets a typed rejection and no
    /// answer, so FD-COMPLETE holds verbatim for every request this operation
    /// answers — a truncated coverage would silently drop containers, which is
    /// the hazard the operation names. A caller wanting more splits the
    /// request.
    ///
    /// `|R|` and `#runs(d)` are the WORLD's and no number here reaches them:
    /// they stay with request rate and concurrency, which are M10's as the
    /// request lifecycle's owner.
    pub fn find_docs_containing(&self, regions: &[RegionSpec]) -> Result<Vec<Address>, FindError> {
        // The UNFILTERED containers — every one readable. M10's dispatch
        // calls [`Query::find_docs_containing_filtered`] with the predicate it
        // threads in per request.
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
    /// each candidate FIRST, before `arranges_any` is paid (PUB-6.17), and only
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
        // span's image, each resolved run lifted by `Run::iextent`, raw and
        // possibly mixed-length: M5's `docs_ever_containing`/`arranges_any`
        // apply the level-class discipline INTERNALLY, so the raw union passes
        // straight through and M6 owns no level-class discipline anywhere.
        // The union of the images IS their concatenation, so they are
        // gathered in submitted order and the coverage is built from them
        // once. Gathering rather than re-unioning is what keeps the walk
        // LINEAR in the coverage: `union` answers with a fresh set, so an
        // accumulator threaded through it copies the coverage built so far at
        // every span, and the budget below would then bound a quantity that
        // costs its own square to produce.
        let mut coverage_spans: Vec<Span> = Vec::new();
        let mut spans_handed = Count::against(MAX_FIND_COVERAGE_SPANS);
        let mut coverage_produced = Count::against(MAX_FIND_COVERAGE_SPANS);
        let over = |OverBudget| FindError::TooMuchCoverage;
        for r in regions {
            for span in &r.spans {
                // The span count, taken as the span is handed and refused
                // before its walk; MAX_COMPARE_OPERAND_BLOCKS's card says why
                // spans are counted beside the coverage, and why a span M5
                // folds to nothing at once counts all the same.
                spans_handed.admit(1).map_err(over)?;
                for run in m5.iter_resolve(&r.doc, span) {
                    coverage_produced.admit(1).map_err(over)?;
                    coverage_spans.push(run.iextent());
                }
            }
        }
        let coverage: SpanSet = coverage_spans.into_iter().collect(); // collect AS GIVEN
        // Phase 2: the historical superset (tumbler-ordered, level-classes
        // handled inside M5), narrowed by the present-tense filter — one
        // `arranges_any` per candidate, true iff the candidate holds some
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
            // pair scan. Its registered-only precondition (PUB-6.37) holds by
            // construction — R records placements in registered documents
            // alone — so nothing is re-checked here.
            .filter(|d| readable(d) && m5.arranges_any(d, &coverage))
            .collect())
    }
}
