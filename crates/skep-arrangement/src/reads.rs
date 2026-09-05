//! §D/§E — arrangement reads (resolve/point/image/project), the content
//! subspace's admission predicates, and the provenance reads
//! (deletions/docs_ever_containing), pure over any M2 snapshot (§2, §9).
//!
//! **Level-class discipline** (§2): a SpanSet aggregated across runs — a
//! region image, an endset's coverage, the internal `content_image`, a
//! document's `ever_contained` record — is in general MIXED-LENGTH
//! (transclusion mixes origin lengths), and M1's length-gated set ops fault
//! `LevelMismatch` on mixed operands. Where geometry is needed, M5 partitions
//! each operand into level-classes by endpoint length
//! (`SpanSet::by_level_class`), runs the M1 op within each class, and unions
//! the per-class results; where overlap/membership suffices it uses the total
//! `classify_spans`/`contains`. The discipline is ENCAPSULATED behind the
//! query methods ([`M5State::project`], [`M5State::deletions`]) and OWED by
//! whoever aggregates run extents themselves — [`M5State::image`]'s raw
//! cover, and the runs [`M5State::resolve`] hands back for a caller to lift.
//! Both routes reach [`Run::iextent`], where the obligation is stated
//! (Conflicts #8).

use std::sync::LazyLock;

use num_traits::One;
use skep_address::{content_subspace, difference_sets, union, Address, Nat, Span, SpanSet};

use crate::run::Run;
use crate::runlist::RunList;
use crate::state::{DocArrangement, M5State};
use crate::vspace::{as_ordinal_vspan, ordinal_vspan, VPos};

/// The arrangement an ABSENT document reads as: the lazy convention stated on
/// [`M5State`], made a value so [`M5State::arrangement_of`] can hand back a
/// borrow on either branch. Once-only initialization of a `Default`.
static EMPTY_ARRANGEMENT: LazyLock<DocArrangement> = LazyLock::new(DocArrangement::default);

impl M5State {
    /// `doc`'s arrangement, or the EMPTY one — the absent-⇒-empty convention
    /// (the eager-lazy split with M3, stated on [`M5State`]) applied ONCE, so
    /// no read decides for itself what an absent document answers and the
    /// eleventh read inherits the convention rather than restating it. Every
    /// read in this file reaches its run-lists through here or through the
    /// two narrowings below, which leaves `arrangements` touched directly only
    /// by the folds that own it.
    fn arrangement_of(&self, doc: &Address) -> &DocArrangement {
        self.arrangements
            .get(doc)
            .unwrap_or_else(|| &*EMPTY_ARRANGEMENT)
    }

    /// `doc`'s content run-list — empty for an absent document.
    fn content_of(&self, doc: &Address) -> &RunList {
        &self.arrangement_of(doc).content
    }

    /// `doc`'s link run-list — empty for an absent document.
    fn link_of(&self, doc: &Address) -> &RunList {
        &self.arrangement_of(doc).link
    }

    /// V→I resolution (§2; ASN-0058 C0; ASN-0118 accept-and-intersect):
    /// I-runs covering an ORDINAL-LEVEL depth-2 V-span (width `[0, n]`,
    /// action point 2), V-ordered, clipped to the active range. The span's
    /// subspace, ordinal and count come from the one reader that establishes
    /// it has them.
    ///
    /// THE RUNS TILE V CONTIGUOUSLY, which is what lets a caller recover each
    /// run's V-position without asking a second time: the FIRST run returned
    /// holds V-ordinal `max(ord, 1)` — the clamp is load-bearing, a span
    /// opening at ordinal 0 still starting its answer at 1 — and each next run
    /// begins where the previous one ends, so accumulating widths from that
    /// start gives every run's V-start. There are no V-gaps to skip because
    /// there are none to have: a subspace's arranged positions are its dense
    /// prefix (D-SEQ★, stated on [`M5State`]), so a span reaching past the
    /// prefix is clipped and one opening past it binds nothing at all rather
    /// than skipping forward to a later position.
    ///
    /// DEFENSIVE (returns ⟨⟩, cannot fault — no `Result`) unless the span is
    /// usable: a span the shared shape reader refuses — the same shape COPY's
    /// `NotOrdinalVSpan` rejects on — yields ⟨⟩, and so does a shape-valid
    /// span whose subspace ∉ {s_C, s_L}, a `DocArrangement` having exactly the
    /// content and link run-lists. Absent doc ⇒ ⟨⟩ (M6/M8 disambiguate
    /// registered-empty vs unallocated via M3). A caller that must tell "bad
    /// request" from "genuinely empty" calls
    /// [`is_ordinal_vspan`](crate::is_ordinal_vspan) itself before asking;
    /// M6's own request gate is deliberately WEAKER (ASN-0115
    /// well-formedness, `#start ≥ 2`), leaving depth compatibility to this
    /// defensive fold.
    ///
    /// MIXED-LENGTH HAZARD for whoever aggregates the returned runs' extents:
    /// see [`Run::iextent`].
    pub fn resolve(&self, doc: &Address, span: &Span) -> Vec<Run> {
        let Some(vspan) = as_ordinal_vspan(span) else {
            return Vec::new();
        };
        let Some(list) = self.arrangement_of(doc).list(vspan.subspace) else {
            return Vec::new();
        };
        list.resolve_range(vspan.ordinal, vspan.count)
    }

    /// `M(d)(p)` (§2): the I-address at V-position `p`, or `None` when
    /// `p.subspace ∉ {s_C, s_L}` (no such run-list) or the ordinal is
    /// unarranged — which under D-SEQ★ ([`M5State`]) is exactly
    /// `p.ordinal ∉ [1, n_s]`, a subspace's arranged positions being its dense
    /// prefix, so one bound settles membership. Every returned `Address` is
    /// T4-valid (synthesis routes through `validate`).
    pub fn point(&self, doc: &Address, p: &VPos) -> Option<Address> {
        self.arrangement_of(doc)
            .list(&p.subspace)?
            .point(&p.ordinal)
    }

    /// The region's I-image as a SpanSet (§2; ASN-0127 `image(W, d, Σ)`, the
    /// addresses `doc`'s arrangement maps the V-region `span` onto):
    /// `⋃ r.iextent()` over the runs [`resolve`](M5State::resolve) returns —
    /// the aggregate M6's FINDDOCSCONTAINING feeds to
    /// [`docs_ever_containing`](M5State::docs_ever_containing) and to
    /// [`project`](M5State::project), lifted here so the query does not
    /// re-derive it. `union` (concatenation) only ⇒ total, never faults, NOT
    /// normalized; possibly mixed-length when `span` covers transcluded runs,
    /// so it is consumed under the level-class discipline (the hazard is
    /// stated on [`Run::iextent`], which every aggregator of run extents
    /// reaches, whether or not it comes through here).
    pub fn image(&self, doc: &Address, span: &Span) -> SpanSet {
        self.resolve(doc, span).into_iter().map(|r| r.iextent()).collect()
    }

    /// The canonical, V-ordered content run decomposition — maximally merged
    /// (ASN-0058 M12), the COMPARE surface for M6. Absent doc ⇒ `[]`. The runs
    /// tile the whole content prefix `[1, n_C]` contiguously (D-SEQ★, stated
    /// on [`M5State`]), so the first begins at V-ordinal 1 and each next where
    /// the previous ends.
    pub fn content_runs(&self, doc: &Address) -> Vec<Run> {
        self.content_of(doc).runs()
    }

    /// The canonical, V-ordered link run decomposition. Absent doc ⇒ `[]`; it
    /// tiles `[1, n_L]` as [`content_runs`](M5State::content_runs) tiles the
    /// content prefix, D-SEQ★ holding per subspace.
    pub fn link_runs(&self, doc: &Address) -> Vec<Run> {
        self.link_of(doc).runs()
    }

    /// `n_C(d)` — the arranged content width. Absent doc ⇒ 0. Under D-SEQ★
    /// ([`M5State`]) it is equally the LARGEST arranged content ordinal and
    /// the width sum of [`content_runs`](M5State::content_runs): the content
    /// positions are `[1, n_C]` with no holes, so a count fixes the extent
    /// (ASN-0113 W2/W4) rather than over-reporting one.
    pub fn content_count(&self, doc: &Address) -> Nat {
        self.content_of(doc).total_width()
    }

    /// `n_L(d)` — the arranged link width. Absent doc ⇒ 0; the D-SEQ★ reading
    /// of [`content_count`](M5State::content_count) holds per subspace, so
    /// this is likewise the largest arranged link ordinal.
    pub fn link_count(&self, doc: &Address) -> Nat {
        self.link_of(doc).total_width()
    }

    /// Does the content subspace admit `ord` as a PLACEMENT boundary —
    /// `1 ≤ ord ≤ n_C + 1` (§1/§3)? The arrangement's own admission rule,
    /// asked rather than re-derived, so the append boundary (and the
    /// `ord = 1` case at `n_C = 0`, ASN-0116's FirstInsertionPosition) has one
    /// definition for INSERT, COPY and REARRANGE's cuts to share. The verdict
    /// each op reports for a refusal stays with that op's error type.
    pub(crate) fn admits_content_boundary(&self, doc: &Address, ord: &Nat) -> bool {
        *ord >= Nat::one() && *ord <= &self.content_count(doc) + &Nat::one()
    }

    /// Does `doc` ARRANGE content ordinal `ord` — is it a position holding an
    /// I-address, `ord ∈ [1, n_C]` (§4)? Answered off the run-list's own
    /// locate, which is the same walk `point` uses. One short of
    /// [`admits_content_boundary`](M5State::admits_content_boundary), which
    /// admits the append boundary as well.
    pub(crate) fn arranges_content_position(&self, doc: &Address, ord: &Nat) -> bool {
        self.content_of(doc).locate(ord).is_some()
    }

    /// Does `doc`'s arranged content CONTAIN the whole range `[from, from +
    /// width)` — `from + width ≤ n_C + 1`, subtraction-free (§4)? The
    /// containment half of DELETE's admission, stated where `n_C` lives.
    /// PRESENT containment, as the corpus uses the word; the historical
    /// question belongs to
    /// [`docs_ever_containing`](M5State::docs_ever_containing).
    pub(crate) fn contains_content_range(&self, doc: &Address, from: &Nat, width: &Nat) -> bool {
        from + width <= &self.content_count(doc) + &Nat::one()
    }

    /// Is `link` already seated in `doc`'s link subspace (§8, CL-UNIQ)? The
    /// link run-list's own membership answer, so a link INTERIOR to a
    /// coalesced link run counts as seated. Absent doc ⇒ not seated.
    pub(crate) fn seats_link(&self, doc: &Address, link: &Address) -> bool {
        self.link_of(doc).holds(link)
    }

    /// I→V projection (§2; ASN-0119 RA7c) — CONTENT subspace ONLY, by
    /// construction (link reverse-discovery is M7's BH3; there is no subspace
    /// argument): the V-positions of `doc` whose content I-address falls in
    /// `coverage` — an I-address cover, either an endset's coverage (M7/M8) or
    /// a region [`image`](M5State::image) (M6), possibly fragmented and
    /// mixed-length — as depth-2 V-spans, normalized. The result is the
    /// FOOTPRINT those addresses have in `doc` (ASN-0119's `project`), which
    /// is why a footprint interrupted in V-space comes back as several spans.
    /// TOTAL — the level-class discipline is applied internally, so the call
    /// is fault-free for any coverage, including cross-length prefix/subtree
    /// spans.
    ///
    /// Per content run × coverage span: the run reports which of its offsets
    /// the span covers ([`Run::offsets_covered_by`], which owns both the
    /// same-level-class intersection and the cross-class boundary search),
    /// and this method turns that offset range into a V-range by adding the
    /// run's implicit V-start. Scan of the forward content map (Open decision
    /// #2 v1 default), so the cost is `#runs(doc) × |coverage|` — the
    /// product of two quantities this method does not bound. `#runs(doc)`
    /// grows with `doc`'s own edit and transclusion history; `|coverage|` is
    /// bounded on M7's and M8's route (an endset is capped at deposit,
    /// `MAX_SLOT_SPANS`) and by nothing on M6's, where it is an
    /// [`image`](M5State::image) of a region. Admission control is the
    /// caller's, as it is for
    /// [`docs_ever_containing`](M5State::docs_ever_containing).
    pub fn project(&self, doc: &Address, coverage: &SpanSet) -> SpanSet {
        let mut vspans: Vec<Span> = Vec::new();
        // An absent document is a CASE and not a path: its content run-list is
        // the empty one, which iterates no runs and answers ⟨⟩.
        for (v_start, run) in self.content_of(doc).iter_runs() {
            for cspan in coverage.iter() {
                let Some((k_lo, k_hi)) = run.offsets_covered_by(cspan) else {
                    continue;
                };
                let at = VPos {
                    subspace: content_subspace(),
                    ordinal: &v_start + &k_lo,
                };
                vspans.push(
                    ordinal_vspan(&at, &(&k_hi - &k_lo))
                        .expect("a covered offset range is nonempty (k_lo < k_hi)"),
                );
            }
        }
        let set: SpanSet = vspans.into_iter().collect();
        // The output V-spans are all depth-2, hence one level class — safe to
        // normalize (fragmentation across runs/spans coalesces where ranges
        // touch).
        set.normalize()
            .expect("depth-2 V-spans share one level class")
    }

    /// The current content-image cover (M5-INTERNAL — the SHOWDELETIONS
    /// operand consumed only by `deletions`, §2/§9): `⋃ r.iextent()` over the
    /// content runs. Union (concatenation) only; possibly mixed-length across
    /// transcluded origins — never blindly normalized, never a seam.
    fn content_image(&self, doc: &Address) -> SpanSet {
        self.content_of(doc).image()
    }

    /// SHOWDELETIONS primitive (§9; ASN-0047 P2; ASN-0075's
    /// `DELETED(a, d) ≡ (a, d) ∈ R ∧ a ∉ ran(M(d))`): what `doc` has ever
    /// contained, minus its current content image, computed PER LEVEL-CLASS —
    /// both operands are iextent-covers that mix origin-lengths when `doc`
    /// transcludes across heterogeneous-depth documents, so each is
    /// partitioned by endpoint length (M1's `by_level_class`),
    /// `difference_sets` runs within each class, and the per-class results
    /// are unioned. Per-class is also the correct semantics:
    /// different-length addresses are distinct and cannot cancel. Classes
    /// ascend by endpoint length, the partition being ordered. M6 reads
    /// SHOWDELETIONS straight off this — neither operand crosses the
    /// boundary. Fault-free.
    pub fn deletions(&self, doc: &Address) -> SpanSet {
        let image = self.content_image(doc).by_level_class();
        let mut out = SpanSet::empty();
        for (len, ever) in self.provenance.ever_contained(doc).by_level_class() {
            let here = image.get(&len).cloned().unwrap_or_else(SpanSet::empty);
            let deleted = difference_sets(&ever, &here)
                .expect("per-class operands share one length class — the gate passes");
            out = union(&out, &deleted);
        }
        out
    }

    /// R⁻¹ candidate documents (§9; ASN-0124 FD-HIST, the ProvenanceQuery
    /// `finddocs_R`; Conflicts #6) — the documents that have EVER contained an
    /// address of `coverage`, which is what the provenance record can answer
    /// and all it can answer. Distinct, in deterministic Tumbler order.
    ///
    /// HISTORY, NOT CONTAINMENT, and the two are different questions the
    /// corpus keeps apart: present containment is `finddocs` (FD-FIND), whose
    /// members each carry a live witness (FD-SOUND), and it is a SUBSET of
    /// this answer (FD-SUPER). The difference is FD-GHOST's `ghosts` —
    /// documents that held queried material at some past boundary and hold
    /// none of it now — which is why a caller wanting present containment must
    /// narrow, with `project(d, coverage) ≠ ⟨⟩` off the same snapshot
    /// (M6's FINDDOCSCONTAINING).
    ///
    /// A SUPERSET with no false negatives: a document genuinely holding an
    /// address of `coverage` placed a span that overlaps it in the tumbler
    /// order (P4★ puts every present containment in R), so it is always a
    /// candidate — which is what makes the narrowing sound. Total for any
    /// coverage, mixed-length included.
    ///
    /// COST, AND WHO OWNS IT. Per call: one span comparison for every pair of
    /// (recorded span, coverage span) over the WHOLE relation, each deriving
    /// both operands' endpoints. Neither factor is bounded here — R never
    /// loses a member (P2), so it is the sum of every run ever placed by any
    /// document, and `coverage` is as large as the caller's own aggregation
    /// (M6 builds it from [`image`](M5State::image), whose size is the source
    /// document's fragmentation). There is no index over R in v1 (Open
    /// decision #3, which belongs here, R's owner) and no admission gate: this
    /// method refuses nothing and bounds nothing, so admission control and
    /// concurrency for the query that composes on it are the CALLER's, and a
    /// route that carries this read owes that number.
    pub fn docs_ever_containing(&self, coverage: &SpanSet) -> Vec<Address> {
        self.provenance.docs_ever_containing(coverage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::M5Rec;
    use crate::testutil::{a, ca, doc1, doc2, la, n, run, t, vca, vp, vspan};
    use skep_address::subtree_of;

    fn place(s: &M5State, doc: &Address, at: u32, runs: Vec<Run>) -> M5State {
        s.apply_m5(&M5Rec::ContentPlace {
            doc: doc.clone(),
            at: n(at),
            runs,
        })
    }

    fn arranged() -> M5State {
        // doc1 content: ca(1..3) then a transcluded length-9 run vca(1..2).
        let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
        place(&s, &doc1(), 4, vec![run(&vca(1), 2)])
    }

    #[test]
    fn resolve_guard_is_complete_and_defensive() {
        // §2: every malformed request folds to ⟨⟩ — never a fault.
        let s = arranged();
        // The usable form resolves.
        assert_eq!(s.resolve(&doc1(), &vspan(1, 1, 3)), vec![run(&ca(1), 3)]);
        // #start ≠ 2 (both < 2 and > 2).
        let short = Span::new(t(&[5]), t(&[1])).expect("T12");
        assert!(s.resolve(&doc1(), &short).is_empty());
        let deep = Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).expect("T12");
        assert!(s.resolve(&doc1(), &deep).is_empty());
        // #width ≠ 2 alone: T12 admits this span (action point 2 ≤ #start 2),
        // its start is a well-formed V-position and its width position 1 is
        // zero, so only the width-length clause refuses it. Served, it would
        // resolve five content ordinals for a span whose reach is [1, 6, 0].
        let deep_width = Span::new(t(&[1, 1]), t(&[0, 5, 0])).expect("T12: action point 2 ≤ #start");
        assert!(s.resolve(&doc1(), &deep_width).is_empty());
        // Non-ordinal width [m, n] with m > 0 (action-point-1).
        let lu = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12");
        assert!(s.resolve(&doc1(), &lu).is_empty());
        // Unknown subspace selects no run-list.
        let odd = Span::new(t(&[3, 1]), t(&[0, 1])).expect("T12");
        assert!(s.resolve(&doc1(), &odd).is_empty());
        // Absent doc.
        assert!(s.resolve(&doc2(), &vspan(1, 1, 1)).is_empty());
    }

    #[test]
    fn resolve_serves_the_link_subspace_off_its_own_run_list() {
        // §2: the span's subspace numeral selects the run-list, so a link
        // span resolves against the LINK runs — which is what makes COPY's
        // `SourceNotContentSubspace` a needed guard rather than a formality,
        // and what M7 relies on when it builds a slot endset.
        let s = arranged();
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(2) });
        assert_eq!(s.resolve(&doc1(), &vspan(2, 1, 2)), vec![run(&la(1), 2)]);
        // Clipped to n_L, exactly as the content side is.
        assert!(s.resolve(&doc1(), &vspan(2, 3, 1)).is_empty());
    }

    #[test]
    fn resolve_clips_accept_and_intersect_and_orders_by_v() {
        // ASN-0118: over-reach silently clipped; V-order preserved across the
        // transclusion seam.
        let s = arranged();
        let got = s.resolve(&doc1(), &vspan(1, 2, 10));
        assert_eq!(got, vec![run(&ca(2), 2), run(&vca(1), 2)]);
    }

    #[test]
    fn the_arrangement_states_which_positions_it_admits() {
        // §1/§3/§4/§8: the placement boundary, the arranged position, the
        // containment of a range and the seating of a link are all facts
        // about the arrangement, so the arrangement answers them.
        let s = arranged(); // n_C = 5
        assert!(s.admits_content_boundary(&doc1(), &n(1)));
        assert!(s.admits_content_boundary(&doc1(), &n(6))); // the append boundary
        assert!(!s.admits_content_boundary(&doc1(), &n(0)));
        assert!(!s.admits_content_boundary(&doc1(), &n(7)));
        // An empty document admits ordinal 1 and nothing else.
        assert!(s.admits_content_boundary(&doc2(), &n(1)));
        assert!(!s.admits_content_boundary(&doc2(), &n(2)));
        // Arranged positions stop one short of that boundary.
        assert!(s.arranges_content_position(&doc1(), &n(5)));
        assert!(!s.arranges_content_position(&doc1(), &n(6)));
        assert!(!s.arranges_content_position(&doc1(), &n(0)));
        assert!(!s.arranges_content_position(&doc2(), &n(1)));
        // Containment: [from, from + width) must fit the arranged content.
        assert!(s.contains_content_range(&doc1(), &n(2), &n(4)));
        assert!(!s.contains_content_range(&doc1(), &n(2), &n(5)));
        // Seating is I-extent membership, so an interior position of a
        // coalesced link run counts.
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(2) });
        assert_eq!(s.link_runs(&doc1()).len(), 1);
        assert!(s.seats_link(&doc1(), &la(1)));
        assert!(s.seats_link(&doc1(), &la(2)));
        assert!(!s.seats_link(&doc1(), &la(3)));
        assert!(!s.seats_link(&doc2(), &la(1)));
    }

    #[test]
    fn each_subspace_arranges_the_dense_prefix_its_count_names() {
        // D-SEQ★ (§1; ASN-0047, via contiguity D-CTG★ and minimum-position
        // D-MIN★), which this slice now PUBLISHES rather than merely keeping:
        // a subspace's arranged positions are exactly [1, n_s], the count is
        // the largest of them, and `resolve`'s runs tile that prefix
        // contiguously from max(ord, 1). All three are what a caller walking
        // an arrangement stands on, so all three are checked — over a
        // fragmented, mixed-length arrangement, after the one fold arm that
        // would open a hole in the middle if the representation admitted one.
        let s = arranged(); // ca(1..3) then vca(1..2): two runs, two lengths
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(3) }); // not I-adjacent
        let s = s.apply_m5(&M5Rec::ContentRemove {
            doc: doc1(),
            from: n(2),
            width: n(2),
        });
        let at = |subspace: u32, ordinal: &Nat| VPos {
            subspace: n(subspace),
            ordinal: ordinal.clone(),
        };
        for (subspace, count, runs) in [
            (1u32, s.content_count(&doc1()), s.content_runs(&doc1())),
            (2, s.link_count(&doc1()), s.link_runs(&doc1())),
        ] {
            assert!(count >= n(2), "the fixture arranges both subspaces");
            assert_eq!(
                runs.iter().fold(n(0), |acc, r| acc + r.width()),
                count,
                "subspace {subspace}: the count is the run widths' sum"
            );
            // Dense from 1: every ordinal below the count is arranged, and the
            // count is the largest — so one bound settles membership.
            assert_eq!(s.point(&doc1(), &at(subspace, &n(0))), None);
            let mut k = n(1);
            while k <= count {
                assert!(
                    s.point(&doc1(), &at(subspace, &k)).is_some(),
                    "subspace {subspace}: ordinal {k} is arranged"
                );
                k = &k + &n(1);
            }
            assert_eq!(
                s.point(&doc1(), &at(subspace, &(&count + &n(1)))),
                None,
                "subspace {subspace}: the count is the LARGEST arranged ordinal"
            );
            // The runs tile V contiguously: accumulating widths from
            // max(ord, 1) names each run's own V-start, and the walk ends at
            // the boundary past the prefix.
            for open in [0u32, 1, 2] {
                let mut v = std::cmp::max(n(open), n(1));
                for r in s.resolve(&doc1(), &vspan(subspace, open, 99)) {
                    assert_eq!(
                        s.point(&doc1(), &at(subspace, &v)).as_ref(),
                        Some(r.i_start()),
                        "subspace {subspace} from {open}: each run begins at the accumulated V-start"
                    );
                    v = &v + r.width();
                }
                assert_eq!(
                    v,
                    &count + &n(1),
                    "subspace {subspace} from {open}: the runs tile the whole prefix"
                );
            }
        }
    }

    #[test]
    fn point_answers_m_of_d_and_folds_bad_positions_to_none() {
        let s = arranged();
        assert_eq!(s.point(&doc1(), &vp(1, 1)), Some(ca(1)));
        assert_eq!(s.point(&doc1(), &vp(1, 4)), Some(vca(1)));
        assert_eq!(s.point(&doc1(), &vp(1, 6)), None); // unarranged ordinal
        assert_eq!(s.point(&doc1(), &vp(3, 1)), None); // unknown subspace
        assert_eq!(s.point(&doc1(), &vp(1, 0)), None); // ordinal 0
        assert_eq!(s.point(&doc2(), &vp(1, 1)), None); // absent doc
        // Link subspace answers off the link run-list.
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
        assert_eq!(s.point(&doc1(), &vp(2, 1)), Some(la(1)));
    }

    #[test]
    fn image_is_the_concatenated_iextent_lift() {
        // §2: ⋃ r.iextent(), total, not normalized, possibly mixed-length.
        let s = arranged();
        let cov = s.image(&doc1(), &vspan(1, 1, 5));
        let spans: Vec<Span> = cov.iter().cloned().collect();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start().len(), 8);
        assert_eq!(spans[1].start().len(), 9); // mixed-length across origins
        assert!(cov.denotes(ca(2).tumbler()));
        assert!(cov.denotes(vca(2).tumbler()));
        assert!(!cov.denotes(ca(4).tumbler()));
    }

    #[test]
    fn project_maps_i_coverage_back_to_v_spans_in_both_branches() {
        let s = arranged();
        // Level-uniform, same-length branch: one element's extent.
        let one = SpanSet::singleton(run(&ca(2), 1).iextent());
        let got = s.project(&doc1(), &one);
        let spans: Vec<Span> = got.iter().cloned().collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start(), &t(&[1, 2]));
        assert_eq!(spans[0].width(), &t(&[0, 1]));
        // Cross-length fallback: doc1's content-base subtree (length 7) picks
        // out exactly the length-8 positions 1..3, not the transcluded tail.
        let base = subtree_of(&t(&[1, 0, 1, 0, 1, 0, 1]));
        let got = s.project(&doc1(), &SpanSet::singleton(base));
        let spans: Vec<Span> = got.iter().cloned().collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start(), &t(&[1, 1]));
        assert_eq!(spans[0].width(), &t(&[0, 3]));
        // Same-length but NOT level-uniform — M1's length-gated `intersect`
        // faults on it, so it takes the fallback too, and `project`'s
        // fault-free claim covers it. `[ca(3), [2])` opens inside the
        // length-8 run and reaches past every address either run holds, so
        // it takes that run's last position and all of the transcluded one:
        // ordinals 3, 4, 5, coalesced into one span.
        let cross = Span::new(ca(3).tumbler().clone(), t(&[1])).expect("T12: action point 1 ≤ 8");
        assert!(!cross.is_level_uniform());
        let got = s.project(&doc1(), &SpanSet::singleton(cross));
        let spans: Vec<Span> = got.iter().cloned().collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start(), &t(&[1, 3]));
        assert_eq!(spans[0].width(), &t(&[0, 3]));
        // Absent doc ⇒ ⟨⟩; empty coverage ⇒ ⟨⟩.
        assert!(s.project(&doc2(), &one).is_empty());
        assert!(s.project(&doc1(), &SpanSet::empty()).is_empty());
    }

    #[test]
    fn project_reports_content_positions_only() {
        // §2/BH3: I→V projection is the CONTENT subspace's, by construction —
        // link reverse-discovery is M7's. A link-subspace coverage has no
        // footprint here, and mixing one into a content coverage adds
        // nothing: the answer is the content footprint alone. The link
        // addresses share the content addresses' length class, so this is
        // decided by the run-lists consulted, not by a length mismatch.
        let s = arranged();
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(2) });
        let links = run(&la(1), 2).iextent();
        assert_eq!(links.start().len(), ca(1).tumbler().len());
        assert!(s.project(&doc1(), &SpanSet::singleton(links.clone())).is_empty());
        let mixed: SpanSet = vec![run(&ca(2), 1).iextent(), links].into_iter().collect();
        let got = s.project(&doc1(), &mixed);
        let spans: Vec<Span> = got.iter().cloned().collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start(), &t(&[1, 2]));
        assert_eq!(spans[0].width(), &t(&[0, 1]));
    }

    #[test]
    fn project_reports_fragmented_footprints() {
        // ASN-0119 RA7c: a footprint interrupted in V-space comes back as
        // separate V-spans (normalized, so truly separate ranges stay apart).
        let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 1)]);
        let s = place(&s, &doc1(), 2, vec![run(&vca(1), 1)]);
        let s = place(&s, &doc1(), 3, vec![run(&ca(2), 1)]);
        // Coverage over ca(1..2) hits V-ordinals 1 and 3, not 2.
        let cov = SpanSet::singleton(run(&ca(1), 2).iextent());
        let got = s.project(&doc1(), &cov);
        let spans: Vec<Span> = got.iter().cloned().collect();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start(), &t(&[1, 1]));
        assert_eq!(spans[1].start(), &t(&[1, 3]));
    }

    #[test]
    fn deletions_subtracts_within_each_level_class() {
        // §9: iextent covers mix origin-lengths under transclusion; the
        // difference runs within each endpoint-length class and unions the
        // results — different-length addresses cannot cancel.
        let s = arranged(); // ever: len-8 [ca1,ca4) + len-9 [vca1,vca3); image same
        assert!(s.deletions(&doc1()).is_empty());
        // Drop everything: both classes surface.
        let s = s.apply_m5(&M5Rec::ContentRemove {
            doc: doc1(),
            from: n(1),
            width: n(5),
        });
        assert_eq!(s.content_count(&doc1()), n(0));
        let d = s.deletions(&doc1());
        let spans: Vec<Span> = d.iter().cloned().collect();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start(), ca(1).tumbler()); // class 8 first (BTreeMap order)
        assert_eq!(spans[1].start(), vca(1).tumbler()); // then class 9
        // Absent doc: empty.
        assert!(s.deletions(&doc2()).is_empty());
    }

    #[test]
    fn docs_ever_containing_is_a_deterministic_overlap_superset() {
        // §9: not-Separated candidates (Adjacent included — a harmless
        // superset member the project filter removes), distinct keys, Tumbler
        // order.
        let s = place(&M5State::genesis(), &doc2(), 1, vec![run(&ca(1), 2)]);
        let s = place(&s, &doc1(), 1, vec![run(&ca(1), 2)]);
        let cov = SpanSet::singleton(run(&ca(1), 1).iextent());
        assert_eq!(s.docs_ever_containing(&cov), vec![doc1(), doc2()]);
        // Adjacent (touching, no shared position) still lands in the
        // candidate superset.
        let adj = SpanSet::singleton(run(&ca(3), 1).iextent());
        assert_eq!(s.docs_ever_containing(&adj), vec![doc1(), doc2()]);
        // Separated does not.
        let sep = SpanSet::singleton(run(&ca(9), 1).iextent());
        assert!(s.docs_ever_containing(&sep).is_empty());
        // A cross-length cover never faults (classify_spans is gate-free).
        let deep = SpanSet::singleton(subtree_of(a(&[1, 0, 1, 0, 1]).tumbler()));
        assert_eq!(s.docs_ever_containing(&deep), vec![doc1(), doc2()]);
    }

    #[test]
    fn ever_containing_keeps_a_ghost_the_present_tense_filter_drops() {
        // ASN-0124 FD-GHOST: doc1 places and then deletes what doc2 still
        // holds. The historical answer keeps doc1 (FD-RMONO — R never loses a
        // member); `project` is the present witness that separates them, and
        // the gap between the two answers IS `ghosts`.
        let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 2)]);
        let s = place(&s, &doc2(), 1, vec![run(&ca(1), 2)]);
        let s = s.apply_m5(&M5Rec::ContentRemove {
            doc: doc1(),
            from: n(1),
            width: n(2),
        });
        let cov = SpanSet::singleton(run(&ca(1), 2).iextent());
        assert_eq!(s.docs_ever_containing(&cov), vec![doc1(), doc2()]);
        assert!(s.project(&doc1(), &cov).is_empty()); // the ghost
        assert!(!s.project(&doc2(), &cov).is_empty()); // the live container
    }
}
