//! §D/§E — arrangement reads (resolve/point/coverage/project), the content
//! subspace's admission predicates, and the provenance reads
//! (deletions/docs_containing), pure over any M2 snapshot (§2, §9).
//!
//! **Level-class discipline** (§2): a SpanSet aggregated across runs —
//! coverage footprints, the internal `content_image`, a document's
//! `ever_placed` record — is in general MIXED-LENGTH (transclusion mixes
//! origin lengths), and M1's length-gated set ops fault `LevelMismatch` on
//! mixed operands. Where geometry is needed, M5 partitions each operand into
//! level-classes by endpoint length (`SpanSet::by_level_class`), runs the M1
//! op within each class, and unions the per-class results; where
//! overlap/membership suffices it uses the total `classify_spans`/`contains`.
//! The discipline is ENCAPSULATED behind the query methods
//! ([`M5State::project`], [`M5State::deletions`]) and OWED by whoever
//! aggregates run extents themselves — [`M5State::resolve_coverage`]'s raw
//! cover, and the runs [`M5State::resolve`] hands back for a caller to lift.
//! Both routes reach [`Run::iextent`], where the obligation is stated
//! (Conflicts #8).

use num_traits::{One, Zero};
use skep_address::{
    content_subspace, difference_sets, link_subspace, union, Address, Nat, Span, SpanSet, Tumbler,
};

use crate::run::Run;
use crate::state::M5State;
use crate::vspace::{is_ordinal_vspan, VPos};

impl M5State {
    /// V→I resolution (§2; ASN-0058 C0; ASN-0118 accept-and-intersect):
    /// I-runs covering an ORDINAL-LEVEL depth-2 V-span (width `[0, n]`,
    /// action point 2), V-ordered, clipped to the active range. Subspace from
    /// `span.start().get(1)`, count from `span.width().get(2)`.
    ///
    /// DEFENSIVE (returns ⟨⟩, cannot fault — no `Result`) unless the span is
    /// usable: a span failing [`is_ordinal_vspan`] — the shared, complete
    /// shape predicate, which COPY's `BadSpan` rejects on — yields ⟨⟩, and so
    /// does a shape-valid span whose subspace `start().get(1)` ∉ {s_C, s_L},
    /// a `DocArrangement` having exactly the content and link run-lists.
    /// Absent doc ⇒ ⟨⟩ (M6/M8 disambiguate registered-empty vs unallocated
    /// via M3). A caller that must tell "bad request" from "genuinely empty"
    /// calls the predicate itself before asking; M6's own request gate is
    /// deliberately WEAKER (ASN-0115 well-formedness, `#start ≥ 2`), leaving
    /// depth compatibility to this defensive fold.
    ///
    /// MIXED-LENGTH HAZARD for whoever aggregates the returned runs' extents:
    /// see [`Run::iextent`].
    pub fn resolve(&self, doc: &Address, span: &Span) -> Vec<Run> {
        if !is_ordinal_vspan(span) {
            return Vec::new();
        }
        let Some(arr) = self.arrangements.get(doc.tumbler()) else {
            return Vec::new();
        };
        let sub = span.start().get(1).expect("#start == 2");
        let list = if *sub == content_subspace() {
            &arr.content
        } else if *sub == link_subspace() {
            &arr.link
        } else {
            return Vec::new();
        };
        list.resolve_range(
            span.start().get(2).expect("#start == 2"),
            span.width().get(2).expect("#width == 2"),
        )
    }

    /// `M(d)(v)` (§2): the I-address at V-position `v`, or `None` when
    /// `v.subspace ∉ {s_C, s_L}` (no such run-list) or the ordinal is
    /// unarranged. Every returned `Address` is T4-valid (synthesis routes
    /// through `validate`).
    pub fn point(&self, doc: &Address, v: &VPos) -> Option<Address> {
        let arr = self.arrangements.get(doc.tumbler())?;
        let list = if v.subspace == content_subspace() {
            &arr.content
        } else if v.subspace == link_subspace() {
            &arr.link
        } else {
            return None;
        };
        list.point(&v.ordinal)
    }

    /// V→I coverage as a SpanSet (§2): `⋃ r.iextent()` over the runs
    /// [`resolve`](M5State::resolve) returns — the aggregate M6's
    /// FINDDOCSCONTAINING feeds to [`docs_containing`](M5State::docs_containing),
    /// lifted here so the query does not re-derive it. `union` (concatenation)
    /// only ⇒ total, never faults, NOT normalized; possibly mixed-length when
    /// `span` covers transcluded runs, so it is consumed under the level-class
    /// discipline (the hazard is stated on [`Run::iextent`], which every
    /// aggregator of run extents reaches, whether or not it comes through
    /// here).
    pub fn resolve_coverage(&self, doc: &Address, span: &Span) -> SpanSet {
        self.resolve(doc, span).into_iter().map(|r| r.iextent()).collect()
    }

    /// The canonical, V-ordered content run decomposition — maximally merged
    /// (ASN-0058 M12), the COMPARE surface for M6. Absent doc ⇒ `[]`.
    pub fn content_runs(&self, doc: &Address) -> Vec<Run> {
        self.arrangements
            .get(doc.tumbler())
            .map(|a| a.content.runs_vec())
            .unwrap_or_default()
    }

    /// The canonical, V-ordered link run decomposition. Absent doc ⇒ `[]`.
    pub fn link_runs(&self, doc: &Address) -> Vec<Run> {
        self.arrangements
            .get(doc.tumbler())
            .map(|a| a.link.runs_vec())
            .unwrap_or_default()
    }

    /// `n_C(d)` — the arranged content width. Absent doc ⇒ 0.
    pub fn content_count(&self, doc: &Address) -> Nat {
        self.arrangements
            .get(doc.tumbler())
            .map(|a| a.content.total_width())
            .unwrap_or_else(Nat::zero)
    }

    /// `n_L(d)` — the arranged link width. Absent doc ⇒ 0.
    pub fn link_count(&self, doc: &Address) -> Nat {
        self.arrangements
            .get(doc.tumbler())
            .map(|a| a.link.total_width())
            .unwrap_or_else(Nat::zero)
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

    /// Is content ordinal `ord` ARRANGED — a position holding an I-address,
    /// `ord ∈ [1, n_C]` (§4)? Answered off the run-list's own locate, which
    /// is the same walk `point` uses.
    pub(crate) fn content_position_arranged(&self, doc: &Address, ord: &Nat) -> bool {
        self.arrangements
            .get(doc.tumbler())
            .is_some_and(|a| a.content.locate(ord).is_some())
    }

    /// Does the arranged content contain the whole range `[from, from +
    /// width)` — `from + width ≤ n_C + 1`, subtraction-free (§4)? The
    /// containment half of DELETE's admission, stated where `n_C` lives.
    pub(crate) fn content_range_within(&self, doc: &Address, from: &Nat, width: &Nat) -> bool {
        from + width <= &self.content_count(doc) + &Nat::one()
    }

    /// Is `link` already seated in `doc`'s link subspace (§8, CL-UNIQ)?
    /// I-extent membership over the link run-list, so a link INTERIOR to a
    /// coalesced link run is caught too. Absent doc ⇒ not seated.
    pub(crate) fn seats_link(&self, doc: &Address, link: &Address) -> bool {
        self.arrangements.get(doc.tumbler()).is_some_and(|a| {
            a.link
                .iter_runs()
                .any(|(_, r)| r.iextent().contains(link.tumbler()))
        })
    }

    /// I→V projection (§2; ASN-0119 RA7c) — CONTENT subspace ONLY, by
    /// construction (link reverse-discovery is M7's BH3; there is no subspace
    /// argument): the V-positions of `doc` whose content I-address falls in
    /// `coverage` (a link footprint, possibly fragmented and mixed-length),
    /// as depth-2 V-spans, normalized. TOTAL — the level-class discipline is
    /// applied internally, so the call is fault-free for any coverage,
    /// including cross-length prefix/subtree spans.
    ///
    /// Per content run × coverage span: the run reports which of its offsets
    /// the span covers ([`Run::offsets_covered_by`], which owns both the
    /// same-level-class intersection and the cross-class boundary search),
    /// and this method turns that offset range into a V-range by adding the
    /// run's implicit V-start. Scan of the forward content map (Open decision
    /// #2 v1 default).
    pub fn project(&self, doc: &Address, coverage: &SpanSet) -> SpanSet {
        let Some(arr) = self.arrangements.get(doc.tumbler()) else {
            return SpanSet::empty();
        };
        let mut vspans: Vec<Span> = Vec::new();
        for (v_start, run) in arr.content.iter_runs() {
            for cspan in coverage.iter() {
                let Some((k_lo, k_hi)) = run.offsets_covered_by(cspan) else {
                    continue;
                };
                let start = Tumbler::new([content_subspace(), &v_start + &k_lo])
                    .expect("a two-component sequence is nonempty");
                let width = Tumbler::new([Nat::zero(), &k_hi - &k_lo])
                    .expect("a two-component sequence is nonempty");
                vspans.push(
                    Span::new(start, width).expect("ordinal-level depth-2 V-span is T12-valid"),
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
        self.arrangements
            .get(doc.tumbler())
            .map(|a| a.content.image())
            .unwrap_or_else(SpanSet::empty)
    }

    /// SHOWDELETIONS primitive (§9; ASN-0047 P2): what `doc` ever placed,
    /// minus its current content image, computed PER LEVEL-CLASS — both
    /// operands are iextent-covers that mix origin-lengths when `doc`
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
        for (len, ever) in self.prov.ever_placed(doc).by_level_class() {
            let here = image.get(&len).cloned().unwrap_or_else(SpanSet::empty);
            let d = difference_sets(&ever, &here)
                .expect("per-class operands share one length class — the gate passes");
            out = union(&out, &d);
        }
        out
    }

    /// R⁻¹ candidate documents (§9; Conflicts #6) — the historical
    /// overlap-superset the provenance record answers, which
    /// FINDDOCSCONTAINING then narrows with `project(d, coverage) ≠ ⟨⟩` off
    /// the same snapshot. Distinct, in deterministic Tumbler order.
    pub fn docs_containing(&self, coverage: &SpanSet) -> Vec<Address> {
        self.prov.docs_containing(coverage)
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
        assert!(s.resolve(&doc1(), &vspan(1, 1, 3)) == vec![run(&ca(1), 3)]);
        // #start ≠ 2 (both < 2 and > 2).
        let short = Span::new(t(&[5]), t(&[1])).expect("T12");
        assert!(s.resolve(&doc1(), &short).is_empty());
        let deep = Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).expect("T12");
        assert!(s.resolve(&doc1(), &deep).is_empty());
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
    fn resolve_clips_accept_and_intersect_and_orders_by_v() {
        // ASN-0118: over-reach silently clipped; V-order preserved across the
        // transclusion seam.
        let s = arranged();
        let got = s.resolve(&doc1(), &vspan(1, 2, 10));
        assert!(got == vec![run(&ca(2), 2), run(&vca(1), 2)]);
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
        assert!(s.content_position_arranged(&doc1(), &n(5)));
        assert!(!s.content_position_arranged(&doc1(), &n(6)));
        assert!(!s.content_position_arranged(&doc1(), &n(0)));
        assert!(!s.content_position_arranged(&doc2(), &n(1)));
        // Containment: [from, from + width) must fit the arranged content.
        assert!(s.content_range_within(&doc1(), &n(2), &n(4)));
        assert!(!s.content_range_within(&doc1(), &n(2), &n(5)));
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
    fn resolve_coverage_is_the_concatenated_iextent_lift() {
        // §2: ⋃ r.iextent(), total, not normalized, possibly mixed-length.
        let s = arranged();
        let cov = s.resolve_coverage(&doc1(), &vspan(1, 1, 5));
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
        // Absent doc ⇒ ⟨⟩; empty coverage ⇒ ⟨⟩.
        assert!(s.project(&doc2(), &one).is_empty());
        assert!(s.project(&doc1(), &SpanSet::empty()).is_empty());
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
    fn deletions_differences_per_level_class() {
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
    fn docs_containing_is_a_deterministic_overlap_superset() {
        // §9: not-Separated candidates (Adjacent included — a harmless
        // superset member the project filter removes), distinct keys, Tumbler
        // order.
        let s = place(&M5State::genesis(), &doc2(), 1, vec![run(&ca(1), 2)]);
        let s = place(&s, &doc1(), 1, vec![run(&ca(1), 2)]);
        let cov = SpanSet::singleton(run(&ca(1), 1).iextent());
        assert_eq!(s.docs_containing(&cov), vec![doc1(), doc2()]);
        // Adjacent (touching, no shared position) still lands in the
        // candidate superset.
        let adj = SpanSet::singleton(run(&ca(3), 1).iextent());
        assert_eq!(s.docs_containing(&adj), vec![doc1(), doc2()]);
        // Separated does not.
        let sep = SpanSet::singleton(run(&ca(9), 1).iextent());
        assert!(s.docs_containing(&sep).is_empty());
        // A cross-length cover never faults (classify_spans is gate-free).
        let deep = SpanSet::singleton(subtree_of(a(&[1, 0, 1, 0, 1]).tumbler()));
        assert_eq!(s.docs_containing(&deep), vec![doc1(), doc2()]);
    }
}
