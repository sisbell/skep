//! §D/§E — arrangement reads (resolve/point/coverage/project) and provenance
//! reads (deletions/docs_containing), pure over any M2 snapshot (§2, §9).
//!
//! **Level-class discipline** (§2): a SpanSet aggregated across runs —
//! coverage footprints, the internal `content_image`/`ever_placed` — is in
//! general MIXED-LENGTH (transclusion mixes origin lengths), and M1's
//! length-gated set ops fault `LevelMismatch` on mixed operands. Where
//! geometry is needed, M5 partitions each operand into level-classes by
//! endpoint length, runs the M1 op within each class, and unions the
//! per-class results; where overlap/membership suffices it uses the total
//! `classify_spans`/`contains`. The discipline is ENCAPSULATED behind the M6
//! query methods ([`M5State::project`], [`M5State::deletions`]) and EXPOSED
//! on exactly one seam — [`M5State::resolve_coverage`], whose raw cover
//! carries the consume-under-the-discipline contract (Conflicts #8).

use std::collections::BTreeMap;

use num_traits::{One, Zero};
use skep_address::{
    classify_spans, difference_sets, intersect, shift, union, validate, Address, Nat, Span,
    SpanRel, SpanSet, Tumbler,
};

use crate::error::VPos;
use crate::run::Run;
use crate::state::M5State;
use crate::{s_c, s_l};

/// Boundary search over a run's offsets (§2 project, cross-class fallback):
/// the least `k ∈ [0, width]` with `shift(i_start, k) ≥ bound`. Monotone in
/// `k` (TS1 strict order), so binary search applies; total across lengths
/// (`Tumbler`'s order is defined over all of the carrier).
fn lower_bound(run: &Run, bound: &Tumbler) -> Nat {
    let mut lo = Nat::zero();
    let mut hi = run.width().clone();
    let two = Nat::from(2u32);
    while lo < hi {
        let mid = (&lo + &hi) / &two;
        if shift(run.i_start().tumbler(), &mid) >= *bound {
            hi = mid;
        } else {
            lo = &mid + &Nat::one();
        }
    }
    lo
}

impl M5State {
    /// V→I resolution (§2; ASN-0058 C0; ASN-0118 accept-and-intersect):
    /// I-runs covering an ORDINAL-LEVEL depth-2 V-span (width `[0, n]`,
    /// action point 2), V-ordered, clipped to the active range. Subspace from
    /// `span.start().get(1)`, count from `span.width().get(2)`.
    ///
    /// DEFENSIVE (returns ⟨⟩, cannot fault — no `Result`) unless the span is
    /// usable — the COMPLETE guard is `#start == 2 ∧ #width == 2 ∧
    /// span.width().get(1) == 0`; in particular `#start ≠ 2` (both < 2 and
    /// > 2), `#width ≠ 2`, or a non-ordinal width (a level-uniform `[m, n]`
    /// with m > 0 is action-point-1, making `get(2)` the wrong extraction)
    /// each yield ⟨⟩. A shape-valid span whose subspace `start().get(1)` ∉
    /// {s_C, s_L} likewise yields ⟨⟩ — a `DocArrangement` has exactly the
    /// content and link run-lists. Absent doc ⇒ ⟨⟩ (M6/M8 disambiguate
    /// registered-empty vs unallocated via M3). The guard is published as
    /// COMPLETE precisely so M6 can pre-validate request-built V-spans and
    /// distinguish "bad request" from "genuinely empty" up front.
    pub fn resolve(&self, doc: &Address, span: &Span) -> Vec<Run> {
        if span.start().len() != 2 || span.width().len() != 2 || !span.width().get(1).is_zero() {
            return Vec::new();
        }
        let Some(arr) = self.arrangements.get(doc.tumbler()) else {
            return Vec::new();
        };
        let sub = span.start().get(1);
        let list = if *sub == s_c() {
            &arr.content
        } else if *sub == s_l() {
            &arr.link
        } else {
            return Vec::new();
        };
        list.resolve_range(span.start().get(2), span.width().get(2))
    }

    /// `M(d)(v)` (§2): the I-address at V-position `v`, or `None` when
    /// `v.subspace ∉ {s_C, s_L}` (no such run-list) or the ordinal is
    /// unarranged. Every returned `Address` is T4-valid (synthesis routes
    /// through `validate`).
    pub fn point(&self, doc: &Address, v: &VPos) -> Option<Address> {
        let arr = self.arrangements.get(doc.tumbler())?;
        let list = if v.subspace == s_c() {
            &arr.content
        } else if v.subspace == s_l() {
            &arr.link
        } else {
            return None;
        };
        list.point(&v.ordinal)
    }

    /// V→I coverage as a SpanSet (§2): `⋃ r.iextent()` over the runs
    /// [`resolve`](M5State::resolve) returns — the centralized correct lift,
    /// so M7's MAKELINK never re-derives `iextent`. `union` (concatenation)
    /// only ⇒ total, never faults, NOT normalized; possibly mixed-length when
    /// `span` covers transcluded runs — consume under the level-class
    /// discipline. In particular, because a transcluded endset's I-coverage
    /// is mixed-length and M1's `canonical_key` is length-gated, M7 MUST form
    /// its coverage-class dedup key PER LEVEL-CLASS (one `canonical_key` per
    /// endpoint-length partition, the per-class results combined), never by a
    /// single `canonical_key` over the raw cover — which would fault
    /// `LevelMismatch`.
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

    /// I→V projection (§2; ASN-0119 RA7c) — CONTENT subspace ONLY, by
    /// construction (link reverse-discovery is M7's BH3; there is no subspace
    /// argument): the V-positions of `doc` whose content I-address falls in
    /// `coverage` (a link footprint, possibly fragmented and mixed-length),
    /// as depth-2 V-spans, normalized. TOTAL — the level-class discipline is
    /// applied internally, so the call is fault-free for any coverage,
    /// including cross-length prefix/subtree spans.
    ///
    /// Per content run × coverage span: a level-uniform span of the run's
    /// I-extent length is intersected with M1 (`intersect`, within one level
    /// class) and the I-sub-extent maps at equal offset to a V-sub-range;
    /// any other span — different length, or same-length but non-uniform
    /// (which `intersect` would fault on) — falls back to the total
    /// order-convex membership boundary search ([`lower_bound`]). Scan of the
    /// forward content map (Open decision #2 v1 default).
    pub fn project(&self, doc: &Address, coverage: &SpanSet) -> SpanSet {
        let Some(arr) = self.arrangements.get(doc.tumbler()) else {
            return SpanSet::empty();
        };
        let mut vspans: Vec<Span> = Vec::new();
        for (v_start, run) in arr.content.iter_runs() {
            let ilen = run.i_start().tumbler().len();
            for cspan in coverage.iter() {
                let seg: Option<(Nat, Nat)> =
                    if cspan.is_level_uniform() && cspan.start().len() == ilen {
                        match intersect(&run.iextent(), cspan)
                            .expect("both operands level-uniform at one length — gate passes")
                        {
                            None => None,
                            Some(sub) => {
                                // The intersection lies inside the run's
                                // extent, so both endpoints share the run's
                                // prefix; offsets are last-component
                                // differences.
                                let base = run.i_start().tumbler().get(ilen);
                                let reach = sub.reach();
                                Some((sub.start().get(ilen) - base, reach.get(ilen) - base))
                            }
                        }
                    } else {
                        // Cross-class (or non-uniform) fallback: the run's
                        // addresses are contiguous and a span is order-convex,
                        // so the contained subset is one contiguous index
                        // range [k_lo, k_hi).
                        let k_lo = lower_bound(run, cspan.start());
                        let reach = cspan.reach();
                        let k_hi = lower_bound(run, &reach);
                        if k_lo < k_hi {
                            Some((k_lo, k_hi))
                        } else {
                            None
                        }
                    };
                let Some((k_lo, k_hi)) = seg else { continue };
                let start = Tumbler::new([s_c(), &v_start + &k_lo])
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

    /// R↾doc (M5-INTERNAL — the `deletions` operand, Conflicts #8): the
    /// iextent cover of content spans ever placed by `doc`. Raw and possibly
    /// mixed-length; it never crosses a module seam.
    fn ever_placed(&self, doc: &Address) -> SpanSet {
        self.prov_by_doc
            .get(doc.tumbler())
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_else(SpanSet::empty)
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

    /// SHOWDELETIONS primitive (§9; ASN-0047 P2): `ever_placed(doc) ∖
    /// content_image(doc)`, computed PER LEVEL-CLASS inside M5 — both
    /// operands are iextent-covers that mix origin-lengths when `doc`
    /// transcludes across heterogeneous-depth documents, so M5 partitions
    /// each by endpoint length, runs `difference_sets` within each class, and
    /// unions the results. Per-class is also the correct semantics:
    /// different-length addresses are distinct and cannot cancel. M6 reads
    /// SHOWDELETIONS straight off this — neither operand crosses the
    /// boundary. Fault-free.
    pub fn deletions(&self, doc: &Address) -> SpanSet {
        let ever = self.ever_placed(doc);
        let image = self.content_image(doc);
        let mut ever_by: BTreeMap<usize, Vec<Span>> = BTreeMap::new();
        for s in ever.iter() {
            ever_by.entry(s.start().len()).or_default().push(s.clone());
        }
        let mut image_by: BTreeMap<usize, Vec<Span>> = BTreeMap::new();
        for s in image.iter() {
            image_by.entry(s.start().len()).or_default().push(s.clone());
        }
        let mut out = SpanSet::empty();
        for (len, spans) in ever_by {
            let e: SpanSet = spans.into_iter().collect();
            let i: SpanSet = image_by
                .remove(&len)
                .map(|v| v.into_iter().collect())
                .unwrap_or_else(SpanSet::empty);
            let d = difference_sets(&e, &i)
                .expect("per-class operands share one length class — the gate passes");
            out = union(&out, &d);
        }
        out
    }

    /// R⁻¹ candidate documents (§9; Conflicts #6): every document with some
    /// placed span not `Separated` from some span of `coverage` under M1's
    /// total, length-gate-free `classify_spans`. An overlap-SUPERSET (no
    /// false negatives — a genuinely contained address forces order-overlap);
    /// FINDDOCSCONTAINING narrows each candidate with
    /// `project(d, coverage) ≠ ⟨⟩` off the same snapshot. Returns
    /// `Vec<Address>` in distinct, deterministic Tumbler order (the `OrdMap`
    /// walk supplies the order; the sequence shape is M5's own choice of
    /// surface). M5 owns R and any index over it (Open decision
    /// #3: v1 scans `prov_by_doc`); M6 owns only the composing query.
    pub fn docs_containing(&self, coverage: &SpanSet) -> Vec<Address> {
        let mut out = Vec::new();
        for (k, spans) in self.prov_by_doc.iter() {
            let hit = spans
                .iter()
                .any(|p| coverage.iter().any(|c| classify_spans(p, c) != SpanRel::Separated));
            if hit {
                out.push(
                    validate(k.clone())
                        .expect("prov keys are registered-document tumblers (T4-valid)"),
                );
            }
        }
        out
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
