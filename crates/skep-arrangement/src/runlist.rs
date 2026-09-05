//! §1 — the implicit-position run-list, per subspace: locate, splice,
//! contract, reorder, eager seam-coalesce (ASN-0058 M12/M14/M16; ASN-0082
//! shift-absorption; ASN-0117 P2; ASN-0119 tile-by-placement).
//!
//! A `RunList` is an ordered sequence of [`Run`]s; V-positions are NOT
//! stored — run *j* occupies the ordinals `[1 + Σ_{i<j} widthᵢ, …]`. This one
//! choice makes the load-bearing invariants free: density / contiguity /
//! minimum-position (D-SEQ★/D-CTG★/D-MIN★) hold by construction (a V-start is
//! always a prefix sum, so no holes), and insert/delete shift the suffix for
//! free (the spec's ASN-0082 displacement is never computed).
//!
//! OPEN DECISION #1 (default taken): the physical persistent structure is
//! `im::Vector<Run>` — free structural sharing (VERSION's O(1) fork share,
//! cheap state clones), O(#runs) locate/splice, fine because #runs scales
//! with transclusions/edit-sessions, not characters. The width-measured tree
//! and `im::OrdMap<ordinal, Run>` alternatives are profiling-gated.

use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use skep_address::{Address, Nat, SpanSet};

use crate::run::Run;

/// I-adjacency (ASN-0058): the right run starts exactly where the left run
/// [`reaches`](Run::reach), so their I-extents abut with no address between.
///
/// THE WHOLE RESIDUAL MERGE TEST. ASN-0058's merge condition (M7) is a
/// conjunction — two blocks may merge iff they are both V-adjacent
/// (`v₂ = v₁ + w₁`) and I-adjacent — and the first conjunct is discharged by
/// the representation: consecutive entries of an implicit-position run-list
/// occupy consecutive V-ordinals, so every neighbouring pair this guard is
/// asked about is already V-adjacent (§1 — the same representation choice
/// that makes D-SEQ★/D-CTG★/D-MIN★ hold). I-adjacency is therefore all that
/// remains to test — and it is also the SAFE half: `a₂ = a₁ + w₁` implies
/// same origin (M16a) and excludes shared-I-extent (M14a), and it is
/// vacuously false across origin-lengths (the reach is length-preserving), so
/// cross-length runs never merge — never across an origin seam (M16), never
/// collapsing a transclusion (M14). **Never coalesce on value** (S4).
///
/// Asked of the left run rather than computed here: the ordinal advance and
/// its TA7a safety argument belong to [`Run`], which states them once.
pub(crate) fn i_adjacent(left: &Run, right_start: &Address) -> bool {
    left.reach() == *right_start.tumbler()
}

/// The placing ops' run accumulator (§1): widen the last run iff I-adjacent,
/// else push. THE ONE PLACE a placement's runs are accumulated, so the merge
/// condition is applied by the element that owns it and no caller decides
/// for itself that two addresses belong to one run — an address that is not
/// I-adjacent to the open run opens a new one, rather than widening a run
/// over the addresses between them.
///
/// Cross-origin runs are cross-length, fail the I-adjacency test, and never
/// coalesce — preserving the origin multiset (ASN-0118 CP11) and
/// transclusion independence (CP4/M14).
pub(crate) fn extend_or_push_run(runs: &mut Vec<Run>, run: Run) {
    if let Some(last) = runs.last_mut() {
        if i_adjacent(last, &run.i_start) {
            last.width = &last.width + &run.width;
            return;
        }
    }
    runs.push(run);
}

/// Eager coalesce (§1, Open decision #8 default): one pass accumulating
/// through [`extend_or_push_run`], so the merge condition is applied by the
/// one element that owns it. Behaviorally identical to seam-only coalescing
/// given the inductive invariant (the resident list is always maximally
/// merged, so only touched seams can newly merge); a full pass cannot miss a
/// seam. The resident form is then the unique maximally-merged decomposition
/// (ASN-0058 M12), so queries read run structure directly.
fn coalesced(runs: Vec<Run>) -> im::Vector<Run> {
    let mut out: Vec<Run> = Vec::with_capacity(runs.len());
    for run in runs {
        extend_or_push_run(&mut out, run);
    }
    out.into_iter().collect()
}

/// Split a run sequence at the ordinal boundary BEFORE `ord`: the prefix
/// covers ordinals `[1, ord)`, the suffix `[ord, total]`. The append boundary
/// `ord = total + 1` — INSERT/COPY's `J = N + 1` and the link-seat append
/// `n_L(d) + 1` — returns (all, empty), so a splice concatenates at the tail
/// (§1). `ord ≤ 1` returns (empty, all) — the defensive clamp under which a
/// split at 0 and at 1 coincide (ASN-0119 tile-by-placement note). An
/// interior `ord` splits the boundary run `Run(a, w) → Run(a, c),
/// Run(a ⊕ c, w − c)` via [`Run::addr_at`](crate::Run::addr_at).
///
/// Over an ITERATOR, not a `RunList`: the ops that split twice (contract,
/// clip, transpose) split a `Vec<Run>` the first split produced, and a
/// splitter that demanded a `RunList` would make each of them rebuild one.
fn split_runs<'a>(mut runs: impl Iterator<Item = &'a Run>, ord: &Nat) -> (Vec<Run>, Vec<Run>) {
    let one = Nat::one();
    if *ord <= one {
        return (Vec::new(), runs.cloned().collect());
    }
    let mut left: Vec<Run> = Vec::new();
    let mut before = Nat::zero();
    while let Some(run) = runs.next() {
        let start = &before + &one; // this run's first ordinal
        if *ord == start {
            // Boundary before this run.
            let mut right: Vec<Run> = vec![run.clone()];
            right.extend(runs.cloned());
            return (left, right);
        }
        let end = &before + &run.width; // this run's last ordinal
        if *ord <= end {
            // Interior: keep c = ord − start elements on the left
            // (1 ≤ c ≤ width − 1 here).
            let c = ord - &start;
            let right_first = Run {
                i_start: run.addr_at(&c),
                width: &run.width - &c,
            };
            left.push(Run {
                i_start: run.i_start.clone(),
                width: c,
            });
            let mut right: Vec<Run> = vec![right_first];
            right.extend(runs.cloned());
            return (left, right);
        }
        left.push(run.clone());
        before = end;
    }
    (left, Vec::new()) // ord ≥ total + 1: the append boundary
}

/// The per-subspace run-list (§Core data model). All mutators are persistent
/// (`&self → RunList`); the `im::Vector` backing keeps clones O(1) (VERSION's
/// structural fork share) while the v1 surgery below is Vec-based O(#runs).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RunList(im::Vector<Run>);

impl RunList {
    /// `n(d)` for this subspace — the total arranged width.
    pub(crate) fn total_width(&self) -> Nat {
        self.0.iter().fold(Nat::zero(), |acc, r| acc + &r.width)
    }

    /// Walk runs accumulating widths until the sum reaches `ord`; return the
    /// run index and the 0-based offset within it. `None` when `ord` is 0 or
    /// past the last arranged ordinal (§1 locate).
    pub(crate) fn locate(&self, ord: &Nat) -> Option<(usize, Nat)> {
        if ord.is_zero() {
            return None;
        }
        let mut before = Nat::zero();
        for (idx, run) in self.0.iter().enumerate() {
            let end = &before + &run.width;
            if *ord <= end {
                return Some((idx, ord - &before - Nat::one()));
            }
            before = end;
        }
        None
    }

    /// `M(d)(p)` for this subspace: the I-address at ordinal `ord`, or `None`
    /// when unarranged (§2 point).
    pub(crate) fn point(&self, ord: &Nat) -> Option<Address> {
        let (idx, off) = self.locate(ord)?;
        let run = self.0.get(idx).expect("locate returns an in-range index");
        Some(run.addr_at(&off))
    }

    /// Does this list hold `a` — is the address inside some run's I-extent
    /// (§8)? The I-side twin of [`locate`](RunList::locate)/
    /// [`point`](RunList::point), which answer the same membership question
    /// from the V-side: an address INTERIOR to a coalesced run counts, runs
    /// being contiguous extents rather than enumerated addresses. CL-UNIQ asks
    /// this of a document's link list.
    pub(crate) fn holds(&self, a: &Address) -> bool {
        self.0.iter().any(|r| r.iextent().contains(a.tumbler()))
    }

    /// [`split_runs`] over this list's runs.
    fn split_at(&self, ord: &Nat) -> (Vec<Run>, Vec<Run>) {
        split_runs(self.0.iter(), ord)
    }

    /// Splice `new_runs` in at `ord` (§1): split, insert, concat, coalesce.
    /// The suffix's implicit positions are now `+Σ width(new_runs)` — the
    /// uniform forward shift, for free.
    #[must_use = "splice_in returns the new run-list; it does not modify the receiver"]
    pub(crate) fn splice_in(&self, ord: &Nat, new_runs: &[Run]) -> RunList {
        let (mut acc, right) = self.split_at(ord);
        acc.extend(new_runs.iter().cloned());
        acc.extend(right);
        RunList(coalesced(acc))
    }

    /// Add `run` after everything this list already holds — the append
    /// boundary `total + 1`, which [`split_runs`] names, the content ops reach
    /// through `admits_content_boundary`, and the link seat targets (§8's
    /// `n_L(d) + 1`). Where the end IS is this list's knowledge, so a caller
    /// meaning "after everything" says that rather than computing it.
    /// Coalesces with the last run when I-adjacent, as any splice does.
    #[must_use = "append returns the new run-list; it does not modify the receiver"]
    pub(crate) fn append(&self, run: Run) -> RunList {
        self.splice_in(&(self.total_width() + Nat::one()), &[run])
    }

    /// Remove ordinals `[from, from + width)` and close the gap (§1): split at
    /// `from` and `from + width`, drop the middle, concat prefix + suffix.
    /// Suffix positions shift left for free; the gap closes by construction
    /// (ASN-0117 P2).
    #[must_use = "remove_range returns the new run-list; it does not modify the receiver"]
    pub(crate) fn remove_range(&self, from: &Nat, width: &Nat) -> RunList {
        let (mut left, rest) = self.split_at(from);
        // The removed range is rest-relative ordinals [1, width].
        let (_dropped, right) = split_runs(rest.iter(), &(width + &Nat::one()));
        left.extend(right);
        RunList(coalesced(left))
    }

    /// Cut-determined, value-blind transpose (§1; ASN-0119): split at each of
    /// the cut sequence's ordinals `ord(cⱼ)` and **tile by placement** —
    /// `[exterior-left][β][μ?][α][exterior-right]` — never offset arithmetic,
    /// so the bijection is structural (no swap-α offset bug, ASN-0084 Q14).
    /// 3 ordinals: pivot (α = [c₀,c₁), β = [c₁,c₂) exchange). 4: swap
    /// (α = [c₀,c₁), μ = [c₁,c₂), β = [c₂,c₃); outer two exchange, middle
    /// stays).
    ///
    /// Pivot and swap are ONE computation. Splitting off the exterior-right
    /// first and then descending through the remaining ordinals peels the
    /// interior regions off right-to-left — β, then μ where there is one, then
    /// α — so emitting them in the order they were peeled IS the exchange,
    /// whatever the region count. A cut sequence outside R-PRE is outside the
    /// fold's input class (§10) and 3|4 is debug-asserted; the tiling is
    /// nonetheless total for any vector — with fewer than three ordinals there
    /// is no interior region to move, so the list comes back unchanged.
    #[must_use = "reorder returns the new run-list; it does not modify the receiver"]
    pub(crate) fn reorder(&self, cut_ordinals: &[Nat]) -> RunList {
        debug_assert!(
            matches!(cut_ordinals.len(), 3 | 4),
            "R-PRE: 3 or 4 cut ordinals (validated at staging)"
        );
        let Some((last, interior)) = cut_ordinals.split_last() else {
            return self.clone();
        };
        // Descending splits on the prefix keep absolute coordinates.
        let (mut prefix, ext_right) = self.split_at(last);
        let mut regions: Vec<Vec<Run>> = Vec::with_capacity(interior.len());
        for cut in interior.iter().rev() {
            let (left, region) = split_runs(prefix.iter(), cut);
            regions.push(region);
            prefix = left;
        }
        let mut out = prefix; // what lies left of the first cut
        for region in regions {
            out.extend(region);
        }
        out.extend(ext_right);
        RunList(coalesced(out))
    }

    /// The runs covering ordinals `[lo, hi_excl)`, the boundary runs clipped
    /// — MATERIALIZING ONLY THE ANSWER. One prefix-sum walk that skips the
    /// runs left of `lo`, stops at the first run at or past `hi_excl`, and
    /// clones nothing outside the range: the cost of a read is the size of
    /// what it returns, not the size of the list it reads from. That matters
    /// because a resolution's caller is a per-spec loop — COPY's, M7's slot
    /// endsets, M6's RETRIEVEV — so any per-call term proportional to the
    /// SOURCE's fragmentation is multiplied by the request's spec count.
    ///
    /// Called with `lo < hi_excl`. Every emitted run then has `width ≥ 1` and
    /// an element-level start: a run reaching the push has `v_start < hi_excl`
    /// and `lo < v_end`, and `v_start < v_end` because a run's width is at
    /// least one, so each of `first`'s two candidates falls below each of
    /// `past`'s and `first < past`; the start is
    /// [`Run::addr_at`](crate::Run::addr_at) of an offset inside the run. Both
    /// `Nat` subtractions are therefore over ordered operands and cannot
    /// underflow.
    fn slice_runs(&self, lo: &Nat, hi_excl: &Nat) -> Vec<Run> {
        let mut out: Vec<Run> = Vec::new();
        for (v_start, run) in self.iter_runs() {
            if v_start >= *hi_excl {
                break;
            }
            let v_end = &v_start + &run.width; // the first ordinal past this run
            if v_end <= *lo {
                continue;
            }
            let first = std::cmp::max(&v_start, lo); // this run's first kept ordinal
            let past = std::cmp::min(&v_end, hi_excl); // one past its last
            out.push(Run {
                i_start: run.addr_at(&(first - &v_start)),
                width: past - first,
            });
        }
        out
    }

    /// I-runs covering ordinals `[ord, ord + count)`, clipped to the arranged
    /// range — accept-and-intersect: out-of-range is silently dropped
    /// (ASN-0118). V-ordered by construction.
    ///
    /// The upper clip needs no `total_width`: no run reaches past `total + 1`,
    /// so clipping each run at `hi_excl` already drops everything beyond the
    /// arrangement, and asking for the total would be a second walk of the
    /// whole list to learn a bound the walk enforces anyway.
    pub(crate) fn resolve_range(&self, ord: &Nat, count: &Nat) -> Vec<Run> {
        let lo = std::cmp::max(ord.clone(), Nat::one());
        let hi_excl = ord + count;
        if lo >= hi_excl {
            return Vec::new();
        }
        self.slice_runs(&lo, &hi_excl)
    }

    /// Iterate `(v_start, run)` pairs — the implicit V-start is the running
    /// prefix sum + 1 (§1 iter_runs).
    pub(crate) fn iter_runs(&self) -> impl Iterator<Item = (Nat, &Run)> + '_ {
        let mut v_start = Nat::one();
        self.0.iter().map(move |r| {
            let s = v_start.clone();
            v_start = &v_start + &r.width;
            (s, r)
        })
    }

    /// The canonical, V-ordered run decomposition (maximally merged — M12).
    /// The runs alone; [`iter_runs`](RunList::iter_runs) is the form that
    /// also reports each run's implicit V-start.
    pub(crate) fn runs(&self) -> Vec<Run> {
        self.0.iter().cloned().collect()
    }

    /// The I-image as a SpanSet: `⋃ r.iextent()` — union (concatenation)
    /// only, total, NOT normalized, possibly mixed-length across transcluded
    /// origins (§2). M5-internal consumers apply the level-class discipline.
    pub(crate) fn image(&self) -> SpanSet {
        self.0.iter().map(Run::iextent).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ca, n, run, vca};

    fn list(runs: Vec<Run>) -> RunList {
        RunList(runs.into_iter().collect())
    }

    #[test]
    fn splice_at_the_append_boundary_concatenates_and_coalesces_iff_i_adjacent() {
        // §1: ord = total + 1 is the single accepted ord > total; I-adjacent
        // appends merge (M12), non-adjacent stay separate.
        let l = list(vec![run(&ca(1), 3)]);
        let merged = l.splice_in(&n(4), &[run(&ca(4), 2)]); // shift(ca(1),3) = ca(4): adjacent
        assert_eq!(merged.runs(), vec![run(&ca(1), 5)]);
        let apart = l.splice_in(&n(4), &[run(&ca(9), 1)]); // not adjacent
        assert_eq!(apart.runs(), vec![run(&ca(1), 3), run(&ca(9), 1)]);
        assert_eq!(apart.total_width(), n(4));
    }

    #[test]
    fn the_list_answers_where_its_end_is_and_what_it_holds() {
        // §1/§8: appending is stated as "after everything", so the boundary
        // `total + 1` is computed by the list that knows its own total —
        // including the empty case, where that boundary is ordinal 1.
        let empty = RunList::default();
        let one = empty.append(run(&ca(1), 1));
        assert_eq!(one.runs(), vec![run(&ca(1), 1)]);
        assert_eq!(one.point(&n(1)), Some(ca(1)));
        // An I-adjacent append coalesces, a non-adjacent one opens a run, and
        // both land past everything already arranged.
        let merged = one.append(run(&ca(2), 1));
        assert_eq!(merged.runs(), vec![run(&ca(1), 2)]);
        let apart = merged.append(run(&ca(9), 1));
        assert_eq!(apart.runs(), vec![run(&ca(1), 2), run(&ca(9), 1)]);
        assert_eq!(apart.point(&n(3)), Some(ca(9)));
        // Membership is over I-extents, so an address INTERIOR to a coalesced
        // run counts — which is the whole of what CL-UNIQ asks.
        assert!(apart.holds(&ca(1)));
        assert!(apart.holds(&ca(2)));
        assert!(apart.holds(&ca(9)));
        assert!(!apart.holds(&ca(3)));
        assert!(!empty.holds(&ca(1)));
        // A different origin length is held by nobody here.
        assert!(!apart.holds(&vca(1)));
    }

    #[test]
    fn interior_splice_splits_the_boundary_run_and_shifts_the_suffix() {
        // §1: Run(a, w) → Run(a, c), Run(a ⊕ c, w − c); suffix positions move
        // +Σ width for free.
        let l = list(vec![run(&ca(1), 4)]);
        let spliced = l.splice_in(&n(3), &[run(&ca(9), 1)]);
        assert_eq!(
            spliced.runs(),
            vec![run(&ca(1), 2), run(&ca(9), 1), run(&ca(3), 2)]
        );
        // point: implicit positions after the shift.
        assert_eq!(spliced.point(&n(2)), Some(ca(2)));
        assert_eq!(spliced.point(&n(3)), Some(ca(9)));
        assert_eq!(spliced.point(&n(4)), Some(ca(3)));
        assert_eq!(spliced.point(&n(6)), None);
    }

    #[test]
    fn remove_range_closes_the_gap_and_recoalesces_rejoined_neighbours() {
        // ASN-0117 P2: contract-then-reseat; the two survivors of one origin
        // run are I-adjacent again only if the removed middle made them so —
        // here removing an interleaved foreign run rejoins ca(1..2) & ca(3..4).
        let l = list(vec![run(&ca(1), 2), run(&vca(5), 1), run(&ca(3), 2)]);
        let out = l.remove_range(&n(3), &n(1));
        assert_eq!(out.runs(), vec![run(&ca(1), 4)]);
        // And an interior removal within one run splits then re-shifts.
        let l2 = list(vec![run(&ca(1), 5)]);
        let out2 = l2.remove_range(&n(2), &n(2));
        assert_eq!(out2.runs(), vec![run(&ca(1), 1), run(&ca(4), 2)]);
        assert_eq!(out2.total_width(), n(3));
    }

    #[test]
    fn cross_length_runs_never_coalesce() {
        // §1: the I-adjacency guard is vacuously false across origin lengths
        // (shift preserves length) — a transclusion seam survives (M14/M16).
        let l = list(vec![run(&ca(1), 1)]);
        let out = l.splice_in(&n(2), &[run(&vca(1), 1)]); // vca is length 9, ca length 8
        assert_eq!(out.runs().len(), 2);
    }

    #[test]
    fn reorder_tiles_by_placement() {
        // ASN-0119: pivot (3 cuts) exchanges the two adjacent regions; swap
        // (4 cuts) exchanges the outer two around the fixed middle.
        let l = list(vec![run(&ca(1), 5)]); // ordinals 1..5 ↦ ca(1..5)
        let pivot = l.reorder(&[n(2), n(4), n(6)]); // α = {2,3}, β = {4,5}
        let got: Vec<Address> = (1..=5).map(|i| pivot.point(&n(i)).expect("arranged")).collect();
        assert_eq!(got, vec![ca(1), ca(4), ca(5), ca(2), ca(3)]);
        let swap = l.reorder(&[n(1), n(2), n(3), n(4)]); // α={1}, μ={2}, β={3}
        let got: Vec<Address> = (1..=5).map(|i| swap.point(&n(i)).expect("arranged")).collect();
        assert_eq!(got, vec![ca(3), ca(2), ca(1), ca(4), ca(5)]);
        // Pure permutation: width preserved.
        assert_eq!(swap.total_width(), n(5));
    }

    #[test]
    fn reorder_recoalesces_the_neighbours_the_transposition_rejoins() {
        // ASN-0058 M12: the resident form is the unique MAXIMALLY MERGED
        // decomposition, and reorder must re-establish it — an exchange can
        // put two runs of one origin side by side that a foreign run had
        // separated. Over a single contiguous run no admissible cut vector
        // can produce a merge (strict ascent forbids adjacency at all three
        // new seams), which is why the exhaustive tiling test below cannot
        // see this and why the fixture here is fragmented across two origin
        // lengths.
        let l = list(vec![run(&ca(1), 1), run(&vca(1), 1), run(&ca(2), 1)]);
        let out = l.reorder(&[n(1), n(2), n(3)]); // pivot: α = {1}, β = {2}
        // V-order becomes vca1, ca1, ca2 — and ca1 REACHES ca2, so the tail
        // merges. Without the coalesce the list holds three runs denoting
        // the same addresses, which no `point` or `total_width` assertion
        // can see.
        assert_eq!(out.runs(), vec![run(&vca(1), 1), run(&ca(1), 2)]);
        assert_eq!(out.total_width(), n(3));
        // The permutation itself is what it was; the merge is about
        // structure, not about which address sits where.
        let got: Vec<Address> = (1..=3).map(|i| out.point(&n(i)).expect("arranged")).collect();
        assert_eq!(got, vec![vca(1), ca(1), ca(2)]);
    }

    #[test]
    fn reorder_tiles_by_placement_for_every_admissible_cut_vector() {
        // ASN-0119/ASN-0084 Q14: the tiling is a law over the whole
        // R-PRE-admissible input class, and at n_C = 5 that class is small
        // enough to exhaust — the strictly ascending 3- and 4-subsets of the
        // admissible boundaries [1, n_C + 1], 20 + 15 = 35 vectors. The two
        // worked examples above test two of them; the swap-α offset bug this
        // construction exists to avoid is exactly the kind that survives a
        // chosen example. The expectation is built by slicing a plain address
        // vector, never by a second run-list, so it cannot inherit the
        // implementation's mistake, and the result is read positionally, so
        // it does not depend on how the runs decompose.
        let base: Vec<Address> = (1u32..=5).map(ca).collect();
        let l = list(vec![run(&ca(1), 5)]);
        let read = |l: &RunList| -> Vec<Address> {
            (1..=5).map(|i| l.point(&n(i)).expect("arranged")).collect()
        };
        let mut checked = 0usize;
        for a in 1..=6usize {
            for b in a + 1..=6 {
                for c in b + 1..=6 {
                    // Pivot: [c₀, c₁) and [c₁, c₂) exchange in place.
                    let want = [&base[..a - 1], &base[b - 1..c - 1], &base[a - 1..b - 1], &base[c - 1..]]
                        .concat();
                    let out = l.reorder(&[n(a as u32), n(b as u32), n(c as u32)]);
                    assert_eq!(read(&out), want, "pivot at {a}, {b}, {c}");
                    assert_eq!(out.total_width(), n(5), "pivot at {a}, {b}, {c} permutes");
                    checked += 1;
                    for d in c + 1..=6 {
                        // Swap: the outer regions exchange, the middle stays.
                        let want = [
                            &base[..a - 1],
                            &base[c - 1..d - 1],
                            &base[b - 1..c - 1],
                            &base[a - 1..b - 1],
                            &base[d - 1..],
                        ]
                        .concat();
                        let out = l.reorder(&[n(a as u32), n(b as u32), n(c as u32), n(d as u32)]);
                        assert_eq!(read(&out), want, "swap at {a}, {b}, {c}, {d}");
                        assert_eq!(out.total_width(), n(5), "swap at {a}, {b}, {c}, {d} permutes");
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 35, "every admissible 3- and 4-cut vector at n_C = 5");
    }

    #[test]
    fn resolve_range_clips_accept_and_intersect() {
        // ASN-0118: out-of-range silently dropped; V-ordered result.
        let l = list(vec![run(&ca(1), 3)]);
        assert_eq!(l.resolve_range(&n(2), &n(10)), vec![run(&ca(2), 2)]);
        assert_eq!(l.resolve_range(&n(0), &n(2)), vec![run(&ca(1), 1)]); // lo clamps to 1
        assert!(l.resolve_range(&n(4), &n(2)).is_empty());
        // A narrow resolution over a FRAGMENTED list answers with the one run
        // it names and nothing else, and it names the right one from each
        // position in the list — first, middle, last. The interesting half is
        // what the answer costs: it is the size of the answer, not the size
        // of the list, which is why a per-spec loop over a heavily
        // transcluded source does not multiply that source's fragmentation
        // by its spec count.
        let frag = list(vec![run(&ca(1), 1), run(&vca(1), 1), run(&ca(5), 1)]);
        assert_eq!(frag.resolve_range(&n(1), &n(1)), vec![run(&ca(1), 1)]);
        assert_eq!(frag.resolve_range(&n(2), &n(1)), vec![run(&vca(1), 1)]);
        assert_eq!(frag.resolve_range(&n(3), &n(1)), vec![run(&ca(5), 1)]);
        // …and a range spanning the seams clips both boundary runs.
        let wide = list(vec![run(&ca(1), 3), run(&vca(1), 3), run(&ca(9), 3)]);
        assert_eq!(
            wide.resolve_range(&n(3), &n(5)),
            vec![run(&ca(3), 1), run(&vca(1), 3), run(&ca(9), 1)]
        );
        // Over-reach past the last arranged ordinal is still dropped without
        // the total ever being computed.
        assert_eq!(wide.resolve_range(&n(8), &n(99)), vec![run(&ca(10), 2)]);
        assert!(wide.resolve_range(&n(10), &n(99)).is_empty());
    }
}
