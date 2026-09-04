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
use skep_address::{shift, Address, Nat, SpanSet};

use crate::run::Run;

/// The §1 I-adjacency guard — the COMPLETE and SAFE coalesce condition:
/// `shift(a₁, w₁) == a₂` implies same origin (ASN-0058 M16a) and excludes
/// shared-I-extent (M14a); it is vacuously false across origin-lengths
/// (`shift` preserves length), so cross-length runs never merge — never
/// across an origin seam (M16), never collapsing a transclusion (M14).
/// **Never coalesce on value** (S4).
pub(crate) fn i_adjacent(left: &Run, right_start: &Address) -> bool {
    shift(left.i_start.tumbler(), &left.width) == *right_start.tumbler()
}

/// Single-address INSERT accumulation (§1): `None ⇒` open a width-1 run;
/// `Some(r)` with `r` I-extending to `a` ⇒ widen in place. Under INSERT's
/// held content lock every `mint_content` advances the same frontier, so
/// each `a` is I-adjacent to the open run; this only ever widens it and the
/// loop closes with exactly one run.
pub(crate) fn extend_run(open: &mut Option<Run>, a: Address) {
    match open {
        None => {
            *open = Some(Run {
                i_start: a,
                width: Nat::one(),
            });
        }
        Some(r) => {
            debug_assert!(
                i_adjacent(r, &a),
                "INSERT's held-lock mints must be I-adjacent to the open run"
            );
            r.width = &r.width + &Nat::one();
        }
    }
}

/// COPY's run accumulator (§1): widen the last run iff I-adjacent, else push.
/// Cross-origin runs are cross-length, fail the I-adjacency test, and never
/// coalesce — preserving the origin multiset (ASN-0118 CP11) and
/// transclusion independence (CP4/M14).
pub(crate) fn extend_or_push_run(runs: &mut Vec<Run>, r: Run) {
    if let Some(last) = runs.last_mut() {
        if i_adjacent(last, &r.i_start) {
            last.width = &last.width + &r.width;
            return;
        }
    }
    runs.push(r);
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

/// The per-subspace run-list (§Core data model). All mutators are persistent
/// (`&self → RunList`); the `im::Vector` backing keeps clones O(1) (VERSION's
/// structural fork share) while the v1 surgery below is Vec-based O(#runs).
#[derive(Clone, Default, Serialize, Deserialize)]
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

    /// `M(d)(v)` for this subspace: the I-address at ordinal `ord`, or `None`
    /// when unarranged (§2 point).
    pub(crate) fn point(&self, ord: &Nat) -> Option<Address> {
        let (idx, off) = self.locate(ord)?;
        let run = self.0.get(idx).expect("locate returns an in-range index");
        Some(run.addr_at(&off))
    }

    /// Split the run-list at the ordinal boundary BEFORE `ord`: the prefix
    /// covers ordinals `[1, ord)`, the suffix `[ord, total]`. The append
    /// boundary `ord = total + 1` — INSERT/COPY's `J = N + 1` and the
    /// link-seat append `n_L(d) + 1` — returns (all, empty), so a splice
    /// concatenates at the tail (§1). `ord ≤ 1` returns (empty, all) — the
    /// defensive clamp under which a split at 0 and at 1 coincide (ASN-0119
    /// tile-by-placement note). An interior `ord` splits the boundary run
    /// `Run(a, w) → Run(a, c), Run(a ⊕ c, w − c)` via
    /// [`Run::addr_at`](crate::Run::addr_at).
    fn split_at(&self, ord: &Nat) -> (Vec<Run>, Vec<Run>) {
        let one = Nat::one();
        if *ord <= one {
            return (Vec::new(), self.0.iter().cloned().collect());
        }
        let mut left: Vec<Run> = Vec::new();
        let mut before = Nat::zero();
        let mut iter = self.0.iter();
        while let Some(run) = iter.next() {
            let start = &before + &one; // this run's first ordinal
            if *ord == start {
                // Boundary before this run.
                let mut right: Vec<Run> = vec![run.clone()];
                right.extend(iter.cloned());
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
                right.extend(iter.cloned());
                return (left, right);
            }
            left.push(run.clone());
            before = end;
        }
        (left, Vec::new()) // ord ≥ total + 1: the append boundary
    }

    /// Splice `new_runs` in at `ord` (§1): split, insert, concat, coalesce.
    /// The suffix's implicit positions are now `+Σ width(new_runs)` — the
    /// uniform forward shift, for free.
    pub(crate) fn splice_in(&self, ord: &Nat, new_runs: &[Run]) -> RunList {
        let (mut acc, right) = self.split_at(ord);
        acc.extend(new_runs.iter().cloned());
        acc.extend(right);
        RunList(coalesced(acc))
    }

    /// Remove ordinals `[from, from + width)` and close the gap (§1): split at
    /// `from` and `from + width`, drop the middle, concat prefix + suffix.
    /// Suffix positions shift left for free; the gap closes by construction
    /// (ASN-0117 P2).
    pub(crate) fn remove_range(&self, from: &Nat, width: &Nat) -> RunList {
        let (mut left, rest) = self.split_at(from);
        let rest: RunList = RunList(rest.into_iter().collect());
        // The removed range is rest-relative ordinals [1, width].
        let (_dropped, right) = rest.split_at(&(width + &Nat::one()));
        left.extend(right);
        RunList(coalesced(left))
    }

    /// Cut-determined, value-blind transpose (§1; ASN-0119): split at each cut
    /// ordinal and **tile by placement** — `[exterior-left][β][μ?][α]
    /// [exterior-right]` — never offset arithmetic, so the bijection is
    /// structural (no swap-α offset bug, ASN-0084 Q14). 3 cuts: pivot
    /// (α = [c₀,c₁), β = [c₁,c₂) exchange). 4 cuts: swap (α = [c₀,c₁),
    /// μ = [c₁,c₂), β = [c₂,c₃); outer two exchange, middle stays). A cut
    /// vector outside R-PRE is outside the fold's input class (§10) — 3|4 is
    /// debug-asserted; release totality falls back to identity.
    pub(crate) fn reorder(&self, cuts: &[Nat]) -> RunList {
        debug_assert!(
            matches!(cuts.len(), 3 | 4),
            "R-PRE: 3 or 4 cuts (validated at staging)"
        );
        let as_list = |v: Vec<Run>| RunList(v.into_iter().collect());
        match cuts {
            [c0, c1, c2] => {
                // Descending splits on prefixes keep absolute coordinates.
                let (l2, ext_right) = self.split_at(c2);
                let (l1, beta) = as_list(l2).split_at(c1);
                let (ext_left, alpha) = as_list(l1).split_at(c0);
                let mut out = ext_left;
                out.extend(beta);
                out.extend(alpha);
                out.extend(ext_right);
                RunList(coalesced(out))
            }
            [c0, c1, c2, c3] => {
                let (l3, ext_right) = self.split_at(c3);
                let (l2, beta) = as_list(l3).split_at(c2);
                let (l1, mu) = as_list(l2).split_at(c1);
                let (ext_left, alpha) = as_list(l1).split_at(c0);
                let mut out = ext_left;
                out.extend(beta);
                out.extend(mu);
                out.extend(alpha);
                out.extend(ext_right);
                RunList(coalesced(out))
            }
            _ => self.clone(),
        }
    }

    /// I-runs covering ordinals `[ord, ord + count)`, clipped to
    /// `[1, total]` — accept-and-intersect: out-of-range is silently dropped
    /// (ASN-0118). V-ordered by construction.
    pub(crate) fn resolve_range(&self, ord: &Nat, count: &Nat) -> Vec<Run> {
        let total = self.total_width();
        let lo = std::cmp::max(ord.clone(), Nat::one());
        let hi_excl = std::cmp::min(ord + count, &total + &Nat::one());
        if lo >= hi_excl {
            return Vec::new();
        }
        let (left, _) = self.split_at(&hi_excl);
        let left: RunList = RunList(left.into_iter().collect());
        let (_, mid) = left.split_at(&lo);
        mid
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

    /// The canonical, V-ordered run vector (maximally merged — M12).
    pub(crate) fn runs_vec(&self) -> Vec<Run> {
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
        assert!(merged.runs_vec() == vec![run(&ca(1), 5)]);
        let apart = l.splice_in(&n(4), &[run(&ca(9), 1)]); // not adjacent
        assert!(apart.runs_vec() == vec![run(&ca(1), 3), run(&ca(9), 1)]);
        assert_eq!(apart.total_width(), n(4));
    }

    #[test]
    fn interior_splice_splits_the_boundary_run_and_shifts_the_suffix() {
        // §1: Run(a, w) → Run(a, c), Run(a ⊕ c, w − c); suffix positions move
        // +Σ width for free.
        let l = list(vec![run(&ca(1), 4)]);
        let spliced = l.splice_in(&n(3), &[run(&ca(9), 1)]);
        assert!(spliced.runs_vec() == vec![run(&ca(1), 2), run(&ca(9), 1), run(&ca(3), 2)]);
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
        assert!(out.runs_vec() == vec![run(&ca(1), 4)]);
        // And an interior removal within one run splits then re-shifts.
        let l2 = list(vec![run(&ca(1), 5)]);
        let out2 = l2.remove_range(&n(2), &n(2));
        assert!(out2.runs_vec() == vec![run(&ca(1), 1), run(&ca(4), 2)]);
        assert_eq!(out2.total_width(), n(3));
    }

    #[test]
    fn cross_length_runs_never_coalesce() {
        // §1: the I-adjacency guard is vacuously false across origin lengths
        // (shift preserves length) — a transclusion seam survives (M14/M16).
        let l = list(vec![run(&ca(1), 1)]);
        let out = l.splice_in(&n(2), &[run(&vca(1), 1)]); // vca is length 9, ca length 8
        assert_eq!(out.runs_vec().len(), 2);
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
    fn resolve_range_clips_accept_and_intersect() {
        // ASN-0118: out-of-range silently dropped; V-ordered result.
        let l = list(vec![run(&ca(1), 3)]);
        assert!(l.resolve_range(&n(2), &n(10)) == vec![run(&ca(2), 2)]);
        assert!(l.resolve_range(&n(0), &n(2)) == vec![run(&ca(1), 1)]); // lo clamps to 1
        assert!(l.resolve_range(&n(4), &n(2)).is_empty());
    }
}
