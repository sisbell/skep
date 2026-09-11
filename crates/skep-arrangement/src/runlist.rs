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

use std::fmt;

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
/// same origin (M16a — the reach changes only the last component, so the two
/// starts share every component before it, their document prefix included)
/// and excludes shared-I-extent (M14a), so no run merges across an origin
/// seam (M16), whatever the two origins' depths, and none collapses a
/// transclusion (M14). Across level classes the test is vacuously false as
/// well — the reach is length-preserving — but that is a consequence of the
/// prefix rule, not the reason for it: two sibling documents share a length
/// and are kept apart by their prefixes alone. **Never coalesce on value**
/// (S4).
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
/// Runs of two different origins never coalesce, whatever their depths. The
/// reach moves only a run's last component, so a run is I-adjacent only to
/// one that shares every other component with it — the same document's same
/// subspace (ASN-0058 M16a: element addresses extend the document prefix).
/// Two sibling documents are two origins in ONE level class, and it is that
/// prefix test, not a difference in length, that keeps their runs apart, as
/// it keeps a trunk's runs apart from its member's. That preserves the origin
/// multiset (ASN-0118 CP11) and transclusion independence (CP4/M14).
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
/// interior `ord` splits the boundary run `Run(a, w) → Run(a, kept),
/// Run(a ⊕ kept, w − kept)` via [`Run::addr_at`](crate::Run::addr_at).
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
        let last = &before + &run.width; // this run's last ordinal
        if *ord <= last {
            // Interior: keep `ord − start` elements on the left
            // (1 ≤ kept ≤ width − 1 here).
            let kept = ord - &start;
            let right_first = Run {
                i_start: run.addr_at(&kept),
                width: &run.width - &kept,
            };
            left.push(Run {
                i_start: run.i_start.clone(),
                width: kept,
            });
            let mut right: Vec<Run> = vec![right_first];
            right.extend(runs.cloned());
            return (left, right);
        }
        left.push(run.clone());
        before = last;
    }
    (left, Vec::new()) // ord ≥ total + 1: the append boundary
}

/// The per-subspace run-list (§Core data model). All mutators are persistent
/// (`&self → RunList`); the `im::Vector` backing keeps clones O(1) (VERSION's
/// structural fork share) while the v1 surgery below is Vec-based O(#runs).
///
/// MAXIMAL MERGE IS THE INVARIANT: the resident form is the unique
/// maximally-merged decomposition (ASN-0058 M12), so
/// [`content_runs`](crate::M5State::content_runs) and
/// [`link_runs`](crate::M5State::link_runs) publish canonical run structure
/// and `resolve` serves it. TWO DOORS keep it. Every mutator here rebuilds
/// through [`coalesced`], and the serde shadow below establishes it on the
/// DECODE path — a checkpoint carries these lists whole, so without that door
/// a recovered list could hold two I-adjacent runs and every read publishing
/// canonicality would answer off it, silently and across restarts.
///
/// The decode door REPAIRS rather than refuses, which is what distinguishes
/// it from [`Run`]'s and `Provenance`'s: a non-merged list denotes exactly the
/// right V→I map, and `coalesced` is total, idempotent and
/// denotation-preserving, so establishing the invariant is what a constructor
/// is for. Refusing would turn a fully recoverable store into a dead one for
/// no gain. The reads therefore rest on the type, not on M2's checksum.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RunListShadow")]
pub(crate) struct RunList(im::Vector<Run>);

/// The deserialization mint path (the serde shadow, as [`Run`] and
/// `Provenance` each carry one, with `from` rather than `try_from` because
/// the conversion is total): the decoded runs re-enter [`coalesced`], so the
/// maximal-merge invariant holds for every `RunList` in the process rather
/// than for every one the folds built.
///
/// It reads exactly what a `RunList` writes — the same newtype over the same
/// vector, which bincode encodes as its inner value — and `Serialize` is
/// derived on `RunList` itself, so the shadow costs the encoding nothing.
#[derive(Deserialize)]
struct RunListShadow(im::Vector<Run>);

impl From<RunListShadow> for RunList {
    fn from(s: RunListShadow) -> RunList {
        RunList(coalesced(s.0.into_iter().collect()))
    }
}

/// Borrowed runs of one subspace's run-list, in V-order — what
/// [`M5State::content_runs`](crate::M5State::content_runs) and
/// [`link_runs`](crate::M5State::link_runs) lend. Opaque, as M1's `Spans` is,
/// so the `im::Vector` backing (Open decision #1) stays this module's own.
///
/// Opacity hides the container, never the walk's capabilities, which are
/// forwarded below: the exact length is `#runs`, answered without reading a
/// run, and the reverse walk and the fused guarantee come with it. `Clone` is
/// withheld for the reason M1 states on `Spans`: `im`'s vector iterator is not
/// cloneable, so a caller wanting two cursors asks the arrangement for two.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Runs<'a>(<&'a im::Vector<Run> as IntoIterator>::IntoIter);

impl<'a> Iterator for Runs<'a> {
    type Item = &'a Run;
    fn next(&mut self) -> Option<&'a Run> {
        self.0.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl<'a> DoubleEndedIterator for Runs<'a> {
    fn next_back(&mut self) -> Option<&'a Run> {
        self.0.next_back()
    }
}

impl ExactSizeIterator for Runs<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::iter::FusedIterator for Runs<'_> {}

/// The cursor, not the runs: the backing's iterator is neither `Clone` nor
/// `Debug`, so there is no way to show what is left without spending it, and
/// the arrangement it was lent from is `Debug` already.
impl fmt::Debug for Runs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runs").finish_non_exhaustive()
    }
}

impl RunList {
    /// `n(d)` for this subspace — the total arranged width.
    pub(crate) fn total_width(&self) -> Nat {
        self.0.iter().fold(Nat::zero(), |acc, r| acc + &r.width)
    }

    /// `#runs` — how many runs the list holds, the fragmentation every
    /// `O(#runs)` walk and splice here is priced in. O(1): the backing vector
    /// knows its own length.
    pub(crate) fn run_count(&self) -> usize {
        self.0.len()
    }

    /// No runs — and so no positions, every run having `width ≥ 1`. O(1),
    /// where `total_width().is_zero()` sums every width to learn the same bit.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The run holding ordinal `ord`, lent, and the 0-based offset of `ord`
    /// within it — `None` when `ord` is 0 or past the last arranged ordinal
    /// (§1 locate). The run itself rather than its index, so a caller holds
    /// what it asked for and never re-fetches it by a coordinate this walk
    /// already resolved. Answered off [`iter_runs`](RunList::iter_runs): the
    /// one prefix-sum walk, which reports each run's V-start.
    pub(crate) fn locate(&self, ord: &Nat) -> Option<(&Run, Nat)> {
        if ord.is_zero() {
            return None; // ordinal 0 lies before every run; the offset would underflow
        }
        self.iter_runs()
            .find(|(v_start, run)| *ord < v_start + &run.width)
            .map(|(v_start, run)| (run, ord - &v_start))
    }

    /// `M(d)(p)` for this subspace: the I-address at ordinal `ord`, or `None`
    /// when unarranged (§2 point).
    pub(crate) fn point(&self, ord: &Nat) -> Option<Address> {
        let (run, off) = self.locate(ord)?;
        Some(run.addr_at(&off))
    }

    /// Does this list hold `a` — is the address inside some run's I-extent
    /// (§8)? The I-side twin of [`locate`](RunList::locate)/
    /// [`point`](RunList::point), which answer the same membership question
    /// from the V-side: an address INTERIOR to a coalesced run counts, runs
    /// being contiguous I-extents rather than enumerated addresses. CL-UNIQ asks
    /// this of a document's link list.
    pub(crate) fn holds(&self, a: &Address) -> bool {
        self.0.iter().any(|r| r.iextent().contains(a.tumbler()))
    }

    /// Does this list hold EVERY address of `run` — is the run's whole
    /// I-extent arranged here, as one resident run or split across several?
    /// [`holds`](RunList::holds) asked of an I-extent rather than a point: the
    /// carried-run test of the publish shot (PUB-6.24, PUB-8.1) — a supplied
    /// run the base already arranges takes no source gate.
    ///
    /// Answered per resident run of `run`'s own endpoint length by the run's
    /// own offset arithmetic
    /// ([`Run::offsets_covered_by`](crate::Run::offsets_covered_by) — which of
    /// `run`'s offsets that resident's I-extent covers) and then by one sweep
    /// over the covered ranges, so the cost is `O(#runs log #runs)`: a
    /// resident of another endpoint length costs one length comparison, and
    /// each of the run's own length one intersection — never a search over
    /// the run's width, which on the shot's path is the client's.
    ///
    /// A resident of ANOTHER endpoint length is skipped, not searched, and
    /// skipping it changes no answer: it holds no address of `run`. Both are
    /// full element positions ([`Run::admits_start`](crate::Run::admits_start)).
    /// The shorter of two such addresses lies outside the longer's I-extent —
    /// it is compared inside the longer's leading components, where both ends
    /// of that extent agree, so it falls below both or above both. And a
    /// longer address inside a shorter run's I-extent would follow that run's
    /// subspace component with two components or more — an element field of
    /// three or more, which no `Run` admits.
    ///
    /// Transclusion multiplicity is harmless: an address this list arranges
    /// twice covers its offset twice, and a sweep over a union counts once.
    pub(crate) fn covers(&self, run: &Run) -> bool {
        let len = run.i_start().tumbler().len();
        let mut covered: Vec<(Nat, Nat)> = self
            .0
            .iter()
            .filter(|resident| resident.i_start().tumbler().len() == len)
            .filter_map(|resident| run.offsets_covered_by(&resident.iextent()))
            .map(|range| (range.lo().clone(), range.hi().clone()))
            .collect();
        covered.sort();
        let mut reached = Nat::zero();
        for (lo, hi) in covered {
            if lo > reached {
                return false;
            }
            if hi > reached {
                reached = hi;
            }
        }
        reached >= *run.width()
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
    /// whatever the region count.
    ///
    /// THE 3|4 CLAUSE IS THE OP'S OBLIGATION, discharged at staging by
    /// [`Vstream::rearrange`](crate::Vstream::rearrange)'s `BadCutCount`, and
    /// it is not re-asked here. The tiling is total for any vector instead:
    /// with fewer than three ordinals there is no interior region to move and
    /// the list comes back unchanged, and with more the peel runs to the end.
    /// That totality is what [`apply_m5`](crate::M5State::apply_m5)'s
    /// panic-free promise requires of this method, a corrupt cut vector being
    /// something the replay path must tile rather than stop on.
    #[must_use = "reorder returns the new run-list; it does not modify the receiver"]
    pub(crate) fn reorder(&self, cut_ordinals: &[Nat]) -> RunList {
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

    /// The runs covering ordinals `[lo, hi_excl)` — or `[lo, total]` when no
    /// bound is given — the boundary runs clipped, yielded LAZILY: nothing
    /// outside the range is cloned, and a consumer that stops early stops the
    /// walk with it (`take_while` short-circuits). THE ONE CLIP, which the
    /// range walk and the suffix walk both ask, so the boundary arithmetic and
    /// its proof are written once.
    ///
    /// WHAT THIS COSTS, since a resolution's caller is a per-spec loop —
    /// COPY's, M7's slot endsets, M6's RETRIEVEV — and a request's spec count
    /// multiplies whatever one call costs. Pulling the whole range is
    /// `Θ(#runs left of lo) + Θ(#runs in the range)`: the prefix-sum walk has
    /// to reach `lo`, one `Nat` addition and one comparison per run it passes
    /// over, so resolving the LAST position of an n-run list costs n steps
    /// however narrow the answer. That term is the `im::Vector<Run>` backing's
    /// (Open decision #1); what laziness removes is the other term, the
    /// materialization of runs a bounded consumer will never look at.
    ///
    /// Called with `lo < hi_excl` when bounded. Every emitted run then has
    /// `width ≥ 1` and an element-level start: a run reaching the push has
    /// `lo < v_reach` and, when bounded, `v_start < hi_excl`; `v_start <
    /// v_reach` because a run's width is at least one; so `first < past`, and
    /// the start is [`Run::addr_at`](crate::Run::addr_at) of an offset inside
    /// the run. Both `Nat` subtractions are therefore over ordered operands
    /// and cannot underflow. A run the range keeps WHOLE is cloned rather
    /// than rebuilt: no shift and no validation for a run the clip does not
    /// touch, which is every interior run of a wide range and every run but
    /// the first of a suffix.
    fn slice_runs(&self, lo: Nat, hi_excl: Option<Nat>) -> impl Iterator<Item = Run> + '_ {
        let stop = hi_excl.clone();
        self.iter_runs()
            .take_while(move |(v_start, _)| stop.as_ref().is_none_or(|stop| v_start < stop))
            .filter_map(move |(v_start, run)| {
                let v_reach = &v_start + &run.width; // the first ordinal past this run
                if v_reach <= lo {
                    return None;
                }
                let first = std::cmp::max(&v_start, &lo); // this run's first kept ordinal
                // One past its last: the bound, or the run's own reach when
                // the walk has no bound.
                let past = hi_excl.as_ref().map_or(&v_reach, |hi| std::cmp::min(&v_reach, hi));
                if first == &v_start && past == &v_reach {
                    return Some(run.clone()); // kept whole
                }
                Some(Run {
                    i_start: run.addr_at(&(first - &v_start)),
                    width: past - first,
                })
            })
    }

    /// I-runs covering ordinals `[ord, ord + count)`, clipped to the arranged
    /// range — accept-and-intersect: out-of-range is silently dropped
    /// (ASN-0118). V-ordered by construction, and LAZY: the clipping happens
    /// as runs are pulled, so a consumer with a budget of its own holds that
    /// budget rather than the whole resolution, whose size is the source
    /// document's fragmentation and not the asking request's choice.
    /// [`M5State::resolve`](crate::M5State::resolve) is where the collecting
    /// form lives, at the level that has consumers wanting a vector.
    ///
    /// The upper clip needs no `total_width`: no run reaches past `total + 1`,
    /// so clipping each run at `hi_excl` already drops everything beyond the
    /// arrangement, and asking for the total would be a second walk of the
    /// whole list to learn a bound the walk enforces anyway.
    pub(crate) fn iter_resolve_range(&self, ord: &Nat, count: &Nat) -> impl Iterator<Item = Run> + '_ {
        let lo = std::cmp::max(ord.clone(), Nat::one());
        let hi_excl = ord + count;
        // An empty range names no position, and it is excluded HERE rather
        // than clipped to nothing below: a run straddling `hi_excl ≤ lo` would
        // otherwise clip to `past − first = hi_excl − lo`, which underflows.
        (lo < hi_excl)
            .then_some((lo, hi_excl))
            .into_iter()
            .flat_map(move |(lo, hi_excl)| self.slice_runs(lo, Some(hi_excl)))
    }

    /// I-runs covering ordinals `[max(ord, 1), total]` — everything from the
    /// boundary before `ord` to the arranged end, V-ordered, the boundary run
    /// clipped as [`iter_resolve_range`](RunList::iter_resolve_range) clips it
    /// and every later run yielded whole. The SUFFIX twin of that range walk,
    /// for a caller that means "everything past a boundary": the list ends
    /// where its runs end, so no upper bound is named and no total is summed
    /// to find one — asking the range walk for `total_width()` positions
    /// would walk the whole list once to learn a bound the walk then never
    /// needs. LAZY as the range walk is, so a consumer with a budget of its
    /// own stops the walk at it; an `ord` past the arranged end yields
    /// nothing, and so does a list holding nothing. The same clip as the
    /// range walk's, asked without a bound.
    pub(crate) fn iter_resolve_from(&self, ord: &Nat) -> impl Iterator<Item = Run> + '_ {
        self.slice_runs(std::cmp::max(ord.clone(), Nat::one()), None)
    }

    /// Iterate `(v_start, run)` pairs — the implicit V-start is the running
    /// prefix sum + 1 (§1 iter_runs).
    pub(crate) fn iter_runs(&self) -> impl Iterator<Item = (Nat, &Run)> + '_ {
        let mut v_start = Nat::one();
        self.0.iter().map(move |run| {
            let start = v_start.clone();
            v_start = &v_start + &run.width;
            (start, run)
        })
    }

    /// The canonical, V-ordered run decomposition (maximally merged — M12),
    /// LENT: the runs alone, borrowed from the list rather than cloned out of
    /// it. [`iter_runs`](RunList::iter_runs) is the form that also reports
    /// each run's implicit V-start.
    pub(crate) fn iter(&self) -> Runs<'_> {
        Runs(self.0.iter())
    }

    /// The same decomposition collected, for this module's tests to compare
    /// against a literal sequence.
    #[cfg(test)]
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
    use crate::testutil::{a, ca, n, run, vca};

    fn list(runs: Vec<Run>) -> RunList {
        RunList(runs.into_iter().collect())
    }

    /// The whole of a resolution, for the assertions whose subject is WHICH
    /// runs come back rather than when. The laziness itself is the subject of
    /// `the_lazy_resolution_yields_a_prefix_when_a_consumer_stops`.
    fn resolved(l: &RunList, ord: u32, count: u32) -> Vec<Run> {
        l.iter_resolve_range(&n(ord), &n(count)).collect()
    }

    /// How many runs the unique maximally-merged decomposition of `addrs`
    /// has (ASN-0058 M12), computed from the addresses alone: a run continues
    /// exactly where the next address repeats every component of the one
    /// before but the last and advances that one by one. Independent of
    /// `RunList`, so an assertion against it cannot inherit the list's own
    /// merge.
    fn canonical_run_count(addrs: &[Address]) -> usize {
        let continues = |prev: &Address, next: &Address| {
            let p: Vec<&Nat> = prev.tumbler().iter().collect();
            let q: Vec<&Nat> = next.tumbler().iter().collect();
            p.len() == q.len()
                && p[..p.len() - 1] == q[..q.len() - 1]
                && *q[q.len() - 1] == p[p.len() - 1] + &n(1)
        };
        let breaks = addrs.windows(2).filter(|w| !continues(&w[0], &w[1])).count();
        if addrs.is_empty() {
            0
        } else {
            breaks + 1
        }
    }

    /// `l` denotes exactly `want`, position by position and nothing past it,
    /// in the maximally-merged decomposition of `want`.
    fn assert_denotes(l: &RunList, want: &[Address], label: &str) {
        for (i, addr) in want.iter().enumerate() {
            let ord = i as u32 + 1;
            assert_eq!(l.point(&n(ord)).as_ref(), Some(addr), "{label}: position {ord}");
        }
        assert_eq!(
            l.point(&n(want.len() as u32 + 1)),
            None,
            "{label}: nothing past the end"
        );
        assert_eq!(l.runs().len(), canonical_run_count(want), "{label}: maximally merged");
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
    fn covers_asks_membership_of_a_whole_i_extent() {
        // §8/PUB-6.24: an I-extent is carried when every one of its addresses
        // is arranged — as one run, or split across several by a foreign run
        // between them — and not when any address is missing, whatever the
        // rest.
        let l = list(vec![run(&ca(1), 2), run(&vca(5), 1), run(&ca(3), 2)]); // ca1..4, split
        assert!(l.covers(&run(&ca(1), 4)), "split across two residents, still whole");
        assert!(l.covers(&run(&ca(2), 2)), "an interior I-extent");
        assert!(l.covers(&run(&vca(5), 1)));
        assert!(!l.covers(&run(&ca(4), 2)), "ca(5) is arranged nowhere");
        assert!(!l.covers(&run(&ca(9), 1)));
        assert!(!l.covers(&run(&vca(1), 1)), "another origin length covers nothing");
        assert!(!RunList::default().covers(&run(&ca(1), 1)));
        // A document arranging the same address twice — transclusion
        // multiplicity — counts it once, and the sweep is unbothered.
        let twice = list(vec![run(&ca(1), 2), run(&vca(5), 1), run(&ca(1), 2)]);
        assert!(twice.covers(&run(&ca(1), 2)));
        assert!(!twice.covers(&run(&ca(1), 3)));
    }

    #[test]
    fn a_run_of_another_endpoint_length_is_covered_by_no_resident_whatever_its_width() {
        // PUB-6.24: `covers` skips a resident of another endpoint length
        // rather than searching it, which is sound only because such a
        // resident holds no address of the run, whatever the two widths. The
        // law is asked of the search itself — starts and residents of lengths
        // 8 and 9 under three origins, each the shorter in turn. Then the one
        // shape a longer address inside a shorter I-extent must take is shown
        // to be no run start. Then `covers` answers a run of the wire's widest
        // width — one the search would walk for tens of thousands of bigint
        // steps per resident — off the residents of its own length. Corpus
        // seed for the fuzzing tier, against a fragmented list.
        let other = a(&[1, 0, 1, 1, 0, 1, 0, 1, 1]); // length 9, another account's document
        let residents = vec![run(&ca(1), 3), run(&vca(1), 2), run(&other, 2)];
        let starts = [ca(1), ca(4), vca(1), vca(3), other.clone()];
        for resident in &residents {
            for start in &starts {
                if start.tumbler().len() == resident.i_start().tumbler().len() {
                    continue;
                }
                for width in 1..=4u32 {
                    assert_eq!(
                        run(start, width).offsets_covered_by(&resident.iextent()),
                        None,
                        "{start:?} × {width} against {resident:?}"
                    );
                }
            }
        }
        // A longer address CAN lie inside a shorter run's I-extent in the
        // tumbler order — by following its subspace component with two more —
        // and that is exactly the element field no run admits.
        let inside = a(&[1, 0, 1, 0, 1, 0, 1, 2, 5]);
        assert!(run(&ca(1), 3).iextent().contains(inside.tumbler()));
        assert_eq!(Run::new(inside, n(1)), Err(crate::RunError::NotAnElementPosition));
        // The widest run the wire can name: a width of 4096 decimal digits.
        let widest = Nat::from(10u32).pow(4096) - Nat::one();
        let l = list(residents);
        for start in [ca(1), vca(1)] {
            let wide = Run::new(start.clone(), widest.clone()).expect("a full element position");
            assert!(!l.covers(&wide), "{start:?}: its own length's residents hold only a prefix of it");
        }
    }

    #[test]
    fn decoding_a_list_re_establishes_the_maximal_merge_the_reads_publish() {
        // §1/M12: `content_runs` and `link_runs` publish the unique
        // maximally-merged decomposition, and a checkpoint carries these
        // lists whole — so the decode path establishes the invariant as the
        // mutators do. Without that door a recovered list could hold two
        // I-adjacent runs, and every read publishing canonicality would
        // answer off it: M6's COMPARE would see a different block structure
        // for the same document after a restart, and M7's slot endsets would
        // count more spans against `MAX_SLOT_SPANS`. Nothing faults, because
        // the denotation is intact — which is why the door repairs rather
        // than refuses, and why only a comparison of run STRUCTURE sees it.
        //
        // The bytes are made by encoding the shadow's own shape, which is the
        // exact form a checkpoint would present.
        #[derive(Serialize)]
        struct Wire(im::Vector<Run>);
        let wire = |runs: Vec<Run>| {
            bincode::serialize(&Wire(runs.into_iter().collect::<im::Vector<Run>>()))
                .expect("the shadow encodes")
        };
        // Two I-adjacent runs — `shift(ca(1), 2) = ca(3)` — which no fold
        // could have written apart, since every mutator here coalesces.
        let split = wire(vec![run(&ca(1), 2), run(&ca(3), 1)]);
        let decoded: RunList = bincode::deserialize(&split).expect("a run sequence decodes");
        assert_eq!(
            decoded.runs(),
            vec![run(&ca(1), 3)],
            "a decoded list is the maximally-merged decomposition"
        );
        // The denotation was never in doubt: repairing preserved it exactly,
        // which is what makes coalescing the right response to this input and
        // refusing the wrong one.
        assert_eq!(decoded.total_width(), n(3));
        for k in 1..=3u32 {
            assert_eq!(decoded.point(&n(k)), Some(ca(k)));
        }
        // The door costs the encoding nothing: a canonical list's bytes are
        // exactly what the shadow's shape writes, and it decodes to itself.
        let canonical = list(vec![run(&ca(1), 3), run(&ca(9), 1)]);
        let bytes = bincode::serialize(&canonical).expect("the list encodes");
        assert_eq!(bytes, wire(vec![run(&ca(1), 3), run(&ca(9), 1)]));
        assert_eq!(
            bincode::deserialize::<RunList>(&bytes).expect("a canonical list decodes"),
            canonical
        );
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
    fn splice_in_inserts_before_every_boundary_and_merges_whichever_seams_it_closes() {
        // §1/M12: a law over boundaries, exhausted — the placed run goes in
        // before `ord`, and the list left is the maximally-merged
        // decomposition of the result. The fixture has gaps a placed run can
        // close from either side: ca(2) at 2 closes BOTH seams, ca(4) at 4
        // closes the RIGHT one — the seam no splice example above visits,
        // those that merge at all merging the placement into what lies before
        // it. The expectation is a plain address vector.
        let gaps = [ca(1), ca(3), vca(1), ca(5)];
        let l = list(gaps.iter().map(|start| run(start, 1)).collect());
        for placed in [ca(2), ca(4), ca(6), vca(2), vca(9)] {
            for ord in 1..=gaps.len() as u32 + 1 {
                let mut want = gaps.to_vec();
                want.insert(ord as usize - 1, placed.clone());
                assert_denotes(
                    &l.splice_in(&n(ord), &[run(&placed, 1)]),
                    &want,
                    &format!("{placed:?} at {ord}"),
                );
            }
        }
    }

    #[test]
    fn remove_range_drops_every_range_and_merges_the_seam_it_closes() {
        // §1/ASN-0117 P2/M12: a law over every admissible (from, width) of a
        // fragmented, mixed-length fixture whose foreign run separates two
        // runs of one origin, so the removals that take it out rejoin them.
        let woven = [ca(1), ca(2), vca(1), ca(3), ca(4), vca(5)];
        let l = list(vec![
            run(&ca(1), 2),
            run(&vca(1), 1),
            run(&ca(3), 2),
            run(&vca(5), 1),
        ]);
        let n_c = woven.len() as u32;
        let mut checked = 0usize;
        for from in 1..=n_c {
            for width in 1..=n_c + 1 - from {
                let mut want = woven.to_vec();
                want.drain(from as usize - 1..(from + width) as usize - 1);
                assert_denotes(
                    &l.remove_range(&n(from), &n(width)),
                    &want,
                    &format!("[{from}, {})", from + width),
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 21, "every contained range at n_C = 6");
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
    fn two_origins_at_one_depth_never_coalesce_even_where_ordinals_line_up() {
        // §1/M16a: origins are kept apart by PREFIX, not by length. doc1's run
        // reaches ordinal 3 and doc2's element 3 opens at ordinal 3 — one
        // length, one level class, one ordinal — and they are still two
        // origins: widening doc1's run over it would place doc1's own ca(3),
        // which is not the address the second run names.
        let doc2_third = a(&[1, 0, 1, 0, 2, 0, 1, 3]);
        assert_eq!(doc2_third.tumbler().len(), ca(1).tumbler().len());
        let l = list(vec![run(&ca(1), 2)]);
        let out = l.splice_in(&n(3), &[run(&doc2_third, 1)]);
        assert_eq!(out.runs(), vec![run(&ca(1), 2), run(&doc2_third, 1)]);
        // The placing ops' accumulator answers the same.
        let mut placed = vec![run(&ca(1), 2)];
        extend_or_push_run(&mut placed, run(&doc2_third, 1));
        assert_eq!(placed, vec![run(&ca(1), 2), run(&doc2_third, 1)]);
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
        for c0 in 1..=6usize {
            for c1 in c0 + 1..=6 {
                for c2 in c1 + 1..=6 {
                    // Pivot: [c₀, c₁) and [c₁, c₂) exchange in place.
                    let want = [
                        &base[..c0 - 1],
                        &base[c1 - 1..c2 - 1],
                        &base[c0 - 1..c1 - 1],
                        &base[c2 - 1..],
                    ]
                    .concat();
                    let out = l.reorder(&[n(c0 as u32), n(c1 as u32), n(c2 as u32)]);
                    assert_eq!(read(&out), want, "pivot at {c0}, {c1}, {c2}");
                    assert_eq!(out.total_width(), n(5), "pivot at {c0}, {c1}, {c2} permutes");
                    checked += 1;
                    for c3 in c2 + 1..=6 {
                        // Swap: the outer regions exchange, the middle stays.
                        let want = [
                            &base[..c0 - 1],
                            &base[c2 - 1..c3 - 1],
                            &base[c1 - 1..c2 - 1],
                            &base[c0 - 1..c1 - 1],
                            &base[c3 - 1..],
                        ]
                        .concat();
                        let out =
                            l.reorder(&[n(c0 as u32), n(c1 as u32), n(c2 as u32), n(c3 as u32)]);
                        assert_eq!(read(&out), want, "swap at {c0}, {c1}, {c2}, {c3}");
                        assert_eq!(
                            out.total_width(),
                            n(5),
                            "swap at {c0}, {c1}, {c2}, {c3} permutes"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 35, "every admissible 3- and 4-cut vector at n_C = 5");
    }

    #[test]
    fn iter_resolve_range_clips_to_the_arranged_range() {
        // ASN-0118 accept-and-intersect: out-of-range silently dropped;
        // V-ordered result.
        let l = list(vec![run(&ca(1), 3)]);
        assert_eq!(resolved(&l, 2, 10), vec![run(&ca(2), 2)]);
        assert_eq!(resolved(&l, 0, 2), vec![run(&ca(1), 1)]); // lo clamps to 1
        assert!(resolved(&l, 4, 2).is_empty());
        // A narrow resolution over a FRAGMENTED list answers with the one run
        // it names and nothing else, and it names the right one from each
        // position in the list — first, middle, last. The interesting half is
        // what the answer costs: it is the size of the answer, not the size
        // of the list, which is why a per-spec loop over a heavily
        // transcluded source does not multiply that source's fragmentation
        // by its spec count.
        let frag = list(vec![run(&ca(1), 1), run(&vca(1), 1), run(&ca(5), 1)]);
        assert_eq!(resolved(&frag, 1, 1), vec![run(&ca(1), 1)]);
        assert_eq!(resolved(&frag, 2, 1), vec![run(&vca(1), 1)]);
        assert_eq!(resolved(&frag, 3, 1), vec![run(&ca(5), 1)]);
        // …and a range spanning the seams clips both boundary runs.
        let wide = list(vec![run(&ca(1), 3), run(&vca(1), 3), run(&ca(9), 3)]);
        assert_eq!(
            resolved(&wide, 3, 5),
            vec![run(&ca(3), 1), run(&vca(1), 3), run(&ca(9), 1)]
        );
        // Over-reach past the last arranged ordinal is still dropped without
        // the total ever being computed.
        assert_eq!(resolved(&wide, 8, 99), vec![run(&ca(10), 2)]);
        assert!(resolved(&wide, 10, 99).is_empty());
    }

    #[test]
    fn the_lazy_resolution_yields_a_prefix_when_a_consumer_stops() {
        // §1: a consumer with a budget of its own — COPY's placement cap —
        // takes what it can hold and stops there, which is the whole reason
        // the resolution is pulled rather than collected. What must be true
        // for that to be safe is that stopping yields exactly the prefix of
        // the full answer and never a different run: a truncated walk must
        // not silently clip a run differently for having been asked for less.
        let frag = list(vec![
            run(&ca(1), 2),
            run(&vca(1), 1),
            run(&ca(5), 2),
            run(&vca(5), 1),
        ]);
        for (ord, count) in [(1u32, 99u32), (2, 4), (3, 1), (0, 3), (7, 99)] {
            let whole = resolved(&frag, ord, count);
            for take in 0..=whole.len() {
                assert_eq!(
                    frag.iter_resolve_range(&n(ord), &n(count))
                        .take(take)
                        .collect::<Vec<_>>(),
                    whole[..take],
                    "({ord}, {count}) stopped after {take}"
                );
            }
        }
        // The empty range is excluded before any clipping — a straddling run
        // would otherwise clip to a width the subtraction underflows on.
        assert!(frag.iter_resolve_range(&n(3), &n(0)).next().is_none());
        assert!(frag.iter_resolve_range(&n(0), &n(0)).next().is_none());
    }

    #[test]
    fn the_suffix_walk_yields_what_the_range_walk_yields_past_the_end() {
        // §1: the suffix walk is the range walk asked for more positions than
        // the list holds — one past the total, so the range reaches the end
        // from ordinal 0 as well, where the clamp opens it at 1 — reached
        // without summing that total, and lazy the same way: stopping yields
        // exactly the prefix of the whole answer. Asked from before the list,
        // at 1, inside a run, at a seam, at the last position, at the end and
        // past it.
        let frag = list(vec![
            run(&ca(1), 2),
            run(&vca(1), 1),
            run(&ca(5), 2),
            run(&vca(5), 1),
        ]);
        let past_the_end = frag.total_width() + Nat::one();
        for ord in [0u32, 1, 2, 3, 5, 6, 7, 99] {
            let whole: Vec<Run> = frag.iter_resolve_from(&n(ord)).collect();
            assert_eq!(
                whole,
                frag.iter_resolve_range(&n(ord), &past_the_end).collect::<Vec<_>>(),
                "from {ord}: the range walk, reaching past the end"
            );
            for take in 0..=whole.len() {
                assert_eq!(
                    frag.iter_resolve_from(&n(ord)).take(take).collect::<Vec<_>>(),
                    whole[..take],
                    "from {ord}: stopped after {take}"
                );
            }
        }
        // The two ends, and the boundary run's clip: from the first position
        // the whole list, run for run; from inside the first run its tail and
        // everything after; from the last position that position alone; past
        // the end nothing, as from an empty list.
        assert_eq!(frag.iter_resolve_from(&n(1)).collect::<Vec<_>>(), frag.runs());
        assert_eq!(
            frag.iter_resolve_from(&n(2)).collect::<Vec<_>>(),
            vec![run(&ca(2), 1), run(&vca(1), 1), run(&ca(5), 2), run(&vca(5), 1)]
        );
        assert_eq!(frag.iter_resolve_from(&n(6)).collect::<Vec<_>>(), vec![run(&vca(5), 1)]);
        assert!(frag.iter_resolve_from(&n(7)).next().is_none());
        assert!(RunList::default().iter_resolve_from(&n(1)).next().is_none());
    }
}
