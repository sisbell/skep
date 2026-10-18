//! The implicit-position run-list, per subspace (§1).
//!
//! It locates, splices, contracts, reorders and eagerly seam-coalesces
//! (ASN-0058 M12/M14/M16; ASN-0082 shift-absorption; ASN-0117 P2; ASN-0119
//! tile-by-placement).
//!
//! A `RunList` is an ordered sequence of [`Run`]s; V-positions are not
//! stored — run *j* occupies the ordinals `[1 + Σ_{i<j} widthᵢ, …]`. This one
//! choice makes the load-bearing invariants free: density / contiguity /
//! minimum-position (D-SEQ★/D-CTG★/D-MIN★) hold by construction (a V-start is
//! always a prefix sum, so no holes), and insert/delete shift the suffix for
//! free (the spec's ASN-0082 displacement is never computed).
//!
//! **Open decision #1** (default taken): the physical persistent structure is
//! `im::Vector<Run>` — free structural sharing (VERSION's O(1) fork share,
//! cheap state clones), O(#runs) locate/splice, fine because #runs scales
//! with transclusions/edit-sessions, not characters. The width-measured tree
//! and `im::OrdMap<ordinal, Run>` alternatives are profiling-gated.

use std::fmt;

use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use skep_address::{Address, Nat, SpanSet};

use crate::decode::element_by_element;
use crate::run::Run;
#[cfg(test)]
use crate::run_union::RunUnion;

/// Returns whether the run at `right_start` is I-adjacent to `left` (ASN-0058).
///
/// I-adjacency: the right run starts exactly where the left run
/// [`reaches`](Run::reach), so their I-extents abut with no address between.
///
/// **The whole residual merge test.** ASN-0058's merge condition (M7) is a
/// conjunction — two blocks may merge iff they are both V-adjacent
/// (`v₂ = v₁ + w₁`) and I-adjacent — and the first conjunct is discharged by
/// the representation: consecutive entries of an implicit-position run-list
/// occupy consecutive V-ordinals, so every neighbouring pair this guard is
/// asked about is already V-adjacent (`b₁.v_reach() == b₂.v_start`, in
/// [`Block`]'s terms; §1 — the same representation choice that makes
/// D-SEQ★/D-CTG★/D-MIN★ hold). I-adjacency is therefore all that
/// remains to test — and it is also the safe half: `a₂ = a₁ + w₁` implies
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
fn i_adjacent(left: &Run, right_start: &Address) -> bool {
    left.reach() == *right_start.tumbler()
}

/// Accumulates `run` into `runs`: the placing ops' run accumulator (§1).
///
/// It widens the last run iff I-adjacent, else pushes. This is the one place
/// a placement's runs are accumulated, so the merge condition is applied by
/// the element that owns it and no caller decides for itself that two
/// addresses belong to one run — an address that is not I-adjacent to the
/// open run opens a new one, rather than widening a run over the addresses
/// between them.
///
/// Runs of two different origins never coalesce, whatever their depths. The
/// reach moves only a run's last component, so a run is I-adjacent only to
/// one that shares every other component with it — the same document's same
/// subspace (ASN-0058 M16a: element addresses extend the document prefix).
/// Two sibling documents are two origins in one level class, and it is that
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

/// Returns `runs` maximally merged (§1, Open decision #8 default).
///
/// It is the eager coalesce: one pass accumulating through
/// [`extend_or_push_run`], so the merge condition is applied by the one
/// element that owns it. Behaviorally identical to seam-only coalescing
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

/// Splits a run sequence at the ordinal boundary before `ord`.
///
/// The prefix covers ordinals `[1, ord)`, the suffix `[ord, total]`. The
/// append boundary `ord = total + 1` — INSERT/COPY's `J = N + 1` and the
/// link-seat append `n_L(d) + 1` — returns (all, empty), so a splice
/// concatenates at the tail (§1). `ord ≤ 1` returns (empty, all) — the
/// defensive clamp under which a split at 0 and at 1 coincide (ASN-0119
/// tile-by-placement note). An interior `ord` splits the boundary run
/// `Run(a, w) → Run(a, kept), Run(a ⊕ kept, w − kept)` via
/// [`Run::addr_at`](crate::Run::addr_at).
///
/// Over an iterator, not a `RunList`: the ops that split more than once
/// (contract, transpose) split a `Vec<Run>` an earlier split produced, and a
/// splitter that demanded a `RunList` would make each of them rebuild one.
/// The V-positions it judges each run at are the blocks' ([`blocks_of`]), so
/// it sums no width for itself.
fn split_runs<'a>(runs: impl Iterator<Item = &'a Run>, ord: &Nat) -> (Vec<Run>, Vec<Run>) {
    if *ord <= Nat::one() {
        return (Vec::new(), runs.cloned().collect());
    }
    let mut left: Vec<Run> = Vec::new();
    let mut blocks = blocks_of(runs);
    while let Some(block) = blocks.next() {
        if *ord == block.v_start {
            // Boundary before this block.
            let mut right: Vec<Run> = vec![block.run.clone()];
            right.extend(blocks.map(|b| b.run.clone()));
            return (left, right);
        }
        if *ord < block.v_reach() {
            // Interior: keep `ord − v_start` elements on the left
            // (1 ≤ kept ≤ width − 1 here).
            let kept = ord - &block.v_start;
            let right_first = Run {
                i_start: block.run.addr_at(&kept),
                width: &block.run.width - &kept,
            };
            left.push(Run {
                i_start: block.run.i_start.clone(),
                width: kept,
            });
            let mut right: Vec<Run> = vec![right_first];
            right.extend(blocks.map(|b| b.run.clone()));
            return (left, right);
        }
        left.push(block.run.clone());
    }
    (left, Vec::new()) // ord ≥ total + 1: the append boundary
}

/// The per-subspace run-list (§Core data model).
///
/// All mutators are persistent (`&self → RunList`); the `im::Vector` backing
/// keeps clones O(1) (VERSION's structural fork share) while the v1 surgery
/// below is Vec-based O(#runs).
///
/// **Maximal merge is the invariant**: the resident form is the unique
/// maximally-merged decomposition (ASN-0058 M12), so
/// [`content_runs`](crate::M5State::content_runs) and
/// [`link_runs`](crate::M5State::link_runs) publish canonical run structure
/// and `resolve` serves it. Two doors keep it. Every mutator here rebuilds
/// through [`coalesced`], and the serde shadow below establishes it on the
/// decode path — a checkpoint carries these lists whole, so without that door
/// a recovered list could hold two I-adjacent runs and every read publishing
/// canonicality would answer off it, silently and across restarts.
///
/// The decode door repairs rather than refuses, which is what distinguishes
/// it from [`Run`]'s and `Provenance`'s: a non-merged list denotes exactly the
/// right V→I map, and `coalesced` is total, idempotent and
/// denotation-preserving, so establishing the invariant is what a constructor
/// is for. Refusing would turn a fully recoverable store into a dead one for
/// no gain. The reads therefore rest on the type, not on M2's checksum.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RunListShadow")]
pub(crate) struct RunList(im::Vector<Run>);

/// The deserialization mint path: the serde shadow, with `from`.
///
/// [`Run`] and `Provenance` each carry one too; this one takes `from` rather
/// than `try_from` because the conversion is total. The decoded runs re-enter
/// [`coalesced`], so the maximal-merge invariant holds for every `RunList` in
/// the process rather than for every one the folds built.
///
/// It reads exactly what a `RunList` writes — the same newtype over the same
/// vector, which bincode encodes as its inner value — and `Serialize` is
/// derived on `RunList` itself, so the shadow costs the encoding nothing. The
/// vector is read run by run ([`element_by_element`]), each run through
/// `Run`'s own door, so no count a checkpoint body declares sizes a
/// reservation.
#[derive(Deserialize)]
struct RunListShadow(#[serde(deserialize_with = "element_by_element")] im::Vector<Run>);

impl From<RunListShadow> for RunList {
    fn from(s: RunListShadow) -> RunList {
        RunList(coalesced(s.0.into_iter().collect()))
    }
}

/// Borrowed runs of one subspace's run-list, in V-order.
///
/// They are what [`M5State::content_runs`](crate::M5State::content_runs) and
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

/// Formats the cursor, not the runs.
///
/// The backing's iterator is neither `Clone` nor `Debug`, so there is no way
/// to show what is left without spending it, and the arrangement it was lent
/// from is `Debug` already.
impl fmt::Debug for Runs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runs").finish_non_exhaustive()
    }
}

/// A mapping block (ASN-0058): one stored run at its V-position in the list.
///
/// It is the atomic unit of V→I correspondence, `(v, a, w)`. The list stores
/// the run `(a, w)` alone; the V-start is the prefix sum of the widths before
/// it (§1), so a block is a view the walk builds and never a stored value —
/// which is what keeps D-SEQ★/D-CTG★/D-MIN★ free. ASN-0058's merge condition
/// is stated on blocks — V-adjacent, `b₁.v_reach() == b₂.v_start`, and
/// I-adjacent — and the walk hands back consecutive blocks, which is how
/// [`i_adjacent`] discharges the first conjunct by construction.
///
/// M6's COMPARE builds a block of its own at its side of the seam — the run
/// as M5 handed it over and where its first position sits in V-space, beside
/// its document and its reach — under the same corpus name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block<'a> {
    /// The block's first V-ordinal — the prefix sum + 1.
    pub(crate) v_start: Nat,
    /// The stored run: its I-start and width.
    pub(crate) run: &'a Run,
}

impl Block<'_> {
    /// Returns the first V-ordinal past the block, `v_start + width`.
    ///
    /// It is the V-side twin of [`Run::reach`]; what `locate`'s bound, the
    /// clip and the splitter's interior test each ask.
    fn v_reach(&self) -> Nat {
        &self.v_start + &self.run.width
    }
}

/// Returns the mapping blocks of a run sequence held any way.
///
/// Each run stands at the running prefix sum + 1, so the list's own runs and
/// a `Vec<Run>` a split produced walk alike. This is the one prefix-sum walk:
/// [`RunList::iter_blocks`] is this over the list, and [`split_runs`] asks it
/// rather than summing widths for itself.
fn blocks_of<'a>(runs: impl Iterator<Item = &'a Run>) -> impl Iterator<Item = Block<'a>> {
    let mut v_start = Nat::one();
    runs.map(move |run| {
        let block = Block {
            v_start: v_start.clone(),
            run,
        };
        v_start = &v_start + &run.width;
        block
    })
}

impl RunList {
    /// Returns `n(d)` for this subspace: the total arranged width.
    pub(crate) fn total_width(&self) -> Nat {
        self.0.iter().map(Run::width).sum()
    }

    /// Returns `#runs`, how many runs the list holds.
    ///
    /// It is the fragmentation every `O(#runs)` walk and splice here is priced
    /// in. O(1): the backing vector knows its own length.
    pub(crate) fn run_count(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the list holds no runs, and so no positions.
    ///
    /// Every run has `width ≥ 1`. O(1), where `total_width().is_zero()` sums
    /// every width to learn the same bit.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the run holding ordinal `ord`, lent, and `ord`'s offset in it.
    ///
    /// The offset is 0-based; `None` when `ord` is 0 or past the last arranged
    /// ordinal (§1 locate). The run itself rather than its index, so a caller
    /// holds what it asked for and never re-fetches it by a coordinate this
    /// walk already resolved. Answered off
    /// [`iter_blocks`](RunList::iter_blocks): the one prefix-sum walk, which
    /// hands each run back at its V-start.
    pub(crate) fn locate(&self, ord: &Nat) -> Option<(&Run, Nat)> {
        if ord.is_zero() {
            return None; // ordinal 0 lies before every run; the offset would underflow
        }
        self.iter_blocks()
            .find(|block| *ord < block.v_reach())
            .map(|block| (block.run, ord - &block.v_start))
    }

    /// Returns `M(d)(p)` for this subspace: the I-address at ordinal `ord`.
    ///
    /// It answers `None` when `ord` is unarranged (§2 point).
    pub(crate) fn point(&self, ord: &Nat) -> Option<Address> {
        let (run, off) = self.locate(ord)?;
        Some(run.addr_at(&off))
    }

    /// Returns whether this list holds `a`, inside some run's I-extent (§8).
    ///
    /// It is the I-side twin of [`locate`](RunList::locate)/
    /// [`point`](RunList::point), which answer the same membership question
    /// from the V-side: an address interior to a coalesced run counts, runs
    /// being contiguous I-extents rather than enumerated addresses. CL-UNIQ
    /// asks this of a document's link list.
    pub(crate) fn holds(&self, a: &Address) -> bool {
        self.0.iter().any(|r| r.iextent().contains(a.tumbler()))
    }

    /// Returns whether this list holds every address of `run`.
    ///
    /// It is [`holds`](RunList::holds) asked of a whole I-extent:
    /// [`RunUnion::covers`] over the union of this list's runs, asked of one
    /// run. The composition the carried-run laws are pinned on; the publish
    /// shot builds the union at most once, at the first run its source gate
    /// must judge, and asks it of each run the gate judges (`admit`, in
    /// `ops/publish.rs`).
    #[cfg(test)]
    fn covers(&self, run: &Run) -> bool {
        RunUnion::of(self.0.iter()).covers(run)
    }

    /// Splits this list's runs at the boundary before `ord`: [`split_runs`].
    fn split_at(&self, ord: &Nat) -> (Vec<Run>, Vec<Run>) {
        split_runs(self.0.iter(), ord)
    }

    /// Returns the list with `new_runs` spliced in at `ord` (§1).
    ///
    /// It splits, inserts, concatenates and coalesces. The suffix's implicit
    /// positions shift by `+Σ width(new_runs)` — the uniform forward shift,
    /// for free. Takes the runs by value, as `Vec::extend` does: the placing
    /// fold hands over clones of the record it borrows, and
    /// [`append`](RunList::append) hands over the one run it owns.
    #[must_use = "splice_in returns the new run-list; it does not modify the receiver"]
    pub(crate) fn splice_in(&self, ord: &Nat, new_runs: impl IntoIterator<Item = Run>) -> RunList {
        let (mut acc, right) = self.split_at(ord);
        acc.extend(new_runs);
        acc.extend(right);
        RunList(coalesced(acc))
    }

    /// Returns the list with `run` added after everything it already holds.
    ///
    /// That is the append boundary `total + 1`, which [`split_runs`] names,
    /// the content ops reach through `admits_content_boundary`, and the link
    /// seat targets (§8's `n_L(d) + 1`). Where the end lies is this list's
    /// knowledge, so a caller meaning "after everything" says that rather than
    /// computing it. Coalesces with the last run when I-adjacent, as any
    /// splice does.
    #[must_use = "append returns the new run-list; it does not modify the receiver"]
    pub(crate) fn append(&self, run: Run) -> RunList {
        self.splice_in(&(self.total_width() + Nat::one()), [run])
    }

    /// Returns the list with ordinals `[from, from + width)` removed (§1).
    ///
    /// It splits at `from` and `from + width`, drops the middle and
    /// concatenates prefix + suffix. Suffix positions shift left for free; the
    /// gap closes by construction (ASN-0117 P2).
    #[must_use = "remove_range returns the new run-list; it does not modify the receiver"]
    pub(crate) fn remove_range(&self, from: &Nat, width: &Nat) -> RunList {
        let (mut left, rest) = self.split_at(from);
        // The removed range is rest-relative ordinals [1, width].
        let (_dropped, right) = split_runs(rest.iter(), &(width + &Nat::one()));
        left.extend(right);
        RunList(coalesced(left))
    }

    /// Returns the list transposed at the cuts' ordinals (§1; ASN-0119).
    ///
    /// The transpose is cut-determined and value-blind: split at each of the
    /// cut sequence's ordinals `ord(cⱼ)` and **tile by placement** —
    /// `[exterior-left][β][μ?][α][exterior-right]` — never offset arithmetic,
    /// so the bijection is structural (no swap-α offset bug, ASN-0084 Q14).
    /// 3 ordinals: pivot (α = [c₀,c₁), β = [c₁,c₂) exchange). 4: swap
    /// (α = [c₀,c₁), μ = [c₁,c₂), β = [c₂,c₃); outer two exchange, middle
    /// stays).
    ///
    /// Pivot and swap are one computation. Splitting off the exterior-right
    /// first and then descending through the remaining ordinals peels the
    /// interior regions off right-to-left — β, then μ where there is one, then
    /// α — so emitting them in the order they were peeled is the exchange,
    /// whatever the region count.
    ///
    /// **The 3|4 clause is the op's obligation**, discharged at staging by
    /// [`Vstream::rearrange`](crate::Vstream::rearrange)'s `BadCutCount`, and
    /// it is not re-asked here. The tiling is total for any vector instead:
    /// with fewer than three ordinals there is no interior region to move and
    /// the list comes back unchanged, and with more the peel runs to the end.
    /// That totality is what [`apply_m5`](crate::M5State::apply_m5)'s
    /// panic-free promise requires of this method, a corrupt cut vector being
    /// something the replay path must tile rather than stop on.
    #[must_use = "reorder returns the new run-list; it does not modify the receiver"]
    pub(crate) fn reorder(&self, cut_ordinals: &[Nat]) -> RunList {
        let Some((last, remaining)) = cut_ordinals.split_last() else {
            return self.clone();
        };
        // Descending splits on the prefix keep absolute coordinates.
        let (mut prefix, exterior_right) = self.split_at(last);
        let mut regions: Vec<Vec<Run>> = Vec::with_capacity(remaining.len());
        for cut in remaining.iter().rev() {
            let (left, region) = split_runs(prefix.iter(), cut);
            regions.push(region);
            prefix = left;
        }
        let mut out = prefix; // what lies left of the first cut
        for region in regions {
            out.extend(region);
        }
        out.extend(exterior_right);
        RunList(coalesced(out))
    }

    /// Returns the runs covering ordinals `[lo, hi_excl)`, boundaries clipped.
    ///
    /// With no bound given the range is `[lo, total]`. The runs are yielded
    /// lazily: nothing outside the range is cloned, and a consumer that stops
    /// early stops the walk with it (`take_while` short-circuits). This is the
    /// one clip, which the range walk and the suffix walk both ask, so the
    /// boundary arithmetic and its proof are written once.
    ///
    /// **What this costs**, since a resolution's caller is a per-spec loop —
    /// COPY's, M7's slot endsets, M6's RETRIEVEV — and a request's spec count
    /// multiplies whatever one call costs. Pulling the whole range is
    /// `Θ(#runs left of lo) + Θ(#runs in the range)`: the prefix-sum walk has
    /// to reach `lo`, two `Nat` additions, a `Nat` clone and up to two
    /// comparisons per run it passes over, so resolving the last position of
    /// an n-run list costs n steps however narrow the answer. That term is the
    /// `im::Vector<Run>` backing's (Open decision #1); what laziness removes is
    /// the other term, the materialization of runs a bounded consumer will
    /// never look at. The first term is charged by the loops that run it
    /// inside a write, each spec at its source's whole run count: COPY's
    /// against [`MAX_COPY_RESOLVE_STEPS`](crate::MAX_COPY_RESOLVE_STEPS), M7's
    /// slots against its own.
    ///
    /// **Precondition.** `lo < hi_excl` when bounded. Every emitted run then
    /// has `width ≥ 1` and a start that is a full element position: a run
    /// reaching the push has `lo < v_reach` and, when bounded,
    /// `v_start < hi_excl`; `v_start < v_reach` because a run's width is at
    /// least one; so `first < past`, and the start is
    /// [`Run::addr_at`](crate::Run::addr_at) of an offset inside the run — an
    /// ordinal shift that keeps the element field's two components. Both `Nat`
    /// subtractions are therefore over ordered operands and cannot underflow.
    /// A run the range keeps whole is cloned rather than rebuilt: no shift and
    /// no validation for a run the clip does not touch, which is every
    /// interior run of a wide range and every run but the first of a suffix.
    ///
    /// # Panics
    ///
    /// Panics where the precondition is broken with `hi_excl < lo` and a run
    /// spans both: `past − first` underflows.
    fn clipped_runs(&self, lo: Nat, hi_excl: Option<Nat>) -> impl Iterator<Item = Run> + '_ {
        let stop = hi_excl.clone();
        self.iter_blocks()
            .take_while(move |block| stop.as_ref().is_none_or(|hi| &block.v_start < hi))
            .filter_map(move |block| {
                let v_reach = block.v_reach(); // the first ordinal past this block
                if v_reach <= lo {
                    return None;
                }
                let first = std::cmp::max(&block.v_start, &lo); // this block's first kept ordinal
                // One past its last: the bound, or the block's own reach when
                // the walk has no bound.
                let past = hi_excl.as_ref().map_or(&v_reach, |hi| std::cmp::min(&v_reach, hi));
                if first == &block.v_start && past == &v_reach {
                    return Some(block.run.clone()); // kept whole
                }
                Some(Run {
                    i_start: block.run.addr_at(&(first - &block.v_start)),
                    width: past - first,
                })
            })
    }

    /// Returns the I-runs covering ordinals `[ord, ord + count)`.
    ///
    /// They are clipped to the arranged range — accept-and-intersect:
    /// out-of-range is silently dropped (ASN-0118). V-ordered by
    /// construction, and lazy: the clipping happens as runs are pulled, so a
    /// consumer with a budget of its own holds that budget rather than the
    /// whole resolution, whose size is the source document's fragmentation and
    /// not the asking request's choice.
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
        // An empty range names no position, and it is excluded here rather
        // than clipped to nothing below: a run straddling `hi_excl ≤ lo` would
        // otherwise clip to `past − first = hi_excl − lo`, which underflows
        // where `hi_excl < lo` and is a zero-width run where the two are equal.
        (lo < hi_excl)
            .then_some((lo, hi_excl))
            .into_iter()
            .flat_map(move |(lo, hi_excl)| self.clipped_runs(lo, Some(hi_excl)))
    }

    /// Returns the I-runs covering ordinals `[max(ord, 1), total]`.
    ///
    /// That is everything from the boundary before `ord` to the arranged end,
    /// V-ordered, the boundary run clipped as
    /// [`iter_resolve_range`](RunList::iter_resolve_range) clips it and every
    /// later run yielded whole. The suffix twin of that range walk, for a
    /// caller that means "everything past a boundary": the list ends where its
    /// runs end, so no upper bound is named and no total is summed to find one
    /// — asking the range walk for `total_width()` positions would walk the
    /// whole list once to learn a bound the walk then never needs. Lazy as the
    /// range walk is, so a consumer with a budget of its own stops the walk at
    /// it; an `ord` past the arranged end yields nothing, and so does a list
    /// holding nothing. The same clip as the range walk's, asked without a
    /// bound.
    pub(crate) fn iter_resolve_from(&self, ord: &Nat) -> impl Iterator<Item = Run> + '_ {
        self.clipped_runs(std::cmp::max(ord.clone(), Nat::one()), None)
    }

    /// Returns the mapping blocks in V-order (§1's `iter_runs`).
    ///
    /// It is [`blocks_of`] over the list's own runs, each stored run at its
    /// implicit V-start, which `locate`, the clip and `project` each ask
    /// rather than summing widths for themselves.
    pub(crate) fn iter_blocks(&self) -> impl Iterator<Item = Block<'_>> + '_ {
        blocks_of(self.0.iter())
    }

    /// Returns the canonical run decomposition, lent (maximally merged — M12).
    ///
    /// It is V-ordered: the runs alone, borrowed from the list rather than
    /// cloned out of it. [`iter_blocks`](RunList::iter_blocks) is the form
    /// that also reports each run's implicit V-start — the blocks.
    pub(crate) fn iter(&self) -> Runs<'_> {
        Runs(self.0.iter())
    }

    /// Returns the same decomposition collected.
    ///
    /// It is for this module's tests to compare against a literal sequence.
    #[cfg(test)]
    fn runs(&self) -> Vec<Run> {
        self.0.iter().cloned().collect()
    }

    /// Returns the I-image as a SpanSet: `⋃ r.iextent()`.
    ///
    /// It is a union (concatenation) only, total, not normalized, possibly
    /// mixed-length across transcluded origins (§2). M5-internal consumers
    /// apply the level-class discipline.
    pub(crate) fn image(&self) -> SpanSet {
        self.0.iter().map(Run::iextent).collect()
    }
}

#[cfg(test)]
mod tests;
