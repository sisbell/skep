//! §1 — the implicit-position run-list, per subspace: locate, splice,
//! contract, reorder, eager seam-coalesce (ASN-0058 M12/M14/M16; ASN-0082
//! shift-absorption; ASN-0117 P2; ASN-0119 tile-by-placement) — and the
//! union of a run set's I-extents ([`RunUnion`]), merged so that whole-run
//! membership is one search.
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
use skep_address::{ordinal, Address, Nat, SpanSet, Tumbler};

use crate::run::Run;

/// I-adjacency (ASN-0058): the right run starts exactly where the left run
/// [`reaches`](Run::reach), so their I-extents abut with no address between.
///
/// THE WHOLE RESIDUAL MERGE TEST. ASN-0058's merge condition (M7) is a
/// conjunction — two blocks may merge iff they are both V-adjacent
/// (`v₂ = v₁ + w₁`) and I-adjacent — and the first conjunct is discharged by
/// the representation: consecutive entries of an implicit-position run-list
/// occupy consecutive V-ordinals, so every neighbouring pair this guard is
/// asked about is already V-adjacent (`b₁.v_reach() == b₂.v_start`, in
/// [`Block`]'s terms; §1 — the same representation choice that makes
/// D-SEQ★/D-CTG★/D-MIN★ hold). I-adjacency is therefore all that
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
fn i_adjacent(left: &Run, right_start: &Address) -> bool {
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

/// A MAPPING BLOCK (ASN-0058): one stored run at the V-position the list
/// gives it — the atomic unit of V→I correspondence, `(v, a, w)`. The list
/// stores the run `(a, w)` alone; the V-start is the prefix sum of the widths
/// before it (§1), so a block is a VIEW the walk builds and never a stored
/// value — which is what keeps D-SEQ★/D-CTG★/D-MIN★ free. ASN-0058's merge
/// condition is stated on blocks — V-adjacent, `b₁.v_reach() == b₂.v_start`,
/// and I-adjacent — and the walk hands back consecutive blocks, which is how
/// [`i_adjacent`] discharges the first conjunct by construction.
///
/// M6's COMPARE builds the same value at its side of the seam — the run as
/// M5 handed it over, plus where its first position sits in V-space — under
/// the same corpus name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block<'a> {
    /// The block's first V-ordinal — the prefix sum + 1.
    pub(crate) v_start: Nat,
    /// The stored run: its I-start and width.
    pub(crate) run: &'a Run,
}

impl Block<'_> {
    /// The first V-ordinal past the block — `v_start + width`, the V-side
    /// twin of [`Run::reach`]; what `locate`'s bound, the clip and the
    /// splitter's interior test each ask.
    fn v_reach(&self) -> Nat {
        &self.v_start + &self.run.width
    }
}

/// The MAPPING BLOCKS of a run sequence held any way — each run at the
/// running prefix sum + 1 — so the list's own runs and a `Vec<Run>` a split
/// produced walk alike. THE ONE prefix-sum walk: [`RunList::iter_blocks`] is
/// this over the list, and [`split_runs`] asks it rather than summing widths
/// for itself.
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

/// Do `a` and `b` lie in ONE content chain — their starts equal in every
/// component but the ordinal, the `doc·0·subspace` both share (each a full
/// element position, [`Run::admits_start`](crate::Run::admits_start))? Two
/// runs share an address only within one content chain. And among run starts
/// one content chain's positions lie together in the tumbler order: a start
/// strictly between two positions of a content chain either is of that
/// content chain or extends its `doc·0·subspace` by two components or more —
/// an element field of three or more, which no run admits — while a start
/// differing earlier compares alike with every position of it. What
/// [`RunUnion`] merges within and searches by.
fn same_content_chain(a: &Run, b: &Run) -> bool {
    let (s, t) = (a.i_start.tumbler(), b.i_start.tumbler());
    s.len() == t.len()
        && s.iter()
            .zip(t.iter())
            .take(s.len() - 1)
            .all(|(x, y)| x == y)
}

/// The UNION of a run set's I-extents — every address some run of the set
/// holds — MERGED: within each content chain, runs that overlap or abut are
/// joined into one piece, so the pieces are disjoint, hold each address once,
/// lie in tumbler order, and no two of one content chain abut. BUILT ONLY by
/// [`RunUnion::of`], which is what lets [`covers`](RunUnion::covers) answer
/// by a binary search: the order it searches is the type's invariant, not a
/// promise its caller keeps.
///
/// BORROWED: a piece names the run that opens it and the run that reaches
/// furthest, two pointers apiece, so the union of a document's runs costs a
/// pointer per run beside the run-list it is asked of rather than a clone of
/// it — whose size stored state, and not the asking request, sets.
///
/// The publish shot asks it twice. Its existence walk (S3★) probes the union
/// of the supplied runs, each address once, so a request naming one stored
/// I-extent many times pays for it once. Its carried-run test (PUB-6.24)
/// merges the base's runs once per admission and asks each supplied run of
/// the union by one search, so a request of many carried runs pays the base's
/// run count once and not once a run.
pub(crate) struct RunUnion<'r>(Vec<UnionPiece<'r>>);

/// One piece of a [`RunUnion`]: the addresses `[first.i_start,
/// furthest.reach())` of one content chain — `first` the run that opens the
/// piece, `furthest` the one of its runs reaching furthest, both of that
/// content chain, so the piece is one contiguous ordinal range. Named fields,
/// both being runs: a positional pair would put them within swapping distance.
struct UnionPiece<'r> {
    first: &'r Run,
    furthest: &'r Run,
}

impl<'r> RunUnion<'r> {
    /// The union of `runs`' I-extents: sorted by start, then each run joined
    /// to the piece before it when it is of that piece's content chain and
    /// opens at or before the piece's reach — overlapping or abutting it — and
    /// opening a piece of its own otherwise. Sorting is what lets one pass
    /// join: one content chain's runs lie together among the starts
    /// ([`same_content_chain`]) and come in ordinal order within it, so a run
    /// joining no piece before it opens past every address that piece holds.
    /// `O(n log n)` comparisons for `n` runs, and a pointer per run.
    pub(crate) fn of(runs: impl IntoIterator<Item = &'r Run>) -> RunUnion<'r> {
        let mut sorted: Vec<&'r Run> = runs.into_iter().collect();
        sorted.sort_unstable_by(|a, b| a.i_start.tumbler().cmp(b.i_start.tumbler()));
        let mut pieces: Vec<UnionPiece<'r>> = Vec::with_capacity(sorted.len());
        // The last piece's reach, kept beside it rather than derived again for
        // every run asked whether it joins.
        let mut last_reach: Option<Tumbler> = None;
        for run in sorted {
            let run_reach = run.reach();
            if let (Some(piece), Some(piece_reach)) = (pieces.last_mut(), last_reach.as_mut()) {
                if same_content_chain(piece.first, run) && *run.i_start.tumbler() <= *piece_reach {
                    if run_reach > *piece_reach {
                        piece.furthest = run;
                        *piece_reach = run_reach;
                    }
                    continue;
                }
            }
            pieces.push(UnionPiece {
                first: run,
                furthest: run,
            });
            last_reach = Some(run_reach);
        }
        RunUnion(pieces)
    }

    /// Does the union hold EVERY address of `run`? One binary search, the
    /// pieces being sorted by start and disjoint: the only piece that can hold
    /// `run`'s start is the last one opening at or before it, which is of
    /// `run`'s content chain whenever any piece of it opens there
    /// ([`same_content_chain`]); and no two pieces of a content chain abut, so
    /// `run` is held whole exactly when that piece is of its content chain and
    /// reaches as far.
    ///
    /// A piece of ANOTHER content chain holds no address of `run`. Within one
    /// length, content chains are disjoint by their prefixes. Across lengths,
    /// a shorter address lies outside a longer piece's I-extent — it is
    /// compared within the longer's leading components, where both ends of
    /// that extent agree, so it falls below both or above both — and a longer
    /// address inside a shorter piece's would follow that piece's subspace
    /// with two components or more, an element field no run admits. So neither
    /// the run's width nor any piece's is searched: `O(log #pieces)`
    /// comparisons and one reach, however wide the run. Transclusion
    /// multiplicity costs nothing — the union holds a doubly arranged address
    /// once.
    pub(crate) fn covers(&self, run: &Run) -> bool {
        let at = self
            .0
            .partition_point(|piece| piece.first.i_start.tumbler() <= run.i_start.tumbler());
        at.checked_sub(1)
            .and_then(|i| self.0.get(i))
            .is_some_and(|piece| {
                same_content_chain(piece.first, run) && run.reach() <= piece.reach()
            })
    }

    /// The union's pieces as owned runs, in tumbler order — every address the
    /// set holds, in exactly one of them. What the shot's existence walk
    /// probes.
    pub(crate) fn runs(&self) -> impl Iterator<Item = Run> + '_ {
        self.0.iter().map(UnionPiece::to_run)
    }
}

impl UnionPiece<'_> {
    /// One I-step past the piece's last address: its furthest run's reach.
    fn reach(&self) -> Tumbler {
        self.furthest.reach()
    }

    /// The piece as an owned run — `first`'s start, widened to the piece's
    /// reach. A PROPAGATING mint, as [`Run::new`](crate::Run::new) divides
    /// them: the start is a run's own, so a full element position; and the
    /// width is the ordinal distance to a reach of the same content chain at or
    /// past `first`'s own, so at least `first`'s width — positive, and the
    /// subtraction cannot underflow.
    fn to_run(&self) -> Run {
        Run {
            i_start: self.first.i_start.clone(),
            width: ordinal(&self.reach()) - ordinal(self.first.i_start.tumbler()),
        }
    }
}

impl RunList {
    /// `n(d)` for this subspace — the total arranged width.
    pub(crate) fn total_width(&self) -> Nat {
        self.0.iter().map(Run::width).sum()
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
    /// already resolved. Answered off [`iter_blocks`](RunList::iter_blocks):
    /// the one prefix-sum walk, which hands each run back at its V-start.
    pub(crate) fn locate(&self, ord: &Nat) -> Option<(&Run, Nat)> {
        if ord.is_zero() {
            return None; // ordinal 0 lies before every run; the offset would underflow
        }
        self.iter_blocks()
            .find(|block| *ord < block.v_reach())
            .map(|block| (block.run, ord - &block.v_start))
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

    /// Does this list hold EVERY address of `run` — [`holds`](RunList::holds)
    /// asked of a whole I-extent: [`RunUnion::covers`] over the union of this
    /// list's runs, asked of one run. The composition the carried-run laws are
    /// pinned on; the publish shot builds the union once and asks it of every
    /// supplied run ([`M5State::content_union`](crate::M5State::content_union)).
    #[cfg(test)]
    fn covers(&self, run: &Run) -> bool {
        RunUnion::of(self.0.iter()).covers(run)
    }

    /// [`split_runs`] over this list's runs.
    fn split_at(&self, ord: &Nat) -> (Vec<Run>, Vec<Run>) {
        split_runs(self.0.iter(), ord)
    }

    /// Splice `new_runs` in at `ord` (§1): split, insert, concat, coalesce.
    /// The suffix's implicit positions are now `+Σ width(new_runs)` — the
    /// uniform forward shift, for free. Takes the runs by value, as
    /// `Vec::extend` does: the placing fold hands over clones of the record it
    /// borrows, and [`append`](RunList::append) hands over the one run it owns.
    #[must_use = "splice_in returns the new run-list; it does not modify the receiver"]
    pub(crate) fn splice_in(&self, ord: &Nat, new_runs: impl IntoIterator<Item = Run>) -> RunList {
        let (mut acc, right) = self.split_at(ord);
        acc.extend(new_runs);
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
        self.splice_in(&(self.total_width() + Nat::one()), [run])
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
    /// materialization of runs a bounded consumer will never look at. The
    /// first term is charged by the loops that run it inside a write, each
    /// spec at its source's whole run count: COPY's against
    /// [`MAX_COPY_RESOLVE_STEPS`](crate::MAX_COPY_RESOLVE_STEPS), M7's slots
    /// against its own.
    ///
    /// Called with `lo < hi_excl` when bounded. Every emitted run then has
    /// `width ≥ 1` and a start that is a full element position: a run reaching
    /// the push has `lo < v_reach` and, when bounded, `v_start < hi_excl`;
    /// `v_start < v_reach` because a run's width is at least one; so
    /// `first < past`, and the start is [`Run::addr_at`](crate::Run::addr_at)
    /// of an offset inside the run — an ordinal shift that keeps the element
    /// field's two components. Both `Nat` subtractions are therefore over
    /// ordered operands and cannot underflow. A run the range keeps WHOLE is
    /// cloned rather than rebuilt: no shift and no validation for a run the
    /// clip does not touch, which is every interior run of a wide range and
    /// every run but the first of a suffix.
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
            .flat_map(move |(lo, hi_excl)| self.clipped_runs(lo, Some(hi_excl)))
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
        self.clipped_runs(std::cmp::max(ord.clone(), Nat::one()), None)
    }

    /// The MAPPING BLOCKS (§1's `iter_runs`), in V-order — [`blocks_of`]
    /// over the list's own runs, each stored run at its implicit V-start —
    /// which `locate`, the clip and `project` each ask rather than summing
    /// widths for themselves.
    pub(crate) fn iter_blocks(&self) -> impl Iterator<Item = Block<'_>> + '_ {
        blocks_of(self.0.iter())
    }

    /// The canonical, V-ordered run decomposition (maximally merged — M12),
    /// LENT: the runs alone, borrowed from the list rather than cloned out of
    /// it. [`iter_blocks`](RunList::iter_blocks) is the form that also
    /// reports each run's implicit V-start — the blocks.
    pub(crate) fn iter(&self) -> Runs<'_> {
        Runs(self.0.iter())
    }

    /// The same decomposition collected, for this module's tests to compare
    /// against a literal sequence.
    #[cfg(test)]
    fn runs(&self) -> Vec<Run> {
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
mod tests;
