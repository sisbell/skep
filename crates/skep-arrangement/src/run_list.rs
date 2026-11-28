//! The implicit-position run-list, per subspace (§1).
//!
//! It locates, splices, contracts, reorders and seam-coalesces (ASN-0058
//! M12/M14/M16; ASN-0082 shift-absorption; ASN-0117 P2; ASN-0119
//! tile-by-placement).
//!
//! A `RunList` is an ordered sequence of [`Run`]s; V-positions are not
//! stored — run *j* occupies the ordinals `[1 + Σ_{i<j} widthᵢ, …]`. This one
//! choice makes the load-bearing invariants free: density / contiguity /
//! minimum-position (D-SEQ★/D-CTG★/D-MIN★) hold by construction (a V-start is
//! always a prefix sum, so no holes), and insert/delete shift the suffix for
//! free (the spec's ASN-0082 displacement is never computed).
//!
//! **Decision #1**: the physical persistent structure is a counted tree
//! (`tree`), each node carrying the width and the run count beneath it and
//! shared between the lists that hold it. The reason is what a flat
//! persistent vector of runs costs. A write rebuilds it whole — a splice
//! reads every run to find its site and writes every run back — and that
//! rebuild runs under M2's applier lock, so a write holds every writer for
//! every run of the document. A list so rebuilt shares nothing with the one
//! it was made from, so each version, landing and edit keeps a whole list of
//! its own. And an ordinal is found by summing widths from the first run.
//! On the tree a write makes anew only the nodes on the paths to its cuts
//! and shares the rest, an ordinal is found by a descent, and a checkpoint
//! writes each shared node once (`table`).

use std::fmt;
use std::sync::Arc;

use num_traits::{One, Zero};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use skep_address::{Address, Nat, SpanSet};

use crate::run::Run;
#[cfg(test)]
use crate::run_union::RunUnion;

// The vector-backed list the tree replaced, kept as the tests' oracle.
#[cfg(test)]
mod oracle;
// The node table: every list of a slice written as one table of nodes, each
// shared node once, and the decode door that rebuilds them shared.
pub(crate) mod table;
// The counted tree a list is held as: the node, the one builder, the
// descents and the walk.
mod tree;

use tree::{Builder, Node, Walk};

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

/// One positional change to a run-list: positions removed, runs placed (§1).
///
/// `width` positions are removed from ordinal `at` on, and `runs` are placed
/// where they stood: a removal alone where `runs` is empty, a placement
/// before `at` alone where `width` is zero, a replacement where it is
/// neither. `at` is an ordinal of the list as it stands before any change of
/// the set it belongs to, so the changes of one set name positions of one
/// state and none is moved by another (`RunList::spliced`, which takes
/// them ascending and apart).
///
/// It is what [`M5Rec::ContentEdit`](crate::M5Rec::ContentEdit) carries, one
/// a change, and so a part of that record's journal encoding: its fields in
/// this order, each [`Run`] through `Run`'s own decode door. Sealed as the
/// record's variants are (`#[non_exhaustive]`): a foreign crate reads one
/// and builds none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Splice {
    /// The ordinal of the first position removed.
    ///
    /// Where `width` is zero it is the ordinal `runs` are placed before, the
    /// append boundary `n + 1` among them.
    pub at: Nat,
    /// How many positions are removed from `at` on.
    pub width: Nat,
    /// The runs placed where the removed positions stood, in order.
    pub runs: Vec<Run>,
}

/// Returns the part of `run` that holds its offsets `[from, to)`.
///
/// `run` whole where the range is the run, cloned; else the clipped run, its
/// start shifted by `from` ([`Run::addr_at`]).
///
/// **Precondition.** `from < to ≤ run.width`: the part holds a position, and
/// none past the run.
fn part_of(run: &Run, from: &Nat, to: &Nat) -> Run {
    if from.is_zero() && *to == run.width {
        return run.clone();
    }
    Run {
        i_start: run.addr_at(from),
        width: to - from,
    }
}

/// Returns the offset before ordinal `ord`: `ord − 1`, and 0 for ordinal 0.
///
/// An offset counts the positions left of a boundary, so the boundary
/// before ordinal 1 and the defensive clamp of ordinal 0 are both offset 0
/// (ASN-0119 tile-by-placement note), and the append boundary `n + 1` is
/// offset `n`, the list's width.
fn offset_before(ord: &Nat) -> Nat {
    if ord.is_zero() {
        Nat::zero()
    } else {
        ord - Nat::one()
    }
}

/// The per-subspace run-list (§Core data model).
///
/// All mutators are persistent (`&self → RunList`). The list is a handle on
/// the root of a counted tree (`tree`): a clone is one more handle (VERSION's
/// structural fork share), and a mutator's answer holds every node of the
/// receiver its change did not reach.
///
/// **Maximal merge is the invariant**: the resident form is the unique
/// maximally-merged decomposition (ASN-0058 M12), so
/// [`content_runs`](crate::M5State::content_runs) and
/// [`link_runs`](crate::M5State::link_runs) publish canonical run structure
/// and `resolve` serves it. It holds across leaves and subtrees as inside a
/// leaf. Every mutator here builds its answer through the tree's one builder,
/// which tests each seam the change makes as it is made — and no other,
/// the receiver holding the invariant already — and both decode doors
/// establish it: this type's own, which reads a list as its runs in V-order,
/// and the node table's (`table`), which reads the lists of a checkpoint.
/// Without them a recovered list could hold two I-adjacent runs and every
/// read publishing canonicality would answer off it, silently and across
/// restarts.
///
/// The decode doors repair rather than refuse, which is what distinguishes
/// them from [`Run`]'s and `Provenance`'s: a non-merged list denotes exactly
/// the right V→I map, and the merge is total, idempotent and
/// denotation-preserving, so establishing the invariant is what a
/// constructor is for. Refusing would turn a fully recoverable store into a
/// dead one for no gain. The reads therefore rest on the type, not on M2's
/// checksum.
///
/// **Equality is the run sequence's**, never the tree's shape: two lists of
/// one run sequence are equal however their nodes are grouped, and `Debug`
/// prints the sequence. A shape is a fact about how a list was reached — a
/// bulk build, a history of splices — and no read answers off it.
///
/// **Its serde form here is its runs in V-order**: a sequence of [`Run`]s,
/// what a list reads as wherever it is written alone. A checkpoint does not
/// write a list so — `M5State`'s own form writes every list it holds as a
/// root of one node table — and the form here is the one a rendering of the
/// slice by its run sequences takes
/// ([`M5State::as_run_sequences`](crate::M5State::as_run_sequences)).
#[derive(Clone, Default, Deserialize)]
#[serde(from = "RunListShadow")]
pub(crate) struct RunList {
    /// The root of the list's tree, `None` for the empty list.
    root: Option<Arc<Node>>,
}

impl PartialEq for RunList {
    fn eq(&self, other: &RunList) -> bool {
        match (&self.root, &other.root) {
            (None, None) => true,
            (Some(mine), Some(theirs)) => {
                Arc::ptr_eq(mine, theirs)
                    || (mine.count() == theirs.count() && mine.width() == theirs.width() && self.iter().eq(other.iter()))
            }
            _ => false,
        }
    }
}

impl Eq for RunList {}

/// Formats the run sequence, as a list of runs prints.
impl fmt::Debug for RunList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct InOrder<'l>(&'l RunList);
        impl fmt::Debug for InOrder<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.0.iter()).finish()
            }
        }
        f.debug_tuple("RunList").field(&InOrder(self)).finish()
    }
}

/// Writes the list as its runs in V-order: a sequence, each run through
/// `Run`'s own form.
impl Serialize for RunList {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        struct InOrder<'l>(&'l RunList);
        impl Serialize for InOrder<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_seq(self.0.iter())
            }
        }
        serializer.serialize_newtype_struct("RunList", &InOrder(self))
    }
}

/// The deserialization mint path of a list written as its runs.
///
/// [`Run`] and `Provenance` each carry a shadow too; this one takes `from`
/// rather than `try_from` because the conversion is total. The decoded runs
/// enter the tree's builder one by one, each tested against the run before
/// it, so the maximal-merge invariant holds for every `RunList` in the
/// process rather than for every one the folds built, and the list comes
/// out in the shape a bulk build gives it.
///
/// It reads exactly what a `RunList` writes — a sequence of runs — run by
/// run, each through `Run`'s own door, so no count the bytes declare sizes
/// a reservation.
#[derive(Deserialize)]
struct RunListShadow(#[serde(deserialize_with = "run_by_run")] RunList);

impl From<RunListShadow> for RunList {
    fn from(shadow: RunListShadow) -> RunList {
        shadow.0
    }
}

/// Decodes a sequence of runs into a list, one run at a time, in order.
///
/// Reserves nothing; each run is decoded by its own `Deserialize` and handed
/// to the tree's builder, which merges it into the run before it where the
/// two are I-adjacent.
///
/// # Errors
///
/// Returns `D::Error` where a run does not decode, including where the input
/// runs out before the count its bytes declare.
fn run_by_run<'de, D: Deserializer<'de>>(deserializer: D) -> Result<RunList, D::Error> {
    struct InOrder;

    impl<'de> Visitor<'de> for InOrder {
        type Value = RunList;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a sequence of runs")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut runs: A) -> Result<RunList, A::Error> {
            let mut out = Builder::new();
            while let Some(run) = runs.next_element()? {
                out.place(run, &mut |_| {});
            }
            Ok(RunList { root: out.finish(&mut |_| {}) })
        }
    }

    deserializer.deserialize_seq(InOrder)
}

/// Borrowed runs of one subspace's run-list, in V-order.
///
/// They are what [`M5State::content_runs`](crate::M5State::content_runs) and
/// [`link_runs`](crate::M5State::link_runs) lend. Opaque, as M1's `Spans` is,
/// so the list's backing (Decision #1) stays this module's own.
///
/// Opacity hides the container, never the walk's capabilities: the exact
/// length is `#runs`, read off the tree's root without reading a run; the
/// walk runs from either end, each end descending its own side of the tree
/// when it is first pulled, the two meeting on the count; and it is fused.
/// `Clone` is withheld, as M1 withholds it on `Spans`: a caller wanting two
/// cursors asks the arrangement for two.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Runs<'a> {
    /// The tree walked, `None` for the empty list.
    root: Option<&'a Node>,
    /// How many runs neither end has yielded.
    left: usize,
    /// The walk from the first run on, once the front is pulled.
    front: Option<Walk<'a>>,
    /// The walk from the last run back, once the back is pulled.
    back: Option<Walk<'a>>,
}

impl<'a> Iterator for Runs<'a> {
    type Item = &'a Run;
    fn next(&mut self) -> Option<&'a Run> {
        if self.left == 0 {
            return None;
        }
        let root = self.root?;
        self.left -= 1;
        self.front.get_or_insert_with(|| Walk::from_first(root, &mut |_| {})).next(&mut |_| {})
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl<'a> DoubleEndedIterator for Runs<'a> {
    fn next_back(&mut self) -> Option<&'a Run> {
        if self.left == 0 {
            return None;
        }
        let root = self.root?;
        self.left -= 1;
        self.back.get_or_insert_with(|| Walk::from_last(root)).back()
    }
}

impl ExactSizeIterator for Runs<'_> {
    fn len(&self) -> usize {
        self.left
    }
}

impl std::iter::FusedIterator for Runs<'_> {}

/// Formats the cursor, not the runs.
///
/// There is no way to show what is left without spending it, and the
/// arrangement it was lent from is `Debug` already.
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
    /// It is the V-side twin of [`Run::reach`].
    #[cfg(test)]
    fn v_reach(&self) -> Nat {
        &self.v_start + &self.run.width
    }
}

/// Returns the mapping blocks of a run sequence held any way.
///
/// Each run stands at the running prefix sum + 1. This is the one prefix-sum
/// walk of every run: [`RunList::iter_blocks`] is this over the list's own
/// runs, for the reads that answer off every block.
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

/// The cursor of one check of a run-list at several sites: the run in hand,
/// at its V-start, and the way on from it.
///
/// It is what [`RunList::arranges_each`] judges every site on. The cursor
/// never moves back: a site left of the run in hand is not held. It moves
/// on by the list's own order where the next position asked is the run in
/// hand's reach, and by a descent from the root anywhere farther, so the
/// runs between two far sites are never read.
struct Cursor<'l> {
    /// The tree walked, `None` for the empty list.
    root: Option<&'l Node>,
    /// The run in hand and the ordinal it stands at: none before the first
    /// seek.
    hand: Option<(&'l Run, Nat)>,
    /// The walk standing just past the run in hand.
    walk: Option<Walk<'l>>,
}

impl<'l> Cursor<'l> {
    /// Moves forward to the run holding `ord` and returns it with `ord`'s
    /// offset in it.
    ///
    /// `None` where the list ends before `ord`, and where the cursor
    /// already stands past it. A seek past the list's end leaves the last
    /// run in hand, and one of ordinal 0 the first, as a walk run by run
    /// would. `steps` is charged one for every node opened and one for
    /// every run read: one run where the cursor moves on to the next, and
    /// a descent — the tree's height plus one in nodes, a leaf's runs at
    /// most — where it jumps.
    fn seek(&mut self, ord: &Nat, steps: &mut impl FnMut(u64)) -> Option<(&'l Run, Nat)> {
        loop {
            if let Some((run, v_start)) = &self.hand {
                if ord < v_start {
                    return None;
                }
                let v_reach = v_start + &run.width;
                if *ord < v_reach {
                    return Some((*run, ord - v_start));
                }
                if *ord == v_reach {
                    // The next run: one step along the list's own order.
                    let next = self.walk.as_mut()?.next(steps)?;
                    self.hand = Some((next, v_reach));
                    continue;
                }
            }
            let root = self.root?;
            if ord.is_zero() {
                // Ordinal 0 lies before every run: the first comes to hand.
                let mut walk = Walk::from_first(root, steps);
                let first = walk.next(steps)?;
                self.hand = Some((first, Nat::one()));
                self.walk = Some(walk);
                continue;
            }
            match Walk::seek(root, &(ord - Nat::one()), steps) {
                Some((walk, run, before)) => {
                    self.hand = Some((run, before + Nat::one()));
                    self.walk = Some(walk);
                }
                None => {
                    // Past the end: the last run comes to hand, as it would
                    // by reading on to it.
                    let (walk, last) = Walk::at_last(root, steps)?;
                    self.hand = Some((last, root.width() - &last.width + Nat::one()));
                    self.walk = Some(walk);
                    return None;
                }
            }
        }
    }
}

/// The clip's walk: the runs over the offsets `[from, to)`, cut at the two
/// ends, pulled one at a time.
///
/// Nothing is read before the first pull, which descends to `from`; each
/// later pull reads the next run of the list's own order.
struct Clipped<'l, F> {
    state: Clip<'l>,
    /// The offset of the first position kept.
    from: Nat,
    /// The offset past the last position kept; `None` for the list's end.
    to: Option<Nat>,
    steps: F,
}

/// Where a [`Clipped`] walk stands.
enum Clip<'l> {
    /// Not pulled yet: the descent to the first position is still to make.
    Unopened(&'l Node),
    /// Pulled: the walk past the run last yielded, and the offset the next
    /// run stands at.
    Open { walk: Walk<'l>, at: Nat },
    /// Past the range, or past the list.
    Done,
}

impl<F: FnMut(u64)> Iterator for Clipped<'_, F> {
    type Item = Run;

    fn next(&mut self) -> Option<Run> {
        let (run, at) = match std::mem::replace(&mut self.state, Clip::Done) {
            Clip::Done => return None,
            Clip::Unopened(root) => {
                let (walk, run, at) = Walk::seek(root, &self.from, &mut self.steps)?;
                self.state = Clip::Open { walk, at: &at + &run.width };
                (run, at)
            }
            Clip::Open { mut walk, at } => {
                if self.to.as_ref().is_some_and(|to| *to <= at) {
                    return None;
                }
                let run = walk.next(&mut self.steps)?;
                self.state = Clip::Open { walk, at: &at + &run.width };
                (run, at)
            }
        };
        let reach = &at + &run.width;
        let first = std::cmp::max(&at, &self.from) - &at;
        let past = self.to.as_ref().map_or(&reach, |to| std::cmp::min(&reach, to)) - &at;
        Some(part_of(run, &first, &past))
    }
}

impl RunList {
    /// Returns the list of `runs` in order, maximally merged.
    ///
    /// The bulk build: the runs handed to the tree's builder one by one, so
    /// two I-adjacent neighbours come out one run, leaves and inner nodes
    /// are packed full from the left, and the last two of a level share
    /// what is left so neither is short.
    #[cfg(test)]
    pub(crate) fn from_runs(runs: impl IntoIterator<Item = Run>) -> RunList {
        let mut out = Builder::new();
        for run in runs {
            out.place(run, &mut |_| {});
        }
        RunList { root: out.finish(&mut |_| {}) }
    }

    /// Returns `n(d)` for this subspace: the total arranged width.
    ///
    /// Read off the tree's root, which carries the sum: no run is read.
    pub(crate) fn total_width(&self) -> Nat {
        self.root.as_ref().map_or_else(Nat::zero, |root| root.width().clone())
    }

    /// Returns `#runs`, how many runs the list holds.
    ///
    /// It is the fragmentation every walk of the whole list here is priced
    /// in. Read off the tree's root, which carries the count.
    pub(crate) fn run_count(&self) -> usize {
        self.root.as_ref().map_or(0, |root| root.count())
    }

    /// Returns whether the list holds no runs, and so no positions.
    ///
    /// Every run has `width ≥ 1`, and the empty list has no root.
    pub(crate) fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Returns the run holding ordinal `ord`, lent, and `ord`'s offset in it.
    ///
    /// The offset is 0-based; `None` when `ord` is 0 or past the last arranged
    /// ordinal (§1 locate). The run itself rather than its index, so a caller
    /// holds what it asked for and never re-fetches it by a coordinate this
    /// read already resolved. A descent on the tree's width sums: it opens
    /// one node a level and reads the runs of one leaf, whatever the list
    /// holds left of `ord`.
    pub(crate) fn locate(&self, ord: &Nat) -> Option<(&Run, Nat)> {
        self.locate_counted(ord, &mut |_| {})
    }

    /// Returns [`locate`](RunList::locate), its descent counted.
    ///
    /// `steps` is charged one for every node opened and one for every run
    /// read: at most `height + 1` nodes and 16 runs.
    fn locate_counted(&self, ord: &Nat, steps: &mut impl FnMut(u64)) -> Option<(&Run, Nat)> {
        if ord.is_zero() {
            return None; // ordinal 0 lies before every run
        }
        tree::locate(self.root.as_deref()?, &(ord - Nat::one()), steps)
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
    /// asks this of a document's link list. The tree is ordered by V and
    /// says nothing of I, so this reads every run until one holds `a`.
    pub(crate) fn holds(&self, a: &Address) -> bool {
        self.iter().any(|r| r.iextent().contains(a.tumbler()))
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
        RunUnion::of(self.iter()).covers(run)
    }

    /// Returns the list with `new_runs` spliced in at `ord` (§1).
    ///
    /// The runs left of the boundary before `ord` are kept, the new runs
    /// placed, and the runs from the boundary on kept after them. The
    /// suffix's implicit positions shift by `+Σ width(new_runs)` — the
    /// uniform forward shift, for free. `ord ≤ 1` places before everything —
    /// the defensive clamp under which a splice at 0 and at 1 coincide
    /// (ASN-0119 tile-by-placement note) — and `ord` past the append
    /// boundary `n + 1` places after everything. An interior `ord` cuts the
    /// run it falls in, `Run(a, w) → Run(a, kept), Run(a ⊕ kept, w − kept)`.
    /// Takes the runs by value, as `Vec::extend` does: the placing fold
    /// hands over clones of the record it borrows.
    ///
    /// **What it makes anew.** The nodes on the path to the boundary and
    /// the leaves the placed runs fill; every other node of the receiver is
    /// shared. Its two seams — the run kept before the placement against the
    /// first run placed, and the last placed against the run kept after —
    /// are tested as they are made, and a run that joins one across a leaf's
    /// edge is merged into it there.
    #[must_use = "splice_in returns the new run-list; it does not modify the receiver"]
    pub(crate) fn splice_in(&self, ord: &Nat, new_runs: impl IntoIterator<Item = Run>) -> RunList {
        self.splice_in_counted(ord, new_runs, &mut |_| {})
    }

    /// Returns [`splice_in`](RunList::splice_in), its walk counted.
    ///
    /// `steps` is charged one for every node opened, one for every run of an
    /// opened leaf read and one for every run placed: at most
    /// `2 · c + #runs placed`, `c` as [`spliced`](RunList::spliced) states
    /// it, whatever the list holds.
    fn splice_in_counted(&self, ord: &Nat, new_runs: impl IntoIterator<Item = Run>, steps: &mut impl FnMut(u64)) -> RunList {
        let at = offset_before(ord);
        let mut out = Builder::new();
        if let Some(root) = &self.root {
            out.keep(root, &Nat::zero(), Some(&at), steps);
        }
        for run in new_runs {
            out.place(run, steps);
        }
        if let Some(root) = &self.root {
            out.keep(root, &at, None, steps);
        }
        RunList { root: out.finish(steps) }
    }

    /// Returns the list with `run` added after everything it already holds.
    ///
    /// That is the append boundary `total + 1`, which the content ops reach
    /// through `admits_content_boundary` and the link seat targets (§8's
    /// `n_L(d) + 1`). Where the end lies is this list's knowledge, so a
    /// caller meaning "after everything" says that rather than computing it:
    /// the receiver's tree is kept whole, no ordinal is found, and the run is
    /// placed after its last. Coalesces with the last run when I-adjacent, as
    /// any splice does.
    #[must_use = "append returns the new run-list; it does not modify the receiver"]
    pub(crate) fn append(&self, run: Run) -> RunList {
        self.append_counted(run, &mut |_| {})
    }

    /// Returns [`append`](RunList::append), its walk counted.
    ///
    /// `steps` is charged as [`splice_in_counted`](RunList::splice_in_counted)
    /// charges, within the same bound: the nodes of the right spine the
    /// run's leaf is made beside, and that leaf's runs.
    fn append_counted(&self, run: Run, steps: &mut impl FnMut(u64)) -> RunList {
        let mut out = Builder::new();
        if let Some(root) = &self.root {
            out.keep(root, &Nat::zero(), None, steps);
        }
        out.place(run, steps);
        RunList { root: out.finish(steps) }
    }

    /// Returns the list with ordinals `[from, from + width)` removed (§1).
    ///
    /// The runs left of `from` are kept and the runs from `from + width` on
    /// kept after them; the runs the two ends fall in are cut there. Suffix
    /// positions shift left for free; the gap closes by construction
    /// (ASN-0117 P2). `from ≤ 1` removes from the first position, and a
    /// removal running past the end removes what is there.
    ///
    /// **What it makes anew.** The nodes on the paths to the two ends. No
    /// node wholly inside the removed range is opened, and every node
    /// outside the two paths is shared. Its one seam — the run kept before
    /// the gap against the run kept after — is tested, and the two merge
    /// where they are I-adjacent, across a leaf's edge as inside a leaf.
    #[must_use = "remove_range returns the new run-list; it does not modify the receiver"]
    pub(crate) fn remove_range(&self, from: &Nat, width: &Nat) -> RunList {
        self.remove_range_counted(from, width, &mut |_| {})
    }

    /// Returns [`remove_range`](RunList::remove_range), its walk counted.
    ///
    /// `steps` is charged one for every node opened and one for every run of
    /// an opened leaf read: at most `2 · c`, `c` as
    /// [`spliced`](RunList::spliced) states it, whatever the list and the
    /// removed range hold.
    fn remove_range_counted(&self, from: &Nat, width: &Nat, steps: &mut impl FnMut(u64)) -> RunList {
        let Some(root) = &self.root else {
            return RunList::default();
        };
        let first = offset_before(from);
        let mut out = Builder::new();
        out.keep(root, &Nat::zero(), Some(&first), steps);
        out.keep(root, &(first + width), None, steps);
        RunList { root: out.finish(steps) }
    }

    /// Returns the list with every change of `changes` made (§1).
    ///
    /// Each change removes its `width` positions from its `at` on and places
    /// its `runs` where they stood ([`Splice`]). The changes name ordinals of
    /// this list as it stands, so the answer is what
    /// [`remove_range`](RunList::remove_range) and
    /// [`splice_in`](RunList::splice_in) leave when each change is made by
    /// the two in turn from the last change down — the order in which no
    /// change moves the positions of one still to make. The suffix past each
    /// site shifts for free, as a splice's and a removal's does.
    ///
    /// **One pass over the changes, and the list read at its cuts alone.**
    /// The answer is built in V-order: the stretch of the list kept before
    /// each change, the runs the change places, and after the last change
    /// the stretch kept to the end. A kept stretch is found by a descent to
    /// each of its ends; the run an end falls in is cut there, and a node
    /// lying whole inside the stretch is shared, never read. So the answer
    /// holds every node of the receiver no change reaches, and makes anew
    /// the nodes on the paths to the changes' cuts and the leaves the placed
    /// runs fill. A change that removes the whole list and places every run
    /// — a landing in its whole form — opens no node of the receiver and
    /// shares none: its answer is the bulk build of its runs.
    ///
    /// **The seams.** Two a change, each tested as it is made: the run kept
    /// before a site against the first run placed there, and the last
    /// placed against the run kept after — or, where a change places
    /// nothing, the two sides of its removal against each other; where two
    /// changes touch, the later's first run against the earlier's last.
    /// Every placed run is tested against the one before it, so the placed
    /// runs need hold no merge among themselves. A seam that joins runs
    /// across a leaf's or a subtree's edge merges them, and the answer is
    /// maximally merged (M12) with no pass of its own.
    ///
    /// `steps` is charged one for every change, one for every run placed,
    /// one for every node opened and one for every run of an opened leaf
    /// read: at most `(#changes + 1) · c + Σ #runs placed`, where
    /// `c = 6 · (height + 1) + 81` bounds what one kept stretch and the
    /// seam before it open — the two paths to the stretch's ends, the path
    /// a joined seam takes a leaf back by, the path of nodes opened where
    /// the levels before them were short, the path the last level's close
    /// repairs, and the runs of the five leaves those paths end in —
    /// whatever the list holds. The list's run count does not enter it.
    ///
    /// **Precondition.** `changes` are ascending and apart — each `at` at or
    /// past `at + width` of the change before it — the first `at` is at
    /// least 1, and the last change's `at + width` is at most `n + 1`. Two
    /// changes may touch, and two placements may name one ordinal, the
    /// earlier's runs then standing before the later's. The body that
    /// stages the record judges all of it
    /// ([`Vstream::edit`](crate::Vstream::edit), by its changes' shapes;
    /// [`stage_substitute`](crate::stage_substitute), whose places it holds
    /// apart before the record is built).
    /// Outside it the answer is total all the same, as the fold's panic-free
    /// promise requires ([`apply_m5`](crate::M5State::apply_m5)): a change
    /// whose site an earlier change's removal has passed is made where that
    /// removal ended, one whose site lies past the list is made at its end,
    /// and a removal running past the end removes what is there.
    #[must_use = "spliced returns the new run-list; it does not modify the receiver"]
    pub(crate) fn spliced(&self, changes: &[Splice], steps: &mut impl FnMut(u64)) -> RunList {
        if changes.is_empty() {
            return self.clone();
        }
        let mut out = Builder::new();
        // The offset of the first position of the list no change has
        // passed: what stands from here on is still to keep or remove.
        let mut passed = Nat::zero();
        for change in changes {
            steps(1);
            let site = offset_before(&change.at);
            if site > passed {
                if let Some(root) = &self.root {
                    out.keep(root, &passed, Some(&site), steps);
                }
                passed = site;
            }
            for run in &change.runs {
                out.place(run.clone(), steps);
            }
            passed += &change.width;
        }
        if let Some(root) = &self.root {
            out.keep(root, &passed, None, steps);
        }
        RunList { root: out.finish(steps) }
    }

    /// Returns, for each site of `sites`, whether the list arranges exactly
    /// the site's runs over the positions that open at its ordinal (§1).
    ///
    /// A site is an ordinal and the runs asked of it, in order. It is held
    /// where the positions from the ordinal on, as many as the runs are
    /// wide together, are arranged, and map to the runs' addresses in the
    /// runs' order and to nothing else: the check by identity, by
    /// membership at the place alone. Run boundaries decide nothing — two
    /// I-adjacent runs asked where the list holds one run, and one run asked
    /// where an edit left the list two, answer alike — so each side's
    /// addresses are compared stretch by stretch, a stretch ending where
    /// either side's run does. A site asking no run is not held: no piece
    /// is no arrangement. Neither is one that opens at ordinal 0, or reaches
    /// past the last arranged position.
    ///
    /// **One cursor, forward only, and a descent to each site.** The cursor
    /// descends to the run a site opens in, compares the site's runs there
    /// run by run along the list's own order, and stands where the
    /// comparison ended for the next site, which it reaches by a descent of
    /// its own — or by one step, where that site opens at the very position
    /// the comparison ended. So no run left of the first site is read, none
    /// between two sites apart, and none past the last.
    ///
    /// `steps` is charged one for every site, one for every run of a site it
    /// compares, one for every node opened and one for every run of the list
    /// read: at most `#sites · (2 · (height + 1) + 20) + 3 · Σ #runs asked`
    /// — for each site its own step, one descent and the walk on from it;
    /// for each run asked its own step and the run or two of the list it is
    /// compared against — whatever the list holds. The list's run count
    /// does not enter it.
    ///
    /// **Precondition.** `sites` are ascending and apart — each ordinal at
    /// or past the reach of the site before it. Outside it the check is
    /// total all the same: a site the cursor has passed is answered not
    /// held, whatever the list arranges there.
    pub(crate) fn arranges_each<'r, S>(
        &self,
        sites: impl IntoIterator<Item = (&'r Nat, S)>,
        steps: &mut impl FnMut(u64),
    ) -> Vec<bool>
    where
        S: IntoIterator<Item = &'r Run>,
    {
        let mut cursor = Cursor { root: self.root.as_deref(), hand: None, walk: None };
        let mut held = Vec::new();
        for (at, asked) in sites {
            steps(1);
            // The next position of the site still to compare.
            let mut here = at.clone();
            let mut any = false;
            let mut same = true;
            'site: for piece in asked {
                steps(1);
                any = true;
                // How many of the piece's positions are compared already.
                let mut done = Nat::zero();
                while done < piece.width {
                    let Some((run, offset)) = cursor.seek(&here, steps) else {
                        same = false;
                        break 'site;
                    };
                    if run.addr_at(&offset) != piece.addr_at(&done) {
                        same = false;
                        break 'site;
                    }
                    let stretch = std::cmp::min(&run.width - &offset, &piece.width - &done);
                    here += &stretch;
                    done += stretch;
                }
            }
            held.push(any && same);
        }
        held
    }

    /// Returns the list transposed at the cuts' ordinals (§1; ASN-0119).
    ///
    /// The transpose is cut-determined and value-blind: cut at each of the
    /// cut sequence's ordinals `ord(cⱼ)` and **tile by placement** —
    /// `[exterior-left][β][μ?][α][exterior-right]` — never offset arithmetic,
    /// so the bijection is structural (no swap-α offset bug, ASN-0084 Q14).
    /// 3 ordinals: pivot (α = [c₀,c₁), β = [c₁,c₂) exchange). 4: swap
    /// (α = [c₀,c₁), μ = [c₁,c₂), β = [c₂,c₃); outer two exchange, middle
    /// stays).
    ///
    /// Pivot and swap are one computation: the stretch left of the first
    /// cut is kept, then the stretches between the cuts from the last pair
    /// down to the first — β, then μ where there is one, then α — then the
    /// stretch from the last cut on, which is the exchange whatever the
    /// region count.
    ///
    /// **What it makes anew.** The nodes on the paths to its cuts; a node
    /// lying whole inside one stretch is shared where it lands. One seam at
    /// each stretch's opening — three for a pivot, four for a swap — is
    /// tested as it is made, and the two runs merge where the exchange
    /// brings I-adjacent runs side by side.
    ///
    /// **The 3|4 clause is the op's obligation**, discharged at staging by
    /// [`Vstream::rearrange`](crate::Vstream::rearrange)'s `BadCutCount`, and
    /// it is not re-asked here. The tiling is total for any vector instead:
    /// each cut is held to the list — `ord ≤ 1` the boundary before
    /// everything, one past the end the boundary after it — and to the cut
    /// after it, read from the last cut down, so with fewer than three
    /// ordinals there is no interior region to move and the list comes back
    /// as it stands, and with more every stretch between two cuts is kept
    /// once. That totality is what
    /// [`apply_m5`](crate::M5State::apply_m5)'s panic-free promise requires
    /// of this method, a corrupt cut vector being something the replay path
    /// must tile rather than stop on.
    #[must_use = "reorder returns the new run-list; it does not modify the receiver"]
    pub(crate) fn reorder(&self, cut_ordinals: &[Nat]) -> RunList {
        self.reorder_counted(cut_ordinals, &mut |_| {})
    }

    /// Returns [`reorder`](RunList::reorder), its walk counted.
    ///
    /// `steps` is charged one for every cut, one for every node opened and
    /// one for every run of an opened leaf read: at most `(#cuts + 1) · c`,
    /// `c` as [`spliced`](RunList::spliced) states it, whatever the list
    /// holds.
    fn reorder_counted(&self, cut_ordinals: &[Nat], steps: &mut impl FnMut(u64)) -> RunList {
        let (Some(root), Some((last, earlier))) = (&self.root, cut_ordinals.split_last()) else {
            return self.clone();
        };
        // The offsets the cuts fall at, the last first: each held to the
        // list and to the cut after it.
        steps(1);
        let mut at = std::cmp::min(offset_before(last), root.width().clone());
        let mut cuts = vec![at.clone()];
        for cut in earlier.iter().rev() {
            steps(1);
            at = std::cmp::min(offset_before(cut), at);
            cuts.push(at.clone());
        }
        let mut out = Builder::new();
        // What lies left of the first cut.
        out.keep(root, &Nat::zero(), cuts.last(), steps);
        // The regions between the cuts, from the last pair down.
        for pair in cuts.windows(2) {
            out.keep(root, &pair[1], Some(&pair[0]), steps);
        }
        // What lies from the last cut on.
        out.keep(root, &cuts[0], None, steps);
        RunList { root: out.finish(steps) }
    }

    /// Returns the runs covering the offsets `[from, to)`, boundaries
    /// clipped, with the walk's steps charged to `steps`.
    ///
    /// With no `to` the range runs to the list's end. The runs are yielded
    /// lazily: nothing outside the range is cloned, nothing is read before
    /// the first pull, and a consumer that stops early stops the walk with
    /// it. This is the one clip, which the range walk and the suffix walk
    /// both ask, so the boundary arithmetic and its proof are written once.
    ///
    /// **What this costs**, since a resolution's caller is a per-spec loop —
    /// COPY's, M7's slot endsets, M6's RETRIEVEV — and a request's spec count
    /// multiplies whatever one call costs. The first pull descends the
    /// tree's width sums to the range's first position: one node a level
    /// and the runs of one leaf, whatever the list holds left of it. Each
    /// later pull reads the next run of the list's own order. So pulling
    /// the whole range is `Θ(height) + Θ(#runs in the range)`, resolving
    /// the last position of an n-run list costs a descent however large n
    /// is, and a range that yields nothing — one opening past the arranged
    /// end — reads no run at all. What a caller bounds is therefore the
    /// runs it pulls, as it pulls them.
    ///
    /// `steps` is charged one for every node opened and one for every run of
    /// the list read: at most `height + 1` nodes and 16 runs for the first
    /// pull, and for each later pull the run it yields and the nodes entered
    /// where a leaf is used up.
    ///
    /// **Precondition.** `from < to` when bounded. Every emitted run then
    /// has `width ≥ 1` and a start that is a full element position: the
    /// first run yielded holds `from`, each later one opens before `to`,
    /// and a run's width is at least one, so `first < past`, and the start
    /// is [`Run::addr_at`](crate::Run::addr_at) of an offset inside the run
    /// — an ordinal shift that keeps the element field's two components.
    /// Both `Nat` subtractions are therefore over ordered operands and
    /// cannot underflow. A run the range keeps whole is cloned rather than
    /// rebuilt: no shift and no validation for a run the clip does not
    /// touch, which is every interior run of a wide range and every run but
    /// the first of a suffix.
    ///
    /// # Panics
    ///
    /// Panics where the precondition is broken with `to < from` and a run
    /// spans both: `past − first` underflows.
    fn clipped_runs<'l, F: FnMut(u64) + 'l>(&'l self, from: Nat, to: Option<Nat>, steps: F) -> impl Iterator<Item = Run> + 'l {
        let state = match self.root.as_deref() {
            Some(root) => Clip::Unopened(root),
            None => Clip::Done,
        };
        Clipped { state, from, to, steps }
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
    /// so clipping each run at the range's end already drops everything
    /// beyond the arrangement.
    pub(crate) fn iter_resolve_range(&self, ord: &Nat, count: &Nat) -> impl Iterator<Item = Run> + '_ {
        self.iter_resolve_range_counted(ord, count, |_| {})
    }

    /// Returns [`iter_resolve_range`](RunList::iter_resolve_range), its
    /// walk counted as the clip counts it.
    fn iter_resolve_range_counted<'l, F: FnMut(u64) + 'l>(&'l self, ord: &Nat, count: &Nat, steps: F) -> impl Iterator<Item = Run> + 'l {
        let lo = std::cmp::max(ord.clone(), Nat::one());
        let hi_excl = ord + count;
        // An empty range names no position, and it is excluded here rather
        // than clipped to nothing below: a run straddling `hi_excl ≤ lo` would
        // otherwise clip to `past − first = hi_excl − lo`, which underflows
        // where `hi_excl < lo` and is a zero-width run where the two are equal.
        (lo < hi_excl)
            .then(|| self.clipped_runs(lo - Nat::one(), Some(hi_excl - Nat::one()), steps))
            .into_iter()
            .flatten()
    }

    /// Returns the I-runs covering ordinals `[max(ord, 1), total]`.
    ///
    /// That is everything from the boundary before `ord` to the arranged end,
    /// V-ordered, the boundary run clipped as
    /// [`iter_resolve_range`](RunList::iter_resolve_range) clips it and every
    /// later run yielded whole. The suffix twin of that range walk, for a
    /// caller that means "everything past a boundary": the list ends where its
    /// runs end, so no upper bound is named. Lazy as the range walk is, so a
    /// consumer with a budget of its own stops the walk at it; an `ord` past
    /// the arranged end yields nothing, and so does a list holding nothing.
    /// The same clip as the range walk's, asked without a bound. No read of
    /// the slice asks it — a shot's member is built from its base's tree,
    /// so nothing walks a base's tail — and it stands for this module's
    /// tests, which hold the unbounded clip to the bounded one.
    #[cfg(test)]
    pub(crate) fn iter_resolve_from(&self, ord: &Nat) -> impl Iterator<Item = Run> + '_ {
        self.clipped_runs(offset_before(ord), None, |_| {})
    }

    /// Returns the mapping blocks in V-order (§1's `iter_runs`).
    ///
    /// It is [`blocks_of`] over the list's own runs, each stored run at its
    /// implicit V-start: a walk of every run, which `project` asks rather
    /// than summing widths for itself.
    pub(crate) fn iter_blocks(&self) -> impl Iterator<Item = Block<'_>> + '_ {
        blocks_of(self.iter())
    }

    /// Returns the canonical run decomposition, lent (maximally merged — M12).
    ///
    /// It is V-ordered: the runs alone, borrowed from the tree's leaves
    /// rather than cloned out of them. [`iter_blocks`](RunList::iter_blocks)
    /// is the form that also reports each run's implicit V-start — the
    /// blocks.
    pub(crate) fn iter(&self) -> Runs<'_> {
        Runs { root: self.root.as_deref(), left: self.run_count(), front: None, back: None }
    }

    /// Returns the same decomposition collected.
    ///
    /// It is for this module's tests to compare against a literal sequence.
    #[cfg(test)]
    fn runs(&self) -> Vec<Run> {
        self.iter().cloned().collect()
    }

    /// Returns the I-image as a SpanSet: `⋃ r.iextent()`.
    ///
    /// It is a union (concatenation) only, total, not normalized, possibly
    /// mixed-length across transcluded origins (§2). M5-internal consumers
    /// apply the level-class discipline.
    pub(crate) fn image(&self) -> SpanSet {
        self.iter().map(Run::iextent).collect()
    }
}

/// What the suites read of a list's tree: its height, its invariants, and
/// which of its nodes it shares.
#[cfg(test)]
impl RunList {
    /// Returns the tree's height: 0 for the empty list and for a lone leaf.
    pub(crate) fn height(&self) -> usize {
        self.root.as_ref().map_or(0, |root| root.height())
    }

    /// Returns what one kept stretch and the seam before it may open of
    /// this list's tree, in steps: `c` of [`spliced`](RunList::spliced)'s
    /// card.
    pub(crate) fn cut_steps(&self) -> u64 {
        6 * (self.height() as u64 + 1) + 81
    }

    /// Holds the tree to every invariant of its module's card.
    ///
    /// # Errors
    ///
    /// Says which invariant the first node to break one broke.
    pub(crate) fn check(&self) -> Result<(), String> {
        self.root.as_ref().map_or(Ok(()), |root| tree::tests::check(root))
    }

    /// Returns whether `self` and `other` are handles on one root.
    pub(crate) fn shares_root_with(&self, other: &RunList) -> bool {
        match (&self.root, &other.root) {
            (Some(mine), Some(theirs)) => Arc::ptr_eq(mine, theirs),
            (None, None) => true,
            _ => false,
        }
    }

    /// Counts the nodes of this list's tree that no list of `others` holds:
    /// the leaves, then the inner nodes.
    pub(crate) fn made_anew(&self, others: &[&RunList]) -> (usize, usize) {
        let mut held = std::collections::HashSet::new();
        for root in others.iter().filter_map(|other| other.root.as_ref()) {
            tree::tests::nodes_of(root, &mut held);
        }
        self.root.as_ref().map_or((0, 0), |root| tree::tests::made_anew(root, &mut held))
    }

    /// Counts the nodes the lists of `lists` hold between them, each once.
    pub(crate) fn nodes_among(lists: &[&RunList]) -> usize {
        let mut held = std::collections::HashSet::new();
        for root in lists.iter().filter_map(|list| list.root.as_ref()) {
            tree::tests::nodes_of(root, &mut held);
        }
        held.len()
    }

    /// Returns how many nodes this thread's read walks have entered: the
    /// count of the reads that take no `steps`, for a suite outside this
    /// module.
    pub(crate) fn nodes_entered() -> u64 {
        tree::ENTERED.with(std::cell::Cell::get)
    }

    /// Returns the tree's fill: how many leaves hold each count of runs,
    /// and how many inner nodes each count of children.
    pub(crate) fn fill(&self) -> (std::collections::BTreeMap<usize, usize>, std::collections::BTreeMap<usize, usize>) {
        self.root.as_ref().map_or_else(Default::default, |root| tree::tests::fill(root))
    }
}

#[cfg(test)]
mod tests;
