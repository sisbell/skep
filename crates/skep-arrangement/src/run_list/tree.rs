//! The counted tree a run-list is held as, and the one builder of it (§1).
//!
//! A list's runs stand in the leaves of a balanced tree, in V-order. Every
//! node carries two sums of what stands under it — its positions and its
//! runs — so an ordinal is found by a descent that reads the sums and no run
//! left of it. A node is never changed once it is built and is held through
//! an `Arc`, so a list handed on is one more handle on its root, and a list
//! made from another holds every node of it the change did not reach.
//!
//! **The shape.** A leaf holds [`MIN`] to [`MAX`] runs and an inner node
//! `MIN` to `MAX` children, the root excepted: a root leaf holds one run or
//! more, a root inner node two children or more. Every leaf stands at one
//! depth, and no node is empty — the empty list has no root.
//!
//! **The shape follows the operations alone.** Where a level is cut into
//! nodes, which nodes are opened and how their entries are grouped again are
//! decided by counts of entries and by the operations' ordinals: no hash,
//! no address, no pointer, no seed and no clock decides a boundary. So two
//! folds of one record stream build one shape, and a list decoded from the
//! node table (`table`) has the shape that was written.
//!
//! **One builder.** Every list but the empty one is what a [`Builder`]
//! answers: it is handed, in V-order, the pieces of the list to make — runs
//! placed, and stretches of an existing tree kept — and makes the nodes
//! that hold them. A kept stretch brings its tree's own nodes with it: a
//! node lying whole inside the stretch is shared, never read, wherever the
//! pieces before it close into nodes of their own. So a change costs the
//! nodes on the paths to its cuts and shares the rest, and the bulk build of
//! a list from its runs is the same builder handed runs alone.
//!
//! **Maximal merge.** No two neighbouring runs of a list are I-adjacent
//! (ASN-0058 M12), across leaves and subtrees as inside a leaf. The builder
//! keeps it at the seams and nowhere else: a run placed is tested against
//! the run out before it, and so is the first run of each kept stretch; the
//! runs after it in the stretch were neighbours in a list that held the
//! invariant, and are not tested again.
//!
//! **The counted unit.** Each walk here charges its `steps` one for every
//! node it opens — reads the entries of — and one for every run it reads or
//! places. A node shared whole is not opened and costs nothing.

use std::sync::Arc;

use num_traits::Zero;
use skep_address::Nat;

use super::{extend_or_push_run, i_adjacent, part_of};
use crate::run::Run;

/// The fewest entries a node holds, the root excepted.
pub(super) const MIN: usize = 8;

/// The most entries a node holds.
pub(super) const MAX: usize = 16;

/// How many waiting entries of one level make the builder cut a node.
///
/// A node of [`MAX`] is cut from the front once a level holds this many, so
/// at least [`MIN`] wait behind it and the level can always close.
const CUT_AT: usize = MAX + MIN;

/// The tallest tree whose runs a machine word counts.
///
/// A root of height `h` holds two children or more and every node beneath
/// it [`MIN`] entries or more, so it holds at least `2 · MIN^h` runs; past
/// this height that is more than `usize::MAX`. No list a fold builds is
/// taller, and the node table's decode door refuses one that is, so every
/// walk of a tree recurses this deep at most.
pub(super) const MAX_HEIGHT: usize = (usize::BITS as usize - 2) / 3;

#[cfg(test)]
thread_local! {
    /// How many nodes this thread's read walks have entered: the tests'
    /// count of a read that takes no `steps`, so one that should read the
    /// root's sums alone is seen to enter no node.
    pub(super) static ENTERED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Notes one node entered by a read walk, for the tests' count.
#[inline]
fn entered() {
    #[cfg(test)]
    ENTERED.with(|count| count.set(count.get() + 1));
}

/// One node of the tree: what stands under it, counted, and its entries.
pub(super) struct Node {
    /// The positions under the node: the sum of its runs' widths.
    width: Nat,
    /// How many runs stand under the node.
    count: usize,
    entries: Entries,
}

/// A node's entries, in V-order.
enum Entries {
    /// A leaf's runs.
    Runs(Box<[Run]>),
    /// An inner node's children, each one level lower than `height`.
    Nodes { height: u8, children: Box<[Arc<Node>]> },
}

/// A node's entries, lent: what [`Node::view`] answers.
pub(super) enum View<'l> {
    /// A leaf's runs, in V-order.
    Runs(&'l [Run]),
    /// An inner node's children, in V-order.
    Nodes(&'l [Arc<Node>]),
}

impl Node {
    /// Builds a leaf of `runs`, its sums counted.
    ///
    /// **Precondition.** `runs` holds one run or more, no two neighbours
    /// I-adjacent; the caller keeps the leaf's bounds.
    pub(super) fn leaf(runs: Vec<Run>) -> Arc<Node> {
        let width = runs.iter().map(|run| &run.width).sum();
        Arc::new(Node { width, count: runs.len(), entries: Entries::Runs(runs.into_boxed_slice()) })
    }

    /// Builds an inner node over `children`, its sums counted.
    ///
    /// The run count saturates, so no sum here can panic; a count past a
    /// machine word needs a list no fold builds ([`MAX_HEIGHT`]).
    ///
    /// **Precondition.** `children` holds one node or more, all of one
    /// height; the caller keeps the node's bounds.
    pub(super) fn inner(children: Vec<Arc<Node>>) -> Arc<Node> {
        let width = children.iter().map(|child| &child.width).sum();
        let count = children.iter().fold(0usize, |sum, child| sum.saturating_add(child.count));
        let height = children.first().map_or(0, |child| child.height()).saturating_add(1);
        let height = u8::try_from(height).unwrap_or(u8::MAX);
        Arc::new(Node { width, count, entries: Entries::Nodes { height, children: children.into_boxed_slice() } })
    }

    /// Returns the positions under the node.
    pub(super) fn width(&self) -> &Nat {
        &self.width
    }

    /// Returns how many runs stand under the node.
    pub(super) fn count(&self) -> usize {
        self.count
    }

    /// Returns the node's height: 0 for a leaf.
    pub(super) fn height(&self) -> usize {
        match &self.entries {
            Entries::Runs(_) => 0,
            Entries::Nodes { height, .. } => usize::from(*height),
        }
    }

    /// Returns how many entries the node holds: its runs, or its children.
    pub(super) fn len(&self) -> usize {
        match &self.entries {
            Entries::Runs(runs) => runs.len(),
            Entries::Nodes { children, .. } => children.len(),
        }
    }

    /// Returns the node's entries, lent.
    pub(super) fn view(&self) -> View<'_> {
        match &self.entries {
            Entries::Runs(runs) => View::Runs(runs),
            Entries::Nodes { children, .. } => View::Nodes(children),
        }
    }

    /// Returns an inner node's children, `None` for a leaf.
    pub(super) fn children(&self) -> Option<&[Arc<Node>]> {
        match &self.entries {
            Entries::Runs(_) => None,
            Entries::Nodes { children, .. } => Some(children),
        }
    }

    /// Returns the first run under the node, down its left spine.
    pub(super) fn first_run(&self) -> Option<&Run> {
        let mut node = self;
        loop {
            match &node.entries {
                Entries::Runs(runs) => return runs.first(),
                Entries::Nodes { children, .. } => node = children.first()?,
            }
        }
    }

    /// Returns the last run under the node, down its right spine.
    pub(super) fn last_run(&self) -> Option<&Run> {
        let mut node = self;
        loop {
            match &node.entries {
                Entries::Runs(runs) => return runs.last(),
                Entries::Nodes { children, .. } => node = children.last()?,
            }
        }
    }
}

/// Returns the sizes `count` entries are closed into: as few nodes as hold
/// them, as even as they come.
///
/// `⌈count ÷ MAX⌉` nodes, the earlier ones the larger by one where the
/// count does not divide; each holds [`MIN`] or more where `count` does.
fn even(count: usize) -> impl Iterator<Item = usize> {
    let nodes = count.div_ceil(MAX).max(1);
    let (each, over) = (count / nodes, count % nodes);
    (0..nodes).map(move |at| each + usize::from(at < over))
}

/// Empties `entries` into the vectors [`even`] sizes, each of exact
/// capacity, leaving `entries` its allocation; none where it holds none.
fn closed<T>(entries: &mut Vec<T>) -> Vec<Vec<T>> {
    let count = entries.len();
    if count == 0 {
        return Vec::new();
    }
    let mut rest = entries.drain(..);
    even(count).map(|size| rest.by_ref().take(size).collect()).collect()
}

/// The builder of a tree: the pieces of a list taken in V-order, and the
/// nodes that hold them made bottom up.
///
/// What is out and not yet under a parent waits in levels: `runs` for a
/// leaf, and `open[h]` — nodes of height `h` — for a parent of height
/// `h + 1`. Every node of `open[h + 1]` stands left of every node of
/// `open[h]`, and `runs` right of them all, so the list out so far reads
/// from the highest level down.
///
/// **What it makes anew, and what it shares.** A run handed over joins
/// `runs`, and a level is cut into a node of [`MAX`] from its front once it
/// holds [`CUT_AT`] entries. A node of a kept stretch that lies whole inside
/// the stretch is put into its level as it stands — shared, not read —
/// where three things hold: its first run does not join the run out before
/// it; it holds [`MIN`] entries or more (a root may hold fewer, and may not
/// stand beneath another node so); and everything waiting below its height
/// closes into nodes of `MIN` or more. Otherwise the node is opened and its
/// entries are handed over one by one, each judged the same way. So the
/// nodes opened are those a stretch's two ends fall strictly inside, those
/// a seam joins a run into, and those right of an end whose entries the
/// short levels before them need; every other node is shared whole.
///
/// **What is grouped again.** The entries of an opened node pass through
/// their level, where they are cut and closed with their neighbours, so the
/// children of two opened siblings may come out grouped otherwise than they
/// went in. A node shared whole keeps its group. No pass re-packs a node the
/// pieces did not open.
pub(super) struct Builder {
    /// The runs out and under no leaf yet.
    runs: Vec<Run>,
    /// For each height, the nodes out and under no parent yet.
    open: Vec<Vec<Arc<Node>>>,
    /// Whether the next kept run opens a stretch, and so is tested against
    /// the run out before it.
    seam: bool,
}

impl Builder {
    /// Returns a builder that has taken nothing.
    pub(super) fn new() -> Builder {
        Builder { runs: Vec::new(), open: Vec::new(), seam: false }
    }

    /// Takes one placed run: the next of the list being built.
    ///
    /// It is tested against the run out before it and widens that run where
    /// the two are I-adjacent, across a leaf's edge as inside one, so the
    /// runs placed need hold no merge among themselves. `steps` is charged
    /// one for the run, and one for every node and run a merge across a
    /// leaf's edge reads back.
    pub(super) fn place(&mut self, run: Run, steps: &mut impl FnMut(u64)) {
        steps(1);
        self.out(run, true, steps);
    }

    /// Takes the stretch of the tree at `root` over the offsets
    /// `[from, to)`: the next of the list being built.
    ///
    /// An offset is an ordinal less one. With no `to` the stretch runs to
    /// the tree's end; a stretch of no position, and the part of one lying
    /// past the end, take nothing. The stretch's first run is tested
    /// against the run out before it, as a placed run is; the others were
    /// its neighbours in `root`'s list and are not. A run an end falls
    /// inside is clipped to the stretch.
    ///
    /// `steps` is charged one for every node the walk opens and one for
    /// every run of an opened leaf it reads: the two paths to the
    /// stretch's ends, and what the builder's own card says is opened
    /// beside them. No node left of `from` or right of `to` is opened.
    pub(super) fn keep(&mut self, root: &Arc<Node>, from: &Nat, to: Option<&Nat>, steps: &mut impl FnMut(u64)) {
        if to.is_some_and(|to| to <= from) || *root.width() <= *from {
            return;
        }
        self.seam = true;
        self.within(root, &Nat::zero(), root.width(), from, to, steps);
    }

    /// Takes the part of `node` inside `[from, to)`, `node` standing over
    /// the offsets `[at, reach)` and reaching into the stretch.
    fn within(&mut self, node: &Arc<Node>, at: &Nat, reach: &Nat, from: &Nat, to: Option<&Nat>, steps: &mut impl FnMut(u64)) {
        if from <= at && to.is_none_or(|to| reach <= to) {
            return self.whole(node, steps);
        }
        steps(1);
        let mut at = at.clone();
        match &node.entries {
            Entries::Runs(runs) => {
                for run in runs.iter() {
                    if to.is_some_and(|to| *to <= at) {
                        break;
                    }
                    steps(1);
                    let reach = &at + &run.width;
                    if reach > *from {
                        let first = std::cmp::max(&at, from) - &at;
                        let past = to.map_or(&reach, |to| std::cmp::min(&reach, to)) - &at;
                        self.kept(part_of(run, &first, &past), steps);
                    }
                    at = reach;
                }
            }
            Entries::Nodes { children, .. } => {
                for child in children.iter() {
                    if to.is_some_and(|to| *to <= at) {
                        break;
                    }
                    let reach = &at + &child.width;
                    if reach > *from {
                        self.within(child, &at, &reach, from, to, steps);
                    }
                    at = reach;
                }
            }
        }
    }

    /// Takes `node` whole: shared as it stands where the builder's card
    /// allows it, opened otherwise.
    fn whole(&mut self, node: &Arc<Node>, steps: &mut impl FnMut(u64)) {
        if self.seam {
            let joins = match (self.last_out(), node.first_run()) {
                (Some(last), Some(first)) => i_adjacent(last, &first.i_start),
                _ => false,
            };
            // Tested, and the stretch's first run stands apart: nothing
            // of the stretch can join what is out.
            if !joins {
                self.seam = false;
            }
        }
        let height = node.height();
        if !self.seam && node.len() >= MIN && self.closes_below(height) {
            self.close_below(height);
            self.push_at(Arc::clone(node), height);
            return;
        }
        steps(1);
        match &node.entries {
            Entries::Runs(runs) => {
                for run in runs.iter() {
                    steps(1);
                    self.kept(run.clone(), steps);
                }
            }
            Entries::Nodes { children, .. } => {
                for child in children.iter() {
                    self.whole(child, steps);
                }
            }
        }
    }

    /// Takes one run of a kept stretch, tested where it opens the stretch.
    fn kept(&mut self, run: Run, steps: &mut impl FnMut(u64)) {
        let opens = std::mem::replace(&mut self.seam, false);
        self.out(run, opens, steps);
    }

    /// Puts one run out, and cuts a leaf where enough wait.
    ///
    /// A `tested` run widens the run out before it where the two are
    /// I-adjacent: through the one accumulator where that run waits in
    /// `runs`, and, where it stands in a leaf already made, with that leaf
    /// taken back first.
    fn out(&mut self, run: Run, tested: bool, steps: &mut impl FnMut(u64)) {
        if self.runs.capacity() == 0 {
            self.runs.reserve_exact(CUT_AT);
        }
        if tested {
            if self.runs.is_empty() && self.last_out().is_some_and(|last| i_adjacent(last, &run.i_start)) {
                self.take_back_last_leaf(steps);
            }
            extend_or_push_run(&mut self.runs, run);
        } else {
            self.runs.push(run);
        }
        if self.runs.len() >= CUT_AT {
            let leaf = Node::leaf(self.runs.drain(..MAX).collect());
            self.push_at(leaf, 0);
        }
    }

    /// Returns the last run out: the last waiting, or the last under the
    /// rightmost node of the lowest level holding one.
    fn last_out(&self) -> Option<&Run> {
        if let Some(run) = self.runs.last() {
            return Some(run);
        }
        let lowest = self.open.iter().find(|level| !level.is_empty())?;
        lowest.last().and_then(|node| node.last_run())
    }

    /// Takes the rightmost leaf back out of the levels: its runs wait
    /// again, and the other children of each node above it wait in the
    /// level they belong to.
    ///
    /// **Precondition.** No run waits: the leaf's runs are the last out.
    fn take_back_last_leaf(&mut self, steps: &mut impl FnMut(u64)) {
        let Some(mut height) = self.open.iter().position(|level| !level.is_empty()) else {
            return;
        };
        let Some(mut node) = self.open[height].pop() else {
            return;
        };
        loop {
            steps(1);
            let last = match &node.entries {
                Entries::Runs(runs) => {
                    steps(runs.len() as u64);
                    self.runs.extend(runs.iter().cloned());
                    return;
                }
                Entries::Nodes { children, .. } => {
                    let Some((last, rest)) = children.split_last() else {
                        return;
                    };
                    height -= 1;
                    self.open[height].extend(rest.iter().cloned());
                    Arc::clone(last)
                }
            };
            node = last;
        }
    }

    /// Puts `node` into the level of its `height`, and cuts a parent where
    /// enough wait.
    fn push_at(&mut self, node: Arc<Node>, height: usize) {
        if self.open.len() <= height {
            self.open.resize_with(height + 1, Vec::new);
        }
        let level = &mut self.open[height];
        if level.capacity() == 0 {
            level.reserve_exact(CUT_AT);
        }
        level.push(node);
        if level.len() >= CUT_AT {
            let parent = Node::inner(level.drain(..MAX).collect());
            self.push_at(parent, height + 1);
        }
    }

    /// Returns whether everything waiting below `height` closes into nodes
    /// of that height with none under [`MIN`] entries.
    fn closes_below(&self, height: usize) -> bool {
        // What waits to close into nodes of the height in hand: the runs
        // into leaves, then each level's nodes beside the ones the level
        // below closes into.
        let mut waiting = self.runs.len();
        for level in 0..height {
            if waiting > 0 && waiting < MIN {
                return false;
            }
            waiting = waiting.div_ceil(MAX) + self.open.get(level).map_or(0, Vec::len);
        }
        waiting == 0 || waiting >= MIN
    }

    /// Closes everything waiting below `height` into nodes of that height.
    ///
    /// **Precondition.** [`closes_below`](Builder::closes_below) of
    /// `height`.
    fn close_below(&mut self, height: usize) {
        for leaf in closed(&mut self.runs) {
            self.put(Node::leaf(leaf), 0);
        }
        for level in 0..height {
            if self.open.get(level).is_some_and(|nodes| !nodes.is_empty()) {
                for children in closed(&mut self.open[level]) {
                    self.put(Node::inner(children), level + 1);
                }
            }
        }
    }

    /// Puts `node` into the level of its `height` and cuts nothing: the
    /// level is being closed, or will be.
    fn put(&mut self, node: Arc<Node>, height: usize) {
        if self.open.len() <= height {
            self.open.resize_with(height + 1, Vec::new);
        }
        self.open[height].push(node);
    }

    /// Returns whether a node waits in any level.
    fn any_open(&self) -> bool {
        self.open.iter().any(|level| !level.is_empty())
    }

    /// Moves the rightmost node above `height` down: its children of that
    /// height wait in front of the level's own, and the other children of
    /// each node between wait in the level they belong to.
    fn borrow_into(&mut self, height: usize, steps: &mut impl FnMut(u64)) {
        let Some(mut from) = (height + 1..self.open.len()).find(|&above| !self.open[above].is_empty()) else {
            return;
        };
        let Some(mut node) = self.open[from].pop() else {
            return;
        };
        loop {
            steps(1);
            let Entries::Nodes { children, .. } = &node.entries else {
                return;
            };
            from -= 1;
            if from == height {
                let mut front: Vec<Arc<Node>> = children.to_vec();
                front.append(&mut self.open[height]);
                self.open[height] = front;
                return;
            }
            let Some((last, rest)) = children.split_last() else {
                return;
            };
            self.open[from].extend(rest.iter().cloned());
            let last = Arc::clone(last);
            node = last;
        }
    }

    /// Returns the root of the list taken, `None` where nothing was.
    ///
    /// Every level is closed from the leaves up. Runs too few for a leaf of
    /// their own take the last leaf made back; a level too short for a
    /// node of its own takes the rightmost node above it down; and the
    /// highest level becomes the root — its one node, or a node over them.
    /// `steps` is charged one for every node those two repairs open and one
    /// for every run the first reads back.
    pub(super) fn finish(mut self, steps: &mut impl FnMut(u64)) -> Option<Arc<Node>> {
        if !self.runs.is_empty() && self.runs.len() < MIN && self.any_open() {
            // The tail's first run was tested against the leaf's last when
            // it came out, and stood apart: the two meet with no merge.
            let tail = std::mem::take(&mut self.runs);
            self.take_back_last_leaf(steps);
            self.runs.extend(tail);
        }
        if !self.runs.is_empty() {
            if !self.any_open() && self.runs.len() <= MAX {
                return Some(Node::leaf(self.runs));
            }
            for leaf in closed(&mut self.runs) {
                self.put(Node::leaf(leaf), 0);
            }
        }
        let mut height = 0;
        loop {
            let higher = self.open.iter().skip(height + 1).any(|level| !level.is_empty());
            let waiting = self.open.get(height).map_or(0, Vec::len);
            if !higher {
                match waiting {
                    0 => return None,
                    1 => return self.open[height].pop(),
                    count if count <= MAX => return Some(Node::inner(std::mem::take(&mut self.open[height]))),
                    _ => {}
                }
            } else if waiting > 0 && waiting < MIN {
                self.borrow_into(height, steps);
            }
            if self.open.get(height).is_some_and(|nodes| !nodes.is_empty()) {
                for children in closed(&mut self.open[height]) {
                    self.put(Node::inner(children), height + 1);
                }
            }
            height += 1;
        }
    }
}

/// Returns the run of `root`'s list holding the offset `at`, lent, and
/// `at`'s offset in it; `None` where `at` lies past the list.
///
/// A descent on the width sums. `steps` is charged one for every node
/// opened — one a level, the root and the leaf among them — and one for
/// every run of the leaf read: at most the tree's height plus one, and
/// [`MAX`].
pub(super) fn locate<'l>(root: &'l Node, at: &Nat, steps: &mut impl FnMut(u64)) -> Option<(&'l Run, Nat)> {
    if *at >= root.width {
        return None;
    }
    let mut left = at.clone();
    let mut node = root;
    'descent: loop {
        steps(1);
        entered();
        match &node.entries {
            Entries::Runs(runs) => {
                for run in runs.iter() {
                    steps(1);
                    if left < run.width {
                        return Some((run, left));
                    }
                    left -= &run.width;
                }
                return None;
            }
            Entries::Nodes { children, .. } => {
                for child in children.iter() {
                    if left < child.width {
                        node = child;
                        continue 'descent;
                    }
                    left -= &child.width;
                }
                return None;
            }
        }
    }
}

/// A place in a tree's V-order, and the way on from it in one direction.
///
/// It holds the leaf in hand as the runs of it still to read, and for each
/// level above it the siblings still to enter, so moving on to the next run
/// reads no sum and opens a node only where a leaf, or a node above it, is
/// used up.
pub(super) struct Walk<'l> {
    /// For each level above the leaf in hand, root first, the children
    /// still to enter.
    above: Vec<std::slice::Iter<'l, Arc<Node>>>,
    /// The runs of the leaf in hand still to read.
    leaf: std::slice::Iter<'l, Run>,
}

impl<'l> Walk<'l> {
    /// Returns a walk that has nothing to read.
    fn spent() -> Walk<'l> {
        Walk { above: Vec::new(), leaf: [].iter() }
    }

    /// Returns a walk standing before the first run under `root`.
    ///
    /// `steps` is charged one for every node entered on the way down: the
    /// tree's height plus one.
    pub(super) fn from_first(root: &'l Node, steps: &mut impl FnMut(u64)) -> Walk<'l> {
        let mut walk = Walk { above: Vec::with_capacity(root.height()), leaf: [].iter() };
        walk.enter_first(root, steps);
        walk
    }

    /// Returns a walk standing past the last run under `root`, to be read
    /// [`back`](Walk::back).
    pub(super) fn from_last(root: &'l Node) -> Walk<'l> {
        let mut walk = Walk { above: Vec::with_capacity(root.height()), leaf: [].iter() };
        walk.enter_last(root);
        walk
    }

    /// Returns the walk standing just past the run holding the offset `at`,
    /// with that run and the offset its first position stands at; `None`
    /// where `at` lies past `root`'s list.
    ///
    /// A descent on the width sums, charged as [`locate`] is.
    pub(super) fn seek(root: &'l Node, at: &Nat, steps: &mut impl FnMut(u64)) -> Option<(Walk<'l>, &'l Run, Nat)> {
        if *at >= root.width {
            return None;
        }
        let mut walk = Walk { above: Vec::with_capacity(root.height()), leaf: [].iter() };
        // The offset the entry in hand stands at.
        let mut before = Nat::zero();
        let mut node = root;
        'descent: loop {
            steps(1);
            entered();
            match &node.entries {
                Entries::Runs(runs) => {
                    let mut leaf = runs.iter();
                    while let Some(run) = leaf.next() {
                        steps(1);
                        let reach = &before + &run.width;
                        if *at < reach {
                            walk.leaf = leaf;
                            return Some((walk, run, before));
                        }
                        before = reach;
                    }
                    return None;
                }
                Entries::Nodes { children, .. } => {
                    let mut siblings = children.iter();
                    while let Some(child) = siblings.next() {
                        let reach = &before + &child.width;
                        if *at < reach {
                            walk.above.push(siblings);
                            node = child;
                            continue 'descent;
                        }
                        before = reach;
                    }
                    return None;
                }
            }
        }
    }

    /// Returns the walk standing just past the last run under `root`, with
    /// that run: nothing is left to read forward.
    pub(super) fn at_last(root: &'l Node, steps: &mut impl FnMut(u64)) -> Option<(Walk<'l>, &'l Run)> {
        let mut node = root;
        loop {
            steps(1);
            entered();
            match &node.entries {
                Entries::Runs(runs) => {
                    steps(1);
                    return runs.last().map(|run| (Walk::spent(), run));
                }
                Entries::Nodes { children, .. } => node = children.last()?,
            }
        }
    }

    /// Stands the walk before the first run under `node`, the siblings
    /// passed on the way kept for later.
    fn enter_first(&mut self, mut node: &'l Node, steps: &mut impl FnMut(u64)) {
        loop {
            steps(1);
            entered();
            match &node.entries {
                Entries::Runs(runs) => {
                    self.leaf = runs.iter();
                    return;
                }
                Entries::Nodes { children, .. } => {
                    let mut siblings = children.iter();
                    let Some(first) = siblings.next() else {
                        return;
                    };
                    self.above.push(siblings);
                    node = first;
                }
            }
        }
    }

    /// Stands the walk past the last run under `node`, the siblings passed
    /// on the way kept for later.
    fn enter_last(&mut self, mut node: &'l Node) {
        loop {
            entered();
            match &node.entries {
                Entries::Runs(runs) => {
                    self.leaf = runs.iter();
                    return;
                }
                Entries::Nodes { children, .. } => {
                    let mut siblings = children.iter();
                    let Some(last) = siblings.next_back() else {
                        return;
                    };
                    self.above.push(siblings);
                    node = last;
                }
            }
        }
    }

    /// Returns the next run in V-order, `None` past the last.
    ///
    /// `steps` is charged one for the run read, and one for every node
    /// entered where the leaf in hand is used up.
    pub(super) fn next(&mut self, steps: &mut impl FnMut(u64)) -> Option<&'l Run> {
        loop {
            if let Some(run) = self.leaf.next() {
                steps(1);
                return Some(run);
            }
            let next = loop {
                let siblings = self.above.last_mut()?;
                if let Some(next) = siblings.next() {
                    break next;
                }
                self.above.pop();
            };
            self.enter_first(next, steps);
        }
    }

    /// Returns the run before the place in V-order, `None` before the
    /// first: [`next`](Walk::next) read the other way.
    pub(super) fn back(&mut self) -> Option<&'l Run> {
        loop {
            if let Some(run) = self.leaf.next_back() {
                return Some(run);
            }
            let next = loop {
                let siblings = self.above.last_mut()?;
                if let Some(next) = siblings.next_back() {
                    break next;
                }
                self.above.pop();
            };
            self.enter_last(next);
        }
    }
}

#[cfg(test)]
pub(super) mod tests;
