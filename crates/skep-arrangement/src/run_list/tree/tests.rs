//! The tree's own invariants, and the helpers the run-list's suites read a
//! tree's shape with.

use std::collections::{BTreeMap, HashSet};

use num_traits::One;

use super::*;
use crate::testutil::{a, n, run};

/// Holds the tree at `root` to every invariant of the module's card.
///
/// Each node's two sums equal a recount of what stands under it; every node
/// holds [`MIN`] to [`MAX`] entries, the root excepted — a root leaf one
/// run or more, a root inner node two children or more; every child of a
/// node is one level lower than it, so every leaf stands at one depth; and
/// no two neighbouring runs are I-adjacent, across every boundary.
///
/// # Errors
///
/// Says which invariant the first node to break one broke.
pub(in crate::run_list) fn check(root: &Node) -> Result<(), String> {
    fn held(node: &Node, is_root: bool) -> Result<(), String> {
        let len = node.len();
        match node.view() {
            View::Runs(runs) => {
                if node.height() != 0 {
                    return Err(format!("a leaf at height {}", node.height()));
                }
                if len == 0 || len > MAX || (!is_root && len < MIN) {
                    return Err(format!("a leaf of {len} runs (root: {is_root})"));
                }
                let width: Nat = runs.iter().map(|run| &run.width).sum();
                if width != *node.width() || node.count() != len {
                    return Err(format!("a leaf's sums {}/{} against its recount {width}/{len}", node.width(), node.count()));
                }
            }
            View::Nodes(children) => {
                if !(2..=MAX).contains(&len) || (!is_root && len < MIN) {
                    return Err(format!("an inner node of {len} children (root: {is_root})"));
                }
                let width: Nat = children.iter().map(|child| child.width()).sum();
                let count: usize = children.iter().map(|child| child.count()).sum();
                if width != *node.width() || count != node.count() {
                    return Err(format!("an inner node's sums {}/{} against its recount {width}/{count}", node.width(), node.count()));
                }
                for child in children {
                    if child.height() + 1 != node.height() {
                        return Err(format!("a child of height {} under a node of height {}", child.height(), node.height()));
                    }
                    held(child, false)?;
                }
            }
        }
        Ok(())
    }
    held(root, true)?;
    let mut walk = Walk::from_first(root, &mut |_| {});
    let mut before: Option<&Run> = None;
    let mut at = 0usize;
    while let Some(run) = walk.next(&mut |_| {}) {
        if before.is_some_and(|before| i_adjacent(before, &run.i_start)) {
            return Err(format!("runs {} and {at} are I-adjacent", at - 1));
        }
        before = Some(run);
        at += 1;
    }
    if at != root.count() {
        return Err(format!("the walk read {at} runs under a root counting {}", root.count()));
    }
    Ok(())
}

/// Collects the address of every node under `root`, itself among them.
pub(in crate::run_list) fn nodes_of(root: &Arc<Node>, into: &mut HashSet<*const Node>) {
    if !into.insert(Arc::as_ptr(root)) {
        return;
    }
    if let View::Nodes(children) = root.view() {
        for child in children {
            nodes_of(child, into);
        }
    }
}

/// Counts the nodes under `root` whose address `held` does not hold: the
/// leaves, then the inner nodes. Each is added to `held` as it is counted.
pub(in crate::run_list) fn made_anew(root: &Arc<Node>, held: &mut HashSet<*const Node>) -> (usize, usize) {
    if !held.insert(Arc::as_ptr(root)) {
        return (0, 0);
    }
    match root.view() {
        View::Runs(_) => (1, 0),
        View::Nodes(children) => children.iter().fold((0, 1), |(leaves, inner), child| {
            let (more_leaves, more_inner) = made_anew(child, held);
            (leaves + more_leaves, inner + more_inner)
        }),
    }
}

/// The fill of the tree at `root`: how many leaves hold each count of runs,
/// and how many inner nodes each count of children.
pub(in crate::run_list) fn fill(root: &Node) -> (BTreeMap<usize, usize>, BTreeMap<usize, usize>) {
    fn count(node: &Node, leaves: &mut BTreeMap<usize, usize>, inner: &mut BTreeMap<usize, usize>) {
        match node.view() {
            View::Runs(runs) => *leaves.entry(runs.len()).or_default() += 1,
            View::Nodes(children) => {
                *inner.entry(children.len()).or_default() += 1;
                for child in children {
                    count(child, leaves, inner);
                }
            }
        }
    }
    let (mut leaves, mut inner) = (BTreeMap::new(), BTreeMap::new());
    count(root, &mut leaves, &mut inner);
    (leaves, inner)
}

/// `count` runs of width 2, none I-adjacent to the next.
fn apart(count: u32) -> impl Iterator<Item = Run> {
    (0..count).map(|k| run(&a(&[1, 0, 1, 0, 1, 0, 1, 1 + 3 * k]), 2))
}

/// The tree a builder handed `runs` alone answers.
fn built(runs: impl IntoIterator<Item = Run>) -> Option<Arc<Node>> {
    let mut out = Builder::new();
    for run in runs {
        out.place(run, &mut |_| {});
    }
    out.finish(&mut |_| {})
}

#[test]
fn a_bulk_build_packs_every_node_full_and_balances_the_last_two() {
    // Runs alone, handed in order: leaves of sixteen from the left, the
    // last two sharing what is left so neither is short, and every level
    // above them packed the same way. Every count from none to past two
    // levels holds the invariants, and the shape is the one this arithmetic
    // gives.
    assert!(built(apart(0)).is_none(), "no run, no root");
    for count in (1..=600u32).chain([4_096, 4_097, 4_103, 4_104, 65_536]) {
        let root = built(apart(count)).expect("a list of a run or more has a root");
        check(&root).unwrap_or_else(|fault| panic!("{count} runs: {fault}"));
        assert_eq!(root.count(), count as usize);
        assert_eq!(*root.width(), n(2 * count));
        let (leaves, _) = fill(&root);
        let count = count as usize;
        let want: BTreeMap<usize, usize> = if count <= MAX {
            BTreeMap::from([(count, 1)])
        } else {
            let (full, over) = (count / MAX, count % MAX);
            let mut want = BTreeMap::new();
            if over == 0 {
                want.insert(MAX, full);
            } else if over >= MIN {
                want.insert(MAX, full);
                *want.entry(over).or_default() += 1;
            } else {
                // The last full leaf and the short tail, shared evenly.
                if full > 1 {
                    want.insert(MAX, full - 1);
                }
                *want.entry((MAX + over).div_ceil(2)).or_default() += 1;
                *want.entry((MAX + over) / 2).or_default() += 1;
            }
            want
        };
        assert_eq!(leaves, want, "{count} runs: the leaves' fill");
    }
    let (leaves, inner) = fill(&built(apart(65_536)).expect("a root"));
    assert_eq!((leaves, inner), (BTreeMap::from([(16, 4_096)]), BTreeMap::from([(16, 273)])), "65,536 runs: three full levels over full leaves");
}

#[test]
fn a_list_grown_by_appends_settles_at_leaves_of_nine() {
    // One run appended at a time: the last leaf fills to sixteen, and the
    // seventeenth run splits it nine and eight; the nine stand for good and
    // the eight fill again. So every leaf but the last few holds nine, and
    // the levels above them the same.
    let mut root: Option<Arc<Node>> = None;
    for (at, run) in apart(4_096).enumerate() {
        let mut out = Builder::new();
        if let Some(root) = &root {
            out.keep(root, &Nat::zero(), None, &mut |_| {});
        }
        out.place(run, &mut |_| {});
        root = out.finish(&mut |_| {});
        if at < 200 || at % 97 == 0 {
            check(root.as_ref().expect("a root")).unwrap_or_else(|fault| panic!("{} runs: {fault}", at + 1));
        }
    }
    let root = root.expect("a root");
    check(&root).expect("the grown tree holds");
    let (leaves, inner) = fill(&root);
    let nines = leaves.get(&9).copied().unwrap_or(0);
    let all: usize = leaves.values().sum();
    assert!(nines + 2 >= all, "all but the last leaves hold nine: {leaves:?}");
    assert!(inner.keys().all(|children| *children >= 2), "{inner:?}");
}

#[test]
fn a_short_root_is_never_shared_beneath_another_node() {
    // A root may hold fewer than eight entries, and may not stand so under
    // a node. Kept whole and followed by enough runs to stand beneath a new
    // root, a root of three runs — and one of three children — is opened,
    // its entries joining the levels.
    for short in [3u32, 7, 40, 100] {
        let old = built(apart(short)).expect("a root");
        let mut out = Builder::new();
        out.keep(&old, &Nat::zero(), None, &mut |_| {});
        for k in 0..5_000u32 {
            out.place(run(&a(&[1, 0, 1, 0, 64, 0, 1, 1 + 3 * k]), 2), &mut |_| {});
        }
        let root = out.finish(&mut |_| {}).expect("a root");
        check(&root).unwrap_or_else(|fault| panic!("a root of {short} runs kept: {fault}"));
        assert_eq!(root.count(), (short + 5_000) as usize);
    }
}

#[test]
fn keeping_a_tree_whole_shares_its_root() {
    // Nothing placed and the whole tree kept: the root itself, where it
    // holds eight entries or more, and an equal tree over the same
    // children where it holds fewer.
    for count in [1u32, 5, 8, 16, 17, 100, 300, 5_000] {
        let old = built(apart(count)).expect("a root");
        let mut out = Builder::new();
        out.keep(&old, &Nat::zero(), None, &mut |_| {});
        let kept = out.finish(&mut |_| {}).expect("a root");
        check(&kept).expect("the kept tree holds");
        if old.len() >= MIN {
            assert!(Arc::ptr_eq(&old, &kept), "{count} runs: the root is shared");
        } else {
            let mut held = HashSet::new();
            nodes_of(&old, &mut held);
            let (leaves, inner) = made_anew(&kept, &mut held);
            assert!(leaves + inner <= 1, "{count} runs: at most the root is made anew");
        }
    }
}

#[test]
fn a_run_that_joins_across_a_leafs_edge_is_merged_into_the_leaf() {
    // The last run of a kept tree stands in a leaf already shared whole. A
    // run placed after it that continues it widens it there: the leaf is
    // taken back and made anew, and no two runs stand I-adjacent across the
    // edge.
    for count in [16u32, 32, 300, 4_096] {
        let old = built(apart(count)).expect("a root");
        let last = old.last_run().expect("a last run").clone();
        let continues = Run { i_start: last.addr_at(&last.width), width: Nat::one() };
        let mut out = Builder::new();
        out.keep(&old, &Nat::zero(), None, &mut |_| {});
        out.place(continues, &mut |_| {});
        let root = out.finish(&mut |_| {}).expect("a root");
        check(&root).unwrap_or_else(|fault| panic!("{count} runs: {fault}"));
        assert_eq!(root.count(), count as usize, "the run joined the last and added none");
        assert_eq!(*root.width(), n(2 * count + 1));
        let mut held = HashSet::new();
        nodes_of(&old, &mut held);
        let (leaves, inner) = made_anew(&root, &mut held);
        assert!(leaves == 1 && inner <= old.height(), "{count} runs: one leaf and its path made anew, {leaves} + {inner}");
    }
}

#[test]
fn a_stretch_is_kept_by_its_two_paths_and_the_rest_is_shared() {
    // A stretch cut out of the middle of a tree: the runs its ends fall in
    // are clipped, the nodes whole inside it are shared, and the walk opens
    // the two paths and what stands beside them, however many runs the
    // stretch holds.
    let old = built(apart(65_536)).expect("a root");
    let mut steps = 0u64;
    let mut out = Builder::new();
    // Offsets 3 to 100,001: from inside the second run to inside a far one.
    out.keep(&old, &n(3), Some(&n(100_001)), &mut |by| steps += by);
    let root = out.finish(&mut |by| steps += by).expect("a root");
    check(&root).expect("the stretch's tree holds");
    assert_eq!(*root.width(), n(99_998));
    let mut held = HashSet::new();
    nodes_of(&old, &mut held);
    let (leaves, inner) = made_anew(&root, &mut held);
    assert!(leaves <= 4 && inner <= 4 * (old.height() + 1), "the two paths made anew: {leaves} leaves, {inner} inner");
    assert!(steps <= (4 * (old.height() as u64 + 1)) + 4 * MAX as u64, "the two paths opened: {steps} steps");
}
