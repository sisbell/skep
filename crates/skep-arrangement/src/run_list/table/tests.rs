//! The node table's claims over lists alone: each node written once, by
//! content; bytes that are a function of the lists; a decode that shares
//! what the table shares; and the door's refusals and repairs. The slice's
//! own suite holds the same over a whole `M5State`.

use std::cell::Cell;
use std::collections::HashSet;

use num_traits::One;
use skep_address::Address;

use super::super::tree::tests::{made_anew, nodes_of};
use super::super::Splice;
use super::*;
use crate::testutil::{a, n, run};

/// A content address of document `doc` at `ordinal`.
fn at_doc(doc: u32, ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, doc, 0, 1, ordinal])
}

/// Run `k` of the lists these cells build: width 2, apart from run `k + 1`.
fn each(k: u32) -> Run {
    run(&at_doc(10 + k % 4, 1 + 3 * k), 2)
}

/// A list of `runs` runs built at once.
fn bulk(runs: u32) -> RunList {
    RunList::from_runs((0..runs).map(each))
}

/// A list of `runs` runs grown a run at a time: leaves of nine.
fn grown(runs: u32) -> RunList {
    (0..runs).fold(RunList::default(), |list, k| list.append(each(k)))
}

/// `list` with run `k` replaced by a run of another document.
fn changed(list: &RunList, k: u32) -> RunList {
    list.spliced(&[Splice { at: n(2 * k + 1), width: n(2), runs: vec![run(&at_doc(30, 1 + 3 * k), 2)] }], &mut |_| {})
}

/// The table of `lists`, in order: its bytes, each list's root and how
/// many nodes it holds.
fn written(lists: &[&RunList]) -> (Vec<u8>, Vec<Root>, usize) {
    let mut table = Writer::new();
    let roots = lists.iter().map(|list| table.root(list)).collect();
    (bincode::serialize(&table).expect("the table encodes"), roots, table.nodes.len())
}

/// `bytes` read through the door.
fn read(bytes: &[u8]) -> bincode::Result<Decoded> {
    bincode::deserialize(bytes)
}

/// The door's refusal of `bytes`, in its words.
#[track_caller]
fn refusal(bytes: &[u8]) -> String {
    match read(bytes) {
        Ok(_) => panic!("the table decoded"),
        Err(refused) => refused.to_string(),
    }
}

/// How many distinct nodes, by address, the lists of `lists` hold.
fn nodes_among(lists: &[&RunList]) -> usize {
    let mut held = HashSet::new();
    for root in lists.iter().filter_map(|list| list.root.as_ref()) {
        nodes_of(root, &mut held);
    }
    held.len()
}

thread_local! {
    /// How many nodes a table keyed by [`counting_key`] has opened.
    static OPENED: Cell<u64> = const { Cell::new(0) };
}

/// The content key, counting each node it is asked of: once a node opened.
fn counting_key(node: &Written<'_>) -> u64 {
    OPENED.with(|opened| opened.set(opened.get() + 1));
    content_key(node)
}

/// One bucket for every node: every key collides.
fn one_bucket(_: &Written<'_>) -> u64 {
    0
}

#[test]
fn a_table_is_its_nodes_children_first_and_a_list_is_its_roots_id() {
    // Seventeen runs: two leaves and a root over them. The table writes
    // the first leaf, the second, then the root as their two ids — a leaf
    // the variant's index 0 and its runs, an inner node the index 1 and its
    // children's ids — and the list is the root's id. The empty list has no
    // node and no id, and a list written again is the id it was given.
    let list = bulk(17);
    let runs: Vec<Run> = (0..17).map(each).collect();
    let empty = RunList::default();
    let (bytes, roots, nodes) = written(&[&list, &empty, &list.clone()]);
    type RawNode<'r> = (u32, &'r [Run]);
    let twin = [
        bincode::serialize(&3u64).expect("encodes"),
        bincode::serialize::<RawNode<'_>>(&(0, &runs[..9])).expect("encodes"),
        bincode::serialize::<RawNode<'_>>(&(0, &runs[9..])).expect("encodes"),
        bincode::serialize(&(1u32, vec![0u64, 1])).expect("encodes"),
    ]
    .concat();
    assert_eq!(bytes, twin, "the table's bytes: a count, then each node");
    assert_eq!((roots.clone(), nodes), (vec![Root(Some(2)), Root(None), Root(Some(2))], 3));
    assert_eq!(bincode::serialize(&roots).expect("encodes"), bincode::serialize(&vec![Some(2u64), None, Some(2)]).expect("encodes"));
    // Read back: the three lists, the two that were one root one root.
    let mut table = read(&bytes).expect("the table decodes");
    let back: Vec<RunList> = roots.iter().map(|root| table.list(*root).expect("a root of the table")).collect();
    table.balanced().expect("every node but the root holds eight or more");
    assert_eq!(back, vec![list.clone(), empty, list]);
    assert!(back[0].shares_root_with(&back[2]));
    back[0].check().expect("the decoded tree holds");
}

#[test]
fn each_node_is_opened_once_and_written_once_whatever_roots_share_it() {
    // A list of 65,536 runs, ten versions each a change on from the last,
    // and a list sharing nothing with them: the table holds exactly the
    // nodes the twelve hold between them, the walk opens each of them once
    // — a subtree a root shares with an earlier one is met by its address
    // and not entered — and the bytes are those nodes' own: a leaf its runs,
    // an inner node its children's ids.
    let first = bulk(65_536);
    let mut lists = vec![first];
    for j in 0..10u32 {
        let next = changed(lists.last().expect("a list"), j * 6_000 + 11);
        lists.push(next);
    }
    lists.push(RunList::from_runs((0..300u32).map(|k| run(&at_doc(40, 1 + 3 * k), 2))));
    let all: Vec<&RunList> = lists.iter().collect();
    let distinct = nodes_among(&all);
    OPENED.with(|opened| opened.set(0));
    let mut table = Writer::keyed_by(counting_key);
    let roots: Vec<Root> = all.iter().map(|list| table.root(list)).collect();
    assert_eq!(table.nodes.len(), distinct, "the table holds each node the lists hold, once");
    assert_eq!(OPENED.with(Cell::get), distinct as u64, "the walk opens each node once");
    let bytes = bincode::serialize(&table).expect("the table encodes");
    // The bytes: the count, then for each node its tag, its length and its
    // entries — 104 bytes a run of these lists, 8 a child id.
    let run_bytes = bincode::serialize(&each(0)).expect("encodes").len();
    assert_eq!(run_bytes, 104);
    let mut held = HashSet::new();
    let (leaves, inner) = all.iter().filter_map(|list| list.root.as_ref()).fold((0, 0), |(leaves, inner), root| {
        let (more_leaves, more_inner) = made_anew(root, &mut held);
        (leaves + more_leaves, inner + more_inner)
    });
    let entries: usize = table.nodes.iter().map(|node| match node {
        Written::Leaf(runs) => runs.len() * run_bytes,
        Written::Inner(children) => children.len() * 8,
    }).sum();
    assert_eq!(bytes.len(), 8 + 12 * (leaves + inner) + entries, "the table's bytes are its distinct nodes'");
    // Eleven lists of 65,536 runs written whole are eleven times the
    // first; the table is the first and ten cut paths.
    let whole: usize = all.iter().map(|list| bincode::serialize(list).expect("the list encodes").len()).sum();
    let one = bincode::serialize(&lists[0]).expect("the list encodes").len();
    assert_eq!((one, whole), (8 + 65_536 * 104, 11 * (8 + 65_536 * 104) + 8 + 300 * 104));
    assert!(bytes.len() < one + one / 25, "the table: {} bytes against one list's {one} and the twelve's {whole}", bytes.len());
    // Read back: every list equal, and every node shared before shared
    // after — the decoded lists hold as many nodes between them as the
    // table has.
    let mut decoded = read(&bytes).expect("the table decodes");
    let back: Vec<RunList> = roots.iter().map(|root| decoded.list(*root).expect("a root of the table")).collect();
    decoded.balanced().expect("the table is balanced");
    drop(decoded);
    assert_eq!(back, lists);
    assert_eq!(nodes_among(&back.iter().collect::<Vec<_>>()), distinct, "the decoded lists share as the written ones did");
    for (list, written) in back.iter().zip(&lists) {
        assert_eq!(list.fill(), written.fill(), "a decoded list has the shape that was written");
    }
    eprintln!("table: 11 lists of 65,536 runs and one of 300: {} bytes in {distinct} nodes ({leaves} leaves, {inner} inner), against {whole} bytes written whole", bytes.len());
}

#[test]
fn nodes_of_equal_content_at_two_addresses_are_one_entry() {
    // One run sequence built twice is two trees of equal nodes at
    // different addresses; and a change made and then reversed leaves a
    // list whose path of nodes is new in memory and equal in content to
    // the one it replaced. Each is one set of entries, by content: the
    // table is no larger for the second, and the two lists are one root id.
    let (first, second) = (bulk(5_000), bulk(5_000));
    assert!(!first.shares_root_with(&second), "the premise: two trees");
    let (alone, _, nodes_alone) = written(&[&first]);
    let (both, roots, nodes_both) = written(&[&first, &second]);
    assert_eq!((nodes_both, roots[0]), (nodes_alone, roots[1]), "the second tree adds no entry and is the first's root");
    assert_eq!(both, alone, "the table is the same bytes for one tree as for two of its content");
    // The change and its reversal: run 2,000 replaced, then put back.
    let reverted = changed(&first, 2_000).spliced(&[Splice { at: n(4_001), width: n(2), runs: vec![each(2_000)] }], &mut |_| {});
    assert_eq!(reverted, first);
    assert_eq!(reverted.made_anew(&[&first]), (1, first.height()), "the premise: the path is new in memory");
    let (bytes, roots, nodes) = written(&[&first, &reverted]);
    assert_eq!((nodes, roots[0], bytes), (nodes_alone, roots[1], alone), "the reverted list is the first list's entries and its root");
    // Decoded, the two are one tree.
    let mut decoded = read(&both).expect("the table decodes");
    let (one, other) = (decoded.list(roots[0]).expect("a root"), decoded.list(roots[1]).expect("a root"));
    assert!(one.shares_root_with(&other), "nodes one in the table are one after the decode");
    // The same sequence in another shape is other nodes, and its own root.
    let other_shape = grown(5_000);
    let (_, roots, nodes) = written(&[&first, &other_shape]);
    assert_ne!(roots[0], roots[1]);
    assert_eq!(nodes, nodes_alone + nodes_among(&[&other_shape]), "a list of another shape shares no node with the first");
}

#[test]
fn nodes_whose_bucket_keys_collide_are_told_apart_by_their_contents() {
    // Every node under one bucket key: each is still compared in full with
    // the nodes before it, so different nodes are different entries, equal
    // ones are one, and the bytes are the bytes any key gives.
    let lists = [bulk(300), grown(300), changed(&bulk(300), 100), bulk(300)];
    let all: Vec<&RunList> = lists.iter().collect();
    let (bytes, roots, nodes) = written(&all);
    let mut colliding = Writer::keyed_by(one_bucket);
    let colliding_roots: Vec<Root> = all.iter().map(|list| colliding.root(list)).collect();
    assert_eq!((colliding.nodes.len(), &colliding_roots), (nodes, &roots), "one bucket: the same entries and the same ids");
    assert_eq!(bincode::serialize(&colliding).expect("the table encodes"), bytes, "one bucket: the same bytes");
    let mut decoded = read(&bytes).expect("the table decodes");
    for (root, list) in roots.iter().zip(&lists) {
        assert_eq!(&decoded.list(*root).expect("a root"), list, "each list decodes to its own runs");
    }
    assert_ne!(roots[0], roots[2], "two different lists are two roots");
    assert_eq!(roots[0], roots[3], "two equal lists of one shape are one");
}

#[test]
fn the_bytes_are_the_lists_whatever_memory_holds_them() {
    // The same lists written twice, by two tables with maps of their own,
    // are one byte string; so are the same lists built again from the same
    // operations, at other addresses and allocated in another order.
    let make = |reversed: bool| -> Vec<RunList> {
        let mut made: Vec<(usize, RunList)> = Vec::new();
        let order: Vec<usize> = if reversed { (0..4).rev().collect() } else { (0..4).collect() };
        for which in order {
            let list = match which {
                0 => bulk(3_000),
                1 => grown(700),
                2 => changed(&bulk(3_000), 1_234),
                _ => grown(700).remove_range(&n(100), &n(333)),
            };
            made.push((which, list));
        }
        made.sort_by_key(|(which, _)| *which);
        made.into_iter().map(|(_, list)| list).collect()
    };
    let (first, second) = (make(false), make(true));
    let (bytes, roots, _) = written(&first.iter().collect::<Vec<_>>());
    for _ in 0..3 {
        assert_eq!(written(&first.iter().collect::<Vec<_>>()).0, bytes, "one table written again");
    }
    let (again, again_roots, _) = written(&second.iter().collect::<Vec<_>>());
    assert_eq!((again, again_roots), (bytes.clone(), roots.clone()), "the same lists built again, in another order");
    // And the table read and written again is the table: a decoded list has
    // the shape that was written.
    let mut decoded = read(&bytes).expect("the table decodes");
    let back: Vec<RunList> = roots.iter().map(|root| decoded.list(*root).expect("a root")).collect();
    assert_eq!(written(&back.iter().collect::<Vec<_>>()).0, bytes, "a table decoded and written again");
}

/// A table of hand-made nodes, as the encoder writes one.
fn table_of(nodes: &[Written<'_>]) -> Vec<u8> {
    bincode::serialize(nodes).expect("the nodes encode")
}

#[test]
fn the_door_refuses_a_table_no_fold_wrote() {
    let runs: Vec<Run> = (0..40).map(each).collect();
    let leaf = |from: usize, to: usize| Written::Leaf(&runs[from..to]);
    // A child id equal to its node's own, one past it, and a cycle of two:
    // each names a node not yet read.
    for (what, nodes) in [
        ("a child that is its own node", vec![leaf(0, 8), Written::Inner(vec![0, 1])]),
        ("a child past its node", vec![leaf(0, 8), Written::Inner(vec![0, 2]), leaf(8, 16)]),
        ("two nodes each the other's child", vec![Written::Inner(vec![1, 1]), Written::Inner(vec![0, 0])]),
        ("a child id no machine word holds", vec![leaf(0, 8), Written::Inner(vec![0, u64::MAX])]),
    ] {
        assert_eq!(refusal(&table_of(&nodes)), Refused::ForwardId.to_string(), "{what}");
    }
    // A chain of one-child nodes as deep as the table: refused where it
    // passes the height a list a machine word counts can have, with every
    // node past that unread and none of them built.
    let mut chain = vec![leaf(0, 8)];
    chain.extend((0..100_000u64).map(|below| Written::Inner(vec![below])));
    assert_eq!(refusal(&table_of(&chain)), Refused::TooDeep.to_string(), "a chain of one-child nodes");
    let admitted = read(&table_of(&chain[..=MAX_HEIGHT])).expect("a chain of the bound's height is read");
    assert_eq!(admitted.nodes.len(), MAX_HEIGHT + 1);
    assert_eq!(admitted.balanced(), Err(Refused::ShortNode), "…and its one-child nodes are refused once the roots are known");
    // A node sixteen wide at every level holds more runs than a machine
    // word counts before it is as tall as the bound.
    let mut wide = vec![leaf(0, 16)];
    wide.extend((0..MAX_HEIGHT as u64).map(|below| Written::Inner(vec![below; 16])));
    assert_eq!(refusal(&table_of(&wide)), Refused::TooManyRuns.to_string(), "more runs than a machine word counts");
    // Children at two heights.
    let uneven = vec![leaf(0, 8), leaf(8, 16), Written::Inner(vec![0, 1]), Written::Inner(vec![2, 0])];
    assert_eq!(refusal(&table_of(&uneven)), Refused::UnevenChildren.to_string());
    // A node of no entry, and one of seventeen.
    assert_eq!(refusal(&table_of(&[leaf(0, 0)])), Refused::EmptyNode.to_string());
    assert_eq!(refusal(&table_of(&[leaf(0, 8), Written::Inner(vec![])])), Refused::EmptyNode.to_string());
    assert_eq!(refusal(&table_of(&[leaf(0, 17)])), Refused::OverfullNode.to_string(), "a leaf of seventeen runs");
    assert_eq!(refusal(&table_of(&[leaf(0, 8), Written::Inner(vec![0; 17])])), Refused::OverfullNode.to_string(), "a node of seventeen children");
    // A run its own door refuses: a width of zero, as the bytes spell it.
    let mut zero_width = table_of(&[leaf(0, 1)]);
    let width_at = zero_width.len() - 12;
    assert_eq!(zero_width[width_at..], bincode::serialize(&n(2)).expect("encodes")[..], "the premise: the run's width ends the body");
    zero_width.truncate(width_at);
    zero_width.extend(bincode::serialize(&n(0)).expect("encodes"));
    assert!(refusal(&zero_width).contains("width must be ≥ 1"), "a run of no width");
    // The roots, once the table is read: an id past it; an inner root of
    // one child; and a short node that is not a root alone.
    let two_leaves = table_of(&[leaf(0, 8), leaf(8, 16), Written::Inner(vec![0, 1]), Written::Inner(vec![0])]);
    let mut table = read(&two_leaves).expect("the table is read");
    for past in [4u64, 5, u64::MAX] {
        assert_eq!(table.list(Root(Some(past))).err(), Some(Refused::RootPastTheTable));
    }
    assert_eq!(table.list(Root(Some(3))).err(), Some(Refused::LoneChild));
    assert!(table.list(Root(Some(2))).is_ok(), "a root of two children");
    assert_eq!(table.balanced(), Err(Refused::ShortNode), "the one-child node is no root");
    // A leaf of seven under a root, and of seven as a root and a child at
    // once: short where any node holds it.
    let short_child = table_of(&[leaf(0, 7), leaf(8, 16), Written::Inner(vec![0, 1])]);
    let mut table = read(&short_child).expect("the table is read");
    table.list(Root(Some(2))).expect("the root");
    assert_eq!(table.balanced(), Err(Refused::ShortNode), "a leaf of seven runs under a root");
    table.list(Root(Some(0))).expect("the short leaf, as a root too");
    assert_eq!(table.balanced(), Err(Refused::ShortNode), "a root that is a child as well holds eight or more");
    // …and alone as a root it stands.
    let mut table = read(&table_of(&[leaf(0, 7)])).expect("the table is read");
    assert_eq!(table.list(Root(Some(0))).expect("the root").run_count(), 7);
    assert_eq!(table.balanced(), Ok(()));
    // A node no list and no node names is short like any other.
    let mut table = read(&table_of(&[leaf(0, 7), leaf(8, 16)])).expect("the table is read");
    table.list(Root(Some(1))).expect("the root");
    assert_eq!(table.balanced(), Err(Refused::ShortNode));
}

#[test]
fn a_count_the_body_does_not_carry_reserves_nothing() {
    // The table's own count, a leaf's and an inner node's, each declared
    // as 2^60 over a body that carries a few entries: the read runs out of
    // body, or meets the seventeenth entry, and refuses, having sized no
    // room by the count. Then `u64::MAX` over every eight bytes of a table
    // of three levels: decoded or refused, never reserved for.
    let list = grown(160);
    let (bytes, _, nodes) = written(&[&list]);
    assert!(list.height() == 2 && nodes > 18, "the premise: leaves, inner nodes and a root over them");
    let declared = |at: usize, count: u64| {
        let mut lying = bytes.clone();
        lying[at..at + 8].copy_from_slice(&count.to_le_bytes());
        std::panic::catch_unwind(|| read(&lying).map(|_| ())).unwrap_or_else(|_| panic!("a count of {count} at byte {at} panicked the read: room sized by a count the body does not carry"))
    };
    // The table's count leads the body; the first node's tag and its
    // runs' count follow it.
    assert_eq!(bytes[..8], (nodes as u64).to_le_bytes());
    assert_eq!(bytes[8..12], 0u32.to_le_bytes(), "the premise: the first node is a leaf");
    assert_eq!(bytes[12..20], 9u64.to_le_bytes(), "the premise: a grown leaf of nine runs");
    assert!(declared(0, 1 << 60).is_err(), "the table's count");
    assert!(declared(12, 1 << 60).is_err(), "a leaf's count");
    // The last node written is the root: its tag, its children's count,
    // then their two ids.
    let root = bytes.len() - (4 + 8 + 2 * 8);
    assert_eq!(bytes[root..root + 4], 1u32.to_le_bytes(), "the premise: the last node is an inner node");
    assert_eq!(bytes[root + 4..root + 12], 2u64.to_le_bytes(), "the premise: two nodes under the root");
    assert!(declared(root + 4, 1 << 60).is_err(), "an inner node's count");
    let mut refused = 0usize;
    for at in 0..=bytes.len() - 8 {
        refused += usize::from(declared(at, u64::MAX).is_err());
    }
    assert!(refused > bytes.len() / 2, "most of the body refuses a count of u64::MAX: {refused} of {}", bytes.len());
}

#[test]
fn an_unmerged_seam_is_mended_and_only_its_path_is_unshared() {
    // A table whose list holds two I-adjacent runs side by side — inside
    // one leaf, and across the edge of two leaves — denotes the right map
    // and breaks the maximal merge. The door reads it, and the list comes
    // back merged: the run sequence the two were split from, in a tree that
    // holds its invariants, sharing with a second list of the table every
    // node the seam's path does not hold.
    let whole = grown(1_000);
    let height = whole.height();
    // The list a change elsewhere leaves: it shares every node of `whole`
    // off its own path, and holds neither damaged leaf.
    for across in [false, true] {
        let mut table = Writer::new();
        let root = table.root(&whole);
        // The leaf holding run 500, by its first run, and the leaf after
        // it. Run 500 is cut in two I-adjacent halves: both in its leaf, or
        // the second moved to open the next leaf.
        let target = each(500);
        let at = table.nodes.iter().position(|node| matches!(node, Written::Leaf(runs) if runs.contains(&target))).expect("the run's leaf");
        let (Written::Leaf(first), Written::Leaf(next)) = (&table.nodes[at], &table.nodes[at + 1]) else {
            panic!("two leaves side by side");
        };
        let (first, next) = (first.to_vec(), next.to_vec());
        let halves = [Run { i_start: target.i_start.clone(), width: Nat::one() }, Run { i_start: target.addr_at(&Nat::one()), width: Nat::one() }];
        let (damaged, damaged_next): (Vec<Run>, Vec<Run>) = if across {
            // The leaf's last run cut, its second half the next leaf's first.
            let last = first.last().expect("a run").clone();
            let cut = [Run { i_start: last.i_start.clone(), width: Nat::one() }, Run { i_start: last.addr_at(&Nat::one()), width: Nat::one() }];
            let mut head = first[..first.len() - 1].to_vec();
            head.push(cut[0].clone());
            let mut tail = vec![cut[1].clone()];
            tail.extend(next.iter().cloned());
            (head, tail)
        } else {
            let seat = first.iter().position(|run| *run == target).expect("the run");
            let mut cut = first[..seat].to_vec();
            cut.extend(halves.iter().cloned());
            cut.extend(first[seat + 1..].iter().cloned());
            (cut, next.clone())
        };
        table.nodes[at] = Written::Leaf(&damaged);
        table.nodes[at + 1] = Written::Leaf(&damaged_next);
        let bytes = bincode::serialize(&table).expect("the table encodes");
        let mut decoded = read(&bytes).expect("an unmerged seam is read");
        let mended = decoded.list(root).expect("the root");
        decoded.balanced().expect("the table is balanced");
        assert_eq!(mended, whole, "across leaves: {across}: the list comes back merged");
        mended.check().expect("the mended tree holds");
        assert!(decoded.list(root).expect("the root").shares_root_with(&mended), "the root asked twice is one mended tree");
        // What the mending made anew: against the nodes the table itself
        // decoded, the seam's path — a leaf or two and the nodes above
        // them — and no more.
        let mut held = HashSet::new();
        for entry in &decoded.nodes {
            held.insert(Arc::as_ptr(&entry.node));
        }
        let (leaves, inner) = made_anew(mended.root.as_ref().expect("a root"), &mut held);
        assert!((1..=3).contains(&leaves) && inner <= 2 * height, "across leaves: {across}: the mending made {leaves} leaves and {inner} inner nodes anew");
    }
    // A list with nothing unmerged is the table's own nodes, none made.
    let (bytes, roots, nodes) = written(&[&whole]);
    let mut decoded = read(&bytes).expect("the table decodes");
    let back = decoded.list(roots[0]).expect("the root");
    assert_eq!(nodes_among(&[&back]), nodes);
}

#[test]
fn a_seam_under_a_node_named_many_times_is_mended_once() {
    // A table may name one child many times, and so hold lists of more runs
    // than it has entries for: a leaf, then a node of eight of that leaf,
    // then a node of eight of that node, and on. Where the leaf holds an
    // unmerged seam every node above it does, and the door mends each ONCE
    // — the leaf, then each node over it from its child's mended tree —
    // whatever number of times the list reaches it. A mend that walked the
    // list would build the leaf again for every time the root reaches it:
    // 4,096 times four levels up, and 8¹² times twelve.
    let whole = each(1);
    let halves = [Run { i_start: whole.i_start.clone(), width: Nat::one() }, Run { i_start: whole.addr_at(&Nat::one()), width: Nat::one() }];
    let mut leaf = vec![each(0)];
    leaf.extend(halves.iter().cloned());
    leaf.extend((2..7).map(each));
    assert_eq!(leaf.len(), MIN, "the premise: a leaf at the least a child holds");
    for levels in [4u32, 12] {
        let mut nodes = vec![Written::Leaf(&leaf)];
        for level in 0..u64::from(levels) {
            nodes.push(Written::Inner(vec![level; MIN]));
        }
        let mut decoded = read(&table_of(&nodes)).expect("the table is read");
        decoded.balanced().expect("every node holds eight entries");
        let mended = decoded.list(Root(Some(u64::from(levels)))).expect("the root");
        assert_eq!(decoded.mends, u64::from(levels) + 1, "{levels} levels: each node holding the seam is built again once");
        // The list is the leaf's seven merged runs, 8^levels times over.
        let leaves = 8usize.pow(levels);
        assert_eq!((mended.run_count(), mended.total_width()), (7 * leaves, Nat::from(14 * leaves)), "{levels} levels");
        assert_eq!(mended.point(&n(3)), Some(whole.i_start.clone()), "the mended run stands where its two halves stood");
        assert_eq!(mended.point(&mended.total_width()), Some(each(6).addr_at(&Nat::one())), "the last position of the last leaf");
        assert!(decoded.list(Root(Some(u64::from(levels)))).expect("the root").shares_root_with(&mended), "asked again, the one mended tree");
        // The mended tree shares as the table did: its nodes number with
        // the levels, never with the runs.
        assert!(nodes_among(&[&mended]) <= 4 * (levels as usize + 1), "{levels} levels: {} nodes", nodes_among(&[&mended]));
        if levels == 4 {
            mended.check().expect("the mended tree holds its invariants");
            assert!(mended.iter().eq((0..leaves).flat_map(|_| (0..7).map(each)).collect::<Vec<_>>().iter()), "the run sequence, merged");
        }
    }
}
