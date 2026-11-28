use std::cell::{Cell, RefCell};

use super::*;
use skep_address::{validate, Tumbler};

use crate::testutil::{a, ca, n, run, vca};

/// What one kept stretch and the seam before it may open of a tree of
/// `height`, in steps: `c` of [`RunList::spliced`]'s card.
fn cut_bound(height: usize) -> u64 {
    6 * (height as u64 + 1) + 81
}

/// What a descent to one ordinal may read of a tree of `height`: a node a
/// level, and a leaf's runs.
fn descent_bound(height: usize) -> u64 {
    height as u64 + 1 + 16
}

/// Returns `f`'s answer beside how many nodes its read walks entered: the
/// count of a read that takes no `steps`.
fn entered<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = tree::ENTERED.with(Cell::get);
    let answer = f();
    (answer, tree::ENTERED.with(Cell::get) - before)
}

/// A list through the coalesce every `RunList` passes, so a fixture holds the
/// maximally-merged decomposition the type promises of every list in the
/// process.
fn list(runs: Vec<Run>) -> RunList {
    RunList::from_runs(runs)
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
    let merged = l.splice_in(&n(4), [run(&ca(4), 2)]); // shift(ca(1),3) = ca(4): adjacent
    assert_eq!(merged.runs(), vec![run(&ca(1), 5)]);
    let apart = l.splice_in(&n(4), [run(&ca(9), 1)]); // not adjacent
    assert_eq!(apart.runs(), vec![run(&ca(1), 3), run(&ca(9), 1)]);
    assert_eq!(apart.total_width(), n(4));
}

#[test]
fn the_blocks_are_the_stored_runs_at_v_positions_that_tile_from_one() {
    // §1/ASN-0058: a mapping block is a stored run at the V-position the
    // list gives it, and the list gives positions by prefix sum — so the
    // first block opens at ordinal 1, each block reaches exactly where the
    // next opens (the V-adjacent conjunct of the merge condition, held by
    // construction), and the last reaches the boundary past the total.
    // `locate` is the same walk asked about one ordinal, so every ordinal
    // a block covers locates to that block's run at that offset.
    let frag = list(vec![run(&ca(1), 2), run(&vca(1), 1), run(&ca(5), 2)]);
    let blocks: Vec<Block<'_>> = frag.iter_blocks().collect();
    assert_eq!(blocks.len(), frag.run_count());
    assert_eq!(blocks[0].v_start, n(1), "the first block opens at ordinal 1");
    for pair in blocks.windows(2) {
        assert_eq!(pair[0].v_reach(), pair[1].v_start, "consecutive blocks are V-adjacent");
    }
    let last = blocks.last().expect("the fixture holds three runs");
    assert_eq!(last.v_reach(), frag.total_width() + n(1));
    for block in &blocks {
        let mut k = n(0);
        while k < block.run.width {
            assert_eq!(
                frag.locate(&(&block.v_start + &k)),
                Some((block.run, k.clone())),
                "{block:?} at offset {k}"
            );
            k = &k + &n(1);
        }
    }
    // The runs are the list's own, lent: what `iter` hands back, in order.
    assert!(blocks.iter().map(|b| b.run).eq(frag.iter()));
    assert_eq!(RunList::default().iter_blocks().count(), 0, "an empty list has no block");
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
    // multiplicity — counts it once: the union holds it in one piece.
    let twice = list(vec![run(&ca(1), 2), run(&vca(5), 1), run(&ca(1), 2)]);
    assert!(twice.covers(&run(&ca(1), 2)));
    assert!(!twice.covers(&run(&ca(1), 3)));
}

#[test]
fn a_run_is_covered_exactly_when_every_one_of_its_addresses_is_held() {
    // §8/PUB-6.24: `covers` is `holds` asked of a whole I-extent, and the
    // oracle is `holds` itself, address by address — a law over runs the
    // list did not choose. The residents leave gaps a probe can straddle at
    // its opening, in its interior and at its tail, hold one address twice,
    // hold one of another length, and are listed OUT of the order they open
    // in — so the union's sort, its joins of overlapping and duplicated runs,
    // its search landing in a gap, and its reach comparison are each visited.
    let l = list(vec![run(&ca(6), 2), run(&vca(1), 1), run(&ca(3), 1), run(&ca(2), 2)]);
    // held: ca2 ca3 ca6 ca7 (ca3 twice), vca1
    let mut carried = 0usize;
    let mut checked = 0usize;
    for start in (1..=8u32).map(ca).chain((1..=2u32).map(vca)) {
        for width in 1..=6u32 {
            let probe = run(&start, width);
            let held = probe.addrs().all(|address| l.holds(&address));
            assert_eq!(l.covers(&probe), held, "{start:?} × {width}");
            carried += usize::from(held);
            checked += 1;
        }
    }
    assert_eq!(checked, 60, "every start and width the residents can be probed with");
    assert_eq!(carried, 7, "the seven runs lying whole within what is held");
}

#[test]
fn a_run_of_another_endpoint_length_is_covered_by_no_resident_whatever_its_width() {
    // PUB-6.24: `covers` asks a run only of the union's piece of its own
    // content chain and never searches a resident of another endpoint
    // length, which is sound only because such a resident holds no address
    // of the run, whatever the two widths. The law is asked of the run's own
    // boundary search — starts and residents of lengths 8 and 9 under three
    // origins, each the shorter in turn. Then the one shape a longer address
    // inside a shorter I-extent must take is shown to be no run start. Then
    // `covers` answers a run of the wire's widest width — one a search of
    // that width would walk for tens of thousands of bigint steps per
    // resident — by one reach comparison. Corpus seed for the fuzzing tier,
    // against a fragmented list.
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
    // maximally-merged decomposition, and a list read back from its run
    // sequence — the form a slice is written in outside a checkpoint —
    // goes through a door that establishes the invariant as the mutators
    // do. Without that door a list so read could hold two I-adjacent
    // runs, and every read publishing canonicality would answer off it:
    // M6's COMPARE would see a different block structure for the same
    // document, and M7's slot endsets would count more spans against
    // `MAX_SLOT_SPANS`. Nothing faults, because the denotation is intact —
    // which is why the door repairs rather than refuses, and why only a
    // comparison of run STRUCTURE sees it. A checkpoint's node table has a
    // door of its own, held to the same rule in `table/tests.rs`.
    //
    // The bytes are made by encoding the shadow's own shape, a sequence of
    // runs.
    #[derive(Serialize)]
    struct Wire(Vec<Run>);
    let wire = |runs: Vec<Run>| bincode::serialize(&Wire(runs)).expect("the shadow encodes");
    // Two I-adjacent runs — `shift(ca(1), 2) = ca(3)` — which no fold
    // could have written apart, since every mutator here joins its seams.
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
    let spliced = l.splice_in(&n(3), [run(&ca(9), 1)]);
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
                &l.splice_in(&n(ord), [run(&placed, 1)]),
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
    let out = l.splice_in(&n(2), [run(&vca(1), 1)]); // vca is length 9, ca length 8
    assert_eq!(out.runs().len(), 2);
}

#[test]
fn two_origins_at_one_depth_never_coalesce_even_where_ordinals_line_up() {
    // §1/M16a: origins are kept apart by PREFIX, not by length. doc1's run
    // reaches ordinal 3 and doc2's element 3 opens at ordinal 3 — one
    // length, one level class, one ordinal — and they are still two
    // origins: widening doc1's run over it would place doc1's own ca(3),
    // which is not the address the second run names.
    let doc2_third = a(&[1, 0, 1, 0, 64, 0, 1, 3]);
    assert_eq!(doc2_third.tumbler().len(), ca(1).tumbler().len());
    let l = list(vec![run(&ca(1), 2)]);
    let out = l.splice_in(&n(3), [run(&doc2_third, 1)]);
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

/// A content address of the account's document `doc` at `ordinal`.
fn at_doc(doc: u32, ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, doc, 0, 1, ordinal])
}

/// One change, built as the fold's record holds one.
fn change(at: u32, width: u32, runs: Vec<Run>) -> Splice {
    Splice { at: n(at), width: n(width), runs }
}

/// What today's two mutators leave when each change is made by them in
/// turn from the last change down, the order in which no change moves the
/// positions of one still to make: the removal, then the placement.
fn made_one_at_a_time(l: &RunList, changes: &[Splice]) -> RunList {
    changes.iter().rev().fold(l.clone(), |l, c| {
        let removed = if c.width.is_zero() { l } else { l.remove_range(&c.at, &c.width) };
        if c.runs.is_empty() {
            removed
        } else {
            removed.splice_in(&c.at, c.runs.iter().cloned())
        }
    })
}

/// The splice of `changes`, held to the two mutators' answer, to the tree's
/// invariants and to its count: within the card's bound, which the list's
/// run count does not enter.
fn spliced_as_the_mutators(l: &RunList, changes: &[Splice], label: &str) -> RunList {
    let mut count = 0u64;
    let got = l.spliced(changes, &mut |steps| count += steps);
    assert_eq!(got, made_one_at_a_time(l, changes), "{label}: equal to the mutators' list");
    got.check().unwrap_or_else(|fault| panic!("{label}: {fault}"));
    let placed: usize = changes.iter().map(|c| c.runs.len()).sum();
    let bound = (changes.len() as u64 + 1) * cut_bound(l.height()) + placed as u64;
    assert!(count <= bound, "{label}: {count} steps past the card's {bound}");
    got
}

/// A small generator, so a generated case is the same case at every run.
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A number in `[0, below)`; 0 where `below` is 0.
    fn below(&mut self, below: u64) -> u64 {
        if below == 0 {
            0
        } else {
            self.next() % below
        }
    }
}

/// A list of `runs` runs over four documents' I-space, each of width 1 to
/// 4: a document's runs taken in address order, most of them cut off from
/// the one before by a gap or by another document's run, so a removal
/// between two of them brings I-adjacent neighbours together.
fn generated_list(gen: &mut Gen, runs: usize) -> RunList {
    let mut next = [1u32; 4];
    let mut out = Vec::with_capacity(runs);
    for _ in 0..runs {
        let doc = gen.below(4) as usize;
        let width = 1 + gen.below(4) as u32;
        // A gap in the document's I-space one time in three.
        next[doc] += if gen.below(3) == 0 { 1 + gen.below(3) as u32 } else { 0 };
        out.push(run(&at_doc(10 + doc as u32, next[doc]), width));
        next[doc] += width;
    }
    list(out)
}

/// `changes` changes to a list whose positions are `held`, ascending and
/// apart: sites at run boundaries and inside runs, removals alone,
/// placements alone and both, placed runs that continue the address before
/// the site or lead into the one after it, the first change at position 1
/// and the last at the end where `ends` asks.
fn generated_changes(gen: &mut Gen, held: &[Address], changes: usize, ends: bool) -> Vec<Splice> {
    let total = held.len() as u64;
    // An address continuing `a`, for a run I-adjacent to it.
    let after = |a: &Address, by: u32| -> Address {
        let comps: Vec<&Nat> = a.tumbler().iter().collect();
        let (last, lead) = comps.split_last().expect("an address has components");
        let mut next: Vec<Nat> = lead.iter().map(|c| (*c).clone()).collect();
        next.push(*last + n(by));
        validate(Tumbler::new(next).expect("nonempty")).expect("a content address shifted is one")
    };
    let mut out = Vec::with_capacity(changes);
    let mut reach = 1u64;
    for k in 0..changes {
        let left = (changes - k) as u64;
        // Room kept for the changes still to come, so every one has a site.
        let slack = (total + 1).saturating_sub(reach) / left;
        let at = if ends && k == 0 {
            1
        } else if ends && k + 1 == changes {
            total + 1
        } else {
            reach + gen.below(slack + 1)
        };
        let width = if at > total { 0 } else { gen.below(4).min(total + 1 - at) };
        let mut runs = Vec::new();
        let placed = if width == 0 { 1 + gen.below(2) } else { gen.below(3) };
        for j in 0..placed {
            let fresh = run(&at_doc(20 + gen.below(3) as u32, 1 + gen.below(1000) as u32), 1 + gen.below(3) as u32);
            let chosen = match gen.below(4) {
                // Continuing the address standing before the site.
                0 if j == 0 && at >= 2 => run(&after(&held[at as usize - 2], 1), 1 + gen.below(2) as u32),
                // Leading into the address standing after the removal.
                1 if j + 1 == placed && at + width <= total => {
                    let next = &held[(at + width) as usize - 1];
                    let last = next.tumbler().iter().next_back().expect("an address has components").clone();
                    if last > n(1) {
                        let comps: Vec<Nat> = next.tumbler().iter().cloned().collect();
                        let mut before = comps[..comps.len() - 1].to_vec();
                        before.push(last - n(1));
                        run(&validate(Tumbler::new(before).expect("nonempty")).expect("a content address"), 1)
                    } else {
                        fresh
                    }
                }
                _ => fresh,
            };
            runs.push(chosen);
        }
        out.push(change(at as u32, width as u32, runs));
        reach = at + width;
    }
    out
}

/// Every address `l` arranges, in V-order.
fn positions(l: &RunList) -> Vec<Address> {
    l.iter().flat_map(|run| run.addrs().collect::<Vec<_>>()).collect()
}

#[test]
fn the_splice_of_changes_joins_every_seam_they_make() {
    // A removal between two runs of one document brings them together.
    let l = list(vec![run(&ca(1), 3), run(&vca(1), 2), run(&ca(4), 3)]);
    let joined = spliced_as_the_mutators(&l, &[change(4, 2, vec![])], "a removal between two I-adjacent runs");
    assert_eq!(joined.runs(), vec![run(&ca(1), 6)]);
    // A run placed at a boundary joins the run before it, and the one after.
    let l = list(vec![run(&ca(1), 3), run(&vca(1), 1), run(&ca(9), 2)]);
    let widened = spliced_as_the_mutators(
        &l,
        &[change(4, 0, vec![run(&ca(4), 2)]), change(5, 0, vec![run(&ca(7), 2)])],
        "runs placed beside their neighbours",
    );
    assert_eq!(widened.runs(), vec![run(&ca(1), 5), run(&vca(1), 1), run(&ca(7), 4)]);
    // A site inside a run cuts it, and a placement of nothing leaves it one.
    let l = list(vec![run(&ca(1), 6)]);
    let cut = spliced_as_the_mutators(&l, &[change(3, 0, vec![run(&vca(1), 1)])], "a site inside a run");
    assert_eq!(cut.runs(), vec![run(&ca(1), 2), run(&vca(1), 1), run(&ca(3), 4)]);
    let removed = spliced_as_the_mutators(&l, &[change(2, 2, vec![]), change(5, 1, vec![])], "two removals inside one run");
    assert_eq!(removed.runs(), vec![run(&ca(1), 1), run(&ca(4), 1), run(&ca(6), 1)]);
    // The addresses a change removes, placed back by it: the list as it was.
    let same = spliced_as_the_mutators(&l, &[change(3, 2, vec![run(&ca(3), 2)])], "a stretch replaced by itself");
    assert_eq!(same, l);
    // Position 1 and the end; two placements at one ordinal, in order; two
    // changes that touch.
    let ends = spliced_as_the_mutators(
        &l,
        &[change(1, 0, vec![run(&vca(1), 1)]), change(7, 0, vec![run(&vca(9), 1)])],
        "position 1 and the append boundary",
    );
    assert_eq!(ends.runs(), vec![run(&vca(1), 1), run(&ca(1), 6), run(&vca(9), 1)]);
    let ordered = spliced_as_the_mutators(
        &l,
        &[change(4, 0, vec![run(&vca(1), 1)]), change(4, 0, vec![run(&vca(5), 1)])],
        "two placements at one ordinal",
    );
    assert_eq!(ordered.runs(), vec![run(&ca(1), 3), run(&vca(1), 1), run(&vca(5), 1), run(&ca(4), 3)]);
    let touching = spliced_as_the_mutators(
        &l,
        &[change(2, 2, vec![run(&vca(1), 1)]), change(4, 1, vec![run(&vca(5), 1)])],
        "two changes that touch",
    );
    assert_eq!(touching.runs(), vec![run(&ca(1), 1), run(&vca(1), 1), run(&vca(5), 1), run(&ca(5), 2)]);
    // The empty list takes placements at its one boundary, and no change at
    // all leaves a list as it stands.
    let filled = spliced_as_the_mutators(&RunList::default(), &[change(1, 0, vec![run(&ca(1), 2)])], "into the empty list");
    assert_eq!(filled.runs(), vec![run(&ca(1), 2)]);
    assert_eq!(spliced_as_the_mutators(&l, &[], "no change"), l);
}

#[test]
fn the_splice_of_changes_equals_the_two_mutators_on_generated_lists() {
    let mut gen = Gen(0x9e37_79b9_7f4a_7c15);
    for (runs, changes) in [(0, 1), (1, 1), (1, 3), (7, 1), (7, 5), (40, 16), (64, 64), (300, 16), (300, 256), (1_500, 256)] {
        for ends in [false, true] {
            let l = generated_list(&mut gen, runs);
            let set = generated_changes(&mut gen, &positions(&l), changes, ends);
            let label = format!("{runs} runs, {changes} changes, ends {ends}");
            let got = spliced_as_the_mutators(&l, &set, &label);
            // Maximally merged, by a count the list's own merge takes no
            // part in.
            assert_eq!(got.runs().len(), canonical_run_count(&positions(&got)), "{label}");
        }
    }
}

#[test]
fn the_splice_of_changes_equals_the_two_mutators_at_the_wires_most_changes() {
    // 4,096 changes, the most one frame names, into a list of 1,024 runs,
    // each made again by the two mutators in turn.
    let mut gen = Gen(0x2545_f491_4f6c_dd1d);
    let l = generated_list(&mut gen, 1_024);
    let set = generated_changes(&mut gen, &positions(&l), 4_096, true);
    assert_eq!(set.len(), 4_096);
    let got = spliced_as_the_mutators(&l, &set, "1,024 runs, 4,096 changes");
    assert_eq!(got.runs().len(), canonical_run_count(&positions(&got)));
}

#[test]
fn a_change_outside_the_folds_input_class_is_made_without_a_panic() {
    // The fold is total: a site the walk has passed is made where the walk
    // stands, a site past the list at its end, and a removal running past
    // the end removes what is there.
    let l = list(vec![run(&ca(1), 4), run(&vca(1), 2)]);
    let mut count = 0u64;
    let behind = l.spliced(
        &[change(3, 2, vec![]), change(2, 0, vec![run(&vca(7), 1)])],
        &mut |steps| count += steps,
    );
    assert_eq!(behind.runs(), vec![run(&ca(1), 2), run(&vca(7), 1), run(&vca(1), 2)]);
    let past = l.spliced(&[change(0, 0, vec![run(&vca(7), 1)]), change(99, 5, vec![run(&vca(9), 1)])], &mut |_| {});
    assert_eq!(past.runs(), vec![run(&vca(7), 1), run(&ca(1), 4), run(&vca(1), 2), run(&vca(9), 1)]);
    let over = l.spliced(&[change(5, 99, vec![])], &mut |_| {});
    assert_eq!(over.runs(), vec![run(&ca(1), 4)]);
}


/// The check's answer for `sites`, each an ordinal and the runs asked of
/// it, with the steps it charged.
fn held_at(l: &RunList, sites: &[(u32, Vec<Run>)]) -> (Vec<bool>, u64) {
    let ordinals: Vec<Nat> = sites.iter().map(|(at, _)| n(*at)).collect();
    let mut count = 0u64;
    let held = l.arranges_each(ordinals.iter().zip(sites).map(|(at, (_, asked))| (at, asked.iter())), &mut |steps| count += steps);
    (held, count)
}

#[test]
fn a_site_is_held_where_the_list_arranges_exactly_its_runs_whatever_the_run_boundaries() {
    // Positions 1–4 `ca(1..)`, 5–6 `vca(1..)`, 7–9 `ca(9..)`.
    let l = list(vec![run(&ca(1), 4), run(&vca(1), 2), run(&ca(9), 3)]);
    let one = |at: u32, asked: Vec<Run>| held_at(&l, &[(at, asked)]).0[0];
    assert!(one(2, vec![run(&ca(2), 2)]), "a piece of a run");
    assert!(one(1, vec![run(&ca(1), 1), run(&ca(2), 3)]), "two I-adjacent runs asked where the list holds one");
    assert!(one(4, vec![run(&ca(4), 1), run(&vca(1), 2), run(&ca(9), 1)]), "across three runs of the list");
    assert!(one(7, vec![run(&ca(9), 3)]), "the last run, to the end");
    assert!(!one(3, vec![run(&ca(4), 2)]), "the address stands one position on");
    assert!(!one(1, vec![run(&ca(2), 1), run(&ca(1), 1)]), "the addresses in another order");
    assert!(!one(4, vec![run(&ca(4), 2)]), "another address among them");
    assert!(!one(8, vec![run(&ca(10), 3)]), "reaching past the last position");
    assert!(!one(10, vec![run(&ca(12), 1)]), "opening past it");
    assert!(!one(0, vec![run(&ca(1), 1)]), "ordinal 0 lies before every run");
    assert!(!one(2, vec![]), "no run asked is no arrangement");
    assert!(!RunList::default().arranges_each([(&n(1), [&run(&ca(1), 1)])], &mut |_| {})[0], "the empty list holds nothing");
    // Every site of one walk is answered on its own: one not held between
    // two that are.
    let (held, _) = held_at(&l, &[(1, vec![run(&ca(1), 2)]), (3, vec![run(&vca(1), 2)]), (5, vec![run(&vca(1), 2)])]);
    assert_eq!(held, vec![true, false, true]);
    // A site the cursor has passed is not held, whatever stands there.
    let (held, _) = held_at(&l, &[(5, vec![run(&vca(1), 2)]), (1, vec![run(&ca(1), 2)])]);
    assert_eq!(held, vec![true, false]);
}

#[test]
fn the_check_descends_to_each_site_and_reads_no_run_it_does_not_compare() {
    // A list of one leaf: a site costs its own step, the one node, the
    // leaf's runs up to the one it opens in, and a step a run asked; a
    // site that opens where the comparison before it ended is reached by
    // one run read, with no descent.
    let l = list(vec![run(&ca(1), 4), run(&vca(1), 2), run(&ca(9), 3)]);
    // Two sites apart, the second in the last run: each its step, the node
    // and the runs up to its own, and its one run asked.
    let (held, count) = held_at(&l, &[(2, vec![run(&ca(2), 2)]), (7, vec![run(&ca(9), 1)])]);
    assert_eq!((held, count), (vec![true, true], (1 + 1 + 1 + 1) + (1 + 1 + 3 + 1)));
    // One site in the first run: that run read and no other.
    let (held, count) = held_at(&l, &[(1, vec![run(&ca(1), 1), run(&ca(2), 1)])]);
    assert_eq!((held, count), (vec![true], 1 + 1 + 1 + 2));
    // Two sites in one run: the run in hand answers the second.
    let (held, count) = held_at(&l, &[(1, vec![run(&ca(1), 1)]), (3, vec![run(&ca(3), 2)])]);
    assert_eq!((held, count), (vec![true, true], (1 + 1 + 1 + 1) + (1 + 1)));
    // A site opening where the one before it ended, in the next run: one
    // run read on, no descent.
    let (held, count) = held_at(&l, &[(1, vec![run(&ca(1), 4)]), (5, vec![run(&vca(1), 2)])]);
    assert_eq!((held, count), (vec![true, true], (1 + 1 + 1 + 1) + (1 + 1 + 1)));
    // The same two far sites over 65,536 runs cost what they cost over
    // three, but for the height: no run between them is read.
    let wide = list((0..65_536u32).map(|k| run(&at_doc(10, 1 + 3 * k), 2)).collect());
    let last = 2 * 65_535 + 1;
    let (held, count) = held_at(&wide, &[(1, vec![run(&at_doc(10, 1), 2)]), (last, vec![run(&at_doc(10, 1 + 3 * 65_535), 2)])]);
    assert_eq!(held, vec![true, true]);
    assert!(count <= 2 * (2 * (wide.height() as u64 + 1) + 20) + 3 * 2, "{count} steps over 65,536 runs");
}

#[test]
fn the_check_of_several_sites_answers_what_a_position_by_position_read_answers_on_generated_lists() {
    let mut gen = Gen(0x0123_4567_89ab_cdef);
    for (runs, sites) in [(1usize, 1usize), (7, 3), (40, 16), (300, 64), (1_500, 256)] {
        let l = generated_list(&mut gen, runs);
        let held = positions(&l);
        // Sites ascending and apart, each one to five positions wide; the
        // runs asked are the addresses standing there, cut at boundaries of
        // the generator's choosing, and one site in four asks its runs one
        // position on.
        let mut asked: Vec<(u32, Vec<Run>)> = Vec::new();
        let mut reach = 1usize;
        for k in 0..sites {
            let slack = (held.len() + 1).saturating_sub(reach) / (sites - k);
            let at = reach + gen.below(slack as u64 + 1) as usize;
            let width = 1 + gen.below(5) as usize;
            let from = if gen.below(4) == 0 { at + 1 } else { at };
            let mut site: Vec<Run> = Vec::new();
            for addr in held.iter().skip(from - 1).take(width) {
                if gen.below(2) == 0 {
                    extend_or_push_run(&mut site, run(addr, 1));
                } else {
                    site.push(run(addr, 1));
                }
            }
            asked.push((at as u32, site));
            reach = at + width;
        }
        // The answer read position by position, the list's own `point`.
        let want: Vec<bool> = asked
            .iter()
            .map(|(at, site)| {
                let addrs: Vec<Address> = site.iter().flat_map(|run| run.addrs().collect::<Vec<_>>()).collect();
                !addrs.is_empty() && addrs.iter().enumerate().all(|(k, addr)| l.point(&n(*at + k as u32)).as_ref() == Some(addr))
            })
            .collect();
        let (got, count) = held_at(&l, &asked);
        assert_eq!(got, want, "{runs} runs, {sites} sites");
        assert!(want.iter().any(|held| *held) && (sites < 8 || want.iter().any(|held| !*held)), "{runs} runs: the case holds both answers");
        let compared: usize = asked.iter().map(|(_, site)| site.len()).sum();
        let bound = sites as u64 * (2 * (l.height() as u64 + 1) + 20) + 3 * compared as u64;
        assert!(count <= bound, "{runs} runs, {sites} sites: {count} steps past the card's {bound}");
        // Each site alone, on a cursor of its own, answers the same.
        for ((at, site), want) in asked.iter().zip(&want) {
            assert_eq!(held_at(&l, &[(*at, site.clone())]).0, vec![*want], "{runs} runs: the site at {at} alone");
        }
    }
}

// ---- The tree held to the vector-backed list, operation by operation ----

/// An address `by` past `a` in its own chain: `a`'s last component moved.
/// `None` where that would leave no ordinal.
fn shifted(a: &Address, by: i64) -> Option<Address> {
    let comps: Vec<Nat> = a.tumbler().iter().cloned().collect();
    let (last, lead) = comps.split_last().expect("an address has components");
    let moved = if by >= 0 {
        last + Nat::from(by as u64)
    } else {
        let back = Nat::from(by.unsigned_abs());
        if *last <= back {
            return None;
        }
        last - back
    };
    let mut next = lead.to_vec();
    next.push(moved);
    Some(validate(Tumbler::new(next).expect("nonempty")).expect("a content address shifted is one"))
}

/// A run of `width` positions from `start`, any width.
fn wide_run(start: &Address, width: Nat) -> Run {
    Run::new(start.clone(), width).expect("a content run")
}

/// The kinds of list the tree is held to the oracle over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// Runs of one document's I-space, most of them continuing the one
    /// before, so nearly every seam a change makes can merge.
    OneOrigin,
    /// Runs of six documents' I-space, of two address lengths.
    ManyOrigins,
    /// A few runs placed over and over: the same identities repeated.
    Repeated,
    /// Many origins, and runs wider than a machine word among them.
    PastAWord,
}

/// The tree-backed list and the vector-backed one, made by the same
/// operations.
#[derive(Clone)]
struct Twin {
    tree: RunList,
    oracle: oracle::RunList,
}

/// One block of the oracle's list: its first ordinal and its run.
type Seat = (Nat, Run);

/// The vector-backed list of `l`'s runs, placed at once.
fn vector_backed(l: &RunList) -> oracle::RunList {
    oracle::RunList::default().splice_in(&Nat::one(), l.iter().cloned())
}

impl Twin {
    fn empty() -> Twin {
        Twin { tree: RunList::default(), oracle: oracle::RunList::default() }
    }

    /// `tree` beside the vector-backed list of its runs.
    fn of(tree: RunList) -> Twin {
        let oracle = vector_backed(&tree);
        Twin { tree, oracle }
    }

    /// The oracle's blocks, collected: where each run stands.
    fn seats(&self) -> Vec<Seat> {
        self.oracle.iter_blocks().map(|block| (block.v_start.clone(), block.run.clone())).collect()
    }

    fn end(&self) -> Nat {
        self.oracle.total_width()
    }

    fn splice_in(&mut self, ord: &Nat, runs: Vec<Run>) {
        self.tree = self.tree.splice_in(ord, runs.clone());
        self.oracle = self.oracle.splice_in(ord, runs);
    }

    fn append(&mut self, run: Run) {
        self.tree = self.tree.append(run.clone());
        self.oracle = self.oracle.append(run);
    }

    fn remove_range(&mut self, from: &Nat, width: &Nat) {
        self.tree = self.tree.remove_range(from, width);
        self.oracle = self.oracle.remove_range(from, width);
    }

    fn reorder(&mut self, cuts: &[Nat]) {
        self.tree = self.tree.reorder(cuts);
        self.oracle = self.oracle.reorder(cuts);
    }

    fn spliced(&mut self, changes: &[Splice]) {
        self.tree = self.tree.spliced(changes, &mut |_| {});
        self.oracle = self.oracle.spliced(changes, &mut |_| {});
    }

    /// Holds the tree to the oracle: the run sequence, the counts, the
    /// tree's own invariants, and every read at the ordinals `probes`
    /// names and at the list's boundaries.
    fn assert_same(&self, gen: &mut Gen, label: &str) {
        assert!(self.tree.iter().eq(self.oracle.iter()), "{label}: the run sequences differ");
        self.tree.check().unwrap_or_else(|fault| panic!("{label}: {fault}"));
        assert_eq!(self.tree.run_count(), self.oracle.run_count(), "{label}: run count");
        assert_eq!(self.tree.total_width(), self.oracle.total_width(), "{label}: total width");
        assert_eq!(self.tree.is_empty(), self.oracle.is_empty(), "{label}: emptiness");
        assert_eq!(self.tree.iter().len(), self.oracle.iter().len(), "{label}: the walk's length");
        let seats = self.seats();
        let end = self.end();
        // The boundary ordinals, and the first, a middle and the last
        // position of sampled runs — of every run where the list is short.
        let mut ordinals = vec![Nat::zero(), Nat::one(), end.clone(), &end + Nat::one(), &end + n(7)];
        // The vector-backed list answers each read by a walk from its first
        // run, so the longer the list the fewer runs are sampled.
        let sampled: Vec<usize> = if seats.len() <= 48 {
            (0..seats.len()).collect()
        } else {
            let some = if seats.len() <= 600 { 12 } else if seats.len() <= 5_000 { 6 } else { 2 };
            (0..some).map(|_| gen.below(seats.len() as u64) as usize).chain([0, seats.len() - 1]).collect()
        };
        for &at in &sampled {
            let (v_start, run) = &seats[at];
            ordinals.push(v_start.clone());
            ordinals.push(v_start + &run.width - Nat::one());
            ordinals.push(v_start + (&run.width / n(2)));
        }
        for ord in &ordinals {
            assert_eq!(self.tree.locate(ord), self.oracle.locate(ord), "{label}: locate {ord}");
            assert_eq!(self.tree.point(ord), self.oracle.point(ord), "{label}: point {ord}");
        }
        // Range reads opening at those ordinals: one position, a few, to
        // the end and past it, and none; pulled whole and stopped early.
        for (k, ord) in ordinals.iter().enumerate() {
            let counts = [Nat::zero(), Nat::one(), n(1 + gen.below(9) as u32), &end + n(3)];
            let count = &counts[k % counts.len()];
            let want: Vec<Run> = self.oracle.iter_resolve_range(ord, count).collect();
            let got: Vec<Run> = self.tree.iter_resolve_range(ord, count).collect();
            assert_eq!(got, want, "{label}: the range ({ord}, {count})");
            let take = gen.below(want.len() as u64 + 1) as usize;
            assert_eq!(self.tree.iter_resolve_range(ord, count).take(take).collect::<Vec<_>>(), want[..take], "{label}: the range ({ord}, {count}) stopped at {take}");
        }
        for ord in ordinals.iter().take(8) {
            let want: Vec<Run> = self.oracle.iter_resolve_from(ord).take(40).collect();
            assert_eq!(self.tree.iter_resolve_from(ord).take(40).collect::<Vec<_>>(), want, "{label}: the suffix from {ord}");
        }
        // Membership: addresses the list holds, and ones beside them.
        for &at in sampled.iter().take(12) {
            let run = &seats[at].1;
            for probe in [Some(run.i_start().clone()), shifted(run.i_start(), -1), Some(run.addr_at(&run.width))].into_iter().flatten() {
                assert_eq!(self.tree.holds(&probe), self.oracle.holds(&probe), "{label}: holds {probe:?}");
            }
        }
        // The whole-list reads, where the list is short enough to take
        // them at every step: the blocks, the image, and the walk backward.
        if seats.len() <= 600 {
            assert!(self.tree.iter_blocks().map(|b| (b.v_start, b.run)).eq(self.oracle.iter_blocks().map(|b| (b.v_start, b.run))), "{label}: the blocks");
            assert_eq!(self.tree.image(), self.oracle.image(), "{label}: the image");
            assert!(self.tree.iter().rev().eq(self.oracle.iter().rev()), "{label}: the walk backward");
        }
        self.assert_same_sites(gen, &seats, label);
    }

    /// Holds the check of several sites to the oracle's, site for site:
    /// sites held, not held, straddling runs, reaching past the end, and
    /// out of order.
    fn assert_same_sites(&self, gen: &mut Gen, seats: &[Seat], label: &str) {
        if seats.is_empty() {
            let asked = [run(&ca(1), 1)];
            let sites = [(n(1), &asked[..])];
            let ask = || sites.iter().map(|(at, runs)| (at, runs.iter()));
            assert_eq!(self.tree.arranges_each(ask(), &mut |_| {}), self.oracle.arranges_each(ask(), &mut |_| {}), "{label}: a site of the empty list");
            return;
        }
        let mut sites: Vec<(Nat, Vec<Run>)> = Vec::new();
        let mut at = gen.below(seats.len() as u64) as usize;
        for _ in 0..6 {
            if at >= seats.len() {
                break;
            }
            let (v_start, first) = &seats[at];
            // The runs standing from this seat on, as the list holds them,
            // one to three of them; the site opens at the first's start or
            // inside it.
            let take = 1 + gen.below(3) as usize;
            let mut asked: Vec<Run> = seats[at..].iter().take(take).map(|(_, run)| run.clone()).collect();
            let inside = if first.width > Nat::one() && gen.below(3) == 0 { &first.width / n(2) } else { Nat::zero() };
            if !inside.is_zero() {
                asked[0] = wide_run(&first.addr_at(&inside), &first.width - &inside);
            }
            match gen.below(6) {
                // Not held: the first run asked one address on.
                0 => {
                    if let Some(moved) = shifted(asked[0].i_start(), 1) {
                        asked[0] = wide_run(&moved, asked[0].width().clone());
                    }
                }
                // Not held: one position more than the list has there.
                1 => {
                    let last = asked.last().expect("a run asked").clone();
                    *asked.last_mut().expect("a run asked") = wide_run(last.i_start(), last.width() + Nat::one());
                }
                // Held, the first run asked in two pieces.
                2 if asked[0].width() > &Nat::one() => {
                    let whole = asked.remove(0);
                    let half = whole.width() / n(2);
                    asked.insert(0, wide_run(&whole.addr_at(&half), whole.width() - &half));
                    asked.insert(0, wide_run(whole.i_start(), half));
                }
                // No run asked.
                3 if gen.below(4) == 0 => asked.clear(),
                _ => {}
            }
            sites.push((v_start + inside, asked));
            at += take + gen.below(4) as usize;
        }
        // Out of order one time in four, and a site past the end, and one
        // at ordinal 0.
        if gen.below(4) == 0 && sites.len() > 1 {
            sites.swap(0, 1);
        }
        sites.push((self.end() + n(1 + gen.below(3) as u32), vec![seats[0].1.clone()]));
        if gen.below(3) == 0 {
            sites.insert(0, (Nat::zero(), vec![seats[0].1.clone()]));
        }
        if gen.below(3) == 0 {
            // After a seek past the end: a site inside the last run.
            let (v_start, last) = seats.last().expect("a seat");
            sites.push((v_start.clone(), vec![last.clone()]));
        }
        let ask = || sites.iter().map(|(at, runs)| (at, runs.iter()));
        let want = self.oracle.arranges_each(ask(), &mut |_| {});
        assert_eq!(self.tree.arranges_each(ask(), &mut |_| {}), want, "{label}: the sites {:?}", sites.iter().map(|(at, _)| at).collect::<Vec<_>>());
    }
}

/// A source of runs of one [`Shape`], and of ordinals worth cutting at.
struct Source {
    shape: Shape,
    /// The next ordinal each origin's fresh runs are taken from.
    next: [u32; 6],
}

impl Source {
    fn new(shape: Shape) -> Source {
        Source { shape, next: [1; 6] }
    }

    /// The origin documents' element addresses: five of one length, one of
    /// another.
    fn origin(&self, which: usize, ordinal: u32) -> Address {
        if which == 5 {
            a(&[1, 0, 1, 0, 64, 1, 0, 1, ordinal])
        } else {
            at_doc(10 + which as u32, ordinal)
        }
    }

    /// A fresh run of the shape.
    fn fresh(&mut self, gen: &mut Gen) -> Run {
        match self.shape {
            Shape::OneOrigin => {
                // Continuing where the origin's last run ended four times
                // in five: I-adjacent to it wherever the two meet.
                self.next[0] += if gen.below(5) == 0 { 1 + gen.below(3) as u32 } else { 0 };
                let width = 1 + gen.below(4) as u32;
                let run = run(&self.origin(0, self.next[0]), width);
                self.next[0] += width;
                run
            }
            Shape::ManyOrigins | Shape::PastAWord => {
                let which = gen.below(6) as usize;
                self.next[which] += if gen.below(3) == 0 { 1 + gen.below(3) as u32 } else { 0 };
                let start = self.origin(which, self.next[which]);
                if self.shape == Shape::PastAWord && gen.below(9) == 0 {
                    // A run wider than a machine word; its origin's later
                    // runs are taken well past where a word could reach.
                    let width = (Nat::one() << 70usize) + n(gen.below(5) as u32);
                    self.next[which] += 1_000;
                    return wide_run(&start, width);
                }
                let width = 1 + gen.below(4) as u32;
                self.next[which] += width;
                run(&start, width)
            }
            Shape::Repeated => {
                // One of three runs, over and over.
                let which = gen.below(3) as u32;
                run(&self.origin(which as usize, 1 + 10 * which), 1 + which)
            }
        }
    }

    /// One to three runs to place at the boundary before seat `at` of
    /// `seats`: fresh ones, a run continuing the one before the boundary,
    /// or a run leading into the one after it.
    fn placed(&mut self, gen: &mut Gen, seats: &[Seat], at: usize) -> Vec<Run> {
        let mut runs = Vec::new();
        for k in 0..1 + gen.below(3) {
            let choice = gen.below(5);
            let before = at.checked_sub(1).and_then(|before| seats.get(before)).map(|(_, run)| run);
            let after = seats.get(at).map(|(_, run)| run);
            let chosen = match (choice, before, after) {
                (0, Some(before), _) if k == 0 => wide_run(&before.addr_at(before.width()), n(1 + gen.below(2) as u32)),
                (1, _, Some(after)) => match shifted(after.i_start(), -1) {
                    Some(lead) => run(&lead, 1),
                    None => self.fresh(gen),
                },
                _ => self.fresh(gen),
            };
            runs.push(chosen);
        }
        runs
    }
}

/// An ordinal worth cutting `twin` at: a boundary between runs, a position
/// inside a run, 0, 1, the end, the append boundary, or past it.
fn cut_at(gen: &mut Gen, twin: &Twin, seats: &[Seat]) -> Nat {
    let end = twin.end();
    match gen.below(12) {
        0 => Nat::zero(),
        1 => Nat::one(),
        2 => end,
        3 => end + Nat::one(),
        4 => end + n(2 + gen.below(5) as u32),
        _ if seats.is_empty() => Nat::one(),
        choice => {
            let (v_start, run) = &seats[gen.below(seats.len() as u64) as usize];
            if choice < 8 || run.width() == &Nat::one() {
                v_start.clone()
            } else {
                // Inside the run: any offset but the first, a wide run's
                // far ones among them.
                let span = run.width() - Nat::one();
                let offset = if span > n(1_000) { &span / n(1 + gen.below(7) as u32) } else { n(gen.below(1_000) as u32) % &span };
                v_start + Nat::one() + offset
            }
        }
    }
}

/// `count` changes to `twin`'s list, ascending and apart, by `pattern`:
/// spread over the whole list, clustered in one neighbourhood, or touching
/// — each change removing up to the next one's site — with two placements
/// at one ordinal among them and the last at the append boundary where
/// `to_the_end` asks.
fn changes_for(gen: &mut Gen, source: &mut Source, twin: &Twin, seats: &[Seat], count: usize, pattern: u64, to_the_end: bool) -> Vec<Splice> {
    if seats.is_empty() {
        return vec![Splice { at: Nat::one(), width: Nat::zero(), runs: vec![source.fresh(gen)] }];
    }
    // The seats the changes fall at, ascending.
    let mut at: Vec<usize> = match pattern {
        0 => (0..count).map(|k| (k * seats.len() / count).min(seats.len() - 1)).collect(),
        1 => {
            let from = gen.below(seats.len() as u64) as usize;
            (0..count).map(|k| (from + k / 2).min(seats.len() - 1)).collect()
        }
        _ => (0..count).map(|_| gen.below(seats.len() as u64) as usize).collect(),
    };
    at.sort_unstable();
    let mut changes: Vec<Splice> = Vec::with_capacity(count);
    let mut reach = Nat::one();
    for (k, &seat) in at.iter().enumerate() {
        let (v_start, run) = &seats[seat];
        // At the run's start, or inside it; never before the change before
        // it ended.
        let inside = if run.width() > &Nat::one() && gen.below(3) == 0 { run.width() / n(2) } else { Nat::zero() };
        let site = std::cmp::max(v_start + inside, reach.clone());
        // Up to the next change's seat: nothing, a few positions, or all
        // of it where the changes touch.
        let room = match at.get(k + 1) {
            Some(&next) => {
                let next_start = &seats[next].0;
                if *next_start > site {
                    next_start - &site
                } else {
                    Nat::zero()
                }
            }
            None => twin.end() + Nat::one() - &site,
        };
        let width = match (pattern, gen.below(4)) {
            (2, _) => room.clone(),
            (_, 0) => Nat::zero(),
            (_, 1) => room.clone(),
            _ => std::cmp::min(room.clone(), n(1 + gen.below(5) as u32)),
        };
        let runs = if width.is_zero() || gen.below(3) != 0 { source.placed(gen, seats, seat) } else { Vec::new() };
        reach = &site + &width;
        changes.push(Splice { at: site, width, runs });
    }
    if to_the_end {
        changes.push(Splice { at: twin.end() + Nat::one(), width: Nat::zero(), runs: vec![source.fresh(gen)] });
    }
    changes
}

/// One operation of the generated stream, made to both lists of `twin`.
fn one_operation(gen: &mut Gen, source: &mut Source, twin: &mut Twin) -> String {
    let seats = twin.seats();
    match gen.below(16) {
        0..=3 => {
            let ord = cut_at(gen, twin, &seats);
            let seat = seats.iter().position(|(v_start, _)| *v_start >= ord).unwrap_or(seats.len());
            let runs = source.placed(gen, &seats, seat);
            twin.splice_in(&ord, runs);
            format!("splice_in at {ord}")
        }
        4..=5 => {
            let run = match seats.last() {
                Some((_, last)) if gen.below(2) == 0 => wide_run(&last.addr_at(last.width()), n(1 + gen.below(2) as u32)),
                _ => source.fresh(gen),
            };
            twin.append(run);
            "append".to_string()
        }
        6..=8 => {
            let from = cut_at(gen, twin, &seats);
            // Nothing, a few positions, a few runs' worth, or past the end.
            let width = match gen.below(5) {
                0 => Nat::zero(),
                1 => twin.end() + n(9),
                2 => n(1 + gen.below(40) as u32),
                _ => n(1 + gen.below(4) as u32),
            };
            twin.remove_range(&from, &width);
            format!("remove_range from {from}, {width} wide")
        }
        9..=10 => {
            // Three or four cuts ascending, as the op stages them — or,
            // one time in four, any vector: short, long, out of order.
            let honest = gen.below(4) != 0;
            let count = if honest { 3 + gen.below(2) as usize } else { gen.below(7) as usize };
            let mut cuts: Vec<Nat> = (0..count).map(|_| cut_at(gen, twin, &seats)).collect();
            if honest {
                cuts.sort();
            }
            twin.reorder(&cuts);
            format!("reorder at {cuts:?}")
        }
        11..=14 => {
            let count = [1usize, 1, 2, 3, 16][gen.below(5) as usize];
            let (pattern, to_the_end) = (gen.below(3), gen.below(4) == 0);
            let mut changes = changes_for(gen, source, twin, &seats, count, pattern, to_the_end);
            // One time in six, outside the fold's input class: the changes
            // out of order, a site at 0, a removal past the end.
            if gen.below(6) == 0 {
                changes.reverse();
                changes.push(Splice { at: Nat::zero(), width: twin.end() + n(5), runs: vec![source.fresh(gen)] });
            }
            twin.spliced(&changes);
            format!("spliced, {} changes", changes.len())
        }
        _ => {
            // Two placements at one ordinal, the earlier's runs first.
            let ord = cut_at(gen, twin, &seats);
            let changes = vec![
                Splice { at: ord.clone(), width: Nat::zero(), runs: vec![source.fresh(gen)] },
                Splice { at: ord.clone(), width: Nat::zero(), runs: vec![source.fresh(gen), source.fresh(gen)] },
            ];
            twin.spliced(&changes);
            format!("two placements at {ord}")
        }
    }
}

/// Holds the tree to the list it replaced over one shape of list: five
/// generated streams of every mutator, inside its precondition and outside
/// it, each made to both lists; after each operation the run sequences,
/// every read and the check of several sites answer alike and the tree
/// holds its invariants. Lists are kept and edited apart, so a list an
/// operation was made from is held equal again after it.
fn every_operation_leaves_what_the_vector_backed_list_holds(shape: Shape) {
    for (seed, start, operations) in [(1u64, 0usize, 220usize), (2, 6, 220), (3, 40, 160), (4, 300, 90), (5, 2_000, 24)] {
        let mut gen = Gen(0x9e37_79b9_7f4a_7c15 ^ (seed << 32) ^ ((shape as u64 + 1) << 8));
        let mut source = Source::new(shape);
        let mut twin = Twin::empty();
        // The start: runs placed at once, a bulk build.
        let runs: Vec<Run> = (0..start).map(|_| source.fresh(&mut gen)).collect();
        twin.splice_in(&Nat::one(), runs);
        let label = format!("{shape:?}, from {start} runs");
        twin.assert_same(&mut gen, &label);
        // Lists kept as they stood, each edited on from time to time.
        let mut kept: Vec<Twin> = vec![twin.clone()];
        for step in 0..operations {
            if gen.below(9) == 0 {
                let which = gen.below(kept.len() as u64) as usize;
                twin = kept[which].clone();
            }
            let made = one_operation(&mut gen, &mut source, &mut twin);
            twin.assert_same(&mut gen, &format!("{label}, operation {step}: {made}"));
            if gen.below(7) == 0 && kept.len() < 12 {
                kept.push(twin.clone());
            }
        }
        // Every list kept stands as it stood: nothing a later operation
        // did reached it.
        for (at, twin) in kept.iter().enumerate() {
            twin.assert_same(&mut gen, &format!("{label}, the list kept {at}th"));
        }
    }
}

#[test]
fn runs_of_one_origin_are_left_as_the_vector_backed_list_leaves_them() {
    every_operation_leaves_what_the_vector_backed_list_holds(Shape::OneOrigin);
}

#[test]
fn runs_of_many_origins_are_left_as_the_vector_backed_list_leaves_them() {
    every_operation_leaves_what_the_vector_backed_list_holds(Shape::ManyOrigins);
}

#[test]
fn repeated_identities_are_left_as_the_vector_backed_list_leaves_them() {
    every_operation_leaves_what_the_vector_backed_list_holds(Shape::Repeated);
}

#[test]
fn runs_wider_than_a_machine_word_are_left_as_the_vector_backed_list_leaves_them() {
    every_operation_leaves_what_the_vector_backed_list_holds(Shape::PastAWord);
}

#[test]
fn a_splice_of_many_changes_equals_the_vector_backed_ones_at_every_pattern() {
    // The splice of one record's changes, at the counts a frame carries:
    // 1, 16, 256 and 4,096 changes into lists of 4,096 runs of each shape,
    // built at once and grown a run at a time, and into one of 65,536 —
    // spread over the list, clustered in one neighbourhood and touching,
    // the spread ones with a placement at the append boundary.
    let mut cases = 0usize;
    for (shape, runs, grown) in [
        (Shape::ManyOrigins, 4_096usize, false),
        (Shape::ManyOrigins, 4_096, true),
        (Shape::OneOrigin, 4_096, false),
        (Shape::OneOrigin, 4_096, true),
        (Shape::PastAWord, 4_096, false),
        (Shape::Repeated, 4_096, true),
        (Shape::ManyOrigins, 65_536, false),
    ] {
        let mut gen = Gen(0x2545_f491_4f6c_dd1d ^ (runs as u64) ^ ((shape as u64 + 1) << 40) ^ u64::from(grown));
        let mut source = Source::new(shape);
        let placed: Vec<Run> = (0..runs).map(|_| source.fresh(&mut gen)).collect();
        let twin = Twin::of(if grown { placed.into_iter().fold(RunList::default(), |list, run| list.append(run)) } else { RunList::from_runs(placed) });
        let seats = twin.seats();
        // Every count at every pattern over the first list; over the
        // others each count once, the patterns in turn.
        let patterns: &[(usize, u64)] = if shape == Shape::ManyOrigins && runs == 4_096 && !grown {
            &[(1, 0), (1, 1), (1, 2), (16, 0), (16, 1), (16, 2), (256, 0), (256, 1), (256, 2), (4_096, 0), (4_096, 1), (4_096, 2)]
        } else {
            &[(1, 2), (16, 1), (256, 0), (256, 2), (4_096, 1)]
        };
        for &(count, pattern) in patterns {
            let changes = changes_for(&mut gen, &mut source, &twin, &seats, count, pattern, pattern == 0);
            let mut made = twin.clone();
            made.spliced(&changes);
            made.assert_same(&mut gen, &format!("{shape:?}, {runs} runs (grown: {grown}), {count} changes, pattern {pattern}"));
            cases += 1;
        }
    }
    assert_eq!(cases, 12 + 6 * 5);
}

// ---- Equality is the run sequence's ----

#[test]
fn lists_of_one_run_sequence_are_equal_whatever_their_shape() {
    // One run sequence reached three ways — built at once, grown a run at
    // a time, and left by a history of splices and removals — is three
    // trees of three shapes. They are equal, print alike and write the same
    // run-sequence form; and a list of the same total width holding other
    // runs is equal to none of them.
    let runs: Vec<Run> = (0..3_000u32).map(|k| run(&at_doc(10 + k % 4, 1 + 3 * k), 2)).collect();
    let bulk = RunList::from_runs(runs.clone());
    let grown = runs.iter().fold(RunList::default(), |list, run| list.append(run.clone()));
    // Every third run placed first, the rest spliced in where they
    // belong, then a stretch removed and put back.
    let mut edited = RunList::from_runs(runs.iter().step_by(3).cloned());
    for (at, run) in runs.iter().enumerate().filter(|(at, _)| at % 3 != 0) {
        edited = edited.splice_in(&n(2 * at as u32 + 1), [run.clone()]);
    }
    edited = edited.remove_range(&n(1_001), &n(600)).splice_in(&n(1_001), runs[500..800].iter().cloned());
    for list in [&bulk, &grown, &edited] {
        list.check().expect("each tree holds");
        assert!(list.iter().eq(runs.iter()), "each holds the one run sequence");
    }
    assert_ne!(bulk.fill(), grown.fill(), "the premise: the bulk build and the grown list are two shapes");
    assert_ne!(bulk.fill(), edited.fill(), "the premise: the edited list is a third");
    assert_eq!(bulk, grown);
    assert_eq!(bulk, edited);
    assert_eq!(grown, edited);
    assert_eq!(format!("{bulk:?}"), format!("{grown:?}"));
    assert_eq!(format!("{bulk:?}"), format!("{edited:?}"));
    assert_eq!(format!("{bulk:#?}"), format!("{edited:#?}"));
    let written = bincode::serialize(&bulk).expect("the list encodes");
    assert_eq!(bincode::serialize(&grown).expect("the list encodes"), written);
    assert_eq!(bincode::serialize(&edited).expect("the list encodes"), written);
    // The print is the run sequence's, as a list of runs prints.
    assert_eq!(format!("{:?}", RunList::from_runs(runs[..2].to_vec())), format!("RunList({:?})", &runs[..2]));
    // Another sequence of the same width, the same count and the same
    // first and last runs.
    let mut other = runs.clone();
    other.swap(1_000, 1_001);
    let other = RunList::from_runs(other);
    assert_eq!((other.total_width(), other.run_count()), (bulk.total_width(), bulk.run_count()));
    assert_ne!(other, bulk);
    assert_ne!(other, grown);
    assert_ne!(RunList::default(), bulk);
    assert_eq!(RunList::default(), bulk.remove_range(&n(1), &bulk.total_width()));
}

// ---- A write and a locate do not follow the list's length ----

/// The count a counted call charges its steps to.
type Charge<'a> = &'a mut dyn FnMut(u64);

/// A list of `runs` runs of width 2, none I-adjacent to the next: built at
/// once, or grown a run at a time.
fn fragmented(runs: u32, grown: bool) -> RunList {
    let each = |k: u32| run(&at_doc(10 + k % 4, 1 + 3 * k), 2);
    if grown {
        (0..runs).fold(RunList::default(), |list, k| list.append(each(k)))
    } else {
        RunList::from_runs((0..runs).map(each))
    }
}

/// `count` changes spread over a list of `runs` runs of width 2: each
/// replaces one run's second position with a run of another document.
fn spread_changes(runs: u32, count: u32) -> Vec<Splice> {
    (0..u64::from(count))
        .map(|j| {
            let at_run = ((2 * j + 1) * u64::from(runs) / (2 * u64::from(count))) as u32;
            change(2 * at_run + 2, 1, vec![run(&at_doc(30, 1 + 2 * j as u32), 1)])
        })
        .collect()
}

#[test]
fn a_write_and_a_locate_cost_the_cut_paths_whatever_the_list_holds() {
    // Every write and every read that finds an ordinal, counted on lists
    // of 4,096, 65,536 and 262,144 runs, built at once and grown a run at
    // a time: each stays within the bound its card states, the same bound
    // at every size but for the tree's height. Beside each stands what the
    // vector-backed list's own count is for the same call at 65,536 —
    // every run of the list, whatever the call asks.
    let mut splice_counts: Vec<(u32, bool, u32, u64)> = Vec::new();
    // Every count taken, for the line printed at the end: the call, its
    // steps and the bound it was held to.
    let taken: RefCell<Vec<String>> = RefCell::new(Vec::new());
    for (runs, grown) in [(4_096u32, false), (4_096, true), (65_536, false), (65_536, true), (262_144, false), (262_144, true)] {
        let l = fragmented(runs, grown);
        let height = l.height();
        let (cut, descent) = (cut_bound(height), descent_bound(height));
        let label = format!("{runs} runs (grown: {grown}), height {height}");
        taken.borrow_mut().push(format!("\n  {label}:"));
        let note = |call: &str, count: u64, bound: u64| taken.borrow_mut().push(format!(" {call} {count}/{bound}"));
        let end = l.total_width();
        let counted = |f: &mut dyn FnMut(Charge<'_>)| {
            let mut count = 0u64;
            f(&mut |steps| count += steps);
            count
        };
        // The splice of one change, and of 256 spread.
        for changes in [1u32, 256] {
            let set = spread_changes(runs, changes);
            let count = counted(&mut |steps| drop(l.spliced(&set, &mut |by| steps(by))));
            let bound = (u64::from(changes) + 1) * cut + u64::from(changes);
            assert!(count <= bound, "{label}: spliced of {changes}: {count} steps past {bound}");
            note(&format!("spliced({changes})"), count, bound);
            splice_counts.push((runs, grown, changes, count));
        }
        // The four mutators of one site.
        let middle = n(runs + 1);
        let count = counted(&mut |steps| drop(l.splice_in_counted(&middle, [run(&at_doc(31, 1), 1)], &mut |by| steps(by))));
        assert!(count <= 2 * cut + 1, "{label}: splice_in: {count} steps");
        note("splice_in", count, 2 * cut + 1);
        let count = counted(&mut |steps| drop(l.remove_range_counted(&middle, &n(5), &mut |by| steps(by))));
        assert!(count <= 2 * cut, "{label}: remove_range: {count} steps");
        note("remove_range", count, 2 * cut);
        let count = counted(&mut |steps| drop(l.remove_range_counted(&n(2), &(&end - n(3)), &mut |by| steps(by))));
        assert!(count <= 2 * cut, "{label}: remove_range of nearly all: {count} steps");
        note("remove_range(nearly all)", count, 2 * cut);
        let count = counted(&mut |steps| drop(l.append_counted(run(&at_doc(31, 1), 1), &mut |by| steps(by))));
        assert!(count <= 2 * cut, "{label}: append: {count} steps");
        note("append", count, 2 * cut);
        let cuts = [n(runs / 2), n(runs), n(runs + runs / 2), n(2 * runs - 5)];
        let count = counted(&mut |steps| drop(l.reorder_counted(&cuts[..3], &mut |by| steps(by))));
        assert!(count <= 4 * cut, "{label}: reorder at three cuts: {count} steps");
        note("reorder(3)", count, 4 * cut);
        let count = counted(&mut |steps| drop(l.reorder_counted(&cuts, &mut |by| steps(by))));
        assert!(count <= 5 * cut, "{label}: reorder at four cuts: {count} steps");
        note("reorder(4)", count, 5 * cut);
        // A point at the first, a middle and the last ordinal.
        for ord in [Nat::one(), middle.clone(), end.clone()] {
            let count = counted(&mut |steps| drop(l.locate_counted(&ord, &mut |by| steps(by))));
            assert!(count <= descent, "{label}: locate {ord}: {count} steps");
            note(&format!("locate({ord})"), count, descent);
            assert!(l.point(&ord).is_some());
        }
        // The width, the count and a walk's length: the root's sums.
        let ((width, count, len), entered_nodes) = entered(|| (l.total_width(), l.run_count(), l.iter().len()));
        assert_eq!((width, count, len, entered_nodes), (n(2 * runs), runs as usize, runs as usize, 0), "{label}: read off the root");
        // A range read of one position at the end, and one past it.
        let steps = Cell::new(0u64);
        let last: Vec<Run> = l.iter_resolve_range_counted(&end, &Nat::one(), |by| steps.set(steps.get() + by)).collect();
        assert_eq!(last.len(), 1);
        assert!(steps.get() <= descent + 1, "{label}: the last position resolved: {} steps", steps.get());
        note("resolve(the last position)", steps.get(), descent + 1);
        steps.set(0);
        assert_eq!(l.iter_resolve_range_counted(&(&end + Nat::one()), &n(9), |by| steps.set(steps.get() + by)).count(), 0);
        assert_eq!(steps.get(), 0, "{label}: a range past the end reads nothing");
        // The check of one site at the end, and of 64 sites spread.
        let asked = |k: u32| (n(2 * k + 1), vec![run(&at_doc(10 + k % 4, 1 + 3 * k), 2)]);
        for sites in [vec![asked(runs - 1)], (0..64).map(|j| asked(j * (runs / 64))).collect::<Vec<_>>()] {
            let mut count = 0u64;
            let held = l.arranges_each(sites.iter().map(|(at, runs)| (at, runs.iter())), &mut |by| count += by);
            assert!(held.iter().all(|held| *held), "{label}: every site held");
            let bound = sites.len() as u64 * (2 * (height as u64 + 1) + 20) + 3 * sites.len() as u64;
            assert!(count <= bound, "{label}: {} sites checked: {count} steps past {bound}", sites.len());
            note(&format!("arranges_each({})", sites.len()), count, bound);
        }
        // The vector-backed list's count for the same calls: every run.
        if runs == 65_536 && !grown {
            let old = vector_backed(&l);
            let set = spread_changes(runs, 1);
            let mut old_count = 0u64;
            let old_made = old.spliced(&set, &mut |by| old_count += by);
            assert_eq!(old_count, u64::from(runs) + 1 + 1, "the vector-backed splice: #runs + #changes + #runs placed");
            let mut new_count = 0u64;
            let new_made = l.spliced(&set, &mut |by| new_count += by);
            assert!(new_made.iter().eq(old_made.iter()));
            assert!(new_count <= 2 * cut + 1 && new_count * 100 < old_count, "the tree's: {new_count} steps against {old_count}");
            let (at, runs_asked) = asked(runs - 1);
            let mut old_count = 0u64;
            assert_eq!(old.arranges_each([(&at, runs_asked.iter())], &mut |by| old_count += by), vec![true]);
            assert_eq!(old_count, u64::from(runs) + 1 + 1, "the vector-backed check: #runs + #sites + #runs asked");
        }
    }
    // The splice's count does not follow the list: sixty-four times the
    // runs cost a level or two of the tree more, a change.
    let count_at = |runs: u32, changes: u32| splice_counts.iter().find(|(r, grown, c, _)| (*r, *grown, *c) == (runs, false, changes)).expect("counted").3;
    for changes in [1u32, 256] {
        let (small, large) = (count_at(4_096, changes), count_at(262_144, changes));
        assert!(large <= small + 12 * u64::from(changes), "{changes} changes: {small} steps into 4,096 runs, {large} into 262,144");
    }
    // Each call's steps over its bound, at each size.
    eprintln!("steps a call, over the bound it is held to:{}", taken.borrow().concat());
}

// ---- A version shares what it did not change ----

#[test]
fn a_changed_list_shares_every_node_its_change_did_not_reach() {
    // After one change into 65,536 and 262,144 runs, the nodes of the new
    // list the old one does not hold are the cut path: a leaf or two, and
    // an inner node a level. After 256 changes spread, 256 such paths less
    // what they share near the root. A clone holds the root itself.
    let mut made_a_version = Vec::new();
    for (runs, grown) in [(65_536u32, false), (65_536, true), (262_144, false), (262_144, true)] {
        let l = fragmented(runs, grown);
        let height = l.height();
        let label = format!("{runs} runs (grown: {grown}), height {height}");
        assert!(l.clone().shares_root_with(&l), "{label}: a clone is one more handle on the root");
        // A run replaced by a run: its leaf, and the node above it at each
        // level, and no other.
        let replaced = l.spliced(&[change(runs + 1, 2, vec![run(&at_doc(30, 1), 2)])], &mut |_| {});
        replaced.check().expect("the changed tree holds");
        assert_eq!(replaced.made_anew(&[&l]), (1, height), "{label}: one run replaced makes its path anew");
        // A position replaced inside a run, which leaves the list a run
        // more: where the leaf was full it becomes two, and so may each
        // node above it — two nodes a level, and a new root over them.
        let one = l.spliced(&spread_changes(runs, 1), &mut |_| {});
        one.check().expect("the changed tree holds");
        let (leaves, inner) = one.made_anew(&[&l]);
        assert!((1..=2).contains(&leaves) && (height..=2 * height + 1).contains(&inner), "{label}: one change made {leaves} leaves and {inner} inner nodes anew");
        let many = l.spliced(&spread_changes(runs, 256), &mut |_| {});
        many.check().expect("the changed tree holds");
        let (leaves, inner) = many.made_anew(&[&l]);
        assert!(leaves <= 2 * 256 && inner <= 256 * (height - 1) + 20, "{label}: 256 changes made {leaves} leaves and {inner} inner nodes anew");
        made_a_version.push((runs, grown, height, one.made_anew(&[&l]), (leaves, inner)));
        // Each of the other mutators: the cut paths, and nothing else.
        let middle = n(runs + 1);
        let made = [
            ("splice_in", l.splice_in(&middle, [run(&at_doc(31, 1), 1)])),
            ("remove_range", l.remove_range(&middle, &n(5))),
            ("append", l.append(run(&at_doc(31, 1), 1))),
            ("reorder", l.reorder(&[n(runs / 2), n(runs), n(runs + runs / 2)])),
        ];
        for (name, list) in &made {
            list.check().unwrap_or_else(|fault| panic!("{label}: {name}: {fault}"));
            let (leaves, inner) = list.made_anew(&[&l]);
            assert!(leaves <= 8 && inner <= 4 * (height + 1), "{label}: {name} made {leaves} leaves and {inner} inner nodes anew");
        }
        // Ten changes in a row, each list kept: ten cut paths, not ten
        // lists.
        let mut kept: Vec<RunList> = vec![l.clone()];
        for j in 0..10u32 {
            let last = kept.last().expect("a list");
            let at = 2 * (j * (runs / 10) + 7) + 2;
            kept.push(last.spliced(&[change(at, 1, vec![run(&at_doc(32, 1 + 2 * j), 1)])], &mut |_| {}));
        }
        let all: Vec<&RunList> = kept.iter().collect();
        let before = RunList::nodes_among(&[&l]);
        let after = RunList::nodes_among(&all);
        assert!(after - before <= 10 * (2 * height + 3), "{label}: ten versions hold {} nodes beside the first list's {before}", after - before);
    }
    // What a version makes anew, at each size: (runs, grown, height, the
    // leaves and inner nodes of one change, and of 256).
    eprintln!("nodes made anew a version: {made_a_version:?}");
}

// ---- The walk from both ends ----

#[test]
fn the_runs_are_walked_from_either_end_with_their_count_exact() {
    // Over the empty list, one leaf, and trees of several levels, built at
    // once and grown: the walk forward and backward, from both ends until
    // they meet, with its length exact at every step and fused past the
    // end — each equal to the vector-backed list's own walk.
    for (runs, grown) in [(0u32, false), (1, false), (7, false), (16, false), (17, true), (200, false), (200, true), (5_000, false), (5_000, true)] {
        let l = fragmented(runs, grown);
        let old = vector_backed(&l);
        let label = format!("{runs} runs (grown: {grown})");
        assert!(l.iter().eq(old.iter()), "{label}: forward");
        assert!(l.iter().rev().eq(old.iter().rev()), "{label}: backward");
        assert_eq!(l.iter().next_back(), old.iter().next_back(), "{label}: the last run first");
        // Both ends, in a generated order, until they meet.
        let mut gen = Gen(0x0123_4567_89ab_cdef ^ u64::from(runs));
        let (mut mine, mut theirs) = (l.iter(), old.iter());
        let mut left = runs as usize;
        loop {
            assert_eq!(mine.len(), left, "{label}: the length, {left} runs from the end");
            assert_eq!(mine.size_hint(), (left, Some(left)));
            let (got, want) = if gen.below(2) == 0 { (mine.next(), theirs.next()) } else { (mine.next_back(), theirs.next_back()) };
            assert_eq!(got, want, "{label}: {left} runs from the end");
            if got.is_none() {
                break;
            }
            left -= 1;
        }
        assert_eq!(left, 0, "{label}: every run yielded once");
        for _ in 0..3 {
            assert!(mine.next().is_none() && mine.next_back().is_none(), "{label}: fused at both ends");
            assert_eq!(mine.len(), 0);
        }
    }
    // The length is the root's count: asking it enters no node, at any
    // point of the walk.
    let l = fragmented(65_536, false);
    let mut runs = l.iter();
    let ((), walked) = entered(|| {
        assert_eq!(runs.len(), 65_536);
    });
    assert_eq!(walked, 0, "the length of an unpulled walk");
    runs.next();
    runs.next_back();
    let ((), walked) = entered(|| {
        assert_eq!(runs.len(), 65_534);
    });
    assert_eq!(walked, 0, "the length of a walk pulled at both ends");
    assert_eq!(format!("{runs:?}"), "Runs { .. }");
}
