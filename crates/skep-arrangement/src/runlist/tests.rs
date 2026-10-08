use std::collections::BTreeSet;

use super::*;
use crate::testutil::{a, ca, n, pca, run, vca};

/// A list through the coalesce every `RunList` passes, so a fixture holds the
/// maximally-merged decomposition the type promises of every list in the
/// process.
fn list(runs: Vec<Run>) -> RunList {
    RunList(coalesced(runs))
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
fn a_run_union_denotes_exactly_the_runs_addresses_each_once_in_tumbler_order() {
    // S3★/PUB-6.24: the union a run set's I-extents name, merged within each
    // content chain — EXACTLY the runs' addresses, none dropped, which the
    // shot's existence walk and its re-insert's `.expect` stand on, and each
    // in one merged run, which is what lets the walk pay a stored position
    // once however often a request names it. Repeats, nesting, overlap,
    // abutment and a gap in one chain; a second chain of the SAME length,
    // kept apart by its prefix alone; a third of another length — listed out
    // of order, so the sort is what brings each chain's runs together.
    let family = vec![
        run(&ca(3), 2),
        run(&ca(1), 2),
        run(&ca(3), 2),
        run(&ca(2), 5),
        run(&ca(9), 1),
        run(&ca(8), 1),
        run(&pca(3), 1),
        run(&pca(1), 1),
        run(&vca(1), 3),
        run(&vca(2), 1),
    ];
    let union = RunUnion::of(&family);
    let merged: Vec<Run> = union.runs().collect();
    assert_eq!(
        merged,
        vec![
            run(&ca(1), 6),
            run(&ca(8), 2),
            run(&vca(1), 3),
            run(&pca(1), 1),
            run(&pca(3), 1)
        ]
    );
    let named: BTreeSet<Address> = family.iter().flat_map(Run::addrs).collect();
    let denoted: Vec<Address> = merged.iter().flat_map(Run::addrs).collect();
    assert_eq!(denoted.len(), named.len(), "no address in two merged runs");
    assert_eq!(denoted.into_iter().collect::<BTreeSet<_>>(), named);
    // And whole-run membership is its search, against the address-by-address
    // oracle, from every start and width across the three chains and their
    // gaps — the same-length chains being where the prefix, and not the
    // length, has to keep the search apart.
    let mut checked = 0usize;
    for start in (1..=10u32).flat_map(|k| [ca(k), pca(k), vca(k)]) {
        for width in 1..=7u32 {
            let probe = run(&start, width);
            let held = probe.addrs().all(|address| named.contains(&address));
            assert_eq!(union.covers(&probe), held, "{start:?} × {width}");
            checked += 1;
        }
    }
    assert_eq!(checked, 210);
    assert_eq!(
        RunUnion::of(std::iter::empty::<&Run>()).runs().count(),
        0,
        "an empty union"
    );
    assert!(!RunUnion::of(std::iter::empty::<&Run>()).covers(&run(&ca(1), 1)));
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
    let doc2_third = a(&[1, 0, 1, 0, 2, 0, 1, 3]);
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
