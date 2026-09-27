use std::collections::BTreeSet;

use super::*;
use crate::state::M5Rec;
use crate::testutil::{a, ca, doc1, doc2, la, n, run, t, vca, vp, vspan};
use skep_address::subtree_of;

fn place(s: &M5State, doc: &Address, at: u32, runs: Vec<Run>) -> M5State {
    s.apply_m5(&M5Rec::ContentPlace {
        doc: doc.clone(),
        at: n(at),
        runs,
    })
}

fn arranged() -> M5State {
    // doc1 content: ca(1..3) then a transcluded length-9 run vca(1..2).
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
    place(&s, &doc1(), 4, vec![run(&vca(1), 2)])
}

#[test]
fn resolve_folds_every_malformed_request_to_nothing() {
    // §2: every malformed request folds to ⟨⟩ — never a fault.
    let s = arranged();
    // The usable form resolves.
    assert_eq!(s.resolve(&doc1(), &vspan(1, 1, 3)), vec![run(&ca(1), 3)]);
    // #start ≠ 2 (both < 2 and > 2).
    let shallow = Span::new(t(&[5]), t(&[1])).expect("T12");
    assert!(s.resolve(&doc1(), &shallow).is_empty());
    let deep = Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).expect("T12");
    assert!(s.resolve(&doc1(), &deep).is_empty());
    // #width ≠ 2 alone: T12 admits this span (action point 2 ≤ #start 2),
    // its start is a well-formed V-position and its width position 1 is
    // zero, so only the width-length clause refuses it. Served, it would
    // resolve five content ordinals for a span whose reach is [1, 6, 0].
    let deep_width = Span::new(t(&[1, 1]), t(&[0, 5, 0])).expect("T12: action point 2 ≤ #start");
    assert!(s.resolve(&doc1(), &deep_width).is_empty());
    // Non-ordinal width [m, n] with m > 0 (action-point-1).
    let action_point_1 = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12");
    assert!(s.resolve(&doc1(), &action_point_1).is_empty());
    // Unknown subspace selects no run-list.
    let odd = Span::new(t(&[3, 1]), t(&[0, 1])).expect("T12");
    assert!(s.resolve(&doc1(), &odd).is_empty());
    // Absent doc.
    assert!(s.resolve(&doc2(), &vspan(1, 1, 1)).is_empty());
}

#[test]
fn resolve_serves_the_link_subspace_off_its_own_run_list() {
    // §2: the span's subspace numeral selects the run-list, so a link
    // span resolves against the LINK runs — which is what makes COPY's
    // `SourceNotContentSubspace` a needed guard rather than a formality,
    // and what M7 relies on when it builds a slot endset.
    let s = arranged();
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(2) });
    assert_eq!(s.resolve(&doc1(), &vspan(2, 1, 2)), vec![run(&la(1), 2)]);
    // Clipped to n_L, exactly as the content side is.
    assert!(s.resolve(&doc1(), &vspan(2, 3, 1)).is_empty());
}

#[test]
fn resolve_clips_the_over_reach_and_preserves_v_order() {
    // ASN-0118 accept-and-intersect: over-reach silently clipped; V-order
    // preserved across the transclusion seam.
    let s = arranged();
    let got = s.resolve(&doc1(), &vspan(1, 2, 10));
    assert_eq!(got, vec![run(&ca(2), 2), run(&vca(1), 2)]);
}

#[test]
fn the_arrangement_states_which_positions_it_admits() {
    // §1/§3/§4/§8: the placement boundary, the arranged position, the
    // containment of a range and the seating of a link are all facts
    // about the arrangement, so the arrangement answers them.
    let s = arranged(); // n_C = 5
    assert!(s.admits_content_boundary(&doc1(), &n(1)));
    assert!(s.admits_content_boundary(&doc1(), &n(6))); // the append boundary
    assert!(!s.admits_content_boundary(&doc1(), &n(0)));
    assert!(!s.admits_content_boundary(&doc1(), &n(7)));
    // An empty document admits ordinal 1 and nothing else.
    assert!(s.admits_content_boundary(&doc2(), &n(1)));
    assert!(!s.admits_content_boundary(&doc2(), &n(2)));
    // Arranged positions stop one short of that boundary.
    assert!(s.arranges_content_position(&doc1(), &n(5)));
    assert!(!s.arranges_content_position(&doc1(), &n(6)));
    assert!(!s.arranges_content_position(&doc1(), &n(0)));
    assert!(!s.arranges_content_position(&doc2(), &n(1)));
    // A FRESH position (the deposit shape) is one past the extent: the
    // append boundary and beyond, in the content subspace alone.
    assert!(s.names_fresh_content_position(&doc1(), &vp(1, 6)));
    assert!(s.names_fresh_content_position(&doc1(), &vp(1, 9)));
    assert!(!s.names_fresh_content_position(&doc1(), &vp(1, 5)));
    assert!(!s.names_fresh_content_position(&doc1(), &vp(1, 1)));
    assert!(!s.names_fresh_content_position(&doc1(), &vp(2, 6)));
    assert!(s.names_fresh_content_position(&doc2(), &vp(1, 1)));
    assert!(!s.names_fresh_content_position(&doc2(), &vp(1, 0)));
    // Containment: [from, from + width) must fit the arranged content.
    assert!(s.contains_content_range(&doc1(), &n(2), &n(4)));
    assert!(!s.contains_content_range(&doc1(), &n(2), &n(5)));
    // Seating is I-extent membership, so an interior position of a
    // coalesced link run counts.
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(2) });
    assert_eq!(s.link_runs(&doc1()).len(), 1);
    assert!(s.seats_link(&doc1(), &la(1)));
    assert!(s.seats_link(&doc1(), &la(2)));
    assert!(!s.seats_link(&doc1(), &la(3)));
    assert!(!s.seats_link(&doc2(), &la(1)));
}

#[test]
fn the_runs_past_an_extent_are_the_arrangements_own_tail() {
    // PUB-2.42/2.45: the shot carries a base's positions past the extent
    // its staged copy took, and the arrangement answers which runs those
    // are — from any extent, across a transclusion seam, the boundary run
    // clipped, and nothing once the extent reaches the end.
    let s = arranged(); // ca(1..3) then vca(1..2): n_C = 5
    let past = |extent: u32| s.content_runs_past(&doc1(), &n(extent)).collect::<Vec<_>>();
    assert_eq!(past(0), vec![run(&ca(1), 3), run(&vca(1), 2)]);
    assert_eq!(past(2), vec![run(&ca(3), 1), run(&vca(1), 2)]);
    assert_eq!(past(3), vec![run(&vca(1), 2)]);
    assert_eq!(past(4), vec![run(&vca(2), 1)]);
    assert!(past(5).is_empty(), "an extent at the end carries nothing");
    assert!(past(9).is_empty(), "nor one past it");
    assert_eq!(s.content_runs_past(&doc2(), &n(0)).next(), None, "absent doc");
}

#[test]
fn the_counts_a_caller_prices_with_are_the_lengths_of_what_they_count() {
    // The quantities the cost statements name, each against the thing it
    // counts: `#runs` per subspace is the length of what `content_runs` /
    // `link_runs` would hand back — runs, not the positions they cover —
    // and `|R↾doc|` is how many spans R↾doc holds, one per placed run,
    // which a delete leaves standing (P2) and a link seat never adds to
    // (J-LV).
    let s = arranged(); // ca(1..3) then vca(1..2): two runs, two placements
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(2) }); // coalesces
    assert_eq!(s.content_run_count(&doc1()), s.content_runs(&doc1()).len());
    assert_eq!(s.content_run_count(&doc1()), 2, "two runs over five positions");
    assert_eq!(s.link_run_count(&doc1()), s.link_runs(&doc1()).len());
    assert_eq!(s.link_run_count(&doc1()), 1);
    assert_eq!(
        s.recorded_span_count(&doc1()),
        s.provenance.ever_contained(&doc1()).len()
    );
    assert_eq!(s.recorded_span_count(&doc1()), 2, "two placements; the seats record nothing");
    // Emptiness is the count's zero, asked of the list rather than summed:
    // a document arranging content is not empty, whatever its links.
    assert!(!s.content_is_empty(&doc1()));
    let s = s.apply_m5(&M5Rec::ContentRemove {
        doc: doc1(),
        from: n(1),
        width: n(5),
    });
    assert_eq!(s.content_run_count(&doc1()), 0);
    assert!(s.content_is_empty(&doc1()), "every position removed, the links kept");
    assert_eq!(s.link_run_count(&doc1()), 1, "a text delete never touches the links");
    assert_eq!(s.recorded_span_count(&doc1()), 2, "R keeps what the delete removed");
    for count in [
        s.content_run_count(&doc2()),
        s.link_run_count(&doc2()),
        s.recorded_span_count(&doc2()),
    ] {
        assert_eq!(count, 0, "an absent document");
    }
    assert!(s.content_is_empty(&doc2()), "an absent document");
}

#[test]
fn the_runs_are_lent_in_v_order_with_their_length_and_reverse_walk() {
    // §2: `content_runs`/`link_runs` lend the stored runs, and the loan
    // forwards what the walk knows — the exact length, which is `#runs`,
    // the reverse walk, and fusing. A hand-written wrapper can drop a
    // forwarded capability without any signature changing, so each is
    // asked of it here.
    let s = arranged(); // ca(1..3) then vca(1..2)
    let (first, second) = (run(&ca(1), 3), run(&vca(1), 2));
    assert_eq!(s.content_runs(&doc1()).collect::<Vec<_>>(), vec![&first, &second]);
    let mut lent = s.content_runs(&doc1());
    assert_eq!(lent.len(), s.content_run_count(&doc1()));
    assert_eq!(lent.len(), 2);
    assert_eq!(lent.next(), Some(&first));
    assert_eq!((lent.len(), lent.size_hint()), (1, (1, Some(1))), "the length tracks the walk");
    assert_eq!(lent.next_back(), Some(&second), "the reverse walk meets the forward one");
    assert_eq!(lent.len(), 0);
    assert_eq!(lent.next(), None);
    assert_eq!(lent.next(), None, "exhausted stays exhausted");
    assert_eq!(
        s.content_runs(&doc1()).rev().collect::<Vec<_>>(),
        vec![&second, &first]
    );
    // The link subspace lends its own list, by the same walk.
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    assert_eq!(s.link_runs(&doc1()).collect::<Vec<_>>(), vec![&run(&la(1), 1)]);
    assert_eq!(s.link_runs(&doc1()).len(), s.link_run_count(&doc1()));
    // An absent document lends nothing, in either subspace.
    for mut empty in [s.content_runs(&doc2()), s.link_runs(&doc2())] {
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.next(), None);
    }
}

#[test]
fn each_subspace_arranges_the_dense_prefix_its_count_names() {
    // D-SEQ★ (§1; ASN-0047, via contiguity D-CTG★ and minimum-position
    // D-MIN★), which this slice now PUBLISHES rather than merely keeping:
    // a subspace's arranged positions are exactly [1, n_s], the count is
    // the largest of them, and `resolve`'s runs tile that prefix
    // contiguously from max(ord, 1). All three are what a caller walking
    // an arrangement stands on, so all three are checked — over a
    // fragmented, mixed-length arrangement, after the one fold arm that
    // would open a hole in the middle if the representation admitted one.
    let s = arranged(); // ca(1..3) then vca(1..2): two runs, two lengths
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(3) }); // not I-adjacent
    let s = s.apply_m5(&M5Rec::ContentRemove {
        doc: doc1(),
        from: n(2),
        width: n(2),
    });
    let at = |subspace: u32, ordinal: &Nat| VPos {
        subspace: n(subspace),
        ordinal: ordinal.clone(),
    };
    for (subspace, count, runs) in [
        (1u32, s.content_count(&doc1()), s.content_runs(&doc1())),
        (2, s.link_count(&doc1()), s.link_runs(&doc1())),
    ] {
        assert!(count >= n(2), "the fixture arranges both subspaces");
        assert_eq!(
            runs.map(Run::width).sum::<Nat>(),
            count,
            "subspace {subspace}: the count is the run widths' sum"
        );
        // Dense from 1: every ordinal below the count is arranged, and the
        // count is the largest — so one bound settles membership.
        assert_eq!(s.point(&doc1(), &at(subspace, &n(0))), None);
        let mut k = n(1);
        while k <= count {
            assert!(
                s.point(&doc1(), &at(subspace, &k)).is_some(),
                "subspace {subspace}: ordinal {k} is arranged"
            );
            k = &k + &n(1);
        }
        assert_eq!(
            s.point(&doc1(), &at(subspace, &(&count + &n(1)))),
            None,
            "subspace {subspace}: the count is the LARGEST arranged ordinal"
        );
        // The runs tile V contiguously: accumulating widths from
        // max(ord, 1) names each run's own V-start, and the walk ends at
        // the boundary past the prefix.
        for open in [0u32, 1, 2] {
            let mut v = std::cmp::max(n(open), n(1));
            for r in s.resolve(&doc1(), &vspan(subspace, open, 99)) {
                assert_eq!(
                    s.point(&doc1(), &at(subspace, &v)).as_ref(),
                    Some(r.i_start()),
                    "subspace {subspace} from {open}: each run begins at the accumulated V-start"
                );
                v = &v + r.width();
            }
            assert_eq!(
                v,
                &count + &n(1),
                "subspace {subspace} from {open}: the runs tile the whole prefix"
            );
        }
    }
}

#[test]
fn point_answers_m_of_d_and_folds_bad_positions_to_none() {
    let s = arranged();
    assert_eq!(s.point(&doc1(), &vp(1, 1)), Some(ca(1)));
    assert_eq!(s.point(&doc1(), &vp(1, 4)), Some(vca(1)));
    assert_eq!(s.point(&doc1(), &vp(1, 6)), None); // unarranged ordinal
    assert_eq!(s.point(&doc1(), &vp(3, 1)), None); // unknown subspace
    assert_eq!(s.point(&doc1(), &vp(1, 0)), None); // ordinal 0
    assert_eq!(s.point(&doc2(), &vp(1, 1)), None); // absent doc
    // Link subspace answers off the link run-list.
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    assert_eq!(s.point(&doc1(), &vp(2, 1)), Some(la(1)));
}

#[test]
fn image_is_the_concatenated_iextent_lift() {
    // §2: ⋃ r.iextent(), total, not normalized, possibly mixed-length.
    let s = arranged();
    let cov = s.image(&doc1(), &vspan(1, 1, 5));
    let spans: Vec<Span> = cov.iter().cloned().collect();
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0].start().len(), 8);
    assert_eq!(spans[1].start().len(), 9); // mixed-length across origins
    assert!(cov.denotes(ca(2).tumbler()));
    assert!(cov.denotes(vca(2).tumbler()));
    assert!(!cov.denotes(ca(4).tumbler()));
}

#[test]
fn project_maps_i_coverage_back_to_v_spans_in_both_branches() {
    let s = arranged();
    // Level-uniform, same-length branch: one element's I-extent.
    let one = SpanSet::singleton(run(&ca(2), 1).iextent());
    let got = s.project(&doc1(), &one);
    let spans: Vec<Span> = got.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), &t(&[1, 2]));
    assert_eq!(spans[0].width(), &t(&[0, 1]));
    // Cross-length fallback: doc1's content-base subtree (length 7) picks
    // out exactly the length-8 positions 1..3, not the transcluded tail.
    let base = subtree_of(&t(&[1, 0, 1, 0, 1, 0, 1]));
    let got = s.project(&doc1(), &SpanSet::singleton(base));
    let spans: Vec<Span> = got.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), &t(&[1, 1]));
    assert_eq!(spans[0].width(), &t(&[0, 3]));
    // Same-length but NOT level-uniform — M1's length-gated `intersect`
    // faults on it, so it takes the fallback too, and `project`'s
    // fault-free claim covers it. `[ca(3), [2])` opens inside the
    // length-8 run and reaches past every address either run holds, so
    // it takes that run's last position and all of the transcluded one:
    // ordinals 3, 4, 5, coalesced into one span.
    let skew = Span::new(ca(3).tumbler().clone(), t(&[1])).expect("T12: action point 1 ≤ 8");
    assert!(!skew.is_level_uniform());
    let got = s.project(&doc1(), &SpanSet::singleton(skew));
    let spans: Vec<Span> = got.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), &t(&[1, 3]));
    assert_eq!(spans[0].width(), &t(&[0, 3]));
    // Absent doc ⇒ ⟨⟩; empty coverage ⇒ ⟨⟩.
    assert!(s.project(&doc2(), &one).is_empty());
    assert!(s.project(&doc1(), &SpanSet::empty()).is_empty());
}

#[test]
fn project_reports_content_positions_only() {
    // §2/BH3: I→V projection is the CONTENT subspace's, by construction —
    // link reverse-discovery is M7's. A link-subspace coverage has no
    // footprint here, and mixing one into a content coverage adds
    // nothing: the answer is the content footprint alone. The link
    // addresses share the content addresses' length class, so this is
    // decided by the run-lists consulted, not by a length mismatch.
    let s = arranged();
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(2) });
    let links = run(&la(1), 2).iextent();
    assert_eq!(links.start().len(), ca(1).tumbler().len());
    assert!(s.project(&doc1(), &SpanSet::singleton(links.clone())).is_empty());
    let mixed: SpanSet = vec![run(&ca(2), 1).iextent(), links].into_iter().collect();
    let got = s.project(&doc1(), &mixed);
    let spans: Vec<Span> = got.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), &t(&[1, 2]));
    assert_eq!(spans[0].width(), &t(&[0, 1]));
}

#[test]
fn project_reports_fragmented_footprints() {
    // ASN-0119 RA7c: a footprint interrupted in V-space comes back as
    // separate V-spans (normalized, so truly separate ranges stay apart).
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 1)]);
    let s = place(&s, &doc1(), 2, vec![run(&vca(1), 1)]);
    let s = place(&s, &doc1(), 3, vec![run(&ca(2), 1)]);
    // Coverage over ca(1..2) hits V-ordinals 1 and 3, not 2.
    let cov = SpanSet::singleton(run(&ca(1), 2).iextent());
    let got = s.project(&doc1(), &cov);
    let spans: Vec<Span> = got.iter().cloned().collect();
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0].start(), &t(&[1, 1]));
    assert_eq!(spans[1].start(), &t(&[1, 3]));
}

#[test]
fn project_reports_every_position_an_address_occupies() {
    // ASN-0119 RA7c: the footprint is EVERY V-position whose I-address
    // falls in the coverage. A document that transcludes its own text
    // holds those addresses twice, and both occurrences are its
    // footprint. An I→V lookup answering one position per address — Open
    // decision #2's inverse hint, built as a map — keeps the first and
    // loses the second.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
    let s = place(&s, &doc1(), 4, vec![run(&ca(1), 3)]); // a b c a b c
    let b = SpanSet::singleton(run(&ca(2), 1).iextent());
    let spans: Vec<Span> = s.project(&doc1(), &b).iter().cloned().collect();
    assert_eq!(spans.len(), 2, "b at positions 2 and 5");
    assert_eq!(spans[0].start(), &t(&[1, 2]));
    assert_eq!(spans[1].start(), &t(&[1, 5]));
    for span in &spans {
        assert_eq!(span.width(), &t(&[0, 1]));
    }
}

#[test]
fn project_answers_exactly_the_positions_whose_address_the_coverage_contains() {
    // ASN-0119 RA7c as a law: for every coverage span in a generated family
    // and every V-ordinal, the footprint holds [s_C, k] exactly when the span
    // contains M(d)(k) — the oracle being `point` and `Span::contains`, which
    // know nothing of blocks or offsets — and it is normalized. The
    // arrangement is fragmented, mixed in length and holds two addresses
    // twice, and the family's spans open and close on every block seam and
    // inside every block, through both of the run's branches.
    let s = place(&arranged(), &doc1(), 6, vec![run(&ca(2), 2)]); // ca1 ca2 ca3 vca1 vca2 ca2 ca3
    let mut family: Vec<Span> = Vec::new();
    for lo in 1..=4u32 {
        for hi in lo + 1..=5 {
            family.push(
                Span::from_endpoints(ca(lo).tumbler().clone(), ca(hi).tumbler()).expect("lo < hi"),
            );
        }
    }
    for lo in 1..=2u32 {
        for hi in lo + 1..=3 {
            family.push(
                Span::from_endpoints(vca(lo).tumbler().clone(), vca(hi).tumbler()).expect("lo < hi"),
            );
        }
    }
    for k in 1..=4u32 {
        family.push(Span::new(ca(k).tumbler().clone(), t(&[1])).expect("T12: action point 1 ≤ 8"));
    }
    family.push(subtree_of(&t(&[1, 0, 1, 0, 1, 0, 1])));
    family.push(subtree_of(&t(&[1, 0, 1, 0, 1, 1])));
    assert_eq!(family.len(), 19);
    for cover in &family {
        let footprint = s.project(&doc1(), &SpanSet::singleton(cover.clone()));
        assert!(footprint.is_empty() || footprint.is_normalized(), "{cover:?}");
        for k in 0..=8u32 {
            let expected = s
                .point(&doc1(), &vp(1, k))
                .is_some_and(|address| cover.contains(address.tumbler()));
            assert_eq!(footprint.denotes(&t(&[1, k])), expected, "{cover:?} at ordinal {k}");
        }
        assert!(!footprint.denotes(&t(&[2, 1])), "{cover:?}: the footprint is the content subspace's");
    }
}

#[test]
fn arranges_any_is_the_footprints_non_emptiness_without_building_it() {
    // §2/FD-FIND: `arranges_any(d, c)` is `!project(d, c).is_empty()`,
    // asked against `project` itself — every span alone, then mixed
    // coverages. The family hits through both of the run's branches (the
    // subtree reaches only the length-9 runs, which a length filter over
    // the covers would skip) and misses three ways.
    let s = place(&arranged(), &doc1(), 6, vec![run(&ca(2), 2)]); // ca1 ca2 ca3 vca1 vca2 ca2 ca3
    let mut family: Vec<Span> = Vec::new();
    for lo in 1..=4u32 {
        for hi in lo + 1..=5 {
            family.push(
                Span::from_endpoints(ca(lo).tumbler().clone(), ca(hi).tumbler()).expect("lo < hi"),
            );
        }
    }
    family.push(subtree_of(&t(&[1, 0, 1, 0, 1, 1])));
    family.push(Span::new(ca(3).tumbler().clone(), t(&[1])).expect("T12: action point 1 ≤ 8"));
    family.push(run(&ca(9), 1).iextent());
    family.push(run(&la(1), 2).iextent());
    assert_eq!(family.len(), 14);
    let mut hits = 0usize;
    for cover in &family {
        let one = SpanSet::singleton(cover.clone());
        let has_footprint = !s.project(&doc1(), &one).is_empty();
        assert_eq!(s.arranges_any(&doc1(), &one), has_footprint, "{cover:?}");
        hits += usize::from(has_footprint);
    }
    assert_eq!(hits, 11, "every span but [ca4, ca5), [ca9, ca10) and the link extent");
    let misses: SpanSet = vec![run(&ca(9), 1).iextent(), run(&la(1), 2).iextent()]
        .into_iter()
        .collect();
    assert!(!s.arranges_any(&doc1(), &misses));
    assert!(s.project(&doc1(), &misses).is_empty());
    let one_hit: SpanSet = vec![run(&ca(9), 1).iextent(), run(&vca(2), 1).iextent()]
        .into_iter()
        .collect();
    assert!(s.arranges_any(&doc1(), &one_hit));
    assert!(!s.project(&doc1(), &one_hit).is_empty());
    assert!(!s.arranges_any(&doc1(), &SpanSet::empty()), "an empty coverage");
    assert!(
        !s.arranges_any(&doc2(), &SpanSet::singleton(run(&ca(1), 1).iextent())),
        "an absent document"
    );
}

#[test]
fn an_address_the_document_still_arranges_elsewhere_is_not_deleted() {
    // §9: SHOWDELETIONS is ASN-0075's DELETED(a, d) ≡ (a, d) ∈ R ∧
    // a ∉ ran(M(d)) — a SET difference. A document that transcludes its
    // own text holds those addresses twice, so removing one occurrence
    // deletes nothing; only the last occurrence's removal makes a
    // deletion. R recording the span twice changes no answer either: it
    // is read as the set-union of its pairs (P2; Open decision #9's
    // premise). A deleted set kept by recording what each ContentRemove
    // took out — the obvious index for this read's cost (Open decision
    // #3) — would report `b` after the first removal.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
    let s = place(&s, &doc1(), 4, vec![run(&ca(1), 3)]); // a b c a b c
    let one_b = s.apply_m5(&M5Rec::ContentRemove {
        doc: doc1(),
        from: n(2),
        width: n(1),
    });
    assert!(one_b.deletions(&doc1()).is_empty(), "the other b is still arranged");
    let one_copy = s.apply_m5(&M5Rec::ContentRemove {
        doc: doc1(),
        from: n(4),
        width: n(3),
    });
    assert!(one_copy.deletions(&doc1()).is_empty(), "a, b and c are each still arranged");
    let last_b = one_copy.apply_m5(&M5Rec::ContentRemove {
        doc: doc1(),
        from: n(2),
        width: n(1),
    });
    let spans: Vec<Span> = last_b.deletions(&doc1()).iter().cloned().collect();
    assert_eq!(spans.len(), 1, "b's last occurrence is gone, and now b is deleted");
    assert_eq!(spans[0].start(), ca(2).tumbler());
    assert_eq!(spans[0].reach(), *ca(3).tumbler());
}

#[test]
fn deletions_is_ever_contained_minus_the_image_over_every_two_placement_history() {
    // §9 / ASN-0075: DELETED(a, d) ≡ (a, d) ∈ R ∧ a ∉ ran(M(d)) — a law over
    // histories, asserted address by address against an oracle built from
    // `Run::addrs` and plain sets. The histories are every ordered pair of
    // placements from a menu — one origin twice, two lengths, an overlapping
    // pair — the second placed at every boundary of the first (so a foreign
    // run can split one origin's R span into two image runs), the state
    // before any removal, then every contained removal. R holding
    // overlapping spans, an image split across a seam, and a class the image
    // no longer reaches are all visited by inputs no one chose.
    let menu = [(ca(1), 2u32), (ca(2), 2), (ca(3), 1), (vca(1), 2)];
    let alphabet: Vec<Address> = (1..=5).map(ca).chain((1..=3).map(vca)).collect();
    let check = |s: &M5State, ever: &BTreeSet<Address>, label: &str| {
        let image: BTreeSet<Address> = s.content_runs(&doc1()).flat_map(Run::addrs).collect();
        let deleted = s.deletions(&doc1());
        for address in &alphabet {
            assert_eq!(
                deleted.denotes(address.tumbler()),
                ever.contains(address) && !image.contains(address),
                "{label}: {address:?}"
            );
        }
    };
    let mut checked = 0usize;
    for (first, w1) in &menu {
        for (second, w2) in &menu {
            let ever: BTreeSet<Address> = run(first, *w1)
                .into_addrs()
                .chain(run(second, *w2).into_addrs())
                .collect();
            let n_c = w1 + w2;
            for at in 1..=w1 + 1 {
                let placed = place(&M5State::genesis(), &doc1(), 1, vec![run(first, *w1)]);
                let placed = place(&placed, &doc1(), at, vec![run(second, *w2)]);
                let label = format!("{first:?}×{w1}, then {second:?}×{w2} at {at}");
                check(&placed, &ever, &label);
                for from in 1..=n_c {
                    for width in 1..=n_c + 1 - from {
                        let removed = placed.apply_m5(&M5Rec::ContentRemove {
                            doc: doc1(),
                            from: n(from),
                            width: n(width),
                        });
                        check(&removed, &ever, &format!("{label}, remove [{from}, {})", from + width));
                        checked += 1;
                    }
                }
            }
        }
    }
    // 9 width-2 pairs × 3 boundaries × 10 removals, 3 × 3 × 6, 3 × 2 × 6, 1 × 2 × 3.
    assert_eq!(checked, 366, "every contained removal of every history");
}

#[test]
fn deletions_subtracts_within_each_level_class() {
    // §9: iextent covers mix origin-lengths under transclusion; the
    // difference runs within each endpoint-length class and unions the
    // results — different-length addresses cannot cancel.
    let s = arranged(); // ever: len-8 [ca1,ca4) + len-9 [vca1,vca3); image same
    assert!(s.deletions(&doc1()).is_empty());
    // Drop everything: both classes surface.
    let s = s.apply_m5(&M5Rec::ContentRemove {
        doc: doc1(),
        from: n(1),
        width: n(5),
    });
    assert_eq!(s.content_count(&doc1()), n(0));
    let d = s.deletions(&doc1());
    let spans: Vec<Span> = d.iter().cloned().collect();
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0].start(), ca(1).tumbler()); // class 8 first (BTreeMap order)
    assert_eq!(spans[1].start(), vca(1).tumbler()); // then class 9
    // Absent doc: empty.
    assert!(s.deletions(&doc2()).is_empty());
}

#[test]
fn docs_ever_containing_is_a_deterministic_overlap_superset() {
    // §9: not-Separated candidates (Adjacent included — a harmless
    // superset member the present-tense filter, `arranges_any`, removes),
    // distinct keys, Tumbler order.
    let s = place(&M5State::genesis(), &doc2(), 1, vec![run(&ca(1), 2)]);
    let s = place(&s, &doc1(), 1, vec![run(&ca(1), 2)]);
    let cov = SpanSet::singleton(run(&ca(1), 1).iextent());
    assert_eq!(s.docs_ever_containing(&cov), vec![doc1(), doc2()]);
    // Adjacent (touching, no shared position) still lands in the
    // candidate superset.
    let adj = SpanSet::singleton(run(&ca(3), 1).iextent());
    assert_eq!(s.docs_ever_containing(&adj), vec![doc1(), doc2()]);
    // Separated does not.
    let sep = SpanSet::singleton(run(&ca(9), 1).iextent());
    assert!(s.docs_ever_containing(&sep).is_empty());
    // A cross-length cover never faults (classify_spans is gate-free).
    let deep = SpanSet::singleton(subtree_of(a(&[1, 0, 1, 0, 1]).tumbler()));
    assert_eq!(s.docs_ever_containing(&deep), vec![doc1(), doc2()]);
}

#[test]
fn ever_containing_keeps_a_ghost_whose_footprint_is_now_empty() {
    // ASN-0124 FD-GHOST: doc1 places and then deletes what doc2 still
    // holds. The historical answer keeps doc1 (FD-RMONO — R never loses a
    // member); `project` is the present witness that separates them, and
    // the gap between the two answers IS `ghosts`.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 2)]);
    let s = place(&s, &doc2(), 1, vec![run(&ca(1), 2)]);
    let s = s.apply_m5(&M5Rec::ContentRemove {
        doc: doc1(),
        from: n(1),
        width: n(2),
    });
    let cov = SpanSet::singleton(run(&ca(1), 2).iextent());
    assert_eq!(s.docs_ever_containing(&cov), vec![doc1(), doc2()]);
    assert!(s.project(&doc1(), &cov).is_empty()); // the ghost
    assert!(!s.project(&doc2(), &cov).is_empty()); // the live container
}
