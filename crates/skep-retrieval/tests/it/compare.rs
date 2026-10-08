//! §D COMPARE (ASN-0122): what the report holds — address-equal
//! correspondences, sound and complete under fan-out (X12 R1–R2), in one
//! deterministic presentation (R3) — checked against a per-position oracle.

use skep_address::{Address, Nat, Span};
use skep_arrangement::{HasM5, VPos, VSpec};
use skep_namespace::PrincipalId;
use skep_retrieval::{CompareReport, CorrPair, Delivery, DeliveryItem, Query, RegionSpec};

use crate::common::*;

#[test]
fn compare_reports_address_equal_correspondences_with_per_block_feet() {
    // ASN-0122 X12 R1 (soundness): each foot is computed WITHIN its own
    // block — u1 offsets the P block, u2 the Q block — so both feet resolve
    // to the shared address; slot 1 ⇐ ρ₁, slot 2 ⇐ ρ₂.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 2, 1),
        }],
    )
    .expect("copy commits"); // doc2 = [ca2]
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 1)])],
    ));
    assert_eq!(rep.len(), 1);
    let pair = &rep.as_slice()[0];
    assert_eq!(pair.d1, doc1());
    assert_eq!(pair.u1.subspace, n(1));
    assert_eq!(pair.u1.ordinal, n(2)); // ca2 is offset 1 within doc1's block
    assert_eq!(pair.d2, doc2());
    assert_eq!(pair.u2.subspace, n(1));
    assert_eq!(pair.u2.ordinal, n(1)); // ca2 is offset 0 within doc2's block
    assert_eq!(pair.width, n(1));
    // Swapped operands swap the slots.
    let rep = ok_of(q.compare(
        &[region_spec(doc2(), vec![vspan(1, 1, 1)])],
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
    ));
    assert_eq!(rep.len(), 1);
    let pair = &rep.as_slice()[0];
    assert_eq!(pair.d1, doc2());
    assert_eq!(pair.u1.ordinal, n(1));
    assert_eq!(pair.d2, doc1());
    assert_eq!(pair.u2.ordinal, n(2));
}

#[test]
fn compare_reports_the_full_width_of_each_overlap() {
    // ASN-0122 X10: a correspondence carries the WIDTH of the shared run, and
    // the width is the NARROWER operand's — the half-open clip
    // `hi = min(p_reach, q_reach)`, exercised from each side in turn.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 3),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2, ca3], one run
    let s = k.snapshot();
    let q = Query::new(&s);
    for (w1, w2, want) in [(3u32, 3u32, 3u32), (3, 2, 2), (2, 3, 2)] {
        let rep = ok_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, w1)])],
            &[region_spec(doc2(), vec![vspan(1, 1, w2)])],
        ));
        assert_eq!(rep.len(), 1, "one overlap for widths ({w1}, {w2})");
        let pair = &rep.as_slice()[0];
        assert_eq!(pair.width, n(want), "width of the ({w1}, {w2}) overlap");
        assert_eq!(pair.u1.ordinal, n(1));
        assert_eq!(pair.u2.ordinal, n(1));
    }
}

#[test]
fn compare_takes_each_blocks_v_start_from_the_span_that_named_it() {
    // ASN-0122 X12 R1 soundness rests on the V-RECONSTRUCTION LEMMA: a
    // content span's FIRST bound V-position is `span.start()`, so a block's
    // V-cursor begins there and not at the subspace anchor `[S, 1]`. A window
    // opened MID-document is the only input that can tell the two apart.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 3, 1),
        }],
    )
    .expect("copy commits"); // doc2 = [ca3]
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 2, 2)])], // doc1 positions 2..3
        &[region_spec(doc2(), vec![vspan(1, 1, 1)])],
    ));
    assert_eq!(rep.len(), 1);
    let pair = &rep.as_slice()[0];
    assert_eq!(pair.u1.ordinal, n(3)); // ca3 IS doc1's THIRD position, not its first
    assert_eq!(pair.u2.ordinal, n(1));
    assert_eq!(pair.width, n(1));
}

#[test]
fn compare_presents_pairs_in_lexicographic_d1_u1_d2_u2_order() {
    // ASN-0122 X12 R3: the presentation is the FOUR-component lexicographic
    // key. The operand below is listed in exactly the reverse of the
    // presentation, and the pairs differ in `d1` and in `u1` as well as in
    // the tail, so no proper prefix of the key reproduces the answer.
    let k = mem_kernel();
    three_runs(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[
            region_spec(doc2(), vec![vspan(1, 4, 1), vspan(1, 2, 1)]), // emitted 1st, 2nd
            region_spec(doc1(), vec![vspan(1, 2, 1)]),                 // emitted 3rd
        ],
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
    ));
    // Emission order is (doc2,4), (doc2,2), (doc1,2); the presentation is not.
    let got: Vec<(Address, Nat)> = rep
        .iter()
        .map(|c| (c.d1.clone(), c.u1.ordinal.clone()))
        .collect();
    assert_eq!(got, vec![(doc1(), n(2)), (doc2(), n(2)), (doc2(), n(4))]);
}

#[test]
fn compare_orders_pairs_that_share_a_first_foot_by_their_second() {
    // ASN-0122 X12 R3, on the half of the key X11's strictness clause exists
    // for: under FAN-OUT several pairs — X11's succ-chains, not the I-chains
    // the fixtures name — land on ONE first foot, so pairs that share
    // `(d1, u1)` are separated only by `(d2, u2)` — a presentation keyed
    // on the first foot alone would leave a fanned-out report's order
    // undetermined. Every pair below shares its first foot, so nothing but the
    // TAIL can explain the order.
    //
    // The fixture is what makes each tail component answerable. doc2 holds ca1
    // at V1 and V2 and doc1 holds it at V1, so the doc1-sourced pair TIES the
    // doc2 pair on `u2` and is separated by `d2` alone, while the two doc2
    // pairs tie on `d2` and are separated by `u2` alone. (A fixture where the
    // doc1 pair's `u2` were uniquely smallest could not tell `d2` from `u2`.)
    let k = mem_kernel();
    fanout_doc2(&k); // doc1 = [a, b, c]; doc2 = [ca1][ca1][own "a"]
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 1)])], // ca1 — ONE first foot
        &[
            region_spec(doc2(), vec![vspan(1, 2, 1), vspan(1, 1, 1)]), // emitted 1st, 2nd
            region_spec(doc1(), vec![vspan(1, 1, 1)]),                 // emitted 3rd
        ],
    ));
    assert!(
        rep.iter()
            .all(|c| c.d1 == doc1() && c.u1 == vp(1, 1) && c.width == n(1)),
        "the premise: one shared first foot, so only the tail can order these"
    );
    // Emitted (doc2,2), (doc2,1), (doc1,1) — the exact reverse of the
    // presentation, which is `d2` ascending and then `u2` ascending.
    let got: Vec<(Address, Nat)> = rep
        .iter()
        .map(|c| (c.d2.clone(), c.u2.ordinal.clone()))
        .collect();
    assert_eq!(got, vec![(doc1(), n(1)), (doc2(), n(1)), (doc2(), n(2))]);
}

#[test]
fn compare_confines_every_pair_to_the_two_named_regions() {
    // ASN-0122 X12 R1: pairs are confined to R_Σ(ρ₁) × R_Σ(ρ₂) — the WINDOW
    // is the operand, not the document. An address the two documents share is
    // reported only when BOTH windows name it.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2]
    let s = k.snapshot();
    let q = Query::new(&s);
    // ρ₁ names ca3, which doc2 does not hold at all.
    assert!(ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 3, 1)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ))
    .is_empty());
    // Both documents hold ca1 and ca2, but the two windows name different ones.
    assert!(ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
        &[region_spec(doc2(), vec![vspan(1, 2, 1)])],
    ))
    .is_empty());
    // The control: widen ρ₂ to cover ca1 and the pair appears.
    assert_eq!(
        ok_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
            &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
        ))
        .len(),
        1
    );
}

#[test]
fn compare_clips_an_overrunning_window_to_its_documents_bound_prefix() {
    // ASN-0122's operand region is each span CLIPPED against the current
    // arrangement — the accept-and-intersect RETRIEVEV's R6 makes, and the
    // opposite of SHOWORIGIN's reject-never-clip on the same span. A window
    // of ten over three positions is a window of two, and its pair's width
    // is the run's, not the span's.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 3),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2, ca3]
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 2, 10)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 3)])],
    ));
    assert_eq!(rep.len(), 1);
    let pair = &rep.as_slice()[0];
    assert_eq!(
        (pair.u1.ordinal.clone(), pair.u2.ordinal.clone(), pair.width.clone()),
        (n(2), n(2), n(2))
    );
    // A window opening past the prefix clips to nothing — a success, not a
    // refusal.
    assert!(ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 4, 1)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 3)])],
    ))
    .is_empty());
}

#[test]
fn compare_is_complete_under_fanout() {
    // ASN-0122 X12 R2, over `corr`'s `P × Q` comprehension: an address held
    // in several blocks yields the FULL cross-product — never a lockstep
    // merge.
    let k = mem_kernel();
    fanout_doc2(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // One P block, two Q blocks holding the same address ⇒ 2 pairs,
    // presented in ascending u2 order.
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ));
    assert_eq!(rep.len(), 2);
    assert_eq!(rep.as_slice()[0].u2.ordinal, n(1));
    assert_eq!(rep.as_slice()[1].u2.ordinal, n(2));
}

#[test]
fn compare_detects_internal_sharing_between_disjoint_windows_of_one_document() {
    // ASN-0122 X8: the diagonal is forced, and it is the WHOLE answer only
    // when the window's restriction is injective. doc2 holds ca1 at V1 and
    // V2, so two disjoint windows of doc2 correspond, and doc2 against itself
    // reports the diagonal AND both off-diagonal pairs — which is exactly
    // what a self-comparison shortcut would omit.
    let k = mem_kernel();
    fanout_doc2(&k); // doc2 = [ca1][ca1][own "a"]
    let s = k.snapshot();
    let q = Query::new(&s);
    let feet = |rep: &CompareReport| -> Vec<(Nat, Nat)> {
        rep.iter()
            .map(|c| (c.u1.ordinal.clone(), c.u2.ordinal.clone()))
            .collect()
    };
    let rep = ok_of(q.compare(
        &[region_spec(doc2(), vec![vspan(1, 1, 1)])],
        &[region_spec(doc2(), vec![vspan(1, 2, 1)])],
    ));
    assert_eq!(feet(&rep), vec![(n(1), n(2))]);
    let rep = ok_of(q.compare(
        &[region_spec(doc2(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 3)])],
    ));
    assert_eq!(
        feet(&rep),
        vec![
            (n(1), n(1)),
            (n(1), n(2)),
            (n(2), n(1)),
            (n(2), n(2)),
            (n(3), n(3))
        ]
    );
}

#[test]
fn compare_joins_on_address_equality_never_on_value() {
    // ASN-0122 X1/X2: the join is a relational equi-join on I-ADDRESS, so
    // equal bytes at distinct addresses do NOT correspond — and COMPARE never
    // opens M4 to find out.
    let k = mem_kernel();
    fanout_doc2(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // The fixture's premise, which is what makes the claim below say
    // anything: doc2's third position is its OWN address, and the bytes there
    // are byte-for-byte doc1's ca1.
    assert_eq!(s.world().m5().point(&doc2(), &vp(1, 3)), Some(doc2_ca(1)));
    assert_ne!(doc2_ca(1), ca(1));
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(doc2(), vspan(1, 3, 1)), spec(doc1(), vspan(1, 1, 1))])),
        Delivery(vec![
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"a")),
        ])
    );
    // Equal bytes, distinct addresses — and no pair follows.
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 3, 1)])],
    ));
    assert!(rep.is_empty());
}

#[test]
fn compare_joins_blocks_of_different_address_lengths_without_pairing_across_them() {
    // ASN-0122 X1/X2 at the one input that can break the join two ways at
    // once: a document transcluding from an 8-component base chain AND a
    // 9-component fork chain resolves to blocks whose I-starts have different
    // lengths, and the exhaustive join tests every mixed-length pair. Such a
    // pair shares no chain, so the ordinal arithmetic behind a foot is
    // undefined on it — the overlap guard must reject it BEFORE that
    // arithmetic runs — and addresses of different lengths are never equal,
    // so a reported pair would be a false correspondence. Compared against
    // itself, the document reports its two same-length diagonal pairs and
    // nothing across the lengths. A corpus seed for the fuzz tier: no other
    // COMPARE fixture in this suite mixes address lengths.
    let k = mem_kernel();
    let vs = insert3(&k); // doc1 = [ca1, ca2, ca3]
    deposit3(&k); // pdoc = [pca1, pca2, pca3]
    let (fork, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("fork commits");
    let (start, _) = vs
        .insert(P1, &fork, vp(1, 4), vec![val(b"z")], declared())
        .expect("fork deposit commits");
    assert_eq!(start, vca(1)); // the fork's chain mints LENGTH-9 elements
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[
            VSpec {
                source: doc1(),
                span: vspan(1, 1, 1),
            },
            VSpec {
                source: fork,
                span: vspan(1, 4, 1),
            },
        ],
    )
    .expect("mixed copy commits"); // doc2 = [ca1][vca1]: an 8-component run, then a 9-component one
    let s = k.snapshot();
    let q = Query::new(&s);
    // The fixture's premise: the two positions hold addresses of different
    // lengths, on chains that never meet.
    assert_eq!(s.world().m5().point(&doc2(), &vp(1, 1)), Some(ca(1)));
    assert_eq!(s.world().m5().point(&doc2(), &vp(1, 2)), Some(vca(1)));
    assert_ne!(ca(1).tumbler().len(), vca(1).tumbler().len());
    let rep = ok_of(q.compare(
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ));
    let feet_and_widths: Vec<(Nat, Nat, Nat)> = rep
        .iter()
        .map(|c| (c.u1.ordinal.clone(), c.u2.ordinal.clone(), c.width.clone()))
        .collect();
    assert_eq!(
        feet_and_widths,
        vec![(n(1), n(1), n(1)), (n(2), n(2), n(1))]
    );
    // The same two blocks against the base and the fork by name: each
    // length meets only its own chain.
    assert_eq!(
        ok_of(q.compare(
            &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
            &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        ))
        .len(),
        1
    );
    assert_eq!(
        ok_of(q.compare(
            &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
            &[region_spec(vdoc(), vec![vspan(1, 1, 4)])],
        ))
        .len(),
        1
    );
}

#[test]
fn compare_lists_a_repeated_window_of_one_operand_twice() {
    // ASN-0122: ⟦Γ⟧ is a set-union, so a repeated window within one operand
    // is redundant rather than wrong — it double-covers, and the report lists
    // both overlaps (denotationally conforming, deterministically ordered).
    let k = mem_kernel();
    fanout_doc2(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 1), vspan(1, 1, 1)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 1)])],
    ));
    assert_eq!(rep.len(), 2);
}

#[test]
fn compare_lists_two_pairs_that_share_a_presentation_key_in_emission_order() {
    // Two NESTED windows of ρ₁ resolve to two blocks with ONE V-start, so
    // their pairs share ALL FOUR key components and differ only in `width`,
    // which is not in the key. Both are reported (the report is
    // finer-than-maximal, and `fold_adjacent` is the identity), each carries
    // its own window's width, and the tie is broken by emission order — the
    // wider window was submitted first.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 3),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2, ca3], ONE run
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3), vspan(1, 1, 2)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 3)])],
    ));
    let key = |c: &CorrPair| (c.d1.clone(), c.u1.clone(), c.d2.clone(), c.u2.clone());
    assert_eq!(rep.len(), 2);
    assert_eq!(key(&rep.as_slice()[0]), key(&rep.as_slice()[1]));
    assert_eq!(
        rep.iter().map(|c| c.width.clone()).collect::<Vec<_>>(),
        vec![n(3), n(2)]
    );
}

#[test]
fn compare_succeeds_emptily_when_an_operand_resolves_to_nothing() {
    // ASN-0122 X12: consulting-state degradations are SUCCESSES with nothing
    // to report — an empty spec-set, a well-formed depth-incompatible span
    // that clips to nothing, and a registered-empty region.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert!(ok_of(q.compare(&[], &[])).is_empty());
    // A depth-incompatible span is clipped to NOTHING — not misread as the
    // depth-2 window its first two components spell. doc1's whole content
    // stands on the other side, so a misreading would report a pair.
    assert!(ok_of(q.compare(
        &[region_spec(doc1(), vec![deep_span(1)])],
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
    ))
    .is_empty());
    // The control that makes the line above mean something.
    assert_eq!(
        ok_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
            &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        ))
        .len(),
        1
    );
    // A registered-empty region contributes nothing either — beside a live
    // one.
    assert!(ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ))
    .is_empty());
}

/// The per-position `(doc, subspace, ordinal, I-address)` triples a spec-set
/// resolves to, read straight off M5 — the independent oracle COMPARE's join
/// is checked against, computed without consulting anything M6 does.
///
/// REQUIRES depth-2 ordinal-level spans, which is what the one test that
/// calls it hands over: `get(2)` is the ordinal only at that depth.
fn positions(w: &World, regions: &[RegionSpec]) -> Vec<(Address, Nat, Nat, Address)> {
    let mut out = Vec::new();
    for r in regions {
        for span in &r.spans {
            let subspace = span.start().get(1).expect("depth 2").clone();
            let mut ordinal = span.start().get(2).expect("depth 2").clone();
            let reach = &ordinal + span.width().get(2).expect("ordinal-level");
            while ordinal < reach {
                let p = VPos {
                    subspace: subspace.clone(),
                    ordinal: ordinal.clone(),
                };
                if let Some(addr) = w.m5().point(&r.doc, &p) {
                    out.push((r.doc.clone(), subspace.clone(), ordinal.clone(), addr));
                }
                ordinal += n(1);
            }
        }
    }
    out
}

/// The position pairs a report denotes: a pair of width `w` is `w` consecutive
/// position pairs on both feet (ASN-0122 X10), so this is the same currency as
/// [`positions`] and the two compare directly. Sorted, so two of these compare
/// as MULTISETS and fan-out multiplicity is checked too.
fn position_pairs(rep: &CompareReport) -> Vec<(Address, Nat, Nat, Address, Nat, Nat)> {
    let mut out = Vec::new();
    for c in rep.iter() {
        let mut offset = n(0);
        while offset < c.width {
            out.push((
                c.d1.clone(),
                c.u1.subspace.clone(),
                &c.u1.ordinal + &offset,
                c.d2.clone(),
                c.u2.subspace.clone(),
                &c.u2.ordinal + &offset,
            ));
            offset += n(1);
        }
    }
    out.sort();
    out
}

#[test]
fn compare_reports_exactly_the_address_equal_position_pairs() {
    // ASN-0122 X12 R2 (completeness) and R1 (soundness) — which R2 states
    // jointly give `⟦Γ⟧ = corr` — say the report IS the set of address-equal
    // position pairs of the two regions: a law over the whole space, not four
    // hand-picked counts. The oracle is a per-position hash join computed
    // from M5 alone, so it shares no reasoning with the block join it checks.
    let k = mem_kernel();
    three_runs(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let oracle = |rho1: &[RegionSpec], rho2: &[RegionSpec]| {
        let (p, q) = (positions(s.world(), rho1), positions(s.world(), rho2));
        let mut out = Vec::new();
        for (d1, s1, o1, a1) in &p {
            for (d2, s2, o2, a2) in &q {
                if a1 == a2 {
                    out.push((
                        d1.clone(),
                        s1.clone(),
                        o1.clone(),
                        d2.clone(),
                        s2.clone(),
                        o2.clone(),
                    ));
                }
            }
        }
        out.sort();
        out
    };
    for (rho1, rho2, want_pairs) in [
        // Whole against whole: three position pairs, from a report of two
        // pairs — one candidate block being doc2's own content, on a chain
        // doc1 never touches.
        (
            vec![region_spec(doc2(), vec![vspan(1, 1, 4)])],
            vec![region_spec(doc1(), vec![vspan(1, 1, 3)])],
            3usize,
        ),
        // Windowed: one position pair, from a report whose second candidate
        // block is disjoint.
        (
            vec![region_spec(doc2(), vec![vspan(1, 2, 3)])],
            vec![region_spec(doc1(), vec![vspan(1, 2, 2)])],
            1,
        ),
    ] {
        let rep = ok_of(q.compare(&rho1, &rho2));
        let want = oracle(&rho1, &rho2);
        assert_eq!(want.len(), want_pairs, "the oracle's own size");
        assert_eq!(
            position_pairs(&rep),
            want,
            "report over {rho1:?} × {rho2:?}"
        );
    }
    // The whole small space: every window of doc2 (four positions, so a start
    // of 5 opens past the end) against every window of doc1 (three), on both
    // sides of the operand order and each against ITSELF — the cases no hand
    // picks: a window opening mid-run with a run behind it, one that overruns
    // and clips, one past the prefix that clips to nothing, and a document
    // against itself, where X8's diagonal is forced and, doc2 holding ca1
    // twice, is not the whole answer.
    let windows = |position_count: u32| -> Vec<Span> {
        (1..=position_count + 1)
            .flat_map(|start| (1..=position_count + 1).map(move |width| vspan(1, start, width)))
            .collect()
    };
    let docs = [(doc1(), windows(3)), (doc2(), windows(4))];
    let (mut nonempty, mut fanned) = (0usize, 0usize);
    for (d1, ws1) in &docs {
        for (d2, ws2) in &docs {
            for w1 in ws1 {
                for w2 in ws2 {
                    let rho1 = vec![region_spec(d1.clone(), vec![w1.clone()])];
                    let rho2 = vec![region_spec(d2.clone(), vec![w2.clone()])];
                    let rep = ok_of(q.compare(&rho1, &rho2));
                    nonempty += usize::from(!rep.is_empty());
                    fanned += usize::from(rep.len() >= 2);
                    assert_eq!(
                        position_pairs(&rep),
                        oracle(&rho1, &rho2),
                        "report over {rho1:?} × {rho2:?}"
                    );
                }
            }
        }
    }
    // The grid's own premise: it met shared addresses, and fan-out.
    assert!(
        nonempty > 0 && fanned > 0,
        "the grid exercised a shared address and a fan-out"
    );
}
