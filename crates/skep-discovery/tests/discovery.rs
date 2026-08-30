//! M8 contract tests over a real kernel (InMemory), stating what the design
//! and interface assert: the doc-then-region gate order and the defined-empty
//! result, image dedup, disjunctive + active-filtered region discovery, the
//! stateless key-cut windowing (clamp, exhaustion, cursor-survives-orphaning),
//! RETRIEVEENDSETS' identity-withholding whole-endset pinned-order read-out,
//! the FTT unit/zero/conjunction algebra and the home address-projection
//! filter, projection and the compound discoverability, the delete-orphan
//! preview's M5-mirroring preconditions and last-witness report, the flipped
//! lineage probes with the residence gate, and the snapshot twins.

mod common;

use common::*;
use skep_arrangement::HasM5;
use skep_discovery::{
    count_v_on, window_v_on, FourSet, LinkQuery, QueryError, SlotSpec, SupClaim, FROM, TO, TYPE,
};
use skep_links::{enc, Endset, LinkWriter, SlotArg, View};

fn all_any() -> FourSet {
    FourSet {
        home: SlotSpec::Any,
        from: SlotSpec::Any,
        to: SlotSpec::Any,
        ty: SlotSpec::Any,
    }
}

// ───────────────────── §1 — content-region discovery ─────────────────────

#[test]
fn region_family_gates_doc_then_region_then_defines_empty() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let lq = LinkQuery::new(&k);

    // Unregistered d → DocNotRegistered, even with a bad region: the document
    // gate is the first act, the region gate second.
    assert!(matches!(
        lq.image(&d7(), &[vspan(2, 1, 1)]),
        Err(QueryError::DocNotRegistered)
    ));
    assert_eq!(
        lq.retrieve_endsets(&d7(), &[vspan(1, 1, 1)]),
        Err(QueryError::DocNotRegistered)
    );

    // Region gate: link-subspace, non-depth-2, and non-ordinal-width spans
    // are all BadRegion — never a silently-clipped different query.
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(2, 1, 1)]),
        Err(QueryError::BadRegion)
    );
    let deep = skep_address::Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).expect("T12-valid");
    assert_eq!(lq.count_v(&doc1(), &[deep]), Err(QueryError::BadRegion));
    let level_uniform = skep_address::Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-valid");
    assert_eq!(
        lq.count_v(&doc1(), &[level_uniform]),
        Err(QueryError::BadRegion)
    );
    // One bad span anywhere in the region rejects the whole request.
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(1, 1, 1), vspan(2, 1, 1)]),
        Err(QueryError::BadRegion)
    );

    // Registered-but-empty d → a DEFINED empty result, distinct from
    // DocNotRegistered.
    assert_eq!(lq.findlinks_v(&doc2(), &[vspan(1, 1, 5)]), Ok(vec![]));
    assert_eq!(lq.count_v(&doc2(), &[vspan(1, 1, 5)]), Ok(0));
    let w = lq.window_v(&doc2(), &[vspan(1, 1, 5)], None, 3).expect("window");
    assert_eq!(w.batch, vec![]);
    assert_eq!(w.next, None);
    assert!(w.exhausted);
    assert_eq!(lq.retrieve_endsets(&doc2(), &[vspan(1, 1, 5)]), Ok(vec![]));

    // An empty region trivially passes the gate and yields the empty image.
    assert!(lq.image(&doc1(), &[]).expect("empty region is defined").is_empty());
}

#[test]
fn image_resolves_dedups_and_clips() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let lq = LinkQuery::new(&k);

    // Ordinary V→I resolution.
    assert!(lq.image(&doc1(), &[vspan(1, 1, 2)]).expect("image") == vec![run(&ca(1), 2)]);
    // Exact-equal repeats are deduped at the boundary (Run: Eq).
    assert!(
        lq.image(&doc1(), &[vspan(1, 1, 2), vspan(1, 1, 2)]).expect("image")
            == vec![run(&ca(1), 2)]
    );
    // Overlapping INPUT spans may still yield partially-overlapping runs —
    // the dedup claim is exact-equality only, not an address-disjoint
    // partition.
    assert!(
        lq.image(&doc1(), &[vspan(1, 1, 2), vspan(1, 2, 2)]).expect("image")
            == vec![run(&ca(1), 2), run(&ca(2), 2)]
    );
    // Out-of-range tails are the arrangement intersection (W ∩ dom M(d)).
    assert!(lq.image(&doc1(), &[vspan(1, 2, 99)]).expect("image") == vec![run(&ca(2), 2)]);
}

#[test]
fn findlinks_v_is_disjunctive_and_active_filtered() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);

    // e1 reaches position 1 via FROM (emit encodes from = enc({ca1})).
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(9)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    assert_eq!(e1, la(1));
    // m1 reaches position 2 via FROM, 3 via TO, and 1 via TYPE (makelink
    // resolves V-specs to content extents).
    let (m1, _) = store
        .makelink(
            SYS,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
        )
        .expect("makelink succeeds");
    assert_eq!(m1, la(2));

    // Disjunction: any slot reaching the region surfaces the link.
    assert_eq!(lq.findlinks_v(&doc1(), &[vspan(1, 2, 1)]), Ok(vec![la(2)]));
    assert_eq!(lq.findlinks_v(&doc1(), &[vspan(1, 3, 1)]), Ok(vec![la(2)]));
    // OR across links: position 1 is reached by e1's FROM and m1's TYPE.
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(1, 1, 1)]),
        Ok(vec![la(1), la(2)])
    );
    assert_eq!(lq.count_v(&doc1(), &[vspan(1, 1, 1)]), Ok(2));
    // Result-as-set: a link touching the region through several slots is
    // found once.
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(1, 1, 3)]),
        Ok(vec![la(1), la(2)])
    );

    // foundation ∩ active: a nullified link never surfaces, even though its
    // coverage still reaches the region. (Homed in doc2 so the retraction
    // tuple's own enc({doc2}) from-fill stays off doc1's content.)
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(lq.findlinks_v(&doc1(), &[vspan(1, 1, 1)]), Ok(vec![la(2)]));
    assert_eq!(lq.count_v(&doc1(), &[vspan(1, 1, 1)]), Ok(1));
}

// ───────────────────────── §2 — windowed enumeration ─────────────────────────

#[test]
fn window_v_pages_by_key_cut_and_survives_orphaning() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    for to in [ca(101), ca(102), ca(103)] {
        store
            .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![to]), SlotArg::Addrs(vec![ra(10)]))
            .expect("emit succeeds");
    }
    let region = [vspan(1, 1, 1)];

    // Ascending address order; next = ≺-max of the batch; full batch ⇒ not
    // exhausted.
    let w1 = lq.window_v(&doc1(), &region, None, 2).expect("window");
    assert_eq!(w1.batch, vec![la(1), la(2)]);
    assert_eq!(w1.next, Some(la(2)));
    assert!(!w1.exhausted);
    // Resume strictly past the cursor; short batch ⇒ exhausted (W9).
    let w2 = lq.window_v(&doc1(), &region, w1.next, 2).expect("window");
    assert_eq!(w2.batch, vec![la(3)]);
    assert_eq!(w2.next, Some(la(3)));
    assert!(w2.exhausted);
    // Past the end: empty batch, cursor unchanged, still exhausted.
    let w3 = lq.window_v(&doc1(), &region, w2.next, 2).expect("window");
    assert_eq!(w3.batch, vec![]);
    assert_eq!(w3.next, Some(la(3)));
    assert!(w3.exhausted);

    // n = 0 is clamped to 1 (total API) — never a false non-terminal.
    let w0 = lq.window_v(&doc1(), &region, None, 0).expect("window");
    assert_eq!(w0.batch, vec![la(1)]);
    assert!(!w0.exhausted);

    // Cursor survives orphaning (W8): la(2) leaves the matched set under
    // nullification, but the key-cut resume needs no lookup of it.
    store.nullify(SYS, &doc2(), &la(2)).expect("nullify succeeds");
    let w4 = lq.window_v(&doc1(), &region, Some(la(2)), 5).expect("window");
    assert_eq!(w4.batch, vec![la(3)]);
    assert!(w4.exhausted);
}

// ───────────────────────── §4 — RETRIEVEENDSETS ─────────────────────────

#[test]
fn retrieve_endsets_withholds_identity_whole_endsets_pinned_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    // Two distinct links with VALUE-IDENTICAL from-endsets (dedup collapse),
    // plus one makelink whose from spans all three positions.
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(
            SYS,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 3)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
        )
        .expect("makelink succeeds");
    let whole = Endset::from_spans([run(&ca(1), 3).iextent()]);

    // A query touching only position 2 surfaces the WHOLE stored endset,
    // never a clip (RE-CLIP/RE-WHOLE); abutting endsets (the emits' enc({ca1})
    // at position 1, the makelink's TO at 3 and TYPE at 1) are Adjacent to
    // the image — not matches.
    assert_eq!(
        lq.retrieve_endsets(&doc1(), &[vspan(1, 2, 1)]),
        Ok(vec![(FROM, whole.clone())])
    );

    // The wide query: identity withheld — the two emits collapse to ONE
    // (FROM, enc({ca1})) pair (RE-UNIT) — and the output order is pinned:
    // slot, then lexicographic span-sequence.
    assert_eq!(
        lq.retrieve_endsets(&doc1(), &[vspan(1, 1, 3)]),
        Ok(vec![
            (FROM, enc(&[ca(1)])),
            (FROM, whole),
            (TO, Endset::from_spans([run(&ca(3), 1).iextent()])),
            (TYPE, Endset::from_spans([run(&ca(1), 1).iextent()])),
        ])
    );
}

// ─────────────────── §3 — four-set descriptor query ───────────────────

#[test]
fn ftt_wildcard_unit_empty_zero_and_conjunction() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc2(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

    // (∗,∗,∗,∗) — the whole addressable slice (FL-WILD), address order.
    assert_eq!(lq.findlinks_ftt(&all_any()), vec![la(1), la(2), la2(1)]);
    assert_eq!(lq.count_ftt(&all_any()), 3);

    // Any constrained-empty slot annihilates (FL-EMP) — both the explicit
    // zero and an empty Spans endset, which never reaches M7.
    let q = FourSet {
        to: SlotSpec::Empty,
        ..all_any()
    };
    assert_eq!(lq.findlinks_ftt(&q), vec![]);
    assert_eq!(lq.count_ftt(&q), 0);
    let q = FourSet {
        from: SlotSpec::Spans(Endset::empty()),
        ..all_any()
    };
    assert_eq!(lq.findlinks_ftt(&q), vec![]);

    // One constrained slot.
    let q_from = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..all_any()
    };
    assert_eq!(lq.findlinks_ftt(&q_from), vec![la(1), la2(1)]);
    // Conjunction across slots (AND-of-ORs, M7's combiner).
    let q_both = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        to: SlotSpec::Spans(enc(&[ca(102)])),
        ..all_any()
    };
    assert_eq!(lq.findlinks_ftt(&q_both), vec![la2(1)]);
    assert_eq!(lq.count_ftt(&q_both), 1);

    // Retraction shrinks the active slice: a found link stays found ONLY
    // absent retraction (FL-MON's hypothesis).
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(lq.findlinks_ftt(&q_from), vec![la2(1)]);
}

#[test]
fn ftt_home_filter_is_an_address_projection_applied_lazily() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc2(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

    // home is matched against home(a) = document_of — an address projection,
    // not a slot and not an arrangement test.
    let q_home1 = FourSet {
        home: SlotSpec::Spans(enc(&[doc1()])),
        ..all_any()
    };
    assert_eq!(lq.findlinks_ftt(&q_home1), vec![la(1), la(2)]);
    assert_eq!(lq.count_ftt(&q_home1), 2);
    let q_home2 = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        ..all_any()
    };
    assert_eq!(lq.findlinks_ftt(&q_home2), vec![la2(1)]);

    // home composes conjunctively with slot constraints.
    let q_h2_from = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..all_any()
    };
    assert_eq!(lq.findlinks_ftt(&q_h2_from), vec![la2(1)]);

    // The home filter is applied lazily during the window walk: pagination
    // over the home-narrowed set with the same cursor mechanism.
    let w1 = lq.window_ftt(&q_home1, None, 1);
    assert_eq!(w1.batch, vec![la(1)]);
    assert!(!w1.exhausted);
    let w2 = lq.window_ftt(&q_home1, w1.next, 5);
    assert_eq!(w2.batch, vec![la(2)]);
    assert!(w2.exhausted);
}

// ─────────────── §5 — projection & discoverability ───────────────

#[test]
fn project_is_content_subspace_i_to_v_with_conflated_notalink() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

    // FROM covers ca(2) ⇒ exactly V-position [s_C, 2] of doc1.
    let proj = lq.project(&e1, FROM, &doc1()).expect("project");
    assert!(proj.denotes(&t(&[1, 2])));
    assert!(!proj.denotes(&t(&[1, 1])));
    assert!(!proj.denotes(&t(&[1, 3])));

    // A slot whose coverage lands nowhere in d's content projects ∅ (TO is a
    // ghost position; TYPE lives in the reserved subspace).
    assert!(lq.project(&e1, TO, &doc1()).expect("project").is_empty());
    assert!(lq.project(&e1, TYPE, &doc1()).expect("project").is_empty());

    // NotALink covers BOTH a non-link `a` AND an out-of-range slot.
    assert_eq!(lq.project(&ca(1), FROM, &doc1()), Err(QueryError::NotALink));
    assert_eq!(lq.project(&e1, 4, &doc1()), Err(QueryError::NotALink));
    // The doc gate comes first.
    assert_eq!(
        lq.project(&e1, FROM, &d7()),
        Err(QueryError::DocNotRegistered)
    );
}

#[test]
fn discoverable_from_is_reachable_and_active_over_both_subspaces() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    assert_eq!(lq.discoverable_from(&e1, &doc1()), Ok(true));
    // Registered-but-empty d: nothing is reachable.
    assert_eq!(lq.discoverable_from(&e1, &doc2()), Ok(false));

    // The LINK-subspace half of LP12: a supersession claim's slots cover only
    // link addresses, which are seated in doc1's link runs by makelink.
    let (m1, _) = store
        .makelink(
            SYS,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
        )
        .expect("makelink succeeds");
    let (m2, _) = store
        .makelink(
            SYS,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
        )
        .expect("makelink succeeds");
    let (claim, _) = store.assert_sup(SYS, &doc2(), &m1, &m2).expect("assert_sup succeeds");
    assert_eq!(lq.discoverable_from(&claim, &doc1()), Ok(true));
    // The claim is homed in doc2 but reaches nothing arranged there
    // (assert_sup never seats).
    assert_eq!(lq.discoverable_from(&claim, &doc2()), Ok(false));

    // Compound "reachable AND active", NOT pure LP12: nullified-but-reachable
    // answers Ok(false) — and a nullified link is still a link (it passes the
    // residence gate rather than erring NotALink).
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(lq.discoverable_from(&e1, &doc1()), Ok(false));

    assert_eq!(
        lq.discoverable_from(&ca(1), &doc1()),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        lq.discoverable_from(&e1, &d7()),
        Err(QueryError::DocNotRegistered)
    );
}

// ─────────────────── §6 — pre-edit link-survival ───────────────────

#[test]
fn delete_orphans_mirrors_delete_preconditions() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let lq = LinkQuery::new(&k);

    assert_eq!(
        lq.delete_orphans(&d7(), &vp(1, 1), &n(1)),
        Err(QueryError::DocNotRegistered)
    );
    // Check order mirrors §6: subspace, then width, then the folded bounds.
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(2, 1), &n(0)),
        Err(QueryError::NotContentSubspace)
    );
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 0), &n(0)),
        Err(QueryError::EmptyWidth)
    );
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 0), &n(1)),
        Err(QueryError::OutOfBounds)
    );
    // OutOfBounds folds M5's NotArranged (start beyond the arranged run) …
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 4), &n(1)),
        Err(QueryError::OutOfBounds)
    );
    // … and M5's OutOfBounds (range overrun).
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 2), &n(3)),
        Err(QueryError::OutOfBounds)
    );
    // Boundary acceptance: the last position, and the whole range.
    assert!(lq.delete_orphans(&doc1(), &vp(1, 3), &n(1)).is_ok());
    assert!(lq.delete_orphans(&doc1(), &vp(1, 1), &n(3)).is_ok());
}

#[test]
fn delete_orphans_reports_active_last_witness_losses() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    // link_a witnesses positions 1 (FROM) and 2 (TO); link_b only 3.
    let (_link_a, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let (link_b, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(3)]), SlotArg::Addrs(vec![ca(3)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

    // Deleting position 3 drops link_b's last witness in d.
    let r = lq.delete_orphans(&doc1(), &vp(1, 3), &n(1)).expect("preview");
    assert_eq!(r.orphaned, vec![la(2)]);
    // Deleting position 1 leaves link_a witnessed at position 2 — no orphan.
    let r = lq.delete_orphans(&doc1(), &vp(1, 1), &n(1)).expect("preview");
    assert_eq!(r.orphaned, vec![]);
    // Deleting everything orphans both (no retained content, no link runs).
    let r = lq.delete_orphans(&doc1(), &vp(1, 1), &n(3)).expect("preview");
    assert_eq!(r.orphaned, vec![la(1), la(2)]);

    // Orphans are reported over the ACTIVE view: a nullified link that loses
    // its last witness is NOT reported (divergence from ASN-0117's D(d,Σ)).
    store.nullify(SYS, &doc2(), &link_b).expect("nullify succeeds");
    let r = lq.delete_orphans(&doc1(), &vp(1, 3), &n(1)).expect("preview");
    assert_eq!(r.orphaned, vec![]);

    // The preview is a pure what-if — the arrangement is untouched.
    assert_eq!(k.snapshot().world().m5().content_count(&doc1()), n(3));
}

// ─────────────── §7 — archival supersession lineage ───────────────

#[test]
fn lineage_probes_flipped_slots_with_residence_gate() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let (e2, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let (claim, _) = store.assert_sup(SYS, &doc1(), &e1, &e2).expect("assert_sup succeeds");

    let expected = SupClaim {
        claim: claim.clone(),
        old: e1.clone(),
        new: e2.clone(),
        home: doc1(),
        active: true,
    };
    // Flipped storage: in(y) = old probes FROM; out(x) = new probes TO.
    assert_eq!(lq.in_claims(&e1, View::Active), vec![expected.clone()]);
    assert_eq!(lq.out_claims(&e2, View::Active), vec![expected.clone()]);
    assert_eq!(lq.in_claims(&e2, View::Active), vec![]);
    assert_eq!(lq.out_claims(&e1, View::Active), vec![]);
    // Default behaves as Active (M7's §G primitives coerce it).
    assert_eq!(lq.in_claims(&e1, View::Default), vec![expected]);

    // Residence gate: a non-link key returns [] — without it, doc1's prefix
    // coverage would over-match the claim (whose endpoints live under doc1).
    assert_eq!(lq.in_claims(&doc1(), View::Active), vec![]);
    assert_eq!(lq.in_claims(&ca(1), View::Active), vec![]);

    // Nullifying the claim removes it from the operative graph but keeps it
    // in the audit history, with its own activity disclosed honestly.
    store.nullify(SYS, &doc2(), &claim).expect("nullify succeeds");
    assert_eq!(lq.in_claims(&e1, View::Active), vec![]);
    let audit = lq.in_claims(&e1, View::Audit);
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].claim, claim);
    assert!(!audit[0].active);
}

// ───────────────────────── snapshot twins ─────────────────────────

#[test]
fn snapshot_twins_read_one_pinned_state() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let region = [vspan(1, 1, 1)];

    // Pin one snapshot, then write past it: the twins keep answering off the
    // pinned root (a count and its window off ONE consistent state), while
    // the handle's fresh snapshot sees the new link.
    let snap = k.snapshot();
    assert_eq!(count_v_on(&snap, &doc1(), &region), Ok(1));
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    assert_eq!(count_v_on(&snap, &doc1(), &region), Ok(1));
    let w = window_v_on(&snap, &doc1(), &region, None, 10).expect("window");
    assert_eq!(w.batch, vec![la(1)]);
    assert_eq!(lq.count_v(&doc1(), &region), Ok(2));
}
