//! M8 contract tests over a real kernel (InMemory), stating what the design
//! and interface assert: the doc-then-region gate order and the defined-empty
//! result, image dedup, disjunctive + active-filtered region discovery, the
//! stateless key-cut windowing (clamp, exhaustion, cursor-survives-orphaning),
//! RETRIEVEENDSETS' identity-withholding whole-endset pinned-order read-out,
//! the FTT unit/zero/conjunction algebra and the home address-projection
//! filter, projection and addressable discoverability, the delete-orphan
//! preview's M5-mirroring preconditions and last-witness report, the flipped
//! lineage probes with the residence gate, the snapshot twins, and — because
//! this file is a crate of its own — the promises M8 makes to a consumer
//! rather than to itself: one named world bound, the standard traits its
//! values carry, and rejection enums that stay exhaustively matchable.

mod common;

use std::collections::HashSet;

use common::*;
use skep_address::{Address, Span};
use skep_arrangement::HasM5;
use skep_discovery::{
    content_vspan, count_ftt_on, count_v_on, window_v_on, DiscoveryWorld, FourSet, LinkQuery,
    OrphanError, OrphanReport, QueryError, SlotSpec, SupClaim, Window, FROM, TO, TYPE,
};
use skep_kernel::Snapshot;
use skep_links::{enc, Endset, LinkWriter, SlotArg, View};

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

    // Region gate: M5's ordinal-level depth-2 V-span shape, restricted to the
    // content subspace — never a silently-clipped different query. The
    // link-subspace span is a shape M5 accepts and M8's added clause refuses …
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(2, 1, 1)]),
        Err(QueryError::BadRegion)
    );
    // … while a non-depth-2 span and an action-point-1 width fail the shape
    // itself, exactly as M5's `is_ordinal_vspan` reads them.
    let deep = skep_address::Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).expect("T12-valid");
    assert!(!skep_arrangement::is_ordinal_vspan(&deep));
    assert_eq!(lq.count_v(&doc1(), &[deep]), Err(QueryError::BadRegion));
    let level_uniform = skep_address::Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-valid");
    assert!(!skep_arrangement::is_ordinal_vspan(&level_uniform));
    assert_eq!(
        lq.count_v(&doc1(), &[level_uniform]),
        Err(QueryError::BadRegion)
    );
    // One bad span anywhere in the region rejects the whole request.
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(1, 1, 1), vspan(2, 1, 1)]),
        Err(QueryError::BadRegion)
    );

    // The published constructor and the gate are two halves of ONE shape:
    // what content_vspan builds the gate accepts, and it declines exactly the
    // two requests that would have been BadRegion — a non-s_C subspace and a
    // zero count.
    let built = content_vspan(&vp(1, 1), &n(1)).expect("s_C, count ≥ 1");
    assert!(lq.count_v(&doc1(), &[built]).is_ok());
    assert_eq!(content_vspan(&vp(2, 1), &n(1)), None);
    assert_eq!(content_vspan(&vp(1, 1), &n(0)), None);

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

    // findlinks_V ∩ addressable: a nullified link never surfaces, even though its
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
    assert_eq!(lq.findlinks_ftt(&FourSet::any()), vec![la(1), la(2), la2(1)]);
    assert_eq!(lq.count_ftt(&FourSet::any()), 3);

    // Any constrained-empty slot annihilates (FL-EMP) — both the explicit
    // zero and an empty Spans endset, which never reaches M7.
    let q = FourSet {
        to: SlotSpec::Empty,
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q), vec![]);
    assert_eq!(lq.count_ftt(&q), 0);
    let q = FourSet {
        from: SlotSpec::Spans(Endset::empty()),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q), vec![]);

    // One constrained slot.
    let q_from = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q_from), vec![la(1), la2(1)]);
    // Conjunction across slots (AND-of-ORs, M7's combiner).
    let q_both = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        to: SlotSpec::Spans(enc(&[ca(102)])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q_both), vec![la2(1)]);
    assert_eq!(lq.count_ftt(&q_both), 1);

    // Retraction shrinks the active slice: a found link stays found ONLY
    // absent retraction (FL-MON's hypothesis).
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(lq.findlinks_ftt(&q_from), vec![la2(1)]);
}

/// §3 — the descriptor answers FL-EMP off its own slots, for all four of
/// them, without asking the store: an `Empty` slot carries no endset to ask
/// the store WITH, so a query built from the slots alone would drop it as
/// though it were the unit.
#[test]
fn the_descriptor_states_its_own_zero() {
    assert!(!FourSet::any().is_unsatisfiable());
    for zero in [SlotSpec::Empty, SlotSpec::Spans(Endset::empty())] {
        for q in [
            FourSet {
                home: zero.clone(),
                ..FourSet::any()
            },
            FourSet {
                from: zero.clone(),
                ..FourSet::any()
            },
            FourSet {
                to: zero.clone(),
                ..FourSet::any()
            },
            FourSet {
                ty: zero.clone(),
                ..FourSet::any()
            },
        ] {
            assert!(q.is_unsatisfiable(), "{q:?} carries the zero");
        }
    }
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
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q_home1), vec![la(1), la(2)]);
    assert_eq!(lq.count_ftt(&q_home1), 2);
    let q_home2 = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q_home2), vec![la2(1)]);

    // home composes conjunctively with slot constraints.
    let q_h2_from = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q_h2_from), vec![la2(1)]);

    // The home slot's zero admits nothing — FL-EMP for a slot that is never
    // carried into M7's conjunction, so the descriptor answers it alone.
    for zero in [SlotSpec::Empty, SlotSpec::Spans(Endset::empty())] {
        let q = FourSet {
            home: zero,
            ..FourSet::any()
        };
        assert_eq!(lq.findlinks_ftt(&q), vec![]);
        assert_eq!(lq.count_ftt(&q), 0);
        assert_eq!(lq.window_ftt(&q, None, 5).batch, vec![]);
    }

    // The home filter is applied lazily during the window walk: pagination
    // over the home-narrowed set with the same cursor mechanism.
    let w1 = lq.window_ftt(&q_home1, None, 1);
    assert_eq!(w1.batch, vec![la(1)]);
    assert!(!w1.exhausted);
    let w2 = lq.window_ftt(&q_home1, w1.next, 5);
    assert_eq!(w2.batch, vec![la(2)]);
    assert!(w2.exhausted);
}

/// §3 — CN-ENUM: one `sat` consumed by every read-out, so the count, the
/// enumeration and the windowed drain cannot disagree about which links match.
/// The home-constrained descriptors are the load-bearing cases: they are the
/// only ones where the residence post-filter narrows the candidate set, so a
/// read-out that evaluated the candidates instead of `sat` would answer wide
/// here and nowhere else.
#[test]
fn ftt_count_enumeration_and_window_read_out_one_sat() {
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

    for q in [
        FourSet::any(),
        FourSet {
            home: SlotSpec::Spans(enc(&[doc1()])),
            ..FourSet::any()
        },
        FourSet {
            home: SlotSpec::Spans(enc(&[doc2()])),
            ..FourSet::any()
        },
        FourSet {
            home: SlotSpec::Spans(enc(&[doc1()])),
            from: SlotSpec::Spans(enc(&[ca(1)])),
            ..FourSet::any()
        },
        FourSet {
            home: SlotSpec::Empty,
            ..FourSet::any()
        },
    ] {
        let enumerated = lq.findlinks_ftt(&q);
        assert_eq!(lq.count_ftt(&q), enumerated.len(), "count = |enum| for {q:?}");

        // The same set again, drained one link at a time through the cursor.
        let mut drained: Vec<_> = Vec::new();
        let mut cur = None;
        loop {
            let w = lq.window_ftt(&q, cur, 1);
            drained.extend(w.batch.iter().cloned());
            cur = w.next;
            if w.exhausted {
                break;
            }
        }
        assert_eq!(drained, enumerated, "the window drains sat for {q:?}");
    }
}

/// §3 — the two zeros ASN-0132 keeps apart: `count_v`'s D-ZERO asserts present
/// unreachability through one document, `count_ftt`'s CN-ZERO a verdict over
/// the whole addressable store. A link homed in a document that arranges
/// nothing shows they are different assertions about one world — the region
/// census says nothing reaches there, the descriptor census counts the link.
#[test]
fn the_region_zero_and_the_descriptor_zero_assert_different_things() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc2(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

    // D-ZERO: nothing reaches doc2's region — it arranges nothing.
    assert_eq!(lq.count_v(&doc2(), &[vspan(1, 1, 5)]), Ok(0));
    // CN-ZERO over the same link: the store's census finds it, unreachable or
    // not (CN-STAB — the descriptor family asks no arrangement question).
    let q_home2 = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        ..FourSet::any()
    };
    assert_eq!(lq.count_ftt(&q_home2), 1);
    // And CN-ZERO proper, over a home no link resides in: a store-wide
    // verdict, not present unreachability.
    let q_home_none = FourSet {
        home: SlotSpec::Spans(enc(&[d7()])),
        ..FourSet::any()
    };
    assert_eq!(lq.count_ftt(&q_home_none), 0);
    assert!(!q_home_none.is_unsatisfiable()); // the request names something
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

    // UNFILTERED — the one read here that is not narrowed to the active view.
    // Nullifying e1 leaves its projection exactly as it was (followlink
    // reports what is RECORDED), while addressably_discoverable_from, which
    // conjoins is_active, flips: the two answer different questions about one
    // link.
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    let retracted = lq.project(&e1, FROM, &doc1()).expect("project");
    assert_eq!(retracted, proj);
    assert!(retracted.denotes(&t(&[1, 2])));
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc1()), Ok(false));
}

#[test]
fn addressably_discoverable_from_is_lp12_and_addressable_over_both_subspaces() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc1()), Ok(true));
    // Registered-but-empty d: nothing is reachable.
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc2()), Ok(false));

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
    assert_eq!(lq.addressably_discoverable_from(&claim, &doc1()), Ok(true));
    // The claim is homed in doc2 but reaches nothing arranged there
    // (assert_sup never seats).
    assert_eq!(lq.addressably_discoverable_from(&claim, &doc2()), Ok(false));

    // LP12 conjoined with addressability: a nullified-but-reachable link is
    // discoverable and not addressable, so it answers Ok(false) — and a
    // nullified link is still a link (it passes the residence gate rather
    // than erring NotALink).
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc1()), Ok(false));

    assert_eq!(
        lq.addressably_discoverable_from(&ca(1), &doc1()),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        lq.addressably_discoverable_from(&e1, &d7()),
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
        Err(OrphanError::DocNotRegistered)
    );
    // Check order mirrors §6: subspace, then width, then the folded bounds.
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(2, 1), &n(0)),
        Err(OrphanError::NotContentSubspace)
    );
    // Width ahead of bounds: an out-of-range p with width 0 is labelled
    // EmptyWidth here where M5's DELETE, checking bounds first, says
    // NotArranged — the same refusal under a different word (§6).
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 0), &n(0)),
        Err(OrphanError::EmptyWidth)
    );
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 0), &n(1)),
        Err(OrphanError::OutOfBounds)
    );
    // OutOfBounds folds M5's NotArranged (start beyond the arranged run) …
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 4), &n(1)),
        Err(OrphanError::OutOfBounds)
    );
    // … and M5's OutOfBounds (range overrun).
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 2), &n(3)),
        Err(OrphanError::OutOfBounds)
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

/// §7 — the lineage read-out is in ascending CLAIM-address order, the same
/// permanent key every enumeration here reads out by: two claims naming one
/// `old` come back ordered, not in whatever order the index handed them over.
#[test]
fn lineage_reads_out_in_claim_address_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let mut made = Vec::new();
    for to in [ca(101), ca(102), ca(103)] {
        let (e, _) = store
            .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![to]), SlotArg::Addrs(vec![ra(10)]))
            .expect("emit succeeds");
        made.push(e);
    }
    // Two successors of one superseded link: two claims, both probed by in().
    let (c1, _) = store
        .assert_sup(SYS, &doc1(), &made[0], &made[1])
        .expect("assert_sup succeeds");
    let (c2, _) = store
        .assert_sup(SYS, &doc1(), &made[0], &made[2])
        .expect("assert_sup succeeds");
    assert!(c1 < c2, "later claims mint later addresses");

    let claims: Vec<Address> = lq
        .in_claims(&made[0], View::Active)
        .into_iter()
        .map(|c| c.claim)
        .collect();
    assert_eq!(claims, vec![c1.clone(), c2.clone()]);
    // out() reads the same order off the TO probe — one claim each here, so
    // the pair is read back through the union of the two probes.
    assert_eq!(
        lq.out_claims(&made[1], View::Active)[0].claim,
        c1
    );
    assert_eq!(
        lq.out_claims(&made[2], View::Active)[0].claim,
        c2
    );
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

// ─────────────────────── the promises to a consumer ───────────────────────

/// The shape a caller composing two M8 reads has to write: ONE bound naming
/// the world, not the four slices behind it. Blanket-implemented, so the
/// assembled test world satisfies it by satisfying the accessors — which is
/// what the call below proves.
fn region_and_home_census<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<(usize, usize), QueryError> {
    let reaching = count_v_on(s, d, region)?;
    let resident = count_ftt_on(
        s,
        &FourSet {
            home: SlotSpec::Spans(enc([d])),
            ..Default::default()
        },
    );
    Ok((reaching, resident))
}

/// One bound names the world M8 reads under, and `Default` is the wildcard
/// base a narrowed descriptor is built from — so a consumer writes the query
/// it means and leaves no slot at something other than the unit by accident.
#[test]
fn one_named_bound_and_the_unit_descriptor_serve_a_composing_caller() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc2(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

    // Both reads off ONE pinned snapshot, through one bound. The two censuses
    // answer different questions about doc1: BOTH links reach its position 1
    // (each from-slot covers ca(1)), and only one is homed there.
    let snap = k.snapshot();
    assert_eq!(
        region_and_home_census(&snap, &doc1(), &[vspan(1, 1, 1)]),
        Ok((2, 1))
    );
    // And about doc2, which arranges nothing yet homes a link — the region
    // zero and the descriptor count, side by side.
    assert_eq!(
        region_and_home_census(&snap, &doc2(), &[vspan(1, 1, 1)]),
        Ok((0, 1))
    );

    // Default IS the unit, at both levels: an unstated slot constrains
    // nothing, and a descriptor built from neither constrains anything.
    assert_eq!(SlotSpec::default(), SlotSpec::Any);
    assert_eq!(FourSet::default(), FourSet::any());
}

/// The values M8 hands back are hashable, so a caller can key on a request
/// and dedup an answer — every field they hold already hashes, and the
/// orphan rule puts the impl out of a consumer's reach.
///
/// Keying is REPRESENTATIONAL: the two spellings of the zero are one query
/// and two keys. A missed hit, never a wrong answer, and the semantic test is
/// `is_unsatisfiable`.
#[test]
fn the_value_surface_is_hashable_and_keys_by_representation() {
    let q_any = FourSet::any();
    let q_from = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    let mut memo: HashSet<FourSet> = HashSet::new();
    assert!(memo.insert(q_any.clone()));
    assert!(memo.insert(q_from.clone()));
    assert!(!memo.insert(q_any.clone())); // an equal descriptor hits
    assert!(memo.contains(&q_from));

    let explicit = FourSet {
        to: SlotSpec::Empty,
        ..FourSet::any()
    };
    let spelled = FourSet {
        to: SlotSpec::Spans(Endset::empty()),
        ..FourSet::any()
    };
    assert!(explicit.is_unsatisfiable() && spelled.is_unsatisfiable()); // one query
    assert!(memo.insert(explicit) && memo.insert(spelled)); // two keys

    // The answer types too: a lineage graph dedups its claims, a window and a
    // report ride in whatever container a caller reaches for.
    let claim = SupClaim {
        claim: la(3),
        old: la(1),
        new: la(2),
        home: doc1(),
        active: true,
    };
    let mut claims: HashSet<SupClaim> = HashSet::new();
    assert!(claims.insert(claim.clone()));
    assert!(!claims.insert(claim));
    let mut windows: HashSet<Window> = HashSet::new();
    assert!(windows.insert(Window {
        batch: vec![la(1)],
        next: Some(la(1)),
        exhausted: true,
    }));
    let mut reports: HashSet<OrphanReport> = HashSet::new();
    assert!(reports.insert(OrphanReport {
        orphaned: vec![la(1)]
    }));
}

/// The handle is a kernel borrow and behaves as one: it prints without asking
/// `W: Debug`, and it copies — a copy binds the same kernel and snapshots
/// afresh, so it answers what the original answers. A consumer holding one in
/// a struct of its own derives over it, which is the wall a missing impl
/// would be.
#[test]
fn the_handle_debugs_and_copies_like_the_borrow_it_is() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let lq = LinkQuery::new(&k);
    assert_eq!(format!("{lq:?}"), "LinkQuery { .. }");

    #[derive(Debug, Clone, Copy)]
    struct Reader<'k> {
        links: LinkQuery<'k, World>,
    }
    let reader = Reader { links: lq }; // lq is Copy — not moved
    assert!(format!("{reader:?}").starts_with("Reader { links: LinkQuery { .. }"));
    assert_eq!(reader.links.count_ftt(&FourSet::any()), 1);
    assert_eq!(lq.count_ftt(&FourSet::any()), 1);
}

/// Both rejection enums are exhaustively matchable from OUTSIDE the crate —
/// this file is a crate of its own, so these matches are the check that they
/// stay so. A consumer's `match` without a catch-all is a completeness proof
/// (M10 must give every refusal a wire code); sealing either enum, or adding
/// a variant, has to fail a build rather than fall into a default arm.
#[test]
fn every_refusal_is_matchable_without_a_catch_all() {
    fn query_word(e: QueryError) -> &'static str {
        match e {
            QueryError::DocNotRegistered => "doc",
            QueryError::NotALink => "link",
            QueryError::BadRegion => "region",
        }
    }
    fn orphan_word(e: OrphanError) -> &'static str {
        match e {
            OrphanError::DocNotRegistered => "doc",
            OrphanError::NotContentSubspace => "subspace",
            OrphanError::EmptyWidth => "width",
            OrphanError::OutOfBounds => "bounds",
        }
    }
    assert_eq!(query_word(QueryError::BadRegion), "region");
    assert_eq!(orphan_word(OrphanError::EmptyWidth), "width");

    // `Display` names the surface that refused, so a relayed refusal says
    // which of the two vocabularies it came from.
    assert!(QueryError::NotALink.to_string().starts_with("query: "));
    assert!(OrphanError::DocNotRegistered
        .to_string()
        .starts_with("delete-orphans: "));
}
