//! §3 — the four-set descriptor query: its unit, zero and conjunction over
//! the four slots, the home slot's prefix coverage, the one `sat` every
//! read-out shares, and its census against the region family's.

use crate::common;

use common::*;
use skep_arrangement::Vstream;
use skep_discovery::{FourSet, LinkQuery, SlotSpec};
use skep_links::{enc, Endset, HasLinks, LinkWriter};

#[test]
fn ftt_the_unit_matches_all_the_zero_annihilates_and_slots_conjoin() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

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

/// §3 — the conjunction is handed to M7 smallest constraint first, because
/// M7 drives ONE whole-store scan with the first and narrows the survivors
/// with the rest. That reordering must move work and not the answer, and the
/// way it could move the answer is by decoupling an endset from its slot: a
/// descriptor whose big constraint is FROM and small is TO answers the same
/// links as it did unsorted, and its MIRROR — the same two endsets in the
/// other slots — answers different links, not the same ones. A sort that lost
/// the pairing would make the two agree.
#[test]
fn ftt_hands_the_smallest_constraint_first_without_moving_the_answer() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    link(&store, &doc1(), &[ca(1)], &[ca(2)]); // la(1): from ca(1), to ca(2)
    link(&store, &doc1(), &[ca(2)], &[ca(1)]); // la(2): the mirror

    // A many-span constraint and a one-span one, so the sort actually
    // reorders rather than leaving the list as written.
    let wide = enc(&[ca(1), ca(101), ca(102), ca(103), ca(104)]);
    let narrow = enc(&[ca(2)]);
    assert!(wide.len() > narrow.len(), "the sort has something to do");

    let wide_from = FourSet {
        from: SlotSpec::Spans(wide.clone()),
        to: SlotSpec::Spans(narrow.clone()),
        ..FourSet::any()
    };
    let wide_to = FourSet {
        from: SlotSpec::Spans(narrow),
        to: SlotSpec::Spans(wide),
        ..FourSet::any()
    };
    // Each descriptor names exactly one of the two links, and they are
    // different links: the endsets stayed with the slots they were written in
    // however the list was ordered on the way to M7.
    assert_eq!(lq.findlinks_ftt(&wide_from), vec![la(1)]);
    assert_eq!(lq.findlinks_ftt(&wide_to), vec![la(2)]);
    assert_eq!(lq.count_ftt(&wide_from), 1);
}

/// §3 — Θ constrains like the other link slots: a descriptor naming a type
/// answers the links carrying it, alone and conjoined. Every other descriptor
/// here constrains FROM, TO or home, so a constraint list that dropped Θ, or
/// paired it with the wrong slot numeral, would pass them all.
#[test]
fn ftt_the_type_slot_answers_the_links_carrying_the_type() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]); // the suite's relation type
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store
        .assert_sup(SYS, &doc1(), &e1, &e2)
        .expect("assert_sup succeeds");
    let sup = enc(&[ra(4)]); // Supersedes, as the fence test reads it off the store
    let of_type = |ty: Endset| FourSet {
        ty: SlotSpec::Spans(ty),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&of_type(rel_ty())), vec![e1.clone(), e2]);
    assert_eq!(lq.findlinks_ftt(&of_type(sup.clone())), vec![claim.clone()]);
    assert_eq!(lq.count_ftt(&of_type(sup.clone())), 1);
    let from_e1 = |ty: Endset| FourSet {
        from: SlotSpec::Spans(enc([&e1])),
        ty: SlotSpec::Spans(ty),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&from_e1(sup)), vec![claim]);
    assert_eq!(lq.findlinks_ftt(&from_e1(rel_ty())), vec![]);
}

#[test]
fn ftt_home_filter_is_an_address_projection_applied_lazily() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

    // The home slot is matched against home(a) = document_of — an address
    // projection, not a link slot and not an arrangement test.
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

/// §3 — `athome` is PREFIX COVERAGE, not address equality: the constraint's
/// coverage must name `home(a)`, and `enc` builds a subtree span. So an
/// ACCOUNT names every link homed under it — the query M10 passes through
/// from the wire unaltered, and the one a rewrite to equality would silently
/// answer `[]` for. Every other home test here names a document address,
/// where coverage and equality agree.
#[test]
fn ftt_home_is_prefix_coverage_not_address_equality() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

    // The account both documents hang under admits the links homed in each.
    let account = FourSet {
        home: SlotSpec::Spans(enc(&[a(&[1, 0, 1])])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&account), vec![la(1), la(2), la2(1)]);
    assert_eq!(lq.count_ftt(&account), 3);

    // And the relation has a direction: an address UNDER doc1 is not a prefix
    // of it, so its coverage names no link's home — a satisfiable request
    // with an empty answer, not the zero.
    let under = FourSet {
        home: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    assert!(!under.is_unsatisfiable(), "the request names something");
    assert_eq!(lq.findlinks_ftt(&under), vec![]);
}

/// §3 — CN-ENUM: one `sat` consumed by every read-out, so the count, the
/// enumeration and the windowed drain cannot disagree about which links match.
/// The home-constrained descriptors are the load-bearing cases: they are the
/// only ones where the residence post-filter narrows the candidate set, so a
/// read-out that evaluated the candidates instead of `sat` would answer wide
/// here and nowhere else — and a residence post-filter applied after the
/// window's slice would come back with a short page claiming more to come.
#[test]
fn ftt_count_enumeration_and_window_read_out_one_sat() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

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

        // The same set again, drained through the cursor at every batch size
        // from the clamp at 0 through one past the set, every page held to
        // what a returned window promises.
        for n in 0..=enumerated.len() + 1 {
            assert_eq!(
                drain_window(n, enumerated.len() + 1, |cur| lq.window_ftt(&q, cur, n)),
                enumerated,
                "the window drains sat for {q:?} at n = {n}"
            );
        }
    }

    // `n = 0` is clamped to 1 on this family too (W9 totality): the drains
    // above visit it, and this pins the one link it answers.
    assert_eq!(lq.window_ftt(&FourSet::any(), None, 0).batch, vec![la(1)]);
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
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    link(&store, &doc2(), &[ca(1)], &[ca(101)]);

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
        home: SlotSpec::Spans(enc(&[unregistered_doc()])),
        ..FourSet::any()
    };
    assert_eq!(lq.count_ftt(&q_home_none), 0);
    assert!(!q_home_none.is_unsatisfiable()); // the request names something
}

/// §3 — the two families' documented STABILITY, which is a different
/// distinction from the two zeros above: `count_v` is non-monotone
/// (D-NONMONO — an arrangement change alone drops it), while `count_ftt` is
/// monotone absent retraction (CN-MONO — nothing but a nullification shrinks
/// it). One delete, no retraction anywhere, separates them; every other drop
/// in this suite is caused by a nullification, which BOTH families honour.
#[test]
fn the_region_census_drops_when_content_leaves_while_the_descriptor_census_holds() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let region = [vspan(1, 1, 2)];
    let homed_here = FourSet {
        home: SlotSpec::Spans(enc(&[doc1()])),
        ..FourSet::any()
    };
    assert_eq!(lq.count_v(&doc1(), &region), Ok(1));
    assert_eq!(lq.count_ftt(&homed_here), 1);

    // The link's only witness in doc1 leaves the arrangement. The link is not
    // retracted, and it is still resident.
    Vstream::new(&k)
        .delete(SYS, &doc1(), vp(1, 1), n(1))
        .expect("delete succeeds");
    assert!(k.snapshot().world().links().is_active(&la(1)));

    assert_eq!(lq.count_v(&doc1(), &region), Ok(0)); // present unreachability
    assert_eq!(lq.count_ftt(&homed_here), 1); // existence, unchanged
}
