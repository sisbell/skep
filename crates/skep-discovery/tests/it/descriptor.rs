//! §3 — the four-set descriptor query: its unit, zero and conjunction over
//! the four slots, the home slot's prefix coverage, the one `sat` every
//! read-out shares, its census against the region family's, and what each
//! shape of it costs, counted: a home slot reads the home's links alone, and
//! a small type class drives ahead of a flooded slot.

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use skep_address::Address;
use skep_arrangement::Vstream;
use skep_discovery::{count_ftt_on, findlinks_ftt_on, window_ftt_on, FourSet, SlotSpec};
use skep_kernel::Kernel;
use skep_links::{enc, Endset, HasLinks, LinkWriter};

#[test]
fn ftt_the_unit_matches_all_the_zero_annihilates_and_slots_conjoin() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

    // (∗,∗,∗,∗) — the whole addressable slice (FL-WILD), address order.
    assert_eq!(reads.findlinks_ftt(&FourSet::any()), vec![la(1), la(2), la2(1)]);
    assert_eq!(reads.count_ftt(&FourSet::any()), 3);

    // Any constrained-empty slot annihilates (FL-EMP) — both the explicit
    // zero and an empty Spans endset, which never reaches M7.
    let q = FourSet {
        to: SlotSpec::Empty,
        ..FourSet::any()
    };
    assert_eq!(reads.findlinks_ftt(&q), vec![]);
    assert_eq!(reads.count_ftt(&q), 0);
    let q = FourSet {
        from: SlotSpec::Spans(Endset::empty()),
        ..FourSet::any()
    };
    assert_eq!(reads.findlinks_ftt(&q), vec![]);

    // One constrained slot.
    let q_from = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    assert_eq!(reads.findlinks_ftt(&q_from), vec![la(1), la2(1)]);
    // Conjunction across slots (AND-of-ORs, M7's combiner).
    let q_both = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        to: SlotSpec::Spans(enc(&[ca(102)])),
        ..FourSet::any()
    };
    assert_eq!(reads.findlinks_ftt(&q_both), vec![la2(1)]);
    assert_eq!(reads.count_ftt(&q_both), 1);

    // Retraction shrinks the active slice: a found link stays found ONLY
    // absent retraction (FL-MON's hypothesis).
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(reads.findlinks_ftt(&q_from), vec![la2(1)]);
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

/// §3 — the conjunction is handed to M7 cheapest constraint first — a TYPE
/// constraint whose class is small moves ahead of the slots written before
/// it, because M7 answers the first by one probe of its coverage index and
/// narrows what it finds with the rest. That order is cost, and no answer
/// shows it. What an answer can show is the one way a reordering could move
/// it: by parting an endset from its slot. A descriptor whose FROM is a
/// content address and whose TYPE is a type address answers the link it would
/// answer unsorted, and its MIRROR — the same two endsets in the other slots —
/// answers a different link, not the same one. A reordering that lost the
/// pairing would make the two agree.
#[test]
fn ftt_orders_its_constraints_without_parting_an_endset_from_its_slot() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let straight = link(&store, &doc1(), &[ca(1)], &[ca(2)]); // from ca(1), typed rel
    let mirror = typed_link(&store, &doc1(), &[rel()], &[ca(2)], &ca(1)); // from rel, typed ca(1)

    // Each type names a class of one link, so the TYPE constraint is the one
    // that moves to the front, ahead of the FROM written before it: the
    // reordering has something to do.
    let snap = k.snapshot();
    for ty in [rel(), ca(1)] {
        assert_eq!(
            snap.world().links().type_hits(&enc([&ty])),
            Some(1),
            "{ty}: a class of one, which drives"
        );
    }

    let content_from = FourSet {
        from: SlotSpec::Spans(enc([&ca(1)])),
        ty: SlotSpec::Spans(rel_ty()),
        ..FourSet::any()
    };
    let type_from = FourSet {
        from: SlotSpec::Spans(rel_ty()),
        ty: SlotSpec::Spans(enc([&ca(1)])),
        ..FourSet::any()
    };
    // Each descriptor names exactly one of the two links, and they are
    // different links: the endsets stayed with the slots they were written in
    // however the list was ordered on the way to M7.
    assert_eq!(reads.findlinks_ftt(&content_from), vec![straight]);
    assert_eq!(reads.findlinks_ftt(&type_from), vec![mirror]);
    assert_eq!(reads.count_ftt(&content_from), 1);
}

/// A world of `flood` links of the suite's relation type homed in doc2, each
/// FROM doc1's position 1, beside what `seed` deposits — the fixture the cost
/// laws read twice, at two floods, so the one thing that differs between the
/// two worlds is the population a read must not pay for.
fn flooded(flood: u32, seed: impl Fn(&LinkWriter<'_, World>)) -> Kernel<World> {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    seed(&store);
    for i in 0..flood {
        link(&store, &doc2(), &[ca(1)], &[ca(1_000 + i)]);
    }
    k
}

/// The heap bytes a read of `k`'s current state asks for, on its second run,
/// so nothing a first call sets up is counted against it.
fn heap_of<T>(k: &Kernel<World>, read: impl Fn(&Kernel<World>) -> T) -> u64 {
    settled_heap_bytes(|| read(k)).1
}

/// §3 — THE HOME SLOT DRIVES, counted (PUB-7.18; #468): a home-constrained
/// descriptor — the home alone, or the home beside a link slot — costs the
/// home's own links and nothing of a passage's flood homed elsewhere. The
/// home with twenty links on position 1 is read beside a thousand links on
/// the same position homed in another document, and the read's heap is the
/// same as beside a hundred: a read that stabbed the position first and
/// dropped the flood by home afterwards, or walked the store, pays for every
/// one of them, which the counts show at once where a clock would not. The
/// enumeration, the count and the window are each held, and the answer is
/// the same twenty links in both worlds.
#[test]
fn a_home_constrained_descriptor_pays_for_the_homes_links_and_not_for_the_passages() {
    const HOMED: u32 = 20;
    let twenty_in_doc1 = |store: &LinkWriter<'_, World>| {
        for i in 0..HOMED {
            link(store, &doc1(), &[ca(1)], &[ca(100 + i)]);
        }
    };
    let (fewer, more) = (flooded(100, twenty_in_doc1), flooded(1_000, twenty_in_doc1));
    let home_only = FourSet {
        home: SlotSpec::Spans(enc([&doc1()])),
        ..FourSet::any()
    };
    let home_and_from = FourSet {
        home: SlotSpec::Spans(enc([&doc1()])),
        from: SlotSpec::Spans(enc([&ca(1)])),
        ..FourSet::any()
    };
    for q in [&home_only, &home_and_from] {
        let expected: Vec<Address> = (1..=HOMED).map(la).collect();
        for k in [&fewer, &more] {
            assert_eq!(Reads(k).findlinks_ftt(q), expected, "the home's twenty, {q:?}");
        }
        for (what, read) in [
            ("findlinks_ftt", &(|k: &Kernel<World>| {
                findlinks_ftt_on(&k.snapshot(), q, &every_home).len()
            }) as &dyn Fn(&Kernel<World>) -> usize),
            ("count_ftt", &|k: &Kernel<World>| count_ftt_on(&k.snapshot(), q, &every_home)),
            ("window_ftt", &|k: &Kernel<World>| {
                window_ftt_on(&k.snapshot(), q, None, 5, &every_home).batch.len()
            }),
        ] {
            assert_eq!(
                heap_of(&more, read),
                heap_of(&fewer, read),
                "{what} over {q:?}: a link homed elsewhere costs the home's read nothing"
            );
        }
    }
    // The control: a descriptor that does not name the home stabs the
    // position and pays for the flood, so the equality above is the home
    // slot's doing and not a read that allocates nothing.
    let from_only = FourSet {
        from: SlotSpec::Spans(enc([&ca(1)])),
        ..FourSet::any()
    };
    let read = |k: &Kernel<World>| findlinks_ftt_on(&k.snapshot(), &from_only, &every_home).len();
    assert!(
        heap_of(&more, read) > heap_of(&fewer, read),
        "the control pays for the flood"
    );
}

/// §3 — THE CHEAPEST CONSTRAINT DRIVES, counted (#650): a descriptor naming
/// a flooded position in `from` and a type of two links in `ty` costs the
/// type's class, not the position's flood. A thousand links of the suite's
/// relation type FROM position 1 sit beside two of a second type FROM the
/// same position; the read for the second type answers the two in both
/// worlds, and its heap beside a thousand is its heap beside a hundred. The
/// same two slots with the flood's own type in `ty` is the control: that
/// class IS the flood, so the read pays for it whichever slot drives.
#[test]
fn a_type_constraint_with_a_small_class_drives_ahead_of_a_flooded_from_slot() {
    let two_of_the_second_type = |store: &LinkWriter<'_, World>| {
        typed_link(store, &doc1(), &[ca(1)], &[ca(101)], &rel2());
        typed_link(store, &doc1(), &[ca(1)], &[ca(102)], &rel2());
    };
    let (fewer, more) = (
        flooded(100, two_of_the_second_type),
        flooded(1_000, two_of_the_second_type),
    );
    let read_with = FourSet {
        from: SlotSpec::Spans(enc([&ca(1)])),
        ty: SlotSpec::Spans(enc([&rel2()])),
        ..FourSet::any()
    };
    for k in [&fewer, &more] {
        assert_eq!(Reads(k).findlinks_ftt(&read_with), vec![la(1), la(2)]);
    }
    let read = |k: &Kernel<World>| findlinks_ftt_on(&k.snapshot(), &read_with, &every_home).len();
    assert_eq!(
        heap_of(&more, read),
        heap_of(&fewer, read),
        "the two-link class drives: the flood from the same position costs nothing"
    );
    let flooded_type = FourSet {
        from: SlotSpec::Spans(enc([&ca(1)])),
        ty: SlotSpec::Spans(rel_ty()),
        ..FourSet::any()
    };
    let read = |k: &Kernel<World>| findlinks_ftt_on(&k.snapshot(), &flooded_type, &every_home).len();
    assert!(
        heap_of(&more, read) > heap_of(&fewer, read),
        "the control: the flood's own type is the flood"
    );
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
    let reads = Reads(&k);
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
    assert_eq!(reads.findlinks_ftt(&of_type(rel_ty())), vec![e1.clone(), e2]);
    assert_eq!(reads.findlinks_ftt(&of_type(sup.clone())), vec![claim.clone()]);
    assert_eq!(reads.count_ftt(&of_type(sup.clone())), 1);
    let from_e1 = |ty: Endset| FourSet {
        from: SlotSpec::Spans(enc([&e1])),
        ty: SlotSpec::Spans(ty),
        ..FourSet::any()
    };
    assert_eq!(reads.findlinks_ftt(&from_e1(sup)), vec![claim]);
    assert_eq!(reads.findlinks_ftt(&from_e1(rel_ty())), vec![]);
}

#[test]
fn ftt_home_filter_is_an_address_projection_applied_lazily() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

    // The home slot is matched against home(a) = document_of — an address
    // projection, not a link slot and not an arrangement test.
    let q_home1 = FourSet {
        home: SlotSpec::Spans(enc(&[doc1()])),
        ..FourSet::any()
    };
    assert_eq!(reads.findlinks_ftt(&q_home1), vec![la(1), la(2)]);
    assert_eq!(reads.count_ftt(&q_home1), 2);
    let q_home2 = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        ..FourSet::any()
    };
    assert_eq!(reads.findlinks_ftt(&q_home2), vec![la2(1)]);

    // home composes conjunctively with slot constraints.
    let q_home2_from = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    assert_eq!(reads.findlinks_ftt(&q_home2_from), vec![la2(1)]);

    // The home slot's zero admits nothing — FL-EMP for a slot that is never
    // carried into M7's conjunction, so the descriptor answers it alone.
    for zero in [SlotSpec::Empty, SlotSpec::Spans(Endset::empty())] {
        let q = FourSet {
            home: zero,
            ..FourSet::any()
        };
        assert_eq!(reads.findlinks_ftt(&q), vec![]);
        assert_eq!(reads.count_ftt(&q), 0);
        assert_eq!(reads.window_ftt(&q, None, 5).batch, vec![]);
    }

    // The home filter is applied lazily during the window walk — before the
    // slice, not after it — so pagination runs over the home-narrowed set
    // with the same cursor mechanism.
    let w1 = reads.window_ftt(&q_home1, None, 1);
    assert_eq!(w1.batch, vec![la(1)]);
    assert!(!w1.exhausted);
    let w2 = reads.window_ftt(&q_home1, w1.next, 5);
    assert_eq!(w2.batch, vec![la(2)]);
    assert!(w2.exhausted);
    // doc2's one link sorts after both of doc1's, so a filter applied to a
    // one-link slice would hand back an empty page here.
    assert_eq!(reads.window_ftt(&q_home2, None, 1).batch, vec![la2(1)]);
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
    let reads = Reads(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

    // The account both documents hang under admits the links homed in each.
    let account = FourSet {
        home: SlotSpec::Spans(enc(&[a(&[1, 0, 1])])),
        ..FourSet::any()
    };
    assert_eq!(reads.findlinks_ftt(&account), vec![la(1), la(2), la2(1)]);
    assert_eq!(reads.count_ftt(&account), 3);

    // And the relation has a direction: an address UNDER doc1 is not a prefix
    // of it, so its coverage names no link's home — a satisfiable request
    // with an empty answer, not the zero.
    let under = FourSet {
        home: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    assert!(!under.is_unsatisfiable(), "the request names something");
    assert_eq!(reads.findlinks_ftt(&under), vec![]);
}

/// §3 — the home slot's coverage reaches a document's VERSION MEMBERS, as
/// `FourSet` states: a member's address extends its document's, so the
/// subtree span `enc` builds for the document covers the member, and a link
/// homed in the member satisfies a home slot naming the document
/// (ASN-0121's `athome`, `home(a) ∈ coverage(H)`). Naming the member admits
/// the member's links alone. The other home tests name private documents,
/// which have no members, so a residence test that read a link's home as its
/// trunk, or matched documents by equality, would pass them all.
#[test]
fn ftt_home_coverage_reaches_a_documents_version_members() {
    let k = published_world();
    let store = LinkWriter::new(&k, &EVERYONE);
    let in_pdoc = link(&store, &pdoc(), &[ca(101)], &[ca(102)]);
    let in_head = link(&store, &phead(), &[ca(101)], &[ca(103)]);
    let reads = Reads(&k);
    let homed_in = |d: &Address| FourSet {
        home: SlotSpec::Spans(enc([d])),
        ..FourSet::any()
    };
    assert_eq!(
        reads.findlinks_ftt(&homed_in(&pdoc())),
        vec![in_pdoc, in_head.clone()],
        "the document's span admits its member's link too"
    );
    assert_eq!(
        reads.findlinks_ftt(&homed_in(&phead())),
        vec![in_head],
        "the member's span admits its own links alone"
    );
}

/// §3 — CN-ENUM: one `sat` consumed by every read-out, so the count, the
/// enumeration and the windowed drain cannot disagree about which links match.
/// The home-constrained descriptors are the load-bearing cases: they are the
/// only ones where the residence post-filter narrows the candidate set, so a
/// read-out that evaluated the candidates instead of `sat` would answer wide
/// here and nowhere else — and a residence post-filter applied after the
/// window's slice would come back with a short page claiming more to come.
///
/// A RETRACTED link, homed in doc1 and naming ca(1), sits in the fixture as
/// one sits in the region family's law: the law is the ACTIVE view's, and a
/// read-out answering over the audit slice — the window is already spelled
/// apart from `sat`, and a size-only shortcut is the count's to take — would
/// answer wide here, where no other test asks the count or the window across a
/// retraction.
#[test]
fn ftt_count_enumeration_and_window_read_out_one_sat() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);
    // … and one RETRACTED link, homed in doc1 and naming ca(1), so it would
    // satisfy every descriptor below but the doc2-homed one and the zero. Its
    // retraction is homed in doc2.
    let retracted = link(&store, &doc1(), &[ca(1)], &[ca(103)]);
    store
        .nullify(SYS, &doc2(), &retracted)
        .expect("nullify succeeds");
    let snap = k.snapshot();
    assert!(
        snap.world().links().readlink(&retracted).is_some()
            && !snap.world().links().is_active(&retracted),
        "retracted, and still resident"
    );

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
        let enumerated = reads.findlinks_ftt(&q);
        assert!(
            !enumerated.contains(&retracted),
            "a nullified link never surfaces: {q:?}"
        );
        assert_eq!(reads.count_ftt(&q), enumerated.len(), "count = |enum| for {q:?}");

        // The same set again, drained through the cursor at every batch size
        // from the clamp at 0 through one past the set, every page held to
        // what a returned window promises.
        for n in 0..=enumerated.len() + 1 {
            assert_eq!(
                drain_window(n, enumerated.len() + 1, |cur| reads.window_ftt(&q, cur, n)),
                enumerated,
                "the window drains sat for {q:?} at n = {n}"
            );
        }
    }

    // `n = 0` is clamped to 1 on this family too (W9 totality): the drains
    // above visit it, and this pins the one link it answers.
    assert_eq!(reads.window_ftt(&FourSet::any(), None, 0).batch, vec![la(1)]);
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
    let reads = Reads(&k);
    link(&store, &doc2(), &[ca(1)], &[ca(101)]);

    // D-ZERO: nothing reaches doc2's region — it arranges nothing.
    assert_eq!(reads.count_v(&doc2(), &[vspan(1, 1, 5)]), Ok(0));
    // CN-ZERO over the same link: the store's census finds it, unreachable or
    // not (CN-STAB — the descriptor family asks no arrangement question).
    let q_home2 = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        ..FourSet::any()
    };
    assert_eq!(reads.count_ftt(&q_home2), 1);
    // And CN-ZERO proper, over a home no link resides in: a store-wide
    // verdict, not present unreachability.
    let q_home_none = FourSet {
        home: SlotSpec::Spans(enc(&[unregistered_doc()])),
        ..FourSet::any()
    };
    assert_eq!(reads.count_ftt(&q_home_none), 0);
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
    let reads = Reads(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let region = [vspan(1, 1, 2)];
    let homed_here = FourSet {
        home: SlotSpec::Spans(enc(&[doc1()])),
        ..FourSet::any()
    };
    assert_eq!(reads.count_v(&doc1(), &region), Ok(1));
    assert_eq!(reads.count_ftt(&homed_here), 1);

    // The link's only witness in doc1 leaves the arrangement. The link is not
    // retracted, and it is still resident.
    Vstream::new(&k)
        .delete(SYS, &doc1(), vp(1, 1), n(1))
        .expect("delete succeeds");
    assert!(k.snapshot().world().links().is_active(&la(1)));

    assert_eq!(reads.count_v(&doc1(), &region), Ok(0)); // present unreachability
    assert_eq!(reads.count_ftt(&homed_here), 1); // existence, unchanged
}
