//! The §G discovery primitives and FOLLOWLINK over a real kernel (InMemory):
//! `stab` and `match_links` admitting each of the three overlap relations
//! against the one they refuse, the per-span disjunction on both sides of that
//! test, the AND-combiner's agreement with its own conjuncts over every subset
//! of a constraint pool in both views, the three primitives' `Default → Active`
//! coercion, `stab`'s empty-query floor and its absent-slot rule, the home
//! ranges against a scan of the store filtered by each key's home — and what
//! they cost, counted — the type-slot count against the stab it predicts, the
//! typed stab against the stab cut to the slice, and the verbatim order
//! FOLLOWLINK folds.

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use im::OrdSet;
use skep_address::{document_of, Address, Span, SpanSet};
use skep_arrangement::Vstream;
use skep_kernel::Kernel;
use skep_links::{
    enc, Caller, Endset, HasLinks, Link, Pattern, SlotArg, Tuple, View, FROM, TO, TYPE,
};
use skep_namespace::PrincipalId;

#[test]
fn stab_and_match_links_match_overlap_but_never_adjacency() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    // from covers [ca1, ca3); to and ty cover [ca3, ca4).
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 2)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
        )
        .expect("makelink");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        // Overlap = ProperOverlap | Containment | Equal.
        assert!(links.stab(FROM, &enc(&[ca(1)]), View::Audit).contains(&l));
        assert!(links.stab(FROM, &enc(&[ca(2)]), View::Audit).contains(&l));
        // NOT Adjacent: subtree(ca3) abuts [ca1, ca3) and must not match
        // FROM — but does match TO.
        assert!(!links.stab(FROM, &enc(&[ca(3)]), View::Audit).contains(&l));
        assert!(links.stab(TO, &enc(&[ca(3)]), View::Audit).contains(&l));
        // ProperOverlap, the third admitted relation and the one REGION
        // queries produce: this query starts inside [ca1, ca3) and reaches
        // past it, so neither span contains the other. Every other query in
        // the suite is unit-depth, which against a same-length extent can
        // only be Containment, Equal, Adjacent or Separated.
        let extent = |lo, hi| Endset::from_spans([iext(lo, hi)]);
        assert!(links.stab(FROM, &extent(2, 5), View::Audit).contains(&l));
        // The control, so the hit above is the overlap arm and not a query
        // that matches everything: a Separated extent misses.
        assert!(!links.stab(FROM, &extent(5, 7), View::Audit).contains(&l));
        // AND-combiner over constrained slots only; empty constraints ⇒ the
        // whole slice.
        assert!(links
            .match_links(&[(FROM, &enc(&[ca(2)])), (TO, &enc(&[ca(3)]))], View::Audit)
            .contains(&l));
        assert!(!links
            .match_links(&[(FROM, &enc(&[ca(2)])), (TO, &enc(&[ca(2)]))], View::Audit)
            .contains(&l));
        assert!(links.match_links(&[], View::Audit).contains(&l));
        // The content type is queryable by its coverage: ty resolved to the
        // single address ca(3), so its class is Addrs({ca3}).
        assert!(links.type_slice(&enc(&[ca(3)]), View::Audit).contains(&l));
    }
    // Active view filters nullified results.
    w.nullify(P1, &doc1(), &l).expect("nullify the link");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(!links.stab(FROM, &enc(&[ca(1)]), View::Active).contains(&l));
    assert!(links.stab(FROM, &enc(&[ca(1)]), View::Audit).contains(&l));
    assert!(!links.match_links(&[], View::Active).contains(&l));
}

#[test]
fn the_overlap_test_is_a_disjunction_on_both_sides() {
    // Overlap is "SOME span of the query overlaps SOME span of the slot" — two
    // disjunctions, and every other §G query in the suite is exactly one span,
    // which makes the query side indistinguishable from a conjunction. Neither
    // side is degenerate in production: M8 lifts a fragmented region's I-runs
    // into a multi-span query `Endset` for `stab`, and a MAKELINK slot carries
    // one span per fragment.
    let k = kernel();
    let w = writer(&k);
    // A two-span slot, with a gap between the spans so every pair below is
    // plainly Separated rather than Adjacent (which the overlap test refuses
    // for its own reasons, tested next door).
    let l = open_deposit(&w, &[ca(1), ca(5)], &[], &[unregistered_ta(10)]);
    let snap = k.snapshot();
    let links = snap.world().links();

    // SLOT side: each span matches on its own — the second as surely as the
    // first, which a first-span-only read would miss.
    assert!(links.stab(FROM, &enc(&[ca(1)]), View::Audit).contains(&l));
    assert!(
        links.stab(FROM, &enc(&[ca(5)]), View::Audit).contains(&l),
        "the slot's SECOND span matches too"
    );
    assert!(
        !links.stab(FROM, &enc(&[ca(3)]), View::Audit).contains(&l),
        "and an address between the two spans matches neither"
    );

    // QUERY side: one span of the query suffices — a conjunction here would
    // empty every fragmented-region query M8 builds.
    assert!(
        links.stab(FROM, &enc(&[ca(3), ca(5)]), View::Audit).contains(&l),
        "one span of a two-span query suffices"
    );
    assert!(
        !links.stab(FROM, &enc(&[ca(3), ca(8)]), View::Audit).contains(&l),
        "and no span of it matching is a miss"
    );

    // The AND-combiner's NARROWING branch reads the same predicate, so the
    // multi-span query must survive it as the second constraint — the branch
    // `stab` never exercises.
    let ty_query = unregistered_ty(10);
    let from_query = enc(&[ca(3), ca(5)]);
    assert!(links
        .match_links(&[(TYPE, &ty_query), (FROM, &from_query)], View::Audit)
        .contains(&l));
}

#[test]
fn match_links_narrows_to_the_same_set_its_conjuncts_intersect() {
    // The AND is a conjunction, so narrowing the accumulator by a slot's own
    // overlap predicate and intersecting whole-store `stab` results are the
    // same set — over every subset of the constraint pool, in both views,
    // with a nullified link present so the Active/Audit split is exercised.
    let k = kernel();
    let w = writer(&k);
    let l1 = open_deposit(&w, &[ca(1)], &[ca(2)], &[ca(7)]);
    let l2 = open_deposit(&w, &[ca(1)], &[ca(4)], &[ca(7)]);
    let l3 = open_deposit(&w, &[ca(5)], &[ca(2)], &[ca(8)]);
    let l4 = open_deposit(&w, &[ca(1), ca(5)], &[ca(2), ca(4)], &[ca(7)]);
    w.nullify(P1, &doc1(), &l3).expect("nullify one");

    let pool = [
        (FROM, enc(&[ca(1)])),
        (TO, enc(&[ca(2)])),
        (TYPE, enc(&[ca(7)])),
    ];
    let snap = k.snapshot();
    let links = snap.world().links();
    for view in [View::Audit, View::Active] {
        for mask in 0u8..8 {
            let constraints: Vec<(usize, &Endset)> = (0..pool.len())
                .filter(|i| mask & (1u8 << i) != 0)
                .map(|i| (pool[i].0, &pool[i].1))
                .collect();
            let got = links.match_links(&constraints, view);
            if constraints.is_empty() {
                continue; // the unconstrained branch has no conjuncts to agree with
            }
            let want = constraints
                .iter()
                .map(|&(slot, query)| links.stab(slot, query, view))
                .reduce(|acc, s| acc.iter().filter(|t| s.contains(*t)).cloned().collect())
                .expect("nonempty");
            assert_eq!(got, want, "{view:?} constraints {mask:#05b}");
        }
    }
    // ...and the sets are not all equal, so the agreement above is not
    // vacuous: the three-slot AND admits l1 and l4 only, and Active drops
    // the nullified link from the one-slot answer.
    let every: Vec<(usize, &Endset)> = pool.iter().map(|(slot, query)| (*slot, query)).collect();
    let matched = links.match_links(&every, View::Audit);
    assert!(matched.contains(&l1) && matched.contains(&l4));
    assert!(!matched.contains(&l2) && !matched.contains(&l3));
    let to_query = enc(&[ca(2)]);
    let to_only = [(TO, &to_query)];
    assert!(links.match_links(&to_only, View::Audit).contains(&l3));
    assert!(!links.match_links(&to_only, View::Active).contains(&l3));
}

#[test]
fn the_discovery_primitives_read_default_as_active() {
    // `View::Default` is undefined for a raw index probe, so all three §G
    // primitives coerce it to `Active` — which M8 depends on, `View`'s own
    // `Default` impl being `Default`. An uncoerced view falls through to the
    // Audit branch and a nullified link reappears in a discovery result.
    let k = kernel();
    let w = writer(&k);
    let (kept, _) = w
        .emit(P1, &doc1(), &pred_stable_ty(), &ca(1), &[])
        .expect("kept");
    let (gone, _) = w
        .emit(P1, &doc1(), &pred_stable_ty(), &ca(3), &[])
        .expect("gone");
    w.nullify(P1, &doc1(), &gone).expect("nullify one");
    let snap = k.snapshot();
    let links = snap.world().links();
    // Both links share a TYPE slot, so one query reaches both.
    let query = pred_stable_ty();
    assert!(
        links.stab(TYPE, &query, View::Audit).contains(&gone),
        "the Audit answer is not vacuous"
    );
    assert!(links.stab(TYPE, &query, View::Default).contains(&kept));
    assert_eq!(
        links.stab(TYPE, &query, View::Default),
        links.stab(TYPE, &query, View::Active)
    );
    assert!(!links.stab(TYPE, &query, View::Default).contains(&gone));
    let constraints = [(TYPE, &query)];
    assert_eq!(
        links.match_links(&constraints, View::Default),
        links.match_links(&constraints, View::Active)
    );
    assert!(!links.match_links(&constraints, View::Default).contains(&gone));
    // The unconstrained branch coerces on its own — the constrained one hands
    // its view to `stab`, which would coerce for it.
    assert!(links.match_links(&[], View::Audit).contains(&gone));
    assert!(!links.match_links(&[], View::Default).contains(&gone));
    assert_eq!(
        links.match_links(&[], View::Default),
        links.match_links(&[], View::Active)
    );
    assert!(links.type_slice(&pred_stable_ty(), View::Audit).contains(&gone));
    assert_eq!(
        links.type_slice(&pred_stable_ty(), View::Default),
        links.type_slice(&pred_stable_ty(), View::Active)
    );
    assert!(!links.type_slice(&pred_stable_ty(), View::Default).contains(&gone));
}

#[test]
fn stab_with_an_empty_query_matches_nothing() {
    // The premise of `match_links`' caller contract: an unconstrained slot is
    // OMITTED, never passed as ⟨⟩, because `stab(slot, ⟨⟩, ·) = ∅` would
    // empty the AND.
    let k = kernel();
    let w = writer(&k);
    w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("a link to miss");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.stab(FROM, &Endset::empty(), View::Audit).is_empty());
    assert!(
        !links.match_links(&[], View::Audit).is_empty(),
        "omitting the slot is the contract, and the store is not empty"
    );
    assert!(
        links
            .match_links(&[(FROM, &Endset::empty())], View::Audit)
            .is_empty(),
        "passing ⟨⟩ is not"
    );
}

#[test]
fn stab_matches_nothing_at_a_slot_the_link_does_not_have() {
    // "Absent slot ⇒ no match" — never probed, because the store holds only
    // arity-3 links and every call in the suite passes 1, 2 or 3. The
    // 1-based convention makes slot 0 absent too, so it must not read as
    // slot 1.
    let k = kernel();
    let w = writer(&k);
    let (l, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("a link to miss");
    let snap = k.snapshot();
    let links = snap.world().links();
    let query = enc(&[ca(1)]);
    // The control: this query DOES match at the slot the link has.
    assert!(links.stab(FROM, &query, View::Audit).contains(&l));
    assert!(
        links.stab(4, &query, View::Audit).is_empty(),
        "past the arity"
    );
    assert!(
        links.stab(0, &query, View::Audit).is_empty(),
        "below the 1-based floor — never slot 1"
    );
}

/// A system-caller deposit into `home` of one link FROM `from` TO `to`, typed
/// `ty` — the way the home-range fixtures populate homes the suite's owner
/// does not own: the sibling's document and a version member of it.
fn deposit_in(k: &Kernel<World>, home: &Address, from: &[Address], to: &[Address], ty: &Address) -> Address {
    writer(k)
        .makelink(
            Caller::System,
            home,
            SlotArg::Addrs(from.to_vec()),
            SlotArg::Addrs(to.to_vec()),
            SlotArg::Addrs(vec![ty.clone()]),
        )
        .expect("a system deposit into a registered home")
        .0
}

/// The home of a key of the store, as the oracle reads it.
fn home_of(a: &Address) -> Address {
    document_of(a).expect("a link has a home")
}

/// §G — THE HOME RANGES ANSWER EXACTLY WHAT A SCAN WOULD: `homed_under` is
/// the links whose HOME the endset covers — a scan of the whole store keeping
/// each key whose `document_of` some span contains — and `homes_under` is
/// their distinct homes, over every view and over a pool of home endsets
/// holding every shape a `home` slot can carry: the node, an account, a
/// document, a version member, an address beneath a document, a link's own
/// address, two documents at once, a sibling run across documents, spans
/// starting or ending inside a document's own subspaces, a span between two
/// trailing-zero prefixes, the off-contract skew and the empty endset. A seek
/// that stopped a home early, skipped a member, took a span's start for its
/// first home's or read the key range for the coverage test answers
/// differently somewhere in the pool.
#[test]
fn homed_under_answers_exactly_what_a_scan_filtered_by_home_would() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    // doc1: three links, one nullified; doc2: two; the sibling's document:
    // one; a version member of the sibling's published document: one.
    let w = writer(&k);
    open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    open_deposit(&w, &[ca(2)], &[], &[unregistered_ta(2)]);
    let gone = open_deposit(&w, &[ca(1)], &[ca(3)], &[unregistered_ta(1)]);
    w.nullify(P1, &doc1(), &gone).expect("retract one");
    deposit_in(&k, &doc2(), &[ca(1)], &[ca(4)], &unregistered_ta(1));
    deposit_in(&k, &doc2(), &[ca(1)], &[ca(5)], &unregistered_ta(1));
    deposit_in(&k, &sib_doc(), &[ca(1)], &[], &unregistered_ta(1));
    let (member, _) = Vstream::new(&k)
        .version(PrincipalId(2), &sib_doc(), None)
        .expect("the owner versions its published document");
    assert_eq!(member, a(&[1, 0, 2, 0, 1, 1]), "the chain's first member");
    deposit_in(&k, &member, &[ca(1)], &[], &unregistered_ta(1));

    let between = |lo: &[u32], hi: &[u32]| {
        Endset::from_spans([Span::from_endpoints(t(lo), &t(hi)).expect("lo < hi at one length")])
    };
    let pool: Vec<Endset> = vec![
        enc(&[a(&[1])]),
        enc(&[a(&[1, 0, 1])]),
        enc(&[a(&[1, 0, 2])]),
        enc(&[doc1()]),
        enc(&[doc2()]),
        enc(&[sib_doc()]),
        enc([&member]),
        enc(&[ca(1)]),
        enc(&[la(1)]),
        enc(&[doc1(), doc2()]),
        enc(&[doc2(), sib_doc(), doc1()]),
        between(&[1, 0, 1, 0, 1], &[1, 0, 1, 0, 3]), // a run across both of the owner's documents
        between(&[1, 0, 1, 0, 1, 0, 1, 5], &[1, 0, 1, 0, 2, 0, 1, 3]), // inside doc1's content to inside doc2's
        between(&[1, 0, 1, 0, 1, 0, 2, 2], &[1, 0, 2, 0, 1, 0, 2, 1]), // doc1's link chain to the sibling's
        between(&[1, 0, 1, 0, 1, 0], &[1, 0, 2, 0, 1, 0]), // two trailing-zero prefixes: doc2 and the sibling's document, not its member
        skew(),
        Endset::empty(),
    ];
    let snap = k.snapshot();
    let links = snap.world().links();
    let (mut homes_found, mut views_part) = (OrdSet::new(), false);
    for view in [View::Audit, View::Active, View::Default] {
        let every = links.match_links(&[], view);
        for h in &pool {
            let expected: OrdSet<Address> = every
                .iter()
                .filter(|a| h.covers(home_of(a).tumbler()))
                .cloned()
                .collect();
            assert_eq!(links.homed_under(h, view), expected, "{view:?}, {h:?}");
            if view == View::Audit {
                let homes: OrdSet<Address> = expected.iter().map(home_of).collect();
                assert_eq!(links.homes_under(h), homes, "the homes of {h:?}");
                homes_found = homes_found.union(homes);
            } else {
                views_part |= expected.len() != links.homed_under(h, View::Audit).len();
            }
        }
    }
    // …and the agreement is not vacuous: every home is found by some span,
    // and the nullified link parts the audit answers from the active ones.
    assert_eq!(
        homes_found,
        OrdSet::from(vec![doc1(), doc2(), sib_doc(), member]),
        "every home holding links is some span's"
    );
    assert!(views_part, "the nullified link parts the views");
}

/// §G — `homed_in` narrows one home's links by the constraints
/// `match_links` tests its later constraints with, under the same relation:
/// the home's whole chain with no constraint, the chain's links whose slot
/// overlaps each constraint with one, in each view — exactly the AND's answer
/// cut to the home — and never a member's link, which is a home of its own.
/// And it refuses a home that is no document, the caller's bug, rather than
/// reading some other range as that home's chain.
#[test]
fn homed_in_narrows_a_homes_chain_as_match_links_narrows_and_refuses_a_non_document() {
    let k = kernel();
    let w = writer(&k);
    let l1 = open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    let l2 = open_deposit(&w, &[ca(2)], &[ca(2)], &[unregistered_ta(2)]);
    let gone = open_deposit(&w, &[ca(1)], &[ca(3)], &[unregistered_ta(1)]);
    // Retracted from doc2, so the retraction tuple — whose F names its home
    // and so covers every position of it — joins doc2's chain, not doc1's.
    w.nullify(P1, &doc2(), &gone).expect("retract one");
    let in_doc2 = deposit_in(&k, &doc2(), &[ca(1)], &[ca(2)], &unregistered_ta(1));
    let snap = k.snapshot();
    let links = snap.world().links();

    let from_ca1 = enc(&[ca(1)]);
    let to_ca2 = enc(&[ca(2)]);
    let pool: [&[(usize, &Endset)]; 4] = [
        &[],
        &[(FROM, &from_ca1)],
        &[(TO, &to_ca2)],
        &[(FROM, &from_ca1), (TO, &to_ca2)],
    ];
    for view in [View::Audit, View::Active, View::Default] {
        for constraints in pool {
            let expected: OrdSet<Address> = links
                .match_links(constraints, view)
                .iter()
                .filter(|a| home_of(a) == doc1())
                .cloned()
                .collect();
            assert_eq!(
                links.homed_in(&doc1(), constraints, view),
                expected,
                "{view:?}, {constraints:?}"
            );
        }
    }
    // The pins behind the agreement: the active FROM-ca(1) chain is l1 alone
    // (gone is nullified, l2 is from ca(2), in_doc2 is doc2's), and Audit
    // keeps gone.
    assert_eq!(
        links.homed_in(&doc1(), &[(FROM, &from_ca1)], View::Active),
        OrdSet::from(vec![l1.clone()])
    );
    assert_eq!(
        links.homed_in(&doc1(), &[(FROM, &from_ca1)], View::Audit),
        OrdSet::from(vec![l1, gone])
    );
    let doc2_chain = links.homed_in(&doc2(), &[], View::Active);
    assert!(
        doc2_chain.contains(&in_doc2) && doc2_chain.len() == 2,
        "doc2's chain: its deposit and the retraction tuple, and nothing of doc1's: {doc2_chain:?}"
    );
    assert!(links.homed_in(&doc1(), &[], View::Audit).contains(&l2), "l2 is doc1's");
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            links.homed_in(&a(&[1, 0, 1]), &[], View::Active)
        }))
        .is_err(),
        "an account is no home"
    );
}

/// §G — THE HOME RANGES PAY FOR THE HOME'S LINKS AND NOT FOR THE STORE,
/// counted: `homed_under` at a document holding twenty links costs the same
/// heap beside a thousand links homed in another document as beside a
/// hundred, where the whole-store walk `match_links` takes with no constraint
/// pays for every one of them. The seeks that find the home and stop past it
/// are logarithmic in the store, and a logarithm the counts cannot see at
/// these sizes is the only term the store contributes.
#[test]
fn homed_under_does_not_pay_for_the_links_homed_elsewhere() {
    let world_of = |n: u32| {
        let k = kernel();
        let w = writer(&k);
        for i in 1..=20 {
            open_deposit(&w, &[ca(i)], &[], &[unregistered_ta(1)]);
        }
        for i in 1..=n {
            deposit_in(&k, &doc2(), &[ca(i)], &[], &unregistered_ta(1));
        }
        k
    };
    let (fewer, more) = (world_of(100), world_of(1_000));
    let home = enc(&[doc1()]);
    let heap_of = |k: &Kernel<World>| {
        let snap = k.snapshot();
        let (found, bytes) =
            settled_heap_bytes(|| snap.world().links().homed_under(&home, View::Active));
        assert_eq!(found.len(), 20, "doc1's twenty");
        bytes
    };
    assert_eq!(
        heap_of(&more),
        heap_of(&fewer),
        "a link homed elsewhere costs the home's range nothing"
    );
    let walk_of = |k: &Kernel<World>| {
        let snap = k.snapshot();
        settled_heap_bytes(|| snap.world().links().match_links(&[], View::Active)).1
    };
    assert!(walk_of(&more) > walk_of(&fewer), "the control: the store walk pays for the store");
}

/// §G — `type_hits` COUNTS WHAT A STAB AT TYPE WOULD REACH: for every
/// address-denoting query, the sum of the sizes of the classes standing in the
/// prefix relation — the type itself, its subtypes beneath it, the wider types
/// above it and the classes denoting it beside another — equals the stab's
/// own hit count, nullified links included; a query that is not
/// address-denoting is `None`; and a class that denotes nothing, a type slot
/// built from a content extent, is counted whole, which is exact where the
/// extent overlaps the query and an over-count where it does not.
#[test]
fn type_hits_counts_what_a_type_stab_reaches() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let (t, u) = (unregistered_ta(1), unregistered_ta(2));
    let sub = a(&[1, 0, 9, 0, 9, 0, 1, 1, 1]); // beneath t
    let above = a(&[1, 0, 9, 0, 9]); // the document t and u are elements of
    let two_t: Vec<Address> = (0..2).map(|_| open_deposit(&w, &[ca(1)], &[ca(2)], std::slice::from_ref(&t))).collect();
    open_deposit(&w, &[ca(1)], &[], std::slice::from_ref(&sub));
    open_deposit(&w, &[ca(1)], &[], std::slice::from_ref(&above));
    for _ in 0..3 {
        open_deposit(&w, &[ca(1)], &[], std::slice::from_ref(&u));
    }
    open_deposit(&w, &[ca(1)], &[], &[t.clone(), u.clone()]);
    w.nullify(P1, &doc1(), &two_t[0]).expect("retract one t-typed link: still counted");
    let queries = [enc([&t]), enc([&u]), enc([&sub]), enc([&above]), enc(&[ca(9)]), enc([&t, &u])];
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        for q in &queries {
            assert_eq!(
                links.type_hits(q),
                Some(links.stab(TYPE, q, View::Audit).len()),
                "{q:?}"
            );
        }
        // The pins behind the agreement: t reaches its two, its subtype, the
        // document above and the two-address class — five — and u reaches
        // its three, the document and the two-address class.
        assert_eq!(links.type_hits(&enc([&t])), Some(5));
        assert_eq!(links.type_hits(&enc([&u])), Some(5));
        assert_eq!(links.type_hits(&enc([&above])), Some(8));
        assert_eq!(links.type_hits(&enc(&[ca(9)])), Some(0));
        assert_eq!(links.type_hits(&Endset::from_spans([iext(1, 3)])), None, "not address-denoting");
    }
    // An extent-typed link, through editlink's open gate: its class denotes
    // nothing and is counted whole — exact for a query it overlaps, one over
    // for one it does not.
    let successor = Link::triple(enc(&[ca(1)]), enc(&[ca(2)]), Endset::from_spans([iext(1, 3)]));
    w.editlink(P1, &two_t[1], successor, &doc1(), &doc1())
        .expect("a level-uniform successor");
    let snap = k.snapshot();
    let links = snap.world().links();
    let overlapping = enc(&[ca(2)]);
    assert!(links.stab(TYPE, &overlapping, View::Audit).len() == 1, "the extent is the one hit");
    assert_eq!(links.type_hits(&overlapping), Some(1), "exact where the extent overlaps");
    for q in &queries {
        assert_eq!(
            links.type_hits(q),
            Some(links.stab(TYPE, q, View::Audit).len() + 1),
            "{q:?}: one over, the extent's class counted whole"
        );
    }
}

/// §G — `stab_typed` IS THE STAB CUT TO THE SLICE: over every slot, view and
/// query of a pool, its tuples are the links `stab` answers that `type_slice`
/// holds, in address order, each carrying the link's own F and G; and at a
/// probe's unit span it reaches every tuple `observe` matches by coverage of
/// the probe — the reader's own coverage test over its answer is `observe`'s
/// answer exactly — beside the tuples whose slot starts strictly beneath the
/// probe, which coverage never reaches.
#[test]
fn stab_typed_answers_the_stab_cut_to_the_typed_slice() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let rel = unregistered_ty(1);
    let other = unregistered_ty(2);
    let l1 = open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    open_deposit(&w, &[ca(1)], &[ca(4)], &[unregistered_ta(2)]); // the other type, same F
    let l3 = open_deposit(&w, &[doc1()], &[ca(2)], &[unregistered_ta(1)]); // F covers every element of doc1
    let beneath = a(&[1, 0, 1, 0, 1, 0, 1, 1, 7]); // strictly beneath ca(1)
    let l4 = open_deposit(&w, std::slice::from_ref(&beneath), &[ca(2)], &[unregistered_ta(1)]);
    let l5 = open_deposit(&w, &[ca(5)], &[ca(2)], &[unregistered_ta(1)]);
    w.nullify(P1, &doc1(), &l5).expect("retract one");
    let snap = k.snapshot();
    let links = snap.world().links();
    let addrs = |tuples: &[Tuple]| tuples.iter().map(|t| t.addr.clone()).collect::<Vec<_>>();

    let queries = [enc(&[ca(1)]), enc(&[ca(2)]), enc(&[doc1()]), enc([&beneath]), enc(&[ca(1), ca(5)]), Endset::from_spans([iext(1, 3)])];
    for ty in [&rel, &other] {
        for view in [View::Audit, View::Active, View::Default] {
            let slice = links.type_slice(ty, view);
            for slot in [FROM, TO, TYPE] {
                for q in &queries {
                    let typed = links.stab_typed(ty, slot, q, view);
                    let expected: Vec<Address> =
                        links.stab(slot, q, view).iter().filter(|a| slice.contains(a)).cloned().collect();
                    assert_eq!(addrs(&typed), expected, "{ty:?} slot {slot} {view:?} {q:?}");
                    for tuple in &typed {
                        let link = links.readlink(&tuple.addr).expect("a stab key is resident");
                        assert_eq!((&tuple.from, &tuple.to), (link.from_slot(), link.to_slot()));
                    }
                }
            }
        }
    }
    // At ca(1)'s unit span the typed stab reaches l1 (equal), l3 (containing)
    // and l4 (starting beneath), where coverage of ca(1) reaches l1 and l3
    // alone — observe's answer, and the stab's after the reader's own test.
    let probe = [ca(1).tumbler().clone()];
    let by_coverage = links.observe(&rel, Pattern { from: &probe, ..Pattern::default() }, View::Active);
    assert_eq!(addrs(&by_coverage), vec![l1.clone(), l3.clone()]);
    let by_overlap = links.stab_typed(&rel, FROM, &enc(&[ca(1)]), View::Active);
    assert_eq!(addrs(&by_overlap), vec![l1, l3, l4]);
    let covering: Vec<Tuple> = by_overlap.into_iter().filter(|t| t.from.covers(&probe[0])).collect();
    assert_eq!(covering, by_coverage);
}

#[test]
fn followlink_folds_the_whole_slot_in_its_recorded_order() {
    // The fold is concatenation, order-preserving (RL1's verbatim read-back
    // through F1/F3) — so a deliberately unsorted multi-span slot reads back
    // unsorted, uncoalesced and whole. Every other followlink case is one
    // span or none, where a normalizing fold would agree.
    let k = kernel();
    let w = writer(&k);
    // FROM unsorted, on purpose.
    let l = open_deposit(&w, &[ca(2), ca(1)], &[], &[unregistered_ta(10)]);
    let want: SpanSet = [
        skep_address::subtree_of(ca(2).tumbler()),
        skep_address::subtree_of(ca(1).tumbler()),
    ]
    .into_iter()
    .collect();
    let snap = k.snapshot();
    assert_eq!(snap.world().links().followlink(&l, FROM), Ok(want));
}
