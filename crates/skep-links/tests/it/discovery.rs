//! The §G discovery primitives and FOLLOWLINK over a real kernel (InMemory):
//! `stab` and `match_links` admitting each of the three overlap relations
//! against the one they refuse, the per-span disjunction on both sides of that
//! test, the AND-combiner's agreement with its own conjuncts over every subset
//! of a constraint pool in both views, the three primitives' `Default → Active`
//! coercion, `stab`'s empty-query floor and its absent-slot rule, the home
//! ranges against a scan of the store filtered by each key's home — and what
//! they cost, counted — the homes-first pair against the stab they compose
//! (every hit's home named once, ascending; the per-home shares concatenated
//! in that order the stab's own answer) and what a read composed over
//! readable homes pays, counted, the typed stab against the stab cut to the
//! slice and its one home's share against the stab cut to the slice and the
//! home, and the verbatim order FOLLOWLINK folds.

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use im::OrdSet;
use skep_address::{document_of, Address, Span, SpanSet};
use skep_arrangement::Vstream;
use skep_kernel::Kernel;
use skep_links::{
    coverage_class, enc, Endset, HasLinks, Link, LinkState, Pattern, SlotArg, Touch, Tuple, View,
    FROM, TO, TYPE,
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

/// The homes of a stab's hits, as the oracle reads them: each hit's
/// `document_of`, once, ascending.
fn homes_of_hits(hits: &OrdSet<Address>) -> Vec<Address> {
    let homes: OrdSet<Address> = hits.iter().map(home_of).collect();
    homes.into_iter().collect()
}

/// §G — `homes_touching` NAMES EVERY HOME OF EVERY HIT, once, ascending, and
/// `stab_in` over the spans it names answers each home's share of the stab:
/// over every slot and a pool of queries of every shape — unit spans at every
/// level, extents, a two-span query, the off-contract witness and the empty
/// endset — the candidate homes are a superset of the hits' homes in address
/// order with no repeat, the per-home stabs concatenated in that order are
/// the stab's own answer in its own order, and a home the walk leaves
/// unstabbed holds no hit. The links are homed in four homes of every shape
/// the mint produces — two documents of one account, a sibling account's
/// document and a version member of it — so the concatenation argument is
/// pinned where a member's address extends its document's. At the type slot
/// the candidates come off the typed slices rather than the directory: a
/// type named only by links homed in one document names that home alone,
/// though a sibling type of the same block types a link homed elsewhere.
#[test]
fn homes_touching_names_every_home_of_every_hit_and_stab_in_concatenates_in_address_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let (t, u) = (unregistered_ta(1), unregistered_ta(2)); // siblings in one directory block
    let gone = open_deposit(&w, &[ca(1)], &[ca(2), la(1)], std::slice::from_ref(&t));
    open_deposit(&w, &[ca(2)], &[doc2()], std::slice::from_ref(&t));
    open_deposit(&w, &[doc1(), ca(3)], &[a(&[1, 0, 2])], &[a(&[1, 0, 9, 0, 9])]); // the document above t and u
    let successor = Link::triple(
        Endset::from_spans([iext(1, 3)]),
        Endset::from_spans([iext(2, 4), iext(60, 70)]),
        Endset::from_spans([iext(1, 3)]),
    );
    w.editlink(P1, &gone, successor, &doc1(), &doc1()).expect("an extent-slotted successor");
    w.nullify(P1, &doc1(), &gone).expect("retract one");
    deposit_in(&k, &doc2(), &[ca(1)], &[ca(4)], &u);
    deposit_in(&k, &doc2(), &[ca(70)], &[ca(1)], &a(&[1, 0, 9, 0, 9, 0, 1, 1, 1])); // beneath t
    deposit_in(&k, &sib_doc(), &[ca(1), ca(5)], &[], &t);
    let (member, _) = Vstream::new(&k)
        .version(PrincipalId(2), &sib_doc(), None)
        .expect("the owner versions its published document");
    assert_eq!(member, a(&[1, 0, 2, 0, 1, 1]), "the chain's first member");
    deposit_in(&k, &member, &[ca(1)], &[ca(2)], &t);
    deposit_in(&k, &member, &[ca(65)], &[ca(2)], &u);

    let snap = k.snapshot();
    let links = snap.world().links();
    let pool = [
        enc(&[ca(1)]),
        enc(&[ca(2)]),
        enc(&[ca(70)]),
        enc(&[doc1()]),
        enc(&[doc2()]),
        enc(&[sib_doc()]),
        enc(&[a(&[1, 0, 2])]),
        enc(&[a(&[1])]),
        enc(&[la(1)]),
        enc([&t]),
        enc([&u]),
        enc(&[a(&[1, 0, 9, 0, 9])]),
        enc(&[ca(1), ca(70)]),
        Endset::from_spans([iext(1, 3)]),
        Endset::from_spans([iext(2, 100)]),
        skew(),
        Endset::empty(),
    ];
    let (mut homes_seen, mut spared) = (OrdSet::new(), 0);
    for slot in [FROM, TO, TYPE] {
        for q in &pool {
            for view in [View::Audit, View::Active] {
                let hits = links.stab(slot, q, view);
                let mut candidates = Vec::new();
                let mut concatenated = Vec::new();
                for touch in links.homes_touching([(slot, q)]) {
                    let share = links.stab_in(touch.home(), slot, touch.spans(0), view);
                    assert_eq!(
                        share,
                        links.stab_in(touch.home(), slot, q.spans(), view),
                        "the spans named answer the home's whole share: slot {slot}, {q:?}"
                    );
                    spared += usize::from(share.is_empty());
                    concatenated.extend(share);
                    candidates.push(touch.into_home());
                }
                let sorted: Vec<Address> = hits.iter().cloned().collect();
                assert_eq!(concatenated, sorted, "slot {slot}, {view:?}, {q:?}: concatenated in home order");
                assert!(candidates.windows(2).all(|p| p[0] < p[1]), "ascending, once each: {candidates:?}");
                let of_hits = homes_of_hits(&hits);
                assert!(
                    of_hits.iter().all(|h| candidates.contains(h)),
                    "slot {slot}, {q:?}: every hit's home is a candidate: {of_hits:?} ⊄ {candidates:?}"
                );
                homes_seen = homes_seen.union(of_hits.into_iter().collect());
            }
        }
    }
    assert_eq!(
        homes_seen,
        OrdSet::from(vec![doc1(), doc2(), sib_doc(), member.clone()]),
        "every home of every shape is some query's"
    );
    assert!(spared > 0, "some candidate holds no hit, so the superset is not the hits' homes restated");
    // The type slot's candidates are the typed slices', exact to the class
    // relation: `t` is homed in doc1, the sibling document and its member,
    // and its subtype in doc2, so `t` names all four; `u` — a sibling type
    // of `t` in the same directory block — is homed in doc2 and the member,
    // and names those two and not the sibling document, which holds `t`
    // alone. doc1 is named for every type query, holding the extent-typed
    // successor, whose class denotes no address and is answered whole.
    let named = |ty: &Endset| -> Vec<Address> {
        links.homes_touching([(TYPE, ty)]).map(|touch| touch.into_home()).collect()
    };
    assert_eq!(named(&enc([&t])), vec![doc1(), doc2(), sib_doc(), member.clone()]);
    assert_eq!(named(&enc([&u])), vec![doc1(), doc2(), member]);
    assert_eq!(named(&enc(&[ca(9)])), vec![doc1()], "the extent-typed class, answered whole");
}

/// The touch the walk over `queries` yields for `home`.
fn touch_at<'q>(
    links: &'q LinkState,
    queries: [(usize, &'q Endset); 2],
    home: &Address,
) -> Touch<'q> {
    links
        .homes_touching(queries)
        .find(|touch| touch.home() == home)
        .expect("the walk names the home")
}

/// §G — `stab_in_slots` IS THE PER-SLOT STABS OF ONE HOME ANSWERED TOGETHER:
/// over every candidate home of every query in a pool, in both views, its
/// `(link, slot)` pairs are exactly the pairs the three `stab_in`s answer —
/// `(a, slot)` for every `a` in `stab_in(home, slot, …)` — in address order
/// then slot order, its probes asking the spans the walk named the home for
/// at the parts of the stab that named it, as the `stab_in`s over those
/// spans and over the whole query ask every part; so the distinct links a
/// caller reads off the pairs, concatenated over the homes, are the union of
/// the three whole stabs in address order, and the attribution it reads off
/// the pairs is each slot's own set. A probe answers its own pair's spans
/// alone; a slot no link has and a pair the walk named the home for by no
/// span contribute nothing, and no probe answers none, asking the heap for
/// nothing. The fixture homes links of every address shape — two documents
/// of one account, a sibling account's document and a version member of it
/// — with one link touching a query at two slots, so the pairs are not the
/// links restated, one type that is a content address, so the type slot's
/// candidates come off the typed slices, and one link nullified, so the two
/// views part.
#[test]
fn stab_in_slots_answers_the_per_slot_stabs_of_one_home_as_pairs_in_address_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let t = unregistered_ta(1);
    // doc1: FROM ca(1); FROM ca(2) TO ca(1), two slots on one query; and
    // one retracted.
    open_deposit(&w, &[ca(1)], &[ca(5)], std::slice::from_ref(&t));
    let twice = open_deposit(&w, &[ca(2)], &[ca(1)], std::slice::from_ref(&t));
    let gone = open_deposit(&w, &[ca(1)], &[ca(6)], std::slice::from_ref(&t));
    w.nullify(P1, &doc1(), &gone).expect("retract one");
    // doc2: TO ca(1), and a TYPE that is ca(1) itself.
    deposit_in(&k, &doc2(), &[ca(7)], &[ca(1)], &t);
    deposit_in(&k, &doc2(), &[ca(8)], &[], &ca(1));
    // The sibling's document and its member: FROM ca(1) apiece, the member
    // with one more a block away.
    deposit_in(&k, &sib_doc(), &[ca(1), ca(3)], &[], &t);
    let (member, _) = Vstream::new(&k)
        .version(PrincipalId(2), &sib_doc(), None)
        .expect("the owner versions its published document");
    deposit_in(&k, &member, &[ca(1)], &[ca(2)], &t);
    deposit_in(&k, &member, &[ca(70)], &[], &t);
    let snap = k.snapshot();
    let links = snap.world().links();

    let pool = [
        enc(&[ca(1)]),
        enc(&[ca(2)]),
        enc(&[ca(70)]),
        enc(&[doc1()]),
        Endset::from_spans([iext(1, 3)]),
        Endset::from_spans([iext(2, 100)]),
        enc(&[ca(1), ca(70)]),
        Endset::empty(),
    ];
    let (mut homes_seen, mut at_two_slots, mut spared, mut views_part) = (OrdSet::new(), 0, 0, false);
    for q in &pool {
        let queries = [(FROM, q), (TO, q), (TYPE, q)];
        for view in [View::Audit, View::Active] {
            let mut concatenated = Vec::new();
            for touch in links.homes_touching(queries) {
                let probes = queries.iter().enumerate().map(|(i, &(slot, _))| (slot, i));
                let pairs = links.stab_in_slots(&touch, probes, view);
                let mut expected: Vec<(Address, usize)> = Vec::new();
                let mut whole: Vec<(Address, usize)> = Vec::new();
                for (i, &(slot, query)) in queries.iter().enumerate() {
                    let share = links.stab_in(touch.home(), slot, touch.spans(i), view);
                    expected.extend(share.iter().map(|a| (a.clone(), slot)));
                    let all = links.stab_in(touch.home(), slot, query.spans(), view);
                    whole.extend(all.iter().map(|a| (a.clone(), slot)));
                }
                expected.sort();
                whole.sort();
                assert_eq!(pairs, expected, "{view:?}, {q:?}, home {:?}", touch.home());
                assert_eq!(
                    pairs, whole,
                    "the spans and the parts named answer the home's whole share: {view:?}, {q:?}"
                );
                let mut distinct: Vec<Address> = pairs.iter().map(|(a, _)| a.clone()).collect();
                distinct.dedup();
                at_two_slots += pairs.len() - distinct.len();
                spared += usize::from(pairs.is_empty());
                views_part |= view == View::Active && pairs.iter().any(|(a, _)| *a == gone);
                concatenated.extend(distinct);
                homes_seen.insert(touch.into_home());
            }
            let union: OrdSet<Address> = queries
                .iter()
                .flat_map(|&(slot, q)| links.stab(slot, q, view))
                .collect();
            assert_eq!(
                concatenated,
                union.iter().cloned().collect::<Vec<_>>(),
                "{view:?}, {q:?}: the distinct links, concatenated over the homes, are the union of the whole stabs"
            );
        }
    }
    assert_eq!(
        homes_seen,
        OrdSet::from(vec![doc1(), doc2(), sib_doc(), member]),
        "every home of every shape is some query's"
    );
    assert!(at_two_slots > 0, "some link touches at two slots, so the pairs are not the links restated");
    assert!(spared > 0, "some candidate holds no hit");
    assert!(!views_part, "the active view never answers the retracted link");
    let extent = Endset::from_spans([iext(1, 3)]);
    let touch = touch_at(links, [(FROM, &extent), (TO, &extent)], &doc1());
    let at_two = links.stab_in_slots(&touch, [(FROM, 0), (TO, 1)], View::Active);
    assert_eq!(
        at_two.iter().filter(|(a, _)| *a == twice).count(),
        2,
        "one link, two pairs: {at_two:?}"
    );
    // A probe answers its own pair's spans alone: `twice`, whose `TO` is
    // ca(1), is no hit of a `TO` probe whose pair asked ca(5), though the
    // walk's other pair asked ca(1).
    let (one, five) = (enc(&[ca(1)]), enc(&[ca(5)]));
    let touch = touch_at(links, [(FROM, &one), (TO, &five)], &doc1());
    let isolated = links.stab_in_slots(&touch, [(FROM, 0), (TO, 1)], View::Audit);
    let mut own: Vec<(Address, usize)> = Vec::new();
    for (i, slot) in [FROM, TO].into_iter().enumerate() {
        let share = links.stab_in(touch.home(), slot, touch.spans(i), View::Audit);
        own.extend(share.iter().map(|a| (a.clone(), slot)));
    }
    own.sort();
    assert_eq!(isolated, own, "each probe asks its own pair's spans");
    assert!(!isolated.contains(&(twice.clone(), TO)), "{isolated:?}");
    // A pair the walk named the home for by no span contributes nothing,
    // though its slot holds a hit of the other pair's span; a slot no link
    // has contributes nothing; and no probe answers none, asking the heap for
    // nothing.
    let seventy = enc(&[ca(70)]);
    let touch = touch_at(links, [(FROM, &one), (TO, &seventy)], &doc1());
    assert_eq!(touch.spans(1).count(), 0, "the premise: ca(70) names doc1 by no span at TO");
    let from_alone: Vec<(Address, usize)> = links
        .stab_in(touch.home(), FROM, touch.spans(0), View::Audit)
        .iter()
        .map(|a| (a.clone(), FROM))
        .collect();
    assert!(!from_alone.is_empty(), "the premise: doc1 holds a FROM hit of ca(1)");
    assert_eq!(
        links.stab_in_slots(&touch, [(FROM, 0), (TO, 1)], View::Audit),
        from_alone,
        "a pair that named the home by no span adds nothing"
    );
    let touch = touch_at(links, [(FROM, &one), (4, &one)], &doc1());
    assert_eq!(
        links.stab_in_slots(&touch, [(FROM, 0), (4, 1)], View::Audit),
        from_alone,
        "past the arity, a slot no link has adds nothing"
    );
    let (answer, bytes) =
        settled_heap_bytes(|| links.stab_in_slots(&touch, std::iter::empty(), View::Active));
    assert!(answer.is_empty(), "no probe");
    assert_eq!(bytes, 0, "no probe asks the heap for nothing");
}

/// §G — THE COMPOSED STAB PAYS NOTHING FOR THE LINKS HOMED WHERE THE READER
/// MAY NOT READ, counted: twenty links in doc1 beside a flood on the same
/// position homed in doc2, which the reader may not read. The read a caller
/// composes — the candidate homes, each asked of the reader once, the
/// readable ones stabbed — costs the same heap beside a thousand flooding
/// links as beside a hundred; the whole stab, which lifts every hit, is the
/// control and pays for the flood. The directory step the unreadable home
/// costs is one entry per block it starts in, which a flood at one position
/// keeps at one.
#[test]
fn a_stab_composed_over_readable_homes_does_not_pay_for_the_links_homed_where_the_reader_may_not_read() {
    let world_of = |n: u32| {
        let k = kernel();
        let w = writer(&k);
        for i in 1..=20 {
            open_deposit(&w, &[ca(1)], &[ca(100 + i)], &[unregistered_ta(1)]);
        }
        for i in 1..=n {
            deposit_in(&k, &doc2(), &[ca(1)], &[ca(1000 + i)], &unregistered_ta(1));
        }
        k
    };
    let (fewer, more) = (world_of(100), world_of(1_000));
    let query = enc(&[ca(1)]);
    let composed = |k: &Kernel<World>| {
        let snap = k.snapshot();
        let links = snap.world().links();
        let (found, bytes) = settled_heap_bytes(|| {
            let mut found = Vec::new();
            for touch in links.homes_touching([(FROM, &query)]) {
                if *touch.home() != doc2() {
                    found.extend(links.stab_in(touch.home(), FROM, touch.spans(0), View::Active));
                }
            }
            found
        });
        assert_eq!(found.len(), 20, "doc1's twenty, and nothing of doc2's");
        bytes
    };
    assert_eq!(
        composed(&more),
        composed(&fewer),
        "a link homed where the reader may not read costs the composed read nothing"
    );
    let whole = |k: &Kernel<World>| {
        let snap = k.snapshot();
        settled_heap_bytes(|| snap.world().links().stab(FROM, &query, View::Active)).1
    };
    assert!(whole(&more) > whole(&fewer), "the control: the whole stab pays for the flood");
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

/// §G — `stab_typed_in` IS ONE HOME'S SHARE OF THE TYPED STAB: over every
/// slot, view and query of a pool, and every home the walk names for the
/// query, its tuples are the links `stab` answers that `type_slice` holds and
/// that are homed in that home, in address order, each carrying the link's
/// own F and G, and the spans the walk named answer what the whole query's
/// do; the shares concatenated in the walk's order are `stab_typed`'s answer;
/// and a class no link was deposited under answers none in every home. The
/// fixture homes links of the class in two documents, one of them retracted
/// so the views part, and links of another type beside them and alone in a
/// third home, so a candidate's share can be empty: a share that skipped the
/// slice test, read another home's keys or dropped the view would part from
/// the oracle somewhere in the pool.
#[test]
fn stab_typed_in_answers_one_homes_share_of_the_typed_stab() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let (rel, other) = (unregistered_ty(1), unregistered_ty(2));
    open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    open_deposit(&w, &[ca(1)], &[ca(3)], &[unregistered_ta(2)]); // the other type, beside it
    let gone = open_deposit(&w, &[ca(2)], &[ca(1)], &[unregistered_ta(1)]);
    w.nullify(P1, &doc1(), &gone).expect("retract one");
    deposit_in(&k, &doc2(), &[ca(1)], &[ca(2)], &unregistered_ta(1));
    // F covers every element of doc1.
    deposit_in(&k, &doc2(), &[doc1()], &[ca(1)], &unregistered_ta(1));
    deposit_in(&k, &sib_doc(), &[ca(1)], &[ca(2)], &unregistered_ta(2)); // the other type alone
    let snap = k.snapshot();
    let links = snap.world().links();
    let addrs = |tuples: &[Tuple]| tuples.iter().map(|t| t.addr.clone()).collect::<Vec<_>>();

    let queries = [
        enc(&[ca(1)]),
        enc(&[ca(2)]),
        enc(&[doc1()]),
        enc(&[ca(1), ca(3)]),
        enc(&[unregistered_ta(1)]),
        Endset::from_spans([iext(1, 3)]),
    ];
    let (mut empty, mut views_part) = (0, false);
    for ty in [&rel, &other] {
        let class = coverage_class(ty);
        for view in [View::Audit, View::Active, View::Default] {
            let slice = links.type_slice(ty, view);
            for slot in [FROM, TO, TYPE] {
                for q in &queries {
                    let hits = links.stab(slot, q, view);
                    let mut concatenated = Vec::new();
                    for touch in links.homes_touching([(slot, q)]) {
                        let home = touch.home().clone();
                        let share = links.stab_typed_in(&class, &home, slot, touch.spans(0), view);
                        let expected: Vec<Address> = hits
                            .iter()
                            .filter(|a| slice.contains(a) && home_of(a) == home)
                            .cloned()
                            .collect();
                        assert_eq!(
                            addrs(&share),
                            expected,
                            "{ty:?} slot {slot} {view:?} {q:?} home {home:?}"
                        );
                        assert_eq!(
                            share,
                            links.stab_typed_in(&class, &home, slot, q.spans(), view),
                            "the spans named answer the home's whole share: {q:?}"
                        );
                        for tuple in &share {
                            let link = links.readlink(&tuple.addr).expect("a stab key is resident");
                            assert_eq!(
                                (&tuple.from, &tuple.to),
                                (link.from_slot(), link.to_slot())
                            );
                        }
                        empty += usize::from(share.is_empty());
                        views_part |= view == View::Audit && share.iter().any(|t| t.addr == gone);
                        concatenated.extend(share);
                    }
                    assert_eq!(
                        concatenated,
                        links.stab_typed(ty, slot, q, view),
                        "{ty:?} slot {slot} {view:?} {q:?}: the shares make the typed stab"
                    );
                }
            }
        }
    }
    assert!(empty > 0, "some candidate holds no link of the class");
    assert!(views_part, "the retracted link parts the views");
    let never = coverage_class(&unregistered_ty(9));
    for home in [doc1(), doc2(), sib_doc()] {
        assert!(
            links
                .stab_typed_in(&never, &home, FROM, enc(&[ca(1)]).spans(), View::Audit)
                .is_empty(),
            "a class no link was deposited under answers none in {home:?}"
        );
    }
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
