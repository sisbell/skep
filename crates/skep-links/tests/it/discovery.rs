//! The §G discovery primitives and FOLLOWLINK over a real kernel (InMemory):
//! `stab` and `match_links` admitting each of the three overlap relations
//! against the one they refuse, the AND-combiner's agreement with its own
//! conjuncts over every subset of a constraint pool in both views, the three
//! primitives' `Default → Active` coercion, `stab`'s empty-query floor and
//! its absent-slot rule, and the verbatim order FOLLOWLINK folds.

use crate::common;

use common::*;
use skep_address::{Address, SpanSet};
use skep_links::{enc, Endset, HasLinks, SlotArg, View, FROM, TO, TYPE};

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
        let extent = |lo: u32, hi: u32| {
            Endset::from_spans([skep_address::Span::from_endpoints(
                ca(lo).tumbler().clone(),
                ca(hi).tumbler(),
            )
            .expect("well-formed span")])
        };
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
fn match_links_narrows_to_the_same_set_its_conjuncts_intersect() {
    // The AND is a conjunction, so narrowing the accumulator by a slot's own
    // overlap predicate and intersecting whole-store `stab` results are the
    // same set — over every subset of the constraint pool, in both views,
    // with a nullified link present so the Active/Audit split is exercised.
    let k = kernel();
    let w = writer(&k);
    let deposit = |from: &[Address], to: &[Address], ty: &[Address]| {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(from.to_vec()),
            SlotArg::Addrs(to.to_vec()),
            SlotArg::Addrs(ty.to_vec()),
        )
        .expect("open-surface deposit")
        .0
    };
    let l1 = deposit(&[ca(1)], &[ca(2)], &[ca(7)]);
    let l2 = deposit(&[ca(1)], &[ca(4)], &[ca(7)]);
    let l3 = deposit(&[ca(5)], &[ca(2)], &[ca(8)]);
    let l4 = deposit(&[ca(1), ca(5)], &[ca(2), ca(4)], &[ca(7)]);
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
    let all = links.match_links(&every, View::Audit);
    assert!(all.contains(&l1) && all.contains(&l4));
    assert!(!all.contains(&l2) && !all.contains(&l3));
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

#[test]
fn followlink_folds_the_whole_slot_in_its_recorded_order() {
    // The fold is concatenation, order-preserving (RL1's verbatim read-back
    // through F1/F3) — so a deliberately unsorted multi-span slot reads back
    // unsorted, uncoalesced and whole. Every other followlink case is one
    // span or none, where a normalizing fold would agree.
    let k = kernel();
    let w = writer(&k);
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(2), ca(1)]), // unsorted, on purpose
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)]),
        )
        .expect("open-surface deposit");
    let want: SpanSet = [
        skep_address::subtree_of(ca(2).tumbler()),
        skep_address::subtree_of(ca(1).tumbler()),
    ]
    .into_iter()
    .collect();
    let snap = k.snapshot();
    assert_eq!(snap.world().links().followlink(&l, FROM), Ok(want));
}
