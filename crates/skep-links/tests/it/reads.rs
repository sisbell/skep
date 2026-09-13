//! The typed reads (§F) over a real kernel (InMemory): the `View` default and
//! raw Observe's `Default → Active` coercion, Observe over a whole slice with
//! its AND-of-probes pattern sides, its view selection and the F/G roles its
//! tuples carry, the class-keyed reads over an unregistered class answered
//! verbatim, BH1's filter — retractable, prefix-closed over carrier T,
//! rewriting `Default` views only and subtracting under every active retired
//! root — the enumeration reads at the cardinality their loops need, the BH3
//! endpoint pair in its two matching regimes beside the join that covers
//! nothing, the residence and activity clauses every active-view read is held
//! to, and BH4's ungated `age` beside the staleness family that refuses every
//! class and aborts on an off-contract `ty`.
//!
//! The registry's population is the compiled shipped five (owner ruling,
//! 2026-08-26 — the app-decl seam is deleted): arbitrary type NUMBERS are
//! unregistered classes these reads answer for verbatim, Binary/Multi tuples
//! enter through the open surface, and the BH3 join and BH4 staleness gates
//! — which no shipped class declares — refuse or answer empty for every
//! input, which is pinned here where their served paths were once exercised.

use crate::common;

use common::*;
use skep_kernel::TxnError;
use skep_links::{
    enc, Endset, HasLinks, NotBh4, Pattern, RetractStaleError, SlotArg, Tuple, View,
};

#[test]
fn view_defaults_to_the_default_view() {
    // The std name means the variant the module calls the default view, not
    // `Audit` — which is merely the one declaration order puts first, and is
    // what a derive would have picked.
    assert_eq!(View::default(), View::Default);
}

#[test]
fn observe_coerces_default_to_active_and_never_filters() {
    // Raw Observe is an index probe, so BH1's result-side rewrite is
    // undefined for it: Default reads as Active even when every match's F is
    // retired — which members(), on the same store, subtracts.
    let k = kernel();
    let w = writer(&k);
    let retired = retired_ty();
    let rel = unregistered_ty(1);
    open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    w.emit(P1, &doc1(), &retired, &ca(1), &[])
        .expect("retire ca1");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_filtered(ca(1).tumbler()));
    assert!(links.members(&rel, View::Default).is_empty());
    assert_eq!(
        links.observe(&rel, Pattern::default(), View::Default),
        links.observe(&rel, Pattern::default(), View::Active)
    );
    assert_eq!(links.observe(&rel, Pattern::default(), View::Default).len(), 1);
}

#[test]
fn observe_returns_every_match_in_ascending_tuple_address_order() {
    // ASN-0086's central read, at the cardinality every real type has. Three
    // claims meet here and none of them is visible at a one-tuple result: the
    // slice is walked WHOLE, each pattern side is an AND of its probes, and
    // the view selects the slice.
    let k = kernel();
    let w = writer(&k);
    let tuple_addrs =
        |tuples: Vec<Tuple>| tuples.into_iter().map(|tuple| tuple.addr).collect::<Vec<_>>();
    let rel = unregistered_ty(11);
    let deposit = |from: u32, to: &[u32]| {
        let to: Vec<_> = to.iter().map(|&i| ca(i)).collect();
        open_deposit(&w, &[ca(from)], &to, &[unregistered_ta(11)])
    };
    let a1 = deposit(1, &[2, 3]);
    let a2 = deposit(4, &[2]);
    let a3 = deposit(1, &[3]);
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        // EVERY match, not the first — and ascending by tuple address.
        assert_eq!(
            tuple_addrs(links.observe(&rel, Pattern::default(), View::Active)),
            vec![a1.clone(), a2.clone(), a3.clone()]
        );
        // One F-probe selects two of the three.
        let f = [ca(1).tumbler().clone()];
        assert_eq!(
            tuple_addrs(links.observe(&rel, Pattern { from: &f, to: &[] }, View::Active)),
            vec![a1.clone(), a3.clone()]
        );
        // A pattern side is an AND of its probes, not an OR: a1's G covers
        // ca(2) AND ca(3); a3's covers only ca(3), so an OR would keep it.
        let g = [ca(2).tumbler().clone(), ca(3).tumbler().clone()];
        assert_eq!(
            tuple_addrs(links.observe(&rel, Pattern { from: &f, to: &g }, View::Active)),
            vec![a1.clone()]
        );
    }
    // The view selects the slice: Audit keeps a nullified tuple, Active drops
    // it. Every other observe case in the suite reads one view only.
    w.nullify(P1, &doc1(), &a2).expect("retract the middle tuple");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        tuple_addrs(links.observe(&rel, Pattern::default(), View::Audit)),
        vec![a1.clone(), a2.clone(), a3.clone()]
    );
    assert_eq!(
        tuple_addrs(links.observe(&rel, Pattern::default(), View::Active)),
        vec![a1, a3]
    );
}

#[test]
fn an_observed_tuple_carries_the_link_s_own_f_and_g_in_those_roles() {
    // A Tuple's `from` and `to` are the matched link's F and G slots IN THOSE
    // ROLES — two same-typed fields read off two same-typed sources, so
    // nothing but this pins which is which. A Multi tuple with |F| ≠ |G| is
    // what makes an exchange fail on arity as well as on content.
    let k = kernel();
    let w = writer(&k);
    // The open surface admits |G| = 2.
    let a1 = open_deposit(&w, &[ca(1)], &[ca(2), ca(3)], &[unregistered_ta(11)]);
    let snap = k.snapshot();
    let links = snap.world().links();
    let tuples = links.observe(&unregistered_ty(11), Pattern::default(), View::Active);
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0].addr, a1);
    assert_eq!(tuples[0].from, enc(&[ca(1)]), "the F slot, verbatim");
    assert_eq!(tuples[0].to, enc(&[ca(2), ca(3)]), "the G slot, verbatim");
    // ...and each is the link's own slot, so the tuple cannot disagree with
    // the value READLINK returns.
    let link = links.readlink(&a1).expect("resident");
    assert_eq!(&tuples[0].from, link.from_slot());
    assert_eq!(&tuples[0].to, link.to_slot());
}

#[test]
fn the_class_keyed_reads_serve_an_unregistered_type_verbatim() {
    // A type is a number (owner ruling, 2026-08-26): the open surface
    // deposits any type name verbatim, the fold indexes a type slice for
    // EVERY coverage class, and observe/is_k/members/targets_of and the BH3
    // endpoint pair answer by CLASS with no registration consulted — what an
    // unregistered type means is its interpreting client's business, and
    // these reads are that client's surface. The two pattern sides stay
    // distinct, which no Unary emission can show.
    let k = kernel();
    let w = writer(&k);
    let rel = unregistered_ty(1);
    // The open surface admits an unregistered type.
    let l1 = open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    let snap = k.snapshot();
    let links = snap.world().links();
    let tuples = links.observe(&rel, Pattern::default(), View::Active);
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0].addr, l1);
    assert_eq!(
        links
            .observe(
                &rel,
                Pattern {
                    from: &[ca(1).tumbler().clone()],
                    to: &[ca(2).tumbler().clone()],
                },
                View::Active
            )
            .len(),
        1
    );
    // The two sides are not interchangeable: ca(1) — which this tuple's F
    // covers — finds nothing as a G-probe.
    assert!(links
        .observe(
            &rel,
            Pattern {
                from: &[],
                to: &[ca(1).tumbler().clone()],
            },
            View::Active
        )
        .is_empty());
    assert!(links.is_k(&rel, ca(1).tumbler()));
    assert_eq!(links.members(&rel, View::Active), vec![ca(1)]);
    assert_eq!(links.targets_of(&rel, &ca(1), View::Active), vec![ca(2)]);
    // The BH3 endpoint pair answers for any class — only the keyed JOIN
    // reads declarations back.
    assert_eq!(links.sources_to(&rel, &ca(2)), vec![ca(1)]);
    assert_eq!(links.target_of(&rel, &ca(1)), Some(ca(2)));
}

#[test]
fn is_filtered_reads_the_active_retired_slice() {
    // BH1's filter is retractable: the filter slice is ACTIVE, so nullifying
    // a retirement restores the probe and the Default view with it.
    let k = kernel();
    let w = writer(&k);
    let retired = retired_ty();
    let rel = unregistered_ty(1);
    open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    let (retirement, _) = w
        .emit(P1, &doc1(), &retired, &ca(1), &[])
        .expect("retire ca1");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert!(links.is_filtered(ca(1).tumbler()));
        assert!(links.members(&rel, View::Default).is_empty());
    }
    w.nullify(P1, &doc1(), &retirement)
        .expect("retract the retirement itself");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(
        !links.is_filtered(ca(1).tumbler()),
        "a nullified retired root filters nothing"
    );
    assert_eq!(links.members(&rel, View::Default), vec![ca(1)]);
}

#[test]
fn retired_filter_rewrites_default_views_only() {
    let k = kernel();
    let w = writer(&k);
    let retired = retired_ty();
    let rel = unregistered_ty(1);
    open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    {
        let snap = k.snapshot();
        assert!(!snap.world().links().is_filtered(ca(1).tumbler()));
    }
    // Retire ca(1) through the shipped Unary/idem⊤ BH1 class.
    w.emit(P1, &doc1(), &retired, &ca(1), &[]).expect("retire ca1");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_filtered(ca(1).tumbler()));
    assert!(!links.is_filtered(ca(2).tumbler()));
    // T-wide probe: any tumbler under a retired root is filtered, address
    // or not.
    assert!(links.is_filtered(&t(&[1, 0, 1, 0, 1, 0, 1, 1, 7])));
    // Default = active ∖ filtered — on members/targets_of only.
    assert_eq!(links.members(&rel, View::Active), vec![ca(1)]);
    assert!(links.members(&rel, View::Default).is_empty());
    assert_eq!(links.targets_of(&rel, &ca(1), View::Default), vec![ca(2)]);
    // is_k is never filtered (BH1 Rewrite scope).
    assert!(links.is_k(&rel, ca(1).tumbler()));
    // J ≠ K′: the filter class itself is not self-subtracted.
    assert_eq!(links.members(&retired, View::Default), vec![ca(1)]);
}

#[test]
fn default_view_subtracts_a_filtered_target() {
    // The result-side half of Default = active ∖ filtered: retiring the
    // TARGET, not the source, is what the targets_of subtraction can see.
    let k = kernel();
    let w = writer(&k);
    let retired = retired_ty();
    let rel = unregistered_ty(1);
    open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    w.emit(P1, &doc1(), &retired, &ca(2), &[])
        .expect("retire the target");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(links.targets_of(&rel, &ca(1), View::Active), vec![ca(2)]);
    assert!(links.targets_of(&rel, &ca(1), View::Default).is_empty());
    // The source is untouched, so the members side still answers.
    assert_eq!(links.members(&rel, View::Default), vec![ca(1)]);
}

#[test]
fn the_default_view_subtracts_under_every_active_retired_root() {
    // BH1's filter domain is the WHOLE active Retired slice, and the
    // result-side subtraction derives it once for the whole result rather
    // than once per element — so a result filtered by the second or third
    // root must be subtracted exactly as one filtered by the first.
    let k = kernel();
    let w = writer(&k);
    let retired = retired_ty();
    let rel = unregistered_ty(11);
    for (source, target) in [(ca(1), ca(5)), (ca(2), ca(6)), (ca(3), ca(7))] {
        open_deposit(&w, &[source], &[target], &[unregistered_ta(11)]);
    }
    for root in [ca(2), ca(3), ca(7)] {
        w.emit(P1, &doc1(), &retired, &root, &[])
            .expect("retire a root");
    }
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.members(&rel, View::Active),
        vec![ca(1), ca(2), ca(3)],
        "the unfiltered control"
    );
    assert_eq!(
        links.members(&rel, View::Default),
        vec![ca(1)],
        "the second and third roots subtract as surely as the first"
    );
    // The third root reaches the targets side, which collects the domain of
    // its own accord.
    assert_eq!(links.targets_of(&rel, &ca(3), View::Active), vec![ca(7)]);
    assert!(links.targets_of(&rel, &ca(3), View::Default).is_empty());
    // Each root still answers the single-probe read, which short-circuits
    // rather than collecting.
    for root in [ca(2), ca(3), ca(7)] {
        assert!(links.is_filtered(root.tumbler()));
    }
    assert!(!links.is_filtered(ca(1).tumbler()));
}

#[test]
fn targets_of_collects_every_target_of_every_matching_tuple() {
    // D3 is two nested loops — every tuple whose F covers the source, and
    // every address that tuple's G denotes — and a one-target result cannot
    // tell either of them from a `next()`. The open surface is what lets
    // |G| > 1 exist at all in this format.
    let k = kernel();
    let w = writer(&k);
    let rel = unregistered_ty(11);
    let deposit = |from: u32, to: &[u32]| {
        let to: Vec<_> = to.iter().map(|&i| ca(i)).collect();
        open_deposit(&w, &[ca(from)], &to, &[unregistered_ta(11)])
    };
    deposit(1, &[2, 3]);
    deposit(1, &[3, 5]);
    deposit(4, &[9]);
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.targets_of(&rel, &ca(1), View::Active),
        vec![ca(2), ca(3), ca(5)],
        "every target of every matching tuple, ca(3) deduplicated across the two"
    );
    // The control: the excluded tuple IS in the slice, so ca(9)'s absence is
    // the F-coverage test and not an absent tuple.
    assert_eq!(links.targets_of(&rel, &ca(4), View::Active), vec![ca(9)]);
}

#[test]
fn sources_to_collects_every_source_deduplicated() {
    // BH3's reverse lookup walks the WHOLE active typed slice: every tuple
    // whose G covers the target contributes its F, deduplicated. The open
    // surface never dedups (ML0), so the repeated tuple deposits fresh.
    let k = kernel();
    let w = writer(&k);
    let rel = unregistered_ty(13);
    let other = unregistered_ty(11);
    let deposit =
        |from: u32, ty: u32| open_deposit(&w, &[ca(from)], &[ca(9)], &[unregistered_ta(ty)]);
    deposit(1, 13);
    deposit(4, 13);
    deposit(1, 13); // a third tuple repeating the first source
    // Another type, same target — the typed slice is the domain.
    deposit(7, 11);
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.sources_to(&rel, &ca(9)),
        vec![ca(1), ca(4)],
        "every source of every matching tuple, deduplicated, in Tumbler order"
    );
    // The control: that other tuple answers for its OWN type, so ca(7)'s
    // absence above is the typed slice and not an absent tuple.
    assert_eq!(links.sources_to(&other, &ca(9)), vec![ca(7)]);
}

#[test]
fn sources_to_matches_a_target_by_coverage() {
    // AM's reverse-lookup rule: sources_to is the one member of the BH3
    // family matched by COVERAGE, so a target part-way through a multi-
    // element G extent is a hit — though that extent denotes no address at
    // all. MAKELINK builds it: the open surface has no shape gate.
    let k = kernel();
    seed_content(&k, &doc1(), 4);
    let w = writer(&k);
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 2)]), // one span, [ca2, ca4)
            SlotArg::Addrs(vec![unregistered_ta(13)]),      // a type is a number
        )
        .expect("makelink");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.type_slice(&unregistered_ty(13), View::Active).contains(&l));
    assert_eq!(
        links.sources_to(&unregistered_ty(13), &ca(2)),
        vec![ca(1)],
        "the extent's first tumbler"
    );
    assert_eq!(
        links.sources_to(&unregistered_ty(13), &ca(3)),
        vec![ca(1)],
        "mid-extent: no denotation reaches it, coverage does"
    );
    assert!(
        links.sources_to(&unregistered_ty(13), &ca(4)).is_empty(),
        "the extent is half-open"
    );
}

#[test]
fn target_of_matches_a_source_by_denotation() {
    // AM's source-vertex rule: target_of matches `source ∈ F.addrs()`, so a
    // tuple whose F merely COVERS the source is not that source's tuple —
    // ⊥, not the target a coverage match would hand back.
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 2)]), // one span, [ca1, ca3)
            SlotArg::Addrs(vec![ca(9)]),
            SlotArg::Addrs(vec![unregistered_ta(13)]),
        )
        .expect("makelink");
    let snap = k.snapshot();
    let links = snap.world().links();
    // The control: the tuple IS in the active typed slice and its F covers
    // the probe, so the ⊥ below is the matching rule and not an absent tuple.
    assert!(links.type_slice(&unregistered_ty(13), View::Active).contains(&l));
    let link = links.readlink(&l).expect("resident");
    assert!(link.from_slot().covers(ca(1).tumbler()));
    assert_eq!(
        links.target_of(&unregistered_ty(13), &ca(1)),
        None,
        "F covers ca(1) and denotes nothing"
    );
    assert!(links.targets_keyed(&ca(1)).is_empty());
}

#[test]
fn bh3_endpoint_reads_are_exact_over_the_active_typed_slice_and_the_join_covers_nothing() {
    // The BH3 endpoint pair answers by CLASS for any type number; only the
    // keyed JOIN reads declarations back, and no class in the compiled
    // shipped population declares ReverseLookup — so `targets_keyed` covers
    // nothing, however cleanly a class's tuples would qualify.
    let k = kernel();
    let w = writer(&k);
    let rel = unregistered_ty(13);
    let other = unregistered_ty(14);
    let deposit =
        |to: u32, ty: u32| open_deposit(&w, &[ca(1)], &[ca(to)], &[unregistered_ta(ty)]);
    deposit(2, 13);
    // A same-source tuple of ANOTHER type must not disturb the typed reads.
    deposit(3, 14);
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(links.target_of(&rel, &ca(1)), Some(ca(2)));
        assert_eq!(links.sources_to(&rel, &ca(2)), vec![ca(1)]);
        assert_eq!(links.target_of(&other, &ca(1)), Some(ca(3)));
        // The join is empty — not because these classes lack qualifying
        // tuples, but because nothing declares BH3 in this format.
        assert!(links.targets_keyed(&ca(1)).is_empty());
    }
    // A second active tuple of the same class denoting the same source makes
    // target_of ⊥ ("exactly one active K-tuple").
    deposit(4, 13);
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(links.target_of(&rel, &ca(1)), None);
    assert!(links.targets_keyed(&ca(1)).is_empty());
}

#[test]
fn a_nullified_tuple_leaves_every_active_typed_read() {
    // `nullify`'s postcondition — "gone from every View::Active slice … while
    // readlink and the Audit view keep it (R3)" — read back through the whole
    // §F surface. `observe` and `type_slice` are pinned elsewhere; these five
    // are not, and three of them (`is_k`, `sources_to`, `target_of`) hardcode
    // `View::Active`, so the constant can be flipped with nothing failing.
    let k = kernel();
    let w = writer(&k);
    let rel = unregistered_ty(11);
    let l = open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(11)]);
    {
        // The control: while it is active, every one of the five sees it.
        let snap = k.snapshot();
        let links = snap.world().links();
        assert!(links.is_k(&rel, ca(1).tumbler()));
        assert_eq!(links.members(&rel, View::Active), vec![ca(1)]);
        assert_eq!(links.targets_of(&rel, &ca(1), View::Active), vec![ca(2)]);
        assert_eq!(links.sources_to(&rel, &ca(2)), vec![ca(1)]);
        assert_eq!(links.target_of(&rel, &ca(1)), Some(ca(2)));
    }
    w.nullify(P1, &doc1(), &l).expect("retract the tuple");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(!links.is_k(&rel, ca(1).tumbler()), "D2 reads the active slice");
    assert!(
        links.members(&rel, View::Active).is_empty(),
        "D1 reads the active slice"
    );
    assert!(
        links.targets_of(&rel, &ca(1), View::Active).is_empty(),
        "D3 reads the active slice"
    );
    assert!(
        links.sources_to(&rel, &ca(2)).is_empty(),
        "BH3 reverse reads the active slice"
    );
    assert_eq!(
        links.target_of(&rel, &ca(1)),
        None,
        "BH3 forward reads the active slice"
    );

    // The audit half of the same postcondition — and `age`, whose `None` means
    // NON-RESIDENCE and nothing else, so a nullified resident still answers.
    assert!(links.readlink(&l).is_some(), "permanence: the value is kept");
    assert_eq!(links.observe(&rel, Pattern::default(), View::Audit).len(), 1);
    assert!(
        links.age(&l).is_some(),
        "age is residence-based, never activity-based"
    );
}

#[test]
fn target_of_recovers_determinacy_when_a_competing_tuple_is_retracted() {
    // "EXACTLY ONE ACTIVE type-ty tuple": restricting to the active slice is
    // what makes the count exact, and this is the direction where an Audit
    // reading is permanently wrong — two tuples make the projection ⊥, and
    // retracting one must make it determinate again rather than leaving it ⊥
    // for the life of the store.
    let k = kernel();
    let w = writer(&k);
    let rel = unregistered_ty(13);
    let first = open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(13)]);
    open_deposit(&w, &[ca(1)], &[ca(3)], &[unregistered_ta(13)]);
    {
        let snap = k.snapshot();
        assert_eq!(
            snap.world().links().target_of(&rel, &ca(1)),
            None,
            "two active matches ⇒ ⊥"
        );
    }
    w.nullify(P1, &doc1(), &first).expect("retract one of the two");
    let snap = k.snapshot();
    assert_eq!(
        snap.world().links().target_of(&rel, &ca(1)),
        Some(ca(3)),
        "one active match remains, so the projection is determinate again"
    );
}

#[test]
fn is_active_requires_residence_so_a_ghost_is_never_live() {
    // `is_active` is resident AND not nullified, and residence is the clause
    // no other call reaches — every other `is_active` in the suite is on a
    // resident address. A ghost is reachable through `current`, which echoes
    // the caller's own argument as its own sink (EL14), so a reader narrowing
    // on `CurrentMember.active` is exactly who a missing residence clause
    // would mislead.
    let k = kernel();
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(!links.is_active(&la(90)), "not resident, so not active");
    assert!(
        !links.is_nullified(&la(90)),
        "and not nullified either — the two clauses are independent"
    );
    let cur = links.current(&la(90));
    assert_eq!(cur.len(), 1, "the walk discloses its own argument as its sink");
    assert_eq!(cur[0].member, la(90));
    assert!(!cur[0].active, "and discloses it as inactive");
}

#[test]
fn targets_keyed_joins_only_the_reverse_lookup_classes() {
    // The join covers registered Binary classes DECLARING ReverseLookup — a
    // fact about registrations, so the registry names them. The shipped
    // Retraction class is Binary too, and a retraction tuple denotes its own
    // home in F, so a join that read shape alone would reach it here.
    let k = kernel();
    let w = writer(&k);
    let (target, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("target");
    w.nullify(P1, &doc1(), &target).expect("retract it from doc1");
    let snap = k.snapshot();
    let links = snap.world().links();
    // The control: that class DOES answer target_of for doc1, so its absence
    // from the join is the behavior scope and not an empty class.
    let retraction = retraction_ty();
    assert_eq!(links.target_of(&retraction, &doc1()), Some(target));
    assert!(links.targets_keyed(&doc1()).is_empty());
}

#[test]
fn age_answers_ungated_and_the_staleness_family_refuses_every_class() {
    // BH4 splits down the middle of its corpus name, and this format makes
    // the split total: `age` reads no registration and answers for any
    // resident link, while `stale` — and `retract_stale`, which builds its
    // batch from it — GATES on an Age declaration that no class in the
    // compiled shipped population carries (all five are idem⊤, and BH4
    // demands idem⊥). So the staleness family refuses every type a caller
    // can name, shipped and unregistered alike, and the refusal fires
    // pre-transact with nothing committed.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    // Three tuples on doc2's chain: ordinals 1..3.
    let (a1, _) = w.emit(P1, &doc2(), &pred_def_ty(), &ca(1), &[]).expect("a1");
    let (a2, _) = w.emit(P1, &doc2(), &pred_def_ty(), &ca(2), &[]).expect("a2");
    let (a3, _) = w.emit(P1, &doc2(), &pred_stable_ty(), &ca(3), &[]).expect("a3");
    let (newest, _) = w
        .makelink(
            P1,
            &doc2(),
            SlotArg::Addrs(vec![ca(4)]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(4)]),
        )
        .expect("an open deposit ages like any other");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        // age = home-relative chain distance (ordinal time): count 4 so far.
        assert_eq!(links.age(&a1), Some(3));
        assert_eq!(links.age(&a2), Some(2));
        assert_eq!(links.age(&a3), Some(1));
        assert_eq!(links.age(&newest), Some(0));
        assert_eq!(links.age(&ca(1)), None); // non-resident ⇒ None
        // stale refuses EVERY class: the registered idem⊤ five and an
        // unregistered number alike — an empty stale set is never conflated
        // with "not a BH4 type".
        assert_eq!(links.stale(&pred_def_ty(), 0), Err(NotBh4));
        assert_eq!(links.stale(&retired_ty(), 0), Err(NotBh4));
        assert_eq!(links.stale(&sup, 0), Err(NotBh4));
        assert_eq!(links.stale(&unregistered_ty(4), 0), Err(NotBh4));
    }
    // The batch nullifier rejects every ty PRE-TRANSACT: typed refusal, no
    // transaction, no effect — the fence that keeps it from ever being aimed
    // at an idem⊤/other class to mass-nullify, and in this format the whole
    // of the op's reachable behavior.
    let before = k.current_seq();
    assert!(matches!(
        w.retract_stale(P1, &doc2(), &pred_def_ty(), 0),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
    assert!(matches!(
        w.retract_stale(P1, &doc2(), &sup, 0),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
    assert!(matches!(
        w.retract_stale(P1, &doc2(), &unregistered_ty(4), 0),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
    // ...even at an unregistered home: NotBh4 outranks the home check, so
    // no transaction opens anywhere on this surface.
    assert!(matches!(
        w.retract_stale(P1, &a(&[1, 0, 1, 0, 7]), &pred_def_ty(), 2),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
    assert_eq!(k.current_seq(), before);
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(!links.is_nullified(&a1), "no batch ever fires");
}

#[test]
#[should_panic(expected = "level-uniform")]
fn stale_panics_on_an_off_contract_ty_rather_than_reaching_its_typed_refusal() {
    // `stale` classifies BEFORE the BH4 lookup, so a malformed `ty` is a
    // caller error and not a freshness answer: `NotBh4` means "this type does
    // not do staleness", and the typed rejection exists precisely so that
    // sentence is never said about something else.
    let k = kernel();
    let snap = k.snapshot();
    let skew = Endset::from_spans([
        skep_address::Span::new(t(&[5, 3]), t(&[0, 2, 7])).expect("T12 admits this span")
    ]);
    let _ = snap.world().links().stale(&skew, 0);
}
