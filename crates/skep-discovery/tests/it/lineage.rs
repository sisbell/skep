//! §7 — archival supersession lineage: the flipped probes behind the
//! resident-key gate, the class they restrict to, what one claim says, the
//! claims of that class with an undefined endpoint, the claims that only
//! cover a key they do not name, the endpoint no probe asks about, and the
//! home every claim has, which the store's fold guarantees.

use crate::common;

use std::panic::{catch_unwind, AssertUnwindSafe};

use common::*;
use serde::Serialize;
use skep_address::{document_of, is_prefix, subtree_of, validate, Address, Tumbler};
use skep_discovery::{in_claims_on, SupClaim, FROM, TO};
use skep_kernel::{Kernel, TxnError};
use skep_links::{
    enc, EditLinkError, Endset, HasLinks, Link, LinkRec, LinkWriter, MakeLinkError, Pattern,
    ShippedType, SlotArg, View,
};

#[test]
fn lineage_probes_flipped_slots_with_residence_gate() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store.assert_sup(SYS, &doc1(), &e1, &e2).expect("assert_sup succeeds");

    let expected = SupClaim {
        claim: claim.clone(),
        old: e1.clone(),
        new: e2.clone(),
        home: doc1(),
        active: true,
    };
    // Flipped storage: in(y) = old probes FROM; out(x) = new probes TO.
    assert_eq!(reads.in_claims(&e1, View::Active), vec![expected.clone()]);
    assert_eq!(reads.out_claims(&e2, View::Active), vec![expected.clone()]);
    assert_eq!(reads.in_claims(&e2, View::Active), vec![]);
    assert_eq!(reads.out_claims(&e1, View::Active), vec![]);
    // Default behaves as Active (M7's reads coerce it) — asserted here while
    // the claim is live, where Audit answers the same; the assertion that
    // separates them follows the retraction.
    assert_eq!(reads.in_claims(&e1, View::Default), vec![expected]);

    // Resident-key gate. A non-link key under e1 or e2 is COVERED by the
    // claim's F (or G), `enc([endpoint])`, so `observe` reaches the claim
    // through it, and it answers [] twice over: the gate refuses the key
    // before the class is walked, and the read-out's equality would refuse
    // the claim, whose endpoint is not that key. Where the gate ALONE
    // decides is a claim whose endpoint IS a non-link key, which no writer
    // deposits; a decoded-deposit test below folds one. doc1 and ca(1), above
    // and beside the endpoints, reach no claim at all.
    let under_e1 = a(&[1, 0, 1, 0, 1, 0, 2, 1, 1]);
    let under_e2 = a(&[1, 0, 1, 0, 1, 0, 2, 2, 1]);
    assert!(is_prefix(e1.tumbler(), under_e1.tumbler()));
    assert!(is_prefix(e2.tumbler(), under_e2.tumbler()));
    assert_eq!(reads.in_claims(&under_e1, View::Active), vec![]);
    assert_eq!(reads.out_claims(&under_e2, View::Active), vec![]);
    assert_eq!(reads.in_claims(&doc1(), View::Active), vec![]);
    assert_eq!(reads.in_claims(&ca(1), View::Active), vec![]);

    // Nullifying the claim removes it from the operative graph but keeps it
    // in the audit history, with its own activity disclosed honestly — asked
    // of BOTH probes, since `Audit` is the only view that tells a passed-
    // through argument from a hard-coded `Active`, and every other
    // `out_claims` here asks `Active` or `Default`, which coerces to it.
    store.nullify(SYS, &doc2(), &claim).expect("nullify succeeds");
    assert_eq!(reads.in_claims(&e1, View::Active), vec![]);
    let in_audit = reads.in_claims(&e1, View::Audit);
    assert_eq!(in_audit.len(), 1);
    assert_eq!(in_audit[0].claim, claim);
    assert!(!in_audit[0].active);
    assert_eq!(reads.out_claims(&e2, View::Active), vec![]);
    let out_audit = reads.out_claims(&e2, View::Audit);
    assert_eq!(out_audit.len(), 1);
    assert_eq!(out_audit[0].claim, claim);
    assert!(!out_audit[0].active);
    // After the retraction Active and Audit part — the one state where
    // "Default reads as Active" can be told from "Default reads as Audit".
    assert_eq!(reads.in_claims(&e1, View::Default), vec![]);
    assert_eq!(reads.out_claims(&e2, View::Default), vec![]);
}

/// §7 — `home` is the CLAIM's own attribution (EL8b), never an endpoint's.
/// `assert_sup` requires ω on the home and on nothing else, so a claim can be
/// asserted in a document its endpoints do not live in — the one shape where
/// a home read off the claim and a home read off `old` (which sits three
/// lines away in the same read-out) disagree. Every other lineage fixture
/// asserts in the document the endpoints were minted in, where the right
/// answer and the wrong one coincide.
#[test]
fn lineage_attributes_a_claim_to_its_own_home_not_its_endpoints() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store
        .assert_sup(SYS, &doc2(), &e1, &e2)
        .expect("assert_sup succeeds");
    assert_eq!(claim, la2(1), "the claim is minted in doc2's link chain");

    assert_eq!(
        reads.in_claims(&e1, View::Active),
        vec![SupClaim {
            claim,
            old: e1,
            new: e2,
            home: doc2(), // NOT doc1, where both endpoints are homed
            active: true,
        }]
    );
}

/// §7 — the view filters CLAIMS, never their endpoints: under any view a
/// claim's `old`/`new` are the addresses it NAMES, read out as recorded, so a
/// live claim can name a nullified link and `active` stays the claim's own.
/// And the enumeration's gate asks RESIDENT, not active — a nullified link
/// is still resident, so it is still a legal probe key. Every other lineage
/// case nullifies the claim; neither promise is watched by that.
#[test]
fn a_live_claim_names_a_nullified_endpoint_and_a_nullified_key_still_probes() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store
        .assert_sup(SYS, &doc1(), &e1, &e2)
        .expect("assert_sup succeeds");
    store.nullify(SYS, &doc2(), &e2).expect("nullify succeeds");

    // The premise: the ENDPOINT is retracted, and the claim naming it is not.
    let snap = k.snapshot();
    assert!(!snap.world().links().is_active(&e2));
    assert!(snap.world().links().is_active(&claim));

    assert_eq!(
        reads.in_claims(&e1, View::Active),
        vec![SupClaim {
            claim: claim.clone(),
            old: e1,
            new: e2.clone(),
            home: doc1(),
            active: true,
        }]
    );
    // A nullified link is resident, so it is still a legal probe key: the
    // gate asks resident, not active.
    assert_eq!(claims_of(reads.out_claims(&e2, View::Active)), vec![claim]);
}

/// §7 — the lineage read-out is in ascending CLAIM-address order, the same
/// permanent key every enumeration here reads out by, off both probes: two
/// claims naming one `old`, and two naming one `new`, come back ordered, not
/// in whatever order the index handed them over.
#[test]
fn lineage_reads_out_in_claim_address_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let mut made = Vec::new();
    for to in [ca(101), ca(102), ca(103)] {
        let e = link(&store, &doc1(), &[ca(1)], &[to]);
        made.push(e);
    }
    // Two successors of one superseded link: two claims, both probed by in().
    let (c1, _) = store
        .assert_sup(SYS, &doc1(), &made[0], &made[1])
        .expect("assert_sup succeeds");
    let (c2, _) = store
        .assert_sup(SYS, &doc1(), &made[0], &made[2])
        .expect("assert_sup succeeds");
    // And a second claim naming made[2] as new, so the TO probe has an order
    // of its own to read out.
    let (c3, _) = store
        .assert_sup(SYS, &doc1(), &made[1], &made[2])
        .expect("assert_sup succeeds");
    assert!(c1 < c2 && c2 < c3, "later claims mint later addresses");

    assert_eq!(
        claims_of(reads.in_claims(&made[0], View::Active)),
        vec![c1.clone(), c2.clone()]
    );
    // out() reads the same order off the TO probe: made[2] is `new` to two
    // claims, made[1] to one.
    assert_eq!(
        claims_of(reads.out_claims(&made[2], View::Active)),
        vec![c2, c3]
    );
    assert_eq!(claims_of(reads.out_claims(&made[1], View::Active)), vec![c1]);
}

/// §7 — the enumeration reads out SUPERSESSION claims alone. A type-blind
/// probe of the key — M7's `match_links`, which the premise below asks —
/// reaches every link naming it at the slot, whatever its type, so an
/// ordinary link naming `e1` at FROM and `e2` at TO is there for a read that
/// asked the store instead of the class. It is the one shape that tells the
/// two apart: every other lineage fixture's endpoints are named by
/// supersession claims alone, where they agree.
#[test]
fn lineage_reads_out_supersession_claims_alone_among_the_links_naming_the_key() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    // Of the suite's relation type, and shaped exactly like a claim over e1→e2.
    let ordinary = link(
        &store,
        &doc1(),
        std::slice::from_ref(&e1),
        std::slice::from_ref(&e2),
    );
    let (claim, _) = store
        .assert_sup(SYS, &doc1(), &e1, &e2)
        .expect("assert_sup succeeds");

    // The premise: a type-blind probe reaches the ordinary link as well as
    // the claim, so a read that asked the store rather than the class would
    // have it to return.
    let snap = k.snapshot();
    let links = snap.world().links();
    for (slot, key) in [(FROM, &e1), (TO, &e2)] {
        let probed = links.match_links(&[(slot, &enc([key]))], View::Active);
        assert!(
            probed.contains(&ordinary) && probed.contains(&claim),
            "the probe at slot {slot} reaches both"
        );
    }

    let only_the_claim = vec![SupClaim {
        claim,
        old: e1.clone(),
        new: e2.clone(),
        home: doc1(),
        active: true,
    }];
    assert_eq!(reads.in_claims(&e1, View::Active), only_the_claim);
    assert_eq!(reads.out_claims(&e2, View::Active), only_the_claim);
}

/// §7 — the lineage read-out reports a `[K_sup]` claim only where its `old`
/// and `new` are defined, and what makes it report EVERY claim a writer
/// deposits is a fence on the WRITE surface: every claim a writer deposits
/// carries unit-depth single-address F and G, so Ŝ^Σ = S^Σ and the read-out
/// skips nothing. That fence is held at sites M8 cannot see and cannot ask
/// about, so what M8 can do is pin it: the two routes by which a caller-shaped
/// tuple could reach the `[K_sup]` class are closed, in the build where a
/// change to either would surface as this test rather than as a deposit the
/// lineage read then skips.
///
/// The open route is `editlink`, whose successor is the caller's: its DC
/// guard asks the part of the schema EL4's `old` and `new` are defined by,
/// and the schema's remaining clauses beside it — the two endpoints distinct,
/// both resident — so a successor with a two-address F is refused rather
/// than deposited. `makelink` refuses the class outright.
#[test]
fn lineage_endpoints_rest_on_a_fence_the_write_surface_keeps() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);

    // The reserved Supersedes type, read off the store rather than spelled:
    // the ghost tumbler is the compiled format constant, and the two are
    // asserted equal so the fixture below names the class M7 recognizes.
    let sup = k
        .snapshot()
        .world()
        .links()
        .reserved_type(ShippedType::Supersedes)
        .clone();
    assert_eq!(sup, enc(&[ra(4)]), "Supersedes is ghost position 4");

    // The open surface refuses the class outright, so no MAKELINK can deposit
    // a [K_sup] tuple of any shape.
    assert!(matches!(
        store.makelink(
            SYS,
            &doc1(),
            SlotArg::Addrs(vec![e1.clone()]),
            SlotArg::Addrs(vec![e2.clone()]),
            SlotArg::Addrs(vec![ra(4)]),
        ),
        Err(TxnError::Rejected(MakeLinkError::SupersessionClass))
    ));

    // The caller-supplied route is gated by the schema the read-out reads
    // back: a [K_sup]-typed successor whose F denotes TWO addresses — the
    // shape `single_denoted` answers `None` for — is refused.
    let two = enc(&[e1.clone(), e2.clone()]);
    assert!(two.single_denoted().is_none(), "F denotes two addresses");
    assert!(matches!(
        store.editlink(
            SYS,
            &e1,
            Link::triple(two, enc(&[e2]), sup),
            &doc1(),
            &doc1(),
        ),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));

    // And the schema-conforming edit IS admitted, so the fence above is a
    // fence and not a closed door: the claim it deposits reads back through
    // the lineage surface with both endpoints named.
    let (edit, _) = store
        .editlink(
            SYS,
            &e1,
            Link::triple(enc(&[ca(1)]), enc(&[ca(103)]), rel_ty()),
            &doc1(),
            &doc1(),
        )
        .expect("a schema-conforming successor is admitted");
    let reads = Reads(&k);
    assert_eq!(
        reads.in_claims(&e1, View::Active),
        vec![SupClaim {
            claim: edit.claim,
            old: e1,
            new: edit.successor,
            home: doc1(),
            active: true,
        }]
    );
}

/// §7 — the read-out reports a claim only where its `old` and `new` are
/// defined: a `[K_sup]` claim whose endpoint slot is not in Df-DISC(ii)'s
/// canonical form — unit-depth spans alone, denoting one address — is a
/// non-conformer, in S^Σ and outside the schema-conforming claims Ŝ^Σ
/// ASN-0125's read ranges over, and is skipped, never a fault. No M7 writer
/// deposits one — the fence test above pins that — but M7's fold admits one,
/// and a restored checkpoint or a replayed journal frame reaches the fold
/// through serde, which checks a link's arity and nothing of the schema. So
/// three such claims are folded here the way a decoded frame would be, beside
/// one conforming claim: one whose F denotes TWO addresses; one whose G
/// denotes doc1's ELEMENT-FIELD PREFIX — doc1 and the zero that opens its
/// element field, so a tumbler with a trailing zero, which is no address —
/// whose subtree covers every link of doc1; and one whose F denotes `e1`
/// alone, beside a span that is not unit-depth. Both probes reach all four
/// claims under both views, and answer the conforming one alone; a read-out
/// that took every claim's endpoints for defined, or read an endpoint off the
/// one address its slot denotes whatever else the slot carries, would fail
/// these probes for as long as the non-conformers are stored. The home rule
/// is asked past that check, so only of the claim reported.
#[test]
fn lineage_skips_a_supersession_claim_with_an_undefined_endpoint() {
    let fixture = OneClaim::new();
    let two = enc([&fixture.e1, &fixture.e2]);
    assert!(two.single_denoted().is_none(), "F denotes two addresses");
    fold_decoded_deposit(
        &fixture.k,
        &la(8),
        Link::triple(two, enc([&fixture.e2]), fixture.sup.clone()),
    );
    let prefix = t(&[1, 0, 1, 0, 1, 0]);
    assert!(
        validate(prefix.clone()).is_err(),
        "a trailing zero is no address"
    );
    let no_address = Endset::from_spans([subtree_of(&prefix)]);
    assert_eq!(
        no_address.single_denoted(),
        Some(&prefix),
        "G denotes it alone"
    );
    fold_decoded_deposit(
        &fixture.k,
        &la(9),
        Link::triple(enc([&fixture.e1]), no_address, fixture.sup.clone()),
    );
    // A third whose F DENOTES one address — `e1`, the start of its one
    // unit-depth span — beside a span that is not unit-depth, so it is not
    // the schema's canonical form and its `old` is undefined.
    let mixed = Endset::from_spans([subtree_of(fixture.e1.tumbler()), run(&ca(1), 3).iextent()]);
    assert_eq!(
        mixed.addrs().collect::<Vec<_>>(),
        vec![fixture.e1.tumbler()],
        "F denotes e1 alone"
    );
    assert!(
        mixed.single_denoted().is_none(),
        "and is not unit-depth throughout"
    );
    fold_decoded_deposit(
        &fixture.k,
        &la(10),
        Link::triple(mixed, enc([&fixture.e2]), fixture.sup.clone()),
    );

    // The premise: each probe reaches all four claims, so the answers
    // below are the read-out's and not the probes'.
    let snap = fixture.k.snapshot();
    let old_probe = [fixture.e1.tumbler().clone()];
    let new_probe = [fixture.e2.tumbler().clone()];
    for view in [View::Active, View::Audit] {
        for pattern in [
            Pattern {
                from: &old_probe,
                ..Pattern::default()
            },
            Pattern {
                to: &new_probe,
                ..Pattern::default()
            },
        ] {
            let reached: Vec<Address> = snap
                .world()
                .links()
                .observe(&fixture.sup, pattern, view)
                .into_iter()
                .map(|t| t.addr)
                .collect();
            assert_eq!(
                reached,
                vec![fixture.claim.clone(), la(8), la(9), la(10)],
                "{pattern:?} under {view:?}"
            );
        }
    }

    // The three non-conformers are skipped: the conforming claim is answered
    // alone, and the home rule is asked of it alone.
    fixture.assert_answered_alone();
}

/// §7 — a claim is read out only where the endpoint its probe names IS the
/// key. `observe` matches by COVERAGE, and a `[K_sup]` claim naming a
/// DOCUMENT at both ends — one T4-valid address a side, so its `old` and
/// `new` are defined — covers every link that document homes. No M7 writer
/// deposits one, but M7's fold admits one, as a restored checkpoint or a
/// replayed journal frame reaches it: both probes reach it beside the
/// conforming claim and answer the conforming claim alone, where a read-out
/// that took coverage for denotation would report a claim whose `old` and
/// `new` are doc1. Beside it, a claim naming a link address no deposit
/// minted is the resident-key gate's alone to refuse: its endpoint IS the key
/// it is probed by, and that key is no resident link. The home rule is asked
/// past both, so only of the claim reported.
#[test]
fn lineage_reads_out_a_claim_only_where_its_endpoint_is_the_key() {
    let fixture = OneClaim::new();

    // A claim naming doc1 at both ends: one T4-valid address a side, so its
    // `old` and `new` are defined, and above every link doc1 homes, so it
    // COVERS both endpoints of the conforming claim.
    let doc = doc1();
    let above = enc([&doc]);
    assert_eq!(
        above.single_denoted(),
        Some(doc.tumbler()),
        "one T4-valid address"
    );
    fold_decoded_deposit(
        &fixture.k,
        &la(8),
        Link::triple(above.clone(), above, fixture.sup.clone()),
    );
    // And a claim naming, at both ends, a link address no deposit minted.
    let unminted = la(99);
    let named = enc([&unminted]);
    fold_decoded_deposit(
        &fixture.k,
        &la(9),
        Link::triple(named.clone(), named, fixture.sup.clone()),
    );

    // The premise: each probe of a conforming endpoint reaches the conforming
    // claim AND the document-naming one, and a probe of the unminted address
    // reaches the claim naming it, which no deposit made a resident link.
    let snap = fixture.k.snapshot();
    let links = snap.world().links();
    let reached = |pattern: Pattern<'_>| -> Vec<Address> {
        links
            .observe(&fixture.sup, pattern, View::Active)
            .into_iter()
            .map(|t| t.addr)
            .collect()
    };
    let old_probe = [fixture.e1.tumbler().clone()];
    let new_probe = [fixture.e2.tumbler().clone()];
    let unminted_probe = [unminted.tumbler().clone()];
    assert_eq!(
        reached(Pattern {
            from: &old_probe,
            ..Pattern::default()
        }),
        vec![fixture.claim.clone(), la(8)]
    );
    assert_eq!(
        reached(Pattern {
            to: &new_probe,
            ..Pattern::default()
        }),
        vec![fixture.claim.clone(), la(8)]
    );
    assert_eq!(
        reached(Pattern {
            from: &unminted_probe,
            ..Pattern::default()
        }),
        vec![la(8), la(9)]
    );
    assert!(links.readlink(&unminted).is_none(), "no deposit minted it");

    // The conforming claim is answered alone. The document-naming claim is
    // homed in doc1 too, so a home rule asked ahead of the denotation filter
    // would show as a second ask of doc1.
    fixture.assert_answered_alone();
    // And a probe of the unminted address answers no claim, though one names
    // it: the resident-key gate refuses a key that is no resident link.
    let reads = Reads(&fixture.k);
    for view in [View::Active, View::Audit] {
        assert_eq!(
            reads.in_claims(&unminted, view),
            vec![],
            "in_claims of the unminted address, {view:?}"
        );
        assert_eq!(
            reads.out_claims(&unminted, view),
            vec![],
            "out_claims of the unminted address, {view:?}"
        );
    }
}

/// §7 — the read checks the endpoint its probe names and not the other, as
/// `in_claims_on` states: a claim whose probed endpoint IS the resident key
/// is returned whatever its other endpoint is — an address that is no
/// resident link, or the key itself. No M7 writer deposits either
/// (`assert_sup` asks both endpoints' residence and their distinctness, and
/// `editlink`'s DC guard asks the same of a caller's successor), but M7's fold
/// admits both, as a restored checkpoint or a replayed journal frame reaches
/// it. The unminted endpoint, probed in its turn, is the resident-key gate's
/// to refuse; the reflexive claim answers both probes of the key.
#[test]
fn lineage_checks_the_endpoint_its_probe_names_and_not_the_other() {
    let fixture = OneClaim::new();
    let unminted = la(99);
    fold_decoded_deposit(
        &fixture.k,
        &la(8),
        Link::triple(enc([&fixture.e1]), enc([&unminted]), fixture.sup.clone()),
    );
    fold_decoded_deposit(
        &fixture.k,
        &la(9),
        Link::triple(enc([&fixture.e1]), enc([&fixture.e1]), fixture.sup.clone()),
    );
    assert!(
        fixture
            .k
            .snapshot()
            .world()
            .links()
            .readlink(&unminted)
            .is_none(),
        "no deposit minted it"
    );

    // Every claim here supersedes `e1`; they differ in the `new` they name.
    let superseding_e1 = |claim: Address, new: &Address| SupClaim {
        claim,
        old: fixture.e1.clone(),
        new: new.clone(),
        home: doc1(),
        active: true,
    };
    let reads = Reads(&fixture.k);
    for view in [View::Active, View::Audit] {
        assert_eq!(
            reads.in_claims(&fixture.e1, view),
            vec![
                superseding_e1(fixture.claim.clone(), &fixture.e2),
                superseding_e1(la(8), &unminted),
                superseding_e1(la(9), &fixture.e1),
            ],
            "in_claims of e1, {view:?}"
        );
        assert_eq!(
            reads.out_claims(&fixture.e1, view),
            vec![superseding_e1(la(9), &fixture.e1)],
            "out_claims of e1, {view:?}"
        );
        assert_eq!(
            reads.out_claims(&unminted, view),
            vec![],
            "out_claims of the unminted address, {view:?}"
        );
    }
}

/// §7 — a claim's HOME is the store's to guarantee, and the read-out asserts
/// it rather than testing it: every key of M7's store has a home (EL8b),
/// because the fold that admits a deposit — the one a replayed journal frame
/// reaches, beside the one that rebuilds a restored checkpoint — fail-stops
/// on a key with none. So a `[K_sup]` claim decoded from M2's bytes at an
/// ACCOUNT address, which has no document field, is refused by the fold
/// itself and never becomes a claim the read-out could meet homeless, and the
/// store is left as it was; the same claim keyed at a link address of doc1
/// folds and reads out, so the key's home is all the fold refused. This is
/// the fence the read-out's assertion rests on, pinned where a change to it
/// surfaces as this test rather than as that assertion firing on a probe.
#[test]
fn lineage_asserts_the_home_m7s_fold_gives_every_claim() {
    let fixture = OneClaim::new();
    let value = Link::triple(enc([&fixture.e1]), enc([&fixture.e2]), fixture.sup.clone());

    let account = a(&[1, 0, 1]);
    assert_eq!(document_of(&account), None, "an account has no home");
    let folded = catch_unwind(AssertUnwindSafe(|| {
        fold_decoded_deposit(&fixture.k, &account, value.clone())
    }));
    assert!(folded.is_err(), "the fold refuses a key with no home");

    // The store is as it was: the conforming claim is answered alone.
    fixture.assert_answered_alone();

    // The same claim keyed at a link address of doc1 folds, and reads out.
    fold_decoded_deposit(&fixture.k, &la(8), value);
    assert_eq!(
        claims_of(Reads(&fixture.k).in_claims(&fixture.e1, View::Active)),
        vec![fixture.claim.clone(), la(8)]
    );
}

/// The world the decoded-deposit tests fold into: two links of doc1, `e1` and
/// `e2`, the one conforming claim over them, and the supersession class's
/// type, read off the store. Whatever a test folds beside that claim,
/// [`OneClaim::assert_answered_alone`] is the verdict that must still hold.
struct OneClaim {
    k: Kernel<World>,
    e1: Address,
    e2: Address,
    claim: Address,
    sup: Endset,
}

impl OneClaim {
    fn new() -> OneClaim {
        let k = kernel();
        seed_content(&k, &doc1(), 1);
        let (e1, e2, claim) = {
            let store = LinkWriter::new(&k, &EVERYONE);
            let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
            let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
            let (claim, _) = store
                .assert_sup(SYS, &doc1(), &e1, &e2)
                .expect("assert_sup succeeds");
            (e1, e2, claim)
        };
        let sup = k
            .snapshot()
            .world()
            .links()
            .reserved_type(ShippedType::Supersedes)
            .clone();
        OneClaim {
            k,
            e1,
            e2,
            claim,
            sup,
        }
    }

    /// The lineage pair answers the conforming claim alone: `in(e1)` and
    /// `out(e2)`, under both views, return it and nothing folded beside it,
    /// and the reader's predicate is asked once, of its home — never of a
    /// claim the read did not report.
    fn assert_answered_alone(&self) {
        let only_the_claim = vec![SupClaim {
            claim: self.claim.clone(),
            old: self.e1.clone(),
            new: self.e2.clone(),
            home: doc1(),
            active: true,
        }];
        let reads = Reads(&self.k);
        for view in [View::Active, View::Audit] {
            assert_eq!(
                reads.in_claims(&self.e1, view),
                only_the_claim,
                "in_claims, {view:?}"
            );
            assert_eq!(
                reads.out_claims(&self.e2, view),
                only_the_claim,
                "out_claims, {view:?}"
            );
        }
        let asked = Asked::default();
        let recorder = asked.recorder();
        assert_eq!(
            in_claims_on(&self.k.snapshot(), &self.e1, View::Active, &recorder),
            only_the_claim
        );
        assert_eq!(asked.take(), vec![doc1()], "asked of its home alone");
    }
}

/// Fold one `LinkRec::Deposit` of `value` at `addr` into the kernel's world
/// the way a restored checkpoint or a replayed journal frame reaches M7's
/// fold: decoded from M2's own bincode bytes, with none of M7's write gates
/// in between. `LinkRec` is `#[non_exhaustive]`, so no crate but M7 builds
/// one; its bytes are written here from `RawLinkRec`, a local mirror of its
/// one variant — the same variant index and fields, so the same encoding —
/// and decoded back as the real record.
fn fold_decoded_deposit(k: &Kernel<World>, addr: &Address, value: Link) {
    #[derive(Serialize)]
    enum RawLinkRec {
        Deposit { addr: Tumbler, value: Link },
    }
    let raw = RawLinkRec::Deposit {
        addr: addr.tumbler().clone(),
        value,
    };
    let bytes = bincode::serialize(&raw).expect("the raw deposit serializes");
    let rec: LinkRec = bincode::deserialize(&bytes).expect("M2's bytes decode as a LinkRec");
    k.transact(&[], |staging| {
        staging.push(Record::Links(rec));
        Ok::<(), ()>(())
    })
    .expect("the decoded deposit folds");
}
