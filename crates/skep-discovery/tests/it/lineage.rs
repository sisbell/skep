//! §7 — archival supersession lineage: the flipped probes behind the
//! resident-key gate, the class they restrict to, and what one claim says.

use crate::common;

use common::*;
use skep_address::Address;
use skep_discovery::{LinkQuery, SupClaim, FROM, TO};
use skep_kernel::TxnError;
use skep_links::{
    enc, EditLinkError, HasLinks, Link, LinkWriter, MakeLinkError, ShippedType, SlotArg, View,
};

#[test]
fn lineage_probes_flipped_slots_with_residence_gate() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
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
    assert_eq!(lq.in_claims(&e1, View::Active), vec![expected.clone()]);
    assert_eq!(lq.out_claims(&e2, View::Active), vec![expected.clone()]);
    assert_eq!(lq.in_claims(&e2, View::Active), vec![]);
    assert_eq!(lq.out_claims(&e1, View::Active), vec![]);
    // Default behaves as Active (M7's §G primitives coerce it) — asserted
    // here while the claim is live, where Audit answers the same; the
    // assertion that separates them follows the retraction.
    assert_eq!(lq.in_claims(&e1, View::Default), vec![expected]);

    // Resident-key gate: a non-link key returns [] — without it, doc1's
    // prefix coverage would over-match the claim (whose endpoints live under
    // doc1).
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
    // After the retraction Active and Audit part — the one state where
    // "Default reads as Active" can be told from "Default reads as Audit".
    assert_eq!(lq.in_claims(&e1, View::Default), vec![]);
    assert_eq!(lq.out_claims(&e2, View::Default), vec![]);
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
    let lq = LinkQuery::new(&k, &every_home);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store
        .assert_sup(SYS, &doc2(), &e1, &e2)
        .expect("assert_sup succeeds");
    assert_eq!(claim, la2(1), "the claim is minted in doc2's link chain");

    assert_eq!(
        lq.in_claims(&e1, View::Active),
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
    let lq = LinkQuery::new(&k, &every_home);
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
        lq.in_claims(&e1, View::Active),
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
    assert_eq!(
        lq.out_claims(&e2, View::Active)
            .into_iter()
            .map(|c| c.claim)
            .collect::<Vec<_>>(),
        vec![claim]
    );
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
    let lq = LinkQuery::new(&k, &every_home);
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

    let claims: Vec<Address> = lq
        .in_claims(&made[0], View::Active)
        .into_iter()
        .map(|c| c.claim)
        .collect();
    assert_eq!(claims, vec![c1.clone(), c2.clone()]);
    // out() reads the same order off the TO probe: made[2] is `new` to two
    // claims, made[1] to one.
    let claims_of =
        |found: Vec<SupClaim>| -> Vec<Address> { found.into_iter().map(|c| c.claim).collect() };
    assert_eq!(
        claims_of(lq.out_claims(&made[2], View::Active)),
        vec![c2, c3]
    );
    assert_eq!(claims_of(lq.out_claims(&made[1], View::Active)), vec![c1]);
}

/// §7 — the enumeration reads out SUPERSESSION claims alone. M7's probe finds
/// every link naming the key at the slot, whatever its type, and the
/// `[K_sup]` class is what narrows it — so an ordinary link naming `e1` at
/// FROM and `e2` at TO, which both probes reach, must never come back as a
/// claim. It is the one shape that tells a read restricting to the class from
/// one reading out every hit: every other lineage fixture's endpoints are
/// named by supersession claims alone, where the two agree.
#[test]
fn lineage_reads_out_supersession_claims_alone_among_the_links_naming_the_key() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
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

    // The premise: both probes reach the ordinary link as well as the claim,
    // so the restriction has something to drop.
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
    assert_eq!(lq.in_claims(&e1, View::Active), only_the_claim);
    assert_eq!(lq.out_claims(&e2, View::Active), only_the_claim);
}

/// §7 — the lineage read-out reports a claim's endpoints with NO per-claim
/// conformance filter, and cannot fault because every stored `[K_sup]` tuple
/// carries unit-depth single-address F and G. That is a fence on the WRITE
/// surface, held at sites M8 cannot see and cannot ask about, so what M8 can
/// do is pin its own reliance: the two routes by which a caller-shaped tuple
/// could reach the `[K_sup]` class are closed, in the build where a change to
/// either would surface as this test rather than as a panic in `claim_at`.
///
/// The open route is `editlink`, whose successor is the caller's: its DC
/// guard is the very predicate the read-out applies, so a successor with a
/// two-address F is refused rather than deposited. `makelink` refuses the
/// class outright.
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
    let lq = LinkQuery::new(&k, &every_home);
    assert_eq!(
        lq.in_claims(&e1, View::Active),
        vec![SupClaim {
            claim: edit.claim,
            old: e1,
            new: edit.successor,
            home: doc1(),
            active: true,
        }]
    );
}
