//! §7 — archival supersession lineage: the flipped probes behind the
//! resident-key gate, the class they restrict to, what one claim says, and
//! the tuples of that class that are no claim.

use crate::common;

use std::cell::RefCell;

use common::*;
use serde::Serialize;
use skep_address::{is_prefix, subtree_of, validate, Address, Tumbler};
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

    // Resident-key gate. The claim's F (or G) is `enc([endpoint])`, which
    // COVERS every address beneath the endpoint, so a non-link key under e1
    // or e2 is the one the gate exists for: without it the claim would come
    // back as naming that key. doc1 and ca(1), above and beside the
    // endpoints, are no claim's endpoint either, and answer [] all the same.
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
    let audit = reads.in_claims(&e1, View::Audit);
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].claim, claim);
    assert!(!audit[0].active);
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
    assert_eq!(
        reads.out_claims(&e2, View::Active)
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

    let claims: Vec<Address> = reads
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

/// §7 — the lineage read-out reports a `[K_sup]` tuple only as a claim it
/// recognizes, and what makes it report EVERY claim a writer deposits is a
/// fence on the WRITE surface: every tuple a writer deposits carries
/// unit-depth single-address F and G, so Ŝ^Σ = S^Σ and the recognition skips
/// nothing. That fence is held at sites M8 cannot see and cannot ask about,
/// so what M8 can do is pin it: the two routes by which a caller-shaped tuple
/// could reach the `[K_sup]` class are closed, in the build where a change to
/// either would surface as this test rather than as a deposit the lineage
/// read then skips as no claim.
///
/// The open route is `editlink`, whose successor is the caller's: its DC
/// guard asks the part of the schema the read-out recognizes a claim by, and
/// the schema's remaining clauses beside it — the two endpoints distinct,
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

/// §7 — the read-out RECOGNIZES a claim before it reports one: a `[K_sup]`
/// tuple whose endpoint is not one address is no claim of the
/// schema-conforming class ASN-0125's read ranges over, and is skipped, never
/// a fault. No M7 writer deposits one — the fence test above pins that — but
/// M7's fold admits one, and a restored checkpoint or a replayed journal frame
/// reaches the fold through serde, which checks a link's arity and nothing of
/// the schema. So two such tuples are folded here the way a decoded frame
/// would be, beside one conforming claim: one whose F denotes TWO addresses,
/// and one whose G denotes doc1's link-subspace PREFIX — a tumbler with a
/// trailing zero, so no address, whose subtree covers every link of doc1.
/// Both probes reach all three tuples under both views, and answer the claim
/// alone; a read-out that took every tuple for a claim would fail each of
/// these probes for as long as the tuples are stored. The home rule is asked
/// past the recognition, so only of the claim reported.
#[test]
fn lineage_skips_a_supersession_tuple_that_is_not_a_claim() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store
        .assert_sup(SYS, &doc1(), &e1, &e2)
        .expect("assert_sup succeeds");
    let sup = k
        .snapshot()
        .world()
        .links()
        .reserved_type(ShippedType::Supersedes)
        .clone();

    let two = enc([&e1, &e2]);
    assert!(two.single_denoted().is_none(), "F denotes two addresses");
    fold_decoded_deposit(&k, &la(8), Link::triple(two, enc([&e2]), sup.clone()));
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
        &k,
        &la(9),
        Link::triple(enc([&e1]), no_address, sup.clone()),
    );

    // The premise: each probe reaches the claim AND both tuples, so the
    // answers below are the recognition's and not the probes'.
    let snap = k.snapshot();
    let old_probe = [e1.tumbler().clone()];
    let new_probe = [e2.tumbler().clone()];
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
                .observe(&sup, pattern, view)
                .into_iter()
                .map(|t| t.addr)
                .collect();
            assert_eq!(
                reached,
                vec![claim.clone(), la(8), la(9)],
                "{pattern:?} under {view:?}"
            );
        }
    }

    let only_the_claim = vec![SupClaim {
        claim,
        old: e1.clone(),
        new: e2.clone(),
        home: doc1(),
        active: true,
    }];
    let reads = Reads(&k);
    for view in [View::Active, View::Audit] {
        assert_eq!(
            reads.in_claims(&e1, view),
            only_the_claim,
            "in_claims, {view:?}"
        );
        assert_eq!(
            reads.out_claims(&e2, view),
            only_the_claim,
            "out_claims, {view:?}"
        );
    }

    // Asked once, of the reported claim's home — not of the two tuples skipped.
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    let recorder = |d: &Address| {
        asked.borrow_mut().push(d.clone());
        true
    };
    assert_eq!(
        in_claims_on(&snap, &e1, View::Active, &recorder),
        only_the_claim
    );
    assert_eq!(asked.take(), vec![doc1()]);
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
