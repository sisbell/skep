//! The ownership gate (as amended 2026-08-16) over a real kernel (InMemory):
//! a foreign home refused with nothing committed, on the dedup hit path too,
//! `nullify`'s target held to ω as well, and the ω-on-the-home-and-nothing-else
//! capability `assert_sup` and `editlink` publish.

use crate::common;

use common::*;
use skep_kernel::TxnError;
use skep_links::{
    enc, AssertSupError, Caller, Edit, EditLinkError, EmitError, HasLinks, Link, MakeLinkError,
    NullifyError, SlotArg, View,
};

#[test]
fn deposit_ops_reject_a_foreign_home_and_commit_nothing() {
    // The probe matrix, link side: principal 2 (account [1,0,2]) deposits
    // into P1's doc1 — make_link / emit / assert_sup / editlink (d_s and
    // d_a) all reject NotOwner carrying the home that failed; nothing
    // commits; System (the M9 automation path) is exempt by architecture.
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let (x, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");
    let before = k.current_seq();
    assert!(matches!(
        w.makelink(
            P2,
            &doc1(),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::NotOwner(d))) if d == doc1()
    ));
    assert!(matches!(
        w.emit(P2, &doc1(), &pred_def_ty(), &ca(9), &[]),
        Err(TxnError::Rejected(EmitError::NotOwner(d))) if d == doc1()
    ));
    assert!(matches!(
        w.assert_sup(P2, &doc1(), &x, &y),
        Err(TxnError::Rejected(AssertSupError::NotOwner(d))) if d == doc1()
    ));
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    // Foreign d_s (successor home): the error names d_s.
    assert!(matches!(
        w.editlink(P2, &x, successor_value.clone(), &doc1(), &sib_doc()),
        Err(TxnError::Rejected(EditLinkError::NotOwner(d))) if d == doc1()
    ));
    // Foreign d_a (claim home): the error names d_a.
    assert!(matches!(
        w.editlink(P2, &x, successor_value.clone(), &sib_doc(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::NotOwner(d))) if d == doc1()
    ));
    // Across an op's several homes, EVERY registration is asked before ANY
    // ownership: an unregistered second home outranks an unowned first, so
    // the verdict does not depend on which home is named first.
    assert!(matches!(
        w.editlink(P1, &x, successor_value, &sib_doc(), &a(&[1, 0, 1, 0, 7])),
        Err(TxnError::Rejected(EditLinkError::HomeNotRegistered))
    ));
    assert_eq!(k.current_seq(), before, "ownership rejections leave no state change");
    // System bypasses the gate (M9 ⟂ M10 — rule fires carry no principal).
    w.emit(Caller::System, &doc1(), &pred_def_ty(), &ca(9), &[])
        .expect("the automation path deposits ungated");
}

#[test]
fn ownership_gate_holds_on_the_idem_hit_path() {
    // Like the hoisted home check, ω is enforced on hit AND miss: a foreign
    // emit whose tuple already exists still rejects NotOwner — the caller
    // cannot observe the dedup branch through the rejection.
    let k = kernel();
    let w = writer(&k);
    w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("incumbent");
    assert!(matches!(
        w.emit(P2, &doc1(), &pred_def_ty(), &ca(1), &[]),
        Err(TxnError::Rejected(EmitError::NotOwner(_)))
    ));
}

#[test]
fn nullify_requires_owning_home_and_target_and_still_filters_the_active_view() {
    // v1 target policy: self-retraction only. Principal 2, from its OWN
    // home, cannot retract P1's link — the rejection names the TARGET; the
    // owner's retraction still lands and filters the active view while the
    // audit view retains everything.
    let k = kernel();
    let w = writer(&k);
    let (target, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("P1's tuple");
    // Foreign target, owned home: NotOwner carrying the target link.
    assert!(matches!(
        w.nullify(P2, &sib_doc(), &target),
        Err(TxnError::Rejected(NullifyError::NotOwner(d))) if d == target
    ));
    // Foreign home is rejected first, naming the home.
    assert!(matches!(
        w.nullify(P2, &doc1(), &target),
        Err(TxnError::Rejected(NullifyError::NotOwner(d))) if d == doc1()
    ));
    {
        let snap = k.snapshot();
        assert!(snap.world().links().is_active(&target), "no foreign retraction landed");
    }
    // The owner's own retraction: active view filtered, audit retains.
    w.nullify(P1, &doc1(), &target).expect("owner retraction");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_nullified(&target));
    assert!(links.readlink(&target).is_some());
    assert!(links.type_slice(&pred_def_ty(), View::Audit).contains(&target));
    assert!(!links.type_slice(&pred_def_ty(), View::Active).contains(&target));
}

#[test]
fn assert_sup_and_editlink_claim_over_links_the_caller_does_not_own() {
    // ω is required on the home(s) named and on NOTHING ELSE — a deliberate
    // permissiveness, framed by the deferred moderation question `nullify`
    // names, and the one ownership rule with no refusal to witness it. So the
    // capability is stated here, positively: without a test, the next
    // hardening pass deletes it and the suite stays green.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (x, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");

    // P2, from a home P2 owns, claims that one of P1's links supersedes
    // another — and the walk family reports it as fact.
    let (c, _) = w
        .assert_sup(P2, &sib_doc(), &x, &y)
        .expect("ω on home only: the endpoints need not be the caller's");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert!(links.is_active(&c));
        assert_eq!(links.succs(&sup, &x), vec![y.clone()]);
    }
    // The endpoints' owner cannot retract it: ω on the CLAIM is the
    // asserter's, the claim's home being d_a.
    assert!(matches!(
        w.nullify(P1, &doc1(), &c),
        Err(TxnError::Rejected(NullifyError::NotOwner(d))) if d == c
    ));

    // editlink the same way: P2 edits P1's link, depositing into its own
    // homes. What it asserts about `original` needs no ω on `original`.
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (Edit { successor: s, claim }, _) = w
        .editlink(P2, &x, successor_value, &sib_doc(), &sib_doc())
        .expect("ω on d_s and d_a only");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_active(&s) && links.is_active(&claim));
    let succs = links.succs(&sup, &x);
    assert!(succs.contains(&s), "the edit's claim entered the adjacency");
    assert!(succs.contains(&y), "and the earlier foreign claim stands");
}
