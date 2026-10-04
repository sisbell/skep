//! The guest class: the draft boundary a fire refuses to cross before any
//! deposit, and the guest-class look every read of a verdict takes.

use crate::common::*;
use crate::terms::*;

use skep_address::Address;
use skep_coordination::{
    Arg, Dom, FireAction, FireError, FireOutcome, Occurrence, Rule, Sort, StepOutcome, Trigger,
    View,
};
use skep_links::{Caller, HasLinks, Visibility};

/// The draft boundary (lane 3.3 §5): a fire whose Marker HOME, or whose
/// bound argument's DOCUMENT, the injected guest predicate answers `false`
/// for is refused BEFORE any deposit — a `Failed` step carrying
/// `DraftBoundary(doc)`, never a silent skip and never a link. A document
/// address bound as the argument is judged as itself, and so is an argument
/// with no document field at all. Under an all-readable predicate the same
/// rule fires.
#[test]
fn a_fire_stops_at_the_draft_boundary_before_any_deposit() {
    // doc2 is the "draft": unreadable at guest class under this predicate.
    let refuse_doc2 = || -> Box<Visibility<'static, World>> {
        Box::new(|_: &World, d: &Address| *d != doc2())
    };

    // (1) The action's HOME is the draft: the member lives in doc1.
    let k = kernel();
    let mut c = coord_with_guest(&k, refuse_doc2());
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let rule = Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: always_addr(&c),
        view: View::Audit,
        action: FireAction::Marker { home: doc2(), ty: key(&marker_ty()) },
    };
    let id = c.register_rule(rule).expect("register");
    match c.step(&k.snapshot()) {
        StepOutcome::Failed { rule, arg, err: FireError::DraftBoundary(d) } => {
            assert_eq!(rule, id);
            assert_eq!(arg, ca(1));
            assert_eq!(d, doc2(), "the refusal names the document that failed");
        }
        other => panic!("expected Failed(DraftBoundary(doc2)), got {other:?}"),
    }
    assert!(
        !k.snapshot().world().links().is_k(&marker_ty(), ca(1).tumbler()),
        "nothing was deposited"
    );
    assert_eq!(c.fire_count(id, &ca(1)), 0);

    // (2) The ARGUMENT's document is the draft: a member inside doc2, the
    // home in doc1 — refused the same way, naming doc2.
    let k = kernel();
    let mut c = coord_with_guest(&k, refuse_doc2());
    let in_doc2 = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &in_doc2, &[]).expect("rel");
    let rule = Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: always_addr(&c),
        view: View::Audit,
        action: marker_action(),
    };
    c.register_rule(rule).expect("register");
    match c.step(&k.snapshot()) {
        StepOutcome::Failed { arg, err: FireError::DraftBoundary(d), .. } => {
            assert_eq!(arg, in_doc2);
            assert_eq!(d, doc2());
        }
        other => panic!("expected Failed(DraftBoundary(doc2)), got {other:?}"),
    }
    assert!(!k.snapshot().world().links().is_k(&marker_ty(), in_doc2.tumbler()));

    // (3) The argument IS the draft's own address: judged as itself.
    let k = kernel();
    let mut c = coord_with_guest(&k, refuse_doc2());
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &doc2(), &[]).expect("rel on the document address");
    c.register_rule(Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: always_addr(&c),
        view: View::Audit,
        action: marker_action(),
    })
    .expect("register");
    match c.step(&k.snapshot()) {
        StepOutcome::Failed { arg, err: FireError::DraftBoundary(d), .. } => {
            assert_eq!(arg, doc2());
            assert_eq!(d, doc2());
        }
        other => panic!("expected Failed(DraftBoundary(doc2)), got {other:?}"),
    }

    // (4) BOTH fail: the home is asked first, so it is the document named —
    // the member's witnessing tuple stays in the readable doc1, its address
    // lives in doc2, and the action's home is a third document the guest
    // class also refuses.
    let k = kernel();
    let mut c = coord_with_guest(&k, |_, d| *d != doc2() && *d != published_doc());
    let in_doc2 = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &in_doc2, &[]).expect("rel");
    c.register_rule(Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: always_addr(&c),
        view: View::Audit,
        action: FireAction::Marker { home: published_doc(), ty: key(&marker_ty()) },
    })
    .expect("register");
    match c.step(&k.snapshot()) {
        StepOutcome::Failed { arg, err: FireError::DraftBoundary(d), .. } => {
            assert_eq!(arg, in_doc2);
            assert_eq!(d, published_doc(), "the home, not the argument's document");
        }
        other => panic!("expected Failed(DraftBoundary(the home)), got {other:?}"),
    }

    // (5) Both readable: the same rule shape fires, and the deposit is real.
    let k = kernel();
    let mut c = coord_with_guest(&k, refuse_doc2());
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let rule = Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: always_addr(&c),
        view: View::Audit,
        action: marker_action(),
    };
    c.register_rule(rule).expect("register");
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Fired { .. }));
    assert!(k.snapshot().world().links().is_k(&marker_ty(), ca(1).tumbler()));

    // (6) The membership re-check speaks BEFORE the boundary: an argument out
    // of the VISIBLE domain is a `NoOp` even when the action's home is the
    // draft — the trigger never reaches the action, so nothing is refused.
    let k = kernel();
    let mut c = coord_with_guest(&k, refuse_doc2());
    link_writer(&k)
        .emit(Caller::System, &doc2(), &pred_stable_ty(), &ca(1), &[])
        .expect("the only witnessing tuple is draft-homed");
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
            trigger: always_addr(&c),
            view: View::Audit,
            action: FireAction::Marker { home: doc2(), ty: key(&marker_ty()) },
        })
        .expect("register");
    assert!(matches!(
        c.fire(&Occurrence { rule: id, arg: Arg::Addr(ca(1)) }).expect("fire"),
        FireOutcome::NoOp
    ));

    // (7) An argument with NO document field — an account address, above the
    // document level — is judged as itself: the guest predicate is asked
    // about it, and refuses the fire.
    let k = kernel();
    let account = a(&[1, 0, 1]);
    let refused = account.clone();
    let mut c = coord_with_guest(&k, move |_, d| *d != refused);
    link_writer(&k)
        .emit(Caller::System, &doc1(), &pred_stable_ty(), &account, &[])
        .expect("an account-level member");
    c.register_rule(Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: always_addr(&c),
        view: View::Audit,
        action: marker_action(),
    })
    .expect("register");
    match c.step(&k.snapshot()) {
        StepOutcome::Failed { arg, err: FireError::DraftBoundary(d), .. } => {
            assert_eq!(arg, account);
            assert_eq!(d, account, "judged as itself");
        }
        other => panic!("expected Failed(DraftBoundary(the account)), got {other:?}"),
    }
    assert!(!k.snapshot().world().links().is_k(&marker_ty(), account.tumbler()));
}

/// THE LOOK AT GUEST CLASS (lane 4.1, PUB-6.28): under a guest predicate that
/// refuses doc2, a tuple homed in doc2 is invisible to every read the
/// evaluator makes — it seeds no domain, satisfies no trigger, and moves no
/// PL verdict — while the same tuple homed in doc1 does all three. The slice
/// stays orthogonal to the class: an `AuditSlice` domain keeps a retracted
/// tuple of the readable doc1. (Under the suite's all-true guest, `coord`'s,
/// the filter is the identity — every test built on `coord` stands as
/// written.)
#[test]
fn the_trigger_s_look_is_filtered_at_guest_class() {
    let refuse_doc2 = || -> Box<Visibility<'static, World>> {
        Box::new(|_: &World, d: &Address| *d != doc2())
    };

    // (1) The only pred_stable tuple on ca1 is homed in doc2: no verdict, no
    // domain, no fire — and a hand-aimed fire is a NoOp (out of the visible
    // domain), never a DraftBoundary: the home doc1 and the member's own
    // document doc1 are both readable, so before lane 4.1 this rule DEPOSITED.
    let k = kernel();
    let mut c = coord_with_guest(&k, refuse_doc2());
    link_writer(&k).emit(Caller::System, &doc2(), &pred_stable_ty(), &ca(1), &[]).expect("rel in doc2");
    assert!(
        k.snapshot().world().links().is_k(&pred_stable_ty(), ca(1).tumbler()),
        "M7's own read holds the tuple — it is the evaluator's look that must not"
    );
    assert!(!decide_now(&k, &c, View::Active, is_k(&pred_stable_ty(), lit_addr(&ca(1)))));
    assert!(!decide_now(&k, &c, View::Audit, is_k(&pred_stable_ty(), lit_addr(&ca(1)))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(concrete(&pred_stable_ty()))), lit_nat(0))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::LinkDom), lit_nat(0))));
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
            trigger: always_addr(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    let s = k.snapshot();
    assert!(c.quiescent(&s));
    assert!(c.next_enabled(&s).is_none());
    assert!(matches!(c.step(&s), StepOutcome::Quiescent));
    assert!(matches!(
        c.fire(&Occurrence { rule: id, arg: Arg::Addr(ca(1)) }).expect("out of domain is a NoOp"),
        FireOutcome::NoOp
    ));
    assert!(!k.snapshot().world().links().is_k(&marker_ty(), ca(1).tumbler()), "nothing deposited");
    assert_eq!(c.fire_count(id, &ca(1)), 0);

    // (2) The trigger side: the member's tuple is in doc1 (visible); the
    // marker that would falsify ¬is_K(marker, x) is in doc2 — invisible to
    // the look, as to the writer's dedup — so the rule fires, minting fresh
    // in doc1 beside the draft's marker, and then quiesces on its own.
    let k = kernel();
    let mut c = coord_with_guest(&k, refuse_doc2());
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel in doc1");
    let (draft_marker, _) =
        link_writer(&k).emit(Caller::System, &doc2(), &marker_ty(), &ca(1), &[]).expect("marker in doc2");
    let trig = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Addr), not(is_k(&marker_ty(), var(1))))
            .expect("trigger"),
    );
    c.register_rule(Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: trig,
        view: View::Audit,
        action: marker_action(),
    })
    .expect("register");
    match c.step(&k.snapshot()) {
        StepOutcome::Fired { arg, effect, .. } => {
            assert_eq!(arg, ca(1));
            assert_ne!(effect, draft_marker, "the draft's marker neither falsified nor absorbed the fire");
            assert_eq!(skep_address::document_of(&effect), Some(doc1()));
        }
        other => panic!("expected Fired, got {other:?}"),
    }
    assert!(
        matches!(c.step(&k.snapshot()), StepOutcome::Quiescent),
        "the public marker now falsifies the trigger"
    );

    // (3) The slice is orthogonal to the class: a retracted tuple of doc1
    // stays in L_K (audit), doc2's never enters.
    let k = kernel();
    let c = coord_with_guest(&k, refuse_doc2());
    let (l1, _) =
        link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel in doc1");
    link_writer(&k).nullify(Caller::System, &doc1(), &l1).expect("retract it");
    link_writer(&k).emit(Caller::System, &doc2(), &pred_stable_ty(), &ca(2), &[]).expect("rel in doc2");
    let in_audit = |a: &Address| {
        decide_now(
            &k,
            &c,
            View::Audit,
            exists(1, Dom::AuditSlice(concrete(&pred_stable_ty())), addr_eq(tup_addr(1), lit_addr(a))),
        )
    };
    assert!(in_audit(&l1), "retracted, but homed in the readable doc1: in the audit slice");
    assert!(decide_now(&k, &c, View::Audit, nat_eq(count(Dom::AuditSlice(concrete(&pred_stable_ty()))), lit_nat(1))));
    assert!(!decide_now(&k, &c, View::Active, is_k(&pred_stable_ty(), lit_addr(&ca(2)))));
}
