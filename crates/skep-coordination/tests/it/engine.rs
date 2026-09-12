//! M9 contract tests over a real kernel (InMemory), group C — the reactive
//! rule engine: registration validation, the three-leg certification lint,
//! fire/step/quiescence with the two-transaction gap accounted, the
//! rotation's fairness, the draft boundary and the guest-class look,
//! scoping, the divergence backstop, and the armer warning. Every assertion
//! states a claim the design or interface makes — nothing more.

use crate::common::*;
use crate::terms::*;

use skep_address::Address;
use skep_coordination::{
    Arg, Coordinator, Dom, FireAction, FireError, FireOutcome, Occurrence, Rule,
    RuleCertification, RuleError, RuleId, ScopeBody, Sort, StepOutcome, Term, Trigger, TypeError,
    TypeKey, TypeRef, TypedTerm, View,
};
use skep_kernel::TxnError;
use skep_links::{enc, Caller, HasLinks, NullifyError, ShippedType, Visibility};

// ───────────────────────────── registration ─────────────────────────────

/// Every `register_rule` validation gate, as a typed rejection — never a
/// deferred fire-time panic; `certify_rule` re-runs the same gates.
#[test]
fn register_rule_validation_gates() {
    let k = kernel();
    let mut c = coord(&k);

    // A helper def for the ref-bearing cases.
    let p = c
        .type_check(vec![(v(1), Sort::Addr)], addr_eq(var(1), lit_addr(&ca(1))))
        .expect("P");
    let (p_start, _) = c.define_predicate(&doc1(), &p).expect("define P");

    let mk = |domain: Dom, trigger: Trigger, action: FireAction| Rule {
        domain,
        trigger,
        view: View::Active,
        action,
    };

    // A bare Reg domain fails the sort check.
    assert!(matches!(
        c.register_rule(mk(Dom::Reg, always_addr(&c), marker_action())),
        Err(RuleError::IllFormedDomain(TypeError::SortMismatch { .. }))
    ));
    // certify_rule re-runs the same validation: a malformed rule is the same
    // typed rejection, callable pre-registration.
    assert!(matches!(
        c.certify_rule(&mk(Dom::Reg, always_addr(&c), marker_action())),
        Err(RuleError::IllFormedDomain(TypeError::SortMismatch { .. }))
    ));
    // An uncataloged domain class.
    assert!(matches!(
        c.register_rule(mk(
            Dom::MembersDom(TypeRef::Concrete(TypeKey(enc(&[ra(20)])))),
            always_addr(&c),
            marker_action()
        )),
        Err(RuleError::IllFormedDomain(TypeError::UnregisteredType(_)))
    ));
    // A Ref inside the domain body — no Def escape for domains.
    assert!(matches!(
        c.register_rule(mk(
            Dom::Filter {
                dom: ad(Dom::LinkDom),
                var: v(2),
                pred: at(Term::Ref { addr: p_start.clone(), args: vec![at(var(2))] }),
            },
            always_addr(&c),
            marker_action()
        )),
        Err(RuleError::RefBearingDomain)
    ));
    // Domain↔trigger sort reconciliation: a Tup domain demands a Tup-param
    // trigger.
    assert!(matches!(
        c.register_rule(mk(Dom::ActiveSlice(conc(&pred_stable_ty())), always_addr(&c), marker_action())),
        Err(RuleError::DomainTriggerSortMismatch { expected: Sort::Tup, found: Sort::Addr })
    ));
    // A Def trigger is Codom-only, so it can never serve a Tup domain.
    assert!(matches!(
        c.register_rule(mk(
            Dom::ActiveSlice(conc(&pred_stable_ty())),
            Trigger::Def(p_start.clone()),
            marker_action()
        )),
        Err(RuleError::DomainTriggerSortMismatch { expected: Sort::Tup, found: Sort::Addr })
    ));
    // A Def trigger's codomain and arity (an Inline trigger is one-parameter
    // Bool by its type — `type_check_trigger` refuses a non-Bool body).
    let (nat_def, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![(v(1), Sort::Addr)], lit_nat(1)).expect("Nat def"))
        .expect("define a Nat-codomain def");
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(conc(&pred_stable_ty())), Trigger::Def(nat_def), marker_action())),
        Err(RuleError::TriggerNotBoolean)
    ));
    let (closed_def, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed def"))
        .expect("define a closed def");
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(conc(&pred_stable_ty())), Trigger::Def(closed_def), marker_action())),
        Err(RuleError::BadTriggerArity)
    ));
    // A ref-bearing Inline trigger.
    let ref_trig = c
        .type_check_trigger((v(1), Sort::Addr), Term::Ref { addr: p_start.clone(), args: vec![at(var(1))] })
        .expect("ref-bearing trigger term");
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(conc(&pred_stable_ty())), Trigger::Inline(ref_trig), marker_action())),
        Err(RuleError::RefBearingInlineTrigger)
    ));
    // A Def trigger with no defined signature.
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(conc(&pred_stable_ty())), Trigger::Def(ca(77)), marker_action())),
        Err(RuleError::DanglingDefTrigger(_))
    ));
    // Marker.ty guards: cataloged Unary and non-PredLayer. A Binary shipped
    // class and an uncataloged number both land BadMarkerType; the PredLayer
    // pair is refused by name (PR-DISC), each of its two classes. The
    // `NonIdemMarkerType` arm is structurally unreachable in this format —
    // every cataloged Unary class is idem⊤ — and stays declared for the day
    // a registered idem⊥ Unary class exists again.
    assert!(matches!(
        c.register_rule(mk(
            Dom::MembersDom(conc(&pred_stable_ty())),
            always_addr(&c),
            FireAction::Marker { home: doc1(), ty: key(&retraction_ty()) }
        )),
        Err(RuleError::BadMarkerType(_))
    ));
    assert!(matches!(
        c.register_rule(mk(
            Dom::MembersDom(conc(&pred_stable_ty())),
            always_addr(&c),
            FireAction::Marker { home: doc1(), ty: key(&uncataloged_ty(20)) }
        )),
        Err(RuleError::BadMarkerType(_))
    ));
    for reserved in [ShippedType::PredDef, ShippedType::PredStable] {
        let ty = TypeKey(c.reserved_type(reserved).clone());
        assert!(
            matches!(
                c.register_rule(mk(
                    Dom::MembersDom(conc(&pred_stable_ty())),
                    always_addr(&c),
                    FireAction::Marker { home: doc1(), ty }
                )),
                Err(RuleError::PredLayerMarkerType(_))
            ),
            "{reserved:?}"
        );
    }
}

/// The lint's three legs, each failed alone: every leg is relative to the
/// declared view; the Marker witness must be the marker's own class AND the
/// trigger's parameter; a `Filter` by an SF predicate leaves the grow-only
/// closure; and a tuple-domained trigger over the tuple's address is not
/// the canonical spelling (sound-but-incomplete, by spelling).
#[test]
fn certify_rule_names_each_failed_leg() {
    let k = kernel();
    let c = coord(&k);
    let members = || Dom::MembersDom(conc(&pred_stable_ty()));
    let trig = |body: Term| {
        Trigger::Inline(c.type_check_trigger((v(1), Sort::Addr), body).expect("trigger"))
    };
    let lint = |domain: Dom, trigger: Trigger, view: View| {
        c.certify_rule(&Rule { domain, trigger, view, action: marker_action() }).expect("well-formed")
    };
    let uncertified =
        |sf: bool, marker: bool, grow_only: bool| RuleCertification::Uncertified { sf, marker, grow_only };

    // The canonical spelling at Active certifies nothing (PC3).
    assert_eq!(
        lint(members(), trig(not(is_k_t(&marker_ty(), var(1)))), View::Active),
        uncertified(false, false, false)
    );
    // (b) the witness class must be the marker's.
    assert_eq!(
        lint(members(), trig(not(is_k_t(&pred_stable_ty(), var(1)))), View::Audit),
        uncertified(true, false, true)
    );
    // (b) the witness must be the trigger's parameter.
    assert_eq!(
        lint(members(), trig(not(is_k_t(&marker_ty(), lit_addr(&ca(1))))), View::Audit),
        uncertified(true, false, true)
    );
    // (c) a Filter by an SF predicate leaves the grow-only closure.
    assert_eq!(
        lint(
            filter(members(), 2, not(is_k_t(&marker_ty(), var(2)))),
            trig(not(is_k_t(&marker_ty(), var(1)))),
            View::Audit
        ),
        uncertified(true, true, false)
    );
    // (b) by spelling: the tuple's address is not the parameter.
    let tup = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Tup), not(is_k_t(&marker_ty(), tup_addr(1))))
            .expect("Tup trigger"),
    );
    assert_eq!(
        lint(Dom::AuditSlice(conc(&pred_stable_ty())), tup, View::Audit),
        uncertified(true, false, true)
    );
}

// ─────────────────────────── fire, step, quiescence ───────────────────────────

/// The canonical SF/Marker rule end to end: certification, Q0, peek, fair
/// stepping to quiescence, extinction (NoOp on a re-aimed fire), the
/// journal-recomputed divergence count, and the self-armer warning.
#[test]
fn marker_rule_certifies_fires_and_quiesces() {
    let k = kernel();
    let mut c = coord(&k);
    let ls = links(&k);
    ls.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel 1");
    ls.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel 2");

    let trig = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Addr), not(is_k_t(&marker_ty(), var(1))))
            .expect("¬is_K(marker, x) @ audit"),
    );
    let rule = Rule {
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
        trigger: trig,
        view: View::Audit,
        action: marker_action(),
    };
    assert_eq!(c.certify_rule(&rule).expect("well-formed"), RuleCertification::CertifiedTerminating);
    let id = c.register_rule(rule).expect("register");

    let s = k.snapshot();
    assert!(!c.quiescent(&s));
    let e = c.next_enabled(&s).expect("an enabled occurrence");
    assert_eq!(e.rule, id);
    assert_eq!(e.arg, Arg::Addr(ca(1))); // members in tumbler order

    match c.step(&k.snapshot()) {
        StepOutcome::Fired { rule, arg, .. } => {
            assert_eq!(rule, id);
            assert_eq!(arg, ca(1));
        }
        other => panic!("expected Fired(ca1), got {other:?}"),
    }
    match c.step(&k.snapshot()) {
        StepOutcome::Fired { arg, .. } => assert_eq!(arg, ca(3)),
        other => panic!("expected Fired(ca3), got {other:?}"),
    }
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Quiescent));
    assert!(c.quiescent(&k.snapshot()));

    // Extinction by construction: the marker flipped the audit trigger, so a
    // re-aimed fire is a falsified-in-place NoOp (Q1) — and the effects are
    // real M7 deposits.
    assert!(matches!(
        c.fire(&Occurrence { rule: id, arg: Arg::Addr(ca(1)) }).expect("fire"),
        FireOutcome::NoOp
    ));
    assert!(k.snapshot().world().links().is_k(&marker_ty(), ca(1).tumbler()));

    // Q-EXT: exactly one real fire per argument (the journal recompute).
    assert_eq!(c.fire_count(id, &ca(1)), 1);
    assert_eq!(c.fire_count(id, &ca(3)), 1);

    // The rule reads the class it emits: a self-loop in the armer graph —
    // the static warning (harmless here: the rule is SF).
    assert_eq!(c.armer_cycles(), vec![vec![id]]);
}

/// The two-transaction gap, accounted exactly: a rule whose trigger no fire
/// falsifies meets its own marker at the second fire — M7 answers the
/// incumbent and commits nothing, the step reports `Deduped` with the
/// incumbent's address, the divergence count does not move, and the rule
/// stays enabled (the monitor's case).
#[test]
fn a_dedup_hit_in_the_gap_reports_deduped_and_commits_nothing() {
    let k = kernel();
    let mut c = coord(&k);
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: always_addr(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    let first = match c.step(&k.snapshot()) {
        StepOutcome::Fired { rule, arg, effect, .. } => {
            assert_eq!((rule, arg), (id, ca(1)));
            effect
        }
        other => panic!("expected Fired, got {other:?}"),
    };
    let before = k.current_seq();
    match c.step(&k.snapshot()) {
        StepOutcome::Deduped { rule, arg, effect, .. } => {
            assert_eq!((rule, arg), (id, ca(1)));
            assert_eq!(effect, first, "the incumbent, not a fresh deposit");
        }
        other => panic!("expected Deduped, got {other:?}"),
    }
    assert_eq!(k.current_seq(), before, "M7 committed nothing");
    assert_eq!(c.fire_count(id, &ca(1)), 1, "only Fired advances the count");
    assert!(!c.quiescent(&k.snapshot()), "a ⊤ trigger stays enabled");
}

/// `step` peeks at the caller's snapshot and `fire` pins its own: an
/// occurrence enabled at a stale snapshot and falsified since is a `NoOp`
/// step — no second deposit, no dedup — and the fresh snapshot is quiescent.
#[test]
fn step_peeks_at_the_caller_s_snapshot_but_fires_at_its_own() {
    let k = kernel();
    let mut c = coord(&k);
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: not_marked(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    let stale = k.snapshot();
    assert!(matches!(
        c.fire(&Occurrence { rule: id, arg: Arg::Addr(ca(1)) }).expect("fire"),
        FireOutcome::Fired { .. }
    ));
    assert!(matches!(c.step(&stale), StepOutcome::NoOp));
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Quiescent));
    assert_eq!(c.fire_count(id, &ca(1)), 1);
}

/// Weak fairness is the rotation's: with two rules each holding enabled
/// occurrences, `step` alternates between them rather than draining the
/// first.
#[test]
fn step_rotates_across_rules_rather_than_draining_one() {
    let k = kernel();
    let mut c = coord(&k);
    let ls = links(&k);
    ls.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel 1");
    ls.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel 2");
    ls.emit(Caller::System, &doc1(), &pred_def_ty(), &ca(5), &[]).expect("def-classed on ca5");
    let r1 = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: not_marked(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("R1");
    let r2 = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_def_ty())),
            trigger: not_marked(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("R2");
    let mut fired = Vec::new();
    loop {
        match c.step(&k.snapshot()) {
            StepOutcome::Fired { rule, arg, .. } => fired.push((rule, arg)),
            StepOutcome::Quiescent => break,
            other => panic!("expected Fired or Quiescent, got {other:?}"),
        }
    }
    assert_eq!(fired, vec![(r1, ca(1)), (r2, ca(5)), (r1, ca(3))]);
}

/// Rotate-past on failure: a rule that fails at every fire is reported as
/// `Failed` and the cursor moves past it, so the rest of the agenda runs;
/// the failing occurrence stays enabled and comes round again.
#[test]
fn a_failing_rule_does_not_starve_the_agenda() {
    let k = kernel();
    let mut c = coord(&k);
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let unregistered = a(&[1, 0, 1, 0, 7]);
    let r1 = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: always_addr(&c),
            view: View::Audit,
            action: FireAction::Marker { home: unregistered, ty: key(&marker_ty()) },
        })
        .expect("R1: fails at every fire");
    let r2 = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: not_marked(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("R2");
    assert!(matches!(
        c.step(&k.snapshot()),
        StepOutcome::Failed { rule, err: FireError::HomeNotRegistered, .. } if rule == r1
    ));
    assert!(matches!(
        c.step(&k.snapshot()),
        StepOutcome::Fired { rule, arg, .. } if rule == r2 && arg == ca(1)
    ));
    assert!(
        matches!(c.step(&k.snapshot()), StepOutcome::Failed { rule, .. } if rule == r1),
        "the failing occurrence stays enabled; the cursor rotated past it, not around it"
    );
}

/// H-HOME, never a silent skip: a Marker whose home is no registered
/// document, and a Nullify whose retracting home is none, each fail loudly
/// with `HomeNotRegistered` and deposit nothing — and the draft boundary is
/// asked first, so an unreadable unregistered home is `DraftBoundary`.
#[test]
fn a_fire_into_an_unregistered_home_fails_loudly() {
    let unregistered = a(&[1, 0, 1, 0, 7]);
    let members = || Dom::MembersDom(conc(&pred_stable_ty()));
    let marker_at = |home: &Address| FireAction::Marker { home: home.clone(), ty: key(&marker_ty()) };

    // (1) A Marker into no document.
    let k = kernel();
    let mut c = coord(&k);
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let id = c
        .register_rule(Rule { domain: members(), trigger: always_addr(&c), view: View::Audit, action: marker_at(&unregistered) })
        .expect("register");
    match c.step(&k.snapshot()) {
        StepOutcome::Failed { rule, arg, err: FireError::HomeNotRegistered } => {
            assert_eq!((rule, arg), (id, ca(1)));
        }
        other => panic!("expected Failed(HomeNotRegistered), got {other:?}"),
    }
    assert!(!k.snapshot().world().links().is_k(&marker_ty(), ca(1).tumbler()));
    assert_eq!(c.fire_count(id, &ca(1)), 0);

    // (2) A Nullify from no document.
    let k = kernel();
    let mut c = coord(&k);
    let m1 = deposit_rel(&k, 2, &ca(1), &ca(2));
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(conc(&pred_stable_ty())),
        trigger: always_tup(&c),
        view: View::Active,
        action: FireAction::Nullify { home: unregistered.clone() },
    })
    .expect("register");
    assert!(matches!(
        c.step(&k.snapshot()),
        StepOutcome::Failed { err: FireError::HomeNotRegistered, .. }
    ));
    assert!(!k.snapshot().world().links().is_nullified(&m1));

    // (3) The boundary is asked before M7's write path is entered.
    let k = kernel();
    let refused = unregistered.clone();
    let mut c = coord_with_guest(&k, Box::new(move |_: &World, d: &Address| *d != refused));
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    c.register_rule(Rule { domain: members(), trigger: always_addr(&c), view: View::Audit, action: marker_at(&unregistered) })
        .expect("register");
    assert!(matches!(
        c.step(&k.snapshot()),
        StepOutcome::Failed { err: FireError::DraftBoundary(d), .. } if d == unregistered
    ));
}

/// A `Def` trigger is the def's checked body, captured at registration: it
/// reads only the snapshot it is evaluated on — one pinned BEFORE the def
/// was defined serves the detector and the peek, as one pinned after does —
/// and the def's later retraction changes nothing: the rule keeps firing,
/// and the lint still reads the trigger's flat expansion.
#[test]
fn a_def_trigger_reads_only_the_snapshot_it_is_evaluated_on() {
    let k = kernel();
    let mut c = coord(&k);
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let before = k.snapshot();

    // T(x) := ¬is_K(marker, x), stored as a def AFTER `before` was pinned.
    let t = c
        .type_check(vec![(v(1), Sort::Addr)], not(is_k_t(&marker_ty(), var(1))))
        .expect("T type-checks");
    let (start, _) = c.define_predicate(&doc1(), &t).expect("define T");
    let rule = Rule {
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
        trigger: Trigger::Def(start.clone()),
        view: View::Audit,
        action: marker_action(),
    };
    assert_eq!(c.certify_rule(&rule).expect("well-formed"), RuleCertification::CertifiedTerminating);
    let id = c.register_rule(rule).expect("register");

    // The snapshot predating the def's registration answers, and agrees
    // with a fresh one.
    assert!(!c.quiescent(&before));
    assert_eq!(c.next_enabled(&before), Some(Occurrence { rule: id, arg: Arg::Addr(ca(1)) }));
    assert!(!c.quiescent(&k.snapshot()));

    // Retract the def: the rule's trigger is its own copy.
    c.retract_pred(&doc1(), &start).expect("retract T");
    assert!(!c.is_active_pred(&start, &k.snapshot()));
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Fired { arg, .. } if arg == ca(1)));
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Quiescent));
    assert_eq!(c.armer_cycles(), vec![vec![id]]);
}

/// A rule's domain is enumerated at the RULE's declared view: a
/// `default`-view rule never sees a UV-hidden member, while the same rule at
/// `Active` does — and the peek names the first enabled rule in
/// registration order.
#[test]
fn a_default_view_rule_never_sees_a_uv_hidden_argument() {
    let k = kernel();
    let mut c = coord(&k);
    let ls = links(&k);
    ls.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel");
    ls.emit(Caller::System, &doc1(), &marker_ty(), &ca(3), &[]).expect("retire ca3");
    let rule = |c: &Coordinator<World>, view: View| Rule {
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
        trigger: always_addr(c),
        view,
        action: marker_action(),
    };
    c.register_rule(rule(&c, View::Default)).expect("R_default");
    let s = k.snapshot();
    assert!(c.quiescent(&s));
    assert!(c.next_enabled(&s).is_none());
    assert!(matches!(c.step(&s), StepOutcome::Quiescent));

    let active = c.register_rule(rule(&c, View::Active)).expect("R_active");
    let s = k.snapshot();
    assert!(!c.quiescent(&s));
    assert_eq!(c.next_enabled(&s), Some(Occurrence { rule: active, arg: Arg::Addr(ca(3)) }));
}

// ───────────────────────── the guest class ─────────────────────────

/// The guest-class filter (lane 3.3 §5): a fire whose Marker HOME, or whose
/// bound argument's DOCUMENT, the injected guest predicate answers `false`
/// for is refused BEFORE any deposit — a `Failed` step carrying
/// `DraftBoundary(doc)`, never a silent skip and never a link. A document
/// address bound as the argument is judged as itself. Under an all-readable
/// predicate the same rule fires.
#[test]
fn a_fire_stops_at_the_draft_boundary_before_any_deposit() {
    // doc2 is the "draft": unreadable at guest class under this predicate.
    let refuse_doc2 = || -> Box<Visibility<'static, World>> {
        Box::new(|_: &World, d: &Address| *d != doc2())
    };

    // (1) The action's HOME is the draft: the member lives in doc1.
    let k = kernel();
    let mut c = coord_with_guest(&k, refuse_doc2());
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let rule = Rule {
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
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
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &in_doc2, &[]).expect("rel");
    let rule = Rule {
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
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
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &doc2(), &[]).expect("rel on the document address");
    c.register_rule(Rule {
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
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

    // (4) Both readable: the same rule shape fires, and the deposit is real.
    let k = kernel();
    let mut c = coord_with_guest(&k, refuse_doc2());
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let rule = Rule {
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
        trigger: always_addr(&c),
        view: View::Audit,
        action: marker_action(),
    };
    c.register_rule(rule).expect("register");
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Fired { .. }));
    assert!(k.snapshot().world().links().is_k(&marker_ty(), ca(1).tumbler()));
}

/// THE LOOK AT GUEST CLASS (lane 4.1, PUB-6.28): under a guest predicate that
/// refuses doc2, a tuple homed in doc2 is invisible to every read the
/// evaluator makes — it seeds no domain, satisfies no trigger, and moves no
/// PL verdict — while the same tuple homed in doc1 does all three. The view
/// stays orthogonal to the class: an `AuditSlice` domain keeps a retracted
/// tuple of the readable doc1. (Under the suite's all-true guest, `coord`'s,
/// the filter is the identity — every other test here stands as written.)
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
    links(&k).emit(Caller::System, &doc2(), &pred_stable_ty(), &ca(1), &[]).expect("rel in doc2");
    assert!(
        k.snapshot().world().links().is_k(&pred_stable_ty(), ca(1).tumbler()),
        "M7's class-free read holds the tuple — it is the evaluator's look that must not"
    );
    assert!(!decide_now(&k, &c, View::Active, is_k_t(&pred_stable_ty(), lit_addr(&ca(1)))));
    assert!(!decide_now(&k, &c, View::Audit, is_k_t(&pred_stable_ty(), lit_addr(&ca(1)))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(conc(&pred_stable_ty()))), lit_nat(0))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::LinkDom), lit_nat(0))));
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
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
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel in doc1");
    let (draft_marker, _) =
        links(&k).emit(Caller::System, &doc2(), &marker_ty(), &ca(1), &[]).expect("marker in doc2");
    let trig = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Addr), not(is_k_t(&marker_ty(), var(1))))
            .expect("trigger"),
    );
    c.register_rule(Rule {
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
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

    // (3) The view is orthogonal to the class: a retracted tuple of doc1
    // stays in L_K (audit), doc2's never enters.
    let k = kernel();
    let c = coord_with_guest(&k, refuse_doc2());
    let (t1, _) =
        links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel in doc1");
    links(&k).nullify(Caller::System, &doc1(), &t1).expect("retract it");
    links(&k).emit(Caller::System, &doc2(), &pred_stable_ty(), &ca(2), &[]).expect("rel in doc2");
    let in_audit = |a: &Address| {
        decide_now(
            &k,
            &c,
            View::Audit,
            exists(1, Dom::AuditSlice(conc(&pred_stable_ty())), addr_eq(tup_addr(1), lit_addr(a))),
        )
    };
    assert!(in_audit(&t1), "retracted, but homed in the readable doc1: in the audit slice");
    assert!(decide_now(&k, &c, View::Audit, nat_eq(count(Dom::AuditSlice(conc(&pred_stable_ty()))), lit_nat(1))));
    assert!(!decide_now(&k, &c, View::Active, is_k_t(&pred_stable_ty(), lit_addr(&ca(2)))));
}

// ─────────────────────────── nullify & scoping ───────────────────────────

/// A Nullify rule is always Uncertified (fails the Marker leg), fires as one
/// atomic retraction on a tuple domain, and — on the documented-contract
/// misuse (an Addr-over-M_K domain) — surfaces `BadTarget` as a `Failed`
/// step, never a silent skip.
#[test]
fn nullify_rules_uncertified_fire_and_failed_surface() {
    let k = kernel();
    let mut c = coord(&k);
    let m1 = deposit_rel(&k, 2, &ca(1), &ca(2)); // a pred_stable-classed tuple

    let trig = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Tup), tru()).expect("Tup trigger"),
    );
    let rule = Rule {
        domain: Dom::ActiveSlice(conc(&pred_stable_ty())),
        trigger: trig,
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    };
    assert_eq!(
        c.certify_rule(&rule).expect("well-formed"),
        RuleCertification::Uncertified { sf: true, marker: false, grow_only: false }
    );
    let id = c.register_rule(rule).expect("register");
    match c.step(&k.snapshot()) {
        StepOutcome::Fired { rule, arg, .. } => {
            assert_eq!(rule, id);
            assert_eq!(arg, m1); // Tup-domain bookkeeping projects to t.addr
        }
        other => panic!("expected Fired, got {other:?}"),
    }
    assert!(k.snapshot().world().links().is_nullified(&m1));
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Quiescent));
    assert_eq!(c.fire_count(id, &m1), 1);

    // The documented contract, violated: member addresses are not resident
    // links, so every fire trips M7's BadTarget — surfaced, rotate-past.
    let k2 = kernel();
    let mut c2 = coord(&k2);
    deposit_rel(&k2, 2, &ca(1), &ca(2));
    let trig2 = Trigger::Inline(
        c2.type_check_trigger((v(1), Sort::Addr), tru()).expect("Addr trigger"),
    );
    let bad = Rule {
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
        trigger: trig2,
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    };
    let id2 = c2.register_rule(bad).expect("register_rule cannot decide link-ness statically");
    match c2.step(&k2.snapshot()) {
        StepOutcome::Failed {
            rule,
            err: FireError::Nullify(TxnError::Rejected(NullifyError::BadTarget)),
            ..
        } => assert_eq!(rule, id2),
        other => panic!("expected Failed(BadTarget), got {other:?}"),
    }
}

/// Q7: scoped quiescence is exact for a sort-homogeneous scoped set and a
/// strict over-approximation (never false quiescence) once a sort-
/// incompatible rule joins the registry.
#[test]
fn quiescent_scoped_exact_then_over_approximates() {
    let k = kernel();
    let mut c = coord(&k);
    let ls = links(&k);
    ls.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel 1");
    ls.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel 2");

    let trig = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Addr), not(is_k_t(&marker_ty(), var(1))))
            .expect("trigger"),
    );
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: trig,
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");

    let scope: TypedTerm = c
        .type_check(vec![(v(9), Sort::Addr)], addr_eq(var(9), lit_addr(&ca(1))))
        .expect("one-Addr-param Bool scope");
    assert!(!c.quiescent_scoped(&scope, ScopeBody::PerAddress, &k.snapshot()));

    // Discharge the in-scope work only: scoped-quiescent, globally not.
    match c.fire(&Occurrence { rule: id, arg: Arg::Addr(ca(1)) }).expect("fire ca1") {
        FireOutcome::Fired { .. } => {}
        other => panic!("expected Fired, got {other:?}"),
    }
    let s2 = k.snapshot();
    assert!(c.quiescent_scoped(&scope, ScopeBody::PerAddress, &s2));
    assert!(!c.quiescent(&s2));

    // A Tup-domain rule is sort-incompatible with PerAddress: left UNSCOPED,
    // its enabled occurrence keeps the scoped verdict false — more work
    // reported, never false quiescence.
    deposit_rel(&k, 1, &ca(5), &ca(6)); // a pred_def-classed tuple
    let trig_t = Trigger::Inline(
        c.type_check_trigger((v(2), Sort::Tup), tru()).expect("Tup trigger"),
    );
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(conc(&pred_def_ty())),
        trigger: trig_t,
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    })
    .expect("register");
    assert!(!c.quiescent_scoped(&scope, ScopeBody::PerAddress, &k.snapshot()));
}

/// Q9's tuple bodies read one slot each: the emitter is the tuple's own
/// address, the source its F, the target its G — a tuple-domained rule's
/// work is reported under exactly the scope that names that slot's address,
/// and always under `PerAddress`, which cannot scope it.
#[test]
fn the_tuple_scope_bodies_read_emitter_source_and_target() {
    let k = kernel();
    let mut c = coord(&k);
    let l1 = deposit_rel(&k, 2, &ca(1), &ca(2));
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(conc(&pred_stable_ty())),
        trigger: always_tup(&c),
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    })
    .expect("register");
    let s = k.snapshot();
    let scope = |x: &Address| c.type_check(vec![(v(9), Sort::Addr)], addr_eq(var(9), lit_addr(x))).expect("scope");
    let quiet = |x: &Address, body: ScopeBody| c.quiescent_scoped(&scope(x), body, &s);
    for (x, source, target, emitter) in [
        (ca(1), false, true, true),
        (ca(2), true, false, true),
        (l1.clone(), true, true, false),
    ] {
        assert_eq!(quiet(&x, ScopeBody::PerSource), source, "PerSource at {x}");
        assert_eq!(quiet(&x, ScopeBody::PerTarget), target, "PerTarget at {x}");
        assert_eq!(quiet(&x, ScopeBody::PerEmitter), emitter, "PerEmitter at {x}");
        assert!(!quiet(&x, ScopeBody::PerAddress), "unscoped under PerAddress: its work is always reported");
    }
}

#[test]
#[should_panic(expected = "quiescent_scoped precondition")]
fn quiescent_scoped_panics_on_a_nat_parameter_scope() {
    let k = kernel();
    let c = coord(&k);
    let scope = c.type_check(vec![(v(9), Sort::Nat)], tru()).expect("a Nat-parameter term");
    let s = k.snapshot();
    let _ = c.quiescent_scoped(&scope, ScopeBody::PerAddress, &s);
}

// ──────────────────── preconditions, the backstop, the armer graph ────────────────────

/// `fire`'s precondition: an occurrence aimed at a rule this coordinator
/// never registered panics at the door.
#[test]
#[should_panic(expected = "fire precondition")]
fn fire_panics_on_a_rule_id_from_another_coordinator() {
    let k = kernel();
    let mut c1 = coord(&k);
    let id = c1
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: always_addr(&c1),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    let c2 = coord(&k);
    let _ = c2.fire(&Occurrence { rule: id, arg: Arg::Addr(ca(1)) });
}

/// The contrast: `fire_count`, a monitor, answers 0 for the same foreign id.
#[test]
fn fire_count_answers_zero_for_a_foreign_rule_id() {
    let k = kernel();
    let mut c1 = coord(&k);
    let id = c1
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: always_addr(&c1),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    let c2 = coord(&k);
    assert_eq!(c2.fire_count(id, &ca(1)), 0);
}

/// The attribution key is exact: a same-typed tuple whose F merely COVERS
/// the argument, and one with the exact F homed elsewhere (a draft's,
/// invisible to the fire's dedup), are both outside the count.
#[test]
fn fire_count_keys_on_exact_coverage_and_home() {
    let k = kernel();
    let mut c = coord_with_guest(&k, Box::new(|_: &World, d: &Address| *d != doc2()));
    let ls = links(&k);
    ls.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    ls.emit(Caller::System, &doc2(), &marker_ty(), &ca(1), &[]).expect("the draft's marker, ahead of the fire");
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: not_marked(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Fired { .. }));
    ls.emit(Caller::System, &doc1(), &marker_ty(), &doc1(), &[]).expect("a marker covering ca1 without naming it");
    assert_eq!(c.fire_count(id, &ca(1)), 1);
}

/// The armer graph's edge rule: an empty footprint is armed by nothing;
/// emitting one class while reading another's audit slice makes no edge;
/// the Default reading charges the BH1 filter slice — the class emitted, a
/// self-loop; and a Marker landing in a Nullify rule's active footprint,
/// whose retraction arms any active-reading trigger, closes a two-rule
/// cycle.
#[test]
fn armer_cycles_follow_the_edge_rule() {
    let rule = |c: &Coordinator<World>, body: Term, view: View, action: FireAction| Rule {
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
        trigger: Trigger::Inline(c.type_check_trigger((v(1), Sort::Addr), body).expect("trigger")),
        view,
        action,
    };
    let none: Vec<Vec<RuleId>> = Vec::new();

    let k = kernel();
    let mut c = coord(&k);
    c.register_rule(rule(&c, tru(), View::Audit, marker_action())).expect("register");
    assert_eq!(c.armer_cycles(), none);

    let k = kernel();
    let mut c = coord(&k);
    c.register_rule(rule(&c, is_k_t(&pred_stable_ty(), var(1)), View::Audit, marker_action())).expect("register");
    assert_eq!(c.armer_cycles(), none);

    let k = kernel();
    let mut c = coord(&k);
    let id = c
        .register_rule(rule(&c, is_k_t(&pred_stable_ty(), var(1)), View::Default, marker_action()))
        .expect("register");
    assert_eq!(c.armer_cycles(), vec![vec![id]]);

    let k = kernel();
    let mut c = coord(&k);
    let a_id = c
        .register_rule(rule(&c, is_k_t(&marker_ty(), var(1)), View::Active, FireAction::Nullify { home: doc1() }))
        .expect("A");
    let b_id = c
        .register_rule(rule(&c, is_k_t(&pred_stable_ty(), var(1)), View::Active, marker_action()))
        .expect("B");
    assert_eq!(c.armer_cycles(), vec![vec![a_id, b_id]]);
}
