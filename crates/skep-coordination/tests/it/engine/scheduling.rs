//! Scheduling: the peek, the fire and the step — the two-transaction gap
//! accounted, the rotation's fairness and rotate-past on failure, quiescence
//! and its base case — and the Nullify action with Q7's scoped quiescence.

use crate::common::*;
use crate::terms::*;

use skep_address::Address;
use skep_coordination::{
    Arg, Coordinator, Dom, FireAction, FireError, FireOutcome, Occurrence, Rule, RuleCertification,
    RuleId, ScopeBody, Sort, StepOutcome, Term, Trigger, TypedTerm, View,
};
use skep_kernel::TxnError;
use skep_links::{enc, Caller, HasLinks, NullifyError, SlotArg, Tuple};

// ─────────────────────────── fire, step, quiescence ───────────────────────────

/// `next_enabled` peeks the first rule in REGISTRATION order among those with
/// an enabled occurrence. The control registers the same two rules the other
/// way round on a second handle: the pick follows registration, not the
/// catalog's class order nor the arguments' address order. (Ids are minted
/// per handle and collide, so the bound argument is what tells the two peeks
/// apart.)
#[test]
fn next_enabled_names_the_first_rule_in_registration_order() {
    let k = kernel();
    let writer = link_writer(&k);
    writer
        .emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[])
        .expect("a pred_stable member");
    writer.emit(Caller::System, &doc1(), &pred_def_ty(), &ca(3), &[]).expect("a pred_def member");
    let stable = |c: &Coordinator<World>| Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: always_addr(c),
        view: View::Audit,
        action: marker_action(),
    };
    let def = |c: &Coordinator<World>| Rule {
        domain: Dom::MembersDom(concrete(&pred_def_ty())),
        trigger: always_addr(c),
        view: View::Audit,
        action: marker_action(),
    };
    let s = k.snapshot();

    let mut c = coord(&k);
    let first = c.register_rule(stable(&c)).expect("R1");
    let second = c.register_rule(def(&c)).expect("R2");
    assert!(first < second, "a RuleId orders by registration");
    assert_eq!(c.next_enabled(&s), Some(Occurrence { rule: first, arg: Arg::Addr(ca(1)) }));

    let mut reversed = coord(&k);
    let def_first = reversed.register_rule(def(&reversed)).expect("R1'");
    reversed.register_rule(stable(&reversed)).expect("R2'");
    assert_eq!(
        reversed.next_enabled(&s),
        Some(Occurrence { rule: def_first, arg: Arg::Addr(ca(3)) })
    );
}

/// A fire's trigger and action see the STORE's domain element, never the
/// caller's: an `Occurrence` is caller-built and carries a whole `Tuple`, so
/// `fire` looks its argument up by identity (`t.addr`) and then uses what the
/// domain yielded. A forgery carrying a live address and invented slots must
/// not drive the verdict.
#[test]
fn a_fire_binds_the_store_s_element_not_the_caller_s() {
    let k = kernel();
    let mut c = coord(&k);
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let trig = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Tup), in_coverage_f(lit_addr(&ca(1)), 1))
            .expect("a trigger that reads the tuple's F"),
    );
    let id = c
        .register_rule(Rule {
            domain: Dom::ActiveSlice(concrete(&pred_stable_ty())),
            trigger: trig,
            view: View::Active,
            action: marker_action(),
        })
        .expect("register");
    let forged = Arg::Tuple(Tuple { addr: l1.clone(), from: enc(&[ca(9)]), to: enc(&[ca(9)]) });
    assert!(
        matches!(
            c.fire(&Occurrence { rule: id, arg: forged }).expect("fire"),
            FireOutcome::Fired { .. }
        ),
        "the trigger read the store's F, not the forgery's"
    );
    assert!(k.snapshot().world().links().is_k(&marker_ty(), l1.tumbler()));
}

/// The empty registry is Q0's base case, vacuously true: no rule has an
/// enabled occurrence, so a driver's `while !quiescent { step }` loop STOPS —
/// `step` answers `Quiescent`, not `NoOp`, which mean opposite things to that
/// loop — and the static reads answer over the empty set.
#[test]
fn a_coordinator_with_no_rules_is_quiescent() {
    let k = kernel();
    let mut c = coord(&k);
    // State a rule could range over, so the verdict is the registry's emptiness.
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let s = k.snapshot();
    assert!(c.quiescent(&s));
    assert_eq!(c.next_enabled(&s), None);
    assert!(matches!(c.step(&s), StepOutcome::Quiescent));
    let none: Vec<Vec<RuleId>> = Vec::new();
    assert_eq!(c.armer_cycles(), none);
    let scope = c.type_check(vec![(v(9), Sort::Addr)], tru()).expect("a scope");
    assert!(c.quiescent_scoped(&scope, ScopeBody::PerAddress, &s));
}

/// The canonical SF/Marker rule end to end: certification, Q0, peek, fair
/// stepping to quiescence, extinction (NoOp on a re-aimed fire), the
/// journal-recomputed divergence count, and the self-armer warning.
#[test]
fn marker_rule_certifies_fires_and_quiesces() {
    let k = kernel();
    let mut c = coord(&k);
    let writer = link_writer(&k);
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel 1");
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel 2");

    let trig = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Addr), not(is_k(&marker_ty(), var(1))))
            .expect("¬is_K(marker, x) @ audit"),
    );
    let rule = Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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
    assert_eq!(e.arg, Arg::Addr(ca(1))); // members in TUMBLER order — ca3 was deposited first

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
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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
    let writer = link_writer(&k);
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel 1");
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel 2");
    writer.emit(Caller::System, &doc1(), &pred_def_ty(), &ca(5), &[]).expect("def-classed on ca5");
    let r1 = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
            trigger: not_marked(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("R1");
    let r2 = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_def_ty())),
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
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let unregistered = a(&[1, 0, 1, 0, 7]);
    let r1 = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
            trigger: always_addr(&c),
            view: View::Audit,
            action: FireAction::Marker { home: unregistered, ty: key(&marker_ty()) },
        })
        .expect("R1: fails at every fire");
    let r2 = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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
    let members_dom = || Dom::MembersDom(concrete(&pred_stable_ty()));
    let marker_at = |home: &Address| FireAction::Marker { home: home.clone(), ty: key(&marker_ty()) };

    // (1) A Marker into no document.
    let k = kernel();
    let mut c = coord(&k);
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let id = c
        .register_rule(Rule { domain: members_dom(), trigger: always_addr(&c), view: View::Audit, action: marker_at(&unregistered) })
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
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(concrete(&pred_stable_ty())),
        trigger: always_tup(&c),
        view: View::Active,
        action: FireAction::Nullify { home: unregistered.clone() },
    })
    .expect("register");
    assert!(matches!(
        c.step(&k.snapshot()),
        StepOutcome::Failed { err: FireError::HomeNotRegistered, .. }
    ));
    assert!(!k.snapshot().world().links().is_nullified(&l1));

    // (3) The boundary is asked before M7's write path is entered.
    let k = kernel();
    let refused = unregistered.clone();
    let mut c = coord_with_guest(&k, Box::new(move |_: &World, d: &Address| *d != refused));
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    c.register_rule(Rule { domain: members_dom(), trigger: always_addr(&c), view: View::Audit, action: marker_at(&unregistered) })
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
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let before = k.snapshot();

    // T(x) := ¬is_K(marker, x), stored as a def AFTER `before` was pinned.
    let t = c
        .type_check(vec![(v(1), Sort::Addr)], not(is_k(&marker_ty(), var(1))))
        .expect("T type-checks");
    let (start, _) = c.define_predicate(&doc1(), &t).expect("define T");
    let rule = Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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
    let writer = link_writer(&k);
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel");
    writer.emit(Caller::System, &doc1(), &retired_ty(), &ca(3), &[]).expect("retire ca3");
    let rule = |c: &Coordinator<World>, view: View| Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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

// ─────────────────────────── nullify & scoping ───────────────────────────

/// A Nullify rule is always Uncertified (fails the Marker leg), fires as one
/// atomic retraction on a tuple domain, and — on the documented-contract
/// misuse (an Addr-over-M_K domain) — surfaces `BadTarget` as a `Failed`
/// step, never a silent skip.
#[test]
fn a_nullify_rule_is_uncertified_fires_once_and_surfaces_bad_target_as_failed() {
    let k = kernel();
    let mut c = coord(&k);
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2)); // a pred_stable-classed tuple

    let trig = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Tup), tru()).expect("Tup trigger"),
    );
    let rule = Rule {
        domain: Dom::ActiveSlice(concrete(&pred_stable_ty())),
        trigger: trig,
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    };
    assert_eq!(
        c.certify_rule(&rule).expect("well-formed"),
        RuleCertification::Uncertified { sf: true, marker: false, grow_only: false }
    );
    let id = c.register_rule(rule).expect("register");
    // The tuple's OWN address, aimed as an `Addr` at a tuple domain: a domain
    // yields one shape, so a probe of the other is out of it by construction
    // — never matched by projecting the tuple to `t.addr`, which is the
    // bookkeeping key and not the element.
    assert!(
        matches!(
            c.fire(&Occurrence { rule: id, arg: Arg::Addr(l1.clone()) }).expect("fire"),
            FireOutcome::NoOp
        ),
        "an argument of a shape this domain never yields is out of it by construction"
    );
    assert!(!k.snapshot().world().links().is_nullified(&l1), "nothing fired");
    match c.step(&k.snapshot()) {
        StepOutcome::Fired { rule, arg, .. } => {
            assert_eq!(rule, id);
            assert_eq!(arg, l1); // Tup-domain bookkeeping projects to t.addr
        }
        other => panic!("expected Fired, got {other:?}"),
    }
    assert!(k.snapshot().world().links().is_nullified(&l1));
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Quiescent));
    assert_eq!(c.fire_count(id, &l1), 1);

    // The documented contract, violated: member addresses are not resident
    // links, so every fire trips M7's BadTarget — surfaced, rotate-past.
    let k2 = kernel();
    let mut c2 = coord(&k2);
    deposit_rel(&k2, PRED_STABLE, &ca(1), &ca(2));
    let trig2 = Trigger::Inline(
        c2.type_check_trigger((v(1), Sort::Addr), tru()).expect("Addr trigger"),
    );
    let bad = Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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
fn quiescent_scoped_is_exact_then_over_approximates_in_the_safe_direction() {
    let k = kernel();
    let mut c = coord(&k);
    let writer = link_writer(&k);
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel 1");
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel 2");

    let trig = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Addr), not(is_k(&marker_ty(), var(1))))
            .expect("trigger"),
    );
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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
    deposit_rel(&k, PRED_DEF, &ca(5), &ca(6)); // a pred_def-classed tuple
    let trig_t = Trigger::Inline(
        c.type_check_trigger((v(2), Sort::Tup), tru()).expect("Tup trigger"),
    );
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(concrete(&pred_def_ty())),
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
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(concrete(&pred_stable_ty())),
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

/// Q9's `PerTarget` and `PerSource` read their slot with `any`: a tuple with
/// two targets is in scope when EITHER is. An `all` would scope the rule's
/// work out and report a quiescence that is not there, which Q7 promises
/// never happens.
#[test]
fn a_multi_address_slot_is_in_scope_when_any_of_its_addresses_is() {
    let k = kernel();
    let mut c = coord(&k);
    link_writer(&k)
        .makelink(
            Caller::System,
            &doc1(),
            SlotArg::Addrs(vec![ca(1), ca(3)]),
            SlotArg::Addrs(vec![ca(2), ca(4)]),
            SlotArg::Addrs(vec![ra(PRED_STABLE)]),
        )
        .expect("a tuple with two sources and two targets");
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(concrete(&pred_stable_ty())),
        trigger: always_tup(&c),
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    })
    .expect("register");
    let s = k.snapshot();
    let scope = |x: &Address| {
        c.type_check(vec![(v(9), Sort::Addr)], addr_eq(var(9), lit_addr(x))).expect("scope")
    };
    for (x, body) in [
        (ca(2), ScopeBody::PerTarget),
        (ca(4), ScopeBody::PerTarget),
        (ca(1), ScopeBody::PerSource),
        (ca(3), ScopeBody::PerSource),
    ] {
        assert!(!c.quiescent_scoped(&scope(&x), body, &s), "{x} under {body:?}");
    }
    assert!(c.quiescent_scoped(&scope(&ca(9)), ScopeBody::PerTarget, &s));
    assert!(c.quiescent_scoped(&scope(&ca(9)), ScopeBody::PerSource, &s));
}

/// `PerEmitter` asks `S` about the tuple's OWN address, a LINK address: a
/// scope naming the home document, `x = D`, holds of no tuple, and the rule's
/// work drops out of it; the scope `ScopeBody::PerEmitter` names for a home,
/// `D ≼ x`, keeps that work in view — and leaves out a tuple homed elsewhere.
#[test]
fn per_emitter_asks_about_the_link_address_not_its_home() {
    let k = kernel();
    let mut c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2)); // homed in doc1
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(concrete(&pred_stable_ty())),
        trigger: always_tup(&c),
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    })
    .expect("register");
    let s = k.snapshot();
    let quiet = |body: Term| {
        let scope = c.type_check(vec![(v(9), Sort::Addr)], body).expect("scope");
        c.quiescent_scoped(&scope, ScopeBody::PerEmitter, &s)
    };
    assert!(quiet(addr_eq(var(9), lit_addr(&doc1()))), "a link address is never its home's");
    assert!(!quiet(prefix(lit_addr(&doc1()), var(9))), "doc1 ≼ the link: the work is in scope");
    assert!(quiet(prefix(lit_addr(&doc2()), var(9))), "a doc1 tuple is outside doc2's scope");
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
