//! M9's fires at GUEST class through the assembled engine (PUB round 2, lane
//! 3.3, §5): the `Coordinator` the engine assembles carries
//! `World::readable_guest` — `published(doc)` — and a fire whose Marker home
//! or bound argument lies in a private draft is refused before any deposit,
//! as a `Failed` step naming the draft. And (lane 3.3b, PUB-6.28) the same
//! predicate is threaded into every writer the coordinator builds, so a
//! fire's value-keyed gates see only guest-readable incumbents: a draft-homed
//! tuple never absorbs a fire as `Deduped`. What is tested is the ASSEMBLY
//! (the predicate reaches M9 on both paths, and it is the publication read);
//! the refusal's own order is M9's suite, the filtered lookup M7's.
//!
//! The caller-to-class mapping has a second arm, and it is here because this
//! is where a dedup hit can be read: a PRINCIPAL writes at its own class, so
//! its writer sees an incumbent homed in its own draft where the System
//! caller's does not (PUB-6.25).
//!
//! And the TRIGGER side (lane 4.1, PUB-6.28's other half): the rule's LOOK —
//! the evaluator's link reads and the domain enumeration — runs at the same
//! guest class, filtered at link HOME by the same predicate, so a draft-homed
//! tuple can neither seed a public rule's domain nor satisfy its trigger; "a
//! fire's verdict never turns on a document rule 4 hides, and a fire commits
//! byte-identically to a world with no drafts". The cells: a rule over a
//! published tuple fires (the four cells above stand); a rule whose only
//! matching tuple is draft-homed does not, with no `DraftBoundary`; the
//! byte-identical commit; the view orthogonal to the class over the tuple
//! domains and `L_dom`; a `Def` trigger seeing the same filtered store as an
//! inline one.

use crate::common;

use std::sync::Arc;

use common::*;
use skep_address::{document_of, Address, Nat};
use skep_coordination::{
    Arg, Atom, Coordinator, Dom, Env, FireAction, FireError, FireOutcome, Lit, Occurrence, Prim,
    Rule, Sort, StepOutcome, Term, Trigger, TypeKey, TypeRef, Value, VarId,
};
use skep_engine::{Engine, World};
use skep_links::{Caller, HasLinks, ShippedType, View};

/// An always-true one-Addr-parameter trigger.
fn always(coord: &Coordinator<World>) -> Trigger {
    let x = VarId::new(1).expect("a test variable below the watershed");
    Trigger::Inline(
        coord.type_check_trigger((x, Sort::Addr), Term::Lit(Lit::True))
            .expect("an always-true trigger type-checks"),
    )
}

/// A Marker rule over the members of the shipped `pred_stable` class, marking
/// them `retired` (the one cataloged Unary idem⊤ class outside the PredLayer
/// pair) in `home`.
fn marker_rule(engine: &Engine, coord: &Coordinator<World>, home: Address) -> Rule {
    let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
    let retired = engine.registry().reserved_type(ShippedType::Retired).clone();
    Rule {
        domain: Dom::MembersDom(TypeRef::Concrete(TypeKey(pred_stable))),
        trigger: always(coord),
        view: View::Audit,
        action: FireAction::Marker { home, ty: TypeKey(retired) },
    }
}

/// The published home `1.0.1.0.1` and the private draft `1.0.1.0.2` of the
/// genesis node's first account.
fn docs(engine: &Engine) -> (Address, Address) {
    let (acct, home) = setup_home(engine);
    assert_eq!(home, addr(&[1, 0, 1, 0, 1]), "the first account's home is its doc 1");
    let (draft, _) = engine
        .namespace()
        .create_new_document(USER, &acct, None)
        .expect("the second flagless mint is a private draft");
    assert_eq!(draft, addr(&[1, 0, 1, 0, 2]));
    (home, draft)
}

/// [`docs`] plus a `pred_stable` member at `member`, deposited in the
/// PUBLISHED home.
fn board(engine: &Engine, member: &Address) -> (Address, Address) {
    let (home, draft) = docs(engine);
    let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
    engine
        .linkstore(&World::visible_to(Caller::System))
        .emit(Caller::System, &home, &pred_stable, member, &[])
        .expect("the member relation deposits in the published home");
    (home, draft)
}

/// PUB-6.58's named cell, the SYSTEM caller at guest class (PUB-6.25,
/// PUB-6.28): the owner has already deposited, in its PRIVATE draft, exactly
/// the tuple the rule emits. Before lane 3.3b that draft-homed incumbent
/// absorbed the fire as `Deduped`; now the fire's gates run at guest class,
/// the draft is invisible to them, and the fire is a FRESH mint in the
/// published home — byte-identical to a world with no drafts. The next step
/// then dedups against that guest-visible marker, never the draft's.
#[test]
fn a_fire_is_never_absorbed_by_a_draft_homed_incumbent() {
    let engine = mem_engine();
    let member = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    let (home, draft) = board(&engine, &member);
    let retired = engine.registry().reserved_type(ShippedType::Retired).clone();

    // The owner's own marker on the member, homed in its draft — the I0 class
    // the fire's value lands in already holds an active tuple.
    let (incumbent, _) = engine
        .linkstore(&World::visible_to(OWNER))
        .emit(OWNER, &draft, &retired, &member, &[])
        .expect("the owner marks the member in its own draft");
    assert_eq!(document_of(&incumbent), Some(draft.clone()));
    assert!(
        engine.kernel().snapshot().world().links().is_k(&retired, member.tumbler()),
        "the class holds the tuple already — in the draft"
    );

    let mut coord = engine.coordinator();
    let rule = marker_rule(&engine, &coord, home.clone());
    let id = coord.register_rule(rule).expect("a well-formed rule registers");
    match coord.step(&engine.kernel().snapshot()) {
        StepOutcome::Fired { rule, arg, effect, .. } => {
            assert_eq!(rule, id);
            assert_eq!(arg, member);
            assert_ne!(effect, incumbent, "the draft's tuple did not absorb the fire");
            assert_eq!(
                document_of(&effect),
                Some(home.clone()),
                "a fresh mint in the published home, as in a world with no drafts"
            );
        }
        other => panic!("expected Fired (a fresh mint), got {other:?}"),
    }
    assert_eq!(coord.fire_count(id, &member), 1, "one real fire, homed where the rule fires");

    // The guest-visible marker is now the incumbent the fire's class can
    // read: the next step is a dedup hit on it, and never on the draft's.
    match coord.step(&engine.kernel().snapshot()) {
        StepOutcome::Deduped { effect, .. } => {
            assert_ne!(effect, incumbent);
            assert_eq!(document_of(&effect), Some(home));
        }
        other => panic!("expected Deduped against the published marker, got {other:?}"),
    }
}

/// The PRINCIPAL arm of the same mapping (PUB-6.25), which the System arm
/// above is the complement of: a principal writes at ITS OWN class, so
/// `emit`'s idempotency gate reads the incumbents that principal can read —
/// including one homed in a private draft of its own. A writer built at guest
/// class instead cannot see that incumbent, and mints a second tuple beside
/// it: two active tuples of one identity in one document, with nothing about
/// either looking wrong.
///
/// Every other write in this crate's suite runs through the principal arm and
/// asserts nothing about it, because visibility gates the dedup LOOKUP and
/// never the deposit — a writer at the wrong class still writes to the same
/// place. The dedup hit is the one answer that moves.
#[test]
fn a_principal_s_writer_dedups_against_its_own_draft_homed_incumbent() {
    let engine = mem_engine();
    // `setup_doc`'s explicit-`false` FIRST mint: the account's doc 1, private.
    let (_acct, draft) = setup_doc(&engine);
    assert!(
        !engine.kernel().snapshot().world().readable(None, &draft),
        "the home must be a draft, or guest class reads it too and this proves nothing"
    );
    let retired = engine.registry().reserved_type(ShippedType::Retired).clone();
    let member = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    let visibility = World::visible_to(OWNER);

    let (first, _) = engine
        .linkstore(&visibility)
        .emit(OWNER, &draft, &retired, &member, &[])
        .expect("the owner marks the member in its own draft");
    let head = engine.kernel().current_seq();
    let (again, _) = engine
        .linkstore(&visibility)
        .emit(OWNER, &draft, &retired, &member, &[])
        .expect("the same tuple, emitted again");

    assert_eq!(again, first, "the owner reads its own draft: the second emit is a dedup hit");
    assert_eq!(engine.kernel().current_seq(), head, "…and a hit commits nothing");
}

/// A Marker whose HOME is the private draft: refused at the draft boundary,
/// naming the draft; nothing deposited.
#[test]
fn a_fire_into_a_draft_home_is_refused_before_any_deposit() {
    let engine = mem_engine();
    let member = addr(&[1, 0, 1, 0, 1, 0, 1, 1]); // a position of the published home
    let (_home, draft) = board(&engine, &member);
    let mut coord = engine.coordinator();
    let rule = marker_rule(&engine, &coord, draft.clone());
    let id = coord.register_rule(rule).expect("a well-formed rule registers");
    match coord.step(&engine.kernel().snapshot()) {
        StepOutcome::Failed { rule, arg, err: FireError::DraftBoundary(d) } => {
            assert_eq!(rule, id);
            assert_eq!(arg, member);
            assert_eq!(d, draft, "the refusal names the draft home");
        }
        other => panic!("expected Failed(DraftBoundary(draft)), got {other:?}"),
    }
    let retired = engine.registry().reserved_type(ShippedType::Retired).clone();
    assert!(
        !engine.kernel().snapshot().world().links().is_k(&retired, member.tumbler()),
        "no marker was deposited"
    );
}

/// A Marker whose bound ARGUMENT lies in the private draft (the home
/// published): refused the same way, naming the draft.
#[test]
fn a_fire_on_a_draft_s_content_is_refused_before_any_deposit() {
    let engine = mem_engine();
    let member = addr(&[1, 0, 1, 0, 2, 0, 1, 1]); // a position of the draft
    let (home, draft) = board(&engine, &member);
    let mut coord = engine.coordinator();
    let rule = marker_rule(&engine, &coord, home);
    coord.register_rule(rule).expect("a well-formed rule registers");
    match coord.step(&engine.kernel().snapshot()) {
        StepOutcome::Failed { arg, err: FireError::DraftBoundary(d), .. } => {
            assert_eq!(arg, member);
            assert_eq!(d, draft, "the refusal names the argument's draft");
        }
        other => panic!("expected Failed(DraftBoundary(draft)), got {other:?}"),
    }
}

/// Home and argument both published: the same rule fires, and the marker is
/// a real deposit in the published home.
#[test]
fn a_fire_within_the_published_world_lands() {
    let engine = mem_engine();
    let member = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    let (home, _draft) = board(&engine, &member);
    let mut coord = engine.coordinator();
    let rule = marker_rule(&engine, &coord, home);
    let id = coord.register_rule(rule).expect("a well-formed rule registers");
    match coord.step(&engine.kernel().snapshot()) {
        StepOutcome::Fired { rule, arg, .. } => {
            assert_eq!(rule, id);
            assert_eq!(arg, member);
        }
        other => panic!("expected Fired, got {other:?}"),
    }
    let retired = engine.registry().reserved_type(ShippedType::Retired).clone();
    assert!(engine.kernel().snapshot().world().links().is_k(&retired, member.tumbler()));
    assert_eq!(coord.fire_count(id, &member), 1);
}

// ───────────────── the trigger's look at guest class (lane 4.1) ─────────────────

/// PUB-6.28's trigger half: a rule over class K whose ONLY matching tuple is
/// homed in a private draft does NOT fire. The tuple is invisible to the
/// rule's look at guest class, so the visible domain is empty — `next_enabled`
/// peeks nothing, `quiescent` holds, `step` reports `Quiescent` (the shape a
/// rule with no matching tuple has always had) — and a fire aimed by hand at
/// the draft's member is `NoOp` (the removed discharge), never
/// `DraftBoundary`: the trigger never reaches the action. Nothing is
/// committed and the divergence count stays at zero.
#[test]
fn a_rule_whose_only_matching_tuple_is_draft_homed_does_not_fire() {
    let engine = mem_engine();
    let member = addr(&[1, 0, 1, 0, 1, 0, 1, 1]); // a position of the PUBLISHED home
    let (home, draft) = docs(&engine);
    let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
    let retired = engine.registry().reserved_type(ShippedType::Retired).clone();

    // The only pred_stable tuple on the member, homed in the owner's draft.
    let (q, _) = engine
        .linkstore(&World::visible_to(OWNER))
        .emit(OWNER, &draft, &pred_stable, &member, &[])
        .expect("the owner deposits the relation in its own draft");
    assert_eq!(document_of(&q), Some(draft));
    assert!(
        engine.kernel().snapshot().world().links().is_k(&pred_stable, member.tumbler()),
        "M7's class-free read holds the tuple — it is the rule's look that must not"
    );

    let mut coord = engine.coordinator();
    let rule = marker_rule(&engine, &coord, home);
    let id = coord.register_rule(rule).expect("a well-formed rule registers");
    let snap = engine.kernel().snapshot();
    assert!(coord.next_enabled(&snap).is_none(), "the draft's tuple seeds no domain");
    assert!(coord.quiescent(&snap));
    match coord.step(&snap) {
        StepOutcome::Quiescent => {}
        other => panic!("expected Quiescent (an empty visible domain), got {other:?}"),
    }
    assert_eq!(
        coord.fire(&Occurrence { rule: id, arg: Arg::Addr(member.clone()) })
            .expect("a fire out of the visible domain is a NoOp, not an error"),
        FireOutcome::NoOp,
        "out of the visible domain: the removed discharge, never a draft-boundary refusal"
    );
    assert!(
        !engine.kernel().snapshot().world().links().is_k(&retired, member.tumbler()),
        "nothing was deposited"
    );
    assert_eq!(coord.fire_count(id, &member), 0);
}

/// PUB-6.28's second sentence, as a test: "a fire commits byte-identically to
/// a world with no drafts". Two engines run the same rule over the same
/// published home. In one, the owner's draft additionally holds a `retired`
/// marker on the member — which falsified the audit trigger `¬is_K(retired,
/// x)` before lane 4.1 — and a `pred_stable` tuple on a second member of the
/// home, which seeded the domain. Both worlds step to quiescence with ONE
/// fire each, and the deposited records — the effect's address and link
/// value, in M2's own wire encoding — are byte-identical.
#[test]
fn a_fire_commits_byte_identically_to_a_world_with_no_drafts() {
    let member = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    let other = addr(&[1, 0, 1, 0, 1, 0, 1, 2]); // another position of the published home
    let x = VarId::new(1).expect("a test variable below the watershed");

    // One world: the board, the rule (M_K over pred_stable at audit, trigger
    // ¬is_K(retired, x), Marker{home, retired}), stepped to quiescence; the
    // commits it made and the member's fire count.
    let run = |with_draft_tuples: bool| -> (Vec<Vec<u8>>, u64) {
        let engine = mem_engine();
        let (home, draft) = board(&engine, &member);
        let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
        let retired = engine.registry().reserved_type(ShippedType::Retired).clone();
        if with_draft_tuples {
            let visibility = World::visible_to(OWNER);
            let owner = engine.linkstore(&visibility);
            owner
                .emit(OWNER, &draft, &retired, &member, &[])
                .expect("the draft's own marker on the member");
            owner
                .emit(OWNER, &draft, &pred_stable, &other, &[])
                .expect("the draft's own relation on another member");
        }
        let mut coord = engine.coordinator();
        let trigger = Trigger::Inline(
            coord.type_check_trigger(
                (x, Sort::Addr),
                Term::Not(Arc::new(Term::Atom(Atom::IsK(
                    TypeRef::Concrete(TypeKey(retired.clone())),
                    Arc::new(Term::Var(x)),
                )))),
            )
            .expect("¬is_K(retired, x) type-checks"),
        );
        let id = coord
            .register_rule(Rule {
                domain: Dom::MembersDom(TypeRef::Concrete(TypeKey(pred_stable))),
                trigger,
                view: View::Audit,
                action: FireAction::Marker { home, ty: TypeKey(retired) },
            })
            .expect("a well-formed rule registers");
        let mut commits = Vec::new();
        loop {
            match coord.step(&engine.kernel().snapshot()) {
                StepOutcome::Fired { effect, .. } => {
                    let snap = engine.kernel().snapshot();
                    let link = snap
                        .world()
                        .links()
                        .readlink(&effect)
                        .expect("the effect is resident")
                        .clone();
                    commits.push(bincode::serialize(&(effect, link)).expect("a deposit serializes"));
                }
                StepOutcome::Quiescent => break,
                other => panic!("expected Fired or Quiescent, got {other:?}"),
            }
        }
        (commits, coord.fire_count(id, &member))
    };

    let (with_drafts, count_with) = run(true);
    let (without_drafts, count_without) = run(false);
    assert_eq!(with_drafts.len(), 1, "one fire, on the visible member alone");
    assert_eq!(
        with_drafts, without_drafts,
        "the fire's commit is byte-identical to a world with no drafts"
    );
    assert_eq!((count_with, count_without), (1, 1));
}

/// The VIEW is orthogonal to the CLASS (visibility is by HOME, PUB-1.31;
/// PUB-6.13): over the tuple domains and `L_dom`, the draft-homed tuple never
/// enters, while a RETRACTED tuple of the published home stays in the audit
/// readings — `AuditSlice` and `L_dom` keep it, `ActiveSlice` drops it for
/// its view's own reason. The rule engine's enumeration answers the same,
/// through `next_enabled`.
#[test]
fn domain_enumeration_excludes_the_draft_tuple_and_keeps_a_retracted_one() {
    let engine = mem_engine();
    let (home, draft) = docs(&engine);
    let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
    let member_1 = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    let member_2 = addr(&[1, 0, 1, 0, 1, 0, 1, 2]);
    let member_3 = addr(&[1, 0, 1, 0, 1, 0, 1, 3]);
    let visibility = World::visible_to(Caller::System);
    let system = engine.linkstore(&visibility);
    let (p1, _) = system
        .emit(Caller::System, &home, &pred_stable, &member_1, &[])
        .expect("p1 in the published home");
    let (p2, _) = system
        .emit(Caller::System, &home, &pred_stable, &member_2, &[])
        .expect("p2 in the published home");
    system
        .nullify(Caller::System, &home, &p2)
        .expect("p2 retracted — a public home's audit history");
    let (q, _) = engine
        .linkstore(&World::visible_to(OWNER))
        .emit(OWNER, &draft, &pred_stable, &member_3, &[])
        .expect("q in the owner's draft");
    assert_eq!(document_of(&q), Some(draft));

    let mut coord = engine.coordinator();
    let snap = engine.kernel().snapshot();
    let t = VarId::new(1).expect("a test variable below the watershed");
    let k = TypeRef::Concrete(TypeKey(pred_stable));

    // ∃ t ∈ D :: addr(t) = a — over a tuple domain through the V-TUP
    // projection, over L_dom (an address domain) by the bound address.
    let holds = |coord: &Coordinator<World>, dom: Dom, a: &Address, tuple_dom: bool| -> bool {
        let lhs = if tuple_dom { Term::Atom(Atom::TupAddr(t)) } else { Term::Var(t) };
        let body = Term::Prim(Prim::AddrEq(Arc::new(lhs), Arc::new(Term::Lit(Lit::Addr(a.clone())))));
        let term = Term::Exists { var: t, dom: Arc::new(dom), body: Arc::new(body) };
        let tt = coord.type_check(vec![], term).expect("a closed Bool term type-checks");
        coord.decide(&tt, &Env::empty(), View::Audit, &snap)
    };
    // AuditSlice: the retracted p2 stays; the draft's q never enters.
    assert!(holds(&coord, Dom::AuditSlice(k.clone()), &p1, true));
    assert!(holds(&coord, Dom::AuditSlice(k.clone()), &p2, true));
    assert!(!holds(&coord, Dom::AuditSlice(k.clone()), &q, true));
    // ActiveSlice: the view drops p2, the class drops q.
    assert!(holds(&coord, Dom::ActiveSlice(k.clone()), &p1, true));
    assert!(!holds(&coord, Dom::ActiveSlice(k.clone()), &p2, true));
    assert!(!holds(&coord, Dom::ActiveSlice(k.clone()), &q, true));
    // L_dom (audit, over every cataloged class): p1 and p2 in, q out.
    assert!(holds(&coord, Dom::LinkDom, &p1, false));
    assert!(holds(&coord, Dom::LinkDom, &p2, false));
    assert!(!holds(&coord, Dom::LinkDom, &q, false));
    // The count agrees: two visible audit tuples of the class.
    let two = coord
        .type_check(
            vec![],
            Term::Prim(Prim::NatEq(
                Arc::new(Term::Count(Arc::new(Dom::AuditSlice(k.clone())))),
                Arc::new(Term::Lit(Lit::Nat(Nat::from(2u32)))),
            )),
        )
        .expect("a closed Bool term type-checks");
    assert!(coord.decide(&two, &Env::empty(), View::Audit, &snap));

    // The rule engine's own enumeration: a Tup-domained rule whose trigger
    // names the draft's tuple peeks nothing; one naming the retracted tuple
    // of the published home peeks it.
    let names = |coord: &Coordinator<World>, a: &Address| -> Trigger {
        Trigger::Inline(
            coord.type_check_trigger(
                (t, Sort::Tup),
                Term::Prim(Prim::AddrEq(
                    Arc::new(Term::Atom(Atom::TupAddr(t))),
                    Arc::new(Term::Lit(Lit::Addr(a.clone()))),
                )),
            )
            .expect("a one-Tup-parameter Bool trigger type-checks"),
        )
    };
    let names_q = names(&coord, &q);
    let names_p2 = names(&coord, &p2);
    coord.register_rule(Rule {
        domain: Dom::AuditSlice(k.clone()),
        trigger: names_q,
        view: View::Audit,
        action: FireAction::Nullify { home: home.clone() },
    })
    .expect("a well-formed rule registers");
    let p2_rule = coord
        .register_rule(Rule {
            domain: Dom::AuditSlice(k),
            trigger: names_p2,
            view: View::Audit,
            action: FireAction::Nullify { home },
        })
        .expect("a well-formed rule registers");
    let e =
        coord.next_enabled(&snap).expect("the retracted tuple of the published home is enabled");
    assert_eq!(e.rule, p2_rule, "the draft's tuple enabled nothing: the first enabled occurrence is the second rule's");
    match e.arg {
        Arg::Tuple(tuple) => assert_eq!(tuple.addr, p2),
        other => panic!("a Tup-domained rule binds a tuple, got {other:?}"),
    }
}

/// A DEF trigger reads the same filtered store as an inline one: the def's
/// checked body, captured at registration, is evaluated through the same
/// guest-class context. The def is stored in the owner's draft (a def cannot be
/// defined into a published document) and its REGISTRATION is class-free —
/// it is the def's LOOK that is at guest class: a `retired` marker homed in
/// the draft is invisible to `T(x) = is_K(retired, x)` whether `T` is the
/// rule's `Def` trigger or its `Inline` twin; the same marker in the
/// published home is seen by both.
#[test]
fn a_def_trigger_sees_the_same_filtered_store_as_an_inline_one() {
    let engine = mem_engine();
    let member = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    let (home, draft) = board(&engine, &member); // pred_stable(member) in the published home
    let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
    let retired = engine.registry().reserved_type(ShippedType::Retired).clone();
    // The ONLY `retired` marker on the member: homed in the draft.
    engine
        .linkstore(&World::visible_to(OWNER))
        .emit(OWNER, &draft, &retired, &member, &[])
        .expect("the owner's marker in its own draft");

    let mut coord = engine.coordinator();
    let x = VarId::new(1).expect("a test variable below the watershed");
    let body = Term::Atom(Atom::IsK(
        TypeRef::Concrete(TypeKey(retired.clone())),
        Arc::new(Term::Var(x)),
    ));
    // T(x) = is_K(retired, x), defined into the draft and registered there
    // (class-free — a pdef tuple in a draft home is still ever-registered).
    let checked =
        coord.type_check(vec![(x, Sort::Addr)], body.clone()).expect("T type-checks");
    let (start, _) =
        coord.define_predicate(&draft, &checked).expect("a def is defined into a draft");
    let inline = Trigger::Inline(
        coord.type_check_trigger((x, Sort::Addr), body).expect("the same body as a trigger"),
    );
    let mk = |trigger: Trigger| Rule {
        domain: Dom::MembersDom(TypeRef::Concrete(TypeKey(pred_stable.clone()))),
        trigger,
        view: View::Audit,
        action: FireAction::Marker { home: home.clone(), ty: TypeKey(retired.clone()) },
    };
    let def_rule = coord
        .register_rule(mk(Trigger::Def(start.clone())))
        .expect("a Def trigger over an ever-registered Boolean def registers");
    let inline_rule = coord.register_rule(mk(inline)).expect("a well-formed rule registers");

    let snap = engine.kernel().snapshot();
    assert!(
        snap.world().links().is_k(&retired, member.tumbler()),
        "M7's class-free read holds the draft's marker"
    );
    assert_eq!(
        coord.evaluate_def(&start, &[Value::Addr(member.clone())], View::Audit, &snap),
        Ok(Value::Bool(false)),
        "the def's look is at guest class"
    );
    assert!(coord.next_enabled(&snap).is_none(), "neither trigger sees the draft's marker");
    assert!(coord.quiescent(&snap));
    for id in [def_rule, inline_rule] {
        assert_eq!(
            coord.fire(&Occurrence { rule: id, arg: Arg::Addr(member.clone()) })
                .expect("a falsified fire is a NoOp"),
            FireOutcome::NoOp,
            "the member is in the visible domain; the trigger, Def or Inline, reads no draft-homed marker"
        );
    }

    // The same marker in the PUBLISHED home: both triggers see it — the Def
    // rule first, in registration order.
    engine
        .linkstore(&World::visible_to(Caller::System))
        .emit(Caller::System, &home, &retired, &member, &[])
        .expect("a public marker on the member");
    let snap = engine.kernel().snapshot();
    assert_eq!(
        coord.evaluate_def(&start, &[Value::Addr(member.clone())], View::Audit, &snap),
        Ok(Value::Bool(true))
    );
    let e = coord.next_enabled(&snap).expect("the public marker enables both rules");
    assert_eq!(e.rule, def_rule);
    assert_eq!(e.arg, Arg::Addr(member));
    assert!(!coord.quiescent(&snap));
}
