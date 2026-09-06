//! M9's fires at GUEST class through the assembled engine (PUB round 2, lane
//! 3.3, §5): the `Coordinator` the engine assembles carries
//! `World::readable_guest` — `published(doc)` — and a fire whose Marker home
//! or bound argument lies in a private draft is refused before any deposit,
//! as a `Failed` step naming the draft. What is tested is the ASSEMBLY (the
//! predicate reaches M9, and it is the publication read); the refusal's own
//! order is M9's suite.

mod common;

use common::*;
use skep_coordination::{
    Dom, FireAction, FireError, Lit, Rule, Sort, StepOutcome, Term, TriggerRef, TypeKey, TypeRef,
    VarId,
};
use skep_engine::Engine;
use skep_links::{Caller, HasLinks, ShippedType, View};

/// An always-true one-Addr-parameter trigger.
fn always(c: &skep_coordination::Coordinator<skep_engine::World>) -> TriggerRef {
    let x = VarId::new(1).expect("a test variable below the watershed");
    TriggerRef::Inline(
        c.type_check_trigger(vec![(x, Sort::Addr)], Term::Lit(Lit::True))
            .expect("an always-true trigger type-checks"),
    )
}

/// A Marker rule over the members of the shipped `pred_stable` class, marking
/// them `retired` (the one cataloged Unary idem⊤ class outside the PredLayer
/// pair) in `home`.
fn marker_rule(engine: &Engine, c: &skep_coordination::Coordinator<skep_engine::World>, home: skep_address::Address) -> Rule {
    let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
    let retired = engine.registry().reserved_type(ShippedType::Retired).clone();
    Rule {
        domain: Dom::MembersDom(TypeRef::Concrete(TypeKey(pred_stable))),
        trigger: always(c),
        view: View::Audit,
        action: FireAction::Marker { home, ty: TypeKey(retired) },
    }
}

/// The published home `1.0.1.0.1` and the private draft `1.0.1.0.2` of the
/// genesis node's first account, plus a `pred_stable` member at `member`.
fn board(engine: &Engine, member: &skep_address::Address) -> (skep_address::Address, skep_address::Address) {
    let (acct, home) = setup_home(engine);
    assert_eq!(home, addr(&[1, 0, 1, 0, 1]), "the first account's home is its doc 1");
    let (draft, _) = engine
        .namespace()
        .create_new_document(USER, &acct, None)
        .expect("the second flagless mint is a private draft");
    assert_eq!(draft, addr(&[1, 0, 1, 0, 2]));
    let pred_stable = engine.registry().reserved_type(ShippedType::PredStable).clone();
    engine
        .linkstore()
        .emit(Caller::System, &home, &pred_stable, member, &[])
        .expect("the member relation deposits in the published home");
    (home, draft)
}

/// A Marker whose HOME is the private draft: refused at the draft boundary,
/// naming the draft; nothing deposited.
#[test]
fn a_fire_into_a_draft_home_is_refused_before_any_deposit() {
    let engine = mem_engine();
    let member = addr(&[1, 0, 1, 0, 1, 0, 1, 1]); // a position of the published home
    let (_home, draft) = board(&engine, &member);
    let mut c = engine.coordinator();
    let rule = marker_rule(&engine, &c, draft.clone());
    let id = c.register_rule(rule).expect("a well-formed rule registers");
    match c.step(&engine.kernel().snapshot()) {
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
    let mut c = engine.coordinator();
    let rule = marker_rule(&engine, &c, home);
    c.register_rule(rule).expect("a well-formed rule registers");
    match c.step(&engine.kernel().snapshot()) {
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
    let mut c = engine.coordinator();
    let rule = marker_rule(&engine, &c, home);
    let id = c.register_rule(rule).expect("a well-formed rule registers");
    match c.step(&engine.kernel().snapshot()) {
        StepOutcome::Fired { rule, arg, .. } => {
            assert_eq!(rule, id);
            assert_eq!(arg, member);
        }
        other => panic!("expected Fired, got {other:?}"),
    }
    let retired = engine.registry().reserved_type(ShippedType::Retired).clone();
    assert!(engine.kernel().snapshot().world().links().is_k(&retired, member.tumbler()));
    assert_eq!(c.fire_count(id, &member), 1);
}
