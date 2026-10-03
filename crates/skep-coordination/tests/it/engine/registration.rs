//! Registration: every `register_rule` gate as its own typed rejection, in its
//! stated order; the nesting cap a rule's domain is checked to; the home an
//! action writes into; and `certify_rule`'s three legs, each failed alone.

use crate::common::*;
use crate::terms::*;

use skep_coordination::{
    Arg, Dom, FireAction, Rule, RuleCertification, RuleError, Sort, Term, Trigger, TypeError,
    TypeKey, TypeRef, View,
};
use skep_links::{enc, Caller, ShippedType};

/// Every `register_rule` validation gate, as a typed rejection — never a
/// deferred fire-time panic; `certify_rule` re-runs the same gates.
#[test]
fn register_rule_refuses_at_each_gate_with_its_own_rejection() {
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
        Err(RuleError::IllFormedDomain(TypeError::UncatalogedTypeKey(_)))
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
        c.register_rule(mk(Dom::ActiveSlice(concrete(&pred_stable_ty())), always_addr(&c), marker_action())),
        Err(RuleError::DomainTriggerSortMismatch { expected: Sort::Tup, found: Sort::Addr })
    ));
    // A Def trigger is Codom-only, so it can never serve a Tup domain.
    assert!(matches!(
        c.register_rule(mk(
            Dom::ActiveSlice(concrete(&pred_stable_ty())),
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
        c.register_rule(mk(Dom::MembersDom(concrete(&pred_stable_ty())), Trigger::Def(nat_def), marker_action())),
        Err(RuleError::TriggerNotBoolean)
    ));
    let (closed_def, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed def"))
        .expect("define a closed def");
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(concrete(&pred_stable_ty())), Trigger::Def(closed_def), marker_action())),
        Err(RuleError::BadTriggerArity)
    ));
    // A ref-bearing Inline trigger.
    let ref_trig = c
        .type_check_trigger((v(1), Sort::Addr), Term::Ref { addr: p_start.clone(), args: vec![at(var(1))] })
        .expect("ref-bearing trigger term");
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(concrete(&pred_stable_ty())), Trigger::Inline(ref_trig.clone()), marker_action())),
        Err(RuleError::RefBearingInlineTrigger)
    ));
    // A Def trigger with no defined signature.
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(concrete(&pred_stable_ty())), Trigger::Def(ca(77)), marker_action())),
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
            Dom::MembersDom(concrete(&pred_stable_ty())),
            always_addr(&c),
            FireAction::Marker { home: doc1(), ty: key(&retraction_ty()) }
        )),
        Err(RuleError::BadMarkerType(_))
    ));
    assert!(matches!(
        c.register_rule(mk(
            Dom::MembersDom(concrete(&pred_stable_ty())),
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
                    Dom::MembersDom(concrete(&pred_stable_ty())),
                    always_addr(&c),
                    FireAction::Marker { home: doc1(), ty }
                )),
                Err(RuleError::PredLayerMarkerType(_))
            ),
            "{reserved:?}"
        );
    }
    // The gates speak in order — the domain, then the trigger, then the
    // action — so a rule failing two reports the earlier.
    let bad_marker = || FireAction::Marker { home: doc1(), ty: key(&uncataloged_ty(20)) };
    assert!(matches!(
        c.register_rule(mk(Dom::Reg, always_addr(&c), bad_marker())),
        Err(RuleError::IllFormedDomain(_))
    ));
    assert!(matches!(
        c.register_rule(mk(
            Dom::ActiveSlice(concrete(&pred_stable_ty())),
            always_addr(&c),
            bad_marker()
        )),
        Err(RuleError::DomainTriggerSortMismatch { .. })
    ));
    // Within a group the stated order likewise decides: for an `Inline`
    // trigger ref-bearing speaks before the sort reconciliation …
    assert!(matches!(
        c.register_rule(mk(
            Dom::ActiveSlice(concrete(&pred_stable_ty())),
            Trigger::Inline(ref_trig),
            marker_action()
        )),
        Err(RuleError::RefBearingInlineTrigger)
    ));
    // … and for a `Def` trigger arity before the Boolean codomain.
    let (nat_closed, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], lit_nat(1)).expect("closed Nat def"))
        .expect("define a closed Nat-codomain def");
    assert!(matches!(
        c.register_rule(mk(
            Dom::MembersDom(concrete(&pred_stable_ty())),
            Trigger::Def(nat_closed),
            marker_action()
        )),
        Err(RuleError::BadTriggerArity)
    ));
}

/// A rule's domain is checked from nesting level 0 by the checker's
/// closed-domain judgment, which refuses a node past the cap — the bound
/// `enum_dom` and `Analyzer::dom` take for a checked domain, having none of
/// their own. A chain of filters whose innermost `L_dom` sits at the cap
/// registers, and is linted and enumerated through every level on this
/// default thread; one filter more is `IllFormedDomain(TooDeep)`.
#[test]
fn a_rule_domain_is_checked_to_the_nesting_cap() {
    let k = kernel();
    let mut c = coord(&k);
    let (link, _) = link_writer(&k)
        .emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[])
        .expect("one cataloged link, so L_dom has an element to pass through");
    // The outermost filter at level 0, filter k at level k, the innermost
    // `L_dom` at level n.
    let filters = |n: usize| (0..n).fold(Dom::LinkDom, |d, _| filter(d, 2, tru()));
    let rule = |domain: Dom, trigger: Trigger| Rule {
        domain,
        trigger,
        view: View::Audit,
        action: marker_action(),
    };
    let at_cap = rule(filters(128), always_addr(&c));
    c.certify_rule(&at_cap).expect("the lint analyzes a domain at the cap");
    c.register_rule(at_cap).expect("a domain at the cap registers");
    assert_eq!(c.next_enabled(&k.snapshot()).map(|o| o.arg), Some(Arg::Addr(link)));
    assert!(matches!(
        c.register_rule(rule(filters(129), always_addr(&c))),
        Err(RuleError::IllFormedDomain(TypeError::TooDeep))
    ));
}

/// `FireAction::home` answers the one fact both variants share — the document
/// a fire of the action writes into, which the draft-boundary filter, M7's
/// H-HOME gate and the divergence monitor's key each read. The enum being
/// `#[non_exhaustive]`, this accessor is the only way a driver outside the
/// crate can learn it: a caller cannot match the variants exhaustively.
#[test]
fn a_fire_action_reports_the_home_it_writes_into() {
    let marker = FireAction::Marker { home: doc1(), ty: key(&marker_ty()) };
    assert_eq!(marker.home(), &doc1());
    assert_eq!(FireAction::Nullify { home: doc2() }.home(), &doc2());
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
    let members_dom = || Dom::MembersDom(concrete(&pred_stable_ty()));
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
        lint(members_dom(), trig(not(is_k(&marker_ty(), var(1)))), View::Active),
        uncertified(false, false, false)
    );
    // (b) the witness class must be the marker's.
    assert_eq!(
        lint(members_dom(), trig(not(is_k(&pred_stable_ty(), var(1)))), View::Audit),
        uncertified(true, false, true)
    );
    // (b) the witness must be the trigger's parameter.
    assert_eq!(
        lint(members_dom(), trig(not(is_k(&marker_ty(), lit_addr(&ca(1))))), View::Audit),
        uncertified(true, false, true)
    );
    // (c) a Filter by an SF predicate leaves the grow-only closure.
    assert_eq!(
        lint(
            filter(members_dom(), 2, not(is_k(&marker_ty(), var(2)))),
            trig(not(is_k(&marker_ty(), var(1)))),
            View::Audit
        ),
        uncertified(true, true, false)
    );
    // (b) by spelling: the tuple's address is not the parameter.
    let tup = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Tup), not(is_k(&marker_ty(), tup_addr(1))))
            .expect("Tup trigger"),
    );
    assert_eq!(
        lint(Dom::AuditSlice(concrete(&pred_stable_ty())), tup, View::Audit),
        uncertified(true, false, true)
    );
}
