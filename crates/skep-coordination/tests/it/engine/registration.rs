//! Registration: every `register_rule` gate as its own typed rejection, in its
//! stated order, and `certify_rule` refusing exactly what it refuses; the
//! nesting cap a rule's domain is checked to; the home an action writes into;
//! and `certify_rule`'s three legs, each failed alone.

use crate::common::*;
use crate::terms::*;

use skep_coordination::{
    Arg, Dom, FireAction, Rule, RuleCertification, RuleError, Sort, Term, Trigger, TypeError,
    TypeKey, TypeRef, View,
};
use skep_links::{enc, Caller, Endset, ShippedType};

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

    let rule = |domain: Dom, trigger: Trigger, action: FireAction| Rule {
        domain,
        trigger,
        view: View::Active,
        action,
    };

    // A bare Reg domain is misplaced: `Reg` ranges over classes.
    assert!(matches!(
        c.register_rule(rule(Dom::Reg, always_addr(&c), marker_action())),
        Err(RuleError::IllFormedDomain(TypeError::MisplacedReg))
    ));
    // certify_rule re-runs the same validation: a malformed rule is the same
    // typed rejection, callable pre-registration.
    assert!(matches!(
        c.certify_rule(&rule(Dom::Reg, always_addr(&c), marker_action())),
        Err(RuleError::IllFormedDomain(TypeError::MisplacedReg))
    ));
    // An uncataloged domain class.
    assert!(matches!(
        c.register_rule(rule(
            Dom::MembersDom(TypeRef::Concrete(TypeKey(enc(&[ra(20)])))),
            always_addr(&c),
            marker_action()
        )),
        Err(RuleError::IllFormedDomain(TypeError::UncatalogedTypeKey(_)))
    ));
    // A Ref inside the domain body — no Def escape for domains.
    assert!(matches!(
        c.register_rule(rule(
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
        c.register_rule(rule(Dom::ActiveSlice(concrete(&pred_stable_ty())), always_addr(&c), marker_action())),
        Err(RuleError::DomainTriggerSortMismatch { expected: Sort::Tup, found: Sort::Addr })
    ));
    // A Def trigger is Codom-only, so it can never serve a Tup domain.
    assert!(matches!(
        c.register_rule(rule(
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
        c.register_rule(rule(Dom::MembersDom(concrete(&pred_stable_ty())), Trigger::Def(nat_def.clone()), marker_action())),
        Err(RuleError::TriggerNotBoolean)
    ));
    let (closed_def, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed def"))
        .expect("define a closed def");
    assert!(matches!(
        c.register_rule(rule(Dom::MembersDom(concrete(&pred_stable_ty())), Trigger::Def(closed_def), marker_action())),
        Err(RuleError::BadTriggerArity)
    ));
    // A ref-bearing Inline trigger.
    let ref_trig = c
        .type_check_trigger((v(1), Sort::Addr), Term::Ref { addr: p_start.clone(), args: vec![at(var(1))] })
        .expect("ref-bearing trigger term");
    assert!(matches!(
        c.register_rule(rule(Dom::MembersDom(concrete(&pred_stable_ty())), Trigger::Inline(ref_trig.clone()), marker_action())),
        Err(RuleError::RefBearingInlineTrigger)
    ));
    // A Def trigger with no defined signature.
    assert!(matches!(
        c.register_rule(rule(Dom::MembersDom(concrete(&pred_stable_ty())), Trigger::Def(ca(77)), marker_action())),
        Err(RuleError::UndefinedDefTrigger(_))
    ));
    // Marker.ty guards: cataloged Unary and non-PredLayer. A Binary shipped
    // class and an uncataloged number both land BadMarkerType; the PredLayer
    // pair is refused by name (PR-DISC), each of its two classes. The
    // `NonIdemMarkerType` arm is structurally unreachable in this format —
    // every cataloged Unary class is idem⊤ — and stays declared for the day
    // a registered idem⊥ Unary class exists again.
    assert!(matches!(
        c.register_rule(rule(
            Dom::MembersDom(concrete(&pred_stable_ty())),
            always_addr(&c),
            FireAction::Marker { home: doc1(), ty: key(&retraction_ty()) }
        )),
        Err(RuleError::BadMarkerType(_))
    ));
    assert!(matches!(
        c.register_rule(rule(
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
                c.register_rule(rule(
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
        c.register_rule(rule(Dom::Reg, always_addr(&c), bad_marker())),
        Err(RuleError::IllFormedDomain(_))
    ));
    assert!(matches!(
        c.register_rule(rule(
            Dom::ActiveSlice(concrete(&pred_stable_ty())),
            always_addr(&c),
            bad_marker()
        )),
        Err(RuleError::DomainTriggerSortMismatch { .. })
    ));
    // Within a group the stated order likewise decides: for an `Inline`
    // trigger ref-bearing speaks before the sort reconciliation …
    assert!(matches!(
        c.register_rule(rule(
            Dom::ActiveSlice(concrete(&pred_stable_ty())),
            Trigger::Inline(ref_trig),
            marker_action()
        )),
        Err(RuleError::RefBearingInlineTrigger)
    ));
    // … and for a `Def` trigger arity before the Boolean codomain …
    let (nat_closed, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], lit_nat(1)).expect("closed Nat def"))
        .expect("define a closed Nat-codomain def");
    assert!(matches!(
        c.register_rule(rule(
            Dom::MembersDom(concrete(&pred_stable_ty())),
            Trigger::Def(nat_closed),
            marker_action()
        )),
        Err(RuleError::BadTriggerArity)
    ));
    // … then the Boolean codomain before the sort reconciliation: an ℕ-valued
    // def over a tuple domain fails both.
    assert!(matches!(
        c.register_rule(rule(
            Dom::ActiveSlice(concrete(&pred_stable_ty())),
            Trigger::Def(nat_def),
            marker_action()
        )),
        Err(RuleError::TriggerNotBoolean)
    ));
}

/// `certify_rule` runs `register_rule`'s one shared validation: every rule
/// `register_rule` refuses, `certify_rule` refuses with the same variant — the
/// law over one malformed rule per gate, each at `audit` with the canonical
/// trigger so the lint's Marker leg would reach the marker type's class. That
/// leg asks the catalog for the class, a question an uncataloged type has no
/// answer to: a lint that skipped the doorkeeper would panic where it must
/// refuse, and would certify where it must refuse a PredLayer or Binary
/// marker.
#[test]
fn certify_rule_refuses_exactly_what_register_rule_refuses() {
    let k = kernel();
    let mut c = coord(&k);
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("P(x)"))
        .expect("define P");
    let (nat_def, _) = c
        .define_predicate(
            &doc1(),
            &c.type_check(vec![(v(1), Sort::Addr)], lit_nat(1)).expect("an ℕ-codomain def"),
        )
        .expect("define an ℕ-codomain def");
    let (closed_def, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("a closed def"))
        .expect("define a closed def");
    let ref_trig = c
        .type_check_trigger(
            (v(1), Sort::Addr),
            Term::Ref { addr: p.clone(), args: vec![at(var(1))] },
        )
        .expect("a ref-bearing trigger");
    let members_dom = || Dom::MembersDom(concrete(&pred_stable_ty()));
    let marker_of = |ty: &Endset| FireAction::Marker { home: doc1(), ty: key(ty) };
    let rule = |domain: Dom, trigger: Trigger, action: FireAction| Rule {
        domain,
        trigger,
        view: View::Audit,
        action,
    };
    let in_domain = Term::Ref { addr: p.clone(), args: vec![at(var(2))] };
    let malformed = vec![
        rule(Dom::Reg, not_marked(&c), marker_action()),
        rule(Dom::MembersDom(concrete(&uncataloged_ty(20))), not_marked(&c), marker_action()),
        rule(filter(Dom::LinkDom, 2, in_domain), not_marked(&c), marker_action()),
        rule(Dom::ActiveSlice(concrete(&pred_stable_ty())), not_marked(&c), marker_action()),
        rule(members_dom(), Trigger::Inline(ref_trig), marker_action()),
        rule(members_dom(), Trigger::Def(ca(77)), marker_action()),
        rule(members_dom(), Trigger::Def(closed_def), marker_action()),
        rule(members_dom(), Trigger::Def(nat_def), marker_action()),
        rule(members_dom(), not_marked(&c), marker_of(&retraction_ty())),
        rule(members_dom(), not_marked(&c), marker_of(&uncataloged_ty(20))),
        rule(members_dom(), not_marked(&c), marker_of(&pred_def_ty())),
        rule(members_dom(), not_marked(&c), marker_of(&pred_stable_ty())),
    ];
    for r in malformed {
        let linted = c.certify_rule(&r).err();
        let refused = c.register_rule(r.clone()).err();
        assert!(refused.is_some(), "register_rule admitted {r:?}");
        assert_eq!(linted, refused, "{r:?}");
    }
}

/// A rule's domain is checked from nesting level 0 by the checker's
/// closed-domain judgment, which refuses a node past the cap — the bound
/// `enum_dom` and `Analyzer::dom` take for a checked domain, having none of
/// their own. A chain of filters whose innermost `L_dom` sits at the cap
/// registers, and is linted and enumerated through every level on a thread
/// of the default 2 MiB stack (`on_the_default_stack`); one filter more is
/// `IllFormedDomain(TooDeep)`.
#[test]
fn a_rule_domain_is_checked_to_the_nesting_cap() {
    on_the_default_stack(|| {
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
    });
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
/// declared view; the witness the trigger negates must be of the marker's
/// own class AND cover the trigger's parameter; a `Filter` by an SF predicate
/// leaves the grow-only closure; and a tuple-domained trigger over the
/// tuple's address is not the canonical spelling (sound-but-incomplete, by
/// spelling).
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
    // (b) the witness must cover the trigger's parameter.
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
