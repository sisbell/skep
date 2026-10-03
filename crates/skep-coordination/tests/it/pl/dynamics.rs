//! Dynamics (`classify`): PD0's lattice placed by spelling, PR-VIEW's
//! view-independence scan, the footprint each view charges, and the
//! classifier's precondition.

use crate::common::*;
use crate::terms::*;

use skep_coordination::{Dom, Sort, Stability, Term, View};
use skep_links::{coverage_class, ShippedType};

/// PD0 by spelling: the 4-point lattice, the count-threshold split, the
/// per-view audit-is_K rule, the PR-VIEW scan, and the named active-view
/// exception.
#[test]
fn classify_places_a_spelling_on_the_lattice_relative_to_its_view() {
    let k = kernel();
    let c = coord(&k);
    let tc = |t: Term| c.type_check(vec![], t).expect("test term type-checks");
    let tc1 = |t: Term| c.type_check(vec![(v(1), Sort::Addr)], t).expect("test term type-checks");

    // ∃ over the grow-only L_K is ST; its negation SF.
    let ex = tc(exists(2, Dom::AuditSlice(concrete(&pred_def_ty())), tru()));
    assert_eq!(c.classify(&ex, View::Audit).stability, Stability::StOnly);
    let nex = tc(not(exists(2, Dom::AuditSlice(concrete(&pred_def_ty())), tru())));
    assert_eq!(c.classify(&nex, View::Audit).stability, Stability::SfOnly);

    // Lower-bound counts ST, upper-bound SF, equality Neither (the
    // authoring-precision recommendation's substance).
    let lo = tc(nat_le(lit_nat(2), count(Dom::AuditSlice(concrete(&pred_def_ty())))));
    assert_eq!(c.classify(&lo, View::Audit).stability, Stability::StOnly);
    let hi = tc(nat_le(count(Dom::AuditSlice(concrete(&pred_def_ty()))), lit_nat(2)));
    assert_eq!(c.classify(&hi, View::Audit).stability, Stability::SfOnly);
    let eq = tc(nat_eq(count(Dom::AuditSlice(concrete(&pred_def_ty()))), lit_nat(2)));
    assert_eq!(c.classify(&eq, View::Audit).stability, Stability::Neither);

    // A codomain other than Bool: the two directions coincide — `StSf`
    // exactly when the term reads no state, `Neither` otherwise, a grow-only
    // set included.
    assert_eq!(c.classify(&tc(lit_nat(1)), View::Audit).stability, Stability::StSf);
    let card = tc(count(Dom::AuditSlice(concrete(&pred_def_ty()))));
    assert_eq!(c.classify(&card, View::Audit).stability, Stability::Neither);
    let audit_members = tc(members(&pred_def_ty()));
    assert_eq!(c.classify(&audit_members, View::Audit).stability, Stability::Neither);

    // Audit is_K at a step-constant argument is ST; the SAME term classified
    // at Active is Neither (PC3: classification is relative to the view).
    let isk = tc1(is_k(&marker_ty(), var(1)));
    assert_eq!(c.classify(&isk, View::Audit).stability, Stability::StOnly);
    assert_eq!(c.classify(&isk, View::Active).stability, Stability::Neither);

    // PR-VIEW: is_K is view-parameterized; an L_K-only spelling is not.
    assert!(!c.classify(&isk, View::Audit).view_independent);
    assert!(c.classify(&ex, View::Audit).view_independent);

    // The named exception: an active-slice read can shrink under retraction —
    // a property of the footprint, so the flag and the footprint's own
    // accessor are one answer.
    let act = tc(exists(2, Dom::ActiveSlice(concrete(&pred_def_ty())), tru()));
    assert!(c.classify(&act, View::Active).active_exceptions.retraction_shrinks);
    assert!(c.classify(&act, View::Active).footprint.retraction_shrinks());
    assert!(!c.classify(&ex, View::Audit).active_exceptions.retraction_shrinks);
    assert!(!c.classify(&ex, View::Audit).footprint.retraction_shrinks());

    // The footprint, read back: the slices each spelling reads and nothing
    // else — L_K in the audit set, A_K in the active set, an audit is_K at
    // the marker class in the audit set, L_dom the whole audit sublayer,
    // is_doc the residence domain.
    let pdef_class = coverage_class(&pred_def_ty());
    let marker_class = coverage_class(&marker_ty());
    let fp_ex = c.classify(&ex, View::Audit).footprint;
    assert!(fp_ex.audit_classes().any(|k| *k == pdef_class));
    assert_eq!(fp_ex.active_classes().count(), 0);
    assert!(!fp_ex.reads_all_audit() && !fp_ex.reads_residence());
    assert!(!fp_ex.reads_home_frontier() && !fp_ex.reads_targets_keyed());
    let fp_act = c.classify(&act, View::Active).footprint;
    assert!(fp_act.active_classes().any(|k| *k == pdef_class));
    assert_eq!(fp_act.audit_classes().count(), 0);
    let fp_isk = c.classify(&isk, View::Audit).footprint;
    assert!(fp_isk.audit_classes().any(|k| *k == marker_class));
    let ldom = tc(exists(2, Dom::LinkDom, tru()));
    assert!(c.classify(&ldom, View::Audit).footprint.reads_all_audit());
    let isdoc = tc1(is_doc(var(1)));
    assert!(c.classify(&isdoc, View::Audit).footprint.reads_residence());
}

/// PR-VIEW's scan refuses EXACTLY the view-parameterized constituents and the
/// UV-rewritten collection atoms — wherever they sit, under a filter's
/// predicate or inside a set-term domain included, where the scan must
/// descend to find them. It is the gate `certify_stable` stands behind, so a
/// form dropped from it certifies a def whose ⊤-stability holds at one view
/// and not another, and a form wrongly added to it refuses a legitimate def.
#[test]
fn view_independence_refuses_every_view_parameterized_and_uv_rewritten_form() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let ps = pred_stable_ty();
    let independent = |t: Term| {
        let tt = c.type_check(vec![], t).expect("test term type-checks");
        let at_view = |view: View| c.classify(&tt, view).view_independent;
        // `view_independent` is the one report `Dynamics` calls view-AGNOSTIC,
        // so every row below states its claim at all three views at once.
        assert_eq!(
            at_view(View::Active),
            at_view(View::Audit),
            "view_independent moved with the view"
        );
        assert_eq!(
            at_view(View::Audit),
            at_view(View::Default),
            "view_independent moved with the view"
        );
        at_view(View::Audit)
    };
    // `sources_to`/`stale` are out of the vocabulary in this format.
    for t in [
        is_k(&ps, lit_addr(&ca(1))),
        members(&ps),
        targets_of(&ps, lit_addr(&ca(1))),
        succs(&sup, lit_addr(&ca(1))),
        chain(&sup, lit_addr(&ca(1))),
        count(Dom::MembersDom(concrete(&ps))),
        // Found wherever it sits: under a filter's predicate, inside a
        // set-term domain.
        count(filter(Dom::AuditSlice(concrete(&ps)), 2, is_k(&ps, lit_addr(&ca(1))))),
        count(Dom::SetTerm(at(members(&ps)))),
    ] {
        assert!(!independent(t.clone()), "view-dependent: {t:?}");
    }
    for t in [
        is_filtered(&retired_ty(), lit_addr(&ca(1))),
        tip(&sup, lit_addr(&ca(1))),
        is_in_chain(&sup, lit_addr(&ca(1)), lit_addr(&ca(2))),
        is_doc(lit_addr(&doc1())),
        count(Dom::ActiveSlice(concrete(&ps))),
        count(Dom::AuditSlice(concrete(&ps))),
        count(Dom::LinkDom),
        count(filter(Dom::AuditSlice(concrete(&ps)), 2, is_doc(lit_addr(&doc1())))),
        count(Dom::SetTerm(at(big_union(Dom::AuditSlice(concrete(&ps)), 2, tup_addrs_g(2))))),
    ] {
        assert!(independent(t.clone()), "view-independent: {t:?}");
    }
}

/// PD0's rules over a generated family: four atoms, one per lattice point,
/// combined through every connective and compared against the stated rule
/// (`∧`/`∨` need both sides; `⇒` combines SF⇒ST; `⇔` needs both sides
/// wholly stable; `¬` swaps) — then each named rule at one assertion: the
/// quantifier cases, `Let` and `IfSome` under a state-reading versus a
/// constant part, grow-only membership and emptiness at audit only, the
/// derived closure forms and the bases under which each can shrink,
/// residence's ⊤-stability, a non-literal threshold, and the Default view's
/// BH1 charge.
#[test]
fn the_pd0_rules_hold_over_a_generated_family() {
    let k = kernel();
    let c = coord(&k);
    let pd = || concrete(&pred_def_ty());
    let lattice = |st: bool, sf: bool| match (st, sf) {
        (true, true) => Stability::StSf,
        (true, false) => Stability::StOnly,
        (false, true) => Stability::SfOnly,
        (false, false) => Stability::Neither,
    };
    let stab = |t: Term, view: View| c.classify(&c.type_check(vec![], t).expect("checks"), view).stability;

    let ex = exists(2, Dom::AuditSlice(pd()), tru());
    let atoms = [
        (ex.clone(), true, false),
        (not(ex.clone()), false, true),
        (tru(), true, true),
        (exists(2, Dom::ActiveSlice(pd()), tru()), false, false),
    ];
    for (x, xst, xsf) in &atoms {
        assert_eq!(stab(x.clone(), View::Audit), lattice(*xst, *xsf), "{x:?}");
        assert_eq!(stab(not(x.clone()), View::Audit), lattice(*xsf, *xst), "¬{x:?}");
        for (y, yst, ysf) in &atoms {
            let (both_st, both_sf) = (*xst && *yst, *xsf && *ysf);
            assert_eq!(stab(and(x.clone(), y.clone()), View::Audit), lattice(both_st, both_sf), "∧");
            assert_eq!(stab(or(x.clone(), y.clone()), View::Audit), lattice(both_st, both_sf), "∨");
            assert_eq!(stab(implies(x.clone(), y.clone()), View::Audit), lattice(*xsf && *yst, *xst && *ysf), "⇒");
            let whole = *xst && *xsf && *yst && *ysf;
            assert_eq!(stab(iff(x.clone(), y.clone()), View::Audit), lattice(whole, whole), "⇔");
        }
    }

    // Quantifiers: ∀ over a grow-only domain is SF; over an active slice, neither.
    assert_eq!(stab(forall(2, Dom::AuditSlice(pd()), tru()), View::Audit), Stability::SfOnly);
    assert_eq!(stab(forall(2, Dom::ActiveSlice(pd()), tru()), View::Audit), Stability::Neither);
    // `L_dom` is grow-only — an audit union — and names no view, so ∃ over it
    // is ST at every one.
    assert_eq!(stab(exists(2, Dom::LinkDom, tru()), View::Audit), Stability::StOnly);
    assert_eq!(stab(exists(2, Dom::LinkDom, tru()), View::Active), Stability::StOnly);
    // Let: a state-reading bound term is Neither; a constant one is transparent.
    assert_eq!(stab(let_(3, ex.clone(), tru()), View::Audit), Stability::Neither);
    assert_eq!(stab(let_(3, lit_nat(1), ex.clone()), View::Audit), Stability::StOnly);
    // IfSome: a state-reading guard is Neither; a constant guard is transparent.
    assert_eq!(
        stab(if_some(Term::MaxT1(ad(Dom::MembersDom(pd()))), 2, tru(), tru()), View::Audit),
        Stability::Neither
    );
    assert_eq!(stab(if_some(bot_addr(), 2, ex.clone(), ex.clone()), View::Audit), Stability::StOnly);
    // Grow-only sets: membership at a constant probe is ST, emptiness SF — at audit only.
    assert_eq!(stab(set_mem(lit_addr(&ca(1)), members(&pred_def_ty())), View::Audit), Stability::StOnly);
    assert_eq!(stab(set_mem(lit_addr(&ca(1)), members(&pred_def_ty())), View::Active), Stability::Neither);
    assert_eq!(stab(is_empty(members(&pred_def_ty())), View::Audit), Stability::SfOnly);
    assert_eq!(stab(is_empty(members(&pred_def_ty())), View::Active), Stability::Neither);
    // The derived closure forms: ⋃ over L_K of a per-binding constant, a
    // Filter of L_K by an ST predicate (and not by an SF one), Reflect of an
    // audit M_K.
    assert_eq!(
        stab(set_mem(lit_addr(&ca(1)), big_union(Dom::AuditSlice(pd()), 2, tup_addrs_f(2))), View::Audit),
        Stability::StOnly
    );
    assert_eq!(
        stab(nat_le(lit_nat(2), count(filter(Dom::AuditSlice(pd()), 2, tru()))), View::Audit),
        Stability::StOnly
    );
    assert_eq!(
        stab(
            nat_le(lit_nat(2), count(filter(Dom::AuditSlice(pd()), 2, not(is_k(&pred_def_ty(), tup_addr(2)))))),
            View::Audit
        ),
        Stability::Neither
    );
    assert_eq!(stab(set_mem(lit_addr(&ca(1)), reflect(Dom::MembersDom(pd()))), View::Audit), Stability::StOnly);
    // … and each grows only where its base does: Reflect of an active M_K, ⋃
    // over A_K, a set-term domain over an active `members` can shrink;
    // `targets_of` at a constant argument is grow-only at audit and nowhere
    // else.
    assert_eq!(
        stab(set_mem(lit_addr(&ca(1)), reflect(Dom::MembersDom(pd()))), View::Active),
        Stability::Neither
    );
    assert_eq!(
        stab(
            set_mem(lit_addr(&ca(1)), big_union(Dom::ActiveSlice(pd()), 2, tup_addrs_f(2))),
            View::Audit
        ),
        Stability::Neither
    );
    let in_targets = || set_mem(lit_addr(&ca(2)), targets_of(&pred_def_ty(), lit_addr(&ca(1))));
    assert_eq!(stab(in_targets(), View::Audit), Stability::StOnly);
    assert_eq!(stab(in_targets(), View::Active), Stability::Neither);
    let over_members = || nat_le(lit_nat(2), count(Dom::SetTerm(at(members(&pred_def_ty())))));
    assert_eq!(stab(over_members(), View::Audit), Stability::StOnly);
    assert_eq!(stab(over_members(), View::Active), Stability::Neither);
    // Residence only ever extends: ST, and never SF.
    assert_eq!(stab(is_doc(lit_addr(&doc1())), View::Audit), Stability::StOnly);
    // A threshold that is not a literal leaves the count unclassified (the
    // widening to a bound parameter is certification-only).
    assert_eq!(
        stab(nat_le(nat_add(lit_nat(1), lit_nat(1)), count(Dom::AuditSlice(pd()))), View::Audit),
        Stability::Neither
    );
    // The Default reading of a core atom charges every BH1 filter slice.
    let isk = c.type_check(vec![(v(1), Sort::Addr)], is_k(&pred_def_ty(), var(1))).expect("checks");
    let retired = coverage_class(&retired_ty());
    assert!(c.classify(&isk, View::Default).footprint.active_classes().any(|x| *x == retired));
    assert!(!c.classify(&isk, View::Active).footprint.active_classes().any(|x| *x == retired));
}

/// A `default`-view term charges the BH1 filter slices for exactly the reads
/// the evaluator UV-rewrites, and for no others: `chain` and `succs` — the
/// collections the rewrite post-filters — carry Retired's slice beside their
/// own class, while `tip` and `is_in_chain`, the verdict/traversal atoms at
/// the SAME class and the same view, carry only their own; the core
/// `members`/`targets_of` and an `M_K` domain carry it, the two tuple slices
/// do not. At `Active` no read carries it, the rewrite not running.
#[test]
fn the_default_view_charges_bh1_slices_for_exactly_the_uv_rewritten_reads() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let retired = coverage_class(&retired_ty());
    let charges = |t: &Term, view: View| {
        let tt = c.type_check(vec![], t.clone()).expect("test term type-checks");
        c.classify(&tt, view).footprint.active_classes().any(|x| *x == retired)
    };
    for t in [
        members(&pred_def_ty()),
        targets_of(&pred_def_ty(), lit_addr(&ca(1))),
        chain(&sup, lit_addr(&ca(1))),
        succs(&sup, lit_addr(&ca(1))),
        count(Dom::MembersDom(concrete(&pred_def_ty()))),
    ] {
        assert!(charges(&t, View::Default), "UV-rewritten at Default: {t:?}");
        assert!(!charges(&t, View::Active), "no rewrite at Active: {t:?}");
    }
    for t in [
        tip(&sup, lit_addr(&ca(1))),
        is_in_chain(&sup, lit_addr(&ca(1)), lit_addr(&ca(2))),
        count(Dom::ActiveSlice(concrete(&pred_def_ty()))),
        count(Dom::AuditSlice(concrete(&pred_def_ty()))),
    ] {
        assert!(!charges(&t, View::Default), "never UV-rewritten: {t:?}");
    }
}

/// The analyzer reads each `Count`'s domain once per threshold: a
/// threshold nested inside its own domain's filter forty levels deep —
/// `count(Filter{L_K, t, count(Filter{L_K, t, …}) ≤ 1}) ≤ 1` — is linear
/// work, and this gate completing is the pin (doubling per level is 2⁴⁰
/// domain analyses, which never returns). By PD0 the innermost upper bound
/// over `L_K` is SF, and a `Filter` by an SF predicate leaves the grow-only
/// closure, so every level above it is Neither.
#[test]
fn classify_analyzes_each_domain_once() {
    let k = kernel();
    let c = coord(&k);
    let l_k = || Dom::AuditSlice(concrete(&pred_def_ty()));
    let innermost = nat_le(count(l_k()), lit_nat(1));
    let nested = |levels: u32| {
        (0..levels).fold(innermost.clone(), |t, _| nat_le(count(filter(l_k(), 2, t)), lit_nat(1)))
    };
    let t0 = c.type_check(vec![], nested(0)).expect("checks");
    assert_eq!(c.classify(&t0, View::Audit).stability, Stability::SfOnly);
    let t40 = c.type_check(vec![], nested(40)).expect("checks");
    assert_eq!(c.classify(&t40, View::Audit).stability, Stability::Neither);
}

#[test]
#[should_panic(expected = "classify precondition")]
fn classify_panics_on_a_ref_bearing_term() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("define");
    let tt = c.type_check(vec![], Term::Ref { addr: p, args: vec![] }).expect("ref-bearing checks");
    let _ = c.classify(&tt, View::Active);
}
