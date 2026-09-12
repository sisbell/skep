//! M9 contract tests over a real kernel (InMemory): the validate-once-or-fail
//! catalog projection, Γ_D-checked typing with `Reg` expansion, the pure
//! evaluator's view/UV semantics, the PD0 classifier, the def lifecycle
//! (store/register/evaluate/supersede/certify/retract), and the rule engine
//! (validation, certification, fire/step/quiescence, scoping, the divergence
//! backstop, the armer warning). Every assertion states a claim the design or
//! interface makes — nothing more.

use crate::common;

use std::sync::Arc;

use common::*;
use skep_coordination::{
    Arg, Atom, CertifyError, Coordinator, DefineError, Dom, Env, EvalError, FireAction,
    FireError, FireOutcome, Lit, Occurrence, Prim, RegisterError, RetractError, Rule,
    RuleCertification, RuleError, ScopeBody, Sort, StepOutcome, Term, Trigger, TypeError,
    TypeKey, TypeRef, TypedTerm, Value, VarId, EXPANSION_NAME_BASE,
};
use skep_kernel::TxnError;
use skep_links::{
    coverage_class, enc, Behavior, Caller, EmitError, HasLinks, NullifyError, ShippedType, Tip,
    View, Visibility,
};
use skep_arrangement::HasM5;

// ───────────────────────── term-building helpers ─────────────────────────

fn v(x: u32) -> VarId {
    VarId::new(x).expect("test var below the watershed")
}

fn at(x: Term) -> skep_coordination::ArcTerm {
    Arc::new(x)
}

fn ad(x: Dom) -> skep_coordination::ArcDom {
    Arc::new(x)
}

fn key(e: &skep_links::Endset) -> TypeKey {
    TypeKey(e.clone())
}

fn conc(e: &skep_links::Endset) -> TypeRef {
    TypeRef::Concrete(key(e))
}

fn var(x: u32) -> Term {
    Term::Var(v(x))
}

fn tru() -> Term {
    Term::Lit(Lit::True)
}

fn lit_addr(a: &skep_address::Address) -> Term {
    Term::Lit(Lit::Addr(a.clone()))
}

fn lit_nat(x: u32) -> Term {
    Term::Lit(Lit::Nat(n(x)))
}

fn not(x: Term) -> Term {
    Term::Not(at(x))
}

fn and(x: Term, y: Term) -> Term {
    Term::And(at(x), at(y))
}

fn count(d: Dom) -> Term {
    Term::Count(ad(d))
}

fn nat_eq(x: Term, y: Term) -> Term {
    Term::Prim(Prim::NatEq(at(x), at(y)))
}

fn nat_le(x: Term, y: Term) -> Term {
    Term::Prim(Prim::NatLe(at(x), at(y)))
}

fn addr_eq(x: Term, y: Term) -> Term {
    Term::Prim(Prim::AddrEq(at(x), at(y)))
}

fn is_k_t(e: &skep_links::Endset, x: Term) -> Term {
    Term::Atom(Atom::IsK(conc(e), at(x)))
}

fn exists(vv: u32, d: Dom, b: Term) -> Term {
    Term::Exists { var: v(vv), dom: ad(d), body: at(b) }
}

/// type_check a closed Bool term and decide it at (view, fresh snapshot).
fn decide_now(k: &Arc<skep_kernel::Kernel<World>>, c: &Coordinator<World>, view: View, t: Term) -> bool {
    let tt = c.type_check(vec![], t).expect("test term type-checks");
    let s = k.snapshot();
    c.decide(&tt, &Env::empty(), view, &s)
}

fn always_addr(c: &Coordinator<World>) -> Trigger {
    Trigger::Inline(c.type_check_trigger((v(1), Sort::Addr), tru()).expect("always-true trigger"))
}

fn marker_action() -> FireAction {
    FireAction::Marker { home: doc1(), ty: key(&marker_ty()) }
}

// ───────────────────────────── construction ─────────────────────────────

/// Catalog projection: a pure, infallible read of the injected registry —
/// the cached `reserved_type` accessor serves the five shipped endsets at
/// the compiled ghost-tumbler constants (there is no twice-passed
/// configuration left to drift; the old validate-once-or-fail arms went
/// with the retired `GenesisConfig` seam).
#[test]
fn catalog_projects_and_serves_reserved_endsets() {
    let k = kernel();
    let c = coord(&k);
    assert_eq!(c.reserved_type(ShippedType::PredDef), &enc(&[ra(1)]));
    assert_eq!(c.reserved_type(ShippedType::PredStable), &enc(&[ra(2)]));
    assert_eq!(c.reserved_type(ShippedType::Retired), &enc(&[ra(3)]));
    assert_eq!(c.reserved_type(ShippedType::Supersedes), &enc(&[ra(4)]));
    assert_eq!(c.reserved_type(ShippedType::Retraction), &enc(&[ra(5)]));
}

/// The reserved expansion-name range is structurally uninhabitable by caller
/// names (`VarId::new` is the sole public constructor); `Env` binds
/// functionally, and is a collection of bindings — built from an iterator,
/// extended, a later binding of a name shadowing an earlier one as `bind`
/// does.
#[test]
fn varid_reservation_and_env_binding() {
    assert!(VarId::new(EXPANSION_NAME_BASE).is_none());
    assert!(VarId::new(EXPANSION_NAME_BASE - 1).is_some());
    let base = Env::empty();
    let bound = base.bind(v(1), Value::Bool(true));
    assert_eq!(bound.get(&v(1)), Some(&Value::Bool(true)));
    assert_eq!(bound.get(&v(2)), None);
    assert_eq!(base.get(&v(1)), None); // functional update

    let mut collected: Env =
        [(v(1), Value::Bool(false)), (v(2), Value::Nat(n(2))), (v(1), Value::Bool(true))]
            .into_iter()
            .collect();
    assert_eq!(collected.get(&v(1)), Some(&Value::Bool(true)));
    assert_eq!(collected.get(&v(2)), Some(&Value::Nat(n(2))));
    collected.extend([(v(2), Value::Nat(n(3)))]);
    assert_eq!(collected.get(&v(2)), Some(&Value::Nat(n(3))));
}

/// A `Coordinator` over the assembled world crosses threads: a driver that
/// shares one behind an `Arc` or moves it onto a worker depends on the
/// promise, and nothing in the handle's signature states it — the boxed
/// factories, the memo's lock and the catalog all have to keep it. And it
/// renders: a struct holding one derives `Debug`, and the rendering is the
/// working set — the registered rule ids and the rotation cursor.
#[test]
fn a_coordinator_is_send_sync_and_debug() {
    fn owed<T: Send + Sync + std::fmt::Debug>() {}
    owed::<Coordinator<World>>();
    let k = kernel();
    let mut c = coord(&k);
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: always_addr(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    let rendered = format!("{c:?}");
    assert!(rendered.starts_with("Coordinator {"), "{rendered}");
    assert!(rendered.contains(&format!("rules: [{id:?}]")), "{rendered}");
    assert!(rendered.contains("cursor: 0"), "{rendered}");
}

/// Every rejection displays, and chains to its cause through
/// `std::error::Error::source` — so a caller boxing one as
/// `Box<dyn Error + Send + Sync>` reads M9's condition and walks back to the
/// upstream refusal beneath it.
#[test]
fn rejections_display_and_chain_to_their_cause() {
    use std::error::Error;
    let k = kernel();
    let c = coord(&k);

    // A parse-level rejection, boxed in the crossing form.
    let g = insert_raw(&k, &doc2(), vec![0xff, 0x01, 0x02]);
    let err = c.register_pred(&doc1(), &g).expect_err("garbage bytes are not a def");
    let boxed: Box<dyn Error + Send + Sync> = Box::new(err);
    assert!(boxed.to_string().starts_with("register_pred:"));
    assert!(boxed.source().is_none(), "a leaf rejection has no cause");

    // A wrapped one chains: DefineError → RegisterError → TypeError.
    let ill = TypeError::UnboundVariable(v(9));
    let define = DefineError::Register(RegisterError::IllTyped(ill.clone()));
    assert_eq!(define.to_string(), format!("define_predicate: register_pred: the def is ill-typed: {ill}"));
    let cause = define.source().expect("Register carries its RegisterError");
    assert_eq!(cause.to_string(), format!("register_pred: the def is ill-typed: {ill}"));
    let root = cause.source().expect("IllTyped carries its TypeError");
    assert_eq!(root.to_string(), ill.to_string());
    assert!(root.source().is_none());
}

// ─────────────────────────────── typing ───────────────────────────────

/// Γ_D is part of the checking judgment: unbound vars, the def-path/
/// trigger-path Tup split, sort synthesis, and the catalog/behavior guards.
#[test]
fn type_check_gamma_and_catalog_guards() {
    let k = kernel();
    let c = coord(&k);

    // A free Var outside Γ_D.
    assert!(matches!(c.type_check(vec![], var(3)), Err(TypeError::UnboundVariable(_))));
    // The def path rejects a Tup parameter; the trigger path — its own
    // type, one parameter by signature — admits it, and requires Bool.
    assert!(matches!(
        c.type_check(vec![(v(1), Sort::Tup)], tru()),
        Err(TypeError::TupParameter(_))
    ));
    let one_tup = c
        .type_check_trigger((v(1), Sort::Tup), Term::Atom(Atom::InCoverageF(at(lit_addr(&ca(1))), v(1))))
        .expect("a one-Tup-parameter Bool trigger");
    assert_eq!(one_tup.param(), &(v(1), Sort::Tup));
    assert!(matches!(
        c.type_check_trigger((v(1), Sort::Addr), lit_nat(1)),
        Err(TypeError::SortMismatch { expected: Sort::Bool, found: Sort::Nat })
    ));
    // Sort synthesis.
    assert!(matches!(
        c.type_check(vec![], and(tru(), lit_nat(1))),
        Err(TypeError::SortMismatch { expected: Sort::Bool, found: Sort::Nat })
    ));
    // The catalog probe is Endset-equality: an uncataloged key misses.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Members(TypeRef::Concrete(TypeKey(uncataloged_ty(20)))))),
        Err(TypeError::UnregisteredType(_))
    ));
    // An atom needing a behavior the registration lacks.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::SourcesTo(conc(&pred_def_ty()), at(lit_addr(&ca(1)))))),
        Err(TypeError::BehaviorMissing { needs: Behavior::ReverseLookup, .. })
    ));
    // A ClassVar under no enclosing Reg binder.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Members(TypeRef::ClassVar(v(5))))),
        Err(TypeError::UnboundClassVar(_))
    ));
    // Ref to an address with no defined signature.
    assert!(matches!(
        c.type_check(vec![], Term::Ref { addr: ca(9), args: vec![] }),
        Err(TypeError::DanglingReference(_))
    ));

    // targets_keyed is in the vocabulary iff some cataloged class attaches
    // BH3 (V-atom): no shipped registration does, so THE catalog — every
    // board's catalog — rejects it.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::TargetsKeyed(at(lit_addr(&ca(1)))))),
        Err(TypeError::NoReverseLookupClass)
    ));
}

/// V-IDX: `count(Reg)` folds to the (constant) registered-class count;
/// Reg-quantifiers expand per class; an instance-wise ill-typed body rejects
/// whole.
#[test]
fn reg_expansion_folds_instantiates_and_rejects() {
    let k = kernel();
    let c = coord(&k);
    let ls = links(&k);

    // The whole population: the shipped five.
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::Reg), lit_nat(5))));

    // ∃K∈Reg :: is_K(x) — false while x heads no cataloged class, true once
    // a tuple lands in one (the other instances denote ⊥ harmlessly).
    let ex = c
        .type_check(
            vec![(v(1), Sort::Addr)],
            Term::Exists {
                var: v(7),
                dom: ad(Dom::Reg),
                body: at(Term::Atom(Atom::IsK(TypeRef::ClassVar(v(7)), at(var(1))))),
            },
        )
        .expect("Reg-quantified IsK body type-checks");
    let env = Env::empty().bind(v(1), Value::Addr(ca(5)));
    assert!(!c.decide(&ex, &env, View::Active, &k.snapshot()));
    ls.emit(Caller::System, &doc1(), &pred_def_ty(), &ca(5), &[]).expect("pred_def emit");
    assert!(c.decide(&ex, &env, View::Active, &k.snapshot()));

    // A class-indexed behavior atom at the bound class dies by instantiation
    // (some instance lacks the behavior) — RegInstanceIllTyped: only Retired
    // declares BH1, so the Forall's pred_def instance is the ill-typed one.
    assert!(matches!(
        c.type_check(
            vec![(v(1), Sort::Addr)],
            Term::Forall {
                var: v(7),
                dom: ad(Dom::Reg),
                body: at(Term::Atom(Atom::IsFiltered(TypeRef::ClassVar(v(7)), at(var(1))))),
            },
        ),
        Err(TypeError::RegInstanceIllTyped(_))
    ));
}

// ─────────────────────────────── evaluation ───────────────────────────────

/// The atom dispatch end-to-end: active/audit/default readings, the UV
/// `K_queried` self-exclusion (settled OQ1), `L_dom`, reflection, BH3, the
/// binder guard, and `is_doc`.
#[test]
fn eval_views_uv_rewrite_and_atoms() {
    let k = kernel();
    let c = coord(&k);
    let ls = links(&k);
    let retired = c.reserved_type(ShippedType::Retired).clone();

    let t1 = deposit_rel(&k, 2, &ca(1), &ca(2)); // pred_stable class, F=ca1, G=ca2
    deposit_rel(&k, 2, &ca(3), &ca(2));

    // is_K / member counting / L_dom / reflection membership.
    assert!(decide_now(&k, &c, View::Active, is_k_t(&pred_stable_ty(), lit_addr(&ca(1)))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(conc(&pred_stable_ty()))), lit_nat(2))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::LinkDom), lit_nat(2))));
    assert!(decide_now(
        &k,
        &c,
        View::Active,
        Term::Prim(Prim::SetMem(at(lit_addr(&la(1))), at(Term::Reflect(ad(Dom::LinkDom)))))
    ));

    // Retraction: the active reading shrinks, the audit reading persists —
    // the term view selects (PR-VIEW: the view is an eval parameter).
    ls.nullify(Caller::System, &doc1(), &t1).expect("retract rel 1");
    assert!(!decide_now(&k, &c, View::Active, is_k_t(&pred_stable_ty(), lit_addr(&ca(1)))));
    assert!(decide_now(&k, &c, View::Audit, is_k_t(&pred_stable_ty(), lit_addr(&ca(1)))));
    // The audit tuple slice still carries t1 (∃ t ∈ L_rel :: ca1 ∈ cov_F(t)).
    assert!(decide_now(
        &k,
        &c,
        View::Active,
        exists(1, Dom::AuditSlice(conc(&pred_stable_ty())), Term::Atom(Atom::InCoverageF(at(lit_addr(&ca(1))), v(1))))
    ));

    // UV default view: members(K, default) drops elements filtered by BH1
    // types OTHER than K — and never by K itself (retired is unfiltered in
    // its own default reading — the OQ1 commitment).
    ls.emit(Caller::System, &doc1(), &retired, &ca(3), &[]).expect("retire ca3");
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(conc(&pred_stable_ty()))), lit_nat(1))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(conc(&pred_stable_ty()))), lit_nat(0))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(conc(&retired))), lit_nat(1))));

    // V-DOC: residence is M3 registration.
    assert!(decide_now(&k, &c, View::Active, Term::Atom(Atom::IsDoc(at(lit_addr(&doc1()))))));
    assert!(!decide_now(&k, &c, View::Active, Term::Atom(Atom::IsDoc(at(lit_addr(&ca(1)))))));

    // The binder guard: IfSome narrows an optional through its `var`, and
    // the else-branch answers when the optional is ⊥. (The BH3 atoms —
    // TargetOf/TargetsKeyed — are out of the vocabulary in this format: no
    // cataloged class declares ReverseLookup, which the typing test pins.)
    assert!(decide_now(
        &k,
        &c,
        View::Active,
        Term::IfSome {
            opt: at(Term::Lit(Lit::BotAddr)),
            var: v(2),
            then_: at(Term::Lit(Lit::False)),
            else_: at(Term::Lit(Lit::True)),
        }
    ));
}

#[test]
#[should_panic(expected = "decide precondition")]
fn decide_panics_on_non_bool_codomain() {
    let k = kernel();
    let c = coord(&k);
    let t = c.type_check(vec![], lit_nat(1)).expect("Nat-codomain term");
    let s = k.snapshot();
    let _ = c.decide(&t, &Env::empty(), View::Active, &s);
}

/// `eval`'s door: an `Env` that leaves a Γ_D parameter unbound (or binds it
/// at the wrong sort) is a precondition violation named at the door, not a
/// failure somewhere inside the walk.
#[test]
#[should_panic(expected = "eval precondition")]
fn eval_panics_on_unbound_parameter() {
    let k = kernel();
    let c = coord(&k);
    let t = c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("one-param term");
    let s = k.snapshot();
    let _ = c.eval(&t, &Env::empty().bind(v(1), Value::Nat(n(1))), View::Active, &s);
}

#[test]
#[should_panic(expected = "eval precondition")]
fn eval_panics_on_ref_bearing_term() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("define");
    let t = c.type_check(vec![], Term::Ref { addr: p, args: vec![] }).expect("ref-bearing checks");
    assert!(!t.is_ref_free());
    let s = k.snapshot();
    let _ = c.eval(&t, &Env::empty(), View::Active, &s);
}

// ─────────────────────────────── dynamics ───────────────────────────────

/// PD0 by spelling: the 4-point lattice, the count-threshold split, the
/// per-view audit-is_K rule, the PR-VIEW scan, and the named active-view
/// exception.
#[test]
fn classify_stability_lattice_and_view_scan() {
    use skep_coordination::Stability;
    let k = kernel();
    let c = coord(&k);
    let tc = |t: Term| c.type_check(vec![], t).expect("test term type-checks");
    let tc1 = |t: Term| c.type_check(vec![(v(1), Sort::Addr)], t).expect("test term type-checks");

    // ∃ over the grow-only L_K is ST; its negation SF.
    let ex = tc(exists(2, Dom::AuditSlice(conc(&pred_def_ty())), tru()));
    assert_eq!(c.classify(&ex, View::Audit).stability, Stability::StOnly);
    let nex = tc(not(exists(2, Dom::AuditSlice(conc(&pred_def_ty())), tru())));
    assert_eq!(c.classify(&nex, View::Audit).stability, Stability::SfOnly);

    // Lower-bound counts ST, upper-bound SF, equality Neither (the
    // authoring-precision recommendation's substance).
    let lo = tc(nat_le(lit_nat(2), count(Dom::AuditSlice(conc(&pred_def_ty())))));
    assert_eq!(c.classify(&lo, View::Audit).stability, Stability::StOnly);
    let hi = tc(nat_le(count(Dom::AuditSlice(conc(&pred_def_ty()))), lit_nat(2)));
    assert_eq!(c.classify(&hi, View::Audit).stability, Stability::SfOnly);
    let eq = tc(nat_eq(count(Dom::AuditSlice(conc(&pred_def_ty()))), lit_nat(2)));
    assert_eq!(c.classify(&eq, View::Audit).stability, Stability::Neither);

    // Audit is_K at a step-constant argument is ST; the SAME term classified
    // at Active is Neither (PC3: classification is relative to the view).
    let isk = tc1(is_k_t(&marker_ty(), var(1)));
    assert_eq!(c.classify(&isk, View::Audit).stability, Stability::StOnly);
    assert_eq!(c.classify(&isk, View::Active).stability, Stability::Neither);

    // PR-VIEW: is_K is view-parameterized; an L_K-only spelling is not.
    assert!(!c.classify(&isk, View::Audit).view_independent);
    assert!(c.classify(&ex, View::Audit).view_independent);

    // The named exception: an active-slice read can shrink under retraction.
    let act = tc(exists(2, Dom::ActiveSlice(conc(&pred_def_ty())), tru()));
    assert!(c.classify(&act, View::Active).active_exceptions.retraction_shrinks);
    assert!(!c.classify(&ex, View::Audit).active_exceptions.retraction_shrinks);

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
    let isdoc = tc1(Term::Atom(Atom::IsDoc(at(var(1)))));
    assert!(c.classify(&isdoc, View::Audit).footprint.reads_residence());
}

// ───────────────────────── definitions lifecycle ─────────────────────────

/// define → registered/evaluable; ≤1 active pdef per start (idem⊤ dedup);
/// retraction is reversible, non-cascading, and evaluation keys on
/// EVER-registration.
#[test]
fn def_lifecycle_register_evaluate_retract() {
    let k = kernel();
    let c = coord(&k);

    let (start, _seq) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("define");
    assert_eq!(start, ca(1)); // first content mint under doc1

    let s = k.snapshot();
    assert!(c.is_ever_pred(&start, &s));
    assert!(c.is_active_pred(&start, &s));
    let sig = c.signature(&start).expect("registered def has a signature");
    assert_eq!(sig.params, vec![]);
    assert_eq!(sig.result, Sort::Bool);
    assert_eq!(c.evaluate_def(&start, &[], View::Active, &s), Ok(Value::Bool(true)));

    // ≤1 active pdef per start: a re-register dedups to the incumbent tuple.
    let (p1, _) = c.register_pred(&doc1(), &start).expect("re-register (dedup)");
    let (p2, _) = c.register_pred(&doc1(), &start).expect("re-register (dedup)");
    assert_eq!(p1, p2);

    // A parameterized def: positional Γ_D binding with arity/sort guards.
    let tt1 = c
        .type_check(vec![(v(1), Sort::Addr)], addr_eq(var(1), lit_addr(&ca(1))))
        .expect("param def");
    let (pd, _) = c.define_predicate(&doc1(), &tt1).expect("define param def");
    let s2 = k.snapshot();
    assert_eq!(c.evaluate_def(&pd, &[Value::Addr(ca(1))], View::Active, &s2), Ok(Value::Bool(true)));
    assert_eq!(c.evaluate_def(&pd, &[Value::Addr(ca(2))], View::Active, &s2), Ok(Value::Bool(false)));
    assert_eq!(c.evaluate_def(&pd, &[], View::Active, &s2), Err(EvalError::ArgArityMismatch));
    assert_eq!(
        c.evaluate_def(&pd, &[Value::Nat(n(1))], View::Active, &s2),
        Err(EvalError::ArgSortMismatch)
    );
    assert_eq!(
        c.evaluate_def(&ca(99), &[], View::Active, &s2),
        Err(EvalError::NotEverRegistered)
    );

    // Retraction: content untouched, audit retained, evaluation still served
    // (ever-keyed), no panic on a second retract, re-registration deposits
    // afresh (the idem class emptied).
    c.retract_pred(&doc1(), &start).expect("retract");
    let s3 = k.snapshot();
    assert!(!c.is_active_pred(&start, &s3));
    assert!(c.is_ever_pred(&start, &s3));
    assert_eq!(c.evaluate_def(&start, &[], View::Active, &s3), Ok(Value::Bool(true)));
    assert!(matches!(c.retract_pred(&doc1(), &start), Err(RetractError::NotActive)));
    let (p3, _) = c.register_pred(&doc1(), &start).expect("resurrect");
    assert_ne!(p3, p1);
}

/// WT-ref + endorsement: refs to registered defs check and evaluate
/// DAG-recursively; a gap-de-registered referent blocks NEW registrations
/// (endorsement) while existing consumers keep evaluating (no cascade).
#[test]
fn def_references_endorsement_and_no_cascade() {
    let k = kernel();
    let c = coord(&k);

    let p = c
        .type_check(vec![(v(1), Sort::Addr)], addr_eq(var(1), lit_addr(&ca(1))))
        .expect("P");
    let (p_start, _) = c.define_predicate(&doc1(), &p).expect("define P");

    let q = c
        .type_check(vec![], Term::Ref { addr: p_start.clone(), args: vec![at(lit_addr(&ca(1)))] })
        .expect("Q references P");
    assert!(!q.is_ref_free());
    let (q_start, _) = c.define_predicate(&doc1(), &q).expect("define Q");
    let s = k.snapshot();
    assert_eq!(c.evaluate_def(&q_start, &[], View::Active, &s), Ok(Value::Bool(true)));
    assert_eq!(c.signature(&q_start).expect("Q has a signature").result, Sort::Bool);

    // Endorsement gates NEW registration…
    c.retract_pred(&doc1(), &p_start).expect("retract P");
    let r = c
        .type_check(vec![], Term::Ref { addr: p_start.clone(), args: vec![at(lit_addr(&ca(2)))] })
        .expect("type_check keys on ever-registration, so a retracted referent still checks");
    match c.define_predicate(&doc1(), &r) {
        Err(DefineError::Register(RegisterError::ReferentNotActive(x))) => assert_eq!(x, p_start),
        other => panic!("expected ReferentNotActive, got {other:?}"),
    }
    // …while the standing consumer keeps evaluating (dangling-but-live).
    let s2 = k.snapshot();
    assert_eq!(c.evaluate_def(&q_start, &[], View::Active, &s2), Ok(Value::Bool(true)));
}

/// register_pred's parse-level gates. (A tuple-binding def is not a
/// rejection here but a type error: `define_predicate` takes a `TypedTerm`,
/// and `type_check_trigger` — the one way to bind a `Tup` — yields a
/// `TriggerTerm`, so no such def can be spelled.)
#[test]
fn define_and_register_rejections() {
    let k = kernel();
    let c = coord(&k);

    // An undisciplined deposit (garbage bytes) is a clean ParseFailed.
    let g = insert_raw(&k, &doc2(), vec![0xff, 0x01, 0x02]);
    assert!(matches!(c.register_pred(&doc1(), &g), Err(RegisterError::ParseFailed)));

    // No content at the start.
    assert!(matches!(c.register_pred(&doc1(), &ca(99)), Err(RegisterError::NotResident)));

    // P0: the home must be a registered document.
    let (start, _) = c
        .define_predicate(&doc2(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("define at doc2");
    let unregistered_doc = a(&[1, 0, 1, 0, 7]);
    assert!(matches!(
        c.register_pred(&unregistered_doc, &start),
        Err(RegisterError::HomeNotRegistered)
    ));
}

/// supersede's up-front gates, `current_version` over the shipped class, and
/// the M7 supersession-fence drift tripwire (see the report: as-built M7
/// rejects a raw `[K_sup]`-typed `emit`, so the design's def-lineage claim
/// cannot commit — the first two of the three non-atomic transactions do).
#[test]
fn supersede_gates_lineage_and_fence_drift() {
    let k = kernel();
    let c = coord(&k);

    assert!(matches!(
        c.supersede(&doc1(), &ca(50), &c.type_check(vec![], tru()).expect("term")),
        Err(DefineError::OldStartNotEverRegistered(_))
    ));

    let (p_start, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("define P");
    let s = k.snapshot();
    assert!(matches!(c.current_version(&p_start, &s), Tip::Sink(x) if x == p_start));

    // DRIFT TRIPWIRE (report: "supersede vs M7's SupersessionClass fence"):
    // the emit route the M9 design resolves to (Conflicts §4) is fenced by
    // the as-built M7, so the third transaction rejects — while the
    // successor's insert + pdef registration (transactions 1–2) stay
    // committed, exactly the documented non-atomicity. When M7 lifts the
    // fence for content-endpoint def lineage, this match arm flips.
    let before = k.snapshot().world().m5().content_count(&doc1());
    match c.supersede(&doc1(), &p_start, &c.type_check(vec![], Term::Lit(Lit::False)).expect("term")) {
        Err(DefineError::Supersede(TxnError::Rejected(EmitError::SupersessionClass))) => {}
        other => panic!("fence drift resolved? got {other:?}"),
    }
    assert_eq!(
        k.snapshot().world().m5().content_count(&doc1()),
        before + n(1) // the successor def's content committed
    );
}

/// CVALID(0..iii) in order, the ST⁺ parameter widening, and the certificate's
/// M7 deposit.
#[test]
fn certify_stable_cvalid_legs() {
    let k = kernel();
    let c = coord(&k);
    let define = |t: Term| {
        let tt = c.type_check(vec![], t).expect("def term");
        c.define_predicate(&doc1(), &tt).expect("define")
    };

    assert!(matches!(c.certify_stable(&doc1(), &ca(40)), Err(CertifyError::NotEverRegistered)));

    // A ⊤-stable, view-independent Boolean def certifies and deposits.
    let (s0, _) = define(exists(1, Dom::AuditSlice(conc(&pred_def_ty())), tru()));
    c.certify_stable(&doc1(), &s0).expect("certify");
    assert!(c.is_certified_stable(&s0, &k.snapshot()));

    // (i) Boolean sort.
    let (sa, _) = define(Term::Lit(Lit::BotAddr));
    assert!(matches!(c.certify_stable(&doc1(), &sa), Err(CertifyError::NotBoolean)));

    // (ii) view-independent expansion (M_K is view-parameterized).
    let (sv, _) = define(exists(1, Dom::MembersDom(conc(&pred_def_ty())), tru()));
    assert!(matches!(c.certify_stable(&doc1(), &sv), Err(CertifyError::ViewDependent)));

    // (iii) ST⁺: an SF-only spelling is not ⊤-stable.
    let (sn, _) = define(not(exists(1, Dom::AuditSlice(conc(&pred_def_ty())), tru())));
    assert!(matches!(c.certify_stable(&doc1(), &sn), Err(CertifyError::NotStable)));

    // The ST⁺ widening: `count(L_K) ≥ x` with x a bound ℕ parameter
    // certifies (a literal-only PD0 would refuse) — while plain classify
    // stays Neither (the widening is certification-only).
    let widened = nat_le(var(1), count(Dom::AuditSlice(conc(&pred_def_ty()))));
    let tw = c.type_check(vec![(v(1), Sort::Nat)], widened).expect("widened def");
    assert_eq!(
        c.classify(&tw, View::Audit).stability,
        skep_coordination::Stability::Neither
    );
    let (sw, _) = c.define_predicate(&doc1(), &tw).expect("define widened");
    c.certify_stable(&doc1(), &sw).expect("ST⁺ certifies the bound-ℕ-parameter threshold");

    // ST⁺ is not compositional over references: (ii) and (iii) are decided
    // over the FLAT expansion, so a def that is nothing but a reference
    // answers as its referent does — stable through s0, view-dependent
    // through sv, unstable through sn — with the referent's parameter bound
    // by the expansion (the widened sw, applied to a literal, certifies).
    let define_ref = |target: &skep_address::Address, args: Vec<Term>| {
        let args = args.into_iter().map(at).collect();
        let tt = c.type_check(vec![], Term::Ref { addr: target.clone(), args }).expect("ref term");
        c.define_predicate(&doc1(), &tt).expect("define ref")
    };
    let (r0, _) = define_ref(&s0, vec![]);
    c.certify_stable(&doc1(), &r0).expect("a reference to a stable def is stable");
    let (rv, _) = define_ref(&sv, vec![]);
    assert!(matches!(c.certify_stable(&doc1(), &rv), Err(CertifyError::ViewDependent)));
    let (rn, _) = define_ref(&sn, vec![]);
    assert!(matches!(c.certify_stable(&doc1(), &rn), Err(CertifyError::NotStable)));
    let (rw, _) = define_ref(&sw, vec![lit_nat(3)]);
    c.certify_stable(&doc1(), &rw).expect("the expansion binds the referent's threshold parameter");

    // (0)/(ii) ordering: a retracted def is NotActive.
    c.retract_pred(&doc1(), &s0).expect("retract");
    assert!(matches!(c.certify_stable(&doc1(), &s0), Err(CertifyError::NotActive)));
}

// ─────────────────────────────── the rule engine ───────────────────────────────

/// Every `register_rule` validation gate, as a typed rejection — never a
/// deferred fire-time panic.
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
    // pair is refused by name (PR-DISC). The `NonIdemMarkerType` arm is
    // structurally unreachable in this format — every cataloged Unary class
    // is idem⊤ — and stays declared for the day a registered idem⊥ Unary
    // class exists again.
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
    let pdef_key = TypeKey(c.reserved_type(ShippedType::PredDef).clone());
    assert!(matches!(
        c.register_rule(mk(
            Dom::MembersDom(conc(&pred_stable_ty())),
            always_addr(&c),
            FireAction::Marker { home: doc1(), ty: pdef_key }
        )),
        Err(RuleError::PredLayerMarkerType(_))
    ));
}

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

/// The guest-class filter (lane 3.3 §5): a fire whose Marker HOME, or whose
/// bound argument's DOCUMENT, the injected guest predicate answers `false`
/// for is refused BEFORE any deposit — a `Failed` step carrying
/// `DraftBoundary(doc)`, never a silent skip and never a link. Under an
/// all-readable predicate the same rule fires.
#[test]
fn a_fire_stops_at_the_draft_boundary_before_any_deposit() {
    // doc2 is the "draft": unreadable at guest class under this predicate.
    let refuse_doc2 = || -> Box<Visibility<'static, World>> {
        Box::new(|_: &World, d: &skep_address::Address| *d != doc2())
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

    // (3) Both readable: the same rule shape fires, and the deposit is real.
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
        Box::new(|_: &World, d: &skep_address::Address| *d != doc2())
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
    let in_audit = |a: &skep_address::Address| {
        decide_now(
            &k,
            &c,
            View::Audit,
            exists(
                1,
                Dom::AuditSlice(conc(&pred_stable_ty())),
                addr_eq(Term::Atom(Atom::TupAddr(v(1))), lit_addr(a)),
            ),
        )
    };
    assert!(in_audit(&t1), "retracted, but homed in the readable doc1: in the audit slice");
    assert!(decide_now(&k, &c, View::Audit, nat_eq(count(Dom::AuditSlice(conc(&pred_stable_ty()))), lit_nat(1))));
    assert!(!decide_now(&k, &c, View::Active, is_k_t(&pred_stable_ty(), lit_addr(&ca(2)))));
}

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
