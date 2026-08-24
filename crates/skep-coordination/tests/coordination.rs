//! M9 contract tests over a real kernel (InMemory): the validate-once-or-fail
//! catalog projection, Γ_D-checked typing with `Reg` expansion, the pure
//! evaluator's view/UV semantics, the PD0 classifier, the def lifecycle
//! (store/register/evaluate/supersede/certify/retract), and the rule engine
//! (validation, certification, fire/step/quiescence, scoping, the divergence
//! backstop, the armer warning). Every assertion states a claim the design or
//! interface makes — nothing more.

mod common;

use std::sync::Arc;

use common::*;
use skep_coordination::{
    Atom, CatalogError, CertifyError, Coordinator, DefineError, Dom, Enabled, Env, EvalError,
    FireAction, FireError, FireOutcome, Lit, Prim, RegisterError, RetractError, Rule,
    RuleCertification, RuleError, ScopeBody, Sort, StepOutcome, Term, TriggerRef, TypeError,
    TypeKey, TypeRef, TypedTerm, Value, VarId, EXPANSION_NAME_BASE,
};
use skep_kernel::TxnError;
use skep_links::{
    enc, Behavior, Caller, EmitError, HasLinks, NullifyError, Registration, Shape, ShippedType,
    Tip, TypeDecl, TypeRegistry, View,
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

fn always_addr(c: &Coordinator<World>) -> TriggerRef {
    TriggerRef::Inline(
        c.type_check_trigger(vec![(v(1), Sort::Addr)], tru()).expect("always-true trigger"),
    )
}

fn marker_action() -> FireAction {
    FireAction::Marker { home: doc1(), ty: key(&marker_ty()) }
}

// ───────────────────────────── construction ─────────────────────────────

/// Catalog projection: validate-once-or-fail against the injected registry;
/// the cached `reserved_type` accessor serves the shipped endsets (coverage-
/// equal — byte-identical in fact — to genesis's).
#[test]
fn catalog_projects_validates_and_serves_reserved_endsets() {
    let k = kernel();
    let c = coord(&k);
    assert_eq!(c.reserved_type(ShippedType::PredDef), &enc(&[ra(1)]));
    assert_eq!(c.reserved_type(ShippedType::PredStable), &enc(&[ra(2)]));
    assert_eq!(c.reserved_type(ShippedType::Retired), &enc(&[ra(3)]));
    assert_eq!(c.reserved_type(ShippedType::Supersedes), &enc(&[ra(4)]));
    assert_eq!(c.reserved_type(ShippedType::Retraction), &enc(&[ra(5)]));

    // Residual drift of the twice-passed pair is caught at assembly.
    let mut drifted = reserved();
    drifted.pred_def = ra(7);
    assert!(matches!(
        try_coord(&k, registry(), drifted, decls()),
        Err(CatalogError::ReservedMismatch(ShippedType::PredDef))
    ));

    let mut extra = decls();
    extra.push(TypeDecl {
        key: enc(&[ra(20)]),
        reg: Registration { shape: Shape::Unary, idem: true, behaviors: im::OrdSet::new() },
    });
    assert!(matches!(
        try_coord(&k, registry(), reserved(), extra),
        Err(CatalogError::DeclNotInRegistry(TypeKey(e))) if e == enc(&[ra(20)])
    ));
}

/// The reserved expansion-name range is structurally uninhabitable by caller
/// names (`VarId::new` is the sole public constructor); `Env` binds
/// functionally.
#[test]
fn varid_reservation_and_env_binding() {
    assert!(VarId::new(EXPANSION_NAME_BASE).is_none());
    assert!(VarId::new(EXPANSION_NAME_BASE - 1).is_some());
    let base = Env::empty();
    let bound = base.bind(v(1), Value::Bool(true));
    assert_eq!(bound.get(&v(1)), Some(&Value::Bool(true)));
    assert_eq!(bound.get(&v(2)), None);
    assert_eq!(base.get(&v(1)), None); // functional update
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
    // Def path rejects a Tup parameter; the trigger path admits exactly one.
    assert!(matches!(
        c.type_check(vec![(v(1), Sort::Tup)], tru()),
        Err(TypeError::TupParameter(_))
    ));
    let one_tup = c.type_check_trigger(
        vec![(v(1), Sort::Tup)],
        Term::Atom(Atom::InCoverageF(at(lit_addr(&ca(1))), v(1))),
    );
    assert!(one_tup.is_ok());
    assert!(matches!(
        c.type_check_trigger(vec![(v(1), Sort::Tup), (v(2), Sort::Tup)], tru()),
        Err(TypeError::TupParameter(x)) if x == v(2)
    ));
    // Sort synthesis.
    assert!(matches!(
        c.type_check(vec![], and(tru(), lit_nat(1))),
        Err(TypeError::SortMismatch { expected: Sort::Bool, found: Sort::Nat })
    ));
    // The catalog probe is Endset-equality: an uncataloged key misses.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Members(TypeRef::Concrete(TypeKey(enc(&[ra(20)])))))),
        Err(TypeError::UnregisteredType(_))
    ));
    // An atom needing a behavior the registration lacks.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::SourcesTo(conc(&rel_ty()), at(lit_addr(&ca(1)))))),
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
    // BH3 (V-atom): a no-BH3 catalog rejects it.
    let no_bh3: Vec<TypeDecl> = decls().into_iter().filter(|d| d.key != bh3_ty()).collect();
    let reg2 = Arc::new(TypeRegistry::build(&config_with(no_bh3.clone())).expect("valid config"));
    let c2 = try_coord(&k, reg2, reserved(), no_bh3).expect("projects");
    assert!(matches!(
        c2.type_check(vec![], Term::Atom(Atom::TargetsKeyed(at(lit_addr(&ca(1)))))),
        Err(TypeError::NoReverseLookupClass)
    ));
}

/// V-IDX: `count(Reg)` folds to the (constant) registered-class count;
/// Reg-quantifiers expand per class with the class-unindexed `targets_keyed`
/// join as the survivor body; an instance-wise ill-typed body rejects whole.
#[test]
fn reg_expansion_folds_instantiates_and_rejects() {
    let k = kernel();
    let c = coord(&k);
    let ls = links(&k);

    // 5 shipped + 5 app decls.
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::Reg), lit_nat(10))));

    // ∃K∈Reg :: def(targets_keyed(x)[K]) — false with no BH3 tuple, true
    // once one exists (the mandatory non-BH3 instances denote ⊥ harmlessly).
    let ex = c
        .type_check(
            vec![(v(1), Sort::Addr)],
            Term::Exists {
                var: v(7),
                dom: ad(Dom::Reg),
                body: at(Term::Prim(Prim::Def(at(Term::Prim(Prim::MapGet(
                    at(Term::Atom(Atom::TargetsKeyed(at(var(1))))),
                    TypeRef::ClassVar(v(7)),
                )))))),
            },
        )
        .expect("Reg-quantified MapGet body type-checks");
    let env = Env::empty().bind(v(1), Value::Addr(ca(5)));
    assert!(!c.decide(&ex, &env, View::Active, &k.snapshot()));
    ls.emit(Caller::System, &doc1(), &bh3_ty(), &ca(5), &[ca(6)]).expect("bh3 emit");
    assert!(c.decide(&ex, &env, View::Active, &k.snapshot()));

    // A class-indexed behavior atom at the bound class dies by instantiation
    // (some instance lacks the behavior) — RegInstanceIllTyped.
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

    let (t1, _) = ls.emit(Caller::System, &doc1(), &rel_ty(), &ca(1), &[ca(2)]).expect("rel 1");
    ls.emit(Caller::System, &doc1(), &rel_ty(), &ca(3), &[ca(2)]).expect("rel 2");

    // is_K / member counting / L_dom / reflection membership.
    assert!(decide_now(&k, &c, View::Active, is_k_t(&rel_ty(), lit_addr(&ca(1)))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(conc(&rel_ty()))), lit_nat(2))));
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
    assert!(!decide_now(&k, &c, View::Active, is_k_t(&rel_ty(), lit_addr(&ca(1)))));
    assert!(decide_now(&k, &c, View::Audit, is_k_t(&rel_ty(), lit_addr(&ca(1)))));
    // The audit tuple slice still carries t1 (∃ t ∈ L_rel :: ca1 ∈ cov_F(t)).
    assert!(decide_now(
        &k,
        &c,
        View::Active,
        exists(1, Dom::AuditSlice(conc(&rel_ty())), Term::Atom(Atom::InCoverageF(at(lit_addr(&ca(1))), v(1))))
    ));

    // UV default view: members(K, default) drops elements filtered by BH1
    // types OTHER than K — and never by K itself (retired is unfiltered in
    // its own default reading — the OQ1 commitment).
    ls.emit(Caller::System, &doc1(), &retired, &ca(3), &[]).expect("retire ca3");
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(conc(&rel_ty()))), lit_nat(1))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(conc(&rel_ty()))), lit_nat(0))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(conc(&retired))), lit_nat(1))));

    // V-DOC: residence is M3 registration.
    assert!(decide_now(&k, &c, View::Active, Term::Atom(Atom::IsDoc(at(lit_addr(&doc1()))))));
    assert!(!decide_now(&k, &c, View::Active, Term::Atom(Atom::IsDoc(at(lit_addr(&ca(1)))))));

    // BH3 + the binder guard: target_of narrows through IfSome; the
    // targets_keyed join keys by class, absent keys denote ⊥.
    ls.emit(Caller::System, &doc1(), &bh3_ty(), &ca(5), &[ca(6)]).expect("bh3 emit");
    assert!(decide_now(
        &k,
        &c,
        View::Active,
        Term::IfSome {
            opt: at(Term::Atom(Atom::TargetOf(conc(&bh3_ty()), at(lit_addr(&ca(5)))))),
            var: v(2),
            then_: at(addr_eq(var(2), lit_addr(&ca(6)))),
            else_: at(Term::Lit(Lit::False)),
        }
    ));
    assert!(decide_now(
        &k,
        &c,
        View::Active,
        Term::Prim(Prim::Def(at(Term::Prim(Prim::MapGet(
            at(Term::Atom(Atom::TargetsKeyed(at(lit_addr(&ca(5)))))),
            conc(&bh3_ty()),
        )))))
    ));
    assert!(!decide_now(
        &k,
        &c,
        View::Active,
        Term::Prim(Prim::Def(at(Term::Prim(Prim::MapGet(
            at(Term::Atom(Atom::TargetsKeyed(at(lit_addr(&ca(5)))))),
            conc(&rel_ty()),
        )))))
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

#[test]
#[should_panic(expected = "eval precondition")]
fn eval_panics_on_ref_bearing_term() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(&doc1(), c.type_check(vec![], tru()).expect("closed True"))
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
    let ex = tc(exists(2, Dom::AuditSlice(conc(&rel_ty())), tru()));
    assert_eq!(c.classify(&ex, View::Audit).stability, Stability::StOnly);
    let nex = tc(not(exists(2, Dom::AuditSlice(conc(&rel_ty())), tru())));
    assert_eq!(c.classify(&nex, View::Audit).stability, Stability::SfOnly);

    // Lower-bound counts ST, upper-bound SF, equality Neither (the
    // authoring-precision recommendation's substance).
    let lo = tc(nat_le(lit_nat(2), count(Dom::AuditSlice(conc(&rel_ty())))));
    assert_eq!(c.classify(&lo, View::Audit).stability, Stability::StOnly);
    let hi = tc(nat_le(count(Dom::AuditSlice(conc(&rel_ty()))), lit_nat(2)));
    assert_eq!(c.classify(&hi, View::Audit).stability, Stability::SfOnly);
    let eq = tc(nat_eq(count(Dom::AuditSlice(conc(&rel_ty()))), lit_nat(2)));
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
    let act = tc(exists(2, Dom::ActiveSlice(conc(&rel_ty())), tru()));
    assert!(c.classify(&act, View::Active).active_exceptions.retraction_shrinks);
    assert!(!c.classify(&ex, View::Audit).active_exceptions.retraction_shrinks);
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
        .define_predicate(&doc1(), c.type_check(vec![], tru()).expect("closed True"))
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
    let (pd, _) = c.define_predicate(&doc1(), tt1).expect("define param def");
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
    let (p_start, _) = c.define_predicate(&doc1(), p).expect("define P");

    let q = c
        .type_check(vec![], Term::Ref { addr: p_start.clone(), args: vec![at(lit_addr(&ca(1)))] })
        .expect("Q references P");
    assert!(!q.is_ref_free());
    let (q_start, _) = c.define_predicate(&doc1(), q).expect("define Q");
    let s = k.snapshot();
    assert_eq!(c.evaluate_def(&q_start, &[], View::Active, &s), Ok(Value::Bool(true)));
    assert_eq!(c.signature(&q_start).expect("Q has a signature").result, Sort::Bool);

    // Endorsement gates NEW registration…
    c.retract_pred(&doc1(), &p_start).expect("retract P");
    let r = c
        .type_check(vec![], Term::Ref { addr: p_start.clone(), args: vec![at(lit_addr(&ca(2)))] })
        .expect("type_check keys on ever-registration, so a retracted referent still checks");
    match c.define_predicate(&doc1(), r) {
        Err(DefineError::Register(RegisterError::ReferentNotActive(x))) => assert_eq!(x, p_start),
        other => panic!("expected ReferentNotActive, got {other:?}"),
    }
    // …while the standing consumer keeps evaluating (dangling-but-live).
    let s2 = k.snapshot();
    assert_eq!(c.evaluate_def(&q_start, &[], View::Active, &s2), Ok(Value::Bool(true)));
}

/// The up-front Tup rejection (no orphan content), and register_pred's
/// parse-level gates.
#[test]
fn define_and_register_rejections() {
    let k = kernel();
    let c = coord(&k);

    let tup_term = c.type_check_trigger(vec![(v(1), Sort::Tup)], tru()).expect("trigger term");
    let n0 = k.snapshot().world().m5().content_count(&doc1());
    assert!(matches!(c.define_predicate(&doc1(), tup_term), Err(DefineError::TupParameter(_))));
    assert_eq!(k.snapshot().world().m5().content_count(&doc1()), n0); // before any insert

    // An undisciplined deposit (garbage bytes) is a clean ParseFailed.
    let g = insert_raw(&k, &doc2(), vec![0xff, 0x01, 0x02]);
    assert!(matches!(c.register_pred(&doc1(), &g), Err(RegisterError::ParseFailed)));

    // No content at the start.
    assert!(matches!(c.register_pred(&doc1(), &ca(99)), Err(RegisterError::NotResident)));

    // P0: the home must be a registered document.
    let (start, _) = c
        .define_predicate(&doc2(), c.type_check(vec![], tru()).expect("closed True"))
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
        c.supersede(&doc1(), &ca(50), c.type_check(vec![], tru()).expect("term")),
        Err(DefineError::OldStartNotEverRegistered(_))
    ));
    let tup_term = c.type_check_trigger(vec![(v(1), Sort::Tup)], tru()).expect("trigger term");
    assert!(matches!(c.supersede(&doc1(), &ca(50), tup_term), Err(DefineError::TupParameter(_))));

    let (p_start, _) = c
        .define_predicate(&doc1(), c.type_check(vec![], tru()).expect("closed True"))
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
    match c.supersede(&doc1(), &p_start, c.type_check(vec![], Term::Lit(Lit::False)).expect("term")) {
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
        c.define_predicate(&doc1(), tt).expect("define")
    };

    assert!(matches!(c.certify_stable(&doc1(), &ca(40)), Err(CertifyError::NotEverRegistered)));

    // A ⊤-stable, view-independent Boolean def certifies and deposits.
    let (s0, _) = define(exists(1, Dom::AuditSlice(conc(&rel_ty())), tru()));
    c.certify_stable(&doc1(), &s0).expect("certify");
    assert!(c.is_certified_stable(&s0, &k.snapshot()));

    // (i) Boolean sort.
    let (sa, _) = define(Term::Lit(Lit::BotAddr));
    assert!(matches!(c.certify_stable(&doc1(), &sa), Err(CertifyError::NotBoolean)));

    // (ii) view-independent expansion (M_K is view-parameterized).
    let (sv, _) = define(exists(1, Dom::MembersDom(conc(&rel_ty())), tru()));
    assert!(matches!(c.certify_stable(&doc1(), &sv), Err(CertifyError::ViewDependent)));

    // (iii) ST⁺: an SF-only spelling is not ⊤-stable.
    let (sn, _) = define(not(exists(1, Dom::AuditSlice(conc(&rel_ty())), tru())));
    assert!(matches!(c.certify_stable(&doc1(), &sn), Err(CertifyError::NotStable)));

    // The ST⁺ widening: `count(L_K) ≥ x` with x a bound ℕ parameter
    // certifies (a literal-only PD0 would refuse) — while plain classify
    // stays Neither (the widening is certification-only).
    let widened = nat_le(var(1), count(Dom::AuditSlice(conc(&rel_ty()))));
    let tw = c.type_check(vec![(v(1), Sort::Nat)], widened).expect("widened def");
    assert_eq!(
        c.classify(&tw, View::Audit).stability,
        skep_coordination::Stability::Neither
    );
    let (sw, _) = c.define_predicate(&doc1(), tw).expect("define widened");
    c.certify_stable(&doc1(), &sw).expect("ST⁺ certifies the bound-ℕ-parameter threshold");

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
    let (p_start, _) = c.define_predicate(&doc1(), p).expect("define P");

    let mk = |domain: Dom, trigger: TriggerRef, action: FireAction| Rule {
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
        c.register_rule(mk(Dom::ActiveSlice(conc(&rel_ty())), always_addr(&c), marker_action())),
        Err(RuleError::DomainTriggerSortMismatch { expected: Sort::Tup, found: Sort::Addr })
    ));
    // A Def trigger is Codom-only, so it can never serve a Tup domain.
    assert!(matches!(
        c.register_rule(mk(
            Dom::ActiveSlice(conc(&rel_ty())),
            TriggerRef::Def(p_start.clone()),
            marker_action()
        )),
        Err(RuleError::DomainTriggerSortMismatch { expected: Sort::Tup, found: Sort::Addr })
    ));
    // Trigger codomain and arity.
    let nat_trig = c.type_check_trigger(vec![(v(1), Sort::Addr)], lit_nat(1)).expect("Nat trigger");
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(conc(&rel_ty())), TriggerRef::Inline(nat_trig), marker_action())),
        Err(RuleError::TriggerNotBoolean)
    ));
    let two_param = c
        .type_check_trigger(vec![(v(1), Sort::Addr), (v(2), Sort::Addr)], tru())
        .expect("two-param term");
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(conc(&rel_ty())), TriggerRef::Inline(two_param), marker_action())),
        Err(RuleError::BadTriggerArity)
    ));
    // A ref-bearing Inline trigger.
    let ref_trig = c
        .type_check_trigger(vec![(v(1), Sort::Addr)], Term::Ref { addr: p_start.clone(), args: vec![at(var(1))] })
        .expect("ref-bearing trigger term");
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(conc(&rel_ty())), TriggerRef::Inline(ref_trig), marker_action())),
        Err(RuleError::RefBearingInlineTrigger)
    ));
    // A Def trigger with no defined signature.
    assert!(matches!(
        c.register_rule(mk(Dom::MembersDom(conc(&rel_ty())), TriggerRef::Def(ca(77)), marker_action())),
        Err(RuleError::DefTriggerUnregistered(_))
    ));
    // Marker.ty guards: cataloged Unary; idem⊤; non-PredLayer.
    assert!(matches!(
        c.register_rule(mk(
            Dom::MembersDom(conc(&rel_ty())),
            always_addr(&c),
            FireAction::Marker { home: doc1(), ty: key(&rel_ty()) }
        )),
        Err(RuleError::BadMarkerType(_))
    ));
    assert!(matches!(
        c.register_rule(mk(
            Dom::MembersDom(conc(&rel_ty())),
            always_addr(&c),
            FireAction::Marker { home: doc1(), ty: key(&bh4_ty()) }
        )),
        Err(RuleError::NonIdemMarkerType(_))
    ));
    let pdef_key = TypeKey(c.reserved_type(ShippedType::PredDef).clone());
    assert!(matches!(
        c.register_rule(mk(
            Dom::MembersDom(conc(&rel_ty())),
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
    ls.emit(Caller::System, &doc1(), &rel_ty(), &ca(1), &[ca(2)]).expect("rel 1");
    ls.emit(Caller::System, &doc1(), &rel_ty(), &ca(3), &[ca(2)]).expect("rel 2");

    let trig = TriggerRef::Inline(
        c.type_check_trigger(vec![(v(1), Sort::Addr)], not(is_k_t(&marker_ty(), var(1))))
            .expect("¬is_K(marker, x) @ audit"),
    );
    let rule = Rule {
        domain: Dom::MembersDom(conc(&rel_ty())),
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
    assert_eq!(e.arg, Value::Addr(ca(1))); // members in tumbler order

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
        c.fire(&Enabled { rule: id, arg: Value::Addr(ca(1)) }).expect("fire"),
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

/// A Nullify rule is always Uncertified (fails the Marker leg), fires as one
/// atomic retraction on a tuple domain, and — on the documented-contract
/// misuse (an Addr-over-M_K domain) — surfaces `BadTarget` as a `Failed`
/// step, never a silent skip.
#[test]
fn nullify_rules_uncertified_fire_and_failed_surface() {
    let k = kernel();
    let mut c = coord(&k);
    let ls = links(&k);
    let (m1, _) = ls.emit(Caller::System, &doc1(), &multi_ty(), &ca(1), &[ca(2)]).expect("multi 1");

    let trig = TriggerRef::Inline(
        c.type_check_trigger(vec![(v(1), Sort::Tup)], tru()).expect("Tup trigger"),
    );
    let rule = Rule {
        domain: Dom::ActiveSlice(conc(&multi_ty())),
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
    links(&k2).emit(Caller::System, &doc1(), &multi_ty(), &ca(1), &[ca(2)]).expect("multi");
    let trig2 = TriggerRef::Inline(
        c2.type_check_trigger(vec![(v(1), Sort::Addr)], tru()).expect("Addr trigger"),
    );
    let bad = Rule {
        domain: Dom::MembersDom(conc(&multi_ty())),
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
    ls.emit(Caller::System, &doc1(), &rel_ty(), &ca(1), &[ca(2)]).expect("rel 1");
    ls.emit(Caller::System, &doc1(), &rel_ty(), &ca(3), &[ca(2)]).expect("rel 2");

    let trig = TriggerRef::Inline(
        c.type_check_trigger(vec![(v(1), Sort::Addr)], not(is_k_t(&marker_ty(), var(1))))
            .expect("trigger"),
    );
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(conc(&rel_ty())),
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
    match c.fire(&Enabled { rule: id, arg: Value::Addr(ca(1)) }).expect("fire ca1") {
        FireOutcome::Fired { .. } => {}
        other => panic!("expected Fired, got {other:?}"),
    }
    let s2 = k.snapshot();
    assert!(c.quiescent_scoped(&scope, ScopeBody::PerAddress, &s2));
    assert!(!c.quiescent(&s2));

    // A Tup-domain rule is sort-incompatible with PerAddress: left UNSCOPED,
    // its enabled occurrence keeps the scoped verdict false — more work
    // reported, never false quiescence.
    ls.emit(Caller::System, &doc1(), &multi_ty(), &ca(5), &[ca(6)]).expect("multi");
    let trig_t = TriggerRef::Inline(
        c.type_check_trigger(vec![(v(2), Sort::Tup)], tru()).expect("Tup trigger"),
    );
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(conc(&multi_ty())),
        trigger: trig_t,
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    })
    .expect("register");
    assert!(!c.quiescent_scoped(&scope, ScopeBody::PerAddress, &k.snapshot()));
}
