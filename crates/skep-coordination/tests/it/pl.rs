//! M9 contract tests over a real kernel (InMemory), group A — the predicate
//! language: the catalog projection and the handle's standing promises,
//! Γ_D-checked typing with `Reg` expansion, the pure evaluator's view/UV
//! semantics and the denotation of every former, and the PD0 classifier.
//! Every assertion states a claim the design or interface makes — nothing
//! more.

use crate::common::*;
use crate::terms::*;

use skep_address::Address;
use skep_coordination::{
    Atom, Coordinator, DefineError, Dom, Env, RegisterError, Rule, Sort, Stability, Term,
    TypeError, TypeKey, TypeRef, Value, VarId, View, EXPANSION_NAME_BASE,
};
use skep_links::{coverage_class, enc, Behavior, Caller, Endset, ShippedType, Tip};

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
        .type_check_trigger((v(1), Sort::Tup), in_cov_f(lit_addr(&ca(1)), 1))
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

/// The checker's documented edges: the two `Ref` arity spellings, the
/// binder guard's and `Def`'s optional-sort requirement and the branch
/// agreement, the address-valued-domain requirement of `Reflect`/`MaxT1`, a
/// bare `Reg` in every position outside ∀/∃/`Count`, and the behavior
/// guards of the BH1/BH2/BH4 atoms — each its own typed rejection.
#[test]
fn type_check_edges() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("P(x)"))
        .expect("define P");
    let (q, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("Q"))
        .expect("define Q");

    // Ref arity: too few arguments — expected the first unmatched formal,
    // found the result sort; too many — expected the result sort, found the
    // extra argument's sort.
    assert_eq!(
        c.type_check(vec![], Term::Ref { addr: p, args: vec![] }).err(),
        Some(TypeError::SortMismatch { expected: Sort::Addr, found: Sort::Bool })
    );
    assert_eq!(
        c.type_check(vec![], Term::Ref { addr: q, args: vec![at(lit_addr(&ca(1)))] }).err(),
        Some(TypeError::SortMismatch { expected: Sort::Bool, found: Sort::Addr })
    );

    // The binder guard and `def` take an optional; the two branches agree.
    let opt_for_bool = || Some(TypeError::SortMismatch { expected: Sort::OptAddr, found: Sort::Bool });
    assert_eq!(c.type_check(vec![], if_some(tru(), 2, tru(), tru())).err(), opt_for_bool());
    assert_eq!(c.type_check(vec![], def_(tru())).err(), opt_for_bool());
    assert_eq!(
        c.type_check(vec![], if_some(bot_addr(), 2, tru(), lit_nat(1))).err(),
        Some(TypeError::SortMismatch { expected: Sort::Bool, found: Sort::Nat })
    );

    // Only an address-valued domain reflects or has a T1 extremum; a bare
    // Reg outside ∀/∃/Count is class-valued and fails the same check.
    let tup_for_addr = || Some(TypeError::SortMismatch { expected: Sort::Addr, found: Sort::Tup });
    let tuples = || Dom::ActiveSlice(conc(&pred_def_ty()));
    assert_eq!(c.type_check(vec![], reflect(tuples())).err(), tup_for_addr());
    assert_eq!(c.type_check(vec![], Term::MaxT1(ad(tuples()))).err(), tup_for_addr());
    assert_eq!(c.type_check(vec![], reflect(Dom::Reg)).err(), tup_for_addr());
    assert_eq!(c.type_check(vec![], Term::MinT1(ad(Dom::Reg))).err(), tup_for_addr());
    assert_eq!(c.type_check(vec![], count(filter(Dom::Reg, 2, tru()))).err(), tup_for_addr());
    assert_eq!(
        c.type_check(vec![], big_union(Dom::Reg, 2, members(&pred_def_ty()))).err(),
        tup_for_addr()
    );

    // The behavior guards, one per behavior: BH4 on a class without Age,
    // BH2 on one without Walk, BH1 on one without ReadFilter.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Age(conc(&pred_def_ty()), at(lit_addr(&ca(1)))))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Age, .. })
    ));
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Stale(conc(&marker_ty()), at(lit_nat(1))))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Age, .. })
    ));
    assert!(matches!(
        c.type_check(vec![], succs(&marker_ty(), lit_addr(&ca(1)))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Walk, .. })
    ));
    assert!(matches!(
        c.type_check(vec![], is_filtered(&pred_def_ty(), lit_addr(&ca(1)))),
        Err(TypeError::BehaviorMissing { needs: Behavior::ReadFilter, .. })
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

/// V-IDX scoping: an inner `Reg` binder that reuses the outer's name
/// shadows it, so the body reads the inner class — `∃K :: ∀K :: is_K(x)`
/// is the universal, false for an address heading one class of five —
/// while a distinct inner name leaves the body to the outer existential.
#[test]
fn an_inner_reg_binder_shadows_the_outer() {
    let k = kernel();
    let c = coord(&k);
    links(&k).emit(Caller::System, &doc1(), &pred_def_ty(), &ca(5), &[]).expect("pred_def on ca5");
    let is_k7 = || Term::Atom(Atom::IsK(TypeRef::ClassVar(v(7)), at(var(1))));
    let shadowed = c
        .type_check(vec![(v(1), Sort::Addr)], exists(7, Dom::Reg, forall(7, Dom::Reg, is_k7())))
        .expect("∃K :: ∀K :: is_K(x)");
    let distinct = c
        .type_check(vec![(v(1), Sort::Addr)], exists(7, Dom::Reg, forall(8, Dom::Reg, is_k7())))
        .expect("∃K :: ∀K' :: is_K(x)");
    let env = Env::empty().bind(v(1), Value::Addr(ca(5)));
    let s = k.snapshot();
    assert!(!c.decide(&shadowed, &env, View::Active, &s));
    assert!(c.decide(&distinct, &env, View::Active, &s));
}

/// The catalog probe is `Endset`-equality, not coverage: a key spelling the
/// canonical endset twice has the same coverage class and misses as
/// `UnregisteredType`.
#[test]
fn a_coverage_equal_but_byte_different_key_misses() {
    let k = kernel();
    let c = coord(&k);
    let canonical = enc(&[ra(1)]);
    let dup = Endset::from_spans(canonical.spans().cloned().chain(canonical.spans().cloned()));
    assert_ne!(dup, canonical);
    assert_eq!(coverage_class(&dup), coverage_class(&canonical));
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Members(TypeRef::Concrete(TypeKey(dup))))),
        Err(TypeError::UnregisteredType(_))
    ));
    assert!(c.type_check(vec![], members(&canonical)).is_ok());
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
    assert!(decide_now(&k, &c, View::Active, set_mem(lit_addr(&la(1)), reflect(Dom::LinkDom))));

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
        exists(1, Dom::AuditSlice(conc(&pred_stable_ty())), in_cov_f(lit_addr(&ca(1)), 1))
    ));

    // UV default view: members(K, default) drops elements filtered by BH1
    // types OTHER than K — and never by K itself (retired is unfiltered in
    // its own default reading — the OQ1 commitment).
    ls.emit(Caller::System, &doc1(), &retired, &ca(3), &[]).expect("retire ca3");
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(conc(&pred_stable_ty()))), lit_nat(1))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(conc(&pred_stable_ty()))), lit_nat(0))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(conc(&retired))), lit_nat(1))));

    // V-DOC: residence is M3 registration.
    assert!(decide_now(&k, &c, View::Active, is_doc(lit_addr(&doc1()))));
    assert!(!decide_now(&k, &c, View::Active, is_doc(lit_addr(&ca(1)))));

    // The binder guard: IfSome narrows an optional through its `var`, and
    // the else-branch answers when the optional is ⊥. (The BH3 atoms —
    // TargetOf/TargetsKeyed — are out of the vocabulary in this format: no
    // cataloged class declares ReverseLookup, which the typing test pins.)
    assert!(decide_now(&k, &c, View::Active, if_some(bot_addr(), 2, fls(), tru())));
}

/// UV never rewrites a verdict atom: `is_K(x)@default` answers for an
/// element the default MEMBER reading of the same class has dropped.
#[test]
fn is_k_at_default_is_never_uv_filtered() {
    let k = kernel();
    let c = coord(&k);
    let ls = links(&k);
    ls.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel");
    ls.emit(Caller::System, &doc1(), &marker_ty(), &ca(3), &[]).expect("retire ca3");
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(conc(&pred_stable_ty()))), lit_nat(0))));
    assert!(decide_now(&k, &c, View::Default, is_k_t(&pred_stable_ty(), lit_addr(&ca(3)))));
}

/// UV on the target side: `targets_of(K, x)@default` drops the targets
/// filtered by a BH1 class other than K, and BH1's `is_filtered_J` is J's
/// own active membership (D2).
#[test]
fn targets_of_at_default_drops_filtered_targets() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, 2, &ca(1), &ca(2));
    deposit_rel(&k, 2, &ca(1), &ca(4));
    links(&k).emit(Caller::System, &doc1(), &marker_ty(), &ca(4), &[]).expect("retire ca4");
    let tof = || targets_of(&pred_stable_ty(), lit_addr(&ca(1)));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count_set(tof()), lit_nat(2))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count_set(tof()), lit_nat(1))));
    assert!(!decide_now(&k, &c, View::Default, set_mem(lit_addr(&ca(4)), tof())));
    assert!(decide_now(&k, &c, View::Default, set_mem(lit_addr(&ca(2)), tof())));
    assert!(decide_now(&k, &c, View::Active, is_filtered(&marker_ty(), lit_addr(&ca(4)))));
    assert!(!decide_now(&k, &c, View::Active, is_filtered(&marker_ty(), lit_addr(&ca(2)))));
}

/// `targets_of` matches its source by COVERAGE of F at `Active`/`Default`
/// and by DENOTATION at `Audit`: a probe strictly under a denoted address
/// has targets at the first two views and none at the third, while the
/// denoted address itself has them at all three — and `is_K` is by
/// coverage at every view.
#[test]
fn targets_of_matches_the_source_by_coverage_at_active_and_by_denotation_at_audit() {
    let k = kernel();
    let c = coord(&k);
    // F = enc({doc1}): its coverage is doc1's whole subtree, its denotation
    // the one address doc1.
    deposit_rel(&k, 2, &doc1(), &ca(2));
    let under = || targets_of(&pred_stable_ty(), lit_addr(&ca(1)));
    let denoted = || targets_of(&pred_stable_ty(), lit_addr(&doc1()));
    assert!(decide_now(&k, &c, View::Active, set_mem(lit_addr(&ca(2)), under())));
    assert!(decide_now(&k, &c, View::Default, set_mem(lit_addr(&ca(2)), under())));
    assert!(!decide_now(&k, &c, View::Audit, set_mem(lit_addr(&ca(2)), under())));
    for view in [View::Active, View::Default, View::Audit] {
        assert!(decide_now(&k, &c, view, set_mem(lit_addr(&ca(2)), denoted())), "{view:?}");
        assert!(
            decide_now(&k, &c, view, is_k_t(&pred_stable_ty(), lit_addr(&ca(1)))),
            "is_K matches by coverage at {view:?}"
        );
    }
}

/// BH2 over a linear lineage: `succs` is the one forward step, `chain` the
/// inclusive path from its start, `tip` the successor-free head — a sink's
/// head is itself — and `is_in_chain` is membership in the walk from its
/// FIRST argument, so it runs one way; `current_version` is `tip` at the
/// shipped class.
#[test]
fn bh2_walk_over_a_linear_lineage() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, 2, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, 2, &ca(3), &ca(4));
    let l3 = deposit_rel(&k, 2, &ca(5), &ca(6));
    let ls = links(&k);
    ls.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    ls.assert_sup(Caller::System, &doc1(), &l2, &l3).expect("l2 → l3");
    let d = |t: Term| decide_now(&k, &c, View::Active, t);

    assert!(d(set_mem(lit_addr(&l2), succs(&sup, lit_addr(&l1)))));
    assert!(d(nat_eq(count_set(succs(&sup, lit_addr(&l1))), lit_nat(1))));
    assert!(d(is_empty(succs(&sup, lit_addr(&l3)))));
    assert!(d(nat_eq(count_set(elems(chain(&sup, lit_addr(&l1)))), lit_nat(3))));
    assert!(d(set_mem(lit_addr(&l1), elems(chain(&sup, lit_addr(&l1))))), "the chain includes its start");
    assert!(d(tip_is(&sup, &l1, &l3)));
    assert!(d(tip_is(&sup, &l3, &l3)), "a sink's head is itself");
    assert!(d(is_in_chain(&sup, lit_addr(&l1), lit_addr(&l3))));
    assert!(d(is_in_chain(&sup, lit_addr(&l1), lit_addr(&l1))));
    assert!(!d(is_in_chain(&sup, lit_addr(&l3), lit_addr(&l1))), "membership runs forward only");
    assert!(!d(is_in_chain(&sup, lit_addr(&l2), lit_addr(&l1))));
    assert_eq!(c.current_version(&l1, &k.snapshot()), Tip::Sink(l3));
}

/// BH2 at a branch and at a cycle: the head is indeterminate, the chain
/// truncates where the walk halts — so a claimed successor past a branch is
/// NOT in the chain — and a cycle's members are each in the other's chain.
#[test]
fn bh2_tip_is_indeterminate_at_a_branch_and_a_cycle() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, 2, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, 2, &ca(3), &ca(4));
    let l3 = deposit_rel(&k, 2, &ca(5), &ca(6));
    let l4 = deposit_rel(&k, 2, &ca(7), &ca(8));
    let l5 = deposit_rel(&k, 2, &ca(9), &ca(10));
    let ls = links(&k);
    ls.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    ls.assert_sup(Caller::System, &doc1(), &l1, &l3).expect("l1 → l3: a branch");
    ls.assert_sup(Caller::System, &doc1(), &l4, &l5).expect("l4 → l5");
    ls.assert_sup(Caller::System, &doc1(), &l5, &l4).expect("l5 → l4: a cycle");
    let d = |t: Term| decide_now(&k, &c, View::Active, t);

    // The branch.
    assert!(!d(def_(tip(&sup, lit_addr(&l1)))));
    assert!(d(nat_eq(count_set(succs(&sup, lit_addr(&l1))), lit_nat(2))));
    assert!(d(nat_eq(count_set(elems(chain(&sup, lit_addr(&l1)))), lit_nat(1))));
    assert!(!d(is_in_chain(&sup, lit_addr(&l1), lit_addr(&l2))), "the chain halts at the branch");
    assert_eq!(c.current_version(&l1, &k.snapshot()), Tip::Indeterminate);
    // The cycle.
    assert!(!d(def_(tip(&sup, lit_addr(&l4)))));
    assert!(d(nat_eq(count_set(elems(chain(&sup, lit_addr(&l4)))), lit_nat(2))));
    assert!(d(is_in_chain(&sup, lit_addr(&l4), lit_addr(&l5))));
    assert!(d(is_in_chain(&sup, lit_addr(&l5), lit_addr(&l4))));
    assert_eq!(c.current_version(&l4, &k.snapshot()), Tip::Indeterminate);
}

/// UV over the BH2 family: a `default`-view term's `chain`/`succs` drop the
/// elements another BH1 class filters, while `tip`/`is_in_chain` walk
/// unfiltered — the same membership answers differently through the
/// collection and through the verdict.
#[test]
fn uv_drops_retired_elements_from_chain_and_succs_but_never_from_the_walk() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, 2, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, 2, &ca(3), &ca(4));
    let l3 = deposit_rel(&k, 2, &ca(5), &ca(6));
    let ls = links(&k);
    ls.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    ls.assert_sup(Caller::System, &doc1(), &l2, &l3).expect("l2 → l3");
    ls.emit(Caller::System, &doc1(), &marker_ty(), &l2, &[]).expect("retire l2");
    let chain_len = |view: View, n_: u32| {
        decide_now(&k, &c, view, nat_eq(count_set(elems(chain(&sup, lit_addr(&l1)))), lit_nat(n_)))
    };
    assert!(chain_len(View::Active, 3));
    assert!(chain_len(View::Audit, 3));
    assert!(chain_len(View::Default, 2));
    assert!(!decide_now(&k, &c, View::Default, set_mem(lit_addr(&l2), elems(chain(&sup, lit_addr(&l1))))));
    assert!(decide_now(&k, &c, View::Default, is_empty(succs(&sup, lit_addr(&l1)))));
    assert!(!decide_now(&k, &c, View::Active, is_empty(succs(&sup, lit_addr(&l1)))));
    assert!(decide_now(&k, &c, View::Default, tip_is(&sup, &l1, &l3)), "the walk runs through l2");
    assert!(decide_now(&k, &c, View::Default, is_in_chain(&sup, lit_addr(&l1), lit_addr(&l2))));
}

/// The walk is rebuilt over the VISIBLE operative claims: a claim homed in
/// a document the guest predicate refuses moves no walk for the refusing
/// coordinator, and moves it for one that reads everything.
#[test]
fn a_draft_homed_claim_moves_no_walk() {
    let k = kernel();
    let l1 = deposit_rel(&k, 2, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, 2, &ca(3), &ca(4));
    links(&k).assert_sup(Caller::System, &doc2(), &l1, &l2).expect("a claim homed in doc2");
    let refusing = coord_with_guest(&k, Box::new(|_: &World, d: &Address| *d != doc2()));
    let sup = refusing.reserved_type(ShippedType::Supersedes).clone();
    assert!(decide_now(&k, &refusing, View::Active, is_empty(succs(&sup, lit_addr(&l1)))));
    assert!(decide_now(&k, &refusing, View::Active, tip_is(&sup, &l1, &l1)));
    let seeing = coord(&k);
    assert!(decide_now(&k, &seeing, View::Active, set_mem(lit_addr(&l2), succs(&sup, lit_addr(&l1)))));
    assert!(decide_now(&k, &seeing, View::Active, tip_is(&sup, &l1, &l2)));
}

/// PC2a set semantics and the binders: an address domain deduplicates
/// while a tuple slice counts tuples; `M_K` the term and `M_K` the domain
/// agree at every view; `Filter`, `⋃`, ∀ and `Let` bind their variable to
/// each element.
#[test]
fn domains_have_set_semantics_and_binders_bind_the_element() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, 2, &ca(1), &ca(2));
    deposit_rel(&k, 2, &ca(1), &ca(4));
    deposit_rel(&k, 2, &ca(3), &ca(4));
    let ps = pred_stable_ty();
    let d = |t: Term| decide_now(&k, &c, View::Active, t);

    // Three tuples, two distinct members.
    assert!(d(nat_eq(count(Dom::MembersDom(conc(&ps))), lit_nat(2))));
    assert!(d(nat_eq(count(Dom::ActiveSlice(conc(&ps))), lit_nat(3))));
    assert!(d(nat_eq(count_set(members(&ps)), lit_nat(2))));
    // The law: the term and the domain are one reading, at every view.
    for view in [View::Active, View::Audit, View::Default] {
        assert!(decide_now(&k, &c, view, set_eq(members(&ps), reflect(Dom::MembersDom(conc(&ps))))), "{view:?}");
        assert!(
            decide_now(&k, &c, view, nat_eq(count_set(members(&ps)), count(Dom::MembersDom(conc(&ps))))),
            "{view:?}"
        );
    }
    // Filter binds each element, address or tuple.
    assert!(d(nat_eq(count(filter(Dom::MembersDom(conc(&ps)), 2, addr_eq(var(2), lit_addr(&ca(1))))), lit_nat(1))));
    assert!(d(nat_eq(count(filter(Dom::ActiveSlice(conc(&ps)), 2, in_cov_g(lit_addr(&ca(4)), 2))), lit_nat(2))));
    // ⋃ over the tuple slice of each tuple's G; ∀ over each tuple's F.
    let targets = || big_union(Dom::ActiveSlice(conc(&ps)), 2, tup_addrs_g(2));
    assert!(d(nat_eq(count_set(targets()), lit_nat(2))));
    assert!(d(set_mem(lit_addr(&ca(4)), targets())));
    assert!(d(forall(
        2,
        Dom::ActiveSlice(conc(&ps)),
        or(set_mem(lit_addr(&ca(1)), tup_addrs_f(2)), set_mem(lit_addr(&ca(3)), tup_addrs_f(2)))
    )));
    // Let binds a set value.
    assert!(d(let_(
        3,
        members(&ps),
        and(set_mem(lit_addr(&ca(1)), var(3)), not(set_mem(lit_addr(&ca(2)), var(3))))
    )));
}

/// The T1 extrema over an address domain — max and min, ⊥ on an empty one
/// (the else-branch answers, nothing panics), and prefix-smaller order (a
/// document address is below its elements) — read through the binder guard.
#[test]
fn t1_extrema_and_the_binder_guard() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, 2, &ca(1), &ca(2));
    deposit_rel(&k, 2, &ca(3), &ca(4));
    let ps = || Dom::MembersDom(conc(&pred_stable_ty()));
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    assert!(d(if_some(Term::MaxT1(ad(ps())), 2, addr_eq(var(2), lit_addr(&ca(3))), fls())));
    assert!(d(if_some(Term::MinT1(ad(ps())), 2, addr_eq(var(2), lit_addr(&ca(1))), fls())));
    let none = || Dom::MembersDom(conc(&marker_ty()));
    assert!(!d(def_(Term::MaxT1(ad(none())))));
    assert!(d(if_some(Term::MinT1(ad(none())), 2, fls(), tru())));
    deposit_rel(&k, 2, &doc1(), &ca(6));
    assert!(d(if_some(Term::MinT1(ad(ps())), 2, addr_eq(var(2), lit_addr(&doc1())), fls())));
    assert!(d(if_some(Term::MaxT1(ad(ps())), 2, addr_eq(var(2), lit_addr(&ca(3))), fls())));
}

/// V-PRIM at the equal cases: ≼ is reflexive and directed, T1's order is
/// strict, ≤ admits equality, definedness and the guard at both optional
/// sorts, the set prims on the empty set — and the connectives over every
/// cell of their tables.
#[test]
fn prims_at_their_equal_cases() {
    let k = kernel();
    let c = coord(&k);
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    assert!(d(prefix(lit_addr(&doc1()), lit_addr(&ca(1)))));
    assert!(d(prefix(lit_addr(&ca(1)), lit_addr(&ca(1)))));
    assert!(!d(prefix(lit_addr(&ca(1)), lit_addr(&doc1()))));
    assert!(!d(prefix(lit_addr(&ca(1)), lit_addr(&ca(2)))));
    assert!(d(t1_lt(lit_addr(&doc1()), lit_addr(&ca(1)))));
    assert!(!d(t1_lt(lit_addr(&ca(1)), lit_addr(&ca(1)))));
    assert!(d(t1_lt(lit_addr(&ca(1)), lit_addr(&ca(2)))));
    assert!(!d(t1_lt(lit_addr(&ca(2)), lit_addr(&ca(1)))));
    assert!(d(nat_eq(nat_add(lit_nat(1), lit_nat(2)), lit_nat(3))));
    assert!(d(nat_le(lit_nat(3), lit_nat(3))));
    assert!(!d(nat_le(lit_nat(4), lit_nat(3))));
    assert!(!d(def_(bot_addr())));
    assert!(!d(def_(bot_nat())));
    assert!(d(if_some(bot_nat(), 2, fls(), tru())));
    assert!(d(is_empty(members(&marker_ty()))));
    assert!(d(set_eq(members(&marker_ty()), members(&marker_ty()))));
    let b = |x: bool| if x { tru() } else { fls() };
    for (x, y) in [(false, false), (false, true), (true, false), (true, true)] {
        assert_eq!(d(and(b(x), b(y))), x && y, "and {x} {y}");
        assert_eq!(d(or(b(x), b(y))), x || y, "or {x} {y}");
        assert_eq!(d(implies(b(x), b(y))), !x || y, "implies {x} {y}");
        assert_eq!(d(iff(b(x), b(y))), x == y, "iff {x} {y}");
    }
    for x in [false, true] {
        assert_eq!(d(not(b(x))), !x, "not {x}");
    }
}

/// A verdict is "as of `snap.seq()`" (M2 V1 retrospective): the same term
/// answers differently at two pinned snapshots on either side of a deposit.
#[test]
fn a_verdict_is_as_of_its_snapshot() {
    let k = kernel();
    let c = coord(&k);
    let s0 = k.snapshot();
    links(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let s1 = k.snapshot();
    let t = c.type_check(vec![], is_k_t(&pred_stable_ty(), lit_addr(&ca(1)))).expect("checks");
    assert!(!c.decide(&t, &Env::empty(), View::Active, &s0));
    assert!(c.decide(&t, &Env::empty(), View::Active, &s1));
    assert!(s0.seq() < s1.seq());
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

/// `eval`'s door: an `Env` that binds a Γ_D parameter at the wrong sort is
/// a precondition violation named at the door, not a failure somewhere
/// inside the walk.
#[test]
#[should_panic(expected = "eval precondition")]
fn eval_panics_on_a_mis_sorted_parameter() {
    let k = kernel();
    let c = coord(&k);
    let t = c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("one-param term");
    let s = k.snapshot();
    let _ = c.eval(&t, &Env::empty().bind(v(1), Value::Nat(n(1))), View::Active, &s);
}

/// `eval`'s door, the other half: an `Env` that leaves a Γ_D parameter
/// unbound is named at the door too.
#[test]
#[should_panic(expected = "eval precondition")]
fn eval_panics_on_an_unbound_parameter() {
    let k = kernel();
    let c = coord(&k);
    let t = c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("one-param term");
    let s = k.snapshot();
    let _ = c.eval(&t, &Env::empty(), View::Active, &s);
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
    let isdoc = tc1(is_doc(var(1)));
    assert!(c.classify(&isdoc, View::Audit).footprint.reads_residence());
}

/// PD0's rules over a generated family: four atoms, one per lattice point,
/// combined through every connective and compared against the stated rule
/// (`∧`/`∨` need both sides; `⇒` combines SF⇒ST; `⇔` needs both sides
/// wholly stable; `¬` swaps) — then each named rule at one assertion: the
/// quantifier cases, `Let` and `IfSome` under a state-reading versus a
/// constant part, grow-only membership and emptiness at audit only, the
/// derived closure forms, a non-literal threshold, and the Default view's
/// BH1 charge.
#[test]
fn pd0_rules_over_a_generated_family() {
    let k = kernel();
    let c = coord(&k);
    let pd = || conc(&pred_def_ty());
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
            nat_le(lit_nat(2), count(filter(Dom::AuditSlice(pd()), 2, not(is_k_t(&pred_def_ty(), tup_addr(2)))))),
            View::Audit
        ),
        Stability::Neither
    );
    assert_eq!(stab(set_mem(lit_addr(&ca(1)), reflect(Dom::MembersDom(pd()))), View::Audit), Stability::StOnly);
    // A threshold that is not a literal leaves the count unclassified (the
    // widening to a bound parameter is certification-only).
    assert_eq!(
        stab(nat_le(nat_add(lit_nat(1), lit_nat(1)), count(Dom::AuditSlice(pd()))), View::Audit),
        Stability::Neither
    );
    // The Default reading of a core atom charges every BH1 filter slice.
    let isk = c.type_check(vec![(v(1), Sort::Addr)], is_k_t(&pred_def_ty(), var(1))).expect("checks");
    let retired = coverage_class(&marker_ty());
    assert!(c.classify(&isk, View::Default).footprint.active_classes().any(|x| *x == retired));
    assert!(!c.classify(&isk, View::Active).footprint.active_classes().any(|x| *x == retired));
}

#[test]
#[should_panic(expected = "classify precondition")]
fn classify_panics_on_a_ref_bearing_term() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("define");
    let t = c.type_check(vec![], Term::Ref { addr: p, args: vec![] }).expect("ref-bearing checks");
    let _ = c.classify(&t, View::Active);
}
