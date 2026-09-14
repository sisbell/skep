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
    Atom, CertifyError, Coordinator, DefineError, Dom, EmitError, Env, EvalError, FireError,
    InsertError, Lit, Nat, NullifyError, RegisterError, RetractError, Rule, RuleCertification,
    RuleError, ScopeBody, Sort, Stability, SupersedeError, Term, TxnError, TypeError, TypeKey,
    TypeRef, Value, VarId, View, EXPANSION_NAME_BASE,
};
use skep_links::{coverage_class, enc, Behavior, Caller, Endset, HasLinks, ShippedType, Tip};

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
fn varid_new_stops_at_the_watershed_and_env_binds_functionally() {
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
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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

    // `supersede` nests one level further, each operation's vocabulary its
    // own: SupersedeError → DefineError → RegisterError → TypeError.
    let sup = SupersedeError::Define(define);
    assert_eq!(
        sup.to_string(),
        format!("supersede: define_predicate: register_pred: the def is ill-typed: {ill}")
    );
    let define_cause = sup.source().expect("Define carries its DefineError");
    assert_eq!(
        define_cause.to_string(),
        format!("define_predicate: register_pred: the def is ill-typed: {ill}")
    );
    assert!(define_cause.source().is_some(), "and the chain runs on beneath it");
    // Its own up-front gate is a leaf, as `register_pred`'s parse refusal is.
    let gate = SupersedeError::OldStartNotEverRegistered(ca(1));
    assert_eq!(gate.to_string(), format!("supersede: old start {} is not an ever-registered def", ca(1)));
    assert!(gate.source().is_none());
}

/// EVERY wrapping rejection yields the cause it carries — the law the two
/// chains above walk one instance of each. Stated over the values because the
/// rest are reachable only when M7 or M5 actually refuses, and because three
/// of the nine `source` impls end in a catch-all, where a variant added later
/// would lose its chain in silence and a driver's report would stop at M9's
/// sentence instead of reaching M2's account.
#[test]
fn every_wrapping_rejection_yields_its_cause() {
    use std::error::Error;
    let emit = || TxnError::Rejected(EmitError::HomeNotRegistered);
    let nullify = || TxnError::Rejected(NullifyError::BadTarget);
    let insert = || TxnError::Rejected(InsertError::DocNotRegistered);
    let wrapped: Vec<(Box<dyn Error + Send + Sync>, String)> = vec![
        (Box::new(RegisterError::Emit(emit())), emit().to_string()),
        (Box::new(CertifyError::Emit(emit())), emit().to_string()),
        (Box::new(RetractError::Nullify(nullify())), nullify().to_string()),
        (Box::new(FireError::Emit(emit())), emit().to_string()),
        (Box::new(FireError::Nullify(nullify())), nullify().to_string()),
        (Box::new(SupersedeError::Lineage(emit())), emit().to_string()),
        (Box::new(DefineError::Insert(insert())), insert().to_string()),
        (Box::new(RuleError::IllFormedDomain(TypeError::TooDeep)), TypeError::TooDeep.to_string()),
        (
            Box::new(TypeError::RegInstanceIllTyped(Box::new(TypeError::TooLarge))),
            TypeError::TooLarge.to_string(),
        ),
    ];
    for (err, cause) in wrapped {
        let source = err.source().unwrap_or_else(|| panic!("{err} carries no cause"));
        assert_eq!(source.to_string(), cause, "{err}");
    }
    // A leaf carries none — the same `source` that must answer above.
    let leaves: Vec<Box<dyn Error + Send + Sync>> = vec![
        Box::new(EvalError::ArgArityMismatch),
        Box::new(RetractError::NotActive),
        Box::new(FireError::HomeNotRegistered),
        Box::new(RuleError::RefBearingDomain),
    ];
    for leaf in leaves {
        assert!(leaf.source().is_none(), "{leaf} is a leaf");
    }
}

/// A rejection naming a type key reads as the addresses the key denotes, not
/// as a dump of its spans — the rejection a caller building a `TypeKey` by
/// hand meets most. An endset denoting no address (no span of it unit-depth)
/// has no addresses to name, and says so.
#[test]
fn a_rejection_names_a_type_key_by_the_addresses_it_denotes() {
    use skep_address::{Span, Tumbler};

    let k = kernel();
    let c = coord(&k);
    let miss = c
        .type_check(vec![], members(&uncataloged_ty(20)))
        .expect_err("ra(20) is not a cataloged class");
    let rendered = miss.to_string();
    assert!(rendered.contains(&format!("{{{}}}", ra(20))), "{rendered}");
    assert!(!rendered.contains("Span") && !rendered.contains("Tumbler"), "{rendered}");

    // A span two element-positions wide is level-uniform and not unit-depth,
    // so it denotes nothing: the key names a span count instead.
    let start: Tumbler = t(&[1, 0, 1, 0, 1]);
    let wide = Span::new(start, t(&[0, 0, 0, 0, 2])).expect("T12-valid");
    let key = TypeKey(Endset::from_spans([wide]));
    assert!(!key.0.is_address_denoting());
    assert_eq!(key.to_string(), "<1 non-denoting span(s)>");
}

/// A caller builds a `Value` from this crate alone: every payload a variant
/// names — M1's tumbler and numeral, `im`'s persistent collections, M7's
/// coverage class — is reachable through `skep_coordination`'s own paths,
/// with no second manifest to version-match. And a value answers its own
/// sort, which is what `eval`'s door and `evaluate_def`'s argument check
/// compare against Γ_D.
#[test]
fn a_value_is_buildable_and_self_describing_through_this_crate_s_own_paths() {
    use skep_coordination::im::{HashMap as ImMap, OrdSet, Vector};
    use skep_coordination::{Address, CoverageClass, Nat as ReNat, Tumbler as ReTumbler};

    let addr: Address = ca(1);
    let tumbler: ReTumbler = addr.tumbler().clone();
    let set = Value::AddrSet(OrdSet::unit(tumbler));
    let shapes = [
        (Value::Bool(true), Sort::Bool),
        (Value::Addr(addr.clone()), Sort::Addr),
        (set.clone(), Sort::AddrSet),
        (Value::OptAddr(None), Sort::OptAddr),
        (Value::AddrSeq(Vector::unit(addr.clone())), Sort::AddrSeq),
        (Value::Map(ImMap::<CoverageClass, Address>::new()), Sort::Map),
        (Value::Nat(ReNat::from(7u32)), Sort::Nat),
        (Value::OptNat(Some(ReNat::from(7u32))), Sort::OptNat),
    ];
    for (val, sort) in &shapes {
        assert_eq!(val.sort(), *sort, "{val:?}");
    }

    // `eval`'s ℘_fin(T) precondition has a discharge point: a caller building
    // a set from hand-made tumblers — this crate re-exports `Tumbler` without
    // M1's `validate` — can reject one before `eval` asserts on it.
    assert!(set.holds_addresses());
    assert!(!Value::AddrSet(OrdSet::unit(t(&[1, 0, 0, 1]))).holds_addresses());

    // The re-exported `OrdSet<Tumbler>` IS the type the doors accept.
    let k = kernel();
    let c = coord(&k);
    let tt = c
        .type_check(
            vec![(v(1), Sort::AddrSet)],
            nat_eq(count(Dom::SetTerm(at(var(1)))), lit_nat(1)),
        )
        .expect("|s| = 1");
    let (start, _) = c.define_predicate(&doc1(), &tt).expect("define");
    let s = k.snapshot();
    assert_eq!(c.evaluate_def(&start, &[set], View::Active, &s), Ok(Value::Bool(true)));
}

/// The public types carry the traits a caller cannot add for itself: an `Env`
/// compares, so one built positionally and one built by `bind` can be checked
/// against each other; a `Signature`, a `Stability`, an `ActiveExceptions`, a
/// `ScopeBody` and a `RuleCertification` all hash, so a driver can group defs
/// by signature, tally checked terms by stability, or key a per-body policy
/// table.
#[test]
fn the_public_types_compare_and_hash_as_a_caller_needs() {
    use std::collections::{HashMap, HashSet};

    let k = kernel();
    let c = coord(&k);

    // `Env`: the two ways of building one agree, and a different binding does
    // not — so the equality is the bindings' and not a blanket true.
    let positional: Env =
        [(v(1), Value::Nat(n(1))), (v(2), Value::Bool(true))].into_iter().collect();
    let bound = Env::empty().bind(v(1), Value::Nat(n(1))).bind(v(2), Value::Bool(true));
    assert_eq!(positional, bound);
    assert_ne!(positional, Env::empty().bind(v(1), Value::Nat(n(1))));
    assert_ne!(positional, bound.bind(v(2), Value::Bool(false)));

    // `Signature`: defs grouped by their calling convention — two DISTINCT
    // defs sharing a Γ_D and a codomain land in one bucket (the hash is the
    // signature's value, not the def's identity), and a different Γ_D does
    // not, its names being part of it as `evaluate_def`'s binding needs.
    let sig_of = |params: Vec<(VarId, Sort)>, body: Term| {
        let tt = c.type_check(params, body).expect("checks");
        let (start, _) = c.define_predicate(&doc1(), &tt).expect("define");
        c.signature(&start).expect("defined")
    };
    let one_addr = sig_of(vec![(v(1), Sort::Addr)], tru());
    let by_signature: HashSet<_> = [
        one_addr.clone(),
        sig_of(vec![(v(1), Sort::Addr)], fls()),
        sig_of(vec![(v(3), Sort::Addr)], tru()),
        sig_of(vec![(v(1), Sort::Nat)], tru()),
    ]
    .into_iter()
    .collect();
    assert_eq!(by_signature.len(), 3, "the two defs sharing a Γ_D share a bucket");
    assert!(by_signature.contains(&one_addr));

    // `Stability` and `ActiveExceptions`: a tally over classified terms.
    let audit = |t: Term| c.classify(&c.type_check(vec![], t).expect("checks"), View::Audit);
    let stable = audit(exists(1, Dom::AuditSlice(concrete(&pred_def_ty())), tru()));
    let mut tally: HashMap<Stability, u32> = HashMap::new();
    for d in [&stable, &audit(not(exists(1, Dom::AuditSlice(concrete(&pred_def_ty())), tru())))] {
        *tally.entry(d.stability).or_default() += 1;
    }
    assert_eq!(tally.get(&Stability::StOnly), Some(&1));
    assert_eq!(tally.get(&Stability::SfOnly), Some(&1));
    assert!(HashSet::from([stable.active_exceptions]).contains(&stable.active_exceptions));

    // `ScopeBody` and `RuleCertification`: policy tables keyed by each.
    let policy = HashMap::from([(ScopeBody::PerAddress, 1u32), (ScopeBody::PerEmitter, 2)]);
    assert_eq!(policy.get(&ScopeBody::PerAddress), Some(&1));
    assert!(HashSet::from([
        RuleCertification::CertifiedTerminating,
        RuleCertification::Uncertified { sf: true, marker: false, grow_only: true },
    ])
    .contains(&RuleCertification::CertifiedTerminating));
}

// ─────────────────────────────── typing ───────────────────────────────

/// Γ_D is part of the checking judgment: unbound vars, the def-path/
/// trigger-path Tup split, sort synthesis, and the catalog/behavior guards.
#[test]
fn type_check_refuses_at_each_gamma_and_catalog_gate() {
    let k = kernel();
    let c = coord(&k);

    // A free Var outside Γ_D.
    assert!(matches!(c.type_check(vec![], var(3)), Err(TypeError::UnboundVariable(_))));
    // Γ_D binds each name once: a repeated name is refused before the body
    // is walked (the body here is unbound on its own), and after the Tup
    // gate.
    assert!(matches!(
        c.type_check(vec![(v(1), Sort::Addr), (v(1), Sort::Nat)], var(3)),
        Err(TypeError::DuplicateParameter(x)) if x == v(1)
    ));
    assert!(matches!(
        c.type_check(vec![(v(1), Sort::Addr), (v(1), Sort::Tup)], tru()),
        Err(TypeError::TupParameter(_))
    ));
    // The def path rejects a Tup parameter; the trigger path — its own
    // type, one parameter by signature — admits it, and requires Bool.
    assert!(matches!(
        c.type_check(vec![(v(1), Sort::Tup)], tru()),
        Err(TypeError::TupParameter(_))
    ));
    let one_tup = c
        .type_check_trigger((v(1), Sort::Tup), in_coverage_f(lit_addr(&ca(1)), 1))
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
        c.type_check(vec![], Term::Atom(Atom::SourcesTo(concrete(&pred_def_ty()), at(lit_addr(&ca(1)))))),
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
fn type_check_refuses_each_documented_edge_by_name() {
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
    assert_eq!(c.type_check(vec![], def(tru())).err(), opt_for_bool());
    assert_eq!(
        c.type_check(vec![], if_some(bot_addr(), 2, tru(), lit_nat(1))).err(),
        Some(TypeError::SortMismatch { expected: Sort::Bool, found: Sort::Nat })
    );

    // Only an address-valued domain reflects or has a T1 extremum; a bare
    // Reg outside ∀/∃/Count is class-valued and fails the same check.
    let tup_for_addr = || Some(TypeError::SortMismatch { expected: Sort::Addr, found: Sort::Tup });
    let tuples = || Dom::ActiveSlice(concrete(&pred_def_ty()));
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
        c.type_check(vec![], Term::Atom(Atom::Age(concrete(&pred_def_ty()), at(lit_addr(&ca(1)))))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Age, .. })
    ));
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Stale(concrete(&retired_ty()), at(lit_nat(1))))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Age, .. })
    ));
    assert!(matches!(
        c.type_check(vec![], succs(&retired_ty(), lit_addr(&ca(1)))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Walk, .. })
    ));
    assert!(matches!(
        c.type_check(vec![], is_filtered(&pred_def_ty(), lit_addr(&ca(1)))),
        Err(TypeError::BehaviorMissing { needs: Behavior::ReadFilter, .. })
    ));
}

/// WHICH rejection speaks when several hold: a node's type position and its
/// behavior guard before its children; children left to right; a binder's
/// domain before its body; a `Ref`'s referent before its arguments, and each
/// argument on its own account before it is matched against its formal.
#[test]
fn type_check_reports_the_first_rejection_in_its_stated_walk_order() {
    let k = kernel();
    let c = coord(&k);
    let mismatch = |expected: Sort, found: Sort| Some(TypeError::SortMismatch { expected, found });
    // Ill-typed on its own account, whatever formal it is matched against.
    let bad_arg = || and(tru(), lit_nat(1));

    // The type position and its guard, before the children.
    assert!(matches!(
        c.type_check(vec![], is_k(&uncataloged_ty(20), lit_nat(1))),
        Err(TypeError::UnregisteredType(_))
    ));
    assert!(matches!(
        c.type_check(vec![], succs(&retired_ty(), lit_nat(1))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Walk, .. })
    ));
    // Children left to right.
    assert_eq!(
        c.type_check(vec![], and(lit_nat(1), lit_addr(&ca(1)))).err(),
        mismatch(Sort::Bool, Sort::Nat)
    );
    // A binder's domain before its body.
    assert!(matches!(
        c.type_check(vec![], exists(2, Dom::MembersDom(concrete(&uncataloged_ty(20))), lit_nat(1))),
        Err(TypeError::UnregisteredType(_))
    ));
    // A `Ref`'s referent before its arguments …
    assert!(matches!(
        c.type_check(vec![], Term::Ref { addr: ca(9), args: vec![at(bad_arg())] }),
        Err(TypeError::DanglingReference(_))
    ));
    // … and an argument's own ill-typedness before its match to the formal,
    // which would report `{expected: Addr, found: Bool}`.
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("P(x)"))
        .expect("define P");
    assert_eq!(
        c.type_check(vec![], Term::Ref { addr: p, args: vec![at(bad_arg())] }).err(),
        mismatch(Sort::Bool, Sort::Nat)
    );
}

/// The node budget: `Reg`-expansion instantiates a body once per cataloged
/// class, so nested `Reg` quantifiers multiply — six over a leaf fit, seven
/// do not (`TooLarge`, before the seventh level's 78 125 instances exist) —
/// and an `Arc`-shared body is charged per traversal, as the tree it
/// unfolds to: forty levels of `And(a, a)` are forty-one nodes to build and
/// 2⁴¹ to check, refused at the budget rather than after it.
#[test]
fn type_check_refuses_an_expansion_past_the_node_budget() {
    let k = kernel();
    let c = coord(&k);
    let nested_reg = |levels: u32| {
        (0..levels).rev().fold(tru(), |body, i| forall(10 + i, Dom::Reg, body))
    };
    c.type_check(vec![], nested_reg(6)).expect("six nested Reg quantifiers fit the budget");
    assert!(matches!(c.type_check(vec![], nested_reg(7)), Err(TypeError::TooLarge)));
    let mut shared = at(tru());
    for _ in 0..40 {
        shared = at(Term::And(shared.clone(), shared));
    }
    assert!(matches!(c.type_check(vec![], Term::And(shared.clone(), shared)), Err(TypeError::TooLarge)));
}

/// The budget bounds the tree's BYTES, not merely its node count: a `Reg`
/// quantifier instantiates its body once per cataloged class, so a literal
/// charged as one node would multiply by five per level while the node count
/// did not. One 128 KB natural checks on its own; under a single `Reg`
/// quantifier — nine nodes in all — the substitution spends the budget
/// instead.
#[test]
fn type_check_charges_a_literal_s_payload_against_the_node_budget() {
    let k = kernel();
    let c = coord(&k);
    let big = || Term::Lit(Lit::Nat(Nat::from_bytes_be(&vec![1u8; 1 << 17]))); // 2¹⁴ limbs
    c.type_check(vec![], nat_eq(big(), lit_nat(1)))
        .expect("one large literal is within the budget");
    assert!(matches!(
        c.type_check(vec![], forall(10, Dom::Reg, nat_eq(big(), lit_nat(1)))),
        Err(TypeError::TooLarge)
    ));
}

/// The nesting cap is the checker's as it is the decoder's: `¬¹²⁸ ⊤`
/// checks and `¬¹²⁹ ⊤` is `TooDeep` — at the cap, before recursing further,
/// so a term nested thousands deep is refused on this default thread rather
/// than walked to its end. A `Reg` quantifier's instances sit under the join
/// chain the expansion builds — one level per cataloged class past the first
/// — so the deepest instance, not the quantifier's own node, is what the cap
/// charges.
#[test]
fn type_check_refuses_a_term_nested_past_the_cap() {
    let k = kernel();
    let c = coord(&k);
    let nested = |n: usize| (0..n).fold(tru(), |t, _| not(t));
    c.type_check(vec![], nested(128)).expect("a term at the cap checks");
    assert!(matches!(c.type_check(vec![], nested(129)), Err(TypeError::TooDeep)));
    assert!(matches!(c.type_check(vec![], nested(2048)), Err(TypeError::TooDeep)));

    // Five shipped classes ⇒ a four-connective join, so a `Reg` quantifier at
    // level n has its instances at n + 4.
    let reg_at = |n: usize| (0..n).fold(forall(10, Dom::Reg, tru()), |t, _| not(t));
    c.type_check(vec![], reg_at(124)).expect("124 + 4 joins = 128: at the cap");
    assert!(matches!(c.type_check(vec![], reg_at(125)), Err(TypeError::TooDeep)));
}

/// The DOMAIN family carries the checker's recursion on its own — a `Filter`
/// chain descends to the innermost domain before any `pred` is checked — so
/// it has a resource door of its own, and a supplied term is charged for
/// every domain former as for every term former. A body of 2¹⁴ leaves, each
/// `∃x ∈ {y ∈ L_dom | ⊤} :: ⊤`, is 2¹⁶ − 1 term formers beside 2¹⁵ domain
/// formers: within the budget were the domains free, `TooLarge` when they
/// are charged — and a body of half the leaves halves all of them, so the
/// refusal is the budget's and not the shape's. The chain then pins the
/// nesting boundary on the same family.
#[test]
fn type_check_charges_the_domain_family_and_caps_its_nesting() {
    let k = kernel();
    let c = coord(&k);
    // Three term formers and two domain formers per leaf, joined by `and`.
    let leaves = |l: u32| {
        let leaf = || exists(2, filter(Dom::LinkDom, 3, tru()), tru());
        let mut t = leaf();
        for _ in 0..l.trailing_zeros() {
            t = Term::And(at(t.clone()), at(t));
        }
        t
    };
    assert!(matches!(c.type_check(vec![], leaves(1 << 14)), Err(TypeError::TooLarge)));
    c.type_check(vec![], leaves(1 << 13)).expect("half the leaves is half of each count");

    // `count` at 0, filter k at k, the innermost `L_dom` at n + 1.
    let filters = |n: usize| (0..n).fold(Dom::LinkDom, |d, _| filter(d, 2, tru()));
    c.type_check(vec![], count(filters(127))).expect("a domain chain at the cap checks");
    assert!(matches!(c.type_check(vec![], count(filters(128))), Err(TypeError::TooDeep)));
}

/// A `Ref`'s arguments are spliced into the flat expansion's `Let` chain at
/// their OWN positions, so argument `i` expands `i` levels below the
/// reference — a depth the reach formula's `arity` term charges once, at the
/// referent's splice point, and never per argument. Charged at one level they
/// would admit a term whose expansion is `arity + argument depth` deep, and
/// hand it to `view_independent` and `st_plus`, which walk it with no bound of
/// their own; chained with descending arities that reaches ~7,900 levels from
/// ~8,000 nodes and overflows the caller's stack. Two nested calls fit and
/// certify; a third, and one deep argument, do not.
#[test]
fn a_reference_s_arguments_are_charged_at_their_expansion_positions() {
    let k = kernel();
    let c = coord(&k);
    const ARITY: u32 = 60;
    let params: Vec<(VarId, Sort)> = (1..=ARITY).map(|i| (v(i), Sort::Bool)).collect();
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(params, tru()).expect("P(b1..b60) := ⊤"))
        .expect("define P");
    // A call whose LAST argument is `last`; the other 59 are ⊤.
    let call = |last: Term| Term::Ref {
        addr: p.clone(),
        args: (1..ARITY).map(|_| at(tru())).chain([at(last)]).collect(),
    };
    // Two nested calls expand to 59 + 60 = 119 `Let`s over the inner body.
    let two = c.type_check(vec![], call(call(tru()))).expect("two levels fit");
    let (two_start, _) = c.define_predicate(&doc1(), &two).expect("define");
    c.certify_stable(&doc1(), &two_start).expect("its 120-level expansion analyzes");
    // A third level would expand 60 levels further; each one adds 59 more.
    assert!(matches!(c.type_check(vec![], call(call(call(tru())))), Err(TypeError::TooDeep)));
    // The same arithmetic for one deep argument: at position 59 it expands 59
    // levels below the reference, so its own 100 put the expansion at 160.
    let deep = (0..100).fold(tru(), |t, _| not(t));
    assert!(matches!(c.type_check(vec![], call(deep)), Err(TypeError::TooDeep)));
}

/// V-IDX: `count(Reg)` folds to the (constant) registered-class count;
/// Reg-quantifiers expand per class; an instance-wise ill-typed body rejects
/// whole.
#[test]
fn reg_expansion_folds_count_instantiates_per_class_and_refuses_an_ill_typed_instance() {
    let k = kernel();
    let c = coord(&k);
    let writer = link_writer(&k);

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
    writer.emit(Caller::System, &doc1(), &pred_def_ty(), &ca(5), &[]).expect("pred_def emit");
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
    link_writer(&k).emit(Caller::System, &doc1(), &pred_def_ty(), &ca(5), &[]).expect("pred_def on ca5");
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

/// A checked term keeps its SOURCE body — `Reg` quantifiers and class
/// variables intact — beside the Reg-expanded projection the evaluator
/// walks; that compact form is what `define_predicate` stores, and its Γ_D
/// is the ordered context the check was made under. A trigger reports the
/// same three of itself.
#[test]
fn a_checked_term_reports_its_source_body_and_its_ordered_context() {
    let k = kernel();
    let c = coord(&k);
    let body = || exists(7, Dom::Reg, Term::Atom(Atom::IsK(TypeRef::ClassVar(v(7)), at(var(1)))));
    let tt = c.type_check(vec![(v(1), Sort::Addr)], body()).expect("Reg-quantified");
    assert_eq!(tt.source_body(), &body(), "the pre-Reg-expansion body, verbatim");
    assert_eq!(tt.params(), &[(v(1), Sort::Addr)]);
    assert_eq!(tt.result_sort(), Sort::Bool);
    assert!(tt.is_ref_free());
    let trig = c.type_check_trigger((v(1), Sort::Addr), body()).expect("trigger");
    assert_eq!(trig.param(), &(v(1), Sort::Addr));
    assert_eq!(trig.source_body(), &body());
    assert!(trig.is_ref_free());
}

/// The catalog probe is `Endset`-equality, not coverage: a key spelling the
/// canonical endset twice has the same coverage class and misses as
/// `UnregisteredType`.
#[test]
fn a_coverage_equal_but_byte_different_key_misses() {
    let k = kernel();
    let c = coord(&k);
    let canonical = pred_def_ty();
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
fn a_verdict_reads_its_view_s_slice_and_uv_drops_only_other_bh1_classes() {
    let k = kernel();
    let c = coord(&k);
    let writer = link_writer(&k);

    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2)); // pred_stable class, F=ca1, G=ca2
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(2));

    // is_K / member counting / L_dom / reflection membership.
    assert!(decide_now(&k, &c, View::Active, is_k(&pred_stable_ty(), lit_addr(&ca(1)))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(concrete(&pred_stable_ty()))), lit_nat(2))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::LinkDom), lit_nat(2))));
    assert!(decide_now(&k, &c, View::Active, set_mem(lit_addr(&la(1)), reflect(Dom::LinkDom))));

    // Retraction: the active reading shrinks, the audit reading persists —
    // the term view selects (PR-VIEW: the view is an eval parameter).
    writer.nullify(Caller::System, &doc1(), &l1).expect("retract rel 1");
    assert!(!decide_now(&k, &c, View::Active, is_k(&pred_stable_ty(), lit_addr(&ca(1)))));
    assert!(decide_now(&k, &c, View::Audit, is_k(&pred_stable_ty(), lit_addr(&ca(1)))));
    // The audit tuple slice still carries l1 (∃ t ∈ L_rel :: ca1 ∈ cov_F(t)).
    assert!(decide_now(
        &k,
        &c,
        View::Active,
        exists(1, Dom::AuditSlice(concrete(&pred_stable_ty())), in_coverage_f(lit_addr(&ca(1)), 1))
    ));

    // UV default view: members(K, default) drops elements filtered by BH1
    // types OTHER than K — and never by K itself (retired is unfiltered in
    // its own default reading — the OQ1 commitment).
    writer.emit(Caller::System, &doc1(), &retired_ty(), &ca(3), &[]).expect("retire ca3");
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(concrete(&pred_stable_ty()))), lit_nat(1))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(concrete(&pred_stable_ty()))), lit_nat(0))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(concrete(&retired_ty()))), lit_nat(1))));

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
    let writer = link_writer(&k);
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel");
    writer.emit(Caller::System, &doc1(), &retired_ty(), &ca(3), &[]).expect("retire ca3");
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(concrete(&pred_stable_ty()))), lit_nat(0))));
    assert!(decide_now(&k, &c, View::Default, is_k(&pred_stable_ty(), lit_addr(&ca(3)))));
}

/// UV on the target side: `targets_of(K, x)@default` drops the targets
/// filtered by a BH1 class other than K, and BH1's `is_filtered_J` is J's
/// own active membership (D2).
#[test]
fn targets_of_at_default_drops_filtered_targets() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(4));
    link_writer(&k).emit(Caller::System, &doc1(), &retired_ty(), &ca(4), &[]).expect("retire ca4");
    let tof = || targets_of(&pred_stable_ty(), lit_addr(&ca(1)));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count_set(tof()), lit_nat(2))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count_set(tof()), lit_nat(1))));
    assert!(!decide_now(&k, &c, View::Default, set_mem(lit_addr(&ca(4)), tof())));
    assert!(decide_now(&k, &c, View::Default, set_mem(lit_addr(&ca(2)), tof())));
    assert!(decide_now(&k, &c, View::Active, is_filtered(&retired_ty(), lit_addr(&ca(4)))));
    assert!(!decide_now(&k, &c, View::Active, is_filtered(&retired_ty(), lit_addr(&ca(2)))));
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
    deposit_rel(&k, PRED_STABLE, &doc1(), &ca(2));
    let under = || targets_of(&pred_stable_ty(), lit_addr(&ca(1)));
    let denoted = || targets_of(&pred_stable_ty(), lit_addr(&doc1()));
    assert!(decide_now(&k, &c, View::Active, set_mem(lit_addr(&ca(2)), under())));
    assert!(decide_now(&k, &c, View::Default, set_mem(lit_addr(&ca(2)), under())));
    assert!(!decide_now(&k, &c, View::Audit, set_mem(lit_addr(&ca(2)), under())));
    for view in [View::Active, View::Default, View::Audit] {
        assert!(decide_now(&k, &c, view, set_mem(lit_addr(&ca(2)), denoted())), "{view:?}");
        assert!(
            decide_now(&k, &c, view, is_k(&pred_stable_ty(), lit_addr(&ca(1)))),
            "is_K matches by coverage at {view:?}"
        );
    }
}

/// The audit slice is the whole record: after a retraction, the retired
/// tuple's F members and G targets persist in an `audit` reading and vanish
/// from an `active` one. Asserted of each read in ABSOLUTE terms — the
/// term/domain law above holds even when both of its sides read the wrong
/// slice. The two tuple domains are fixed slices, whatever the term view
/// says.
#[test]
fn an_audit_reading_keeps_what_a_retraction_removes_from_the_active_one() {
    let k = kernel();
    let c = coord(&k);
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    link_writer(&k).nullify(Caller::System, &doc1(), &l1).expect("retract the ca1 tuple");
    let ps = pred_stable_ty();
    let decide_at = |view: View, t: Term| decide_now(&k, &c, view, t);

    // members / M_K
    assert!(decide_at(View::Audit, set_mem(lit_addr(&ca(1)), members(&ps))));
    assert!(!decide_at(View::Active, set_mem(lit_addr(&ca(1)), members(&ps))));
    assert!(decide_at(View::Audit, nat_eq(count(Dom::MembersDom(concrete(&ps))), lit_nat(2))));
    assert!(decide_at(View::Active, nat_eq(count(Dom::MembersDom(concrete(&ps))), lit_nat(1))));
    // targets_of
    let tof = || targets_of(&ps, lit_addr(&ca(1)));
    assert!(decide_at(View::Audit, set_mem(lit_addr(&ca(2)), tof())));
    assert!(!decide_at(View::Active, set_mem(lit_addr(&ca(2)), tof())));
    // A_K and L_K name their own slice at every term view.
    assert!(decide_at(View::Audit, nat_eq(count(Dom::ActiveSlice(concrete(&ps))), lit_nat(1))));
    assert!(decide_at(View::Active, nat_eq(count(Dom::AuditSlice(concrete(&ps))), lit_nat(2))));
}

/// The atoms PR-VIEW's scan calls view-INDEPENDENT must DENOTE the same at
/// every view — the scan's half of that claim is watched
/// (`view_independence_refuses_every_view_parameterized_and_uv_rewritten_form`),
/// and this is the evaluator's, which is what `certify_stable` certifies on.
/// Each reads a FIXED slice, so a retracted witness the AUDIT slice still
/// holds must not move the answer; every row is stated absolutely, and the
/// `audit` row is the one a view-parameterized read would fail. (`is_doc`
/// reads M3 and no slice; the rest of the list is dormant in this format or
/// binds a tuple.)
#[test]
fn a_fixed_slice_atom_denotes_the_same_at_every_view() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let writer = link_writer(&k);
    // A claim the audit slice keeps and the active slice does not …
    let (claim, _) = writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    writer.nullify(Caller::System, &doc1(), &claim).expect("retract the claim");
    // … and a BH1 membership likewise.
    let (retired, _) =
        writer.emit(Caller::System, &doc1(), &retired_ty(), &ca(5), &[]).expect("retire ca5");
    writer.nullify(Caller::System, &doc1(), &retired).expect("un-retire ca5");
    for view in [View::Active, View::Audit, View::Default] {
        assert!(
            !decide_now(&k, &c, view, is_filtered(&retired_ty(), lit_addr(&ca(5)))),
            "is_filtered reads the ACTIVE retired slice at {view:?}"
        );
        assert!(
            decide_now(&k, &c, view, tip_is(&sup, &l1, &l1)),
            "the walk follows only OPERATIVE claims at {view:?}"
        );
        assert!(
            !decide_now(&k, &c, view, is_in_chain(&sup, lit_addr(&l1), lit_addr(&l2))),
            "the chain halts at l1 at {view:?}"
        );
    }
}

/// BH2 over a linear lineage: `succs` is the one forward step, `chain` the
/// inclusive path from its start, `tip` the successor-free head — a sink's
/// head is itself — and `is_in_chain` is membership in the walk from its
/// FIRST argument, so it runs one way; `current_version` is `tip` at the
/// shipped class.
#[test]
fn over_a_linear_lineage_the_tip_is_the_sink_and_the_chain_runs_forward() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let l3 = deposit_rel(&k, PRED_STABLE, &ca(5), &ca(6));
    let writer = link_writer(&k);
    writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    writer.assert_sup(Caller::System, &doc1(), &l2, &l3).expect("l2 → l3");
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
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let l3 = deposit_rel(&k, PRED_STABLE, &ca(5), &ca(6));
    let l4 = deposit_rel(&k, PRED_STABLE, &ca(7), &ca(8));
    let l5 = deposit_rel(&k, PRED_STABLE, &ca(9), &ca(10));
    let writer = link_writer(&k);
    writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    writer.assert_sup(Caller::System, &doc1(), &l1, &l3).expect("l1 → l3: a branch");
    writer.assert_sup(Caller::System, &doc1(), &l4, &l5).expect("l4 → l5");
    writer.assert_sup(Caller::System, &doc1(), &l5, &l4).expect("l5 → l4: a cycle");
    let d = |t: Term| decide_now(&k, &c, View::Active, t);

    // The branch.
    assert!(!d(def(tip(&sup, lit_addr(&l1)))));
    assert!(d(nat_eq(count_set(succs(&sup, lit_addr(&l1))), lit_nat(2))));
    assert!(d(nat_eq(count_set(elems(chain(&sup, lit_addr(&l1)))), lit_nat(1))));
    assert!(!d(is_in_chain(&sup, lit_addr(&l1), lit_addr(&l2))), "the chain halts at the branch");
    assert_eq!(c.current_version(&l1, &k.snapshot()), Tip::Indeterminate);
    // The cycle.
    assert!(!d(def(tip(&sup, lit_addr(&l4)))));
    assert!(d(nat_eq(count_set(elems(chain(&sup, lit_addr(&l4)))), lit_nat(2))));
    assert!(d(is_in_chain(&sup, lit_addr(&l4), lit_addr(&l5))));
    assert!(d(is_in_chain(&sup, lit_addr(&l5), lit_addr(&l4))));
    assert_eq!(c.current_version(&l4, &k.snapshot()), Tip::Indeterminate);
}

/// A claim is operative iff unnullified (Df-SUCC): the walk reads the ACTIVE
/// claims, so retracting the CLAIM — not its endpoints — removes the edge and
/// the head falls back to the node itself.
#[test]
fn a_nullified_claim_is_not_operative_so_the_walk_does_not_follow_it() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let writer = link_writer(&k);
    let (claim, _) = writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    assert!(decide_now(&k, &c, View::Active, tip_is(&sup, &l1, &l2)));
    assert_eq!(c.current_version(&l1, &k.snapshot()), Tip::Sink(l2.clone()));

    writer.nullify(Caller::System, &doc1(), &claim).expect("retract the claim");
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    assert!(d(is_empty(succs(&sup, lit_addr(&l1)))));
    assert!(d(tip_is(&sup, &l1, &l1)), "the head falls back to l1 itself");
    assert!(d(nat_eq(count_set(elems(chain(&sup, lit_addr(&l1)))), lit_nat(1))));
    assert!(!d(is_in_chain(&sup, lit_addr(&l1), lit_addr(&l2))));
    assert_eq!(c.current_version(&l1, &k.snapshot()), Tip::Sink(l1));
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
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let l3 = deposit_rel(&k, PRED_STABLE, &ca(5), &ca(6));
    let writer = link_writer(&k);
    writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    writer.assert_sup(Caller::System, &doc1(), &l2, &l3).expect("l2 → l3");
    writer.emit(Caller::System, &doc1(), &retired_ty(), &l2, &[]).expect("retire l2");
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
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    link_writer(&k).assert_sup(Caller::System, &doc2(), &l1, &l2).expect("a claim homed in doc2");
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
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(4));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let ps = pred_stable_ty();
    let d = |t: Term| decide_now(&k, &c, View::Active, t);

    // Three tuples, two distinct members.
    assert!(d(nat_eq(count(Dom::MembersDom(concrete(&ps))), lit_nat(2))));
    assert!(d(nat_eq(count(Dom::ActiveSlice(concrete(&ps))), lit_nat(3))));
    assert!(d(nat_eq(count_set(members(&ps)), lit_nat(2))));
    // The law: the term and the domain are one reading, at every view.
    for view in [View::Active, View::Audit, View::Default] {
        assert!(decide_now(&k, &c, view, set_eq(members(&ps), reflect(Dom::MembersDom(concrete(&ps))))), "{view:?}");
        assert!(
            decide_now(&k, &c, view, nat_eq(count_set(members(&ps)), count(Dom::MembersDom(concrete(&ps))))),
            "{view:?}"
        );
    }
    // Filter binds each element, address or tuple.
    assert!(d(nat_eq(count(filter(Dom::MembersDom(concrete(&ps)), 2, addr_eq(var(2), lit_addr(&ca(1))))), lit_nat(1))));
    assert!(d(nat_eq(count(filter(Dom::ActiveSlice(concrete(&ps)), 2, in_coverage_g(lit_addr(&ca(4)), 2))), lit_nat(2))));
    // ⋃ over the tuple slice of each tuple's G; ∀ over each tuple's F.
    let targets = || big_union(Dom::ActiveSlice(concrete(&ps)), 2, tup_addrs_g(2));
    assert!(d(nat_eq(count_set(targets()), lit_nat(2))));
    assert!(d(set_mem(lit_addr(&ca(4)), targets())));
    assert!(d(forall(
        2,
        Dom::ActiveSlice(concrete(&ps)),
        or(set_mem(lit_addr(&ca(1)), tup_addrs_f(2)), set_mem(lit_addr(&ca(3)), tup_addrs_f(2)))
    )));
    // Let binds a set value.
    assert!(d(let_(
        3,
        members(&ps),
        and(set_mem(lit_addr(&ca(1)), var(3)), not(set_mem(lit_addr(&ca(2)), var(3))))
    )));
}

/// PC1's two quantifiers denote `all` and `any`: over ONE domain and ONE body
/// that some elements satisfy and others do not, `∀` is false while `∃` is
/// true — so neither is a constant and `∀` is not `∃`. The empty domain is the
/// other edge: `∀` is vacuously true there and `∃` false.
#[test]
fn the_quantifiers_denote_all_and_any() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let slice = || Dom::ActiveSlice(concrete(&pred_stable_ty()));
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    // ca1 is the F of one tuple of two.
    assert!(d(exists(2, slice(), in_coverage_f(lit_addr(&ca(1)), 2))));
    assert!(!d(forall(2, slice(), in_coverage_f(lit_addr(&ca(1)), 2))));
    // A body no element satisfies, and one every element satisfies.
    assert!(!d(exists(2, slice(), in_coverage_f(lit_addr(&ca(9)), 2))));
    assert!(d(forall(2, slice(), not(in_coverage_f(lit_addr(&ca(9)), 2)))));
    // The empty domain: ∀ vacuous, ∃ false.
    let empty = || Dom::MembersDom(concrete(&marker_ty()));
    assert!(d(forall(2, empty(), fls())));
    assert!(!d(exists(2, empty(), tru())));
}

/// `L_dom` is the typed-relation sublayer and nothing else: a link deposited
/// through the open surface in an UNCATALOGED type is outside PL's universe —
/// it seeds no domain element and enters no reflection — while the cataloged
/// links do, at every term view (the domain is fixed-audit), and stay once
/// retracted, the `[R]` tuple joining them as a cataloged link of its own.
#[test]
fn link_dom_holds_the_cataloged_links_only_and_reads_the_audit_slice() {
    let k = kernel();
    let c = coord(&k);
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_DEF, &ca(3), &ca(4));
    let open = deposit_rel(&k, 20, &ca(5), &ca(6)); // an uncataloged type number
    assert!(
        k.snapshot().world().links().readlink(&open).is_some(),
        "M7's store holds the open link — it is PL's universe that must not"
    );
    let in_ldom = |view: View, x: &Address| {
        decide_now(&k, &c, view, set_mem(lit_addr(x), reflect(Dom::LinkDom)))
    };
    for view in [View::Active, View::Audit, View::Default] {
        assert!(in_ldom(view, &l1), "{view:?}");
        assert!(in_ldom(view, &l2), "{view:?}");
        assert!(!in_ldom(view, &open), "an open link is outside PL's universe at {view:?}");
    }
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::LinkDom), lit_nat(2))));

    // The sublayer is the AUDIT record: a retracted cataloged link stays.
    link_writer(&k).nullify(Caller::System, &doc1(), &l1).expect("retract l1");
    assert!(in_ldom(View::Active, &l1));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::LinkDom), lit_nat(3))));
}

/// The T1 extrema over an address domain — max and min, ⊥ on an empty one
/// (the else-branch answers, nothing panics), and prefix-smaller order (a
/// document address is below its elements) — read through the binder guard.
#[test]
fn t1_extrema_answer_max_min_and_bot_through_the_binder_guard() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let stable_dom = || Dom::MembersDom(concrete(&pred_stable_ty()));
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    assert!(d(if_some(Term::MaxT1(ad(stable_dom())), 2, addr_eq(var(2), lit_addr(&ca(3))), fls())));
    assert!(d(if_some(Term::MinT1(ad(stable_dom())), 2, addr_eq(var(2), lit_addr(&ca(1))), fls())));
    let empty_dom = || Dom::MembersDom(concrete(&marker_ty()));
    assert!(!d(def(Term::MaxT1(ad(empty_dom())))));
    assert!(d(if_some(Term::MinT1(ad(empty_dom())), 2, fls(), tru())));
    deposit_rel(&k, PRED_STABLE, &doc1(), &ca(6));
    assert!(d(if_some(Term::MinT1(ad(stable_dom())), 2, addr_eq(var(2), lit_addr(&doc1())), fls())));
    assert!(d(if_some(Term::MaxT1(ad(stable_dom())), 2, addr_eq(var(2), lit_addr(&ca(3))), fls())));
}

/// V-PRIM at the equal cases: ≼ is reflexive and directed, T1's order is
/// strict, ≤ admits equality, definedness and the guard at both optional
/// sorts, the set prims on the empty set — and the connectives over every
/// cell of their tables.
#[test]
fn prims_answer_their_equal_cases_and_the_connectives_their_tables() {
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
    assert!(!d(def(bot_addr())));
    assert!(!d(def(bot_nat())));
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

/// Every V-PRIM Boolean denotes a FUNCTION, not a constant: the two equalities
/// answer false at some input and definedness answers true at some input.
/// Without this the suite's count assertions — all of them `nat_eq` — hold
/// under an always-true `NatEq`, and PC2a's set semantics, the UV
/// member-count rewrite, `count(Reg)` and `L_dom`'s population go dark.
#[test]
fn every_boolean_prim_answers_both_ways() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let ps = pred_stable_ty();
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    let sources = || members(&ps); // {ca1, ca3}
    let targets = || big_union(Dom::ActiveSlice(concrete(&ps)), 2, tup_addrs_g(2)); // {ca2, ca4}

    // ℕ `=` — the suite's count instrument.
    assert!(d(nat_eq(lit_nat(2), lit_nat(2))));
    assert!(!d(nat_eq(lit_nat(2), lit_nat(3))));
    assert!(!d(nat_eq(count(Dom::MembersDom(concrete(&ps))), lit_nat(3))));
    // ℘_fin(T) `=` — two sets of the SAME size and different elements, so a
    // cardinality-only equality is caught as well as a constant one.
    assert!(d(set_eq(sources(), sources())));
    assert!(!d(set_eq(sources(), targets())));
    assert!(!d(set_eq(sources(), members(&marker_ty()))));
    // Definedness, true at a defined optional.
    assert!(d(def(Term::MinT1(ad(Dom::MembersDom(concrete(&ps)))))));
    assert!(!d(def(bot_addr())));
}

/// A verdict is "as of `snap.seq()`" (M2 V1 retrospective): the same term
/// answers differently at two pinned snapshots on either side of a deposit.
#[test]
fn a_verdict_is_as_of_its_snapshot() {
    let k = kernel();
    let c = coord(&k);
    let s0 = k.snapshot();
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let s1 = k.snapshot();
    let tt = c.type_check(vec![], is_k(&pred_stable_ty(), lit_addr(&ca(1)))).expect("checks");
    assert!(!c.decide(&tt, &Env::empty(), View::Active, &s0));
    assert!(c.decide(&tt, &Env::empty(), View::Active, &s1));
    assert!(s0.seq() < s1.seq());
}

#[test]
#[should_panic(expected = "decide precondition")]
fn decide_panics_on_non_bool_codomain() {
    let k = kernel();
    let c = coord(&k);
    let tt = c.type_check(vec![], lit_nat(1)).expect("Nat-codomain term");
    let s = k.snapshot();
    let _ = c.decide(&tt, &Env::empty(), View::Active, &s);
}

/// `eval`'s door: an `Env` that binds a Γ_D parameter at the wrong sort is
/// a precondition violation named at the door, not a failure somewhere
/// inside the walk.
#[test]
#[should_panic(expected = "eval precondition")]
fn eval_panics_on_a_mis_sorted_parameter() {
    let k = kernel();
    let c = coord(&k);
    let tt = c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("one-param term");
    let s = k.snapshot();
    let _ = c.eval(&tt, &Env::empty().bind(v(1), Value::Nat(n(1))), View::Active, &s);
}

/// `eval`'s door, the other half: an `Env` that leaves a Γ_D parameter
/// unbound is named at the door too.
#[test]
#[should_panic(expected = "eval precondition")]
fn eval_panics_on_an_unbound_parameter() {
    let k = kernel();
    let c = coord(&k);
    let tt = c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("one-param term");
    let s = k.snapshot();
    let _ = c.eval(&tt, &Env::empty(), View::Active, &s);
}

/// `eval`'s door, the set half: an `AddrSet` argument holding a tumbler
/// that is no T4-valid address (adjacent separators) is no ℘_fin(T) value,
/// and is named at the door — never lifted inside the walk.
#[test]
#[should_panic(expected = "eval precondition")]
fn eval_panics_on_a_set_holding_a_non_address() {
    let k = kernel();
    let c = coord(&k);
    let tt = c.type_check(vec![(v(1), Sort::AddrSet)], tru()).expect("one-set-param term");
    let s = k.snapshot();
    let bad = Value::AddrSet(im::OrdSet::unit(t(&[1, 0, 0, 1])));
    let _ = c.eval(&tt, &Env::empty().bind(v(1), bad), View::Active, &s);
}

#[test]
#[should_panic(expected = "eval precondition")]
fn eval_panics_on_a_ref_bearing_term() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("define");
    let tt = c.type_check(vec![], Term::Ref { addr: p, args: vec![] }).expect("ref-bearing checks");
    assert!(!tt.is_ref_free());
    let s = k.snapshot();
    let _ = c.eval(&tt, &Env::empty(), View::Active, &s);
}

// ─────────────────────────────── dynamics ───────────────────────────────

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
/// UV-rewritten collection atoms — the gate `certify_stable` stands behind, so
/// a form dropped from it certifies a def whose ⊤-stability holds at one view
/// and not another, and a form wrongly added to it refuses a legitimate def.
#[test]
fn view_independence_refuses_every_view_parameterized_and_uv_rewritten_form() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let ps = pred_stable_ty();
    let independent = |t: Term| {
        let tt = c.type_check(vec![], t).expect("test term type-checks");
        let at = |view: View| c.classify(&tt, view).view_independent;
        // `view_independent` is the one report `Dynamics` calls view-AGNOSTIC,
        // so every row below states its claim at all three views at once.
        assert_eq!(at(View::Active), at(View::Audit), "view_independent moved with the view");
        assert_eq!(at(View::Audit), at(View::Default), "view_independent moved with the view");
        at(View::Audit)
    };
    // `sources_to`/`stale` are out of the vocabulary in this format.
    for t in [
        is_k(&ps, lit_addr(&ca(1))),
        members(&ps),
        targets_of(&ps, lit_addr(&ca(1))),
        succs(&sup, lit_addr(&ca(1))),
        chain(&sup, lit_addr(&ca(1))),
        count(Dom::MembersDom(concrete(&ps))),
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
/// derived closure forms, a non-literal threshold, and the Default view's
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
