//! M9 contract tests over a real kernel (InMemory) of the public surface as
//! one piece — what the root publishes across all three capability groups:
//! the catalog projection and the handle's standing promises (it crosses
//! threads, it renders), every rejection's display and cause chain, the
//! re-exported paths a caller builds a `Value` through, and the traits the
//! public types carry. Every assertion states a claim the design or
//! interface makes — nothing more.

use crate::common::*;
use crate::terms::*;

use skep_coordination::{
    CertifyError, Coordinator, DefineError, Dom, EmitError, Env, EvalError, FireError,
    InsertError, NullifyError, RegisterError, RetractError, Rule, RuleCertification, RuleError,
    ScopeBody, Sort, Stability, SupersedeError, Term, TxnError, TypeError, TypeKey, Value, VarId,
    View, EXPANSION_NAME_BASE,
};
use skep_links::{enc, Endset, ShippedType};

/// Catalog projection: a pure, infallible read of the injected registry —
/// the cached `reserved_type` accessor serves the five shipped endsets at
/// the compiled ghost-tumbler constants (there is no twice-passed
/// configuration left to drift; the old validate-once-or-fail arms went
/// with the retired `GenesisConfig` seam).
#[test]
fn catalog_projects_and_serves_reserved_endsets() {
    let k = kernel();
    let c = coord(&k);
    assert_eq!(c.reserved_type(ShippedType::PredDef), &enc(&[ra(PRED_DEF)]));
    assert_eq!(c.reserved_type(ShippedType::PredStable), &enc(&[ra(PRED_STABLE)]));
    assert_eq!(c.reserved_type(ShippedType::Retired), &enc(&[ra(RETIRED)]));
    assert_eq!(c.reserved_type(ShippedType::Supersedes), &enc(&[ra(SUPERSEDES)]));
    assert_eq!(c.reserved_type(ShippedType::Retraction), &enc(&[ra(RETRACTION)]));
}

/// The reserved expansion-name range is structurally uninhabitable by caller
/// names (`VarId::new` is the sole public constructor, and a `const fn`, so a
/// driver's named constants are held to the watershed at compile time);
/// `Env` binds functionally, and is a collection of bindings — built from an
/// iterator, extended, a later binding of a name shadowing an earlier one as
/// `bind` does.
#[test]
fn varid_new_stops_at_the_watershed_and_env_binds_functionally() {
    assert!(VarId::new(EXPANSION_NAME_BASE).is_none());
    assert!(VarId::new(EXPANSION_NAME_BASE - 1).is_some());
    const FIRST: VarId = VarId::new(1).expect("below the watershed");
    const RESERVED: Option<VarId> = VarId::new(EXPANSION_NAME_BASE);
    assert_eq!(Some(FIRST), VarId::new(1));
    assert!(RESERVED.is_none());
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
/// names — M1's address and numeral, `im`'s persistent collections, M7's
/// coverage class, tuple and endset — is reachable through
/// `skep_coordination`'s own paths, with no second manifest to version-match.
/// And a value answers its own sort, which is what `eval`'s door and
/// `evaluate_def`'s argument check compare against Γ_D — a tuple's, `Tup`,
/// being one no stored def's Γ_D holds.
#[test]
fn a_value_is_buildable_and_self_describing_through_this_crate_s_own_paths() {
    use skep_coordination::im::{HashMap as ImMap, OrdSet, Vector};
    use skep_coordination::{Address, CoverageClass, Endset as ReEndset, Nat as ReNat, Tuple};

    let addr: Address = ca(1);
    let set = Value::AddrSet(OrdSet::unit(addr.clone()));
    let tuple = Tuple { addr: la(1), from: ReEndset::empty(), to: ReEndset::empty() };
    let shapes = [
        (Value::Bool(true), Sort::Bool),
        (Value::Addr(addr.clone()), Sort::Addr),
        (set.clone(), Sort::AddrSet),
        (Value::OptAddr(None), Sort::OptAddr),
        (Value::AddrSeq(Vector::unit(addr.clone())), Sort::AddrSeq),
        (Value::Map(ImMap::<CoverageClass, Address>::new()), Sort::Map),
        (Value::Nat(ReNat::from(7u32)), Sort::Nat),
        (Value::OptNat(Some(ReNat::from(7u32))), Sort::OptNat),
        (Value::Tuple(tuple), Sort::Tup),
    ];
    for (val, sort) in &shapes {
        assert_eq!(val.sort(), *sort, "{val:?}");
    }

    // The re-exported `OrdSet<Address>` IS the type the doors accept.
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
