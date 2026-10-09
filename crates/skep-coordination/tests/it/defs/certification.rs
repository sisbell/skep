//! Certification (`certify_stable`): CVALID's legs in their order, ST⁺
//! decided over the flat expansion through references, the state-reading
//! atoms that pass PR-VIEW and leave ST⁺ the only guard, and a `Reg`
//! quantifier read through its instances, directly and through a reference.

use crate::common::*;
use crate::terms::*;

use skep_address::Address;
use skep_coordination::{CertifyError, Dom, Lit, Sort, Stability, Term, TypeRef, Value, View};
use skep_links::{Caller, ShippedType};

/// CVALID(0..iii) in order, the ST⁺ parameter widening, and the certificate's
/// M7 deposit.
#[test]
fn certify_stable_refuses_each_cvalid_leg_in_order_and_certifies_through_references() {
    let k = kernel();
    let c = coord(&k);
    let define = |t: Term| {
        let tt = c.type_check(vec![], t).expect("def term");
        c.define_predicate(&doc1(), &tt).expect("define")
    };

    assert!(matches!(c.certify_stable(&doc1(), &ca(40)), Err(CertifyError::NotEverRegistered)));

    // A ⊤-stable, view-independent Boolean def certifies and deposits; a
    // re-certification answers the incumbent and commits nothing.
    let (s0, _) = define(exists(1, Dom::AuditSlice(concrete(&pred_def_ty())), tru()));
    assert!(!c.is_certified_stable(&s0, &k.snapshot()), "uncertified until it is certified");
    let (cert, _) = c.certify_stable(&doc1(), &s0).expect("certify");
    assert!(c.is_certified_stable(&s0, &k.snapshot()));
    let before = k.current_seq();
    assert_eq!(c.certify_stable(&doc1(), &s0).expect("re-certify").0, cert);
    assert_eq!(k.current_seq(), before, "re-certification dedups and commits nothing");

    // (i) Boolean sort.
    let (sa, _) = define(Term::Lit(Lit::BotAddr));
    assert!(matches!(c.certify_stable(&doc1(), &sa), Err(CertifyError::NotBoolean)));

    // (ii) view-independent expansion (M_K is view-parameterized).
    let (sv, _) = define(exists(1, Dom::MembersDom(concrete(&pred_def_ty())), tru()));
    assert!(matches!(c.certify_stable(&doc1(), &sv), Err(CertifyError::ViewDependent)));

    // (iii) ST⁺: an SF-only spelling is not ⊤-stable.
    let (sn, _) = define(not(exists(1, Dom::AuditSlice(concrete(&pred_def_ty())), tru())));
    assert!(matches!(c.certify_stable(&doc1(), &sn), Err(CertifyError::StabilityUnproven)));
    assert!(!c.is_certified_stable(&sn, &k.snapshot()), "a refused certification deposits nothing");
    // … and the refusal means UNPROVEN, never unstable (ASN-0130): a
    // tautology — true at every state — is refused too, ST⁺ classifying by
    // spelling.
    let ex = || exists(1, Dom::AuditSlice(concrete(&pred_def_ty())), tru());
    let (taut, _) = define(or(ex(), not(ex())));
    assert!(matches!(c.certify_stable(&doc1(), &taut), Err(CertifyError::StabilityUnproven)));

    // The ST⁺ widening: `count(L_K) ≥ x` with x a bound ℕ parameter
    // certifies (a literal-only PD0 would refuse) — while plain classify
    // stays Neither (the widening is certification-only).
    let widened = nat_le(var(1), count(Dom::AuditSlice(concrete(&pred_def_ty()))));
    let tw = c.type_check(vec![(v(1), Sort::Nat)], widened).expect("widened def");
    assert_eq!(c.classify(&tw, View::Audit).stability, Stability::Neither);
    let (sw, _) = c.define_predicate(&doc1(), &tw).expect("define widened");
    c.certify_stable(&doc1(), &sw).expect("ST⁺ certifies the bound-ℕ-parameter threshold");

    // ST⁺ is not compositional over references: (ii) and (iii) are decided
    // over the FLAT expansion, so a def that is nothing but a reference
    // answers as its referent does — stable through s0, view-dependent
    // through sv, unstable through sn — with the referent's parameter bound
    // by the expansion (the widened sw, applied to a literal, certifies).
    let define_ref = |target: &Address, args: Vec<Term>| {
        let args = args.into_iter().map(at).collect();
        let tt = c.type_check(vec![], Term::Ref { addr: target.clone(), args }).expect("ref term");
        c.define_predicate(&doc1(), &tt).expect("define ref")
    };
    let (r0, _) = define_ref(&s0, vec![]);
    c.certify_stable(&doc1(), &r0).expect("a reference to a stable def is stable");
    let (rv, _) = define_ref(&sv, vec![]);
    assert!(matches!(c.certify_stable(&doc1(), &rv), Err(CertifyError::ViewDependent)));
    let (rn, _) = define_ref(&sn, vec![]);
    assert!(matches!(c.certify_stable(&doc1(), &rn), Err(CertifyError::StabilityUnproven)));
    let (rw, _) = define_ref(&sw, vec![lit_nat(3)]);
    c.certify_stable(&doc1(), &rw).expect("the expansion binds the referent's threshold parameter");

    // Two levels deep: a reference to a reference, and the threshold
    // parameter threaded through an intermediate def's own parameter.
    let (rr0, _) = define_ref(&r0, vec![]);
    c.certify_stable(&doc1(), &rr0).expect("stable through two references");
    let w2 = c
        .type_check(vec![(v(1), Sort::Nat)], Term::Ref { addr: sw.clone(), args: vec![at(var(1))] })
        .expect("W2(n) := SW(n)");
    let (w2, _) = c.define_predicate(&doc1(), &w2).expect("define W2");
    let (rw2, _) = define_ref(&w2, vec![lit_nat(3)]);
    c.certify_stable(&doc1(), &rw2).expect("the threshold threads through two expansion levels");

    // The order is forced where two legs fail: view-dependence speaks before
    // ST⁺, and the sort check before the activity check.
    let (svn, _) = define(not(exists(1, Dom::MembersDom(concrete(&pred_def_ty())), tru())));
    assert!(matches!(c.certify_stable(&doc1(), &svn), Err(CertifyError::ViewDependent)));
    c.retract_pred(&doc1(), &sa).expect("retract the non-Boolean def");
    assert!(matches!(c.certify_stable(&doc1(), &sa), Err(CertifyError::NotBoolean)));

    // (0)/(ii) ordering: a retracted def is NotActive — and retraction does
    // not cascade to the certificate, which is about the immutable content.
    c.retract_pred(&doc1(), &s0).expect("retract");
    assert!(matches!(c.certify_stable(&doc1(), &s0), Err(CertifyError::NotActive)));
    assert!(c.is_certified_stable(&s0, &k.snapshot()));
    assert!(!c.is_active_pred(&s0, &k.snapshot()));
}

/// ST⁺ is all that stands between `certify_stable` and a view-INDEPENDENT
/// Boolean def, and the atoms that pass PR-VIEW while reading state are where
/// that matters: `is_filtered`, `is_in_chain` and `tip` read FIXED active
/// slices, so each can go true → false — the history below makes each do so
/// after its refusal — and each def is `StabilityUnproven`; `is_doc` reads
/// residence, which is permanent, and the same gate certifies it. An analyzer
/// arm that called any of the first three ⊤-stable, or forgot the slice `tip`
/// reads, would stamp a permanent `pd_stable` claim on a def this history
/// falsifies.
#[test]
fn certify_stable_refuses_a_view_independent_def_the_store_can_falsify() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let writer = link_writer(&k);
    let define = |t: Term| {
        let tt = c.type_check(vec![], t).expect("a closed Boolean def");
        c.define_predicate(&doc1(), &tt).expect("define").0
    };
    let now = |p: &Address| c.evaluate_def(p, &[], View::Audit, &k.snapshot());

    let (retirement, _) =
        writer.emit(Caller::System, &doc1(), &retired_ty(), &ca(15), &[]).expect("retire ca15");
    let filtered = define(is_filtered(&retired_ty(), lit_addr(&ca(15))));
    assert_eq!(now(&filtered), Ok(Value::Bool(true)));
    assert!(matches!(c.certify_stable(&doc1(), &filtered), Err(CertifyError::StabilityUnproven)));
    writer.nullify(Caller::System, &doc1(), &retirement).expect("un-retire ca15");
    assert_eq!(now(&filtered), Ok(Value::Bool(false)), "the falsification refused above");

    let l1 = deposit_rel(&k, PRED_STABLE, &ca(11), &ca(12));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(13), &ca(14));
    let (claim, _) = writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    let chained = define(is_in_chain(&sup, lit_addr(&l1), lit_addr(&l2)));
    assert_eq!(now(&chained), Ok(Value::Bool(true)));
    assert!(matches!(c.certify_stable(&doc1(), &chained), Err(CertifyError::StabilityUnproven)));
    writer.nullify(Caller::System, &doc1(), &claim).expect("retract the claim");
    assert_eq!(now(&chained), Ok(Value::Bool(false)), "the falsification refused above");

    // `tip` is the third such read, and the one whose refusal rests on its
    // FOOTPRINT alone: read through the binder guard it is `IfSome`'s guard,
    // whose stability is the guard's footprint. With its claim retracted, l1
    // heads its own lineage — until the next claim.
    let headed = define(tip_is(&sup, &l1, &l1));
    assert_eq!(now(&headed), Ok(Value::Bool(true)));
    assert!(matches!(c.certify_stable(&doc1(), &headed), Err(CertifyError::StabilityUnproven)));
    let l3 = deposit_rel(&k, PRED_STABLE, &ca(16), &ca(17));
    writer.assert_sup(Caller::System, &doc1(), &l1, &l3).expect("l1 → l3");
    assert_eq!(now(&headed), Ok(Value::Bool(false)), "the falsification refused above");

    let resident = define(is_doc(lit_addr(&doc1())));
    c.certify_stable(&doc1(), &resident)
        .expect("residence is permanent: ⊤-stable and view-independent");
}

/// ST⁺ decides over the FLAT expansion, which carries a referent's quantifier
/// as the referent spelled it: `∀t ∈ L_K :: ca11 ∈ cov_F(t)` holds of the
/// empty slice and falls to the first tuple not covering ca11 — ⊥-stable,
/// never ⊤-stable — so it is refused, and so is a def that is nothing but a
/// reference to it; its `∃` twin certifies, directly and through a reference.
/// Evaluation never reads the expansion, so only certification can see a `∀`
/// rebuilt as an `∃` — and it would certify the def this test falsifies.
#[test]
fn st_plus_reads_a_referent_s_universal_as_a_universal() {
    let k = kernel();
    let c = coord(&k);
    let define = |t: Term| {
        let tt = c.type_check(vec![], t).expect("a closed Boolean def");
        c.define_predicate(&doc1(), &tt).expect("define").0
    };
    let through = |p: &Address| define(Term::Ref { addr: p.clone(), args: vec![] });
    // The Retired class: nothing below deposits into it but the falsification.
    let l_k = || Dom::AuditSlice(concrete(&retired_ty()));
    let covers_ca11 = || in_coverage_f(lit_addr(&ca(11)), 2);
    let all = define(forall(2, l_k(), covers_ca11()));
    let some = define(exists(2, l_k(), covers_ca11()));
    let (all_ref, some_ref) = (through(&all), through(&some));
    let now = |p: &Address| c.evaluate_def(p, &[], View::Audit, &k.snapshot());
    assert_eq!(now(&all_ref), Ok(Value::Bool(true)), "vacuous over the empty slice");
    for p in [&all, &all_ref] {
        assert!(
            matches!(c.certify_stable(&doc1(), p), Err(CertifyError::StabilityUnproven)),
            "{p}"
        );
    }
    for p in [&some, &some_ref] {
        c.certify_stable(&doc1(), p).expect("∃ over the grow-only L_K is ST⁺");
    }
    deposit_rel(&k, RETIRED, &ca(12), &ca(13));
    assert_eq!(
        now(&all_ref),
        Ok(Value::Bool(false)),
        "the falsification the refusal stood against"
    );
}

/// A reference WITH arguments reaches ST⁺ as a `let` chain binding them over
/// the referent's body (PR3a), so the referent's ⊤-stability arrives through
/// `Let`'s rule. `P(x) := ¬∃t ∈ L_K :: ⊤` holds until the first K tuple, and
/// so does `R := P(ca1)`: ST⁺ must refuse R as it refuses P. A reference with
/// no argument builds no `let`, so it cannot tell; a `Let` that passed a
/// constant bound's body through as ⊤-stable would certify R, which the
/// deposit below falsifies.
#[test]
fn a_reference_with_an_argument_is_as_unproven_as_its_referent() {
    let k = kernel();
    let c = coord(&k);
    // The Retired class: nothing below deposits into it but the falsification.
    let none_retired = not(exists(2, Dom::AuditSlice(concrete(&retired_ty())), tru()));
    let p = c.type_check(vec![(v(1), Sort::Addr)], none_retired).expect("P(x)");
    let (p, _) = c.define_predicate(&doc1(), &p).expect("define P");
    let r = Term::Ref { addr: p.clone(), args: vec![at(lit_addr(&ca(1)))] };
    let (r, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], r).expect("R := P(ca1)"))
        .expect("define R");
    for d in [&p, &r] {
        assert!(
            matches!(c.certify_stable(&doc1(), d), Err(CertifyError::StabilityUnproven)),
            "{d}"
        );
    }
    let now = || c.evaluate_def(&r, &[], View::Audit, &k.snapshot());
    assert_eq!(now(), Ok(Value::Bool(true)));
    deposit_rel(&k, RETIRED, &ca(12), &ca(13));
    assert_eq!(now(), Ok(Value::Bool(false)), "the falsification the refusal stood against");
}

/// A stored def keeps its `Reg` quantifier in its SOURCE, and every reader of
/// its checked form walks the instances instead: its flat expansion, directly
/// and through a reference, and its denotation through a reference. `P(x) :=
/// ∃K ∈ Reg :: ∃t ∈ L_K :: x ∈ cov_F(t)` — some audit tuple of some cataloged
/// class covers x in its F — is ⊤-stable and view-independent once expanded,
/// so it certifies, and so does `R := P(x₀)`; R denotes false until a tuple
/// covers x₀. The suite's one other class-quantifying def is only ever
/// evaluated directly, so a reader that took the source body — which neither
/// the evaluator nor the analyzer can walk — passed it.
#[test]
fn a_reg_quantified_def_is_certified_and_evaluated_through_a_reference() {
    let k = kernel();
    let c = coord(&k);
    let in_some_class = exists(
        7,
        Dom::Reg,
        exists(2, Dom::AuditSlice(TypeRef::ClassVar(v(7))), in_coverage_f(var(1), 2)),
    );
    let p = c.type_check(vec![(v(1), Sort::Addr)], in_some_class).expect("P(x)");
    let (p, _) = c.define_predicate(&doc1(), &p).expect("define P");
    // A doc2 position: no def's `pdef` or certificate covers it.
    let x0 = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    let r = c
        .type_check(vec![], Term::Ref { addr: p.clone(), args: vec![at(lit_addr(&x0))] })
        .expect("R := P(x₀)");
    let (r, _) = c.define_predicate(&doc1(), &r).expect("define R");
    c.certify_stable(&doc1(), &p).expect("P's instances are ⊤-stable and view-independent");
    c.certify_stable(&doc1(), &r).expect("and so is a reference to it");
    let now = || c.evaluate_def(&r, &[], View::Active, &k.snapshot());
    assert_eq!(now(), Ok(Value::Bool(false)));
    deposit_rel(&k, PRED_STABLE, &x0, &ca(9));
    assert_eq!(now(), Ok(Value::Bool(true)), "a tuple of one cataloged class covers x₀");
}
