//! Certification (`certify_stable`): CVALID's legs in their order, ST⁺
//! decided over the flat expansion through references, and the state-reading
//! atoms that pass PR-VIEW and leave ST⁺ the only guard.

use crate::common::*;
use crate::terms::*;

use skep_address::Address;
use skep_coordination::{CertifyError, Dom, Lit, Sort, Stability, Term, Value, View};
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
/// that matters: `is_filtered` and `is_in_chain` read FIXED active slices, so
/// each can go true → false — the history below makes each do so after its
/// refusal — and each def is `StabilityUnproven`; `is_doc` reads residence,
/// which is permanent, and the same gate certifies it. An analyzer arm that
/// called either of the first two ⊤-stable would stamp a permanent
/// `pd_stable` claim on a def this history falsifies.
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

    let resident = define(is_doc(lit_addr(&doc1())));
    c.certify_stable(&doc1(), &resident)
        .expect("residence is permanent: ⊤-stable and view-independent");
}
