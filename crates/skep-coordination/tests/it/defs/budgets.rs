//! The resource doors on the stored-bytes path, each at its boundary: the
//! nesting cap, counted through references; the node budget; and the
//! expansion budget.

use crate::common::*;
use crate::defs::{envelope, forged_negations, varint};
use crate::terms::*;

use skep_address::Address;
use skep_coordination::{
    CertifyError, Dom, Lit, Nat, RegisterError, Rule, RuleError, Sort, Term, Trigger, TypeError,
    Value, View,
};

/// The nesting cap defends, and is counted through references: a
/// hand-forged body one former past it is `ParseFailed`, and one exactly at
/// it registers and then survives every walk a stored body drives — the
/// parse and check of a fresh memo, the evaluation, the certification's
/// expansion and analysis — on this default test thread, whose stack is the
/// budget the cap is set against. A body at the cap has no room for a
/// reference to it (`TooDeep`: the reference would derive it deeper than the
/// cap admits); the deepest body a reference can reach is the cap less the
/// derivation's own levels, and every walk THROUGH a reference to it — a
/// cold derivation, the evaluation, the expansion — survives too.
#[test]
fn a_hand_forged_body_at_the_decode_cap_survives_every_walk() {
    const CAP: usize = 128;
    const DERIVATION: usize = 2;
    let k = kernel();
    let c = coord(&k);
    let past = insert_raw(&k, &doc1(), forged_negations(CAP + 1));
    assert!(matches!(c.register_pred(&doc1(), &past), Err(RegisterError::ParseFailed)));
    let start = insert_raw(&k, &doc1(), forged_negations(CAP));
    c.register_pred(&doc1(), &start).expect("a body at the cap registers");

    // A fresh memo: parse + check + evaluate. `¬^128 True` is `True`.
    let fresh = coord(&k);
    assert_eq!(fresh.evaluate_def(&start, &[], View::Active, &k.snapshot()), Ok(Value::Bool(true)));
    fresh.certify_stable(&doc1(), &start).expect("expand + analyze at the cap");
    assert!(matches!(
        fresh.type_check(vec![], Term::Ref { addr: start.clone(), args: vec![] }),
        Err(TypeError::TooDeep)
    ));

    // The deepest referenceable body, and the walks through a reference.
    let reachable = insert_raw(&k, &doc1(), forged_negations(CAP - DERIVATION));
    fresh.register_pred(&doc1(), &reachable).expect("a body the derivation's levels below the cap");
    let through = fresh
        .type_check(vec![], Term::Ref { addr: reachable.clone(), args: vec![] })
        .expect("a reference to it");
    let (r, _) = fresh.define_predicate(&doc1(), &through).expect("define the reference");
    fresh.certify_stable(&doc1(), &r).expect("expand through the reference at the cap");
    let one_deeper = insert_raw(&k, &doc1(), forged_negations(CAP - DERIVATION + 1));
    fresh.register_pred(&doc1(), &one_deeper).expect("registers on its own");
    assert!(matches!(
        fresh.type_check(vec![], Term::Ref { addr: one_deeper, args: vec![] }),
        Err(TypeError::TooDeep)
    ));
    let cold = coord(&k);
    assert_eq!(cold.evaluate_def(&r, &[], View::Active, &k.snapshot()), Ok(Value::Bool(true)));
    assert_eq!(cold.signature(&r).map(|s| s.result), Some(Sort::Bool));
}

/// A refused reference judges the referring term, never its referent: on a
/// coordinator whose first contact with a registered def is a `Ref` too deep
/// to reach it, the term is `TooDeep` — as on a warm memo — and the def stays
/// defined: its signature answers, it evaluates, and a reference one level
/// shallower checks on that same coordinator. Through two levels likewise: a
/// registered consumer of the def, reached by a `Ref` too deep for its own
/// reach, leaves both itself and the def defined.
#[test]
fn a_refused_reference_leaves_its_referent_defined_on_a_cold_memo() {
    let k = kernel();
    let c = coord(&k);
    // P := ¬¹⁰⁰ ⊤, reach 100; Q := P, reach 102 (the derivation's two levels).
    let p = insert_raw(&k, &doc1(), forged_negations(100));
    c.register_pred(&doc1(), &p).expect("¬¹⁰⁰ ⊤ registers");
    let (q, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], Term::Ref { addr: p.clone(), args: vec![] }).expect("Q := P"))
        .expect("define Q");
    let under = |start: &Address, negations: usize| {
        (0..negations).fold(Term::Ref { addr: start.clone(), args: vec![] }, |t, _| not(t))
    };

    // The reference sits at level 27, the derivation starts at 29, and P's
    // literal would land at 129. Still cold afterwards, the reference one
    // level shallower derives P at 28 — the cap exactly — and P is defined.
    let cold = coord(&k);
    assert!(matches!(cold.type_check(vec![], under(&p, 27)), Err(TypeError::TooDeep)));
    cold.type_check(vec![], under(&p, 26)).expect("26 + 2 + 100 = 128: at the cap");
    assert_eq!(cold.signature(&p).map(|s| s.result), Some(Sort::Bool));
    assert_eq!(cold.evaluate_def(&p, &[], View::Active, &k.snapshot()), Ok(Value::Bool(true)));
    assert!(matches!(c.type_check(vec![], under(&p, 27)), Err(TypeError::TooDeep)), "the warm memo agrees");

    // Two levels: Q at 25 asks for P at 29 through Q's own derivation at 27.
    let cold = coord(&k);
    assert!(matches!(cold.type_check(vec![], under(&q, 25)), Err(TypeError::TooDeep)));
    cold.type_check(vec![], under(&q, 24)).expect("24 + 2 + 102 = 128: at the cap");
    assert_eq!(cold.signature(&q).map(|s| s.result), Some(Sort::Bool));
    assert_eq!(cold.signature(&p).map(|s| s.result), Some(Sort::Bool));
    assert_eq!(cold.evaluate_def(&q, &[], View::Active, &k.snapshot()), Ok(Value::Bool(true)));
}

/// The node budget on the stored-bytes path: ten nested `Reg` quantifiers
/// over a leaf — thirty-three bytes of PR-ENC — would instantiate 5¹⁰
/// bodies, and are `IllTyped(TooLarge)` at the budget instead. The bytes
/// are a corpus seed for a def-codec fuzz target.
#[test]
fn register_pred_refuses_a_stored_reg_expansion_past_the_node_budget() {
    let k = kernel();
    let c = coord(&k);
    let mut payload = vec![0u8]; // no parameters
    for var in 1..=10u8 {
        payload.extend([10u8, var, 5]); // FORALL, the binder, REG
    }
    payload.extend([2u8, 1]); // LIT, TRUE
    let forged = insert_raw(&k, &doc1(), envelope(payload));
    assert!(matches!(
        c.register_pred(&doc1(), &forged),
        Err(RegisterError::IllTyped(TypeError::TooLarge))
    ));
    assert!(c.signature(&forged).is_none(), "orphan content, never registered");
}

/// The stored-bytes path charges a literal's payload too, so the budget
/// bounds what a run of hostile bytes can command rather than what it spells:
/// ONE `Reg` quantifier over a 64 KB natural — nine formers, and a `Val` the
/// decoder accepts — instantiates that natural once per cataloged class, and
/// is `IllTyped(TooLarge)` at the budget. The bytes are a corpus seed for a
/// def-codec fuzz target.
#[test]
fn register_pred_refuses_a_stored_literal_that_multiplies_past_the_node_budget() {
    let k = kernel();
    let c = coord(&k);
    let limbs = 1u64 << 13; // 8192 limbs — a fraction of the budget on its own
    let mut payload = vec![0u8]; // no parameters
    payload.extend([10u8, 1, 5]); // FORALL, the binder, REG
    payload.extend([4u8, 8]); // PRIM, NAT_EQ
    payload.extend([2u8, 3]); // LIT, NAT
    payload.extend(varint(limbs * 8));
    payload.extend(std::iter::repeat_n(1u8, (limbs * 8) as usize));
    payload.extend([2u8, 3, 1, 1]); // LIT, NAT, one byte, the numeral 1
    let forged = insert_raw(&k, &doc1(), envelope(payload));
    assert!(matches!(
        c.register_pred(&doc1(), &forged),
        Err(RegisterError::IllTyped(TypeError::TooLarge))
    ));
    assert!(c.signature(&forged).is_none(), "orphan content, never registered");
}

/// A reference chain is bounded at registration, not discovered at a cold
/// derivation: `P₀(x) := ⊤`, `Pᵢ(x) := Pᵢ₋₁(x)` registers while its reach —
/// three levels per link: the reference's derivation and its one argument —
/// fits the cap, and the first link past it is `IllTyped(TooDeep)`. The
/// chain at the cap then derives COLD on a fresh coordinator — every link
/// parsed and checked one derivation inside the last — evaluates through
/// every link, and expands and analyzes through every link, on this
/// default thread: this test and its argument-free twin below, the deeper of
/// the two, are the measurements the derivation's level cost is set against.
#[test]
fn a_reference_chain_at_the_cap_derives_cold_and_one_deeper_is_refused() {
    let k = kernel();
    let c = coord(&k);
    let (mut top, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("P₀"))
        .expect("define P₀");
    let mut links = 0u32;
    loop {
        let next = Term::Ref { addr: top.clone(), args: vec![at(var(1))] };
        match c.type_check(vec![(v(1), Sort::Addr)], next) {
            Ok(tt) => {
                top = c.define_predicate(&doc1(), &tt).expect("define the next link").0;
                links += 1;
            }
            Err(TypeError::TooDeep) => break,
            Err(other) => panic!("expected TooDeep at the cap, got {other:?}"),
        }
    }
    assert_eq!(links, 42, "three levels per link, over a cap of 128");

    let fresh = coord(&k);
    assert_eq!(fresh.signature(&top).map(|s| s.result), Some(Sort::Bool));
    assert_eq!(
        fresh.evaluate_def(&top, &[Value::Addr(ca(1))], View::Active, &k.snapshot()),
        Ok(Value::Bool(true))
    );
    fresh.certify_stable(&doc1(), &top).expect("expand and analyze through every link");
}

/// The derivation's level cost measured at its WORST case: references with no
/// arguments spend every level they are charged on derivations — two per
/// link, where the one-argument chain above spends one of its three on an
/// argument that never nests — so the chain reaches the cap in 64 links and
/// derives 65 deep on a cold memo, against that chain's 43. It registers to
/// the cap and no further, then derives cold, evaluates and certifies through
/// every link on this default thread.
#[test]
fn an_argument_free_reference_chain_at_the_cap_derives_cold() {
    let k = kernel();
    let c = coord(&k);
    let (mut top, _) =
        c.define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("P₀")).expect("define P₀");
    let mut links = 0u32;
    loop {
        match c.type_check(vec![], Term::Ref { addr: top.clone(), args: vec![] }) {
            Ok(tt) => {
                top = c.define_predicate(&doc1(), &tt).expect("define the next link").0;
                links += 1;
            }
            Err(TypeError::TooDeep) => break,
            Err(other) => panic!("expected TooDeep at the cap, got {other:?}"),
        }
    }
    assert_eq!(links, 64, "two levels per link, over a cap of 128");
    let fresh = coord(&k);
    assert_eq!(fresh.signature(&top).map(|s| s.result), Some(Sort::Bool));
    assert_eq!(fresh.evaluate_def(&top, &[], View::Active, &k.snapshot()), Ok(Value::Bool(true)));
    fresh.certify_stable(&doc1(), &top).expect("expand and analyze through every link");
}

/// The expansion budget: `Pᵢ(x) := Pᵢ₋₁(x) ∧ Pᵢ₋₁(x)` is a few nodes per
/// def and registers at every level (its reach grows four per level), while
/// its flat expansion doubles per level — `P₈` certifies, `P₁₆` is
/// `ExpansionTooLarge` before its 2¹⁶ copies of `P₀` exist, and a `Def`
/// trigger over it is refused at the door `certify_rule` and `armer_cycles`
/// stand behind. Retracted, `P₁₆` is `NotActive` instead: the activity leg
/// speaks before the expansion is built.
#[test]
fn certify_stable_refuses_an_expansion_past_the_node_budget() {
    let k = kernel();
    let mut c = coord(&k);
    let (mut p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("P₀"))
        .expect("define P₀");
    let mut p8 = None;
    for i in 1..=16 {
        let twice = and(
            Term::Ref { addr: p.clone(), args: vec![at(var(1))] },
            Term::Ref { addr: p.clone(), args: vec![at(var(1))] },
        );
        let tt = c.type_check(vec![(v(1), Sort::Addr)], twice).expect("Pᵢ");
        p = c.define_predicate(&doc1(), &tt).expect("define Pᵢ").0;
        if i == 8 {
            p8 = Some(p.clone());
        }
    }
    let p8 = p8.expect("P₈ was defined");
    c.certify_stable(&doc1(), &p8).expect("P₈'s expansion fits the budget");
    assert!(matches!(c.certify_stable(&doc1(), &p), Err(CertifyError::ExpansionTooLarge)));
    let rule = Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: Trigger::Def(p.clone()),
        view: View::Audit,
        action: marker_action(),
    };
    assert!(matches!(c.certify_rule(&rule), Err(RuleError::TriggerExpansionTooLarge)));
    assert!(matches!(c.register_rule(rule), Err(RuleError::TriggerExpansionTooLarge)));
    c.retract_pred(&doc1(), &p).expect("retract P₁₆");
    assert!(
        matches!(c.certify_stable(&doc1(), &p), Err(CertifyError::NotActive)),
        "endorsement before the expansion"
    );
}

/// The expansion budget is charged in payload too, because PR3's fresh-name
/// discipline forbids sharing: a referent holding an 8 KB natural is copied
/// WHOLE into every unfolding, so a doubling chain over it multiplies bytes
/// where the node count says it multiplies leaves. One level of doubling
/// certifies; five is `ExpansionTooLarge`, though every def in the chain is a
/// handful of formers and registers.
#[test]
fn certify_stable_charges_a_referent_s_payload_against_the_expansion_budget() {
    let k = kernel();
    let c = coord(&k);
    let big = || Term::Lit(Lit::Nat(Nat::from_bytes_be(&vec![1u8; 1 << 13]))); // 2¹⁰ limbs
    let (mut p, _) = c
        .define_predicate(
            &doc1(),
            &c.type_check(vec![(v(1), Sort::Addr)], nat_eq(big(), big())).expect("P₀"),
        )
        .expect("define P₀");
    let mut p1 = None;
    for i in 1..=5 {
        let twice = and(
            Term::Ref { addr: p.clone(), args: vec![at(var(1))] },
            Term::Ref { addr: p.clone(), args: vec![at(var(1))] },
        );
        let tt = c.type_check(vec![(v(1), Sort::Addr)], twice).expect("Pᵢ");
        p = c.define_predicate(&doc1(), &tt).expect("define Pᵢ").0;
        if i == 1 {
            p1 = Some(p.clone());
        }
    }
    let p1 = p1.expect("P₁ was defined");
    c.certify_stable(&doc1(), &p1).expect("two copies of the referent fit the budget");
    assert!(matches!(c.certify_stable(&doc1(), &p), Err(CertifyError::ExpansionTooLarge)));
}
