//! M9 contract tests over a real kernel (InMemory), group B — predicate
//! definitions as content: store/register/evaluate/supersede/certify/
//! retract, the PR-ENC byte contract as `register_pred` reads it back, the
//! memo's two permanent verdicts and the one it never keeps, and the
//! class-free registration probes beside the guest-class look. Every
//! assertion states a claim the design or interface makes — nothing more.

use crate::common::*;
use crate::terms::*;

use skep_address::{document_of, Address};
use skep_arrangement::{HasM5, InsertError};
use skep_content::HasContent;
use skep_coordination::{
    CertifyError, Coordinator, DefineError, Dom, EvalError, Lit, Nat, RegisterError, RetractError,
    Rule, Sort, Stability, Term, Trigger, TypeError, Value, View, RuleError,
};
use skep_kernel::TxnError;
use skep_links::{Caller, EmitError, NullifyError, Tip};

// ───────────────────────── definitions lifecycle ─────────────────────────

/// define → registered/evaluable; ≤1 active pdef per start (idem⊤ dedup);
/// retraction is reversible, non-cascading, and evaluation keys on
/// EVER-registration.
#[test]
fn a_def_registers_evaluates_retracts_and_re_registers_afresh() {
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

    // ≤1 active pdef per start: a re-register dedups to the incumbent tuple,
    // and a dedup hit commits nothing — M7 answers the incumbent with its
    // base `Seq`.
    let before = k.current_seq();
    let (p1, _) = c.register_pred(&doc1(), &start).expect("re-register (dedup)");
    let (p2, _) = c.register_pred(&doc1(), &start).expect("re-register (dedup)");
    assert_eq!(p1, p2);
    assert_eq!(k.current_seq(), before, "a dedup hit commits nothing");

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

/// `define_predicate` returns the `pdef` EMIT's commit `Seq` — the last of
/// its two transactions, never the insert's.
#[test]
fn define_predicate_returns_the_pdef_emit_s_seq() {
    let k = kernel();
    let c = coord(&k);
    let before = k.current_seq();
    let (_, seq) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("define");
    assert!(seq > before);
    assert_eq!(seq, k.current_seq(), "the pdef emit's commit, after the insert's");
}

/// WT-ref + endorsement: refs to registered defs check and evaluate
/// DAG-recursively; a gap-de-registered referent blocks NEW registrations
/// (endorsement) while existing consumers keep evaluating (no cascade).
#[test]
fn endorsement_gates_a_new_reference_and_retraction_never_cascades() {
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
fn register_pred_refuses_garbage_bytes_an_empty_start_and_an_unregistered_home() {
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

/// The home requirement on the three other def writes is the STORE's door,
/// and it speaks after M9's own gates: M5 refuses `define_predicate` with
/// nothing committed; `certify_stable` reaches M7 only after every static
/// leg; `retract_pred` only after the `NotActive` probe.
#[test]
fn an_unregistered_home_is_refused_by_the_store_after_m9_s_own_gates() {
    let k = kernel();
    let c = coord(&k);
    let unregistered = a(&[1, 0, 1, 0, 7]);
    let term = c.type_check(vec![], tru()).expect("closed True");

    let before = k.current_seq();
    assert!(matches!(
        c.define_predicate(&unregistered, &term),
        Err(DefineError::Insert(TxnError::Rejected(InsertError::DocNotRegistered)))
    ));
    assert_eq!(k.current_seq(), before, "nothing committed");

    let (start, _) = c.define_predicate(&doc1(), &term).expect("define");
    let (nat_def, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], lit_nat(1)).expect("ℕ def"))
        .expect("define");
    // A static leg speaks first…
    assert!(matches!(c.certify_stable(&unregistered, &nat_def), Err(CertifyError::NotBoolean)));
    // …then M7's door.
    assert!(matches!(
        c.certify_stable(&unregistered, &start),
        Err(CertifyError::Emit(TxnError::Rejected(EmitError::HomeNotRegistered)))
    ));
    // The probe speaks first…
    assert!(matches!(c.retract_pred(&unregistered, &ca(99)), Err(RetractError::NotActive)));
    // …then M7's door.
    assert!(matches!(
        c.retract_pred(&unregistered, &start),
        Err(RetractError::Nullify(TxnError::Rejected(NullifyError::HomeNotRegistered)))
    ));
}

/// A def's home is a DRAFT: `define_predicate`'s insert is `Undeclared`, and
/// M5 admits an undeclared insert into a published TARGET at no position, so
/// a published `d` is refused at the store's door with nothing committed —
/// `Caller::System` is exempt from ω and from nothing else. `supersede`
/// writes its successor through `define_predicate`, and inherits it. The LINK
/// deposits do not: a `pdef` emit and its retraction are outside the
/// version-chain rule, and land in the published document.
#[test]
fn define_predicate_refuses_a_published_home_while_the_link_writes_land_there() {
    let k = kernel();
    let c = coord(&k);
    let term = c.type_check(vec![], tru()).expect("closed True");

    let before = k.current_seq();
    assert!(matches!(
        c.define_predicate(&published_doc(), &term),
        Err(DefineError::Insert(TxnError::Rejected(InsertError::PublishedTarget)))
    ));
    assert_eq!(k.current_seq(), before, "nothing committed");

    // A draft home takes the same term …
    let (start, _) = c.define_predicate(&doc1(), &term).expect("define into a draft");
    // … and `supersede` carries the requirement through its successor's insert.
    assert!(matches!(
        c.supersede(&published_doc(), &start, &term),
        Err(DefineError::Insert(TxnError::Rejected(InsertError::PublishedTarget)))
    ));

    // The link path is outside the rule: a def whose content lives in a draft
    // registers — and de-registers — homed in the published document.
    let drafted = insert_raw(&k, &doc1(), forged_negations(1));
    let (tuple, _) = c
        .register_pred(&published_doc(), &drafted)
        .expect("a pdef emit is a link deposit, outside the version-chain rule");
    assert_eq!(document_of(&tuple), Some(published_doc()));
    let (retraction, _) = c.retract_pred(&published_doc(), &drafted).expect("nullify likewise");
    assert_eq!(document_of(&retraction), Some(published_doc()));
}

/// register_pred's gate order at a stored reference: the referent's
/// ever-registration is asked BEFORE WT-ref, so a stored body naming an
/// address nothing was ever registered at is `ReferentNotEverRegistered`,
/// not `IllTyped(DanglingReference)`. The rejection leaves orphan content —
/// never registered, never poisoned — which a later `register_pred` adopts
/// once the referent exists. The stored bytes are PR-ENC's, so the
/// reference is retargeted by rewriting the referent's last component.
#[test]
fn register_pred_refuses_a_stored_referent_that_was_never_registered_before_checking_types() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("P"))
        .expect("define P");
    let (q, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], Term::Ref { addr: p.clone(), args: vec![] }).expect("Q := P"))
        .expect("define Q");
    assert_eq!((p, q.clone()), (ca(1), ca(2)));

    let mut bytes = k
        .snapshot()
        .world()
        .content()
        .value_at(q.tumbler())
        .expect("Q is resident")
        .as_bytes()
        .to_vec();
    let end = bytes.len();
    assert_eq!(&bytes[end - 2..], &[1, 0], "PR-ENC: the referent's last component, then the argument count");
    bytes[end - 2] = 4; // the reference now names ca4 — nothing is there
    let forged = insert_raw(&k, &doc1(), bytes);
    assert_eq!(forged, ca(3));
    match c.register_pred(&doc1(), &forged) {
        Err(RegisterError::ReferentNotEverRegistered(x)) => assert_eq!(x, ca(4)),
        other => panic!("expected ReferentNotEverRegistered(ca4) ahead of WT-ref, got {other:?}"),
    }
    assert!(!c.is_ever_pred(&forged, &k.snapshot()));
    assert!(c.signature(&forged).is_none());

    let (r, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("R"))
        .expect("define R");
    assert_eq!(r, ca(4));
    c.register_pred(&doc1(), &forged).expect("the orphan content is adopted");
    assert_eq!(c.evaluate_def(&forged, &[], View::Active, &k.snapshot()), Ok(Value::Bool(true)));
}

/// Stored content that parses and fails WT is `IllTyped`, carrying the
/// checker's own rejection: a parameter's sort tag rewritten from `Addr`
/// to `Nat` under a body that compares it as an address.
#[test]
fn register_pred_refuses_stored_content_that_parses_but_fails_wt() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(
            &doc1(),
            &c.type_check(vec![(v(1), Sort::Addr)], addr_eq(var(1), var(1))).expect("x = x"),
        )
        .expect("define");
    let mut bytes = k
        .snapshot()
        .world()
        .content()
        .value_at(p.tumbler())
        .expect("resident")
        .as_bytes()
        .to_vec();
    // Envelope length · parameter count · the parameter's name · its sort.
    assert_eq!(&bytes[1..4], &[1, 1, 2], "PR-ENC: one parameter, named 1, sorted Addr");
    bytes[3] = 7; // Nat
    let forged = insert_raw(&k, &doc1(), bytes);
    assert!(matches!(
        c.register_pred(&doc1(), &forged),
        Err(RegisterError::IllTyped(TypeError::SortMismatch { expected: Sort::Addr, found: Sort::Nat }))
    ));
    assert!(c.signature(&forged).is_none(), "orphan content, never registered");
}

/// PR-ENC's minimal-form LEB128, the one length/count encoding the format
/// uses.
fn varint(mut x: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let limb = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            out.push(limb);
            return out;
        }
        out.push(limb | 0x80);
    }
}

/// PR-ENC's envelope around a payload: the minimal varint length, then the
/// bytes.
fn envelope(payload: Vec<u8>) -> Vec<u8> {
    let mut out = varint(payload.len() as u64);
    out.extend(payload);
    out
}

/// A hand-forged closed body `¬^depth ⊤` in PR-ENC (`¬` is one tag per
/// level over the closed `True`, which the codec's own suite pins).
fn forged_negations(depth: usize) -> Vec<u8> {
    let mut payload = vec![0u8]; // no parameters
    payload.extend(std::iter::repeat_n(7u8, depth)); // NOT, per level
    payload.extend([2u8, 1]); // LIT, TRUE
    envelope(payload)
}

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
/// default thread: this test is the measurement the derivation's level
/// cost is set against.
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

/// The expansion budget: `Pᵢ(x) := Pᵢ₋₁(x) ∧ Pᵢ₋₁(x)` is a few nodes per
/// def and registers at every level (its reach grows four per level), while
/// its flat expansion doubles per level — `P₈` certifies, `P₁₆` is
/// `ExpansionTooLarge` before its 2¹⁶ copies of `P₀` exist, and a `Def`
/// trigger over it is refused at the door `certify_rule` and `armer_cycles`
/// stand behind.
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
        domain: Dom::MembersDom(conc(&pred_stable_ty())),
        trigger: Trigger::Def(p.clone()),
        view: View::Audit,
        action: marker_action(),
    };
    assert!(matches!(c.certify_rule(&rule), Err(RuleError::TriggerExpansionTooLarge)));
    assert!(matches!(c.register_rule(rule), Err(RuleError::TriggerExpansionTooLarge)));
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

/// `evaluate_def`'s argument door on a set: an `AddrSet` holding a tumbler
/// that is no T4-valid address (adjacent separators) is `ArgSortMismatch`,
/// where one holding an address is bound and counted.
#[test]
fn evaluate_def_refuses_a_set_argument_holding_a_non_address() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(
            &doc1(),
            &c.type_check(
                vec![(v(1), Sort::AddrSet)],
                nat_eq(count(Dom::SetTerm(at(var(1)))), lit_nat(1)),
            )
            .expect("|s| = 1"),
        )
        .expect("define");
    let s = k.snapshot();
    let bad = Value::AddrSet(im::OrdSet::unit(t(&[1, 0, 0, 1])));
    assert_eq!(c.evaluate_def(&p, &[bad], View::Active, &s), Err(EvalError::ArgSortMismatch));
    let good = Value::AddrSet(im::OrdSet::unit(ca(1).tumbler().clone()));
    assert_eq!(c.evaluate_def(&p, &[good], View::Active, &s), Ok(Value::Bool(true)));
}

/// PR-DISC's freeze-on-breach: a `pdef` on content that is no def —
/// registered past `register_pred`'s gate, through M7 directly — is
/// EVER-registered, so the registration probes answer yes, and every
/// question that needs the def's signature answers with the breach:
/// `UndisciplinedDef` on the evaluation and the certification side alike
/// (never `NotEverRegistered` — the two `None` causes stay distinct), no
/// signature, a dangling reference, a dangling `Def` trigger, and the
/// gate's own `ParseFailed`.
#[test]
fn a_breach_freezes_the_start_poisoned() {
    let k = kernel();
    let mut c = coord(&k);
    let g = insert_raw(&k, &doc1(), vec![0xff, 0x01, 0x02]);
    link_writer(&k)
        .emit(Caller::System, &doc1(), &pred_def_ty(), &g, &[])
        .expect("the breach: a pdef past the gate");
    let s = k.snapshot();
    assert!(c.is_ever_pred(&g, &s));
    assert!(c.is_active_pred(&g, &s));
    assert_eq!(c.evaluate_def(&g, &[], View::Active, &s), Err(EvalError::UndisciplinedDef));
    assert!(matches!(c.certify_stable(&doc1(), &g), Err(CertifyError::UndisciplinedDef)));
    assert!(c.signature(&g).is_none());
    assert!(matches!(
        c.type_check(vec![], Term::Ref { addr: g.clone(), args: vec![] }),
        Err(TypeError::DanglingReference(x)) if x == g
    ));
    assert!(matches!(
        c.register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: Trigger::Def(g.clone()),
            view: View::Audit,
            action: marker_action(),
        }),
        Err(RuleError::DanglingDefTrigger(x)) if x == g
    ));
    assert!(matches!(c.register_pred(&doc1(), &g), Err(RegisterError::ParseFailed)));
}

/// A never-registered start is never memoized: every probe made before the
/// definition — signature, evaluation, WT-ref, a `Def` trigger — answers
/// "no such def", and the same probes answer yes once the definition lands
/// at that start.
#[test]
fn a_probe_before_registration_does_not_freeze_the_start() {
    let k = kernel();
    let mut c = coord(&k);
    let start = ca(1);
    let def_rule = |c: &mut Coordinator<World>| {
        c.register_rule(Rule {
            domain: Dom::MembersDom(conc(&pred_stable_ty())),
            trigger: Trigger::Def(start.clone()),
            view: View::Audit,
            action: marker_action(),
        })
    };
    let reference = || Term::Ref { addr: start.clone(), args: vec![at(lit_addr(&ca(2)))] };

    assert!(c.signature(&start).is_none());
    assert_eq!(
        c.evaluate_def(&start, &[Value::Addr(ca(2))], View::Active, &k.snapshot()),
        Err(EvalError::NotEverRegistered)
    );
    assert!(matches!(c.type_check(vec![], reference()), Err(TypeError::DanglingReference(_))));
    assert!(matches!(def_rule(&mut c), Err(RuleError::DanglingDefTrigger(_))));

    let (defined, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("P(x)"))
        .expect("define");
    assert_eq!(defined, start);
    assert_eq!(c.signature(&start).map(|s| s.result), Some(Sort::Bool));
    assert_eq!(
        c.evaluate_def(&start, &[Value::Addr(ca(2))], View::Active, &k.snapshot()),
        Ok(Value::Bool(true))
    );
    assert!(c.type_check(vec![], reference()).is_ok());
    def_rule(&mut c).expect("a Def trigger over the now-defined start");
}

/// The def-registration probes are class-free by design, and the
/// evaluator's look is not: a def registered into a document the guest
/// predicate refuses is ever-registered, active, signed and evaluable —
/// and invisible to `is_K(pdef, ·)` at every view.
#[test]
fn def_probes_are_class_free_while_the_evaluator_s_look_is_not() {
    let k = kernel();
    let c = coord_with_guest(&k, Box::new(|_: &World, d: &Address| *d != doc2()));
    let (start, _) = c
        .define_predicate(&doc2(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("a def registered into the draft");
    let s = k.snapshot();
    assert!(c.is_ever_pred(&start, &s));
    assert!(c.is_active_pred(&start, &s));
    assert!(c.signature(&start).is_some());
    assert_eq!(c.evaluate_def(&start, &[], View::Active, &s), Ok(Value::Bool(true)));
    for view in [View::Active, View::Audit, View::Default] {
        assert!(!decide_now(&k, &c, view, is_k(&pred_def_ty(), lit_addr(&start))), "{view:?}");
    }
}

/// ≤1 active `pdef` per start (PR0) holds WITHIN the guest class the writer
/// runs at (lane 3.3b): a pdef homed where the guest predicate refuses is
/// invisible to M7's idempotency lookup, so a second registration mints a
/// fresh tuple beside it — and `is_active_pred`, which reads class-free,
/// stays true until each of the two is retracted, one per call.
#[test]
fn a_pdef_hidden_from_the_guest_class_does_not_absorb_a_second_registration() {
    let k = kernel();
    let c = coord_with_guest(&k, Box::new(|_: &World, d: &Address| *d != doc2()));
    let term = c.type_check(vec![], tru()).expect("closed True");
    let (start, _) = c.define_predicate(&doc2(), &term).expect("define into the draft");

    let (fresh, _) = c.register_pred(&doc1(), &start).expect("register again, visibly");
    assert_eq!(
        document_of(&fresh),
        Some(doc1()),
        "a fresh deposit — the draft's incumbent is invisible to the dedup"
    );
    let (again, _) = c.register_pred(&doc1(), &start).expect("now it dedups");
    assert_eq!(again, fresh, "the VISIBLE incumbent absorbs the third");

    assert!(c.is_active_pred(&start, &k.snapshot()));
    c.retract_pred(&doc1(), &start).expect("one active pdef retracted");
    assert!(c.is_active_pred(&start, &k.snapshot()), "the twin is still active");
    c.retract_pred(&doc1(), &start).expect("the twin retracted");
    assert!(!c.is_active_pred(&start, &k.snapshot()));

    // The control: where the guest class hides nothing, the doc2 incumbent is
    // visible to the lookup and absorbs the second registration — one active
    // pdef per start, and one retraction clears it.
    let k = kernel();
    let c = coord(&k);
    let term = c.type_check(vec![], tru()).expect("closed True");
    let (start, _) = c.define_predicate(&doc2(), &term).expect("define");
    let (hit, _) = c.register_pred(&doc1(), &start).expect("register again");
    assert_eq!(document_of(&hit), Some(doc2()), "the incumbent, wherever it is homed");
    c.retract_pred(&doc1(), &start).expect("the one pdef retracted");
    assert!(!c.is_active_pred(&start, &k.snapshot()));
}

/// A def's Γ_D is an ORDERED context: it survives the codec round trip, a
/// cold coordinator reports it in order, and `evaluate_def` binds
/// positionally — so two same-sorted parameters are not interchangeable.
#[test]
fn a_def_s_parameters_are_ordered_and_arguments_bind_positionally() {
    let k = kernel();
    let c = coord(&k);
    let tt = c
        .type_check(
            vec![(v(1), Sort::Addr), (v(2), Sort::Addr)],
            and(addr_eq(var(1), lit_addr(&ca(1))), addr_eq(var(2), lit_addr(&ca(2)))),
        )
        .expect("P(x, y) := x = ca1 ∧ y = ca2");
    let (start, _) = c.define_predicate(&doc1(), &tt).expect("define");
    let cold = coord(&k); // re-derives Γ_D from the stored bytes
    assert_eq!(
        cold.signature(&start).expect("defined").params,
        vec![(v(1), Sort::Addr), (v(2), Sort::Addr)]
    );
    let s = k.snapshot();
    let ordered = [Value::Addr(ca(1)), Value::Addr(ca(2))];
    let swapped = [Value::Addr(ca(2)), Value::Addr(ca(1))];
    assert_eq!(cold.evaluate_def(&start, &ordered, View::Active, &s), Ok(Value::Bool(true)));
    assert_eq!(cold.evaluate_def(&start, &swapped, View::Active, &s), Ok(Value::Bool(false)));
}

/// PC2's binder guard narrows `ℕ∪{⊥} → ℕ` in the then-branch — the one
/// optional-narrowing branch reachable in this format, an `OptNat` parameter
/// being its only source.
#[test]
fn an_opt_nat_argument_narrows_through_the_binder_guard() {
    let k = kernel();
    let c = coord(&k);
    let tt = c
        .type_check(
            vec![(v(1), Sort::OptNat)],
            if_some(var(1), 2, nat_le(var(2), lit_nat(3)), fls()),
        )
        .expect("P(o) := if some n = o then n ≤ 3 else ⊥");
    let (start, _) = c.define_predicate(&doc1(), &tt).expect("define");
    let s = k.snapshot();
    let at_arg = |val: Value| c.evaluate_def(&start, &[val], View::Active, &s);
    assert_eq!(at_arg(Value::OptNat(Some(n(2)))), Ok(Value::Bool(true)));
    assert_eq!(at_arg(Value::OptNat(Some(n(5)))), Ok(Value::Bool(false)));
    assert_eq!(at_arg(Value::OptNat(None)), Ok(Value::Bool(false)));
    assert_eq!(at_arg(Value::Nat(n(2))), Err(EvalError::ArgSortMismatch));
}

/// supersede's up-front gates, `current_version` over the shipped class, and
/// the M7 supersession-fence drift tripwire (see the report: as-built M7
/// rejects a raw `[K_sup]`-typed `emit`, so the design's def-lineage claim
/// cannot commit — the first two of the three non-atomic transactions do).
#[test]
fn supersede_gates_up_front_and_trips_m7_s_supersession_fence() {
    let k = kernel();
    let c = coord(&k);

    // Gated before any transaction: nothing is inserted.
    let untouched = k.snapshot().world().m5().content_count(&doc1());
    assert!(matches!(
        c.supersede(&doc1(), &ca(50), &c.type_check(vec![], tru()).expect("term")),
        Err(DefineError::OldStartNotEverRegistered(_))
    ));
    assert_eq!(k.snapshot().world().m5().content_count(&doc1()), untouched);

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
    let (s0, _) = define(exists(1, Dom::AuditSlice(conc(&pred_def_ty())), tru()));
    let (cert, _) = c.certify_stable(&doc1(), &s0).expect("certify");
    assert!(c.is_certified_stable(&s0, &k.snapshot()));
    let before = k.current_seq();
    assert_eq!(c.certify_stable(&doc1(), &s0).expect("re-certify").0, cert);
    assert_eq!(k.current_seq(), before, "re-certification dedups and commits nothing");

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
    assert!(matches!(c.certify_stable(&doc1(), &rn), Err(CertifyError::NotStable)));
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

    // (0)/(ii) ordering: a retracted def is NotActive — and retraction does
    // not cascade to the certificate, which is about the immutable content.
    c.retract_pred(&doc1(), &s0).expect("retract");
    assert!(matches!(c.certify_stable(&doc1(), &s0), Err(CertifyError::NotActive)));
    assert!(c.is_certified_stable(&s0, &k.snapshot()));
    assert!(!c.is_active_pred(&s0, &k.snapshot()));
}
