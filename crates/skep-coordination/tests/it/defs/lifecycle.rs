//! A def's life through the writes: define, register (and its idem⊤ dedup),
//! retract, re-register and supersede — what each returns, and that a
//! retraction never cascades.

use crate::common::*;
use crate::terms::*;

use skep_arrangement::HasM5;
use skep_coordination::{
    DefineError, EvalError, Lit, RegisterError, RetractError, Sort, SupersedeError, Term, Value,
    View,
};
use skep_kernel::TxnError;
use skep_links::{enc, EmitError, HasLinks, Tip, Tuple};

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
    let (incumbent, _) = c.register_pred(&doc1(), &start).expect("re-register (dedup)");
    let (again, _) = c.register_pred(&doc1(), &start).expect("re-register (dedup)");
    assert_eq!(incumbent, again);
    assert_eq!(k.current_seq(), before, "a dedup hit commits nothing");

    // A parameterized def: positional Γ_D binding with arity/sort guards.
    let tt = c
        .type_check(vec![(v(1), Sort::Addr)], addr_eq(var(1), lit_addr(&ca(1))))
        .expect("param def");
    let (param_def, _) = c.define_predicate(&doc1(), &tt).expect("define param def");
    let s2 = k.snapshot();
    assert_eq!(
        c.evaluate_def(&param_def, &[Value::Addr(ca(1))], View::Active, &s2),
        Ok(Value::Bool(true))
    );
    assert_eq!(
        c.evaluate_def(&param_def, &[Value::Addr(ca(2))], View::Active, &s2),
        Ok(Value::Bool(false))
    );
    assert_eq!(
        c.evaluate_def(&param_def, &[], View::Active, &s2),
        Err(EvalError::ArgArityMismatch)
    );
    assert_eq!(
        c.evaluate_def(&param_def, &[Value::Nat(n(1))], View::Active, &s2),
        Err(EvalError::ArgSortMismatch)
    );
    // A tuple is no Γ_D value: its sort, `Tup`, matches no stored parameter.
    let tuple = Tuple { addr: la(1), from: enc(&[ca(1)]), to: enc(&[ca(2)]) };
    assert_eq!(
        c.evaluate_def(&param_def, &[Value::Tuple(tuple)], View::Active, &s2),
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
    let (fresh, _) = c.register_pred(&doc1(), &start).expect("resurrect");
    assert_ne!(fresh, incumbent);
}

/// `retract_pred` returns the `[R]` TUPLE it deposited — never the `pdef` it
/// nullified — so a driver reconciling a retraction against M7's journal
/// follows the right link. Both are homed in the retracting document, so only
/// the slots tell them apart: the retraction's F denotes that home and its G
/// the tuple it nullified.
#[test]
fn retract_pred_returns_the_retraction_never_the_pdef_it_nullified() {
    let k = kernel();
    let c = coord(&k);
    let (start, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("define");
    // A re-registration dedups to the incumbent, which IS the active pdef.
    let (pdef, _) = c.register_pred(&doc1(), &start).expect("dedup to the incumbent");
    let (retraction, _) = c.retract_pred(&doc1(), &start).expect("retract");
    assert_ne!(retraction, pdef);
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_nullified(&pdef), "the pdef is what was nullified");
    let r = links.readlink(&retraction).expect("the returned address is a resident link");
    assert_eq!(r.type_slot(), &retraction_ty());
    assert_eq!(r.from_slot().single_denoted(), Some(doc1().tumbler()));
    assert_eq!(r.to_slot().single_denoted(), Some(pdef.tumbler()));
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

    // The argument reaches the referent and the referent's verdict comes back:
    // the same reference at a different argument denotes false.
    let q_false = c
        .type_check(vec![], Term::Ref { addr: p_start.clone(), args: vec![at(lit_addr(&ca(2)))] })
        .expect("Q' references P at ca2");
    let (q_false_start, _) = c.define_predicate(&doc1(), &q_false).expect("define Q'");
    assert_eq!(
        c.evaluate_def(&q_false_start, &[], View::Active, &k.snapshot()),
        Ok(Value::Bool(false))
    );

    // Endorsement gates NEW registration…
    c.retract_pred(&doc1(), &p_start).expect("retract P");
    let r = c
        .type_check(vec![], Term::Ref { addr: p_start.clone(), args: vec![at(lit_addr(&ca(2)))] })
        .expect("type_check keys on ever-registration, so a retracted referent still checks");
    match c.define_predicate(&doc1(), &r) {
        Err(DefineError::Register(RegisterError::ReferentNotActive(x))) => assert_eq!(x, p_start),
        other => panic!("expected ReferentNotActive, got {other:?}"),
    }
    // …while the standing consumer keeps evaluating: its reference to P
    // dangles but stays live (ASN-0130 OQ3).
    let s2 = k.snapshot();
    assert_eq!(c.evaluate_def(&q_start, &[], View::Active, &s2), Ok(Value::Bool(true)));
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
        Err(SupersedeError::OldStartNotEverRegistered(_))
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
        Err(SupersedeError::Lineage(TxnError::Rejected(EmitError::SupersessionClass))) => {}
        other => panic!("fence drift resolved? got {other:?}"),
    }
    assert_eq!(
        k.snapshot().world().m5().content_count(&doc1()),
        before + n(1) // the successor def's content committed
    );
}

/// `supersede`'s up-front gate is EVER-registration, not endorsement:
/// superseding a RETRACTED def is legitimate lineage (PR4). The gate passes
/// and the successor's definition commits; the lineage claim then meets
/// whatever M7 answers — as built, its supersession fence, which the
/// tripwire above pins — and these assertions hold either way.
#[test]
fn supersede_admits_a_retracted_old_start() {
    let k = kernel();
    let c = coord(&k);
    let term = c.type_check(vec![], tru()).expect("closed True");
    let (old, _) = c.define_predicate(&doc1(), &term).expect("define");
    c.retract_pred(&doc1(), &old).expect("retract");
    assert!(!c.is_active_pred(&old, &k.snapshot()));
    let before = k.snapshot().world().m5().content_count(&doc1());
    let result = c.supersede(&doc1(), &old, &term);
    assert!(!matches!(result, Err(SupersedeError::OldStartNotEverRegistered(_))), "{result:?}");
    assert_eq!(
        k.snapshot().world().m5().content_count(&doc1()),
        before + n(1),
        "the gate passed and the successor's content committed"
    );
}
