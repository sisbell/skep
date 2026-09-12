//! M9 contract tests over a real kernel (InMemory), group B — predicate
//! definitions as content: store/register/evaluate/supersede/certify/
//! retract, the PR-ENC byte contract as `register_pred` reads it back, the
//! memo's two permanent verdicts and the one it never keeps, and the
//! class-free registration probes beside the guest-class look. Every
//! assertion states a claim the design or interface makes — nothing more.

use crate::common::*;
use crate::terms::*;

use skep_address::Address;
use skep_arrangement::HasM5;
use skep_content::HasContent;
use skep_coordination::{
    CertifyError, Coordinator, DefineError, Dom, EvalError, Lit, RegisterError, RetractError,
    Rule, Sort, Stability, Term, Trigger, TypeError, Value, View, RuleError,
};
use skep_kernel::TxnError;
use skep_links::{Caller, EmitError, Tip};

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
    let g = insert_raw(&k, &doc1(), bytes);
    assert_eq!(g, ca(3));
    match c.register_pred(&doc1(), &g) {
        Err(RegisterError::ReferentNotEverRegistered(x)) => assert_eq!(x, ca(4)),
        other => panic!("expected ReferentNotEverRegistered(ca4) ahead of WT-ref, got {other:?}"),
    }
    assert!(!c.is_ever_pred(&g, &k.snapshot()));
    assert!(c.signature(&g).is_none());

    let (r, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("R"))
        .expect("define R");
    assert_eq!(r, ca(4));
    c.register_pred(&doc1(), &g).expect("the orphan content is adopted");
    assert_eq!(c.evaluate_def(&g, &[], View::Active, &k.snapshot()), Ok(Value::Bool(true)));
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
    let g = insert_raw(&k, &doc1(), bytes);
    assert!(matches!(
        c.register_pred(&doc1(), &g),
        Err(RegisterError::IllTyped(TypeError::SortMismatch { expected: Sort::Addr, found: Sort::Nat }))
    ));
    assert!(c.signature(&g).is_none(), "orphan content, never registered");
}

/// The decode cap defends: a hand-forged body one former past it is
/// `ParseFailed`, and one exactly at it registers and then survives every
/// walk a stored body drives — the parse and check of a fresh memo, the
/// evaluation, the certification's expansion and analysis, and the expansion
/// through a reference — on this default test thread, whose stack is the
/// budget the cap is set against. (The bytes are PR-ENC's: `¬` is one tag
/// per level over the closed `True`, which the codec's own suite pins.)
#[test]
fn a_hand_forged_body_at_the_decode_cap_survives_every_walk() {
    const CAP: usize = 128;
    let forged = |depth: usize| -> Vec<u8> {
        let mut payload = vec![0u8]; // no parameters
        payload.extend(std::iter::repeat_n(7u8, depth)); // NOT, per level
        payload.extend([2u8, 1]); // LIT, TRUE
        let mut out = Vec::new();
        let mut len = payload.len() as u64;
        loop {
            let limb = (len & 0x7f) as u8;
            len >>= 7;
            if len == 0 {
                out.push(limb);
                break;
            }
            out.push(limb | 0x80);
        }
        out.extend(payload);
        out
    };
    let k = kernel();
    let c = coord(&k);
    let past = insert_raw(&k, &doc1(), forged(CAP + 1));
    assert!(matches!(c.register_pred(&doc1(), &past), Err(RegisterError::ParseFailed)));
    let start = insert_raw(&k, &doc1(), forged(CAP));
    c.register_pred(&doc1(), &start).expect("a body at the cap registers");

    // A fresh memo: parse + check + evaluate. `¬^128 True` is `True`.
    let fresh = coord(&k);
    assert_eq!(fresh.evaluate_def(&start, &[], View::Active, &k.snapshot()), Ok(Value::Bool(true)));
    fresh.certify_stable(&doc1(), &start).expect("expand + analyze at the cap");
    let through = fresh.type_check(vec![], Term::Ref { addr: start, args: vec![] }).expect("a reference to it");
    let (r, _) = fresh.define_predicate(&doc1(), &through).expect("define the reference");
    fresh.certify_stable(&doc1(), &r).expect("expand through the reference at the cap");
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
    links(&k)
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
        assert!(!decide_now(&k, &c, view, is_k_t(&pred_def_ty(), lit_addr(&start))), "{view:?}");
    }
}

/// supersede's up-front gates, `current_version` over the shipped class, and
/// the M7 supersession-fence drift tripwire (see the report: as-built M7
/// rejects a raw `[K_sup]`-typed `emit`, so the design's def-lineage claim
/// cannot commit — the first two of the three non-atomic transactions do).
#[test]
fn supersede_gates_lineage_and_fence_drift() {
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

    // (0)/(ii) ordering: a retracted def is NotActive.
    c.retract_pred(&doc1(), &s0).expect("retract");
    assert!(matches!(c.certify_stable(&doc1(), &s0), Err(CertifyError::NotActive)));
}
