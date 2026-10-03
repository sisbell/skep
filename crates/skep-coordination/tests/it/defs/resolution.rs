//! Resolution: the memo's two permanent statuses — the poisoned one a
//! per-handle policy, and the answer to every breach a level-0 derivation
//! meets, a body too deep and a reference cycle included — and the one it
//! never keeps, and the class-free registration probes beside the guest-class
//! look.

use crate::common::*;
use crate::defs::envelope;
use crate::terms::*;

use skep_address::document_of;
use skep_content::HasContent;
use skep_coordination::{
    CertifyError, Coordinator, Dom, EvalError, RegisterError, Rule, RuleError, Sort, Term, Trigger,
    TypeError, Value, View,
};
use skep_links::{Caller, ShippedType, Tip};

/// PR-DISC's freeze-on-breach: a `pdef` on content that is no def —
/// registered past `register_pred`'s gate, through M7 directly — is
/// EVER-registered, so the registration probes answer yes, and every
/// question that needs the def's signature answers with the breach:
/// `UndisciplinedDef` on the evaluation and the certification side alike
/// (never `NotEverRegistered` — the two `None` causes stay distinct), no
/// signature, an undefined reference, an undefined `Def` trigger, and the
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
        Err(TypeError::UndefinedReference(x)) if x == g
    ));
    assert!(matches!(
        c.register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
            trigger: Trigger::Def(g.clone()),
            view: View::Audit,
            action: marker_action(),
        }),
        Err(RuleError::UndefinedDefTrigger(x)) if x == g
    ));
    assert!(matches!(c.register_pred(&doc1(), &g), Err(RegisterError::ParseFailed)));
}

/// Freeze-on-breach is a per-handle POLICY, not an immutability fact
/// (§Internal 4): content deposited past the gate before its referent exists,
/// and probed in that window, freezes POISONED on the probing handle and stays
/// so — through the referent's registration, and through a `register_pred`
/// that passes every gate and returns `Ok` — while a handle that first probes
/// it afterwards derives it defined. The disagreement runs only toward
/// `None`: the cold handle's `Some` is right.
#[test]
fn a_freeze_on_breach_holds_on_its_handle_and_errs_only_toward_none() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) =
        c.define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("P")).expect("define P");
    let (q, _) = c
        .define_predicate(
            &doc1(),
            &c.type_check(vec![], Term::Ref { addr: p.clone(), args: vec![] }).expect("Q := P"),
        )
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
    assert_eq!(
        &bytes[end - 2..],
        &[1, 0],
        "PR-ENC: the referent's last component, then the argument count"
    );
    bytes[end - 2] = 4; // the reference now names ca4 — nothing is there yet
    let s = insert_raw(&k, &doc1(), bytes);
    assert_eq!(s, ca(3));
    link_writer(&k)
        .emit(Caller::System, &doc1(), &pred_def_ty(), &s, &[])
        .expect("the breach: a pdef past the gate, ahead of its referent");
    assert!(c.signature(&s).is_none(), "probed while ca4 is unregistered: frozen poisoned");

    let (r, _) =
        c.define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("R")).expect("define R");
    assert_eq!(r, ca(4));
    assert!(c.signature(&s).is_none(), "the freeze declines to re-check");
    assert_eq!(
        c.evaluate_def(&s, &[], View::Active, &k.snapshot()),
        Err(EvalError::UndisciplinedDef)
    );
    c.register_pred(&doc1(), &s).expect("every gate passes now — the dedup absorbs it");
    assert!(c.signature(&s).is_none(), "the memo's first fill stands");

    let cold = coord(&k);
    assert_eq!(cold.signature(&s).map(|sig| sig.result), Some(Sort::Bool));
    assert_eq!(cold.evaluate_def(&s, &[], View::Active, &k.snapshot()), Ok(Value::Bool(true)));
}

/// A body the decoder admits and the checker refuses as too deep AT LEVEL 0
/// is the content's own fault, never an asking term's: `register_pred`
/// refuses it `IllTyped(TooDeep)`, and where a breach registers it anyway it
/// freezes POISONED like any undisciplined content — every probe answers the
/// breach, none panics. `¬¹²⁵(∀K ∈ Reg :: ⊤)` decodes with its quantifier at
/// level 125, inside the cap, and checks its `Reg` instances four joins
/// deeper, at 129.
#[test]
fn a_body_too_deep_at_level_zero_is_a_breach_and_freezes_poisoned() {
    let k = kernel();
    let c = coord(&k);
    let mut payload = vec![0u8]; // no parameters
    payload.extend(std::iter::repeat_n(7u8, 125)); // NOT, per level
    payload.extend([10u8, 10, 5, 2, 1]); // FORALL v10 ∈ REG :: LIT TRUE
    let s = insert_raw(&k, &doc1(), envelope(payload));
    assert!(matches!(
        c.register_pred(&doc1(), &s),
        Err(RegisterError::IllTyped(TypeError::TooDeep))
    ));
    link_writer(&k)
        .emit(Caller::System, &doc1(), &pred_def_ty(), &s, &[])
        .expect("the breach: a pdef past the gate");
    assert!(c.signature(&s).is_none());
    assert_eq!(
        c.evaluate_def(&s, &[], View::Active, &k.snapshot()),
        Err(EvalError::UndisciplinedDef)
    );
    assert!(matches!(c.certify_stable(&doc1(), &s), Err(CertifyError::UndisciplinedDef)));
}

/// A breach CYCLE ends: two runs registered past the gate, each a reference
/// to the other, derive their referent two levels deeper per hop
/// (`referent_depth`) until the checker's nesting door refuses; each refusal
/// above level 0 is the asking term's and fills nothing, and the root, at
/// level 0, freezes poisoned on its own account — as does the other member,
/// the root of its own derivation when it is first probed. Asked at a fixed
/// level, the first probe would recurse without end; a level-0 refusal taken
/// for the asking term's would reach `def_status`'s `unreachable!`.
#[test]
fn a_breach_cycle_ends_at_the_nesting_cap_and_freezes_its_root() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) =
        c.define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("P")).expect("define P");
    let (q, _) = c
        .define_predicate(
            &doc1(),
            &c.type_check(vec![], Term::Ref { addr: p.clone(), args: vec![] }).expect("Q := P"),
        )
        .expect("define Q");
    assert_eq!((p, q.clone()), (ca(1), ca(2)));
    let template = k
        .snapshot()
        .world()
        .content()
        .value_at(q.tumbler())
        .expect("Q is resident")
        .as_bytes()
        .to_vec();
    let end = template.len();
    assert_eq!(
        &template[end - 2..],
        &[1, 0],
        "PR-ENC: the referent's last component, then the argument count"
    );
    let referring_to = |ordinal: u8| {
        let mut bytes = template.clone();
        bytes[end - 2] = ordinal;
        bytes
    };
    let cycle_a = insert_raw(&k, &doc1(), referring_to(4)); // → ca4, landing at ca3
    let cycle_b = insert_raw(&k, &doc1(), referring_to(3)); // → ca3, landing at ca4
    assert_eq!((cycle_a.clone(), cycle_b.clone()), (ca(3), ca(4)));
    for start in [&cycle_a, &cycle_b] {
        link_writer(&k)
            .emit(Caller::System, &doc1(), &pred_def_ty(), start, &[])
            .expect("the breach: a pdef past the gate");
    }
    assert!(c.signature(&cycle_a).is_none(), "the cycle ends, its root poisoned");
    assert_eq!(
        c.evaluate_def(&cycle_a, &[], View::Active, &k.snapshot()),
        Err(EvalError::UndisciplinedDef)
    );
    assert!(c.signature(&cycle_b).is_none());
    assert_eq!(
        c.evaluate_def(&cycle_b, &[], View::Active, &k.snapshot()),
        Err(EvalError::UndisciplinedDef)
    );
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
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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
    assert!(matches!(c.type_check(vec![], reference()), Err(TypeError::UndefinedReference(_))));
    assert!(matches!(def_rule(&mut c), Err(RuleError::UndefinedDefTrigger(_))));

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
/// predicate refuses is ever-registered, active, signed, evaluable and
/// endorsable as a referent — and invisible to `is_K(pdef, ·)` at every view.
#[test]
fn def_probes_are_class_free_while_the_evaluator_s_look_is_not() {
    let k = kernel();
    let c = coord_with_guest(&k, |_, d| *d != doc2());
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

    // Endorsement is a registration question too: a consumer of the
    // draft-registered def registers in a readable home, the referent active
    // to `register_pred`'s class-free gate though hidden from the look.
    let consumer = c
        .type_check(vec![], Term::Ref { addr: start.clone(), args: vec![] })
        .expect("a reference to the draft-registered def");
    c.define_predicate(&doc1(), &consumer).expect("the endorsement gate reads class-free");

    // `is_certified_stable` is the same split: the certificate lands in the
    // draft, so the def probe answers and the evaluator's look does not.
    let (certificate, _) =
        c.certify_stable(&doc2(), &start).expect("⊤ is Bool, active, view-independent and ST⁺");
    assert!(c.is_certified_stable(&start, &k.snapshot()));
    for view in [View::Active, View::Audit, View::Default] {
        assert!(!decide_now(&k, &c, view, is_k(&pred_stable_ty(), lit_addr(&start))), "{view:?}");
    }
    // ≤1 active `pd_stable` per start holds WITHIN THE GUEST CLASS the writer
    // runs at: the draft's certificate is invisible to its dedup, so a
    // re-certification into the draft mints a second one and commits.
    let before = k.current_seq();
    let (twin, seq) = c.certify_stable(&doc2(), &start).expect("re-certify into the draft");
    assert_ne!(twin, certificate, "a guest-hidden incumbent absorbs no re-certification");
    assert!(seq > before, "and the re-certification commits");

    // `current_version` walks M7's claims CLASS-FREE, where the `tip` atom
    // rebuilds the walk over the VISIBLE ones — so one draft-homed claim moves
    // the def layer's lineage read and not the evaluator's.
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    link_writer(&k)
        .assert_sup(Caller::System, &doc2(), &l1, &l2)
        .expect("a claim homed in the draft");
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    assert_eq!(c.current_version(&l1, &k.snapshot()), Tip::Sink(l2));
    assert!(decide_now(&k, &c, View::Active, tip_is(&sup, &l1, &l1)), "the atom's walk stops at l1");
}

/// ≤1 active `pdef` per start (PR0) holds WITHIN the guest class the writer
/// runs at (lane 3.3b): a pdef homed where the guest predicate refuses is
/// invisible to M7's idempotency lookup, so a second registration mints a
/// fresh tuple beside it — and `is_active_pred`, which reads class-free,
/// stays true until each of the two is retracted, one per call.
#[test]
fn a_pdef_hidden_from_the_guest_class_does_not_absorb_a_second_registration() {
    let k = kernel();
    let c = coord_with_guest(&k, |_, d| *d != doc2());
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
