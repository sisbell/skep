//! Resolution: the memo's two permanent statuses and the one it never keeps,
//! and the class-free registration probes beside the guest-class look.

use crate::common::*;
use crate::terms::*;

use skep_address::{document_of, Address};
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
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
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
/// predicate refuses is ever-registered, active, signed, evaluable and
/// endorsable as a referent — and invisible to `is_K(pdef, ·)` at every view.
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

    // Endorsement is a registration question too: a consumer of the
    // draft-registered def registers in a readable home, the referent active
    // to `register_pred`'s class-free gate though hidden from the look.
    let consumer = c
        .type_check(vec![], Term::Ref { addr: start.clone(), args: vec![] })
        .expect("a reference to the draft-registered def");
    c.define_predicate(&doc1(), &consumer).expect("the endorsement gate reads class-free");

    // `is_certified_stable` is the same split: the certificate lands in the
    // draft, so the def probe answers and the evaluator's look does not.
    c.certify_stable(&doc2(), &start).expect("⊤ is Bool, active, view-independent and ST⁺");
    assert!(c.is_certified_stable(&start, &k.snapshot()));
    for view in [View::Active, View::Audit, View::Default] {
        assert!(!decide_now(&k, &c, view, is_k(&pred_stable_ty(), lit_addr(&start))), "{view:?}");
    }

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
