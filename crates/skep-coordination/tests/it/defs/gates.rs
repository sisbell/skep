//! Every refusal a def write meets, and the order they speak in:
//! `register_pred`'s gates, read back over PR-ENC bytes the tests forge, and
//! the store's own home doors.

use crate::common::*;
use crate::defs::forged_negations;
use crate::terms::*;

use skep_address::document_of;
use skep_arrangement::InsertError;
use skep_content::HasContent;
use skep_coordination::{
    CertifyError, DefineError, RegisterError, RetractError, Sort, SupersedeError, Term, TypeError,
    Value, VarId, View,
};
use skep_kernel::TxnError;
use skep_links::{EmitError, NullifyError};

/// register_pred's parse-level gates. (A def with a tuple parameter is not a
/// rejection here but a type error: `define_predicate` takes a `TypedTerm`,
/// and `type_check_trigger` — the one way to declare a `Tup` parameter —
/// yields a `TriggerTerm`, so no such def can be spelled.)
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
        Err(SupersedeError::Define(DefineError::Insert(TxnError::Rejected(
            InsertError::PublishedTarget
        ))))
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

/// The two later joints of `register_pred`'s stated gate order, each forced by
/// a body that fails the gates on both sides of it: WT (`IllTyped`) speaks
/// before endorsement (`ReferentNotActive`), and endorsement before the home
/// gate (`HomeNotRegistered`, P0) — and where several referents fail
/// endorsement, the one named is the FIRST in first-occurrence pre-order.
#[test]
fn register_pred_s_later_gates_speak_in_their_stated_order() {
    let k = kernel();
    let c = coord(&k);
    let define = |params: Vec<(VarId, Sort)>, t: Term| {
        let tt = c.type_check(params, t).expect("checks");
        c.define_predicate(&doc1(), &tt).expect("define").0
    };
    let p = define(vec![(v(1), Sort::Addr)], tru()); // P(x) := ⊤
    let p2 = define(vec![], tru()); // P2 := ⊤
    let q = define(vec![(v(1), Sort::Addr)], Term::Ref { addr: p.clone(), args: vec![at(var(1))] });
    let r = define(
        vec![],
        and(
            Term::Ref { addr: p2.clone(), args: vec![] },
            Term::Ref { addr: p.clone(), args: vec![at(lit_addr(&ca(1)))] },
        ),
    );
    // Q's parameter re-sorted Addr → Nat: its argument no longer meets P's formal.
    let mut bytes = k
        .snapshot()
        .world()
        .content()
        .value_at(q.tumbler())
        .expect("Q is resident")
        .as_bytes()
        .to_vec();
    assert_eq!(&bytes[1..4], &[1, 1, 2], "PR-ENC: one parameter, named 1, sorted Addr");
    bytes[3] = 7; // Nat
    let forged = insert_raw(&k, &doc1(), bytes);
    c.retract_pred(&doc1(), &p).expect("retract P");
    c.retract_pred(&doc1(), &p2).expect("retract P2");

    // WT before endorsement: P is retracted, and the forged Q is refused as
    // ill-typed all the same.
    assert!(matches!(
        c.register_pred(&doc1(), &forged),
        Err(RegisterError::IllTyped(TypeError::SortMismatch {
            expected: Sort::Addr,
            found: Sort::Nat
        }))
    ));
    // Endorsement before the home: R names an unregistered home, and both its
    // referents are retracted — P2, the first, is the one named.
    match c.register_pred(&a(&[1, 0, 1, 0, 7]), &r) {
        Err(RegisterError::ReferentNotActive(x)) => assert_eq!(x, p2, "R names P2 before P"),
        other => panic!("expected ReferentNotActive(P2) ahead of the home gate, got {other:?}"),
    }
}
