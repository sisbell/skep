//! A stored def's denotation (`evaluate_def`): the view and the snapshot it
//! reads at, its argument door, positional binding, the binders in its body,
//! and the source form it is stored as and re-derived from.

use crate::common::*;
use crate::terms::*;

use skep_address::Address;
use skep_content::HasContent;
use skep_coordination::{Atom, Dom, EvalError, Sort, Term, TypeRef, Value, View};
use skep_links::Caller;

/// `evaluate_def`'s `view` is the term view the denotation reads at: a stored
/// def over a view-parameterized atom answers differently at `active` and
/// `audit` once its witness is retracted — the same split `eval` makes, and
/// the parameter is the caller's.
#[test]
fn a_stored_def_denotes_at_the_view_the_caller_names() {
    let k = kernel();
    let c = coord(&k);
    let (l1, _) = link_writer(&k)
        .emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(5), &[])
        .expect("a witness for ca5");
    let tt = c
        .type_check(vec![(v(1), Sort::Addr)], is_k(&pred_stable_ty(), var(1)))
        .expect("P(x) := is_K(pred_stable, x)");
    let (p, _) = c.define_predicate(&doc1(), &tt).expect("define");
    let at_view = |view: View| c.evaluate_def(&p, &[Value::Addr(ca(5))], view, &k.snapshot());
    assert_eq!(at_view(View::Active), Ok(Value::Bool(true)));
    assert_eq!(at_view(View::Audit), Ok(Value::Bool(true)));
    link_writer(&k).nullify(Caller::System, &doc1(), &l1).expect("retract the witness");
    assert_eq!(at_view(View::Active), Ok(Value::Bool(false)));
    assert_eq!(at_view(View::Audit), Ok(Value::Bool(true)), "audit keeps the record");
}

/// `evaluate_def` answers as of the CALLER's snapshot in both of its halves:
/// the ever-registration gate reads `snap` — a snapshot pinned before the def
/// was registered refuses it, though it is registered now — and so does the
/// denotation, which cannot see a witness deposited after `snap`. Only the
/// def's resolution is the memo's own pin, and that is content-intrinsic.
#[test]
fn a_stored_def_answers_as_of_the_caller_s_snapshot() {
    let k = kernel();
    let c = coord(&k);
    let unregistered = k.snapshot();
    let tt = c
        .type_check(vec![(v(1), Sort::Addr)], is_k(&pred_stable_ty(), var(1)))
        .expect("P(x) := is_K(pred_stable, x)");
    let (p, _) = c.define_predicate(&doc1(), &tt).expect("define");
    let unwitnessed = k.snapshot();
    link_writer(&k)
        .emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(5), &[])
        .expect("a witness after the pin");
    let witnessed = k.snapshot();
    let args = [Value::Addr(ca(5))];
    assert_eq!(
        c.evaluate_def(&p, &args, View::Active, &unregistered),
        Err(EvalError::NotEverRegistered)
    );
    assert_eq!(c.evaluate_def(&p, &args, View::Active, &unwitnessed), Ok(Value::Bool(false)));
    assert_eq!(c.evaluate_def(&p, &args, View::Active, &witnessed), Ok(Value::Bool(true)));
}

/// `evaluate_def` binds an `AddrSet` argument — a set of addresses by type,
/// so there is no element its door could refuse — and the def counts it: one
/// address satisfies `|s| = 1`, two do not.
#[test]
fn a_set_argument_is_bound_as_a_set_of_addresses() {
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
    let one = Value::AddrSet(im::OrdSet::unit(ca(1)));
    assert_eq!(c.evaluate_def(&p, &[one], View::Active, &s), Ok(Value::Bool(true)));
    let two = Value::AddrSet([ca(1), ca(2)].into_iter().collect());
    assert_eq!(c.evaluate_def(&p, &[two], View::Active, &s), Ok(Value::Bool(false)));
}

/// A def's Γ_D is an ORDERED context: it survives the codec round trip, a
/// cold coordinator reports it in order, and `evaluate_def` binds
/// positionally — so two same-sorted parameters are not interchangeable —
/// and a reference to the def binds the same way, through the evaluator's own
/// `Ref` arm.
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
    // A REFERENCE binds the same way — through the evaluator's own `Ref` arm,
    // a binding of its own that `evaluate_def`'s does not exercise: a call in
    // P's order holds, the crossed call does not.
    let call = |x: Address, y: Address| {
        let args = vec![at(lit_addr(&x)), at(lit_addr(&y))];
        let tt =
            c.type_check(vec![], Term::Ref { addr: start.clone(), args }).expect("a call of P");
        c.define_predicate(&doc1(), &tt).expect("define the call").0
    };
    let (in_order, crossed) = (call(ca(1), ca(2)), call(ca(2), ca(1)));
    let after = k.snapshot();
    assert_eq!(cold.evaluate_def(&in_order, &[], View::Active, &after), Ok(Value::Bool(true)));
    assert_eq!(cold.evaluate_def(&crossed, &[], View::Active, &after), Ok(Value::Bool(false)));
}

/// A def's PARAMETERS are Codom-only (`TupParameter` refuses a tuple one),
/// yet its body binds tuples like any PL term — through a quantifier over
/// `A_K`/`L_K` — and reads them through V-TUP: such a def stores, re-derives
/// from its own bytes on a cold coordinator, evaluates, and certifies over its
/// flat expansion.
#[test]
fn a_stored_def_binds_tuples_through_its_quantifiers() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let tt = c
        .type_check(
            vec![(v(1), Sort::Addr)],
            exists(2, Dom::AuditSlice(concrete(&pred_stable_ty())), in_coverage_f(var(1), 2)),
        )
        .expect("P(x) := ∃ t ∈ L_K :: x ∈ cov_F(t)");
    let (p, _) = c.define_predicate(&doc1(), &tt).expect("define");
    let cold = coord(&k); // re-derives the body from its stored bytes
    let s = k.snapshot();
    let at_arg = |x: Address| cold.evaluate_def(&p, &[Value::Addr(x)], View::Active, &s);
    assert_eq!(at_arg(ca(1)), Ok(Value::Bool(true)));
    assert_eq!(at_arg(ca(3)), Ok(Value::Bool(false)));
    cold.certify_stable(&doc1(), &p).expect("∃ over the grow-only L_K is ST⁺");
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

/// A stored def is its SOURCE: `define_predicate` encodes the compact
/// pre-`Reg`-expansion body, so `∃K ∈ Reg :: is_K(x)` names no class and its
/// stored run is SHORTER than that of its first instance `is_K(Retired, x)`,
/// which spells a key — the expansion would spell five. A cold coordinator
/// re-derives the expansion from those bytes, its last instance included.
#[test]
fn a_def_is_stored_as_its_source_and_expanded_when_derived() {
    let k = kernel();
    let c = coord(&k);
    let define = |t: Term| {
        let tt = c.type_check(vec![(v(1), Sort::Addr)], t).expect("P(x)");
        c.define_predicate(&doc1(), &tt).expect("define").0
    };
    let in_some_class = Term::Atom(Atom::IsK(TypeRef::ClassVar(v(7)), at(var(1))));
    let some_class = define(exists(7, Dom::Reg, in_some_class));
    let one_class = define(is_k(&retired_ty(), var(1)));
    let stored = |start: &Address| {
        k.snapshot().world().content().value_at(start.tumbler()).expect("resident").len()
    };
    assert!(
        stored(&some_class) < stored(&one_class),
        "{} bytes against {}",
        stored(&some_class),
        stored(&one_class)
    );
    // PredStable is the catalog's last class, so its instance is the last the
    // expansion builds.
    link_writer(&k)
        .emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(5), &[])
        .expect("ca5 heads PredStable");
    let cold = coord(&k);
    let s = k.snapshot();
    let at_arg = |x: Address| cold.evaluate_def(&some_class, &[Value::Addr(x)], View::Active, &s);
    assert_eq!(at_arg(ca(5)), Ok(Value::Bool(true)));
    assert_eq!(at_arg(doc2()), Ok(Value::Bool(false)));
}
