//! Typing (`type_check`, `type_check_trigger`): the Γ_D-checked judgment with
//! `Reg` expansion — each gate's own rejection, the walk order that decides
//! which one speaks, and the nesting cap and node budget at their boundaries.

use crate::common::*;
use crate::terms::*;

use skep_coordination::{
    Atom, Dom, Lit, Nat, Sort, Term, TypeError, TypeKey, TypeRef, Value, VarId, View,
};
use skep_links::{coverage_class, Behavior, Caller, Endset, ShippedType};

/// Γ_D is part of the checking judgment: unbound vars, the def-path/
/// trigger-path Tup split, sort synthesis, and the catalog/behavior guards.
#[test]
fn type_check_refuses_at_each_gamma_and_catalog_gate() {
    let k = kernel();
    let c = coord(&k);

    // A free Var outside Γ_D.
    assert!(matches!(c.type_check(vec![], var(3)), Err(TypeError::UnboundVariable(_))));
    // Γ_D binds each name once: a repeated name is refused before the body
    // is walked (the body here is unbound on its own), and after the Tup
    // gate.
    assert!(matches!(
        c.type_check(vec![(v(1), Sort::Addr), (v(1), Sort::Nat)], var(3)),
        Err(TypeError::DuplicateParameter(x)) if x == v(1)
    ));
    assert!(matches!(
        c.type_check(vec![(v(1), Sort::Addr), (v(1), Sort::Tup)], tru()),
        Err(TypeError::TupParameter(_))
    ));
    // The def path rejects a Tup parameter; the trigger path — its own
    // type, one parameter by signature — admits it, and requires Bool.
    assert!(matches!(
        c.type_check(vec![(v(1), Sort::Tup)], tru()),
        Err(TypeError::TupParameter(_))
    ));
    let one_tup = c
        .type_check_trigger((v(1), Sort::Tup), in_coverage_f(lit_addr(&ca(1)), 1))
        .expect("a one-Tup-parameter Bool trigger");
    assert_eq!(one_tup.param(), &(v(1), Sort::Tup));
    assert!(matches!(
        c.type_check_trigger((v(1), Sort::Addr), lit_nat(1)),
        Err(TypeError::SortMismatch { expected: Sort::Bool, found: Sort::Nat })
    ));
    // Sort synthesis.
    assert!(matches!(
        c.type_check(vec![], and(tru(), lit_nat(1))),
        Err(TypeError::SortMismatch { expected: Sort::Bool, found: Sort::Nat })
    ));
    // The catalog probe is Endset-equality: an uncataloged key misses.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Members(TypeRef::Concrete(TypeKey(uncataloged_ty(20)))))),
        Err(TypeError::UncatalogedTypeKey(_))
    ));
    // An atom needing a behavior the registration lacks.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::SourcesTo(concrete(&pred_def_ty()), at(lit_addr(&ca(1)))))),
        Err(TypeError::BehaviorMissing { needs: Behavior::ReverseLookup, .. })
    ));
    // A ClassVar under no enclosing Reg binder.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Members(TypeRef::ClassVar(v(5))))),
        Err(TypeError::UnboundClassVar(_))
    ));
    // Ref to an address with no defined signature.
    assert!(matches!(
        c.type_check(vec![], Term::Ref { addr: ca(9), args: vec![] }),
        Err(TypeError::UndefinedReference(_))
    ));

    // targets_keyed is in the vocabulary iff some cataloged class attaches
    // BH3 (V-atom): no shipped registration does, so THE catalog — every
    // board's catalog — rejects it.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::TargetsKeyed(at(lit_addr(&ca(1)))))),
        Err(TypeError::NoReverseLookupClass)
    ));
}

/// The checker's documented edges: a `Ref`'s arity, short and long, and its
/// arguments matched to their formals by position; the binder guard's and
/// `Def`'s optional-sort requirement and the branch agreement; the
/// address-valued-domain requirement of `Reflect`/`MaxT1`; a bare `Reg` in
/// every position outside ∀/∃/`Count`; and the behavior guards of the
/// BH1/BH2/BH4 atoms — each its own typed rejection, and an arity refusal's
/// message naming the referent and both counts, so a caller holding only the
/// message reads what was wrong.
#[test]
fn type_check_refuses_each_documented_edge_by_name() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("P(x)"))
        .expect("define P");
    let (q, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("Q"))
        .expect("define Q");

    // Ref arity: too few arguments, and too many.
    let short = c.type_check(vec![], Term::Ref { addr: p.clone(), args: vec![] }).err();
    assert_eq!(
        short,
        Some(TypeError::ArgArityMismatch { referent: p.clone(), expected: 1, found: 0 })
    );
    assert_eq!(
        c.type_check(vec![], Term::Ref { addr: q.clone(), args: vec![at(lit_addr(&ca(1)))] }).err(),
        Some(TypeError::ArgArityMismatch { referent: q, expected: 0, found: 1 })
    );
    let said = short.expect("refused").to_string();
    assert!(
        said.contains(&format!(
            "a reference to {p} passes 0 argument(s) to a def of 1 parameter(s)"
        )),
        "{said}"
    );
    // … and arguments meet formals BY POSITION: a referent of two sorts takes
    // its arguments in its own order and refuses them swapped, at the first.
    let (r, _) = c
        .define_predicate(
            &doc1(),
            &c.type_check(vec![(v(1), Sort::Addr), (v(2), Sort::Nat)], tru()).expect("R(x, n)"),
        )
        .expect("define R");
    let calling_r = |args: [Term; 2]| {
        let args = args.into_iter().map(at).collect();
        c.type_check(vec![], Term::Ref { addr: r.clone(), args })
    };
    calling_r([lit_addr(&ca(1)), lit_nat(1)]).expect("each argument at its own formal");
    assert_eq!(
        calling_r([lit_nat(1), lit_addr(&ca(1))]).err(),
        Some(TypeError::SortMismatch { expected: Sort::Addr, found: Sort::Nat })
    );

    // The binder guard and `def` take an optional; the two branches agree.
    let opt_for_bool = || Some(TypeError::SortMismatch { expected: Sort::OptAddr, found: Sort::Bool });
    assert_eq!(c.type_check(vec![], if_some(tru(), 2, tru(), tru())).err(), opt_for_bool());
    assert_eq!(c.type_check(vec![], def(tru())).err(), opt_for_bool());
    assert_eq!(
        c.type_check(vec![], if_some(bot_addr(), 2, tru(), lit_nat(1))).err(),
        Some(TypeError::SortMismatch { expected: Sort::Bool, found: Sort::Nat })
    );

    // Only an address-valued domain reflects or has a T1 extremum.
    let tup_for_addr = || Some(TypeError::SortMismatch { expected: Sort::Addr, found: Sort::Tup });
    let tuples = || Dom::ActiveSlice(concrete(&pred_def_ty()));
    assert_eq!(c.type_check(vec![], reflect(tuples())).err(), tup_for_addr());
    assert_eq!(c.type_check(vec![], Term::MaxT1(ad(tuples()))).err(), tup_for_addr());
    // A bare Reg outside ∀/∃/Count is misplaced wherever it sits — a
    // quantifier's FILTERED domain included: ∃ admits Reg only as its own.
    let misplaced = || Some(TypeError::MisplacedReg);
    assert_eq!(c.type_check(vec![], reflect(Dom::Reg)).err(), misplaced());
    assert_eq!(c.type_check(vec![], Term::MinT1(ad(Dom::Reg))).err(), misplaced());
    assert_eq!(c.type_check(vec![], count(filter(Dom::Reg, 2, tru()))).err(), misplaced());
    assert_eq!(
        c.type_check(vec![], exists(2, filter(Dom::Reg, 3, tru()), tru())).err(),
        misplaced()
    );
    assert_eq!(
        c.type_check(vec![], big_union(Dom::Reg, 2, members(&pred_def_ty()))).err(),
        misplaced()
    );

    // The behavior guards, one per behavior: BH4 on a class without Age,
    // BH2 on one without Walk, BH1 on one without ReadFilter.
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Age(concrete(&pred_def_ty()), at(lit_addr(&ca(1)))))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Age, .. })
    ));
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Stale(concrete(&retired_ty()), at(lit_nat(1))))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Age, .. })
    ));
    assert!(matches!(
        c.type_check(vec![], succs(&retired_ty(), lit_addr(&ca(1)))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Walk, .. })
    ));
    assert!(matches!(
        c.type_check(vec![], is_filtered(&pred_def_ty(), lit_addr(&ca(1)))),
        Err(TypeError::BehaviorMissing { needs: Behavior::ReadFilter, .. })
    ));
}

/// WHICH rejection speaks when several hold: a node's type position and its
/// behavior guard before its children; children left to right; a binder's
/// domain before its body; a `Ref`'s referent before its arguments, and each
/// argument on its own account before it is matched against its formal — an
/// extra argument included, before the arity it breaks.
#[test]
fn type_check_reports_the_first_rejection_in_its_stated_walk_order() {
    let k = kernel();
    let c = coord(&k);
    let mismatch = |expected: Sort, found: Sort| Some(TypeError::SortMismatch { expected, found });
    // Ill-typed on its own account, whatever formal it is matched against.
    let bad_arg = || and(tru(), lit_nat(1));

    // The type position and its guard, before the children.
    assert!(matches!(
        c.type_check(vec![], is_k(&uncataloged_ty(20), lit_nat(1))),
        Err(TypeError::UncatalogedTypeKey(_))
    ));
    assert!(matches!(
        c.type_check(vec![], succs(&retired_ty(), lit_nat(1))),
        Err(TypeError::BehaviorMissing { needs: Behavior::Walk, .. })
    ));
    // Children left to right.
    assert_eq!(
        c.type_check(vec![], and(lit_nat(1), lit_addr(&ca(1)))).err(),
        mismatch(Sort::Bool, Sort::Nat)
    );
    // A binder's domain before its body.
    assert!(matches!(
        c.type_check(vec![], exists(2, Dom::MembersDom(concrete(&uncataloged_ty(20))), lit_nat(1))),
        Err(TypeError::UncatalogedTypeKey(_))
    ));
    // A `Ref`'s referent before its arguments …
    assert!(matches!(
        c.type_check(vec![], Term::Ref { addr: ca(9), args: vec![at(bad_arg())] }),
        Err(TypeError::UndefinedReference(_))
    ));
    // … and an argument's own ill-typedness before its match to the formal,
    // which would report `{expected: Addr, found: Bool}`.
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("P(x)"))
        .expect("define P");
    assert_eq!(
        c.type_check(vec![], Term::Ref { addr: p, args: vec![at(bad_arg())] }).err(),
        mismatch(Sort::Bool, Sort::Nat)
    );
    // An EXTRA argument likewise speaks on its own account before the arity
    // it breaks — which would report `ArgArityMismatch`.
    let (q, _) =
        c.define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("Q")).expect("define Q");
    assert_eq!(
        c.type_check(vec![], Term::Ref { addr: q, args: vec![at(bad_arg())] }).err(),
        mismatch(Sort::Bool, Sort::Nat)
    );
}

/// WT is what makes `eval` infallible past its door, one position at a time:
/// every place the checker requires a sort refuses a child of another, and
/// each refusal stands between a checked term and an `unreachable!` in the
/// evaluator. One row per such place — a reference's arguments aside, which
/// `type_check_refuses_each_documented_edge_by_name` and the stored-bytes gate
/// pin — and PC2's line crossed both ways: an optional is not a value, nor a
/// value an optional; the binder guard is the only way from `T∪{⊥}` to `T`.
#[test]
fn every_sorted_position_refuses_a_child_of_another_sort() {
    let k = kernel();
    let c = coord(&k);
    let mismatch = |expected: Sort, found: Sort| TypeError::SortMismatch { expected, found };
    let set = || members(&pred_def_ty());
    let addr = || lit_addr(&ca(1));
    for (t, refused) in [
        (not(lit_nat(1)), mismatch(Sort::Bool, Sort::Nat)),
        (and(lit_nat(1), tru()), mismatch(Sort::Bool, Sort::Nat)),
        (exists(2, Dom::LinkDom, lit_nat(1)), mismatch(Sort::Bool, Sort::Nat)),
        (
            forall(7, Dom::Reg, lit_nat(1)),
            TypeError::RegInstanceIllTyped(Box::new(mismatch(Sort::Bool, Sort::Nat))),
        ),
        (count(filter(Dom::LinkDom, 2, lit_nat(1))), mismatch(Sort::Bool, Sort::Nat)),
        (big_union(Dom::LinkDom, 2, lit_nat(1)), mismatch(Sort::AddrSet, Sort::Nat)),
        (count_set(lit_nat(1)), mismatch(Sort::AddrSet, Sort::Nat)),
        (reflect(Dom::ActiveSlice(concrete(&pred_def_ty()))), mismatch(Sort::Addr, Sort::Tup)),
        (is_doc(lit_nat(1)), mismatch(Sort::Addr, Sort::Nat)),
        (exists(1, Dom::LinkDom, is_doc(tup_addr(1))), mismatch(Sort::Tup, Sort::Addr)),
        (addr_eq(lit_nat(1), addr()), mismatch(Sort::Addr, Sort::Nat)),
        (set_eq(lit_nat(1), set()), mismatch(Sort::AddrSet, Sort::Nat)),
        (is_empty(lit_nat(1)), mismatch(Sort::AddrSet, Sort::Nat)),
        (nat_le(tru(), lit_nat(1)), mismatch(Sort::Nat, Sort::Bool)),
        (nat_add(tru(), lit_nat(1)), mismatch(Sort::Nat, Sort::Bool)),
        (elems(set()), mismatch(Sort::AddrSeq, Sort::AddrSet)),
        (set_mem(lit_nat(1), set()), mismatch(Sort::Addr, Sort::Nat)),
        (set_mem(addr(), lit_nat(1)), mismatch(Sort::AddrSet, Sort::Nat)),
        (map_get(lit_nat(1), &pred_def_ty()), mismatch(Sort::Map, Sort::Nat)),
        // PC2's line, crossed both ways.
        (addr_eq(bot_addr(), addr()), mismatch(Sort::Addr, Sort::OptAddr)),
        (nat_le(bot_nat(), lit_nat(1)), mismatch(Sort::Nat, Sort::OptNat)),
        (if_some(bot_addr(), 2, bot_addr(), addr()), mismatch(Sort::OptAddr, Sort::Addr)),
        (def(addr()), mismatch(Sort::OptAddr, Sort::Addr)),
        (if_some(lit_nat(1), 2, tru(), tru()), mismatch(Sort::OptAddr, Sort::Nat)),
    ] {
        assert_eq!(c.type_check(vec![], t.clone()).err(), Some(refused), "{t:?}");
    }
}

/// A variable is read only inside its binder's scope, the other half of what
/// keeps `eval` from meeting an unbound name: a tuple projection names a
/// variable some binder bound, and the binder guard binds its variable in the
/// THEN-branch alone — the else-branch runs exactly when nothing was bound,
/// so it cannot read the name, and where the name is also bound outside it
/// reads that outer binding at its own sort.
#[test]
fn a_binder_s_variable_is_read_only_inside_its_scope() {
    let k = kernel();
    let c = coord(&k);
    assert_eq!(c.type_check(vec![], tup_addrs_f(9)).err(), Some(TypeError::UnboundVariable(v(9))));
    assert_eq!(
        c.type_check(vec![], if_some(bot_addr(), 2, tru(), is_doc(var(2)))).err(),
        Some(TypeError::UnboundVariable(v(2)))
    );
    let shadowing = c
        .type_check(
            vec![(v(2), Sort::Nat)],
            if_some(bot_addr(), 2, is_doc(var(2)), nat_le(var(2), lit_nat(3))),
        )
        .expect("then reads the guard's v2: Addr; else the parameter v2: Nat");
    assert!(c.decide(&shadowing, &[Value::Nat(n(2))], View::Active, &k.snapshot()));
}

/// `is_ref_free` is "false iff any `Ref` node survives" — a law over every
/// position a child term can occupy. The checker computes the flag by hand at
/// every node it rebuilds, and four doors stand on it: `eval` and
/// `quiescent_scoped` refuse a ref-bearing term before evaluating it,
/// `classify` before analyzing it, and `register_rule` answers a ref-bearing
/// `Inline` trigger or domain with a typed rejection. A position that dropped
/// its child from the flag would hand the reference past every door — to the
/// analyzer's `unreachable!` inside `register_rule`, or the evaluator's `Ref`
/// arm inside a later `step`. Each row puts ONE reference at one position and
/// must report ref-bearing; the same row over an ordinary term of that sort
/// must not.
#[test]
fn a_reference_at_any_position_makes_the_term_ref_bearing() {
    fn both(at_position: &dyn Fn(Term) -> Term, leaves: &(Term, Term)) -> (Term, Term) {
        (at_position(leaves.0.clone()), at_position(leaves.1.clone()))
    }
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let pd = pred_def_ty();
    let x = || lit_addr(&ca(1));
    let def_ref = |params: Vec<(VarId, Sort)>, body: Term, args: Vec<Term>| {
        let tt = c.type_check(params, body).expect("a def of the sort the position asks for");
        let addr = c.define_predicate(&doc1(), &tt).expect("define").0;
        Term::Ref { addr, args: args.into_iter().map(at).collect() }
    };
    // Per sort a position asks for: an ordinary term, and a reference of that sort.
    let boolean = (tru(), def_ref(vec![], tru(), vec![]));
    let address = (x(), def_ref(vec![], x(), vec![]));
    let set = (members(&pd), def_ref(vec![], members(&pd), vec![]));
    let nat = (lit_nat(1), def_ref(vec![], lit_nat(1), vec![]));
    let opt = (bot_addr(), def_ref(vec![], bot_addr(), vec![]));
    let seq = (chain(&sup, x()), def_ref(vec![], chain(&sup, x()), vec![]));
    // A map's one source is a `Map` parameter: every row checks under v8: Map.
    let map = (var(8), def_ref(vec![(v(1), Sort::Map)], var(1), vec![var(8)]));
    let fixed = |s: Term| Dom::SetTerm(at(s));
    let rows = [
        both(&|r| and(r, tru()), &boolean),
        both(&|r| and(tru(), r), &boolean),
        both(&|r| or(r, tru()), &boolean),
        both(&|r| or(tru(), r), &boolean),
        both(&|r| implies(r, tru()), &boolean),
        both(&|r| implies(tru(), r), &boolean),
        both(&|r| iff(r, tru()), &boolean),
        both(&|r| iff(tru(), r), &boolean),
        both(&not, &boolean),
        both(&|r| forall(5, Dom::LinkDom, r), &boolean),
        both(&|r| exists(5, Dom::LinkDom, r), &boolean),
        both(&|r| forall(7, Dom::Reg, r), &boolean),
        both(&|r| let_(5, lit_nat(1), r), &boolean),
        both(&|r| if_some(bot_addr(), 5, r, tru()), &boolean),
        both(&|r| if_some(bot_addr(), 5, tru(), r), &boolean),
        both(&|r| count(filter(Dom::LinkDom, 5, r)), &boolean),
        both(&|r| let_(5, r, tru()), &nat),
        both(&|r| nat_eq(r, lit_nat(1)), &nat),
        both(&|r| nat_eq(lit_nat(1), r), &nat),
        both(&|r| nat_le(r, lit_nat(1)), &nat),
        both(&|r| nat_le(lit_nat(1), r), &nat),
        both(&|r| nat_add(r, lit_nat(1)), &nat),
        both(&|r| nat_add(lit_nat(1), r), &nat),
        both(&|r| is_k(&pd, r), &address),
        both(&|r| targets_of(&pd, r), &address),
        both(&|r| is_filtered(&retired_ty(), r), &address),
        both(&|r| succs(&sup, r), &address),
        both(&|r| chain(&sup, r), &address),
        both(&|r| tip(&sup, r), &address),
        both(&|r| is_in_chain(&sup, r, x()), &address),
        both(&|r| is_in_chain(&sup, x(), r), &address),
        both(&is_doc, &address),
        both(&|r| exists(6, Dom::AuditSlice(concrete(&pd)), in_coverage_f(r, 6)), &address),
        both(&|r| exists(6, Dom::AuditSlice(concrete(&pd)), in_coverage_g(r, 6)), &address),
        both(&|r| addr_eq(r, x()), &address),
        both(&|r| addr_eq(x(), r), &address),
        both(&|r| prefix(r, x()), &address),
        both(&|r| prefix(x(), r), &address),
        both(&|r| t1_lt(r, x()), &address),
        both(&|r| t1_lt(x(), r), &address),
        both(&|r| set_mem(r, members(&pd)), &address),
        both(&|r| set_mem(x(), r), &set),
        both(&|r| set_eq(r, members(&pd)), &set),
        both(&|r| set_eq(members(&pd), r), &set),
        both(&is_empty, &set),
        both(&|r| big_union(Dom::LinkDom, 5, r), &set),
        both(&|r| big_union(fixed(r), 5, members(&pd)), &set),
        both(&|r| count(fixed(r)), &set),
        both(&|r| forall(5, fixed(r), tru()), &set),
        both(&|r| exists(5, fixed(r), tru()), &set),
        both(&|r| Term::MaxT1(ad(fixed(r))), &set),
        both(&|r| Term::MinT1(ad(fixed(r))), &set),
        both(&|r| reflect(fixed(r)), &set),
        both(&|r| count(filter(fixed(r), 5, tru())), &set),
        both(&|r| if_some(r, 5, tru(), tru()), &opt),
        both(&def, &opt),
        both(&elems, &seq),
        both(&|r| map_get(r, &pd), &map),
    ];
    let check = |t: &Term| c.type_check(vec![(v(8), Sort::Map)], t.clone()).expect("checks");
    for (ordinary, referring) in &rows {
        assert!(check(ordinary).is_ref_free(), "an ordinary term: {ordinary:?}");
        assert!(!check(referring).is_ref_free(), "a reference at this position: {referring:?}");
    }
}

/// V-STAT's behavior guard as a law over every atom that needs one: each
/// refuses a class whose registration lacks its behavior, naming the key and
/// the behavior, so no atom denotes a walk, a reverse lookup or an age over
/// tuples no registration declared able to answer it. `PredDef` declares none
/// of the four; the classes that declare one admit its atoms (`Walk` at the
/// shipped `Supersedes`, `ReadFilter` at `Retired`; nothing declares
/// `ReverseLookup` or `Age` in this format).
#[test]
fn every_behavior_atom_refuses_a_class_without_its_behavior() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let pd = pred_def_ty();
    let x = || lit_addr(&ca(1));
    let atom = |a: Atom| Term::Atom(a);
    for (t, needs) in [
        (is_filtered(&pd, x()), Behavior::ReadFilter),
        (succs(&pd, x()), Behavior::Walk),
        (chain(&pd, x()), Behavior::Walk),
        (tip(&pd, x()), Behavior::Walk),
        (is_in_chain(&pd, x(), x()), Behavior::Walk),
        (atom(Atom::SourcesTo(concrete(&pd), at(x()))), Behavior::ReverseLookup),
        (atom(Atom::TargetOf(concrete(&pd), at(x()))), Behavior::ReverseLookup),
        (atom(Atom::Age(concrete(&pd), at(x()))), Behavior::Age),
        (atom(Atom::Stale(concrete(&pd), at(lit_nat(1)))), Behavior::Age),
    ] {
        assert_eq!(
            c.type_check(vec![], t.clone()).err(),
            Some(TypeError::BehaviorMissing { ty: key(&pd), needs }),
            "{t:?}"
        );
    }
    for t in [
        is_filtered(&retired_ty(), x()),
        succs(&sup, x()),
        chain(&sup, x()),
        tip(&sup, x()),
        is_in_chain(&sup, x(), x()),
    ] {
        assert!(c.type_check(vec![], t.clone()).is_ok(), "{t:?}");
    }
}

/// A `Ref`'s referent speaks before its arguments in both of its parts —
/// whether it resolves, then how deep a walk through it reaches — so which
/// rejection speaks does not turn on whether the memo was warm. Cold, the
/// referent's derivation is refused at the level the reference asks for it
/// at; warm, the reach the reference is charged is refused at the same
/// point; an argument with a fault of its own is reached on neither, and the
/// same argument under a shallow reference shows the fault is real.
#[test]
fn a_reference_too_deep_for_its_referent_is_refused_before_its_arguments_warm_or_cold() {
    let k = kernel();
    let warm = coord(&k);
    // P(x) := ¬¹⁰⁰ ⊤, reach 100 — defined through `warm`, which memoizes it.
    let p_body = (0..100).fold(tru(), |t, _| not(t));
    let p_term = warm.type_check(vec![(v(1), Sort::Addr)], p_body).expect("P(x) := ¬¹⁰⁰ ⊤");
    let (p, _) = warm.define_predicate(&doc1(), &p_term).expect("define P");
    let reference = || Term::Ref { addr: p.clone(), args: vec![at(and(tru(), lit_nat(1)))] };
    // At level 27: P derives at 29 and would reach 129; the reference is
    // charged 27 + 2 + 1 + 100 = 130.
    let deep = (0..27).fold(reference(), |t, _| not(t));
    let cold = coord(&k);
    assert!(matches!(cold.type_check(vec![], deep.clone()), Err(TypeError::TooDeep)));
    assert!(matches!(warm.type_check(vec![], deep), Err(TypeError::TooDeep)));
    // At the root the reach fits, and the argument's own fault speaks.
    assert_eq!(
        warm.type_check(vec![], reference()).err(),
        Some(TypeError::SortMismatch { expected: Sort::Bool, found: Sort::Nat })
    );
}

/// The node budget: `Reg`-expansion instantiates a body once per cataloged
/// class, so nested `Reg` quantifiers multiply — six over a leaf fit, seven
/// do not (`TooLarge`, before the seventh level's 78 125 instances exist) —
/// and an `Arc`-shared body is charged per traversal, as the tree it
/// unfolds to: forty levels of `And(a, a)` are forty-one nodes to build and
/// 2⁴¹ to check, refused at the budget rather than after it.
#[test]
fn type_check_charges_reg_instances_and_shared_bodies_against_the_node_budget() {
    let k = kernel();
    let c = coord(&k);
    let nested_reg = |levels: u32| {
        (0..levels).rev().fold(tru(), |body, i| forall(10 + i, Dom::Reg, body))
    };
    c.type_check(vec![], nested_reg(6)).expect("six nested Reg quantifiers fit the budget");
    assert!(matches!(c.type_check(vec![], nested_reg(7)), Err(TypeError::TooLarge)));
    let mut shared = at(tru());
    for _ in 0..40 {
        shared = at(Term::And(shared.clone(), shared));
    }
    assert!(matches!(c.type_check(vec![], Term::And(shared.clone(), shared)), Err(TypeError::TooLarge)));
}

/// The budget bounds the tree's BYTES, not merely its node count: a `Reg`
/// quantifier instantiates its body once per cataloged class, so a literal
/// charged as one node would multiply by five per level while the node count
/// did not. One 128 KB natural checks on its own; under a single `Reg`
/// quantifier — nine nodes in all — the substitution spends the budget
/// instead.
#[test]
fn type_check_charges_a_literal_s_payload_against_the_node_budget() {
    let k = kernel();
    let c = coord(&k);
    let big = || Term::Lit(Lit::Nat(Nat::from_bytes_be(&vec![1u8; 1 << 17]))); // 2¹⁴ limbs
    c.type_check(vec![], nat_eq(big(), lit_nat(1)))
        .expect("one large literal is within the budget");
    assert!(matches!(
        c.type_check(vec![], forall(10, Dom::Reg, nat_eq(big(), lit_nat(1)))),
        Err(TypeError::TooLarge)
    ));
}

/// `TooLarge` names four payloads besides the node itself, and the checker
/// charges each where it meets it — not only a `Nat`'s limbs: a Γ_D
/// parameter, before anything is sized by the context's length, so an
/// over-long context is `TooLarge` even where it also repeats a name; a
/// literal address's components, once per `Reg` instance it is copied into;
/// and a `Ref`'s address, at the `Ref`'s own node, before its referent is
/// resolved. Each refused term fits the budget once its payload goes
/// uncharged.
#[test]
fn type_check_charges_every_payload_kind_against_the_node_budget() {
    let k = kernel();
    let c = coord(&k);
    let context = |n: u32| (1..=n).map(|i| (v(i), Sort::Bool)).collect::<Vec<_>>();
    c.type_check(context(60_000), tru()).expect("sixty thousand parameters fit the budget");
    let mut repeated = context(70_000);
    repeated.push((v(1), Sort::Bool));
    assert!(matches!(c.type_check(repeated, tru()), Err(TypeError::TooLarge)));

    let long = a(&vec![1u32; 1 << 13]); // 8 192 components, no separator: a node address
    c.type_check(vec![], is_doc(lit_addr(&long))).expect("one long literal fits");
    assert!(matches!(
        c.type_check(vec![], forall(10, Dom::Reg, is_doc(lit_addr(&long)))),
        Err(TypeError::TooLarge)
    ));

    let far = Term::Ref { addr: a(&vec![1u32; 1 << 16]), args: vec![] };
    assert!(matches!(c.type_check(vec![], far), Err(TypeError::TooLarge)));
}

/// The nesting cap is the checker's as it is the decoder's: `¬¹²⁸ ⊤`
/// checks and `¬¹²⁹ ⊤` is `TooDeep` — at the cap, before recursing further,
/// so a term nested thousands deep is refused on this default thread rather
/// than walked to its end. A `Reg` quantifier's instances sit under the join
/// chain `Reg`-expansion builds — one level per cataloged class past the first
/// — so the deepest instance, not the quantifier's own node, is what the cap
/// charges.
#[test]
fn type_check_refuses_a_term_nested_past_the_cap() {
    let k = kernel();
    let c = coord(&k);
    let nested = |n: usize| (0..n).fold(tru(), |t, _| not(t));
    c.type_check(vec![], nested(128)).expect("a term at the cap checks");
    assert!(matches!(c.type_check(vec![], nested(129)), Err(TypeError::TooDeep)));
    assert!(matches!(c.type_check(vec![], nested(2048)), Err(TypeError::TooDeep)));

    // Five shipped classes ⇒ a four-connective join, so a `Reg` quantifier at
    // level n has its instances at n + 4.
    let reg_at = |n: usize| (0..n).fold(forall(10, Dom::Reg, tru()), |t, _| not(t));
    c.type_check(vec![], reg_at(124)).expect("124 + 4 joins = 128: at the cap");
    assert!(matches!(c.type_check(vec![], reg_at(125)), Err(TypeError::TooDeep)));
}

/// The DOMAIN family carries the checker's recursion on its own — a `Filter`
/// chain descends to the innermost domain before any `pred` is checked — so
/// it has a resource door of its own, and a supplied term is charged for
/// every domain former as for every term former. A body of 2¹⁴ leaves, each
/// `∃x ∈ {y ∈ L_dom | ⊤} :: ⊤`, is 2¹⁶ − 1 term formers beside 2¹⁵ domain
/// formers: within the budget were the domains free, `TooLarge` when they
/// are charged — and a body of half the leaves halves all of them, so the
/// refusal is the budget's and not the shape's. The chain then pins the
/// nesting boundary on the same family.
#[test]
fn type_check_charges_the_domain_family_and_caps_its_nesting() {
    let k = kernel();
    let c = coord(&k);
    // Three term formers and two domain formers per leaf, joined by `and`.
    let leaves = |l: u32| {
        let leaf = || exists(2, filter(Dom::LinkDom, 3, tru()), tru());
        let mut t = leaf();
        for _ in 0..l.trailing_zeros() {
            t = Term::And(at(t.clone()), at(t));
        }
        t
    };
    assert!(matches!(c.type_check(vec![], leaves(1 << 14)), Err(TypeError::TooLarge)));
    c.type_check(vec![], leaves(1 << 13)).expect("half the leaves is half of each count");

    // `count` at 0, filter k at k, the innermost `L_dom` at n + 1.
    let filters = |n: usize| (0..n).fold(Dom::LinkDom, |d, _| filter(d, 2, tru()));
    c.type_check(vec![], count(filters(127))).expect("a domain chain at the cap checks");
    assert!(matches!(c.type_check(vec![], count(filters(128))), Err(TypeError::TooDeep)));
}

/// A `Ref`'s arguments are spliced into the flat expansion's `Let` chain at
/// their OWN positions, so argument `i` expands `i` levels below the
/// reference — a depth the reach formula's `arity` term charges once, at the
/// referent's splice point, and never per argument. Charged at one level they
/// would admit a term whose expansion is `arity + argument depth` deep, and
/// hand it to `view_independent` and `st_plus`, which walk it with no bound of
/// their own; chained with descending arities that reaches ~7,900 levels from
/// ~8,000 nodes and overflows the caller's stack. Two nested calls fit and
/// certify; a third, and one deep argument, do not.
#[test]
fn a_reference_s_arguments_are_charged_at_their_expansion_positions() {
    let k = kernel();
    let c = coord(&k);
    const ARITY: u32 = 60;
    let params: Vec<(VarId, Sort)> = (1..=ARITY).map(|i| (v(i), Sort::Bool)).collect();
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(params, tru()).expect("P(b1..b60) := ⊤"))
        .expect("define P");
    // A call whose LAST argument is `last`; the other 59 are ⊤.
    let call = |last: Term| Term::Ref {
        addr: p.clone(),
        args: (1..ARITY).map(|_| at(tru())).chain([at(last)]).collect(),
    };
    // Two nested calls expand to 59 + 60 = 119 `Let`s over the inner body.
    let two = c.type_check(vec![], call(call(tru()))).expect("two levels fit");
    let (two_start, _) = c.define_predicate(&doc1(), &two).expect("define");
    c.certify_stable(&doc1(), &two_start).expect("its 120-level expansion analyzes");
    // A third level would expand 60 levels further; each one adds 59 more.
    assert!(matches!(c.type_check(vec![], call(call(call(tru())))), Err(TypeError::TooDeep)));
    // The same arithmetic for one deep argument: at position 59 it expands 59
    // levels below the reference, so its own 100 put the expansion at 160.
    let deep = (0..100).fold(tru(), |t, _| not(t));
    assert!(matches!(c.type_check(vec![], call(deep)), Err(TypeError::TooDeep)));
}

/// V-IDX: `count(Reg)` folds to the (constant) registered-class count;
/// Reg-quantifiers expand per class; an instance-wise ill-typed body rejects
/// whole.
#[test]
fn reg_expansion_folds_count_instantiates_per_class_and_refuses_an_ill_typed_instance() {
    let k = kernel();
    let c = coord(&k);
    let writer = link_writer(&k);

    // The whole population: the shipped five.
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::Reg), lit_nat(5))));

    // ∃K∈Reg :: is_K(x) — false while x heads no cataloged class, true once
    // a tuple lands in one (the other instances denote ⊥ harmlessly).
    let ex = c
        .type_check(
            vec![(v(1), Sort::Addr)],
            Term::Exists {
                var: v(7),
                dom: ad(Dom::Reg),
                body: at(Term::Atom(Atom::IsK(TypeRef::ClassVar(v(7)), at(var(1))))),
            },
        )
        .expect("Reg-quantified IsK body type-checks");
    let args = [Value::Addr(ca(5))];
    assert!(!c.decide(&ex, &args, View::Active, &k.snapshot()));
    writer.emit(Caller::System, &doc1(), &pred_def_ty(), &ca(5), &[]).expect("pred_def emit");
    assert!(c.decide(&ex, &args, View::Active, &k.snapshot()));

    // A class-indexed behavior atom at the bound class dies by instantiation
    // (some instance lacks the behavior) — RegInstanceIllTyped, naming the
    // FIRST ill-typed instance in catalog order: only Retired declares BH1,
    // so it is the second class's, Supersedes'.
    assert_eq!(
        c.type_check(
            vec![(v(1), Sort::Addr)],
            Term::Forall {
                var: v(7),
                dom: ad(Dom::Reg),
                body: at(Term::Atom(Atom::IsFiltered(TypeRef::ClassVar(v(7)), at(var(1))))),
            },
        )
        .err(),
        Some(TypeError::RegInstanceIllTyped(Box::new(TypeError::BehaviorMissing {
            ty: key(c.reserved_type(ShippedType::Supersedes)),
            needs: Behavior::ReadFilter,
        })))
    );
}

/// V-IDX scoping: an inner `Reg` binder that reuses the outer's name
/// shadows it, so the body reads the inner class — `∃K :: ∀K :: is_K(x)`
/// is the universal, false for an address heading one class of five —
/// while a distinct inner name leaves the body to the outer existential.
#[test]
fn an_inner_reg_binder_shadows_the_outer() {
    let k = kernel();
    let c = coord(&k);
    link_writer(&k).emit(Caller::System, &doc1(), &pred_def_ty(), &ca(5), &[]).expect("pred_def on ca5");
    let is_k7 = || Term::Atom(Atom::IsK(TypeRef::ClassVar(v(7)), at(var(1))));
    let shadowed = c
        .type_check(vec![(v(1), Sort::Addr)], exists(7, Dom::Reg, forall(7, Dom::Reg, is_k7())))
        .expect("∃K :: ∀K :: is_K(x)");
    let distinct = c
        .type_check(vec![(v(1), Sort::Addr)], exists(7, Dom::Reg, forall(8, Dom::Reg, is_k7())))
        .expect("∃K :: ∀K' :: is_K(x)");
    let args = [Value::Addr(ca(5))];
    let s = k.snapshot();
    assert!(!c.decide(&shadowed, &args, View::Active, &s));
    assert!(c.decide(&distinct, &args, View::Active, &s));
}

/// A checked term keeps its SOURCE body — `Reg` quantifiers and class
/// variables intact — beside the Reg-expanded projection the evaluator
/// walks; that compact form is what `define_predicate` stores, and its Γ_D
/// is the ordered context the check was made under. A trigger reports the
/// same three of itself.
#[test]
fn a_checked_term_reports_its_source_body_and_its_ordered_context() {
    let k = kernel();
    let c = coord(&k);
    let body = || exists(7, Dom::Reg, Term::Atom(Atom::IsK(TypeRef::ClassVar(v(7)), at(var(1)))));
    let tt = c.type_check(vec![(v(1), Sort::Addr)], body()).expect("Reg-quantified");
    assert_eq!(tt.source_body(), &body(), "the pre-Reg-expansion body, verbatim");
    assert_eq!(tt.params(), &[(v(1), Sort::Addr)]);
    assert_eq!(tt.result_sort(), Sort::Bool);
    assert!(tt.is_ref_free());
    let trig = c.type_check_trigger((v(1), Sort::Addr), body()).expect("trigger");
    assert_eq!(trig.param(), &(v(1), Sort::Addr));
    assert_eq!(trig.source_body(), &body());
    assert!(trig.is_ref_free());
}

/// The catalog probe is `Endset`-equality, not coverage: a key spelling the
/// canonical endset twice has the same coverage class and misses as
/// `UncatalogedTypeKey` — its class is cataloged; its key is not.
#[test]
fn a_coverage_equal_but_byte_different_key_misses() {
    let k = kernel();
    let c = coord(&k);
    let canonical = pred_def_ty();
    let dup = Endset::from_spans(canonical.spans().cloned().chain(canonical.spans().cloned()));
    assert_ne!(dup, canonical);
    assert_eq!(coverage_class(&dup), coverage_class(&canonical));
    assert!(matches!(
        c.type_check(vec![], Term::Atom(Atom::Members(TypeRef::Concrete(TypeKey(dup))))),
        Err(TypeError::UncatalogedTypeKey(_))
    ));
    assert!(c.type_check(vec![], members(&canonical)).is_ok());
}
