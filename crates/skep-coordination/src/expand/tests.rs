use std::collections::HashMap;

use skep_address::{validate, Address, Nat, Tumbler};

use super::*;
use crate::ast::Prim;
use crate::check::TypedTerm;
use crate::value::{SignedTerm, Sort};

/// A referent table standing in for the memo.
struct Stub(HashMap<Tumbler, Arc<TypedTerm>>);

impl DefSource for Stub {
    fn resolve_def(&self, addr: &Address) -> Option<Arc<TypedTerm>> {
        self.0.get(addr.tumbler()).cloned()
    }
}

fn v(x: u32) -> VarId {
    VarId::new(x).expect("test var below the watershed")
}

fn a(comps: &[u32]) -> Address {
    validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty"))
        .expect("T4-valid")
}

fn addr_eq(x: Term, y: Term) -> Term {
    Term::Prim(Prim::AddrEq(Arc::new(x), Arc::new(y)))
}

/// PR3/PR3a on one node: the referent's parameter takes the first fresh
/// name (signature order), its binder the next (depth-first), the
/// arguments bind through `Let`, and the host's own binder — spelled
/// with the SAME source name as the referent's — is untouched, so the
/// expansion captures nothing. Deterministic: a second expansion is
/// equal.
#[test]
fn expands_a_reference_with_fresh_disjoint_names() {
    let p = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
    // P(x) := ∃ y ∈ L_dom :: y = x — the binder `y` is v(2), as the
    // host's is.
    let body = Term::Exists {
        var: v(2),
        dom: Arc::new(Dom::LinkDom),
        body: Arc::new(addr_eq(Term::Var(v(2)), Term::Var(v(1)))),
    };
    let referent = TypedTerm::from_parts(
        SignedTerm { params: vec![(v(1), Sort::Addr)], body: body.clone() },
        Sort::Bool,
        Arc::new(body),
        true, // ref-free
        2,    // reach
    );
    let stub = Stub(HashMap::from([(p.tumbler().clone(), Arc::new(referent))]));
    // Host: ∃ y ∈ L_dom :: P(y).
    let host = Term::Exists {
        var: v(2),
        dom: Arc::new(Dom::LinkDom),
        body: Arc::new(Term::Ref { addr: p.clone(), args: vec![Arc::new(Term::Var(v(2)))] }),
    };

    let x0 = VarId::expansion(0); // P's parameter
    let x1 = VarId::expansion(1); // P's binder
    let expected = Term::Exists {
        var: v(2),
        dom: Arc::new(Dom::LinkDom),
        body: Arc::new(Term::Let {
            var: x0,
            bound: Arc::new(Term::Var(v(2))),
            body: Arc::new(Term::Exists {
                var: x1,
                dom: Arc::new(Dom::LinkDom),
                body: Arc::new(addr_eq(Term::Var(x1), Term::Var(x0))),
            }),
        }),
    };
    assert_eq!(Expander::new(&stub).expand(&host), Ok(expected.clone()));
    assert_eq!(Expander::new(&stub).expand(&host), Ok(expected), "deterministic per expansion");
}

/// PR3's renaming over EVERY binding position — the four binding term
/// formers and `Dom::Filter` — in one expansion: the referent's
/// parameters take the first fresh names in signature order, its binders
/// follow depth-first left to right, and each binder's IN-SCOPE child
/// alone sees the extended map, so an `IfSome`'s else-branch still reads
/// the enclosing `Let`'s name. The host's arguments are left as they
/// stand, though they are spelled with the referent's own parameter
/// names, so the `Let` chain binds the fresh names and captures nothing.
#[test]
fn every_binding_position_takes_a_fresh_name_in_its_own_scope() {
    let p = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
    // P(x, o) := let z = x in ⋃(y ∈ {w ∈ L_dom | w = z}, if some z = o
    // then z else z) — the inner `z` shadows the outer only in `then_`.
    let body = Term::Let {
        var: v(3),
        bound: Arc::new(Term::Var(v(1))),
        body: Arc::new(Term::BigUnion {
            dom: Arc::new(Dom::Filter {
                dom: Arc::new(Dom::LinkDom),
                var: v(4),
                pred: Arc::new(addr_eq(Term::Var(v(4)), Term::Var(v(3)))),
            }),
            var: v(5),
            body: Arc::new(Term::IfSome {
                opt: Arc::new(Term::Var(v(2))),
                var: v(3),
                then_: Arc::new(Term::Var(v(3))),
                else_: Arc::new(Term::Var(v(3))),
            }),
        }),
    };
    let referent = TypedTerm::from_parts(
        SignedTerm {
            params: vec![(v(1), Sort::Addr), (v(2), Sort::OptAddr)],
            body: body.clone(),
        },
        Sort::AddrSet,
        Arc::new(body),
        true, // ref-free
        5,    // reach
    );
    let stub = Stub(HashMap::from([(p.tumbler().clone(), Arc::new(referent))]));
    // The host spells its arguments with the referent's OWN parameter
    // names, which the expansion must not touch.
    let host = Term::Ref {
        addr: p.clone(),
        args: vec![Arc::new(Term::Var(v(1))), Arc::new(Term::Var(v(2)))],
    };

    let x = |n: u32| VarId::expansion(n);
    let (x0, x1) = (x(0), x(1)); // P's two parameters, in signature order
    let (x2, x3, x4, x5) = (x(2), x(3), x(4), x(5)); // Let, Filter, ⋃, IfSome
    let expected = Term::Let {
        var: x0,
        bound: Arc::new(Term::Var(v(1))),
        body: Arc::new(Term::Let {
            var: x1,
            bound: Arc::new(Term::Var(v(2))),
            body: Arc::new(Term::Let {
                var: x2,
                bound: Arc::new(Term::Var(x0)),
                body: Arc::new(Term::BigUnion {
                    dom: Arc::new(Dom::Filter {
                        dom: Arc::new(Dom::LinkDom),
                        var: x3,
                        pred: Arc::new(addr_eq(Term::Var(x3), Term::Var(x2))),
                    }),
                    var: x4,
                    body: Arc::new(Term::IfSome {
                        opt: Arc::new(Term::Var(x1)),
                        var: x5,
                        then_: Arc::new(Term::Var(x5)),
                        // The else-branch is OUTSIDE the guard's binder.
                        else_: Arc::new(Term::Var(x2)),
                    }),
                }),
            }),
        }),
    };
    assert_eq!(Expander::new(&stub).expand(&host), Ok(expected));
}

/// The expansion charges a DOMAIN former as it charges a term, in both of its
/// walks — the expansion and the α-renaming — so the domain family is
/// bounded at this door as at the decoder's and the checker's. Each leaf of
/// the referent (structural, as every stub here is: the expander reads no
/// sort) is `count` over three nested filters of `L_dom` — four term formers
/// and four domain formers — joined by `∧`, and both walks charge every one:
/// 2 048 leaves fit (36 871 units) and 4 096 do not (73 735), where without
/// either walk's domain charge they would (57 351).
#[test]
fn the_expansion_charges_domain_formers_in_both_walks() {
    let p = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
    let stub = |leaves: u32| {
        let mut d = Dom::LinkDom;
        for _ in 0..3 {
            d = Dom::Filter { dom: Arc::new(d), var: v(2), pred: Arc::new(Term::Lit(Lit::True)) };
        }
        let mut body = Term::Count(Arc::new(d));
        for _ in 0..leaves.trailing_zeros() {
            body = Term::And(Arc::new(body.clone()), Arc::new(body));
        }
        let referent = TypedTerm::from_parts(
            SignedTerm { params: vec![], body: body.clone() },
            Sort::Bool,
            Arc::new(body),
            true, // ref-free
            0,    // reach: the expander does not read it
        );
        Stub(HashMap::from([(p.tumbler().clone(), Arc::new(referent))]))
    };
    let host = Term::Ref { addr: p.clone(), args: vec![] };
    assert!(Expander::new(&stub(2048)).expand(&host).is_ok(), "2 048 leaves fit the budget");
    assert!(
        matches!(Expander::new(&stub(4096)).expand(&host), Err(ExpansionTooLarge)),
        "4 096 leaves expanded within the budget"
    );
}
