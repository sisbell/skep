//! Shared term builders: PL formers spelled as short functions so a test
//! reads as the claim it states, plus the closed-term verdict helper and the
//! two rule fixtures every engine test starts from. Each builder is a
//! one-line constructor over the public AST; a suite module imports the lot
//! and uses what it needs.

#![allow(dead_code)] // each suite module uses a subset

use std::sync::Arc;

use skep_address::Address;
use skep_coordination::{
    ArcDom, ArcTerm, Atom, Coordinator, Dom, Env, FireAction, Lit, Prim, Sort, Term, Trigger,
    TypeKey, TypeRef, VarId, View,
};
use skep_kernel::Kernel;
use skep_links::Endset;

use crate::common::{doc1, marker_ty, n, World};

pub fn v(x: u32) -> VarId {
    VarId::new(x).expect("test var below the watershed")
}

pub fn at(x: Term) -> ArcTerm {
    Arc::new(x)
}

pub fn ad(x: Dom) -> ArcDom {
    Arc::new(x)
}

pub fn key(e: &Endset) -> TypeKey {
    TypeKey(e.clone())
}

pub fn conc(e: &Endset) -> TypeRef {
    TypeRef::Concrete(key(e))
}

// ───────────────────────────── literals & vars ─────────────────────────────

pub fn var(x: u32) -> Term {
    Term::Var(v(x))
}

pub fn tru() -> Term {
    Term::Lit(Lit::True)
}

pub fn fls() -> Term {
    Term::Lit(Lit::False)
}

pub fn lit_addr(a: &Address) -> Term {
    Term::Lit(Lit::Addr(a.clone()))
}

pub fn lit_nat(x: u32) -> Term {
    Term::Lit(Lit::Nat(n(x)))
}

pub fn bot_addr() -> Term {
    Term::Lit(Lit::BotAddr)
}

pub fn bot_nat() -> Term {
    Term::Lit(Lit::BotNat)
}

// ─────────────────────────────── connectives ───────────────────────────────

pub fn not(x: Term) -> Term {
    Term::Not(at(x))
}

pub fn and(x: Term, y: Term) -> Term {
    Term::And(at(x), at(y))
}

pub fn or(x: Term, y: Term) -> Term {
    Term::Or(at(x), at(y))
}

pub fn implies(x: Term, y: Term) -> Term {
    Term::Implies(at(x), at(y))
}

pub fn iff(x: Term, y: Term) -> Term {
    Term::Iff(at(x), at(y))
}

// ───────────────────────────── binders & folds ─────────────────────────────

pub fn exists(vv: u32, d: Dom, b: Term) -> Term {
    Term::Exists { var: v(vv), dom: ad(d), body: at(b) }
}

pub fn forall(vv: u32, d: Dom, b: Term) -> Term {
    Term::Forall { var: v(vv), dom: ad(d), body: at(b) }
}

pub fn let_(vv: u32, bound: Term, body: Term) -> Term {
    Term::Let { var: v(vv), bound: at(bound), body: at(body) }
}

pub fn if_some(opt: Term, vv: u32, then_: Term, else_: Term) -> Term {
    Term::IfSome { opt: at(opt), var: v(vv), then_: at(then_), else_: at(else_) }
}

pub fn count(d: Dom) -> Term {
    Term::Count(ad(d))
}

/// `count` of a ℘_fin(T)-valued term, through the QD set-term closure.
pub fn count_set(t: Term) -> Term {
    count(Dom::SetTerm(at(t)))
}

pub fn big_union(d: Dom, vv: u32, body: Term) -> Term {
    Term::BigUnion { dom: ad(d), var: v(vv), body: at(body) }
}

pub fn reflect(d: Dom) -> Term {
    Term::Reflect(ad(d))
}

pub fn filter(d: Dom, vv: u32, pred: Term) -> Dom {
    Dom::Filter { dom: ad(d), var: v(vv), pred: at(pred) }
}

// ───────────────────────────────── prims ─────────────────────────────────

pub fn nat_eq(x: Term, y: Term) -> Term {
    Term::Prim(Prim::NatEq(at(x), at(y)))
}

pub fn nat_le(x: Term, y: Term) -> Term {
    Term::Prim(Prim::NatLe(at(x), at(y)))
}

pub fn nat_add(x: Term, y: Term) -> Term {
    Term::Prim(Prim::NatAdd(at(x), at(y)))
}

pub fn addr_eq(x: Term, y: Term) -> Term {
    Term::Prim(Prim::AddrEq(at(x), at(y)))
}

pub fn prefix(x: Term, y: Term) -> Term {
    Term::Prim(Prim::Prefix(at(x), at(y)))
}

pub fn t1_lt(x: Term, y: Term) -> Term {
    Term::Prim(Prim::T1Lt(at(x), at(y)))
}

pub fn set_mem(x: Term, s: Term) -> Term {
    Term::Prim(Prim::SetMem(at(x), at(s)))
}

pub fn set_eq(x: Term, y: Term) -> Term {
    Term::Prim(Prim::SetEq(at(x), at(y)))
}

pub fn is_empty(s: Term) -> Term {
    Term::Prim(Prim::IsEmpty(at(s)))
}

pub fn elems(q: Term) -> Term {
    Term::Prim(Prim::Elems(at(q)))
}

pub fn def_(x: Term) -> Term {
    Term::Prim(Prim::Def(at(x)))
}

// ───────────────────────────────── atoms ─────────────────────────────────

pub fn is_k_t(e: &Endset, x: Term) -> Term {
    Term::Atom(Atom::IsK(conc(e), at(x)))
}

pub fn members(e: &Endset) -> Term {
    Term::Atom(Atom::Members(conc(e)))
}

pub fn targets_of(e: &Endset, x: Term) -> Term {
    Term::Atom(Atom::TargetsOf(conc(e), at(x)))
}

pub fn is_filtered(e: &Endset, x: Term) -> Term {
    Term::Atom(Atom::IsFiltered(conc(e), at(x)))
}

pub fn succs(e: &Endset, x: Term) -> Term {
    Term::Atom(Atom::Succs(conc(e), at(x)))
}

pub fn chain(e: &Endset, x: Term) -> Term {
    Term::Atom(Atom::Chain(conc(e), at(x)))
}

pub fn tip(e: &Endset, x: Term) -> Term {
    Term::Atom(Atom::Tip(conc(e), at(x)))
}

/// `tip(e, x) = y` — the head, narrowed through the binder guard; false at
/// an indeterminate head.
pub fn tip_is(e: &Endset, x: &Address, y: &Address) -> Term {
    if_some(tip(e, lit_addr(x)), 2, addr_eq(var(2), lit_addr(y)), fls())
}

pub fn is_in_chain(e: &Endset, x: Term, y: Term) -> Term {
    Term::Atom(Atom::IsInChain(conc(e), at(x), at(y)))
}

pub fn is_doc(x: Term) -> Term {
    Term::Atom(Atom::IsDoc(at(x)))
}

pub fn tup_addr(vv: u32) -> Term {
    Term::Atom(Atom::TupAddr(v(vv)))
}

pub fn tup_addrs_f(vv: u32) -> Term {
    Term::Atom(Atom::TupAddrsF(v(vv)))
}

pub fn tup_addrs_g(vv: u32) -> Term {
    Term::Atom(Atom::TupAddrsG(v(vv)))
}

pub fn in_cov_f(x: Term, vv: u32) -> Term {
    Term::Atom(Atom::InCoverageF(at(x), v(vv)))
}

pub fn in_cov_g(x: Term, vv: u32) -> Term {
    Term::Atom(Atom::InCoverageG(at(x), v(vv)))
}

// ─────────────────────────── verdicts & fixtures ───────────────────────────

/// type_check a closed Bool term and decide it at (view, fresh snapshot).
pub fn decide_now(k: &Arc<Kernel<World>>, c: &Coordinator<World>, view: View, t: Term) -> bool {
    let tt = c.type_check(vec![], t).expect("test term type-checks");
    let s = k.snapshot();
    c.decide(&tt, &Env::empty(), view, &s)
}

/// The always-true one-`Addr`-parameter trigger.
pub fn always_addr(c: &Coordinator<World>) -> Trigger {
    Trigger::Inline(c.type_check_trigger((v(1), Sort::Addr), tru()).expect("always-true trigger"))
}

/// The always-true one-`Tup`-parameter trigger.
pub fn always_tup(c: &Coordinator<World>) -> Trigger {
    Trigger::Inline(c.type_check_trigger((v(1), Sort::Tup), tru()).expect("always-true Tup trigger"))
}

/// The canonical certifiable trigger `¬is_K(marker, x)` — the marker class
/// the suite's Marker action emits, so the fire falsifies it in place.
pub fn not_marked(c: &Coordinator<World>) -> Trigger {
    Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Addr), not(is_k_t(&marker_ty(), var(1))))
            .expect("¬is_K(marker, x)"),
    )
}

/// The Marker action at doc1 in the shipped Retired class — the one
/// cataloged Unary idem⊤ class outside the PredLayer pair.
pub fn marker_action() -> FireAction {
    FireAction::Marker { home: doc1(), ty: key(&marker_ty()) }
}
