//! §Internal 4 (PR3/PR3a) — the flat reference expansion: the one
//! syntax-directed transform that removes `Ref` nodes from a checked def
//! body, for the analyses that are not compositional over references
//! (ST⁺ certification, the rule lint's trigger leg, the armer graph).
//! Evaluation never uses it — `evaluate_def`'s denotation is DAG-recursive
//! (Conflicts §5); certification alone needs the materialized flat term.
//!
//! Reference nodes are processed bottom-up (arguments before the node).
//! Fresh names are drawn from the reserved `VarId ≥ EXPANSION_NAME_BASE`
//! supply by ONE content-deterministic counter per top-level expansion — at
//! each reference node the referent's parameters first (signature order),
//! then its binders depth-first left-to-right — so the expansion is
//! deterministic and its names are disjoint from every host binder by
//! construction. A reference node is realized as `Let`-bindings of its
//! (expanded) arguments over the α-renamed referent body.

use std::sync::Arc;

use crate::ast::{ArcDom, ArcTerm, Atom, Dom, Prim, Term, VarId};
use crate::eval::DefSource;

/// One expansion's state: the referent supplier and the fresh-name counter.
/// Build one per top-level expansion (`certify_stable`'s and the rule
/// engine's each start at zero — PR3's determinism is per expansion).
pub(crate) struct Flattener<'a> {
    defs: &'a dyn DefSource,
    next: u32,
}

impl<'a> Flattener<'a> {
    pub(crate) fn new(defs: &'a dyn DefSource) -> Flattener<'a> {
        Flattener { defs, next: 0 }
    }

    /// The ONE mint site: the next reserved name off this expansion's
    /// counter.
    fn fresh(&mut self) -> VarId {
        let v = VarId::expansion(self.next);
        self.next += 1;
        v
    }

    /// The flat expansion of a checked (every `Ref` resolvable) body.
    pub(crate) fn flatten(&mut self, t: &Term) -> Term {
        match t {
            Term::Ref { addr, args } => {
                // Bottom-up: the arguments first, left to right.
                let flat_args: Vec<Term> = args.iter().map(|a| self.flatten(a)).collect();
                let referent = self
                    .defs
                    .resolve_def(addr)
                    .unwrap_or_else(|| {
                        unreachable!("WT-ref: a checked body's referent has a defined signature")
                    });
                // The node: fresh names for the referent's parameters first,
                // in signature order …
                let fresh: Vec<VarId> = referent.sig.params.iter().map(|_| self.fresh()).collect();
                // … then its (recursively flattened) body's binders,
                // depth-first left-to-right.
                let inner_flat = self.flatten(&referent.expanded);
                let mut map: im::HashMap<VarId, VarId> = im::HashMap::new();
                for ((p, _), fr) in referent.sig.params.iter().zip(fresh.iter()) {
                    map.insert(p.clone(), fr.clone());
                }
                let mut out = self.rename(&inner_flat, &map);
                for (fr, arg) in fresh.into_iter().zip(flat_args).rev() {
                    out = Term::Let { var: fr, bound: Arc::new(arg), body: Arc::new(out) };
                }
                out
            }
            Term::Var(_) | Term::Lit(_) => t.clone(),
            Term::Atom(a) => Term::Atom(match a {
                Atom::IsK(tr, e) => Atom::IsK(tr.clone(), self.f(e)),
                Atom::Members(tr) => Atom::Members(tr.clone()),
                Atom::TargetsOf(tr, e) => Atom::TargetsOf(tr.clone(), self.f(e)),
                Atom::IsFiltered(tr, e) => Atom::IsFiltered(tr.clone(), self.f(e)),
                Atom::Succs(tr, e) => Atom::Succs(tr.clone(), self.f(e)),
                Atom::Chain(tr, e) => Atom::Chain(tr.clone(), self.f(e)),
                Atom::Tip(tr, e) => Atom::Tip(tr.clone(), self.f(e)),
                Atom::IsInChain(tr, x, y) => Atom::IsInChain(tr.clone(), self.f(x), self.f(y)),
                Atom::SourcesTo(tr, e) => Atom::SourcesTo(tr.clone(), self.f(e)),
                Atom::TargetOf(tr, e) => Atom::TargetOf(tr.clone(), self.f(e)),
                Atom::TargetsKeyed(e) => Atom::TargetsKeyed(self.f(e)),
                Atom::Age(tr, e) => Atom::Age(tr.clone(), self.f(e)),
                Atom::Stale(tr, e) => Atom::Stale(tr.clone(), self.f(e)),
                Atom::IsDoc(e) => Atom::IsDoc(self.f(e)),
                Atom::TupAddr(v) => Atom::TupAddr(v.clone()),
                Atom::TupAddrsF(v) => Atom::TupAddrsF(v.clone()),
                Atom::TupAddrsG(v) => Atom::TupAddrsG(v.clone()),
                Atom::InCoverageF(e, v) => Atom::InCoverageF(self.f(e), v.clone()),
                Atom::InCoverageG(e, v) => Atom::InCoverageG(self.f(e), v.clone()),
            }),
            Term::Prim(p) => Term::Prim(match p {
                Prim::AddrEq(x, y) => Prim::AddrEq(self.f(x), self.f(y)),
                Prim::Prefix(x, y) => Prim::Prefix(self.f(x), self.f(y)),
                Prim::T1Lt(x, y) => Prim::T1Lt(self.f(x), self.f(y)),
                Prim::SetMem(x, y) => Prim::SetMem(self.f(x), self.f(y)),
                Prim::SetEq(x, y) => Prim::SetEq(self.f(x), self.f(y)),
                Prim::IsEmpty(x) => Prim::IsEmpty(self.f(x)),
                Prim::Elems(x) => Prim::Elems(self.f(x)),
                Prim::NatEq(x, y) => Prim::NatEq(self.f(x), self.f(y)),
                Prim::NatLe(x, y) => Prim::NatLe(self.f(x), self.f(y)),
                Prim::NatAdd(x, y) => Prim::NatAdd(self.f(x), self.f(y)),
                Prim::MapGet(m, tr) => Prim::MapGet(self.f(m), tr.clone()),
                Prim::Def(x) => Prim::Def(self.f(x)),
            }),
            Term::And(x, y) => Term::And(self.f(x), self.f(y)),
            Term::Or(x, y) => Term::Or(self.f(x), self.f(y)),
            Term::Not(x) => Term::Not(self.f(x)),
            Term::Implies(x, y) => Term::Implies(self.f(x), self.f(y)),
            Term::Iff(x, y) => Term::Iff(self.f(x), self.f(y)),
            Term::Forall { var, dom, body } => {
                Term::Forall { var: var.clone(), dom: self.fd(dom), body: self.f(body) }
            }
            Term::Exists { var, dom, body } => {
                Term::Exists { var: var.clone(), dom: self.fd(dom), body: self.f(body) }
            }
            Term::Let { var, bound, body } => {
                Term::Let { var: var.clone(), bound: self.f(bound), body: self.f(body) }
            }
            Term::IfSome { opt, var, then_, else_ } => Term::IfSome {
                opt: self.f(opt),
                var: var.clone(),
                then_: self.f(then_),
                else_: self.f(else_),
            },
            Term::Count(d) => Term::Count(self.fd(d)),
            Term::MaxT1(d) => Term::MaxT1(self.fd(d)),
            Term::MinT1(d) => Term::MinT1(self.fd(d)),
            Term::BigUnion { dom, var, body } => {
                Term::BigUnion { dom: self.fd(dom), var: var.clone(), body: self.f(body) }
            }
            Term::Reflect(d) => Term::Reflect(self.fd(d)),
        }
    }

    fn f(&mut self, x: &ArcTerm) -> ArcTerm {
        Arc::new(self.flatten(x))
    }

    fn fd(&mut self, d: &ArcDom) -> ArcDom {
        Arc::new(self.flatten_dom(d))
    }

    fn flatten_dom(&mut self, d: &Dom) -> Dom {
        match d {
            Dom::MembersDom(_) | Dom::ActiveSlice(_) | Dom::AuditSlice(_) | Dom::LinkDom | Dom::Reg => {
                d.clone()
            }
            Dom::Filter { dom, var, pred } => {
                Dom::Filter { dom: self.fd(dom), var: var.clone(), pred: self.f(pred) }
            }
            Dom::SetTerm(t) => Dom::SetTerm(self.f(t)),
        }
    }

    /// α-rename an already-flat (ref-free) referent body: substitute `map`
    /// on free occurrences, and give every internal binder a fresh reserved
    /// name, depth-first left-to-right (PR3's binding-site renaming).
    fn rename(&mut self, t: &Term, map: &im::HashMap<VarId, VarId>) -> Term {
        let rv = |v: &VarId| map.get(v).cloned().unwrap_or_else(|| v.clone());
        match t {
            Term::Var(v) => Term::Var(rv(v)),
            Term::Lit(_) => t.clone(),
            Term::Atom(a) => Term::Atom(match a {
                Atom::IsK(tr, e) => Atom::IsK(tr.clone(), self.r(e, map)),
                Atom::Members(tr) => Atom::Members(tr.clone()),
                Atom::TargetsOf(tr, e) => Atom::TargetsOf(tr.clone(), self.r(e, map)),
                Atom::IsFiltered(tr, e) => Atom::IsFiltered(tr.clone(), self.r(e, map)),
                Atom::Succs(tr, e) => Atom::Succs(tr.clone(), self.r(e, map)),
                Atom::Chain(tr, e) => Atom::Chain(tr.clone(), self.r(e, map)),
                Atom::Tip(tr, e) => Atom::Tip(tr.clone(), self.r(e, map)),
                Atom::IsInChain(tr, x, y) => {
                    Atom::IsInChain(tr.clone(), self.r(x, map), self.r(y, map))
                }
                Atom::SourcesTo(tr, e) => Atom::SourcesTo(tr.clone(), self.r(e, map)),
                Atom::TargetOf(tr, e) => Atom::TargetOf(tr.clone(), self.r(e, map)),
                Atom::TargetsKeyed(e) => Atom::TargetsKeyed(self.r(e, map)),
                Atom::Age(tr, e) => Atom::Age(tr.clone(), self.r(e, map)),
                Atom::Stale(tr, e) => Atom::Stale(tr.clone(), self.r(e, map)),
                Atom::IsDoc(e) => Atom::IsDoc(self.r(e, map)),
                Atom::TupAddr(v) => Atom::TupAddr(rv(v)),
                Atom::TupAddrsF(v) => Atom::TupAddrsF(rv(v)),
                Atom::TupAddrsG(v) => Atom::TupAddrsG(rv(v)),
                Atom::InCoverageF(e, v) => Atom::InCoverageF(self.r(e, map), rv(v)),
                Atom::InCoverageG(e, v) => Atom::InCoverageG(self.r(e, map), rv(v)),
            }),
            Term::Prim(p) => Term::Prim(match p {
                Prim::AddrEq(x, y) => Prim::AddrEq(self.r(x, map), self.r(y, map)),
                Prim::Prefix(x, y) => Prim::Prefix(self.r(x, map), self.r(y, map)),
                Prim::T1Lt(x, y) => Prim::T1Lt(self.r(x, map), self.r(y, map)),
                Prim::SetMem(x, y) => Prim::SetMem(self.r(x, map), self.r(y, map)),
                Prim::SetEq(x, y) => Prim::SetEq(self.r(x, map), self.r(y, map)),
                Prim::IsEmpty(x) => Prim::IsEmpty(self.r(x, map)),
                Prim::Elems(x) => Prim::Elems(self.r(x, map)),
                Prim::NatEq(x, y) => Prim::NatEq(self.r(x, map), self.r(y, map)),
                Prim::NatLe(x, y) => Prim::NatLe(self.r(x, map), self.r(y, map)),
                Prim::NatAdd(x, y) => Prim::NatAdd(self.r(x, map), self.r(y, map)),
                Prim::MapGet(m, tr) => Prim::MapGet(self.r(m, map), tr.clone()),
                Prim::Def(x) => Prim::Def(self.r(x, map)),
            }),
            Term::And(x, y) => Term::And(self.r(x, map), self.r(y, map)),
            Term::Or(x, y) => Term::Or(self.r(x, map), self.r(y, map)),
            Term::Not(x) => Term::Not(self.r(x, map)),
            Term::Implies(x, y) => Term::Implies(self.r(x, map), self.r(y, map)),
            Term::Iff(x, y) => Term::Iff(self.r(x, map), self.r(y, map)),
            Term::Forall { var, dom, body } => {
                let d2 = self.rename_dom(dom, map);
                let v2 = self.fresh();
                let m2 = map.update(var.clone(), v2.clone());
                Term::Forall { var: v2, dom: Arc::new(d2), body: self.r(body, &m2) }
            }
            Term::Exists { var, dom, body } => {
                let d2 = self.rename_dom(dom, map);
                let v2 = self.fresh();
                let m2 = map.update(var.clone(), v2.clone());
                Term::Exists { var: v2, dom: Arc::new(d2), body: self.r(body, &m2) }
            }
            Term::Let { var, bound, body } => {
                let b2 = self.r(bound, map);
                let v2 = self.fresh();
                let m2 = map.update(var.clone(), v2.clone());
                Term::Let { var: v2, bound: b2, body: self.r(body, &m2) }
            }
            Term::IfSome { opt, var, then_, else_ } => {
                let o2 = self.r(opt, map);
                let v2 = self.fresh();
                let m2 = map.update(var.clone(), v2.clone());
                Term::IfSome { opt: o2, var: v2, then_: self.r(then_, &m2), else_: self.r(else_, map) }
            }
            Term::Count(d) => Term::Count(Arc::new(self.rename_dom(d, map))),
            Term::MaxT1(d) => Term::MaxT1(Arc::new(self.rename_dom(d, map))),
            Term::MinT1(d) => Term::MinT1(Arc::new(self.rename_dom(d, map))),
            Term::BigUnion { dom, var, body } => {
                let d2 = self.rename_dom(dom, map);
                let v2 = self.fresh();
                let m2 = map.update(var.clone(), v2.clone());
                Term::BigUnion { dom: Arc::new(d2), var: v2, body: self.r(body, &m2) }
            }
            Term::Reflect(d) => Term::Reflect(Arc::new(self.rename_dom(d, map))),
            Term::Ref { .. } => unreachable!("rename runs on flattened (ref-free) bodies"),
        }
    }

    fn r(&mut self, x: &ArcTerm, map: &im::HashMap<VarId, VarId>) -> ArcTerm {
        Arc::new(self.rename(x, map))
    }

    fn rename_dom(&mut self, d: &Dom, map: &im::HashMap<VarId, VarId>) -> Dom {
        match d {
            Dom::MembersDom(_) | Dom::ActiveSlice(_) | Dom::AuditSlice(_) | Dom::LinkDom | Dom::Reg => {
                d.clone()
            }
            Dom::Filter { dom, var, pred } => {
                let base = self.rename_dom(dom, map);
                let v2 = self.fresh();
                let m2 = map.update(var.clone(), v2.clone());
                Dom::Filter { dom: Arc::new(base), var: v2, pred: self.r(pred, &m2) }
            }
            Dom::SetTerm(t) => Dom::SetTerm(self.r(t, map)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use skep_address::{validate, Address, Nat, Tumbler};

    use super::*;
    use crate::memo::DefEntry;
    use crate::value::{Signature, Sort};

    /// A referent table standing in for the memo.
    struct Stub(HashMap<Tumbler, Arc<DefEntry>>);

    impl DefSource for Stub {
        fn resolve_def(&self, addr: &Address) -> Option<Arc<DefEntry>> {
            self.0.get(addr.tumbler()).cloned()
        }
    }

    fn v(x: u32) -> VarId {
        VarId::new(x).expect("test var below the watershed")
    }

    fn ad(comps: &[u32]) -> Address {
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
    fn flattens_a_reference_with_fresh_disjoint_names() {
        let p = ad(&[1, 0, 1, 0, 1, 0, 1, 1]);
        // P(x) := ∃ y ∈ L_dom :: y = x — the binder `y` is v(2), as the
        // host's is.
        let referent = DefEntry {
            sig: Signature { params: vec![(v(1), Sort::Addr)], result: Sort::Bool },
            expanded: Arc::new(Term::Exists {
                var: v(2),
                dom: Arc::new(Dom::LinkDom),
                body: Arc::new(addr_eq(Term::Var(v(2)), Term::Var(v(1)))),
            }),
        };
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
                var: x0.clone(),
                bound: Arc::new(Term::Var(v(2))),
                body: Arc::new(Term::Exists {
                    var: x1.clone(),
                    dom: Arc::new(Dom::LinkDom),
                    body: Arc::new(addr_eq(Term::Var(x1), Term::Var(x0))),
                }),
            }),
        };
        assert_eq!(Flattener::new(&stub).flatten(&host), expected);
        assert_eq!(Flattener::new(&stub).flatten(&host), expected, "deterministic per expansion");
    }
}
