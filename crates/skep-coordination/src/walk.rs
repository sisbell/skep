//! §Core data model — the two generic structural walks over the PL tree: the
//! ONE statement of which children each node has. A structure-preserving
//! transform implements [`Rewrite`], a structural query implements [`Visit`];
//! each overrides only the positions its semantics touch and falls through to
//! the defaults for the rest. Adding a former to `ast.rs` is one arm in each
//! of [`rewrite_term`]/[`visit_term`] (or their `Dom` twins) and one in each
//! SEMANTIC pass — `check`, `codec`, the `Analyzer`, `eval` — never a further
//! hand-written recursion.
//!
//! Children are walked left to right in declaration order, and a binder's
//! out-of-scope children (a quantifier's domain, a `Let`'s bound term, an
//! `IfSome`'s guard) before its in-scope ones — the order a counter-carrying
//! rewrite (the flat expansion's fresh-name supply) is deterministic in.

use std::sync::Arc;

use crate::ast::{ArcDom, ArcTerm, Atom, Dom, Prim, Term, TypeRef, VarId};

/// A structure-preserving rewrite. The defaults rebuild a node with every
/// child rewritten; binders are copied VERBATIM, so a scope-aware rewrite
/// overrides [`Rewrite::term`] for the five binding formers (`Forall`/
/// `Exists`/`Let`/`IfSome`/`BigUnion`) and [`Rewrite::dom`] for
/// `Dom::Filter`, and falls through for the rest.
pub(crate) trait Rewrite {
    fn term(&mut self, t: &Term) -> Term {
        rewrite_term(self, t)
    }

    fn dom(&mut self, d: &Dom) -> Dom {
        rewrite_dom(self, d)
    }

    /// A type position — an atom's, a prim's or a domain's `TypeRef`.
    fn typeref(&mut self, tr: &TypeRef) -> TypeRef {
        tr.clone()
    }

    /// A variable USE — a `Var` node or a V-TUP atom's tuple variable —
    /// never a binder.
    fn var_use(&mut self, v: &VarId) -> VarId {
        v.clone()
    }
}

fn arc<R: Rewrite + ?Sized>(r: &mut R, t: &ArcTerm) -> ArcTerm {
    Arc::new(r.term(t))
}

fn arcd<R: Rewrite + ?Sized>(r: &mut R, d: &ArcDom) -> ArcDom {
    Arc::new(r.dom(d))
}

/// The default term rewrite: every child through `r`, the node rebuilt.
pub(crate) fn rewrite_term<R: Rewrite + ?Sized>(r: &mut R, t: &Term) -> Term {
    match t {
        Term::Var(v) => Term::Var(r.var_use(v)),
        Term::Lit(l) => Term::Lit(l.clone()),
        Term::Atom(a) => Term::Atom(match a {
            Atom::IsK(tr, e) => Atom::IsK(r.typeref(tr), arc(r, e)),
            Atom::Members(tr) => Atom::Members(r.typeref(tr)),
            Atom::TargetsOf(tr, e) => Atom::TargetsOf(r.typeref(tr), arc(r, e)),
            Atom::IsFiltered(tr, e) => Atom::IsFiltered(r.typeref(tr), arc(r, e)),
            Atom::Succs(tr, e) => Atom::Succs(r.typeref(tr), arc(r, e)),
            Atom::Chain(tr, e) => Atom::Chain(r.typeref(tr), arc(r, e)),
            Atom::Tip(tr, e) => Atom::Tip(r.typeref(tr), arc(r, e)),
            Atom::IsInChain(tr, x, y) => Atom::IsInChain(r.typeref(tr), arc(r, x), arc(r, y)),
            Atom::SourcesTo(tr, e) => Atom::SourcesTo(r.typeref(tr), arc(r, e)),
            Atom::TargetOf(tr, e) => Atom::TargetOf(r.typeref(tr), arc(r, e)),
            Atom::TargetsKeyed(e) => Atom::TargetsKeyed(arc(r, e)),
            Atom::Age(tr, e) => Atom::Age(r.typeref(tr), arc(r, e)),
            Atom::Stale(tr, e) => Atom::Stale(r.typeref(tr), arc(r, e)),
            Atom::IsDoc(e) => Atom::IsDoc(arc(r, e)),
            Atom::TupAddr(v) => Atom::TupAddr(r.var_use(v)),
            Atom::TupAddrsF(v) => Atom::TupAddrsF(r.var_use(v)),
            Atom::TupAddrsG(v) => Atom::TupAddrsG(r.var_use(v)),
            Atom::InCoverageF(e, v) => Atom::InCoverageF(arc(r, e), r.var_use(v)),
            Atom::InCoverageG(e, v) => Atom::InCoverageG(arc(r, e), r.var_use(v)),
        }),
        Term::Prim(p) => Term::Prim(match p {
            Prim::AddrEq(x, y) => Prim::AddrEq(arc(r, x), arc(r, y)),
            Prim::Prefix(x, y) => Prim::Prefix(arc(r, x), arc(r, y)),
            Prim::T1Lt(x, y) => Prim::T1Lt(arc(r, x), arc(r, y)),
            Prim::SetMem(x, y) => Prim::SetMem(arc(r, x), arc(r, y)),
            Prim::SetEq(x, y) => Prim::SetEq(arc(r, x), arc(r, y)),
            Prim::IsEmpty(x) => Prim::IsEmpty(arc(r, x)),
            Prim::Elems(x) => Prim::Elems(arc(r, x)),
            Prim::NatEq(x, y) => Prim::NatEq(arc(r, x), arc(r, y)),
            Prim::NatLe(x, y) => Prim::NatLe(arc(r, x), arc(r, y)),
            Prim::NatAdd(x, y) => Prim::NatAdd(arc(r, x), arc(r, y)),
            Prim::MapGet(m, tr) => Prim::MapGet(arc(r, m), r.typeref(tr)),
            Prim::Def(x) => Prim::Def(arc(r, x)),
        }),
        Term::And(x, y) => Term::And(arc(r, x), arc(r, y)),
        Term::Or(x, y) => Term::Or(arc(r, x), arc(r, y)),
        Term::Not(x) => Term::Not(arc(r, x)),
        Term::Implies(x, y) => Term::Implies(arc(r, x), arc(r, y)),
        Term::Iff(x, y) => Term::Iff(arc(r, x), arc(r, y)),
        Term::Forall { var, dom, body } => {
            Term::Forall { var: var.clone(), dom: arcd(r, dom), body: arc(r, body) }
        }
        Term::Exists { var, dom, body } => {
            Term::Exists { var: var.clone(), dom: arcd(r, dom), body: arc(r, body) }
        }
        Term::Let { var, bound, body } => {
            Term::Let { var: var.clone(), bound: arc(r, bound), body: arc(r, body) }
        }
        Term::IfSome { opt, var, then_, else_ } => Term::IfSome {
            opt: arc(r, opt),
            var: var.clone(),
            then_: arc(r, then_),
            else_: arc(r, else_),
        },
        Term::Count(d) => Term::Count(arcd(r, d)),
        Term::MaxT1(d) => Term::MaxT1(arcd(r, d)),
        Term::MinT1(d) => Term::MinT1(arcd(r, d)),
        Term::BigUnion { dom, var, body } => {
            Term::BigUnion { dom: arcd(r, dom), var: var.clone(), body: arc(r, body) }
        }
        Term::Reflect(d) => Term::Reflect(arcd(r, d)),
        Term::Ref { addr, args } => {
            Term::Ref { addr: addr.clone(), args: args.iter().map(|a| arc(r, a)).collect() }
        }
    }
}

/// The default domain rewrite: every child through `r`, the node rebuilt.
pub(crate) fn rewrite_dom<R: Rewrite + ?Sized>(r: &mut R, d: &Dom) -> Dom {
    match d {
        Dom::MembersDom(tr) => Dom::MembersDom(r.typeref(tr)),
        Dom::ActiveSlice(tr) => Dom::ActiveSlice(r.typeref(tr)),
        Dom::AuditSlice(tr) => Dom::AuditSlice(r.typeref(tr)),
        Dom::LinkDom => Dom::LinkDom,
        Dom::Reg => Dom::Reg,
        Dom::Filter { dom, var, pred } => {
            Dom::Filter { dom: arcd(r, dom), var: var.clone(), pred: arc(r, pred) }
        }
        Dom::SetTerm(t) => Dom::SetTerm(arc(r, t)),
    }
}

/// A structural fold. The defaults visit every child; override to act at a
/// node and (usually) fall through.
pub(crate) trait Visit {
    fn term(&mut self, t: &Term) {
        visit_term(self, t)
    }

    fn dom(&mut self, d: &Dom) {
        visit_dom(self, d)
    }
}

/// The default term visit: every child through `v`.
pub(crate) fn visit_term<V: Visit + ?Sized>(v: &mut V, t: &Term) {
    match t {
        Term::Var(_) | Term::Lit(_) => {}
        Term::Atom(a) => match a {
            Atom::IsK(_, e)
            | Atom::TargetsOf(_, e)
            | Atom::IsFiltered(_, e)
            | Atom::Succs(_, e)
            | Atom::Chain(_, e)
            | Atom::Tip(_, e)
            | Atom::SourcesTo(_, e)
            | Atom::TargetOf(_, e)
            | Atom::TargetsKeyed(e)
            | Atom::Age(_, e)
            | Atom::Stale(_, e)
            | Atom::IsDoc(e)
            | Atom::InCoverageF(e, _)
            | Atom::InCoverageG(e, _) => v.term(e),
            Atom::IsInChain(_, x, y) => {
                v.term(x);
                v.term(y);
            }
            Atom::Members(_) | Atom::TupAddr(_) | Atom::TupAddrsF(_) | Atom::TupAddrsG(_) => {}
        },
        Term::Prim(p) => match p {
            Prim::AddrEq(x, y)
            | Prim::Prefix(x, y)
            | Prim::T1Lt(x, y)
            | Prim::SetMem(x, y)
            | Prim::SetEq(x, y)
            | Prim::NatEq(x, y)
            | Prim::NatLe(x, y)
            | Prim::NatAdd(x, y) => {
                v.term(x);
                v.term(y);
            }
            Prim::IsEmpty(x) | Prim::Elems(x) | Prim::Def(x) | Prim::MapGet(x, _) => v.term(x),
        },
        Term::And(x, y) | Term::Or(x, y) | Term::Implies(x, y) | Term::Iff(x, y) => {
            v.term(x);
            v.term(y);
        }
        Term::Not(x) => v.term(x),
        Term::Forall { dom, body, .. } | Term::Exists { dom, body, .. } => {
            v.dom(dom);
            v.term(body);
        }
        Term::Let { bound, body, .. } => {
            v.term(bound);
            v.term(body);
        }
        Term::IfSome { opt, then_, else_, .. } => {
            v.term(opt);
            v.term(then_);
            v.term(else_);
        }
        Term::Count(d) | Term::MaxT1(d) | Term::MinT1(d) | Term::Reflect(d) => v.dom(d),
        Term::BigUnion { dom, body, .. } => {
            v.dom(dom);
            v.term(body);
        }
        Term::Ref { args, .. } => {
            for a in args {
                v.term(a);
            }
        }
    }
}

/// The default domain visit: every child through `v`.
pub(crate) fn visit_dom<V: Visit + ?Sized>(v: &mut V, d: &Dom) {
    match d {
        Dom::MembersDom(_) | Dom::ActiveSlice(_) | Dom::AuditSlice(_) | Dom::LinkDom | Dom::Reg => {}
        Dom::Filter { dom, pred, .. } => {
            v.dom(dom);
            v.term(pred);
        }
        Dom::SetTerm(t) => v.term(t),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::fixture::every_former;

    /// The two walks state one tree: the identity rewrite reproduces every
    /// former (a child passed twice or to the wrong slot would show), and a
    /// node count taken through `Visit` equals one taken through `Rewrite`
    /// (a child skipped by either walk would show).
    #[test]
    fn the_two_walks_agree_on_every_former() {
        struct Identity(usize);
        impl Rewrite for Identity {
            fn term(&mut self, t: &Term) -> Term {
                self.0 += 1;
                rewrite_term(self, t)
            }
        }
        struct Count(usize);
        impl Visit for Count {
            fn term(&mut self, t: &Term) {
                self.0 += 1;
                visit_term(self, t)
            }
        }
        let body = every_former().body;
        let mut id = Identity(0);
        assert_eq!(id.term(&body), body);
        let mut count = Count(0);
        count.term(&body);
        assert_eq!(count.0, id.0);
        assert!(count.0 > 60, "the fixture spans every former");
    }
}
