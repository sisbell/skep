//! §Internal 4 (PR3/PR3a) — the expander: `expand(start)`, the one
//! syntax-directed transform that removes `Ref` nodes from a checked def
//! body, yielding its flat reference expansion for the analyses that are not
//! compositional over references (ST⁺ certification, the rule lint's trigger
//! leg, the armer graph). Evaluation never uses it — a def's denotation is
//! DAG-recursive (Conflicts §5); the static analyses alone need the
//! materialized flat term.
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

use crate::ast::{ArcTerm, Dom, Term, VarId};
use crate::eval::DefSource;
use crate::walk::{rewrite_dom, rewrite_term, Rewrite};

/// One expansion's fresh-name counter — the ONE mint site for reserved
/// names, so an expansion's name sequence is a function of its content.
struct Supply(u32);

impl Supply {
    fn fresh(&mut self) -> VarId {
        let v = VarId::expansion(self.0);
        self.0 += 1;
        v
    }
}

/// The expander (ASN-0130): one expansion's state — the referent supplier
/// and the fresh-name supply. Build one per top-level expansion
/// (`certify_stable`'s and the rule engine's each start at zero — PR3's
/// determinism is per expansion).
pub(crate) struct Expander<'a> {
    defs: &'a dyn DefSource,
    supply: Supply,
}

impl<'a> Expander<'a> {
    pub(crate) fn new(defs: &'a dyn DefSource) -> Expander<'a> {
        Expander { defs, supply: Supply(0) }
    }

    /// `expand` — the flat reference expansion of a checked (every `Ref`
    /// resolvable) body.
    pub(crate) fn expand(&mut self, t: &Term) -> Term {
        self.term(t)
    }
}

impl Rewrite for Expander<'_> {
    /// The one node the expansion acts on; every other former falls through.
    fn term(&mut self, t: &Term) -> Term {
        let Term::Ref { addr, args } = t else {
            return rewrite_term(self, t);
        };
        // Bottom-up: the arguments first, left to right.
        let flat_args: Vec<Term> = args.iter().map(|a| self.term(a)).collect();
        let referent = self
            .defs
            .resolve_def(addr)
            .unwrap_or_else(|| unreachable!("WT-ref: a checked body's referent has a defined signature"));
        // The node: fresh names for the referent's parameters first, in
        // signature order …
        let fresh: Vec<VarId> = referent.params().iter().map(|_| self.supply.fresh()).collect();
        // … then its (recursively expanded) body's binders, depth-first
        // left-to-right.
        let inner_flat = self.term(&referent.evaluable);
        let map: im::HashMap<VarId, VarId> =
            referent.params().iter().map(|(p, _)| *p).zip(fresh.iter().copied()).collect();
        let mut out = Rename { supply: &mut self.supply, map }.term(&inner_flat);
        for (fr, arg) in fresh.into_iter().zip(flat_args).rev() {
            out = Term::Let { var: fr, bound: Arc::new(arg), body: Arc::new(out) };
        }
        out
    }
}

/// The α-renaming of an already-flat (ref-free) referent body: `map` on free
/// occurrences, and a fresh reserved name for every internal binder,
/// depth-first left-to-right (PR3's binding-site renaming).
struct Rename<'a> {
    supply: &'a mut Supply,
    map: im::HashMap<VarId, VarId>,
}

impl Rename<'_> {
    /// Rewrite `body` in the scope of the binder `var`: mint its fresh name,
    /// extend the map for the in-scope child, restore for whatever follows.
    fn under(&mut self, var: VarId, body: &Term) -> (VarId, ArcTerm) {
        let fresh = self.supply.fresh();
        let inner = self.map.update(var, fresh);
        let outer = std::mem::replace(&mut self.map, inner);
        let renamed = Arc::new(self.term(body));
        self.map = outer;
        (fresh, renamed)
    }
}

impl Rewrite for Rename<'_> {
    fn var_use(&mut self, v: &VarId) -> VarId {
        self.map.get(v).copied().unwrap_or(*v)
    }

    /// The binding formers: out-of-scope children first, under the current
    /// map; then the binder, freshly named, over its in-scope child.
    fn term(&mut self, t: &Term) -> Term {
        match t {
            Term::Forall { var, dom, body } => {
                let dom = Arc::new(self.dom(dom));
                let (var, body) = self.under(*var, body);
                Term::Forall { var, dom, body }
            }
            Term::Exists { var, dom, body } => {
                let dom = Arc::new(self.dom(dom));
                let (var, body) = self.under(*var, body);
                Term::Exists { var, dom, body }
            }
            Term::Let { var, bound, body } => {
                let bound = Arc::new(self.term(bound));
                let (var, body) = self.under(*var, body);
                Term::Let { var, bound, body }
            }
            Term::IfSome { opt, var, then_, else_ } => {
                let opt = Arc::new(self.term(opt));
                let (var, then_) = self.under(*var, then_);
                let else_ = Arc::new(self.term(else_));
                Term::IfSome { opt, var, then_, else_ }
            }
            Term::BigUnion { dom, var, body } => {
                let dom = Arc::new(self.dom(dom));
                let (var, body) = self.under(*var, body);
                Term::BigUnion { dom, var, body }
            }
            Term::Ref { .. } => unreachable!("rename runs on flat (ref-free) referent bodies"),
            _ => rewrite_term(self, t),
        }
    }

    fn dom(&mut self, d: &Dom) -> Dom {
        match d {
            Dom::Filter { dom, var, pred } => {
                let dom = Arc::new(self.dom(dom));
                let (var, pred) = self.under(*var, pred);
                Dom::Filter { dom, var, pred }
            }
            _ => rewrite_dom(self, d),
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn expands_a_reference_with_fresh_disjoint_names() {
        let p = ad(&[1, 0, 1, 0, 1, 0, 1, 1]);
        // P(x) := ∃ y ∈ L_dom :: y = x — the binder `y` is v(2), as the
        // host's is.
        let body = Term::Exists {
            var: v(2),
            dom: Arc::new(Dom::LinkDom),
            body: Arc::new(addr_eq(Term::Var(v(2)), Term::Var(v(1)))),
        };
        let referent = TypedTerm {
            signed: SignedTerm { params: vec![(v(1), Sort::Addr)], body: body.clone() },
            result: Sort::Bool,
            evaluable: Arc::new(body),
            ref_free: true,
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
                var: x0,
                bound: Arc::new(Term::Var(v(2))),
                body: Arc::new(Term::Exists {
                    var: x1,
                    dom: Arc::new(Dom::LinkDom),
                    body: Arc::new(addr_eq(Term::Var(x1), Term::Var(x0))),
                }),
            }),
        };
        assert_eq!(Expander::new(&stub).expand(&host), expected);
        assert_eq!(Expander::new(&stub).expand(&host), expected, "deterministic per expansion");
    }
}
