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
//!
//! The flat tree is a TREE: PR3's fresh-name discipline forbids sharing, so
//! a referent used twice is expanded twice, and a reference DAG unfolds
//! exponentially in its depth. The expansion is therefore budgeted, in
//! [`MAX_TERM_NODES`] — every node either walk visits or builds is charged,
//! with the payload it carries ([`weight`]), since a literal's tumbler is
//! copied whole into every unfolding — and past the budget neither walk
//! descends further: the result is [`ExpansionTooLarge`], never a tree the
//! analyses would then traverse.

use std::sync::Arc;

use crate::ast::{weight, ArcTerm, Dom, Lit, Term, VarId, MAX_TERM_NODES};
use crate::eval::DefSource;
use crate::walk::{rewrite_dom, rewrite_term, Rewrite};

/// The expansion outgrew [`MAX_TERM_NODES`]: the reference DAG's unfolding
/// is past the tree the analyses are budgeted to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpansionTooLarge;

/// One expansion's state: the fresh-name counter — the ONE mint site for
/// reserved names, so an expansion's name sequence is a function of its
/// content — and the node budget, one sum across the expander's walk and
/// the renamer's, sticky once spent.
struct Budget {
    next: u32,
    nodes: usize,
    exhausted: bool,
}

impl Budget {
    fn fresh(&mut self) -> VarId {
        let v = VarId::expansion(self.next);
        self.next += 1;
        v
    }

    /// A charge of `weight` units — a node and the payload it carries
    /// ([`weight`]): `false` once the budget is spent, and thereafter.
    fn charge(&mut self, weight: usize) -> bool {
        self.nodes = self.nodes.saturating_add(weight);
        if self.nodes > MAX_TERM_NODES {
            self.exhausted = true;
        }
        !self.exhausted
    }
}

/// The expander (ASN-0130): one expansion's state — the referent supplier
/// and the budget. Build one per top-level expansion (`certify_stable`'s
/// and the rule engine's each start at zero — PR3's determinism is per
/// expansion).
pub(crate) struct Expander<'a> {
    defs: &'a dyn DefSource,
    budget: Budget,
}

impl<'a> Expander<'a> {
    pub(crate) fn new(defs: &'a dyn DefSource) -> Expander<'a> {
        Expander { defs, budget: Budget { next: 0, nodes: 0, exhausted: false } }
    }

    /// `expand` — the flat reference expansion of a checked (every `Ref`
    /// resolvable) body, or `ExpansionTooLarge` once the budget is spent.
    pub(crate) fn expand(&mut self, t: &Term) -> Result<Term, ExpansionTooLarge> {
        let out = self.term(t);
        if self.budget.exhausted {
            Err(ExpansionTooLarge)
        } else {
            Ok(out)
        }
    }
}

impl Rewrite for Expander<'_> {
    /// The one node the expansion acts on; every other former falls through.
    /// Past the budget: a stub, and no descent.
    fn term(&mut self, t: &Term) -> Term {
        if !self.budget.charge(weight(t)) {
            return Term::Lit(Lit::True);
        }
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
        let fresh_names: Vec<VarId> = referent.params().iter().map(|_| self.budget.fresh()).collect();
        // … then its (recursively expanded) body's binders, depth-first
        // left-to-right.
        let inner_flat = self.term(&referent.evaluable);
        let map: im::HashMap<VarId, VarId> =
            referent.params().iter().map(|(p, _)| *p).zip(fresh_names.iter().copied()).collect();
        let mut out = Rename { budget: &mut self.budget, map }.term(&inner_flat);
        for (fresh, arg) in fresh_names.into_iter().zip(flat_args).rev() {
            out = Term::Let { var: fresh, bound: Arc::new(arg), body: Arc::new(out) };
        }
        out
    }

    fn dom(&mut self, d: &Dom) -> Dom {
        if !self.budget.charge(1) {
            return Dom::LinkDom;
        }
        rewrite_dom(self, d)
    }
}

/// The α-renaming of an already-flat (ref-free) referent body: `map` on free
/// occurrences, and a fresh reserved name for every internal binder,
/// depth-first left-to-right (PR3's binding-site renaming). Charges the
/// expansion's budget per node and per unit of payload, as the expander does.
struct Rename<'a> {
    budget: &'a mut Budget,
    map: im::HashMap<VarId, VarId>,
}

impl Rename<'_> {
    /// Rewrite `body` in the scope of the binder `var`: mint its fresh name,
    /// extend the map for the in-scope child, restore for whatever follows.
    fn under(&mut self, var: VarId, body: &Term) -> (VarId, ArcTerm) {
        let fresh = self.budget.fresh();
        let inner = self.map.update(var, fresh);
        let outer = std::mem::replace(&mut self.map, inner);
        let renamed = Arc::new(self.term(body));
        self.map = outer;
        (fresh, renamed)
    }
}

impl Rewrite for Rename<'_> {
    fn var_use(&mut self, v: VarId) -> VarId {
        self.map.get(&v).copied().unwrap_or(v)
    }

    /// The binding formers: out-of-scope children first, under the current
    /// map; then the binder, freshly named, over its in-scope child. Past
    /// the budget: a stub, and no descent.
    fn term(&mut self, t: &Term) -> Term {
        if !self.budget.charge(weight(t)) {
            return Term::Lit(Lit::True);
        }
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
        if !self.budget.charge(1) {
            return Dom::LinkDom;
        }
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
        let referent = TypedTerm {
            signed: SignedTerm { params: vec![(v(1), Sort::Addr)], body: body.clone() },
            result: Sort::Bool,
            evaluable: Arc::new(body),
            ref_free: true,
            reach: 2,
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
        assert_eq!(Expander::new(&stub).expand(&host), Ok(expected.clone()));
        assert_eq!(Expander::new(&stub).expand(&host), Ok(expected), "deterministic per expansion");
    }
}
