//! §Internal 4 (PR3/PR3a) — the expander: `expand(start)`, the one
//! syntax-directed transform that removes `Ref` nodes from a checked def
//! body, yielding its flat reference expansion for the analyses that are not
//! compositional over references (ST⁺ certification, the rule lint's trigger
//! leg, the armer graph). Evaluation never uses it — a def's denotation is
//! DAG-recursive (Conflicts §5); the static analyses alone need the
//! materialized flat term.
//!
//! The flat tree is no deeper than [`crate::budget::MAX_DEPTH`]: the checker charged every
//! node at a level no shallower than the position its expansion occupies —
//! each argument at its own `Let` position in the chain below, the referent's
//! body past the whole chain — and recorded the maximum as
//! `TypedTerm::reach`. So the analyses that walk this tree need no depth
//! parameter of their own, and neither does the recursive `Drop` that frees
//! it.
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
//! exponentially in its depth. The expansion is therefore budgeted, against
//! the shared node [`Budget`] — every node either walk visits or builds is
//! charged, with the payload it carries ([`weight`]), since a literal's
//! tumbler is copied whole into every unfolding — and past the budget neither
//! walk descends further: the result is [`ExpansionTooLarge`], never a tree
//! the analyses would then traverse.

use std::sync::Arc;

use crate::ast::{ArcTerm, Dom, Lit, Term, VarId};
use crate::budget::{weight, Budget};
use crate::eval::DefSource;
use crate::walk::{rewrite_dom, rewrite_term, Rewrite};

/// The expansion spent its node [`Budget`]: the reference DAG's unfolding is
/// past the tree the analyses are budgeted to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpansionTooLarge;

/// One expansion's state, shared by the expander's walk and the renamer's:
/// the fresh-name counter — the ONE mint site for reserved names, so an
/// expansion's name sequence is a function of its content — and the node
/// budget, one sum across both walks.
struct State {
    next: u32,
    nodes: Budget,
}

impl State {
    fn fresh(&mut self) -> VarId {
        let v = VarId::expansion(self.next);
        self.next += 1;
        v
    }
}

/// The expander (ASN-0130): one expansion's referent supplier and state.
/// Build one per top-level expansion (`certify_stable`'s and the rule
/// engine's each start at zero — PR3's determinism is per expansion).
pub(crate) struct Expander<'a> {
    defs: &'a dyn DefSource,
    state: State,
}

impl<'a> Expander<'a> {
    pub(crate) fn new(defs: &'a dyn DefSource) -> Expander<'a> {
        Expander { defs, state: State { next: 0, nodes: Budget::default() } }
    }

    /// `expand` — the flat reference expansion of a checked (every `Ref`
    /// resolvable) body, or `ExpansionTooLarge` once the budget is spent.
    pub(crate) fn expand(&mut self, t: &Term) -> Result<Term, ExpansionTooLarge> {
        let out = self.term(t);
        if self.state.nodes.spent() {
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
        if !self.state.nodes.charge(weight(t)) {
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
        let fresh_names: Vec<VarId> = referent.params().iter().map(|_| self.state.fresh()).collect();
        // … then its (recursively expanded) body's binders, depth-first
        // left-to-right.
        let inner_flat = self.term(&referent.evaluable);
        let map: im::HashMap<VarId, VarId> =
            referent.params().iter().map(|(p, _)| *p).zip(fresh_names.iter().copied()).collect();
        let mut out = Rename { state: &mut self.state, map }.term(&inner_flat);
        for (fresh, arg) in fresh_names.into_iter().zip(flat_args).rev() {
            out = Term::Let { var: fresh, bound: Arc::new(arg), body: Arc::new(out) };
        }
        out
    }

    fn dom(&mut self, d: &Dom) -> Dom {
        if !self.state.nodes.charge(1) {
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
    state: &'a mut State,
    map: im::HashMap<VarId, VarId>,
}

impl Rename<'_> {
    /// Rewrite `body` in the scope of the binder `var`: mint its fresh name,
    /// extend the map for the in-scope child, restore for whatever follows.
    fn under(&mut self, var: VarId, body: &Term) -> (VarId, ArcTerm) {
        let fresh = self.state.fresh();
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
        if !self.state.nodes.charge(weight(t)) {
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
        if !self.state.nodes.charge(1) {
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
        let referent = TypedTerm {
            signed: SignedTerm {
                params: vec![(v(1), Sort::Addr), (v(2), Sort::OptAddr)],
                body: body.clone(),
            },
            result: Sort::AddrSet,
            evaluable: Arc::new(body),
            ref_free: true,
            reach: 5,
        };
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
}
