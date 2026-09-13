//! §Internal 1 — the type checker: a single bottom-up synthesis pass over the
//! raw `Term`, checked under the caller-supplied ordered parameter context
//! Γ_D (ASN-0129 WT is a Γ-parameterized CHECKING judgment), with `Reg`
//! expansion (V-IDX), the catalog + behavior guards (V-STAT), and WT-ref via
//! the signature resolver. Decided once at construction, valid at every
//! reachable state (WT).
//!
//! The pass is also the crate's two resource doors for a term, stored or
//! supplied: it refuses a tree that nests past [`MAX_DEPTH`] — counting the
//! evaluable projection it builds (`Reg`-expansion joins included) and the
//! reach of every reference through its referent — and one that grows past
//! [`MAX_TERM_NODES`], counting every node it visits or builds, so nested
//! `Reg` quantifiers and an `Arc`-shared body are charged for what they
//! produce and the check stops at the budget rather than after it.

use std::cell::Cell;
use std::sync::Arc;

use skep_address::{Address, Nat};
use skep_links::Behavior;

use crate::ast::{
    ArcDom, ArcTerm, Atom, Dom, Lit, Prim, Term, TypeKey, TypeRef, VarId, DERIVATION_COST,
    MAX_DEPTH, MAX_TERM_NODES,
};
use crate::catalog::{CatalogEntry, TypeCatalog};
use crate::error::TypeError;
use crate::value::{Signature, SignedTerm, Sort};
use crate::walk::{rewrite_term, Rewrite};

/// The post-type-check form — the ONE checked-term shape in the crate: what
/// `type_check` hands back, what a stored def's memo entry holds, what a
/// rule's trigger is captured as. Carries the signed term — Γ_D and the
/// compact pre-`Reg`-expansion body, read back via [`TypedTerm::params`] /
/// [`TypedTerm::source_body`], the form `define_predicate` encodes
/// (§Internal 4) — the synthesized codomain ([`TypedTerm::result_sort`]),
/// the ref-free flag, the Reg-expanded evaluable projection (every
/// `TypeRef` `Concrete`, no surviving `Reg` quantifier — `Ref` nodes may
/// remain: see [`TypedTerm::is_ref_free`]), and the term's reach — the
/// deepest level any walk over it recurses to, counted through its
/// references. Deliberately carries NO view (PR-VIEW): the view is an
/// evaluation/classification parameter, never a term annotation.
///
/// Every `TypedTerm` a caller can hold came through `type_check`, whose Γ_D
/// is Codom-only (ASN-0130 SignedTerm): the type has no other public
/// constructor, and a [`TriggerTerm`] — the one checked term that may bind a
/// tuple — does not yield one. That is what lets `define_predicate` take a
/// `TypedTerm` and store it without a tuple check of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedTerm {
    pub(crate) signed: SignedTerm,
    pub(crate) result: Sort,
    pub(crate) evaluable: ArcTerm,
    pub(crate) ref_free: bool,
    /// The reach, relative to the root: the deepest level any walk — the
    /// evaluator's, the expander's, the analyzer's, a cold derivation's —
    /// recurses to over this term, its `Reg`-expansion joins and its
    /// references' own reaches included. `≤ MAX_DEPTH` by construction; a
    /// `Ref` to this term adds `DERIVATION_COST` and one per argument.
    pub(crate) chain_depth: u32,
}

impl TypedTerm {
    /// Γ_D — the ordered free-parameter context this term was checked under.
    pub fn params(&self) -> &[(VarId, Sort)] {
        &self.signed.params
    }

    /// C_D — the synthesized codomain sort.
    pub fn result_sort(&self) -> Sort {
        self.result
    }

    /// False iff any `Ref` node survives — every PL evaluator but
    /// `evaluate_def` requires it true.
    pub fn is_ref_free(&self) -> bool {
        self.ref_free
    }

    /// The original pre-`Reg`-expansion syntactic body (`Reg`-quantifiers and
    /// `ClassVar` refs intact) — distinct from the Reg-expanded evaluable
    /// tree.
    pub fn source_body(&self) -> &Term {
        &self.signed.body
    }

    /// `(Γ_D, C_D)` — the term's signature (PR-SIG).
    pub(crate) fn signature(&self) -> Signature {
        Signature { params: self.signed.params.clone(), result: self.result }
    }
}

/// A rule trigger, checked by `Coordinator::type_check_trigger`: a
/// ONE-parameter Bool term whose parameter may be `Tup`-sorted — the only PL
/// term that binds a tuple (ASN-0133 ρ_R). A type of its own so the def path
/// cannot receive it: `define_predicate` takes a `TypedTerm`, and this type
/// yields none (its accessors are the trigger's parameter, its ref-freeness
/// and its source body; the checked term beneath is the rule engine's).
/// Holds the checked term shared, so a registration captures it without a
/// copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerTerm(pub(crate) Arc<TypedTerm>);

impl TriggerTerm {
    /// The one parameter — `register_rule` reconciles its sort with the
    /// domain's element sort.
    pub fn param(&self) -> &(VarId, Sort) {
        &self.0.params()[0]
    }

    /// False iff any `Ref` node survives — `register_rule` requires it true
    /// of an `Inline` trigger.
    pub fn is_ref_free(&self) -> bool {
        self.0.ref_free
    }

    /// The original pre-`Reg`-expansion syntactic body.
    pub fn source_body(&self) -> &Term {
        self.0.source_body()
    }

    /// The checked term beneath, shared — the shape the rule engine
    /// captures at registration.
    pub(crate) fn checked(&self) -> &Arc<TypedTerm> {
        &self.0
    }
}

/// One node's charge against [`MAX_TERM_NODES`]: `false` once the budget is
/// spent. Shared by every walk the checker runs — its own and the `Reg`
/// substitution's — so their work is one sum.
fn tick(nodes: &Cell<usize>) -> bool {
    let n = nodes.get().saturating_add(1);
    nodes.set(n);
    n <= MAX_TERM_NODES
}

/// The V-IDX expansion step (§Internal 1): `TypeRef::ClassVar(cvar) →
/// TypeRef::Concrete(key)` throughout a body, stopping at an inner `Reg`
/// binder that rebinds `cvar` (shadowing). Charges the checker's node budget
/// per node it visits — an `Arc`-shared body is a tree to a rewrite — and
/// past the budget builds nothing more, leaving `exhausted` for the caller
/// to refuse on.
struct SubstClassVar<'a> {
    cvar: VarId,
    key: &'a TypeKey,
    nodes: &'a Cell<usize>,
    exhausted: bool,
}

impl Rewrite for SubstClassVar<'_> {
    fn typeref(&mut self, tr: &TypeRef) -> TypeRef {
        match tr {
            TypeRef::ClassVar(v) if *v == self.cvar => TypeRef::Concrete(self.key.clone()),
            other => other.clone(),
        }
    }

    fn term(&mut self, t: &Term) -> Term {
        if !tick(self.nodes) {
            self.exhausted = true;
            return Term::Lit(Lit::True);
        }
        match t {
            // An inner Reg binder rebinding cvar shadows the outer one.
            Term::Forall { var, dom, .. } | Term::Exists { var, dom, .. }
                if matches!(dom.as_ref(), Dom::Reg) && *var == self.cvar =>
            {
                t.clone()
            }
            _ => rewrite_term(self, t),
        }
    }
}

/// The internal checked rule-domain carrier — the `Dom` analogue of
/// `TypedTerm`'s evaluable projection (every `TypeRef` `Concrete`, no
/// surviving `Reg` binder, element sort recorded). Internal to the working
/// set (§Internal 5).
#[derive(Debug, Clone)]
pub(crate) struct TypedDom {
    pub(crate) dom: ArcDom,
    pub(crate) elem: Sort,
}

pub(crate) type Ctx = im::HashMap<VarId, Sort>;

/// A checked term: its evaluable projection, sort, ref-freeness, and the
/// deepest level (absolute — counted from the check's starting depth) any
/// walk over the projection reaches, references' reaches included.
#[derive(Debug, Clone)]
pub(crate) struct Checked {
    pub(crate) term: ArcTerm,
    pub(crate) sort: Sort,
    pub(crate) ref_free: bool,
    pub(crate) deepest: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct CheckedDom {
    pub(crate) dom: ArcDom,
    pub(crate) elem: Sort,
    pub(crate) ref_free: bool,
    pub(crate) deepest: u32,
}

fn want(expected: Sort, found: Sort) -> Result<(), TypeError> {
    if expected == found {
        Ok(())
    } else {
        Err(TypeError::SortMismatch { expected, found })
    }
}

/// The checking pass. `resolve` is the referent resolver WT-ref consults —
/// the only external consultation (it reads the immutable def memo, so even
/// ref-bearing type-checking is "decided once") — asked at the depth the
/// referent's own check would start at, so a cold derivation reaches
/// exactly the levels the `Ref` node was charged for. `nodes` is the node
/// budget, one sum across the pass and its `Reg` substitutions.
pub(crate) struct Checker<'a> {
    catalog: &'a TypeCatalog,
    resolve: &'a dyn Fn(&Address, u32) -> Option<Arc<TypedTerm>>,
    nodes: Cell<usize>,
}

impl<'a> Checker<'a> {
    pub(crate) fn new(
        catalog: &'a TypeCatalog,
        resolve: &'a dyn Fn(&Address, u32) -> Option<Arc<TypedTerm>>,
    ) -> Checker<'a> {
        Checker { catalog, resolve, nodes: Cell::new(0) }
    }

    /// The two doors at every node: nesting past `MAX_DEPTH` and the node
    /// budget.
    fn enter(&self, depth: u32) -> Result<(), TypeError> {
        if depth > MAX_DEPTH {
            return Err(TypeError::TooDeep);
        }
        if !tick(&self.nodes) {
            return Err(TypeError::TooLarge);
        }
        Ok(())
    }

    /// Resolve a type position: a surviving `ClassVar` (no enclosing `Reg`
    /// binder substituted it) is `UnboundClassVar`; a `Concrete` key is
    /// probed by `Endset`-equality — absent ⇒ `UnregisteredType` (which also
    /// rules out non-address-denoting keys and coverage-equal-but-
    /// byte-different misses).
    fn typeref(&self, tr: &TypeRef) -> Result<(TypeKey, &CatalogEntry), TypeError> {
        match tr {
            TypeRef::ClassVar(v) => Err(TypeError::UnboundClassVar(*v)),
            TypeRef::Concrete(k) => match self.catalog.get(k) {
                Some(e) => Ok((k.clone(), e)),
                None => Err(TypeError::UnregisteredType(k.clone())),
            },
        }
    }

    fn need(&self, k: &TypeKey, e: &CatalogEntry, b: Behavior) -> Result<(), TypeError> {
        if e.reg.behaviors.contains(&b) {
            Ok(())
        } else {
            Err(TypeError::BehaviorMissing { ty: k.clone(), needs: b })
        }
    }

    /// BH2 v1 narrowing (Conflicts §8): Walk atoms admitted only at the
    /// shipped `Supersedes` key — M7 v1 serves the walk only there.
    fn bh2(&self, tr: &TypeRef) -> Result<TypeKey, TypeError> {
        let (k, e) = self.typeref(tr)?;
        self.need(&k, e, Behavior::Walk)?;
        if k != self.catalog.supersedes_key {
            return Err(TypeError::UnservedWalkClass(k));
        }
        Ok(k)
    }

    /// A child at `depth`, required at `expected`.
    fn sub(&self, ctx: &Ctx, t: &ArcTerm, expected: Sort, depth: u32) -> Result<Checked, TypeError> {
        let c = self.check_term(ctx, t, depth)?;
        want(expected, c.sort)?;
        Ok(c)
    }

    /// A Bool connective: both children at Bool, the node rebuilt through
    /// its constructor.
    fn bool2(
        &self,
        ctx: &Ctx,
        a: &ArcTerm,
        b: &ArcTerm,
        depth: u32,
        mk: fn(ArcTerm, ArcTerm) -> Term,
    ) -> Result<Checked, TypeError> {
        let ca = self.sub(ctx, a, Sort::Bool, depth)?;
        let cb = self.sub(ctx, b, Sort::Bool, depth)?;
        Ok(Checked {
            term: Arc::new(mk(ca.term, cb.term)),
            sort: Sort::Bool,
            ref_free: ca.ref_free && cb.ref_free,
            deepest: ca.deepest.max(cb.deepest),
        })
    }

    /// A quantifier's checked parts: the domain, and the Bool body under the
    /// binder at the domain's element sort. The `Reg` case is `expand_reg`'s.
    fn quantified(
        &self,
        ctx: &Ctx,
        var: VarId,
        dom: &ArcDom,
        body: &ArcTerm,
        depth: u32,
    ) -> Result<(CheckedDom, Checked), TypeError> {
        let d = self.check_dom(ctx, dom, depth)?;
        let ctx2 = ctx.update(var, d.elem);
        let c = self.sub(&ctx2, body, Sort::Bool, depth)?;
        Ok((d, c))
    }

    /// A T1 order-extremum over an address-valued domain (PC2a).
    fn extremum(
        &self,
        ctx: &Ctx,
        d: &ArcDom,
        depth: u32,
        mk: fn(ArcDom) -> Term,
    ) -> Result<Checked, TypeError> {
        let cd = self.check_dom(ctx, d, depth)?;
        want(Sort::Addr, cd.elem)?;
        Ok(Checked {
            term: Arc::new(mk(cd.dom)),
            sort: Sort::OptAddr,
            ref_free: cd.ref_free,
            deepest: cd.deepest,
        })
    }

    /// A leaf: no children, its own level.
    fn leaf(term: Term, sort: Sort, depth: u32) -> Checked {
        Checked { term: Arc::new(term), sort, ref_free: true, deepest: depth }
    }

    /// WT over `t` at nesting level `depth` (0 at a term's root; a def
    /// derived through a `Ref` starts at the `Ref`'s level plus
    /// `DERIVATION_COST`).
    pub(crate) fn check_term(&self, ctx: &Ctx, t: &Term, depth: u32) -> Result<Checked, TypeError> {
        self.enter(depth)?;
        let d = depth + 1;
        match t {
            Term::Var(v) => match ctx.get(v) {
                Some(s) => Ok(Self::leaf(Term::Var(*v), *s, depth)),
                None => Err(TypeError::UnboundVariable(*v)),
            },
            Term::Lit(l) => {
                let sort = match l {
                    Lit::True | Lit::False => Sort::Bool,
                    Lit::Nat(_) => Sort::Nat,
                    Lit::Addr(_) => Sort::Addr,
                    Lit::BotAddr => Sort::OptAddr,
                    Lit::BotNat => Sort::OptNat,
                };
                Ok(Self::leaf(Term::Lit(l.clone()), sort, depth))
            }
            Term::Atom(a) => self.check_atom(ctx, a, depth),
            Term::Prim(p) => self.check_prim(ctx, p, depth),
            Term::And(a, b) => self.bool2(ctx, a, b, d, Term::And),
            Term::Or(a, b) => self.bool2(ctx, a, b, d, Term::Or),
            Term::Implies(a, b) => self.bool2(ctx, a, b, d, Term::Implies),
            Term::Iff(a, b) => self.bool2(ctx, a, b, d, Term::Iff),
            Term::Not(a) => {
                let ca = self.sub(ctx, a, Sort::Bool, d)?;
                Ok(Checked {
                    term: Arc::new(Term::Not(ca.term)),
                    sort: Sort::Bool,
                    ref_free: ca.ref_free,
                    deepest: ca.deepest,
                })
            }
            Term::Forall { var, dom, body } if matches!(dom.as_ref(), Dom::Reg) => {
                self.expand_reg(ctx, *var, body, depth, Term::And)
            }
            Term::Exists { var, dom, body } if matches!(dom.as_ref(), Dom::Reg) => {
                self.expand_reg(ctx, *var, body, depth, Term::Or)
            }
            Term::Forall { var, dom, body } => {
                let (cd, cb) = self.quantified(ctx, *var, dom, body, d)?;
                Ok(Checked {
                    term: Arc::new(Term::Forall { var: *var, dom: cd.dom, body: cb.term }),
                    sort: Sort::Bool,
                    ref_free: cd.ref_free && cb.ref_free,
                    deepest: cd.deepest.max(cb.deepest),
                })
            }
            Term::Exists { var, dom, body } => {
                let (cd, cb) = self.quantified(ctx, *var, dom, body, d)?;
                Ok(Checked {
                    term: Arc::new(Term::Exists { var: *var, dom: cd.dom, body: cb.term }),
                    sort: Sort::Bool,
                    ref_free: cd.ref_free && cb.ref_free,
                    deepest: cd.deepest.max(cb.deepest),
                })
            }
            Term::Let { var, bound, body } => {
                let cb = self.check_term(ctx, bound, d)?;
                let ctx2 = ctx.update(*var, cb.sort);
                let cy = self.check_term(&ctx2, body, d)?;
                Ok(Checked {
                    term: Arc::new(Term::Let { var: *var, bound: cb.term, body: cy.term }),
                    sort: cy.sort,
                    ref_free: cb.ref_free && cy.ref_free,
                    deepest: cb.deepest.max(cy.deepest),
                })
            }
            Term::IfSome { opt, var, then_, else_ } => {
                // The binder guard narrows T∪{⊥} → T (resp. ℕ∪{⊥} → ℕ) in
                // the then-branch (PC2).
                let co = self.check_term(ctx, opt, d)?;
                let narrowed = match co.sort {
                    Sort::OptAddr => Sort::Addr,
                    Sort::OptNat => Sort::Nat,
                    other => return Err(TypeError::SortMismatch { expected: Sort::OptAddr, found: other }),
                };
                let ctx2 = ctx.update(*var, narrowed);
                let ct = self.check_term(&ctx2, then_, d)?;
                let ce = self.check_term(ctx, else_, d)?;
                want(ct.sort, ce.sort)?;
                Ok(Checked {
                    term: Arc::new(Term::IfSome {
                        opt: co.term,
                        var: *var,
                        then_: ct.term,
                        else_: ce.term,
                    }),
                    sort: ct.sort,
                    ref_free: co.ref_free && ct.ref_free && ce.ref_free,
                    deepest: co.deepest.max(ct.deepest).max(ce.deepest),
                })
            }
            Term::Count(dm) => match dm.as_ref() {
                // count(Reg) folds to a Lit — the registered-class count,
                // constant by R1/C0 (V-IDX).
                Dom::Reg => Ok(Self::leaf(
                    Term::Lit(Lit::Nat(Nat::from(self.catalog.classes().len()))),
                    Sort::Nat,
                    depth,
                )),
                _ => {
                    let cd = self.check_dom(ctx, dm, d)?;
                    Ok(Checked {
                        term: Arc::new(Term::Count(cd.dom)),
                        sort: Sort::Nat,
                        ref_free: cd.ref_free,
                        deepest: cd.deepest,
                    })
                }
            },
            Term::MaxT1(dm) => self.extremum(ctx, dm, d, Term::MaxT1),
            Term::MinT1(dm) => self.extremum(ctx, dm, d, Term::MinT1),
            Term::BigUnion { dom, var, body } => {
                // PC2a excludes Reg from ⋃; Addr and Tup element sorts bind.
                let cd = self.check_dom(ctx, dom, d)?;
                let ctx2 = ctx.update(*var, cd.elem);
                let cb = self.sub(&ctx2, body, Sort::AddrSet, d)?;
                Ok(Checked {
                    term: Arc::new(Term::BigUnion { dom: cd.dom, var: *var, body: cb.term }),
                    sort: Sort::AddrSet,
                    ref_free: cd.ref_free && cb.ref_free,
                    deepest: cd.deepest.max(cb.deepest),
                })
            }
            Term::Reflect(dm) => {
                // QD-refl: only an address-valued domain reflects; a
                // tuple-valued (or class-valued Reg) domain is rejected at
                // the element-sort check.
                let cd = self.check_dom(ctx, dm, d)?;
                want(Sort::Addr, cd.elem)?;
                Ok(Checked {
                    term: Arc::new(Term::Reflect(cd.dom)),
                    sort: Sort::AddrSet,
                    ref_free: cd.ref_free,
                    deepest: cd.deepest,
                })
            }
            Term::Ref { addr, args } => {
                // WT-ref: types to C_r when signature(addr) is defined and
                // each argᵢ checks at Cᵢ. No defined signature (never
                // registered, or undisciplined) ⇒ DanglingReference. An
                // arity mismatch is reported as a SortMismatch against the
                // first unmatched formal (too few: expected that formal,
                // found the result sort; too many: expected the result sort,
                // found the extra argument's sort) — the closest expression
                // the declared vocabulary admits.
                //
                // The referent is asked for at the level its own check would
                // start at from here — this node's plus the derivation's —
                // so the levels a cold derivation through this node reaches
                // are exactly the reach charged below: this node's, the
                // derivation's, one per argument (the expansion's `Let`
                // chain), and the referent's own.
                let referent = (self.resolve)(addr, depth + DERIVATION_COST)
                    .ok_or_else(|| TypeError::DanglingReference(addr.clone()))?;
                let params = referent.params();
                let mut e_args: Vec<ArcTerm> = Vec::with_capacity(args.len());
                let mut deepest = depth;
                for (i, a) in args.iter().enumerate() {
                    let c = self.check_term(ctx, a, d)?;
                    match params.get(i) {
                        Some((_, s)) => want(*s, c.sort)?,
                        None => {
                            return Err(TypeError::SortMismatch {
                                expected: referent.result,
                                found: c.sort,
                            })
                        }
                    }
                    deepest = deepest.max(c.deepest);
                    e_args.push(c.term);
                }
                if args.len() < params.len() {
                    return Err(TypeError::SortMismatch {
                        expected: params[args.len()].1,
                        found: referent.result,
                    });
                }
                let arity = u32::try_from(args.len()).unwrap_or(u32::MAX);
                let reach = depth
                    .saturating_add(DERIVATION_COST)
                    .saturating_add(arity)
                    .saturating_add(referent.chain_depth);
                if reach > MAX_DEPTH {
                    return Err(TypeError::TooDeep);
                }
                Ok(Checked {
                    term: Arc::new(Term::Ref { addr: addr.clone(), args: e_args }),
                    sort: referent.result,
                    ref_free: false,
                    deepest: deepest.max(reach),
                })
            }
        }
    }

    /// V-IDX `Reg` expansion: instantiate `body` once per registered class,
    /// substituting `ClassVar(cvar) → Concrete(class)`, check EACH instance
    /// (an ill-typed one rejects the whole term — `RegInstanceIllTyped`), and
    /// join the instances through `join` (`And` for ∀, `Or` for ∃) as the
    /// evaluable projection. The join is a left-nested chain of `n − 1`
    /// connectives over `n` classes, so an instance sits up to `n − 1` levels
    /// below the quantifier's node in the evaluable: every instance is
    /// checked at that level, the deepest one's, so the projection's real
    /// depth is what the walks are charged for.
    fn expand_reg(
        &self,
        ctx: &Ctx,
        cvar: VarId,
        body: &Term,
        depth: u32,
        join: fn(ArcTerm, ArcTerm) -> Term,
    ) -> Result<Checked, TypeError> {
        let classes = self.catalog.classes();
        let joins = u32::try_from(classes.len().saturating_sub(1)).unwrap_or(u32::MAX);
        let inst_depth = depth.saturating_add(joins);
        let mut acc: Option<Checked> = None;
        for key in classes {
            let mut subst = SubstClassVar { cvar, key, nodes: &self.nodes, exhausted: false };
            let inst = subst.term(body);
            if subst.exhausted {
                return Err(TypeError::TooLarge);
            }
            let c = self
                .check_term(ctx, &inst, inst_depth)
                .and_then(|c| {
                    want(Sort::Bool, c.sort)?;
                    Ok(c)
                })
                .map_err(|e| match e {
                    // The budgets are the whole term's, not an instance's.
                    TypeError::TooDeep | TypeError::TooLarge => e,
                    other => TypeError::RegInstanceIllTyped(Box::new(other)),
                })?;
            acc = Some(match acc {
                None => c,
                Some(prev) => Checked {
                    term: Arc::new(join(prev.term, c.term)),
                    sort: Sort::Bool,
                    ref_free: prev.ref_free && c.ref_free,
                    deepest: prev.deepest.max(c.deepest),
                },
            });
        }
        Ok(acc.expect("the catalog holds the five shipped classes at minimum"))
    }

    fn check_atom(&self, ctx: &Ctx, a: &Atom, depth: u32) -> Result<Checked, TypeError> {
        let d = depth + 1;
        // A V-TUP variable must be a Tup-sorted binding in scope.
        let tup_var = |v: VarId| -> Result<VarId, TypeError> {
            match ctx.get(&v) {
                Some(Sort::Tup) => Ok(v),
                Some(s) => Err(TypeError::SortMismatch { expected: Sort::Tup, found: *s }),
                None => Err(TypeError::UnboundVariable(v)),
            }
        };
        // A one-argument atom at a type position: the argument at `sort`.
        let arg = |e: &ArcTerm, sort: Sort| self.sub(ctx, e, sort, d);
        let (atom, sort, ref_free, deepest) = match a {
            Atom::IsK(tr, e) => {
                let (k, _) = self.typeref(tr)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::IsK(TypeRef::Concrete(k), c.term), Sort::Bool, c.ref_free, c.deepest)
            }
            Atom::Members(tr) => {
                let (k, _) = self.typeref(tr)?;
                (Atom::Members(TypeRef::Concrete(k)), Sort::AddrSet, true, depth)
            }
            Atom::TargetsOf(tr, e) => {
                let (k, _) = self.typeref(tr)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::TargetsOf(TypeRef::Concrete(k), c.term), Sort::AddrSet, c.ref_free, c.deepest)
            }
            Atom::IsFiltered(tr, e) => {
                let (k, entry) = self.typeref(tr)?;
                self.need(&k, entry, Behavior::ReadFilter)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::IsFiltered(TypeRef::Concrete(k), c.term), Sort::Bool, c.ref_free, c.deepest)
            }
            Atom::Succs(tr, e) => {
                let k = self.bh2(tr)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::Succs(TypeRef::Concrete(k), c.term), Sort::AddrSet, c.ref_free, c.deepest)
            }
            Atom::Chain(tr, e) => {
                let k = self.bh2(tr)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::Chain(TypeRef::Concrete(k), c.term), Sort::AddrSeq, c.ref_free, c.deepest)
            }
            Atom::Tip(tr, e) => {
                let k = self.bh2(tr)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::Tip(TypeRef::Concrete(k), c.term), Sort::OptAddr, c.ref_free, c.deepest)
            }
            Atom::IsInChain(tr, e1, e2) => {
                let k = self.bh2(tr)?;
                let c1 = arg(e1, Sort::Addr)?;
                let c2 = arg(e2, Sort::Addr)?;
                (
                    Atom::IsInChain(TypeRef::Concrete(k), c1.term, c2.term),
                    Sort::Bool,
                    c1.ref_free && c2.ref_free,
                    c1.deepest.max(c2.deepest),
                )
            }
            Atom::SourcesTo(tr, e) => {
                let (k, entry) = self.typeref(tr)?;
                self.need(&k, entry, Behavior::ReverseLookup)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::SourcesTo(TypeRef::Concrete(k), c.term), Sort::AddrSet, c.ref_free, c.deepest)
            }
            Atom::TargetOf(tr, e) => {
                let (k, entry) = self.typeref(tr)?;
                self.need(&k, entry, Behavior::ReverseLookup)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::TargetOf(TypeRef::Concrete(k), c.term), Sort::OptAddr, c.ref_free, c.deepest)
            }
            Atom::TargetsKeyed(e) => {
                // V-atom: in the vocabulary iff some cataloged class attaches
                // BH3.
                if !self.catalog.has_bh3() {
                    return Err(TypeError::NoReverseLookupClass);
                }
                let c = arg(e, Sort::Addr)?;
                (Atom::TargetsKeyed(c.term), Sort::Map, c.ref_free, c.deepest)
            }
            Atom::Age(tr, e) => {
                let (k, entry) = self.typeref(tr)?;
                self.need(&k, entry, Behavior::Age)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::Age(TypeRef::Concrete(k), c.term), Sort::OptNat, c.ref_free, c.deepest)
            }
            Atom::Stale(tr, e) => {
                let (k, entry) = self.typeref(tr)?;
                self.need(&k, entry, Behavior::Age)?;
                let c = arg(e, Sort::Nat)?;
                (Atom::Stale(TypeRef::Concrete(k), c.term), Sort::AddrSet, c.ref_free, c.deepest)
            }
            Atom::IsDoc(e) => {
                let c = arg(e, Sort::Addr)?;
                (Atom::IsDoc(c.term), Sort::Bool, c.ref_free, c.deepest)
            }
            Atom::TupAddr(v) => (Atom::TupAddr(tup_var(*v)?), Sort::Addr, true, depth),
            Atom::TupAddrsF(v) => (Atom::TupAddrsF(tup_var(*v)?), Sort::AddrSet, true, depth),
            Atom::TupAddrsG(v) => (Atom::TupAddrsG(tup_var(*v)?), Sort::AddrSet, true, depth),
            Atom::InCoverageF(e, v) => {
                let c = arg(e, Sort::Addr)?;
                (Atom::InCoverageF(c.term, tup_var(*v)?), Sort::Bool, c.ref_free, c.deepest)
            }
            Atom::InCoverageG(e, v) => {
                let c = arg(e, Sort::Addr)?;
                (Atom::InCoverageG(c.term, tup_var(*v)?), Sort::Bool, c.ref_free, c.deepest)
            }
        };
        Ok(Checked { term: Arc::new(Term::Atom(atom)), sort, ref_free, deepest })
    }

    /// A binary prim over two children of one sort, `(operand, result)` in
    /// `sorts`, the node rebuilt through its constructor.
    fn prim2(
        &self,
        ctx: &Ctx,
        x: &ArcTerm,
        y: &ArcTerm,
        depth: u32,
        sorts: (Sort, Sort),
        mk: fn(ArcTerm, ArcTerm) -> Prim,
    ) -> Result<Checked, TypeError> {
        let (operand, sort) = sorts;
        let cx = self.sub(ctx, x, operand, depth)?;
        let cy = self.sub(ctx, y, operand, depth)?;
        Ok(Checked {
            term: Arc::new(Term::Prim(mk(cx.term, cy.term))),
            sort,
            ref_free: cx.ref_free && cy.ref_free,
            deepest: cx.deepest.max(cy.deepest),
        })
    }

    /// A unary prim over one child, `(operand, result)` in `sorts`.
    fn prim1(
        &self,
        ctx: &Ctx,
        x: &ArcTerm,
        depth: u32,
        sorts: (Sort, Sort),
        mk: fn(ArcTerm) -> Prim,
    ) -> Result<Checked, TypeError> {
        let (operand, sort) = sorts;
        let cx = self.sub(ctx, x, operand, depth)?;
        Ok(Checked {
            term: Arc::new(Term::Prim(mk(cx.term))),
            sort,
            ref_free: cx.ref_free,
            deepest: cx.deepest,
        })
    }

    fn check_prim(&self, ctx: &Ctx, p: &Prim, depth: u32) -> Result<Checked, TypeError> {
        let d = depth + 1;
        match p {
            Prim::AddrEq(a, b) => self.prim2(ctx, a, b, d, (Sort::Addr, Sort::Bool), Prim::AddrEq),
            Prim::Prefix(a, b) => self.prim2(ctx, a, b, d, (Sort::Addr, Sort::Bool), Prim::Prefix),
            Prim::T1Lt(a, b) => self.prim2(ctx, a, b, d, (Sort::Addr, Sort::Bool), Prim::T1Lt),
            Prim::SetEq(a, b) => self.prim2(ctx, a, b, d, (Sort::AddrSet, Sort::Bool), Prim::SetEq),
            Prim::NatEq(a, b) => self.prim2(ctx, a, b, d, (Sort::Nat, Sort::Bool), Prim::NatEq),
            Prim::NatLe(a, b) => self.prim2(ctx, a, b, d, (Sort::Nat, Sort::Bool), Prim::NatLe),
            Prim::NatAdd(a, b) => self.prim2(ctx, a, b, d, (Sort::Nat, Sort::Nat), Prim::NatAdd),
            Prim::IsEmpty(s) => self.prim1(ctx, s, d, (Sort::AddrSet, Sort::Bool), Prim::IsEmpty),
            Prim::Elems(q) => self.prim1(ctx, q, d, (Sort::AddrSeq, Sort::AddrSet), Prim::Elems),
            Prim::SetMem(x, s) => {
                let cx = self.sub(ctx, x, Sort::Addr, d)?;
                let cs = self.sub(ctx, s, Sort::AddrSet, d)?;
                Ok(Checked {
                    term: Arc::new(Term::Prim(Prim::SetMem(cx.term, cs.term))),
                    sort: Sort::Bool,
                    ref_free: cx.ref_free && cs.ref_free,
                    deepest: cx.deepest.max(cs.deepest),
                })
            }
            Prim::MapGet(m, tr) => {
                // V-PRIM admits ·[K] per registered class — cataloged-only,
                // no behavior requirement; a non-BH3/absent key denotes ⊥.
                let (k, _) = self.typeref(tr)?;
                let cm = self.sub(ctx, m, Sort::Map, d)?;
                Ok(Checked {
                    term: Arc::new(Term::Prim(Prim::MapGet(cm.term, TypeRef::Concrete(k)))),
                    sort: Sort::OptAddr,
                    ref_free: cm.ref_free,
                    deepest: cm.deepest,
                })
            }
            Prim::Def(x) => {
                let c = self.check_term(ctx, x, d)?;
                match c.sort {
                    Sort::OptAddr | Sort::OptNat => {}
                    other => return Err(TypeError::SortMismatch { expected: Sort::OptAddr, found: other }),
                }
                Ok(Checked {
                    term: Arc::new(Term::Prim(Prim::Def(c.term))),
                    sort: Sort::Bool,
                    ref_free: c.ref_free,
                    deepest: c.deepest,
                })
            }
        }
    }

    /// The WT domain judgment `⊢ D dom(s)`, `s ∈ {Addr, Tup}`, at nesting
    /// level `depth`. A `Reg` in a non-quantifier/`Count` position —
    /// including here — is class-valued and has no element sort; per the
    /// design's "likewise rejected at the element-sort check" it surfaces as
    /// `SortMismatch{expected: Addr, found: Tup}` (the vocabulary has no
    /// class sort to name).
    pub(crate) fn check_dom(&self, ctx: &Ctx, dm: &Dom, depth: u32) -> Result<CheckedDom, TypeError> {
        self.enter(depth)?;
        let d = depth + 1;
        let leaf = |dom: Dom, elem: Sort| CheckedDom {
            dom: Arc::new(dom),
            elem,
            ref_free: true,
            deepest: depth,
        };
        match dm {
            Dom::MembersDom(tr) => {
                let (k, _) = self.typeref(tr)?;
                Ok(leaf(Dom::MembersDom(TypeRef::Concrete(k)), Sort::Addr))
            }
            Dom::ActiveSlice(tr) => {
                let (k, _) = self.typeref(tr)?;
                Ok(leaf(Dom::ActiveSlice(TypeRef::Concrete(k)), Sort::Tup))
            }
            Dom::AuditSlice(tr) => {
                let (k, _) = self.typeref(tr)?;
                Ok(leaf(Dom::AuditSlice(TypeRef::Concrete(k)), Sort::Tup))
            }
            Dom::LinkDom => Ok(leaf(Dom::LinkDom, Sort::Addr)),
            Dom::Reg => Err(TypeError::SortMismatch { expected: Sort::Addr, found: Sort::Tup }),
            Dom::Filter { dom, var, pred } => {
                let base = self.check_dom(ctx, dom, d)?;
                let ctx2 = ctx.update(*var, base.elem);
                let c = self.sub(&ctx2, pred, Sort::Bool, d)?;
                Ok(CheckedDom {
                    dom: Arc::new(Dom::Filter { dom: base.dom, var: *var, pred: c.term }),
                    elem: base.elem,
                    ref_free: base.ref_free && c.ref_free,
                    deepest: base.deepest.max(c.deepest),
                })
            }
            Dom::SetTerm(t) => {
                let c = self.sub(ctx, t, Sort::AddrSet, d)?;
                Ok(CheckedDom {
                    dom: Arc::new(Dom::SetTerm(c.term)),
                    elem: Sort::Addr,
                    ref_free: c.ref_free,
                    deepest: c.deepest,
                })
            }
        }
    }
}
