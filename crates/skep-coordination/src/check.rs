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
//! reach of every reference through its referent — and one that spends the
//! node [`Budget`], counting every node it visits or builds, so nested `Reg`
//! quantifiers and an `Arc`-shared body are charged for what they produce and
//! the check stops at the budget rather than after it.

use std::cell::Cell;
use std::collections::HashSet;
use std::sync::Arc;

use skep_address::{Address, Nat};
use skep_links::Behavior;

use crate::ast::{ArcDom, ArcTerm, Atom, Dom, Lit, Prim, Term, TypeKey, TypeRef, VarId};
use crate::budget::{weight, Budget, DERIVATION_COST, MAX_DEPTH};
use crate::catalog::TypeCatalog;
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
    ///
    /// It bounds the FLAT REFERENCE EXPANSION's depth as well as this tree's,
    /// because every node was checked at a level no shallower than the
    /// position its expansion occupies — the `Reg` joins at the deepest
    /// instance's level, a reference's arguments each at their own `Let`
    /// position, its referent's body past the whole chain. That is what makes
    /// the walks with no depth parameter of their own — `view_independent`'s
    /// scan, `Analyzer::term`, the recursive `Drop` of an `Arc<Term>` chain —
    /// safe on a caller's thread.
    pub(crate) reach: u32,
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

    /// The checked term beneath, shared — the shape the rule engine captures
    /// at registration, and the rule engine's alone. NEVER route it to
    /// `define_predicate`: that signature takes the `&TypedTerm` this derefs
    /// to, and its encode `expect` rests on a Γ_D that is Codom-only, which a
    /// trigger's need not be (`type_check_trigger` admits one `Tup`
    /// parameter). A `Tup`-sorted trigger persisted through that path is the
    /// codec's `UnencodableTup` — a panic, not a rejection. The type system
    /// does not close this: only the crate's own routing does.
    pub(crate) fn checked(&self) -> &Arc<TypedTerm> {
        &self.0
    }
}

/// The V-IDX expansion step (§Internal 1): `TypeRef::ClassVar(cvar) →
/// TypeRef::Concrete(key)` throughout a body, stopping at an inner `Reg`
/// binder that rebinds `cvar` (shadowing). Charges the checker's node budget
/// per node it visits AND per unit of payload that node carries — an
/// `Arc`-shared body is a tree to a rewrite, and a literal's tumbler is
/// copied whole into every instance — and past the budget builds nothing
/// more, leaving the spent budget for the caller to refuse on.
struct SubstClassVar<'a> {
    cvar: VarId,
    key: &'a TypeKey,
    nodes: &'a Budget,
}

impl Rewrite for SubstClassVar<'_> {
    fn typeref(&mut self, tr: &TypeRef) -> TypeRef {
        match tr {
            TypeRef::ClassVar(v) if *v == self.cvar => TypeRef::Concrete(self.key.clone()),
            other => other.clone(),
        }
    }

    fn term(&mut self, t: &Term) -> Term {
        if !self.nodes.charge(weight(t)) {
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

pub(crate) type Ctx = im::HashMap<VarId, Sort>;

/// A checked term: its evaluable projection, sort and ref-freeness. How deep
/// the pass went is the pass's own record ([`Checker::deepest`]), not a
/// per-node field.
#[derive(Debug, Clone)]
pub(crate) struct Checked {
    pub(crate) term: ArcTerm,
    pub(crate) sort: Sort,
    pub(crate) ref_free: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct CheckedDom {
    pub(crate) dom: ArcDom,
    pub(crate) elem: Sort,
    pub(crate) ref_free: bool,
}

fn want(expected: Sort, found: Sort) -> Result<(), TypeError> {
    if expected == found {
        Ok(())
    } else {
        Err(TypeError::SortMismatch { expected, found })
    }
}

/// The resolver's two refusals, each the `Ref` arm's own rejection:
/// `Dangling` — the address has no defined signature (never registered, or
/// ever-registered-but-undisciplined), WT-ref's domain failure; `TooDeep` —
/// the referent's derivation could not complete at the level it was asked
/// at, a verdict about the ASKING term's nesting and never about the
/// referent, which the resolver leaves unjudged (and unmemoized).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unresolved {
    Dangling,
    TooDeep,
}

/// The referent resolver WT-ref consults (the signature resolver, PR-SIG):
/// the defined referent at an address, its derivation — if the memo misses
/// — rooted at the level asked for, or one of the two [`Unresolved`]
/// refusals.
pub(crate) type Resolver<'a> = dyn Fn(&Address, u32) -> Result<Arc<TypedTerm>, Unresolved> + 'a;

/// What a type position must satisfy beyond being cataloged (V-STAT).
enum Guard {
    /// Cataloged only, no behavior requirement — the core atoms, `·[K]`, the
    /// slice domains.
    Cataloged,
    /// The class's registration must declare this behavior.
    Needs(Behavior),
    /// BH2's v1 narrowing (Conflicts §8): the `Walk` behavior AND the shipped
    /// `Supersedes` key — M7 v1 serves the walk only there, so admitting any
    /// other Walk class would silently denote ∅/\[\].
    Walk,
}

/// A prim's typing rule: every operand at `operand`, the node at `result`.
/// Named per V-PRIM family below, so a call site cannot transpose the two —
/// as an unnamed `(Sort, Sort)` it could, and a transposition retypes the
/// operator with nothing to object.
#[derive(Clone, Copy)]
struct PrimRule {
    operand: Sort,
    result: Sort,
}

/// `= ≼ T1` — an address comparison.
const ADDR_PRED: PrimRule = PrimRule { operand: Sort::Addr, result: Sort::Bool };
/// `= ∅` and set `=` — a ℘_fin(T) test.
const SET_PRED: PrimRule = PrimRule { operand: Sort::AddrSet, result: Sort::Bool };
/// ℕ `=` and `≤`.
const NAT_PRED: PrimRule = PrimRule { operand: Sort::Nat, result: Sort::Bool };
/// ℕ `+`.
const NAT_OP: PrimRule = PrimRule { operand: Sort::Nat, result: Sort::Nat };
/// `elems` — Seq_fin(T) → ℘_fin(T).
const SEQ_ELEMS: PrimRule = PrimRule { operand: Sort::AddrSeq, result: Sort::AddrSet };

/// The checking pass. `resolve` is the referent resolver WT-ref consults —
/// the only external consultation (it reads the immutable def memo, so even
/// ref-bearing type-checking is "decided once") — asked at the depth the
/// referent's own check would start at, so a cold derivation reaches
/// exactly the levels the `Ref` node was charged for, and answering
/// [`Unresolved::TooDeep`] when the referent cannot be derived there.
/// `nodes` is the node budget, one sum across the pass and its `Reg`
/// substitutions; `deepest` is the pass's high-water mark, so how deep the
/// judgment went is recorded once per level entered rather than recombined
/// at every node. One judgment per `Checker`: [`Checker::check_signed`]
/// consumes it, so a second judgment cannot inherit the first's mark.
pub(crate) struct Checker<'a> {
    catalog: &'a TypeCatalog,
    resolve: &'a Resolver<'a>,
    nodes: Budget,
    deepest: Cell<u32>,
}

impl<'a> Checker<'a> {
    pub(crate) fn new(catalog: &'a TypeCatalog, resolve: &'a Resolver<'a>) -> Checker<'a> {
        Checker { catalog, resolve, nodes: Budget::default(), deepest: Cell::new(0) }
    }

    /// The whole judgment over a signed term — its body under its Γ_D — into
    /// the checked-term shape, the body's root at nesting level `depth`.
    ///
    /// Γ_D is charged against the node budget first, so a context longer than
    /// the budget is `TooLarge` before anything is sized by its length (the
    /// duplicate-name set, the typing context); then Γ_D binds each name once
    /// (`DuplicateParameter` otherwise), so that an `Env` can bind every
    /// parameter at its sort; then WT + WT-ref over the body, referents
    /// resolved at the levels the `Ref` arm charges them.
    /// [`TypedTerm::reach`] is the pass's high-water mark RELATIVE to this
    /// root — the same quantity [`Checker::check_term`]'s `Ref` arm adds to
    /// its own level when it charges a reference to this term, so the two
    /// halves of the depth accounting are stated together.
    pub(crate) fn check_signed(self, signed: SignedTerm, depth: u32) -> Result<TypedTerm, TypeError> {
        if !self.nodes.charge(signed.params.len()) {
            return Err(TypeError::TooLarge);
        }
        let mut seen: HashSet<VarId> = HashSet::with_capacity(signed.params.len());
        if let Some((v, _)) = signed.params.iter().find(|(v, _)| !seen.insert(*v)) {
            return Err(TypeError::DuplicateParameter(*v));
        }
        let ctx: Ctx = signed.params.iter().copied().collect();
        let checked = self.check_term(&ctx, &signed.body, depth)?;
        Ok(TypedTerm {
            signed,
            result: checked.sort,
            evaluable: checked.term,
            ref_free: checked.ref_free,
            reach: self.deepest.get().saturating_sub(depth),
        })
    }

    /// The two doors at every node — nesting past `MAX_DEPTH` and the node
    /// budget, charged `weight` units for the node and the payload it carries
    /// — and, once both pass, the ONE place a level is recorded against the
    /// pass's high-water mark.
    fn enter(&self, weight: usize, depth: u32) -> Result<(), TypeError> {
        if depth > MAX_DEPTH {
            return Err(TypeError::TooDeep);
        }
        if !self.nodes.charge(weight) {
            return Err(TypeError::TooLarge);
        }
        self.deepest.set(self.deepest.get().max(depth));
        Ok(())
    }

    /// The cataloged key of a type position, its `guard` met (V-STAT). A
    /// surviving `ClassVar` is `UnboundClassVar` (no enclosing `Reg` binder
    /// substituted it); a `Concrete` key absent from the catalog is
    /// `UnregisteredType` — the probe being `Endset`-equality, that subsumes
    /// non-address-denoting keys and coverage-equal-but-byte-different
    /// misses.
    fn guarded(&self, tr: &TypeRef, guard: Guard) -> Result<TypeKey, TypeError> {
        let k = match tr {
            TypeRef::ClassVar(v) => return Err(TypeError::UnboundClassVar(*v)),
            TypeRef::Concrete(k) => k,
        };
        let entry = self.catalog.get(k).ok_or_else(|| TypeError::UnregisteredType(k.clone()))?;
        let declares = |needs: Behavior| -> Result<(), TypeError> {
            if entry.registration.behaviors.contains(&needs) {
                Ok(())
            } else {
                Err(TypeError::BehaviorMissing { ty: k.clone(), needs })
            }
        };
        match guard {
            Guard::Cataloged => {}
            Guard::Needs(b) => declares(b)?,
            // The behavior speaks before the serving narrowing: a class with
            // no `Walk` is `BehaviorMissing`, a Walk class M7 v1 does not
            // serve is `UnservedWalkClass`.
            Guard::Walk => {
                declares(Behavior::Walk)?;
                if k != self.catalog.supersedes_key() {
                    return Err(TypeError::UnservedWalkClass(k.clone()));
                }
            }
        }
        Ok(k.clone())
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
        let cd = self.check_dom(ctx, dom, depth)?;
        let inner = ctx.update(var, cd.elem);
        let c = self.sub(&inner, body, Sort::Bool, depth)?;
        Ok((cd, c))
    }

    /// A T1 order-extremum over an address-valued domain (PC2a).
    fn extremum(
        &self,
        ctx: &Ctx,
        dm: &ArcDom,
        depth: u32,
        mk: fn(ArcDom) -> Term,
    ) -> Result<Checked, TypeError> {
        let cd = self.check_dom(ctx, dm, depth)?;
        want(Sort::Addr, cd.elem)?;
        Ok(Checked { term: Arc::new(mk(cd.dom)), sort: Sort::OptAddr, ref_free: cd.ref_free })
    }

    /// A leaf: no children.
    fn leaf(term: Term, sort: Sort) -> Checked {
        Checked { term: Arc::new(term), sort, ref_free: true }
    }

    /// WT over `t` at nesting level `depth` (0 at a term's root; a def
    /// derived through a `Ref` starts at the `Ref`'s level plus
    /// `DERIVATION_COST`).
    pub(crate) fn check_term(&self, ctx: &Ctx, t: &Term, depth: u32) -> Result<Checked, TypeError> {
        self.enter(weight(t), depth)?;
        // `depth` is this node's level, `child_depth` the level its children
        // occupy. Three arms pass `depth` deliberately: `Atom` and `Prim`,
        // whose helpers derive their own child level, and `expand_reg`, whose
        // join chain replaces this node rather than nesting beneath it.
        let child_depth = depth + 1;
        match t {
            Term::Var(v) => match ctx.get(v) {
                Some(s) => Ok(Self::leaf(Term::Var(*v), *s)),
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
                Ok(Self::leaf(Term::Lit(l.clone()), sort))
            }
            Term::Atom(a) => self.check_atom(ctx, a, depth),
            Term::Prim(p) => self.check_prim(ctx, p, depth),
            Term::And(a, b) => self.bool2(ctx, a, b, child_depth, Term::And),
            Term::Or(a, b) => self.bool2(ctx, a, b, child_depth, Term::Or),
            Term::Implies(a, b) => self.bool2(ctx, a, b, child_depth, Term::Implies),
            Term::Iff(a, b) => self.bool2(ctx, a, b, child_depth, Term::Iff),
            Term::Not(a) => {
                let ca = self.sub(ctx, a, Sort::Bool, child_depth)?;
                Ok(Checked {
                    term: Arc::new(Term::Not(ca.term)),
                    sort: Sort::Bool,
                    ref_free: ca.ref_free,
                })
            }
            Term::Forall { var, dom, body } if matches!(dom.as_ref(), Dom::Reg) => {
                self.expand_reg(ctx, *var, body, depth, Term::And)
            }
            Term::Exists { var, dom, body } if matches!(dom.as_ref(), Dom::Reg) => {
                self.expand_reg(ctx, *var, body, depth, Term::Or)
            }
            Term::Forall { var, dom, body } => {
                let (cd, cb) = self.quantified(ctx, *var, dom, body, child_depth)?;
                Ok(Checked {
                    term: Arc::new(Term::Forall { var: *var, dom: cd.dom, body: cb.term }),
                    sort: Sort::Bool,
                    ref_free: cd.ref_free && cb.ref_free,
                })
            }
            Term::Exists { var, dom, body } => {
                let (cd, cb) = self.quantified(ctx, *var, dom, body, child_depth)?;
                Ok(Checked {
                    term: Arc::new(Term::Exists { var: *var, dom: cd.dom, body: cb.term }),
                    sort: Sort::Bool,
                    ref_free: cd.ref_free && cb.ref_free,
                })
            }
            Term::Let { var, bound, body } => {
                let cbound = self.check_term(ctx, bound, child_depth)?;
                let inner = ctx.update(*var, cbound.sort);
                let cbody = self.check_term(&inner, body, child_depth)?;
                Ok(Checked {
                    term: Arc::new(Term::Let { var: *var, bound: cbound.term, body: cbody.term }),
                    sort: cbody.sort,
                    ref_free: cbound.ref_free && cbody.ref_free,
                })
            }
            Term::IfSome { opt, var, then_, else_ } => {
                // The binder guard narrows T∪{⊥} → T (resp. ℕ∪{⊥} → ℕ) in
                // the then-branch (PC2).
                let co = self.check_term(ctx, opt, child_depth)?;
                let narrowed = match co.sort {
                    Sort::OptAddr => Sort::Addr,
                    Sort::OptNat => Sort::Nat,
                    other => return Err(TypeError::SortMismatch { expected: Sort::OptAddr, found: other }),
                };
                let inner = ctx.update(*var, narrowed);
                let ct = self.check_term(&inner, then_, child_depth)?;
                let ce = self.check_term(ctx, else_, child_depth)?;
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
                })
            }
            Term::Count(dm) => match dm.as_ref() {
                // count(Reg) folds to a Lit — the registered-class count,
                // constant by R1/C0 (V-IDX).
                Dom::Reg => Ok(Self::leaf(
                    Term::Lit(Lit::Nat(Nat::from(self.catalog.classes().len()))),
                    Sort::Nat,
                )),
                _ => {
                    let cd = self.check_dom(ctx, dm, child_depth)?;
                    Ok(Checked {
                        term: Arc::new(Term::Count(cd.dom)),
                        sort: Sort::Nat,
                        ref_free: cd.ref_free,
                    })
                }
            },
            Term::MaxT1(dm) => self.extremum(ctx, dm, child_depth, Term::MaxT1),
            Term::MinT1(dm) => self.extremum(ctx, dm, child_depth, Term::MinT1),
            Term::BigUnion { dom, var, body } => {
                // PC2a excludes Reg from ⋃; Addr and Tup element sorts bind.
                let cd = self.check_dom(ctx, dom, child_depth)?;
                let inner = ctx.update(*var, cd.elem);
                let cb = self.sub(&inner, body, Sort::AddrSet, child_depth)?;
                Ok(Checked {
                    term: Arc::new(Term::BigUnion { dom: cd.dom, var: *var, body: cb.term }),
                    sort: Sort::AddrSet,
                    ref_free: cd.ref_free && cb.ref_free,
                })
            }
            Term::Reflect(dm) => {
                // QD-refl: only an address-valued domain reflects; a
                // tuple-valued (or class-valued Reg) domain is rejected at
                // the element-sort check.
                let cd = self.check_dom(ctx, dm, child_depth)?;
                want(Sort::Addr, cd.elem)?;
                Ok(Checked {
                    term: Arc::new(Term::Reflect(cd.dom)),
                    sort: Sort::AddrSet,
                    ref_free: cd.ref_free,
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
                // chain), and the referent's own. A derivation that cannot
                // complete at that level is THIS node's TooDeep — the same
                // answer the reach check below gives on a memo hit — and
                // says nothing about the referent.
                let referent = (self.resolve)(addr, depth + DERIVATION_COST).map_err(|u| match u {
                    Unresolved::Dangling => TypeError::DanglingReference(addr.clone()),
                    Unresolved::TooDeep => TypeError::TooDeep,
                })?;
                let params = referent.params();
                let mut checked_args: Vec<ArcTerm> = Vec::with_capacity(args.len());
                for (i, arg) in args.iter().enumerate() {
                    // PR3a binds each argument through a `Let` AT ITS OWN
                    // POSITION, so argument `i` sits `i` levels below this
                    // node in the flat expansion and its own expansion sits
                    // below that. Each is therefore charged AT that position,
                    // which is what keeps the invariant every walk over the
                    // expansion rests on: a subterm's expansion position is
                    // never deeper than its checked depth. The `arity` term
                    // below bounds the referent's splice point and nothing
                    // else, so without this charge `arity + argument reach`
                    // could carry the expansion past `MAX_DEPTH` while every
                    // recorded level stayed inside it — and that expansion is
                    // what `certify_stable`'s and `certify_rule`'s analyses
                    // walk, with no bound of their own.
                    let pos = child_depth.saturating_add(u32::try_from(i).unwrap_or(u32::MAX));
                    let c = self.check_term(ctx, arg, pos)?;
                    match params.get(i) {
                        Some((_, s)) => want(*s, c.sort)?,
                        None => {
                            return Err(TypeError::SortMismatch {
                                expected: referent.result,
                                found: c.sort,
                            })
                        }
                    }
                    checked_args.push(c.term);
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
                    .saturating_add(referent.reach);
                if reach > MAX_DEPTH {
                    return Err(TypeError::TooDeep);
                }
                // The levels a walk through this node reaches are the
                // referent's, which no `enter` on this pass records.
                self.deepest.set(self.deepest.get().max(reach));
                Ok(Checked {
                    term: Arc::new(Term::Ref { addr: addr.clone(), args: checked_args }),
                    sort: referent.result,
                    ref_free: false,
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
            let inst = SubstClassVar { cvar, key, nodes: &self.nodes }.term(body);
            if self.nodes.spent() {
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
                },
            });
        }
        Ok(acc.expect("the catalog holds the five shipped classes at minimum"))
    }

    fn check_atom(&self, ctx: &Ctx, a: &Atom, depth: u32) -> Result<Checked, TypeError> {
        let child_depth = depth + 1;
        // A V-TUP variable must be a Tup-sorted binding in scope.
        let tup_var = |v: VarId| -> Result<VarId, TypeError> {
            match ctx.get(&v) {
                Some(Sort::Tup) => Ok(v),
                Some(s) => Err(TypeError::SortMismatch { expected: Sort::Tup, found: *s }),
                None => Err(TypeError::UnboundVariable(v)),
            }
        };
        // A one-argument atom at a type position: the argument at `sort`.
        let arg = |e: &ArcTerm, sort: Sort| self.sub(ctx, e, sort, child_depth);
        let (atom, sort, ref_free) = match a {
            Atom::IsK(tr, e) => {
                let k = self.guarded(tr, Guard::Cataloged)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::IsK(TypeRef::Concrete(k), c.term), Sort::Bool, c.ref_free)
            }
            Atom::Members(tr) => {
                let k = self.guarded(tr, Guard::Cataloged)?;
                (Atom::Members(TypeRef::Concrete(k)), Sort::AddrSet, true)
            }
            Atom::TargetsOf(tr, e) => {
                let k = self.guarded(tr, Guard::Cataloged)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::TargetsOf(TypeRef::Concrete(k), c.term), Sort::AddrSet, c.ref_free)
            }
            Atom::IsFiltered(tr, e) => {
                let k = self.guarded(tr, Guard::Needs(Behavior::ReadFilter))?;
                let c = arg(e, Sort::Addr)?;
                (Atom::IsFiltered(TypeRef::Concrete(k), c.term), Sort::Bool, c.ref_free)
            }
            Atom::Succs(tr, e) => {
                let k = self.guarded(tr, Guard::Walk)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::Succs(TypeRef::Concrete(k), c.term), Sort::AddrSet, c.ref_free)
            }
            Atom::Chain(tr, e) => {
                let k = self.guarded(tr, Guard::Walk)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::Chain(TypeRef::Concrete(k), c.term), Sort::AddrSeq, c.ref_free)
            }
            Atom::Tip(tr, e) => {
                let k = self.guarded(tr, Guard::Walk)?;
                let c = arg(e, Sort::Addr)?;
                (Atom::Tip(TypeRef::Concrete(k), c.term), Sort::OptAddr, c.ref_free)
            }
            Atom::IsInChain(tr, e1, e2) => {
                let k = self.guarded(tr, Guard::Walk)?;
                let c1 = arg(e1, Sort::Addr)?;
                let c2 = arg(e2, Sort::Addr)?;
                (
                    Atom::IsInChain(TypeRef::Concrete(k), c1.term, c2.term),
                    Sort::Bool,
                    c1.ref_free && c2.ref_free,
                )
            }
            Atom::SourcesTo(tr, e) => {
                let k = self.guarded(tr, Guard::Needs(Behavior::ReverseLookup))?;
                let c = arg(e, Sort::Addr)?;
                (Atom::SourcesTo(TypeRef::Concrete(k), c.term), Sort::AddrSet, c.ref_free)
            }
            Atom::TargetOf(tr, e) => {
                let k = self.guarded(tr, Guard::Needs(Behavior::ReverseLookup))?;
                let c = arg(e, Sort::Addr)?;
                (Atom::TargetOf(TypeRef::Concrete(k), c.term), Sort::OptAddr, c.ref_free)
            }
            Atom::TargetsKeyed(e) => {
                // V-atom: in the vocabulary iff some cataloged class declares
                // `ReverseLookup` (BH3).
                if !self.catalog.has_reverse_lookup_class() {
                    return Err(TypeError::NoReverseLookupClass);
                }
                let c = arg(e, Sort::Addr)?;
                (Atom::TargetsKeyed(c.term), Sort::Map, c.ref_free)
            }
            Atom::Age(tr, e) => {
                let k = self.guarded(tr, Guard::Needs(Behavior::Age))?;
                let c = arg(e, Sort::Addr)?;
                (Atom::Age(TypeRef::Concrete(k), c.term), Sort::OptNat, c.ref_free)
            }
            Atom::Stale(tr, e) => {
                let k = self.guarded(tr, Guard::Needs(Behavior::Age))?;
                let c = arg(e, Sort::Nat)?;
                (Atom::Stale(TypeRef::Concrete(k), c.term), Sort::AddrSet, c.ref_free)
            }
            Atom::IsDoc(e) => {
                let c = arg(e, Sort::Addr)?;
                (Atom::IsDoc(c.term), Sort::Bool, c.ref_free)
            }
            Atom::TupAddr(v) => (Atom::TupAddr(tup_var(*v)?), Sort::Addr, true),
            Atom::TupAddrsF(v) => (Atom::TupAddrsF(tup_var(*v)?), Sort::AddrSet, true),
            Atom::TupAddrsG(v) => (Atom::TupAddrsG(tup_var(*v)?), Sort::AddrSet, true),
            Atom::InCoverageF(e, v) => {
                let c = arg(e, Sort::Addr)?;
                (Atom::InCoverageF(c.term, tup_var(*v)?), Sort::Bool, c.ref_free)
            }
            Atom::InCoverageG(e, v) => {
                let c = arg(e, Sort::Addr)?;
                (Atom::InCoverageG(c.term, tup_var(*v)?), Sort::Bool, c.ref_free)
            }
        };
        Ok(Checked { term: Arc::new(Term::Atom(atom)), sort, ref_free })
    }

    /// A binary prim over two children of one sort, the node rebuilt through
    /// its constructor.
    fn prim2(
        &self,
        ctx: &Ctx,
        x: &ArcTerm,
        y: &ArcTerm,
        depth: u32,
        rule: PrimRule,
        mk: fn(ArcTerm, ArcTerm) -> Prim,
    ) -> Result<Checked, TypeError> {
        let cx = self.sub(ctx, x, rule.operand, depth)?;
        let cy = self.sub(ctx, y, rule.operand, depth)?;
        Ok(Checked {
            term: Arc::new(Term::Prim(mk(cx.term, cy.term))),
            sort: rule.result,
            ref_free: cx.ref_free && cy.ref_free,
        })
    }

    /// A unary prim over one child.
    fn prim1(
        &self,
        ctx: &Ctx,
        x: &ArcTerm,
        depth: u32,
        rule: PrimRule,
        mk: fn(ArcTerm) -> Prim,
    ) -> Result<Checked, TypeError> {
        let cx = self.sub(ctx, x, rule.operand, depth)?;
        Ok(Checked {
            term: Arc::new(Term::Prim(mk(cx.term))),
            sort: rule.result,
            ref_free: cx.ref_free,
        })
    }

    fn check_prim(&self, ctx: &Ctx, p: &Prim, depth: u32) -> Result<Checked, TypeError> {
        let child_depth = depth + 1;
        match p {
            Prim::AddrEq(a, b) => self.prim2(ctx, a, b, child_depth, ADDR_PRED, Prim::AddrEq),
            Prim::Prefix(a, b) => self.prim2(ctx, a, b, child_depth, ADDR_PRED, Prim::Prefix),
            Prim::T1Lt(a, b) => self.prim2(ctx, a, b, child_depth, ADDR_PRED, Prim::T1Lt),
            Prim::SetEq(a, b) => self.prim2(ctx, a, b, child_depth, SET_PRED, Prim::SetEq),
            Prim::NatEq(a, b) => self.prim2(ctx, a, b, child_depth, NAT_PRED, Prim::NatEq),
            Prim::NatLe(a, b) => self.prim2(ctx, a, b, child_depth, NAT_PRED, Prim::NatLe),
            Prim::NatAdd(a, b) => self.prim2(ctx, a, b, child_depth, NAT_OP, Prim::NatAdd),
            Prim::IsEmpty(s) => self.prim1(ctx, s, child_depth, SET_PRED, Prim::IsEmpty),
            Prim::Elems(q) => self.prim1(ctx, q, child_depth, SEQ_ELEMS, Prim::Elems),
            Prim::SetMem(x, s) => {
                let cx = self.sub(ctx, x, Sort::Addr, child_depth)?;
                let cs = self.sub(ctx, s, Sort::AddrSet, child_depth)?;
                Ok(Checked {
                    term: Arc::new(Term::Prim(Prim::SetMem(cx.term, cs.term))),
                    sort: Sort::Bool,
                    ref_free: cx.ref_free && cs.ref_free,
                })
            }
            Prim::MapGet(m, tr) => {
                // V-PRIM admits ·[K] per registered class — cataloged-only,
                // no behavior requirement; a non-BH3/absent key denotes ⊥.
                let k = self.guarded(tr, Guard::Cataloged)?;
                let cm = self.sub(ctx, m, Sort::Map, child_depth)?;
                Ok(Checked {
                    term: Arc::new(Term::Prim(Prim::MapGet(cm.term, TypeRef::Concrete(k)))),
                    sort: Sort::OptAddr,
                    ref_free: cm.ref_free,
                })
            }
            Prim::Def(x) => {
                let c = self.check_term(ctx, x, child_depth)?;
                match c.sort {
                    Sort::OptAddr | Sort::OptNat => {}
                    other => return Err(TypeError::SortMismatch { expected: Sort::OptAddr, found: other }),
                }
                Ok(Checked {
                    term: Arc::new(Term::Prim(Prim::Def(c.term))),
                    sort: Sort::Bool,
                    ref_free: c.ref_free,
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
        // A domain former carries no unbounded payload of its own: its type
        // position is a cataloged endset (`guarded`), its children are terms.
        self.enter(1, depth)?;
        let child_depth = depth + 1;
        let leaf = |dom: Dom, elem: Sort| CheckedDom { dom: Arc::new(dom), elem, ref_free: true };
        match dm {
            Dom::MembersDom(tr) => {
                let k = self.guarded(tr, Guard::Cataloged)?;
                Ok(leaf(Dom::MembersDom(TypeRef::Concrete(k)), Sort::Addr))
            }
            Dom::ActiveSlice(tr) => {
                let k = self.guarded(tr, Guard::Cataloged)?;
                Ok(leaf(Dom::ActiveSlice(TypeRef::Concrete(k)), Sort::Tup))
            }
            Dom::AuditSlice(tr) => {
                let k = self.guarded(tr, Guard::Cataloged)?;
                Ok(leaf(Dom::AuditSlice(TypeRef::Concrete(k)), Sort::Tup))
            }
            Dom::LinkDom => Ok(leaf(Dom::LinkDom, Sort::Addr)),
            Dom::Reg => Err(TypeError::SortMismatch { expected: Sort::Addr, found: Sort::Tup }),
            Dom::Filter { dom, var, pred } => {
                let base = self.check_dom(ctx, dom, child_depth)?;
                let inner = ctx.update(*var, base.elem);
                let c = self.sub(&inner, pred, Sort::Bool, child_depth)?;
                Ok(CheckedDom {
                    dom: Arc::new(Dom::Filter { dom: base.dom, var: *var, pred: c.term }),
                    elem: base.elem,
                    ref_free: base.ref_free && c.ref_free,
                })
            }
            Dom::SetTerm(t) => {
                let c = self.sub(ctx, t, Sort::AddrSet, child_depth)?;
                Ok(CheckedDom {
                    dom: Arc::new(Dom::SetTerm(c.term)),
                    elem: Sort::Addr,
                    ref_free: c.ref_free,
                })
            }
        }
    }
}
