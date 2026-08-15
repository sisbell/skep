//! §Internal 1 — the type checker: a single bottom-up synthesis pass over the
//! raw `Term`, checked under the caller-supplied ordered parameter context
//! Γ_D (ASN-0129 WT is a Γ-parameterized CHECKING judgment), with `Reg`
//! expansion (V-IDX), the catalog + behavior guards (V-STAT), and WT-ref via
//! the signature resolver. Decided once at construction, valid at every
//! reachable state (WT).

use std::sync::Arc;

use skep_address::Address;
use skep_links::Behavior;

use crate::ast::{subst_classvar_term, ArcDom, ArcTerm, Atom, Dom, Lit, Prim, Term, TypeKey, TypeRef, VarId};
use crate::catalog::{CatalogEntry, TypeCatalog};
use crate::error::TypeError;
use crate::value::{Signature, Sort};
use skep_address::Nat;

/// The post-type-check form. Carries Γ_D (read back via [`TypedTerm::params`]
/// / [`TypedTerm::result_sort`]), the ref-free flag, the original
/// pre-`Reg`-expansion syntactic body ([`TypedTerm::source_body`] — the
/// compact canonical form `define_predicate` encodes, §Internal 4), and the
/// expanded evaluable projection (every `TypeRef` `Concrete`, no surviving
/// `Reg` quantifier). Deliberately carries NO view (PR-VIEW): the view is an
/// evaluation/classification parameter, never a term annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedTerm {
    pub(crate) gamma: Vec<(VarId, Sort)>,
    pub(crate) result: Sort,
    pub(crate) source: Term,
    pub(crate) evaluable: ArcTerm,
    pub(crate) ref_free: bool,
}

impl TypedTerm {
    /// Γ_D — the ordered free-parameter context this term was checked under.
    pub fn params(&self) -> &[(VarId, Sort)] {
        &self.gamma
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
    /// `ClassVar` refs intact) — distinct from the expanded evaluable tree.
    pub fn source_body(&self) -> &Term {
        &self.source
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

pub(crate) struct Checked {
    pub(crate) term: ArcTerm,
    pub(crate) sort: Sort,
    pub(crate) ref_free: bool,
}

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

/// The checking pass. `resolve` is the signature resolver WT-ref consults —
/// the only external consultation (it reads the immutable sig memo, so even
/// ref-bearing type-checking is "decided once").
pub(crate) struct Checker<'a> {
    pub(crate) catalog: &'a TypeCatalog,
    pub(crate) resolve: &'a dyn Fn(&Address) -> Option<Signature>,
}

impl<'a> Checker<'a> {
    /// Resolve a type position: a surviving `ClassVar` (no enclosing `Reg`
    /// binder substituted it) is `UnboundClassVar`; a `Concrete` key is
    /// probed by `Endset`-equality — absent ⇒ `UnregisteredType` (which also
    /// rules out non-address-denoting keys and coverage-equal-but-
    /// byte-different misses).
    fn typeref(&self, tr: &TypeRef) -> Result<(TypeKey, &CatalogEntry), TypeError> {
        match tr {
            TypeRef::ClassVar(v) => Err(TypeError::UnboundClassVar(v.clone())),
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

    fn sub(&self, ctx: &Ctx, t: &ArcTerm, expected: Sort) -> Result<(ArcTerm, bool), TypeError> {
        let c = self.check_term(ctx, t)?;
        want(expected, c.sort)?;
        Ok((c.term, c.ref_free))
    }

    pub(crate) fn check_term(&self, ctx: &Ctx, t: &Term) -> Result<Checked, TypeError> {
        match t {
            Term::Var(v) => match ctx.get(v) {
                Some(s) => Ok(Checked { term: Arc::new(Term::Var(v.clone())), sort: *s, ref_free: true }),
                None => Err(TypeError::UnboundVariable(v.clone())),
            },
            Term::Lit(l) => {
                let sort = match l {
                    Lit::True | Lit::False => Sort::Bool,
                    Lit::Nat(_) => Sort::Nat,
                    Lit::Addr(_) => Sort::Addr,
                    Lit::BotAddr => Sort::OptAddr,
                    Lit::BotNat => Sort::OptNat,
                };
                Ok(Checked { term: Arc::new(Term::Lit(l.clone())), sort, ref_free: true })
            }
            Term::Atom(a) => self.check_atom(ctx, a),
            Term::Prim(p) => self.check_prim(ctx, p),
            Term::And(a, b) | Term::Or(a, b) | Term::Implies(a, b) | Term::Iff(a, b) => {
                let (ea, ra) = self.sub(ctx, a, Sort::Bool)?;
                let (eb, rb) = self.sub(ctx, b, Sort::Bool)?;
                let term = match t {
                    Term::And(..) => Term::And(ea, eb),
                    Term::Or(..) => Term::Or(ea, eb),
                    Term::Implies(..) => Term::Implies(ea, eb),
                    _ => Term::Iff(ea, eb),
                };
                Ok(Checked { term: Arc::new(term), sort: Sort::Bool, ref_free: ra && rb })
            }
            Term::Not(a) => {
                let (ea, ra) = self.sub(ctx, a, Sort::Bool)?;
                Ok(Checked { term: Arc::new(Term::Not(ea)), sort: Sort::Bool, ref_free: ra })
            }
            Term::Forall { var, dom, body } if matches!(dom.as_ref(), Dom::Reg) => {
                self.expand_reg(ctx, var, body, true)
            }
            Term::Exists { var, dom, body } if matches!(dom.as_ref(), Dom::Reg) => {
                self.expand_reg(ctx, var, body, false)
            }
            Term::Forall { var, dom, body } | Term::Exists { var, dom, body } => {
                let d = self.check_dom(ctx, dom)?;
                let ctx2 = ctx.update(var.clone(), d.elem);
                let (eb, rb) = {
                    let c = self.check_term(&ctx2, body)?;
                    want(Sort::Bool, c.sort)?;
                    (c.term, c.ref_free)
                };
                let term = if matches!(t, Term::Forall { .. }) {
                    Term::Forall { var: var.clone(), dom: d.dom, body: eb }
                } else {
                    Term::Exists { var: var.clone(), dom: d.dom, body: eb }
                };
                Ok(Checked { term: Arc::new(term), sort: Sort::Bool, ref_free: d.ref_free && rb })
            }
            Term::Let { var, bound, body } => {
                let cb = self.check_term(ctx, bound)?;
                let ctx2 = ctx.update(var.clone(), cb.sort);
                let cy = self.check_term(&ctx2, body)?;
                Ok(Checked {
                    term: Arc::new(Term::Let { var: var.clone(), bound: cb.term, body: cy.term }),
                    sort: cy.sort,
                    ref_free: cb.ref_free && cy.ref_free,
                })
            }
            Term::IfSome { opt, var, then_, else_ } => {
                // The binder guard narrows T∪{⊥} → T (resp. ℕ∪{⊥} → ℕ) in
                // the then-branch (PC2).
                let co = self.check_term(ctx, opt)?;
                let narrowed = match co.sort {
                    Sort::OptAddr => Sort::Addr,
                    Sort::OptNat => Sort::Nat,
                    other => return Err(TypeError::SortMismatch { expected: Sort::OptAddr, found: other }),
                };
                let ctx2 = ctx.update(var.clone(), narrowed);
                let ct = self.check_term(&ctx2, then_)?;
                let ce = self.check_term(ctx, else_)?;
                want(ct.sort, ce.sort)?;
                Ok(Checked {
                    term: Arc::new(Term::IfSome {
                        opt: co.term,
                        var: var.clone(),
                        then_: ct.term,
                        else_: ce.term,
                    }),
                    sort: ct.sort,
                    ref_free: co.ref_free && ct.ref_free && ce.ref_free,
                })
            }
            Term::Count(d) => match d.as_ref() {
                // count(Reg) folds to a Lit — the registered-class count,
                // constant by R1/C0 (V-IDX).
                Dom::Reg => Ok(Checked {
                    term: Arc::new(Term::Lit(Lit::Nat(Nat::from(self.catalog.classes().len() as u64)))),
                    sort: Sort::Nat,
                    ref_free: true,
                }),
                _ => {
                    let cd = self.check_dom(ctx, d)?;
                    Ok(Checked { term: Arc::new(Term::Count(cd.dom)), sort: Sort::Nat, ref_free: cd.ref_free })
                }
            },
            Term::MaxT1(d) | Term::MinT1(d) => {
                let cd = self.check_dom(ctx, d)?;
                want(Sort::Addr, cd.elem)?;
                let term = if matches!(t, Term::MaxT1(_)) { Term::MaxT1(cd.dom) } else { Term::MinT1(cd.dom) };
                Ok(Checked { term: Arc::new(term), sort: Sort::OptAddr, ref_free: cd.ref_free })
            }
            Term::BigUnion { dom, var, body } => {
                // PC2a excludes Reg from ⋃; Addr and Tup element sorts bind.
                let cd = self.check_dom(ctx, dom)?;
                let ctx2 = ctx.update(var.clone(), cd.elem);
                let (eb, rb) = {
                    let c = self.check_term(&ctx2, body)?;
                    want(Sort::AddrSet, c.sort)?;
                    (c.term, c.ref_free)
                };
                Ok(Checked {
                    term: Arc::new(Term::BigUnion { dom: cd.dom, var: var.clone(), body: eb }),
                    sort: Sort::AddrSet,
                    ref_free: cd.ref_free && rb,
                })
            }
            Term::Reflect(d) => {
                // QD-refl: only an address-valued domain reflects; a
                // tuple-valued (or class-valued Reg) domain is rejected at
                // the element-sort check.
                let cd = self.check_dom(ctx, d)?;
                want(Sort::Addr, cd.elem)?;
                Ok(Checked { term: Arc::new(Term::Reflect(cd.dom)), sort: Sort::AddrSet, ref_free: cd.ref_free })
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
                let sig = (self.resolve)(addr).ok_or_else(|| TypeError::DanglingReference(addr.clone()))?;
                let mut e_args: Vec<ArcTerm> = Vec::with_capacity(args.len());
                for (i, a) in args.iter().enumerate() {
                    let c = self.check_term(ctx, a)?;
                    match sig.params.get(i) {
                        Some((_, s)) => want(*s, c.sort)?,
                        None => {
                            return Err(TypeError::SortMismatch { expected: sig.result, found: c.sort })
                        }
                    }
                    e_args.push(c.term);
                }
                if args.len() < sig.params.len() {
                    return Err(TypeError::SortMismatch {
                        expected: sig.params[args.len()].1,
                        found: sig.result,
                    });
                }
                Ok(Checked {
                    term: Arc::new(Term::Ref { addr: addr.clone(), args: e_args }),
                    sort: sig.result,
                    ref_free: false,
                })
            }
        }
    }

    /// V-IDX `Reg` expansion: instantiate `body` once per registered class,
    /// substituting `ClassVar(cvar) → Concrete(class)`, check EACH instance
    /// (an ill-typed one rejects the whole term — `RegInstanceIllTyped`), and
    /// emit the And/Or of the instances as the evaluable projection.
    fn expand_reg(&self, ctx: &Ctx, cvar: &VarId, body: &Term, conj: bool) -> Result<Checked, TypeError> {
        let mut acc: Option<(ArcTerm, bool)> = None;
        for key in self.catalog.classes() {
            let inst = subst_classvar_term(body, cvar, key);
            let c = self
                .check_term(ctx, &inst)
                .and_then(|c| {
                    want(Sort::Bool, c.sort)?;
                    Ok(c)
                })
                .map_err(|e| TypeError::RegInstanceIllTyped(Box::new(e)))?;
            acc = Some(match acc {
                None => (c.term, c.ref_free),
                Some((prev, rf)) => {
                    let joined = if conj { Term::And(prev, c.term) } else { Term::Or(prev, c.term) };
                    (Arc::new(joined), rf && c.ref_free)
                }
            });
        }
        let (term, ref_free) = acc.expect("the catalog holds the five shipped classes at minimum");
        Ok(Checked { term, sort: Sort::Bool, ref_free })
    }

    fn check_atom(&self, ctx: &Ctx, a: &Atom) -> Result<Checked, TypeError> {
        // A V-TUP variable must be a Tup-sorted binding in scope.
        let tup_var = |v: &VarId| -> Result<VarId, TypeError> {
            match ctx.get(v) {
                Some(Sort::Tup) => Ok(v.clone()),
                Some(s) => Err(TypeError::SortMismatch { expected: Sort::Tup, found: *s }),
                None => Err(TypeError::UnboundVariable(v.clone())),
            }
        };
        let (atom, sort, ref_free) = match a {
            Atom::IsK(tr, e) => {
                let (k, _) = self.typeref(tr)?;
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::IsK(TypeRef::Concrete(k), ee), Sort::Bool, rf)
            }
            Atom::Members(tr) => {
                let (k, _) = self.typeref(tr)?;
                (Atom::Members(TypeRef::Concrete(k)), Sort::AddrSet, true)
            }
            Atom::TargetsOf(tr, e) => {
                let (k, _) = self.typeref(tr)?;
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::TargetsOf(TypeRef::Concrete(k), ee), Sort::AddrSet, rf)
            }
            Atom::IsFiltered(tr, e) => {
                let (k, entry) = self.typeref(tr)?;
                self.need(&k, entry, Behavior::ReadFilter)?;
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::IsFiltered(TypeRef::Concrete(k), ee), Sort::Bool, rf)
            }
            Atom::Succs(tr, e) => {
                let k = self.bh2(tr)?;
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::Succs(TypeRef::Concrete(k), ee), Sort::AddrSet, rf)
            }
            Atom::Chain(tr, e) => {
                let k = self.bh2(tr)?;
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::Chain(TypeRef::Concrete(k), ee), Sort::AddrSeq, rf)
            }
            Atom::Tip(tr, e) => {
                let k = self.bh2(tr)?;
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::Tip(TypeRef::Concrete(k), ee), Sort::OptAddr, rf)
            }
            Atom::IsInChain(tr, e1, e2) => {
                let k = self.bh2(tr)?;
                let (a1, r1) = self.sub(ctx, e1, Sort::Addr)?;
                let (a2, r2) = self.sub(ctx, e2, Sort::Addr)?;
                (Atom::IsInChain(TypeRef::Concrete(k), a1, a2), Sort::Bool, r1 && r2)
            }
            Atom::SourcesTo(tr, e) => {
                let (k, entry) = self.typeref(tr)?;
                self.need(&k, entry, Behavior::ReverseLookup)?;
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::SourcesTo(TypeRef::Concrete(k), ee), Sort::AddrSet, rf)
            }
            Atom::TargetOf(tr, e) => {
                let (k, entry) = self.typeref(tr)?;
                self.need(&k, entry, Behavior::ReverseLookup)?;
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::TargetOf(TypeRef::Concrete(k), ee), Sort::OptAddr, rf)
            }
            Atom::TargetsKeyed(e) => {
                // V-atom: in the vocabulary iff some cataloged class attaches
                // BH3.
                if !self.catalog.has_bh3() {
                    return Err(TypeError::NoReverseLookupClass);
                }
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::TargetsKeyed(ee), Sort::Map, rf)
            }
            Atom::Age(tr, e) => {
                let (k, entry) = self.typeref(tr)?;
                self.need(&k, entry, Behavior::Age)?;
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::Age(TypeRef::Concrete(k), ee), Sort::OptNat, rf)
            }
            Atom::Stale(tr, e) => {
                let (k, entry) = self.typeref(tr)?;
                self.need(&k, entry, Behavior::Age)?;
                let (ee, rf) = self.sub(ctx, e, Sort::Nat)?;
                (Atom::Stale(TypeRef::Concrete(k), ee), Sort::AddrSet, rf)
            }
            Atom::IsDoc(e) => {
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::IsDoc(ee), Sort::Bool, rf)
            }
            Atom::TupAddr(v) => (Atom::TupAddr(tup_var(v)?), Sort::Addr, true),
            Atom::TupAddrsF(v) => (Atom::TupAddrsF(tup_var(v)?), Sort::AddrSet, true),
            Atom::TupAddrsG(v) => (Atom::TupAddrsG(tup_var(v)?), Sort::AddrSet, true),
            Atom::InCoverageF(e, v) => {
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::InCoverageF(ee, tup_var(v)?), Sort::Bool, rf)
            }
            Atom::InCoverageG(e, v) => {
                let (ee, rf) = self.sub(ctx, e, Sort::Addr)?;
                (Atom::InCoverageG(ee, tup_var(v)?), Sort::Bool, rf)
            }
        };
        Ok(Checked { term: Arc::new(Term::Atom(atom)), sort, ref_free })
    }

    fn check_prim(&self, ctx: &Ctx, p: &Prim) -> Result<Checked, TypeError> {
        let (prim, sort, ref_free) = match p {
            Prim::AddrEq(a, b) | Prim::Prefix(a, b) | Prim::T1Lt(a, b) => {
                let (ea, ra) = self.sub(ctx, a, Sort::Addr)?;
                let (eb, rb) = self.sub(ctx, b, Sort::Addr)?;
                let prim = match p {
                    Prim::AddrEq(..) => Prim::AddrEq(ea, eb),
                    Prim::Prefix(..) => Prim::Prefix(ea, eb),
                    _ => Prim::T1Lt(ea, eb),
                };
                (prim, Sort::Bool, ra && rb)
            }
            Prim::SetMem(x, s) => {
                let (ex, rx) = self.sub(ctx, x, Sort::Addr)?;
                let (es, rs) = self.sub(ctx, s, Sort::AddrSet)?;
                (Prim::SetMem(ex, es), Sort::Bool, rx && rs)
            }
            Prim::SetEq(a, b) => {
                let (ea, ra) = self.sub(ctx, a, Sort::AddrSet)?;
                let (eb, rb) = self.sub(ctx, b, Sort::AddrSet)?;
                (Prim::SetEq(ea, eb), Sort::Bool, ra && rb)
            }
            Prim::IsEmpty(s) => {
                let (es, rs) = self.sub(ctx, s, Sort::AddrSet)?;
                (Prim::IsEmpty(es), Sort::Bool, rs)
            }
            Prim::Elems(q) => {
                let (eq_, rq) = self.sub(ctx, q, Sort::AddrSeq)?;
                (Prim::Elems(eq_), Sort::AddrSet, rq)
            }
            Prim::NatEq(a, b) | Prim::NatLe(a, b) => {
                let (ea, ra) = self.sub(ctx, a, Sort::Nat)?;
                let (eb, rb) = self.sub(ctx, b, Sort::Nat)?;
                let prim = if matches!(p, Prim::NatEq(..)) { Prim::NatEq(ea, eb) } else { Prim::NatLe(ea, eb) };
                (prim, Sort::Bool, ra && rb)
            }
            Prim::NatAdd(a, b) => {
                let (ea, ra) = self.sub(ctx, a, Sort::Nat)?;
                let (eb, rb) = self.sub(ctx, b, Sort::Nat)?;
                (Prim::NatAdd(ea, eb), Sort::Nat, ra && rb)
            }
            Prim::MapGet(m, tr) => {
                // V-PRIM admits ·[K] per registered class — cataloged-only,
                // no behavior requirement; a non-BH3/absent key denotes ⊥.
                let (k, _) = self.typeref(tr)?;
                let (em, rm) = self.sub(ctx, m, Sort::Map)?;
                (Prim::MapGet(em, TypeRef::Concrete(k)), Sort::OptAddr, rm)
            }
            Prim::Def(x) => {
                let c = self.check_term(ctx, x)?;
                match c.sort {
                    Sort::OptAddr | Sort::OptNat => {}
                    other => return Err(TypeError::SortMismatch { expected: Sort::OptAddr, found: other }),
                }
                (Prim::Def(c.term), Sort::Bool, c.ref_free)
            }
        };
        Ok(Checked { term: Arc::new(Term::Prim(prim)), sort, ref_free })
    }

    /// The WT domain judgment `⊢ D dom(s)`, `s ∈ {Addr, Tup}`. A `Reg` in a
    /// non-quantifier/`Count` position — including here — is class-valued and
    /// has no element sort; per the design's "likewise rejected at the
    /// element-sort check" it surfaces as `SortMismatch{expected: Addr,
    /// found: Tup}` (the vocabulary has no class sort to name).
    pub(crate) fn check_dom(&self, ctx: &Ctx, d: &Dom) -> Result<CheckedDom, TypeError> {
        match d {
            Dom::MembersDom(tr) => {
                let (k, _) = self.typeref(tr)?;
                Ok(CheckedDom {
                    dom: Arc::new(Dom::MembersDom(TypeRef::Concrete(k))),
                    elem: Sort::Addr,
                    ref_free: true,
                })
            }
            Dom::ActiveSlice(tr) => {
                let (k, _) = self.typeref(tr)?;
                Ok(CheckedDom {
                    dom: Arc::new(Dom::ActiveSlice(TypeRef::Concrete(k))),
                    elem: Sort::Tup,
                    ref_free: true,
                })
            }
            Dom::AuditSlice(tr) => {
                let (k, _) = self.typeref(tr)?;
                Ok(CheckedDom {
                    dom: Arc::new(Dom::AuditSlice(TypeRef::Concrete(k))),
                    elem: Sort::Tup,
                    ref_free: true,
                })
            }
            Dom::LinkDom => Ok(CheckedDom { dom: Arc::new(Dom::LinkDom), elem: Sort::Addr, ref_free: true }),
            Dom::Reg => Err(TypeError::SortMismatch { expected: Sort::Addr, found: Sort::Tup }),
            Dom::Filter { dom, var, pred } => {
                let base = self.check_dom(ctx, dom)?;
                let ctx2 = ctx.update(var.clone(), base.elem);
                let c = self.check_term(&ctx2, pred)?;
                want(Sort::Bool, c.sort)?;
                Ok(CheckedDom {
                    dom: Arc::new(Dom::Filter { dom: base.dom, var: var.clone(), pred: c.term }),
                    elem: base.elem,
                    ref_free: base.ref_free && c.ref_free,
                })
            }
            Dom::SetTerm(t) => {
                let c = self.check_term(ctx, t)?;
                want(Sort::AddrSet, c.sort)?;
                Ok(CheckedDom { dom: Arc::new(Dom::SetTerm(c.term)), elem: Sort::Addr, ref_free: c.ref_free })
            }
        }
    }
}
