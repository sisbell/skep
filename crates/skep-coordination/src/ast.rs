//! §Core data model — the PL AST: a finite, acyclic, tagged-union tree in two
//! mutually-recursive families ([`Term`]/[`Dom`]), reified (not
//! closure-encoded) so the three syntax-directed analyses — type-check,
//! footprint, stability — can read structure. Subterms are `Arc`-shared.

use std::sync::Arc;

use skep_address::{Address, Nat};
use skep_links::Endset;

/// `Arc`-shared term node.
pub type ArcTerm = Arc<Term>;
/// `Arc`-shared domain node.
pub type ArcDom = Arc<Dom>;

/// The reserved-expansion-name watershed: `VarId(v)` with `v ≥
/// EXPANSION_NAME_BASE` is reserved for reference-expansion fresh names
/// (PR-ENC's reserved supply, §Internal 4) — no recorded parameter name and no
/// body binder may inhabit it.
pub const EXPANSION_NAME_BASE: u32 = 1 << 31;

/// A PL variable name.
///
/// The reservation is structural, not merely intended: [`VarId::new`] — the
/// sole public constructor — rejects the reserved range, expansion names are
/// minted only by the crate-private flattening counter (§Internal 4), and the
/// def codec rejects a reserved-range `VarId` in a decoded body
/// (`ParseFailed`), so PR-ENC's body-binder-disjointness holds by
/// construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarId(pub(crate) u32);

impl VarId {
    /// The sole public constructor — the reservation's enforcement point:
    /// `None ⇔ v ≥ EXPANSION_NAME_BASE`.
    pub fn new(v: u32) -> Option<VarId> {
        if v >= EXPANSION_NAME_BASE {
            None
        } else {
            Some(VarId(v))
        }
    }
}

/// A registered/reserved type, named by its key endset.
///
/// Caller contract (§Core data model): the catalog probe is `Endset`-equality
/// while M7's type identity is by coverage (I0), so every `Concrete` `TypeKey`
/// MUST be built from a canonical catalog endset —
/// `Coordinator::reserved_type(ShippedType)`, the shipped five being the
/// catalog's whole population. A coverage-equal-but-byte-different key
/// misses as `UnregisteredType`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeKey(pub Endset);

/// A type position: a concrete cataloged type OR a class variable bound by an
/// enclosing `Reg` quantifier (V-IDX). `Reg`-expansion substitutes
/// `ClassVar(cvar) → Concrete(class)` per registered class at type-check, so
/// a `TypedTerm`'s evaluable projection holds only `Concrete` refs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeRef {
    Concrete(TypeKey),
    ClassVar(VarId),
}

/// PL term formers (ASN-0129 PC0–PC2a, QD-refl; ASN-0130 `Ref`).
#[allow(clippy::large_enum_variant)] // the interface declares these shapes verbatim
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Var(VarId),
    /// ⊤ ⊥ ℕ-lit addr-lit ; ⊥:T∪{⊥} ; ⊥:ℕ∪{⊥}.
    Lit(Lit),
    /// State-reading atoms (BH1–BH4, V-DOC, V-TUP).
    Atom(Atom),
    /// V-PRIM ops: = ≼ T1 ∈ set= =∅ elems ℕ(= ≤ +) ·\[K\] def.
    Prim(Prim),
    And(ArcTerm, ArcTerm),
    Or(ArcTerm, ArcTerm),
    Not(ArcTerm),
    /// PC0.
    Implies(ArcTerm, ArcTerm),
    /// PC0.
    Iff(ArcTerm, ArcTerm),
    /// PC1 (`Reg`-quantifiers expanded away by `type_check`).
    Forall { var: VarId, dom: ArcDom, body: ArcTerm },
    /// PC1.
    Exists { var: VarId, dom: ArcDom, body: ArcTerm },
    /// PC2 plain composition.
    Let { var: VarId, bound: ArcTerm, body: ArcTerm },
    /// PC2 binder guard — narrows `T∪{⊥} → T` (resp. `ℕ∪{⊥} → ℕ`) in `then_`.
    IfSome { opt: ArcTerm, var: VarId, then_: ArcTerm, else_: ArcTerm },
    /// PC2a.
    Count(ArcDom),
    /// PC2a — global T1 order-extremum over an address-valued domain.
    MaxT1(ArcDom),
    /// PC2a.
    MinT1(ArcDom),
    /// PC2a ⋃(D, f).
    BigUnion { dom: ArcDom, var: VarId, body: ArcTerm },
    /// QD-refl: address-valued domain → ℘_fin(T) term.
    Reflect(ArcDom),
    /// ASN-0130; only inside stored-def bodies — ref-bearing ⇒
    /// `is_ref_free() == false`.
    Ref { addr: Address, args: Vec<ArcTerm> },
}

/// State-reading atoms (ASN-0128/0129).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Atom {
    /// Core (view-parameterized).
    IsK(TypeRef, ArcTerm),
    /// Core — `M_K`'s dedicated view-parameterized term twin.
    Members(TypeRef),
    /// Core (view-parameterized).
    TargetsOf(TypeRef, ArcTerm),
    /// BH1.
    IsFiltered(TypeRef, ArcTerm),
    /// BH2 (fixed active; v1 served only at the shipped `Supersedes` key).
    Succs(TypeRef, ArcTerm),
    /// BH2.
    Chain(TypeRef, ArcTerm),
    /// BH2.
    Tip(TypeRef, ArcTerm),
    /// BH2.
    IsInChain(TypeRef, ArcTerm, ArcTerm),
    /// BH3 (fixed active).
    SourcesTo(TypeRef, ArcTerm),
    /// BH3.
    TargetOf(TypeRef, ArcTerm),
    /// BH3 — class-unindexed join.
    TargetsKeyed(ArcTerm),
    /// BH4 (fixed active + home-frontier).
    Age(TypeRef, ArcTerm),
    /// BH4.
    Stale(TypeRef, ArcTerm),
    /// V-DOC.
    IsDoc(ArcTerm),
    /// V-TUP (state-independent).
    TupAddr(VarId),
    /// V-TUP.
    TupAddrsF(VarId),
    /// V-TUP.
    TupAddrsG(VarId),
    /// V-TUP.
    InCoverageF(ArcTerm, VarId),
    /// V-TUP.
    InCoverageG(ArcTerm, VarId),
}

/// Quantification/fold domains (ASN-0129 QD).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dom {
    /// `M_K` : dom(T), view-parameterized.
    MembersDom(TypeRef),
    /// `A_K` : dom(Tup), fixed active.
    ActiveSlice(TypeRef),
    /// `L_K` : dom(Tup), fixed audit.
    AuditSlice(TypeRef),
    /// `L_dom` : dom(T) — the typed-relation sublayer only (open MAKELINK
    /// links are outside PL's universe).
    LinkDom,
    /// Class-valued; quantification-only (admissible under exactly
    /// `Forall`/`Exists`/`Count`); expanded/folded at type_check (V-IDX).
    Reg,
    Filter { dom: ArcDom, var: VarId, pred: ArcTerm },
    /// QD set-valued-term closure: a ℘_fin(T)-valued term reflected as a
    /// domain.
    SetTerm(ArcTerm),
}

/// Literals. `BotAddr : T∪{⊥}`, `BotNat : ℕ∪{⊥}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lit {
    True,
    False,
    Nat(Nat),
    Addr(Address),
    BotAddr,
    BotNat,
}

/// V-PRIM operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prim {
    /// Address `=`.
    AddrEq(ArcTerm, ArcTerm),
    /// `≼` (tumbler prefix).
    Prefix(ArcTerm, ArcTerm),
    /// T1 strict order.
    T1Lt(ArcTerm, ArcTerm),
    /// `∈` on ℘_fin(T).
    SetMem(ArcTerm, ArcTerm),
    /// `=` on ℘_fin(T).
    SetEq(ArcTerm, ArcTerm),
    /// `= ∅`.
    IsEmpty(ArcTerm),
    /// Seq_fin(T) → ℘_fin(T).
    Elems(ArcTerm),
    NatEq(ArcTerm, ArcTerm),
    NatLe(ArcTerm, ArcTerm),
    NatAdd(ArcTerm, ArcTerm),
    /// `·[K]` on Map_fin — per registered class, no behavior requirement.
    MapGet(ArcTerm, TypeRef),
    /// Definedness `· ≠ ⊥`.
    Def(ArcTerm),
}

// ───────────────────────── structural helpers ─────────────────────────

/// Substitute `TypeRef::ClassVar(cvar) → TypeRef::Concrete(key)` throughout
/// `t`, stopping at an inner `Reg` binder that rebinds `cvar` (shadowing) —
/// the V-IDX expansion step (§Internal 1).
pub(crate) fn subst_classvar_term(t: &Term, cvar: &VarId, key: &TypeKey) -> Term {
    let s = |x: &ArcTerm| -> ArcTerm { Arc::new(subst_classvar_term(x, cvar, key)) };
    let sd = |d: &ArcDom| -> ArcDom { Arc::new(subst_classvar_dom(d, cvar, key)) };
    let str_ = |tr: &TypeRef| subst_typeref(tr, cvar, key);
    match t {
        Term::Var(v) => Term::Var(v.clone()),
        Term::Lit(l) => Term::Lit(l.clone()),
        Term::Atom(a) => Term::Atom(match a {
            Atom::IsK(tr, e) => Atom::IsK(str_(tr), s(e)),
            Atom::Members(tr) => Atom::Members(str_(tr)),
            Atom::TargetsOf(tr, e) => Atom::TargetsOf(str_(tr), s(e)),
            Atom::IsFiltered(tr, e) => Atom::IsFiltered(str_(tr), s(e)),
            Atom::Succs(tr, e) => Atom::Succs(str_(tr), s(e)),
            Atom::Chain(tr, e) => Atom::Chain(str_(tr), s(e)),
            Atom::Tip(tr, e) => Atom::Tip(str_(tr), s(e)),
            Atom::IsInChain(tr, a1, a2) => Atom::IsInChain(str_(tr), s(a1), s(a2)),
            Atom::SourcesTo(tr, e) => Atom::SourcesTo(str_(tr), s(e)),
            Atom::TargetOf(tr, e) => Atom::TargetOf(str_(tr), s(e)),
            Atom::TargetsKeyed(e) => Atom::TargetsKeyed(s(e)),
            Atom::Age(tr, e) => Atom::Age(str_(tr), s(e)),
            Atom::Stale(tr, e) => Atom::Stale(str_(tr), s(e)),
            Atom::IsDoc(e) => Atom::IsDoc(s(e)),
            Atom::TupAddr(v) => Atom::TupAddr(v.clone()),
            Atom::TupAddrsF(v) => Atom::TupAddrsF(v.clone()),
            Atom::TupAddrsG(v) => Atom::TupAddrsG(v.clone()),
            Atom::InCoverageF(e, v) => Atom::InCoverageF(s(e), v.clone()),
            Atom::InCoverageG(e, v) => Atom::InCoverageG(s(e), v.clone()),
        }),
        Term::Prim(p) => Term::Prim(match p {
            Prim::AddrEq(a, b) => Prim::AddrEq(s(a), s(b)),
            Prim::Prefix(a, b) => Prim::Prefix(s(a), s(b)),
            Prim::T1Lt(a, b) => Prim::T1Lt(s(a), s(b)),
            Prim::SetMem(a, b) => Prim::SetMem(s(a), s(b)),
            Prim::SetEq(a, b) => Prim::SetEq(s(a), s(b)),
            Prim::IsEmpty(a) => Prim::IsEmpty(s(a)),
            Prim::Elems(a) => Prim::Elems(s(a)),
            Prim::NatEq(a, b) => Prim::NatEq(s(a), s(b)),
            Prim::NatLe(a, b) => Prim::NatLe(s(a), s(b)),
            Prim::NatAdd(a, b) => Prim::NatAdd(s(a), s(b)),
            Prim::MapGet(m, tr) => Prim::MapGet(s(m), str_(tr)),
            Prim::Def(a) => Prim::Def(s(a)),
        }),
        Term::And(a, b) => Term::And(s(a), s(b)),
        Term::Or(a, b) => Term::Or(s(a), s(b)),
        Term::Not(a) => Term::Not(s(a)),
        Term::Implies(a, b) => Term::Implies(s(a), s(b)),
        Term::Iff(a, b) => Term::Iff(s(a), s(b)),
        Term::Forall { var, dom, body } => {
            // An inner Reg binder rebinding cvar shadows the outer one.
            if matches!(dom.as_ref(), Dom::Reg) && var == cvar {
                Term::Forall { var: var.clone(), dom: dom.clone(), body: body.clone() }
            } else {
                Term::Forall { var: var.clone(), dom: sd(dom), body: s(body) }
            }
        }
        Term::Exists { var, dom, body } => {
            if matches!(dom.as_ref(), Dom::Reg) && var == cvar {
                Term::Exists { var: var.clone(), dom: dom.clone(), body: body.clone() }
            } else {
                Term::Exists { var: var.clone(), dom: sd(dom), body: s(body) }
            }
        }
        Term::Let { var, bound, body } => Term::Let { var: var.clone(), bound: s(bound), body: s(body) },
        Term::IfSome { opt, var, then_, else_ } => Term::IfSome {
            opt: s(opt),
            var: var.clone(),
            then_: s(then_),
            else_: s(else_),
        },
        Term::Count(d) => Term::Count(sd(d)),
        Term::MaxT1(d) => Term::MaxT1(sd(d)),
        Term::MinT1(d) => Term::MinT1(sd(d)),
        Term::BigUnion { dom, var, body } => {
            Term::BigUnion { dom: sd(dom), var: var.clone(), body: s(body) }
        }
        Term::Reflect(d) => Term::Reflect(sd(d)),
        Term::Ref { addr, args } => Term::Ref { addr: addr.clone(), args: args.iter().map(s).collect() },
    }
}

fn subst_classvar_dom(d: &Dom, cvar: &VarId, key: &TypeKey) -> Dom {
    let s = |x: &ArcTerm| -> ArcTerm { Arc::new(subst_classvar_term(x, cvar, key)) };
    let str_ = |tr: &TypeRef| subst_typeref(tr, cvar, key);
    match d {
        Dom::MembersDom(tr) => Dom::MembersDom(str_(tr)),
        Dom::ActiveSlice(tr) => Dom::ActiveSlice(str_(tr)),
        Dom::AuditSlice(tr) => Dom::AuditSlice(str_(tr)),
        Dom::LinkDom => Dom::LinkDom,
        Dom::Reg => Dom::Reg,
        Dom::Filter { dom, var, pred } => Dom::Filter {
            dom: Arc::new(subst_classvar_dom(dom, cvar, key)),
            var: var.clone(),
            pred: s(pred),
        },
        Dom::SetTerm(t) => Dom::SetTerm(s(t)),
    }
}

fn subst_typeref(tr: &TypeRef, cvar: &VarId, key: &TypeKey) -> TypeRef {
    match tr {
        TypeRef::ClassVar(v) if v == cvar => TypeRef::Concrete(key.clone()),
        other => other.clone(),
    }
}

/// Collect every `Ref` address in `t` (recursively, including inside domain
/// bodies) — the direct referents `register_pred`'s (iii)/(iv) checks range
/// over (§Internal 4).
pub(crate) fn collect_ref_addrs(t: &Term, out: &mut Vec<Address>) {
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
            | Atom::InCoverageG(e, _) => collect_ref_addrs(e, out),
            Atom::IsInChain(_, a1, a2) => {
                collect_ref_addrs(a1, out);
                collect_ref_addrs(a2, out);
            }
            Atom::Members(_) | Atom::TupAddr(_) | Atom::TupAddrsF(_) | Atom::TupAddrsG(_) => {}
        },
        Term::Prim(p) => match p {
            Prim::AddrEq(a, b)
            | Prim::Prefix(a, b)
            | Prim::T1Lt(a, b)
            | Prim::SetMem(a, b)
            | Prim::SetEq(a, b)
            | Prim::NatEq(a, b)
            | Prim::NatLe(a, b)
            | Prim::NatAdd(a, b) => {
                collect_ref_addrs(a, out);
                collect_ref_addrs(b, out);
            }
            Prim::IsEmpty(a) | Prim::Elems(a) | Prim::Def(a) | Prim::MapGet(a, _) => {
                collect_ref_addrs(a, out)
            }
        },
        Term::And(a, b) | Term::Or(a, b) | Term::Implies(a, b) | Term::Iff(a, b) => {
            collect_ref_addrs(a, out);
            collect_ref_addrs(b, out);
        }
        Term::Not(a) => collect_ref_addrs(a, out),
        Term::Forall { dom, body, .. } | Term::Exists { dom, body, .. } => {
            collect_ref_addrs_dom(dom, out);
            collect_ref_addrs(body, out);
        }
        Term::Let { bound, body, .. } => {
            collect_ref_addrs(bound, out);
            collect_ref_addrs(body, out);
        }
        Term::IfSome { opt, then_, else_, .. } => {
            collect_ref_addrs(opt, out);
            collect_ref_addrs(then_, out);
            collect_ref_addrs(else_, out);
        }
        Term::Count(d) | Term::MaxT1(d) | Term::MinT1(d) | Term::Reflect(d) => {
            collect_ref_addrs_dom(d, out)
        }
        Term::BigUnion { dom, body, .. } => {
            collect_ref_addrs_dom(dom, out);
            collect_ref_addrs(body, out);
        }
        Term::Ref { addr, args } => {
            out.push(addr.clone());
            for a in args {
                collect_ref_addrs(a, out);
            }
        }
    }
}

pub(crate) fn collect_ref_addrs_dom(d: &Dom, out: &mut Vec<Address>) {
    match d {
        Dom::MembersDom(_) | Dom::ActiveSlice(_) | Dom::AuditSlice(_) | Dom::LinkDom | Dom::Reg => {}
        Dom::Filter { dom, pred, .. } => {
            collect_ref_addrs_dom(dom, out);
            collect_ref_addrs(pred, out);
        }
        Dom::SetTerm(t) => collect_ref_addrs(t, out),
    }
}
