//! §Core data model — the PL AST: a finite, acyclic, tagged-union tree in two
//! mutually-recursive families ([`Term`]/[`Dom`]), reified (not
//! closure-encoded) so the three syntax-directed analyses — type-check,
//! footprint, stability — can read structure. Subterms are `Arc`-shared. The
//! tree's child structure is stated once, in `walk.rs`; a structural pass
//! implements `Rewrite` or `Visit` there rather than matching every former.

use std::sync::Arc;

use skep_address::{Address, Nat};
use skep_links::Endset;

use crate::walk::{visit_term, Visit};

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
/// The reservation is structural, not merely intended: the type has exactly
/// two constructors, one per side of the watershed — [`VarId::new`], the
/// sole public one, rejects the reserved range; [`VarId::expansion`], the
/// crate-private one, inhabits nothing else and is what the flat expansion's
/// fresh-name supply mints through (§Internal 4). The def codec decodes a
/// name through `new`, so a reserved-range name in stored content is a
/// parse failure and PR-ENC's body-binder disjointness holds by
/// construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarId(u32);

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

    /// The `n`-th reserved expansion name, `EXPANSION_NAME_BASE + n` — the
    /// one mint site for the flat reference expansion's fresh names
    /// (PR3/PR3a). Panics only on supply exhaustion (2³¹ names in one
    /// expansion).
    pub(crate) fn expansion(n: u32) -> VarId {
        VarId(
            EXPANSION_NAME_BASE
                .checked_add(n)
                .expect("expansion-name supply exhausted"),
        )
    }

    /// The name's numeral — what the def codec writes; it reads one back
    /// through [`VarId::new`].
    pub(crate) fn index(&self) -> u32 {
        self.0
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
    /// Core (view-parameterized). The source is matched by COVERAGE of F at
    /// `Active`/`Default` (M7's D3) and by DENOTATION — `x ∈ F.addrs()`
    /// (V-AUD) — at `Audit`: a probe strictly under a denoted address has
    /// targets at `Active` and none at `Audit`.
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

/// Collect every `Ref` address in `t` (recursively, including inside domain
/// bodies), in pre-order — the direct referents `register_pred`'s (iii)/(iv)
/// checks range over (§Internal 4).
pub(crate) fn collect_ref_addrs(t: &Term, out: &mut Vec<Address>) {
    struct RefAddrs<'a>(&'a mut Vec<Address>);
    impl Visit for RefAddrs<'_> {
        fn term(&mut self, t: &Term) {
            if let Term::Ref { addr, .. } = t {
                self.0.push(addr.clone());
            }
            visit_term(self, t);
        }
    }
    RefAddrs(out).term(t);
}

/// A body spelling every former, atom, prim, domain, literal and type
/// position, with every encodable sort in Γ_D — the input the codec's round
/// trip and the walks' agreement are checked on. It need not type-check: the
/// codec and the walks are structural.
#[cfg(test)]
pub(crate) mod fixture {
    use std::sync::Arc;

    use skep_address::{validate, Address, Nat, Tumbler};
    use skep_links::enc;

    use super::*;
    use crate::value::Sort;

    fn v(x: u32) -> VarId {
        VarId::new(x).expect("test var below the watershed")
    }

    fn ad(comps: &[u32]) -> Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty"))
            .expect("T4-valid")
    }

    fn a(t: Term) -> ArcTerm {
        Arc::new(t)
    }

    fn d(x: Dom) -> ArcDom {
        Arc::new(x)
    }

    pub(crate) fn every_former() -> (Vec<(VarId, Sort)>, Term) {
        let k = TypeRef::Concrete(TypeKey(enc(&[ad(&[1, 1, 0, 1, 0, 1, 0, 1, 1])])));
        let c = TypeRef::ClassVar(v(9));
        let x = || Term::Var(v(1));
        let y = || Term::Var(v(2));
        let lits = [
            Lit::True,
            Lit::False,
            Lit::Nat(Nat::from(7u32)),
            Lit::Addr(ad(&[1, 0, 1, 0, 1, 0, 1, 3])),
            Lit::BotAddr,
            Lit::BotNat,
        ]
        .into_iter()
        .map(Term::Lit);
        let atoms = [
            Atom::IsK(k.clone(), a(x())),
            Atom::Members(c.clone()),
            Atom::TargetsOf(k.clone(), a(x())),
            Atom::IsFiltered(k.clone(), a(x())),
            Atom::Succs(k.clone(), a(x())),
            Atom::Chain(k.clone(), a(x())),
            Atom::Tip(k.clone(), a(x())),
            Atom::IsInChain(k.clone(), a(x()), a(y())),
            Atom::SourcesTo(k.clone(), a(x())),
            Atom::TargetOf(k.clone(), a(x())),
            Atom::TargetsKeyed(a(x())),
            Atom::Age(k.clone(), a(x())),
            Atom::Stale(k.clone(), a(x())),
            Atom::IsDoc(a(x())),
            Atom::TupAddr(v(3)),
            Atom::TupAddrsF(v(3)),
            Atom::TupAddrsG(v(3)),
            Atom::InCoverageF(a(x()), v(3)),
            Atom::InCoverageG(a(x()), v(3)),
        ]
        .into_iter()
        .map(Term::Atom);
        let prims = [
            Prim::AddrEq(a(x()), a(y())),
            Prim::Prefix(a(x()), a(y())),
            Prim::T1Lt(a(x()), a(y())),
            Prim::SetMem(a(x()), a(y())),
            Prim::SetEq(a(x()), a(y())),
            Prim::IsEmpty(a(x())),
            Prim::Elems(a(x())),
            Prim::NatEq(a(x()), a(y())),
            Prim::NatLe(a(x()), a(y())),
            Prim::NatAdd(a(x()), a(y())),
            Prim::MapGet(a(x()), c.clone()),
            Prim::Def(a(x())),
        ]
        .into_iter()
        .map(Term::Prim);
        let formers = [
            Term::Or(a(x()), a(y())),
            Term::Not(a(x())),
            Term::Implies(a(x()), a(y())),
            Term::Iff(a(x()), a(y())),
            Term::Forall { var: v(5), dom: d(Dom::MembersDom(k.clone())), body: a(x()) },
            Term::Exists { var: v(5), dom: d(Dom::ActiveSlice(k.clone())), body: a(x()) },
            Term::Let { var: v(6), bound: a(x()), body: a(y()) },
            Term::IfSome { opt: a(x()), var: v(7), then_: a(y()), else_: a(x()) },
            Term::Count(d(Dom::AuditSlice(c))),
            Term::MaxT1(d(Dom::LinkDom)),
            Term::MinT1(d(Dom::Reg)),
            Term::BigUnion {
                dom: d(Dom::Filter { dom: d(Dom::LinkDom), var: v(4), pred: a(x()) }),
                var: v(8),
                body: a(y()),
            },
            Term::Reflect(d(Dom::SetTerm(a(x())))),
            Term::Ref { addr: ad(&[1, 0, 1, 0, 1, 0, 1, 4]), args: vec![a(x()), a(y())] },
        ];
        // `And` is the spine, so it is spelled by the fold itself.
        let body = lits
            .chain(atoms)
            .chain(prims)
            .chain(formers)
            .reduce(|l, r| Term::And(a(l), a(r)))
            .expect("nonempty");
        let params = vec![
            (v(1), Sort::Bool),
            (v(2), Sort::Addr),
            (v(3), Sort::AddrSet),
            (v(4), Sort::OptAddr),
            (v(5), Sort::AddrSeq),
            (v(6), Sort::Map),
            (v(7), Sort::Nat),
            (v(8), Sort::OptNat),
        ];
        (params, body)
    }
}
