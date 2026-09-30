//! §Core data model — the PL AST: a finite, acyclic, tagged-union tree in two
//! mutually-recursive families ([`Term`]/[`Dom`]), reified (not
//! closure-encoded) so the three syntax-directed analyses — type-check,
//! footprint, stability — can read structure. Subterms are `Arc`-shared. The
//! tree's child structure is stated once, in `walk.rs`; a structural pass
//! implements `Rewrite` or `Visit` there rather than matching every former.

use std::fmt;
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
/// The reservation is structural, not merely intended: the type has exactly
/// two constructors, one per side of the watershed — [`VarId::new`], the
/// sole public one, rejects the reserved range; [`VarId::expansion`], the
/// crate-private one, inhabits nothing else and is what the flat expansion's
/// fresh-name supply mints through (§Internal 4). The def codec decodes a
/// name through `new`, so a reserved-range name in stored content is a
/// parse failure and PR-ENC's body-binder disjointness holds by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// A type key as the addresses it denotes — `{a}` for the one-address keys
/// the catalog holds — falling back to the span count for an endset that
/// denotes no address, which is exactly what a key built by hand and refused
/// as `UnregisteredType` may be. So a rejection naming a key reads.
impl fmt::Display for TypeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.0.is_address_denoting() {
            return write!(f, "<{} non-denoting span(s)>", self.0.len());
        }
        f.write_str("{")?;
        for (i, a) in self.0.addrs().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{a}")?;
        }
        f.write_str("}")
    }
}

/// A type position: a concrete cataloged type OR a class variable bound by an
/// enclosing `Reg` quantifier (V-IDX). `Reg`-expansion substitutes
/// `ClassVar(cvar) → Concrete(class)` per registered class at type-check, so
/// a `TypedTerm`'s evaluable projection holds only `Concrete` refs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeRef {
    Concrete(TypeKey),
    ClassVar(VarId),
}

impl TypeRef {
    /// The concrete key — the post-`Reg`-expansion invariant, stated once for
    /// every walk over a checked tree (the evaluator, the analyses): the
    /// checker substitutes `ClassVar → Concrete` at each enclosing `Reg`
    /// binder and refuses any survivor as `UnboundClassVar`, so a checked
    /// term's type positions are all `Concrete`.
    pub(crate) fn key(&self) -> &TypeKey {
        match self {
            TypeRef::Concrete(k) => k,
            TypeRef::ClassVar(v) => unreachable!(
                "post-Reg-expansion trees hold only Concrete TypeRefs, found ClassVar({v:?})"
            ),
        }
    }
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
    /// QD set-valued-term closure: a ℘_fin(T)-valued term used as a domain.
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
