//! The PL AST (§Core data model): a finite, acyclic, tagged-union tree.
//!
//! The tree has two mutually-recursive families ([`Term`]/[`Dom`]), reified
//! (not closure-encoded) so the three syntax-directed analyses — type-check,
//! footprint, stability — can read structure. Subterms are `Arc`-shared. The
//! tree's child structure is stated once, in `walk.rs`; a structural pass
//! implements its `Rewrite` or `Visit` rather than matching every former.

use std::fmt;
use std::sync::Arc;

use skep_address::{Address, Nat};
use skep_links::Endset;

/// `Arc`-shared term node.
pub type ArcTerm = Arc<Term>;
/// `Arc`-shared domain node.
pub type ArcDom = Arc<Dom>;

/// The reserved-expansion-name watershed.
///
/// A `VarId(v)` with `v ≥ EXPANSION_NAME_BASE` is reserved for
/// reference-expansion fresh names (PR-ENC's reserved supply, §Internal 4) —
/// no recorded parameter name and no body binder may inhabit it.
pub const EXPANSION_NAME_BASE: u32 = 1 << 31;

/// A PL variable name.
///
/// The reservation is structural, not merely intended: the type has exactly
/// two constructors, one per side of the watershed — [`VarId::new`], the
/// sole public one, rejects the reserved range; `VarId::expansion`, the
/// crate-private one, inhabits nothing else and is what the flat expansion's
/// fresh-name supply mints through (§Internal 4). The def codec decodes a
/// name through `new`, so a reserved-range name in stored content is a
/// parse failure and PR-ENC's body-binder disjointness holds by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarId(u32);

impl VarId {
    /// Returns the name `v`, or `None` in the reserved range.
    ///
    /// The sole public constructor — the reservation's enforcement point:
    /// `None ⇔ v ≥ EXPANSION_NAME_BASE`. A `const fn`, so a driver can name
    /// its PL variables as constants and have the watershed checked at
    /// compile time.
    pub const fn new(v: u32) -> Option<VarId> {
        if v >= EXPANSION_NAME_BASE {
            None
        } else {
            Some(VarId(v))
        }
    }

    /// Returns the `n`-th reserved expansion name, `EXPANSION_NAME_BASE + n`.
    ///
    /// The one mint site for the flat reference expansion's fresh names
    /// (PR3/PR3a).
    ///
    /// # Panics
    ///
    /// Panics only on supply exhaustion (2³¹ names in one expansion).
    pub(crate) fn expansion(n: u32) -> VarId {
        VarId(
            EXPANSION_NAME_BASE
                .checked_add(n)
                .expect("expansion-name supply exhausted"),
        )
    }

    /// Returns the name's numeral, which the def codec writes.
    ///
    /// The codec reads one back through [`VarId::new`].
    pub(crate) fn index(&self) -> u32 {
        self.0
    }
}

/// A type *key*: an endset spelling a link type.
///
/// The key, not the type, so its equality is the spelling's. One type (one
/// coverage class) has many spellings, and the catalog admits only its own.
///
/// Caller contract (§Core data model): the catalog probe is `Endset`-equality
/// while M7's type identity is by coverage (I0), so every `Concrete` `TypeKey`
/// must be built from a canonical catalog endset —
/// `Coordinator::reserved_type(ShippedType)`, the shipped five being the
/// catalog's whole population. A coverage-equal-but-byte-different key
/// misses as `UncatalogedTypeKey`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeKey(pub Endset);

/// A type key shown as the addresses it denotes, or as its span count.
///
/// It reads `{a}` for the one-address keys the catalog holds, and falls back
/// to the span count for an endset that is not address-denoting — one with a
/// span that denotes no address, which is exactly what a key built by hand
/// and refused as `UncatalogedTypeKey` may be. So a rejection naming a key
/// reads.
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

/// A type position: a concrete type key or a class variable (V-IDX).
///
/// A class variable is bound by an enclosing `Reg` quantifier. The checker
/// admits a `Concrete` key only as the catalog spells it
/// (`UncatalogedTypeKey` otherwise), and `Reg`-expansion substitutes
/// `ClassVar(cvar) → Concrete(key)` — the catalog's key for each registered
/// class — at type-check, so a `TypedTerm`'s evaluable projection holds only
/// `Concrete` refs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeRef {
    /// A concrete type key.
    Concrete(TypeKey),
    /// A class variable, bound by an enclosing `Reg` quantifier.
    ClassVar(VarId),
}

impl TypeRef {
    /// Returns the concrete key.
    ///
    /// This is the post-`Reg`-expansion invariant, stated once for every walk
    /// over a checked tree (the evaluator, the analyses): the checker
    /// substitutes `ClassVar → Concrete` at each enclosing `Reg` binder and
    /// refuses any survivor as `UnboundClassVar`, so a checked term's type
    /// positions are all `Concrete`.
    ///
    /// # Panics
    ///
    /// Panics on a `ClassVar`, which no checked tree holds.
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Term {
    /// A variable, bound by Γ_D or by an enclosing binder.
    Var(VarId),
    /// A literal: ⊤, ⊥, an ℕ or address literal, or ⊥ at T∪{⊥} or at ℕ∪{⊥}.
    Lit(Lit),
    /// An atom: one that reads state, or one that reads a bound tuple.
    ///
    /// The atoms that read state are the core atoms, BH1–BH4 and V-DOC;
    /// V-TUP's tuple projections and coverage tests read only their bound
    /// tuple.
    Atom(Atom),
    /// V-PRIM ops: = ≼ T1 ∈ set= =∅ elems ℕ(= ≤ +) ·\[K\] def.
    Prim(Prim),
    /// Conjunction.
    And(ArcTerm, ArcTerm),
    /// Disjunction.
    Or(ArcTerm, ArcTerm),
    /// Negation.
    Not(ArcTerm),
    /// Implication (PC0).
    Implies(ArcTerm, ArcTerm),
    /// The biconditional (PC0).
    Iff(ArcTerm, ArcTerm),
    /// Universal quantification over a domain (PC1).
    ///
    /// `Reg`-quantifiers are expanded away by `type_check`.
    Forall { var: VarId, dom: ArcDom, body: ArcTerm },
    /// Existential quantification over a domain (PC1).
    Exists { var: VarId, dom: ArcDom, body: ArcTerm },
    /// Plain composition (PC2).
    Let { var: VarId, bound: ArcTerm, body: ArcTerm },
    /// PC2 binder guard — narrows `T∪{⊥} → T` (resp. `ℕ∪{⊥} → ℕ`) in `then_`.
    IfSome { opt: ArcTerm, var: VarId, then_: ArcTerm, else_: ArcTerm },
    /// The count of a domain's elements (PC2a).
    Count(ArcDom),
    /// The global T1 order-maximum over an address-valued domain (PC2a).
    MaxT1(ArcDom),
    /// The global order-minimum over an address-valued domain (PC2a).
    MinT1(ArcDom),
    /// The union ⋃(D, f) of a set-valued body over a domain (PC2a).
    BigUnion { dom: ArcDom, var: VarId, body: ArcTerm },
    /// QD-refl: address-valued domain → ℘_fin(T) term.
    Reflect(ArcDom),
    /// A reference to the def whose content starts at `addr` (ASN-0130).
    ///
    /// The checker admits one in any term, which is then ref-bearing
    /// (`is_ref_free() == false`) and usable only as a stored def's body.
    Ref { addr: Address, args: Vec<ArcTerm> },
}

/// PL's atoms (ASN-0128/0129), V-PRIM's primitives aside ([`Prim`]).
///
/// They are those that read state — the three view-parameterized core
/// atoms, BH1–BH4 and V-DOC — and V-TUP's tuple projections and coverage
/// tests, which read only the tuple bound to their variable and so are
/// constant across states (ASN-0129 V-TUP).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Atom {
    /// `is_K(x)`, a core atom (view-parameterized).
    IsK(TypeRef, ArcTerm),
    /// Core — `M_K`'s dedicated view-parameterized term twin.
    Members(TypeRef),
    /// `targets_of(K, x)`, a core atom (view-parameterized).
    ///
    /// The source is matched by *coverage* of F at `Active`/`Default`
    /// (M7's D3) and by *denotation* — `x ∈ F.addrs()` (V-AUD) — at
    /// `Audit`: a probe strictly under a denoted address has targets at
    /// `Active` and none at `Audit`.
    TargetsOf(TypeRef, ArcTerm),
    /// BH1 — the per-type filter `is_filtered_J(x)`.
    IsFiltered(TypeRef, ArcTerm),
    /// BH2 — the successors of an address.
    ///
    /// Fixed active; v1 served only at the shipped `Supersedes` key.
    Succs(TypeRef, ArcTerm),
    /// BH2 — the chain walked forward from an address.
    Chain(TypeRef, ArcTerm),
    /// BH2 — the head of the chain from an address.
    Tip(TypeRef, ArcTerm),
    /// BH2 — whether the second address is on the chain from the first.
    IsInChain(TypeRef, ArcTerm, ArcTerm),
    /// BH3 — the sources of the links that target an address (fixed active).
    SourcesTo(TypeRef, ArcTerm),
    /// BH3 — the one target of a source address, or ⊥.
    TargetOf(TypeRef, ArcTerm),
    /// BH3 — class-unindexed join.
    TargetsKeyed(ArcTerm),
    /// BH4 — a link's age (fixed active + home-frontier).
    Age(TypeRef, ArcTerm),
    /// BH4 — the stale links at a horizon.
    Stale(TypeRef, ArcTerm),
    /// V-DOC — whether an address is a registered document.
    IsDoc(ArcTerm),
    /// V-TUP — a bound tuple's own address (state-independent).
    TupAddr(VarId),
    /// V-TUP — the addresses a bound tuple's F denotes.
    TupAddrsF(VarId),
    /// V-TUP — the addresses a bound tuple's G denotes.
    TupAddrsG(VarId),
    /// V-TUP — whether a bound tuple's F covers an address.
    InCoverageF(ArcTerm, VarId),
    /// V-TUP — whether a bound tuple's G covers an address.
    InCoverageG(ArcTerm, VarId),
}

/// Quantification/fold domains (ASN-0129 QD).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Dom {
    /// `M_K` : dom(T), view-parameterized.
    MembersDom(TypeRef),
    /// `A_K` : dom(Tup), fixed active.
    ActiveSlice(TypeRef),
    /// `L_K` : dom(Tup), fixed audit.
    AuditSlice(TypeRef),
    /// `L_dom` : dom(T) — the typed-relation sublayer only.
    ///
    /// An open MAKELINK link is outside PL's universe unless its type slot is
    /// of a cataloged class.
    LinkDom,
    /// The registered classes: class-valued, quantification-only (V-IDX).
    ///
    /// Admissible under exactly `Forall`/`Exists`/`Count`
    /// (`TypeError::MisplacedReg` elsewhere); expanded/folded at
    /// `type_check`.
    Reg,
    /// The elements of `dom` that satisfy `pred`, each bound at `var`.
    Filter { dom: ArcDom, var: VarId, pred: ArcTerm },
    /// QD set-valued-term closure: a ℘_fin(T)-valued term used as a domain.
    SetTerm(ArcTerm),
}

/// PL's literals.
///
/// `BotAddr : T∪{⊥}`, `BotNat : ℕ∪{⊥}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Lit {
    /// The Boolean ⊤.
    True,
    /// The Boolean ⊥.
    False,
    /// An ℕ literal.
    Nat(Nat),
    /// An address literal.
    Addr(Address),
    /// ⊥ at T∪{⊥}: no address.
    BotAddr,
    /// ⊥ at ℕ∪{⊥}: no number.
    BotNat,
}

/// V-PRIM operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    /// The emptiness test `= ∅`.
    IsEmpty(ArcTerm),
    /// A sequence's elements as a set: Seq_fin(T) → ℘_fin(T).
    Elems(ArcTerm),
    /// ℕ `=`.
    NatEq(ArcTerm, ArcTerm),
    /// ℕ `≤`.
    NatLe(ArcTerm, ArcTerm),
    /// ℕ `+`.
    NatAdd(ArcTerm, ArcTerm),
    /// `·[K]` on Map_fin — per registered class, no behavior requirement.
    MapGet(ArcTerm, TypeRef),
    /// Definedness `· ≠ ⊥`.
    Def(ArcTerm),
}
