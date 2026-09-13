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

/// The ONE bound on the nesting of a PL tree, counted THROUGH references:
/// every walk over a term — the def decoder, the checker, the evaluator, the
/// expander, the analyzer — recurses once per former on the caller's thread,
/// and none is bounded otherwise. The decoder refuses a stored body nested
/// past it (`Malformed`); the checker refuses any term, stored or supplied,
/// whose evaluable projection — `Reg`-expansion joins and reference reaches
/// included — would carry a walk past it (`TypeError::TooDeep`), and records
/// each checked term's reach as `TypedTerm::reach`, so a reference chain is
/// bounded at registration rather than discovered at a cold derivation. The value sits where all of the walks fit a default 2 MiB
/// thread with margin in a debug build (the checker, the heaviest, overflows
/// one near 200 levels there; a release build carries several times that),
/// and far above any hand-authored body. The suite runs each walk at exactly
/// this depth on a default thread
/// (`a_hand_forged_body_at_the_decode_cap_survives_every_walk`,
/// `a_reference_chain_at_the_cap_derives_cold_and_one_deeper_is_refused`),
/// so a cap raised past the budget, or a walk grown past it, aborts there
/// rather than in a daemon.
pub(crate) const MAX_DEPTH: u32 = 128;

/// The levels a reference costs beyond its own node, in [`MAX_DEPTH`]'s
/// units: the frames between a `Ref` node's check and its referent's — the
/// resolver, the memo probe, the derivation — and the evaluator's and
/// expander's re-entry at the referent. Each argument is charged one more on
/// top of this (the flat expansion's `Let` per argument). Set against the
/// same measurement as [`MAX_DEPTH`]: the chain test derives a chain
/// registered to the cap cold, on a default thread, so a cost set too low
/// aborts there.
pub(crate) const DERIVATION_COST: u32 = 2;

/// The ONE budget on the SIZE of a PL tree, in nodes: what the def decoder
/// builds from one run, what the checker traverses and builds (`Reg`
/// expansion instantiates a body once per cataloged class, so nested `Reg`
/// quantifiers multiply — six over a leaf fit, seven do not — and a
/// `Arc`-shared input is charged per traversal, as a tree), and what the
/// expander traverses and builds for one flat reference expansion. A node is
/// ~100 bytes behind its `Arc`, so the budget is ~6 MiB — held per memo
/// entry and per captured rule trigger for the life of the process, and
/// transiently per expansion — against hand-authored predicates of tens to
/// hundreds of nodes. Past it: `Malformed` at the decoder,
/// `TypeError::TooLarge` at the checker, `ExpansionTooLarge` at the expander.
pub(crate) const MAX_TERM_NODES: usize = 1 << 16;

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

/// Every `Ref` address in `t` (recursively, including inside domain bodies),
/// in pre-order — the direct referents `register_pred`'s (iii)/(iv) checks
/// range over (§Internal 4).
pub(crate) fn ref_addrs(t: &Term) -> Vec<Address> {
    struct RefAddrs(Vec<Address>);
    impl Visit for RefAddrs {
        fn term(&mut self, t: &Term) {
            if let Term::Ref { addr, .. } = t {
                self.0.push(addr.clone());
            }
            visit_term(self, t);
        }
    }
    let mut refs = RefAddrs(Vec::new());
    refs.term(t);
    refs.0
}

/// A signed term spelling every former, atom, prim, domain, literal and type
/// position, with every encodable sort in Γ_D — the input the codec's round
/// trip and the walks' agreement are checked on. It need not type-check: the
/// codec and the walks are structural.
#[cfg(test)]
pub(crate) mod fixture {
    use std::sync::Arc;

    use skep_address::{validate, Address, Nat, Tumbler};
    use skep_links::enc;

    use super::*;
    use crate::value::{SignedTerm, Sort};

    fn v(x: u32) -> VarId {
        VarId::new(x).expect("test var below the watershed")
    }

    fn a(comps: &[u32]) -> Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty"))
            .expect("T4-valid")
    }

    fn at(t: Term) -> ArcTerm {
        Arc::new(t)
    }

    fn ad(x: Dom) -> ArcDom {
        Arc::new(x)
    }

    pub(crate) fn every_former() -> SignedTerm {
        let k = TypeRef::Concrete(TypeKey(enc(&[a(&[1, 1, 0, 1, 0, 1, 0, 1, 1])])));
        let c = TypeRef::ClassVar(v(9));
        let x = || Term::Var(v(1));
        let y = || Term::Var(v(2));
        let lits = [
            Lit::True,
            Lit::False,
            Lit::Nat(Nat::from(7u32)),
            // A natural past one byte: the codec's length-prefixed
            // big-endian limbs, not a single-byte special case.
            Lit::Nat(Nat::from(1u64 << 40)),
            Lit::Addr(a(&[1, 0, 1, 0, 1, 0, 1, 3])),
            Lit::BotAddr,
            Lit::BotNat,
        ]
        .into_iter()
        .map(Term::Lit);
        let atoms = [
            Atom::IsK(k.clone(), at(x())),
            Atom::Members(c.clone()),
            Atom::TargetsOf(k.clone(), at(x())),
            Atom::IsFiltered(k.clone(), at(x())),
            Atom::Succs(k.clone(), at(x())),
            Atom::Chain(k.clone(), at(x())),
            Atom::Tip(k.clone(), at(x())),
            Atom::IsInChain(k.clone(), at(x()), at(y())),
            Atom::SourcesTo(k.clone(), at(x())),
            Atom::TargetOf(k.clone(), at(x())),
            Atom::TargetsKeyed(at(x())),
            Atom::Age(k.clone(), at(x())),
            Atom::Stale(k.clone(), at(x())),
            Atom::IsDoc(at(x())),
            Atom::TupAddr(v(3)),
            Atom::TupAddrsF(v(3)),
            Atom::TupAddrsG(v(3)),
            Atom::InCoverageF(at(x()), v(3)),
            Atom::InCoverageG(at(x()), v(3)),
        ]
        .into_iter()
        .map(Term::Atom);
        let prims = [
            Prim::AddrEq(at(x()), at(y())),
            Prim::Prefix(at(x()), at(y())),
            Prim::T1Lt(at(x()), at(y())),
            Prim::SetMem(at(x()), at(y())),
            Prim::SetEq(at(x()), at(y())),
            Prim::IsEmpty(at(x())),
            Prim::Elems(at(x())),
            Prim::NatEq(at(x()), at(y())),
            Prim::NatLe(at(x()), at(y())),
            Prim::NatAdd(at(x()), at(y())),
            Prim::MapGet(at(x()), c.clone()),
            Prim::Def(at(x())),
        ]
        .into_iter()
        .map(Term::Prim);
        let formers = [
            Term::Or(at(x()), at(y())),
            Term::Not(at(x())),
            Term::Implies(at(x()), at(y())),
            Term::Iff(at(x()), at(y())),
            Term::Forall { var: v(5), dom: ad(Dom::MembersDom(k.clone())), body: at(x()) },
            Term::Exists { var: v(5), dom: ad(Dom::ActiveSlice(k.clone())), body: at(x()) },
            Term::Let { var: v(6), bound: at(x()), body: at(y()) },
            Term::IfSome { opt: at(x()), var: v(7), then_: at(y()), else_: at(x()) },
            Term::Count(ad(Dom::AuditSlice(c))),
            Term::MaxT1(ad(Dom::LinkDom)),
            Term::MinT1(ad(Dom::Reg)),
            Term::BigUnion {
                dom: ad(Dom::Filter { dom: ad(Dom::LinkDom), var: v(4), pred: at(x()) }),
                var: v(8),
                body: at(y()),
            },
            Term::Reflect(ad(Dom::SetTerm(at(x())))),
            Term::Ref { addr: a(&[1, 0, 1, 0, 1, 0, 1, 4]), args: vec![at(x()), at(y())] },
        ];
        // `And` is the spine, so it is spelled by the fold itself.
        let body = lits
            .chain(atoms)
            .chain(prims)
            .chain(formers)
            .reduce(|l, r| Term::And(at(l), at(r)))
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
        SignedTerm { params, body }
    }
}
