//! §Core data model — values, sorts, signatures, the eval environment.

use im::{HashMap, OrdSet, Vector};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_links::{CoverageClass, Tuple};

use crate::ast::{Term, VarId};

/// COD ∪ {Tup} (ASN-0129 WT). `Tup` is bound only by a rule trigger's one
/// parameter (`type_check_trigger`) and by a binder over `A_K`/`L_K` — `∀`,
/// `∃`, a `Filter`, a `⋃` — or a `Let` rebinding such a value; a stored def's
/// `Γ_D` is Codom-only (ASN-0130 SignedTerm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sort {
    Bool,
    Addr,
    AddrSet,
    OptAddr,
    AddrSeq,
    Map,
    Nat,
    OptNat,
    Tup,
}

/// Denoted values. `AddrSet` is ℘_fin(T) as `im::OrdSet<Address>`: M1 orders
/// and compares an `Address` by its tumbler (T1), so union (the ⋃-fold),
/// dedup (`count`'s set semantics) and the T1 extrema cost no more than over
/// the tumblers M7's endsets yield, and every element is an address BY TYPE —
/// a set is gathered from addresses M7 or M3 hand over, or from the tumblers a
/// stored slot denotes, each lifted once as it is gathered (the crate's
/// `lift`). `AddrSeq` has the same element type, so `elems` converts nothing,
/// and a quantifier, a fold or a rule binds a set's element as it stands.
/// `Tuple` binds a `Tup` var.
///
/// The payload types are M1's `Address`/`Nat`, M7's `CoverageClass`/`Tuple`
/// and `im`'s persistent collections — each re-exported from this crate's
/// root, so a caller builds a `Value` without naming a second manifest.
///
/// Deliberately NOT `Hash`, unlike the PL tree: `Map` holds an
/// `im::HashMap`, whose `Hash` folds its entries in iteration order — an
/// order each map's own hasher fixes — while its `PartialEq` compares
/// contents, so two equal values could hash apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Addr(Address),
    AddrSet(OrdSet<Address>),
    OptAddr(Option<Address>),
    AddrSeq(Vector<Address>),
    Map(HashMap<CoverageClass, Address>),
    Nat(Nat),
    OptNat(Option<Nat>),
    Tuple(Tuple),
}

impl Value {
    /// The sort this value inhabits — what both evaluators' positional
    /// binding compares against Γ_D, so a caller can ask the same question of
    /// its own values before it calls.
    pub fn sort(&self) -> Sort {
        match self {
            Value::Bool(_) => Sort::Bool,
            Value::Addr(_) => Sort::Addr,
            Value::AddrSet(_) => Sort::AddrSet,
            Value::OptAddr(_) => Sort::OptAddr,
            Value::AddrSeq(_) => Sort::AddrSeq,
            Value::Map(_) => Sort::Map,
            Value::Nat(_) => Sort::Nat,
            Value::OptNat(_) => Sort::OptNat,
            Value::Tuple(_) => Sort::Tup,
        }
    }
}

/// The lift of a tumbler a stored slot DENOTES — the start of a unit-depth
/// span in an M7 endset, as `Endset::addrs()` and `Endset::single_denoted()`
/// yield it — to the `Address` a PL value holds: M1 `validate`, infallible on
/// what reaches it (§Internal 2). Its callers are the reads that gather a
/// slot's denotation — `GuestLinks`' set reads, its claim index and its
/// `target_of`, the V-TUP slot atoms, and the scope bodies — so a set is made
/// of addresses from the moment it is gathered. Every other address a value
/// holds is one by type: handed over by M7 or M3 as an `Address`, decoded as
/// a literal through the codec's own `validate`, or supplied by a caller.
///
/// That rests on one upstream property that is M7's to keep: EVERY UNIT-DEPTH
/// SPAN IN A STORED SLOT HAS A T4-VALID START. `Endset::addrs()` filters on a
/// span's SHAPE (`s == subtree_of(s.start())`) and says nothing about its
/// start, so the property is established by M7's write doors — which admit a
/// start only as an `Address` (`SlotArg::Addrs`, `emit`'s and `assert_sup`'s
/// endpoints) or as a `Run::i_start`, an `Address` by type — and is NOT
/// re-established on the journal/checkpoint deserialize path, where `Endset`
/// derives a plain `Deserialize` while `Address`, `Span`, `Tumbler` and `Link`
/// each validate through a shadow. So a tampered store reaches this `expect`
/// at the first read that gathers the slot; a hostile peer does not.
pub(crate) fn lift(t: &Tumbler) -> Address {
    validate(t.clone()).expect("a stored slot denotes T4-valid addresses only (M7's write doors)")
}

/// A PL DOMAIN ELEMENT — what `[D]_snap` yields (QD, §Internal 2): an address,
/// from an address-valued domain (`M_K`, `L_dom`, a reflected set term), or a
/// whole tuple, from a tuple-valued slice (`A_K`, `L_K`). The two element
/// sorts the WT domain judgment admits — `dom(Addr)` and `dom(Tup)` — are this
/// type's two shapes, so a quantifier, a fold and a rule each bind exactly
/// what a domain can yield. A rule's bound argument is one of these
/// (`Occurrence.arg`), projected to an address for bookkeeping
/// ([`Arg::key_addr`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Addr(Address),
    Tuple(Tuple),
}

impl Arg {
    /// The bookkeeping key for a bound argument of EITHER shape: the address
    /// itself, or the tuple's `t.addr` (R1 AddressInjectivity, so an address
    /// hit is a value hit) — what a `StepOutcome` reports and what
    /// `fire_count` keys on, so a driver holding a peeked `Occurrence`
    /// reaches the same key the rule engine would rather than re-deriving it.
    pub fn key_addr(&self) -> &Address {
        match self {
            Arg::Addr(a) => a,
            Arg::Tuple(t) => &t.addr,
        }
    }

    /// Are these the same domain element? Addresses by address; tuples by
    /// `t.addr` (R1 AddressInjectivity — an address hit is a value hit);
    /// NEVER across shapes, a domain yielding one shape only, so a probe of
    /// the other is out of that domain by construction — which is why `fire`
    /// answers `NoOp` for it rather than refusing.
    pub(crate) fn same_element(&self, other: &Arg) -> bool {
        match (self, other) {
            (Arg::Addr(a), Arg::Addr(b)) => a == b,
            (Arg::Tuple(t), Arg::Tuple(u)) => t.addr == u.addr,
            _ => false,
        }
    }
}

/// The value a trigger's one parameter, or a quantifier's binder, binds to.
impl From<Arg> for Value {
    fn from(a: Arg) -> Value {
        match a {
            Arg::Addr(a) => Value::Addr(a),
            Arg::Tuple(t) => Value::Tuple(t),
        }
    }
}

/// The signed term `(Γ_D, body)` (ASN-0130 SignedTerm): a PL body with its
/// recorded parameter context — what the def codec stores a def as
/// (`codec::stored_run`) and parses back, and `parse_def` recovers from a
/// run. Unchecked: WT over it is `Checker::check_signed`'s, whose result
/// carries it as `TypedTerm::signed`; that check is where Γ_D's names are
/// required distinct (`DuplicateParameter`), so a checked term's context
/// binds each name once.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SignedTerm {
    pub(crate) params: Vec<(VarId, Sort)>,
    pub(crate) body: Term,
}

/// `(Γ_D, C_D)` — a stored def's checked signature (PR-SIG). Each param sort
/// ∈ COD: a stored def's parameters are bound by `evaluate_def` to values,
/// never a tuple (the `Tup` latitude lives only in the rule-trigger path,
/// whose result a `Signature` never describes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    pub params: Vec<(VarId, Sort)>,
    pub result: Sort,
}

/// The evaluator's environment: a term's Γ_D arguments and every name a
/// quantifier, `Let` or binder guard binds, `VarId → Value`, updated
/// functionally — `bind` returns a new `Env`, a later binding of a name
/// shadowing an earlier one, so a binder's scope ends where its subterm does.
/// Crate-private: a caller hands a term its arguments positionally
/// (`Coordinator::eval`, `Coordinator::evaluate_def`), so how the evaluator
/// holds its bindings is its own to change.
#[derive(Debug, Clone)]
pub(crate) struct Env(HashMap<VarId, Value>);

impl Env {
    pub(crate) fn empty() -> Env {
        Env(HashMap::new())
    }

    #[must_use = "bind returns the extended environment; Env is persistent and the receiver is untouched"]
    pub(crate) fn bind(&self, v: VarId, val: Value) -> Env {
        Env(self.0.update(v, val))
    }

    pub(crate) fn get(&self, v: &VarId) -> Option<&Value> {
        self.0.get(v)
    }
}

/// A Γ_D zipped with its arguments: `bind_args`'s binding, and the
/// evaluator's of a referent's parameters to a `Ref`'s arguments.
impl FromIterator<(VarId, Value)> for Env {
    fn from_iter<I: IntoIterator<Item = (VarId, Value)>>(iter: I) -> Env {
        Env(iter.into_iter().collect())
    }
}
