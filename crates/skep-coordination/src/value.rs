//! §Core data model — values, sorts, signatures, the eval environment.

use im::{HashMap, OrdSet, Vector};
use skep_address::{is_t4_valid, validate, Address, Nat, Tumbler};
use skep_links::{CoverageClass, Tuple};

use crate::ast::{Term, VarId};

/// COD ∪ {Tup} (ASN-0129 WT). `Tup` is bindable only by a rule trigger's one
/// parameter (`type_check_trigger`) and by quantifier binders over `A_K`/`L_K`
/// — a stored def's `Γ_D` is Codom-only (ASN-0130 SignedTerm).
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

/// Denoted values. Set values hold raw `Tumbler`s (cheap union for ⋃-folds,
/// dedup = set semantics for `count`); the lift to M1's `Address` happens at
/// the binding sites via `validate` (§Internal 2), so every element of an
/// `AddrSet` IS a T4-valid address: the evaluator builds its sets from
/// store-minted addresses only, and the two doors that take a caller's
/// value — `evaluate_def`'s argument check and `eval`'s precondition —
/// refuse a set holding anything else. `Tuple` binds a `Tup` var.
///
/// The payload types are M1's `Tumbler`/`Address`/`Nat`, M7's
/// `CoverageClass`/`Tuple` and `im`'s persistent collections — each
/// re-exported from this crate's root, so a caller builds a `Value` without
/// naming a second manifest.
#[allow(clippy::large_enum_variant)] // the interface declares these shapes verbatim
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Addr(Address),
    AddrSet(OrdSet<Tumbler>),
    OptAddr(Option<Address>),
    AddrSeq(Vector<Address>),
    Map(HashMap<CoverageClass, Address>),
    Nat(Nat),
    OptNat(Option<Nat>),
    Tuple(Tuple),
}

impl Value {
    /// The sort this value inhabits — what `eval`'s door and
    /// `evaluate_def`'s positional argument check compare against Γ_D, so a
    /// caller can ask the same question of its own values before it calls.
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

    /// The ℘_fin(T) invariant a caller-built value must meet: an `AddrSet`'s
    /// every element is a T4-valid address. True of every other shape — their
    /// address positions are `Address`-typed already. This is the DOOR's half
    /// of the invariant ([`lift`] is the binding site's): `eval`'s
    /// precondition and `evaluate_def`'s argument check ask it of every value
    /// a caller supplies, so `lift` is infallible on what passed here.
    pub(crate) fn holds_addresses(&self) -> bool {
        match self {
            Value::AddrSet(s) => s.iter().all(is_t4_valid),
            _ => true,
        }
    }
}

/// Set-element lift (Tumbler → Address) at the binding sites — M1 `validate`,
/// infallible on what reaches it (§Internal 2), and the BINDING SITE's half of
/// the ℘_fin(T) invariant [`Value::holds_addresses`] checks at the doors.
/// Every tumbler lifted here is one of two things: the start of a unit-depth
/// span in a stored slot endset — `Endset::addrs()` yields no other, and M7's
/// slot doors admit a start only as an `Address` (`SlotArg::Addrs`, `emit`'s
/// and `assert_sup`'s endpoints) or as a `Run::i_start`, an `Address` by type
/// — or an element of a `Value::AddrSet`, which the evaluator builds from
/// those and the two caller-facing doors (`evaluate_def`, `eval`) check
/// element by element.
pub(crate) fn lift(t: &Tumbler) -> Address {
    validate(t.clone()).expect("PL set elements are store-minted, T4-valid addresses")
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
    /// reaches the same key the engine would rather than re-deriving it.
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
/// recorded parameter context — what `define_predicate` encodes, the def
/// codec parses, and `parse_def` recovers from a run. Unchecked: WT over it
/// is `Checker::check_signed`'s, whose result carries it as
/// `TypedTerm::signed`; that check is where Γ_D's names are required
/// distinct (`DuplicateParameter`), so a checked term's context binds each
/// name once.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Eval environment: free-param + quantifier/Let-bound `VarId → Value`.
/// Functional (persistent) update — `bind` returns a new `Env`. A collection
/// of bindings: built from an iterator of `(VarId, Value)` pairs (a def's
/// Γ_D zipped with its arguments) and extended by one; a later binding of a
/// name shadows an earlier one, as `bind` does. Two environments are equal
/// when they bind the same names to the same values, so one built
/// positionally and one built by `bind` can be compared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env(HashMap<VarId, Value>);

impl Env {
    pub fn empty() -> Env {
        Env(HashMap::new())
    }

    #[must_use = "bind returns the extended environment; Env is persistent and the receiver is untouched"]
    pub fn bind(&self, v: VarId, val: Value) -> Env {
        Env(self.0.update(v, val))
    }

    pub fn get(&self, v: &VarId) -> Option<&Value> {
        self.0.get(v)
    }
}

impl FromIterator<(VarId, Value)> for Env {
    fn from_iter<I: IntoIterator<Item = (VarId, Value)>>(iter: I) -> Env {
        Env(iter.into_iter().collect())
    }
}

impl Extend<(VarId, Value)> for Env {
    fn extend<I: IntoIterator<Item = (VarId, Value)>>(&mut self, iter: I) {
        self.0.extend(iter)
    }
}
