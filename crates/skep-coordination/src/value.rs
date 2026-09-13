//! §Core data model — values, sorts, signatures, the eval environment.

use im::{HashMap, OrdSet, Vector};
use skep_address::{is_t4_valid, Address, Nat, Tumbler};
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
    /// every element is a T4-valid address (the evaluator lifts each one to
    /// an `Address` at its binding sites, infallibly). True of every other
    /// shape — their address positions are `Address`-typed already.
    pub(crate) fn holds_addresses(&self) -> bool {
        match self {
            Value::AddrSet(s) => s.iter().all(is_t4_valid),
            _ => true,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub params: Vec<(VarId, Sort)>,
    pub result: Sort,
}

/// Eval environment: free-param + quantifier/Let-bound `VarId → Value`.
/// Functional (persistent) update — `bind` returns a new `Env`. A collection
/// of bindings: built from an iterator of `(VarId, Value)` pairs (a def's
/// Γ_D zipped with its arguments) and extended by one; a later binding of a
/// name shadows an earlier one, as `bind` does.
#[derive(Debug, Clone, Default)]
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
