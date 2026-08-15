//! §Core data model — values, sorts, signatures, the eval environment.

use im::{HashMap, OrdSet, Vector};
use skep_address::{Address, Nat, Tumbler};
use skep_links::{CoverageClass, Tuple};

use crate::ast::VarId;

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
/// the binding sites via `validate` (§Internal 2). `Tuple` binds a `Tup` var.
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

/// The sort a value inhabits — evaluate_def's positional arg check reads this.
pub(crate) fn value_sort(v: &Value) -> Sort {
    match v {
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
/// Functional (persistent) update — `bind` returns a new `Env`.
#[derive(Debug, Clone, Default)]
pub struct Env(HashMap<VarId, Value>);

impl Env {
    pub fn empty() -> Env {
        Env(HashMap::new())
    }

    pub fn bind(&self, v: VarId, val: Value) -> Env {
        Env(self.0.update(v, val))
    }

    pub fn get(&self, v: &VarId) -> Option<&Value> {
        self.0.get(v)
    }
}
