//! Values, sorts and signatures (§Core data model).
//!
//! The module also holds the stored slice a read touches and the eval
//! environment.

use im::{HashMap, OrdSet, Vector};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_links::{CoverageClass, Tuple, View};

use crate::ast::{Term, VarId};

/// A PL sort: COD ∪ {Tup} (ASN-0129 WT).
///
/// `Tup` is bound only by a rule trigger's one parameter
/// (`type_check_trigger`) and by a binder over `A_K`/`L_K` — `∀`, `∃`, a
/// `Filter`, a `⋃` — or a `Let` rebinding such a value; a stored def's `Γ_D`
/// is Codom-only (ASN-0130 SignedTerm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sort {
    /// The Booleans.
    Bool,
    /// Addresses, T.
    Addr,
    /// Finite address sets, ℘_fin(T).
    AddrSet,
    /// An address or ⊥, T∪{⊥}.
    OptAddr,
    /// Finite address sequences, Seq_fin(T).
    AddrSeq,
    /// Finite maps from coverage class to address, Map_fin.
    Map,
    /// Natural numbers, ℕ.
    Nat,
    /// A natural number or ⊥, ℕ∪{⊥}.
    OptNat,
    /// Whole link tuples, outside COD.
    Tup,
}

/// A denoted value.
///
/// `AddrSet` is ℘_fin(T) as `im::OrdSet<Address>`: M1 orders and compares an
/// `Address` by its tumbler (T1), so union (the ⋃-fold), dedup (`count`'s set
/// semantics) and the T1 extrema cost no more than over the tumblers M7's
/// endsets yield, and every element is an address *by type* — a set is
/// gathered from addresses M7 hands over (M3 hands over none), or from the
/// tumblers a stored slot denotes, each lifted once as it is gathered (the
/// crate's `lift`). `AddrSeq` has the same element type, so `elems` converts
/// nothing, and a quantifier, a fold or a rule binds a set's element as it
/// stands. `Tuple` binds a `Tup` var.
///
/// The payload types are M1's `Address`/`Nat`, M7's `CoverageClass`/`Tuple`
/// and `im`'s persistent collections — each re-exported from this crate's
/// root, so a caller builds a `Value` without naming a second manifest.
///
/// Deliberately not `Hash`, unlike the PL tree: `Map` holds an
/// `im::HashMap`, whose `Hash` folds its entries in iteration order — an
/// order each map's own hasher fixes — while its `PartialEq` compares
/// contents, so two equal values could hash apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A Boolean.
    Bool(bool),
    /// An address.
    Addr(Address),
    /// A finite address set, ℘_fin(T).
    AddrSet(OrdSet<Address>),
    /// An address, or ⊥ as `None`.
    OptAddr(Option<Address>),
    /// A finite address sequence.
    AddrSeq(Vector<Address>),
    /// A finite map from coverage class to address.
    Map(HashMap<CoverageClass, Address>),
    /// A natural number.
    Nat(Nat),
    /// A natural number, or ⊥ as `None`.
    OptNat(Option<Nat>),
    /// A whole link tuple.
    Tuple(Tuple),
}

impl Value {
    /// Returns the sort this value inhabits.
    ///
    /// It is what both evaluators' positional binding compares against Γ_D,
    /// so a caller can ask the same question of its own values before it
    /// calls.
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

/// Lifts a tumbler a stored slot denotes to the `Address` a PL value holds.
///
/// The tumbler is the start of a unit-depth span in an M7 endset, as
/// `Endset::addrs()` and `Endset::single_denoted()` yield it; the lift is M1
/// `validate`, infallible on what reaches it (§Internal 2). Its callers are
/// the reads that gather a slot's denotation — `GuestLinks`' set reads, its
/// claim index and its `target_of`, the V-TUP slot atoms, and the scope
/// bodies — so a set is made of addresses from the moment it is gathered.
/// Every other address a value holds is one by type: handed over by M7 as an
/// `Address` (M3 hands over none), decoded as a literal through the codec's
/// own `validate`, or supplied by a caller.
///
/// # Panics
///
/// Panics on a tumbler that is not T4-valid. The lift's infallibility rests
/// on one upstream property, and not every M7 write door establishes it:
/// *every unit-depth span in a stored F or G has a T4-valid start* — F and G
/// being the slots every caller above lifts out of. `Endset::addrs()` filters
/// on a span's *shape* (`s == subtree_of(s.start())`) and says nothing about
/// its start. `SlotArg`'s two forms, which both `makelink` writes take, and
/// the endpoints of `emit`, `assert_sup` and `nullify` build F and G from an
/// `Address` or a `Run::i_start`, and so establish it. `editlink` does not:
/// it takes a caller-built successor `Link`, and of its F and G asks only a
/// span count and level-uniformity (and, of a `[K_sup]`-typed successor, one
/// resident endpoint each side, the two distinct), which a unit-depth span
/// at a T4-invalid start — `subtree_of(1.0.0.1)`, adjacent zeros — passes in
/// a successor of any other type. There the property holds only by its one
/// caller's construction: M10's dispatch of EDITLINK hands it the successor
/// `successor_link` builds, whose F and G are `Run::iextent`s. Nor is it
/// re-established on the journal/checkpoint deserialize path, where `Endset`
/// derives a plain `Deserialize` while `Address`, `Span`, `Tumbler` and
/// `Link` each validate through a shadow. So a tampered store reaches this
/// `expect` at the first read that gathers the slot, and so would a second
/// `editlink` caller that built a successor from raw spans; a hostile peer on
/// the wire does not. M7's own reads (`lift_denoted`) rest on the same
/// property.
pub(crate) fn lift(t: &Tumbler) -> Address {
    validate(t.clone()).expect("a stored F/G slot's unit-depth spans start at T4-valid addresses")
}

/// A PL domain element: what `[D]_snap` yields (QD, §Internal 2).
///
/// It is an address, from an address-valued domain (`M_K`, `L_dom`, a
/// reflected set term), or a whole tuple, from a tuple-valued slice (`A_K`,
/// `L_K`). The two element sorts the WT domain judgment admits — `dom(Addr)`
/// and `dom(Tup)` — are this type's two shapes, so a quantifier, a fold and a
/// rule each bind exactly what a domain can yield. A rule's bound argument is
/// one of these (`Occurrence.arg`); what a fire acts at, and the bookkeeping
/// key, is its address ([`Arg::key_addr`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// An address, from an address-valued domain.
    Addr(Address),
    /// A whole tuple, from a tuple-valued slice.
    Tuple(Tuple),
}

impl Arg {
    /// Returns the address a bound argument of either shape stands for.
    ///
    /// That is the address itself, or the tuple's `t.addr` (R1
    /// AddressInjectivity, so an address hit is a value hit). It is what a
    /// fire acts at — the address a Marker's tuple covers, the link a Nullify
    /// retracts, the address whose document the draft boundary judges
    /// (§Internal 5: `a` is the bound argument's address) — and the
    /// bookkeeping key: what a `StepOutcome` reports, what `fire_count` keys
    /// on and what a rule's `step` rotation advances past, so a driver holding
    /// a peeked `Occurrence` reaches the same key the rule engine would rather
    /// than re-deriving it.
    pub fn key_addr(&self) -> &Address {
        match self {
            Arg::Addr(a) => a,
            Arg::Tuple(t) => &t.addr,
        }
    }

    /// Returns whether these are the same domain element.
    ///
    /// Addresses compare by address; tuples by `t.addr` (R1
    /// AddressInjectivity — an address hit is a value hit); never across
    /// shapes, a domain yielding one shape only, so a probe of the other is
    /// out of that domain by construction — which is why `fire` answers
    /// `NoOp` for it rather than refusing.
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

/// The stored slice a read touches.
///
/// It is the active tuples, or the whole audit record. `A_K` and `L_K` —
/// PL's two tuple domains — are its two values, and `Observe_K`'s two
/// selectable slices (§Internal 2).
///
/// Distinct from a term's [`View`] (PC3), an evaluation parameter with three
/// values: `default` names no slice — it is the active slice plus M9's UV
/// rewrite over it (`EvalCtx`). [`Slice::of`] is the one statement of that
/// relation, asked where a term view circulates: by the evaluator, choosing
/// the slice a view-parameterized read takes — save
/// `EvalCtx::targets_of_at`, which chooses its read by the view itself, its
/// matching regime moving with the view — and by the analyzer, charging that
/// slice to a footprint. The read surface (`GuestLinks`) reads *by* a slice
/// and widens it to M7's `View` where it calls M7. At a direct `LinkState`
/// read, at no visibility class — the def probes (`coordinator/defs.rs`) and
/// the divergence monitor (`coordinator/engine.rs`) — M9 speaks M7's `View`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slice {
    Active,
    Audit,
}

impl Slice {
    /// Returns the slice a term at `view` reads.
    ///
    /// `audit` reads the whole record; `active` and `default` both read the
    /// active tuples — they differ only by the UV rewrite applied *over* them
    /// (`EvalCtx::uv_keeps`), never by which slice is read. Deliberately not a
    /// `From`: the step is lossy, and naming it is what keeps the two
    /// concepts apart.
    pub(crate) fn of(view: View) -> Slice {
        match view {
            View::Audit => Slice::Audit,
            View::Active | View::Default => Slice::Active,
        }
    }
}

/// The signed term `(Γ_D, body)` (ASN-0130 SignedTerm).
///
/// It is a PL body with its recorded parameter context — what the def codec
/// stores a def as (`codec::stored_run`) and parses back, and `parse_def`
/// recovers from a run. Unchecked: WT over it is `Checker::check_signed`'s,
/// whose result carries it as `TypedTerm::signed`; that check is where Γ_D's
/// names are required distinct (`DuplicateParameter`), so a checked term's
/// context binds each name once.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SignedTerm {
    pub(crate) params: Vec<(VarId, Sort)>,
    pub(crate) body: Term,
}

/// A stored def's checked signature, `(Γ_D, C_D)` (PR-SIG).
///
/// Each param sort ∈ COD: a stored def's parameters are bound by
/// `evaluate_def` to values, never a tuple (the `Tup` latitude lives only in
/// the rule-trigger path, whose result a `Signature` never describes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    /// Γ_D, the ordered parameter context.
    pub params: Vec<(VarId, Sort)>,
    /// C_D, the codomain sort.
    pub result: Sort,
}

/// The evaluator's environment, `VarId → Value`, updated functionally.
///
/// It holds a term's Γ_D arguments and every name a quantifier, `Let` or
/// binder guard binds — `bind` returns a new `Env`, a later binding of a
/// name shadowing an earlier one, so a binder's scope ends where its subterm
/// does. Crate-private: a caller hands a term its arguments positionally
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

/// A Γ_D zipped with its arguments.
///
/// It is `bind_args`'s binding, and the evaluator's of a referent's
/// parameters to a `Ref`'s arguments.
impl FromIterator<(VarId, Value)> for Env {
    fn from_iter<I: IntoIterator<Item = (VarId, Value)>>(iter: I) -> Env {
        Env(iter.into_iter().collect())
    }
}
