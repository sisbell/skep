//! §Core data model — the result/error types and the `?`-conversions the op
//! bodies need. Enums wrapping M2's `TxnError` derive `Debug` only (an
//! `io::Error` is neither `Clone` nor `PartialEq`); the rest derive the full
//! comparison set for test/matcher ergonomics. Every one implements
//! `Display` and `std::error::Error`, `source` spelled variant by variant as
//! M2's `TxnError` does, so a rejection climbing out of the substrate
//! through M9 keeps its chain: a caller boxes any of them as
//! `Box<dyn Error + Send + Sync>` and walks it back to M2's own account.

use std::error::Error;
use std::fmt;

use skep_address::Address;
use skep_arrangement::InsertError;
use skep_kernel::TxnError;
use skep_links::{Behavior, EmitError, NullifyError};

use crate::ast::{TypeKey, VarId};
use crate::value::Sort;

/// `type_check`/`type_check_trigger` rejection (ASN-0129 WT, V-IDX, V-STAT,
/// WT-ref).
///
/// `#[non_exhaustive]`: the vocabulary names neither a `Ref` arity mismatch
/// nor a bare `Reg` domain (both spelled `SortMismatch` today), and a
/// dedicated variant for either is an addition a consumer's catch-all should
/// absorb rather than a broken build.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypeError {
    /// A free `Var` outside the supplied Γ_D (the missing-context case).
    UnboundVariable(VarId),
    /// A `TypeRef::ClassVar` under no enclosing `Reg` binder (V-IDX).
    UnboundClassVar(VarId),
    /// A `type_check` Γ_D parameter sorted `Tup` — excluded from Codom
    /// (ASN-0130 SignedTerm); a rule trigger, the one term that binds a
    /// tuple, is checked by `type_check_trigger` into a `TriggerTerm`.
    TupParameter(VarId),
    /// A Γ_D name bound twice — a context binds each name once, so that an
    /// `Env` can bind every parameter at its sort. Carries the repeated name.
    DuplicateParameter(VarId),
    SortMismatch { expected: Sort, found: Sort },
    /// An atom needs a behavior the (concrete) type's registration lacks.
    BehaviorMissing { ty: TypeKey, needs: Behavior },
    /// A BH2 atom (`Succs`/`Chain`/`Tip`/`IsInChain`) at a cataloged Walk
    /// class other than shipped `Supersedes` — M7 v1 serves the walk only for
    /// `Supersedes` (empty/trivial otherwise), so admitting it would silently
    /// denote ∅/\[\]; lifts when M7 serves app Walk classes (Conflicts §8).
    UnservedWalkClass(TypeKey),
    /// Concrete `TypeKey` absent from the catalog (subsumes
    /// non-address-denoting — every cataloged key is genesis-validated
    /// address-denoting — and the coverage-equal-but-byte-different miss,
    /// the probe being `Endset`-equality).
    UnregisteredType(TypeKey),
    /// The `targets_keyed` atom used (bare or under `MapGet`) with no
    /// cataloged class attaching BH3 (V-atom).
    NoReverseLookupClass,
    /// `Ref` to an address with NO DEFINED SIGNATURE (WT-ref domain failure):
    /// never-registered, or ever-registered-but-undisciplined (§Internal 4).
    DanglingReference(Address),
    /// A `Reg`-quantified body has an ill-typed concrete instance (V-IDX).
    RegInstanceIllTyped(Box<TypeError>),
    /// The term nests past `MAX_DEPTH`, counted through references: its
    /// evaluable projection (`Reg`-expansion joins included), or the reach of
    /// a `Ref` — the referent's own recorded depth plus the derivation and
    /// the arguments — would carry a walk deeper than the one bound every
    /// walk is set against; or a `Ref` whose referent's derivation cannot
    /// complete at the level the `Ref` sits at, the referent left unjudged.
    /// A def at the cap admits no reference to it.
    TooDeep,
    /// The term, after `Reg`-expansion, exceeds the `MAX_TERM_NODES` budget —
    /// counted per node the checker visits or builds AND per unit of payload
    /// that node carries (a literal's tumbler components, a `Nat`'s limbs, a
    /// `Ref`'s address, a Γ_D parameter), so the budget bounds the tree's
    /// bytes rather than its node count alone: nested `Reg` quantifiers, an
    /// `Arc`-shared body and a large literal are each charged for what they
    /// produce, and the check stops at the budget.
    TooLarge,
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeError::UnboundVariable(v) => write!(f, "type_check: unbound variable {v:?}"),
            TypeError::UnboundClassVar(v) => {
                write!(f, "type_check: class variable {v:?} under no enclosing Reg binder (V-IDX)")
            }
            TypeError::TupParameter(v) => write!(
                f,
                "type_check: parameter {v:?} is Tup-sorted — a stored def's Γ_D is Codom-only \
                 (a tuple-binding term is a rule trigger; use type_check_trigger)"
            ),
            TypeError::DuplicateParameter(v) => {
                write!(f, "type_check: parameter {v:?} is bound twice in Γ_D")
            }
            TypeError::SortMismatch { expected, found } => {
                write!(f, "type_check: expected sort {expected:?}, found {found:?}")
            }
            TypeError::BehaviorMissing { ty, needs } => {
                write!(f, "type_check: type {ty} does not declare behavior {needs:?}")
            }
            TypeError::UnservedWalkClass(ty) => write!(
                f,
                "type_check: BH2 walk atoms are served only at the shipped Supersedes class, not {ty}"
            ),
            TypeError::UnregisteredType(ty) => {
                write!(f, "type_check: type key {ty} is not a cataloged class")
            }
            TypeError::NoReverseLookupClass => f.write_str(
                "type_check: targets_keyed is outside the vocabulary — no cataloged class attaches BH3",
            ),
            TypeError::DanglingReference(a) => {
                write!(f, "type_check: reference to {a} has no defined signature (WT-ref)")
            }
            TypeError::RegInstanceIllTyped(e) => {
                write!(f, "type_check: a Reg-quantified instance is ill-typed: {e}")
            }
            TypeError::TooDeep => f.write_str(
                "type_check: the term nests past MAX_DEPTH (counted through references)",
            ),
            TypeError::TooLarge => f.write_str(
                "type_check: the term exceeds the MAX_TERM_NODES budget after Reg-expansion \
                 (nodes and the payload they carry)",
            ),
        }
    }
}

impl Error for TypeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TypeError::RegInstanceIllTyped(e) => Some(&**e),
            _ => None,
        }
    }
}

/// `define_predicate`/`supersede` rejection. A tuple-binding term has no
/// variant here: stored-def parameters are Codom-only (ASN-0130 SignedTerm)
/// by the `TypedTerm` type, which no `Tup`-binding term inhabits.
#[derive(Debug)]
pub enum DefineError {
    /// `supersede` only: `old_start` is not an ever-registered def — gated UP
    /// FRONT, before any transaction (a typo'd non-def address must not seed
    /// a `supersedes` lineage; PR4 presupposes the superseded address IS a
    /// definition).
    OldStartNotEverRegistered(Address),
    Insert(TxnError<InsertError>),
    Register(RegisterError),
    Supersede(TxnError<EmitError>),
}

impl fmt::Display for DefineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DefineError::OldStartNotEverRegistered(a) => {
                write!(f, "supersede: old start {a} is not an ever-registered def")
            }
            DefineError::Insert(e) => write!(f, "define_predicate: content insert failed: {e}"),
            DefineError::Register(e) => write!(f, "define_predicate: {e}"),
            DefineError::Supersede(e) => write!(f, "supersede: the supersedes emit failed: {e}"),
        }
    }
}

impl Error for DefineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DefineError::Insert(e) => Some(e),
            DefineError::Register(e) => Some(e),
            DefineError::Supersede(e) => Some(e),
            DefineError::OldStartNotEverRegistered(_) => None,
        }
    }
}

/// `register_pred` rejection (gate-first; ASN-0130 VALID).
#[derive(Debug)]
pub enum RegisterError {
    NotResident,
    ParseFailed,
    IllTyped(TypeError),
    ReferentNotEverRegistered(Address),
    ReferentNotActive(Address),
    HomeNotRegistered,
    Emit(TxnError<EmitError>),
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterError::NotResident => f.write_str("register_pred: no content Val at start"),
            RegisterError::ParseFailed => {
                f.write_str("register_pred: the run at start is not a well-formed def (PR-ENC)")
            }
            RegisterError::IllTyped(e) => write!(f, "register_pred: the def is ill-typed: {e}"),
            RegisterError::ReferentNotEverRegistered(a) => {
                write!(f, "register_pred: referent {a} is not ever-registered")
            }
            RegisterError::ReferentNotActive(a) => {
                write!(f, "register_pred: referent {a} is not actively registered (endorsement)")
            }
            RegisterError::HomeNotRegistered => {
                f.write_str("register_pred: home is not a registered document (P0)")
            }
            RegisterError::Emit(e) => write!(f, "register_pred: the pdef emit failed: {e}"),
        }
    }
}

impl Error for RegisterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RegisterError::IllTyped(e) => Some(e),
            RegisterError::Emit(e) => Some(e),
            _ => None,
        }
    }
}

/// `evaluate_def` rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalError {
    NotEverRegistered,
    /// Ever-registered start whose immutable content fails the PR-ENC
    /// parse/WT — reachable only under a PR-DISC breach (§Internal 4).
    UndisciplinedDef,
    ArgArityMismatch,
    /// An argument's sort differs from Γ_D's — or an `AddrSet` argument
    /// holds a tumbler that is not a T4-valid address, which is no ℘_fin(T)
    /// value at all (the evaluator lifts every set element to an `Address`
    /// at its binding sites).
    ArgSortMismatch,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EvalError::NotEverRegistered => "evaluate_def: start is not an ever-registered def",
            EvalError::UndisciplinedDef => {
                "evaluate_def: the def's content fails the parse/WT (PR-DISC breach)"
            }
            EvalError::ArgArityMismatch => "evaluate_def: argument count differs from Γ_D's",
            EvalError::ArgSortMismatch => "evaluate_def: an argument's sort differs from Γ_D's",
        })
    }
}

impl Error for EvalError {}

/// `certify_stable` rejection (CVALID 0..iii).
///
/// `#[non_exhaustive]`: the static refusals a certification makes before its
/// deposit — over the flat expansion, which no bound but this crate's own
/// governs — are a vocabulary that grows with the analyses; a consumer's
/// catch-all should absorb a new one rather than break.
#[derive(Debug)]
#[non_exhaustive]
pub enum CertifyError {
    NotEverRegistered,
    /// Ever-registered start with NO defined signature — the permanent
    /// poisoned memo entry (PR-DISC breach, §Internal 4); mirrors
    /// `EvalError`'s variant so CVALID (0)'s two `None` causes surface
    /// distinctly.
    UndisciplinedDef,
    NotBoolean,
    NotActive,
    /// The def's flat reference expansion exceeds the `MAX_TERM_NODES`
    /// budget — a reference DAG whose unfolding into the tree ST⁺ classifies
    /// is past it in nodes or in the payload they carry (each `Ref`
    /// re-expands its referent under fresh names, PR3, copying its literals
    /// whole, so a def referenced twice per level unfolds exponentially).
    /// Asked before view-independence: the expansion is what both legs read.
    ExpansionTooLarge,
    ViewDependent,
    NotStable,
    Emit(TxnError<EmitError>),
}

impl fmt::Display for CertifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertifyError::NotEverRegistered => {
                f.write_str("certify_stable: start is not an ever-registered def")
            }
            CertifyError::UndisciplinedDef => {
                f.write_str("certify_stable: the def's content fails the parse/WT (PR-DISC breach)")
            }
            CertifyError::NotBoolean => f.write_str("certify_stable: the def's codomain is not Bool"),
            CertifyError::NotActive => f.write_str("certify_stable: the def is not actively registered"),
            CertifyError::ExpansionTooLarge => f.write_str(
                "certify_stable: the def's flat reference expansion exceeds the MAX_TERM_NODES \
                 budget (nodes and the payload they carry)",
            ),
            CertifyError::ViewDependent => {
                f.write_str("certify_stable: the def's expansion is view-dependent (PR-VIEW)")
            }
            CertifyError::NotStable => f.write_str("certify_stable: the def is not ⊤-stable (ST⁺)"),
            CertifyError::Emit(e) => write!(f, "certify_stable: the pd_stable emit failed: {e}"),
        }
    }
}

impl Error for CertifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CertifyError::Emit(e) => Some(e),
            _ => None,
        }
    }
}

/// `retract_pred` rejection. `NotActive`: no active `pdef` tuple — a clean
/// rejection, never a panic (item 8).
#[derive(Debug)]
pub enum RetractError {
    NotActive,
    Nullify(TxnError<NullifyError>),
}

impl fmt::Display for RetractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RetractError::NotActive => f.write_str("retract_pred: no active pdef tuple at start"),
            RetractError::Nullify(e) => write!(f, "retract_pred: the nullify failed: {e}"),
        }
    }
}

impl Error for RetractError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RetractError::Nullify(e) => Some(e),
            RetractError::NotActive => None,
        }
    }
}

/// `fire` rejection. `HomeNotRegistered` is shared by the Marker emit and
/// Nullify (H-HOME — never a silent skip).
///
/// `#[non_exhaustive]`: an occurrence aimed at a rule this coordinator never
/// registered is a precondition violation today (a panic, like `decide`'s);
/// naming it here is an addition a driver's catch-all should absorb.
#[derive(Debug)]
#[non_exhaustive]
pub enum FireError {
    /// The action's home, or the bound argument's document, is not readable
    /// at GUEST class (PUB round 2, lane 3.3, §5): the fire would cross the
    /// draft boundary, and is refused before any deposit — carrying the
    /// document that failed. Ahead of `HomeNotRegistered`: the check runs off
    /// the fire snapshot, before M7's write path is entered.
    DraftBoundary(Address),
    HomeNotRegistered,
    Emit(TxnError<EmitError>),
    Nullify(TxnError<NullifyError>),
}

impl fmt::Display for FireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FireError::DraftBoundary(d) => {
                write!(f, "fire: document {d} is not readable at guest class (draft boundary)")
            }
            FireError::HomeNotRegistered => {
                f.write_str("fire: the action's home is not a registered document (H-HOME)")
            }
            FireError::Emit(e) => write!(f, "fire: the marker emit failed: {e}"),
            FireError::Nullify(e) => write!(f, "fire: the nullify failed: {e}"),
        }
    }
}

impl Error for FireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            FireError::Emit(e) => Some(e),
            FireError::Nullify(e) => Some(e),
            FireError::DraftBoundary(_) | FireError::HomeNotRegistered => None,
        }
    }
}

/// `register_rule`/`certify_rule` validation rejection (ASN-0133 Rule — each
/// failure typed, never a late fire-time panic).
///
/// `#[non_exhaustive]`: a `Nullify` action over an `Addr`-over-`M_K` domain
/// registers today and fails at every fire (`BadTarget`); refusing the
/// statically-decidable root case is a variant this vocabulary may grow.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleError {
    /// `Inline` must be ref-free; persist-as-def + `Def` works only for a
    /// Codom-param trigger — a tuple-domained trigger must inline the helper.
    RefBearingInlineTrigger,
    /// A `Ref` inside the rule domain (`Filter`/`SetTerm` body) — no `Def`
    /// escape for domains; inline the helper.
    RefBearingDomain,
    /// `rule.domain` fails the WT-domain + `Reg`-expansion pass (incl. a bare
    /// `Reg` domain — the sort check).
    IllFormedDomain(TypeError),
    /// Trigger param sort ≠ domain element sort — the reconciliation the two
    /// independent type-checks omit.
    DomainTriggerSortMismatch { expected: Sort, found: Sort },
    /// A `Def` trigger whose def's codomain ≠ Bool (a `TriggerTerm` is Bool
    /// by type).
    TriggerNotBoolean,
    /// `Trigger::Def` names an address with no defined signature —
    /// never-registered, or ever-registered-but-undisciplined (§Internal 4):
    /// the rule-level twin of `TypeError::DanglingReference`.
    DanglingDefTrigger(Address),
    /// A `Def` trigger whose def is not single-parameter (a `TriggerTerm`
    /// binds exactly one by type).
    BadTriggerArity,
    /// A `Def` trigger whose def's flat reference expansion exceeds the
    /// `MAX_TERM_NODES` budget, in nodes or in the payload they carry — the
    /// tree the lint and the armer graph read.
    /// Refused at registration, so every registered trigger expands within
    /// the budget and the static analyses over the working set stay
    /// infallible (an `Inline` trigger is ref-free: its projection is its
    /// own expansion).
    TriggerExpansionTooLarge,
    /// `Marker.ty` not a cataloged Unary type.
    BadMarkerType(TypeKey),
    /// `Marker.ty` cataloged Unary but idem = ⊥ — the fire executor's gap
    /// dedup-absorption and the Q3/I1a extinction analysis both require
    /// idem⊤.
    NonIdemMarkerType(TypeKey),
    /// `Marker.ty` ∈ {pdef, pd_stable} — PR-DISC reserves those slices for
    /// `register_pred`/`certify_stable`.
    PredLayerMarkerType(TypeKey),
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleError::RefBearingInlineTrigger => {
                f.write_str("register_rule: an Inline trigger must be ref-free")
            }
            RuleError::RefBearingDomain => {
                f.write_str("register_rule: the rule domain must be ref-free")
            }
            RuleError::IllFormedDomain(e) => write!(f, "register_rule: ill-formed domain: {e}"),
            RuleError::DomainTriggerSortMismatch { expected, found } => write!(
                f,
                "register_rule: the domain's element sort is {expected:?}, the trigger's parameter sort {found:?}"
            ),
            RuleError::TriggerNotBoolean => {
                f.write_str("register_rule: the Def trigger's codomain is not Bool")
            }
            RuleError::DanglingDefTrigger(a) => {
                write!(f, "register_rule: Def trigger {a} has no defined signature")
            }
            RuleError::BadTriggerArity => {
                f.write_str("register_rule: the Def trigger's def does not bind exactly one parameter")
            }
            RuleError::TriggerExpansionTooLarge => f.write_str(
                "register_rule: the Def trigger's flat reference expansion exceeds the \
                 MAX_TERM_NODES budget (nodes and the payload they carry)",
            ),
            RuleError::BadMarkerType(ty) => {
                write!(f, "register_rule: Marker type {ty} is not a cataloged Unary class")
            }
            RuleError::NonIdemMarkerType(ty) => {
                write!(f, "register_rule: Marker type {ty} is not idempotent (idem⊤ required)")
            }
            RuleError::PredLayerMarkerType(ty) => write!(
                f,
                "register_rule: Marker type {ty} is a PredLayer class (pdef/pd_stable), reserved by PR-DISC"
            ),
        }
    }
}

impl Error for RuleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RuleError::IllFormedDomain(e) => Some(e),
            _ => None,
        }
    }
}

// ───────────────── `?`-conversions the op bodies need ─────────────────

impl From<TxnError<InsertError>> for DefineError {
    fn from(e: TxnError<InsertError>) -> Self {
        DefineError::Insert(e)
    }
}

impl From<RegisterError> for DefineError {
    fn from(e: RegisterError) -> Self {
        DefineError::Register(e)
    }
}

impl From<TxnError<EmitError>> for RegisterError {
    fn from(e: TxnError<EmitError>) -> Self {
        RegisterError::Emit(e)
    }
}

impl From<TxnError<EmitError>> for CertifyError {
    fn from(e: TxnError<EmitError>) -> Self {
        CertifyError::Emit(e)
    }
}

impl From<TxnError<NullifyError>> for RetractError {
    fn from(e: TxnError<NullifyError>) -> Self {
        RetractError::Nullify(e)
    }
}
