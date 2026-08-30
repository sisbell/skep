//! §Core data model — the result/error types and the `?`-conversions the op
//! bodies need. Enums wrapping M2's `TxnError` derive `Debug` only (an
//! `io::Error` is neither `Clone` nor `PartialEq`); the rest derive the full
//! comparison set for test/matcher ergonomics.

use skep_address::Address;
use skep_arrangement::InsertError;
use skep_kernel::TxnError;
use skep_links::{Behavior, EmitError, NullifyError};

use crate::ast::{TypeKey, VarId};
use crate::value::Sort;

/// `type_check`/`type_check_trigger` rejection (ASN-0129 WT, V-IDX, V-STAT,
/// WT-ref).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeError {
    /// A free `Var` outside the supplied Γ_D (the missing-context case).
    UnboundVariable(VarId),
    /// A `TypeRef::ClassVar` under no enclosing `Reg` binder (V-IDX).
    UnboundClassVar(VarId),
    /// A DEF-PATH Γ_D parameter sorted `Tup` — excluded from Codom (ASN-0130
    /// SignedTerm); the trigger path (`type_check_trigger`) admits one.
    TupParameter(VarId),
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
}

/// `define_predicate`/`supersede` rejection.
#[derive(Debug)]
pub enum DefineError {
    /// A `Tup`-sorted Γ_D parameter — rejected UP FRONT, before any insert
    /// (no orphan content); stored-def params are Codom-only (ASN-0130
    /// SignedTerm). Checked by `define_predicate` AND `supersede`.
    TupParameter(VarId),
    /// `supersede` only: `old_start` is not an ever-registered def — gated UP
    /// FRONT, before any transaction (a typo'd non-def address must not seed
    /// a `supersedes` lineage; PR4 presupposes the superseded address IS a
    /// definition).
    OldStartNotEverRegistered(Address),
    Insert(TxnError<InsertError>),
    Register(RegisterError),
    Supersede(TxnError<EmitError>),
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

/// `evaluate_def` rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalError {
    NotEverRegistered,
    /// Ever-registered start whose immutable content fails the PR-ENC
    /// parse/WT — reachable only under a PR-DISC breach (§Internal 4).
    UndisciplinedDef,
    ArgArityMismatch,
    ArgSortMismatch,
}

/// `certify_stable` rejection (CVALID 0..iii).
#[derive(Debug)]
pub enum CertifyError {
    NotEverRegistered,
    /// Ever-registered start with NO defined signature — the permanent
    /// poisoned memo entry (PR-DISC breach, §Internal 4); mirrors
    /// `EvalError`'s variant so CVALID (0)'s two `None` causes surface
    /// distinctly.
    UndisciplinedDef,
    NotBoolean,
    NotActive,
    ViewDependent,
    NotStable,
    Emit(TxnError<EmitError>),
}

/// `retract_pred` rejection. `NotActive`: no active `pdef` tuple — a clean
/// rejection, never a panic (item 8).
#[derive(Debug)]
pub enum RetractError {
    NotActive,
    Nullify(TxnError<NullifyError>),
}

/// `fire` rejection. `HomeNotRegistered` is shared by the Marker emit and
/// Nullify (H-HOME — never a silent skip).
#[derive(Debug)]
pub enum FireError {
    HomeNotRegistered,
    Emit(TxnError<EmitError>),
    Nullify(TxnError<NullifyError>),
}

/// `register_rule`/`certify_rule` validation rejection (ASN-0133 Rule — each
/// failure typed, never a late fire-time panic).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Trigger codomain ≠ Bool.
    TriggerNotBoolean,
    /// `TriggerRef::Def` addr has no defined signature (never-registered or
    /// undisciplined).
    DefTriggerUnregistered(Address),
    /// Trigger not single-parameter.
    BadTriggerArity,
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

/// `supersede`'s `supersedes`-emit (the third transaction).
impl From<TxnError<EmitError>> for DefineError {
    fn from(e: TxnError<EmitError>) -> Self {
        DefineError::Supersede(e)
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
