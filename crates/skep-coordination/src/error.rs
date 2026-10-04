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
/// `#[non_exhaustive]`: the checker's refusals are a vocabulary that grows — a
/// further resource door, say — and an addition is one a consumer's catch-all
/// should absorb rather than a broken build.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypeError {
    /// A free `Var` outside the supplied Γ_D (the missing-context case).
    UnboundVariable(VarId),
    /// A `TypeRef::ClassVar` under no enclosing `Reg` binder (V-IDX).
    UnboundClassVar(VarId),
    /// A `type_check` Γ_D parameter sorted `Tup` — excluded from Codom
    /// (ASN-0130 SignedTerm); a rule trigger, the one term with a tuple
    /// parameter, is checked by `type_check_trigger` into a `TriggerTerm`.
    TupParameter(VarId),
    /// A Γ_D name bound twice — a context binds each name once: a repeated
    /// name's later binding would shadow its earlier one, leaving the argument
    /// passed at the earlier position unreadable. Carries the repeated name.
    DuplicateParameter(VarId),
    SortMismatch { expected: Sort, found: Sort },
    /// A `Ref` passing `found` arguments to a referent whose Γ_D binds
    /// `expected` (WT-ref: one argument per formal). Speaks where
    /// `type_check`'s walk order puts it — at the first unmatched position,
    /// every argument up to it, the extra one included, checked first.
    ArgArityMismatch { referent: Address, expected: usize, found: usize },
    /// A `Reg` domain under any former but `∀`, `∃` and `count`, the three
    /// V-IDX admits it under: `Reg` ranges over classes, so it has no element
    /// sort to bind, reflect, fold or filter by.
    MisplacedReg,
    /// An atom needs a behavior the (concrete) type's registration lacks.
    BehaviorMissing { ty: TypeKey, needs: Behavior },
    /// A BH2 atom (`Succs`/`Chain`/`Tip`/`IsInChain`) at a cataloged Walk
    /// class other than shipped `Supersedes` — M7 v1 serves the walk only for
    /// `Supersedes` (empty/trivial otherwise), so admitting it would silently
    /// denote ∅/\[\]; lifts when M7 serves app Walk classes (Conflicts §8).
    UnservedWalkClass(TypeKey),
    /// A concrete `TypeKey` that is not one of the catalog's keys. The probe
    /// is `Endset`-equality, so this subsumes a non-address-denoting key
    /// (every cataloged key is genesis-validated address-denoting) and the
    /// coverage-equal-but-byte-different miss — a key whose CLASS is
    /// cataloged, spelled otherwise than the catalog spells it. The remedy is
    /// the key `reserved_type` hands out, never a registration.
    UncatalogedTypeKey(TypeKey),
    /// The `targets_keyed` atom used (bare or under `MapGet`) with no
    /// cataloged class attaching BH3 (V-atom).
    NoReverseLookupClass,
    /// A `Ref` whose referent's signature is UNDEFINED — ASN-0130's WT-ref
    /// failure ("a never-registered referent leaves `sig(r)` undefined —
    /// hence no typing judgment"): never registered, or
    /// ever-registered-but-undisciplined (§Internal 4). Not a reference to a
    /// RETRACTED def: that referent's signature stays defined and the
    /// reference types — ASN-0130's *dangling live* reference (OQ3), which
    /// only a NEW registration refuses (`RegisterError::ReferentNotActive`).
    UndefinedReference(Address),
    /// A `Reg`-quantified body has an ill-typed concrete instance (V-IDX).
    RegInstanceIllTyped(Box<TypeError>),
    /// The term nests past `MAX_DEPTH`, counted through references: its
    /// evaluable projection (`Reg`-expansion joins included), or the reach of
    /// a `Ref` — the referent's own recorded depth plus the derivation and
    /// the arguments — would carry a walk deeper than the one bound every
    /// walk is set against; or a `Ref` ARGUMENT whose own nesting, at the
    /// `Let` position its index gives it in the flat expansion, would do the
    /// same; or a `Ref` whose referent's derivation cannot complete at the
    /// level the `Ref` sits at, the referent left unjudged. A def at the cap
    /// admits no reference to it.
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
                 (a term with a tuple parameter is a rule trigger; use type_check_trigger)"
            ),
            TypeError::DuplicateParameter(v) => {
                write!(f, "type_check: parameter {v:?} is bound twice in Γ_D")
            }
            TypeError::SortMismatch { expected, found } => {
                write!(f, "type_check: expected sort {expected:?}, found {found:?}")
            }
            TypeError::ArgArityMismatch { referent, expected, found } => write!(
                f,
                "type_check: a reference to {referent} passes {found} argument(s) to a def of \
                 {expected} parameter(s) (WT-ref)"
            ),
            TypeError::MisplacedReg => f.write_str(
                "type_check: Reg ranges over classes — admissible only as the domain of ∀, ∃ or \
                 count (V-IDX)",
            ),
            TypeError::BehaviorMissing { ty, needs } => {
                write!(f, "type_check: type {ty} does not declare behavior {needs:?}")
            }
            TypeError::UnservedWalkClass(ty) => write!(
                f,
                "type_check: BH2 walk atoms are served only at the shipped Supersedes class, not {ty}"
            ),
            TypeError::UncatalogedTypeKey(ty) => write!(
                f,
                "type_check: type key {ty} is not a catalog key (the probe is Endset-equality, \
                 not coverage — build the key from reserved_type)"
            ),
            TypeError::NoReverseLookupClass => f.write_str(
                "type_check: targets_keyed is outside the vocabulary — no cataloged class attaches BH3",
            ),
            TypeError::UndefinedReference(a) => {
                write!(f, "type_check: undefined reference — {a} has no defined signature (WT-ref)")
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

/// `define_predicate` rejection — its one refusal made before any
/// transaction, then its two transactions, the content insert and the `pdef`
/// registration.
///
/// Deliberately exhaustive: its variants are those three steps, and the
/// codec's Codom-only invariant (ASN-0130 SignedTerm) needs none — no
/// `TypedTerm` with a `Tup` parameter reaches it, in this crate or out of
/// it: `type_check` refuses one, a stored def's Γ_D is decoded from a format
/// with no `Tup` tag, and the one checked term whose parameter may be a
/// tuple is held in a `TriggerTerm`, which yields none.
#[derive(Debug)]
pub enum DefineError {
    /// The term checked, but the def codec has no stored run for it
    /// (`codec::stored_run`) — its encoding is one the decoder would not read
    /// back — so it is refused BEFORE any transaction and nothing is
    /// committed: `register_pred` would refuse the stored run `ParseFailed`
    /// and leave an orphan no registration adopts. The checker and the
    /// decoder meter different trees (`budget.rs`): the decoder charges every
    /// count an encoding spells — a shipped type key's span and its two
    /// nine-component tumblers, 37 units, where the checker charges a type
    /// position nothing; an address literal's components and their limbs,
    /// where the checker charges the components — so a body of some 1 600
    /// concrete type positions outgrows it; and it reads a `count(Reg)`'s
    /// domain a level below the node the checker folds to a literal, past
    /// `MAX_DEPTH` at the cap.
    Unstorable,
    Insert(TxnError<InsertError>),
    Register(RegisterError),
}

impl fmt::Display for DefineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DefineError::Unstorable => f.write_str(
                "define_predicate: the term's encoding is past what the def codec reads back \
                 (MAX_DEPTH, or the node budget as the decoder meters it); nothing committed",
            ),
            DefineError::Insert(e) => write!(f, "define_predicate: content insert failed: {e}"),
            DefineError::Register(e) => write!(f, "define_predicate: {e}"),
        }
    }
}

impl Error for DefineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DefineError::Unstorable => None,
            DefineError::Insert(e) => Some(e),
            DefineError::Register(e) => Some(e),
        }
    }
}

/// `supersede` rejection — its own up-front gate, the successor's definition
/// (which carries `define_predicate`'s whole home requirement), and the
/// lineage claim, the third of three non-atomic transactions.
#[derive(Debug)]
pub enum SupersedeError {
    /// `old_start` is not an ever-registered def — gated UP FRONT, before any
    /// transaction (a typo'd non-def address must not seed a `supersedes`
    /// lineage; PR4 presupposes the superseded address IS a definition).
    OldStartNotEverRegistered(Address),
    Define(DefineError),
    /// The lineage claim — the `supersedes` emit, the third of three
    /// non-atomic transactions, the first two committed. As built it is
    /// `Rejected(SupersessionClass)` on every call that reaches it: M7 fences
    /// the class to `assert_sup`/`editlink` (`Coordinator::supersede` states
    /// what that costs a retry).
    Lineage(TxnError<EmitError>),
}

impl fmt::Display for SupersedeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SupersedeError::OldStartNotEverRegistered(a) => {
                write!(f, "supersede: old start {a} is not an ever-registered def")
            }
            SupersedeError::Define(e) => write!(f, "supersede: {e}"),
            SupersedeError::Lineage(e) => {
                write!(f, "supersede: the supersedes emit failed: {e}")
            }
        }
    }
}

impl Error for SupersedeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SupersedeError::Define(e) => Some(e),
            SupersedeError::Lineage(e) => Some(e),
            SupersedeError::OldStartNotEverRegistered(_) => None,
        }
    }
}

/// `register_pred` rejection (gate-first; ASN-0130 VALID).
///
/// `#[non_exhaustive]`: the gates are the design's, but one resource gate is
/// foreseen — a cap on the DISTINCT referents a stored body may name. Each
/// costs this call an unindexed audit-slice scan at gate (iii), and the
/// decoder's node budget admits some sixteen thousand in one body (a `Ref` to
/// a one-component address is three units, its join one more). The cap's
/// refusal is a variant here, and a consumer's catch-all should absorb it
/// rather than break.
#[derive(Debug)]
#[non_exhaustive]
pub enum RegisterError {
    NotResident,
    /// The run at `start` is not a def the PR-ENC codec reads back: a
    /// malformed encoding, or a well-formed one past the decoder's two doors
    /// (`MAX_DEPTH`, the node budget as the decoder meters it).
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
            RegisterError::ParseFailed => f.write_str(
                "register_pred: the run at start is not a def the PR-ENC codec reads (malformed, \
                 or past MAX_DEPTH or the node budget)",
            ),
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
///
/// `#[non_exhaustive]`: PL evaluation has no fuel budget, and a stored def's
/// denotation is where the need is measured — `Pᵢ(x) := Pᵢ₋₁(x) ∧ Pᵢ₋₁(x)`
/// registers through `P₃₂` (its reach grows four levels per def), and one
/// `evaluate_def` of `P₃₂` walks 2³² leaves. A fuel budget's refusal lands
/// here, this being the one evaluator that already answers in a `Result`, and
/// a consumer's catch-all should absorb it rather than break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvalError {
    NotEverRegistered,
    /// Ever-registered start whose content is absent, or fails the PR-ENC
    /// parse/WT — reachable only under a PR-DISC breach (§Internal 4). The
    /// memo freezes the second (freeze-on-breach) and never the first: a run
    /// may yet be minted at a start that holds none.
    UndisciplinedDef,
    ArgArityMismatch,
    /// An argument's sort differs from Γ_D's.
    ArgSortMismatch,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EvalError::NotEverRegistered => "evaluate_def: start is not an ever-registered def",
            EvalError::UndisciplinedDef => {
                "evaluate_def: the def's content is absent or fails parse/WT (PR-DISC breach)"
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
    /// Ever-registered start with NO defined signature — its content absent,
    /// or failing the parse/WT, the latter a permanent poisoned memo entry
    /// (PR-DISC breach, §Internal 4); mirrors `EvalError`'s variant so CVALID
    /// (0)'s two `None` causes surface distinctly.
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
    /// CVALID (iii): the flat expansion is outside ST⁺, so the def's
    /// ⊤-stability is UNPROVEN — ASN-0130's *unknown*, never *unstable*. ST⁺
    /// classifies by spelling and is sound but incomplete: an extensionally
    /// ⊤-stable def spelled outside its rules (a tautology, say) lands here
    /// too, and the remedy is a respelling, not a conclusion about the
    /// predicate.
    StabilityUnproven,
    Emit(TxnError<EmitError>),
}

impl fmt::Display for CertifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertifyError::NotEverRegistered => {
                f.write_str("certify_stable: start is not an ever-registered def")
            }
            CertifyError::UndisciplinedDef => f.write_str(
                "certify_stable: the def's content is absent or fails parse/WT (PR-DISC breach)",
            ),
            CertifyError::NotBoolean => f.write_str("certify_stable: the def's codomain is not Bool"),
            CertifyError::NotActive => f.write_str("certify_stable: the def is not actively registered"),
            CertifyError::ExpansionTooLarge => f.write_str(
                "certify_stable: the def's flat reference expansion exceeds the MAX_TERM_NODES \
                 budget (nodes and the payload they carry)",
            ),
            CertifyError::ViewDependent => {
                f.write_str("certify_stable: the def's expansion is view-dependent (PR-VIEW)")
            }
            CertifyError::StabilityUnproven => f.write_str(
                "certify_stable: the def's ⊤-stability is unproven (ST⁺ classifies by spelling — \
                 unknown, not unstable)",
            ),
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

/// `retract_pred` rejection. `NotActive`: no active `pdef` tuple names the
/// start.
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
    /// `Reg` domain — `MisplacedReg`). Carries that pass's own resource
    /// refusals too, `TooDeep` and `TooLarge`: the domain is checked under a
    /// fresh budget of its own, never the submitting term's.
    IllFormedDomain(TypeError),
    /// Trigger param sort ≠ domain element sort — the reconciliation the two
    /// independent type-checks omit.
    DomainTriggerSortMismatch { expected: Sort, found: Sort },
    /// A `Def` trigger whose def's codomain ≠ Bool (a `TriggerTerm` is Bool
    /// by type).
    TriggerNotBoolean,
    /// `Trigger::Def` names an address whose signature is undefined —
    /// never-registered, or ever-registered-but-undisciplined (§Internal 4):
    /// the rule-level twin of `TypeError::UndefinedReference`.
    UndefinedDefTrigger(Address),
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
            RuleError::UndefinedDefTrigger(a) => {
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

impl From<DefineError> for SupersedeError {
    fn from(e: DefineError) -> Self {
        SupersedeError::Define(e)
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
