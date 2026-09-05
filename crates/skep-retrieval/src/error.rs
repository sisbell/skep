//! §Errors — the typed rejections of M6's seven operations (all surfaced
//! verbatim by M10 — never a silent skip).
//!
//! WHICH REFUSAL SPEAKS, in three clauses a caller may rely on.
//!
//! ONE PASS, REQUEST ORDER. Each gate walks the request as submitted and
//! reports the FIRST fault it reaches, whatever its kind — a fault at an
//! earlier position outranks any fault at a later one, which is what makes
//! `index` / `(region, index)` / `(operand, region, index)` locate anything:
//! the payload names a position the caller can trust everything before to be
//! clean of.
//!
//! WITHIN ONE POSITION — one spec, or one region and one of its spans — the
//! checks run in variant declaration order: registry, then (COMPARE) content
//! residence, then the span gate. [`OriginError`] is the whole-enum case, its
//! operation naming one document and one span, so its six variants read WF_V's
//! conjuncts i, ii/iv, iii, v, vi in sequence with no positional clause to
//! compose against.
//!
//! THE BUDGET REFUSALS ARE LOCATED AT NO POSITION. `TooManyBlocks`,
//! `TooManyPairs` and `TooMuchCoverage` can fire only after their operation's
//! gate has completed over the WHOLE request, so a shape fault always outranks
//! a size refusal — which is also their declaration order, the budget variants
//! being declared last.
//!
//! The first two clauses compose, and the composition is what a caller reads
//! precedence by: a request whose FIRST spec has a malformed span and whose
//! SECOND names an unregistered document reports `MalformedSpec`, though
//! `DocNotRegistered` is declared first.
//!
//! [`SpanFault`] is a fault VOCABULARY rather than an operation's ladder, so
//! none of the three applies to it: which of its four a malformed span reports
//! is fixed by its own decision order, stated on [`SpanFault`] and enforced at
//! `gate_vspan`, where it is tested.
//!
//! Derive policy, in two classes that take different derives for a reason.
//! The six OPERATION enums are the `E` of a public `Result`, and derive
//! `Clone + Debug + PartialEq + Eq + Serialize`. [`SpanFault`] and [`Operand`]
//! are classification VOCABULARIES that travel as payload inside those six,
//! so they take the derives M1 gives its own — `Level`, `Class`, `SpanRel` —
//! adding `Copy` and `Hash`: a consumer that keys by one cannot supply the
//! impl (both the trait and the type are foreign to it), and M10's `FaultSite`
//! embeds both, so withholding `Hash` here is what would decide whether that
//! type can have it. Not `Ord`, and the asymmetry is deliberate:
//! [`SpanFault`]'s declaration order carries no meaning (the decision order is
//! stated on the type itself), and a derived `Ord` would give reordering the
//! variants an observable effect. Not `Hash` on the six either — no consumer
//! keys by a rejection, and M10 converts each to its own `Rejection` at the
//! seam.
//!
//! `DocNotRegistered` carries the offending document wherever
//! the interface declares a payload (RETRIEVEV/SHOWDELETIONS/COMPARE/
//! FINDDOCSCONTAINING); the interface declares ExtentError's and OriginError's
//! as payload-free — the document is recoverable from the single-document
//! request — and the interface is the verbatim binding.
//!
//! WHERE THE DOCUMENT SITS. A registry rejection carries no index, and the
//! first clause above is what locates it: the offending position is the FIRST
//! spec or region, in request order and ρ₁ before ρ₂, naming the carried
//! document. Everything before it is span-clean too, since a span fault there
//! would have spoken instead. So the payload localizes exactly as an `index`
//! does, and the before-is-clean promise is one a caller can act on rather
//! than only read.
//!
//! All six carry the workspace's shape for a typed rejection —
//! `Debug + Display + std::error::Error`, each a LEAF with no `source()`,
//! because no M6 variant wraps another error — so a caller boxes one, `?`s it
//! into a `Box<dyn Error>` or an `anyhow` chain, and reads its message like
//! any other error in the system. That is independent of `Serialize`, which
//! is how M10 marshals them; `Display` carries the human-readable message,
//! naming the offending document in M1's dotted-decimal form wherever the
//! variant carries one.
//!
//! [`SpanFault`] and [`Operand`] deliberately stop at `Debug + Display`: they
//! are payload INSIDE those six and are never the `E` of a public `Result`,
//! so an `Error` impl there would only invite a `source()` that double-prints
//! the message its carrier already interpolates.

use std::error::Error;
use std::fmt;

use serde::Serialize;
use skep_address::Address;

/// Span well-formedness faults (ASN-0115): the four ways a request span fails
/// the span half of the V-spec gate. `StartTooShallow` is `#start < 2`; a
/// well-formed `#start ≥ 3` span is NOT a fault here — depth-compatibility is
/// consulting-state, not well-formedness (§Conflicts resolved 8).
///
/// THE DECISION ORDER, which a repair loop may rely on. A span can fail
/// several of the four at once, and the one reported is the first of:
/// [`NotLevelUniform`], [`NotOrdinalLevel`], [`StartNotZeroFree`],
/// [`StartTooShallow`]. So a fault means "the clauses before it hold" and
/// says nothing about the ones after it: a caller repairing a span walks the
/// ladder forward, in a bounded number of round trips, rather than treating
/// each report as the only defect.
///
/// That is the DECISION order and deliberately NOT the declaration order
/// below, which carries no meaning — the reason `Ord` is withheld, so that
/// reordering the variants can have no observable effect. The ladder is
/// enforced in one place, `gate_vspan`, where it is tested.
///
/// [`NotLevelUniform`]: SpanFault::NotLevelUniform
/// [`NotOrdinalLevel`]: SpanFault::NotOrdinalLevel
/// [`StartNotZeroFree`]: SpanFault::StartNotZeroFree
/// [`StartTooShallow`]: SpanFault::StartTooShallow
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize)]
pub enum SpanFault {
    /// Width does not act at its deepest component (not ordinal-level).
    NotOrdinalLevel,
    /// `#start ≠ #width` (not level-uniform).
    NotLevelUniform,
    /// The start carries a zero component (not zero-free).
    StartNotZeroFree,
    /// `#start < 2` (ASN-0115 WF requires `#start ≥ 2`).
    StartTooShallow,
}

/// Which COMPARE spec-set (ρ₁/ρ₂) a fault came from — `Copy`, captured into
/// the gate loop.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize)]
pub enum Operand {
    First,
    Second,
}

/// RETRIEVEV rejection (ASN-0115): a malformed spec rejects the WHOLE request
/// (well-formedness precondition); `index` names the offending spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum RetrieveError {
    DocNotRegistered(Address),
    MalformedSpec { index: usize, fault: SpanFault },
}

/// RETRIEVEDOCVSPAN / RETRIEVEDOCVSPANSET rejection (ASN-0112/0113 W-pre):
/// the document is not registered. Payload-free per the interface (the
/// document is the request's one argument).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ExtentError {
    DocNotRegistered,
}

/// SHOWORIGIN_V rejection (ASN-0077 WF_V/O13) — reject, never clamp; each
/// inadmissibility carries its own variant so M10/clients can localize the
/// cause ("wrong-depth span" is never conflated with "unbound positions").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum OriginError {
    /// The document is not a registered document (WF_V(i)'s `d ∈ Σ.E_doc`).
    DocNotRegistered,
    /// WF_V(ii/iv): the span fails span well-formedness.
    MalformedSpan(SpanFault),
    /// The span's start subspace is ∉ {s_C, s_L} — distinct from a real but
    /// empty subspace.
    NoSuchSubspace,
    /// WF_V(iii): a real subspace (s_C or s_L) with no occupied positions.
    EmptySubspace,
    /// WF_V(v): span depth ≠ the subspace common depth `m_S ≡ 2`
    /// (`#start ≥ 3`) — decided by M5's `is_ordinal_vspan`, the shape its
    /// `resolve` serves.
    DepthIncompatible,
    /// WF_V(vi): a depth-2 span naming positions not all currently bound.
    RangeNotPresent,
}

/// SHOWDELETIONS rejection (ASN-0075): both documents must be registered;
/// carries the offending document (`d_a` is checked first).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum DeletionsError {
    DocNotRegistered(Address),
}

/// COMPARE rejection (ASN-0122): every SPAN fault carries an unambiguous
/// `(operand, region, span-index)` — FINDDOCSCONTAINING's `(region, index)`
/// plus the operand tag; the registry fault carries the offending document
/// instead, which locates it just as unambiguously. Per span, the
/// content-subspace residence check runs BEFORE the well-formedness gate.
///
/// The last two are the budget refusals COMPARE's superlinear join needs, and
/// are the only rejections here that name no defect in the request's SHAPE —
/// only its size. Both name the budget they passed, so a client learns which
/// dimension to narrow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum CompareError {
    DocNotRegistered(Address),
    NotContentSubspace {
        operand: Operand,
        region: usize,
        index: usize,
    },
    MalformedSpan {
        operand: Operand,
        region: usize,
        index: usize,
        fault: SpanFault,
    },
    /// The operand resolves to more than [`MAX_COMPARE_OPERAND_BLOCKS`]
    /// blocks. The join is `|P|·|Q|`, so a per-operand budget is what bounds
    /// it; refused before the join runs, with ρ₁ resolved first.
    ///
    /// [`MAX_COMPARE_OPERAND_BLOCKS`]: crate::MAX_COMPARE_OPERAND_BLOCKS
    TooManyBlocks { operand: Operand },
    /// The join runs to more than [`MAX_COMPARE_PAIRS`] correspondences. The
    /// block budget cannot see this one: two small operands naming the same
    /// position fan out to their product.
    ///
    /// [`MAX_COMPARE_PAIRS`]: crate::MAX_COMPARE_PAIRS
    TooManyPairs,
}

/// FINDDOCSCONTAINING rejection (ASN-0124): every named document must be
/// registered and every region span well-formed; a malformed span is a typed
/// rejection, never a silent under-resolution that drops containers
/// (FD-COMPLETE).
///
/// The last is the budget refusal, and the only rejection here that names no
/// defect in the request's SHAPE — only its size. It names the budget it
/// passed, so a client learns what to narrow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum FindError {
    DocNotRegistered(Address),
    MalformedSpan {
        region: usize,
        index: usize,
        fault: SpanFault,
    },
    /// The request resolves to more than [`MAX_FIND_COVERAGE_SPANS`] coverage
    /// spans — the one factor of this operation's cost that the request owns,
    /// and the multiplier it applies to two world-sized scans. Refused BEFORE
    /// the candidate scan runs; a refusal, never a truncation, so FD-COMPLETE
    /// holds verbatim for every request answered.
    ///
    /// [`MAX_FIND_COVERAGE_SPANS`]: crate::MAX_FIND_COVERAGE_SPANS
    TooMuchCoverage,
}

impl fmt::Display for SpanFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SpanFault::NotOrdinalLevel => {
                "span width does not act at its deepest component (not ordinal-level)"
            }
            SpanFault::NotLevelUniform => "span start and width lengths differ (not level-uniform)",
            SpanFault::StartNotZeroFree => "span start carries a zero component (not zero-free)",
            SpanFault::StartTooShallow => "span start has fewer than 2 components (#start < 2)",
        })
    }
}
impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Operand::First => "first spec-set (ρ₁)",
            Operand::Second => "second spec-set (ρ₂)",
        })
    }
}

impl fmt::Display for RetrieveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RetrieveError::DocNotRegistered(d) => {
                write!(f, "retrieve_v: {d} is not a registered document")
            }
            RetrieveError::MalformedSpec { index, fault } => {
                write!(f, "retrieve_v: spec {index} is malformed: {fault}")
            }
        }
    }
}
impl Error for RetrieveError {}

impl fmt::Display for ExtentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("doc_vspan/doc_vspanset: doc is not a registered document")
    }
}
impl Error for ExtentError {}

impl fmt::Display for OriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OriginError::DocNotRegistered => {
                f.write_str("show_origin_v: doc is not a registered document")
            }
            OriginError::MalformedSpan(fault) => {
                write!(f, "show_origin_v: span is malformed: {fault}")
            }
            OriginError::NoSuchSubspace => f.write_str(
                "show_origin_v: the span's start subspace is neither content nor link",
            ),
            OriginError::EmptySubspace => {
                f.write_str("show_origin_v: the named subspace has no occupied positions")
            }
            OriginError::DepthIncompatible => f.write_str(
                "show_origin_v: span depth must equal the subspace common depth (#start = 2)",
            ),
            OriginError::RangeNotPresent => f.write_str(
                "show_origin_v: the span names positions not all currently bound (never clamped)",
            ),
        }
    }
}
impl Error for OriginError {}

impl fmt::Display for DeletionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeletionsError::DocNotRegistered(d) => {
                write!(f, "show_deletions: {d} is not a registered document")
            }
        }
    }
}
impl Error for DeletionsError {}

impl fmt::Display for CompareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompareError::DocNotRegistered(d) => {
                write!(f, "compare: {d} is not a registered document")
            }
            CompareError::NotContentSubspace {
                operand,
                region,
                index,
            } => write!(
                f,
                "compare: {operand} region {region} span {index} does not start in the content subspace"
            ),
            CompareError::MalformedSpan {
                operand,
                region,
                index,
                fault,
            } => write!(
                f,
                "compare: {operand} region {region} span {index} is malformed: {fault}"
            ),
            CompareError::TooManyBlocks { operand } => write!(
                f,
                "compare: {operand} resolves past the {}-block operand budget \
                 (MAX_COMPARE_OPERAND_BLOCKS); narrow its spans or split the request",
                crate::MAX_COMPARE_OPERAND_BLOCKS
            ),
            CompareError::TooManyPairs => write!(
                f,
                "compare: the report passes {} correspondences (MAX_COMPARE_PAIRS); \
                 narrow the two regions",
                crate::MAX_COMPARE_PAIRS
            ),
        }
    }
}
impl Error for CompareError {}

impl fmt::Display for FindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindError::DocNotRegistered(d) => {
                write!(f, "find_docs_containing: {d} is not a registered document")
            }
            FindError::MalformedSpan {
                region,
                index,
                fault,
            } => write!(
                f,
                "find_docs_containing: region {region} span {index} is malformed: {fault}"
            ),
            FindError::TooMuchCoverage => write!(
                f,
                "find_docs_containing: the request resolves past the {}-span coverage budget \
                 (MAX_FIND_COVERAGE_SPANS); narrow its spans or split the request",
                crate::MAX_FIND_COVERAGE_SPANS
            ),
        }
    }
}
impl Error for FindError {}