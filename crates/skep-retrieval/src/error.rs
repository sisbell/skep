//! §Errors — the typed rejections of M6's seven operations (all surfaced
//! verbatim by M10 — never a silent skip). Variant declaration order matches
//! the interface's, which is also each operation's check order (the "which
//! error wins" contract the conformance tests rely on).
//!
//! Derive policy: all six operation enums derive `Clone + Debug + PartialEq +
//! Eq + Serialize`; the payload-free [`SpanFault`]/[`Operand`] additionally
//! derive `Copy`. `DocNotRegistered` carries the offending document wherever
//! the interface declares a payload (RETRIEVEV/SHOWDELETIONS/COMPARE/
//! FINDDOCSCONTAINING); the interface declares ExtentError's and OriginError's
//! as payload-free — the document is recoverable from the single-document
//! request — and the interface is the verbatim binding.
//!
//! None implements `std::error::Error`, because nothing consumes one as a
//! `dyn Error`: M10 marshals every rejection through `Serialize`, and
//! `Display` carries the human-readable message — naming the offending
//! document, in M1's dotted-decimal form, wherever the variant carries one.

use std::fmt;

use serde::Serialize;
use skep_address::Address;

/// Span well-formedness faults (ASN-0115): the four ways a request span fails
/// the span half of the V-spec gate. `StartTooShallow` is `#start < 2`; a
/// well-formed `#start ≥ 3` span is NOT a fault here — depth-compatibility is
/// consulting-state, not well-formedness (§Conflicts resolved 8).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
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
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
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
    /// The span's start subspace is ∉ {s_C, s_L} — distinct from a real but
    /// empty subspace.
    NoSuchSubspace,
    /// WF_V(iii): a real subspace (s_C or s_L) with no occupied positions.
    EmptySubspace,
    /// WF_V(v): span depth ≠ the subspace common depth `m_S ≡ 2`
    /// (`#start ≥ 3`).
    DepthIncompatible,
    /// WF_V(vi): a depth-2 span naming positions not all currently bound.
    RangeNotPresent,
    /// WF_V(ii/iv): the span fails span well-formedness.
    MalformedSpan(SpanFault),
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
}

/// FINDDOCSCONTAINING rejection (ASN-0124): every named document must be
/// registered and every region span well-formed; a malformed span is a typed
/// rejection, never a silent under-resolution that drops containers
/// (FD-COMPLETE).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum FindError {
    DocNotRegistered(Address),
    MalformedSpan {
        region: usize,
        index: usize,
        fault: SpanFault,
    },
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
impl fmt::Display for ExtentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("doc_vspan/doc_vspanset: doc is not a registered document")
    }
}
impl fmt::Display for OriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OriginError::DocNotRegistered => {
                f.write_str("show_origin_v: doc is not a registered document")
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
            OriginError::MalformedSpan(fault) => {
                write!(f, "show_origin_v: span is malformed: {fault}")
            }
        }
    }
}
impl fmt::Display for DeletionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeletionsError::DocNotRegistered(d) => {
                write!(f, "show_deletions: {d} is not a registered document")
            }
        }
    }
}
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
        }
    }
}
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
        }
    }
}