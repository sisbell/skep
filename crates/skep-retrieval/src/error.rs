//! §Errors — the typed rejections of M6's seven operations (all surfaced
//! verbatim by M10 — never a silent skip). Variant declaration order matches
//! the interface's, which is also each operation's check order (the "which
//! error wins" contract the conformance tests rely on).
//!
//! Derive policy: all six operation enums derive `Clone + PartialEq + Eq +
//! Serialize`; none derives `Debug` (they carry `Address` — see the policy
//! note in `types`). The payload-free [`SpecFault`]/[`Operand`] additionally
//! derive `Copy + Debug`. `DocNotRegistered` carries the offending document
//! wherever the interface declares a payload (RETRIEVEV/SHOWDELETIONS/
//! COMPARE/FINDDOCSCONTAINING); the interface declares ExtentError's and
//! OriginError's as payload-free — the document is recoverable from the
//! single-document request — and the interface is the verbatim binding.

use std::error::Error;
use std::fmt;

use serde::Serialize;
use skep_address::Address;

/// VSpec well-formedness faults (ASN-0115): the four ways a request span
/// fails the `gate_vspec` gate. `StartTooShallow` is `#start < 2`; a
/// well-formed `#start ≥ 3` span is NOT a fault here — depth-compatibility is
/// consulting-state, not well-formedness (§Conflicts resolved 8).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub enum SpecFault {
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
#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum RetrieveError {
    DocNotRegistered(Address),
    MalformedSpec { index: usize, fault: SpecFault },
}

/// RETRIEVEDOCVSPAN / RETRIEVEDOCVSPANSET rejection (ASN-0112/0113 W-pre):
/// unallocated document. Payload-free per the interface (the document is the
/// request's one argument).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum ExtentError {
    DocNotRegistered,
}

/// SHOWORIGIN_V rejection (ASN-0077 WF_V/O13) — reject, never clamp; each
/// inadmissibility carries its own variant so M10/clients can localize the
/// cause ("wrong-depth span" is never conflated with "unbound positions").
#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum OriginError {
    /// WF_V(i): the document is unallocated.
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
    /// WF_V(ii/iv): the span fails VSpec well-formedness.
    MalformedSpan(SpecFault),
}

/// SHOWDELETIONS rejection (ASN-0075): both documents must be registered;
/// carries the offending document (`d_a` is checked first).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum DeletionsError {
    DocNotRegistered(Address),
}

/// COMPARE rejection (ASN-0122): every fault carries an unambiguous
/// `(operand, region, span-index)` — FINDDOCSCONTAINING's `(region, index)`
/// plus the operand tag. Per span, the content-subspace residence check runs
/// BEFORE the well-formedness gate.
#[derive(Clone, PartialEq, Eq, Serialize)]
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
        fault: SpecFault,
    },
}

/// FINDDOCSCONTAINING rejection (ASN-0124): every named document must be
/// registered and every region span well-formed; a malformed span is a typed
/// rejection, never a silent under-resolution that drops containers
/// (FD-COMPLETE).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum FindError {
    DocNotRegistered(Address),
    MalformedSpan {
        region: usize,
        index: usize,
        fault: SpecFault,
    },
}

impl fmt::Display for SpecFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SpecFault::NotOrdinalLevel => {
                "span width does not act at its deepest component (not ordinal-level)"
            }
            SpecFault::NotLevelUniform => "span start and width lengths differ (not level-uniform)",
            SpecFault::StartNotZeroFree => "span start carries a zero component (not zero-free)",
            SpecFault::StartTooShallow => "span start has fewer than 2 components (#start < 2)",
        })
    }
}
impl Error for SpecFault {}

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
            RetrieveError::DocNotRegistered(_) => {
                f.write_str("retrieve_v: a spec's doc is not a registered document")
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
impl Error for OriginError {}

impl fmt::Display for DeletionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("show_deletions: a document is not registered")
    }
}
impl Error for DeletionsError {}

impl fmt::Display for CompareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompareError::DocNotRegistered(_) => {
                f.write_str("compare: a region's doc is not a registered document")
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
impl Error for CompareError {}

impl fmt::Display for FindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindError::DocNotRegistered(_) => {
                f.write_str("find_docs_containing: a region's doc is not a registered document")
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
impl Error for FindError {}
