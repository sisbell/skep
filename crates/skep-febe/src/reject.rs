//! Typed rejection (the never-silent contract): [`Rejection`], the flat
//! deduped [`RejectCode`] union, the advisory [`Disposition`] hint and its
//! policy table, and the localized [`FaultSite`] (§5).

use skep_address::Address;
use skep_retrieval::{Operand, SpecFault};

use crate::op::OpKind;
use crate::response::Response;

/// A typed, classified rejection. `code` is authoritative; `disposition` is
/// an advisory Lampson hint (recomputable); `site` localizes span/operand/
/// document faults; `detail` is an optional message (ASN-0134 rejection path,
/// OQ8).
#[derive(Debug)]
pub struct Rejection {
    pub op: OpKind,
    pub code: RejectCode,
    pub disposition: Disposition,
    pub site: Option<FaultSite>,
    pub detail: Option<String>,
}

/// Advisory hint: the client may reissue under `Reorder`/`Retry`; `Halt`
/// means the kernel stopped; anything not explicitly hinted is `Permanent`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disposition {
    Permanent,
    Reorder,
    Retry,
    Halt,
}

/// Where in a multi-part request a fault landed — threaded from M6's
/// variant-carried localization (`RetrieveError::MalformedSpec{index, fault}`,
/// COMPARE's `{operand, region, index}`, and the offending document `Address`
/// of the multi-document `DocNotRegistered(Address)` variants), and — since
/// the ownership ruling (2026-08-16) — from M5's and M7's
/// `NotOwner(Address)`, whose `addr` names the document (or target link)
/// that failed the ω check. Every other M5/M8 variant still lowers with
/// `site = None` (§5; M8's `DocNotRegistered` is fieldless, unlike M6's).
#[derive(Debug, Default)]
pub struct FaultSite {
    /// Which COMPARE spec-set (ρ₁/ρ₂) the fault came from.
    pub operand: Option<Operand>,
    /// The offending region index (COMPARE / FINDDOCSCONTAINING).
    pub region: Option<usize>,
    /// The offending spec/span index.
    pub index: Option<usize>,
    /// The span well-formedness fault.
    pub fault: Option<SpecFault>,
    /// Offending document of the multi-document `DocNotRegistered(Address)`
    /// variants (RetrieveError/DeletionsError/CompareError/FindError).
    pub addr: Option<Address>,
}

/// The deduped union of every store error variant plus M10's own — flat &
/// `Copy`, keyed by the disposition table (§5). Built mechanically: each
/// store error enum lowers to `(RejectCode, Option<FaultSite>)` via the
/// crate-internal `Lower` trait.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RejectCode {
    // ── M10-originated ──
    Unauthenticated,
    Malformed,
    Durability,
    TxnOverBudget,
    Poisoned,
    // ── registration / residence (M3/M5/M7/M8) ──
    HomeNotRegistered,
    DocNotRegistered,
    SourceNotRegistered,
    ParentNotRegistered,
    NotRegistered,
    OriginalNotResident,
    EndpointNotResident,
    // ── M3 namespace / authority ──
    NotOwner,
    NotAnAccount,
    Gate,
    DelegatorUnknown,
    DuplicateId,
    NotAncestor,
    NotAuthorized,
    NotAccountTier,
    NotTopDown,
    NotNextForm,
    NotValid,
    NotNode,
    TooDeep,
    NotDescendantOfBootstrap,
    NotFresh,
    // ── M5 arrangement ──
    BadPosition,
    EmptyContent,
    Content,
    EmptySource,
    BadSpan,
    DanglingSource,
    EmptyResult,
    NotArranged,
    OutOfBounds,
    EmptyWidth,
    BadCutCount,
    NotAscending,
    EmptyContentSubspace,
    NotAPrincipal,
    NodeTierCrossOwner,
    NotHomeLink,
    AlreadySeated,
    NotContentSubspace,
    // ── M7 link ──
    IllFormedSpec,
    EmptyTypeResolution,
    ShapeViolation,
    RetractionClass,
    NonAddressDenotingType,
    BadTarget,
    SelfSupersession,
    IllFormedSuccessor,
    DcViolation,
    // ── M6 content/provenance read (MalformedSpan also covers
    //    RetrieveError::MalformedSpec) ──
    NoSuchSubspace,
    EmptySubspace,
    DepthIncompatible,
    RangeNotPresent,
    MalformedSpan,
    // ── M8 link discovery read ──
    NotALink,
    BadRegion,
}

/// The fixed operator-condition detail a `Gate` rejection carries (§5): M3
/// documents `MintError::Gate` as defensive — it fires only on a corrupted
/// frontier, never on a well-formed request against a healthy store.
const GATE_DETAIL: &str = "inc-gate tripped: corrupted frontier — operator condition";

/// The disposition policy — a single total lookup off the flat code (§5).
/// Returns exactly the explicit `Reorder`/`Retry`/`Halt` cases and defaults
/// everything else to `Permanent` (the catch-all is the DESIGNED shape here:
/// a code absent from the table is `Permanent` by construction).
///
/// Named `Permanent` calls (not left to the catch-all by accident — §5):
/// `NotRegistered` (genesis-immutable registry), `NotFresh` (append-only
/// allocations), `Gate` (store corruption), `TxnOverBudget` (M2's
/// per-transaction byte budget, ruled Permanent 2026-08-21 — no retry
/// shrinks a transaction; the client splits it), and the recovery-steering
/// `NotNextForm` (re-derive via `NextAccountPrefix`, a *different* request).
/// The conservatively-`Permanent` state-dependent codes (`NotArranged`,
/// `OutOfBounds`, `EmptySource`, `EmptyContentSubspace`, `RangeNotPresent`,
/// `EmptySubspace`, `DelegatorUnknown`, `NotAPrincipal`, …) are the
/// documented heuristic split of Open build decision 7.
pub(crate) fn disposition_of(code: RejectCode) -> Disposition {
    match code {
        RejectCode::Poisoned => Disposition::Halt,
        RejectCode::Durability => Disposition::Retry,
        RejectCode::BadTarget
        | RejectCode::DocNotRegistered
        | RejectCode::HomeNotRegistered
        | RejectCode::SourceNotRegistered
        | RejectCode::NotAnAccount
        | RejectCode::OriginalNotResident
        | RejectCode::EndpointNotResident
        | RejectCode::ParentNotRegistered => Disposition::Reorder,
        _ => Disposition::Permanent,
    }
}

impl Rejection {
    /// Build a classified rejection: disposition recomputed from the flat
    /// code; `Gate` is the one code carrying a FIXED M10 detail (it signals
    /// store corruption — an operator condition — never client error; §5).
    pub(crate) fn classified(op: OpKind, code: RejectCode, site: Option<FaultSite>) -> Rejection {
        let detail = matches!(code, RejectCode::Gate).then(|| GATE_DETAIL.to_string());
        Rejection { op, code, disposition: disposition_of(code), site, detail }
    }

    /// Attach a detail message (the `Durability` arm threads the underlying
    /// `io::Error` text so an operator sees the cause behind the `Retry`
    /// hint; §5).
    pub(crate) fn with_detail(mut self, d: String) -> Rejection {
        self.detail = Some(d);
        self
    }
}

/// A bare `Response::Rejected` for `execute`'s steps (b)/(c) (§1/§5).
pub(crate) fn reject(op: OpKind, code: RejectCode) -> Response {
    Response::Rejected(reject1(op, code))
}

/// A bare `Rejection` for dispatch arms (§5).
pub(crate) fn reject1(op: OpKind, code: RejectCode) -> Rejection {
    Rejection::classified(op, code, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §5 disposition table: the explicit Halt/Retry/Reorder rows.
    #[test]
    fn explicit_dispositions() {
        assert_eq!(disposition_of(RejectCode::Poisoned), Disposition::Halt);
        assert_eq!(disposition_of(RejectCode::Durability), Disposition::Retry);
        for code in [
            RejectCode::BadTarget,
            RejectCode::DocNotRegistered,
            RejectCode::HomeNotRegistered,
            RejectCode::SourceNotRegistered,
            RejectCode::NotAnAccount,
            RejectCode::OriginalNotResident,
            RejectCode::EndpointNotResident,
            RejectCode::ParentNotRegistered,
        ] {
            assert_eq!(disposition_of(code), Disposition::Reorder);
        }
    }

    /// §5: the named-`Permanent` codes (invariant-forced or recovery-steering)
    /// and the conservative state-dependent bucket all land `Permanent`.
    #[test]
    fn named_permanent_codes() {
        for code in [
            RejectCode::NotRegistered,
            RejectCode::NotFresh,
            RejectCode::Gate,
            RejectCode::TxnOverBudget,
            RejectCode::NotNextForm,
            RejectCode::NotArranged,
            RejectCode::OutOfBounds,
            RejectCode::EmptySource,
            RejectCode::EmptyContentSubspace,
            RejectCode::RangeNotPresent,
            RejectCode::EmptySubspace,
            RejectCode::DelegatorUnknown,
            RejectCode::NotAPrincipal,
            RejectCode::NotOwner,
            RejectCode::Unauthenticated,
            RejectCode::Malformed,
        ] {
            assert_eq!(disposition_of(code), Disposition::Permanent);
        }
    }

    /// §5: `Gate` carries the fixed operator-condition detail; other codes
    /// carry none unless threaded.
    #[test]
    fn gate_detail_is_fixed_and_exclusive() {
        let g = Rejection::classified(OpKind::CreateNewDocument, RejectCode::Gate, None);
        assert_eq!(g.detail.as_deref(), Some(GATE_DETAIL));
        let other = Rejection::classified(OpKind::CreateNewDocument, RejectCode::NotOwner, None);
        assert!(other.detail.is_none());
    }
}
