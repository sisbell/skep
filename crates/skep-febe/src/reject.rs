//! Typed rejection (the never-silent contract): [`Rejection`], the flat
//! deduped [`RejectCode`] union, the advisory [`Disposition`] hint and its
//! policy table, and the localized [`FaultSite`] (§5).

use std::fmt;

use skep_address::Address;
use skep_retrieval::{Operand, SpecFault};

use crate::codec::ParseError;
use crate::op::OpKind;
use crate::response::Response;

/// A typed, classified rejection. `code` is authoritative; `disposition` is
/// an advisory Lampson hint (recomputable); `site` localizes span/operand/
/// document faults; `detail` is an optional message (ASN-0134 rejection path,
/// OQ8).
///
/// For every rejection M10 produces: `disposition == disposition_of(code)`,
/// and `detail` is `code`'s standing explanation — the fixed sentence a code
/// that means the same thing every time it fires carries — unless a call site
/// threaded one of its own. [`Rejection::classified`] applies both policies
/// off the flat code and is the constructor that holds them.
///
/// The fields are public, so that pairing is a property of the rejections M10
/// builds rather than of the type: a caller assembling the struct by hand
/// answers for it. That is why the classifying constructor and
/// [`disposition_of`] are both published — a caller raising one of these codes
/// on its own channel can apply M10's policy instead of transcribing it.
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
    TxnUnencodable,
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
    SlotTooLarge,
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

/// The standing-explanation policy — the second total lookup off the flat
/// code, beside [`disposition_of`] (§5). A code whose meaning is the same
/// sentence every time it fires carries that sentence here rather than at
/// whichever call site happened to raise it; everything else carries no
/// detail unless a call site threads one (`Rejection::with_detail`).
///
/// `Gate` is the one such code today: it signals store corruption — an
/// operator condition — never client error.
fn fixed_detail(code: RejectCode) -> Option<&'static str> {
    match code {
        RejectCode::Gate => Some(GATE_DETAIL),
        _ => None,
    }
}

/// The disposition policy — a single total lookup off the flat code (§5).
/// Returns exactly the explicit `Reorder`/`Retry`/`Halt` cases and defaults
/// everything else to `Permanent` (the catch-all is the DESIGNED shape here:
/// a code absent from the table is `Permanent` by construction).
///
/// Public because the disposition is documented as recomputable, and a hint
/// nobody outside the crate can recompute is one a transport transcribes
/// instead: a caller raising one of these codes on its own channel asks here
/// and cannot drift from the row [`Rejection::classified`] applies.
///
/// Named `Permanent` calls (not left to the catch-all by accident — §5):
/// `NotRegistered` (genesis-immutable registry), `NotFresh` (append-only
/// allocations), `Gate` (store corruption), `TxnOverBudget` (M2's
/// per-transaction byte budget, ruled Permanent 2026-08-21 — no retry
/// shrinks a transaction; the client splits it), `TxnUnencodable` (a record
/// M2's serializer refused — the same request re-presented stages the same
/// record), and the recovery-steering `NotNextForm` (re-derive via
/// `NextAccountPrefix`, a *different* request).
/// The conservatively-`Permanent` state-dependent codes (`NotArranged`,
/// `OutOfBounds`, `EmptySource`, `EmptyContentSubspace`, `RangeNotPresent`,
/// `EmptySubspace`, `DelegatorUnknown`, `NotAPrincipal`, …) are the
/// documented heuristic split of Open build decision 7.
pub fn disposition_of(code: RejectCode) -> Disposition {
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
    /// Build a classified rejection: both per-code policies applied off the
    /// flat code — the disposition from [`disposition_of`], and the standing
    /// explanation the code carries by policy, when it carries one (§5).
    ///
    /// Public for the reason [`disposition_of`] is: a caller that raises one
    /// of M10's codes on its own channel builds it here and gets the whole
    /// classification, rather than transcribing half of it and drifting from
    /// the rows every other rejection of that code is given.
    pub fn classified(kind: OpKind, code: RejectCode, site: Option<FaultSite>) -> Rejection {
        let detail = fixed_detail(code).map(str::to_string);
        Rejection { op: kind, code, disposition: disposition_of(code), site, detail }
    }

    /// The rejection for a frame that never parsed into an [`Op`] — the one
    /// rejection M10 cannot raise for itself, since [`Operation::execute`]
    /// takes an already-parsed [`Request`] and so has no `Op` and no
    /// `OpKind` from `Op::kind()`. The transport's [`Codec`] impl calls this
    /// on its own `parse` failure and marshals the result like any other
    /// response, which is how a malformed frame still gets exactly one
    /// answer (Invariants, never-silent).
    ///
    /// Classification stays M10's: the code is `Malformed` and the
    /// disposition is whatever the table says `Malformed` disposes to, so an
    /// unparseable frame is advised exactly as every other `Malformed` is.
    /// `e.detail` rides through as the message.
    ///
    /// [`Op`]: crate::Op
    /// [`Codec`]: crate::Codec
    /// [`Operation::execute`]: crate::Operation::execute
    /// [`Request`]: crate::Request
    pub fn unparseable(e: ParseError) -> Rejection {
        let r = Rejection::classified(OpKind::Unparseable, RejectCode::Malformed, None);
        match e.detail {
            Some(d) => r.with_detail(d),
            None => r,
        }
    }

    /// Attach a detail message (the `Durability` arm threads the underlying
    /// `io::Error` text so an operator sees the cause behind the `Retry`
    /// hint; §5).
    pub(crate) fn with_detail(mut self, d: String) -> Rejection {
        self.detail = Some(d);
        self
    }
}

/// An operator-facing line: the op that was refused, the authoritative code,
/// the advisory disposition, and the detail when one was threaded.
///
/// The codes render through their own `Debug` spelling, NOT a table of wire
/// strings: the wire vocabulary is the transport's (skepd's `code_name`,
/// pinned against `docs/wire.md`), and a second vocabulary here would be a
/// second thing to keep in step. A caller that needs the wire string reads
/// `code`, which is authoritative.
impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} rejected: {:?} ({:?})", self.op, self.code, self.disposition)?;
        match &self.detail {
            Some(d) => write!(f, ": {d}"),
            None => Ok(()),
        }
    }
}

/// No `source`: the lowering table flattens each upstream error into a
/// [`RejectCode`] and a [`FaultSite`], so a rejection holds a classification
/// rather than the error it came from — there is nothing to return.
impl std::error::Error for Rejection {}

/// A bare `Response::Rejected` for `execute`'s steps (b)/(c) (§1/§5).
pub(crate) fn reject(kind: OpKind, code: RejectCode) -> Response {
    Response::Rejected(rejection(kind, code))
}

/// A bare `Rejection` for dispatch arms (§5).
pub(crate) fn rejection(kind: OpKind, code: RejectCode) -> Rejection {
    Rejection::classified(kind, code, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §5 disposition table: the explicit Halt/Retry/Reorder rows.
    #[test]
    fn the_explicit_rows_advise_halt_retry_and_reorder() {
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
    fn invariant_forced_and_state_dependent_codes_are_permanent() {
        for code in [
            RejectCode::NotRegistered,
            RejectCode::NotFresh,
            RejectCode::Gate,
            RejectCode::TxnOverBudget,
            RejectCode::TxnUnencodable,
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

    /// The parse-failure rejection is classified by the same table as every
    /// other `Malformed`, and carries the codec's cause when it has one.
    #[test]
    fn an_unparseable_frame_is_classified_by_the_same_table() {
        let r = Rejection::unparseable(ParseError { detail: Some("unknown op".into()) });
        assert_eq!(r.op, OpKind::Unparseable);
        assert_eq!(r.code, RejectCode::Malformed);
        assert_eq!(r.disposition, disposition_of(RejectCode::Malformed));
        assert_eq!(r.detail.as_deref(), Some("unknown op"));
        let bare = Rejection::unparseable(ParseError { detail: None });
        assert!(bare.detail.is_none());
    }

    /// Both failure types are std errors: boxable, and rendered with the
    /// op/code/disposition a `{}` log line needs, the detail appended when
    /// one was threaded.
    #[test]
    fn both_failures_are_std_errors() {
        fn boxed(e: impl std::error::Error + 'static) -> Box<dyn std::error::Error> {
            Box::new(e)
        }

        let r = Rejection::classified(OpKind::Insert, RejectCode::Durability, None)
            .with_detail("disk gone".into());
        let line = r.to_string();
        assert!(line.contains("Insert") && line.contains("Durability"));
        assert!(line.contains("Retry"), "the advisory hint belongs in the line: {line}");
        assert!(line.ends_with("disk gone"));
        assert_eq!(boxed(r).to_string(), line);

        let bare = Rejection::classified(OpKind::Insert, RejectCode::NotOwner, None).to_string();
        assert!(bare.contains("NotOwner") && !bare.ends_with(':'));

        let e = ParseError { detail: Some("unknown op".into()) };
        assert!(e.to_string().contains("unknown op"));
        assert_eq!(boxed(e).to_string(), "unparseable frame: unknown op");
        assert_eq!(ParseError { detail: None }.to_string(), "unparseable frame");
    }

    // ────────────── the disposition table over its whole domain ─────────────

    /// The §5 table read off the design rather than off the code: an
    /// EXHAUSTIVE match with no `_` arm, so every code's advice is a
    /// deliberate row here even where the production lookup reaches it
    /// through the designed catch-all.
    ///
    /// A newly added [`RejectCode`] lands in TWO places in this file: here,
    /// and in [`ALL_CODES`].
    fn documented_disposition(c: RejectCode) -> Disposition {
        match c {
            // The kernel stopped.
            RejectCode::Poisoned => Disposition::Halt,
            // The one transient fault: the I/O may succeed next time.
            RejectCode::Durability => Disposition::Retry,
            // Registration/residence: the referent may yet arrive, so a
            // client that raced its own prerequisite may reissue.
            RejectCode::BadTarget
            | RejectCode::DocNotRegistered
            | RejectCode::HomeNotRegistered
            | RejectCode::SourceNotRegistered
            | RejectCode::NotAnAccount
            | RejectCode::OriginalNotResident
            | RejectCode::EndpointNotResident
            | RejectCode::ParentNotRegistered => Disposition::Reorder,
            // Everything else: reissuing the identical request cannot help.
            RejectCode::Unauthenticated
            | RejectCode::Malformed
            | RejectCode::TxnUnencodable
            | RejectCode::TxnOverBudget
            | RejectCode::NotRegistered
            | RejectCode::NotOwner
            | RejectCode::Gate
            | RejectCode::DelegatorUnknown
            | RejectCode::DuplicateId
            | RejectCode::NotAncestor
            | RejectCode::NotAuthorized
            | RejectCode::NotAccountTier
            | RejectCode::NotTopDown
            | RejectCode::NotNextForm
            | RejectCode::NotValid
            | RejectCode::NotNode
            | RejectCode::TooDeep
            | RejectCode::NotDescendantOfBootstrap
            | RejectCode::NotFresh
            | RejectCode::EmptyContent
            | RejectCode::Content
            | RejectCode::EmptySource
            | RejectCode::BadSpan
            | RejectCode::DanglingSource
            | RejectCode::EmptyResult
            | RejectCode::NotArranged
            | RejectCode::OutOfBounds
            | RejectCode::EmptyWidth
            | RejectCode::BadCutCount
            | RejectCode::NotAscending
            | RejectCode::EmptyContentSubspace
            | RejectCode::NotAPrincipal
            | RejectCode::NodeTierCrossOwner
            | RejectCode::NotHomeLink
            | RejectCode::AlreadySeated
            | RejectCode::NotContentSubspace
            | RejectCode::IllFormedSpec
            | RejectCode::SlotTooLarge
            | RejectCode::EmptyTypeResolution
            | RejectCode::ShapeViolation
            | RejectCode::RetractionClass
            | RejectCode::NonAddressDenotingType
            | RejectCode::SelfSupersession
            | RejectCode::IllFormedSuccessor
            | RejectCode::DcViolation
            | RejectCode::NoSuchSubspace
            | RejectCode::EmptySubspace
            | RejectCode::DepthIncompatible
            | RejectCode::RangeNotPresent
            | RejectCode::MalformedSpan
            | RejectCode::NotALink
            | RejectCode::BadRegion => Disposition::Permanent,
        }
    }

    /// Every code, in declaration order — the domain the policy is total
    /// over. A newly added code lands here and in
    /// [`documented_disposition`].
    const ALL_CODES: [RejectCode; 62] = [
        RejectCode::Unauthenticated,
        RejectCode::Malformed,
        RejectCode::Durability,
        RejectCode::TxnUnencodable,
        RejectCode::TxnOverBudget,
        RejectCode::Poisoned,
        RejectCode::HomeNotRegistered,
        RejectCode::DocNotRegistered,
        RejectCode::SourceNotRegistered,
        RejectCode::ParentNotRegistered,
        RejectCode::NotRegistered,
        RejectCode::OriginalNotResident,
        RejectCode::EndpointNotResident,
        RejectCode::NotOwner,
        RejectCode::NotAnAccount,
        RejectCode::Gate,
        RejectCode::DelegatorUnknown,
        RejectCode::DuplicateId,
        RejectCode::NotAncestor,
        RejectCode::NotAuthorized,
        RejectCode::NotAccountTier,
        RejectCode::NotTopDown,
        RejectCode::NotNextForm,
        RejectCode::NotValid,
        RejectCode::NotNode,
        RejectCode::TooDeep,
        RejectCode::NotDescendantOfBootstrap,
        RejectCode::NotFresh,
        RejectCode::EmptyContent,
        RejectCode::Content,
        RejectCode::EmptySource,
        RejectCode::BadSpan,
        RejectCode::DanglingSource,
        RejectCode::EmptyResult,
        RejectCode::NotArranged,
        RejectCode::OutOfBounds,
        RejectCode::EmptyWidth,
        RejectCode::BadCutCount,
        RejectCode::NotAscending,
        RejectCode::EmptyContentSubspace,
        RejectCode::NotAPrincipal,
        RejectCode::NodeTierCrossOwner,
        RejectCode::NotHomeLink,
        RejectCode::AlreadySeated,
        RejectCode::NotContentSubspace,
        RejectCode::IllFormedSpec,
        RejectCode::SlotTooLarge,
        RejectCode::EmptyTypeResolution,
        RejectCode::ShapeViolation,
        RejectCode::RetractionClass,
        RejectCode::NonAddressDenotingType,
        RejectCode::BadTarget,
        RejectCode::SelfSupersession,
        RejectCode::IllFormedSuccessor,
        RejectCode::DcViolation,
        RejectCode::NoSuchSubspace,
        RejectCode::EmptySubspace,
        RejectCode::DepthIncompatible,
        RejectCode::RangeNotPresent,
        RejectCode::MalformedSpan,
        RejectCode::NotALink,
        RejectCode::BadRegion,
    ];

    /// §5: the policy is a TOTAL function off the flat code, and the advice
    /// it gives for each of the 62 codes is the advice the design's table
    /// documents — not merely the advice the catch-all happens to produce.
    #[test]
    fn the_disposition_table_deviates_only_where_documented() {
        for code in ALL_CODES {
            assert_eq!(
                disposition_of(code),
                documented_disposition(code),
                "{code:?} is advised against the design's §5 table"
            );
        }
    }

    /// [`ALL_CODES`] is the domain the law above quantifies over, so it must
    /// hold every code exactly once.
    #[test]
    fn all_codes_lists_each_code_once() {
        for (i, a) in ALL_CODES.iter().enumerate() {
            for b in &ALL_CODES[i + 1..] {
                assert_ne!(a, b, "{a:?} is listed twice");
            }
        }
    }
}
