//! The mechanical error lowering (§5): each store error enum implements
//! [`Lower`] — `self → (RejectCode, Option<FaultSite>)` — under the
//! nested-error rule: flat variants map to the same-named [`RejectCode`]
//! leaf; wrapper variants (`Mint`, `Seat`, `Content`) recurse into the leaf
//! enum's own impl. Neither converter ever returns `Ok` — every upstream
//! failure becomes a [`Rejection`].
//!
//! The ownership ruling (2026-08-16): M5's and M7's `NotOwner(Address)`
//! variants thread the failing document (or target link) into
//! `FaultSite::addr` — the same address-localization shape M6's
//! `DocNotRegistered(Address)` established.

use skep_arrangement::{CopyError, DeleteError, InsertError, RearrangeError, SeatError, VersionError};
use skep_content::ContentError;
use skep_discovery::QueryError;
use skep_kernel::TxnError;
use skep_links::{AssertSupError, EditLinkError, EmitError, MakeLinkError, NullifyError};
use skep_namespace::{CreateDocumentError, DelegateError, MintError, NodeError};
use skep_retrieval::{CompareError, DeletionsError, ExtentError, FindError, OriginError, RetrieveError};

use crate::op::OpKind;
use crate::reject::{FaultSite, RejectCode, Rejection};

/// One impl per store error enum (mechanical; §5).
pub(crate) trait Lower {
    fn lower(self) -> (RejectCode, Option<FaultSite>);
}

/// The `NotOwner(Address)` lowering, shared by every ω-gated write enum
/// (ownership ruling, 2026-08-16): the failing address rides `site.addr`.
fn not_owner(a: skep_address::Address) -> (RejectCode, Option<FaultSite>) {
    (RejectCode::NotOwner, Some(FaultSite { addr: Some(a), ..FaultSite::default() }))
}

/// Lower a read error into a classified [`Rejection`] (§5).
pub(crate) fn lower_read<E: Lower>(kind: OpKind, e: E) -> Rejection {
    let (c, s) = e.lower();
    Rejection::classified(kind, c, s)
}

/// Lower a write path's `TxnError` into a classified [`Rejection`] (§5): the
/// store's own typed refusal through its [`Lower`] impl, and M2's four
/// transaction-level outcomes into M10's own codes.
///
/// Each of those four says something different about reissuing, and says it
/// in the disposition, with the cause threaded where an operator needs it.
/// `Durability` is the one `Retry` — the I/O text rides along, so the hint
/// has a reason attached. The two encoding refusals are both `Permanent`,
/// and each carries its own code because they ask different things of an
/// operator: `TxnUnencodable` names records M2's serializer refused (the
/// records are staged by the owning store, so the same request re-presented
/// stages the same record — nothing the client can reframe), while
/// `TxnOverBudget` names records that all encode but overrun the journal's
/// per-transaction budget, and carries the remedy — split the request.
/// `Poisoned` is `Halt`.
pub(crate) fn lower_txn<E: Lower>(kind: OpKind, e: TxnError<E>) -> Rejection {
    match e {
        TxnError::Rejected(inner) => {
            let (c, s) = inner.lower();
            Rejection::classified(kind, c, s)
        }
        TxnError::Durability(io) => {
            Rejection::classified(kind, RejectCode::Durability, None).with_detail(io.to_string())
        }
        TxnError::Unencodable(cause) => {
            Rejection::classified(kind, RejectCode::TxnUnencodable, None)
                .with_detail(cause.to_string())
        }
        TxnError::OverBudget { bytes } => {
            Rejection::classified(kind, RejectCode::TxnOverBudget, None).with_detail(format!(
                "transaction encodes to {bytes} bytes, over the journal's \
                 per-transaction budget; split it"
            ))
        }
        TxnError::Poisoned => Rejection::classified(kind, RejectCode::Poisoned, None),
    }
}

// ───────────────────────────── M3 (namespace) ─────────────────────────────

impl Lower for MintError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let code = match self {
            MintError::HomeNotRegistered => RejectCode::HomeNotRegistered,
            MintError::SourceNotRegistered => RejectCode::SourceNotRegistered,
            MintError::NotAnAccount => RejectCode::NotAnAccount,
            // The inner GateViolation is a fieldless M1 struct — nothing to
            // thread; the Gate operator-condition detail is M10's own fixed
            // string, attached in Rejection::classified (§5).
            MintError::Gate(_) => RejectCode::Gate,
        };
        (code, None)
    }
}

impl Lower for CreateDocumentError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            CreateDocumentError::NotOwner => (RejectCode::NotOwner, None),
            CreateDocumentError::Mint(m) => m.lower(),
        }
    }
}

impl Lower for DelegateError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let code = match self {
            DelegateError::DelegatorUnknown => RejectCode::DelegatorUnknown,
            DelegateError::DuplicateId => RejectCode::DuplicateId,
            DelegateError::NotAncestor => RejectCode::NotAncestor,
            DelegateError::NotAuthorized => RejectCode::NotAuthorized,
            DelegateError::NotAccountTier => RejectCode::NotAccountTier,
            DelegateError::NotTopDown => RejectCode::NotTopDown,
            DelegateError::NotFresh => RejectCode::NotFresh,
            DelegateError::NotNextForm => RejectCode::NotNextForm,
            DelegateError::NotValid => RejectCode::NotValid,
            DelegateError::ParentNotRegistered => RejectCode::ParentNotRegistered,
        };
        (code, None)
    }
}

impl Lower for NodeError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let code = match self {
            NodeError::NotValid => RejectCode::NotValid,
            NodeError::NotNode => RejectCode::NotNode,
            NodeError::TooDeep => RejectCode::TooDeep,
            NodeError::NotFresh => RejectCode::NotFresh,
            NodeError::NotDescendantOfBootstrap => RejectCode::NotDescendantOfBootstrap,
        };
        (code, None)
    }
}

// ──────────────────────── M4 (content — type-only edge) ───────────────────

impl Lower for ContentError {
    /// The flagged wholesale collapse (§5, Open build decision 8): the
    /// `M10 → M4` edge is type-only, so M4's error structure is out of scope
    /// and every `ContentError` lowers to the single `Content` code
    /// (disposition `Permanent` — a transient content fault is thereby
    /// misclassified, documented, to revisit if the M4 edge is ratified).
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        (RejectCode::Content, None)
    }
}

// ──────────────────────────── M5 (arrangement) ─────────────────────────────

impl Lower for SeatError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let code = match self {
            SeatError::NotHomeLink => RejectCode::NotHomeLink,
            SeatError::AlreadySeated => RejectCode::AlreadySeated,
        };
        (code, None)
    }
}

impl Lower for InsertError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            InsertError::DocNotRegistered => (RejectCode::DocNotRegistered, None),
            InsertError::NotOwner(a) => not_owner(a),
            InsertError::NotContentSubspace => (RejectCode::NotContentSubspace, None),
            InsertError::OutOfBounds => (RejectCode::OutOfBounds, None),
            InsertError::EmptyContent => (RejectCode::EmptyContent, None),
            InsertError::Mint(m) => m.lower(),
            InsertError::Content(c) => c.lower(),
        }
    }
}

impl Lower for CopyError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            CopyError::DocNotRegistered => (RejectCode::DocNotRegistered, None),
            CopyError::NotOwner(a) => not_owner(a),
            CopyError::NotContentSubspace => (RejectCode::NotContentSubspace, None),
            CopyError::OutOfBounds => (RejectCode::OutOfBounds, None),
            CopyError::SourceNotRegistered => (RejectCode::SourceNotRegistered, None),
            CopyError::EmptySource => (RejectCode::EmptySource, None),
            CopyError::BadSpan => (RejectCode::BadSpan, None),
            // As-built M5 splits the source-residence guard into its own
            // variant; the design's RejectCode union carries no same-named
            // leaf, so it lowers to the shared NotContentSubspace (surfaced
            // in the build report as upstream drift).
            CopyError::SourceNotContentSubspace => (RejectCode::NotContentSubspace, None),
            CopyError::DanglingSource => (RejectCode::DanglingSource, None),
            CopyError::EmptyResult => (RejectCode::EmptyResult, None),
        }
    }
}

impl Lower for DeleteError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            DeleteError::DocNotRegistered => (RejectCode::DocNotRegistered, None),
            DeleteError::NotOwner(a) => not_owner(a),
            DeleteError::NotContentSubspace => (RejectCode::NotContentSubspace, None),
            DeleteError::NotArranged => (RejectCode::NotArranged, None),
            DeleteError::OutOfBounds => (RejectCode::OutOfBounds, None),
            DeleteError::EmptyWidth => (RejectCode::EmptyWidth, None),
        }
    }
}

impl Lower for RearrangeError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            RearrangeError::DocNotRegistered => (RejectCode::DocNotRegistered, None),
            RearrangeError::NotOwner(a) => not_owner(a),
            RearrangeError::BadCutCount => (RejectCode::BadCutCount, None),
            RearrangeError::NotAscending => (RejectCode::NotAscending, None),
            RearrangeError::NotContentSubspace => (RejectCode::NotContentSubspace, None),
            RearrangeError::OutOfBounds => (RejectCode::OutOfBounds, None),
            RearrangeError::EmptyContentSubspace => (RejectCode::EmptyContentSubspace, None),
        }
    }
}

impl Lower for VersionError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            VersionError::SourceNotRegistered => (RejectCode::SourceNotRegistered, None),
            VersionError::NotAPrincipal => (RejectCode::NotAPrincipal, None),
            VersionError::NodeTierCrossOwner => (RejectCode::NodeTierCrossOwner, None),
            VersionError::Mint(m) => m.lower(),
        }
    }
}

// ─────────────────────────────── M7 (links) ────────────────────────────────

impl Lower for MakeLinkError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            MakeLinkError::HomeNotRegistered => (RejectCode::HomeNotRegistered, None),
            MakeLinkError::NotOwner(a) => not_owner(a),
            MakeLinkError::IllFormedSpec => (RejectCode::IllFormedSpec, None),
            // Its own leaf rather than a ride on `IllFormedSpec`: the spec is
            // well formed and the slot is too big, and the two ask different
            // things of the client — fix the spec, versus narrow the span.
            // Permanent by the catch-all is right, for the reason
            // `TxnOverBudget` is: no retry shrinks the slot.
            MakeLinkError::SlotTooLarge => (RejectCode::SlotTooLarge, None),
            MakeLinkError::EmptyTypeResolution => (RejectCode::EmptyTypeResolution, None),
            MakeLinkError::RetractionClass => (RejectCode::RetractionClass, None),
            // The `[K_sup]` sole-writer fence, lowering as EmitError's does:
            // the design's RejectCode union has no same-named leaf, so it
            // rides DcViolation — the claim-schema discipline editlink's DC
            // guard names. Permanent is right: reissuing identically cannot
            // succeed — use AssertSup/EditLink.
            MakeLinkError::SupersessionClass => (RejectCode::DcViolation, None),
            MakeLinkError::Mint(m) => m.lower(),
            MakeLinkError::Seat(s) => s.lower(),
        }
    }
}

impl Lower for EmitError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            EmitError::HomeNotRegistered => (RejectCode::HomeNotRegistered, None),
            EmitError::NotOwner(a) => not_owner(a),
            EmitError::NotRegistered => (RejectCode::NotRegistered, None),
            EmitError::ShapeViolation => (RejectCode::ShapeViolation, None),
            EmitError::RetractionClass => (RejectCode::RetractionClass, None),
            // As-built M7 carries the supersession-schema fence
            // (`[K_sup]` claims write only via assert_sup/editlink) as its
            // own variant; the design's RejectCode union has no same-named
            // leaf, so it lowers to DcViolation — the same claim-schema
            // discipline editlink's DC guard names (surfaced in the build
            // report as upstream drift). Permanent is right: reissuing
            // identically cannot succeed — use AssertSup/EditLink.
            EmitError::SupersessionClass => (RejectCode::DcViolation, None),
            EmitError::NonAddressDenotingType => (RejectCode::NonAddressDenotingType, None),
            // The same per-slot span budget MAKELINK's slots carry, on `to`
            // — so the same leaf, and permanent for the same reason: no
            // retry shrinks the list.
            EmitError::SlotTooLarge => (RejectCode::SlotTooLarge, None),
            EmitError::Mint(m) => m.lower(),
        }
    }
}

impl Lower for NullifyError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            NullifyError::HomeNotRegistered => (RejectCode::HomeNotRegistered, None),
            // Carries whichever ω check failed — the home or the target link.
            NullifyError::NotOwner(a) => not_owner(a),
            NullifyError::BadTarget => (RejectCode::BadTarget, None),
            NullifyError::Mint(m) => m.lower(),
        }
    }
}

impl Lower for AssertSupError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            AssertSupError::HomeNotRegistered => (RejectCode::HomeNotRegistered, None),
            AssertSupError::NotOwner(a) => not_owner(a),
            AssertSupError::EndpointNotResident => (RejectCode::EndpointNotResident, None),
            AssertSupError::SelfSupersession => (RejectCode::SelfSupersession, None),
            AssertSupError::Mint(m) => m.lower(),
        }
    }
}

impl Lower for EditLinkError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            EditLinkError::OriginalNotResident => (RejectCode::OriginalNotResident, None),
            EditLinkError::HomeNotRegistered => (RejectCode::HomeNotRegistered, None),
            // Carries whichever home failed — d_s or d_a.
            EditLinkError::NotOwner(a) => not_owner(a),
            // The successor's slots are resolve-built here in M10, so this is
            // the same budget and the same leaf MAKELINK's slots take.
            EditLinkError::SlotTooLarge => (RejectCode::SlotTooLarge, None),
            EditLinkError::IllFormedSuccessor => (RejectCode::IllFormedSuccessor, None),
            EditLinkError::DcViolation => (RejectCode::DcViolation, None),
            EditLinkError::Mint(m) => m.lower(),
        }
    }
}

// ─────────────────── M6 (retrieval — the sole FaultSite producer) ──────────

impl Lower for RetrieveError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            RetrieveError::DocNotRegistered(a) => (
                RejectCode::DocNotRegistered,
                Some(FaultSite { addr: Some(a), ..FaultSite::default() }),
            ),
            // MalformedSpan covers RetrieveError::MalformedSpec (§5).
            RetrieveError::MalformedSpec { index, fault } => (
                RejectCode::MalformedSpan,
                Some(FaultSite { index: Some(index), fault: Some(fault), ..FaultSite::default() }),
            ),
        }
    }
}

impl Lower for ExtentError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            // Payload-free upstream (the document is the request's one
            // argument), so there is no address to thread.
            ExtentError::DocNotRegistered => (RejectCode::DocNotRegistered, None),
        }
    }
}

impl Lower for OriginError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            OriginError::DocNotRegistered => (RejectCode::DocNotRegistered, None),
            OriginError::NoSuchSubspace => (RejectCode::NoSuchSubspace, None),
            OriginError::EmptySubspace => (RejectCode::EmptySubspace, None),
            OriginError::DepthIncompatible => (RejectCode::DepthIncompatible, None),
            OriginError::RangeNotPresent => (RejectCode::RangeNotPresent, None),
            OriginError::MalformedSpan(fault) => (
                RejectCode::MalformedSpan,
                Some(FaultSite { fault: Some(fault), ..FaultSite::default() }),
            ),
        }
    }
}

impl Lower for DeletionsError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            DeletionsError::DocNotRegistered(a) => (
                RejectCode::DocNotRegistered,
                Some(FaultSite { addr: Some(a), ..FaultSite::default() }),
            ),
        }
    }
}

impl Lower for CompareError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            CompareError::DocNotRegistered(a) => (
                RejectCode::DocNotRegistered,
                Some(FaultSite { addr: Some(a), ..FaultSite::default() }),
            ),
            CompareError::NotContentSubspace { operand, region, index } => (
                RejectCode::NotContentSubspace,
                Some(FaultSite {
                    operand: Some(operand),
                    region: Some(region),
                    index: Some(index),
                    ..FaultSite::default()
                }),
            ),
            CompareError::MalformedSpan { operand, region, index, fault } => (
                RejectCode::MalformedSpan,
                Some(FaultSite {
                    operand: Some(operand),
                    region: Some(region),
                    index: Some(index),
                    fault: Some(fault),
                    ..FaultSite::default()
                }),
            ),
        }
    }
}

impl Lower for FindError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            FindError::DocNotRegistered(a) => (
                RejectCode::DocNotRegistered,
                Some(FaultSite { addr: Some(a), ..FaultSite::default() }),
            ),
            FindError::MalformedSpan { region, index, fault } => (
                RejectCode::MalformedSpan,
                Some(FaultSite {
                    region: Some(region),
                    index: Some(index),
                    fault: Some(fault),
                    ..FaultSite::default()
                }),
            ),
        }
    }
}

// ────────────────────────────── M8 (discovery) ─────────────────────────────

impl Lower for QueryError {
    /// Every M8 variant is fieldless (its `DocNotRegistered`, unlike M6's,
    /// carries no address), so every lowering fills only `code` (§5).
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let code = match self {
            QueryError::DocNotRegistered => RejectCode::DocNotRegistered,
            QueryError::NotALink => RejectCode::NotALink,
            QueryError::BadRegion => RejectCode::BadRegion,
            QueryError::NotContentSubspace => RejectCode::NotContentSubspace,
            QueryError::EmptyWidth => RejectCode::EmptyWidth,
            QueryError::OutOfBounds => RejectCode::OutOfBounds,
        };
        (code, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reject::Disposition;
    use skep_address::{validate, Nat, Tumbler};
    use skep_retrieval::{Operand, SpecFault};

    fn addr() -> skep_address::Address {
        validate(Tumbler::new([1u32, 0, 1, 0, 1].map(Nat::from)).expect("nonempty"))
            .unwrap_or_else(|_| panic!("T4-valid"))
    }

    /// §5 nested-error rule: wrappers recurse into the leaf's own impl.
    #[test]
    fn wrappers_recurse() {
        let (c, s) = CreateDocumentError::Mint(MintError::NotAnAccount).lower();
        assert_eq!(c, RejectCode::NotAnAccount);
        assert!(s.is_none());
        let (c, _) = InsertError::Mint(MintError::HomeNotRegistered).lower();
        assert_eq!(c, RejectCode::HomeNotRegistered);
        let (c, _) = MakeLinkError::Seat(SeatError::AlreadySeated).lower();
        assert_eq!(c, RejectCode::AlreadySeated);
    }

    /// §5: `Content(ContentError)` collapses wholesale to `Content`
    /// (Permanent), discarding M4's structure — the flagged best-effort.
    #[test]
    fn content_error_collapses_wholesale() {
        let e = InsertError::Content(ContentError::AlreadyPresent(
            Tumbler::new([1u32].map(Nat::from)).expect("nonempty"),
        ));
        let (c, s) = e.lower();
        assert_eq!(c, RejectCode::Content);
        assert!(s.is_none());
        assert_eq!(crate::reject::disposition_of(c), Disposition::Permanent);
    }

    /// §5: M6 is the sole producer of a populated FaultSite; the
    /// variant-carried localization survives into it.
    #[test]
    fn m6_faults_thread_their_site() {
        let (c, s) = RetrieveError::MalformedSpec { index: 3, fault: SpecFault::StartTooShallow }.lower();
        assert_eq!(c, RejectCode::MalformedSpan);
        let s = s.expect("localized");
        assert_eq!(s.index, Some(3));
        assert!(matches!(s.fault, Some(SpecFault::StartTooShallow)));
        assert!(s.operand.is_none() && s.region.is_none() && s.addr.is_none());

        let (c, s) = CompareError::MalformedSpan {
            operand: Operand::Second,
            region: 1,
            index: 2,
            fault: SpecFault::NotLevelUniform,
        }
        .lower();
        assert_eq!(c, RejectCode::MalformedSpan);
        let s = s.expect("localized");
        assert!(matches!(s.operand, Some(Operand::Second)));
        assert_eq!(s.region, Some(1));
        assert_eq!(s.index, Some(2));

        let (c, s) = FindError::DocNotRegistered(addr()).lower();
        assert_eq!(c, RejectCode::DocNotRegistered);
        assert_eq!(s.expect("localized").addr, Some(addr()));
    }

    /// Ownership ruling (2026-08-16): every gated write enum's
    /// `NotOwner(Address)` lowers to the `NotOwner` code with the failing
    /// address threaded into `site.addr`.
    #[test]
    fn not_owner_threads_the_failing_address() {
        for (c, s) in [
            InsertError::NotOwner(addr()).lower(),
            CopyError::NotOwner(addr()).lower(),
            DeleteError::NotOwner(addr()).lower(),
            RearrangeError::NotOwner(addr()).lower(),
            MakeLinkError::NotOwner(addr()).lower(),
            EmitError::NotOwner(addr()).lower(),
            NullifyError::NotOwner(addr()).lower(),
            AssertSupError::NotOwner(addr()).lower(),
            EditLinkError::NotOwner(addr()).lower(),
        ] {
            assert_eq!(c, RejectCode::NotOwner);
            assert_eq!(s.expect("localized").addr, Some(addr()));
            assert_eq!(crate::reject::disposition_of(c), Disposition::Permanent);
        }
    }

    /// §5: M2's transaction-level outcomes take M10's own codes, each with
    /// the disposition its remedy calls for, and a typed `Rejected(E)`
    /// lowers verbatim through the store's own impl.
    #[test]
    fn txn_errors_carry_their_remedy() {
        let rej = lower_txn::<InsertError>(
            OpKind::Insert,
            TxnError::Durability(std::io::Error::other("disk gone")),
        );
        assert_eq!(rej.code, RejectCode::Durability);
        assert_eq!(rej.disposition, Disposition::Retry);
        assert!(rej.detail.as_deref().is_some_and(|d| d.contains("disk gone")));

        // Unencodable: its own code, never Malformed — the frame the client
        // presented parsed, and the records M2 refused are the store's.
        let rej = lower_txn::<InsertError>(
            OpKind::Insert,
            TxnError::Unencodable("record too large".into()),
        );
        assert_eq!(rej.code, RejectCode::TxnUnencodable);
        assert_eq!(
            rej.disposition,
            Disposition::Permanent,
            "a record M2 cannot journal must never be advertised as retryable"
        );
        assert!(rej.detail.as_deref().is_some_and(|d| d.contains("record too large")));

        // OverBudget: its own code (the records all encode — only the
        // transaction is too big), Permanent per the 2026-08-21 ruling, with
        // the accounted size and the split remedy threaded for the operator.
        let rej = lower_txn::<InsertError>(OpKind::Insert, TxnError::OverBudget { bytes: 99 });
        assert_eq!(rej.code, RejectCode::TxnOverBudget);
        assert_eq!(rej.disposition, Disposition::Permanent);
        assert!(rej.detail.as_deref().is_some_and(|d| d.contains("99") && d.contains("split")));

        let rej = lower_txn::<InsertError>(OpKind::Insert, TxnError::Poisoned);
        assert_eq!(rej.code, RejectCode::Poisoned);
        assert_eq!(rej.disposition, Disposition::Halt);

        let rej = lower_txn(OpKind::Insert, TxnError::Rejected(InsertError::EmptyContent));
        assert_eq!(rej.code, RejectCode::EmptyContent);
        assert_eq!(rej.disposition, Disposition::Permanent);
    }

    /// §5: M8's fieldless `DocNotRegistered` lowers with no site — unlike
    /// M6's — and the as-built fence/split variants map to their documented
    /// nearest leaves.
    #[test]
    fn m8_and_as_built_variants() {
        let (c, s) = QueryError::DocNotRegistered.lower();
        assert_eq!(c, RejectCode::DocNotRegistered);
        assert!(s.is_none());
        let (c, _) = EmitError::SupersessionClass.lower();
        assert_eq!(c, RejectCode::DcViolation);
        let (c, _) = CopyError::SourceNotContentSubspace.lower();
        assert_eq!(c, RejectCode::NotContentSubspace);
    }

    // ─────────────── the nested-error rule as a law, not examples ───────────

    /// The variant's own name, as its `Debug` spells it, up to whatever
    /// punctuation its payload starts with.
    fn variant_name<E: std::fmt::Debug>(e: &E) -> String {
        let rendered = format!("{e:?}");
        rendered.split(['(', ' ', '{']).next().unwrap_or_default().to_string()
    }

    /// The §5 rule for one flat variant: it lowers to the SAME-NAMED
    /// [`RejectCode`] leaf. `name` is spelled by the caller because M6's
    /// enums withhold `Debug` by upstream derive policy (they carry
    /// `Address`); everywhere else [`same_name`] reads it off the variant.
    fn same_named<E: Lower>(name: &str, e: E) {
        let (code, _) = e.lower();
        assert_eq!(
            name,
            format!("{code:?}"),
            "a flat variant lowers to the same-named leaf (§5); {name} lowered to {code:?}"
        );
    }

    fn same_name<E: Lower + std::fmt::Debug>(e: E) {
        let name = variant_name(&e);
        same_named(&name, e);
    }

    /// The exceptions, and the whole list of them: a flat variant whose
    /// documented leaf is NOT its own name. Asserting the names differ is
    /// what keeps this a list of deviations — a variant that stops deviating
    /// belongs with the mechanical ones above.
    fn deviates<E: Lower>(name: &str, e: E, expected: RejectCode) {
        let (code, _) = e.lower();
        assert_eq!(code, expected, "{name} lowers to the documented near leaf");
        assert_ne!(
            name,
            format!("{code:?}"),
            "{name} no longer deviates — move it to the same-named list"
        );
    }

    /// §5's mechanical claim over the whole table rather than a sample of it:
    /// EVERY flat variant of EVERY upstream error enum lowers to the leaf
    /// with its own name, and the five documented deviations are the only
    /// ones. Wrapper variants belong to `wrappers_recurse`.
    #[test]
    fn flat_variants_lower_to_the_same_named_code() {
        // ── M3 (namespace) ──
        same_name(MintError::HomeNotRegistered);
        same_name(MintError::SourceNotRegistered);
        same_name(MintError::NotAnAccount);
        same_name(MintError::Gate(skep_address::GateViolation));
        same_name(CreateDocumentError::NotOwner);
        same_name(DelegateError::NotValid);
        same_name(DelegateError::NotAccountTier);
        same_name(DelegateError::DelegatorUnknown);
        same_name(DelegateError::NotAncestor);
        same_name(DelegateError::NotAuthorized);
        same_name(DelegateError::NotTopDown);
        same_name(DelegateError::NotFresh);
        same_name(DelegateError::DuplicateId);
        same_name(DelegateError::ParentNotRegistered);
        same_name(DelegateError::NotNextForm);
        same_name(NodeError::NotValid);
        same_name(NodeError::NotNode);
        same_name(NodeError::TooDeep);
        same_name(NodeError::NotFresh);
        same_name(NodeError::NotDescendantOfBootstrap);

        // ── M4 (content) — the wholesale collapse, Open build decision 8.
        //    M4's variant set is feature-dependent and `#[non_exhaustive]`,
        //    which the collapse makes moot: whatever the variant, the code is
        //    `Content`.
        deviates(
            "AlreadyPresent",
            ContentError::AlreadyPresent(Tumbler::new([1u32].map(Nat::from)).expect("nonempty")),
            RejectCode::Content,
        );

        // ── M5 (arrangement) ──
        same_name(SeatError::NotHomeLink);
        same_name(SeatError::AlreadySeated);
        same_name(InsertError::DocNotRegistered);
        same_name(InsertError::NotOwner(addr()));
        same_name(InsertError::NotContentSubspace);
        same_name(InsertError::OutOfBounds);
        same_name(InsertError::EmptyContent);
        same_name(CopyError::DocNotRegistered);
        same_name(CopyError::NotOwner(addr()));
        same_name(CopyError::NotContentSubspace);
        same_name(CopyError::OutOfBounds);
        same_name(CopyError::SourceNotRegistered);
        same_name(CopyError::EmptySource);
        same_name(CopyError::BadSpan);
        same_name(CopyError::DanglingSource);
        same_name(CopyError::EmptyResult);
        // As-built M5 split the source-residence guard out; the design's
        // union carries no same-named leaf.
        deviates(
            "SourceNotContentSubspace",
            CopyError::SourceNotContentSubspace,
            RejectCode::NotContentSubspace,
        );
        same_name(DeleteError::DocNotRegistered);
        same_name(DeleteError::NotOwner(addr()));
        same_name(DeleteError::NotContentSubspace);
        same_name(DeleteError::NotArranged);
        same_name(DeleteError::OutOfBounds);
        same_name(DeleteError::EmptyWidth);
        same_name(RearrangeError::DocNotRegistered);
        same_name(RearrangeError::NotOwner(addr()));
        same_name(RearrangeError::BadCutCount);
        same_name(RearrangeError::NotAscending);
        same_name(RearrangeError::NotContentSubspace);
        same_name(RearrangeError::OutOfBounds);
        same_name(RearrangeError::EmptyContentSubspace);
        same_name(VersionError::SourceNotRegistered);
        same_name(VersionError::NotAPrincipal);
        same_name(VersionError::NodeTierCrossOwner);

        // ── M7 (links) ──
        same_name(MakeLinkError::HomeNotRegistered);
        same_name(MakeLinkError::NotOwner(addr()));
        same_name(MakeLinkError::IllFormedSpec);
        same_name(MakeLinkError::SlotTooLarge);
        same_name(MakeLinkError::EmptyTypeResolution);
        same_name(MakeLinkError::RetractionClass);
        // The `[K_sup]` sole-writer fence, on both enums that carry it.
        deviates(
            "SupersessionClass",
            MakeLinkError::SupersessionClass,
            RejectCode::DcViolation,
        );
        same_name(EmitError::HomeNotRegistered);
        same_name(EmitError::NotOwner(addr()));
        same_name(EmitError::NotRegistered);
        same_name(EmitError::RetractionClass);
        same_name(EmitError::ShapeViolation);
        same_name(EmitError::NonAddressDenotingType);
        same_name(EmitError::SlotTooLarge);
        deviates("SupersessionClass", EmitError::SupersessionClass, RejectCode::DcViolation);
        same_name(NullifyError::HomeNotRegistered);
        same_name(NullifyError::NotOwner(addr()));
        same_name(NullifyError::BadTarget);
        same_name(AssertSupError::HomeNotRegistered);
        same_name(AssertSupError::NotOwner(addr()));
        same_name(AssertSupError::EndpointNotResident);
        same_name(AssertSupError::SelfSupersession);
        same_name(EditLinkError::OriginalNotResident);
        same_name(EditLinkError::HomeNotRegistered);
        same_name(EditLinkError::NotOwner(addr()));
        same_name(EditLinkError::SlotTooLarge);
        same_name(EditLinkError::IllFormedSuccessor);
        same_name(EditLinkError::DcViolation);

        // ── M6 (retrieval) — names spelled: these enums withhold `Debug` ──
        same_named("DocNotRegistered", RetrieveError::DocNotRegistered(addr()));
        // `MalformedSpan` covers RETRIEVEV's differently-named fault (§5).
        deviates(
            "MalformedSpec",
            RetrieveError::MalformedSpec { index: 0, fault: SpecFault::NotOrdinalLevel },
            RejectCode::MalformedSpan,
        );
        same_named("DocNotRegistered", ExtentError::DocNotRegistered);
        same_named("DocNotRegistered", OriginError::DocNotRegistered);
        same_named("NoSuchSubspace", OriginError::NoSuchSubspace);
        same_named("EmptySubspace", OriginError::EmptySubspace);
        same_named("DepthIncompatible", OriginError::DepthIncompatible);
        same_named("RangeNotPresent", OriginError::RangeNotPresent);
        same_named("MalformedSpan", OriginError::MalformedSpan(SpecFault::NotLevelUniform));
        same_named("DocNotRegistered", DeletionsError::DocNotRegistered(addr()));
        same_named("DocNotRegistered", CompareError::DocNotRegistered(addr()));
        same_named(
            "NotContentSubspace",
            CompareError::NotContentSubspace { operand: Operand::First, region: 0, index: 0 },
        );
        same_named(
            "MalformedSpan",
            CompareError::MalformedSpan {
                operand: Operand::First,
                region: 0,
                index: 0,
                fault: SpecFault::StartNotZeroFree,
            },
        );
        same_named("DocNotRegistered", FindError::DocNotRegistered(addr()));
        same_named(
            "MalformedSpan",
            FindError::MalformedSpan { region: 0, index: 0, fault: SpecFault::StartTooShallow },
        );

        // ── M8 (discovery) ──
        same_name(QueryError::DocNotRegistered);
        same_name(QueryError::NotALink);
        same_name(QueryError::BadRegion);
        same_name(QueryError::NotContentSubspace);
        same_name(QueryError::EmptyWidth);
        same_name(QueryError::OutOfBounds);
    }
}
