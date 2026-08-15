//! The mechanical error lowering (§5): each store error enum implements
//! [`Lower`] — `self → (RejectCode, Option<FaultSite>)` — under the
//! nested-error rule: flat variants map to the same-named [`RejectCode`]
//! leaf; wrapper variants (`Mint`, `Seat`, `Content`) recurse into the leaf
//! enum's own impl. Neither converter ever returns `Ok` — every upstream
//! failure becomes a [`Rejection`].

use skep_arrangement::{CopyError, DeleteError, InsertError, RearrangeError, SeatError, VersionError};
use skep_content::ContentError;
use skep_discovery::QueryError;
use skep_links::{AssertSupError, EditLinkError, EmitError, MakeLinkError, NullifyError};
use skep_namespace::{DelegateError, MintError, NodeError, OpError};
use skep_retrieval::{CompareError, DeletionsError, ExtentError, FindError, OriginError, RetrieveError};

use crate::op::OpKind;
use crate::reject::{FaultSite, RejectCode, Rejection};

/// One impl per store error enum (mechanical; §5).
pub(crate) trait Lower {
    fn lower(self) -> (RejectCode, Option<FaultSite>);
}

/// Lower a read error into a classified [`Rejection`] (§5). Stays a free
/// function: a read can never poison the kernel, so no latch is involved.
pub(crate) fn map_read<E: Lower>(op: OpKind, e: E) -> Rejection {
    let (c, s) = e.lower();
    Rejection::classified(op, c, s)
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

impl Lower for OpError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            OpError::NotOwner => (RejectCode::NotOwner, None),
            OpError::Mint(m) => m.lower(),
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
        let code = match self {
            CopyError::DocNotRegistered => RejectCode::DocNotRegistered,
            CopyError::NotContentSubspace => RejectCode::NotContentSubspace,
            CopyError::OutOfBounds => RejectCode::OutOfBounds,
            CopyError::SourceNotRegistered => RejectCode::SourceNotRegistered,
            CopyError::EmptySource => RejectCode::EmptySource,
            CopyError::BadSpan => RejectCode::BadSpan,
            // As-built M5 splits the source-residence guard into its own
            // variant; the design's RejectCode union carries no same-named
            // leaf, so it lowers to the shared NotContentSubspace (surfaced
            // in the build report as upstream drift).
            CopyError::SourceNotContentSubspace => RejectCode::NotContentSubspace,
            CopyError::DanglingSource => RejectCode::DanglingSource,
            CopyError::EmptyResult => RejectCode::EmptyResult,
        };
        (code, None)
    }
}

impl Lower for DeleteError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let code = match self {
            DeleteError::DocNotRegistered => RejectCode::DocNotRegistered,
            DeleteError::NotContentSubspace => RejectCode::NotContentSubspace,
            DeleteError::NotArranged => RejectCode::NotArranged,
            DeleteError::OutOfBounds => RejectCode::OutOfBounds,
            DeleteError::EmptyWidth => RejectCode::EmptyWidth,
        };
        (code, None)
    }
}

impl Lower for RearrangeError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let code = match self {
            RearrangeError::DocNotRegistered => RejectCode::DocNotRegistered,
            RearrangeError::BadCutCount => RejectCode::BadCutCount,
            RearrangeError::NotAscending => RejectCode::NotAscending,
            RearrangeError::NotContentSubspace => RejectCode::NotContentSubspace,
            RearrangeError::OutOfBounds => RejectCode::OutOfBounds,
            RearrangeError::EmptyContentSubspace => RejectCode::EmptyContentSubspace,
        };
        (code, None)
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
            MakeLinkError::IllFormedSpec => (RejectCode::IllFormedSpec, None),
            MakeLinkError::EmptyTypeResolution => (RejectCode::EmptyTypeResolution, None),
            MakeLinkError::Mint(m) => m.lower(),
            MakeLinkError::Seat(s) => s.lower(),
        }
    }
}

impl Lower for EmitError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            EmitError::HomeNotRegistered => (RejectCode::HomeNotRegistered, None),
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
            EmitError::Mint(m) => m.lower(),
        }
    }
}

impl Lower for NullifyError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            NullifyError::HomeNotRegistered => (RejectCode::HomeNotRegistered, None),
            NullifyError::BadTarget => (RejectCode::BadTarget, None),
            NullifyError::Mint(m) => m.lower(),
        }
    }
}

impl Lower for AssertSupError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            AssertSupError::HomeNotRegistered => (RejectCode::HomeNotRegistered, None),
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
        let (c, s) = OpError::Mint(MintError::NotAnAccount).lower();
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
}
