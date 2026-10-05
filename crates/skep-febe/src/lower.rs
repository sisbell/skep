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

use skep_arrangement::{
    CopyError, DeleteError, InsertError, PublishError, RearrangeError, SeatError, VersionError,
};
use skep_content::ContentError;
use skep_discovery::{OrphanError, QueryError};
use skep_kernel::TxnError;
use skep_links::{AssertSupError, EditLinkError, EmitError, MakeLinkError, NullifyError};
use skep_namespace::{CreateDocumentError, DelegateError, MintError, RegisterNodeError};
use skep_retrieval::{CompareError, DeletionsError, ExtentError, FindError, OriginError, RetrieveError};

use crate::reject::{FaultSite, RejectCode, Rejection};
use crate::request::OpKind;

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
    let (code, site) = e.lower();
    Rejection::classified(kind, code, site)
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
            let (code, site) = inner.lower();
            Rejection::classified(kind, code, site)
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
            DelegateError::TooDeep => RejectCode::TooDeep,
            DelegateError::NotTopDown => RejectCode::NotTopDown,
            DelegateError::NotFresh => RejectCode::NotFresh,
            DelegateError::NotNextForm => RejectCode::NotNextForm,
            DelegateError::NotValid => RejectCode::NotValid,
            DelegateError::ParentNotRegistered => RejectCode::ParentNotRegistered,
        };
        (code, None)
    }
}

impl Lower for RegisterNodeError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let code = match self {
            RegisterNodeError::NotValid => RejectCode::NotValid,
            RegisterNodeError::NotNode => RejectCode::NotNode,
            RegisterNodeError::TooDeep => RejectCode::TooDeep,
            RegisterNodeError::NotFresh => RejectCode::NotFresh,
            RegisterNodeError::NotDescendantOfBootstrap => RejectCode::NotDescendantOfBootstrap,
        };
        (code, None)
    }
}

// ───────────────────── M4 (content — named, never called) ─────────────────

impl Lower for ContentError {
    /// The flagged wholesale collapse (§5, Open build decision 8): M10 calls
    /// no M4 function, so M4's error structure is out of scope and every
    /// `ContentError` lowers to the single `Content` code (disposition
    /// `Permanent` — a transient content fault is thereby misclassified,
    /// documented, to revisit if the M4 edge is ratified).
    ///
    /// The arm is LIVE: it is reached through `InsertError::Content` and
    /// `PublishError::Content` when M5's `insert` or `publish` refuses, so the
    /// structure the collapse discards is a fault a client can meet, not a
    /// dead branch.
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        (RejectCode::Content, None)
    }
}

// ──────────────────────────── M5 (arrangement) ─────────────────────────────

impl Lower for SeatError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let code = match self {
            SeatError::NotLinkAddress => RejectCode::NotLinkAddress,
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
            InsertError::PublishedTarget => (RejectCode::PublishedTarget, None),
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
            CopyError::PublishedTarget => (RejectCode::PublishedTarget, None),
            CopyError::NotContentSubspace => (RejectCode::NotContentSubspace, None),
            CopyError::OutOfBounds => (RejectCode::OutOfBounds, None),
            CopyError::SourceNotRegistered => (RejectCode::SourceNotRegistered, None),
            CopyError::EmptySource => (RejectCode::EmptySource, None),
            CopyError::NotOrdinalVSpan => (RejectCode::NotOrdinalVSpan, None),
            // As-built M5 splits the source-residence guard into its own
            // variant; the design's RejectCode union carries no same-named
            // leaf, so it lowers to the shared NotContentSubspace (surfaced
            // in the build report as upstream drift).
            CopyError::SourceNotContentSubspace => (RejectCode::NotContentSubspace, None),
            CopyError::DanglingSource => (RejectCode::DanglingSource, None),
            CopyError::TooManyRuns => (RejectCode::TooManyRuns, None),
            CopyError::EmptyResult => (RejectCode::EmptyResult, None),
        }
    }
}

impl Lower for DeleteError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            DeleteError::DocNotRegistered => (RejectCode::DocNotRegistered, None),
            DeleteError::NotOwner(a) => not_owner(a),
            DeleteError::PublishedTarget => (RejectCode::PublishedTarget, None),
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
            RearrangeError::PublishedTarget => (RejectCode::PublishedTarget, None),
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
            // The version-chain model's two `version` refusals (D2b): the
            // faces are the client's, keyed on the code — and on the flag
            // the client itself sent, for the versionless one — so nothing
            // is threaded into the site.
            VersionError::PrivateSourceVersionless => (RejectCode::PrivateSourceVersionless, None),
            VersionError::PrivateVersionOfPublished => {
                (RejectCode::PrivateVersionOfPublished, None)
            }
            VersionError::Mint(m) => m.lower(),
        }
    }
}

impl Lower for PublishError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            PublishError::DocNotRegistered => (RejectCode::DocNotRegistered, None),
            PublishError::NotOwner(a) => not_owner(a),
            PublishError::SourceNotRegistered => (RejectCode::SourceNotRegistered, None),
            PublishError::BadRun => (RejectCode::BadRun, None),
            PublishError::BaseNotInChain => (RejectCode::BaseNotInChain, None),
            PublishError::BaseSuperseded => (RejectCode::BaseSuperseded, None),
            PublishError::BaseExtentTooLarge => (RejectCode::BaseExtentTooLarge, None),
            // ONE code with `version`'s (PUB-2.9): the face is that code's
            // `true` arm, the intent being publication.
            PublishError::PrivateSourceVersionless => (RejectCode::PrivateSourceVersionless, None),
            // PUB-8.4's pinned shape: `site.addr` is the withheld document —
            // the first unreadable origin — and nothing else rides the code
            // (PUB-8.5: no detail, ever).
            PublishError::Withheld(origin) => (
                RejectCode::Withheld,
                Some(FaultSite { addr: Some(origin), ..FaultSite::default() }),
            ),
            PublishError::DanglingSource => (RejectCode::DanglingSource, None),
            PublishError::TooManyRuns => (RejectCode::TooManyRuns, None),
            PublishError::TooManyValues => (RejectCode::TooManyValues, None),
            PublishError::Mint(m) => m.lower(),
            PublishError::Content(c) => c.lower(),
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
            // The `replaces` class's fence, lowering as its `[K_sup]` twin
            // does — the design's union holds no same-named leaf. Reached
            // Engine-direct alone: the daemon refuses the same slots ahead of
            // the transaction under the wire's own code,
            // `replaces_not_standalone` (PUB-5.15). Permanent: the class is
            // minted only beside its record, by MAKELINK's `replaces` member.
            MakeLinkError::ReplacesClass => (RejectCode::DcViolation, None),
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
            // The `replaces` class's fence, as MakeLinkError's lowers it.
            EmitError::ReplacesClass => (RejectCode::DcViolation, None),
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
            // M7's own restatement of the per-slot span budget over the
            // finished successor — the same budget and the same leaf
            // MAKELINK's slots take. M10 builds those slots and charges them
            // against M7's two per-slot budgets, the spans kept and the steps
            // walked, as it builds them (`successor::successor_slot`),
            // refusing there where the door judged the write. Where the door
            // deferred to the store's own gate, a slot over either budget is
            // left one span past the span budget and this arm is the one that
            // answers it, after M7's home gate — as it is for a successor
            // assembled some other way.
            EditLinkError::SlotTooLarge => (RejectCode::SlotTooLarge, None),
            EditLinkError::IllFormedSuccessor => (RejectCode::IllFormedSuccessor, None),
            EditLinkError::DcViolation => (RejectCode::DcViolation, None),
            EditLinkError::Mint(m) => m.lower(),
        }
    }
}

// ─────────── M6 (retrieval — variant-carried localization) ────────────
//
// M6 is the one producer of `operand`, `region` and `fault`, and shares
// `index` with M10's successor guard and `addr` with every `NotOwner` and
// `Withheld`; `FaultSite`'s fields name every producer.

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
            // The delivery budget names the request's whole shape and no
            // position in it, so it carries no site — `TooMuchCoverage`'s
            // position exactly.
            RetrieveError::TooManyItems => (RejectCode::TooManyItems, None),
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
            // The two budget refusals. `TooManyBlocks` is one operand's, so
            // the operand rides the site; `TooManyPairs` is the report's and
            // belongs to neither.
            CompareError::TooManyBlocks { operand } => (
                RejectCode::TooManyBlocks,
                Some(FaultSite { operand: Some(operand), ..FaultSite::default() }),
            ),
            CompareError::TooManyPairs => (RejectCode::TooManyPairs, None),
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
            // The coverage budget names the request's whole shape and no
            // position in it, so it carries no site — `TooManyPairs`'s
            // position exactly.
            FindError::TooMuchCoverage => (RejectCode::TooMuchCoverage, None),
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
            // M8's two budget refusals name the request's whole shape and no
            // position in it, so they carry no site — M6's `TooManyPairs`
            // and `TooMuchCoverage` exactly.
            QueryError::ImageTooLarge => RejectCode::ImageTooLarge,
            QueryError::EndsetsTooLarge => RejectCode::EndsetsTooLarge,
        };
        (code, None)
    }
}

impl Lower for OrphanError {
    /// The delete-orphan preview's own refusals, fieldless like the rest of
    /// M8's (§5).
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let code = match self {
            OrphanError::DocNotRegistered => RejectCode::DocNotRegistered,
            OrphanError::NotContentSubspace => RejectCode::NotContentSubspace,
            OrphanError::EmptyWidth => RejectCode::EmptyWidth,
            OrphanError::OutOfBounds => RejectCode::OutOfBounds,
            // The preview's run budget lowers to the leaf the query surface's
            // (`QueryError::ImageTooLarge` above) does, and carries no site
            // for the same reason: it names no position in the request.
            OrphanError::ImageTooLarge => RejectCode::ImageTooLarge,
        };
        (code, None)
    }
}

#[cfg(test)]
mod tests;
