//! The mechanical error lowering (§5).
//!
//! Each store error enum implements [`Lower`] —
//! `self → (RejectCode, Option<FaultSite>)` — under the nested-error rule:
//! flat variants map to the same-named [`RejectCode`] leaf where the union
//! has one, and otherwise to the leaf their arm names; wrapper variants
//! (`Mint`, `Seat`, `Content`) recurse into the leaf enum's own impl. Neither
//! converter ever returns `Ok` — every upstream failure becomes a
//! [`Rejection`].
//!
//! The write path's converter, [`lower_txn`], is also the door a caller
//! outside the crate lowers through: the daemon's head writer calls the
//! stores directly, holds the same `TxnError<E>` the dispatch table holds at
//! its own arms, and renders its refusal as the wire renders a rejection —
//! the code and the detail, never a `Debug` rendering of the store's error
//! — by lowering it here, through the one table, with the I/O kind set
//! where the arm is `Durability` (the operations design §1.1 row 38).
//!
//! M5's and M7's `NotOwner(Address)` variants thread the failing document
//! (or target link) into `FaultSite::addr` — the same address-localization
//! shape M6's `DocNotRegistered(Address)` takes.

use skep_arrangement::{
    CopyError, DeleteError, InsertError, PublishError, RearrangeError, ReinstateError, SeatError,
    VersionError,
};
use skep_content::ContentError;
use skep_discovery::{OrphanError, QueryError};
use skep_kernel::TxnError;
use skep_links::{
    AssertSupError, EditLinkError, EmitError, MakeLinkError, NullifyError, PlanFault,
    PublicationError,
};
use skep_namespace::{CreateDocumentError, DelegateError, MintError, RegisterNodeError};
use skep_retrieval::{CompareError, DeletionsError, ExtentError, FindError, OriginError, RetrieveError};

use crate::reject::{FaultSite, RejectCode, Rejection};
use crate::request::OpKind;

/// A store error enum's lowering into a code and a site (§5).
///
/// One impl per store error enum (mechanical), every one of them in this
/// file: the table is the one lowering, and a store error that gains a
/// variant is lowered here, never at a caller.
///
/// Public because [`lower_txn`] is, and a door bounded on a trait its caller
/// cannot name is no door. Not sealed: an impl a dependent wrote for a type
/// of its own would classify on that dependent's account, which
/// [`Rejection::classified`] already lets it do by hand — so a seal would
/// guard nothing this crate does not publish. What a dependent cannot do is
/// change how a store error M10 names lowers: those impls are here.
pub trait Lower {
    /// Returns the code this error lowers to, and the site that localizes it.
    fn lower(self) -> (RejectCode, Option<FaultSite>);

    /// Returns the code, the site, and the `detail` token the refusal
    /// carries, where its code names a cause beside its site.
    ///
    /// The three deposit codes that do (`old_refused`, `retract_refused`,
    /// `read_with_refused`; the link-sets design §5.7) and the edition
    /// claim's (`claim_refused`, `member_stands`; skep #692) override this;
    /// every other error carries none, and this is [`Lower::lower`] with
    /// `None` beside it. [`lower_txn`] lowers through it, so a cause reaches
    /// the rejection's `detail` by the one table.
    fn lower_with_detail(self) -> (RejectCode, Option<FaultSite>, Option<String>)
    where
        Self: Sized,
    {
        let (code, site) = self.lower();
        (code, site, None)
    }
}

/// Returns the `NotOwner(Address)` lowering, shared by every enum with one.
///
/// The failing address rides `site.addr`.
fn not_owner(a: skep_address::Address) -> (RejectCode, Option<FaultSite>) {
    (RejectCode::NotOwner, Some(FaultSite { addr: Some(a), ..FaultSite::default() }))
}

/// Lowers a read error into a classified [`Rejection`] (§5).
pub(crate) fn lower_read<E: Lower>(kind: OpKind, e: E) -> Rejection {
    let (code, site) = e.lower();
    Rejection::classified(kind, code, site)
}

/// Lowers a write path's `TxnError` into a classified [`Rejection`] (§5).
///
/// The store's own typed refusal goes through its [`Lower`] impl, and M2's
/// four transaction-level outcomes into M10's own codes.
///
/// Each of those four says in the disposition what reissuing is worth, with
/// the cause threaded where an operator needs it. `Durability` is the one
/// `Retry` — the I/O text rides along, so the hint has a reason attached,
/// and the I/O kind rides beside it in [`Rejection::io_kind`], for the
/// daemon: the journal's append and barrier failures, the rotation's segment
/// creation and the salt's entropy refusal share this one code, and only the
/// kind tells a full volume from the rest. The text is marshaled to the
/// client as it stands, M10 stripping nothing from it, so what it may name
/// is the kernel's account's to keep — `TxnError::Durability`'s card names
/// the file and the act, never a path — and a host path in it would reach
/// the client (PATTERNS SP-13). The two encoding refusals are both
/// `Permanent`, and each carries its own code because they ask different
/// things of an operator: `TxnUnencodable` names records M2 could not frame
/// — one its serializer refused, or one past the journal's frame cap (the
/// records are staged by the owning store, so the same request re-presented
/// stages the same record — nothing the client can reframe), while
/// `TxnOverBudget` names records that all encode but overrun the journal's
/// per-transaction budget, and carries the remedy — split the request.
/// `Poisoned` is `Halt`.
///
/// **The door (the operations design §1.1 row 38).** It is public, so a
/// caller that drives a store itself — the daemon's head writer, which meets
/// `TxnError<CreateDocumentError>` at its staging draft's mint and
/// `TxnError<InsertError>` and `TxnError<PublishError>` at the head atom's
/// insert and publish — lowers what it holds exactly as the dispatch table
/// lowers the same error for the front door, under the `OpKind` it names,
/// and renders the rejection's code and detail rather than the store error's
/// `Debug`. The `detail` is the error's own words where one is threaded (the
/// I/O text; M2's encoding account), this function's own sentence naming
/// the encoded size for an over-budget transaction, and the code's standing
/// explanation otherwise; no arm renders a variant name. One body: this
/// function is the lowering the dispatch table calls, so the door and the
/// front door cannot drift.
pub fn lower_txn<E: Lower>(kind: OpKind, e: TxnError<E>) -> Rejection {
    match e {
        TxnError::Rejected(inner) => {
            let (code, site, detail) = inner.lower_with_detail();
            let rejection = Rejection::classified(kind, code, site);
            match detail {
                Some(detail) => rejection.with_detail(detail),
                None => rejection,
            }
        }
        TxnError::Durability(io) => Rejection::classified(kind, RejectCode::Durability, None)
            .with_detail(io.to_string())
            .with_io_kind(io.kind()),
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

// ───────────── M4 (content — named; its errors arrive wrapped) ────────────

impl Lower for ContentError {
    /// Lowers every `ContentError` to the single `Content` code (§5).
    ///
    /// It is the flagged wholesale collapse (Open build decision 8): M10 calls
    /// no M4 function that can refuse, so M4's error structure is out of scope
    /// (disposition `Permanent` — a transient content fault is thereby
    /// misclassified, documented, to revisit if the M4 edge is ratified).
    ///
    /// The arm is live: it is reached through `InsertError::Content` and
    /// `PublishError::Content` when M5's `insert` or `publish` refuses, so the
    /// structure the collapse discards is a fault a client meets wherever an
    /// upstream invariant breaks — never in correct operation — and not a dead
    /// branch.
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
            // M5 splits the source-residence guard into its own variant; the
            // design's RejectCode union carries no same-named leaf, so it
            // lowers to the shared NotContentSubspace.
            CopyError::SourceNotContentSubspace => (RejectCode::NotContentSubspace, None),
            CopyError::DanglingSource => (RejectCode::DanglingSource, None),
            CopyError::TooManyRuns => (RejectCode::TooManyRuns, None),
            CopyError::EmptyResult => (RejectCode::EmptyResult, None),
        }
    }
}

impl Lower for ReinstateError {
    /// Lowers the write by identity's verdicts to codes COPY and the shot use.
    ///
    /// Every one is a code the wire carries for those two: the destination's
    /// five are COPY's, the per-run four are the shot's (`bad_run`,
    /// `source_not_registered`, `dangling_source`, `too_many_runs`), and
    /// `empty_result` is COPY's for an empty list.
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            ReinstateError::DocNotRegistered => (RejectCode::DocNotRegistered, None),
            ReinstateError::NotOwner(a) => not_owner(a),
            ReinstateError::PublishedTarget => (RejectCode::PublishedTarget, None),
            ReinstateError::NotContentSubspace => (RejectCode::NotContentSubspace, None),
            ReinstateError::OutOfBounds => (RejectCode::OutOfBounds, None),
            ReinstateError::BadRun => (RejectCode::BadRun, None),
            ReinstateError::SourceNotRegistered => (RejectCode::SourceNotRegistered, None),
            ReinstateError::DanglingSource => (RejectCode::DanglingSource, None),
            ReinstateError::TooManyRuns => (RejectCode::TooManyRuns, None),
            ReinstateError::EmptyResult => (RejectCode::EmptyResult, None),
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
            // The version-chain model's two `version` refusals (PUB-kickoff
            // D2b): the faces are the client's, keyed on the code — and on
            // the flag the client itself sent, for the versionless one — so
            // nothing is threaded into the site.
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
            // The edition claim into an edition that already holds a member
            // (skep #692): `site.addr` is the edition, and the one cause
            // rides as `detail` through `lower_with_detail` below.
            PublishError::ClaimRefused(edition) => (
                RejectCode::ClaimRefused,
                Some(FaultSite { addr: Some(edition), ..FaultSite::default() }),
            ),
            // One code with `version`'s (PUB-2.9): the face is that code's
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

    /// The claim's refusal carries its one cause, `member_stands`, as
    /// `detail` beside the edition in `site.addr`.
    fn lower_with_detail(self) -> (RejectCode, Option<FaultSite>, Option<String>) {
        let detail = matches!(self, PublishError::ClaimRefused(_)).then(|| "member_stands".to_string());
        let (code, site) = self.lower();
        (code, site, detail)
    }
}

// ─────────────────────────────── M7 (links) ────────────────────────────────

/// Lowers the deposit plan's refusal (the link-sets design §5.7's validation
/// (3)–(5); lane S3): each the lane's own token or the slot-form and
/// class-fence code `make_link` answers, with the entry's index as
/// `site.index` — and, for `old_refused`, `retract_refused` and
/// `read_with_refused`, the cause as `detail`.
///
/// `NotOwner`, a `links` entry's home that is not the caller's, rides
/// `not_owner` with the home as `site.addr`, ω's own site; the slot-form
/// codes name the entry and, for the content clause, the slot — never a
/// span's index within the slot, the entry being the site the lane names.
/// The three fenced classes lower as `make_link`'s do, to `dc_violation`,
/// the daemon's own token speaking ahead over the wire for the two commons
/// classes.
impl Lower for PlanFault {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        let at = |index: usize| Some(FaultSite { index: Some(index), ..FaultSite::default() });
        match self {
            PlanFault::NotOwner(a) => not_owner(a),
            PlanFault::LinkHome { index } => (RejectCode::LinkHomeRefused, at(index)),
            PlanFault::DuplicateOriginal { index } => (RejectCode::DuplicateOriginal, at(index)),
            PlanFault::ReadWithInLinks { index } => (RejectCode::ReadWithInLinks, at(index)),
            PlanFault::Old { index, .. } => (RejectCode::OldRefused, at(index)),
            PlanFault::NotContentSpan { index, slot } => (
                RejectCode::NotContentSubspace,
                Some(FaultSite { slot: Some(slot), index: Some(index), ..FaultSite::default() }),
            ),
            PlanFault::SlotTooLarge { index } => (RejectCode::SlotTooLarge, at(index)),
            PlanFault::EmptyType { index } => (RejectCode::EmptyTypeResolution, at(index)),
            PlanFault::RetractionClass { index } => (RejectCode::RetractionClass, at(index)),
            PlanFault::SupersessionClass { index }
            | PlanFault::ReplacesClass { index }
            | PlanFault::CorrespondenceClass { index } => (RejectCode::DcViolation, at(index)),
            PlanFault::MemberSpan { index } => (RejectCode::Malformed, at(index)),
            PlanFault::ClaimWithoutDraft => (RejectCode::Malformed, None),
            PlanFault::Retract { index, .. } => (RejectCode::RetractRefused, at(index)),
            PlanFault::ReadWith { index, .. } => (RejectCode::ReadWithRefused, at(index)),
        }
    }

    /// The three detailed codes carry their cause's token as `detail`.
    fn lower_with_detail(self) -> (RejectCode, Option<FaultSite>, Option<String>) {
        let detail = match &self {
            PlanFault::Old { cause, .. } => Some(cause.token().to_string()),
            PlanFault::Retract { cause, .. } => Some(cause.token().to_string()),
            PlanFault::ReadWith { cause, .. } => Some(cause.token().to_string()),
            _ => None,
        };
        let (code, site) = self.lower();
        (code, site, detail)
    }
}

impl Lower for PublicationError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            // The shot's own verdicts lower through M5's table, so the
            // publication's refusals read as `publish`'s, slot for slot.
            PublicationError::Publish(e) => e.lower(),
            // The deposit plan's: the lane's tokens with their entries.
            PublicationError::Plan(f) => f.lower(),
            // The twin fence: `site.addr` the member the record's `to` was
            // minted into, and nothing else rides the code.
            PublicationError::AlreadyPublished { site } => (
                RejectCode::AlreadyPublished,
                Some(FaultSite { addr: Some(site), ..FaultSite::default() }),
            ),
            PublicationError::HomeNotRegistered => (RejectCode::HomeNotRegistered, None),
            PublicationError::NotOwner(a) => not_owner(a),
            PublicationError::Mint(m) => m.lower(),
            PublicationError::Seat(s) => s.lower(),
            // The re-window's check: `site.index` the `runs` entry whose
            // kept place the draft no longer honours, and nothing else rides
            // the code.
            PublicationError::KeptPlaceMoved { index } => (
                RejectCode::KeptPlaceMoved,
                Some(FaultSite { index: Some(index), ..FaultSite::default() }),
            ),
            // The stray places' record read: `site.index` the `runs` entry
            // no record of the draft covers whole, and nothing else.
            PublicationError::StrayPlaceUnrecorded { index } => (
                RejectCode::StrayPlaceUnrecorded,
                Some(FaultSite { index: Some(index), ..FaultSite::default() }),
            ),
            // The re-window's placement and removal lower through M5's
            // tables, so they read as `reinstate`'s and `delete`'s.
            PublicationError::Reinstate(e) => e.lower(),
            PublicationError::Delete(e) => e.lower(),
        }
    }

    /// The deposit plan's detailed refusals carry their cause through, and
    /// so does the shot's table's one (`claim_refused`'s `member_stands`).
    fn lower_with_detail(self) -> (RejectCode, Option<FaultSite>, Option<String>) {
        match self {
            PublicationError::Plan(f) => f.lower_with_detail(),
            PublicationError::Publish(e) => e.lower_with_detail(),
            other => {
                let (code, site) = other.lower();
                (code, site, None)
            }
        }
    }
}

impl Lower for MakeLinkError {
    fn lower(self) -> (RejectCode, Option<FaultSite>) {
        match self {
            MakeLinkError::HomeNotRegistered => (RejectCode::HomeNotRegistered, None),
            MakeLinkError::NotOwner(a) => not_owner(a),
            MakeLinkError::IllFormedSpec => (RejectCode::IllFormedSpec, None),
            // The I-span form's shape, the content clause (W6 (a)): a span
            // whose start is no content-subspace element position, or whose
            // width is no ordinal displacement, under the read by identity's
            // own code for the same fault, localized as M10's successor guard
            // localizes a spec — the slot in M7's numbering, the span's index
            // within it. Permanent by the catch-all: the span's own bytes are
            // what is wrong.
            MakeLinkError::NotContentSpan { slot, index } => (
                RejectCode::NotContentSubspace,
                Some(FaultSite { slot: Some(slot), index: Some(index), ..FaultSite::default() }),
            ),
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
            // The correspondence class's fence, the `replaces` fence's twin
            // (the link-sets design §5.7) — the same near leaf. Reached
            // Engine-direct alone: the daemon refuses the same slots ahead of
            // the transaction under its own token,
            // `correspondence_not_standalone`. Permanent: the class's one
            // writer is the publish shot's own record mint.
            MakeLinkError::CorrespondenceClass => (RejectCode::DcViolation, None),
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
            // M7 carries the supersession-schema fence (`[K_sup]` claims
            // write only via assert_sup/editlink) as its own variant; the
            // design's RejectCode union has no same-named leaf, so it lowers
            // to DcViolation — the same claim-schema discipline editlink's DC
            // guard names. Permanent is right: reissuing identically cannot
            // succeed — use AssertSup/EditLink.
            EmitError::SupersessionClass => (RejectCode::DcViolation, None),
            // The `replaces` class's fence, as MakeLinkError's lowers it.
            EmitError::ReplacesClass => (RejectCode::DcViolation, None),
            // The correspondence class's fence, as MakeLinkError's lowers it
            // — the daemon's token, `correspondence_not_standalone`, speaks
            // ahead of the transaction over the wire.
            EmitError::CorrespondenceClass => (RejectCode::DcViolation, None),
            EmitError::NonAddressDenotingType => (RejectCode::NonAddressDenotingType, None),
            // The same per-slot span budget MAKELINK's slots carry, on `to`
            // and `ty` — so the same leaf, and permanent for the same reason:
            // no retry shrinks the list.
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
// `index` with M10's successor guard and its read consult's span-shape
// refusal, and `addr` with every `NotOwner(Address)` and `Withheld`;
// `FaultSite`'s fields name every producer.

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
    /// Fills only `code`, every M8 variant being fieldless (§5).
    ///
    /// Its `DocNotRegistered`, unlike M6's multi-document ones, carries no
    /// address.
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
    /// Lowers the delete-orphan preview's own refusals (§5).
    ///
    /// They are fieldless like the rest of M8's.
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
