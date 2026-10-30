//! The typed rejections of M7's write surface, and FOLLOWLINK's ⊥ marker.
//!
//! They cover the write surface (§C/§D) and its staleness family (§7 —
//! [`NotBh4`], [`RetractStaleError`]); FOLLOWLINK's ⊥ marker is
//! [`Invalid`].
//!
//! Variant declaration order is each op's precedence: where an input
//! satisfies several rejections at once, the earlier-declared one speaks.
//! Three hoists put a check ahead of other verdicts. The first overrides
//! that order in [`EditLinkError`], which declares `OriginalNotResident`
//! ahead of the home pair, and the second in [`EmitError`]; the third keeps
//! it, its variant declared first:
//!
//! * the home/ω pair runs ahead of every other in-transaction verdict — each
//!   gate, each dedup short-circuit, and each op's own residence and
//!   well-formedness checks — so an unregistered or unowned home is refused
//!   on hit and miss, whatever else the input violates (Conflicts §8);
//! * [`EmitError::NonAddressDenotingType`], [`EmitError::SupersessionClass`],
//!   [`EmitError::ReplacesClass`], [`EmitError::CorrespondenceClass`] and
//!   [`EmitError::SlotTooLarge`] are pre-transact — in that firing order —
//!   so all five outrank every in-transaction verdict including the home/ω
//!   pair;
//! * [`RetractStaleError::NotBh4`] is likewise pre-transact, ahead of the
//!   constituent nullifies' own rejections.

use std::error::Error;
use std::fmt;

use skep_address::Address;
use skep_arrangement::{DeleteError, PublishError, ReinstateError, SeatError};
use skep_namespace::MintError;

// Ownership: every op that deposits into a home document's link subspace
// carries a `NotOwner(Address)` rejection — the in-txn ω gate on that home
// (and, for nullify, on the target link's own address) — checked after home
// registration, before every other gate. The payload is the address that
// failed the check (M10 threads it into the rejection's fault site); because
// they carry it, these enums are not `Copy`.

/// MAKELINK rejection (ASN-0120; §C/§2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MakeLinkError {
    /// `home` is not a registered Document (L1a/ML0 P0).
    HomeNotRegistered,
    /// The caller is not `home`'s effective owner (ω, exact account match).
    NotOwner(Address),
    /// A `Resolve` V-spec fails wf.
    ///
    /// Its source is unregistered, or it is not a depth-2 content V-position
    /// with ordinal displacement (`#start = 2 ∧ start₁ = s_C ∧ #width = 2 ∧
    /// width₁ = 0`) — the deliberate depth-2 narrowing of ASN-0120's
    /// `#u_j ≥ 2` (Conflicts §12). `Addrs` slots have no wf step.
    IllFormedSpec,
    /// A span of an I-span slot is no content I-span.
    ///
    /// The I-span form ([`crate::SlotArg::Spans`]) records content I-spans
    /// verbatim, so each span must be one by its own bytes: its start a
    /// content-subspace element position and its width that run's ordinal
    /// displacement, `0…0.n` with `n ≥ 1` — `SlotArg::ill_formed_span`, the
    /// one spelling of the shape, by request arithmetic and no world read.
    /// `slot` is the slot in M7's numbering ([`crate::FROM`], [`crate::TO`],
    /// [`crate::TYPE`]) and `index` the span's position within it. The content
    /// clause is what keeps a span from spelling a type address's unit span —
    /// a credential type's, which would route a deposit around the credential
    /// sequence, the registry's, the `replaces` class — in a form no
    /// classifier of the daemon's reads. Never a registration or occupancy
    /// question of the spans' document: a ghost position is a valid name, as
    /// in the address form.
    NotContentSpan {
        /// The slot the span sits in: [`crate::FROM`], [`crate::TO`] or
        /// [`crate::TYPE`].
        slot: usize,
        /// The span's position within the slot.
        index: usize,
    },
    /// A slot is over one of the two per-slot budgets.
    ///
    /// It holds more than [`crate::MAX_SLOT_SPANS`] spans in whichever form
    /// built it — a `Resolve` slot resolved past the budget, an `Addrs`
    /// list naming more addresses than it, or a `Spans` list carrying more
    /// — or, for a `Resolve` slot, its
    /// specs command more than [`crate::MAX_SLOT_RESOLVE_STEPS`] run-list
    /// steps. One rejection for both, because both are the same answer to
    /// the caller — this slot asks for more than a slot may have — and one
    /// `Display` text, which names both numbers. Why the request that carried
    /// a slot bounds neither is the two constants' own account.
    SlotTooLarge,
    /// The type slot is empty as given (ML6 — `e₃ ≠ ∅`).
    ///
    /// The `Resolve` spec-set resolved to `⟨⟩`, or the `Addrs` name list was
    /// empty.
    EmptyTypeResolution,
    /// The resolved type slot lands in the `[R]` class.
    ///
    /// Retraction writes only through `nullify` (K ≁ R). The hint fold
    /// recognizes a deposit by its type slot's class, never by the surface it
    /// arrived through, so an `[R]`-classed link deposited here would
    /// tombstone every address its `TO` slot denotes; this is the same
    /// sole-writer fence `emit` states.
    RetractionClass,
    /// The resolved type slot lands in the `[K_sup]` class.
    ///
    /// Supersession writes only through `assert_sup`/`editlink`, the two
    /// paths that establish the Df-DISC(ii) schema (resident endpoints,
    /// single denoted addresses, irreflexivity) the walk family reads back as
    /// fact.
    SupersessionClass,
    /// The resolved type slot lands in the `replaces` class.
    ///
    /// That class ([`crate::replaces_type`]; PUB-5.15, RES-309/310) is the
    /// authority successor, whose one writer is
    /// [`crate::LinkWriter::makelink_replacing`], minting it in its record's
    /// own transaction. The grant fold reads a record's `replaces` as the link
    /// deposited at the record's own next address, so a `replaces` link put
    /// there by any other act would name a state for a record whose signed
    /// bytes named none — the sole-writer fence the `[K_sup]` one above
    /// states for its class. Refused whether or not the op carries a member:
    /// a record of this class is itself a `replaces` link.
    ReplacesClass,
    /// The resolved type slot lands in the correspondence class.
    ///
    /// That class ([`crate::correspondence_type`], `1.1.0.1.0.1.0.3.102.1`;
    /// the link-sets design §5.7, "the CLASS HAS ONE WRITER") is the publish
    /// shot's own record — that a draft run's identity became the member's —
    /// whose one writer is the shot's record mint in the shot's own
    /// transaction, not yet built, so today nothing deposits the class at
    /// all. Its readers take a record's `from` and `to` as the exact
    /// correspondence the shot computed, so a record of the class put there
    /// by any other act would state an identity the shot never minted — the
    /// sole-writer fence the two above state for theirs. PUB-6.64's member
    /// beside them: its `nullify` is refused too. The parent `counterpart`
    /// `3.102` is an ordinary type and is not fenced.
    CorrespondenceClass,
    /// M3's mint failed structurally.
    Mint(MintError),
    /// M5's seat step refused (CL-OWN/CL-UNIQ).
    ///
    /// Unreachable for a freshly minted home link, kept typed per the design.
    Seat(SeatError),
}

/// Emit_K rejection (ASN-0086/0126/0128; §D).
///
/// `SupersessionClass` is the `[K_sup]` write fence (Conflicts §10) — the
/// exact parallel of the `[R]` fence, making `assert_sup`/`editlink` the sole
/// `[K_sup]`-writers so every stored claim is schema-conformant, which the
/// walk family leans on. `ReplacesClass` is the `replaces` class's fence,
/// making [`crate::LinkWriter::makelink_replacing`] that class's sole writer;
/// `CorrespondenceClass` the correspondence class's, whose sole writer is
/// the publish shot's record mint, not yet built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitError {
    /// `home` is not a registered Document (P0).
    ///
    /// Enforced on hit and miss — Conflicts §8.
    HomeNotRegistered,
    /// The caller is not `home`'s effective owner (ω).
    ///
    /// Enforced on hit and miss, like the home check it follows.
    NotOwner(Address),
    /// `ty`'s coverage class is not registered (Managed gate (i)).
    NotRegistered,
    /// `ty ~ [R]` — retraction writes only through `nullify` (K ≁ R).
    ///
    /// Ahead of `ShapeViolation`: an `[R]`-typed emit with a non-conforming
    /// `|G|` satisfies both, and the fence speaks (design's K ≁ R before
    /// Sh-conf).
    RetractionClass,
    /// Span counts violate the registered shape (P3 Sh-conf).
    ///
    /// One `FROM` span always, and no `TO` span under Unary, exactly one
    /// under Binary, any finite number under Multi — each slot's spans counted
    /// as a set, a repeated span once.
    ShapeViolation,
    /// `ty ~ [K_sup]` — a class only `assert_sup` and `editlink` write.
    ///
    /// The fence is Conflicts §10's. Pre-transact.
    SupersessionClass,
    /// `ty ~ replaces` — the authority successor's class, which has one writer.
    ///
    /// That writer is [`crate::LinkWriter::makelink_replacing`] (PUB-5.15,
    /// RES-309/310). Pre-transact, and independent of the registry: the class
    /// is a commons value no registration holds, so without the fence the
    /// Managed gate's `NotRegistered` would refuse it — the fence is what
    /// keeps it refused if a registration ever names it.
    ReplacesClass,
    /// `ty ~ correspondence` — the publish shot's record class, which has
    /// one writer.
    ///
    /// That writer is the shot's own record mint (the link-sets design
    /// §5.7), not yet built. Pre-transact, behind `ReplacesClass` and
    /// independent of the registry as it is: a commons value no registration
    /// holds.
    CorrespondenceClass,
    /// `ty` is not address-denoting.
    ///
    /// Rejected before any class computation (§Core data model totality).
    /// Pre-transact.
    NonAddressDenotingType,
    /// One of the two caller-sized slots is over the per-slot span budget.
    ///
    /// The budget is [`crate::MAX_SLOT_SPANS`] — `to`'s address count or
    /// `ty`'s own span count — as [`crate::emit_tuple`] holds it, which also
    /// says why `ty` is held to it as squarely as `to`. Pre-transact, and so
    /// ahead of `ShapeViolation`.
    SlotTooLarge,
    /// M3's mint failed structurally.
    Mint(MintError),
}

/// Nullify rejection (ASN-0128; §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullifyError {
    /// `home` (`d_retr`) is not a registered Document (P0).
    HomeNotRegistered,
    /// The caller is not the effective owner (ω) of the address carried.
    ///
    /// That is `home`, or the target link's own address (self-retraction only
    /// — the v1 nullify target policy; owning the retraction's home does not
    /// license retracting someone else's link). `home` is checked first, so a
    /// caller owning neither is told about `home`.
    NotOwner(Address),
    /// P-tgt: `target` is neither a resident link nor this call's `a_emit`.
    ///
    /// `a_emit` is the address this call's own retraction tuple would occupy
    /// — sterilization made unreachable through the surface (DR).
    BadTarget,
    /// M3's mint failed structurally.
    Mint(MintError),
}

/// assert_sup rejection (ASN-0125 Df-DISC; §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertSupError {
    /// `home` is not a registered Document (P0).
    HomeNotRegistered,
    /// The caller is not `home`'s effective owner (ω).
    NotOwner(Address),
    /// `old` or `new` is not a resident link.
    EndpointNotResident,
    /// `old == new` (Df-DISC(ii) irreflexivity).
    SelfSupersession,
    /// M3's mint failed structurally.
    Mint(MintError),
}

/// editlink rejection (ASN-0125 EDITop/DC; §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditLinkError {
    /// `original` is not a resident link.
    OriginalNotResident,
    /// `d_s` or `d_a` is not a registered Document.
    HomeNotRegistered,
    /// The caller is not the effective owner (ω) of the carried home.
    ///
    /// That home is `d_s` or `d_a`, whichever failed.
    NotOwner(Address),
    /// A successor slot carries more than [`crate::MAX_SLOT_SPANS`] spans.
    ///
    /// That is the budget every caller-shaped slot is held to. Checked ahead
    /// of `IllFormedSuccessor`, because every per-span step below it runs
    /// inside the transact.
    SlotTooLarge,
    /// The supplied successor is ill-formed.
    ///
    /// It has arity ≠ 3 (the deliberate narrowing of EDITop's N ≥ 3 —
    /// Conflicts §11), an empty type slot, or a non-level-uniform span in any
    /// slot (keeps `coverage_class` total for the DC guard, which reads the
    /// type slot, and for the hint fold's dedup key, which reads all three).
    IllFormedSuccessor,
    /// DC: the successor fails the DC guard.
    ///
    /// It is retraction-typed, `replaces`-typed (that class's one writer
    /// being [`crate::LinkWriter::makelink_replacing`] — PUB-5.15, RES-309),
    /// correspondence-typed (that class's one writer the publish shot's
    /// record mint — the link-sets design §5.7), or `[K_sup]`-typed without
    /// the Df-DISC(ii) schema (unit-depth single-addr F/G, resident
    /// endpoints, irreflexive).
    DcViolation,
    /// M3's mint failed structurally.
    Mint(MintError),
}

/// The staleness family's served-only-where-declared rejection (§7).
///
/// `ty` is not registered with BH4 (Age), so `stale` does not serve it. A
/// typed refusal, never `Ok(vec![])` — so a caller reading an empty stale
/// set is reading a truthful freshness answer, never "this type does not do
/// staleness".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotBh4;

/// retract_stale rejection (§7).
///
/// It is the pre-transact BH4 fence, or a constituent nullify's own
/// rejection lifted into the batch. Not `Copy`, as `NullifyError` is not:
/// its `NotOwner` carries an `Address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetractStaleError {
    /// `ty` is not registered with BH4 (Age).
    ///
    /// Rejected before any transaction is opened (served only where declared;
    /// the fence that keeps the batch nullifier off idem⊤ classes).
    NotBh4,
    /// A constituent `nullify` transact rejected.
    ///
    /// Earlier nullifies in the batch stay committed (append-only, no
    /// rollback).
    Nullify(NullifyError),
}

impl From<NullifyError> for RetractStaleError {
    fn from(e: NullifyError) -> Self {
        RetractStaleError::Nullify(e)
    }
}

/// Why a `links` entry's `old` is refused: the `old_refused` token's
/// `detail` (the link-sets design §5.7, THE VALIDATION's (3)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OldCause {
    /// No resident link stands at `old`.
    Absent,
    /// `old` is homed in a published document.
    Public,
    /// `old` is retracted.
    Retracted,
    /// `old` is not the caller's own.
    NotOwner,
    /// `old` reaches the words the shot publishes through a whole-work end
    /// alone — a unit span at a document's address or an ancestor's — and
    /// through no content span: the corner's link, which no panel offers
    /// (the link-sets design §5.1's stored-endset test).
    WholeWork,
    /// `old` — or, where `old` is a successor, its own original — is
    /// superseded by an active claim of the caller's naming a public copy.
    Superseded,
}

impl OldCause {
    /// Returns the cause's `detail` token.
    pub fn token(self) -> &'static str {
        match self {
            OldCause::Absent => "absent",
            OldCause::Public => "public",
            OldCause::Retracted => "retracted",
            OldCause::NotOwner => "not_owner",
            OldCause::WholeWork => "whole_work",
            OldCause::Superseded => "superseded",
        }
    }
}

/// Why a `retract` entry is refused: the `retract_refused` token's `detail`
/// (THE VALIDATION's (4)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetractCause {
    /// No resident link stands at the target.
    Absent,
    /// The target is not the caller's own.
    NotOwner,
    /// The target is not homed in a published document of the caller's.
    NotPublished,
}

impl RetractCause {
    /// Returns the cause's `detail` token.
    pub fn token(self) -> &'static str {
        match self {
            RetractCause::Absent => "absent",
            RetractCause::NotOwner => "not_owner",
            RetractCause::NotPublished => "not_published",
        }
    }
}

/// Why a `read_with` entry is refused: the `read_with_refused` token's
/// `detail` (THE VALIDATION's (5)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadWithCause {
    /// `S` is no registered document.
    NotRegistered,
    /// `S` is a member, not a document.
    NotDocument,
    /// `S` is not the caller's.
    NotOwner,
    /// `S` is not published.
    NotPublished,
}

impl ReadWithCause {
    /// Returns the cause's `detail` token.
    pub fn token(self) -> &'static str {
        match self {
            ReadWithCause::NotRegistered => "not_registered",
            ReadWithCause::NotDocument => "not_document",
            ReadWithCause::NotOwner => "not_owner",
            ReadWithCause::NotPublished => "not_published",
        }
    }
}

/// The deposit plan's refusal (the link-sets design §5.7, THE VALIDATION's
/// (3)–(5)): the first fault in list order, naming its entry.
///
/// The lane's tokens (the survey's ruling 8), each a `RejectCode` with a
/// site — the entry's index, or, for a `links` entry's home that is not the
/// caller's, the home's address, `not_owner`'s own site. The slot forms and
/// the class fences answer as `make_link`'s do, with the entry. Built by
/// `plan_deposits` (`writes/publication/plan.rs`), and carried by
/// [`PublicationError::Plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanFault {
    /// A `links` entry's bare home is not the caller's: ω, with the home.
    NotOwner(Address),
    /// A `links` entry's home is neither the tag `member` nor a published
    /// document of the caller's: a private document, a member, an
    /// unregistered address, the edition's tag with no mint.
    LinkHome {
        /// The entry's position in `links`.
        index: usize,
    },
    /// A second `links` entry names one original.
    DuplicateOriginal {
        /// The second entry's position in `links`.
        index: usize,
    },
    /// A `links` entry's stored type slot names the read-with type.
    ReadWithInLinks {
        /// The entry's position in `links`.
        index: usize,
    },
    /// A `links` entry's `old` is refused, the cause named.
    Old {
        /// The entry's position in `links`.
        index: usize,
        /// Which clause refused it.
        cause: OldCause,
    },
    /// A `links` entry's I-span slot holds a span that is no content I-span.
    NotContentSpan {
        /// The entry's position in `links`.
        index: usize,
        /// The slot, in M7's numbering.
        slot: usize,
    },
    /// A `links` entry's slot is past M7's per-slot budget.
    SlotTooLarge {
        /// The entry's position in `links`.
        index: usize,
    },
    /// A `links` entry's type slot is empty.
    EmptyType {
        /// The entry's position in `links`.
        index: usize,
    },
    /// A `links` entry's type slot lands in the retraction class.
    RetractionClass {
        /// The entry's position in `links`.
        index: usize,
    },
    /// A `links` entry's type slot lands in the supersession class.
    SupersessionClass {
        /// The entry's position in `links`.
        index: usize,
    },
    /// A `links` entry's type slot lands in the `replaces` class.
    ReplacesClass {
        /// The entry's position in `links`.
        index: usize,
    },
    /// A `links` entry's type slot lands in the correspondence class.
    CorrespondenceClass {
        /// The entry's position in `links`.
        index: usize,
    },
    /// A `links` entry's member-position end lies outside `[1, placed]`, has
    /// a zero width, or is not canonical; or a tag or the member-position
    /// form stands in its type slot — the codec's refusals, backstops here.
    MemberSpan {
        /// The entry's position in `links`.
        index: usize,
    },
    /// The edition claim names no origin: the request claims, at either
    /// form, with no draft — the codec's refusal, a backstop here.
    ClaimWithoutDraft,
    /// A `retract` entry is refused, the cause named.
    Retract {
        /// The entry's position in `retract`.
        index: usize,
        /// Which clause refused it.
        cause: RetractCause,
    },
    /// A `read_with` entry is refused, the cause named.
    ReadWith {
        /// The entry's position in `read_with`.
        index: usize,
        /// Which clause refused it.
        cause: ReadWithCause,
    },
}

/// The publication's rejection (the link-sets design §5.7): the shot's own
/// verdicts, the twin fence, the deposit plan's, the correspondence records'
/// and the deposits' backstops, and the re-window's.
///
/// In the order the composite answers: at the mint form, the account's
/// registration and ownership (`Publish` carrying `DocNotRegistered` or
/// `NotOwner` with the account) and the edition's mint (`Mint`); the shot's
/// admission through its source gate (`Publish`, M5's verdicts as `publish`
/// states their order, the draft's registration and ownership among them);
/// then THE TWIN FENCE (`AlreadyPublished`), before anything is staged;
/// then THE DEPOSIT PLAN (`Plan`: THE VALIDATION's (3), (4) and (5), the
/// first fault in list order); then the shot's staging (`Publish` again:
/// the re-insert's count, the existence walk, the placement, the member's
/// mint); then, per correspondence record, the deposit gate's home check
/// (`HomeNotRegistered`, `NotOwner`) — a backstop the admission's draft
/// slots make unreachable on the composite's path, reachable through
/// [`stage_correspondence`](crate::stage_correspondence) alone — and the
/// record's mint and seat; then the deposits as planned — each deposit's
/// gate (`NotOwner` on a home the plan did not read, a backstop), its mint
/// and its seat; then THE RE-WINDOW, per `runs` entry that carries a kept
/// place, in `runs`' order: for a stray run the records' read
/// (`StrayPlaceUnrecorded`), the check by identity (`KeptPlaceMoved`), then
/// the placement's own verdicts (`Reinstate`) and the removal's (`Delete`)
/// as the fresh run is put at the place and the draft-native piece taken
/// out behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationError {
    /// The shot's own refusal, as `publish` states it — and, at the mint
    /// form, the account's registration and ownership under its codes.
    Publish(PublishError),
    /// The deposit plan's refusal: a `links`, `retract` or `read_with`
    /// entry, the first fault in list order.
    Plan(PlanFault),
    /// A draft-native run of the request overlaps a span a correspondence
    /// record homed in the draft already names as its `from`: those words
    /// are published already, in the member `site` names — the record's
    /// `to`'s member. Permanent: the record stands for good.
    AlreadyPublished {
        /// The member the record's `to` span was minted into.
        site: Address,
    },
    /// The draft a record is homed in, or a deposit's home, is not a
    /// registered document.
    HomeNotRegistered,
    /// The caller is not the effective owner (ω, exact account match) of
    /// the draft, or of a home a deposit lands in.
    NotOwner(Address),
    /// A mint was refused: a record's or a deposit's link mint, or the
    /// edition's own at the mint form.
    Mint(MintError),
    /// A record's or a deposit's seat in its home's link subspace was
    /// refused.
    Seat(SeatError),
    /// The draft no longer arranges a run's identity at the kept place the
    /// request carries for it (the link-sets design §5.7): since the client
    /// read the place the draft moved the run, split it, deleted it, or
    /// arranges it elsewhere — or arranges its addresses there in another
    /// order. `index` is the `runs` entry the place belongs to. Permanent:
    /// the same request can never land; the client re-reads the draft and
    /// composes the places afresh. Nothing is committed.
    KeptPlaceMoved {
        /// The position in the request's `runs` of the entry whose place the
        /// draft no longer honours.
        index: usize,
    },
    /// A kept place stands beside a run of the document's own identity — a
    /// stray run, re-composed by reference to a correspondence record's
    /// published words (the link-sets design §5.7, THE STRAY PLACES) — and
    /// the records homed in the draft do not name that identity as their
    /// `to`, whole: no record covers the span, or the records covering it
    /// leave a gap. `index` is the `runs` entry. Permanent: a record names
    /// fresh identity once, at the publication that minted it, so no later
    /// commit can cover the span; the client re-reads the draft's records
    /// and re-composes the run by them. Nothing is committed.
    StrayPlaceUnrecorded {
        /// The position in the request's `runs` of the entry whose identity
        /// no record of the draft names whole.
        index: usize,
    },
    /// The re-window's placement of a fresh run at a kept place was refused —
    /// `reinstate`'s own verdict, `PublishedTarget` where the draft named is
    /// a published document, `TooManyRuns` where the draft's run-list is at
    /// its budget; the rest are made unreachable by the check ahead of it.
    Reinstate(ReinstateError),
    /// The re-window's removal of the draft-native piece behind the fresh run
    /// was refused — `delete`'s own verdict, made unreachable but for a
    /// published draft by the check and the placement ahead of it.
    Delete(DeleteError),
}

impl From<PublishError> for PublicationError {
    fn from(e: PublishError) -> Self {
        PublicationError::Publish(e)
    }
}

impl From<PlanFault> for PublicationError {
    fn from(e: PlanFault) -> Self {
        PublicationError::Plan(e)
    }
}

impl From<SeatError> for PublicationError {
    fn from(e: SeatError) -> Self {
        PublicationError::Seat(e)
    }
}

impl From<ReinstateError> for PublicationError {
    fn from(e: ReinstateError) -> Self {
        PublicationError::Reinstate(e)
    }
}

impl From<DeleteError> for PublicationError {
    fn from(e: DeleteError) -> Self {
        PublicationError::Delete(e)
    }
}

/// FOLLOWLINK's ⊥: link or slot absent (§E).
///
/// Distinct from `Ok(⟨⟩)` — a valid-but-empty endset — so `⟨⟩ ≠ ⊥` is
/// unforgeable (F7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid;

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("followlink: link or slot absent (⊥)")
    }
}
impl Error for Invalid {}

impl fmt::Display for MakeLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MakeLinkError::HomeNotRegistered => {
                f.write_str("makelink: home is not a registered Document (L1a)")
            }
            MakeLinkError::NotOwner(_) => {
                f.write_str("makelink: the caller is not home's effective owner (ω)")
            }
            MakeLinkError::IllFormedSpec => f.write_str(
                "makelink: a V-spec is not a registered-source depth-2 content V-position (wf, Conflicts §12)",
            ),
            MakeLinkError::NotContentSpan { slot, index } => write!(
                f,
                "makelink: span {index} of slot {slot} is not a content I-span (a content-subspace element start and an ordinal width of at least 1)"
            ),
            MakeLinkError::SlotTooLarge => write!(
                f,
                "makelink: a slot carries more than {} spans, or its specs command more than {} resolve steps",
                crate::budget::MAX_SLOT_SPANS,
                crate::budget::MAX_SLOT_RESOLVE_STEPS
            ),
            MakeLinkError::EmptyTypeResolution => {
                f.write_str("makelink: the type slot is empty as given (ML6)")
            }
            MakeLinkError::RetractionClass => {
                f.write_str("makelink: ty ~ [R] — retraction writes only through nullify (K ≁ R)")
            }
            MakeLinkError::SupersessionClass => f.write_str(
                "makelink: ty ~ [K_sup] — supersession writes only through assert_sup/editlink",
            ),
            MakeLinkError::ReplacesClass => f.write_str(
                "makelink: ty ~ replaces — the authority successor writes only through a record's own makelink_replacing",
            ),
            MakeLinkError::CorrespondenceClass => f.write_str(
                "makelink: ty ~ correspondence — the publish shot's record class writes only through the shot's own mint",
            ),
            MakeLinkError::Mint(e) => write!(f, "makelink: mint failed: {e}"),
            MakeLinkError::Seat(e) => write!(f, "makelink: seat refused: {e}"),
        }
    }
}
impl Error for MakeLinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            MakeLinkError::Mint(e) => Some(e),
            MakeLinkError::Seat(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmitError::HomeNotRegistered => {
                f.write_str("emit: home is not a registered Document (P0)")
            }
            EmitError::NotOwner(_) => {
                f.write_str("emit: the caller is not home's effective owner (ω)")
            }
            EmitError::NotRegistered => f.write_str("emit: ty's coverage class is not registered"),
            EmitError::ShapeViolation => {
                f.write_str("emit: span counts violate the registered shape (P3)")
            }
            EmitError::RetractionClass => {
                f.write_str("emit: ty ~ [R] — retraction writes only through nullify (K ≁ R)")
            }
            EmitError::SupersessionClass => f.write_str(
                "emit: ty ~ [K_sup] — supersession writes only through assert_sup/editlink (Conflicts §10)",
            ),
            EmitError::ReplacesClass => f.write_str(
                "emit: ty ~ replaces — the authority successor writes only through a record's own makelink_replacing",
            ),
            EmitError::CorrespondenceClass => f.write_str(
                "emit: ty ~ correspondence — the publish shot's record class writes only through the shot's own mint",
            ),
            EmitError::NonAddressDenotingType => {
                f.write_str("emit: ty is not address-denoting (rejected before class computation)")
            }
            EmitError::SlotTooLarge => write!(
                f,
                "emit: to or ty carries more than {} spans",
                crate::budget::MAX_SLOT_SPANS
            ),
            EmitError::Mint(e) => write!(f, "emit: mint failed: {e}"),
        }
    }
}
impl Error for EmitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EmitError::Mint(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for NullifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NullifyError::HomeNotRegistered => {
                f.write_str("nullify: home is not a registered Document (P0)")
            }
            NullifyError::NotOwner(_) => f.write_str(
                "nullify: the caller is not the effective owner (ω) of the home or target link",
            ),
            NullifyError::BadTarget => f.write_str(
                "nullify: target is neither a resident link nor the address this call's own retraction tuple would occupy (P-tgt)",
            ),
            NullifyError::Mint(e) => write!(f, "nullify: mint failed: {e}"),
        }
    }
}
impl Error for NullifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NullifyError::Mint(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for AssertSupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssertSupError::HomeNotRegistered => {
                f.write_str("assert_sup: home is not a registered Document (P0)")
            }
            AssertSupError::NotOwner(_) => {
                f.write_str("assert_sup: the caller is not home's effective owner (ω)")
            }
            AssertSupError::EndpointNotResident => {
                f.write_str("assert_sup: old or new is not a resident link")
            }
            AssertSupError::SelfSupersession => {
                f.write_str("assert_sup: old == new (Df-DISC(ii) irreflexivity)")
            }
            AssertSupError::Mint(e) => write!(f, "assert_sup: mint failed: {e}"),
        }
    }
}
impl Error for AssertSupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AssertSupError::Mint(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for EditLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditLinkError::OriginalNotResident => {
                f.write_str("editlink: original is not a resident link")
            }
            EditLinkError::HomeNotRegistered => {
                f.write_str("editlink: d_s or d_a is not a registered Document")
            }
            EditLinkError::NotOwner(_) => {
                f.write_str("editlink: the caller is not the effective owner (ω) of d_s or d_a")
            }
            EditLinkError::SlotTooLarge => write!(
                f,
                "editlink: a successor slot carries more than {} spans",
                crate::budget::MAX_SLOT_SPANS
            ),
            EditLinkError::IllFormedSuccessor => f.write_str(
                "editlink: successor arity ≠ 3, empty type slot, or a non-level-uniform span in some slot (Conflicts §11)",
            ),
            EditLinkError::DcViolation => f.write_str(
                "editlink: DC — retraction-, replaces- or correspondence-typed successor, or schema-non-conforming [K_sup]-typed successor",
            ),
            EditLinkError::Mint(e) => write!(f, "editlink: mint failed: {e}"),
        }
    }
}
impl Error for EditLinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EditLinkError::Mint(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for PlanFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanFault::NotOwner(_) => f.write_str("a links entry's home is not the caller's (ω)"),
            PlanFault::LinkHome { index } => write!(
                f,
                "links[{index}]: the home is neither the member nor a published document of the caller's"
            ),
            PlanFault::DuplicateOriginal { index } => {
                write!(f, "links[{index}]: a second copy of one original")
            }
            PlanFault::ReadWithInLinks { index } => write!(
                f,
                "links[{index}]: the type names the read-with, which a publication writes through read_with alone"
            ),
            PlanFault::Old { index, cause } => {
                write!(f, "links[{index}]: old is refused: {}", cause.token())
            }
            PlanFault::NotContentSpan { index, slot } => {
                write!(f, "links[{index}]: a span of slot {slot} is not a content I-span")
            }
            PlanFault::SlotTooLarge { index } => write!(
                f,
                "links[{index}]: a slot carries more than {} spans",
                crate::budget::MAX_SLOT_SPANS
            ),
            PlanFault::EmptyType { index } => write!(f, "links[{index}]: the type slot is empty"),
            PlanFault::RetractionClass { index } => {
                write!(f, "links[{index}]: ty ~ [R] — retraction writes only through nullify")
            }
            PlanFault::SupersessionClass { index } => write!(
                f,
                "links[{index}]: ty ~ [K_sup] — supersession writes only through assert_sup/editlink"
            ),
            PlanFault::ReplacesClass { index } => write!(
                f,
                "links[{index}]: ty ~ replaces — the authority successor has one writer"
            ),
            PlanFault::CorrespondenceClass { index } => write!(
                f,
                "links[{index}]: ty ~ correspondence — the shot's record class has one writer"
            ),
            PlanFault::MemberSpan { index } => write!(
                f,
                "links[{index}]: a member-position end lies outside [1, placed] or is not canonical, or a type slot takes no tag and no member positions"
            ),
            PlanFault::ClaimWithoutDraft => {
                f.write_str("claim: the edition claim names the staging draft, and the request names none")
            }
            PlanFault::Retract { index, cause } => {
                write!(f, "retract[{index}]: refused: {}", cause.token())
            }
            PlanFault::ReadWith { index, cause } => {
                write!(f, "read_with[{index}]: refused: {}", cause.token())
            }
        }
    }
}
impl Error for PlanFault {}

impl fmt::Display for PublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // This layer only — the shot's own words are the `source`.
            PublicationError::Publish(_) => f.write_str("publication: the shot refused"),
            PublicationError::Plan(_) => f.write_str("publication: a deposit the request names is refused"),
            PublicationError::AlreadyPublished { .. } => f.write_str(
                "publication: a draft-native run of the request is already published — a correspondence record homed in the draft names its words",
            ),
            PublicationError::HomeNotRegistered => {
                f.write_str("publication: the draft a record is homed in is not a registered Document")
            }
            PublicationError::NotOwner(_) => {
                f.write_str("publication: the caller is not the draft's effective owner (ω)")
            }
            PublicationError::Mint(e) => write!(f, "publication: a record's mint failed: {e}"),
            PublicationError::Seat(e) => write!(f, "publication: a record's seat refused: {e}"),
            PublicationError::KeptPlaceMoved { index } => write!(
                f,
                "publication: the draft no longer arranges run {index}'s identity at the kept place the request carries for it"
            ),
            PublicationError::StrayPlaceUnrecorded { index } => write!(
                f,
                "publication: no correspondence record of the draft names run {index}'s identity whole as its published words, so its kept place re-windows nothing"
            ),
            PublicationError::Reinstate(e) => write!(f, "publication: the re-window's placement refused: {e}"),
            PublicationError::Delete(e) => write!(f, "publication: the re-window's removal refused: {e}"),
        }
    }
}
impl Error for PublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PublicationError::Publish(e) => Some(e),
            PublicationError::Plan(e) => Some(e),
            PublicationError::Mint(e) => Some(e),
            PublicationError::Seat(e) => Some(e),
            PublicationError::Reinstate(e) => Some(e),
            PublicationError::Delete(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for NotBh4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("stale: ty is not registered with BH4 (Age) — served only where declared (§7)")
    }
}
impl Error for NotBh4 {}

impl fmt::Display for RetractStaleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RetractStaleError::NotBh4 => f.write_str(
                "retract_stale: ty is not registered with BH4 (Age) — served only where declared (§7)",
            ),
            RetractStaleError::Nullify(e) => write!(f, "retract_stale: {e}"),
        }
    }
}
impl Error for RetractStaleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RetractStaleError::Nullify(e) => Some(e),
            _ => None,
        }
    }
}
