//! Typed rejection (the never-silent contract) and its classification (§5).
//!
//! It holds [`Rejection`], the flat deduped [`RejectCode`] union, the
//! advisory [`Disposition`] hint and its policy table, and the localized
//! [`FaultSite`]. The one rejection built for a frame that never parsed,
//! `Rejection::unparseable`, lives beside the codec that raises it, in
//! `codec`.

use std::{fmt, io};

use skep_address::Address;
use skep_retrieval::{Operand, SpanFault};

use crate::request::OpKind;

/// A typed, classified rejection.
///
/// `code` is authoritative; `disposition` is an advisory Lampson hint
/// (recomputable); `site` localizes span/operand/document faults; `detail` is
/// an optional message (ASN-0134 rejection path, OQ8).
///
/// For every rejection M10 produces: `disposition == code.disposition()`,
/// and `detail` is `code`'s standing explanation — the fixed sentence a code
/// that means the same thing every time it fires carries — unless a call site
/// threaded one of its own. [`Rejection::classified`] applies both policies
/// off the flat code and is the constructor that holds them.
///
/// The fields are public, so that pairing is a property of the rejections M10
/// builds rather than of the type: a caller assembling the struct by hand
/// answers for it. That is why the classifying constructor and
/// [`RejectCode::disposition`] are both published — a caller raising one of
/// these codes on its own channel can apply M10's policy instead of
/// transcribing it.
///
/// A value, with value equality, so a caller may keep one (the last refusal
/// per operation, say) and compare it against another. Equality is over all
/// six fields, `detail` and `io_kind` included: two rejections agreeing on
/// op/code/disposition/site but carrying different messages are different
/// answers to an operator, and compare unequal. `Hash` agrees with that
/// equality, so a transport may key by a whole rejection — per-`(op, code)`
/// tallies, a set of the distinct refusals a client has met — as it already
/// keys by a bare [`RejectCode`].
///
/// `#[must_use]`: a rejection is an answer owed to a client, so building one
/// and dropping it is the silence this module exists to prevent.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rejection {
    /// The operation refused.
    pub op: OpKind,
    /// The authoritative refusal code.
    pub code: RejectCode,
    /// The advisory hint on reissuing, recomputable from `code`.
    pub disposition: Disposition,
    /// Where in the request the fault landed, or which document it is about.
    pub site: Option<FaultSite>,
    /// Any message: `code`'s standing explanation, or one a call site threaded.
    ///
    /// It is marshaled — the client reads it, as it never reads `io_kind` —
    /// so nothing threads into it what a client may not read: the I/O text a
    /// `Durability` refusal carries is the kernel's account of the file and
    /// the act, which names no path (PATTERNS SP-13).
    pub detail: Option<String>,
    /// The I/O kind behind a `Durability` refusal, for the daemon alone.
    ///
    /// The kernel's journal append and barrier, its segment rotation and its
    /// salt's entropy refusal all lower to the one code with the OS text as
    /// `detail`, and the text is no contract — so the kind rides beside it,
    /// `Some` on exactly the rejections `lower_txn` builds from
    /// `TxnError::Durability` and `None` on every other. The daemon's write
    /// path reads it to tell a full volume (`StorageFull`) from any other
    /// durability failure and say so on its operator stream; it is never
    /// marshaled — the transport's codec reads the five members above by name
    /// and the wire's rejection carries them alone — and `Display` does not
    /// render it, so no client sees it and nothing in a log line changes with
    /// it (the operations design §1.1 m1: "set at `lower_txn`, read by the
    /// daemon and never marshaled").
    pub io_kind: Option<io::ErrorKind>,
}

/// The advisory half of a rejection: what reissuing would be worth.
///
/// `code` is authoritative and this is a hint, recomputed off it by
/// [`RejectCode::disposition`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Disposition {
    /// Reissuing the identical request cannot help.
    Permanent,
    /// The referent the request named may yet arrive.
    ///
    /// A client that raced its own prerequisite may reissue once that
    /// prerequisite commits.
    Reorder,
    /// The operation did nothing, and this same request may succeed unchanged.
    ///
    /// It may because the code is one many transient faults share — but where
    /// the cause is the volume's room (the journal's append or barrier failed
    /// on a full volume) no reissue succeeds until the operator frees it,
    /// which the operator stream names; the client's act is then to say so,
    /// never to reissue blindly.
    Retry,
    /// The kernel stopped accepting writes.
    ///
    /// Reads are still served.
    Halt,
}

/// Where a multi-part request's fault landed, or which document it concerns.
///
/// Each field below names every producer that fills it; a refusal none of
/// them names carries `site = None` (§5) — among them every fieldless
/// `DocNotRegistered` (M5's, M8's, and M6's single-document ones), M10's own
/// registration refusal for the two publication reads that take a document
/// and the content-frontier read (each names exactly one, so the client
/// already knows which address was refused), and the link-address absence
/// answers (`OriginalNotResident`, `EndpointNotResident`), which match a
/// never-deposited address's exactly.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct FaultSite {
    /// Which COMPARE spec-set (ρ₁/ρ₂) the fault came from.
    ///
    /// M6's alone.
    pub operand: Option<Operand>,
    /// The offending region index (COMPARE / FINDDOCSCONTAINING).
    ///
    /// M6's alone.
    pub region: Option<usize>,
    /// The offending link slot of an EDITLINK successor, in M7's numbering.
    ///
    /// The numbering is [`FROM`]/[`TO`]/[`TYPE`], re-exported by this crate,
    /// so the `index` beside it is read as a position within that slot.
    /// Filled by M10's successor guard, which is the only place M10 builds a
    /// slot for itself (§4). Every refusal that guard raises names its slot.
    ///
    /// [`FROM`]: crate::FROM
    /// [`TO`]: crate::TO
    /// [`TYPE`]: crate::TYPE
    pub slot: Option<usize>,
    /// The offending spec/span index, within the innermost container named.
    ///
    /// It counts within the innermost container the other fields name: within
    /// the slot where `slot` is present, else within the region `region` (and,
    /// for COMPARE, `operand`) names, else within the request's own top-level
    /// list — RETRIEVEV's `specs` or RETRIEVEI's `spans`. So the fields are
    /// read together, and an `index` alone always has exactly one container.
    /// Filled by M6's per-spec and per-span refusals, by M10's successor guard
    /// for a per-spec refusal, and by the doc-argument consult's refusal of a
    /// RETRIEVEI span's shape; the guard's `SlotTooLarge` names its slot and
    /// no index, the slot rather than one spec being at fault.
    pub index: Option<usize>,
    /// The span well-formedness fault.
    ///
    /// M6's alone.
    pub fault: Option<SpanFault>,
    /// The document — or link — the code is about.
    ///
    /// It comes from three families: M6's multi-document
    /// `DocNotRegistered(Address)`
    /// (RetrieveError/DeletionsError/CompareError/FindError); every ω-gated
    /// write's `NotOwner(Address)`, M5's and M7's, naming the document or
    /// target link that failed the ω check; and every `Withheld` — M10's
    /// doc-argument consult and source consult, and M5's publish shot —
    /// naming the first unreadable document in declaration order (PUB-8.4's
    /// pinned `site.addr`).
    pub addr: Option<Address>,
}

/// The deduped union of every store error variant plus M10's own (§5).
///
/// Flat and `Copy`, keyed by the disposition table. Built mechanically: each
/// store error enum lowers to `(RejectCode, Option<FaultSite>)` via the
/// `Lower` trait, whose one table of impls is the `lower` module's.
///
/// `Hash`, so a caller may key by it: per-code counters are the first thing
/// a transport instruments this surface with, and only this crate can supply
/// the impl. Not `#[non_exhaustive]`, for [`Op`]'s reason.
///
/// [`Op`]: crate::Op
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RejectCode {
    // ── M10-originated ──
    /// A write under a session that resolves to no principal.
    Unauthenticated,
    /// A frame that never parsed, or an op handed to the other dispatch table.
    Malformed,
    /// The transaction could not be made durable, and nothing of it stands.
    Durability,
    /// The kernel could not turn the staged records into journal frames.
    TxnUnencodable,
    /// The transaction encodes past the journal's per-transaction budget.
    TxnOverBudget,
    /// The kernel has halted its write paths.
    Poisoned,
    // ── registration / residence (M3/M5/M7/M8; the content queries and this
    //    crate's own checks raise some too) ──
    /// A write's home is not a registered document.
    HomeNotRegistered,
    /// A document the request names is not a registered document.
    DocNotRegistered,
    /// A source the operation reads is not a registered document.
    SourceNotRegistered,
    /// A delegated prefix's parent is not a registered entity.
    ParentNotRegistered,
    /// An emit's type names no registered coverage class.
    NotRegistered,
    /// The link an edit supersedes is not resident.
    OriginalNotResident,
    /// A supersession claim's `old` or `new` is not a resident link.
    EndpointNotResident,
    // ── M3 namespace / authority ──
    /// The caller is not the effective owner (ω) the write requires.
    NotOwner,
    /// A document mint's target is not a registered account.
    NotAnAccount,
    /// The inc gate refused a mint, a defect no store state reaches.
    Gate,
    /// The delegator id names no principal.
    DelegatorUnknown,
    /// A delegation's new id is already carried by a principal.
    DuplicateId,
    /// The delegator's prefix is not a strict ancestor of the new prefix.
    NotAncestor,
    /// The delegator is not the effective owner (ω) of the new prefix.
    NotAuthorized,
    /// A delegated prefix is not account-tier.
    NotAccountTier,
    /// A principal already sits strictly under the new prefix.
    NotTopDown,
    /// A delegated prefix is not the namespace's next address.
    NotNextForm,
    /// A delegated prefix or an admitted node address is not T4-valid.
    NotValid,
    /// An admitted node address is not node-level.
    NotNode,
    /// A delegated prefix or an admitted node address has too many components.
    TooDeep,
    /// An admitted node address lies outside the bootstrap lineage `[1]`.
    NotDescendantOfBootstrap,
    /// The delegated prefix or the admitted node is already allocated.
    NotFresh,
    // ── M5 arrangement ──
    /// An insert carries no values.
    EmptyContent,
    /// The content store refused a write; every cause lowers to this one code.
    Content,
    /// A copy spec's source arranges no content.
    EmptySource,
    /// A copy spec's span is not an ordinal V-span.
    NotOrdinalVSpan,
    /// An address a placed run names holds no stored value.
    DanglingSource,
    /// A placement, or the walk resolving its specs, exceeds its budget.
    TooManyRuns,
    /// A publish shot exceeds its re-insert budget.
    ///
    /// The draft-native runs' widths, summed, exceed M5's
    /// `MAX_REINSERTED_VALUES` (arithmetic on the request; discloses nothing
    /// about what exists). Its own leaf rather than a ride on `TooManyRuns`:
    /// the re-inserted values are I-adjacent and coalesce, so a shot refused
    /// here may place a single run. Permanent by the catch-all, for
    /// `TooManyRuns`'s reason: a shot cannot be split to meet it.
    TooManyValues,
    /// The net placement is empty, or a reinstate names no run.
    EmptyResult,
    /// A delete's start names no arranged content position.
    NotArranged,
    /// A position or range lies outside the bounds its operation admits.
    OutOfBounds,
    /// A width is zero.
    EmptyWidth,
    /// A rearrange holds neither three cuts nor four.
    BadCutCount,
    /// A rearrange's cuts are not strictly ascending.
    NotAscending,
    /// A rearrange's document has an empty content subspace.
    EmptyContentSubspace,
    /// A `version`'s caller names no registered principal.
    NotAPrincipal,
    /// A cross-owner fork whose forker's prefix is not a registered account.
    NodeTierCrossOwner,
    /// A link being seated is not a full element position in the link subspace.
    NotLinkAddress,
    /// A link being seated is not homed in the document it is seated in.
    NotHomeLink,
    /// The link is already seated in its document's link subspace.
    AlreadySeated,
    /// A position, span or cut is not in the content subspace.
    NotContentSubspace,
    // ── M5 arrangement: the version-chain model's three write-path
    //    refusals (PUB-kickoff D2b). Each is a permanent class (PUB-8.3's
    //    idiom); the faces are pinned verbatim at PUB-2.11's table and are
    //    the client's to render, keyed on the code (PUB-6.7) —
    //    `private_source_versionless`'s splitting on the flag the client
    //    itself sent, the code staying one. ──
    /// PUB-2.11: an in-place arrangement edit on a published target.
    ///
    /// The edits are `insert`, `copy`-into, `reinstate`, `delete` and
    /// `rearrange`; a declared deposit at fresh positions is the one insert it
    /// admits (PUB-2.59, PUB-9.13).
    PublishedTarget,
    /// PUB-2.7: a private `version` of a published source the caller owns.
    ///
    /// It is the explicit-`false` arm; absent inherits (PUB-2.8).
    PrivateVersionOfPublished,
    /// PUB-2.9: a `version` on a private source the caller owns.
    ///
    /// Whatever the flag: private documents are versionless. Also the publish
    /// shot's refusal on a private document: a shot appends a version, and
    /// the face is this code's `true` arm — publishing means minting a
    /// separate edition.
    PrivateSourceVersionless,
    // ── M5 arrangement: the publish shot. The source gate's `withheld` is
    //    the one code here whose disposition is not `Permanent`: it is
    //    `Reorder` in every cell (PUB-8.4, PUB-8.6), names the withheld
    //    document in `site.addr` and carries no `detail` (PUB-8.5). The four
    //    request-shape refusals beside it are the shot's, permanent, and
    //    `BadRun` is the write by identity's too. ──
    /// PUB-6.23 / PUB-8.1 / PUB-8.4: a shot's run windows an unreadable origin.
    ///
    /// The shooter may not read that origin, and `site.addr` is its document.
    /// The front door's two consults answer it too, naming the first
    /// unreadable document a read names or derives, or a write reads.
    Withheld,
    /// A supplied run is not a content run of its stated origin.
    ///
    /// Address arithmetic on the request; discloses nothing about what exists.
    BadRun,
    /// The base is neither the document nor a member of its chain (PUB-2.37).
    BaseNotInChain,
    /// The base is absent or the document itself while a member exists.
    ///
    /// The document's pre-chain arrangement is no base (PUB-2.34, PUB-2.66).
    BaseSuperseded,
    /// The base extent exceeds the base's current content count.
    BaseExtentTooLarge,
    // ── M7 link ──
    /// A `Resolve` V-spec fails its well-formedness check.
    IllFormedSpec,
    /// A link slot is over a per-slot budget.
    SlotTooLarge,
    /// A make_link's type slot is empty as given.
    EmptyTypeResolution,
    /// An emit's span counts violate its class's registered shape.
    ShapeViolation,
    /// A type slot lands in the retraction class, which only `nullify` writes.
    RetractionClass,
    /// An emit's type is not address-denoting.
    NonAddressDenotingType,
    /// A nullify's target is not a resident link.
    BadTarget,
    /// A supersession claim names one link as both `old` and `new`.
    SelfSupersession,
    /// An edit's successor link is ill-formed.
    IllFormedSuccessor,
    /// A type slot breaks a sole-writer fence or the DC guard's claim schema.
    DcViolation,
    // ── M6 content/provenance read (MalformedSpan also covers
    //    RetrieveError::MalformedSpec; the last four are M6's own budget
    //    refusals — two for COMPARE, whose join squares in the request, one
    //    for FINDDOCSCONTAINING, whose coverage is the multiplier it applies
    //    to two world-sized scans, and one for RETRIEVEV, whose delivery is
    //    sized by a virtual extent no request field prices; every one but
    //    `TooManyPairs` also refuses its operation's run-list walk past M6's
    //    walk budget. This crate raises `TooManyItems` for RETRIEVEI too, on
    //    its spans' widths) ──
    /// A span's start subspace is neither the content nor the link subspace.
    NoSuchSubspace,
    /// A real subspace has no occupied positions.
    EmptySubspace,
    /// A span's depth is not its subspace's common depth.
    DepthIncompatible,
    /// A span names positions not all currently bound.
    RangeNotPresent,
    /// A span fails span well-formedness; `site.fault` says how.
    MalformedSpan,
    /// A COMPARE operand's resolution or walk exceeds its budget.
    TooManyBlocks,
    /// A COMPARE join runs past its correspondence budget.
    TooManyPairs,
    /// A FINDDOCSCONTAINING resolution or walk exceeds its budget.
    TooMuchCoverage,
    /// A delivery, or the walk behind it, exceeds its budget.
    TooManyItems,
    // ── M8 link discovery read (the last two are M8's own budget refusals —
    //    one for the arrangement runs a request materializes or joins
    //    against, one for the spans a RETRIEVEENDSETS answer carries) ──
    /// No visible link occupies the address, or the slot is past its arity.
    NotALink,
    /// A region span is not the shape a content V-span takes.
    BadRegion,
    /// A read would materialize or join more arrangement runs than its budget.
    ImageTooLarge,
    /// A RETRIEVEENDSETS answer would carry more spans than its budget.
    EndsetsTooLarge,
}

/// The fixed detail a `Gate` rejection carries (§5).
///
/// Its words name a corrupted frontier, an operator condition. M3 documents
/// `MintError::Gate` as defensive: no store state reaches it, corrupted or
/// not, and it fires only if a mint's own structural gate regresses — a
/// defect in the minting code — and never on a well-formed request against a
/// healthy store.
const GATE_DETAIL: &str = "inc-gate tripped: corrupted frontier — operator condition";

/// The code's two per-code policies (§5), each a total lookup off the code.
///
/// They are the disposition, public, and the standing explanation
/// [`Rejection::classified`] attaches.
impl RejectCode {
    /// Returns the code's disposition: a single total lookup off it (§5).
    ///
    /// It answers exactly the explicit `Reorder`/`Retry`/`Halt` cases and
    /// defaults everything else to `Permanent` (the catch-all is the designed
    /// shape here: a code absent from the table is `Permanent` by
    /// construction).
    ///
    /// Public because the disposition is documented as recomputable, and a
    /// hint nobody outside the crate can recompute is one a transport
    /// transcribes instead: a caller raising one of these codes on its own
    /// channel asks here and cannot drift from the row
    /// [`Rejection::classified`] applies.
    ///
    /// Named `Permanent` calls (not left to the catch-all by accident — §5):
    /// `NotRegistered` (genesis-immutable registry), `NotFresh` (append-only
    /// allocations), `Gate` (a minting defect, which its detail calls store
    /// corruption), `TxnOverBudget` (M2's per-transaction byte budget — no
    /// retry shrinks a transaction; the client splits it), `TxnUnencodable`
    /// (a record M2 could not frame, its serializer refusing it or the frame
    /// cap — the same request re-presented stages the same record), the
    /// recovery-steering `NotNextForm` (re-derive via `NextAccountPrefix`, a
    /// *different* request), and the version-chain model's three refusals
    /// `PublishedTarget` / `PrivateVersionOfPublished` /
    /// `PrivateSourceVersionless` (PUB-8.3's "permanent class": publication
    /// never transitions, PUB-1.9, so the same request can never land — the
    /// act that does is another request, the one the face names).
    ///
    /// `Withheld` is `Reorder` in every cell (PUB-8.4, PUB-8.6): the one
    /// filling event is a later grant commit, and the wire token stays
    /// `reorder` wherever no such event can exist — the face derives the
    /// honest answer. The conservatively-`Permanent` state-dependent codes
    /// (`NotArranged`, `OutOfBounds`, `EmptySource`, `EmptyContentSubspace`,
    /// `RangeNotPresent`, `EmptySubspace`, `DelegatorUnknown`,
    /// `NotAPrincipal`, …) are the documented heuristic split of Open build
    /// decision 7.
    pub fn disposition(self) -> Disposition {
        match self {
            RejectCode::Poisoned => Disposition::Halt,
            RejectCode::Durability => Disposition::Retry,
            RejectCode::BadTarget
            | RejectCode::DocNotRegistered
            | RejectCode::HomeNotRegistered
            | RejectCode::SourceNotRegistered
            | RejectCode::NotAnAccount
            | RejectCode::OriginalNotResident
            | RejectCode::EndpointNotResident
            | RejectCode::ParentNotRegistered
            | RejectCode::Withheld => Disposition::Reorder,
            _ => Disposition::Permanent,
        }
    }

    /// Returns the code's standing explanation, if it carries one (§5).
    ///
    /// It is the second total lookup off the flat code, beside
    /// [`RejectCode::disposition`]. A code whose meaning is the same sentence
    /// every time it fires carries that sentence here rather than at
    /// whichever call site happened to raise it; everything else carries no
    /// detail unless a call site threads one (`Rejection::with_detail`).
    ///
    /// `Gate` is the one such code: its sentence names store corruption — an
    /// operator condition — though only a minting defect reaches it, and
    /// never client error.
    fn fixed_detail(self) -> Option<&'static str> {
        match self {
            RejectCode::Gate => Some(GATE_DETAIL),
            _ => None,
        }
    }
}

impl Rejection {
    /// Builds a classified rejection, both per-code policies applied (§5).
    ///
    /// Both come off the flat code: the disposition from
    /// [`RejectCode::disposition`], and the standing explanation the code
    /// carries by policy, when it carries one.
    ///
    /// Public for the reason [`RejectCode::disposition`] is: a caller that
    /// raises one of M10's codes on its own channel builds it here and gets
    /// the whole classification, rather than transcribing half of it and
    /// drifting from the rows every other rejection of that code is given.
    pub fn classified(kind: OpKind, code: RejectCode, site: Option<FaultSite>) -> Rejection {
        let detail = code.fixed_detail().map(str::to_string);
        Rejection { op: kind, code, disposition: code.disposition(), site, detail, io_kind: None }
    }

    /// Attaches a detail message (§5).
    ///
    /// The `Durability` arm threads the underlying `io::Error` text so an
    /// operator sees the cause behind the `Retry` hint.
    pub(crate) fn with_detail(mut self, d: String) -> Rejection {
        self.detail = Some(d);
        self
    }

    /// Attaches the I/O kind behind a `Durability` refusal.
    ///
    /// It is `with_detail`'s shape, for the member beside `detail`. Called at
    /// one site outside the tests, the `Durability` arm of `lower_txn`, which
    /// is what keeps [`Rejection::io_kind`]'s "`Some` on exactly the
    /// rejections `lower_txn` builds from `TxnError::Durability`" true.
    pub(crate) fn with_io_kind(mut self, kind: io::ErrorKind) -> Rejection {
        self.io_kind = Some(kind);
        self
    }
}

/// Formats an operator-facing line for the rejection.
///
/// The line names the op that was refused, the authoritative code, the
/// advisory disposition, and the detail when the rejection carries one. Not
/// the I/O kind: the detail already carries the OS text, and the kind is the
/// daemon's to read and put into words of its own ([`Rejection::io_kind`]).
///
/// The codes render through their own `Debug` spelling, not a table of wire
/// strings: the wire vocabulary is the transport's (skep-core's `code_name`,
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

/// Has no `source`: a rejection holds a classification, not the error.
///
/// The lowering table flattens each upstream error into a [`RejectCode`] and
/// a [`FaultSite`], so a rejection holds a classification rather than the
/// error it came from — there is nothing to return.
impl std::error::Error for Rejection {}

/// Returns a bare `Rejection` for dispatch arms (§5).
pub(crate) fn rejection(kind: OpKind, code: RejectCode) -> Rejection {
    Rejection::classified(kind, code, None)
}

#[cfg(test)]
mod tests;
