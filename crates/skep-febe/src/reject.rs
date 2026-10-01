//! Typed rejection (the never-silent contract): [`Rejection`], the flat
//! deduped [`RejectCode`] union, the advisory [`Disposition`] hint and its
//! policy table, and the localized [`FaultSite`] (§5). The one rejection
//! built for a frame that never parsed, `Rejection::unparseable`, lives
//! beside the codec that raises it, in `codec`.

use std::fmt;

use skep_address::Address;
use skep_retrieval::{Operand, SpanFault};

use crate::request::OpKind;

/// A typed, classified rejection. `code` is authoritative; `disposition` is
/// an advisory Lampson hint (recomputable); `site` localizes span/operand/
/// document faults; `detail` is an optional message (ASN-0134 rejection path,
/// OQ8).
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
/// five fields, `detail` included: two rejections agreeing on op/code/
/// disposition/site but carrying different messages are different answers to
/// an operator, and compare unequal. `Hash` agrees with that equality, so a
/// transport may key by a whole rejection — per-`(op, code)` tallies, a set
/// of the distinct refusals a client has met — as it already keys by a bare
/// [`RejectCode`].
///
/// `#[must_use]`: a rejection is an answer owed to a client, so building one
/// and dropping it is the silence this module exists to prevent.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rejection {
    pub op: OpKind,
    pub code: RejectCode,
    pub disposition: Disposition,
    pub site: Option<FaultSite>,
    pub detail: Option<String>,
}

/// The advisory half of a rejection: what reissuing would be worth. `code` is
/// authoritative and this is a hint, recomputed off it by
/// [`RejectCode::disposition`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Disposition {
    /// Reissuing the identical request cannot help.
    Permanent,
    /// The referent the request named may yet arrive: a client that raced its
    /// own prerequisite may reissue once that prerequisite commits.
    Reorder,
    /// The fault was transient — an I/O hiccup, and the operation did
    /// nothing — so this same request may succeed unchanged.
    Retry,
    /// The kernel stopped accepting writes. Reads are still served.
    Halt,
}

/// Where in a multi-part request a fault landed, or which document a code is
/// about. Each field below names every producer that fills it; a refusal none
/// of them names carries `site = None` (§5) — among them every fieldless
/// `DocNotRegistered` (M5's, M8's, and M6's single-document ones), M10's own
/// registration refusal for the two publication reads that take a document
/// (each names exactly one, so the client already knows which address was
/// refused), and the link-address absence answers (`OriginalNotResident`,
/// `EndpointNotResident`), which match a never-deposited address's exactly.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct FaultSite {
    /// Which COMPARE spec-set (ρ₁/ρ₂) the fault came from. M6's alone.
    pub operand: Option<Operand>,
    /// The offending region index (COMPARE / FINDDOCSCONTAINING). M6's alone.
    pub region: Option<usize>,
    /// The offending link slot of an EDITLINK successor, in M7's slot
    /// numbering — [`FROM`]/[`TO`]/[`TYPE`], re-exported by this crate — so
    /// the `index` beside it is read as a position WITHIN that slot. Filled
    /// by M10's successor guard, which is the only place M10 builds a slot
    /// for itself (§4). Every refusal that guard raises names its slot.
    ///
    /// [`FROM`]: crate::FROM
    /// [`TO`]: crate::TO
    /// [`TYPE`]: crate::TYPE
    pub slot: Option<usize>,
    /// The offending spec/span index, counted within the innermost container
    /// the other fields name: within the slot where `slot` is present, else
    /// within the region `region` (and, for COMPARE, `operand`) names, else
    /// within the request's own top-level list — RETRIEVEV's `specs`. So the
    /// fields are read together, and an `index` alone always has exactly one
    /// container. Filled by M6's per-spec and per-span refusals, and by M10's
    /// successor guard for a per-spec refusal; the guard's `SlotTooLarge`
    /// names its slot and no index, the slot rather than one spec being at
    /// fault.
    pub index: Option<usize>,
    /// The span well-formedness fault. M6's alone.
    pub fault: Option<SpanFault>,
    /// The document — or link — the code is about, from three families: M6's
    /// multi-document `DocNotRegistered(Address)`
    /// (RetrieveError/DeletionsError/CompareError/FindError); every ω-gated
    /// write's `NotOwner(Address)`, M5's and M7's (the ownership ruling,
    /// 2026-08-16), naming the document or target link that failed the ω
    /// check; and every `Withheld` — M10's doc-argument consult and source
    /// consult, and M5's publish shot — naming the first unreadable document
    /// in declaration order (PUB-8.4's pinned `site.addr`).
    pub addr: Option<Address>,
}

/// The deduped union of every store error variant plus M10's own — flat &
/// `Copy`, keyed by the disposition table (§5). Built mechanically: each
/// store error enum lowers to `(RejectCode, Option<FaultSite>)` via the
/// crate-internal `Lower` trait.
///
/// `Hash`, so a caller may key by it: per-code counters are the first thing
/// a transport instruments this surface with, and only this crate can supply
/// the impl. Not `#[non_exhaustive]`, for [`Op`]'s reason.
///
/// [`Op`]: crate::Op
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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
    NotOrdinalVSpan,
    DanglingSource,
    TooManyRuns,
    /// The publish shot's re-insert budget: the draft-native runs' widths,
    /// summed, exceed M5's `MAX_REINSERTED_VALUES` (arithmetic on the
    /// request; discloses nothing about what exists). Its own leaf rather
    /// than a ride on `TooManyRuns`: the re-inserted values are I-adjacent and
    /// coalesce, so a shot refused here may place a single run. Permanent by
    /// the catch-all, for `TooManyRuns`'s reason: a shot cannot be split to
    /// meet it.
    TooManyValues,
    EmptyResult,
    NotArranged,
    OutOfBounds,
    EmptyWidth,
    BadCutCount,
    NotAscending,
    EmptyContentSubspace,
    NotAPrincipal,
    NodeTierCrossOwner,
    NotLinkAddress,
    NotHomeLink,
    AlreadySeated,
    NotContentSubspace,
    // ── M5 arrangement: the version-chain model's three write-path
    //    refusals (PUB round 2, lane 3.1; owner ruling D2b). Each is a
    //    PERMANENT class (PUB-8.3's idiom); the faces are pinned verbatim at
    //    PUB-2.11's table and are the CLIENT's to render, keyed on the code
    //    (PUB-6.7) — `private_source_versionless`'s splitting on the flag
    //    the client itself sent, the code staying one. ──
    /// PUB-2.11 — an in-place arrangement edit (`insert`, `copy`-into,
    /// `delete`, `rearrange`) on a PUBLISHED target; a DECLARED deposit at
    /// fresh positions is the one insert it admits (PUB-2.59, PUB-9.13).
    PublishedTarget,
    /// PUB-2.7 — a `version` resolving PRIVATE on a PUBLISHED source the
    /// caller owns (the explicit-`false` arm; absent inherits, PUB-2.8).
    PrivateVersionOfPublished,
    /// PUB-2.9 — a `version` on a PRIVATE source the caller owns, whatever
    /// the flag: private documents are versionless. ALSO the publish shot's
    /// refusal on a private document (lane 3.2): a shot appends a version,
    /// and the face is this code's `true` arm — publishing means minting a
    /// separate edition.
    PrivateSourceVersionless,
    // ── M5 arrangement: the publish shot (PUB round 2, lane 3.2). The
    //    source gate's `withheld` is the one code here whose disposition is
    //    not `Permanent`: it is `Reorder` in EVERY cell (PUB-8.4, PUB-8.6),
    //    names the withheld document in `site.addr` and carries no `detail`
    //    (PUB-8.5). The four request-shape refusals beside it are the
    //    shot's own, permanent. ──
    /// PUB-6.23 / PUB-8.1 / PUB-8.4 — a supplied run windows an origin the
    /// shooter may not read; `site.addr` is that origin's document.
    Withheld,
    /// A supplied run is not a content run of its stated origin (address
    /// arithmetic on the request; discloses nothing about what exists).
    BadRun,
    /// The base is neither the document nor a member of its chain
    /// (PUB-2.37).
    BaseNotInChain,
    /// The base is absent or the document itself while the document already
    /// has a member: its pre-chain arrangement is no base (PUB-2.34,
    /// PUB-2.66).
    BaseSuperseded,
    /// The base extent exceeds the base's current content count.
    BaseExtentTooLarge,
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
    //    RetrieveError::MalformedSpec; the last three are M6's own budget
    //    refusals — two for COMPARE, whose join squares in the request, and
    //    one for FINDDOCSCONTAINING, whose coverage is the multiplier it
    //    applies to two world-sized scans) ──
    NoSuchSubspace,
    EmptySubspace,
    DepthIncompatible,
    RangeNotPresent,
    MalformedSpan,
    TooManyBlocks,
    TooManyPairs,
    TooMuchCoverage,
    // ── M8 link discovery read (the last two are M8's own budget refusals —
    //    one for the arrangement runs a request materializes or joins
    //    against, one for the spans a RETRIEVEENDSETS answer carries) ──
    NotALink,
    BadRegion,
    ImageTooLarge,
    EndsetsTooLarge,
}

/// The fixed operator-condition detail a `Gate` rejection carries (§5): M3
/// documents `MintError::Gate` as defensive — it fires only on a corrupted
/// frontier, never on a well-formed request against a healthy store.
const GATE_DETAIL: &str = "inc-gate tripped: corrupted frontier — operator condition";

/// The code's two per-code policies (§5), each a total lookup off the flat
/// code: the disposition, public, and the standing explanation
/// [`Rejection::classified`] attaches.
impl RejectCode {
    /// The disposition policy — a single total lookup off the flat code (§5).
    /// Returns exactly the explicit `Reorder`/`Retry`/`Halt` cases and
    /// defaults everything else to `Permanent` (the catch-all is the DESIGNED
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
    /// allocations), `Gate` (store corruption), `TxnOverBudget` (M2's
    /// per-transaction byte budget, ruled Permanent 2026-08-21 — no retry
    /// shrinks a transaction; the client splits it), `TxnUnencodable` (a
    /// record M2's serializer refused — the same request re-presented stages
    /// the same record), the recovery-steering `NotNextForm` (re-derive via
    /// `NextAccountPrefix`, a *different* request), and the version-chain
    /// model's three refusals `PublishedTarget` / `PrivateVersionOfPublished`
    /// / `PrivateSourceVersionless` (PUB-8.3's "permanent class": publication
    /// never transitions, PUB-1.9, so the same request can never land — the
    /// act that does is another request, the one the face names).
    ///
    /// `Withheld` is `Reorder` in EVERY cell (PUB-8.4, PUB-8.6): the one
    /// filling event is a later grant commit, and the wire token stays
    /// `reorder` wherever no such event can exist — the FACE derives the
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

    /// The standing-explanation policy — the second total lookup off the flat
    /// code, beside [`RejectCode::disposition`] (§5). A code whose meaning is
    /// the same sentence every time it fires carries that sentence here
    /// rather than at whichever call site happened to raise it; everything
    /// else carries no detail unless a call site threads one
    /// (`Rejection::with_detail`).
    ///
    /// `Gate` is the one such code today: it signals store corruption — an
    /// operator condition — never client error.
    fn fixed_detail(self) -> Option<&'static str> {
        match self {
            RejectCode::Gate => Some(GATE_DETAIL),
            _ => None,
        }
    }
}

impl Rejection {
    /// Build a classified rejection: both per-code policies applied off the
    /// flat code — the disposition from [`RejectCode::disposition`], and the
    /// standing explanation the code carries by policy, when it carries one
    /// (§5).
    ///
    /// Public for the reason [`RejectCode::disposition`] is: a caller that
    /// raises one of M10's codes on its own channel builds it here and gets
    /// the whole classification, rather than transcribing half of it and
    /// drifting from the rows every other rejection of that code is given.
    pub fn classified(kind: OpKind, code: RejectCode, site: Option<FaultSite>) -> Rejection {
        let detail = code.fixed_detail().map(str::to_string);
        Rejection { op: kind, code, disposition: code.disposition(), site, detail }
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

/// A bare `Rejection` for dispatch arms (§5).
pub(crate) fn rejection(kind: OpKind, code: RejectCode) -> Rejection {
    Rejection::classified(kind, code, None)
}

#[cfg(test)]
mod tests;
