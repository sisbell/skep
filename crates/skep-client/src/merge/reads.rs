//! The merge's READS — the merge record's §1.3 in its order — and what they
//! build: [`compose`], which reads the head, the base and every side as run
//! lists, composes them through the core and writes nothing; the conversion
//! of an `image` answer's runs to the core's, each origin the BARE document
//! ([`origin_of`]); [`head_of`], the feed-walk fallback for a bare
//! document's head member; and [`Refusal`], every refusal a read or a
//! landing can meet.
//!
//! The reads, in the record's order (§1.3): the document's metadata and the
//! head's extent; the base — named by the caller, or derived by `base_of`
//! for members of one chain — imaged whole; the head and each side imaged
//! whole; the shared material joined by the core over the three lists; the
//! values where the value rule has work, read through the side that holds
//! them; and the prior records for the key, so a standing record is known
//! before anything is written (§3, idempotence). Every `image` past the run
//! budget is re-asked in halves and the parts re-joined by I-adjacency (§8:
//! "a region past the budget can be asked in parts"), every `retrieve_v`
//! past the delivery budget likewise. A side the reader may not read, or a
//! side whose base the library cannot read — a fork, a member of another
//! document, a draft of another account (decision 15) — refuses before the
//! first `image`.
//!
//! The reads go through [`Board::op`] under the caller's token, [`Board::guest`]
//! where none is given, and [`Board::op_at`] for a draft at a position, whose
//! `history_busy` is retried a bounded number of times (§7, "What it reads
//! through"). Nothing here writes.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use skep_address::{validate, Address, Nat, Tumbler};

use crate::address::{doc_1_of, parse_address};
use crate::board::answers::{self, IRun, Metadata};
use crate::board::{
    frames, Answer, AtAnswer, Board, ChangesAnswer, ChangesQuery, Rejection, Token,
};
use crate::halt::Halt;

use super::compose::{base_of, compose_runs, Composed, Item, Options, Run, SideIx};
use super::record::{self, Record, RecordKey, SideAt};

/// The most runs one shot may name — the wire's list cap, `MAX_WIRE_LIST` =
/// 4,096 elements per request array, which the shot's `runs` is parsed
/// through (the merge record's §8, "The three caps, read at the pin"). A
/// merged list past it is refused with the count, never split (decision 13).
pub const SHOT_RUN_CAP: usize = 1 << 12;

/// The most items one `retrieve_v` delivers — `MAX_DELIVERY_ITEMS`, 131,072
/// (wire.md §Rejection codes, `too_many_items`): a value read wider than it
/// is made in parts.
pub(super) const MAX_DELIVERY_ITEMS: u64 = 1 << 17;

/// How many times a `history_busy` on a read at a position is retried
/// before [`Refusal::HistoryBusy`] (§7: "retry with backoff, bounded").
const HISTORY_BUSY_RETRIES: u32 = 4;

// ── the inputs ────────────────────────────────────────────────────────────

/// What a merge is composed from (the merge record's §7, `Inputs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inputs {
    /// The trunk document `D`.
    pub doc: Address,
    /// The head MEMBER `D.h` — side A in every shape the record draws. No
    /// read answers a bare document's head member (UNVERIFIED-HERE 7), so
    /// the caller names it, from its own knowledge or from [`head_of`].
    pub head: Address,
    /// The base member, where the caller knows it — the editor's staging
    /// base for a draft side; derived by `base_of` for members of one chain
    /// where `None` (§1.2).
    pub base: Option<Address>,
    /// The other sides, in commit order.
    pub sides: Vec<Side>,
    /// The composition's switches and the merger's resolutions.
    pub options: Options,
    /// The merge record kind's TYPE address — the link's type slot and the
    /// record's class. Decision 9's row is interim and unpinned, so the
    /// embedder names it.
    pub kind: Address,
}

/// One side of a merge besides the head (the merge record's §7, `Side`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    /// A member of the document's chain — a daughter, or a daughter's
    /// daughter.
    Member(Address),
    /// A draft of the merger's own account, read as of `position` where one
    /// is given, else at the head (§1.2 shape (2)).
    Draft {
        /// The draft's address.
        at: Address,
        /// The commit position the draft is read at; `None` the head.
        position: Option<u64>,
    },
    /// A cross-owner fork: NOT OFFERED until the fork-source read lands
    /// (decision 15) — refused [`Refusal::BaseUnknown`] before any read.
    Fork(Address),
}

impl Side {
    /// The side's address — the member, the draft, the fork.
    pub fn address(&self) -> &Address {
        match self {
            Side::Member(a) | Side::Fork(a) => a,
            Side::Draft { at, .. } => at,
        }
    }

    /// The side's role in the record's `sides` (§4).
    pub fn role(&self) -> Role {
        match self {
            Side::Member(_) => Role::Alternative,
            Side::Draft { .. } => Role::Draft,
            Side::Fork(_) => Role::Fork,
        }
    }

    /// The position a draft side is read at.
    fn position(&self) -> Option<u64> {
        match self {
            Side::Draft { position, .. } => *position,
            Side::Member(_) | Side::Fork(_) => None,
        }
    }
}

/// A side's role, as the record spells it (the merge record's §4, `role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The head member, side A.
    Head,
    /// A daughter of the document's chain.
    Alternative,
    /// A draft of the merger's own account.
    Draft,
    /// A cross-owner fork.
    Fork,
}

impl Role {
    /// The role's spelling in the record: `head`, `alternative`, `draft`,
    /// `fork`.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Head => "head",
            Role::Alternative => "alternative",
            Role::Draft => "draft",
            Role::Fork => "fork",
        }
    }

    /// The role a spelling names, `None` for any other text.
    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "head" => Some(Role::Head),
            "alternative" => Some(Role::Alternative),
            "draft" => Some(Role::Draft),
            "fork" => Some(Role::Fork),
            _ => None,
        }
    }
}

/// A run's family in the shot (the merge record's §1.5, the three families
/// the wire states): the document's own I-space placed by reference, a
/// window onto another document, or a staging draft's text re-inserted as
/// fresh identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// The document's own I-space, by reference — its bytes signed by value.
    Own,
    /// Another document's I-space, kept as a window — signed by address.
    Window,
    /// A draft side's fresh text, re-inserted under the document's own
    /// I-space by the shot — its bytes signed by value.
    DraftNative,
}

/// What [`compose`] returns before anything is written (the merge record's
/// §1.5, "What the library returns BEFORE the write"; §7, `Merged`): the
/// core's result wrapped with what the landing needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged {
    /// The inputs as composed.
    pub inputs: Inputs,
    /// M, the gap report, the counts, the value log, the resolutions not
    /// applied — the core's result.
    pub composed: Composed,
    /// Each run of M's family, parallel to `composed.runs`.
    pub families: Vec<Family>,
    /// The key the record is current under: `(doc, base, {sides})`.
    pub key: RecordKey,
    /// The cap `composed.counts.m` is checked against at the landing —
    /// [`SHOT_RUN_CAP`]. The count is carried whatever it is, so a face can
    /// show it; the refusal is the landing's.
    pub cap: usize,
    /// The record the landing will write, unlanded: `landed` none, `claims`
    /// none, `replaces` the prior record's link where one stands.
    pub record: Record,
    /// The highest `as_of` the reads answered.
    pub as_of: u64,
    /// The standing record for the key, where one is current (§3, "What a
    /// second agent sees").
    pub prior: Option<Record>,
    /// The head's content extent AS READ — the shot's `base_extent`.
    pub head_extent: u64,
    /// The head's and each side's image, in side order, which the landing
    /// reads the shot's values through.
    pub(super) maps: Vec<Imaged>,
}

// ── the refusals ──────────────────────────────────────────────────────────

/// Every refusal the reads and the landing can meet (the merge record's §7,
/// "Its errors"), each named for the wire code it answers; the library's
/// own faults and the board's other refusals ride [`Refusal::Halt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A side whose base the library cannot read — a fork, a member of
    /// another document, a draft of another account, a draft with no named
    /// base — refused before any read (decision 15; no interim).
    BaseUnknown(Side),
    /// Two draft sides: not a merge shape — the shot admits one draft, so
    /// the way out is to shoot one (§1.2 shape (3)).
    TwoDrafts,
    /// `withheld` on the document named: a side or the base the reader may
    /// not read; nothing composed.
    Unreadable(Address),
    /// `doc_not_registered` on the document named.
    NoSuchDocument(Address),
    /// `image_too_large` down to a region of one position: the document's
    /// runs cannot be imaged, `runs_seen` of them counted before the floor
    /// (§8's measurement, reported).
    TooFragmented {
        /// The document imaged.
        doc: Address,
        /// The runs the parts that answered carried.
        runs_seen: usize,
    },
    /// `history_busy` on a read at a position, past the bounded retries.
    HistoryBusy,
    /// `withheld` on the shot naming an origin the merger may not read: a
    /// window the source gate refuses (§7, THE SHOT).
    WindowWithheld(Address),
    /// The merged list holds more runs than one shot may name (decision
    /// 13): refused with the count, never split.
    OverCap {
        /// `counts.m`.
        runs: usize,
        /// [`SHOT_RUN_CAP`].
        cap: usize,
    },
    /// `signed_session_required`: the landing's session is bare.
    NeedsSignedSession,
    /// The library's own fault named (A-288's own-bug class) — a frame the
    /// board refused as malformed in substance, a shape it does not know —
    /// the board's other refusals verbatim, and every transport halt.
    Halt(Halt),
}

impl From<Halt> for Refusal {
    fn from(h: Halt) -> Refusal {
        Refusal::Halt(h)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::BaseUnknown(side) => write!(f, "the base of the side {} cannot be read: a cross-account side is not offered until the fork-source read lands", side.address()),
            Refusal::TwoDrafts => f.write_str("two drafts off one head are no merge shape: shoot one first"),
            Refusal::Unreadable(doc) => write!(f, "{doc} is not readable to this reader (withheld); nothing was composed"),
            Refusal::NoSuchDocument(doc) => write!(f, "{doc} is not registered at this board"),
            Refusal::TooFragmented { doc, runs_seen } => write!(f, "{doc} is in more pieces than `image` can answer, even one position at a time ({runs_seen} runs seen)"),
            Refusal::HistoryBusy => f.write_str("the board was busy reading history (history_busy) past the bounded retries"),
            Refusal::WindowWithheld(origin) => write!(f, "{origin} is not shared with you — the shot windows it; nothing was published"),
            Refusal::OverCap { runs, cap } => write!(f, "the merged list is in more pieces than one publication can carry — {runs}, where {cap} is the most; publishing this merge is not offered"),
            Refusal::NeedsSignedSession => f.write_str("a signed session is needed to land a merge on a claimed board (signed_session_required)"),
            Refusal::Halt(h) => h.fmt(f),
        }
    }
}

impl std::error::Error for Refusal {}

// ── the origin rule ───────────────────────────────────────────────────────

/// Returns the BARE DOCUMENT a content I-address was minted under: the
/// prefix before its last `.0.1.` — the content subspace's marker — stripped
/// of any version component to the trunk (the merge record's §1.3 step 3:
/// "derived from its `i_start` by address arithmetic, `document_of` then the
/// trunk"; the rule skep-cli's dev board states as `origin_of`).
///
/// The core's `Run::origin` is this address, never a member's: a
/// version-qualified origin would make every anchor and every `Choice::After`
/// lookup answer none. `None` for a text that is no content I-address.
pub fn origin_of(i_start: &str) -> Option<Address> {
    let at = i_start.rfind(".0.1.")?;
    let minted_under = &i_start[..at];
    parse_address(&crate::address::document_of(minted_under)?)
}

/// The content I-address prefix of `origin`'s positions — the spelling an
/// `image` answer's `i_start` opens with.
pub(super) fn content_prefix(origin: &Address) -> String {
    format!("{origin}.0.1")
}

/// Returns the core's runs for an `image` answer's runs: each origin by
/// [`origin_of`], I-adjacent runs of one origin coalesced — the daemon's own
/// accumulator, `extend_or_push_run`, whose whole test is I-adjacency — so a
/// run a part boundary cut is one run again (§8).
///
/// # Errors
///
/// A run whose `i_start` is no content I-address is the board's fault,
/// named.
pub(super) fn runs_of(imaged: &[IRun]) -> Result<Vec<Run>, Halt> {
    let mut out: Vec<Run> = Vec::new();
    for r in imaged {
        let i_start = format!("{}.{}", r.prefix, r.first);
        let origin = origin_of(&i_start).ok_or_else(|| {
            Halt::face(
                "an `image` run is no content I-address",
                format!("`{i_start}` has no `.0.1.` content marker before its ordinal"),
                "this is a board fault; nothing was written",
            )
        })?;
        if let Some(last) = out.last_mut() {
            if last.origin == origin && last.reach() == r.first {
                last.width = last.width.saturating_add(r.width);
                continue;
            }
        }
        out.push(Run::new(origin, r.first, r.width));
    }
    Ok(out)
}

// ── address arithmetic over members ───────────────────────────────────────

/// The trunk a document, member or element address lies in; `None` for an
/// account or a node.
pub(super) fn trunk_of(a: &Address) -> Option<Address> {
    parse_address(&crate::address::document_of(&a.to_string())?)
}

/// An address's components, for the comparisons the tumbler's own type does
/// not offer.
pub(super) fn comps(a: &Address) -> Vec<Nat> {
    a.tumbler().iter().cloned().collect()
}

/// A member's version components after the trunk `doc`'s; `None` where `a`
/// is not under `doc`, or is `doc` itself.
pub(super) fn version_components(doc: &Address, a: &Address) -> Option<Vec<Nat>> {
    let (doc, comps) = (comps(doc), comps(a));
    if comps.len() <= doc.len() || comps[..doc.len()] != doc[..] {
        return None;
    }
    Some(comps[doc.len()..].to_vec())
}

/// Whether `a` is a TRUNK member of `doc` — one version component.
pub(super) fn is_trunk_member(doc: &Address, a: &Address) -> bool {
    version_components(doc, a).is_some_and(|v| v.len() == 1)
}

/// The trunk member after `head`: its one version component plus one.
pub(super) fn next_trunk_member(head: &Address) -> Option<Address> {
    let mut comps = comps(head);
    let last = comps.last_mut()?;
    *last = &*last + &Nat::from(1u32);
    validate(Tumbler::new(comps).ok()?).ok()
}

/// The `k`-th daughter of `member`: the member's address extended by `k`.
pub(super) fn daughter_of(member: &Address, k: u64) -> Option<Address> {
    let comps = comps(member).into_iter().chain(std::iter::once(Nat::from(k)));
    validate(Tumbler::new(comps).ok()?).ok()
}

/// The account an address lies in — `N.0.U` — as text; `None` for a node.
pub(super) fn account_of(a: &Address) -> Option<String> {
    let node: Vec<String> = a.node_field().iter().map(ToString::to_string).collect();
    let account: Vec<String> = a.account_field()?.iter().map(ToString::to_string).collect();
    Some(format!("{}.0.{}", node.join("."), account.join(".")))
}

/// The ordinal — the last component — of an address, where it fits `u64`.
pub(super) fn last_component(a: &Address) -> Option<u64> {
    u64::try_from(a.tumbler().iter().last()?).ok()
}

// ── the reader ────────────────────────────────────────────────────────────

/// One document's image, whole: its extent and its runs as served, each
/// run's `ordinal` the document's own V-ordinal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Imaged {
    /// The document imaged — a member, or a draft.
    pub(super) doc: Address,
    /// The position a draft was read at; `None` the head.
    pub(super) at: Option<u64>,
    /// The content extent.
    pub(super) extent: u64,
    /// The runs, in V order.
    pub(super) runs: Vec<IRun>,
}

/// The reads' one door: a board and the caller's token, every answer's
/// `as_of` kept.
pub(super) struct Reader<'a> {
    board: &'a Board,
    token: Option<&'a Token>,
    as_of: Cell<u64>,
}

impl<'a> Reader<'a> {
    /// A reader at `board` as `token`'s principal, or as a guest.
    pub(super) fn new(board: &'a Board, token: Option<&'a Token>) -> Reader<'a> {
        Reader { board, token, as_of: Cell::new(0) }
    }

    /// The highest `as_of` answered so far.
    pub(super) fn as_of(&self) -> u64 {
        self.as_of.get()
    }

    fn note(&self, v: &Value) {
        if let Some(a) = answers::as_of(v) {
            self.as_of.set(self.as_of.get().max(a));
        }
    }

    /// One read frame answered as its response document — a rejection
    /// included — at the head, or as of `at` through `/op-at`, whose
    /// `history_busy` is retried with backoff up to [`HISTORY_BUSY_RETRIES`]
    /// times.
    ///
    /// # Errors
    ///
    /// The death signal under the token is the session's end, faced; a
    /// position fault of `/op-at` is the caller's position, faced;
    /// [`Refusal::HistoryBusy`] past the retries; a transport halt the
    /// dialer's.
    pub(super) fn read(&self, frame: &Value, at: Option<u64>) -> Result<Value, Refusal> {
        let Some(at) = at else {
            return match self.board.op(self.token, frame)? {
                Answer::Closed => Err(closed("reading").into()),
                Answer::Document(v) => {
                    self.note(&v);
                    Ok(v)
                }
            };
        };
        for attempt in 0..=HISTORY_BUSY_RETRIES {
            match self.board.op_at(self.token, at, frame)? {
                AtAnswer::Document(v) => {
                    self.note(&v);
                    return Ok(v);
                }
                AtAnswer::Closed => return Err(closed("reading at a position").into()),
                AtAnswer::Busy => {
                    if attempt < HISTORY_BUSY_RETRIES {
                        thread::sleep(Duration::from_millis(20 * u64::from(attempt + 1)));
                    }
                }
                other => {
                    return Err(Halt::face(
                        format!("the draft cannot be read as of position {at}"),
                        format!("`/op-at` answered {other:?}: the position is below the board's retention floor, past its head, or no position"),
                        "read the draft at a position the board still answers, or at the head",
                    )
                    .into())
                }
            }
        }
        Err(Refusal::HistoryBusy)
    }

    /// The refusal a read of `doc` answered, mapped: `withheld` is
    /// [`Refusal::Unreadable`], `doc_not_registered` [`Refusal::NoSuchDocument`],
    /// the rest the board's own, surfaced verbatim.
    pub(super) fn refuse(&self, doc: &Address, r: &Rejection, v: &Value) -> Refusal {
        match r.key() {
            "withheld" => Refusal::Unreadable(doc.clone()),
            "doc_not_registered" => Refusal::NoSuchDocument(doc.clone()),
            _ => Refusal::Halt(r.refused(v)),
        }
    }

    /// A read of `doc` whose answer must be a document: a rejection is
    /// mapped by [`Reader::refuse`].
    pub(super) fn answered(
        &self,
        doc: &Address,
        frame: &Value,
        at: Option<u64>,
    ) -> Result<Value, Refusal> {
        let v = self.read(frame, at)?;
        match Rejection::of(&v) {
            Some(r) => Err(self.refuse(doc, &r, &v)),
            None => Ok(v),
        }
    }

    /// `doc_metadata(doc)`, decoded.
    pub(super) fn metadata(&self, doc: &Address) -> Result<Metadata, Refusal> {
        let v = self.answered(doc, &frames::doc_metadata(&doc.to_string()), None)?;
        answers::metadata(&v).ok_or_else(|| shape("doc_metadata", &v).into())
    }

    /// The content extent of `doc`, at the head or as of `at`.
    pub(super) fn extent(&self, doc: &Address, at: Option<u64>) -> Result<u64, Refusal> {
        let v = self.answered(doc, &frames::span_set(&doc.to_string()), at)?;
        if v["resp"].as_str() != Some("span_set") {
            return Err(shape("retrieve_doc_v_span_set", &v).into());
        }
        Ok(answers::content_extent(&v))
    }

    /// `image` over content ordinals `from ..` of `doc`, `width` of them —
    /// whole where its runs are at or under the run budget, else in parts,
    /// halving until each part answers (§8) — the runs in V order with each
    /// run's `ordinal` the document's own.
    ///
    /// # Errors
    ///
    /// [`Refusal::TooFragmented`] where a part of one position is still
    /// refused `image_too_large`.
    pub(super) fn image(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
    ) -> Result<Vec<IRun>, Refusal> {
        let mut out = Vec::new();
        let mut seen = 0usize;
        self.image_into(doc, at, from, width, &mut out, &mut seen)?;
        Ok(out)
    }

    fn image_into(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
        out: &mut Vec<IRun>,
        seen: &mut usize,
    ) -> Result<(), Refusal> {
        if width == 0 {
            return Ok(());
        }
        let v = self.read(&frames::image(&doc.to_string(), from, width), at)?;
        if let Some(r) = Rejection::of(&v) {
            if r.key() != "image_too_large" {
                return Err(self.refuse(doc, &r, &v));
            }
            if width == 1 {
                return Err(Refusal::TooFragmented { doc: doc.clone(), runs_seen: *seen });
            }
            let left = width / 2;
            self.image_into(doc, at, from, left, out, seen)?;
            return self.image_into(doc, at, from + left, width - left, out, seen);
        }
        let runs = answers::i_runs(&v, width).ok_or_else(|| shape("image", &v))?;
        *seen += runs.len();
        out.extend(runs.into_iter().map(|mut r| {
            r.ordinal += from - 1;
            r
        }));
        Ok(())
    }

    /// The extent and the whole image of `doc`, at the head or as of `at`.
    pub(super) fn imaged(&self, doc: &Address, at: Option<u64>) -> Result<Imaged, Refusal> {
        let extent = self.extent(doc, at)?;
        let runs = self.image(doc, at, 1, extent)?;
        Ok(Imaged { doc: doc.clone(), at, extent, runs })
    }

    /// The values at content ordinals `from ..` of `doc`, `width` of them,
    /// one item a position — `retrieve_v` in parts past the delivery budget
    /// and on `too_many_items`.
    ///
    /// # Errors
    ///
    /// A delivery holding an item no value can be spelled from — a withheld
    /// run, a reference — is faced: the merge reads the document's own
    /// positions, which its reader may read whole.
    pub(super) fn values(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
    ) -> Result<Vec<Item>, Refusal> {
        let mut out = Vec::new();
        let mut cursor = from;
        let end = from.saturating_add(width);
        while cursor < end {
            let part = MAX_DELIVERY_ITEMS.min(end - cursor);
            cursor += self.values_part(doc, at, cursor, part, &mut out)?;
        }
        Ok(out)
    }

    /// One part of [`Reader::values`]: the positions delivered, a
    /// `too_many_items` halving the part.
    fn values_part(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
        out: &mut Vec<Item>,
    ) -> Result<u64, Refusal> {
        let v = self.read(&frames::retrieve_v(&doc.to_string(), from, width), at)?;
        if let Some(r) = Rejection::of(&v) {
            if r.key() == "too_many_items" && width > 1 {
                let left = width / 2;
                let read = self.values_part(doc, at, from, left, out)?;
                return Ok(read + self.values_part(doc, at, from + left, width - left, out)?);
            }
            return Err(self.refuse(doc, &r, &v));
        }
        let items = answers::delivery_values(&v).ok_or_else(|| {
            Halt::face(
                format!("a position of {doc} cannot be read as a value"),
                format!("the delivery at {from} holds an item no value is spelled from — a withheld run, a reference, or a kind this client does not know: {}", crate::halt::clipped(&v.to_string(), 200)),
                "this is a board fault, or a window the merge should have signed by address; nothing was written",
            )
        })?;
        if items.len() as u64 != width {
            return Err(Halt::face(
                format!("{doc} delivered {} positions where {width} were asked", items.len()),
                format!("the delivery at {from} is short of, or past, the span asked"),
                "this is a board fault; nothing was written",
            )
            .into());
        }
        out.extend(items);
        Ok(width)
    }
}

/// The death signal under the caller's token, faced.
fn closed(during: &str) -> Halt {
    Halt::face(
        format!("the session ended while {during}"),
        "the board answered `Skepd-Session: closed` (wire.md §Sessions)",
        "open a session again and run the merge again: every step resumes by reading",
    )
}

/// An answer without the shape the frame's `resp` promises.
fn shape(op: &str, v: &Value) -> Halt {
    Halt::face(
        format!("`{op}` answered a document this client cannot read"),
        crate::halt::clipped(&v.to_string(), 200).to_string(),
        "this board is not speaking the wire this client expects; nothing was written",
    )
}

// ── the value mapping (the fragment model) ────────────────────────────────

/// Where the positions of `run` stand among the sides' images: each stretch
/// as `(the image's index, the V-ordinal it begins at, its width)` — the
/// image at `prefer` asked first, then the others in order — so a sub-run
/// of a run a side holds is read at that side's own V-ordinals
/// (`ordinal_of`'s mapping), and a shared identity at whichever side holds
/// it.
///
/// # Errors
///
/// A position no image holds is the library's own fault: the core places
/// only positions some side gave it.
pub(super) fn locate(
    maps: &[Imaged],
    prefer: Option<usize>,
    run: &Run,
) -> Result<Vec<(usize, u64, u64)>, Halt> {
    let prefix = content_prefix(&run.origin);
    let order: Vec<usize> =
        prefer.into_iter().chain((0..maps.len()).filter(|i| Some(*i) != prefer)).collect();
    let mut out = Vec::new();
    let mut pos = run.i_start;
    let end = run.reach();
    while pos < end {
        let found = order.iter().find_map(|&i| {
            maps[i]
                .runs
                .iter()
                .find(|r| r.prefix == prefix && r.first <= pos && pos - r.first < r.width)
                .map(|r| (i, r))
        });
        let Some((i, r)) = found else {
            return Err(Halt::face(
                format!("no side holds the position {prefix}.{pos}"),
                "the merged list names a position none of the images read holds — a fault in this client's composition",
                "this is this client's fault; nothing was written",
            ));
        };
        let stretch = (end - pos).min(r.first + r.width - pos);
        out.push((i, r.ordinal + (pos - r.first), stretch));
        pos += stretch;
    }
    Ok(out)
}

/// The values of `run`'s positions, read through the sides that hold them
/// ([`locate`]), `prefer` asked first.
pub(super) fn values_for(
    reader: &Reader<'_>,
    maps: &[Imaged],
    prefer: Option<usize>,
    run: &Run,
) -> Result<Vec<Item>, Refusal> {
    let mut out = Vec::with_capacity(run.width as usize);
    for (i, ordinal, width) in locate(maps, prefer, run)? {
        out.extend(reader.values(&maps[i].doc, maps[i].at, ordinal, width)?);
    }
    Ok(out)
}

// ── the shape's reads ─────────────────────────────────────────────────────

/// Everything the reads of one shape yield, which `compose` and `verify`
/// both build on.
pub(super) struct Readings {
    /// The base member, named or derived.
    pub(super) base: Address,
    /// The base's image.
    pub(super) base_image: Imaged,
    /// The head's and each side's image, in side order.
    pub(super) maps: Vec<Imaged>,
    /// The head's content extent as read.
    pub(super) head_extent: u64,
    /// The trunk's owner account.
    pub(super) owner: String,
    /// The core's result.
    pub(super) composed: Composed,
    /// Each run of M's family.
    pub(super) families: Vec<Family>,
}

/// The reads of §1.3 in order, then the core's walk: the document's
/// metadata, the head's extent, the base imaged, the head and each side
/// imaged, the composition with the values read through the sides.
///
/// # Errors
///
/// In this order: a fork side, a member of another document, a draft of
/// another account or a draft with no named base is
/// [`Refusal::BaseUnknown`] — decided before any `image`; two drafts
/// [`Refusal::TwoDrafts`]; then each read's own refusals.
pub(super) fn read_shape(
    reader: &Reader<'_>,
    doc: &Address,
    head: &Address,
    base: Option<Address>,
    sides: &[Side],
    options: &Options,
) -> Result<Readings, Refusal> {
    if !is_trunk_member(doc, head) {
        return Err(Halt::face(
            format!("{head} is not a trunk member of {doc}"),
            "the head is the document's latest trunk member, `D.h`",
            "name the head member, or read it with `head_of`",
        )
        .into());
    }
    if sides.iter().filter(|s| matches!(s, Side::Draft { .. })).count() > 1 {
        return Err(Refusal::TwoDrafts);
    }
    for side in sides {
        match side {
            Side::Fork(_) => return Err(Refusal::BaseUnknown(side.clone())),
            Side::Member(m) => {
                if trunk_of(m).as_ref() != Some(doc) || version_components(doc, m).is_none() {
                    return Err(Refusal::BaseUnknown(side.clone()));
                }
            }
            Side::Draft { .. } => {
                if base.is_none() {
                    return Err(Refusal::BaseUnknown(side.clone()));
                }
            }
        }
    }
    // Step 1: the document and the head.
    let meta = reader.metadata(doc)?;
    for side in sides {
        if let Side::Draft { at, .. } = side {
            if account_of(at).as_deref() != Some(meta.owner.as_str()) {
                return Err(Refusal::BaseUnknown(side.clone()));
            }
        }
    }
    let head_extent = reader.extent(head, None)?;
    // Step 2: the base, named or derived along the anchor chains.
    let base = match base {
        Some(b) => b,
        None => {
            let mut b = head.clone();
            for side in sides {
                b = match base_of(&b, side.address()) {
                    Some(b) => b,
                    None => return Err(Refusal::BaseUnknown(side.clone())),
                };
            }
            b
        }
    };
    if trunk_of(&base).as_ref() != Some(doc) || version_components(doc, &base).is_none() {
        return Err(Halt::face(
            format!("{base} is no member of {doc}'s chain"),
            "the base of a merge is the member both sides descend from",
            "name a base member of the document, or none to derive it",
        )
        .into());
    }
    let base_image = reader.imaged(&base, None)?;
    // Step 3: the head, then each side.
    let mut maps = vec![Imaged {
        doc: head.clone(),
        at: None,
        extent: head_extent,
        runs: reader.image(head, None, 1, head_extent)?,
    }];
    for side in sides {
        maps.push(reader.imaged(side.address(), side.position())?);
    }
    // Steps 4 and 5: the join and the walk, the values through the sides.
    let base_runs = runs_of(&base_image.runs)?;
    let mut side_runs = Vec::with_capacity(maps.len());
    for (i, m) in maps.iter().enumerate() {
        side_runs.push((SideIx(i as u8), runs_of(&m.runs)?));
    }
    let fault: RefCell<Option<Refusal>> = RefCell::new(None);
    let values = |side: SideIx, run: &Run| -> Option<Vec<Item>> {
        match values_for(reader, &maps, Some(side.0 as usize), run) {
            Ok(items) => Some(items),
            Err(e) => {
                fault.borrow_mut().get_or_insert(e);
                None
            }
        }
    };
    let composed = compose_runs(&base_runs, &side_runs, None, options, &values);
    if let Some(e) = fault.into_inner() {
        return Err(e);
    }
    let families = composed.runs.iter().map(|p| family_of(&p.run.origin, doc, sides)).collect();
    Ok(Readings { base, base_image, maps, head_extent, owner: meta.owner, composed, families })
}

/// A run's family by its origin: the trunk's own, a draft side's, or a
/// window.
fn family_of(origin: &Address, doc: &Address, sides: &[Side]) -> Family {
    if origin == doc {
        Family::Own
    } else if sides.iter().any(|s| matches!(s, Side::Draft { at, .. } if at == origin)) {
        Family::DraftNative
    } else {
        Family::Window
    }
}

/// The first V-ordinal, counted from 1, at which the member's `actual` runs
/// over its placed positions differ from the `expected` list the merge
/// composed — `None` where they agree. A draft side's fresh runs are
/// re-minted by the shot under `doc`'s own I-space, consecutively, so an
/// expected `DraftNative` run matches any stretch of `doc`'s positions of
/// its width in its place, whatever their ordinals.
pub(super) fn first_difference(
    expected: &[(Run, Family)],
    actual: &[Run],
    doc: &Address,
) -> Option<u64> {
    let mut cursor = 1u64;
    let (mut i, mut j, mut off_i, mut off_j) = (0usize, 0usize, 0u64, 0u64);
    while i < expected.len() && j < actual.len() {
        let (e, fam) = &expected[i];
        let a = &actual[j];
        let stretch = (e.width - off_i).min(a.width - off_j);
        let same_origin =
            if *fam == Family::DraftNative { a.origin == *doc } else { a.origin == e.origin };
        let same_start = *fam == Family::DraftNative || e.i_start + off_i == a.i_start + off_j;
        if !(same_origin && same_start) {
            return Some(cursor);
        }
        cursor += stretch;
        off_i += stretch;
        off_j += stretch;
        if off_i == e.width {
            i += 1;
            off_i = 0;
        }
        if off_j == a.width {
            j += 1;
            off_j = 0;
        }
    }
    (i < expected.len() || j < actual.len()).then_some(cursor)
}

// ── the oracle of the join ────────────────────────────────────────────────

/// Checks the client's join against the daemon's `compare` (the merge
/// record's §1.3 step 4): ONE `compare` of the base's whole content against
/// every side's — the second operand a region per side — asked in parts
/// past its budgets (`too_many_blocks`, `too_many_pairs`: the larger operand
/// halved and re-asked), and for each side the base positions the pairs name
/// as shared must be exactly the base positions that side's image holds.
///
/// # Errors
///
/// A disagreement is this library's own fault — the core's join reproduces
/// the daemon's equi-join on I-address — faced; the reads' refusals.
pub(super) fn check_join(reader: &Reader<'_>, readings: &Readings) -> Result<(), Refusal> {
    let base = &readings.base_image;
    let at = readings.maps.iter().find_map(|m| m.at);
    let regions: Vec<(Address, u64, u64)> =
        readings.maps.iter().map(|m| (m.doc.clone(), 1, m.extent)).collect();
    let mut pairs = Vec::new();
    compare_parts(reader, &base.doc, 1, base.extent, &regions, at, &mut pairs)?;
    for m in &readings.maps {
        let doc = m.doc.to_string();
        let mut oracle: Vec<(u64, u64)> =
            pairs.iter().filter(|p| p.d2 == doc).map(|p| (p.u1, p.width)).collect();
        let mut join: Vec<(u64, u64)> = Vec::new();
        for b in &base.runs {
            for s in m.runs.iter().filter(|s| s.prefix == b.prefix) {
                let lo = b.first.max(s.first);
                let hi = (b.first + b.width).min(s.first + s.width);
                if lo < hi {
                    join.push((b.ordinal + (lo - b.first), hi - lo));
                }
            }
        }
        if coalesced(&mut oracle) != coalesced(&mut join) {
            return Err(Halt::face(
                format!("the client's join over {} and {} disagrees with the board's `compare`", base.doc, m.doc),
                format!("compare: {oracle:?}; the images' intersection: {join:?}"),
                "this is this client's fault — its reproduction of the daemon's equi-join; nothing was written",
            )
            .into());
        }
    }
    Ok(())
}

/// `(start, width)` ranges sorted and merged where they touch.
fn coalesced(ranges: &mut Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &(start, width) in ranges.iter() {
        if let Some(last) = out.last_mut() {
            if last.0 + last.1 >= start {
                last.1 = (start + width).max(last.0 + last.1) - last.0;
                continue;
            }
        }
        out.push((start, width));
    }
    out
}

/// One `compare` of the base region against the side regions, halving the
/// larger operand on a budget refusal until each part answers.
fn compare_parts(
    reader: &Reader<'_>,
    base: &Address,
    from: u64,
    width: u64,
    sides: &[(Address, u64, u64)],
    at: Option<u64>,
    out: &mut Vec<answers::Correspondence>,
) -> Result<(), Refusal> {
    if width == 0 || sides.iter().all(|(_, _, w)| *w == 0) {
        return Ok(());
    }
    let rho1 = [frames::region(&base.to_string(), from, width)];
    let rho2: Vec<Value> = sides
        .iter()
        .filter(|(_, _, w)| *w > 0)
        .map(|(d, f, w)| frames::region(&d.to_string(), *f, *w))
        .collect();
    let v = reader.read(&frames::compare(&rho1, &rho2), at)?;
    if let Some(r) = Rejection::of(&v) {
        if !matches!(r.key(), "too_many_blocks" | "too_many_pairs") {
            return Err(reader.refuse(base, &r, &v));
        }
        if sides.len() > 1 {
            for side in sides {
                compare_parts(reader, base, from, width, std::slice::from_ref(side), at, out)?;
            }
            return Ok(());
        }
        let (side, sf, sw) = &sides[0];
        if width >= *sw && width > 1 {
            let left = width / 2;
            compare_parts(reader, base, from, left, sides, at, out)?;
            return compare_parts(reader, base, from + left, width - left, sides, at, out);
        }
        if *sw > 1 {
            let left = sw / 2;
            compare_parts(reader, base, from, width, &[(side.clone(), *sf, left)], at, out)?;
            return compare_parts(
                reader,
                base,
                from,
                width,
                &[(side.clone(), sf + left, sw - left)],
                at,
                out,
            );
        }
        return Err(Halt::face(
            format!("`compare` refuses {base} against {side} down to one position"),
            format!("{}: the board's compare budget refuses operands of one position", r.token()),
            "this board is not speaking the wire this client expects; nothing was written",
        )
        .into());
    }
    let pairs = answers::compare_pairs(&v).ok_or_else(|| shape("compare", &v))?;
    out.extend(pairs);
    Ok(())
}

// ── compose ───────────────────────────────────────────────────────────────

/// Composes a merge from the board: §1.3's reads in order, the core's walk,
/// the prior records for the key — and writes nothing (the merge record's
/// §7, `compose`).
///
/// `token` is the caller's — `None` reads as a guest, which reads public
/// members alone. The result carries M with each run's family, the gap
/// report, the counts (`counts.m` against [`SHOT_RUN_CAP`], carried, not
/// refused here), the record the landing would write, and the standing
/// record for the key where one is current.
///
/// # Errors
///
/// `read_shape`'s, then a halt reading the prior records.
pub fn compose(board: &Board, token: Option<&Token>, inputs: &Inputs) -> Result<Merged, Refusal> {
    let reader = Reader::new(board, token);
    let readings = read_shape(
        &reader,
        &inputs.doc,
        &inputs.head,
        inputs.base.clone(),
        &inputs.sides,
        &inputs.options,
    )?;
    let Readings { base, maps, head_extent, owner, composed, families, .. } = readings;
    let key = RecordKey::new(
        inputs.doc.clone(),
        base.clone(),
        std::iter::once(inputs.head.clone())
            .chain(inputs.sides.iter().map(|s| s.address().clone())),
    );
    // Step 7: the prior records, the trunk owner's home current over another's.
    let owner_home = doc_1_of(&owner);
    let prior = record::current_among(&reader, &inputs.kind, &key, Some(&owner_home))?;
    let mut sides: Vec<SideAt> = vec![SideAt::Member { at: inputs.head.clone(), role: Role::Head }];
    sides.extend(inputs.sides.iter().map(SideAt::of));
    let record = Record {
        doc: inputs.doc.clone(),
        base,
        sides,
        landed: None,
        claims: Vec::new(),
        runs: composed.counts,
        retries: inputs.options.retries,
        gaps: composed.gaps.clone(),
        values: composed.values.clone(),
        replaces: prior.as_ref().and_then(|p| p.link.clone()),
        by: record::by(),
        link: None,
    };
    Ok(Merged {
        inputs: inputs.clone(),
        composed,
        families,
        key,
        cap: SHOT_RUN_CAP,
        record,
        as_of: reader.as_of(),
        prior,
        head_extent,
        maps,
    })
}

// ── the feed-walk fallback ────────────────────────────────────────────────

/// Returns the HEAD MEMBER of the bare document `doc` by walking its change
/// feed — the fallback the merge record's §1.3 step 1 describes, "read
/// backwards to the last `publish` row": no single read answers a bare
/// document's head member (UNVERIFIED-HERE 7), so the last `publish` row
/// under `doc` whose minted member is a TRUNK member names it; a daughter's
/// row never does. `None` for a document with no member, or one whose rows
/// are all below the feed's retention floor.
///
/// The walk is paged from the floor up under `under=doc`, so its cost is the
/// document's own rows; an embedder that knows the head names it instead.
///
/// # Errors
///
/// The feed's halts: a transport fault, the death signal under the token.
pub fn head_of(
    board: &Board,
    token: Option<&Token>,
    doc: &Address,
) -> Result<Option<Address>, Halt> {
    let mut head: Option<Address> = None;
    feed_rows(board, token, &doc.to_string(), |row| {
        if row["op"].as_str() != Some("publish") {
            return;
        }
        if let Some(member) = row["docs"]
            .as_array()
            .and_then(|d| d.first())
            .and_then(Value::as_str)
            .and_then(parse_address)
        {
            if is_trunk_member(doc, &member) {
                head = Some(member);
            }
        }
    })?;
    Ok(head)
}

/// The commit position of the `publish` row that minted `member`, off its
/// own rows of the feed; `None` where the feed no longer holds it.
pub(super) fn position_of(
    board: &Board,
    token: Option<&Token>,
    member: &Address,
) -> Result<Option<u64>, Halt> {
    let mut at = None;
    let text = member.to_string();
    feed_rows(board, token, &text, |row| {
        if at.is_none()
            && row["op"].as_str() == Some("publish")
            && row["docs"].as_array().and_then(|d| d.first()).and_then(Value::as_str)
                == Some(text.as_str())
        {
            at = row["at"].as_u64();
        }
    })?;
    Ok(at)
}

/// Every row of the feed under `under`, oldest first, from the floor to the
/// head: the retention floor restarts the walk at the floor, a page past the
/// byte budget is re-asked at the limit that fits.
fn feed_rows(
    board: &Board,
    token: Option<&Token>,
    under: &str,
    mut each: impl FnMut(&Value),
) -> Result<(), Halt> {
    let mut since = 0u64;
    let mut limit = None;
    loop {
        let query = ChangesQuery { since, under: Some(under), drafts: false, limit };
        match board.changes(token, &query)? {
            ChangesAnswer::Page(page) => {
                for row in &page.changes {
                    each(row);
                }
                if !page.more {
                    return Ok(());
                }
                since = page.last;
            }
            ChangesAnswer::HistoryReclaimed { floor } => {
                // The page is `(since, head]`, so the oldest answerable
                // position is reached from the one below it.
                let next = floor.map_or(since + 1, |f| f.saturating_sub(1));
                if next <= since {
                    return Ok(());
                }
                since = next;
            }
            ChangesAnswer::TooLarge { fits } => limit = Some(fits),
            ChangesAnswer::Closed => return Err(closed("walking the change feed")),
        }
    }
}
