//! The publication composition — a draft's one `publish` request, composed
//! (the link-sets design `_designs/LINK-SETS/2026-10-17-link-sets-design.md`
//! §5.1–§5.8; the client lane's brief 1).
//!
//! The daemon takes ONE `publish` request that carries the links a person
//! accepts, the marks they took off, the sets their page is read with, the
//! kept places that re-window the draft and a first edition's mint and
//! claim, and writes it all in one commit (wire.md §The publish shot and
//! head-float). This module composes that request from a draft and a
//! selection, as ONE composition family in P28's layer, beside `merge` and
//! behind `acting`: every step is a function the caller sequences, every
//! input is typed, every output is DATA with a code or a kind — the words a
//! person reads are the copy's and the UI lane's, never this module's — and
//! the composition holds its frames, its reads, its armed refusals and its
//! order in one place. The order:
//!
//! 1. [`enumerate`](mod@enumerate) — THE ENUMERATION (§5.1): one `image` of the draft
//!    inverted over the held selection, one `find_links_v` over the
//!    selection's V-spans as one region array, each address kept where its
//!    home's account is the person's exactly, each kept link read once and
//!    kept where its STORED endset touches the selection through a content
//!    span; the read-through of the counterpart records whose `to` lies in
//!    the selection and the links on their `from` spans by two batched
//!    four-set reads; the filter's `in_claims` and `out_claims` per
//!    candidate, a candidate dropped where an active claim of the person's
//!    names a public successor homed in a published document of theirs
//!    covering the published spans; the candidates grouped by HOME.
//! 2. [`panel`](mod@panel) — THE PANEL's DATA (§5.2): the rows by home in the design's
//!    order with each set's state and label, the links folded by type with
//!    their far documents, the line counts, the formatting line by its test,
//!    the held removals as its job list with the re-makes split out, the
//!    public row's read-with state; and THE COUNT's four numbers from the
//!    rows as switched (PUB-3.8).
//! 3. [`price`](mod@price) — THE PRICE (§5.6): the lists, the body, the staged bytes,
//!    the in-lock reads, each against its cap, from the worst-case table the
//!    daemon prices by, pinned equal to it.
//! 4. [`request`](mod@request) — THE RE-READ (§5.6, §5.7) and THE REQUEST (§5.7): the
//!    enumeration read again over the same held selection and the two
//!    answers diffed, the held runs placed by the one image, a difference
//!    answered as a re-statement for the caller to confirm again; then the
//!    request built from the confirmed rows — every member, the kept places,
//!    the member-position end spelled canonically from the client's own
//!    runs, the signed body through the one body builder, a fresh `id`.
//! 5. [`send`](mod@send) — THE SEND AND THE FACES (§5.7): the frame under the token,
//!    never unsigned on a claimed board, the one re-ask under the same `id`,
//!    the refusal family as typed arms with their sites, the one re-sign at
//!    a skipped deposit.
//! 6. [`landed`](mod@landed) — THE LANDED TEST (§5.5, §5.7): the twin pre-check before
//!    the act, and after a lost answer or `already_published` the one test
//!    that says whether THIS request's effect committed and in which member
//!    — by the draft's records, by the walk from the base, or by the edition
//!    claim — the position-fenced read per home and the retract-mark
//!    liveness read inside it.
//!
//! The caller — the shell for the page (brief 2), the merge landing for its
//! bare shot, a test — holds the selection as I-runs in V-order (P51), its
//! readable drafts, its published documents, the rows' switches and the
//! answers at a window onto its own unpublished origin; nothing here asks a
//! person anything. Every read goes through one door, `Door`, under the
//! caller's token, which counts its frames per step and caches each link's
//! value — links never change — so the report can say what each step costs.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use skep_address::Address;

use crate::address::{account_of, document_of, parse_address};
use crate::board::answers::{self, IRun, LinkValue, Metadata};
use crate::board::{frames, Answer, Board, Rejection, Token};
use crate::halt::Halt;
use crate::sign::Signer;

pub mod enumerate;
pub mod landed;
pub mod panel;
pub mod price;
pub mod request;
pub mod send;

#[cfg(test)]
mod tests;

pub use enumerate::{enumerate, Candidate, Enumeration, Placement, Record, Successor, Via, MAX_WIRE_LIST};
pub use landed::{landed, twin_precheck, Base, Missing, Recomposed, Verdict};
pub use panel::{count, panel, Count, Destination, Formatting, LineCounts, Panel, Removal, Row, RowKind, Switches, TypeFold};
pub use price::{price, Price, Term};
pub use request::{build, reread, Answer as OriginAnswer, Built, Confirmed, Counterpart, End, Entry, EntryHome, Inert, Piece, Reread, Request, Restatement, Unspellable};
pub use send::{send, Ack, AckVia, OwnFault, RaceKey, Refusal, Sent};

/// One run of permanent content I-addresses — the selection's unit, and a
/// request's.
///
/// `width` positions of the document `origin`'s content I-space from the
/// ordinal `i_start`: the address `origin·0·1·i_start` and the `width − 1`
/// after it. The origin is the document whose chain minted the positions —
/// the draft for its own words, the edition's trunk for kept words, another
/// document for a window. It is the shape the merge's core holds too; the
/// merge stands behind its own feature, so this module spells its own.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Run {
    /// The document whose chain minted the positions.
    pub origin: Address,
    /// The first position's ordinal in the origin's content subspace.
    pub i_start: u64,
    /// How many positions the run holds; at least one.
    pub width: u64,
}

impl Run {
    /// Returns a run over `width` positions of `origin` from `i_start`.
    pub fn new(origin: Address, i_start: u64, width: u64) -> Run {
        Run { origin, i_start, width }
    }

    /// Returns the ordinal one past the run's last position.
    pub fn reach(&self) -> u64 {
        self.i_start.saturating_add(self.width)
    }

    /// Returns the content chain the run lies on — `origin.0.1`, the spelling
    /// an I-address opens with.
    pub fn chain(&self) -> String {
        format!("{}.0.1", self.origin)
    }

    /// Returns the run's first I-address in its dotted spelling.
    pub fn i_start_text(&self) -> String {
        format!("{}.{}", self.chain(), self.i_start)
    }

    /// Returns the run as the piece of itself over `[from, to)` of its
    /// ordinals, `None` where the two do not cut it.
    pub fn piece(&self, from: u64, to: u64) -> Option<Run> {
        (from >= self.i_start && to <= self.reach() && from < to).then(|| Run::new(self.origin.clone(), from, to - from))
    }

    /// Returns the overlap of the run with `[first, reach)` on `chain`, as
    /// ordinals, where the chain is this run's.
    pub fn overlap(&self, chain: &str, first: u64, reach: u64) -> Option<(u64, u64)> {
        if self.chain() != chain {
            return None;
        }
        let (lo, hi) = (self.i_start.max(first), self.reach().min(reach));
        (lo < hi).then_some((lo, hi))
    }
}

/// A stored span read as an I-span: its content chain, its first ordinal and
/// its width — the shape every stored-endset test and every mapping through
/// a record works in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ISpan {
    /// The content chain, `document.0.1`.
    pub chain: String,
    /// The first ordinal.
    pub first: u64,
    /// The positions.
    pub width: u64,
}

impl ISpan {
    /// Reads a stored span as an I-span: a span whose start is a content
    /// element address and whose width is one count at that depth. `None`
    /// for a unit span at a document, an account or a link, and for a span
    /// of another shape.
    pub fn of(span: &answers::LinkSpan) -> Option<ISpan> {
        let width = span.count()?;
        let (chain, first) = span.start.rsplit_once('.')?;
        let first: u64 = first.parse().ok()?;
        let parsed = parse_address(&span.start)?;
        if parsed.subspace() != Some(&skep_address::content_subspace()) || parsed.element_field().is_none() {
            return None;
        }
        Some(ISpan { chain: chain.to_string(), first, width })
    }

    /// Returns the ordinal one past the last.
    pub fn reach(&self) -> u64 {
        self.first.saturating_add(self.width)
    }

    /// Returns the document the chain lies in.
    pub fn document(&self) -> Option<String> {
        document_of(&format!("{}.{}", self.chain, self.first))
    }

    /// Returns the span as the run it names.
    pub fn run(&self) -> Option<Run> {
        Some(Run::new(parse_address(&self.document()?)?, self.first, self.width))
    }

    /// Returns the overlap with `[first, reach)` on `chain`.
    pub fn overlap(&self, chain: &str, first: u64, reach: u64) -> Option<(u64, u64)> {
        if self.chain != chain {
            return None;
        }
        let (lo, hi) = (self.first.max(first), self.reach().min(reach));
        (lo < hi).then_some((lo, hi))
    }

    /// Returns whether any of `runs` holds a position of the span.
    pub fn touches(&self, runs: &[Run]) -> bool {
        runs.iter().any(|r| r.overlap(&self.chain, self.first, self.reach()).is_some())
    }

    /// Returns whether every position of the span lies in `runs`.
    pub fn within(&self, runs: &[Run]) -> bool {
        let mut covered = 0u64;
        for r in runs {
            if let Some((lo, hi)) = r.overlap(&self.chain, self.first, self.reach()) {
                covered += hi - lo;
            }
        }
        covered >= self.width
    }

    /// Returns the span's spelling as a `spans`-form element.
    pub fn wire(&self) -> Value {
        frames::i_span(&format!("{}.{}", self.chain, self.first), self.width)
    }
}

/// Returns the document a link address is homed in: the text before its
/// `.0.2.` — a member's address for a link homed in a version member.
pub fn home_of_link(link: &str) -> Option<&str> {
    link.rfind(".0.2.").map(|idx| &link[..idx])
}

/// Returns the trunk document an address lies in — a member's document, a
/// link's or an element's document.
pub fn trunk_of(addr: &str) -> Option<String> {
    document_of(addr)
}

/// The person publishing: the board, the signed session they act as and
/// the hand that signs.
///
/// The facts are taken as facts, never as the ceremony's own session type:
/// the embedder opens the session through the handshake and lends its
/// token, its account and its signer here, as the merge's `Merger` does.
#[derive(Clone, Copy)]
pub struct Publisher<'a> {
    /// The board.
    pub board: &'a Board,
    /// The signed session's token — what every read and the write present.
    pub token: &'a Token,
    /// The account the session acts as, `principal_prefix(principal)`.
    pub account: &'a str,
    /// The signer the session was opened with — the request's hand.
    pub signer: &'a dyn Signer,
}

/// What the caller holds for one publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inputs {
    /// `E`, the published document — the document form; `None` at the mint
    /// form, where [`Inputs::mint`] names the parent account.
    pub doc: Option<Address>,
    /// The parent account the edition is minted under — THE MINT FORM, a
    /// first publication of a free-standing draft (§5.7 (iv)).
    pub mint: Option<Address>,
    /// Whether the request carries the edition claim.
    ///
    /// Sent only with `mint` in this build: the claim admitted without a
    /// mint (the owner's ruling (i)) is the daemon's own lane, and this
    /// builder gains the arm then (`request`'s doc).
    pub claim: bool,
    /// The base member and `base_extent` — `None` the birth shape.
    pub base: Option<(Address, u64)>,
    /// `D`, the staging draft the records are homed in.
    pub draft: Address,
    /// THE SELECTION, held as I-runs in V-order (P51): the runs the client
    /// composes the shot from.
    pub selection: Vec<Run>,
    /// The person's notes documents, in the order their rows stand.
    pub notes: Vec<Address>,
    /// Every draft of the person's the read-through reads — their own, in
    /// the caller's order; the draft itself among them where it is one.
    pub readable_drafts: Vec<Address>,
    /// The person's own published documents, the client's own list: key
    /// (i)'s home test and the public rows' destinations.
    pub published: Vec<Address>,
}

impl Inputs {
    /// Returns the trunk the member is minted under — `doc` at the document
    /// form, `None` at the mint form (minted in the commit).
    pub fn trunk(&self) -> Option<&Address> {
        self.doc.as_ref()
    }

    /// Returns the term the entry frame's `doc` row names: the trunk, or the
    /// account at the mint form.
    pub fn term(&self) -> Option<&Address> {
        self.doc.as_ref().or(self.mint.as_ref())
    }

    /// Returns whether `addr` lies in a published document of the person's,
    /// off the caller's own list and no read.
    pub fn is_published_home(&self, home: &str) -> bool {
        let trunk = trunk_of(home);
        self.published.iter().any(|p| {
            let p = p.to_string();
            p == home || trunk.as_deref() == Some(p.as_str())
        })
    }
}

/// Why a step stopped: the composition's own arms, and every other halt
/// carried as it arrived.
///
/// The arms a caller acts on are named; a read's own halt, a refusal the
/// composition does not arm and every transport fault ride
/// [`Fault::Halt`]. The send's refusal family is [`send::Refusal`], a
/// RESULT of the send and not a fault of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// `withheld` on a document a read needs.
    Unreadable(Address),
    /// `doc_not_registered` on a document a read needs.
    NoSuchDocument(Address),
    /// The death signal under the session: the session ended.
    SessionEnded,
    /// `scan_busy` past the bounded reissues on a read; nothing written.
    Busy,
    /// A held run the draft no longer arranges whole at one place, at the
    /// FIRST enumeration — before any re-read can re-state it.
    SelectionNotArranged {
        /// The run's index in the selection.
        index: usize,
    },
    /// The board answered a document this client cannot read as the frame's
    /// answer; `op` the frame, `body` the answer, clipped.
    Shape {
        /// The frame's op.
        op: String,
        /// The answer, clipped.
        body: String,
    },
    /// Every other halt: the board's refusals verbatim, transport faults.
    Halt(Halt),
}

impl From<Halt> for Fault {
    fn from(h: Halt) -> Fault {
        Fault::Halt(h)
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::Unreadable(d) => write!(f, "{d} is not readable to this reader (withheld); nothing was published"),
            Fault::NoSuchDocument(d) => write!(f, "{d} is not registered at this board"),
            Fault::SessionEnded => f.write_str("the session ended (Skepd-Session: closed); nothing further was read or written"),
            Fault::Busy => f.write_str("the board was busy (scan_busy) past the bounded reissues; nothing was published"),
            Fault::SelectionNotArranged { index } => write!(f, "the draft no longer arranges the selection's run {index} whole at one place"),
            Fault::Shape { op, body } => write!(f, "`{op}` answered a document this client cannot read: {body}"),
            Fault::Halt(h) => h.fmt(f),
        }
    }
}

impl std::error::Error for Fault {}

/// How many times a `scan_busy` on a read is reissued, under a short
/// backoff, before the step halts [`Fault::Busy`] (the link-sets design
/// §5.7: "REISSUED in B1-S4's form a bounded number of times under a short
/// backoff, nothing written between").
pub const SCAN_BUSY_REISSUES: u32 = 6;

/// The door of every read this module makes: the board under the caller's
/// token, the frames counted per step, each link's value cached.
pub(crate) struct Door<'a> {
    board: &'a Board,
    token: &'a Token,
    as_of: Cell<u64>,
    step: Cell<&'static str>,
    frames: RefCell<Vec<(&'static str, usize)>>,
    links: RefCell<BTreeMap<String, Option<LinkValue>>>,
    meta: RefCell<BTreeMap<String, Metadata>>,
}

impl<'a> Door<'a> {
    /// Returns a door at `board` under `token`.
    pub(crate) fn new(board: &'a Board, token: &'a Token) -> Door<'a> {
        Door { board, token, as_of: Cell::new(0), step: Cell::new("start"), frames: RefCell::new(Vec::new()), links: RefCell::new(BTreeMap::new()), meta: RefCell::new(BTreeMap::new()) }
    }

    /// Names the step the frames from here on are counted under.
    pub(crate) fn step(&self, name: &'static str) {
        self.step.set(name);
    }

    /// Returns the frames sent per step, in the order the steps ran.
    pub(crate) fn counts(&self) -> Vec<(&'static str, usize)> {
        self.frames.borrow().clone()
    }

    /// Returns the highest `as_of` answered so far.
    pub(crate) fn as_of(&self) -> u64 {
        self.as_of.get()
    }

    fn count(&self) {
        let step = self.step.get();
        let mut frames = self.frames.borrow_mut();
        match frames.last_mut() {
            Some((s, n)) if *s == step => *n += 1,
            _ => frames.push((step, 1)),
        }
    }

    /// Sends one frame under the token and answers its document, a rejection
    /// included; `scan_busy` is reissued under a short backoff up to
    /// [`SCAN_BUSY_REISSUES`] times.
    pub(crate) fn read(&self, frame: &Value) -> Result<Value, Fault> {
        for attempt in 0..=SCAN_BUSY_REISSUES {
            self.count();
            match self.board.op(Some(self.token), frame) {
                Ok(Answer::Closed) => return Err(Fault::SessionEnded),
                Ok(Answer::Document(v)) => {
                    if let Some(a) = answers::as_of(&v) {
                        self.as_of.set(self.as_of.get().max(a));
                    }
                    return Ok(v);
                }
                Err(Halt::Refused(r)) if r.code == "scan_busy" && attempt < SCAN_BUSY_REISSUES => {
                    thread::sleep(Duration::from_millis(20 * u64::from(attempt + 1)));
                }
                Err(Halt::Refused(r)) if r.code == "scan_busy" => return Err(Fault::Busy),
                Err(h) => return Err(Fault::Halt(h)),
            }
        }
        Err(Fault::Busy)
    }

    /// Maps the refusal a read of `about` answered.
    pub(crate) fn refuse(&self, about: &str, r: &Rejection, v: &Value) -> Fault {
        let addr = || parse_address(about);
        match (r.key(), addr()) {
            ("withheld", Some(a)) => Fault::Unreadable(a),
            ("doc_not_registered", Some(a)) => Fault::NoSuchDocument(a),
            _ => Fault::Halt(r.refused(v)),
        }
    }

    /// Reads a frame about `about` whose answer must be a document.
    pub(crate) fn answered(&self, about: &str, frame: &Value) -> Result<Value, Fault> {
        let v = self.read(frame)?;
        match Rejection::of(&v) {
            Some(r) => Err(self.refuse(about, &r, &v)),
            None => Ok(v),
        }
    }

    /// Reads a discovery's `addrs` — a `find_links_v` or a four-set.
    pub(crate) fn addrs(&self, about: &str, frame: &Value) -> Result<Vec<String>, Fault> {
        let v = self.answered(about, frame)?;
        if v["resp"].as_str() != Some("addrs") {
            return Err(shape(frame, &v));
        }
        Ok(answers::addrs(&v).into_iter().map(str::to_string).collect())
    }

    /// Reads a link's value once — `None` for an absent address or one in a
    /// home the reader may not read — and keeps it: links never change.
    pub(crate) fn link(&self, a: &str) -> Result<Option<LinkValue>, Fault> {
        if let Some(cached) = self.links.borrow().get(a) {
            return Ok(cached.clone());
        }
        let frame = frames::read_link(a);
        let v = self.answered(a, &frame)?;
        let value = answers::link_value(&v).ok_or_else(|| shape(&frame, &v))?;
        self.links.borrow_mut().insert(a.to_string(), value.clone());
        Ok(value)
    }

    /// Reads `doc_metadata(doc)` once per document and keeps it.
    pub(crate) fn metadata(&self, doc: &str) -> Result<Metadata, Fault> {
        if let Some(cached) = self.meta.borrow().get(doc) {
            return Ok(cached.clone());
        }
        let frame = frames::doc_metadata(doc);
        let v = self.answered(doc, &frame)?;
        let meta = answers::metadata(&v).ok_or_else(|| shape(&frame, &v))?;
        self.meta.borrow_mut().insert(doc.to_string(), meta.clone());
        Ok(meta)
    }

    /// Reads the content extent of `doc`.
    pub(crate) fn extent(&self, doc: &str) -> Result<u64, Fault> {
        let frame = frames::span_set(doc);
        let v = self.answered(doc, &frame)?;
        if v["resp"].as_str() != Some("span_set") {
            return Err(shape(&frame, &v));
        }
        Ok(answers::content_extent(&v))
    }

    /// Images content ordinals `from ..` of `doc`, `width` of them — whole
    /// where the runs are under the run budget, else in parts, halving on
    /// `image_too_large` until each part answers, never refused: a run cut
    /// by a part boundary is re-joined by I-adjacency.
    pub(crate) fn image(&self, doc: &str, from: u64, width: u64) -> Result<Vec<IRun>, Fault> {
        let mut out: Vec<IRun> = Vec::new();
        self.image_into(doc, from, width, &mut out)?;
        Ok(out)
    }

    fn image_into(&self, doc: &str, from: u64, width: u64, out: &mut Vec<IRun>) -> Result<(), Fault> {
        if width == 0 {
            return Ok(());
        }
        let frame = frames::image(doc, from, width);
        let v = self.read(&frame)?;
        if let Some(r) = Rejection::of(&v) {
            if r.key() != "image_too_large" || width == 1 {
                return Err(self.refuse(doc, &r, &v));
            }
            let left = width / 2;
            self.image_into(doc, from, left, out)?;
            return self.image_into(doc, from + left, width - left, out);
        }
        let runs = answers::i_runs(&v, width).ok_or_else(|| shape(&frame, &v))?;
        for mut run in runs {
            run.ordinal += from - 1;
            match out.last_mut() {
                Some(last) if last.prefix == run.prefix && last.first + last.width == run.first && last.ordinal + last.width == run.ordinal => last.width += run.width,
                _ => out.push(run),
            }
        }
        Ok(())
    }

    /// Reads the values at content ordinals `from ..` of `doc`, `width` of
    /// them, one item a position, in parts on `too_many_items`.
    pub(crate) fn values(&self, doc: &str, from: u64, width: u64) -> Result<Vec<Vec<u8>>, Fault> {
        let mut out = Vec::with_capacity(width as usize);
        self.values_into(doc, from, width, &mut out)?;
        Ok(out)
    }

    fn values_into(&self, doc: &str, from: u64, width: u64, out: &mut Vec<Vec<u8>>) -> Result<(), Fault> {
        if width == 0 {
            return Ok(());
        }
        let frame = frames::retrieve_v(doc, from, width);
        let v = self.read(&frame)?;
        if let Some(r) = Rejection::of(&v) {
            if r.key() != "too_many_items" || width == 1 {
                return Err(self.refuse(doc, &r, &v));
            }
            let left = width / 2;
            self.values_into(doc, from, left, out)?;
            return self.values_into(doc, from + left, width - left, out);
        }
        let items = answers::delivery_values(&v).ok_or_else(|| shape(&frame, &v))?;
        if items.len() as u64 != width {
            return Err(shape(&frame, &v));
        }
        out.extend(items);
        Ok(())
    }
}

/// Faces an answer without the shape the frame's `resp` promises.
pub(crate) fn shape(frame: &Value, v: &Value) -> Fault {
    Fault::Shape { op: frame["op"].as_str().unwrap_or("?").to_string(), body: crate::halt::clipped(&v.to_string(), 200).to_string() }
}

/// Returns whether `home`'s account is `account` exactly — the owned-home
/// test (§5.1), off the address and no read.
pub(crate) fn owned_by(home: &str, account: &str) -> bool {
    account_of(home).as_deref() == Some(account)
}

/// Returns the member positions `runs` tile from 1: per run its first
/// position.
pub(crate) fn positions_of(runs: &[Run]) -> Vec<u64> {
    let mut out = Vec::with_capacity(runs.len());
    let mut position = 1u64;
    for r in runs {
        out.push(position);
        position = position.saturating_add(r.width);
    }
    out
}

/// Returns the canonical member-position spelling of `pieces` over `runs`:
/// each piece's addresses at the LOWEST member position holding each,
/// consecutive positions merged — the rule the daemon's `member_end` spells
/// the row by (wire.md §Arrangement, `publish`; the link-sets design §5.7,
/// W3 (a)), computed here from the client's own runs. `None` where a piece's
/// address lies in no run.
pub(crate) fn canonical_member_spans(runs: &[Run], pieces: &[ISpan]) -> Option<Vec<(u64, u64)>> {
    let positions = positions_of(runs);
    let mut out: Vec<(u64, u64)> = Vec::new();
    for piece in pieces {
        let reach = piece.reach();
        let holding: Vec<(usize, &Run)> = runs.iter().enumerate().filter(|(_, r)| r.chain() == piece.chain && r.i_start < reach && r.reach() > piece.first).collect();
        let mut cuts = std::collections::BTreeSet::from([piece.first, reach]);
        for (_, r) in &holding {
            for c in [r.i_start, r.reach()] {
                if c > piece.first && c < reach {
                    cuts.insert(c);
                }
            }
        }
        let cuts: Vec<u64> = cuts.into_iter().collect();
        for pair in cuts.windows(2) {
            let (x, y) = (pair[0], pair[1]);
            let best = holding.iter().filter(|(_, r)| r.i_start <= x && x < r.reach()).min_by_key(|(k, r)| positions[*k] + (x - r.i_start))?;
            let ordinal = positions[best.0] + (x - best.1.i_start);
            match out.last_mut() {
                Some(last) if last.0 + last.1 == ordinal => last.1 += y - x,
                _ => out.push((ordinal, y - x)),
            }
        }
    }
    Some(out)
}

/// Resolves member-position spans over `runs` to the I-spans the member
/// holds at them, I-adjacent pieces merged — the daemon's `member_end`'s
/// stored half, which the landed test compares a copy's stored slot to.
/// `None` where a span lies outside the positions the runs place.
pub(crate) fn resolve_member_spans(runs: &[Run], spans: &[(u64, u64)]) -> Option<Vec<ISpan>> {
    let positions = positions_of(runs);
    let placed: u64 = runs.iter().map(|r| r.width).sum();
    let mut pieces: Vec<ISpan> = Vec::new();
    for &(ordinal, width) in spans {
        if ordinal == 0 || width == 0 || ordinal.checked_add(width)? - 1 > placed {
            return None;
        }
        let reach = ordinal + width;
        for (k, r) in runs.iter().enumerate() {
            let (p, p_reach) = (positions[k], positions[k] + r.width);
            let (lo, hi) = (ordinal.max(p), reach.min(p_reach));
            if lo >= hi {
                continue;
            }
            let piece = ISpan { chain: r.chain(), first: r.i_start + (lo - p), width: hi - lo };
            match pieces.last_mut() {
                Some(last) if last.chain == piece.chain && last.reach() == piece.first => last.width += piece.width,
                _ => pieces.push(piece),
            }
        }
    }
    Some(pieces)
}

/// Returns a fresh per-request `id`: sixteen OS-drawn bytes in lowercase hex
/// under the publication's prefix — unique within the session (wire.md
/// §Correlation and idempotency), FRESH per request, re-signed or
/// re-composed request included (§5.7, A LOST ACKNOWLEDGMENT).
pub fn fresh_id() -> String {
    format!("publication.{}", crate::hex::encode(&crate::sign::fresh_bytes(16)))
}
