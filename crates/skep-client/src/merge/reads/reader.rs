//! The door of the merge's reads: the [`Reader`] and a session's end.
//!
//! A [`Reader`] reads at the head or as of one position, under the caller's
//! token or as a guest, and keeps the highest `as_of` its answers carry. It
//! reads values at the head alone, many stretches a read: a member's by its
//! V-ordinals ([`Reader::values_by_ordinal`]), and words a draft or a fork
//! held by the I-addresses its image served ([`Reader::values_by_identity`]),
//! each read sized to the board's budgets and the dialer's answer cap and
//! halved where the board or the dialer refuses its size. A death signal met
//! under the token is answered by [`session_ended`], faced for the act's
//! [`OnEnd`]. Which reads a merge makes, in which order and at which
//! position, is the `reads` module's doc.

use std::cell::Cell;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::answers::{self, IRun, Metadata};
use crate::board::{frames, guest_closed, Answer, AtAnswer, Board, Image, Rejection, Token};
use crate::dial::{DialError, MAX_ANSWER_BYTES};
use crate::halt::Halt;
use crate::merge::compose::Item;
use crate::publication::MAX_WIRE_LIST;

use super::refusal::Refusal;
use super::{HISTORY_BUSY_RETRIES, MAX_DELIVERY_ITEMS};

// ── the reader ────────────────────────────────────────────────────────────

/// One document's image, whole.
///
/// It holds the document, the position it was read at, its extent and its
/// runs as served, each run's `ordinal` the document's own V-ordinal, the
/// position the answers named, and whether it is the document's own
/// arrangement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Imaged {
    /// The document imaged — a member, a draft, or the bare document whose
    /// own arrangement a base is.
    pub(in crate::merge) doc: Address,
    /// Whether the image is `doc`'s own arrangement, read with `own`
    /// (PUB-2.66): a base that is the bare document, its arrangement from
    /// before its first version. The join's `compare` reads the base region
    /// so too ([`check_join`]). The head and the sides are never read so,
    /// and no value is read through an own image.
    ///
    /// [`check_join`]: super::check_join
    pub(in crate::merge) own: bool,
    /// The position the document was read at; `None` the head.
    ///
    /// A composition images at the head, but for a draft side named at a
    /// position, which it reads with every side that can change as of that
    /// position; a verification images as of the position its record names
    /// (the `reads` module's doc). No value is read at it: values are read at
    /// the head, a member's by the V-ordinals the image holds them at and a
    /// draft's or a fork's by the I-addresses the image served.
    pub(in crate::merge) at: Option<u64>,
    /// The content extent.
    pub(crate) extent: u64,
    /// The runs, in V order.
    pub(crate) runs: Vec<IRun>,
    /// The highest `as_of` the extent's and the image's answers carried.
    ///
    /// It is `at` where the document was read as of a position, which the
    /// board echoes (wire.md §Reading history), and the head's position at
    /// the read where it was read at the head: a later read as of it
    /// answers the same image. `None` where no answer carried one.
    pub(in crate::merge) as_of: Option<u64>,
}

impl Imaged {
    /// Returns the runs as an [`Image`], each at the spelling the board served.
    ///
    /// A run keeps its own prefix, a member's chain as the member's, where
    /// the core's runs name the trunk alone ([`runs_of`]); a run holding no
    /// address is dropped, as `whole_image` drops one, and the ordinals are
    /// the image's own from 1. It is what a write of a state the board held
    /// is mapped and spelled from: the restore's, and the take-backs'.
    ///
    /// # Errors
    ///
    /// An image whose positions reach the largest ordinal is the board's
    /// fault, faced.
    ///
    /// [`runs_of`]: super::runs_of
    pub(crate) fn into_image(self) -> Result<Image, Halt> {
        let Imaged { doc, at, runs, .. } = self;
        let pieces =
            runs.into_iter().filter(|r| r.width > 0).map(|r| (r.prefix, r.first, r.width));
        Image::tiled(pieces).ok_or_else(|| {
            let read = at.map_or_else(|| "at the head".to_string(), |at| format!("as of {at}"));
            Halt::face(
                "a document's image cannot be held",
                format!("the image of {doc} {read} arranges positions up to the largest ordinal"),
                "this is a board fault; nothing was written",
            )
        })
    }
}

/// The door of the merge's reads, and the restore's: a board, the caller's
/// token and the way on its act leaves where the session ends.
///
/// The highest `as_of` its frames' answers carry is kept. The feed walk
/// goes through it too ([`feed_rows`]); the journal's reads ask the board
/// directly.
///
/// [`feed_rows`]: super::feed_rows
pub(crate) struct Reader<'a> {
    pub(super) board: &'a Board,
    pub(super) token: Option<&'a Token>,
    as_of: Cell<u64>,
    pub(super) on_end: OnEnd,
}

impl<'a> Reader<'a> {
    /// Returns a reader at `board` as `token`'s principal, or as a guest,
    /// for an act whose session's end leaves `on_end`.
    pub(crate) fn new(board: &'a Board, token: Option<&'a Token>, on_end: OnEnd) -> Reader<'a> {
        Reader { board, token, as_of: Cell::new(0), on_end }
    }

    /// Returns the highest `as_of` answered so far.
    pub(in crate::merge) fn as_of(&self) -> u64 {
        self.as_of.get()
    }

    /// Returns the way on this reader's act leaves where the session ends.
    pub(in crate::merge) fn on_end(&self) -> OnEnd {
        self.on_end
    }

    fn note(&self, v: &Value) {
        if let Some(a) = answers::as_of(v) {
            self.as_of.set(self.as_of.get().max(a));
        }
    }

    /// Reads one frame at the head, or as of `at` through `/op-at`.
    ///
    /// It answers the response document, a rejection included; `/op-at`'s
    /// `history_busy` is retried with backoff up to [`HISTORY_BUSY_RETRIES`]
    /// times.
    ///
    /// # Errors
    ///
    /// The death signal under the token is [`Refusal::SessionEnded`],
    /// faced for this reader's act; with no token it is the board's or the
    /// transport's fault, [`Refusal::Halt`] — at the head this reader's own
    /// `guest_closed` face, at a position [`Board::op_at`]'s — for no session
    /// stood to end; a position the board has reclaimed the history at is
    /// [`Refusal::HistoryReclaimed`], one past its head
    /// [`Refusal::BeyondHead`] and one inside a commit
    /// [`Refusal::NotAPosition`], each the caller's position and never read
    /// at the head instead; [`Refusal::HistoryBusy`] past the retries;
    /// [`Board::op`]'s and [`Board::op_at`]'s other errors.
    pub(crate) fn read(&self, frame: &Value, at: Option<u64>) -> Result<Value, Refusal> {
        let Some(at) = at else {
            return match self.board.op(self.token, frame)? {
                Answer::Closed if self.token.is_none() => Err(guest_closed().into()),
                Answer::Closed => Err(session_ended("reading", self.on_end)),
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
                AtAnswer::Closed => {
                    return Err(session_ended("reading at a position", self.on_end))
                }
                AtAnswer::Busy => {
                    if attempt < HISTORY_BUSY_RETRIES {
                        thread::sleep(Duration::from_millis(20 * u64::from(attempt + 1)));
                    }
                }
                AtAnswer::HistoryReclaimed { floor } => {
                    return Err(Refusal::HistoryReclaimed { at, floor });
                }
                AtAnswer::BeyondHead { head } => {
                    return Err(Refusal::BeyondHead { at, head, recorded: None });
                }
                AtAnswer::NotAPosition { nearest } => {
                    return Err(Refusal::NotAPosition { at, nearest, recorded: None });
                }
            }
        }
        Err(Refusal::HistoryBusy)
    }

    /// Maps the refusal a read answered.
    ///
    /// `withheld` is [`Refusal::Unreadable`] and `doc_not_registered`
    /// [`Refusal::NoSuchDocument`], each naming the document the rejection's
    /// `site.addr` names — of a read naming several, the first the board
    /// refused in declaration order (wire.md §Rejections) — else `doc`, the
    /// document a read of one document is of; the rest the board's own,
    /// surfaced verbatim. A read of several documents — the join's `compare`,
    /// the read by identity — passes no `doc`, so where the board names no
    /// document this client parses, its refusal is surfaced verbatim too,
    /// never one of the read's documents standing in for the one it refused
    /// (SP-18).
    pub(in crate::merge) fn refuse(&self, doc: Option<&Address>, r: &Rejection, v: &Value) -> Refusal {
        let named = r.site().addr.as_deref().and_then(parse_address).or_else(|| doc.cloned());
        match (r.key(), named) {
            ("withheld", Some(doc)) => Refusal::Unreadable(doc),
            ("doc_not_registered", Some(doc)) => Refusal::NoSuchDocument(doc),
            _ => Refusal::Halt(r.refused(v)),
        }
    }

    /// Reads a frame of `doc` whose answer must be a document.
    ///
    /// # Errors
    ///
    /// A rejection, mapped by [`Reader::refuse`]; otherwise [`Reader::read`]'s
    /// errors.
    pub(crate) fn answered(
        &self,
        doc: &Address,
        frame: &Value,
        at: Option<u64>,
    ) -> Result<Value, Refusal> {
        let v = self.read(frame, at)?;
        match Rejection::of(&v) {
            Some(r) => Err(self.refuse(Some(doc), &r, &v)),
            None => Ok(v),
        }
    }

    /// Reads `doc_metadata(doc)`, decoded, at the head or as of `at`.
    ///
    /// # Errors
    ///
    /// [`Reader::answered`]'s errors; an answer that does not decode, faced.
    pub(in crate::merge) fn metadata(&self, doc: &Address, at: Option<u64>) -> Result<Metadata, Refusal> {
        Ok(self.metadata_read(doc, at)?.0)
    }

    /// Reads `doc_metadata(doc)` as [`Reader::metadata`] does, with the
    /// answer's `as_of` beside it.
    ///
    /// It is a read whose `as_of` fixes a position for the reads after it: a
    /// verification's first, where its record names no position (the `reads`
    /// module's doc), and a draft's own at the head, which a restore or a
    /// take-back types its write against.
    ///
    /// # Errors
    ///
    /// As [`Reader::metadata`]'s.
    pub(crate) fn metadata_read(&self, doc: &Address, at: Option<u64>) -> Result<(Metadata, Option<u64>), Refusal> {
        let v = self.answered(doc, &frames::doc_metadata(&doc.to_string()), at)?;
        let meta = answers::metadata(&v).ok_or_else(|| shape("doc_metadata", &v))?;
        Ok((meta, answers::as_of(&v)))
    }

    /// Reads the content extent of `doc`, at the head or as of `at`.
    ///
    /// # Errors
    ///
    /// [`Reader::span_set`]'s errors.
    pub(in crate::merge) fn extent(&self, doc: &Address, at: Option<u64>) -> Result<u64, Refusal> {
        Ok(self.span_set(doc, at)?.0)
    }

    /// Reads the span set of `doc`, answering its content extent and the
    /// answer's `as_of`.
    ///
    /// # Errors
    ///
    /// [`Reader::answered`]'s errors; an answer that is no `span_set`, faced.
    pub(super) fn span_set(&self, doc: &Address, at: Option<u64>) -> Result<(u64, Option<u64>), Refusal> {
        let v = self.answered(doc, &frames::span_set(&doc.to_string()), at)?;
        if v["resp"].as_str() != Some("span_set") {
            return Err(shape("retrieve_doc_v_span_set", &v).into());
        }
        Ok((answers::content_extent(&v), answers::as_of(&v)))
    }

    /// Images content ordinals `from ..` of `doc`, `width` of them.
    ///
    /// The image is whole, whatever its runs: one frame where they are at or
    /// under the board's run budget, else a page a frame, each answered
    /// ([`Reader::image_read`]) — the runs in V order with each run's
    /// `ordinal` the document's own.
    ///
    /// # Errors
    ///
    /// [`Reader::image_read`]'s errors.
    pub(in crate::merge) fn image(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
    ) -> Result<Vec<IRun>, Refusal> {
        Ok(self.image_read(doc, at, from, width, false)?.0)
    }

    /// Images as [`Reader::image`] does — `doc`'s own arrangement where
    /// `own`, sent with `own` (PUB-2.66) — with the `as_of` the image
    /// answers: its one answer's, or its first page's, the position the
    /// read began at; `None` where nothing was read, or it carried none.
    ///
    /// A document in R runs is ⌈R ÷ 4,096⌉ frames, each answered: a short
    /// page is followed from its go-on, and the pages are one state's
    /// ([`paged_image`](answers::paged_image)). At the head, a continuation
    /// the board refuses because the draft changed begins the read again,
    /// and past the restart bound the pages are read as of the last first
    /// page's position, through `/op-at`. As of `at`, every page is read
    /// through `/op-at` there, where a state does not move: the board
    /// rebuilds the position once and keeps it for the read, one
    /// reconstruction and one of its two permits whatever the pages — 8 to
    /// 11 s for 16 pages a checkpoint cadence above a base, measured over a
    /// world of three documents; a board's base is larger — and a page that
    /// finds its read let go asks a reconstruction of its own, retried
    /// where the board is busy as any read at a position is.
    ///
    /// # Errors
    ///
    /// A refusal, mapped by [`Reader::refuse`] — `page_moved` among them,
    /// the board's own, where the pages could not be read as one state even
    /// at a position; an answer that is no image, faced; [`Reader::read`]'s
    /// errors.
    pub(super) fn image_read(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
        own: bool,
    ) -> Result<(Vec<IRun>, Option<u64>), Refusal> {
        if width == 0 {
            return Ok((Vec::new(), None));
        }
        let text = doc.to_string();
        let frame = if own {
            frames::image_own(&text, from, width)
        } else {
            frames::image(&text, from, width)
        };
        let v = answers::paged_image(&frame, |frame, moved_to| self.read(frame, moved_to.or(at)))?;
        if let Some(r) = Rejection::of(&v) {
            return Err(self.refuse(Some(doc), &r, &v));
        }
        let mut runs = answers::i_runs(&v, width).ok_or_else(|| shape("image", &v))?;
        for run in &mut runs {
            run.ordinal += from - 1;
        }
        Ok((runs, answers::as_of(&v)))
    }

    /// Reads the extent and the whole image of `doc`.
    ///
    /// Both are read at the head or as of `at`; the image's `as_of` is the
    /// highest the two reads answered.
    ///
    /// # Errors
    ///
    /// [`Reader::span_set`]'s and [`Reader::image_read`]'s errors.
    pub(crate) fn imaged(&self, doc: &Address, at: Option<u64>) -> Result<Imaged, Refusal> {
        let (extent, as_of) = self.span_set(doc, at)?;
        let (runs, imaged_as_of) = self.image_read(doc, at, 1, extent, false)?;
        Ok(Imaged {
            doc: doc.clone(),
            own: false,
            at,
            extent,
            runs,
            as_of: as_of.max(imaged_as_of),
        })
    }

    /// Reads `doc`'s own arrangement whole, at the head or as of `at`.
    ///
    /// It is the arrangement a published document held before its first
    /// version, which `image` with `own` answers (PUB-2.66), its `count`
    /// positions. `count` is the `own_count` the trunk's `doc_metadata` served where
    /// this read is made; at 0 nothing is read and the image is empty. The
    /// image is whole, in pages past the run budget, as [`Reader::image`]
    /// reads one.
    ///
    /// # Errors
    ///
    /// [`Reader::image_read`]'s errors.
    pub(in crate::merge) fn imaged_own(&self, doc: &Address, at: Option<u64>, count: u64) -> Result<Imaged, Refusal> {
        let (runs, as_of) = self.image_read(doc, at, 1, count, true)?;
        Ok(Imaged { doc: doc.clone(), own: true, at, extent: count, runs, as_of })
    }

    /// Reads the values at content ordinals `from ..` of `doc`, at the head.
    ///
    /// They are `width` of them, one item a position, read as
    /// [`Reader::values_by_ordinal`] reads one span.
    ///
    /// # Errors
    ///
    /// As [`Reader::values_by_ordinal`]'s.
    pub(in crate::merge) fn values(&self, doc: &Address, from: u64, width: u64) -> Result<Vec<Item>, Refusal> {
        Ok(self.values_by_ordinal(doc, &[(from, width)])?.pop().unwrap_or_default())
    }

    /// Reads the values of `doc`'s V-spans at the head, one list a span.
    ///
    /// Each span is `(from, width)`, its list one item a position. The
    /// spans go out in as few `retrieve_v` reads as the budgets allow,
    /// one spec a span (wire.md §Content & provenance reads): a read holds
    /// at most [`MAX_DELIVERY_ITEMS`] positions and `MAX_WIRE_LIST` specs, a
    /// span past what one has room for going on in the next. A read refused
    /// `too_many_items`, or whose answer passes the dialer's cap — a
    /// composite value's item is as long as the value — is asked again in
    /// halves, its specs split, then one spec's width (§8). A member's
    /// V-ordinals hold the same I-addresses at every position the merge
    /// reads it at — a version never changes, and the head only gains
    /// deposits past its extent — so the read needs no past position.
    ///
    /// # Errors
    ///
    /// A delivery holding a `withheld` item is [`Refusal::Unreadable`] naming
    /// the item's origin: `doc` is readable, but a run it windows from a
    /// document the reader may not read is masked at its own position
    /// (wire.md §Value encodings), and the value rule reads such runs as it
    /// reads a side's own. A delivery holding another item no value can be
    /// spelled from — a reference, a hex that does not decode, a kind this
    /// client does not know — is faced, as is one short of, or past, the
    /// positions asked; one position still refused `too_many_items` is the
    /// board's refusal verbatim, and one whose answer still passes the cap
    /// the dialer's halt; another refusal is mapped by [`Reader::refuse`];
    /// otherwise [`Reader::read`]'s errors.
    pub(in crate::merge) fn values_by_ordinal(&self, doc: &Address, spans: &[(u64, u64)]) -> Result<Vec<Vec<Item>>, Refusal> {
        let text = doc.to_string();
        let widths: Vec<u64> = spans.iter().map(|s| s.1).collect();
        self.read_values(&widths, |_| 0, |part| {
            let specs: Vec<(u64, u64)> = part.iter().map(|a| (spans[a.span].0 + a.into, a.width)).collect();
            let from = specs.first().map_or(0, |s| s.0);
            let v = match self.read(&frames::retrieve_v_of(&text, &specs), None) {
                Err(e @ Refusal::Halt(Halt::Dial(DialError::TooLarge { .. }))) => return Ok(Delivered::TooLarge(e)),
                other => other?,
            };
            if let Some(r) = Rejection::of(&v) {
                let refusal = self.refuse(Some(doc), &r, &v);
                return if r.key() == "too_many_items" { Ok(Delivered::TooLarge(refusal)) } else { Err(refusal) };
            }
            let Some(items) = answers::delivery_values(&v) else {
                // A run of `doc` whose origin the reader may not read, masked
                // at its own position: `doc` stays readable, its origin does
                // not.
                if let Some(origin) = answers::withheld_origin(&v).and_then(parse_address) {
                    return Err(Refusal::Unreadable(origin));
                }
                return Err(Halt::face(
                    format!("a position of {doc} cannot be read as a value"),
                    format!("the delivery from {from} holds an item no value is spelled from — a reference, a hex that does not decode, or a kind this client does not know: {}", crate::halt::clipped(&v.to_string(), 200)),
                    "this is a board fault, or an item kind newer than this client — update the client where the kind is new; nothing was written",
                )
                .into());
            };
            Ok(Delivered::Values(items))
        })
        .map_err(|fault| fault.faced(doc))
    }

    /// Reads the values at the I-addresses spans name, at the head.
    ///
    /// Each span `(prefix, first, width)` is `width` positions from
    /// `<prefix>.<first>`, words `holder`'s image served, and its list is
    /// one item a position. It is the read by identity, `retrieve_i` (wire.md §Content &
    /// provenance reads): a value at an I-address is written once, so what a
    /// draft or a fork held is read as it was minted, whatever the side has
    /// become since. The spans go out in as few reads as the budgets allow —
    /// each at most [`MAX_DELIVERY_ITEMS`] positions and `MAX_WIRE_LIST`
    /// spans, and no more positions than the dialer's answer cap holds at the
    /// room one takes beside its address ([`frames::I_ITEM_ROOM`]) — and a
    /// read refused `too_many_items`, or whose answer still passes the cap,
    /// is asked again in halves as [`Reader::values_by_ordinal`] asks one.
    ///
    /// # Errors
    ///
    /// `withheld` naming the document a span lies in, [`Refusal::Unreadable`]
    /// naming it, and another refusal, mapped by [`Reader::refuse`] as a
    /// read of several documents — one naming no document this client parses
    /// is the board's refusal verbatim, never `holder` (SP-18); an item
    /// `null` — no value at an address an image served — or one no value is
    /// spelled from, and an answer short of, or past, the positions asked,
    /// faced; one position still refused as [`Reader::values_by_ordinal`]'s
    /// is; otherwise [`Reader::read`]'s errors.
    pub(in crate::merge) fn values_by_identity(&self, holder: &Address, spans: &[(&str, u64, u64)]) -> Result<Vec<Vec<Item>>, Refusal> {
        let widths: Vec<u64> = spans.iter().map(|s| s.2).collect();
        let room = |span: usize| {
            let (prefix, first, width) = spans[span];
            (frames::I_ITEM_ROOM + prefix.len() + ".".len() + first.saturating_add(width).to_string().len()) as u64
        };
        self.read_values(&widths, room, |part| {
            let starts: Vec<String> = part.iter().map(|a| format!("{}.{}", spans[a.span].0, spans[a.span].1 + a.into)).collect();
            let list: Vec<(&str, u64)> = starts.iter().zip(part).map(|(start, a)| (start.as_str(), a.width)).collect();
            let v = match self.read(&frames::retrieve_i(&list), None) {
                Err(e @ Refusal::Halt(Halt::Dial(DialError::TooLarge { .. }))) => return Ok(Delivered::TooLarge(e)),
                other => other?,
            };
            if let Some(r) = Rejection::of(&v) {
                // A read of the documents the spans lie in, which need not
                // include `holder`: the one the board names, or its refusal.
                let refusal = self.refuse(None, &r, &v);
                return if r.key() == "too_many_items" { Ok(Delivered::TooLarge(refusal)) } else { Err(refusal) };
            }
            let Some(items) = answers::i_delivery_values(&v) else {
                return Err(Halt::face(
                    format!("a word {holder} held cannot be read as a value"),
                    format!("the read by identity from {} holds an item no value is spelled from — a hex that does not decode, a per-byte item of another length than one byte, or a kind this client does not know: {}", starts.first().map_or("", String::as_str), crate::halt::clipped(&v.to_string(), 200)),
                    "this is a board fault, or an item kind newer than this client — update the client where the kind is new; nothing was written",
                )
                .into());
            };
            // An address the image served names a minted word: the board
            // holds a value at every one.
            if let Some(k) = items.iter().position(Option::is_none) {
                let at = address_at(spans, part, k);
                return Err(Halt::face(
                    format!("the board holds no value at {at}"),
                    format!("{at} is a word {holder}'s image arranged, and the read by identity answered `null` there — a position never minted"),
                    "this is a board fault; nothing was written",
                )
                .into());
            }
            Ok(Delivered::Values(items.into_iter().flatten().collect()))
        })
        .map_err(|fault| fault.faced(holder))
    }

    /// Reads the values of spans of `widths`, one list a span.
    ///
    /// They are read in the parts [`parts`] plans at `room` bytes a position
    /// of each span, each part read by `read`, which answers its values in
    /// order or that the part is too large — asked again in halves, its
    /// stretches split, then one stretch's width, down to one position,
    /// whose refusal is the read's.
    ///
    /// # Errors
    ///
    /// `read`'s; a part whose values are not as many as its positions, as
    /// [`ValueFault::Count`].
    fn read_values(
        &self,
        widths: &[u64],
        room: impl Fn(usize) -> u64,
        read: impl Fn(&[Asking]) -> Result<Delivered, Refusal>,
    ) -> Result<Vec<Vec<Item>>, ValueFault> {
        let mut out: Vec<Vec<Item>> = widths.iter().map(|w| Vec::with_capacity(*w as usize)).collect();
        for part in parts(widths, room) {
            ask(&part, &read, &mut out)?;
        }
        Ok(out)
    }
}

/// What one value read answered.
///
/// It is its values in order, or a part too large to be read whole, with
/// the refusal a part of one position answers.
enum Delivered {
    /// One value a position, in the order asked.
    Values(Vec<Item>),
    /// `too_many_items`, or an answer past the dialer's cap.
    TooLarge(Refusal),
}

/// A value read's fault: the read's refusal, or the answer's count.
enum ValueFault {
    /// The read's own refusal.
    Refused(Refusal),
    /// A delivery of `got` values where `asked` positions were asked.
    Count {
        /// The positions asked.
        asked: u64,
        /// The values delivered.
        got: usize,
    },
}

impl From<Refusal> for ValueFault {
    fn from(r: Refusal) -> ValueFault {
        ValueFault::Refused(r)
    }
}

impl ValueFault {
    /// Returns the refusal a read of `doc`'s values answers for this fault.
    fn faced(self, doc: &Address) -> Refusal {
        match self {
            ValueFault::Refused(r) => r,
            ValueFault::Count { asked, got } => Halt::face(
                format!("{doc} delivered {got} positions where {asked} were asked"),
                "a value read delivers one value a position asked, in the order asked",
                "this is a board fault; nothing was written",
            )
            .into(),
        }
    }
}

/// One stretch a value read asks.
///
/// It is `width` positions of the span `span`, from `into` positions into
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Asking {
    span: usize,
    into: u64,
    width: u64,
}

/// Returns the parts spans of `widths` are read in, in order.
///
/// A part holds at most [`MAX_DELIVERY_ITEMS`] positions and
/// `MAX_WIRE_LIST` stretches, and its answer at most the dialer's cap
/// ([`MAX_ANSWER_BYTES`]) at `room(k)` bytes a position of span `k`, beside
/// an `i_delivery`'s envelope ([`frames::I_DELIVERY_ENVELOPE`]) — a room of
/// 0 bounds nothing; a span past what a part has room for goes on in the
/// next. A part holds one position at least, whatever its room.
fn parts(widths: &[u64], room: impl Fn(usize) -> u64) -> Vec<Vec<Asking>> {
    let budget = MAX_ANSWER_BYTES.saturating_sub(frames::I_DELIVERY_ENVELOPE) as u64;
    let (mut out, mut part, mut positions, mut bytes) = (Vec::new(), Vec::new(), 0u64, 0u64);
    for (span, &width) in widths.iter().enumerate() {
        let room = room(span);
        let mut into = 0u64;
        while into < width {
            let by_bytes = budget.saturating_sub(bytes).checked_div(room).unwrap_or(u64::MAX);
            let fits = (MAX_DELIVERY_ITEMS - positions).min(by_bytes);
            if part.len() == MAX_WIRE_LIST || (fits == 0 && !part.is_empty()) {
                out.push(std::mem::take(&mut part));
                (positions, bytes) = (0, 0);
                continue;
            }
            let width = fits.max(1).min(width - into);
            part.push(Asking { span, into, width });
            (positions, bytes, into) = (positions + width, bytes.saturating_add(width.saturating_mul(room)), into + width);
        }
    }
    if !part.is_empty() {
        out.push(part);
    }
    out
}

/// Reads one part, halving it where it is too large.
///
/// Each stretch's values are appended to its span's list in `out`.
fn ask(part: &[Asking], read: &impl Fn(&[Asking]) -> Result<Delivered, Refusal>, out: &mut [Vec<Item>]) -> Result<(), ValueFault> {
    match read(part)? {
        Delivered::Values(items) => {
            let asked: u64 = part.iter().map(|a| a.width).sum();
            if items.len() as u64 != asked {
                return Err(ValueFault::Count { asked, got: items.len() });
            }
            let mut items = items.into_iter();
            for a in part {
                out[a.span].extend(items.by_ref().take(a.width as usize));
            }
            Ok(())
        }
        Delivered::TooLarge(refusal) => match part {
            [] => Ok(()),
            [one] if one.width <= 1 => Err(refusal.into()),
            [one] => {
                let left = one.width / 2;
                ask(&[Asking { width: left, ..*one }], read, out)?;
                ask(&[Asking { into: one.into + left, width: one.width - left, ..*one }], read, out)
            }
            _ => {
                let (left, right) = part.split_at(part.len() / 2);
                ask(left, read, out)?;
                ask(right, read, out)
            }
        },
    }
}

/// Returns the I-address of the `k`-th position `part` asks of `spans`.
fn address_at(spans: &[(&str, u64, u64)], part: &[Asking], k: usize) -> String {
    let mut k = k as u64;
    for a in part {
        let (prefix, first, _) = spans[a.span];
        if k < a.width {
            return format!("{prefix}.{}", first + a.into + k);
        }
        k -= a.width;
    }
    String::new()
}

/// What a session's end leaves of the act it stopped: the way on the face
/// of [`Refusal::SessionEnded`] says.
///
/// No write the death signal met landed — the board runs a dead token's
/// frame as a guest's (wire.md §Sessions) — so what stands is what the act
/// wrote before it, and the act's kind says what takes it up. The one write
/// that may stand all the same is a take-back's whose first answer was lost
/// before the signal met its re-ask or the read of its rows back
/// ([`OnEnd::Unconfirmed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnEnd {
    /// The act is run again: a composition, a verification or a lookup,
    /// the restore, a take-back up to and at its one write, the record of a
    /// publication — each reads what stands before it writes.
    Rerun,
    /// A landing, landed in part or not at all, which `resume` takes up.
    ///
    /// `resume` reads what of it landed and writes nothing twice: a shot's
    /// member, or a landing in a draft named, is completed with its record,
    /// and a fresh draft the merge landed in before its record is named
    /// ([`Refusal::LandingBegun`]) for a `resume` naming that draft.
    Resume,
    /// A take-back's record, its one write standing: nothing more is
    /// written, a re-run finding no merge to take out and writing none.
    TakenOut,
    /// An undo's record, its one write standing and an earlier landing's
    /// marker put back (skep #964).
    ///
    /// Nothing more is written; a re-run takes that earlier merge back too,
    /// as a step of its own.
    EarlierBack,
    /// A withdrawal's undo's record, its one write standing.
    ///
    /// Nothing more is written, a re-run finding the merge put back and
    /// writing none.
    PutBack,
    /// A take-back's one write, its first answer lost and the signal met at
    /// its re-ask or at the read of the draft's rows back: the write may
    /// have landed, its record unwritten either way, and only the draft
    /// tells which (the `undo` module's doc, **The lost answer**).
    Unconfirmed(LostTakeBack),
}

/// A take-back whose one write's answer was lost, as its way on names it
/// ([`OnEnd::Unconfirmed`]): what the draft shows where the write landed,
/// and what a re-run of the act then does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LostTakeBack {
    /// An undo of the landing at `landing`.
    ///
    /// Where it landed, that landing no longer stands in the draft, and the
    /// merge marked at `earlier` stands there again where the write puts
    /// that marker back (skep #964): a re-run then takes that merge back
    /// too, or on a draft with no recorded base the landing beneath it,
    /// where one stands.
    Undo { landing: u64, earlier: Option<u64> },
    /// A withdrawal: where it landed, the draft carries no merge, and a
    /// re-run takes nothing out.
    Withdraw,
    /// A withdrawal's undo: where it landed, the draft carries the merge
    /// marked at `at` again, and a re-run puts nothing back.
    Unwithdraw { at: u64 },
    /// A restore: where it landed, the draft holds the state restored.
    Restore,
}

impl LostTakeBack {
    /// Returns the way on: how the draft tells whether the write landed,
    /// and what running the act again does either way.
    pub(crate) fn way_on(self) -> String {
        match self {
            LostTakeBack::Undo { landing, earlier: Some(earlier) } => format!("read the draft's merge before running this again: where it is the merge marked at position {earlier}, this undo landed and its record is not written, and a re-run takes that merge back too, so run it only to take that merge out; where it is still the merge marked at position {landing}, the undo never landed, and a re-run takes it out"),
            LostTakeBack::Undo { landing, earlier: None } => format!("read the draft before running this again: where the merge landed in it at position {landing} no longer stands, this undo landed and its record is not written, and a re-run takes back the merge landed before it, where one stands; where it still stands, the undo never landed, and a re-run takes it out"),
            LostTakeBack::Withdraw => "read the draft before running this again: where it carries no merge, this withdrawal landed and its record is not written, and a re-run takes nothing out; where it still carries the merge, the withdrawal never landed, and a re-run takes it out".to_string(),
            LostTakeBack::Unwithdraw { at } => format!("read the draft before running this again: where it carries the merge marked at position {at}, this undo of the withdrawal landed and its record is not written, and a re-run puts nothing back; where it carries no merge, the undo never landed, and a re-run puts the merge back"),
            LostTakeBack::Restore => "read the draft before restoring again: where it holds the state restored, the restore landed; else it never landed, and a restore typed at a fresh read lands it".to_string(),
        }
    }
}

impl OnEnd {
    /// Returns the face's state for a session that ended `during` a step.
    fn state(self, during: &str) -> String {
        match self {
            OnEnd::Rerun | OnEnd::Resume => format!("the session ended while {during}"),
            OnEnd::TakenOut => format!(
                "the merge is out of the draft, and its record is not written: the session ended while {during}"
            ),
            OnEnd::EarlierBack => format!(
                "the merge is out of the draft, the merge landed before it standing again, and its record is not written: the session ended while {during}"
            ),
            OnEnd::PutBack => format!(
                "the merge is back in the draft, and its record is not written: the session ended while {during}"
            ),
            OnEnd::Unconfirmed(_) => format!(
                "the write may have landed, and its record is not written: its answer was lost, and the session ended while {during}"
            ),
        }
    }

    /// Returns the face's act: the one way on.
    pub(crate) fn act(self) -> String {
        match self {
            OnEnd::Rerun => "open a session again and run this again: it reads what stands before it writes".to_string(),
            OnEnd::Resume => "open a session again and resume: it reads what of the landing stands and writes nothing twice, and a fresh draft the merge landed in before its record is named, for resume naming that draft to write the record".to_string(),
            OnEnd::TakenOut => "nothing more is written: the draft stands as the act left it, and a re-run writes no record, finding no merge to take out; the landing's record stands alone in the journal".to_string(),
            OnEnd::EarlierBack => "nothing more is written: the draft stands as the act left it, carrying the merge landed in it before; a re-run takes that merge back too, as a step of its own, so run it only to take that merge out; the landing's record stands alone in the journal".to_string(),
            OnEnd::PutBack => "nothing more is written: the draft stands as the act left it, and a re-run writes no record, finding the merge put back; the withdrawal's record stands alone in the journal".to_string(),
            OnEnd::Unconfirmed(lost) => format!("open a session again and {}", lost.way_on()),
        }
    }
}

/// Returns the death signal under the caller's token met `during` a step of
/// an act that leaves `on_end`, as [`Refusal::SessionEnded`].
///
/// It is the one composer of the arm's face (the `reads` module's doc).
pub(crate) fn session_ended(during: &str, on_end: OnEnd) -> Refusal {
    Refusal::SessionEnded(Halt::face(
        on_end.state(during),
        "the board answered `Skepd-Session: closed` (wire.md §Sessions)",
        on_end.act(),
    ))
}

/// Faces an answer without the shape the frame's `resp` promises.
pub(crate) fn shape(op: &str, v: &Value) -> Halt {
    Halt::face(
        format!("`{op}` answered a document this client cannot read"),
        crate::halt::clipped(&v.to_string(), 200).to_string(),
        "this board is not speaking the wire this client expects; nothing was written",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asserts `parts` ask every position of each span of `widths` once, in
    /// order.
    fn asks_each_position_once(parts: &[Vec<Asking>], widths: &[u64]) {
        let mut next = vec![0u64; widths.len()];
        for asking in parts.iter().flatten() {
            assert_eq!(asking.into, next[asking.span], "{asking:?}");
            next[asking.span] += asking.width;
        }
        assert_eq!(next, widths);
    }

    /// The positions each part asks.
    fn positions(parts: &[Vec<Asking>]) -> Vec<u64> {
        parts.iter().map(|part| part.iter().map(|a| a.width).sum()).collect()
    }

    /// A value read's parts keep every budget, and ask every position once.
    ///
    /// A part holds at most the delivery budget's positions and a wire
    /// list's stretches, and no more positions than the dialer's answer cap
    /// holds at their room beside the envelope; a span past what a part has
    /// room for goes on in the next, in order; a room of 0 bounds nothing
    /// but the two counts, and a part holds one position whatever its room
    /// (the mutant that sizes a read by its positions alone asks answers
    /// past the dialer's cap; the one that drops the floor of one position
    /// loops on a room past the cap).
    #[test]
    fn a_value_reads_parts_keep_every_budget_and_ask_every_position_once() {
        let widths = [MAX_DELIVERY_ITEMS + 1];
        let planned = parts(&widths, |_| 0);
        assert_eq!(positions(&planned), [MAX_DELIVERY_ITEMS, 1], "the delivery budget's positions, then the rest");
        asks_each_position_once(&planned, &widths);
        let widths = vec![1u64; MAX_WIRE_LIST + 1];
        let planned = parts(&widths, |_| 0);
        assert_eq!(planned.iter().map(Vec::len).collect::<Vec<_>>(), [MAX_WIRE_LIST, 1], "a wire list's stretches, then the rest");
        asks_each_position_once(&planned, &widths);
        let budget = (MAX_ANSWER_BYTES - frames::I_DELIVERY_ENVELOPE) as u64;
        let widths = [budget / 100 + 1, 3];
        let planned = parts(&widths, |_| 100);
        assert_eq!(positions(&planned), [budget / 100, 4], "as many positions of 100 bytes as the cap holds, then the rest with the next span");
        asks_each_position_once(&planned, &widths);
        let widths = [2u64];
        let planned = parts(&widths, |_| budget + 1);
        assert_eq!(positions(&planned), [1, 1], "one position a part, whatever its room");
        asks_each_position_once(&planned, &widths);
        assert!(parts(&[], |_| 0).is_empty() && parts(&[0, 0], |_| 0).is_empty(), "nothing to read, no part");
    }
}
