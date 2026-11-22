//! The door of the merge's reads: the [`Reader`] and a session's end.
//!
//! A [`Reader`] reads at the head or as of one position, under the caller's
//! token or as a guest, and keeps the highest `as_of` its answers carry; a
//! death signal met under the token is answered by [`session_ended`], faced
//! for the act's [`OnEnd`]. Which reads a merge makes, in which order and
//! at which position, is the `reads` module's doc.

use std::cell::Cell;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::answers::{self, IRun, Metadata};
use crate::board::{frames, guest_closed, Answer, AtAnswer, Board, Rejection, Token};
use crate::halt::Halt;
use crate::merge::compose::Item;

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
    /// Every image a shape's reads make carries the one position P (the `reads`
    /// module's doc), the head's included, so the values read through it are
    /// read at P too; `None` is a landing's own read of a draft as it stands.
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

    /// Maps the refusal a read of `doc` answered.
    ///
    /// `withheld` is [`Refusal::Unreadable`] and `doc_not_registered`
    /// [`Refusal::NoSuchDocument`], each naming the document the rejection's
    /// `site.addr` names — of a read naming several, the first the board
    /// refused in declaration order (wire.md §Rejections) — and `doc` where
    /// it names none; the rest the board's own, surfaced verbatim.
    pub(in crate::merge) fn refuse(&self, doc: &Address, r: &Rejection, v: &Value) -> Refusal {
        let refused =
            || r.site().addr.as_deref().and_then(parse_address).unwrap_or_else(|| doc.clone());
        match r.key() {
            "withheld" => Refusal::Unreadable(refused()),
            "doc_not_registered" => Refusal::NoSuchDocument(refused()),
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
            Some(r) => Err(self.refuse(doc, &r, &v)),
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
    /// It is the shape's first read, whose `as_of` is the one position every
    /// later read is made at where no side names one.
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
    /// The image is whole where its runs are at or under the run budget,
    /// else in parts, halving until each part answers (§8) — the runs in V
    /// order with each run's `ordinal` the document's own.
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
    /// `own`, sent with `own` (PUB-2.66) — with the highest `as_of` the
    /// parts answered: `None` where no part was read, or none carried one.
    ///
    /// # Errors
    ///
    /// [`Refusal::TooFragmented`] where a part of one position is still
    /// refused `image_too_large`; another refusal, mapped by
    /// [`Reader::refuse`]; an answer that is no image, faced;
    /// [`Reader::read`]'s errors.
    pub(super) fn image_read(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
        own: bool,
    ) -> Result<(Vec<IRun>, Option<u64>), Refusal> {
        let mut out = Vec::new();
        let as_of = self.image_into(doc, at, from, width, own, &mut out)?;
        Ok((out, as_of))
    }

    /// Images one part of [`Reader::image_read`] into `out`, halving it on
    /// `image_too_large`; the runs `out` holds are the runs seen so far.
    fn image_into(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
        own: bool,
        out: &mut Vec<IRun>,
    ) -> Result<Option<u64>, Refusal> {
        if width == 0 {
            return Ok(None);
        }
        let text = doc.to_string();
        let frame = if own {
            frames::image_own(&text, from, width)
        } else {
            frames::image(&text, from, width)
        };
        let v = self.read(&frame, at)?;
        if let Some(r) = Rejection::of(&v) {
            if r.key() != "image_too_large" {
                return Err(self.refuse(doc, &r, &v));
            }
            if width == 1 {
                return Err(Refusal::TooFragmented { doc: doc.clone(), runs_seen: out.len() });
            }
            let left = width / 2;
            let first = self.image_into(doc, at, from, left, own, out)?;
            let rest = self.image_into(doc, at, from + left, width - left, own, out)?;
            return Ok(first.max(rest));
        }
        let runs = answers::i_runs(&v, width).ok_or_else(|| shape("image", &v))?;
        out.extend(runs.into_iter().map(|mut r| {
            r.ordinal += from - 1;
            r
        }));
        Ok(answers::as_of(&v))
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

    /// Reads `doc`'s own arrangement as of `at`, its `count` positions
    /// whole: the arrangement a published document held before its first
    /// version, which `image` with `own` answers (PUB-2.66).
    ///
    /// `count` is the `own_count` the trunk's `doc_metadata` served at `at`;
    /// at 0 nothing is read and the image is empty. The image is whole or
    /// in parts as [`Reader::image`] reads one.
    ///
    /// # Errors
    ///
    /// [`Reader::image_read`]'s errors.
    pub(super) fn imaged_own(&self, doc: &Address, at: u64, count: u64) -> Result<Imaged, Refusal> {
        let (runs, as_of) = self.image_read(doc, Some(at), 1, count, true)?;
        Ok(Imaged { doc: doc.clone(), own: true, at: Some(at), extent: count, runs, as_of })
    }

    /// Reads the values at content ordinals `from ..` of `doc`.
    ///
    /// The values are `width` of them, one item a position — `retrieve_v` in
    /// parts past the delivery budget and on `too_many_items`.
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
    /// span asked; another refusal is mapped by [`Reader::refuse`];
    /// otherwise [`Reader::read`]'s errors.
    pub(in crate::merge) fn values(
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

    /// Reads one part of [`Reader::values`], answering the positions delivered.
    ///
    /// A `too_many_items` halves the part.
    ///
    /// # Errors
    ///
    /// As [`Reader::values`]'s.
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
        let Some(items) = answers::delivery_values(&v) else {
            // A run of `doc` whose origin the reader may not read, masked at
            // its own position: `doc` stays readable, its origin does not.
            if let Some(origin) = answers::withheld_origin(&v).and_then(parse_address) {
                return Err(Refusal::Unreadable(origin));
            }
            return Err(Halt::face(
                format!("a position of {doc} cannot be read as a value"),
                format!("the delivery at {from} holds an item no value is spelled from — a reference, a hex that does not decode, or a kind this client does not know: {}", crate::halt::clipped(&v.to_string(), 200)),
                "this is a board fault, or an item kind newer than this client — update the client where the kind is new; nothing was written",
            )
            .into());
        };
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

/// What a session's end leaves of the act it stopped: the way on the face
/// of [`Refusal::SessionEnded`] says.
///
/// No write the death signal met landed — the board runs a dead token's
/// frame as a guest's (wire.md §Sessions) — so what stands is what the act
/// wrote before it, and the act's kind says what takes it up.
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
        }
    }

    /// Returns the face's act: the one way on.
    pub(crate) fn act(self) -> &'static str {
        match self {
            OnEnd::Rerun => "open a session again and run this again: it reads what stands before it writes",
            OnEnd::Resume => "open a session again and resume: it reads what of the landing stands and writes nothing twice, and a fresh draft the merge landed in before its record is named, for resume naming that draft to write the record",
            OnEnd::TakenOut => "nothing more is written: the draft stands as the act left it, and a re-run writes no record, finding no merge to take out; the landing's record stands alone in the journal",
            OnEnd::EarlierBack => "nothing more is written: the draft stands as the act left it, carrying the merge landed in it before; a re-run takes that merge back too, as a step of its own, so run it only to take that merge out; the landing's record stands alone in the journal",
            OnEnd::PutBack => "nothing more is written: the draft stands as the act left it, and a re-run writes no record, finding the merge put back; the withdrawal's record stands alone in the journal",
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
