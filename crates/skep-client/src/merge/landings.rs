//! The landing standing in a draft with no recorded base.
//!
//! A draft the board records no base for — a free-standing draft, or an
//! admitted fork (the landing lane's N4, its baseless case) — carries no
//! merge marker (wire.md §Arrangement, `merge`). Its landings are kept on
//! its own `set_arrangement` rows on the supplement
//! (`/changes?under=S&drafts=true`, wire.md §The change feed): a landing's
//! row names the merge, its sides and its head, and every other row — an
//! undo's, a restore's, a plain re-arrangement's — names none. [`Landings`]
//! reads those rows in one walk and answers which landing stands by THE ONE
//! RULE (skep #914): a landing stands in a draft from its write until it is
//! taken back, and when it is taken back the landing that stood when it was
//! made stands again — none where none did. A row naming no merge that
//! leaves the draft exactly as it stood before the standing landing — the
//! two states mapped through one read of the records over both, each run at
//! its own spelling, as the undo maps what it sends (`owners_records`,
//! `mapped_image`) — is that landing's take-back, and it stays taken back
//! whatever is written after. No other row changes which landing stands: a
//! restore, or any other re-arrangement, neither ends one nor brings one
//! back. A draft with a recorded base keeps the same rule by its marker,
//! which a take-back clears or puts back as it stood and a restore leaves
//! standing. One difference remains: on a draft with no marker, a restore
//! to the state before the standing landing is that landing's take-back,
//! the same write as the undo's.
//!
//! **The reads.** The rows are walked once, from the floor. The standing
//! landing is found newest first, each past state read once and only where
//! it is needed: the newest landing stands unless a plain row after it is
//! its take-back, each such row compared, oldest first, with the state
//! before that landing; where one is, the landing that stood when it was
//! made faces the plain rows after that take-back, which is the latest
//! write that put it back. So with no plain row after the newest landing
//! nothing is read at a past position, the land side's common case. The
//! landing beneath the one standing, by which the undo's record is judged,
//! is read only where the undo asks for it ([`Landings::beneath`]).
//!
//! **A past state reclaimed.** A take-back is judged on states the board
//! answers through `/op-at`. Where the board has reclaimed one the walk
//! needs, that state is gone from the board for good: the land side reads
//! it as no landing standing ([`standing_mark`]), so it reports and records
//! nothing on a landing it cannot judge, while the undo refuses
//! [`Refusal::HistoryReclaimed`], nothing sent. Every other refusal,
//! `history_busy` past the bounded retries among them, is answered as
//! itself (SP-14).
//!
//! **The past states.** [`before`] reads a draft's state before a commit,
//! the take-backs' pre-landing read, and [`arranged_at`] its arrangement as
//! of a position, each kept as the board served it, each run under the
//! chain that minted it; [`position_fault`] types a refusal of either at a
//! position this library took from the board's own answers.

use skep_address::Address;

use crate::board::answers::{self, MergeMarker, Metadata};
use crate::board::{Board, Image, Token};
use crate::publication;

use super::land::own_fault_face;
use super::reads::{feed_rows, mapped_image, owners_records, runs_of, OnEnd, Reader, Refusal};

/// Returns the merge landing standing in a draft with no recorded base.
///
/// It is the landing `draft`'s own `set_arrangement` rows on the supplement
/// leave standing by the one rule — a landing stands from its write until
/// it is taken back, the landing that stood when it was made then standing
/// again, a restore or any other re-arrangement neither ending one nor
/// bringing one back (skep #914) — answered as a marker: the sides and the
/// head its row names, `at` the row's position, `head_copied` none. A row
/// naming no merge that leaves the draft exactly as it stood before the
/// standing landing, both states read through `/op-at` and mapped through
/// one read of the correspondence records over the two, is that landing's
/// take-back. `None` where no landing row stands, or every one was taken
/// back. It is the landing [`undo`](fn@super::undo) takes back on such a
/// draft, which carries no marker (wire.md §Arrangement, `merge`): an
/// embedder reads it to know that landing before an undo, as it reads a
/// draft's marker where the board records a base for it. On a draft with a
/// recorded base its marker is the mark, never this.
///
/// # Errors
///
/// The feed walk's: a transport fault, [`Refusal::Halt`]. Then, where a
/// plain row follows a landing, the reads of the draft's past states:
/// [`Refusal::HistoryReclaimed`] where the board no longer answers one;
/// [`Refusal::HistoryBusy`] past the bounded retries; a position past the
/// board's head or inside a commit, and a draft the board did not register
/// before its landing, as the library's own faults; the reads' other
/// refusals; an image whose positions reach the largest ordinal, or a run
/// that is no content I-address, the board's fault, faced; the records'
/// reads' refusals at the head; a record mapping a state past the largest
/// ordinal, the board's fault, faced (SP-19). The death signal under the
/// token at any read is [`Refusal::SessionEnded`], the read made again on a
/// new session.
pub fn baseless_landing(
    board: &Board,
    token: Option<&Token>,
    draft: &Address,
) -> Result<Option<MergeMarker>, Refusal> {
    let reader = Reader::new(board, token, OnEnd::Rerun);
    Ok(Landings::read(&reader, draft)?.standing(&reader)?.map(|standing| standing.mark))
}

/// Returns the land side's mark of the landing standing in `draft`.
///
/// It is [`Landings::standing`]'s mark, for a draft with no recorded base.
/// A past state the walk needs that the board has reclaimed answers none:
/// the land side then reports and records nothing on a landing it cannot
/// judge (the module's doc).
///
/// # Errors
///
/// [`Landings::read`]'s and [`Landings::standing`]'s, but
/// [`Refusal::HistoryReclaimed`], each as itself (SP-14).
pub(super) fn standing_mark(
    reader: &Reader<'_>,
    draft: &Address,
) -> Result<Option<MergeMarker>, Refusal> {
    match Landings::read(reader, draft)?.standing(reader) {
        Ok(standing) => Ok(standing.map(|standing| standing.mark)),
        Err(Refusal::HistoryReclaimed { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// One `set_arrangement` row of a draft, as [`Landings`] reads it.
enum Row {
    /// A landing: the row's `merge` is an object.
    Landing {
        /// The merge the row names, its sides and its head, `at` the row's
        /// position; a term that names no head, or no sides, marks no
        /// merge.
        mark: MergeMarker,
        /// The row's position.
        at: u64,
    },
    /// A plain re-arrangement, naming no merge, at its position.
    Plain(u64),
}

/// A draft's `set_arrangement` rows, oldest first, as one walk read them.
///
/// It answers which landing stands among them (the module's doc).
pub(super) struct Landings {
    /// The draft whose rows they are.
    draft: Address,
    /// The rows, oldest first.
    rows: Vec<Row>,
}

/// The landing standing in a draft with no recorded base.
pub(super) struct Standing {
    /// Its mark: the sides and the head its row names, `at` its position.
    pub(super) mark: MergeMarker,
    /// Its row's position, the landing's.
    pub(super) at: u64,
    /// The latest take-back of a landing made over it, which made it stand
    /// again: its put-back; `None` where none was.
    pub(super) put_back: Option<u64>,
    /// The state before it, as the walk read it, with the records it
    /// compared that state through, read over it and the latest plain row
    /// compared with it; `None` where no plain row followed it and nothing
    /// was read.
    pub(super) before: Option<(Image, Vec<publication::Record>)>,
    /// Its row's place among the draft's rows.
    row: usize,
}

impl Landings {
    /// Reads `draft`'s `set_arrangement` rows, oldest first.
    ///
    /// It walks the supplement under the draft (`drafts=true`) once, keeping
    /// each `set_arrangement` row that names its position: a landing where
    /// its `merge` is an object, the merge it names its mark — a term that
    /// names no head, or no sides, marking no merge — and a plain
    /// re-arrangement where it names none (wire.md §The change feed).
    ///
    /// # Errors
    ///
    /// The feed walk's (`feed_rows`), through `reader`.
    pub(super) fn read(reader: &Reader<'_>, draft: &Address) -> Result<Landings, Refusal> {
        let mut rows = Vec::new();
        feed_rows(reader, &draft.to_string(), true, 0, |row| {
            let Some(at) = row["at"].as_u64() else { return };
            if row["op"].as_str() != Some("set_arrangement") {
                return;
            }
            rows.push(if row["merge"].is_object() {
                let named = answers::marker_of(row).unwrap_or_else(|| MergeMarker {
                    sides: Vec::new(),
                    head: String::new(),
                    head_copied: None,
                    at: None,
                });
                Row::Landing { mark: MergeMarker { head_copied: None, at: Some(at), ..named }, at }
            } else {
                Row::Plain(at)
            });
        })?;
        Ok(Landings { draft: draft.clone(), rows })
    }

    /// Returns whether any row is a landing.
    pub(super) fn any(&self) -> bool {
        self.rows.iter().any(|row| matches!(row, Row::Landing { .. }))
    }

    /// Returns the landing standing in the draft (the module's doc).
    ///
    /// # Errors
    ///
    /// Where a plain row follows a landing: the read of the state before
    /// that landing ([`Landings::stood_before`]); the read of the draft at
    /// the plain row, typed by [`position_fault`]; a run of either state that
    /// is no content I-address, the board's fault, faced; the records' reads'
    /// refusals at the head; a record mapping either state past the largest
    /// ordinal, the board's fault, faced (SP-19).
    pub(super) fn standing(&self, reader: &Reader<'_>) -> Result<Option<Standing>, Refusal> {
        self.top(reader, self.rows.len())
    }

    /// Returns the landing that stood when `standing` was made.
    ///
    /// It is the landing beneath `standing`, the one standing over the rows
    /// before its own, which stands again once `standing` is taken back;
    /// `None` where none stood.
    ///
    /// # Errors
    ///
    /// As [`Landings::standing`]'s, over those rows.
    pub(super) fn beneath(
        &self,
        reader: &Reader<'_>,
        standing: &Standing,
    ) -> Result<Option<Standing>, Refusal> {
        self.top(reader, standing.row)
    }

    /// Returns the state before the landing at `at`.
    ///
    /// It is the arrangement the pre-landing read answers ([`before`]).
    ///
    /// # Errors
    ///
    /// [`before`]'s; a draft the board did not register before its landing,
    /// as the library's own fault.
    pub(super) fn stood_before(&self, reader: &Reader<'_>, at: u64) -> Result<Image, Refusal> {
        let draft = &self.draft;
        match before(reader, draft, at, "the position before the landing")? {
            Before::Stood { image, .. } => Ok(image),
            Before::Unregistered => Err(own_fault_face(
                "the draft did not exist before its landing",
                format!("{draft}'s feed names a landing at position {at}, and `doc_metadata` as of the position before it answers `doc_not_registered`"),
            )),
        }
    }

    /// Returns the landing standing over the rows before `end`.
    ///
    /// The newest landing among them stands unless a plain row after it — one
    /// of those rows, then each of the plain rows a take-back above left
    /// to face — is its take-back; then the landing that stood when it was
    /// made faces the plain rows after that one, its put-back the latest
    /// take-back that left it standing (the module's doc).
    ///
    /// # Errors
    ///
    /// As [`Landings::standing`]'s.
    fn top(&self, reader: &Reader<'_>, end: usize) -> Result<Option<Standing>, Refusal> {
        let (mut end, mut later, mut put_back) = (end, Vec::new(), None);
        'landings: loop {
            let newest = self.rows[..end].iter().enumerate().rev().find_map(|(row, r)| match r {
                Row::Landing { mark, at } => Some((row, mark, *at)),
                Row::Plain(_) => None,
            });
            let Some((row, mark, at)) = newest else { return Ok(None) };
            let plains: Vec<u64> = self.rows[row + 1..end]
                .iter()
                .filter_map(|r| match r {
                    Row::Plain(p) => Some(*p),
                    Row::Landing { .. } => None,
                })
                .chain(later)
                .collect();
            let mut judged: Option<(Image, Vec<publication::Record>)> = None;
            for (k, &plain) in plains.iter().enumerate() {
                let stood = match judged.take() {
                    Some((stood, _)) => stood,
                    None => self.stood_before(reader, at)?,
                };
                let what = "the position of a re-arrangement past the landing";
                let left = arranged_at(reader, &self.draft, plain, what)?;
                let state = [runs_of(stood.runs())?, runs_of(left.runs())?].concat();
                let records = owners_records(reader, &state)?;
                if mapped_image(&stood, &records)? == mapped_image(&left, &records)? {
                    // Its take-back: the landing that stood when it was made
                    // faces the plain rows after this one, this its put-back.
                    end = row;
                    later = plains[k + 1..].to_vec();
                    put_back = Some(put_back.map_or(plain, |back: u64| back.max(plain)));
                    continue 'landings;
                }
                judged = Some((stood, records));
            }
            return Ok(Some(Standing { mark: mark.clone(), at, put_back, before: judged, row }));
        }
    }
}

/// What stood before a commit (the take-backs' pre-landing read).
pub(super) enum Before {
    /// The draft did not exist at the position before the commit: an
    /// inherited marker's case (P2).
    Unregistered,
    /// The draft's metadata and arrangement as they stood.
    Stood {
        /// `doc_metadata` as of the position before the commit.
        meta: Metadata,
        /// The arrangement as of the same position, as the board served it.
        image: Image,
    },
}

/// Reads the draft's state before the commit at `at`.
///
/// It is the pre-landing read of the `undo` module's doc: `doc_metadata`
/// asked at `at − 1`, re-asked at the `nearest` a `not_a_position` names,
/// then the image at that one position; `what` names that position in a
/// fault's face.
///
/// # Errors
///
/// [`Refusal::HistoryReclaimed`] at either read, with nothing read
/// elsewhere; a position past the board's head, or a `not_a_position`
/// naming no `nearest`, or a write at position 0, as the library's own
/// fault; the reads' other refusals.
pub(super) fn before(
    reader: &Reader<'_>,
    draft: &Address,
    at: u64,
    what: &str,
) -> Result<Before, Refusal> {
    let below = at.checked_sub(1).ok_or_else(|| {
        own_fault_face("a write at position 0", format!("{what} names a write of {draft} at the genesis position, before which nothing stood"))
    })?;
    let own_fault = |e| position_fault(draft, what, e);
    let (position, meta) = match reader.metadata(draft, Some(below)) {
        Ok(meta) => (below, meta),
        Err(Refusal::NoSuchDocument(_)) => return Ok(Before::Unregistered),
        Err(Refusal::NotAPosition { nearest: Some(nearest), .. }) => {
            match reader.metadata(draft, Some(nearest)) {
                Ok(meta) => (nearest, meta),
                Err(Refusal::NoSuchDocument(_)) => return Ok(Before::Unregistered),
                Err(e) => return Err(own_fault(e)),
            }
        }
        Err(e) => return Err(own_fault(e)),
    };
    let image = arranged_at(reader, draft, position, what)?;
    Ok(Before::Stood { meta, image })
}

/// Returns `draft`'s arrangement as of `at`, the position `what` names.
///
/// The extent and the image are both read at `at` through `/op-at`, never at
/// the head instead, and the image is kept as the board served it, each run
/// under the chain that minted it (the `undo` module's doc, **The
/// mapping**).
///
/// # Errors
///
/// The reads' refusals, typed by [`position_fault`]; an image whose
/// positions reach the largest ordinal, the board's fault, faced.
pub(super) fn arranged_at(
    reader: &Reader<'_>,
    draft: &Address,
    at: u64,
    what: &str,
) -> Result<Image, Refusal> {
    let imaged = reader.imaged(draft, Some(at)).map_err(|e| position_fault(draft, what, e))?;
    Ok(imaged.into_image()?)
}

/// Types the refusal `e` of a read of `draft` at the position `what` names.
///
/// The position is one this library took from the board's own answers, so
/// one past the board's head, or one inside a commit where the board named
/// no position below it, is this library's own fault; any other refusal is
/// itself.
pub(super) fn position_fault(draft: &Address, what: &str, e: Refusal) -> Refusal {
    match e {
        Refusal::BeyondHead { at, head, .. } => own_fault_face(
            format!("{what} is past the board's head"),
            format!(
                "a read of {draft} as of {at} answered beyond_head{}",
                head.map(|h| format!(" (the head is {h})")).unwrap_or_default()
            ),
        ),
        Refusal::NotAPosition { at, .. } => own_fault_face(
            format!("{what} is inside a commit and the board named no position below it"),
            format!("a read of {draft} as of {at} answered not_a_position with no `nearest`"),
        ),
        e => e,
    }
}
