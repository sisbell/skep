//! The restore — a draft's past state made current (B3-S7; `client.md`
//! §4b.1's `history.restore` row; skep #782).
//!
//! The module stands behind the `merge` feature, riding the merge's reader
//! and the one write the take-backs send (the `merge::undo` module): a
//! restore is the same read at a position, the same records' read and
//! mapping the undo sends its state through, and the same
//! `set_arrangement`, with no base and no `merge`, at any position the
//! board still answers.
//! Two calls, the reads apart from the write, so an embedder says what the
//! draft will hold before anything is written:
//!
//! * [`past`] — THE READS. The draft's `doc_metadata` at the head, whose
//!   `as_of` is the position the draft stands at: a published document is
//!   [`Refusal::Published`], and a position at or past that `as_of` is
//!   [`Refusal::NotPast`], refused before any read at a position. Then THE
//!   STATE: the draft's extent and image as of `at` through `/op-at`, each
//!   position fault typed as the reader types it — reclaimed
//!   ([`Refusal::HistoryReclaimed`]), inside one commit
//!   ([`Refusal::NotAPosition`] naming the nearest below), a draft that did
//!   not exist then ([`Refusal::NoSuchDocument`]) — and never read at the
//!   head instead; an empty state is admitted, and sets an empty
//!   arrangement. Then THE RECORDS, at the head and never at `at`, since a
//!   record minted after the state must be seen: for each distinct origin
//!   among the state's runs, in run order, whose account is the person's
//!   exactly (the owned-home test), one four-set read per chunk of that
//!   origin's spans — `{home: [the origin], from: [the spans], ty: [the
//!   correspondence class]}`, the twin fence's own read — each hit judged
//!   off its address and read once, kept by `Record::of`. Then THE MAPPING
//!   ([`mapped`]): each run walked from its first ordinal, the piece a record
//!   covers mapped by `Record::map` to the published span it became — its
//!   origin the TRUNK the record's `to` lies in — the piece no record covers
//!   kept as read, I-adjacent pieces of one origin merged. A state in more
//!   pieces than one write may name is [`Refusal::OverCap`], nothing sent.
//! * [`restore`] — THE ONE WRITE: `set_arrangement` of the mapped runs,
//!   `as_of` the first read's position, no `head`, no `base`, no `merge`, so
//!   the board moves nothing of the draft's record — the base and the merge
//!   marker stand as they are (wire.md §Arrangement, `set_arrangement`:
//!   absent, "NOTHING of the record moves, the marker included"). A draft
//!   changed since the read is refused `arrangement_moved` with nothing
//!   changed; the embedder reads again. The write's id names the draft, the
//!   position restored and the position the frame is typed against, so a
//!   second call over one [`Past`] in one session is answered from the memo,
//!   and a restore after the restore landed is a write of its own. No head
//!   record is read first: the frame has no entry frame and signs nothing,
//!   so SP-14's pre-check does not apply. Nothing of a merge record is
//!   written or replaced.
//!
//! **Why the mapping.** The board's twin fence refuses a draft-native run a
//! record already names `already_published` (wire.md §The publish shot and
//! head-float), and the publication composition re-composes such a run by
//! reference before any send: a restore that sent the old identity would
//! leave the draft holding words the board no longer lets it publish as its
//! own, and the design's rule is that the restored words come back as they
//! stand now, marked public, the links on them returning with them (B3-S7).
//! The records are read at every origin the person owns, not the restored
//! draft's alone: a state of one draft can hold another draft of the
//! family's identity, whose record is homed in that draft.
//!
//! **The marker.** A restore to a state before a merge landed leaves the
//! draft's marker standing, so the next publication would claim its sides
//! superseded by a version without their words; [`Past::marker`] carries
//! the marker as it stands, for the embedder to say before and after the act
//! and to name the withdrawal (`merge::withdraw`) beside it. The restore
//! itself never takes a merge out.

use skep_address::Address;

use crate::board::answers::MergeMarker;
use crate::board::{frames, Answer, Board, Token};
use crate::halt::Halt;
use crate::merge::land::closed;
use crate::merge::reads::{records_of, runs_of, Reader, Refusal, SHOT_RUN_CAP};
use crate::merge::undo::{frame_runs, judge, Act};
use crate::merge::Run;
use crate::publication::Record;

pub use crate::merge::reads::mapped;

/// A draft's past state, read and mapped, before the write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Past {
    /// The draft.
    pub draft: Address,
    /// The position the state was read at.
    pub at: u64,
    /// The position the draft stands at — the first read's `as_of`, which
    /// the write is typed against. An editor that types its writes against
    /// its own last acknowledgment sets it there before the write.
    pub as_of: u64,
    /// The arrangement as read at `at`, in V order.
    pub state: Vec<Run>,
    /// The same, mapped through the records: what the write sends.
    pub sent: Vec<Run>,
    /// The correspondence records the mapping used, in the order they were
    /// read.
    pub records: Vec<Record>,
    /// The draft's merge marker as it stands now; `None` where it carries
    /// none. The restore leaves it as it is.
    pub marker: Option<MergeMarker>,
}

impl Past {
    /// Returns the positions of the state a record covers: how many of its
    /// words come back as the published words they became.
    pub fn covered(&self) -> u64 {
        covered(&self.state, &self.records)
    }

    /// Returns the positions the state holds.
    pub fn extent(&self) -> u64 {
        self.state.iter().map(|r| r.width).sum()
    }
}

/// What a restore answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// The draft restored.
    pub draft: Address,
    /// The position the state was read at.
    pub at: u64,
    /// The one write's commit position, its ack's `at`.
    pub position: u64,
}

/// Reads `draft`'s state as of `at`, mapped through the records, as
/// `account`'s reader under `token`.
///
/// It is the module's doc's reads, in order, writing nothing.
///
/// # Errors
///
/// In this order:
///
/// - the draft's `doc_metadata` read's refusals — [`Refusal::Unreadable`],
///   [`Refusal::NoSuchDocument`] — and [`Refusal::Published`] for a
///   published document; an answer naming no `as_of`, faced;
/// - [`Refusal::NotPast`] where `at` is at or past the draft's position,
///   before any read at a position;
/// - the state's reads' at `at`: [`Refusal::HistoryReclaimed`],
///   [`Refusal::NotAPosition`], [`Refusal::NoSuchDocument`] for a draft that
///   did not exist then, [`Refusal::HistoryBusy`] past the retries,
///   [`Refusal::TooFragmented`];
/// - the records' reads' refusals at the head;
/// - [`Refusal::OverCap`] where the mapped state is in more pieces than one
///   write may name;
/// - the death signal under the token, faced, and the dialer's halts.
pub fn past(board: &Board, token: &Token, account: &str, draft: &Address, at: u64) -> Result<Past, Refusal> {
    let reader = Reader::new(board, Some(token));
    let (meta, as_of) = reader.metadata_read(draft, None)?;
    if meta.published {
        return Err(Refusal::Published { doc: draft.clone() });
    }
    let as_of = as_of.ok_or_else(|| {
        Halt::face(
            "`doc_metadata` answered no `as_of`",
            format!("the read of {draft} named no position (wire.md §The response envelope: every response names where it sits)"),
            "this board is not speaking the wire this client expects; nothing was written",
        )
    })?;
    if at >= as_of {
        return Err(Refusal::NotPast { draft: draft.clone(), at, current: as_of });
    }
    let state = runs_of(&reader.imaged(draft, Some(at))?.runs)?;
    let records = records_of(&reader, account, &state)?;
    let sent = mapped(&state, &records);
    if sent.len() > SHOT_RUN_CAP {
        return Err(Refusal::OverCap { runs: sent.len(), cap: SHOT_RUN_CAP });
    }
    Ok(Past { draft: draft.clone(), at, as_of, state, sent, records, marker: meta.merge })
}

/// Makes `past`'s state current: the one write under `token`.
///
/// # Errors
///
/// `arrangement_moved` as the board's verdict, [`Refusal::Halt`] with
/// `Refused` saying the draft changed since it was read and nothing was
/// changed; [`Refusal::NotOwner`]; [`Refusal::Published`];
/// [`Refusal::WindowWithheld`] naming an origin a run windows that the
/// person may not read; [`Refusal::NeedsSignedSession`];
/// [`Refusal::NoSuchDocument`]; the refusals of the runs as this library's
/// own fault, since it sends what the board itself held; the board's other
/// refusals verbatim; the death signal under the token, faced; a lost
/// acknowledgment as the dialer's halt, with no re-ask — the embedder reads
/// first on a re-run.
pub fn restore(board: &Board, token: &Token, past: &Past) -> Result<Restored, Refusal> {
    let Past { draft, at, as_of, sent, .. } = past;
    let frame = frames::set_arrangement(
        &draft.to_string(),
        &frame_runs(sent)?,
        *as_of,
        None,
        None,
        None,
        Some(&format!("restore:{draft}:{at}:{as_of}.arrangement")),
    );
    let v = match board.op(Some(token), &frame)? {
        Answer::Closed => return Err(closed("restoring the draft").into()),
        Answer::Document(v) => v,
    };
    let position = judge(&v, draft, *as_of, Act::Restore)?;
    Ok(Restored { draft: draft.clone(), at: *at, position })
}

/// Returns how many positions of `state` the records cover.
pub fn covered(state: &[Run], records: &[Record]) -> u64 {
    state
        .iter()
        .map(|run| {
            let chain = format!("{}.0.1", run.origin);
            records.iter().filter_map(|r| r.from.overlap(&chain, run.i_start, run.reach())).map(|(lo, hi)| hi - lo).sum::<u64>()
        })
        .sum()
}

#[cfg(test)]
mod tests;
