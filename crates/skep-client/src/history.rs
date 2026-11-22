//! The restore — a draft's past state made current (B3-S7; `client.md`
//! §4b.1's `history.restore` row; skep #782).
//!
//! The module stands behind the `merge` feature, riding the merge's reader
//! and the one write the take-backs send (the `merge::undo` module): a
//! restore is the same read at a position, the same records' read and the
//! same mapping of the state's image the undo makes, and the same
//! `set_arrangement`, spelled as theirs is, with no base and no `merge`, at
//! any position the board still answers.
//! Two calls make the restore, the reads apart from the write, so an
//! embedder says what the draft will hold before anything is written; two
//! more lend its records and its mapping to a comparison by identity:
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
//!   ([`mapped_image`], the mapping of images below): the state's image
//!   mapped at its own spelling, the words a record covers coming back as
//!   the published span they became on the trunk's chain, the rest kept as
//!   read, a run minted under a member's chain kept under that chain — the
//!   runs the write sends, [`Past::written`]; [`Past::sent`] is the same
//!   runs as the core's, each origin the trunk its words were minted under,
//!   for drawing. A state in more runs than one write may name, counted on
//!   the runs the write sends, is [`Refusal::OverCap`], nothing sent.
//! * [`restore`] — THE ONE WRITE: `set_arrangement` of [`Past::written`],
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
//!   written or replaced. Each run is as [`written_runs`] spells it, the
//!   take-backs' spelling: its own first I-address, and its `origin` the
//!   document that minted it, a member's version component kept (wire.md
//!   §Arrangement, `publish`).
//! * [`records`] and [`mapped_image`] — THE RECORDS AND THE MAPPING OF
//!   IMAGES, for the diff (`text.diff`; skep #1095). A publication re-mints
//!   a draft's words, so a mark made before it, or a document that copied
//!   from the draft, no longer shares the draft's identity; the diff maps
//!   both images through one read of the records, made after both are read.
//!   [`records`] is THE RECORDS' read above over every image handed it at
//!   once, at *every* distinct origin among their runs — the person's, and
//!   another account's draft a mark or a copy holds words of — each hit held
//!   to the account that owns the origin: only that account's own
//!   publication re-mints the draft's words, and it homes their records in
//!   the draft (the merge's `owners_records`). The runs are the distinct
//!   runs of all the images, as the merge's reads take them — exact for
//!   every run a record can name, records being homed only in private
//!   drafts, whose chains carry no member's component — and each record is
//!   read once however many images name its span. An origin the reader may
//!   not read yields no record, the board answering no link homed where it
//!   may not read, and its words are compared as read. [`mapped_image`] is
//!   the merge reads' mapping of one image at its own spelling, the one the
//!   restore's write and the take-backs' are mapped by: each run is keyed by
//!   its I-address prefix, so a run minted under a member's chain is
//!   compared as itself, the piece a record covers becomes the span the
//!   record's `to` names at the same offset, every sum checked (SP-19), and
//!   the ordinals are tiled again from 1, the extent unchanged. Their cost
//!   (SP-23): one four-set read per distinct origin for each
//!   `MAX_WIRE_LIST` of its spans, one `read_link` per hit homed in a
//!   document of that origin's own account, then a walk of each run against
//!   the records.
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

use std::collections::HashSet;

use skep_address::Address;

use crate::board::answers::MergeMarker;
use crate::board::{frames, Answer, Board, Image, Token};
use crate::halt::Halt;
use crate::merge::shared::{
    judge, owners_records, records_of, runs_of, session_ended, Act, OnEnd, Reader,
};
use crate::merge::{Refusal, Run, SHOT_RUN_CAP};
use crate::publication::Record;

pub use crate::merge::shared::{mapped, mapped_image, written_runs};

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
    /// [`Past::written`] as the core's runs, for drawing.
    ///
    /// Each run's origin is the trunk its words were minted under, and
    /// I-adjacent runs of one origin are one run, so a member's own words
    /// stand here as the trunk's positions of the same ordinals: never what
    /// the write sends.
    pub sent: Vec<Run>,
    /// The state's image mapped through the records at its own spelling, in
    /// V order: what the write sends.
    ///
    /// Each run lies on the chain that minted it — a deposit naming a member
    /// on the member's — and the words a record covers on the trunk's chain
    /// the record's `to` names ([`mapped_image`]).
    pub written: Image,
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
///   [`Refusal::TooFragmented`]; a run that is no content I-address, or an
///   image that reaches the largest ordinal, the board's fault, faced;
/// - the records' reads' refusals at the head;
/// - a record mapping the state past the largest ordinal, the board's
///   fault, faced (SP-19);
/// - [`Refusal::OverCap`] where the written runs are more than one write
///   may name;
/// - the death signal under the token at any read,
///   [`Refusal::SessionEnded`], its face saying to run this again; the
///   dialer's halts.
pub fn past(board: &Board, token: &Token, account: &str, draft: &Address, at: u64) -> Result<Past, Refusal> {
    let reader = Reader::new(board, Some(token), OnEnd::Rerun);
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
    let imaged = reader.imaged(draft, Some(at))?;
    let state = runs_of(&imaged.runs)?;
    let read = imaged.into_image()?;
    let records = records_of(&reader, account, &state)?;
    // Every sum of a record's numbers is made here, checked (SP-19): the
    // core's runs below are the mapped image's, never mapped again.
    let written = mapped_image(&read, &records)?;
    if written.runs().len() > SHOT_RUN_CAP {
        return Err(Refusal::OverCap { runs: written.runs().len(), cap: SHOT_RUN_CAP });
    }
    let sent = runs_of(written.runs())?;
    Ok(Past { draft: draft.clone(), at, as_of, state, sent, written, records, marker: meta.merge })
}

/// Makes `past`'s state current: the one write under `token`.
///
/// The write sets [`Past::written`], each run as [`written_runs`] spells
/// it.
///
/// # Errors
///
/// A run of [`Past::written`] that is no content I-address, the board's
/// fault, faced with nothing sent ([`written_runs`]); then
/// `arrangement_moved` as the board's verdict, [`Refusal::Halt`] with
/// `Refused` saying the draft changed since it was read and nothing was
/// changed, and asking a read of the draft and a restore typed at that
/// read, since a `past` whose `as_of` its caller set meets the same
/// refusal sent again; [`Refusal::NotOwner`]; [`Refusal::Published`];
/// [`Refusal::WindowWithheld`] naming an origin a run windows that the
/// person may not read; [`Refusal::NeedsSignedSession`];
/// [`Refusal::NoSuchDocument`]; the refusals of the runs as this library's
/// own fault, since it sends what the board itself held; the board's other
/// refusals verbatim; the death signal under the token,
/// [`Refusal::SessionEnded`], nothing restored and its face saying to run
/// this again; a lost acknowledgment as the dialer's halt, with no re-ask —
/// the embedder reads first on a re-run.
pub fn restore(board: &Board, token: &Token, past: &Past) -> Result<Restored, Refusal> {
    let Past { draft, at, as_of, written, .. } = past;
    let frame = frames::set_arrangement(
        &draft.to_string(),
        &written_runs(written)?,
        *as_of,
        None,
        None,
        None,
        Some(&format!("restore:{draft}:{at}:{as_of}.arrangement")),
    );
    let v = match board.op(Some(token), &frame)? {
        Answer::Closed => return Err(session_ended("restoring the draft", OnEnd::Rerun)),
        Answer::Document(v) => v,
    };
    let position = judge(&v, draft, *as_of, Act::Restore)?;
    Ok(Restored { draft: draft.clone(), at: *at, position })
}

/// Reads the correspondence records of every origin among `images`' runs.
///
/// Each origin's records are held to its owner's own account, read at the
/// head under `token`. It is the module doc's THE RECORDS AND THE MAPPING
/// OF IMAGES: the distinct runs of every image handed it at once, in order,
/// each record read once however many images name its span. A caller
/// comparing two images reads both first and hands both here, so a
/// publication landing between its reads leaves neither image unmapped.
///
/// # Errors
///
/// A run whose I-address is no content I-address, the board's fault, faced;
/// the records' reads' refusals — [`Refusal::Unreadable`] for an origin the
/// board answers `withheld`, [`Refusal::NoSuchDocument`] for one it answers
/// `doc_not_registered`, an answer of another shape faced; the death signal
/// under the token at any read, [`Refusal::SessionEnded`], its face saying
/// to run this again; the dialer's halts.
pub fn records(board: &Board, token: &Token, images: &[&Image]) -> Result<Vec<Record>, Refusal> {
    let (mut seen, mut runs) = (HashSet::new(), Vec::new());
    for image in images {
        for run in runs_of(image.runs())? {
            if seen.insert(run.clone()) {
                runs.push(run);
            }
        }
    }
    owners_records(&Reader::new(board, Some(token), OnEnd::Rerun), &runs)
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
