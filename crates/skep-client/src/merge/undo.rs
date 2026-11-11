//! The undo and the withdrawal of a merge landed in a draft.
//!
//! Both are skep #783's: the landing lane's rulings R6 and N4 with their
//! precisions P2, P3 and P4, and the withdrawal ruled beside them.
//!
//! A merge landed in a draft (the `land` module's draft landing) leaves the
//! draft holding M, its base re-recorded on the head the merge composed on,
//! and the marker beside it (`doc_metadata`'s `merge`) saying the draft's
//! next version replaces the merged sides. Two acts take that back, each
//! one `set_arrangement` of the draft (wire.md §Arrangement):
//!
//! * [`undo`] puts the draft back as it stood before the landing — its
//!   arrangement C and its base as they were, and the marker it carried
//!   then put back as it stood, or cleared where it carried none — typed
//!   against the landing's position, or against a later one where **The
//!   typed position** says (P3);
//! * [`withdraw`] takes the merge out and keeps the words — the draft's
//!   current arrangement sent back whole, its recorded base re-sent
//!   unmoved, no `merge` — typed against the position it read the draft at.
//!
//! A third act takes a withdrawal back (skep #870; B3-S11, D6 BM-36):
//! [`unwithdraw`] puts the marker the withdrawal cleared back as it stood —
//! the draft's current words, mapped as the undo's are (**The mapping**),
//! its recorded base re-sent unmoved, the marker's head pair, sides and
//! position, `merge.at` the landing's own (wire.md §Arrangement) — typed
//! against the withdrawal's position, or the caller's own last
//! acknowledgment where later (P3). The board admits the position only
//! where it names a marker it put on the draft since the draft's base last
//! moved at a publication, so after the withdrawal's undo the draft and its
//! marker stand exactly as they stood before the withdrawal, and [`undo`]
//! reads them as it read them then. **What names a withdrawal**: no record
//! names its act or its position, and an undo's feed row has a withdrawal's
//! shape, so the state decides — the draft's feed row at the position is a
//! `set_arrangement` naming a base and no merge, the state before it
//! carries a marker, and the base pair and the words at it are those
//! before it; anything else is [`Refusal::NoWithdrawal`], nothing sent.
//! **Nothing to undo**, nothing sent, judged on the draft as it stands, the
//! marker first: a draft carrying a marker — the one put back already, or a
//! merge landed since — is [`NoUndo::Remarked`]; then a base moved since the
//! withdrawal is [`NoUndo::Published`] where the draft's feed holds a
//! `publish` row past it, naming the member that row names first, and
//! [`NoUndo::Remarked`] where it holds none, a merge having landed and been
//! taken out again. Its record is written only where the newest record of
//! the kind on the draft is the withdrawal's take-back of a landing in it
//! whose head and sides are the marker's: the landing's record composed
//! again, `replaces` the take-back's link. The write's id names the draft,
//! the withdrawal and the position the call read the draft at.
//!
//! **The dispatch (P4).** The undo reads the draft's `doc_metadata` live
//! and dispatches on the base record first, then the marker:
//!
//! * a base recorded and a marker — the undo by the marker: the state
//!   before the landing is read at the pre-landing read (below) for the
//!   marker's `at`; a draft that did not exist there inherited the marker
//!   when it was staged (P2), and there is nothing of its own to take back
//!   ([`NoUndo::Inherited`]); else the one write sends C with the base read
//!   there — address and extent, P1's pair — typed as **The typed
//!   position** says, the marker's `at` the landing's position. Where the
//!   state there carried a marker — an earlier landing's, the same
//!   landing's among them (skep #790), or the one the draft's stage copied
//!   — the write puts it back as it stood (skep #964): its head pair, its
//!   sides and its own `at` (wire.md §Arrangement, `merge.at`), a marker
//!   naming no position or no extent being this library's own fault; where
//!   it carried none the write sends no `merge`, and the marker is cleared;
//! * a base recorded, no marker — nothing to undo: the merge was published
//!   — from the draft, the base record standing on that version, or by a
//!   merge's shot naming the draft, which keeps its base (skep #944) — and
//!   an undo from the feed would re-record the base backward, the false
//!   fact N4 forbids ([`NoUndo::Published`], naming the member the row
//!   names first); the words alone come from the draft's
//!   own latest feed row of the kinds that end a marker, read and never
//!   acted on — a `publish` row P4's words, a `set_arrangement` row naming
//!   a base and no merge an undo's or a withdrawal's already made
//!   ([`NoUndo::TakenBack`]), neither a draft carrying no merge
//!   ([`Refusal::NoMerge`]);
//! * no base record (N4's baseless case: a free-standing draft, an admitted
//!   fork) — the landing's position is the draft's own latest
//!   `set_arrangement` row carrying a `merge` term, read off the supplement
//!   (`/changes?under=S&drafts=true`, wire.md §The change feed); no such
//!   row is nothing to undo ([`Refusal::NoMerge`]). The one write sends C
//!   from the pre-landing read with no `base`, no `head` and no `merge`,
//!   typed as **The typed position** says, that row's `at` the landing's
//!   position — unless the landing was already taken back (P4). On such a
//!   draft the feed tells an undo's row from a restore's or any plain
//!   re-arrangement's by none of its terms, so where `set_arrangement` rows
//!   naming no merge stand past the landing's, the draft is read at the
//!   latest of them through `/op-at`: that state, mapped through the same
//!   records as C (**The mapping**), equal to C mapped is the merge taken
//!   back there ([`NoUndo::TakenBack`]), nothing sent and the draft's edits
//!   since standing; any other state leaves the write to the board's
//!   verdict.
//!
//! **The pre-landing read.** The state before a commit at position `at` is
//! read through `/op-at` at the answer for `at − 1`: a landing with a base
//! record is one commit of three records, so `at − 1` lies inside it and
//! the board answers `not_a_position` naming the greatest position at or
//! below as `nearest`; the library then reads at `nearest`, never at
//! `at − 1` itself, and never at the head. `image` and `doc_metadata` of
//! the draft are both read at that one position. `history_reclaimed` there
//! is [`Refusal::HistoryReclaimed`] — the state before the merge is no
//! longer on this board, and nothing is sent; `doc_not_registered` there
//! is the inherited marker's case; `beyond_head` there is this library's
//! own fault.
//!
//! **The mapping.** C is sent mapped through the correspondence records of
//! the merger's own origins among its runs, read at the head after the
//! pre-landing read — the restore's read and its mapping (the merge
//! reader's `records_of` and `mapped`; the `history` module's doc) — so
//! words a publication made public since the landing come back as the
//! published words they became, their origin the trunk, and the links on
//! them return with them (B3-S11; B3-S7). A run no record covers is sent as
//! read. A baseless landing already taken back is answered after the
//! mapping (the dispatch, above); then a C mapped into more runs than one
//! write may name is [`Refusal::OverCap`], nothing sent.
//!
//! **The typed position (P3).** The undo's one write is typed against the
//! landing's position — the command's and an agent's rule, `own_ack` none —
//! or against the put-back's (below), or against `own_ack`, the caller's
//! own last acknowledged write on the draft, whichever is latest. `own_ack`
//! is the editor's rule, as every burst is typed, so the person's own later
//! changes, taken back first on the editor's stack, never leave the undo
//! refused. With `own_ack` none it lands only where nothing but a
//! take-back of the merge and its undo changed the arrangement since the
//! landing: taking a later change back changes it again, and no frame typed
//! below the arrangement's last change lands (wire.md §Rejection codes,
//! `arrangement_moved`), so its refusal says to edit the draft, never to
//! take the change back first. **The put-back** (skep #964): a withdrawal's
//! undo, or the undo of a landing made over this one, puts the landing's
//! marker back with its `at`, and moves the arrangement as every
//! `set_arrangement` does (wire.md §Arrangement, `merge`). The latest such
//! write is found on the draft's own feed rows past the landing — a
//! `set_arrangement` row whose `merge` names the marker's `at` beside its
//! head and its sides, which a landing's row never names (wire.md §The
//! change feed) — and the draft is read through `/op-at` at the landing
//! and at that write. Where the two states, mapped through the records of
//! the merger's own origins among them as C is (**The mapping**), are
//! equal, the take-back and its undo moved the words and nothing else
//! did, and the write is typed past them; where they differ, a change made
//! between the landing and the take-back stands in the words, and the
//! write is typed against the landing, which the board refuses, the change
//! standing. No position below the landing's lands, the landing having
//! changed the arrangement there, so the latest is the one sent; a position
//! past the board's head as the first read names it is no acknowledgment's,
//! and is refused before any other read. The write's id names the draft and
//! the typed position.
//!
//! **The guarantees.** Each act is one write: a draft changed since the
//! position it is typed against is refused `arrangement_moved` by the board
//! with nothing changed — the undo's is the landing's position, the
//! put-back's where only the take-back and its undo moved the words since,
//! or the caller's own last acknowledgment past both, so any change since
//! that position refuses it, which past the caller's own last
//! acknowledgment is another hand's; the withdrawal's is its read's, so an
//! edit between its read and its write refuses it. A re-run of a take-back
//! takes nothing back twice: it finds the marker cleared, or on a baseless
//! draft the undo's own row still the latest re-arrangement past the
//! landing's, in any session and whatever position it is typed against, so
//! the draft's edits since stand. After an undo that put an earlier
//! landing's marker back the draft carries that merge, and the undo run
//! again takes it back as a step of its own: each undo takes back the
//! newest step alone. The base record is never made false: the undo
//! restores the base read before the landing, the withdrawal re-sends the
//! base it read unmoved, a draft whose base record has no marker is never
//! undone from the feed, and a baseless document is never sent a `base`.
//!
//! **The record.** After the write lands, the current record naming the
//! draft as landed in — found by the links of the kind to the draft, the
//! newest by the order they were minted, and for an undo by the marker the
//! one standing for the marker: the newest with its head and sides, naming
//! a position at or before its `at` and replaced by no record linked to the
//! draft — is replaced: a record composed from it with `landed` none and
//! `replaces` its link is appended to the journal (`journal`, or the
//! account's default) and linked from its atom there, the link homed in
//! the journal beside it, unsigned, so a reader of the journal sees the
//! merge no longer stands on the draft. A merge landed in the draft again
//! with no take-back recorded between is the same landing (skep #790; the
//! `land` module's doc): the undo takes back the later write, the one the
//! marker or the feed row names, and puts the earlier write's marker back,
//! so the first landing's record, which stands for both, stands on and
//! none is written — as wherever the record found is the one standing for
//! the marker put back. A marker the draft's stage copied marks no landing
//! in it (P2), so a record found beside it is replaced. Where no record
//! stands none is written, and the act stands all the same. A re-run after
//! either act writes nothing for it (**The guarantees**) — so where the
//! record is not written after the act's write, for a lost acknowledgment
//! at its writes, a board too busy to answer the find of the account's
//! journal, or a journal the record's step finds unable to take it, the
//! landing's record stands alone, which the halt says; a lost
//! acknowledgment of the act's own write, the dialer's halt, leaves it
//! alone too. A `resume` of the landing after either act finds nothing to
//! resume of the write taken back, whether or not either record was
//! written: it goes by the marker, which the act cleared, or put back as
//! the earlier landing left it — the landing a `resume` then answers where
//! it is this merge's and the draft holds M — or for a baseless draft by
//! the latest `set_arrangement` row, the act's own, naming no merge (the
//! `land` module's doc). A landing of the key made after either act writes
//! a record of its own, which replaces this one: the landing's read-first
//! takes the merger's newest record of the key, and this one names no
//! landing (the `land` module's doc).
//!
//! **The journal, before the write.** A journal named is checked before the
//! one write, as a landing's is (the `land` module's doc): one
//! `doc_metadata` at the head, after the reads and the cap, and one this
//! merger may not read, one this board does not register or another
//! account's is refused there as a halt naming the journal and the check it
//! fails, a published one of the merger's own as
//! [`Refusal::PublishedJournal`] — a merge record is kept only in a private
//! document — with nothing sent (P13), whether or not a record of the
//! landing stands to be replaced.
//!
//! **Nothing signed.** The one write is a draft's `set_arrangement` and the
//! record's two writes go into a private journal, none of which takes an
//! `attest`, so neither act reads the board's head: each lands on a claimed
//! board whose head is owed as on any other. A lost acknowledgment of the
//! one write is the dialer's halt, with no re-ask: each act reads first on
//! a re-run.
//!
//! **The session's end.** The death signal under the merger's token is
//! [`Refusal::SessionEnded`]: up to and at the one write the act is run
//! again, nothing having changed; at the record, after the write, the act
//! stands with its record unwritten, as a journal that cannot take the
//! record leaves it there.

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::answers::Metadata;
use crate::board::{acked_at, frames, Board, Rejection};
use crate::halt::{Halt, Refused};

use super::compose::Run;
use super::land::{own_fault, own_fault_face, shape_face, Merger, Unwritten, Writer};
use super::reads::{
    feed_rows, mapped, records_of, runs_of, NoUndo, OnEnd, Reader, Refusal, Role, SHOT_RUN_CAP,
};
use super::record::{self, newest, read_record, Found, Record, RecordLanding};
use crate::board::answers::MergeMarker;

/// What an undo answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undone {
    /// The draft the merge was taken back out of.
    pub draft: Address,
    /// The one write's commit position, its ack's `at`.
    pub position: u64,
    /// The replacing record's link, homed in its journal, where a record of
    /// the landing stood.
    ///
    /// `None` where none did, or where the one standing is the record of
    /// the earlier landing whose marker the undo put back, which stands for
    /// it (skep #790), and none was written.
    pub record: Option<Address>,
    /// The base restored — the pair read before the landing, address and
    /// extent — where the board records a base for the draft; `None` where
    /// the undo went by the draft's feed row, a baseless document whose
    /// landing moved nothing.
    pub restored: Option<(Address, u64)>,
    /// The marker the draft carries again (skep #964).
    ///
    /// It is the one the draft carried before the landing, put back as it
    /// stood with its own `at`: an earlier landing's, or the one the draft's
    /// stage copied (P2). `None` where the draft carried none, the marker
    /// cleared, and where the undo went by the draft's feed row.
    pub marker: Option<MergeMarker>,
}

/// What a withdrawal answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawn {
    /// The draft the merge was taken out of, its words kept.
    pub draft: Address,
    /// The one write's commit position, its ack's `at`.
    pub position: u64,
    /// The replacing record's link, homed in its journal, where a record of
    /// the landing stood; `None` where none did, and none was written.
    pub record: Option<Address>,
}

/// What a withdrawal's undo answered (skep #870).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unwithdrawn {
    /// The draft the merge was put back into.
    pub draft: Address,
    /// The one write's commit position, its ack's `at`.
    pub position: u64,
    /// The record written putting the landing's back, homed in its journal.
    ///
    /// It is written where the newest record of the kind on the draft is
    /// the withdrawal's take-back of a landing in it; `None` where none is,
    /// and none was written.
    pub record: Option<Address>,
}

/// Puts a draft back as it stood before the latest merge landed in it (R6).
///
/// The latest landing is the write the draft's marker names, or for a
/// baseless draft its feed row. The dispatch, the pre-landing read, the
/// mapping, the typed position, the one write and the record are the
/// module's doc. `own_ack` is the position of the caller's own last
/// acknowledged write on the draft, the write typed against it where it is
/// past the landing's and the put-back's (P3's editor rule); `None` types
/// it against the later of those two (the command's and an agent's).
/// `journal` is the merge journal the replacing record goes to, or the
/// account's default where `None`, as a landing's.
///
/// **Precondition.** `own_ack`, where given, is the position of a write of
/// the caller's own that changed the draft's arrangement — a burst or a
/// `set_arrangement` — with none of its own since: a link write homed in
/// the draft changes no arrangement (wire.md §Arrangement), and the board
/// admits a write typed past another hand's change, which the undo would
/// then replace.
///
/// # Errors
///
/// In this order:
///
/// - the draft's `doc_metadata` read's refusals — [`Refusal::Unreadable`],
///   [`Refusal::NoSuchDocument`] — and [`Refusal::Published`] for a
///   published document;
/// - `own_ack` past the position that read stood at, or a read naming no
///   position where `own_ack` is given, as [`Refusal::Halt`] with a face,
///   nothing sent;
/// - [`Refusal::NothingToUndo`] with its reason, and [`Refusal::NoMerge`],
///   each with nothing sent — a baseless draft's [`NoUndo::TakenBack`]
///   after the records' reads, below; the feed walk's refusals;
/// - the pre-landing read's: [`Refusal::HistoryReclaimed`] where the board
///   no longer answers the position before the landing, nothing sent; its
///   other refusals, a position past the board's head among them as the
///   library's own fault;
/// - for an undo by the marker, a marker before the landing naming no
///   position or no extent as the library's own fault; the feed walk's
///   refusals past the landing; where a write put the marker back since,
///   the reads of the draft at the landing and at that write, refused as
///   the pre-landing read is, and the records' reads over the two states;
/// - the records' reads' refusals at the head; on a baseless draft, the
///   read of it at its latest re-arrangement past the landing's, refused as
///   the pre-landing read is, and [`NoUndo::TakenBack`] where the state
///   there, mapped, is C mapped, nothing sent; then [`Refusal::OverCap`]
///   where C mapped is in more runs than one write may name, nothing sent;
/// - a journal named that cannot take the record, nothing sent (P13): one
///   this merger may not read, one this board does not register or another
///   account's, as [`Refusal::Halt`] naming the journal and the check it
///   fails; a published one of the merger's own, as
///   [`Refusal::PublishedJournal`]; the journal's `doc_metadata` read's
///   other refusals and halts;
/// - the one write's: `arrangement_moved` as the board's verdict,
///   [`Refusal::Halt`] with `Refused` saying the draft changed since the
///   position the write was typed against — the landing, the put-back with
///   the landing's position beside it, or the caller's last write with the
///   landing's position beside it — the put-back's position named where the
///   words at it were no longer the landing's, that nothing was changed,
///   and with `own_ack` none that the undo can no longer land;
///   `marker_not_restorable` where the write puts a marker back, the draft
///   published since it was read, as [`Refusal::Halt`] saying nothing was
///   changed; [`Refusal::NotOwner`]; [`Refusal::Published`];
///   [`Refusal::WindowWithheld`]; [`Refusal::NeedsSignedSession`];
///   [`Refusal::NoSuchDocument`];
///   `source_not_registered`, `no_base_to_record`, `base_not_in_chain`,
///   `base_extent_too_large` and the runs' refusals as the library's own
///   faults, since it sends only the base, the marker and the runs it read,
///   mapped through the records the board served; a lost acknowledgment as
///   the dialer's halt, with no re-ask;
/// - the record's reads' refusals; a journal the record's step finds unable
///   to take it, as [`Refusal::Halt`] saying the merge is out of the draft
///   — and an earlier landing's merge back in it, where its marker was put
///   back — and the record is not written, nothing of the record written;
///   then the record's writes' as `Writer::write_record` answers them, the
///   act standing.
///
/// The death signal under the merger's token, met at any step, is
/// [`Refusal::SessionEnded`]: up to and at the one write its face says to
/// run the undo again, nothing changed; at the record's, that the merge is
/// out of the draft with its record unwritten — an earlier landing's merge
/// back in it, where its marker was put back, which an undo run again
/// takes back too — and nothing more is written.
pub fn undo(
    board: &Board,
    merger: Merger<'_>,
    draft: &Address,
    kind: &Address,
    own_ack: Option<u64>,
    journal: Option<&Address>,
) -> Result<Undone, Refusal> {
    let writer = Writer::new(board, merger, OnEnd::Rerun);
    let reader = &writer.reader;
    let (meta, read_at) = reader.metadata_read(draft, None)?;
    if meta.published {
        return Err(Refusal::Published { doc: draft.clone() });
    }
    if let Some(own) = own_ack {
        let head = read_at.ok_or_else(|| unpositioned(draft))?;
        if own > head {
            return Err(Halt::face(
                format!("the undo cannot be typed against position {own}"),
                format!("the read of {draft} stood at position {head}, the board's head, and no acknowledgment of a write names a position past it"),
                "pass the position of your own last acknowledged write on the draft, or none to type the undo against the landing's position; nothing was written",
            )
            .into());
        }
    }
    // THE DISPATCH (P4): the base record first, then the marker.
    let taken = meta.merge.as_ref().filter(|_| meta.base.is_some());
    let taking = match (meta.base.as_deref(), meta.merge.as_ref()) {
        (Some(_), Some(marker)) => by_marker(reader, merger.account, draft, marker)?,
        (Some(_), None) => {
            // Nothing to undo, never the feed (N4): the words alone are the
            // feed's, the version the member the row names first (wire.md
            // §The change feed) — the one a publication of the draft
            // minted, or a merge's shot naming the draft, which keeps its
            // base (skep #944).
            let why = match latest_ending_row(reader, draft)? {
                Some(Ending::Publish { member }) => NoUndo::Published {
                    version: member.ok_or_else(|| {
                        own_fault_face(
                            "the draft's latest publication names no member",
                            format!("{draft}'s latest `publish` row on the feed names no member first, which every `publish` row the wire serves names (wire.md §The change feed)"),
                        )
                    })?,
                },
                Some(Ending::TakenBack) => NoUndo::TakenBack,
                None => return Err(Refusal::NoMerge { draft: draft.clone() }),
            };
            return Err(Refusal::NothingToUndo { draft: draft.clone(), why });
        }
        (None, _) => {
            let Some(LandingRows { at, rearranged }) = landing_rows(reader, draft)? else {
                return Err(Refusal::NoMerge { draft: draft.clone() });
            };
            let runs = match before(reader, draft, at, "the position before the landing")? {
                Before::Stood { runs, .. } => runs,
                Before::Unregistered => {
                    return Err(own_fault_face(
                        "the draft did not exist before its landing",
                        format!("{draft}'s feed names a landing at position {at}, and `doc_metadata` as of the position before it answers `doc_not_registered`"),
                    ))
                }
            };
            Taking { landing: at, restored: None, runs, rearranged, earlier: None, put_back: None }
        }
    };
    let Taking { landing, restored, runs, rearranged, earlier, put_back } = taking;
    // THE MAPPING: C through the records of the merger's own origins.
    let records = records_of(reader, merger.account, &runs)?;
    let sent = mapped(&runs, &records);
    // A baseless landing taken back (P4): the latest re-arrangement past it
    // left the draft where this write would put it.
    if let Some(later) = rearranged {
        let what = "the position of the draft's latest re-arrangement";
        let left = arranged_at(reader, draft, later, what)?;
        if mapped(&left, &records) == sent {
            return Err(Refusal::NothingToUndo { draft: draft.clone(), why: NoUndo::TakenBack });
        }
    }
    if sent.len() > SHOT_RUN_CAP {
        return Err(Refusal::OverCap { runs: sent.len(), cap: SHOT_RUN_CAP });
    }
    // THE TYPED POSITION (P3): the landing's, the put-back's where only the
    // take-back and its undo moved the words since, or the caller's own
    // last ack where it is later.
    let typed = put_back.filter(|p| p.kept).map_or(landing, |p| p.at);
    let as_of = own_ack.map_or(typed, |own| own.max(typed));
    let stem = format!("undo:{draft}:{as_of}");
    let base_text = restored.as_ref().map(|(base, copied)| (base.to_string(), *copied));
    // The marker the state before the landing carried, put back as it
    // stood (skep #964); none sent where it carried none.
    let sides: Vec<&str> =
        earlier.iter().flat_map(|e| &e.marker.sides).map(String::as_str).collect();
    let frame = frames::set_arrangement(
        &draft.to_string(),
        &frame_runs(&sent)?,
        as_of,
        earlier.as_ref().map(|e| (e.marker.head.as_str(), e.head_copied)),
        base_text.as_ref().map(|(base, copied)| (base.as_str(), *copied)),
        earlier.as_ref().map(|e| (sides.as_slice(), Some(e.at))),
        Some(&format!("{stem}.arrangement")),
    );
    writer.check_journal(journal, &format!("the merge cannot be taken out of {draft}"))?;
    let restores = earlier.is_some();
    let act = Act::Undo { landing, put_back, own_ack: own_ack.is_some(), restores };
    let position = send(&writer, &frame, draft, as_of, act)?;
    // The record is judged by the markers, the one put back only where it
    // marks a landing: never the one a stage copied (P2).
    let landed_before = earlier.as_ref().filter(|e| meta.at != Some(e.at));
    let markers = taken.map(|taken| Markers { taken, landing, earlier: landed_before });
    let record = replace_record(board, merger, kind, draft, &stem, journal, act, markers)?;
    let marker = earlier.map(|e| e.marker);
    Ok(Undone { draft: draft.clone(), position, record, restored, marker })
}

/// What an undo takes back: its landing and the state before it.
///
/// The dispatch yields it (the module's doc, **The dispatch**).
struct Taking {
    /// The landing's position.
    landing: u64,
    /// The base read before the landing, address and extent; `None` for a
    /// baseless draft.
    restored: Option<(Address, u64)>,
    /// C, the arrangement before the landing.
    runs: Vec<Run>,
    /// A baseless draft's latest re-arrangement past its landing's row.
    rearranged: Option<u64>,
    /// The marker the state before the landing carried, which the write
    /// puts back as it stood.
    earlier: Option<Restorable>,
    /// The latest write that put the landing's marker back since.
    put_back: Option<PutBack>,
}

/// A marker as a write puts it back, its position and extent known.
///
/// It is the marker's sides, its head pair and its own `at`, which the
/// board takes only where it stamped that marker on the draft (wire.md
/// §Arrangement, `merge.at`).
struct Restorable {
    /// The marker as `doc_metadata` served it.
    marker: MergeMarker,
    /// The position of the commit that stamped it.
    at: u64,
    /// Its head's content count as read at the compose.
    head_copied: u64,
}

impl Restorable {
    /// Returns `marker`, read `before` a write of `draft`, as one put back.
    ///
    /// # Errors
    ///
    /// A marker naming no position or no extent, as the library's own fault:
    /// every marker the wire serves carries both.
    fn of(draft: &Address, marker: MergeMarker, before: &str) -> Result<Restorable, Refusal> {
        match (marker.at, marker.head_copied) {
            (Some(at), Some(head_copied)) => Ok(Restorable { marker, at, head_copied }),
            _ => Err(own_fault_face(
                "the marker names no position or no extent",
                format!("{draft}'s `doc_metadata` {before} carries a merge with no `at` or no `head_copied`, which every marker the wire serves carries (wire.md §The response envelope)"),
            )),
        }
    }
}

/// The latest write that put an undo's marker back since its landing.
///
/// It is found and judged as the module's doc's **The put-back** says.
#[derive(Clone, Copy)]
pub(crate) struct PutBack {
    /// Its commit position.
    at: u64,
    /// Whether the draft's words there, mapped, are those at the landing.
    ///
    /// Where they are, the take-back and its undo moved them and nothing
    /// else did, and the undo is typed past it.
    kept: bool,
}

/// Reads what an undo by the marker takes back (the module's doc).
///
/// It is the state before the landing at `marker`'s `at`, through the
/// pre-landing read, with the marker that state carried (**The dispatch**),
/// and the latest write that put `marker` back since the landing, judged by
/// the draft's words at the landing and at it, mapped through the records
/// of `account`'s own origins among them (**The put-back**).
///
/// # Errors
///
/// A marker naming no position, as the library's own fault;
/// [`Refusal::NothingToUndo`] with [`NoUndo::Inherited`] where the draft
/// did not exist before the landing; the pre-landing read's refusals; a
/// draft recording no base before the landing, or a marker there naming no
/// position or no extent, as the library's own faults; the feed walk's
/// refusals; the reads at the landing and at the put-back, typed by
/// [`position_fault`]; the records' reads' over the two states.
fn by_marker(
    reader: &Reader<'_>,
    account: &str,
    draft: &Address,
    marker: &MergeMarker,
) -> Result<Taking, Refusal> {
    let at = marker.at.ok_or_else(|| {
        own_fault_face(
            "the marker names no position",
            format!("{draft}'s `doc_metadata` carries a merge with no `at`, which every marker the wire serves carries (wire.md §The response envelope)"),
        )
    })?;
    let (then, runs) = match before(reader, draft, at, "the position before the landing")? {
        Before::Unregistered => {
            return Err(Refusal::NothingToUndo { draft: draft.clone(), why: NoUndo::Inherited })
        }
        Before::Stood { meta, runs } => (meta, runs),
    };
    let old = match (then.base.as_deref().and_then(parse_address), then.base_copied) {
        (Some(base), Some(copied)) => (base, copied),
        _ => {
            return Err(own_fault_face(
                "the draft recorded no base before the landing",
                format!("{draft} carries a base record and a marker now, and `doc_metadata` as of the position before the landing answers none: a landing records a base only where one stood (wire.md §Arrangement, `no_base_to_record`)"),
            ))
        }
    };
    let earlier = then.merge.map(|m| Restorable::of(draft, m, "before the landing")).transpose()?;
    // THE PUT-BACK (skep #964): the take-back and its undo alone moved the
    // words since the landing where the states at the two writes, mapped,
    // are one.
    let put_back = match put_back_of(reader, draft, marker, at)? {
        None => None,
        Some(back) => {
            let landed = arranged_at(reader, draft, at, "the landing's position")?;
            let put = arranged_at(reader, draft, back, "the position the merge was put back at")?;
            let records =
                records_of(reader, account, &[landed.as_slice(), put.as_slice()].concat())?;
            Some(PutBack { at: back, kept: mapped(&landed, &records) == mapped(&put, &records) })
        }
    };
    Ok(Taking { landing: at, restored: Some(old), runs, rearranged: None, earlier, put_back })
}

/// Returns the position of the latest write that put `marker` back.
///
/// It walks the supplement under the draft (`drafts=true`) past `at`, the
/// marker's own position, keeping the last `set_arrangement` row whose
/// `merge` names `at` beside the marker's head and its sides — a merge put
/// back, never a landing, whose row names no `at` (wire.md §The change
/// feed). `None` where no such row stands.
///
/// # Errors
///
/// The feed walk's (`feed_rows`), through `reader`.
fn put_back_of(
    reader: &Reader<'_>,
    draft: &Address,
    marker: &MergeMarker,
    at: u64,
) -> Result<Option<u64>, Refusal> {
    let mut latest = None;
    feed_rows(reader, &draft.to_string(), true, at, |row| {
        let merge = &row["merge"];
        let names = row["op"].as_str() == Some("set_arrangement")
            && merge["at"].as_u64() == Some(at)
            && merge["head"].as_str() == Some(marker.head.as_str())
            && merge["sides"].as_array().is_some_and(|s| {
                s.iter().map(Value::as_str).eq(marker.sides.iter().map(|x| Some(x.as_str())))
            });
        if names {
            latest = row["at"].as_u64().or(latest);
        }
    })?;
    Ok(latest)
}

/// Takes the merge out of a draft and keeps its words.
///
/// The draft's `doc_metadata` is read live and its image at THAT read's
/// position through `/op-at`; the one write sends the image back whole with
/// the recorded base re-sent unmoved — address and extent as read — and no
/// `merge`, typed against that position, so the marker is cleared and the
/// draft's words and base stay as they are; an inherited marker is taken
/// out the same way. The record and the journal are as [`undo`]'s.
///
/// # Errors
///
/// In this order:
///
/// - the draft's `doc_metadata` read's refusals — [`Refusal::Unreadable`],
///   [`Refusal::NoSuchDocument`] — and [`Refusal::Published`] for a
///   published document;
/// - [`Refusal::NoMerge`] where the draft carries no marker, nothing sent;
/// - the image read's refusals at the read's position;
/// - a journal named that cannot take the record, as [`undo`]'s, nothing
///   sent (P13);
/// - the one write's, as [`undo`]'s, `arrangement_moved` saying the draft
///   changed since it was read;
/// - the record's, as [`undo`]'s.
///
/// The death signal under the merger's token is [`Refusal::SessionEnded`],
/// faced as [`undo`]'s.
pub fn withdraw(
    board: &Board,
    merger: Merger<'_>,
    draft: &Address,
    kind: &Address,
    journal: Option<&Address>,
) -> Result<Withdrawn, Refusal> {
    let writer = Writer::new(board, merger, OnEnd::Rerun);
    let reader = &writer.reader;
    let (meta, as_of) = reader.metadata_read(draft, None)?;
    if meta.published {
        return Err(Refusal::Published { doc: draft.clone() });
    }
    if meta.merge.is_none() {
        return Err(Refusal::NoMerge { draft: draft.clone() });
    }
    let as_of = as_of.ok_or_else(|| unpositioned(draft))?;
    let base = match (meta.base.as_deref().and_then(parse_address), meta.base_copied) {
        (Some(base), Some(copied)) => (base, copied),
        _ => {
            return Err(own_fault_face(
                "the draft carries a marker and no base",
                format!("{draft}'s `doc_metadata` carries a merge beside no base record, and the marker is recorded only beside a base (wire.md §Arrangement)"),
            ))
        }
    };
    // THE ONE POSITION: the image as of the metadata's read.
    let runs = runs_of(&reader.imaged(draft, Some(as_of))?.runs)?;
    let stem = format!("withdraw:{draft}:{as_of}");
    let base_text = base.0.to_string();
    let frame = frames::set_arrangement(
        &draft.to_string(),
        &frame_runs(&runs)?,
        as_of,
        None,
        Some((base_text.as_str(), base.1)),
        None,
        Some(&format!("{stem}.arrangement")),
    );
    writer.check_journal(journal, &format!("the merge cannot be taken out of {draft}"))?;
    let position = send(&writer, &frame, draft, as_of, Act::Withdraw)?;
    let record = replace_record(board, merger, kind, draft, &stem, journal, Act::Withdraw, None)?;
    Ok(Withdrawn { draft: draft.clone(), position, record })
}

/// Takes a withdrawal back (skep #870; B3-S11, D6 BM-36).
///
/// The merge it took out of a draft is put back as it stood.
/// `withdrawal` is the position of the withdrawal's one write, its
/// [`Withdrawn::position`]. The draft's `doc_metadata` is read live; the
/// draft is read at `withdrawal` and before it through `/op-at` as the
/// pre-landing read reads; what names a withdrawal, nothing to undo, the
/// mapping, the one write, its typed position and its record are the
/// module's doc. `own_ack` is the position of the caller's own last
/// acknowledged write on the draft, the write typed against it where it is
/// past `withdrawal` (P3's editor rule), as [`undo`] takes it; `journal` is
/// as [`undo`]'s.
///
/// **Precondition.** `own_ack`, where given, is as [`undo`]'s.
///
/// # Errors
///
/// In this order:
///
/// - the draft's `doc_metadata` read's refusals — [`Refusal::Unreadable`],
///   [`Refusal::NoSuchDocument`] — and [`Refusal::Published`] for a
///   published document; a read naming no position;
/// - `own_ack` past the position that read stood at, as [`undo`]'s;
/// - the reads at `withdrawal` and before it: [`Refusal::HistoryReclaimed`]
///   where the board no longer answers either, nothing sent; a position the
///   board answers `beyond_head`, `not_a_position` or `doc_not_registered`
///   at as [`Refusal::NoWithdrawal`]; the reads' other refusals;
/// - [`Refusal::NoWithdrawal`] where the position names no withdrawal of
///   the draft, after the feed walk's refusals, nothing sent;
/// - [`Refusal::NothingToUndo`] with [`NoUndo::Remarked`] or
///   [`NoUndo::Published`], nothing sent;
/// - the records' reads' refusals at the head, then [`Refusal::OverCap`]
///   where the words mapped are in more runs than one write may name,
///   nothing sent;
/// - a journal named that cannot take the record, as [`undo`]'s, nothing
///   sent (P13);
/// - the one write's, as [`undo`]'s — `arrangement_moved` saying the draft
///   changed since the merge was taken out, or since the caller's last
///   write past it — and `marker_not_restorable`, the draft published since
///   it was read, as [`Refusal::Halt`] saying nothing was changed;
/// - the record's reads' refusals; a journal the record's step finds unable
///   to take it, as [`Refusal::Halt`] saying the merge is back in the draft
///   and the record is not written; then the record's writes'.
///
/// The death signal under the merger's token is [`Refusal::SessionEnded`],
/// faced as [`undo`]'s up to and at the one write, and at the record's
/// saying the merge is back in the draft with its record unwritten.
pub fn unwithdraw(
    board: &Board,
    merger: Merger<'_>,
    draft: &Address,
    kind: &Address,
    withdrawal: u64,
    own_ack: Option<u64>,
    journal: Option<&Address>,
) -> Result<Unwithdrawn, Refusal> {
    let writer = Writer::new(board, merger, OnEnd::Rerun);
    let reader = &writer.reader;
    let (meta, read_at) = reader.metadata_read(draft, None)?;
    if meta.published {
        return Err(Refusal::Published { doc: draft.clone() });
    }
    let read_at = read_at.ok_or_else(|| unpositioned(draft))?;
    if let Some(own) = own_ack.filter(|own| *own > read_at) {
        return Err(Halt::face(
            format!("the undo cannot be typed against position {own}"),
            format!("the read of {draft} stood at position {read_at}, the board's head, and no acknowledgment of a write names a position past it"),
            "pass the position of your own last acknowledged write on the draft, or none to type the undo against the withdrawal's position; nothing was written",
        )
        .into());
    }
    // WHAT NAMES A WITHDRAWAL: the state at it and the state before it.
    let none = || Refusal::NoWithdrawal { draft: draft.clone(), at: withdrawal };
    let after = match reader.metadata(draft, Some(withdrawal)) {
        Ok(after) => after,
        Err(Refusal::NoSuchDocument(_) | Refusal::BeyondHead { .. } | Refusal::NotAPosition { .. }) => return Err(none()),
        Err(e) => return Err(e),
    };
    let left = arranged_at(reader, draft, withdrawal, "the withdrawal's position")?;
    let Before::Stood { meta: then, runs: stood } = before(reader, draft, withdrawal, "the position before the withdrawal")? else {
        return Err(none());
    };
    let pair = |m: &Metadata| m.base.as_deref().and_then(parse_address).zip(m.base_copied);
    let (Some(cleared), Some(base)) = (then.merge.clone(), pair(&after)) else { return Err(none()) };
    if pair(&then).as_ref() != Some(&base) || stood != left {
        return Err(none());
    }
    let rows = withdrawal_rows(reader, draft, withdrawal)?;
    if !rows.withdrew {
        return Err(none());
    }
    // NOTHING TO UNDO: the marker first, then the base.
    if meta.merge.is_some() {
        return Err(Refusal::NothingToUndo { draft: draft.clone(), why: NoUndo::Remarked });
    }
    if pair(&meta).as_ref() != Some(&base) {
        let why = match rows.published {
            Some(member) => NoUndo::Published {
                version: member.ok_or_else(|| {
                    own_fault_face(
                        "the draft's latest publication names no member",
                        format!("{draft}'s latest `publish` row on the feed names no member first, which every `publish` row the wire serves names (wire.md §The change feed)"),
                    )
                })?,
            },
            None => NoUndo::Remarked,
        };
        return Err(Refusal::NothingToUndo { draft: draft.clone(), why });
    }
    let cleared = Restorable::of(draft, cleared, "before the withdrawal")?;
    // THE MAPPING: the draft's words as they stand, through the records.
    let runs = runs_of(&reader.imaged(draft, Some(read_at))?.runs)?;
    let records = records_of(reader, merger.account, &runs)?;
    let sent = mapped(&runs, &records);
    if sent.len() > SHOT_RUN_CAP {
        return Err(Refusal::OverCap { runs: sent.len(), cap: SHOT_RUN_CAP });
    }
    // THE TYPED POSITION (P3): the withdrawal's, or the caller's own last
    // ack where it is later.
    let as_of = own_ack.map_or(withdrawal, |own| own.max(withdrawal));
    let stem = format!("unwithdraw:{draft}:{withdrawal}:{read_at}");
    let base_text = base.0.to_string();
    let sides: Vec<&str> = cleared.marker.sides.iter().map(String::as_str).collect();
    let frame = frames::set_arrangement(
        &draft.to_string(),
        &frame_runs(&sent)?,
        as_of,
        Some((cleared.marker.head.as_str(), cleared.head_copied)),
        Some((base_text.as_str(), base.1)),
        Some((&sides, Some(cleared.at))),
        Some(&format!("{stem}.arrangement")),
    );
    writer.check_journal(journal, &format!("the merge cannot be put back into {draft}"))?;
    let act = Act::Unwithdraw { withdrawal, own_ack: own_ack.is_some() };
    let position = send(&writer, &frame, draft, as_of, act)?;
    let record = restore_record(board, merger, kind, draft, &cleared.marker, &stem, journal)?;
    Ok(Unwithdrawn { draft: draft.clone(), position, record })
}

/// The draft's feed rows a withdrawal's undo reads (the module's doc).
struct WithdrawalRows {
    /// Whether the withdrawal's row names a base and no merge.
    ///
    /// The row is the `set_arrangement` row at the withdrawal's position.
    withdrew: bool,
    /// The member the latest `publish` row past that position names first.
    ///
    /// `None` where no such row stands; `Some(None)` where it names none
    /// this client can read.
    published: Option<Option<Address>>,
}

/// Returns the draft's feed rows at the withdrawal's position and past it.
///
/// It walks the supplement under the draft (`drafts=true`), as
/// [`latest_ending_row`] does.
///
/// # Errors
///
/// The feed walk's (`feed_rows`), through `reader`.
fn withdrawal_rows(reader: &Reader<'_>, draft: &Address, withdrawal: u64) -> Result<WithdrawalRows, Refusal> {
    let mut rows = WithdrawalRows { withdrew: false, published: None };
    feed_rows(reader, &draft.to_string(), true, 0, |row| {
        let Some(at) = row["at"].as_u64() else { return };
        match row["op"].as_str() {
            Some("set_arrangement") if at == withdrawal => {
                rows.withdrew = row["base"].is_string() && row["merge"].is_null();
            }
            Some("publish") if at > withdrawal => {
                let member = row["docs"].as_array().and_then(|d| d.first()).and_then(Value::as_str).and_then(parse_address);
                rows.published = Some(member);
            }
            _ => {}
        }
    })?;
    Ok(rows)
}

/// Which act a `set_arrangement` is, for its words.
///
/// The four acts that send a draft one `set_arrangement` of a state the
/// board already held: the two take-backs here and the withdrawal's undo,
/// and the `history` module's restore, whose write is judged by [`judge`]
/// as theirs are.
#[derive(Clone, Copy)]
pub(crate) enum Act {
    /// An undo: its landing's position, the latest write that put the
    /// landing's marker back since, whether `own_ack` was given, and whether
    /// the write puts the earlier marker back.
    ///
    /// Its words name `landing` where the write was typed past it, and the
    /// put-back where one stands. With `own_ack` false the write is typed
    /// against the landing or the put-back (P3), and no later change, one
    /// taken back included, lets it land. A write that puts a marker back
    /// (skep #964) meets `marker_not_restorable` where a publication moved
    /// the draft's base since its read.
    Undo {
        landing: u64,
        put_back: Option<PutBack>,
        own_ack: bool,
        restores: bool,
    },
    Withdraw,
    /// A withdrawal's undo, its words as an undo's are.
    ///
    /// It carries the withdrawal's position and whether `own_ack` was
    /// given.
    Unwithdraw {
        withdrawal: u64,
        own_ack: bool,
    },
    Restore,
}

impl Act {
    /// The act's name in a face.
    fn name(self) -> &'static str {
        match self {
            Act::Undo { .. } => "the undo",
            Act::Withdraw => "the withdrawal",
            Act::Unwithdraw { .. } => "the withdrawal's undo",
            Act::Restore => "the restore",
        }
    }
}

/// Faces a `doc_metadata` answer of `draft` that names no position.
fn unpositioned(draft: &Address) -> Halt {
    Halt::face(
        "`doc_metadata` answered no `as_of`",
        format!("the read of {draft} named no position (wire.md §The response envelope: every response names where it sits)"),
        "this board is not speaking the wire this client expects; nothing was written",
    )
}

/// What stood before a commit (the module's doc, the pre-landing read).
enum Before {
    /// The draft did not exist at the position before the commit: an
    /// inherited marker's case (P2).
    Unregistered,
    /// The draft's metadata and arrangement as they stood.
    Stood {
        /// `doc_metadata` as of the position before the commit.
        meta: Metadata,
        /// The arrangement as of the same position.
        runs: Vec<Run>,
    },
}

/// Reads the draft's state before the commit at `at`.
///
/// It is the pre-landing read of the module's doc: `doc_metadata` asked at
/// `at − 1`, re-asked at the `nearest` a `not_a_position` names, then the
/// image at that one position; `what` names that position in a fault's
/// face.
///
/// # Errors
///
/// [`Refusal::HistoryReclaimed`] at either read, with nothing read
/// elsewhere; a position past the board's head, or a `not_a_position`
/// naming no `nearest`, or a write at position 0, as the library's own
/// fault; the reads' other refusals.
fn before(reader: &Reader<'_>, draft: &Address, at: u64, what: &str) -> Result<Before, Refusal> {
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
    let runs = arranged_at(reader, draft, position, what)?;
    Ok(Before::Stood { meta, runs })
}

/// Returns `draft`'s arrangement as of `at`, the position `what` names.
///
/// The extent and the image are both read at `at` through `/op-at`, never at
/// the head instead.
///
/// # Errors
///
/// The reads' refusals, typed by [`position_fault`]; an `image` run that is
/// no content I-address.
fn arranged_at(
    reader: &Reader<'_>,
    draft: &Address,
    at: u64,
    what: &str,
) -> Result<Vec<Run>, Refusal> {
    let imaged = reader.imaged(draft, Some(at)).map_err(|e| position_fault(draft, what, e))?;
    Ok(runs_of(&imaged.runs)?)
}

/// Types the refusal `e` of a read of `draft` at the position `what` names.
///
/// The position is one this library took from the board's own answers, so
/// one past the board's head, or one inside a commit where the board named
/// no position below it, is this library's own fault; any other refusal is
/// itself.
fn position_fault(draft: &Address, what: &str, e: Refusal) -> Refusal {
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

/// What the latest feed row that ends a marker under a draft is.
enum Ending {
    /// A `publish` row: the merge was published from the draft.
    Publish {
        /// The member the row names first: the one the shot minted.
        ///
        /// `None` where the row names none this client can read.
        member: Option<Address>,
    },
    /// A `set_arrangement` row naming a base and no merge: an undo's or a
    /// withdrawal's.
    TakenBack,
}

/// Returns the kind of the latest row under `draft` that ends a marker.
///
/// It walks the supplement under the draft (`drafts=true`), keeping the
/// last of the `publish` rows — with the member each names first — and the
/// `set_arrangement` rows whose `base` is present and `merge` null (wire.md
/// §The change feed); a bare row of the second kind, carrying neither
/// term, counts as neither. `None` where no such row stands.
///
/// # Errors
///
/// The feed walk's (`feed_rows`), through `reader`.
fn latest_ending_row(reader: &Reader<'_>, draft: &Address) -> Result<Option<Ending>, Refusal> {
    let mut latest = None;
    feed_rows(reader, &draft.to_string(), true, 0, |row| match row["op"].as_str() {
        Some("publish") => {
            let member = row["docs"].as_array().and_then(|d| d.first()).and_then(Value::as_str).and_then(parse_address);
            latest = Some(Ending::Publish { member });
        }
        Some("set_arrangement") if row["base"].is_string() && row["merge"].is_null() => {
            latest = Some(Ending::TakenBack);
        }
        _ => {}
    })?;
    Ok(latest)
}

/// A baseless draft's latest landing, by its feed rows.
struct LandingRows {
    /// The `at` of the draft's latest `set_arrangement` row whose `merge`
    /// term is present.
    at: u64,
    /// The `at` of the latest `set_arrangement` row past it whose `merge` is
    /// null, where one stands: an undo's, a restore's and the person's own
    /// alike, each a plain re-arrangement on the feed of a draft with no
    /// base record (wire.md §The change feed).
    rearranged: Option<u64>,
}

/// Returns the latest landing on `draft` by its feed rows.
///
/// It walks the supplement under the draft (`drafts=true`): the landing is
/// the last `set_arrangement` row whose `merge` term is present — the merge
/// it marked, `{sides, head}` (wire.md §The change feed) — and its
/// re-arrangement the last `set_arrangement` row after that one, naming no
/// merge. `None` where no landing row stands.
///
/// # Errors
///
/// The feed walk's (`feed_rows`), through `reader`.
fn landing_rows(reader: &Reader<'_>, draft: &Address) -> Result<Option<LandingRows>, Refusal> {
    let mut latest: Option<LandingRows> = None;
    feed_rows(reader, &draft.to_string(), true, 0, |row| {
        let Some(p) = row["at"].as_u64() else { return };
        if row["op"].as_str() != Some("set_arrangement") {
            return;
        }
        if row["merge"].is_object() {
            latest = Some(LandingRows { at: p, rearranged: None });
        } else if let Some(landing) = latest.as_mut() {
            landing.rearranged = Some(p);
        }
    })?;
    Ok(latest)
}

/// Returns `runs` as a `set_arrangement` frame spells them.
///
/// # Errors
///
/// A run with no address, as the library's own fault.
pub(crate) fn frame_runs(runs: &[Run]) -> Result<Vec<Value>, Refusal> {
    runs.iter()
        .map(|r| {
            let i_start = r
                .address_at(0)
                .ok_or_else(|| own_fault_face("a run of the draft names no address", format!("{r:?}")))?;
            Ok(frames::shot_run(&r.origin.to_string(), &i_start.to_string(), r.width))
        })
        .collect()
}

/// Sends the one write, answering its position.
///
/// The frame goes under the merger's token, unsigned — a draft's
/// `set_arrangement` takes no `attest`, so no head is read — and its answer
/// is judged by [`judge`].
///
/// # Errors
///
/// As [`undo`]'s one write's.
fn send(writer: &Writer<'_>, frame: &Value, draft: &Address, as_of: u64, act: Act) -> Result<u64, Refusal> {
    let v = writer.answered_write(
        frame,
        match act {
            Act::Undo { .. } => "taking the merge back out of the draft",
            Act::Withdraw => "taking the merge out of the draft",
            Act::Unwithdraw { .. } => "putting the merge back into the draft",
            Act::Restore => "restoring the draft",
        },
    )?;
    judge(&v, draft, as_of, act)
}

/// Judges a `set_arrangement`'s answer `v`, answering the write's position.
///
/// The frame was typed against `as_of` for `act`; its refusals are mapped
/// as the module's doc lists them, each the same at every act but
/// `arrangement_moved`, whose words are the act's own ([`undo_moved`] for
/// an undo's) — an undo with no `own_ack` saying it can no longer land, and
/// one typed past its landing naming `as_of` as the caller's last write,
/// and the landing's position beside it.
///
/// # Errors
///
/// As [`undo`]'s one write's: `arrangement_moved` as the board's verdict in
/// the person's words; [`Refusal::WindowWithheld`],
/// [`Refusal::NeedsSignedSession`], [`Refusal::NoSuchDocument`],
/// [`Refusal::NotOwner`] and [`Refusal::Published`] by their codes; the
/// refusals of what the library composed as its own fault; the board's
/// other refusals verbatim; an answer that is no acknowledgment and no
/// rejection, faced.
pub(crate) fn judge(v: &Value, draft: &Address, as_of: u64, act: Act) -> Result<u64, Refusal> {
    if let Some(at) = acked_at(v) {
        return Ok(at);
    }
    let Some(r) = Rejection::of(v) else { return Err(shape_face("set_arrangement", v).into()) };
    let site = r.site().addr.as_deref().and_then(parse_address);
    Err(match r.key() {
        // A change past the typed position: the board's verdict, its words
        // the person's, and nothing was changed (the one write wipes
        // nothing).
        "arrangement_moved" => {
            let current = v["site"]["current"].as_u64();
            let since = |what: &str| match current {
                Some(c) => format!(" ({what} at position {as_of}, the draft changed at {c})"),
                None => format!(" ({what} at position {as_of})"),
            };
            let detail = match act {
                Act::Undo { landing, put_back, own_ack, .. } => {
                    undo_moved(draft, as_of, landing, put_back, own_ack, &since)
                }
                // A withdrawal's undo, typed as an undo is.
                Act::Unwithdraw { own_ack: false, .. } => format!("{draft} changed since the merge was taken out{} — nothing was changed; an undo typed against the withdrawal can no longer land, since taking the later changes back changes the draft again: edit the draft as it stands", since("the merge was taken out")),
                Act::Unwithdraw { withdrawal, .. } if withdrawal == as_of => format!("{draft} changed since the merge was taken out{} — nothing was changed; undo the later changes first, or edit", since("the merge was taken out")),
                Act::Unwithdraw { withdrawal, .. } => format!("{draft} changed since your last write to it{} — the change is another hand's, made after the merge was taken out at position {withdrawal}, and it stands; nothing was changed: edit the draft as it stands", since("your last write was")),
                Act::Withdraw | Act::Restore => format!("{draft} changed since it was read{} — nothing was changed; run this again, which reads the draft as it stands", since("read")),
            };
            Refusal::Halt(Halt::Refused(Refused {
                status: 200,
                code: r.code().to_string(),
                detail: Some(detail),
                op: r.op().map(str::to_string),
                body: v.clone(),
            }))
        }
        // A position the board stamped no marker at since the draft's base
        // last moved: the withdrawal's undo, or an undo putting the earlier
        // marker back, read the draft unpublished and a publication of it
        // landed before the write (skep #870, #964).
        "marker_not_restorable" if matches!(act, Act::Unwithdraw { .. } | Act::Undo { restores: true, .. }) => Refusal::Halt(Halt::Refused(Refused {
            status: 200,
            code: r.code().to_string(),
            detail: Some(format!("{draft} was published since it was read, and a publication of the draft ends the merge it carried — nothing was changed; nothing to undo: a version stands, and the way back is to publish the older text again")),
            op: r.op().map(str::to_string),
            body: v.clone(),
        })),
        "withheld" => Refusal::WindowWithheld(site.unwrap_or_else(|| draft.clone())),
        "signed_session_required" => Refusal::NeedsSignedSession,
        "doc_not_registered" => Refusal::NoSuchDocument(draft.clone()),
        "not_owner" => Refusal::NotOwner { draft: draft.clone() },
        "published_target" => Refusal::Published { doc: draft.clone() },
        // The base is the one the draft recorded, read, and a head rides
        // only beside a marker put back, as read; the runs are the draft's
        // own image, mapped through the records the board served: a refusal
        // of them is this library's own fault.
        "source_not_registered"
        | "no_base_to_record"
        | "base_not_in_chain"
        | "base_extent_too_large"
        | "fork_base_moved"
        | "marker_not_restorable"
        | "bad_run"
        | "dangling_source"
        | "too_many_runs"
        | "malformed" => own_fault(&format!("{}'s write", act.name()), &r),
        _ => Refusal::Halt(r.refused(&v)),
    })
}

/// Returns the words of an undo refused `arrangement_moved` (P3).
///
/// The write was typed against `as_of`: the landing's position `landing`,
/// the put-back's where the words at it were the landing's, or the caller's
/// own last write past both; `since` names that position beside the
/// draft's latest change. An undo typed at the landing or the put-back with
/// no `own_ack` can no longer land, taking a change back changing the draft
/// again; one typed at the caller's own last write met another hand's
/// change. A put-back whose words were not the landing's is named, the
/// change before it standing in the words.
fn undo_moved(
    draft: &Address,
    as_of: u64,
    landing: u64,
    put_back: Option<PutBack>,
    own_ack: bool,
    since: &dyn Fn(&str) -> String,
) -> String {
    let typed = put_back.filter(|p| p.kept).map_or(landing, |p| p.at);
    if as_of > typed {
        // Typed at the caller's own last write past the landing: the change
        // since it is another hand's.
        return format!("{draft} changed since your last write to it{} — the change is another hand's, made after the merge landed at position {landing}, and it stands; nothing was changed: edit the draft as it stands", since("your last write was"));
    }
    let (changed, against) = match put_back {
        Some(PutBack { kept: true, .. }) => (
            format!("{draft} changed since the merge was put back{}, after it landed at position {landing}", since("the merge was put back")),
            "the merge's put-back",
        ),
        Some(PutBack { at, kept: false }) => (
            format!("{draft} changed since the merge landed{}: its words changed before the merge was put back at position {at}", since("the merge landed")),
            "the landing",
        ),
        None => (format!("{draft} changed since the merge landed{}", since("the merge landed")), "the landing"),
    };
    if own_ack {
        // The caller's own last write before it: the later changes taken
        // back through the caller move that write past it, where the next
        // undo is typed.
        format!("{changed} — nothing was changed; undo the later changes first, or edit")
    } else {
        // No `own_ack`: taking a change back changes the draft again, so
        // this undo never lands.
        format!("{changed} — nothing was changed; an undo typed against {against} can no longer land, since taking the later changes back changes the draft again: edit the draft as it stands")
    }
}

/// The markers an undo by the marker judges its record by.
///
/// They are the module's doc's **The record**.
#[derive(Clone, Copy)]
struct Markers<'a> {
    /// The marker the undo takes back.
    taken: &'a MergeMarker,
    /// The landing's position, the taken marker's `at`.
    landing: u64,
    /// The earlier landing's marker the undo put back.
    ///
    /// `None` where it put none back, or put back the one the draft's stage
    /// copied, which marks no landing in it (P2).
    earlier: Option<&'a Restorable>,
}

/// Writes the replacing record, answering its link where one is written.
///
/// It is the module's doc's record: the current record naming the draft as
/// landed in — for an undo by the marker, `markers`, the one standing for
/// the marker taken back ([`standing_for`]) — with `landed` none and
/// `replaces` its link, under the act's stem; `None` where no record
/// stands, or where that record is the one standing for the earlier
/// landing's marker put back (skep #790), nothing written. It reads and
/// writes through a writer of its own over `board` as `merger`, built for
/// the step after the act's one write: a session's end at any of its reads
/// or writes leaves the act standing with its record unwritten
/// ([`OnEnd::TakenOut`], or [`OnEnd::EarlierBack`] where an earlier
/// landing's marker was put back).
///
/// # Errors
///
/// The record's read's refusals (`Writer::records_to`), then its writes'
/// (`Writer::write_record`).
#[allow(clippy::too_many_arguments)]
fn replace_record(
    board: &Board,
    merger: Merger<'_>,
    kind: &Address,
    draft: &Address,
    stem: &str,
    journal: Option<&Address>,
    act: Act,
    markers: Option<Markers<'_>>,
) -> Result<Option<Address>, Refusal> {
    let earlier = markers.and_then(|m| m.earlier);
    let on_end = if earlier.is_some() { OnEnd::EarlierBack } else { OnEnd::TakenOut };
    let writer = Writer::new(board, merger, on_end);
    let linked = writer.records_to(kind, draft)?;
    let current = match markers {
        None => newest(linked.into_iter().filter(|f| matches!(&f.record.landed, Some(RecordLanding::Draft { draft: d, .. }) if d == draft))),
        Some(Markers { taken, landing, earlier }) => {
            let current = standing_for(&linked, draft, taken, landing);
            let standing = earlier.and_then(|e| standing_for(&linked, draft, &e.marker, e.at));
            if let (Some(current), Some(standing)) = (&current, &standing) {
                if current.link == standing.link {
                    return Ok(None);
                }
            }
            current
        }
    };
    let Some(current) = current.map(|found| found.record) else { return Ok(None) };
    let record = Record {
        landed: None,
        claims: Vec::new(),
        replaces: current.link.clone(),
        by: record::by(),
        link: None,
        ..current
    };
    let owed = |why: Unwritten, cause: String| {
        let out = match earlier {
            Some(_) => {
                format!("the merge is out of {draft}, the merge landed before it standing again")
            }
            None => format!("the merge is out of {draft}"),
        };
        Halt::face(
            format!("{out}, and the record of {} is not written: {}", act.name(), why.reason()),
            cause,
            on_end.act(),
        )
    };
    writer.write_record(kind, &record, draft, stem, journal, &owed).map(Some)
}

/// Returns the record standing for `marker`'s landing in `draft`.
///
/// It is the newest among `linked`, the records of the kind linked to the
/// draft, that names the draft as landed in at or before `at`, the
/// marker's position, with the marker's head and sides, and that no record
/// linked to the draft replaces: the record of that landing, or of the
/// same landing made earlier (skep #790), never one a take-back replaced
/// or one of a landing made since. `None` where none stands.
fn standing_for(linked: &[Found], draft: &Address, marker: &MergeMarker, at: u64) -> Option<Found> {
    let replaced = |f: &Found| linked.iter().any(|g| g.record.replaces.as_ref() == Some(&f.link));
    newest(
        linked
            .iter()
            .filter(|f| landed_by(f, draft, at) && lands_the_marker(&f.record, draft, marker))
            .filter(|f| !replaced(f))
            .cloned(),
    )
}

/// Returns whether `found` names `draft` as landed in at or before `at`.
fn landed_by(found: &Found, draft: &Address, at: u64) -> bool {
    matches!(&found.record.landed, Some(RecordLanding::Draft { draft: d, position }) if d == draft && *position <= at)
}

/// Writes the record of a withdrawal's undo (skep #870; the module's doc).
///
/// It answers the record's link where one is written.
/// The newest record of the kind on the draft (`Writer::records_to`) must be
/// a take-back — `landed` none — replacing a landing's record that names
/// the draft as landed in, its head the `cleared` marker's and its sides,
/// the draft's own excepted, the marker's; the record written is that
/// landing's record again, `replaces` the take-back's link, under `stem`.
/// `None` where the newest record is no such take-back, nothing written.
/// It reads and writes through a writer of its own built for the step after
/// the act's one write ([`OnEnd::PutBack`]).
///
/// # Errors
///
/// The records' reads' refusals, then the record's writes'
/// (`Writer::write_record`).
fn restore_record(
    board: &Board,
    merger: Merger<'_>,
    kind: &Address,
    draft: &Address,
    cleared: &MergeMarker,
    stem: &str,
    journal: Option<&Address>,
) -> Result<Option<Address>, Refusal> {
    let writer = Writer::new(board, merger, OnEnd::PutBack);
    let Some(newest) = newest(writer.records_to(kind, draft)?) else { return Ok(None) };
    let (None, Some(replaced)) = (&newest.record.landed, &newest.record.replaces) else { return Ok(None) };
    let Some(landing) = read_record(&writer.reader, replaced)? else { return Ok(None) };
    if !lands_the_marker(&landing.record, draft, cleared) {
        return Ok(None);
    }
    let record = Record { replaces: Some(newest.link.clone()), by: record::by(), link: None, ..landing.record };
    let owed = |why: Unwritten, cause: String| {
        Halt::face(
            format!("the merge is back in {draft}, and the record of the withdrawal's undo is not written: {}", why.reason()),
            cause,
            OnEnd::PutBack.act(),
        )
    };
    writer.write_record(kind, &record, draft, stem, journal, &owed).map(Some)
}

/// Returns whether `record` is a landing in `draft` of `marker`'s merge.
///
/// It is landed in the draft, its head the marker's, and its sides, the
/// draft's own excepted, the marker's sides.
fn lands_the_marker(record: &Record, draft: &Address, marker: &MergeMarker) -> bool {
    let landed_here = matches!(&record.landed, Some(RecordLanding::Draft { draft: d, .. }) if d == draft);
    let head = record.head().map(|h| h.address().to_string());
    let mut sides: Vec<String> = record
        .sides
        .iter()
        .filter(|s| s.role() != Role::Head && s.address() != draft)
        .map(|s| s.address().to_string())
        .collect();
    let mut marked = marker.sides.clone();
    sides.sort();
    marked.sort();
    landed_here && head.as_deref() == Some(marker.head.as_str()) && sides == marked
}
