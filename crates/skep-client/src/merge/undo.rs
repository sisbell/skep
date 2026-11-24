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
//!   current arrangement sent back whole as read, each word under the chain
//!   that minted it (**The mapping**), its recorded base re-sent unmoved,
//!   no `merge` — typed against the position it read the draft at.
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
//! **Nothing to undo**, nothing sent, judged on the draft as it stands and
//! on its rows past the withdrawal, the marker first: a draft carrying a
//! marker — the one put back already, or a merge landed since — is
//! [`NoUndo::Remarked`], and so is a draft whose rows past the withdrawal
//! hold a `set_arrangement` naming the cleared marker's `at` in its `merge`
//! — that marker put back since, which a landing's row never names (wire.md
//! §The change feed), whatever took it out again after — since the undo
//! takes back the newest step alone, and that put-back is a step past the
//! withdrawal; then a base moved since the withdrawal is
//! [`NoUndo::Published`] where the draft's feed holds a `publish` row past
//! it, naming the member that row names first, and [`NoUndo::Remarked`]
//! where it holds none, a merge having landed and been taken out again. A
//! landing composed on the head its draft was staged from re-records the
//! base pair the draft held, so the base alone never tells a put-back taken
//! out again. Its record is judged by the marker it puts back, among
//! the merger's own records of the kind linked to the draft (**The
//! record.**): the landing's record is the newest naming the draft as
//! landed in at or before the marker's `at`, with its head and sides,
//! whether replaced or not, and it is composed again, `replaces` the
//! take-back's link, only where a take-back of it was made since the
//! landing — the newest of the merger's records naming no landing that
//! replaces it, its link minted past that `at`. Where none was — the
//! landing's record standing, or taken back only before the marker's
//! landing was made — none is written, and a record of another merge, of a
//! merge the draft is a side of or of a landing made since never decides
//! it. The write's id names the draft, the withdrawal and the position the
//! call read the draft at.
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
//!   fork) — the landing is the one standing in the draft by its own
//!   `set_arrangement` rows on the supplement (`/changes?under=S&drafts=true`,
//!   wire.md §The change feed; the `landings` module's doc, skep #914): a
//!   landing stands from its write until it is taken back, the landing
//!   that stood when it was made then standing again, and a row naming no
//!   merge that leaves the draft exactly as it stood before the standing
//!   landing — that state and the one before the landing read through
//!   `/op-at` and mapped through one read of the records over both (**The
//!   mapping**) — is its take-back, for good, while no other row, a
//!   restore's or any plain re-arrangement's, ends one or brings one back.
//!   No landing row is nothing to undo ([`Refusal::NoMerge`]); landing rows
//!   every one taken back are the merge already taken back
//!   ([`NoUndo::TakenBack`]), nothing sent and the draft's edits since
//!   standing (P4). Else the one write sends C, the state before the
//!   standing landing, with no `base`, no `head` and no `merge` — `at`
//!   without a `base` is `malformed` (wire.md §Arrangement, `merge`), so the
//!   landing it leaves standing again is put back by the write's words
//!   alone — typed as **The typed position** says, the landing's row's `at`
//!   the landing's position. With no marker, a restore to the state before
//!   the standing landing is that landing's take-back, the same write as
//!   the undo's.
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
//! **The mapping.** Every state these acts read is kept as the image the
//! board served, each run under the chain that minted it: a word a deposit
//! naming a member minted stands under the member's chain, `D.v.0.1.k`
//! (wire.md §The publish shot and head-float, the deposit cell; PUB-2.65),
//! and is never the trunk's word of the same ordinal, `D.0.1.k`. What the
//! acts compare and what they send is that image mapped at its own spelling
//! (the merge reader's `mapped_image`), so two states are one only where
//! every word of one is the other's by identity. C is sent mapped through
//! the correspondence records of every origin among its runs, each read in
//! its owner's account — a draft of the merger's and another account's
//! draft C holds words of alike, only that draft's owner's shot homing a
//! record in it — at the head after the pre-landing read, or on a baseless
//! draft the one read its rows' walk made over C and the latest state it
//! compared with C, where it made one: the restore's read and its mapping
//! (the merge reader's `owners_records`; the `history` module's doc). So
//! words a publication made public since the landing —
//! the merger's, or those of another account's draft its owner published —
//! come back as the published words they became, on the trunk's chain, and
//! the links on them return with them (B3-S11; B3-S7). The withdrawal's
//! undo maps the draft's words as they stand by the same read. A run no
//! record covers is sent as read, as is every run of an origin the merger
//! may not read, which yields no record. The records' read takes the
//! image's runs as the core's, each origin its trunk — exact for every run
//! a record can name, records being homed only in private drafts, whose
//! chains carry no member's component — and asks each span once, however
//! many of the states it maps hold it. A withdrawal reads no record and
//! maps nothing: the words it keeps go back as read.
//! Each run is written as [`written_runs`] spells it — its own first
//! I-address, its `origin` the document that minted it, a member's version
//! component kept (wire.md §Arrangement, `publish`). At each of the three
//! acts, a state in more runs than one write may name, counted on the runs
//! the write sends, is [`Refusal::OverCap`], nothing sent.
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
//! change feed); on a baseless draft, which carries no marker, it is the
//! latest take-back of a landing made over this one, which left this one
//! standing again (skep #914; the `landings` module's doc) — and the draft
//! is read through `/op-at` at the landing and at that write. Where the
//! two states, mapped through one read of the records over both as C is
//! (**The mapping**), are equal, the take-back and its undo moved the
//! words and nothing else did, and the write is typed past them: a word
//! read at the landing as a draft's own and at the put-back as the
//! published word a shot made of it is one word, whichever account's
//! draft it was minted in. Where they differ, a change made
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
//! draft the landing taken back by the undo's own row, for good whatever
//! was written since, in any session and whatever position it is typed
//! against, so the draft's edits since stand; and a withdrawal's undo run
//! again finds the marker it put back standing, or its put-back's row past
//! the withdrawal where that marker was taken out again since, and puts it
//! back no second time over words the draft holds since. After an undo
//! that put an earlier landing's marker back, or on a baseless draft left
//! the landing beneath standing again, the draft carries that merge, and
//! the undo run again takes it back as a step of its own: each undo takes
//! back the newest step alone. The base record is never made false: the undo
//! restores the base read before the landing, the withdrawal re-sends the
//! base it read unmoved, a draft whose base record has no marker is never
//! undone from the feed, and a baseless document is never sent a `base`.
//!
//! **The record.** After the write lands, the current record naming the
//! draft as landed in is replaced. The records judged are the merger's
//! own: the links of the kind to the draft whose addresses lie in the
//! merger's account exactly, kept before any record is read — a record
//! names in `replaces` one of its own home's (P20), so another account's, a
//! sub-account's among them, is never read, never replaced and never
//! counts as replacing one of the merger's. Of those, the current record
//! is the one standing for the landing the act takes out — the marker on a
//! draft with a base record, the standing landing's mark on a baseless one:
//! the newest with its head and sides, naming a position at or before its
//! `at` — a marker naming none bounding no position — and replaced by none
//! of the merger's records linked to the draft. A record composed from it
//! with `landed` none and `replaces` its link is appended to the journal
//! (`journal`, or the account's default) and linked from its atom there,
//! the link homed in the journal beside it, unsigned, so a reader of the
//! journal sees the merge no longer stands on the draft. A merge landed in
//! the draft again with no take-back recorded between is the same landing
//! (skep #790; the `land` module's doc): the undo takes back the later
//! write, the one the marker or the standing landing's row names, and the
//! earlier write stands again — its marker put back, or on a baseless draft
//! its landing the one beneath — so the first landing's record, which
//! stands for both, stands on and none is written. So wherever the record
//! found names its key's first landing in the draft at or before the
//! landing standing again: that landing itself, or one beneath it, which
//! another merge's landing went over before the key landed again on top —
//! the first landing stands on beneath, and its record with it. The write
//! puts that landing back by its words alone on a baseless draft, naming
//! no `merge`, so that landing reaches the record's judgement and never the
//! frame. A marker the draft's stage copied marks no landing in it (P2), so
//! a record found beside it is replaced, and a withdrawal of it finds none
//! to replace. Where no record stands none is written — a landing whose
//! record was never written leaves another merge's record standing — and
//! the act stands all the same. A re-run after either act writes nothing
//! for it (**The guarantees**) — so where the record is not written after
//! the act's write, for a lost acknowledgment at its writes, a board too
//! busy to answer the find of the account's journal, a journal the
//! record's step finds unable to take it, or any other refusal of the
//! step's reads and writes, the landing's record stands alone, which the
//! face says: every one of them is faced as the act standing with its
//! record unwritten, the refusal its cause. The act's own write unconfirmed
//! (**The lost answer**) leaves it alone too. A `resume` of the landing
//! after either act finds nothing to resume of the write taken back,
//! whether or not either record was written: it goes by the marker, which
//! the act cleared, or put back as the earlier landing left it — the
//! landing a `resume` then answers where it is this merge's and the draft
//! holds M — or for a baseless draft by the landing standing by its rows,
//! which the act's own row took back, the landing beneath standing again
//! (the `land` module's doc). A landing of the key made after either act
//! writes a record of its own, which replaces this one: the landing's
//! read-first takes the merger's newest record of the key, and this one
//! names no landing (the `land` module's doc).
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
//! board whose head is owed as on any other.
//!
//! **The lost answer.** Each of the act's writes is asked again once under
//! its id where the transport lost its answer (the `land` module's
//! `send_write`), and the board answers an id it has acknowledged in the
//! session with that acknowledgment, so the write lands once and the act
//! goes on to its record. The one write's answer is lost all the same where
//! the re-ask's is lost too; where the re-ask meets the death signal — a
//! daemon restarted between the two asks kills every token, its memo with
//! them (wire.md §Sessions), after the first ask may have committed; and
//! where the board answers `500 internal_panic`, which is no verdict on a
//! write: it may have committed, its acknowledgment never memoized (wire.md
//! §HTTP status codes). Then the one write is looked for on the draft's own
//! rows past the position it was typed against: the first row there to
//! change the draft's arrangement is the write's where it is a
//! `set_arrangement` row carrying the frame's base and merge terms and the
//! draft as of it holds the frame's runs, and the act answers that row's
//! position and writes its record. Else the write is unconfirmed — never
//! landed, not landed yet, or landed with its row's testimony lost to a
//! panic (wire.md §The change feed, a bare row), which no read tells apart
//! — and the act answers so, its record unwritten either way: a face where
//! the session stands, [`Refusal::SessionEnded`] where it ended
//! ([`OnEnd::Unconfirmed`]), and a read of the rows that fails is answered
//! so too, never as its own halt. Its way on says what the draft shows
//! where the write landed and what a run again then does: an undo's takes
//! back the landing beneath it, where one stands, as a step of its own; a
//! withdrawal's, or its undo's, refuses. So the write a lost answer stopped
//! is finished by the act itself wherever the board shows it, never sent
//! again over the state it made, and one it cannot confirm is named as
//! such.
//!
//! **The session's end.** The death signal under the merger's token is
//! [`Refusal::SessionEnded`]: up to and at the one write's first ask the
//! act is run again, nothing having changed; at its re-ask or its read back
//! after a lost answer, the write is unconfirmed (**The lost answer**); at
//! the record, after the write, the act stands with its record unwritten,
//! as a journal that cannot take the record leaves it there.

use serde_json::Value;
use skep_address::{content_subspace, document_of, Address};

use crate::address::parse_address;
use crate::board::answers::Metadata;
use crate::board::{acked_at, frames, Answer, Board, Image, Rejection};
use crate::halt::{Halt, Refused};
use crate::publication;

use super::land::{
    own_fault, own_fault_face, send_write, shape_face, Asked, Merger, Unrecorded, Unwritten, Writer,
};
use super::landings::{arranged_at, before, Before, Landings};
use super::reads::{
    feed_rows, mapped_image, owners_records, runs_of, session_ended, stretches, LostTakeBack,
    NoUndo, OnEnd, Reader, Refusal, SHOT_RUN_CAP,
};
use super::record::{self, linked_to, standing_for, taken_back, Record, RecordLanding};
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
    /// `None` where none did, or where the one standing names its key's
    /// first landing in the draft at or before the earlier landing standing
    /// again — its marker put back, or on a baseless draft the landing
    /// beneath — that landing itself (skep #790) or one beneath it, which
    /// stands on with its record, and none was written.
    pub record: Option<Address>,
    /// The base restored — the pair read before the landing, address and
    /// extent — where the board records a base for the draft; `None` where
    /// the undo went by the draft's rows, a baseless document whose landing
    /// moved nothing.
    pub restored: Option<(Address, u64)>,
    /// The marker the draft carries again (skep #964).
    ///
    /// It is the one the draft carried before the landing, put back as it
    /// stood with its own `at`: an earlier landing's, or the one the draft's
    /// stage copied (P2). `None` where the draft carried none, the marker
    /// cleared, and where the undo went by the draft's rows, which carry no
    /// marker.
    pub marker: Option<MergeMarker>,
}

/// What a withdrawal answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawn {
    /// The draft the merge was taken out of, its words kept.
    pub draft: Address,
    /// The one write's commit position, its ack's `at`.
    pub position: u64,
    /// The replacing record's link, homed in its journal.
    ///
    /// It is written where a record of the merger's own stood for the marker
    /// taken out; `None` where none did, and none was written.
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
    /// It is written where the merger's own record of the landing the
    /// marker put back marks was taken back since that landing (the
    /// module's doc); `None` where it was not — the landing's record
    /// standing, or none of the merger's — and none was written.
    pub record: Option<Address>,
}

/// Puts a draft back as it stood before the landing standing in it (R6).
///
/// The landing is the write the draft's marker names, or for a baseless
/// draft the one standing by its rows ([`baseless_landing`]; skep #914). The
/// dispatch, the pre-landing read, the mapping, the typed position, the one
/// write and the record are the module's doc. `own_ack` is the position of
/// the caller's own last acknowledged write on the draft, the write typed
/// against it where it is past the landing's and the put-back's (P3's
/// editor rule); `None` types it against the later of those two (the
/// command's and an agent's).
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
/// - on a draft whose base record carries no marker, the feed walk's
///   refusals, then [`Refusal::NothingToUndo`] with [`NoUndo::Published`]
///   or [`NoUndo::TakenBack`], or [`Refusal::NoMerge`], nothing sent;
/// - for an undo by the marker, a marker naming no position as the
///   library's own fault; the pre-landing read's: [`Refusal::NothingToUndo`]
///   with [`NoUndo::Inherited`] where the draft did not exist before the
///   landing, nothing sent; [`Refusal::HistoryReclaimed`] where the board
///   no longer answers the position before the landing, nothing sent; its
///   other refusals, a position past the board's head among them as the
///   library's own fault, and an image whose positions reach the largest
///   ordinal as the board's; a draft recording no base before the landing,
///   or a marker there naming no position or no extent, as the library's
///   own faults; the feed walk's refusals past the landing; where a write
///   put the marker back since, the reads of the draft at the landing and
///   at that write, refused as the pre-landing read is, and the records'
///   reads over the two states, a run of either that is no content
///   I-address and a record mapping either past the largest ordinal the
///   board's faults, faced;
/// - on a baseless draft, the feed walk's refusals; where a plain row
///   follows a landing, the reads of the state before that landing and of
///   the draft at the row, refused as the pre-landing read is —
///   [`Refusal::HistoryReclaimed`] where the board no longer answers either,
///   nothing sent — with the records' reads over the two, and a run of
///   either that is no content I-address and a record mapping either past
///   the largest ordinal the board's faults, faced (SP-19); then
///   [`Refusal::NoMerge`] where no landing row stands, and
///   [`Refusal::NothingToUndo`] with [`NoUndo::TakenBack`] where every
///   landing was taken back, each with nothing sent; the pre-landing read's
///   where the walk read no state before the standing landing, a draft not
///   registered there the library's own fault; where a take-back of a
///   landing made over it put it back, the reads at the landing and at that
///   take-back, as an undo by the marker's; then the walk's reads for the
///   landing beneath it, refused alike;
/// - the records' reads' refusals at the head where none were read over C,
///   a run of C that is no content I-address, the board's fault, faced; a
///   record mapping C past the largest ordinal, the board's fault, faced
///   (SP-19); then [`Refusal::OverCap`] where C mapped is in more runs than
///   one write may name, counted on the runs the write sends, nothing sent,
///   and a run a record mapped that is no content I-address, the board's
///   fault, faced;
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
///   [`Refusal::WindowWithheld`] naming the document `withheld` names, and
///   a `withheld` naming no document this client parses as the board's
///   refusal verbatim (SP-18); [`Refusal::NeedsSignedSession`];
///   [`Refusal::NoSuchDocument`];
///   `source_not_registered`, `no_base_to_record`, `base_not_in_chain`,
///   `base_extent_too_large` and the runs' refusals as the library's own
///   faults, since it sends only the base, the marker and the runs it read,
///   mapped through the records the board served; a lost acknowledgment
///   asked again once under its id, and where the write's answer stays lost
///   — the re-ask's lost too, the death signal at the re-ask, or the board's
///   `500 internal_panic` — the read of the draft's rows past the typed
///   position and of the draft at the write's row (**The lost answer**), then
///   the write unconfirmed where no row shows it or the read fails, as
///   [`Refusal::Halt`] with a face saying it may have landed, how the
///   draft tells, and that an undo run again where it landed takes the
///   landing beneath it back too;
/// - the record's step's every refusal — its reads, a journal it finds
///   unable to take the record, its writes — as [`Refusal::Halt`] with a
///   face saying the merge is out of the draft — and an earlier landing's
///   merge back in it, where one stands again — and the record is not
///   written, the refusal its cause, the act standing.
///
/// The death signal under the merger's token, met at any step, is
/// [`Refusal::SessionEnded`]: up to and at the one write's first ask its
/// face says to run the undo again, nothing changed; at the write's re-ask
/// or its read back after a lost answer, that the write may have landed and
/// how the draft tells; at the record's, that the merge is out of the draft
/// with its record unwritten — an earlier landing's merge back in it, where
/// one stands again, which an undo run again takes back too — and nothing
/// more is written.
///
/// [`baseless_landing`]: super::baseless_landing
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
    let taking = match (meta.base.as_deref(), meta.merge.as_ref()) {
        (Some(_), Some(marker)) => by_marker(reader, draft, marker, meta.at)?,
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
        (None, _) => by_rows(reader, draft)?,
    };
    let Taking { taken, landing, restored, image, records, earlier, landed_before, put_back } =
        taking;
    // THE MAPPING: C's image through the records of every origin among its
    // runs, each in its owner's account, each run at its own spelling — the
    // one read the walk made over C and a state it compared with C, where
    // it made one (P4).
    let records = match records {
        Some(records) => records,
        None => owners_records(reader, &runs_of(image.runs())?)?,
    };
    let sent = mapped_image(&image, &records)?;
    let runs = capped_runs(&sent)?;
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
        &runs,
        as_of,
        earlier.as_ref().map(|e| (e.marker.head.as_str(), e.head_copied)),
        base_text.as_ref().map(|(base, copied)| (base.as_str(), *copied)),
        earlier.as_ref().map(|e| (sides.as_slice(), Some(e.at))),
        Some(&format!("{stem}.arrangement")),
    );
    writer.check_journal(journal, &format!("the merge cannot be taken out of {draft}"))?;
    let restores = earlier.as_ref().map(|e| e.at);
    let act = Act::Undo { landing, put_back, own_ack: own_ack.is_some(), earlier: restores };
    let position = send(&writer, &frame, draft, as_of, act)?;
    // The record is judged by the landing taken back and the one standing
    // again (**The record.**).
    let markers = Markers { taken: &taken, landing, earlier: landed_before };
    let record = replace_record(board, merger, kind, draft, &stem, journal, act, markers)?;
    let marker = earlier.map(|e| e.marker);
    Ok(Undone { draft: draft.clone(), position, record, restored, marker })
}

/// What an undo takes back: its landing and the state before it.
///
/// The dispatch yields it (the module's doc, **The dispatch**).
struct Taking {
    /// The landing's mark: the draft's marker, or on a baseless draft the
    /// mark its row makes.
    taken: MergeMarker,
    /// The landing's position.
    landing: u64,
    /// The base read before the landing, address and extent; `None` for a
    /// baseless draft.
    restored: Option<(Address, u64)>,
    /// C, the arrangement before the landing, as the board served it: each
    /// run under the chain that minted it.
    image: Image,
    /// The records a baseless draft's walk read over C and the latest state
    /// it compared with C, which map C as sent; `None` where it read none.
    records: Option<Vec<publication::Record>>,
    /// The marker the state before the landing carried, which the write
    /// puts back as it stood.
    earlier: Option<Restorable>,
    /// The position of the landing standing again once this one is taken
    /// back, by which the record is judged (**The record.**).
    ///
    /// It is the earlier landing whose marker the write puts back, never
    /// the one the draft's stage copied (P2), or on a baseless draft the
    /// landing that stood when this one was made; `None` where none does.
    landed_before: Option<u64>,
    /// The latest write that put the landing back since.
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

/// The latest write that put an undo's landing back since it was made.
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

impl PutBack {
    /// Returns the put-back at `back` of the landing at `landing`, judged.
    ///
    /// The draft is read through `/op-at` at the landing and at the
    /// put-back, and the two states, mapped through one read of the records
    /// of every origin among them, each in its owner's account, are kept
    /// where they are one (the module's doc, **The put-back**).
    ///
    /// # Errors
    ///
    /// The reads at the two positions, typed by `position_fault`; a run of
    /// either state that is no content I-address, the board's fault, faced;
    /// the records' reads' over the two states; a record mapping either past
    /// the largest ordinal, the board's fault, faced.
    fn judged(reader: &Reader<'_>, draft: &Address, landing: u64, back: u64) -> Result<PutBack, Refusal> {
        let landed = arranged_at(reader, draft, landing, "the landing's position")?;
        let put = arranged_at(reader, draft, back, "the position the merge was put back at")?;
        let state = [runs_of(landed.runs())?, runs_of(put.runs())?].concat();
        let records = owners_records(reader, &state)?;
        let kept = mapped_image(&landed, &records)? == mapped_image(&put, &records)?;
        Ok(PutBack { at: back, kept })
    }
}

/// Reads what an undo by the marker takes back (the module's doc).
///
/// It is the state before the landing at `marker`'s `at`, through the
/// pre-landing read, with the marker that state carried (**The dispatch**),
/// a marker whose `at` is `minted`, the draft's own mint, standing again
/// as no landing (P2), and the latest write that put `marker` back since
/// the landing, judged ([`PutBack::judged`]; **The put-back**).
///
/// # Errors
///
/// A marker naming no position, as the library's own fault;
/// [`Refusal::NothingToUndo`] with [`NoUndo::Inherited`] where the draft
/// did not exist before the landing; the pre-landing read's refusals; a
/// draft recording no base before the landing, or a marker there naming no
/// position or no extent, as the library's own faults; the feed walk's
/// refusals; the put-back's judgement's.
fn by_marker(
    reader: &Reader<'_>,
    draft: &Address,
    marker: &MergeMarker,
    minted: Option<u64>,
) -> Result<Taking, Refusal> {
    let at = marker.at.ok_or_else(|| {
        own_fault_face(
            "the marker names no position",
            format!("{draft}'s `doc_metadata` carries a merge with no `at`, which every marker the wire serves carries (wire.md §The response envelope)"),
        )
    })?;
    let (then, image) = match before(reader, draft, at, "the position before the landing")? {
        Before::Unregistered => {
            return Err(Refusal::NothingToUndo { draft: draft.clone(), why: NoUndo::Inherited })
        }
        Before::Stood { meta, image } => (meta, image),
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
    // The record is judged by the marker put back only where it marks a
    // landing: never the one a stage copied (P2).
    let landed_before = earlier.as_ref().map(|e| e.at).filter(|at| minted != Some(*at));
    // THE PUT-BACK (skep #964): the take-back and its undo alone moved the
    // words since the landing where the states at the two writes, mapped,
    // are one.
    let put_back = put_back_of(reader, draft, marker, at)?
        .map(|back| PutBack::judged(reader, draft, at, back))
        .transpose()?;
    Ok(Taking {
        taken: marker.clone(),
        landing: at,
        restored: Some(old),
        image,
        records: None,
        earlier,
        landed_before,
        put_back,
    })
}

/// Reads what an undo takes back on a draft with no recorded base.
///
/// It is the landing standing in the draft by its `set_arrangement` rows
/// (`Landings`; the module's doc, **The dispatch**): the state before it,
/// as the walk read it with the records it compared it through, else
/// through the pre-landing read; the latest take-back of a landing made
/// over it, which put it back, judged ([`PutBack::judged`]; **The
/// put-back**); and the landing that stood when it was made, which stands
/// again once it is taken back (**The record.**).
///
/// # Errors
///
/// The feed walk's refusals; the walk's reads where a plain row follows a
/// landing — the state before the landing and the draft at the row,
/// [`Refusal::HistoryReclaimed`] where the board no longer answers either,
/// their other refusals and faults as the pre-landing read's, the records'
/// reads' refusals over the two, a record mapping either past the largest
/// ordinal the board's fault, faced; [`Refusal::NoMerge`] where no landing
/// row stands, and [`Refusal::NothingToUndo`] with [`NoUndo::TakenBack`]
/// where every landing was taken back, each with nothing sent; then the
/// pre-landing read's where the walk read no state before the landing, the
/// put-back's judgement's, and the walk's reads for the landing beneath.
fn by_rows(reader: &Reader<'_>, draft: &Address) -> Result<Taking, Refusal> {
    let landings = Landings::read(reader, draft)?;
    let Some(mut standing) = landings.standing(reader)? else {
        return Err(if landings.any() {
            Refusal::NothingToUndo { draft: draft.clone(), why: NoUndo::TakenBack }
        } else {
            Refusal::NoMerge { draft: draft.clone() }
        });
    };
    let at = standing.at;
    let (image, records) = match standing.before.take() {
        Some((image, records)) => (image, Some(records)),
        None => (landings.stood_before(reader, at)?, None),
    };
    let put_back =
        standing.put_back.map(|back| PutBack::judged(reader, draft, at, back)).transpose()?;
    let beneath = landings.beneath(reader, &standing)?;
    Ok(Taking {
        taken: standing.mark,
        landing: at,
        restored: None,
        image,
        records,
        earlier: None,
        landed_before: beneath.map(|b| b.at),
        put_back,
    })
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
/// position through `/op-at`; the one write sends the image back whole as
/// read — each run under the chain that minted it, no record read and
/// nothing mapped (the module's doc, **The mapping**) — with the recorded
/// base re-sent unmoved — address and extent as read — and no `merge`,
/// typed against that position, so the marker is cleared and the draft's
/// words and base stay as they are; an inherited marker is taken out the
/// same way. The record and the journal are as [`undo`]'s.
///
/// # Errors
///
/// In this order:
///
/// - the draft's `doc_metadata` read's refusals — [`Refusal::Unreadable`],
///   [`Refusal::NoSuchDocument`] — and [`Refusal::Published`] for a
///   published document;
/// - [`Refusal::NoMerge`] where the draft carries no marker, nothing sent —
///   a draft with no recorded base carries none even where a merge landed
///   in it, a landing [`undo`] takes back by the draft's rows;
/// - the image read's refusals at the read's position, and an image whose
///   positions reach the largest ordinal, the board's fault, faced;
/// - [`Refusal::OverCap`] where the image is in more runs than one write
///   may name, nothing sent; then a run of it that is no content
///   I-address, the board's fault, faced;
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
    let Some(marker) = meta.merge.as_ref() else {
        return Err(Refusal::NoMerge { draft: draft.clone() });
    };
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
    // THE ONE POSITION: the image as of the metadata's read, sent back as
    // read — no record is read and none maps it.
    let image = reader.imaged(draft, Some(as_of))?.into_image()?;
    let runs = capped_runs(&mapped_image(&image, &[])?)?;
    let stem = format!("withdraw:{draft}:{as_of}");
    let base_text = base.0.to_string();
    let frame = frames::set_arrangement(
        &draft.to_string(),
        &runs,
        as_of,
        None,
        Some((base_text.as_str(), base.1)),
        None,
        Some(&format!("{stem}.arrangement")),
    );
    writer.check_journal(journal, &format!("the merge cannot be taken out of {draft}"))?;
    let position = send(&writer, &frame, draft, as_of, Act::Withdraw)?;
    // The record is judged by the marker taken out, as an undo's is; one
    // naming no position bounds none.
    let landing = marker.at.unwrap_or(u64::MAX);
    let markers = Markers { taken: marker, landing, earlier: None };
    let record =
        replace_record(board, merger, kind, draft, &stem, journal, Act::Withdraw, markers)?;
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
/// - [`Refusal::NothingToUndo`] with [`NoUndo::Remarked`] — the draft
///   carrying a marker, or its rows past the withdrawal putting the cleared
///   marker back since — or with [`NoUndo::Published`], nothing sent;
/// - the read of the draft's words at the first read's position, its
///   refusals, and a run of them that is no content I-address, the board's
///   fault, faced; the records' reads' refusals at the head; a record
///   mapping the words past the largest ordinal, the board's fault, faced
///   (SP-19); then [`Refusal::OverCap`] where the words mapped are in more
///   runs than one write may name, counted on the runs the write sends,
///   nothing sent;
/// - a journal named that cannot take the record, as [`undo`]'s, nothing
///   sent (P13);
/// - the one write's, as [`undo`]'s — `arrangement_moved` saying the draft
///   changed since the merge was taken out, or since the caller's last
///   write past it — and `marker_not_restorable`, the draft published since
///   it was read, as [`Refusal::Halt`] saying nothing was changed;
/// - the record's step's every refusal, as [`Refusal::Halt`] saying the
///   merge is back in the draft and the record is not written, the refusal
///   its cause.
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
    let Before::Stood { meta: then, image: stood } = before(reader, draft, withdrawal, "the position before the withdrawal")? else {
        return Err(none());
    };
    let pair = |m: &Metadata| m.base.as_deref().and_then(parse_address).zip(m.base_copied);
    let (Some(cleared), Some(base)) = (then.merge.clone(), pair(&after)) else { return Err(none()) };
    if pair(&then).as_ref() != Some(&base) || mapped_image(&stood, &[])? != mapped_image(&left, &[])? {
        return Err(none());
    }
    let rows = withdrawal_rows(reader, draft, withdrawal, cleared.at)?;
    if !rows.withdrew {
        return Err(none());
    }
    // NOTHING TO UNDO: the marker first, then a put-back of the cleared
    // marker since, then the base.
    if meta.merge.is_some() || rows.put_back {
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
    let image = reader.imaged(draft, Some(read_at))?.into_image()?;
    let records = owners_records(reader, &runs_of(image.runs())?)?;
    let runs = capped_runs(&mapped_image(&image, &records)?)?;
    // THE TYPED POSITION (P3): the withdrawal's, or the caller's own last
    // ack where it is later.
    let as_of = own_ack.map_or(withdrawal, |own| own.max(withdrawal));
    let stem = format!("unwithdraw:{draft}:{withdrawal}:{read_at}");
    let base_text = base.0.to_string();
    let sides: Vec<&str> = cleared.marker.sides.iter().map(String::as_str).collect();
    let frame = frames::set_arrangement(
        &draft.to_string(),
        &runs,
        as_of,
        Some((cleared.marker.head.as_str(), cleared.head_copied)),
        Some((base_text.as_str(), base.1)),
        Some((&sides, Some(cleared.at))),
        Some(&format!("{stem}.arrangement")),
    );
    writer.check_journal(journal, &format!("the merge cannot be put back into {draft}"))?;
    let act = Act::Unwithdraw { withdrawal, own_ack: own_ack.is_some(), marker: cleared.at };
    let position = send(&writer, &frame, draft, as_of, act)?;
    let record = restore_record(board, merger, kind, draft, &cleared, &stem, journal)?;
    Ok(Unwithdrawn { draft: draft.clone(), position, record })
}

/// The draft's feed rows a withdrawal's undo reads (the module's doc).
struct WithdrawalRows {
    /// Whether the withdrawal's row names a base and no merge.
    ///
    /// The row is the `set_arrangement` row at the withdrawal's position.
    withdrew: bool,
    /// Whether a `set_arrangement` row past the withdrawal put back the
    /// marker it cleared: its `merge` names that marker's `at`, which a
    /// landing's row never names (wire.md §The change feed).
    put_back: bool,
    /// The member the latest `publish` row past that position names first.
    ///
    /// `None` where no such row stands; `Some(None)` where it names none
    /// this client can read.
    published: Option<Option<Address>>,
}

/// Returns the draft's feed rows at the withdrawal's position and past it.
///
/// `cleared` is the `at` of the marker the withdrawal cleared, as the state
/// before it carried it; a put-back is a row past the withdrawal whose
/// `merge` names it, `None` naming none. It walks the supplement under the
/// draft (`drafts=true`), as [`latest_ending_row`] does, from the position
/// just below the withdrawal, so its pages hold the rows at the withdrawal
/// and past it alone, whatever the draft was written before.
///
/// # Errors
///
/// The feed walk's (`feed_rows`), through `reader`.
fn withdrawal_rows(
    reader: &Reader<'_>,
    draft: &Address,
    withdrawal: u64,
    cleared: Option<u64>,
) -> Result<WithdrawalRows, Refusal> {
    let mut rows = WithdrawalRows { withdrew: false, put_back: false, published: None };
    let since = withdrawal.saturating_sub(1);
    feed_rows(reader, &draft.to_string(), true, since, |row| {
        let Some(at) = row["at"].as_u64() else { return };
        match row["op"].as_str() {
            Some("set_arrangement") if at == withdrawal => {
                rows.withdrew = row["base"].is_string() && row["merge"].is_null();
            }
            Some("set_arrangement") if at > withdrawal => {
                let names = row["merge"]["at"].as_u64();
                rows.put_back |= cleared.is_some() && names == cleared;
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
    /// landing's marker back since, whether `own_ack` was given, and the
    /// position of the earlier marker the write puts back, where it puts one
    /// back.
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
        earlier: Option<u64>,
    },
    Withdraw,
    /// A withdrawal's undo, its words as an undo's are.
    ///
    /// It carries the withdrawal's position, whether `own_ack` was given,
    /// and the position of the marker the write puts back.
    Unwithdraw {
        withdrawal: u64,
        own_ack: bool,
        marker: u64,
    },
    /// The `history` module's restore.
    ///
    /// Its write is typed at the `as_of` its caller gives, which may be a
    /// state of the caller's own and not the restore's read, so its words
    /// ask a read and a restore typed at it: the same call at the same state
    /// meets the same refusal.
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

    /// The act's one write, as a step a session's end can meet.
    fn during(self) -> &'static str {
        match self {
            Act::Undo { .. } => "taking the merge back out of the draft",
            Act::Withdraw => "taking the merge out of the draft",
            Act::Unwithdraw { .. } => "putting the merge back into the draft",
            Act::Restore => "restoring the draft",
        }
    }

    /// The act whose one write's answer was lost, as its way on names it.
    fn lost(self) -> LostTakeBack {
        match self {
            Act::Undo { landing, earlier, .. } => LostTakeBack::Undo { landing, earlier },
            Act::Withdraw => LostTakeBack::Withdraw,
            Act::Unwithdraw { marker, .. } => LostTakeBack::Unwithdraw { at: marker },
            Act::Restore => LostTakeBack::Restore,
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

/// Returns `image`'s runs as the write of a state the board held spells them.
///
/// It is the one spelling of the take-backs' writes and of the restore's
/// (the `history` module). Each run is `frames::shot_run` of the run's own
/// first I-address in its one spelling, its width, and its `origin`: the
/// document that minted it, version component and all — for a deposit
/// naming a member, the member (wire.md §Arrangement, `publish`: "`origin`
/// must be the document that minted the run's addresses"). A run minted
/// under a member's chain is written as itself, never as the trunk's
/// position of the same ordinal.
///
/// # Errors
///
/// A run whose first I-address is no content I-address, the board's fault,
/// faced: an image is a board's answer, or one mapped from it.
pub fn written_runs(image: &Image) -> Result<Vec<Value>, Halt> {
    image
        .runs()
        .iter()
        .map(|run| {
            let named = format!("{}.{}", run.prefix, run.first);
            let spelled = parse_address(&named)
                .filter(|a| a.subspace() == Some(&content_subspace()))
                .and_then(|a| Some((document_of(&a)?, a)));
            let (origin, i_start) = spelled.ok_or_else(|| {
                Halt::face(
                    "an image run is no content I-address",
                    format!("`{named}` is no address in the content subspace"),
                    "this is a board fault; nothing was written",
                )
            })?;
            Ok(frames::shot_run(&origin.to_string(), &i_start.to_string(), run.width))
        })
        .collect()
}

/// Returns `sent`'s runs as a take-back's one write spells them, capped.
///
/// The count is of the runs the write names, `sent`'s own: a trunk's run
/// and a member's beside it are two, however the core's runs join them.
///
/// # Errors
///
/// [`Refusal::OverCap`] where `sent` is in more runs than one write may
/// name, before any is spelled; then [`written_runs`]'s.
fn capped_runs(sent: &Image) -> Result<Vec<Value>, Refusal> {
    let runs = sent.runs().len();
    if runs > SHOT_RUN_CAP {
        return Err(Refusal::OverCap { runs, cap: SHOT_RUN_CAP });
    }
    Ok(written_runs(sent)?)
}

/// Sends the one write, answering its position.
///
/// The frame goes under the merger's token, unsigned — a draft's
/// `set_arrangement` takes no `attest`, so no head is read — through
/// [`send_write`], which asks it again once under its id where its answer
/// is lost, and its answer is judged by [`judge`]. Where the write's answer
/// is lost — every answer of the re-ask but a document, and the board's
/// `500 internal_panic`, which is no verdict on a write (wire.md §HTTP
/// status codes) — the draft's own rows past `as_of` are read for the
/// write's (`landed_at`; the module's doc, **The lost answer**), and a
/// write no row confirms is answered unconfirmed ([`OnEnd::Unconfirmed`]).
///
/// # Errors
///
/// As [`undo`]'s one write's.
fn send(writer: &Writer<'_>, frame: &Value, draft: &Address, as_of: u64, act: Act) -> Result<u64, Refusal> {
    let during = act.during();
    let unconfirmed = OnEnd::Unconfirmed(act.lost());
    let Asked { answer, again } = send_write(writer.board, writer.merger.token, frame);
    let lost = match answer {
        Ok(Answer::Document(v)) => return judge(&v, frame, draft, as_of, act),
        // A dead token's write runs as a guest's: the first ask landed
        // nothing, its re-ask may follow one that did.
        Ok(Answer::Closed) if !again => {
            return Err(session_ended(during, writer.reader.on_end()))
        }
        Ok(Answer::Closed) => return Err(session_ended(during, unconfirmed)),
        Err(h) if again || answer_lost(&h) => h,
        Err(h) => return Err(h.into()),
    };
    let read_back = landed_at(&writer.reader, draft, as_of, frame);
    let cause = match read_back {
        Ok(Some(at)) => return Ok(at),
        Ok(None) => format!("{lost}; and no row of the draft's past the position the write was typed against, {as_of}, is the write's"),
        Err(Refusal::SessionEnded(_)) => return Err(session_ended(during, unconfirmed)),
        Err(e) => format!("{lost}; and the read of the draft's rows back: {e}"),
    };
    Err(Halt::face(
        format!("the write may have landed, and its record is not written: its answer was lost while {during}"),
        cause,
        act.lost().way_on(),
    )
    .into())
}

/// Returns whether `h` leaves a write's answer lost, whatever it did.
///
/// It is a dial fault, and the board's `500 internal_panic`: the write may
/// have committed before the panic, its acknowledgment never memoized
/// (wire.md §HTTP status codes; §Correlation and idempotency).
fn answer_lost(h: &Halt) -> bool {
    match h {
        Halt::Dial(_) => true,
        Halt::Refused(r) => r.status == 500 && r.code == "internal_panic",
        Halt::Halt(_) | Halt::Blocked(_) => false,
    }
}

/// Returns the position a take-back's write landed at, its answers lost.
///
/// The write was typed against `as_of`, so where it landed it is the first
/// write past `as_of` to change the draft's arrangement: the first row of
/// the draft's own feed past `as_of` naming it with an arrangement op — on
/// the supplement, `drafts=true` (wire.md §The change feed) — is read, and
/// it is the write's where it is a `set_arrangement` row carrying the
/// frame's two terms, the base it records and its merge beside its head,
/// and where the draft as of it holds the frame's runs as the frame spells
/// them, I-adjacent pieces of one chain joined as every take-back joins
/// what it sends (`mapped_image`): the end the write meant. `None` where it
/// is not — the write never landed, or is still on its way, which no read
/// tells apart — and where no such row stands.
///
/// # Errors
///
/// The feed walk's (`feed_rows`) and the read of the draft at the row
/// (`arranged_at`), each as itself; a run of the state read there that is
/// no content I-address, the board's fault, faced.
fn landed_at(
    reader: &Reader<'_>,
    draft: &Address,
    as_of: u64,
    frame: &Value,
) -> Result<Option<u64>, Refusal> {
    const ARRANGING: [&str; 7] = [
        "insert",
        "delete",
        "copy",
        "reinstate",
        "rearrange",
        "set_arrangement",
        "publish",
    ];
    let text = draft.to_string();
    let mut first: Option<Value> = None;
    feed_rows(reader, &text, true, as_of, |row| {
        let names = row["docs"]
            .as_array()
            .is_some_and(|d| d.iter().any(|x| *x == text));
        let arranges = row["op"].as_str().is_some_and(|op| ARRANGING.contains(&op));
        if first.is_none() && names && arranges {
            first = Some(row.clone());
        }
    })?;
    let Some(row) = first else { return Ok(None) };
    // The row's terms as the frame's write records them: the base's
    // address, and the merge beside the head with the position it names.
    let merge = frame["merge"].as_object().map(|m| {
        let mut term = serde_json::json!({"sides": m["sides"], "head": frame["head"]["at"]});
        if let Some(at) = m.get("at") {
            term["at"] = at.clone();
        }
        term
    });
    let terms = row["base"] == frame["base"]["at"] && row["merge"] == merge.unwrap_or(Value::Null);
    let Some(at) = row["at"]
        .as_u64()
        .filter(|_| row["op"] == "set_arrangement" && terms)
    else {
        return Ok(None);
    };
    let held = mapped_image(
        &arranged_at(reader, draft, at, "the position the take-back's row names")?,
        &[],
    )?;
    Ok((Value::Array(written_runs(&held)?) == frame["runs"]).then_some(at))
}

/// Judges a `set_arrangement`'s answer `v` to `frame`, answering the write's
/// position.
///
/// `frame` was typed against `as_of` for `act`; its refusals are mapped
/// as the module's doc lists them, each the same at every act but
/// `arrangement_moved`, whose words are the act's own ([`undo_moved`] for
/// an undo's) — an undo with no `own_ack` saying it can no longer land, and
/// one typed past its landing naming `as_of` as the caller's last write,
/// and the landing's position beside it.
///
/// # Errors
///
/// As [`undo`]'s one write's: `arrangement_moved` as the board's verdict in
/// the person's words; [`Refusal::WindowWithheld`] where the board's
/// `withheld` names in `site.addr` a document this client parses, naming
/// beside it its words in the state `frame` sends ([`refused_runs`]) — a
/// `withheld` naming none is the board's refusal verbatim (SP-18);
/// [`Refusal::NeedsSignedSession`], [`Refusal::NoSuchDocument`],
/// [`Refusal::NotOwner`] and [`Refusal::Published`] by their codes; the
/// refusals of what the library composed as its own fault; the board's
/// other refusals verbatim; an answer that is no acknowledgment and no
/// rejection, faced.
pub(crate) fn judge(
    v: &Value,
    frame: &Value,
    draft: &Address,
    as_of: u64,
    act: Act,
) -> Result<u64, Refusal> {
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
                Act::Withdraw => format!("{draft} changed since it was read{} — nothing was changed; run this again, which reads the draft as it stands", since("read")),
                Act::Restore => format!("{draft} changed since it was read{} — nothing was changed; read the draft as it stands, then restore again typed at that read", since("read")),
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
        "marker_not_restorable" if matches!(act, Act::Unwithdraw { .. } | Act::Undo { earlier: Some(_), .. }) => Refusal::Halt(Halt::Refused(Refused {
            status: 200,
            code: r.code().to_string(),
            detail: Some(format!("{draft} was published since it was read, and a publication of the draft ends the merge it carried — nothing was changed; nothing to undo: a version stands, and the way back is to publish the older text again")),
            op: r.op().map(str::to_string),
            body: v.clone(),
        })),
        "withheld" => match site {
            Some(origin) => {
                let positions = refused_runs(frame, &origin).map(stretches).unwrap_or_default();
                Refusal::WindowWithheld { origin, positions }
            }
            // The board names no document this client parses, and none is
            // typed in its place: the wire names one on every `withheld`
            // (wire.md §Rejections), and never the draft, whose own words
            // the source gate never consults. It rides verbatim (SP-18).
            None => Refusal::Halt(r.refused(v)),
        },
        "signed_session_required" => Refusal::NeedsSignedSession,
        "doc_not_registered" => Refusal::NoSuchDocument(draft.clone()),
        "not_owner" => Refusal::NotOwner { draft: draft.clone() },
        "published_target" => Refusal::Published { doc: draft.clone() },
        // The base is the one the draft recorded, read, and a head rides
        // only beside a marker put back, as read; the runs are the draft's
        // own image, each spelled under the chain that minted it, mapped
        // through the records the board served and no more than one write
        // may name: a refusal of them is this library's own fault.
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

/// Returns `frame`'s runs in V order, each as whether its origin is
/// `origin`, the document the board's `withheld` names, and its width.
///
/// The runs are a take-back's or a restore's one write's, each as
/// [`written_runs`] spells it — its `origin` the document that minted it,
/// its `width` a decimal string — so each reads back; `None` where one does
/// not, so a refusal names no position where it cannot name the right one.
fn refused_runs(frame: &Value, origin: &Address) -> Option<Vec<(bool, u64)>> {
    frame["runs"]
        .as_array()?
        .iter()
        .map(|run| {
            let minted = parse_address(run["origin"].as_str()?)?;
            let width = run["width"].as_str()?.parse().ok()?;
            Some((minted == *origin, width))
        })
        .collect()
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

/// The landings a take-back judges its record by.
///
/// They are the module's doc's **The record**: an undo's — by the marker,
/// or on a baseless draft by its rows — and a withdrawal's.
#[derive(Clone, Copy)]
struct Markers<'a> {
    /// The mark of the landing the act takes out: the draft's marker, or a
    /// baseless draft's standing landing's.
    taken: &'a MergeMarker,
    /// The landing's position, the taken mark's `at`.
    ///
    /// It is the largest position, bounding none, where the board serves no
    /// `at`.
    landing: u64,
    /// The position of the earlier landing standing again once the act
    /// lands.
    ///
    /// It is the one whose marker the undo puts back, or on a baseless
    /// draft the one that stood when the landing taken back was made.
    /// `None` where none stands again, where the marker put back is the one
    /// the draft's stage copied, which marks no landing in it (P2), and for
    /// a withdrawal, which puts none back.
    earlier: Option<u64>,
}

/// Writes the replacing record, answering its link where one is written.
///
/// It is the module's doc's record: of the merger's own records of the
/// kind linked to the draft ([`linked_to`]), the one standing for the
/// landing `markers` names taken out ([`standing_for`]) — written again
/// with `landed` none and `replaces` its link, under the act's stem.
/// `None`, nothing written, where no record stands for it, or where that
/// record names its key's first landing in the draft at or before the
/// earlier landing standing again: that landing itself (skep #790), or one
/// it went over, which stands on beneath it — the write taken back being a
/// later landing of the key, which writes no record of its own. It reads
/// and writes through a writer of its own over `board` as `merger`, built
/// for the step after the act's one write: a session's end at any of its
/// reads or writes leaves the act standing with its record unwritten
/// ([`OnEnd::TakenOut`], or [`OnEnd::EarlierBack`] where an earlier landing
/// stands again), and so does every other refusal of the step, faced so.
///
/// # Errors
///
/// Every refusal of the step — the read of the merger's records
/// ([`linked_to`]) and the record's writes (`Writer::write_record`) — faced
/// as the act standing with its record unwritten, the refusal its cause
/// ([`Unrecorded::faced`]); the session's end, [`Refusal::SessionEnded`],
/// faced for the step after the act's write.
#[allow(clippy::too_many_arguments)]
fn replace_record(
    board: &Board,
    merger: Merger<'_>,
    kind: &Address,
    draft: &Address,
    stem: &str,
    journal: Option<&Address>,
    act: Act,
    markers: Markers<'_>,
) -> Result<Option<Address>, Refusal> {
    let Markers { taken, landing, earlier } = markers;
    let on_end = if earlier.is_some() { OnEnd::EarlierBack } else { OnEnd::TakenOut };
    let writer = Writer::new(board, merger, on_end);
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
    let own = linked_to(&writer.reader, kind, draft, merger.account)
        .map_err(|e| Unrecorded::from(e).faced(&owed))?;
    let Some(current) = standing_for(&own, draft, taken, landing) else { return Ok(None) };
    // The record names its key's first landing in the draft (skep #790): at
    // or before the landing standing again, that first landing stands on
    // beneath the write taken back, and the record with it.
    let beneath = matches!(
        (&current.record.landed, earlier),
        (Some(RecordLanding::Draft { position, .. }), Some(at)) if *position <= at
    );
    if beneath {
        return Ok(None);
    }
    let current = current.record;
    let record = Record {
        landed: None,
        claims: Vec::new(),
        replaces: current.link.clone(),
        by: record::by(),
        link: None,
        ..current
    };
    writer
        .write_record(kind, &record, draft, stem, journal, &owed)
        .map(Some)
        .map_err(|e| e.faced(&owed))
}

/// Writes the record of a withdrawal's undo (skep #870; the module's doc).
///
/// It answers the record's link where one is written. Of the merger's own
/// records of the kind linked to the draft ([`linked_to`]), the landing's
/// record and the take-back of it made since the landing are those
/// [`taken_back`] answers for the `cleared` marker at its `at`; the record
/// written is that landing's record again, `replaces` the take-back's link,
/// under `stem`. `None` where either is missing, nothing written. It reads
/// and writes through a writer of its own built for the step after the
/// act's one write ([`OnEnd::PutBack`]), every refusal of the step leaving
/// the act standing with its record unwritten.
///
/// # Errors
///
/// As [`replace_record`]'s, faced for the merge put back.
fn restore_record(
    board: &Board,
    merger: Merger<'_>,
    kind: &Address,
    draft: &Address,
    cleared: &Restorable,
    stem: &str,
    journal: Option<&Address>,
) -> Result<Option<Address>, Refusal> {
    let writer = Writer::new(board, merger, OnEnd::PutBack);
    let owed = |why: Unwritten, cause: String| {
        Halt::face(
            format!("the merge is back in {draft}, and the record of the withdrawal's undo is not written: {}", why.reason()),
            cause,
            OnEnd::PutBack.act(),
        )
    };
    let own = linked_to(&writer.reader, kind, draft, merger.account)
        .map_err(|e| Unrecorded::from(e).faced(&owed))?;
    let Some((landing, take_back)) = taken_back(&own, draft, &cleared.marker, cleared.at) else {
        return Ok(None);
    };
    let record =
        Record { replaces: Some(take_back.link), by: record::by(), link: None, ..landing.record };
    writer
        .write_record(kind, &record, draft, stem, journal, &owed)
        .map(Some)
        .map_err(|e| e.faced(&owed))
}
