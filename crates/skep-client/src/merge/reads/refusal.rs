//! Every refusal a merge's acts can meet (the merge record's §7).
//!
//! [`Refusal`] is the one error of the composition, the landing, the undo,
//! the withdrawal and its undo, and the restore; [`NoUndo`] says why an undo
//! has nothing to take back. How a session's end is answered is the `reads`
//! module's doc.

use std::fmt;

use skep_address::Address;

use crate::halt::Halt;
use crate::merge::windows::{Misfit, WindowPart};
use crate::publication::SupersedeCause;

use super::inputs::Side;

// ── the refusals ──────────────────────────────────────────────────────────

/// Every refusal the reads and the landing can meet.
///
/// The merge record's §7 names them ("Its errors"), each that answers a
/// wire code named for the code; the session's end under the caller's
/// token is [`Refusal::SessionEnded`]; the library's own faults and the
/// board's other refusals ride [`Refusal::Halt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A side whose base the library cannot read, refused before any `image`.
    ///
    /// It is a member of another document, the bare document itself or an
    /// address within a member, a fork in the document's own tree — the
    /// document, a member of its chain or an address within either — a
    /// draft of an account other than the trunk owner's, a draft the board
    /// records no base for — never staged, or minted by `fork` or
    /// `create_new_document` — or whose recorded base lies in another
    /// document, or a fork the board records neither a base nor a source
    /// for, or whose recorded base, else source, lies in another document —
    /// a staged fork published as an edition of its own among them
    /// (decision 15; no interim).
    BaseUnknown(Side),
    /// A fork side that lies in the trunk owner's own account.
    ///
    /// A fork is another account's document (§1.2 shape (4), case (j)),
    /// its words kept as windows onto it; the owner's own draft is the
    /// draft side (shape (2)), whose words the shot re-mints as the
    /// document's own. So a document of the owner's account named as a fork
    /// — a draft the owner staged from a version, its `source` in the chain
    /// — is refused after the trunk's metadata and before any other read,
    /// to be named as the draft side instead. The account is compared
    /// exactly: a sub-account's or an agent's document is another account's.
    ForkOfOwner {
        /// The fork side's address.
        fork: Address,
    },
    /// A side begun before the document's first version whose base cannot
    /// be read, refused before any `image`.
    ///
    /// Its base is the document's own arrangement from before that version
    /// (PUB-2.66), and either no version of the document stands yet, so
    /// there is nothing to merge onto — the editor's shell refuses a side
    /// so, `hop` none, before it composes — or the board serves no count of
    /// that arrangement, its `doc_metadata` carrying no `own_count` (an
    /// older board), which is where the composition refuses. The side is a
    /// draft staged from the bare document, a fork taken from it, or a side
    /// whose line of recorded bases passes a member published from it once
    /// version 1 stood (its daughter `D.1.k`, recorded against `D`).
    BareSource {
        /// The side whose line ends at the document.
        side: Side,
        /// Where the side's line ends: the bare document.
        source: Address,
        /// The member on the side's line whose recorded base is the
        /// document — the side itself where it is that member; `None` where
        /// the side's own base or source is the document.
        hop: Option<Address>,
    },
    /// A hop on a side's line of recorded bases the board records no parent
    /// for, refused before any `image` (the owner's ruling of 2026-11-02: a
    /// version tree takes a daughter's parent from the base the board
    /// recorded, never from its address).
    ///
    /// The hop is a member below the trunk whose `doc_metadata` serves
    /// neither `shot_base` nor `source` — one a build before the board
    /// recorded a shot's base minted. Its address need not name the member
    /// it was published against, so no base is derived through it.
    HopUnrecorded {
        /// The side whose line passes the hop.
        side: Side,
        /// The member the board records no parent for.
        hop: Address,
    },
    /// A base the caller named for a fork side, refused before any read.
    ///
    /// A fork's base is derived from where the board records it standing —
    /// its recorded base, else its source — never the caller's to name (the
    /// fork-source design record, decision 8): a named one contradicts the
    /// substrate's fact and is refused rather than honoured.
    ForkBaseNamed {
        /// The fork side's address.
        fork: Address,
        /// The base the caller named.
        base: Address,
    },
    /// A base the caller named beside a draft side that is not the one the
    /// board's records derive, refused before any `image`.
    ///
    /// A draft's anchor is the base the board records for it
    /// (`doc_metadata`'s `base`), and the merge's base is derived from it up
    /// the recorded bases as for every side; a named one is taken only
    /// where it equals that, so naming the base never moves what a merge
    /// composes against — a wrong guess is refused, never composed against.
    DraftBaseDisagrees {
        /// The draft side.
        side: Side,
        /// The base the caller named.
        named: Address,
        /// The base the board's records derive.
        served: Address,
    },
    /// A base the caller named beside member sides alone that is not the
    /// one the board's recorded bases derive, refused before any `image`.
    ///
    /// It is the rule [`Refusal::DraftBaseDisagrees`] keeps beside a draft:
    /// naming the base never moves what a merge composes against. A merge
    /// record names its base so at [`record::verify`], and a record composed
    /// over another base than the records derive is refused here, never
    /// verified against it.
    ///
    /// [`record::verify`]: super::record::verify
    NamedBaseDisagrees {
        /// The base the caller named.
        named: Address,
        /// The base the board's recorded bases derive.
        served: Address,
    },
    /// Two draft sides: not a merge shape.
    ///
    /// The shot admits one draft, so the way out is to shoot one (§1.2 shape
    /// (3)).
    TwoDrafts,
    /// `withheld` on the document named.
    ///
    /// It is a document an act reads before its first write that the reader
    /// may not read, so nothing of the act is written: at the composition the
    /// trunk, the head, the base or a side; at the shot a run's origin its
    /// values are read through; at the draft landing the draft landed into;
    /// at the undo and the withdrawal the draft taken back. It is as well
    /// the origin of a `withheld` item a value read met: a run a readable
    /// side windows from a document the reader may not read, which the board
    /// masks at its own position (wire.md §Value encodings). Its words name
    /// the document and the code alone, the same at every act; the embedder
    /// says what the act did (SP-10).
    ///
    /// Where the reads are a merge record's recomputation, [`record::verify`]
    /// answers [`Verdict::Unreadable`] naming the document instead: the
    /// verdict withheld (D14).
    ///
    /// [`record::verify`]: super::record::verify
    /// [`Verdict::Unreadable`]: super::record::Verdict::Unreadable
    Unreadable(Address),
    /// `doc_not_registered` on the document named.
    NoSuchDocument(Address),
    /// `image_too_large` down to a region of one position.
    ///
    /// The document's runs cannot be imaged, `runs_seen` of them counted
    /// before the floor (§8's measurement, reported).
    TooFragmented {
        /// The document imaged.
        doc: Address,
        /// The runs the parts that answered carried.
        runs_seen: usize,
    },
    /// `history_busy` on a read at a position, past the bounded retries.
    HistoryBusy,
    /// `history_reclaimed` on a read at the one position P: the board no
    /// longer answers P, and nothing is read at another position in its
    /// place (skep #762).
    ///
    /// Where P is a position a merge record names, [`record::verify`]
    /// answers [`Verdict::Unreadable`] instead: the verdict withheld
    /// (skep #761).
    ///
    /// [`record::verify`]: super::record::verify
    /// [`Verdict::Unreadable`]: super::record::Verdict::Unreadable
    HistoryReclaimed {
        /// The position refused.
        at: u64,
        /// The oldest position the board still answers, where it said.
        floor: Option<u64>,
    },
    /// `beyond_head` on a read at a position past the board's head.
    ///
    /// The board has committed no position as late as `at`, and nothing is
    /// read at another position in its place (wire.md §Reading history).
    BeyondHead {
        /// The position refused.
        at: u64,
        /// The board's committed head, where it said.
        head: Option<u64>,
        /// The document a merge record names `at` for.
        ///
        /// It is the record's draft side, or the draft it landed in, where
        /// [`record::verify`] read a position the record names (skep #761);
        /// `None` where the position is the caller's — a draft side's named
        /// position, or the one a composition or a landing read at.
        ///
        /// [`record::verify`]: super::record::verify
        recorded: Option<Address>,
    },
    /// `not_a_position` on a read at a number inside one commit.
    ///
    /// No answer carries such a number, and nothing is read at another
    /// position in its place (wire.md §Reading history).
    NotAPosition {
        /// The position refused.
        at: u64,
        /// The greatest position at or below `at`, where the board said.
        nearest: Option<u64>,
        /// The document a merge record names `at` for.
        ///
        /// As [`Refusal::BeyondHead`]'s: `None` where the position is the
        /// caller's.
        recorded: Option<Address>,
    },
    /// `fork_base_moved` on the draft landing: `into` is a FORK — a document
    /// the board records no base for, born sharing a published version, its
    /// `source` — and the merge was composed on another head than that
    /// source, which a landing would make false (wire.md §Rejection codes).
    ///
    /// The way out is a fresh fork from the head, landed into.
    ForkBaseMoved {
        /// The fork landed into.
        fork: Address,
        /// The source the board records for it, `site.addr`.
        source: Address,
        /// The head the merge was composed on.
        head: Address,
    },
    /// `base_not_in_chain` on the draft landing: `into` is a draft of
    /// another document — its recorded base lies in a chain the head is no
    /// member of (wire.md §Rejection codes).
    BaseNotInChain {
        /// The draft landed into.
        into: Address,
        /// The head the merge was composed on.
        head: Address,
    },
    /// `withheld` on a write naming an origin the merger may not read.
    ///
    /// The write is the shot, the draft landing's one write, the undo's or
    /// the withdrawal's, the origin a window one of its runs names that the
    /// source gate refuses (§7, the shot), and nothing of the act is written.
    /// Its words name the origin and the code alone, the same at every
    /// write; the embedder says what the act did (SP-10).
    WindowWithheld(Address),
    /// A run list holds more runs than one write may name.
    ///
    /// It is the merged list at a landing, `counts.m` (decision 13), or the
    /// state a restore or a take-back — the undo, the withdrawal, its undo —
    /// would set, the runs the write would send: refused with the count
    /// before any frame, never split.
    OverCap {
        /// The runs the list holds.
        runs: usize,
        /// [`SHOT_RUN_CAP`](super::SHOT_RUN_CAP).
        cap: usize,
    },
    /// `signed_session_required`: the landing's session is bare.
    NeedsSignedSession,
    /// `not_owner` naming the DRAFT side: the draft the merge stages its fresh
    /// words in is another account's — a sub-account's or an agent's proposal
    /// draft (wire.md §The publish shot and head-float, the unowned-draft
    /// edge) — and a publication keeps its records in the draft it was
    /// staged in, so the shot is refused; nothing was published.
    UnownedDraft {
        /// The draft named, `site.addr`.
        draft: Address,
    },
    /// `not_owner` on an undo's or a withdrawal's one write: the draft a
    /// merge is taken out of is another account's, and a draft's
    /// arrangement is its owner's to set (wire.md §Arrangement,
    /// `set_arrangement`); nothing was changed.
    NotOwner {
        /// The draft named.
        draft: Address,
    },
    /// A published document named to an undo or a withdrawal: a merge is
    /// taken out of a DRAFT alone — a published document, or a member of
    /// one, carries no marker and takes no `set_arrangement`
    /// (`published_target`); nothing was changed.
    Published {
        /// The document named.
        doc: Address,
    },
    /// A published document named as the merge journal: a merge record is
    /// kept only in a private document, so the act is refused before its
    /// first write, nothing sent (P13; the merge record's decision 7).
    ///
    /// It is any document the journal's `doc_metadata` names published —
    /// doc 1, a document born published, an edition or a version of one —
    /// found by the check of a journal named before a landing's, an undo's
    /// or a withdrawal's first write, the owner judged first: another
    /// account's published document is another account's journal, a halt.
    PublishedJournal {
        /// The journal named.
        journal: Address,
    },
    /// Nothing to undo on the draft named, and nothing was sent.
    ///
    /// The merge landed in it is not one an undo can take back, for the
    /// reason carried (the landing lane's precisions P2 and P4).
    NothingToUndo {
        /// The draft named.
        draft: Address,
        /// Why there is nothing to undo.
        why: NoUndo,
    },
    /// The draft named carries no merge: nothing to undo, and nothing to
    /// take out, with nothing sent.
    ///
    /// It is a draft with no marker and no base record, or whose feed holds
    /// no landing on it; for a withdrawal, any draft with no marker.
    NoMerge {
        /// The draft named.
        draft: Address,
    },
    /// The position a withdrawal's undo named is no withdrawal (skep #870).
    ///
    /// It names no withdrawal of a merge from the draft named, and nothing
    /// was sent.
    /// A withdrawal is a `set_arrangement` of the draft naming a base and no
    /// merge, before which the draft carried a marker and across which its
    /// base and its words did not move; a position naming any other write,
    /// a position inside a commit or past the board's head, or one before
    /// the draft existed, names none.
    NoWithdrawal {
        /// The draft named.
        draft: Address,
        /// The position named.
        at: u64,
    },
    /// A restore named a position at or past the draft's current one: no
    /// past state lies there, and nothing is read at a position (the
    /// `history` module; B3-S7).
    NotPast {
        /// The draft named.
        draft: Address,
        /// The position named.
        at: u64,
        /// The position the draft stands at — the `as_of` of its
        /// `doc_metadata` read at the head.
        current: u64,
    },
    /// `supersede_refused` on the shot: the board refused a daughter the
    /// shot names in `supersede`, the whole publication with it, nothing
    /// committed (wire.md §The publish shot and head-float, the deposits;
    /// the merge bridge lane) — never this library's fault. At
    /// [`SupersedeCause::HeadMoved`] the trunk's head moved under the merge,
    /// so the shot would have landed as a daughter and a claim would have
    /// named a side version for good: the merge is composed again on the
    /// head the cause names, with `retries` one higher, as the embedder
    /// re-runs after [`Landed::AsDaughter`](crate::merge::Landed::AsDaughter).
    SupersedeRefused {
        /// The entry in the shot's `supersede` — the `Member` sides in
        /// order — `site.index`; 0 at `head_moved`, the list refused whole.
        index: u64,
        /// The cause, the rejection's `detail`.
        cause: SupersedeCause,
    },
    /// The shot's one re-send refused `already_published` (the twin fence).
    ///
    /// The shot sends a draft's words a correspondence record names as
    /// published by reference, so the fence (PUB-3.9; wire.md §The publish
    /// shot and head-float) is met only where a publication lands them after
    /// the records' read: met once, the records are read again and the shot
    /// sent once more; met again, it is this refusal, nothing committed,
    /// never the library's fault, the merge to run again (the merge record's
    /// §1.5).
    AlreadyPublished {
        /// The draft whose words the board found already published.
        draft: Address,
        /// The member the board names them published into (`site.addr`).
        member: Address,
    },
    /// A landing of this merge begun in a draft and never recorded.
    ///
    /// It is the answer of a draft landing with no draft named, at [`land`] and
    /// [`resume`] alike, where no record of the merger's own stands for a
    /// landing of the key and a draft of the merger's account carries this
    /// merge's landing as the board marks it, no record of the merger's own of
    /// the merge naming that draft: a landing cut off between its one write and
    /// its record. Nothing is staged and nothing is written, so the merge never
    /// lands twice, and the landing is never finished unasked (PUB-8.32). The
    /// ways on are the merger's: the merge composed again and landed naming
    /// `draft`, every check run again and its record written; `resume` naming
    /// `draft`, the record alone, written where `draft` still holds the merge;
    /// or the landing taken back by `undo` naming `draft`.
    ///
    /// [`land`]: fn@crate::merge::land
    /// [`resume`]: crate::merge::resume
    LandingBegun {
        /// The draft the merge landed in.
        draft: Address,
        /// The position the board marks the landing at.
        position: u64,
    },
    /// A window part of the shot with no answer, or an answer that fits
    /// nothing: nothing is sent (the merge record's §1.5, THE SHOT's WINDOW
    /// PARTS; §7).
    ///
    /// It names every part that needs an answer, final in meaning and the
    /// same for every caller: the landing never answers a window's part for
    /// its caller. A part named since its answer was given is among them,
    /// flagged [`WindowPart::named_since`] (PUB-3.108).
    WindowPartsOwed {
        /// Every part that needs an answer.
        parts: Vec<WindowPart>,
        /// The answers given that fit nothing, or name the same words.
        misfits: Vec<Misfit>,
        /// The answers that stand beside them.
        given: Vec<WindowPart>,
    },
    /// The death signal under the caller's token: the session ended
    /// (wire.md §Sessions).
    ///
    /// It is met at any read or write of an act that presents the token,
    /// and nothing is read or written past it; the write it met did not
    /// land, the board running a dead token's frame as a guest's. The face
    /// carried is the one the act owes its person: the step the signal met,
    /// and the way on — at a landing [`resume`](crate::merge::resume), at a
    /// take-back's record the act standing with its record unwritten, at
    /// every other step the act run again, which reads what stands before
    /// it writes. An embedder that holds the session ends it on this arm.
    SessionEnded(Halt),
    /// The library's own fault named (A-288's own-bug class).
    ///
    /// The fault is a frame the board refused as malformed in substance, a
    /// shape it does not know; the board's other refusals ride here verbatim,
    /// every transport halt, and the death signal met by a read that
    /// presented no token, a fault of the board or the transport, never a
    /// session's end. One of the publication's own refusals of the shot rides
    /// here VERBATIM too, never as the library's fault:
    /// `publication_over_budget` with the daemon's detail, a `Halt::Refused`
    /// whose `body` carries the `site`.
    Halt(Halt),
}

/// Why an undo has nothing to take back ([`Refusal::NothingToUndo`]).
///
/// Each is read off the draft's `doc_metadata` and, for a draft whose base
/// is recorded with no marker beside it, off the draft's own latest feed row
/// of the kinds that end a marker — read, never acted on; for a draft with
/// no base record, off its latest re-arrangement past its landing's row and
/// the state it left (the undo module's doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoUndo {
    /// The marker was inherited when the draft was staged (P2): its `at` is
    /// the stage's own position, so the state before it is the draft's own
    /// `doc_not_registered` — there is nothing of the draft's to take back;
    /// discard it or edit it.
    Inherited,
    /// The merge was published (P4), so there is nothing to undo.
    ///
    /// It was published from the draft, its base record standing on the
    /// version the shot minted, or by a merge's shot naming the draft, which
    /// keeps its base (skep #944); no marker stands, so the way back is to
    /// publish the older text again, never a re-recorded base.
    Published {
        /// The version the merge is.
        ///
        /// It is the member the draft's latest `publish` row names first.
        version: Address,
    },
    /// The merge was already taken back.
    ///
    /// The draft's latest marker-ending row is a `set_arrangement` naming a
    /// base and no merge — an undo's or a withdrawal's; or, on a draft with
    /// no base record, the latest `set_arrangement` past the landing's row
    /// names no merge and left the draft as the undo's write would, mapped
    /// as it is (P4).
    TakenBack,
    /// A withdrawal's undo found a merge in the draft since (skep #870).
    ///
    /// It found the draft carrying a merge again, or one landed in it since
    /// the withdrawal.
    /// The draft carries a marker — the one the withdrawal cleared, put
    /// back already by this undo, or a merge landed since — or its base
    /// moved with no publication since the withdrawal, a merge having
    /// landed and been taken out again; the undo takes back the newest step
    /// alone, so the merge standing, or the draft as it stands, is the one
    /// to undo or edit.
    Remarked,
}

impl From<Halt> for Refusal {
    fn from(h: Halt) -> Refusal {
        Refusal::Halt(h)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::BaseUnknown(side) => write!(f, "the base of the side {} cannot be read: a side is a version of the document, a draft of the document owner's account the board records a base for (one `stage` minted), or another account's fork of one of the document's versions", side.address()),
            Refusal::ForkOfOwner { fork } => write!(f, "{fork} is of the document owner's own account, not another account's fork: name the owner's draft as the draft side; nothing was merged"),
            Refusal::BareSource { side, source, hop } => {
                write!(f, "the {} {} ", side.noun(), side.address())?;
                match hop {
                    Some(hop) if hop != side.address() => write!(f, "descends from {hop}, begun from {source} itself before its first version")?,
                    Some(_) | None => write!(f, "was begun from {source} itself, before its first version")?,
                }
                write!(f, ": its base is {source}'s arrangement from before that version, and either no version of {source} stands yet, so there is nothing to merge onto (publishing it lands version 1), or this board serves no count of that arrangement (doc_metadata's own_count), so it cannot be read; nothing was merged")
            }
            Refusal::HopUnrecorded { side, hop } => write!(f, "the board records no base for {hop}, on the line of the {} {} (its doc_metadata serves neither shot_base nor source — a member an older build minted): a base is never taken from an address, so this merge is not composed; nothing was merged", side.noun(), side.address()),
            Refusal::ForkBaseNamed { fork, base } => write!(f, "the base {base} was named for the fork {fork}: a fork's base is derived from where the board records it standing (doc_metadata's base, else its source), never the caller's to name — leave base unset"),
            Refusal::DraftBaseDisagrees { side, named, served } => write!(f, "the base {named} was named for the draft {}, whose recorded base (doc_metadata's base) derives the base {served}: a draft's base is the board's to serve — leave base unset, or name the base the board derives", side.address()),
            Refusal::NamedBaseDisagrees { named, served } => write!(f, "the base {named} was named, and the bases the board records for the sides derive the base {served}: a merge's base is the board's to serve — leave base unset, or name the base the board derives"),
            Refusal::TwoDrafts => f.write_str("two drafts off one head are no merge shape: shoot one first"),
            Refusal::Unreadable(doc) => write!(f, "{doc} is not readable to this reader (withheld)"),
            Refusal::NoSuchDocument(doc) => write!(f, "{doc} is not registered at this board"),
            Refusal::TooFragmented { doc, runs_seen } => write!(f, "{doc} is in more pieces than `image` can answer, even one position at a time ({runs_seen} runs seen)"),
            Refusal::HistoryBusy => f.write_str("the board was busy reading history (history_busy) past the bounded retries"),
            Refusal::HistoryReclaimed { at, floor } => {
                write!(f, "the board no longer answers position {at} (history_reclaimed")?;
                if let Some(floor) = floor {
                    write!(f, "; the oldest it answers is {floor}")?;
                }
                f.write_str("): every read of this merge is made at that one position, and nothing was read at another — compose the merge again, which reads at the board's current position")
            }
            Refusal::BeyondHead { at, head, recorded } => {
                match recorded {
                    Some(doc) => write!(f, "the merge record names position {at} for {doc}, past the board's head")?,
                    None => write!(f, "position {at} is past the board's head")?,
                }
                if let Some(head) = head {
                    write!(f, " at position {head}")?;
                }
                match recorded {
                    Some(_) => f.write_str(" (beyond_head): the record was not written against this board's history as it stands, so it cannot be checked here, and nothing was read at another position"),
                    None => f.write_str(" (beyond_head), and nothing was read there: read at a position the board has answered, or at the head"),
                }
            }
            Refusal::NotAPosition { at, nearest, recorded } => {
                match recorded {
                    Some(doc) => write!(f, "the merge record names position {at} for {doc}, which falls inside one commit and is no position the board answers (not_a_position")?,
                    None => write!(f, "position {at} falls inside one commit and is no position the board answers (not_a_position")?,
                }
                if let Some(nearest) = nearest {
                    write!(f, "; the greatest position at or below it is {nearest}")?;
                }
                match recorded {
                    Some(_) => f.write_str("): the record was not written against this board's history, so it cannot be checked here, and nothing was read at another position"),
                    None => f.write_str("), and nothing was read there: read at a position the board has answered, or at the head"),
                }
            }
            Refusal::ForkBaseMoved { fork, source, head } => write!(f, "{fork} was forked from {source}, and this merge was composed on {head} — fork {head} afresh and land the merge there; nothing was merged"),
            Refusal::BaseNotInChain { into, head } => write!(f, "{into} is a draft of another document: its recorded base is no version of the document {head} heads — land the merge in a draft staged from that document; nothing was merged"),
            Refusal::WindowWithheld(origin) => write!(f, "{origin} is not shared with you (withheld), and a run this write sends windows it"),
            Refusal::OverCap { runs, cap } => write!(f, "the list is in more pieces than one write can carry — {runs}, where {cap} is the most; nothing was sent"),
            Refusal::NeedsSignedSession => f.write_str("a signed session is needed to land a merge on a claimed board (signed_session_required)"),
            Refusal::UnownedDraft { draft } => write!(f, "the draft {draft} is another account's (not_owner): a publication keeps its records in the draft it was staged in, so the shot is refused; nothing was published"),
            Refusal::NotOwner { draft } => write!(f, "{draft} is another account's draft (not_owner): a merge is taken out of a draft by its owner alone; nothing was changed"),
            Refusal::Published { doc } => write!(f, "{doc} is published (published_target): a merge is taken out of a draft alone, and a published document carries none — nothing to undo or take out"),
            Refusal::PublishedJournal { journal } => write!(f, "{journal} is published, and a merge record is kept only in a private document — nothing was written"),
            Refusal::NothingToUndo { draft, why } => match why {
                NoUndo::Inherited => write!(f, "nothing to undo: {draft} inherited the merge when it was staged; discard it or edit it"),
                NoUndo::Published { version } => write!(f, "nothing to undo: {draft} was published as version {version} since, and a version stands — the way back is to publish the older text again"),
                NoUndo::TakenBack => write!(f, "nothing to undo: the merge in {draft} was already taken back"),
                NoUndo::Remarked => write!(f, "nothing to undo: {draft} carries a merge again, or a merge landed in it since the merge was taken out — undo that merge, or edit the draft as it stands"),
            },
            Refusal::NoMerge { draft } => write!(f, "{draft} carries no merge: nothing to undo, nothing to take out"),
            Refusal::NoWithdrawal { draft, at } => write!(f, "position {at} names no withdrawal of a merge from {draft}: nothing to undo, and nothing was sent"),
            Refusal::NotPast { draft, at, current } => write!(f, "position {at} is not before the state {draft} stands at (position {current}): a restore names a position before the draft's current one, and nothing was read or sent"),
            Refusal::SupersedeRefused { index, cause } => match cause {
                SupersedeCause::HeadMoved { head: Some(head) } => write!(f, "the head moved under the merge: the trunk's head is now {head}, so the shot would have landed as a daughter, and a shot claiming a daughter superseded is refused whole (supersede_refused, head_moved) — nothing was published; compose the merge again on {head}"),
                SupersedeCause::HeadMoved { head: None } => f.write_str("the head moved under the merge, so the shot would have landed as a daughter, and a shot claiming a daughter superseded is refused whole (supersede_refused, head_moved) — nothing was published; compose the merge again on the trunk's head"),
                SupersedeCause::NotMember => write!(f, "the board refused the supersession claim at entry {index} (supersede_refused, not_member): the side is no registered version member of the document's own chain — nothing was published"),
                SupersedeCause::Base => write!(f, "the board refused the supersession claim at entry {index} (supersede_refused, base): the side is the member the shot appends to — nothing was published"),
                SupersedeCause::Duplicate => write!(f, "the board refused the supersession claim at entry {index} (supersede_refused, duplicate): the side is named twice — nothing was published"),
            },
            Refusal::AlreadyPublished { draft, member } => write!(f, "the words of {draft} were published as {member} while this merge was being sent (already_published) — nothing was published; run the merge again, which sends words already published by reference"),
            Refusal::LandingBegun { draft, position } => write!(f, "this merge already landed in {draft} at position {position}, and its record is not written — nothing was staged or written, so the merge does not land twice; to go on, compose the merge again and land it naming {draft} (the command's --into {draft}), which runs every check again and writes its record, or resume naming {draft}, which writes the record alone where {draft} still holds the merge; to give it up, undo it naming {draft} (the command's --undo {draft}), or discard {draft}"),
            Refusal::WindowPartsOwed { parts, misfits, .. } => {
                write!(f, "nothing was published: {} window part{} of this merge need{} an answer", parts.len(), if parts.len() == 1 { "" } else { "s" }, if parts.len() == 1 { "s" } else { "" })?;
                if !misfits.is_empty() {
                    write!(f, ", and {} answer{} fit{} nothing", misfits.len(), if misfits.len() == 1 { "" } else { "s" }, if misfits.len() == 1 { "s" } else { "" })?;
                }
                Ok(())
            }
            Refusal::SessionEnded(h) | Refusal::Halt(h) => h.fmt(f),
        }
    }
}

impl std::error::Error for Refusal {}
