//! How a merge lands and what the landing answers (the merge record's §7).
//!
//! [`Merger`] is the signed session's facts and hand, [`Landing`] the shot
//! or the draft landing asked for and [`Landed`] what it answers; the steps
//! are the `land` module's doc.

use skep_address::Address;

use crate::board::Token;
use crate::merge::windows::{Answers, WindowPart};
use crate::sign::Signer;

/// The merger: a signed session's facts and its hand.
///
/// The facts are the session's token, the account it acts as, and the
/// signer it was opened with (the merge record's §7, "What it reads
/// through"). They are taken as facts, never as the ceremony's own session
/// type, which this module does not name: the embedder opens the session
/// with a content scope through the handshake and lends its token, its
/// account and its signer here.
#[derive(Clone, Copy)]
pub struct Merger<'a> {
    /// The signed session's token — what every write presents.
    pub token: &'a Token,
    /// The account the session acts as, `principal_prefix(principal)`.
    ///
    /// Its own links of the record's kind find its journals and its
    /// records.
    pub account: &'a str,
    /// The signer the session was opened with.
    ///
    /// It is the shot's hand.
    pub signer: &'a dyn Signer,
}

/// How a merge lands (the merge record's §7, `Landing`).
///
/// It is the shot from the head, or the draft landing into a staging draft.
pub enum Landing<'a> {
    /// One `publish` from the head with M as the runs (§1.5).
    ///
    /// The claim's read and the record follow it.
    Shot {
        /// The merger's signed session and hand.
        merger: Merger<'a>,
        /// The staging draft whose fresh text the shot re-inserts.
        ///
        /// The caller names it where the merger typed any; a draft side's
        /// is named without asking where M holds its fresh text.
        draft: Option<Address>,
        /// The caller's answers at M's window parts (the merge record's §7,
        /// `Answers`; the `windows` module's doc): empty where M windows
        /// nothing unpublished, and a part left unanswered refuses before
        /// the shot's first write.
        answers: Answers,
        /// The merge journal the record goes to.
        ///
        /// The account's default where `None` — the private journal its
        /// first record went to, or a private one minted (decision 7). One
        /// named is checked before the shot: a draft this account owns,
        /// readable and registered, a published one refused
        /// [`Refusal::PublishedJournal`] (P13; the `land` module's doc).
        ///
        /// [`Refusal::PublishedJournal`]: super::Refusal::PublishedJournal
        journal: Option<Address>,
    },
    /// M set as the whole arrangement of a draft in one `set_arrangement`.
    ///
    /// The write is typed against the position the merge was composed at (the
    /// `land` module's doc); the record follows, with `landed` the draft — no
    /// claim: the person's own shot is the claim's moment (decision 16).
    Draft {
        /// The merger's signed session and hand.
        merger: Merger<'a>,
        /// The draft M is landed into.
        ///
        /// `None` lands it in a fresh draft staged from the head the merge
        /// was composed on (R3): `stage {from: the head}`, then the write
        /// typed against the stage's position, the base the stage recorded
        /// re-recorded on the head — unless a draft the merger's records of
        /// the key name, read at the landing, still holds this composition's
        /// landing, which is reported at the position its draft marks it
        /// with nothing staged, its `staged` false, or, where none does, a
        /// draft of the merger's carries a landing of the merge no record of
        /// theirs names, refused [`Refusal::LandingBegun`] with nothing
        /// staged. A draft that marks no landing of the merge — taken back,
        /// its take-back's record unwritten — or whose landing placed another
        /// composition's list holds none.
        ///
        /// [`Refusal::LandingBegun`]: super::Refusal::LandingBegun
        into: Option<Address>,
        /// The merge journal, or the account's default.
        ///
        /// One named is checked before the stage or the one write, as the
        /// shot's is.
        journal: Option<Address>,
    },
}

/// What a landing answered (the merge record's §7, `Landed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Landed {
    /// The merge landed on the trunk.
    ///
    /// It carries the member, the shot's position, the claims standing at
    /// the daughters, the record's link, and the retries the record
    /// carries.
    Member {
        /// The merged member, `D.h+1`.
        address: Address,
        /// The shot's commit position.
        ///
        /// Where the member already stood, it is the position the member
        /// was minted at, its own `doc_metadata` `at`: a landing made before
        /// the composition and found standing answers a position at or below
        /// `Merged::as_of`. Where the board serves no such position, it is
        /// the position of the member's mint row on the feed, else the
        /// highest `as_of` the reads answered.
        position: u64,
        /// The supersession claims standing at the daughters whose `new` is the
        /// member, as read after the shot — the claims the shot deposited, one
        /// per `Member` side (the `land` module's doc), homed in the trunk;
        /// none where the shot named no daughter, or where every daughter was
        /// already claimed by the merger's own and skipped.
        claims: Vec<Address>,
        /// The record's link.
        ///
        /// It is the one written, homed in the merger's journal beside the
        /// record, or the one already standing for this key and landing.
        record: Address,
        /// `Options::retries`, as written into the record.
        retries: u32,
        /// Each window part as answered, in M's order (the merge record's
        /// §1.5: the acknowledgment names every answer given).
        answers: Vec<WindowPart>,
    },
    /// The head moved under the merge; the shot landed as its daughter.
    ///
    /// Reported, never a success. The daughter holds this merge's result, so
    /// the embedder merges it with the new head — the daughter as a
    /// `Side::Member`, `retries` one higher (decision 17; C-46's re-apply) —
    /// which asks only where the new head's changes meet this merge's and
    /// claims the daughter superseded; composing this merge's own sides
    /// again on the new head asks every gap again and leaves the daughter
    /// standing beside the head. Only a shot naming NO daughter
    /// can meet it — a merge of draft or fork sides alone, or one whose
    /// every daughter an active claim of the merger's own names superseded
    /// by a version at or below the head it composed on (the skip) — or a
    /// landing whose read-first finds a daughter of the head already holding
    /// M: a shot naming a daughter in `supersede` is refused whole at a moved
    /// head, [`Refusal::SupersedeRefused`], and lands as the trunk's next
    /// member or not at all (the `land` module's doc).
    ///
    /// [`Refusal::SupersedeRefused`]: super::Refusal::SupersedeRefused
    AsDaughter {
        /// The daughter minted.
        address: Address,
        /// The shot's commit position.
        ///
        /// Where the daughter already stood, it is the position it was
        /// minted at, as `Member`'s `position` is.
        position: u64,
    },
    /// M landed into a draft.
    ///
    /// It carries the draft — the one named, the fresh one staged, or one a
    /// record of the merger's of the key names, found standing — the write's
    /// position, the record's link, the newer head where the board told one,
    /// and whether this call staged the draft.
    Draft {
        /// The draft.
        into: Address,
        /// The `set_arrangement`'s commit position, the write's `at`.
        ///
        /// Where the landing was found standing, it is the position the
        /// board marks it at — the draft's marker, or on a draft with no
        /// recorded base its `set_arrangement` row — the draft as of it
        /// holding M, or with that position reclaimed and the draft edited
        /// since a record of the key standing for it, for a `resume` naming
        /// the draft, and for a fresh landing a draft the merger's records of
        /// the key name, marking the merge at or past the position its record
        /// names, the draft as of it holding M or that position reclaimed
        /// and the draft edited since; such a fresh landing whose draft's
        /// mark cannot be read, the walk of its rows needing a past state the
        /// board has reclaimed, answers the record's position. A landing into the
        /// draft the standing record names is the same landing (skep #790):
        /// `position` is this write's, and the record's own is the first
        /// landing's.
        position: u64,
        /// The record's link, homed in the merger's journal.
        ///
        /// It is the one written, or the one standing for this landing,
        /// whose `landed` names the position of the write that first landed
        /// the key in the draft.
        record: Address,
        /// The trunk's current head, where it is no longer the head the
        /// merge was composed on (R5, "land and tell").
        ///
        /// The write landed all the same, recorded on the head it composed
        /// on; the embedder tells that a newer version stands, and a merge
        /// composed again on it includes it. `None` where the head used is
        /// the trunk's, and where the landing was found standing.
        head_moved: Option<Address>,
        /// Whether this call staged the draft it landed in.
        ///
        /// It is true only where no draft was named and this call sent the
        /// `stage`, the write landing in the draft the stage answered. It is
        /// false for a draft named, for a landing found standing — a draft
        /// a record of the merger's of the key names, nothing staged —
        /// and for every [`resume`], which sends no stage. An embedder says a
        /// fresh draft was made from it (SP-10), never from whether it named
        /// a draft: a landing of the merger's own made after the composition
        /// — on another device, or by another process — is found, not staged,
        /// or refused [`Refusal::LandingBegun`] where its record is unwritten.
        ///
        /// [`resume`]: super::resume
        /// [`Refusal::LandingBegun`]: super::Refusal::LandingBegun
        staged: bool,
    },
}

impl<'a> Landing<'a> {
    pub(super) fn merger(&self) -> Merger<'a> {
        match self {
            Landing::Shot { merger, .. } | Landing::Draft { merger, .. } => *merger,
        }
    }

    pub(super) fn journal(&self) -> Option<&Address> {
        match self {
            Landing::Shot { journal, .. } | Landing::Draft { journal, .. } => journal.as_ref(),
        }
    }
}
