//! The merge's landing — the merge record's §1.5.
//!
//! The landing is the one `publish` of the merged list from the head with
//! its signed body, the supersession claims riding it, then the claims'
//! read and the record in the journal with its link beside it, each step
//! idempotent by reading first (P4, P14); the draft landing, ONE
//! `set_arrangement` of the merged list into the draft (the landing lane's
//! rulings R1, R4, R5; skep #764); [`resume`], the residue walk that
//! completes what a lost acknowledgment left, writing nothing twice; and
//! [`record_published`], the record of a landing the merger's own
//! publication made, written once and never a second shot.
//!
//! **The order, and what each step reads first.** The cap: `counts.m`
//! against the shot's run cap before any frame (decision 13; P13). A journal
//! named: checked after the read-first steps, before the first write. The shot:
//! the trunk's next member, then the head's daughters, read for a member
//! whose first `placed` positions already hold M — else one `publish` from
//! the head, its body every copied run's bytes re-read through the side that
//! holds them and every window signed by address, re-asked once under the
//! same per-session `id` where the acknowledgment was lost. The frame and
//! its body go through the publication composition's request builder
//! (`crate::publication::Request`) with one deposit list — `supersede`, the
//! daughters (the claim, below) — and no `links`, `retract` or `read_with`
//! entry, no place beside any run, the document form — the merge's delta
//! from a publication (the link-sets design §5.5: "the walk's base the
//! `base` it holds"), so a shot naming no daughter signs today's body byte
//! for byte through the one body builder. A daughter in the acknowledgment
//! is reported at once ([`Landed::AsDaughter`]): the head moved under a shot
//! naming no daughter, the library never re-runs, the embedder does with
//! `retries` one higher (decision 17). The record: the merger's current
//! record for the key, read by the landing itself as the composition reads
//! the prior records (the merge record's §1.5 (ii), §1.3's step 7) — the
//! links of the kind to each side of the key, kept to the merger's own
//! account, the newest by the order they were minted — standing where it
//! names this landing's member or draft, whatever position it names; else
//! the journal found or minted, the atom appended at its end, and the link
//! homed in the journal beside it, from the atom to the member and every
//! side besides the head under the kind, the record naming that newest
//! record in `replaces` (P20: a later record names the one it replaces).
//! The journal is a private draft, so the record and its link are private
//! writes, signed by no `attest`. A newer record of the key — an undo's, a
//! withdrawal's, a landing of it elsewhere — replaces this landing's, so a
//! landing after it writes its own. A merge composed again and landed in
//! the draft the newest record names, no take-back recorded between, is the
//! same landing (skep #790): its write lands under its own ids and no record
//! is written, the record keeping the first landing's position
//! (`Newest::naming`). The composition's `Merged::prior` is what the
//! composition saw, under the reader's currency, and never the landing's
//! answer: a composition kept across a take-back, or one made before its
//! own landing, lands by the board as it stands.
//!
//! **The head, before the shot.** The shot is the landing's one public
//! write, and the one signed: it is preceded by the board's head
//! (`Board::board_head`; SP-14), `H.1`'s pair, which its `attest` signs
//! over, or none on a board no one has claimed, which takes it without one.
//! A claimed board serving no head record halts the shot with nothing sent,
//! the merge not landed. The head is read after the read-first steps and
//! the check of a journal named, so a [`resume`] that finds nothing landed
//! answers with no head read. The board's own
//! `attestation_invalid:board_unavailable` at the shot — a head owed past
//! that read — is faced the same, never as this library's fault. A shot sent
//! unsigned to a board read as no one's and refused `attestation_required`
//! met a claim that landed past that read, its head written, and was refused
//! before its transaction (wire.md §Credential refusals, a reorder): the head
//! is read again and the shot sent ONCE more, signed over that pair, under
//! its own id, its answer a signed frame's. A second read that finds no head
//! to sign over is faced as the head the board owes, nothing sent; a signed
//! shot refused `attestation_required` is this library's own fault. The
//! draft landing's stage and one write, and every write of the record, go
//! to private drafts, which take no `attest`, and read no head.
//!
//! **The journal, before the first write and at the record.** A merge
//! record is kept only in a private document: its atom is appended to its
//! journal as a plain insert, which a published document refuses, so a
//! journal takes a record only as a draft the merger's account owns,
//! readable and registered at this board (the merge record's decision 7),
//! and no record goes into a published document. A journal the caller names
//! is checked before the landing's first write — one `doc_metadata` at the
//! head, after the read-first steps and, at the shot, before the head's
//! read — and one this merger may not read (`withheld`), one this board
//! does not register or another account's is refused there as a halt
//! naming the journal and the check it fails, a published one of the
//! merger's own as [`Refusal::PublishedJournal`], with nothing sent (P13);
//! [`journal::check`] is that check alone, for a caller that says it before
//! it lands. A landing found standing makes no write before its record, and
//! no journal is checked there. At the record the journal's extent is read,
//! the end the atom is appended at: a journal that read answers `withheld`
//! or `doc_not_registered`, or a journal named whose atom the board refuses
//! `published_target` or `not_owner`, halts the record with nothing of it
//! written, faced as the landing standing with its record unwritten — never
//! as a refusal of the landing — for [`resume`] to record into a journal the
//! merger can write, or into the account's own. The account's own journal,
//! found or minted at the record, is this library's choice — a private
//! draft of the account's, read before it is taken (`journal`'s doc) — so
//! the board's refusal of its atom is this library's own fault. Its find is
//! a class scan, reissued while the board is busy; refused busy past the
//! bound, it leaves the landing standing with its record unwritten, as a
//! journal that cannot take the record does.
//!
//! **The draft landing is one write.** M is sent whole as one
//! `set_arrangement` of the draft (wire.md §Arrangement), TYPED against the
//! one position the merge was composed at — `Merged::as_of`, the position
//! every read of the composition was made at (skep #762) — so an edit made
//! to the draft after the merge was composed is refused `arrangement_moved`
//! with nothing changed, and the draft holds M or what it held, never a
//! state between. The refusal is said off the draft as it stands, read
//! after it: where the change is this merge's own landing, made after the
//! composition — a composition landed again in a session holding no memo
//! of its write, the landing found by the draft's marker or, on a draft
//! with no recorded base, which carries none, by its latest `set_arrangement`
//! row on the supplement (wire.md §The change feed) — it names that landing
//! and its record, written or not, with [`resume`] the way on where the
//! draft holds M; else it names the draft that changed and that
//! nothing was merged. The frame carries the head the merge composed on with
//! its extent AS READ (`head`), the same pair as the base to record where
//! the board records a base for the draft — read off the draft's
//! `doc_metadata` at that position; a baseless draft and a fork get none,
//! so the library never sends a `base` the board refuses `no_base_to_record`
//! (N4) — and the merge the draft is to carry (`merge`, every side but the
//! draft itself). The board re-records the base on the head and sets the
//! marker in the same commit (R4); a newer version published since the
//! compose is not refused: the write lands against the head it composed on
//! and the ack names the trunk's current head as `head_moved`, which the
//! landing carries out (R5, "land and tell"). The write is sent where the
//! draft already holds M too, so the base and the marker are recorded. With
//! no draft named ([`Landing::Draft`]'s `into` none), a fresh draft is
//! staged from the head first — `stage {from: the head}`, two commits, the
//! state between a plain staged draft (R3) — and the write is typed against
//! the stage's own position; where the merger's newest record for the key,
//! read before the stage, names a draft landing, that landing is reported
//! and nothing is staged, so [`Landed::Draft`]'s `staged` is true only where
//! the call sent the stage. The record follows, its draft landing's position
//! the write's `at`. [`resume`] finds a landing in a draft named by that same
//! marker or row, at the position it marks, the draft holding M — never by
//! the draft's words, which a withdrawal keeps: a landing withdrawn or
//! undone, its mark cleared, leaves nothing to resume (R2). Nor is a
//! landing found by a marker the draft inherited when it was staged from a
//! marked draft: the stage copies the marker with the words, stamped at its
//! own commit, the draft's mint (P2), so a marker whose `at` is the draft's
//! own `at` in its `doc_metadata` marks no landing in it.
//!
//! **The per-session ids.** Every write of a landing carries the id
//! `<stem>.<frame>`, its stem `merge:` and the SHA-256, in lowercase hex,
//! of the text naming the write — 70 bytes whatever the text, so a merge of
//! any number of sides lands under ids inside the 256-byte id cap skepd
//! holds at parse. An id is unique within its session: the board answers a
//! frame under an id it has acknowledged with that acknowledgment, never
//! judging the frame (wire.md §Correlation and idempotency), so the text
//! names all that makes a write another. `<key>` is the key's text
//! (`RecordKey::text`). The shot's text is `<key>`, for `<stem>.publish`,
//! then the record's `<stem>.record` and `<stem>.link`; the draft
//! landing's names the key, the draft and the position the write is typed
//! against, `<key>:<draft>@<at>`, for `<stem>.draft`, `<stem>.record` and
//! `<stem>.link` — for a draft named, `<key>:<draft>@<at>~<link>` where the
//! landing follows a record (`Newest::follows`): `<link>` the merger's
//! newest record of the key, or the one that record replaces where it names
//! the draft as landed in, so a retry after the landing's own record is
//! written spells its first call's text; the stage's names the key and P,
//! the composition's position, `<key>@<P>`, or `<key>@<P>~<link>` where a
//! record of the merger's of the key stands, `<link>` the newest one's,
//! which the landing's record will replace, for `<stem>.stage`. The board
//! answers a second call over one composition from its ids, and a landing
//! composed after a take-back, landed into another draft, landed into its
//! draft again after a take-back recorded since, or landed fresh again
//! after its own landing was taken back, is a write of its own, which the
//! board judges: one typed against a position its draft has changed since
//! is refused `arrangement_moved`, nothing written. The one signed send of
//! a shot after a claim keeps its frame's id: the board never memoizes a
//! refusal, so it judges that id afresh (wire.md §Correlation and
//! idempotency), and only that id lets a second call over the composition
//! meet the write it made, never make another.
//!
//! **The claim rides the shot** (the merge record's §1.5 (i); the merge
//! bridge lane). The shot's `supersede` names every `Member` side — the
//! daughters the member takes in, in side order — and never a draft side or
//! a fork side: no public claim supersedes a private draft or another
//! account's fork. The board deposits one supersession claim per daughter in
//! the same commit, homed in the trunk, `old` the daughter and `new` the
//! member it mints, signed in the body as the publication composes it
//! (wire.md §The publish shot and head-float, the deposits). THE SKIP IS
//! READ BEFORE SIGNING: `in_claims{y: the daughter, view: active}` at each,
//! a daughter an active claim of the merger's own already names dropped from
//! the list and the body, as the board's plan drops it, so the body signed
//! is the body the board composes. A shot naming a daughter lands on the
//! trunk or not at all: where the head moved under the merge the board
//! refuses it whole, `supersede_refused` with `detail` `head_moved`, nothing
//! committed, answered as [`Refusal::SupersedeRefused`] naming the trunk's
//! head for the merge to be composed again on. After the shot the claims
//! are read back at the daughters ([`Writer::claims_standing`]) and written
//! into the record; a merger that loses the acknowledgment finds them with
//! the member ([`resume`]), since a landed shot carried them.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use skep_address::Address;
use skep_identity::{entry_frame, BoardTerm, DocTerm, EntryBody};

use crate::address::parse_address;
use crate::board::{
    acked_addr, acked_at, acked_head_moved, answers, frames, Answer, Board, BoardHead, Rejection,
    Token,
};
use crate::halt::{Halt, Refused};
use crate::publication::{self, own_claim_names, Piece, SupersedeCause, SCAN_BUSY_REISSUES};
use crate::sign::{sig_hex, Signer};

use super::compose::Run;
use super::journal::{self, Unfound};
use super::reads::{
    daughter_of, feed_rows, first_difference, is_trunk_member, next_trunk_member, position_of,
    runs_of, session_ended, values_for, version_components, Family, Merged, OnEnd, Reader, Refusal,
    Role, Side,
};
use super::record::{newest, read_record, records_of, Record, RecordLanding};

/// The most bytes a shot's signed body may run to.
///
/// It is the frame routes' request-body cap, 8 MiB (wire.md §HTTP status
/// codes, `413 payload_too_large`), the parity the daemon holds a shot's
/// body to. The body is composed through the publication's request
/// builder and measured against it; a body past it is refused by name.
pub const SHOT_BODY_BUDGET: usize = 8 * 1024 * 1024;

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
        /// The merge journal the record goes to.
        ///
        /// The account's default where `None` — the private journal its
        /// first record went to, or a private one minted (decision 7). One
        /// named is checked before the shot: a draft this account owns,
        /// readable and registered, a published one refused
        /// [`Refusal::PublishedJournal`] (P13; the module's doc).
        journal: Option<Address>,
    },
    /// M set as the whole arrangement of a draft in one `set_arrangement`.
    ///
    /// The write is typed against the position the merge was composed at
    /// (the module's doc); the record follows, with `landed` the draft — no
    /// claim: the person's own shot is the claim's moment (decision 16).
    Draft {
        /// The merger's signed session and hand.
        merger: Merger<'a>,
        /// The draft M is landed into.
        ///
        /// `None` lands it in a fresh draft staged from the head the merge
        /// was composed on (R3): `stage {from: the head}`, then the write
        /// typed against the stage's position, the base the stage recorded
        /// re-recorded on the head — unless the merger's newest record for
        /// the key, read at the landing, names a draft landing, which is
        /// reported with nothing staged, its `staged` false.
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
        /// Where the member already stood and the feed holds no row of its
        /// mint, it is the highest `as_of` the reads answered.
        position: u64,
        /// The supersession claims standing at the daughters whose `new` is
        /// the member, as read after the shot — the claims the shot
        /// deposited, one per `Member` side (the module's doc), homed in the
        /// trunk; none where the shot named no daughter, or where every
        /// daughter was already claimed by the merger's own and skipped.
        claims: Vec<Address>,
        /// The record's link.
        ///
        /// It is the one written, homed in the merger's journal beside the
        /// record, or the one already standing for this key and landing.
        record: Address,
        /// `Options::retries`, as written into the record.
        retries: u32,
    },
    /// The head moved under the merge; the shot landed as its daughter.
    ///
    /// Reported, never a success; the embedder re-runs with the new head and
    /// `retries` one higher (decision 17). Only a shot naming NO daughter
    /// can meet it — a merge of draft or fork sides alone — or a landing
    /// whose read-first finds a daughter of the head already holding M: a
    /// shot naming a daughter in `supersede` is refused whole at a moved
    /// head, [`Refusal::SupersedeRefused`], and lands as the trunk's next
    /// member or not at all (the module's doc).
    AsDaughter {
        /// The daughter minted.
        address: Address,
        /// The shot's commit position.
        ///
        /// Where the daughter already stood and the feed holds no row of its
        /// mint, it is the highest `as_of` the reads answered.
        position: u64,
    },
    /// M landed into a draft.
    ///
    /// It carries the draft — the one named, the fresh one staged, or the
    /// one the merger's newest record for the key names, found standing —
    /// the write's position, the record's link, the newer head where the
    /// board told one, and whether this call staged the draft.
    Draft {
        /// The draft.
        into: Address,
        /// The `set_arrangement`'s commit position, the write's `at`.
        ///
        /// Where the landing was found standing, it is that landing's: for a
        /// `resume`, the position the board marks it at — the draft's
        /// marker, or on a draft with no recorded base its `set_arrangement`
        /// row — the draft holding M; for a fresh landing the merger's
        /// newest record for the key names, the position that record names.
        /// A landing into the draft the standing record names is the same
        /// landing (skep #790): `position` is this write's, and the
        /// record's own is the first landing's.
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
        /// false for a draft named, for a landing found standing — the draft
        /// the merger's newest record for the key names, nothing staged —
        /// and for every [`resume`], which sends no stage. An embedder says a
        /// fresh draft was made from it (SP-10), never from whether it named
        /// a draft: a landing of the merger's own made after the composition
        /// — on another device, or by another process — is found, not staged.
        staged: bool,
    },
}

impl<'a> Landing<'a> {
    fn merger(&self) -> Merger<'a> {
        match self {
            Landing::Shot { merger, .. } | Landing::Draft { merger, .. } => *merger,
        }
    }

    fn journal(&self) -> Option<&Address> {
        match self {
            Landing::Shot { journal, .. } | Landing::Draft { journal, .. } => journal.as_ref(),
        }
    }
}

/// Lands a composed merge (the merge record's §7, `land`).
///
/// The shot is followed by the claim's read and the record, the draft
/// landing by the record alone, each step read first — the draft's one
/// write under a per-session id the board answers again — so a second call
/// over the same `merged` in one session writes nothing twice. In another
/// session the board holds no memo of the write into a draft named: typed
/// against the position its own landing moved the draft past, it is refused
/// `arrangement_moved`, nothing written, naming that landing and its
/// record, written or not, with [`resume`] the way on where the draft still
/// holds M. A merge
/// composed again after an undo or a withdrawal lands as a write of its
/// own, in the same session or another: its ids name the position it was
/// composed at, and the take-back's record leaves no record standing for
/// it, so it writes its own. One composed again with no take-back between
/// and landed in the draft the standing record names lands its write under
/// its own ids and writes no record: the same landing (skep #790). A draft
/// landing reads the merger's newest record for the key before any write,
/// whatever the composition saw. With a draft named, the ids name the
/// record the landing follows, so the same `merged` landed again into its
/// draft after a take-back recorded since is a write of its own, which the
/// board judges: typed against the position the merge was composed at,
/// which the landing taken back moved the draft past, it is refused
/// `arrangement_moved` with nothing written. With no draft named, a draft
/// landing that record names is the answer, in any session, with nothing
/// staged and [`Landed::Draft`]'s `staged` false; a take-back's record
/// leaves the key open, so the same `merged` landed again stages a draft of
/// its own, the stage's id naming that record, its `staged` true.
///
/// # Errors
///
/// In this order:
///
/// - [`Refusal::OverCap`], before any frame;
/// - the reads' refusals, for a member already holding M or for the
///   merger's newest record for the key at a draft landing;
/// - a journal named that cannot take the record, before the landing's
///   first write with nothing sent (P13): one this merger may not read, one
///   this board does not register or another account's, as
///   [`Refusal::Halt`] naming the journal and the check it fails; a
///   published one of the merger's own, as [`Refusal::PublishedJournal`];
///   the journal's `doc_metadata` read's other refusals and halts;
/// - the reads' refusals for the draft's `doc_metadata` at the position the
///   write is typed against;
/// - a claimed board serving no head record, as [`Refusal::Halt`] naming
///   `H.1`, before the shot, with nothing sent; and the `H.1` and `/health`
///   reads' halts (SP-14);
/// - the shot's: the skip reads' refusals at the daughters, then the value
///   reads', [`Refusal::WindowWithheld`],
///   [`Refusal::NeedsSignedSession`], [`Refusal::NoSuchDocument`], the
///   board's `not_owner` naming the draft side as [`Refusal::UnownedDraft`],
///   `supersede_refused` as [`Refusal::SupersedeRefused`] — at `head_moved`
///   the trunk's head named, the merge to compose again on it, nothing
///   committed and nothing re-sent —
///   `already_published` and `publication_over_budget` verbatim as
///   [`Refusal::Halt`] (never the library's fault),
///   `attestation_invalid:board_unavailable` faced as the head the board
///   owes, nothing landed, `attestation_required` at a shot sent unsigned
///   answered by its one signed re-send, a head the second read does not
///   find faced as the head the board owes, nothing landed, and a lost
///   acknowledgment as the dialer's halt after one re-ask, for [`resume`]
///   to complete — or the draft landing's: the
///   stage's refusals where a fresh draft is staged ([`Refusal::Unreadable`]
///   and [`Refusal::NoSuchDocument`] naming the head, the first never met at
///   a version member, which is published), then the one write's
///   — `arrangement_moved` as the board's verdict, [`Refusal::Halt`] with
///   `Refused` naming this merge's own landing where it moved the draft
///   after the composition, [`resume`] the way on where the draft holds M,
///   else the draft that changed after the merge was composed and that
///   nothing was merged, or the refusals of the draft's reads after it,
///   each as itself; [`Refusal::ForkBaseMoved`];
///   [`Refusal::BaseNotInChain`]; [`Refusal::WindowWithheld`];
///   [`Refusal::NeedsSignedSession`]; [`Refusal::NoSuchDocument`] naming
///   the draft; `source_not_registered`, `no_base_to_record` and
///   `base_extent_too_large` as the library's own faults, since it names
///   the head and the extent the merge read, and a base only where the
///   draft records one at the position the write is typed against — and a
///   lost acknowledgment as the dialer's halt, with no re-ask;
/// - the claim's and the record's reads' refusals; the account's journal
///   not found for a board too busy to answer the find, past its bounded
///   reissues, a journal whose extent read answers `withheld` or
///   `doc_not_registered`, or a journal named whose atom the board refuses
///   as another account's or a published one, each faced as the landing
///   standing with its record unwritten, nothing of the record written, for
///   [`resume`] to record; then the record's writes', and
///   [`Refusal::NeedsSignedSession`] at its link.
///
/// At any step the library's own faults, the board's other refusals
/// verbatim and transport halts are [`Refusal::Halt`]; the death signal
/// under the merger's token is [`Refusal::SessionEnded`], its face naming
/// the step it met and [`resume`] as the way on.
///
/// # Panics
///
/// Panics if a landing that shoots answers none; the walk with `shoot` on
/// answers one on every path, so the `expect` never fires.
pub fn land(board: &Board, merged: &Merged, landing: Landing<'_>) -> Result<Landed, Refusal> {
    walk(board, merged, landing, true)
        .map(|landed| landed.expect("a landing that shoots answers a landing"))
}

/// Completes a landing whose acknowledgment was lost — the residue walk.
///
/// Where the shot landed and its acknowledgment was lost, the walk (the
/// merge record's §1.5, P14) finds the member whose first `placed`
/// positions equal M — the trunk's next member, else a daughter of the
/// head, which it reports as [`Landed::AsDaughter`] — or the landing the
/// board marks in the draft named, at the position it marks, the draft
/// holding M, and completes the record, after the claims' read for the
/// trunk's member — a landed shot carried its claims, so the member is
/// found with them (the module's doc) — writing nothing twice; `None` where
/// nothing landed, with nothing written: a shot refused whole left nothing
/// to find. The draft's mark is the marker naming this merge, or on a draft
/// with no recorded base its latest `set_arrangement` row naming it, never
/// the draft's words: a landing withdrawn or undone, its mark cleared, is
/// no landing to resume, whatever the draft holds (R2); nor is a marker the
/// draft inherited when it was staged from a draft the merge landed in,
/// whose `at` is the draft's own mint (P2). A draft landing
/// reads the merger's newest record for the key first, as [`land`] does, so
/// the record it completes goes under the landing's own ids; a fresh
/// landing names no draft to read, and that record is its answer where it
/// names a draft landing, else `None`. It stages nothing, so a draft landing
/// it answers carries `staged` false. It reads no head: it sends no write
/// but the record's, which a private journal takes unsigned.
///
/// # Errors
///
/// As [`land`]'s but the check of a journal named, the head's and the
/// shot's, the stage's and the draft's write's: it sends no write before
/// the record, so a journal it is given is met at the record alone. A draft
/// named is read as it stands — its `doc_metadata`, the feed walk's pages
/// on a draft with no recorded base, and its `image` where the board marks
/// the landing — each refusal answered as itself, never as no landing
/// (SP-14).
pub fn resume(
    board: &Board,
    merged: &Merged,
    landing: Landing<'_>,
) -> Result<Option<Landed>, Refusal> {
    walk(board, merged, landing, false)
}

/// Records a merge a publication of the merger's own landed (the merge
/// record's §1.5 (ii); the merge bridge lane).
///
/// `member` and `position` are the member and the commit position that
/// publication acknowledged — the editor's shot, composed through the
/// publication family from the draft the merge was landed in and carrying
/// the daughters as its `supersede`, or any shot of the merger's that
/// minted the member — and `merged` the composition the record describes.
/// No shot is sent: the claims are read at the daughters as the landing
/// reads them after its own shot (`Writer::claims_standing`), the
/// merger's newest record for the key is read, and the record is written
/// through the one record writer — `landed` the member at the position,
/// `claims` as read, `replaces` the newest — under the shot's per-session
/// ids (the module's doc), unless the newest record already names the
/// member as landed in, which is answered with nothing written (P4, P14).
/// It never runs the shot landing's read-first: a member the person edited
/// before publishing holds other runs than M, which [`land`] with
/// [`Landing::Shot`] would read as no landing and shoot M again.
///
/// # Errors
///
/// A member outside `merged`'s document's chain, as the library's own fault
/// ([`Refusal::Halt`]), nothing read; then as [`land`]'s from the claims'
/// reads on — the record is this call's first write, so a journal named is
/// met at the record alone: the claims' and the record's reads' refusals, a
/// journal this merger may not read or this board does not register, or
/// one named that is another account's or published, faced as the landing
/// standing with its record unwritten, and the record's writes'.
/// The death signal under the merger's token is [`Refusal::SessionEnded`],
/// its way on this call made again: it reads the record first and writes
/// it once, where [`resume`] would read no landing in a member the person
/// edited before publishing.
pub fn record_published(
    board: &Board,
    merged: &Merged,
    merger: Merger<'_>,
    member: &Address,
    position: u64,
    journal: Option<&Address>,
) -> Result<Landed, Refusal> {
    if version_components(&merged.inputs.doc, member).is_none() {
        return Err(own_fault_face(
            "the member is no version of the merged document",
            format!("{member} lies outside the chain of {}", merged.inputs.doc),
        ));
    }
    let writer = Writer::new(board, merger, OnEnd::Rerun);
    let claims = writer.claims_standing(merged, member)?;
    let landed = RecordLanding::Member { member: member.clone(), position };
    let newest = writer.newest_record(merged)?;
    let record = match newest.naming(&landed) {
        Some(link) => link.clone(),
        None => {
            let stem = Stem::of(&merged.key.text());
            writer.write_landing_record(merged, landed, &claims, &newest, &stem, journal)?
        }
    };
    Ok(Landed::Member {
        address: member.clone(),
        position,
        claims,
        record,
        retries: merged.inputs.options.retries,
    })
}

/// Runs the landing's steps, each read first.
///
/// They are the shot, the claim's read and the record, or the draft landing
/// and the record. `shoot` is whether a landing not found standing is made.
/// A journal named is checked once, after the read-first steps and before
/// the landing's first write ([`Writer::check_journal`]); a landing found
/// standing writes nothing before its record and checks none.
///
/// # Errors
///
/// As [`land`]'s, or as [`resume`]'s with `shoot` off.
fn walk(
    board: &Board,
    merged: &Merged,
    landing: Landing<'_>,
    shoot: bool,
) -> Result<Option<Landed>, Refusal> {
    let (m, cap) = (merged.composed.counts.m, merged.cap);
    if m > cap {
        return Err(Refusal::OverCap { runs: m, cap });
    }
    let merger = landing.merger();
    let writer = Writer::new(board, merger, OnEnd::Resume);
    let check_journal = || writer.check_journal(landing.journal(), "the merge cannot land");
    match &landing {
        Landing::Shot { draft, .. } => {
            let (member, position) = match writer.standing_member(merged)? {
                Standing::Trunk(member, at) => (member, at),
                Standing::Daughter(address, position) => {
                    return Ok(Some(Landed::AsDaughter { address, position }))
                }
                Standing::Absent => {
                    if !shoot {
                        return Ok(None);
                    }
                    check_journal()?;
                    let (address, position) = writer.publish(merged, draft.as_ref())?;
                    if !is_trunk_member(&merged.inputs.doc, &address) {
                        return Ok(Some(Landed::AsDaughter { address, position }));
                    }
                    (address, position)
                }
            };
            let claims = writer.claims_standing(merged, &member)?;
            let landed = RecordLanding::Member { member: member.clone(), position };
            let newest = writer.newest_record(merged)?;
            let record = match newest.naming(&landed) {
                Some(link) => link.clone(),
                None => {
                    let stem = Stem::of(&merged.key.text());
                    let journal = landing.journal();
                    writer.write_landing_record(merged, landed, &claims, &newest, &stem, journal)?
                }
            };
            Ok(Some(Landed::Member {
                address: member,
                position,
                claims,
                record,
                retries: merged.inputs.options.retries,
            }))
        }
        Landing::Draft { into, .. } => {
            // The merger's newest record for the key, read from the board
            // before any write: the record a named draft's ids follow, and a
            // fresh landing's answer where it names a draft landing. The
            // stage and the one write write no record, so it is the record
            // step's read too.
            let newest = writer.newest_record(merged)?;
            // The draft, the position the write is typed against, the text
            // the landing's per-session ids are spelled over (the module's
            // doc), and whether this call staged the draft: for a draft
            // named, the merge's one position and the record the landing
            // follows, so a landing composed after a take-back, into another
            // draft, or into its draft again after a take-back recorded
            // since, is a write of its own; for a fresh draft, the stage's
            // own draft and position.
            let (into, as_of, text, staged) = match into {
                Some(into) => {
                    if shoot {
                        check_journal()?;
                    }
                    let text = format!("{}:{into}@{}", merged.key.text(), merged.as_of);
                    let text = match newest.follows(into) {
                        Some(link) => format!("{text}~{link}"),
                        None => text,
                    };
                    (into.clone(), merged.as_of, text, false)
                }
                None => {
                    if let Some(standing) = newest.draft_landing() {
                        return Ok(Some(standing));
                    }
                    if !shoot {
                        return Ok(None);
                    }
                    check_journal()?;
                    let (fresh, at) = writer.stage(merged, &newest)?;
                    let text = format!("{}:{fresh}@{at}", merged.key.text());
                    (fresh, at, text, true)
                }
            };
            let stem = Stem::of(&text);
            let Some((position, head_moved)) =
                writer.land_into_draft(merged, &into, as_of, &stem, &newest, shoot)?
            else {
                return Ok(None);
            };
            let landed = RecordLanding::Draft { draft: into.clone(), position };
            let record = match newest.naming(&landed) {
                Some(link) => link.clone(),
                None => {
                    let journal = landing.journal();
                    writer.write_landing_record(merged, landed, &[], &newest, &stem, journal)?
                }
            };
            Ok(Some(Landed::Draft { into, position, record, head_moved, staged }))
        }
    }
}

/// Whether a member already holds the merge.
enum Standing {
    /// No member of the head's reach holds M.
    Absent,
    /// The trunk's next member holds M, minted at this position.
    ///
    /// Where the feed holds no row of the mint, the position is the reads'
    /// highest `as_of`.
    Trunk(Address, u64),
    /// A daughter of the head holds M: the shot landed under a moved head.
    Daughter(Address, u64),
}

/// What one member of the chain holds against M.
enum Holds {
    /// Not registered.
    Nothing,
    /// Another arrangement, or one this reader cannot read.
    Other,
    /// M over its first `placed` positions, minted at this position.
    ///
    /// Where the feed holds no row of the mint, the position is the reads'
    /// highest `as_of`.
    Merged(u64),
}

/// The stem of a landing write's per-session ids (wire.md §Correlation and
/// idempotency; the merge record's §1.5).
///
/// It is `merge:` and the lowercase hex of the SHA-256 of the text naming
/// the write (the module's doc), 70 bytes whatever the text, so every id a
/// landing sends stays inside the 256-byte id cap skepd holds at parse
/// (skep-febe's `MAX_REQ_ID_BYTES`; a longer id is refused `malformed`),
/// however many sides the key spells and however deep their addresses.
/// Equal texts give equal stems and distinct texts distinct ones, so the
/// board's memo answers a second call over one write and never another
/// write's.
pub(super) struct Stem(String);

impl Stem {
    /// Returns the stem of the write `text` names.
    pub(super) fn of(text: &str) -> Stem {
        Stem(format!("merge:{}", crate::hex::encode(&Sha256::digest(text.as_bytes()))))
    }

    /// Returns the id `<stem>.<suffix>` of one of the write's frames.
    pub(super) fn id(&self, suffix: &str) -> String {
        format!("{}.{suffix}", self.0)
    }

    /// Returns the stem's text.
    fn as_str(&self) -> &str {
        &self.0
    }
}

/// The merger's newest record for the key, as the landing read it.
///
/// Only [`Writer::newest_record`] builds one, from the board, so what a
/// landing finds standing, the record a draft landing's ids follow and the
/// record it writes replaces are the board's state at the landing (P20),
/// never what the composition saw. Empty where no record of the merger's
/// own of the key stands.
struct Newest(Option<(Address, Record)>);

impl Newest {
    /// Returns the newest record's link: what a record written now replaces.
    fn link(&self) -> Option<&Address> {
        self.0.as_ref().map(|(link, _)| link)
    }

    /// Returns the record a landing into `draft` follows, which its ids name.
    ///
    /// It is the newest record's link, or — where that record names `draft`
    /// as landed in — the link it replaces: the record is then this
    /// landing's own, met on a retry, or the first landing's, which a
    /// landing of the key into the same draft keeps (skep #790), and either
    /// follows the record that stood before it. So every call over one
    /// landing names one record, and a landing after a take-back recorded
    /// since names the take-back's. `None` where no record stands, or where
    /// the one naming `draft` replaces none.
    fn follows(&self, draft: &Address) -> Option<&Address> {
        let (link, record) = self.0.as_ref()?;
        match &record.landed {
            Some(RecordLanding::Draft { draft: landed, .. }) if landed == draft => {
                record.replaces.as_ref()
            }
            _ => Some(link),
        }
    }

    /// Returns the newest record's link where it names `landed`.
    ///
    /// It does where both land in the same member, or both in the same
    /// draft, whatever either's position. An undo's or a withdrawal's
    /// record names no landing and a landing of the key elsewhere names
    /// another, so either leaves nothing standing for `landed`.
    ///
    /// **The same landing (skep #790).** A landing of the key into the
    /// draft the newest record names — no take-back recorded since, whether
    /// the draft was edited in between or a take-back's record went
    /// unwritten — is that record's landing: its write lands, and no record
    /// is written. The record keeps the first landing's body and position,
    /// while the draft's marker, or for a baseless draft its feed row, names
    /// the later write. Nothing that writes reads that position: the undo
    /// goes by the marker's `at` or the feed row, the withdrawal by its own
    /// read, and a take-back's record names this one by its link, carrying
    /// no landing. `verify` reads the draft at it, where the draft held the
    /// first landing's M, and a fresh landing that finds the record standing
    /// answers it ([`Newest::draft_landing`]).
    fn naming(&self, landed: &RecordLanding) -> Option<&Address> {
        let (link, record) = self.0.as_ref()?;
        let same = match (record.landed.as_ref()?, landed) {
            (RecordLanding::Member { member: a, .. }, RecordLanding::Member { member: b, .. }) => {
                a == b
            }
            (RecordLanding::Draft { draft: a, .. }, RecordLanding::Draft { draft: b, .. }) => {
                a == b
            }
            _ => false,
        };
        same.then_some(link)
    }

    /// Returns the draft landing the newest record names, found standing.
    ///
    /// It is a fresh landing's answer with nothing staged: the draft, the
    /// position the record names and the record's link, with no newer head
    /// told and `staged` false. `None` where the newest names no draft
    /// landing or none stands.
    fn draft_landing(&self) -> Option<Landed> {
        let (link, record) = self.0.as_ref()?;
        let Some(RecordLanding::Draft { draft, position }) = &record.landed else {
            return None;
        };
        Some(Landed::Draft {
            into: draft.clone(),
            position: *position,
            record: link.clone(),
            head_moved: None,
            staged: false,
        })
    }
}

/// The landing's writer: the merger and a reader under its token.
///
/// The undo and the withdrawal (the `undo` module) write through it too:
/// the journal's check, the one write and the record are theirs as the
/// landing's. Its reads and writes face a session's end alike, for the
/// one act it was built for: its reader's [`OnEnd`].
pub(super) struct Writer<'a> {
    pub(super) board: &'a Board,
    pub(super) merger: Merger<'a>,
    pub(super) reader: Reader<'a>,
}

impl<'a> Writer<'a> {
    /// Returns a writer over `board` as `merger`, its reader under the
    /// merger's token, for an act whose session's end leaves `on_end`.
    pub(super) fn new(board: &'a Board, merger: Merger<'a>, on_end: OnEnd) -> Writer<'a> {
        Writer { board, merger, reader: Reader::new(board, Some(merger.token), on_end) }
    }
}

impl Writer<'_> {
    /// Finds the member that already holds M, the shot's read-first.
    ///
    /// It reads the trunk's next member, then — where that is another's —
    /// the head's daughters in order until the first absent.
    ///
    /// # Errors
    ///
    /// A member's reads' refusals, as `holds` answers them; a head or a
    /// daughter whose address cannot be spelled, as the library's own fault.
    fn standing_member(&self, merged: &Merged) -> Result<Standing, Refusal> {
        let head = &merged.inputs.head;
        let next = next_trunk_member(head).ok_or_else(|| {
            own_fault_face(
                "the head's next member cannot be spelled",
                format!("{head} has no component to count on"),
            )
        })?;
        match self.holds(merged, &next)? {
            Holds::Merged(at) => return Ok(Standing::Trunk(next, at)),
            Holds::Nothing => return Ok(Standing::Absent),
            Holds::Other => {}
        }
        for k in 1u64.. {
            let daughter = daughter_of(head, k).ok_or_else(|| {
                own_fault_face(
                    "a daughter's address cannot be spelled",
                    format!("{head} extended by {k}"),
                )
            })?;
            match self.holds(merged, &daughter)? {
                Holds::Merged(at) => return Ok(Standing::Daughter(daughter, at)),
                Holds::Nothing => return Ok(Standing::Absent),
                Holds::Other => {}
            }
        }
        Ok(Standing::Absent)
    }

    /// Returns whether `member` holds M over its first `placed` positions.
    ///
    /// # Errors
    ///
    /// The member's reads' refusals but `withheld`, a `doc_not_registered`
    /// on its metadata and a member too fragmented to image, which answer as
    /// what it holds; an `image` run that is no content I-address; the feed
    /// walk's halts.
    fn holds(&self, merged: &Merged, member: &Address) -> Result<Holds, Refusal> {
        let meta = match self.reader.metadata(member, None) {
            Ok(m) => m,
            Err(Refusal::NoSuchDocument(_)) => return Ok(Holds::Nothing),
            Err(Refusal::Unreadable(_)) => return Ok(Holds::Other),
            Err(e) => return Err(e),
        };
        let Some(placed) = meta.placed else { return Ok(Holds::Other) };
        let image = match self.reader.image(member, None, 1, placed) {
            Ok(runs) => runs,
            Err(Refusal::Unreadable(_)) | Err(Refusal::TooFragmented { .. }) => {
                return Ok(Holds::Other)
            }
            Err(e) => return Err(e),
        };
        let actual = runs_of(&image)?;
        let expected: Vec<(Run, Family)> = merged
            .composed
            .runs
            .iter()
            .map(|p| p.run.clone())
            .zip(merged.families.iter().copied())
            .collect();
        if first_difference(&expected, &actual, &merged.inputs.doc).is_some() {
            return Ok(Holds::Other);
        }
        let at = position_of(&self.reader, member)?.unwrap_or_else(|| self.reader.as_of());
        Ok(Holds::Merged(at))
    }

    /// Sends the shot, answering the member minted and the ack's position.
    ///
    /// The frame and its body go through the publication's request builder
    /// with the daughters as its one deposit list and no place — every
    /// copied run's values re-read through the side that holds them, every
    /// window by address, the base group the head and its extent as read,
    /// `supersede` the `Member` sides with the skip read first
    /// ([`Writer::daughters`]) — then the frame with its `attest` and its
    /// id, one re-ask under the same id on a lost acknowledgment, and the
    /// frame sent once more, signed, under the same id where it went
    /// unsigned and a claim landed past the head's read
    /// ([`Writer::attest_after_claim`]).
    ///
    /// # Errors
    ///
    /// The head's refusal and halts ([`Writer::signing_term`]), read before
    /// the values, nothing sent, and read again after a claim, nothing sent
    /// past it; the skip reads' refusals at the daughters;
    /// [`Refusal::WindowWithheld`],
    /// [`Refusal::NeedsSignedSession`] and [`Refusal::NoSuchDocument`] as the
    /// board answers them; `not_owner` naming the draft side as
    /// [`Refusal::UnownedDraft`], `supersede_refused` as
    /// [`Refusal::SupersedeRefused`] with its entry and cause,
    /// `already_published` and
    /// `publication_over_budget` as the board's refusal verbatim, never this
    /// library's fault, and `attestation_invalid:board_unavailable` faced as
    /// the head the board owes; the value reads' refusals; the attest's
    /// fault; a body past [`SHOT_BODY_BUDGET`], a run with no address, a
    /// window of width 0, and the board's refusal of the frame's substance —
    /// the shot's own table, a place's or another deposit's token, which this
    /// frame never carries — as the library's own faults; an answer of a
    /// shape this client does not know, faced; the death signal,
    /// [`Refusal::SessionEnded`]; a dial fault after the one re-ask; the
    /// board's other refusals verbatim.
    fn publish(&self, merged: &Merged, draft: Option<&Address>) -> Result<(Address, u64), Refusal> {
        let term = self.signing_term()?;
        let doc = &merged.inputs.doc;
        let head = &merged.inputs.head;
        let supersede = self.daughters(merged)?;
        let draft_side = merged.inputs.sides.iter().find_map(|s| match s {
            Side::Draft { at, .. } => Some(at.clone()),
            _ => None,
        });
        let fresh = merged.families.contains(&Family::DraftNative);
        let draft = draft.cloned().or(if fresh { draft_side } else { None });
        let mut runs = Vec::with_capacity(merged.composed.runs.len());
        let mut pieces = Vec::with_capacity(merged.composed.runs.len());
        for (placed, family) in merged.composed.runs.iter().zip(&merged.families) {
            let run = &placed.run;
            let i_start = run
                .address_at(0)
                .ok_or_else(|| own_fault_face("a run of M names no address", format!("{run:?}")))?;
            runs.push(publication::Run::new(run.origin.clone(), run.i_start, run.width));
            match family {
                Family::Window => {
                    if run.width == 0 {
                        return Err(own_fault_face("a window of width 0", format!("{run:?}")));
                    }
                    pieces.push(Piece::Window { start: i_start, width: run.width });
                }
                Family::Own | Family::DraftNative => {
                    let items = values_for(
                        &self.reader,
                        &merged.maps,
                        placed.side.map(|s| s.0 as usize),
                        run,
                    )?;
                    pieces.push(Piece::Values(items));
                }
            }
        }
        // THE REQUEST BUILDER, with the daughters alone: the merge's delta
        // from a publication is no other deposit and no place, in either
        // list.
        let n = runs.len();
        let request = publication::Request {
            doc: Some(doc.clone()),
            mint: None,
            claim: false,
            base: Some((head.clone(), merged.head_extent)),
            draft: draft.clone(),
            also: Vec::new(),
            runs,
            places: vec![None; n],
            also_places: Vec::new(),
            stray_records: vec![0; n],
            pieces,
            entries: Vec::new(),
            retract: Vec::new(),
            originals: Vec::new(),
            read_with: Vec::new(),
            supersede,
            unspellable: Vec::new(),
            id: Stem::of(&merged.key.text()).id("publish"),
            count: publication::Count::default(),
            price: publication::Price::default(),
            as_of: self.reader.as_of(),
        };
        let body = request.body();
        if body.as_bytes().len() > SHOT_BODY_BUDGET {
            return Err(own_fault_face("the shot's body cannot be composed", format!("the merged list's values pass what one shot's body may carry ({SHOT_BODY_BUDGET} bytes)")));
        }
        let mut v = self.shoot(&request.frame(self.attest(term, doc, &body)?))?;
        // A claim landed past the head's read: the shot once more, signed,
        // under its own id (the module's doc).
        if let Some(attest) = self.attest_after_claim(term, &v, doc, &body)? {
            v = self.shoot(&request.frame(Some(attest)))?;
        }
        if let (Some(addr), Some(at)) = (acked_addr(&v), acked_at(&v)) {
            let member = parse_address(addr).ok_or_else(|| shape_face("publish", &v))?;
            return Ok((member, at));
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("publish", &v).into()) };
        let site = r.site().addr.as_deref().and_then(parse_address);
        Err(match r.key() {
            "withheld" => Refusal::WindowWithheld(site.unwrap_or_else(|| doc.clone())),
            "signed_session_required" => Refusal::NeedsSignedSession,
            "doc_not_registered" => Refusal::NoSuchDocument(doc.clone()),
            // The publication's own refusals of the shot: the unowned draft
            // side named, the twin fence's member and the budget's detail
            // verbatim.
            "not_owner" if site.is_some() && site == draft => match site.clone() {
                Some(draft) => Refusal::UnownedDraft { draft },
                None => own_fault("the shot", &r),
            },
            // The plan's judgement of the daughters, typed: the board's
            // verdict, never this frame's fault; a detail this client does
            // not know rides verbatim.
            "supersede_refused" => match SupersedeCause::of(r.detail(), r.site()) {
                Some(cause) => {
                    Refusal::SupersedeRefused { index: r.site().index.unwrap_or(0), cause }
                }
                None => Refusal::Halt(r.refused(&v)),
            },
            "already_published" | "publication_over_budget" => Refusal::Halt(r.refused(&v)),
            "base_superseded"
            | "base_not_in_chain"
            | "base_extent_too_large"
            | "bad_run"
            | "dangling_source"
            | "source_not_registered"
            | "not_owner"
            | "too_many_runs"
            | "too_many_values"
            | "private_source_versionless"
            | "kept_place_moved"
            | "stray_place_unrecorded"
            | "link_home_refused"
            | "old_refused"
            | "duplicate_original"
            | "read_with_in_links"
            | "retract_refused"
            | "read_with_refused"
            | "malformed" => own_fault("the shot", &r),
            // The board's state, never this library's frame (a reorder).
            "attestation_invalid:board_unavailable" => head_owed(format!(
                "{}: the board refused the shot, serving no head record (`H.1`) to verify its signature over — a head the board owes, never this library's frame",
                r.token()
            ))
            .into(),
            k if k.starts_with("attestation_") => own_fault("the shot's attest", &r),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Sends the shot's frame, answering the board's document.
    ///
    /// A lost acknowledgment is re-asked once under the same id in the same
    /// session (§1.5: the per-session idempotency key), else `resume`.
    ///
    /// # Errors
    ///
    /// The death signal, [`Refusal::SessionEnded`]; a dial fault after the
    /// one re-ask; the frame's other halts.
    fn shoot(&self, frame: &Value) -> Result<Value, Refusal> {
        let answer = match self.board.op(Some(self.merger.token), frame) {
            Err(Halt::Dial(_)) => self.board.op(Some(self.merger.token), frame)?,
            other => other?,
        };
        match answer {
            Answer::Closed => Err(session_ended("publishing the merge", self.reader.on_end())),
            Answer::Document(v) => Ok(v),
        }
    }

    /// Returns the `attest` a shot sent unsigned is sent again with, where a
    /// claim landed past the head's read.
    ///
    /// The shot went out with `sent_with`, the term [`Writer::signing_term`]
    /// read before it; where that was none — a board read as no one's — and
    /// the board answered `v` refusing it `attestation_required`, a claim
    /// landed between the read and the shot's turn, its head written, and
    /// the board refused the shot before its transaction (wire.md
    /// §Credential refusals, a reorder). The head is read again and the
    /// `attest` composed over `body`, the shot's `doc` row `doc`, for the
    /// shot's one re-send under its own id: the refusal left the id
    /// unmemoized (wire.md §Correlation and idempotency). `None` where the
    /// shot went signed, or `v` is another answer: a signed shot refused so
    /// is the shot's own fault arm.
    ///
    /// # Errors
    ///
    /// The second read's: a head that stands and cannot be read; a claimed
    /// board serving no head record, faced as [`head_owed`]; and one serving
    /// none with no claimant named, faced the same, naming the board's token
    /// — the board refused the shot for want of a signature this read finds
    /// no head to make. Then the attest's fault. Nothing is sent past any of
    /// them.
    fn attest_after_claim(
        &self,
        sent_with: Option<BoardTerm>,
        v: &Value,
        doc: &Address,
        body: &EntryBody,
    ) -> Result<Option<Value>, Refusal> {
        if sent_with.is_some() {
            return Ok(None);
        }
        let Some(r) = Rejection::of(v).filter(|r| r.key() == "attestation_required") else {
            return Ok(None);
        };
        let Some(term) = self.signing_term()? else {
            return Err(head_owed(format!(
                "{}: the board refused the shot for want of its signature and serves no head record (`H.1`) to sign it over",
                r.token()
            ))
            .into());
        };
        self.attest(Some(term), doc, body)
    }

    /// Returns the shot's `supersede`: the daughters — every `Member` side,
    /// in side order — with THE SKIP read first, as the board's plan decides
    /// it: `in_claims{y: the daughter, view: active}` at each, one an active
    /// claim of the merger's own already names dropped, so the body signed
    /// is the body the board composes (the module's doc). A draft side and a
    /// fork side name no daughter.
    ///
    /// # Errors
    ///
    /// The `in_claims` read's refusal at a daughter.
    fn daughters(&self, merged: &Merged) -> Result<Vec<Address>, Refusal> {
        let mut out = Vec::new();
        for side in &merged.inputs.sides {
            let Side::Member(daughter) = side else { continue };
            let v =
                self.reader.answered(daughter, &frames::in_claims(&daughter.to_string()), None)?;
            if !own_claim_names(&answers::claims(&v), self.merger.account) {
                out.push(daughter.clone());
            }
        }
        Ok(out)
    }

    /// Returns the claims' read: the active claims whose `new` is the member,
    /// read at each daughter after the shot — the claims the shot deposited
    /// (the module's doc), each homed in the trunk, and any another writer
    /// filed naming the member.
    ///
    /// # Errors
    ///
    /// The `in_claims` read's refusal at a daughter.
    fn claims_standing(&self, merged: &Merged, member: &Address) -> Result<Vec<Address>, Refusal> {
        let mut out = Vec::new();
        let member = member.to_string();
        for side in &merged.inputs.sides {
            let Side::Member(daughter) = side else { continue };
            let v =
                self.reader.answered(daughter, &frames::in_claims(&daughter.to_string()), None)?;
            for claim in answers::claims(&v) {
                if claim.active && claim.new == member {
                    if let Some(a) = parse_address(&claim.claim) {
                        out.push(a);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Returns the record's read: the merger's newest record for the key.
    ///
    /// It is the merger's current record for the key (the merge record's
    /// §1.5 (ii), read first as §1.3's step 7 reads; §4's currency, newest
    /// per key), read by the landing from the board. It is found as the
    /// composition's prior records are, by the links of the kind to each
    /// side of the key, each homed in the journal holding its record, and
    /// kept to the merger's own account, exactly: the newest of those by the
    /// order their links were minted, in whichever of its journals, is the
    /// record. A record of the key in another account's journal — a
    /// sub-account's among them — is never the merger's: its landing is
    /// another's, and a record names in `replaces` one of its own account's
    /// (P20). It stands for a landing it names ([`Newest::naming`]); one
    /// naming no landing or another — an undo's or a withdrawal's, or a
    /// landing of the key elsewhere — replaced the record of this landing. A
    /// landing into a draft named spells its ids over the record it follows
    /// ([`Newest::follows`]).
    ///
    /// # Errors
    ///
    /// A halt reading the links or a record.
    fn newest_record(&self, merged: &Merged) -> Result<Newest, Refusal> {
        let own = records_of(&self.reader, &merged.inputs.kind, &merged.key)?
            .into_iter()
            .filter(|f| f.lies_in(self.merger.account));
        Ok(Newest(newest(own).map(|f| (f.link, f.record))))
    }

    /// Writes a landing's record, answering its link's address.
    ///
    /// The record is the composition's with `landed` and `claims` filled
    /// and `replaces` the link of `newest`, the merger's newest record for
    /// the key as the landing read it — none where none stands (P20). It is
    /// written through [`Writer::write_record`] under `stem` — the shot's,
    /// over the key, or the draft landing's, over the key, the draft, the
    /// position its write is typed against and, for a draft named, the
    /// record the landing follows (the module's doc) — the link's first end
    /// the landed address, and a journal it cannot find or write into faced
    /// as the landing standing with its record unwritten ([`record_owed`]).
    ///
    /// # Errors
    ///
    /// [`Writer::write_record`]'s.
    fn write_landing_record(
        &self,
        merged: &Merged,
        landed: RecordLanding,
        claims: &[Address],
        newest: &Newest,
        stem: &Stem,
        journal: Option<&Address>,
    ) -> Result<Address, Refusal> {
        let target = match &landed {
            RecordLanding::Member { member, .. } => member.clone(),
            RecordLanding::Draft { draft, .. } => draft.clone(),
        };
        let mut record = merged.record.clone();
        record.landed = Some(landed.clone());
        record.claims = claims.to_vec();
        record.replaces = newest.link().cloned();
        let owed = |why: Unwritten, cause: String| record_owed(&landed, &why, cause);
        self.write_record(&merged.inputs.kind, &record, &target, stem.as_str(), journal, &owed)
    }

    /// Writes `record` under `kind`, answering its link's address.
    ///
    /// The journal is found or minted, the atom appended at its end as a
    /// plain insert, and the link homed in the journal beside it, from the
    /// atom to `target` — the landed address, or the draft an undo or a
    /// withdrawal names — and every side of the record besides its head
    /// under the kind (§4, "Its home"). Both are writes into a private
    /// draft, which takes no `attest`, so no head is read and nothing is
    /// signed. The two writes carry the per-session ids `<stem>.record` and
    /// `<stem>.link`; `owed` faces the act standing with its record
    /// unwritten, for the [`Unwritten`] reason it is given: the account's
    /// journal not found, its find refused busy past the bounded reissues
    /// (the `journal` module's doc); a journal whose extent read answers
    /// `withheld` or `doc_not_registered`; or a journal named whose atom the
    /// board refuses `published_target` or `not_owner` — the caller's
    /// journal, where the account's own is this library's choice.
    ///
    /// # Errors
    ///
    /// The find of the account's journal refused busy past its reissues,
    /// faced by `owed` with nothing of the record sent; the journal's other
    /// refusals ([`journal::of`]); a journal this merger may not read or this
    /// board does not register, faced by `owed` with nothing of the record
    /// sent; the extent read's other refusals; a journal named whose atom the
    /// board refuses as published or another account's, faced by `owed` with
    /// nothing of the record written; the account's own journal refused so,
    /// a journal that is full, and a journal whose link this session may not
    /// make, as the library's own faults; an answer of a shape this client
    /// does not know, faced; [`Refusal::NeedsSignedSession`] at the link; the
    /// death signal, [`Refusal::SessionEnded`]; the board's other refusals
    /// verbatim.
    pub(super) fn write_record(
        &self,
        kind: &Address,
        record: &Record,
        target: &Address,
        stem: &str,
        journal: Option<&Address>,
        owed: &dyn Fn(Unwritten, String) -> Halt,
    ) -> Result<Address, Refusal> {
        let named = journal.is_some();
        let on_end = self.reader.on_end();
        let journal = match journal::found(self.board, &self.merger, kind, journal.cloned(), on_end) {
            Ok(journal) => journal,
            Err(Unfound::Busy(r)) => {
                return Err(owed(Unwritten::Busy, format!("{}: the board refused the find of the account's merge journal, a class scan, on its first send and its {SCAN_BUSY_REISSUES} reissues — every class-scan permit was in use — so no write of the record was sent", r.code)).into())
            }
            Err(Unfound::Other(r)) => return Err(r),
        };
        let text = record.to_value().to_string();
        // The journal's read at the record, after the act it records: a
        // journal the act cannot write its record into leaves the act
        // standing.
        let extent = self.reader.extent(&journal, None).map_err(|e| {
            let unfit = match e {
                Refusal::Unreadable(_) => Unfit::Withheld,
                Refusal::NoSuchDocument(_) => Unfit::Unregistered,
                e => return e,
            };
            Refusal::from(owed(Unwritten::Journal(journal.clone(), unfit), format!("the board refused the read of {journal}'s extent, the end the record's atom is appended at, so no write of the record was sent")))
        })?;
        let ordinal = extent.checked_add(1).ok_or_else(|| {
            own_fault_face(
                "the journal is full",
                format!("{journal} answered an extent with no ordinal after it"),
            )
        })?;
        // Typed against the state the extent was read at (skep #442): the
        // reader's highest `as_of`, which that read just raised.
        let v = self.answered_write(
            &frames::insert_plain_atom(
                &journal.to_string(),
                ordinal,
                &text,
                self.reader.as_of(),
                Some(&format!("{stem}.record")),
            ),
            "appending the record",
        )?;
        let atom = match acked_addr(&v) {
            Some(a) => parse_address(a).ok_or_else(|| shape_face("insert", &v))?,
            None => {
                let Some(r) = Rejection::of(&v) else {
                    return Err(shape_face("insert", &v).into());
                };
                // A journal the caller named is the caller's: the act stands
                // with its record unwritten. The account's own is this
                // library's choice, so its refusal is the library's fault.
                let refused = |unfit: Unfit| -> Refusal {
                    owed(Unwritten::Journal(journal.clone(), unfit), format!("{}: the board refused the record's atom into {journal}, so nothing of the record was written", r.token())).into()
                };
                return Err(match r.key() {
                    "published_target" if named => refused(Unfit::Published),
                    "not_owner" if named => refused(Unfit::Foreign),
                    "published_target" => own_fault_face("the journal is not a draft", format!("{}: the merge journal {journal} is published, and a record is appended as a plain insert into a draft", r.token())),
                    "not_owner" => own_fault_face("the journal is not this account's", format!("{}: {journal} is owned by another account", r.token())),
                    _ => Refusal::Halt(r.refused(&v)),
                });
            }
        };
        // The link homed in the journal, beside the record: the atom's unit
        // span to the target and every side of the record besides its head,
        // typed the kind (§4, "Its home") — a private draft's link, unsigned.
        let mut to: Vec<Address> = vec![target.clone()];
        for side in record.sides.iter().filter(|s| s.role() != Role::Head) {
            if !to.contains(side.address()) {
                to.push(side.address().clone());
            }
        }
        let atom_text = atom.to_string();
        let to_text: Vec<String> = to.iter().map(ToString::to_string).collect();
        let to_refs: Vec<&str> = to_text.iter().map(String::as_str).collect();
        let frame = frames::make_link(
            &journal.to_string(),
            &[&atom_text],
            &to_refs,
            &kind.to_string(),
            Some(&format!("{stem}.link")),
        );
        let v = self.answered_write(&frame, "linking the record")?;
        if let Some(link) = acked_addr(&v) {
            return parse_address(link).ok_or_else(|| shape_face("make_link", &v).into());
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("make_link", &v).into()) };
        Err(match r.key() {
            "not_owner" => own_fault_face(
                "this session does not own the journal its record's link is homed in",
                format!(
                    "{}: the record's link is homed in {journal}, the journal that took its atom",
                    r.token()
                ),
            ),
            "signed_session_required" => Refusal::NeedsSignedSession,
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Returns the current record naming `draft` as landed in.
    ///
    /// It is read through the links of `kind` to the draft, each record's
    /// atom through its journal, keeping the records whose `landed` is the
    /// draft, and answering the newest of them by the order their links
    /// were minted, with that link; a record whose journal the merger may
    /// not read is no candidate. `None` where none stands: the undo's and
    /// the withdrawal's record is then not written (the `undo` module's
    /// doc).
    ///
    /// # Errors
    ///
    /// The link read's refusal at the draft; a halt reading a record.
    pub(super) fn landed_record(
        &self,
        kind: &Address,
        draft: &Address,
    ) -> Result<Option<Record>, Refusal> {
        let v = self.reader.answered(
            draft,
            &frames::find_links_ftt(&kind.to_string(), &draft.to_string()),
            None,
        )?;
        let mut landed_here = Vec::new();
        for link in answers::addrs(&v) {
            let Some(link) = parse_address(link) else { continue };
            let Some(found) = read_record(&self.reader, &link)? else { continue };
            let landed = &found.record.landed;
            if matches!(landed, Some(RecordLanding::Draft { draft: d, .. }) if d == draft) {
                landed_here.push(found);
            }
        }
        Ok(newest(landed_here).map(|found| found.record))
    }

    /// Stages a fresh draft from the head, answering it and its position.
    ///
    /// It is `stage {from: the head the merge composed on}` (R3) under the
    /// per-session id `<stem>.stage`, its [`Stem`] over `<key>@<P>`, P the
    /// position the merge was composed at, or over `<key>@<P>~<link>` where
    /// `newest`, the merger's newest record for the key, stands — `<link>`
    /// its link, the record the landing's own will replace. A retry of the
    /// same landing reads the same newest record, so it is answered its
    /// stage again; one composed after a take-back stages afresh, and so
    /// does the same composition landed again after its landing was taken
    /// back, whose newest record is the take-back's. The board mints a
    /// private draft of the merger's account holding the head by identity
    /// and records the head as its base, so the write that follows
    /// re-records that base on the same head. A private draft's mint, it
    /// carries no `attest` and reads no head (the module's doc).
    ///
    /// # Errors
    ///
    /// [`Refusal::Unreadable`] and [`Refusal::NoSuchDocument`] naming
    /// the head, as the board's `withheld` and `source_not_registered` on the
    /// stage's source — the first never met at a version member, since every
    /// member of a published chain is published (wire.md §Arrangement,
    /// `version`); an answer of a shape this client does not know,
    /// faced; the death signal, [`Refusal::SessionEnded`]; a dial fault; the
    /// board's other refusals verbatim — `mint_home_first` among them.
    fn stage(&self, merged: &Merged, newest: &Newest) -> Result<(Address, u64), Refusal> {
        let head = &merged.inputs.head;
        let text = match newest.link() {
            None => format!("{}@{}", merged.key.text(), merged.as_of),
            Some(link) => format!("{}@{}~{link}", merged.key.text(), merged.as_of),
        };
        let id = Stem::of(&text).id("stage");
        let frame = frames::stage(&head.to_string(), Some(&id));
        let v = self.answered_write(&frame, "staging a fresh draft")?;
        if let (Some(addr), Some(at)) = (acked_addr(&v), acked_at(&v)) {
            let fresh = parse_address(addr).ok_or_else(|| shape_face("stage", &v))?;
            return Ok((fresh, at));
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("stage", &v).into()) };
        Err(match r.key() {
            "withheld" => Refusal::Unreadable(head.clone()),
            "source_not_registered" => Refusal::NoSuchDocument(head.clone()),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Lands M into the draft in one write, answering its position and the
    /// newer head where the board told one.
    ///
    /// The one frame is `set_arrangement` (the module's doc): M's runs,
    /// typed against `as_of` — the merge's one position for a draft named,
    /// the stage's position for a fresh one — with the head the merge
    /// composed on and its extent as read, the same pair as the base to
    /// record where the draft's `doc_metadata`, read at `as_of`, records a
    /// base, and the merge's sides but the draft itself; its id
    /// `<stem>.draft`, `stem` the [`Stem`] over the key, the draft, `as_of`
    /// and, for a draft named, the record the landing follows, which the
    /// board answers again in the same session for the same landing.
    /// It is sent where the draft already holds M too, so the base and the
    /// marker are recorded; a private draft's write, it reads no head (the
    /// module's doc). A write refused `arrangement_moved` is said in words
    /// read off the draft as it stands ([`Writer::moved_words`]), `newest`
    /// the record they name. With `shoot` off nothing is sent: the draft is
    /// read as it stands, and it answers the position of this merge's
    /// landing as the board marks it ([`Writer::marked_landing`]) where the
    /// draft holds M, or `None` where the board marks no landing of this
    /// merge — a take-back cleared it, none was made, or the draft's marker
    /// is the one its stage copied from the draft it was staged from — or
    /// the draft holds another list.
    ///
    /// # Errors
    ///
    /// The draft's reads' refusals — the feed walk's, with `shoot` off, on a
    /// draft with no recorded base ([`Writer::marked_landing`]), and a draft
    /// that did not exist at `as_of`, faced, naming the way out; the
    /// board's `arrangement_moved` as its verdict, [`Refusal::Halt`] with the
    /// `Refused` re-said in [`Writer::moved_words`]'s words — this merge's
    /// own landing named where it moved the draft after `as_of`, else the
    /// draft that changed after the merge was composed and nothing merged —
    /// or those reads' refusals, each as itself (SP-14);
    /// [`Refusal::ForkBaseMoved`] and
    /// [`Refusal::BaseNotInChain`], the two refusals a person meets;
    /// [`Refusal::WindowWithheld`] where a run names an origin the merger may
    /// not read; [`Refusal::NeedsSignedSession`];
    /// [`Refusal::NoSuchDocument`] naming the draft; a run with no address
    /// and the board's refusal of the frame's substance — the head and the
    /// extent the merge read and the base the draft records at `as_of`
    /// (`source_not_registered`, `no_base_to_record`,
    /// `base_extent_too_large`), a run's origin (`source_not_registered`,
    /// `bad_run`, `dangling_source`, `too_many_runs`), the draft's standing
    /// (`published_target`, `not_owner`) — as the library's own faults; an
    /// answer of a shape this client does not know, faced; the death signal,
    /// [`Refusal::SessionEnded`]; a dial fault; the board's other refusals
    /// verbatim.
    fn land_into_draft(
        &self,
        merged: &Merged,
        into: &Address,
        as_of: u64,
        stem: &Stem,
        newest: &Newest,
        shoot: bool,
    ) -> Result<Option<(u64, Option<Address>)>, Refusal> {
        let head = &merged.inputs.head;
        if !shoot {
            // The residue walk: the landing the board marks in the draft as
            // it stands, then M in the draft — never the draft's words alone.
            let meta = self.reader.metadata(into, None)?;
            let Some(at) = self.marked_landing(merged, into, &meta)? else {
                return Ok(None);
            };
            return Ok(self.holds_merge(merged, into)?.then_some((at, None)));
        }
        let target: Vec<Run> = merged.composed.runs.iter().map(|p| p.run.clone()).collect();
        // The base to record: the head's pair, only where the board records
        // a base for the draft at the position the write is typed against
        // (N4) — a baseless draft and a fork get none.
        let meta = match self.reader.metadata(into, Some(as_of)) {
            Ok(meta) => meta,
            Err(Refusal::NoSuchDocument(_)) => {
                return Err(Halt::face(
                    format!("{into} did not exist at position {as_of}, the position this merge was composed at"),
                    "the merge reads every draft it uses at one board position and types its landing against it, so the draft it lands into must stand there: a draft minted after the composition changed after it",
                    "run the merge again naming the draft, or land it in a fresh draft (`into` none; the command's --new)",
                )
                .into())
            }
            Err(e) => return Err(e),
        };
        let head_text = head.to_string();
        let pair = Some((head_text.as_str(), merged.head_extent));
        let base = if meta.base.is_some() { pair } else { None };
        let runs: Vec<Value> = target
            .iter()
            .map(|r| {
                let i_start = r
                    .address_at(0)
                    .ok_or_else(|| own_fault_face("a run of M names no address", format!("{r:?}")))?;
                Ok(frames::shot_run(&r.origin.to_string(), &i_start.to_string(), r.width))
            })
            .collect::<Result<_, Refusal>>()?;
        let sides = marked_sides(merged, into);
        let side_refs: Vec<&str> = sides.iter().map(String::as_str).collect();
        let id = stem.id("draft");
        let frame = frames::set_arrangement(
            &into.to_string(),
            &runs,
            as_of,
            pair,
            base,
            Some(&side_refs),
            Some(&id),
        );
        let v = self.answered_write(&frame, "landing the merge in the draft")?;
        if let Some(at) = acked_at(&v) {
            let head_moved = match acked_head_moved(&v) {
                Some(h) => Some(parse_address(h).ok_or_else(|| shape_face("set_arrangement", &v))?),
                None => None,
            };
            return Ok(Some((at, head_moved)));
        }
        let Some(r) = Rejection::of(&v) else {
            return Err(shape_face("set_arrangement", &v).into());
        };
        let site = r.site().addr.as_deref().and_then(parse_address);
        Err(match r.key() {
            "withheld" => Refusal::WindowWithheld(site.unwrap_or_else(|| into.clone())),
            "signed_session_required" => Refusal::NeedsSignedSession,
            "doc_not_registered" => Refusal::NoSuchDocument(into.clone()),
            // The draft changed past the position the write was typed
            // against: the board's verdict, nothing changed (the one write
            // wipes nothing), never this client's fault, in the person's
            // words read off the draft as it stands — this merge's own
            // landing where it made the change, else another hand's race.
            "arrangement_moved" => {
                let current = v["site"]["current"].as_u64();
                match self.moved_words(merged, into, as_of, newest, current) {
                    Ok(detail) => Refusal::Halt(Halt::Refused(Refused {
                        status: 200,
                        code: r.code().to_string(),
                        detail: Some(detail),
                        op: r.op().map(str::to_string),
                        body: v.clone(),
                    })),
                    Err(e) => e,
                }
            }
            "fork_base_moved" => Refusal::ForkBaseMoved {
                fork: into.clone(),
                source: site.unwrap_or_else(|| into.clone()),
                head: head.clone(),
            },
            "base_not_in_chain" => Refusal::BaseNotInChain { into: into.clone(), head: head.clone() },
            // The head and its extent are the merge's own reads — a member
            // registered for good, whose count never falls (PUB-2.43) — the
            // base is sent only where the draft records one at the position
            // the write is typed against, and every run was composed from
            // the merge's images: a refusal of them is its own fault.
            "no_base_to_record"
            | "base_extent_too_large"
            | "source_not_registered"
            | "published_target"
            | "not_owner"
            | "bad_run"
            | "dangling_source"
            | "too_many_runs"
            | "malformed" => own_fault("the draft landing", &r),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Returns whether `into`, read as it stands, holds M whole.
    ///
    /// # Errors
    ///
    /// The draft's `image` read's refusals; an `image` run that is no
    /// content I-address.
    fn holds_merge(&self, merged: &Merged, into: &Address) -> Result<bool, Refusal> {
        let current = runs_of(&self.reader.imaged(into, None)?.runs)?;
        let target: Vec<(Run, Family)> =
            merged.composed.runs.iter().map(|p| (p.run.clone(), Family::Own)).collect();
        Ok(first_difference(&target, &current, &merged.inputs.doc).is_none())
    }

    /// Returns the position of this merge's landing in `into`, as the board
    /// marks it.
    ///
    /// It is the landing the board shows, read by the base record `meta`
    /// answers for the draft as it stands (P4, N4). With a base, it is the
    /// marker (`meta`'s `merge`) where it names the head the merge composed
    /// on and the sides the landing marks ([`marked_sides`]): set by the
    /// landing whether or not its record was written, cleared by a take-back
    /// and by the draft's `publish`. A marker whose `at` is the draft's own
    /// mint, `meta`'s `at`, marks none: the stage that minted the draft
    /// copied it from the draft it was staged from, stamped at that stage's
    /// commit (P2), while a landing's own stands past the mint, the board
    /// writing only into a draft it has registered. With no base, the draft
    /// carries no marker, and it is the draft's latest `set_arrangement` row
    /// on the supplement where that row's `merge` names them (wire.md §The
    /// change feed): an undo or a restore after the landing writes a row
    /// naming no merge, and another merge's landing a row naming another.
    /// `None` where no such landing stands, whatever the draft holds: a
    /// withdrawal keeps M's words, a stage copies them with the marker, and
    /// another write can leave a list equal to M, so the words never tell a
    /// landing (R2).
    ///
    /// # Errors
    ///
    /// The feed walk's (`feed_rows`), on a draft with no recorded base.
    fn marked_landing(
        &self,
        merged: &Merged,
        into: &Address,
        meta: &answers::Metadata,
    ) -> Result<Option<u64>, Refusal> {
        let head = merged.inputs.head.to_string();
        let sides = marked_sides(merged, into);
        if meta.base.is_some() {
            return Ok(meta
                .merge
                .as_ref()
                .filter(|m| m.head == head && m.sides == sides)
                .and_then(|m| m.at)
                .filter(|at| meta.at != Some(*at)));
        }
        let mut latest = None;
        feed_rows(&self.reader, &into.to_string(), true, |row| {
            if row["op"].as_str() == Some("set_arrangement") {
                let merge = &row["merge"];
                let marks = merge["head"].as_str() == Some(head.as_str())
                    && merge["sides"].as_array().is_some_and(|s| {
                        s.iter().map(Value::as_str).eq(sides.iter().map(|x| Some(x.as_str())))
                    });
                latest = row["at"].as_u64().filter(|_| marks);
            }
        })?;
        Ok(latest)
    }

    /// Returns the words of a draft landing refused `arrangement_moved`.
    ///
    /// The board refused the one write into `into`: the draft changed past
    /// `as_of`, the position the write was typed against, at `current` where
    /// the refusal names it. Where this merge's own landing stands
    /// ([`Writer::marked_landing`]) at a position past `as_of` — met by a
    /// composition landed again in a session that holds no memo of its
    /// write — the words name it and its record, `newest` where it names
    /// `into` as landed in, else unwritten, and what `into` holds now:
    /// holding M, `resume` is the way on, which answers that landing and
    /// writes a record it lacks; holding another list, nothing to resume.
    /// Else the words name the change and that nothing was merged, and what
    /// a merge run again does with it: it reads `into` as it stands where
    /// `into` is a side of the merge, and where it is none, it never reads
    /// the change, so landing there again replaces it with the merged list.
    ///
    /// # Errors
    ///
    /// The reads' refusals, each as itself (SP-14): the draft's
    /// `doc_metadata` as it stands, the feed walk ([`Writer::marked_landing`])
    /// and, where a landing stands, the draft's `image`.
    fn moved_words(
        &self,
        merged: &Merged,
        into: &Address,
        as_of: u64,
        newest: &Newest,
        current: Option<u64>,
    ) -> Result<String, Refusal> {
        let meta = self.reader.metadata(into, None)?;
        if let Some(at) = self.marked_landing(merged, into, &meta)?.filter(|at| *at > as_of) {
            let landing = RecordLanding::Draft { draft: into.clone(), position: at };
            let link = newest.naming(&landing);
            let record = match link {
                Some(link) => format!("its record is {link}"),
                None => "its record is not written".to_string(),
            };
            if !self.holds_merge(merged, into)? {
                return Ok(format!(
                    "this merge landed in {into} at position {at}, after it was composed at position {as_of}, and {record}; {into} holds another list now — nothing was written"
                ));
            }
            let writes = if link.is_some() { "" } else { " and writes its record" };
            return Ok(format!(
                "{into} already holds this merge: it landed there at position {at}, after the merge was composed at position {as_of}, and {record} — nothing was written now; resume answers that landing{writes}"
            ));
        }
        let since = match current {
            Some(c) => format!(" (composed at position {as_of}, the draft changed at {c})"),
            None => format!(" at position {as_of}"),
        };
        let again = if merged.inputs.sides.iter().any(|s| s.address() == into) {
            "run the merge again, which reads the draft as it stands".to_string()
        } else {
            format!("{into} is no side of this merge, which never read that change, so landing the merge there again replaces the change with the merged list")
        };
        Ok(format!(
            "{into} changed after the merge was composed{since} — nothing was merged; {again}"
        ))
    }

    /// Sends one write under the merger's token.
    ///
    /// Its answer is the response document.
    ///
    /// # Errors
    ///
    /// The death signal under the token, [`Refusal::SessionEnded`] naming
    /// the write `during` names, faced for the writer's act; otherwise
    /// [`Board::op`]'s errors.
    pub(super) fn answered_write(&self, frame: &Value, during: &str) -> Result<Value, Refusal> {
        match self.board.op(Some(self.merger.token), frame)? {
            Answer::Closed => Err(session_ended(during, self.reader.on_end())),
            Answer::Document(v) => Ok(v),
        }
    }

    /// Checks a journal the caller named before the act's first write (P13).
    ///
    /// The record goes into the journal after the act's write, so a journal
    /// that cannot take it is refused before that write, never met after
    /// it: one `doc_metadata` of `journal` at the head, judged in the board's
    /// own order for the atom's insert ([`Unfit`]) — the read answered, then
    /// the owner, then the published bit. `None`, the account's own journal
    /// found or minted at the record, is not read. `blocked` names what the
    /// refusal stops, after the journal's reason in the face's state.
    ///
    /// # Errors
    ///
    /// In this order, nothing sent:
    ///
    /// - a journal this merger may not read, one this board does not
    ///   register, or another account's, as [`Refusal::Halt`] with a face
    ///   naming the journal and the check it fails;
    /// - a merger's account this client cannot spell, as the library's own
    ///   fault;
    /// - a published journal of the merger's own, as
    ///   [`Refusal::PublishedJournal`] naming it: a merge record is kept only
    ///   in a private document;
    /// - the read's other refusals and halts; the death signal,
    ///   [`Refusal::SessionEnded`].
    pub(super) fn check_journal(
        &self,
        journal: Option<&Address>,
        blocked: &str,
    ) -> Result<(), Refusal> {
        let Some(journal) = journal else {
            return Ok(());
        };
        let (unfit, found) = match self.reader.metadata(journal, None) {
            Err(Refusal::Unreadable(_)) => {
                (Unfit::Withheld, "its `doc_metadata` answered withheld".to_string())
            }
            Err(Refusal::NoSuchDocument(_)) => {
                (Unfit::Unregistered, "its `doc_metadata` answered doc_not_registered".to_string())
            }
            Err(e) => return Err(e),
            Ok(meta) => {
                let account = parse_address(self.merger.account).ok_or_else(|| {
                    own_fault_face(
                        "the merger's account cannot be spelled",
                        self.merger.account.to_string(),
                    )
                })?;
                if parse_address(&meta.owner).as_ref() != Some(&account) {
                    (Unfit::Foreign, format!("its `doc_metadata` names the owner {}, and only a document's owner writes into it (not_owner)", meta.owner))
                } else if meta.published {
                    return Err(Refusal::PublishedJournal { journal: journal.clone() });
                } else {
                    return Ok(());
                }
            }
        };
        Err(Halt::face(
            format!("{}, so {blocked}", unfit.reason(journal)),
            format!("the merge's record goes into the journal named after the act's write, so the journal is read before any write: {found}"),
            "name as the journal a draft this account owns, or none for the account's own; nothing was written",
        )
        .into())
    }

    /// Returns the term the shot signs over (SP-14).
    ///
    /// It is `H.1`'s pair, or `None` on a board no one has claimed, which
    /// takes the shot without an `attest` (`Board::board_head`). The shot
    /// reads it first, and again where it went unsigned and a claim landed
    /// past that read ([`Writer::attest_after_claim`]); no other write of a
    /// merge is signed, so none reads it (the module's doc).
    ///
    /// # Errors
    ///
    /// A claimed board serving no head record, faced as [`head_owed`], with
    /// nothing sent; `Board::board_head`'s halts, a head record that stands
    /// and cannot be read among them.
    fn signing_term(&self) -> Result<Option<BoardTerm>, Refusal> {
        let claimant = match self.board.board_head()? {
            BoardHead::Term(term) => return Ok(Some(term)),
            BoardHead::Unclaimed => return Ok(None),
            BoardHead::Owed { claimant } => claimant,
        };
        Err(head_owed(format!("the board names {claimant} its claimant and serves no head record (`H.1`), and the shot signs over that record's pair (signed ops), so it is not sent before the board writes it")).into())
    }

    /// Returns the `attest` member over `body`.
    ///
    /// It is for a write whose `doc` row is `doc`: the entry frame under
    /// `term` — `H.1`'s pair as [`Writer::signing_term`] read it — the
    /// merger's account and the row, signed by the merger's signer (signed
    /// ops; `skep_identity::entry_frame`, the one composer). `None` where
    /// `term` is none: a board no one has claimed, which drops the member
    /// unread.
    ///
    /// # Errors
    ///
    /// A merger's account this client cannot spell, as the library's own
    /// fault.
    pub(super) fn attest(
        &self,
        term: Option<BoardTerm>,
        doc: &Address,
        body: &EntryBody,
    ) -> Result<Option<Value>, Refusal> {
        let Some(term) = term else { return Ok(None) };
        let account = parse_address(self.merger.account).ok_or_else(|| {
            own_fault_face(
                "the merger's account cannot be spelled",
                self.merger.account.to_string(),
            )
        })?;
        let alg = self.merger.signer.public_key().alg().to_string();
        let bytes = entry_frame(&alg, term, &account, DocTerm::One(doc), body);
        Ok(Some(json!({"alg": alg, "sig": sig_hex(&self.merger.signer.sign(&bytes))})))
    }
}

/// Returns the sides a landing into `into` marks.
///
/// They are every side of the merge but `into` itself, in side order, as
/// the landing's `set_arrangement` names them in its `merge` and the board
/// carries them back on the marker and on the write's feed row.
fn marked_sides(merged: &Merged, into: &Address) -> Vec<String> {
    merged
        .inputs
        .sides
        .iter()
        .map(Side::address)
        .filter(|s| *s != into)
        .map(ToString::to_string)
        .collect()
}

/// Faces a claimed board whose head is owed, met before the shot (SP-14).
///
/// Nothing of the landing is written: the shot, its first write, could not
/// be signed.
fn head_owed(cause: String) -> Halt {
    Halt::face(
        "this board has no H.1 yet, so the merge cannot land",
        cause,
        "retry once the board has written its head; nothing was written",
    )
}

/// Why an act's record is not written, the act standing.
///
/// The record is a landing's, an undo's or a withdrawal's last step, so
/// the member or the draft already holds what the act wrote; the face says
/// so, and why the record is not.
pub(super) enum Unwritten {
    /// The account's journal is not found: the board refused its find, a
    /// class scan, busy on every bounded reissue (the `journal` module's
    /// doc).
    Busy,
    /// The journal cannot take the record, for the check it fails.
    Journal(Address, Unfit),
}

impl Unwritten {
    /// Returns why the record is not written, as a face's state says it.
    pub(super) fn reason(&self) -> String {
        match self {
            Unwritten::Busy => {
                "the board was too busy to find the account's merge journal".to_string()
            }
            Unwritten::Journal(journal, unfit) => unfit.reason(journal),
        }
    }

    /// Returns when `resume` writes the record, as a face's act says it.
    fn remedy(&self) -> &'static str {
        match self {
            Unwritten::Busy => "once the board is less busy, or with a journal named",
            Unwritten::Journal(..) => {
                "with a journal this account can write, or with none for its own"
            }
        }
    }
}

/// Why a journal cannot take a merge record: the check it fails.
///
/// A record's atom goes into its journal as a plain insert, so the journal
/// is a draft the merger's account owns, readable and registered at this
/// board (the merge record's decision 7). A journal named is checked before
/// an act's first write (`Writer::check_journal`; P13), which faces the
/// first three and answers a published one [`Refusal::PublishedJournal`];
/// one the record's step finds failing a check leaves the act standing with
/// its record unwritten ([`Unwritten::Journal`]). The checks run in the
/// board's order for the atom: the read's answer, then the owner, then the
/// published bit.
#[derive(Clone, Copy)]
pub(super) enum Unfit {
    /// It answers `withheld`: this merger may not read it.
    Withheld,
    /// It answers `doc_not_registered`.
    Unregistered,
    /// It is another account's, so the atom is refused `not_owner`
    /// (wire.md §Identity, ownership).
    Foreign,
    /// It is published, so the atom is refused `published_target` (wire.md
    /// §The version-chain refusals).
    Published,
}

impl Unfit {
    /// Returns what the check found of `journal`, as a face's state says it.
    fn reason(self, journal: &Address) -> String {
        match self {
            Unfit::Withheld => {
                format!("the journal {journal} is not readable to this merger (withheld)")
            }
            Unfit::Unregistered => {
                format!("the journal {journal} is not registered at this board (doc_not_registered)")
            }
            Unfit::Foreign => format!("the journal {journal} is another account's"),
            Unfit::Published => format!("the journal {journal} is published"),
        }
    }
}

/// Faces a landing that stands with its record unwritten.
///
/// The member or the draft holds the merge and the record is not written,
/// for `why` — the account's journal not found, its find refused busy, or a
/// journal that cannot take the record ([`Unfit`]): `resume` writes it once
/// the board answers the find, or into a journal the merger can write, told
/// the draft for a draft landing, since a fresh draft's landing is
/// otherwise found by its record alone.
fn record_owed(landed: &RecordLanding, why: &Unwritten, cause: String) -> Halt {
    let (at, act) = match landed {
        RecordLanding::Member { member, .. } => (member, format!("resume {}: it finds the member holding the merge and writes the record", why.remedy())),
        RecordLanding::Draft { draft, .. } => (draft, format!("resume naming {draft} {}: it finds the draft holding the merge and writes the record", why.remedy())),
    };
    Halt::face(
        format!("the merge stands at {at}, and its record is not written: {}", why.reason()),
        cause,
        act,
    )
}

/// Faces a board refusal of this library's own frame (A-288's own-bug class).
///
/// It is nothing a person can act on.
pub(super) fn own_fault(what: &str, r: &Rejection) -> Refusal {
    own_fault_face(format!("the board refused {what}"), format!("{}: the frame this library composed is wrong in substance — its base, its runs, its home or its attest", r.token()))
}

/// Returns this library's own fault, faced.
///
/// There is no user-facing act to offer.
pub(crate) fn own_fault_face(state: impl Into<String>, cause: impl Into<String>) -> Refusal {
    Refusal::Halt(Halt::face(state, cause, "this is a fault in this library, not in your keys or your act; nothing further was written"))
}

/// Faces an answer without the shape the write's ack promises.
pub(crate) fn shape_face(op: &str, v: &Value) -> Halt {
    Halt::face(
        format!("`{op}` answered a document this client cannot read"),
        crate::halt::clipped(&v.to_string(), 200).to_string(),
        "this board is not speaking the wire this client expects",
    )
}
