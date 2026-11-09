//! The merge's reads — the merge record's §1.3 in its order.
//!
//! Beside them stands what they build: [`compose`], which reads the head,
//! the base and every side as run lists, composes them through the core and
//! writes nothing; the conversion of an `image` answer's runs to the core's,
//! each origin the bare document ([`origin_of`]); [`head_of`], the
//! feed-walk fallback for a bare document's head member; the read of the
//! correspondence records of the person's own origins among a past state's
//! runs, and [`mapped`], the state mapped through them — what the restore
//! and the undo send, so words a publication made public since come back as
//! the published words they became; and [`Refusal`], every refusal a read
//! or a landing can meet.
//!
//! The reads, in the record's order (§1.3): the document's metadata and the
//! head's extent; the base — named by the caller, or derived by `base_of`
//! for members of one chain — imaged whole; the head and each side imaged
//! whole; the shared material joined by the core over the lists; the values
//! where the value rule has work, read through the side that holds them;
//! and the prior records for the key, so a standing record is known before
//! anything is written (§3, idempotence). Every `image` past the run budget
//! is re-asked in halves and the parts re-joined by I-adjacency (§8: "a
//! region past the budget can be asked in parts"), every `retrieve_v` past
//! the delivery budget likewise. A fork side's base is the SOURCE the board
//! serves for it — `doc_metadata`'s `source`, the member the fork was born
//! sharing (the fork-source design record, arm A; the merge record's case
//! (j)) — and a draft side's the BASE the board records for it —
//! `doc_metadata`'s `base`, the member it was staged from, moved to the
//! member each publication it rendered minted (wire.md §Namespace, `stage`)
//! — each read before the head's extent and never the caller's to know: a
//! base the caller names beside a draft side must be the one the records
//! derive, and one named beside a fork side is refused unread.
//!
//! **One position for everything** (skep #762; the landing lane's ruling).
//! Every frame a shape's reads send is answered at ONE board position P:
//! the position the draft side names where it names one, else the `as_of`
//! of the shape's first read, the document's `doc_metadata`, made at the
//! head. Every later read — a fork's source, a draft's base, the head's
//! extent and image, the base's image, each side's image, the values read
//! through the sides, the join's `compare` — goes through `/op-at` at P, so
//! the record describes a state the board held at one moment and never one
//! that an edit landing between two reads composed; the record carries P
//! for its draft side (§4: "for a draft read at N"), the result carries it
//! as its `as_of`, and the draft landing is typed against P. A P the board
//! does not answer is refused by name — its history reclaimed
//! ([`Refusal::HistoryReclaimed`]), past the board's head
//! ([`Refusal::BeyondHead`]) or inside one commit
//! ([`Refusal::NotAPosition`]) — never read at the head instead; where P is
//! the position a merge record names, [`record::verify`] answers for it
//! (skep #761). The prior records' lookup after the shape's reads reads the
//! journal, not a draft, and stays at the head. A side
//! whose base the library cannot read — a member of another document or the
//! bare document itself, a draft of an account other than the trunk
//! owner's, a draft the board records no base for, a fork no `version`
//! minted or one taken from another document (decision 15) — refuses
//! before the first `image`, as does a fork of a BARE source or a draft
//! staged from one, a side taken from the document before its first
//! version, whose base is history the board does not serve; a side the
//! reader may not read refuses at its own read. A run a readable side
//! windows from a document the reader may not read is answered whole by
//! `image` and `compare` and masked by `retrieve_v` (wire.md §The read
//! predicate, "a delivery masks per run"), so it refuses where a value is
//! read, naming that document ([`Refusal::Unreadable`]); the value rule
//! switched off reads no value of it.
//!
//! The reads go through [`Board::op`] under the caller's token, or with no
//! token where none is given, for the first read and the journal's, and
//! [`Board::op_at`] for every read at P, whose `history_busy` is retried a
//! bounded number of times (§7, "What it reads through"); the feed walk
//! goes through [`Board::changes`]. Nothing here writes.
//!
//! **The session's end.** Every read and write of the merge, the restore
//! and the take-backs that meets the death signal under the caller's token
//! answers [`Refusal::SessionEnded`] (wire.md §Sessions), carrying the face
//! that names the step it met and the way on that the act it stopped
//! leaves — a landing resumed, a take-back whose write stands left as it
//! is, every other act run again — so an embedder ends its session on the
//! arm, never on the words. The reader and the writer are each built for
//! one act's way on (`OnEnd`), and the one constructor composes the face
//! (`session_ended`). A read that presented no token cannot meet the
//! signal: one that does is the board's or the transport's fault,
//! [`Refusal::Halt`], as [`Board`] faces it.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use skep_address::{validate, Address, Nat, Tumbler};

use crate::address::parse_address;
use crate::board::answers::{self, IRun, Metadata};
use crate::board::{
    frames, guest_closed, Answer, AtAnswer, Board, ChangesAnswer, ChangesQuery, Rejection, Token,
};
use crate::halt::Halt;
use crate::publication::enumerate::MAX_WIRE_LIST;
use crate::publication::{self, home_of_link, owned_by, SupersedeCause};

use super::compose::{base_of, compose_runs, Composed, Item, Options, Run, SideIx};
use super::record::{self, Record, RecordKey, SideAt};
use super::windows::{Misfit, WindowPart};

/// The most runs one shot may name.
///
/// It is the wire's list cap, `MAX_WIRE_LIST` = 4,096 elements per request
/// array, which the shot's `runs` is parsed through (the merge record's §8,
/// "The three caps, read at the pin"). A merged list past it is refused
/// with the count, never split (decision 13).
pub const SHOT_RUN_CAP: usize = 1 << 12;

/// The most sides one merge composes besides the head.
///
/// Every list the core walks is numbered by its one-byte [`SideIx`], the
/// head's `0` and each side's its place after it. A merge of more sides is
/// refused by name before any read.
pub(super) const MAX_SIDES: usize = u8::MAX as usize;

/// The most items one `retrieve_v` delivers.
///
/// It is `MAX_DELIVERY_ITEMS`, 131,072 (wire.md §Rejection codes,
/// `too_many_items`): a value read wider than it is made in parts.
pub(super) const MAX_DELIVERY_ITEMS: u64 = 1 << 17;

/// How many times a `history_busy` on a read at a position is retried.
///
/// Past them the read is [`Refusal::HistoryBusy`] (§7: "retry with backoff,
/// bounded").
const HISTORY_BUSY_RETRIES: u32 = 4;

// ── the inputs ────────────────────────────────────────────────────────────

/// What a merge is composed from (the merge record's §7, `Inputs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inputs {
    /// The trunk document `D`.
    pub doc: Address,
    /// The head member `D.h` — side A in every shape the record draws.
    ///
    /// No read answers a bare document's head member (unverified-here 7), so
    /// the caller names it, from its own knowledge or from [`head_of`].
    pub head: Address,
    /// The base member, where the caller names it.
    ///
    /// Derived where `None`: by `base_of` along the sides' anchors — a
    /// member its own, a fork side's the source the board serves for it, a
    /// draft side's the base the board records for it (`doc_metadata`'s
    /// `base`) — so no merge needs one named (§1.2). Named beside a draft
    /// side it is checked against the derived base and refused where it
    /// disagrees ([`Refusal::DraftBaseDisagrees`]); beside a fork side it is
    /// refused unread ([`Refusal::ForkBaseNamed`]); beside member sides
    /// alone it is taken as named.
    pub base: Option<Address>,
    /// The other sides, in commit order.
    ///
    /// At most 255: every list a merge composes is numbered by one byte,
    /// the head's first, and [`compose`] refuses more before any read.
    pub sides: Vec<Side>,
    /// The composition's switches and the merger's resolutions.
    pub options: Options,
    /// The merge record kind's type address.
    ///
    /// It is the link's type slot and the record's class. Decision 9's row is
    /// interim and unpinned, so the embedder names it.
    pub kind: Address,
}

/// One side of a merge besides the head (the merge record's §7, `Side`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    /// A member of the document's chain.
    ///
    /// It is a daughter, or a daughter's daughter.
    Member(Address),
    /// A draft of the trunk owner's account (§1.2 shape (2)).
    ///
    /// It is read as of `position` where one is given — which is then the
    /// one position P every read of the composition is made at — else at
    /// the position the composition's first read answers, its base and its
    /// image alike. Its base is the one the board records for it — the
    /// `base` member of its `doc_metadata`, the member it was staged from,
    /// moved to the member each publication it rendered minted (wire.md
    /// §Namespace, `stage`) — read as of the same position, so a record's
    /// side, which carries the position its draft was read at, composes
    /// against the base that stood then. A draft the board records no base
    /// for, or whose recorded base lies in another document, is refused
    /// [`Refusal::BaseUnknown`]; one staged from the bare document, before
    /// its first version, [`Refusal::BareSource`]; a base the caller names
    /// beside it must be the one the records derive
    /// ([`Refusal::DraftBaseDisagrees`]).
    Draft {
        /// The draft's address.
        at: Address,
        /// The commit position the draft is read at; `None` for the position
        /// the composition's first read answers.
        ///
        /// The record's side carries the position read either way: this
        /// one, or the one the first read answered.
        position: Option<u64>,
    },
    /// A cross-owner fork of one of the document's published versions (§1.2
    /// shape (4), case (j)).
    ///
    /// Its base is the source the board serves for it — the `source` member
    /// of its `doc_metadata`, the version member the fork was born sharing —
    /// and never the caller's to name ([`Refusal::ForkBaseNamed`]). A fork
    /// whose source is the bare document, taken before its first version,
    /// is refused [`Refusal::BareSource`]; one no `version` minted, or one
    /// taken from another document, [`Refusal::BaseUnknown`]. Read as named:
    /// a published fork with members of its own would float to its head, so
    /// the caller names the member of it it means.
    Fork(Address),
}

impl Side {
    /// Returns the side's address — the member, the draft, the fork.
    pub fn address(&self) -> &Address {
        match self {
            Side::Member(a) | Side::Fork(a) => a,
            Side::Draft { at, .. } => at,
        }
    }

    /// Returns the side's role in the record's `sides` (§4).
    pub fn role(&self) -> Role {
        match self {
            Side::Member(_) => Role::Alternative,
            Side::Draft { .. } => Role::Draft,
            Side::Fork(_) => Role::Fork,
        }
    }

    /// Returns the position a draft side is read at.
    fn position(&self) -> Option<u64> {
        match self {
            Side::Draft { position, .. } => *position,
            Side::Member(_) | Side::Fork(_) => None,
        }
    }
}

/// A side's role, as the record spells it (the merge record's §4, `role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The head member, side A.
    Head,
    /// A daughter of the document's chain.
    Alternative,
    /// A draft of the trunk owner's account.
    Draft,
    /// A cross-owner fork.
    Fork,
}

impl Role {
    /// Returns the role's spelling in the record.
    ///
    /// It is `head`, `alternative`, `draft` or `fork`.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Head => "head",
            Role::Alternative => "alternative",
            Role::Draft => "draft",
            Role::Fork => "fork",
        }
    }

    /// Returns the role a spelling names, `None` for any other text.
    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "head" => Some(Role::Head),
            "alternative" => Some(Role::Alternative),
            "draft" => Some(Role::Draft),
            "fork" => Some(Role::Fork),
            _ => None,
        }
    }
}

/// A run's family in the shot (the merge record's §1.5).
///
/// The three families the wire states: the document's own I-space placed
/// by reference, a window onto another document, or a staging draft's text
/// re-inserted as fresh identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// The document's own I-space, by reference — its bytes signed by value.
    Own,
    /// Another document's I-space, kept as a window — signed by address.
    Window,
    /// A draft side's fresh text, re-inserted by the shot.
    ///
    /// It lands under the document's own I-space, its bytes signed by value.
    DraftNative,
}

/// What [`compose`] returns before anything is written.
///
/// It is the core's result wrapped with what the landing needs (the merge
/// record's §1.5, "What the library returns before the write"; §7,
/// `Merged`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged {
    /// The inputs as composed.
    pub inputs: Inputs,
    /// The core's result.
    ///
    /// It is M, the gap report, the counts, the value log, the resolutions
    /// not applied.
    pub composed: Composed,
    /// Each run of M's family, parallel to `composed.runs`.
    pub families: Vec<Family>,
    /// The key the record is current under: `(doc, base, {sides})`.
    pub key: RecordKey,
    /// The cap `composed.counts.m` is checked against at the landing.
    ///
    /// It is [`SHOT_RUN_CAP`]. The count is carried whatever it is, so a face
    /// can show it; the refusal is the landing's.
    pub cap: usize,
    /// The record the landing will write, unlanded.
    ///
    /// Its `landed` is none, its `claims` none, its `replaces` the prior
    /// record's link where one stands, and its draft side at `as_of`, the
    /// one position the draft was read at. The landing fills `landed` and
    /// `claims`, and sets `replaces` from its own read of the merger's
    /// newest record for the key (the `land` module's doc; P20).
    pub record: Record,
    /// The one position the shape's reads were taken at, P.
    ///
    /// It is the position the draft side named, else the `as_of` the first
    /// read answered; every frame the composition sent was answered at it
    /// (the module's doc). It is never the highest `as_of` any read
    /// answered: the prior records' lookup reads the journal at the head
    /// and raises no position here. The draft landing is typed against it.
    pub as_of: u64,
    /// The standing record for the key, where one is current.
    ///
    /// It is §3's "What a second agent sees", under the reader's currency
    /// (the trunk owner's records first) at the composition. The landing never
    /// lands by it: it reads the merger's own newest record for the key
    /// when it lands (the `land` module's doc).
    pub prior: Option<Record>,
    /// The head's content extent as read — the shot's `base_extent`.
    pub head_extent: u64,
    /// The head's and each side's image, in side order.
    ///
    /// The landing reads the shot's values through them.
    pub(super) maps: Vec<Imaged>,
}

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
    /// It is a member of another document or the bare document itself, a
    /// draft of an account other than the trunk owner's, a draft the board
    /// records no base for — never staged, or minted by `fork` or
    /// `create_new_document` — or whose recorded base lies in another
    /// document, a fork no `version` minted or one taken from another
    /// document, or a side no base can be derived with (decision 15; no
    /// interim).
    BaseUnknown(Side),
    /// A fork side whose source, or a draft side whose recorded base, is the
    /// bare document: a side taken from the document before its first
    /// version, refused before any `image`.
    ///
    /// Its base is the document's arrangement as it stood at the fork's
    /// mint or the draft's staging — history the board does not serve as a
    /// base (the fork-source design record, decision 4) — so merging it is
    /// not offered.
    BareSource {
        /// The fork or draft side.
        side: Side,
        /// The source the board serves for a fork, or the base it records for
        /// a draft: the bare document.
        source: Address,
    },
    /// A base the caller named for a fork side, refused before any read.
    ///
    /// A fork's base is the source the board serves for it, never the
    /// caller's to name (the fork-source design record, decision 8): a named
    /// one contradicts the substrate's fact and is refused rather than
    /// honoured.
    ForkBaseNamed {
        /// The fork side's address.
        fork: Address,
        /// The base the caller named.
        base: Address,
    },
    /// A base the caller named beside a draft side that is not the one the
    /// board's records derive, refused before any `image`.
    ///
    /// A draft's base is the one the board records for it (`doc_metadata`'s
    /// `base`), and the merge's base is derived from it along the anchors as
    /// for every side; a named one is taken only where it equals that, so
    /// naming the base never moves what a merge composes against — a wrong
    /// guess is refused, never composed against.
    DraftBaseDisagrees {
        /// The draft side.
        side: Side,
        /// The base the caller named.
        named: Address,
        /// The base the board's records derive.
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
    /// answers [`Verdict::Unreadable`](record::Verdict::Unreadable) naming
    /// the document instead: the verdict withheld (D14).
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
    /// answers [`Verdict::Unreadable`](record::Verdict::Unreadable) instead:
    /// the verdict withheld (skep #761).
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
    /// It is the merged list at a landing, `counts.m` (decision 13), or a
    /// past state at a restore, the runs the write would send: refused with
    /// the count before any frame, never split.
    OverCap {
        /// The runs the list holds.
        runs: usize,
        /// [`SHOT_RUN_CAP`].
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
    /// re-runs after [`Landed::AsDaughter`](super::Landed::AsDaughter).
    SupersedeRefused {
        /// The entry in the shot's `supersede` — the `Member` sides in
        /// order — `site.index`; 0 at `head_moved`, the list refused whole.
        index: u64,
        /// The cause, the rejection's `detail`.
        cause: SupersedeCause,
    },
    /// A window part of the shot with no answer, or an answer that fits
    /// nothing: nothing is sent (the merge record's §1.5, THE SHOT's WINDOW
    /// PARTS; §7).
    ///
    /// It names every part that needs an answer, final in meaning and the
    /// same for every caller: the landing never answers a window's part for
    /// its caller. A part named since its answer was given is among them,
    /// flagged [`WindowPart::named_since`](super::windows::WindowPart::named_since)
    /// (PUB-3.108).
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
    /// and the way on — at a landing [`resume`](super::resume), at a
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
    /// session's end. Two of the publication's own refusals of the shot ride
    /// here VERBATIM too, never as the library's fault — `already_published`
    /// naming the member the draft's words were published into,
    /// `publication_over_budget` with the daemon's detail — each a
    /// `Halt::Refused` whose `body` carries the `site`.
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
    /// The merge was published from the draft (P4): the base record stands
    /// on the version the shot minted and the marker is gone, so the way
    /// back is to publish the older text again, never a re-recorded base.
    Published {
        /// The version the merge is — the draft's recorded base.
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
}

impl From<Halt> for Refusal {
    fn from(h: Halt) -> Refusal {
        Refusal::Halt(h)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::BaseUnknown(side) => write!(f, "the base of the side {} cannot be read: a side is a version of the document, a draft of the document owner's account the board records a base for (one `stage` minted), or a fork of one of the document's versions", side.address()),
            Refusal::BareSource { side, source } => match side {
                Side::Draft { at, .. } => write!(f, "the draft {at} was staged from {source} itself, before it had a version (a bare base): its base is history the board does not serve, and merging it is not offered"),
                Side::Member(_) | Side::Fork(_) => write!(f, "the fork {} was taken from {source} itself, before it had a version (a bare source): its base is history the board does not serve, and merging it is not offered", side.address()),
            },
            Refusal::ForkBaseNamed { fork, base } => write!(f, "the base {base} was named for the fork {fork}: a fork's base is the source the board serves for it (doc_metadata's source), never the caller's to name — leave base unset"),
            Refusal::DraftBaseDisagrees { side, named, served } => write!(f, "the base {named} was named for the draft {}, whose recorded base (doc_metadata's base) derives the base {served}: a draft's base is the board's to serve — leave base unset, or name the base the board derives", side.address()),
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
                NoUndo::Published { version } => write!(f, "nothing to undo; the merge is version {version} — to take it back, publish the older text again"),
                NoUndo::TakenBack => write!(f, "nothing to undo: the merge in {draft} was already taken back"),
            },
            Refusal::NoMerge { draft } => write!(f, "{draft} carries no merge: nothing to undo, nothing to take out"),
            Refusal::NotPast { draft, at, current } => write!(f, "position {at} is not before the state {draft} stands at (position {current}): a restore names a position before the draft's current one, and nothing was read or sent"),
            Refusal::SupersedeRefused { index, cause } => match cause {
                SupersedeCause::HeadMoved { head: Some(head) } => write!(f, "the head moved under the merge: the trunk's head is now {head}, so the shot would have landed as a daughter, and a shot claiming a daughter superseded is refused whole (supersede_refused, head_moved) — nothing was published; compose the merge again on {head}"),
                SupersedeCause::HeadMoved { head: None } => f.write_str("the head moved under the merge, so the shot would have landed as a daughter, and a shot claiming a daughter superseded is refused whole (supersede_refused, head_moved) — nothing was published; compose the merge again on the trunk's head"),
                SupersedeCause::NotMember => write!(f, "the board refused the supersession claim at entry {index} (supersede_refused, not_member): the side is no registered version member of the document's own chain — nothing was published"),
                SupersedeCause::Base => write!(f, "the board refused the supersession claim at entry {index} (supersede_refused, base): the side is the member the shot appends to — nothing was published"),
                SupersedeCause::Duplicate => write!(f, "the board refused the supersession claim at entry {index} (supersede_refused, duplicate): the side is named twice — nothing was published"),
            },
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

// ── the origin rule ───────────────────────────────────────────────────────

/// Returns the bare document a content I-address was minted under.
///
/// It is the prefix before its last `.0.1.` — the content subspace's marker
/// — stripped of any version component to the trunk (the merge record's
/// §1.3 step 3: "derived from its `i_start` by address arithmetic,
/// `document_of` then the trunk"; the rule skep-cli's dev board states as
/// `origin_of`).
///
/// The core's `Run::origin` is this address, never a member's: a
/// version-qualified origin would make every anchor and every `Choice::After`
/// lookup answer none. `None` for a text that is no content I-address.
pub fn origin_of(i_start: &str) -> Option<Address> {
    let at = i_start.rfind(".0.1.")?;
    let minted_under = &i_start[..at];
    parse_address(&crate::address::document_of(minted_under)?)
}

/// Returns the content I-address prefix of `origin`'s positions.
///
/// It is the spelling an `image` answer's `i_start` opens with.
pub(super) fn content_prefix(origin: &Address) -> String {
    format!("{origin}.0.1")
}

/// Returns the core's runs for an `image` answer's runs.
///
/// Each origin is by [`origin_of`], I-adjacent runs of one origin coalesced
/// — the daemon's own accumulator, `extend_or_push_run`, whose whole test is
/// I-adjacency — so a run a part boundary cut is one run again (§8).
///
/// # Errors
///
/// A run whose `i_start` is no content I-address is the board's fault,
/// named.
pub(crate) fn runs_of(imaged: &[IRun]) -> Result<Vec<Run>, Halt> {
    let mut out: Vec<Run> = Vec::new();
    for r in imaged {
        let i_start = format!("{}.{}", r.prefix, r.first);
        let origin = origin_of(&i_start).ok_or_else(|| {
            Halt::face(
                "an `image` run is no content I-address",
                format!("`{i_start}` has no `.0.1.` content marker before its ordinal"),
                "this is a board fault; nothing was written",
            )
        })?;
        if let Some(last) = out.last_mut() {
            if last.origin == origin && last.reach() == r.first {
                last.width = last.width.saturating_add(r.width);
                continue;
            }
        }
        out.push(Run::new(origin, r.first, r.width));
    }
    Ok(out)
}

// ── address arithmetic over members ───────────────────────────────────────

/// Returns the trunk a document, member or element address lies in.
///
/// `None` for an account or a node.
pub(super) fn trunk_of(a: &Address) -> Option<Address> {
    parse_address(&crate::address::document_of(&a.to_string())?)
}

/// Returns an address's components.
///
/// They serve the comparisons the tumbler's own type does not offer.
pub(super) fn comps(a: &Address) -> Vec<Nat> {
    a.tumbler().iter().cloned().collect()
}

/// Returns a member's version components after the trunk `doc`'s.
///
/// `None` where `a` is not under `doc`, or is `doc` itself.
pub(super) fn version_components(doc: &Address, a: &Address) -> Option<Vec<Nat>> {
    let (doc, comps) = (comps(doc), comps(a));
    if comps.len() <= doc.len() || comps[..doc.len()] != doc[..] {
        return None;
    }
    Some(comps[doc.len()..].to_vec())
}

/// Returns whether `a` is a trunk member of `doc` — one version component.
pub(super) fn is_trunk_member(doc: &Address, a: &Address) -> bool {
    version_components(doc, a).is_some_and(|v| v.len() == 1)
}

/// Returns the trunk member after `head`: its one version component plus one.
pub(super) fn next_trunk_member(head: &Address) -> Option<Address> {
    let mut comps = comps(head);
    let last = comps.last_mut()?;
    *last = &*last + &Nat::from(1u32);
    validate(Tumbler::new(comps).ok()?).ok()
}

/// Returns the `k`-th daughter of `member`, its address extended by `k`.
pub(super) fn daughter_of(member: &Address, k: u64) -> Option<Address> {
    let comps = comps(member).into_iter().chain(std::iter::once(Nat::from(k)));
    validate(Tumbler::new(comps).ok()?).ok()
}

/// Returns the account an address lies in, `N.0.U`, as text.
///
/// `None` for a node.
pub(super) fn account_of(a: &Address) -> Option<String> {
    let node: Vec<String> = a.node_field().iter().map(ToString::to_string).collect();
    let account: Vec<String> = a.account_field()?.iter().map(ToString::to_string).collect();
    Some(format!("{}.0.{}", node.join("."), account.join(".")))
}

/// Returns an address's last component, its ordinal, where it fits `u64`.
pub(super) fn last_component(a: &Address) -> Option<u64> {
    u64::try_from(a.tumbler().iter().last()?).ok()
}

// ── the reader ────────────────────────────────────────────────────────────

/// One document's image, whole.
///
/// It holds the document, the position it was read at, its extent and its
/// runs as served, each run's `ordinal` the document's own V-ordinal, and
/// the position the answers named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Imaged {
    /// The document imaged — a member, or a draft.
    pub(super) doc: Address,
    /// The position the document was read at; `None` the head.
    ///
    /// Every image a shape's reads make carries the one position P (the
    /// module's doc), the head's included, so the values read through it
    /// are read at P too; `None` is a landing's own read of a draft as it
    /// stands.
    pub(super) at: Option<u64>,
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
    pub(super) as_of: Option<u64>,
}

/// The door of the merge's reads, and the restore's: a board, the caller's
/// token and the way on its act leaves where the session ends.
///
/// The highest `as_of` its frames' answers carry is kept. The feed walk
/// goes through it too ([`feed_rows`]); the journal's reads ask the board
/// directly.
pub(crate) struct Reader<'a> {
    board: &'a Board,
    token: Option<&'a Token>,
    as_of: Cell<u64>,
    on_end: OnEnd,
}

impl<'a> Reader<'a> {
    /// Returns a reader at `board` as `token`'s principal, or as a guest,
    /// for an act whose session's end leaves `on_end`.
    pub(crate) fn new(board: &'a Board, token: Option<&'a Token>, on_end: OnEnd) -> Reader<'a> {
        Reader { board, token, as_of: Cell::new(0), on_end }
    }

    /// Returns the highest `as_of` answered so far.
    pub(super) fn as_of(&self) -> u64 {
        self.as_of.get()
    }

    /// Returns the way on this reader's act leaves where the session ends.
    pub(super) fn on_end(&self) -> OnEnd {
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
    pub(super) fn refuse(&self, doc: &Address, r: &Rejection, v: &Value) -> Refusal {
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
    pub(super) fn metadata(&self, doc: &Address, at: Option<u64>) -> Result<Metadata, Refusal> {
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
    pub(super) fn extent(&self, doc: &Address, at: Option<u64>) -> Result<u64, Refusal> {
        Ok(self.span_set(doc, at)?.0)
    }

    /// Reads the span set of `doc`, answering its content extent and the
    /// answer's `as_of`.
    ///
    /// # Errors
    ///
    /// [`Reader::answered`]'s errors; an answer that is no `span_set`, faced.
    fn span_set(&self, doc: &Address, at: Option<u64>) -> Result<(u64, Option<u64>), Refusal> {
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
    pub(super) fn image(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
    ) -> Result<Vec<IRun>, Refusal> {
        Ok(self.image_read(doc, at, from, width)?.0)
    }

    /// Images as [`Reader::image`] does, with the highest `as_of` the parts
    /// answered — `None` where no part was read, or none carried one.
    ///
    /// # Errors
    ///
    /// [`Refusal::TooFragmented`] where a part of one position is still
    /// refused `image_too_large`; another refusal, mapped by
    /// [`Reader::refuse`]; an answer that is no image, faced;
    /// [`Reader::read`]'s errors.
    fn image_read(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
    ) -> Result<(Vec<IRun>, Option<u64>), Refusal> {
        let mut out = Vec::new();
        let mut seen = 0usize;
        let as_of = self.image_into(doc, at, from, width, &mut out, &mut seen)?;
        Ok((out, as_of))
    }

    fn image_into(
        &self,
        doc: &Address,
        at: Option<u64>,
        from: u64,
        width: u64,
        out: &mut Vec<IRun>,
        seen: &mut usize,
    ) -> Result<Option<u64>, Refusal> {
        if width == 0 {
            return Ok(None);
        }
        let v = self.read(&frames::image(&doc.to_string(), from, width), at)?;
        if let Some(r) = Rejection::of(&v) {
            if r.key() != "image_too_large" {
                return Err(self.refuse(doc, &r, &v));
            }
            if width == 1 {
                return Err(Refusal::TooFragmented { doc: doc.clone(), runs_seen: *seen });
            }
            let left = width / 2;
            let first = self.image_into(doc, at, from, left, out, seen)?;
            let rest = self.image_into(doc, at, from + left, width - left, out, seen)?;
            return Ok(first.max(rest));
        }
        let runs = answers::i_runs(&v, width).ok_or_else(|| shape("image", &v))?;
        *seen += runs.len();
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
        let (runs, imaged_as_of) = self.image_read(doc, at, 1, extent)?;
        Ok(Imaged { doc: doc.clone(), at, extent, runs, as_of: as_of.max(imaged_as_of) })
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
    pub(super) fn values(
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
    /// A landing, landed in part or not at all: `resume` finds what of it
    /// landed and completes the rest, writing nothing twice.
    Resume,
    /// A take-back's record, its one write standing: nothing more is
    /// written, a re-run finding no merge to take out and writing none.
    TakenOut,
}

impl OnEnd {
    /// Returns the face's state for a session that ended `during` a step.
    fn state(self, during: &str) -> String {
        match self {
            OnEnd::Rerun | OnEnd::Resume => format!("the session ended while {during}"),
            OnEnd::TakenOut => format!(
                "the merge is out of the draft, and its record is not written: the session ended while {during}"
            ),
        }
    }

    /// Returns the face's act: the one way on.
    pub(crate) fn act(self) -> &'static str {
        match self {
            OnEnd::Rerun => "open a session again and run this again: it reads what stands before it writes",
            OnEnd::Resume => "open a session again and resume: every step of the landing resumes by reading",
            OnEnd::TakenOut => "nothing more is written: the draft stands as the act left it, and a re-run writes no record, finding no merge to take out; the landing's record stands alone in the journal",
        }
    }
}

/// Returns the death signal under the caller's token met `during` a step of
/// an act that leaves `on_end`, as [`Refusal::SessionEnded`].
///
/// It is the one composer of the arm's face (the module's doc).
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

// ── the correspondence records ────────────────────────────────────────────

/// Reads the correspondence records of `account`'s own origins among
/// `state`'s runs, at the head.
///
/// It is the read a write of a past state makes before it is sent — the
/// restore's (the `history` module) and the undo's (the `undo` module):
/// one four-set read per chunk of each distinct owned origin's spans, in
/// run order — `{home: [the origin], from: [the spans], ty: [the
/// correspondence class]}`, the twin fence's own read — each hit judged
/// off its address, read once and kept by `Record::of`. The reads are made
/// at the head and never at the state's position, since a record minted
/// after the state must be seen.
///
/// # Errors
///
/// The reads' refusals: `withheld` on an origin as [`Refusal::Unreadable`],
/// `doc_not_registered` as [`Refusal::NoSuchDocument`], an answer of
/// another shape faced, the reader's other errors.
pub(crate) fn records_of(
    reader: &Reader<'_>,
    account: &str,
    state: &[Run],
) -> Result<Vec<publication::Record>, Refusal> {
    let subtype =
        frames::unit_span(frames::T_CORRESPONDENCE).as_array().cloned().unwrap_or_default();
    let mut origins: Vec<&Address> = Vec::new();
    for run in state {
        if !origins.contains(&&run.origin) && owned_by(&run.origin.to_string(), account) {
            origins.push(&run.origin);
        }
    }
    let mut records: Vec<publication::Record> = Vec::new();
    for origin in origins {
        let text = origin.to_string();
        let home = frames::unit_span(&text).as_array().cloned().unwrap_or_default();
        let spans: Vec<Value> = state
            .iter()
            .filter(|r| r.origin == *origin)
            .map(|r| frames::i_span(&format!("{text}.0.1.{}", r.i_start), r.width))
            .collect();
        for chunk in spans.chunks(MAX_WIRE_LIST) {
            let query = frames::find_links_four(
                frames::Slot::Spans(&home),
                frames::Slot::Spans(chunk),
                frames::Slot::Any,
                frames::Slot::Spans(&subtype),
            );
            let v = reader.answered(origin, &query, None)?;
            if v["resp"].as_str() != Some("addrs") {
                return Err(shape("find_links_ftt", &v).into());
            }
            let hits: Vec<String> = answers::addrs(&v).into_iter().map(str::to_string).collect();
            for hit in hits {
                if records.iter().any(|r| r.link.to_string() == hit) {
                    continue;
                }
                if !home_of_link(&hit).is_some_and(|h| owned_by(h, account)) {
                    continue;
                }
                let lv = reader.answered(origin, &frames::read_link(&hit), None)?;
                let Some(value) =
                    answers::link_value(&lv).ok_or_else(|| shape("read_link", &lv))?
                else {
                    continue;
                };
                if let Some(record) = publication::Record::of(&hit, &value, account) {
                    records.push(record);
                }
            }
        }
    }
    Ok(records)
}

/// Maps `state` through `records`: the runs a write of it sends.
///
/// Each run is walked from its first ordinal; the piece a record covers —
/// the first record covering the ordinal — is mapped by `Record::map` onto
/// the published span it became, its origin the document the record's `to`
/// lies in; the piece no record covers is kept as read; I-adjacent pieces
/// of one origin are merged. The order is the state's. A run of an origin
/// no record names passes through unchanged, as does a piece whose mapped
/// span this client cannot spell.
pub fn mapped(state: &[Run], records: &[publication::Record]) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::new();
    let mut push = |run: Run| match out.last_mut() {
        Some(last) if last.origin == run.origin && last.reach() == run.i_start => {
            last.width += run.width
        }
        _ => out.push(run),
    };
    for run in state {
        let chain = format!("{}.0.1", run.origin);
        let mut cursor = run.i_start;
        while cursor < run.reach() {
            let covering =
                records.iter().find(|r| r.from.overlap(&chain, cursor, cursor + 1).is_some());
            let end = match covering {
                Some(r) => r.from.reach().min(run.reach()),
                None => records
                    .iter()
                    .filter_map(|r| {
                        (r.from.chain == chain && r.from.first > cursor).then_some(r.from.first)
                    })
                    .min()
                    .unwrap_or(run.reach())
                    .min(run.reach()),
            };
            let width = end - cursor;
            let piece = covering
                .and_then(|r| r.map(&chain, cursor, end))
                .and_then(|to| Some(Run::new(parse_address(&to.document()?)?, to.first, width)))
                .unwrap_or_else(|| Run::new(run.origin.clone(), cursor, width));
            push(piece);
            cursor = end;
        }
    }
    out
}

// ── the value mapping (the fragment model) ────────────────────────────────

/// Returns where the positions of `run` stand among the sides' images.
///
/// Each stretch is `(the image's index, the V-ordinal it begins at, its
/// width)` — the image at `prefer` asked first, then the others in order —
/// so a sub-run of a run a side holds is read at that side's own V-ordinals
/// (`ordinal_of`'s mapping), and a shared identity at whichever side holds
/// it.
///
/// # Errors
///
/// A position no image holds is the library's own fault: the core places
/// only positions some side gave it.
pub(super) fn locate(
    maps: &[Imaged],
    prefer: Option<usize>,
    run: &Run,
) -> Result<Vec<(usize, u64, u64)>, Halt> {
    let prefix = content_prefix(&run.origin);
    let order: Vec<usize> =
        prefer.into_iter().chain((0..maps.len()).filter(|i| Some(*i) != prefer)).collect();
    let mut out = Vec::new();
    let mut pos = run.i_start;
    let end = run.reach();
    while pos < end {
        let found = order.iter().find_map(|&i| {
            maps[i]
                .runs
                .iter()
                .find(|r| r.prefix == prefix && r.first <= pos && pos - r.first < r.width)
                .map(|r| (i, r))
        });
        let Some((i, r)) = found else {
            return Err(Halt::face(
                format!("no side holds the position {prefix}.{pos}"),
                "the merged list names a position none of the images read holds — a fault in this client's composition",
                "this is this client's fault; nothing was written",
            ));
        };
        let stretch = (end - pos).min(r.first + r.width - pos);
        out.push((i, r.ordinal + (pos - r.first), stretch));
        pos += stretch;
    }
    Ok(out)
}

/// Reads the values of `run`'s positions through the sides that hold them.
///
/// The sides are found by [`locate`], `prefer` asked first.
///
/// # Errors
///
/// [`locate`]'s fault; [`Reader::values`]'s errors.
pub(super) fn values_for(
    reader: &Reader<'_>,
    maps: &[Imaged],
    prefer: Option<usize>,
    run: &Run,
) -> Result<Vec<Item>, Refusal> {
    let mut out = Vec::with_capacity(run.width as usize);
    for (i, ordinal, width) in locate(maps, prefer, run)? {
        out.extend(reader.values(&maps[i].doc, maps[i].at, ordinal, width)?);
    }
    Ok(out)
}

// ── the shape's reads ─────────────────────────────────────────────────────

/// Everything the reads of one shape yield.
///
/// `compose` and `verify` both build on it.
pub(super) struct Readings {
    /// The one position P every read but the first was made at (the
    /// module's doc): the draft side's named position, else the first
    /// read's `as_of`.
    pub(super) at: u64,
    /// The base member, named or derived.
    pub(super) base: Address,
    /// The base's image.
    pub(super) base_image: Imaged,
    /// The head's and each side's image, in side order.
    pub(super) maps: Vec<Imaged>,
    /// The head's content extent as read.
    pub(super) head_extent: u64,
    /// The trunk's owner account.
    pub(super) owner: String,
    /// The core's result.
    pub(super) composed: Composed,
    /// Each run of M's family.
    pub(super) families: Vec<Family>,
}

/// Makes the reads of §1.3 in order, then the core's walk.
///
/// The reads are the document's metadata, each fork and draft side's
/// metadata for its base — a fork's the source it was born sharing, a
/// draft's the base the board records for it — the head's extent, the base
/// imaged, the head and each side imaged, the composition with the values
/// read through the sides. The first read is made at the position the
/// draft side names, else at the head, and every later read at the one
/// position P that read answered (the module's doc): a draft at a position
/// names P; else P is the first read's `as_of`, and an edit landing on any
/// side between two reads changes nothing the reads answer.
///
/// A side's ANCHOR along the base derivation is its base as the board
/// serves it: a fork's its source — the version member the board serves as
/// its `doc_metadata` `source` (the merge record's case (j); the fork-source
/// design record, arm A) — a draft's the member its `doc_metadata` `base`
/// names as of the position the draft is read at (`draft_base`), a member's
/// itself. A base handed in beside a fork side is the record's own at
/// `verify`, never a caller's ([`compose`] refuses one): it must be the base
/// the sources derive, else the record contradicts the board. A base handed
/// in beside a draft side — a caller's or the record's — must be the base
/// the anchors derive too, else it is refused by name
/// ([`Refusal::DraftBaseDisagrees`]): naming the base never moves what the
/// merge composes against.
///
/// # Errors
///
/// In this order:
///
/// - a head that is no trunk member of `doc`, faced;
/// - two drafts, [`Refusal::TwoDrafts`];
/// - more sides besides the head than [`MAX_SIDES`], faced;
/// - a member of another document or the bare document itself,
///   [`Refusal::BaseUnknown`];
/// - the metadata read's refusals — at the named position,
///   [`Reader::read`]'s faults of a position included — and an answer
///   naming no `as_of`, faced;
/// - a draft of an account other than the trunk owner's,
///   [`Refusal::BaseUnknown`];
/// - for each fork or draft side in order: its metadata read's refusals at
///   P — [`Reader::read`]'s faults of a position included,
///   [`Refusal::HistoryReclaimed`] among them — the side unreadable,
///   [`Refusal::Unreadable`]; a fork no `version` minted or a draft the
///   board records no base for, or one whose source or recorded base lies
///   in another document, [`Refusal::BaseUnknown`]; a fork of the bare
///   document or a draft staged from it, [`Refusal::BareSource`];
/// - the head's extent read's refusals;
/// - a base that cannot be derived, [`Refusal::BaseUnknown`] — every
///   `BaseUnknown` decided before any `image`;
/// - a named base beside a fork side that is not the one the sources
///   derive, faced;
/// - a named base beside a draft side that is not the one the anchors
///   derive, [`Refusal::DraftBaseDisagrees`];
/// - a base that is no member of `doc`'s chain, faced;
/// - then each image and value read's own refusals — a run a readable side
///   windows from a document the reader may not read,
///   [`Refusal::Unreadable`] naming that document where the value rule
///   reads its values — and an `image` run that is no content I-address.
pub(super) fn read_shape(
    reader: &Reader<'_>,
    doc: &Address,
    head: &Address,
    base: Option<Address>,
    sides: &[Side],
    options: &Options,
) -> Result<Readings, Refusal> {
    if !is_trunk_member(doc, head) {
        return Err(Halt::face(
            format!("{head} is not a trunk member of {doc}"),
            "the head is the document's latest trunk member, `D.h`",
            "name the head member, or read it with `head_of`",
        )
        .into());
    }
    if sides.iter().filter(|s| matches!(s, Side::Draft { .. })).count() > 1 {
        return Err(Refusal::TwoDrafts);
    }
    // Every list the walk is given is numbered by its one-byte `SideIx`, the
    // head's 0 and each side's its place after it: `last` is the last side's.
    let Ok(last) = u8::try_from(sides.len()) else {
        return Err(Halt::face(
            format!(
                "this merge names {} sides besides the head, past the {MAX_SIDES} one merge composes",
                sides.len()
            ),
            "a merge numbers every list it composes by one byte, the head's first",
            "merge fewer sides at a time; nothing was read or written",
        )
        .into());
    };
    for side in sides {
        match side {
            // A fork's base and a draft's are read off the board below,
            // after the trunk's own metadata.
            Side::Fork(_) | Side::Draft { .. } => {}
            Side::Member(m) => {
                if trunk_of(m).as_ref() != Some(doc) || version_components(doc, m).is_none() {
                    return Err(Refusal::BaseUnknown(side.clone()));
                }
            }
        }
    }
    // Step 1: the document and the head. THE ONE POSITION P (skep #762): the
    // draft side's named position, else the `as_of` of this first read,
    // made at the head; every read after it is made at P.
    let named = sides.iter().find_map(Side::position);
    let (meta, meta_as_of) = reader.metadata_read(doc, named)?;
    let at = match named.or(meta_as_of) {
        Some(at) => at,
        None => {
            return Err(Halt::face(
                "`doc_metadata` answered no `as_of`",
                format!("the read of {doc} named no position (wire.md §The response envelope: every response names where it sits)"),
                "this board is not speaking the wire this client expects; nothing was written",
            )
            .into())
        }
    };
    for side in sides {
        if let Side::Draft { at, .. } = side {
            if account_of(at).as_deref() != Some(meta.owner.as_str()) {
                return Err(Refusal::BaseUnknown(side.clone()));
            }
        }
    }
    // Each side's anchor along the base derivation: a fork's is the source
    // the board serves for it and a draft's the base the board records for
    // it, each read now at P; a member's is itself.
    let mut anchors: Vec<Address> = Vec::with_capacity(sides.len());
    for side in sides {
        anchors.push(match side {
            Side::Fork(fork) => fork_source(reader, doc, side, fork, at)?,
            Side::Draft { at: draft, .. } => draft_base(reader, doc, side, draft, at)?,
            Side::Member(m) => m.clone(),
        });
    }
    let (head_extent, head_as_of) = reader.span_set(head, Some(at))?;
    // Step 2: the base, named or derived along the anchor chains.
    let derived = || -> Result<Address, Refusal> {
        let mut b = head.clone();
        for (side, anchor) in sides.iter().zip(&anchors) {
            b = base_of(&b, anchor).ok_or_else(|| Refusal::BaseUnknown(side.clone()))?;
        }
        Ok(b)
    };
    let has_fork = sides.iter().any(|s| matches!(s, Side::Fork(_)));
    let draft = sides.iter().find(|s| matches!(s, Side::Draft { .. }));
    let base = match base {
        Some(b) if has_fork => {
            let served = derived()?;
            if served != b {
                return Err(Halt::face(
                    format!("the base {b} is not the base {served} the board serves for the fork side"),
                    "a fork's base is the source its `doc_metadata` names, which this record contradicts",
                    "this record is not one this library would write against this board; nothing was written",
                )
                .into());
            }
            b
        }
        // Beside a draft side a named base is checked against the base the
        // board's records derive — never against the draft's recorded base
        // itself, which a daughter's staging makes a different member.
        Some(b) => match draft {
            Some(side) => {
                let served = derived()?;
                if served != b {
                    return Err(Refusal::DraftBaseDisagrees {
                        side: side.clone(),
                        named: b,
                        served,
                    });
                }
                b
            }
            None => b,
        },
        None => derived()?,
    };
    if trunk_of(&base).as_ref() != Some(doc) || version_components(doc, &base).is_none() {
        return Err(Halt::face(
            format!("{base} is no member of {doc}'s chain"),
            "the base of a merge is the member both sides descend from",
            "name a base member of the document, or none to derive it",
        )
        .into());
    }
    let base_image = reader.imaged(&base, Some(at))?;
    // Step 3: the head, then each side — every image at P, the head's
    // included, so the values read through the images are read at P too.
    let (head_runs, head_imaged_as_of) = reader.image_read(head, Some(at), 1, head_extent)?;
    let mut maps = vec![Imaged {
        doc: head.clone(),
        at: Some(at),
        extent: head_extent,
        runs: head_runs,
        as_of: head_as_of.max(head_imaged_as_of),
    }];
    for side in sides {
        maps.push(reader.imaged(side.address(), Some(at))?);
    }
    // Steps 4 and 5: the join and the walk, the values through the sides.
    let base_runs = runs_of(&base_image.runs)?;
    let mut side_runs = Vec::with_capacity(maps.len());
    for (ix, m) in (0..=last).zip(&maps) {
        side_runs.push((SideIx(ix), runs_of(&m.runs)?));
    }
    let fault: RefCell<Option<Refusal>> = RefCell::new(None);
    let values = |side: SideIx, run: &Run| -> Option<Vec<Item>> {
        match values_for(reader, &maps, Some(side.0 as usize), run) {
            Ok(items) => Some(items),
            Err(e) => {
                fault.borrow_mut().get_or_insert(e);
                None
            }
        }
    };
    let composed = compose_runs(&base_runs, &side_runs, None, options, &values);
    if let Some(e) = fault.into_inner() {
        return Err(e);
    }
    let families = composed.runs.iter().map(|p| family_of(&p.run.origin, doc, sides)).collect();
    Ok(Readings { at, base, base_image, maps, head_extent, owner: meta.owner, composed, families })
}

/// Reads the source a fork side was born sharing, checked as the fork's base.
///
/// It is the fork's `doc_metadata` `source` (the fork-source design record,
/// arm A), read at the one position `at`, and it is the base where it is a
/// version member of `doc` (the merge record's case (j)): the three checks
/// in order — present, of this document, a member.
///
/// # Errors
///
/// [`Reader::metadata`]'s errors on the fork — the fork unreadable,
/// [`Refusal::Unreadable`]; a fork no `version` minted (no source), or one
/// whose source lies in another document, [`Refusal::BaseUnknown`]; a fork
/// of the bare document, [`Refusal::BareSource`].
fn fork_source(
    reader: &Reader<'_>,
    doc: &Address,
    side: &Side,
    fork: &Address,
    at: u64,
) -> Result<Address, Refusal> {
    let meta = reader.metadata(fork, Some(at))?;
    let Some(source) = meta.source.as_deref().and_then(parse_address) else {
        return Err(Refusal::BaseUnknown(side.clone()));
    };
    if trunk_of(&source).as_ref() != Some(doc) {
        return Err(Refusal::BaseUnknown(side.clone()));
    }
    if version_components(doc, &source).is_none() {
        return Err(Refusal::BareSource { side: side.clone(), source });
    }
    Ok(source)
}

/// Reads the base the board records for a draft side, checked as its base.
///
/// It is the draft's `doc_metadata` `base` (wire.md §Namespace, `stage`;
/// §The response envelope): the member the draft was staged from, moved to
/// the member each publication the draft rendered minted — read as
/// [`fork_source`] reads a fork's `source`, never the caller's to know — and
/// it is the draft's anchor where it is a version member of `doc`: the
/// three checks in order — recorded, of this document, a member. The read
/// is at the one position `at`, as the draft's image is (wire.md §Reading
/// history): the base that stood when the draft was read, which the
/// publication that rendered the draft may have moved since, so a record's
/// side composes against the base its merge composed against. The merge's
/// base is then derived from it along the anchors, so a draft staged from a
/// daughter `D.k.m` merges with the head over `D.k`, not over the daughter.
///
/// # Errors
///
/// [`Reader::metadata`]'s errors on the draft — the draft unreadable,
/// [`Refusal::Unreadable`]; a draft the board records no base for — never
/// staged, or minted by `fork` or `create_new_document` — or one whose
/// recorded base lies in another document, [`Refusal::BaseUnknown`]; a
/// draft whose recorded base is the bare document, staged before the
/// document's first version, [`Refusal::BareSource`].
fn draft_base(
    reader: &Reader<'_>,
    doc: &Address,
    side: &Side,
    draft: &Address,
    at: u64,
) -> Result<Address, Refusal> {
    let meta = reader.metadata(draft, Some(at))?;
    let Some(base) = meta.base.as_deref().and_then(parse_address) else {
        return Err(Refusal::BaseUnknown(side.clone()));
    };
    if trunk_of(&base).as_ref() != Some(doc) {
        return Err(Refusal::BaseUnknown(side.clone()));
    }
    if version_components(doc, &base).is_none() {
        return Err(Refusal::BareSource { side: side.clone(), source: base });
    }
    Ok(base)
}

/// Returns a run's family by its origin.
///
/// It is the trunk's own, a draft side's, or a window.
fn family_of(origin: &Address, doc: &Address, sides: &[Side]) -> Family {
    if origin == doc {
        Family::Own
    } else if sides.iter().any(|s| matches!(s, Side::Draft { at, .. } if at == origin)) {
        Family::DraftNative
    } else {
        Family::Window
    }
}

/// Returns the first V-ordinal, counted from 1, at which two lists differ.
///
/// The lists are the `actual` runs — a member's over its placed positions,
/// or a draft's whole — and the `expected` list the merge composed — `None`
/// where they agree. A
/// draft side's fresh runs are re-minted by the shot under `doc`'s own
/// I-space, consecutively, so an expected `DraftNative` run matches any
/// stretch of `doc`'s positions of its width in its place, whatever their
/// ordinals.
pub(super) fn first_difference(
    expected: &[(Run, Family)],
    actual: &[Run],
    doc: &Address,
) -> Option<u64> {
    let mut cursor = 1u64;
    let (mut i, mut j, mut off_i, mut off_j) = (0usize, 0usize, 0u64, 0u64);
    while i < expected.len() && j < actual.len() {
        let (e, fam) = &expected[i];
        let a = &actual[j];
        let stretch = (e.width - off_i).min(a.width - off_j);
        let same_origin =
            if *fam == Family::DraftNative { a.origin == *doc } else { a.origin == e.origin };
        let same_start = *fam == Family::DraftNative || e.i_start + off_i == a.i_start + off_j;
        if !(same_origin && same_start) {
            return Some(cursor);
        }
        cursor += stretch;
        off_i += stretch;
        off_j += stretch;
        if off_i == e.width {
            i += 1;
            off_i = 0;
        }
        if off_j == a.width {
            j += 1;
            off_j = 0;
        }
    }
    (i < expected.len() || j < actual.len()).then_some(cursor)
}

// ── the oracle of the join ────────────────────────────────────────────────

/// Checks the client's join against the daemon's `compare`.
///
/// It is the merge record's §1.3 step 4: one `compare` of the base's whole
/// content against every side's — the second operand a region per side —
/// asked in parts past its budgets (`too_many_blocks`, `too_many_pairs`:
/// the sides asked one at a time, then the larger operand halved and
/// re-asked), and for each side the base positions the pairs name as shared
/// must be exactly the base positions that side's image holds.
///
/// # Errors
///
/// A disagreement is this library's own fault — the core's join reproduces
/// the daemon's equi-join on I-address — faced; the reads' refusals.
pub(super) fn check_join(reader: &Reader<'_>, readings: &Readings) -> Result<(), Refusal> {
    let base = &readings.base_image;
    // The oracle at the one position every image was read at.
    let at = Some(readings.at);
    let regions: Vec<(Address, u64, u64)> =
        readings.maps.iter().map(|m| (m.doc.clone(), 1, m.extent)).collect();
    let mut pairs = Vec::new();
    compare_parts(reader, &base.doc, 1, base.extent, &regions, at, &mut pairs)?;
    for m in &readings.maps {
        let doc = m.doc.to_string();
        let mut oracle: Vec<(u64, u64)> =
            pairs.iter().filter(|p| p.d2 == doc).map(|p| (p.u1, p.width)).collect();
        let mut join: Vec<(u64, u64)> = Vec::new();
        for b in &base.runs {
            for s in m.runs.iter().filter(|s| s.prefix == b.prefix) {
                let lo = b.first.max(s.first);
                let hi = (b.first + b.width).min(s.first + s.width);
                if lo < hi {
                    join.push((b.ordinal + (lo - b.first), hi - lo));
                }
            }
        }
        if coalesced(&mut oracle) != coalesced(&mut join) {
            return Err(Halt::face(
                format!("the client's join over {} and {} disagrees with the board's `compare`", base.doc, m.doc),
                format!("compare: {oracle:?}; the images' intersection: {join:?}"),
                "this is this client's fault — its reproduction of the daemon's equi-join; nothing was written",
            )
            .into());
        }
    }
    Ok(())
}

/// Sorts `(start, width)` ranges and merges those that touch.
fn coalesced(ranges: &mut Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &(start, width) in ranges.iter() {
        if let Some(last) = out.last_mut() {
            if last.0 + last.1 >= start {
                last.1 = (start + width).max(last.0 + last.1) - last.0;
                continue;
            }
        }
        out.push((start, width));
    }
    out
}

/// Asks one `compare` of the base region against the side regions.
///
/// On a budget refusal it asks the sides one at a time, then halves the
/// larger operand, until each part answers.
///
/// # Errors
///
/// A refusal other than a budget's, mapped by [`Reader::refuse`] — a
/// `withheld` or `doc_not_registered` naming the region's document the
/// board refused, the base's or a side's; a budget refusal down to one
/// position each, faced; an answer that is no `compare` answer, faced;
/// [`Reader::read`]'s errors.
fn compare_parts(
    reader: &Reader<'_>,
    base: &Address,
    from: u64,
    width: u64,
    sides: &[(Address, u64, u64)],
    at: Option<u64>,
    out: &mut Vec<answers::Correspondence>,
) -> Result<(), Refusal> {
    if width == 0 || sides.iter().all(|(_, _, w)| *w == 0) {
        return Ok(());
    }
    let rho1 = [frames::region(&base.to_string(), from, width)];
    let rho2: Vec<Value> = sides
        .iter()
        .filter(|(_, _, w)| *w > 0)
        .map(|(d, f, w)| frames::region(&d.to_string(), *f, *w))
        .collect();
    let v = reader.read(&frames::compare(&rho1, &rho2), at)?;
    if let Some(r) = Rejection::of(&v) {
        if !matches!(r.key(), "too_many_blocks" | "too_many_pairs") {
            return Err(reader.refuse(base, &r, &v));
        }
        if sides.len() > 1 {
            for side in sides {
                compare_parts(reader, base, from, width, std::slice::from_ref(side), at, out)?;
            }
            return Ok(());
        }
        let (side, sf, sw) = &sides[0];
        if width >= *sw && width > 1 {
            let left = width / 2;
            compare_parts(reader, base, from, left, sides, at, out)?;
            return compare_parts(reader, base, from + left, width - left, sides, at, out);
        }
        if *sw > 1 {
            let left = sw / 2;
            compare_parts(reader, base, from, width, &[(side.clone(), *sf, left)], at, out)?;
            return compare_parts(
                reader,
                base,
                from,
                width,
                &[(side.clone(), sf + left, sw - left)],
                at,
                out,
            );
        }
        return Err(Halt::face(
            format!("`compare` refuses {base} against {side} down to one position"),
            format!("{}: the board's compare budget refuses operands of one position", r.token()),
            "this board is not speaking the wire this client expects; nothing was written",
        )
        .into());
    }
    let pairs = answers::compare_pairs(&v).ok_or_else(|| shape("compare", &v))?;
    out.extend(pairs);
    Ok(())
}

// ── compose ───────────────────────────────────────────────────────────────

/// Composes a merge from the board, writing nothing.
///
/// It makes §1.3's reads in order, the core's walk and the prior records'
/// read for the key (the merge record's §7, `compose`) — all but step 6's,
/// the shot's bytes, which the landing reads.
///
/// `token` is the caller's — `None` reads as a guest, which reads public
/// members alone. Every read of the shape is made at one board position P
/// (the module's doc), which the result carries as `as_of` and as the
/// record's draft side position, so a verifier reads the draft and its
/// recorded base as this composition did (§4: "for a draft read at N") and
/// the landing types its write against it. The result carries M with each
/// run's family, the gap report, the counts (`counts.m` against
/// [`SHOT_RUN_CAP`], carried, not refused here), the record the landing
/// would write, and the standing record for the key where one is current.
///
/// # Errors
///
/// A base named beside a fork side, [`Refusal::ForkBaseNamed`], before any
/// read — a fork's base is the board's to serve (the fork-source design
/// record, decision 8); then `read_shape`'s — more than 255 sides besides
/// the head among them, faced before any read — then the prior records'
/// reads' refusals, which `record::current` answers.
pub fn compose(board: &Board, token: Option<&Token>, inputs: &Inputs) -> Result<Merged, Refusal> {
    if let Some(base) = &inputs.base {
        if let Some(fork) = inputs.sides.iter().find_map(|s| match s {
            Side::Fork(f) => Some(f),
            _ => None,
        }) {
            return Err(Refusal::ForkBaseNamed { fork: fork.clone(), base: base.clone() });
        }
    }
    let reader = Reader::new(board, token, OnEnd::Rerun);
    let readings = read_shape(
        &reader,
        &inputs.doc,
        &inputs.head,
        inputs.base.clone(),
        &inputs.sides,
        &inputs.options,
    )?;
    let Readings { at, base, maps, head_extent, owner, composed, families, .. } = readings;
    let key = RecordKey::new(
        inputs.doc.clone(),
        base.clone(),
        std::iter::once(inputs.head.clone())
            .chain(inputs.sides.iter().map(|s| s.address().clone())),
    );
    // Step 7: the prior records, the trunk owner's account's current over
    // another's — the journal's reads, at the head: they raise the reader's
    // running `as_of` past P, which nothing below reads.
    let prior = record::current_among(&reader, &inputs.kind, &key, Some(&owner))?;
    // The record's sides: the head, then each side — a draft at P, the one
    // position it was read at.
    let mut sides: Vec<SideAt> = vec![SideAt::Member { at: inputs.head.clone(), role: Role::Head }];
    for side in &inputs.sides {
        sides.push(match side {
            Side::Draft { at: draft, .. } => SideAt::Draft { at: draft.clone(), position: Some(at) },
            side => SideAt::of(side),
        });
    }
    let record = Record {
        doc: inputs.doc.clone(),
        base,
        sides,
        landed: None,
        claims: Vec::new(),
        runs: composed.counts,
        retries: inputs.options.retries,
        gaps: composed.gaps.clone(),
        values: composed.values.clone(),
        answers: Vec::new(),
        replaces: prior.as_ref().and_then(|p| p.link.clone()),
        by: record::by(),
        link: None,
    };
    Ok(Merged {
        inputs: inputs.clone(),
        composed,
        families,
        key,
        cap: SHOT_RUN_CAP,
        record,
        // P explicitly — never the reader's highest `as_of`, which the prior
        // records' reads at the head just raised.
        as_of: at,
        prior,
        head_extent,
        maps,
    })
}

// ── the feed-walk fallback ────────────────────────────────────────────────

/// Returns the head member of bare document `doc` by walking its change feed.
///
/// The walk is the fallback the merge record's §1.3 step 1 describes, "read
/// backwards to the last `publish` row": no single read answers a bare
/// document's head member (unverified-here 7), so the last `publish` row
/// under `doc` whose minted member is a trunk member names it; a daughter's
/// row never does. `None` for a document with no member, or one whose head
/// member's `publish` row is below the feed's retention floor.
///
/// The walk is paged from the floor up under `under=doc`, so its cost is the
/// document's own rows; an embedder that knows the head names it instead.
///
/// # Errors
///
/// The feed walk's: a transport fault, [`Refusal::Halt`]; the death signal
/// under the token, [`Refusal::SessionEnded`], the walk run again on a new
/// session.
pub fn head_of(
    board: &Board,
    token: Option<&Token>,
    doc: &Address,
) -> Result<Option<Address>, Refusal> {
    let mut head: Option<Address> = None;
    feed_rows(&Reader::new(board, token, OnEnd::Rerun), &doc.to_string(), false, |row| {
        if row["op"].as_str() != Some("publish") {
            return;
        }
        if let Some(member) = row["docs"]
            .as_array()
            .and_then(|d| d.first())
            .and_then(Value::as_str)
            .and_then(parse_address)
        {
            if is_trunk_member(doc, &member) {
                head = Some(member);
            }
        }
    })?;
    Ok(head)
}

/// Returns the commit position of the `publish` row that minted `member`.
///
/// It is read off the member's own rows of the feed, through `reader`;
/// `None` where the feed no longer holds it.
///
/// # Errors
///
/// [`feed_rows`]'s.
pub(super) fn position_of(reader: &Reader<'_>, member: &Address) -> Result<Option<u64>, Refusal> {
    let mut at = None;
    let text = member.to_string();
    feed_rows(reader, &text, false, |row| {
        if at.is_none()
            && row["op"].as_str() == Some("publish")
            && row["docs"].as_array().and_then(|d| d.first()).and_then(Value::as_str)
                == Some(text.as_str())
        {
            at = row["at"].as_u64();
        }
    })?;
    Ok(at)
}

/// Walks every row of the feed under `under`, oldest first.
///
/// The walk runs from the floor to the head: the retention floor restarts
/// the walk at the floor, a page past the byte budget is re-asked at the
/// limit that fits. With `drafts` the walk is the supplement's,
/// `drafts=true` — the rows naming a draft the token's class may read, which
/// is where a draft's own `set_arrangement` rows are (wire.md §The change
/// feed, Narrowings); without it the published stream's, the member rows a
/// head or a mint position is read off. The pages are read through
/// `reader`'s board under its token.
///
/// # Errors
///
/// The feed's halts, [`Refusal::Halt`]: a transport fault, and the death
/// signal on a walk that presents no token, the board's fault; the death
/// signal under the token, [`Refusal::SessionEnded`], faced for `reader`'s
/// act.
pub(super) fn feed_rows(
    reader: &Reader<'_>,
    under: &str,
    drafts: bool,
    mut each: impl FnMut(&Value),
) -> Result<(), Refusal> {
    let mut since = 0u64;
    let mut limit = None;
    loop {
        let query = ChangesQuery { since, under: Some(under), drafts, limit };
        match reader.board.changes(reader.token, &query)? {
            ChangesAnswer::Page(page) => {
                for row in &page.changes {
                    each(row);
                }
                if !page.more {
                    return Ok(());
                }
                since = page.last;
            }
            ChangesAnswer::HistoryReclaimed { floor } => {
                // The page is `(since, head]`, so the oldest answerable
                // position is reached from the one below it.
                let next = floor.map_or(since + 1, |f| f.saturating_sub(1));
                if next <= since {
                    return Ok(());
                }
                since = next;
            }
            ChangesAnswer::TooLarge { fits } => limit = Some(fits),
            ChangesAnswer::Closed => {
                return Err(session_ended("walking the change feed", reader.on_end))
            }
        }
    }
}
