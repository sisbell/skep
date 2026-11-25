//! The merge record — the D13 `merge` kind (the merge record's §4).
//!
//! It holds the schema as a struct whose JSON is built by hand, the key a
//! record is current under and the currency rule ([`current`]: newest wins
//! per key, by the order the records' links were minted, the trunk owner's
//! records over another account's, decision 8), how a reader finds a record
//! (the link of the kind homed in the journal beside the record, from its
//! atom to the landed member or draft and every side besides the head, the
//! atom read through the journal's arrangement and never by identity), the
//! record standing for the landing a draft's merge marker marks, found
//! through the links of the kind to the draft whatever the merge landed in
//! since, the account's own links kept before any record is read
//! ([`landing_record`], or [`standing_landing`] with the mark read off the
//! draft as it stands — its marker, or on a baseless draft the landing
//! standing by its `set_arrangement` rows (the `landings` module's doc);
//! an undo and a withdrawal find the record they replace by the same rule,
//! and a withdrawal's undo, by the marker it puts back, the landing's
//! record it writes again and the take-back made since that landing it
//! replaces), and [`verify`], the record's testimony recomputed.
//!
//! **Kept private.** A merge record is kept only in a private document: its
//! journal is a private draft of the merger's own, the record's link homed
//! in it and hidden with it, unsigned, and a published one is refused before
//! any write (the [`journal`](super::journal) module); no publication
//! publishes a record, the publication's enumeration leaving every atom of
//! the kind out of what it publishes (`crate::publication::is_merge_record`);
//! and what a merge makes public is its version and, at a published
//! daughter, the claim riding its shot.
//!
//! **Testimony, plainly (D4).** The record is a claim its writer makes, as
//! the supersession claim beside it is; the daemon derives nothing from it,
//! the member's arrangement is the fact. Everything it asserts is
//! recomputable from reads a verifier can make — the base is a member or
//! the document's own arrangement from before its first version, the one
//! the board's recorded bases derive for the sides, the sides are members
//! or a draft the verifier may read, the rules are versioned, the value
//! switches are in the body — so `verify` recomputes M, under this build's
//! rules whatever version the record names ([`RULES`]), and compares it
//! with the landed member's image over its first `placed` positions, or the
//! draft's at the position recorded, the daemon's `compare` the oracle the
//! client's join is checked against (§1.3 step 4), and answers `Equal`,
//! `Differs`, `SideMoved` or `Unreadable`, never a verdict manufactured for
//! a document it may not read (D14): the trunk, the head, the base, a side
//! or the landed document withheld from the reader answers `Unreadable`
//! naming it, as does the origin of a run a side windows whose values the
//! value rule reads, or the line rule reads in the text that decides
//! whether two sides' neighbouring changes meet at a line's edge whatever
//! the switches — the composition's `LineTextWithheld` — masked as a
//! `withheld` item.
//! A fork's text can change after the merge, so the record keeps each
//! mutable side's state beside its address — the position its text last
//! changed at when the merge was composed, `doc_metadata`'s `arranged_at`
//! ([`SideState`]) — and a fork arranged since answers `SideMoved` naming
//! it, never `Differs`; a draft side is read at the position the record
//! names for it, so its later edits change nothing the verdict reads.
//! A position the record names is read as named or not at all: one whose
//! history the board has reclaimed withholds the verdict (`Unreadable`),
//! and one past the board's head or inside one commit is refused as the
//! record's, its face advising no read elsewhere (skep #761).
//!
//! **One schema**, kind `merge`: `type` fixed, `v` the schema's version,
//! `rules` the rule set's, then `doc`, `base`, `sides` — a fork side and a
//! draft side carrying `arranged`, its state — `landed`, `claims`, `runs`,
//! `retries`, `gaps`, `values`, `replaces` and `by` (§4, "Under D13"), with
//! `answers` beside them only where a window part was answered
//! (§1.5, THE SHOT's WINDOW PARTS) or the shot sent a draft side's words by
//! reference because a record named them as published (the twins, the
//! `windows` module's doc): each is those words and their answer, the
//! published words they were windowed from where they were — so the list
//! `verify` recomputes is M as those answers left it, one function with the
//! shot's own (`merge::windows`). The record is encoded as the one
//! JSON object `serde_json` renders; a reader that does not know a member
//! treats it as absent.

use std::collections::{HashSet, VecDeque};

use serde_json::{json, Value};
use skep_address::{Address, Nat};

use crate::address::{document_of, parse_address};
use crate::board::answers::{self, IRun, MergeMarker};
use crate::board::{frames, Board, Token};
use crate::halt::Halt;
use crate::publication::{home_of_link, owned_by};

use super::compose::{
    Choice, Gap, GapId, GapKind, Options, Placement, Removed, Resolution, ResolvedBy, Run,
    RunCounts, SideIx, Spot, ValueLog,
};
use super::landings;
use super::reads::{self, last_component, origin_of, OnEnd, Reader, Refusal, Role, Side};

/// The kind's `type` member, `merge`.
///
/// It is the word on every surface (decision 12), stated once as the
/// publication's [`MERGE_RECORD_TYPE`](crate::publication::MERGE_RECORD_TYPE),
/// whose enumeration keeps every atom carrying it out of what it publishes.
pub const TYPE: &str = crate::publication::MERGE_RECORD_TYPE;

/// The schema's version, `v`.
pub const SCHEMA_VERSION: u64 = 1;

/// The rule set's version, `rules`: §2's rule set, `merge-rules-4`.
///
/// Its gaps hold a `moves` gap with spots wherever two or more sides placed
/// one fresh identity at different spots (CM-I33), and each gap keeps the
/// number the report composed with no resolution gives it, the order chosen
/// at a spine's `moves` gap included (skep #1155). An identity several
/// sides hold at one spot is kept where it breaks no holder's own order,
/// whichever side is listed first, and asks where none can be found, or
/// where a holder orders the words it shares otherwise or sets words of
/// its own beside them, each such holder keeping its copy at the gap and M
/// laying it once; the sides' reorders fold in the order listed, each
/// applied where it composes with those applied before it and a `moves` gap
/// where it does not, a choice at one such gap settling that gap alone, the
/// last naming it standing; a move takes the placement of a run placed
/// twice nearest the gap's composed place, and moves no gap the rules
/// settled; `KeepBoth` confirms a gap's placement as composed, never
/// putting back a copy the dedup dropped; and a one-sided addition — R2's
/// `anchor` beside a removal among them — another side's addition meets at
/// a line's edge, or a removal another side alone made with no words of its
/// own in its place, is a `line` gap, unsettled, read off the base text
/// between them whatever the value switches, the removal named in its
/// `removed`, neither change one the other's side also made, a word kept
/// once counted as each holder's that placed it (skep #1173, #1176).
/// [`verify`] composes under this build's rules whatever version a record
/// names, so a record written under an earlier set can verify `Differs`
/// where the sets part — and so can a record naming this set whose `line`
/// gaps this build composes otherwise, the name standing for records
/// composed with the line rule and without it, with its removal pairs, its
/// anchors and its words kept once each holder's, and without them: its
/// gaps numbered otherwise, its choices name other gaps.
pub const RULES: &str = "merge-rules-4";

/// Returns the `by` member: this library's crate and version.
pub(super) fn by() -> String {
    format!("skep-client {}", env!("CARGO_PKG_VERSION"))
}

// ── the key ───────────────────────────────────────────────────────────────

/// The key a record is current under — `(doc, base, {sides}, {states})`.
///
/// It is a term of the body (the merge record's §4, "Its currency"; P20).
/// The sides are a set: kept sorted, so two keys naming the same sides in
/// another order are one. The states are each mutable side's — a fork's, a
/// draft's — so a merge composed over a side whose text changed since is a
/// key of its own, never the same landing as the earlier one (skep #790).
/// Equality is exact: a state [`SideState::Unrecorded`] equals no other, so
/// a record written before the states were kept is current for no key
/// composed since. [`RecordKey::stateless`] drops the states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordKey {
    /// The trunk document.
    pub doc: Address,
    /// The base: a member, or the document itself where a side was begun
    /// before its first version.
    pub base: Address,
    /// Every side's address, the head's included, in address order.
    ///
    /// They are what the links of a record's kind are found by.
    pub sides: Vec<Address>,
    /// Each fork or draft side's address and state, in address order.
    pub states: Vec<(Address, SideState)>,
}

impl RecordKey {
    /// Returns a key over `sides` and `states`.
    ///
    /// Each is sorted by address and deduplicated.
    pub fn new(
        doc: Address,
        base: Address,
        sides: impl IntoIterator<Item = Address>,
        states: impl IntoIterator<Item = (Address, SideState)>,
    ) -> RecordKey {
        let mut sides: Vec<Address> = sides.into_iter().collect();
        sides.sort_by_key(reads::comps);
        sides.dedup();
        let mut states: Vec<(Address, SideState)> = states.into_iter().collect();
        states.sort_by_key(|(at, _)| reads::comps(at));
        states.dedup_by(|a, b| a.0 == b.0);
        RecordKey { doc, base, sides, states }
    }

    /// Returns the key with its states dropped.
    ///
    /// It is the key of the composition whatever state its mutable sides
    /// were read in: the one a person's earlier landing of the merge is
    /// found by ([`landed_draft`]) after a side's text has changed.
    pub fn stateless(&self) -> RecordKey {
        RecordKey { states: Vec::new(), ..self.clone() }
    }

    /// Returns the key as one line of text.
    ///
    /// The text is `merge:<doc>:<base>:<side>+<side>…`, then `:<side>@<q>`
    /// for each state — `@null` for [`SideState::Unarranged`], none for
    /// [`SideState::Unrecorded`] — as long as its sides make it. So a key
    /// with no fork or draft side, or one of a record written before the
    /// states were kept, spells the text it spelled then. It is the text
    /// naming the shot's writes, and it opens the draft landing's, which
    /// names the draft and the position too and, for a draft named, the
    /// record the landing follows where one stands, and the stage's, which
    /// names the position and, where one stands, the record the landing will
    /// replace. A write's per-session ids are spelled over the SHA-256 of its
    /// text, a fixed width whatever the sides (the `land` module's doc).
    pub fn text(&self) -> String {
        let sides: Vec<String> = self.sides.iter().map(ToString::to_string).collect();
        let mut text = format!("merge:{}:{}:{}", self.doc, self.base, sides.join("+"));
        for (at, state) in &self.states {
            match state {
                SideState::Unrecorded => {}
                SideState::Unarranged => text.push_str(&format!(":{at}@null")),
                SideState::At(q) => text.push_str(&format!(":{at}@{q}")),
            }
        }
        text
    }

    /// Returns a position every record of this key was linked past: the
    /// floor of a lookup of them ([`NewestFirst`]).
    ///
    /// A record of the key is written after a composition read the head it
    /// names, minted at `head_minted`, and each fork or draft side in the
    /// state the key keeps, its text last changed at that state's position,
    /// so its link is minted past the greatest of them. `None` where none is
    /// known.
    pub(super) fn floor(&self, head_minted: Option<u64>) -> Option<u64> {
        let states = self.states.iter().filter_map(|(_, state)| match state {
            SideState::At(q) => Some(*q),
            SideState::Unarranged | SideState::Unrecorded => None,
        });
        states.chain(head_minted).max()
    }
}

/// A mutable side's state, as the record keeps it (§4; skep #770).
///
/// It is the position the side's text last changed at as of the position P
/// the composition stands at, `doc_metadata`'s `arranged_at` read off the
/// side's own metadata (wire.md §The response envelope): the fork's and
/// the draft's, whose texts change after a merge. A member is immutable, so
/// its address is its state and it carries none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideState {
    /// No state recorded.
    ///
    /// It is a record written before the states were kept, its side
    /// carrying no `arranged` member.
    Unrecorded,
    /// The board served `arranged_at` `null` at P.
    ///
    /// It is a document never arranged since its mint, or one minted
    /// before the board kept the position.
    Unarranged,
    /// The side's `arranged_at` at P.
    At(u64),
}

impl SideState {
    /// Returns the state a served `arranged_at` names.
    ///
    /// It is `At` its position, `Unarranged` for `null`.
    pub fn of(arranged_at: Option<u64>) -> SideState {
        arranged_at.map_or(SideState::Unarranged, SideState::At)
    }

    /// Returns whether a side recorded in this state has moved since.
    ///
    /// `now` is the state the side is read in. An `At` or `Unarranged` side has
    /// moved where `now` is another state. An `Unrecorded` one has where its
    /// text was arranged after `since`, the position of the landing the record
    /// names — never where `since` is unknown.
    pub fn moved(self, now: SideState, since: Option<u64>) -> bool {
        let now = match now {
            SideState::At(q) => Some(q),
            SideState::Unarranged | SideState::Unrecorded => None,
        };
        match self {
            SideState::At(q) => now != Some(q),
            SideState::Unarranged => now.is_some(),
            SideState::Unrecorded => since.zip(now).is_some_and(|(since, now)| now > since),
        }
    }

    /// Returns the state as a record's `arranged` member spells it.
    ///
    /// It is the position, `null` for `Unarranged`, and `None` — no member
    /// — for `Unrecorded`.
    fn to_value(self) -> Option<Value> {
        match self {
            SideState::Unrecorded => None,
            SideState::Unarranged => Some(Value::Null),
            SideState::At(q) => Some(Value::from(q)),
        }
    }

    /// Returns the state a side's `arranged` member spells.
    ///
    /// It is `Unrecorded` where the member is missing, `Unarranged` for
    /// `null` and `At` for a number; `None` for a member of another kind.
    fn from_value(v: Option<&Value>) -> Option<SideState> {
        match v {
            None => Some(SideState::Unrecorded),
            Some(Value::Null) => Some(SideState::Unarranged),
            Some(q) => q.as_u64().map(SideState::At),
        }
    }
}

// ── the sides and the landing, as the record spells them ──────────────────

/// One side as the record's `sides` carries it (§4).
///
/// It is a member with its role, a fork with its state, or a draft with the
/// position it was read at and its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideAt {
    /// `{"at": <member>, "role": …}` — the head or an alternative.
    Member {
        /// The member.
        at: Address,
        /// Its role, the head's or an alternative's.
        role: Role,
    },
    /// `{"at": <fork>, "role": "fork", "arranged": N}`.
    Fork {
        /// The fork.
        at: Address,
        /// The fork's state when the merge was composed.
        ///
        /// [`verify`] answers [`Verdict::SideMoved`] where the fork has been
        /// arranged since, never `Differs`.
        arranged: SideState,
    },
    /// A draft, with the position it was read at and its state.
    ///
    /// It is spelled `{"at": {"draft": <address>, "position": N}, "role":
    /// "draft", "arranged": N}`.
    Draft {
        /// The draft.
        at: Address,
        /// The position the draft was read at (§4: "for a draft read at N").
        ///
        /// Every record `compose` builds names one — the position P the
        /// composition stands at: the input's, else the one its fences stand
        /// at, the draft unchanged across them (the `reads` module's doc) —
        /// and [`verify`] reads the draft and its recorded base as of it,
        /// whatever the landing
        /// that rendered the draft has made of either since. A record naming
        /// none reads them at the position its own first read answers.
        position: Option<u64>,
        /// The draft's state as of that position.
        ///
        /// It is a term of the key; `verify` reads the draft at `position`
        /// whatever its state now.
        arranged: SideState,
    },
}

impl SideAt {
    /// Returns the record's side for a composed [`Side`].
    ///
    /// The side stood at `at` as it was read, the position P the composition
    /// stands at, and `arranged_at` is the `doc_metadata` term its anchor was
    /// read with. A
    /// draft names `at` as the position it was read at, and a fork and a
    /// draft carry their state, `arranged_at` or `Unarranged` where the
    /// board served none; a member carries neither.
    pub fn of(side: &Side, at: u64, arranged_at: Option<u64>) -> SideAt {
        match side {
            Side::Member(member) => SideAt::Member { at: member.clone(), role: Role::Alternative },
            Side::Fork(fork) => {
                SideAt::Fork { at: fork.clone(), arranged: SideState::of(arranged_at) }
            }
            Side::Draft { at: draft, .. } => SideAt::Draft {
                at: draft.clone(),
                position: Some(at),
                arranged: SideState::of(arranged_at),
            },
        }
    }

    /// Returns the side's address.
    pub fn address(&self) -> &Address {
        match self {
            SideAt::Member { at, .. } | SideAt::Fork { at, .. } | SideAt::Draft { at, .. } => at,
        }
    }

    /// Returns the side's role.
    pub fn role(&self) -> Role {
        match self {
            SideAt::Member { role, .. } => *role,
            SideAt::Fork { .. } => Role::Fork,
            SideAt::Draft { .. } => Role::Draft,
        }
    }

    /// Returns the side's state: a fork's or a draft's, `None` for a member.
    pub fn arranged(&self) -> Option<SideState> {
        match self {
            SideAt::Member { .. } => None,
            SideAt::Fork { arranged, .. } | SideAt::Draft { arranged, .. } => Some(*arranged),
        }
    }

    /// Returns the [`Side`] a record's side composes as; the head is no side.
    pub fn side(&self) -> Option<Side> {
        match self {
            SideAt::Member { role: Role::Head, .. } => None,
            SideAt::Member { at, .. } => Some(Side::Member(at.clone())),
            SideAt::Fork { at, .. } => Some(Side::Fork(at.clone())),
            SideAt::Draft { at, position, .. } => {
                Some(Side::Draft { at: at.clone(), position: *position })
            }
        }
    }

    fn to_value(&self) -> Value {
        let (mut v, arranged) = match self {
            SideAt::Member { at, role } => {
                (json!({"at": at.to_string(), "role": role.as_str()}), None)
            }
            SideAt::Fork { at, arranged } => {
                (json!({"at": at.to_string(), "role": Role::Fork.as_str()}), arranged.to_value())
            }
            SideAt::Draft { at, position, arranged } => (
                json!({"at": {"draft": at.to_string(), "position": position}, "role": Role::Draft.as_str()}),
                arranged.to_value(),
            ),
        };
        if let Some(arranged) = arranged {
            v["arranged"] = arranged;
        }
        v
    }

    /// Returns the side a record's `sides` entry spells.
    ///
    /// An `at` object is a draft read at its `position`; an `at` address is
    /// a fork where the role is `fork`, else a member. A missing `arranged`
    /// reads as [`SideState::Unrecorded`], and `None` is answered for an
    /// entry this build cannot read.
    fn from_value(v: &Value) -> Option<SideAt> {
        let role = Role::parse(v["role"].as_str()?)?;
        let arranged = || SideState::from_value(v.get("arranged"));
        match (&v["at"], role) {
            (Value::String(at), Role::Fork) => {
                Some(SideAt::Fork { at: parse_address(at)?, arranged: arranged()? })
            }
            (Value::String(at), role) => Some(SideAt::Member { at: parse_address(at)?, role }),
            (at, _) => Some(SideAt::Draft {
                at: parse_address(at["draft"].as_str()?)?,
                position: at["position"].as_u64(),
                arranged: arranged()?,
            }),
        }
    }
}

/// Where a record's merge landed (§4, `landed`).
///
/// It is the member minted and the ack's position, or the draft the merged
/// list was landed into and the position of the `set_arrangement` that
/// first landed it — a later landing of the key into that draft is the same
/// landing and writes no record (skep #790; the `land` module's doc); where
/// the landing found the member standing, the position is the one it was
/// minted at, its own `doc_metadata` `at`. `None` in the
/// record is the question — a merger that chose not to land (§3) — or,
/// where the record `replaces` one naming a draft landing, the undo's or
/// the withdrawal's testimony that the merge no longer stands on the draft
/// (the `undo` module's doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordLanding {
    /// `{"member": …, "position": N}`.
    Member {
        /// The member minted.
        member: Address,
        /// The shot's commit position.
        ///
        /// Where the landing found the member standing, it is the member's
        /// own `doc_metadata` `at`, the commit that minted it; on a board
        /// serving none, the position of the member's mint row on the feed,
        /// else the reads' highest `as_of`.
        position: u64,
    },
    /// `{"draft": …, "position": N}`.
    Draft {
        /// The staging draft.
        draft: Address,
        /// The commit position of the `set_arrangement` that first landed
        /// the key in the draft — the write's ack `at`.
        ///
        /// At that landing it is the position the merge marker on the draft
        /// carries (`doc_metadata`'s `merge.at`), or on a draft with no
        /// recorded base — a baseless draft, an admitted fork — the
        /// position of its `set_arrangement` row naming the merge, the mark
        /// a `resume` finds the landing by. The record keeps it: a later
        /// landing of the key into the draft moves the mark and writes no
        /// record (skep #790), so the mark, never this, names the draft's
        /// latest landing, and a fresh landing that finds this record
        /// standing answers the mark's position as `Landed::Draft`'s
        /// `position`, this one only where the mark cannot be read, the walk
        /// of a baseless draft's rows needing a past state the board has
        /// reclaimed; a draft marking no landing of the merge at or past it
        /// holds none, and that landing stages afresh. `verify` reads the
        /// draft at it.
        position: u64,
    },
}

// ── the answers at the window parts ───────────────────────────────────────

/// How a window part was answered (§1.5, THE SHOT's WINDOW PARTS), as the
/// record spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedAnswer {
    /// Windowed from the published words a record names.
    Window,
    /// Left out of the merge.
    LeaveOut,
    /// Kept behind a placeholder.
    KeepPrivate,
}

impl RecordedAnswer {
    /// Returns the answer's spelling in the record.
    ///
    /// It is `window`, `leave_out` or `keep_private`.
    pub fn as_str(self) -> &'static str {
        match self {
            RecordedAnswer::Window => "window",
            RecordedAnswer::LeaveOut => "leave_out",
            RecordedAnswer::KeepPrivate => "keep_private",
        }
    }

    /// Returns the answer a spelling names, `None` for any other text.
    pub fn parse(text: &str) -> Option<RecordedAnswer> {
        match text {
            "window" => Some(RecordedAnswer::Window),
            "leave_out" => Some(RecordedAnswer::LeaveOut),
            "keep_private" => Some(RecordedAnswer::KeepPrivate),
            _ => None,
        }
    }
}

/// One answer as the record keeps it (§4, `answers`).
///
/// It is a window part's, or a draft side's words the shot sent by
/// reference, identified by its words, never by a position in a draft, so
/// the answer can be applied to the merged list a verifier recomputes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartAnswer {
    /// The part's words, on its origin.
    pub from: Run,
    /// The answer given.
    pub answer: RecordedAnswer,
    /// The published words it was windowed from, where it was.
    pub to: Option<Run>,
}

impl PartAnswer {
    fn to_value(&self) -> Value {
        let spell = |run: &Run| json!({"i_start": run.address_at(0).map(|a| a.to_string()), "width": run.width.to_string()});
        let mut v = json!({"from": spell(&self.from), "answer": self.answer.as_str()});
        if let Some(to) = &self.to {
            v["to"] = spell(to);
        }
        v
    }

    fn from_value(v: &Value) -> Option<PartAnswer> {
        let run = |m: &Value| {
            let i_start = m["i_start"].as_str()?;
            let origin = origin_of(i_start)?;
            let first = last_component(&parse_address(i_start)?)?;
            let width: u64 = m["width"].as_str()?.parse().ok()?;
            Some(Run::new(origin, first, width))
        };
        let answer = RecordedAnswer::parse(v["answer"].as_str()?)?;
        let to = match v.get("to") {
            None | Some(Value::Null) => None,
            Some(to) => Some(run(to)?),
        };
        Some(PartAnswer { from: run(&v["from"])?, answer, to })
    }
}

// ── the record ────────────────────────────────────────────────────────────

/// The merge record (§4, "Under D13"), as a struct.
///
/// It is one JSON object, its `type` fixed [`TYPE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The trunk.
    pub doc: Address,
    /// The base — never absent: a member, or the document itself where a
    /// side was begun before its first version, its own arrangement from
    /// before that version the state composed over.
    ///
    /// The `no_base` shape is not offered (decision 15).
    pub base: Address,
    /// The head, then every side composed.
    ///
    /// Every shape the record draws has two or more.
    pub sides: Vec<SideAt>,
    /// Where the merge landed, or `None` for the question — or, in a record
    /// replacing one that names a draft landing, for the merge taken back
    /// out of the draft by an undo or a withdrawal.
    pub landed: Option<RecordLanding>,
    /// The supersession claims' addresses.
    ///
    /// They are those standing at the daughters when the record was written
    /// whose `new` is the landed member — the claims the shot deposited, one
    /// per daughter it named (the `land` module's doc); none at a draft
    /// landing, and none where the shot named no daughter.
    pub claims: Vec<Address>,
    /// The run counts, `{a, b, m}` (decision 17).
    pub runs: RunCounts,
    /// How many times the merger's publish landed as a daughter.
    ///
    /// Each time, it composed again (decision 17).
    pub retries: u32,
    /// The gap report, as §1.4's.
    pub gaps: Vec<Gap>,
    /// The value rule's switches and where it fired.
    pub values: ValueLog,
    /// The answers the shot's list was composed under, where any stands.
    ///
    /// They are the merger's at the window parts (§1.5, THE SHOT's WINDOW
    /// PARTS) and a draft side's words the shot sent by reference because a
    /// record names them as published, each windowed to the record's `to`
    /// (the `windows` module's doc, the twins).
    pub answers: Vec<PartAnswer>,
    /// The record this one supersedes under the key.
    ///
    /// It is its link's address — or `None` at the first (P1). A record
    /// with `landed` none replacing one that names a draft landing is an
    /// undo's or a withdrawal's: the merge was taken out of that draft.
    pub replaces: Option<Address>,
    /// The library's crate and version.
    pub by: String,
    /// The link this record was found through, homed in its journal.
    ///
    /// It stands where the record was read from a board; `None` for one
    /// composed and not yet landed. No member of the body.
    pub link: Option<Address>,
}

impl Record {
    /// Returns the record as its one JSON object.
    pub fn to_value(&self) -> Value {
        let landed = match &self.landed {
            None => Value::Null,
            Some(RecordLanding::Member { member, position }) => {
                json!({"member": member.to_string(), "position": position})
            }
            Some(RecordLanding::Draft { draft, position }) => {
                json!({"draft": draft.to_string(), "position": position})
            }
        };
        let mut body = json!({
            "type": TYPE,
            "v": SCHEMA_VERSION,
            "rules": RULES,
            "doc": self.doc.to_string(),
            "base": self.base.to_string(),
            "sides": self.sides.iter().map(SideAt::to_value).collect::<Vec<_>>(),
            "landed": landed,
            "claims": self.claims.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "runs": {"a": self.runs.a, "b": self.runs.b, "m": self.runs.m},
            "retries": self.retries,
            "gaps": self.gaps.iter().map(gap_to_value).collect::<Vec<_>>(),
            "values": {"dedup": self.values.dedup, "retype": self.values.retype, "applied": self.values.applied.iter().map(|g| g.0).collect::<Vec<_>>()},
            "replaces": self.replaces.as_ref().map(ToString::to_string),
            "by": self.by,
        });
        if !self.values.retyped.is_empty() {
            body["values"]["retyped"] = self
                .values
                .retyped
                .iter()
                .map(|(side, run)| side_run_to_value(*side, run))
                .collect();
        }
        if !self.answers.is_empty() {
            body["answers"] = Value::Array(self.answers.iter().map(PartAnswer::to_value).collect());
        }
        body
    }

    /// Returns the record a JSON object spells.
    ///
    /// `None` for an object of another `type`, another schema version, or
    /// one missing a member this build cannot do without or spelling one it
    /// cannot read — a gap naming a side past the one byte a side is
    /// numbered by among them; a missing `landed`, `claims`, `retries`,
    /// `replaces`, `by`, `values.applied`, `values.retyped` or `answers`, or
    /// a gap's missing `spots` or `removed`, reads as its empty value, a
    /// side's missing `arranged` as [`SideState::Unrecorded`], and `rules` is
    /// not read: [`verify`] composes under this build's [`RULES`]. A member
    /// this build does not know is left unread.
    pub fn from_value(v: &Value) -> Option<Record> {
        if v["type"].as_str() != Some(TYPE) || v["v"].as_u64() != Some(SCHEMA_VERSION) {
            return None;
        }
        let addr = |m: &Value| m.as_str().and_then(parse_address);
        let landed = match &v["landed"] {
            Value::Null => None,
            l if l.get("member").is_some() => Some(RecordLanding::Member {
                member: addr(&l["member"])?,
                position: l["position"].as_u64()?,
            }),
            l => Some(RecordLanding::Draft {
                draft: addr(&l["draft"])?,
                position: l["position"].as_u64()?,
            }),
        };
        let sides =
            v["sides"].as_array()?.iter().map(SideAt::from_value).collect::<Option<Vec<_>>>()?;
        let claims =
            v["claims"].as_array().map_or(Some(Vec::new()), |c| c.iter().map(addr).collect())?;
        let count = |m: &Value| m.as_u64().map(|n| n as usize);
        let runs = RunCounts {
            a: count(&v["runs"]["a"])?,
            b: count(&v["runs"]["b"])?,
            m: count(&v["runs"]["m"])?,
        };
        let gaps = v["gaps"].as_array()?.iter().map(gap_from_value).collect::<Option<Vec<_>>>()?;
        let applied = v["values"]["applied"].as_array().map_or(Some(Vec::new()), |a| {
            a.iter().map(|g| g.as_u64().map(|n| GapId(n as u32))).collect()
        })?;
        let retyped = v["values"]["retyped"]
            .as_array()
            .map_or(Some(Vec::new()), |a| a.iter().map(side_run_from_value).collect())?;
        let answers = v["answers"].as_array().map_or(Some(Vec::new()), |a| {
            a.iter().map(PartAnswer::from_value).collect()
        })?;
        Some(Record {
            doc: addr(&v["doc"])?,
            base: addr(&v["base"])?,
            sides,
            landed,
            claims,
            runs,
            retries: v["retries"].as_u64().unwrap_or(0) as u32,
            gaps,
            values: ValueLog {
                dedup: v["values"]["dedup"].as_bool()?,
                retype: v["values"]["retype"].as_bool()?,
                applied,
                retyped,
            },
            answers,
            replaces: v["replaces"].as_str().and_then(parse_address),
            by: v["by"].as_str().unwrap_or("").to_string(),
            link: None,
        })
    }

    /// Returns the key the record is current under.
    ///
    /// It is its sides' addresses and the state of each fork or draft side.
    pub fn key(&self) -> RecordKey {
        RecordKey::new(
            self.doc.clone(),
            self.base.clone(),
            self.sides.iter().map(|s| s.address().clone()),
            self.sides.iter().filter_map(|s| Some((s.address().clone(), s.arranged()?))),
        )
    }

    /// Returns the head side — the one with `role` `head`.
    pub fn head(&self) -> Option<&SideAt> {
        self.sides.iter().find(|s| s.role() == Role::Head)
    }

    /// Returns the composition's options the record carries.
    ///
    /// They are the value switches, the retries, and the merger's
    /// resolutions as the gaps record them, so a verifier composes the same
    /// M and the same gaps (§4). Each gap a person, an agent or an answer
    /// settled is re-stated as its place, then its placement (§1.4 step 7):
    /// the place is a move `After` the anchor M holds before the gap and one
    /// `Before` the anchor after it, each that stands, which name the place
    /// together where a run the base places twice holds an anchor at two
    /// places (skep #763); the placement is the order or the omission its
    /// `placed` spells. At a gap of one group a move also places it by its
    /// anchor, so a gap placed `after` gives its `After` last and one placed
    /// `before` its `Before`. A `moves` gap, which has no anchors, is
    /// re-stated by its order alone — at one with spots the holder whose
    /// placement M took (CM-I33).
    pub fn options(&self) -> Options {
        let mut resolutions = Vec::new();
        for gap in &self.gaps {
            let by = match &gap.resolved_by {
                Some(ResolvedBy::Rule) | None => continue,
                Some(by) => by.clone(),
            };
            let after = gap.after.clone().map(Choice::After);
            let before = gap.before.clone().map(Choice::Before);
            let places: Vec<Choice> = match gap.placed {
                Placement::After => before.into_iter().chain(after).collect(),
                _ => after.into_iter().chain(before).collect(),
            };
            // The places first: at a gap of one group a move also sets the
            // placement, which the order or the omission after it sets again.
            let choices: Vec<Choice> = match &gap.placed {
                Placement::Order(sides) => {
                    places.into_iter().chain([Choice::Order(sides.clone())]).collect()
                }
                Placement::Omitted => places.into_iter().chain([Choice::Omit]).collect(),
                Placement::After | Placement::Before => places,
            };
            resolutions.extend(
                choices.into_iter().map(|choice| Resolution { gap: gap.id, choice, by: by.clone() }),
            );
        }
        Options {
            dedup: self.values.dedup,
            retype: self.values.retype,
            resolutions,
            retries: self.retries,
        }
    }

    /// Returns each place the value rule's dedup kept once, by gap number.
    ///
    /// They are the gaps `values.applied` names (§4, `values`; §5, case
    /// (g)), each read off the gap alone: `kept` its `placed` order and
    /// `dropped` its runs of every other side, in the gap's order, less the
    /// words a kept side lists too, which M holds ([`Run::without`]). A gap
    /// is read only where the dedup's placement stands — an `order` gap
    /// placed by sides and settled by the rule, or left unsettled where the
    /// dedup kept two or more sides' copies of three or more — so an id
    /// naming no gap, a gap of another kind or placement, one a person, an
    /// agent or an answer resolved, and one where no word is left out name
    /// no place.
    pub fn deduped(&self) -> Vec<Deduped> {
        let mut ids = self.values.applied.clone();
        ids.sort();
        ids.dedup();
        ids.into_iter()
            .filter_map(|id| {
                let gap = self.gaps.iter().find(|g| g.id == id && g.kind == GapKind::Order)?;
                let Placement::Order(kept) = &gap.placed else { return None };
                let by_the_dedup = match gap.resolved_by {
                    Some(ResolvedBy::Rule) => true,
                    None => kept.len() >= 2,
                    Some(_) => false,
                };
                let held: Vec<&Run> = gap
                    .runs
                    .iter()
                    .filter(|(side, _)| kept.contains(side))
                    .map(|(_, run)| run)
                    .collect();
                let dropped: Vec<(SideIx, Run)> = gap
                    .runs
                    .iter()
                    .filter(|(side, _)| !kept.contains(side))
                    .flat_map(|(side, run)| {
                        run.without(held.iter().copied())
                            .into_iter()
                            .map(move |piece| (*side, piece))
                    })
                    .collect();
                if !by_the_dedup || dropped.is_empty() {
                    return None;
                }
                Some(Deduped { gap: id, kept: kept.clone(), dropped })
            })
            .collect()
    }
}

/// One place the value rule's dedup kept once (§5, case (g)).
///
/// Two or more sides added the same bytes at one spot, an `order` gap: M
/// holds the copy of each side `kept` names, and each run `dropped` names
/// stays in its side, with any link on it, carried into no merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deduped {
    /// The gap, by its number in the report.
    pub gap: GapId,
    /// The sides whose copy M holds, in M's order: the gap's `placed`.
    pub kept: Vec<SideIx>,
    /// Every other side's runs at the gap, in the gap's order, less the
    /// words a kept side lists too.
    pub dropped: Vec<(SideIx, Run)>,
}

/// Returns one gap as the record spells it (§4, `gaps`).
///
/// A `moves` gap with spots carries `spots`, each `{side, after, before}`
/// (CM-I33), and a `line` gap a lone removal meets carries `removed`, each
/// `{side, after, before}` too (skep #1176); every other gap carries
/// neither.
fn gap_to_value(g: &Gap) -> Value {
    let kind = match g.kind {
        GapKind::Order => "order",
        GapKind::Anchor => "anchor",
        GapKind::Corner => "corner",
        GapKind::Cut => "cut",
        GapKind::Collision => "collision",
        GapKind::Moves => "moves",
        GapKind::Line => "line",
    };
    let placed = match &g.placed {
        Placement::Order(sides) => Value::from(sides.iter().map(|s| s.0).collect::<Vec<u8>>()),
        Placement::After => Value::from("after"),
        Placement::Before => Value::from("before"),
        Placement::Omitted => Value::from("omitted"),
    };
    let resolved_by = match &g.resolved_by {
        None => Value::Null,
        Some(ResolvedBy::Rule) => Value::from("rule"),
        Some(ResolvedBy::Person) => Value::from("person"),
        Some(ResolvedBy::Agent) => Value::from("agent"),
        Some(ResolvedBy::Answer(a)) => Value::from(format!("answer:{a}")),
    };
    let runs: Vec<Value> = g.runs.iter().map(|(side, run)| side_run_to_value(*side, run)).collect();
    let mut gap = json!({
        "id": g.id.0,
        "kind": kind,
        "after": g.after.as_ref().map(ToString::to_string),
        "before": g.before.as_ref().map(ToString::to_string),
        "runs": runs,
        "placed": placed,
        "settled": g.settled,
        "resolved_by": resolved_by,
    });
    if !g.spots.is_empty() {
        gap["spots"] = g
            .spots
            .iter()
            .map(|s| {
                json!({
                    "side": s.side.0,
                    "after": s.after.as_ref().map(ToString::to_string),
                    "before": s.before.as_ref().map(ToString::to_string),
                })
            })
            .collect();
    }
    if !g.removed.is_empty() {
        gap["removed"] = g
            .removed
            .iter()
            .map(|s| {
                json!({
                    "side": s.side.0,
                    "after": s.after.as_ref().map(ToString::to_string),
                    "before": s.before.as_ref().map(ToString::to_string),
                })
            })
            .collect();
    }
    gap
}

/// Returns a run with the side that placed it as the record spells one:
/// `{side, i_start, width}`, a gap's runs and the retype's alike (§4).
fn side_run_to_value(side: SideIx, run: &Run) -> Value {
    json!({"side": side.0, "i_start": run.address_at(0).map(|a| a.to_string()), "width": run.width.to_string()})
}

/// Returns the run and its side a `{side, i_start, width}` object spells,
/// the origin by [`origin_of`]; `None` for one this build cannot read.
fn side_run_from_value(v: &Value) -> Option<(SideIx, Run)> {
    let i_start = v["i_start"].as_str()?;
    let origin = origin_of(i_start)?;
    let first = last_component(&parse_address(i_start)?)?;
    let width: u64 = v["width"].as_str()?.parse().ok()?;
    Some((side_ix(&v["side"])?, Run::new(origin, first, width)))
}

/// Returns the gap a JSON object spells, its runs' origins by [`origin_of`].
///
/// A gap with no `spots` reads with none, as one written before a `moves`
/// gap carried them does, and a gap with no `removed` reads with none, as
/// one written before a `line` gap named its lone removals does.
fn gap_from_value(v: &Value) -> Option<Gap> {
    let kind = match v["kind"].as_str()? {
        "order" => GapKind::Order,
        "anchor" => GapKind::Anchor,
        "corner" => GapKind::Corner,
        "cut" => GapKind::Cut,
        "collision" => GapKind::Collision,
        "moves" => GapKind::Moves,
        "line" => GapKind::Line,
        _ => return None,
    };
    let placed = match &v["placed"] {
        Value::Array(sides) => Placement::Order(
            sides.iter().map(side_ix).collect::<Option<Vec<_>>>()?,
        ),
        Value::String(s) if s == "after" => Placement::After,
        Value::String(s) if s == "before" => Placement::Before,
        Value::String(s) if s == "omitted" => Placement::Omitted,
        _ => return None,
    };
    let resolved_by = match &v["resolved_by"] {
        Value::Null => None,
        Value::String(s) if s == "rule" => Some(ResolvedBy::Rule),
        Value::String(s) if s == "person" => Some(ResolvedBy::Person),
        Value::String(s) if s == "agent" => Some(ResolvedBy::Agent),
        Value::String(s) => Some(ResolvedBy::Answer(parse_address(s.strip_prefix("answer:")?)?)),
        _ => return None,
    };
    let runs = v["runs"].as_array()?.iter().map(side_run_from_value).collect::<Option<Vec<_>>>()?;
    let anchor = |m: &Value| match m {
        Value::Null => Some(None),
        Value::String(s) => parse_address(s).map(Some),
        _ => None,
    };
    let spots = match &v["spots"] {
        Value::Null => Vec::new(),
        spots => spots
            .as_array()?
            .iter()
            .map(|s| {
                Some(Spot { side: side_ix(&s["side"])?, after: anchor(&s["after"])?, before: anchor(&s["before"])? })
            })
            .collect::<Option<Vec<_>>>()?,
    };
    let removed = match &v["removed"] {
        Value::Null => Vec::new(),
        removed => removed
            .as_array()?
            .iter()
            .map(|s| {
                Some(Removed { side: side_ix(&s["side"])?, after: anchor(&s["after"])?, before: anchor(&s["before"])? })
            })
            .collect::<Option<Vec<_>>>()?,
    };
    Some(Gap {
        id: GapId(v["id"].as_u64()? as u32),
        kind,
        after: anchor(&v["after"])?,
        before: anchor(&v["before"])?,
        runs,
        placed,
        settled: v["settled"].as_bool()?,
        resolved_by,
        spots,
        removed,
    })
}

/// Returns the side a gap's `side` or `placed` entry names.
///
/// A side is numbered by one byte, its [`SideIx`]: a number past `u8::MAX`
/// names no side the composition could have numbered, so `None`.
fn side_ix(v: &Value) -> Option<SideIx> {
    v.as_u64().and_then(|n| u8::try_from(n).ok()).map(SideIx)
}

// ── how a reader finds it, and its currency ───────────────────────────────

/// Returns the current record for `key`.
///
/// It is the newest record naming the key, the trunk owner's records
/// current over another account's (§4, "Its currency"; decision 8), found
/// as "How a reader finds it" says: the links of `kind` to each side
/// (`find_links_ftt` over `ty` and `to`, never a class scan), each homed in
/// the journal holding its record, each record's atom read through its
/// journal's arrangement — `image` then `retrieve_v`, never `retrieve_i` —
/// and its key checked. A record whose journal the reader may not read is
/// no candidate: a journal is a private draft, its links hidden with it, so
/// a reader finds the records of the journals it may read. Nor is one whose
/// journal is not registered or is in more pieces than `image` answers,
/// whose atom is not arranged, or whose bytes are no record of the kind
/// (`NewestFirst`); and the trunk's owner is unknown only where the trunk
/// is withheld or not registered. Every other refusal of a read is answered
/// as itself, never as no record standing (SP-14). `None` where no readable
/// record names the key.
///
/// Newest: the record whose link was minted last (`Found::age`), the
/// owner's account's records preferred before any other's — an account's
/// records being those whose links lie in it exactly, never in an account
/// nested under it. The owner's links are read first, and another
/// account's only where none of the owner's records names the key. Each
/// pool is read newest first and no further than its first record of the
/// key, nor past the key's floor (`NewestFirst`): the mint of the latest
/// trunk member among the key's sides, read where a link to them stands
/// (one `doc_metadata`), and each fork's and draft's state.
///
/// # Errors
///
/// A transport halt, the board's other refusals of a read and a board
/// answer of a shape this client does not know, [`Refusal::Halt`]; the
/// death signal under the token, [`Refusal::SessionEnded`], the lookup made
/// again on a new session.
pub fn current(
    board: &Board,
    token: Option<&Token>,
    kind: &Address,
    key: &RecordKey,
) -> Result<Option<Record>, Refusal> {
    let reader = Reader::new(board, token, OnEnd::Rerun);
    let owner = match reader.metadata(&key.doc, None) {
        Ok(meta) => Some(meta.owner),
        Err(Refusal::Unreadable(_) | Refusal::NoSuchDocument(_)) => None,
        Err(e) => return Err(e),
    };
    let floor = || Ok(key.floor(trunk_minted(&reader, key)?));
    current_among(&reader, kind, key, owner.as_deref(), None, floor)
}

/// Runs [`current`] over a reader, the trunk owner's account known where it
/// is.
///
/// `head`, where the caller knows it, is the key's head side, whose links
/// are not read: a record links its target and its sides besides the head
/// (§4, "Its home"), so a link to the head is a record of the merge that
/// minted it, never one of this key. `floor` answers the lookup's floor
/// ([`RecordKey::floor`]), asked only where a link stands to walk.
///
/// # Errors
///
/// As [`current`]'s, `floor`'s among them, the death signal faced for
/// `reader`'s act.
pub(super) fn current_among(
    reader: &Reader<'_>,
    kind: &Address,
    key: &RecordKey,
    owner: Option<&str>,
    head: Option<&Address>,
    floor: impl FnOnce() -> Result<Option<u64>, Refusal>,
) -> Result<Option<Record>, Refusal> {
    let links = record_links(reader, kind, key.sides.iter().filter(|s| Some(*s) != head))?;
    if links.is_empty() {
        return Ok(None);
    }
    let floor = floor()?;
    let (owned, others): (Vec<Address>, Vec<Address>) = links
        .into_iter()
        .partition(|link| owner.is_some_and(|owner| owned_by(&link.to_string(), owner)));
    for pool in [owned, others] {
        let mut walk = NewestFirst::new(reader, pool, floor);
        while let Some(found) = walk.next_found()? {
            if found.record.key() == *key {
                return Ok(Some(found.record));
            }
        }
    }
    Ok(None)
}

/// Returns the position the latest trunk member among `key`'s sides was
/// minted at, a floor of a lookup of the records naming them: every side
/// stood before a record naming it was written (one `doc_metadata`).
///
/// # Errors
///
/// As [`minted`]'s.
fn trunk_minted(reader: &Reader<'_>, key: &RecordKey) -> Result<Option<u64>, Refusal> {
    let trunk = key.sides.iter().filter(|side| reads::is_trunk_member(&key.doc, side));
    match trunk.max_by_key(|side| reads::comps(side)) {
        Some(member) => minted(reader, member),
        None => Ok(None),
    }
}

/// Returns the position `doc` was minted at, read off its `doc_metadata` at
/// the head.
///
/// `None` where the board serves none, or refuses the read `withheld` or
/// `doc_not_registered`: a lookup given it as its floor then reads to its
/// oldest link.
///
/// # Errors
///
/// The read's other refusals, each as itself (SP-14).
fn minted(reader: &Reader<'_>, doc: &Address) -> Result<Option<u64>, Refusal> {
    match reader.metadata(doc, None) {
        Ok(meta) => Ok(meta.at),
        Err(Refusal::Unreadable(_) | Refusal::NoSuchDocument(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Returns `account`'s own record of a draft landing of `key`'s merge.
///
/// The key's states are ignored. The record is found as [`current`] finds
/// records — the links of `kind` to each side of the key, each record's atom
/// read through its journal — but matched on `doc`, `base` and `sides` alone
/// ([`RecordKey::stateless`]), so a record composed over a fork or a draft side
/// whose text has changed since matches, and so does one written before the
/// states were kept. Only the links lying in `account` exactly are read,
/// another account's passed over unread; of their matches, it is the newest
/// by the order their links were minted that names a draft
/// landing and that no take-back's record among them replaces
/// (`taken_back_links`): a record stands for the landing it names until a
/// take-back replaces it, whatever landing of the key was recorded since, so
/// an undo of a later landing elsewhere leaves the earlier one named (P20).
/// The records are read newest first and no further than that one
/// (`NewestFirst`) — a take-back is newer than the record it replaces, so
/// read before it — nor past the mint of the latest trunk member among the
/// key's sides, read where a link to them stands (one `doc_metadata`).
/// `None` where every draft landing so recorded was taken back. An embedder
/// reads it where a composition finds no record of its own key standing, to
/// find the draft holding the person's latest landing of the merge, still the
/// one to land in; that draft's marker, read as it stands, says whether the
/// landing stands there. The record a draft's own landing stands on is
/// [`standing_landing`]'s, read by that draft's mark.
///
/// # Errors
///
/// As [`current`]'s.
pub fn landed_draft(
    board: &Board,
    token: Option<&Token>,
    kind: &Address,
    key: &RecordKey,
    account: &str,
) -> Result<Option<Record>, Refusal> {
    let reader = Reader::new(board, token, OnEnd::Rerun);
    let stateless = key.stateless();
    let links: Vec<Address> = record_links(&reader, kind, &key.sides)?
        .into_iter()
        .filter(|link| owned_by(&link.to_string(), account))
        .collect();
    if links.is_empty() {
        return Ok(None);
    }
    let mut walk = NewestFirst::new(&reader, links, trunk_minted(&reader, key)?);
    let mut taken_back: Vec<Address> = Vec::new();
    while let Some(Found { link, record, .. }) = walk.next_found()? {
        if record.key().stateless() != stateless {
            continue;
        }
        match &record.landed {
            Some(RecordLanding::Draft { .. }) if !taken_back.contains(&link) => {
                return Ok(Some(record))
            }
            None => taken_back.extend(record.replaces.clone()),
            Some(_) => {}
        }
    }
    Ok(None)
}

/// Returns the links of the records among `found` that a take-back replaces.
///
/// A take-back's record — an undo's or a withdrawal's — names no landing and
/// names in `replaces` the record of the landing it took back (P20), so a
/// record whose link is among these stands for no landing. A landing's own
/// `replaces` ends none: the landing whose record it names stands on in its
/// draft until a take-back of it.
pub(super) fn taken_back_links(found: &[Found]) -> Vec<Address> {
    found
        .iter()
        .filter(|f| f.record.landed.is_none())
        .filter_map(|f| f.record.replaces.clone())
        .collect()
}

/// Returns `account`'s own record of the landing `marker` marks in `draft`.
///
/// It is the record a re-open of the draft goes by, whatever the merge
/// landed in since: a landing of the same merge in another draft writes a
/// record of its own, newest of the merge, which [`landed_draft`] answers.
/// The records are those of `kind` linked to the draft whose links lie in
/// `account` exactly, kept before any record is read (`linked_to`), each
/// record's atom read through its journal: another account's record is
/// never read, never answered, and never replaces one of the account's own
/// (P20, a record replacing one of its own home). Of those it is the one
/// standing for the marker (`standing_for`): the newest naming the draft as
/// landed in at or before the marker's `at`, with the marker's head and
/// sides, that no record of the account's linked to the draft replaces —
/// the record of that landing, or of the same landing made earlier (skep
/// #790), never one a take-back replaced, one of a landing made since or
/// one of another merge. A marker whose `at` the board serves none bounds
/// no position. `None` where none stands: a landing cut off before its
/// record among them. [`standing_landing`] reads the mark off the draft as it
/// stands and answers this for it.
///
/// # Errors
///
/// The read of the links to the draft refused `withheld`, as
/// [`Refusal::Unreadable`], or `doc_not_registered`, as
/// [`Refusal::NoSuchDocument`], naming it; then the floor's and each
/// record's read as [`current`] reads them, a refusal but the absences it
/// reads as none answered as itself (SP-14): a transport halt, the board's
/// other refusals and an answer of a shape this client does not know,
/// [`Refusal::Halt`]; the death signal under the token,
/// [`Refusal::SessionEnded`], the lookup made again on a new session.
pub fn landing_record(
    board: &Board,
    token: Option<&Token>,
    kind: &Address,
    draft: &Address,
    marker: &MergeMarker,
    account: &str,
) -> Result<Option<Record>, Refusal> {
    let reader = Reader::new(board, token, OnEnd::Rerun);
    let mut own = linked_to(&reader, kind, draft, account, &marker.head)?;
    let at = marker.at.unwrap_or(u64::MAX);
    Ok(standing_for(&mut own, draft, marker, at)?.map(|f| f.record))
}

/// Returns `account`'s own record of the merge landing standing in `draft`.
///
/// The landing is the one the board marks in the draft as it stands, never
/// one found by the draft's words (the landing lane's R2), and the record is
/// [`landing_record`]'s for that mark, whatever the merge landed in since.
/// The draft's `doc_metadata` is read first. Where the board records a base
/// for the draft, the mark is its marker (`merge`). Where it records none,
/// the draft carries no marker (wire.md §Arrangement, `merge`), and the mark
/// is the landing standing by its `set_arrangement` rows on the supplement:
/// its sides and head, at its row's position ([`baseless_landing`]; skep
/// #914) — a landing stands from its write until it is taken back, and a
/// restore or any other re-arrangement neither ends it nor brings it back.
/// `None` where no landing stands: a published document, read no further;
/// a draft whose base record carries no marker; a baseless draft whose
/// landings were each taken back, or that has none, or one whose walk
/// needs a past state the board has reclaimed, so nothing is said of a
/// landing it cannot judge (the `landings` module's doc); and a mark no
/// record of the account's stands for, a landing cut off before its record
/// among them. An embedder reads it before a landing into a draft it names,
/// for the landing that one goes over.
///
/// # Errors
///
/// In this order:
///
/// - the draft's `doc_metadata` refused `withheld`, as
///   [`Refusal::Unreadable`], or `doc_not_registered`, as
///   [`Refusal::NoSuchDocument`], naming it, and an answer of a shape this
///   client does not know, faced;
/// - on a draft with no recorded base, [`baseless_landing`]'s but
///   [`Refusal::HistoryReclaimed`]: the feed walk's, a transport fault as
///   [`Refusal::Halt`], and where a plain row follows a landing the reads of
///   the draft's past states, [`Refusal::HistoryBusy`] past the bounded
///   retries among them, each as itself (SP-14);
/// - [`landing_record`]'s.
///
/// [`baseless_landing`]: super::baseless_landing
///
/// The death signal under the token at any read is
/// [`Refusal::SessionEnded`], the lookup made again on a new session.
pub fn standing_landing(
    board: &Board,
    token: Option<&Token>,
    kind: &Address,
    draft: &Address,
    account: &str,
) -> Result<Option<Record>, Refusal> {
    let reader = Reader::new(board, token, OnEnd::Rerun);
    let meta = reader.metadata(draft, None)?;
    if meta.published {
        return Ok(None);
    }
    let marker = match meta.base {
        Some(_) => meta.merge,
        None => landings::standing_mark(&reader, draft)?,
    };
    match marker {
        Some(marker) => landing_record(board, token, kind, draft, &marker, account),
        None => Ok(None),
    }
}

/// Returns `account`'s own merge records of `kind` linked to `draft`, as a
/// walk from the newest down ([`NewestFirst`]).
///
/// They are found through the links of the kind to the draft, each link
/// kept where its address lies in `account` exactly — never in an account
/// nested under it — before its record is read: a record names in
/// `replaces` one of its own home's (P20), so another account's record, a
/// sub-account's among them, is never read, never judged and never counts
/// as replacing one of the account's own, and no refusal of its journal's
/// reads stops the account's act. Each record kept is read through its
/// journal as the walk comes to it, whatever its `landed` names — a
/// landing's record, or a take-back's, which names none (skep #870) — each
/// with the link it was found through; a record whose journal the reader
/// may not read is no candidate. A record's link runs to the draft it
/// landed in, or the one a take-back took the merge out of, and to each of
/// its sides besides the head (§4, "Its home"), so these hold the account's
/// records of every landing in the draft and of their take-backs, beside
/// those of merges the draft is a side of: [`landing_record`] reads a
/// draft's landing record among them, and the take-backs the record their
/// act replaces or writes again (the `undo` module's doc). Each looks for
/// one landing's record, of the merge `head` names, so the walk's floor is
/// that head's mint ([`minted`], one `doc_metadata` where a link stands):
/// every record of a landing on that head, and every take-back of one, was
/// written after it.
///
/// # Errors
///
/// The link read's refusal at the draft, `withheld` and `doc_not_registered`
/// naming it; then [`minted`]'s.
pub(super) fn linked_to<'r, 'a>(
    reader: &'r Reader<'a>,
    kind: &Address,
    draft: &Address,
    account: &str,
    head: &str,
) -> Result<NewestFirst<'r, 'a>, Refusal> {
    let v = reader.answered(
        draft,
        &frames::find_links_ftt(&kind.to_string(), &draft.to_string()),
        None,
    )?;
    let own: Vec<Address> = answers::addrs(&v)
        .into_iter()
        .filter(|link| owned_by(link, account))
        .filter_map(parse_address)
        .collect();
    let floor = match parse_address(head) {
        Some(head) if !own.is_empty() => minted(reader, &head)?,
        _ => None,
    };
    Ok(NewestFirst::new(reader, own, floor))
}

/// Returns the record standing for `marker`'s landing in `draft`.
///
/// It is the newest among `own`, an account's own records of the kind
/// linked to the draft ([`linked_to`]), that names the draft as landed in
/// at or before `at`, the marker's position, with the marker's head and
/// sides, and that none of `own` replaces: the record of that landing, or
/// of the same landing made earlier (skep #790), never one a take-back
/// replaced or one of a landing made since. The walk stops at it: a record
/// naming another in `replaces` is newer than it, so read before it. `None`
/// where none stands.
///
/// # Errors
///
/// The walk's ([`NewestFirst::next_found`]).
pub(super) fn standing_for(
    own: &mut NewestFirst<'_, '_>,
    draft: &Address,
    marker: &MergeMarker,
    at: u64,
) -> Result<Option<Found>, Refusal> {
    let mut replaced: Vec<Address> = Vec::new();
    while let Some(found) = own.next_found()? {
        if of_the_landing(&found, draft, marker, at) && !replaced.contains(&found.link) {
            return Ok(Some(found));
        }
        replaced.extend(found.record.replaces);
    }
    Ok(None)
}

/// Returns the take-back a withdrawal's undo replaces and the landing's record.
///
/// The landing's record is the newest among `own`, an account's own
/// records of the kind linked to the draft ([`linked_to`]), that names
/// `draft` as landed in at or before `at`, the cleared marker's position,
/// with `marker`'s head and sides, whether any of `own` replaces it or not:
/// the record of that landing, or of the same landing made earlier (skep
/// #790). The take-back is the newest among `own` that names no landing,
/// replaces that record and was minted past `at`: one made since the
/// landing — the withdrawal's, or that of a later act that took the marker
/// out again — whatever record has named it in `replaces` since, a later
/// landing of the merge among them. The walk stops at the landing's record,
/// every take-back of it being newer and read before it. `None` where either
/// is missing: no record of the landing among `own`; or none of its
/// take-backs made since the landing — the record standing, the withdrawal's
/// own unwritten, or the record already written again — or every one made
/// before it, the record an earlier landing's, taken back before this
/// landing was made with its own record unwritten. A link the board serves
/// no position for is minted past no position.
///
/// # Errors
///
/// The walk's ([`NewestFirst::next_found`]).
pub(super) fn taken_back(
    own: &mut NewestFirst<'_, '_>,
    draft: &Address,
    marker: &MergeMarker,
    at: u64,
) -> Result<Option<(Found, Found)>, Refusal> {
    let mut newer: Vec<Found> = Vec::new();
    while let Some(landing) = own.next_found()? {
        if !of_the_landing(&landing, draft, marker, at) {
            newer.push(landing);
            continue;
        }
        let takes_back = |f: &&Found| {
            f.record.landed.is_none()
                && f.record.replaces.as_ref() == Some(&landing.link)
                && f.at.is_some_and(|minted| minted > at)
        };
        let take_back = newest(newer.iter().filter(takes_back).cloned());
        return Ok(take_back.map(|take_back| (landing, take_back)));
    }
    Ok(None)
}

/// Returns whether `found` is a record of `marker`'s landing in `draft`.
///
/// It names the draft as landed in at or before `at`, the marker's
/// position, with the marker's head and sides ([`lands_the_marker`]).
fn of_the_landing(found: &Found, draft: &Address, marker: &MergeMarker, at: u64) -> bool {
    let position = match &found.record.landed {
        Some(RecordLanding::Draft { position, .. }) => *position,
        _ => return false,
    };
    position <= at && lands_the_marker(&found.record, draft, marker)
}

/// Returns whether `record` is a landing in `draft` of `marker`'s merge.
///
/// It is landed in the draft, its head the marker's, and its sides, the
/// draft's own excepted, the marker's sides.
fn lands_the_marker(record: &Record, draft: &Address, marker: &MergeMarker) -> bool {
    let landed_here =
        matches!(&record.landed, Some(RecordLanding::Draft { draft: d, .. }) if d == draft);
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

/// A record as a reader found it: the record, the link it was found
/// through, and that link's age.
#[derive(Clone)]
pub(super) struct Found {
    /// The link of the kind, homed in the journal holding the record.
    pub(super) link: Address,
    /// The position of the commit that minted the link (`read_link`'s
    /// `at`); `None` where the board serves none — a link a build before
    /// the position map minted.
    pub(super) at: Option<u64>,
    /// The record, its `link` the one it was found through.
    pub(super) record: Record,
}

impl Found {
    /// Returns where the record stands in the order its links were minted
    /// (§4, "Its currency": the latest one naming the key).
    ///
    /// It is the position its link was minted at — a link the board serves
    /// none for was minted by a build before the position map, so before
    /// any it serves one for — the link's address breaking a tie. Each link
    /// is homed in the journal that holds its record, any number of them
    /// per account, so an address orders links within one journal alone.
    pub(super) fn age(&self) -> (Option<u64>, Vec<Nat>) {
        (self.at, reads::comps(&self.link))
    }
}

/// Returns the newest of `found` by the order its links were minted in
/// (`Found::age`).
pub(super) fn newest(found: impl IntoIterator<Item = Found>) -> Option<Found> {
    found.into_iter().max_by_key(Found::age)
}

/// Returns the links of `kind` to each of `to`, each link once, in the order
/// the board answered them.
///
/// It is one `find_links_ftt` over `ty` and `to` the side, never a class
/// scan, for each side: the links a reader finds records through (§4, "How
/// a reader finds it").
///
/// # Errors
///
/// The finds' refusals as [`Reader::read`] answers them.
pub(super) fn record_links<'a>(
    reader: &Reader<'_>,
    kind: &Address,
    to: impl IntoIterator<Item = &'a Address>,
) -> Result<Vec<Address>, Refusal> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for side in to {
        let v = reader.read(&frames::find_links_ftt(&kind.to_string(), &side.to_string()), None)?;
        for link in answers::addrs(&v) {
            if seen.insert(link.to_string()) {
                out.extend(parse_address(link));
            }
        }
    }
    Ok(out)
}

/// One link of the kind, as read: its age and the atom its `from` names.
struct Pointed {
    link: Address,
    at: Option<u64>,
    atom: String,
}

impl Pointed {
    /// Returns where the link stands in the order links were minted, as
    /// `Found::age` orders the record it names.
    fn age(&self) -> (Option<u64>, Vec<Nat>) {
        (self.at, reads::comps(&self.link))
    }
}

/// One home's links of the kind, walked from its newest down.
struct HomeLinks {
    /// The links not yet read, oldest first: the walk takes the last.
    unread: Vec<Address>,
    /// The newest link read and not yet taken.
    ahead: Option<Pointed>,
}

/// A record lookup's walk: the records some links of the kind name, read
/// newest first down to a floor (§4, "Its currency": the latest one naming
/// the key).
///
/// A link is homed in the journal holding its record, and a home mints its
/// links in order, so a link's ordinal within its home is the order it was
/// minted in: each home's links are read from its newest down, one read
/// ahead in each, and the walk takes the newest of those by `Found::age`. A
/// home's walk ends at the first link minted at or below the floor, a
/// position past which every record the lookup can answer was linked
/// ([`RecordKey::floor`]); a link the board serves no position for is read
/// and passed, never an end. A link names no record where it reads as no
/// link or its `from` names no atom.
///
/// A record is read through its journal's arrangement, never by identity:
/// the journal's extent and image once a walk, then its atom's value by its
/// V-ordinal ([`Reader::values_by_ordinal`]). The links taken are read in
/// batches of one, two, four and on, each batch's atoms one read a journal,
/// so a lookup that stops at the newest record reads one link and one
/// value, and one that stops at the k-th reads about `log₂ k` values a
/// journal; [`NewestFirst::rest`] reads every record left in one batch. A
/// link names no record where its journal is not readable to this reader,
/// is not registered or is in more pieces than `image` answers, where its
/// atom is not arranged or is no composite value, and where the atom's
/// bytes are no record of the kind; where a batch's read meets an item no
/// value is spelled from, its journal's atoms are read one by one, so such
/// an atom names no record and its neighbours stand.
pub(super) struct NewestFirst<'r, 'a> {
    reader: &'r Reader<'a>,
    floor: Option<u64>,
    homes: Vec<HomeLinks>,
    /// Each journal read, with its image; `None` where it holds no record.
    journals: Vec<(Address, Option<Vec<IRun>>)>,
    /// Records read and not yet taken, newest first.
    ready: VecDeque<Found>,
    /// How many links the next batch takes.
    batch: usize,
}

impl<'r, 'a> NewestFirst<'r, 'a> {
    /// Returns the walk over `links` down to `floor`, nothing read yet.
    pub(super) fn new(
        reader: &'r Reader<'a>,
        links: Vec<Address>,
        floor: Option<u64>,
    ) -> NewestFirst<'r, 'a> {
        let mut homes: Vec<(String, HomeLinks)> = Vec::new();
        for link in links {
            let text = link.to_string();
            let home = home_of_link(&text).unwrap_or(&text).to_string();
            match homes.iter_mut().find(|(h, _)| *h == home) {
                Some((_, walk)) => walk.unread.push(link),
                None => homes.push((home, HomeLinks { unread: vec![link], ahead: None })),
            }
        }
        let homes = homes
            .into_iter()
            .map(|(_, mut walk)| {
                walk.unread.sort_by_key(reads::comps);
                walk.unread.dedup();
                walk
            })
            .collect();
        NewestFirst { reader, floor, homes, journals: Vec::new(), ready: VecDeque::new(), batch: 1 }
    }

    /// Returns the next record, the newest not yet taken; `None` where none
    /// is left above the floor.
    ///
    /// # Errors
    ///
    /// A refusal reading a link, a journal or an atom but the absences a
    /// link names no record for, as itself: a transport fault and the
    /// board's other refusals, [`Refusal::Halt`]; the death signal under the
    /// token, [`Refusal::SessionEnded`].
    pub(super) fn next_found(&mut self) -> Result<Option<Found>, Refusal> {
        loop {
            if let Some(found) = self.ready.pop_front() {
                return Ok(Some(found));
            }
            let mut taken = Vec::new();
            while taken.len() < self.batch {
                match self.newest_link()? {
                    Some(pointed) => taken.push(pointed),
                    None => break,
                }
            }
            if taken.is_empty() {
                return Ok(None);
            }
            self.batch = self.batch.saturating_mul(2);
            let read = bodies(self.reader, &mut self.journals, taken)?;
            self.ready.extend(read);
        }
    }

    /// Returns every record left above the floor, newest first, their atoms
    /// read in one batch.
    ///
    /// # Errors
    ///
    /// As [`NewestFirst::next_found`]'s.
    pub(super) fn rest(mut self) -> Result<Vec<Found>, Refusal> {
        let mut taken = Vec::new();
        while let Some(pointed) = self.newest_link()? {
            taken.push(pointed);
        }
        let mut found: Vec<Found> = self.ready.drain(..).collect();
        found.extend(bodies(self.reader, &mut self.journals, taken)?);
        Ok(found)
    }

    /// Returns the newest link not yet taken, each home's newest read first.
    fn newest_link(&mut self) -> Result<Option<Pointed>, Refusal> {
        for h in 0..self.homes.len() {
            self.read_ahead(h)?;
        }
        let newest = self
            .homes
            .iter()
            .enumerate()
            .filter_map(|(h, walk)| Some((walk.ahead.as_ref()?.age(), h)))
            .max()
            .map(|(_, h)| h);
        Ok(newest.and_then(|h| self.homes[h].ahead.take()))
    }

    /// Reads home `h`'s newest unread links until one names a record's atom,
    /// or one minted at or below the floor ends the home's walk.
    fn read_ahead(&mut self, h: usize) -> Result<(), Refusal> {
        let walk = &mut self.homes[h];
        while walk.ahead.is_none() {
            let Some(link) = walk.unread.pop() else { return Ok(()) };
            let lv = self.reader.read(&frames::read_link(&link.to_string()), None)?;
            let Some(Some(value)) = answers::link_value(&lv) else { continue };
            if value.at.zip(self.floor).is_some_and(|(at, floor)| at <= floor) {
                walk.unread.clear();
                return Ok(());
            }
            let Some(atom) = value.from.first().map(|span| span.start.clone()) else { continue };
            walk.ahead = Some(Pointed { link, at: value.at, atom });
        }
        Ok(())
    }
}

/// Returns the records `taken` name, in their order, each with its link and
/// the link's age.
///
/// Each journal the atoms lie in is read once a walk, `journals` keeping
/// its image, and its atoms among `taken` in one read ([`atom_values`]).
///
/// # Errors
///
/// As [`NewestFirst::next_found`]'s.
fn bodies(
    reader: &Reader<'_>,
    journals: &mut Vec<(Address, Option<Vec<IRun>>)>,
    taken: Vec<Pointed>,
) -> Result<Vec<Found>, Refusal> {
    let mut by_journal: Vec<(Address, Vec<usize>)> = Vec::new();
    for (k, pointed) in taken.iter().enumerate() {
        let Some(journal) = document_of(&pointed.atom).and_then(|j| parse_address(&j)) else {
            continue;
        };
        match by_journal.iter_mut().find(|(j, _)| *j == journal) {
            Some((_, ks)) => ks.push(k),
            None => by_journal.push((journal, vec![k])),
        }
    }
    let mut bytes: Vec<Option<Vec<u8>>> = vec![None; taken.len()];
    for (journal, ks) in by_journal {
        let at = match journals.iter().position(|(j, _)| *j == journal) {
            Some(at) => at,
            None => {
                let image = journal_image(reader, &journal)?;
                journals.push((journal.clone(), image));
                journals.len() - 1
            }
        };
        let Some(runs) = &journals[at].1 else { continue };
        let atoms: Vec<&str> = ks.iter().map(|&k| taken[k].atom.as_str()).collect();
        for (k, value) in ks.iter().zip(atom_values(reader, &journal, runs, &atoms)?) {
            bytes[*k] = value;
        }
    }
    Ok(taken
        .into_iter()
        .zip(bytes)
        .filter_map(|(pointed, bytes)| {
            let body = serde_json::from_slice::<Value>(&bytes?).ok()?;
            let mut record = Record::from_value(&body)?;
            record.link = Some(pointed.link.clone());
            Some(Found { link: pointed.link, at: pointed.at, record })
        })
        .collect())
}

/// Returns `journal`'s image, the atoms of its records arranged in it.
///
/// `None` where the journal is not readable to this reader, is not
/// registered, is in more pieces than `image` answers or holds no position.
///
/// # Errors
///
/// The extent's and the image's other refusals, each as itself.
fn journal_image(reader: &Reader<'_>, journal: &Address) -> Result<Option<Vec<IRun>>, Refusal> {
    let absent = |e: Refusal| match e {
        Refusal::Unreadable(_) | Refusal::NoSuchDocument(_) | Refusal::TooFragmented { .. } => {
            Ok(None)
        }
        e => Err(e),
    };
    let extent = match reader.extent(journal, None) {
        Ok(extent) => extent,
        Err(e) => return absent(e),
    };
    if extent == 0 {
        return Ok(None);
    }
    match reader.image(journal, None, 1, extent) {
        Ok(runs) => Ok(Some(runs)),
        Err(e) => absent(e),
    }
}

/// Returns the composite value at each of `atoms` in `journal`, whose image
/// is `runs`, in their order: `None` for an atom the journal does not
/// arrange or whose value is no composite one.
///
/// The values are read in one batch ([`Reader::values_by_ordinal`]), each
/// atom one position; where the batch meets an item no value is spelled
/// from, each atom is read alone, its value the delivery's first atom, an
/// atom whose read the board refuses `withheld` or `doc_not_registered`
/// naming none.
///
/// # Errors
///
/// As [`NewestFirst::next_found`]'s.
fn atom_values(
    reader: &Reader<'_>,
    journal: &Address,
    runs: &[IRun],
    atoms: &[&str],
) -> Result<Vec<Option<Vec<u8>>>, Refusal> {
    let ordinals: Vec<Option<u64>> = atoms.iter().map(|atom| answers::ordinal_of(runs, atom)).collect();
    let spans: Vec<(u64, u64)> = ordinals.iter().flatten().map(|&ordinal| (ordinal, 1)).collect();
    match reader.values_by_ordinal(journal, &spans) {
        Ok(read) => {
            let mut read = read.into_iter();
            Ok(ordinals
                .iter()
                .map(|ordinal| ordinal.and_then(|_| read.next()?.into_iter().next()))
                .collect())
        }
        Err(e @ Refusal::SessionEnded(_)) => Err(e),
        Err(_) => {
            let mut values = Vec::with_capacity(atoms.len());
            for ordinal in ordinals {
                let Some(ordinal) = ordinal else {
                    values.push(None);
                    continue;
                };
                let frame = frames::retrieve_v(&journal.to_string(), ordinal, 1);
                match reader.answered(journal, &frame, None) {
                    Ok(v) => values.push(answers::first_atom(&v)),
                    Err(Refusal::Unreadable(_) | Refusal::NoSuchDocument(_)) => values.push(None),
                    Err(e) => return Err(e),
                }
            }
            Ok(values)
        }
    }
}

// ── verify ────────────────────────────────────────────────────────────────

/// What [`verify`] answers (§4, testimony).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The landed member holds M over its first `placed` positions.
    ///
    /// For a draft landing, the draft's whole image at the position recorded
    /// is M.
    Equal,
    /// The landed member or draft differs from M, first at this V-ordinal.
    Differs {
        /// The first V-ordinal, counted from 1, at which the two differ.
        at: u64,
    },
    /// A fork side's text has changed since the merge was composed.
    ///
    /// The record names the fork's state when it was composed; the board
    /// now serves another, so the recomputation would read a text the merge
    /// never composed from, and no verdict on the landing is made of it —
    /// never `Differs`, which a record that is wrong answers (skep #770). A
    /// record written before the states were kept answers so where the fork
    /// was arranged after the landing it names.
    SideMoved {
        /// The fork side.
        side: Address,
        /// Its state as the record names it.
        recorded: SideState,
        /// Its `arranged_at` as the board serves it now; `None` for `null`.
        now: Option<u64>,
    },
    /// A document the verdict needs is not readable to this reader.
    ///
    /// It is the trunk, the head, the base or a side, withheld at any read
    /// the recomputation makes, the join's `compare` included; the origin of
    /// a run a side windows, met as a `withheld` item, or as the `withheld`
    /// a read by identity answers, where the value rule reads the run's
    /// values or the line rule reads it among the text that decides whether
    /// two sides' neighbouring changes meet at a line's edge, whatever the
    /// value switches — the composition's [`Refusal::LineTextWithheld`]; the
    /// landed member, or the draft, withheld or not registered; or the draft
    /// side, or the draft landed in, as of the position the record names for
    /// it, whose history the board has reclaimed: the verdict withheld, never
    /// made up (D14). At a read of several documents — the join's `compare`,
    /// the read by identity — it is the document the board names, and a
    /// `withheld` naming none is no verdict (SP-18).
    Unreadable(Address),
}

/// Verifies a record's testimony (§4, testimony; §7, `verify`).
///
/// M is recomputed from the record's inputs — its base, checked against the
/// base the board's recorded bases derive for its sides, its sides, its
/// value switches and the choices its gaps record — the merger's answers at
/// its window parts applied to it (`answers`, one function with the shot's
/// own, `merge::windows`'s `applied`), and compared with the landed
/// member's image over its first `placed` positions, or the draft's whole
/// image at the position recorded. A member is compared as the shot
/// minted it, a draft side's fresh text re-minted under the trunk, which
/// its addresses match by width alone: the member's words there and the
/// draft side's own are read at the head and compared position by position,
/// the first that differs answering `Differs`; a draft
/// is compared by identity, every run of M as the sides hold it, since the
/// one `set_arrangement` that landed it re-mints nothing. A draft side, and
/// the base the board records for it, are read as of the position the
/// record names for the side (wire.md §Reading history), so the testimony
/// is checked against the state the merge composed from, whatever the
/// landing that rendered the draft has made of either since. A fork side
/// is read at that same position where the record names one, else as it
/// stands, its anchor — the base the board records for it, else its source
/// — with it, so its state is checked first (skep #770): its `arranged_at`
/// is read where the recomputation will read the fork, and where it is not
/// the state the record names — or, in a record written before the states
/// were kept, where it is past the landing's position — the verdict is
/// [`Verdict::SideMoved`] naming the fork, before anything is recomputed;
/// the fork's state at the recomputation's own position is compared again
/// after its reads, so an edit landing between the two is `SideMoved` too,
/// never `Differs`. A fork whose recorded base moved since the record with
/// its text unmoved, or one the record, written before the states were
/// kept, names no state for, derives another base than the record names,
/// and the record is faced, never verified. The daemon's `compare` is asked
/// once as the oracle of the client's join (§1.3 step 4), in parts past its
/// budgets. Every metadata and image the recomputation reads is read as of
/// one position — the record's draft side's, else the `as_of` of its first
/// read, made at the head — and its values at the head, as a composition
/// reads them: a member's by its V-ordinals, a draft's or a fork's words by
/// the I-addresses its image served there (the `reads` module's doc).
///
/// A document the recomputation reads — the trunk, the head, the base, a
/// side — that the reader may not read withholds the verdict (§4,
/// testimony; D14): the board's `withheld` at any of its reads, the join's
/// `compare` included, answers [`Verdict::Unreadable`] naming the document
/// the board refused, and so does a `withheld` item a value read meets —
/// a run a side windows from a document the reader may not read, masked
/// at its own position (wire.md §Value encodings), which the value rule
/// reads or the line rule reads whatever the record's value switches (the
/// composition's [`Refusal::LineTextWithheld`]) — naming the item's
/// origin. A document the board has never registered is
/// no withheld one (wire.md §The read predicate): it is refused. A
/// `withheld` or a `doc_not_registered` at a read of several documents —
/// the join's `compare`, the read by identity — that names no document this
/// client parses is the board's refusal verbatim, never a verdict naming
/// one of the read's documents in the board's place (SP-18).
///
/// A position the record names — its draft side's, its draft landing's —
/// is read as named or not at all (skep #761): where the board has
/// reclaimed the history there the verdict is withheld,
/// [`Verdict::Unreadable`] naming the draft, and nothing is read at
/// another position in its place (D14).
///
/// # Errors
///
/// Before any read: a record with no head side is faced; then one whose
/// sides no merge composes — a head that is no trunk member of the
/// document, two draft sides ([`Refusal::TwoDrafts`]), more sides besides
/// the head than a merge numbers, faced, or a member or a fork no shape
/// reads ([`Refusal::BaseUnknown`]); then one with `landed` none, faced —
/// there is nothing to verify against. Then the fork sides' state
/// reads' refusals — a fork this reader may not read answers
/// [`Verdict::Unreadable`] naming it, a fork the board has not registered
/// is [`Refusal::NoSuchDocument`], and a position the record names answers
/// as the recomputation's reads at it do; then the reads' refusals
/// ([`Refusal`]) on the trunk, the head, the base and the sides — a
/// document the board has not registered, [`Refusal::NoSuchDocument`],
/// among them — but `withheld`, a rejection or an item a value read meets,
/// and a reclaimed position the record names, which answer
/// [`Verdict::Unreadable`], save a `withheld` or a `doc_not_registered`
/// naming no document this client parses at the join's `compare` or a read
/// by identity, the board's refusal verbatim ([`Refusal::Halt`], SP-18);
/// a record whose base is not the one the sides'
/// recorded bases derive, [`Refusal::NamedBaseDisagrees`] — beside a draft
/// side [`Refusal::DraftBaseDisagrees`], and beside a fork side faced,
/// naming the base the record names and the one the board's records now
/// derive: the fork's recorded base moved since the record with its text
/// unmoved, or the record, written before the states were kept, names no
/// state for it — never verified against the base it names; a record whose
/// fork side is of the trunk owner's own account, [`Refusal::ForkOfOwner`]
/// — the owner's draft is the draft side, and no composition names it as a
/// fork — never verified as a fork's merge; a position the record names
/// past the board's head or inside one commit, [`Refusal::BeyondHead`] or
/// [`Refusal::NotAPosition`] naming the draft as the record's — the record
/// was not written against this board's history as it stands; a client
/// join the oracle disagrees with is this library's own fault, faced; a
/// landed member with no `placed` term is faced; the landed document's
/// reads' refusals but `withheld`, `doc_not_registered` and a reclaimed
/// landing position, which answer [`Verdict::Unreadable`]; an `image` run
/// that is no content I-address. The death signal under the token at any
/// read is [`Refusal::SessionEnded`], the verification made again on a new
/// session.
pub fn verify(board: &Board, token: Option<&Token>, record: &Record) -> Result<Verdict, Refusal> {
    let reader = Reader::new(board, token, OnEnd::Rerun);
    let head = record.head().ok_or_else(|| {
        Halt::face(
            "the record names no head side",
            "a merge record's `sides` carries one side with the role `head`",
            "this record is not one this library wrote; nothing to verify",
        )
    })?;
    // The record's sides besides the head, and the sides they compose as,
    // in one order.
    let named: Vec<&SideAt> = record.sides.iter().filter(|s| s.side().is_some()).collect();
    let sides: Vec<Side> = named.iter().filter_map(|s| s.side()).collect();
    reads::check_shape(&record.doc, head.address(), &sides)?;
    let Some(landed) = &record.landed else {
        return Err(Halt::face(
            "nothing to verify: the record landed nothing",
            "a record with `landed` null is the question a merger filed, not a landing",
            "verify the record of the landing that answered it",
        )
        .into());
    };
    let (RecordLanding::Member { position: landed_at, .. }
    | RecordLanding::Draft { position: landed_at, .. }) = *landed;
    let options = record.options();
    // The position the record names for its draft side: every metadata and
    // image read of the recomputation, the join's oracle included, is made
    // at it, its values at the head.
    let composed_at = record.sides.iter().find_map(|s| match s {
        SideAt::Draft { at, position: Some(p), .. } => Some((at, *p)),
        SideAt::Draft { .. } | SideAt::Member { .. } | SideAt::Fork { .. } => None,
    });
    // Each fork's state, read where the recomputation will read the fork:
    // one arranged since the merge is no text the merge composed from.
    for side in &named {
        let SideAt::Fork { at: fork, arranged } = side else { continue };
        let now = match reader.metadata(fork, composed_at.map(|(_, p)| p)) {
            Ok(meta) => meta.arranged_at.position(),
            Err(Refusal::Unreadable(doc)) => return Ok(Verdict::Unreadable(doc)),
            Err(e) => return at_record(e, composed_at),
        };
        if arranged.moved(SideState::of(now), Some(landed_at)) {
            return Ok(Verdict::SideMoved { side: fork.clone(), recorded: *arranged, now });
        }
    }
    let readings = match reads::read_shape(
        &reader,
        reads::Reading::Verifying,
        &record.doc,
        head.address(),
        Some(record.base.clone()),
        &sides,
        &options,
    ) {
        Ok(readings) => readings,
        // A document the recomputation reads that this reader may not read,
        // the text deciding the line rule's among them: the verdict
        // withheld, never manufactured (§4, testimony; D14).
        Err(Refusal::Unreadable(doc) | Refusal::LineTextWithheld { doc, .. }) => {
            return Ok(Verdict::Unreadable(doc))
        }
        Err(e) => return at_record(e, composed_at),
    };
    // The forks' states at the recomputation's own position: an edit
    // landing after the check above is a fork arranged since, never a
    // difference.
    for (side, now) in named.iter().zip(&readings.arranged) {
        let SideAt::Fork { at: fork, arranged } = side else { continue };
        if arranged.moved(SideState::of(*now), Some(landed_at)) {
            return Ok(Verdict::SideMoved { side: fork.clone(), recorded: *arranged, now: *now });
        }
    }
    match reads::check_join(&reader, &readings) {
        Ok(()) => {}
        Err(Refusal::Unreadable(doc)) => return Ok(Verdict::Unreadable(doc)),
        Err(e) => return at_record(e, composed_at),
    }
    let (target, at, placed) = match landed {
        RecordLanding::Member { member, .. } => {
            let meta = match reader.metadata(member, None) {
                Ok(m) => m,
                Err(Refusal::Unreadable(_)) | Err(Refusal::NoSuchDocument(_)) => {
                    return Ok(Verdict::Unreadable(member.clone()))
                }
                Err(e) => return Err(e),
            };
            let placed = meta.placed.ok_or_else(|| Halt::face(format!("{member} carries no `placed` term"), "a member a shot minted carries the positions the client placed (wire.md §Namespace, `doc_metadata`)", "this member was not minted by a shot this library can verify"))?;
            (member.clone(), None, placed)
        }
        RecordLanding::Draft { draft, position } => {
            let extent = match reader.extent(draft, Some(*position)) {
                Ok(e) => e,
                Err(Refusal::Unreadable(_)) | Err(Refusal::NoSuchDocument(_)) => {
                    return Ok(Verdict::Unreadable(draft.clone()))
                }
                Err(e) => return at_record(e, Some((draft, *position))),
            };
            (draft.clone(), Some(*position), extent)
        }
    };
    let image = match reader.image(&target, at, 1, placed) {
        Ok(runs) => runs,
        Err(Refusal::Unreadable(_)) | Err(Refusal::NoSuchDocument(_)) => {
            return Ok(Verdict::Unreadable(target))
        }
        Err(e) => return at_record(e, at.map(|p| (&target, p))),
    };
    let actual = reads::runs_of(&image)?;
    // A member holds a draft side's text re-minted under the trunk, which
    // its family says, and each part as the merger's answer left it; a
    // draft holds every run of M by identity.
    let by_identity = matches!(record.landed, Some(RecordLanding::Draft { .. }));
    let answered = super::windows::applied(&readings.composed.runs, &readings.families, &record.doc, &record.answers);
    let expected: Vec<(Run, reads::Family)> = answered
        .iter()
        .map(|a| (a.run.clone(), if by_identity { reads::Family::Own } else { a.family }))
        .collect();
    if let Some(at) = reads::first_difference(&expected, &actual, &record.doc) {
        return Ok(Verdict::Differs { at });
    }
    // A member's re-minted words, matched above by their widths alone, are
    // the draft side's own or the member holds another text.
    if by_identity {
        return Ok(Verdict::Equal);
    }
    let re_minted = super::windows::re_minted(&answered);
    match reads::first_word_difference(&reader, &record.doc, &readings.maps, &target, &re_minted) {
        Ok(None) => Ok(Verdict::Equal),
        Ok(Some(at)) => Ok(Verdict::Differs { at }),
        Err(Refusal::Unreadable(doc)) => Ok(Verdict::Unreadable(doc)),
        Err(e) => Err(e),
    }
}

/// Returns what a refused read answers where the record named its position.
///
/// `recorded` is the document the record names a position for and that
/// position (§4: "for a draft read at N"; `landed`'s `position`). A read
/// refused there because the board has reclaimed the history is the
/// verdict withheld, [`Verdict::Unreadable`] naming the document; one past
/// the board's head or inside one commit is [`Refusal::BeyondHead`] or
/// [`Refusal::NotAPosition`] naming the document as the record's, whose
/// face advises no read elsewhere (skep #761). Nothing is read at another
/// position in its place (D14). Every other refusal, and one at a position
/// the record does not name, is the read's own.
///
/// # Errors
///
/// The refusal given, relabelled as the record's where it is a position
/// fault at the position recorded.
fn at_record(e: Refusal, recorded: Option<(&Address, u64)>) -> Result<Verdict, Refusal> {
    let Some((doc, position)) = recorded else { return Err(e) };
    match e {
        Refusal::HistoryReclaimed { at, .. } if at == position => {
            Ok(Verdict::Unreadable(doc.clone()))
        }
        Refusal::BeyondHead { at, head, .. } if at == position => {
            Err(Refusal::BeyondHead { at, head, recorded: Some(doc.clone()) })
        }
        Refusal::NotAPosition { at, nearest, .. } if at == position => {
            Err(Refusal::NotAPosition { at, nearest, recorded: Some(doc.clone()) })
        }
        e => Err(e),
    }
}
