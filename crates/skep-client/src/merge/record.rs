//! The merge record — the D13 `merge` kind (the merge record's §4).
//!
//! It holds the schema as a struct whose JSON is built by hand, the key a
//! record is current under and the currency rule ([`current`]: newest wins
//! per key, by the order the records' links were minted, the trunk owner's
//! records over another account's, decision 8), how a reader finds a record
//! (the link of the kind homed in the journal beside the record, from its
//! atom to the landed member or draft and every side besides the head, the
//! atom read through the journal's arrangement and never by identity), and
//! [`verify`], the record's testimony recomputed.
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
//! recomputable from reads a verifier can make — the base and the sides are
//! members, or a draft the verifier may read, the rules are versioned, the
//! value switches are in the body — so `verify` recomputes M and compares it
//! with the landed member's image over its first `placed` positions, or the
//! draft's at the position recorded, the daemon's `compare` the oracle the
//! client's join is checked against (§1.3 step 4), and answers `Equal`,
//! `Differs` or `Unreadable`, never a verdict manufactured for a document
//! it may not read (D14): the trunk, the head, the base, a side or the
//! landed document withheld from the reader answers `Unreadable` naming it,
//! as does the origin of a run a side windows whose values the value rule
//! reads, masked as a `withheld` item.
//! A position the record names is read as named or not at all: one whose
//! history the board has reclaimed withholds the verdict (`Unreadable`),
//! and one past the board's head or inside one commit is refused as the
//! record's, its face advising no read elsewhere (skep #761).
//!
//! **One schema**, kind `merge`: `type` fixed, `v` the schema's version,
//! `rules` the rule set's, then `doc`, `base`, `sides`, `landed`, `claims`,
//! `runs`, `retries`, `gaps`, `values`, `replaces` and `by` (§4, "Under
//! D13"), with `answers` beside them only where a window part was answered
//! (§1.5, THE SHOT's WINDOW PARTS): each is that part's words and its
//! answer, the published words it was windowed from where it was — so the
//! list `verify` recomputes is M as those answers left it, one function
//! with the shot's own (`merge::windows`). The record is encoded as the one
//! JSON object `serde_json` renders; a reader that does not know a member
//! treats it as absent.

use serde_json::{json, Value};
use skep_address::{Address, Nat};

use crate::address::{document_of, parse_address};
use crate::board::answers;
use crate::board::{frames, Board, Token};
use crate::halt::Halt;
use crate::publication::owned_by;

use super::compose::{
    Choice, Gap, GapId, GapKind, Options, Placement, Resolution, ResolvedBy, Run, RunCounts,
    SideIx, ValueLog,
};
use super::reads::{self, last_component, origin_of, OnEnd, Reader, Refusal, Role, Side};

/// The kind's `type` member, `merge`.
///
/// It is the word on every surface (decision 12), stated once as the
/// publication's [`MERGE_RECORD_TYPE`](crate::publication::MERGE_RECORD_TYPE),
/// whose enumeration keeps every atom carrying it out of what it publishes.
pub const TYPE: &str = crate::publication::MERGE_RECORD_TYPE;

/// The schema's version, `v`.
pub const SCHEMA_VERSION: u64 = 1;

/// The rule set's version, `rules`: §2's rule set is `merge-rules-1`.
pub const RULES: &str = "merge-rules-1";

/// Returns the `by` member: this library's crate and version.
pub(super) fn by() -> String {
    format!("skep-client {}", env!("CARGO_PKG_VERSION"))
}

// ── the key ───────────────────────────────────────────────────────────────

/// The key a record is current under — `(doc, base, {sides})`.
///
/// It is a term of the body (the merge record's §4, "Its currency"; P20).
/// The sides are a set: kept sorted, so two keys naming the same sides in
/// another order are one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordKey {
    /// The trunk document.
    pub doc: Address,
    /// The base member.
    pub base: Address,
    /// Every side's address, the head's included, in address order.
    pub sides: Vec<Address>,
}

impl RecordKey {
    /// Returns a key over `sides`, sorted and deduplicated.
    pub fn new(doc: Address, base: Address, sides: impl IntoIterator<Item = Address>) -> RecordKey {
        let mut sides: Vec<Address> = sides.into_iter().collect();
        sides.sort_by_key(reads::comps);
        sides.dedup();
        RecordKey { doc, base, sides }
    }

    /// Returns the key as one line of text.
    ///
    /// The text is `merge:<doc>:<base>:<side>+<side>…`, as long as its
    /// sides make it. It is the text naming the shot's writes, and it opens
    /// the draft landing's, which names the draft and the position too and,
    /// for a draft named, the record the landing follows where one stands,
    /// and the stage's, which names the position and, where one stands, the
    /// record the landing will replace. A write's per-session ids are
    /// spelled over the SHA-256 of its text, a fixed width whatever the
    /// sides (the `land` module's doc).
    pub fn text(&self) -> String {
        let sides: Vec<String> = self.sides.iter().map(ToString::to_string).collect();
        format!("merge:{}:{}:{}", self.doc, self.base, sides.join("+"))
    }
}

// ── the sides and the landing, as the record spells them ──────────────────

/// One side as the record's `sides` carries it (§4).
///
/// It is a member with its role, or a draft with the position it was read
/// at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideAt {
    /// `{"at": <member>, "role": …}` — the head, an alternative, or a fork.
    Member {
        /// The member.
        at: Address,
        /// Its role.
        role: Role,
    },
    /// `{"at": {"draft": <address>, "position": N}, "role": "draft"}`.
    Draft {
        /// The draft.
        at: Address,
        /// The position the draft was read at (§4: "for a draft read at N").
        ///
        /// Every record `compose` builds names one — the one position P
        /// every read of the composition was made at: the input's, else the
        /// one the composition's first read answered — and [`verify`] reads
        /// the draft and its recorded base as of it, whatever the landing
        /// that rendered the draft has made of either since. A record naming
        /// none reads them at the position its own first read answers.
        position: Option<u64>,
    },
}

impl SideAt {
    /// Returns the record's side for a composed [`Side`].
    pub fn of(side: &Side) -> SideAt {
        match side {
            Side::Member(at) => SideAt::Member { at: at.clone(), role: Role::Alternative },
            Side::Fork(at) => SideAt::Member { at: at.clone(), role: Role::Fork },
            Side::Draft { at, position } => SideAt::Draft { at: at.clone(), position: *position },
        }
    }

    /// Returns the side's address.
    pub fn address(&self) -> &Address {
        match self {
            SideAt::Member { at, .. } | SideAt::Draft { at, .. } => at,
        }
    }

    /// Returns the side's role.
    pub fn role(&self) -> Role {
        match self {
            SideAt::Member { role, .. } => *role,
            SideAt::Draft { .. } => Role::Draft,
        }
    }

    /// Returns the [`Side`] a record's side composes as; the head is no side.
    pub fn side(&self) -> Option<Side> {
        match self {
            SideAt::Member { role: Role::Head, .. } => None,
            SideAt::Member { at, role: Role::Fork } => Some(Side::Fork(at.clone())),
            SideAt::Member { at, .. } => Some(Side::Member(at.clone())),
            SideAt::Draft { at, position } => {
                Some(Side::Draft { at: at.clone(), position: *position })
            }
        }
    }

    fn to_value(&self) -> Value {
        match self {
            SideAt::Member { at, role } => json!({"at": at.to_string(), "role": role.as_str()}),
            SideAt::Draft { at, position } => {
                json!({"at": {"draft": at.to_string(), "position": position}, "role": Role::Draft.as_str()})
            }
        }
    }

    fn from_value(v: &Value) -> Option<SideAt> {
        let role = Role::parse(v["role"].as_str()?)?;
        match &v["at"] {
            Value::String(at) => Some(SideAt::Member { at: parse_address(at)?, role }),
            at => Some(SideAt::Draft {
                at: parse_address(at["draft"].as_str()?)?,
                position: at["position"].as_u64(),
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
/// the landing found the member standing with no feed row of its mint, the
/// position is the reads' highest `as_of`. `None` in the
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
        /// It is the reads' highest `as_of` where the member stood with no
        /// feed row of its mint.
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
        /// carries (`doc_metadata`'s `merge.at`), so a `resume` that finds
        /// the draft holding M with the marker of this merge's head takes
        /// the marker's `at`; where the draft carries no such marker — a
        /// baseless draft, an admitted fork — it is the resume's own read's
        /// `as_of`. The record keeps it: a later landing of the key into the
        /// draft moves the marker and writes no record (skep #790), so the
        /// marker, never this, names the draft's latest landing. `verify`
        /// reads the draft at it, and a fresh landing that finds this record
        /// standing answers it as `Landed::Draft`'s `position`.
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

/// One window part's answer as the record keeps it (§4, `answers`).
///
/// It is identified by its words, never by a position in a draft, so the
/// answer can be applied to the merged list a verifier recomputes.
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
    /// The base member — never absent.
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
    /// The merger's answers at the window parts of the shot, where any was
    /// given (§1.5, THE SHOT's WINDOW PARTS).
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
    /// `replaces`, `by`, `values.applied` or `answers` reads as its empty
    /// value, and `rules` is not read. A member this build does not know is left
    /// unread.
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
            },
            answers,
            replaces: v["replaces"].as_str().and_then(parse_address),
            by: v["by"].as_str().unwrap_or("").to_string(),
            link: None,
        })
    }

    /// Returns the key the record is current under.
    pub fn key(&self) -> RecordKey {
        RecordKey::new(
            self.doc.clone(),
            self.base.clone(),
            self.sides.iter().map(|s| s.address().clone()),
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
    /// the place is `After` the anchor M holds before the gap, or, at the
    /// start of M, `Before` the one after it, and the placement is the order
    /// or the omission its `placed` spells. A gap placed `after` is re-stated
    /// by its place alone and one placed `before` by its `before` anchor,
    /// either of which places a gap of one group by that anchor; a `moves`
    /// gap, which has no anchors, is re-stated by its order alone.
    pub fn options(&self) -> Options {
        let mut resolutions = Vec::new();
        for gap in &self.gaps {
            let by = match &gap.resolved_by {
                Some(ResolvedBy::Rule) | None => continue,
                Some(by) => by.clone(),
            };
            let place = gap
                .after
                .clone()
                .map(Choice::After)
                .or_else(|| gap.before.clone().map(Choice::Before));
            // The place first: at a gap of one group a move also sets the
            // placement, which the order or the omission after it sets again.
            let choices: Vec<Choice> = match &gap.placed {
                Placement::Order(sides) => {
                    place.into_iter().chain([Choice::Order(sides.clone())]).collect()
                }
                Placement::Omitted => place.into_iter().chain([Choice::Omit]).collect(),
                Placement::After => place.into_iter().collect(),
                Placement::Before => gap.before.clone().map(Choice::Before).into_iter().collect(),
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
}

/// Returns one gap as the record spells it (§4, `gaps`).
fn gap_to_value(g: &Gap) -> Value {
    let kind = match g.kind {
        GapKind::Order => "order",
        GapKind::Anchor => "anchor",
        GapKind::Corner => "corner",
        GapKind::Cut => "cut",
        GapKind::Collision => "collision",
        GapKind::Moves => "moves",
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
    let runs: Vec<Value> = g
        .runs
        .iter()
        .map(|(side, run)| json!({"side": side.0, "i_start": run.address_at(0).map(|a| a.to_string()), "width": run.width.to_string()}))
        .collect();
    json!({
        "id": g.id.0,
        "kind": kind,
        "after": g.after.as_ref().map(ToString::to_string),
        "before": g.before.as_ref().map(ToString::to_string),
        "runs": runs,
        "placed": placed,
        "settled": g.settled,
        "resolved_by": resolved_by,
    })
}

/// Returns the gap a JSON object spells, its runs' origins by [`origin_of`].
fn gap_from_value(v: &Value) -> Option<Gap> {
    let kind = match v["kind"].as_str()? {
        "order" => GapKind::Order,
        "anchor" => GapKind::Anchor,
        "corner" => GapKind::Corner,
        "cut" => GapKind::Cut,
        "collision" => GapKind::Collision,
        "moves" => GapKind::Moves,
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
    let runs = v["runs"]
        .as_array()?
        .iter()
        .map(|r| {
            let i_start = r["i_start"].as_str()?;
            let origin = origin_of(i_start)?;
            let first = last_component(&parse_address(i_start)?)?;
            let width: u64 = r["width"].as_str()?.parse().ok()?;
            Some((side_ix(&r["side"])?, Run::new(origin, first, width)))
        })
        .collect::<Option<Vec<_>>>()?;
    let anchor = |m: &Value| match m {
        Value::Null => Some(None),
        Value::String(s) => parse_address(s).map(Some),
        _ => None,
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
/// (`read_record`); and the trunk's owner is unknown only where the trunk
/// is withheld or not registered. Every other refusal of a read is answered
/// as itself, never as no record standing (SP-14). `None` where no readable
/// record names the key.
///
/// Newest: the record whose link was minted last (`Found::age`), the
/// owner's account's records preferred before any other's — an account's
/// records being those whose links lie in it exactly, never in an account
/// nested under it.
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
    current_among(&reader, kind, key, owner.as_deref())
}

/// Runs [`current`] over a reader, the trunk owner's account known where it
/// is.
///
/// # Errors
///
/// As [`current`]'s, the death signal faced for `reader`'s act.
pub(super) fn current_among(
    reader: &Reader<'_>,
    kind: &Address,
    key: &RecordKey,
    owner: Option<&str>,
) -> Result<Option<Record>, Refusal> {
    let found = records_of(reader, kind, key)?;
    let (owned, others): (Vec<Found>, Vec<Found>) =
        found.into_iter().partition(|f| owner.is_some_and(|owner| f.lies_in(owner)));
    let pool = if owned.is_empty() { others } else { owned };
    Ok(newest(pool).map(|f| f.record))
}

/// A record as a reader found it: the record, the link it was found
/// through, and that link's age.
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
    /// Returns whether the record's link lies in `account` exactly — never
    /// in an account nested under it.
    pub(super) fn lies_in(&self, account: &str) -> bool {
        owned_by(&self.link.to_string(), account)
    }

    /// Returns where the record stands in the order its links were minted
    /// (§4, "Its currency": the latest one naming the key).
    ///
    /// It is the position its link was minted at — a link the board serves
    /// none for was minted by a build before the position map, so before
    /// any it serves one for — the link's address breaking a tie. Each link
    /// is homed in the journal that holds its record, any number of them
    /// per account, so an address orders links within one journal alone.
    fn age(&self) -> (Option<u64>, Vec<Nat>) {
        (self.at, reads::comps(&self.link))
    }
}

/// Returns the newest of `found` by the order its links were minted in
/// (`Found::age`).
pub(super) fn newest(found: impl IntoIterator<Item = Found>) -> Option<Found> {
    found.into_iter().max_by_key(Found::age)
}

/// Returns every record naming `key` that the reader can read.
///
/// Each comes with the link it was found through and that link's age, in
/// the order the links were answered. They are found as [`current`] finds
/// them: the links of `kind` to each side of the key, each link once, each
/// record's atom read through its journal's arrangement and its key
/// checked.
///
/// # Errors
///
/// As [`current_among`]'s.
pub(super) fn records_of(
    reader: &Reader<'_>,
    kind: &Address,
    key: &RecordKey,
) -> Result<Vec<Found>, Refusal> {
    let mut seen: Vec<String> = Vec::new();
    let mut found: Vec<Found> = Vec::new();
    for side in &key.sides {
        let v = reader.read(&frames::find_links_ftt(&kind.to_string(), &side.to_string()), None)?;
        for link in answers::addrs(&v) {
            if seen.iter().any(|s| s == link) {
                continue;
            }
            seen.push(link.to_string());
            let Some(link_addr) = parse_address(link) else { continue };
            if let Some(f) = read_record(reader, &link_addr)? {
                if f.record.key() == *key {
                    found.push(f);
                }
            }
        }
    }
    Ok(found)
}

/// Returns the record a link of the kind names, with the link's age.
///
/// It is the atom the link's `from` slot starts at, read through the
/// journal's arrangement, and the position `read_link` answers for the
/// link; `None` where the journal or its atom is not readable to this
/// reader, where the journal is not registered or is in more pieces than
/// `image` answers, where the atom is not arranged, or where its bytes are
/// no record of the kind.
///
/// # Errors
///
/// A refusal reading the link, the journal or the atom but those absences,
/// as itself: a transport fault and the board's other refusals,
/// [`Refusal::Halt`]; the death signal under the token,
/// [`Refusal::SessionEnded`].
pub(super) fn read_record(reader: &Reader<'_>, link: &Address) -> Result<Option<Found>, Refusal> {
    let lv = reader.read(&frames::read_link(&link.to_string()), None)?;
    let Some(Some(value)) = answers::link_value(&lv) else { return Ok(None) };
    let Some(atom) = value.from.first().map(|span| span.start.as_str()) else { return Ok(None) };
    let Some(journal) = document_of(atom).and_then(|j| parse_address(&j)) else { return Ok(None) };
    let unreadable = |e: Refusal| match e {
        Refusal::Unreadable(_) | Refusal::NoSuchDocument(_) | Refusal::TooFragmented { .. } => {
            Ok(None)
        }
        e => Err(e),
    };
    let extent = match reader.extent(&journal, None) {
        Ok(e) => e,
        Err(e) => return unreadable(e),
    };
    if extent == 0 {
        return Ok(None);
    }
    let runs = match reader.image(&journal, None, 1, extent) {
        Ok(r) => r,
        Err(e) => return unreadable(e),
    };
    let Some(ordinal) = answers::ordinal_of(&runs, atom) else { return Ok(None) };
    let v = match reader.answered(
        &journal,
        &frames::retrieve_v(&journal.to_string(), ordinal, 1),
        None,
    ) {
        Ok(v) => v,
        Err(e) => return unreadable(e),
    };
    let Some(bytes) = answers::first_atom(&v) else { return Ok(None) };
    let Ok(body) = serde_json::from_slice::<Value>(&bytes) else { return Ok(None) };
    Ok(Record::from_value(&body).map(|mut record| {
        record.link = Some(link.clone());
        Found { link: link.clone(), at: value.at, record }
    }))
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
    /// A document the verdict needs is not readable to this reader.
    ///
    /// It is the trunk, the head, the base or a side, withheld at any read
    /// the recomputation makes, the join's `compare` included; the origin of
    /// a run a side windows, met as a `withheld` item where the value rule
    /// reads the run's values; the landed member, or the draft, withheld or
    /// not registered; or the draft side, or the draft landed in, as of the
    /// position the record names for it, whose history the board has
    /// reclaimed: the verdict withheld, never made up (D14).
    Unreadable(Address),
}

/// Verifies a record's testimony (§4, testimony; §7, `verify`).
///
/// M is recomputed from the record's inputs — its base, its sides, its
/// value switches and the choices its gaps record — the merger's answers at
/// its window parts applied to it (`answers`, one function with the shot's
/// own, `merge::windows`'s `applied`), and compared with the landed
/// member's image over its first `placed` positions, or the draft's whole
/// image at the position recorded. A member is compared as the shot
/// minted it, a draft side's fresh text re-minted under the trunk; a draft
/// is compared by identity, every run of M as the sides hold it, since the
/// one `set_arrangement` that landed it re-mints nothing. A draft side, and
/// the base the board records for it, are read as of the position the
/// record names for the side (wire.md §Reading history), so the testimony
/// is checked against the state the merge composed from, whatever the
/// landing that rendered the draft has made of either since. The daemon's
/// `compare` is asked once as the oracle of the client's join (§1.3 step
/// 4), in parts past its budgets.
///
/// A document the recomputation reads — the trunk, the head, the base, a
/// side — that the reader may not read withholds the verdict (§4,
/// testimony; D14): the board's `withheld` at any of its reads, the join's
/// `compare` included, answers [`Verdict::Unreadable`] naming the document
/// the board refused, and so does a `withheld` item a value read meets —
/// a run a side windows from a document the reader may not read, masked
/// at its own position (wire.md §Value encodings) — naming the item's
/// origin. A document the board has never registered is no withheld one
/// (wire.md §The read predicate): it is refused.
///
/// A position the record names — its draft side's, its draft landing's —
/// is read as named or not at all (skep #761): where the board has
/// reclaimed the history there the verdict is withheld,
/// [`Verdict::Unreadable`] naming the draft, and nothing is read at
/// another position in its place (D14).
///
/// # Errors
///
/// The reads' refusals ([`Refusal`]) on the trunk, the head, the base and
/// the sides — a document the board has not registered,
/// [`Refusal::NoSuchDocument`], among them — but `withheld`, a rejection
/// or an item a value read meets, and a reclaimed position the record
/// names, which answer [`Verdict::Unreadable`]; a position the record names
/// past the board's head or inside one commit, [`Refusal::BeyondHead`] or
/// [`Refusal::NotAPosition`] naming the draft as the record's — the record
/// was not written against this board's history as it stands; a record
/// with no head side or with `landed` none is faced — there is nothing to
/// verify against — and so is one naming more sides besides the head than
/// a merge numbers, before any read; a client join the oracle disagrees
/// with is this library's own fault, faced; a landed member with no
/// `placed` term is faced; the landed document's reads' refusals but
/// `withheld`, `doc_not_registered` and a reclaimed landing position, which
/// answer [`Verdict::Unreadable`]; an `image` run that is no content
/// I-address. The death signal under the token at any read is
/// [`Refusal::SessionEnded`], the verification made again on a new session.
pub fn verify(board: &Board, token: Option<&Token>, record: &Record) -> Result<Verdict, Refusal> {
    let reader = Reader::new(board, token, OnEnd::Rerun);
    let head = record.head().ok_or_else(|| {
        Halt::face(
            "the record names no head side",
            "a merge record's `sides` carries one side with the role `head`",
            "this record is not one this library wrote; nothing to verify",
        )
    })?;
    let sides: Vec<Side> = record.sides.iter().filter_map(SideAt::side).collect();
    let options = record.options();
    // The position the record names for its draft side: every read of the
    // recomputation, the join's oracle included, is made at it.
    let composed_at = record.sides.iter().find_map(|s| match s {
        SideAt::Draft { at, position: Some(p) } => Some((at, *p)),
        SideAt::Draft { .. } | SideAt::Member { .. } => None,
    });
    let recomputed = reads::read_shape(
        &reader,
        &record.doc,
        head.address(),
        Some(record.base.clone()),
        &sides,
        &options,
    )
    .and_then(|readings| reads::check_join(&reader, &readings).map(|()| readings));
    let readings = match recomputed {
        Ok(readings) => readings,
        // A document the recomputation reads that this reader may not read:
        // the verdict withheld, never manufactured (§4, testimony; D14).
        Err(Refusal::Unreadable(doc)) => return Ok(Verdict::Unreadable(doc)),
        Err(e) => return at_record(e, composed_at),
    };
    let (target, at, placed) = match &record.landed {
        Some(RecordLanding::Member { member, .. }) => {
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
        Some(RecordLanding::Draft { draft, position }) => {
            let extent = match reader.extent(draft, Some(*position)) {
                Ok(e) => e,
                Err(Refusal::Unreadable(_)) | Err(Refusal::NoSuchDocument(_)) => {
                    return Ok(Verdict::Unreadable(draft.clone()))
                }
                Err(e) => return at_record(e, Some((draft, *position))),
            };
            (draft.clone(), Some(*position), extent)
        }
        None => {
            return Err(Halt::face(
                "nothing to verify: the record landed nothing",
                "a record with `landed` null is the question a merger filed, not a landing",
                "verify the record of the landing that answered it",
            )
            .into())
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
        .into_iter()
        .map(|a| (a.run, if by_identity { reads::Family::Own } else { a.family }))
        .collect();
    Ok(match reads::first_difference(&expected, &actual, &record.doc) {
        None => Verdict::Equal,
        Some(at) => Verdict::Differs { at },
    })
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
