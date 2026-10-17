//! The merge record — the D13 `merge` kind (the merge record's §4).
//!
//! It holds the schema as a struct whose JSON is built by hand, the key a
//! record is current under and the currency rule ([`current`]: newest wins
//! per key, the trunk owner's home over another's, decision 8), how a reader
//! finds a record (the public link from the merger's doc 1 to the landed
//! member or draft and every side besides the head, the atom read through
//! the journal's arrangement and never by identity), and [`verify`], the
//! record's testimony recomputed.
//!
//! **Testimony, plainly (D4).** The record is a claim its writer makes, as
//! the supersession claim beside it is; the daemon derives nothing from it,
//! the member's arrangement is the fact. Everything it asserts is
//! recomputable from reads a verifier can make — the base and the sides are
//! members, or a draft the verifier may read, the rules are versioned, the
//! value switches are in the body — so `verify` recomputes M and compares it
//! with the landed member's image over its first `placed` positions, or the
//! draft's at the position recorded, the daemon's `compare` the oracle the
//! client's join is checked against (§1.3 step 4),
//! and answers `Equal`, `Differs` or `Unreadable`, never a verdict
//! manufactured for a side it may not read (D14).
//!
//! **One schema**, kind `merge`: `type` fixed, `v` the schema's version,
//! `rules` the rule set's, then `doc`, `base`, `sides`, `landed`, `claims`,
//! `runs`, `retries`, `gaps`, `values`, `replaces` and `by` (§4, "Under
//! D13"). The record is encoded as the one JSON object `serde_json`
//! renders; a reader that does not know a member treats it as absent.

use serde_json::{json, Value};
use skep_address::Address;

use crate::address::{doc_1_of, document_of, parse_address};
use crate::board::answers;
use crate::board::{frames, Board, Token};
use crate::halt::Halt;

use super::compose::{
    Choice, Gap, GapId, GapKind, Options, Placement, Resolution, ResolvedBy, Run, RunCounts,
    SideIx, ValueLog,
};
use super::reads::{self, last_component, origin_of, Reader, Refusal, Role, Side};

/// The kind's `type` member, `merge`.
///
/// It is the word on every surface (decision 12).
pub const TYPE: &str = "merge";

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
    /// The text is `merge:<doc>:<base>:<side>+<side>…`, the stem of the
    /// per-session idempotency ids the landing's writes carry.
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
        /// The position it was read at; `None` the head.
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
/// list was landed into and the position of its last edit; where the
/// landing found the member standing with no feed row of its mint, or the
/// draft already holding M, the position is the reads' highest `as_of`.
/// `None` in the record is the question — a merger that chose not to land
/// (§3).
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
        /// The last edit's commit position.
        ///
        /// It is the reads' highest `as_of` where the draft already held M.
        position: u64,
    },
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
    /// Where the merge landed, or `None` for the question.
    pub landed: Option<RecordLanding>,
    /// The supersession claims' addresses.
    ///
    /// They are those standing at the daughters when the record was written.
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
    /// The record this one supersedes under the key.
    ///
    /// It is its public link's address — or `None` at the first (P1).
    pub replaces: Option<Address>,
    /// The library's crate and version.
    pub by: String,
    /// The public link this record was found through.
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
        json!({
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
        })
    }

    /// Returns the record a JSON object spells.
    ///
    /// `None` for an object of another `type`, another schema version, or
    /// one missing a member this build cannot do without; a missing
    /// `landed`, `claims`, `retries`, `replaces`, `by` or `values.applied`
    /// reads as its empty value, and `rules` is not read. A member this build
    /// does not know is left unread.
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
    /// resolutions as the gaps record them — each gap settled by a person,
    /// an agent or an answer re-stated as the choice its `placed` spells, so
    /// a verifier composes the same M (§4) — save a gap of two or more groups
    /// a merger moved, which is re-stated as its order alone and composed at
    /// its default place.
    pub fn options(&self) -> Options {
        let mut resolutions = Vec::new();
        for gap in &self.gaps {
            let by = match &gap.resolved_by {
                Some(ResolvedBy::Rule) | None => continue,
                Some(by) => by.clone(),
            };
            let choice = match &gap.placed {
                Placement::Order(sides) => Choice::Order(sides.clone()),
                Placement::After => match &gap.after {
                    Some(a) => Choice::After(a.clone()),
                    None => continue,
                },
                Placement::Before => match &gap.before {
                    Some(b) => Choice::Before(b.clone()),
                    None => continue,
                },
                Placement::Omitted => Choice::Omit,
            };
            resolutions.push(Resolution { gap: gap.id, choice, by });
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
            sides
                .iter()
                .map(|s| s.as_u64().map(|n| SideIx(n as u8)))
                .collect::<Option<Vec<_>>>()?,
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
            Some((SideIx(r["side"].as_u64()? as u8), Run::new(origin, first, width)))
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

// ── how a reader finds it, and its currency ───────────────────────────────

/// Returns the current record for `key`.
///
/// It is the newest record naming the key, the trunk owner's home current
/// over another account's (§4, "Its currency"; decision 8), found as "How a
/// reader finds it" says: the links of `kind` to each side (`find_links_ftt`
/// over `ty` and `to`, never a class scan), each record's atom read through
/// its journal's arrangement — `image` then `retrieve_v`, never
/// `retrieve_i` — and its key checked. A record whose journal the reader
/// may not read is no candidate: its link's type, ends and position stay
/// visible, its body does not. `None` where no readable record names the
/// key.
///
/// Newest: within one home the link minted last, by its ordinal; across
/// homes the greater link address, the owner's home preferred before either.
///
/// # Errors
///
/// A transport halt, the death signal under the token, a board answer of a
/// shape this client does not know.
pub fn current(
    board: &Board,
    token: Option<&Token>,
    kind: &Address,
    key: &RecordKey,
) -> Result<Option<Record>, Halt> {
    let reader = Reader::new(board, token);
    let owner_home = match reader.metadata(&key.doc) {
        Ok(meta) => Some(doc_1_of(&meta.owner)),
        Err(Refusal::Halt(h)) => return Err(h),
        Err(_) => None,
    };
    current_among(&reader, kind, key, owner_home.as_deref())
}

/// Runs [`current`] over a reader, the owner's home known where it is.
///
/// # Errors
///
/// As [`current`]'s.
pub(super) fn current_among(
    reader: &Reader<'_>,
    kind: &Address,
    key: &RecordKey,
    owner_home: Option<&str>,
) -> Result<Option<Record>, Halt> {
    let mut seen: Vec<String> = Vec::new();
    let mut found: Vec<(Address, Record)> = Vec::new();
    for side in &key.sides {
        let v = reader
            .read(&frames::find_links_ftt(&kind.to_string(), &side.to_string()), None)
            .map_err(into_halt)?;
        for link in answers::addrs(&v) {
            if seen.iter().any(|s| s == link) {
                continue;
            }
            seen.push(link.to_string());
            let Some(link_addr) = parse_address(link) else { continue };
            if let Some(record) = read_record(reader, &link_addr)? {
                if record.key() == *key {
                    found.push((link_addr, record));
                }
            }
        }
    }
    let home_of = |link: &Address| document_of(&link.to_string());
    let owned: Vec<&(Address, Record)> =
        found.iter().filter(|(link, _)| home_of(link).as_deref() == owner_home).collect();
    let pool: Vec<&(Address, Record)> =
        if owned.is_empty() { found.iter().collect() } else { owned };
    Ok(pool.into_iter().max_by_key(|(link, _)| reads::comps(link)).map(|(link, record)| {
        let mut record = record.clone();
        record.link = Some(link.clone());
        record
    }))
}

/// Returns the record a link of the kind names.
///
/// It is the atom its `from` slot starts at, read through the journal's
/// arrangement; `None` where the journal or its atom is not readable to
/// this reader, where the atom is not arranged, or where its bytes are no
/// record of the kind.
///
/// # Errors
///
/// A halt reading the link, the journal or the atom: a transport fault, the
/// death signal under the token.
pub(super) fn read_record(reader: &Reader<'_>, link: &Address) -> Result<Option<Record>, Halt> {
    let lv = reader.read(&frames::read_link(&link.to_string()), None).map_err(into_halt)?;
    let Some(atom) = answers::link_from(&lv) else { return Ok(None) };
    let Some(journal) = document_of(atom).and_then(|j| parse_address(&j)) else { return Ok(None) };
    let unreadable = |e: Refusal| match e {
        Refusal::Halt(h) => Err(h),
        _ => Ok(None),
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
    Ok(Record::from_value(&body).map(|mut r| {
        r.link = Some(link.clone());
        r
    }))
}

/// Returns a read refusal as a halt, where the reads are a lookup's.
///
/// A halt surfaces; a refusal of the document read is the lookup's own
/// answer and never reaches here.
fn into_halt(e: Refusal) -> Halt {
    match e {
        Refusal::Halt(h) => h,
        other => Halt::face(
            "a record lookup met a refusal it cannot act on",
            other.to_string(),
            "this is this client's fault; nothing was written",
        ),
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
    /// A document the verdict needs is not readable to this reader.
    ///
    /// It is the landed member, or the draft, withheld or not registered:
    /// the verdict withheld, never made up.
    Unreadable(Address),
}

/// Verifies a record's testimony (§4, testimony; §7, `verify`).
///
/// M is recomputed from the record's inputs — its base, its sides, its
/// value switches and the choices its gaps record — and compared with the
/// landed member's image over its first `placed` positions, or the draft's
/// whole image at the position recorded. The daemon's `compare` is asked
/// once as the oracle of the client's join (§1.3 step 4), in parts past its
/// budgets.
///
/// # Errors
///
/// The reads' refusals ([`Refusal`]) on the base and the sides; a record
/// with no head side or with `landed` none is faced — there is nothing to
/// verify against; a client join the oracle disagrees with is this
/// library's own fault, faced; a landed member with no `placed` term is
/// faced; the landed document's reads' refusals but `withheld` and
/// `doc_not_registered`, which answer [`Verdict::Unreadable`]; an `image`
/// run that is no content I-address.
pub fn verify(board: &Board, token: Option<&Token>, record: &Record) -> Result<Verdict, Refusal> {
    let reader = Reader::new(board, token);
    let head = record.head().ok_or_else(|| {
        Halt::face(
            "the record names no head side",
            "a merge record's `sides` carries one side with the role `head`",
            "this record is not one this library wrote; nothing to verify",
        )
    })?;
    let sides: Vec<Side> = record.sides.iter().filter_map(SideAt::side).collect();
    let options = record.options();
    let readings = reads::read_shape(
        &reader,
        &record.doc,
        head.address(),
        Some(record.base.clone()),
        &sides,
        &options,
    )?;
    reads::check_join(&reader, &readings)?;
    let (target, at, placed) = match &record.landed {
        Some(RecordLanding::Member { member, .. }) => {
            let meta = match reader.metadata(member) {
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
                Err(e) => return Err(e),
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
        Err(e) => return Err(e),
    };
    let actual = reads::runs_of(&image)?;
    let expected: Vec<(Run, reads::Family)> = readings
        .composed
        .runs
        .iter()
        .map(|p| p.run.clone())
        .zip(readings.families.iter().copied())
        .collect();
    Ok(match reads::first_difference(&expected, &actual, &record.doc) {
        None => Verdict::Equal,
        Some(at) => Verdict::Differs { at },
    })
}
