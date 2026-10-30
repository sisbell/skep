//! THE TWIN PRE-CHECK and THE LANDED TEST (the link-sets design §5.5, §5.7).
//!
//! **The pre-check, before the act.** `D`'s records constrained by the
//! request's draft-native spans — one four-set read `{home: [D], ty: [the
//! subtype], from: [the spans]}`, the twin fence's own read — each hit read
//! once and kept by the exact type; a draft-native run a record's `from`
//! overlaps is RE-COMPOSED by reference to the record's `to` at the run's
//! offset into the `from`, in pieces where a record covers it in part, each
//! piece with its kept place beside it as a draft-native run's — the stray
//! places the commit re-windows — so the request never meets
//! `already_published` for words this draft already published.
//!
//! **The landed test, after a lost answer or `already_published`.** ONE
//! composition answering whether THIS request's effect committed and in
//! which member, from a BASE each site states: the member `already_published`
//! names (`site.addr`); the draft's records where the request re-inserted
//! runs — one records read over `D` naming a draft-native run, a record
//! found naming the member its commit minted (the publish row at the
//! record's position); the walk from the request's own `base` for a
//! records-less shot — the trunk's next member, then the base's daughters
//! in order until the first absent, the merge landing's `standing_member`
//! generalised to the base it holds; and `edition_claims(D)` for a minting
//! records-less request, the claims kept where their home's owner is the
//! person and their stored type is the claim type exactly. A member found
//! passes where it holds THE RUNS over its first `placed` positions — its
//! image read in parts, a fragmented member never taken as absence — a COPY
//! of every `links` entry in that entry's own home at the member's commit
//! position, found by THE POSITION-FENCED READ (a home's link ordinals rise
//! with commit position; no read serves a home's frontier, so a galloping
//! probe over `read_link` finds it, then a binary search for the first
//! ordinal at or past the position and the first past it, `O(log n)` reads
//! a home, counted), each copy matched by endset and type, a member-position
//! end compared by the I-spans the member's positions hold; and every
//! `retract` mark STANDING RETRACTED (the retraction-stands read). Pass: the
//! acknowledgment, the publication complete. A member that holds the runs
//! and fails the rest is ANOTHER's commit: the twin face's data, never the
//! end. No member found: nothing committed — and at the minting form, where
//! no claim stands, the halt's data: the publication may already stand.

use std::collections::BTreeSet;

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::answers::{IRun, LinkValue};
use crate::board::frames::{self, Slot, T_CORRESPONDENCE, T_EDITION};
use crate::board::{ChangesAnswer, ChangesQuery, T_RETRACTION};

use super::enumerate::Record;
use super::request::{End, EntryHome, Request};
use super::send::{Ack, AckVia};
use super::{home_of_link, owned_by, resolve_member_spans, trunk_of, Door, Fault, ISpan, Inputs, Publisher, Run};

/// The runs and places after the twin pre-check re-composed what the
/// draft's records already name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recomposed {
    /// The runs, in order — a draft-native run a record covers in part split
    /// into its pieces.
    pub runs: Vec<Run>,
    /// The kept places, parallel to the runs.
    pub places: Vec<Option<u64>>,
    /// The runs' places in the draft, parallel — the value reads' addresses
    /// — a window's `None`.
    pub draft_places: Vec<Option<u64>>,
    /// Per run, the records covering it where it was re-composed by
    /// reference; zero elsewhere.
    pub stray_records: Vec<usize>,
    /// The records the pre-check read.
    pub records: Vec<Record>,
    /// The frames sent.
    pub frames: Vec<(&'static str, usize)>,
}

/// Reads the draft's records constrained by the draft-native spans of
/// `runs`, each with its kept place in `places` and its place in the draft
/// in `draft_places`, and re-composes what they cover by reference.
///
/// # Errors
///
/// The reads' faults.
pub fn twin_precheck(p: &Publisher<'_>, inputs: &Inputs, runs: &[Run], places: &[Option<u64>], draft_places: &[Option<u64>]) -> Result<Recomposed, Fault> {
    let door = Door::new(p.board, p.token);
    twin_precheck_with(&door, p, inputs, runs, places, draft_places)
}

/// Reads the draft's records through `door` and re-composes.
pub(crate) fn twin_precheck_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, runs: &[Run], places: &[Option<u64>], draft_places: &[Option<u64>]) -> Result<Recomposed, Fault> {
    door.step("twin_precheck");
    let draft = inputs.draft.to_string();
    let native: Vec<Value> = runs.iter().filter(|r| r.origin == inputs.draft).map(|r| frames::i_span(&r.i_start_text(), r.width)).collect();
    let mut records: Vec<Record> = Vec::new();
    if !native.is_empty() {
        let unit = frames::unit_span(&draft).as_array().cloned().unwrap_or_default();
        let subtype = frames::unit_span(T_CORRESPONDENCE).as_array().cloned().unwrap_or_default();
        for chunk in native.chunks(super::enumerate::MAX_WIRE_LIST) {
            for hit in door.addrs(&draft, &frames::find_links_four(Slot::Spans(&unit), Slot::Spans(chunk), Slot::Any, Slot::Spans(&subtype)))? {
                if records.iter().any(|r| r.link.to_string() == hit) {
                    continue;
                }
                if let Some(record) = read_record(door, p, &hit)? {
                    records.push(record);
                }
            }
        }
    }
    let mut out = Recomposed { runs: Vec::new(), places: Vec::new(), draft_places: Vec::new(), stray_records: Vec::new(), records: Vec::new(), frames: Vec::new() };
    for (k, run) in runs.iter().enumerate() {
        let place = places.get(k).copied().flatten();
        let in_draft = draft_places.get(k).copied().flatten();
        if run.origin != inputs.draft {
            out.push(run.clone(), place, in_draft, 0);
            continue;
        }
        // The pieces: each ordinal of the run either covered by one record
        // (the first covering it) or not, consecutive alike merged.
        let chain = run.chain();
        let mut cursor = run.i_start;
        while cursor < run.reach() {
            let covering = records.iter().find(|r| r.from.overlap(&chain, cursor, cursor + 1).is_some());
            let end = match covering {
                Some(r) => r.from.reach().min(run.reach()),
                None => records.iter().filter_map(|r| (r.from.chain == chain && r.from.first > cursor).then_some(r.from.first)).min().unwrap_or(run.reach()).min(run.reach()),
            };
            let width = end - cursor;
            let offset = cursor - run.i_start;
            match covering {
                Some(r) => {
                    let to = r.map(&chain, cursor, end).expect("the record covers the piece");
                    let origin = to.document().and_then(|d| parse_address(&d)).expect("a record's to is a content span");
                    out.push(Run::new(origin, to.first, width), place.map(|p| p + offset), in_draft.map(|p| p + offset), 1);
                }
                None => out.push(Run::new(run.origin.clone(), cursor, width), place.map(|p| p + offset), in_draft.map(|p| p + offset), 0),
            }
            cursor = end;
        }
    }
    out.records = records;
    out.frames = door.counts();
    Ok(out)
}

impl Recomposed {
    fn push(&mut self, run: Run, place: Option<u64>, in_draft: Option<u64>, stray: usize) {
        self.runs.push(run);
        self.places.push(place);
        self.draft_places.push(in_draft);
        self.stray_records.push(stray);
    }
}

/// Reads one record by address: `None` where it is absent, of another type,
/// another account's, or of no I-span shape.
pub(crate) fn read_record(door: &Door<'_>, p: &Publisher<'_>, hit: &str) -> Result<Option<Record>, Fault> {
    let Some(home) = home_of_link(hit) else { return Ok(None) };
    if !owned_by(home, p.account) {
        return Ok(None);
    }
    let Some(value) = door.link(hit)? else { return Ok(None) };
    if !value.typed_exactly(T_CORRESPONDENCE) {
        return Ok(None);
    }
    let (Some(from), Some(to)) = (value.from.first().and_then(ISpan::of), value.to.first().and_then(ISpan::of)) else { return Ok(None) };
    let (Some(link), Some(home)) = (parse_address(hit), parse_address(home)) else { return Ok(None) };
    Ok(Some(Record { link, home, from, to, at: value.at }))
}

/// Where the landed test starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base {
    /// The member `already_published` named.
    Member(Address),
    /// The draft's records naming a draft-native run of the request.
    Records,
    /// The walk from the request's own base — the trunk's next member, then
    /// the base's daughters.
    Walk,
    /// The edition claim read from the draft, at the mint form.
    EditionClaims,
}

/// What the test found missing in a member that holds the runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// A `links` entry's copy, by its index.
    Copy(usize),
    /// A `retract` mark not retracted, by its index.
    Retraction(usize),
}

/// The landed test's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The request's effect committed: the acknowledgment.
    Passed(Ack),
    /// A member holds the request's runs and fails the rest: another's
    /// commit — the twin face's data.
    Anothers {
        /// The member.
        member: Address,
        /// What it lacks.
        missing: Missing,
    },
    /// No member holds the request's runs: nothing committed.
    NotFound,
    /// A minting records-less request with no claim standing: the
    /// publication may already stand; never re-sent.
    MayAlreadyStand,
}

/// Runs the landed test from `base`.
///
/// # Errors
///
/// The reads' faults.
pub fn landed(p: &Publisher<'_>, inputs: &Inputs, request: &Request, base: Base) -> Result<Verdict, Fault> {
    let door = Door::new(p.board, p.token);
    landed_with(&door, p, inputs, request, base)
}

/// Runs the landed test through `door`.
pub(crate) fn landed_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, request: &Request, base: Base) -> Result<Verdict, Fault> {
    door.step("landed");
    let draft = inputs.draft.to_string();
    let native = request.runs.iter().find(|r| r.origin == inputs.draft);
    match base {
        Base::Member(member) => test_member(door, inputs, request, &member, AckVia::Twin),
        Base::Records => {
            let Some(run) = native else { return landed_with(door, p, inputs, request, Base::Walk) };
            let unit = frames::unit_span(&draft).as_array().cloned().unwrap_or_default();
            let subtype = frames::unit_span(T_CORRESPONDENCE).as_array().cloned().unwrap_or_default();
            let span = [frames::i_span(&run.i_start_text(), run.width)];
            let hits = door.addrs(&draft, &frames::find_links_four(Slot::Spans(&unit), Slot::Spans(&span), Slot::Any, Slot::Spans(&subtype)))?;
            let mut record = None;
            for hit in hits {
                if let Some(r) = read_record(door, p, &hit)? {
                    record = Some(r);
                    break;
                }
            }
            let Some(record) = record else { return Ok(Verdict::NotFound) };
            let Some(at) = record.at else { return landed_with(door, p, inputs, request, Base::Walk) };
            let Some(trunk) = record.to.document() else { return Ok(Verdict::NotFound) };
            match member_at(door, p, &trunk, at)? {
                Some(member) => test_member(door, inputs, request, &member, AckVia::Records),
                None => landed_with(door, p, inputs, request, Base::Walk),
            }
        }
        Base::Walk => {
            let Some((base_member, _)) = &inputs.base else {
                return if inputs.mint.is_some() { landed_with(door, p, inputs, request, Base::EditionClaims) } else { walk_birth(door, inputs, request) };
            };
            let Some(trunk) = inputs.doc.as_ref() else { return Ok(Verdict::NotFound) };
            let mut members: Vec<Address> = Vec::new();
            if let Some(next) = next_member(trunk, base_member) {
                members.push(next);
            }
            for member in members {
                match test_member(door, inputs, request, &member, AckVia::Walk)? {
                    Verdict::NotFound => {}
                    other => return Ok(other),
                }
            }
            for k in 1u64.. {
                let daughter = parse_address(&format!("{base_member}.{k}")).expect("a daughter's address");
                match door.metadata(&daughter.to_string()) {
                    Err(Fault::NoSuchDocument(_)) => return Ok(Verdict::NotFound),
                    Err(e) => return Err(e),
                    Ok(_) => {}
                }
                match test_member(door, inputs, request, &daughter, AckVia::Walk)? {
                    Verdict::NotFound => {}
                    other => return Ok(other),
                }
            }
            Ok(Verdict::NotFound)
        }
        Base::EditionClaims => {
            let v = door.answered(&draft, &frames::edition_claims(&draft))?;
            for row in crate::board::answers::edition_claims(&v) {
                if !owned_by(&row.home, p.account) {
                    continue;
                }
                let Some(claim) = door.link(&row.claim)? else { continue };
                if !claim.typed_exactly(T_EDITION) {
                    continue;
                }
                let Some(member) = parse_address(&format!("{}.1", row.home)) else { continue };
                match test_member(door, inputs, request, &member, AckVia::EditionClaim)? {
                    Verdict::NotFound => {}
                    other => return Ok(other),
                }
            }
            Ok(Verdict::MayAlreadyStand)
        }
    }
}

/// The birth shape's walk: the trunk's first member, then its daughters.
fn walk_birth(door: &Door<'_>, inputs: &Inputs, request: &Request) -> Result<Verdict, Fault> {
    let Some(trunk) = inputs.doc.as_ref() else { return Ok(Verdict::NotFound) };
    let Some(first) = parse_address(&format!("{trunk}.1")) else { return Ok(Verdict::NotFound) };
    match door.metadata(&first.to_string()) {
        Err(Fault::NoSuchDocument(_)) => return Ok(Verdict::NotFound),
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    test_member(door, inputs, request, &first, AckVia::Walk)
}

/// Returns the trunk member after `base`: its one version component plus
/// one; `None` where `base` is the memberless document itself.
fn next_member(trunk: &Address, base: &Address) -> Option<Address> {
    let (trunk, base) = (trunk.to_string(), base.to_string());
    let rest = base.strip_prefix(&format!("{trunk}."))?;
    let k: u64 = rest.parse().ok()?;
    parse_address(&format!("{trunk}.{}", k + 1))
}

/// Returns the member the publish row at `at` under `trunk` names first,
/// off one page of the feed.
fn member_at(door: &Door<'_>, p: &Publisher<'_>, trunk: &str, at: u64) -> Result<Option<Address>, Fault> {
    let query = ChangesQuery { since: at.saturating_sub(1), under: Some(trunk), drafts: false, limit: Some(1) };
    match p.board.changes(Some(p.token), &query)? {
        ChangesAnswer::Page(page) => Ok(page.changes.iter().find(|row| row["at"].as_u64() == Some(at) && row["op"].as_str() == Some("publish")).and_then(|row| row["docs"][0].as_str()).and_then(parse_address)),
        ChangesAnswer::Closed => Err(Fault::SessionEnded),
        _ => {
            let _ = door;
            Ok(None)
        }
    }
}

/// Tests one member: the runs, each copy, each retraction.
fn test_member(door: &Door<'_>, inputs: &Inputs, request: &Request, member: &Address, via: AckVia) -> Result<Verdict, Fault> {
    let member_text = member.to_string();
    let meta = match door.metadata(&member_text) {
        Ok(m) => m,
        Err(Fault::NoSuchDocument(_)) => return Ok(Verdict::NotFound),
        Err(e) => return Err(e),
    };
    let Some(placed) = meta.placed else { return Ok(Verdict::NotFound) };
    let image = door.image(&member_text, 1, placed)?;
    let trunk = trunk_of(&member_text).and_then(|t| parse_address(&t));
    let Some(trunk) = trunk else { return Ok(Verdict::NotFound) };
    if !holds_runs(&image, &request.runs, &inputs.draft, &trunk) {
        return Ok(Verdict::NotFound);
    }
    let at = meta.at.unwrap_or(0);
    // The member's runs as the request's, with the fresh identity in place of
    // the draft's, for the member-position ends' resolution.
    let member_runs: Vec<Run> = image.iter().filter_map(|r| Some(Run::new(parse_address(&trunk_of(&format!("{}.{}", r.prefix, r.first))?)?, r.first, r.width))).collect();
    let edition = request.mint.as_ref().map(|_| trunk.clone());
    for (index, entry) in request.entries.iter().enumerate() {
        let home = match &entry.home {
            EntryHome::Member => member.clone(),
            EntryHome::Set(s) => s.clone(),
        };
        let (deposits, _probes) = deposits_at(door, &home.to_string(), at)?;
        let want = [spell(&entry.from, member, edition.as_ref(), &member_runs), spell(&entry.to, member, edition.as_ref(), &member_runs), spell(&entry.ty, member, edition.as_ref(), &member_runs)];
        let found = deposits.iter().any(|(_, value)| [slot_of(&value.from), slot_of(&value.to), slot_of(&value.ty)] == want);
        if !found {
            return Ok(Verdict::Anothers { member: member.clone(), missing: Missing::Copy(index) });
        }
    }
    for (index, mark) in request.retract.iter().enumerate() {
        let mark = mark.to_string();
        if door.addrs(&mark, &frames::find_links_ftt(T_RETRACTION, &mark))?.is_empty() {
            return Ok(Verdict::Anothers { member: member.clone(), missing: Missing::Retraction(index) });
        }
    }
    Ok(Verdict::Passed(Ack { member: member.clone(), at, edition, via, claim: request.claim }))
}

/// Returns whether `image` holds `runs` over the member's placed positions:
/// a draft-native run matches any stretch of the trunk's identity of its
/// width in its place, every other run by its origin and start.
pub(crate) fn holds_runs(image: &[IRun], runs: &[Run], draft: &Address, trunk: &Address) -> bool {
    let trunk_chain = format!("{trunk}.0.1");
    let (mut i, mut j, mut off_i, mut off_j) = (0usize, 0usize, 0u64, 0u64);
    while i < runs.len() && j < image.len() {
        let (e, a) = (&runs[i], &image[j]);
        let stretch = (e.width - off_i).min(a.width - off_j);
        let native = e.origin == *draft;
        let same_chain = if native { a.prefix == trunk_chain } else { a.prefix == e.chain() };
        let same_start = native || e.i_start + off_i == a.first + off_j;
        if !(same_chain && same_start) {
            return false;
        }
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
    i == runs.len() && j == image.len()
}

/// Returns a slot's spans as `(start, width)` strings.
fn slot_of(spans: &[crate::board::answers::LinkSpan]) -> Vec<(String, String)> {
    spans.iter().map(|s| (s.start.clone(), s.width.clone())).collect()
}

/// Spells an entry's end as the store holds it at `member`: the address
/// form's unit spans, the tags resolved; the I-span form verbatim; the
/// member-position form resolved through the member's runs.
fn spell(end: &End, member: &Address, edition: Option<&Address>, member_runs: &[Run]) -> Vec<(String, String)> {
    let one = |v: Value| -> (String, String) { (v["start"].as_str().unwrap_or("").to_string(), v["width"].as_str().unwrap_or("").to_string()) };
    match end {
        End::Addrs(list) => list
            .iter()
            .map(|a| {
                let addr = match a.as_str() {
                    "member" => member.to_string(),
                    "edition" => edition.unwrap_or(member).to_string(),
                    other => other.to_string(),
                };
                one(frames::unit_span(&addr)[0].clone())
            })
            .collect(),
        End::Spans(list) => list.iter().map(|s| one(s.wire())).collect(),
        End::Member(spans) => resolve_member_spans(member_runs, spans).unwrap_or_default().iter().map(|s| one(s.wire())).collect(),
    }
}

/// THE POSITION-FENCED READ: the links a commit at `at` deposited in `home`
/// — the contiguous run of the home's ordinals whose `read_link` `at` is the
/// position — over `read_link` alone: the frontier by a galloping probe
/// (ordinals 1, 2, 4, 8, … until the null answer, then a binary search
/// between), then a binary search for the first ordinal at or past `at` and
/// the first past it. Answers the links with their ordinals, and how many
/// `read_link`s the probe and the searches sent.
pub(crate) fn deposits_at(door: &Door<'_>, home: &str, at: u64) -> Result<(Vec<(u64, LinkValue)>, usize), Fault> {
    let mut probes = 0usize;
    let mut at_of = |k: u64| -> Result<Option<u64>, Fault> {
        probes += 1;
        Ok(door.link(&format!("{home}.0.2.{k}"))?.map(|v| v.at.unwrap_or(0)))
    };
    let mut probe = 1u64;
    while at_of(probe)?.is_some() {
        probe = probe.saturating_mul(2);
    }
    let (mut lo, mut hi) = (probe / 2, probe);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if at_of(mid)?.is_some() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let frontier = lo;
    if frontier == 0 {
        return Ok((Vec::new(), probes));
    }
    let mut lower_bound = |strict: bool| -> Result<u64, Fault> {
        let (mut lo, mut hi) = (1u64, frontier + 1);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let a = at_of(mid)?.unwrap_or(0);
            if if strict { a > at } else { a >= at } {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        Ok(lo)
    };
    let first = lower_bound(false)?;
    let past = lower_bound(true)?;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for k in first..past {
        if !seen.insert(k) {
            continue;
        }
        if let Some(value) = door.link(&format!("{home}.0.2.{k}"))? {
            out.push((k, value));
        }
    }
    Ok((out, probes))
}
