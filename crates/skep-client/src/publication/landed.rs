//! THE TWIN PRE-CHECK and THE LANDED TEST (the link-sets design §5.5, §5.7).
//!
//! **The pre-check, before the act.** Each named draft's records — the
//! rendering draft `D`'s, then each draft `also` names — constrained by the
//! request's runs of THAT draft's identity: one four-set read `{home: [the
//! draft], ty: [the subtype], from: [its spans]}` per named draft, the twin
//! fence's own read — each hit read once and kept by the exact type; a
//! draft-native run a record's `from` overlaps is RE-COMPOSED by reference
//! to the record's `to` at the run's offset into the `from`, in pieces where
//! a record covers it in part, each piece with EVERY named draft's kept
//! place beside it at the piece's offset — the rendering draft's in
//! `places`, each `also` draft's in its own `also_places` list (skep #739)
//! — the stray places the commit re-windows each draft at through the
//! record, so the request never meets `already_published` for words any
//! draft of the family already published. A run of no named draft's identity passes
//! through as given: with its place where the request's counterpart arm
//! sent one beside a window part a record names — counted as the one record
//! the commit reads for that part — and with none otherwise. The read and
//! the cut are the enumeration's too: it reads THE TWINS over the
//! selection's carried pieces and composes the selection as published by
//! the same cut, so every offer is judged over the words this pre-check
//! sends (the link-sets design §5.1, the stray words).
//!
//! **The landed test, after a lost answer or `already_published`.** ONE
//! composition answering whether THIS request's effect committed and in
//! which member, from a BASE each site states: the member `already_published`
//! names (`site.addr`); the named drafts' records where the request
//! re-inserted runs — one records read over `D` naming a draft-native run
//! of its own identity, then, where the request names other drafts of the
//! family, one over each of theirs for the runs of its own identity (B3-S11
//! L176), the first record found naming the member its commit minted (the
//! publish row at the record's position); the walk from the request's own `base` for a
//! records-less shot — the trunk's next member, then the base's daughters
//! in order until the first absent, the merge landing's `standing_member`
//! generalised to the base it holds; for the bare document as the base, the
//! chain's first member — the chain may have been empty at the send, the
//! shot then minting it — then that member's daughters, among which a draft
//! begun before any version lands once a member stands, and never the
//! trunk's second member; and `edition_claims(D)` for a minting
//! records-less request, the claims kept where their home's owner is the
//! person and their stored type is the claim type exactly. A member found
//! passes where it holds THE RUNS — the test's two cases. A request that
//! names no stretch is held over the member's first `placed` positions —
//! its image read in parts, a fragmented member never taken as absence. A
//! request that names its stretches is held by the member's ARRANGEMENT:
//! the member's `shot_base` is the request's base at the request's extent,
//! and the member is that base with the request's stretches replaced —
//! read where either list's stretches lie ([`hulls`]): the member there,
//! off the stretch list its own `doc_metadata` serves, and the base between
//! the request's stretches there. That is a fact of the member and not of
//! how the change was spelled: a request cut another way finds its own
//! member, and another writer's member over the same base, holding another
//! change, is not taken for it. Then, at either case, a COPY
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

use super::enumerate::{read_record, Record};
use super::request::{AlsoPlaces, End, EntryHome, Request};
use super::send::{Ack, AckVia};
use super::{owned_by, resolve_member_spans, trunk_of, Door, Fault, Inputs, Publisher, Run};

/// The runs and places after the twin pre-check re-composed what the
/// draft's records already name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recomposed {
    /// The runs, in order — a draft-native run a record covers in part split
    /// into its pieces.
    pub runs: Vec<Run>,
    /// The rendering draft's kept places, parallel to the runs.
    pub places: Vec<Option<u64>>,
    /// Each `also` draft's own kept places, one entry per draft in the
    /// request's order, each list parallel to the runs — a piece
    /// re-composed by reference carrying the draft's place at the piece's
    /// offset, as `places` does the rendering draft's.
    pub also_places: Vec<AlsoPlaces>,
    /// The runs' places in the draft, parallel — the value reads' addresses
    /// — a window's `None`.
    pub draft_places: Vec<Option<u64>>,
    /// Per run, the records covering it where it was re-composed by
    /// reference with a place — one for a piece this pre-check re-composed,
    /// one for a window part the request's arm placed by its counterpart;
    /// zero elsewhere.
    pub stray_records: Vec<usize>,
    /// The records the pre-check read.
    pub records: Vec<Record>,
    /// The frames sent.
    pub frames: Vec<(&'static str, usize)>,
}

/// Reads each named draft's records constrained by the spans of `runs` of
/// its identity, each run with the rendering draft's kept place in
/// `places`, each `also` draft's own in `also_places` and its place in the
/// draft in `draft_places`, and re-composes what they cover by reference.
///
/// # Errors
///
/// The reads' faults.
pub fn twin_precheck(p: &Publisher<'_>, inputs: &Inputs, runs: &[Run], places: &[Option<u64>], draft_places: &[Option<u64>], also_places: &[AlsoPlaces]) -> Result<Recomposed, Fault> {
    let door = Door::new(p.board, p.token);
    twin_precheck_with(&door, p, inputs, runs, places, draft_places, also_places)
}

/// Reads the named drafts' records through `door` and re-composes.
///
/// The records are the twin fence's own read ([`twin_records`]). A run of
/// no named draft's identity is passed through as given, its record count
/// `1` where it carries a place — a window part taken by its counterpart,
/// re-composed by the request's arm by reference to the record the
/// enumeration read — and `0` otherwise; a named draft's run is cut by the
/// records ([`recompose`]), a piece re-composed by reference counting `1`
/// where a list places it. Every list is carried beside the pieces: a
/// piece re-composed by reference, or left as given, takes the rendering
/// draft's place and each `also` draft's at the piece's offset into the
/// run, so a draft that arranges the recorded words is re-windowed there
/// through the record whichever list places it.
pub(crate) fn twin_precheck_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, runs: &[Run], places: &[Option<u64>], draft_places: &[Option<u64>], also_places: &[AlsoPlaces]) -> Result<Recomposed, Fault> {
    door.step("twin_precheck");
    let records = twin_records(door, p, inputs, runs)?;
    let mut out = Recomposed {
        runs: Vec::new(),
        places: Vec::new(),
        also_places: also_places.iter().map(|a| AlsoPlaces { draft: a.draft.clone(), places: Vec::new() }).collect(),
        draft_places: Vec::new(),
        stray_records: Vec::new(),
        records: Vec::new(),
        frames: Vec::new(),
    };
    for (k, run) in runs.iter().enumerate() {
        let place = places.get(k).copied().flatten();
        let in_draft = draft_places.get(k).copied().flatten();
        // Each `also` draft's place at this run, carried at a piece's offset
        // as the rendering draft's is.
        let also_at: Vec<Option<u64>> = also_places.iter().map(|a| a.places.get(k).copied().flatten()).collect();
        let also_from = |offset: u64| -> Vec<Option<u64>> { also_at.iter().map(|p| p.map(|p| p + offset)).collect() };
        if !inputs.is_named_draft(&run.origin) {
            // A placed run of no named draft's identity is a counterpart's
            // covered piece: the one record the commit reads for it.
            out.push(run.clone(), place, in_draft, usize::from(place.is_some()), &also_at);
            continue;
        }
        let placed = place.is_some() || also_at.iter().any(Option::is_some);
        for (piece, offset, by_reference) in recompose(run, &records) {
            out.push(piece, place.map(|p| p + offset), in_draft.map(|p| p + offset), usize::from(by_reference && placed), &also_from(offset));
        }
    }
    out.records = records;
    out.frames = door.counts();
    Ok(out)
}

/// Reads THE TWINS through `door`: each named draft's records whose `from`
/// overlaps `runs` of that draft's identity — the twin fence's own read.
///
/// One four-set read per chunk of each named draft's spans — the rendering
/// draft first, then each `also` draft, in the request's order — `{home:
/// [the draft], ty: [the subtype], from: [its spans]}`, each hit read once
/// and kept by the exact type (`read_record`); a named draft with no run of
/// its identity in `runs` is not read, and a run of no named draft's
/// identity reads nothing. The twin pre-check reads them over the request's
/// runs, the enumeration over the selection's carried pieces (the link-sets
/// design §5.1, the stray words); the caller names the step.
///
/// # Errors
///
/// The reads' faults.
pub(crate) fn twin_records(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, runs: &[Run]) -> Result<Vec<Record>, Fault> {
    let subtype = frames::unit_span(T_CORRESPONDENCE).as_array().cloned().unwrap_or_default();
    let mut records: Vec<Record> = Vec::new();
    for draft in inputs.named_drafts() {
        let native: Vec<Value> = runs.iter().filter(|r| r.origin == *draft).map(|r| frames::i_span(&r.i_start_text(), r.width)).collect();
        if native.is_empty() {
            continue;
        }
        let draft = draft.to_string();
        let unit = frames::unit_span(&draft).as_array().cloned().unwrap_or_default();
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
    Ok(records)
}

/// Returns `run`, a run of a named draft's identity, cut by `records` into
/// the pieces the request sends, in order — THE TWIN PRE-CHECK's cut.
///
/// Each stretch the first record covering its first position names, up to
/// the end of that record's `from`, is re-composed BY REFERENCE onto the
/// record's `to` at its offset ([`Record::map`]); each stretch no record
/// covers, up to the next record's first position, is the run's own. Each
/// piece comes with its offset into `run`, where its places are read, and
/// whether a record re-composed it.
///
/// # Panics
///
/// Where a record's `to` is no content span — never for a record
/// [`Record::of`] reads.
pub(crate) fn recompose(run: &Run, records: &[Record]) -> Vec<(Run, u64, bool)> {
    let chain = run.chain();
    let mut out = Vec::new();
    let mut cursor = run.i_start;
    while cursor < run.reach() {
        let covering = records.iter().find(|r| r.from.overlap(&chain, cursor, cursor + 1).is_some());
        let end = match covering {
            Some(r) => r.from.reach().min(run.reach()),
            None => records.iter().filter_map(|r| (r.from.chain == chain && r.from.first > cursor).then_some(r.from.first)).min().unwrap_or(run.reach()).min(run.reach()),
        };
        let offset = cursor - run.i_start;
        out.push(match covering {
            Some(r) => {
                let to = r.map(&chain, cursor, end).expect("the record covers the piece");
                let origin = to.document().and_then(|d| parse_address(&d)).expect("a record's to is a content span");
                (Run::new(origin, to.first, end - cursor), offset, true)
            }
            None => (Run::new(run.origin.clone(), cursor, end - cursor), offset, false),
        });
        cursor = end;
    }
    out
}

impl Recomposed {
    /// Pushes one run with its places: the rendering draft's, its place in
    /// the draft, its record count and each `also` draft's, parallel to
    /// `also_places`.
    fn push(&mut self, run: Run, place: Option<u64>, in_draft: Option<u64>, stray: usize, also: &[Option<u64>]) {
        self.runs.push(run);
        self.places.push(place);
        self.draft_places.push(in_draft);
        self.stray_records.push(stray);
        for (entry, place) in self.also_places.iter_mut().zip(also) {
            entry.places.push(*place);
        }
    }
}

/// Where the landed test starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base {
    /// The member `already_published` named.
    Member(Address),
    /// The draft's records naming a draft-native run of the request.
    Records,
    /// The walk from the request's own base — the trunk's next member, then
    /// the base's daughters; for the bare document as the base, the chain's
    /// first member, then its daughters.
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
///
/// At [`Base::Records`] the named drafts are read in the request's order —
/// the rendering draft's records for a run of its identity first, then each
/// `also` draft's for a run of its own (B3-S11 L176) — and the first record
/// found names the member; a request re-inserting no run of any named draft
/// falls to the walk.
pub(crate) fn landed_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, request: &Request, base: Base) -> Result<Verdict, Fault> {
    door.step("landed");
    let draft = inputs.draft.to_string();
    match base {
        Base::Member(member) => test_member(door, inputs, request, &member, AckVia::Twin),
        Base::Records => {
            let subtype = frames::unit_span(T_CORRESPONDENCE).as_array().cloned().unwrap_or_default();
            let mut any_native = false;
            for named in inputs.named_drafts() {
                let Some(run) = request.runs.iter().find(|r| r.origin == *named) else { continue };
                any_native = true;
                let home = named.to_string();
                let unit = frames::unit_span(&home).as_array().cloned().unwrap_or_default();
                let span = [frames::i_span(&run.i_start_text(), run.width)];
                let hits = door.addrs(&home, &frames::find_links_four(Slot::Spans(&unit), Slot::Spans(&span), Slot::Any, Slot::Spans(&subtype)))?;
                let mut record = None;
                for hit in hits {
                    if let Some(r) = read_record(door, p, &hit)? {
                        record = Some(r);
                        break;
                    }
                }
                let Some(record) = record else { continue };
                let Some(at) = record.at else { return landed_with(door, p, inputs, request, Base::Walk) };
                let Some(trunk) = record.to.document() else { return Ok(Verdict::NotFound) };
                return match member_at(door, p, &trunk, at)? {
                    Some(member) => test_member(door, inputs, request, &member, AckVia::Records),
                    None => landed_with(door, p, inputs, request, Base::Walk),
                };
            }
            if !any_native {
                return landed_with(door, p, inputs, request, Base::Walk);
            }
            Ok(Verdict::NotFound)
        }
        Base::Walk => {
            let Some((base_member, _)) = &inputs.base else {
                return if inputs.mint.is_some() { landed_with(door, p, inputs, request, Base::EditionClaims) } else { walk_birth(door, inputs, request) };
            };
            let Some(trunk) = inputs.doc.as_ref() else { return Ok(Verdict::NotFound) };
            // The member the shot mints where the base is the head, and the
            // member whose daughters it lands among where it is not: for a
            // member base the trunk's next member and the base itself; for
            // the BARE DOCUMENT as the base the chain's first member both
            // ways — the chain may have been empty at the send, the shot
            // then minting `⟨trunk⟩.1`, and a draft begun before any version
            // lands among that member's daughters once a member stands.
            // Never the trunk's second member, which no bare-based shot
            // mints.
            let (next, under) = if base_member == trunk {
                let Some(first) = parse_address(&format!("{trunk}.1")) else { return Ok(Verdict::NotFound) };
                (Some(first.clone()), first)
            } else {
                (next_member(trunk, base_member), base_member.clone())
            };
            if let Some(next) = next {
                match test_member(door, inputs, request, &next, AckVia::Walk)? {
                    Verdict::NotFound => {}
                    other => return Ok(other),
                }
            }
            for k in 1u64.. {
                let daughter = parse_address(&format!("{under}.{k}")).expect("a daughter's address");
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
/// one; `None` where `base` is the memberless document itself, whose walk
/// the caller starts at the chain's first member instead.
fn next_member(trunk: &Address, base: &Address) -> Option<Address> {
    let (trunk, base) = (trunk.to_string(), base.to_string());
    let rest = base.strip_prefix(&format!("{trunk}."))?;
    let k: u64 = rest.parse().ok()?;
    parse_address(&format!("{trunk}.{}", k + 1))
}

/// Returns the member the publish row at `at` under `trunk` names first,
/// off one page of the feed.
pub(crate) fn member_at(door: &Door<'_>, p: &Publisher<'_>, trunk: &str, at: u64) -> Result<Option<Address>, Fault> {
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

/// One stretch as the landed test reads it: the first position of the base
/// it replaces, how many it replaces, and how many positions replace them.
pub(crate) type Positions = (u64, u64, u64);

/// What stands at one place of a hull, by a request's stretches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stands {
    /// Positions of the base no stretch of the request names: `width` of
    /// them from `from`.
    Base {
        /// The first position, in the base.
        from: u64,
        /// How many.
        width: u64,
    },
    /// The positions the request's stretch at `index` places.
    Stretch {
        /// The stretch's place in the request's list.
        index: usize,
    },
}

/// One stretch of base positions where a member's stretches or a request's
/// lie, and what each side holds there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hull {
    /// Where the hull lies in the member: its first position, and how many
    /// the member holds there.
    pub(crate) member: (u64, u64),
    /// What the request says the member holds there, in order.
    pub(crate) expected: Vec<Stands>,
}

/// Plans the landed test of a request that names its stretches: where to
/// read the member, and what the request says stands there.
///
/// `member` is the stretch list the member was born by and `request` the
/// request's, each ascending and apart in the coordinates of the one base
/// both name. A member and a request that replace the same base alike hold
/// the base's own positions wherever neither names a stretch, so the two
/// are compared only inside the HULLS: each the least run of base positions
/// that holds whole every stretch, of either list, it meets — two stretches
/// that touch lie in one. For each hull the answer says where its positions
/// lie in the member, by the member's own stretches, and what the request
/// places there: its stretches' runs, and the base's positions between
/// them. `None` where some hull holds one count of positions by the member's
/// list and another by the request's: the two are not one arrangement, and
/// nothing need be read to know it.
///
/// Arithmetic on the two lists, reading nothing. Lists that are not
/// ascending and apart, or whose sums pass a machine word, answer `None`.
pub(crate) fn hulls(member: &[Positions], request: &[Positions]) -> Option<Vec<Hull>> {
    let reach = |stretch: &Positions| stretch.0.checked_add(stretch.1);
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    // What the member's stretches before the hull placed and replaced.
    let (mut placed_before, mut replaced_before) = (0u64, 0u64);
    while i < member.len() || j < request.len() {
        let lo = match (member.get(i), request.get(j)) {
            (Some(m), Some(r)) => m.0.min(r.0),
            (Some(m), None) => m.0,
            (None, Some(r)) => r.0,
            (None, None) => break,
        };
        let (first_member, first_request) = (i, j);
        let mut hi = lo;
        loop {
            let mut grew = false;
            while let Some(m) = member.get(i).filter(|m| m.0 <= hi) {
                if m.0 < lo {
                    return None;
                }
                hi = hi.max(reach(m)?);
                i += 1;
                grew = true;
            }
            while let Some(r) = request.get(j).filter(|r| r.0 <= hi) {
                if r.0 < lo {
                    return None;
                }
                hi = hi.max(reach(r)?);
                j += 1;
                grew = true;
            }
            if !grew {
                break;
            }
        }
        let sums = |stretches: &[Positions]| -> Option<(u64, u64)> {
            stretches.iter().try_fold((0u64, 0u64), |(placed, replaced), s| Some((placed.checked_add(s.2)?, replaced.checked_add(s.1)?)))
        };
        let (member_placed, member_replaced) = sums(&member[first_member..i])?;
        let (request_placed, request_replaced) = sums(&request[first_request..j])?;
        let wide = hi - lo;
        let held = wide.checked_add(member_placed)?.checked_sub(member_replaced)?;
        if held != wide.checked_add(request_placed)?.checked_sub(request_replaced)? {
            return None;
        }
        let from = lo.checked_add(placed_before)?.checked_sub(replaced_before)?;
        let mut expected = Vec::new();
        let mut cursor = lo;
        for (index, stretch) in request.iter().enumerate().take(j).skip(first_request) {
            if stretch.0 < cursor {
                return None;
            }
            if stretch.0 > cursor {
                expected.push(Stands::Base { from: cursor, width: stretch.0 - cursor });
            }
            expected.push(Stands::Stretch { index });
            cursor = reach(stretch)?;
        }
        if cursor < hi {
            expected.push(Stands::Base { from: cursor, width: hi - cursor });
        }
        out.push(Hull { member: (from, held), expected });
        placed_before = placed_before.checked_add(member_placed)?;
        replaced_before = replaced_before.checked_add(member_replaced)?;
    }
    Some(out)
}

/// Returns the part of `image`, runs in V-order, over its positions
/// `[from, from + width)` counted from 0 at its first: each run clipped to
/// the range.
pub(crate) fn clipped(image: &[IRun], from: u64, width: u64) -> Vec<IRun> {
    let (mut at, reach) = (0u64, from.saturating_add(width));
    let mut out = Vec::new();
    for held in image {
        let (lo, hi) = (at.max(from), at.saturating_add(held.width).min(reach));
        if lo < hi {
            out.push(IRun { prefix: held.prefix.clone(), first: held.first + (lo - at), width: hi - lo, ordinal: held.ordinal + (lo - at) });
        }
        at = at.saturating_add(held.width);
    }
    out
}

/// Reads `member` where its stretches or the request's lie and returns its
/// runs over the positions the request's own runs take, in the request's
/// order — or `None` where the member is not the request's base with the
/// request's stretches replaced.
///
/// The landed test's second case (the module's doc). The member's
/// `shot_base` and `base_extent` are the request's; the hulls of the two
/// stretch lists are planned ([`hulls`]) — a member born of no list is the
/// one stretch over its base's positions, its `placed` leading it — and in
/// each the member's image is compared with what the request places there:
/// its runs, a named draft's matching any stretch of the trunk's identity of
/// its width, and the base's own image between them, address for address.
/// What is read is the hulls: the member's image there, and the base's
/// between the request's stretches there.
///
/// # Errors
///
/// The image reads' faults.
fn holds_change(door: &Door<'_>, inputs: &Inputs, request: &Request, member: &str, meta: &crate::board::answers::Metadata, trunk: &Address) -> Result<Option<Vec<IRun>>, Fault> {
    let Some((base, extent)) = &request.base else { return Ok(None) };
    let base = base.to_string();
    let (Some(placed), Some(member_extent)) = (meta.placed, meta.base_extent) else { return Ok(None) };
    if meta.shot_base.as_deref() != Some(base.as_str()) || member_extent != *extent {
        return Ok(None);
    }
    // The request's stretches with the positions each places, and where
    // each one's runs begin among the request's.
    let mut first_run = Vec::with_capacity(request.stretches.len());
    let mut taken = 0usize;
    let asked: Vec<Positions> = request
        .stretches
        .iter()
        .map(|stretch| {
            first_run.push(taken);
            let runs = request.runs.iter().skip(taken).take(stretch.count);
            taken = taken.saturating_add(stretch.count);
            (stretch.start, stretch.width, runs.map(|run| run.width).sum())
        })
        .collect();
    let born: Vec<Positions> = if meta.stretches.is_empty() { vec![(1, member_extent, placed)] } else { meta.stretches.clone() };
    let Some(plan) = hulls(&born, &asked) else { return Ok(None) };
    let mut over_the_change: Vec<Vec<IRun>> = vec![Vec::new(); request.stretches.len()];
    for hull in plan {
        let actual = if hull.member.1 == 0 { Vec::new() } else { door.image(member, hull.member.0, hull.member.1)? };
        let mut expected: Vec<(Run, bool)> = Vec::new();
        let mut at = 0u64;
        for stands in &hull.expected {
            match *stands {
                Stands::Base { from, width } => {
                    for held in door.image(&base, from, width)? {
                        let Some(origin) = trunk_of(&format!("{}.{}", held.prefix, held.first)).and_then(|t| parse_address(&t)) else { return Ok(None) };
                        expected.push((Run::new(origin, held.first, held.width), false));
                    }
                    at = at.saturating_add(width);
                }
                Stands::Stretch { index } => {
                    let runs = request.runs.iter().skip(first_run[index]).take(request.stretches[index].count);
                    expected.extend(runs.map(|run| (run.clone(), inputs.is_named_draft(&run.origin))));
                    over_the_change[index] = clipped(&actual, at, asked[index].2);
                    at = at.saturating_add(asked[index].2);
                }
            }
        }
        if !holds_marked(&actual, &expected, trunk) {
            return Ok(None);
        }
    }
    Ok(Some(over_the_change.into_iter().flatten().collect()))
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
    let trunk = trunk_of(&member_text).and_then(|t| parse_address(&t));
    let Some(trunk) = trunk else { return Ok(Verdict::NotFound) };
    // The member's runs over the positions the request's runs take: its
    // first `placed` for a request naming no stretch; for one that names its
    // stretches, the member read where either list's lie.
    let image = if request.stretches.is_empty() {
        let image = door.image(&member_text, 1, placed)?;
        if !holds_runs(&image, &request.runs, inputs, &trunk) {
            return Ok(Verdict::NotFound);
        }
        image
    } else {
        match holds_change(door, inputs, request, &member_text, &meta, &trunk)? {
            Some(image) => image,
            None => return Ok(Verdict::NotFound),
        }
    };
    let at = meta.at.unwrap_or(0);
    // The member's runs as the request's, with the fresh identity in place of
    // the draft's, for the member-position ends' resolution: an end counts
    // positions over the request's own runs.
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
    Ok(Verdict::Passed(Ack { member: member.clone(), at, edition, via, claim: request.claim, supersede: request.supersede.clone() }))
}

/// Returns whether `image` holds `runs` over the member's placed positions:
/// a draft-native run — of any named draft, the rendering draft's or an
/// `also` draft's — matches any stretch of the trunk's identity of its
/// width in its place, every other run by its origin and start.
pub(crate) fn holds_runs(image: &[IRun], runs: &[Run], inputs: &Inputs, trunk: &Address) -> bool {
    let marked: Vec<(Run, bool)> = runs.iter().map(|run| (run.clone(), inputs.is_named_draft(&run.origin))).collect();
    holds_marked(image, &marked, trunk)
}

/// Returns whether `image` holds `runs`, position for position: a run
/// marked re-minted matches any stretch of the trunk's identity of its
/// width in its place, every other by its origin and start.
///
/// [`holds_runs`] marks a request's runs by their origin; the landed test of
/// a request that names its stretches marks them apart from the base's own,
/// which the member holds address for address whatever their origin.
pub(crate) fn holds_marked(image: &[IRun], runs: &[(Run, bool)], trunk: &Address) -> bool {
    let trunk_chain = format!("{trunk}.0.1");
    let (mut i, mut j, mut off_i, mut off_j) = (0usize, 0usize, 0u64, 0u64);
    while i < runs.len() && j < image.len() {
        let ((e, native), a) = (&runs[i], &image[j]);
        let native = *native;
        let stretch = (e.width - off_i).min(a.width - off_j);
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
