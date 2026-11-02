//! THE ENUMERATION (the link-sets design §5.1): which links are offered, and
//! how they are read.
//!
//! The reads, in order, each a step the door counts: (1) `image` — ONE
//! `retrieve_doc_v_span_set` and ONE `image` of the draft whole, read in
//! parts past the run budget and never refused, inverted locally over the
//! held selection: each held run placed at the V-ordinal the draft arranges
//! it at (a run absent, split or arranged at a second place is a fault at
//! the first enumeration and a DIFFERENCE at the re-read, `request`'s), the
//! placed runs' V-spans the selection's REGION; (2) `find_links_v` — ONE
//! read over the region as one array; (3) `links` — each answered address
//! read for its HOME off the address and kept where the home's account is
//! the person's EXACTLY, never nested under theirs, and never a home in the
//! edition's own chain ("`E` no row"); each kept link read once
//! (`read_link`) and kept as a candidate only where its STORED endset
//! touches the selection through a content span — a whole-work end, a unit
//! span at a document's or an account's address, is no candidate — and
//! where its stored type is no record class, by the reader's own exact test
//! (the correspondence subtype, the held removal, a grant, a credential, a
//! claim, the succession pair, a retraction, the `replaces` link, an edition
//! claim, the journal designation, the consumption marker); (4) `records` —
//! THE READ-THROUGH's first hop: the counterpart records whose `to` lies in
//! the selection, one four-set read `{home: "any", ty: [the subtype], to:
//! [the selection's I-spans]}` in chunks of the wire list cap, each record
//! read once, kept by the exact type and where its home's account is the
//! person's (a record of a draft the person reads but does not own is
//! dropped); (5) `read_through` — the second hop, the links on every
//! record's `from` by TWO batched four-set reads over all of them, `{from:
//! […]}` and `{to: […]}`, up to the cap a read, each answered link kept where
//! its home is a PRIVATE one of the person's (the read-through is
//! private-only: a public link there is the carriage v1 does not make) and
//! mapped back to the records whose `from` it overlaps; (6) `claims` — THE
//! FILTER: one `in_claims` and one `out_claims`, both `view: "active"`, per
//! candidate; a candidate DROPPED where an active claim of the person's —
//! homed in a home whose account is theirs, off the claim's address — names
//! a public successor homed in a published document of theirs, off the
//! caller's own list and no read, COVERING every position of the candidate
//! this publication publishes, read off one `read_link` of the successor
//! (keys (i) and (iii); no liveness key — sweep 5 S1); and where an
//! `out_claims` row of the person's names an `old` — the candidate a
//! successor — that original's `in_claims`, the candidate dropped as REVISED
//! where an accept's claim of the person's names a public copy, wherever
//! the original's ends lie (W17). The candidates are grouped BY HOME in the
//! order their homes first answered.
//!
//! What it does not read: other people's links, left out by the owned-homes
//! rule and no refusal; links of the person's touching no span of the
//! selection; the edition's own links (its home projects to `E`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::answers::{self, IRun, LinkValue};
use crate::board::frames::{self, Slot, T_CORRESPONDENCE, T_EDITION, T_GRANT, T_HELD_REMOVAL, T_REPLACES};
use crate::board::{T_CLAIM, T_ENROLL, T_RETIRE, T_RETRACTION, T_SUPERSEDES};

use super::{home_of_link, owned_by, trunk_of, Door, Fault, ISpan, Inputs, Publisher, Run};

/// The most elements one wire array may carry — the codec's `MAX_WIRE_LIST`,
/// 4,096, which every list of a request and every four-set slot is held to
/// (wire.md §Rejection codes, `slot_too_large`; the publish shot's lists).
/// The read-through's batched reads and the request's lists are chunked and
/// priced by it; `price` pins it to the board's.
pub const MAX_WIRE_LIST: usize = 4096;

/// The journal designation, `3.22` (the registry's vocabulary): a record, never
/// a candidate.
const T_JOURNAL_DESIGNATION: &str = "1.1.0.1.0.1.0.3.22";

/// The consumption marker, `3.91` (the registry's vocabulary): a record, never
/// a candidate.
const T_CONSUMPTION_MARKER: &str = "1.1.0.1.0.1.0.3.91";

/// Where a held run stands in the draft's image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// Arranged whole at one place: its V-ordinal.
    Whole {
        /// The V-ordinal of the run's first position.
        ordinal: u64,
    },
    /// Arranged in pieces: each piece's V-ordinal, first I-ordinal and
    /// width, in the draft's order.
    Split(Vec<(u64, u64, u64)>),
    /// Not arranged.
    Absent,
}

/// One counterpart record the read-through holds: a correspondence record
/// homed in a draft of the person's, `from` the draft-native span an earlier
/// shot re-inserted and `to` the member's span it became, of one width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record link's address.
    pub link: Address,
    /// The draft it is homed in.
    pub home: Address,
    /// The draft-native span.
    pub from: ISpan,
    /// The published span it became.
    pub to: ISpan,
    /// The position of the commit that minted it — the publication's.
    pub at: Option<u64>,
}

impl Record {
    /// Maps `[first, reach)` on the record's `from` chain onto the `to` span
    /// at the same offset, where the record covers it.
    pub fn map(&self, chain: &str, first: u64, reach: u64) -> Option<ISpan> {
        let (lo, hi) = self.from.overlap(chain, first, reach)?;
        Some(ISpan { chain: self.to.chain.clone(), first: self.to.first + (lo - self.from.first), width: hi - lo })
    }
}

/// How a candidate was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// The region read over the selection.
    Region,
    /// The read-through: the records whose `from` the link's ends overlap.
    ReadThrough(Vec<Address>),
}

/// One successor an active claim of the person's names, with the two keys
/// read for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Successor {
    /// The claim.
    pub claim: Address,
    /// Its `new`.
    pub new: Address,
    /// (i) `new`'s home is a published document of the person's, off the
    /// caller's list.
    pub published_home: bool,
    /// (iii) `new`'s ends cover every position of the candidate this
    /// publication publishes.
    pub covers: bool,
}

impl Successor {
    /// Whether this successor drops its original from the list: both keys.
    pub fn drops(&self) -> bool {
        self.published_home && self.covers
    }
}

/// One candidate of the enumeration: an active link in a home the person
/// owns, touching the selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The link.
    pub link: Address,
    /// Its home — the set.
    pub home: Address,
    /// Its value as stored.
    pub value: LinkValue,
    /// How it was reached.
    pub via: Via,
    /// The successors its active claims name, each with its keys.
    pub successors: Vec<Successor>,
    /// Dropped as a successor whose original has a public copy of the
    /// person's (the `out_claims` key; the row's ⟨u⟩).
    pub revised: bool,
}

impl Candidate {
    /// Whether the candidate is offered: no successor drops it and it is no
    /// revision of a published original.
    pub fn offered(&self) -> bool {
        !self.revised && !self.successors.iter().any(Successor::drops)
    }

    /// Returns the candidate's ends as I-spans — `from` then `to`, the unit
    /// spans at non-content addresses left out.
    pub fn end_spans(&self) -> Vec<ISpan> {
        self.value.from.iter().chain(&self.value.to).filter_map(ISpan::of).collect()
    }
}

/// What the enumeration answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumeration {
    /// The draft's content extent.
    pub extent: u64,
    /// The draft's image, whole, in V-order.
    pub image: Vec<IRun>,
    /// Where each held run stands, parallel to the selection.
    pub placed: Vec<Placement>,
    /// The selection's V-spans in the draft, merged where adjacent.
    pub region: Vec<(u64, u64)>,
    /// Every candidate, dropped ones included.
    pub candidates: Vec<Candidate>,
    /// The counterpart records the read-through kept.
    pub records: Vec<Record>,
    /// The candidates by home, in the order the homes first answered: each
    /// home with the indices of its candidates into `candidates`.
    pub homes: Vec<(Address, Vec<usize>)>,
    /// The frames sent, per step.
    pub frames: Vec<(&'static str, usize)>,
    /// The highest `as_of` the reads answered.
    pub as_of: u64,
}

impl Enumeration {
    /// Returns the offered candidates' indices, in order.
    pub fn offered(&self) -> Vec<usize> {
        self.candidates.iter().enumerate().filter(|(_, c)| c.offered()).map(|(i, _)| i).collect()
    }

    /// Returns the offered links grouped by home — the oracle's grouping.
    pub fn offered_by_home(&self) -> Vec<(Address, Vec<Address>)> {
        self.homes
            .iter()
            .map(|(home, indices)| (home.clone(), indices.iter().filter(|i| self.candidates[**i].offered()).map(|i| self.candidates[*i].link.clone()).collect()))
            .filter(|(_, links): &(Address, Vec<Address>)| !links.is_empty())
            .collect()
    }
}

/// Places the held runs in the image: each whole at one V-ordinal, in
/// pieces, or absent. A run the selection holds TWICE — a request may name
/// a run twice (the design's M7 (b)) — takes the draft's occurrences in
/// V-order, the k-th held copy the k-th place.
pub fn place_selection(image: &[IRun], selection: &[Run]) -> Vec<Placement> {
    let mut out = Vec::with_capacity(selection.len());
    for (k, run) in selection.iter().enumerate() {
        let chain = run.chain();
        let mut pieces: Vec<(u64, u64, u64)> = Vec::new();
        let mut wholes: Vec<u64> = Vec::new();
        for r in image.iter().filter(|r| r.prefix == chain) {
            let (lo, hi) = (run.i_start.max(r.first), run.reach().min(r.first + r.width));
            if lo < hi {
                pieces.push((r.ordinal + (lo - r.first), lo, hi - lo));
                if lo == run.i_start && hi == run.reach() {
                    wholes.push(r.ordinal + (lo - r.first));
                }
            }
        }
        let occurrence = selection[..k].iter().filter(|s| *s == run).count();
        out.push(match wholes.get(occurrence) {
            Some(ordinal) => Placement::Whole { ordinal: *ordinal },
            None if pieces.is_empty() => Placement::Absent,
            None => Placement::Split(pieces),
        });
    }
    out
}

/// Returns the V-spans the placements cover, sorted and merged where
/// adjacent.
pub fn region_of(placed: &[Placement], selection: &[Run]) -> Vec<(u64, u64)> {
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for (p, run) in placed.iter().zip(selection) {
        match p {
            Placement::Whole { ordinal } => spans.push((*ordinal, run.width)),
            Placement::Split(pieces) => spans.extend(pieces.iter().map(|(o, _, w)| (*o, *w))),
            Placement::Absent => {}
        }
    }
    spans.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (from, width) in spans {
        match out.last_mut() {
            Some(last) if last.0 + last.1 >= from => last.1 = (from + width).max(last.0 + last.1) - last.0,
            _ => out.push((from, width)),
        }
    }
    out
}

/// Returns whether `ty` is a record class no enumeration offers: the exact
/// test over the stored type slot, the edition class with its subtypes.
pub fn is_record_class(value: &LinkValue) -> bool {
    let exact = [T_CORRESPONDENCE, T_HELD_REMOVAL, T_GRANT, T_ENROLL, T_RETIRE, T_CLAIM, T_SUPERSEDES, T_RETRACTION, T_REPLACES, T_JOURNAL_DESIGNATION, T_CONSUMPTION_MARKER];
    if exact.iter().any(|t| value.typed_exactly(t)) {
        return true;
    }
    value.ty.len() == 1 && value.ty[0].is_unit() && (value.ty[0].start == T_EDITION || value.ty[0].start.starts_with(&format!("{T_EDITION}.")))
}

/// Returns whether `value`'s stored endset touches `selection` through a
/// content span — THE STORED-ENDSET TEST.
pub fn touches(value: &LinkValue, selection: &[Run]) -> bool {
    value.from.iter().chain(&value.to).filter_map(ISpan::of).any(|s| s.touches(selection))
}

/// Returns the positions of `spans` that lie in `selection`, as
/// `(chain, lo, hi)` ranges.
fn on_selection(spans: &[ISpan], selection: &[Run]) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    for s in spans {
        for r in selection {
            if let Some((lo, hi)) = r.overlap(&s.chain, s.first, s.reach()) {
                out.push((s.chain.clone(), lo, hi));
            }
        }
    }
    out
}

/// Returns whether `cover` holds every position of `ranges`.
fn covered(ranges: &[(String, u64, u64)], cover: &[ISpan]) -> bool {
    ranges.iter().all(|(chain, lo, hi)| {
        let mut held = 0u64;
        for c in cover {
            if let Some((a, b)) = c.overlap(chain, *lo, *hi) {
                held += b - a;
            }
        }
        held >= hi - lo
    })
}

/// Returns the selection's I-spans as four-set slot elements.
fn selection_spans(selection: &[Run]) -> Vec<Value> {
    selection.iter().map(|r| frames::i_span(&r.i_start_text(), r.width)).collect()
}

/// Makes the enumeration's reads under a door of its own.
///
/// # Errors
///
/// [`Fault::SelectionNotArranged`] where a held run is not arranged whole at
/// one place — the first enumeration's answer, the re-read's a difference;
/// the reads' faults: `withheld` and `doc_not_registered` on the draft, the
/// death signal, `scan_busy` past the reissues, a shape this client cannot
/// read, the board's other refusals and transport faults verbatim.
pub fn enumerate(p: &Publisher<'_>, inputs: &Inputs) -> Result<Enumeration, Fault> {
    let door = Door::new(p.board, p.token);
    enumerate_with(&door, p, inputs, true)
}

/// Makes the enumeration's reads through `door`.
///
/// `strict` refuses a held run not arranged whole; the re-read passes
/// `false` and reads the placements as differences.
pub(crate) fn enumerate_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, strict: bool) -> Result<Enumeration, Fault> {
    let d = inputs.draft.to_string();
    door.step("image");
    let extent = door.extent(&d)?;
    let image = door.image(&d, 1, extent)?;
    let placed = place_selection(&image, &inputs.selection);
    if strict {
        if let Some(index) = placed.iter().position(|pl| !matches!(pl, Placement::Whole { .. })) {
            return Err(Fault::SelectionNotArranged { index });
        }
    }
    let region = region_of(&placed, &inputs.selection);
    let trunk = inputs.doc.as_ref().map(ToString::to_string);

    door.step("find_links_v");
    let addrs = if region.is_empty() { Vec::new() } else { door.addrs(&d, &frames::find_links_v(&d, &region))? };

    door.step("links");
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut keep = |link: &str, via: Via, door: &Door<'_>, candidates: &mut Vec<Candidate>, private_only: bool| -> Result<(), Fault> {
        let Some(home) = home_of_link(link) else { return Ok(()) };
        if !owned_by(home, p.account) {
            return Ok(());
        }
        if trunk.as_deref().is_some_and(|e| trunk_of(home).as_deref() == Some(e)) {
            return Ok(());
        }
        if let Some(&i) = seen.get(link) {
            if let (Via::ReadThrough(records), Via::ReadThrough(more)) = (&mut candidates[i].via, &via) {
                for r in more {
                    if !records.contains(r) {
                        records.push(r.clone());
                    }
                }
            }
            return Ok(());
        }
        let Some(value) = door.link(link)? else { return Ok(()) };
        if is_record_class(&value) {
            return Ok(());
        }
        if private_only && door.metadata(home)?.published {
            return Ok(());
        }
        let touching = match &via {
            Via::Region => touches(&value, &inputs.selection),
            Via::ReadThrough(_) => true,
        };
        if !touching {
            return Ok(());
        }
        let (Some(link_addr), Some(home_addr)) = (parse_address(link), parse_address(home)) else { return Ok(()) };
        seen.insert(link.to_string(), candidates.len());
        candidates.push(Candidate { link: link_addr, home: home_addr, value, via, successors: Vec::new(), revised: false });
        Ok(())
    };
    for a in &addrs {
        keep(a, Via::Region, door, &mut candidates, false)?;
    }

    door.step("records");
    let mut records: Vec<Record> = Vec::new();
    let mut record_seen: BTreeSet<String> = BTreeSet::new();
    let spans = selection_spans(&inputs.selection);
    let subtype = frames::unit_span(T_CORRESPONDENCE);
    let subtype_spans = subtype.as_array().cloned().unwrap_or_default();
    for chunk in spans.chunks(MAX_WIRE_LIST) {
        let hits = door.addrs(&d, &frames::find_links_four(Slot::Any, Slot::Any, Slot::Spans(chunk), Slot::Spans(&subtype_spans)))?;
        for hit in hits {
            if !record_seen.insert(hit.clone()) {
                continue;
            }
            let Some(home) = home_of_link(&hit) else { continue };
            if !owned_by(home, p.account) {
                continue;
            }
            let Some(value) = door.link(&hit)? else { continue };
            if !value.typed_exactly(T_CORRESPONDENCE) {
                continue;
            }
            let (Some(from), Some(to)) = (value.from.first().and_then(ISpan::of), value.to.first().and_then(ISpan::of)) else { continue };
            let (Some(link), Some(home)) = (parse_address(&hit), parse_address(home)) else { continue };
            records.push(Record { link, home, from, to, at: value.at });
        }
    }

    door.step("read_through");
    if !records.is_empty() {
        let from_spans: Vec<Value> = records.iter().map(|r| r.from.wire()).collect();
        let mut hits: Vec<String> = Vec::new();
        for chunk in from_spans.chunks(MAX_WIRE_LIST) {
            hits.extend(door.addrs(&d, &frames::find_links_four(Slot::Any, Slot::Spans(chunk), Slot::Any, Slot::Any))?);
            hits.extend(door.addrs(&d, &frames::find_links_four(Slot::Any, Slot::Any, Slot::Spans(chunk), Slot::Any))?);
        }
        let mut hit_seen: BTreeSet<String> = BTreeSet::new();
        for hit in hits {
            if !hit_seen.insert(hit.clone()) {
                continue;
            }
            let Some(home) = home_of_link(&hit) else { continue };
            if !owned_by(home, p.account) {
                continue;
            }
            let Some(value) = door.link(&hit)? else { continue };
            let ends: Vec<ISpan> = value.from.iter().chain(&value.to).filter_map(ISpan::of).collect();
            let mapped: Vec<Address> = records.iter().filter(|r| ends.iter().any(|e| e.overlap(&r.from.chain, r.from.first, r.from.reach()).is_some())).map(|r| r.link.clone()).collect();
            if mapped.is_empty() {
                continue;
            }
            keep(&hit, Via::ReadThrough(mapped), door, &mut candidates, true)?;
        }
    }

    door.step("claims");
    for c in &mut candidates {
        let link = c.link.to_string();
        let on = on_selection(&c.end_spans(), &inputs.selection);
        let ins = answers::claims(&door.answered(&link, &frames::in_claims(&link))?);
        for row in ins.iter().filter(|r| r.active && owned_by(&r.home, p.account)) {
            let (Some(claim), Some(new)) = (parse_address(&row.claim), parse_address(&row.new)) else { continue };
            let published_home = home_of_link(&row.new).is_some_and(|h| inputs.is_published_home(h));
            let covers = match door.link(&row.new)? {
                Some(value) => !on.is_empty() && covered(&on, &value.from.iter().chain(&value.to).filter_map(ISpan::of).collect::<Vec<_>>()),
                None => false,
            };
            c.successors.push(Successor { claim, new, published_home, covers });
        }
        let outs = answers::claims(&door.answered(&link, &frames::out_claims(&link))?);
        for row in outs.iter().filter(|r| r.active && owned_by(&r.home, p.account)) {
            let originals = answers::claims(&door.answered(&row.old, &frames::in_claims(&row.old))?);
            if originals.iter().any(|o| o.active && owned_by(&o.home, p.account) && home_of_link(&o.new).is_some_and(|h| inputs.is_published_home(h))) {
                c.revised = true;
            }
        }
    }

    let mut homes: Vec<(Address, Vec<usize>)> = Vec::new();
    for (i, c) in candidates.iter().enumerate() {
        match homes.iter_mut().find(|(h, _)| *h == c.home) {
            Some((_, indices)) => indices.push(i),
            None => homes.push((c.home.clone(), vec![i])),
        }
    }
    Ok(Enumeration { extent, image, placed, region, candidates, records, homes, frames: door.counts(), as_of: door.as_of() })
}
