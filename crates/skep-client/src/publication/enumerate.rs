//! THE ENUMERATION (the link-sets design §5.1): which links are offered, and
//! how they are read.
//!
//! The reads, in order, each a step the door counts: (1) `image` — ONE
//! `retrieve_doc_v_span_set` and ONE `image` of the draft whole, read in
//! parts past the run budget and never refused, inverted locally over the
//! held selection: each held run placed at the V-ordinal the draft arranges
//! it at (a run absent, split or arranged at a second place is a fault at
//! the first enumeration and a DIFFERENCE at the re-read, `request`'s), the
//! placed runs' V-spans, less (2)'s merge records, the selection's REGION —
//! and, per draft `also`
//! names, one `retrieve_doc_v_span_set` and one `image` of THAT draft whole,
//! in `also`'s order, held for the kept places the request sends in its
//! own list (`also_places`, skep #739: every named draft re-windowed in the
//! one commit), read again at the re-read and never diffed there — a run
//! an `also` draft no longer arranges whole takes no place in its list, and
//! the board's fence meets it at that draft's own next shot; (2)
//! `merge_records` — the atoms of each held run of a named draft, the
//! rendering draft's or one `also` names, read through the rendering draft
//! at the run's place, a run's bytes counted and kept nowhere: each
//! position whose atom is a MERGE RECORD ([`is_merge_record`]) is left out
//! of THE SELECTION AS PUBLISHED, the held runs cut around it
//! ([`Enumeration::selection`]), which the region, every later read and
//! every later step test and compose from — no publication places a merge
//! record's atom as a run or sends a kept place for one, so a journal's
//! records are never re-minted or re-windowed (the merge record's decision
//! 7) — and a selection of merge records alone is refused
//! [`Fault::OnlyMergeRecords`]; a window's run and the trunk's own are read
//! for none, neither being re-minted; (3) `find_links_v` — ONE
//! read over the region as one array; (4) `links` — each answered address
//! read for its HOME off the address and kept where the home's account is
//! the person's EXACTLY, never nested under theirs, and never a home in the
//! edition's own chain ("`E` no row"); each kept link read once
//! (`read_link`) and kept as a candidate only where its STORED endset
//! touches the selection through a content span — a whole-work end, a unit
//! span at a document's or an account's address, is no candidate — and
//! where its stored type is no record class, by the reader's own exact test
//! (the correspondence subtype, the held removal, a grant, a credential, a
//! claim, the succession pair, a retraction, the `replaces` link, an edition
//! claim, the journal designation, the consumption marker); (5) `records` —
//! THE READ-THROUGH's first hop: the counterpart records whose `to` lies in
//! the selection, one four-set read `{home: "any", ty: [the subtype], to:
//! [the selection's I-spans]}` in chunks of the wire list cap, each record
//! read once, kept by the exact type and where its home's account is the
//! person's (a record of a draft the person reads but does not own is
//! dropped); (6) `read_through` — the second hop, the links on every
//! record's `from` by TWO batched four-set reads over all of them, `{from:
//! […]}` and `{to: […]}`, up to the cap a read, each answered link kept where
//! its home is a PRIVATE one of the person's (the read-through is
//! private-only: a public link there is the carriage v1 does not make) and
//! mapped back to the records whose `from` it overlaps; (7) `claims` — THE
//! FILTER, run once every candidate is known: one `in_claims` and one
//! `out_claims`, both `view: "active"`, per candidate; a candidate DROPPED
//! where an active claim of the person's — homed in a home whose account is
//! theirs, off the claim's address — names, as its `new`, a successor that
//! drops it by one of two arms. A public successor, homed in a published
//! document of theirs off the caller's own list and no read, drops it where
//! its ends as stored, read off one `read_link` of the successor, COVER
//! every position of the candidate this publication publishes — the
//! candidate's ends read through the records, below (keys (i) and (iii); no
//! liveness key — sweep 5 S1) — and none of those positions lies on a named
//! draft's own words, which the shot publishes as new: a successor standing
//! before the shot covers none of them, whatever its ends name (PUB-3.9). So
//! a copy an earlier selection cut leaves its original offered, to be re-made
//! over the whole run (W4); the original of an end that lay wholly on
//! left-out words, its copy holding the draft's own addresses, is offered at
//! the publication that publishes those words (§5.2's ⟨d⟩); and a copy an
//! earlier shot made over the words it re-minted drops its original at
//! every later publication. Any other successor drops it where it is itself
//! a candidate of this enumeration, dropped or offered — a retype or an end
//! move made in the draft before the shot (B3-S12), a move into another set
//! of theirs (§2) — read off the candidates' own addresses and no read
//! (proposal 23): one since retracted is no candidate, nor is one touching
//! nothing selected, and its original is offered. And where an `out_claims`
//! row of the person's names an `old` — the candidate a successor — that
//! original's `in_claims`, the candidate dropped as REVISED where an
//! accept's claim of the person's names a public copy, wherever the
//! original's ends lie (W17). The candidates are grouped BY HOME in the
//! order their homes first answered.
//!
//! **The walk through the records.** A link on a record's `from` run "is a
//! candidate as a link on its `to` run is" (§5.1), so a candidate's ends
//! are read as the request spells them. Every end of a candidate the
//! read-through reached, and a span on a named draft's own words of any
//! candidate, is walked through the counterpart records the enumeration
//! holds: the record covering the first position not yet read maps the
//! piece, up to the end of its `from`, onto the published words of its
//! `to`, and a piece no record covers runs as stored up to the next record's
//! first position. Every other span is read as stored. Key (iii), the
//! panel's line counts and the request's `spell_end` read this one walk,
//! `RecordWalk`, so a candidate is judged on the words its entry sends.
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

/// The merge record kind's `type` member, `merge` (the merge record's §4).
///
/// It is the word a merge record's atom carries, which no publication
/// publishes ([`is_merge_record`]); the `merge` module's record kind names
/// its `type` by it.
pub const MERGE_RECORD_TYPE: &str = "merge";

/// Returns whether `atom`, one position's value, is a merge record.
///
/// It is one where the value is one JSON object whose `type` is
/// [`MERGE_RECORD_TYPE`], whatever its schema's version — the test the
/// enumeration keeps a journal's records private by (the merge record's
/// decision 7), never a list of journals.
pub fn is_merge_record(atom: &[u8]) -> bool {
    atom.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') && serde_json::from_slice::<Value>(atom).is_ok_and(|v| v["type"].as_str() == Some(MERGE_RECORD_TYPE))
}

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
    /// Reads the stored link `value` at `link` as a counterpart record of
    /// `account`'s — THE ONE READER OF THE RECORD SHAPE.
    ///
    /// It is a record where the link's home is owned by `account` exactly
    /// (the owned-home test, off the address), its stored type slot is the
    /// correspondence class exactly, and its `from` and `to` each open with
    /// a content I-span (wire.md §The publish shot and head-float, the
    /// correspondence records). `None` for a link of another home, another
    /// type or another shape, and for an address this client cannot spell.
    pub fn of(link: &str, value: &LinkValue, account: &str) -> Option<Record> {
        let home = home_of_link(link)?;
        if !owned_by(home, account) || !value.typed_exactly(T_CORRESPONDENCE) {
            return None;
        }
        let from = value.from.first().and_then(ISpan::of)?;
        let to = value.to.first().and_then(ISpan::of)?;
        Some(Record { link: parse_address(link)?, home: parse_address(home)?, from, to, at: value.at })
    }

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

/// One successor an active claim of the person's names, with its keys.
///
/// Keys (i) and (iii) judge a public successor; whether it is a candidate
/// judges any other (§5.1, proposal 23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Successor {
    /// The claim.
    pub claim: Address,
    /// Its `new`.
    pub new: Address,
    /// (i) `new`'s home is a published document of the person's, off the
    /// caller's list.
    pub published_home: bool,
    /// (iii) Whether `new` covers the candidate's words this shot publishes.
    ///
    /// Its ends, as stored, hold every position of the candidate this
    /// publication publishes — the candidate's ends read through the records
    /// as the request spells them (`RecordWalk`) — and none of those
    /// positions lies on a named draft's own words, which the shot publishes
    /// as new: a successor standing before the shot covers none of them,
    /// whatever addresses its ends name (PUB-3.9; §5.2's ⟨c⟩ and ⟨d⟩).
    pub covers: bool,
    /// Whether `new` is another candidate of this enumeration.
    ///
    /// Read off the candidates' own addresses, dropped ones among them, and
    /// no read (proposal 23).
    pub candidate: bool,
}

impl Successor {
    /// Returns whether this successor drops its original from the list.
    ///
    /// A public successor drops it where it covers, keys (i) and (iii), so a
    /// copy an earlier selection cut drops nothing (W4); any other drops it
    /// where it is a candidate — the retype, end move or move the person
    /// made in the draft before the shot (§5.1, proposal 23; B3-S12).
    pub fn drops(&self) -> bool {
        if self.published_home {
            self.covers
        } else {
            self.candidate
        }
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

    /// Returns the candidate's ends as stored, as I-spans — `from` then
    /// `to`, the unit spans at non-content addresses left out.
    ///
    /// The filter, the panel and the request read them through the records
    /// (`RecordWalk`).
    pub fn end_spans(&self) -> Vec<ISpan> {
        self.value.from.iter().chain(&self.value.to).filter_map(ISpan::of).collect()
    }
}

/// One piece of a candidate's stored span, as the publication reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndPiece {
    /// The positions: on the record's `to` where `mapped`, else as stored.
    pub(crate) span: ISpan,
    /// Whether a record mapped the piece onto the published words it became.
    pub(crate) mapped: bool,
}

/// The walk through the records: how the publication reads a candidate's
/// stored ends (§5.1).
///
/// The walk takes every end of a candidate the read-through reached,
/// whatever its chain, and a span of any candidate on a named draft's own
/// words. A taken span is read from its first position: the record covering
/// the position maps the piece up to the end of the record's `from` onto
/// its `to`, and a piece no record covers runs as stored up to the next
/// record's first position. Every other span is read as stored. The filter's
/// key (iii), the panel's line counts and the request's spelling read this
/// one walk.
pub(crate) struct RecordWalk<'r> {
    records: &'r [Record],
    named_chains: Vec<String>,
}

impl<'r> RecordWalk<'r> {
    /// Returns the walk through `records` for the drafts `inputs` names.
    pub(crate) fn new(inputs: &Inputs, records: &'r [Record]) -> RecordWalk<'r> {
        RecordWalk { records, named_chains: inputs.named_drafts().map(|d| format!("{d}.0.1")).collect() }
    }

    /// Returns whether `chain` is a named draft's content chain, whose words
    /// the shot re-mints.
    pub(crate) fn is_named_chain(&self, chain: &str) -> bool {
        self.named_chains.iter().any(|c| c == chain)
    }

    /// Returns `span`, an end of a candidate reached `via`, as the pieces the
    /// publication reads it in: the walk's, in order, or the span itself
    /// where the walk does not take it.
    pub(crate) fn pieces(&self, span: &ISpan, via: &Via) -> Vec<EndPiece> {
        if !matches!(via, Via::ReadThrough(_)) && !self.is_named_chain(&span.chain) {
            return vec![EndPiece { span: span.clone(), mapped: false }];
        }
        let mut out = Vec::new();
        let mut cursor = span.first;
        while cursor < span.reach() {
            let covering = self.records.iter().find(|r| r.from.overlap(&span.chain, cursor, cursor + 1).is_some());
            let end = match covering {
                Some(r) => r.from.reach().min(span.reach()),
                None => self.records.iter().filter_map(|r| (r.from.chain == span.chain && r.from.first > cursor).then_some(r.from.first)).min().unwrap_or(span.reach()).min(span.reach()),
            };
            out.push(match covering.and_then(|r| r.map(&span.chain, cursor, end)) {
                Some(to) => EndPiece { span: to, mapped: true },
                None => EndPiece { span: ISpan { chain: span.chain.clone(), first: cursor, width: end - cursor }, mapped: false },
            });
            cursor = end;
        }
        out
    }

    /// Returns `candidate`'s ends as the publication reads them: `from`
    /// then `to`, each content span's pieces in order.
    pub(crate) fn spans(&self, candidate: &Candidate) -> Vec<ISpan> {
        candidate.end_spans().iter().flat_map(|s| self.pieces(s, &candidate.via)).map(|p| p.span).collect()
    }
}

/// One draft `also` names, imaged whole for its own kept places.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlsoImage {
    /// The draft, as `also` names it.
    pub draft: Address,
    /// Its content extent.
    pub extent: u64,
    /// Its image, whole, in V-order.
    pub image: Vec<IRun>,
}

/// What the enumeration answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumeration {
    /// The draft's content extent.
    pub extent: u64,
    /// The draft's image, whole, in V-order.
    pub image: Vec<IRun>,
    /// Each draft `also` names, in `also`'s order, with its extent and its
    /// image — the places its own list carries are read off it.
    pub also: Vec<AlsoImage>,
    /// Where each held run stands, parallel to the selection.
    pub placed: Vec<Placement>,
    /// The positions of each held run whose atom is a merge record,
    /// parallel to the selection: I-ordinals, ascending, none for a run of
    /// no named draft.
    pub merge_atoms: Vec<Vec<u64>>,
    /// THE SELECTION AS PUBLISHED: the held runs in their order, each cut
    /// around its merge records' positions — the runs every later step tests
    /// and composes from, so no publication carries a merge record.
    pub selection: Vec<Run>,
    /// The selection's V-spans in the draft, merged where adjacent, its
    /// merge records' positions left out.
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
    /// Returns the pieces of `run`, the `i`-th held run, a publication
    /// carries, each with the V-ordinal the rendering draft arranges it at.
    ///
    /// They are the run's placement — whole at one place, in pieces, or none
    /// — cut around its merge records' positions, which no publication
    /// carries.
    pub fn pieces(&self, i: usize, run: &Run) -> Vec<(Run, u64)> {
        let atoms = self.merge_atoms.get(i).map_or(&[][..], Vec::as_slice);
        self.placed.get(i).map_or_else(Vec::new, |placement| carried(run, placement, atoms))
    }

    /// Returns the offered candidates' indices, in order.
    pub fn offered(&self) -> Vec<usize> {
        self.candidates.iter().enumerate().filter(|(_, c)| c.offered()).map(|(i, _)| i).collect()
    }

    /// Returns each `also` draft's content run count — its image's runs —
    /// in `also`'s order: the price's term for a draft its list places.
    pub fn also_run_counts(&self) -> Vec<usize> {
        self.also.iter().map(|a| a.image.len()).collect()
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
    merged(spans)
}

/// Returns `spans` sorted and merged where adjacent or overlapping.
fn merged(mut spans: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
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

/// Returns `run` cut around `atoms`, the I-ordinals of its positions whose
/// atom is a merge record, ascending: the pieces between them, in order.
fn cut(run: &Run, atoms: &[u64]) -> Vec<Run> {
    let mut out = Vec::new();
    let mut from = run.i_start;
    for &n in atoms.iter().filter(|&&n| run.i_start <= n && n < run.reach()) {
        out.extend(run.piece(from, n));
        from = n + 1;
    }
    out.extend(run.piece(from, run.reach()));
    out
}

/// Returns the pieces of `run`, placed by `placement`, a publication
/// carries, each with its V-ordinal: every piece of the placement cut
/// around `atoms`, the run's merge records' positions.
fn carried(run: &Run, placement: &Placement, atoms: &[u64]) -> Vec<(Run, u64)> {
    let placed: Vec<(Run, u64)> = match placement {
        Placement::Whole { ordinal } => vec![(run.clone(), *ordinal)],
        Placement::Split(parts) => parts.iter().map(|(o, first, width)| (Run::new(run.origin.clone(), *first, *width), *o)).collect(),
        Placement::Absent => Vec::new(),
    };
    let mut out = Vec::new();
    for (piece, ordinal) in placed {
        for p in cut(&piece, atoms) {
            let at = ordinal + (p.i_start - piece.i_start);
            out.push((p, at));
        }
    }
    out
}

/// Returns the positions of each held run whose atom is a merge record (the
/// module's doc, step 2).
///
/// They are read off the atoms of every run of a named draft, through the
/// rendering draft `d` at the places `placed` gives — none for a run of no
/// named draft, whose words are not re-minted, nor for one the draft does
/// not arrange.
fn merge_atoms_of(door: &Door<'_>, d: &str, inputs: &Inputs, placed: &[Placement]) -> Result<Vec<Vec<u64>>, Fault> {
    let mut out = Vec::with_capacity(inputs.selection.len());
    for (run, placement) in inputs.selection.iter().zip(placed) {
        let mut atoms = Vec::new();
        if inputs.is_named_draft(&run.origin) {
            for (piece, ordinal) in carried(run, placement, &[]) {
                for (at, bytes) in door.atoms(d, ordinal, piece.width)? {
                    if is_merge_record(&bytes) {
                        atoms.push(piece.i_start + (at - ordinal));
                    }
                }
            }
            atoms.sort_unstable();
        }
        out.push(atoms);
    }
    Ok(out)
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
pub(crate) fn selected_ranges(spans: &[ISpan], selection: &[Run]) -> Vec<(String, u64, u64)> {
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
/// In this order: the images' faults; [`Fault::SelectionNotArranged`] where
/// a held run is not arranged whole at one place — the first enumeration's
/// answer, the re-read's a difference; the atoms' reads' faults; then
/// [`Fault::OnlyMergeRecords`] where every position of the selection holds
/// a merge record, nothing further read; then the other reads' faults. A
/// read's faults are `withheld` and `doc_not_registered` on the draft or on
/// a draft `also` names (each is imaged for its own kept places), the death
/// signal, `scan_busy` past the reissues, a shape this client cannot read,
/// the board's other refusals and transport faults verbatim.
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
    // Each `also` draft whole, for the kept places its own list carries:
    // one extent and one image apiece, no other read.
    let mut also: Vec<AlsoImage> = Vec::with_capacity(inputs.also.len());
    for draft in &inputs.also {
        let text = draft.to_string();
        let extent = door.extent(&text)?;
        let image = door.image(&text, 1, extent)?;
        also.push(AlsoImage { draft: draft.clone(), extent, image });
    }
    let placed = place_selection(&image, &inputs.selection);
    if strict {
        if let Some(index) = placed.iter().position(|pl| !matches!(pl, Placement::Whole { .. })) {
            return Err(Fault::SelectionNotArranged { index });
        }
    }

    // The merge records, which no publication carries: the selection as
    // published, and its region, cut around them.
    door.step("merge_records");
    let merge_atoms = merge_atoms_of(door, &d, inputs, &placed)?;
    let selection: Vec<Run> = inputs.selection.iter().zip(&merge_atoms).flat_map(|(run, atoms)| cut(run, atoms)).collect();
    if selection.is_empty() && merge_atoms.iter().any(|atoms| !atoms.is_empty()) {
        return Err(Fault::OnlyMergeRecords { draft: inputs.draft.clone() });
    }
    let pieces = inputs.selection.iter().zip(&placed).zip(&merge_atoms).flat_map(|((run, placement), atoms)| carried(run, placement, atoms));
    let region = merged(pieces.map(|(piece, ordinal)| (ordinal, piece.width)).collect());
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
            Via::Region => touches(&value, &selection),
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
    let spans = selection_spans(&selection);
    let subtype = frames::unit_span(T_CORRESPONDENCE);
    let subtype_spans = subtype.as_array().cloned().unwrap_or_default();
    for chunk in spans.chunks(MAX_WIRE_LIST) {
        let hits = door.addrs(&d, &frames::find_links_four(Slot::Any, Slot::Any, Slot::Spans(chunk), Slot::Spans(&subtype_spans)))?;
        for hit in hits {
            if !record_seen.insert(hit.clone()) {
                continue;
            }
            // The home judged off the address before the read, so a record
            // of another's draft costs no `read_link`.
            if !home_of_link(&hit).is_some_and(|home| owned_by(home, p.account)) {
                continue;
            }
            let Some(value) = door.link(&hit)? else { continue };
            if let Some(record) = Record::of(&hit, &value, p.account) {
                records.push(record);
            }
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
    // Candidacy reads every candidate, dropped ones included, so an original
    // still drops where a covering copy has superseded its successor in turn.
    let held: BTreeSet<Address> = candidates.iter().map(|c| c.link.clone()).collect();
    // Key (iii) reads the candidate's ends through the records, as the
    // request spells them, and the successor's ends as stored. A selected
    // position the records leave on a named draft's own words is one of the
    // shot's new words, which no successor covers.
    let walk = RecordWalk::new(inputs, &records);
    for c in &mut candidates {
        let link = c.link.to_string();
        let on = selected_ranges(&walk.spans(c), &selection);
        let new_words = on.iter().any(|(chain, ..)| walk.is_named_chain(chain));
        let ins = answers::claims(&door.answered(&link, &frames::in_claims(&link))?);
        for row in ins.iter().filter(|r| r.active && owned_by(&r.home, p.account)) {
            let (Some(claim), Some(new)) = (parse_address(&row.claim), parse_address(&row.new)) else { continue };
            let published_home = home_of_link(&row.new).is_some_and(|h| inputs.is_published_home(h));
            let covers = match door.link(&row.new)? {
                Some(value) => !on.is_empty() && !new_words && covered(&on, &value.from.iter().chain(&value.to).filter_map(ISpan::of).collect::<Vec<_>>()),
                None => false,
            };
            let candidate = held.contains(&new);
            c.successors.push(Successor { claim, new, published_home, covers, candidate });
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
    Ok(Enumeration { extent, image, also, placed, merge_atoms, selection, region, candidates, records, homes, frames: door.counts(), as_of: door.as_of() })
}
