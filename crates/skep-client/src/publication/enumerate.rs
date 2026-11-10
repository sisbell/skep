//! THE ENUMERATION (the link-sets design §5.1): which links are offered, and
//! how they are read.
//!
//! The reads, in order, each a step the door counts: (1) `image` — ONE
//! `retrieve_doc_v_span_set` and ONE `image` of the draft whole, read in
//! parts past the run budget and never refused, inverted locally over the
//! held selection: each held run placed at a V-ordinal the draft arranges
//! it at, widest run first and no two held runs at overlapping places
//! ([`place_selection`]; a run absent or split is a fault at the first
//! enumeration and, like a run standing whole at a second place since the
//! panel's reads, a DIFFERENCE at the re-read, `request`'s — **The second
//! places**, below), the placed runs' V-spans, less (2)'s merge records,
//! the selection's REGION —
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
//! of every run a publication carries ([`Enumeration::pieces`]), so at the
//! re-read a word the draft no longer arranges counts nowhere (PUB-3.108)
//! — no publication places a merge record's atom as a run or sends a kept
//! place for one, so a journal's records are never re-minted or re-windowed
//! (the merge record's decision 7) — and a selection whose arranged
//! positions are merge records alone is refused [`Fault::OnlyMergeRecords`];
//! a window's run and the trunk's own are read for none, neither being
//! re-minted; (3) `windows` — THE WINDOWS (B3-S11 P2 (i); the link-sets
//! design §5.7): each held run onto a document neither a named draft nor
//! the trunk is read for its state, one `doc_metadata` per origin, and kept
//! where unpublished and the person's own exactly — or, at a merge, where
//! another account's ([`Inputs::merge_landing`]; a run onto another's
//! document stays a window by address, unasked, at every other publication)
//! — the origin's ONE four-set over the record class homed in it, `from`
//! the run, every record kept in the origin's own account (§5.5), and none
//! read where the origin answers `withheld`; each piece of the run the
//! draft arranges is cut into PARTS at the records' edges by the shared
//! core ([`parts`]) — a stretch one record names as published, or a
//! stretch none names — each part admitting its own answers
//! ([`Part::admits`]); (4) `twins` — THE TWINS (the link-sets
//! design §5.1, the stray words; §5.5): each named draft's correspondence
//! records whose `from` the selection's carried pieces hold — words an
//! earlier shot published, shown as a draft's own again by an act the
//! editor's mapping does not reach (a second device's undo, an agent's raw
//! `reinstate`) or left so in an `also` draft a shot left as it stood —
//! read as the twin pre-check reads them, one four-set read per named
//! draft holding a carried piece, in chunks of the wire list cap, each
//! record read once; each stretch a twin names is STRAY: the request
//! re-composes it by reference onto the published words the record's `to`
//! names (`landed`'s cut), and those words join the words any answer can
//! publish; (5) `find_links_v` — ONE read over the region as one array;
//! (6) `links` — each answered address read for its HOME off the address
//! and kept where the home's account is
//! the person's EXACTLY, never nested under theirs, and never a home in
//! the edition's own chain ("`E` no row"); each kept link read once
//! (`read_link`) and kept as a candidate only where its STORED endset
//! touches THE WORDS ANY ANSWER CAN PUBLISH ([`Enumeration::publishable`])
//! through a content span — a whole-work end, a unit span at a document's
//! or an account's address, is no candidate — and where its stored type is
//! no record class, by the reader's own exact test (the correspondence
//! subtype, the held removal, a grant, a credential, a claim, the
//! succession pair, a retraction, the `replaces` link, an edition claim,
//! the journal designation, the consumption marker); (7) `counterparts` —
//! THE COUNTERPART'S IDENTITY: the links on every named part's published
//! words and on every stray stretch's by TWO batched four-set reads,
//! `{from: […]}` and `{to: […]}`, up to the cap a read, each answered link
//! kept as (6) keeps one, so an answer at a part needs no read and a link
//! the person made on published words the draft no longer shows is a
//! candidate as it was while the draft showed them; (8) `records` — THE
//! READ-THROUGH's first hop: the twins, then the counterpart records whose
//! `to` lies in the publishable words — a named part's own record among
//! them — one four-set read `{home: "any", ty: [the subtype], to: [their
//! I-spans]}` in chunks of the wire list cap, each record read once, kept
//! by the exact type and where its home's account is the person's (a
//! record of a draft the person reads but does not own is dropped); (9)
//! `read_through` — the second hop, the links on every record's `from` by
//! TWO batched four-set reads over all of them, `{from: […]}` and `{to:
//! […]}`, up to the cap a read, each answered link kept where its home is
//! a PRIVATE one of the person's (the read-through is private-only: a
//! public link there is the carriage v1 does not make) and mapped back to
//! the records whose `from` it overlaps; (10) `claims` —
//! THE FILTER's reads, run once every candidate is known: one `in_claims`
//! and one `out_claims`, both `view: "active"`, per candidate; each active
//! claim of the person's — homed in a home whose account is theirs, off
//! the claim's address — kept with its successor's `new`, whether that
//! successor is homed in a published document of theirs (off the caller's
//! own list and no read), whether it is itself a candidate (proposal 23)
//! and its stored content ends, read off one `read_link`; and where an
//! `out_claims` row of the person's names an `old` — the candidate a
//! successor — that original's `in_claims`, the candidate REVISED where an
//! accept's claim of the person's names a public copy, wherever the
//! original's ends lie (W17); (11) `base` — VERSION ⟨k⟩ (**The base**,
//! below): where the request's `base` names a version member, one
//! `doc_metadata` of it for its position and one `image` of it over its
//! positions `1 ..= base_extent`, in parts past the run budget — the read
//! the request's inert check makes, kept on the enumeration
//! ([`Enumeration::base`]) so the re-read and the build image it never
//! again. The candidates are grouped BY HOME in the order their homes
//! first answered.
//!
//! **The composition** ([`Enumeration::composed`]), from those reads and no
//! other. The answers at the windows' parts decide THE SELECTION AS
//! PUBLISHED ([`Enumeration::selection`]): the named drafts' runs and the
//! trunk's as the draft places them, cut around their merge records, a
//! named draft's stray stretch as the published words its twin names; a
//! part answered by its counterpart as the published words its record
//! names; a part kept private as its own words, behind a placeholder; a
//! part left out, answered publish-first or not yet answered, nothing — a
//! window awaiting its answer counts toward nothing. Over that selection
//! every candidate is judged again: the stored-endset test, and THE
//! FILTER's drop — a public successor, homed in a published document of
//! the person's, drops a candidate where its ends as stored COVER every
//! position of the candidate this publication publishes and version ⟨k⟩
//! did not hold — the candidate's ends read through the walk below, the
//! base's words compared in the same identity (**The base**; keys (i) and
//! (iii); no liveness key — sweep 5 S1) — and none of those positions lies
//! on a named draft's own words, which the shot publishes as new: a
//! successor standing before the shot covers none of them, whatever its
//! ends name (PUB-3.9). So a copy an earlier selection cut leaves its
//! original offered at the version that brings in words of it the copy
//! does not reach, to be re-made over the whole run (W4), and at no later
//! one while those words stay in the base (E4 2.1's save); the original of
//! an end that lay wholly on left-out words, its copy holding the draft's
//! own addresses, is offered at the publication that publishes those words
//! (§5.2's ⟨d⟩); a copy an earlier shot made over the words it re-minted
//! drops its original at every later publication — stray words among them,
//! which the walk reads as the published words they are, so where the
//! draft shows them as its own nothing is offered again and nothing refused
//! (§5.1); and a first copy laid on a placeholder's words drops its
//! original while the part is kept private there, is offered at the version
//! whose counterpart fills it and at no later one. Each candidate is
//! decided UNCHANGED since version ⟨k⟩ or not ([`Candidate::unchanged`]),
//! the fold's test the panel's rows count. Any other successor drops it
//! where it is itself a candidate,
//! dropped or offered — a retype or an end move made in the draft before
//! the shot (B3-S12), a move into another set of theirs (§2) — one since
//! retracted being no candidate, nor one touching nothing selected, and
//! its original offered. A FORMATTING MARK
//! — the formatting line's shape test, its inline-mark exception kept
//! ([`is_formatting`]) — is judged on THE WORDS A READER RECEIVES
//! ([`Enumeration::received`]), the selection less every placeholder: no
//! mark goes onto a placeholder, one lying partly there is cut at its edge
//! and one lying wholly there is not offered, kept in the draft's own set
//! until a version shows its words. An original the board refused by its
//! lineage at an earlier send of the publication is left out of the offer
//! ([`Enumeration::left_out`]). [`enumerate`] answers the composition under
//! no answer, and every later step composes from the composition it is
//! handed.
//!
//! **The walk through the records.** A link on a record's `from` run "is a
//! candidate as a link on its `to` run is" (§5.1), so a candidate's ends
//! are read as the request spells them. Every end of a candidate the
//! read-through reached, and a span on a named draft's own words of any
//! candidate, is walked through the counterpart records the enumeration
//! holds, the twins among them: the record covering the first position not
//! yet read maps the piece, up to the end of its `from`, onto the published
//! words of its `to`, and a piece no record covers runs as stored up to the
//! next record's first position. Every position of a window part answered
//! by its counterpart is mapped through that part's own record, whoever's
//! link the end is. Every other span is read as stored. Key (iii), the panel's
//! line counts and the request's `spell_end` read this one walk,
//! `RecordWalk`, so a candidate is judged on the words its entry sends.
//!
//! **The second places** (PUB-3.108; the link-sets design §5.7, sweep 6
//! W10). The selection holds no place, and a held run takes one at the
//! first enumeration: a place the draft arranged it at when the panel was
//! read, and the person did not pick, stays out of the version. A second
//! place since — the run standing whole at more places than the panel's
//! image shows — is a difference at the re-read, and the re-statement
//! showing it is what lets it join the request: the run's last held copy
//! then takes every whole place no held run's place overlaps
//! ([`Placement::Places`], `place_again`), a count because any edit
//! shifts every ordinal and identity says what, never where. A run already
//! carried so is placed the same way at each later re-read, so a place
//! gone or moved is re-stated too. A part of the run copied elsewhere is
//! none of its places. A held panel's re-open re-reads without a
//! re-statement ([`enumerate_again`]), so no new place joins there, and a
//! run the panel carries at several takes no more than it had.
//!
//! **The base.** VERSION ⟨k⟩ is the member the request's `base` names, the
//! draft's recorded base (A-350), and THE WORDS IT HOLDS are what it
//! arranges itself — every run its image answers over its positions
//! `1 ..= base_extent`, its own words and its windows onto other documents
//! alike ([`BaseImage`]) — compared in the identity this publication
//! publishes them in: a candidate's positions are the walk's, so a span on
//! the draft's earlier words is compared as the published words its record
//! names, a part taken by its counterpart as the counterpart's, a part kept
//! private as its origin's own words and a part left out not at all (the
//! counterpart-first decision §1). A run this shot places by reference is
//! held only where the base arranged it: a window's words are held from the
//! version after the one that first windows them, and a placeholder's
//! passage while the hole stands but not at the version that fills it.
//! KEY (III) leaves the positions the base holds out of those a public
//! successor must cover (E4 2.1, the save: an original is offered at a
//! version that brings in words of it its copy does not reach, and at none
//! while those words stay in the versions), and THE FOLD (E4 1.1) decides a
//! candidate UNCHANGED since version ⟨k⟩ where (i) its own commit position,
//! `read_link`'s `at`, is lower than the base's, `doc_metadata`'s `at`, both
//! read, and (ii) every position by which it touches the selection as
//! composed lies on words the base holds and none on a named draft's own
//! words. A base that is no version member — the bare document, and no base
//! at all at the birth shape and the mint form — folds nothing and keys no
//! save: key (iii) asks a successor to cover every published position.
//!
//! What it does not read: other people's links, left out by the owned-homes
//! rule and no refusal; links of the person's touching no word any answer
//! can publish; the edition's own links (its home projects to `E`), which
//! are no row's — the panel reads those on the words the shot re-inserts
//! and counts them (`Panel::edition_links`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use skep_address::Address;

use crate::address::{account_of, parse_address};
use crate::board::answers::{self, IRun, LinkValue};
use crate::board::frames::{self, Slot, REGISTRY_DOCUMENT, T_CORRESPONDENCE, T_EDITION, T_GRANT, T_HELD_REMOVAL, T_REPLACES};
use crate::board::{T_CLAIM, T_ENROLL, T_RETIRE, T_RETRACTION, T_SUPERSEDES};

use super::landed::{recompose, twin_records};
use super::parts::{self, compose_part, origin_state, parts_of, window_records, Answer, OriginState, Part, PartComposition, PartKey, Window};
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

/// The formatting types' subtrees (the link-sets design §5.2; the registry's
/// vocabulary): heading `3.20`, the paragraph family `3.21`, the inline
/// family `3.23`.
pub const FORMATTING_TYPES: [&str; 3] = ["1.1.0.1.0.1.0.3.20", "1.1.0.1.0.1.0.3.21", "1.1.0.1.0.1.0.3.23"];

/// The one member of the inline family the line does NOT take: `3.23.4`
/// mark, a highlight, offered in its set's own row (proposal 15).
pub const INLINE_MARK: &str = "1.1.0.1.0.1.0.3.23.4";

/// Returns whether `atom`, one position's value, is a merge record.
///
/// It is one where the value is one JSON object whose `type` is
/// [`MERGE_RECORD_TYPE`], whatever its schema's version — the test the
/// enumeration keeps a journal's records private by (the merge record's
/// decision 7), never a list of journals.
pub fn is_merge_record(atom: &[u8]) -> bool {
    atom.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') && serde_json::from_slice::<Value>(atom).is_ok_and(|v| v["type"].as_str() == Some(MERGE_RECORD_TYPE))
}

/// Returns whether `value` is a mark the formatting line takes: the line's
/// shape test, its inline-mark exception kept (the link-sets design §5.2).
pub fn is_formatting(value: &LinkValue) -> bool {
    formatting_shape(value, false)
}

/// Returns whether `value` is a mark of THE FORMATTING TYPES: the line's
/// shape test without its inline-mark exception (P11) — the test the rider
/// applies to a held removal's mark, an inline mark's original ending with
/// its copy as a bold's does (the link-sets design §2, E3).
pub fn is_formatting_type(value: &LinkValue) -> bool {
    formatting_shape(value, true)
}

/// The formatting line's shape test: one content end, and one unit type
/// span under the formatting types — the inline mark among them where
/// `inline_marks` — beside nothing but registry addresses.
fn formatting_shape(value: &LinkValue, inline_marks: bool) -> bool {
    if value.from.is_empty() == value.to.is_empty() {
        return false;
    }
    let mut named = 0usize;
    for span in &value.ty {
        let under = |root: &str| span.start == root || span.start.starts_with(&format!("{root}."));
        if span.is_unit() && FORMATTING_TYPES.iter().any(|t| under(t)) && (inline_marks || !under(INLINE_MARK)) {
            named += 1;
        } else if !under(REGISTRY_DOCUMENT) {
            return false;
        }
    }
    named == 1
}

/// Where a held run stands in the draft's image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// Arranged whole at one place: its V-ordinal, which overlaps no other
    /// held run's place unless every place the run stands whole at does
    /// (`place_selection`).
    Whole {
        /// The V-ordinal of the run's first position.
        ordinal: u64,
    },
    /// Carried whole at more than one place: each V-ordinal, ascending, none
    /// overlapping another held run's place.
    ///
    /// The re-read's answer alone, for a run standing at more places than
    /// the panel's reads found (the module's doc, **The second places**),
    /// and the request carries the run once per place.
    Places(Vec<u64>),
    /// Arranged in pieces: each piece's V-ordinal, first I-ordinal and
    /// width, in the draft's order.
    Split(Vec<(u64, u64, u64)>),
    /// Not arranged.
    Absent,
}

impl Placement {
    /// Returns the V-ordinal of the occurrence of the run holding position
    /// `at`: the placement's own ordinal at or before it.
    ///
    /// The request and the selection as published are ordered by occurrence,
    /// so a run cut into pieces or parts keeps them together and a run
    /// nested in another's place comes after it, while a run the draft moved
    /// or arranged at a second place stands where the draft now shows it.
    pub(crate) fn occurrence_at(&self, at: u64) -> u64 {
        match self {
            Placement::Whole { ordinal } => *ordinal,
            Placement::Places(ordinals) => ordinals.iter().rev().find(|o| **o <= at).copied().unwrap_or(at),
            Placement::Split(pieces) => pieces.iter().rev().map(|(o, ..)| *o).find(|o| *o <= at).unwrap_or(at),
            Placement::Absent => at,
        }
    }
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

    /// Maps `[first, reach)` on the record's `to` chain back onto the `from`
    /// span at the same offset, where the record covers it — [`Record::map`]
    /// inverted: the draft words a published span stands for.
    pub fn unmap(&self, chain: &str, first: u64, reach: u64) -> Option<ISpan> {
        let (lo, hi) = self.to.overlap(chain, first, reach)?;
        Some(ISpan { chain: self.from.chain.clone(), first: self.from.first + (lo - self.to.first), width: hi - lo })
    }
}

/// Reads one record by address: `None` where it is absent, of another type,
/// another account's, or of no I-span shape (`Record::of`); the home is
/// judged off the address first, so another's record costs no read.
pub(crate) fn read_record(door: &Door<'_>, p: &Publisher<'_>, hit: &str) -> Result<Option<Record>, Fault> {
    read_record_as(door, p.account, hit)
}

/// Reads one record by address, held to `account` as [`read_record`] holds
/// one to the person's: the record of a window onto another account's origin
/// is read in that account's own name (the [`parts`] module's doc).
pub(crate) fn read_record_as(door: &Door<'_>, account: &str, hit: &str) -> Result<Option<Record>, Fault> {
    if !home_of_link(hit).is_some_and(|home| owned_by(home, account)) {
        return Ok(None);
    }
    let Some(value) = door.link(hit)? else { return Ok(None) };
    Ok(Record::of(hit, &value, account))
}

/// How a candidate was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// A read over the words a publication can carry: the region read over
    /// the draft's arrangement, or the counterpart read over a named part's
    /// published words.
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
    /// `new`'s content ends as stored, read once: what key (iii) holds the
    /// candidate's published positions to at every composition. Empty where
    /// `new` is absent.
    pub ends: Vec<ISpan>,
    /// (iii) Whether `new` covers the candidate's words this shot publishes
    /// and version ⟨k⟩ did not hold.
    ///
    /// Its ends, as stored, hold every position of the candidate this
    /// publication publishes that the base's image does not — the
    /// candidate's ends read through the records as the request spells them
    /// (`RecordWalk`), the base held in the same identity (the module's
    /// doc, **The base**) — and none of those positions lies on a named
    /// draft's own words, which the shot publishes as new: a successor
    /// standing before the shot covers none of them, whatever addresses its
    /// ends name (PUB-3.9; §5.2's ⟨c⟩ and ⟨d⟩). Every published position held
    /// by the base, none is left to cover and it covers (E4 2.1). Decided by
    /// the composition ([`Enumeration::composed`]).
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
    /// copy an earlier selection cut drops nothing at the version that
    /// brings in the words it does not reach (W4) and drops it at every
    /// version whose base holds them (E4 2.1); any other drops it where it
    /// is a candidate — the retype, end move or move the person made in the
    /// draft before the shot (§5.1, proposal 23; B3-S12).
    pub fn drops(&self) -> bool {
        if self.published_home {
            self.covers
        } else {
            self.candidate
        }
    }
}

/// One candidate of the enumeration: an active link in a home the person
/// owns, touching words some answer can publish.
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
    /// Whether the candidate touches the selection as the answers compose
    /// it — its stored endset, or its ends read through the walk — a
    /// formatting mark the words a reader receives.
    pub touching: bool,
    /// Left out of the offer: the board refused it by its lineage at an
    /// earlier send of this publication.
    pub left_out: bool,
    /// Whether the candidate is UNCHANGED since version ⟨k⟩, by the fold's
    /// test (E4 1.1; the module's doc, **The base**): its commit position
    /// lower than the base's, and every position by which it touches the
    /// selection as composed held by the base, none on a named draft's own
    /// words. Never where no version member is the base. Decided by the
    /// composition ([`Enumeration::composed`]).
    pub unchanged: bool,
}

impl Candidate {
    /// Whether the candidate is offered: it touches the selection as
    /// composed, no successor drops it, it is no revision of a published
    /// original and it was not left out.
    pub fn offered(&self) -> bool {
        self.touching && !self.revised && !self.left_out && !self.successors.iter().any(Successor::drops)
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
/// record's first position. Every span of any candidate is mapped through
/// the record of a window part answered by its counterpart, over that
/// part's words. Every other span is read as stored. The filter's key
/// (iii), the panel's line counts and the request's spelling read this one
/// walk.
pub(crate) struct RecordWalk<'r> {
    records: &'r [Record],
    named_chains: Vec<String>,
    /// The parts answered by their counterpart: each part's words and the
    /// record that maps them.
    counterparts: Vec<(ISpan, Record)>,
}

impl<'r> RecordWalk<'r> {
    /// Returns the walk through `records` for the drafts `inputs` names,
    /// mapping no window part.
    pub(crate) fn new(inputs: &Inputs, records: &'r [Record]) -> RecordWalk<'r> {
        RecordWalk { records, named_chains: inputs.named_drafts().map(|d| format!("{d}.0.1")).collect(), counterparts: Vec::new() }
    }

    /// Returns the walk through `records` with the parts `e`'s answers take
    /// by their counterpart mapped through their own records.
    pub(crate) fn composed(inputs: &Inputs, records: &'r [Record], e: &Enumeration) -> RecordWalk<'r> {
        RecordWalk { counterparts: e.counterpart_parts(), ..RecordWalk::new(inputs, records) }
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
        let walked = matches!(via, Via::ReadThrough(_)) || self.is_named_chain(&span.chain);
        // The stretches that map, each with its record: a counterpart part's
        // words first, then — where the walk takes the span — every record's
        // `from`.
        let maps: Vec<(&ISpan, &Record)> = self
            .counterparts
            .iter()
            .map(|(words, record)| (words, record))
            .chain(self.records.iter().filter(|_| walked).map(|r| (&r.from, r)))
            .filter(|(range, _)| range.chain == span.chain)
            .collect();
        if maps.is_empty() {
            return vec![EndPiece { span: span.clone(), mapped: false }];
        }
        let mut out = Vec::new();
        let mut cursor = span.first;
        while cursor < span.reach() {
            let covering = maps.iter().find(|(range, _)| range.first <= cursor && cursor < range.reach());
            let end = match covering {
                Some((range, _)) => range.reach().min(span.reach()),
                None => maps.iter().filter(|(range, _)| range.first > cursor).map(|(range, _)| range.first).min().unwrap_or(span.reach()).min(span.reach()),
            };
            out.push(match covering.and_then(|(_, r)| r.map(&span.chain, cursor, end)) {
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

/// VERSION ⟨k⟩ imaged: the member the request's `base` names, read once
/// per open (the module's doc, **The base**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseImage {
    /// The member, as the request's `base` names it.
    pub member: Address,
    /// The positions imaged, `1 ..= extent`: the request's `base_extent`.
    pub extent: u64,
    /// The position of the commit that minted the member — its shot's, off
    /// `doc_metadata`; `None` where the board serves none.
    pub at: Option<u64>,
    /// Its image over positions `1 ..= extent`, in V-order: its own words
    /// and its windows onto other documents alike.
    pub image: Vec<IRun>,
}

impl BaseImage {
    /// Returns whether this is the image of `base`, a request's `base` and
    /// `base_extent`.
    pub(crate) fn is_of(&self, base: &(Address, u64)) -> bool {
        self.member == base.0 && self.extent == base.1
    }

    /// Returns the words the base holds: each run of its image, as an
    /// I-span.
    fn held(&self) -> Vec<ISpan> {
        self.image.iter().map(|r| ISpan { chain: r.prefix.clone(), first: r.first, width: r.width }).collect()
    }

    /// Returns whether a link minted at `at` came before the base — the
    /// fold's test (i) (E4 1.1): its commit position lower than the base's,
    /// never where either was served `null`.
    fn precedes(&self, at: Option<u64>) -> bool {
        matches!((at, self.at), (Some(link), Some(base)) if link < base)
    }
}

/// Returns whether `member`, a request's `base`, is a version member — the
/// base that keys the fold and the save — and not the bare document, which
/// keys neither (E4 1.1).
fn is_version_member(member: &Address) -> bool {
    let text = member.to_string();
    trunk_of(&text).is_some_and(|trunk| trunk != text)
}

/// What the enumeration answers: its reads, and the composition the answers
/// make of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumeration {
    /// The draft's content extent.
    pub extent: u64,
    /// The draft's image, whole, in V-order.
    pub image: Vec<IRun>,
    /// Each draft `also` names, in `also`'s order, with its extent and its
    /// image — the places its own list carries are read off it.
    pub also: Vec<AlsoImage>,
    /// VERSION ⟨k⟩, where the request's `base` names a version member: the
    /// words it holds and its position, read once per open and handed to the
    /// re-read; `None` at the bare document, the birth shape and the mint
    /// form, where nothing folds and no save is keyed.
    pub base: Option<BaseImage>,
    /// Where each held run stands, parallel to the selection.
    pub placed: Vec<Placement>,
    /// The positions of each held run whose atom is a merge record,
    /// parallel to the selection: I-ordinals, ascending, none for a run of
    /// no named draft.
    pub merge_atoms: Vec<Vec<u64>>,
    /// The windows, in the selection's order, each in its parts: the
    /// person's own unpublished origins and, at a merge, another account's
    /// (`Inputs::merge_landing`); the drafts `also` names excluded.
    pub windows: Vec<Window>,
    /// THE TWINS: each named draft's correspondence records whose `from`
    /// the selection's carried pieces hold, in the order the twin
    /// pre-check reads them — the records that re-compose a stray stretch
    /// by reference onto the published words their `to` names (the
    /// link-sets design §5.1, §5.5).
    pub twins: Vec<Record>,
    /// The answers the composition stands under, by part — an answer a part
    /// does not admit counting as none.
    pub answers: BTreeMap<PartKey, Answer>,
    /// The originals the composition leaves out of the offer: each one the
    /// board refused by its lineage at an earlier send.
    pub left_out: BTreeSet<Address>,
    /// The selection as published: the runs a publication carries under
    /// the answers, in the draft's order.
    ///
    /// They are the named drafts' and the trunk's pieces as the draft places
    /// them, each cut around its run's merge records' positions, a named
    /// draft's stretch a twin names as the published words the twin pre-check
    /// re-composes it onto, and each window part as its answer composes it —
    /// its counterpart, or its own words behind a placeholder; a part left
    /// out or not yet answered holds nothing — the runs every later step
    /// tests and composes from, so no publication carries a merge record, no
    /// offer is judged on words the request sends by reference as their own,
    /// and at the re-read a word the draft no longer arranges counts nowhere
    /// (PUB-3.108).
    pub selection: Vec<Run>,
    /// THE WORDS A READER RECEIVES: the selection less every part kept behind
    /// a placeholder — what a formatting mark is judged on.
    pub received: Vec<Run>,
    /// The selection's V-spans in the draft, merged where adjacent, its
    /// merge records' positions left out — every window's whole among them,
    /// as the region read reads it.
    pub region: Vec<(u64, u64)>,
    /// Every candidate, dropped ones included.
    pub candidates: Vec<Candidate>,
    /// The counterpart records the walk maps through and the read-through
    /// read: the twins, then each record whose `to` lies in the words any
    /// answer can publish.
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
    /// They are the run's placement — whole at one place or at several, in
    /// pieces, or none — cut around its merge records' positions, which no
    /// publication carries.
    pub fn pieces(&self, i: usize, run: &Run) -> Vec<(Run, u64)> {
        let atoms = self.merge_atoms.get(i).map_or(&[][..], Vec::as_slice);
        self.placed.get(i).map_or_else(Vec::new, |placement| carried(run, placement, atoms))
    }

    /// Returns THE WORDS ANY ANSWER CAN PUBLISH: every held run's carried
    /// pieces — each window's whole among them — then the published words
    /// every twin names for them, then every named part's counterpart.
    ///
    /// It is the union the enumeration's reads are made over, so every
    /// composition is decided from them.
    pub fn publishable(&self, inputs: &Inputs) -> Vec<Run> {
        let pieces: Vec<Run> = inputs.selection.iter().enumerate().flat_map(|(i, run)| self.pieces(i, run)).map(|(piece, _)| piece).collect();
        let stray = stray_words(inputs, &pieces, &self.twins);
        publishable_of(pieces, &stray, &self.windows)
    }

    /// Returns the runs this publication re-inserts as fresh identity.
    ///
    /// Each comes with the V-ordinal the rendering draft arranges it at. They
    /// are every named draft's carried pieces, each cut by the twins as the
    /// twin pre-check cuts it (`landed`'s `recompose`), less the stretches a
    /// twin names, which go by reference onto the published words (§5.1, the
    /// stray words). They depend on no answer: an answer composes a window's
    /// words, and a run of a named draft is never a window.
    pub(crate) fn reinserted(&self, inputs: &Inputs) -> Vec<(Run, u64)> {
        inputs
            .selection
            .iter()
            .enumerate()
            .filter(|(_, run)| inputs.is_named_draft(&run.origin))
            .flat_map(|(i, run)| self.pieces(i, run))
            .flat_map(|(piece, ordinal)| recompose(&piece, &self.twins).into_iter().filter(|(.., by_reference)| !by_reference).map(move |(stretch, offset, _)| (stretch, ordinal + offset)))
            .collect()
    }

    /// Returns the answer `window`'s `k`-th part stands under: the one given,
    /// where the part admits it.
    pub fn answer_at(&self, window: &Window, k: usize) -> Option<Answer> {
        parts::answer_at(window, k, &self.answers)
    }

    /// Returns the parts answered by their counterpart: each part's words
    /// and its record, the walk's mappings.
    pub(crate) fn counterpart_parts(&self) -> Vec<(ISpan, Record)> {
        self.answered_parts().filter(|(_, answer)| *answer == Some(Answer::Counterpart)).filter_map(|(part, _)| Some((part.span.clone(), part.record.clone()?))).collect()
    }

    /// Returns the words kept behind a placeholder: every part answered
    /// keep-private.
    pub(crate) fn placeholder_words(&self) -> Vec<ISpan> {
        self.answered_parts().filter(|(_, answer)| *answer == Some(Answer::KeepPrivate)).map(|(part, _)| part.span.clone()).collect()
    }

    /// Returns the words no answer publishes: every part left out, answered
    /// publish-first or awaiting its answer.
    pub(crate) fn held_back_words(&self) -> Vec<ISpan> {
        self.answered_parts().filter(|(_, answer)| !matches!(answer, Some(Answer::Counterpart | Answer::KeepPrivate))).map(|(part, _)| part.span.clone()).collect()
    }

    /// Returns every window part with the answer it stands under.
    fn answered_parts(&self) -> impl Iterator<Item = (&Part, Option<Answer>)> + '_ {
        self.windows.iter().flat_map(move |w| w.parts.iter().enumerate().map(move |(k, part)| (part, self.answer_at(w, k))))
    }

    /// Returns the runs `c` is judged against: the words a reader receives
    /// for a formatting mark, the selection as published otherwise.
    pub(crate) fn judged(&self, c: &Candidate) -> &[Run] {
        if is_formatting(&c.value) {
            &self.received
        } else {
            &self.selection
        }
    }

    /// Returns the enumeration as `answers` compose it, `left_out` left out
    /// of the offer — THE COMPOSITION (the module's doc), from the reads
    /// alone: nothing is read.
    ///
    /// The selection as published and the words a reader receives are
    /// composed from the held runs and the answers; each candidate's
    /// stored-endset test, its successors' key (iii) and the fold's test are
    /// decided over them through the walk, against the words the base holds
    /// ([`Enumeration::base`]), a formatting mark on the words a reader
    /// receives; a candidate `left_out` names is offered nowhere. Any
    /// composition this enumeration made before is replaced whole.
    pub fn composed(&self, inputs: &Inputs, answers: &BTreeMap<PartKey, Answer>, left_out: &BTreeSet<Address>) -> Enumeration {
        let mut e = self.clone();
        e.answers = answers.clone();
        e.left_out = left_out.clone();
        let (selection, received) = e.composed_runs(inputs);
        e.selection = selection.clone();
        e.received = received.clone();
        let records = e.records.clone();
        let walk = RecordWalk::composed(inputs, &records, &e);
        let base = e.base.clone();
        let held = base.as_ref().map(BaseImage::held).unwrap_or_default();
        for c in &mut e.candidates {
            let against: &[Run] = if is_formatting(&c.value) { &received } else { &selection };
            let on = selected_ranges(&walk.spans(c), against);
            // Key (iii) reads the candidate's ends through the walk, as the
            // request spells them, and the successor's ends as stored. A
            // published position the walk leaves on a named draft's own
            // words is one of the shot's new words, which no successor
            // covers; one a twin names the walk maps onto the published
            // words it is. The positions the base holds, in that identity,
            // are no successor's to cover (E4 2.1).
            let new_words = on.iter().any(|(chain, ..)| walk.is_named_chain(chain));
            let unheld = unheld_ranges(&on, &held);
            for s in &mut c.successors {
                s.covers = !on.is_empty() && !new_words && covered(&unheld, &s.ends);
            }
            c.touching = touches(&c.value, against) || !on.is_empty();
            c.left_out = left_out.contains(&c.link);
            // The fold's two tests (E4 1.1): made before the base, and every
            // position it touches the selection at held by the base.
            c.unchanged = base.as_ref().is_some_and(|b| b.precedes(c.value.at)) && !on.is_empty() && !new_words && unheld.is_empty();
        }
        e
    }

    /// Returns the selection as published and the words a reader receives,
    /// as the answers compose the held runs, in the draft's order, occurrence
    /// by occurrence: a run the draft moved since the panel's reads, or
    /// carries at a second place, stands where the draft now shows it, as
    /// the request sends it.
    ///
    /// A named draft's carried piece is cut by the twins as the twin
    /// pre-check cuts it (`landed`'s `recompose`), each stretch a twin names
    /// the published words the request sends in its place.
    fn composed_runs(&self, inputs: &Inputs) -> (Vec<Run>, Vec<Run>) {
        let mut placed: Vec<(u64, Run, bool)> = Vec::new();
        for (i, run) in inputs.selection.iter().enumerate() {
            let occurrence = |at: u64| self.placed.get(i).map_or(at, |placement| placement.occurrence_at(at));
            let Some(window) = self.windows.iter().find(|w| w.run == i) else {
                let named = inputs.is_named_draft(&run.origin);
                for (piece, ordinal) in self.pieces(i, run) {
                    let at = occurrence(ordinal);
                    if named {
                        placed.extend(recompose(&piece, &self.twins).into_iter().map(|(sent, ..)| (at, sent, true)));
                    } else {
                        placed.push((at, piece, true));
                    }
                }
                continue;
            };
            for (k, part) in window.parts.iter().enumerate() {
                let at = occurrence(part.ordinal);
                match compose_part(window, k, self.answer_at(window, k)) {
                    PartComposition::ByReference(published) => placed.push((at, published, true)),
                    PartComposition::KeptPrivate(words) => placed.push((at, words, false)),
                    PartComposition::LeftOut | PartComposition::PublishFirst | PartComposition::Owed => {}
                }
            }
        }
        placed.sort_by_key(|(at, ..)| *at);
        let received = placed.iter().filter(|(.., reader)| *reader).map(|(_, run, _)| run.clone()).collect();
        (placed.into_iter().map(|(_, run, _)| run).collect(), received)
    }

    /// Returns each part of `now` — a later read of the same selection's
    /// windows — whose naming differs from this enumeration's at its first
    /// word ([`parts::renamed`]), each with the record naming it now.
    pub fn renamed(&self, now: &[Window]) -> Vec<(PartKey, Option<Address>)> {
        parts::renamed(&self.windows, now)
    }

    /// Returns this composition's answers carried onto `now`, a later read
    /// of the same selection's windows (PUB-3.108; [`parts::answers_onto`]).
    pub fn answers_onto(&self, now: &[Window]) -> BTreeMap<PartKey, Answer> {
        parts::answers_onto(&self.windows, &self.answers, now)
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

/// Returns `pieces`, the carried pieces of every held run, then `stray`,
/// the published words the twins name for them, then every named part's
/// counterpart among `windows`: the words any answer can publish.
fn publishable_of(mut pieces: Vec<Run>, stray: &[Run], windows: &[Window]) -> Vec<Run> {
    pieces.extend(stray.iter().cloned());
    pieces.extend(windows.iter().flat_map(|w| &w.parts).filter_map(|p| p.counterpart()?.run()));
    pieces
}

/// Returns THE STRAY WORDS of `pieces`, carried pieces of the held runs:
/// the published words `twins` name for a named draft's piece, each
/// stretch the twin pre-check re-composes by reference, in order.
fn stray_words(inputs: &Inputs, pieces: &[Run], twins: &[Record]) -> Vec<Run> {
    pieces.iter().filter(|piece| inputs.is_named_draft(&piece.origin)).flat_map(|piece| recompose(piece, twins)).filter_map(|(sent, _, by_reference)| by_reference.then_some(sent)).collect()
}

/// Returns the indices of `runs` widest first, runs of one width in their
/// order: the order held runs take their kept places in, so a run takes
/// its place before any run it encloses.
fn widest_first(runs: &[Run]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..runs.len()).collect();
    order.sort_by_key(|&k| std::cmp::Reverse(runs[k].width));
    order
}

/// The kept places held runs have taken in one draft: V-spans, keyed by
/// their first ordinal, no two of which overlap.
#[derive(Debug, Default)]
struct TakenPlaces(BTreeMap<u64, u64>);

impl TakenPlaces {
    /// Takes the V-span `width` wide at `at`, answering whether it took it:
    /// it takes nothing where the span overlaps a place already taken.
    fn take(&mut self, at: u64, width: u64) -> bool {
        // No two taken spans overlap, so the only one that can reach into
        // this span is the one opening last before its end.
        let free = self.0.range(..at.saturating_add(width)).next_back().is_none_or(|(start, taken)| start.saturating_add(*taken) <= at);
        if free {
            self.0.insert(at, width);
        }
        free
    }
}

/// Returns where `image` arranges `run`: each piece of it as its V-ordinal,
/// first I-ordinal and width, and the V-ordinals it stands whole at, both
/// in V-order.
fn arranged_in(image: &[IRun], run: &Run) -> (Vec<(u64, u64, u64)>, Vec<u64>) {
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
    (pieces, wholes)
}

/// Places the held runs in the image: each whole at one V-ordinal, in
/// pieces, or absent.
///
/// No two held runs take overlapping places (PUB-3.9 step 5, the re-window
/// checked by identity): the board re-windows a list's places in the runs'
/// order over what the entries before left, so a place inside one already
/// re-windowed is refused `kept_place_moved`. The runs take their places
/// widest first, runs of one width in the selection's order, each the
/// first place in V-order it stands whole at that overlaps none taken: a
/// run enclosing another takes its place whichever comes first in the
/// selection, and a run the selection holds TWICE — a request may name a
/// run twice (the design's M7 (b)) — takes the draft's occurrences in
/// V-order, the k-th held copy the k-th place.
///
/// Where every place a run stands whole at overlaps one taken, the run
/// answers the place its occurrence names — the k-th held copy whole at the
/// k-th, in pieces past the last — and `disjoint_places` gives that place
/// up where the request is composed, the run enclosing it covering its
/// words.
///
/// A run takes one place here, whatever else of it the draft arranges: the
/// first enumeration's answer, and the one an `also` draft's list takes
/// its occurrences by. A place the run gains since the panel's reads is the
/// re-read's to take (the module's doc, **The second places**).
pub fn place_selection(image: &[IRun], selection: &[Run]) -> Vec<Placement> {
    place_runs(image, selection, |_, _| 1)
}

/// Places the held runs as a later read does, over `first`, the enumeration
/// the panel was read over (the module's doc, **The second places**).
///
/// `grows` is the re-read's: a run standing whole at more places than
/// `first`'s image shows, and any `first` carries at several, takes every
/// whole place it stands at. Without it, at a held panel's re-open, a run
/// `first` carries at several takes as many as `first` carried, and any
/// other run the one [`place_selection`] gives it.
fn place_again(image: &[IRun], selection: &[Run], first: &Enumeration, grows: bool) -> Vec<Placement> {
    place_runs(image, selection, |k, standing| match first.placed.get(k) {
        Some(Placement::Places(held)) if !grows => held.len(),
        Some(Placement::Places(_)) => usize::MAX,
        _ if grows && standing > arranged_in(&first.image, &selection[k]).1.len() => usize::MAX,
        _ => 1,
    })
}

/// Places each held run as [`place_selection`] does, then lets a run take
/// further whole places.
///
/// `most` answers how many places the run at an index may stand at, given
/// how many it stands whole at now. Only a run's last held copy takes more,
/// so the k-th copy keeps the k-th place, each in V-order through the same
/// [`TakenPlaces`], so none lies inside a place a held run took.
fn place_runs(image: &[IRun], selection: &[Run], most: impl Fn(usize, usize) -> usize) -> Vec<Placement> {
    let mut taken = TakenPlaces::default();
    let mut out = vec![Placement::Absent; selection.len()];
    let order = widest_first(selection);
    for &k in &order {
        let run = &selection[k];
        let (pieces, wholes) = arranged_in(image, run);
        let occurrence = selection[..k].iter().filter(|s| *s == run).count();
        out[k] = match wholes.iter().copied().find(|&at| taken.take(at, run.width)).or_else(|| wholes.get(occurrence).copied()) {
            Some(ordinal) => Placement::Whole { ordinal },
            None if pieces.is_empty() => Placement::Absent,
            None => Placement::Split(pieces),
        };
    }
    for &k in &order {
        let run = &selection[k];
        let Placement::Whole { ordinal } = out[k] else { continue };
        if selection[k + 1..].contains(run) {
            continue;
        }
        let (_, wholes) = arranged_in(image, run);
        let limit = most(k, wholes.len());
        let mut places = vec![ordinal];
        for at in wholes {
            if places.len() >= limit {
                break;
            }
            if taken.take(at, run.width) {
                places.push(at);
            }
        }
        if places.len() > 1 {
            places.sort_unstable();
            out[k] = Placement::Places(places);
        }
    }
    out
}

/// Returns `places`, one draft's kept places parallel to `runs`, with no
/// two overlapping (PUB-3.9, the re-window checked by identity).
///
/// The runs keep their places in the order `place_selection` takes them,
/// widest first, and a place overlapping one already kept becomes `None`.
/// The draft stands as it is at that run: the words the kept place holds
/// are re-windowed by the run that kept it, and any of a partial overlap's
/// words outside it stay the draft's own until its next shot.
pub(crate) fn disjoint_places(runs: &[Run], places: &[Option<u64>]) -> Vec<Option<u64>> {
    let mut taken = TakenPlaces::default();
    let mut kept = vec![None; places.len()];
    for k in widest_first(runs) {
        kept[k] = places[k].filter(|&at| taken.take(at, runs[k].width));
    }
    kept
}

/// Returns the V-spans the placements cover, sorted and merged where
/// adjacent.
pub fn region_of(placed: &[Placement], selection: &[Run]) -> Vec<(u64, u64)> {
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for (p, run) in placed.iter().zip(selection) {
        match p {
            Placement::Whole { ordinal } => spans.push((*ordinal, run.width)),
            Placement::Places(ordinals) => spans.extend(ordinals.iter().map(|o| (*o, run.width))),
            Placement::Split(pieces) => spans.extend(pieces.iter().map(|(o, _, w)| (*o, *w))),
            Placement::Absent => {}
        }
    }
    merged(spans)
}

/// Returns `spans` sorted and merged where adjacent or overlapping.
pub(crate) fn merged(mut spans: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
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
        Placement::Places(ordinals) => ordinals.iter().map(|ordinal| (run.clone(), *ordinal)).collect(),
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
            atoms.dedup();
        }
        out.push(atoms);
    }
    Ok(out)
}

/// Reads the windows of the selection, each in its parts.
///
/// It is the enumeration's windows step run on its own over one image of
/// the draft — the shell re-reads them at a held panel's re-open, never
/// from the read's cache (B3-S11 P2 (i)).
///
/// # Errors
///
/// The reads' faults, as [`enumerate`]'s.
pub fn windows(p: &Publisher<'_>, inputs: &Inputs) -> Result<Vec<Window>, Fault> {
    let door = Door::new(p.board, p.token);
    let d = inputs.draft.to_string();
    door.step("image");
    let extent = door.extent(&d)?;
    let image = door.image(&d, 1, extent)?;
    windows_with(&door, p, inputs, &place_selection(&image, &inputs.selection))
}

/// Reads the windows through `door`, over the held runs as `placed` places
/// them.
///
/// A run is a window where its origin is neither a named draft — the
/// rendering draft, or one `also` names, whose words are re-minted — nor the
/// trunk, where the draft arranges some of it, and where its origin is
/// unpublished ([`origin_state`]): the person's own exactly, or at a merge
/// any other account's (`Inputs::merge_landing`), each asked the one way —
/// one `doc_metadata` read per origin, kept. Each window's records are read
/// in the origin's own account, every record kept (the link-sets design
/// §5.5; [`window_records`]), and none where the origin answers `withheld`;
/// each arranged piece is cut into its parts at their edges ([`parts_of`]).
///
/// # Errors
///
/// The reads' faults; [`Fault::Unreadable`] naming a window onto the
/// person's own document that answers `withheld`.
pub(crate) fn windows_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, placed: &[Placement]) -> Result<Vec<Window>, Fault> {
    door.step("windows");
    let trunk = inputs.doc.as_ref();
    let mut out = Vec::new();
    for (i, run) in inputs.selection.iter().enumerate() {
        if inputs.is_named_draft(&run.origin) || trunk == Some(&run.origin) {
            continue;
        }
        let origin = run.origin.to_string();
        let foreign = !owned_by(&origin, p.account);
        if foreign && !inputs.merge_landing {
            continue;
        }
        let state = origin_state(door, &origin)?;
        match state {
            OriginState::Published => continue,
            OriginState::Withheld if !foreign => return Err(Fault::Unreadable(run.origin.clone())),
            OriginState::Private | OriginState::Withheld => {}
        }
        let pieces = placed.get(i).map_or_else(Vec::new, |placement| carried(run, placement, &[]));
        if pieces.is_empty() {
            continue;
        }
        let owner = account_of(&origin).unwrap_or_default();
        let records = if state == OriginState::Private { window_records(door, &owner, run)? } else { Vec::new() };
        let parts = pieces.iter().flat_map(|(piece, ordinal)| parts_of(piece, *ordinal, &records, foreign)).collect();
        out.push(Window { run: i, origin: run.origin.clone(), owner, i_start: run.i_start, width: run.width, parts });
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

/// Returns the positions of `ranges` that `held` does not hold, as
/// `(chain, lo, hi)` ranges: the published positions version ⟨k⟩ did not
/// arrange (key (iii); the fold's test (ii)).
fn unheld_ranges(ranges: &[(String, u64, u64)], held: &[ISpan]) -> Vec<(String, u64, u64)> {
    ranges
        .iter()
        .flat_map(|(chain, lo, hi)| ISpan { chain: chain.clone(), first: *lo, width: hi - lo }.less(held))
        .map(|s| (s.chain.clone(), s.first, s.reach()))
        .collect()
}

/// Returns whether `cover` holds every position of `ranges` — vacuously
/// where `ranges` is empty.
fn covered(ranges: &[(String, u64, u64)], cover: &[ISpan]) -> bool {
    ranges.iter().all(|(chain, lo, hi)| ISpan { chain: chain.clone(), first: *lo, width: hi - lo }.less(cover).is_empty())
}

/// Returns the runs' I-spans as four-set slot elements.
fn run_spans(runs: &[Run]) -> Vec<Value> {
    runs.iter().map(|r| frames::i_span(&r.i_start_text(), r.width)).collect()
}

/// Makes the enumeration's reads under a door of its own, and answers their
/// composition under no answer.
///
/// # Errors
///
/// In this order: the images' faults; [`Fault::SelectionNotArranged`] where
/// a held run is not arranged whole at one place — the first enumeration's
/// answer, the re-read's a difference; the atoms' reads' faults; then
/// [`Fault::OnlyMergeRecords`] where every position of the selection holds
/// a merge record, nothing further read — the re-read's answer too, over
/// what the draft still arranges of it; then the other reads' faults. A
/// read's faults are `withheld` and `doc_not_registered` on the draft or on
/// a draft `also` names (each is imaged for its own kept places), the death
/// signal, `scan_busy` past the reissues, a shape this client cannot read,
/// the board's other refusals and transport faults verbatim.
pub fn enumerate(p: &Publisher<'_>, inputs: &Inputs) -> Result<Enumeration, Fault> {
    let door = Door::new(p.board, p.token);
    enumerate_with(&door, p, inputs, true, None)
}

/// Makes the enumeration's reads again for a panel `first` was read over, a
/// held panel's re-open, and answers their composition under no answer.
///
/// [`enumerate`] with one exception (the module's doc, **The second
/// places**): a run `first` carries at several places stays carried at as
/// many. A place since then waits for the re-read's re-statement.
///
/// # Errors
///
/// [`enumerate`]'s.
pub fn enumerate_again(p: &Publisher<'_>, inputs: &Inputs, first: &Enumeration) -> Result<Enumeration, Fault> {
    let door = Door::new(p.board, p.token);
    enumerate_with(&door, p, inputs, true, Some(first))
}

/// Makes the enumeration's reads through `door`, and answers their
/// composition under no answer.
///
/// `strict` refuses a held run not arranged whole; the re-read passes
/// `false` and reads the placements as differences. `first` is an earlier
/// read of this publication: a run it carries at several places is carried
/// so again and, at the re-read, a run standing at more places than its
/// image shows joins them (the module's doc, **The second places**); and
/// its version ⟨k⟩, where that is the image of the request's `base`, is
/// kept and the base read never again — a published member's positions
/// never change.
pub(crate) fn enumerate_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, strict: bool, first: Option<&Enumeration>) -> Result<Enumeration, Fault> {
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
    let placed = match first {
        Some(first) => place_again(&image, &inputs.selection, first, !strict),
        None => place_selection(&image, &inputs.selection),
    };
    if strict {
        if let Some(index) = placed.iter().position(|pl| !matches!(pl, Placement::Whole { .. } | Placement::Places(_))) {
            return Err(Fault::SelectionNotArranged { index });
        }
    }

    // The pieces a publication can carry and their region: each held run as
    // the draft places it, cut around its merge records — at the re-read,
    // what the draft still arranges of it (PUB-3.108; the link-sets design
    // §5.7).
    door.step("merge_records");
    let merge_atoms = merge_atoms_of(door, &d, inputs, &placed)?;
    let pieces: Vec<(Run, u64)> = inputs.selection.iter().zip(&placed).zip(&merge_atoms).flat_map(|((run, placement), atoms)| carried(run, placement, atoms)).collect();
    if pieces.is_empty() && merge_atoms.iter().any(|atoms| !atoms.is_empty()) {
        return Err(Fault::OnlyMergeRecords { draft: inputs.draft.clone() });
    }
    let region = merged(pieces.iter().map(|(piece, ordinal)| (*ordinal, piece.width)).collect());
    let trunk = inputs.doc.as_ref().map(ToString::to_string);

    let windows = windows_with(door, p, inputs, &placed)?;

    // THE TWINS: the records whose `from` the named drafts' carried pieces
    // hold, read as the twin pre-check reads them, and the stray words they
    // name — published words the request sends in the pieces' place.
    door.step("twins");
    let carried_runs: Vec<Run> = pieces.into_iter().map(|(piece, _)| piece).collect();
    let twins = twin_records(door, p, inputs, &carried_runs)?;
    let stray = stray_words(inputs, &carried_runs, &twins);
    let publishable = publishable_of(carried_runs, &stray, &windows);

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
            Via::Region => touches(&value, &publishable),
            Via::ReadThrough(_) => true,
        };
        if !touching {
            return Ok(());
        }
        let (Some(link_addr), Some(home_addr)) = (parse_address(link), parse_address(home)) else { return Ok(()) };
        seen.insert(link.to_string(), candidates.len());
        candidates.push(Candidate { link: link_addr, home: home_addr, value, via, successors: Vec::new(), revised: false, touching: false, left_out: false, unchanged: false });
        Ok(())
    };
    for a in &addrs {
        keep(a, Via::Region, door, &mut candidates, false)?;
    }

    // THE COUNTERPART'S IDENTITY: the links on each named part's published
    // words and on the stray words, kept as the region's are, so an answer
    // at the part reads nothing and a link made on published words the
    // draft shows as its own again is read as it was while it showed them.
    door.step("counterparts");
    let published_words: Vec<Value> = windows.iter().flat_map(|w| &w.parts).filter_map(Part::counterpart).map(|s| s.wire()).chain(run_spans(&stray)).collect();
    for chunk in published_words.chunks(MAX_WIRE_LIST) {
        let mut hits = door.addrs(&d, &frames::find_links_four(Slot::Any, Slot::Spans(chunk), Slot::Any, Slot::Any))?;
        hits.extend(door.addrs(&d, &frames::find_links_four(Slot::Any, Slot::Any, Slot::Spans(chunk), Slot::Any))?);
        for hit in hits {
            keep(&hit, Via::Region, door, &mut candidates, false)?;
        }
    }

    // The twins first, so the walk and the read-through take them as any
    // earlier shot's record; the read below meets them again over the stray
    // words and keeps none of them twice.
    door.step("records");
    let mut records: Vec<Record> = twins.clone();
    let mut record_seen: BTreeSet<String> = twins.iter().map(|r| r.link.to_string()).collect();
    let spans = run_spans(&publishable);
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
    // Each successor's ends are kept, so key (iii) is decided at every
    // composition without a read.
    let held: BTreeSet<Address> = candidates.iter().map(|c| c.link.clone()).collect();
    for c in &mut candidates {
        let link = c.link.to_string();
        let ins = answers::claims(&door.answered(&link, &frames::in_claims(&link))?);
        for row in ins.iter().filter(|r| r.active && owned_by(&r.home, p.account)) {
            let (Some(claim), Some(new)) = (parse_address(&row.claim), parse_address(&row.new)) else { continue };
            let published_home = home_of_link(&row.new).is_some_and(|h| inputs.is_published_home(h));
            let ends = match door.link(&row.new)? {
                Some(value) => value.from.iter().chain(&value.to).filter_map(ISpan::of).collect(),
                None => Vec::new(),
            };
            let candidate = held.contains(&new);
            c.successors.push(Successor { claim, new, published_home, ends, covers: false, candidate });
        }
        let outs = answers::claims(&door.answered(&link, &frames::out_claims(&link))?);
        for row in outs.iter().filter(|r| r.active && owned_by(&r.home, p.account)) {
            let originals = answers::claims(&door.answered(&row.old, &frames::in_claims(&row.old))?);
            if originals.iter().any(|o| o.active && owned_by(&o.home, p.account) && home_of_link(&o.new).is_some_and(|h| inputs.is_published_home(h))) {
                c.revised = true;
            }
        }
    }

    // VERSION ⟨k⟩: the member the request's `base` names, its position and
    // its image over the positions the draft's copy took — kept where an
    // earlier read of this publication imaged it, a member's positions
    // never changing.
    door.step("base");
    let base = match &inputs.base {
        Some(base) if is_version_member(&base.0) => match first.and_then(|f| f.base.as_ref()).filter(|k| k.is_of(base)) {
            Some(known) => Some(known.clone()),
            None => {
                let member = base.0.to_string();
                let at = door.metadata(&member)?.at;
                let image = door.image(&member, 1, base.1)?;
                Some(BaseImage { member: base.0.clone(), extent: base.1, at, image })
            }
        },
        Some(_) | None => None,
    };

    let mut homes: Vec<(Address, Vec<usize>)> = Vec::new();
    for (i, c) in candidates.iter().enumerate() {
        match homes.iter_mut().find(|(h, _)| *h == c.home) {
            Some((_, indices)) => indices.push(i),
            None => homes.push((c.home.clone(), vec![i])),
        }
    }
    let read = Enumeration {
        extent,
        image,
        also,
        base,
        placed,
        merge_atoms,
        windows,
        twins,
        answers: BTreeMap::new(),
        left_out: BTreeSet::new(),
        selection: Vec::new(),
        received: Vec::new(),
        region,
        candidates,
        records,
        homes,
        frames: door.counts(),
        as_of: door.as_of(),
    };
    Ok(read.composed(inputs, &BTreeMap::new(), &BTreeSet::new()))
}
