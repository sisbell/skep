//! THE PANEL's DATA (the link-sets design §5.2) and THE COUNT (§5.6;
//! PUB-3.8's four terms).
//!
//! **The reads, once, at the open**, over every candidate of every identity
//! the enumeration read — so an answer at a window part re-decides the
//! panel from them with no read ([`Panel::composed`]): THE HELD REMOVALS,
//! `D`'s `3.24` records read home-constrained and kept by the exact type,
//! each naming a published mark by address, the mark read once, whether its
//! retraction already STANDS (the retraction-stands read), and for a mark
//! of THE FORMATTING TYPES (the line's shape test without its inline-mark
//! exception, P11) not spent and lying on words any answer can publish, its
//! private original read from its own accept claim; each home's state off
//! `doc_metadata`, one read per home; the state of every document a
//! candidate's ends or a record's `to` can name as a far document, and of a
//! type's own document, one read each; each home's label, its first line,
//! read by one `retrieve_doc_v_span_set` and one `retrieve_v` per home; and
//! the read-with presence over the person's published homes (W1 (a)),
//! for every published document of the person's, the possible
//! destinations, so the count knows which read-with a destination still
//! needs.
//!
//! **The composition**, from the enumeration as the answers compose it
//! ([`Enumeration::composed`]) and those reads alone. The rows, one per
//! home with a candidate touching the selection as composed, in the
//! design's order: the draft's own set first, then the notes set(s) in the
//! caller's order, then the person's other sets, PRIVATE before PUBLIC; per
//! row the offered links folded by TYPE with each type's count and each far
//! document, and the line's counts as DATA — ⟨p⟩ links pointing into
//! private documents, ⟨d⟩ links with an end wholly on words of the draft
//! the selection leaves out, ⟨c⟩ links with an end running past the
//! selection's cut, ⟨t⟩ links typed by a private document, ⟨u⟩ revisions of
//! links already published; and per row THE FOLD ([`FoldCounts`], E4 1.8):
//! its offered links counted UNCHANGED since version ⟨k⟩ — the fold's test
//! the enumeration decides against the member the request's `base` names
//! ([`Candidate::unchanged`]) — and not, so a private row whose every link
//! passes is drawn compact and one with any that fails whole, folded by
//! change (E4 1.2, 1.3). THE FORMATTING LINE, in the draft's own set
//! alone, holds the offered links the line's TEST keeps: exactly one of
//! `from` and `to` non-empty, the type slot exactly one unit span in the
//! formatting types' own subtrees — `3.20` heading, `3.21` paragraph and its
//! family, `3.23` inline and its family save `3.23.4` mark — and no other
//! span save a parameter inside the registry document. A mark is judged on
//! THE WORDS A READER RECEIVES (`Enumeration::received`): no mark goes onto
//! a window part kept behind a placeholder — formatting goes out with the
//! words readers receive, and a placeholder gives them none — so one lying
//! partly there runs past the cut at its edge, and one lying wholly there
//! is no mark of the line and stays in the draft's own set. Per window
//! part, what its answer brings ([`PartCounts`]): at the counterpart, the
//! line's marks and the private rows' links on the published words; behind
//! a placeholder, the person's formatting marks held back there. THE HELD
//! REMOVALS are the line's job list: a removal whose mark is off the
//! selection stays off the line; one whose retraction already stands is
//! spent and dropped; the ⟨r⟩/⟨e⟩ split by the job list's overlap with the
//! line's own marks of the same type — a RE-MAKE is the mark's `links` entry
//! and the removal's `retract` entry, counted once in ⟨e⟩ and in neither
//! ⟨n⟩ nor ⟨r⟩. A PUBLIC row states whether `E` is read with the set and
//! draws no switch. Every row's SWITCH is the caller's input ([`Switches`]:
//! a private row OFF by default, the formatting line no switch, a public row
//! its state). The drafts `also` names have no window — their runs are
//! re-minted as the document's own words, not windowed (the Nelson way,
//! B3-S10) — and the panel answers for each instead THE STATEMENT's count
//! ([`inherited`]): the passages first written in it, the data of P2 (i)'s
//! statement before the act ("⟨n⟩ passages first written in ⟨D⟩ publish as
//! ⟨E⟩'s own words; ⟨D⟩ keeps a record of where they went"), consecutive
//! runs of one origin in the selection's V-order counted once; the
//! rendering draft's own words are counted nowhere, nor a passage an
//! earlier shot already published, which the selection as published holds
//! as the published words its twin names. THE MERGE RECORDS LEFT
//! OUT ([`MergeRecords`]) are the panel's data too: per named draft whose
//! runs of the selection hold any, how many — the enumeration's cut, which
//! no publication carries (the merge record's decision 7), the data of the
//! statement "⟨n⟩ merge records in ⟨label⟩ stay private and are not
//! published with it". WHETHER P3 STANDS ([`Panel::p3_stands`], E4 1.4) is
//! the panel's data too: it stands where it holds something to decide or to
//! say before the act — a private row with a link not unchanged since
//! version ⟨k⟩, the formatting line's marks or listed removals, a
//! re-offered original (an offered candidate a public successor of the
//! person's names), or a public row's link on words this version publishes
//! as new — and not where it would draw compact rows and public rows alone.
//! Every test of the selection here — the line's ⟨c⟩ and ⟨d⟩, the
//! formatting line's cut, the job list, the statement's passages, P3's
//! new words — reads the selection as published
//! ([`Enumeration::selection`]).
//!
//! **Ends read through the records.** The line's ⟨c⟩, ⟨d⟩ and far
//! documents, the formatting line's cut and its re-make test read a
//! candidate's ends as the filter reads them (`RecordWalk`), so an end on
//! words an earlier shot published counts as the published words the
//! request spells it on, never as words of this draft left out, and an end
//! on a window part taken by its counterpart as the published words its
//! record names.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use skep_address::Address;

use crate::address::{document_of, parse_address};
use crate::board::answers::{self, LinkValue};
use crate::board::frames::{self, Slot, REGISTRY_DOCUMENT, T_HELD_REMOVAL, T_READ_WITH};
use crate::board::T_RETRACTION;

use super::enumerate::{is_formatting, is_formatting_type, selected_ranges, touches, Candidate, EndPiece, Enumeration, Record, RecordWalk, Via};
use super::parts::{Answer, PartKey};
use super::{home_of_link, owned_by, Door, Fault, ISpan, Inputs, Publisher, Run};

/// How many positions of a home the label read takes at most: the first
/// line is cut at the first newline within them.
pub const LABEL_POSITIONS: u64 = 256;

/// A row's kind, and the order rows stand in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowKind {
    /// The draft's own set — the text being published.
    Own,
    /// A notes document the caller named.
    Notes,
    /// Another private set of the person's.
    Private,
    /// A set in a published document of the person's.
    Public {
        /// Whether `E` is read with the set now.
        read_with: bool,
    },
}

/// The links of one type in a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeFold {
    /// The type slot's address.
    pub ty: String,
    /// How many of the row's links carry it.
    pub n: usize,
    /// Each far document the links of this type point into, in address
    /// order.
    pub far: Vec<String>,
}

/// The line's counts, as data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LineCounts {
    /// Links with an end into a private document.
    pub p: usize,
    /// Links with an end wholly on words of this draft the selection leaves
    /// out.
    pub d: usize,
    /// Links with an end that runs past the selection's cut.
    pub c: usize,
    /// Links typed by a private document.
    pub t: usize,
    /// Revisions of links already published, not offered.
    pub u: usize,
}

/// A row's FOLD (E4 1.8): its offered links counted by the fold's test —
/// unchanged since version ⟨k⟩ ([`Candidate::unchanged`]) and not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FoldCounts {
    /// Links unchanged since version ⟨k⟩: made before it, on words it holds.
    pub unchanged: usize,
    /// Links not: made since, or touching words version ⟨k⟩ did not hold or
    /// this version publishes as new.
    pub changed: usize,
}

/// One row of the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The home — the set.
    pub home: Address,
    /// Its kind.
    pub kind: RowKind,
    /// The home's first line, as its bytes read.
    pub label: Vec<u8>,
    /// The offered links on the row: indices into the enumeration's
    /// candidates, the formatting line's left out.
    pub links: Vec<usize>,
    /// The links folded by type.
    pub types: Vec<TypeFold>,
    /// The line's counts.
    pub line: LineCounts,
    /// How many of the row's links the read-through reached: the private
    /// move's share where the row is left off.
    pub read_through: usize,
    /// The row's links counted by the fold's test: a private row whose
    /// every link is unchanged since version ⟨k⟩ is drawn compact (E4 1.2),
    /// one with any link changed whole, folded by change (E4 1.3).
    pub fold: FoldCounts,
}

/// The private original a held removal's mark stands for, which the commit
/// ends with the mark (the link-sets design §5.7 (vi′); §2).
///
/// Found FROM THE COPY, never from the draft: the `old` of the mark's own
/// accept claim — the active claim homed in a private document of the
/// person's whose `new` is the mark, one `out_claims` at the mark — read
/// once for its value. The rider the request carries names it, with the
/// rest, and the one commit retracts it at its home beside the mark's
/// retraction, so the mark taken off is drawn nowhere after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Original {
    /// The original, by address.
    pub link: Address,
    /// Its value as stored.
    pub value: LinkValue,
    /// The rest: the original's content spans less every span a copy of it
    /// covers — the copies the active claims at the original name, each
    /// read once, their published spans mapped back through the records
    /// where a shot re-minted the words — the words no copy ever covered,
    /// which the commit keeps formatted by a fresh mark; empty where every
    /// word is covered.
    pub rest: Vec<ISpan>,
}

/// One held removal of the draft: the formatting line's job list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// The `3.24` record in the draft.
    pub record: Address,
    /// The published mark it names, by address.
    pub mark: Address,
    /// The mark's value as stored.
    pub mark_value: LinkValue,
    /// Whether the mark is on the selection's words.
    pub on_selection: bool,
    /// Whether a retraction of the mark already stands — spent, no entry.
    pub spent: bool,
    /// The formatting-line mark that re-makes it, where one does: an index
    /// into the enumeration's candidates.
    pub remake: Option<usize>,
    /// The original the mark stands for, where the removal is on the job
    /// list, the mark is of THE FORMATTING TYPES (the line's shape test
    /// without its inline-mark exception, P11) and an active claim homed in
    /// a private document of the person's names the mark as its `new`;
    /// `None` for a removal off the list, a mark of another type — a note,
    /// a citation, a typed link keep their originals — one no such claim
    /// names, or whose original is gone or already retracted.
    pub original: Option<Original>,
}

impl Removal {
    /// Whether the removal is on the job list: on the selection and not
    /// spent.
    pub fn listed(&self) -> bool {
        self.on_selection && !self.spent
    }
}

/// The formatting line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Formatting {
    /// The marks on the line: indices into the enumeration's candidates.
    pub marks: Vec<usize>,
    /// How many of them run past the selection's cut, or lie partly on a
    /// placeholder, cut at its edge.
    pub cut: usize,
    /// The held removals, listed or not.
    pub removals: Vec<Removal>,
}

impl Formatting {
    /// Returns the job list: the removals on the selection, not spent.
    pub fn job_list(&self) -> Vec<&Removal> {
        self.removals.iter().filter(|r| r.listed()).collect()
    }
}

/// THE STATEMENT's count for one draft `also` names (B3-S11 P2 (i)'s
/// statement before the act, the Nelson way): the draft, and how many
/// PASSAGES of the selection were first written in it — the selection's runs
/// of that origin, consecutive runs of one origin in the selection's V-order
/// counted once. The ⟨n⟩ of "⟨n⟩ passages first written in ⟨D⟩ publish as
/// ⟨E⟩'s own words; ⟨D⟩ keeps a record of where they went", as DATA; the
/// statement itself is the page's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inherited {
    /// The draft `also` names.
    pub draft: Address,
    /// The passages of the selection first written in it.
    pub passages: usize,
}

/// The merge records of one named draft the selection holds, left out of
/// the publication (the merge record's decision 7).
///
/// It is the draft whose identity the records are and how many: the ⟨n⟩ of
/// "⟨n⟩ merge records in ⟨label⟩ stay private and are not published with
/// it", as DATA; the statement itself is the page's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeRecords {
    /// The named draft the records were written in.
    pub draft: Address,
    /// The merge records of it the selection holds.
    pub n: usize,
}

/// What one window part's answer brings to the panel: the data of the
/// answered row's clause (B3-S11 P2 (i)), the words the page's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartCounts {
    /// The part.
    pub part: PartKey,
    /// Taken by its counterpart: the formatting line's marks on the
    /// published words, which go out with them.
    pub marks: usize,
    /// Taken by its counterpart: the private rows' offered links on the
    /// published words, offered next.
    pub links: usize,
    /// Kept behind a placeholder: the person's formatting marks on its
    /// words, which stay in the draft until a version shows them.
    pub kept_marks: usize,
}

/// What the panel read at the open: every fact a composition needs, so an
/// answer reads nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct PanelReads {
    /// Per document — each home, and each document a composition can name
    /// as a far document or a type's own — whether it is published.
    published: BTreeMap<String, bool>,
    /// Per home, its first line.
    labels: BTreeMap<Address, Vec<u8>>,
    /// The held removals as read: whether each is spent, and the original
    /// of a mark that may be listed under some composition.
    removals: Vec<Removal>,
    /// Per published document of the person's, whether `E` is read with it.
    read_with: BTreeMap<Address, bool>,
}

/// The panel's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Panel {
    /// The rows, in the design's order.
    pub rows: Vec<Row>,
    /// The formatting line.
    pub formatting: Formatting,
    /// Per published document of the person's, whether `E` is read with it
    /// now — the destinations' states.
    pub read_with: BTreeMap<Address, bool>,
    /// What each window part's answer brings, one per part in the windows'
    /// order — zeros at a part left out or awaiting its answer.
    pub parts: Vec<PartCounts>,
    /// The statement's count per draft `also` names, in the request's
    /// order ([`inherited`]).
    pub inherited: Vec<Inherited>,
    /// The merge records left out, per named draft holding any, in the
    /// selection's order: never published, so the page says so.
    pub merge_records: Vec<MergeRecords>,
    /// Whether P3 stands (E4 1.4): it holds something to decide or to say
    /// before the act — a private row holding a link changed since version
    /// ⟨k⟩, the formatting line's marks or listed removals, a re-offered
    /// original, or a public row's link on words this version publishes as
    /// new. Where it does not stand, P2's own line says the links stayed
    /// private.
    pub p3_stands: bool,
    /// The frames sent, per step.
    pub frames: Vec<(&'static str, usize)>,
    /// The reads the open made, which every composition reads.
    reads: PanelReads,
}

impl Panel {
    /// Returns the panel as `e`'s composition decides it — the rows and
    /// their folds, the formatting line, the job list, the statement's
    /// count, whether P3 stands — from the reads this panel's open made:
    /// nothing is read.
    ///
    /// `e` is the enumeration the panel was read over, composed under the
    /// answers that stand ([`Enumeration::composed`]).
    pub fn composed(&self, inputs: &Inputs, e: &Enumeration) -> Panel {
        compose(inputs, e, &self.reads, self.frames.clone())
    }
}

/// Returns THE STATEMENT's count per draft of `also`, in its order.
///
/// For each it is the passages of `selection` — the selection as published
/// ([`Enumeration::selection`]) — first written in it: the selection's runs
/// of that origin, consecutive runs of one origin in the selection's
/// V-order counted once. Request arithmetic over the selection, reading
/// nothing; the rendering draft's own words are not counted (they are the
/// draft's, said nowhere).
pub fn inherited(also: &[Address], selection: &[Run]) -> Vec<Inherited> {
    also.iter()
        .map(|draft| {
            let mut passages = 0usize;
            let mut within = false;
            for run in selection {
                let of_draft = run.origin == *draft;
                if of_draft && !within {
                    passages += 1;
                }
                within = of_draft;
            }
            Inherited { draft: draft.clone(), passages }
        })
        .collect()
}

/// Returns the merge records the selection holds, per named draft holding
/// any, in the selection's order: each held run's merge records counted
/// under its origin, the draft whose identity they are (the enumeration's
/// `merge_records` step). Arithmetic over the enumeration, reading nothing.
fn merge_records(inputs: &Inputs, e: &Enumeration) -> Vec<MergeRecords> {
    let mut out: Vec<MergeRecords> = Vec::new();
    for (run, atoms) in inputs.selection.iter().zip(&e.merge_atoms).filter(|(_, atoms)| !atoms.is_empty()) {
        match out.iter_mut().find(|m| m.draft == run.origin) {
            Some(m) => m.n += atoms.len(),
            None => out.push(MergeRecords { draft: run.origin.clone(), n: atoms.len() }),
        }
    }
    out
}

/// Where a switched-on private row's links are published into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// The member the shot mints — the page at that version.
    Member,
    /// A published document of the person's, one pick away.
    Set(Address),
}

/// The rows' switches — the caller's input.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Switches {
    /// The private rows switched ON, by home; every other private row is
    /// off, the formatting line has no switch and a public row only its
    /// state.
    pub on: BTreeSet<Address>,
    /// A switched-on row's destination; the member where unnamed.
    pub destinations: BTreeMap<Address, Destination>,
}

impl Switches {
    /// Returns the destination of `home`'s row.
    pub fn destination(&self, home: &Address) -> Destination {
        self.destinations.get(home).cloned().unwrap_or(Destination::Member)
    }
}

/// THE COUNT's four numbers (PUB-3.8), and the claim clause.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Count {
    /// ⟨l⟩: the switched-on sets' `links` entries plus the `read_with`
    /// entries.
    pub l: usize,
    /// ⟨n⟩: the formatting line's `links` entries that re-make nothing.
    pub n: usize,
    /// ⟨r⟩: the `retract` entries no re-make covers.
    pub r: usize,
    /// ⟨e⟩: the re-makes — one `links` entry and one `retract` entry each.
    pub e: usize,
    /// Whether the one write carries the edition claim.
    pub claim: bool,
    /// The `read_with` entries the count carries: each switched-on private
    /// row's destination other than the member, once, where `E` is not
    /// already read with it.
    pub read_with: Vec<Address>,
    /// The daughters the one write claims superseded — the caller's
    /// [`Inputs::supersede`] as asked, the count's clause for "with its
    /// claim" (the merge bridge lane). The count reads nothing: a daughter an
    /// active claim of the person's own already names is dropped when the
    /// request is built, and the acknowledgment carries what rode
    /// ([`super::send::Ack::supersede`]).
    pub supersede: Vec<Address>,
}

/// Returns the original a held removal's `mark` stands for, with its rest,
/// read through `door` (the link-sets design §5.7 (vi′)).
///
/// One `out_claims` at the mark: the first active claim homed in a private
/// document of the person's — owned by the account, not among the
/// published documents — names the original as its `old`. One `read_link`
/// of it: gone, or a retraction of it standing, is no entry. The rest is
/// the original's content spans less every span a copy covers: one
/// `in_claims` at the original, each active claim's `new` read once, its
/// content spans and the draft words they stand for through `records`
/// ([`Record::unmap`]) subtracted on their chains.
///
/// # Errors
///
/// The reads' faults.
fn original_of(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, mark: &str, records: &[Record]) -> Result<Option<Original>, Fault> {
    let private = |home: &str| owned_by(home, p.account) && !inputs.is_published_home(home);
    let claims = answers::claims(&door.answered(mark, &frames::out_claims(mark))?);
    let Some(claim) = claims.iter().find(|c| c.active && c.new == mark && private(&c.home)) else { return Ok(None) };
    let Some(value) = door.link(&claim.old)? else { return Ok(None) };
    if !door.addrs(&claim.old, &frames::find_links_ftt(T_RETRACTION, &claim.old))?.is_empty() {
        return Ok(None); // already retracted: nothing to end
    }
    let Some(link) = parse_address(&claim.old) else { return Ok(None) };
    let mut covered: Vec<ISpan> = Vec::new();
    for copy in answers::claims(&door.answered(&claim.old, &frames::in_claims(&claim.old))?) {
        if !copy.active || copy.old != claim.old {
            continue;
        }
        let Some(copy_value) = door.link(&copy.new)? else { continue };
        for span in copy_value.from.iter().chain(&copy_value.to).filter_map(ISpan::of) {
            covered.extend(records.iter().filter_map(|r| r.unmap(&span.chain, span.first, span.reach())));
            covered.push(span);
        }
    }
    let rest = value.from.iter().chain(&value.to).filter_map(ISpan::of).flat_map(|span| span.less(&covered)).collect();
    Ok(Some(Original { link, value, rest }))
}

/// One stored content span of a candidate's end, read through the records
/// against the selection.
struct SpanReading {
    /// The pieces the walk reads the span in (`RecordWalk::pieces`).
    pieces: Vec<EndPiece>,
    /// Whether some piece holds a position the selection holds.
    touching: bool,
    /// Whether every piece lies in the selection.
    within: bool,
}

impl SpanReading {
    /// Reads `span`, an end of a candidate reached `via`, through `walk`
    /// against `selection`.
    fn of(walk: &RecordWalk<'_>, span: &ISpan, via: &Via, selection: &[Run]) -> SpanReading {
        let pieces = walk.pieces(span, via);
        let touching = pieces.iter().any(|p| p.span.touches(selection));
        let within = pieces.iter().all(|p| p.span.within(selection));
        SpanReading { pieces, touching, within }
    }

    /// Returns whether the span runs past the selection's cut: on the
    /// selection, and not wholly.
    fn past_the_cut(&self) -> bool {
        self.touching && !self.within
    }
}

fn ranges_overlap(a: &[(String, u64, u64)], b: &[(String, u64, u64)]) -> bool {
    a.iter().any(|(ca, la, ha)| b.iter().any(|(cb, lb, hb)| ca == cb && la.max(lb) < ha.min(hb)))
}

/// Builds the panel's data from the enumeration.
///
/// # Errors
///
/// The reads' faults, as `enumerate`'s.
pub fn panel(p: &Publisher<'_>, inputs: &Inputs, enumeration: &Enumeration) -> Result<Panel, Fault> {
    let door = Door::new(p.board, p.token);
    panel_with(&door, p, inputs, enumeration)
}

/// Makes the panel's reads through `door` and answers it composed as `e`
/// stands.
pub(crate) fn panel_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, e: &Enumeration) -> Result<Panel, Fault> {
    let draft = inputs.draft.to_string();
    let trunk = inputs.doc.as_ref().map(ToString::to_string);
    let publishable = e.publishable(inputs);

    // The held removals: D's 3.24 records, the mark read, the retraction
    // read, and for a mark of the formatting types some composition can
    // list its original read from its own accept claim.
    door.step("removals");
    let unit = |a: &str| frames::unit_span(a).as_array().cloned().unwrap_or_default();
    let mut removals = Vec::new();
    let hits = door.addrs(&draft, &frames::find_links_four(Slot::Spans(&unit(&draft)), Slot::Any, Slot::Any, Slot::Spans(&unit(T_HELD_REMOVAL))))?;
    for hit in hits {
        let Some(value) = door.link(&hit)? else { continue };
        if !value.typed_exactly(T_HELD_REMOVAL) {
            continue;
        }
        let Some(mark) = value.to.first().filter(|s| s.is_unit()).map(|s| s.start.clone()) else { continue };
        if home_of_link(&mark).is_none() {
            continue;
        }
        let Some(mark_value) = door.link(&mark)? else { continue };
        let spent = !door.addrs(&mark, &frames::find_links_ftt(T_RETRACTION, &mark))?.is_empty();
        let (Some(record), Some(mark_addr)) = (parse_address(&hit), parse_address(&mark)) else { continue };
        let listable = !spent && touches(&mark_value, &publishable) && is_formatting_type(&mark_value);
        let original = if listable { original_of(door, p, inputs, &mark, &e.records)? } else { None };
        removals.push(Removal { record, mark: mark_addr, mark_value, on_selection: false, spent, remake: None, original });
    }

    // The homes' states, then every document a composition can name as a
    // far document or a type's own.
    door.step("homes");
    let mut published: BTreeMap<String, bool> = BTreeMap::new();
    for (home, _) in &e.homes {
        let home_text = home.to_string();
        let state = door.metadata(&home_text)?.published;
        published.insert(home_text, state);
    }
    door.step("far");
    for doc in far_documents(inputs, e) {
        if let Entry::Vacant(slot) = published.entry(doc) {
            let state = door.metadata(slot.key())?.published;
            slot.insert(state);
        }
    }

    door.step("labels");
    let mut labels: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
    for (home, _) in &e.homes {
        let home_text = home.to_string();
        let extent = if *home == inputs.draft { e.extent } else { door.extent(&home_text)? };
        let width = extent.min(LABEL_POSITIONS);
        let mut label = Vec::new();
        if width > 0 {
            let bytes: Vec<u8> = door.values(&home_text, 1, width)?.into_iter().flatten().collect();
            let end = bytes.iter().position(|b| *b == b'\n').unwrap_or(bytes.len());
            label = bytes[..end].to_vec();
        }
        labels.insert(home.clone(), label);
    }

    door.step("read_with");
    let mut read_with: BTreeMap<Address, bool> = BTreeMap::new();
    if let Some(edition) = &trunk {
        for set in &inputs.published {
            let set_text = set.to_string();
            if set_text == *edition {
                continue;
            }
            let stands = read_with_stands(door, p, edition, &set_text)?;
            read_with.insert(set.clone(), stands);
        }
    }

    let reads = PanelReads { published, labels, removals, read_with };
    Ok(compose(inputs, e, &reads, door.counts()))
}

/// Returns every document a composition can name as a far document of a
/// candidate that may be offered — each content span's own, a unit span's,
/// each record's `to` the walk can map onto, a window part's among them —
/// or as the document of its type, the registry's, the draft and the trunk
/// left out.
fn far_documents(inputs: &Inputs, e: &Enumeration) -> BTreeSet<String> {
    let mut docs: BTreeSet<String> = BTreeSet::new();
    for c in e.candidates.iter().filter(|c| !c.revised) {
        for span in c.value.from.iter().chain(&c.value.to) {
            match ISpan::of(span) {
                Some(s) => docs.extend(s.document()),
                None => docs.extend(document_of(&span.start)),
            }
        }
        docs.extend(c.value.type_address().and_then(document_of).filter(|doc| doc != REGISTRY_DOCUMENT));
    }
    let part_records = e.windows.iter().flat_map(|w| &w.parts).filter_map(|p| p.record.as_ref());
    docs.extend(e.records.iter().chain(part_records).filter_map(|r| r.to.document()));
    docs.remove(&inputs.draft.to_string());
    if let Some(trunk) = &inputs.doc {
        docs.remove(&trunk.to_string());
    }
    docs
}

/// Composes the panel from the enumeration as composed and the open's
/// reads (the module's doc, **The composition**).
fn compose(inputs: &Inputs, e: &Enumeration, reads: &PanelReads, frames: Vec<(&'static str, usize)>) -> Panel {
    let draft = inputs.draft.to_string();
    let trunk = inputs.doc.as_ref().map(ToString::to_string);
    let is_published = |doc: &str| reads.published.get(doc).copied().unwrap_or(false);

    // Every candidate's ends read through the records and the parts taken by
    // their counterpart, as the filter reads them and the request spells
    // them.
    let walk = RecordWalk::composed(inputs, &e.records, e);

    // The formatting line: the draft's own set's offered marks by the line's
    // test, each on the words a reader receives.
    let own: Vec<usize> = e.homes.iter().find(|(h, _)| *h == inputs.draft).map(|(_, i)| i.clone()).unwrap_or_default();
    let marks: Vec<usize> = own.iter().copied().filter(|&i| e.candidates[i].offered() && is_formatting(&e.candidates[i].value)).collect();
    let placeholders = e.placeholder_words();
    let on_placeholder = |s: &ISpan| placeholders.iter().any(|w| w.overlap(&s.chain, s.first, s.reach()).is_some());
    let cut = marks
        .iter()
        .filter(|&&i| {
            let c = &e.candidates[i];
            c.end_spans().iter().any(|s| SpanReading::of(&walk, s, &c.via, e.judged(c)).past_the_cut()) || walk.spans(c).iter().any(on_placeholder)
        })
        .count();

    // The job list: each removal on the selection as composed, its re-make
    // among the line's marks, its original where it is listed.
    let removals: Vec<Removal> = reads
        .removals
        .iter()
        .map(|read| {
            let on_selection = touches(&read.mark_value, &e.selection);
            let listed = on_selection && !read.spent;
            let remake = listed
                .then(|| {
                    let mark_spans: Vec<ISpan> = read.mark_value.from.iter().chain(&read.mark_value.to).filter_map(ISpan::of).collect();
                    let mark_on = selected_ranges(&mark_spans, &e.selection);
                    marks.iter().copied().find(|&i| {
                        let c = &e.candidates[i];
                        c.value.type_address() == read.mark_value.type_address() && ranges_overlap(&selected_ranges(&walk.spans(c), &e.selection), &mark_on)
                    })
                })
                .flatten();
            let original = if listed && is_formatting_type(&read.mark_value) { read.original.clone() } else { None };
            Removal { on_selection, remake, original, ..read.clone() }
        })
        .collect();

    // The rows: one per home a candidate touches the composition at — its
    // state, its label, the fold by type, the line's counts.
    let mut rows: Vec<Row> = Vec::new();
    for (home, indices) in &e.homes {
        if !indices.iter().any(|i| e.candidates[*i].touching) {
            continue;
        }
        let kind = if *home == inputs.draft {
            RowKind::Own
        } else if inputs.notes.contains(home) {
            RowKind::Notes
        } else if is_published(&home.to_string()) {
            RowKind::Public { read_with: reads.read_with.get(home).copied().unwrap_or(false) }
        } else {
            RowKind::Private
        };
        let links: Vec<usize> = indices.iter().copied().filter(|i| e.candidates[*i].offered() && !marks.contains(i)).collect();
        let u = indices.iter().filter(|i| e.candidates[**i].revised).count();
        let label = reads.labels.get(home).cloned().unwrap_or_default();
        let unchanged = links.iter().filter(|i| e.candidates[**i].unchanged).count();
        let fold = FoldCounts { unchanged, changed: links.len() - unchanged };
        rows.push(Row { home: home.clone(), kind, label, links, types: Vec::new(), line: LineCounts { u, ..LineCounts::default() }, read_through: 0, fold });
    }
    rows.sort_by_key(|r| match r.kind {
        RowKind::Own => (0, 0, r.home.to_string()),
        RowKind::Notes => (1, inputs.notes.iter().position(|n| *n == r.home).unwrap_or(0), String::new()),
        RowKind::Private => (2, 0, address_key(&r.home.to_string())),
        RowKind::Public { .. } => (3, 0, address_key(&r.home.to_string())),
    });

    for row in &mut rows {
        let mut folds: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();
        let mut line = row.line;
        for &i in &row.links {
            let c: &Candidate = &e.candidates[i];
            if matches!(c.via, Via::ReadThrough(_)) {
                row.read_through += 1;
            }
            let mut far: BTreeSet<String> = BTreeSet::new();
            let (mut p_hit, mut d_hit, mut c_hit) = (false, false, false);
            for span in c.value.from.iter().chain(&c.value.to) {
                match ISpan::of(span) {
                    Some(s) => {
                        let read = SpanReading::of(&walk, &s, &c.via, e.judged(c));
                        if read.past_the_cut() {
                            c_hit = true;
                        }
                        if !read.touching {
                            for piece in &read.pieces {
                                let doc = piece.span.document().unwrap_or_default();
                                if doc == draft {
                                    d_hit = true;
                                } else if !doc.is_empty() {
                                    far.insert(doc);
                                }
                            }
                        }
                    }
                    None => {
                        if let Some(doc) = document_of(&span.start) {
                            far.insert(doc);
                        }
                    }
                }
            }
            for doc in &far {
                if trunk.as_deref() == Some(doc.as_str()) {
                    continue;
                }
                if !is_published(doc) {
                    p_hit = true;
                }
            }
            let ty = c.value.type_address().unwrap_or("").to_string();
            if let Some(doc) = document_of(&ty) {
                if doc != REGISTRY_DOCUMENT && !is_published(&doc) {
                    line.t += 1;
                }
            }
            line.p += usize::from(p_hit);
            line.d += usize::from(d_hit);
            line.c += usize::from(c_hit);
            let entry = folds.entry(ty).or_insert((0, BTreeSet::new()));
            entry.0 += 1;
            entry.1.extend(far);
        }
        row.line = line;
        row.types = folds.into_iter().map(|(ty, (n, far))| TypeFold { ty, n, far: far.into_iter().collect() }).collect();
    }

    // What each part's answer brings: at the counterpart, the line's marks
    // and the private rows' links on the published words; behind a
    // placeholder, the person's formatting marks held back on its words.
    let lies_on = |words: &ISpan, c: &Candidate| walk.spans(c).iter().any(|s| words.overlap(&s.chain, s.first, s.reach()).is_some());
    let mut parts = Vec::new();
    for window in &e.windows {
        for (k, part) in window.parts.iter().enumerate() {
            let mut counts = PartCounts { part: window.key(k), marks: 0, links: 0, kept_marks: 0 };
            match e.answer_at(window, k) {
                Some(Answer::Counterpart) => {
                    if let Some(words) = part.counterpart() {
                        counts.marks = marks.iter().filter(|&&i| lies_on(&words, &e.candidates[i])).count();
                        counts.links = rows.iter().filter(|r| !matches!(r.kind, RowKind::Public { .. })).flat_map(|r| &r.links).filter(|&&i| lies_on(&words, &e.candidates[i])).count();
                    }
                }
                Some(Answer::KeepPrivate) => {
                    counts.kept_marks = e.candidates.iter().filter(|c| is_formatting(&c.value) && !c.revised && !c.left_out && lies_on(&part.span, c)).count();
                }
                Some(Answer::Drop | Answer::PublishFirst) | None => {}
            }
            parts.push(counts);
        }
    }

    // Whether P3 stands (E4 1.4): a private row holding a link changed since
    // version ⟨k⟩, the formatting line holding a mark or a listed removal, a
    // re-offered original — one a public successor of the person's does not
    // drop — or a public row's link on words this version publishes as new.
    let on_new_words = |c: &Candidate| selected_ranges(&walk.spans(c), e.judged(c)).iter().any(|(chain, ..)| walk.is_named_chain(chain));
    let p3_stands = rows.iter().any(|r| !matches!(r.kind, RowKind::Public { .. }) && r.fold.changed > 0)
        || !marks.is_empty()
        || removals.iter().any(Removal::listed)
        || e.candidates.iter().any(|c| c.offered() && c.successors.iter().any(|s| s.published_home))
        || rows.iter().filter(|r| matches!(r.kind, RowKind::Public { .. })).flat_map(|r| &r.links).any(|&i| on_new_words(&e.candidates[i]));

    Panel {
        rows,
        formatting: Formatting { marks, cut, removals },
        read_with: reads.read_with.clone(),
        parts,
        inherited: inherited(&inputs.also, &e.selection),
        merge_records: merge_records(inputs, e),
        p3_stands,
        frames,
        reads: reads.clone(),
    }
}

/// Returns an address's components as numbers, the address order's key.
fn address_key(a: &str) -> String {
    a.split('.').map(|c| format!("{:020}", c.parse::<u64>().unwrap_or(0))).collect::<Vec<_>>().join(".")
}

/// Returns whether a read-with from `edition` to `set` stands in a PUBLISHED
/// home the person owns — the presence the daemon's plan reads (W1 (a)):
/// the rows the three slots match, each kept where its stored `from` and
/// `to` are exactly the two unit spans, its home's account the person's off
/// the address and its home published.
pub(crate) fn read_with_stands(door: &Door<'_>, p: &Publisher<'_>, edition: &str, set: &str) -> Result<bool, Fault> {
    let unit = |a: &str| frames::unit_span(a).as_array().cloned().unwrap_or_default();
    let hits = door.addrs(set, &frames::find_links_four(Slot::Any, Slot::Spans(&unit(edition)), Slot::Spans(&unit(set)), Slot::Spans(&unit(T_READ_WITH))))?;
    for hit in hits {
        let Some(home) = home_of_link(&hit) else { continue };
        if !owned_by(home, p.account) {
            continue;
        }
        let Some(value) = door.link(&hit)? else { continue };
        let exact = |slot: &[crate::board::answers::LinkSpan], start: &str| slot.len() == 1 && slot[0].start == start && slot[0].is_unit();
        if !(exact(&value.from, edition) && exact(&value.to, set)) {
            continue;
        }
        if door.metadata(home)?.published {
            return Ok(true);
        }
    }
    Ok(false)
}

/// THE COUNT (PUB-3.8): the four numbers from the rows as switched, and the
/// claim clause.
pub fn count(panel: &Panel, switches: &Switches, inputs: &Inputs) -> Count {
    let mut l = 0usize;
    let mut read_with: Vec<Address> = Vec::new();
    for row in &panel.rows {
        if matches!(row.kind, RowKind::Public { .. }) || !switches.on.contains(&row.home) {
            continue;
        }
        l += row.links.len();
        if let Destination::Set(set) = switches.destination(&row.home) {
            let stands = panel.read_with.get(&set).copied().unwrap_or(false);
            if !stands && !read_with.contains(&set) && inputs.doc.as_ref() != Some(&set) {
                read_with.push(set);
            }
        }
    }
    l += read_with.len();
    let remakes: BTreeSet<usize> = panel.formatting.removals.iter().filter(|r| r.listed()).filter_map(|r| r.remake).collect();
    let e = panel.formatting.removals.iter().filter(|r| r.listed() && r.remake.is_some()).count();
    let n = panel.formatting.marks.iter().filter(|m| !remakes.contains(m)).count();
    let r = panel.formatting.removals.iter().filter(|r| r.listed() && r.remake.is_none()).count();
    // The claim clause where the caller asks the claim, at either form:
    // whether the edition may take it is the board's to refuse; the daughters
    // as asked, the skip among them the request's read.
    Count { l, n, r, e, claim: inputs.claim, read_with, supersede: inputs.supersede.clone() }
}
