//! THE RE-READ (the link-sets design §5.6, §5.7) and THE REQUEST (§5.7).
//!
//! **The re-read.** At the confirmation the enumeration and the panel run
//! AGAIN over the same held selection — the region read with its
//! stored-endset test, the read-through, the filter's claims, the held
//! removals — and the two answers are DIFFED: a link no longer offered (gone
//! or retracted), a candidate a claim of the person's has since superseded,
//! a held removal since undone, a link that has arrived, and the held runs
//! against the one image in V-order — a run absent, split, moved or
//! re-ordered since the panel's reads is a DIFFERENCE. Any difference is
//! answered as a [`Restatement`], data for the caller to confirm again over
//! what is left; nothing is sent on it. The image's places are the kept
//! places the request then carries per draft-native run.
//!
//! **The request.** From the confirmed rows: the runs from the held
//! selection as the re-read placed them — a split run as its pieces in the
//! draft's order, each with its own kept place — every window onto the
//! person's own unpublished origin answered first (THE THREE ANSWERS:
//! publish-first is NOT this request, which stays inert; DROP leaves the
//! run out; KEEP PRIVATE sends it as a window with no place beside it) and
//! THE COUNTERPART offered first where a record of a draft the person reads
//! names a window's words; the twin pre-check re-composing what the draft's
//! records already name; then `links` — each switched-on row's offered
//! links and the formatting line's marks, `home` the tag `member` or the
//! row's picked set, `from`/`to` in the address form, the I-span form or THE
//! MEMBER-POSITION FORM for an end on this shot's new words, spelled
//! CANONICALLY from the client's own runs (the lowest positions holding each
//! value, consecutive positions merged), `ty` verbatim, `old` the original;
//! `retract` the job list's marks; `read_with` the switched-on rows'
//! destinations other than the edition, once each, none where the edition
//! is already read with it; `claim` with `mint` and `account` at a first
//! publication of a free-standing draft; `places` beside `runs`; the signed
//! body through the one body builder, `entry_body_publication`, from the
//! request AS BUILT; a fresh `id`. INERT where the request changes nothing
//! against its base. The price is computed on the request as built.
//!
//! `todo`: `claim` WITHOUT `mint` — the claim admitted at a first version
//! into an edition that holds no member yet (the owner's ruling (i)) — is
//! the daemon's own lane; until it lands this builder sends `claim` only
//! with `mint`, and gains the arm then.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use serde_json::Value;
use skep_address::{Address, Nat, Span, Tumbler};
use skep_identity::{entry_body_publication, unit_span, DepositHome, DepositKind, DepositRow, DepositSlot, EntryBody, MemberPositions, PublishBody, ShotBase, SlotElement};

use crate::address::parse_address;
use crate::board::answers::LinkSpan;
use crate::board::frames::{self, PublishFrame, Slot, T_CORRESPONDENCE, T_EDITION, T_READ_WITH};
use crate::board::T_RETRACTION;

use super::enumerate::{enumerate_with, Enumeration, Placement, Record};
use super::landed::{read_record, twin_precheck_with};
use super::panel::{count, panel_with, Count, Destination, Panel, RowKind};
use super::price::{self, EndShape, EntryShape, Price, Shape};
use super::{canonical_member_spans, fresh_id, owned_by, Door, Fault, ISpan, Inputs, Publisher, Run};

/// The caller's answer at a window onto their own unpublished origin, or
/// onto words a counterpart record names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Publish the origin first: NOT this request, which stays inert.
    PublishFirst,
    /// Leave the run out of `runs` and `places`.
    Drop,
    /// Send the run as a window onto the private origin, no place beside it.
    KeepPrivate,
    /// Take the counterpart: the run re-composed by reference to the
    /// record's published words.
    Counterpart,
}

/// The counterpart offered first at a window onto a draft the person reads:
/// a record of that draft names the run's words as published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counterpart {
    /// The run's index in the selection.
    pub run: usize,
    /// The draft the record is homed in.
    pub draft: Address,
    /// The record.
    pub record: Address,
    /// The part of the run the record covers, on the run's own chain.
    pub from: ISpan,
    /// The published span that part became.
    pub to: ISpan,
}

/// What the caller confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Confirmed {
    /// The rows' switches.
    pub switches: super::panel::Switches,
    /// The answers, by the run's index in the selection.
    pub answers: BTreeMap<usize, Answer>,
}

/// Why no request is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inert {
    /// Windows onto the person's own unpublished origins with no answer yet,
    /// by the run's index.
    Unanswered(Vec<usize>),
    /// The caller publishes an origin first: those runs, by index; this
    /// request is not sent.
    PublishFirst(Vec<usize>),
    /// The request changes nothing against its base: every run by reference
    /// to the base member's in its order and no entry.
    Unchanged,
}

/// What the re-read found changed since the panel's reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Restatement {
    /// Links offered before and gone now — retracted, or no longer on the
    /// words.
    pub left: Vec<Address>,
    /// Links offered before and superseded since by a claim of the person's.
    pub superseded: Vec<Address>,
    /// Links offered now that were not before.
    pub came: Vec<Address>,
    /// Held removals on the job list before and gone now.
    pub removals_undone: Vec<Address>,
    /// Held removals on the job list now that were not before.
    pub removals_came: Vec<Address>,
    /// Held runs whose placement changed: the run's index and where it
    /// stands now.
    pub selection: Vec<(usize, Placement)>,
}

impl Restatement {
    fn is_empty(&self) -> bool {
        self.left.is_empty() && self.superseded.is_empty() && self.came.is_empty() && self.removals_undone.is_empty() && self.removals_came.is_empty() && self.selection.is_empty()
    }
}

/// The re-read's answer: the enumeration and the panel as they stand now,
/// and the differences, where any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reread {
    /// The enumeration now.
    pub enumeration: Enumeration,
    /// The panel now.
    pub panel: Panel,
    /// What changed, or `None`.
    pub restatement: Option<Restatement>,
}

/// Reads the enumeration and the panel again and diffs them against the
/// first.
///
/// # Errors
///
/// The reads' faults.
pub fn reread(p: &Publisher<'_>, inputs: &Inputs, first: &Enumeration, first_panel: &Panel) -> Result<Reread, Fault> {
    let door = Door::new(p.board, p.token);
    let enumeration = enumerate_with(&door, p, inputs, false)?;
    let panel = panel_with(&door, p, inputs, &enumeration)?;
    let restatement = restate(first, first_panel, &enumeration, &panel);
    Ok(Reread { enumeration, panel, restatement })
}

/// Diffs two answers of the enumeration and the panel.
pub fn restate(first: &Enumeration, first_panel: &Panel, now: &Enumeration, now_panel: &Panel) -> Option<Restatement> {
    let offered = |e: &Enumeration| -> BTreeSet<Address> { e.offered().into_iter().map(|i| e.candidates[i].link.clone()).collect() };
    let (before, after) = (offered(first), offered(now));
    let mut out = Restatement::default();
    for link in before.difference(&after) {
        let superseded = now.candidates.iter().any(|c| c.link == *link && !c.offered());
        if superseded {
            out.superseded.push(link.clone());
        } else {
            out.left.push(link.clone());
        }
    }
    out.came = after.difference(&before).cloned().collect();
    let jobs = |p: &Panel| -> BTreeSet<Address> { p.formatting.job_list().iter().map(|r| r.mark.clone()).collect() };
    let (jobs_before, jobs_after) = (jobs(first_panel), jobs(now_panel));
    out.removals_undone = jobs_before.difference(&jobs_after).cloned().collect();
    out.removals_came = jobs_after.difference(&jobs_before).cloned().collect();
    for (i, (a, b)) in first.placed.iter().zip(&now.placed).enumerate() {
        if a != b {
            out.selection.push((i, b.clone()));
        }
    }
    (!out.is_empty()).then_some(out)
}

/// A `links` entry's home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryHome {
    /// The member the shot mints.
    Member,
    /// A published document of the person's.
    Set(Address),
}

/// One end of a `links` entry, as the request spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// The address form: addresses, or the tags `member` and `edition`.
    Addrs(Vec<String>),
    /// The I-span form.
    Spans(Vec<ISpan>),
    /// The member-position form, canonical.
    Member(Vec<(u64, u64)>),
}

impl End {
    fn wire(&self) -> Value {
        match self {
            End::Addrs(list) => frames::addrs_end(&list.iter().map(String::as_str).collect::<Vec<_>>()),
            End::Spans(list) => frames::spans_end(&list.iter().map(|s| frames::end_span(&format!("{}.{}", s.chain, s.first), s.width)).collect::<Vec<_>>()),
            End::Member(spans) => frames::member_end(spans),
        }
    }

    fn shape(&self) -> EndShape {
        match self {
            End::Addrs(list) => EndShape::Addrs(list.clone()),
            End::Spans(list) => EndShape::Spans(list.clone()),
            End::Member(spans) => EndShape::Member(spans.clone()),
        }
    }
}

/// One `links` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The home.
    pub home: EntryHome,
    /// The `from` end.
    pub from: End,
    /// The `to` end.
    pub to: End,
    /// The type slot.
    pub ty: End,
    /// The private original the copy stands for.
    pub old: Option<Address>,
    /// The candidate the entry carries: an index into the enumeration's
    /// candidates.
    pub candidate: usize,
}

/// Why a switched-on link's end could not be spelled in one form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unspellable {
    /// An end on this shot's new words beside a span the member does not
    /// hold: the member-position form cannot carry the far span, nor the
    /// I-span form the new words.
    MixedForms,
    /// An end mixing an address — a link, a document — with content spans.
    MixedAddress,
}

/// One piece of the shot's signed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    /// Positions the commit copies in, one value each.
    Values(Vec<Vec<u8>>),
    /// A window onto another document's I-space, signed by address.
    Window {
        /// The run's first I-address.
        start: Address,
        /// The run's width.
        width: u64,
    },
}

/// The one request, as built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `E`, at the document form.
    pub doc: Option<Address>,
    /// The parent account, at the mint form.
    pub mint: Option<Address>,
    /// Whether the edition claim rides (with `mint` alone).
    pub claim: bool,
    /// The base member and extent.
    pub base: Option<(Address, u64)>,
    /// The staging draft; `None` at a bare shot naming none (the merge's).
    pub draft: Option<Address>,
    /// The runs, in V-order.
    pub runs: Vec<Run>,
    /// The kept places, parallel to the runs.
    pub places: Vec<Option<u64>>,
    /// Per run, the records covering a stray run re-composed by reference.
    pub stray_records: Vec<usize>,
    /// The signed body's pieces, parallel to the runs.
    pub pieces: Vec<Piece>,
    /// The `links` entries.
    pub entries: Vec<Entry>,
    /// The `retract` entries.
    pub retract: Vec<Address>,
    /// The `read_with` entries.
    pub read_with: Vec<Address>,
    /// The switched-on links left out for want of one form, with why.
    pub unspellable: Vec<(Address, Unspellable)>,
    /// The counterparts offered at windows onto drafts the person reads.
    pub counterparts: Vec<Counterpart>,
    /// The per-session `id`, fresh per request.
    pub id: String,
    /// The count the rows as switched give.
    pub count: Count,
    /// The price on the request as built.
    pub price: Price,
    /// The highest `as_of` the request's reads answered — the position the
    /// race face reads the feed from.
    pub as_of: u64,
}

impl Request {
    /// Returns the term the entry frame's `doc` row names: the trunk, or the
    /// account at the mint form.
    pub fn term(&self) -> &Address {
        self.doc.as_ref().or(self.mint.as_ref()).expect("a request is the document form or the mint form")
    }

    /// Returns the shot's own body — the count, the segments, the base group.
    pub fn shot_body(&self) -> EntryBody {
        let base_text = self.base.as_ref();
        let mut body = PublishBody::within(usize::MAX, base_text.map(|(member, extent)| ShotBase { member, extent: *extent })).expect("no bound refuses the body of no segments");
        for piece in &self.pieces {
            body = match piece {
                Piece::Values(values) => {
                    let mut b = body;
                    for v in values {
                        b = b.push(v).expect("no bound refuses a piece");
                    }
                    b
                }
                Piece::Window { start, width } => body.window(start, NonZeroU64::new(*width).expect("a run has width")).expect("no bound refuses a window"),
            };
        }
        body.finish()
    }

    /// Returns the signed body: the shot's rows, then the deposit rows in the
    /// one order, through the one body builder.
    pub fn body(&self) -> EntryBody {
        let rows = self.rows();
        let borrowed: Vec<DepositRow<'_>> = rows.iter().map(OwnedRow::borrow).collect();
        entry_body_publication(self.shot_body(), &borrowed)
    }

    /// Returns the frame, with `attest` where one is composed, under the
    /// request's `id`.
    pub fn frame(&self, attest: Option<Value>) -> Value {
        let runs: Vec<Value> = self.runs.iter().map(|r| frames::shot_run(&r.origin.to_string(), &r.i_start_text(), r.width)).collect();
        let places: Vec<Value> = self.places.iter().map(|p| p.map_or(Value::Null, frames::place)).collect();
        let links: Vec<Value> = self.entries.iter().map(|e| frames::link_entry(&home_text(&e.home), e.from.wire(), e.to.wire(), e.ty.wire(), e.old.as_ref().map(ToString::to_string).as_deref())).collect();
        let retract: Vec<String> = self.retract.iter().map(ToString::to_string).collect();
        let read_with: Vec<String> = self.read_with.iter().map(ToString::to_string).collect();
        let (doc, account, base, draft) = (self.doc.as_ref().map(ToString::to_string), self.mint.as_ref().map(ToString::to_string), self.base.as_ref().map(|(m, e)| (m.to_string(), *e)), self.draft.as_ref().map(ToString::to_string));
        frames::publication(&PublishFrame {
            doc: doc.as_deref(),
            account: account.as_deref(),
            mint: self.mint.is_some(),
            claim: self.claim && self.mint.is_some(),
            base: base.as_ref().map(|(m, e)| (m.as_str(), *e)),
            draft: draft.as_deref(),
            runs: &runs,
            places: &places,
            links: &links,
            retract: &retract.iter().map(String::as_str).collect::<Vec<_>>(),
            read_with: &read_with.iter().map(String::as_str).collect::<Vec<_>>(),
            attest,
            id: Some(&self.id),
        })
    }

    /// Returns the deposit rows in the signed order: the member's, then a
    /// minted edition's, then every other home's in address order; inside a
    /// home the edition claim, the copies, the retractions, the read-withs,
    /// each in declared order.
    pub(crate) fn rows(&self) -> Vec<OwnedRow> {
        let mut homes: BTreeMap<OwnedHome, Vec<OwnedRow>> = BTreeMap::new();
        let mut push = |home: OwnedHome, kind: DepositKind, ty: OwnedSlot, from: OwnedSlot, to: OwnedSlot| {
            homes.entry(home.clone()).or_default().push(OwnedRow { home, kind, ty, from, to });
        };
        if let (true, Some(_), Some(draft)) = (self.claim, &self.mint, &self.draft) {
            push(OwnedHome::Edition, DepositKind::EditionClaim, OwnedSlot::unit(&address(T_EDITION)), OwnedSlot::Stored(vec![OwnedElement::Edition]), OwnedSlot::unit(draft));
        }
        for entry in &self.entries {
            let home = match &entry.home {
                EntryHome::Member => OwnedHome::Member,
                EntryHome::Set(s) => OwnedHome::Addr(s.clone()),
            };
            push(home, DepositKind::Copy, OwnedSlot::of(&entry.ty), OwnedSlot::of(&entry.from), OwnedSlot::of(&entry.to));
        }
        for mark in &self.retract {
            let home = address(super::home_of_link(&mark.to_string()).unwrap_or_default());
            push(OwnedHome::Addr(home.clone()), DepositKind::Retraction, OwnedSlot::unit(&address(T_RETRACTION)), OwnedSlot::unit(&home), OwnedSlot::unit(mark));
        }
        for set in &self.read_with {
            let from = match &self.doc {
                Some(trunk) => OwnedSlot::unit(trunk),
                None => OwnedSlot::Stored(vec![OwnedElement::Edition]),
            };
            push(OwnedHome::Addr(set.clone()), DepositKind::ReadWith, OwnedSlot::unit(&address(T_READ_WITH)), from, OwnedSlot::unit(set));
        }
        homes.into_values().flatten().collect()
    }

    /// Returns the `links` entries' shapes for the price.
    fn entry_shapes(&self) -> Vec<EntryShape> {
        self.entries.iter().map(|e| EntryShape { from: e.from.shape(), to: e.to.shape(), ty: e.ty.shape(), old: e.old.is_some() }).collect()
    }

    /// Prices the request as it stands, with the caller's home count and the
    /// draft's run count.
    pub fn priced(&self, homes: usize, draft_runs: usize) -> Price {
        let entries = self.entry_shapes();
        let term = self.term().clone();
        let draft = self.draft.clone().unwrap_or_else(|| term.clone());
        price::price(&Shape {
            runs: &self.runs,
            draft: &draft,
            term: &term,
            mint: self.mint.is_some(),
            claim: self.claim && self.mint.is_some(),
            places: &self.places,
            stray_records: &self.stray_records,
            entries: &entries,
            retract: self.retract.len(),
            read_with: self.read_with.len(),
            body_bytes: self.body().as_bytes().len(),
            homes,
            draft_runs,
        })
    }

    /// Re-composes the request without the entries at `retract_skipped`
    /// and `read_with_skipped`, under a FRESH `id` — the one re-sign at
    /// `attestation_invalid:signature` for a deposit the transaction skipped.
    pub fn without(&mut self, retract_skipped: &[usize], read_with_skipped: &[usize]) {
        let retract = std::mem::take(&mut self.retract);
        self.retract = retract.into_iter().enumerate().filter(|(i, _)| !retract_skipped.contains(i)).map(|(_, m)| m).collect();
        let read_with = std::mem::take(&mut self.read_with);
        self.read_with = read_with.into_iter().enumerate().filter(|(i, _)| !read_with_skipped.contains(i)).map(|(_, s)| s).collect();
        self.id = fresh_id();
    }
}

fn home_text(home: &EntryHome) -> String {
    match home {
        EntryHome::Member => "member".to_string(),
        EntryHome::Set(s) => s.to_string(),
    }
}

fn address(text: &str) -> Address {
    parse_address(text).unwrap_or_else(|| parse_address("1.1").expect("an address"))
}

/// The home of a deposit's rows, in the signed order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OwnedHome {
    Member,
    Edition,
    Addr(Address),
}

#[derive(Debug, Clone)]
pub(crate) enum OwnedElement {
    Span(Span),
    Member,
    Edition,
}

#[derive(Debug, Clone)]
pub(crate) enum OwnedSlot {
    Stored(Vec<OwnedElement>),
    Member(Vec<MemberPositions>),
}

/// One deposit's rows, owned ahead of the builder's borrow.
#[derive(Debug, Clone)]
pub(crate) struct OwnedRow {
    home: OwnedHome,
    kind: DepositKind,
    ty: OwnedSlot,
    from: OwnedSlot,
    to: OwnedSlot,
}

impl OwnedSlot {
    fn unit(a: &Address) -> OwnedSlot {
        OwnedSlot::Stored(vec![OwnedElement::Span(unit_span(a))])
    }

    fn of(end: &End) -> OwnedSlot {
        match end {
            End::Addrs(list) => OwnedSlot::Stored(
                list.iter()
                    .map(|a| match a.as_str() {
                        "member" => OwnedElement::Member,
                        "edition" => OwnedElement::Edition,
                        text => OwnedElement::Span(unit_span(&address(text))),
                    })
                    .collect(),
            ),
            End::Spans(list) => OwnedSlot::Stored(list.iter().map(|s| OwnedElement::Span(span_of(s))).collect()),
            End::Member(spans) => OwnedSlot::Member(spans.iter().map(|&(ordinal, width)| MemberPositions { ordinal, width }).collect()),
        }
    }

    fn borrow(&self) -> DepositSlot<'_> {
        match self {
            OwnedSlot::Stored(elements) => DepositSlot::Stored(
                elements
                    .iter()
                    .map(|e| match e {
                        OwnedElement::Span(s) => SlotElement::Span(s),
                        OwnedElement::Member => SlotElement::Member,
                        OwnedElement::Edition => SlotElement::Edition,
                    })
                    .collect(),
            ),
            OwnedSlot::Member(spans) => DepositSlot::MemberPositions(spans.clone()),
        }
    }
}

impl OwnedRow {
    fn borrow(&self) -> DepositRow<'_> {
        let home = match &self.home {
            OwnedHome::Member => DepositHome::Member,
            OwnedHome::Edition => DepositHome::Edition,
            OwnedHome::Addr(a) => DepositHome::Address(a),
        };
        DepositRow { home, kind: self.kind, ty: self.ty.borrow(), from: self.from.borrow(), to: self.to.borrow() }
    }
}

/// Returns an I-span as the `Span` the body spells.
fn span_of(s: &ISpan) -> Span {
    let comps: Vec<Nat> = s.chain.split('.').map(|c| Nat::from(c.parse::<u64>().unwrap_or(0))).chain([Nat::from(s.first)]).collect();
    let depth = comps.len();
    let start = Tumbler::new(comps).expect("a chain and an ordinal");
    let width = Tumbler::new(std::iter::repeat_n(Nat::from(0u32), depth - 1).chain([Nat::from(s.width)])).expect("nonempty");
    Span::new(start, width).expect("a count at the start's depth is well-formed")
}

/// What `build` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Built {
    /// The request, ready to price and send.
    Request(Box<Request>),
    /// No request: why.
    Inert(Inert),
}

/// Builds the request from the confirmed rows over the re-read's answer.
///
/// # Errors
///
/// The reads' faults: the origins' metadata, the counterpart reads, the twin
/// pre-check, the values, the base's image.
pub fn build(p: &Publisher<'_>, inputs: &Inputs, e: &Enumeration, panel: &Panel, confirmed: &Confirmed) -> Result<Built, Fault> {
    let door = Door::new(p.board, p.token);
    build_with(&door, p, inputs, e, panel, confirmed)
}

/// Builds the request through `door`.
pub(crate) fn build_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, e: &Enumeration, panel: &Panel, confirmed: &Confirmed) -> Result<Built, Fault> {
    door.step("origins");
    let trunk = inputs.doc.clone();
    // The runs as placed, each with its kept place and its place in the draft.
    let mut runs: Vec<Run> = Vec::new();
    let mut places: Vec<Option<u64>> = Vec::new();
    let mut draft_places: Vec<Option<u64>> = Vec::new();
    let mut unanswered = Vec::new();
    let mut publish_first = Vec::new();
    let mut counterparts: Vec<Counterpart> = Vec::new();
    let unit = |a: &str| frames::unit_span(a).as_array().cloned().unwrap_or_default();
    let subtype = unit(T_CORRESPONDENCE);
    for (i, run) in inputs.selection.iter().enumerate() {
        let pieces: Vec<(Run, u64)> = match e.placed.get(i) {
            Some(Placement::Whole { ordinal }) => vec![(run.clone(), *ordinal)],
            Some(Placement::Split(parts)) => parts.iter().map(|(o, first, width)| (Run::new(run.origin.clone(), *first, *width), *o)).collect(),
            Some(Placement::Absent) | None => Vec::new(),
        };
        let native = run.origin == inputs.draft;
        let own = trunk.as_ref() == Some(&run.origin);
        if native || own {
            for (piece, ordinal) in pieces {
                runs.push(piece);
                places.push(native.then_some(ordinal));
                draft_places.push(Some(ordinal));
            }
            continue;
        }
        // A window. Onto the person's own unpublished origin: an answer owed.
        let origin = run.origin.to_string();
        let own_unpublished = owned_by(&origin, p.account) && !door.metadata(&origin)?.published;
        // The counterpart first, at a window onto a draft the person reads.
        let mut counterpart: Option<Counterpart> = None;
        if inputs.readable_drafts.contains(&run.origin) {
            let span = [frames::i_span(&run.i_start_text(), run.width)];
            for hit in door.addrs(&origin, &frames::find_links_four(Slot::Spans(&unit(&origin)), Slot::Spans(&span), Slot::Any, Slot::Spans(&subtype)))? {
                if let Some(record) = read_record(door, p, &hit)? {
                    if let (Some((lo, hi)), Some(to)) = (record.from.overlap(&run.chain(), run.i_start, run.reach()), record.map(&run.chain(), run.i_start, run.reach())) {
                        counterpart = Some(Counterpart { run: i, draft: run.origin.clone(), record: record.link.clone(), from: ISpan { chain: run.chain(), first: lo, width: hi - lo }, to });
                        break;
                    }
                }
            }
        }
        let answer = confirmed.answers.get(&i).copied();
        if let Some(c) = &counterpart {
            counterparts.push(c.clone());
        }
        match (own_unpublished, answer) {
            (_, Some(Answer::Drop)) => {}
            (_, Some(Answer::PublishFirst)) => publish_first.push(i),
            (_, Some(Answer::Counterpart)) if counterpart.is_some() => {
                // The part the record covers by reference to its published
                // words, the rest a window, in the piece's order.
                let c = counterpart.as_ref().expect("a counterpart");
                let origin = parse_address(&c.to.document().unwrap_or_default()).unwrap_or_else(|| run.origin.clone());
                for (piece, ordinal) in pieces {
                    let mut cursor = piece.i_start;
                    while cursor < piece.reach() {
                        let hi = c.from.reach().min(piece.reach());
                        let covered = c.from.first <= cursor && cursor < hi;
                        let end = if covered { hi } else if c.from.first > cursor && c.from.first < piece.reach() { c.from.first } else { piece.reach() };
                        let run_out = if covered { Run::new(origin.clone(), c.to.first + (cursor - c.from.first), end - cursor) } else { Run::new(piece.origin.clone(), cursor, end - cursor) };
                        runs.push(run_out);
                        places.push(None);
                        draft_places.push(Some(ordinal + (cursor - piece.i_start)));
                        cursor = end;
                    }
                }
            }
            (true, None) => unanswered.push(i),
            _ => {
                // KEEP PRIVATE, or a window onto a published origin or
                // another's draft: by address, no place.
                for (piece, ordinal) in pieces {
                    runs.push(piece);
                    places.push(None);
                    draft_places.push(Some(ordinal));
                }
            }
        }
    }
    if !unanswered.is_empty() {
        return Ok(Built::Inert(Inert::Unanswered(unanswered)));
    }
    if !publish_first.is_empty() {
        return Ok(Built::Inert(Inert::PublishFirst(publish_first)));
    }

    // The twin pre-check: what the draft's records already name, by reference.
    let recomposed = twin_precheck_with(door, p, inputs, &runs, &places, &draft_places)?;
    let (runs, places, draft_places, stray_records) = (recomposed.runs, recomposed.places, recomposed.draft_places, recomposed.stray_records);
    let mut records: Vec<Record> = e.records.clone();
    for r in recomposed.records {
        if !records.iter().any(|k| k.link == r.link) {
            records.push(r);
        }
    }

    // The entries.
    door.step("entries");
    let mut entries: Vec<Entry> = Vec::new();
    let mut unspellable: Vec<(Address, Unspellable)> = Vec::new();
    let ctx = SpellContext { draft_chain: format!("{}.0.1", inputs.draft), runs: &runs, records: &records };
    let mut add = |candidate: usize, home: EntryHome| {
        let c = &e.candidates[candidate];
        let ends = (spell_end(&c.value.from, &ctx), spell_end(&c.value.to, &ctx), spell_type(&c.value.ty));
        match ends {
            (Ok(from), Ok(to), Ok(ty)) => entries.push(Entry { home, from, to, ty, old: Some(c.link.clone()), candidate }),
            (Err(why), _, _) | (_, Err(why), _) | (_, _, Err(why)) => unspellable.push((c.link.clone(), why)),
        }
    };
    for &mark in &panel.formatting.marks {
        add(mark, EntryHome::Member);
    }
    for row in &panel.rows {
        if matches!(row.kind, RowKind::Public { .. }) || !confirmed.switches.on.contains(&row.home) {
            continue;
        }
        let home = match confirmed.switches.destination(&row.home) {
            Destination::Member => EntryHome::Member,
            Destination::Set(s) => EntryHome::Set(s),
        };
        for &i in &row.links {
            add(i, home.clone());
        }
    }
    let retract: Vec<Address> = panel.formatting.job_list().iter().map(|r| r.mark.clone()).collect();
    let count = count(panel, &confirmed.switches, inputs);
    let read_with = count.read_with.clone();

    // Inert where nothing changes against the base.
    door.step("base");
    let fresh = runs.iter().any(|r| r.origin == inputs.draft);
    if !fresh && entries.is_empty() && retract.is_empty() && read_with.is_empty() && inputs.mint.is_none() && places.iter().all(Option::is_none) {
        if let Some((base, extent)) = &inputs.base {
            let image = door.image(&base.to_string(), 1, *extent)?;
            let same = image.len() == runs.len() && image.iter().zip(&runs).all(|(a, r)| a.prefix == r.chain() && a.first == r.i_start && a.width == r.width);
            if same {
                return Ok(Built::Inert(Inert::Unchanged));
            }
        }
    }

    // The body's pieces: the values of every copied run read through the
    // draft, which arranges them at their places; a window by address.
    door.step("values");
    let draft = inputs.draft.to_string();
    let mut pieces = Vec::with_capacity(runs.len());
    for (k, run) in runs.iter().enumerate() {
        let copied = run.origin == inputs.draft || trunk.as_ref() == Some(&run.origin);
        match (copied, draft_places[k]) {
            (true, Some(place)) => pieces.push(Piece::Values(door.values(&draft, place, run.width)?)),
            (true, None) => pieces.push(Piece::Values(door.values(&run.origin.to_string(), run.i_start, run.width)?)),
            (false, _) => pieces.push(Piece::Window { start: parse_address(&run.i_start_text()).expect("a run's address"), width: run.width }),
        }
    }

    let mut request = Request {
        doc: inputs.doc.clone(),
        mint: inputs.mint.clone(),
        claim: inputs.claim,
        base: inputs.base.clone(),
        draft: Some(inputs.draft.clone()),
        runs,
        places,
        stray_records,
        pieces,
        entries,
        retract,
        read_with,
        unspellable,
        counterparts,
        id: fresh_id(),
        count,
        price: Price { lists: [0; 5], body: 0, values: 0, reads: 0, bytes: 0, over: Vec::new() },
        as_of: door.as_of().max(e.as_of),
    };
    let homes = e.homes.len() + inputs.published.iter().filter(|s| !e.homes.iter().any(|(h, _)| h == *s)).count();
    request.price = request.priced(homes, e.image.len());
    Ok(Built::Request(Box::new(request)))
}

/// What spelling an end needs.
struct SpellContext<'a> {
    draft_chain: String,
    runs: &'a [Run],
    records: &'a [Record],
}

/// Spells one end from its stored slot: the address form where every span
/// is a unit span at a non-content address; else the I-span form over
/// permanent spans — a span on the draft's own words mapped through the
/// records onto the published words where an earlier shot minted them, a
/// left-out span cut — or the member-position form where any span lies on
/// this shot's new words, every span of the end then one the member holds.
fn spell_end(slot: &[LinkSpan], ctx: &SpellContext<'_>) -> Result<End, Unspellable> {
    if slot.is_empty() {
        return Ok(End::Addrs(Vec::new()));
    }
    let spans: Vec<Option<ISpan>> = slot.iter().map(ISpan::of).collect();
    if spans.iter().all(Option::is_none) {
        return Ok(End::Addrs(slot.iter().map(|s| s.start.clone()).collect()));
    }
    if spans.iter().any(Option::is_none) {
        return Err(Unspellable::MixedAddress);
    }
    let spans: Vec<ISpan> = spans.into_iter().flatten().collect();
    let native_runs: Vec<&Run> = ctx.runs.iter().filter(|r| r.chain() == ctx.draft_chain).collect();
    let mut kept: Vec<ISpan> = Vec::new();
    let mut member_pieces: Vec<ISpan> = Vec::new();
    let mut any_native = false;
    for s in &spans {
        if s.chain == ctx.draft_chain {
            // Through the records first, then this shot's new words, the rest cut.
            let mut cursor = s.first;
            while cursor < s.reach() {
                if let Some(mapped) = ctx.records.iter().find_map(|r| r.map(&s.chain, cursor, s.reach())) {
                    let width = mapped.width;
                    kept.push(mapped);
                    cursor += width;
                    continue;
                }
                if let Some(run) = native_runs.iter().find(|r| r.i_start <= cursor && cursor < r.reach()) {
                    let end = run.reach().min(s.reach());
                    member_pieces.push(ISpan { chain: s.chain.clone(), first: cursor, width: end - cursor });
                    any_native = true;
                    cursor = end;
                    continue;
                }
                // Left out: cut at the next record or run boundary.
                let next = ctx.records.iter().filter(|r| r.from.chain == s.chain && r.from.first > cursor).map(|r| r.from.first).chain(native_runs.iter().filter(|r| r.i_start > cursor).map(|r| r.i_start)).min().unwrap_or(s.reach()).min(s.reach());
                cursor = next;
            }
        } else {
            kept.push(s.clone());
        }
    }
    if any_native {
        // Every span of the end must be one the member holds.
        let mut pieces = member_pieces;
        for k in &kept {
            if !k.within(ctx.runs) {
                return Err(Unspellable::MixedForms);
            }
            pieces.push(k.clone());
        }
        // In the stored order: re-sort the pieces by their place in `spans`.
        let order = |p: &ISpan| spans.iter().position(|s| s.chain == p.chain && s.first <= p.first && p.first < s.reach()).unwrap_or(usize::MAX);
        pieces.sort_by_key(order);
        let canonical = canonical_member_spans(ctx.runs, &pieces).ok_or(Unspellable::MixedForms)?;
        return Ok(End::Member(canonical));
    }
    if kept.is_empty() {
        // Wholly on left-out words of the draft: decision 5's far end with
        // this draft as its document, written as it is.
        return Ok(End::Spans(spans));
    }
    Ok(End::Spans(kept))
}

/// Spells the type slot: the address form where every span is a unit span,
/// else the I-span form verbatim.
fn spell_type(slot: &[LinkSpan]) -> Result<End, Unspellable> {
    if slot.iter().all(LinkSpan::is_unit) {
        return Ok(End::Addrs(slot.iter().map(|s| s.start.clone()).collect()));
    }
    let spans: Vec<ISpan> = slot.iter().map(ISpan::of).collect::<Option<_>>().ok_or(Unspellable::MixedAddress)?;
    Ok(End::Spans(spans))
}
