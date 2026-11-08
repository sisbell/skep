//! THE RE-READ (the link-sets design §5.6, §5.7) and THE REQUEST (§5.7).
//!
//! **The re-read.** At the confirmation the enumeration and the panel run
//! AGAIN over the same held selection, every test over what the draft still
//! arranges of it ([`Enumeration::selection`]; PUB-3.108) — the region read
//! with its stored-endset test, the read-through, the filter's claims, the
//! held removals — and the two answers are DIFFED: a link no longer offered
//! (gone or retracted), a candidate a claim of the person's has since
//! superseded, a held removal since undone, a link that has arrived, and the
//! held runs against the one image in V-order — a run absent, split, moved
//! or re-ordered since the panel's reads is a DIFFERENCE. Any difference is
//! answered as a [`Restatement`], data for the caller to confirm again over
//! what is left; nothing is sent on it. The image's places are the kept
//! places the request then carries per run of a named draft's identity; the
//! `also` drafts' images, read again beside it, give each its own list. The
//! base's standing is the caller's to read again beside it
//! ([`super::standing`]), a moved one riding the same re-statement.
//!
//! **The request.** From the confirmed rows: the runs from the held
//! selection as the re-read placed them — a split run as its pieces in the
//! draft's order, each run cut around its merge records, which no
//! publication carries as a run or with a kept place
//! ([`Enumeration::pieces`]), every named draft's run with the rendering
//! draft's kept place beside it (its own words and an `also` draft's
//! alike, which the rendering draft holds by identity), and, per draft
//! `also` names, THAT draft's own kept places in `also_places`, read off
//! its image, so the one commit re-windows every named draft at its own
//! places (skep #739; the Nelson way, B3-S10) — every window onto the
//! person's own unpublished origin answered first (THE THREE ANSWERS:
//! publish-first is NOT this request, which stays inert; DROP leaves the
//! run out; KEEP PRIVATE sends it as a window with no place beside it), a
//! window the draft no longer arranges carrying nothing and asked nothing
//! (PUB-3.108), and THE COUNTERPART offered first where a record of a draft
//! the person reads names a window's words — taken, the covered piece
//! re-composed by reference to the record's `to`, in this document or another,
//! with its kept place beside it as a stray's, so the commit re-windows the
//! draft there through the record; the twin pre-check re-composing what the
//! draft's records already name; then `links` — each switched-on row's offered
//! links and the formatting line's marks, `home` the tag `member` or the
//! row's picked set, `from`/`to` read through the records (`RecordWalk`)
//! and spelled in the address form, the I-span form or THE MEMBER-POSITION
//! FORM for an end on this shot's new words, spelled CANONICALLY from the
//! client's own runs (the lowest positions holding each value, consecutive
//! positions merged), `ty` verbatim, `old` the original;
//! `retract` the job list's marks; `read_with` the switched-on rows'
//! destinations other than the edition, once each, none where the edition
//! is already read with it; `claim` where the caller asks it, at either
//! form — with `mint` and `account` at a first publication of a
//! free-standing draft, or at the document form where `doc` is an edition
//! holding no member yet (the owner's ruling (i); skep #692), the claim row
//! then homed in `doc`'s trunk by address, first in that home's group;
//! `supersede` the daughters the caller names, each one supersession claim
//! homed in the trunk and its group last in the trunk's (the merge bridge
//! lane), THE SKIP READ FIRST: `in_claims` at each daughter, one an active
//! claim of the person's own already names dropped from the list and so
//! from the body, as the board's plan skips it, so the body signed is the
//! body the board composes; `places` and `also_places` beside `runs`,
//! neither in the signed body; the signed body through the one body
//! builder, `entry_body_publication`, from the request AS BUILT; a fresh
//! `id`. INERT where the request changes nothing against its base — a place
//! in either list is a change, and so is a daughter claimed. The price is
//! computed on the request as built.
//!
//! THE CLIENT DOES NOT DECIDE whether the edition is empty: it sends the
//! claim where asked, and the board refuses `claim_refused` where a member
//! already stands, which the send maps to its own arm naming the edition.
//! Nor whether the head stands: it sends the daughters where asked, and the
//! board refuses the whole publication `supersede_refused` where the base
//! is not the trunk's head, which the send maps to its own arm naming it.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use serde_json::Value;
use skep_address::{Address, Nat, Span, Tumbler};
use skep_identity::{entry_body_publication, unit_span, DepositHome, DepositKind, DepositRow, DepositSlot, EntryBody, MemberPositions, PublishBody, ShotBase, SlotElement};

use crate::address::parse_address;
use crate::board::answers::{self, LinkSpan};
use crate::board::frames::{self, AlsoPlacesFrame, PublishFrame, T_EDITION, T_READ_WITH};
use crate::board::{T_RETRACTION, T_SUPERSEDES};

use super::base::Standing;
use super::enumerate::{enumerate_with, place_selection, Enumeration, Placement, Record, RecordWalk, Via};
use super::landed::twin_precheck_with;
use super::panel::{count, panel_with, Count, Counterpart, Destination, Panel, RowKind};
use super::price::{self, EndShape, EntryShape, Price, Shape};
use super::{canonical_member_spans, fresh_id, own_claim_names, Door, Fault, ISpan, Inputs, Publisher, Run};

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
    /// record's published words, its covered piece sent with its kept place
    /// so the commit re-windows the draft there through the record.
    Counterpart,
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
    /// Unanswered windows the draft still arranges, by the run's index.
    ///
    /// Each is a run onto an unpublished origin of the person's own; a window
    /// the draft no longer arranges carries nothing and is owed no answer.
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
    /// Held runs whose placement in the rendering draft changed: the run's
    /// index and where it stands now.
    pub selection: Vec<(usize, Placement)>,
    /// The base's standing where it moved since the panel — a sibling's shot
    /// landing while the panel stood — as the caller typed it again; `None`
    /// where it stands as it stood, and from [`restate`], which diffs the
    /// enumeration and the panel alone.
    pub standing: Option<Standing>,
}

impl Restatement {
    fn is_empty(&self) -> bool {
        self.left.is_empty() && self.superseded.is_empty() && self.came.is_empty() && self.removals_undone.is_empty() && self.removals_came.is_empty() && self.selection.is_empty() && self.standing.is_none()
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

/// Reads the enumeration and the panel again and diffs them with the first.
///
/// # Errors
///
/// The reads' faults, in `enumerate`'s order, save that a held run the
/// draft no longer arranges whole is a difference and no fault; so
/// [`Fault::OnlyMergeRecords`] where every position the draft still
/// arranges of the selection holds a merge record, nothing further read.
pub fn reread(p: &Publisher<'_>, inputs: &Inputs, first: &Enumeration, first_panel: &Panel) -> Result<Reread, Fault> {
    let door = Door::new(p.board, p.token);
    let enumeration = enumerate_with(&door, p, inputs, false)?;
    let panel = panel_with(&door, p, inputs, &enumeration)?;
    let restatement = restate(first, first_panel, &enumeration, &panel);
    Ok(Reread { enumeration, panel, restatement })
}

/// Diffs two answers of the enumeration and the panel.
///
/// The placements diffed are the RENDERING draft's — the held selection
/// against its one image — and no member is added for an `also` draft's: a
/// run an `also` draft moved since the panel takes no place in that draft's
/// list (`also_places`, composed off its re-read image), the draft left as
/// it stands there; and a move the re-read did not see — between the
/// re-read and the commit — is the board's `kept_place_moved` naming that
/// draft (`site.addr`), answered as the rendering draft's is: the re-read
/// again, then the re-statement where it finds a difference, or the
/// refusal, naming the draft, where it finds none.
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

/// The kept places of one draft `also` names (the wire's `also_places`
/// entry; skep #739): the request's own spelling of the board's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlsoPlaces {
    /// The draft `also` names.
    pub draft: Address,
    /// Its kept places, parallel to the request's `runs`: at a run of this
    /// draft's identity the V-position its image arranged the run at when
    /// the request was composed, `None` where it did not arrange it whole
    /// and in order, and `None` at every run of another origin.
    pub places: Vec<Option<u64>>,
}

impl AlsoPlaces {
    /// Returns whether any entry carries a place: the draft is re-windowed,
    /// and the entry is sent.
    pub fn carries_a_place(&self) -> bool {
        self.places.iter().any(Option::is_some)
    }
}

/// The one request, as built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `E`, at the document form.
    pub doc: Option<Address>,
    /// The parent account, at the mint form.
    pub mint: Option<Address>,
    /// Whether the edition claim rides, at either form.
    pub claim: bool,
    /// The base member and extent.
    pub base: Option<(Address, u64)>,
    /// The rendering draft; `None` at a bare shot naming none (the merge's).
    pub draft: Option<Address>,
    /// The family's other drafts whose identity the shot re-mints beside
    /// the rendering draft's (the wire's `also`), in the request's order;
    /// empty at the one-draft shot and at a bare shot.
    pub also: Vec<Address>,
    /// The runs, in V-order.
    pub runs: Vec<Run>,
    /// The RENDERING draft's kept places, parallel to the runs: at a run of
    /// any named draft's identity — its own, or an `also` draft's it holds
    /// by identity — the rendering draft's own V-position of it; at a stray
    /// run re-composed by reference, the place of the words it stood for;
    /// `None` at a window.
    pub places: Vec<Option<u64>>,
    /// Each `also` draft's OWN kept places (the wire's `also_places`; skep
    /// #739), one entry per draft `also` names in its order, each list
    /// parallel to the runs: at a run of that draft's identity the
    /// V-position its image arranged the run at when the request was
    /// composed; `None` where it did not arrange it whole and in order —
    /// moved, split or deleted since the panel — the draft then left as it
    /// stands at that run and healed at its own next shot; `None` at every
    /// other run; a piece the twin pre-check re-composed by reference
    /// carries the draft's place at the piece's offset, a stray place the
    /// commit re-windows the draft at through its own record. An entry
    /// carrying no place is not sent. The one commit re-windows the
    /// rendering draft at `places`, then each `also` draft at its entry, in
    /// `also`'s order.
    pub also_places: Vec<AlsoPlaces>,
    /// Per run, the records covering a run re-composed by reference with a
    /// place — a stray run the twin pre-check re-composed, or a counterpart's
    /// covered piece, one record each; zero elsewhere.
    pub stray_records: Vec<usize>,
    /// The signed body's pieces, parallel to the runs.
    pub pieces: Vec<Piece>,
    /// The `links` entries.
    pub entries: Vec<Entry>,
    /// The `retract` entries.
    pub retract: Vec<Address>,
    /// The `read_with` entries.
    pub read_with: Vec<Address>,
    /// The `supersede` entries: the daughters the member takes in, AS KEPT
    /// — the caller's [`Inputs::supersede`] with each daughter an active
    /// claim of the person's own already names dropped, the skip the board's
    /// plan decides read off the board at the build (`in_claims` at each)
    /// and again at the one re-sign, so the frame's list and the signed
    /// groups agree with the board's composition. Each is one group of the
    /// signed body homed in the trunk, `from` the daughter, `to` the member
    /// by tag (the merge bridge lane).
    pub supersede: Vec<Address>,
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
        let supersede: Vec<String> = self.supersede.iter().map(ToString::to_string).collect();
        let (doc, account, base, draft) = (self.doc.as_ref().map(ToString::to_string), self.mint.as_ref().map(ToString::to_string), self.base.as_ref().map(|(m, e)| (m.to_string(), *e)), self.draft.as_ref().map(ToString::to_string));
        let also: Vec<String> = self.also.iter().map(ToString::to_string).collect();
        let also_places: Vec<(String, Vec<Value>)> = self.also_places.iter().map(|a| (a.draft.to_string(), a.places.iter().map(|p| p.map_or(Value::Null, frames::place)).collect())).collect();
        let also_entries: Vec<AlsoPlacesFrame<'_>> = also_places.iter().map(|(draft, places)| AlsoPlacesFrame { draft, places }).collect();
        frames::publication(&PublishFrame {
            doc: doc.as_deref(),
            account: account.as_deref(),
            mint: self.mint.is_some(),
            claim: self.claim,
            base: base.as_ref().map(|(m, e)| (m.as_str(), *e)),
            draft: draft.as_deref(),
            also: &also.iter().map(String::as_str).collect::<Vec<_>>(),
            runs: &runs,
            places: &places,
            also_places: &also_entries,
            links: &links,
            retract: &retract.iter().map(String::as_str).collect::<Vec<_>>(),
            read_with: &read_with.iter().map(String::as_str).collect::<Vec<_>>(),
            supersede: &supersede.iter().map(String::as_str).collect::<Vec<_>>(),
            attest,
            id: Some(&self.id),
        })
    }

    /// Returns the deposit rows in the signed order: the member's, then a
    /// minted edition's, then every other home's in address order; inside a
    /// home the edition claim, the copies, the retractions, the read-withs,
    /// the supersession claims, each in declared order. A supersession
    /// claim's group is the trunk's address, the supersedes class's unit
    /// span, `from` the daughter's unit span and `to` the tag `member` — the
    /// one address of the claim no signer holds before the commit — as the
    /// daemon's composer spells it from its plan (wire.md §The publish shot
    /// and head-float, the deposits); at the mint form, where no trunk
    /// stands, the row is homed under the edition's tag so the frame signs
    /// at all — the board refuses every such entry at the plan.
    pub(crate) fn rows(&self) -> Vec<OwnedRow> {
        let mut homes: BTreeMap<OwnedHome, Vec<OwnedRow>> = BTreeMap::new();
        let mut push = |home: OwnedHome, kind: DepositKind, ty: OwnedSlot, from: OwnedSlot, to: OwnedSlot| {
            homes.entry(home.clone()).or_default().push(OwnedRow { home, kind, ty, from, to });
        };
        if let (true, Some(draft)) = (self.claim, &self.draft) {
            // The edition the claim is homed in: the one the commit mints,
            // by tag, at the mint form; the trunk `doc` names, by address,
            // at the document form — whether that edition holds no member
            // yet is the board's to judge, never this builder's.
            let (home, from) = match &self.mint {
                Some(_) => (OwnedHome::Edition, OwnedSlot::Stored(vec![OwnedElement::Edition])),
                None => {
                    let edition = address(&super::trunk_of(&self.term().to_string()).unwrap_or_default());
                    (OwnedHome::Addr(edition.clone()), OwnedSlot::unit(&edition))
                }
            };
            push(home, DepositKind::EditionClaim, OwnedSlot::unit(&address(T_EDITION)), from, OwnedSlot::unit(draft));
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
        for daughter in &self.supersede {
            let home = match &self.doc {
                Some(trunk) => OwnedHome::Addr(trunk.clone()),
                None => OwnedHome::Edition,
            };
            push(home, DepositKind::Supersede, OwnedSlot::unit(&address(T_SUPERSEDES)), OwnedSlot::unit(daughter), OwnedSlot::Stored(vec![OwnedElement::Member]));
        }
        homes.into_values().flatten().collect()
    }

    /// Returns the `links` entries' shapes for the price.
    fn entry_shapes(&self) -> Vec<EntryShape> {
        self.entries.iter().map(|e| EntryShape { from: e.from.shape(), to: e.to.shape(), ty: e.ty.shape(), old: e.old.is_some() }).collect()
    }

    /// Prices the request as it stands, with the caller's home count, the
    /// rendering draft's content run count and each `also` draft's in
    /// `also`'s order (`Enumeration::also_run_counts`): the price counts a
    /// draft's runs only where its list places it.
    pub fn priced(&self, homes: usize, draft_runs: usize, also_runs: &[usize]) -> Price {
        let entries = self.entry_shapes();
        let term = self.term().clone();
        // The named drafts — the rendering draft, then each of `also` — whose
        // runs are re-inserted and priced as values; none at a bare shot.
        let drafts: Vec<Address> = self.draft.iter().chain(&self.also).cloned().collect();
        price::price(&Shape {
            runs: &self.runs,
            drafts: &drafts,
            draft: self.draft.as_ref(),
            term: &term,
            mint: self.mint.is_some(),
            claim: self.claim,
            places: &self.places,
            also_places: &self.also_places,
            also_runs,
            stray_records: &self.stray_records,
            entries: &entries,
            retract: self.retract.len(),
            read_with: self.read_with.len(),
            body_bytes: self.body().as_bytes().len(),
            homes,
            draft_runs,
        })
    }

    /// Re-composes the request without the entries at `retract_skipped`,
    /// `read_with_skipped` and `supersede_skipped`, under a FRESH `id` — the
    /// one re-sign at `attestation_invalid:signature` for a deposit the
    /// transaction skipped.
    pub fn without(&mut self, retract_skipped: &[usize], read_with_skipped: &[usize], supersede_skipped: &[usize]) {
        let retract = std::mem::take(&mut self.retract);
        self.retract = retract.into_iter().enumerate().filter(|(i, _)| !retract_skipped.contains(i)).map(|(_, m)| m).collect();
        let read_with = std::mem::take(&mut self.read_with);
        self.read_with = read_with.into_iter().enumerate().filter(|(i, _)| !read_with_skipped.contains(i)).map(|(_, s)| s).collect();
        let supersede = std::mem::take(&mut self.supersede);
        self.supersede = supersede.into_iter().enumerate().filter(|(i, _)| !supersede_skipped.contains(i)).map(|(_, d)| d).collect();
        self.id = fresh_id();
    }
}

/// Returns whether an active claim of the person's own already names
/// `daughter` as its `old` — the skip the board's plan decides for a
/// `supersede` entry, read as the board reads it: `in_claims{y: the
/// daughter, view: active}` through `door`, each claim kept where its home
/// is the person's ([`own_claim_names`]).
///
/// # Errors
///
/// The read's faults.
pub(crate) fn claimed_by_own(door: &Door<'_>, p: &Publisher<'_>, daughter: &Address) -> Result<bool, Fault> {
    let daughter = daughter.to_string();
    let v = door.answered(&daughter, &frames::in_claims(&daughter))?;
    Ok(own_claim_names(&answers::claims(&v), p.account))
}

/// Returns `daughters` with each one an active claim of the person's own
/// already names dropped — THE SKIP, read before signing ([`claimed_by_own`]
/// at each), so the request's list and its signed groups agree with the
/// board's composition.
///
/// # Errors
///
/// The reads' faults.
fn kept_daughters(door: &Door<'_>, p: &Publisher<'_>, daughters: &[Address]) -> Result<Vec<Address>, Fault> {
    let mut kept = Vec::with_capacity(daughters.len());
    for daughter in daughters {
        if !claimed_by_own(door, p, daughter)? {
            kept.push(daughter.clone());
        }
    }
    Ok(kept)
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
    pub(crate) fn borrow(&self) -> DepositRow<'_> {
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
/// The windows and their counterparts are the panel's, taken as given
/// (`panel::windows`): nothing is read of an origin here.
///
/// # Errors
///
/// The reads' faults: the twin pre-check, the values, the base's image.
pub fn build(p: &Publisher<'_>, inputs: &Inputs, e: &Enumeration, panel: &Panel, confirmed: &Confirmed) -> Result<Built, Fault> {
    let door = Door::new(p.board, p.token);
    build_with(&door, p, inputs, e, panel, confirmed)
}

/// Builds the request through `door`.
pub(crate) fn build_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, e: &Enumeration, panel: &Panel, confirmed: &Confirmed) -> Result<Built, Fault> {
    let trunk = inputs.doc.clone();
    // The runs as placed, each with its kept place and its place in the draft.
    let mut runs: Vec<Run> = Vec::new();
    let mut places: Vec<Option<u64>> = Vec::new();
    let mut draft_places: Vec<Option<u64>> = Vec::new();
    let mut unanswered = Vec::new();
    let mut publish_first = Vec::new();
    let mut counterparts: Vec<Counterpart> = Vec::new();
    for (i, run) in inputs.selection.iter().enumerate() {
        // The run as placed, cut around its merge records, which no
        // publication carries: no run and no kept place for one. A run that
        // carries nothing — the draft no longer arranges it, or it holds
        // merge records alone — is sent nowhere and asked nothing, so a
        // window the draft has deleted owes no answer (PUB-3.108).
        let pieces = e.pieces(i, run);
        if pieces.is_empty() {
            continue;
        }
        // A named draft's run — the rendering draft's or an `also` draft's —
        // is the document's own words, re-minted, and the rendering draft's
        // kept place is sent for EVERY such run: its own position of the
        // run, which the commit re-windows it at whichever named draft's
        // identity the run was (skep #739; an `also` draft's own place for
        // its run rides that draft's `also_places` entry, composed below).
        // The trunk's own words, held by reference, take no place.
        let native = inputs.is_named_draft(&run.origin);
        let own = trunk.as_ref() == Some(&run.origin);
        if native || own {
            for (piece, ordinal) in pieces {
                runs.push(piece);
                places.push(native.then_some(ordinal));
                draft_places.push(Some(ordinal));
            }
            continue;
        }
        // A window. Onto the person's own unpublished origin — one the panel's
        // windows name — an answer is owed; the counterpart is the window's,
        // offered first where the panel read one.
        let window = panel.windows.iter().find(|w| w.run == i);
        let own_unpublished = window.is_some();
        let counterpart: Option<Counterpart> = window.and_then(|w| w.counterpart.clone());
        let answer = confirmed.answers.get(&i).copied();
        if let Some(c) = &counterpart {
            counterparts.push(c.clone());
        }
        match (own_unpublished, answer) {
            (_, Some(Answer::Drop)) => {}
            (_, Some(Answer::PublishFirst)) => publish_first.push(i),
            (_, Some(Answer::Counterpart)) if counterpart.is_some() => {
                // The part the record covers by reference to its published
                // words — in whichever document the record's `to` lies,
                // this request's or another's — WITH ITS KEPT PLACE, the
                // rendering draft's own V-position of the piece, so the
                // commit re-windows the draft there through the record (the
                // link-sets design §5.5, the counterpart first; its "KEPT
                // PLACE sent beside it as a stray's is"); the uncovered
                // remainder a window with none, in the piece's order. A
                // request whose only place is such a piece is NOT inert: the
                // healed window is a change to the draft.
                let c = counterpart.as_ref().expect("a counterpart");
                let origin = parse_address(&c.to.document().unwrap_or_default()).unwrap_or_else(|| run.origin.clone());
                for (piece, ordinal) in pieces {
                    let mut cursor = piece.i_start;
                    while cursor < piece.reach() {
                        let hi = c.from.reach().min(piece.reach());
                        let covered = c.from.first <= cursor && cursor < hi;
                        let end = if covered { hi } else if c.from.first > cursor && c.from.first < piece.reach() { c.from.first } else { piece.reach() };
                        let run_out = if covered { Run::new(origin.clone(), c.to.first + (cursor - c.from.first), end - cursor) } else { Run::new(piece.origin.clone(), cursor, end - cursor) };
                        let in_draft = ordinal + (cursor - piece.i_start);
                        runs.push(run_out);
                        places.push(covered.then_some(in_draft));
                        draft_places.push(Some(in_draft));
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

    // Each `also` draft's own kept places off its image, beside the rendering
    // draft's; then the twin pre-check: what each named draft's records
    // already name, by reference, every list carried beside the pieces.
    let also_places = also_places_of(e, &runs);
    let recomposed = twin_precheck_with(door, p, inputs, &runs, &places, &draft_places, &also_places)?;
    let (runs, places, draft_places, stray_records, also_places) = (recomposed.runs, recomposed.places, recomposed.draft_places, recomposed.stray_records, recomposed.also_places);
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
    let ctx = SpellContext { walk: RecordWalk::new(inputs, &records), runs: &runs };
    let mut add = |candidate: usize, home: EntryHome| {
        let c = &e.candidates[candidate];
        let ends = (spell_end(&c.value.from, &c.via, &ctx), spell_end(&c.value.to, &c.via, &ctx), spell_type(&c.value.ty));
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

    // The daughters, the skip read first: one an active claim of the
    // person's own already names is dropped, as the board's plan drops it.
    door.step("supersede");
    let supersede = kept_daughters(door, p, &inputs.supersede)?;

    // Inert where nothing changes against the base: a place in either list
    // — the rendering draft's, or an `also` draft's re-window alone — is a
    // change to that draft, and a daughter claimed is a change to the trunk.
    door.step("base");
    let fresh = runs.iter().any(|r| inputs.is_named_draft(&r.origin));
    let placed = places.iter().any(Option::is_some) || also_places.iter().any(AlsoPlaces::carries_a_place);
    if !fresh && entries.is_empty() && retract.is_empty() && read_with.is_empty() && supersede.is_empty() && inputs.mint.is_none() && !placed {
        if let Some((base, extent)) = &inputs.base {
            let image = door.image(&base.to_string(), 1, *extent)?;
            let same = image.len() == runs.len() && image.iter().zip(&runs).all(|(a, r)| a.prefix == r.chain() && a.first == r.i_start && a.width == r.width);
            if same {
                return Ok(Built::Inert(Inert::Unchanged));
            }
        }
    }

    // The body's pieces: the values of every copied run — a named draft's,
    // the trunk's own — read through the rendering draft, which arranges
    // them at their places; a window by address.
    door.step("values");
    let draft = inputs.draft.to_string();
    let mut pieces = Vec::with_capacity(runs.len());
    for (k, run) in runs.iter().enumerate() {
        let copied = inputs.is_named_draft(&run.origin) || trunk.as_ref() == Some(&run.origin);
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
        also: inputs.also.clone(),
        runs,
        places,
        also_places,
        stray_records,
        pieces,
        entries,
        retract,
        read_with,
        supersede,
        unspellable,
        counterparts,
        id: fresh_id(),
        count,
        price: Price { lists: [0; 5], body: 0, values: 0, reads: 0, bytes: 0, over: Vec::new() },
        as_of: door.as_of().max(e.as_of),
    };
    let homes = e.homes.len() + inputs.published.iter().filter(|s| !e.homes.iter().any(|(h, _)| h == *s)).count();
    request.price = request.priced(homes, e.image.len(), &e.also_run_counts());
    Ok(Built::Request(Box::new(request)))
}

/// Composes each `also` draft's own kept places over `runs`, off its image
/// (the wire's `also_places`; skep #739), in `also`'s order.
///
/// At a run of THAT draft's identity: the V-ordinal its image arranges the
/// run at, found as the rendering draft's places are (`place_selection`:
/// whole and in order, the k-th equal run the k-th occurrence); `None`
/// where its image does not arrange it whole — moved, split or deleted
/// since the panel, a place the client is not sure of, so the draft is left
/// as it stands at that run and the board's fence meets it at the draft's
/// own next shot. `None` at every other run — the rendering draft's own,
/// the trunk's, a window's, another `also` draft's — whose place is no
/// business of this draft's list; a stray of the draft's own (published
/// words it arranges that a record names) is not composed here, and heals
/// at its own shot. Where a draft arranges a run's identity twice, its image
/// answers each place and the k-th equal run in `runs` takes the k-th
/// (`place_selection`); a place no run in `runs` takes is left standing, as
/// a stray is.
pub(crate) fn also_places_of(e: &Enumeration, runs: &[Run]) -> Vec<AlsoPlaces> {
    e.also
        .iter()
        .map(|a| {
            let placed = place_selection(&a.image, runs);
            let places = runs
                .iter()
                .zip(&placed)
                .map(|(run, placement)| match placement {
                    Placement::Whole { ordinal } if run.origin == a.draft => Some(*ordinal),
                    _ => None,
                })
                .collect();
            AlsoPlaces { draft: a.draft.clone(), places }
        })
        .collect()
}

/// What spelling an end needs.
struct SpellContext<'a> {
    /// The walk through the records — the enumeration's and the twin
    /// pre-check's — that reads a candidate's ends as the filter reads them.
    walk: RecordWalk<'a>,
    runs: &'a [Run],
}

/// Spells one end of a candidate reached `via` from its stored slot.
///
/// The address form where every span is a unit span at a non-content
/// address. Otherwise each span is read in the pieces the walk through the
/// records reads it in (`RecordWalk`), in the stored order: a piece a
/// record maps is the published words it became, a piece of a named
/// draft's own words no record maps is this shot's new words where the
/// shot's runs hold them and is cut where they do not, and any other piece
/// is kept as stored. The end is the member-position form where a piece
/// lies on this shot's new words, every other piece then one the member
/// holds; else the I-span form over the pieces kept, or over the stored
/// spans as written where every piece was cut.
fn spell_end(slot: &[LinkSpan], via: &Via, ctx: &SpellContext<'_>) -> Result<End, Unspellable> {
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
    // The pieces the end sends, in the stored order, each with whether it
    // lies on this shot's new words.
    let mut sent: Vec<(ISpan, bool)> = Vec::new();
    for s in &spans {
        for piece in ctx.walk.pieces(s, via) {
            let p = piece.span;
            if piece.mapped || !ctx.walk.is_named_chain(&p.chain) {
                sent.push((p, false));
                continue;
            }
            // The shot's runs of the piece's own chain hold the named
            // draft's new words; the rest is left out and cut.
            let native_runs: Vec<&Run> = ctx.runs.iter().filter(|r| r.chain() == p.chain).collect();
            let mut cursor = p.first;
            while cursor < p.reach() {
                match native_runs.iter().find(|r| r.i_start <= cursor && cursor < r.reach()) {
                    Some(run) => {
                        let end = run.reach().min(p.reach());
                        sent.push((ISpan { chain: p.chain.clone(), first: cursor, width: end - cursor }, true));
                        cursor = end;
                    }
                    None => cursor = native_runs.iter().filter(|r| r.i_start > cursor).map(|r| r.i_start).min().unwrap_or(p.reach()).min(p.reach()),
                }
            }
        }
    }
    if sent.iter().any(|(_, new)| *new) {
        // Every other piece of the end must be one the member holds.
        if sent.iter().any(|(s, new)| !new && !s.within(ctx.runs)) {
            return Err(Unspellable::MixedForms);
        }
        let pieces: Vec<ISpan> = sent.into_iter().map(|(s, _)| s).collect();
        let canonical = canonical_member_spans(ctx.runs, &pieces).ok_or(Unspellable::MixedForms)?;
        return Ok(End::Member(canonical));
    }
    if sent.is_empty() {
        // Wholly on left-out words of the draft: decision 5's far end with
        // this draft as its document, written as it is.
        return Ok(End::Spans(spans));
    }
    Ok(End::Spans(sent.into_iter().map(|(s, _)| s).collect()))
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
