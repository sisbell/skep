//! THE DEPOSIT PLAN (the link-sets design §5.7): the request members a
//! publication carries beside its shot, the one function that validates
//! them in the design's order and returns the deposits the commit will stage
//! — read twice on one world, by the daemon's composer to build the body
//! the signature is checked against and by the composite to stage exactly
//! that — and the one function the member-position end form is spelled and
//! stored through.
//!
//! **The members** (THE REQUEST): [`PublishTarget`], where the publication
//! lands — a published document of the caller's, or an edition minted under
//! an account in the commit (`mint: true` with `account`, `doc` absent, and
//! `claim: true` beside it where the edition claim is written);
//! [`PublishDeposits`], the three lists — `links`, one [`LinkEntry`] per
//! accepted link, `retract`, the held removals' marks by address, and
//! `read_with`, the sets the document is newly read with. An entry names an
//! address the commit mints by TAG ([`NamedAddress`]): the member by
//! `member`, the edition by `edition`. An end is one of three forms
//! ([`EndArg`]): the address form, the I-span form, or THE MEMBER-POSITION
//! FORM — spans of the member's positions inside `[1, placed]`
//! ([`MemberSpan`]), the form an end on this shot's own new words takes,
//! spelled in the signed row as the request spells it and stored as the
//! I-spans the commit mints.
//!
//! **The plan** ([`plan_deposits`]) runs THE VALIDATION's (3), (4) and (5)
//! over a world — never a staging — and answers a [`DepositPlan`]: the
//! deposits per home in THE SIGNED ENTRY's order (the member first, then a
//! minted edition, then every other home in address order; inside a home
//! the edition claim, then the copies, then the retractions, then the
//! read-withs, each list in declared order), each skip decided — a
//! retraction whose target is already retracted, a read-with that stands in
//! a published home of the caller's — and each copy's private claim beside
//! it, outside the signed set. The first fault in list order refuses the
//! whole ([`PlanFault`]), naming the entry.
//!
//! **One world, one plan.** Under the daemon's serialization lock the
//! snapshot the admission reads IS the base the transaction opens on (the
//! survey's C8), and the plan is a pure function of that world and the
//! request, so the body the composer signs against and the deposits the
//! composite stages agree by construction; `tests/it/publication.rs` pins
//! the purity.

use std::collections::{BTreeMap, BTreeSet};

use skep_address::{document_of, is_prefix, subtree_of, validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{trunk_of, Caller, HasM5, Pairing, Run, Shot};
use skep_namespace::M3State;
use std::sync::LazyLock;

use super::super::makelink::SlotArg;
use super::super::{is_correspondence_class, is_replaces_class};
use crate::budget::MAX_SLOT_SPANS;
use crate::class::coverage_class;
use crate::endset::{enc, Endset, Link};
use crate::registry::{registry, ShippedType};
use crate::error::{OldCause, PlanFault, ReadWithCause, RetractCause};
use crate::state::{LinkState, View, FROM, TO, TYPE};
use crate::LinkWorld;

// ───────────────────────────── the members ─────────────────────────────

/// Where a publication lands.
///
/// The document form is today's: `doc`, a published document of the
/// caller's (a member names its document). The mint form (the design's (iv);
/// sweep 6 W16) names the PARENT ACCOUNT alone — `doc` absent — the commit
/// minting the edition under it and its first member beside it, `claim`
/// saying whether the commit writes the edition claim homed in that
/// edition. An enum and not an `Option<doc>` beside a flag: the two forms
/// are two values with their own readers — the trunk of `doc` at the one,
/// the account at the other — and every exhaustive match decides its mint
/// arm, where an option would let a request carry both or neither and leave
/// each reader to re-derive the form from two fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PublishTarget {
    /// A published document of the caller's: the shot appends its chain.
    Document(Address),
    /// An edition minted in the commit under `account`, the shot its birth
    /// version; `claim` writes the R20 edition claim in it.
    Mint {
        /// The parent account the edition is minted under.
        account: Address,
        /// Whether the commit writes the edition claim, `to` the staging
        /// draft.
        claim: bool,
    },
}

impl PublishTarget {
    /// Returns the document the shot appends, at the document form.
    pub fn document(&self) -> Option<&Address> {
        match self {
            PublishTarget::Document(doc) => Some(doc),
            PublishTarget::Mint { .. } => None,
        }
    }

    /// Returns the parent account, at the mint form.
    pub fn account(&self) -> Option<&Address> {
        match self {
            PublishTarget::Document(_) => None,
            PublishTarget::Mint { account, .. } => Some(account),
        }
    }

    /// Returns whether the commit mints an edition.
    pub fn mints(&self) -> bool {
        matches!(self, PublishTarget::Mint { .. })
    }

    /// Returns whether the commit writes the edition claim.
    pub fn claims(&self) -> bool {
        matches!(self, PublishTarget::Mint { claim: true, .. })
    }

    /// Returns the frame's `doc` term: the document's trunk, or the account.
    ///
    /// It is the address the shot's address form classes runs against too —
    /// at the mint form no run is the edition's own, the edition having no
    /// I-space before the commit, so an account there classes every run of
    /// another document as a window, as the commit will keep it.
    pub fn term(&self) -> Address {
        match self {
            PublishTarget::Document(doc) => trunk_of(doc),
            PublishTarget::Mint { account, .. } => account.clone(),
        }
    }
}

/// An address inside a publication's entries, or a tag standing for one the
/// commit mints.
///
/// The tags are the strings `member` and `edition` where an address is
/// expected — a `home`, an address-form end, a read-with's `from` at a mint
/// — each resolved by the daemon to the address it mints, the verifier
/// deriving both from the committed row (the design's M2: never a predicted
/// address). Ordered as the signed entry orders homes: the member first,
/// then the edition, then every address in address order.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NamedAddress {
    /// The member the commit mints: the tag `member`.
    Member,
    /// The edition the commit mints: the tag `edition`.
    Edition,
    /// An address standing before the commit.
    Address(Address),
}

/// One span of the member's positions: the member-position end form.
///
/// `ordinal` is the first position, 1-based, and `width` the count, at
/// least one, the span inside `[1, placed]`. Canonical by THE LOWEST MEMBER
/// POSITIONS holding each value (the design's W3 (a)) — [`member_end`]'s
/// rule — so one body stands against one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemberSpan {
    /// The first position, 1-based.
    pub ordinal: u64,
    /// The count of positions, at least one.
    pub width: u64,
}

/// One end of a `links` entry, in one of the three forms a publication
/// admits.
///
/// A V-spec is admitted in no entry (the survey's ruling 7): the ceremony
/// sends I-spans, and the wire's codec refuses the form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndArg {
    /// The address form, the tags admitted among the addresses.
    Addrs(Vec<NamedAddress>),
    /// The I-span form: content I-spans recorded verbatim.
    Spans(Vec<Span>),
    /// The member-position form.
    Member(Vec<MemberSpan>),
}

/// One `links` entry: an accepted link's public copy, and the original it
/// stands for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkEntry {
    /// The copy's home: the member by tag, or a published document of the
    /// caller's by address.
    pub home: NamedAddress,
    /// The copy's `from`.
    pub from: EndArg,
    /// The copy's `to`.
    pub to: EndArg,
    /// The copy's type: the address form (no tag), or the I-span form.
    pub ty: EndArg,
    /// The original's address, where a private original stands behind the
    /// copy — in v1 on every entry; the daemon deposits the claim in its
    /// home.
    pub old: Option<Address>,
}

/// The three optional lists a publication carries beside its shot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PublishDeposits {
    /// One entry per accepted link.
    pub links: Vec<LinkEntry>,
    /// The held removals' marks, by address.
    pub retract: Vec<Address>,
    /// The sets the document is newly read with, by address.
    pub read_with: Vec<Address>,
}

impl PublishDeposits {
    /// Returns whether the request carries none of the three.
    pub fn is_empty(&self) -> bool {
        self.links.is_empty() && self.retract.is_empty() && self.read_with.is_empty()
    }
}

// ─────────────────────────── the commons values ───────────────────────────

/// Returns the read-with type — the commons value `1.1.0.1.0.1.0.3.71`.
///
/// It is the type of the read-with a publication writes through its one
/// door, `read_with` (the design's (vii)), and the type a `links` entry may
/// not carry. M7's own spelling, as [`super::super::correspondence_type`] is;
/// the engine's ledger pins the same address and its tests hold the two
/// equal.
pub fn read_with_type() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons(&[71]));
    &ADDR
}

/// Returns the edition-claim type — the commons value `1.1.0.1.0.1.0.3.14`
/// (R20).
///
/// It is the type of the claim a minting publication writes homed in the
/// edition, `to` the origin draft, the shape the class's reader
/// `edition_claims` reads. M7's own spelling, as [`read_with_type`] is.
pub fn edition_type() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons(&[14]));
    &ADDR
}

/// Returns the commons type at `tail` under `1.1.0.1.0.1.0.3`.
fn commons(tail: &[u32]) -> Address {
    validate(
        Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3].into_iter().chain(tail.iter().copied()).map(Nat::from))
            .expect("the commons type components are nonempty"),
    )
    .expect("a subspace-3 element of the ghost document is T4-valid by construction")
}

/// Returns whether the type slot `ty` names the read-with type: some
/// denoted address lies under `3.71` by prefix.
///
/// The test every reader of the read-with applies — the design's "exact"
/// stored-type test, over every address the slot denotes, so a slot naming
/// the type beside another is a read-with to this test as it is to a
/// `find_links_ftt` over the type.
pub fn names_read_with(ty: &Endset) -> bool {
    ty.addrs().any(|t| is_prefix(read_with_type().tumbler(), t))
}

// ───────────────────────────── the plan ─────────────────────────────

/// One public deposit's end as the plan holds it: the stored endset where
/// the request names it, the tags where it names an address the commit
/// mints, the member's positions where it names the shot's own words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedEnd {
    /// The endset as the store will hold it.
    Stored(Endset),
    /// The address form with a tag among its elements: resolved to unit
    /// spans at the commit, the tags to the addresses it mints.
    Named(Vec<NamedAddress>),
    /// The member-position form, canonical: resolved to the I-spans the
    /// member holds at those positions, once the member is minted.
    Member(Vec<MemberSpan>),
}

/// A copy's private claim: `old` superseded by the copy, homed in `old`'s
/// home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedClaim {
    /// The original.
    pub old: Address,
    /// The original's home, a private document of the caller's.
    pub home: Address,
}

/// One deposit the commit stages, as planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedDeposit {
    /// The edition claim: typed the edition class, `from` the edition by
    /// tag, `to` the origin draft.
    EditionClaim {
        /// The staging draft `D` the claim names.
        origin: Address,
    },
    /// A `links` entry's public copy, its private claim beside it.
    Copy {
        /// The entry's position in `links`.
        index: usize,
        /// The type slot as the store will hold it.
        ty: Endset,
        /// The `from` end.
        from: PlannedEnd,
        /// The `to` end.
        to: PlannedEnd,
        /// The claim deposited in `old`'s home, where the entry names one.
        claim: Option<PlannedClaim>,
    },
    /// A `retract` entry's retraction tuple at its target's home.
    Retraction {
        /// The entry's position in `retract`.
        index: usize,
        /// The link retracted.
        target: Address,
    },
    /// A `read_with` entry's read-with, homed in the set.
    ReadWith {
        /// The entry's position in `read_with`.
        index: usize,
        /// The set `S`.
        set: Address,
    },
}

/// One home's deposits, in the order the daemon mints them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedHome {
    /// The home, by tag or address.
    pub home: NamedAddress,
    /// Its deposits: the edition claim, the copies, the retractions, the
    /// read-withs, each list in declared order.
    pub deposits: Vec<PlannedDeposit>,
}

/// The deposits a publication stages, per home in the signed entry's order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DepositPlan {
    /// The homes written, the member first, then a minted edition, then
    /// every other in address order; a home with no deposit is absent.
    pub homes: Vec<PlannedHome>,
}

impl DepositPlan {
    /// Returns whether the plan stages nothing.
    pub fn is_empty(&self) -> bool {
        self.homes.is_empty()
    }
}

/// Plans a publication's deposits over `world`: THE VALIDATION's (3), (4)
/// and (5) in the design's order, and the deposits per home in the signed
/// entry's order.
///
/// `caller` is the writer, whose homes the reads range over; `target` the
/// request's form; `shot` the request's shot, read for its draft and for
/// the member's positions a member-position end names; `deposits` the three
/// lists. The reads are the design's in-lock reads, composed from M7's own
/// primitives (the survey's C16): (3)'s claims naming `old` over the
/// caller's homes alone — `homes_under` of the caller's account, then one
/// typed stab per home — never another hand's; `old`'s residence, activity
/// and ownership off the store and the registry; (5)'s presence over the
/// caller's PUBLISHED homes, each row kept where its stored `from` is the
/// edition's own unit span and its stored `to` the set's, exactly.
///
/// In order, per entry, the first fault refusing the whole:
///
/// 3. each `links` entry: its home registered, then the caller's (ω), then
///    the tag `member` or a published trunk document; the slot forms — the
///    I-span form's content clause by slot, the budget, an empty type —
///    and the class fences on `ty`; a type naming the read-with refused;
///    then `old` where present — resident, private, active and owned, not
///    superseded by an active claim of the caller's naming a public
///    successor homed in a published document of the caller's whose ends
///    cover every published content span of this entry (a span on the
///    shot's own new words is covered by nothing, so such an entry is never
///    superseded), nor, where `old` is itself a successor, its original so
///    superseded; a second entry naming one `old` refused at the second;
/// 4. each `retract` entry: the target resident, the caller's own, homed in
///    a published document of the caller's; already retracted → SKIPPED;
/// 5. each `read_with` entry: `S` a registered trunk document, the
///    caller's, published; a read-with from the edition to `S` standing in
///    a published home of the caller's → SKIPPED, the maker's published
///    homes only; at the mint form the edition is the tag, no presence can
///    stand, and the read-with is written.
///
/// The edition claim, where the target claims, leads the edition's home,
/// `to` the shot's draft.
///
/// # Errors
///
/// [`PlanFault`], the first in the order above.
pub fn plan_deposits<W: LinkWorld + HasM5>(
    world: &W,
    caller: Caller,
    target: &PublishTarget,
    shot: &Shot,
    deposits: &PublishDeposits,
) -> Result<DepositPlan, PlanFault> {
    let (m3, links) = (world.m3(), world.links());
    let mut homes: BTreeMap<NamedAddress, Vec<PlannedDeposit>> = BTreeMap::new();
    // The edition claim, first of the edition's deposits.
    if target.claims() {
        let origin = shot.draft_document().ok_or(PlanFault::ClaimWithoutDraft)?;
        homes.entry(NamedAddress::Edition).or_default().push(PlannedDeposit::EditionClaim { origin });
    }
    let image = request_image(shot);
    let mut originals: BTreeSet<&Address> = BTreeSet::new();
    // (3) each link.
    for (index, entry) in deposits.links.iter().enumerate() {
        match &entry.home {
            NamedAddress::Member => {}
            NamedAddress::Edition => return Err(PlanFault::LinkHome { index }),
            NamedAddress::Address(home) => {
                if !m3.is_registered_document(home) {
                    return Err(PlanFault::LinkHome { index });
                }
                if !caller.is_owner(m3, home) {
                    return Err(PlanFault::NotOwner(home.clone()));
                }
                if trunk_of(home) != *home || !m3.published(home) {
                    return Err(PlanFault::LinkHome { index });
                }
            }
        }
        let ty = planned_type(&entry.ty, index)?;
        let from = planned_end(&entry.from, &image, index, FROM)?;
        let to = planned_end(&entry.to, &image, index, TO)?;
        if names_read_with(&ty) {
            return Err(PlanFault::ReadWithInLinks { index });
        }
        let claim = match &entry.old {
            None => None,
            Some(old) => {
                if !originals.insert(old) {
                    return Err(PlanFault::DuplicateOriginal { index });
                }
                let spans = published_spans(&from, &to, &image, shot.draft_document().as_ref());
                let home = check_old(world, caller, old, &spans)
                    .map_err(|cause| PlanFault::Old { index, cause })?;
                Some(PlannedClaim { old: old.clone(), home })
            }
        };
        homes
            .entry(entry.home.clone())
            .or_default()
            .push(PlannedDeposit::Copy { index, ty, from, to, claim });
    }
    // (4) each retraction.
    for (index, target_link) in deposits.retract.iter().enumerate() {
        let Some(home) = check_retract(m3, links, caller, target_link)
            .map_err(|cause| PlanFault::Retract { index, cause })?
        else {
            continue; // already retracted: the entry commits nothing
        };
        homes
            .entry(NamedAddress::Address(home))
            .or_default()
            .push(PlannedDeposit::Retraction { index, target: target_link.clone() });
    }
    // (5) each read-with.
    let edition = target.document().map(trunk_of);
    for (index, set) in deposits.read_with.iter().enumerate() {
        check_read_with(m3, caller, set).map_err(|cause| PlanFault::ReadWith { index, cause })?;
        if let Some(edition) = &edition {
            if read_with_stands(world, caller, edition, set) {
                continue; // present in a published home of the maker's
            }
        }
        homes
            .entry(NamedAddress::Address(set.clone()))
            .or_default()
            .push(PlannedDeposit::ReadWith { index, set: set.clone() });
    }
    Ok(DepositPlan {
        homes: homes.into_iter().map(|(home, deposits)| PlannedHome { home, deposits }).collect(),
    })
}

/// Returns a `links` entry's type slot as the store will hold it, under the
/// slot forms' checks and the class fences.
///
/// # Errors
///
/// `NotContentSpan` for an I-span that is no content I-span, `SlotTooLarge`
/// past the budget, `EmptyType` for an empty slot, then the four fences;
/// `MemberSpan` for the member-position form, which no type slot takes.
fn planned_type(ty: &EndArg, index: usize) -> Result<Endset, PlanFault> {
    let endset = match ty {
        EndArg::Addrs(named) => {
            let mut addrs = Vec::with_capacity(named.len());
            for element in named {
                match element {
                    NamedAddress::Address(a) => addrs.push(a),
                    // A type slot names a type: the tags stand for documents
                    // the commit mints, which no type slot is — the codec's
                    // refusal, a backstop here.
                    NamedAddress::Member | NamedAddress::Edition => {
                        return Err(PlanFault::MemberSpan { index })
                    }
                }
            }
            if addrs.len() > MAX_SLOT_SPANS {
                return Err(PlanFault::SlotTooLarge { index });
            }
            enc(addrs)
        }
        EndArg::Spans(spans) => stored_spans(spans, index, TYPE)?,
        EndArg::Member(_) => return Err(PlanFault::MemberSpan { index }),
    };
    if endset.is_empty() {
        return Err(PlanFault::EmptyType { index });
    }
    let class = coverage_class(&endset);
    if class == *registry().shipped_class(ShippedType::Retraction) {
        return Err(PlanFault::RetractionClass { index });
    }
    if class == *registry().shipped_class(ShippedType::Supersedes) {
        return Err(PlanFault::SupersessionClass { index });
    }
    if is_replaces_class(&endset) {
        return Err(PlanFault::ReplacesClass { index });
    }
    if is_correspondence_class(&endset) {
        return Err(PlanFault::CorrespondenceClass { index });
    }
    Ok(endset)
}

/// Returns an I-span slot as stored, under the content clause and the budget.
fn stored_spans(spans: &[Span], index: usize, slot: usize) -> Result<Endset, PlanFault> {
    if SlotArg::ill_formed_span(spans).is_some() {
        return Err(PlanFault::NotContentSpan { index, slot });
    }
    if spans.len() > MAX_SLOT_SPANS {
        return Err(PlanFault::SlotTooLarge { index });
    }
    Ok(Endset::from_spans(spans.iter().cloned()))
}

/// Returns a `links` entry's `from` or `to` as the plan holds it.
///
/// The address form with no tag is stored outright, `enc`'s unit spans; with
/// a tag it stays named, resolved at the commit; the I-span form is stored
/// under the content clause; the member-position form is held to its
/// canonical spelling ([`member_end`] over the request's image) and kept as
/// positions, resolved once the member is minted.
fn planned_end(end: &EndArg, image: &[Run], index: usize, slot: usize) -> Result<PlannedEnd, PlanFault> {
    Ok(match end {
        EndArg::Addrs(named) => {
            if named.len() > MAX_SLOT_SPANS {
                return Err(PlanFault::SlotTooLarge { index });
            }
            if named.iter().all(|n| matches!(n, NamedAddress::Address(_))) {
                PlannedEnd::Stored(enc(named.iter().filter_map(|n| match n {
                    NamedAddress::Address(a) => Some(a),
                    NamedAddress::Member | NamedAddress::Edition => None,
                })))
            } else {
                PlannedEnd::Named(named.clone())
            }
        }
        EndArg::Spans(spans) => PlannedEnd::Stored(stored_spans(spans, index, slot)?),
        EndArg::Member(spans) => {
            if spans.len() > MAX_SLOT_SPANS {
                return Err(PlanFault::SlotTooLarge { index });
            }
            let end = member_end(image, spans).ok_or(PlanFault::MemberSpan { index })?;
            if end.canonical != *spans {
                return Err(PlanFault::MemberSpan { index });
            }
            PlannedEnd::Member(spans.clone())
        }
    })
}

/// Returns the content spans of an entry's two ends that lie on published
/// identity — the spans a standing successor could cover.
///
/// An I-span end's spans as given, a draft's own left out; a
/// member-position end's spans at positions the shot places by reference,
/// resolved through the request's image, where a span at a draft-native
/// position — the shot's own new words, fresh at the commit — is left out,
/// nothing standing before the commit could cover it (the request's image
/// maps such a position to the draft's own address, which names the draft).
/// An address-form end names no content span.
fn published_spans(from: &PlannedEnd, to: &PlannedEnd, image: &[Run], draft: Option<&Address>) -> Vec<Span> {
    let of_draft = |s: &Span| -> bool {
        draft.is_some()
            && validate(s.start().clone()).ok().and_then(|a| document_of(&a)).map(|d| trunk_of(&d)).as_ref() == draft
    };
    let mut out = Vec::new();
    for end in [from, to] {
        match end {
            PlannedEnd::Stored(endset) => {
                out.extend(endset.spans().filter(|s| !is_unit_depth(s) && !of_draft(s)).cloned());
            }
            PlannedEnd::Named(_) => {}
            PlannedEnd::Member(spans) => {
                if let Some(end) = member_end(image, spans) {
                    out.extend(end.stored.spans().filter(|s| !of_draft(s)).cloned());
                }
            }
        }
    }
    out
}

/// Returns whether `s` is a unit-depth span: an address's own subtree span.
fn is_unit_depth(s: &Span) -> bool {
    *s == subtree_of(s.start())
}

/// Checks a `links` entry's `old` (THE VALIDATION's (3)): the panel filter's
/// rule, read at the commit's position.
///
/// Answers `old`'s home, the claim's. `spans` are the entry's published
/// content spans ([`published_spans`]).
fn check_old<W: LinkWorld + HasM5>(
    world: &W,
    caller: Caller,
    old: &Address,
    spans: &[Span],
) -> Result<Address, OldCause> {
    let (m3, links) = (world.m3(), world.links());
    if links.readlink(old).is_none() {
        return Err(OldCause::Absent);
    }
    let home = document_of(old).ok_or(OldCause::Absent)?;
    if !caller.is_owner(m3, old) {
        return Err(OldCause::NotOwner);
    }
    if m3.published(&home) {
        return Err(OldCause::Public);
    }
    if !links.is_active(old) {
        return Err(OldCause::Retracted);
    }
    let own_homes = own_homes(m3, links, caller);
    if superseded_by_own_claim(m3, links, caller, &own_homes, old, spans) {
        return Err(OldCause::Superseded);
    }
    // Where `old` is itself a successor — a revision of an original — its
    // own original not superseded by an accept's claim of the caller's.
    for original in originals_of(links, &own_homes, old) {
        if superseded_by_own_claim(m3, links, caller, &own_homes, &original, spans) {
            return Err(OldCause::Superseded);
        }
    }
    Ok(home)
}

/// Returns the homes under the caller's account holding links, the caller's
/// own: `homes_under` of the account, each kept where ω answers the caller.
fn own_homes(m3: &M3State, links: &LinkState, caller: Caller) -> Vec<Address> {
    let Caller::Principal(p) = caller else { return Vec::new() };
    let Some(account) = m3.principal_prefix(p) else { return Vec::new() };
    links
        .homes_under(&enc([account]))
        .into_iter()
        .filter(|home| caller.is_owner(m3, home))
        .collect()
}

/// Returns whether an active claim of the caller's supersedes `y` by a
/// public successor covering `spans`.
///
/// Over the caller's homes alone (`homes`): one typed stab per home of the
/// supersession class at `FROM` over `y`'s unit span, each claim kept where
/// its `from` denotes `y` itself; its `new` a resident link homed in a
/// published document of the caller's; and `new`'s content ends covering
/// every span of `spans` — none where `spans` is empty, an entry on the
/// shot's own words being covered by nothing. No liveness of `new` is asked
/// (§5.1's keys (i) and (iii)).
fn superseded_by_own_claim(
    m3: &M3State,
    links: &LinkState,
    caller: Caller,
    homes: &[Address],
    y: &Address,
    spans: &[Span],
) -> bool {
    if spans.is_empty() {
        return false;
    }
    let sup = registry().shipped_class(ShippedType::Supersedes);
    let probe = subtree_of(y.tumbler());
    for home in homes {
        for claim in links.stab_typed_in(sup, home, FROM, [&probe], View::Active) {
            if claim.from.single_denoted() != Some(y.tumbler()) {
                continue;
            }
            let Some(new) = claim.to.single_denoted().and_then(|t| validate(t.clone()).ok()) else {
                continue;
            };
            let Some(new_home) = document_of(&new) else { continue };
            if !(m3.is_registered_document(&new_home) && m3.published(&new_home) && caller.is_owner(m3, &new_home)) {
                continue;
            }
            let Some(successor) = links.readlink(&new) else { continue };
            if covers_all(successor, spans) {
                return true;
            }
        }
    }
    false
}

/// Returns the originals `y` is a successor of, by the claims of the
/// caller's own homes naming `y` as `new`.
fn originals_of(links: &LinkState, homes: &[Address], y: &Address) -> Vec<Address> {
    let sup = registry().shipped_class(ShippedType::Supersedes);
    let probe = subtree_of(y.tumbler());
    let mut out = Vec::new();
    for home in homes {
        for claim in links.stab_typed_in(sup, home, TO, [&probe], View::Active) {
            if claim.to.single_denoted() != Some(y.tumbler()) {
                continue;
            }
            if let Some(old) = claim.from.single_denoted().and_then(|t| validate(t.clone()).ok()) {
                out.push(old);
            }
        }
    }
    out
}

/// Returns whether every span of `spans` lies within some content span of
/// `link`'s `from` or `to`.
fn covers_all(link: &Link, spans: &[Span]) -> bool {
    let ends: Vec<&Span> = link.from_slot().spans().chain(link.to_slot().spans()).collect();
    spans.iter().all(|s| {
        ends.iter().any(|e| {
            e.start().len() == s.start().len() && *e.start() <= *s.start() && s.reach() <= e.reach()
        })
    })
}

/// Checks a `retract` entry (THE VALIDATION's (4)); answers the target's
/// home, or `None` where the target is already retracted and the entry is
/// skipped.
fn check_retract(
    m3: &M3State,
    links: &LinkState,
    caller: Caller,
    target: &Address,
) -> Result<Option<Address>, RetractCause> {
    if links.readlink(target).is_none() {
        return Err(RetractCause::Absent);
    }
    if !caller.is_owner(m3, target) {
        return Err(RetractCause::NotOwner);
    }
    let home = document_of(target).ok_or(RetractCause::Absent)?;
    if !(m3.is_registered_document(&home) && m3.published(&home) && caller.is_owner(m3, &home)) {
        return Err(RetractCause::NotPublished);
    }
    Ok(links.is_active(target).then_some(home))
}

/// Checks a `read_with` entry's `S` (THE VALIDATION's (5)): a registered
/// trunk document, the caller's, published.
fn check_read_with(m3: &M3State, caller: Caller, set: &Address) -> Result<(), ReadWithCause> {
    if !m3.is_registered_document(set) {
        return Err(ReadWithCause::NotRegistered);
    }
    if trunk_of(set) != *set {
        return Err(ReadWithCause::NotDocument);
    }
    if !caller.is_owner(m3, set) {
        return Err(ReadWithCause::NotOwner);
    }
    if !m3.published(set) {
        return Err(ReadWithCause::NotPublished);
    }
    Ok(())
}

/// Returns whether an active read-with of the caller's from `edition` to
/// `set` stands in a PUBLISHED home the caller owns — the presence (5)
/// skips on: the maker's published homes only, each row kept where its
/// stored `from` is the edition's own unit span and its stored `to` the
/// set's, exactly, and its type names the read-with.
fn read_with_stands<W: LinkWorld + HasM5>(world: &W, caller: Caller, edition: &Address, set: &Address) -> bool {
    let (m3, links) = (world.m3(), world.links());
    own_homes(m3, links, caller)
        .into_iter()
        .filter(|home| m3.published(home))
        .any(|home| read_with_in(links, &home, edition, set))
}

/// Returns whether an active read-with from `edition` to `set` is homed in
/// `home`: a row whose stored `from` is the edition's own unit span and its
/// stored `to` the set's, exactly, and whose type names the read-with —
/// the test the presence (5) applies per home ([`plan_deposits`]), and the
/// test the daemon's feed row applies over the commit's two worlds to say
/// whether a `read_with` entry's deposit landed in its set or was skipped.
/// One index probe: the home's rows driven by `from` over the edition's
/// unit span, the two other slots as constraints.
///
/// # Panics
///
/// Panics where `home` is not a document address, as
/// [`LinkState::match_links_in`] does; a read-with's set is a registered
/// trunk document, and the caller's homes are documents.
pub fn read_with_in(links: &LinkState, home: &Address, edition: &Address, set: &Address) -> bool {
    let (from, to) = (enc([edition]), enc([set]));
    let rw = Endset::from_spans([subtree_of(read_with_type().tumbler())]);
    let from_span = subtree_of(edition.tumbler());
    links
        .match_links_in(home, (FROM, [&from_span]), &[(TO, &to), (TYPE, &rw)], View::Active)
        .into_iter()
        .filter_map(|hit| links.readlink(&hit))
        .any(|link| *link.from_slot() == from && *link.to_slot() == to && names_read_with(link.type_slot()))
}

// ──────────────────── the member-position end's one function ────────────────────

/// Returns the member's positions `[1, placed]` as the request's runs hold
/// them: each run in `runs`' order, a draft-native run by its draft
/// addresses — the identity keys the commit mints fresh identity for, one
/// per draft identity, so two positions hold one key here exactly where
/// they hold one fresh address in the member.
///
/// The image a signer composes a member-position end over before the
/// commit, and the one the plan canonicalizes it against.
pub fn request_image(shot: &Shot) -> Vec<Run> {
    shot.runs.iter().map(|r| r.run.clone()).collect()
}

/// Returns the member's positions `[1, placed]` as the minted member holds
/// them: each run in `runs`' order, a draft-native run replaced by the
/// fresh runs the pairing placed for it, in placement order.
///
/// The image the composite resolves a member-position end through, once
/// [`stage_publish`](skep_arrangement::stage_publish) has minted the member;
/// a verifier holding the member reads the same off `image(member, [1..placed])`.
pub fn member_image(shot: &Shot, pairing: &Pairing) -> Vec<Run> {
    let draft = shot.draft_document();
    let mut out = Vec::with_capacity(shot.runs.len());
    for (index, stated) in shot.runs.iter().enumerate() {
        let native = draft.is_some()
            && document_of(stated.run.i_start()).map(|d| trunk_of(&d)) == draft;
        if native {
            out.extend(pairing.iter().filter(|p| p.index == index).map(|p| p.to.clone()));
        } else {
            out.push(stated.run.clone());
        }
    }
    out
}

/// A member-position end, built by [`member_end`]: the stored endset and
/// the canonical spelling of its positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberEnd {
    /// The row's spelling: the lowest member positions holding each value,
    /// consecutive positions merged, in the stored spans' order.
    pub canonical: Vec<MemberSpan>,
    /// The endset as stored: the I-spans the member holds at the positions,
    /// I-adjacent pieces merged in sequence.
    pub stored: Endset,
}

/// Builds a member-position end over `image`: the stored endset and the
/// canonical request row, by ONE function (the design's W3 (a)).
///
/// Each span of `spans` resolves to the I-spans the image's runs hold at
/// its positions, in order, consecutive I-adjacent pieces merged — the
/// stored endset — and the canonical row is [`canonical_member_spans`] of
/// that endset: for each stored span, in order, the LOWEST member positions
/// holding each of its values, consecutive positions merged. A request is
/// canonical where its spelling equals that row, which the codec holds it
/// to; the daemon stores the endset and signs the row; a verifier holding
/// the member maps the stored endset back through the member's image to the
/// same row.
///
/// `None` where a span has a zero width, lies outside `[1, placed]`, or a
/// width passes `u64`.
pub fn member_end(image: &[Run], spans: &[MemberSpan]) -> Option<MemberEnd> {
    let rows = rows_of(image)?;
    let placed: u64 = rows.iter().map(|r| r.width).sum();
    let mut pieces: Vec<Piece> = Vec::new();
    for span in spans {
        if span.width == 0 || span.ordinal == 0 {
            return None;
        }
        let reach = span.ordinal.checked_add(span.width)?;
        if reach - 1 > placed {
            return None;
        }
        for row in &rows {
            let row_reach = row.position + row.width;
            let lo = span.ordinal.max(row.position);
            let hi = reach.min(row_reach);
            if lo >= hi {
                continue;
            }
            let piece = Piece { chain: row.chain.clone(), first: row.first + (lo - row.position), width: hi - lo };
            match pieces.last_mut() {
                Some(last) if last.chain == piece.chain && last.first + last.width == piece.first => {
                    last.width += piece.width;
                }
                _ => pieces.push(piece),
            }
        }
    }
    let stored = Endset::from_spans(pieces.iter().map(Piece::span));
    let canonical = canonical_over(&rows, &pieces)?;
    Some(MemberEnd { canonical, stored })
}

/// Returns the canonical member-position spelling of `stored` over `image`:
/// for each stored span, in order, the lowest member positions holding each
/// of its values, consecutive positions merged.
///
/// The verifier's half of [`member_end`]: a reader holding the member and a
/// deposited link composes the signed row from the stored endset and
/// `image(member, [1..placed])`. `None` where a stored span is no content
/// span the image holds whole.
pub fn canonical_member_spans(image: &[Run], stored: &Endset) -> Option<Vec<MemberSpan>> {
    let rows = rows_of(image)?;
    let pieces: Vec<Piece> = stored.spans().map(Piece::of_span).collect::<Option<_>>()?;
    canonical_over(&rows, &pieces)
}

/// One run of an image as the position arithmetic reads it: its content
/// chain (every component but the ordinal), its first ordinal, its width,
/// and the member position its first address holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    chain: Vec<Nat>,
    first: u64,
    width: u64,
    position: u64,
}

/// One piece of a resolved end: `width` addresses from `first` on `chain`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Piece {
    chain: Vec<Nat>,
    first: u64,
    width: u64,
}

impl Piece {
    /// Returns the piece as the I-span it names.
    fn span(&self) -> Span {
        let tumbler = |ordinal: u64| {
            Tumbler::new(self.chain.iter().cloned().chain([Nat::from(ordinal)]))
                .expect("a content address has a chain and an ordinal")
        };
        Span::from_endpoints(tumbler(self.first), &tumbler(self.first + self.width))
            .expect("width ≥ 1 and one length: the span is well-formed")
    }

    /// Reads a stored I-span as a piece: its start's chain and ordinal, its
    /// width's last component. `None` for a span that is no I-span.
    fn of_span(span: &Span) -> Option<Piece> {
        let start = span.start();
        let width = span.width();
        if start.len() != width.len() || start.len() < 2 {
            return None;
        }
        if width.iter().take(width.len() - 1).any(|c| *c != Nat::from(0u32)) {
            return None;
        }
        let (chain, first) = split(start)?;
        let count = u64::try_from(width.get(width.len())?).ok()?;
        (count > 0).then_some(Piece { chain, first, width: count })
    }
}

/// Splits a content address into its chain and its ordinal.
fn split(t: &Tumbler) -> Option<(Vec<Nat>, u64)> {
    let mut chain: Vec<Nat> = t.iter().cloned().collect();
    let ordinal = chain.pop()?;
    Some((chain, u64::try_from(&ordinal).ok()?))
}

/// Returns `image`'s runs as rows, their positions tiling from 1.
fn rows_of(image: &[Run]) -> Option<Vec<Row>> {
    let mut rows = Vec::with_capacity(image.len());
    let mut position: u64 = 1;
    for run in image {
        let (chain, first) = split(run.i_start().tumbler())?;
        let width = u64::try_from(run.width()).ok()?;
        rows.push(Row { chain, first, width, position });
        position = position.checked_add(width)?;
    }
    Some(rows)
}

/// Returns the canonical spelling of `pieces` over `rows`: each piece's
/// addresses at the lowest position holding each, consecutive positions
/// merged. `None` where a piece's address lies in no row.
fn canonical_over(rows: &[Row], pieces: &[Piece]) -> Option<Vec<MemberSpan>> {
    let mut out: Vec<MemberSpan> = Vec::new();
    for piece in pieces {
        let reach = piece.first + piece.width;
        // The rows holding some of the piece, and the breakpoints they cut.
        let holding: Vec<&Row> = rows
            .iter()
            .filter(|r| r.chain == piece.chain && r.first < reach && r.first + r.width > piece.first)
            .collect();
        let mut cuts: BTreeSet<u64> = BTreeSet::from([piece.first, reach]);
        for r in &holding {
            for c in [r.first, r.first + r.width] {
                if c > piece.first && c < reach {
                    cuts.insert(c);
                }
            }
        }
        let cuts: Vec<u64> = cuts.into_iter().collect();
        for pair in cuts.windows(2) {
            let (x, y) = (pair[0], pair[1]);
            // The row placing `x` lowest: positions rise with the address
            // at the same slope in every row, so the lowest is the row with
            // the least `position - first` among those holding `x`.
            let best = holding
                .iter()
                .filter(|r| r.first <= x && x < r.first + r.width)
                .min_by_key(|r| r.position + (x - r.first))?;
            let ordinal = best.position + (x - best.first);
            match out.last_mut() {
                Some(last) if last.ordinal + last.width == ordinal => last.width += y - x,
                _ => out.push(MemberSpan { ordinal, width: y - x }),
            }
        }
    }
    Some(out)
}

/// Resolves a planned end to the endset the commit stores, once the member
/// is minted: a stored end as it is, a named end's tags to the minted
/// addresses, a member-position end through the member's image
/// ([`member_end`]).
///
/// `None` where the member-position end does not resolve, which the plan's
/// own check over the request's image rules out for every end it holds.
pub fn resolve_end(end: &PlannedEnd, member: &Address, edition: Option<&Address>, image: &[Run]) -> Option<Endset> {
    Some(match end {
        PlannedEnd::Stored(endset) => endset.clone(),
        PlannedEnd::Named(named) => Endset::from_spans(named.iter().map(|n| match n {
            NamedAddress::Member => subtree_of(member.tumbler()),
            NamedAddress::Edition => subtree_of(edition.unwrap_or(member).tumbler()),
            NamedAddress::Address(a) => subtree_of(a.tumbler()),
        })),
        PlannedEnd::Member(spans) => member_end(image, spans)?.stored,
    })
}

#[cfg(test)]
mod tests;
