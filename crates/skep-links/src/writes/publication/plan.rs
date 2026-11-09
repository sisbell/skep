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
//! an account in the commit (`mint: true` with `account`, `doc` absent);
//! [`PublishDeposits`], the edition claim's flag (`claim: true`, at either
//! form), the four lists — `links`, one [`LinkEntry`] per accepted link,
//! `retract`, the held removals' marks by address, `read_with`, the sets
//! the document is newly read with, and `supersede`, the daughters the
//! member takes in, by address (the merge bridge lane, brief A: skep #805)
//! — and, beside `retract`, THE PRIVATE RIDER `originals` (§5.7 (vi′)):
//! one [`OriginalEntry`] per original the commit ends — a private link of
//! the caller's whose copy this request's `retract` list retracts, by
//! address, and the REST where one stands, the original's words no copy of
//! it ever covered, as content I-spans. The rider is outside the signed
//! preimage and no term of the count: its writes are private, in the
//! original's home. An entry names an address the commit
//! mints by TAG ([`NamedAddress`]): the member by `member`, the edition by
//! `edition`. An end is one of three forms
//! ([`EndArg`]): the address form, the I-span form, or THE MEMBER-POSITION
//! FORM — spans of the member's positions inside `[1, placed]`
//! ([`MemberSpan`]), the form an end on this shot's own new words takes,
//! spelled in the signed row as the request spells it and stored as the
//! I-spans the commit mints.
//!
//! **The plan** ([`plan_deposits`]) runs THE VALIDATION's (3), (4), (4′),
//! (5) and (6) over a world — never a staging — and answers a
//! [`DepositPlan`]: the deposits per home in THE SIGNED ENTRY's order (the
//! member first, then a minted edition, then every other home in address
//! order; inside a home the edition claim, then the copies, then the
//! retractions, then the read-withs, then the supersession claims, each
//! list in declared order), each skip decided — a retraction whose target
//! is already retracted, a read-with that stands in a published home of the
//! caller's, a daughter a claim of the caller's own already names — each
//! copy's private claim beside it, outside the signed set, and, in a list
//! of its own that is in no home ([`DepositPlan::originals`]), the
//! originals the rider ends ([`PlannedOriginal`]), each with the fresh mark
//! its rest takes, an original already retracted skipped. The first fault
//! in list order refuses the whole ([`PlanFault`]), naming the entry. The
//! edition claim is homed in
//! the edition whichever form names it — the tag `edition` at the mint
//! form, the trunk's own address at the document form, where it sorts among
//! the other homes — and the plan plans the row either way: whether the
//! document form may carry it at all (the edition holding no member yet) is
//! the composite's step, judged on the same base ahead of the plan.
//!
//! **The member a claim names.** A supersession claim names the member by
//! tag, and the plan asks where the shot lands before it plans one: where a
//! member stands and the base is not the trunk's head, M5 mints the base's
//! daughter (PUB-2.39), so the `supersede` list is refused whole as
//! `head_moved`, and every claim the plan holds names the trunk's next
//! member. The plan restates M5's destination rule through M5's own head
//! read, and `tests/it/publication.rs` holds the two to each other over a
//! kernel.
//!
//! **One world, one plan.** Under the daemon's serialization lock the
//! snapshot the admission reads IS the base the transaction opens on (the
//! survey's C8), and the plan is a pure function of that world and the
//! request, so the body the composer signs against and the deposits the
//! composite stages agree by construction; `tests/it/publication.rs` pins
//! the purity.

use std::collections::{BTreeMap, BTreeSet};

use skep_address::{
    content_subspace, document_of, is_prefix, subtree_of, validate, Address, Level, Nat, Span,
    Tumbler,
};
use skep_arrangement::{trunk_head, trunk_of, Caller, HasM5, Pairing, Run, Shot};
use skep_namespace::M3State;
use std::sync::LazyLock;

use super::super::makelink::SlotArg;
use super::super::{is_correspondence_class, is_replaces_class};
use crate::budget::MAX_SLOT_SPANS;
use crate::class::coverage_class;
use crate::endset::{enc, Endset, Link};
use crate::registry::{registry, ShippedType};
use crate::error::{OldCause, OriginalCause, PlanFault, ReadWithCause, RetractCause, SupersedeCause};
use crate::state::{LinkState, View, FROM, TO, TYPE};
use crate::LinkWorld;

// ───────────────────────────── the members ─────────────────────────────

/// Where a publication lands.
///
/// The document form is today's: `doc`, a published document of the
/// caller's (a member names its document). The mint form (the design's (iv);
/// sweep 6 W16) names the PARENT ACCOUNT alone — `doc` absent — the commit
/// minting the edition under it and its first member beside it. An enum and
/// not an `Option<doc>` beside a flag: the two forms are two values with
/// their own readers — the trunk of `doc` at the one, the account at the
/// other — and every exhaustive match decides its mint arm, where an option
/// would let a request carry both or neither and leave each reader to
/// re-derive the form from two fields. Whether the commit writes the edition
/// claim is no part of the target: the claim is a deposit, carried once on
/// [`PublishDeposits::claim`] for either form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PublishTarget {
    /// A published document of the caller's: the shot appends its chain.
    Document(Address),
    /// An edition minted in the commit under `account`, the shot its birth
    /// version.
    Mint {
        /// The parent account the edition is minted under.
        account: Address,
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

/// One entry of a publication's `originals` rider: an original the commit
/// ends, and the rest it keeps formatted (the link-sets design §5.7 (vi′);
/// §2).
///
/// `old` is a private link of the caller's whose copy — the `new` of an
/// active claim of the caller's naming `old` — this request's `retract`
/// list retracts; the commit retracts `old` at its own home in the same
/// transaction, so the mark taken off is drawn nowhere after. `rest` is the
/// original's words NO COPY OF IT HAS EVER COVERED — a cut copy's rest,
/// words a selection left out — as content I-spans; where it holds a span
/// the commit first writes a fresh mark of the original's type over exactly
/// those words in the original's home, so they keep the formatting as the
/// draft's own, then retracts the original. Empty where no rest stands.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OriginalEntry {
    /// The original: a private link of the caller's, by address.
    pub old: Address,
    /// The rest's spans, content I-spans within the original's own ends;
    /// empty where no rest stands.
    pub rest: Vec<Span>,
}

/// The deposits a publication carries beside its shot: the edition claim's
/// flag, the four optional lists and the private rider.
///
/// The claim is the first deposit of the edition's group whichever form
/// minted or named the edition, so its flag lives here, once, beside the
/// lists — never on the target. At the mint form the commit writes it homed
/// in the edition it mints; at the document form homed in `doc`'s trunk,
/// which must hold no member yet (the composite's refusal, `ClaimRefused`).
/// Either way it names the staging draft, which the request must then carry.
///
/// `supersede` (the merge bridge lane, brief A; skep #805) names the
/// DAUGHTERS the member takes in — members of `doc`'s own chain, a merged
/// version's sides — each deposited as one supersession claim, `old` the
/// daughter and `new` THE MEMBER THIS COMMIT MINTS, typed as `assert_sup`
/// types it, homed in `doc`'s trunk as the edition claim is at the document
/// form, in the shot's one commit. The two claims never land together: the
/// edition claim is a first version's, and a daughter exists only once a
/// member stands.
///
/// `originals` (the link-sets design §5.7 (vi′)) is THE PRIVATE RIDER
/// beside `retract`: the originals the commit ends, one [`OriginalEntry`]
/// each. Its writes are private — a retraction at the original's own home
/// and, over a rest, a fresh mark there — so it is outside the signed
/// preimage and no term of the count, as the correspondence records and the
/// re-window are; it rides the request as the four lists do, and is a
/// member of it, so a request carrying the rider alone is not empty and is
/// planned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PublishDeposits {
    /// Whether the commit writes the edition claim (`claim: true`): typed the
    /// edition class, `from` the edition, `to` the staging draft.
    pub claim: bool,
    /// One entry per accepted link.
    pub links: Vec<LinkEntry>,
    /// The held removals' marks, by address.
    pub retract: Vec<Address>,
    /// The sets the document is newly read with, by address.
    pub read_with: Vec<Address>,
    /// The daughters the member supersedes, by address — version members of
    /// `doc`'s own chain; absent and empty alike on the wire.
    pub supersede: Vec<Address>,
    /// The originals the commit ends, one entry each — the private rider;
    /// absent and empty alike on the wire.
    pub originals: Vec<OriginalEntry>,
}

impl PublishDeposits {
    /// Returns whether the request carries no deposit and no rider: no
    /// claim, none of the four lists, no original.
    pub fn is_empty(&self) -> bool {
        !self.claim
            && self.links.is_empty()
            && self.retract.is_empty()
            && self.read_with.is_empty()
            && self.supersede.is_empty()
            && self.originals.is_empty()
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
    /// A `supersede` entry's claim: typed the supersedes class, `from` the
    /// daughter, `to` the member the commit mints — homed in `doc`'s trunk,
    /// by address.
    Supersede {
        /// The entry's position in `supersede`.
        index: usize,
        /// The daughter superseded: a version member of `doc`'s own chain.
        old: Address,
    },
}

/// One home's deposits, in the order the daemon mints them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedHome {
    /// The home, by tag or address.
    pub home: NamedAddress,
    /// Its deposits: the edition claim, the copies, the retractions, the
    /// read-withs, the supersession claims, each list in declared order.
    pub deposits: Vec<PlannedDeposit>,
}

/// One original the commit ends, as planned (the link-sets design §5.7
/// (vi′)): the private rider's staged writes, in no home of the signed
/// entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedOriginal {
    /// The entry's position in `originals`.
    pub index: usize,
    /// The original, a private link of the caller's.
    pub old: Address,
    /// Its home, a private document of the caller's: where both writes land.
    pub home: Address,
    /// The fresh mark over the rest, where one stands: the original's type
    /// slot, and the rest's spans in the end of the original each lies
    /// within — staged, seated, ahead of the original's retraction. `None`
    /// where the entry names no rest.
    pub rest: Option<Link>,
}

/// The deposits a publication stages, per home in the signed entry's order,
/// and beside them the originals the private rider ends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DepositPlan {
    /// The homes written, the member first, then a minted edition, then
    /// every other in address order; a home with no deposit is absent.
    pub homes: Vec<PlannedHome>,
    /// The originals the commit ends, in declared order, each with its
    /// fresh mark where a rest stands — never among `homes`, from which the
    /// signed rows are built: the rider is outside the preimage by
    /// construction. An original already retracted is absent, skipped.
    pub originals: Vec<PlannedOriginal>,
}

impl DepositPlan {
    /// Returns whether the plan stages nothing: no deposit, no original.
    pub fn is_empty(&self) -> bool {
        self.homes.is_empty() && self.originals.is_empty()
    }
}

/// Plans a publication's deposits over `world`: THE VALIDATION's (3), (4),
/// (4′), (5) and (6) in the design's order, the deposits per home in the
/// signed entry's order, and the originals the rider ends beside them.
///
/// `caller` is the writer, whose homes the reads range over; `target` the
/// request's form; `shot` the request's shot, read for its draft, for its
/// base and for the member's positions a member-position end names;
/// `deposits` the four lists and the rider. The reads are the design's
/// in-lock reads,
/// composed from M7's own primitives (the survey's C16): (3)'s claims
/// naming `old` over the caller's homes alone — `homes_under` of the
/// caller's account, then one typed stab per home — never another hand's;
/// `old`'s residence, activity and ownership off the store and the
/// registry; (4′)'s claims naming the original over the caller's homes,
/// as (3)'s; (5)'s presence over the caller's PUBLISHED homes, each row kept
/// where its stored `from` is the edition's own unit span and its stored
/// `to` the set's, exactly; (6)'s claims naming the daughter over the
/// caller's homes, as (3)'s.
///
/// In order, per entry, the first fault refusing the whole:
///
/// 3. each `links` entry: its home registered, then the caller's (ω), then
///    the tag `member` or a published trunk document; the slot forms — the
///    I-span form's content clause by slot, the budget, an empty type —
///    and the class fences on `ty`; a type naming the read-with refused;
///    then `old` where present — resident, private, active and owned;
///    standing on the words the shot publishes through a content span (an
///    original reaching them through a whole-work end alone — a unit span
///    at a document's address or an ancestor's — is the corner's link, no
///    panel's, and is refused); not superseded by an active claim of the
///    caller's naming a public successor homed in a published document of
///    the caller's whose ends cover every published content span of this
///    entry, an entry with a member-position end on the shot's own new
///    words never so superseded, as nothing standing covers fresh words
///    (§5.1's key (iii), PUB-3.9); nor, where `old` is itself a successor,
///    its original superseded by such a claim over the entry's published
///    content spans, whatever new words the entry holds; a second entry
///    naming one `old` refused at the second;
/// 4. each `retract` entry: the target resident, the caller's own, homed in
///    a published document of the caller's; already retracted → SKIPPED;
///
/// 4′. each `originals` entry (the private rider, §5.7 (vi′)): the
///    original resident (`absent`), the caller's own (`not_owner`), homed
///    in a private document (`public`), named once (`duplicate` at the
///    second); where a rest stands, its spans content I-spans by the
///    content clause (`not_content_span`), within the slot budget
///    (`too_large`), the original's type no class the open surface never
///    writes — the retraction, supersession, `replaces` and correspondence
///    classes, whose one writer each is never a fresh mark (`fenced_type`)
///    — and each span within some content span of the original's two ends
///    (`rest_outside`), the fresh mark then the original's type over the
///    rest's spans, each in the end of the original it lies within; then
///    an ACTIVE claim of the caller's — one typed stab of the supersession
///    class at `FROM` per own home, as (3)'s — naming the original as `old`
///    and, as `new`, an address of THIS REQUEST's `retract` list, as sent
///    (`unclaimed`): so only the original of a mark taken off in this
///    commit can ride, never an arbitrary private retraction. Membership in
///    the list, not a landed retraction, is the test: the daemon's composer
///    runs this plan ahead of the signature check, and a copy retracted on
///    another device since the panel is a skipped `retract` entry the
///    client's one re-sign drops with the original paired to it — a test on
///    the landing would turn that benign race into a refusal. Last, an
///    original already retracted → SKIPPED, nothing planned for it, as (4)
///    skips its target;
/// 5. each `read_with` entry: `S` a registered trunk document, the
///    caller's, published; a read-with from the edition to `S` standing in
///    a published home of the caller's → SKIPPED, the maker's published
///    homes only; at the mint form the edition is the tag, no presence can
///    stand, and the read-with is written;
/// 6. the `supersede` list (the merge bridge lane, brief A): first, at the
///    document form, the shot landing on the trunk — where a member stands
///    and the base is not the trunk's head, the shot would mint the base's
///    daughter (PUB-2.39), and the list is refused whole at its first
///    entry, `head_moved` with the head, ahead of every entry's own check;
///    then each entry: the daughter a registered VERSION MEMBER of `doc`'s
///    own chain — the trunk itself, a document or member outside the chain,
///    an element address, a member not yet minted, and every entry at the
///    mint form, whose edition has no chain before the commit, are
///    `not_member`; the member the shot appends to, its base, is `base`; a
///    second entry naming one daughter is `duplicate` at the second — then
///    a daughter an ACTIVE claim of the caller's own already names as its
///    `old`, in any home the caller owns and whatever its `new` → SKIPPED,
///    never refused (the design's "dropped where a claim of the person's own
///    already names it, never refused"). The claim is homed in `doc`'s trunk
///    by address, where the edition claim lands at the document form, so one
///    home holds every daughter's claim, its key stands before the commit,
///    the signer spells it from the request's `doc` alone and the feed row
///    names it as it names the edition; its `new` is the member BY TAG, the
///    one address of the claim no signer holds before the commit, and that
///    member is the trunk's next — the head check refuses every shot that
///    would mint another — so the claim names the version that takes the
///    daughter in, never a side version.
///
/// The edition claim, where the deposits claim, leads the edition's home,
/// `to` the shot's draft: the tag `edition` at the mint form, the trunk of
/// `doc` by its ADDRESS at the document form (the tag is for a home the
/// commit mints), that home sorting among the other homes in address order.
/// The plan does not ask whether the document form may carry it — that the
/// trunk holds no member yet is the composite's refusal ahead of the plan,
/// on the same base — so the row it plans is the row a signer composes.
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
    // The edition claim, first of the edition's deposits: the edition by tag
    // where the commit mints it, by address where `doc` names it.
    if deposits.claim {
        let origin = shot.draft_document().ok_or(PlanFault::ClaimWithoutDraft)?;
        let edition = match target {
            PublishTarget::Document(doc) => NamedAddress::Address(trunk_of(doc)),
            PublishTarget::Mint { .. } => NamedAddress::Edition,
        };
        homes.entry(edition).or_default().push(PlannedDeposit::EditionClaim { origin });
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
                let spans = published_spans(&from, &to, &image, shot);
                let new_words = holds_new_words(&from, &to, &image, shot);
                let home = check_old(world, caller, old, &image, &spans, new_words)
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
    // (4′) each original the rider ends: resident, the caller's own, private,
    // named once, its rest within it, and claimed onto a mark this request
    // retracts; one already retracted is skipped, as (4) skips its target.
    let mut originals: Vec<PlannedOriginal> = Vec::new();
    let mut ended: BTreeSet<&Address> = BTreeSet::new();
    let own = (!deposits.originals.is_empty()).then(|| own_homes(m3, links, caller));
    let marks: BTreeSet<&Address> = deposits.retract.iter().collect();
    for (index, entry) in deposits.originals.iter().enumerate() {
        let fault = |cause| PlanFault::Original { index, cause };
        let Some(link) = links.readlink(&entry.old) else {
            return Err(fault(OriginalCause::Absent));
        };
        let home = document_of(&entry.old).ok_or(fault(OriginalCause::Absent))?;
        if !caller.is_owner(m3, &entry.old) {
            return Err(fault(OriginalCause::NotOwner));
        }
        if m3.published(&home) {
            return Err(fault(OriginalCause::Public));
        }
        if !ended.insert(&entry.old) {
            return Err(fault(OriginalCause::Duplicate));
        }
        let rest = rest_mark(link, &entry.rest).map_err(fault)?;
        if !claimed_onto_a_mark(links, own.as_deref().unwrap_or(&[]), &entry.old, &marks) {
            return Err(fault(OriginalCause::Unclaimed));
        }
        if !links.is_active(&entry.old) {
            continue; // already retracted: the entry commits nothing
        }
        originals.push(PlannedOriginal { index, old: entry.old.clone(), home, rest });
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
    // (6) each daughter superseded: the shot landing on the trunk, then each
    // a member of the chain, not the base, named once; one a claim of the
    // caller's own already names is skipped.
    let base = shot.base.as_ref().map(|base| &base.member);
    if !deposits.supersede.is_empty() {
        if let Some(head) = edition.as_ref().and_then(|trunk| moved_head(m3, trunk, base)) {
            return Err(PlanFault::Supersede { index: 0, cause: SupersedeCause::HeadMoved(head) });
        }
    }
    let mut daughters: BTreeSet<&Address> = BTreeSet::new();
    let own = (!deposits.supersede.is_empty()).then(|| own_homes(m3, links, caller));
    for (index, daughter) in deposits.supersede.iter().enumerate() {
        let fault = |cause| PlanFault::Supersede { index, cause };
        let Some(trunk) = &edition else {
            return Err(fault(SupersedeCause::NotMember)); // the mint form: no chain yet
        };
        if !is_chain_member(m3, trunk, daughter) {
            return Err(fault(SupersedeCause::NotMember));
        }
        if base == Some(daughter) {
            return Err(fault(SupersedeCause::Base));
        }
        if !daughters.insert(daughter) {
            return Err(fault(SupersedeCause::Duplicate));
        }
        if claimed_by_own(links, own.as_deref().unwrap_or(&[]), daughter) {
            continue; // the caller's own claim names it: the entry commits nothing
        }
        homes
            .entry(NamedAddress::Address(trunk.clone()))
            .or_default()
            .push(PlannedDeposit::Supersede { index, old: daughter.clone() });
    }
    Ok(DepositPlan {
        homes: homes.into_iter().map(|(home, deposits)| PlannedHome { home, deposits }).collect(),
        originals,
    })
}

/// Returns the fresh mark an `originals` entry's rest takes, or `None` for
/// an entry naming no rest (THE VALIDATION's (4′); the link-sets design §2,
/// a cut copy's rest).
///
/// The mark is the original's type slot over the rest's spans, each span
/// placed in the end of the original it lies within — `from` where a span
/// of the original's `from` contains it, else `to` — so a formatting mark,
/// whose one content end holds its words, yields a mark of the same shape
/// over exactly the rest, and no other end is carried.
///
/// # Errors
///
/// In order: `NotContentSpan` for a rest span that is no content I-span —
/// the content clause every I-span slot passes ([`SlotArg::ill_formed_span`]);
/// `TooLarge` past the slot budget; `FencedType` where the original's type
/// is the retraction, supersession, `replaces` or correspondence class,
/// each with one writer that is never a fresh mark — of the four only a
/// correspondence record has content ends a rest could lie within, and the
/// daemon's class cell refuses it ahead of the store, so this is the plan's
/// own backstop; `RestOutside` for a span within no content span of the
/// original's two ends.
fn rest_mark(original: &Link, rest: &[Span]) -> Result<Option<Link>, OriginalCause> {
    if rest.is_empty() {
        return Ok(None);
    }
    if SlotArg::ill_formed_span(rest).is_some() {
        return Err(OriginalCause::NotContentSpan);
    }
    if rest.len() > MAX_SLOT_SPANS {
        return Err(OriginalCause::TooLarge);
    }
    let ty = original.type_slot();
    // The two reserved classes are address-denoting, so a type that is not
    // names neither and is never classified here; the two commons fences
    // are total.
    let reserved = ty.is_address_denoting() && {
        let class = coverage_class(ty);
        class == *registry().shipped_class(ShippedType::Retraction)
            || class == *registry().shipped_class(ShippedType::Supersedes)
    };
    if reserved || is_replaces_class(ty) || is_correspondence_class(ty) {
        return Err(OriginalCause::FencedType);
    }
    let (mut from, mut to) = (Vec::new(), Vec::new());
    for span in rest {
        if original.from_slot().spans().any(|end| lies_within(span, end)) {
            from.push(span.clone());
        } else if original.to_slot().spans().any(|end| lies_within(span, end)) {
            to.push(span.clone());
        } else {
            return Err(OriginalCause::RestOutside);
        }
    }
    Ok(Some(Link::triple(Endset::from_spans(from), Endset::from_spans(to), ty.clone())))
}

/// Returns whether the content span `s` lies within the content span `end`:
/// one depth, and `s`'s positions among `end`'s.
fn lies_within(s: &Span, end: &Span) -> bool {
    end.start().len() == s.start().len() && *end.start() <= *s.start() && s.reach() <= end.reach()
}

/// Returns whether an ACTIVE claim homed in one of `homes` — the caller's
/// own — names `old` as its `old` and one of `marks` as its `new`: the
/// claim (4′) admits an original on, `marks` the request's `retract` list
/// as sent. One typed stab of the supersession class at `FROM` over the
/// original's unit span per home, as [`claimed_by_own`] makes it, each claim
/// kept where its `from` denotes the original itself and its `to` denotes a
/// mark of the list.
fn claimed_onto_a_mark(links: &LinkState, homes: &[Address], old: &Address, marks: &BTreeSet<&Address>) -> bool {
    let sup = registry().shipped_class(ShippedType::Supersedes);
    let probe = subtree_of(old.tumbler());
    homes.iter().any(|home| {
        links.stab_typed_in(sup, home, FROM, [&probe], View::Active).iter().any(|claim| {
            claim.from.single_denoted() == Some(old.tumbler())
                && claim
                    .to
                    .single_denoted()
                    .and_then(|t| validate(t.clone()).ok())
                    .is_some_and(|new| marks.contains(&new))
        })
    })
}

/// Returns the trunk's head where a shot off `base` would not mint the
/// trunk's next member (THE VALIDATION's (6); PUB-2.39's head/older).
///
/// A member stands and the base is not it: an older member or a daughter,
/// whose own daughter the shot mints; the bare document, which lands as the
/// first member's daughter; or no base, which the shot's own table refuses
/// `BaseSuperseded` ahead of the plan. `None` where the shot mints the
/// trunk's next member — off the head, or into a chain with no member yet.
/// It is M5's destination rule read through M5's own head ([`trunk_head`]),
/// the head the shot's admission judges its base against.
fn moved_head(m3: &M3State, trunk: &Address, base: Option<&Address>) -> Option<Address> {
    trunk_head(m3, trunk).filter(|head| base != Some(head))
}

/// Returns whether `a` is a registered version member of the chain `trunk`
/// anchors (THE VALIDATION's (6)): a document-tier address other than the
/// trunk itself whose trunk is `trunk` — address arithmetic, `trunk_of` —
/// and registered with M3, so a member not yet minted is no member. An
/// element address, an account and a document outside the chain project to
/// themselves or to another trunk and fail the arithmetic before M3 is
/// asked.
fn is_chain_member(m3: &M3State, trunk: &Address, a: &Address) -> bool {
    a.level() == Level::Document && a != trunk && trunk_of(a) == *trunk && m3.is_registered_document(a)
}

/// Returns whether an ACTIVE claim homed in one of `homes` — the caller's
/// own — names `daughter` as its `old`, whatever its `new`: the skip (6)
/// decides on. One typed stab of the supersession class at `FROM` over the
/// daughter's unit span per home, each claim kept where its `from` denotes
/// the daughter itself — the read the design's resume makes through
/// `in_claims{y: the daughter, view: active}`, cut to the caller's homes.
fn claimed_by_own(links: &LinkState, homes: &[Address], daughter: &Address) -> bool {
    let sup = registry().shipped_class(ShippedType::Supersedes);
    let probe = subtree_of(daughter.tumbler());
    homes.iter().any(|home| {
        links
            .stab_typed_in(sup, home, FROM, [&probe], View::Active)
            .iter()
            .any(|claim| claim.from.single_denoted() == Some(daughter.tumbler()))
    })
}

/// Returns whether an active supersession claim `old → new` is homed in
/// `home`: a row of the supersedes class whose stored `from` is `old`'s
/// unit span and whose stored `to` is `new`'s, exactly — the test the
/// daemon's feed row applies over the commit's post-world to say whether a
/// `supersede` entry's claim landed in `doc`'s trunk or was skipped, as
/// [`read_with_in`] is for a `read_with` entry. One index probe: the home's
/// rows driven by `from` over `old`'s unit span, the two other slots as
/// constraints.
///
/// # Panics
///
/// Panics where `home` is not a document address, as
/// [`LinkState::match_links_in`] does; the claim's home is `doc`'s trunk.
pub fn supersession_claim_in(links: &LinkState, home: &Address, old: &Address, new: &Address) -> bool {
    let (from, to) = (enc([old]), enc([new]));
    let sup = registry().reserved_type(ShippedType::Supersedes);
    let from_span = subtree_of(old.tumbler());
    links
        .match_links_in(home, (FROM, [&from_span]), &[(TO, &to), (TYPE, sup)], View::Active)
        .into_iter()
        .filter_map(|hit| links.readlink(&hit))
        .any(|link| *link.from_slot() == from && *link.to_slot() == to && *link.type_slot() == *sup)
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
/// An I-span end's spans as given, any named draft's own left out
/// ([`on_named_draft`]), the shot re-minting every one of them, its
/// member-position form the entry's spelling; a member-position end's spans
/// at positions the shot places by reference, resolved through the request's
/// image, where a span at a draft-native position — the shot's own new
/// words, fresh at the commit — is left out, nothing standing before the
/// commit could cover it (the request's image maps such a position to the
/// draft's own address, which names a named draft). An address-form end
/// names no content span. Whether an end lies on new words at all is
/// [`holds_new_words`]'s answer, which (3) reads beside these spans.
fn published_spans(from: &PlannedEnd, to: &PlannedEnd, image: &[Run], shot: &Shot) -> Vec<Span> {
    let mut out = Vec::new();
    for end in [from, to] {
        match end {
            PlannedEnd::Stored(endset) => {
                out.extend(endset.spans().filter(|s| !is_unit_depth(s) && !on_named_draft(s, shot)).cloned());
            }
            PlannedEnd::Named(_) => {}
            PlannedEnd::Member(spans) => {
                if let Some(end) = member_end(image, spans) {
                    out.extend(end.stored.spans().filter(|s| !on_named_draft(s, shot)).cloned());
                }
            }
        }
    }
    out
}

/// Returns whether a member-position end lies on the shot's own new words.
///
/// Some piece the end resolves to through the request's image lies on a
/// named draft ([`on_named_draft`]): a draft-native position, which the
/// commit mints fresh and no successor standing before it covers (§5.1's key
/// (iii)). The member-position form alone, the form an end on the shot's new
/// words takes (§5.7): an I-span end on a named draft's words is stored as
/// the draft's own identity, the far end of an original on words the shot
/// leaves out.
fn holds_new_words(from: &PlannedEnd, to: &PlannedEnd, image: &[Run], shot: &Shot) -> bool {
    [from, to].into_iter().any(|end| match end {
        PlannedEnd::Member(spans) => {
            member_end(image, spans).is_some_and(|end| end.stored.spans().any(|s| on_named_draft(s, shot)))
        }
        PlannedEnd::Stored(_) | PlannedEnd::Named(_) => false,
    })
}

/// Returns whether `s` starts on a named draft's own words.
///
/// The rendering draft's or an `also` draft's alike (`Shot::is_draft_native`):
/// the words the shot re-mints wherever it places them.
fn on_named_draft(s: &Span, shot: &Shot) -> bool {
    validate(s.start().clone())
        .ok()
        .and_then(|a| document_of(&a))
        .map(|d| trunk_of(&d))
        .is_some_and(|d| shot.is_draft_native(&d))
}

/// Returns whether `s` is a unit-depth span: an address's own subtree span.
fn is_unit_depth(s: &Span) -> bool {
    *s == subtree_of(s.start())
}

/// Checks a `links` entry's `old` by the panel filter's rule (PUB-3.9).
///
/// THE VALIDATION's (3), read at the commit's position. Answers `old`'s
/// home, the claim's. `image` is the shot's runs as the request states them
/// ([`request_image`]), the words the publication publishes; `spans` are
/// the entry's published content spans ([`published_spans`]); `new_words`
/// is whether a member-position end lies on the shot's own new words
/// ([`holds_new_words`]). A claim naming `old` supersedes it only where
/// `new_words` is false, no successor covering fresh words (§5.1's key
/// (iii)); where `old` is a revision, a claim naming its original
/// supersedes it over `spans` whatever new words the entry holds.
fn check_old<W: LinkWorld + HasM5>(
    world: &W,
    caller: Caller,
    old: &Address,
    image: &[Run],
    spans: &[Span],
    new_words: bool,
) -> Result<Address, OldCause> {
    let (m3, links) = (world.m3(), world.links());
    let Some(link) = links.readlink(old) else {
        return Err(OldCause::Absent);
    };
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
    if reaches_by_whole_work_end_alone(link, image) {
        return Err(OldCause::WholeWork);
    }
    let own_homes = own_homes(m3, links, caller);
    if !new_words && superseded_by_own_claim(m3, links, caller, &own_homes, old, spans) {
        return Err(OldCause::Superseded);
    }
    // Where `old` is itself a successor — a revision of an original — its
    // own original not superseded by an accept's claim of the caller's,
    // whatever new words the entry holds.
    for original in originals_of(links, &own_homes, old) {
        if superseded_by_own_claim(m3, links, caller, &own_homes, &original, spans) {
            return Err(OldCause::Superseded);
        }
    }
    Ok(home)
}

/// Returns whether `link`'s stored endset reaches the published words
/// through a whole-work end alone — THE STORED-ENDSET TEST at the door (the
/// link-sets design §5.1): some end is a unit-depth span at a document's
/// address or an ancestor's, no content position, whose start is a prefix
/// of a run of `image`, and no content span of either end shares a position
/// with a run. Such a link is the corner's, which no panel offers. A link
/// whose ends reach the words through nothing at all is not this test's.
fn reaches_by_whole_work_end_alone(link: &Link, image: &[Run]) -> bool {
    let ends: Vec<&Span> = link.from_slot().spans().chain(link.to_slot().spans()).collect();
    let runs: Vec<Span> = image.iter().map(Run::iextent).collect();
    let by_content = ends
        .iter()
        .filter(|e| is_content_span(e))
        .any(|e| runs.iter().any(|r| share_a_position(e, r)));
    if by_content {
        return false;
    }
    ends.iter()
        .filter(|e| !is_content_span(e) && is_unit_depth(e))
        .any(|e| runs.iter().any(|r| is_prefix(e.start(), r.start())))
}

/// Returns whether `s` starts at a content position: an address in the
/// content subspace, whatever the width.
fn is_content_span(s: &Span) -> bool {
    validate(s.start().clone()).is_ok_and(|a| a.subspace() == Some(&content_subspace()))
}

/// Returns whether two content spans of one chain share a position: the
/// same depth, and the half-open ranges intersecting.
fn share_a_position(a: &Span, b: &Span) -> bool {
    a.start().len() == b.start().len() && *a.start() < b.reach() && *b.start() < a.reach()
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
/// every span of `spans` — none where `spans` is empty, the entry publishing
/// no span a successor could cover. No liveness of `new` is asked (§5.1's
/// keys (i) and (iii)); the entry's new words, which key (iii) never
/// covers, are [`check_old`]'s to weigh.
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
    let mut out = Vec::with_capacity(shot.runs.len());
    for (index, stated) in shot.runs.iter().enumerate() {
        // A named draft's run — the rendering draft's or an `also` draft's —
        // is replaced by the fresh runs the pairing placed for it.
        let native = document_of(stated.run.i_start())
            .map(|d| trunk_of(&d))
            .is_some_and(|d| shot.is_draft_native(&d));
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
