//! THE PUBLICATION (the link-sets design §5.7): the publish shot's one
//! commit — the member minted, the edition where the request mints one, the
//! shot's correspondence records beside it in each named draft, every public
//! deposit the request carries (the accepted links as copies with their
//! claims, the held removals' retractions, the read-withs, the edition
//! claim, the supersession claims over the daughters a merged member takes
//! in — the merge bridge lane, brief A), the private rider's originals ended
//! at their own homes (§5.7 (vi′)) and every named draft re-windowed at
//! its own kept places, in one transaction.
//!
//! [`stage_publication`] is the composite as a function over a caller-opened
//! staging — at the mint form the edition's mint first; the shot's admission;
//! THE TWIN FENCE, per named draft; the edition claim's one precondition at
//! the document form (the edition holds no member yet) and THE DEPOSIT PLAN
//! ([`plan_deposits`], the child module `plan`, both read on the
//! transaction's base); the shot's staging ([`stage_publish`], M5's); per
//! piece of draft identity the shot minted one correspondence record homed
//! in the named draft whose identity the piece was — the rendering `draft`'s
//! in it, an `also` draft's in that draft (the Nelson way, B3-S10; A-328) —
//! ([`stage_correspondence`]); THE DEPOSITS, exactly as planned, per home in
//! the signed entry's order; THE ORIGINALS the rider ends, each in its own
//! home — the fresh mark over its rest where one stands, then its
//! retraction; and THE RE-WINDOW OF EVERY NAMED DRAFT, each at
//! its own kept places (§5.7 (viii), the Nelson way): the rendering draft at
//! the request's `places`, then each draft `also` names at its
//! [`AlsoPlaces`] entry, in `also`'s order — for each run a list carries a
//! kept place for, the check that that draft still arranges the run's
//! identity at that place and its replacement there by the fresh run it
//! became, every place of a draft checked on one walk of its run-list and
//! staged as one record ([`stage_substitute`], M5's) — a named draft's
//! run's pieces read off the
//! pairing, whichever draft is re-windowed; a stray run's — one of published
//! identity, the document's own or another document's, re-composed by
//! reference to a record's `to` — off the correspondence records the caller
//! may read whose `to` covers the run, wherever homed (the child module
//! `stray`); a named draft no list carries a place for is left as it stands,
//! its words published through the records it holds and healed by the stray
//! path at its own next shot — and
//! [`LinkWriter::publication`] the public op: one `transact_attested` over
//! the union of the shot's keys, each named draft's link key where a run of
//! its identity is re-inserted, each re-windowed draft's content key where
//! its list carries a place, every home's link key where a deposit lands or
//! an original is ended,
//! and the account's document key where an edition is minted. The
//! correspondence class has this one writer; the fences on the three
//! request-typed doors keep every other act off it. Within one commit a
//! home's link addresses rise in the order the daemon mints them — THE PIN,
//! stated at `mint_link`'s frontier read and held by
//! `tests/it/publication.rs`.
//!
//! Beside the composite sits its price, [`price_publication_reads`]: the
//! reads the composite makes under the lock — the plan's per home and
//! entry, the twin fence's per re-inserted run — the re-window's run-list
//! steps per document it re-windows, its content runs and the pieces its
//! lists place, summed, and, its fifth term, the bytes
//! it would stage, priced from the child module `sizes` — the worst-case
//! bytes per entry kind as the kernel prices them, the table a panel prices
//! a request's records from before the act, over the pieces each run is cut
//! into, which both terms read, and over the UNITS its re-insert comes to,
//! M5's own count of them, which the price carries as a figure of its own —
//! which a transport asks of a snapshot ahead
//! of its lock and refuses past [`MAX_PUBLICATION_READS`] or past the
//! kernel's transaction budget. Everything it counts of a document is
//! counted at the caller's visibility class, the class the commit reads at.
//! The composite reads and stages as it did; the price merely bounds it.

use std::collections::BTreeMap;

use skep_address::{document_of, validate, Address, Nat, SpanSet, Tumbler};
use skep_arrangement::{
    head_lock_key, shot_admission, stage_publish, stage_seat_link, stage_substitute, trunk_head,
    trunk_of, Caller, HasM5, Pairing, PublishWorld, ReinsertWorld, ReinstateError,
    Replacement, Run, Shot, ShotRun, SubstituteError, Substitution, VPos, MAX_REINSERTED_UNITS,
    MAX_REINSERTED_VALUES,
};
use skep_kernel::{LockKey, Seq, Staging, TxnError, MAX_TXN_BYTES};
use skep_namespace::{first_version_address, HasM3, M3State};

use super::nullify::retraction_tuple;
use super::supersession::supersession_claim;
use super::{
    correspondence_type, emit_core, is_correspondence_class, EmitCoreError, Gate, HomeFault,
    LinkWriter, Visibility,
};
use crate::budget::{MAX_PUBLICATION_READS, MAX_SLOT_SPANS};
use crate::endset::{enc, Endset, Link};
use crate::error::{PlanFault, PublicationError};
use crate::state::{LinkRec, View, FROM, TYPE};
use crate::LinkWorld;

// The deposit plan: the request members a publication carries beside its
// shot, the one function that validates them and plans the deposits, and
// the member-position end's one function.
mod plan;
// The worst-case table: the staged bytes per entry kind as the kernel
// prices them, and the price of a request's staged bytes from it.
mod sizes;
// The stray places: the record read that turns a run of published identity,
// re-composed by reference to a record's `to`, back into the draft words
// the re-window checks and replaces — over every record the caller may
// read, wherever homed.
mod stray;

pub use plan::{
    base_runs, canonical_member_spans, edition_type, member_end, member_image, names_read_with,
    plan_deposits, read_with_in, read_with_type, request_image, resolve_end,
    supersession_claim_in, DepositPlan, EndArg, LinkEntry, MemberEnd, MemberSpan, NamedAddress,
    OriginalEntry, PlannedClaim, PlannedDeposit, PlannedEnd, PlannedHome, PlannedOriginal,
    PublishDeposits, PublishTarget,
};
pub use sizes::{
    price_staged_bytes, stored_span_bytes, stored_tumbler_bytes, CLAIM_BYTES, COPY_BYTES,
    COPY_FIXED_BYTES, CORRESPONDENCE_RECORD_BYTES, EDITION_CLAIM_BYTES, EDITION_MINT_BYTES,
    KEPT_PLACE_BYTES, PLACED_RUN_BYTES, READ_WITH_BYTES, REINSERTED_UNIT_BYTES,
    REQUEST_BODY_BYTES, RETRACTION_BYTES, REWINDOWED_DRAFT_BYTES, SHOT_BYTES,
};

/// The kept places of one draft `also` names (the wire's `also_places`
/// entry; the link-sets design §5.7 (viii), every named draft re-windowed
/// at its own kept places).
///
/// `draft` is a draft the request's `also` names, as the request spells it;
/// `places` is parallel to the shot's `runs` by index, as the request's
/// `places` is for the rendering draft — each entry the V-position the run
/// held IN THIS DRAFT when the client composed the request, read off this
/// draft's image, or `None` for a run this draft is not re-windowed at. A
/// place stands beside a run of this draft's own identity (its pieces the
/// pairing's) or beside a stray run of published identity (its pieces the
/// records' the caller may read, wherever homed); the wire's codec refuses
/// one beside a run of the rendering draft's or another `also` draft's
/// identity, which that draft alone may be re-windowed at. The commit
/// re-windows this draft at these places after the rendering draft, in
/// `also`'s order, each place checked by identity against this draft
/// (`KeptPlaceMoved` naming it). Outside the signed preimage as `places`
/// is. A list shorter than `runs` is read as padded with `None`; an entry
/// past the runs is nothing's and is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlsoPlaces {
    /// The draft `also` names whose kept places these are.
    pub draft: Address,
    /// Its kept places, parallel to the shot's `runs` by index.
    pub places: Vec<Option<VPos>>,
}

impl AlsoPlaces {
    /// Returns whether any entry carries a place: the draft is re-windowed.
    pub fn carries_a_place(&self) -> bool {
        self.places.iter().any(Option::is_some)
    }
}

/// Returns the `also_places` entries that carry a place, by the document
/// each one's draft projects to — the first such entry per document, as a
/// lookup in list order finds it.
///
/// Built once per request, each entry's draft projected once, it is the one
/// lookup [`rewindows`] makes for the re-window, the lock set and the
/// reads' price, so each reads the same entry per draft: `O(log k)` a
/// draft, where a scan of the list per `also` draft would pay the list's
/// length in projections for each.
fn also_places_by_draft(also_places: &[AlsoPlaces]) -> BTreeMap<Address, &AlsoPlaces> {
    let mut by_draft = BTreeMap::new();
    for entry in also_places.iter().filter(|entry| entry.carries_a_place()) {
        by_draft.entry(trunk_of(&entry.draft)).or_insert(entry);
    }
    by_draft
}

/// One document the commit re-windows: a draft, as the document it projects
/// to, beside every list that carries a kept place for it, in the commit's
/// order.
///
/// One list for every request the wire admits — the rendering draft's
/// `places`, or an `also` draft's own entry. Two where a request below the
/// codec names one document twice, as its rendering draft and among `also`
/// or twice in `also`: the document is still re-windowed once, at the
/// places of both lists.
type Rewindow<'a> = (Address, Vec<&'a [Option<VPos>]>);

/// Returns THE RE-WINDOWS the commit makes, in its order: each document it
/// re-windows once ([`Rewindow`]), by its first list — the rendering draft
/// at `places` where it carries a place, then each `also` draft at its
/// `also_places` entry where one carries a place, in `also`'s order; none
/// for a shot naming no rendering draft.
///
/// The one sequence step 9 of [`stage_publication`] stages, the lock set
/// takes each draft's content key by and the two prices price, read off
/// `by_draft` ([`also_places_by_draft`]); a list with no place re-windows
/// nothing and is left out. Request arithmetic.
fn rewindows<'a>(
    shot: &Shot,
    places: &'a [Option<VPos>],
    by_draft: &BTreeMap<Address, &'a AlsoPlaces>,
) -> Vec<Rewindow<'a>> {
    let Some(rendering) = shot.draft_document() else { return Vec::new() };
    let mut out: Vec<Rewindow<'a>> = Vec::new();
    let mut add = |draft: Address, list: &'a [Option<VPos>]| match out.iter_mut().find(|(held, _)| *held == draft) {
        Some((_, lists)) => lists.push(list),
        None => out.push((draft, vec![list])),
    };
    if places.iter().any(Option::is_some) {
        add(rendering, places);
    }
    for draft in shot.also.iter().map(trunk_of) {
        if let Some(entry) = by_draft.get(&draft) {
            add(draft, entry.places.as_slice());
        }
    }
    out
}

/// The price of a publication: the four in-lock reads the design names,
/// read off one snapshot (the link-sets design §5.7, EVERY IN-LOCK READ IS
/// BOUNDED BY A REFUSAL AHEAD OF THE LOCK), its fifth term, the bytes
/// the commit would stage, priced from the worst-case table (§5.6, M6), and
/// the units its re-insert comes to, which those bytes are priced over.
///
/// It is what [`price_publication_reads`] answers and a transport refuses
/// on ([`ReadPrice::over_budget`]), carried whole so the refusal can name
/// each term: the caller's link-holding home count, the entries that read
/// per home, the re-window's steps, the twin fence's stabs, and the staged
/// bytes against the transaction budget. The units are no term of that
/// refusal: a shot past their budget is the store's own to refuse, and the
/// figure rides here so a caller pricing a request ahead of the act reads
/// it, and the two budgets the store holds a re-insert to, off the price
/// ([`ReadPrice::UNIT_BUDGET`], [`ReadPrice::POSITION_BUDGET`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadPrice {
    /// The caller's link-holding homes: `homes_under` of the caller's
    /// account — every document under it holding a resident link, the
    /// plan's `own_homes` before its ownership filter, so at or above the
    /// homes the plan reads.
    pub homes: usize,
    /// The `links` entries, the `originals` entries, the `read_with` entries
    /// and the `supersede` entries, summed: the entries whose read ranges
    /// over the caller's homes — (3)'s claim read, (4′)'s claim read, (5)'s
    /// presence read and (6)'s claim read.
    pub entries: usize,
    /// The re-window's steps, summed over every document the commit
    /// re-windows — the rendering draft where `places` carries a place, each
    /// `also` draft whose `also_places` entry carries one, two lists naming
    /// one document one term: its content runs, and the pieces its lists
    /// place. The commit walks the document's run-list once for all of its
    /// places, compares each piece on that walk and puts every one in by
    /// one record, so a place adds its pieces and nothing for the runs it
    /// cuts; a run no list places adds no piece, and `0` is a shot that
    /// re-windows nothing. The runs are counted only where the class the
    /// price is taken at admits the document: a re-windowed draft the
    /// caller may not read adds its pieces and no run, whatever it holds.
    pub rewindow: usize,
    /// The twin fence's stabs: one per re-inserted run, of whichever named
    /// draft — each run one stab of its own draft's records
    /// ([`Shot::reinserted_runs_by_draft`], its groups summed), whether or
    /// not any list places it.
    pub fence: usize,
    /// The bytes the commit would stage, as [`price_staged_bytes`] prices
    /// them from the worst-case table: an upper bound on what the kernel
    /// charges the transaction, held to [`ReadPrice::BYTE_BUDGET`].
    pub staged_bytes: u64,
    /// The units the shot's re-insert comes to, as M5 counts them
    /// ([`Shot::reinserted_units`]) over the snapshot priced: the atoms and
    /// the maximal runs of single-byte values of the draft-native runs'
    /// unminted portions, two staged records each — what the store holds to
    /// [`ReadPrice::UNIT_BUDGET`] and refuses past it, where the reads and
    /// the bytes are refused ahead of the lock. `0` for a shot naming no
    /// draft; and where the store would refuse the re-insert, the count as
    /// far as it went: `0` past the positions' budget
    /// ([`ReadPrice::POSITION_BUDGET`]), which is arithmetic the count reads
    /// nothing after; the units' budget plus one past the units'; the units
    /// standing ahead of a position that holds no value. And `0` where the
    /// class the price is taken at does not admit a draft the shot names:
    /// nothing of a draft the caller may not read is counted, or read.
    pub units: u64,
}

impl ReadPrice {
    /// The budget the reads are held to:
    /// [`MAX_PUBLICATION_READS`].
    pub const BUDGET: usize = MAX_PUBLICATION_READS;

    /// The budget the staged bytes are held to: the kernel's own
    /// [`MAX_TXN_BYTES`], so a request priced past it never reaches the
    /// kernel's `txn_over_budget` (M6: "met only by a bug or a race").
    pub const BYTE_BUDGET: u64 = MAX_TXN_BYTES;

    /// The budget the store holds a shot's units to: M5's own
    /// [`MAX_REINSERTED_UNITS`]. No comparison here reads it — the shot's
    /// refusal past it is the store's — it stands beside the figure so an
    /// answer built off the price states the number the store refuses at.
    pub const UNIT_BUDGET: u64 = MAX_REINSERTED_UNITS as u64;

    /// The budget the store holds the distinct positions a shot re-inserts
    /// to: M5's own [`MAX_REINSERTED_VALUES`]. The price carries no count of
    /// the positions — they are request arithmetic a caller does itself
    /// ([`Shot::reinserted_values`]) — and states the budget they are held
    /// to, for the reason [`ReadPrice::UNIT_BUDGET`] is stated.
    pub const POSITION_BUDGET: u64 = MAX_REINSERTED_VALUES as u64;

    /// Returns the reads' price: `homes × entries + rewindow + fence`,
    /// saturating.
    pub fn total(&self) -> usize {
        self.homes.saturating_mul(self.entries).saturating_add(self.rewindow).saturating_add(self.fence)
    }

    /// Returns whether the reads are priced past [`ReadPrice::BUDGET`].
    pub fn reads_over_budget(&self) -> bool {
        self.total() > Self::BUDGET
    }

    /// Returns whether the staged bytes are priced past
    /// [`ReadPrice::BYTE_BUDGET`].
    pub fn bytes_over_budget(&self) -> bool {
        self.staged_bytes > Self::BYTE_BUDGET
    }

    /// Returns whether the price is past either budget.
    ///
    /// The one comparison against the budgets (PATTERNS SP-23): a transport
    /// refuses where this answers `true` and reads the terms off the price
    /// — and which bound was passed, [`ReadPrice::reads_over_budget`] and
    /// [`ReadPrice::bytes_over_budget`] — for its refusal's detail. The
    /// units are not judged here: past their budget the shot is refused by
    /// the store under its own code, before it stages a record, and a
    /// refusal ahead of the lock would answer another.
    pub fn over_budget(&self) -> bool {
        self.reads_over_budget() || self.bytes_over_budget()
    }
}

/// Prices a publication over `world`: [`ReadPrice`]'s four read terms, its
/// staged bytes and its units, read off the snapshot a transport admits on,
/// ahead of its lock, as `caller` at the visibility class `readable`.
///
/// The caller's link-holding homes are [`homes_under`] of the caller's
/// account (one seek per home found, the account's prefix read off M3's
/// principal table); a caller that is no principal — `Caller::System`, which
/// no request path carries — has no account and so no homes. The entries
/// and the fence's stabs are request arithmetic, the stabs counted off the
/// one grouping the fence walks ([`Shot::reinserted_runs_by_draft`]). The
/// re-window is priced per document the commit re-windows, in two reads:
/// THE PIECES each placed run is cut into — the pairing's bound for a
/// draft-native run, one stab of every home's records for a stray, the
/// records `readable` admits the home of — read
/// once beside the staged bytes, which [`price_staged_bytes`] prices off
/// the same pieces from the table; and THE RUNS, each re-windowed
/// document's content run count by M5's one map lookup, made of the
/// documents `readable` admits and of no other. No run-list is
/// walked for the price: a place that cuts a run costs the commit nothing a
/// step a piece does not cover. THE UNITS are M5's own count of the shot's
/// re-insert over `world`'s stored content ([`Shot::reinserted_units`]):
/// the positions asked first, by arithmetic, and past their budget nothing
/// read; then one walk of the stored pieces of the draft-native runs'
/// unminted portions, at most [`ReadPrice::POSITION_BUDGET`] pieces, which
/// answers the units figure and the bytes the re-insert is priced at —
/// each unit at its own bytes — so the figure answered and the bytes
/// priced are one count's. `steps` is charged one for every stored piece
/// that count reads; a caller that counts nothing hands it a count that
/// compiles away.
///
/// **The class.** `readable(world, doc)` answers whether the caller reads
/// `doc`, and is the class the commit of the same request would read at —
/// the write's own visibility class for the transport's refusal ahead of
/// its lock, the request's read predicate for a price asked as a read. A
/// stray place is counted at it and at no other: a correspondence record
/// homed in a document the caller may not read is no piece and adds
/// nothing to any figure, so the answer is the same whatever such a
/// document holds. THE UNITS are counted at it too
/// (`sizes::reinsert_tally`): the named drafts' stored pieces are read only
/// where `readable` admits every draft the shot names, and where it does
/// not admit one the re-insert is priced no unit and no byte and no piece
/// is read — a transport's refusal ahead of its lock is answered before the
/// store has asked who owns a draft, so without the class its bytes would
/// tell a caller how a draft it may not read holds its content. Such a shot
/// stages nothing: the store's ω of every named draft refuses it ahead of
/// its count. THE RUNS are counted at it draft by draft (`rewindow_steps`):
/// a re-windowed draft `readable` does not admit adds its placed pieces and
/// no run to the re-window's steps, and one it admits beside it its own.
/// And AN ORIGINAL's STORED TYPE is read at it (`sizes::staged_bytes`): the
/// fresh mark over an `originals` entry's rest is priced at the original's
/// type slot only where `readable` admits the original's home, and at the
/// figure of an address where no link stands where it does not, so the
/// bytes do not tell a link the caller may not read from no link at all.
/// Neither request stages what the price leaves out — the first is refused
/// by ω of the draft, the second by the plan, the original not the
/// caller's own — so every figure answered is the same whatever a document
/// the caller may not read holds, and the price stays a bound.
///
/// The counts may move between this read and the composite's own, where
/// the transport takes its lock after it (the survey's C8): the budget is
/// conservative by design, and the composite reads under the lock exactly
/// as it did before it was priced.
///
/// [`homes_under`]: crate::LinkState::homes_under
#[allow(clippy::too_many_arguments)]
pub fn price_publication_reads<W: LinkWorld + HasM5 + ReinsertWorld>(
    world: &W,
    caller: Caller,
    readable: &Visibility<'_, W>,
    target: &PublishTarget,
    shot: &Shot,
    places: &[Option<VPos>],
    also_places: &[AlsoPlaces],
    deposits: &PublishDeposits,
    steps: &mut impl FnMut(u64),
) -> ReadPrice {
    let homes = match caller {
        Caller::Principal(p) => world
            .m3()
            .principal_prefix(p)
            .map_or(0, |account| world.links().homes_under(&enc([account])).len()),
        Caller::System => 0,
    };
    let pieces = sizes::run_pieces(world, readable, shot, |index| sizes::placed_in(places, also_places, index) > 0);
    let by_draft = also_places_by_draft(also_places);
    let rewindows = rewindows(shot, places, &by_draft);
    // The re-insert, counted once and at the caller's class: its units are
    // the figure, and they and their bytes what the staged bytes price it
    // at — nothing, where the class does not admit a named draft.
    let units = sizes::reinsert_tally(world, readable, shot, steps);
    ReadPrice {
        homes,
        entries: deposits
            .links
            .len()
            .saturating_add(deposits.originals.len())
            .saturating_add(deposits.read_with.len())
            .saturating_add(deposits.supersede.len()),
        rewindow: rewindows
            .iter()
            .map(|rewindow| rewindow_steps(world, readable, shot, rewindow, &pieces))
            .fold(0usize, usize::saturating_add),
        fence: shot.reinserted_runs_by_draft().iter().map(|(_, runs)| runs.len()).fold(0usize, usize::saturating_add),
        staged_bytes: sizes::staged_bytes(world, readable, target, shot, places, also_places, deposits, &pieces, &rewindows, units),
        units: units.units,
    }
}

/// Returns the steps of one document's re-window, as the reads' price
/// charges them at the class `readable`: its content runs, where the class
/// admits the document, and the pieces its lists place, summed, saturating.
///
/// The runs are the document's content run count, one map lookup off the
/// snapshot, made only where `readable` admits the document; the pieces
/// [`sizes::RunPieces::pieces`] of each run a list carries a place at,
/// summed over the document's lists. It is what the commit walks for the
/// document: one walk of its run-list, which checks every place and is made
/// once whatever the places number, and a step a piece compared and put in.
///
/// **The class**, for the run count. How many runs a draft's content lies in
/// is a fact about that draft, and the price is answered ahead of the
/// store's ω of it, so the count is read at the caller's own class and of
/// no other document: a draft `readable` does not admit adds no run and is
/// not looked up, whatever it holds, while one it admits — re-windowed
/// beside it by the same shot — adds its own. The pieces stay either way:
/// a draft-native run's are request arithmetic, and a stray's are counted
/// at this class already (`sizes::run_pieces`). The price stays a bound on
/// what a request's commit walks: a principal's class admits every draft it
/// owns, so a shot naming one its class does not admit is refused at the
/// shot's admission, ω of every named draft, before any draft is
/// re-windowed (`Caller::System` alone passes ω, and no request path
/// carries it).
fn rewindow_steps<W: HasM5>(
    world: &W,
    readable: &Visibility<'_, W>,
    shot: &Shot,
    rewindow: &Rewindow<'_>,
    pieces: &[sizes::RunPieces],
) -> usize {
    let (draft, lists) = rewindow;
    let placed = lists
        .iter()
        .flat_map(|list| placed_runs(shot, list))
        .map(|(index, _, _)| usize::try_from(pieces[index].pieces()).unwrap_or(usize::MAX))
        .fold(0usize, usize::saturating_add);
    let runs = if readable(world, draft) { world.m5().content_run_count(draft) } else { 0 };
    runs.saturating_add(placed)
}

/// Returns the runs `list` carries a place at, each with its index and its
/// place, in `runs`' order — an entry past the runs being nothing's, as the
/// re-window reads it.
fn placed_runs<'a>(
    shot: &'a Shot,
    list: &'a [Option<VPos>],
) -> impl Iterator<Item = (usize, &'a VPos, &'a ShotRun)> + 'a {
    list.iter()
        .zip(&shot.runs)
        .enumerate()
        .filter_map(|(index, (place, entry))| place.as_ref().map(|place| (index, place, entry)))
}

impl From<HomeFault> for PublicationError {
    fn from(e: HomeFault) -> Self {
        match e {
            HomeFault::NotRegistered => PublicationError::HomeNotRegistered,
            HomeFault::NotOwner(a) => PublicationError::NotOwner(a),
        }
    }
}

impl From<EmitCoreError> for PublicationError {
    // The record, the edition claim, a copy, a read-with and a rest's fresh
    // mark take the Open gate over a type slot the plan found non-empty —
    // the mark's the stored type of a resident link, which the gate that
    // deposited it held non-empty; the two claims — a copy's over its
    // original, a daughter's over the member — take the Managed gate over
    // the registry-fixed `[K_sup]` class and the retractions — a `retract`
    // target's, an original's — the Retraction gate over the shipped `[R]`
    // class, each Binary over a tuple built one address a side — so of the
    // gate's verdicts only Home and Mint are reachable.
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::Home(f) => f.into(),
            EmitCoreError::Mint(m) => PublicationError::Mint(m),
            EmitCoreError::EmptyType
            | EmitCoreError::NotRegistered
            | EmitCoreError::ShapeViolation
            | EmitCoreError::RetractionClass => unreachable!(
                "the publication's deposits take the Open gate over a type the plan found \
                 non-empty, the Managed gate over the registry-fixed claim and the Retraction \
                 gate over the shipped retraction tuple: no gate verdict but Home and Mint"
            ),
        }
    }
}

/// Stages a publication into the caller's transaction: the edition where
/// the request mints one, the shot, for every piece of draft identity it
/// minted one correspondence record in the named draft whose identity the
/// piece was, every public deposit the request carries as the plan holds
/// it, every original the private rider ends, and every named draft's
/// re-window at the kept places the request
/// carries for it — the rendering draft's in `places`, each `also` draft's
/// in its `also_places` entry.
///
/// It is the link-sets design's ONE COMMIT (§5.7) as a function over a
/// caller-opened [`Staging`], the form every store op a composite may need
/// takes (PATTERNS SP-30), so a wider composite stages it under one
/// transaction with its own. In order:
///
/// 1. THE MINT, at the mint form ([`PublishTarget::Mint`]): ω of `account`
///    — registered, the caller's — then the edition minted under it, born
///    published, through M3's staging mint; the shot's `doc` is then the
///    edition, which the admission below finds registered, published and
///    memberless in the working world (M5's `mint_admission` states that
///    agreement). Refused `Publish(DocNotRegistered)`, `Publish(NotOwner)`
///    carrying the account, or `Mint`.
/// 2. THE SHOT's OWN TABLE: M5's admission through its source gate
///    ([`shot_admission`], asked of the working world) — `doc`'s
///    registration and ω, each named draft's registration and ω in the
///    request's order (the unowned-draft edge, per home: a draft the caller
///    does not own, `draft` or one `also` names, is refused `NotOwner`
///    carrying it here, ahead of every readability question), the runs, the
///    source gate. Refused as `Publish`.
/// 3. THE TWIN FENCE, reading nothing but `stg.working()` and staging
///    nothing: PER NAMED DRAFT — the rendering draft first, then each `also`
///    draft, in the request's order, each once — for each draft-native run
///    of that draft's identity (`Shot::reinserted_runs_by_draft`, every
///    draft's runs grouped in one pass over the request), the
///    correspondence records homed in THAT draft whose `from` overlaps
///    the run's I-span — one home's stab of the FROM slot
///    ([`match_links_in`], `O(log n)` per probe plus the home's hits and
///    nothing of any other home's), each hit kept by the stored type slot's
///    exact test ([`is_correspondence_class`]: a link typed the parent
///    `counterpart` is an ordinary link and no record), on the active view.
///    Any hit refuses `AlreadyPublished`, its `site` the member the record's
///    `to` was minted into — so a sub-run of published words, split from its
///    run by an edit on a stale device, is no way past, at every principal
///    and from whichever draft of the family. It costs the request's
///    overlaps, one stab per run, never any draft's history. A shot naming
///    no draft at all reads nothing here and mints no record.
/// 4. THE CLAIM's PRECONDITION, then THE DEPOSIT PLAN, both over
///    `stg.base()`. The edition claim is a first version's alone, written
///    in the commit that gives the edition its first member: at the
///    document form a request whose deposits claim is refused
///    `Publish(ClaimRefused)` naming the edition where `doc`'s trunk
///    already holds a member — the trunk's head, the read the shot's
///    admission makes of the base (skep #692); a shot off the bare document
///    onto such a chain lands as the first member's daughter and is refused
///    here all the same where it claims, the claim being no daughter's; the
///    mint form's edition is memberless by construction. Then the plan
///    ([`plan_deposits`]) — THE VALIDATION's (3), (4), (4′), (5) and (6),
///    the first fault in list order refusing the whole as `Plan`, (6)
///    refusing
///    a `supersede` list whole, `head_moved`, where a member stands and the
///    base is not the trunk's head, so every supersession claim staged
///    below names the trunk's next member — the same world the daemon's
///    composer read for the body it checked the signature against (the
///    survey's C8: under the serialization lock the admission's snapshot is
///    the base), so the deposits staged below are the deposits the
///    signature covers, by one function over one world; the claim's row
///    among them, homed in the edition by tag where the commit mints it and
///    by address where `doc` names it; the rider's originals beside the
///    homes, in no row.
/// 5. THE SHOT: [`stage_publish`] — the admission again, one answer (its
///    card states why), the re-insert's count, the existence walk, the
///    placement with each draft identity minted once, the member's mint and
///    its placing record — returning the member and the pairing. The
///    member's `ShotPlace` is staged here, ahead of every link homed in the
///    member below (the survey's C14).
/// 6. THE RECORDS: for each MINTED piece of the pairing, in minting order,
///    one record homed in the named draft whose identity the piece was —
///    the pairing's `home`, the rendering draft for its runs and an `also`
///    draft for its own (A-328: the client writes none) — through
///    [`stage_correspondence`] — `from` the piece's draft-native span, `to`
///    the fresh span it became, both the permanent I-spans they are, of one
///    width — its positions rising in minting order within each home, each
///    seated in its home's link subspace; a piece placed by reference to an
///    identity an earlier entry minted is the first's record's and takes
///    none. A shot that names no draft, or re-inserts nothing, stages no
///    record.
/// 7. THE DEPOSITS (`stage_deposits`), home by home in the plan's order
///    and inside each home in its order, each through the one deposit gate
///    under the gate its class takes: the edition claim (`Gate::Open`,
///    typed the edition class, `from` the edition's own unit span, `to` the
///    origin draft — the R20 shape `edition_claims` reads — seated); each
///    copy (`Gate::Open`, its tags resolved to the minted member and
///    edition and its member-position ends to the fresh I-spans through the
///    member's image, [`resolve_end`]; seated) and then its claim
///    (`supersession_claim(old, copy)` under `Gate::Managed` in `old`'s
///    home, as `editlink` deposits its — the residence of `old` read off
///    the base by the plan, the claim after the copy, the public schema
///    check skipped, its dedup a guaranteed miss, the survey's C15); each
///    retraction (`retraction_tuple(home, target)` under `Gate::Retraction`
///    at the target's home, as `nullify` deposits it, unseated as `nullify`
///    leaves it); each read-with (`Gate::Open`, `{home: S, ty: rw, from:
///    unit(E), to: unit(S)}`, seated); each supersession claim
///    (`supersession_claim(daughter, member)` under `Gate::Managed` in the
///    trunk, as `assert_sup` deposits its claim — `new` the member THIS
///    commit minted at step 5, the trunk's next, the plan having refused a
///    base the trunk moved past; the claim's dedup a guaranteed miss,
///    unseated as `assert_sup` leaves it; the merge bridge lane, brief A).
///    Every deposit's home passes the gate's registration and ω check, so
///    a home the plan did not read is refused `NotOwner` with its address.
///    A request carrying no deposit stages none here and commits as S2
///    left it.
/// 8. THE ORIGINALS the private rider ends (`stage_originals`; the
///    link-sets design §5.7 (vi′)), in declared order, each in the
///    original's own home — a private document of the caller's the plan
///    read: where the entry names a rest, the fresh mark the plan built
///    (`Gate::Open`, the original's type over exactly the rest's spans, as
///    `makelink` deposits a draft's own formatting; seated), then the
///    original's retraction (`retraction_tuple(home, old)` under
///    `Gate::Retraction`, as `nullify` deposits it, unseated) — so the
///    mark's address rises ahead of the retraction's within the home (THE
///    PIN), the words still published keep the formatting through their
///    copy, the words never published keep it as the draft's own, and the
///    words taken off lose it. Private writes, outside the signed body;
///    the plan found each original active, so no incumbent retraction
///    answers.
/// 9. THE RE-WINDOW, last (`stage_rewindow`), of EVERY NAMED DRAFT at its
///    own kept places (the design's §5.7 (viii), the Nelson way): first THE
///    RENDERING DRAFT at `places`, then EACH `also` DRAFT at its
///    `also_places` entry, in `also`'s order — each document once: two
///    lists naming one document, which no request the wire admits does,
///    re-window it at the places of both, the later list's entries behind
///    the earlier's. Within one draft, for each `runs` entry
///    that carries a kept place in that draft's list — the V-position the
///    run held in THAT draft when the client composed the request, outside
///    the signed preimage as `draft` is — the check that
///    the draft still arranges that run's draft words at that place, every
///    place checked on one walk of the draft's run-list and the earliest
///    failing entry in `runs`' order answering, then
///    their replacement there by the published identity, all of the draft's
///    places in one record, a run a piece: a
///    named draft's entry's pieces are the pairing's for that entry
///    (`piece.index == index`), the fresh runs it became — THE SAME PIECES
///    whichever named draft is re-windowed at the entry, the rendering draft
///    arranging an `also` draft's identity by identity and the `also` draft
///    natively; a STRAY entry's — a run of published identity no pairing
///    holds, the document's own or another document's, re-composed by
///    reference to a correspondence record's `to` — are the records' (the
///    child module `stray`): every correspondence record the caller may read
///    whose `to` covers the run, wherever homed — the rendering draft's, an
///    `also` draft's, a granted draft's — the draft words each names as its
///    `from`; a stray run no record the caller may read covers whole refuses
///    `StrayPlaceUnrecorded` with the entry and the draft. A named draft no
///    list carries a place for is left as it stands: "each shows the words
///    it contributed as a COUNTERPART from then on, through the record the
///    shot homed in it (P57) … and is healed at its own next shot by the
///    stray path". A request with no place in any list is today's shot,
///    writing nothing of any draft. NO `also` DRAFT's RECORDED BASE MOVES:
///    the fold moves the rendering draft's base alone to the member it
///    renders (M5's `ShotPlace`, its `draft`) — a re-windowed `also` draft
///    stands behind the member it now windows, the designed outcome — and
///    only where the shot is that draft's own publication: a shot setting
///    `keep_base` (skep #944) moves no base at all, so its rendering draft,
///    re-windowed at `places` as ever, stands behind the member as an
///    `also` draft does.
///
/// `places` is parallel to `shot.runs` by index, each entry the run's place
/// in the rendering draft or `None`; each `also_places` entry's list is
/// parallel the same way, the place in THAT draft; a shorter list is read
/// as padded with `None`, and an entry past the runs is nothing's and is
/// ignored. A place in the rendering draft's list belongs to a run of ANY
/// named draft's identity — its own, or an `also` draft's, which the
/// rendering draft arranges by identity — or to a run of any published
/// document's — the document's own trunk, or another document whose words
/// the draft holds by transclusion; a place in an `also` draft's list to a
/// run of that draft's own identity or to a run of a published document's,
/// the wire's codec refusing one beside the rendering draft's or another
/// `also` draft's run (`malformed`, with the entry). Below that door a
/// placed run no pairing holds is re-windowed through the records or
/// refused `StrayPlaceUnrecorded` — an ordinary window, which no record
/// names, is refused, never silently kept; every placed run is checked as
/// any place is against the draft being re-windowed, which arranges that
/// identity there or refuses `KeptPlaceMoved` naming it; a list with no
/// draft named is ignored with the re-window, which has no draft to window.
///
/// The caller's lock keys are the union of the shot's
/// ([`stage_publish`]'s card), each named draft's `link_lock_key` where
/// records will be minted in it (a run of its identity re-inserted), each
/// re-windowed draft's `content_lock_key` — the rendering draft's where
/// `places` carries a place, each `also` draft's where its `also_places`
/// entry does — `link_lock_key` of every home a deposit names by address,
/// of every original's home, and
/// the account's `document_lock_key` at the mint form —
/// [`LinkWriter::publication`] supplies exactly that. The visibility class
/// `readable` is the caller's: the shot's source gate consults it per
/// origin, every deposit's gate is handed it as every deposit's is — the
/// claim's dedup runs at it, a guaranteed miss — and the re-window's stray
/// read keeps a record only where it admits the record's home.
///
/// Returns the member and the pairing [`stage_publish`] returned beside it,
/// for a wider composite that places the pieces itself.
///
/// # Errors
///
/// In the order above, as the bare [`PublicationError`] the caller's
/// transaction answers as `TxnError::Rejected`: the mint's (`Publish`,
/// `Mint`), the shot's admission (`Publish`), the fence
/// (`AlreadyPublished`), the claim's precondition (`Publish(ClaimRefused)`
/// with the edition), the plan's (`Plan`), the shot's staging
/// (`Publish`), a record's or a deposit's backstops (`HomeNotRegistered`,
/// `NotOwner`) and its `Mint` and `Seat` — and `Plan(SlotTooLarge)` where a
/// member-position end resolves to more spans than a slot holds, which the
/// request's own run count cannot tell ahead of the mint — then the
/// re-window's (`Reinstate` carrying a draft's gate, then `StrayPlaceUnrecorded`
/// and `KeptPlaceMoved` with the entry and the draft — `stage_rewindow`
/// states which are reachable), the rendering draft's first and then each
/// `also` draft's in `also`'s order. An `Err` commits nothing of the
/// transaction.
///
/// # Panics
///
/// As [`stage_publish`]: where `readable` calls `transact` on the caller's
/// kernel.
///
/// [`match_links_in`]: crate::LinkState::match_links_in
#[allow(clippy::too_many_arguments)]
pub fn stage_publication<W>(
    stg: &mut Staging<W>,
    caller: Caller,
    target: &PublishTarget,
    shot: &Shot,
    places: &[Option<VPos>],
    also_places: &[AlsoPlaces],
    deposits: &PublishDeposits,
    readable: &Visibility<'_, W>,
) -> Result<(Address, Pairing), PublicationError>
where
    W: PublishWorld + LinkWorld,
    W::Record: From<LinkRec>,
{
    // 1. The mint, first of all: the edition under the account.
    let (doc, edition): (Address, Option<Address>) = match target {
        PublishTarget::Document(doc) => (doc.clone(), None),
        PublishTarget::Mint { account, .. } => {
            let m3 = stg.working().m3();
            if !m3.is_registered_account(account) {
                return Err(skep_arrangement::PublishError::DocNotRegistered.into());
            }
            if !caller.is_owner(m3, account) {
                return Err(skep_arrangement::PublishError::NotOwner(account.clone()).into());
            }
            // The edition minted here has no chain for a base to lie in:
            // the mint form is the birth shape alone, as M5's
            // `mint_admission` refuses it ahead of the mint.
            if shot.base.is_some() {
                return Err(skep_arrangement::PublishError::BaseNotInChain.into());
            }
            let (edition, rec) = m3.mint_document(account, true).map_err(PublicationError::Mint)?;
            stg.push(rec.into());
            (edition.clone(), Some(edition))
        }
    };
    let doc = &doc;
    // 2. The shot's own table, ahead of the fence: ω speaks first, and a
    //    draft the caller does not own discloses none of its records.
    shot_admission(stg.working(), caller, doc, shot, readable)?;
    // 3. The twin fence, per named draft: each draft's own records, read
    //    for the runs of its identity — the rendering draft's first, then
    //    each `also` draft's, in the request's order.
    {
        let ty = enc([correspondence_type()]);
        let world = stg.working();
        let links = world.links();
        for (draft, runs) in shot.reinserted_runs_by_draft() {
            for run in runs {
                let span = run.iextent();
                for hit in links.match_links_in(&draft, (FROM, [&span]), &[(TYPE, &ty)], View::Active) {
                    let Some(record) = links.readlink(&hit) else { continue };
                    if !is_correspondence_class(record.type_slot()) {
                        continue; // the parent type, an ordinary link: no record
                    }
                    let site = member_of_span(world, record.to_slot()).unwrap_or_else(|| draft.clone());
                    return Err(PublicationError::AlreadyPublished { site });
                }
            }
        }
    }
    // 4. The claim's precondition, then the deposit plan, both on the base
    //    the daemon's composer read: at the document form the edition claim
    //    is admitted into an edition holding no member yet, and refused,
    //    naming the edition, where the trunk's head stands.
    if deposits.claim && !target.mints() && trunk_head(stg.base().m3(), doc).is_some() {
        return Err(skep_arrangement::PublishError::ClaimRefused(trunk_of(doc)).into());
    }
    let plan = plan_deposits(stg.base(), caller, target, shot, deposits)?;
    // 5. The shot.
    let (member, pairing) = stage_publish(stg, caller, doc, shot, readable)?;
    // 6. The records, one per minted piece, in minting order, each homed in
    //    the named draft whose identity the piece was (`MintedRun::home`).
    for piece in pairing.iter().filter(|piece| piece.minted) {
        stage_correspondence(stg, readable, caller, &piece.home, &piece.from, &piece.to)?;
    }
    // 7. The deposits, exactly as planned.
    stage_deposits(stg, readable, caller, &plan, &member, edition.as_ref(), &trunk_of(doc), shot, &pairing)?;
    // 8. The originals the rider ends, each at its own home: the rest's
    //    fresh mark where one stands, then the retraction.
    stage_originals(stg, readable, caller, &plan.originals)?;
    // 9. The re-window, last: the rendering draft at `places`, then each
    //    `also` draft at its own list, in `also`'s order, each document
    //    once — every stray read at the caller's own visibility class.
    for rewindow in rewindows(shot, places, &also_places_by_draft(also_places)) {
        stage_rewindow(stg, readable, caller, &rewindow, shot, &pairing)?;
    }
    Ok((member, pairing))
}

/// Stages the plan's deposits: home by home in the plan's order, inside each
/// home in its order, every tag resolved to the address the commit minted.
///
/// The body of [`stage_publication`]'s step 7, which states each deposit's
/// gate, value and seat. `edition` is the one the commit minted, at the
/// mint form; `trunk` the document the shot appends — the edition's own
/// address at the mint form, which the read-with's `from` names.
///
/// # Errors
///
/// A deposit's gate (`HomeNotRegistered`, `NotOwner`), its `Mint` and its
/// `Seat`; `Plan(SlotTooLarge)` for a member-position end resolving past the
/// slot budget; `Plan(MemberSpan)` where one fails to resolve, which the plan
/// rules out.
#[allow(clippy::too_many_arguments)]
fn stage_deposits<W>(
    stg: &mut Staging<W>,
    readable: &Visibility<'_, W>,
    caller: Caller,
    plan: &DepositPlan,
    member: &Address,
    edition: Option<&Address>,
    trunk: &Address,
    shot: &Shot,
    pairing: &Pairing,
) -> Result<(), PublicationError>
where
    W: PublishWorld + LinkWorld,
    W::Record: From<LinkRec>,
{
    let image = member_image(shot, pairing);
    for PlannedHome { home, deposits } in &plan.homes {
        let home: Address = match home {
            NamedAddress::Member => member.clone(),
            // The plan admits the edition's tag at the mint form alone.
            NamedAddress::Edition => edition.cloned().unwrap_or_else(|| trunk.clone()),
            NamedAddress::Address(a) => a.clone(),
        };
        for deposit in deposits {
            match deposit {
                PlannedDeposit::EditionClaim { origin } => {
                    let value = Link::triple(enc([&home]), enc([origin]), enc([edition_type()]));
                    let claim = emit_core(stg, readable, caller, &home, value, Gate::Open)?.minted();
                    seat(stg, &home, &claim)?;
                }
                PlannedDeposit::Copy { index, ty, from, to, claim } => {
                    let resolve = |end: &PlannedEnd| -> Result<Endset, PublicationError> {
                        let endset = resolve_end(end, member, edition, &image)
                            .ok_or(PlanFault::MemberSpan { index: *index })?;
                        if endset.len() > MAX_SLOT_SPANS {
                            return Err(PlanFault::SlotTooLarge { index: *index }.into());
                        }
                        Ok(endset)
                    };
                    let value = Link::triple(resolve(from)?, resolve(to)?, ty.clone());
                    let copy = emit_core(stg, readable, caller, &home, value, Gate::Open)?.minted();
                    seat(stg, &home, &copy)?;
                    if let Some(PlannedClaim { old, home: old_home }) = claim {
                        let value = supersession_claim(old, &copy);
                        // `minted`: the claim's I0 carries the copy, minted a
                        // line above, so no incumbent can answer.
                        emit_core(stg, readable, caller, old_home, value, Gate::Managed)?.minted();
                    }
                }
                PlannedDeposit::Retraction { target, .. } => {
                    let value = retraction_tuple(&home, target);
                    // As `nullify` deposits it: the Retraction gate, unseated.
                    // The plan found the target active, so no incumbent
                    // retraction stands; the address is taken either way.
                    emit_core(stg, readable, caller, &home, value, Gate::Retraction)?.into_address();
                }
                PlannedDeposit::ReadWith { set, .. } => {
                    let from = enc([edition.unwrap_or(trunk)]);
                    let value = Link::triple(from, enc([set]), enc([read_with_type()]));
                    let link = emit_core(stg, readable, caller, &home, value, Gate::Open)?.minted();
                    seat(stg, &home, &link)?;
                }
                PlannedDeposit::Supersede { old, .. } => {
                    // The daughter superseded by THE MEMBER THIS COMMIT
                    // MINTED — the trunk's next, the plan having refused a
                    // shot off any base but the head (`head_moved`) — as
                    // `assert_sup` deposits its claim: the Managed gate,
                    // unseated. `minted`: the claim's I0 carries the member,
                    // minted above in this transaction, so no incumbent can
                    // answer.
                    let value = supersession_claim(old, member);
                    emit_core(stg, readable, caller, &home, value, Gate::Managed)?.minted();
                }
            }
        }
    }
    Ok(())
}

/// Stages the originals the private rider ends, in declared order, each in
/// its own home: the fresh mark over the rest where the plan built one,
/// then the original's retraction.
///
/// The body of [`stage_publication`]'s step 8, which states each write's
/// gate, value and seat: the mark through the one deposit gate under
/// `Gate::Open` and seated, as `makelink` deposits a draft's own formatting
/// (the link-sets design §2, B3-S13 (1)'s form); the retraction
/// `retraction_tuple(home, old)` under `Gate::Retraction`, unseated, as
/// `nullify` deposits it — `into_address`, as the `retract` arm takes it:
/// the plan found the original active, so no incumbent stands, and the
/// address is taken either way.
///
/// # Errors
///
/// A write's gate (`HomeNotRegistered`, `NotOwner` — backstops, the plan
/// having read the home), its `Mint` and, for the mark, its `Seat`.
fn stage_originals<W>(
    stg: &mut Staging<W>,
    readable: &Visibility<'_, W>,
    caller: Caller,
    originals: &[PlannedOriginal],
) -> Result<(), PublicationError>
where
    W: PublishWorld + LinkWorld,
    W::Record: From<LinkRec>,
{
    for PlannedOriginal { old, home, rest, .. } in originals {
        if let Some(value) = rest {
            // `minted`: the Open gate runs no dedup, so no incumbent can
            // answer.
            let mark = emit_core(stg, readable, caller, home, value.clone(), Gate::Open)?.minted();
            seat(stg, home, &mark)?;
        }
        emit_core(stg, readable, caller, home, retraction_tuple(home, old), Gate::Retraction)?.into_address();
    }
    Ok(())
}

/// Seats `link` in `home`'s link subspace, as MAKELINK seats what it
/// deposits.
fn seat<W>(stg: &mut Staging<W>, home: &Address, link: &Address) -> Result<(), PublicationError>
where
    W: PublishWorld + LinkWorld,
{
    let seat = stage_seat_link(stg.working().m5(), home, link)?;
    stg.push(seat.into());
    Ok(())
}

/// Stages one draft's re-window at its kept places: for each `runs` entry
/// that carries a place in one of `lists`, the check that `draft` still
/// arranges that run's draft words there, and their replacement there by
/// the published identity — every place checked on one walk of the draft's
/// run-list, and all of them staged as one record.
///
/// It is the link-sets design's "re-window of `D` at its kept places,
/// checked by identity — and of every draft the request names beside it,
/// each at its own kept places" (§5.7 (viii)), with THE STRAY PLACES beside
/// it, run once per re-windowed document ([`Rewindow`]): `draft` the
/// rendering draft with the request's `places`, or a draft `also` names with
/// its `also_places` entry's list — the pieces the same whichever draft is
/// re-windowed, the check and the replacement asked of `draft` alone. Two
/// steps:
///
/// THE PIECES, gathered for every entry of `shot.runs` with a place in a
///     list, list by list and in `runs`' order, refusing nothing yet: each
///     entry is re-windowed as pieces, a draft-native `from` beside the
///     published `to` it stands for, of one width. A NAMED DRAFT's entry's
///     — of `draft`'s own identity, or of another named draft's which
///     `draft` arranges by identity — are its pieces of the pairing
///     [`stage_publish`] returned — the fresh runs it became, or an earlier
///     entry's where it placed the identity by reference — tiling the run
///     from its start in I-order ([`Pairing`]'s contract), found by two
///     binary searches (`plan::pieces_at`). A STRAY entry's — a run of
///     published identity no pairing holds, the document's own trunk's or
///     ANY other document's, re-composed by the client by reference to a
///     correspondence record's `to` where the draft still arranges that
///     record's `from` (the design's "AND THE STRAY PLACES WITH THEM", and
///     §5.5's counterpart first: a window onto another draft's words that
///     an earlier shot of that draft published, in this document or in
///     another) — are read off the records ([`stray::record_pieces`]):
///     every correspondence record the caller may read whose `to` covers
///     the entry's span, wherever homed — the draft's, an `also` draft's, a
///     granted draft's — each cut to the piece it covers and mapped onto
///     the same piece of its `from`. A span no record the caller may read
///     covers whole — an ordinary window onto another document, which no
///     record names, among them — is handed on with no pieces, and refused
///     in its turn below, never silently kept.
/// THE SUBSTITUTION, M5's ([`stage_substitute`]), over the entries in that
///     order. It asks the draft's gate first — its registration, its owner,
///     and the published-target refusal (a draft named outside the chain
///     need not be private) — and then judges every entry: its place in
///     the content subspace; its pieces found; and THE CHECK, that the
///     positions its place opens at resolve, in the draft as the records
///     staged so far left it (`stg.working()`), to exactly the pieces'
///     `from` runs in sequence and nothing else. The question is asked of
///     the place alone, by MEMBERSHIP: a draft that
///     arranges the identity twice is re-windowed at the named place and
///     left standing at the other, the twin fence meeting the other at its
///     own publication. The predicate implies the design's projection
///     membership — `project(D, the run's I-span)` covering the span — and
///     refuses in addition a run whose addresses the draft arranges at the
///     place in another order, and a place that overlaps the place of an
///     entry before it. The entry that answers is the EARLIEST that fails,
///     in the lists' order and within a list in `runs`' order, whichever
///     place the walk meets first. Where every entry holds, each place's
///     draft words are replaced by its pieces' `to` runs, placed by
///     identity — a published identity REINSTATE admits into a private
///     draft as any; its precondition on the origin's readability holds,
///     the record's `to` being a published member's identity, readable to
///     every caller — so the draft reads the same bytes at every position
///     and arranges the member's identity where it arranged its own: no
///     mint, no link record, the draft's link run-list untouched (links
///     move with identity, `reinstate`'s rule). A piece placed by reference
///     to an identity an earlier entry minted re-windows to the same piece
///     of the first's fresh run; a stray piece to the record's published
///     words.
///
/// Cost: per place its pieces found in the pairing, or one stab of the TO
/// slot across every home for a stray, each hit asked of `readable` once;
/// then ONE walk of the draft's run-list for every place together, and ONE
/// record ([`M5Rec::ContentEdit`](skep_arrangement::M5Rec::ContentEdit)), a
/// change a place and a run a piece, which the fold splices in one walk
/// more and R takes a span a piece from — the draft's runs and the pieces
/// placed, which [`price_publication_reads`] charges as its re-window term.
///
/// # Errors
///
/// `Reinstate` carrying the gate's verdict — `PublishedTarget` where the
/// draft is a published document, ahead of every entry; `DocNotRegistered`
/// and `NotOwner`, which the shot's admission answers first; then the
/// earliest failing entry's: `Reinstate(NotContentSubspace)` for a place
/// outside the content subspace, which the wire's codec refuses first;
/// `StrayPlaceUnrecorded { index, draft }` where a stray entry's span is not
/// covered whole by the records the caller may read; `KeptPlaceMoved {
/// index, draft }` where the check fails or the place overlaps an earlier
/// entry's — each naming `draft`, the one being re-windowed; and
/// `Reinstate` with a placed run's own (`BadRun`, `SourceNotRegistered`,
/// `DanglingSource`), which the shot's staging and the records rule out.
fn stage_rewindow<W>(
    stg: &mut Staging<W>,
    readable: &Visibility<'_, W>,
    caller: Caller,
    rewindow: &Rewindow<'_>,
    shot: &Shot,
    pairing: &Pairing,
) -> Result<(), PublicationError>
where
    W: PublishWorld + LinkWorld,
{
    let (draft, lists) = rewindow;
    // The pieces, of every placed entry: the pairing's for a named draft's
    // entry — whichever draft is being re-windowed at it — the records' for
    // a stray entry, a run of published identity no pairing holds, of
    // whichever document, read wherever homed at the caller's own
    // visibility class; none where no record covers it whole, and none read
    // for a place the substitution refuses for its subspace.
    let mut entries: Vec<Substitution> = Vec::new();
    for list in lists {
        for (index, place, entry) in placed_runs(shot, list) {
            let own = plan::pieces_at(pairing, index);
            let pieces: Option<Vec<Replacement>> = if !place.is_content() {
                None
            } else if own.is_empty() {
                stray::record_pieces(stg.working(), readable, &entry.run)
                    .map(|pieces| pieces.into_iter().map(|piece| Replacement { from: piece.from, to: piece.to }).collect())
            } else {
                Some(own.iter().map(|piece| Replacement { from: piece.from.clone(), to: piece.to.clone() }).collect())
            };
            entries.push(Substitution { index, at: place.clone(), pieces });
        }
    }
    // The substitution: the gate, every entry's check on one walk, one
    // record. Its verdicts are spelled as the codes the re-window answers.
    stage_substitute(stg, caller, draft, &entries, &mut |_| {}).map_err(|refused| match refused {
        SubstituteError::Moved { index } => PublicationError::KeptPlaceMoved { index, draft: draft.clone() },
        SubstituteError::Unrecorded { index } => PublicationError::StrayPlaceUnrecorded { index, draft: draft.clone() },
        SubstituteError::DocNotRegistered => ReinstateError::DocNotRegistered.into(),
        SubstituteError::NotOwner(doc) => ReinstateError::NotOwner(doc).into(),
        SubstituteError::PublishedTarget => ReinstateError::PublishedTarget.into(),
        SubstituteError::NotContentSubspace { .. } => ReinstateError::NotContentSubspace.into(),
        SubstituteError::BadRun { .. } => ReinstateError::BadRun.into(),
        SubstituteError::SourceNotRegistered { .. } => ReinstateError::SourceNotRegistered.into(),
        SubstituteError::DanglingSource { .. } => ReinstateError::DanglingSource.into(),
    })
}

/// Stages one correspondence record in `draft` — the named draft whose
/// identity the piece was, the rendering draft or one `also` names: `from`
/// the draft-native run, `to` the fresh run it became, typed the
/// correspondence class — and its seat.
///
/// It is the body of a deposit, in `emit_core`'s shape: the value
/// `Link::triple(from's I-span, to's I-span, enc([the correspondence
/// type]))`, both spans stored as the permanent I-spans they are, through
/// the one deposit gate under `Gate::Open` — as the `replaces` link, the
/// sibling sole-writer commons class, takes it: the class holds no
/// registration for the Managed discipline to read, no dedup section exists
/// for it, and both spans are fresh, so no incumbent could be met — then
/// the seat in the draft's link subspace ([`stage_seat_link`]), so a draft
/// published often keeps one run there. The gate's home check (registered,
/// then ω) runs as it does for every deposit; on the publication's path the
/// shot's admission asked both of the same draft already. Public, as the
/// staging functions SP-30 names are, for a composite that stages the shot
/// through [`stage_publish`] itself; the class's one writer is the
/// publication, and nothing on a request path reaches this.
///
/// # Errors
///
/// `HomeNotRegistered`, then `NotOwner` carrying the draft, from the deposit
/// gate's home check; `Mint` where the link mint fails; `Seat` where the
/// seat step refuses.
pub fn stage_correspondence<W>(
    stg: &mut Staging<W>,
    visibility: &Visibility<'_, W>,
    caller: Caller,
    draft: &Address,
    from: &Run,
    to: &Run,
) -> Result<Address, PublicationError>
where
    W: PublishWorld + LinkWorld,
    W::Record: From<LinkRec>,
{
    let value = Link::triple(
        Endset::from_spans([from.iextent()]),
        Endset::from_spans([to.iextent()]),
        enc([correspondence_type()]),
    );
    // `minted`: the Open gate runs no dedup, so no incumbent can answer.
    let addr = emit_core(stg, visibility, caller, draft, value, Gate::Open)?.minted();
    let seat = stage_seat_link(stg.working().m5(), draft, &addr)?;
    stg.push(seat.into());
    Ok(addr)
}

/// Returns the member a record's `to` span was minted into.
///
/// The span's addresses lie under the content chain of the edition the shot
/// published into (its trunk, by address arithmetic — the fresh identity is
/// minted under the trunk's chain whichever member the shot minted), so the
/// member is found among that chain's members: the trunk's, and each one's
/// daughters, enumerated off M3's version frontiers; the ones arranging the
/// span, of which the earliest minted is the shot's own — the span being
/// fresh at that shot, no earlier member arranges it, and a later one may,
/// by reference. `None` for a slot that is no content I-span of a
/// registered chain, which no record the publication wrote carries. Costs
/// the chain's member count in projections, on the fence's refusal path
/// alone.
fn member_of_span<W: HasM3 + HasM5>(world: &W, to: &Endset) -> Option<Address> {
    let span = to.spans().next()?;
    let start = validate(span.start().clone()).ok()?;
    let trunk = trunk_of(&document_of(&start)?);
    let coverage = SpanSet::singleton(span.clone());
    let (m3, m5) = (world.m3(), world.m5());
    let mut candidates: Vec<Address> = Vec::new();
    let mut queue = vec![trunk];
    while let Some(anchor) = queue.pop() {
        let Some(latest) = m3.latest_version(&anchor) else { continue };
        for member in chain_members(&latest) {
            if m5.arranges_any(&member, &coverage) {
                candidates.push(member.clone());
            }
            queue.push(member);
        }
    }
    candidates.into_iter().min_by_key(|member| m3.minted_at(member))
}

/// Returns every member of the chain `latest` closes, ascending: the
/// addresses sharing its components but the last ordinal, `1` to its own.
fn chain_members(latest: &Address) -> impl Iterator<Item = Address> {
    let mut prefix: Vec<Nat> = latest.tumbler().iter().cloned().collect();
    let bound = prefix.pop().expect("a tumbler is nonempty");
    let mut k = Nat::from(1u32);
    std::iter::from_fn(move || {
        if k > bound {
            return None;
        }
        let member = validate(Tumbler::new(prefix.iter().cloned().chain([k.clone()])).ok()?).ok();
        k += Nat::from(1u32);
        member
    })
}

impl<'k, W> LinkWriter<'k, W>
where
    W: PublishWorld + LinkWorld,
    W::Record: From<LinkRec>,
{
    /// THE PUBLICATION (the link-sets design §5.7): the publish shot, the
    /// edition where the request mints one, its correspondence records in
    /// each named draft, every public deposit the request carries, every
    /// original the private rider ends and every
    /// named draft's re-window at its own kept places in ONE commit.
    ///
    /// It opens one transaction over the union of the shot's keys —
    /// `doc`'s head key, `content_lock_key` of the document it projects to,
    /// the base's `version_lock_key` where the base is a member and the
    /// first member's where the base is the bare document — each
    /// named draft's `link_lock_key` where records will be minted in it (a
    /// run of its identity re-inserted: the rendering `draft`'s, and each
    /// `also` draft's), each re-windowed draft's `content_lock_key` — the
    /// rendering draft's where `places` carries a place, each `also` draft's
    /// where its `also_places` entry does (the re-window edits exactly those
    /// drafts' arrangements) — the
    /// `link_lock_key` of every home a deposit names by address (a `links`
    /// entry's bare home, its `old`'s home, a `retract` target's home, an
    /// `originals` entry's home, a
    /// `read_with` set, and the trunk of `doc` where the deposits claim at
    /// the document form or name a daughter superseded — the edition claim
    /// and the supersession claims are minted in its link
    /// subspace) and, at the mint form, the account's `document_lock_key`
    /// as `create_new_document` takes it — a home the commit mints has no
    /// key to name before it —
    /// sorted and deduped as `editlink`'s pair is, under this handle's
    /// attestation, and stages [`stage_publication`]: the mint, the shot's
    /// admission, the twin fence, the plan, the shot, the records, the
    /// deposits, the originals, the re-window. What the shot does and refuses is M5's
    /// `publish` word for word; what this adds is stated on the staging
    /// function. The visibility class this handle carries is the shot's
    /// `readable`, the value M10 lends M5's shot on the plain path.
    ///
    /// `places` is the request's kept places in the rendering draft,
    /// parallel to `shot.runs` by index — empty for a request that sends
    /// none; `also_places` the kept places of each draft `also` names, one
    /// [`AlsoPlaces`] per draft that is re-windowed — empty for one that
    /// re-windows no `also` draft; `deposits` the request's four lists and
    /// its private rider —
    /// empty for one that sends none. All empty, at the document form, is
    /// today's shot.
    ///
    /// Returns `(member, seq)`: the member's address, the ack's — at the
    /// mint form, the first member of the edition minted, its trunk — and
    /// the one commit's `Seq`. A caller reads the records back off each
    /// named draft's link subspace, the deposits off each home's, in
    /// minting order, and each re-windowed draft off its arrangement.
    ///
    /// # Errors
    ///
    /// Each refusal comes as `TxnError::Rejected`, in [`stage_publication`]'s
    /// order; the kernel's own failures — `Durability`, `Unencodable`,
    /// `OverBudget`, `Poisoned` — come back as `transact` returns them.
    ///
    /// # Panics
    ///
    /// As M5's `publish`: where this handle's visibility class calls
    /// `transact` on this kernel.
    pub fn publication(
        &self,
        caller: Caller,
        target: &PublishTarget,
        shot: &Shot,
        places: &[Option<VPos>],
        also_places: &[AlsoPlaces],
        deposits: &PublishDeposits,
    ) -> Result<(Address, Seq), TxnError<PublicationError>> {
        let keys = publication_lock_keys(target, shot, places, also_places, deposits);
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            stage_publication(stg, caller, target, shot, places, also_places, deposits, self.visibility)
                .map(|(member, _)| member)
        })
    }
}

/// Returns the lock keys a publication's one transaction takes, sorted and
/// deduped: the set the card on [`LinkWriter::publication`] lists, as one
/// function over the request so the set is held by a test without a kernel.
///
/// The shot's — `doc`'s head key, `content_lock_key` of the document it
/// projects to, the base's `version_lock_key` where the base is a member and
/// the first member's (`D.1`'s) where the base is the bare document — taken
/// whether or not the chain holds a member yet, since this function cannot
/// know, and while it holds none the shot mints `D.1` itself under the head
/// key every shot takes —
/// the trunk's `link_lock_key` where the deposits claim at the document form
/// or name a daughter superseded (both claims are minted in the trunk's link
/// subspace) — or the account's `document_lock_key` at the mint form; each named
/// draft's `link_lock_key` where a run of its identity is re-inserted (its
/// records are minted there — the rendering `draft`'s and each `also`
/// draft's alike); each re-windowed draft's `content_lock_key` — the
/// rendering draft's where `places` carries a place, each `also` draft's
/// where its `also_places` entry does; a named draft no list places takes
/// none, nothing being re-windowed in it; the `link_lock_key` of every home
/// a deposit names by address, and of every original's home — the rider's
/// two writes are minted there, the home key covering the retraction's
/// dedup as it does a `retract` target's. M2's own bytewise order, duplicates
/// collapsed, as `editlink` hands its pair.
fn publication_lock_keys(
    target: &PublishTarget,
    shot: &Shot,
    places: &[Option<VPos>],
    also_places: &[AlsoPlaces],
    deposits: &PublishDeposits,
) -> Vec<LockKey> {
    let mut keys = match target {
        PublishTarget::Document(doc) => {
            let trunk = trunk_of(doc);
            let mut keys = vec![head_lock_key(doc), M3State::content_lock_key(&trunk)];
            if let Some(base) = &shot.base {
                // A member's own version key; the first member's for the
                // bare document, whose daughter the shot mints once a
                // member stands.
                let frontier = if base.member == trunk { first_version_address(&trunk) } else { Some(base.member.clone()) };
                if let Some(frontier) = frontier {
                    keys.push(M3State::version_lock_key(&frontier));
                }
            }
            // The edition claim at the document form, and every
            // supersession claim, land in the trunk's link subspace, a
            // home that stands before the commit and so has a key to name.
            if deposits.claim || !deposits.supersede.is_empty() {
                keys.push(M3State::link_lock_key(&trunk));
            }
            keys
        }
        // The account's document chain, as `create_new_document` takes
        // it; the principals key it holds beside is M3's own and
        // defensive there, its ω read stale-safe on the base.
        PublishTarget::Mint { account, .. } => vec![M3State::document_lock_key(account)],
    };
    // Each named draft's link key where a run of its identity is
    // re-inserted (its records are minted there); each re-windowed draft's
    // content key — the rendering draft's where `places` carries a place,
    // each `also` draft's where its own list does.
    for (draft, runs) in shot.reinserted_runs_by_draft() {
        if !runs.is_empty() {
            keys.push(M3State::link_lock_key(&draft));
        }
    }
    let by_draft = also_places_by_draft(also_places);
    keys.extend(rewindows(shot, places, &by_draft).into_iter().map(|(draft, _)| M3State::content_lock_key(&draft)));
    for entry in &deposits.links {
        if let NamedAddress::Address(home) = &entry.home {
            keys.push(M3State::link_lock_key(home));
        }
        if let Some(home) = entry.old.as_ref().and_then(document_of) {
            keys.push(M3State::link_lock_key(&home));
        }
    }
    for target_link in &deposits.retract {
        if let Some(home) = document_of(target_link) {
            keys.push(M3State::link_lock_key(&home));
        }
    }
    for entry in &deposits.originals {
        if let Some(home) = document_of(&entry.old) {
            keys.push(M3State::link_lock_key(&home));
        }
    }
    for set in &deposits.read_with {
        keys.push(M3State::link_lock_key(set));
    }
    // M2's own bytewise order, duplicates collapsed, as `editlink` hands
    // its pair: the same set in the same sequence however it was named.
    keys.sort();
    keys.dedup();
    keys
}
