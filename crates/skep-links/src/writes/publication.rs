//! THE PUBLICATION (the link-sets design §5.7): the publish shot's one
//! commit — the member minted, the edition where the request mints one, the
//! shot's correspondence records beside it, every public deposit the request
//! carries (the accepted links as copies with their claims, the held
//! removals' retractions, the read-withs, the edition claim) and the draft
//! re-windowed at its kept places, in one transaction.
//!
//! [`stage_publication`] is the composite as a function over a caller-opened
//! staging — at the mint form the edition's mint first; the shot's admission;
//! THE TWIN FENCE; THE DEPOSIT PLAN ([`plan_deposits`], the child module
//! `plan`, read on the transaction's base); the shot's staging
//! ([`stage_publish`], M5's); per piece of draft identity the shot minted
//! one correspondence record homed in the draft ([`stage_correspondence`]);
//! THE DEPOSITS, exactly as planned, per home in the signed entry's order;
//! and THE RE-WINDOW: for each run the request carries a kept place for, the
//! check that the draft still arranges that run's identity at that place
//! and its replacement there by the fresh run it became, a placement and a
//! removal ([`stage_reinstate_at`], [`stage_delete_at`], M5's) — and
//! [`LinkWriter::publication`] the public op: one `transact_attested` over
//! the union of the shot's keys, the draft's link key, the draft's content
//! key where a place is carried, every home's link key where a deposit
//! lands, and the account's document key where an edition is minted. The
//! correspondence class has this one writer; the fences on the three
//! request-typed doors keep every other act off it. Within one commit a
//! home's link addresses rise in the order the daemon mints them — THE
//! PIN, stated at `mint_link`'s frontier read and held by
//! `tests/it/publication.rs`.
//!
//! Beside the composite sit its two bounds: [`price_publication_reads`],
//! the price of the four reads the composite makes under the lock, which a
//! transport asks of a snapshot ahead of its lock and refuses past
//! [`MAX_PUBLICATION_READS`] — the
//! composite reads as it did, the price merely bounds it — and the child
//! module `sizes`, the worst-case bytes per entry kind as the kernel prices
//! them, the table a panel prices a request's records from before the act.

use skep_address::{document_of, validate, Address, Nat, SpanSet, Tumbler};
use skep_arrangement::{
    head_lock_key, ordinal_vspan, shot_admission, stage_delete_at, stage_publish,
    stage_reinstate_at, stage_seat_link, trunk_of, Caller, HasM5, M5State, Pairing,
    PublishWorld, ReinstateError, Run, Shot, ShotRun, VPos,
};
use skep_kernel::{Seq, Staging, TxnError};
use skep_namespace::{HasM3, M3State};

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
// prices them, and the maximal request's sum against the transaction
// budget.
mod sizes;

pub use plan::{
    canonical_member_spans, edition_type, member_end, member_image, names_read_with,
    plan_deposits, read_with_in, read_with_type, request_image, resolve_end, DepositPlan, EndArg,
    LinkEntry, MemberEnd, MemberSpan, NamedAddress, PlannedClaim, PlannedDeposit, PlannedEnd,
    PlannedHome, PublishDeposits, PublishTarget,
};
pub use sizes::{
    CLAIM_BYTES, COPY_BYTES, CORRESPONDENCE_RECORD_BYTES, EDITION_CLAIM_BYTES,
    EDITION_MINT_BYTES, KEPT_PLACE_BYTES, MAXIMAL_PUBLICATION_BYTES, PLACED_RUN_BYTES,
    READ_WITH_BYTES, REINSERTED_VALUE_BYTES, RETRACTION_BYTES, SHOT_BYTES,
};

/// The price of a publication's in-lock reads: the four terms the design
/// names, read off one snapshot (the link-sets design §5.7, EVERY IN-LOCK
/// READ IS BOUNDED BY A REFUSAL AHEAD OF THE LOCK).
///
/// It is what [`price_publication_reads`] answers and a transport refuses
/// on ([`ReadPrice::over_budget`]), carried whole so the refusal can name
/// each term: the caller's link-holding home count, the entries that read
/// per home, the draft's content run count and the request's runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadPrice {
    /// The caller's link-holding homes: `homes_under` of the caller's
    /// account — every document under it holding a resident link, the
    /// plan's `own_homes` before its ownership filter, so at or above the
    /// homes the plan reads.
    pub homes: usize,
    /// The `links` entries and the `read_with` entries, summed: the entries
    /// whose read ranges over the caller's homes — (3)'s claim read and
    /// (5)'s presence read.
    pub entries: usize,
    /// The draft's content runs, `content_run_count` of the draft the shot
    /// names; `0` for a shot naming none.
    pub draft_runs: usize,
    /// The request's runs, `shot.runs.len()`: the kept-place check costs
    /// the draft's run count per placed run, and the twin fence one stab per
    /// re-inserted run, so the runs bound both.
    pub runs: usize,
}

impl ReadPrice {
    /// The budget the price is held to:
    /// [`MAX_PUBLICATION_READS`].
    pub const BUDGET: usize = MAX_PUBLICATION_READS;

    /// Returns the price: `homes × entries + draft_runs × runs`, saturating.
    pub fn total(&self) -> usize {
        self.homes
            .saturating_mul(self.entries)
            .saturating_add(self.draft_runs.saturating_mul(self.runs))
    }

    /// Returns whether the price is past [`ReadPrice::BUDGET`].
    ///
    /// The one comparison against the budget (PATTERNS SP-23): a transport
    /// refuses where this answers `true` and reads the terms off the price
    /// for its refusal's detail.
    pub fn over_budget(&self) -> bool {
        self.total() > Self::BUDGET
    }
}

/// Prices a publication's in-lock reads over `world`: [`ReadPrice`]'s four
/// terms, read off the snapshot a transport admits on, ahead of its lock.
///
/// It reads two counts of the world and two of the request, and walks
/// nothing: the caller's link-holding homes by [`homes_under`] of the
/// caller's account (one seek per home found, the account's prefix read
/// off M3's principal table), the draft's content run count by M5's one map
/// lookup, the entries and the runs off the request's lists. A caller that
/// is no principal — `Caller::System`, which no request path carries — has
/// no account and so no homes, and prices the draft term alone. The counts
/// may move between this read and the composite's own, where the transport
/// takes its lock after it (the survey's C8): the budget is conservative
/// by design, and the composite reads under the lock exactly as it did
/// before it was priced.
///
/// [`homes_under`]: crate::LinkState::homes_under
pub fn price_publication_reads<W: LinkWorld + HasM5>(
    world: &W,
    caller: Caller,
    shot: &Shot,
    deposits: &PublishDeposits,
) -> ReadPrice {
    let homes = match caller {
        Caller::Principal(p) => world
            .m3()
            .principal_prefix(p)
            .map_or(0, |account| world.links().homes_under(&enc([account])).len()),
        Caller::System => 0,
    };
    let draft_runs = shot
        .draft_document()
        .map_or(0, |draft| world.m5().content_run_count(&draft));
    ReadPrice {
        homes,
        entries: deposits.links.len().saturating_add(deposits.read_with.len()),
        draft_runs,
        runs: shot.runs.len(),
    }
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
    // The record, the edition claim, a copy and a read-with take the Open
    // gate over a type slot the plan found non-empty; the claim takes the
    // Managed gate over the registry-fixed `[K_sup]` class and the
    // retraction the Retraction gate over the shipped `[R]` class, each
    // Binary over a tuple built one address a side — so of the gate's
    // verdicts only Home and Mint are reachable.
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
/// minted one correspondence record in the draft, every public deposit the
/// request carries as the plan holds it, and the draft's re-window at the
/// kept places the request carries.
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
///    registration and ω, the draft's registration and ω (the unowned-draft
///    edge: a draft the caller does not own is refused `NotOwner` here,
///    ahead of every readability question), the runs, the source gate.
///    Refused as `Publish`.
/// 3. THE TWIN FENCE, reading nothing but `stg.working()` and staging
///    nothing: for each draft-native run of the request, the correspondence
///    records homed in the draft whose `from` overlaps the run's I-span —
///    one home's stab of the FROM slot ([`match_links_in`], `O(log n)` per
///    probe plus the home's hits and nothing of any other home's), each hit
///    kept by the stored type slot's exact test ([`is_correspondence_class`]:
///    a link typed the parent `counterpart` is an ordinary link and no
///    record), on the active view. Any hit refuses `AlreadyPublished`, its
///    `site` the member the record's `to` was minted into — so a sub-run of
///    published words, split from its run by an edit on a stale device, is
///    no way past, at every principal. It costs the request's overlaps, never
///    the draft's history.
/// 4. THE DEPOSIT PLAN ([`plan_deposits`]) over `stg.base()` — THE
///    VALIDATION's (3), (4) and (5), the first fault in list order refusing
///    the whole as `Plan` — the same world the daemon's composer read for
///    the body it checked the signature against (the survey's C8: under
///    the serialization lock the admission's snapshot is the base), so the
///    deposits staged below are the deposits the signature covers, by one
///    function over one world.
/// 5. THE SHOT: [`stage_publish`] — the admission again, one answer (its
///    card states why), the re-insert's count, the existence walk, the
///    placement with each draft identity minted once, the member's mint and
///    its placing record — returning the member and the pairing. The
///    member's `ShotPlace` is staged here, ahead of every link homed in the
///    member below (the survey's C14).
/// 6. THE RECORDS: for each MINTED piece of the pairing, in minting order,
///    one record homed in the draft through [`stage_correspondence`] —
///    `from` the piece's draft-native span, `to` the fresh span it became,
///    both the permanent I-spans they are, of one width — its positions
///    rising in minting order, each seated in the draft's link subspace; a
///    piece placed by reference to an identity an earlier entry minted is
///    the first's record's and takes none. A shot that names no draft, or
///    re-inserts nothing, stages no record.
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
///    unit(E), to: unit(S)}`, seated). Every deposit's home passes the
///    gate's registration and ω check, so a home the plan did not read is
///    refused `NotOwner` with its address. A request carrying no deposit
///    stages none here and commits as S2 left it.
/// 8. THE RE-WINDOW, last (`stage_rewindow`): for each `runs` entry that
///    carries a kept place in `places` — the V-position the run held in the
///    draft when the client composed the request, outside the signed
///    preimage as `draft` is — in `runs`' order, the check that the draft
///    still arranges that run's identity at that place, then the entry's
///    replacement there by the fresh run it became, piece by piece. A
///    request with no place — `places` empty, or every entry `None` — is
///    today's shot, writing nothing of the draft.
///
/// `places` is parallel to `shot.runs` by index, each entry the run's place
/// or `None`; a shorter list is read as padded with `None`, and an entry
/// past the runs is nothing's and is ignored. A place belongs to a
/// draft-native run alone — the wire's codec refuses one on any other run
/// (`malformed`, with the entry) — and below that door one on a run that is
/// not draft-native is checked as any place is and re-windows nothing, the
/// entry having no draft-native piece; one with no draft named is ignored
/// with the re-window, which has no draft to window.
///
/// The caller's lock keys are the union of the shot's
/// ([`stage_publish`]'s card), the draft's `link_lock_key` where records
/// will be minted, the draft's `content_lock_key` where a place is carried,
/// `link_lock_key` of every home a deposit names by address and the
/// account's `document_lock_key` at the mint form —
/// [`LinkWriter::publication`] supplies exactly that. The visibility class
/// `readable` is the caller's: the shot's source gate consults it per
/// origin, and every deposit's gate is handed it as every deposit's is —
/// the claim's dedup runs at it, a guaranteed miss.
///
/// Returns the member and the pairing [`stage_publish`] returned beside it,
/// for a wider composite that places the pieces itself.
///
/// # Errors
///
/// In the order above, as the bare [`PublicationError`] the caller's
/// transaction answers as `TxnError::Rejected`: the mint's (`Publish`,
/// `Mint`), the shot's admission (`Publish`), the fence
/// (`AlreadyPublished`), the plan's (`Plan`), the shot's staging
/// (`Publish`), a record's or a deposit's backstops (`HomeNotRegistered`,
/// `NotOwner`) and its `Mint` and `Seat` — and `Plan(SlotTooLarge)` where a
/// member-position end resolves to more spans than a slot holds, which the
/// request's own run count cannot tell ahead of the mint — then the
/// re-window's (`KeptPlaceMoved` with the entry, `Reinstate`, `Delete` —
/// `stage_rewindow` states which are reachable). An `Err` commits nothing
/// of the transaction.
///
/// # Panics
///
/// As [`stage_publish`]: where `readable` calls `transact` on the caller's
/// kernel.
///
/// [`match_links_in`]: crate::LinkState::match_links_in
pub fn stage_publication<W>(
    stg: &mut Staging<W>,
    caller: Caller,
    target: &PublishTarget,
    shot: &Shot,
    places: &[Option<VPos>],
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
    // 3. The twin fence.
    if let Some(draft) = shot.draft_document() {
        let ty = enc([correspondence_type()]);
        let world = stg.working();
        let links = world.links();
        for run in shot.reinserted_runs() {
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
    // 4. The deposit plan, on the base the daemon's composer read.
    let plan = plan_deposits(stg.base(), caller, target, shot, deposits)?;
    // 5. The shot.
    let (member, pairing) = stage_publish(stg, caller, doc, shot, readable)?;
    // 6. The records, one per minted piece, in minting order.
    if let Some(draft) = shot.draft_document() {
        for piece in pairing.iter().filter(|piece| piece.minted) {
            stage_correspondence(stg, readable, caller, &draft, &piece.from, &piece.to)?;
        }
    }
    // 7. The deposits, exactly as planned.
    stage_deposits(stg, readable, caller, &plan, &member, edition.as_ref(), &trunk_of(doc), shot, &pairing)?;
    // 8. The re-window, last.
    if let Some(draft) = shot.draft_document() {
        stage_rewindow(stg, caller, &draft, &trunk_of(doc), shot, places, &pairing)?;
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
                    emit_core(stg, readable, caller, &home, value, Gate::Retraction)?.address();
                }
                PlannedDeposit::ReadWith { set, .. } => {
                    let from = enc([edition.unwrap_or(trunk)]);
                    let value = Link::triple(from, enc([set]), enc([read_with_type()]));
                    let link = emit_core(stg, readable, caller, &home, value, Gate::Open)?.minted();
                    seat(stg, &home, &link)?;
                }
            }
        }
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

/// Stages the draft's re-window at its kept places: for each `runs` entry
/// that carries a place, the check that `draft` still arranges that run's
/// identity there, and the entry's replacement there by the fresh run it
/// became.
///
/// It is the link-sets design's "re-window of `D` at its kept places,
/// checked by identity" (§5.7), the S-gate's composite, over the pairing
/// [`stage_publish`] returned: for each entry of `shot.runs` with a place in
/// `places`, in `runs`' order —
///
/// (a) THE CHECK: the V-span of the entry's width that opens at the place
///     resolves, in the draft as the records staged so far left it
///     (`stg.working()`), to exactly the entry's run — M5's V→I resolution
///     ([`M5State::resolve`]) answering the run's addresses in its order and
///     nothing else over that span ([`arranged_at`]). The question is asked
///     of the place alone, by MEMBERSHIP (the S-gate's ruling): a draft that
///     arranges the identity twice is re-windowed at the named place and
///     left standing at the other, the twin fence meeting the other at its
///     own publication. The predicate implies the design's projection
///     membership — `project(D, the run's I-span)` covering the span — and
///     refuses in addition a run whose addresses the draft arranges at the
///     place in another order, a rearrangement within the span since the
///     place was read, which the projection cannot see and the replacement
///     would silently undo. Failing, `KeptPlaceMoved` with the entry: the
///     draft moved the run, split it, deleted it or arranges it elsewhere
///     since the place was read, and nothing is committed — never a guess.
/// (b) THE REPLACEMENT, piece by piece along the entry's pieces of the
///     pairing, each at its offset from the place (the pieces tile the run
///     from its start, in I-order — [`Pairing`]'s contract — so the offset is
///     the widths before it, summed): the fresh piece placed by identity at
///     the place plus the offset ([`stage_reinstate_at`], windowing the
///     edition's trunk, which minted it), which moves the draft-native piece
///     right by the fresh one's width; then that piece's position RE-DERIVED
///     off the working world — the fresh piece's width past its place, where
///     the placement left it, asked of the arrangement again and never
///     carried over — and the piece removed there ([`stage_delete_at`]), so
///     the draft reads the same bytes at every position and arranges the
///     member's identity where it arranged its own. A piece placed by
///     reference to an identity an earlier entry minted re-windows to the
///     same piece of the first's fresh run.
///
/// Cost: per place, one resolution of the entry's span over the draft's
/// run-list, and two records per piece.
///
/// # Errors
///
/// `Reinstate(NotContentSubspace)` for a place outside the content subspace
/// — the placement's own verdict for the position, asked ahead of the check,
/// which the wire's codec refuses first; `KeptPlaceMoved { index }` where the
/// check fails, and where the re-derivation finds the piece elsewhere than
/// the placement left it, which the check rules out; `Reinstate` with the
/// placement's own — `PublishedTarget` where the draft is a published
/// document (a draft named outside the chain need not be private),
/// `TooManyRuns` where the draft's run-list is at M5's budget; the rest
/// made unreachable by the check and the admission — and `Delete` with the
/// removal's, `PublishedTarget` alone reachable, the placement refusing it
/// first.
fn stage_rewindow<W>(
    stg: &mut Staging<W>,
    caller: Caller,
    draft: &Address,
    trunk: &Address,
    shot: &Shot,
    places: &[Option<VPos>],
    pairing: &Pairing,
) -> Result<(), PublicationError>
where
    W: PublishWorld,
{
    for (index, (entry, place)) in shot.runs.iter().zip(places).enumerate() {
        let Some(place) = place else { continue };
        if !place.is_content() {
            return Err(ReinstateError::NotContentSubspace.into());
        }
        // (a) The check, of the working world: the entry's run, at the
        //     place, in its order, and nothing else over its span.
        if !arranged_at(stg.working().m5(), draft, place, &entry.run) {
            return Err(PublicationError::KeptPlaceMoved { index });
        }
        // (b) The replacement, piece by piece at each piece's offset.
        let mut offset = Nat::from(0u32);
        for piece in pairing.iter().filter(|piece| piece.index == index) {
            let at = VPos::content(&place.ordinal + &offset);
            let fresh = ShotRun { origin: trunk.clone(), run: piece.to.clone() };
            stage_reinstate_at(stg, caller, draft, at.clone(), &[fresh])?;
            // The draft-native piece, where the placement left it: the fresh
            // piece's width past its place, read off the working world.
            let moved = VPos::content(&at.ordinal + piece.to.width());
            if !arranged_at(stg.working().m5(), draft, &moved, &piece.from) {
                return Err(PublicationError::KeptPlaceMoved { index });
            }
            stage_delete_at(stg, caller, draft, moved, piece.from.width().clone())?;
            offset = &offset + piece.from.width();
        }
    }
    Ok(())
}

/// Returns whether `doc` arranges exactly `run` over the V-span of `run`'s
/// width that opens at `at`.
///
/// It is the re-window's check by identity, asked of the arrangement `m5`
/// holds: the span resolves (M5's V→I resolution, clipped to the arranged
/// range) to runs that tile it, and they are `run`'s addresses in `run`'s
/// order and nothing else — each resolved run opening where the previous
/// one reached, the first at `run`'s start and the last reaching `run`'s
/// reach. A span opening past the arranged end, or reaching past it,
/// resolves short and answers `false`; so does one holding another address
/// among the run's, or the run's addresses in another order.
fn arranged_at(m5: &M5State, doc: &Address, at: &VPos, run: &Run) -> bool {
    let Some(span) = ordinal_vspan(at.clone(), run.width().clone()) else {
        return false; // a run's width is ≥ 1, so no span is no arrangement
    };
    let mut next = run.i_start().tumbler().clone();
    for resolved in m5.iter_resolve(doc, &span) {
        if resolved.i_start().tumbler() != &next {
            return false;
        }
        next = resolved.reach();
    }
    next == run.reach()
}

/// Stages one correspondence record in `draft`: `from` the draft-native
/// run, `to` the fresh run it became, typed the correspondence class — and
/// its seat.
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
    /// edition where the request mints one, its correspondence records,
    /// every public deposit the request carries and the draft's re-window
    /// at its kept places in ONE commit.
    ///
    /// It opens one transaction over the union of the shot's keys —
    /// `doc`'s head key, `content_lock_key` of the document it projects to,
    /// the base's `version_lock_key` where the base is a member — the
    /// draft's `link_lock_key` where records will be minted (a draft named
    /// and a run re-inserted), the draft's `content_lock_key` where `places`
    /// carries a place (the re-window edits the draft's arrangement), the
    /// `link_lock_key` of every home a deposit names by address (a `links`
    /// entry's bare home, its `old`'s home, a `retract` target's home, a
    /// `read_with` set) and, at the mint form, the account's
    /// `document_lock_key` as `create_new_document` takes it — a home the
    /// commit mints has no key to name before it —
    /// sorted and deduped as `editlink`'s pair is, under this handle's
    /// attestation, and stages [`stage_publication`]: the mint, the shot's
    /// admission, the twin fence, the plan, the shot, the records, the
    /// deposits, the re-window. What the shot does and refuses is M5's
    /// `publish` word for word; what this adds is stated on the staging
    /// function. The visibility class this handle carries is the shot's
    /// `readable`, the value M10 lends M5's shot on the plain path.
    ///
    /// `places` is the request's kept places, parallel to `shot.runs` by
    /// index — empty for a request that sends none; `deposits` the request's
    /// three lists — empty for one that sends none. Both empty, at the
    /// document form, is today's shot.
    ///
    /// Returns `(member, seq)`: the member's address, the ack's — at the
    /// mint form, the first member of the edition minted, its trunk — and
    /// the one commit's `Seq`. A caller reads the records back off the
    /// draft's link subspace, the deposits off each home's, in minting
    /// order, and the re-windowed draft off its arrangement.
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
        deposits: &PublishDeposits,
    ) -> Result<(Address, Seq), TxnError<PublicationError>> {
        let mut keys = match target {
            PublishTarget::Document(doc) => {
                let trunk = trunk_of(doc);
                let mut keys = vec![head_lock_key(doc), M3State::content_lock_key(&trunk)];
                if let Some(base) = &shot.base {
                    if base.member != trunk {
                        keys.push(M3State::version_lock_key(&base.member));
                    }
                }
                keys
            }
            // The account's document chain, as `create_new_document` takes
            // it; the principals key it holds beside is M3's own and
            // defensive there, its ω read stale-safe on the base.
            PublishTarget::Mint { account, .. } => vec![M3State::document_lock_key(account)],
        };
        if let Some(draft) = shot.draft_document() {
            if shot.reinserted_runs().next().is_some() {
                keys.push(M3State::link_lock_key(&draft));
            }
            if places.iter().any(Option::is_some) {
                keys.push(M3State::content_lock_key(&draft));
            }
        }
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
        for set in &deposits.read_with {
            keys.push(M3State::link_lock_key(set));
        }
        // M2's own bytewise order, duplicates collapsed, as `editlink` hands
        // its pair: the same set in the same sequence however it was named.
        keys.sort();
        keys.dedup();
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            stage_publication(stg, caller, target, shot, places, deposits, self.visibility)
                .map(|(member, _)| member)
        })
    }
}
