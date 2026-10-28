//! THE PUBLICATION (the link-sets design §5.7): the publish shot's one
//! commit, the member minted, the shot's correspondence records beside it,
//! and the draft re-windowed at its kept places, in one transaction.
//!
//! [`stage_publication`] is the composite as a function over a caller-opened
//! staging — the shot's admission, THE TWIN FENCE, the shot's staging
//! ([`stage_publish`], M5's), per piece of draft identity the shot minted one
//! correspondence record homed in the draft ([`stage_correspondence`]), and
//! THE RE-WINDOW: for each run the request carries a kept place for, the
//! check that the draft still arranges that run's identity at that place
//! and its replacement there by the fresh run it became, a placement and a
//! removal ([`stage_reinstate_at`], [`stage_delete_at`], M5's) — and
//! [`LinkWriter::publication`] the public op: one `transact_attested` over
//! the union of the shot's keys, the draft's link key and, where a place is
//! carried, the draft's content key. The correspondence class has this one
//! writer; the fences on the three request-typed doors keep every other act
//! off it.

use skep_address::{document_of, validate, Address, Nat, SpanSet, Tumbler};
use skep_arrangement::{
    head_lock_key, ordinal_vspan, shot_admission, stage_delete_at, stage_publish,
    stage_reinstate_at, stage_seat_link, trunk_of, Caller, HasM5, M5State, Pairing,
    PublishWorld, ReinstateError, Run, Shot, ShotRun, VPos,
};
use skep_kernel::{Seq, Staging, TxnError};
use skep_namespace::{HasM3, M3State};

use super::{
    correspondence_type, emit_core, is_correspondence_class, EmitCoreError, Gate, HomeFault,
    LinkWriter, Visibility,
};
use crate::endset::{enc, Endset, Link};
use crate::error::PublicationError;
use crate::state::{LinkRec, View, FROM, TYPE};
use crate::LinkWorld;

impl From<HomeFault> for PublicationError {
    fn from(e: HomeFault) -> Self {
        match e {
            HomeFault::NotRegistered => PublicationError::HomeNotRegistered,
            HomeFault::NotOwner(a) => PublicationError::NotOwner(a),
        }
    }
}

impl From<EmitCoreError> for PublicationError {
    // Open: only EmptyType/Home/Mint reachable, and EmptyType is dead too —
    // the record's type slot is the one commons value, spelled here.
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::Home(f) => f.into(),
            EmitCoreError::Mint(m) => PublicationError::Mint(m),
            EmitCoreError::EmptyType
            | EmitCoreError::NotRegistered
            | EmitCoreError::ShapeViolation
            | EmitCoreError::RetractionClass => unreachable!(
                "the correspondence record takes the Open gate with the class's own type slot: \
                 no Managed/Retraction rejection, and no empty type"
            ),
        }
    }
}

/// Stages a publication into the caller's transaction: the shot, for every
/// piece of draft identity it minted one correspondence record in the draft,
/// and the draft's re-window at the kept places the request carries.
///
/// It is the link-sets design's ONE COMMIT (§5.7) as a function over a
/// caller-opened [`Staging`], the form every store op a composite may need
/// takes (PATTERNS SP-30), so a wider composite — the deposits — stages it
/// under one transaction with its own. In order:
///
/// 1. THE SHOT's OWN TABLE: M5's admission through its source gate
///    ([`shot_admission`], asked of the working world) — `doc`'s
///    registration and ω, the draft's registration and ω (the unowned-draft
///    edge: a draft the caller does not own is refused `NotOwner` here,
///    ahead of every readability question), the runs, the source gate.
///    Refused as `Publish`.
/// 2. THE TWIN FENCE, reading nothing but `stg.working()` and staging
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
/// 3. THE SHOT: [`stage_publish`] — the admission again, one answer (its
///    card states why), the re-insert's count, the existence walk, the
///    placement with each draft identity minted once, the member's mint and
///    its placing record — returning the member and the pairing.
/// 4. THE RECORDS: for each MINTED piece of the pairing, in minting order,
///    one record homed in the draft through [`stage_correspondence`] —
///    `from` the piece's draft-native span, `to` the fresh span it became,
///    both the permanent I-spans they are, of one width — its positions
///    rising in minting order, each seated in the draft's link subspace; a
///    piece placed by reference to an identity an earlier entry minted is
///    the first's record's and takes none. A shot that names no draft, or
///    re-inserts nothing, stages no record and commits exactly as the shot
///    alone does.
/// 5. THE RE-WINDOW, last (`stage_rewindow`): for each `runs` entry that
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
/// will be minted, and the draft's `content_lock_key` where a place is
/// carried — [`LinkWriter::publication`] supplies exactly that. The
/// visibility class `readable` is the caller's: the shot's source gate
/// consults it per origin, and the records' deposit gate is handed it as
/// every deposit's is, though the Open gate reads no incumbent.
///
/// Returns the member and the pairing [`stage_publish`] returned beside it,
/// for a wider composite that places the pieces itself.
///
/// # Errors
///
/// In the order above, as the bare [`PublicationError`] the caller's
/// transaction answers as `TxnError::Rejected`: the shot's admission
/// (`Publish`), the fence (`AlreadyPublished`), the shot's staging
/// (`Publish`), a record's backstops (`HomeNotRegistered`, `NotOwner` —
/// unreachable past the admission, which asked both of the same draft) and
/// its `Mint` and `Seat`, then the re-window's (`KeptPlaceMoved` with the
/// entry, `Reinstate`, `Delete` — `stage_rewindow` states which are
/// reachable). An `Err` commits nothing of the transaction.
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
    doc: &Address,
    shot: &Shot,
    places: &[Option<VPos>],
    readable: &Visibility<'_, W>,
) -> Result<(Address, Pairing), PublicationError>
where
    W: PublishWorld + LinkWorld,
    W::Record: From<LinkRec>,
{
    // 1. The shot's own table, ahead of the fence: ω speaks first, and a
    //    draft the caller does not own discloses none of its records.
    shot_admission(stg.working(), caller, doc, shot, readable)?;
    // 2. The twin fence.
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
    // 3. The shot.
    let (member, pairing) = stage_publish(stg, caller, doc, shot, readable)?;
    if let Some(draft) = shot.draft_document() {
        // 4. The records, one per minted piece, in minting order.
        for piece in pairing.iter().filter(|piece| piece.minted) {
            stage_correspondence(stg, readable, caller, &draft, &piece.from, &piece.to)?;
        }
        // 5. The re-window, last.
        stage_rewindow(stg, caller, &draft, &trunk_of(doc), shot, places, &pairing)?;
    }
    Ok((member, pairing))
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
    /// THE PUBLICATION (the link-sets design §5.7): the publish shot, its
    /// correspondence records and the draft's re-window at its kept places
    /// in ONE commit.
    ///
    /// It opens one transaction over the union of the shot's keys —
    /// `doc`'s head key, `content_lock_key` of the document it projects to,
    /// the base's `version_lock_key` where the base is a member — the
    /// draft's `link_lock_key` where records will be minted (a draft named
    /// and a run re-inserted), and the draft's `content_lock_key` where
    /// `places` carries a place (the re-window edits the draft's
    /// arrangement), sorted and deduped as `editlink`'s pair is, under this
    /// handle's attestation, and stages [`stage_publication`]: the shot's
    /// admission, the twin fence, the shot, the records, the re-window. What
    /// the shot does and refuses is M5's `publish` word for word; what this
    /// adds is the fence, the records and the re-window, stated on the
    /// staging function. The visibility class this handle carries is the
    /// shot's `readable`, the value M10 lends M5's shot on the plain path.
    ///
    /// `places` is the request's kept places, parallel to `shot.runs` by
    /// index — empty for a request that sends none, which is today's shot.
    ///
    /// Returns `(member, seq)`: the member's address, the ack's, and the one
    /// commit's `Seq`. A caller reads the records back off the draft's link
    /// subspace, in minting order, and the re-windowed draft off its
    /// arrangement.
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
        doc: &Address,
        shot: &Shot,
        places: &[Option<VPos>],
    ) -> Result<(Address, Seq), TxnError<PublicationError>> {
        let trunk = trunk_of(doc);
        let mut keys = vec![head_lock_key(doc), M3State::content_lock_key(&trunk)];
        if let Some(base) = &shot.base {
            if base.member != trunk {
                keys.push(M3State::version_lock_key(&base.member));
            }
        }
        if let Some(draft) = shot.draft_document() {
            if shot.reinserted_runs().next().is_some() {
                keys.push(M3State::link_lock_key(&draft));
            }
            if places.iter().any(Option::is_some) {
                keys.push(M3State::content_lock_key(&draft));
            }
        }
        // M2's own bytewise order, duplicates collapsed, as `editlink` hands
        // its pair: the same set in the same sequence however it was named.
        keys.sort();
        keys.dedup();
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            stage_publication(stg, caller, doc, shot, places, self.visibility).map(|(member, _)| member)
        })
    }
}
