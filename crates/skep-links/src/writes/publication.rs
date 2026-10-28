//! THE PUBLICATION (the link-sets design §5.7): the publish shot's one
//! commit, the member minted and the shot's correspondence records beside
//! it, in one transaction.
//!
//! [`stage_publication`] is the composite as a function over a caller-opened
//! staging — the shot's admission, THE TWIN FENCE, the shot's staging
//! ([`stage_publish`], M5's) and, per piece of draft identity the shot
//! minted, one correspondence record homed in the draft
//! ([`stage_correspondence`]) — and [`LinkWriter::publication`] the public
//! op: one `transact_attested` over the union of the shot's keys and the
//! draft's link key. The correspondence class has this one writer; the
//! fences on the three request-typed doors keep every other act off it.

use skep_address::{document_of, validate, Address, Nat, SpanSet, Tumbler};
use skep_arrangement::{
    head_lock_key, shot_admission, stage_publish, stage_seat_link, trunk_of, Caller, HasM5,
    MintedRun, PublishWorld, Run, Shot,
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

/// Stages a publication into the caller's transaction: the shot and, for
/// every piece of draft identity it minted, one correspondence record in
/// the draft.
///
/// It is the link-sets design's ONE COMMIT (§5.7) as a function over a
/// caller-opened [`Staging`], the form every store op a composite may need
/// takes (PATTERNS SP-30), so a wider composite — the kept places, the
/// deposits — stages it under one transaction with its own. In order:
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
/// 4. THE RECORDS: for each minted piece of the pairing, in minting order,
///    one record homed in the draft through [`stage_correspondence`] —
///    `from` the piece's draft-native span, `to` the fresh span it became,
///    both the permanent I-spans they are, of one width — its positions
///    rising in minting order, each seated in the draft's link subspace. A
///    shot that names no draft, or re-inserts nothing, stages no record and
///    commits exactly as the shot alone does.
///
/// The caller's lock keys are the union of the shot's
/// ([`stage_publish`]'s card) and the draft's `link_lock_key` where records
/// will be minted — [`LinkWriter::publication`] supplies exactly that. The
/// visibility class `readable` is the caller's: the shot's source gate
/// consults it per origin, and the records' deposit gate is handed it as
/// every deposit's is, though the Open gate reads no incumbent.
///
/// # Errors
///
/// In the order above, as the bare [`PublicationError`] the caller's
/// transaction answers as `TxnError::Rejected`: the shot's admission
/// (`Publish`), the fence (`AlreadyPublished`), the shot's staging
/// (`Publish`), a record's backstops (`HomeNotRegistered`, `NotOwner` —
/// unreachable past the admission, which asked both of the same draft) and
/// its `Mint` and `Seat`. An `Err` commits nothing of the transaction.
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
    readable: &Visibility<'_, W>,
) -> Result<Address, PublicationError>
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
    // 4. The records, one per minted piece, in minting order.
    if let Some(draft) = shot.draft_document() {
        for MintedRun { from, to } in &pairing {
            stage_correspondence(stg, readable, caller, &draft, from, to)?;
        }
    }
    Ok(member)
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
    /// THE PUBLICATION (the link-sets design §5.7): the publish shot and its
    /// correspondence records in ONE commit.
    ///
    /// It opens one transaction over the union of the shot's keys —
    /// `doc`'s head key, `content_lock_key` of the document it projects to,
    /// the base's `version_lock_key` where the base is a member — and the
    /// draft's `link_lock_key` where records will be minted (a draft named
    /// and a run re-inserted), sorted and deduped as `editlink`'s pair is,
    /// under this handle's attestation, and stages [`stage_publication`]:
    /// the shot's admission, the twin fence, the shot, the records. What
    /// the shot does and refuses is M5's `publish` word for word; what this
    /// adds is the fence and the records, stated on the staging function.
    /// The visibility class this handle carries is the shot's `readable`,
    /// the value M10 lends M5's shot on the plain path.
    ///
    /// Returns `(member, seq)`: the member's address, the ack's, and the one
    /// commit's `Seq`. A caller reads the records back off the draft's link
    /// subspace, in minting order.
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
        }
        // M2's own bytewise order, duplicates collapsed, as `editlink` hands
        // its pair: the same set in the same sequence however it was named.
        keys.sort();
        keys.dedup();
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            stage_publication(stg, caller, doc, shot, self.visibility)
        })
    }
}
