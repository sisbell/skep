//! The two static dispatch tables (§1–§4).
//!
//! Between them, every [`Op`] is handed to the store or query module that
//! owns it. The write half runs under the proven-bound [`WriteCtx`] and
//! lowers every store refusal through the `lower` table; the read half
//! answers off the one snapshot it pins, through the request's one read
//! predicate. Each table's complement arm rejects the other half's
//! operations `Malformed`, so a new `Op` variant is classified at both before
//! it compiles.

// `FebeWorld` names the accessor bound set, and its supertraits carry the
// `m3()`/`m5()`/`links()`/`content()` methods the read arms call, so no
// accessor trait is imported here by name.
use skep_address::{ordinal, shift, validate, Nat};
use skep_arrangement::{published_target, trunk_of, M5Rec};
use skep_content::{ContentStretch, ContentWrite};
use skep_discovery::{
    addressably_discoverable_from_on, count_ftt_on, count_v_on, delete_orphans_on,
    findlinks_ftt_on, findlinks_v_on, image_on, in_claims_on, out_claims_on, project_on,
    retrieve_endsets_on, window_ftt_on, window_v_on,
};
use skep_kernel::Attestation;
use skep_links::{Invalid, LinkRec};
use skep_namespace::{M3Rec, PrincipalId};
use skep_retrieval::{Query, MAX_DELIVERY_ITEMS};

use super::door::{consult_read, home_readable};
use super::{OperationSurface, WriteCtx};
use crate::lower::{lower_read, lower_txn};
use crate::publication::{birth_version, covered_universal_grants, require_registered_document};
use crate::reject::{rejection, RejectCode, Rejection};
use crate::request::Op;
use crate::response::{IItem, Response};
use crate::successor::successor_link;
use crate::world::FebeWorld;

impl<W> OperationSurface<W>
where
    W: FebeWorld,
    W::Record: From<M3Rec> + From<M5Rec> + From<LinkRec> + From<ContentWrite> + From<ContentStretch>,
{
    // ── write dispatch (§1/§3/§4) ──

    /// Dispatches a write to the store that owns it: the write half's table.
    ///
    /// Every arm acquires a driver per-op from the factory, returns only its
    /// post-commit value (A7 is upheld structurally — M10 has nothing to put
    /// on the wire until the driver returns at/after `lin(op)`), classifies
    /// `TxnError<E>` through the `lower` table, and stamps the committed
    /// `Seq`. Exhaustive over `Op` with no `_` wildcard: the complementary
    /// (read) half is one explicit `|`-list arm rejecting `Malformed` — never
    /// a panic — so a newly added `Op` variant is a compile-time
    /// non-exhaustiveness error here, at `is_read`, and at `dispatch_read`.
    ///
    /// The coordinate a driver hands back is `committed_at` — the design's own
    /// word for it — in the three arms whose operation carries an `at` of its
    /// own (a `VPos`), and `at` in every other arm. Those are the only two
    /// spellings; a third would make one concept read as two.
    ///
    /// **The attestation (signed ops).** It rides every M5 and M7 driver a
    /// write acquires, and the M3 driver of the two document mints —
    /// [`Stores::namespace_attested`], [`Stores::vstream_attested`] and
    /// [`Stores::linkstore_attested`] — and which of a store's transactions it
    /// signs is that store's alone, stated on its handle's `attest` field: a
    /// handle built with a value fills no signature slot outside the
    /// transactions its store signs. So this table holds no copy of the
    /// checked set — skepd's name for the writes an attestation is admitted
    /// on, the ten publish-class kinds — and widening it is the stores' and
    /// the transport's work. `delegate` and `register_node` acquire the plain
    /// namespace driver, so there it is dropped. Nothing is classified,
    /// verified or filtered here: the value arrives admitted by the dispatched
    /// write path's check, or not at all.
    ///
    /// # Errors
    ///
    /// In this order, the first that holds answering: the door's refusal
    /// (`consult_write`'s); for `edit_link`, the successor build's
    /// ([`successor_link`]'s); then the store's own, lowered through
    /// [`lower_txn`] beside the kernel's transaction outcomes (`Durability`,
    /// `TxnUnencodable`, `TxnOverBudget`, `Poisoned`). A read handed here is
    /// answered `Malformed`.
    ///
    /// [`Stores::namespace_attested`]: crate::Stores::namespace_attested
    /// [`Stores::vstream_attested`]: crate::Stores::vstream_attested
    /// [`Stores::linkstore_attested`]: crate::Stores::linkstore_attested
    pub(super) fn dispatch_write(
        &self,
        wc: WriteCtx,
        op: Op,
        attest: Option<&Attestation>,
    ) -> Result<Response, Rejection> {
        let kind = op.kind();
        // One snapshot for the door's own pre-dispatch reads (the write side's
        // consult below, and the EDITLINK successor build) — a prior
        // snapshot, deliberately not the write transaction's base (§4); the
        // store's own gates re-run against the base they commit on.
        let snap = self.stores.kernel().snapshot();
        // `judgment` is whether the door judged this write's sources, off that
        // snapshot; where it did not, nothing built from them below may speak
        // ahead of the store.
        let judgment = self.consult_write(&wc, &op, snap.world())?;
        // The visibility class of this write (PUB-6.25), the read predicate's
        // sibling: one value per request, from the same proven-bound
        // principal, lent to whichever store gates this write inside its own
        // transaction. Bound once here, so every such gate is handed the one
        // closure.
        let visibility = self.visible_to(wc.principal);
        match op {
            // ── namespace writes (→ M3) ──
            // The three-valued publication flag rides the op verbatim
            // (PUB-8.16); M3's create path resolves the absent arm — the
            // account's first document born published, every later flagless
            // one private (PUB-8.21). The explicit-false first-mint refusal
            // is the daemon's door (PUB-8.20, PUB-kickoff D2c), not this
            // dispatch's.
            Op::CreateNewDocument { account, published } => {
                let (addr, at) = self
                    .stores
                    .namespace_attested(attest)
                    .create_new_document(wc.principal, &account, published)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::Delegate { new_prefix, new_id } => {
                let (addr, at) = self
                    .stores
                    .namespace()
                    .delegate(wc.principal, new_prefix, new_id)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // No principal: the node addr is supplied by provisioning, and
            // M3's `register_node` takes none. The step-(b) bound-session
            // gate applied, uniformly (§6) — and it is the whole authority
            // check this path gets, here or in M3 (see `Op::RegisterNode`).
            Op::RegisterNode { addr } => {
                let (addr, at) =
                    self.stores.namespace().register_node(addr).map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // Fork ≠ Version (§3): mints an empty account-tier document,
            // sharing no content; the content-sharing fork is Op::Version.
            // The three-valued flag (PUB-8.16) rides through verbatim:
            // `Namespace::fork` resolves it at M3's create path exactly as
            // `create_new_document` does — one rule, one place.
            Op::Fork { published } => {
                let (addr, at) = self
                    .stores
                    .namespace_attested(attest)
                    .fork(wc.principal, published)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // ── arrangement writes (→ M5; ω-gated in-store under the
            //    session caller; the version-chain refusals in-store too,
            //    PUB-kickoff D2b) ──
            // The deposit declaration rides the op as M5's own value
            // (PUB-9.13), class type and all (PUB-2.64), so the exemption is
            // claimed only by the `Deposit::Declared` the client sent: M10
            // converts nothing and tests nothing — the class test is M5's.
            Op::Insert { doc, at, values, deposit } => {
                let (start, committed_at) = self
                    .stores
                    .vstream_attested(attest)
                    .insert(wc.caller(), &doc, at, values, deposit)
                    .map_err(|e| lower_txn(kind, e))?; // returns post-commit
                Ok(Response::AckAddr { addr: start, at: committed_at }) // the exact V1 coordinate
            }
            Op::Delete { doc, p, width } => {
                let at = self
                    .stores
                    .vstream_attested(attest)
                    .delete(wc.caller(), &doc, p, width)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::Ack { at })
            }
            Op::Copy { doc, at, specs } => {
                let committed_at = self
                    .stores
                    .vstream_attested(attest)
                    .copy(wc.caller(), &doc, at, &specs)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::Ack { at: committed_at })
            }
            // The write by identity (the replacement act's record): the
            // client's I-runs placed as given. Its origins were consulted at
            // the door above, as `copy`'s sources were (`Op::source_arguments`,
            // the distinct origins in run order), so the store takes no
            // predicate; the handle drops the attestation for a kind outside
            // its three.
            Op::Reinstate { doc, at, runs } => {
                let committed_at = self
                    .stores
                    .vstream_attested(attest)
                    .reinstate(wc.caller(), &doc, at, &runs)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::Ack { at: committed_at })
            }
            Op::Rearrange { doc, cuts } => {
                let at = self
                    .stores
                    .vstream_attested(attest)
                    .rearrange(wc.caller(), &doc, &cuts)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::Ack { at })
            }
            Op::Version { d_src, published } => {
                let (addr, at) = self
                    .stores
                    .vstream_attested(attest)
                    // M5 does the owned/cross-owner branch and resolves the
                    // three-valued flag: None ⇒ inherit published(d_src),
                    // off its own working state (PUB-8.17/8.18).
                    .version(wc.principal, &d_src, published)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // The shot (PUB-2.33, PUB-8.1), as THE PUBLICATION (the
            // link-sets design §5.7): M7's composite stages M5's shot — which
            // decides the destination, places the runs by origin, each draft
            // identity once, and runs the source gate — and, for every piece
            // of draft identity the shot minted, one correspondence record
            // homed in the draft, in ONE transaction, behind the twin fence
            // that refuses a run a record already names. What M10 adds is
            // the session's visibility class (`visible_to`) — the same value
            // the five link writes lend M7 — which M5 evaluates per origin
            // over the shot's own working world, the world in which it has
            // just found each origin registered (PUB-6.37), and M7 lends the
            // records' deposit gate. The ack is the member's address
            // (PUB-2.37); the records are the draft's to read back.
            Op::Publish { doc, shot } => {
                let (addr, at) = self
                    .stores
                    .linkstore_attested(&visibility, attest)
                    .publication(wc.caller(), &doc, &shot)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // ── link writes (→ M7; ω-gated in-store on each written home;
            //    the value-keyed gates at the session principal's visibility
            //    class, the writer built per write over `visible_to`) ──
            Op::MakeLink { home, from, to, ty, replaces } => {
                // M7 handles both slot forms inside its transact: Resolve
                // V-specs off the txn base, Addrs deposited verbatim. The
                // `replaces` member (PUB-5.15) picks the composite: absent,
                // the record alone; present, the record and its `replaces`
                // link in one transaction under the one attestation. The ack
                // is the record's address either way.
                let writer = self.stores.linkstore_attested(&visibility, attest);
                let (addr, at) = match replaces {
                    None => writer.makelink(wc.caller(), &home, from, to, ty),
                    Some(replaces) => {
                        writer.makelink_replacing(wc.caller(), &home, from, to, ty, &replaces)
                    }
                }
                .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // Idempotent zero-step ops need no special case (§3): a dedup hit
            // returns (incumbent, base_seq) with no commit; marshaled
            // identically to a miss (ASN-0134 §A1). The incumbent a hit names
            // is one this principal can read (PUB-6.25, PUB-6.26).
            Op::Emit { home, ty, from, to } => {
                let (addr, at) = self
                    .stores
                    .linkstore_attested(&visibility, attest)
                    .emit(wc.caller(), &home, &ty, &from, &to)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::Nullify { home, target } => {
                let (addr, at) = self
                    .stores
                    .linkstore_attested(&visibility, attest)
                    .nullify(wc.caller(), &home, &target)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::AssertSup { home, old, new } => {
                let (addr, at) = self
                    .stores
                    .linkstore_attested(&visibility, attest)
                    .assert_sup(wc.caller(), &home, &old, &new)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // The one read-assembled request (§4): the successor's content
            // V-specs resolve through M5 off a prior snapshot — deliberately
            // not in editlink's write transaction (recorded I-addresses are
            // permanent, so a source's arrangement may move underneath with no
            // hazard). One operation ⇒ still one M2 transaction. The
            // visibility class rides the writer as on every link write; the
            // claim's dedup is a guaranteed miss (PUB-6.27), so no ack here
            // can name an address this principal could not read. Where the
            // door judged the write, the successor's sources were consulted
            // above, before this build reads their arrangements (PUB-6.38);
            // where it deferred to the store's own gate they were not, and the
            // build, told so by `judgment`, issues no verdict their
            // arrangements decide — the store's home gate speaks first.
            Op::EditLink { original, successor, d_s, d_a } => {
                let link =
                    successor_link(snap.world().m3(), snap.world().m5(), &successor, judgment)?;
                let (edit, at) = self
                    .stores
                    .linkstore_attested(&visibility, attest)
                    .editlink(wc.caller(), &original, link, &d_s, &d_a)
                    .map_err(|e| lower_txn(kind, e))?;
                Ok(Response::AckEdit { successor: edit.successor, claim: edit.claim, at })
            }
            // Complementary half — unreachable under the is_write partition
            // that selected this function; written as an explicit |-list (no
            // `_`) so a new Op variant fails to compile here, and rejecting
            // (never panicking) so execute's Total contract holds regardless
            // of the partition's correctness (§1).
            Op::NextAccountPrefix { .. }
            | Op::PrincipalPrefix { .. }
            | Op::EffectiveOwner { .. }
            | Op::ReadLink { .. }
            | Op::FollowLink { .. }
            | Op::RetrieveV { .. }
            | Op::RetrieveI { .. }
            | Op::ContentFrontier { .. }
            | Op::RetrieveDocVSpan { .. }
            | Op::RetrieveDocVSpanSet { .. }
            | Op::ShowOrigin { .. }
            | Op::ShowDeletions { .. }
            | Op::Compare { .. }
            | Op::FindDocsContaining { .. }
            | Op::Image { .. }
            | Op::FindLinksV { .. }
            | Op::FindLinksFtt { .. }
            | Op::CountV { .. }
            | Op::CountFtt { .. }
            | Op::WindowV { .. }
            | Op::WindowFtt { .. }
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::DocMetadata { .. }
            | Op::EditionClaims { .. }
            | Op::UniversalGrants => Err(rejection(kind, RejectCode::Malformed)),
        }
    }

    // ── read dispatch (§1/§2) ──

    /// Dispatches a read to the module that owns it: the read half's table.
    ///
    /// This function pins the one snapshot every arm answers against, and
    /// takes `as_of` from it once: a read is a single linearization point,
    /// M10 reports exactly that point (V1), and any multi-constituent verdict
    /// discharges MIC clause 6 by construction (A3/V2) — properties of the
    /// pinning, not of each arm remembering to do it.
    ///
    /// With the snapshot in hand the arms reach only the snapshot-based
    /// surfaces: `Query::new` for M6, M8's `*_on` reads over that same
    /// snapshot (Conflicts resolved #5), and the snapshot's own world for
    /// every other arm, so no answer comes from a position other than the one
    /// `as_of` names. Reads hold no lock against writers, are zero-step (A1),
    /// and have no commit-before-ack obligation.
    ///
    /// No arm takes a session gate. What `principal` (`None` is the guest)
    /// shapes is decided in exactly two places. One is the per-request read
    /// predicate this function builds once off it, which every masking arm
    /// answers through — and which, at the doc-argument consult below,
    /// refuses a request naming — or, reading by identity, deriving — a
    /// document this caller may not read. The
    /// other is the any-principal arm, which asks the principal itself:
    /// grants reach principals alone (PUB-5.109), so the guest is answered no
    /// rows — the one per-caller rule on this path that is not the predicate,
    /// decided here because this is where the caller is known. The three
    /// registry reads answer through neither, their data being public and the
    /// same for every caller.
    ///
    /// Exhaustive over `Op` with the complementary (write) half as one
    /// explicit rejecting |-list — see `dispatch_write`.
    ///
    /// # Errors
    ///
    /// In this order, the first that holds answering: the doc-argument
    /// consult's refusal ([`consult_read`]'s); then the arm's own — the read
    /// by identity's `TooManyItems` where its spans' widths, summed, pass
    /// `MAX_DELIVERY_ITEMS`; `DocNotRegistered`, raised here, where the
    /// content-frontier, doc-metadata or edition-claim read names no
    /// registered document; or the reader's refusal, lowered through
    /// `lower_read`. A write handed here is answered `Malformed`.
    ///
    /// # Panics
    ///
    /// Panics if the read by identity's shifted element ordinal stops being a
    /// T4-valid address, or a registered document's content chain answers no
    /// next address — two states no input reaches.
    pub(super) fn dispatch_read(
        &self,
        op: Op,
        principal: Option<PrincipalId>,
    ) -> Result<Response, Rejection> {
        let kind = op.kind();
        let snap = self.stores.kernel().snapshot();
        let as_of = snap.seq();
        let world = snap.world();
        // The read predicate of this request (`readable_by`), bound off this
        // read snapshot — or off the supplied `ReadPredicate`, which a
        // historical front door closes over one head snapshot (PUB-6.48) — and
        // threaded to every arm below that masks.
        let readable = self.readable_by(world, principal);
        // The doc-argument consult (PUB-6.12), off that same predicate and
        // ahead of every arm, so no read validates an argument it may not
        // describe: the first unreadable named document — then derived one —
        // answers withheld.
        consult_read(&op, &readable)?;
        match op {
            // ── namespace reads (→ M3, §2): the M3-internal frontier/
            //    registry values Delegate/CreateNewDocument demand, and ω's
            //    whole entry. Total — an `Option` each, no fault path.
            Op::NextAccountPrefix { parent } => {
                let addr = world.m3().next_account_prefix(&parent);
                Ok(Response::MaybeAddr { addr, as_of })
            }
            // Takes an explicit wire id, not the session's bound principal —
            // deliberate (§2): a prefix is public, immutable registry data, so
            // the answer is the same for every caller and the wire id is what
            // is being asked about.
            Op::PrincipalPrefix { id } => {
                let addr = world.m3().principal_prefix(id).cloned();
                Ok(Response::MaybeAddr { addr, as_of })
            }
            // AUTH-6.37: ω's whole entry off one walk of M3's registry
            // (`effective_owner_pair`); the two projections composed would
            // walk it twice. `addr` is a registry probe, not a doc-argument, so
            // the consult above passed it by. What the entry means to a caller
            // — the allocation test included — is `Op::EffectiveOwner`'s
            // contract.
            Op::EffectiveOwner { addr } => {
                let owner =
                    world.m3().effective_owner_pair(&addr).map(|(prefix, id)| (prefix.clone(), id));
                Ok(Response::EffectiveOwner { owner, as_of })
            }
            // ── raw link reads (→ M7, §2): no driver handle — straight off
            //    the one snapshot.
            Op::ReadLink { a } => {
                // A link homed in an unreadable document reads as absent
                // (PUB-6.6): `⊥`, exactly as a never-deposited address — its
                // age with it, so absence says nothing a link's position
                // would. Where the link is read, `at` is the position M3's
                // position map keeps for its mint (D6: the position in the
                // world, never an index over the feed), `None` for a link
                // a build before the map minted; the time is the transport's
                // to add (`Response::mint_mut`).
                let link = if home_readable(&a, &readable) {
                    world.links().readlink(&a).cloned()
                } else {
                    None
                };
                let at = link.as_ref().and_then(|_| world.m3().minted_at(&a));
                Ok(Response::LinkValue { link, at, time: None, as_of })
            }
            // Carries its own Result in-band, deliberately (§2): M7 defines
            // ⟨⟩ ≠ ⊥ as two answers of FOLLOWLINK; lowering Invalid to a
            // Rejection would erase an unforgeable distinction. Contrast
            // Project, where M8's NotALink is a precondition failure.
            Op::FollowLink { a, slot } => {
                // Absence for an unreadable home (PUB-6.6): `⊥`, the same
                // `Err(Invalid)` a non-link answers — never ⟨⟩, which is a
                // present link's empty slot.
                let result = if home_readable(&a, &readable) {
                    world.links().followlink(&a, slot)
                } else {
                    Err(Invalid)
                };
                Ok(Response::Follow { result, as_of })
            }
            // ── content/provenance reads (→ M6, §2; the read by identity and
            //    the frontier read the world directly) ──
            Op::RetrieveV { specs } => {
                // The delivery masks per run through the threaded predicate
                // (PUB-6.41): each spec's named doc was consulted above; the
                // runs its arrangement windows are masked here, a masked run
                // emitted as the withheld arm at its own position.
                let items = Query::new(&snap)
                    .retrieve_v_masked(&specs, &readable)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Delivery { items, as_of })
            }
            // The read by identity (AUTH-6.38–6.40; M-I2 (a), (h)): every
            // span's derived document passed the consult above — its shape
            // too, so each start is an element position and each width at
            // least one — and what remains is M4's point read per position,
            // keyed by I-address and blind to arrangement. The budget first
            // (P29): the widths summed are the delivery's size, request
            // arithmetic, refused whole past `MAX_DELIVERY_ITEMS` before the
            // first address is expanded, as RETRIEVEV's delivery is held to the
            // same number.
            Op::RetrieveI { spans } => {
                let total = spans.iter().try_fold(0u64, |sum, span| {
                    u64::try_from(&span.width).ok().and_then(|w| sum.checked_add(w))
                });
                if total.is_none_or(|n| n > MAX_DELIVERY_ITEMS as u64) {
                    return Err(rejection(kind, RejectCode::TooManyItems));
                }
                let content = world.content();
                let one = Nat::from(1u32);
                let mut items = Vec::new();
                for span in &spans {
                    let mut at = span.start.tumbler().clone();
                    let mut left = span.width.clone();
                    while left > Nat::from(0u32) {
                        // The ordinal advanced keeps the address T4-valid: an
                        // element position's last component is at least one
                        // and only grows, and the document prefix is untouched.
                        let addr = validate(at.clone())
                            .expect("a shifted element ordinal stays a T4-valid address");
                        // M4's point read lends a piece — a value, or the one
                        // byte at a position inside a stretch — and the item
                        // owns a `Val`: `to_val` is the one allocation a
                        // position inside a stretch costs here, beside the
                        // address the item carries anyway.
                        items.push(IItem {
                            at: addr,
                            value: content.value_at(&at).map(|piece| piece.to_val()),
                        });
                        at = shift(&at, &one);
                        left -= &one;
                    }
                }
                Ok(Response::IDelivery { items, as_of })
            }
            // The content frontier (AUTH-6.38): `doc` passed the consult
            // above, so a draft's mint count is told to no reader the draft
            // does not admit; registration is M10's own refusal, as the
            // doc-metadata read's is, since the chain's peek answers nothing
            // for a document M3 never registered. The peek is M3's content
            // chain's — the next address the mint would issue, read and not
            // staged — and its ordinal is the frontier plus one.
            Op::ContentFrontier { doc } => {
                let m3 = world.m3();
                require_registered_document(m3, kind, &doc)?;
                let next = m3
                    .next_content_address(&doc)
                    .expect("a registered document's content chain has a next address");
                Ok(Response::Frontier { next: ordinal(next.tumbler()).clone(), as_of })
            }
            Op::RetrieveDocVSpan { doc } => {
                let set = Query::new(&snap).doc_vspan(&doc).map_err(|e| lower_read(kind, e))?;
                Ok(Response::SpanSet { set, as_of })
            }
            Op::RetrieveDocVSpanSet { doc } => {
                let set = Query::new(&snap).doc_vspanset(&doc).map_err(|e| lower_read(kind, e))?;
                Ok(Response::SpanSet { set, as_of })
            }
            Op::ShowOrigin { doc, span } => {
                let addrs = Query::new(&snap)
                    .show_origin_v(&doc, &span)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Addrs { addrs, as_of })
            }
            Op::ShowDeletions { d_a, d_b } => {
                let rep = Query::new(&snap)
                    .show_deletions(&d_a, &d_b)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Deletions { rep, as_of })
            }
            Op::Compare { rho1, rho2 } => {
                let rep =
                    Query::new(&snap).compare(&rho1, &rho2).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Compare { rep, as_of })
            }
            Op::FindDocsContaining { regions } => {
                // The container filter: a candidate the reader may not read is
                // dropped at its identity; the region-spec docs were consulted
                // above.
                let addrs = Query::new(&snap)
                    .find_docs_containing_filtered(&regions, &readable)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Addrs { addrs, as_of })
            }
            // ── link discovery reads (→ M8, §2): M8's *_on reads over M10's
            //    one snapshot.
            Op::Image { d, region } => {
                let runs = image_on(&snap, &d, &region).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Runs { runs, as_of })
            }
            // The result-set family: every reader drops each link whose home
            // the reader may not read, threaded the predicate. `d` was
            // consulted above; the filter is on the result links' homes.
            Op::FindLinksV { d, region } => {
                let addrs = findlinks_v_on(&snap, &d, &region, &readable)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Addrs { addrs, as_of })
            }
            Op::FindLinksFtt { q } => {
                let addrs = findlinks_ftt_on(&snap, &q, &readable); // total
                Ok(Response::Addrs { addrs, as_of })
            }
            Op::CountV { d, region } => {
                let n =
                    count_v_on(&snap, &d, &region, &readable).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Count { n, as_of })
            }
            Op::CountFtt { q } => {
                let n = count_ftt_on(&snap, &q, &readable); // total
                Ok(Response::Count { n, as_of })
            }
            Op::WindowV { d, region, cur, n } => {
                let window = window_v_on(&snap, &d, &region, cur, n, &readable)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Page { window, as_of })
            }
            Op::WindowFtt { q, cur, n } => {
                let window = window_ftt_on(&snap, &q, cur, n, &readable); // total
                Ok(Response::Page { window, as_of })
            }
            Op::RetrieveEndsets { d, region } => {
                let pairs = retrieve_endsets_on(&snap, &d, &region, &readable)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Endsets { pairs, as_of })
            }
            // `project` and `discoverable_from`: `d` is in the consult above
            // (the dual row, PUB-6.8); the absence of a link `a` homed in an
            // unreadable document (PUB-6.6) is M8's to answer, through the
            // predicate, and both answer it `NotALink` — which is also what
            // each gives for an address no link occupies, so the two are
            // indistinguishable as the rule requires. An admitted `project`
            // is unfiltered at origin (PUB-6.15); an admitted `a` that is
            // retracted answers `discoverable_from` `false`.
            Op::Project { a, slot, d } => {
                let set =
                    project_on(&snap, &a, slot, &d, &readable).map_err(|e| lower_read(kind, e))?;
                Ok(Response::SpanSet { set, as_of })
            }
            Op::DiscoverableFrom { a, d } => {
                let val = addressably_discoverable_from_on(&snap, &a, &d, &readable)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Bool { val, as_of })
            }
            Op::DeleteOrphans { d, p, width } => {
                let report = delete_orphans_on(&snap, &d, &p, &width, &readable)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Orphans { report, as_of })
            }
            Op::InClaims { y, view } => {
                let claims = in_claims_on(&snap, &y, view, &readable); // total
                Ok(Response::Claims { claims, as_of })
            }
            Op::OutClaims { x, view } => {
                let claims = out_claims_on(&snap, &x, view, &readable); // total
                Ok(Response::Claims { claims, as_of })
            }
            // ── publication reads (PUB-8.47): answers M10 composes; what
            //    they need that no store computes is `crate::publication`'s ──
            // PUB-8.12: `doc` passed the consult above, so an unreadable one
            // was answered `withheld` before the registration refusal below
            // could describe it. The argument projects to its trunk (PUB-2.15)
            // and every document field is read off that one address: M5's own
            // `published_target` (the bit every gate keys on), M3's ω, and the
            // birth version. The shot terms and the fork source are read off
            // the address named (signed-ops D25, and the fork-source record,
            // each served as a member read): a version member the shot minted
            // answers its own terms, a document a `version` minted answers its
            // own source, and everything else — a trunk no `version` minted
            // included — answers none. The source takes no gate of its own:
            // whoever may read the fork reads the address it was born sharing
            // (the record's decision 2), and nothing else of the source rides
            // with it. The mint position is read off the address named too
            // (M3's position map; D6): a member answers its own mint, the
            // document its own, and the time is the transport's to add.
            Op::DocMetadata { doc } => {
                let m3 = world.m3();
                require_registered_document(m3, kind, &doc)?;
                let terms = world.m5().shot_terms(&doc).cloned();
                let source = world.m5().fork_source(&doc).cloned();
                let at = m3.minted_at(&doc);
                let trunk = trunk_of(&doc);
                let published = published_target(m3, &trunk);
                let owner = m3.effective_owner_prefix(&trunk).cloned();
                let birth = birth_version(m3, world.m5(), &trunk);
                Ok(Response::DocMetadata {
                    doc: trunk,
                    published,
                    owner,
                    birth,
                    terms,
                    source,
                    at,
                    time: None,
                    as_of,
                })
            }
            // PUB-8.46: the world answers the class unfiltered, in
            // link-address order; the home rule (PUB-6.13) keeps each row whose
            // home this request's predicate admits, so the order survives the
            // filter. The registration refusal is what confines the world's
            // `to` range to one document's subtree.
            Op::EditionClaims { target } => {
                require_registered_document(world.m3(), kind, &target)?;
                let claims = world
                    .edition_claims(&target)
                    .into_iter()
                    .filter(|claim| readable(&claim.home))
                    .collect();
                Ok(Response::EditionClaims { claims, as_of })
            }
            // PUB-8.47: the guest is answered before the index is enumerated,
            // so the index is not walked for a requester no grant reaches. For
            // a bound principal: one enumeration off this snapshot, narrowed by
            // `covered_universal_grants` with ω asked of the same snapshot's
            // registry. Index rows and served rows are two types, so the index
            // cannot reach the wire unnarrowed. What the answer promises is
            // `Op::UniversalGrants`'s contract.
            Op::UniversalGrants => {
                let rows = match principal {
                    None => Vec::new(),
                    Some(_) => covered_universal_grants(world.m3(), world.universal_grant_index()),
                };
                Ok(Response::UniversalGrants { rows, as_of })
            }
            // Complementary half — see dispatch_write's twin arm (§1).
            Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork { .. }
            | Op::Insert { .. }
            | Op::Delete { .. }
            | Op::Copy { .. }
            | Op::Reinstate { .. }
            | Op::Rearrange { .. }
            | Op::Version { .. }
            | Op::Publish { .. }
            | Op::MakeLink { .. }
            | Op::Emit { .. }
            | Op::Nullify { .. }
            | Op::AssertSup { .. }
            | Op::EditLink { .. } => Err(rejection(kind, RejectCode::Malformed)),
        }
    }
}
