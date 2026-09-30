//! The two static dispatch tables (§1–§4): every [`Op`] handed to the store
//! or query module that owns it. The write half runs under the proven-bound
//! [`WriteCtx`] and lowers every store refusal through
//! [`OperationSurface::lower_write`]; the read half answers off the one
//! snapshot it pins, through the request's one read predicate. Each table's
//! complement arm rejects the other half's operations `Malformed`, so a new
//! `Op` variant is classified at both before it compiles.

// `FebeWorld` names the accessor bound set, and its supertraits carry the
// `m3()`/`m5()`/`links()` methods the read arms call, so no accessor trait
// is imported here by name.
use skep_arrangement::{published_target, trunk_of, M5Rec};
use skep_content::ContentWrite;
use skep_discovery::{
    addressably_discoverable_from_on, count_ftt_on, count_v_on, delete_orphans_on,
    findlinks_ftt_on, findlinks_v_on, image_on, in_claims_on, out_claims_on, project_on,
    retrieve_endsets_on, window_ftt_on, window_v_on,
};
use skep_kernel::Attestation;
use skep_links::{Invalid, LinkRec};
use skep_namespace::{M3Rec, PrincipalId};
use skep_retrieval::Query;

use super::door::{consult_read, consult_write, home_readable};
use super::{OperationSurface, WriteCtx};
use crate::lower::lower_read;
use crate::op::Op;
use crate::publication::{birth_version, covered_universal_grants, require_registered_document};
use crate::reject::{rejection, RejectCode, Rejection};
use crate::response::Response;
use crate::successor::successor_link;
use crate::world::FebeWorld;

impl<W> OperationSurface<W>
where
    W: FebeWorld,
    W::Record: From<M3Rec> + From<M5Rec> + From<LinkRec> + From<ContentWrite>,
{
    // ── write dispatch (§1/§3/§4) ──

    /// The static table for the write half: every arm acquires a driver
    /// per-op from the factory, returns only its post-commit value (A7 is
    /// upheld structurally — M10 has nothing to put on the wire until the
    /// driver returns at/after `lin(op)`), classifies `TxnError<E>` through
    /// [`OperationSurface::lower_write`] so the poison hint latches on the way
    /// past, and stamps the committed `Seq`. Exhaustive over `Op` with NO `_`
    /// wildcard: the complementary (read) half is one explicit `|`-list arm
    /// rejecting `Malformed` — never a panic — so a newly added `Op` variant
    /// is a compile-time non-exhaustiveness error here, at `is_read`, and at
    /// `dispatch_read`.
    ///
    /// The coordinate a driver hands back is `at` in every arm, and
    /// `committed_at` — the design's own word for it — in the two arms whose
    /// operation carries an `at` of its own (a `VPos`). Those are the only
    /// two spellings; a third would make one concept read as two.
    ///
    /// THE ATTESTATION (signed ops) reaches exactly three arms — `insert`,
    /// `publish`, `make_link`, the seam build's slice — through the ATTESTED
    /// handles [`Stores::vstream_attested`] and [`Stores::linkstore_attested`],
    /// which hand it to the kernel at the one transaction each opens; every
    /// other arm builds a plain handle and the value, if a caller set one, is
    /// dropped here unwritten. Nothing is classified or verified in this
    /// module: the value arrives ADMITTED by the dispatched write path's
    /// check, or not at all.
    ///
    /// [`Stores::vstream_attested`]: crate::Stores::vstream_attested
    /// [`Stores::linkstore_attested`]: crate::Stores::linkstore_attested
    pub(super) fn dispatch_write(
        &self,
        wc: WriteCtx,
        op: Op,
        attest: Option<&Attestation>,
    ) -> Result<Response, Rejection> {
        let kind = op.kind();
        // ONE snapshot for the door's own pre-dispatch reads (the write side's
        // consult below, and the EDITLINK successor build) — a PRIOR
        // snapshot, deliberately not the write transaction's base (§4); the
        // store's own gates re-run against the base they commit on.
        let snap = self.stores.kernel().snapshot();
        // THE read predicate of this write (PUB-6.39), bound off that snapshot
        // for the PROVEN-bound principal and from nothing else — the consult's
        // stated precondition, which is why the two sit on adjacent lines.
        // `judged` is whether the door judged this write's sources; where it
        // did not, nothing built from them below may speak ahead of the store.
        let readable = self.readable_by(snap.world(), Some(wc.principal));
        let judged = consult_write(&wc, &op, snap.world().m3(), &readable)?;
        // THE VISIBILITY CLASS of this write (PUB-6.25), the read predicate's
        // sibling: one value per request, derived from the same proven-bound
        // principal, lent to whichever store gates this write INSIDE its own
        // transaction — M5's per-origin source gate on the shot, M7's
        // value-keyed gates on the five link writes. Bound once here, so
        // "the ONE closure every such gate is handed" is a fact of the code
        // rather than six arms agreeing.
        let visibility = self.visible_to(wc.principal);
        match op {
            // ── namespace writes (→ M3) ──
            // The three-valued publication flag rides the op verbatim
            // (PUB-8.16); M3's create path resolves the ABSENT arm — the
            // account's first document born published, every later flagless
            // one private (PUB-8.21). The explicit-false FIRST-mint refusal
            // is the DAEMON's door (PUB-8.20, D2c), not this dispatch's.
            Op::CreateNewDocument { account, published } => {
                let (addr, at) = self
                    .stores
                    .namespace()
                    .create_new_document(wc.principal, &account, published)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::Delegate { new_prefix, new_id } => {
                let (addr, at) = self
                    .stores
                    .namespace()
                    .delegate(wc.principal, new_prefix, new_id)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // No principal: the node addr is supplied by provisioning, and
            // M3's `register_node` takes none. The step-(b) bound-session
            // gate applied, uniformly (§6) — and it is the whole authority
            // check this path gets, here or in M3 (see `Op::RegisterNode`).
            Op::RegisterNode { addr } => {
                let (addr, at) = self
                    .stores
                    .namespace()
                    .register_node(addr)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // Fork ≠ Version (§3): mints an EMPTY account-tier document,
            // sharing NO content; the content-sharing fork is Op::Version.
            // The three-valued flag (PUB-8.16) rides through verbatim:
            // `Namespace::fork` resolves it at M3's create path exactly as
            // `create_new_document` does (owner 2026-09-05 — one rule, one
            // place; the reduction M10 spelled for itself in round 1 is
            // retired with it).
            Op::Fork { published } => {
                let (addr, at) = self
                    .stores
                    .namespace()
                    .fork(wc.principal, published)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // ── arrangement writes (→ M5; ω-gated in-store under the
            //    session caller — the ownership ruling, 2026-08-16; the
            //    version-chain refusals in-store too, D2b) ──
            // The DEPOSIT DECLARATION rides the op as M5's own value
            // (PUB-9.13), class type and all (PUB-2.64), so the exemption is
            // claimed only by the `Deposit::Declared` the client sent: M10
            // converts nothing and tests nothing — the class test is M5's.
            Op::Insert { doc, at, values, deposit } => {
                let (start, committed_at) = self
                    .stores
                    .vstream_attested(attest)
                    .insert(wc.caller(), &doc, at, values, deposit)
                    .map_err(|e| self.lower_write(kind, e))?; // returns post-commit
                Ok(Response::AckAddr { addr: start, at: committed_at }) // the exact V1 coordinate
            }
            Op::Delete { doc, p, width } => {
                let at = self
                    .stores
                    .vstream()
                    .delete(wc.caller(), &doc, p, width)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::Ack { at })
            }
            Op::Copy { doc, at, specs } => {
                let committed_at = self
                    .stores
                    .vstream()
                    .copy(wc.caller(), &doc, at, &specs)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::Ack { at: committed_at })
            }
            Op::Rearrange { doc, cuts } => {
                let at = self
                    .stores
                    .vstream()
                    .rearrange(wc.caller(), &doc, &cuts)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::Ack { at })
            }
            Op::Version { d_src, published } => {
                let (addr, at) = self
                    .stores
                    .vstream()
                    // M5 does the owned/cross-owner branch AND resolves the
                    // three-valued flag: None ⇒ INHERIT published(d_src),
                    // off its own working state (PUB-8.17/8.18).
                    .version(wc.principal, &d_src, published)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // The SHOT (PUB-2.33, PUB-8.1): M5's composite decides the
            // destination, places the runs by origin and runs the source
            // gate; what M10 adds is the session's VISIBILITY CLASS
            // (`visible_to`, lane 3.3b) — the same value the five link writes
            // lend M7 — which M5 evaluates per ORIGIN over the shot's own
            // working world, the world in which it has just found each origin
            // registered (PUB-6.37). The ack is the member's address
            // (PUB-2.37).
            Op::Publish { doc, shot } => {
                let (addr, at) = self
                    .stores
                    .vstream_attested(attest)
                    .publish(wc.caller(), &doc, shot, &visibility)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // ── link writes (→ M7; ω-gated in-store on each written home —
            //    the ownership ruling, 2026-08-16; the value-keyed gates at
            //    the session principal's VISIBILITY class — lane 3.3b, the
            //    writer built per write over `visible_to`) ──
            Op::MakeLink { home, from, to, ty, replaces } => {
                // M7 handles both slot forms INSIDE its transact: Resolve
                // V-specs off the txn base, Addrs deposited verbatim. The
                // `replaces` member (PUB-5.15) picks the composite: absent,
                // the record alone; present, the record and its `replaces`
                // link in ONE transaction under the one attestation. The ack
                // is the RECORD's address either way.
                let writer = self.stores.linkstore_attested(&visibility, attest);
                let (addr, at) = match replaces {
                    None => writer.makelink(wc.caller(), &home, from, to, ty),
                    Some(named) => {
                        writer.makelink_replacing(wc.caller(), &home, from, to, ty, &named)
                    }
                }
                .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // Idempotent zero-step ops need no special case (§3): a dedup hit
            // returns (incumbent, base_seq) with no commit; marshaled
            // identically to a miss (ASN-0134 §A1). The incumbent a hit names
            // is one this principal can read (PUB-6.25, PUB-6.26).
            Op::Emit { home, ty, from, to } => {
                let (addr, at) = self
                    .stores
                    .linkstore(&visibility)
                    .emit(wc.caller(), &home, &ty, &from, &to)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::Nullify { home, target } => {
                let (addr, at) = self
                    .stores
                    .linkstore(&visibility)
                    .nullify(wc.caller(), &home, &target)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::AssertSup { home, old, new } => {
                let (addr, at) = self
                    .stores
                    .linkstore(&visibility)
                    .assert_sup(wc.caller(), &home, &old, &new)
                    .map_err(|e| self.lower_write(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // The one read-assembled request (§4): the successor's content
            // V-specs resolve through M5 off a PRIOR snapshot — deliberately
            // not in editlink's write transaction (recorded I-addresses are
            // permanent, so d_s's arrangement may move underneath with no
            // hazard). One operation ⇒ still one M2 transaction. The
            // visibility class rides the writer as on every link write; the
            // claim's dedup is a guaranteed miss (PUB-6.27), so no ack here
            // can name an address this principal could not read. Where the
            // door judged the write, the successor's sources were consulted
            // above, BEFORE this build reads their arrangements (PUB-6.38);
            // where it deferred to the store's own gate they were not, and the
            // build, told so by `judged`, issues no verdict their arrangements
            // decide — the store's `not_owner` speaks first.
            Op::EditLink { original, successor, d_s, d_a } => {
                let link =
                    successor_link(snap.world().m3(), snap.world().m5(), &successor, judged)?;
                let (edit, at) = self
                    .stores
                    .linkstore(&visibility)
                    .editlink(wc.caller(), &original, link, &d_s, &d_a)
                    .map_err(|e| self.lower_write(kind, e))?;
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

    /// The static table for the read half. THIS function pins the one
    /// snapshot every arm answers against, and takes `as_of` from it once:
    /// a read is a single linearization point, M10 reports exactly that
    /// point (V1), and any multi-constituent verdict discharges MIC clause 6
    /// by construction (A3/V2) — properties of the pinning, not of each arm
    /// remembering to do it.
    ///
    /// With the snapshot in hand the arms reach only the snapshot-based
    /// surfaces: `Query::new` for M6, and M8's `*_on` reads over that same
    /// snapshot (Conflicts resolved #5), so no answer comes from a position
    /// other than the one `as_of` names. Reads hold no lock against writers,
    /// are zero-step (A1), and have no commit-before-ack obligation.
    ///
    /// No arm takes a session gate. What `principal` (`None` is the guest)
    /// SHAPES is decided in exactly two places. One is the per-request read
    /// predicate this function builds once off it, which every masking arm
    /// answers through — and which, at the doc-argument consult below,
    /// refuses a request naming a document this caller may not read. The
    /// other is the any-principal arm, which asks the principal itself:
    /// grants reach principals alone (PUB-5.109), so the guest is answered no
    /// rows — the one per-caller rule on this path that is not the predicate,
    /// decided here because this is where the caller is known. The three
    /// registry reads answer through neither, their data being public and the
    /// same for every caller.
    ///
    /// Exhaustive over `Op` with the complementary (write) half as one
    /// explicit rejecting |-list — see `dispatch_write`.
    pub(super) fn dispatch_read(
        &self,
        op: Op,
        principal: Option<PrincipalId>,
    ) -> Result<Response, Rejection> {
        let kind = op.kind();
        let snap = self.stores.kernel().snapshot();
        let as_of = snap.seq();
        let world = snap.world();
        // THE read predicate of this request (`readable_by`), bound off THIS
        // read snapshot — or off the supplied `ReadPredicate`, which a
        // historical front door closes over one HEAD snapshot (PUB-6.48) — and
        // threaded to every arm below.
        let readable = self.readable_by(world, principal);
        // The doc-argument consult (PUB-6.12), off that same predicate and
        // ahead of every arm, so no read validates an argument it may not
        // describe: the first unreadable NAMED document answers WITHHELD.
        consult_read(&op, &readable)?;
        match op {
            // ── namespace reads (→ M3, §2): the M3-internal frontier/
            //    registry values Delegate/CreateNewDocument demand. Total —
            //    Option<Address>, no fault path.
            Op::NextAccountPrefix { parent } => {
                let addr = world.m3().next_account_prefix(&parent);
                Ok(Response::MaybeAddr { addr, as_of })
            }
            // Takes an explicit wire id, not the session's bound principal —
            // deliberate (§2): a prefix is public, immutable registry data, so
            // the answer is the same for every caller and the wire id is what
            // is being asked ABOUT.
            Op::PrincipalPrefix { id } => {
                let addr = world.m3().principal_prefix(id).cloned();
                Ok(Response::MaybeAddr { addr, as_of })
            }
            // AUTH-6.37: ω's whole entry off ONE walk of M3's registry
            // (`effective_owner_pair`); the two projections composed would
            // walk it twice. `addr` is a registry probe, not a doc-argument, so
            // the consult above passed it by. What the entry means to a caller
            // — the allocation test included — is `Op::EffectiveOwner`'s
            // contract.
            Op::EffectiveOwner { addr } => {
                let owner = world
                    .m3()
                    .effective_owner_pair(&addr)
                    .map(|(prefix, principal)| (prefix.clone(), principal));
                Ok(Response::EffectiveOwner { owner, as_of })
            }
            // ── raw link reads (→ M7, §2): no driver handle — straight off
            //    the one snapshot.
            Op::ReadLink { a } => {
                // A link homed in an unreadable document reads as ABSENT
                // (PUB-6.6): `⊥`, exactly as a never-deposited address.
                let link = if home_readable(&a, &readable) {
                    world.links().readlink(&a).cloned()
                } else {
                    None
                };
                Ok(Response::LinkValue { link, as_of })
            }
            // Carries its own Result in-band, deliberately (§2): M7 defines
            // ⟨⟩ ≠ ⊥ as two ANSWERS of FOLLOWLINK; lowering Invalid to a
            // Rejection would erase an unforgeable distinction. Contrast
            // Project, where M8's NotALink IS a precondition failure.
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
            // ── content/provenance reads (→ M6, §2) ──
            Op::RetrieveV { specs } => {
                // The delivery masks per RUN through the threaded predicate
                // (§4, PUB-6.41): each spec's NAMED doc was consulted above; the
                // runs its arrangement windows are masked here, a masked run
                // emitted as the withheld arm at its own position.
                let items = Query::new(&snap)
                    .retrieve_v_masked(&specs, &readable)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Delivery { items, as_of })
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
                let addrs =
                    Query::new(&snap).show_origin_v(&doc, &span).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Addrs { addrs, as_of })
            }
            Op::ShowDeletions { d_a, d_b } => {
                let rep =
                    Query::new(&snap).show_deletions(&d_a, &d_b).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Deletions { rep, as_of })
            }
            Op::Compare { rho1, rho2 } => {
                let rep =
                    Query::new(&snap).compare(&rho1, &rho2).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Compare { rep, as_of })
            }
            Op::FindDocsContaining { regions } => {
                // The container filter (§3): a candidate the reader may not
                // read is dropped at its identity; the region-spec docs were
                // consulted above.
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
            // The result-set family (§3): every reader drops each link whose
            // HOME the reader may not read, threaded the predicate. `d` was
            // consulted above; the filter is on the RESULT links' homes.
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
                let n = count_v_on(&snap, &d, &region, &readable)
                    .map_err(|e| lower_read(kind, e))?;
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
            // (the dual row, PUB-6.8); the ABSENCE of a link `a` homed in an
            // unreadable document (PUB-6.6) is M8's to answer, through the
            // predicate, and both answer it `NotALink` — which is also what
            // each gives for an address no link occupies, so the two are
            // indistinguishable as the rule requires. An admitted `project`
            // is UNFILTERED at origin (PUB-6.15); an admitted `a` that is
            // retracted answers `discoverable_from` `false`.
            Op::Project { a, slot, d } => {
                let set = project_on(&snap, &a, slot, &d, &readable)
                    .map_err(|e| lower_read(kind, e))?;
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
            // ── publication reads (lane 3.4, PUB-8.47): answers this door
            //    COMPOSES; what they need that no store computes is
            //    `crate::publication`'s ──
            // PUB-8.12: `doc` passed the consult above, so an unreadable one
            // was answered `withheld` before the registration refusal below
            // could describe it. The argument projects to its trunk (PUB-2.15)
            // and every document field is read off that one address: M5's own
            // `published_target` (the bit every gate keys on), M3's ω, and the
            // birth version. The SHOT TERMS alone are read off the address
            // NAMED (D25's (c′), served as a member read): a version member
            // the shot minted answers its own, and everything else — the trunk
            // included — answers none.
            Op::DocMetadata { doc } => {
                let m3 = world.m3();
                require_registered_document(m3, kind, &doc)?;
                let terms = world.m5().shot_terms(&doc).cloned();
                let trunk = trunk_of(&doc);
                let published = published_target(m3, &trunk);
                let owner = m3.effective_owner_prefix(&trunk).cloned();
                let birth = birth_version(m3, world.m5(), &trunk);
                Ok(Response::DocMetadata { doc: trunk, published, owner, birth, terms, as_of })
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
