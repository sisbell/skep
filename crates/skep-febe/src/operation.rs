//! The lifecycle entry ([`Operation::execute`]) and the two static dispatch
//! tables (§1–§4): parse → authorize → linearize → commit-gate → marshal →
//! surface. The lifecycle's order lives here; the two pieces of state it
//! consults belong to their own cards — [`crate::session::Sessions`] for the
//! ephemeral binding (§6), [`crate::idem::IdemCache`] for the committed-write
//! retry memo (§7).

use std::sync::atomic::{AtomicBool, Ordering};

// `FebeWorld` names the accessor bound set, and its supertraits carry the
// `m3()`/`m5()`/`links()` methods the read arms call, so no accessor trait
// is imported here by name.
use skep_arrangement::{Caller, M5Rec};
use skep_content::ContentWrite;
use skep_discovery::{
    count_ftt_on, count_v_on, delete_orphans_on, discoverable_from_on, findlinks_ftt_on,
    findlinks_v_on, image_on, in_claims_on, out_claims_on, project_on, retrieve_endsets_on,
    window_ftt_on, window_v_on,
};
use skep_kernel::{Seq, TxnError, WorldState};
use skep_links::{enc, Link, LinkRec, SlotArg, MAX_SLOT_SPANS};
use skep_namespace::{M3Rec, PrincipalId, BOOTSTRAP_PRINCIPAL};
use skep_retrieval::Query;

use crate::idem::IdemCache;
use crate::lower::{lower_read, lower_txn, Lower};
use crate::op::{Op, OpKind, Request};
use crate::reject::{reject, rejection, RejectCode, Rejection};
use crate::response::Response;
use crate::session::{SessionId, Sessions};
use crate::successor::endset_from_vspecs;
use crate::{FebeWorld, Stores};

/// M10's front-door handle (§Public interface). Owns **no** authoritative
/// substrate state and **no** `im` structure — its fields are the ephemeral
/// connection state ([`Sessions`]), a best-effort committed-write retry memo
/// ([`IdemCache`]), and a recomputable poison hint; none is ever snapshotted
/// or replayed, which is why this is the one module that legitimately departs
/// from the `im`-everywhere convention (§Core data model).
pub struct Operation<W: WorldState> {
    /// Borrowed authority: the binary's factory (M2/M3/M5/M7 own real state).
    stores: Box<dyn Stores<W>>,
    /// Which principal each open session speaks for — retired only by
    /// [`Operation::close_session`] (§6).
    sessions: Sessions,
    /// Hint: the committed-write retry memo (§7). A session's entries are
    /// swept by [`Operation::close_session`] — those present when the sweep
    /// runs (§6) — and the whole memo is lost on restart, so a post-restart
    /// retry re-executes (duplicate, by design — ASN-0134 §A7).
    idem: IdemCache,
    /// Hint: recomputable by attempting `transact`; latched by the first
    /// `TxnError::Poisoned` in [`Operation::map_txn`] (§5/§9).
    poisoned: AtomicBool,
}

/// The proven-bound write context (§1). Step (b) resolves the principal
/// BEFORE dispatch, so each ownership-checked write arm names `wc.principal`
/// (a `PrincipalId`, never an `Option`) — no `.expect()`, no non-local "the
/// gate guaranteed it" reasoning.
struct WriteCtx {
    principal: PrincipalId,
}

impl WriteCtx {
    /// The session principal as the stores' caller identity (the ownership
    /// ruling, as amended 2026-08-16): M10 passes it through verbatim —
    /// the stores own the mechanism "is this principal the effective owner".
    /// M10 never constructs `Caller::System`.
    fn caller(&self) -> Caller {
        Caller::Principal(self.principal)
    }
}

impl<W> Operation<W>
where
    W: FebeWorld,
    W::Record: From<M3Rec> + From<M5Rec> + From<LinkRec> + From<ContentWrite>,
{
    /// Receive a [`Stores`] factory (built by the binary/engine, wrapping the
    /// recovered kernel via the store-driver constructors). The binary calls
    /// `Kernel::open` (M2 recovery), handles `OpenError::{Corruption,
    /// BadCheckpoint}`, and builds the factory BEFORE constructing us — M10
    /// holds neither the kernel nor the registry directly (§9). We reach the
    /// kernel via `stores.kernel()` and acquire each store driver per-op.
    ///
    /// The idempotency memo is bounded at a crate-fixed default capacity: the
    /// design's explicit `idem_capacity` construction knob conflicts with the
    /// interface's one-argument `new`, and the interface wins (see
    /// [`IdemCache`]).
    pub fn new(stores: Box<dyn Stores<W>>) -> Self {
        Operation {
            stores,
            sessions: Sessions::new(),
            idem: IdemCache::new(),
            poisoned: AtomicBool::new(false),
        }
    }

    // ── session binding (M10-owned, ephemeral — §6) ──

    /// Record the binding and return a fresh `SessionId`, unique within one
    /// M10 uptime (reset on restart; clients re-authenticate). The caller
    /// (transport) supplies the authenticated `PrincipalId`; unforgeability
    /// of the id is the transport's precondition (§6): it must inject `s`
    /// from the connection's authenticated binding, never read it off the
    /// wire.
    pub fn open_session(&self, principal: PrincipalId) -> SessionId {
        self.sessions.open(principal)
    }

    /// Retire the binding, then sweep the session's memoized acks (§6/§7).
    /// The two collaborators are asked in turn, their locks never nested.
    ///
    /// The order is load-bearing, and it is what makes the first half
    /// unconditional: `close` runs before the sweep, so the moment this
    /// returns the id resolves to no principal for the rest of the uptime and
    /// no write on it can ever be authorized again.
    ///
    /// The sweep is not atomic against a request already in flight. An
    /// `execute` past its step-(a) lookup may deposit its ack after the sweep
    /// has passed, and that entry then lives until eviction. What it can do is
    /// bounded: presenting the retired id again replays one acknowledgment of
    /// a write this session itself committed. It authorizes nothing and
    /// commits nothing — the binding is already gone — and it cannot cross
    /// principals, because the memo's key confines a `ReqId` to the session
    /// that committed under it.
    ///
    /// Calling this on connection drop is a transport obligation: nothing else
    /// retires a binding.
    pub fn close_session(&self, s: SessionId) {
        self.sessions.close(s);
        self.idem.purge_session(s);
    }

    /// A session bound to `BOOTSTRAP_PRINCIPAL`, so the first
    /// `delegate`/`create`/`register_node` can happen. Confinement is
    /// transport policy (§6): the transport must not expose this beyond
    /// provisioning — it mints bootstrap authority ungated.
    pub fn bootstrap_session(&self) -> SessionId {
        self.open_session(BOOTSTRAP_PRINCIPAL)
    }

    /// THE lifecycle entry (§1). Total: always yields a `Response` to send
    /// (rejections are a `Response` variant) — totality leans on the
    /// non-poisoning locks its two state collaborators hold (§7) and on the
    /// step-(b) read/write split, which hands each write arm a PROVEN-bound
    /// principal so no dispatch arm unwraps an `Option`. Reentrant & `Sync`
    /// — the transport may call it concurrently for pipelined requests (§8).
    ///
    /// Caller precondition (§6, non-forgeability): `s` MUST originate in the
    /// transport's connection state, never a wire-supplied value.
    ///
    /// Two refusals can hold at once on a write, and the contract names which
    /// speaks: the poison gate (c) is consulted BEFORE the session gate (b),
    /// so a write from an unbound session against a halted kernel answers
    /// `Poisoned`/`Halt` and never `Unauthenticated`. A client is told the
    /// engine has stopped even where its own defect is that it must
    /// re-authenticate. Step (a) precedes both, so a retry of a write that
    /// already committed is answered from the memo whatever either gate would
    /// have said.
    pub fn execute(&self, s: SessionId, req: Request) -> Response {
        let Request { id, op } = req;
        let kind = op.kind(); // Copy; captured before dispatch moves the op
        // (a) idempotency: a repeated (s, id) whose op-kind matches returns
        //     the memoized committed-write ack, never re-executing. Keyed
        //     (s, id) — a replay under a DIFFERENT session misses (§7).
        if let Some(id) = &id {
            if let Some(ack) = self.idem.get(s, id, kind) {
                return ack.into();
            }
        }
        // (c) then (b) — in that order, which is the stated precedence when
        //     both refusals hold — gating the write path only, since the
        //     is_write/is_read split gives each path exactly the authority it
        //     needs (§1). The write path resolves a PROVEN-bound principal
        //     HERE (the one place it can fail); the read path takes neither
        //     gate.
        let resp = if op.is_write() {
            // (c) refuse writes on a poisoned kernel; reads are still served
            //     through the else-branch (§9).
            if self.poisoned.load(Ordering::Relaxed) {
                return reject(kind, RejectCode::Poisoned); // disposition_of ⇒ Halt
            }
            match self.sessions.principal_of(s) {
                // (b) the one place authority can fail
                Some(principal) => self.dispatch_write(WriteCtx { principal }, op),
                None => return reject(kind, RejectCode::Unauthenticated), // ⇒ Permanent
            }
        } else {
            self.dispatch_read(op) // reads tolerate an unbound session
        }
        .unwrap_or_else(Response::Rejected);
        // (d) memoize ONLY a committed-write ack. `as_ack` is what decides —
        //     a Rejected and a read answer both yield None, so neither can
        //     be replayed (a Reorder/Retry reissue MUST re-execute; a cached
        //     read would replay a stale snapshot). The memo holds that small
        //     ack, not the Response (§7). Nested on the id, so a request that
        //     carried none never builds the ack it would then drop — `as_ack`
        //     clones the acknowledged addresses.
        if let Some(id) = id {
            if let Some(ack) = resp.as_ack() {
                self.idem.put(s, id, kind, ack);
            }
        }
        resp
    }

    /// Bare "where is the log?" — `stores.kernel().current_seq()`; never
    /// regresses (the read-your-writes building block, G0).
    pub fn log_position(&self) -> Seq {
        self.stores.kernel().current_seq()
    }

    // ── write dispatch (§1/§3/§4) ──

    /// The static table for the write half: every arm acquires a driver
    /// per-op from the factory, returns only its post-commit value (A7 is
    /// upheld structurally — M10 has nothing to put on the wire until the
    /// driver returns at/after `lin(op)`), classifies `TxnError<E>` through
    /// [`Operation::map_txn`] so the poison hint latches on the way past,
    /// and stamps the committed `Seq`. Exhaustive over `Op` with NO `_`
    /// wildcard: the complementary (read) half is one explicit `|`-list arm
    /// rejecting `Malformed` — never a panic — so a newly added `Op` variant
    /// is a compile-time non-exhaustiveness error here, at `is_read`, and at
    /// `dispatch_read`.
    ///
    /// The coordinate a driver hands back is `at` in every arm, and
    /// `committed_at` — the design's own word for it — in the two arms whose
    /// operation carries an `at` of its own (a `VPos`). Those are the only
    /// two spellings; a third would make one concept read as two.
    fn dispatch_write(&self, wc: WriteCtx, op: Op) -> Result<Response, Rejection> {
        let kind = op.kind();
        match op {
            // ── namespace writes (→ M3) ──
            Op::CreateNewDocument { account } => {
                let (addr, at) = self
                    .stores
                    .namespace()
                    .create_new_document(wc.principal, &account)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::Delegate { new_prefix, new_id } => {
                let (addr, at) = self
                    .stores
                    .namespace()
                    .delegate(wc.principal, new_prefix, new_id)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // No principal: the node addr is supplied by provisioning, and
            // M3's `register_node` takes none. The step-(b) bound-session
            // gate applied, uniformly (§6) — and it is the whole authority
            // check this path gets, here or in M3 (see `Op::RegisterNode`).
            Op::RegisterNode { addr } => {
                let (addr, at) =
                    self.stores.namespace().register_node(addr).map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // Fork ≠ Version (§3): mints an EMPTY account-tier document,
            // sharing NO content; the content-sharing fork is Op::Version.
            Op::Fork => {
                let (addr, at) =
                    self.stores.namespace().fork(wc.principal).map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // ── arrangement writes (→ M5; ω-gated in-store under the
            //    session caller — the ownership ruling, 2026-08-16) ──
            Op::Insert { doc, at, values } => {
                let (start, committed_at) = self
                    .stores
                    .vstream()
                    .insert(wc.caller(), &doc, at, values)
                    .map_err(|e| self.map_txn(kind, e))?; // returns post-commit
                Ok(Response::AckAddr { addr: start, at: committed_at }) // the exact V1 coordinate
            }
            Op::Delete { doc, p, width } => {
                let at = self
                    .stores
                    .vstream()
                    .delete(wc.caller(), &doc, p, width)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::Ack { at })
            }
            Op::Copy { doc, at, specs } => {
                let committed_at = self
                    .stores
                    .vstream()
                    .copy(wc.caller(), &doc, at, specs)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::Ack { at: committed_at })
            }
            Op::Rearrange { doc, cuts } => {
                let at = self
                    .stores
                    .vstream()
                    .rearrange(wc.caller(), &doc, cuts)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::Ack { at })
            }
            Op::Version { d_src } => {
                let (addr, at) = self
                    .stores
                    .vstream()
                    .version(wc.principal, &d_src) // M5 does the owned/cross-owner branch
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // ── link writes (→ M7; ω-gated in-store on each written home —
            //    the ownership ruling, 2026-08-16) ──
            Op::MakeLink { home, from, to, ty } => {
                // M7 handles both slot forms INSIDE its transact: Resolve
                // V-specs off the txn base, Addrs deposited verbatim.
                let (addr, at) = self
                    .stores
                    .linkstore()
                    .makelink(wc.caller(), &home, from, to, ty)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // Idempotent zero-step ops need no special case (§3): a dedup hit
            // returns (incumbent, base_seq) with no commit; marshaled
            // identically to a miss (ASN-0134 §A1).
            Op::Emit { home, ty, from, to } => {
                let (addr, at) = self
                    .stores
                    .linkstore()
                    .emit(wc.caller(), &home, &ty, &from, &to)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::Nullify { home, target } => {
                let (addr, at) = self
                    .stores
                    .linkstore()
                    .nullify(wc.caller(), &home, &target)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::AssertSup { home, old, new } => {
                let (addr, at) = self
                    .stores
                    .linkstore()
                    .assert_sup(wc.caller(), &home, &old, &new)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // The one read-assembled request (§4): the successor's content
            // V-specs resolve through M5 off a PRIOR snapshot — deliberately
            // not in editlink's write transaction (recorded I-addresses are
            // permanent, so d_s's arrangement may move underneath with no
            // hazard). One operation ⇒ still one M2 transaction.
            Op::EditLink { original, successor, d_s, d_a } => {
                let snap = self.stores.kernel().snapshot();
                let (m3, m5) = (snap.world().m3(), snap.world().m5());
                // `from`, then `to`, then `ty` — the slot order IS the refusal
                // precedence a client is promised (`SuccessorSpec`), and the
                // `?` is what makes the first refusal the only one.
                let from = endset_from_vspecs(m3, m5, &successor.from)?;
                let to = endset_from_vspecs(m3, m5, &successor.to)?;
                let ty = match &successor.ty {
                    // TYPE is the successor's one two-form slot (§4):
                    // address-denoting or content-resolved; M7 owns the
                    // slot-shape/schema verdict inside editlink. Both forms
                    // are held to M7's per-slot budget HERE, where the slot
                    // is built, and before the encoding is: `enc` turns each
                    // ~19-byte name into a subtree span of two multi-component
                    // tumblers, so a list bounded only by the frame is a ~26×
                    // amplification into memory M7 would then refuse anyway.
                    SlotArg::Addrs(a) => {
                        if a.len() > MAX_SLOT_SPANS {
                            return Err(rejection(kind, RejectCode::SlotTooLarge));
                        }
                        enc(a)
                    }
                    SlotArg::Resolve(v) => endset_from_vspecs(m3, m5, v)?,
                };
                let link = Link::triple(from, to, ty);
                let (succ, claim, at) = self
                    .stores
                    .linkstore()
                    .editlink(wc.caller(), &original, link, &d_s, &d_a)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckEdit { successor: succ, claim, at })
            }
            // Complementary half — unreachable under the is_write partition
            // that selected this function; written as an explicit |-list (no
            // `_`) so a new Op variant fails to compile here, and rejecting
            // (never panicking) so execute's Total contract holds regardless
            // of the partition's correctness (§1).
            Op::NextAccountPrefix { .. }
            | Op::PrincipalPrefix { .. }
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
            | Op::OutClaims { .. } => Err(rejection(kind, RejectCode::Malformed)),
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
    /// surfaces: `Query::new` for M6, and M8's pure `*_on` twins rather than
    /// the self-snapshotting `LinkQuery` handle (Conflicts resolved #5),
    /// whose second snapshot would answer from one position while `as_of`
    /// named another. Reads hold no lock against writers, are zero-step
    /// (A1), and have no commit-before-ack obligation. No principal, no
    /// session. Exhaustive over `Op` with the complementary (write) half as
    /// one explicit rejecting |-list — see `dispatch_write`.
    fn dispatch_read(&self, op: Op) -> Result<Response, Rejection> {
        let kind = op.kind();
        let snap = self.stores.kernel().snapshot();
        let as_of = snap.seq();
        match op {
            // ── namespace reads (→ M3, §2): the M3-internal frontier/
            //    registry values Delegate/CreateNewDocument demand. Total —
            //    Option<Address>, no fault path.
            Op::NextAccountPrefix { parent } => {
                let addr = snap.world().m3().next_account_prefix(&parent);
                Ok(Response::MaybeAddr { addr, as_of })
            }
            // Takes an explicit wire id, not the session's bound principal —
            // deliberate (§2): a prefix is public, immutable registry data,
            // and the read path is principal-free by construction.
            Op::PrincipalPrefix { id } => {
                let addr = snap.world().m3().principal_prefix(id).cloned();
                Ok(Response::MaybeAddr { addr, as_of })
            }
            // ── raw link reads (→ M7, §2): no driver handle — straight off
            //    the one snapshot.
            Op::ReadLink { a } => {
                let link = snap.world().links().readlink(&a).cloned();
                Ok(Response::LinkValue { link, as_of })
            }
            // Carries its own Result in-band, deliberately (§2): M7 defines
            // ⟨⟩ ≠ ⊥ as two ANSWERS of FOLLOWLINK; lowering Invalid to a
            // Rejection would erase an unforgeable distinction. Contrast
            // Project, where M8's NotALink IS a precondition failure.
            Op::FollowLink { a, slot } => {
                let result = snap.world().links().followlink(&a, slot);
                Ok(Response::Follow { result, as_of })
            }
            // ── content/provenance reads (→ M6, §2) ──
            Op::RetrieveV { specs } => {
                let items =
                    Query::new(&snap).retrieve_v(&specs).map_err(|e| lower_read(kind, e))?;
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
                let addrs = Query::new(&snap)
                    .find_docs_containing(&regions)
                    .map_err(|e| lower_read(kind, e))?;
                Ok(Response::Addrs { addrs, as_of })
            }
            // ── link discovery reads (→ M8, §2): always the pure *_on twins
            //    over M10's one snapshot, never the self-snapshotting handle.
            Op::Image { d, region } => {
                let runs = image_on(&snap, &d, &region).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Runs { runs, as_of })
            }
            Op::FindLinksV { d, region } => {
                let addrs = findlinks_v_on(&snap, &d, &region).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Addrs { addrs, as_of })
            }
            Op::FindLinksFtt { q } => {
                let addrs = findlinks_ftt_on(&snap, &q); // total — no error map
                Ok(Response::Addrs { addrs, as_of })
            }
            Op::CountV { d, region } => {
                let n = count_v_on(&snap, &d, &region).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Count { n, as_of })
            }
            Op::CountFtt { q } => {
                let n = count_ftt_on(&snap, &q); // total
                Ok(Response::Count { n, as_of })
            }
            Op::WindowV { d, region, cur, n } => {
                let window =
                    window_v_on(&snap, &d, &region, cur, n).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Page { window, as_of })
            }
            Op::WindowFtt { q, cur, n } => {
                let window = window_ftt_on(&snap, &q, cur, n); // total
                Ok(Response::Page { window, as_of })
            }
            Op::RetrieveEndsets { d, region } => {
                let pairs = retrieve_endsets_on(&snap, &d, &region).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Endsets { pairs, as_of })
            }
            Op::Project { a, slot, d } => {
                let set = project_on(&snap, &a, slot, &d).map_err(|e| lower_read(kind, e))?;
                Ok(Response::SpanSet { set, as_of })
            }
            Op::DiscoverableFrom { a, d } => {
                let val = discoverable_from_on(&snap, &a, &d).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Bool { val, as_of })
            }
            Op::DeleteOrphans { d, p, width } => {
                let report =
                    delete_orphans_on(&snap, &d, &p, &width).map_err(|e| lower_read(kind, e))?;
                Ok(Response::Orphans { report, as_of })
            }
            Op::InClaims { y, view } => {
                let claims = in_claims_on(&snap, &y, view); // total
                Ok(Response::Claims { claims, as_of })
            }
            Op::OutClaims { x, view } => {
                let claims = out_claims_on(&snap, &x, view); // total
                Ok(Response::Claims { claims, as_of })
            }
            // Complementary half — see dispatch_write's twin arm (§1).
            Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork
            | Op::Insert { .. }
            | Op::Delete { .. }
            | Op::Copy { .. }
            | Op::Rearrange { .. }
            | Op::Version { .. }
            | Op::MakeLink { .. }
            | Op::Emit { .. }
            | Op::Nullify { .. }
            | Op::AssertSup { .. }
            | Op::EditLink { .. } => Err(rejection(kind, RejectCode::Malformed)),
        }
    }

    // ── rejection surfacing (§5) ──

    /// Classify a write path's `TxnError` through the [`lower_txn`] table,
    /// latching the poison hint on the way past `Poisoned` so `execute` step
    /// (c) can fail the next write fast rather than opening a doomed
    /// transaction. The latch is why every write arm classifies HERE and not
    /// through `lower_txn` directly. `Relaxed` suffices: the flag is a hint,
    /// and M2 independently returns `Poisoned` to every later write whether
    /// or not this one is seen.
    fn map_txn<E: Lower>(&self, kind: OpKind, e: TxnError<E>) -> Rejection {
        if matches!(e, TxnError::Poisoned) {
            self.poisoned.store(true, Ordering::Relaxed); // LATCH (§1(c)/§9)
        }
        lower_txn(kind, e)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde::{Deserialize, Serialize};
    use skep_address::{validate, Address, Nat, Tumbler};
    use skep_arrangement::{HasM5, InsertError, M5Rec, M5State, VPos};
    use skep_content::{ContentStore, ContentWrite, HasContent, Val};
    use skep_kernel::{
        CheckpointPolicy, Durability, Kernel, KernelConfig, Seq, TxnError, WorldState,
    };
    use skep_links::{HasLinks, LinkRec, LinkState, LinkWriter};
    use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

    use super::*;
    use crate::op::ReqId;
    use crate::reject::Disposition;

    // ── a minimal assembled world (the composition contract in miniature) ──

    #[derive(Clone, Serialize, Deserialize)]
    struct World {
        m3: M3State,
        content: ContentStore,
        m5: M5State,
        links: LinkState,
    }

    #[derive(Clone, Serialize, Deserialize)]
    enum Record {
        M3(M3Rec),
        Content(ContentWrite),
        M5(M5Rec),
        Links(LinkRec),
    }

    impl WorldState for World {
        type Record = Record;
        fn apply(&self, r: &Record) -> World {
            match r {
                Record::M3(x) => World { m3: self.m3.apply_m3(x), ..self.clone() },
                Record::Content(x) => World { content: self.content.apply_write(x), ..self.clone() },
                Record::M5(x) => World { m5: self.m5.apply_m5(x), ..self.clone() },
                Record::Links(x) => World { links: self.links.apply_link(x), ..self.clone() },
            }
        }
        fn rebuild_derived(self) -> Self {
            let World { m3, content, m5, links } = self;
            World { m3, content, m5: m5.rebuild_derived(), links: links.rebuild_derived() }
        }
    }

    impl HasM3 for World {
        fn m3(&self) -> &M3State {
            &self.m3
        }
    }
    impl HasContent for World {
        fn content(&self) -> &ContentStore {
            &self.content
        }
    }
    impl HasM5 for World {
        fn m5(&self) -> &M5State {
            &self.m5
        }
    }
    impl HasLinks for World {
        fn links(&self) -> &LinkState {
            &self.links
        }
    }
    impl From<M3Rec> for Record {
        fn from(r: M3Rec) -> Record {
            Record::M3(r)
        }
    }
    impl From<ContentWrite> for Record {
        fn from(r: ContentWrite) -> Record {
            Record::Content(r)
        }
    }
    impl From<M5Rec> for Record {
        fn from(r: M5Rec) -> Record {
            Record::M5(r)
        }
    }
    impl From<LinkRec> for Record {
        fn from(r: LinkRec) -> Record {
            Record::Links(r)
        }
    }

    fn tum(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }
    fn addr(comps: &[u32]) -> Address {
        validate(tum(comps)).unwrap_or_else(|_| panic!("T4-valid test address"))
    }
    fn genesis_world() -> World {
        World {
            m3: M3State::genesis(),
            content: ContentStore::default(),
            m5: M5State::genesis(),
            links: LinkState::genesis(),
        }
    }

    fn kernel() -> Arc<Kernel<World>> {
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        Arc::new(Kernel::open(cfg, genesis_world()).expect("in-memory open cannot fail"))
    }

    struct KernelStores {
        kernel: Arc<Kernel<World>>,
    }

    impl crate::Stores<World> for KernelStores {
        fn kernel(&self) -> &Kernel<World> {
            &self.kernel
        }
        fn linkstore(&self) -> LinkWriter<'_, World> {
            LinkWriter::new(&self.kernel)
        }
    }

    fn operation() -> Operation<World> {
        Operation::new(Box::new(KernelStores { kernel: kernel() }))
    }

    fn insert_op() -> Op {
        Op::Insert {
            doc: addr(&[1, 0, 1, 0, 1]),
            at: VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) },
            values: vec![Val::new(vec![1u8])],
        }
    }

    fn rejected(r: Response) -> Rejection {
        match r {
            Response::Rejected(rej) => rej,
            _ => panic!("expected Rejected"),
        }
    }

    /// §8: `execute` is reentrant & Sync — the handle is shareable across the
    /// transport's pipelined callers.
    #[test]
    fn operation_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Operation<World>>();
    }

    /// §6: ids are unique within an uptime; a closed session is unbound, so a
    /// later write on it is rejected `Unauthenticated` (Permanent) before any
    /// transaction — no store is touched.
    #[test]
    fn closed_session_write_is_unauthenticated() {
        let febe = operation();
        let s1 = febe.open_session(PrincipalId(1));
        let s2 = febe.open_session(PrincipalId(2));
        assert_ne!(s1, s2);
        febe.close_session(s1);
        let rej = rejected(febe.execute(s1, Request { id: None, op: insert_op() }));
        assert_eq!(rej.op, OpKind::Insert);
        assert_eq!(rej.code, RejectCode::Unauthenticated);
        assert_eq!(rej.disposition, Disposition::Permanent);
    }

    /// §6/§Invariants: the step-(b) gate is ONE uniform rule — a write
    /// requires a bound session, full stop — so it holds for all fourteen
    /// writes, `RegisterNode` (whose principal M3 ignores) included. And it
    /// holds BEFORE any transaction, which is what the unmoved log position
    /// witnesses: no store is reached on the way to the refusal.
    #[test]
    fn every_write_on_an_unbound_session_is_unauthenticated_before_any_transaction() {
        let febe = operation();
        let s = febe.open_session(PrincipalId(1));
        febe.close_session(s);
        let before = febe.log_position();
        for (op, is_read) in crate::op::tests::all_ops() {
            if is_read {
                continue;
            }
            let kind = op.kind();
            match febe.execute(s, Request { id: None, op }) {
                Response::Rejected(rej) => {
                    assert_eq!(rej.op, kind, "the rejection names the op it refused");
                    assert_eq!(rej.code, RejectCode::Unauthenticated, "{kind:?}");
                    assert_eq!(rej.disposition, Disposition::Permanent, "{kind:?}");
                }
                _ => panic!("{kind:?} was answered on an unbound session"),
            }
        }
        assert_eq!(
            febe.log_position(),
            before,
            "no write on an unbound session may reach a transaction"
        );
    }

    /// §1/§2, the complement of the gate above: a read tolerates an unbound
    /// session — no principal, no session. Every read arm is driven through
    /// `execute` on an id that was never opened; each may reject for its own
    /// reasons against a genesis world, but never for authentication. Driving
    /// all 24 also exercises `execute`'s Total contract on the read half: an
    /// arm that panics fails here.
    #[test]
    fn no_read_is_ever_rejected_for_an_unbound_session() {
        let febe = operation();
        let never_opened = SessionId(9999);
        for (op, is_read) in crate::op::tests::all_ops() {
            if !is_read {
                continue;
            }
            let kind = op.kind();
            if let Response::Rejected(rej) = febe.execute(never_opened, Request { id: None, op }) {
                assert_ne!(
                    rej.code,
                    RejectCode::Unauthenticated,
                    "{kind:?} is a read: the session gate is not its to fail"
                );
            }
        }
    }

    /// §5/§9: the first `TxnError::Poisoned` latches the flag inside
    /// `map_txn`; thereafter writes fail fast with Halt at step (c) while
    /// reads keep being served off the last root.
    #[test]
    fn poison_latch_halts_writes_but_reads_continue() {
        let febe = operation();
        let s = febe.open_session(PrincipalId(1));
        let rej = febe.map_txn(OpKind::Insert, TxnError::<InsertError>::Poisoned);
        assert_eq!(rej.code, RejectCode::Poisoned);
        assert_eq!(rej.disposition, Disposition::Halt);
        assert!(febe.poisoned.load(Ordering::Relaxed));
        // Write: fails fast pre-dispatch.
        let rej = rejected(febe.execute(s, Request { id: None, op: insert_op() }));
        assert_eq!(rej.code, RejectCode::Poisoned);
        assert_eq!(rej.disposition, Disposition::Halt);
        // Read: still served (M2 snapshots survive a poisoned kernel).
        let resp = febe.execute(s, Request { id: None, op: Op::NextAccountPrefix { parent: addr(&[1]) } });
        match resp {
            Response::MaybeAddr { addr, .. } => assert!(addr.is_some()),
            _ => panic!("read must still be served on a poisoned kernel"),
        }
    }

    /// §1: the precedence when both write gates would refuse. Gate (c) is
    /// consulted before gate (b), so a write on a CLOSED session against a
    /// latched kernel answers `Poisoned`/`Halt` — the client is told the
    /// engine stopped, not that it must re-authenticate. Without the order
    /// this request has two defensible answers and nothing choosing between
    /// them.
    #[test]
    fn a_halted_kernel_outranks_an_unbound_session() {
        let febe = operation();
        let s = febe.open_session(PrincipalId(1));
        febe.close_session(s);
        febe.map_txn(OpKind::Insert, TxnError::<InsertError>::Poisoned); // LATCH
        let rej = rejected(febe.execute(s, Request { id: None, op: insert_op() }));
        assert_eq!(
            rej.code,
            RejectCode::Poisoned,
            "the poison gate speaks first, so an unbound session is not what this refusal names"
        );
        assert_eq!(rej.disposition, Disposition::Halt);
    }

    /// §7/§1(d): the memo admits a committed-write acknowledgment and
    /// nothing else. `as_ack` is what refuses the other two shapes, so
    /// neither a rejection surfaced through `execute` (a Reorder/Retry
    /// reissue MUST re-execute) nor a read answer (whose snapshot goes
    /// stale) can be memoized even when the request carried an id.
    #[test]
    fn only_committed_writes_are_cached() {
        let febe = operation();
        let s = febe.open_session(PrincipalId(1));
        assert!(Response::Count { n: 3, as_of: Seq(1) }.as_ack().is_none());
        assert!(Response::Rejected(rejection(OpKind::Insert, RejectCode::Unauthenticated))
            .as_ack()
            .is_none());
        // A rejected write carrying an id leaves no entry behind.
        let id = ReqId(b"req-2".to_vec());
        let stray = febe.open_session(PrincipalId(3));
        febe.close_session(stray);
        let r = febe.execute(stray, Request { id: Some(id.clone()), op: insert_op() });
        assert!(matches!(r, Response::Rejected(_)));
        assert!(febe.idem.get(stray, &id, OpKind::Insert).is_none());
        // Nor does a read carrying one.
        let rid = ReqId(b"req-3".to_vec());
        let resp = febe.execute(
            s,
            Request { id: Some(rid.clone()), op: Op::NextAccountPrefix { parent: addr(&[1]) } },
        );
        assert!(matches!(resp, Response::MaybeAddr { .. }));
        assert!(febe.idem.get(s, &rid, OpKind::NextAccountPrefix).is_none());
    }

    /// §1: step (a) runs AHEAD of the step-(c) poison gate, and that order is
    /// what a client retrying a write it already committed depends on — it
    /// receives the acknowledgment it lost, not the news that the kernel has
    /// since halted. A write it has NOT committed is halted, which is what
    /// makes the replay above a statement about the order rather than about
    /// the latch being unset.
    #[test]
    fn a_memoized_ack_is_replayed_on_a_poisoned_kernel() {
        let febe = operation();
        let s = febe.bootstrap_session();
        let id = ReqId(b"node-5".to_vec());
        let node = || Op::RegisterNode { addr: tum(&[1, 5]) };
        let (addr, at) = match febe.execute(s, Request { id: Some(id.clone()), op: node() }) {
            Response::AckAddr { addr, at } => (addr, at),
            _ => panic!("RegisterNode under the bootstrap session commits"),
        };

        // The kernel halts AFTER that write committed.
        febe.map_txn(OpKind::Insert, TxnError::<InsertError>::Poisoned);
        assert!(febe.poisoned.load(Ordering::Relaxed));

        // A fresh keyed write is halted at step (c) — the gate is live.
        let rej = rejected(febe.execute(
            s,
            Request { id: Some(ReqId(b"node-6".to_vec())), op: Op::RegisterNode { addr: tum(&[1, 6]) } },
        ));
        assert_eq!(rej.code, RejectCode::Poisoned);
        assert_eq!(rej.disposition, Disposition::Halt);

        // The retry of the committed one is answered from the memo instead.
        match febe.execute(s, Request { id: Some(id), op: node() }) {
            Response::AckAddr { addr: replayed, at: replayed_at } => {
                assert_eq!(replayed, addr, "the replayed ack is the committed one");
                assert_eq!(replayed_at, at, "…at the coordinate it committed");
            }
            _ => panic!("a memoized ack is served ahead of the poison gate"),
        }
    }

    /// §1: the partition is written in three places — `is_read`, and each
    /// dispatch table's complement `|`-list — and they must agree. Adding a
    /// variant is caught by the compiler at all three; MOVING one across the
    /// partition is not, because every match stays exhaustive: `is_read`
    /// alone picks the table, so an op moved in that one list would route to
    /// the table whose complement arm holds it and answer `Malformed`
    /// forever. Feeding every op to the WRONG table pins the agreement — each
    /// complement arm must hold exactly the ops `is_read` sends elsewhere.
    #[test]
    fn each_dispatch_table_rejects_exactly_the_other_half() {
        let febe = operation();
        for (op, is_read) in crate::op::tests::all_ops() {
            let kind = op.kind();
            let wrong_table = if is_read {
                febe.dispatch_write(WriteCtx { principal: PrincipalId(1) }, op)
            } else {
                febe.dispatch_read(op)
            };
            match wrong_table {
                Err(rej) => {
                    assert_eq!(rej.op, kind);
                    assert_eq!(rej.code, RejectCode::Malformed, "{kind:?}");
                }
                Ok(_) => panic!("{kind:?} was answered by the table for the other half"),
            }
        }
    }
}
