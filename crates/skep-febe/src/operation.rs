//! The lifecycle entry ([`Operation::execute`]) and the two static dispatch
//! tables (§1–§4): parse → authorize → linearize → commit-gate → marshal →
//! surface, plus the ephemeral session binding (§6) and the idempotency
//! cache (§7).

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use lru::LruCache;
use parking_lot::Mutex;

use skep_address::{Address, Nat, Span};
use skep_arrangement::{Caller, HasM5, M5Rec, M5State, Run, VSpec};
use skep_content::{ContentWrite, HasContent};
use skep_discovery::{
    count_ftt_on, count_v_on, delete_orphans_on, discoverable_from_on, findlinks_ftt_on,
    findlinks_v_on, image_on, in_claims_on, out_claims_on, project_on, retrieve_endsets_on,
    window_ftt_on, window_v_on,
};
use skep_kernel::{Seq, TxnError, WorldState};
use skep_links::{enc, Endset, HasLinks, Link, LinkRec, SlotArg};
use skep_namespace::{HasM3, M3Rec, PrincipalId, BOOTSTRAP_PRINCIPAL};
use skep_retrieval::Query;

use crate::lower::{map_read, Lower};
use crate::op::{Op, OpKind, ReqId, Request, SessionId};
use crate::reject::{reject, reject1, RejectCode, Rejection};
use crate::response::Response;
use crate::Stores;

/// The idempotency LRU's capacity.
// OPEN DECISION: the interface pins `Operation::new(stores)` with NO
// `idem_capacity` parameter, while the design (§7 / Core data model / Open
// build decision 3) calls for an explicit construction-time knob with "no
// implicit default". The interface is the higher authority for the public
// surface, so the knob is absent and this crate-fixed default bounds the LRU
// instead — surfaced in the build report as an interface↔design conflict.
const DEFAULT_IDEM_CAPACITY: usize = 1024;

/// M10's front-door handle (§Public interface). Owns **no** authoritative
/// substrate state and **no** `im` structure — its fields are ephemeral
/// connection state (`sessions`), a best-effort committed-write retry memo
/// (`idem`), and a recomputable poison hint; none is ever snapshotted or
/// replayed, which is why this is the one module that legitimately departs
/// from the `im`-everywhere convention (§Core data model).
pub struct Operation<W: WorldState> {
    /// Borrowed authority: the binary's factory (M2/M3/M5/M7 own real state).
    stores: Box<dyn Stores<W>>,
    /// Ephemeral authoritative connection state — retired only by
    /// [`Operation::close_session`] (§6). Non-poisoning lock (§7): a panic
    /// while held must not break `execute`'s Total contract.
    sessions: Mutex<HashMap<SessionId, PrincipalId>>,
    /// Ephemeral session-id counter — ids unique within one uptime (§6).
    next_session: AtomicU64,
    /// Hint: best-effort committed-write retry memo, keyed per-session
    /// (§7/item-4); purged on `close_session` (§6); lost on restart — a
    /// post-restart retry re-executes (duplicate, by design — ASN-0134 §A7).
    idem: Mutex<LruCache<(SessionId, ReqId), Cached>>,
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

/// The committed-write essence + the op-kind that produced it; trivially
/// `Clone` (`OpKind`/`Seq`: `Copy`, `Address`: `Clone`). The op-kind tag lets
/// `idem_get` reject a `ReqId` reused across op-kinds (miss → re-execute), so
/// a wrong-shaped ack is never served. The cache's value type — NOT a whole
/// [`Response`] (§7).
#[derive(Clone)]
struct Cached {
    op: OpKind,
    essence: AckEssence,
}

#[derive(Clone)]
enum AckEssence {
    Ack { at: Seq },
    AckAddr { addr: Address, at: Seq },
    AckEdit { successor: Address, claim: Address, at: Seq },
}

impl<W> Operation<W>
where
    W: WorldState + HasM3 + HasM5 + HasLinks + HasContent,
    W::Record: From<M3Rec> + From<M5Rec> + From<LinkRec> + From<ContentWrite>,
{
    /// Receive a [`Stores`] factory (built by the binary/engine, wrapping the
    /// recovered kernel via the store-driver constructors). The binary calls
    /// `Kernel::open` (M2 recovery), handles `OpenError::{Corruption,
    /// BadCheckpoint}`, and builds the factory BEFORE constructing us — M10
    /// holds neither the kernel nor the registry directly (§9). We reach the
    /// kernel via `stores.kernel()` and acquire each store driver per-op.
    ///
    /// The idempotency LRU is bounded at a crate-fixed default capacity: the
    /// design's explicit `idem_capacity` construction knob conflicts with the
    /// interface's one-argument `new`, and the interface wins (see
    /// `DEFAULT_IDEM_CAPACITY`).
    pub fn new(stores: Box<dyn Stores<W>>) -> Self {
        let cap = NonZeroUsize::new(DEFAULT_IDEM_CAPACITY).expect("capacity is a nonzero constant");
        Operation {
            stores,
            sessions: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(1),
            idem: Mutex::new(LruCache::new(cap)),
            poisoned: AtomicBool::new(false),
        }
    }

    // ── session binding (M10-owned, ephemeral — §6) ──

    /// Record the binding and return a fresh `SessionId` minted from an
    /// atomic counter — unique within one M10 uptime (reset on restart;
    /// clients re-authenticate). The caller (transport) supplies the
    /// authenticated `PrincipalId`; unforgeability of the id is the
    /// transport's precondition (§6): it must inject `s` from the
    /// connection's authenticated binding, never read it off the wire.
    pub fn open_session(&self, principal: PrincipalId) -> SessionId {
        let s = SessionId(self.next_session.fetch_add(1, Ordering::Relaxed));
        self.sessions.lock().insert(s, principal);
        s
    }

    /// Drop the binding AND purge the session's idem entries (§6/§7) — the
    /// two locks taken sequentially, never nested; a linear sweep of the
    /// bounded LRU. The id is retired permanently (never reissued within the
    /// uptime). Calling this on connection drop is a transport obligation:
    /// nothing else retires a binding.
    pub fn close_session(&self, s: SessionId) {
        self.sessions.lock().remove(&s);
        let mut g = self.idem.lock();
        let dead: Vec<(SessionId, ReqId)> =
            g.iter().filter(|(k, _)| k.0 == s).map(|(k, _)| k.clone()).collect();
        for k in dead {
            g.pop(&k);
        }
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
    /// non-poisoning `parking_lot::Mutex` locks (§7) and the step-(b)
    /// read/write split, which hands each write arm a PROVEN-bound principal
    /// so no dispatch arm unwraps an `Option`. Reentrant & `Sync` — the
    /// transport may call it concurrently for pipelined requests (§8).
    ///
    /// Caller precondition (§6, non-forgeability): `s` MUST originate in the
    /// transport's connection state, never a wire-supplied value.
    pub fn execute(&self, s: SessionId, req: Request) -> Response {
        let Request { id, op } = req;
        let kind = op.kind(); // Copy; captured before dispatch moves the op
        // (a) idempotency: a repeated (s, id) whose op-kind matches returns
        //     the rebuilt committed-write ack, never re-executing. Keyed
        //     (s, id) — a replay under a DIFFERENT session misses (§7).
        if let Some(id) = &id {
            if let Some(r) = self.idem_get(s, id, kind) {
                return r;
            }
        }
        // (b)+(c) gate, SPLIT on the is_write/is_read partition so each
        //     dispatch path carries exactly the authority it needs (§1). The
        //     write path resolves a PROVEN-bound principal HERE (the one
        //     place it can fail); the read path takes none.
        let resp = if op.is_write() {
            // (c) refuse writes on a poisoned kernel; reads are still served
            //     through the else-branch (§9).
            if self.poisoned.load(Ordering::Relaxed) {
                return reject(kind, RejectCode::Poisoned); // disposition_of ⇒ Halt
            }
            let bound = self.sessions.lock().get(&s).copied(); // (b) lock drops at this `;`
            match bound {
                Some(principal) => self.dispatch_write(WriteCtx { principal }, op),
                None => return reject(kind, RejectCode::Unauthenticated), // ⇒ Permanent
            }
        } else {
            self.dispatch_read(op) // reads tolerate an unbound session
        }
        .unwrap_or_else(Response::Rejected);
        // (d) cache ONLY a committed-write ack — never a Rejected (a
        //     Reorder/Retry reissue MUST re-execute) nor a read (a cached
        //     read replays a stale snapshot). idem_put stores a small Cached
        //     essence (§7), not the Response.
        if let Some(id) = id {
            if resp.is_committed_write() {
                self.idem_put(s, &id, kind, &resp);
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
    /// driver returns at/after `lin(op)`), maps `TxnError<E>` via `map_txn`,
    /// and stamps the committed `Seq`. Exhaustive over `Op` with NO `_`
    /// wildcard: the complementary (read) half is one explicit `|`-list arm
    /// rejecting `Malformed` — never a panic — so a newly added `Op` variant
    /// is a compile-time non-exhaustiveness error here, at `is_read`, and at
    /// `dispatch_read`.
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
            // No principal: the node addr is supplied by provisioning; the
            // step-(b) bound-session gate still applied, uniformly (§6).
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
                let (start, at_seq) = self
                    .stores
                    .vstream()
                    .insert(wc.caller(), &doc, at, values)
                    .map_err(|e| self.map_txn(kind, e))?; // returns post-commit
                Ok(Response::AckAddr { addr: start, at: at_seq }) // the exact V1 coordinate
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
                let seq = self
                    .stores
                    .vstream()
                    .copy(wc.caller(), &doc, at, specs)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::Ack { at: seq })
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
                let m5 = snap.world().m5();
                let from = endset_from_vspecs(m5, &successor.from)?;
                let to = endset_from_vspecs(m5, &successor.to)?;
                let ty = match &successor.ty {
                    // TYPE is the successor's one two-form slot (§4):
                    // address-denoting or content-resolved; M7 owns the
                    // slot-shape/schema verdict inside editlink.
                    SlotArg::Addrs(a) => enc(a),
                    SlotArg::Resolve(v) => endset_from_vspecs(m5, v)?,
                };
                let link = Link::new([from, to, ty])
                    .ok_or_else(|| reject1(kind, RejectCode::IllFormedSpec))?;
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
            | Op::OutClaims { .. } => Err(reject1(kind, RejectCode::Malformed)),
        }
    }

    // ── read dispatch (§1/§2) ──

    /// The static table for the read half: every arm takes ONE snapshot
    /// in-arm and reads through the snapshot-based surfaces (`Query::new`
    /// for M6; M8's pure `*_on` twins, never the self-snapshotting handles —
    /// Conflicts resolved #5), so M10 reports the exact `as_of = snap.seq()`
    /// (V1) and any multi-constituent verdict discharges MIC clause 6 by
    /// construction (A3/V2). Reads hold no lock against writers, are
    /// zero-step (A1), and have no commit-before-ack obligation. No
    /// principal, no session. Exhaustive over `Op` with the complementary
    /// (write) half as one explicit rejecting |-list — see `dispatch_write`.
    fn dispatch_read(&self, op: Op) -> Result<Response, Rejection> {
        let kind = op.kind();
        match op {
            // ── namespace reads (→ M3, §2): the M3-internal frontier/
            //    registry values Delegate/CreateNewDocument demand. Total —
            //    Option<Address>, no fault path.
            Op::NextAccountPrefix { parent } => {
                let snap = self.stores.kernel().snapshot();
                let addr = snap.world().m3().next_account_prefix(&parent);
                Ok(Response::MaybeAddr { addr, as_of: snap.seq() })
            }
            // Takes an explicit wire id, not the session's bound principal —
            // deliberate (§2): a prefix is public, immutable registry data,
            // and the read path is principal-free by construction.
            Op::PrincipalPrefix { id } => {
                let snap = self.stores.kernel().snapshot();
                let addr = snap.world().m3().principal_prefix(id);
                Ok(Response::MaybeAddr { addr, as_of: snap.seq() })
            }
            // ── raw link reads (→ M7, §2): no driver handle — straight off
            //    the one snapshot.
            Op::ReadLink { a } => {
                let snap = self.stores.kernel().snapshot();
                let link = snap.world().links().readlink(&a);
                Ok(Response::LinkValue { link, as_of: snap.seq() })
            }
            // Carries its own Result in-band, deliberately (§2): M7 defines
            // ⟨⟩ ≠ ⊥ as two ANSWERS of FOLLOWLINK; lowering Invalid to a
            // Rejection would erase an unforgeable distinction. Contrast
            // Project, where M8's NotALink IS a precondition failure.
            Op::FollowLink { a, slot } => {
                let snap = self.stores.kernel().snapshot();
                let result = snap.world().links().followlink(&a, slot);
                Ok(Response::Follow { result, as_of: snap.seq() })
            }
            // ── content/provenance reads (→ M6, §2) ──
            Op::RetrieveV { specs } => {
                let snap = self.stores.kernel().snapshot();
                let items =
                    Query::new(&snap).retrieve_v(&specs).map_err(|e| map_read(kind, e))?;
                Ok(Response::Delivery { items, as_of: snap.seq() })
            }
            Op::RetrieveDocVSpan { doc } => {
                let snap = self.stores.kernel().snapshot();
                let set = Query::new(&snap).doc_vspan(&doc).map_err(|e| map_read(kind, e))?;
                Ok(Response::SpanSet { set, as_of: snap.seq() })
            }
            Op::RetrieveDocVSpanSet { doc } => {
                let snap = self.stores.kernel().snapshot();
                let set = Query::new(&snap).doc_vspanset(&doc).map_err(|e| map_read(kind, e))?;
                Ok(Response::SpanSet { set, as_of: snap.seq() })
            }
            Op::ShowOrigin { doc, span } => {
                let snap = self.stores.kernel().snapshot();
                let addrs =
                    Query::new(&snap).show_origin_v(&doc, &span).map_err(|e| map_read(kind, e))?;
                Ok(Response::Addrs { addrs, as_of: snap.seq() })
            }
            Op::ShowDeletions { d_a, d_b } => {
                let snap = self.stores.kernel().snapshot();
                let rep =
                    Query::new(&snap).show_deletions(&d_a, &d_b).map_err(|e| map_read(kind, e))?;
                Ok(Response::Deletions { rep, as_of: snap.seq() })
            }
            Op::Compare { rho1, rho2 } => {
                let snap = self.stores.kernel().snapshot();
                let rep =
                    Query::new(&snap).compare(&rho1, &rho2).map_err(|e| map_read(kind, e))?;
                Ok(Response::Compare { rep, as_of: snap.seq() })
            }
            Op::FindDocsContaining { regions } => {
                let snap = self.stores.kernel().snapshot();
                let addrs = Query::new(&snap)
                    .find_docs_containing(&regions)
                    .map_err(|e| map_read(kind, e))?;
                Ok(Response::Addrs { addrs, as_of: snap.seq() })
            }
            // ── link discovery reads (→ M8, §2): always the pure *_on twins
            //    over M10's one snapshot, never the self-snapshotting handle.
            Op::Image { d, region } => {
                let snap = self.stores.kernel().snapshot();
                let runs = image_on(&snap, &d, &region).map_err(|e| map_read(kind, e))?;
                Ok(Response::Runs { runs, as_of: snap.seq() })
            }
            Op::FindLinksV { d, region } => {
                let snap = self.stores.kernel().snapshot();
                let addrs = findlinks_v_on(&snap, &d, &region).map_err(|e| map_read(kind, e))?;
                Ok(Response::Addrs { addrs, as_of: snap.seq() })
            }
            Op::FindLinksFtt { q } => {
                let snap = self.stores.kernel().snapshot();
                let addrs = findlinks_ftt_on(&snap, &q); // total — no error map
                Ok(Response::Addrs { addrs, as_of: snap.seq() })
            }
            Op::CountV { d, region } => {
                let snap = self.stores.kernel().snapshot();
                let n = count_v_on(&snap, &d, &region).map_err(|e| map_read(kind, e))?;
                Ok(Response::Count { n, as_of: snap.seq() })
            }
            Op::CountFtt { q } => {
                let snap = self.stores.kernel().snapshot();
                let n = count_ftt_on(&snap, &q); // total
                Ok(Response::Count { n, as_of: snap.seq() })
            }
            Op::WindowV { d, region, cur, n } => {
                let snap = self.stores.kernel().snapshot();
                let window =
                    window_v_on(&snap, &d, &region, cur, n).map_err(|e| map_read(kind, e))?;
                Ok(Response::Page { window, as_of: snap.seq() })
            }
            Op::WindowFtt { q, cur, n } => {
                let snap = self.stores.kernel().snapshot();
                let window = window_ftt_on(&snap, &q, cur, n); // total
                Ok(Response::Page { window, as_of: snap.seq() })
            }
            Op::RetrieveEndsets { d, region } => {
                let snap = self.stores.kernel().snapshot();
                let pairs = retrieve_endsets_on(&snap, &d, &region).map_err(|e| map_read(kind, e))?;
                Ok(Response::Endsets { pairs, as_of: snap.seq() })
            }
            Op::Project { a, slot, d } => {
                let snap = self.stores.kernel().snapshot();
                let set = project_on(&snap, &a, slot, &d).map_err(|e| map_read(kind, e))?;
                Ok(Response::SpanSet { set, as_of: snap.seq() })
            }
            Op::DiscoverableFrom { a, d } => {
                let snap = self.stores.kernel().snapshot();
                let val = discoverable_from_on(&snap, &a, &d).map_err(|e| map_read(kind, e))?;
                Ok(Response::Bool { val, as_of: snap.seq() })
            }
            Op::DeleteOrphans { d, p, width } => {
                let snap = self.stores.kernel().snapshot();
                let report =
                    delete_orphans_on(&snap, &d, &p, &width).map_err(|e| map_read(kind, e))?;
                Ok(Response::Orphans { report, as_of: snap.seq() })
            }
            Op::InClaims { y, view } => {
                let snap = self.stores.kernel().snapshot();
                let claims = in_claims_on(&snap, &y, view); // total
                Ok(Response::Claims { claims, as_of: snap.seq() })
            }
            Op::OutClaims { x, view } => {
                let snap = self.stores.kernel().snapshot();
                let claims = out_claims_on(&snap, &x, view); // total
                Ok(Response::Claims { claims, as_of: snap.seq() })
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
            | Op::EditLink { .. } => Err(reject1(kind, RejectCode::Malformed)),
        }
    }

    // ── rejection surfacing (§5) ──

    /// Lower a write-path `TxnError` into a classified [`Rejection`]. A
    /// `&self` method so the `Poisoned` arm can latch the poison flag on the
    /// spot (read by `execute` step (c)); `Relaxed` suffices — the flag is a
    /// hint (M2 independently returns `Poisoned` to every later write), it
    /// only lets a write fail fast before opening a doomed transaction.
    fn map_txn<E: Lower>(&self, op: OpKind, e: TxnError<E>) -> Rejection {
        match e {
            TxnError::Rejected(inner) => {
                let (c, s) = inner.lower();
                Rejection::classified(op, c, s)
            }
            // Operators see the I/O cause behind the Retry hint.
            TxnError::Durability(io) => Rejection::classified(op, RejectCode::Durability, None)
                .with_detail(io.to_string()),
            // Nothing committed, and the request itself is what M2 could not
            // journal — so re-sending it is futile and the client is told so
            // (Malformed ⇒ Permanent, §5), with the encoder's own account.
            TxnError::Unencodable(io) => Rejection::classified(op, RejectCode::Malformed, None)
                .with_detail(io.to_string()),
            TxnError::Poisoned => {
                self.poisoned.store(true, Ordering::Relaxed); // LATCH (§1(c)/§9)
                Rejection::classified(op, RejectCode::Poisoned, None)
            }
        }
    }

    // ── idempotency cache (§7) ──

    /// Memoize a committed-write ack as its op-kind-tagged essence, keyed
    /// `(SessionId, ReqId)`. The call site guards `is_committed_write`; the
    /// `_` arm is a defensive return, never a panic.
    fn idem_put(&self, s: SessionId, id: &ReqId, op: OpKind, resp: &Response) {
        let essence = match resp {
            Response::Ack { at } => AckEssence::Ack { at: *at },
            Response::AckAddr { addr, at } => {
                AckEssence::AckAddr { addr: addr.clone(), at: *at }
            }
            Response::AckEdit { successor, claim, at } => AckEssence::AckEdit {
                successor: successor.clone(),
                claim: claim.clone(),
                at: *at,
            },
            _ => return, // unreachable under the is_committed_write guard
        };
        self.idem.lock().put((s, id.clone()), Cached { op, essence });
    }

    /// Rebuild the cached ack — a miss on session OR op-kind mismatch (a
    /// `ReqId` reused across op-kinds re-executes rather than serving a
    /// wrong-shaped ack; §7). The `(SessionId, ReqId)` key confines every hit
    /// to the session that committed the write (the pre-auth step-(a)
    /// ordering is therefore harmless — item-4).
    fn idem_get(&self, s: SessionId, id: &ReqId, op: OpKind) -> Option<Response> {
        let mut g = self.idem.lock();
        let c = g.get(&(s, id.clone()))?; // foreign session simply misses; bumps LRU recency
        if c.op != op {
            return None; // ReqId reused across op-kinds ⇒ miss, re-execute
        }
        Some(match &c.essence {
            AckEssence::Ack { at } => Response::Ack { at: *at },
            AckEssence::AckAddr { addr, at } => Response::AckAddr { addr: addr.clone(), at: *at },
            AckEssence::AckEdit { successor, claim, at } => Response::AckEdit {
                successor: successor.clone(),
                claim: claim.clone(),
                at: *at,
            },
        })
    }
}

// ── editlink's read-assembly helpers (§4) ──

/// The fallible successor-slot assembler: reject any ill-formed VSpec (M5's
/// `resolve` clips a malformed span to ⟨⟩ silently, which would breach the
/// never-silent contract), then the resolve→lift→assemble tail is infallible
/// (`Run::iextent` is total — every `Run` has `width ≥ 1` and an
/// element-level `i_start`). An empty from/to is structurally fine; M7 gates
/// the type slot.
fn endset_from_vspecs(m5: &M5State, specs: &[VSpec]) -> Result<Endset, Rejection> {
    let mut spans = Vec::new();
    for vs in specs {
        // M10-side well-formedness (the same content-V check makelink
        // applies): else a typed reject, not a silent ⟨⟩.
        if !is_content_vspan(&vs.span) {
            return Err(reject1(OpKind::EditLink, RejectCode::IllFormedSpec));
        }
        spans.extend(m5.resolve(&vs.source, &vs.span).iter().map(Run::iextent));
    }
    Ok(Endset::from_spans(spans))
}

/// The content-V well-formedness predicate makelink applies (M5/M7 reject ⟨⟩
/// otherwise): a depth-2, content-subspace, ordinal-level V-span. Every read
/// is fallible, so a span of any shape answers rather than faulting, which is
/// what `execute`'s Total contract needs.
fn is_content_vspan(span: &Span) -> bool {
    let start = span.start();
    let width = span.width();
    start.len() == 2 && width.len() == 2
        && start.get(1) == Some(&Nat::from(1u32)) // start's subspace component == s_C (= 1)
        && width.get(1) == Some(&Nat::from(0u32)) // ordinal-level: width's subspace component == 0
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde::{Deserialize, Serialize};
    use skep_address::{validate, Address, Nat, Span, Tumbler};
    use skep_arrangement::{HasM5, InsertError, M5Rec, M5State, VPos, Vstream};
    use skep_content::{ContentStore, ContentWrite, HasContent, Val};
    use skep_kernel::{
        CheckpointPolicy, Durability, Kernel, KernelConfig, Seq, TxnError, WorldState,
    };
    use skep_links::{HasLinks, LinkRec, LinkState, LinkStore, ReservedAddrs};
    use skep_namespace::{HasM3, M3Rec, M3State, Namespace, PrincipalId};

    use super::*;
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
        Ns(M3Rec),
        Content(ContentWrite),
        M5(M5Rec),
        Links(LinkRec),
    }

    impl WorldState for World {
        type Record = Record;
        fn apply(&self, r: &Record) -> World {
            match r {
                Record::Ns(x) => World { m3: self.m3.apply_ns(x), ..self.clone() },
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
            Record::Ns(r)
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

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }
    fn a(comps: &[u32]) -> Address {
        validate(t(comps)).unwrap_or_else(|_| panic!("T4-valid test address"))
    }
    fn ra(k: u32) -> Address {
        a(&[9, 0, 9, 0, 9, 0, 9, k]) // reserved-type fixtures: subspace 9 ∉ {s_C, s_L}
    }

    fn genesis_world() -> World {
        World {
            m3: M3State::genesis(),
            content: ContentStore::default(),
            m5: M5State::genesis(),
            links: LinkState::genesis(
                ReservedAddrs {
                    pred_def: ra(1),
                    pred_stable: ra(2),
                    retired: ra(3),
                    supersedes: ra(4),
                    retraction: ra(5),
                },
                vec![],
            )
            .expect("test genesis type config is valid"),
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
        fn namespace(&self) -> Namespace<World> {
            Namespace::new(Arc::clone(&self.kernel))
        }
        fn vstream(&self) -> Vstream<'_, World> {
            Vstream::new(&self.kernel)
        }
        fn linkstore(&self) -> LinkStore<'_, World> {
            LinkStore::new(&self.kernel)
        }
    }

    fn operation() -> Operation<World> {
        Operation::new(Box::new(KernelStores { kernel: kernel() }))
    }

    fn insert_op() -> Op {
        Op::Insert {
            doc: a(&[1, 0, 1, 0, 1]),
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
        let op = operation();
        let s1 = op.open_session(PrincipalId(1));
        let s2 = op.open_session(PrincipalId(2));
        assert_ne!(s1, s2);
        op.close_session(s1);
        let rej = rejected(op.execute(s1, Request { id: None, op: insert_op() }));
        assert_eq!(rej.op, OpKind::Insert);
        assert_eq!(rej.code, RejectCode::Unauthenticated);
        assert_eq!(rej.disposition, Disposition::Permanent);
    }

    /// §5/§9: the first `TxnError::Poisoned` latches the flag inside
    /// `map_txn`; thereafter writes fail fast with Halt at step (c) while
    /// reads keep being served off the last root.
    #[test]
    fn poison_latch_halts_writes_but_reads_continue() {
        let op = operation();
        let s = op.open_session(PrincipalId(1));
        let rej = op.map_txn(OpKind::Insert, TxnError::<InsertError>::Poisoned);
        assert_eq!(rej.code, RejectCode::Poisoned);
        assert_eq!(rej.disposition, Disposition::Halt);
        assert!(op.poisoned.load(Ordering::Relaxed));
        // Write: fails fast pre-dispatch.
        let rej = rejected(op.execute(s, Request { id: None, op: insert_op() }));
        assert_eq!(rej.code, RejectCode::Poisoned);
        assert_eq!(rej.disposition, Disposition::Halt);
        // Read: still served (M2 snapshots survive a poisoned kernel).
        let resp = op.execute(s, Request { id: None, op: Op::NextAccountPrefix { parent: a(&[1]) } });
        match resp {
            Response::MaybeAddr { addr, .. } => assert!(addr.is_some()),
            _ => panic!("read must still be served on a poisoned kernel"),
        }
    }

    /// §5: `Durability` threads the io::Error text (Retry hint with an
    /// operator-visible cause); `Unencodable` threads its cause too but
    /// disposes Permanent — the same no-op, and one no retry can fix; a typed
    /// `Rejected(E)` lowers verbatim.
    #[test]
    fn map_txn_lowers_durability_and_rejected() {
        let op = operation();
        let rej = op.map_txn::<InsertError>(
            OpKind::Insert,
            TxnError::Durability(std::io::Error::other("disk gone")),
        );
        assert_eq!(rej.code, RejectCode::Durability);
        assert_eq!(rej.disposition, Disposition::Retry);
        assert!(rej.detail.as_deref().is_some_and(|d| d.contains("disk gone")));
        let rej = op.map_txn::<InsertError>(
            OpKind::Insert,
            TxnError::Unencodable(std::io::Error::other("record too large")),
        );
        assert_eq!(rej.code, RejectCode::Malformed);
        assert_eq!(
            rej.disposition,
            Disposition::Permanent,
            "a record M2 cannot journal must never be advertised as retryable"
        );
        assert!(rej
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("record too large")));
        let rej = op.map_txn(OpKind::Insert, TxnError::Rejected(InsertError::EmptyContent));
        assert_eq!(rej.code, RejectCode::EmptyContent);
        assert_eq!(rej.disposition, Disposition::Permanent);
    }

    /// §7: the cache round-trips a committed-write essence keyed
    /// `(SessionId, ReqId)` and op-kind-matched — a foreign session or a
    /// reused-across-kinds `ReqId` misses; `close_session` purges (§6).
    #[test]
    fn idem_cache_confinement_and_purge() {
        let op = operation();
        let s1 = op.open_session(PrincipalId(1));
        let s2 = op.open_session(PrincipalId(2));
        let id = ReqId(b"req-1".to_vec());
        let ack = Response::AckAddr { addr: a(&[1, 0, 1]), at: Seq(9) };
        op.idem_put(s1, &id, OpKind::CreateNewDocument, &ack);
        // Same session + kind: hit, rebuilt equal.
        match op.idem_get(s1, &id, OpKind::CreateNewDocument) {
            Some(Response::AckAddr { addr, at }) => {
                assert_eq!(addr, a(&[1, 0, 1]));
                assert_eq!(at, Seq(9));
            }
            _ => panic!("expected a rebuilt AckAddr hit"),
        }
        // Foreign session: miss (cross-principal confinement, item-4).
        assert!(op.idem_get(s2, &id, OpKind::CreateNewDocument).is_none());
        // Op-kind mismatch: miss (wrong-shaped ack never served).
        assert!(op.idem_get(s1, &id, OpKind::Fork).is_none());
        // close_session purges the session's entries.
        op.close_session(s1);
        assert!(op.idem_get(s1, &id, OpKind::CreateNewDocument).is_none());
    }

    /// §7/§1(d): only committed-write acks are memoized — a non-ack put is a
    /// defensive no-op, and a rejection produced through `execute` is never
    /// cached (a Reorder/Retry reissue must re-execute).
    #[test]
    fn only_committed_writes_are_cached() {
        let op = operation();
        let s = op.open_session(PrincipalId(1));
        let id = ReqId(b"req-2".to_vec());
        op.idem_put(s, &id, OpKind::CountV, &Response::Count { n: 3, as_of: Seq(1) });
        assert!(op.idem_get(s, &id, OpKind::CountV).is_none());
        // A rejected write (unbound session) with an id is not cached.
        let stray = op.open_session(PrincipalId(3));
        op.close_session(stray);
        let r = op.execute(stray, Request { id: Some(id.clone()), op: insert_op() });
        assert!(matches!(r, Response::Rejected(_)));
        assert!(op.idem_get(stray, &id, OpKind::Insert).is_none());
        // A read with an id is not cached either (stale-snapshot hazard).
        let rid = ReqId(b"req-3".to_vec());
        let resp = op.execute(
            s,
            Request { id: Some(rid.clone()), op: Op::NextAccountPrefix { parent: a(&[1]) } },
        );
        assert!(matches!(resp, Response::MaybeAddr { .. }));
        assert!(op.idem_get(s, &rid, OpKind::NextAccountPrefix).is_none());
    }

    /// §4: the content-V guard — depth-2, content-subspace (s_C = 1),
    /// ordinal-level — answering for a span of any shape, deeper and
    /// shallower included.
    #[test]
    fn content_vspan_guard() {
        let ok = Span::new(t(&[1, 1]), t(&[0, 2])).unwrap_or_else(|_| panic!("well-formed"));
        assert!(is_content_vspan(&ok));
        let link_subspace = Span::new(t(&[2, 1]), t(&[0, 1])).unwrap_or_else(|_| panic!("wf"));
        assert!(!is_content_vspan(&link_subspace));
        let not_ordinal = Span::new(t(&[1, 1]), t(&[1, 0])).unwrap_or_else(|_| panic!("wf"));
        assert!(!is_content_vspan(&not_ordinal));
        let depth1 = Span::new(t(&[5]), t(&[1])).unwrap_or_else(|_| panic!("wf"));
        assert!(!is_content_vspan(&depth1)); // shallower than depth 2
        let depth3 = Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).unwrap_or_else(|_| panic!("wf"));
        assert!(!is_content_vspan(&depth3));
    }
}
