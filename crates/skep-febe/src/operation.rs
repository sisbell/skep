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
use skep_address::{checked_inc, document_of, Address};
use skep_arrangement::{trunk_of, Caller, M5Rec};
use skep_content::ContentWrite;
use skep_discovery::{
    addressably_discoverable_from_on, count_ftt_on, count_v_on, delete_orphans_on,
    findlinks_ftt_on, findlinks_v_on, image_on, in_claims_on, out_claims_on, project_on,
    retrieve_endsets_on, window_ftt_on, window_v_on,
};
use skep_kernel::{Seq, TxnError, WorldState};
use skep_links::{Invalid, LinkRec};
use skep_namespace::{M3Rec, PrincipalId, BOOTSTRAP_PRINCIPAL};
use skep_retrieval::Query;

use crate::idem::IdemCache;
use crate::lower::{lower_read, lower_txn, Lower};
use crate::op::{Op, OpKind, Request};
use crate::reject::{reject, rejection, FaultSite, RejectCode, Rejection};
use crate::response::Response;
use crate::session::{SessionId, Sessions};
use crate::successor::successor_link;
use crate::{FebeWorld, Stores};

/// THE read predicate, as the transport may SUPPLY it (PUB-1.31; PUB-6.39's
/// one-per-request shape; PUB round 2, lane 3.3 — the `Consult` widened from
/// the publish shot's source gate to the whole read surface): may `principal`
/// (`None` = the GUEST) read the document `doc`? Consulted by every read arm
/// — the doc-argument consult, the per-run withheld arm, the result-set
/// filter — and by the publish composite's source gate (PUB-6.23, PUB-8.1's
/// second constraint), always on a DOCUMENT known registered (PUB-6.37).
///
/// Absent ([`Operation::new`] alone), M10 answers the world's own
/// [`ReadableWorld::readable`] off the ONE snapshot it pins per request, which
/// is the live daemon's case: the answer and the `as_of` it is stamped with
/// stand on one committed state. Supplied ([`Operation::with_consult`]), it
/// OVERRIDES the world the predicate is evaluated over — what a HISTORICAL
/// read needs: `/op-at N` answers the N-world's content through the HEAD's
/// exception set and grant set (PUB-6.48), so the daemon's throwaway front
/// door over the reconstructed world consults a predicate closed over one
/// head snapshot. `Send + Sync + 'static`, since the front door is shared
/// across a transport's worker pool.
///
/// [`ReadableWorld::readable`]: crate::ReadableWorld::readable
pub type Consult = dyn Fn(Option<PrincipalId>, &Address) -> bool + Send + Sync;

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
    /// The supplied read predicate ([`Consult`]), or none — in which case
    /// every read arm and the publish arm answer the world's own predicate
    /// off the one snapshot the request pins.
    consult: Option<Box<Consult>>,
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

/// The WRITE DESTINATIONS whose ownership stands AHEAD of the door's consult
/// (PUB-6.36 slot 1, PUB-6.38 — see [`Operation::consult_write`]): `Some` for
/// exactly the writes the consult reaches — a source-reading write or one
/// validating a link by address — listing the documents the store's own
/// `not_owner` is judged on; `Some(empty)` for `version`, whose mint lands in
/// the caller's own account and which no destination gate precedes (MINT-FIRST
/// is the daemon's, slot 2); `None` for a write with nothing to consult and
/// for every read. `nullify` is `None` on purpose: its target takes PUB-6.9's
/// ω-first order and the slot-5 nullify-class refusals (lane 3.5), not this
/// consult. `emit`'s endpoints are address-form (PUB-6.11) and `publish`'s
/// source gate is the composite's own, threaded per origin (PUB-8.1).
/// EXHAUSTIVE with no `_` arm: a new `Op` decides its row here.
fn consulted_destinations(op: &Op) -> Option<Vec<&Address>> {
    match op {
        Op::Copy { doc, .. } => Some(vec![doc]),
        Op::Version { .. } => Some(Vec::new()),
        Op::MakeLink { home, .. } => Some(vec![home]),
        Op::AssertSup { home, .. } => Some(vec![home]),
        Op::EditLink { d_s, d_a, .. } => Some(vec![d_s, d_a]),
        Op::CreateNewDocument { .. }
        | Op::Delegate { .. }
        | Op::RegisterNode { .. }
        | Op::Fork { .. }
        | Op::Insert { .. }
        | Op::Delete { .. }
        | Op::Rearrange { .. }
        | Op::Publish { .. }
        | Op::Emit { .. }
        | Op::Nullify { .. }
        | Op::NextAccountPrefix { .. }
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
        | Op::OutClaims { .. }
        | Op::DocMetadata { .. }
        | Op::EditionClaims { .. } => None,
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
            consult: None,
        }
    }

    /// Supply the read predicate ([`Consult`]) this front door answers
    /// through instead of its own world's — the transport's HEAD predicate
    /// for a historical read (PUB-6.48), closed over one head snapshot per
    /// request (PUB-6.39). Without it every read arm and the publish shot's
    /// source gate answer [`ReadableWorld::readable`] off the one snapshot
    /// the request pins, which is what a live front door wants.
    ///
    /// [`ReadableWorld::readable`]: crate::ReadableWorld::readable
    pub fn with_consult(mut self, consult: Box<Consult>) -> Self {
        self.consult = Some(consult);
        self
    }

    /// `readable(doc, principal)` for this front door: the supplied
    /// [`Consult`] where one was given, else the world's own
    /// [`ReadableWorld::readable`] off `world` — the snapshot the calling arm
    /// pinned. `None` is the guest. Every consult of the predicate, read
    /// path and publish shot alike, goes through here, so a front door
    /// answers ONE predicate.
    ///
    /// [`ReadableWorld::readable`]: crate::ReadableWorld::readable
    fn readable(&self, world: &W, principal: Option<PrincipalId>, doc: &Address) -> bool {
        match &self.consult {
            Some(consult) => consult(principal, doc),
            None => world.readable(principal, doc),
        }
    }

    /// THE VISIBILITY CLASS OF A WRITE (PUB round 2, lane 3.3b; PUB-6.25,
    /// PUB-6.28): the predicate M7's value-keyed gates run under for a link
    /// write of this session — `readable(doc, principal)` for the session's
    /// PRINCIPAL, closed here and lent to the store driver for the one write.
    /// M7 evaluates it INSIDE the write transaction, over the WORKING world
    /// it hands the closure, at each candidate incumbent's home — never over
    /// the snapshot a read pins. Where this front door carries a supplied
    /// [`Consult`] (the historical door), that is what answers here too — one
    /// front door, one predicate — and the world M7 hands in is then not
    /// consulted, the head snapshot the `Consult` closed over being the world
    /// it reads; such a door dispatches no write today, and the case is the
    /// round's escalated one.
    fn visible_to(
        &self,
        principal: PrincipalId,
    ) -> impl Fn(&W, &Address) -> bool + Send + Sync + '_ {
        move |world: &W, doc: &Address| self.readable(world, Some(principal), doc)
    }

    /// THE WRITE SIDE'S CONSULT (PUB round 2, lane 3.3c; PUB-6.23, PUB-6.24,
    /// PUB-6.36 slot 6, PUB-6.38): the door's pre-dispatch check on a write
    /// that READS a document before it writes — `copy`'s sources, `version`'s
    /// `d_src`, the RESOLVE-form slots of `make_link` and `edit_link` — and
    /// the LINK-ADDRESS rule on the links a write validates by address
    /// (PUB-6.6: `edit_link.original`, `assert_sup.old`/`new`). Consulted off
    /// `world`, the one snapshot the door pinned for this write, through the
    /// same [`Operation::readable`] every read arm answers — one front door,
    /// one predicate — and BEFORE the store call (or the EDITLINK successor
    /// build) that would read the source's arrangement.
    ///
    /// ORDER, as PUB-6.36 pins it and PUB-6.38 places it: slot 1, the
    /// DESTINATION's `not_owner`, stands AHEAD of this consult. The store
    /// words that verdict inside its own transaction, so the door realizes
    /// the order by DEFERRING: the consult runs only where the destination's
    /// own gate would pass — registered, and ω-owned by the caller, asked
    /// through the store's one spelling of ω (`Caller::is_owner`, M5's, which
    /// is M3's `is_effective_owner`) — and where it would not, nothing here
    /// speaks and the store answers its own `doc_not_registered` /
    /// `home_not_registered` / `not_owner`. A session that may not write here
    /// is never told whether it may read there (PUB-6.43's ground). M10 words
    /// no ownership verdict of its own; it only declines to judge a source
    /// ahead of one. Registration of the SOURCE stands ahead too (PUB-6.37),
    /// by the predicate's own construction: an unregistered address is
    /// fail-open readable (PUB-7.5), so it passes here and takes the store's
    /// `source_not_registered` — a withheld answer is only ever a REGISTERED
    /// private document.
    ///
    /// SLOT 5 AHEAD OF SLOT 6, and how this door reaches it (PUB round 2,
    /// lane 4.2, F3; PUB-6.36, PUB-2.11, PUB-6.38): the model's refusals are
    /// evaluated INSIDE the store transaction (owner ruling D2b), which once
    /// left one cell the door could not order — a source the caller may not
    /// read, copied into a PUBLISHED destination the caller owns — answered
    /// `withheld` where PUB-6.36 has slot 5 speak first. The door now
    /// PRE-EVALUATES the in-place advance refusal itself, between the
    /// deferral and the consult, for the in-place ARRANGEMENT-edit class
    /// PUB-2.11 governs among the consulted ops — `copy`, the one write here
    /// whose destination is an existing document's arrangement (the link
    /// writes are outside the rule, PUB-2.12; `version` is a mint, and
    /// `insert`/`delete`/`rearrange` read no source and take no consult) —
    /// through the same projection the store's own check reads (M3's bit on
    /// `trunk_of(doc)`, PUB-2.15, on a destination the deferral has just
    /// found registered, PUB-6.37), and answers `published_target`
    /// byte-identically to the store's (same code, disposition, no site, no
    /// detail). So a session refused the write is never told whether it may
    /// read the source (PUB-6.43's ground), the store's own refusal is
    /// simply unreached on that cell, and every other cell answers as before:
    /// where the destination is a draft the check is silent, and where the
    /// store would have refused `published_target` it still does, one layer
    /// earlier and in the same bytes. The versionless sibling never meets the
    /// consult: `private_source_versionless` fires only on a source the
    /// caller OWNS, which the subtree clause makes readable, so no source is
    /// both unreadable and versionless. M5's own refusal stands untouched.
    ///
    /// The two verdicts this consult can speak are the read side's own,
    /// wire-identical to what the store would say of the same address in a
    /// world without the draft: `withheld` — `reorder`, `site.addr` the
    /// FIRST unreadable source in declaration order (PUB-6.4,
    /// [`Op::source_arguments`]), no `detail` (PUB-8.5) — and, for a link
    /// homed in a document the caller may not read, the op's OWN
    /// never-deposited answer (`original_not_resident`,
    /// `endpoint_not_resident`), never a withheld that confirms a
    /// draft-homed link exists (PUB-6.6). `document_of(a)` is address
    /// arithmetic — no read (PUB-6.38). Within `edit_link` the link-address
    /// argument speaks first: `original` is declared ahead of `successor`,
    /// and the store's own residence check precedes its slot checks.
    /// `nullify.target` takes no rule here — PUB-6.9's ω-first order and the
    /// slot-5 nullify-class refusals govern it (lane 3.5).
    fn consult_write(&self, wc: &WriteCtx, op: &Op, world: &W) -> Result<(), Rejection> {
        let kind = op.kind();
        let Some(destinations) = consulted_destinations(op) else {
            return Ok(()); // no source and no link-address argument (see the table)
        };
        // Slot 1 ahead of slot 6: defer to the store wherever the
        // destination's own gate would refuse.
        let m3 = world.m3();
        let caller = wc.caller();
        if !destinations.iter().all(|d| m3.is_registered_document(d) && caller.is_owner(m3, d)) {
            return Ok(());
        }
        // Slot 5 ahead of slot 6 (lane 4.2, F3): the model's in-place advance
        // refusal on a `copy`'s destination — PUB-2.11, read as the store
        // reads it (M3's bit on the document `doc` projects to, PUB-2.15;
        // registered, by the deferral above) and answered in the store's own
        // bytes — BEFORE any source is consulted, so the one cell where both
        // apply answers `published_target`, never `withheld`.
        if let Op::Copy { doc, .. } = op {
            if m3.published(&trunk_of(doc)) {
                return Err(rejection(kind, RejectCode::PublishedTarget));
            }
        }
        let principal = Some(wc.principal);
        let readable = |a: &Address| self.readable(world, principal, a);
        let home_readable = |a: &Address| document_of(a).is_none_or(|h| readable(&h));
        // §2 — the link-address rule on writes (PUB-6.6): the op's own absence
        // answer, exactly as for an address no link occupies.
        match op {
            Op::EditLink { original, .. } if !home_readable(original) => {
                return Err(rejection(kind, RejectCode::OriginalNotResident));
            }
            Op::AssertSup { old, new, .. } if !home_readable(old) || !home_readable(new) => {
                return Err(rejection(kind, RejectCode::EndpointNotResident));
            }
            _ => {}
        }
        // §1 — the source consult: the first unreadable source, in
        // declaration order, answers WITHHELD naming itself.
        for source in op.source_arguments() {
            if !readable(source) {
                return Err(Rejection::classified(
                    kind,
                    RejectCode::Withheld,
                    Some(FaultSite { addr: Some(source.clone()), ..FaultSite::default() }),
                ));
            }
        }
        Ok(())
    }

    // ── session binding (M10-owned, ephemeral — §6) ──

    /// Record the binding and return a fresh `SessionId`, unique within one
    /// M10 uptime (reset on restart; clients re-authenticate). The caller
    /// (transport) supplies the authenticated `PrincipalId`; unforgeability
    /// of the id is the transport's precondition (§6): it must hold the
    /// returned `SessionId` in the connection's authenticated state and inject
    /// it into [`Operation::execute`], never read one off the wire.
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
    /// WRITES are the whole of what this retires. Reads take no session gate
    /// ([`Operation::execute`]), so the retired id still reaches every read
    /// arm and is answered — a transport whose logout must stop reads holds
    /// that policy itself.
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
    pub fn close_session(&self, session: SessionId) {
        self.sessions.close(session);
        self.idem.purge_session(session);
    }

    /// A session bound to `BOOTSTRAP_PRINCIPAL`, so the first
    /// `delegate`/`create`/`register_node` can happen. Confinement is
    /// transport policy (§6): the transport must not expose this beyond
    /// provisioning — it mints bootstrap authority ungated.
    pub fn bootstrap_session(&self) -> SessionId {
        self.open_session(BOOTSTRAP_PRINCIPAL)
    }

    /// THE lifecycle entry (§1). Total: always yields a `Response` to send
    /// (rejections are a `Response` variant). Totality rests on three things,
    /// and only two of them are M10's — the non-poisoning locks its two state
    /// collaborators hold (§7), and the step-(b) read/write split, which hands
    /// each write arm a PROVEN-bound principal so no dispatch arm unwraps an
    /// `Option`. Between them M10's own code holds no panic path. The third is
    /// upstream: this call unwinds if a store panics beneath it, so totality
    /// rests equally on M5's, M6's, M7's and M8's read and write paths not
    /// panicking on honest input. What panic sites they hold guard their own
    /// internal invariants, so no honest request reaches one — and none of
    /// their contracts states the obligation, which is why it is written here.
    ///
    /// Reentrant & `Sync` — the transport may call it concurrently for
    /// pipelined requests (§8), and that concurrency is the caller's to use.
    /// Two requests in flight at once under one `ReqId` are two operations:
    /// the retry memo is read at step (a) and written at step (d), with the
    /// whole dispatch in between, so both miss and both execute (§7).
    ///
    /// AUTHORIZATION is the write path's. `session` is consulted at step (b)
    /// and nowhere else: every read is dispatched against any `SessionId` —
    /// bound, retired by [`Operation::close_session`], or never opened — and
    /// reaches its store carrying no principal, since no read arm passes one.
    /// A transport that requires read authorization owns the whole of it, no
    /// module below this one performing any.
    ///
    /// Two caller preconditions, neither of which this module can check for
    /// itself:
    ///
    /// * NON-FORGEABILITY (§6): `session` MUST originate in the transport's
    ///   connection state, never a wire-supplied value.
    /// * SIZE: M10 measures no field of the [`Op`] it is handed, so every
    ///   list, tumbler and magnitude in `req` reaches the owning store as
    ///   presented. A transport discharges this in [`Codec::parse`], where
    ///   the obligation is stated in full; a caller that assembles an [`Op`]
    ///   and calls HERE has no parser in between and owns the whole of it.
    ///   Two reads are why it is worth owning: [`Op::Compare`] joins its two
    ///   operand sets pairwise, and [`Op::RetrieveV`] concatenates per spec
    ///   without dedup, so one whole-document spec repeated n times delivers
    ///   n copies of the document. Nothing on this path enforces either — the
    ///   one list M10 measures is the EDITLINK successor slot it builds for
    ///   itself, against M7's per-slot budget.
    ///
    /// [`Codec::parse`]: crate::Codec::parse
    ///
    /// Two refusals can hold at once on a write, and the contract names which
    /// speaks: the poison gate (c) is consulted BEFORE the session gate (b),
    /// so a write from an unbound session against a halted kernel answers
    /// `Poisoned`/`Halt` and never `Unauthenticated`. A client is told the
    /// engine has stopped even where its own defect is that it must
    /// re-authenticate. Step (a) precedes both, so a retry of a write that
    /// already committed is answered from the memo whatever either gate would
    /// have said.
    pub fn execute(&self, session: SessionId, req: Request) -> Response {
        let Request { id, op } = req;
        let kind = op.kind(); // Copy; captured before dispatch moves the op
        // (a) idempotency: a repeated (session, id) whose op-kind matches
        //     returns the memoized committed-write ack, never re-executing.
        //     Keyed on both — a replay under a DIFFERENT session misses (§7).
        if let Some(id) = &id {
            if let Some(ack) = self.idem.get(session, id, kind) {
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
            match self.sessions.principal_of(session) {
                // (b) the one place authority can fail
                Some(principal) => self.dispatch_write(WriteCtx { principal }, op),
                None => return reject(kind, RejectCode::Unauthenticated), // ⇒ Permanent
            }
        } else {
            // Reads tolerate an unbound session (§2): the principal is
            // resolved for the READ PREDICATE — the doc-argument consult, the
            // per-run withheld arm, the result-set filter — never to GATE the
            // read. `None` (unbound/guest) builds the guest predicate.
            self.dispatch_read(op, self.sessions.principal_of(session))
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
                self.idem.put(session, id, kind, ack);
            }
        }
        resp
    }

    /// The engine's current linearization frontier: the coordinate of the last
    /// committed write, on the same log every `at` and `as_of` names, and
    /// directly comparable with either. It never regresses (G0), and asking
    /// costs no operation — nothing is dispatched, committed or snapshotted.
    ///
    /// What a client compares it against is [the two
    /// coordinates](crate#the-two-coordinates).
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
        // ONE snapshot for the door's own pre-dispatch reads (the write side's
        // consult below, and the EDITLINK successor build) — a PRIOR
        // snapshot, deliberately not the write transaction's base (§4); the
        // store's own gates re-run against the base they commit on.
        let snap = self.stores.kernel().snapshot();
        self.consult_write(&wc, &op, snap.world())?;
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
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // ── arrangement writes (→ M5; ω-gated in-store under the
            //    session caller — the ownership ruling, 2026-08-16; the
            //    version-chain refusals in-store too, D2b) ──
            Op::Insert { doc, at, values, deposit } => {
                let (start, committed_at) = self
                    .stores
                    .vstream()
                    .insert(wc.caller(), &doc, at, values, deposit)
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
                    .copy(wc.caller(), &doc, at, &specs)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::Ack { at: committed_at })
            }
            Op::Rearrange { doc, cuts } => {
                let at = self
                    .stores
                    .vstream()
                    .rearrange(wc.caller(), &doc, &cuts)
                    .map_err(|e| self.map_txn(kind, e))?;
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
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // The SHOT (PUB-2.33, PUB-8.1): M5's composite decides the
            // destination, places the runs by origin and runs the source
            // gate; what M10 adds is the consult it hands down — the
            // daemon's, or today's publication read off ONE snapshot pinned
            // here for the whole shot, so every origin is judged against one
            // committed state. The ack is the member's address (PUB-2.37).
            Op::Publish { doc, shot } => {
                let principal = Some(wc.principal);
                let readable = |origin: &Address| self.readable(snap.world(), principal, origin);
                let (addr, at) = self
                    .stores
                    .vstream()
                    .publish(wc.caller(), &doc, &shot, &readable)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // ── link writes (→ M7; ω-gated in-store on each written home —
            //    the ownership ruling, 2026-08-16; the value-keyed gates at
            //    the session principal's VISIBILITY class — lane 3.3b, the
            //    writer built per write over `visible_to`) ──
            Op::MakeLink { home, from, to, ty } => {
                // M7 handles both slot forms INSIDE its transact: Resolve
                // V-specs off the txn base, Addrs deposited verbatim.
                let visibility = self.visible_to(wc.principal);
                let (addr, at) = self
                    .stores
                    .linkstore(&visibility)
                    .makelink(wc.caller(), &home, from, to, ty)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // Idempotent zero-step ops need no special case (§3): a dedup hit
            // returns (incumbent, base_seq) with no commit; marshaled
            // identically to a miss (ASN-0134 §A1). The incumbent a hit names
            // is one this principal can read (PUB-6.25, PUB-6.26).
            Op::Emit { home, ty, from, to } => {
                let visibility = self.visible_to(wc.principal);
                let (addr, at) = self
                    .stores
                    .linkstore(&visibility)
                    .emit(wc.caller(), &home, &ty, &from, &to)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::Nullify { home, target } => {
                let visibility = self.visible_to(wc.principal);
                let (addr, at) = self
                    .stores
                    .linkstore(&visibility)
                    .nullify(wc.caller(), &home, &target)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            Op::AssertSup { home, old, new } => {
                let visibility = self.visible_to(wc.principal);
                let (addr, at) = self
                    .stores
                    .linkstore(&visibility)
                    .assert_sup(wc.caller(), &home, &old, &new)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckAddr { addr, at })
            }
            // The one read-assembled request (§4): the successor's content
            // V-specs resolve through M5 off a PRIOR snapshot — deliberately
            // not in editlink's write transaction (recorded I-addresses are
            // permanent, so d_s's arrangement may move underneath with no
            // hazard). One operation ⇒ still one M2 transaction. The
            // visibility class rides the writer as on every link write; the
            // claim's dedup is a guaranteed miss (PUB-6.27), so no ack here
            // can name an address this principal could not read. The
            // successor's sources were consulted at the door above, BEFORE
            // this build reads their arrangements (PUB-6.38).
            Op::EditLink { original, successor, d_s, d_a } => {
                let link = successor_link(snap.world().m3(), snap.world().m5(), &successor)?;
                let visibility = self.visible_to(wc.principal);
                let (edit, at) = self
                    .stores
                    .linkstore(&visibility)
                    .editlink(wc.caller(), &original, link, &d_s, &d_a)
                    .map_err(|e| self.map_txn(kind, e))?;
                Ok(Response::AckEdit { successor: edit.successor, claim: edit.claim, at })
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
            | Op::OutClaims { .. }
            | Op::DocMetadata { .. }
            | Op::EditionClaims { .. } => Err(rejection(kind, RejectCode::Malformed)),
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
    fn dispatch_read(&self, op: Op, principal: Option<PrincipalId>) -> Result<Response, Rejection> {
        let kind = op.kind();
        let snap = self.stores.kernel().snapshot();
        let as_of = snap.seq();
        let world = snap.world();
        // THE read predicate for this request (PUB-6.39), built ONCE off THIS
        // read snapshot — or off the supplied `Consult`, which a historical
        // front door closes over one HEAD snapshot (PUB-6.48) — so the answer
        // and the `as_of` it is stamped with stand on one committed state. An
        // opaque `Fn(&Address) -> bool` threaded down: M6/M8 filter and mask
        // through it and never see the principal (the STRUCK second form).
        // `None` principal is the guest predicate.
        let readable = |a: &Address| self.readable(world, principal, a);
        // The doc-argument consult (§2, PUB-6.12): the FIRST unreadable NAMED
        // document, in declaration order, answers WITHHELD (reorder, `site.addr`
        // the document, no detail — lane 3.2's shape). It runs after
        // registration — an unregistered document is fail-open readable here
        // (PUB-7.5) and defers to its store's own `*NotRegistered` — and before
        // any other validation. A published document never answers withheld.
        for arg in op.doc_arguments() {
            if !readable(arg) {
                return Err(Rejection::classified(
                    kind,
                    RejectCode::Withheld,
                    Some(FaultSite { addr: Some(arg.clone()), ..FaultSite::default() }),
                ));
            }
        }
        // A link-ADDRESS op answers ABSENCE for a link homed in an unreadable
        // document (§2, PUB-6.6): its home is unreadable ⟹ the read behaves as
        // if the link is not there. A non-element `a` has no home and is left
        // to the store.
        let home_readable = |a: &Address| document_of(a).is_none_or(|h| readable(&h));
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
                // A link homed in an unreadable document reads as ABSENT
                // (PUB-6.6): `⊥`, exactly as a never-deposited address.
                let link = if home_readable(&a) {
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
                let result = if home_readable(&a) {
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
            // ── link discovery reads (→ M8, §2): always the pure *_on twins
            //    over M10's one snapshot, never the self-snapshotting handle.
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
            // predicate — see `project_on` and
            // `addressably_discoverable_from_on` for the shape each gives
            // and where it falls among their refusals. An admitted `project` is
            // UNFILTERED at origin (PUB-6.15).
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
            // ── publication reads (lane 3.4) ──
            // The doc-metadata read (PUB-8.12): `doc` was consulted above,
            // so a withheld answer has already spoken for a private document
            // the caller cannot read; registration is the store's contract
            // (PUB-6.37) and an unregistered address answers its own code.
            // A version member projects to its DOCUMENT (PUB-2.15), whose
            // state is the one every gate keys on. The owner is M3's ω,
            // carried rather than recomputed by the client (`Some` on every
            // registered document — ω is total over the registered space —
            // the `Option` standing only so the shape never invents one).
            // The birth version is `D.1` while the chain has a member, and
            // its extent is that member's arranged content count, which a
            // version never changes (PUB-2.50) — the base extent PUB-3.19's
            // edition test images over. No arrangement is read for a
            // document with no member: the field is absent, not zero.
            Op::DocMetadata { doc } => {
                let m3 = world.m3();
                if !m3.is_registered_document(&doc) {
                    return Err(rejection(kind, RejectCode::DocNotRegistered));
                }
                let document = trunk_of(&doc);
                let published = m3.published(&document);
                let owner = m3.effective_owner_prefix(&document).cloned();
                let birth = m3.latest_version(&document).map(|_| {
                    checked_inc(&document, 1).expect("k = 1 passes the TA5a gate on every address")
                });
                let birth_extent = birth.as_ref().map(|b| world.m5().content_count(b));
                Ok(Response::DocMetadata { doc: document, published, owner, birth, birth_extent, as_of })
            }
            // The audit-view edition-claim lookup (PUB-8.46): the world
            // answers the CLASS over `target`'s subtree — admitted,
            // unsuperseded, retracted-or-not — and this door keeps each row
            // whose HOME the caller reads (PUB-6.13, the result-set rule),
            // off the one predicate above. A draft edition's claim is thereby
            // invisible to a stranger and listed for its owner; the client's
            // own PUB-3.19 admission test runs over the home this row names.
            Op::EditionClaims { target } => {
                if !world.m3().is_registered_document(&target) {
                    return Err(rejection(kind, RejectCode::DocNotRegistered));
                }
                let claims = world
                    .edition_claims(&target)
                    .into_iter()
                    .filter(|claim| readable(&claim.home))
                    .collect();
                Ok(Response::EditionClaims { claims, as_of })
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
    use skep_links::{HasLinks, LinkRec, LinkState, LinkWriter, Visibility};
    use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

    use super::*;
    use crate::op::ReqId;
    use crate::reject::Disposition;
    use crate::response::CommittedAck;

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
    impl crate::ReadableWorld for World {
        // The test world admits every read: masking (published ∨ subtree ∨
        // grant) is the engine's predicate, exercised by skepd's suite and the
        // engine's own; M10's lifecycle tests are principal-partition and
        // dispatch tests, orthogonal to it.
        fn readable(&self, _principal: Option<PrincipalId>, _doc: &Address) -> bool {
            true
        }
        // The edition-claim class is the engine's composition (the pinned
        // type address lives there); this world carries none, so the lookup
        // answers the empty class and the arm's shape is what is exercised.
        fn edition_claims(&self, _target: &Address) -> Vec<crate::EditionClaim> {
            Vec::new()
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
        fn linkstore<'a>(
            &'a self,
            visibility: &'a Visibility<'a, World>,
        ) -> LinkWriter<'a, World> {
            LinkWriter::new(&self.kernel, visibility)
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
            deposit: false,
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
    /// all 26 also exercises `execute`'s Total contract on the read half: an
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
        // Raised for the latch alone; the rejection itself answers no request.
        let _ = febe.map_txn(OpKind::Insert, TxnError::<InsertError>::Poisoned);
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

        // The kernel halts AFTER that write committed — the latch is what this
        // call is for, so the rejection it builds answers nothing.
        let _ = febe.map_txn(OpKind::Insert, TxnError::<InsertError>::Poisoned);
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

    /// §1/§6/§7: step (a) precedes the SESSION gate, and the documented
    /// outcome of the close/purge race. An `execute` already past its
    /// step-(a) lookup may deposit its ack after `close_session` has swept,
    /// and that entry then lives until eviction — so presenting the retired
    /// id replays one acknowledgment of a write that session itself
    /// committed, rather than answering `Unauthenticated`. It authorizes
    /// nothing and commits nothing.
    #[test]
    fn a_memoized_ack_outliving_its_binding_is_replayed_not_refused() {
        let febe = operation();
        let s = febe.open_session(PrincipalId(1));
        let id = ReqId(b"in-flight".to_vec());
        // The deposit a request already past step (a) makes after the sweep.
        febe.close_session(s);
        febe.idem.put(
            s,
            id.clone(),
            OpKind::Insert,
            CommittedAck::Addr { addr: addr(&[1, 0, 1, 0, 1]), at: Seq(3) },
        );
        let before = febe.log_position();

        match febe.execute(s, Request { id: Some(id), op: insert_op() }) {
            Response::AckAddr { addr: replayed, at } => {
                assert_eq!(replayed, addr(&[1, 0, 1, 0, 1]), "the memo answers ahead of the gate");
                assert_eq!(at, Seq(3), "…at the coordinate it committed");
            }
            _ => panic!("a memoized ack is served ahead of the session gate"),
        }
        assert_eq!(febe.log_position(), before, "a replayed ack commits nothing");

        // The binding really is gone: an unkeyed write on the same id is
        // refused, so the replay above says something about the ORDER of the
        // two steps and not about the session still being bound.
        let rej = rejected(febe.execute(s, Request { id: None, op: insert_op() }));
        assert_eq!(rej.code, RejectCode::Unauthenticated);
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
                febe.dispatch_read(op, Some(PrincipalId(1)))
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
