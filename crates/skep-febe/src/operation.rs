//! The LIFECYCLE: [`OperationSurface`], the state it holds for one uptime,
//! and its entry ([`OperationSurface::execute`]) — parse → authorize →
//! linearize → commit-gate → marshal → surface (§1–§4). The lifecycle's order
//! lives here, with what its gates read: the session table, the retry memo,
//! and the poison mirror beside the one method that latches it
//! ([`OperationSurface::lower_write`]). The pieces it consults belong to their
//! own cards — [`crate::session::Sessions`] for the ephemeral binding (§6),
//! [`crate::idem::IdemCache`] for the committed-write retry memo (§7), and
//! [`crate::publication`] for what the publication reads need that no store
//! computes.
//!
//! Beneath it, two children, each seeing this module's private items the way
//! a child does, so nothing here is widened for them:
//!
//! * [`door`] — the READABILITY DOOR: the one read predicate a request
//!   answers through, the two consults it drives, and the link-address
//!   absence rule. `OperationSurface::readable`, where a supplied predicate
//!   and the world's own meet, is private to it.
//! * [`dispatch`] — the two static tables that hand every `Op` to the store or
//!   query module that owns it: the write half under the proven-bound
//!   [`WriteCtx`], the read half over one pinned snapshot.

// The readability door: the one predicate of a request, the two consults
// it drives, and the link-address absence rule.
mod door;
// The two static tables: every `Op` to the store or query module that owns it.
mod dispatch;

pub use door::{consult_read, ReadPredicate};

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use skep_address::Address;
use skep_arrangement::{Caller, M5Rec};
use skep_content::ContentWrite;
use skep_kernel::{Seq, TxnError, WorldState};
use skep_links::LinkRec;
use skep_namespace::{M3Rec, PrincipalId, BOOTSTRAP_PRINCIPAL};

use crate::idem::IdemCache;
use crate::lower::{lower_txn, Lower};
use crate::op::{OpKind, Request};
use crate::reject::{rejection, RejectCode, Rejection};
use crate::response::Response;
use crate::session::{SessionId, Sessions};
use crate::world::{FebeWorld, Stores};

/// M10's front-door handle (§Public interface). Owns **no** authoritative
/// substrate state and **no** `im` structure — its fields are the ephemeral
/// connection state ([`Sessions`]), a best-effort committed-write retry memo
/// ([`IdemCache`]), and a mirror of M2's poison state; none is ever snapshotted
/// or replayed, which is why this is the one module that legitimately departs
/// from the `im`-everywhere convention (§Core data model).
pub struct OperationSurface<W: WorldState> {
    /// Borrowed authority: the binary's factory (M2/M3/M5/M7 own real state).
    stores: Box<dyn Stores<W>>,
    /// Which principal each open session speaks for — retired only by
    /// [`OperationSurface::close_session`] (§6).
    sessions: Sessions,
    /// Hint: the committed-write retry memo (§7). A session's entries are
    /// swept by [`OperationSurface::close_session`] — those present when the
    /// sweep runs (§6) — and the whole memo is lost on restart, so a
    /// post-restart retry re-executes (duplicate, by design — ASN-0134 §A7).
    idem: IdemCache,
    /// Hint: a MIRROR of M2's own poison state, which is the fact's owner and
    /// publishes it as `Kernel::is_poisoned` — lock-free, infallible, and
    /// terminal in the one direction that matters, so a `true` there is
    /// actionable without a race. This copy is kept only so `execute`'s step
    /// (c) can fail a write fast without opening a doomed transaction, and it
    /// is raised by the first `TxnError::Poisoned` M10 itself meets
    /// ([`OperationSurface::lower_write`], §5/§9).
    ///
    /// It therefore LAGS exactly the writes M10 did not issue — M9's rule
    /// fires reach M7's gated write path directly rather than through this
    /// surface — so a kernel poisoned by one of those is mirrored `false`
    /// until an M10 write fails. Nothing rests on the lag: poison is
    /// terminal, so the mirror is never falsely `true`, and M2's own refusal
    /// is the authoritative answer either way.
    poisoned: AtomicBool,
    /// The supplied [`ReadPredicate`], or none — in which case every read arm
    /// answers the world's own predicate off the one snapshot the request
    /// pins, and the publish arm over the working world M5 hands its source
    /// gate.
    read_predicate: Option<Box<ReadPredicate>>,
}

/// Lock-free, as the kernel's own `Debug` is: the kernel this surface answers
/// through — M2's rendering, which reads the installed head and the poison bit
/// without a lock, so `dbg!` is safe anywhere — and whether a supplied
/// [`ReadPredicate`] answers in place of the world's, the one fact about a
/// front door that decides every masked answer and that nothing else shows.
/// Nothing more: the session table and the retry memo sit behind locks, and
/// the poison MIRROR lags the bit the kernel field prints. Written out rather
/// than derived, as M5's `Vstream` and M7's `LinkWriter` are: a derive would
/// bound the impl on `W: Debug`, and the factory and the predicate are trait
/// objects that carry none.
impl<W: WorldState> fmt::Debug for OperationSurface<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationSurface")
            .field("kernel", self.stores.kernel())
            .field("read_predicate", &self.read_predicate.as_ref().map(|_| "supplied"))
            .finish_non_exhaustive()
    }
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

/// A bare `Response::Rejected` for `execute`'s steps (b)/(c) (§1/§5).
fn reject(kind: OpKind, code: RejectCode) -> Response {
    Response::Rejected(rejection(kind, code))
}

impl<W> OperationSurface<W>
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
        OperationSurface {
            stores,
            sessions: Sessions::new(),
            idem: IdemCache::new(),
            poisoned: AtomicBool::new(false),
            read_predicate: None,
        }
    }

    /// Supply the [`ReadPredicate`] this front door answers through instead of
    /// its own world's — the transport's HEAD predicate for a historical read
    /// (PUB-6.48), closed over one head snapshot per request (PUB-6.39).
    /// Without it every read arm answers [`ReadableWorld::readable`] off the
    /// one snapshot the request pins, and the publish shot's source gate over
    /// the working world of its own transaction, which is what a live front
    /// door wants.
    ///
    /// It is the WHOLE predicate that is supplied, not merely what the two
    /// consults ask: the same value answers every result-set filter, every
    /// per-run mask, the link-address absence rule, and the visibility class
    /// lent to M5 and M7 on a write.
    ///
    /// TWO OBLIGATIONS ride with it that M10 cannot check for the supplier,
    /// both stated in full on [`ReadPredicate`]. Lent as a visibility class,
    /// the predicate is evaluated inside the store's write transaction under
    /// M2's applier lock, so it must not call `transact` on that kernel, and
    /// its cost is paid by every waiting writer. And it is asked about
    /// addresses of any tier, registered or not, so it must be total and must
    /// answer READABLE for an address the store has not registered: refusing
    /// there turns each arm's own `*NotRegistered` into a `withheld` and
    /// tells a prober that a nonexistent address is merely hidden.
    ///
    /// Takes the closure and boxes it here, since the box is this door's
    /// storage rather than the caller's concern — [`ReadPredicate`] names the
    /// shape the bound spells out, and an already-boxed predicate satisfies
    /// that bound too.
    ///
    /// [`ReadableWorld::readable`]: crate::ReadableWorld::readable
    pub fn with_read_predicate<F>(mut self, predicate: F) -> Self
    where
        F: Fn(Option<PrincipalId>, &Address) -> bool + Send + Sync + 'static,
    {
        self.read_predicate = Some(Box::new(predicate));
        self
    }

    // ── session binding (M10-owned, ephemeral — §6) ──

    /// Record the binding and return a fresh `SessionId`, unique within one
    /// M10 uptime (reset on restart; clients re-authenticate). The caller
    /// (transport) supplies the authenticated `PrincipalId`; unforgeability
    /// of the id is the transport's precondition (§6): it must hold the
    /// returned `SessionId` in the connection's authenticated state and inject
    /// it into [`OperationSurface::execute`], never read one off the wire.
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
    /// WRITES are the whole of what this REFUSES. Reads take no session gate
    /// ([`OperationSurface::execute`]), so the retired id still reaches
    /// every read arm and is answered — as the GUEST, since it now resolves
    /// to no principal and `None` is the guest predicate. Logout therefore
    /// NARROWS the read surface to the published documents rather than
    /// closing it; a transport whose logout must REFUSE reads holds that
    /// policy itself. A transport that needs a guest names
    /// [`SessionId::GUEST`] rather than opening a session only to retire it
    /// here, which leaves a live binding wherever the retirement is missed.
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
    /// internal invariants, so no honest request reaches one. M5 states that
    /// obligation in its own contract (skep-arrangement, §Failure channels),
    /// and it is written here for the rest.
    ///
    /// Reentrant & `Sync` — the transport may call it concurrently for
    /// pipelined requests (§8), and that concurrency is the caller's to use.
    /// Two requests in flight at once under one `ReqId` are two operations:
    /// the retry memo is read at step (a) and written at step (d), with the
    /// whole dispatch in between, so both miss and both execute (§7).
    ///
    /// AUTHORIZATION: `session` is consulted on BOTH paths, for two different
    /// purposes, and the difference is the one a transport author needs.
    ///
    /// * On the WRITE path, at step (b), it resolves a PROVEN-bound principal,
    ///   and its absence REFUSES: an unbound session is answered
    ///   `Unauthenticated` and no store is reached. That is a gate.
    /// * On the READ path it resolves an `Option<PrincipalId>` for the read
    ///   predicate this surface answers, which SHAPES the answer rather than
    ///   gating the operation. Every read is therefore served against any
    ///   `SessionId` — bound, retired by
    ///   [`OperationSurface::close_session`], or never opened, among which
    ///   [`SessionId::GUEST`] is the one a caller can name and the handle for
    ///   a request that presents no session — and an id that resolves to no
    ///   principal is answered as the GUEST, whose predicate admits the
    ///   published documents alone. That is a mask. Where the predicate does
    ///   REFUSE (form (1) below), the refusal names a DOCUMENT and never the
    ///   caller's standing to read at all.
    ///
    /// So reads are masked, not gated, and the masking is M6's and M8's,
    /// driven by the one predicate this surface answers (PUB-6.39). A
    /// transport that adds its own read gate is adding a SECOND predicate to
    /// a surface that answers one, and two predicates that disagree about a
    /// private draft is the failure `OperationSurface::readable` is a
    /// chokepoint to prevent.
    ///
    /// WHAT A MASKED ANSWER LOOKS LIKE, since "masked" does not by itself
    /// tell a client what it will receive. Four forms, numbered below in the
    /// order they are given, and one read may carry more than one:
    ///
    /// * a `Withheld` REJECTION naming the first unreadable document the
    ///   request NAMES, in declaration order. Which documents an operation
    ///   names is [`Op::doc_arguments`], public for this reason.
    /// * a SILENTLY SMALLER answer, which PUB-6.13 splits in two. The
    ///   discovery, census, window, endset, orphan, lineage and
    ///   edition-claim readers drop every row whose HOME the caller may not
    ///   read; the container family drops every CONTAINER the caller cannot
    ///   read, at its own identity. Either way a count is a count of what
    ///   THIS caller may see, and no field reports that anything was dropped.
    ///   The any-principal read is smaller still for the GUEST: grants reach
    ///   principals alone (PUB-5.109), so the guest is answered no rows, and
    ///   an empty answer there says nothing about whether any grant stands.
    /// * ABSENCE. A link address whose home document the caller may not read
    ///   answers as an address no link occupies (PUB-6.6), so absence does
    ///   not distinguish "no link there" from "a link that is not yours to
    ///   see" — at [`Op::ReadLink`], [`Op::FollowLink`], [`Op::Project`] and
    ///   [`Op::DiscoverableFrom`], the four ops the rule covers.
    /// * a WITHHELD ITEM inside a payload, at its own position — RETRIEVEV's
    ///   delivery, whose runs are masked by origin ([`Op::RetrieveV`]).
    ///
    /// What a client may rely on, stated to the width it holds: no read is
    /// ever refused for want of a BOUND SESSION — that is the gate/mask
    /// distinction above, and it is why any `SessionId` is served. Forms (2),
    /// (3) and (4) disclose nothing further: no field reports a drop, and
    /// absence does not distinguish "no link" from "not yours to see". Form
    /// (1) is the informative one, BY DESIGN — PUB-6.12 makes a `Withheld`
    /// mean a REGISTERED PRIVATE document, which is exactly why the
    /// predicate must answer readable for an address the store has not
    /// registered ([`ReadableWorld::readable`]), so that no refusal can turn
    /// a nonexistent address into a hidden one.
    ///
    /// [`ReadableWorld::readable`]: crate::ReadableWorld::readable
    /// [`Op::doc_arguments`]: crate::Op::doc_arguments
    /// [`Op::ReadLink`]: crate::Op::ReadLink
    /// [`Op::FollowLink`]: crate::Op::FollowLink
    /// [`Op::Project`]: crate::Op::Project
    /// [`Op::DiscoverableFrom`]: crate::Op::DiscoverableFrom
    /// [`Op::RetrieveV`]: crate::Op::RetrieveV
    ///
    /// Two caller preconditions, neither of which this module can check for
    /// itself:
    ///
    /// * NON-FORGEABILITY (§6): `session` MUST originate in the transport's
    ///   connection state, never a wire-supplied value.
    /// * SIZE: M10 measures no field of the [`Op`] it is handed — the one list
    ///   it measures is the EDITLINK successor slot it builds for itself,
    ///   against M7's two per-slot budgets — so every list, tumbler and
    ///   magnitude in `req` reaches the owning store as presented. A transport
    ///   discharges this in [`Codec::parse`], which also names and prices the
    ///   operations whose work their size does not bound; a caller that
    ///   assembles an [`Op`] and calls HERE has no parser in between and owns
    ///   the same obligation.
    ///
    /// [`Op`]: crate::Op
    /// [`Codec::parse`]: crate::Codec::parse
    ///
    /// Two refusals can hold at once on a write, and the contract names which
    /// speaks: the poison gate (c) is consulted BEFORE the session gate (b),
    /// so a write from an unbound session against a halted kernel answers
    /// `Poisoned`/`Halt` and never `Unauthenticated`. A client is told the
    /// engine has stopped even where its own defect is that it must
    /// re-authenticate. The retry memo (a) precedes both, so a retry of a
    /// write that already committed is answered from the memo whatever either
    /// gate would have said. A READ takes none of the three: no gate, and no
    /// memo either, the memo holding committed-write acknowledgments alone.
    pub fn execute(&self, session: SessionId, req: Request) -> Response {
        let Request { id, op, attest } = req;
        let kind = op.kind(); // Copy; captured before dispatch moves the op
        // (a), then (c), then (b) — that order being the stated precedence
        //     when more than one applies — and all three on the write path
        //     only, since the is_write/is_read split gives each path exactly
        //     the authority it needs (§1). The write path resolves a
        //     PROVEN-bound principal HERE (the one place it can fail); the
        //     read path takes no gate and consults no memo.
        let resp = if op.is_write() {
            // (a) idempotency: a repeated (session, id) whose op-kind matches
            //     returns the memoized committed-write ack, never
            //     re-executing. Keyed on both — a replay under a DIFFERENT
            //     session misses (§7). Asked here rather than of every
            //     request because the memo holds committed-write acks alone,
            //     so a read's `kind` can never be a key and its lookup could
            //     only take the memo's lock to be told so.
            if let Some(id) = &id {
                if let Some(ack) = self.idem.get(session, id, kind) {
                    return ack.into();
                }
            }
            // (c) refuse writes on a poisoned kernel; reads are still served
            //     through the else-branch (§9).
            if self.poisoned.load(Ordering::Relaxed) {
                return reject(kind, RejectCode::Poisoned); // ⇒ Halt
            }
            match self.sessions.principal_of(session) {
                // (b) the one place authority can fail
                Some(principal) => {
                    self.dispatch_write(WriteCtx { principal }, op, attest.as_ref())
                }
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
        // (d) memoize ONLY a committed-write ack. `to_ack` is what decides —
        //     a Rejected and a read answer both yield None, so neither can
        //     be replayed (a Reorder/Retry reissue MUST re-execute; a cached
        //     read would replay a stale snapshot). The memo holds that small
        //     ack, not the Response (§7). Nested on the id, so a request that
        //     carried none never builds an ack it would then drop.
        if let Some(id) = id {
            if let Some(ack) = resp.to_ack() {
                self.idem.put(session, id, kind, ack);
            }
        }
        resp
    }

    /// The coordinate of the COMMITTED HEAD — the last committed write — on
    /// the same log every `at` and `as_of` names, and directly comparable with
    /// either. It never regresses (G0), and asking costs no operation —
    /// nothing is dispatched, committed or snapshotted.
    ///
    /// What a client compares it against is [the two
    /// coordinates](crate#the-two-coordinates).
    pub fn log_position(&self) -> Seq {
        self.stores.kernel().current_seq()
    }

    /// The COMMITTED HEAD's coordinate together with the commit chain's value
    /// AT it — [`log_position`]'s `Seq` beside the quantity
    /// `Kernel::chain_head` reads — off ONE kernel `Snapshot`, one root
    /// load: the root carries the two beside each other, so the pair names
    /// one committed state, and the chain value IS the chain of that
    /// position. `current_seq()` and `chain_head()` asked separately cannot
    /// promise that: a commit may land between the two loads. What
    /// `/health` serves as `log_position` and `chain_head` (QUEUE item 10,
    /// piece (c)). Like [`log_position`], asking costs no operation and
    /// takes no lock. The chain is the seed — thirty-two zero bytes — at
    /// `Seq(0)` and, under `Durability::InMemory`, at every coordinate.
    ///
    /// [`log_position`]: OperationSurface::log_position
    pub fn head_coordinate(&self) -> (Seq, [u8; 32]) {
        let snap = self.stores.kernel().snapshot();
        (snap.seq(), snap.chain())
    }

    // ── rejection surfacing (§5) ──

    /// Lower a write path's `TxnError` — the write half of the lowering
    /// family, beside the read arms' [`lower_read`]. It runs the [`lower_txn`]
    /// table and latches the poison hint on the way past `Poisoned`, so
    /// `execute` step (c) can fail the next write fast rather than opening a
    /// doomed transaction.
    ///
    /// That latch is why this is a METHOD where `lower_read` is a free
    /// function: every write arm comes through HERE and none reaches
    /// [`lower_txn`] directly. It is imported beside this method and not into
    /// `dispatch`, where the arms are; called from an arm it would build the
    /// same rejection while leaving its operation outside the latch's cover.
    /// And the latch exists only because the gate reads M10's MIRROR of M2's
    /// poison state rather than asking M2, so this method's whole reason is
    /// the mirror's ([`OperationSurface`]). `Relaxed` suffices: the flag is a
    /// hint, and M2 independently returns `Poisoned` to every later write
    /// whether or not this one is seen.
    ///
    /// [`lower_read`]: crate::lower::lower_read
    fn lower_write<E: Lower>(&self, kind: OpKind, e: TxnError<E>) -> Rejection {
        if matches!(e, TxnError::Poisoned) {
            self.poisoned.store(true, Ordering::Relaxed); // LATCH (§1(c)/§9)
        }
        lower_txn(kind, e)
    }
}

#[cfg(test)]
mod tests;
