//! The daemon's write path — the whole ordering protocol on one card: a
//! write commits, its change-feed record is appended, and its position is
//! announced, in that order, under one lock ([`WritePath::commit_under`],
//! which runs inside a guard its caller holds).
//!
//! Holding the three together is what makes two guarantees facts about this
//! element rather than conventions each caller remembers. `commits.log` is
//! appended in position order with monotone times, which is the premise
//! `sidecar.rs` states its invariants on; and every position a `GET /events`
//! subscriber is told about is one `GET /changes` already carries.
//!
//! That second guarantee is an induction with both halves held here.
//! [`WritePath::open`] is the BASE CASE: the stream is seeded from the head
//! the sidecar has just covered, before any febe exists to commit between
//! the two, so a connecting subscriber is told [`WritePath::announced`] and
//! that first position is already answerable. [`WritePath::commit_under`]
//! is the STEP: each announcement happens behind the record that made its
//! position answerable. Neither half is a rule a caller remembers, so the
//! two can never come apart in the window between a commit and its record.
//! Reads never come here and never take the lock.
//!
//! [`write_meta`] is also THE read/write partition — a read is exactly an
//! `Op` the change feed has nothing to record — so the history surface and
//! the change feed decide from one table and cannot disagree about a
//! variant.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use skep_address::Address;
use skep_engine::Engine;
use skep_febe::{Op, OpKind, Response};
use skep_kernel::Seq;

use crate::codec::op_name;
use crate::sidecar::{ChangesAnswer, Sidecar};

/// The commit stream's wait bound: a subscriber that has heard nothing for
/// this long is answered [`StreamStep::Keepalive`], which `server.rs` frames
/// as the wire's `:ka` comment, so proxies and clients can detect liveness —
/// and the daemon detects a dead subscriber by the failed write within one
/// interval.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// The write-serialization guard, newtyped so a function whose contract is
/// "under the serialization lock" names it in its arguments — the device
/// `auth/`'s [`crate::auth::LockRead`]/[`crate::auth::LockWrite`] already
/// are. A bare `MutexGuard<'_, ()>` is satisfied by a guard over ANY
/// `Mutex<()>`, so the parameter would say "some unit lock is held" where
/// the contract says "this one is" — unambiguous only while the crate holds
/// exactly one, in a daemon whose body cap already anticipates a second
/// write path (the media round's blob route) by name.
///
/// The honest limit is [`WritePath::serial_lock`]'s, unchanged: the guard
/// proves the lock is held and proves nothing about where the caller's
/// snapshot came from.
pub(crate) struct SerialGuard<'a>(#[allow(dead_code)] parking_lot::MutexGuard<'a, ()>);

/// The write path: the serialization point, the commit-metadata sidecar
/// behind it, and the commit stream in front of it.
///
/// The delegating methods below are one-line calls into the sidecar or the
/// stream, deliberately: what this card buys over holding the two side by
/// side is EXCLUSIVE ACCESS. [`Sidecar::record`] and
/// `CommitStream::announce` are reachable only from
/// [`WritePath::commit_under`], which is what makes the ordering above a
/// property of this type rather than a rule each handler remembers —
/// `Sidecar::record`'s caller contract is discharged by there being nowhere
/// else to fail it. Reaching the two through here is what that costs.
///
/// What that does NOT buy is the guard's SPAN. [`WritePath::serial_lock`]
/// hands the lock out, so that the snapshot a caller's gates read was taken
/// under the same guard is that method's contract with its callers, not
/// this type's — the same shape as `Sidecar::record`'s, one layer up.
pub(crate) struct WritePath {
    /// The serialization point. M2's applier serializes the commits
    /// themselves anyway, so this only moves that point up — and buys the
    /// ordering: a write's sidecar record and its announcement ride behind
    /// its own commit. A process crash can lose at most the one in-flight
    /// record (the append is flushed before the lock releases); an OS crash
    /// can lose more of the un-fsynced tail — either way the reopen walk
    /// re-covers the gap as bare entries.
    serial: Mutex<()>,
    /// The commit-metadata sidecar behind `GET /changes` and `/health`'s
    /// `head_time` (wire v6) — the daemon's testimony about its own writes.
    sidecar: Sidecar,
    /// The commit stream behind `GET /events` (wire v4).
    commit_stream: CommitStream,
}

impl WritePath {
    /// Replay the commit-metadata sidecar in `data_dir` and open the commit
    /// stream at the journal's committed head — in that order, which is the
    /// base case of this card's guarantee (see the module doc). Fallible
    /// only in the sidecar — the lock and the stream are memory — so the
    /// caller's error type need name only that.
    pub fn open(data_dir: &Path, engine: &Engine) -> io::Result<WritePath> {
        let sidecar = Sidecar::open(data_dir, engine)?;
        // Seeded AFTER the sidecar, from the same head, and before any febe
        // exists to commit between the two: the stream's first announced
        // position is therefore one `/changes` already carries. That is the
        // BASE CASE of this card's guarantee, and it is why the two are
        // sequenced statements — the order is then a fact of the code
        // rather than of the order two fields happen to be listed in.
        let commit_stream = CommitStream::at(engine.kernel().current_seq());
        Ok(WritePath { serial: Mutex::new(()), sidecar, commit_stream })
    }

    /// Take the write-serialization lock ALONE — for the auth write
    /// sequences, which must take their world snapshot AFTER no further
    /// commit can intervene (the gates' answers and the execute they gate
    /// then stand on one committed state). Lock order is fixed at the
    /// caller: the credential lock first, then this, never inverted.
    ///
    /// CALLER CONTRACT, and the half [`WritePath`] cannot hold for them:
    /// take the snapshot the gates read under THIS guard, and run any
    /// COMMITTING execute through [`WritePath::commit_under`] under it. A
    /// refusal that commits nothing may simply drop the guard, which is
    /// what every gate arm does; what must not happen is a committing
    /// `execute` under this guard OUTSIDE `commit_under`, which would
    /// leave the position unrecorded and unannounced. The one execute this
    /// crate performs outside it is the guest reply, and it is safe for a
    /// reason stated elsewhere: [`crate::server::open_guest_session`]'s
    /// session is retired, so M10 refuses a write under it without
    /// committing. Nothing here can check either half, and a snapshot
    /// taken outside the guard lets a commit land between what a gate read
    /// and what it gated.
    pub fn serial_lock(&self) -> SerialGuard<'_> {
        SerialGuard(self.serial.lock())
    }

    /// One write, whole, under a serialization guard the CALLER already
    /// holds ([`WritePath::serial_lock`]): execute, record the position it
    /// committed, announce that position, and hand back the answer. The
    /// guard argument is what keeps the three steps one operation even now
    /// that the lock's scope is the caller's write sequence.
    ///
    /// `execute` is a closure so this card stays free of M10's session and
    /// request types: what belongs here is the ordering, not the dispatch.
    /// It runs exactly once, inside the lock.
    ///
    /// PRECONDITION: `meta` is [`write_meta`]'s answer for the `Op` that
    /// `execute` runs, attributed to the session `execute` runs it under.
    /// Nothing here can check the first half — the closure is opaque by
    /// design, which is what keeps this card free of M10 — and a mismatch is
    /// not a fault but a silent lie: the change feed reports that position
    /// under the wrong op kind, or names a document the write did not touch,
    /// permanently, since nothing re-derives an entry the sidecar already
    /// holds. The daemon's write sequences establish it by deriving `meta`
    /// from the frame they are about to execute, and are the only callers.
    /// The second half needs no discharging: [`FrameMeta::attributed`] is
    /// the only way to reach a [`WriteMeta`], so a path that forgot to
    /// attribute does not compile rather than testifying `"bare"` for a
    /// signed write.
    pub fn commit_under(
        &self,
        _serial: &SerialGuard<'_>,
        meta: WriteMeta,
        execute: impl FnOnce() -> Response,
    ) -> Response {
        let resp = execute();
        if let Some(at) = self.record(meta, &resp) {
            self.commit_stream.announce(at);
        }
        resp
    }

    /// The data behind `GET /changes?since=N&limit=K`.
    pub fn changes(&self, since: u64, limit: usize) -> ChangesAnswer {
        self.sidecar.changes(since, limit)
    }

    /// The HEAD position's recorded wall-clock time (`/health`'s
    /// `head_time`), or `None` when that position's record is bare.
    ///
    /// The sidecar answers for the head by answering for its last recorded
    /// position, which is the same position because
    /// [`WritePath::commit_under`] records and announces inside the guard
    /// the caller holds across both. That premise is kept HERE;
    /// `Sidecar::head_time` states what relying on it costs.
    pub fn head_time(&self) -> Option<u64> {
        self.sidecar.head_time()
    }

    /// What one subscriber does next — see [`CommitStream::next`], where the
    /// receiver names the stream and the bare word is complete.
    pub fn next_step(&self, last: Seq) -> StreamStep {
        self.commit_stream.next(last)
    }

    /// End every open stream: each subscriber wakes on the broadcast and
    /// returns [`StreamStep::Shutdown`].
    pub fn shutdown(&self) {
        self.commit_stream.shutdown();
    }

    /// The last position ANNOUNCED: what a subscriber connecting now is told
    /// first, and what a test can witness without opening a socket.
    ///
    /// Deliberately not the kernel's committed head. Between a write's
    /// commit and its change-feed record — [`WritePath::commit_under`] holds
    /// the lock across both — the head names a position `/changes` cannot yet
    /// answer, and a subscriber told that number reads an empty delta and
    /// shows a stale view until the next commit. Announced positions sit
    /// behind their own records by construction, which is what makes this
    /// card's guarantee hold for a stream's FIRST event as well as its
    /// later ones.
    pub fn announced(&self) -> Seq {
        self.commit_stream.head()
    }

    /// Record one write's answer in the sidecar. What this layer decides,
    /// over [`Sidecar::record`]'s own job of appending a line, is WHETHER
    /// there is anything to record: an ack carries the committed position,
    /// while a rejection committed nothing. Runs under the serialization
    /// lock. EXHAUSTIVE with no `_` arm, like the other `Response` walks in
    /// this crate: a new answer shape carrying a committed position must
    /// decide whether the change feed reports it, and fails to compile
    /// until it does.
    ///
    /// Returns the position [`WritePath::commit_under`] announces, and in
    /// every case one `/changes` already carries — which is the guarantee,
    /// rather than the narrower "the position whose record this call made".
    /// Three paths reach it: a new commit, whose record this call makes; a
    /// position already recorded this uptime (an idempotency replay), which
    /// the sidecar declines and which was announced when it was first
    /// committed; and one at or below the open-time head (`emit`'s
    /// incumbent ack), which the sidecar also declines, which the reopen
    /// walk has already covered, and which the monotone stream ignores
    /// because it sits below the seed. A failed append is the fourth: the
    /// line is lost but the in-memory entry is not, so `/changes` answers
    /// that position this uptime and answers it bare after a restart.
    fn record(&self, meta: WriteMeta, resp: &Response) -> Option<Seq> {
        let WriteMeta { kind, docs, key } = meta;
        let (at, minted) = match resp {
            Response::Ack { at } => (*at, None),
            Response::AckAddr { addr, at } => (*at, Some(addr)),
            Response::AckEdit { at, .. } => (*at, None),
            Response::Delivery { .. }
            | Response::SpanSet { .. }
            | Response::Addrs { .. }
            | Response::MaybeAddr { .. }
            | Response::Count { .. }
            | Response::Page { .. }
            | Response::Endsets { .. }
            | Response::Runs { .. }
            | Response::Bool { .. }
            | Response::LinkValue { .. }
            | Response::Follow { .. }
            | Response::Deletions { .. }
            | Response::Compare { .. }
            | Response::Orphans { .. }
            | Response::Claims { .. }
            | Response::Rejected(_) => return None,
        };
        // [`AffectedDocs::Minted`] and this arm are one decision in two
        // tables: a `Minted` op must answer `AckAddr`, the one ack whose
        // address is the document the write minted. `Ack` carries none, and
        // `AckEdit`'s two are a successor link and its supersession claim —
        // link addresses, not a minted document — so neither binds `minted`
        // above. A `Minted` op answering either would render `docs: []`,
        // indistinguishable on the wire from `delegate`'s legitimate empty
        // list, on the field wire.md tells clients to dispatch on. The
        // fallback below is therefore what keeps this walk total, not a case
        // with a meaning of its own.
        let docs = match docs {
            AffectedDocs::Named(v) => v,
            AffectedDocs::Minted => {
                minted.map(|a| vec![a.tumbler().to_string()]).unwrap_or_default()
            }
        };
        self.sidecar.record(at.0, op_name(kind), docs, key);
        Some(at)
    }
}

// ── the read/write partition, and what a write records ───────────────────

/// What the change feed will say about one write as far as the FRAME can
/// tell: the op kind and the affected documents. Not yet a [`WriteMeta`]:
/// the AUTH testimony (AUTH-4.48) is the committing session's, which no
/// frame carries, so [`FrameMeta::attributed`] is the only way to reach a
/// value [`WritePath::commit_under`] accepts. A placeholder key would be a
/// wrong answer that looks right — `"bare"` is what a genuine bare-session
/// write records, and the sidecar never re-derives an entry it holds.
#[derive(Debug)]
pub(crate) struct FrameMeta {
    pub kind: OpKind,
    pub docs: AffectedDocs,
}

impl FrameMeta {
    /// Attribute this write to the session committing it — the key
    /// testimony from [`crate::auth::session::SessionBinding::testimony`].
    pub fn attributed(self, key: String) -> WriteMeta {
        WriteMeta { kind: self.kind, docs: self.docs, key }
    }
}

/// What the change feed will say about one write: the op kind, the
/// affected documents, and the session that committed it. The
/// frame-derived stage of a `commits.log` entry — [`crate::sidecar::CommitMeta`]
/// is the next one, completed at record time with the committed position
/// and the wall-clock time. Reachable only through
/// [`FrameMeta::attributed`], which is what lets
/// [`WritePath::commit_under`] state its precondition about one value.
#[derive(Debug)]
pub(crate) struct WriteMeta {
    pub kind: OpKind,
    pub docs: AffectedDocs,
    /// The AUTH key testimony (AUTH-4.48): the establishing key's
    /// fingerprint hex, or `"bare"` for a bare bind.
    pub key: String,
}

/// A write's affected document(s) for the sidecar (wire.md §The change
/// feed): the write's target doc; a link write names its home (`edit_link`
/// both its homes, the successor's `d_s` first); the MINTED document for
/// create/fork/version (known only from the ack); delegate/register_node
/// touch no document.
#[derive(Debug)]
pub(crate) enum AffectedDocs {
    /// The documents the frame itself names, already in the sidecar's
    /// dotted-decimal form — the only form anything downstream wants, so
    /// no address is cloned here to be rendered and dropped a moment later.
    Named(Vec<String>),
    /// The document the write mints, known only from its ack.
    ///
    /// An op classified `Minted` must answer `AckAddr`, the one ack whose
    /// address is the minted document — see [`WritePath::record`]'s `Minted`
    /// arm, which is the other half of this decision.
    Minted,
}

/// The [`FrameMeta`] of a write `Op` — `None` for reads, which is also
/// THE read/write partition: [`op_is_read`] is defined as this answer's
/// absence, so the two cannot disagree about a variant. EXHAUSTIVE with no
/// `_` arm: a new `Op` fails to compile here until its change-feed entry is
/// decided, and that one decision classifies it for the history surface
/// too.
///
/// OBLIGATION, and the one this table cannot check: `Some` for exactly the
/// ops M10 executes as writes (`Op::is_write`, `pub(crate)` there, so this
/// table is a restatement rather than a delegation). Both tables are
/// exhaustive over `Op` and neither is derived from the other, so a
/// divergence compiles. A write classified here as a read runs outside
/// [`WritePath::commit_under`]'s lock, unrecorded and unannounced: `/changes`
/// misses that position for the rest of the uptime, `/events` never
/// announces it, and [`crate::sidecar::Sidecar::head_time`]'s premise that
/// every commit is recorded fails, so `/health` reports an older position's
/// time AS the head's — the one thing that method's contract says it does
/// not do. A read classified here as a write is refused from `/op-at` as
/// `write_at_history`, denying a legitimate historical read. The two tables
/// agree at 14 writes of 38, with M10's own
/// `partition_matches_the_design_grouping` pinning that side.
pub(crate) fn write_meta(op: &Op) -> Option<FrameMeta> {
    let meta = |kind, docs| Some(FrameMeta { kind, docs });
    let one = |a: &Address| AffectedDocs::Named(vec![a.tumbler().to_string()]);
    match op {
        Op::CreateNewDocument { .. } => meta(OpKind::CreateNewDocument, AffectedDocs::Minted),
        Op::Delegate { .. } => meta(OpKind::Delegate, AffectedDocs::Named(Vec::new())),
        Op::RegisterNode { .. } => meta(OpKind::RegisterNode, AffectedDocs::Named(Vec::new())),
        Op::Fork => meta(OpKind::Fork, AffectedDocs::Minted),
        Op::Insert { doc, .. } => meta(OpKind::Insert, one(doc)),
        Op::Delete { doc, .. } => meta(OpKind::Delete, one(doc)),
        Op::Copy { doc, .. } => meta(OpKind::Copy, one(doc)),
        Op::Rearrange { doc, .. } => meta(OpKind::Rearrange, one(doc)),
        Op::Version { .. } => meta(OpKind::Version, AffectedDocs::Minted),
        Op::MakeLink { home, .. } => meta(OpKind::MakeLink, one(home)),
        Op::Emit { home, .. } => meta(OpKind::Emit, one(home)),
        Op::Nullify { home, .. } => meta(OpKind::Nullify, one(home)),
        Op::AssertSup { home, .. } => meta(OpKind::AssertSup, one(home)),
        Op::EditLink { d_s, d_a, .. } => {
            // The successor's home leads (wire.md: "both its homes,
            // successor's first"), and the claim's home is appended only
            // when it differs — one home named twice is one document.
            let mut docs = vec![d_s.tumbler().to_string()];
            if d_a != d_s {
                docs.push(d_a.tumbler().to_string());
            }
            meta(OpKind::EditLink, AffectedDocs::Named(docs))
        }
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
        | Op::OutClaims { .. } => None,
    }
}

/// The wire's read/write partition, mirroring M10's own `Op::is_read`
/// (crate-private there, so restated here — the one classification the
/// history surface needs before dispatch). A read is exactly an `Op` the
/// change feed has nothing to record: one table decides both, so an `Op`
/// admitted to history can never be one that commits.
///
/// What the restatement costs — that agreeing with M10 is an unchecked
/// obligation rather than a compiled fact — is [`write_meta`]'s to state,
/// since that is the table which carries it.
pub(crate) fn op_is_read(op: &Op) -> bool {
    write_meta(op).is_none()
}

// ── the commit stream (wire v4) ──────────────────────────────────────────

/// One head + shutdown flag under a mutex, one condvar. Every committing
/// write announces the position it committed (write-path notification —
/// `/op` is the only live write path, so no head advance can be missed);
/// each subscriber blocks in [`CommitStream::next`] with the keepalive
/// interval as its wait bound. Shutdown broadcasts on the same condvar,
/// which is what makes closing open streams immediate rather than a poll
/// away.
struct CommitStream {
    state: Mutex<StreamState>,
    cond: Condvar,
}

struct StreamState {
    head: Seq,
    shutdown: bool,
}

/// What a subscriber does next.
#[derive(Debug)]
pub(crate) enum StreamStep {
    /// The head advanced past the subscriber's last-sent position.
    Commit(Seq),
    /// Nothing moved for one keepalive interval.
    Keepalive,
    /// The daemon is stopping; end the stream.
    Shutdown,
}

impl CommitStream {
    fn at(head: Seq) -> CommitStream {
        CommitStream {
            state: Mutex::new(StreamState { head, shutdown: false }),
            cond: Condvar::new(),
        }
    }

    fn announce(&self, seq: Seq) {
        let mut state = self.state.lock();
        if seq.0 > state.head.0 {
            state.head = seq;
            self.cond.notify_all();
        }
    }

    fn shutdown(&self) {
        self.state.lock().shutdown = true;
        self.cond.notify_all();
    }

    /// The position last announced.
    fn head(&self) -> Seq {
        self.state.lock().head
    }

    /// Block until the head passes `last`, the daemon stops, or the
    /// keepalive interval elapses — whichever comes first. Returning the
    /// current head (not a queue of commits) is the coalescing: a burst of
    /// commits between wakes is one step.
    fn next(&self, last: Seq) -> StreamStep {
        let deadline = Instant::now() + KEEPALIVE_INTERVAL;
        let mut state = self.state.lock();
        loop {
            if state.shutdown {
                return StreamStep::Shutdown;
            }
            if state.head.0 > last.0 {
                return StreamStep::Commit(state.head);
            }
            if self.cond.wait_until(&mut state, deadline).timed_out() {
                return StreamStep::Keepalive;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skep_namespace::PrincipalId;

    /// The partition is one table's two faces: reads are exactly the ops
    /// the change feed records nothing for.
    #[test]
    fn reads_are_exactly_the_ops_with_no_change_feed_entry() {
        let read = Op::Fork;
        assert!(!op_is_read(&read), "fork commits");
        assert!(write_meta(&read).is_some());
        let query = Op::PrincipalPrefix { id: PrincipalId(1) };
        assert!(op_is_read(&query), "principal_prefix reads");
        assert!(write_meta(&query).is_none());
    }

    /// The commit stream only ever moves forward, and a burst between wakes
    /// coalesces onto one step — the property `next` answers "anything past
    /// what I last sent" for, rather than queueing.
    #[test]
    fn the_commit_stream_is_monotone_and_coalesces() {
        let stream = CommitStream::at(Seq(4));
        let step = stream.next(Seq(3));
        assert!(matches!(step, StreamStep::Commit(Seq(4))), "the head on connect: {step:?}");
        stream.announce(Seq(9));
        stream.announce(Seq(7)); // an idempotency replay's older position
        let step = stream.next(Seq(4));
        assert!(
            matches!(step, StreamStep::Commit(Seq(9))),
            "an older position never displaces the head, and the burst is one step: {step:?}"
        );
        stream.shutdown();
        let step = stream.next(Seq(0));
        assert!(
            matches!(step, StreamStep::Shutdown),
            "shutdown outranks a commit: {step:?}"
        );
    }
}
