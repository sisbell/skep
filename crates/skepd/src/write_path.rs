//! The daemon's write path — the whole ordering protocol on one card: a
//! write commits, its change-feed record is appended, and its position is
//! announced, in that order and under one lock ([`WritePath::commit`]).
//!
//! Holding the three together is what makes two guarantees facts about this
//! element rather than conventions each caller remembers. `commits.log` is
//! appended in position order with monotone times, which is the premise
//! `sidecar.rs` states its invariants on; and every position a `GET /events`
//! subscriber is told about is one `GET /changes` already carries, because
//! the announcement happens behind the record that made it answerable. That
//! second guarantee covers a stream's FIRST event too: a connecting
//! subscriber is told [`WritePath::announced`], not the kernel's head, so
//! the two can never come apart in the window between a commit and its
//! record. Reads never come here and never take the lock.
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

/// SSE keepalive cadence, and so the commit stream's wait bound: a
/// subscriber that has heard nothing for this long is answered
/// [`StreamStep::Keepalive`] and writes its `:ka` comment, so proxies and
/// clients can detect liveness — and the daemon detects a dead subscriber
/// by the failed write within one interval.
const SSE_KEEPALIVE: Duration = Duration::from_secs(15);

/// The write path: the serialization point, the commit-metadata sidecar
/// behind it, and the commit stream in front of it.
///
/// The delegating methods below are one-line calls into the sidecar or the
/// stream, deliberately: what this card buys over holding the two side by
/// side is EXCLUSIVE ACCESS. [`Sidecar::record`] and
/// `CommitStream::publish` are reachable only from [`WritePath::commit`],
/// which is what makes the ordering above a property of this type rather
/// than a rule each handler remembers — `Sidecar::record`'s caller contract
/// is discharged by there being nowhere else to fail it. Reaching the two
/// through here is what that costs.
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
    /// stream at the journal's committed head. Fallible only in the sidecar
    /// — the lock and the stream are memory — so the caller's error type
    /// need name only that.
    pub fn open(data_dir: &Path, engine: &Engine) -> io::Result<WritePath> {
        Ok(WritePath {
            serial: Mutex::new(()),
            sidecar: Sidecar::open(data_dir, engine)?,
            commit_stream: CommitStream::at(engine.kernel().current_seq()),
        })
    }

    /// One write, whole: execute under the serialization lock, record the
    /// position it committed, announce that position, and hand back the
    /// answer. The three steps are one operation precisely so no caller can
    /// perform two of them.
    ///
    /// `execute` is a closure so this card stays free of M10's session and
    /// request types: what belongs here is the ordering, not the dispatch.
    /// It runs exactly once, inside the lock.
    ///
    /// PRECONDITION: `kind` and `docs` are [`write_meta`]'s answer for the
    /// `Op` that `execute` runs. Nothing here can check it — the closure is
    /// opaque by design, which is what keeps this card free of M10 — and a
    /// mismatch is not a fault but a silent lie: the change feed reports
    /// that position under the wrong op kind, or names a document the write
    /// did not touch, permanently, since nothing re-derives an entry the
    /// sidecar already holds. `Daemon::post_op` establishes it by deriving
    /// both from one [`write_meta`] call on the frame it is about to
    /// execute, and is the only caller.
    pub fn commit(
        &self,
        kind: OpKind,
        docs: AffectedDocs,
        execute: impl FnOnce() -> Response,
    ) -> Response {
        let _serial = self.serial.lock();
        let resp = execute();
        if let Some(at) = self.record(kind, docs, &resp) {
            self.commit_stream.publish(at);
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
    /// position, which is the same position because [`WritePath::commit`]
    /// records every commit under the lock it commits under. That premise
    /// is kept HERE; `Sidecar::head_time` states what relying on it costs.
    pub fn head_time(&self) -> Option<u64> {
        self.sidecar.head_time()
    }

    /// What one subscriber does next — see [`CommitStream::next`].
    pub fn next(&self, last: Seq) -> StreamStep {
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
    /// commit and its change-feed record — [`WritePath::commit`] holds the
    /// lock across both — the head names a position `/changes` cannot yet
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
    /// Returns the position [`WritePath::commit`] announces, which is
    /// exactly the position whose record this call just made — so an
    /// announcement can never outrun `/changes`. An idempotency replay
    /// re-acks an OLD position, which the sidecar declines to re-record and
    /// the monotone commit stream ignores, since that position was
    /// announced when it was first committed.
    fn record(&self, kind: OpKind, docs: AffectedDocs, resp: &Response) -> Option<Seq> {
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
        self.sidecar.record(at.0, op_name(kind), docs);
        Some(at)
    }
}

// ── the read/write partition, and what a write records ───────────────────

/// A write's affected document(s) for the sidecar (ruling §0): the write's
/// target doc; a link write names its home (`edit_link` both homes); the
/// MINTED document for create/fork/version (known only from the ack);
/// delegate/register_node touch no document.
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

/// The sidecar metadata of a write `Op` — `None` for reads, which is also
/// THE read/write partition: [`op_is_read`] is defined as this answer's
/// absence, so the two cannot disagree about a variant. EXHAUSTIVE with no
/// `_` arm: a new `Op` fails to compile here until its change-feed entry is
/// decided, and that one decision classifies it for the history surface
/// too.
pub(crate) fn write_meta(op: &Op) -> Option<(OpKind, AffectedDocs)> {
    let one = |a: &Address| AffectedDocs::Named(vec![a.tumbler().to_string()]);
    match op {
        Op::CreateNewDocument { .. } => Some((OpKind::CreateNewDocument, AffectedDocs::Minted)),
        Op::Delegate { .. } => Some((OpKind::Delegate, AffectedDocs::Named(Vec::new()))),
        Op::RegisterNode { .. } => Some((OpKind::RegisterNode, AffectedDocs::Named(Vec::new()))),
        Op::Fork => Some((OpKind::Fork, AffectedDocs::Minted)),
        Op::Insert { doc, .. } => Some((OpKind::Insert, one(doc))),
        Op::Delete { doc, .. } => Some((OpKind::Delete, one(doc))),
        Op::Copy { doc, .. } => Some((OpKind::Copy, one(doc))),
        Op::Rearrange { doc, .. } => Some((OpKind::Rearrange, one(doc))),
        Op::Version { .. } => Some((OpKind::Version, AffectedDocs::Minted)),
        Op::MakeLink { home, .. } => Some((OpKind::MakeLink, one(home))),
        Op::Emit { home, .. } => Some((OpKind::Emit, one(home))),
        Op::Nullify { home, .. } => Some((OpKind::Nullify, one(home))),
        Op::AssertSup { home, .. } => Some((OpKind::AssertSup, one(home))),
        Op::EditLink { d_s, d_a, .. } => {
            let mut docs = vec![d_s.tumbler().to_string()];
            if d_a != d_s {
                docs.push(d_a.tumbler().to_string());
            }
            Some((OpKind::EditLink, AffectedDocs::Named(docs)))
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
pub(crate) fn op_is_read(op: &Op) -> bool {
    write_meta(op).is_none()
}

// ── the commit stream (wire v4) ──────────────────────────────────────────

/// One head + shutdown flag under a mutex, one condvar. Every committing
/// write publishes the position it committed (write-path notification —
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

    fn publish(&self, seq: Seq) {
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
        let deadline = Instant::now() + SSE_KEEPALIVE;
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
        stream.publish(Seq(9));
        stream.publish(Seq(7)); // an idempotency replay's older position
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
