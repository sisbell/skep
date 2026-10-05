//! The daemon's write path — the whole ordering protocol on one card: a
//! write commits, its change-feed record is appended, and its position is
//! announced, in that order, under one lock ([`WritePath::commit_under`],
//! which runs inside a guard its caller holds).
//!
//! Holding the three together is what makes two guarantees facts about this
//! element rather than conventions each caller remembers. `commits.log` is
//! appended in position order with monotone times, which is the premise
//! `sidecar.rs` states its invariants on; and every position a `GET /events`
//! subscriber is told about is one `GET /changes` already carries — at the
//! classes that may see it: the record is CLASSIFIED against the
//! post-commit head as it is made (`feed.rs`), which is why this card
//! holds the engine's store factory and takes a snapshot behind each
//! execute.
//!
//! That second guarantee is an induction with both halves held here.
//! [`WritePath::open`] is the BASE CASE: the stream opens at the head the
//! sidecar has just covered, before any febe exists to commit between the
//! two, so a connecting subscriber is told [`WritePath::announced`] and
//! that first position is already answerable. [`WritePath::commit_recorded`]
//! is the STEP, and both doors run it: each announcement happens behind the
//! record that made its position answerable. Neither half is a rule a caller
//! remembers, so the two can never come apart in the window between a
//! commit and its record. Reads never come here and never take the lock.
//!
//! AND THEN THE HEAD WRITER'S TURN (PUB-6.65). A session write, once recorded
//! and announced, gives the PUBLISHED HEAD writer (`head.rs`, this card's own
//! child) its turn under the same guard. When the cadence is due, the writer
//! commits up to three writes of the daemon's own — the staging draft's
//! one-time mint, the record's insert, and the publish into `H` — before
//! [`WritePath::commit_under`] returns. So "after `commit_under` returns"
//! means after this write AND any head it triggered: a caller reading the
//! world then reads the head's records beside its own, and pays their fsyncs
//! under whatever locks it holds, the credential write lock included. The
//! head's own writes take [`WritePath::commit_recorded`], the protocol
//! alone; the door is the whole difference between the two. And ONCE, the
//! head is not the cadence's but the CLAIM's (signed ops, s1): the write that
//! claims the board is followed, under the same guard and before any later
//! write is admitted, by the board's first head `H.1`
//! ([`WritePath::write_first_head`]) — the board term every attested write's
//! entry frame names — and a daemon that opens a claimed board with no head
//! writes it there, before it serves. Where the head writer's driver refuses
//! `H.1`, the refusal is surfaced and the claim stands, the head OWED at the
//! write path's next turn — a refused write's turn included
//! ([`WritePath::take_turn_after_refusal`]; l7-C1), ahead of the cadence's
//! own triggers — so the board is without a board term for exactly one
//! write (`head.rs`, WHAT A REFUSAL DOES).
//!
//! AND THE HALT (SO-I5 (d): no signature the board keeps is lost by a
//! crash, a power loss or a failed write). Below the reclaim floor the
//! attest store (`feed/attest.rs`) holds an entry signature's only copy, and
//! the record step syncs each of its lines before it returns. Where one
//! FAILS — its write or its sync — the commit it records stands and is
//! acked, and from then on [`WritePath::commit_recorded`] refuses every
//! commit, a session's and the head writer's alike, for the rest of the
//! uptime: any commit can trigger the checkpoint that deletes the journal
//! copy the lost line depends on. The refusal is M10's own for a board that
//! cannot commit, `poisoned` (`halt`). Reads are served throughout, and the
//! restart's open rebuilds the line from the journal.
//!
//! The read/write partition is M10's own `Op::is_read`. A read is exactly an
//! `Op` the change feed has nothing to record, so [`write_meta`] answers
//! `None` for precisely those — an equivalence it asserts against the
//! partition rather than assumes.
//!
//! AND THE CELL INDEX's ENTRY (`media.md` Op inventory 1: "EACH ENTRY IS
//! ENTERED IN skepd's MEMORY AT EVERY COMMIT THAT MINTS A CELL, whichever
//! op minted it … before that commit's guard drops"). [`WritePath::record`]
//! is the one step every commit rides, and it takes the post-commit
//! snapshot under the guard — so it is where the index is entered: for an
//! `insert`, the values the ack placed, read off that snapshot at the
//! addresses the commit minted; for a `publish`, the values the shot
//! re-inserted as fresh identity under the trunk's content chain. `copy`
//! and `version` mint no cell and take no entry. Which values a write may
//! mint a cell at is decided per op by [`write_meta`] ([`Minting`]), off
//! the frame, through the index's cheap prefix test, so a prose insert of
//! a million bytes costs the hook a byte compare apiece and no read.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use skep_address::{document_of, Address};
use skep_arrangement::HasM5;
use skep_engine::{Engine, EngineStores, World};
use skep_febe::{Op, OpKind, RejectCode, Rejection, Response, Stores};
use skep_kernel::{Attestation, Seq};

// The change feed behind `GET /changes`: its authority file, and the one
// question it asks the world.
mod classify;
mod feed;
mod sidecar;

// The published head writer, which commits through this module's own door.
mod head;

pub(crate) use feed::{ChangesAnswer, ChangesQuery, FeedClass};
pub(crate) use head::board_term;

use self::head::HeadWriter;
use self::sidecar::OpTerms;
use crate::codec::op_name;
use crate::media::index::{names_kind_by_prefix, CellIndex};
use crate::serial::{Serial, SerialGuard};
use feed::Feed;

/// The commit stream's wait bound: a subscriber that has heard nothing for
/// this long is answered [`StreamStep::Keepalive`], which `server.rs` frames
/// as the wire's `:ka` comment, so proxies and clients can detect liveness —
/// and the daemon detects a dead subscriber by the failed write within one
/// interval.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// The write path: the serialization point, the change feed's sidecars
/// behind it, the commit stream in front of it, and the published head
/// writer whose turn follows every session write.
///
/// The delegating methods below are one-line calls into the feed or the
/// stream, deliberately: what this card buys over holding the two side by
/// side is EXCLUSIVE ACCESS. [`Feed::record`] and
/// `CommitStream::announce` are reachable only from
/// [`WritePath::commit_recorded`], whose two callers are
/// [`WritePath::commit_under`] and the head writer, this card's own child,
/// which is what makes the ordering above a property of this type rather
/// than a rule each handler remembers — `CommitsLog::record`'s caller
/// contract is discharged by there being nowhere else to fail it. Reaching
/// the two through here is what that costs.
///
/// What that does NOT buy is the guard's SPAN. [`WritePath::serial_lock`]
/// hands the lock out, so that the snapshot a caller's gates read was taken
/// under the same guard is that method's contract with its callers, not
/// this type's — the same shape as `CommitsLog::record`'s, one layer up.
pub(crate) struct WritePath {
    /// The serialization point. M2's applier serializes the commits
    /// themselves anyway, so this only moves that point up — and buys the
    /// ordering: a write's sidecar record and its announcement ride behind
    /// its own commit. A process crash can lose at most the one in-flight
    /// record (the append is flushed before the lock releases); an OS crash
    /// can lose more of the un-fsynced tail — either way the reopen walk
    /// re-covers the gap as bare entries.
    serial: Serial,
    /// The change feed behind `GET /changes` and `/health`'s `head_time`
    /// (wire v6; class-gated since v7.8) — `commits.log`, the daemon's
    /// testimony about its own writes, and its four derived sidecars.
    feed: Feed,
    /// The commit stream behind `GET /events` (wire v4).
    commit_stream: CommitStream,
    /// The engine's store factory — the kernel behind it is where the
    /// POST-COMMIT snapshot each record is classified against comes from
    /// (`Feed::record` takes the head as it stands after the execute, under
    /// the serialization guard, so it is this commit's own state).
    stores: EngineStores,
    /// The PUBLISHED HEAD writer (PUB-6.65), this card's own child: given its
    /// turn by [`WritePath::commit_under`] after every session write, it
    /// writes `H` on the cadence through [`WritePath::commit_recorded`], under
    /// the caller's serialization guard.
    head_writer: HeadWriter,
    /// THE CELL INDEX — the media gate's, shared: entered by
    /// [`WritePath::record`] at every commit that mints a cell, under the
    /// serialization guard, before it drops.
    index: Arc<CellIndex>,
    /// THE HALT (the module doc; SO-I5 (d)): set by [`WritePath::record`]
    /// where the attest store failed a line, and never cleared — every
    /// commit after it is refused at [`WritePath::commit_recorded`]'s door.
    /// Set and read under the serialization guard alone, so the guard is
    /// what orders it, and the atomic only what makes the field `Sync`.
    halted: AtomicBool,
}

impl WritePath {
    /// Open the change feed in `data_dir` — `commits.log` replayed and its
    /// derived sidecars checked — then the commit stream at the journal's
    /// committed head, then the head writer over the feed just replayed — in
    /// that order, the first two being the base case of this card's
    /// guarantee (see the module doc). `index` is the cell index every
    /// commit from here on enters. Fallible only in the feed — the lock and
    /// the stream are memory, and the head writer resumes as if no head
    /// were written where it cannot read one — so the caller's error type
    /// need name only that.
    pub fn open(data_dir: &Path, engine: &Engine, index: Arc<CellIndex>) -> io::Result<WritePath> {
        let feed = Feed::open(data_dir, engine)?;
        // Opened AFTER the feed, at the same head, and before any febe
        // exists to commit between the two: the stream's first announced
        // position is therefore one `/changes` already carries. That is the
        // BASE CASE of this card's guarantee, and it is why the two are
        // sequenced statements — the order is then a fact of the code
        // rather than of the order two fields happen to be listed in.
        let commit_stream = CommitStream::at(engine.kernel().current_seq());
        // The head writer resumes by reading H's latest member off the engine's
        // recovered root (PUB-6.65's I7 (a)) and its cadence's two counters off
        // the feed opened above — the commits landed since that head, and the
        // head's own recorded time (the chain's open items, item 2).
        let head_writer = HeadWriter::open(engine.stores(), &feed);
        Ok(WritePath {
            serial: Serial::new(),
            feed,
            commit_stream,
            stores: engine.stores(),
            head_writer,
            index,
            halted: AtomicBool::new(false),
        })
    }

    /// The test seam behind `crate::Daemon::set_head_writer_clock_millis`:
    /// fix the head writer's clock, so a test drives the time-bound trigger
    /// without a `sleep`. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn set_head_writer_clock_millis(&self, millis: u64) {
        self.head_writer.set_clock_millis(millis);
    }

    /// The test seam behind `crate::Daemon::refuse_the_next_head_once`: the
    /// head writer's driver refuses the next head it is due to write, once,
    /// exactly as a driver refusal is handled. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn refuse_next_head_once(&self) {
        self.head_writer.refuse_next_head_once();
    }

    /// The test seam behind `crate::Daemon::attest_store_synced_through`:
    /// the coverage the attest store's last successful sync made durable.
    /// Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn attest_store_synced_through(&self) -> u64 {
        self.feed.attest_store_synced_through()
    }

    /// The test seam behind `crate::Daemon::fail_the_attest_stores_next_write`:
    /// the attest store's next write fails at the OS, answered as any store
    /// failure is (the module doc's HALT). Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn fail_the_attest_stores_next_write(&self) {
        self.feed.fail_the_attest_stores_next_write();
    }

    /// THE CLAIM'S HEAD (signed ops, s1; RULED 2026-09-25): the board's first
    /// head `H.1`, written now under the caller's serialization guard through
    /// the head writer's own door, whatever the cadence says — a no-op on a
    /// board that has a head. Two callers, both the daemon's: the claim-flip
    /// tail, under the guard the claim itself committed under, so the head
    /// names the claim's own position and no write lands between the two;
    /// and the open, on a claimed board whose journal holds no head — the
    /// crash window between the claim's transaction and the head's, or an
    /// `H.1` the head writer's driver refused while serving. `true` iff a
    /// head landed; `false` is a no-op or a refusal the head writer has
    /// already surfaced. Nothing else about a head moves:
    /// [`HeadWriter::write_first_head`] states the rule.
    pub(crate) fn write_first_head(&self, serial: &SerialGuard<'_>) -> bool {
        self.head_writer.write_first_head(self, serial)
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
    /// leave the position unrecorded and unannounced and give the head
    /// writer no turn. Every execute this crate performs outside the write
    /// path's two doors commits nothing: the guest reply — under this guard,
    /// or ahead of it at the credential sequence's first step — runs under
    /// `SessionId::GUEST`, which M10 never binds, so M10 refuses a write
    /// under it without committing; and every other is a READ, admitted by
    /// M10's own partition — `/op`'s through [`write_meta`], whose assertion
    /// holds it to that partition, and `/op-at`'s by asking it directly.
    /// Nothing here can check either half, and a snapshot taken outside the
    /// guard lets a commit land between what a gate read and what it gated.
    pub fn serial_lock(&self) -> SerialGuard<'_> {
        self.serial.lock()
    }

    /// One write, whole, under a serialization guard the CALLER already
    /// holds ([`WritePath::serial_lock`]): execute, record the position it
    /// committed, announce that position, give the published head writer
    /// its turn, and hand back the answer. The first three are
    /// [`WritePath::commit_recorded`]'s; the turn is this door's alone, and
    /// what it adds to "after this returns" is the module doc's to state.
    /// The guard argument is what keeps the four one operation though the
    /// lock's scope is the caller's write sequence.
    ///
    /// `execute` is a closure so this card stays free of M10's session and
    /// request types: what belongs here is the ordering, not the dispatch.
    /// It runs exactly once, inside the lock.
    ///
    /// PRECONDITION: `meta` is [`write_meta`]'s answer for the `Op` that
    /// `execute` runs, attributed to its committer — at this door, the session
    /// `execute` runs it under. Nothing here can check the first half — the
    /// closure is opaque by design, which is what keeps this card free of
    /// M10 — and a mismatch is not a fault but a silent lie: the change feed
    /// reports that position under the wrong op kind, or names a document the
    /// write did not touch, permanently, since nothing re-derives an entry
    /// the sidecar already holds. The daemon's write sequences establish it
    /// by deriving `meta` from the frame they are about to execute, and are
    /// the only callers. The second half needs no discharging:
    /// [`FrameMeta::attributed`] is the only way to reach a [`WriteMeta`], so
    /// a path that forgot to attribute does not compile rather than
    /// testifying `"bare"` for a signed write.
    pub fn commit_under(
        &self,
        serial: &SerialGuard<'_>,
        meta: WriteMeta,
        execute: impl FnOnce() -> Response,
    ) -> Response {
        let resp = self.commit_recorded(serial, meta, execute);
        // THE HEAD WRITER'S TURN (PUB-6.65), under the same guard. Given after
        // every write this door runs, a refusal included: whether anything
        // LANDED is the writer's to decide — the kernel's seq, never the
        // answer — so this door hands it nothing to decide it by.
        self.head_writer.take_turn(self, serial);
        resp
    }

    /// THE HEAD WRITER'S TURN after a write the sequence REFUSED ahead of
    /// the store — an admission refusal, which never reaches
    /// [`WritePath::commit_under`] — under the caller's serialization guard
    /// (l7-C1; SO-I4 (a)): nothing landed, so the cadence counts nothing and
    /// evaluates no trigger, and what the turn is for is the one head no
    /// trigger makes due — the claim's `H.1` where its driver refused it,
    /// owed until a head lands (`head.rs`, THE CLAIM'S HEAD, OWED). Free
    /// where no head is owed: one lock, one look at the state.
    pub fn take_turn_after_refusal(&self, serial: &SerialGuard<'_>) {
        self.head_writer.take_turn(self, serial);
    }

    /// The ordering protocol and NOTHING after it: execute, record the
    /// position the write committed, announce that position, and hand back
    /// the answer — [`WritePath::commit_under`] less the head writer's turn.
    ///
    /// EVERY commit this daemon makes rides this step — `/op`'s through
    /// [`WritePath::commit_under`], the published head's own directly — and
    /// that is the one premise the commit stream's completeness and
    /// [`sidecar::CommitsLog::head_time`] rest on: a commit that
    /// bypassed it would be unrecorded and unannounced, and both would be
    /// wrong about it in silence. Their docs cite this step rather than
    /// naming the writers: a writer is covered by passing through it, and by
    /// nothing else.
    ///
    /// The head writer's door, and PRIVATE to this module so it stays the
    /// head writer's alone: a session write through it would commit without
    /// giving the head writer its turn. `execute` runs exactly once, inside
    /// the lock, and [`WritePath::commit_under`]'s precondition on `meta` is
    /// this door's, its committer the head writer itself — no session, so its
    /// writes are attributed to [`head::SYSTEM_TESTIMONY`], and it discharges
    /// the first half as the write sequences do, deriving `meta` from the
    /// `Op` whose fields its driver call then runs.
    ///
    /// Once the write path has HALTED (the module doc; SO-I5 (d)), none of
    /// it: `execute` never runs, and the answer is M10's `Poisoned`
    /// (`Halt`), built as M10 builds it, so the bytes are M10's own. Being
    /// this door's, the refusal follows the write sequence's admission —
    /// and the credential memo's recall — and precedes M10's whole
    /// `execute`, its retry memo included: a plain write repeated after its
    /// ack was lost meets the halt and not its original ack. A guest's
    /// write never reaches the door, and M10 refuses it `Unauthenticated`,
    /// committing nothing.
    fn commit_recorded(
        &self,
        serial: &SerialGuard<'_>,
        meta: WriteMeta,
        execute: impl FnOnce() -> Response,
    ) -> Response {
        if self.halted.load(Ordering::Relaxed) {
            let halt = Rejection::classified(meta.kind, RejectCode::Poisoned, None);
            return Response::Rejected(halt);
        }
        let resp = execute();
        if let Some(at) = self.record(serial, meta, &resp) {
            self.commit_stream.announce(at);
        }
        resp
    }

    /// The data behind `GET /changes` at the requester's class — the FEED
    /// CLASS the route resolved off its one head snapshot, and the query.
    pub fn changes(&self, class: &FeedClass<'_>, query: &ChangesQuery) -> ChangesAnswer {
        self.feed.page(class, query)
    }

    /// The HEAD position's recorded wall-clock time (`/health`'s
    /// `head_time`), or `None` when that position's record is bare.
    ///
    /// The feed answers for the head by answering for its last recorded
    /// position, which is the same position because every commit rides
    /// [`WritePath::commit_recorded`], which records it under the guard it
    /// committed under. That premise is kept HERE; `CommitsLog::head_time`
    /// states what relying on it costs.
    pub fn head_time(&self) -> Option<u64> {
        self.feed.head_time()
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
        self.commit_stream.announced()
    }

    /// Record one write's answer in the feed. What this layer decides,
    /// over [`Feed::record`]'s own job of appending the lines, is WHETHER
    /// there is anything to record: an ack carries the committed position,
    /// while a rejection committed nothing. Runs under the serialization
    /// lock. EXHAUSTIVE with no `_` arm, like the other `Response` walks in
    /// this crate: a new answer shape carrying a committed position must
    /// decide whether the change feed reports it, and fails to compile
    /// until it does.
    ///
    /// Returns the position [`WritePath::commit_recorded`] announces, and in
    /// every case one `/changes` already carries — which is the guarantee,
    /// rather than the narrower "the position whose record this call made".
    /// Three paths reach it: a new commit, whose record this call makes; a
    /// position already recorded this uptime (an idempotency replay), which
    /// the feed declines and which was announced when it was first
    /// committed; and one at or below the open-time head (`emit`'s
    /// incumbent ack), which the feed also declines, which the reopen
    /// walk has already covered, and which the monotone stream ignores
    /// because it sits at or below the position the stream opened at. A
    /// failed append is the fourth: the line is lost but the in-memory entry
    /// is not, so `/changes` answers that position this uptime and answers it
    /// bare after a restart. A failed ATTEST STORE line is the fifth, and
    /// HALTS the write path (the module doc; SO-I5 (d)): this commit stands
    /// and is announced, and every later one is refused.
    ///
    /// The record is classified against the head AS IT STANDS after the
    /// execute — this commit's own post-state, since the serialization
    /// guard admits no other commit between the two — so a minted document
    /// is in the exception set the classification reads (PUB-7.7's
    /// one-snapshot clause, read from the feed's side). That guard is
    /// forwarded rather than dropped: the feed's own record and the
    /// authority file's below it are the same obligation, and each names it
    /// in its arguments.
    ///
    /// THE CELL INDEX IS ENTERED HERE, off the same post-commit snapshot,
    /// under the same guard (the module doc) — for a FRESH commit alone,
    /// the one whose position is the snapshot's own: an idempotency
    /// replay's memoized ack names an older position, and its cells were
    /// entered when it first committed.
    fn record(&self, serial: &SerialGuard<'_>, meta: WriteMeta, resp: &Response) -> Option<Seq> {
        let WriteMeta { kind, docs, testimony, signed, terms, minting } = meta;
        let (at, minted) = match resp {
            Response::Ack { at } => (*at, None),
            Response::AckAddr { addr, at } => (*at, Some(addr)),
            Response::AckEdit { at, .. } => (*at, None),
            Response::Delivery { .. }
            | Response::IDelivery { .. }
            | Response::Frontier { .. }
            | Response::SpanSet { .. }
            | Response::Addrs { .. }
            | Response::MaybeAddr { .. }
            | Response::EffectiveOwner { .. }
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
            | Response::DocMetadata { .. }
            | Response::EditionClaims { .. }
            | Response::UniversalGrants { .. }
            | Response::Rejected(_) => return None,
        };
        // [`AffectedDocs::Minted`] and this arm are one decision in two
        // tables: a `Minted` op must answer `AckAddr`, the one ack whose
        // address is the document the write minted. `Ack` carries none, and
        // `AckEdit`'s two are a successor link and its supersession claim —
        // link addresses, not a minted document — so neither binds `minted`
        // above. A `Minted` op answering either would render `docs: []`,
        // indistinguishable on the wire from `delegate`'s legitimate empty
        // list, on the field wire.md tells clients to dispatch on. So the
        // arm below asserts the premise rather than defaulting quietly past
        // it, and its fallback is what keeps the walk total in release, not
        // a case with a meaning of its own.
        let docs = match docs {
            AffectedDocs::Named(v) => v,
            AffectedDocs::Minted => {
                // The obligation [`AffectedDocs::Minted`] states, made loud.
                // In release the fallback keeps this walk total and produces
                // a `docs: []` entry, which `feed`'s mask NEVER masks:
                // the op, the wall-clock time and the fingerprint of the
                // signing key of a draft mint, served to every class,
                // permanently, since nothing re-derives an entry the sidecar
                // already holds.
                debug_assert!(
                    minted.is_some(),
                    "a Minted op must answer AckAddr, the ack carrying the document it minted"
                );
                minted.cloned().map(|a| vec![a]).unwrap_or_default()
            }
        };
        let post = self.stores.kernel().snapshot();
        if post.seq() == at {
            match (&minting, minted) {
                (Minting::Insert { naming }, Some(start)) if !naming.is_empty() => {
                    self.index.enter_insert(post.world(), start, naming);
                }
                (Minting::Publish { reinserted }, Some(member)) if *reinserted > 0 => {
                    self.index.enter_publish(post.world(), member, *reinserted);
                }
                _ => {}
            }
        }
        let terms = terms.complete(minted, post.world());
        let recorded = self.feed.record(
            serial,
            at.0,
            op_name(kind),
            docs,
            testimony,
            signed,
            terms,
            post.world(),
        );
        if recorded.is_err() {
            // The store has said it, once: the line's file and position.
            self.halted.store(true, Ordering::Relaxed);
        }
        Some(at)
    }
}

// ── the read/write partition, and what a write records ───────────────────

/// HOW a write's entry is SIGNED, as the sequence that admitted it knows
/// (signed ops; D12): the daemon's own assertion, recorded at commit, of
/// why the row's `key` is absent — and, for the marker, the value itself,
/// which the attest store appends in the same `record` call that appends
/// `commits.log`. `None` is an unsigned entry, whose row serves `key`.
/// Reaches the feed by the one door [`FrameMeta::attributed`] guards.
#[derive(Debug)]
pub(crate) enum Signed {
    /// The marker slot is filled with this — the attestation the plain
    /// sequence's check ADMITTED and handed the kernel
    /// (`transact_attested`); the store mirrors it, the wire renders it as
    /// the row's `attest`.
    Marker(Attestation),
    /// The entry's signature is its CREDENTIAL record's own `sig` member —
    /// the deposit's `make_link`, where the record grade VERIFIED it under the
    /// set that opens its home (lane D's `record_grade_check`; D26: a record
    /// is judged at its link). The LINK row alone (as7-E2 (a), owner
    /// 2026-10-01 — e-Q2 re-cut at the atom row): the atom's `insert` is
    /// admitted unsigned, so its row carries `key`, the daemon's testimony of
    /// the writing session — one asserted hand for an orphan atom whose link
    /// never lands, D12's audit diagnostic. Neither row carries `attest`.
    RecordSig,
}

/// What the change feed will say about one write as far as the FRAME can
/// tell: the op kind, the affected documents, and which of the op's own
/// terms its row carries — a `delegate`'s seated principal among them, the
/// one term the request supplies. Not yet a [`WriteMeta`]: the AUTH testimony
/// (AUTH-4.48) is the committer's — a session's, or the head writer's own —
/// which no frame carries, and the entry's signedness is the admitting
/// sequence's, so [`FrameMeta::attributed`] is the only way to reach a value
/// either of the write path's doors accepts. A placeholder testimony would
/// be a wrong answer that looks right — `"bare"` is what a genuine
/// bare-session write records, and the feed never re-derives an entry it
/// holds.
#[derive(Debug)]
pub(crate) struct FrameMeta {
    pub kind: OpKind,
    docs: AffectedDocs,
    /// Which of the op's own terms its row carries ([`RowTerms`]).
    terms: RowTerms,
    /// Which content addresses the write may mint a cell at ([`Minting`]).
    minting: Minting,
}

impl FrameMeta {
    /// Attribute this write to its committer — a session's testimony
    /// ([`crate::auth::session::SessionBinding::testimony`] — the
    /// establishing key's fingerprint, or `"bare"`), or the head writer's own
    /// ([`head::SYSTEM_TESTIMONY`]), which commits with no session at all —
    /// and to its SIGNATURE where it has one ([`Signed`]): the marker the
    /// plain sequence admitted, or the credential record's own `sig`; `None`
    /// for an unsigned entry, the head writer's own included.
    pub fn attributed(self, testimony: String, signed: Option<Signed>) -> WriteMeta {
        WriteMeta {
            kind: self.kind,
            docs: self.docs,
            testimony,
            signed,
            terms: self.terms,
            minting: self.minting,
        }
    }
}

/// WHICH CONTENT ADDRESSES A WRITE MINTS THAT MAY HOLD A CELL — the cell
/// index's entry at commit, decided per op by [`write_meta`] off the frame
/// and completed by [`WritePath::record`] off the post-commit snapshot.
/// Two ops mint content from a request's or a draft's values; every other
/// mints none, `copy` and `version` sharing identity (the media record's
/// §The publication seam: a copy of a cell mints no baptism).
#[derive(Debug)]
enum Minting {
    /// No content value is minted.
    None,
    /// An `insert`: its values are minted I-adjacent from the ack's address;
    /// `naming` holds the indices of those whose bytes pass the index's
    /// prefix test — read ahead of the commit, so a prose insert enters
    /// nothing and reads nothing after it.
    Insert { naming: Vec<usize> },
    /// A `publish`: the shot re-inserts `reinserted` values of the staging
    /// draft as fresh identity under the trunk's content chain — the count
    /// the shot's own arithmetic answers, each value read off the
    /// post-commit snapshot.
    Publish { reinserted: u64 },
}

/// What the change feed will say about one write: the op kind, the
/// affected documents, the committer's testimony, the entry's signedness
/// and which of the op's own terms its row carries. The frame-derived stage
/// of a `commits.log` entry — [`sidecar::CommitMeta`] is the next one,
/// completed at record time with the committed position, the wall-clock time
/// and the terms' values, from the ack and the post-commit world.
///
/// Reachable only through [`FrameMeta::attributed`] — a fact of the FIELDS
/// and not of the call sites: they are private, so `server.rs`, which is
/// where the write sequences live and where a hand-built meta is the thing
/// to reach for, cannot spell the struct expression. That is what lets
/// [`WritePath::commit_under`] state its precondition about one value.
#[derive(Debug)]
pub(crate) struct WriteMeta {
    kind: OpKind,
    docs: AffectedDocs,
    /// The write's AUTH TESTIMONY (AUTH-4.48; wire.md §The change feed):
    /// the establishing key's fingerprint hex, `"bare"` for a bare bind, or
    /// [`head::SYSTEM_TESTIMONY`] for the published head's own writes —
    /// never an absence, which the wire's `key` field reserves for testimony
    /// that was LOST. Recorded on every line; served on the wire only where
    /// `signed` is `None` (D12).
    testimony: String,
    /// The entry's signature, where it has one — see [`Signed`].
    signed: Option<Signed>,
    /// Which of the op's own terms its row carries ([`RowTerms`]).
    terms: RowTerms,
    /// Which content addresses the write may mint a cell at ([`Minting`]).
    minting: Minting,
}

/// A write's affected document(s) for the feed (wire.md §The change feed):
/// the write's target doc; a link write names its home (`edit_link` both
/// its homes, the successor's `d_s` first; `nullify` its home AND the
/// target link's home, as a set — PUB-6.46); the MINTED document for
/// create/fork/version and the minted MEMBER for `publish` (each known only
/// from the ack); delegate/register_node touch no document.
#[derive(Debug)]
enum AffectedDocs {
    /// The documents the frame itself names. Held as ADDRESSES, which is
    /// what the feed's classification wants — it reads each one against the
    /// head's exception set — so the rendering belongs at the sidecar's own
    /// door and not here: text handed down would be parsed straight back,
    /// and the parse would have nowhere to report a name it could not read.
    Named(Vec<Address>),
    /// The document the write mints, known only from its ack.
    ///
    /// An op classified `Minted` must answer `AckAddr`, the one ack whose
    /// address is the minted document — see [`WritePath::record`]'s `Minted`
    /// arm, which is the other half of this decision.
    Minted,
}

/// Which of the op's own terms (`sidecar::OpTerms`) its row carries — wire.md
/// §The change feed; r6-2a, AUTH-6.36, D25's d25-S1 — decided per op by
/// [`write_meta`], beside the documents, and completed at record time
/// ([`RowTerms::complete`]) from the ack and the post-commit world, as
/// [`AffectedDocs::Minted`] is. Three ops carry terms; every other op's row
/// carries none — wire.md's "absent on every other op's row", stated arm by
/// arm in the table rather than by a default.
#[derive(Debug)]
enum RowTerms {
    /// The row carries none of the op terms.
    Absent,
    /// `delegate`'s pair: the principal it seats, from the REQUEST; the
    /// minted account address, from its `AckAddr`.
    Delegate { new_id: u64 },
    /// `make_link`'s minted link address, from its `AckAddr` — the GRANT
    /// RECORD's address for a replacing grant; its `replaces` link sits at the
    /// next.
    MakeLink,
    /// `publish`'s placed count and base extent — the POST-COMMIT world's
    /// shot terms of the member its `AckAddr` names, the very value
    /// `doc_metadata` serves for it (M5's `ShotPlace`, folded per member), so
    /// the row and the member read cannot disagree.
    Publish,
}

impl RowTerms {
    /// The row's terms, completed from the ack's minted address and the
    /// post-commit world — `None` for an op whose row carries none.
    ///
    /// A `delegate` or `make_link` that answered no `AckAddr`, or a `publish`
    /// whose member the fold holds no terms for, records none — the same
    /// fallback [`WritePath::record`]'s `Minted` arm takes for `docs`, and as
    /// unreachable: each of the three answers `AckAddr`, and M5 journals a
    /// `ShotPlace` for every shot (lanes B+C). Asserted in debug for the same
    /// reason that arm asserts.
    fn complete(self, minted: Option<&Address>, post: &World) -> Option<OpTerms> {
        let terms = match &self {
            RowTerms::Absent => return None,
            RowTerms::Delegate { new_id } => minted.map(|prefix| OpTerms::Delegate {
                new_prefix: prefix.to_string(),
                new_id: *new_id,
            }),
            RowTerms::MakeLink => minted.map(|link| OpTerms::MakeLink { link: link.to_string() }),
            RowTerms::Publish => {
                minted.and_then(|member| post.m5().shot_terms(member)).map(|t| OpTerms::Publish {
                    placed: t.placed.to_string(),
                    base_extent: t.base_extent.as_ref().map(ToString::to_string),
                })
            }
        };
        debug_assert!(
            terms.is_some(),
            "{self:?} answers AckAddr and (a publish) folds its shot terms, so its row's terms \
             resolve"
        );
        terms
    }
}

/// The [`FrameMeta`] of a write `Op` — `None` for reads, which is M10's
/// read/write partition seen from the change feed's side. EXHAUSTIVE with no
/// `_` arm: a new `Op` fails to compile here until its change-feed entry is
/// decided — the documents its row names and the terms it carries, each arm
/// stating both.
///
/// OBLIGATION: `Some` for exactly the ops M10 executes as writes. This
/// table answers a second question — which documents a commit touched — so
/// it is its own match rather than a call to [`Op::is_write`]; the assertion
/// below is what keeps the two from drifting, since M10 owns the partition
/// and this table only restates its shape. What a drift would cost, were it
/// to reach a release build: a write classified here as a read runs outside
/// [`WritePath::commit_under`]'s lock, unrecorded and unannounced —
/// `/changes` misses that position for the rest of the uptime, `/events`
/// never announces it, and [`sidecar::CommitsLog::head_time`]'s
/// premise that every commit is recorded fails, so `/health` reports an
/// older position's time AS the head's, the one thing that method's contract
/// says it does not do. A read classified here as a write is refused from
/// `/op-at` as `write_at_history`, denying a legitimate historical read.
/// The two tables agree at 15 writes of 45.
///
/// SECOND OBLIGATION, and the one no assertion here can reach:
/// [`classify::derived_docs`] answers this same question — which
/// documents a commit touched — from the JOURNAL, for a position whose record
/// was lost, and the two must agree on the MASK. Precisely: every DRAFT this
/// table names must appear in that one's answer, and that one's answer must
/// name nothing this table does not. An op whose effect no witness of
/// `derived_docs` catches derives an EMPTY class, and an empty class is never
/// masked, so its draft writes are served to every requester from the restart
/// that reconstructs them. The compiler forces a new `Op` through this table
/// and through nothing there. The equivalence is about the MASK alone, so the
/// narrowings inherit whatever difference remains: a bare position whose
/// derived class is empty is excluded from an `under=` page where its
/// recorded twin would match. And a check is possible but not worth its cost
/// here — [`WritePath::commit_under`] would have to hold a pre-commit
/// snapshot and run `derived_docs` per write, a full link enumeration of two
/// worlds on the write path even in a debug build — so the pair of inclusions
/// above is what a test at the wire asserts instead.
pub(crate) fn write_meta(op: &Op) -> Option<FrameMeta> {
    let meta = |kind, docs, terms| Some(FrameMeta { kind, docs, terms, minting: Minting::None });
    let one = |a: &Address| AffectedDocs::Named(vec![a.clone()]);
    let absent = RowTerms::Absent;
    let answer = match op {
        Op::CreateNewDocument { .. } => {
            meta(OpKind::CreateNewDocument, AffectedDocs::Minted, absent)
        }
        // The seated principal rides from the request; the minted prefix is
        // the ack's (`RowTerms::complete`).
        Op::Delegate { new_id, .. } => meta(
            OpKind::Delegate,
            AffectedDocs::Named(Vec::new()),
            RowTerms::Delegate { new_id: new_id.0 },
        ),
        Op::RegisterNode { .. } => {
            meta(OpKind::RegisterNode, AffectedDocs::Named(Vec::new()), absent)
        }
        Op::Fork { .. } => meta(OpKind::Fork, AffectedDocs::Minted, absent),
        // The values that may hold a cell, by index — the prefix test ahead
        // of the commit, so the record's entry reads only those.
        Op::Insert { doc, values, .. } => Some(FrameMeta {
            kind: OpKind::Insert,
            docs: one(doc),
            terms: absent,
            minting: Minting::Insert {
                naming: values
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| names_kind_by_prefix(v.as_bytes()))
                    .map(|(i, _)| i)
                    .collect(),
            },
        }),
        Op::Delete { doc, .. } => meta(OpKind::Delete, one(doc), absent),
        Op::Copy { doc, .. } => meta(OpKind::Copy, one(doc), absent),
        Op::Rearrange { doc, .. } => meta(OpKind::Rearrange, one(doc), absent),
        Op::Version { .. } => meta(OpKind::Version, AffectedDocs::Minted, absent),
        // The shot mints the chain's next member, known only from its ack —
        // the document it advances is the member's own trunk — and
        // re-inserts the draft's values as fresh identity under it.
        Op::Publish { shot, .. } => Some(FrameMeta {
            kind: OpKind::Publish,
            docs: AffectedDocs::Minted,
            terms: RowTerms::Publish,
            minting: Minting::Publish {
                reinserted: u64::try_from(&shot.reinserted_values()).unwrap_or(u64::MAX),
            },
        }),
        Op::MakeLink { home, .. } => meta(OpKind::MakeLink, one(home), RowTerms::MakeLink),
        // `emit` mints a link too, and its row carries no `link`: r6-2a names
        // `make_link` alone.
        Op::Emit { home, .. } => meta(OpKind::Emit, one(home), absent),
        Op::Nullify { home, target } => {
            // The record's home AND the target link's home (PUB-6.46): a
            // retraction lands at its target, so a draft-homed record
            // against a public link shows to a guest as the target's entry.
            // A SET, each document once — a same-home retraction reduces to
            // one name identically, and the entry alone distinguishes
            // nothing. `document_of` is address arithmetic (PUB-6.38); a
            // target with no document is not a link a committed nullify
            // could have named, and contributes nothing.
            let mut docs = vec![home.clone()];
            if let Some(t) = document_of(target) {
                if &t != home {
                    docs.push(t);
                }
            }
            meta(OpKind::Nullify, AffectedDocs::Named(docs), absent)
        }
        Op::AssertSup { home, .. } => meta(OpKind::AssertSup, one(home), absent),
        Op::EditLink { d_s, d_a, .. } => {
            // The successor's home leads (wire.md: "both its homes,
            // successor's first"), and the claim's home is appended only
            // when it differs — one home named twice is one document — and,
            // as `emit`'s, the row carries no `link` for the successor or the
            // claim it mints.
            let mut docs = vec![d_s.clone()];
            if d_a != d_s {
                docs.push(d_a.clone());
            }
            meta(OpKind::EditLink, AffectedDocs::Named(docs), absent)
        }
        Op::NextAccountPrefix { .. }
        | Op::PrincipalPrefix { .. }
        | Op::EffectiveOwner { .. }
        | Op::UniversalGrants
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
        | Op::EditionClaims { .. } => None,
    };
    debug_assert_eq!(
        answer.is_some(),
        op.is_write(),
        "the change-feed table and M10's read/write partition disagree about this op"
    );
    answer
}

// ── the commit stream (wire v4) ──────────────────────────────────────────

/// The last ANNOUNCED position and the shutdown flag under a mutex, one
/// condvar. Every committing write announces the position it committed —
/// every commit rides [`WritePath::commit_recorded`], which announces behind
/// the record it made, so no head advance can be missed; each subscriber
/// blocks in [`CommitStream::next`] with the keepalive interval as its wait
/// bound. Shutdown broadcasts on the same condvar, which is what makes
/// closing open streams immediate rather than a poll away.
struct CommitStream {
    state: Mutex<StreamState>,
    cond: Condvar,
}

struct StreamState {
    announced: Seq,
    shutdown: bool,
}

/// What a subscriber does next.
#[derive(Debug)]
pub(crate) enum StreamStep {
    /// A position past the subscriber's last-sent one was announced.
    Commit(Seq),
    /// Nothing moved for one keepalive interval.
    Keepalive,
    /// The daemon is stopping; end the stream.
    Shutdown,
}

impl CommitStream {
    /// A stream whose first announced position is `announced` —
    /// [`WritePath::open`] passes the head the feed has just covered, the
    /// base case.
    fn at(announced: Seq) -> CommitStream {
        CommitStream {
            state: Mutex::new(StreamState { announced, shutdown: false }),
            cond: Condvar::new(),
        }
    }

    fn announce(&self, seq: Seq) {
        let mut state = self.state.lock();
        if seq > state.announced {
            state.announced = seq;
            self.cond.notify_all();
        }
    }

    fn shutdown(&self) {
        self.state.lock().shutdown = true;
        self.cond.notify_all();
    }

    /// The position last announced.
    fn announced(&self) -> Seq {
        self.state.lock().announced
    }

    /// Block until the announced position passes `last`, the daemon stops,
    /// or the keepalive interval elapses — whichever comes first. Returning
    /// the last announced position (not a queue of commits) is the
    /// coalescing: a burst of commits between wakes is one step.
    fn next(&self, last: Seq) -> StreamStep {
        let deadline = Instant::now() + KEEPALIVE_INTERVAL;
        let mut state = self.state.lock();
        loop {
            if state.shutdown {
                return StreamStep::Shutdown;
            }
            if state.announced > last {
                return StreamStep::Commit(state.announced);
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
    use skep_content::Val;
    use skep_namespace::PrincipalId;

    /// Reads are exactly the ops the change feed records nothing for —
    /// M10's partition and this table's answer, agreeing on both sides.
    #[test]
    fn reads_are_exactly_the_ops_with_no_change_feed_entry() {
        let write = Op::Fork { published: None };
        assert!(!write.is_read(), "fork commits");
        assert!(write_meta(&write).is_some());
        let read = Op::PrincipalPrefix { id: PrincipalId(1) };
        assert!(read.is_read(), "principal_prefix reads");
        assert!(write_meta(&read).is_none());
    }

    /// The index's entry hint, decided off the frame: an insert names the
    /// indices of its values that pass the prefix test and nothing of the
    /// rest; a publish carries the shot's re-inserted count; every other
    /// write mints no cell.
    #[test]
    fn each_write_states_which_addresses_may_hold_a_cell() {
        use skep_address::Nat;
        use skep_febe::{Deposit, Shot, VPos};

        let doc = crate::codec::wire_address("1.0.1.0.1").expect("a test address");
        let cell = format!(
            r#"{{"type":"{}","hash":"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262","size":5}}"#,
            crate::media::cell::KIND
        );
        let insert = Op::Insert {
            doc: doc.clone(),
            at: VPos::content(Nat::from(1u32)),
            values: vec![
                Val::new(b"a".as_slice()),
                Val::new(cell.as_bytes()),
                Val::new(b"b".as_slice()),
            ],
            deposit: Deposit::Undeclared,
        };
        let minting = write_meta(&insert).expect("a write").minting;
        assert!(matches!(&minting, Minting::Insert { naming } if naming == &[1]), "{minting:?}");
        let prose = Op::Insert {
            doc: doc.clone(),
            at: VPos::content(Nat::from(1u32)),
            values: vec![Val::new(b"ab".as_slice())],
            deposit: Deposit::Undeclared,
        };
        assert!(
            matches!(write_meta(&prose).expect("a write").minting, Minting::Insert { naming } if naming.is_empty())
        );
        let publish = Op::Publish { doc, shot: Shot { base: None, draft: None, runs: Vec::new() } };
        assert!(matches!(
            write_meta(&publish).expect("a write").minting,
            Minting::Publish { reinserted: 0 }
        ));
        assert!(matches!(
            write_meta(&Op::Fork { published: None }).expect("a write").minting,
            Minting::None
        ));
    }

    /// Each write's arm of the table states the terms its row carries, beside
    /// its documents, and no default decides it: `delegate` carries the
    /// principal it seats, from the request; `make_link` and `publish` carry
    /// theirs, completed from the ack; every other write carries none —
    /// `emit` and `edit_link` among them, though each mints a link (r6-2a
    /// names `make_link` alone).
    #[test]
    fn each_write_states_the_terms_its_row_carries() {
        use skep_address::Nat;
        use skep_febe::{Deposit, Endset, Shot, SlotArg, SuccessorSpec, VPos};

        let addr = |s: &str| crate::codec::wire_address(s).expect("a test address");
        let doc = addr("1.0.1.0.1");
        let terms = |op: Op| write_meta(&op).expect("a write").terms;
        let no_slot = || SlotArg::Addrs(Vec::new());

        let delegate = Op::Delegate {
            new_prefix: crate::codec::wire_tumbler("1.0.2").expect("a tumbler"),
            new_id: PrincipalId(41),
        };
        let seated = terms(delegate);
        assert!(matches!(seated, RowTerms::Delegate { new_id: 41 }), "{seated:?}");
        let make_link = Op::MakeLink {
            home: doc.clone(),
            from: no_slot(),
            to: no_slot(),
            ty: no_slot(),
            replaces: None,
        };
        assert!(matches!(terms(make_link), RowTerms::MakeLink));
        let publish = Op::Publish {
            doc: doc.clone(),
            shot: Shot { base: None, draft: None, runs: Vec::new() },
        };
        assert!(matches!(terms(publish), RowTerms::Publish));

        let emit =
            Op::Emit { home: doc.clone(), ty: Endset::empty(), from: doc.clone(), to: Vec::new() };
        let edit_link = Op::EditLink {
            original: addr("1.0.1.0.1.0.2.1"),
            successor: SuccessorSpec { from: Vec::new(), to: Vec::new(), ty: no_slot() },
            d_s: doc.clone(),
            d_a: doc.clone(),
        };
        let insert = Op::Insert {
            doc: doc.clone(),
            at: VPos::content(Nat::from(1u32)),
            values: Vec::new(),
            deposit: Deposit::Undeclared,
        };
        for (op, name) in [
            (emit, "emit"),
            (edit_link, "edit_link"),
            (Op::Fork { published: None }, "fork"),
            (insert, "insert"),
        ] {
            let carried = terms(op);
            assert!(matches!(carried, RowTerms::Absent), "{name} carries no term: {carried:?}");
        }
    }

    /// The commit stream only ever moves forward, and a burst between wakes
    /// coalesces onto one step — the property `next` answers "anything past
    /// what I last sent" for, rather than queueing.
    #[test]
    fn the_commit_stream_is_monotone_and_coalesces() {
        let stream = CommitStream::at(Seq(4));
        let step = stream.next(Seq(3));
        assert!(
            matches!(step, StreamStep::Commit(Seq(4))),
            "the opening position on connect: {step:?}"
        );
        stream.announce(Seq(9));
        stream.announce(Seq(7)); // an idempotency replay's older position
        let step = stream.next(Seq(4));
        assert!(
            matches!(step, StreamStep::Commit(Seq(9))),
            "an older position never displaces the announced one, and the burst is one \
             step: {step:?}"
        );
        stream.shutdown();
        let step = stream.next(Seq(0));
        assert!(matches!(step, StreamStep::Shutdown), "shutdown outranks a commit: {step:?}");
    }
}
