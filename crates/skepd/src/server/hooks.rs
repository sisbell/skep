//! `Daemon`'s test hooks and the notices their holds write — every
//! `#[doc(hidden)]` item of `Daemon`.

use std::num::NonZeroU64;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use parking_lot::{Condvar, Mutex};
use skep_engine::{HistoryError, Recovery};
#[cfg(feature = "test-hooks")]
use skep_kernel::Step;
use skep_kernel::{Attestation, CheckpointHeader, SaltSource, Seq};
use skep_media::gate::LimitsRefused;
use skep_media::index::{Rebuild, WALK_FAULT, WALK_HOLD};
use skep_media::pruner::PrunePass;
use skep_media::serve::STREAM_HOLD;
use skep_media::MediaOptions;
#[cfg(feature = "test-hooks")]
use skep_util::notice;
use skep_util::permits::Permit;

use super::{Daemon, DaemonError};
use crate::auth::AuthOptions;

/// THE WORKER's FAULT DOOR (the test seam behind [`Daemon::panic_the_next_worker`]):
/// one process-wide arm — `WORKER_FAULT_NONE` while nothing is armed, else
/// one of the three arms. The two ONCE arms, `inside` and `outside`, are
/// fired ONCE by the next worker that reaches each and disarmed as they
/// fire; the EVERY arm is READ at the outside site and never taken, so it
/// fires in every worker that reaches it and stands until another arming
/// replaces it. Process-wide, as the stream hold is, because the workers
/// are the transport's threads and a child binary arms it before any daemon
/// exists.
static WORKER_FAULT: AtomicU8 = AtomicU8::new(WORKER_FAULT_NONE);

/// The door's four states: nothing armed; a panic INSIDE the handler's
/// catch on the next request; a panic OUTSIDE it at the worker's next loop
/// turn, after its reply; and that same panic outside the catch in EVERY
/// worker that reaches it, one reply each — the arm a suite ends every
/// worker with under the real worker floor, where one death leaves the
/// rest serving.
const WORKER_FAULT_NONE: u8 = 0;
const WORKER_FAULT_INSIDE: u8 = 1;
const WORKER_FAULT_OUTSIDE: u8 = 2;
const WORKER_FAULT_EVERY: u8 = 3;

/// The door's arm named: the words the hook takes and the child's variable
/// carries, one spelling for both.
fn worker_fault_arm(arm: &str) -> u8 {
    match arm {
        "inside" => WORKER_FAULT_INSIDE,
        "outside" => WORKER_FAULT_OUTSIDE,
        "every" => WORKER_FAULT_EVERY,
        other => panic!("no worker fault arm named {other:?}: `inside`, `outside` or `every`"),
    }
}

/// Take a ONCE arm where it is the one armed: `true` once per arming, so
/// the panic fires on one worker and no later one. The every arm is never
/// taken: [`the_every_arm_stands`] reads it.
fn take_the_worker_fault(arm: u8) -> bool {
    WORKER_FAULT
        .compare_exchange(arm, WORKER_FAULT_NONE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Whether the EVERY arm stands — read and never cleared, so every worker
/// that asks is answered the same until another arming replaces it.
fn the_every_arm_stands() -> bool {
    WORKER_FAULT.load(Ordering::Acquire) == WORKER_FAULT_EVERY
}

/// The worker's side of the INSIDE arm, called by the transport inside its
/// handler's catch before the request is routed: a panic whose payload is a
/// literal, so the binary's hook carries it, and whose location is the
/// CALLER's — the site in the worker's loop, as a fault there would name
/// it; the catch answers `500 internal_panic` and the worker serves on.
#[track_caller]
pub(super) fn fire_the_worker_fault_inside_the_catch() {
    if take_the_worker_fault(WORKER_FAULT_INSIDE) {
        panic!("the test seam's worker fault, inside the handler's catch");
    }
}

/// The worker's side of the OUTSIDE arm and of the EVERY arm, called by the
/// transport at the worker's next loop turn after its reply is written: a
/// panic past the catch, located at the caller's site, which ends the
/// worker — the shape a worker's death has. The outside arm is taken, so
/// one worker ends; the every arm is read, so every worker that reaches
/// this site ends, each after its one reply, with one panic text for both.
#[track_caller]
pub(super) fn fire_the_worker_fault_outside_the_catch() {
    if take_the_worker_fault(WORKER_FAULT_OUTSIDE) || the_every_arm_stands() {
        panic!("the test seam's worker fault, outside the handler's catch");
    }
}

/// Take a per-daemon arm where it stands: `true` once per arming.
fn take_the_fault(arm: &AtomicBool) -> bool {
    arm.swap(false, Ordering::AcqRel)
}

/// THE WRITE GUARD's HOLD (the test seam behind
/// [`Daemon::hold_the_write_guard`]): armed, the plain write sequence parks
/// AFTER taking its permit and both of its locks — the shape of the trigger
/// inside an inline backstop, which holds the guard for its whole run —
/// until released; the writers behind it take their permits and block on
/// `serial_lock()`, and the one past the pool is refused `write_busy` at
/// once. Process-wide, as the index walk's hold is: the sequence is a method
/// of whichever daemon serves the write, and the hold is armed before it.
struct WriteGuardHold {
    held: Mutex<bool>,
    released: Condvar,
}

/// The test seam's one hold on the write guard.
static WRITE_GUARD_HOLD: WriteGuardHold =
    WriteGuardHold { held: Mutex::new(false), released: Condvar::new() };

/// The write sequence's side of the hold, called by `op.rs`'s plain sequence
/// once its permit and its two locks are taken: park while the hold is
/// armed, the locks and the permit held through the park.
pub(super) fn park_while_the_write_guard_is_held() {
    let mut held = WRITE_GUARD_HOLD.held.lock();
    while *held {
        WRITE_GUARD_HOLD.released.wait(&mut held);
    }
}

impl Daemon {
    /// The checkpoint thread's side of its panic seam, called by the
    /// transport at the top of the thread's loop turn, after the hold and
    /// before it looks at the flag: a panic whose payload is a literal, so
    /// the binary's hook carries it, located at the CALLER's site, which
    /// the loop's catch contains — the consequence line, the flag, and the
    /// thread's end.
    #[track_caller]
    pub(super) fn fire_the_checkpoint_threads_fault(&self) {
        if take_the_fault(&self.faults.checkpointer) {
            panic!("the test seam's fault in the checkpoint thread's loop");
        }
    }

    /// The pruner's side of its panic seam, called by the transport at the
    /// top of the pruner's loop turn: the shape above, the pruner's catch
    /// containing it.
    #[track_caller]
    pub(super) fn fire_the_pruners_fault(&self) {
        if take_the_fault(&self.faults.pruner) {
            panic!("the test seam's fault in the pruner's loop");
        }
    }

    /// The deferred unlink's side of its panic seam, called inside
    /// `Daemon::retire_asides` before the store's unlink: the shape above,
    /// the worker's catch around the unlink containing it — the reply
    /// already on the socket, the worker serving on.
    #[track_caller]
    pub(super) fn fire_the_unlinks_fault(&self) {
        if take_the_fault(&self.faults.unlink) {
            panic!("the test seam's fault in the deferred unlink");
        }
    }

    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): PANIC THE CHECKPOINT THREAD at the top of its next loop
    /// turn — the turn a crossing's wake, a tick or a release of the hold
    /// brings — once: the loop's catch says the consequence line, sets the
    /// liveness flag ([`Daemon::checkpoint_thread_ended`]) and the thread
    /// ends, every later checkpoint the backstop's. Arming again re-arms.
    #[doc(hidden)]
    pub fn panic_the_checkpoint_thread_next(&self) {
        self.faults.checkpointer.store(true, Ordering::Release);
    }

    /// TEST HOOK (the same standing): PANIC THE PRUNER's THREAD at the top
    /// of its next loop turn — within its readiness poll while the index
    /// walks, else at its next cadence — once: its catch says the
    /// consequence line, sets the flag ([`Daemon::pruner_thread_ended`])
    /// and the thread ends, no pass running after. Arming again re-arms.
    #[doc(hidden)]
    pub fn panic_the_pruner_next(&self) {
        self.faults.pruner.store(true, Ordering::Release);
    }

    /// TEST HOOK (the same standing): PANIC INSIDE THE NEXT DEFERRED UNLINK
    /// — `Daemon::retire_asides`, which the transport runs after a blob
    /// family's reply is on the socket — once: the catch around it contains
    /// the panic, the aside stands for the pass, and the worker serves its
    /// next connection. Arming again re-arms.
    #[doc(hidden)]
    pub fn panic_in_the_next_unlink(&self) {
        self.faults.unlink.store(true, Ordering::Release);
    }

    /// TEST HOOK (the same standing): whether the checkpoint thread has
    /// ENDED on a caught panic this uptime — the liveness flag its catch
    /// sets. No standing line comes after it: the thread is the carrier.
    #[doc(hidden)]
    pub fn checkpoint_thread_ended(&self) -> bool {
        self.threads.checkpointer_ended.load(Ordering::Acquire)
    }

    /// TEST HOOK (the same standing): whether the pruner's thread has ENDED
    /// on a caught panic this uptime — the liveness flag its catch sets and
    /// the standing line reads as `the pruner's thread is gone`.
    #[doc(hidden)]
    pub fn pruner_thread_ended(&self) -> bool {
        self.threads.pruner_ended.load(Ordering::Acquire)
    }

    /// TEST HOOK (the same standing): SHORTEN THE STANDING INTERVAL to
    /// `millis` — the checkpoint thread's timed wait ticks every so many
    /// milliseconds from now in place of the shipped hour, the deadline
    /// still carried across the crossings' wakes — so a suite drives the
    /// standing line through a seam rather than a wait, as
    /// [`Daemon::set_head_writer_clock_millis`] drives the head's clock.
    /// Every daemon's interval is the constant until this is called.
    #[doc(hidden)]
    pub fn set_standing_interval_millis(&self, millis: u64) {
        self.writes.checkpoint_signal().set_tick_interval(Duration::from_millis(millis));
    }
    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): PANIC THE NEXT WORKER, ONCE — `"inside"` its handler's
    /// catch on its next request, the request answered `500 internal_panic`
    /// and the worker serving on, or `"outside"` it at its next loop turn
    /// after a reply, the worker ending — or PANIC EVERY WORKER, `"every"`:
    /// the outside arm's panic in every worker that reaches that site, each
    /// after its one reply, the arm read and never taken — so a suite drives
    /// the binary's panic hook and, under the real worker floor with one
    /// request per worker, the workers' end and the exit it earns. A once
    /// arm fires on the first worker to reach it and disarms; the every arm
    /// stands until another arming replaces it; arming again replaces the
    /// arm. Process-wide, armed before or after a daemon exists; a child
    /// binary is armed by the variable `SKEPD_TEST_WORKER_FAULT`, which
    /// `main.rs` reads under `test-hooks` and hands here. Any other word is
    /// a caller's bug and PANICS.
    #[doc(hidden)]
    pub fn panic_the_next_worker(arm: &str) {
        WORKER_FAULT.store(worker_fault_arm(arm), Ordering::Release);
    }

    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): hold one FETCH permit exactly as an in-flight fetch
    /// does, or `None` when all [`MAX_CONCURRENT_FETCHES`](skep_media::limits::MAX_CONCURRENT_FETCHES)
    /// are taken. A permit from here is a slot of the fetch pool alone:
    /// holding every one leaves `/op-at` and the class scans untouched.
    #[doc(hidden)]
    #[must_use = "a permit dropped at once holds nothing"]
    pub fn try_hold_fetch_permit(&self) -> Option<Permit<'_>> {
        self.fetches.try_hold()
    }

    /// TEST HOOK (the same standing): hold one UPLOAD permit exactly as an
    /// in-flight creation or resume of `/blob/upload` does, or `None` when
    /// all [`MAX_CONCURRENT_UPLOADS`](skep_media::limits::MAX_CONCURRENT_UPLOADS)
    /// are taken (M-I5 (f)). A permit from here is a slot of the upload pool
    /// alone: holding every one leaves the fetch, `/op-at` and the class
    /// scans untouched — and holds no worker, so a suite that pins the
    /// pool's count drains it here and a suite that pins worker OCCUPANCY
    /// holds real streams instead.
    #[doc(hidden)]
    #[must_use = "a permit dropped at once holds nothing"]
    pub fn try_hold_upload_permit(&self) -> Option<Permit<'_>> {
        self.uploads.try_hold()
    }

    /// TEST HOOK (the same standing): hold one WRITE permit exactly as an
    /// in-flight write on `/op` does, or `None` when all
    /// [`MAX_CONCURRENT_WRITES`](super::MAX_CONCURRENT_WRITES) are taken
    /// (`operations.md` §4 rows 25, 27). A permit from here is a slot of the
    /// write pool alone: holding every one refuses the next write on `/op`
    /// `write_busy` and leaves the fetch, the upload, `/op-at`, the class
    /// scans and every read untouched — and holds no worker, so a suite that
    /// pins the pool's count drains it here and a suite that pins worker
    /// OCCUPANCY parks real writes under [`Daemon::hold_the_write_guard`]
    /// instead.
    #[doc(hidden)]
    #[must_use = "a permit dropped at once holds nothing"]
    pub fn try_hold_write_permit(&self) -> Option<Permit<'_>> {
        self.write_permits.try_acquire()
    }

    /// TEST HOOK (the same standing): HOLD THE WRITE GUARD — in this
    /// process, the plain write sequence parks after taking its permit and
    /// both of its locks until [`Daemon::release_the_write_guard`], the
    /// shape of the trigger inside an inline backstop; the writers behind it
    /// take their permits and park on the guard, and the one past the pool is
    /// refused `write_busy` at once, not after the guard frees. A
    /// process-wide seam, as the index walk's is. A suite releases it before
    /// its daemon stops: a parked worker is one the stop joins.
    #[doc(hidden)]
    pub fn hold_the_write_guard() {
        *WRITE_GUARD_HOLD.held.lock() = true;
    }

    /// TEST HOOK (the same standing): release the parked writer, and hold no
    /// later one.
    #[doc(hidden)]
    pub fn release_the_write_guard() {
        *WRITE_GUARD_HOLD.held.lock() = false;
        WRITE_GUARD_HOLD.released.notify_all();
    }

    /// TEST HOOK (the same standing): HOLD EVERY FETCH STREAM between two
    /// of its chunks — armed before a suite's request, so the suite can
    /// close the session or revoke the grant while the stream stands, then
    /// [`Daemon::release_the_fetch_stream`] and watch the re-check end it.
    /// A process-wide seam, as the index walk's is.
    #[doc(hidden)]
    pub fn hold_the_fetch_stream() {
        STREAM_HOLD.hold();
    }

    /// TEST HOOK (the same standing): release every held stream, and hold
    /// no later one.
    #[doc(hidden)]
    pub fn release_the_fetch_stream() {
        STREAM_HOLD.release();
    }

    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): whether the cell index's walk at open has completed —
    /// what a suite waits on before its first PUT, rather than racing the
    /// walk's thread.
    #[doc(hidden)]
    pub fn index_is_ready(&self) -> bool {
        self.media.index_ready()
    }

    /// TEST HOOK (the same standing): whether the cell index's walk at open
    /// DIED — the FAILED state its thread's catch set (`operations.md` §4
    /// row 26), which the three readers, the door, the pruner's loop and
    /// the standing line read; never true beside [`Daemon::index_is_ready`].
    #[doc(hidden)]
    pub fn index_is_failed(&self) -> bool {
        self.media.index_failed()
    }

    /// TEST HOOK (the same standing): the walk's report once it has
    /// completed — the values walked, the cells and halt marks entered, its
    /// duration and the time past the prefix test — the open-cost measure.
    #[doc(hidden)]
    pub fn index_rebuild_report(&self) -> Option<Rebuild> {
        self.media.index().rebuild_report()
    }

    /// TEST HOOK (the same standing): the index's counts — cells, distinct
    /// hashes, halt marks.
    #[doc(hidden)]
    pub fn index_counts(&self) -> (usize, usize, usize) {
        self.media.index().counts()
    }

    /// TEST HOOK (the same standing): HOLD THE WALK — every cell index walk
    /// started from here on, in this process, parks before its first entry
    /// until [`Daemon::release_the_index_walk`]. Armed BEFORE a daemon
    /// opens, so a suite can serve requests against a daemon whose index is
    /// not ready: the readiness refusal at the three readers, every other
    /// request served, the composition clause at the release. A process-wide
    /// seam, since the walk starts inside the open.
    #[doc(hidden)]
    pub fn hold_the_index_walk() {
        WALK_HOLD.hold();
    }

    /// TEST HOOK (the same standing): release every held walk, and hold no
    /// later one.
    #[doc(hidden)]
    pub fn release_the_index_walk() {
        WALK_HOLD.release();
    }

    /// TEST HOOK (the same standing): FAIL THE WALK — the next cell index
    /// walk started in this process PANICS after its hold and before its
    /// first entry, ONCE (the seam disarms as it fires), so a suite serves
    /// requests against a daemon whose index FAILED (`operations.md` §4 row
    /// 26): the three readers' `index_failed` for the uptime, the door's
    /// lease arm as final, the pruner's one line and no pass, the standing
    /// line's clause. Armed BEFORE a daemon opens, as
    /// [`Daemon::hold_the_index_walk`] is, since the walk starts inside the
    /// open — a process-wide seam, as the hold is; armed under the hold, it
    /// fires at the release. Arming again re-arms.
    #[doc(hidden)]
    pub fn fail_the_index_walk() {
        WALK_FAULT.arm();
    }

    /// The line the feed walk's hold writes on the operator stream as it
    /// parks — what the dirty-crash harness watches the child's stderr for
    /// before it kills.
    #[doc(hidden)]
    pub const FEED_WALK_HOLD_NOTICE: &'static str = crate::write_path::FEED_WALK_HOLD_NOTICE;

    /// TEST HOOK (the same standing): HOLD THE FEED WALK — every walk of a
    /// lost or torn `commits.log`'s region started from here on, in this
    /// process, parks after its `open:` line and before its first boundary,
    /// writing [`Daemon::FEED_WALK_HOLD_NOTICE`], until
    /// [`Daemon::release_the_feed_walk`]. Armed BEFORE a daemon opens, so a
    /// suite serves requests against a daemon whose region is pending: the
    /// refusal on a page into it, every other request served, a write
    /// admitted, the landing at the release. A process-wide seam, since the
    /// walk starts inside the open; a child binary arms it by the variable
    /// `SKEPD_TEST_FEED_WALK_HOLD`, which `main.rs` reads under `test-hooks`.
    /// A held walk is one the stop ends: the walk parks in timed waits and
    /// reads the stop between them, so a daemon dropped while its walk is
    /// held joins it at once, nothing written, the region walked again at
    /// the next open.
    #[doc(hidden)]
    pub fn hold_the_feed_walk() {
        crate::write_path::FEED_WALK_HOLD.hold();
    }

    /// TEST HOOK (the same standing): release every held feed walk, and hold
    /// no later one.
    #[doc(hidden)]
    pub fn release_the_feed_walk() {
        crate::write_path::FEED_WALK_HOLD.release();
    }

    /// TEST HOOK (the same standing): THE REGION PENDING — `(low, head]`,
    /// the positions a lost or torn `commits.log` left uncovered that the
    /// walk behind the listener has yet to land, `low` covered and `head`
    /// the last of the region, or `None` once the landing wrote it (or
    /// where the log covered the head) — what a suite waits on before it
    /// reads a feed the walk is landing, and pins a page's refusal against.
    #[doc(hidden)]
    pub fn feed_pending_region(&self) -> Option<(u64, u64)> {
        self.writes.feed_pending_region()
    }

    /// TEST HOOK (the same standing): PANIC THE FEED WALK's THREAD after its
    /// `open:` line and its hold, before its first boundary — once: its
    /// catch says the consequence line, sets the flag the standing line
    /// reads (`the feed walk's thread is gone`) and the thread ends, the
    /// region pending for the uptime, `/changes` refusing pages into it, a
    /// restart walking again. Process-wide, as the hold is: armed before
    /// the open, or while the walk parks at the hold; arming again re-arms.
    #[doc(hidden)]
    pub fn panic_the_feed_walk() {
        crate::write_path::arm_the_feed_walks_fault();
    }

    /// TEST HOOK (the same standing): SET THE FEED WALK's PROGRESS CADENCE —
    /// its `progress:` line every `boundaries` boundaries or `millis`
    /// milliseconds, whichever comes first, in place of the shipped
    /// `FEED_WALK_PROGRESS_BOUNDARIES` and `FEED_WALK_PROGRESS_INTERVAL` —
    /// read by the walk per boundary, so a walk parked at the hold takes a
    /// cadence set meanwhile; nothing where this daemon runs no walk. As
    /// [`Daemon::set_standing_interval_millis`] drives the standing line
    /// through a seam rather than a wait.
    #[doc(hidden)]
    pub fn set_feed_walk_progress_cadence(&self, boundaries: u64, millis: u64) {
        self.writes.set_feed_walk_progress_cadence(boundaries, millis);
    }

    /// TEST HOOK (the same standing): RUN THE PRUNER's PASS now, on this
    /// thread — the pass the cadence runs, under the credential lock's
    /// write arm one file at a time, ITS LINE SAID as the cadence says it
    /// (`Daemon::say_the_pass`: row 34, or row 35 where a step failed) — and
    /// answer what it did; `None` where the index is not ready and the pass
    /// did not start. A step's failure is the REPORT's (`PrunePass::failed`,
    /// the step and the cause beside the figures and the compaction's state),
    /// never a panic here: a suite reads it as the operator's line does.
    #[doc(hidden)]
    pub fn prune_now(&self) -> Option<PrunePass> {
        let pass = self.prune_pass();
        self.say_the_pass(&pass);
        pass.expect("the test seam's pass")
    }

    /// The line the pruner's hold writes on the operator stream as it
    /// parks — what the harness watches the child's stderr for before it
    /// kills.
    #[doc(hidden)]
    pub const PRUNE_HOLD_NOTICE: &'static str = skep_media::gate::MediaGate::PRUNE_HOLD_NOTICE;

    /// TEST HOOK (the same standing): HOLD THE PASS after its next rename
    /// aside — the arm released, the aside not yet unlinked, the next file's
    /// acquisition not yet taken — writing [`Daemon::PRUNE_HOLD_NOTICE`] and
    /// parking the pass's thread for good, so the dirty-crash harness can
    /// SIGKILL the process between the rename and the unlink and judge the
    /// reopen: an aside open removes. Not disarmable.
    #[doc(hidden)]
    pub fn hold_the_prune_pass_after_a_rename(&self) {
        self.media.arm_prune_hold();
    }

    /// TEST HOOK (the same standing): run the replaced files' deferred step
    /// now — what the transport runs after a blob reply — and answer how
    /// many asides it unlinked; the socket-free router runs none itself.
    #[doc(hidden)]
    pub fn retire_asides_now(&self) -> usize {
        self.media.store().unlink_asides().expect("the test seam's drain")
    }

    /// TEST HOOK (the same standing): the pruner passes this daemon has
    /// completed — the cadence's and the hook's alike — so a suite seeding
    /// files before the open waits for the cadence's first pass to end
    /// before it lapses their leases, rather than racing it.
    #[doc(hidden)]
    pub fn prune_passes_completed(&self) -> u64 {
        self.media.passes_completed()
    }

    /// The line [`Daemon::hold_blob_finish_at`]'s hold writes on the
    /// operator stream as it parks — what the harness watches the child's
    /// stderr for before it kills.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub const BLOB_HOLD_NOTICE: &'static str =
        "test seam: held inside a blob finish; kill this process";

    /// TEST HOOK (the same standing): HOLD every later finish of the blob
    /// store before the named step — writing
    /// [`Daemon::BLOB_HOLD_NOTICE`] on the operator stream and parking
    /// the request's thread for good — so the dirty-crash harness
    /// (`tests/it/hazard.rs`) can SIGKILL the process THERE and judge the
    /// reopen over exactly the directory a crash at that step leaves. Held
    /// at the deferred `UnlinkAside` step, the hold parks the TRANSPORT's
    /// thread after the reply is written, the answer already given. Not
    /// disarmable.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn hold_blob_finish_at(&self, step: skep_blobs::Step) {
        self.media.store().hold_at(step, || {
            notice::line(Self::BLOB_HOLD_NOTICE);
            loop {
                std::thread::park();
            }
        });
    }

    /// TEST HOOK (the same standing): the volume's capacity the media gate
    /// read once at the open — the default per-account limit's source — so
    /// a suite judges the deposit read's `per_account` against the same
    /// read; `None` where the host answered none.
    #[doc(hidden)]
    pub fn media_capacity(&self) -> Option<u64> {
        self.media.capacity()
    }

    /// TEST HOOK (the same standing): FAIL every later finish of the blob
    /// store at the named step with an I/O error, or `None` to fail nothing
    /// — the store's own injection (`skep-blobs`'s `fail_at`), so a suite
    /// drives a finish cut before its rename over the wire and judges the
    /// empty resume that finishes it.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn fail_blob_finish_at(&self, step: Option<skep_blobs::Step>) {
        self.media.store().fail_at(step);
    }

    /// TEST HOOK (the same standing): INSTALL a media limits record — the
    /// serving layer's channel (AUTH-4.70) in a suite's hand until that
    /// channel lands: the per-account limit, the venue's total, the lease
    /// interval (`None` keeps the daemon's default), the per-file cap
    /// (`None` is the route's own, `MAX_BLOB_BYTES`) and the record's
    /// address the deposit read echoes — the media gate's own hook, which
    /// answers the install's REFUSAL where the cap named exceeds the route's
    /// (op-D6 (a): refused as malformed, said once, the limits in force
    /// standing, never clamped), so a suite can present a record past the
    /// cap and read what the installer is answered.
    #[doc(hidden)]
    pub fn install_media_limits(
        &self,
        per_account: Option<u64>,
        venue_total: Option<u64>,
        lease_interval_ms: Option<u64>,
        per_file_cap: Option<u64>,
        address: Option<String>,
    ) -> Result<(), LimitsRefused> {
        self.media.install_limits(
            per_account,
            venue_total,
            lease_interval_ms,
            per_file_cap,
            address,
        )
    }

    /// TEST HOOK (the same standing): every line the MEDIA GATE has said
    /// through its own classed door this uptime — the floor's binding and
    /// its lift, a limits record's refusal — each `{class}: {text}`, oldest
    /// first. Said below the daemon's door, so [`Daemon::lines_said`] holds
    /// none of them; the stream itself no in-process suite reads.
    #[doc(hidden)]
    pub fn media_lines_said(&self) -> Vec<String> {
        self.media.lines_said()
    }

    /// TEST HOOK (the same standing): advance the media gate's clock by
    /// `ms` — every upload expiry and lease is judged against it — so a
    /// suite drives an expiration through a seam rather than a `sleep`.
    #[doc(hidden)]
    pub fn advance_media_clock_ms(&self, ms: u64) {
        self.media.advance_clock_ms(ms);
    }

    /// TEST HOOK (the same standing): the floor reads `bytes` as the
    /// volume's free space (`None`: the host's again), so a suite reaches
    /// the floor's refusal without filling a disk.
    #[doc(hidden)]
    pub fn set_media_free_space(&self, bytes: Option<u64>) {
        self.media.set_free_space(bytes);
    }

    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): hold one reconstruction permit exactly as an in-flight
    /// reconstruction does, or `None` when the whole budget is taken. Real
    /// reconstructions finish in milliseconds, so the integration tests pin
    /// the counter through this instead of racing the engine.
    #[doc(hidden)]
    #[must_use = "a permit dropped at once holds nothing"]
    pub fn try_hold_reconstruction_permit(&self) -> Option<Permit<'_>> {
        self.history.try_hold_permit()
    }

    /// TEST HOOK (the same standing as
    /// [`Daemon::try_hold_reconstruction_permit`]: `#[doc(hidden)]`, not a
    /// stable API): hold one CLASS-SCAN permit exactly as an in-flight class
    /// scan does, or `None` when all [`MAX_CONCURRENT_CLASS_SCANS`](super::scan::MAX_CONCURRENT_CLASS_SCANS) are
    /// taken. A real class scan over a test-sized world finishes in
    /// microseconds, so the integration tests pin the counter through this
    /// instead of racing the store. A permit from here is a slot of the scan
    /// pool alone: holding every one leaves `/op-at`, `/dump?at` and
    /// `/chain?at` untouched, which is the disjointness the wire promises.
    #[doc(hidden)]
    #[must_use = "a permit dropped at once holds nothing"]
    pub fn try_hold_scan_permit(&self) -> Option<Permit<'_>> {
        self.scans.try_hold()
    }

    /// TEST HOOK (the same standing as the two above: `#[doc(hidden)]`, not a
    /// stable API): fix the HEAD WRITER's clock at `millis`, so a test drives
    /// the published head's time bound (PUB-6.65 trigger (c)) through a seam
    /// rather than a `sleep`. The reading is WALL-CLOCK UNIX MILLISECONDS —
    /// the writer's own domain, whose hour is measured from the last head's
    /// recorded time or from open, both wall-clock — so a test sets it
    /// RELATIVE TO the wall clock: a small number is dwarfed by that origin
    /// and the time bound never fires. A fixed reading holds until changed,
    /// and every value is one — `u64::MAX` included.
    ///
    /// The head writer's reading ALONE: every commit's `time`, and so
    /// `/health`'s `head_time`, is stamped by the change feed's own reading
    /// of the wall clock, which this seam does not move.
    #[doc(hidden)]
    pub fn set_head_writer_clock_millis(&self, millis: u64) {
        self.writes.set_head_writer_clock_millis(millis);
    }

    /// The line [`Daemon::hold_between_the_claim_and_its_head`]'s hold writes
    /// on the operator stream as it parks — what the harness watches the
    /// child's stderr for before it kills. `#[doc(hidden)]` with the hook.
    #[doc(hidden)]
    pub const CLAIM_HOLD_NOTICE: &'static str =
        "test seam: held between the claim and its head; kill this process";

    /// TEST HOOK (the same standing: `#[doc(hidden)]`, not a stable API):
    /// HOLD the claim's step at the crash window — after the claim's commit
    /// is durable and the fold has flipped, before `H.1`'s first commit opens
    /// ([`Daemon::on_claim_flip`]) — writing [`Daemon::CLAIM_HOLD_NOTICE`] on
    /// the operator stream and then parking the request's thread for good,
    /// both locks held, so the dirty-crash harness (`tests/it/hazard.rs`, the
    /// kernel hazard suite's self-exec pattern) can SIGKILL the process THERE
    /// and judge the reopen ([`Daemon::write_the_claims_head_if_owed`]) over
    /// exactly the journal a crash between the two transactions leaves: the
    /// claim, and no head. A daemon so armed serves normally until a claim
    /// flips its board and cannot serve a write past that point — every
    /// later write waits on the parked locks — which is the point: it exists
    /// to be killed. Not disarmable.
    #[doc(hidden)]
    pub fn hold_between_the_claim_and_its_head(&self) {
        self.hold_between_claim_and_head.store(true, Ordering::Relaxed);
    }

    /// TEST HOOK (the same standing: `#[doc(hidden)]`, not a stable API):
    /// the HEAD WRITER'S DRIVER REFUSES THE NEXT HEAD it is due to write,
    /// once — armed before a claim, the claim's own `H.1` — handled exactly
    /// as a driver refusal is (`head.rs`, WHAT A REFUSAL DOES: surfaced once
    /// per cause with its position, the state unadvanced, the triggering
    /// write untouched), so a suite can stand a RUNNING claimed board with
    /// no board term and judge what the write path does next (l7-C1: the
    /// first head owed at every turn, a refused write's included —
    /// `tests/it/head.rs`). The refusal is injected INSIDE the driver — the
    /// first store call of the head's write answers a `durability`
    /// rejection whose `detail` is the seam's standing one, `the test
    /// seam's refusal` — so it rides row 38's whole path. Disarms itself at
    /// the one refusal it injects.
    #[doc(hidden)]
    pub fn refuse_the_next_head_once(&self) {
        self.writes.refuse_next_head_once(None);
    }

    /// TEST HOOK (the same standing): [`Daemon::refuse_the_next_head_once`]
    /// with a `detail` of the suite's own in place of the standing one — so
    /// a suite stands two DIFFERENT causes against the once-per-cause memo
    /// (`operations.md` §1.1 row 38) and judges the second said where the
    /// same cause again is not.
    #[doc(hidden)]
    pub fn refuse_the_next_head_once_as(&self, detail: &str) {
        self.writes.refuse_next_head_once(Some(detail));
    }

    /// TEST HOOK (the same standing: `#[doc(hidden)]`, not a stable API):
    /// [`Daemon::open_with`] under the SEEDED salt source
    /// (`SaltSource::Seeded(seed)`) in place of OS entropy, so two harness
    /// daemons over one op sequence write one chain and one head byte string
    /// (the head suite's determinism pin, `tests/it/head.rs`), and two seeds
    /// write two — the salt's effect pinned from the wire. NEVER a
    /// deployment's: the seeded stream is a pure function of the seed and the
    /// position, which is exactly the predictability the salt exists to deny
    /// a reader of `/chain?at=N`; `open_with` is the production door and
    /// takes no source.
    #[doc(hidden)]
    pub fn open_seeded(
        data_dir: impl AsRef<Path>,
        opts: AuthOptions,
        seed: u64,
    ) -> Result<Daemon, DaemonError> {
        Self::open_under(data_dir.as_ref(), opts, MediaOptions::default(), SaltSource::Seeded(seed))
    }

    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): what the engine's open found in the data dir — the start
    /// point, the retained checkpoints it passed over and whether a
    /// slice-less start point resolved empty — the account the open's two
    /// warnings are rendered from (`recovery_warnings`), so a suite can pin
    /// what the daemon LOGGED against the report it logged it from.
    #[doc(hidden)]
    pub fn recovery(&self) -> Option<&Recovery> {
        self.engine.recovery()
    }

    /// TEST HOOK (the same standing): take a KERNEL checkpoint now — the real
    /// one, with every consequence a checkpoint has (`Kernel::checkpoint`),
    /// on the calling thread and off the write path's guard, which is
    /// exactly what the daemon's checkpoint thread does when the cadence's
    /// flag is due (that thread adds the byte bound's and the floor's
    /// re-read and the feed's compaction, which
    /// [`Daemon::service_the_checkpoint_now`] runs). It becomes the newest
    /// retained checkpoint, which is what the head suite drives the head's
    /// trigger (b) with, without committing a whole
    /// `CHECKPOINT_EVERY_COMMITS` window; and it counts toward the two this
    /// daemon retains, reclaiming the closed journal below the oldest, so a
    /// test that takes more than two can find an old position answering
    /// `history_reclaimed`. A checkpoint this cannot take PANICS: a seam
    /// whose act failed fails its test here, and not at a later assertion
    /// about a head that never came.
    #[doc(hidden)]
    pub fn checkpoint_now(&self) {
        self.engine.kernel().checkpoint().expect("the test seam's checkpoint");
    }

    /// TEST HOOK (the same standing): what THE CHECKPOINT THREAD runs when
    /// the cadence's flag is due, on the calling thread — the checkpoint,
    /// and on a landing the byte bound and the media floor re-read from it
    /// and the change feed's five files compacted to the reclaim floor; on a
    /// failure the operator's one line — so a suite drives the thread's whole
    /// act without waiting on the thread.
    #[doc(hidden)]
    pub fn service_the_checkpoint_now(&self) {
        self.service_the_checkpoint();
    }

    /// TEST HOOK (the same standing): whether the kernel's cadence has
    /// crossed since the last checkpoint began — the due flag the thread
    /// services (`Kernel::checkpoint_due`).
    #[doc(hidden)]
    pub fn checkpoint_is_due_now(&self) -> bool {
        self.checkpoint_is_due()
    }

    /// TEST HOOK (the same standing): move the cadence's BYTE BOUND to
    /// `bytes` — `Kernel::set_cadence_bytes`, under the applier lock — so a
    /// suite makes the next commit cross the cadence without committing a
    /// window of 1024 or the bound's 24 MiB, and watches the thread service
    /// the flag. The thread re-reads the bound from the checkpoint that
    /// lands, so one crossing is what a suite buys. PANICS on zero, which
    /// the bound's type refuses.
    #[doc(hidden)]
    pub fn set_checkpoint_bytes_bound(&self, bytes: u64) {
        let bound = NonZeroU64::new(bytes).expect("the test seam's byte bound is non-zero");
        self.engine.kernel().set_cadence_bytes(bound);
    }

    /// TEST HOOK (the same standing): PARK THE CADENCE — both of its bounds,
    /// the commit count and the bytes, moved past any total a suite commits
    /// (`Kernel::set_cadence_commits`, `Kernel::set_cadence_bytes`), so no
    /// checkpoint lands on this daemon's own trigger for its life, the
    /// journal reclaims nothing and the feed's files compact nothing. For a
    /// suite whose subject is a board that must stay WHOLE from genesis —
    /// a cold mirror opened over it, a measure of the open's cost — and
    /// nothing else: `checkpoint_now` still takes a checkpoint on demand.
    /// The checkpoint thread re-reads the BYTE bound only after a landing,
    /// and none lands, so the parked bounds hold.
    #[doc(hidden)]
    pub fn park_the_cadence(&self) {
        let past_any = NonZeroU64::new(u64::MAX).expect("u64::MAX is non-zero");
        let kernel = self.engine.kernel();
        kernel.set_cadence_commits(past_any);
        kernel.set_cadence_bytes(past_any);
    }

    /// TEST HOOK (the same standing): the newest retained checkpoint's
    /// header — its seq, chain, body hash and length
    /// (`Kernel::newest_checkpoint`) — or `None` before the first, so a
    /// suite pins which checkpoint the thread landed and the size the floor
    /// and the byte bound were re-read from.
    #[doc(hidden)]
    pub fn newest_checkpoint(&self) -> Option<CheckpointHeader> {
        self.engine.kernel().newest_checkpoint()
    }

    /// TEST HOOK (the same standing): the media floor IN FORCE — the larger
    /// of the constant and twice the newest checkpoint plus one maximal
    /// segment, as the gate reads it at every creation and every chunk — so
    /// a suite pins the open's reading and the thread's re-reading of it.
    #[doc(hidden)]
    pub fn media_floor_in_force(&self) -> u64 {
        self.media.floor()
    }

    /// TEST HOOK (the same standing): FAIL THE FEED's NEXT REWRITE PAST ITS
    /// RENAME — each of the five files' next compaction rewrite refused at
    /// the reopen of the file it has just renamed into place — so a suite
    /// reaches the stop that arm carries: the file takes no further line
    /// this uptime, said once, the next open re-deriving. Disarms itself at
    /// the one rewrite it fails.
    #[doc(hidden)]
    pub fn fail_the_feeds_next_rewrite_past_rename(&self) {
        self.writes.fail_the_feeds_next_rewrite_past_rename();
    }

    /// TEST HOOK (the same standing): the feed files STOPPED this uptime —
    /// `commits.log` and the four derived files that take no further line —
    /// by name; the write path's own read carries each stop's position
    /// beside the name, which the standing line says.
    #[doc(hidden)]
    pub fn stopped_feed_files(&self) -> Vec<&'static str> {
        self.writes.stopped_feed_files().into_iter().map(|file| file.name).collect()
    }

    /// TEST HOOK (the same standing): FAIL THE NEXT `step` of the kernel's
    /// write paths with an I/O error of `kind` — the kernel's own write-fault
    /// seam (`Kernel::fail_the_next`), which serves BOTH write paths, the
    /// journal's as well as the checkpoint's, whatever this door's name says
    /// — reached through the daemon so a suite drives the checkpoint thread's
    /// failure line at each of the checkpoint's steps: `CheckpointSync`
    /// armed fails the checkpoint BEFORE its rename (no base,
    /// `CheckpointError::Io`), `CheckpointDirSync` fails the directory's
    /// sync AFTER it (a landed base, `CheckpointError::Landed`); a full
    /// volume is `io::ErrorKind::StorageFull` — and the kernel's halt at the
    /// journal's: `JournalBarrier` armed fails a commit's barrier,
    /// `JournalRepair` armed beside it fails the truncation that repairs it,
    /// which POISONS the kernel (`TxnError::Poisoned`, the write answered
    /// `poisoned`). ONCE: the arm fires and disarms; arming a step again
    /// replaces its arm.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn fail_the_next_checkpoint_step(&self, step: Step, kind: std::io::ErrorKind) {
        self.engine.kernel().fail_the_next(step, kind);
    }

    /// TEST HOOK (the same standing): PANIC at the next `step` of the
    /// kernel's write paths — the seam's panic arm (`Kernel::panic_at_the_next`),
    /// beside the failure arm above: the checkpoint write's three steps, or
    /// `JournalAppend`, the unwind out of the commit region the kernel's
    /// guard repairs, whose repair `JournalRepair` armed to fail then fails
    /// — the kernel poisoned and the panic re-raised, so the write answers
    /// `500 internal_panic` at the transport's catch, where the kernel's
    /// halt line is read. The barrier and the repair take no panic arm, and
    /// naming one PANICS here as the kernel's door does. ONCE, as the
    /// failure arm is.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn panic_at_the_next_kernel_step(&self, step: Step) {
        self.engine.kernel().panic_at_the_next(step);
    }

    /// TEST HOOK (the same standing): how many checkpoints the kernel has run
    /// INLINE on a committing thread this uptime (`Kernel::inline_checkpoints`)
    /// — under the daemon's deferred cadence, the backstop's runs alone — as
    /// the daemon reads it beside the due flag after every commit.
    #[doc(hidden)]
    pub fn inline_checkpoints(&self) -> u64 {
        self.engine.kernel().inline_checkpoints()
    }

    /// TEST HOOK (the same standing): how the LAST inline checkpoint failed,
    /// as the kernel rendered it (`Kernel::last_inline_checkpoint_failure`),
    /// or `None` where it landed or none has run — what the backstop's line
    /// carries after "the last".
    #[doc(hidden)]
    pub fn last_inline_checkpoint_failure(&self) -> Option<String> {
        self.engine.kernel().last_inline_checkpoint_failure()
    }

    /// TEST HOOK (the same standing): the journal bytes the LAST landed
    /// checkpoint reclaimed (`Kernel::last_reclaimed_bytes`) — `Some(0)` for a
    /// landing that reclaimed nothing, `None` before any landing this uptime
    /// — the figure line 25 carries as "{r} journal bytes reclaimed".
    #[doc(hidden)]
    pub fn last_reclaimed_bytes(&self) -> Option<u64> {
        self.engine.kernel().last_reclaimed_bytes()
    }

    /// TEST HOOK (the same standing): every line the checkpoint thread's arms
    /// have rendered this uptime, oldest first, each as `{class}: {text}` —
    /// the landing (line 25), the failure (line 26) and the backstop's line
    /// (m13) with the class word each was emitted under — so a suite pins
    /// the words and the class of what went to the operator stream, which no
    /// suite captures in-process. The whole act is the thread's or
    /// [`Daemon::service_the_checkpoint_now`]'s; this is its record.
    #[doc(hidden)]
    pub fn checkpoint_lines(&self) -> Vec<String> {
        self.checkpointer.lines.lock().clone()
    }

    /// TEST HOOK (the same standing): every line this daemon has said
    /// through its own classed door this uptime, oldest first, each as
    /// `{class}: {text}` — a notice of several lines kept whole, the head
    /// then each line of the rest on a line of its own — the configuration
    /// warnings at both their moments, the open's-report `auth:` line, the
    /// node prefix, the blocked list at its three moments, the claim's flip
    /// line and a reissue's refusal among them; and the standing line
    /// (`standing:`), the kernel's halt line, the full volume's line, the
    /// feed files' lines — a cut, the unreadable slots and the malformed
    /// names at their open, a stop past a rename while serving — and the
    /// two thread catches' consequence lines (`failure:`) — so a suite pins
    /// the words and the class of what went to the operator stream, which
    /// no suite captures in-process. The open's own lines (said before the
    /// write path exists) and the checkpoint thread's own landing, failure
    /// and backstop lines ([`Daemon::checkpoint_lines`]) are not among them.
    #[doc(hidden)]
    pub fn lines_said(&self) -> Vec<String> {
        self.said.lock().clone()
    }

    /// TEST HOOK (the same standing): the daemon's HIGH-WATER of its own
    /// resident set — the largest reading it has taken, one per landing and
    /// per backstop wake — or `None` before the first reading; the figure
    /// line 25 carries as "peaked at", so a suite pins the line's figure
    /// against the daemon's and its monotonicity across landings.
    #[doc(hidden)]
    pub fn resident_set_peak(&self) -> Option<u64> {
        match self.checkpointer.resident_peak.load(Ordering::Acquire) {
            0 => None,
            peak => Some(peak),
        }
    }

    /// TEST HOOK (the same standing): move the MEDIA FLOOR in force to
    /// `bytes` (`MediaGate::set_floor`) — the floor's twin of
    /// [`Daemon::set_checkpoint_bytes_bound`] — so a suite pins that the
    /// thread's re-read after a landing it did not take itself (a backstop's,
    /// a base that landed before its run failed) restores the floor the
    /// newest checkpoint sizes: a small board's checkpoint sizes the floor at
    /// its constant, which a suite cannot otherwise tell from "not re-read".
    #[doc(hidden)]
    pub fn set_media_floor(&self, bytes: u64) {
        self.media.set_floor(bytes);
    }

    /// TEST HOOK (the same standing): HOLD THE CHECKPOINT THREAD — from the
    /// top of its next loop, before it looks at the kernel's due flag, until
    /// [`Daemon::release_the_checkpoint_thread`] — so a suite lands a second
    /// crossing while the first's flag still stands and the kernel's
    /// backstop runs that checkpoint inline on the committing thread,
    /// deterministically and with no race against the thread, which on its
    /// release finds no flag and takes the backstop's wake arm. A held thread
    /// parks between landings and holds no lock. Released by the stop too,
    /// so a shutdown under the hold joins.
    #[doc(hidden)]
    pub fn hold_the_checkpoint_thread(&self) {
        *self.checkpointer.hold.held.lock() = true;
    }

    /// TEST HOOK (the same standing): release the held checkpoint thread, and
    /// hold it at no later loop.
    #[doc(hidden)]
    pub fn release_the_checkpoint_thread(&self) {
        let hold = &self.checkpointer.hold;
        *hold.held.lock() = false;
        hold.released.notify_all();
    }

    /// The thread's side of the hold: park here while it is armed and no
    /// stop has been asked — `listen.rs`'s loop calls it at the top of each
    /// pass. Timed waits, so the stop reaches a thread held when it comes.
    pub(crate) fn wait_while_the_checkpoint_thread_is_held(&self, stopped: impl Fn() -> bool) {
        let hold = &self.checkpointer.hold;
        let mut held = hold.held.lock();
        while *held && !stopped() {
            hold.released.wait_for(&mut held, Duration::from_millis(50));
        }
    }

    /// TEST HOOK (the same standing: `#[doc(hidden)]`, not a stable API):
    /// the MARKER SLOT of the transaction that committed the boundary `at` —
    /// `Kernel::attestation_at` on the daemon's own kernel, and a [`Seq`] as
    /// that read and [`Daemon::world_at`] take one — so a suite can pin WHICH
    /// commits' marker slots the write-path check filled and which stayed
    /// empty (signed ops), against the journal itself rather than the feed:
    /// `/changes` serves the slot as the row's `attest` member off the
    /// attest store (`feed-attest.log`), which mirrors the marker at commit
    /// and is rebuilt above the reclaim floor from the one-scan list
    /// `Kernel::boundaries_above`, which answers at each boundary what this
    /// read answers there (the design record §7.3 (i)) — so the two are one
    /// value where both answer, and this read is what a suite compares the
    /// served member against.
    #[doc(hidden)]
    pub fn attestation_at(&self, at: Seq) -> Result<Option<Attestation>, HistoryError> {
        self.engine.kernel().attestation_at(at)
    }

    /// TEST HOOK (the same standing): THE BASES THE DAEMON's KERNEL HAS
    /// LOADED for its history reads since the open — `Kernel::bases_loaded`
    /// on the daemon's own kernel, one per base a read selected, a
    /// checkpoint's whole body decoded or genesis seeded — so a suite pins
    /// what a reopen COSTS in bases rather than in seconds: the attest
    /// store's rebuild (`feed-attest.log`) lists every boundary above its
    /// fence in ONE scan from one base (the operations design §3.3 step 2),
    /// where a read per position loaded a base per position — one whole
    /// checkpoint decoded per commit since the last open. The open's own
    /// reads load bases too (the feed's floor probe among them), so a suite
    /// reads this after two opens of one board and pins the DIFFERENCE,
    /// never an absolute.
    #[doc(hidden)]
    pub fn bases_loaded(&self) -> u64 {
        self.engine.kernel().bases_loaded()
    }

    /// TEST HOOK (the same standing: `#[doc(hidden)]`, not a stable API):
    /// the position through which the ATTEST STORE's file was last SYNCED —
    /// the coverage its last successful `sync_data` made durable — so a
    /// suite can pin that each attested commit's line is on disk before the
    /// next commit begins (SO-I5 (d)), which no kill can show: a killed
    /// process loses nothing the OS already holds.
    #[doc(hidden)]
    pub fn attest_store_synced_through(&self) -> u64 {
        self.writes.attest_store_synced_through()
    }

    /// TEST HOOK (the same standing): FAIL THE ATTEST STORE'S NEXT WRITE —
    /// its file's handle swapped for a read-only one, so the next line's
    /// write fails at the OS — answered as every store failure is (SO-I5
    /// (d)): that commit acked, every later write refused `poisoned` until a
    /// restart, whose open rebuilds the line from the journal. A seam whose
    /// act failed PANICS here. Not disarmable.
    #[doc(hidden)]
    pub fn fail_the_attest_stores_next_write(&self) {
        self.writes.fail_the_attest_stores_next_write();
    }
}
