//! The test hooks and `CLAIM_HOLD_NOTICE` (`#[doc(hidden)]` items of `Daemon`).

use std::path::Path;
use std::sync::atomic::Ordering;

use skep_engine::HistoryError;
use skep_kernel::{Attestation, SaltSource, Seq};

use super::{Daemon, DaemonError};
use crate::auth::AuthOptions;
use crate::media::index::{Rebuild, WALK_HOLD};
use crate::media::pruner::PrunePass;
use crate::permits::Permit;

impl Daemon {
    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): whether the cell index's walk at open has completed —
    /// what a suite waits on before its first PUT, rather than racing the
    /// walk's thread.
    #[doc(hidden)]
    pub fn index_is_ready(&self) -> bool {
        self.media.index_ready()
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

    /// TEST HOOK (the same standing): RUN THE PRUNER's PASS now, on this
    /// thread — the pass the cadence runs, under the credential lock's
    /// write arm one file at a time — and answer what it did; `None` where
    /// the index is not ready and the pass did not start. A pass that
    /// cannot read or unlink PANICS here: a seam whose act failed fails its
    /// test here, not at a later assertion.
    #[doc(hidden)]
    pub fn prune_now(&self) -> Option<PrunePass> {
        self.prune_pass().expect("the test seam's pass")
    }

    /// The line the pruner's hold writes on the operator stream as it
    /// parks — what the harness watches the child's stderr for before it
    /// kills.
    #[doc(hidden)]
    pub const PRUNE_HOLD_NOTICE: &'static str = crate::media::gate::MediaGate::PRUNE_HOLD_NOTICE;

    /// TEST HOOK (the same standing): HOLD THE PASS after its next unlink —
    /// the arm released, the next file's acquisition not yet taken — writing
    /// [`Daemon::PRUNE_HOLD_NOTICE`] and parking the pass's thread for good,
    /// so the dirty-crash harness can SIGKILL the process between an unlink
    /// and the next acquisition and judge the reopen. Not disarmable.
    #[doc(hidden)]
    pub fn hold_the_prune_pass_after_an_unlink(&self) {
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
    /// as a driver refusal is (`head.rs`, WHAT A REFUSAL DOES: surfaced, the
    /// state unadvanced, the triggering write untouched), so a suite can
    /// stand a RUNNING claimed board with no board term and judge what the
    /// write path does next (l7-C1: the first head owed at every turn, a
    /// refused write's included — `tests/it/head.rs`). Disarms itself at the
    /// one refusal it injects.
    #[doc(hidden)]
    pub fn refuse_the_next_head_once(&self) {
        self.writes.refuse_next_head_once();
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
        Self::open_under(data_dir.as_ref(), opts, SaltSource::Seeded(seed))
    }

    /// TEST HOOK (the same standing): take a KERNEL checkpoint now — the real
    /// one, with every consequence a checkpoint has (`Kernel::checkpoint`).
    /// It becomes the newest retained checkpoint, which is what the head
    /// suite drives the head's trigger (b) with, without committing a whole
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

    /// TEST HOOK (the same standing: `#[doc(hidden)]`, not a stable API):
    /// the MARKER SLOT of the transaction that committed the boundary `at` —
    /// `Kernel::attestation_at` on the daemon's own kernel, and a [`Seq`] as
    /// that read and [`Daemon::world_at`] take one — so a suite can pin WHICH
    /// commits' marker slots the write-path check filled and which stayed
    /// empty (signed ops), against the journal itself rather than the feed:
    /// `/changes` serves the slot as the row's `attest` member off the
    /// attest store (`feed-attest.log`), which mirrors the marker at commit
    /// and is rebuilt from this very read above the reclaim floor (the
    /// design record §7.3 (i)) — so the two are one value where both answer,
    /// and this read is what a suite compares the served member against.
    #[doc(hidden)]
    pub fn attestation_at(&self, at: Seq) -> Result<Option<Attestation>, HistoryError> {
        self.engine.kernel().attestation_at(at)
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
