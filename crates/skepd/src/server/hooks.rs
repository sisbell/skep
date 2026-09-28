//! The seven test hooks and `CLAIM_HOLD_NOTICE` (`#[doc(hidden)]` items of `Daemon`).

use std::path::Path;
use std::sync::atomic::Ordering;

use skep_engine::HistoryError;
use skep_kernel::{Attestation, SaltSource, Seq};

use super::{Daemon, DaemonError};
use crate::auth::AuthOptions;
use crate::permits::Permit;

impl Daemon {
    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): hold one reconstruction permit exactly as an in-flight
    /// reconstruction does, or `None` when the whole budget is taken. Real
    /// reconstructions finish in milliseconds, so the integration tests pin
    /// the counter through this instead of racing the engine.
    #[doc(hidden)]
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
    /// empty (signed ops), `/changes` carrying no `attest` member yet (the
    /// design record §7.3 (i), owed).
    #[doc(hidden)]
    pub fn attestation_at(&self, at: Seq) -> Result<Option<Attestation>, HistoryError> {
        self.engine.kernel().attestation_at(at)
    }
}
