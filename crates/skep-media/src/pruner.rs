//! THE PRUNER (`media.md` Op inventory 1 — "Unreferenced blobs … are
//! prunable sidecar garbage … pruning checks reference absence, in the cell
//! index … ONLY UNDER THE DESIGNATIONS THIS BUILD's SCHEMAS PIN, a value
//! naming the cell's kind that parses under no schema this build knows
//! HALTING THE PRUNER's UNLINK OF AN UNREFERENCED FILE"; Op inventory 2 —
//! "the PRUNER TAKES A FILE's NAME ONLY UNDER THE GATE's EXCLUSIVE ARM,
//! `gate.write()` [the record's `gate` here is the credential write lock,
//! AUTH-3.1–3.3's write gate, whose write arm this pass is handed as
//! `exclusive` — never the media gate whose store and index it reads],
//! re-reading the cell index and the lease there, ONE FILE PER ACQUISITION
//! — re-read, rename aside, release, the aside unlinked after under no
//! arm"; §The media stores — "the pruner's pass rewrites either store the
//! same way once its log has passed a size trigger"; the register M-I5 (b),
//! (f); the rulings ms5-R, ms5-T4 — D13's carve-out): THE PASS, run once
//! the index is ready and then on a cadence (the daemon's
//! `PRUNE_INTERVAL`, the transport's thread waiting it out).
//!
//! Each pass, in order: (a) THE EXPIRED PARTIALS — every upload record past
//! its expiry and held by no stream is retired and its partial removed,
//! off the store's own read of expiry and the media gate's hold, reading no
//! reference; (b) THE HALTS — a designation directory under `blobs/`
//! outside the pinned set, or a halt mark standing in the index, halts the
//! unlink pass before its first unlink, with one operator line naming the
//! directory or the schema; (c) THE UNREFERENCED FILES — for each file at a
//! hex name under the pinned designation, under the credential lock's
//! EXCLUSIVE ARM taken for that one file: the index re-read (no cell names
//! the hash, and no halt mark stands), the lease log re-read (no key holds
//! a live lease on it), the file RENAMED ASIDE to `.retired-<hex>-<n>` —
//! the REPLACE's own aside name — the arm released; and the aside UNLINKED
//! AFTER, under no arm, which is where the file's blocks are freed. A file
//! a cell names or any live lease holds is KEPT (M-I5 (b): no housekeeping
//! act creates a hole — the re-read and the rename are one interval under
//! the arm, and a crash between the rename and the unlink leaves an aside
//! open removes); the arm is held one re-read and one rename, never across
//! an unlink (M-I5 (f): a retirement never queues behind a drain's I/O —
//! at the per-file cap an unlink held every write on the board for the
//! freeing's time); a replace's aside the deferred step did not reach is
//! removed at the pass's end, as before. Then (d) THE LOGS' COMPACTION —
//! the lease log's leases past the horizon dropped first, as the store's
//! open drops them, then each of the two logs rewritten to its current
//! records where its lines have passed
//! [`crate::limits::COMPACTION_TRIGGER`] times those records
//! (never under [`crate::limits::COMPACTION_MIN_LINES`]), under the store's
//! own lock on that log's appends alone and NO arm of the credential lock
//! (P22: the honest-null arm compacted by its reclaimer); a log that has
//! STOPPED — an append whose cut back to its last whole line failed too, or
//! a compaction that failed past its rename — takes no append until a
//! compaction completes, and the pass's line names it WITH ITS CAUSE, the
//! OS's own (a full volume told apart from a read-only mount or a failing
//! device, so the act that clears it is the one named), how long it has
//! stood and the appends it has refused, and names a stop the pass's own
//! rewrite lifted as it stood. Every pass's line says each log's size, and
//! what a compaction rewrote it from, and the bytes the pass's removals
//! freed. The pass never touches a partial whose upload stands, and reads
//! no directory's bytes as a scope (M-I6: the scopes stay record-derived).
//!
//! THE PASS's EXIT (`operations.md` §4 row 5; §1.1 row 35): steps (a)–(c)
//! run collecting the FIRST error a store call answers — the step it came
//! from named, that step's loop stopped there and the steps after it
//! skipped, as the `?` that once ended the pass skipped them — and step (d)
//! runs on EVERY exit, the halt arm's included. The pass answers the error
//! BESIDE its report ([`PrunePass::failed`]), never in place of it, so the
//! compaction that lifts a stopped log runs whatever failed before it: the
//! retirement a stopped `uploads.log` refuses at (a) was the very failure
//! that, ending the pass before (d), left the stop standing for the uptime
//! and the restart its one cure; now the same pass's (d) lifts it. The halt
//! is the report's too — line 34 carries it, its reason and the expired
//! partials removed, hourly (§1.1 row 36 RETIRED: the pass writes no
//! standalone line of its own).
//!
//! THE ARM IS THE SESSION LAYER's and is handed in: this module sits
//! beside the write path and names nothing above it, so the pass takes the
//! acquisition as a closure and holds whatever guard it answers for
//! exactly one file.
//!
//! THE PRUNER ([`Pruner`]) is the pass as one daemon runs it, beside that
//! daemon's media gate: the gate holds the store and the index the pass
//! reads, and the pruner what is the pass's own — under the test seam its
//! hold and its count, and nothing outside it.

use std::fmt;
use std::io;
#[cfg(any(test, feature = "test-hooks"))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::{Condvar, Mutex};
use skep_blobs::{LogSize, LogStop, Store};
#[cfg(any(test, feature = "test-hooks"))]
use skep_util::notice::{self, Class};

use crate::cell::PINNED_DESIGNATIONS;
use crate::gate::MediaGate;
use crate::limits::{COMPACTION_MIN_LINES, COMPACTION_TRIGGER};

/// What one pass did — the test hook's answer, and, rendered through its
/// [`fmt::Display`], the operator's line 34 (`operations.md` §1.1 row 34);
/// where a step failed, the failure stands beside the figures
/// ([`PrunePass::failed`]) and the daemon's loop renders line 35 from both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrunePass {
    /// Expired uploads retired, their partials removed.
    pub expired_partials: usize,
    /// Files at hex names taken — renamed aside under the arm and unlinked
    /// after it.
    pub unlinked: usize,
    /// Files at hex names kept — named by a cell or held by a live lease.
    pub kept: usize,
    /// Asides removed at the pass's end — the deferred step's leftovers,
    /// and a pass's own aside a crash left behind.
    pub asides: usize,
    /// THE BYTES THE PASS FREED — what it reclaimed, a landing line's figure
    /// (`operations.md` §1, RULED 2026-10-07, set 1): each removal's as the
    /// store answers it (`Store::remove_aside`, `Store::expire_upload`), a
    /// file's length where its unlink took its last name and nothing where
    /// another name still holds it — so a pass that unlinked files and freed
    /// nothing, a hard-link backup holding the volume full, says so.
    pub freed: u64,
    /// Why the unlink pass halted before its first unlink, if it did — the
    /// operator line's reason, naming the directory or the schema.
    pub halted: Option<String>,
    /// The logs this pass COMPACTED — `(uploads, leases)`, each by the size
    /// it was rewritten from (`Store::compact_logs_if_past`), `None` where
    /// the pass left it as it was.
    pub compacted: (Option<LogSize>, Option<LogSize>),
    /// Each log's size once the pass is done — `(uploads, leases)`
    /// (`Store::log_sizes`): its whole lines and their bytes, said at every
    /// pass, the room the next rewrite of each needs being a second copy of
    /// it, and each log named by it on the line.
    pub logs: (LogSize, LogSize),
    /// Why a compaction failed, if one did — the operator line's reason;
    /// the logs then stopped are named beside it.
    pub compaction_failed: Option<String>,
    /// The logs STOPPED after this pass — `(uploads, leases)`, each its stop
    /// as the store keeps it (`Store::stopped_logs`: the cause, the stop's
    /// age, the appends refused since), `None` where the log takes appends:
    /// each takes no append until a compaction completes.
    pub stopped: (Option<LogStop>, Option<LogStop>),
    /// The stops this pass's compaction LIFTED — `(uploads, leases)`, each
    /// as it stood before the rewrite: a log stopped before the rewrite and
    /// taking appends after it.
    pub lifted: (Option<LogStop>, Option<LogStop>),
    /// THE FIRST FAILURE of steps (a)–(c), if one (`operations.md` §4 row
    /// 5; §1.1 row 35): the step it came from and the cause the store
    /// answered. The steps after it did not run — as the `?` that once
    /// ended the pass skipped them — and step (d) ran regardless, so a stop
    /// this pass met is lifted by its own compaction and not a restart's.
    /// Line 35's `{e}`, said beside [`PrunePass::compaction`]; `None` is
    /// line 34.
    pub failed: Option<PassFailure>,
}

/// The first failure of a pass's steps (a)–(c): the step and the cause the
/// store answered — line 35's `{e}`, `{step}: {cause}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassFailure {
    /// The step the store call failed in.
    pub step: PassStep,
    /// The I/O error's text, as the store spelled it.
    pub cause: String,
}

impl fmt::Display for PassFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.step, self.cause)
    }
}

/// The steps of a pass a store call can fail in — (a), (b) and (c); (d),
/// the compaction, answers its failure as the report's own
/// (`compaction_failed`) and never ends the pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassStep {
    /// (a) THE EXPIRED PARTIALS: a partial's removal or its record's
    /// retirement — the retirement an append `uploads.log` refuses while
    /// it has stopped.
    ExpiredPartials,
    /// (b) THE HALTS' READ: the designation directories under `blobs/`.
    Halts,
    /// (c) THE UNREFERENCED FILES: a listing, a rename aside, an unlink.
    UnreferencedFiles,
}

impl fmt::Display for PassStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PassStep::ExpiredPartials => "step (a), the expired partials",
            PassStep::Halts => "step (b), the halts' read",
            PassStep::UnreferencedFiles => "step (c), the unreferenced files",
        })
    }
}

impl PassStep {
    /// This step's failure for `cause` — what the step's `?` arms map a
    /// store's error to.
    fn failed(self) -> impl Fn(io::Error) -> PassFailure {
        move |e| PassFailure { step: self, cause: e.to_string() }
    }
}

impl PrunePass {
    /// THE COMPACTION HALF of the pass's line — each log by its name within
    /// the data directory, as every other blob-store line names it, with its
    /// size: `; blobs/uploads.log {n} lines ({b} bytes)`, and where this
    /// pass rewrote it ` — compacted from {n} lines ({b} bytes)`; then `;
    /// {log}'s stop lifted, rewritten whole after {stop}`, `; a compaction
    /// FAILED: {why}` and `; STOPPED: {log} takes no append until a
    /// compaction completes — {stop}`, each where it applies — what line 34
    /// ends with and line 35 carries after the failure, so the
    /// stopped-or-compacted half is one rendering on both (`operations.md`
    /// §1.1 row 35: "names the failure AND the stopped logs"). A stop is
    /// said with its cause, the act that clears it turning on that cause —
    /// room on a full volume, the mount or the device where they refuse —
    /// how long it has stood and the appends it has refused: `{cause};
    /// stopped {ms} ms, {n} appends refused`. Every figure is said with a
    /// fixed label, `{n} lines` as `{n} files unlinked`, so one search finds
    /// each whatever its count.
    pub fn compaction(&self) -> impl fmt::Display + '_ {
        Compaction(self)
    }
}

/// [`PrunePass::compaction`]'s rendering.
struct Compaction<'a>(&'a PrunePass);

impl fmt::Display for Compaction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pass = self.0;
        let logs = [&pass.logs.0, &pass.logs.1];
        for (size, from) in logs.into_iter().zip([&pass.compacted.0, &pass.compacted.1]) {
            write!(f, "; {} {} lines ({} bytes)", size.name, size.lines, size.bytes)?;
            if let Some(from) = from {
                write!(f, " — compacted from {} lines ({} bytes)", from.lines, from.bytes)?;
            }
        }
        for (size, stop) in logs.into_iter().zip([&pass.lifted.0, &pass.lifted.1]) {
            if let Some(stop) = stop {
                write!(f, "; {}'s stop lifted, rewritten whole after {}", size.name, Stop(stop))?;
            }
        }
        if let Some(why) = &pass.compaction_failed {
            write!(f, "; a compaction FAILED: {why}")?;
        }
        for (size, stop) in logs.into_iter().zip([&pass.stopped.0, &pass.stopped.1]) {
            if let Some(stop) = stop {
                write!(
                    f,
                    "; STOPPED: {} takes no append until a compaction completes — {}",
                    size.name,
                    Stop(stop)
                )?;
            }
        }
        Ok(())
    }
}

/// A log's stop as the pass's line says it: `{cause}; stopped {ms} ms, {n}
/// appends refused` — the cause in the store's words, how long the stop has
/// stood (a duration in milliseconds, `operations.md` §1), and the appends
/// it has refused, the uploads it cost.
struct Stop<'a>(&'a LogStop);

impl fmt::Display for Stop<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stop = self.0;
        write!(
            f,
            "{}; stopped {} ms, {} appends refused",
            stop.cause,
            stop.age.as_millis(),
            stop.refused
        )
    }
}

/// The operator's line 34 for this pass — its figures and the bytes they
/// freed, the halt, each log's size, the compaction and any stopped log —
/// written to the formatter as it is composed, so the classed door that
/// carries it (`skep_util::notice::emit`, through the daemon's `say`) builds
/// no string of its own. The failure, if one, is not here: line 35 is the
/// daemon's rendering of [`PrunePass::failed`] beside
/// [`PrunePass::compaction`].
impl fmt::Display for PrunePass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pruner: {} expired partials removed, {} files unlinked, {} kept, {} asides removed, \
             {} bytes freed",
            self.expired_partials, self.unlinked, self.kept, self.asides, self.freed
        )?;
        if let Some(why) = &self.halted {
            write!(f, " — the unlink pass halted: {why}")?;
        }
        fmt::Display::fmt(&self.compaction(), f)
    }
}

/// THE PRUNER — the pass as one daemon runs it ([`Pruner::pass`]), one per
/// daemon beside its media gate. The pass reads the gate's store and index
/// and the exclusive arm it is handed; what is the pass's own stands here —
/// under the test seam, the hold the dirty-crash harness parks a pass in
/// between a rename aside and its unlink, and the count of passes completed
/// a suite waits on; outside the seam, nothing.
#[derive(Default)]
pub struct Pruner {
    /// The test seam's hold inside the pass, after a rename aside.
    #[cfg(any(test, feature = "test-hooks"))]
    hold: AtomicBool,
    /// The test seam's count of passes completed — a suite waits for the
    /// cadence's first pass before it moves the clock.
    #[cfg(any(test, feature = "test-hooks"))]
    passes_completed: AtomicU64,
}

impl Pruner {
    /// A pruner that has run no pass — its hold unarmed and its count
    /// nought, under the test seam.
    pub fn new() -> Pruner {
        Pruner::default()
    }

    /// ONE PASS over the media gate's store and index (`media_gate`),
    /// `exclusive` the acquisition of the credential lock's write arm —
    /// called once per file, its guard held across that file's re-read and
    /// rename aside and dropped before the aside's unlink and before the
    /// next. `None` where the index is not ready: the pass does not start
    /// (ms5-R).
    ///
    /// THE EXIT RULE (the module's card): steps (a)–(c) run to their first
    /// store failure or the halt (`steps`), step (d) runs on EVERY exit, and
    /// the answer is the report — a step's failure is its `failed` member,
    /// beside the figures and the compaction's state, so no pass answers a
    /// failure that skipped its compaction.
    pub fn pass<G>(&self, media_gate: &MediaGate, exclusive: impl Fn() -> G) -> Option<PrunePass> {
        if !media_gate.index().is_ready() {
            return None;
        }
        let mut report = PrunePass {
            expired_partials: 0,
            unlinked: 0,
            kept: 0,
            asides: 0,
            freed: 0,
            halted: None,
            compacted: (None, None),
            // Read again at (d)'s end, the sizes the line says.
            logs: media_gate.store().log_sizes(),
            compaction_failed: None,
            stopped: (None, None),
            lifted: (None, None),
            failed: None,
        };
        // (a)–(c), to the first failure or the halt; the error kept beside
        // the figures, the steps after it skipped.
        report.failed = self.steps(media_gate, &exclusive, &mut report).err();
        // (d) THE LOGS' COMPACTION, under no arm — on EVERY exit: the stop a
        // failed step may have met is lifted here, by this pass.
        compact_logs(media_gate.store(), media_gate.now_ms(), &mut report);
        #[cfg(any(test, feature = "test-hooks"))]
        self.passes_completed.fetch_add(1, Ordering::Release);
        Some(report)
    }

    /// The line the pruner's hold writes on the operator stream as it
    /// parks — what the dirty-crash harness watches for before it kills.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub const PRUNE_HOLD_NOTICE: &'static str =
        "test seam: held inside the pruner's pass after a rename aside; kill this process";

    /// TEST SEAM: arm the hold inside this pruner's pass — after the next
    /// rename aside, the arm released and the aside not yet unlinked, the
    /// pass writes [`Pruner::PRUNE_HOLD_NOTICE`] and parks its thread for
    /// good. Not disarmable.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn arm_prune_hold(&self) {
        self.hold.store(true, Ordering::Relaxed);
    }

    /// The pass's side of the seam: park here where the hold is armed.
    #[cfg(any(test, feature = "test-hooks"))]
    fn hold_after_rename_if_armed(&self) {
        if self.hold.load(Ordering::Relaxed) {
            notice::emit(Class::Failure, Self::PRUNE_HOLD_NOTICE);
            loop {
                std::thread::park();
            }
        }
    }

    /// TEST SEAM: the passes this pruner has completed so far — the
    /// cadence's and a hook's alike; a pass that did not start counts none.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn passes_completed(&self) -> u64 {
        self.passes_completed.load(Ordering::Acquire)
    }

    /// Steps (a)–(c) of the pass, to the FIRST store failure — answered as
    /// the step and its cause, that step's loop stopped there and the steps
    /// after it not run — or the halt, which ends them after (b) with the
    /// report's `halted` set and nothing unlinked. The figures land in
    /// `report` as each act completes, so a failure's report still counts
    /// what ran before it.
    fn steps<G>(
        &self,
        media_gate: &MediaGate,
        exclusive: &impl Fn() -> G,
        report: &mut PrunePass,
    ) -> Result<(), PassFailure> {
        let store = media_gate.store();
        let index = media_gate.index();
        let now = media_gate.now_ms();

        // (a) THE EXPIRED PARTIALS — the store's own read of expiry, the media
        // gate's hold; no reference read, no arm. The retirement is an append:
        // a stopped `uploads.log` refuses it, and the failure is this step's.
        for record in store.expired_uploads(now) {
            // A stream holds it: left to that stream's end.
            let Some(_hold) = media_gate.claim(record.id) else { continue };
            if let Some(freed) =
                store.expire_upload(&record.id, now).map_err(PassStep::ExpiredPartials.failed())?
            {
                report.expired_partials += 1;
                report.freed += freed;
            }
        }

        // (b) THE HALTS, before the first unlink.
        let halt = {
            let foreign = store
                .designation_dirs()
                .map_err(PassStep::Halts.failed())?
                .into_iter()
                .find(|name| !PINNED_DESIGNATIONS.contains(&name.as_str()));
            match (foreign, index.first_halt()) {
                (Some(dir), _) => Some(format!(
                    "a designation directory blobs/{dir}/ is outside the set this build pins ({}): a sidecar of another build's schema",
                    PINNED_DESIGNATIONS.join(", ")
                )),
                (None, Some(mark)) => Some(format!(
                    "a value at {} names the kind {} under no schema this build reads ({})",
                    mark.at, mark.kind, mark.fault
                )),
                (None, None) => None,
            }
        };
        if let Some(reason) = halt {
            // The report carries the halt; line 34 says it (row 36 RETIRED: no
            // standalone line here).
            report.halted = Some(reason);
            return Ok(());
        }

        // (c) THE UNREFERENCED FILES, one per acquisition, under the pinned
        // designations alone.
        let failed = PassStep::UnreferencedFiles.failed();
        for designation in PINNED_DESIGNATIONS {
            for hex in store.blobs_of(designation).map_err(&failed)? {
                let aside = {
                    let _arm = exclusive();
                    // THE RE-READ under the arm: a cell committed since the
                    // listing, a halt mark entered since, a lease taken since.
                    let referenced = index.referenced(designation, &hex)
                        || index.first_halt().is_some()
                        || store.any_live_lease(designation, &hex, media_gate.now_ms());
                    if referenced {
                        report.kept += 1;
                        None
                    } else {
                        // THE RENAME ASIDE, the arm's one act: the name is taken
                        // here and the blocks freed below, the arm released.
                        store.rename_aside(designation, &hex).map_err(&failed)?
                    }
                };
                let Some(aside) = aside else { continue };
                report.unlinked += 1;
                // The arm released, the aside not yet unlinked: the dirty-crash
                // harness's seam — a crash here leaves an aside open removes.
                #[cfg(any(test, feature = "test-hooks"))]
                self.hold_after_rename_if_armed();
                // THE UNLINK AFTER, under no arm: the freeing's cost lands on
                // this thread alone, and what it freed on the line.
                report.freed +=
                    store.remove_aside(designation, &aside).map_err(&failed)?.unwrap_or(0);
            }
            for aside in store.asides_of(designation).map_err(&failed)? {
                let _arm = exclusive();
                if let Some(freed) = store.remove_aside(designation, &aside).map_err(&failed)? {
                    report.asides += 1;
                    report.freed += freed;
                }
            }
        }
        Ok(())
    }
}

/// (d) THE LOGS' COMPACTION at `now_ms`, the media gate's clock: the lease
/// log's leases past the horizon dropped first, as the store's open drops
/// them, then each log rewritten where it has passed the trigger — or has
/// STOPPED, whatever its count — under the store's lock on that log's
/// appends alone — no arm of the credential lock is held here — and the
/// stopped logs read before and after it: a stop standing before the
/// rewrite and gone after it is one this pass LIFTED, said as it stood.
/// Then each log's size, the line's figure. Run on EVERY exit of the pass, a
/// failed step's included. A failure here is the report's and never the
/// pass's: the next pass tries again, and a stopped log is rewritten then
/// whatever its count.
fn compact_logs(store: &Store, now_ms: u64, report: &mut PrunePass) {
    let before = store.stopped_logs();
    match store.compact_logs_if_past(COMPACTION_TRIGGER, COMPACTION_MIN_LINES, now_ms) {
        Ok(compacted) => report.compacted = compacted,
        Err(e) => report.compaction_failed = Some(e.to_string()),
    }
    report.stopped = store.stopped_logs();
    report.lifted = (
        before.0.filter(|_| report.stopped.0.is_none()),
        before.1.filter(|_| report.stopped.1.is_none()),
    );
    report.logs = store.log_sizes();
}

/// THE CADENCE: the pruner thread's clock and stop, one condvar — a wait of
/// the interval ends early at the stop, so a shutdown never waits on it.
pub struct Cadence {
    stopped: Mutex<bool>,
    wake: Condvar,
}

/// What a wait ended with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wake {
    /// The interval passed.
    Due,
    /// The stop was asked.
    Stop,
}

impl Cadence {
    /// A cadence not yet stopped.
    pub fn new() -> Cadence {
        Cadence { stopped: Mutex::new(false), wake: Condvar::new() }
    }

    /// Wait `interval`, or less where the stop arrives first.
    pub fn wait(&self, interval: Duration) -> Wake {
        let mut stopped = self.stopped.lock();
        if *stopped {
            return Wake::Stop;
        }
        self.wake.wait_for(&mut stopped, interval);
        if *stopped {
            Wake::Stop
        } else {
            Wake::Due
        }
    }

    /// Stop: every waiter wakes with [`Wake::Stop`], now and forever.
    pub fn stop(&self) {
        *self.stopped.lock() = true;
        self.wake.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    /// The cadence wakes at the interval, and at once at the stop — before
    /// and after it is asked.
    #[test]
    fn the_cadence_wakes_due_or_stopped() {
        let cadence = Cadence::new();
        let started = Instant::now();
        assert_eq!(cadence.wait(Duration::from_millis(20)), Wake::Due);
        assert!(started.elapsed() >= Duration::from_millis(20));
        let waiter = std::thread::scope(|s| {
            let h = s.spawn(|| cadence.wait(Duration::from_secs(3600)));
            std::thread::sleep(Duration::from_millis(20));
            cadence.stop();
            h.join().expect("waiter")
        });
        assert_eq!(waiter, Wake::Stop);
        assert_eq!(cadence.wait(Duration::from_secs(3600)), Wake::Stop, "stopped stays stopped");
    }

    /// THE PASS's (a) and the hold (clause (5)): an expired upload a stream
    /// still holds is left to that stream's end — its partial and its record
    /// untouched by the pass — and, the hold released, the next pass retires
    /// it. The pruner counts the passes it ran, and a pass over an index not
    /// yet ready does not start: it answers nothing and counts none.
    #[test]
    fn an_expired_upload_a_stream_holds_is_left_to_that_streams_end() {
        use skep_blobs::HashFunction;
        use skep_namespace::PrincipalId;

        use crate::index::Rebuild;

        let pruner = Pruner::new();
        let unready_dir = tempfile::tempdir().expect("tempdir");
        let unready = MediaGate::open(unready_dir.path()).expect("the store opens");
        assert_eq!(pruner.pass(&unready, || ()), None, "the index not ready: no pass starts");
        assert_eq!(pruner.passes_completed(), 0, "…and none is counted");

        let dir = tempfile::tempdir().expect("tempdir");
        let gate = MediaGate::open(dir.path()).expect("the store opens");
        gate.index().complete(Rebuild {
            values: 0,
            cells: 0,
            halts: 0,
            walk: Duration::ZERO,
            parse: Duration::ZERO,
        });
        let now = gate.now_ms();
        let key = MediaGate::key(PrincipalId(1));
        let interval = Duration::from_millis(1_000);
        let record = gate
            .store()
            .create_upload(&key, HashFunction::Blake3, 10, interval, now)
            .expect("an upload");
        gate.advance_clock_ms(2_000);
        let hold = gate.claim(record.id).expect("a fresh upload is claimable");
        let pass_now = || pruner.pass(&gate, || ()).expect("the index is ready");
        assert_eq!(pass_now().expired_partials, 0, "held: left to its stream");
        assert!(gate.store().expired_uploads(gate.now_ms()).iter().any(|r| r.id == record.id));
        drop(hold);
        assert_eq!(pass_now().expired_partials, 1, "released: the next pass retires it");
        assert!(gate.store().expired_uploads(gate.now_ms()).is_empty(), "…its record with it");
        assert_eq!(pruner.passes_completed(), 2, "the two passes that ran");
    }
}
