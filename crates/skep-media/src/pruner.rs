//! The pruner: the pass, run once the index is ready and then on a cadence.
//!
//! Its rules are `media.md` Op inventory 1 — "Unreferenced blobs … are
//! prunable sidecar garbage … pruning checks reference absence, in the cell
//! index … only under the designations this build's schemas pin, a value
//! naming the cell's kind that parses under no schema this build knows
//! halting the pruner's unlink of an unreferenced file"; Op inventory 2 —
//! "the pruner takes a file's name only under the gate's exclusive arm,
//! `gate.write()` [the record's `gate` here is the credential write lock,
//! AUTH-3.1–3.3's write gate, whose write arm this pass is handed as
//! `exclusive` — never the media gate whose store and index it reads],
//! re-reading the cell index and the lease there, one file per acquisition
//! — re-read, rename aside, release, the aside unlinked after under no
//! arm"; §The media stores — "the pruner's pass rewrites either store the
//! same way once its log has passed a size trigger"; the register M-I5 (b),
//! (f); D13's carve-out. The cadence is the daemon's `PRUNE_INTERVAL`, the
//! transport's thread waiting it out.
//!
//! Each pass, in order: (a) the expired partials — every upload record past its
//! expiry and held by no stream is retired and its partial removed, off the
//! store's own read of expiry and the media gate's hold, reading no reference,
//! an upload whose partial the OS will not remove left standing, expired, for
//! the next pass while the walk goes on to the next; (b) the halts — a
//! designation directory under `blobs/` outside the pinned set, or a halt mark
//! standing in the index, halts the unlink pass before its first unlink, and so
//! do a read of them that failed and the daemon's standing halt
//! ([`Pruner::halt_the_unlink_pass`]) — the pass's line naming the directory or
//! the schema, saying them unread, or giving the daemon's reason; (c) the
//! unreferenced files — for each file at a hex name under the pinned
//! designation, under the credential lock's exclusive arm taken for that one
//! file: the index re-read (no cell names the hash, and no halt mark stands),
//! the lease log re-read (no key holds a live lease on it), the file renamed
//! aside to `.retired-<hex>-<n>` — the replace's own aside name — the arm
//! released; and the aside unlinked after, under no arm, which is where the
//! file's blocks are freed. A file a cell names or any live lease holds is kept
//! (M-I5 (b): no housekeeping act creates a hole — the re-read and the rename
//! are one interval under the arm, and a crash between the rename and the
//! unlink leaves an aside open removes); the arm is held one re-read and one
//! rename, never across the unlink of a file the pass takes (M-I5 (f): a
//! retirement never queues behind a drain's I/O — at the per-file cap an unlink
//! under the arm would hold every write on the board for the freeing's time); a
//! replace's aside the deferred step did not reach is removed at the pass's
//! end, one per acquisition of the arm, which is held across that removal. Then
//! (d) the logs' compaction — the lease log's leases past the horizon dropped
//! first, as the store's open drops them, then each of the two logs rewritten
//! to its current records where its lines have passed
//! [`crate::limits::COMPACTION_TRIGGER`] times those records (never under
//! [`crate::limits::COMPACTION_MIN_LINES`]), or where it has stopped, whatever
//! its count, under the store's own lock on that log's appends alone and no arm
//! of the credential lock (P22: the honest-null arm compacted by its
//! reclaimer); a log that has stopped — an append whose cut back to its last
//! whole line failed too, or a compaction that failed past its rename — takes
//! no append until a compaction completes, and the pass's line names it with
//! its cause, the OS's own (a full volume told apart from a read-only mount or
//! a failing device, so the act that clears it is the one named), how long it
//! has stood and the appends it has refused, and names a stop the pass's own
//! rewrite lifted as it stood. Every pass's line says each log's size, and what
//! a compaction rewrote it from, and the bytes the pass's removals freed. The
//! pass never touches a partial whose upload stands, and reads no directory's
//! bytes as a scope (M-I6: the scopes stay record-derived).
//!
//! **The pass's exit** (`operations.md` §4 row 5; §1.1 row 35). A file the
//! pass cannot delete never stops it deleting the rest: each step goes on
//! past an act that failed and leaves what it could not take for the next
//! pass — an expired upload whose partial the OS will not remove, its record
//! standing expired; a file whose rename aside failed, at its hex name to be
//! judged again; an aside whose unlink failed, for the step's aside loop, a
//! later pass or the next open. An expiry whose retirement a stopped
//! `uploads.log` refused is counted removed, its bytes freed, and failed
//! too: its partial went, and the record left this process. A listing that
//! fails ends its step, there being nothing left to walk. Each step's failure
//! is the report's and never the pass's: the first error a store call
//! answered in that step, the step named, and how many of its acts failed
//! ([`PrunePass::failed`], in step order). Every step but (c) runs whatever
//! an earlier one answered; the one step whose failure stops another is (b).
//! At the pruner an absence is a permission (D13's carve-out), so halts it
//! could not read halt the unlink pass as halts it read do, and (c) runs
//! only where (b) read them and found none. So an expiry that fails at (a)
//! never costs the pass its unlinks: the room a full volume needs most, and
//! the room (d) needs for a log's second copy as it rewrites it. Step (d)
//! runs on every exit, the halt's included, so the compaction that lifts a
//! stopped log runs whatever failed before it. The halt and the failures are
//! the report's, and its one line says them — line 34, or line 35 where a
//! step failed, each failure ahead of the figures — hourly: the pass writes
//! no standalone line of its own (§1.1 row 36).
//!
//! **The arm is the session layer's** and is handed in: this module sits
//! beside the write path and names nothing above it, so the pass takes the
//! acquisition as a closure and holds whatever guard it answers for
//! exactly one file.
//!
//! **The pruner** ([`Pruner`]) is the pass as one daemon runs it, beside
//! that daemon's media gate: the gate holds the store and the index the
//! pass reads, and the pruner what is the pass's own — the daemon's
//! standing halt of the unlink pass, and under the test seam its hold and
//! its count.

use std::fmt;
use std::io;
#[cfg(any(test, feature = "test-hooks"))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::{Condvar, Mutex};
use skep_blobs::{ExpiryFailed, LogSize, LogStop, Store};
#[cfg(any(test, feature = "test-hooks"))]
use skep_util::notice::{self, Class};

use crate::cell::PINNED_DESIGNATIONS;
use crate::gate::{MediaGate, STORE_DIR};
use crate::limits::{COMPACTION_MIN_LINES, COMPACTION_TRIGGER};

/// What one pass did: the test hook's answer, and the operator's line.
///
/// Rendered through its [`fmt::Display`], it is the pass's one line, line 34
/// (`operations.md` §1.1 row 34) or line 35 (row 35) where a step failed —
/// each failure named ahead of the same figures ([`PrunePass::failed`]) —
/// but the tail the daemon appends: the pass's duration, and on line 34 a
/// reading of the resident set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrunePass {
    /// Expired uploads retired, their partials removed.
    ///
    /// An expiry whose retirement line a stopped `uploads.log` refused is
    /// among them, beside its failure: its partial went, and its record left
    /// this process.
    pub expired_partials: usize,
    /// Files at hex names taken: renamed aside under the arm, unlinked after.
    ///
    /// Each is counted once its aside's unlink went; one whose unlink failed
    /// is not, its aside left for the aside loop, a later pass or the next
    /// open.
    pub unlinked: usize,
    /// Files at hex names kept.
    ///
    /// Each was named by a cell or held by a live lease, or met a halt mark
    /// entered since the listing.
    pub kept: usize,
    /// Asides removed at the pass's end.
    ///
    /// They are the deferred step's leftovers, and a pass's own aside whose
    /// unlink failed after its rename, this pass's or an earlier one's.
    pub asides: usize,
    /// The bytes the pass freed: what it reclaimed, a landing line's figure.
    ///
    /// The landing line's figure (`operations.md` §1) is each removal's as
    /// the store answers it (`Store::remove_aside`, `Store::expire_upload`),
    /// a file's length where its unlink took its last name and nothing where
    /// another name still holds it — so a pass that unlinked files and freed
    /// nothing, a hard-link backup holding the volume full, says so.
    pub freed: u64,
    /// Why the unlink pass halted before its first unlink, if it did.
    ///
    /// It is the operator line's reason: the directory or the schema it
    /// halted on, the halts unread where step (b)'s read of them failed, or
    /// the reason the daemon's standing halt gave
    /// ([`Pruner::halt_the_unlink_pass`]).
    pub halted: Option<String>,
    /// The logs this pass compacted, as `(uploads, leases)`.
    ///
    /// Each is by the size it was rewritten from
    /// (`Store::compact_logs_if_past`), `None` where the pass left it as it
    /// was.
    pub compacted: (Option<LogSize>, Option<LogSize>),
    /// Each log's size once the pass is done, as `(uploads, leases)`.
    ///
    /// It is its whole lines and their bytes (`Store::log_sizes`), said at
    /// every pass, the room the next rewrite of each needs being a second
    /// copy of it, and each log named by it on the line.
    pub logs: (LogSize, LogSize),
    /// Why a compaction failed, if one did: the operator line's reason.
    ///
    /// The logs then stopped are named beside it.
    pub compaction_failed: Option<String>,
    /// The logs stopped after this pass, as `(uploads, leases)`.
    ///
    /// Each is its stop as the store keeps it (`Store::stopped_logs`: the
    /// cause, the stop's age, the appends refused since), `None` where the
    /// log takes appends: each takes no append until a compaction completes.
    pub stopped: (Option<LogStop>, Option<LogStop>),
    /// The stops this pass's compaction lifted, as `(uploads, leases)`.
    ///
    /// Each is as it stood before the rewrite: a log stopped before the
    /// rewrite and taking appends after it.
    pub lifted: (Option<LogStop>, Option<LogStop>),
    /// Each step's failure, in step order.
    ///
    /// Each is the first error a store call answered in that step, the step
    /// named, with how many of its acts failed (`operations.md` §4 row 5;
    /// §1.1 row 35): at most one of (a)'s, and one of (b)'s or (c)'s, since a
    /// failed (b) halts the unlink pass (`halted`) and (c) never runs over
    /// halts unread. The step went on past each of its acts that failed, a
    /// listing's aside, every other step ran past it, and step (d) on every
    /// exit, so a stop this pass met is lifted by its own compaction, where
    /// the rewrite completes, and not a restart's. Empty, the pass's line is
    /// line 34; else line 35, naming each failure ahead of the figures.
    pub failed: Vec<PassFailure>,
}

/// One step's failure: the step, its first error and how many acts failed.
///
/// Line 35 names it `{step}: {cause} — the first of {count} failures`, the
/// count said with its fixed label whatever it is, as every figure on the
/// line is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassFailure {
    /// The step the store calls failed in.
    pub step: PassStep,
    /// The first failure's text, as the store spelled it.
    pub cause: String,
    /// How many of the step's acts failed this pass: at least one.
    ///
    /// Step (b) is one read, so its count is always one. Read beside the
    /// line's `expired partials removed` and `files unlinked`, it tells one
    /// file the volume will not remove from a directory or a device that
    /// fails every one.
    pub count: usize,
}

impl fmt::Display for PassFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} — the first of {} failures", self.step, self.cause, self.count)
    }
}

/// The steps of a pass a store call can fail in: (a), (b) and (c).
///
/// Step (d), the compaction, answers its failure as the report's own
/// (`compaction_failed`) and never ends the pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassStep {
    /// (a) The expired partials.
    ///
    /// A partial's removal, which leaves its upload standing, expired, for
    /// the next pass; or its record's retirement, an append `uploads.log`
    /// refuses while it has stopped, the partial gone and counted all the
    /// same.
    ExpiredPartials,
    /// (b) The halts' read: the designation directories under `blobs/`.
    ///
    /// Its failure halts the unlink pass as a halt read does: (c) never runs
    /// over halts unread.
    Halts,
    /// (c) The unreferenced files.
    ///
    /// A listing, which ends the step; or a rename aside or an unlink, which
    /// leave their file — at its hex name, or as an aside — for a later pass.
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

/// One step's failures as it meets them: the first's words and a count.
///
/// A step that goes on past an act that failed notes it here, so the one
/// [`PassFailure`] it answers names its first failure and counts them all.
struct Tally {
    step: PassStep,
    failure: Option<PassFailure>,
}

impl Tally {
    /// Returns the tally of `step`, no failure noted yet.
    fn of(step: PassStep) -> Tally {
        Tally { step, failure: None }
    }

    /// Notes one failed act: its words kept where it is the step's first.
    fn note(&mut self, error: &io::Error) {
        match &mut self.failure {
            Some(failure) => failure.count += 1,
            None => {
                self.failure =
                    Some(PassFailure { step: self.step, cause: error.to_string(), count: 1 });
            }
        }
    }

    /// Returns the step's failure, `None` where no act failed.
    fn into_failure(self) -> Option<PassFailure> {
        self.failure
    }
}

/// The compaction half of the pass's line.
///
/// Each log goes by its name within the data directory, as every other
/// blob-store line names it, with its size: `; blobs/uploads.log {n} lines
/// ({b} bytes)`, and where this pass rewrote it ` — compacted from {n} lines
/// ({b} bytes)`. Then come `; {log}'s stop lifted, rewritten whole after
/// {stop}`, `; a compaction FAILED: {why}` and `; STOPPED: {log} takes no
/// append until a compaction completes — {stop}`, each where it applies
/// (`operations.md` §1.1 row 35: "names the failure and the stopped logs").
/// A stop is said with its cause, the act that clears it turning on that
/// cause — room on a full volume, the mount or the device where they refuse
/// — how long it has stood and the appends it has refused: `{cause}; stopped
/// {ms} ms, {n} appends refused`. Every figure is said with a fixed label,
/// `{n} lines` as `{n} files unlinked`, so one search finds each whatever
/// its count.
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

/// A log's stop as the pass's line says it.
///
/// It reads `{cause}; stopped {ms} ms, {n} appends refused` — the cause in
/// the store's words, how long the stop has stood (a duration in
/// milliseconds, `operations.md` §1), and the appends it has refused: a
/// refused creation, byte received, end or finish costing its client that
/// act, and a refused retirement of an expired upload costing no one.
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

/// The operator's line for this pass, line 34 or line 35, in one rendering.
///
/// It reads `pruner: `, then, where a step failed, `the pass failed:
/// {failure}[; {failure}]; `, each in step order (`operations.md` §1.1 rows
/// 34, 35); then the figures and the bytes they freed, the halt, each log's
/// size, the compaction and any stopped log — so a failed pass says what it
/// did beside what failed. It is written to the formatter as it is
/// composed, so no string of it is built ahead of the classed door that
/// carries it (`skep_util::notice::emit`, through the daemon's `say`); the
/// class word is the daemon's, by [`PrunePass::failed`].
impl fmt::Display for PrunePass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pruner: ")?;
        if let Some((first, rest)) = self.failed.split_first() {
            write!(f, "the pass failed: {first}")?;
            for failure in rest {
                write!(f, "; {failure}")?;
            }
            f.write_str("; ")?;
        }
        write!(
            f,
            "{} expired partials removed, {} files unlinked, {} kept, {} asides removed, {} bytes \
             freed",
            self.expired_partials, self.unlinked, self.kept, self.asides, self.freed
        )?;
        if let Some(why) = &self.halted {
            write!(f, " — the unlink pass halted: {why}")?;
        }
        fmt::Display::fmt(&Compaction(self), f)
    }
}

/// The pruner: the pass as one daemon runs it ([`Pruner::pass`]).
///
/// There is one per daemon, beside its media gate. The pass reads the gate's
/// store and index and the exclusive arm it is handed; what is the pass's
/// own stands here — the daemon's standing halt of the unlink pass, and
/// under the test seam, the hold the dirty-crash harness parks a pass in
/// between a rename aside and its unlink, and the count of passes completed
/// a suite waits on.
#[derive(Default)]
pub struct Pruner {
    /// A halt of the unlink pass the daemon arms for the uptime.
    ///
    /// It is the reason [`Pruner::halt_the_unlink_pass`] gave, read by step
    /// (b) ahead of the halts it reads itself, and never cleared: the leases
    /// the lease log's open lost to damage are gone from memory, and a pass
    /// that unlinked over that loss would delete the files they held.
    unlink_halted: std::sync::OnceLock<String>,
    /// The test seam's hold inside the pass, after a rename aside.
    #[cfg(any(test, feature = "test-hooks"))]
    hold: AtomicBool,
    /// The test seam's count of passes completed.
    ///
    /// A suite waits for the cadence's first pass before it moves the clock.
    #[cfg(any(test, feature = "test-hooks"))]
    passes_completed: AtomicU64,
}

impl Pruner {
    /// Returns a pruner that has run no pass.
    ///
    /// Its hold is unarmed and its count nought, under the test seam.
    pub fn new() -> Pruner {
        Pruner::default()
    }

    /// Halts the unlink pass for the rest of this uptime, for `reason`.
    ///
    /// It is the daemon's word where the blob store's open found the lease
    /// log damaged — a whole line cut as damage, lines it could not read, or
    /// the log absent beside a standing store — so the leases lost with it
    /// hold no file in memory, and a pass's step (c) would unlink the files
    /// they held as unreferenced. Every later pass halts at step (b) with
    /// this reason, said on its line (`operations.md` §1.1 row 34), while
    /// steps (a) and (d) run; nothing but a restart, whose open reads the log
    /// afresh, lifts it. The first reason given stands.
    pub fn halt_the_unlink_pass(&self, reason: String) {
        let _ = self.unlink_halted.set(reason);
    }

    /// Runs one pass over the media gate's store and index (`media_gate`).
    ///
    /// `exclusive` is the acquisition of the credential lock's write arm —
    /// called once per file, its guard held across that file's re-read and
    /// rename aside and dropped before the aside's unlink and before the
    /// next, and once per leftover aside at the pass's end, its guard held
    /// across that aside's removal. `None` where the index is not ready: the
    /// pass does not start.
    ///
    /// **The exit rule** (the module's card). Each step goes on past an act
    /// that failed, a listing's aside, leaving what it could not take for the
    /// next pass; every step runs whatever an earlier one failed — (c) only
    /// where (b) read the halts and found none (`steps`) — and step (d) on
    /// every exit; the answer is the report. Each step's failure, its first
    /// error and how many of its acts failed, is a member of its `failed`,
    /// beside the figures and the compaction's state, so no failure costs the
    /// pass the rest of its step's room, another step's, or its compaction.
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
            failed: Vec::new(),
        };
        // (a)–(c), each step's failure kept beside the figures, (c) gated on
        // (b)'s halts alone.
        self.steps(media_gate, &exclusive, &mut report);
        // (d) The logs' compaction, under no arm — on every exit: the stop a
        // failed step may have met is lifted here, by this pass, where the
        // rewrite completes.
        compact_logs(media_gate.store(), media_gate.now_ms(), &mut report);
        #[cfg(any(test, feature = "test-hooks"))]
        self.passes_completed.fetch_add(1, Ordering::Release);
        Some(report)
    }

    /// The line the pruner's hold writes on the operator stream as it parks.
    ///
    /// It is what the dirty-crash harness watches for before it kills.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub const PRUNE_HOLD_NOTICE: &'static str =
        "test seam: held inside the pruner's pass after a rename aside; kill this process";

    /// Arms the hold inside this pruner's pass.
    ///
    /// The test seam's hold: after the next rename aside, the arm released
    /// and the aside not yet unlinked, the pass writes
    /// [`Pruner::PRUNE_HOLD_NOTICE`] and parks its thread for good. Not
    /// disarmable.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn arm_prune_hold(&self) {
        self.hold.store(true, Ordering::Relaxed);
    }

    /// Parks here where the hold is armed: the pass's side of the seam.
    #[cfg(any(test, feature = "test-hooks"))]
    fn hold_after_rename_if_armed(&self) {
        if self.hold.load(Ordering::Relaxed) {
            notice::emit(Class::Failure, Self::PRUNE_HOLD_NOTICE);
            loop {
                std::thread::park();
            }
        }
    }

    /// Returns the passes this pruner has completed so far.
    ///
    /// The test seam's count: the cadence's and a hook's alike; a pass that
    /// did not start counts none.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn passes_completed(&self) -> u64 {
        self.passes_completed.load(Ordering::Acquire)
    }

    /// Runs steps (a)–(c) of the pass into `report`.
    ///
    /// Each step answers its failure, where any of its acts failed, and the
    /// failure is pushed onto the report's `failed` in step order, ending no
    /// other step, (b)'s aside: (a) runs, then (b), and (c) only where (b)
    /// read the halts and found none. A halt read is the report's `halted`,
    /// and so is a read that failed ([`HALTS_UNREAD`]) and the daemon's
    /// standing halt ([`Pruner::halt_the_unlink_pass`]), read first; nothing
    /// is unlinked under any. The figures land in `report` as each act
    /// completes, so a failed step's report counts every act that went.
    fn steps<G>(&self, media_gate: &MediaGate, exclusive: &impl Fn() -> G, report: &mut PrunePass) {
        let expired = expire_partials(media_gate, report);
        report.failed.extend(expired);
        let halt = match self.unlink_halted.get() {
            Some(reason) => Ok(Some(reason.clone())),
            None => halts(media_gate),
        };
        match halt {
            Ok(None) => {
                let unreferenced = self.unlink_unreferenced(media_gate, exclusive, report);
                report.failed.extend(unreferenced);
            }
            // The report carries the halt; its line says it, and no
            // standalone line is written here (row 36).
            Ok(Some(reason)) => report.halted = Some(reason),
            // (b) gates (c): at the pruner an absence is a permission (D13's
            // carve-out), so halts the read could not see halt the unlink
            // pass as halts it saw do.
            Err(error) => {
                let mut failed = Tally::of(PassStep::Halts);
                failed.note(&error);
                report.failed.extend(failed.into_failure());
                report.halted = Some(HALTS_UNREAD.to_string());
            }
        }
    }

    /// Runs step (c), the unreferenced files, into `report`.
    ///
    /// It takes one file per acquisition of `exclusive`, under the pinned
    /// designations alone: each file at a hex name re-read under the arm and
    /// renamed aside where nothing holds it, the aside unlinked after under
    /// no arm; then the asides the deferred step did not reach, one per
    /// acquisition. Answers the step's failure, where any act failed: its
    /// first error and their count. A listing that fails ends the step, as
    /// nothing is left to walk; every other act that fails leaves its file
    /// and the walk goes on — a file whose rename aside failed stands at its
    /// hex name for the next pass to judge again, an aside whose unlink
    /// failed stands for this designation's aside loop below, a later pass
    /// or the next open, and a leftover aside that will not go is left.
    fn unlink_unreferenced<G>(
        &self,
        media_gate: &MediaGate,
        exclusive: &impl Fn() -> G,
        report: &mut PrunePass,
    ) -> Option<PassFailure> {
        let store = media_gate.store();
        let index = media_gate.index();
        let mut failed = Tally::of(PassStep::UnreferencedFiles);
        for designation in PINNED_DESIGNATIONS {
            let hexes = match store.blobs_of(designation) {
                Ok(hexes) => hexes,
                Err(error) => {
                    failed.note(&error);
                    return failed.into_failure();
                }
            };
            for hex in hexes {
                let aside = {
                    let _arm = exclusive();
                    // The re-read under the arm: a cell committed since the
                    // listing, a halt mark entered since, a lease taken since.
                    let referenced = index.referenced(designation, &hex)
                        || index.first_halt().is_some()
                        || store.any_live_lease(designation, &hex, media_gate.now_ms());
                    if referenced {
                        report.kept += 1;
                        continue;
                    }
                    // The rename aside, the arm's one act: the name is taken
                    // here and the blocks freed below, the arm released.
                    match store.rename_aside(designation, &hex) {
                        Ok(aside) => aside,
                        Err(error) => {
                            failed.note(&error);
                            None
                        }
                    }
                };
                let Some(aside) = aside else { continue };
                // The arm released, the aside not yet unlinked: the dirty-crash
                // harness's seam — a crash here leaves an aside open removes.
                #[cfg(any(test, feature = "test-hooks"))]
                self.hold_after_rename_if_armed();
                // The unlink after, under no arm: the freeing's cost lands on
                // this thread alone, and what it freed on the line.
                match store.remove_aside(designation, &aside) {
                    Ok(freed) => {
                        report.unlinked += 1;
                        report.freed += freed.unwrap_or(0);
                    }
                    Err(error) => failed.note(&error),
                }
            }
            let asides = match store.asides_of(designation) {
                Ok(asides) => asides,
                Err(error) => {
                    failed.note(&error);
                    return failed.into_failure();
                }
            };
            for aside in asides {
                let _arm = exclusive();
                match store.remove_aside(designation, &aside) {
                    Ok(Some(freed)) => {
                        report.asides += 1;
                        report.freed += freed;
                    }
                    Ok(None) => {}
                    Err(error) => failed.note(&error),
                }
            }
        }
        failed.into_failure()
    }
}

/// Runs step (a), the expired partials, into `report`.
///
/// It reads the store's own expiry and the media gate's hold, no reference
/// and no arm: each expired upload no stream holds is retired, its partial
/// removed first, and the walk goes on past one that fails. Answers the
/// step's failure, where any expiry failed: its first error and their count.
/// A partial the OS will not remove keeps its record standing, expired, and
/// the next pass meets it again; a retirement a stopped `uploads.log`
/// refuses is a failure too, but its partial went, and it is counted
/// removed with the bytes it freed.
fn expire_partials(media_gate: &MediaGate, report: &mut PrunePass) -> Option<PassFailure> {
    let store = media_gate.store();
    let now = media_gate.now_ms();
    let mut failed = Tally::of(PassStep::ExpiredPartials);
    for record in store.expired_uploads(now) {
        // A stream holds it: left to that stream's end.
        let Some(_hold) = media_gate.claim(record.id) else { continue };
        let freed = match store.expire_upload(&record.id, now) {
            Ok(Some(freed)) => freed,
            Ok(None) => continue,
            Err(ExpiryFailed::Retirement { freed, error }) => {
                failed.note(&error);
                freed
            }
            Err(ExpiryFailed::Removal(error)) => {
                failed.note(&error);
                continue;
            }
        };
        report.expired_partials += 1;
        report.freed += freed;
    }
    failed.into_failure()
}

/// The halt's reason where step (b)'s read of the halts failed.
///
/// The pass's line says it after `the unlink pass halted: `, so a pass that
/// judged no file never reads as a board with none to judge.
const HALTS_UNREAD: &str = "the halts are unread, so no file is judged";

/// Returns step (b)'s reason to halt the unlink pass, or `None`.
///
/// The reason is a designation directory under `blobs/` outside the pinned
/// set, or a halt mark standing in the index; it is read before the first
/// unlink.
///
/// # Errors
///
/// The designation directories' listing failing: step (b)'s one act, which
/// `steps` tallies as the step's failure.
fn halts(media_gate: &MediaGate) -> io::Result<Option<String>> {
    let foreign = media_gate
        .store()
        .designation_dirs()?
        .into_iter()
        .find(|name| !PINNED_DESIGNATIONS.contains(&name.as_str()));
    Ok(match (foreign, media_gate.index().first_halt()) {
        (Some(dir), _) => Some(format!(
            "a designation directory {STORE_DIR}/{dir}/ is outside the set this build pins ({}): a sidecar of another build's schema",
            PINNED_DESIGNATIONS.join(", ")
        )),
        (None, Some(mark)) => Some(format!(
            "a value at {} names the kind {} under no schema this build reads ({})",
            mark.at, mark.kind, mark.fault
        )),
        (None, None) => None,
    })
}

/// Runs step (d), the logs' compaction, at `now_ms`, the media gate's clock.
///
/// The lease log's leases past the horizon are dropped first, as the
/// store's open drops them, then each log rewritten where it has passed the
/// trigger — or has stopped, whatever its count — under the store's lock on
/// that log's appends alone — no arm of the credential lock is held here —
/// and the stopped logs read before and after it: a stop standing before
/// the rewrite and gone after it is one this pass lifted, said as it stood.
/// Then each log's size, the line's figure. Run on every exit of the pass, a
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

/// The cadence: the pruner thread's clock and stop, one condvar.
///
/// A wait of the interval ends early at the stop, so a shutdown never waits
/// on it.
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
    /// Returns a cadence not yet stopped.
    pub fn new() -> Cadence {
        Cadence { stopped: Mutex::new(false), wake: Condvar::new() }
    }

    /// Waits `interval`, or less where the stop arrives first.
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

    /// Stops the cadence.
    ///
    /// Every waiter wakes with [`Wake::Stop`], now and forever.
    pub fn stop(&self) {
        *self.stopped.lock() = true;
        self.wake.notify_all();
    }
}

#[cfg(test)]
mod tests;
