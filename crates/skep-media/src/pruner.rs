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
//! Each pass, in order: (a) the expired partials — every upload record past
//! its expiry and held by no stream is retired and its partial removed, off
//! the store's own read of expiry and the media gate's hold, reading no
//! reference; (b) the halts — a designation directory under `blobs/`
//! outside the pinned set, or a halt mark standing in the index, halts the
//! unlink pass before its first unlink, and so do a read of them that
//! failed and the daemon's standing halt ([`Pruner::halt_the_unlink_pass`])
//! — the pass's line naming the directory or the schema, saying them
//! unread, or giving the daemon's reason; (c) the unreferenced files — for
//! each file at a hex name under the pinned designation, under the
//! credential lock's exclusive arm taken for that one file: the index
//! re-read (no cell names the hash, and no halt mark stands), the lease log
//! re-read (no key holds a live lease on it), the file renamed aside to
//! `.retired-<hex>-<n>` — the replace's own aside name — the arm released;
//! and the aside unlinked after, under no arm, which is where the file's
//! blocks are freed. A file a cell names or any live lease holds is kept
//! (M-I5 (b): no housekeeping act creates a hole — the re-read and the
//! rename are one interval under the arm, and a crash between the rename
//! and the unlink leaves an aside open removes); the arm is held one
//! re-read and one rename, never across the unlink of a file the pass takes
//! (M-I5 (f): a retirement never queues behind a drain's I/O — at the
//! per-file cap an unlink under the arm would hold every write on the board
//! for the freeing's time); a replace's aside the deferred step did not
//! reach is removed at the pass's end, one per acquisition of the arm,
//! which is held across that removal. Then (d) the logs' compaction — the
//! lease log's leases past the horizon dropped first, as the store's open
//! drops them, then each of the two logs rewritten to its current records
//! where its lines have passed [`crate::limits::COMPACTION_TRIGGER`] times
//! those records (never under [`crate::limits::COMPACTION_MIN_LINES`]), or
//! where it has stopped, whatever its count, under the store's own lock on
//! that log's appends alone and no arm of the credential lock (P22: the
//! honest-null arm compacted by its reclaimer); a log that has stopped — an
//! append whose cut back to its last whole line failed too, or a compaction
//! that failed past its rename — takes no append until a compaction
//! completes, and the pass's line names it with its cause, the OS's own (a
//! full volume told apart from a read-only mount or a failing device, so the
//! act that clears it is the one named), how long it has stood and the
//! appends it has refused, and names a stop the pass's own rewrite lifted as
//! it stood. Every pass's line says each log's size, and what a compaction
//! rewrote it from, and the bytes the pass's removals freed. The pass never
//! touches a partial whose upload stands, and reads no directory's bytes as
//! a scope (M-I6: the scopes stay record-derived).
//!
//! **The pass's exit** (`operations.md` §4 row 5; §1.1 row 35). Every step
//! but (c) runs whatever an earlier one answered, and each step's failure is
//! the report's and never the pass's: the first error a store call answered
//! in that step, the step named and that step's own loop stopped there
//! ([`PrunePass::failed`], in step order). The one step whose failure stops
//! another is (b). At the pruner an absence is a permission (D13's
//! carve-out), so halts it could not read halt the unlink pass as halts it
//! read do, and (c) runs only where (b) read them and found none. So an
//! expiry that fails at (a) — a stopped `uploads.log` refusing a
//! retirement, a partial the OS will not remove — never costs the pass its
//! unlinks: the room a full volume needs most, and the room (d) needs for a
//! log's second copy as it rewrites it. Step (d) runs on every exit, the
//! halt's included, so the compaction that lifts a stopped log runs
//! whatever failed before it. The halt and the failures are the report's,
//! and its one line says them — line 34, or line 35 where a step failed,
//! each failure ahead of the figures — hourly: the pass writes no
//! standalone line of its own (§1.1 row 36).
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
use skep_blobs::{LogSize, LogStop, Store};
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
    pub expired_partials: usize,
    /// Files at hex names taken: renamed aside under the arm, unlinked after.
    pub unlinked: usize,
    /// Files at hex names kept.
    ///
    /// Each was named by a cell or held by a live lease, or met a halt mark
    /// entered since the listing.
    pub kept: usize,
    /// Asides removed at the pass's end.
    ///
    /// They are the deferred step's leftovers, and a pass's own aside an
    /// earlier pass's failed unlink left behind.
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
    /// named (`operations.md` §4 row 5; §1.1 row 35): at most one of (a)'s,
    /// and one of (b)'s or (c)'s, since a failed (b) halts the unlink pass
    /// (`halted`) and (c) never runs over halts unread. Every other step ran
    /// past it, and step (d) on every exit, so a stop this pass met is lifted
    /// by its own compaction, where the rewrite completes, and not a
    /// restart's. Empty, the pass's line is line 34; else line 35, naming
    /// each failure ahead of the figures.
    pub failed: Vec<PassFailure>,
}

/// One step's failure: the step and the store's first error in it.
///
/// Line 35 names it `{step}: {cause}`.
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

/// The steps of a pass a store call can fail in: (a), (b) and (c).
///
/// Step (d), the compaction, answers its failure as the report's own
/// (`compaction_failed`) and never ends the pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassStep {
    /// (a) The expired partials.
    ///
    /// A partial's removal or its record's retirement — the retirement an
    /// append `uploads.log` refuses while it has stopped.
    ExpiredPartials,
    /// (b) The halts' read: the designation directories under `blobs/`.
    ///
    /// Its failure halts the unlink pass as a halt read does: (c) never runs
    /// over halts unread.
    Halts,
    /// (c) The unreferenced files: a listing, a rename aside, an unlink.
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
    /// Returns this step's failure for a store's error, as a mapping.
    ///
    /// It is what the step's `?` arms map a store's error to.
    fn failed(self) -> impl Fn(io::Error) -> PassFailure {
        move |e| PassFailure { step: self, cause: e.to_string() }
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
/// milliseconds, `operations.md` §1), and the appends it has refused, the
/// uploads it cost.
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
    /// **The exit rule** (the module's card). Every step runs whatever an
    /// earlier one failed — (c) only where (b) read the halts and found none
    /// (`steps`) — and step (d) on every exit; the answer is the report.
    /// Each step's failure is a member of its `failed`, beside the figures
    /// and the compaction's state, so no failure costs the pass another
    /// step's room or its compaction.
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
    /// Each step's failure is pushed onto the report's `failed` in step order
    /// and ends no other step, (b)'s aside: (a) runs, then (b), and (c) only
    /// where (b) read the halts and found none. A halt read is the report's
    /// `halted`, and so is a read that failed ([`HALTS_UNREAD`]) and the
    /// daemon's standing halt ([`Pruner::halt_the_unlink_pass`]), read first;
    /// nothing is unlinked under any. The figures land in `report` as each act
    /// completes, so a failed step's report still counts what ran before its
    /// failure.
    fn steps<G>(&self, media_gate: &MediaGate, exclusive: &impl Fn() -> G, report: &mut PrunePass) {
        if let Err(failure) = expire_partials(media_gate, report) {
            report.failed.push(failure);
        }
        let halt = match self.unlink_halted.get() {
            Some(reason) => Ok(Some(reason.clone())),
            None => halts(media_gate),
        };
        match halt {
            Ok(None) => {
                if let Err(failure) = self.unlink_unreferenced(media_gate, exclusive, report) {
                    report.failed.push(failure);
                }
            }
            // The report carries the halt; its line says it, and no
            // standalone line is written here (row 36).
            Ok(Some(reason)) => report.halted = Some(reason),
            // (b) gates (c): at the pruner an absence is a permission (D13's
            // carve-out), so halts the read could not see halt the unlink
            // pass as halts it saw do.
            Err(failure) => {
                report.failed.push(failure);
                report.halted = Some(HALTS_UNREAD.to_string());
            }
        }
    }

    /// Runs step (c), the unreferenced files, into `report`.
    ///
    /// It takes one file per acquisition of `exclusive`, under the pinned
    /// designations alone: each file at a hex name re-read under the arm and
    /// renamed aside where nothing holds it, the aside unlinked after under
    /// no arm; then the asides the deferred step did not reach.
    ///
    /// # Errors
    ///
    /// The first store failure — a listing, a rename aside or an unlink — as
    /// step (c)'s; the step stops there.
    fn unlink_unreferenced<G>(
        &self,
        media_gate: &MediaGate,
        exclusive: &impl Fn() -> G,
        report: &mut PrunePass,
    ) -> Result<(), PassFailure> {
        let store = media_gate.store();
        let index = media_gate.index();
        let failed = PassStep::UnreferencedFiles.failed();
        for designation in PINNED_DESIGNATIONS {
            for hex in store.blobs_of(designation).map_err(&failed)? {
                let aside = {
                    let _arm = exclusive();
                    // The re-read under the arm: a cell committed since the
                    // listing, a halt mark entered since, a lease taken since.
                    let referenced = index.referenced(designation, &hex)
                        || index.first_halt().is_some()
                        || store.any_live_lease(designation, &hex, media_gate.now_ms());
                    if referenced {
                        report.kept += 1;
                        None
                    } else {
                        // The rename aside, the arm's one act: the name is
                        // taken here and the blocks freed below, the arm
                        // released.
                        store.rename_aside(designation, &hex).map_err(&failed)?
                    }
                };
                let Some(aside) = aside else { continue };
                report.unlinked += 1;
                // The arm released, the aside not yet unlinked: the dirty-crash
                // harness's seam — a crash here leaves an aside open removes.
                #[cfg(any(test, feature = "test-hooks"))]
                self.hold_after_rename_if_armed();
                // The unlink after, under no arm: the freeing's cost lands on
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

/// Runs step (a), the expired partials, into `report`.
///
/// It reads the store's own expiry and the media gate's hold, no reference
/// and no arm: each expired upload no stream holds is retired, its partial
/// removed first.
///
/// # Errors
///
/// The first store failure, as step (a)'s; the step stops there. The
/// retirement is an append, so a stopped `uploads.log` refuses it; a partial
/// the OS will not remove keeps its record standing, expired, and the next
/// pass meets it again.
fn expire_partials(media_gate: &MediaGate, report: &mut PrunePass) -> Result<(), PassFailure> {
    let store = media_gate.store();
    let now = media_gate.now_ms();
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
    Ok(())
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
/// The designation directories' listing failing, as step (b)'s.
fn halts(media_gate: &MediaGate) -> Result<Option<String>, PassFailure> {
    let foreign = media_gate
        .store()
        .designation_dirs()
        .map_err(PassStep::Halts.failed())?
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
mod tests {
    use std::path::Path;
    use std::time::Instant;

    use super::*;
    use crate::index::Rebuild;

    /// Returns a gate over `dir` whose index is ready, built by hand.
    ///
    /// It goes through the walk's door, with nothing walked.
    ///
    /// # Panics
    ///
    /// Panics where the store does not open.
    fn ready_gate(dir: &Path) -> MediaGate {
        let gate = MediaGate::open(dir).expect("the store opens");
        gate.index().complete(Rebuild {
            values: 0,
            cells: 0,
            halts: 0,
            walk: Duration::ZERO,
            parse: Duration::ZERO,
        });
        gate
    }

    /// Checks that the cadence wakes due or stopped.
    ///
    /// It wakes at the interval, and at once at the stop — before and after
    /// it is asked.
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

    /// Checks the pass's (a) and the hold (clause (5)).
    ///
    /// An expired upload a stream still holds is left to that stream's end —
    /// its partial and its record untouched by the pass — and, the hold
    /// released, the next pass retires it. The pruner counts the passes it
    /// ran, and a pass over an index not yet ready does not start: it answers
    /// nothing and counts none.
    #[test]
    fn an_expired_upload_a_stream_holds_is_left_to_that_streams_end() {
        use skep_blobs::HashFunction;
        use skep_namespace::PrincipalId;

        let pruner = Pruner::new();
        let unready_dir = tempfile::tempdir().expect("tempdir");
        let unready = MediaGate::open(unready_dir.path()).expect("the store opens");
        assert_eq!(pruner.pass(&unready, || ()), None, "the index not ready: no pass starts");
        assert_eq!(pruner.passes_completed(), 0, "…and none is counted");

        let dir = tempfile::tempdir().expect("tempdir");
        let gate = ready_gate(dir.path());
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

    /// Checks that a failure at step (a) never skips step (c).
    ///
    /// The pass's exit (`operations.md` §4 row 5; §1.1 row 35): an expired
    /// upload whose partial the OS will not remove — a directory holding a
    /// file stands at its name, which no unlink takes — fails (a), the step
    /// named and the store's words for the act in its cause. The pass goes
    /// on and unlinks the lapsed deposit no cell names, its bytes freed and
    /// nothing halted, and its line names the failure ahead of what it did.
    /// The record stands expired, so the next pass fails at (a) again, with
    /// nothing left to unlink.
    #[test]
    fn a_failed_expiry_never_skips_the_unreferenced_files() {
        use skep_namespace::PrincipalId;

        use crate::cell::DESIGNATION;

        let dir = tempfile::tempdir().expect("tempdir");
        let gate = ready_gate(dir.path());
        gate.install_limits(None, None, Some(1_000), None, None).expect("a record installs");
        let p = PrincipalId(1);
        let now = gate.now_ms();
        let stuck = gate.create_upload(p, 10, now).expect("an upload");
        let partial =
            dir.path().join("blobs").join(DESIGNATION).join(format!(".upload-{}", stuck.id));
        std::fs::remove_file(&partial).expect("the empty partial");
        std::fs::create_dir(&partial).expect("a directory at its name");
        std::fs::write(partial.join("held"), b"x").expect("a file inside it");
        let bytes = b"a picture no cell names";
        let record = gate.create_upload(p, bytes.len() as u64, now).expect("a creation");
        let mut stream =
            gate.store().resume(&MediaGate::key(p), &record.id, 0, now).expect("a resume");
        stream.append(bytes, now).expect("the bytes");
        let hex = gate.finish_upload(stream, now).expect("a finish").hex;
        let blob = gate.store().blob_path(DESIGNATION, &hex).expect("a path");
        gate.advance_clock_ms(2_000);
        let pruner = Pruner::new();
        let pass = pruner.pass(&gate, || ()).expect("the index is ready");
        let [failure] = pass.failed.as_slice() else { panic!("one failure, (a)'s: {pass:?}") };
        assert_eq!(failure.step, PassStep::ExpiredPartials, "{pass:?}");
        assert!(failure.cause.contains(": remove: "), "the store's words for the act: {failure}");
        assert_eq!((pass.expired_partials, pass.unlinked, pass.kept), (0, 1, 0), "{pass:?}");
        assert_eq!(pass.freed, bytes.len() as u64, "the deposit's bytes: {pass:?}");
        assert_eq!(pass.halted, None, "{pass:?}");
        assert!(!blob.exists(), "unlinked in the pass whose (a) failed");
        let line = pass.to_string();
        assert!(
            line.starts_with(&format!(
                "pruner: the pass failed: {failure}; 0 expired partials removed, 1 files \
                 unlinked, 0 kept, 0 asides removed, {} bytes freed; blobs/uploads.log ",
                bytes.len()
            )),
            "the failure named ahead of what the pass did: {line}"
        );
        let again = pruner.pass(&gate, || ()).expect("the index is ready");
        assert_eq!(again.failed, pass.failed, "the record stands expired: (a) fails again");
        assert_eq!((again.unlinked, again.kept, again.freed), (0, 0, 0), "{again:?}");
    }
}
