//! THE PRUNER (`media.md` Op inventory 1 — "Unreferenced blobs … are
//! prunable sidecar garbage … pruning checks reference absence, in the cell
//! index … ONLY UNDER THE DESIGNATIONS THIS BUILD's SCHEMAS PIN, a value
//! naming the cell's kind that parses under no schema this build knows
//! HALTING THE PRUNER's UNLINK OF AN UNREFERENCED FILE"; Op inventory 2 —
//! "the PRUNER UNLINKS ONLY UNDER THE GATE's EXCLUSIVE ARM, `gate.write()`,
//! re-reading the cell index and the lease there, ONE FILE PER ACQUISITION
//! — re-read, unlink, release"; the register M-I5 (b), (f); the rulings
//! ms5-R, ms5-T4 — D13's carve-out): THE PASS, run once the index is ready
//! and then on a cadence ([`crate::limits::PRUNE_INTERVAL`]).
//!
//! Each pass, in order: (a) THE EXPIRED PARTIALS — every upload record past
//! its expiry and held by no stream is retired and its partial removed,
//! off the store's own read of expiry and the gate's hold, reading no
//! reference; (b) THE HALTS — a designation directory under `blobs/`
//! outside the pinned set, or a halt mark standing in the index, halts the
//! unlink pass before its first unlink, with one operator line naming the
//! directory or the schema; (c) THE UNREFERENCED FILES — for each file at a
//! hex name under the pinned designation, under the credential lock's
//! EXCLUSIVE ARM taken for that one file: the index re-read (no cell names
//! the hash, and no halt mark stands), the lease log re-read (no key holds
//! a live lease on it), the file unlinked, the arm released. A file a cell
//! names or any live lease holds is KEPT (M-I5 (b): no housekeeping act
//! creates a hole); the arm is held one file at a time (M-I5 (f): a
//! retirement never queues behind a drain's I/O); a replace's aside the
//! deferred step did not reach is removed under the same arm, nothing
//! naming it. The pass never touches a partial whose upload stands, and
//! reads no directory's bytes as a scope (M-I6: the scopes stay
//! record-derived).
//!
//! THE ARM IS THE SESSION LAYER's and is handed in: this module sits
//! beside the write path and names nothing above it, so the pass takes the
//! acquisition as a closure and holds whatever guard it answers for
//! exactly one file.

use std::io;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

use super::gate::{MediaGate, DESIGNATION};
use crate::notice;

/// What one pass did — the test hook's answer, and the operator's line's
/// figures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrunePass {
    /// Expired uploads retired, their partials removed.
    pub expired_partials: usize,
    /// Files at hex names unlinked.
    pub unlinked: usize,
    /// Files at hex names kept — named by a cell or held by a live lease.
    pub kept: usize,
    /// Asides removed — the deferred step's leftovers.
    pub asides: usize,
    /// Why the unlink pass halted before its first unlink, if it did — the
    /// operator line's reason, naming the directory or the schema.
    pub halted: Option<String>,
}

/// THE PINNED DESIGNATION SET: the designations this build's schemas pin
/// — `blake3`, the one cell schema's. A directory under `blobs/` named
/// otherwise is a sidecar of a build this one is not, and halts the
/// unlink pass.
pub(crate) const PINNED_DESIGNATIONS: &[&str] = &[DESIGNATION];

/// ONE PASS over `gate`'s store and index, `exclusive` the acquisition of
/// the credential lock's write arm — called once per file, its guard held
/// across that file's re-read and unlink and dropped before the next.
/// `None` where the index is not ready: the pass does not start (ms5-R).
pub(crate) fn pass<G>(gate: &MediaGate, exclusive: impl Fn() -> G) -> io::Result<Option<PrunePass>> {
    let index = gate.index();
    if !index.is_ready() {
        return Ok(None);
    }
    let store = gate.store();
    let now = gate.now_ms();
    let mut report =
        PrunePass { expired_partials: 0, unlinked: 0, kept: 0, asides: 0, halted: None };

    // (a) THE EXPIRED PARTIALS — the store's own read of expiry, the gate's
    // hold; no reference read, no arm.
    for record in store.expired_uploads(now) {
        if !gate.claim(record.id) {
            continue; // a stream holds it: left to that stream's end
        }
        let removed = store.expire_upload(&record.id, now);
        gate.release(record.id);
        if removed? {
            report.expired_partials += 1;
        }
    }

    // (b) THE HALTS, before the first unlink.
    let halt = {
        let foreign = store
            .designations()?
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
        notice::line(format_args!(
            "pruner: the unlink pass is halted — {reason}; {} expired partials removed, no file unlinked",
            report.expired_partials
        ));
        report.halted = Some(reason);
        #[cfg(any(test, feature = "test-hooks"))]
        gate.note_pass_completed();
        return Ok(Some(report));
    }

    // (c) THE UNREFERENCED FILES, one per acquisition, under the pinned
    // designations alone.
    for designation in PINNED_DESIGNATIONS {
        for hex in store.blobs_of(designation)? {
            let unlinked = {
                let _arm = exclusive();
                // THE RE-READ under the arm: a cell committed since the
                // listing, a halt mark entered since, a lease taken since.
                let referenced = index.referenced(designation, &hex)
                    || index.first_halt().is_some()
                    || store.any_live_lease(designation, &hex, gate.now_ms());
                if referenced {
                    report.kept += 1;
                    false
                } else {
                    let went = store.unlink_blob(designation, &hex)?;
                    if went {
                        report.unlinked += 1;
                    }
                    went
                }
            };
            // The arm released, the next acquisition not yet taken: the
            // dirty-crash harness's seam, after an unlink.
            #[cfg(any(test, feature = "test-hooks"))]
            if unlinked {
                gate.hold_after_unlink_if_armed();
            }
            #[cfg(not(any(test, feature = "test-hooks")))]
            let _ = unlinked;
        }
        for aside in store.asides_of(designation)? {
            let _arm = exclusive();
            if store.remove_aside(designation, &aside)? {
                report.asides += 1;
            }
        }
    }
    #[cfg(any(test, feature = "test-hooks"))]
    gate.note_pass_completed();
    Ok(Some(report))
}

/// THE CADENCE: the pruner thread's clock and stop, one condvar — a wait of
/// the interval ends early at the stop, so a shutdown never waits on it.
pub(crate) struct Cadence {
    stopped: Mutex<bool>,
    wake: Condvar,
}

/// What a wait ended with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wake {
    /// The interval passed.
    Due,
    /// The stop was asked.
    Stop,
}

impl Cadence {
    pub(crate) fn new() -> Cadence {
        Cadence { stopped: Mutex::new(false), wake: Condvar::new() }
    }

    /// Wait `interval`, or less where the stop arrives first.
    pub(crate) fn wait(&self, interval: Duration) -> Wake {
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
    pub(crate) fn stop(&self) {
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
        assert_eq!(PINNED_DESIGNATIONS, ["blake3"]);
    }
}
