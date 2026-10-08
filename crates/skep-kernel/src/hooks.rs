//! THE TEST SEAM — compiled only with `test-hooks`, which this crate's own
//! suites and the daemon's turn on and no shipped build does. THE
//! WRITE-FAULT SEAM: the hook before each [`Step`] of the checkpoint write
//! and of the journal's append, barrier and repair, where an armed FAILURE
//! answers an `io::Error` of the kind the test named in the step's place —
//! `StorageFull` for the full volume — and an armed PANIC unwinds there.
//! Each arm fires ONCE and disarms: the next call of the same step runs the
//! real step. It is what lets the full volume's failures at a write, at a
//! checkpoint — before or after the base landed — and at the repair after
//! an unwind, and a panic inside the checkpoint write, be driven on cue in
//! the gate on every platform, where the one failure a test could reach
//! before was a directory squatting on a name.
//!
//! The state is ONE KERNEL's, never the process's — one test opens several
//! kernels, and the suite runs many tests in one process: [`Kernel`] holds
//! it and hands its journal appender a second handle at the open
//! (`JournalWriter::with_seam`), and the checkpoint write takes it by
//! reference (`checkpoint::write`); the `Seam` alias in `lib.rs` is the
//! handle. The doors a test arms it through are [`Kernel`]'s
//! `#[doc(hidden)]` [`fail_the_next`], [`panic_at_the_next`] and
//! [`armed_steps`], which delegate here. A build without the feature
//! carries none of it, and the write sites' hook before a step is the
//! no-op `NoHooks` of `lib.rs`. Like [`SaltSource::Seeded`], a test-time
//! knob the shipped binary never turns: the kernel still has no logging
//! seam — it answers facts, and this seam only makes a step fail.
//!
//! [`Kernel`]: crate::Kernel
//! [`fail_the_next`]: crate::Kernel::fail_the_next
//! [`panic_at_the_next`]: crate::Kernel::panic_at_the_next
//! [`armed_steps`]: crate::Kernel::armed_steps
//! [`SaltSource::Seeded`]: crate::SaltSource::Seeded

use std::io;

use parking_lot::Mutex;

use crate::Step;

/// What an armed step does in the real step's place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// Answer an `io::Error` of this kind, naming the kind and the step.
    Fail(io::ErrorKind),
    /// Unwind, naming the step.
    Panic,
}

/// The write-fault seam's state: at most one arm per step, each TAKEN by
/// the first hook that reaches its step. Behind an `Arc` (the `Seam`
/// alias) so the kernel and its journal appender hold one state: the
/// kernel's doors arm it, the appender's and the checkpoint write's hooks
/// fire it.
#[derive(Default)]
pub(crate) struct Hooks {
    armed: Mutex<Vec<(Step, Arm)>>,
}

impl Hooks {
    /// The seam's hook before a step — what each write site calls: the arm
    /// standing at `step`, if one does, is TAKEN, so the next call of the
    /// same step runs the real step, and fires in the step's place — a
    /// failure answers its `io::Error`, the message naming the kind and the
    /// step; a panic unwinds, its message naming the step. No lock of the
    /// seam's is held while either fires. With no arm standing the answer
    /// is `Ok(())`, and the step runs.
    pub(crate) fn before(&self, step: Step) -> io::Result<()> {
        let arm = {
            let mut armed = self.armed.lock();
            let at = armed.iter().position(|(at, _)| *at == step);
            at.map(|i| armed.remove(i).1)
        };
        match arm {
            None => Ok(()),
            Some(Arm::Fail(kind)) => {
                Err(io::Error::new(kind, format!("injected {kind:?} at {step:?}")))
            }
            Some(Arm::Panic) => panic!("injected panic at {step:?}"),
        }
    }

    /// Arm `step`, replacing any arm standing there: one arm per step.
    fn arm(&self, step: Step, arm: Arm) {
        let mut armed = self.armed.lock();
        armed.retain(|(at, _)| *at != step);
        armed.push((step, arm));
    }

    /// FAIL the next `step` with an `io::Error` of `kind`, once.
    pub(crate) fn fail_the_next(&self, step: Step, kind: io::ErrorKind) {
        self.arm(step, Arm::Fail(kind));
    }

    /// PANIC at the next `step`, once. Only a step that
    /// [`takes_a_panic_arm`] can be armed so; arming another is a caller's
    /// bug, answered as one.
    pub(crate) fn panic_at_the_next(&self, step: Step) {
        assert!(
            takes_a_panic_arm(step),
            "{step:?} takes no panic arm: the barrier's would be the append's, and a panic \
             inside the repair models no failure the kernel names (arm a failure there)"
        );
        self.arm(step, Arm::Panic);
    }

    /// The steps an arm still stands at, in arming order — empty once every
    /// arm has fired.
    pub(crate) fn armed_steps(&self) -> Vec<Step> {
        self.armed.lock().iter().map(|(step, _)| *step).collect()
    }
}

/// Which steps take a panic arm: the checkpoint write's three — the panic
/// the design's row of a panic past the commit region names, which the
/// backstop's inline checkpoint propagates out of `transact` after the
/// commit landed — and the journal's append, the unwind out of the commit
/// region the §3 guard repairs, whose repair the seam can then fail. Not
/// the barrier: its unwind leaves the appender in the append's own state
/// (`InFlight::Appending`), and the same repair answers it. Not the
/// repair: its failure is `truncate_to`'s `Err`, which the failure arm is,
/// and an unwind out of the repair after an unwind would leave the
/// appender's length above a partial append with the kernel unpoisoned — a
/// state no `set_len` produces and no card describes. Spelled out variant
/// by variant, so a step added to [`Step`] says whether it takes one before
/// the build passes.
fn takes_a_panic_arm(step: Step) -> bool {
    match step {
        Step::CheckpointCreate
        | Step::CheckpointSync
        | Step::CheckpointDirSync
        | Step::JournalAppend => true,
        Step::JournalBarrier | Step::JournalRepair => false,
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::*;

    const EVERY: [Step; 6] = [
        Step::CheckpointCreate,
        Step::CheckpointSync,
        Step::CheckpointDirSync,
        Step::JournalAppend,
        Step::JournalBarrier,
        Step::JournalRepair,
    ];

    #[test]
    fn an_arm_fires_once_at_its_own_step_and_the_message_names_the_kind_and_the_step() {
        let hooks = Hooks::default();
        hooks.fail_the_next(Step::JournalBarrier, io::ErrorKind::StorageFull);
        // Every other step runs, the arm standing.
        for step in EVERY.iter().filter(|s| **s != Step::JournalBarrier) {
            hooks.before(*step).expect("an unarmed step runs");
        }
        assert_eq!(hooks.armed_steps(), vec![Step::JournalBarrier]);
        let e = hooks.before(Step::JournalBarrier).expect_err("the armed step fails");
        assert_eq!(e.kind(), io::ErrorKind::StorageFull);
        assert_eq!(e.to_string(), "injected StorageFull at JournalBarrier");
        // Fired once: the same step, asked again, runs.
        assert!(hooks.armed_steps().is_empty());
        hooks.before(Step::JournalBarrier).expect("the step runs for real after its arm fired");
    }

    #[test]
    fn a_panic_arm_unwinds_once_naming_the_step() {
        let hooks = Hooks::default();
        hooks.panic_at_the_next(Step::CheckpointSync);
        let unwound = catch_unwind(AssertUnwindSafe(|| hooks.before(Step::CheckpointSync)));
        let payload = unwound.expect_err("the armed step unwinds");
        let message = payload.downcast_ref::<String>().map(String::as_str);
        assert_eq!(message, Some("injected panic at CheckpointSync"));
        assert!(hooks.armed_steps().is_empty());
        hooks.before(Step::CheckpointSync).expect("the step runs for real after its arm fired");
    }

    #[test]
    fn arming_a_step_again_replaces_its_arm_and_the_steps_list_in_arming_order() {
        let hooks = Hooks::default();
        hooks.fail_the_next(Step::JournalAppend, io::ErrorKind::StorageFull);
        hooks.fail_the_next(Step::JournalRepair, io::ErrorKind::Interrupted);
        // The append re-armed with another kind: one arm per step, the
        // later one standing, its place in the order the re-arming's.
        hooks.fail_the_next(Step::JournalAppend, io::ErrorKind::PermissionDenied);
        assert_eq!(hooks.armed_steps(), vec![Step::JournalRepair, Step::JournalAppend]);
        let e = hooks.before(Step::JournalAppend).expect_err("the re-armed step fails");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "the later arm, not the first");
        // …and a panic arm replaces a failure arm the same way.
        hooks.fail_the_next(Step::JournalAppend, io::ErrorKind::StorageFull);
        hooks.panic_at_the_next(Step::JournalAppend);
        assert!(catch_unwind(AssertUnwindSafe(|| hooks.before(Step::JournalAppend))).is_err());
        assert_eq!(hooks.armed_steps(), vec![Step::JournalRepair]);
    }

    #[test]
    fn only_the_checkpoint_steps_and_the_append_take_a_panic_arm() {
        let hooks = Hooks::default();
        for step in EVERY {
            let armed = catch_unwind(AssertUnwindSafe(|| hooks.panic_at_the_next(step))).is_ok();
            assert_eq!(armed, takes_a_panic_arm(step), "{step:?}");
        }
        assert_eq!(
            hooks.armed_steps(),
            vec![
                Step::CheckpointCreate,
                Step::CheckpointSync,
                Step::CheckpointDirSync,
                Step::JournalAppend
            ]
        );
    }
}
