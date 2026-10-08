//! Checkpoints (§6): their failures and what each leaves behind, retention
//! and the reclamation floor, the on-commit trigger's discipline, and the
//! deferred arm — the due flag, the thread's call that clears it first, and
//! the backstop.

use std::io;
use std::num::NonZeroU64;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use super::*;
use crate::mutilate::{ckpt_file, flip_byte, seg_file};
use skep_kernel::{CheckpointError, LandedStep};
use tempfile::tempdir;

/// The daemon's shape of the deferred policy — a commit count beside a byte
/// bound, the crossing deferred — at a count a test can reach.
fn deferred_every(n: u64) -> CheckpointPolicy {
    CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EitherOf(
        Box::new(CheckpointPolicy::EveryN(n)),
        Box::new(CheckpointPolicy::JournalBytes(u64::MAX)),
    )))
}

/// A crossing under the deferred arm SETS THE DUE FLAG and runs nothing on
/// the committing thread; the caller's own call to `checkpoint()` runs it,
/// the file lands, and the flag reads false after (M-I5 (f): the cadence's
/// window is bounded, and the checkpoint that bounds it is off the
/// committing thread). A caller's checkpoint with no flag set runs as any
/// call does and clears nothing it needs to.
#[test]
fn a_deferred_crossing_sets_the_due_flag_and_the_callers_checkpoint_services_it() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 4);
    cfg.checkpoint = deferred_every(2);
    let k = Kernel::open(cfg, genesis()).unwrap();
    assert!(!k.checkpoint_due(), "nothing has crossed");
    commit(&k, 1);
    assert!(!k.checkpoint_due(), "1 of 2");
    commit(&k, 2);
    assert!(k.checkpoint_due(), "the crossing set the flag");
    assert_eq!(checkpoint_count(dir.path()), 0, "…and ran nothing on the committing thread");

    assert_eq!(k.checkpoint().unwrap(), Seq(2), "the caller's thread runs it");
    assert!(ckpt_file(dir.path(), 2).exists());
    assert!(!k.checkpoint_due(), "the flag reads false after the run");

    // The next window is the same again: no file at 3, the flag at 4.
    commit(&k, 3);
    assert!(!k.checkpoint_due());
    commit(&k, 4);
    assert!(k.checkpoint_due());
    assert_eq!(checkpoint_count(dir.path()), 1, "still the one the caller took");
}

/// THE BACKSTOP: a second crossing that finds the flag still set — no caller
/// serviced the first — runs the checkpoint INLINE on the committing thread,
/// as the inline arms do, and clears the flag; the crossing after that is a
/// deferred one again. So a caller that never services the flag gets a
/// checkpoint at every SECOND crossing: the journal between checkpoints is
/// bounded by two windows, never unbounded (M-I5 (f), the grace of one
/// window). And each such run is COUNTED, with the last one's failure kept
/// as text (§6, the kernel's read seam for the backstop's line): the count
/// is 0 before the first and moves at every inline run, landed or failed —
/// a failed run's commit lands all the same — the text names the failure's
/// cause while the last inline run failed and is `None` once one lands
/// after, and a caller's own `checkpoint()` moves neither.
#[test]
fn a_second_crossing_with_the_flag_set_runs_inline_as_the_backstop() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 8);
    cfg.checkpoint = deferred_every(2);
    let k = Kernel::open(cfg, genesis()).unwrap();
    assert_eq!(k.inline_checkpoints(), 0, "nothing has run inline");
    assert_eq!(k.last_inline_checkpoint_failure(), None);
    for x in 1..=8u64 {
        commit(&k, x);
    }
    // Crossings at 2, 4, 6, 8: the first and third deferred (nobody
    // services them), the second and fourth the backstop's, inline.
    assert!(!ckpt_file(dir.path(), 2).exists(), "the first crossing was deferred");
    assert!(ckpt_file(dir.path(), 4).exists(), "the second ran inline: the backstop");
    assert!(!ckpt_file(dir.path(), 6).exists(), "the third was deferred again");
    assert!(ckpt_file(dir.path(), 8).exists(), "the fourth ran inline");
    assert_eq!(checkpoint_count(dir.path()), 2);
    assert_eq!(k.inline_checkpoints(), 2, "the two backstop runs, counted");
    assert_eq!(k.last_inline_checkpoint_failure(), None, "the last of them landed");
    assert!(!k.checkpoint_due(), "an inline run clears the flag it was the backstop for");
    commit(&k, 9);
    commit(&k, 10);
    assert!(k.checkpoint_due(), "…and the next crossing is deferred");
    assert_eq!(checkpoint_count(dir.path()), 2);
    assert_eq!(k.inline_checkpoints(), 2, "a deferred crossing runs nothing inline");

    // THE TEXT: the next backstop run FAILS — the full volume at the temp
    // file's sync — and the count moves all the same, the failure kept as
    // text for the caller above to say; the commit that ran it landed.
    k.fail_the_next(Step::CheckpointSync, io::ErrorKind::StorageFull);
    commit(&k, 11);
    assert_eq!(commit(&k, 12), Seq(12), "the backstop's failure never fails the commit");
    assert_eq!(k.inline_checkpoints(), 3, "a failed inline run counts");
    let text = k.last_inline_checkpoint_failure().expect("the last inline run failed");
    assert!(
        text.contains("StorageFull") && text.contains("CheckpointSync"),
        "the text names the cause: {text}"
    );
    assert!(!ckpt_file(dir.path(), 12).exists(), "…and the run did fail");
    // A caller's own call is no inline run: it lands, and moves neither the
    // count nor the text.
    assert_eq!(k.checkpoint().unwrap(), Seq(12));
    assert_eq!(k.inline_checkpoints(), 3, "a caller's own checkpoint counts not");
    assert_eq!(k.last_inline_checkpoint_failure(), Some(text), "…and clears no text");
    // The next backstop run lands, and the text says so: the answer is the
    // last run's, not the last failure's.
    commit(&k, 13);
    commit(&k, 14);
    assert!(k.checkpoint_due(), "deferred again");
    commit(&k, 15);
    commit(&k, 16);
    assert!(ckpt_file(dir.path(), 16).exists(), "the backstop ran inline");
    assert_eq!(k.inline_checkpoints(), 4);
    assert_eq!(k.last_inline_checkpoint_failure(), None, "the last inline run landed");
}

/// Under an INLINE arm every crossing's checkpoint runs on the committing
/// thread, and every one is counted: the count is of the runs `transact`
/// made inline, whichever arm made them, and a caller's own call is none of
/// them.
#[test]
fn an_inline_arms_crossings_are_counted_as_the_backstops_are() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 8);
    cfg.checkpoint = CheckpointPolicy::EveryN(2);
    let k = Kernel::open(cfg, genesis()).unwrap();
    for x in 1..=6u64 {
        commit(&k, x);
    }
    assert_eq!(checkpoint_count(dir.path()), 3, "crossings at 2, 4 and 6");
    assert_eq!(k.inline_checkpoints(), 3, "each ran inline, and each counted");
    assert_eq!(k.last_inline_checkpoint_failure(), None);
    assert_eq!(k.checkpoint().unwrap(), Seq(6));
    assert_eq!(k.inline_checkpoints(), 3, "a caller's own call counts not");
}

/// A world whose serialize PARKS at a gate, once: the checkpointing thread
/// enters the gate inside `checkpoint()`, the test commits a crossing while
/// it stands there, then releases it. bincode walks a value twice — once to
/// size it, once to write it — so the gate arms for the first walk alone.
#[derive(Clone)]
struct GatedWorld {
    items: Vec<u64>,
    gate: Option<Arc<Gate>>,
}

struct Gate {
    armed: AtomicBool,
    entered: Barrier,
    release: Barrier,
}

impl Gate {
    fn new() -> Arc<Gate> {
        Arc::new(Gate {
            armed: AtomicBool::new(true),
            entered: Barrier::new(2),
            release: Barrier::new(2),
        })
    }
}

impl Serialize for GatedWorld {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if let Some(gate) = &self.gate {
            if gate.armed.swap(false, Ordering::AcqRel) {
                gate.entered.wait();
                gate.release.wait();
            }
        }
        self.items.serialize(s)
    }
}

impl<'de> Deserialize<'de> for GatedWorld {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Vec::<u64>::deserialize(d).map(|items| GatedWorld { items, gate: None })
    }
}

impl WorldState for GatedWorld {
    type Record = u64;

    fn apply(&self, record: &u64) -> Self {
        let mut next = self.clone();
        next.items.push(*record);
        next
    }
}

/// THE FLAG IS CLEARED BEFORE THE RUN, not after it: a checkpoint started
/// with the flag set clears it at its start, so a crossing DURING the run
/// finds it clear, sets it again and runs nothing inline — the thread
/// services it with one more call after this one returns. Cleared after the
/// run, every crossing during a long checkpoint would meet the backstop: an
/// inline checkpoint queued on the committing thread behind this one's
/// mutex, the writer's wait doubled. The checkpoint embodies the root it
/// loaded, at or below the head the crossing moved.
#[test]
fn the_flag_is_cleared_before_the_run_so_a_crossing_during_it_leaves_it_set_after() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 4);
    cfg.checkpoint = deferred_every(2);
    let gate = Gate::new();
    let k = Arc::new(Kernel::open(cfg, GatedWorld { items: vec![], gate: Some(gate.clone()) }).unwrap());
    let commit = |x: u64| {
        k.transact(&[], |stg| {
            stg.push(x);
            Ok::<(), ()>(())
        })
        .unwrap()
        .1
    };
    commit(1);
    commit(2);
    assert!(k.checkpoint_due(), "the first crossing");

    // The thread's call: it clears the flag, loads the root and parks
    // inside the serialize.
    let checkpointer = {
        let k = Arc::clone(&k);
        thread::spawn(move || k.checkpoint())
    };
    gate.entered.wait();
    assert!(!k.checkpoint_due(), "cleared at the run's start, the serialize still in flight");

    // A crossing DURING the run: it finds the flag clear, sets it, and runs
    // nothing inline — an inline run here would wait on the checkpoint
    // mutex the parked thread holds, which is the doubled wait the order
    // exists to avoid.
    commit(3);
    assert_eq!(commit(4), Seq(4));
    assert!(k.checkpoint_due(), "the crossing during the run set the flag again");
    assert_eq!(checkpoint_count(dir.path()), 0, "…and nothing ran inline");

    gate.release.wait();
    assert_eq!(checkpointer.join().unwrap().unwrap(), Seq(2), "the root it loaded, not the head");
    assert!(ckpt_file(dir.path(), 2).exists());
    assert!(k.checkpoint_due(), "set after the run: the thread's next call services it");
    assert_eq!(k.checkpoint().unwrap(), Seq(4), "…which embodies the crossing's head");
    assert!(!k.checkpoint_due());
    assert_eq!(checkpoint_count(dir.path()), 2);
}

/// THE COMPOSITE crosses on whichever half crosses first — the commit count
/// or the byte bound — and one crossing resets both windows: the count's
/// after a byte crossing, the bytes' after a count crossing. Inline here, so
/// the files are the witness.
#[test]
fn either_of_crosses_on_the_count_or_the_bytes_whichever_first_and_resets_both() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 8);
    cfg.checkpoint = CheckpointPolicy::EitherOf(
        Box::new(CheckpointPolicy::EveryN(3)),
        Box::new(CheckpointPolicy::JournalBytes(4096)),
    );
    let k = Kernel::open(cfg, genesis()).unwrap();
    assert_eq!(commit_blob(&k), Seq(1)); // one commit, far past the byte bound
    assert!(ckpt_file(dir.path(), 1).exists(), "the BYTES crossed first");
    for x in 2..=3u64 {
        commit(&k, x); // 1 and 2 of 3: the count's window restarted at 1
    }
    assert_eq!(checkpoint_count(dir.path()), 1, "a byte crossing reset the count's window too");
    commit(&k, 4);
    assert!(ckpt_file(dir.path(), 4).exists(), "the COUNT crossed: 3 of 3 since 1");
    for x in 5..=6u64 {
        commit(&k, x); // 1 and 2 of 3, a few dozen bytes each
    }
    assert_eq!(checkpoint_count(dir.path()), 2);
    assert_eq!(commit_blob(&k), Seq(7));
    assert!(ckpt_file(dir.path(), 7).exists(), "the bytes crossed again, at 3 of 3 as well");
    assert_eq!(checkpoint_count(dir.path()), 3);
}

/// The byte bound MOVES in a running kernel: `set_cadence_bytes` replaces the
/// threshold under the applier lock, wherever the arms nest it, and the next
/// commit tests the new bound against the window as it stands — the figure
/// a caller sizes from the newest checkpoint's length, re-read as each
/// lands. A policy holding no byte bound answers that nothing moved.
#[test]
fn set_cadence_bytes_moves_the_byte_bound_of_a_running_kernel() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 4);
    cfg.checkpoint = deferred_every(1024);
    let k = Kernel::open(cfg, genesis()).unwrap();
    for x in 1..=3u64 {
        commit(&k, x);
    }
    assert!(!k.checkpoint_due(), "3 of 1024, a few dozen bytes of u64::MAX");
    assert!(k.set_cadence_bytes(NonZeroU64::new(1).unwrap()), "the policy held a bound");
    commit(&k, 4);
    assert!(k.checkpoint_due(), "the moved bound: one byte, crossed by the next commit");
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    let newest = k.newest_checkpoint().expect("the base just written");
    assert_eq!(newest.seq, Seq(4));
    assert_eq!(
        newest.len,
        fs::metadata(ckpt_file(dir.path(), 4)).unwrap().len(),
        "the length a caller sizes the next bound by"
    );
    // Sized by it, as the daemon does — a bound no small commit reaches.
    assert!(k.set_cadence_bytes(NonZeroU64::new(newest.len * 1024).unwrap()));
    for x in 5..=8u64 {
        commit(&k, x);
    }
    assert!(!k.checkpoint_due(), "the bound re-read: nothing crosses");

    let bare = Kernel::open(cfg_retain(&dir.path().join("manual"), 2), genesis()).unwrap();
    assert!(!bare.set_cadence_bytes(NonZeroU64::new(1).unwrap()), "Manual holds no bound");
}

/// A checkpoint that fails PAST its temp file's creation — the rename
/// refused by a directory at the checkpoint's own name — leaves no
/// `checkpoint.tmp`, answers the write's own failure, poisons nothing, and
/// lands on the retry once the name is clear: the kernel removes its own
/// temp file (M-I5 (f): a failed checkpoint keeps no room on the volume).
#[test]
fn a_checkpoint_that_fails_past_its_temp_files_creation_leaves_no_tmp() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    fs::create_dir(ckpt_file(dir.path(), 1)).unwrap();
    let err = k.checkpoint().expect_err("the rename onto a directory is refused");
    assert!(matches!(err, CheckpointError::Io(_)), "got {err:?}");
    assert!(!dir.path().join("checkpoint.tmp").exists(), "the temp file was removed");
    assert!(!k.is_poisoned());
    assert!(!k.checkpoint_due(), "a failed call clears the flag like a landed one");
    fs::remove_dir(ckpt_file(dir.path(), 1)).unwrap();
    assert_eq!(k.checkpoint().unwrap(), Seq(1));
    assert!(ckpt_file(dir.path(), 1).exists());
    assert!(!dir.path().join("checkpoint.tmp").exists());
}

#[test]
fn checkpoint_surfaces_the_serializers_account_of_an_unencodable_world() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), FragileWorld::default()).unwrap();
    k.transact::<_, ()>(&[], |stg| {
        stg.push(Fragility::Break);
        Ok(())
    })
    .unwrap();
    let err = k
        .checkpoint()
        .expect_err("an unencodable world cannot be checkpointed");
    assert!(matches!(err, CheckpointError::Serialize(_)), "got {err:?}");
    // The cause travels: M2 never inspects `W`, so the serializer's own
    // account is the only thing that identifies the failure.
    assert!(std::error::Error::source(&err).is_some());
    // Nothing half-written, not even a stray tmp (§6's crash argument).
    assert_eq!(checkpoint_count(dir.path()), 0);
    assert!(!dir.path().join("checkpoint.tmp").exists());
    // A failed checkpoint is not a poison: the write path still works.
    k.transact::<_, ()>(&[], |stg| {
        stg.push(Fragility::Sound);
        Ok(())
    })
    .unwrap();
    assert_eq!(k.current_seq(), Seq(2));
}

#[test]
fn a_checkpoint_io_failure_is_retryable_and_never_poisons() {
    // §6: a failed checkpoint leaves at most an ignored `.tmp` and an
    // unreclaimed journal, so it is safe to retry — the opposite disposition
    // from `Serialize`, which repeats until `W` itself encodes. The two share
    // one two-arm match, and only one arm was exercised.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    // The write builds through the FIXED `checkpoint.tmp`, so a directory on
    // that name fails `File::create` (EISDIR).
    fs::create_dir(dir.path().join("checkpoint.tmp")).unwrap();
    let err = k
        .checkpoint()
        .expect_err("a checkpoint that cannot be written fails");
    assert!(matches!(err, CheckpointError::Io(_)), "got {err:?}");
    // The cause travels, and it is the environment's — not `W`'s.
    assert!(std::error::Error::source(&err).is_some());
    assert_eq!(checkpoint_count(dir.path()), 0);
    // Never a poison, and never a disturbance to the write path.
    assert!(!k.is_poisoned());
    assert_eq!(commit(&k, 20), Seq(2));

    // "Safe to retry, and a retry re-does the whole sequence from a fresh
    // root": the base it then writes is at the NEW head, and it is a base a
    // reopen actually loads.
    fs::remove_dir(dir.path().join("checkpoint.tmp")).unwrap();
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    assert!(ckpt_file(dir.path(), 2).exists());
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
}

/// §6: the full volume BEFORE the rename — `StorageFull` at the temp file's
/// creation, or at its fsync with the header and body written — answers
/// `CheckpointError::Io` of that kind, naming the step, with NO base and NO
/// `checkpoint.tmp` (the sync's removed before the failure is answered, the
/// creation's never made), the kernel not poisoned, the due flag cleared as
/// a landed call clears it; and the next call lands, the arm having fired
/// once (M-I5 (f): a failed checkpoint keeps no room on the volume).
#[test]
fn a_checkpoint_that_fails_before_its_rename_lands_no_base_and_keeps_no_tmp() {
    for step in [Step::CheckpointCreate, Step::CheckpointSync] {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("checkpoint.tmp");
        let mut cfg = cfg_retain(dir.path(), 4);
        cfg.checkpoint = deferred_every(1);
        let k = Kernel::open(cfg, genesis()).unwrap();
        commit(&k, 10);
        assert!(k.checkpoint_due(), "{step:?}: the crossing set the flag");
        k.fail_the_next(step, io::ErrorKind::StorageFull);
        let e = match k.checkpoint() {
            Err(CheckpointError::Io(e)) => e,
            other => panic!("{step:?}: expected the write's I/O failure, got {other:?}"),
        };
        assert_eq!(e.kind(), io::ErrorKind::StorageFull, "{step:?}: the kind, unchanged: {e}");
        assert!(e.to_string().contains(&format!("{step:?}")), "{step:?}: names the step: {e}");
        assert_eq!(checkpoint_count(dir.path()), 0, "{step:?}: no base landed");
        assert!(k.newest_checkpoint().is_none());
        assert!(!tmp.exists(), "{step:?}: no temp file survives");
        assert!(!k.is_poisoned());
        assert!(!k.checkpoint_due(), "{step:?}: a failed call clears the flag like a landed one");
        assert!(k.armed_steps().is_empty(), "{step:?}: the arm fired once");
        assert_eq!(k.checkpoint().unwrap(), Seq(1), "{step:?}: the next call lands");
        assert!(ckpt_file(dir.path(), 1).exists());
        assert!(!tmp.exists());
    }
}

/// §6: the full volume PAST the rename — `StorageFull` at the directory's
/// fsync — answers `CheckpointError::Landed` naming the directory sync as
/// the step, the cause of that kind, AND leaves the base ON DISK:
/// `newest_checkpoint` has moved to this call's `Seq`, the file is there,
/// retention did not run (a third base stands where two are kept), no
/// `checkpoint.tmp` remains and the kernel is not poisoned — what
/// `CheckpointError::Landed`'s card says survives. The next open loads that
/// base; the next call lands and applies the retention the failed one did
/// not.
#[test]
fn a_checkpoint_that_fails_past_its_rename_leaves_the_base_on_disk() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    for x in 1..=2u64 {
        commit(&k, x);
        assert_eq!(k.checkpoint().unwrap(), Seq(x));
    }
    commit(&k, 3);
    k.fail_the_next(Step::CheckpointDirSync, io::ErrorKind::StorageFull);
    let e = match k.checkpoint() {
        Err(CheckpointError::Landed { step: LandedStep::DirectorySync, cause }) => cause,
        other => panic!("expected the directory sync's failure over a landed base, got {other:?}"),
    };
    assert_eq!(e.kind(), io::ErrorKind::StorageFull, "the kind, unchanged: {e}");
    assert!(e.to_string().contains("CheckpointDirSync"), "names the step: {e}");
    // The base LANDED: the rename published it before the failure…
    let newest = k.newest_checkpoint().expect("a base stands");
    assert_eq!(newest.seq, Seq(3), "this call's base");
    assert!(ckpt_file(dir.path(), 3).exists());
    // …and nothing after the rename ran: a third base where two are kept.
    assert_eq!(checkpoint_count(dir.path()), 3, "retention did not run");
    assert!(!dir.path().join("checkpoint.tmp").exists());
    assert!(!k.is_poisoned());
    assert!(k.armed_steps().is_empty(), "the arm fired once");

    // The next open loads that base.
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let recovery = k.recovery().expect("journaled");
    assert_eq!(recovery.start_point, Seq(3), "the landed base is the start point");
    assert!(recovery.skipped.is_empty());
    assert_eq!(items(&k), vec![1, 2, 3]);
    // …and the next call lands and applies the retention the failed one
    // did not.
    commit(&k, 4);
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    assert_eq!(checkpoint_count(dir.path()), 2);
    assert!(ckpt_file(dir.path(), 3).exists() && ckpt_file(dir.path(), 4).exists());
}

/// §6: A PANIC IN THE CHECKPOINT WRITE. The arm fires inside `checkpoint()`
/// and propagates, the kernel not poisoned; and through THE BACKSTOP — the
/// deferred cadence's second crossing with the flag still set, which runs
/// the checkpoint inline on the committing thread — it unwinds out of
/// `transact` AFTER the commit landed: the order advanced, the root
/// installed, nothing poisoned, the kernel committing on. What the unwind
/// LEAVES is the step's: a panic before the temp file's creation leaves
/// nothing; one at the temp file's sync — inside the published window,
/// where the `Err` arm's removal does not run for an unwind — leaves
/// `checkpoint.tmp` whole on disk, which the next open removes and reports
/// by its size (`stray_checkpoint_removed`: "the open one a crash left").
/// Either way the reopen holds every commit, the one the panic unwound out
/// of included.
#[test]
fn a_panic_in_the_checkpoint_write_unwinds_out_of_transact_after_the_commit_landed() {
    for (step, leaves_the_tmp) in [(Step::CheckpointCreate, false), (Step::CheckpointSync, true)] {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("checkpoint.tmp");
        let mut cfg = cfg_retain(dir.path(), 4);
        cfg.checkpoint = deferred_every(1);
        let k = Kernel::open(cfg.clone(), genesis()).unwrap();
        commit(&k, 1);
        assert!(k.checkpoint_due(), "{step:?}: the first crossing, deferred");

        // Directly: the arm fires inside `checkpoint()` and propagates.
        k.panic_at_the_next(step);
        let unwound = catch_unwind(AssertUnwindSafe(|| k.checkpoint()));
        let payload = unwound.expect_err("the armed step unwinds the call");
        assert_eq!(panic_message(&*payload), format!("injected panic at {step:?}"));
        assert!(!k.is_poisoned());
        assert!(!k.checkpoint_due(), "{step:?}: cleared first, before the run that unwound");
        assert_eq!(tmp.exists(), leaves_the_tmp, "{step:?}: what the unwind leaves");
        assert_eq!(checkpoint_count(dir.path()), 0);

        // Through the backstop: a crossing with the flag clear defers; the
        // next, finding it set, runs inline — and unwinds out of `transact`.
        assert_eq!(commit(&k, 2), Seq(2));
        assert!(k.checkpoint_due(), "{step:?}: the second crossing, deferred again");
        k.panic_at_the_next(step);
        let unwound = catch_unwind(AssertUnwindSafe(|| commit(&k, 3)));
        let payload = unwound.expect_err("the backstop's checkpoint unwinds out of transact");
        assert_eq!(panic_message(&*payload), format!("injected panic at {step:?}"));
        // …AFTER the commit landed.
        assert_eq!(k.current_seq(), Seq(3), "{step:?}: the order advanced");
        assert_eq!(items(&k), vec![1, 2, 3], "{step:?}: the root installed");
        assert!(!k.is_poisoned());
        assert!(k.armed_steps().is_empty(), "{step:?}: the arm fired once");
        assert!(!k.checkpoint_due(), "{step:?}: the backstop's call cleared the flag first");
        assert_eq!(tmp.exists(), leaves_the_tmp, "{step:?}: what the unwind leaves");
        assert_eq!(checkpoint_count(dir.path()), 0, "{step:?}: no base landed");
        // The kernel commits on.
        assert_eq!(commit(&k, 4), Seq(4));

        // The reopen: the stray reported by its size where one was left —
        // a whole checkpoint, its header and its body — and every commit
        // held.
        let left = leaves_the_tmp.then(|| fs::metadata(&tmp).unwrap().len());
        assert!(left.is_none_or(|len| len > 88), "{step:?}: a header and a body: {left:?}");
        drop(k);
        let k = Kernel::open(cfg, genesis()).unwrap();
        assert_eq!(k.stray_checkpoint_removed(), left, "{step:?}: the open reports the stray");
        assert!(!tmp.exists());
        assert_eq!(items(&k), vec![1, 2, 3, 4]);
        assert_eq!(k.current_seq(), Seq(4));
    }
}

#[test]
fn an_auto_triggered_checkpoint_failure_never_fails_the_committed_txn() {
    // §3/§6: the txn is already durable and installed, so there is no sound
    // path for the checkpoint's error through TxnError — surfacing it would
    // un-acknowledge a real effect. It is logged and dropped.
    let dir = tempdir().unwrap();
    let mut cfg = cfg_fsync(dir.path());
    cfg.checkpoint = CheckpointPolicy::EveryN(1);
    let k = Kernel::open(cfg, FragileWorld::default()).unwrap();
    k.transact::<_, ()>(&[], |stg| {
        stg.push(Fragility::Sound);
        Ok(())
    })
    .unwrap();
    assert!(ckpt_file(dir.path(), 1).exists(), "the auto-trigger is live");
    let (_, seq) = k
        .transact::<_, ()>(&[], |stg| {
            stg.push(Fragility::Break);
            Ok(())
        })
        .expect("the commit is durable and installed; its checkpoint's failure is not its own");
    assert_eq!(seq, Seq(2));
    assert!(!ckpt_file(dir.path(), 2).exists()); // the checkpoint did fail
    assert_eq!(k.current_seq(), Seq(2));
}

/// …and the landing ANSWERS what it reclaimed (§6, the kernel's read seam
/// for the landing's line): `None` before any landing, `Some(0)` for a
/// landing that removed no segment — it says so — and the removed segments'
/// lengths, read before their removal, for one that did.
#[test]
fn reclamation_floor_is_the_oldest_retained_checkpoint() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    assert_eq!(k.last_reclaimed_bytes(), None, "no landing yet");
    for _ in 0..4 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    assert_eq!(
        k.last_reclaimed_bytes(),
        Some(0),
        "seg-1 is active and never range-reclaimed: a landing that reclaimed nothing says so"
    );
    for _ in 0..4 {
        commit_blob(&k); // txn 5 rotates into seg-5 (§1 name-by-firstSeq)
    }
    assert_eq!(commit_blob(&k), Seq(9)); // …and txn 9 into seg-9, CLOSING seg-5
    assert!(
        seg_file(dir.path(), 9).exists(),
        "the fixture must rotate twice"
    );
    let seg1_len = fs::metadata(seg_file(dir.path(), 1)).unwrap().len();
    assert_eq!(k.checkpoint().unwrap(), Seq(9));
    // Reclamation dropped the closed segment wholly below the OLDEST retained
    // checkpoint (S_old = 4)…
    assert!(!seg_file(dir.path(), 1).exists());
    assert_eq!(
        k.last_reclaimed_bytes(),
        Some(seg1_len),
        "the removed segment's length, read before its removal"
    );
    // …and kept the closed one above it, which covers (4, 8]: a floor at the
    // NEWEST checkpoint deletes it (§6).
    assert!(
        seg_file(dir.path(), 5).exists(),
        "reclamation ran below the newest retained checkpoint, taking the journal \
         the older base replays"
    );
    drop(k);
    // That floor is what makes the fallback real: corrupt the newest
    // checkpoint and recovery replays from the older RETAINED base — genesis
    // is gone, so no other base can carry the answer.
    let cp = ckpt_file(dir.path(), 9);
    let len = fs::metadata(&cp).unwrap().len();
    flip_byte(&cp, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k).len(), 9);
    assert_eq!(k.snapshot().world().sum, 9 * BLOB as u64);
    assert_eq!(k.current_seq(), Seq(9));
}

/// Retention keeps the newest `N` — and KEEPS THE BASES THAT LOAD (§6):
/// after an open that skipped the damaged `B` and loaded from `A`, the first
/// landing `C` keeps `A` beside `C` and removes `B` as excess, where
/// counting by name would keep `B` and delete `A`, the one base that
/// loaded; a second open, `A` and `C` sound, skips nothing; and the landing
/// after that counts as it always did. The claim with no skip is the first
/// half, unchanged.
#[test]
fn retention_keeps_the_newest_n_checkpoints() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    for x in 1..=3u64 {
        commit(&k, x);
        assert_eq!(k.checkpoint().unwrap(), Seq(x));
    }
    // The third checkpoint pushes the first out (§6).
    assert_eq!(checkpoint_count(dir.path()), 2);
    assert!(!ckpt_file(dir.path(), 1).exists());
    assert!(ckpt_file(dir.path(), 2).exists());
    assert!(ckpt_file(dir.path(), 3).exists());
    drop(k);
    // What retention keeps is a REAL fallback base: destroy the newest and
    // recovery lands on the whole world from the one below it.
    let cp = ckpt_file(dir.path(), 3);
    let len = fs::metadata(&cp).unwrap().len();
    flip_byte(&cp, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![1, 2, 3]);
    assert_eq!(k.snapshot().world().sum, 6);
    assert_eq!(k.current_seq(), Seq(3));

    // RETENTION KEEPS THE BASES THAT LOAD: A = 2 loaded, B = 3 skipped.
    let recovery = k.recovery().expect("journaled");
    assert_eq!(recovery.start_point, Seq(2), "A loaded");
    let skipped: Vec<Seq> = recovery.skipped.iter().map(|b| b.seq).collect();
    assert_eq!(skipped, vec![Seq(3)], "B skipped");
    // The first landing after the skip, C = 4, keeps A and C and removes B.
    commit(&k, 4);
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    assert_eq!(checkpoint_count(dir.path()), 2);
    assert!(ckpt_file(dir.path(), 2).exists(), "A, the base the open loaded from, stands");
    assert!(!ckpt_file(dir.path(), 3).exists(), "B, the skipped base, is removed as excess");
    assert!(ckpt_file(dir.path(), 4).exists(), "C, the new base");
    drop(k);
    // A second open — A and C sound — skips nothing; with B gone, the damage
    // that refused it can refuse nothing.
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let recovery = k.recovery().expect("journaled");
    assert_eq!(recovery.start_point, Seq(4));
    assert!(recovery.skipped.is_empty(), "nothing skipped: {recovery:?}");
    assert_eq!(items(&k), vec![1, 2, 3, 4]);
    // …and the landing after that counts as it always did: the newest two.
    commit(&k, 5);
    assert_eq!(k.checkpoint().unwrap(), Seq(5));
    assert!(!ckpt_file(dir.path(), 2).exists(), "A, now the oldest of three, goes");
    assert!(ckpt_file(dir.path(), 4).exists() && ckpt_file(dir.path(), 5).exists());
}

/// §6, the rule's reason: after an open that skipped the newest base `B` and
/// loaded from `A`, the first landing's RECLAMATION FLOOR is `A`'s seq — the
/// oldest base KEPT — so the journal `A` replays through survives the
/// landing, and a damage to the new base `C` still leaves `A` a base that
/// carries the whole world. Counting by name would set the floor at `B`,
/// reclaim the segment below it, and leave the board on `C` alone with
/// genesis gone: one more damage, and the open refuses.
#[test]
fn the_first_landing_after_a_skip_reclaims_below_the_loaded_base_not_the_skipped_one() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    for _ in 0..4 {
        commit_blob(&k); // Seqs 1..=4 fill seg-1 past the threshold
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(4)); // A
    for _ in 0..4 {
        commit_blob(&k); // 5 rotates into seg-5; 6..=8 fill it
    }
    assert_eq!(commit_blob(&k), Seq(9)); // 9 rotates into seg-9, CLOSING seg-5 (5..=8)
    assert_eq!(k.checkpoint().unwrap(), Seq(9)); // B: keeps {A, B}, reclaims seg-1 below A
    assert!(!seg_file(dir.path(), 1).exists(), "the fixture must reclaim genesis");
    assert!(seg_file(dir.path(), 5).exists(), "…and keep the segment above A");
    drop(k);
    // B damaged: the open loads A and replays 5..=9 through seg-5 and seg-9.
    let b = ckpt_file(dir.path(), 9);
    let len = fs::metadata(&b).unwrap().len();
    flip_byte(&b, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let recovery = k.recovery().expect("journaled");
    assert_eq!((recovery.start_point, recovery.replayed), (Seq(4), 5), "A loaded, five replayed");
    let skipped: Vec<Seq> = recovery.skipped.iter().map(|s| s.seq).collect();
    assert_eq!(skipped, vec![Seq(9)], "B skipped");
    for _ in 0..3 {
        commit_blob(&k); // 10..=12 fill seg-9 past the threshold
    }
    assert_eq!(commit_blob(&k), Seq(13)); // 13 rotates into seg-13, CLOSING seg-9 (9..=12)
    assert_eq!(k.checkpoint().unwrap(), Seq(13)); // C

    // The landing kept A and C, removed B, and reclaimed below A — nothing:
    // seg-5 reaches 8, above A — where a floor at B would have taken seg-5.
    assert!(ckpt_file(dir.path(), 4).exists() && ckpt_file(dir.path(), 13).exists());
    assert!(!ckpt_file(dir.path(), 9).exists(), "B removed as excess");
    assert_eq!(checkpoint_count(dir.path()), 2);
    assert!(seg_file(dir.path(), 5).exists(), "the journal A replays through survives the landing");
    assert_eq!(
        k.last_reclaimed_bytes(),
        Some(0),
        "the floor is A's seq; nothing lies wholly below"
    );
    drop(k);
    // What the floor is for: damage C, and the open still lands on the whole
    // world from A — through the segment the old rule would have reclaimed.
    let c = ckpt_file(dir.path(), 13);
    let len = fs::metadata(&c).unwrap().len();
    flip_byte(&c, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(k.recovery().unwrap().start_point, Seq(4), "A carries the world again");
    assert_eq!(items(&k).len(), 13);
    assert_eq!(k.current_seq(), Seq(13));
}

/// A checkpoint written OVER a skipped name is a base again: the open
/// skipped `B` at the head, the first `checkpoint()` with nothing committed
/// since writes `B`'s name anew, sound, and retention counts it — kept
/// beside `A`, not passed over as the skipped file it replaced — and the
/// landing after it keeps the newest two as ever, the rewritten one among
/// them; a reopen loads it and skips nothing.
#[test]
fn a_checkpoint_written_over_a_skipped_name_is_a_base_again() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    commit(&k, 1);
    assert_eq!(k.checkpoint().unwrap(), Seq(1)); // A
    commit(&k, 2);
    assert_eq!(k.checkpoint().unwrap(), Seq(2)); // B, at the head
    drop(k);
    let b = ckpt_file(dir.path(), 2);
    let len = fs::metadata(&b).unwrap().len();
    flip_byte(&b, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(k.recovery().unwrap().start_point, Seq(1), "A loaded, B skipped");
    assert_eq!(k.current_seq(), Seq(2), "the head is B's seq");
    // The write at the head lands on B's name, sound, and is counted: kept
    // beside A, where passing the name over would delete the base just
    // written.
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    assert!(ckpt_file(dir.path(), 1).exists() && ckpt_file(dir.path(), 2).exists());
    assert_eq!(checkpoint_count(dir.path()), 2);
    assert_eq!(k.checkpoint_header(Seq(2)).map(|h| h.chain_head), Some(k.chain_head()));
    // The landing after it, in the same kernel: the newest two, the
    // rewritten base among them — its name is passed over no longer.
    commit(&k, 3);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    assert!(!ckpt_file(dir.path(), 1).exists(), "A, the oldest of three, goes");
    assert!(ckpt_file(dir.path(), 2).exists(), "the rewritten base stands");
    assert!(ckpt_file(dir.path(), 3).exists());
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let recovery = k.recovery().unwrap();
    assert_eq!((recovery.start_point, recovery.skipped.len()), (Seq(3), 0));
    assert_eq!(items(&k), vec![1, 2, 3]);
}

/// THE STEP IS NAMED (§6): a failure after the base LANDED says which of
/// the three steps after the rename failed — the directory's fsync,
/// retention, the journal's reclamation — as `CheckpointError::Landed`'s
/// `step`, the cause beside it and under `source()`, the `Display` carrying
/// both; the base stands in every case, and a later call lands. A failure
/// BEFORE the rename carries no step: it is `Io`, and no base landed.
#[test]
fn a_failure_after_the_base_landed_names_its_step() {
    // The directory's fsync, through the seam.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    commit(&k, 1);
    k.fail_the_next(Step::CheckpointDirSync, io::ErrorKind::StorageFull);
    let e = k.checkpoint().expect_err("the directory sync fails");
    assert!(
        matches!(e, CheckpointError::Landed { step: LandedStep::DirectorySync, .. }),
        "got {e:?}"
    );
    let text = e.to_string();
    assert!(text.contains("landed") && text.contains("StorageFull"), "{text}");
    let source = std::error::Error::source(&e).expect("the cause travels");
    assert!(source.to_string().contains("CheckpointDirSync"), "{source}");
    assert!(ckpt_file(dir.path(), 1).exists(), "the base landed");

    // Retention: a directory squatting on a name retention must remove — a
    // base by name, the oldest, which `remove_file` refuses.
    commit(&k, 2);
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    fs::create_dir(ckpt_file(dir.path(), 0)).unwrap();
    commit(&k, 3);
    let e = k.checkpoint().expect_err("retention cannot remove a directory");
    assert!(matches!(e, CheckpointError::Landed { step: LandedStep::Retention, .. }), "got {e:?}");
    assert!(e.to_string().contains("retention"), "{e}");
    assert!(std::error::Error::source(&e).is_some());
    assert!(ckpt_file(dir.path(), 3).exists(), "the base landed");
    assert!(ckpt_file(dir.path(), 1).exists(), "retention stopped at the name it could not remove");
    fs::remove_dir(ckpt_file(dir.path(), 0)).unwrap();
    assert_eq!(k.checkpoint().unwrap(), Seq(3), "the retry lands and applies the retention");
    assert_eq!(checkpoint_count(dir.path()), 2);

    // The journal's reclamation: a directory squatting on the closed
    // segment's name below the floor.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_retain(dir.path(), 1), genesis()).unwrap();
    for _ in 0..5 {
        commit_blob(&k); // four fill seg-1 past the threshold; the fifth rotates
    }
    assert_eq!(segment_count(dir.path()), 2, "the fixture must rotate");
    let seg1 = seg_file(dir.path(), 1);
    fs::remove_file(&seg1).unwrap();
    fs::create_dir(&seg1).unwrap();
    let e = k.checkpoint().expect_err("reclamation cannot remove a directory");
    assert!(
        matches!(e, CheckpointError::Landed { step: LandedStep::Reclamation, .. }),
        "got {e:?}"
    );
    assert!(e.to_string().contains("reclamation"), "{e}");
    assert!(std::error::Error::source(&e).is_some());
    assert!(ckpt_file(dir.path(), 5).exists(), "the base landed");
    assert_eq!(k.last_reclaimed_bytes(), None, "a failed call is no landing");
    fs::remove_dir(&seg1).unwrap();
    assert_eq!(k.checkpoint().unwrap(), Seq(5), "the retry lands");
    assert_eq!(k.last_reclaimed_bytes(), Some(0), "…and finds nothing left to reclaim");

    // Before the rename: no step, and no base.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 1);
    k.fail_the_next(Step::CheckpointSync, io::ErrorKind::StorageFull);
    let e = k.checkpoint().expect_err("the sync fails");
    assert!(matches!(e, CheckpointError::Io(_)), "no step before the rename: {e:?}");
    assert!(std::error::Error::source(&e).is_some());
    assert_eq!(checkpoint_count(dir.path()), 0, "no base landed");
}

/// THE HEADER BY SEQ: `checkpoint_header` answers the header of the one base
/// named — the start point's after an open that skipped a newer base, which
/// is what a caller sizes a floor by where the newest file's header is the
/// skipped base's claim — equal to the file's by its seq and its length;
/// `None` for a seq no checkpoint was taken at, for one retention has
/// removed, for genesis, and in memory; and a damaged BODY still answers its
/// header, as the newest read does.
#[test]
fn checkpoint_header_answers_the_start_points_header_by_its_seq() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    assert_eq!(k.checkpoint_header(Seq(1)), None, "no checkpoint yet");
    for x in 1..=2u64 {
        commit(&k, x);
        assert_eq!(k.checkpoint().unwrap(), Seq(x));
    }
    let one = k.checkpoint_header(Seq(1)).expect("the base at 1 answers its header");
    assert_eq!(one.seq, Seq(1));
    assert_eq!(one.len, fs::metadata(ckpt_file(dir.path(), 1)).unwrap().len());
    assert_eq!(k.checkpoint_header(Seq(2)), k.newest_checkpoint(), "the newest, by its seq");
    assert_eq!(k.checkpoint_header(Seq(3)), None, "no checkpoint was taken at 3");
    assert_eq!(k.checkpoint_header(Seq(0)), None, "genesis is no checkpoint");
    drop(k);
    // The newest base's body damaged: the open loads the older, and the
    // start point's header is the one to size by — the newest file's answers
    // too, its header being intact, and that claim is the one a caller must
    // not size by.
    let two = ckpt_file(dir.path(), 2);
    let len = fs::metadata(&two).unwrap().len();
    flip_byte(&two, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let start = k.recovery().unwrap().start_point;
    assert_eq!(start, Seq(1));
    let header = k.checkpoint_header(start).expect("the start point's header");
    assert_eq!(header.len, fs::metadata(ckpt_file(dir.path(), 1)).unwrap().len());
    assert_eq!(k.newest_checkpoint().map(|h| h.seq), Some(Seq(2)), "the newest file still answers");
    assert!(k.checkpoint_header(Seq(2)).is_some(), "…by its seq too: the body is not verified");
    // The first landing removes the skipped base and keeps the start point:
    // the removed one answers `None`, the kept one as before.
    commit(&k, 3);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    assert_eq!(k.checkpoint_header(Seq(2)), None, "removed by retention");
    assert_eq!(k.checkpoint_header(Seq(1)), Some(header));
    // The landing after that removes the start point as any base.
    commit(&k, 4);
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    assert_eq!(k.checkpoint_header(Seq(1)), None);
    let in_memory = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    assert_eq!(in_memory.checkpoint_header(Seq(0)), None, "no directory, no header");
}

#[test]
fn every_n_trigger_fires_on_commit_and_manual_calls_do_not_reset_it() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 3);
    cfg.checkpoint = CheckpointPolicy::EveryN(3);
    let k = Kernel::open(cfg, genesis()).unwrap();
    commit(&k, 1);
    commit(&k, 2);
    assert_eq!(checkpoint_count(dir.path()), 0); // threshold not crossed
    assert_eq!(k.checkpoint().unwrap(), Seq(2)); // caller-invoked
    assert!(ckpt_file(dir.path(), 2).exists());
    // A caller-invoked checkpoint() cannot touch the applier-locked cadence
    // counters, so the third commit still crosses EveryN(3) and auto-fires.
    commit(&k, 3);
    assert!(ckpt_file(dir.path(), 3).exists(), "auto-trigger did not fire");
}

#[test]
fn every_n_restarts_its_window_at_the_crossing() {
    // §6: a crossing resets the counters, so the next window starts at that
    // commit — which is what makes `EveryN(n)` "every n" rather than "every
    // commit from the nth on", a degeneration nothing else would report.
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 4);
    cfg.checkpoint = CheckpointPolicy::EveryN(3);
    let k = Kernel::open(cfg, genesis()).unwrap();
    for x in 1..=6u64 {
        commit(&k, x);
    }
    assert!(
        ckpt_file(dir.path(), 3).exists(),
        "the first window did not fire"
    );
    assert!(
        !ckpt_file(dir.path(), 4).exists(),
        "the window did not restart"
    );
    assert!(!ckpt_file(dir.path(), 5).exists());
    assert!(
        ckpt_file(dir.path(), 6).exists(),
        "the second window did not fire"
    );
    assert_eq!(checkpoint_count(dir.path()), 2);
}

#[test]
fn manual_policy_never_auto_checkpoints() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // Manual
    for x in 0..5 {
        commit(&k, x);
    }
    assert_eq!(checkpoint_count(dir.path()), 0);
}

#[test]
fn journal_bytes_trigger_counts_bytes_not_commits() {
    // The threshold is one no count of commits can reach, so the trigger
    // fires only on the commit that actually appends that many bytes (§6).
    let dir = tempdir().unwrap();
    let mut cfg = cfg_fsync(dir.path());
    cfg.checkpoint = CheckpointPolicy::JournalBytes(4096);
    let k = Kernel::open(cfg, genesis()).unwrap();
    for x in 1..=5u64 {
        commit(&k, x); // a few dozen journal bytes each
    }
    assert_eq!(checkpoint_count(dir.path()), 0);
    commit_blob(&k); // one commit, far past the threshold
    assert!(ckpt_file(dir.path(), 6).exists(), "the byte trigger did not fire");
}

#[test]
fn journal_bytes_restarts_its_window_at_the_crossing() {
    // §6: a crossing resets EVERY counter, so `JournalBytes(n)` is "every n
    // bytes" rather than "every commit once n bytes have first gone by".
    // `every_n_restarts_its_window_at_the_crossing` observes the commit
    // counter; this observes the byte counter beside it.
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 8); // keep every base a stuck window would write
    cfg.checkpoint = CheckpointPolicy::JournalBytes(4096);
    let k = Kernel::open(cfg, genesis()).unwrap();
    assert_eq!(commit_blob(&k), Seq(1)); // one commit, far past the threshold
    assert!(ckpt_file(dir.path(), 1).exists(), "the first window did not fire");
    for x in 2..=6u64 {
        commit(&k, x); // 88 journal bytes each: nowhere near a fresh window
    }
    assert_eq!(
        checkpoint_count(dir.path()),
        1,
        "the byte window did not restart"
    );
    assert_eq!(commit_blob(&k), Seq(7));
    assert!(ckpt_file(dir.path(), 7).exists(), "the second window did not fire");
}

#[test]
fn a_zero_step_op_neither_journals_nor_advances_the_cadence() {
    // §6: a zero-step op installs nothing, so it never advances a counter or
    // trips the trigger — which is also what keeps `Interval` measuring from
    // real work rather than from read traffic.
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 3);
    cfg.checkpoint = CheckpointPolicy::EveryN(2);
    let k = Kernel::open(cfg, genesis()).unwrap();
    let seg = seg_file(dir.path(), 1);
    for _ in 0..3 {
        assert_eq!(k.transact(&[], |_| Ok::<_, ()>(())).unwrap().1, Seq(0));
    }
    assert_eq!(
        fs::metadata(&seg).unwrap().len(),
        0,
        "a zero-step op journals nothing"
    );
    assert_eq!(checkpoint_count(dir.path()), 0);
    commit(&k, 1); // the FIRST commit: 1 of 2
    assert_eq!(
        checkpoint_count(dir.path()),
        0,
        "the zero-step ops advanced the cadence"
    );
    k.transact(&[], |_| Ok::<_, ()>(())).unwrap();
    commit(&k, 2); // the second commit crosses
    assert!(
        ckpt_file(dir.path(), 2).exists(),
        "the trigger counts commits, not calls"
    );
}

#[test]
fn interval_is_evaluated_on_commit_never_on_a_clock() {
    // Duration::ZERO: the window is always elapsed, so the first COMMIT
    // crosses — while a quiescent kernel fires nothing at all, which is what
    // lets §6 do without a timer thread and its shutdown coordination.
    let dir = tempdir().unwrap();
    let mut cfg = cfg_fsync(dir.path());
    cfg.checkpoint = CheckpointPolicy::Interval(Duration::ZERO);
    let k = Kernel::open(cfg, genesis()).unwrap();
    k.transact(&[], |_| Ok::<_, ()>(())).unwrap(); // a read: nothing new to persist
    assert_eq!(
        checkpoint_count(dir.path()),
        0,
        "a quiescent kernel fired the trigger"
    );
    commit(&k, 1);
    assert!(
        ckpt_file(dir.path(), 1).exists(),
        "the first commit past the window did not fire"
    );
}

#[test]
fn interval_does_not_fire_before_its_window_elapses() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_fsync(dir.path());
    cfg.checkpoint = CheckpointPolicy::Interval(Duration::from_secs(3600));
    let k = Kernel::open(cfg, genesis()).unwrap();
    for x in 1..=5 {
        commit(&k, x);
    }
    assert_eq!(checkpoint_count(dir.path()), 0);
}
