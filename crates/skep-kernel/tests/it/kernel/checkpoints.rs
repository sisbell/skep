//! Checkpoints (§6): their failures and what each leaves behind, retention
//! and the reclamation floor, the on-commit trigger's discipline, and the
//! deferred arm — the due flag, the thread's call that clears it first, and
//! the backstop.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use super::*;
use crate::mutilate::{ckpt_file, flip_byte, seg_file};
use skep_kernel::CheckpointError;
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
/// window).
#[test]
fn a_second_crossing_with_the_flag_set_runs_inline_as_the_backstop() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 8);
    cfg.checkpoint = deferred_every(2);
    let k = Kernel::open(cfg, genesis()).unwrap();
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
    assert!(!k.checkpoint_due(), "an inline run clears the flag it was the backstop for");
    commit(&k, 9);
    commit(&k, 10);
    assert!(k.checkpoint_due(), "…and the next crossing is deferred");
    assert_eq!(checkpoint_count(dir.path()), 2);
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

#[test]
fn reclamation_floor_is_the_oldest_retained_checkpoint() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    for _ in 0..4 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    for _ in 0..4 {
        commit_blob(&k); // txn 5 rotates into seg-5 (§1 name-by-firstSeq)
    }
    assert_eq!(commit_blob(&k), Seq(9)); // …and txn 9 into seg-9, CLOSING seg-5
    assert!(
        seg_file(dir.path(), 9).exists(),
        "the fixture must rotate twice"
    );
    assert_eq!(k.checkpoint().unwrap(), Seq(9));
    // Reclamation dropped the closed segment wholly below the OLDEST retained
    // checkpoint (S_old = 4)…
    assert!(!seg_file(dir.path(), 1).exists());
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
