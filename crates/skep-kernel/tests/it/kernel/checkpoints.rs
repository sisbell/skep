//! Checkpoints (§6): their failures and what each leaves behind, retention
//! and the reclamation floor, and the on-commit trigger's discipline.

use std::time::Duration;

use super::*;
use crate::mutilate::{ckpt_file, flip_byte, seg_file};
use skep_kernel::CheckpointError;
use tempfile::tempdir;

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
