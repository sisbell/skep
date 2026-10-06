//! Recovery (§7) and the kernel's lifecycle: exactly-once replay, the torn
//! tail cut and its coordinates reused, halts that cut nothing, the fallback
//! chain, and one live kernel per journal.

use super::*;
use crate::mutilate::{append_bytes, ckpt_file, copy_dir, flip_byte, seg_file, truncate_file};
use skep_kernel::OpenError;
use tempfile::tempdir;

#[test]
fn recovery_replays_journal_exactly_once() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // Fsync-path open runs rebuild_derived once on the loaded base (genesis
    // here) — and never again on live commits.
    assert_eq!(k.snapshot().world().rebuilds, 1);
    commit(&k, 1);
    commit(&k, 2);
    commit(&k, 3);
    assert_eq!(k.snapshot().world().rebuilds, 1);
    k.flush().unwrap(); // no-op Ok under per-commit Fsync
    drop(k);

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // apply is non-idempotent, so equality proves each committed record was
    // folded exactly once, in Seq order (A6).
    assert_eq!(items(&k), vec![1, 2, 3]);
    assert_eq!(k.snapshot().world().sum, 6);
    assert_eq!(k.snapshot().world().rebuilds, 1);
    assert_eq!(k.current_seq(), Seq(3));
    drop(k);
    // Recovery is idempotent.
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![1, 2, 3]);
    assert_eq!(k.current_seq(), Seq(3));
}

#[test]
fn recovery_with_checkpoint_replays_only_the_tail() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 1);
    commit(&k, 2);
    commit(&k, 3);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    commit(&k, 4);
    commit(&k, 5);
    drop(k);

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // Checkpoint embodies Seq ≤ 3; replay covers exactly (3, 5] — no record
    // twice, none skipped (§6 complementarity). The skip-serialized hint was
    // reseeded by rebuild_derived for the prefix and folded by apply for the
    // tail: sum == 15 proves both paths agree (§7 trait contract).
    assert_eq!(items(&k), vec![1, 2, 3, 4, 5]);
    assert_eq!(k.snapshot().world().sum, 15);
    assert_eq!(k.snapshot().world().rebuilds, 1);
    assert_eq!(k.current_seq(), Seq(5));
}

#[test]
fn torn_tail_is_physically_truncated_and_seqs_reused() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 6); // T1 rec/marker, T2 rec/marker, T3 rec/marker
    // Crash mid-append of T3's marker: no committed marker → un-acked tail.
    truncate_file(&seg, spans[5].0 + 3);

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
    // The tail (T3's intact record included — its txn holds no committed
    // marker) was DURABLY removed before writes were served (§7), cutting at
    // T2's marker frame end.
    assert_eq!(fs::metadata(&seg).unwrap().len(), spans[4].0);
    // Under Rollback the next session reuses the discarded coordinates —
    // safe exactly because the stale tail is gone (§1/§7 Txn uniqueness).
    assert_eq!(commit(&k, 30), Seq(3));
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20, 30]);
    assert_eq!(k.current_seq(), Seq(3));
}

#[test]
fn with_no_committed_marker_at_all_everything_scanned_is_tail() {
    // §7's tail rule at its empty edge, which every other torn-tail fixture
    // sits above: with no committed marker anywhere, the first scanned segment
    // is cut at offset 0. What would survive otherwise is the torn
    // transaction's whole RECORD frame, carrying `Txn(1)` — the identity the
    // next session's first commit takes — and the recovery after that groups
    // the two by `txn`, meets `Seq(1)` twice, and drops an acknowledged commit.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 2); // T1's record and its marker
    // Crash mid-append of T1's marker: its record frame is whole, and nothing
    // is committed.
    truncate_file(&seg, spans[1].0 + 3);

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(k.current_seq(), Seq(0));
    assert_eq!(items(&k), Vec::<u64>::new());
    assert_eq!(
        fs::metadata(&seg).unwrap().len(),
        0,
        "the torn transaction's record frame survived recovery"
    );
    // …which is what makes reusing its coordinate, and its `Txn`, safe.
    assert_eq!(commit(&k, 20), Seq(1));
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(
        items(&k),
        vec![20],
        "an acknowledged commit was merged with the torn transaction whose Txn it reused"
    );
    assert_eq!(k.current_seq(), Seq(1));
}

#[test]
fn corruption_in_replayed_range_halts_with_marker_landing_payload() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    // Corrupt T2's record (an INTERIOR committed txn): the resync lands on
    // T2's marker, so at = last_seq + 1 = 3 and inferred max = 2 ∈ (0, 3] —
    // durable committed data the recovered state needs: halt, never drop (§7).
    flip_byte(&seg, spans[2].0 + FRAME_HEADER_LEN + 1);
    // A torn tail past the last committed marker, so there IS something a
    // truncation would take — without it the cut lands at end-of-file and no
    // assertion could tell a halt from a truncation.
    append_bytes(&seg, &[0xAB, 0xCD, 0xEF]);
    let before = fs::read(&seg).unwrap();

    let err = Kernel::open(cfg_fsync(dir.path()), genesis()).err().unwrap();
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(3), .. }),
        "got {err:?}"
    );
    // A halt cuts nothing: the classification precedes the tail truncation, so
    // the journal an operator images after a `Corruption` is the journal that
    // was there (§7 — destroying evidence ahead of intervention would be wrong).
    assert_eq!(
        fs::read(&seg).unwrap(),
        before,
        "a halted open truncated the journal"
    );
}

#[test]
fn corruption_below_s_load_is_harmless_including_the_boundary_frame() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    commit(&k, 40);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 8);
    // Corrupt T3's record. The resync lands on T3's marker: inferred max =
    // last_seq = 3 = S_load → HARMLESS (already embodied in the checkpoint),
    // even though the payload coordinate is S_load + 1 — classifying by `at`
    // instead of the inferred max would spuriously halt on exactly this
    // boundary frame (§7).
    flip_byte(&seg, spans[4].0 + FRAME_HEADER_LEN + 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20, 30, 40]);
    assert_eq!(k.snapshot().world().sum, 100);
    assert_eq!(k.current_seq(), Seq(4));
}

#[test]
fn an_unreadable_segment_fails_the_open_as_io_not_as_corruption() {
    // `Corruption` says the durable data itself is bad and an operator must
    // intervene; `Io` says this process could not read it. A segment the
    // process cannot READ is the second — and it must never be read AROUND,
    // which answers `Ok` with a world missing every record it held.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    for _ in 0..5 {
        commit_blob(&k); // four fill seg-1 past the threshold; the fifth rotates
    }
    drop(k);
    assert_eq!(segment_count(dir.path()), 2, "the fixture must rotate");

    // Unreadable, deterministically and without depending on privileges: a
    // directory bearing a segment's name. `list_segments` parses names and not
    // file types, which the `journal_path` caller contract already says. The
    // CLOSED segment, so a scan that read around it would answer `Ok` with a
    // world missing its four records rather than failing at the cut.
    let seg1 = seg_file(dir.path(), 1);
    fs::remove_file(&seg1).unwrap();
    fs::create_dir(&seg1).unwrap();

    let err = Kernel::open(cfg_fsync(dir.path()), genesis())
        .expect_err("an unreadable segment is not something to recover around");
    assert!(matches!(err, OpenError::Io(_)), "got {err:?}");
    // The cause travels, and it is the environment's — not the media's.
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn post_commit_rot_of_the_final_txn_demotes_w_silently() {
    // The documented §7 blind spot, asserted as specified: rot in the LAST
    // committed txn's record leaves its marker intact but checksum-failing,
    // W demotes to the prior marker, and the acked txn is silently discarded
    // as tail — no Corruption signal (out of scope for v1).
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    flip_byte(&seg, spans[4].0 + FRAME_HEADER_LEN + 1); // T3's record
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
    assert_eq!(fs::metadata(&seg).unwrap().len(), spans[4].0); // physically discarded
}

#[test]
fn bad_newest_checkpoint_falls_back_to_older_retained_base() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    commit(&k, 10);
    commit(&k, 20);
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    commit(&k, 30);
    commit(&k, 40);
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    drop(k);
    // Corrupt the newest checkpoint's body: its header checksum fails, and
    // recovery falls back to the older RETAINED base and replays more (§6/§7).
    let cp = ckpt_file(dir.path(), 4);
    let len = fs::metadata(&cp).unwrap().len();
    flip_byte(&cp, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20, 30, 40]);
    assert_eq!(k.snapshot().world().sum, 100);
    assert_eq!(k.current_seq(), Seq(4));
}

#[test]
fn recovery_skips_only_the_segments_the_base_already_embodies() {
    // §7's skip, which no other test reaches: every multi-segment fixture in
    // the suite recovers from genesis, and every checkpoint fixture has one
    // segment. A skip that is one segment too greedy loses the records in
    // (S_load, that segment's last] and answers `Ok` with a short world.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    assert_eq!(commit_blob(&k), Seq(1)); // seg-1
    assert_eq!(k.checkpoint().unwrap(), Seq(1)); // holds the reclamation floor at 1
    for _ in 0..3 {
        commit_blob(&k); // Seqs 2..=4, filling seg-1 past the threshold
    }
    assert_eq!(commit_blob(&k), Seq(5)); // rotates into seg-5
    assert_eq!(commit_blob(&k), Seq(6));
    assert_eq!(k.checkpoint().unwrap(), Seq(6)); // S_load on reopen; S_old is still 1
    for _ in 0..2 {
        commit_blob(&k); // Seqs 7..=8, filling seg-5 past the threshold
    }
    assert_eq!(commit_blob(&k), Seq(9)); // rotates into seg-9
    drop(k);
    assert_eq!(segment_count(dir.path()), 3, "the fixture must rotate twice");
    assert!(
        seg_file(dir.path(), 1).exists(),
        "…and keep the segment below the base"
    );

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // seg-1's inferred lastSeq is 4 ≤ 6, so it is skipped unopened; seg-5
    // STRADDLES the base (it covers 5..=8) and must be scanned for 7 and 8;
    // seg-9 is active and is always scanned.
    assert_eq!(k.current_seq(), Seq(9));
    assert_eq!(items(&k).len(), 9);
    assert_eq!(k.snapshot().world().sum, 9 * BLOB as u64);
}

#[test]
fn the_format_probe_opens_the_segment_the_scan_begins_at_and_names_the_base() {
    // `open` reads one sync word before it scans: the first of the first
    // segment the SCAN will read, once the base has said where that is. A
    // damaged word in a closed segment the base embodies is never read — the
    // base carries those records — so the open succeeds; one in the segment
    // the scan reads first is refused even though its frame lies below the
    // base (the probe reads no `Seq`), and is named at the base's own
    // coordinate. Every other probe fixture at this tier sits at genesis,
    // where "the first scanned segment" is the first segment and "the base's
    // coordinate" is 0.
    let tmp = tempdir().unwrap();
    let fixture = tmp.path().join("fixture");
    let k = Kernel::open(cfg_fsync(&fixture), genesis()).unwrap(); // retain 2
    assert_eq!(commit_blob(&k), Seq(1));
    assert_eq!(k.checkpoint().unwrap(), Seq(1)); // holds the reclamation floor at 1
    for _ in 0..3 {
        commit_blob(&k); // Seqs 2..=4, filling seg-1 past the threshold
    }
    assert_eq!(commit_blob(&k), Seq(5)); // rotates into seg-5
    assert_eq!(commit_blob(&k), Seq(6));
    assert_eq!(k.checkpoint().unwrap(), Seq(6)); // the base a reopen selects
    for _ in 0..2 {
        commit_blob(&k); // Seqs 7..=8, filling seg-5 past the threshold
    }
    assert_eq!(commit_blob(&k), Seq(9)); // rotates into seg-9
    drop(k);
    assert_eq!(segment_count(&fixture), 3, "the fixture must rotate twice");

    // seg-1 (Seqs 1..=4) lies wholly below the base at 6: the scan skips it,
    // and so must the probe.
    let skipped = tmp.path().join("skipped");
    copy_dir(&fixture, &skipped);
    flip_byte(&seg_file(&skipped, 1), 3); // `SKJ4` → a foreign-shaped word
    let k = Kernel::open(cfg_fsync(&skipped), genesis())
        .expect("a damaged word in a segment the base embodies is no reason to halt");
    assert_eq!(k.current_seq(), Seq(9));
    assert_eq!(items(&k).len(), 9);
    drop(k);

    // seg-5 (Seqs 5..=8) straddles the base, so the scan reads it first —
    // and T5's damaged word, below the base, is refused all the same.
    let straddling = tmp.path().join("straddling");
    copy_dir(&fixture, &straddling);
    let seg5 = seg_file(&straddling, 5);
    flip_byte(&seg5, 3);
    let before = fs::read(&seg5).unwrap();
    match Kernel::<TestWorld>::open(cfg_fsync(&straddling), genesis()) {
        Err(OpenError::Corruption {
            at,
            cause: Some(cause),
        }) => {
            assert_eq!(at, Seq(6), "named at the base's own coordinate, where the scan begins");
            assert!(cause.to_string().contains("damaged sync word"), "got {cause}");
        }
        other => panic!("expected the damaged-sync-word halt at the base, got {other:?}"),
    }
    assert_eq!(fs::read(&seg5).unwrap(), before, "a halted open touched the segment");
}

#[test]
fn an_absent_segment_halts_as_a_chain_break_where_a_damaged_one_halts_as_a_run() {
    // Recovery's damage model WAS frames that fail their CRC, and an absent
    // closed segment was its documented blind spot: REMOVING a segment leaves
    // no run to classify and no gap to detect — §7 requires no `Seq`
    // contiguity, so a missing segment is indistinguishable from a burned
    // range by coordinates alone — and recovery answered `Ok` with a world
    // short by exactly that segment's records, at the true head, silently.
    // The commit chain (`SKJ3`, QUEUE item 10) closes it: every committed
    // transaction above the base carries SHA-256 over its predecessor's chain
    // value, and the first transaction after the hole chains from a
    // predecessor the scan never saw, so its link does not verify. Both
    // halves now HALT — `Corruption`, nothing folded, nothing cut — and what
    // this fixture makes the subject is the SYMMETRY: the same coordinate,
    // two accounts. A damaged segment is a corrupt run, which speaks first
    // and carries no cause; an absent one is a chain break, whose cause says
    // which link failed.
    let tmp = tempdir().unwrap();
    let fixture = tmp.path().join("fixture");
    let k = Kernel::open(cfg_fsync(&fixture), genesis()).unwrap();
    for _ in 0..5 {
        commit_blob(&k); // four fill seg-1; the fifth rotates into seg-5
    }
    for _ in 0..4 {
        commit_blob(&k); // three fill seg-5; the fourth rotates into seg-9
    }
    drop(k);
    assert_eq!(segment_count(&fixture), 3, "the fixture must rotate twice");

    // Damaged: the middle segment's frames stop passing their CRC, so the
    // resync opens a run inside (S_load, W] that lands on T9's first intact
    // frame — a loud halt at 9, the run's verdict, with no cause: the run's
    // own bytes are unreadable. (T9's link fails too — it chains from a T8
    // the run swallowed — but the run names the root cause and speaks first.)
    let damaged = tmp.path().join("damaged");
    copy_dir(&fixture, &damaged);
    let mid = seg_file(&damaged, 5);
    let len = fs::metadata(&mid).unwrap().len() as usize;
    fs::write(&mid, vec![0u8; len]).unwrap();
    let err = Kernel::<TestWorld>::open(cfg_fsync(&damaged), genesis())
        .expect_err("a corrupt run in the replayed range is a halt");
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(9), cause: None }),
        "a damaged segment is a corrupt run, named at the next intact frame: got {err:?}"
    );

    // Absent: the same records, unreachable the other way. The scan reads
    // seg-1 (T1..T4) and then seg-9; T9's marker chains from T8's value, the
    // scan's running value is T4's, so the link fails at T9's `last_seq` — a
    // CHAIN BREAK at 9, never a shorter world at the true head.
    let absent = tmp.path().join("absent");
    copy_dir(&fixture, &absent);
    fs::remove_file(seg_file(&absent, 5)).unwrap();
    let survivors = [seg_file(&absent, 1), seg_file(&absent, 9)];
    let found: Vec<Vec<u8>> = survivors.iter().map(|seg| fs::read(seg).unwrap()).collect();
    let err = Kernel::<TestWorld>::open(cfg_fsync(&absent), genesis())
        .expect_err("an absent closed segment is a chain break, not a shorter world");
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(9), cause: Some(_) }),
        "an absent segment is a chain break at the first transaction after it: got {err:?}"
    );
    assert!(err.to_string().contains("chain break"), "the account names the break: {err}");
    assert!(std::error::Error::source(&err).is_some(), "the cause travels");
    // A halt cuts nothing: the surviving segments are byte for byte as they
    // were found, and the refusal REPEATS — nothing was written, so nothing
    // repaired it, and an operator can act on what the second open says.
    for (seg, before) in survivors.iter().zip(&found) {
        assert_eq!(&fs::read(seg).unwrap(), before, "a halted open touched {}", seg.display());
    }
    assert!(matches!(
        Kernel::<TestWorld>::open(cfg_fsync(&absent), genesis()),
        Err(OpenError::Corruption { at: Seq(9), cause: Some(_) })
    ));
}

#[test]
fn recovery_deletes_the_wholly_later_segments_the_tail_spans() {
    // §7's tail truncation is two acts: cut the segment holding the last
    // committed marker, and DELETE every wholly-later segment. Only the first
    // is exercised elsewhere — every other fixture's tail sits in the segment
    // it cuts.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    for _ in 0..5 {
        commit_blob(&k); // four fill seg-1 past the threshold; the fifth rotates
    }
    drop(k);
    assert_eq!(segment_count(dir.path()), 2, "the fixture must rotate");
    let seg5 = seg_file(dir.path(), 5);
    let spans = frame_spans(&seg5);
    assert_eq!(spans.len(), 2); // T5's record and its marker
    // Crash mid-append of T5's marker: seg-5 holds no committed marker, so the
    // whole segment is tail and the cut lands at seg-1's end.
    truncate_file(&seg5, spans[1].0 + 3);

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(k.current_seq(), Seq(4));
    assert_eq!(items(&k).len(), 4);
    // DURABLY REMOVED, not merely filtered out of the fold: the appender
    // reopens the LAST segment on disk, so a survivor is the file the next
    // session appends into (§1/§7).
    assert!(!seg5.exists(), "the tail's later segment survived recovery");

    // …which is what makes reusing the discarded coordinate safe: the next
    // commit takes Seq(5) again, and the session after it recovers rather than
    // meeting one Seq presented twice.
    assert_eq!(commit_blob(&k), Seq(5));
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k).len(), 5);
    assert_eq!(k.current_seq(), Seq(5));
}

#[test]
fn an_exhausted_fallback_chain_refuses_to_open() {
    let dir = tempdir().unwrap();
    // Retain 1: newest is the sole base — no fallback (§6).
    let cfg = cfg_retain(dir.path(), 1);
    let k = Kernel::open(cfg.clone(), genesis()).unwrap();
    for _ in 0..8 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(8));
    drop(k);
    // Reclamation dropped seg-1, so the earliest surviving segment's firstSeq
    // is no longer Seq(1): genesis is unreachable. Destroy the sole retained
    // checkpoint → the whole fallback chain is exhausted (§6/§7).
    assert!(!seg_file(dir.path(), 1).exists());
    fs::remove_file(ckpt_file(dir.path(), 8)).unwrap();
    let err = Kernel::open(cfg, genesis()).err().unwrap();
    // No candidate was tried at all — the journal retains no checkpoint — so
    // there is no refusal to account for, and the variant says as much rather
    // than naming a remedy it cannot know.
    assert!(
        matches!(err, OpenError::BadCheckpoint { cause: None }),
        "got {err:?}"
    );
}

#[test]
fn open_creates_the_journal_directory_it_was_pointed_at() {
    // The `journal_path` caller contract: `open()` creates it if absent, which
    // is what lets a first run of a fresh install start at all.
    let tmp = tempdir().unwrap();
    let dir = tmp.path().join("not-yet");
    assert!(!dir.exists());
    let k = Kernel::open(cfg_fsync(&dir), genesis()).unwrap();
    assert_eq!(commit(&k, 1), Seq(1));
    drop(k);
    // …and what it created is a journal a reopen recovers from.
    let k = Kernel::open(cfg_fsync(&dir), genesis()).unwrap();
    assert_eq!(items(&k), vec![1]);
}

/// A `checkpoint.tmp` a crash left — no base, and room kept on the volume —
/// is REMOVED by the open, under the flock, and the fact reported with its
/// size for the daemon's startup line: the directory is the kernel's alone,
/// so the file is the kernel's to delete, and the operator's acts at the
/// floor stay two. Fixed at the open: a reopen with none standing answers
/// `None`, as the in-memory mode, which opens no directory, always does.
/// The bases beside it stand, and the world recovers whole (M-I5 (f);
/// the checkpoint's safety: the `.tmp` is never a base).
#[test]
fn an_open_removes_a_stray_checkpoint_tmp_and_answers_its_size() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(k.stray_checkpoint_removed(), None, "a fresh directory holds none");
    commit(&k, 1);
    assert_eq!(k.checkpoint().unwrap(), Seq(1));
    commit(&k, 2);
    drop(k);
    let junk = b"\xFF\x00a checkpoint a crash left half-written";
    let tmp = dir.path().join("checkpoint.tmp");
    fs::write(&tmp, junk).unwrap();

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(
        k.stray_checkpoint_removed(),
        Some(junk.len() as u64),
        "the open found it and removed it, reporting its size"
    );
    assert!(!tmp.exists(), "…and it is gone");
    assert_eq!(items(&k), vec![1, 2], "the base beside it stood and the tail replayed");
    assert!(ckpt_file(dir.path(), 1).exists(), "the real base is untouched");
    assert_eq!(k.checkpoint().unwrap(), Seq(2), "the next checkpoint builds through the name again");
    drop(k);

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(k.stray_checkpoint_removed(), None, "a report of this open, not of the last");
    let in_memory = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    assert_eq!(in_memory.stray_checkpoint_removed(), None, "no directory, no temp file");
}

#[test]
fn a_journal_admits_one_live_kernel_at_a_time() {
    let dir = tempdir().unwrap();
    let k1 = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // Exclusive advisory ownership (Lifecycle): appender OR recoverer, never
    // both — a second open() fails with the acquisition error.
    let err = Kernel::open(cfg_fsync(dir.path()), genesis()).err().unwrap();
    assert!(matches!(err, OpenError::Io(_)), "got {err:?}");
    // …and the exclusion ends with the kernel that held it, so the journal is
    // reopenable rather than owned for the life of the process.
    drop(k1);
    Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
}

#[test]
fn in_memory_mode_starts_from_genesis_and_recovers_nothing() {
    // The mode names no journal — [`Durability::InMemory`] carries no path
    // and no retention count — so "it writes nothing" needs no assertion
    // here; there is nothing to point a stray write at. What remains
    // checkable is the behaviour: genesis directly, an auto-trigger that
    // evaluates over a `checkpoint()` that is a no-op, and no recovery.
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::EveryN(1), // trigger evaluates; checkpoint() is a no-op
        salt: SaltSource::Seeded(TEST_SEED),
    };
    let k = Kernel::open(cfg.clone(), genesis()).unwrap();
    // "Directly from genesis": no load, no rebuild_derived (Lifecycle).
    assert_eq!(k.snapshot().world().rebuilds, 0);
    assert_eq!(commit(&k, 1), Seq(1));
    assert_eq!(commit(&k, 2), Seq(2));
    assert_eq!(k.checkpoint().unwrap(), Seq(2)); // no-op returning current_seq (§6)
    k.flush().unwrap();
    drop(k);
    // No journal → no recovery story: a reopen starts from genesis.
    let k = Kernel::open(cfg, genesis()).unwrap();
    assert_eq!(k.current_seq(), Seq(0));
    assert_eq!(items(&k), Vec::<u64>::new());
}
