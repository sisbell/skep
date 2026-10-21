//! Recovery (§7) and the kernel's lifecycle: exactly-once replay, the torn
//! tail cut and its coordinates reused, the damaged tail refused until its
//! cut is accepted by name — then kept, cut, and the order started past the
//! position it claimed — halts that cut nothing, the fallback chain, and one
//! live kernel per journal.

use std::io;

use super::*;
use crate::mutilate::{
    append_bytes, ckpt_file, copy_dir, flip_byte, rewrite_frame, seg_file, truncate_file,
    MARKER_LAST_SEQ_AT, MARKER_SIG_ALG_AT, RECORD_BYTES_AT,
};
use skep_kernel::{
    DamagedTail, DamagedTailTell, HistoryError, OpenError, TxnError, MAX_CRASH_TAIL_BYTES,
};
use tempfile::tempdir;

/// [`cfg_fsync`] with the damaged tail's cut accepted: the operator's word
/// for one open (`Durability::Fsync`'s `cut_damaged_tail`).
fn cfg_cutting(dir: &Path) -> KernelConfig {
    let mut cfg = cfg_fsync(dir);
    if let Durability::Fsync { cut_damaged_tail, .. } = &mut cfg.durability {
        *cut_damaged_tail = true;
    }
    cfg
}

/// Returns the damaged tail's halt: the coordinate and the typed cause.
///
/// It is `OpenError::Corruption` carrying a `DamagedTail`, which a caller
/// above reads back through the cause's downcast; anything else is a
/// finding.
fn damaged_tail_of(err: &OpenError) -> (Seq, DamagedTail) {
    match err {
        OpenError::Corruption { at, cause: Some(cause) } => {
            let damaged = cause
                .downcast_ref::<DamagedTail>()
                .unwrap_or_else(|| panic!("the ninth cause, typed: {err}"))
                .clone();
            (*at, damaged)
        }
        other => panic!("expected the damaged tail's halt, got {other:?}"),
    }
}

/// Sets `path`'s length to `len`, zero-filled: bytes no frame anchors.
fn extend_to(path: &Path, len: u64) {
    fs::OpenOptions::new().write(true).open(path).unwrap().set_len(len).unwrap();
}

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
    // The open's own report: genesis stood in, so every commit was replayed,
    // and a clean shutdown left nothing above the last marker to cut.
    let recovery = k.recovery().expect("journaled");
    assert_eq!((recovery.start_point, recovery.replayed, recovery.tail_cut), (Seq(0), 3, 0));
    drop(k);
    // Recovery is idempotent.
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![1, 2, 3]);
    assert_eq!(k.current_seq(), Seq(3));
    assert_eq!(k.recovery().unwrap().replayed, 3, "…and so is its report");
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
    // The report counts the tail alone: the two commits above the base.
    let recovery = k.recovery().expect("journaled");
    assert_eq!((recovery.start_point, recovery.replayed, recovery.tail_cut), (Seq(3), 2, 0));
    // A base taken AT the head replays nothing.
    assert_eq!(k.checkpoint().unwrap(), Seq(5));
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let recovery = k.recovery().expect("journaled");
    assert_eq!((recovery.start_point, recovery.replayed), (Seq(5), 0), "the base is the head");
    assert_eq!(items(&k), vec![1, 2, 3, 4, 5]);
}

/// `replayed` counts COMMITS, never records: a composite of three records is
/// one transaction under one marker, and the open reports it as one.
#[test]
fn replayed_counts_the_commits_folded_not_their_records() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let (_, composite) = k
        .transact(&[], |stg| {
            stg.push(TestRec::Append(1));
            stg.push(TestRec::Append(2));
            stg.push(TestRec::Append(3));
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(composite, Seq(3), "three records, one boundary");
    assert_eq!(commit(&k, 4), Seq(4));
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![1, 2, 3, 4], "four records folded");
    assert_eq!(k.recovery().unwrap().replayed, 2, "…in two commits");
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
    // …and the open REPORTS the cut: the bytes from T2's marker's end to the
    // torn end — T3's whole record frame and three bytes of its marker — and
    // the two commits the cut left standing, replayed.
    let recovery = k.recovery().expect("journaled");
    assert_eq!(recovery.tail_cut, spans[5].0 + 3 - spans[4].0, "the bytes cut, exactly");
    assert_eq!(recovery.replayed, 2);
    // A crash's torn tail holds an intact RECORD and a torn marker — nothing
    // no torn write leaves — so the cut is reported as the crash's alone,
    // claiming no position, from the byte T3's record began at, and its bytes
    // are cut and gone: kept nowhere, as §7 rules.
    assert_eq!(recovery.tail_cut_intact, 0, "a crash's torn tail is nothing but a crash's");
    assert_eq!(recovery.tail_cut_claimed, None, "a torn marker claims nothing");
    assert_eq!(recovery.tail_cut_from, Some(("seg-1.wal".to_string(), spans[4].0)));
    assert!(recovery.tail_cut_kept.is_empty(), "a crash's tail is kept nowhere");
    assert_eq!(kept_files(dir.path()), Vec::<String>::new());
    assert!(!recovery.began, "a journal stood: this open recovered it");
    // Under Rollback the next session reuses the discarded coordinates —
    // safe exactly because the stale tail is gone (§1/§7 Txn uniqueness).
    assert_eq!(commit(&k, 30), Seq(3));
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20, 30]);
    assert_eq!(k.current_seq(), Seq(3));
    assert_eq!(k.recovery().unwrap().tail_cut, 0, "a clean journal: nothing to cut");
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
    // The report: everything scanned was cut, and nothing was replayed.
    let recovery = k.recovery().expect("journaled");
    assert_eq!((recovery.replayed, recovery.tail_cut), (0, spans[1].0 + 3));
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
    // …and passed over, NOT in silence: the open's report counts the run
    // below its start point and accounts it — the bytes it spans and the
    // position it holds none above — since a derivation from a base below
    // it meets it: a history read from genesis halts on the damage the
    // account names, as an open falling back past checkpoint.3 would.
    let recovery = k.recovery().expect("journaled");
    assert_eq!(recovery.start_point, Seq(3));
    assert_eq!(recovery.runs_passed_over, 1, "the run below the start point, counted");
    let account = recovery.first_run_passed_over.as_deref().expect("the run's account");
    let span = format!("corrupt run in seg-1.wal from byte {} to byte {}", spans[4].0, spans[5].0);
    assert!(account.starts_with(&span), "{span:?} does not open: {account}");
    assert!(account.contains("holding no position above position 3"), "{account}");
    match k.world_at(Seq(2)) {
        Err(HistoryError::Corruption { at: Seq(4), .. }) => {}
        other => {
            panic!("a read from a base below the run meets what the open passed over: {other:?}")
        }
    }
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
    // The cause travels, and it is the environment's — not the media's — on
    // the file and the act that met it, so the operator knows which to fix.
    assert!(std::error::Error::source(&err).is_some());
    assert!(err.to_string().contains("seg-1.wal: read: "), "the file and the act: {err}");
}

/// Returns the names of the files the open's tail cut kept in `dir`, sorted.
///
/// They are `seg-{n}.wal.cut-{byte}` and its `….{k}` successors, beside the
/// journal.
fn kept_files(dir: &std::path::Path) -> Vec<String> {
    let mut kept: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".wal.cut-"))
        .collect();
    kept.sort();
    kept
}

/// Rot in the LAST acknowledged transaction's record HALTS the open (§7).
///
/// The transaction's marker stands intact and closes nothing — a tell no
/// crash leaves — so the tail is not a crash's, and the write it holds was
/// acknowledged at the position the marker claims. The open refuses it as
/// `Corruption` at that position, the cause a typed `DamagedTail` naming
/// the marker's frame, the claim, the tail's extent and the two acts; the
/// journal is byte-identical after the refusal and nothing is kept, so the
/// directory an operator images is the one that was there — and a second
/// open without the operator's word refuses the same way.
#[test]
fn post_commit_rot_of_the_final_txn_halts_the_open_naming_the_marker_and_its_claim() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    flip_byte(&seg, spans[4].0 + FRAME_HEADER_LEN + 1); // T3's record
    let found = fs::read(&seg).unwrap();
    for attempt in ["the first open", "the open after it"] {
        let err = Kernel::open(cfg_fsync(dir.path()), genesis())
            .expect_err("a damaged tail halts the open");
        let (at, damaged) = damaged_tail_of(&err);
        assert_eq!(at, Seq(3), "{attempt}: the position the cut tail claims");
        assert_eq!(
            damaged,
            DamagedTail {
                segment: "seg-1.wal".to_string(),
                byte: spans[4].0,
                head: Seq(2),
                bytes: found.len() as u64 - spans[4].0,
                intact: 1,
                claimed: Some(Seq(3)),
                tell: DamagedTailTell::MarkerCommitsNothing {
                    segment: "seg-1.wal".to_string(),
                    byte: spans[5].0,
                    position: Seq(3),
                },
            },
            "{attempt}: the frame, the claim and the extent, typed"
        );
        let line = err.to_string();
        assert!(
            line.starts_with(&format!(
                "durable committed data cannot be read; position 3 names the damage: damaged \
                 journal tail: the {} bytes after the last committed marker at position 2, from \
                 byte {} of seg-1.wal, are not a crash's — the intact commit marker at byte {} of \
                 seg-1.wal commits nothing",
                found.len() as u64 - spans[4].0,
                spans[4].0,
                spans[5].0
            )),
            "{attempt}: the refusal's words: {line}"
        );
        for act in [
            "claims position 3, the position the write it closed was acknowledged at",
            "nothing was cut. Two acts: restore seg-1.wal from a copy, or open once accepting the cut",
            &format!("beside the journal as seg-1.wal.cut-{} and then cuts them", spans[4].0),
            "handing out no position the tail claims",
        ] {
            assert!(line.contains(act), "{attempt}: {act:?} missing from: {line}");
        }
        assert_eq!(fs::read(&seg).unwrap(), found, "{attempt}: a halt cuts nothing");
        assert_eq!(kept_files(dir.path()), Vec::<String>::new(), "{attempt}: and keeps nothing");
    }
}

/// An ACCEPTED cut of the rotted transaction keeps, cuts, and starts the
/// order past the position the cut claimed (§7).
///
/// Under `cut_damaged_tail` the open keeps every byte it will cut beside the
/// journal first, owner-only, cuts, and reports the cut as the kept file,
/// the intact marker and the claim; the recovered head is the marker before
/// the cut, and the order's floor is the claim: a failed transaction before
/// the first commit rolls back to it and never below, the first commit takes
/// the position after it — never the claimed one — and the reopen, told
/// nothing, is clean, the claimed position a gap no boundary answers and
/// the kept file untouched.
#[test]
fn an_accepted_cut_keeps_the_rotted_txn_cuts_it_and_starts_the_order_past_its_claim() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    flip_byte(&seg, spans[4].0 + FRAME_HEADER_LEN + 1); // T3's record
    let found = fs::read(&seg).unwrap();
    let k = Kernel::open(cfg_cutting(dir.path()), genesis()).expect("the cut, accepted");
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
    assert_eq!(fs::metadata(&seg).unwrap().len(), spans[4].0); // cut from the journal
    let recovery = k.recovery().expect("journaled");
    let (marker_start, marker_len) = spans[5];
    assert_eq!(
        recovery.tail_cut,
        marker_start + marker_len - spans[4].0,
        "T3 cut whole, its marker with it"
    );
    assert_eq!(recovery.tail_cut_intact, 1, "T3's intact marker, counted as the rot's tell");
    assert_eq!(recovery.tail_cut_claimed, Some(Seq(3)), "the position the acked write held");
    assert_eq!(recovery.tail_cut_from, Some(("seg-1.wal".to_string(), spans[4].0)));
    let kept = format!("seg-1.wal.cut-{}", spans[4].0);
    assert_eq!(recovery.tail_cut_kept, vec![kept.clone()], "the one kept file, named");
    assert_eq!(kept_files(dir.path()), vec![kept.clone()]);
    let kept_path = dir.path().join(&kept);
    let kept_bytes = fs::read(&kept_path).unwrap();
    assert_eq!(kept_bytes, &found[spans[4].0 as usize..], "the cut bytes, whole");
    #[cfg(unix)]
    {
        // Born owner-only, as every file the kernel makes (the `journal_path`
        // caller contract): it holds a write's bytes whole.
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&kept_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "the kept file is 0600 exactly");
    }
    // THE ORDER STARTS PAST THE CLAIM: the floor is the claimed position,
    // a failed transaction rolls back to it and not to the head below it,
    // and the first commit takes the position after it — never position 3,
    // which a client's acknowledgement still names.
    assert_eq!(k.order_floor(), Seq(3), "the claim, trusted: the cut could hold it");
    k.fail_the_next(Step::JournalBarrier, io::ErrorKind::StorageFull);
    let refused = k.transact(&[], |stg| {
        stg.push(TestRec::Append(99));
        Ok::<(), ()>(())
    });
    assert!(matches!(refused, Err(TxnError::Durability(_))), "the barrier refused: {refused:?}");
    assert_eq!(commit(&k, 31), Seq(4), "the next commit takes C+1, never the claimed C");
    drop(k);
    // The reopen, told nothing: clean, the gap folded across, the kept file
    // as it was and no open reading, moving or writing over it.
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20, 31]);
    assert_eq!(k.current_seq(), Seq(4));
    assert_eq!(k.order_floor(), Seq(4), "a clean open's floor is its head");
    let recovery = k.recovery().expect("journaled");
    assert_eq!((recovery.tail_cut, recovery.tail_cut_kept.len()), (0, 0), "a clean reopen");
    assert_eq!(fs::read(&kept_path).unwrap(), kept_bytes, "the kept file, untouched");
    assert!(
        matches!(k.world_at(Seq(3)), Err(HistoryError::NotABoundary { nearest: Seq(2) })),
        "the claimed position is a gap no boundary answers"
    );
}

/// A CRC-intact frame of the last transaction that does not decode halts
/// the open, and cuts only under the knob (§7; the chain matrix's case 17).
///
/// The last marker's signature slot is rewritten to its tag with no bytes
/// after it, its CRC re-fixed: no torn write leaves a frame that passes its
/// CRC and does not decode. The open refuses at the first position above the
/// head — the frame claims none, its fields unread — naming the frame; under
/// `cut_damaged_tail` the whole transaction is kept and cut, the intact frame
/// counted, no claim read, and the order starts at the head.
#[test]
fn a_crc_intact_frame_that_does_not_decode_in_the_last_txn_halts_and_cuts_only_under_the_knob() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    rewrite_frame(&seg, spans[5].0 as usize, |payload| payload[MARKER_SIG_ALG_AT] = 1);
    let found = fs::read(&seg).unwrap();
    let err = Kernel::open(cfg_fsync(dir.path()), genesis()).expect_err("the frame halts");
    let (at, damaged) = damaged_tail_of(&err);
    assert_eq!(at, Seq(3), "no claim read: the first position above the head");
    assert_eq!(
        (damaged.segment.as_str(), damaged.byte, damaged.head, damaged.intact, damaged.claimed),
        ("seg-1.wal", spans[4].0, Seq(2), 1, None),
        "the tail begins at T3's record, its marker the intact frame of no writer's"
    );
    assert_eq!(
        damaged.tell,
        DamagedTailTell::FrameDoesNotDecode { segment: "seg-1.wal".to_string(), byte: spans[5].0 }
    );
    assert!(
        err.to_string().contains(&format!(
            "the frame at byte {} of seg-1.wal passes its CRC and does not decode",
            spans[5].0
        )),
        "{err}"
    );
    assert_eq!(fs::read(&seg).unwrap(), found, "a halt cuts nothing");
    assert!(kept_files(dir.path()).is_empty());

    let k = Kernel::open(cfg_cutting(dir.path()), genesis()).expect("the cut, accepted");
    assert_eq!((items(&k), k.current_seq()), (vec![10, 20], Seq(2)));
    let recovery = k.recovery().expect("journaled");
    let kept = format!("seg-1.wal.cut-{}", spans[4].0);
    assert_eq!(
        (recovery.tail_cut_intact, recovery.tail_cut_claimed, recovery.tail_cut_kept.clone()),
        (1, None, vec![kept.clone()])
    );
    assert_eq!(fs::read(dir.path().join(&kept)).unwrap(), &found[spans[4].0 as usize..]);
    assert_eq!(k.order_floor(), Seq(2), "nothing claimed: the order starts at the head");
    assert_eq!(commit(&k, 31), Seq(3));
}

/// THE LENGTH TEST, either side of the bound (§7): a tail no frame anchors
/// is a crash's at exactly what one append can leave, and damage one byte
/// past it.
///
/// Zero-filled bytes past the last committed marker hold no sync word, so
/// the scan reads one run to the end of the file. At `MAX_CRASH_TAIL_BYTES`
/// the open cuts them as the torn tail, nothing kept; one byte more and no
/// append could have left them — the open halts naming the bound, the file
/// as found, and under the knob keeps every one of them and cuts, the order
/// starting at the head.
#[test]
fn a_frameless_tail_at_the_bound_is_cut_as_a_crashs_and_one_byte_past_it_halts() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let clean_len = fs::metadata(&seg).unwrap().len();

    // AT THE BOUND: a crash's, cut and gone.
    extend_to(&seg, clean_len + MAX_CRASH_TAIL_BYTES);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).expect("at the bound, a crash's");
    let recovery = k.recovery().expect("journaled");
    assert_eq!(
        (recovery.tail_cut, recovery.tail_cut_intact, recovery.tail_cut_kept.len()),
        (MAX_CRASH_TAIL_BYTES, 0, 0),
        "cut whole, nothing kept"
    );
    assert_eq!(fs::metadata(&seg).unwrap().len(), clean_len);
    assert_eq!(k.current_seq(), Seq(2));
    drop(k);
    assert!(kept_files(dir.path()).is_empty());

    // ONE BYTE PAST IT: damage, refused with the bound named.
    extend_to(&seg, clean_len + MAX_CRASH_TAIL_BYTES + 1);
    let err = Kernel::open(cfg_fsync(dir.path()), genesis()).expect_err("past the bound");
    let (at, damaged) = damaged_tail_of(&err);
    assert_eq!(at, Seq(3), "the first position above the head");
    assert_eq!(
        damaged,
        DamagedTail {
            segment: "seg-1.wal".to_string(),
            byte: clean_len,
            head: Seq(2),
            bytes: MAX_CRASH_TAIL_BYTES + 1,
            intact: 0,
            claimed: None,
            tell: DamagedTailTell::LongerThanOneAppend { bound: MAX_CRASH_TAIL_BYTES },
        }
    );
    assert!(
        err.to_string().contains(&format!(
            "no intact frame stands among them and they are longer than one interrupted append \
             leaves ({MAX_CRASH_TAIL_BYTES} bytes"
        )),
        "{err}"
    );
    assert_eq!(fs::metadata(&seg).unwrap().len(), clean_len + MAX_CRASH_TAIL_BYTES + 1, "uncut");
    assert!(kept_files(dir.path()).is_empty());

    // THE CUT ACCEPTED: kept whole, cut, the head the floor.
    let k = Kernel::open(cfg_cutting(dir.path()), genesis()).expect("the cut, accepted");
    let recovery = k.recovery().expect("journaled");
    let kept = format!("seg-1.wal.cut-{clean_len}");
    assert_eq!(
        (recovery.tail_cut, recovery.tail_cut_intact, recovery.tail_cut_kept.clone()),
        (MAX_CRASH_TAIL_BYTES + 1, 0, vec![kept.clone()])
    );
    assert_eq!(
        fs::metadata(dir.path().join(&kept)).unwrap().len(),
        MAX_CRASH_TAIL_BYTES + 1,
        "every byte kept"
    );
    assert_eq!(fs::metadata(&seg).unwrap().len(), clean_len);
    assert_eq!(k.order_floor(), Seq(2));
    assert_eq!(commit(&k, 30), Seq(3));
}

/// A claim the cut could not have held is NOT trusted (§7).
///
/// The last transaction's record is rotted and its marker's `last_seq`
/// forged, the CRC re-fixed — the rot, so the marker is the tail's bare
/// tell and not the edited transaction the chain matrix halts on first
/// (case 2) — so the marker closes nothing and claims the forged position:
/// the open halts at it, and under the knob the order's floor is the head
/// where the claim lies past what the tail's bytes could number — a record
/// frame of the smallest payload per position — or at the order's ceiling,
/// where no successor could follow; a claim within what the tail could hold
/// is trusted, and the first commit takes the position after it.
#[test]
fn a_claim_the_cut_could_not_have_held_is_not_trusted() {
    let fixture = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(fixture.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let spans = frame_spans(&seg_file(fixture.path(), 1));
    let tail_bytes = fs::metadata(seg_file(fixture.path(), 1)).unwrap().len() - spans[4].0;
    let smallest_record_frame = FRAME_HEADER_LEN + RECORD_BYTES_AT as u64;
    let could_hold = tail_bytes / smallest_record_frame;
    assert!(could_hold >= 2, "the fixture's tail could number more than its one position");
    let claiming = |name: &str, claim: u64| {
        let case = fixture.path().join(name);
        copy_dir(fixture.path(), &case);
        flip_byte(&seg_file(&case, 1), spans[4].0 + FRAME_HEADER_LEN + 1); // T3's record
        rewrite_frame(&seg_file(&case, 1), spans[5].0 as usize, |payload| {
            payload[MARKER_LAST_SEQ_AT..MARKER_LAST_SEQ_AT + 8]
                .copy_from_slice(&claim.to_le_bytes());
        });
        let err = Kernel::open(cfg_fsync(&case), genesis()).expect_err("a forged claim halts");
        let (at, damaged) = damaged_tail_of(&err);
        assert_eq!((at, damaged.claimed), (Seq(claim), Some(Seq(claim))), "{name}: the claim");
        let k = Kernel::open(cfg_cutting(&case), genesis()).expect("the cut, accepted");
        assert_eq!(k.recovery().unwrap().tail_cut_claimed, Some(Seq(claim)), "{name}: reported");
        let floor = k.order_floor();
        let next = commit(&k, 31);
        (floor, next)
    };
    assert_eq!(
        claiming("ceiling", u64::MAX - 2),
        (Seq(2), Seq(3)),
        "a claim at the order's ceiling is not trusted: the head is the floor"
    );
    assert_eq!(
        claiming("past", 2 + could_hold + 1),
        (Seq(2), Seq(3)),
        "a claim past what the tail's bytes could number is not trusted"
    );
    assert_eq!(
        claiming("held", 2 + could_hold),
        (Seq(2 + could_hold), Seq(2 + could_hold + 1)),
        "a claim the tail could hold is trusted, and the next commit takes the position after it"
    );
}

/// A wholly-later segment is refused, then kept whole under the knob, and the
/// order starts past the position it claimed.
///
/// Rot in the record of the transaction that opened a segment leaves the
/// segment's own intact marker closing nothing, the last committed marker
/// ending the segment before it. The open refuses, naming the later segment
/// as where the tail begins; told to cut, it moves the tail segment aside
/// whole, `seg-5.wal.cut-0`, before the cut, and the cut takes no byte of
/// the segment before. The next commit takes the position after the claim,
/// and so a new segment's name, `seg-6.wal`; the same rot there is refused
/// and kept the same way, the first kept file standing as it was.
#[test]
fn a_tail_segment_holding_an_intact_frame_is_refused_then_moved_aside_whole_under_the_knob() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    for _ in 0..4 {
        commit_blob(&k); // Seqs 1..=4, filling seg-1 past the threshold
    }
    assert_eq!(commit_blob(&k), Seq(5)); // rotates into seg-5
    drop(k);
    let seg5 = seg_file(dir.path(), 5);
    let rot = |seg: &std::path::Path| {
        let spans = frame_spans(seg);
        assert_eq!(spans.len(), 2, "the segment's one record and its marker");
        flip_byte(seg, spans[0].0 + FRAME_HEADER_LEN + 1); // the record
    };
    rot(&seg5);
    let found = fs::read(&seg5).unwrap();
    let seg1_len = fs::metadata(seg_file(dir.path(), 1)).unwrap().len();

    let err = Kernel::open(cfg_fsync(dir.path()), genesis()).expect_err("refused");
    let (at, damaged) = damaged_tail_of(&err);
    assert_eq!((at, damaged.segment.as_str(), damaged.byte), (Seq(5), "seg-5.wal", 0));
    assert_eq!(
        (damaged.head, damaged.bytes, damaged.claimed),
        (Seq(4), found.len() as u64, Some(Seq(5)))
    );
    assert!(seg5.exists() && fs::read(&seg5).unwrap() == found, "a halt moves nothing");

    let k = Kernel::open(cfg_cutting(dir.path()), genesis()).expect("the cut, accepted");
    assert_eq!(k.current_seq(), Seq(4));
    assert_eq!(items(&k).len(), 4);
    let recovery = k.recovery().expect("journaled");
    assert_eq!((recovery.tail_cut_intact, recovery.tail_cut_claimed), (1, Some(Seq(5))));
    assert_eq!(recovery.tail_cut, found.len() as u64, "seg-5 cut whole");
    assert_eq!(recovery.tail_cut_from, Some(("seg-5.wal".to_string(), 0)), "seg-1 gave no byte");
    assert_eq!(recovery.tail_cut_kept, vec!["seg-5.wal.cut-0".to_string()]);
    assert!(!seg5.exists(), "the tail segment is gone from under its own name");
    assert_eq!(fs::read(dir.path().join("seg-5.wal.cut-0")).unwrap(), found, "moved whole");
    assert_eq!(fs::metadata(seg_file(dir.path(), 1)).unwrap().len(), seg1_len, "seg-1 uncut");

    // The next commit takes position 6, past the claim — and a fresh segment
    // named for it — and the same rot there is kept beside the first.
    assert_eq!(k.order_floor(), Seq(5));
    assert_eq!(commit_blob(&k), Seq(6));
    drop(k);
    let seg6 = seg_file(dir.path(), 6);
    assert!(!seg5.exists() && seg6.exists(), "the next session's segment takes the next name");
    rot(&seg6);
    let again = fs::read(&seg6).unwrap();
    assert!(Kernel::open(cfg_fsync(dir.path()), genesis()).is_err(), "refused again");
    let k = Kernel::open(cfg_cutting(dir.path()), genesis()).unwrap();
    assert_eq!(k.current_seq(), Seq(4));
    assert_eq!(k.recovery().unwrap().tail_cut_kept, vec!["seg-6.wal.cut-0".to_string()]);
    assert_eq!(fs::read(dir.path().join("seg-5.wal.cut-0")).unwrap(), found, "never written over");
    assert_eq!(fs::read(dir.path().join("seg-6.wal.cut-0")).unwrap(), again);
    assert_eq!(
        kept_files(dir.path()),
        vec!["seg-5.wal.cut-0".to_string(), "seg-6.wal.cut-0".to_string()]
    );
    assert_eq!(k.order_floor(), Seq(6));
    assert_eq!(commit_blob(&k), Seq(7));
}

/// A name standing where the keep would go is passed over whole.
///
/// Whatever stands under the keep's first name and is no copy of these very
/// bytes — here a directory holding a file of its own — is never written
/// over, and the copy takes the next free name. (A keep that fails cuts
/// nothing and fails the open; the open's seam is its own, so the cut's unit
/// suite drives that failure, through a seam of its own.)
#[test]
fn a_name_standing_where_the_keep_would_go_is_passed_over_whole() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    flip_byte(&seg, spans[4].0 + FRAME_HEADER_LEN + 1); // T3's record
    let found = fs::read(&seg).unwrap();
    let kept = format!("seg-1.wal.cut-{}", spans[4].0);
    // A directory under the keep's first name: no copy of these bytes, so the
    // keep passes it over whole and takes the next name.
    fs::create_dir(dir.path().join(&kept)).unwrap();
    fs::write(dir.path().join(&kept).join("theirs"), b"an operator's file").unwrap();
    let k = Kernel::open(cfg_cutting(dir.path()), genesis()).unwrap();
    assert_eq!(k.recovery().unwrap().tail_cut_kept, vec![format!("{kept}.1")]);
    assert_eq!(
        fs::read(dir.path().join(format!("{kept}.1"))).unwrap(),
        &found[spans[4].0 as usize..],
        "the copy, under the next free name"
    );
    assert_eq!(
        fs::read(dir.path().join(&kept).join("theirs")).unwrap(),
        b"an operator's file",
        "what stood under the name, untouched"
    );
    assert_eq!(items(&k), vec![10, 20]);
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
            let account = cause.to_string();
            assert!(account.contains("damaged sync word"), "got {account}");
            // …and on the file it lies in: which segment the scan reads first
            // turns on the base and the skip rule, which the operator cannot
            // work out from a coordinate.
            assert!(account.contains("seg-5.wal opens with"), "the file named: {account}");
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
    // and names the file its bytes lie in — closed here, so the act it names
    // loses nothing, and this fixture performs it; an absent one is a chain
    // break, whose cause says which link failed.
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
    // frame — a loud halt at 9, the run's verdict. The run's own bytes are
    // unreadable, but where they lie is not: the account names seg-5.wal from
    // its first byte to its end, CLOSED — seg-9.wal follows it — so the act
    // it names is one file's restore. (T9's link fails too — it chains from a
    // T8 the run swallowed — but the run names the root cause and speaks
    // first.)
    let damaged = tmp.path().join("damaged");
    copy_dir(&fixture, &damaged);
    let mid = seg_file(&damaged, 5);
    let len = fs::metadata(&mid).unwrap().len() as usize;
    fs::write(&mid, vec![0u8; len]).unwrap();
    let err = Kernel::<TestWorld>::open(cfg_fsync(&damaged), genesis())
        .expect_err("a corrupt run in the replayed range is a halt");
    let OpenError::Corruption { at: Seq(9), cause: Some(cause) } = &err else {
        panic!("a damaged segment is a corrupt run, named at the next intact frame: got {err:?}")
    };
    let account = cause.to_string();
    for named in [
        "corrupt run in seg-5.wal from byte 0 to its end",
        "seg-5.wal is closed — seg-9.wal follows it",
        "restore seg-5.wal alone from a copy that holds seg-9.wal",
    ] {
        assert!(account.contains(named), "{named:?} missing from: {account}");
    }
    // …and the act it names is the whole repair: the closed segment, restored
    // alone from a copy that holds the segment after it, reopens the journal
    // at its true head — the halt cut nothing, and the chain verifies every
    // link the restored file carries.
    fs::copy(seg_file(&fixture, 5), &mid).unwrap();
    let k = Kernel::<TestWorld>::open(cfg_fsync(&damaged), genesis())
        .expect("one closed segment restored from a copy reopens the journal");
    assert_eq!(k.current_seq(), Seq(9), "nothing is lost");
    assert_eq!(items(&k).len(), 9);
    drop(k);

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
    // committed marker, and take every wholly-later segment out of the
    // journal. A crash's tail, as here, is deleted and kept nowhere; a tail
    // holding an intact frame no torn write leaves is moved aside whole
    // instead (`a_tail_segment_holding_an_intact_frame_is_moved_aside_…`).
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
    // The cut REPORTED counts the discarded segment whole — seg-1 was cut at
    // its own end, contributing nothing — beside the four commits replayed.
    let recovery = k.recovery().expect("journaled");
    assert_eq!(recovery.tail_cut, spans[1].0 + 3, "seg-5's length, discarded whole");
    assert_eq!(
        recovery.tail_cut_from,
        Some(("seg-5.wal".to_string(), 0)),
        "the cut began at the first byte it took: seg-5's first, seg-1 giving none"
    );
    assert!(recovery.tail_cut_kept.is_empty(), "a crash's tail is kept nowhere");
    assert_eq!(kept_files(dir.path()), Vec::<String>::new(), "…not even moved aside");
    assert_eq!(recovery.replayed, 4);

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
    // The open says it BEGAN a journal rather than recovered one — the one
    // tell, on a board that had a journal, that the directory opened is not
    // where it lives.
    assert!(k.recovery().expect("journaled").began, "no journal stood: this open began one");
    assert_eq!(commit(&k, 1), Seq(1));
    drop(k);
    // …and what it created is a journal a reopen recovers from.
    let k = Kernel::open(cfg_fsync(&dir), genesis()).unwrap();
    assert_eq!(items(&k), vec![1]);
    assert!(!k.recovery().expect("journaled").began, "a journal stood: this open recovered it");
    drop(k);
    // An existing directory that holds no journal — a mount point the volume
    // did not mount over — is a beginning too, said the same way.
    let empty = tmp.path().join("mount-point");
    fs::create_dir(&empty).unwrap();
    let k = Kernel::open(cfg_fsync(&empty), genesis()).unwrap();
    assert!(k.recovery().expect("journaled").began, "an empty directory held no journal");
}

/// The open removes a stray `checkpoint.tmp` and answers its size.
///
/// A `checkpoint.tmp` a crash left — no base, and room kept on the volume —
/// is removed by the open, under the flock, and the fact reported with its
/// size for the daemon's startup line: the name is one of those the kernel
/// owns, so the file is the kernel's to delete, and the operator's acts at
/// the floor stay two. Fixed at the open: a reopen with none standing
/// answers `None`, as the in-memory mode, which opens no directory, always
/// does. The bases beside it stand, and the world recovers whole (M-I5 (f);
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

/// Every name in the kernel's directory but its own is left alone.
///
/// The kernel owns `seg-<n>.wal`, `checkpoint.<n>`, `checkpoint.tmp`,
/// `kernel.lock` and the tail cut's kept `seg-<n>.wal.cut-<b>`
/// (`Durability::Fsync`'s `journal_path` contract), so an embedder keeps
/// files of its own beside the journal: a file at the root, a directory with
/// a file in it, and names that only resemble the kernel's, in spellings its
/// writer never emits, come through an open, a rotation, a landing's
/// retention and reclamation, and a reopen, byte for byte.
#[test]
fn every_name_but_the_kernels_own_is_left_alone() {
    let dir = tempdir().unwrap();
    let own: [(&str, &[u8]); 5] = [
        ("commits.log", b"the embedder's own log"),
        ("blobs/blake3-ab", b"a file in a directory of the embedder's"),
        ("seg-01.wal", b"no segment: the writer spells its first one seg-1.wal"),
        ("checkpoint.07", b"no checkpoint: the writer spells this one checkpoint.7"),
        ("checkpoint.tmp.old", b"not the temp file"),
    ];
    fs::create_dir(dir.path().join("blobs")).unwrap();
    for (name, bytes) in own {
        fs::write(dir.path().join(name), bytes).unwrap();
    }
    let k = Kernel::open(cfg_retain(dir.path(), 1), genesis()).unwrap();
    for _ in 0..5 {
        commit_blob(&k); // four fill seg-1 past the threshold, the fifth rotates
    }
    assert!(seg_file(dir.path(), 5).exists(), "the fixture rotates");
    assert_eq!(k.checkpoint().unwrap(), Seq(5));
    assert!(!seg_file(dir.path(), 1).exists(), "the landing reclaimed the kernel's own segment");
    drop(k);
    let k = Kernel::open(cfg_retain(dir.path(), 1), genesis()).unwrap();
    assert_eq!(items(&k).len(), 5, "the journal reopens whole beside the embedder's files");
    drop(k);
    for (name, bytes) in own {
        assert_eq!(fs::read(dir.path().join(name)).unwrap(), bytes, "{name} is the embedder's");
    }
}

#[test]
fn a_journal_admits_one_live_kernel_at_a_time() {
    let dir = tempdir().unwrap();
    let k1 = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // Exclusive advisory ownership (Lifecycle): appender OR recoverer, never
    // both — a second open() fails with the acquisition error, its kind kept
    // for the callers that branch on it, and its words saying what it MEANS:
    // another process holds the journal directory, not a disk that failed.
    let err = Kernel::open(cfg_fsync(dir.path()), genesis()).err().unwrap();
    let OpenError::Io(io_err) = &err else { panic!("got {err:?}") };
    assert_eq!(io_err.kind(), io::ErrorKind::WouldBlock, "the kind, kept: {io_err}");
    let words = io_err.to_string();
    assert!(words.starts_with("kernel.lock: lock: "), "the file and the act: {words}");
    assert!(words.contains("another process holds it"), "what the refusal means: {words}");
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

    // The inline arm's runs are counted in this mode too — each the no-op,
    // each landed — and the journaled reads answer `None`: no journal to
    // reclaim, no base to name, no open to report.
    assert_eq!(k.inline_checkpoints(), 2, "EveryN(1): a no-op run per commit");
    assert_eq!(k.last_inline_checkpoint_failure(), None);
    assert_eq!(k.last_reclaimed_bytes(), None);
    assert_eq!(k.checkpoint_header(Seq(2)), None);
    assert!(k.recovery().is_none());
    k.flush().unwrap();
    drop(k);
    // No journal → no recovery story: a reopen starts from genesis.
    let k = Kernel::open(cfg, genesis()).unwrap();
    assert_eq!(k.current_seq(), Seq(0));
    assert_eq!(items(&k), Vec::<u64>::new());
}
