use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};

use super::*;
use crate::journal::tests::{chain_of_marker_at, fresh_writer, frame_starts, rec};
use crate::journal::{txn_encoded_len, RECORD_PAYLOAD_OVERHEAD};
use tempfile::tempdir;

/// THE FILLED SLOT IS OUTSIDE THE TRANSACTION BUDGET (signed ops; the
/// design record §4.4 (b)): a staging AT the budget commits attested as
/// it commits unattested — the blob's width is charged to nothing the
/// budget judges — and the same staging one byte past it is refused the
/// same way with or without an attestation, the accounted figure the
/// records' own. So `transact_attested` answers no refusal `transact`
/// would not, which is what lets a `publish` shot — unsplittable — be
/// attested at any size it commits unattested.
#[test]
fn a_filled_slot_is_outside_the_transaction_budget() {
    let prefix = encode_record(&Vec::<u8>::new()).unwrap().len();
    let mut journal = Journal::InMemory;
    let mut installs = 0u32;
    let attestation = Attestation::new(1, vec![0xA5; 3_373]).unwrap();
    let body = (MAX_TXN_BYTES - txn_encoded_len(&[Vec::new()], None)) as usize - prefix;
    let at_budget = vec![vec![0u8; body]];
    assert!(journal.commit_txn(1, at_budget, Some(&attestation), |_| installs += 1).is_ok());
    assert_eq!(installs, 1);
    let past_budget = vec![vec![0u8; body + 1]];
    match journal.commit_txn(1, past_budget, Some(&attestation), |_| installs += 1) {
        Err(CommitFail::OverBudget { bytes }) => assert_eq!(bytes, MAX_TXN_BYTES + 1),
        other => panic!("expected OverBudget, got {other:?}"),
    }
    assert_eq!(installs, 1);
}

#[test]
fn commit_txn_refuses_what_no_mode_may_accept() {
    // Each record is charged against the two size limits as the commit
    // encodes it.
    // `Vec<u8>` encodes as an 8-byte length prefix plus its bytes, so a
    // body of `n` occupies `n + prefix` of a frame payload.
    let prefix = encode_record(&Vec::<u8>::new()).unwrap().len();
    let mut journal = Journal::InMemory;
    let mut installs = 0u32;

    // A record one past the frame cap's payload edge is the RECORD's own
    // fault — Unencodable, not OverBudget, though the sum is over too: a
    // caller fixing a value is not first told to split.
    let cap_bytes = (MAX_FRAME_LEN as u64 - RECORD_PAYLOAD_OVERHEAD) as usize;
    let over_frame = vec![vec![0u8; cap_bytes + 1 - prefix]];
    let out = journal.commit_txn(1, over_frame, None, |_| installs += 1);
    assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");

    // At the budget exactly: commits — the refusal begins one past the
    // budget, not at it.
    let body = (MAX_TXN_BYTES - txn_encoded_len(&[Vec::new()], None)) as usize - prefix;
    let at_budget = vec![vec![0u8; body]];
    assert_eq!(
        txn_encoded_len(&[encode_record(&at_budget[0]).unwrap()], None),
        MAX_TXN_BYTES
    );
    assert!(journal.commit_txn(1, at_budget, None, |_| installs += 1).is_ok());

    // One byte past: OverBudget, carrying the size.
    let past_budget = vec![vec![0u8; body + 1]];
    match journal.commit_txn(1, past_budget, None, |_| installs += 1) {
        Err(CommitFail::OverBudget { bytes }) => assert_eq!(bytes, MAX_TXN_BYTES + 1),
        other => panic!("expected OverBudget, got {other:?}"),
    }

    // …and a staging FAR past the budget still reports the whole accounted
    // size. The charge runs on past the crossing precisely so the figure a
    // caller's split must get under is the one they staged, where a charge
    // that stopped where it refused would name a number they already met.
    let half = (MAX_TXN_BYTES / 2) as usize;
    let far_over = vec![vec![0u8; half], vec![0u8; half], vec![0u8; 8]];
    let expected = {
        let encoded: Vec<Vec<u8>> =
            far_over.iter().map(|r| encode_record(r).unwrap()).collect();
        txn_encoded_len(&encoded, None)
    };
    assert!(expected > MAX_TXN_BYTES + record_frame_len(8 + prefix));
    match journal.commit_txn(1, far_over, None, |_| installs += 1) {
        Err(CommitFail::OverBudget { bytes }) => assert_eq!(bytes, expected),
        other => panic!("expected the whole staging accounted, got {other:?}"),
    }

    assert_eq!(installs, 1, "only the at-budget transaction installs");
}

#[test]
fn a_record_past_the_frame_cap_is_unencodable_after_the_budget_is_crossed() {
    // The record's own refusal precedes the staging's AT EVERY POSITION,
    // not only at the first: the loop keeps judging each record's frame
    // cap past the crossing, so a caller fixing a value is never first
    // told to split — and then handed the same refusal on the split half.
    let prefix = encode_record(&Vec::<u8>::new()).unwrap().len();
    let cap_bytes = (MAX_FRAME_LEN as u64 - RECORD_PAYLOAD_OVERHEAD) as usize;
    // The largest record the frame cap admits already puts the transaction
    // over the budget on its own — so the crossing happens at record one…
    let at_cap = vec![0u8; cap_bytes - prefix];
    // …and record two, one byte larger, still cannot be framed.
    let past_cap = vec![0u8; cap_bytes + 1 - prefix];
    let mut journal = Journal::InMemory;
    let mut installed = false;
    let out = journal.commit_txn(1, vec![at_cap, past_cap], None, |_| installed = true);
    assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");
    assert!(!installed, "a refused transaction installs nothing");
}

/// A record whose serializer refuses — the cheapest way to reach the
/// encode step, which no size of value can exercise.
struct RefusesSerialization;

impl Serialize for RefusesSerialization {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("record refused to serialize"))
    }
}

#[test]
fn the_in_memory_journal_refuses_what_the_durable_one_refuses() {
    // The encode and the two size judgments belong to `Journal::commit_txn`
    // and run above its own mode branch, so the mode that journals nothing
    // still serializes every record and still refuses what only the frames
    // could reject. The frame cap once lived in the frame builder alone —
    // which this arm never reaches — and a store whose values could exceed
    // it passed every in-memory test and met the refusal in production;
    // owning the check above the branch is what keeps that closed by
    // construction rather than by whatever the caller remembers to do
    // first.
    let mut installed = false;
    let mut in_memory = Journal::InMemory;

    // The encode: a record the serializer refuses, in the mode that would
    // otherwise never encode anything.
    let out = in_memory.commit_txn(1, vec![RefusesSerialization], None, |_| installed = true);
    assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");

    // The frame cap, which is a property of frames this arm never builds.
    let prefix = encode_record(&Vec::<u8>::new()).unwrap().len();
    let cap_bytes = (MAX_FRAME_LEN as u64 - RECORD_PAYLOAD_OVERHEAD) as usize;
    let over_frame = vec![vec![0u8; cap_bytes + 1 - prefix]];
    let out = in_memory.commit_txn(1, over_frame, None, |_| installed = true);
    assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");

    // The transaction budget, likewise.
    let half = (MAX_TXN_BYTES / 2) as usize;
    let over_budget = vec![vec![0u8; half], vec![0u8; half]];
    let out = in_memory.commit_txn(1, over_budget, None, |_| installed = true);
    assert!(matches!(out, Err(CommitFail::OverBudget { .. })), "got {out:?}");

    assert!(!installed, "a refused transaction installs nothing");

    // …and the durable arm answers the same, which is the parity these
    // three refusals exist to hold: one judgment, one place, both modes.
    let dir = tempdir().unwrap();
    let mut segments = Journal::Segments(fresh_writer(dir.path()));
    let out = segments.commit_txn(1, vec![RefusesSerialization], None, |_| installed = true);
    assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");
    assert!(!installed, "a refused transaction installs nothing");
}

#[test]
fn an_installed_commit_leaves_nothing_in_flight() {
    // The install happens inside the commit, so an installed transaction
    // is behind the writer by the time it returns: a later unwind finds
    // nothing of it to repair, and the next transaction starts clean (§3).
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    let mut installed = None;
    writer
        .commit_txn(1, vec![rec(10)], None, |chain| installed = Some(chain))
        .expect("fixture commit");
    let installed = installed.expect("the commit installs before it returns");
    // …and hands the install the chain the marker on disk carries.
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    assert_eq!(installed, chain_of_marker_at(&segs[0].path, starts[1]));
    let repair = writer.repair_after_unwind();
    assert!(matches!(repair, UnwindRepair::Clean), "got {repair:?}");
}

/// THE SEAM AT THE JOURNAL (`test-hooks`): the append and the barrier, armed
/// to fail, answer `CommitFail::Clean` carrying the kind armed and naming
/// the step, the segment durably back at its mark — the barrier's frames
/// appended and truncated away, the append's never written — and nothing
/// installed; each fires ONCE, the same commit then landing at the same
/// coordinate. The repair, armed to fail beside a failing barrier, answers
/// `CommitFail::Unrepaired` with the barrier's frames left standing — and
/// fires once: the repair after an unwind, asked next, truncates for real
/// and answers `Clean`. The append's panic arm unwinds in the append's
/// place, the repair after it answers `Clean` with nothing on disk, and the
/// commit after that lands; the barrier and the repair take no panic arm.
#[test]
fn each_journal_step_fires_its_arm_once_and_the_step_then_runs_for_real() {
    for step in [Step::JournalAppend, Step::JournalBarrier] {
        let dir = tempdir().unwrap();
        let seam = Seam::default();
        let mut writer = fresh_writer(dir.path()).with_seam(seam.clone());
        writer.commit_txn(1, vec![rec(10)], None, |_| {}).expect("fixture commit");
        let seg = segment_path(dir.path(), 1);
        let mark = fs::metadata(&seg).unwrap().len();

        seam.fail_the_next(step, io::ErrorKind::StorageFull);
        let mut installed = false;
        let out = writer.commit_txn(2, vec![rec(20)], None, |_| installed = true);
        let e = match out {
            Err(CommitFail::Clean(e)) => e,
            other => panic!("{step:?}: expected a clean failure, got {other:?}"),
        };
        assert_eq!(e.kind(), io::ErrorKind::StorageFull, "{step:?}: the kind armed");
        assert!(e.to_string().contains(&format!("{step:?}")), "{step:?}: names the step: {e}");
        // …named as the real step's failure is: the segment, then the act.
        let act = if step == Step::JournalAppend { "append" } else { "fsync" };
        assert!(
            e.to_string().starts_with(&format!("seg-1.wal: {act}: ")),
            "{step:?}: names the segment and the act: {e}"
        );
        assert!(!installed, "{step:?}: nothing installed");
        assert_eq!(fs::metadata(&seg).unwrap().len(), mark, "{step:?}: back at the mark");
        assert!(seam.armed_steps().is_empty(), "{step:?}: fired and disarmed");

        writer
            .commit_txn(2, vec![rec(20)], None, |_| installed = true)
            .expect("the step, unarmed, runs for real");
        assert!(installed);
        assert_eq!(frame_starts(&seg).len(), 4, "two transactions, a record and a marker each");
    }

    // The repair: armed beside a failing barrier, so there is something to
    // repair, and the failure answered is the repair's own.
    let dir = tempdir().unwrap();
    let seam = Seam::default();
    let mut writer = fresh_writer(dir.path()).with_seam(seam.clone());
    let seg = segment_path(dir.path(), 1);
    seam.fail_the_next(Step::JournalBarrier, io::ErrorKind::StorageFull);
    seam.fail_the_next(Step::JournalRepair, io::ErrorKind::StorageFull);
    let out = writer.commit_txn(1, vec![rec(10)], None, |_| {});
    // Both failures travel, each named on the segment: the barrier's, and the
    // truncation's that left its frames standing — what the halt is said with.
    match out {
        Err(CommitFail::Unrepaired { failed, repair }) => {
            assert!(failed.to_string().starts_with("seg-1.wal: fsync: "), "{failed}");
            assert!(repair.to_string().starts_with("seg-1.wal: truncate: "), "{repair}");
            assert!(repair.to_string().contains("JournalRepair"), "{repair}");
        }
        other => panic!("expected the unrepaired failure, got {other:?}"),
    }
    assert!(seam.armed_steps().is_empty(), "both arms fired");
    let left = fs::metadata(&seg).unwrap().len();
    assert!(left > 0, "the barrier's frames stand: the repair never ran");
    // Fired once: the repair after an unwind, asked next, truncates them.
    let repair = writer.repair_after_unwind();
    assert!(matches!(repair, UnwindRepair::Clean), "got {repair:?}");
    assert_eq!(fs::metadata(&seg).unwrap().len(), 0, "the real repair ran");

    // The append's panic arm.
    seam.panic_at_the_next(Step::JournalAppend);
    let unwound =
        catch_unwind(AssertUnwindSafe(|| writer.commit_txn(1, vec![rec(10)], None, |_| {})));
    assert!(unwound.is_err(), "the armed append unwinds the commit");
    assert_eq!(fs::metadata(&seg).unwrap().len(), 0, "nothing reached the file");
    let repair = writer.repair_after_unwind();
    assert!(matches!(repair, UnwindRepair::Clean), "got {repair:?}");
    writer.commit_txn(1, vec![rec(10)], None, |_| {}).expect("the append, unarmed, lands");
    assert_eq!(frame_starts(&seg).len(), 2);

    // The two that take none.
    for step in [Step::JournalBarrier, Step::JournalRepair] {
        let refused = catch_unwind(AssertUnwindSafe(|| seam.panic_at_the_next(step)));
        assert!(refused.is_err(), "{step:?} takes no panic arm");
    }
    assert!(seam.armed_steps().is_empty());
}

/// Checks that a rotation refused its directory sync names no path.
///
/// A commit that finds its segment at `SEGMENT_ROTATE_BYTES` creates the
/// next segment and syncs the directory before a byte of it is appended. A
/// directory of mode `0300` takes the create and refuses the sync's open, so
/// the commit is answered `CommitFail::Clean` of kind `PermissionDenied`,
/// named `the journal directory: sync: …` with no byte of the directory's
/// path — the account M10 hands a refused writer whole (PATTERNS SP-13) —
/// and nothing of the transaction is on disk. Restored, the same commit
/// lands in the new segment. A process that lists a mode-`0300` directory
/// (root) stages no refusal, and the claim is not run.
#[cfg(unix)]
#[test]
fn a_rotation_refused_its_directory_sync_names_the_journal_directory_and_never_its_path() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    let fill = vec![vec![7u8; SEGMENT_ROTATE_BYTES as usize]];
    writer.commit_txn(1, fill, None, |_| {}).expect("the fill commits");
    let seg1 = segment_path(dir.path(), 1);
    let seg2 = segment_path(dir.path(), 2);
    let mark = fs::metadata(&seg1).unwrap().len();
    assert!(mark >= SEGMENT_ROTATE_BYTES, "premise: the next commit rotates");
    let mode = |bits| fs::set_permissions(dir.path(), fs::Permissions::from_mode(bits)).unwrap();
    mode(0o300);
    if fs::read_dir(dir.path()).is_ok() {
        mode(0o700);
        eprintln!("a privileged process lists a mode-0300 directory: the claim is not run");
        return;
    }
    let mut installed = false;
    let out = writer.commit_txn(2, vec![rec(20)], None, |_| installed = true);
    mode(0o700);
    let e = match out {
        Err(CommitFail::Clean(e)) => e,
        other => panic!("the rotation's refusal is a clean failure: {other:?}"),
    };
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "the OS's kind kept: {e}");
    let text = e.to_string();
    assert!(text.starts_with("the journal directory: sync: "), "the directory by its name: {text}");
    let path = dir.path().display().to_string();
    let leaf = dir.path().file_name().unwrap().to_string_lossy().into_owned();
    assert!(!text.contains(&path) && !text.contains(&leaf), "no byte of the path: {text}");
    assert!(!installed, "nothing installed");
    assert_eq!(fs::metadata(&seg1).unwrap().len(), mark, "the full segment untouched");
    assert_eq!(fs::metadata(&seg2).map_or(0, |m| m.len()), 0, "no byte in the next segment");

    writer
        .commit_txn(2, vec![rec(20)], None, |_| installed = true)
        .expect("the directory syncs: the commit lands");
    assert!(installed);
    assert_eq!(frame_starts(&seg2).len(), 2, "in the new segment: a record and a marker");
}
