//! Bounded replay, `Kernel::world_at`: the base it selects, the refusals it
//! makes and their order, and the answers it gives beside a live appender
//! (§6/§7) — the one-pass boundary list, `Kernel::boundaries_above`, held to
//! the per-position read it stands in for (the operations design §3.3 step
//! 2) — and the bases the kernel holds, which a read at or above the oldest
//! stands on in place of a checkpoint's file (§6).

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::mutilate::{append_bytes, ckpt_file, flip_byte, seg_file, FRAME_MAGIC};
use skep_kernel::{CheckpointError, HistoryError};
use tempfile::tempdir;

#[test]
fn world_at_falls_back_down_the_same_base_chain_recovery_uses() {
    // Bounded replay derives its world the way recovery does, so it inherits
    // the whole fallback chain: a base that fails its checksum is skipped for
    // the next-older RETAINED one, then for genesis while reachable, and the
    // answer is the same world whichever base carries it (§6/§7).
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    commit(&k, 10);
    commit(&k, 20);
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    commit(&k, 30);
    commit(&k, 40);
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    commit(&k, 50);
    let whole = vec![10, 20, 30, 40, 50];
    assert_eq!(world_items(&k.world_at(Seq(5)).unwrap()), whole);
    // The roots the two landings wrote are held, and a read standing on one
    // reads no file: released, every read below takes its base from the
    // directory, where the chain runs.
    k.release_held_bases();

    // Newest base unusable → the older retained one carries the answer.
    let cp4 = ckpt_file(dir.path(), 4);
    let len = fs::metadata(&cp4).unwrap().len();
    flip_byte(&cp4, len - 1);
    assert_eq!(world_items(&k.world_at(Seq(4)).unwrap()), vec![10, 20, 30, 40]);
    assert_eq!(world_items(&k.world_at(Seq(5)).unwrap()), whole);

    // Both bases unusable → genesis carries it, replaying everything.
    let cp2 = ckpt_file(dir.path(), 2);
    let len = fs::metadata(&cp2).unwrap().len();
    flip_byte(&cp2, len - 1);
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
    assert_eq!(world_items(&k.world_at(Seq(5)).unwrap()), whole);
    // The hint arrives seeded whichever base was chosen (§7 seam contract 2).
    assert_eq!(k.world_at(Seq(5)).unwrap().sum, 150);
}

#[test]
fn world_at_answers_the_base_boundary_without_consulting_the_journal() {
    // Bit-rot above the base: every boundary that must fold over the damaged
    // region halts, and the base's own boundary — answered wholly from the
    // checkpoint that embodies it — does not.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    commit(&k, 40);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 8);
    // Rot in T4's record while the kernel lives — `world_at` reads the
    // journal under the appender, which is where at-rest damage meets it.
    // The resync lands on T4's marker: a run whose inferred max (4) is above
    // the base, so a fold that must cross it could answer from a hole (§7).
    flip_byte(&seg, spans[6].0 + FRAME_HEADER_LEN + 1);
    match k.world_at(Seq(4)) {
        Err(HistoryError::Corruption { at, .. }) => assert_eq!(at, Seq(5)),
        other => panic!("expected Corruption, got {other:?}"),
    }
    assert_eq!(world_items(&k.world_at(Seq(3)).unwrap()), vec![10, 20, 30]);
}

#[test]
fn world_at_halts_on_at_rest_damage_before_judging_the_boundary() {
    // §7 refusal precedence: a corrupt run makes the boundary SET itself
    // underivable — the damage can swallow a marker — so `Corruption` speaks
    // before `NotABoundary`. Here Seq(2) IS a boundary `transact` returned and
    // the damage merely hides it; judging membership first would tell a caller
    // that their own committed coordinate was never a boundary at all.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(commit(&k, 10), Seq(1));
    assert_eq!(commit(&k, 20), Seq(2)); // a real boundary, about to be hidden
    assert_eq!(commit(&k, 30), Seq(3));
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 6);
    // Rot T2's MARKER: its txn stops being committed, so Seq(2) drops out of
    // the boundary set, and the resync lands on T3's record (inferred max 2).
    flip_byte(&seg, spans[3].0 + FRAME_HEADER_LEN + 1);
    match k.world_at(Seq(2)) {
        Err(HistoryError::Corruption { at, .. }) => assert_eq!(at, Seq(3)),
        other => panic!("expected Corruption before the boundary judgment, got {other:?}"),
    }
}

#[test]
fn world_at_halts_when_the_frame_stream_cannot_be_enumerated() {
    // A record whose own bytes plant frame headers, with the frame carrying
    // them broken: every planted header is then a resync candidate, and the
    // scan gives up rather than spending work quadratic in a size the record's
    // author chose. Nothing is derived, so there is no boundary set and no
    // committed head to answer from — a halt at the base's own coordinate (§7).
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let mut evil = Vec::new();
    while evil.len() < 256 * 1024 {
        evil.extend_from_slice(FRAME_MAGIC);
        evil.extend_from_slice(&(64 * 1024u32).to_le_bytes()); // a len that fits
        evil.extend_from_slice(&0u32.to_le_bytes()); // a crc that will not
        evil.extend_from_slice(&[0u8; 4]);
    }
    k.transact::<_, ()>(&[], |stg| {
        stg.push(TestRec::Blob(evil));
        Ok(())
    })
    .unwrap();
    assert_eq!(commit(&k, 20), Seq(2));
    let seg = seg_file(dir.path(), 1);
    flip_byte(&seg, FRAME_HEADER_LEN + 1); // T1's record: sync is lost here
    match k.world_at(Seq(2)) {
        Err(HistoryError::Corruption { at, cause }) => {
            assert_eq!(at, Seq(0));
            // The coordinate is the base's, which says nothing of where the
            // damage lies; the account names the segment that refused.
            let cause = cause.expect("the refusal names the segment it could not enumerate");
            assert!(
                cause.to_string().starts_with("seg-1.wal's frames could not be enumerated"),
                "got {cause}"
            );
        }
        other => panic!("expected Corruption at the base, got {other:?}"),
    }
}

#[test]
fn world_at_reports_an_unreadable_segment_rather_than_reading_around_it() {
    // The read path's half of the same claim, and the sharper one: a scan that
    // skipped the segment would answer from what is left — here, by reporting
    // a boundary `transact` really returned as one that never existed. `Io` is
    // what the doc promises, and it promises it as TRANSIENT: a retry
    // re-derives from the file as it then stands.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    assert_eq!(commit(&k, 20), Seq(2)); // a boundary in the segment that breaks
    for _ in 0..5 {
        commit_blob(&k); // four fill seg-1 past the threshold; the fifth rotates
    }
    assert_eq!(segment_count(dir.path()), 2, "the fixture must rotate");

    // seg-1 is closed, so the live appender is elsewhere; stash it rather than
    // destroy it, so the retry half is checkable. `seg-1.stashed` fails the
    // segment name parse and is invisible to recovery.
    let seg1 = seg_file(dir.path(), 1);
    let stash = dir.path().join("seg-1.stashed");
    fs::rename(&seg1, &stash).unwrap();
    fs::create_dir(&seg1).unwrap();
    match k.world_at(Seq(2)) {
        Err(HistoryError::Io(_)) => {}
        other => panic!("expected a transient Io, got {other:?}"),
    }

    // …and the retry re-derives from the file as it now stands.
    fs::remove_dir(&seg1).unwrap();
    fs::rename(&stash, &seg1).unwrap();
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
}

#[test]
fn world_at_refuses_a_boundary_below_the_reclamation_floor() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_retain(dir.path(), 1), genesis()).unwrap();
    for _ in 0..8 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(8));
    // Reclamation dropped seg-1: genesis is no longer reachable, and every
    // retained checkpoint sits above these boundaries, so no base at or below
    // them remains derivable (§6/§7). Refusing is the only honest answer —
    // folding a partial journal onto genesis would serve a wrong world.
    assert!(!seg_file(dir.path(), 1).exists());
    for at in [Seq(4), Seq(5)] {
        match k.world_at(at) {
            // The retained base is healthy and merely sits ABOVE the boundary
            // asked for, so no candidate was tried and there is no refusal to
            // account for. That absence is what tells a caller the floor is
            // worth re-asking at, where a base that refused to load would
            // refuse identically there.
            Err(HistoryError::Reclaimed { floor, cause: None }) => {
                assert_eq!(floor, Some(Seq(8)))
            }
            other => panic!("expected Reclaimed at {at}, got {other:?}"),
        }
    }
    // The floor the error names IS answerable — from the base embodying it.
    assert_eq!(k.world_at(Seq(8)).unwrap().items.len(), 8);
}

#[test]
fn world_at_says_why_the_floor_it_names_refuses_when_that_base_is_damaged() {
    // `Reclaimed.floor` is the oldest CANDIDATE, not a guarantee, and `cause`
    // is what tells a caller which it is. The sibling above pins the absent
    // half, where the floor answers; this is the half that ends the retry.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_retain(dir.path(), 1), genesis()).unwrap();
    for _ in 0..8 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(8));
    assert!(!seg_file(dir.path(), 1).exists(), "genesis must be unreachable");
    // Rot in the sole retained base: its header checksum refuses it.
    let cp = ckpt_file(dir.path(), 8);
    let len = fs::metadata(&cp).unwrap().len();
    flip_byte(&cp, len - 1);
    // The root the landing wrote is held, and the file still answers the
    // header it was held against, so a read at the floor stands on the root
    // and answers the committed world: the rot beneath the header is unseen
    // until the root is released, and the directory's read meets it.
    assert_eq!(k.world_at(Seq(8)).unwrap().items.len(), 8, "the held root answers");
    k.release_held_bases();

    // Below the window no candidate is tried, so the floor is the next thing
    // to ask…
    match k.world_at(Seq(4)) {
        Err(HistoryError::Reclaimed {
            floor: Some(Seq(8)),
            cause: None,
        }) => {}
        other => panic!("expected Reclaimed at 4 with nothing tried, got {other:?}"),
    }
    // …and AT the floor the base is tried, and its refusal is the answer.
    let err = k
        .world_at(Seq(8))
        .expect_err("a damaged sole base cannot answer its own boundary");
    let HistoryError::Reclaimed {
        floor: Some(Seq(8)),
        cause: Some(cause),
    } = &err
    else {
        panic!("the floor's refusal must travel, or a caller re-asks at 8 forever: {err:?}")
    };
    assert!(cause.to_string().contains("checksum"), "got {cause}");
    assert!(
        std::error::Error::source(&err).is_some(),
        "the refusal must reach a chain walker"
    );
    assert!(
        err.to_string().contains("checksum"),
        "…and the sentence an operator reads: {err}"
    );
}

#[test]
fn world_at_answers_the_same_world_under_a_live_appender() {
    // The read path takes no kernel lock and opens the journal files while
    // the appender is writing them and rotation is adding new ones. Every
    // frame at or below the head is durable before that head was installed
    // (§1 durable-before-visible), so a boundary answered under a live writer
    // answers exactly as it does at rest — including reaching back past a
    // rotation for a boundary in an older segment. Nothing reclaims here
    // (Manual), so no transient is licensed: a refusal is as much a finding
    // as a wrong answer.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20); // boundary Seq(2), below everything the writer adds
    let writing = AtomicBool::new(true);
    std::thread::scope(|s| {
        let k = &k;
        let writing = &writing;
        s.spawn(move || {
            // Fat records, so the appends straddle rotations.
            for _ in 0..20 {
                commit_blob(k);
            }
            writing.store(false, Ordering::Release);
        });
        let mut reads = 0u32;
        while writing.load(Ordering::Acquire) || reads < 20 {
            assert_eq!(
                world_items(&k.world_at(Seq(2)).expect("a live appender never refuses a read")),
                vec![10, 20],
                "history diverged under a concurrent appender"
            );
            reads += 1;
        }
    });
    assert!(
        segment_count(dir.path()) > 1,
        "the fixture must rotate, so the reads reach back past a rotation"
    );
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
}

#[test]
fn world_at_ignores_the_suffix_a_racing_append_can_leave() {
    // What a racing append can leave, injected deterministically at rest: a
    // record frame that landed without its marker, then a frame torn
    // mid-write. Neither belongs to a committed transaction; the torn one
    // classifies as an EOF run — the un-acked/torn tail, which the last
    // committed marker precedes — so a history read ignores it rather than
    // halting on it (§7), and answers the boundary it was asked for.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 4); // T1 rec/marker, T2 rec/marker
    let full_len = fs::metadata(&seg).unwrap().len();

    // A record frame that landed while its marker had not: intact, its txn
    // uncommitted, so it is never folded into an answer.
    let buf = fs::read(&seg).unwrap();
    let (offset, len) = (spans[2].0 as usize, spans[2].1 as usize);
    append_bytes(&seg, &buf[offset..offset + len]);
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);

    // A frame torn mid-write: a header claiming a payload that never landed.
    let mut torn = FRAME_MAGIC.to_vec();
    torn.extend_from_slice(&4096u32.to_le_bytes()); // a length…
    torn.extend_from_slice(&0u32.to_le_bytes()); // …a crc…
    torn.extend_from_slice(b"xyz"); // …and the payload stops here
    append_bytes(&seg, &torn);
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
    assert_eq!(world_items(&k.world_at(Seq(1)).unwrap()), vec![10]);

    // A history read writes nothing: the suffix it ignored is still there.
    assert!(fs::metadata(&seg).unwrap().len() > full_len);
}

/// §3.3 STEP 2 — THE ONE PASS EQUALS THE PER-POSITION READ: over a journal
/// with two checkpoints, attested and unattested commits and two composites,
/// `boundaries_above(p)` is, boundary by boundary in `Seq` order, `(seq,
/// attestation_at(seq))` for every committed boundary in `(p, head]` — for
/// `p` at genesis, at a checkpoint's seq, at a composite's interior, at a
/// boundary between the two checkpoints and at one above the newest — the
/// interiors absent, `p` never judged a boundary, and the slots value-equal
/// to what `transact_attested` wrote, not merely to what the other read
/// answers.
#[test]
fn boundaries_above_equals_attestation_at_boundary_by_boundary() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    let tag_a = Attestation::new(1, vec![0xA1; 64]).unwrap();
    let tag_b = Attestation::new(2, vec![0xB2; 3_373]).unwrap();
    let tag_c = Attestation::new(1, vec![0xC3]).unwrap();
    assert_eq!(commit(&k, 10), Seq(1));
    assert_eq!(commit_attested(&k, 20, &tag_a), Seq(2));
    assert_eq!(commit_all(&k, &[30, 31, 32]), Seq(5)); // interiors 3, 4
    assert_eq!(k.checkpoint().unwrap(), Seq(5));
    assert_eq!(commit_attested(&k, 60, &tag_b), Seq(6));
    assert_eq!(commit(&k, 70), Seq(7));
    assert_eq!(k.checkpoint().unwrap(), Seq(7));
    assert_eq!(commit_all(&k, &[80, 81]), Seq(9)); // interior 8
    assert_eq!(commit_attested(&k, 100, &tag_c), Seq(10));
    assert_eq!(k.current_seq(), Seq(10));
    let boundaries = [1u64, 2, 5, 6, 7, 9, 10];

    // The per-position read, once per boundary above `p`: what the one
    // pass must equal, entry for entry.
    let per_position = |p: u64| -> Vec<(Seq, Option<Attestation>)> {
        boundaries
            .iter()
            .filter(|&&b| b > p)
            .map(|&b| (Seq(b), k.attestation_at(Seq(b)).unwrap()))
            .collect()
    };
    for p in [0u64, 5, 3, 6, 8, 2, 7, 9] {
        assert_eq!(k.boundaries_above(Seq(p)).unwrap(), per_position(p), "above {p}");
    }
    assert_eq!(
        k.boundaries_above(Seq(0)).unwrap(),
        vec![
            (Seq(1), None),
            (Seq(2), Some(tag_a)),
            (Seq(5), None),
            (Seq(6), Some(tag_b)),
            (Seq(7), None),
            (Seq(9), None),
            (Seq(10), Some(tag_c)),
        ],
        "the slots are the ones written"
    );
}

/// THE ENDS: `p == head` answers the empty list — on a fresh journal, where
/// the head is genesis, as after commits — WITHOUT consulting the journal:
/// with the one segment unreadable the head's own position still answers,
/// where the position below it refuses `Io`; `p > head` refuses
/// `BeyondHead` naming the head; and an in-memory kernel refuses
/// `Unjournaled` at every position, ahead of everything.
#[test]
fn boundaries_above_answers_empty_at_the_head_and_refuses_beyond_it() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(k.boundaries_above(Seq(0)).unwrap(), vec![], "a fresh journal's head is genesis");
    assert!(matches!(k.boundaries_above(Seq(1)), Err(HistoryError::BeyondHead { head: Seq(0) })));
    commit(&k, 10);
    commit(&k, 20);
    assert_eq!(k.boundaries_above(Seq(2)).unwrap(), vec![]);
    assert_eq!(k.boundaries_above(Seq(1)).unwrap(), vec![(Seq(2), None)]);
    for beyond in [3, u64::MAX] {
        assert!(
            matches!(
                k.boundaries_above(Seq(beyond)),
                Err(HistoryError::BeyondHead { head: Seq(2) })
            ),
            "above {beyond}"
        );
    }

    // The empty range is settled by the head alone: nothing is listed, no
    // base is loaded, no segment is read.
    let seg1 = seg_file(dir.path(), 1);
    let stash = dir.path().join("seg-1.stashed");
    fs::rename(&seg1, &stash).unwrap();
    fs::create_dir(&seg1).unwrap();
    assert_eq!(k.boundaries_above(Seq(2)).unwrap(), vec![], "the head's own position");
    match k.boundaries_above(Seq(1)) {
        Err(HistoryError::Io(_)) => {}
        other => panic!("expected the segment's transient Io below the head, got {other:?}"),
    }
    fs::remove_dir(&seg1).unwrap();
    fs::rename(&stash, &seg1).unwrap();
    assert_eq!(k.boundaries_above(Seq(1)).unwrap(), vec![(Seq(2), None)]);

    let in_memory = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    commit(&in_memory, 10);
    for p in [0, 1, 9] {
        assert!(
            matches!(in_memory.boundaries_above(Seq(p)), Err(HistoryError::Unjournaled)),
            "in memory, above {p}"
        );
    }
}

/// THE FLOOR: with the journal reclaimed below a checkpoint, a position
/// below that floor refuses `Reclaimed` naming it with nothing tried, as
/// `attestation_at(p + 1)` refuses — the one base rule, a base at or below
/// the position being a base strictly below the boundary above it; and a
/// position AT the floor answers the list above it from the base embodying
/// the floor, where `attestation_at` refuses at the floor itself, its base
/// having to sit lower still.
#[test]
fn boundaries_above_refuses_below_the_reclamation_floor_and_answers_at_it() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_retain(dir.path(), 1), genesis()).unwrap();
    for _ in 0..8 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(8));
    assert!(!seg_file(dir.path(), 1).exists(), "genesis must be unreachable");
    let tag = Attestation::new(1, vec![0x5A; 16]).unwrap();
    assert_eq!(commit_attested(&k, 90, &tag), Seq(9));
    assert_eq!(commit(&k, 100), Seq(10));

    for p in [0u64, 4, 7] {
        match k.boundaries_above(Seq(p)) {
            Err(HistoryError::Reclaimed { floor: Some(Seq(8)), cause: None }) => {}
            other => panic!("expected Reclaimed above {p}, got {other:?}"),
        }
        assert!(
            matches!(
                k.attestation_at(Seq(p + 1)),
                Err(HistoryError::Reclaimed { floor: Some(Seq(8)), cause: None })
            ),
            "attestation_at({}) refuses alike",
            p + 1
        );
    }
    // AT the floor: the list above it, from the base embodying it…
    assert_eq!(k.boundaries_above(Seq(8)).unwrap(), vec![(Seq(9), Some(tag)), (Seq(10), None)]);
    assert_eq!(k.boundaries_above(Seq(9)).unwrap(), vec![(Seq(10), None)]);
    // …where the one-boundary slot read must sit below the floor, and cannot.
    assert!(matches!(
        k.attestation_at(Seq(8)),
        Err(HistoryError::Reclaimed { floor: Some(Seq(8)), cause: None })
    ));
}

/// THE AT-REST HALT: a flipped byte in a committed frame above `p` answers
/// `Corruption` at the coordinate `world_at` names, before any boundary is
/// listed — a run's own seqs are unreadable, so a list around it could omit
/// the commit it swallowed — and the journal is untouched by the read. The
/// same damage BELOW a checkpoint is embodied by that base, so the position
/// at the checkpoint's seq answers: the base rule made visible, a position
/// that is a checkpoint's seq taking that checkpoint.
#[test]
fn boundaries_above_halts_on_at_rest_damage_and_writes_nothing() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    commit(&k, 40);
    commit(&k, 50);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    // T1..T5, a record and a marker each.
    assert_eq!(spans.len(), 10);
    // Rot in T2's record: the run lands on T2's marker, inferred max 2 —
    // above genesis, embodied by the checkpoint at 3.
    flip_byte(&seg, spans[2].0 + FRAME_HEADER_LEN + 1);
    for p in [0u64, 1, 2] {
        match k.boundaries_above(Seq(p)) {
            Err(HistoryError::Corruption { at, cause: Some(cause) }) => {
                assert_eq!(at, Seq(3), "above {p}");
                assert!(
                    cause.to_string().starts_with("corrupt run in seg-1.wal from byte "),
                    "above {p}, the run's account names its segment: {cause}"
                );
            }
            other => panic!("expected Corruption above {p}, got {other:?}"),
        }
    }
    match k.world_at(Seq(1)) {
        Err(HistoryError::Corruption { at, .. }) => assert_eq!(at, Seq(3), "as world_at halts"),
        other => panic!("expected world_at to halt alike, got {other:?}"),
    }
    assert_eq!(k.boundaries_above(Seq(3)).unwrap(), vec![(Seq(4), None), (Seq(5), None)]);
    assert_eq!(k.boundaries_above(Seq(4)).unwrap(), vec![(Seq(5), None)]);

    // Rot above the base too, in T5's record: the run lands on T5's marker,
    // inferred max 5, fatal from every base below it.
    flip_byte(&seg, spans[8].0 + FRAME_HEADER_LEN + 1);
    let damaged = fs::read(&seg).unwrap();
    for p in [3u64, 4] {
        match k.boundaries_above(Seq(p)) {
            Err(HistoryError::Corruption { at, cause: Some(cause) }) => {
                assert_eq!(at, Seq(6), "above {p}");
                assert!(
                    cause.to_string().starts_with("corrupt run in seg-1.wal from byte "),
                    "above {p}, the run's account names its segment: {cause}"
                );
            }
            other => panic!("expected Corruption above {p}, got {other:?}"),
        }
    }
    assert_eq!(
        k.boundaries_above(Seq(5)).unwrap(),
        vec![],
        "the head's own position consults nothing"
    );
    // A history read writes nothing: the damage lies exactly as it was put.
    assert_eq!(fs::read(&seg).unwrap(), damaged);
}

/// UNDER A LIVE APPENDER: a read while another thread commits answers a
/// list bounded at the head the call began with — every entry a committed
/// boundary at that head, consecutive here since every commit is one
/// record, none above the head read after the call and none in `(2, the
/// head read before it]` missing — as `world_at` answers the same world
/// under the appender. Nothing reclaims (Manual), so no transient is
/// licensed: a refusal is as much a finding as a wrong list.
#[test]
fn boundaries_above_answers_a_prefix_bounded_at_the_head_under_a_live_appender() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20); // the position asked from: Seq(2), below everything the writer adds
    let writing = AtomicBool::new(true);
    std::thread::scope(|s| {
        let k = &k;
        let writing = &writing;
        s.spawn(move || {
            // Fat records, so the appends straddle rotations.
            for _ in 0..20 {
                commit_blob(k);
            }
            writing.store(false, Ordering::Release);
        });
        let mut reads = 0u32;
        while writing.load(Ordering::Acquire) || reads < 20 {
            let before = k.current_seq();
            let list = k.boundaries_above(Seq(2)).expect("a live appender never refuses a read");
            let after = k.current_seq();
            // The head the call began with lies between the two readings,
            // and the list is every boundary in (2, that head].
            let bound = list.last().map_or(2, |(seq, _)| seq.0);
            assert!(
                before.0 <= bound && bound <= after.0,
                "bounded at a head the call could have read: {before} ≤ {bound} ≤ {after}"
            );
            assert_eq!(list, (3..=bound).map(|seq| (Seq(seq), None)).collect::<Vec<_>>());
            reads += 1;
        }
    });
    assert!(
        segment_count(dir.path()) > 1,
        "the fixture must rotate, so the reads reach back past a rotation"
    );
    assert_eq!(k.boundaries_above(Seq(2)).unwrap().len(), 20);
}

// ---- the bases the kernel holds (§6) ----

/// Runs `read` on `k`, answering it beside the two base counts it moved.
///
/// The counts are every base the read stood on (`Kernel::bases_loaded`) and
/// the held ones among them (`Kernel::held_bases_stood_on`).
fn bases_moved<T>(
    k: &Kernel<TestWorld>,
    read: impl FnOnce(&Kernel<TestWorld>) -> T,
) -> (T, (u64, u64)) {
    let before = (k.bases_loaded(), k.held_bases_stood_on());
    let answer = read(k);
    (answer, (k.bases_loaded() - before.0, k.held_bases_stood_on() - before.1))
}

/// Returns the seqs of the checkpoints standing in `dir`, ascending.
fn checkpoints_on_disk(dir: &Path) -> Vec<Seq> {
    let mut seqs: Vec<Seq> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.unwrap().file_name().into_string().ok())
        .filter_map(|name| name.strip_prefix("checkpoint.")?.parse().ok().map(Seq))
        .collect();
    seqs.sort();
    seqs
}

/// Returns a board of five commits and landings at 2 and 4, two bases kept.
fn two_landings(dir: &Path) -> Kernel<TestWorld> {
    let k = Kernel::open(cfg_fsync(dir), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    commit(&k, 30);
    commit(&k, 40);
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    commit(&k, 50);
    k
}

/// A read at or above a held base stands on its root and reads no checkpoint.
///
/// Over two landings, the four reads at every coordinate whose base may sit
/// at a held one each move both counts by one, and the two whose base sits
/// below the oldest move the held count by none. Released, every answer
/// repeats exactly, each from the directory.
#[test]
fn a_read_at_or_above_a_held_base_reads_no_checkpoint() {
    let dir = tempdir().unwrap();
    let k = two_landings(dir.path());
    assert_eq!(k.held_bases(), vec![Seq(2), Seq(4)]);

    // Every read whose base may sit at a held one, answered, with its cost:
    // the worlds, the chains, the slots and the boundary lists.
    type Slot = Option<Attestation>;
    type Answers = (Vec<(Vec<u64>, u64)>, Vec<[u8; 32]>, Vec<Slot>, Vec<Vec<(Seq, Slot)>>);
    let read_all = |k: &Kernel<TestWorld>, cost: (u64, u64), why: &str| -> Answers {
        let worlds = (2..=5)
            .map(|at| {
                let (w, moved) = bases_moved(k, |k| k.world_at(Seq(at)).unwrap());
                assert_eq!(moved, cost, "world_at({at}): {why}");
                (world_items(&w), w.sum)
            })
            .collect();
        let chains = (2..=5)
            .map(|at| {
                let (chain, moved) = bases_moved(k, |k| k.chain_at(Seq(at)).unwrap());
                assert_eq!(moved, cost, "chain_at({at}): {why}");
                chain
            })
            .collect();
        let slots = (3..=5)
            .map(|at| {
                let (slot, moved) = bases_moved(k, |k| k.attestation_at(Seq(at)).unwrap());
                assert_eq!(moved, cost, "attestation_at({at}): {why}");
                slot
            })
            .collect();
        let lists = (2..=4)
            .map(|p| {
                let (list, moved) = bases_moved(k, |k| k.boundaries_above(Seq(p)).unwrap());
                assert_eq!(moved, cost, "boundaries_above({p}): {why}");
                list
            })
            .collect();
        (worlds, chains, slots, lists)
    };
    let held = read_all(&k, (1, 1), "a held base stood on, no file read");
    assert_eq!(held.0[3], (vec![10, 20, 30, 40, 50], 150), "the whole world, its hint folded");
    assert_eq!(held.1[3], k.chain_head(), "the chain at the head");

    // Below the oldest held base: the directory.
    let (w, moved) = bases_moved(&k, |k| k.world_at(Seq(1)).unwrap());
    assert_eq!((world_items(&w), moved), (vec![10], (1, 0)), "world_at(1) from genesis");
    let (slot, moved) = bases_moved(&k, |k| k.attestation_at(Seq(2)).unwrap());
    assert_eq!((slot, moved), (None, (1, 0)), "attestation_at(2): its base below 2");

    k.release_held_bases();
    assert_eq!(k.held_bases(), vec![]);
    let read = read_all(&k, (1, 0), "released, every base from the directory");
    assert_eq!(read, held, "every answer repeats exactly");
}

/// A body rotted beneath its header is unseen by a read on its held base.
///
/// The read answers the committed world from the root; released, it takes
/// the directory, where the rotted base refuses its checksum and the older
/// retained one answers the same world.
#[test]
fn a_body_rotted_beneath_its_header_is_unseen_by_a_read_on_its_held_base() {
    let dir = tempdir().unwrap();
    let k = two_landings(dir.path());
    let cp4 = ckpt_file(dir.path(), 4);
    let len = fs::metadata(&cp4).unwrap().len();
    flip_byte(&cp4, len - 1);
    let whole = (vec![10, 20, 30, 40, 50], 150);

    let (w, moved) = bases_moved(&k, |k| k.world_at(Seq(5)).unwrap());
    assert_eq!(((world_items(&w), w.sum), moved), (whole.clone(), (1, 1)), "the held root");

    k.release_held_bases();
    let (w, moved) = bases_moved(&k, |k| k.world_at(Seq(5)).unwrap());
    assert_eq!(((world_items(&w), w.sum), moved), (whole, (1, 0)), "from checkpoint.2");
}

/// A header that no longer matches sends the read to the directory.
///
/// Each variant on a board of its own, the held count moving by none in
/// each: checkpoint.4's chain head edited refuses `Corruption` at the base's
/// own coordinate, as the directory's read of that file does; its stamp
/// flipped, and the file removed, each answer the world from checkpoint.2.
#[test]
fn a_changed_header_sends_the_read_to_the_directory() {
    // `SKC4`'s chain head, bytes 24..56: no checksum or hash covers it.
    const CHAIN_HEAD_AT: u64 = 24;

    let dir = tempdir().unwrap();
    let k = two_landings(dir.path());
    flip_byte(&ckpt_file(dir.path(), 4), CHAIN_HEAD_AT + 3);
    let (out, moved) = bases_moved(&k, |k| k.world_at(Seq(5)));
    match out {
        Err(HistoryError::Corruption { at, .. }) => assert_eq!(at, Seq(4), "at the base's own"),
        other => panic!("the chain head edited: expected Corruption, got {other:?}"),
    }
    assert_eq!(moved, (1, 0), "the chain head edited: the directory's base");

    let whole = (vec![10, 20, 30, 40, 50], 150);
    let stamp_flipped = |cp4: &Path| flip_byte(cp4, 3);
    let removed = |cp4: &Path| fs::remove_file(cp4).unwrap();
    for (variant, change) in [("stamp", &stamp_flipped as &dyn Fn(&Path)), ("removed", &removed)] {
        let dir = tempdir().unwrap();
        let k = two_landings(dir.path());
        change(&ckpt_file(dir.path(), 4));
        let (w, moved) = bases_moved(&k, |k| k.world_at(Seq(5)).unwrap());
        assert_eq!(((world_items(&w), w.sum), moved), (whole.clone(), (1, 0)), "{variant}");
    }
}

/// A landing holds its root once the rename has published its base.
///
/// The directory's fsync refused past the rename answers `Landed`, the root
/// held and stood on; the temp file's fsync refused before it answers `Io`,
/// nothing published and nothing held.
#[test]
fn a_landing_holds_its_root_once_the_rename_has_published_its_base() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let at = commit(&k, 10);
    k.fail_the_next(Step::CheckpointSync, std::io::ErrorKind::StorageFull);
    assert!(matches!(k.checkpoint(), Err(CheckpointError::Io(_))));
    assert_eq!(k.held_bases(), vec![], "no base published, none held");
    k.fail_the_next(Step::CheckpointDirSync, std::io::ErrorKind::StorageFull);
    assert!(matches!(k.checkpoint(), Err(CheckpointError::Landed { .. })));
    assert_eq!(k.held_bases(), vec![at], "the base on disk, its root held");
    let (w, moved) = bases_moved(&k, |k| k.world_at(at).unwrap());
    assert_eq!((world_items(&w), moved), (vec![10], (1, 1)), "and stood on");
    assert_eq!(k.checkpoint().unwrap(), at, "a second landing at the same seq");
    assert_eq!(k.held_bases(), vec![at], "replaces the base held there");
}

/// A landing retires the held bases its retention did not keep (§6).
///
/// Under one retained base and fat records, the landing at 8 holds 8 alone
/// and reclaims the segment below it, and a read below 8 refuses `Reclaimed`
/// with nothing tried — never a scan of a held 2 over the reclaimed segment.
/// Under two, over six landings, the held seqs are the checkpoints on disk
/// after each.
#[test]
fn a_landing_retires_the_held_bases_its_retention_did_not_keep() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_retain(dir.path(), 1), genesis()).unwrap();
    commit_blob(&k);
    commit_blob(&k);
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    for _ in 0..6 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(8));
    assert_eq!(k.held_bases(), vec![Seq(8)]);
    assert!(!seg_file(dir.path(), 1).exists(), "the segment below 8 reclaimed");
    for at in [Seq(2), Seq(3)] {
        match k.world_at(at) {
            Err(HistoryError::Reclaimed { floor: Some(Seq(8)), cause: None }) => {}
            other => panic!("at {at}: expected Reclaimed, never Corruption, got {other:?}"),
        }
    }

    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    for landing in 1..=6 {
        commit_blob(&k);
        k.checkpoint().unwrap();
        assert_eq!(k.held_bases(), checkpoints_on_disk(dir.path()), "landing {landing}");
    }
}

/// A landing retires a held base its retention removed though the cap keeps it.
///
/// A base landed past its directory's fsync by an unwind is on disk and not
/// held, so at the next landing the cap leaves two bases held while
/// retention keeps the unheld one beside the new: only the retirement leaves
/// the new base alone held, one of the two on disk.
#[test]
fn a_landing_retires_a_held_base_its_retention_removed_though_the_cap_keeps_it() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    let a = commit(&k, 10);
    k.checkpoint().unwrap();
    let b = commit(&k, 20);
    k.checkpoint().unwrap();
    assert_eq!(k.held_bases(), vec![a, b]);
    let c = commit(&k, 30);
    k.panic_at_the_next(Step::CheckpointDirSync);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| k.checkpoint()));
    assert!(unwound.is_err(), "the armed step unwinds past the rename");
    assert_eq!(checkpoints_on_disk(dir.path()), vec![a, b, c], "c landed on disk");
    assert_eq!(k.held_bases(), vec![a, b], "…and is not held: the unwind ran past the hold");
    let d = commit(&k, 40);
    assert_eq!(k.checkpoint().unwrap(), d);
    assert_eq!(checkpoints_on_disk(dir.path()), vec![c, d], "retention removed a and b");
    assert_eq!(k.held_bases(), vec![d], "b, which the cap kept, retired with its file");
}

/// The open holds its start base, and no other.
///
/// Reopened over checkpoints 2 and 4, it holds 4 alone, so reads below 4
/// take the directory, and the next landing holds its root beside 4. A
/// fresh directory and an in-memory kernel hold nothing; and with the newest
/// base rotted before a reopen the older one it loads is held, the skipped
/// one never.
#[test]
fn the_open_holds_its_start_base_and_no_other() {
    let dir = tempdir().unwrap();
    {
        let fresh = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
        assert_eq!(fresh.held_bases(), vec![], "a fresh directory: genesis, which is not held");
    }
    drop(two_landings(dir.path()));
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(k.held_bases(), vec![Seq(4)]);
    for (at, items) in [(2, vec![10, 20]), (3, vec![10, 20, 30])] {
        let (w, moved) = bases_moved(&k, |k| k.world_at(Seq(at)).unwrap());
        assert_eq!((world_items(&w), moved), (items, (1, 0)), "{at}: below 4, the directory");
    }
    let (w, moved) = bases_moved(&k, |k| k.world_at(Seq(5)).unwrap());
    let whole = (vec![10, 20, 30, 40, 50], 150);
    assert_eq!(((world_items(&w), w.sum), moved), (whole, (1, 1)), "above it, the held base");
    let s = commit(&k, 60);
    assert_eq!(k.checkpoint().unwrap(), s);
    assert_eq!(k.held_bases(), vec![Seq(4), s]);
    drop(k);

    let in_memory = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    commit(&in_memory, 10);
    assert_eq!(in_memory.checkpoint().unwrap(), Seq(1));
    assert_eq!(in_memory.held_bases(), vec![], "in memory, nothing is held");

    let cp = ckpt_file(dir.path(), s.0);
    let len = fs::metadata(&cp).unwrap().len();
    flip_byte(&cp, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let recovery = k.recovery().expect("journaled");
    assert_eq!((recovery.start_point, recovery.skipped[0].seq), (Seq(4), s));
    assert_eq!(k.held_bases(), vec![Seq(4)], "the base it loaded");
    let next = commit(&k, 70);
    k.checkpoint().unwrap();
    assert_eq!(k.held_bases(), vec![Seq(4), next], "the skipped one never");
}

/// The open holds no base where genesis stood in, a checkpoint at 0 skipped.
///
/// A checkpoint taken before the first commit is a file at genesis's seq: one
/// that loads is the open's start base, and held. Rotted beneath its intact
/// header it is passed over and genesis stands in, and nothing is held,
/// though a header still answers at 0.
#[test]
fn the_open_holds_no_base_where_genesis_stood_in_beside_a_checkpoint_at_zero() {
    let dir = tempdir().unwrap();
    {
        let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
        assert_eq!(k.checkpoint().unwrap(), Seq(0));
        assert_eq!(k.held_bases(), vec![Seq(0)], "a landing at genesis holds its root");
    }
    {
        let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
        assert!(k.recovery().expect("journaled").skipped.is_empty());
        assert_eq!(k.held_bases(), vec![Seq(0)], "the checkpoint at 0 loaded, and is held");
    }
    let cp0 = ckpt_file(dir.path(), 0);
    let len = fs::metadata(&cp0).unwrap().len();
    flip_byte(&cp0, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let recovery = k.recovery().expect("journaled");
    assert_eq!((recovery.start_point, recovery.skipped.len()), (Seq(0), 1), "genesis stood in");
    assert!(k.checkpoint_header(Seq(0)).is_some(), "the rotted file still answers its header");
    assert_eq!(k.held_bases(), vec![], "genesis is not held, nor the base passed over");
}

/// A read racing landings meets no damage that is not in the journal.
///
/// Under one retained base and fat records, one thread lands a checkpoint
/// after every commit — each holding its root, retiring the last and
/// reclaiming the segments below — while another reads the world and the
/// chain at the head and the boundary below it, a bounded number of times:
/// every refusal is a transient or a verdict on the position, never
/// `Corruption`.
#[test]
fn a_read_racing_landings_meets_no_damage_that_is_not_in_the_journal() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_retain(dir.path(), 1), genesis()).unwrap();
    commit_blob(&k);
    commit_blob(&k);
    let landing = AtomicBool::new(true);
    std::thread::scope(|s| {
        let k = &k;
        let landing = &landing;
        s.spawn(move || {
            for _ in 0..24 {
                commit_blob(k);
                k.checkpoint().expect("a landing");
            }
            landing.store(false, Ordering::Release);
        });
        // A segment or a checkpoint a landing removed under the read, or a
        // position a landing's reclamation took: what a retry re-derives.
        let licensed = |refusal: &HistoryError| match refusal {
            HistoryError::Io(e) => e.kind() == std::io::ErrorKind::NotFound,
            HistoryError::Reclaimed { .. } | HistoryError::NotABoundary { .. } => true,
            _ => false,
        };
        let mut reads = 0u32;
        while landing.load(Ordering::Acquire) && reads < 5_000 {
            let head = k.current_seq();
            for at in [head, Seq(head.0 - 1)] {
                for answer in [k.world_at(at).map(|_| ()), k.chain_at(at).map(|_| ())] {
                    if let Err(refusal) = answer {
                        assert!(licensed(&refusal), "a read at {at} beside a landing: {refusal:?}");
                    }
                }
            }
            reads += 1;
        }
    });
    assert_eq!(segment_count(dir.path()), 1, "the landings reclaimed every closed segment");
}
