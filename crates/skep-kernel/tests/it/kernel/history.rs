//! Bounded replay, `Kernel::world_at`: the base it selects, the refusals it
//! makes and their order, and the answers it gives beside a live appender
//! (§6/§7).

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::mutilate::{append_bytes, ckpt_file, flip_byte, seg_file};
use skep_kernel::HistoryError;
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
        evil.extend_from_slice(b"SKJ4");
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
        Err(HistoryError::Corruption { at, .. }) => assert_eq!(at, Seq(0)),
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
    // committed marker precedes — so a bounded read ignores it rather than
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
    let mut torn = b"SKJ4".to_vec();
    torn.extend_from_slice(&4096u32.to_le_bytes()); // a length…
    torn.extend_from_slice(&0u32.to_le_bytes()); // …a crc…
    torn.extend_from_slice(b"xyz"); // …and the payload stops here
    append_bytes(&seg, &torn);
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
    assert_eq!(world_items(&k.world_at(Seq(1)).unwrap()), vec![10]);

    // A bounded read writes nothing: the suffix it ignored is still there.
    assert!(fs::metadata(&seg).unwrap().len() > full_len);
}
