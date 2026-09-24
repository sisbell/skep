//! The GOLDEN BYTE FIXTURE (the encoding report's §7; QUEUE item 10, the
//! hash chain's first lane; `SKJ4`/`SKC4` since the chain's salt): one
//! journal segment, one checkpoint and one world dump per boundary, produced
//! BY THE OPS of [`Fixture::build_golden`] — the hazard suite's eleven
//! extended by the seven that reach every journal variant and leaf form —
//! under the SEEDED salt source ([`GOLDEN_SALT_SEED`]: a marker's salt is a
//! pure function of the seed and the transaction, so the bytes reproduce),
//! and committed under `tests/golden/` as `seg-1.wal`, `checkpoint.<S>` and
//! `dumps/<seq>.txt`.
//!
//! What the pin catches: a release of bincode or serde that moves a width or
//! a tag, a field reordered or inserted, a variant inserted, a shadow that no
//! longer matches its type, a chain formula or seed that moves, a salt
//! formula that moves, a checkpoint header field that moves, a slice whose
//! iteration order stops being a function of its contents — each fails here
//! by name. What it cannot catch is a change that keeps the bytes, which is
//! no change.
//!
//! Three tests, as the report names them: the WRITER pin (the ops reproduce
//! the files byte for byte), the READER pin (this build opens the files and
//! answers every recorded boundary — H6's frozen data dir), and the STAMP
//! gate (the files carry this build's own format stamps, so a bump without a
//! new golden fails by name). A fourth proves option (i)'s claim directly:
//! two PROCESSES writing one history write one checkpoint byte string.
//!
//! REGENERATION — at a format bump or a genesis change, and never otherwise:
//!
//! ```text
//! SKEP_GOLDEN_WRITE=1 cargo test -p skep-kernel --test it golden::the_writer_pin
//! ```
//!
//! rewrites the three artifacts from the ops; the stamp gate then holds the
//! new files to the new stamp, and the bump's commit carries them.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::hazard_util::{
    cfg_manual, ckpt_file, copy_dir, flip_byte, node1, seg_file, Fixture, GOLDEN_OPS,
    GOLDEN_SALT_SEED, USER,
};
use skep_engine::Engine;
use skep_kernel::Seq;
use skep_namespace::{HasM3, BOOTSTRAP_PRINCIPAL};
use tempfile::tempdir;

/// The op after which the golden checkpoints: the pivot, so the checkpoint
/// body carries the wide node, the published bit, both documents and a
/// fragmented arrangement, and the copy and the swap replay ABOVE it — the
/// reader pin then exercises the `SKC4` header's `chain_head` as the value
/// the chain continues from, and the boundaries below it fold from genesis
/// with the chain verified from its seed.
const CHECKPOINT_AFTER_OP: usize = 16;

/// The seed the golden was regenerated under, restated beside the stamps it
/// belongs with: a golden written under another seed carries other salts,
/// other chains and another checkpoint header, and fails the writer pin by
/// name.
const _: () = assert!(GOLDEN_SALT_SEED == 0x534B_4A34);

/// The journal frame header: magic + len + crc, restated for the byte-level
/// probe below.
const FRAME_HEADER_LEN: u64 = 12;

/// The golden's home, beside the crate and under version control.
fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden")
}

/// The one `checkpoint.<S>` in `dir`.
fn checkpoint_in(dir: &Path) -> PathBuf {
    let mut found: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("list {}: {e}", dir.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("checkpoint."))
                .is_some_and(|seq| seq.parse::<u64>().is_ok())
        })
        .collect();
    assert_eq!(found.len(), 1, "exactly one checkpoint expected in {}: {found:?}", dir.display());
    found.pop().expect("one checkpoint")
}

/// The recorded dumps, by boundary — `0` is genesis.
fn golden_dumps() -> BTreeMap<u64, String> {
    let dumps = golden_dir().join("dumps");
    fs::read_dir(&dumps)
        .unwrap_or_else(|e| panic!("list {}: {e}", dumps.display()))
        .map(|entry| {
            let path = entry.expect("a directory entry").path();
            let seq: u64 = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse().ok())
                .unwrap_or_else(|| panic!("a dump is named <seq>.txt: {}", path.display()));
            (seq, fs::read_to_string(&path).expect("read a dump"))
        })
        .collect()
}

/// The four bytes a file opens with — its format stamp.
fn stamp_of(path: &Path) -> [u8; 4] {
    let data = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    data[..4].try_into().expect("four bytes")
}

fn stamp_text(stamp: &[u8; 4]) -> String {
    stamp.escape_ascii().to_string()
}

/// The golden's ops, into `dir`.
fn build_golden_fixture(dir: &Path) -> Fixture {
    Fixture::build_golden(dir, &[CHECKPOINT_AFTER_OP])
}

/// Whether this run REWRITES the golden from the ops (`SKEP_GOLDEN_WRITE=1`)
/// — the regeneration path at a format bump, never set in the gate.
fn rewriting() -> bool {
    std::env::var_os("SKEP_GOLDEN_WRITE").is_some_and(|v| v == "1")
}

/// Replace the golden with `fixture`'s files: the segment, the checkpoint,
/// and one dump per boundary, genesis included.
fn write_golden(fixture: &Fixture) {
    let golden = golden_dir();
    if golden.exists() {
        fs::remove_dir_all(&golden).expect("clear the old golden");
    }
    fs::create_dir_all(golden.join("dumps")).expect("create the golden dir");
    fs::copy(seg_file(&fixture.dir, 1), golden.join("seg-1.wal")).expect("copy the segment");
    let checkpoint = checkpoint_in(&fixture.dir);
    fs::copy(&checkpoint, golden.join(checkpoint.file_name().expect("a name")))
        .expect("copy the checkpoint");
    fs::write(golden.join("dumps").join("0.txt"), fixture.genesis_dump.as_str())
        .expect("write the genesis dump");
    for boundary in &fixture.boundaries {
        fs::write(
            golden.join("dumps").join(format!("{}.txt", boundary.seq)),
            boundary.dump.as_str(),
        )
        .expect("write a boundary dump");
    }
    eprintln!("golden rewritten at {}", golden.display());
}

/// Byte equality that names the first divergence, so a moved byte reports
/// as an offset rather than as two hex dumps. `theirs` is the golden in the
/// writer pin and the second process's file in the two-process proof, so the
/// remedy is the caller's to name, in `what`.
fn assert_bytes_equal(mine: &[u8], theirs: &[u8], what: &str) {
    if mine == theirs {
        return;
    }
    let first = mine
        .iter()
        .zip(theirs)
        .position(|(a, b)| a != b)
        .unwrap_or(mine.len().min(theirs.len()));
    panic!(
        "{what} — first divergence at byte {first} (this process wrote {} bytes, the other file \
         holds {}); this process's byte there is {:?}, the other's {:?}",
        mine.len(),
        theirs.len(),
        mine.get(first),
        theirs.get(first)
    );
}

/// What the writer pin says when the ops no longer reproduce a golden file.
const GOLDEN_MOVED: &str = "the ops no longer reproduce the golden; a moved byte is a format \
    event: if it is meant, bump the stamp and regenerate with SKEP_GOLDEN_WRITE=1";

/// (a) THE WRITER PIN — the ops, driven into a temporary directory, write
/// `seg-1.wal` and `checkpoint.<S>` byte-equal to the golden, and dump every
/// boundary equal to the recorded dumps. Every byte of the format is under
/// this pin: the frame envelope, the codec's widths and tags, every record
/// variant and leaf form, the marker's chain and slot, the checkpoint header
/// with its chain head and body hash, and the canonical order of every slice
/// in the body.
#[test]
fn the_writer_pin_the_ops_reproduce_the_golden_byte_for_byte() {
    let tmp = tempdir().expect("tempdir");
    let fixture = build_golden_fixture(&tmp.path().join("fixture"));
    assert_eq!(fixture.boundaries.len(), GOLDEN_OPS);
    if rewriting() {
        write_golden(&fixture);
    }
    let golden = golden_dir();

    let mine = fs::read(seg_file(&fixture.dir, 1)).expect("read the segment written");
    let theirs = fs::read(golden.join("seg-1.wal")).expect("read the golden segment");
    assert_bytes_equal(&mine, &theirs, &format!("seg-1.wal: {GOLDEN_MOVED}"));

    let my_checkpoint = checkpoint_in(&fixture.dir);
    let golden_checkpoint = checkpoint_in(&golden);
    assert_eq!(
        my_checkpoint.file_name(),
        golden_checkpoint.file_name(),
        "the checkpoint is taken at the boundary the golden's is"
    );
    assert_eq!(
        golden_checkpoint.file_name().and_then(|n| n.to_str()),
        Some(format!("checkpoint.{}", fixture.boundaries[CHECKPOINT_AFTER_OP - 1].seq).as_str())
    );
    let mine = fs::read(&my_checkpoint).expect("read the checkpoint written");
    let theirs = fs::read(&golden_checkpoint).expect("read the golden checkpoint");
    assert_bytes_equal(&mine, &theirs, &format!("checkpoint.<S>: {GOLDEN_MOVED}"));

    let dumps = golden_dumps();
    assert_eq!(
        dumps.len(),
        fixture.boundaries.len() + 1,
        "one dump per boundary, genesis included, and none the ops did not produce"
    );
    assert_eq!(dumps.get(&0).map(String::as_str), Some(fixture.genesis_dump.as_str()));
    for boundary in &fixture.boundaries {
        assert_eq!(
            dumps.get(&boundary.seq).map(String::as_str),
            Some(boundary.dump.as_str()),
            "the dump at boundary {} is not the golden's",
            boundary.seq
        );
    }
}

/// (b) THE READER PIN — this build opens a copy of the golden directory and
/// answers its head, its live dump and every recorded boundary's `world_at`
/// dump, writes nothing to the files, and takes the golden checkpoint as its
/// base: H6's frozen-data-dir compatibility check, over the files as they
/// were committed.
#[test]
fn the_reader_pin_this_build_opens_the_golden_and_answers_every_boundary() {
    let tmp = tempdir().expect("tempdir");
    let case = tmp.path().join("golden");
    copy_dir(&golden_dir(), &case); // the regular files: the segment, the checkpoint
    let segment = seg_file(&case, 1);
    let checkpoint = checkpoint_in(&case);
    let (segment_before, checkpoint_before) =
        (fs::read(&segment).expect("segment"), fs::read(&checkpoint).expect("checkpoint"));
    let dumps = golden_dumps();
    let last = *dumps.keys().max().expect("the golden records boundaries");

    let engine = Engine::open(cfg_manual(&case))
        .unwrap_or_else(|e| panic!("this build does not open the golden: {e}"));
    assert_eq!(engine.kernel().current_seq(), Seq(last), "the recovered head");
    assert_eq!(
        engine.world_dump().as_str(),
        dumps[&last],
        "the recovered world is not the one the golden recorded at its head"
    );
    for (seq, dump) in &dumps {
        let world = engine
            .world_at(Seq(*seq))
            .unwrap_or_else(|e| panic!("boundary {seq} of the golden is unanswerable: {e}"));
        assert_eq!(
            engine.dump_of(&world).as_str(),
            dump,
            "history at boundary {seq} diverges from what the golden recorded"
        );
    }
    engine.check_hints().expect("the recovered hints equal a from-authoritative rebuild");
    drop(engine);
    assert_eq!(fs::read(&segment).expect("segment"), segment_before, "the open cut the segment");
    assert_eq!(fs::read(&checkpoint).expect("checkpoint"), checkpoint_before);

    // The checkpoint IS the base, not a bystander: with a byte flipped inside
    // the first transaction — far below the checkpoint's coordinate — the
    // open still succeeds at the same head with the same world, because the
    // run is embodied in the base and never replayed. Off genesis the same
    // damage halts, which is what tells the two apart.
    let probe = tmp.path().join("probe");
    copy_dir(&golden_dir(), &probe);
    flip_byte(&seg_file(&probe, 1), FRAME_HEADER_LEN + 1);
    let engine = Engine::open(cfg_manual(&probe))
        .unwrap_or_else(|e| panic!("the golden checkpoint did not stand in as the base: {e}"));
    assert_eq!(engine.kernel().current_seq(), Seq(last));
    assert_eq!(engine.world_dump().as_str(), dumps[&last]);
    assert!(
        engine.world_at(Seq(1)).is_err(),
        "below the base the damaged first transaction must halt a genesis replay"
    );
}

/// (c) THE STAMP GATE — the golden's files open with this build's own
/// format stamps, observed through the public surface (a fresh journal's and
/// a fresh checkpoint's first four bytes), and those are `SKJ4` and `SKC4`.
/// A stamp bump without a regenerated golden fails here by name, as does a
/// regenerated golden under a stamp this test does not spell.
#[test]
fn the_stamp_gate_the_golden_carries_this_builds_format_stamps() {
    let tmp = tempdir().expect("tempdir");
    let probe = tmp.path().join("probe");
    let (journal_stamp, checkpoint_stamp) = {
        let engine = Engine::open(cfg_manual(&probe)).expect("probe open");
        let prefix = {
            let snap = engine.kernel().snapshot();
            snap.world().m3().next_account_prefix(&node1()).expect("a delegable prefix")
        };
        engine
            .namespace()
            .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), USER)
            .expect("one commit, so the segment holds a frame");
        let at = engine.kernel().checkpoint().expect("one checkpoint");
        (stamp_of(&seg_file(&probe, 1)), stamp_of(&ckpt_file(&probe, at.0)))
    };

    let golden = golden_dir();
    let golden_journal_stamp = stamp_of(&golden.join("seg-1.wal"));
    let golden_checkpoint_stamp = stamp_of(&checkpoint_in(&golden));
    assert_eq!(
        golden_journal_stamp,
        journal_stamp,
        "the golden journal was written under `{}`; this build writes `{}` — a format bump \
         without a new golden. Regenerate with SKEP_GOLDEN_WRITE=1 and commit the files under \
         the new stamp",
        stamp_text(&golden_journal_stamp),
        stamp_text(&journal_stamp)
    );
    assert_eq!(
        golden_checkpoint_stamp,
        checkpoint_stamp,
        "the golden checkpoint was written under `{}`; this build writes `{}` — a format bump \
         without a new golden. Regenerate with SKEP_GOLDEN_WRITE=1 and commit the files under \
         the new stamp",
        stamp_text(&golden_checkpoint_stamp),
        stamp_text(&checkpoint_stamp)
    );
    // The spellings this lane pinned: a regenerated golden under a later
    // stamp must move these too, in the same commit as its stamp bump.
    assert_eq!(&golden_journal_stamp, b"SKJ4");
    assert_eq!(&golden_checkpoint_stamp, b"SKC4");
}

/// Option (i)'s claim, proved directly: two PROCESSES — this one and a
/// re-exec of this test binary, each with its own `RandomState`, its own
/// hasher instances, its own allocation order — write one history to one
/// checkpoint byte string, and one journal. The writer pin proves the same
/// across time (the golden was written by another process on another day);
/// this proves it without the golden in the loop.
#[test]
fn two_processes_write_one_history_to_one_checkpoint_byte_string() {
    if let Some(dir) = std::env::var_os("SKEP_GOLDEN_CHILD_DIR") {
        // The child half: the same ops, into the directory the parent named.
        build_golden_fixture(Path::new(&dir));
        return;
    }
    let tmp = tempdir().expect("tempdir");
    let mine = build_golden_fixture(&tmp.path().join("mine"));
    let theirs = tmp.path().join("theirs");
    let status = Command::new(std::env::current_exe().expect("test binary path"))
        .args([
            "golden::two_processes_write_one_history_to_one_checkpoint_byte_string",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SKEP_GOLDEN_CHILD_DIR", &theirs)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn the second process");
    assert!(status.success(), "the second process failed to build the fixture: {status}");

    let (my_checkpoint, their_checkpoint) = (checkpoint_in(&mine.dir), checkpoint_in(&theirs));
    assert_eq!(my_checkpoint.file_name(), their_checkpoint.file_name());
    assert_bytes_equal(
        &fs::read(&my_checkpoint).expect("my checkpoint"),
        &fs::read(&their_checkpoint).expect("their checkpoint"),
        "checkpoint.<S> across two processes",
    );
    assert_bytes_equal(
        &fs::read(seg_file(&mine.dir, 1)).expect("my segment"),
        &fs::read(seg_file(&theirs, 1)).expect("their segment"),
        "seg-1.wal across two processes",
    );
}
