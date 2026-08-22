//! H3 — the dirty-crash program over M2's contracts, driven hostile: torn
//! journal tails (exhaustive over the final record), garbage tails,
//! checkpoint corruption, and kill-mid-checkpoint process crashes. Fixtures
//! are built through the PUBLIC engine surface, mutilated as files on a
//! closed store, and judged through the public surface against the
//! capture-and-compare oracle in `hazard_util` — exactly three honest
//! outcomes per the contracts (full recovery / bounded rollback of
//! never-acked tail / loud refusal); silent divergence and wedged opens are
//! findings.
//!
//! Finding protocol (per the H3 ruling): a test that discovers a real
//! contract violation is converted to `#[ignore = "FINDING-<n>: …"]` with
//! its assertion INTACT and the reproduction in a comment block — never
//! weakened, never left failing. `HAZARD_EXHAUSTIVE=1` unlocks the full
//! sweeps; default grids stay inside the suite's runtime budget.

mod hazard_util;

use std::fs;
use std::io::{BufRead, BufReader, Write as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use hazard_util::*;
use skep_content::Val;
use skep_engine::observe::dump;
use skep_engine::{Engine, EngineError, GenesisConfig, OpenError};
use skep_kernel::{CheckpointPolicy, Seq};
use skep_namespace::{HasM3, BOOTSTRAP_PRINCIPAL};
use tempfile::tempdir;

// ── A. Torn journal tail ─────────────────────────────────────────────────

/// Scenario A: truncate the journal to every prefix length in the grid and
/// reopen. Every prefix must recover to EXACTLY the last committed marker
/// wholly inside it (outcome 1/2; the torn suffix classifies as EOF), with
/// the world byte-equal to the healthy-life oracle — no refusal, no wedge,
/// no silent divergence.
///
/// Grid: dense (every byte length) over the final two transactions' byte
/// range — the "exhaustive over the final record" clause with one txn of
/// margin — plus stride-37 samples down to zero; `HAZARD_EXHAUSTIVE=1`
/// sweeps every length from full−1 to 0.
#[test]
fn a_torn_journal_tail_recovers_to_the_exact_boundary() {
    let tmp = tempdir().expect("tempdir");
    let fixture = Fixture::build(&tmp.path().join("fixture"), &[]);
    let full_len = fixture.full_len;
    let n = fixture.boundaries.len();
    let dense_lo = fixture.boundaries[n - 3].journal_len;
    let prefix_lens: Vec<u64> = if exhaustive() {
        (0..full_len).rev().collect()
    } else {
        let mut v: Vec<u64> = (dense_lo..full_len).rev().collect();
        v.extend((0..dense_lo).step_by(37));
        v
    };

    let cases = tmp.path().join("cases");
    let mut by_boundary: std::collections::BTreeMap<u64, usize> = Default::default();
    for (i, &prefix_len) in prefix_lens.iter().enumerate() {
        let case = cases.join(format!("a-{prefix_len}"));
        copy_dir(&fixture.dir, &case);
        truncate_file(&seg_file(&case, 1), prefix_len);
        let ctx = format!("A: torn tail, prefix {prefix_len} of {full_len}");
        // Deep history probes on a sample; head + dump equality on every one.
        let depth = if i % 25 == 0 { Depth::Full } else { Depth::Head };
        let head = judge_prefix(&fixture, &case, prefix_len, depth, &ctx);
        *by_boundary.entry(head).or_default() += 1;
        fs::remove_dir_all(&case).expect("case cleanup");
    }
    println!(
        "A: {} prefixes judged (dense {}..{}, stride 37 below; exhaustive={}); \
         recovered-boundary distribution: {:?}",
        prefix_lens.len(),
        dense_lo,
        full_len,
        exhaustive(),
        by_boundary
    );
}

// ── B. Torn tail + garbage tail ──────────────────────────────────────────

/// Scenario B: instead of a clean truncation, the tail is junk — appended
/// after a cut, or overwritten in place to EOF — in three patterns (zeros,
/// 0xFF, seeded random). "A torn suffix classifies as EOF": the junk must
/// never be read as records, so the judgment is identical to scenario A's
/// at the same cut point.
#[test]
fn b_garbage_tail_classifies_as_eof_not_as_records() {
    let tmp = tempdir().expect("tempdir");
    let fixture = Fixture::build(&tmp.path().join("fixture"), &[]);
    let full_len = fixture.full_len;
    let n = fixture.boundaries.len();

    // Cut points: for each covered txn its clean boundary, boundary−1, and
    // a mid-txn byte; plus the clean full journal (pure garbage beyond it).
    let first_boundary = if exhaustive() { 1 } else { n - 3 };
    let mut cuts: Vec<u64> = vec![full_len];
    for boundary_index in first_boundary..n {
        let lo = fixture.boundaries[boundary_index - 1].journal_len;
        let hi = fixture.boundaries[boundary_index].journal_len;
        cuts.push(hi - 1);
        cuts.push(lo + (hi - lo) / 2);
        cuts.push(lo);
    }
    cuts.sort_unstable();
    cuts.dedup();

    let junk_lens: &[u64] = if exhaustive() { &[1, 7, 64, 512, 4096] } else { &[7, 512] };
    let cases = tmp.path().join("cases");
    let mut judged = 0usize;
    for (cut_index, &cut) in cuts.iter().enumerate() {
        let patterns = [
            Junk::Zeros,
            Junk::Ones,
            Junk::Rand(0x5EED_0000 + cut_index as u64),
        ];
        for pattern in patterns {
            for &junk_len in junk_lens {
                let case = cases.join(format!("b-app-{cut}-{}-{junk_len}", pattern.name()));
                copy_dir(&fixture.dir, &case);
                truncate_file(&seg_file(&case, 1), cut);
                append_bytes(&seg_file(&case, 1), &pattern.bytes(junk_len as usize));
                let ctx = format!(
                    "B: cut {cut} of {full_len} + {} junk ×{junk_len} appended \
                     (seed base 0x5EED_0000+{cut_index})",
                    pattern.name()
                );
                judge_prefix(&fixture, &case, cut, Depth::Head, &ctx);
                fs::remove_dir_all(&case).expect("case cleanup");
                judged += 1;
            }
            if cut < full_len {
                let case = cases.join(format!("b-ovr-{cut}-{}", pattern.name()));
                copy_dir(&fixture.dir, &case);
                overwrite_range(&seg_file(&case, 1), cut, &pattern.bytes((full_len - cut) as usize));
                let ctx = format!(
                    "B: in-place {} overwrite of [{cut}, {full_len}) \
                     (seed base 0x5EED_0000+{cut_index})",
                    pattern.name()
                );
                judge_prefix(&fixture, &case, cut, Depth::Head, &ctx);
                fs::remove_dir_all(&case).expect("case cleanup");
                judged += 1;
            }
        }
    }
    println!(
        "B: {judged} garbage-tail cases judged over {} cut points (exhaustive={})",
        cuts.len(),
        exhaustive()
    );
}

// ── C. Checkpoint corruption ─────────────────────────────────────────────

/// A checkpoint file's header: magic + seq + crc + body_len. Restated here
/// because this tier damages the format as bytes rather than through the
/// crate's own writer; the body starts at this offset.
const CHECKPOINT_HEADER_LEN: u64 = 24;

/// The offset halfway through the body of a checkpoint file of `len` bytes —
/// where a flip or a cut lands in the serialized `W` rather than in a header
/// field, so the damage is the body checksum's to catch.
fn mid_body(len: u64) -> u64 {
    CHECKPOINT_HEADER_LEN + (len - CHECKPOINT_HEADER_LEN) / 2
}

/// Scenario C (i)–(iii) plus the stray-`.tmp` case: with two retained
/// checkpoints and an intact journal, ANY damage to checkpoints — a flipped
/// byte at every header/body region of the newest, truncations, deletion of
/// the newest, and all-retained damage — must yield FULL recovery (fallback
/// to the older base or to genesis, replaying more), never a silent serve
/// from a corrupt base. The dump comparison against the pure-fold oracle is
/// what would catch a silently-wrong base.
///
/// (iv) with genesis still reachable: corrupting ALL retained checkpoints
/// recovers fully by journal replay from genesis — that is the contract's
/// answer here, and this test documents it; the loud-refusal half of (iv)
/// lives in the next test, where reclamation has made genesis unreachable.
#[test]
fn c_checkpoint_damage_falls_back_and_never_serves_a_corrupt_base() {
    let tmp = tempdir().expect("tempdir");
    // Checkpoints after ops 4 and 8: two retained bases, a replay tail.
    let fixture = Fixture::build(&tmp.path().join("fixture"), &[4, 8]);
    let newest = ckpt_file(&fixture.dir, fixture.boundaries[7].seq);
    let older = ckpt_file(&fixture.dir, fixture.boundaries[3].seq);
    assert!(newest.exists() && older.exists(), "fixture holds two retained checkpoints");
    let newest_len = fs::metadata(&newest).expect("newest checkpoint").len();
    let newest_name = newest.file_name().expect("name").to_owned();
    let older_name = older.file_name().expect("name").to_owned();

    let cases = tmp.path().join("cases");
    let mut judged = 0usize;
    let mut run = |label: String, mutate: &dyn Fn(&std::path::Path)| {
        let case = cases.join(format!("c-{judged}"));
        copy_dir(&fixture.dir, &case);
        mutate(&case);
        judge_full_recovery(&fixture, &case, &format!("C: {label}"));
        fs::remove_dir_all(&case).expect("case cleanup");
        judged += 1;
    };

    // (i) one flipped byte: magic, seq field, crc field, body_len field,
    // mid-body, last byte.
    for offset in [0, 5, 13, 20, mid_body(newest_len), newest_len - 1] {
        let name = newest_name.clone();
        run(
            format!("newest checkpoint byte {offset} flipped"),
            &move |case| flip_byte(&case.join(&name), offset),
        );
    }
    // (ii) truncations: empty, mid-header, header-only, mid-body, last-byte.
    for cut in [0, 10, CHECKPOINT_HEADER_LEN, mid_body(newest_len), newest_len - 1] {
        let name = newest_name.clone();
        run(format!("newest checkpoint truncated to {cut}"), &move |case| {
            truncate_file(&case.join(&name), cut)
        });
    }
    // (iii) newest deleted.
    {
        let name = newest_name.clone();
        run("newest checkpoint deleted".into(), &move |case| {
            fs::remove_file(case.join(&name)).expect("delete newest checkpoint")
        });
    }
    // A crash-mid-checkpoint leftover: junk `checkpoint.tmp` must be ignored.
    run("stray junk checkpoint.tmp".into(), &|case| {
        fs::write(case.join("checkpoint.tmp"), b"\xFF\x00garbage, not a checkpoint")
            .expect("write junk tmp")
    });
    // (iv, genesis-reachable) ALL retained checkpoints damaged three ways.
    {
        let (newest_name, older_name) = (newest_name.clone(), older_name.clone());
        run("both checkpoints flipped mid-body".into(), &move |case| {
            flip_byte(&case.join(&newest_name), mid_body(newest_len));
            let older_len = fs::metadata(case.join(&older_name)).expect("older").len();
            flip_byte(&case.join(&older_name), mid_body(older_len));
        });
    }
    {
        let (newest_name, older_name) = (newest_name.clone(), older_name.clone());
        run("both checkpoints truncated to 3 bytes".into(), &move |case| {
            truncate_file(&case.join(&newest_name), 3);
            truncate_file(&case.join(&older_name), 3);
        });
    }
    {
        run("both checkpoints deleted".into(), &move |case| {
            fs::remove_file(case.join(&newest_name)).expect("delete newest");
            fs::remove_file(case.join(&older_name)).expect("delete older");
        });
    }
    println!(
        "C: {judged} checkpoint-damage cases judged — all full recoveries (older base or \
         genesis replay); all-checkpoints-bad with genesis reachable recovers by full replay"
    );
}

/// What is done to the one retained checkpoint below: the two ways a base
/// can stop being loadable, damaged and absent.
#[derive(Clone, Copy)]
enum SoleDamage {
    FlipMidBody,
    Delete,
}

impl SoleDamage {
    /// The case directory's suffix.
    fn slug(self) -> &'static str {
        match self {
            SoleDamage::FlipMidBody => "flip",
            SoleDamage::Delete => "del",
        }
    }

    /// What a panic reports this case as.
    fn label(self) -> &'static str {
        match self {
            SoleDamage::FlipMidBody => "sole checkpoint flipped mid-body",
            SoleDamage::Delete => "sole checkpoint deleted",
        }
    }
}

/// Scenario C (iv), the loud half: reclamation has dropped the
/// genesis-reaching segments (blob commits force rotation; a checkpoint
/// with retain=1 reclaims the closed prefix), so when the SOLE retained
/// checkpoint is damaged the whole fallback chain is exhausted. The
/// contract's answer is `OpenError::BadCheckpoint` — a loud refusal, never
/// a partial world.
#[test]
fn c_checkpoint_chain_exhausted_with_genesis_unreachable_refuses_loudly() {
    let tmp = tempdir().expect("tempdir");
    let dir = tmp.path().join("fixture");
    let genesis = GenesisConfig::standard();
    const BLOB: usize = 300 * 1024;
    {
        let engine =
            Engine::open(cfg(&dir, CheckpointPolicy::Manual, 1), genesis.clone())
                .expect("blob fixture open");
        let prefix = {
            let snap = engine.kernel().snapshot();
            snap.world().m3().next_account_prefix(&node1()).expect("delegable prefix")
        };
        let (acct, _) = engine
            .namespace()
            .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), USER)
            .expect("delegate");
        let (doc, _) =
            engine.namespace().create_new_document(USER, &acct).expect("create document");
        // One fat Val is ONE position (a composite atom), so appends land at
        // ordinal i+1; each still journals ~300 KiB, forcing rotation.
        for i in 0..8u32 {
            engine
                .vstream()
                .insert(OWNER, &doc, vp(1, i + 1), vec![Val::new(vec![b'a' + i as u8; BLOB])])
                .expect("blob insert");
        }
        engine.kernel().checkpoint().expect("blob checkpoint");
    }
    assert!(
        !seg_file(&dir, 1).exists(),
        "fixture precondition: the checkpoint's reclamation must drop seg-1 (genesis unreachable)"
    );
    let checkpoints: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("fixture dir")
        .filter_map(|entry| {
            let entry = entry.expect("entry");
            let name = entry.file_name().into_string().ok()?;
            name.strip_prefix("checkpoint.")?.parse::<u64>().ok()?;
            Some(entry.path())
        })
        .collect();
    assert_eq!(checkpoints.len(), 1, "retain=1 keeps exactly one checkpoint");
    let cp_name = checkpoints[0].file_name().expect("name").to_owned();
    let cp_len = fs::metadata(&checkpoints[0]).expect("checkpoint").len();

    for damage in [SoleDamage::FlipMidBody, SoleDamage::Delete] {
        let case = tmp.path().join(format!("c2-{}", damage.slug()));
        copy_dir(&dir, &case);
        match damage {
            SoleDamage::FlipMidBody => flip_byte(&case.join(&cp_name), mid_body(cp_len)),
            SoleDamage::Delete => {
                fs::remove_file(case.join(&cp_name)).expect("delete sole checkpoint")
            }
        }
        let ctx = format!("C-exhausted: {}", damage.label());
        match timed_open_result(&case, &ctx) {
            Err(EngineError::Open(OpenError::BadCheckpoint)) => {}
            Err(other) => panic!(
                "FINDING ({ctx}): expected the loud BadCheckpoint refusal, got a different \
                 refusal: {other}"
            ),
            Ok(engine) => panic!(
                "FINDING ({ctx}): open SUCCEEDED at head {} where the fallback chain is \
                 exhausted — a partial world would be silent wrong state",
                engine.kernel().current_seq().0
            ),
        }
        fs::remove_dir_all(&case).expect("case cleanup");
    }
    println!("C-exhausted: both damage modes refused loudly with BadCheckpoint");
}

// ── D. Kill mid-checkpoint ───────────────────────────────────────────────

/// The child half of scenario D: re-exec'd by
/// `d_kill_mid_checkpoint_loses_no_acked_commit` with
/// `SKEP_HAZARD_D_DIR`/`SKEP_HAZARD_D_DOC` set, it recovers the store and
/// commits 48 KiB inserts forever — checkpointing every second commit
/// (retain generous, so no reclamation and every boundary stays
/// answerable) — printing `HAZACK <seq>` after each ack until SIGKILLed.
/// In a normal test run (no env) it is an instant pass.
#[test]
fn hazard_d_child_process_entry() {
    let Some(dir) = std::env::var_os("SKEP_HAZARD_D_DIR") else { return };
    let dir = PathBuf::from(dir);
    let doc = parse_addr(&std::env::var("SKEP_HAZARD_D_DOC").expect("child doc env"));
    let engine = Engine::open(
        cfg(&dir, CheckpointPolicy::EveryN(2), 999),
        GenesisConfig::standard(),
    )
    .expect("hazard child: engine open");
    const BLOB: usize = 48 * 1024;
    let stdout = std::io::stdout();
    for i in 0u64.. {
        // One fat Val occupies ONE position: append at ordinal i+1.
        let ord = (i + 1) as u32;
        engine
            .vstream()
            .insert(OWNER, &doc, vp(1, ord), vec![Val::new(vec![b'a' + (i % 26) as u8; BLOB])])
            .expect("hazard child: insert");
        let seq = engine.kernel().current_seq().0;
        let mut out = stdout.lock();
        writeln!(out, "HAZACK {seq}").expect("hazard child: ack line");
        out.flush().expect("hazard child: ack flush");
    }
}

/// Scenario D: drive commits with an every-2-commits checkpoint cadence in
/// a CHILD process (this test binary re-exec'd) and SIGKILL it at a seeded
/// random delay, dozens of trials. The judgment after each kill: reopen
/// succeeds (no wedge, no refusal — a half-written checkpoint is at most an
/// ignored `.tmp`), no acked commit vanishes, every acked boundary answers
/// `world_at`, the recovered fold dumps byte-equal to a checkpoint+replay
/// of the same head, hints match a from-scratch rebuild, and recovery is
/// idempotent (a second reopen dumps byte-equal).
#[test]
fn d_kill_mid_checkpoint_loses_no_acked_commit() {
    let trials: u64 = if exhaustive() { 40 } else { 10 };
    let mut total_acks = 0usize;
    let mut unacked_replays = 0u64;
    for trial in 0..trials {
        let (acks, unacked) = d_trial(trial);
        total_acks += acks;
        unacked_replays += unacked;
    }
    println!(
        "D: {trials} SIGKILL trials (seeds 0xD00D+trial), {total_acks} acked commits verified, \
         {unacked_replays} committed-but-unacked records replayed (the lost-ack case, by design)"
    );
}

fn d_trial(trial: u64) -> (usize, u64) {
    let tmp = tempdir().expect("tempdir");
    let dir = tmp.path().join("store");
    let genesis = GenesisConfig::standard();
    // Prologue in THIS process: delegate an account, create the document
    // the child will write into; then release the journal lock.
    let doc_str = {
        let engine = Engine::open(cfg_manual(&dir), genesis.clone()).expect("D prologue open");
        let prefix = {
            let snap = engine.kernel().snapshot();
            snap.world().m3().next_account_prefix(&node1()).expect("delegable prefix")
        };
        let (acct, _) = engine
            .namespace()
            .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), USER)
            .expect("delegate");
        let (doc, _) =
            engine.namespace().create_new_document(USER, &acct).expect("create document");
        tum_str(doc.tumbler())
    };

    let exe = std::env::current_exe().expect("test binary path");
    let mut child = Command::new(exe)
        .args(["hazard_d_child_process_entry", "--exact", "--nocapture", "--test-threads=1"])
        .env("SKEP_HAZARD_D_DIR", &dir)
        .env("SKEP_HAZARD_D_DOC", &doc_str)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn hazard D child");
    let stdout = child.stdout.take().expect("child stdout");
    let (tx, rx) = mpsc::channel::<u64>();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if let Some(rest) = line.strip_prefix("HAZACK ") {
                if let Ok(seq) = rest.trim().parse::<u64>() {
                    if tx.send(seq).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut acks = vec![rx
        .recv_timeout(Duration::from_secs(30))
        .expect("hazard D child produced no ack within 30s (startup wedge or crash)")];
    let mut rng = SplitMix64::new(0xD00D + trial);
    let delay = Duration::from_millis(20 + rng.next_range(330));
    let deadline = Instant::now() + delay;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok(seq) => acks.push(seq),
            Err(_) => break, // timeout, or the child died on its own
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    // Acks already in the pipe when the kill landed still count.
    while let Ok(seq) = rx.recv_timeout(Duration::from_millis(500)) {
        acks.push(seq);
    }
    reader.join().expect("ack reader thread");

    let ctx = format!(
        "D trial {trial}: SIGKILL after {delay:?} (seed 0xD00D+{trial}), {} acks",
        acks.len()
    );
    let engine = timed_open(&dir, &ctx);
    let head = engine.kernel().current_seq().0;
    let max_ack = *acks.iter().max().expect("at least one ack");
    assert!(
        head >= max_ack,
        "FINDING ({ctx}): acked commit vanished — recovered head {head} < acked {max_ack}"
    );
    for &at in &acks {
        engine.world_at(Seq(at)).unwrap_or_else(|e| {
            panic!("FINDING ({ctx}): acked boundary {at} unanswerable after the kill: {e}")
        });
    }
    let live = engine.world_dump();
    let refold = dump(&engine.world_at(Seq(head)).expect("head answers"), &genesis);
    assert_eq!(live, refold, "FINDING ({ctx}): fold ≢ checkpoint+replay after the kill");
    engine
        .check_hints()
        .unwrap_or_else(|e| panic!("FINDING ({ctx}): hint divergence after the kill: {e}"));
    drop(engine);
    let again = timed_open(&dir, &ctx).world_dump();
    assert_eq!(live, again, "FINDING ({ctx}): recovery is not idempotent");
    (acks.len(), head - max_ack)
}

// ── E. Seeded random mutation ────────────────────────────────────────────

/// Scenario E: the shapes A–D do not reach — a few seeded-random bytes flipped
/// ANYWHERE in the journal, rather than at a cut point, a tail, or a
/// hand-picked frame offset. Two grids, because two different judgments are
/// available:
///
/// * flips confined to the FINAL transaction leave every earlier boundary
///   intact, so the boundary rule applies unchanged and the judgment is
///   scenario A's — recover to EXACTLY the boundary the intact prefix
///   supports, byte-equal to the oracle there — plus the reopen, since a
///   recovery that truncated a tail must answer the same on its second look;
/// * flips anywhere can tear an interior transaction, which is durable
///   committed data and licenses the halt, so the judgment is the one that
///   holds either way: it answers at all (no panic, no wedge), and a refusal
///   REPEATS, since the halt paths write nothing and a refusal that repairs
///   itself is one no operator can act on.
///
/// This is the in-gate stand-in for a coverage-guided fuzzer over the frame
/// parser and the scan. The crafted shapes such a fuzzer would want seeding
/// with — a transaction repeating a `Seq`, a marker at the `Seq` ceiling —
/// are pinned as unit tests inside `skep-kernel`, where the frame builder is
/// reachable and the input can be stated exactly.
#[test]
fn e_seeded_random_mutation_lands_on_the_boundary_or_refuses_repeatably() {
    let tmp = tempdir().expect("tempdir");
    let fixture = Fixture::build(&tmp.path().join("fixture"), &[]);
    let trials: u64 = if exhaustive() { 400 } else { 40 };
    let cases = tmp.path().join("cases");
    let last_txn_lo = fixture.boundaries[fixture.boundaries.len() - 2].journal_len;
    let (mut recovered, mut refused) = (0u32, 0u32);
    for trial in 0..trials {
        let seed = 0x00F1_1900 + trial;
        let mut rng = SplitMix64::new(seed);
        let case = cases.join(format!("e-{trial}"));
        copy_dir(&fixture.dir, &case);
        let final_txn_only = trial % 2 == 0;
        let lo = if final_txn_only { last_txn_lo } else { 0 };
        let mut offsets: Vec<u64> = (0..1 + rng.next_range(4))
            .map(|_| lo + rng.next_range(fixture.full_len - lo))
            .collect();
        offsets.sort_unstable();
        offsets.dedup();
        for &offset in &offsets {
            flip_byte(&seg_file(&case, 1), offset);
        }
        let first_flip = offsets[0];
        let ctx = format!(
            "E trial {trial}: seed {seed:#x}, flipped {offsets:?} of {} ({})",
            fixture.full_len,
            if final_txn_only { "final txn" } else { "anywhere" }
        );
        if final_txn_only {
            // Nothing below the first flip changed, so the boundary rule
            // binds exactly as it does under a clean truncation there.
            recovered += 1;
            let depth = if trial % 8 == 0 { Depth::Full } else { Depth::Head };
            let head = judge_prefix(&fixture, &case, first_flip, depth, &ctx);
            let again = timed_open(&case, &ctx).world_dump();
            assert_eq!(
                again,
                *fixture.dump_for(head),
                "FINDING ({ctx}): recovery is not idempotent"
            );
        } else {
            match timed_open_result(&case, &ctx) {
                Ok(engine) => {
                    recovered += 1;
                    let head = engine.kernel().current_seq();
                    assert!(
                        head.0 <= fixture.last_seq(),
                        "FINDING ({ctx}): recovered head {head} above the fixture's own {}",
                        fixture.last_seq()
                    );
                    let live = engine.world_dump();
                    let at_head = engine.world_at(head).unwrap_or_else(|e| {
                        panic!("FINDING ({ctx}): recovered head {head} unanswerable: {e}")
                    });
                    assert_eq!(
                        live,
                        dump(&at_head, &fixture.genesis),
                        "FINDING ({ctx}): fold ≢ checkpoint+replay"
                    );
                    engine
                        .check_hints()
                        .unwrap_or_else(|e| panic!("FINDING ({ctx}): hint divergence: {e}"));
                    drop(engine);
                    let again = timed_open(&case, &ctx).world_dump();
                    assert_eq!(live, again, "FINDING ({ctx}): recovery is not idempotent");
                }
                Err(e) => {
                    refused += 1;
                    let ctx = format!("{ctx} — first open refused with {e}");
                    if let Ok(engine) = timed_open_result(&case, &ctx) {
                        panic!(
                            "FINDING ({ctx}): the second open SUCCEEDED at head {} — a halt \
                             writes nothing, so a refusal that repairs itself is one nobody \
                             can act on",
                            engine.kernel().current_seq()
                        );
                    }
                }
            }
        }
        fs::remove_dir_all(&case).expect("case cleanup");
    }
    println!(
        "E: {trials} seeded mutation trials (seeds 0xF11900+trial, exhaustive={}): \
         {recovered} recovered, {refused} refused loudly",
        exhaustive()
    );
}
