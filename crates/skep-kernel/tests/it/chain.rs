//! THE CHAIN'S TAMPER MATRIX (QUEUE item 10, piece (b); the owner's ruling
//! of 2026-09-04: "Every entry carries the hash of the previous entry over
//! CANONICAL bytes … Any rewrite breaks the chain from that point forward on
//! the next replay"). The attacker is a FILE-LEVEL WRITER of the data
//! directory — a breached host, a dishonest process — who can rewrite any
//! byte and re-fix any CRC: the frame CRCs and the marker's
//! `records_checksum` are CRC32C over bytes the attacker holds, so every
//! case below leaves them consistent and asks what the chain alone can see.
//!
//! Every case is built from the golden fixture's ops in a temporary
//! directory — byte-equal to `tests/golden/seg-1.wal`, so the matrix is
//! over the golden's bytes — copied per case, damaged as files on a closed
//! journal, opened through the PUBLIC engine surface, and held to one of
//! three outcomes:
//!
//! * CAUGHT — `OpenError::Corruption` naming a CHAIN BREAK at the `last_seq`
//!   of the first committed transaction whose marker's chain is not the
//!   recomputation over its predecessor's — or, since the chain's open
//!   items (2026-09-23), the BASE'S OWN LINK at the base's seq (a checkpoint
//!   header disagreeing with the marker closing it, seen at the head always)
//!   or the EDITED TRANSACTION at its own seq (an intact transaction its
//!   intact marker does not close, a shape no writer leaves) — the cause
//!   travelling, every file byte for byte as found (a halt cuts nothing),
//!   and the refusal repeating; since `SKJ4` the marker's SALT is a chain
//!   input too, and a salt edited is a link that fails (case 16);
//! * REFUSED — the checkpoint's own refusal (`body_hash`), the fallback
//!   chain then reaching genesis, which re-verifies the journal;
//! * NOT CAUGHT BY DESIGN — a history the chain alone accepts, which the
//!   ruling assigns to piece 2, the PUBLISHED HEAD, whose saved pairs are
//!   checked against the board's RECOMPUTATION through `Kernel::chain_at`:
//!   a clean tail cut; a consistent re-chain, from genesis or from any
//!   point, the checkpoint's head rewritten with it — the forger choosing
//!   its own salts, the salt being no anchor; a checkpoint body
//!   forged with its hash re-fixed; the base's own link edited consistently
//!   on both sides and re-chained above (case 14), or its marker's segment
//!   skipped — the boundary coincidence, case 15; and — the owner's reading
//!   of "any rewrite", case 12 — damage below a standing base, unseen at
//!   open and seen by any bounded read below the base. Each is asserted as
//!   such, and named in `Kernel::open`'s damage model.
//!
//! Two bases are exercised. With the golden's checkpoint REMOVED the open's
//! base is genesis and every one of the eighteen links is verified, which is
//! where the mid-history cases live; with it STANDING (`checkpoint.37`) the
//! open verifies the base's own link — the marker closing 37 is in the one
//! segment — and the two transactions above it, and a `world_at` below it
//! verifies from genesis — which is what cases 9, 12 and 14 turn on.
//!
//! A case the code does not meet at the outcome the ruling requires is a
//! STOP by name, never an assertion loosened to what the code does. None
//! arose. Case 2 once named one transaction LATER — the marker's own
//! validation speaking before the chain — and since the open items it names
//! the edited transaction itself; the test says why.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::hazard_util::{
    cfg_manual, ckpt_file, copy_dir, flip_byte, node1, seg_file, t, timed_open,
    timed_open_result, truncate_file, vp, Fixture, GOLDEN_OPS, GOLDEN_SALT_SEED, OWNER, USER,
};
use crate::mutilate::{
    delete_txn, records_checksum, replace_frame_payload, reseal_frame, rewrite_frame,
    rewrite_txn, rollback_segment, swap_txns, transactions, Txn, MARKER_CHAIN_AT,
    MARKER_CHECKSUM_AT, MARKER_EMPTY_LEN, MARKER_LAST_SEQ_AT, MARKER_SALT_AT,
    MARKER_SIG_ALG_AT, MARKER_SIG_LEN_AT, RECORD_BYTES_AT,
};
use sha2::{Digest, Sha256};
use skep_arrangement::Deposit;
use skep_content::Val;
use skep_engine::dump::WorldDump;
use skep_engine::{Engine, EngineError, OpenError};
use skep_kernel::{CheckpointPolicy, Durability, HistoryError, KernelConfig, SaltSource, Seq};
use skep_namespace::{HasM3, BOOTSTRAP_PRINCIPAL};
use tempfile::{tempdir, TempDir};

/// The op after which the golden checkpoints — the golden suite's own
/// constant, restated: `checkpoint.37`, with ops 17 and 18 above it.
const CHECKPOINT_AFTER_OP: usize = 16;

/// The chain's seed, restated: the value a journal's first transaction chains
/// from, which the golden's first marker pins. The forger of case 11 starts
/// from it.
const CHAIN_GENESIS: [u8; 32] = [0u8; 32];

/// The checkpoint header (`SKC4`), restated for the byte-level edits of
/// cases 8, 9 and 11: `[magic 4][seq u64][crc32c(body) u32][body_len u64]
/// [chain_head 32][body_hash 32][body]`.
const CHECKPOINT_CRC_AT: usize = 12;
const CHECKPOINT_BODY_LEN_AT: usize = 16;
const CHECKPOINT_CHAIN_HEAD_AT: usize = 24;
const CHECKPOINT_BODY_HASH_AT: usize = 56;
const CHECKPOINT_HEADER_LEN: usize = 88;

/// The committed golden segment, under version control beside the crate.
fn golden_segment() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("seg-1.wal")
}

/// The matrix's fixture: the golden's ops in a temporary directory, its
/// segment byte-equal to the committed golden's, its eighteen transactions
/// mapped as the frames lay them down.
struct Golden {
    tmp: TempDir,
    fixture: Fixture,
    /// Op `i` (1-based) is `txns[i - 1]`.
    txns: Vec<Txn>,
}

impl Golden {
    fn build() -> Golden {
        let tmp = tempdir().expect("tempdir");
        let fixture =
            Fixture::build_golden(&tmp.path().join("fixture"), &[CHECKPOINT_AFTER_OP]);
        let data = fs::read(seg_file(&fixture.dir, 1)).expect("the fixture's segment");
        assert_eq!(
            data,
            fs::read(golden_segment()).expect("the committed golden segment"),
            "the matrix is over the golden's bytes, and the ops no longer reproduce them (the \
             writer pin says where)"
        );
        let txns = transactions(&data);
        assert_eq!(txns.len(), GOLDEN_OPS, "one marker per op");
        for (txn, boundary) in txns.iter().zip(&fixture.boundaries) {
            assert_eq!(txn.last_seq, boundary.seq, "a marker closes at its op's boundary");
            assert_eq!(
                txn.bytes.end as u64,
                boundary.journal_len,
                "a transaction ends where its commit left the file"
            );
            assert_eq!(
                txn.records_checksum,
                records_checksum(&data, txn),
                "the layout restated here reads the checksum the writer wrote"
            );
            // The golden was regenerated under the SEEDED source: every
            // marker's salt is the stream's value for its transaction, which
            // is what makes the bytes reproducible — and what a golden
            // written under OS entropy could never be.
            assert_eq!(
                txn.salt,
                seeded_salt(GOLDEN_SALT_SEED, txn.txn),
                "the marker at {} carries the seeded source's salt",
                txn.last_seq
            );
        }
        Golden { tmp, fixture, txns }
    }

    /// The transaction op `op` (1-based) committed.
    fn txn(&self, op: usize) -> &Txn {
        &self.txns[op - 1]
    }

    /// The boundary op `op` committed at — the coordinate a chain break at
    /// that transaction is named with.
    fn seq(&self, op: usize) -> u64 {
        self.txn(op).last_seq
    }

    fn head(&self) -> u64 {
        self.fixture.last_seq()
    }

    fn checkpoint_seq(&self) -> u64 {
        self.seq(CHECKPOINT_AFTER_OP)
    }

    fn dump(&self, seq: u64) -> &WorldDump {
        self.fixture.dump_for(seq)
    }

    /// A case directory: the fixture's files copied, the golden checkpoint
    /// STANDING — the open's base is `checkpoint.37`.
    fn case(&self, name: &str) -> PathBuf {
        let dir = self.tmp.path().join(name);
        copy_dir(&self.fixture.dir, &dir);
        dir
    }

    /// A case directory with the checkpoint REMOVED: the open's base is
    /// genesis, and every link of the eighteen is verified.
    fn case_from_genesis(&self, name: &str) -> PathBuf {
        let dir = self.case(name);
        fs::remove_file(ckpt_file(&dir, self.checkpoint_seq())).expect("remove the checkpoint");
        dir
    }
}

/// Every regular file of `dir` by name — what a halted open must leave byte
/// for byte.
fn files_of(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(dir)
        .expect("case dir lists")
        .map(|entry| entry.expect("dir entry"))
        .filter(|entry| entry.file_type().expect("file type").is_file())
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path()).expect("read a case file"),
            )
        })
        .collect()
}

fn segment_count(dir: &Path) -> usize {
    fs::read_dir(dir)
        .expect("dir")
        .filter_map(|e| e.expect("entry").file_name().into_string().ok())
        .filter(|n| n.starts_with("seg-") && n.ends_with(".wal"))
        .count()
}

/// The three accounts a halt travels with, by the phrase each opens on — the
/// scan's three verdicts: a chain break (a link that failed its
/// recomputation), a base mismatch (a header disagreeing with the marker
/// closing its seq), and the edited transaction (an intact transaction its
/// intact marker does not close). A case names the one it expects, so a halt
/// at the right coordinate for the wrong reason is a finding.
const CHAIN_BREAK: &str = "chain break: the commit marker";
const BASE_MISMATCH: &str = "chain break at the base";
const EDITED_TXN: &str = "chain break at an edited transaction";

/// CAUGHT: the open halts with a chain break at `at` — the cause travels and
/// names the break, nothing is cut or written, and the refusal repeats.
fn open_halts_with_chain_break(dir: &Path, at: u64, ctx: &str) {
    open_halts_naming(dir, at, CHAIN_BREAK, ctx);
}

/// CAUGHT, by the verdict `phrase` names: the open halts with `Corruption`
/// at `at`, the account opening on `phrase` and travelling as a source,
/// nothing cut or written, and the refusal repeating.
fn open_halts_naming(dir: &Path, at: u64, phrase: &str, ctx: &str) {
    let before = files_of(dir);
    let err = match timed_open_result(dir, ctx) {
        Ok(_) => panic!("FINDING ({ctx}): the open SUCCEEDED over a rewrite the chain must catch"),
        Err(err) => err,
    };
    match &err {
        EngineError::Open(OpenError::Corruption { at: found, cause }) => {
            assert_eq!(
                *found,
                Seq(at),
                "FINDING ({ctx}): the break is named at the wrong coordinate: {err}"
            );
            assert!(cause.is_some(), "FINDING ({ctx}): a chain break travels with its account: {err}");
        }
        other => panic!("FINDING ({ctx}): expected a Corruption halt naming {at}, got {other:?}"),
    }
    assert!(
        err.to_string().contains(phrase),
        "FINDING ({ctx}): the account names the verdict ({phrase:?}): {err}"
    );
    assert!(
        std::error::Error::source(&err).is_some(),
        "FINDING ({ctx}): the cause travels as a source"
    );
    assert_eq!(files_of(dir), before, "FINDING ({ctx}): a halted open wrote to the directory");
    assert!(
        matches!(
            timed_open_result(dir, ctx),
            Err(EngineError::Open(OpenError::Corruption { at: found, .. })) if found == Seq(at)
        ),
        "FINDING ({ctx}): the refusal did not repeat"
    );
}

/// RECOVERED: the open succeeds at `head` with the world the golden recorded
/// there.
fn open_recovers(dir: &Path, golden: &Golden, head: u64, ctx: &str) -> Engine {
    let engine = timed_open(dir, ctx);
    assert_eq!(engine.kernel().current_seq(), Seq(head), "FINDING ({ctx}): the recovered head");
    assert_eq!(
        &engine.world_dump(),
        golden.dump(head),
        "FINDING ({ctx}): SILENT DIVERGENCE at {head}"
    );
    engine
}

/// …and every boundary at or below the head answers the dump the golden
/// recorded, with the hints matching a from-scratch rebuild.
fn every_boundary_answers(engine: &Engine, golden: &Golden, ctx: &str) {
    let head = engine.kernel().current_seq().0;
    assert_eq!(
        engine.dump_of(&engine.world_at(Seq(0)).expect("genesis answers")),
        golden.fixture.genesis_dump,
        "FINDING ({ctx}): genesis diverged"
    );
    for boundary in golden.fixture.boundaries.iter().filter(|b| b.seq <= head) {
        let world = engine.world_at(Seq(boundary.seq)).unwrap_or_else(|e| {
            panic!("FINDING ({ctx}): boundary {} unanswerable: {e}", boundary.seq)
        });
        assert_eq!(
            engine.dump_of(&world),
            boundary.dump,
            "FINDING ({ctx}): history at {} diverges",
            boundary.seq
        );
    }
    engine
        .check_hints()
        .unwrap_or_else(|e| panic!("FINDING ({ctx}): hint divergence: {e}"));
}

/// A bounded read at `at` halts with a chain break at `break_at`.
fn history_halts_with_chain_break(engine: &Engine, at: u64, break_at: u64, ctx: &str) {
    history_halts_naming(engine, at, break_at, CHAIN_BREAK, ctx);
}

/// A bounded read at `at` — the world AND the chain, which run the same
/// verification — halts with `Corruption` at `break_at`, the account
/// opening on `phrase`.
fn history_halts_naming(engine: &Engine, at: u64, break_at: u64, phrase: &str, ctx: &str) {
    let world = engine.world_at(Seq(at)).map(|_| ());
    let chain = engine.kernel().chain_at(Seq(at)).map(|_| ());
    for (what, outcome) in [("world_at", world), ("chain_at", chain)] {
        match outcome {
            Err(HistoryError::Corruption { at: found, cause }) => {
                assert_eq!(
                    found,
                    Seq(break_at),
                    "FINDING ({ctx}): {what}({at}) names the wrong coordinate"
                );
                let cause = cause.unwrap_or_else(|| {
                    panic!("FINDING ({ctx}): a chain break travels with its account")
                });
                assert!(cause.to_string().contains(phrase), "FINDING ({ctx}): {what}: {cause}");
            }
            Err(other) => {
                panic!("FINDING ({ctx}): {what}({at}) refused for another reason: {other}")
            }
            Ok(()) => {
                panic!("FINDING ({ctx}): {what}({at}) ANSWERED over a rewrite the chain must catch")
            }
        }
    }
}

/// `Kernel::chain_at(at)` answers `expected`.
fn chain_at_is(engine: &Engine, at: u64, expected: &[u8; 32], ctx: &str) {
    let found = engine
        .kernel()
        .chain_at(Seq(at))
        .unwrap_or_else(|e| panic!("FINDING ({ctx}): chain_at({at}) refused: {e}"));
    assert_eq!(&found, expected, "FINDING ({ctx}): chain_at({at}) is not the chain at {at}");
}

/// One link of the chain, recomputed exactly as the writer states it —
/// SHA-256 over the predecessor's value, the record payloads as framed, then
/// `txn`, `last_seq` and `records_checksum` in their wire form, then the
/// marker's SALT as the segment holds it NOW (read off `data`, not off the
/// `Txn` mapped before any edit, so a forger who re-salts a marker chains
/// over the salt it wrote). Restated here so the forger of case 11 is held
/// to the writer's own formula: were the two to drift, the forgery would be
/// CAUGHT and that case would fail loudly rather than pass. The sanity check
/// at its head pins them equal over the untouched golden.
fn chain_over(prev: &[u8; 32], data: &[u8], txn: &Txn) -> [u8; 32] {
    let mut link = Sha256::new().chain_update(prev);
    for record in &txn.records {
        link.update(&data[record.payload.clone()]);
    }
    let salt_at = txn.marker.payload.start + MARKER_SALT_AT;
    link.chain_update(txn.txn.to_le_bytes())
        .chain_update(txn.last_seq.to_le_bytes())
        .chain_update(records_checksum(data, txn).to_le_bytes())
        .chain_update(&data[salt_at..salt_at + 32])
        .finalize()
        .into()
}

/// The seeded salt source's formula, restated: `SHA-256(seed LE64 ‖ txn
/// LE64)` — what every golden marker's salt must be, and what a golden
/// regenerated under any other source or seed fails by name.
fn seeded_salt(seed: u64, txn: u64) -> [u8; 32] {
    Sha256::new()
        .chain_update(seed.to_le_bytes())
        .chain_update(txn.to_le_bytes())
        .finalize()
        .into()
}

/// A salt of the FORGER's choosing for the marker closing `last_seq` —
/// nothing to do with the writer's stream, which the forger need not know:
/// the salt is no anchor, and a consistent re-chain chains over whatever the
/// marker holds.
fn forger_salt(last_seq: u64) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"a salt of the forger's own choosing")
        .chain_update(last_seq.to_le_bytes())
        .finalize()
        .into()
}

/// Write `salt` into `txn`'s marker in place. The frame's CRC is the
/// caller's to re-seal.
fn set_marker_salt(data: &mut [u8], txn: &Txn, salt: &[u8; 32]) {
    let at = txn.marker.payload.start + MARKER_SALT_AT;
    data[at..at + 32].copy_from_slice(salt);
}

/// Flip a byte of one of a transaction's RECORD payloads, inside the
/// record's own bytes.
fn flip_record_byte(data: &mut [u8], txn: &Txn, record_index: usize, offset: usize) {
    let at = txn.records[record_index].payload.start + RECORD_BYTES_AT + offset;
    assert!(at < txn.records[record_index].payload.end, "the byte lies inside the record");
    data[at] ^= 0xFF;
}

/// Rewrite the checkpoint's body through `edit` and re-fix the header's CRC
/// over it — `body_hash` left as it was.
fn rewrite_checkpoint_body(path: &Path, edit: impl FnOnce(&mut [u8])) {
    let mut data = fs::read(path).expect("read the checkpoint");
    edit(&mut data[CHECKPOINT_HEADER_LEN..]);
    let crc = crc32c::crc32c(&data[CHECKPOINT_HEADER_LEN..]);
    data[CHECKPOINT_CRC_AT..CHECKPOINT_BODY_LEN_AT].copy_from_slice(&crc.to_le_bytes());
    fs::write(path, data).expect("write the checkpoint");
}

/// Write `head` into the checkpoint's `chain_head` — nothing else in the
/// header covers it, so nothing else moves.
fn set_checkpoint_chain_head(path: &Path, head: &[u8; 32]) {
    let mut data = fs::read(path).expect("read the checkpoint");
    data[CHECKPOINT_CHAIN_HEAD_AT..CHECKPOINT_BODY_HASH_AT].copy_from_slice(head);
    fs::write(path, data).expect("write the checkpoint");
}

fn checkpoint_chain_head(path: &Path) -> [u8; 32] {
    fs::read(path).expect("read the checkpoint")[CHECKPOINT_CHAIN_HEAD_AT..CHECKPOINT_BODY_HASH_AT]
        .try_into()
        .expect("thirty-two bytes")
}

/// What a forger does about the golden's checkpoint after re-chaining the
/// journal below it.
#[derive(Clone, Copy)]
enum CheckpointAfterForgery {
    /// Left as the golden wrote it: its `chain_head` then contradicts the
    /// re-chained journal, which is case 9's door.
    Kept,
    /// Its `chain_head` rewritten with the re-chained link at its
    /// coordinate; its BODY left standing.
    HeadRewritten,
    /// Removed, so the open replays the forged journal from genesis.
    Removed,
}

/// Forge op `op`: replace `needle` — found ONCE across the op's record
/// payloads — with `replacement` of the same length, give every marker from
/// that transaction on a salt of the forger's own choosing, re-chain every
/// link from there to the end over those salts, and deal with the golden's
/// checkpoint as `checkpoint` says. Answers the re-chained links by boundary.
fn forge_and_rechain(
    golden: &Golden,
    case: &Path,
    op: usize,
    needle: &[u8],
    replacement: &[u8],
    checkpoint: CheckpointAfterForgery,
) -> Vec<(u64, [u8; 32])> {
    assert_eq!(needle.len(), replacement.len(), "a rewrite in place");
    let seg = seg_file(case, 1);
    rewrite_txn(&seg, op - 1, |data, txn| {
        let hits: Vec<usize> = txn
            .records
            .iter()
            .flat_map(|record| {
                let payload = &data[record.payload.clone()];
                payload
                    .windows(needle.len())
                    .enumerate()
                    .filter(|(_, window)| *window == needle)
                    .map(|(i, _)| record.payload.start + i)
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(hits.len(), 1, "the needle is found once in op {op}'s records: {hits:?}");
        data[hits[0]..hits[0] + needle.len()].copy_from_slice(replacement);
    });
    // Re-chain from the forged transaction, seeded with its predecessor's
    // value as the golden wrote it — the seed itself for the first — each
    // marker re-salted with the forger's own value first, so the links are
    // over salts the writer never drew.
    let mut prev = if op == 1 { CHAIN_GENESIS } else { golden.txn(op - 1).chain };
    let mut data = fs::read(&seg).expect("segment");
    let txns = transactions(&data);
    let mut chains = Vec::new();
    for txn in &txns[op - 1..] {
        set_marker_salt(&mut data, txn, &forger_salt(txn.last_seq));
        let chain = chain_over(&prev, &data, txn);
        let at = txn.marker.payload.start + MARKER_CHAIN_AT;
        data[at..at + 32].copy_from_slice(&chain);
        reseal_frame(&mut data, &txn.marker);
        chains.push((txn.last_seq, chain));
        prev = chain;
    }
    fs::write(&seg, data).expect("write the re-chained segment");
    let ckpt = ckpt_file(case, golden.checkpoint_seq());
    match checkpoint {
        CheckpointAfterForgery::Kept => {}
        CheckpointAfterForgery::HeadRewritten => {
            let (_, head) = chains
                .iter()
                .find(|(seq, _)| *seq == golden.checkpoint_seq())
                .expect("the forgery sits at or below the checkpoint");
            set_checkpoint_chain_head(&ckpt, head);
        }
        CheckpointAfterForgery::Removed => fs::remove_file(&ckpt).expect("remove the checkpoint"),
    }
    chains
}

/// CASE 1 — A RECORD PAYLOAD REWRITTEN MID-HISTORY, EVERY CRC RE-FIXED — the
/// frame's and the marker's `records_checksum` both, so the frame passes and
/// the transaction still commits as rewritten: CAUGHT at that transaction,
/// whose chain no longer follows from its predecessor over its own bytes.
///
/// The weaker rewrite that re-fixes the frame CRC alone leaves the marker's
/// `records_checksum` stale, and the marker's own validation — older than
/// the chain — refuses to close the group: the transaction UN-COMMITS. It is
/// then an intact transaction its intact marker does not close, a shape no
/// writer leaves, and the open names THAT transaction (the chain's open
/// items, case 2's verdict) rather than the next committed one, whose link
/// also fails. Caught either way; the account differs.
#[test]
fn c01_a_record_payload_rewritten_with_every_crc_refixed_breaks_at_that_transaction() {
    let golden = Golden::build();
    // The nullify: two records, mid-history, below the golden's checkpoint.
    const OP: usize = 9;

    let case = golden.case_from_genesis("c01-consistent");
    rewrite_txn(&seg_file(&case, 1), OP - 1, |data, txn| flip_record_byte(data, txn, 0, 40));
    open_halts_with_chain_break(
        &case,
        golden.seq(OP),
        "case 1: a record byte rewritten, its frame CRC and the marker's records_checksum re-fixed",
    );

    let case = golden.case_from_genesis("c01-frame-crc-only");
    rewrite_frame(&seg_file(&case, 1), golden.txn(OP).records[0].start, |payload| {
        payload[RECORD_BYTES_AT + 40] ^= 0xFF
    });
    open_halts_naming(
        &case,
        golden.seq(OP),
        EDITED_TXN,
        "case 1, the weaker rewrite: the frame CRC re-fixed, records_checksum stale — the \
         transaction un-commits, and is named as the intact transaction its marker does not close",
    );
}

/// CASE 2 — A MARKER'S `records_checksum` OR `last_seq` EDITED, CRC RE-FIXED. Both
/// are chain inputs — but they are the marker's OWN validation first, older
/// than the chain: a marker whose checksum or `last_seq` does not close its
/// group commits nothing, so the edited transaction UN-COMMITS before the
/// chain sees it. What is left is an INTACT transaction — every record
/// frame and the marker passing their CRCs — that its marker does not
/// close, and no writer of this format leaves that shape: the writer
/// streams the checksum over the frames it writes and sets `last_seq` to
/// the last record's, a crash truncates or loses frames. So the scan
/// records the edited transaction by the GROUP's own last seq (in the
/// `last_seq` arm the marker's is the forged field) and the open is CAUGHT
/// AT THAT TRANSACTION with the edited-transaction account — before the
/// next committed transaction's link, which fails too, gets to name the
/// coordinate one later, as it did before the chain's open items.
///
/// On the LAST transaction the same edit was once a tail cut in disguise —
/// the un-committed marker read as the torn tail, recovery cut it and
/// opened one transaction short. Now it halts the same way, nothing cut:
/// the halt precedes the tail truncation, and the segment keeps its
/// length.
#[test]
fn c02_a_markers_checksum_or_last_seq_edited_is_caught_at_that_transaction_uncut() {
    let golden = Golden::build();
    const OP: usize = 9;
    for (field, at) in [("records_checksum", MARKER_CHECKSUM_AT), ("last_seq", MARKER_LAST_SEQ_AT)] {
        let case = golden.case_from_genesis(&format!("c02-{field}"));
        rewrite_frame(&seg_file(&case, 1), golden.txn(OP).marker.start, |payload| {
            payload[at] ^= 0xFF
        });
        open_halts_naming(
            &case,
            golden.seq(OP),
            EDITED_TXN,
            &format!(
                "case 2: the marker's {field} edited, its CRC re-fixed — the marker no longer \
                 closes its intact group, and the transaction is named as the edited one"
            ),
        );
    }

    let case = golden.case("c02-last");
    let seg = seg_file(&case, 1);
    rewrite_frame(&seg, golden.txn(GOLDEN_OPS).marker.start, |payload| {
        payload[MARKER_CHECKSUM_AT] ^= 0xFF
    });
    open_halts_naming(
        &case,
        golden.seq(GOLDEN_OPS),
        EDITED_TXN,
        "case 2 on the last transaction: once a tail cut in disguise, now the edited transaction",
    );
    assert_eq!(
        fs::metadata(&seg).expect("segment").len(),
        golden.fixture.full_len,
        "the halt precedes the tail truncation: the un-committed last transaction was not cut"
    );
}

/// CASE 3 — A MARKER'S `chain` FIELD EDITED, CRC RE-FIXED: CAUGHT at that
/// transaction — the stored chain is not the recomputation — and the NEXT
/// does not mask it: the next transaction's own link fails too (it chains
/// from the value the marker carried before the edit, while the scan
/// continues from the marker's claim), and the first break is the one
/// recorded. Mid-history from genesis, above a standing base, and on the
/// last transaction — where, unlike its checksum (case 2), the chain field
/// leaves the marker a committed one, so its link IS recomputed and fails.
#[test]
fn c03_a_markers_chain_field_edited_breaks_at_that_transaction_and_the_next_does_not_mask_it() {
    let golden = Golden::build();
    const OP: usize = 9;

    let case = golden.case_from_genesis("c03");
    rewrite_frame(&seg_file(&case, 1), golden.txn(OP).marker.start, |payload| {
        payload[MARKER_CHAIN_AT + 5] ^= 0xFF
    });
    open_halts_with_chain_break(&case, golden.seq(OP), "case 3: the marker's chain edited");

    let case = golden.case("c03-above-base");
    let op = CHECKPOINT_AFTER_OP + 1;
    rewrite_frame(&seg_file(&case, 1), golden.txn(op).marker.start, |payload| {
        payload[MARKER_CHAIN_AT] ^= 0xFF
    });
    open_halts_with_chain_break(
        &case,
        golden.seq(op),
        "case 3: the first marker above the base, its chain edited, one transaction after it",
    );

    let case = golden.case("c03-last");
    rewrite_frame(&seg_file(&case, 1), golden.txn(GOLDEN_OPS).marker.start, |payload| {
        payload[MARKER_CHAIN_AT + 31] ^= 0xFF
    });
    open_halts_with_chain_break(
        &case,
        golden.seq(GOLDEN_OPS),
        "case 3: the last marker's chain edited — a committed marker still, so its link fails",
    );
}

/// CASE 4 — THE SIGNATURE SLOT IS NOT A CHAIN INPUT, by design — a signature over
/// the chain must sit outside it. A FILLED slot (tag 1, the ruled default
/// pair; two bytes the kernel never interprets; the marker frame two bytes
/// longer, its `len` and CRC re-sealed) opens: the chain does not break, the
/// head and every boundary answer the golden's world, nothing is cut. So the
/// slot stays free for signed ops.
///
/// An INCONSISTENT slot — the tag set with no bytes — is not a marker at
/// all: the decoder holds the slot's one-spelling-of-empty rule, the frame
/// is undecodable and reads as a corrupt run landing on the next
/// transaction's first record, reported at that record's coordinate with no
/// cause — never admitted as a commit under a pair that signed nothing. The
/// marker's decode rule, not the chain's.
#[test]
fn c04_the_signature_slot_is_not_a_chain_input_a_filled_slot_opens() {
    let golden = Golden::build();
    const OP: usize = 9;
    let fill = |seg: &Path, txn: &Txn| {
        let data = fs::read(seg).expect("segment");
        let mut payload = data[txn.marker.payload.clone()].to_vec();
        assert_eq!(payload.len(), MARKER_EMPTY_LEN, "an unsigned marker");
        payload[MARKER_SIG_ALG_AT] = 1;
        payload[MARKER_SIG_LEN_AT..MARKER_EMPTY_LEN].copy_from_slice(&2u64.to_le_bytes());
        payload.extend_from_slice(&[0xAA, 0xBB]);
        replace_frame_payload(seg, txn.marker.start, &payload);
    };

    let case = golden.case_from_genesis("c04-filled");
    fill(&seg_file(&case, 1), golden.txn(OP));
    let engine =
        open_recovers(&case, &golden, golden.head(), "case 4: a filled signature slot mid-history");
    every_boundary_answers(&engine, &golden, "case 4");
    assert_eq!(
        engine.kernel().chain_head(),
        golden.txn(GOLDEN_OPS).chain,
        "the head's chain is the golden's: the slot is outside every link"
    );
    drop(engine);
    assert_eq!(
        fs::metadata(seg_file(&case, 1)).expect("segment").len(),
        golden.fixture.full_len + 2,
        "the open kept the filled slot: nothing cut"
    );

    let case = golden.case("c04-filled-above-base");
    fill(&seg_file(&case, 1), golden.txn(CHECKPOINT_AFTER_OP + 1));
    open_recovers(&case, &golden, golden.head(), "case 4: a filled slot above a standing base");

    let case = golden.case_from_genesis("c04-tag-without-bytes");
    rewrite_frame(&seg_file(&case, 1), golden.txn(OP).marker.start, |payload| {
        payload[MARKER_SIG_ALG_AT] = 1
    });
    let err = match timed_open_result(&case, "case 4: a tag without bytes") {
        Ok(_) => panic!("FINDING: a marker under a pair that signed nothing was admitted"),
        Err(err) => err,
    };
    let next_record = Seq(golden.txn(OP + 1).first_seq);
    assert!(
        matches!(
            &err,
            EngineError::Open(OpenError::Corruption { at, cause: None }) if *at == next_record
        ),
        "an inconsistent slot is an undecodable frame: a corrupt run landing on the next \
         transaction's first record, no cause — got {err:?}"
    );
}

/// CASE 5 — TWO WHOLE TRANSACTIONS SWAPPED, frames intact, CRCs valid, every marker
/// closing its group — and a fold, being by `Seq` and not by file position,
/// would even have rebuilt the right world. The chain is over JOURNAL ORDER,
/// the order the writer chained in: CAUGHT at the first swapped position,
/// named as the transaction now sitting there, whose link follows the value
/// of the transaction before its old place.
#[test]
fn c05_two_transactions_swapped_break_at_the_first_swapped_position() {
    let golden = Golden::build();

    let case = golden.case_from_genesis("c05-distant");
    swap_txns(&seg_file(&case, 1), 9 - 1, 12 - 1);
    open_halts_with_chain_break(
        &case,
        golden.seq(12),
        "case 5: ops 9 and 12 swapped — op 12 now sits first, chaining from op 11's value",
    );

    let case = golden.case_from_genesis("c05-adjacent");
    swap_txns(&seg_file(&case, 1), 9 - 1, 10 - 1);
    open_halts_with_chain_break(&case, golden.seq(10), "case 5: ops 9 and 10 swapped");

    let case = golden.case("c05-above-base");
    swap_txns(&seg_file(&case, 1), 17 - 1, 18 - 1);
    open_halts_with_chain_break(
        &case,
        golden.seq(18),
        "case 5: the two transactions above the base swapped",
    );
}

/// CASE 6 — A TRANSACTION DELETED FROM THE MIDDLE, THE FILE CLOSED UP. §7 requires
/// no `Seq` contiguity, so the hole is a burned range by coordinates alone —
/// once a shorter world at the true head, answered `Ok`. CAUGHT at the next
/// transaction, which chains from a predecessor the scan never saw.
#[test]
fn c06_a_transaction_deleted_from_the_middle_breaks_at_the_next() {
    let golden = Golden::build();

    let case = golden.case_from_genesis("c06");
    delete_txn(&seg_file(&case, 1), 9 - 1);
    open_halts_with_chain_break(&case, golden.seq(10), "case 6: op 9 deleted, the file closed up");

    let case = golden.case("c06-above-base");
    delete_txn(&seg_file(&case, 1), 17 - 1);
    open_halts_with_chain_break(&case, golden.seq(18), "case 6: op 17 deleted above the base");
}

/// CASE 7 — A CLOSED SEGMENT REPLACED BY AN OLDER COPY OF ITSELF while later
/// segments stand — the cross-segment carry under test. Rotation is the
/// constant `SEGMENT_ROTATE_BYTES` (1 MiB), tested before a transaction is
/// appended and only at a boundary, so a ~1 MiB insert lands in `seg-1` and
/// the commit after it rotates: this case's history is its own, built
/// through the engine. CAUGHT at the first transaction of the next segment,
/// which chains from the marker the rolled-back segment no longer holds.
#[test]
fn c07_a_closed_segment_rolled_back_to_an_older_copy_breaks_at_the_next_segments_first_transaction()
{
    const SEGMENT_FILL: usize = 1024 * 1024;
    let tmp = tempdir().expect("tempdir");
    let dir = tmp.path().join("two-segments");
    let seg1 = seg_file(&dir, 1);
    let (older, break_at, head, dump) = {
        let engine = Engine::open(cfg_manual(&dir)).expect("open the fixture");
        let prefix = {
            let snap = engine.kernel().snapshot();
            snap.world().m3().next_account_prefix(&node1()).expect("a delegable prefix")
        };
        let (acct, _) = engine
            .namespace()
            .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), USER)
            .expect("delegate");
        let (doc, _) = engine
            .namespace()
            .create_new_document(USER, &acct, Some(false))
            .expect("create a draft");
        engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'a'])], Deposit::Undeclared)
            .expect("insert a");
        // The OLDER copy: three transactions, ending on a committed marker.
        let older = fs::read(&seg1).expect("seg-1 before the fill");
        engine
            .vstream()
            .insert(
                OWNER,
                &doc,
                vp(1, 2),
                vec![Val::new(vec![0x5A; SEGMENT_FILL])],
                Deposit::Undeclared,
            )
            .expect("the ~1 MiB insert");
        assert_eq!(segment_count(&dir), 1, "the fill lands in seg-1");
        let (_, rotated) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 3), vec![Val::new(vec![b'b'])], Deposit::Undeclared)
            .expect("insert b");
        assert_eq!(segment_count(&dir), 2, "the commit after the fill rotates");
        let (_, last) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 4), vec![Val::new(vec![b'c'])], Deposit::Undeclared)
            .expect("insert c");
        (older, rotated.0, last.0, engine.world_dump())
    };
    {
        let engine = timed_open(&dir, "case 7: the two-segment history before any damage");
        assert_eq!(engine.kernel().current_seq(), Seq(head));
        assert_eq!(engine.world_dump(), dump);
    }
    rollback_segment(&seg1, &older);
    open_halts_with_chain_break(
        &dir,
        break_at,
        "case 7: seg-1 rolled back to its copy before the fill, seg-2 standing",
    );
}

/// CASE 8 — A CHECKPOINT'S BODY REWRITTEN, ITS CRC RE-FIXED: REFUSED by
/// `body_hash` — the fallback reaches genesis (the golden's one segment
/// begins at `Seq(1)`), the journal re-verifies from its seed, and the open
/// recovers the whole history. The door is named by putting genesis out of
/// reach: the exhausted fallback chain's account is the hash's refusal, the
/// checksum having passed.
///
/// NOT CAUGHT BY DESIGN — the body FORGED: another world's canonical body
/// under this coordinate (the golden's ops checkpointed one op earlier: the
/// world at 36 posing as 37), the CRC, `body_len` and `body_hash` re-fixed
/// over it, `seq` and `chain_head` kept. It loads as the base, the two links
/// above it verify against the head it kept, and the open succeeds at the
/// true head serving a world that is not the golden's. Only the published
/// head, naming the checkpoint by `(seq, chain_head, body_hash)`, can see a
/// hash that was re-fixed.
#[test]
fn c08_a_checkpoint_body_rewritten_is_refused_by_its_hash_and_a_body_forged_with_its_hash_is_not() {
    let golden = Golden::build();
    let ckpt_seq = golden.checkpoint_seq();
    let damage = |body: &mut [u8]| {
        let mid = body.len() / 2;
        body[mid] ^= 0xFF;
    };

    let case = golden.case("c08-refused");
    rewrite_checkpoint_body(&ckpt_file(&case, ckpt_seq), damage);
    let engine = open_recovers(
        &case,
        &golden,
        golden.head(),
        "case 8: a body byte rewritten, the CRC re-fixed, the hash stale",
    );
    every_boundary_answers(&engine, &golden, "case 8");
    drop(engine);

    let case = golden.case("c08-refused-unreachable");
    rewrite_checkpoint_body(&ckpt_file(&case, ckpt_seq), damage);
    fs::rename(seg_file(&case, 1), seg_file(&case, 2)).expect("rename the segment");
    let err = match timed_open_result(&case, "case 8: nothing stands in") {
        Ok(_) => panic!("FINDING: opened with no base derivable"),
        Err(err) => err,
    };
    let EngineError::Open(OpenError::BadCheckpoint { cause: Some(cause) }) = &err else {
        panic!(
            "expected an exhausted fallback chain carrying the newest refusal's account, got {err:?}"
        )
    };
    let cause = cause.to_string();
    assert!(
        cause.contains("hash") && !cause.contains("checksum"),
        "the hash refused and the checksum passed: {cause}"
    );

    let other = Fixture::build_golden(&golden.tmp.path().join("other"), &[CHECKPOINT_AFTER_OP - 1]);
    let other_seq = other.boundaries[CHECKPOINT_AFTER_OP - 2].seq;
    let body = fs::read(ckpt_file(&other.dir, other_seq)).expect("the other checkpoint")
        [CHECKPOINT_HEADER_LEN..]
        .to_vec();
    let case = golden.case("c08-forged");
    let ckpt = ckpt_file(&case, ckpt_seq);
    let mut data = fs::read(&ckpt).expect("the checkpoint");
    data.truncate(CHECKPOINT_HEADER_LEN);
    data[CHECKPOINT_CRC_AT..CHECKPOINT_BODY_LEN_AT]
        .copy_from_slice(&crc32c::crc32c(&body).to_le_bytes());
    data[CHECKPOINT_BODY_LEN_AT..CHECKPOINT_CHAIN_HEAD_AT]
        .copy_from_slice(&(body.len() as u64).to_le_bytes());
    data[CHECKPOINT_BODY_HASH_AT..CHECKPOINT_HEADER_LEN]
        .copy_from_slice(&<[u8; 32]>::from(Sha256::digest(&body)));
    data.extend_from_slice(&body);
    fs::write(&ckpt, data).expect("write the forged checkpoint");
    let engine = timed_open(&case, "case 8: a forged body with its hash re-fixed");
    assert_eq!(engine.kernel().current_seq(), Seq(golden.head()));
    assert_eq!(
        engine.kernel().chain_head(),
        golden.txn(GOLDEN_OPS).chain,
        "the chain above the base verified: it cannot see the base"
    );
    assert_ne!(
        &engine.world_dump(),
        golden.dump(golden.head()),
        "the forged base was served at the true head"
    );
    assert_eq!(
        &engine.dump_of(&engine.world_at(Seq(ckpt_seq)).expect("the base's own boundary")),
        other.dump_for(other_seq),
        "the base's own boundary answers the forged world — the other history's, one op earlier, \
         under this coordinate"
    );
}

/// CASE 9 — A CHECKPOINT'S `chain_head` EDITED, its CRC and `body_hash` left
/// consistent — which they are: nothing in the `SKC4` header covers that
/// field. So the code does not REFUSE — the base LOADS carrying the edited
/// value — and the open is CAUGHT at the BASE'S OWN COORDINATE: the marker
/// closing the base's seq is in the scanned segment (the golden's one
/// segment; at the head, the active segment always), and the chain it
/// carries is not the header's — two stored values disagreeing, nothing
/// recomputed, named with the base's own account (the chain's open items,
/// item 4). Where that marker is NOT scanned — its closed segment ending
/// exactly at the base's seq, case 15 — the first transaction above the
/// base is the one whose link fails against the header, as it was before.
///
/// The checkpoint AT THE HEAD was the fork the chain alone accepted:
/// nothing above the base, no link to fail, the root carrying the edited
/// value and the next commit chaining from it — which since `0f0115b` the
/// head document would have PUBLISHED as the board's own. Now CAUGHT the
/// same way: the head's marker is in the active segment, always scanned,
/// and disagrees with the header. Nothing is cut, and the files stay as
/// found.
#[test]
fn c09_a_checkpoints_chain_head_edited_breaks_at_the_bases_own_coordinate() {
    let golden = Golden::build();

    let case = golden.case("c09");
    flip_byte(&ckpt_file(&case, golden.checkpoint_seq()), (CHECKPOINT_CHAIN_HEAD_AT + 3) as u64);
    open_halts_naming(
        &case,
        golden.checkpoint_seq(),
        BASE_MISMATCH,
        "case 9: the checkpoint's chain_head edited, mid-history, its marker in the scanned segment",
    );

    let at_head = Fixture::build_golden(&golden.tmp.path().join("at-head"), &[GOLDEN_OPS]);
    let head = at_head.last_seq();
    let edited = [0xE7u8; 32];
    set_checkpoint_chain_head(&ckpt_file(&at_head.dir, head), &edited);
    open_halts_naming(
        &at_head.dir,
        head,
        BASE_MISMATCH,
        "case 9: a head checkpoint's chain_head edited — the at-head fork, closed",
    );
}

/// CASE 10 — THE TAIL TRUNCATED AT A TRANSACTION BOUNDARY: NOT CAUGHT BY DESIGN.
/// A shorter history is a valid history to the chain alone: the open
/// recovers at the shorter head with the world the golden recorded THERE,
/// cuts nothing further (the file already ends on a marker), and the chain
/// head is the shorter history's — a peer holding the head as it was finds
/// this history does not EXTEND it, which is piece 2's check and the only
/// one there is. With the golden's checkpoint standing (one transaction cut;
/// both above the base cut, the head then the base itself) and from genesis
/// (eight cut).
#[test]
fn c10_a_clean_tail_cut_opens_at_the_shorter_head() {
    let golden = Golden::build();
    for cut_to in [GOLDEN_OPS - 1, CHECKPOINT_AFTER_OP] {
        let case = golden.case(&format!("c10-standing-{cut_to}"));
        let seg = seg_file(&case, 1);
        truncate_file(&seg, golden.txn(cut_to).bytes.end as u64);
        let engine = open_recovers(
            &case,
            &golden,
            golden.seq(cut_to),
            &format!("case 10: the tail cut at op {cut_to}'s boundary"),
        );
        assert_eq!(
            engine.kernel().chain_head(),
            golden.txn(cut_to).chain,
            "the head is the shorter history's"
        );
        every_boundary_answers(&engine, &golden, "case 10");
        drop(engine);
        assert_eq!(
            fs::metadata(&seg).expect("segment").len(),
            golden.txn(cut_to).bytes.end as u64,
            "nothing further cut"
        );
    }

    let case = golden.case_from_genesis("c10-genesis");
    truncate_file(&seg_file(&case, 1), golden.txn(10).bytes.end as u64);
    let engine =
        open_recovers(&case, &golden, golden.seq(10), "case 10: eight transactions cut, from genesis");
    assert_eq!(engine.kernel().chain_head(), golden.txn(10).chain);
    every_boundary_answers(&engine, &golden, "case 10, from genesis");
}

/// CASE 11 — THE HISTORY REWRITTEN WITH A CONSISTENT CHAIN: NOT CAUGHT BY DESIGN.
/// The golden's first marker's chain is SHA-256 over the seed, and every
/// later link is over bytes the forger holds, so a forgery re-chained from
/// any point — genesis, or mid-history — passes: the chain has no anchor
/// but its seed and the base's header. The SALT (`SKJ4`) is no anchor
/// either, and the forger here proves it by CHOOSING ITS OWN — every
/// re-chained marker is re-salted with a value the writer never drew, and
/// the links recomputed over those; the salt sits in the marker beside the
/// bytes it salts, and a party holding the journal holds both. STILL NOT
/// CAUGHT BY DESIGN: what the salt closes is the confirmation oracle over
/// SERVED values, which a party who can rewrite the journal never needed.
/// The world served is the forger's, at every boundary from the forgery on;
/// the head's chain is not the golden's — which is exactly what a published
/// head would show, and all it could.
///
/// The checkpoint is the forger's one loose end, and it is not a check: with
/// its `chain_head` rewritten the open passes, and its BODY — which nothing
/// compares to the journal below it — goes on answering the golden's world
/// at its own coordinate and above while the journal below answers the
/// forger's. The forger closes that with the kernel's own tools: remove the
/// base, replay the forged journal from genesis, checkpoint. Every file is
/// then consistent with every other, and nothing in this crate can tell.
#[test]
fn c11_a_consistent_rewrite_from_genesis_or_from_any_point_passes() {
    let golden = Golden::build();
    // The forger's formula IS the writer's: re-chaining the untouched golden
    // from its seed reproduces every marker's chain byte for byte, and the
    // checkpoint's head is the link at its coordinate. What follows passes
    // because the forgery is consistent, not because the formula drifted.
    {
        let data = fs::read(golden_segment()).expect("the golden segment");
        let mut prev = CHAIN_GENESIS;
        for txn in &golden.txns {
            let chain = chain_over(&prev, &data, txn);
            assert_eq!(chain, txn.chain, "the formula drifted from the writer's at {}", txn.last_seq);
            prev = chain;
        }
        assert_eq!(
            golden.txn(CHECKPOINT_AFTER_OP).chain,
            checkpoint_chain_head(&ckpt_file(&golden.fixture.dir, golden.checkpoint_seq()))
        );
    }

    // Every boundary answers — nothing halts — and the world at each is the
    // golden's below `forged_from` and the forger's from it on.
    let boundaries_answer = |engine: &Engine, forged_from: usize, ctx: &str| {
        for (op, boundary) in golden.fixture.boundaries.iter().enumerate().map(|(i, b)| (i + 1, b))
        {
            let world = engine.world_at(Seq(boundary.seq)).unwrap_or_else(|e| {
                panic!("FINDING ({ctx}): boundary {} halted over a consistent forgery: {e}", boundary.seq)
            });
            if op < forged_from {
                assert_eq!(engine.dump_of(&world), boundary.dump, "{ctx}: below the forgery, the golden's");
            } else {
                assert_ne!(engine.dump_of(&world), boundary.dump, "{ctx}: from the forgery on, the forger's");
            }
        }
    };
    let ckpt_seq = golden.checkpoint_seq();

    // (a) FROM GENESIS: op 1's RegisterPrincipal id rewritten — USER's 7
    //     becomes 9, one u64 found once in the transaction's records — every
    //     link recomputed from the seed, the checkpoint's head rewritten. The
    //     open passes at the true head; below the base every boundary is the
    //     forger's; AT the base and above, the checkpoint's own body answers
    //     — the golden's world, the one witness the journal forgery leaves
    //     behind, which nothing compares to the journal below it.
    let case = golden.case("c11-from-genesis");
    forge_and_rechain(
        &golden,
        &case,
        1,
        &7u64.to_le_bytes(),
        &9u64.to_le_bytes(),
        CheckpointAfterForgery::HeadRewritten,
    );
    // The forger's salts are on disk — none of them the seeded stream's —
    // and every one of the eighteen links verifies over them.
    for txn in transactions(&fs::read(seg_file(&case, 1)).expect("segment")) {
        assert_eq!(txn.salt, forger_salt(txn.last_seq), "the forger's own salt at {}", txn.last_seq);
        assert_ne!(txn.salt, seeded_salt(GOLDEN_SALT_SEED, txn.txn));
    }
    let engine = timed_open(&case, "case 11: a consistent forgery from genesis, the base's head rewritten");
    assert_eq!(engine.kernel().current_seq(), Seq(golden.head()));
    assert_ne!(engine.kernel().chain_head(), golden.txn(GOLDEN_OPS).chain, "the head moved");
    for boundary in &golden.fixture.boundaries {
        let world = engine.world_at(Seq(boundary.seq)).unwrap_or_else(|e| {
            panic!("FINDING: boundary {} halted over a consistent forgery: {e}", boundary.seq)
        });
        if boundary.seq < ckpt_seq {
            assert_ne!(engine.dump_of(&world), boundary.dump, "below the base: the forger's");
        } else {
            assert_eq!(engine.dump_of(&world), boundary.dump, "at the base and above: the base's body");
        }
    }
    assert_eq!(&engine.world_dump(), golden.dump(golden.head()), "the head is the base's body folded on");
    drop(engine);
    //     The forger's remaining writes, with the kernel's own tools: remove
    //     the base, replay the forged journal from genesis — it passes — and
    //     checkpoint, minting the canonical body of the forged world under
    //     the re-chained head. Reopened, the base is the forger's, the head
    //     and every boundary are the forger's, and nothing halts anywhere.
    fs::remove_file(ckpt_file(&case, ckpt_seq)).expect("the forger removes the stale base");
    let engine = timed_open(&case, "case 11: the forged journal replayed from genesis");
    assert_eq!(engine.kernel().current_seq(), Seq(golden.head()));
    boundaries_answer(&engine, 1, "case 11 (a), from genesis");
    assert_ne!(&engine.world_dump(), golden.dump(golden.head()), "the head is the forger's");
    engine.check_hints().expect("the forged history is consistent with itself");
    let forged_head = engine.kernel().chain_head();
    let minted = engine.kernel().checkpoint().expect("the forger's checkpoint");
    assert_eq!(minted, Seq(golden.head()));
    assert_eq!(checkpoint_chain_head(&ckpt_file(&case, minted.0)), forged_head);
    drop(engine);
    let engine = timed_open(&case, "case 11: the forged history over the forger's base");
    assert_eq!(engine.kernel().current_seq(), Seq(golden.head()));
    assert_eq!(engine.kernel().chain_head(), forged_head);
    boundaries_answer(&engine, 1, "case 11 (a), over the forger's base");
    drop(engine);

    // (b) FROM ANY POINT: op 4's inserted 'a' becomes 'A', below the
    //     checkpoint; the links from op 4 on recomputed from op 3's value as
    //     the golden wrote it; the base removed, so the open replays the
    //     forged journal from genesis. The boundaries below the forgery
    //     answer the golden's world, those from it on the forger's, and
    //     nothing halts.
    const A: &[u8] = &[1, 0, 0, 0, 0, 0, 0, 0, b'a'];
    const FORGED: &[u8] = &[1, 0, 0, 0, 0, 0, 0, 0, b'A'];
    let case = golden.case("c11-from-op-4");
    forge_and_rechain(&golden, &case, 4, A, FORGED, CheckpointAfterForgery::Removed);
    let engine = timed_open(&case, "case 11: a consistent forgery from op 4");
    assert_eq!(engine.kernel().current_seq(), Seq(golden.head()));
    assert_ne!(engine.kernel().chain_head(), golden.txn(GOLDEN_OPS).chain, "the head moved");
    boundaries_answer(&engine, 4, "case 11 (b), from op 4");
    drop(engine);

    // (c) …and the checkpoint's `chain_head` is the one anchor the journal
    //     has above its seed: the same forgery with the checkpoint left as
    //     the golden wrote it fails the BASE'S OWN LINK — the forger
    //     re-chained op 16's marker, the header still carries the golden's
    //     value, and the two disagree at 37 — case 9's door, which a forger
    //     who can write the checkpoint file closes with one more write, as
    //     (a) did.
    let case = golden.case("c11-checkpoint-kept");
    forge_and_rechain(&golden, &case, 4, A, FORGED, CheckpointAfterForgery::Kept);
    open_halts_naming(
        &case,
        golden.checkpoint_seq(),
        BASE_MISMATCH,
        "case 11 with the checkpoint's head kept as the golden wrote it",
    );
}

/// CASE 12 — DAMAGE BELOW A STANDING CHECKPOINT BASE — a consistent rewrite in the
/// segment the base already covers, the segment still present. The
/// ruling's "any rewrite" as the owner reads it (2026-09-23): the chain is
/// verified for transactions above the base a replay SELECTS. So the base
/// embodies the rewritten transaction, the scan verifies the base's own
/// link and the two links above it, and the open recovers the whole
/// history at the true head with the golden's world — NOT CAUGHT while the
/// base stands, and once reclamation drops the segment, beyond any replay.
/// A bounded read BELOW the base — a world or a chain, `world_at` and
/// `chain_at` running one verification — selects genesis and verifies
/// every link from there to the journal's end, and is caught at the
/// rewritten transaction whether the boundary asked lies above it or below
/// it: the on-demand full verification of the surviving journal, which the
/// daemon serves as `GET /chain?at=N` with no world materialized.
#[test]
fn c12_damage_below_a_standing_base_is_unseen_at_open_and_seen_by_a_replay_from_genesis() {
    let golden = Golden::build();
    const OP: usize = 9;
    let case = golden.case("c12");
    rewrite_txn(&seg_file(&case, 1), OP - 1, |data, txn| flip_record_byte(data, txn, 0, 40));
    let engine = open_recovers(
        &case,
        &golden,
        golden.head(),
        "case 12: a consistent rewrite below the base, the base standing",
    );
    assert_eq!(engine.kernel().chain_head(), golden.txn(GOLDEN_OPS).chain);
    let ckpt_seq = golden.checkpoint_seq();
    assert_eq!(
        &engine.dump_of(&engine.world_at(Seq(ckpt_seq)).expect("the base's own boundary")),
        golden.dump(ckpt_seq),
        "the base's own boundary answers from the base, without a scan"
    );
    let above = golden.seq(CHECKPOINT_AFTER_OP + 1);
    assert_eq!(
        &engine.dump_of(&engine.world_at(Seq(above)).expect("a boundary above the base")),
        golden.dump(above),
        "a boundary above the base scans above it only"
    );
    // The chain at and above the base: the base's own (the header's, which
    // is the golden's marker's at 37) and the two markers above, none of
    // them consulting the rewritten segment below the base.
    chain_at_is(&engine, ckpt_seq, &golden.txn(CHECKPOINT_AFTER_OP).chain, "case 12: at the base");
    chain_at_is(&engine, above, &golden.txn(CHECKPOINT_AFTER_OP + 1).chain, "case 12: above the base");
    chain_at_is(&engine, golden.head(), &golden.txn(GOLDEN_OPS).chain, "case 12: at the head");
    // Below the base, the world and the chain halt alike, at the rewrite.
    history_halts_with_chain_break(
        &engine,
        golden.seq(12),
        golden.seq(OP),
        "case 12: a boundary above the rewrite and below the base",
    );
    history_halts_with_chain_break(
        &engine,
        golden.seq(3),
        golden.seq(OP),
        "case 12: a boundary below the rewrite",
    );
}

/// CASE 13 — TWO DAMAGES, ONE ABOVE THE OTHER: CAUGHT at the FIRST; the error
/// names the first coordinate only — the chain cannot see past a break.
#[test]
fn c13_two_damages_name_the_first_only() {
    let golden = Golden::build();

    let case = golden.case_from_genesis("c13-records");
    let seg = seg_file(&case, 1);
    rewrite_txn(&seg, 5 - 1, |data, txn| flip_record_byte(data, txn, 0, 40));
    rewrite_txn(&seg, 12 - 1, |data, txn| flip_record_byte(data, txn, 0, 20));
    open_halts_with_chain_break(&case, golden.seq(5), "case 13: consistent rewrites at ops 5 and 12");

    let case = golden.case_from_genesis("c13-chain-fields");
    let seg = seg_file(&case, 1);
    rewrite_frame(&seg, golden.txn(5).marker.start, |payload| payload[MARKER_CHAIN_AT] ^= 0xFF);
    rewrite_frame(&seg, golden.txn(12).marker.start, |payload| payload[MARKER_CHAIN_AT] ^= 0xFF);
    open_halts_with_chain_break(&case, golden.seq(5), "case 13: chain fields edited at ops 5 and 12");
}

/// Give op `op`'s marker the chain `value` and re-chain every marker above
/// it from that value, each frame re-sealed — what a forger who edits the
/// base's own link does to keep the links above it verifying. Answers the
/// chains written, by boundary, `op`'s first.
fn set_marker_chain_and_rechain_above(seg: &Path, op: usize, value: &[u8; 32]) -> Vec<(u64, [u8; 32])> {
    let mut data = fs::read(seg).expect("segment");
    let txns = transactions(&data);
    let edited = &txns[op - 1];
    let at = edited.marker.payload.start + MARKER_CHAIN_AT;
    data[at..at + 32].copy_from_slice(value);
    reseal_frame(&mut data, &edited.marker);
    let mut chains = vec![(edited.last_seq, *value)];
    let mut prev = *value;
    for txn in &txns[op..] {
        let chain = chain_over(&prev, &data, txn);
        let at = txn.marker.payload.start + MARKER_CHAIN_AT;
        data[at..at + 32].copy_from_slice(&chain);
        reseal_frame(&mut data, &txn.marker);
        chains.push((txn.last_seq, chain));
        prev = chain;
    }
    fs::write(seg, data).expect("write the re-chained segment");
    chains
}

/// CASE 14 — THE BASE'S OWN LINK EDITED ON BOTH SIDES: the marker closing the
/// base's seq given a new chain, every link above re-chained from it, and
/// the header rewritten to match — the residue item 4's check leaves (the
/// damage model's (i)). NOT CAUGHT at open: the two stored values agree,
/// the links above verify, the root carries the edit, and the world is the
/// golden's at every boundary (no record was touched). SEEN by any bounded
/// read BELOW the base — a world or a chain, one verification — which
/// selects genesis, recomputes the link at the base's seq over its true
/// predecessor, and fails it THERE. `chain_at` at the base answers the
/// edit: the forgery a peer's saved pair contradicts.
#[test]
fn c14_the_bases_link_edited_on_both_sides_passes_at_open_and_fails_from_below() {
    let golden = Golden::build();
    let ckpt_seq = golden.checkpoint_seq();
    let edited = [0x5Cu8; 32];

    let case = golden.case("c14");
    let rechained = set_marker_chain_and_rechain_above(&seg_file(&case, 1), CHECKPOINT_AFTER_OP, &edited);
    set_checkpoint_chain_head(&ckpt_file(&case, ckpt_seq), &edited);
    let engine = open_recovers(
        &case,
        &golden,
        golden.head(),
        "case 14: the base's marker and header edited alike, the links above re-chained",
    );
    let (_, head_chain) = rechained.last().expect("the re-chained head");
    assert_eq!(engine.kernel().chain_head(), *head_chain, "the root carries the re-chained head");
    assert_ne!(*head_chain, golden.txn(GOLDEN_OPS).chain, "the head moved");
    // At and above the base: the world is the golden's, the chain the edit's.
    assert_eq!(
        &engine.dump_of(&engine.world_at(Seq(ckpt_seq)).expect("the base's own boundary")),
        golden.dump(ckpt_seq)
    );
    chain_at_is(&engine, ckpt_seq, &edited, "case 14: the base answers the header's edited value");
    let above = golden.seq(CHECKPOINT_AFTER_OP + 1);
    assert_eq!(
        &engine.dump_of(&engine.world_at(Seq(above)).expect("a boundary above the base")),
        golden.dump(above)
    );
    chain_at_is(&engine, above, &rechained[1].1, "case 14: above the base, the re-chained link");
    // Below the base: genesis is selected, and the link at the base's seq
    // fails over op 16's true predecessor — the link's own account, since
    // from genesis there is no base whose header could disagree.
    history_halts_with_chain_break(
        &engine,
        golden.seq(12),
        ckpt_seq,
        "case 14: a boundary below the base recomputes the edited link",
    );
    history_halts_with_chain_break(&engine, golden.seq(3), ckpt_seq, "case 14: a boundary further below");
}

/// CASE 16 — A MARKER'S SALT EDITED, CRC RE-FIXED (`SKJ4`): THE SALT IS A CHAIN
/// INPUT. The writer closed the link with the salt it drew and stored; the
/// scan closes it with the salt it READS off the marker; so a salt edited in
/// place is a link that no longer verifies — CAUGHT at that transaction with
/// the link's account, the next not masking it (it chains from the stored
/// value, which the edit left alone). Mid-history from genesis, above a
/// standing base, and on the last transaction, as case 3 for the chain
/// field; the edit is a single byte, so nothing but the salt moved. Case 4
/// (the slot) is unchanged: the slot stays outside every link.
///
/// What the salt is NOT: an anchor. The same edit with the chain recomputed
/// over the new salt and every link above re-chained — a consistent rewrite
/// — opens at the true head with the golden's world at every boundary, its
/// chain the forger's: case 11's shape, restated for the salt alone.
#[test]
fn c16_a_markers_salt_edited_breaks_at_that_transaction() {
    let golden = Golden::build();
    const OP: usize = 9;

    let case = golden.case_from_genesis("c16");
    rewrite_frame(&seg_file(&case, 1), golden.txn(OP).marker.start, |payload| {
        payload[MARKER_SALT_AT + 7] ^= 0xFF
    });
    open_halts_with_chain_break(&case, golden.seq(OP), "case 16: the marker's salt edited");

    let case = golden.case("c16-above-base");
    let op = CHECKPOINT_AFTER_OP + 1;
    rewrite_frame(&seg_file(&case, 1), golden.txn(op).marker.start, |payload| {
        payload[MARKER_SALT_AT] ^= 0xFF
    });
    open_halts_with_chain_break(
        &case,
        golden.seq(op),
        "case 16: the first marker above the base, its salt edited, one transaction after it",
    );

    let case = golden.case("c16-last");
    rewrite_frame(&seg_file(&case, 1), golden.txn(GOLDEN_OPS).marker.start, |payload| {
        payload[MARKER_SALT_AT + 31] ^= 0xFF
    });
    open_halts_with_chain_break(
        &case,
        golden.seq(GOLDEN_OPS),
        "case 16: the last marker's salt edited — a committed marker still, so its link fails",
    );

    // The consistent rewrite: op 9 re-salted, its chain recomputed over the
    // new salt from op 8's value, every link above re-chained — the base
    // removed so the open replays from genesis. NOT CAUGHT BY DESIGN: the
    // world is the golden's everywhere (no record moved), the chain is the
    // forger's from op 9 on.
    let case = golden.case_from_genesis("c16-rechained");
    let seg = seg_file(&case, 1);
    let mut data = fs::read(&seg).expect("segment");
    let txns = transactions(&data);
    let mut prev = golden.txn(OP - 1).chain;
    let mut rechained = Vec::new();
    for txn in &txns[OP - 1..] {
        if txn.last_seq == golden.seq(OP) {
            set_marker_salt(&mut data, txn, &forger_salt(txn.last_seq));
        }
        let chain = chain_over(&prev, &data, txn);
        let at = txn.marker.payload.start + MARKER_CHAIN_AT;
        data[at..at + 32].copy_from_slice(&chain);
        reseal_frame(&mut data, &txn.marker);
        rechained.push((txn.last_seq, chain));
        prev = chain;
    }
    fs::write(&seg, data).expect("write the re-chained segment");
    let engine = open_recovers(
        &case,
        &golden,
        golden.head(),
        "case 16: the salt rewritten and the chain recomputed over it — consistent, not caught",
    );
    let (_, head_chain) = rechained.last().expect("the re-chained head");
    assert_eq!(engine.kernel().chain_head(), *head_chain, "the root carries the re-chained head");
    assert_ne!(*head_chain, golden.txn(GOLDEN_OPS).chain, "the head moved");
    for op in 1..GOLDEN_OPS + 1 {
        if op < OP {
            chain_at_is(&engine, golden.seq(op), &golden.txn(op).chain, "case 16: below the re-salt, the golden's chain");
        } else {
            chain_at_is(&engine, golden.seq(op), &rechained[op - OP].1, "case 16: from the re-salt on, the forger's chain");
        }
    }
    every_boundary_answers(&engine, &golden, "case 16, re-chained: the world is the golden's");
}

/// The segment files of `dir`, ascending by the first seq their names carry.
fn segment_paths(dir: &Path) -> Vec<PathBuf> {
    let mut segs: Vec<(u64, PathBuf)> = fs::read_dir(dir)
        .expect("dir")
        .filter_map(|entry| {
            let entry = entry.expect("entry");
            let name = entry.file_name().into_string().ok()?;
            let first: u64 = name.strip_prefix("seg-")?.strip_suffix(".wal")?.parse().ok()?;
            Some((first, entry.path()))
        })
        .collect();
    segs.sort();
    segs.into_iter().map(|(_, path)| path).collect()
}

/// The two-segment history cases 15 and the reclaim refusal are built on:
/// a ~1 MiB insert fills `seg-1`, the checkpoint is taken AT that commit —
/// so the marker closing the base's seq is seg-1's LAST frame and seg-1's
/// inferred last seq is the base's — and the next commit rotates into
/// `seg-2`, which the one after extends. Its own history, built through
/// the engine as case 7's is.
struct TwoSegments {
    dir: PathBuf,
    /// The fill's boundary: the checkpoint's seq, and seg-1's inferred last.
    base: u64,
    /// The two boundaries above, both in seg-2.
    above: [u64; 2],
    /// The chain at each of the three boundaries, as the engine reported it.
    chains: BTreeMap<u64, [u8; 32]>,
    dump_at_base: WorldDump,
    dump_at_head: WorldDump,
}

impl TwoSegments {
    fn build(dir: &Path) -> TwoSegments {
        const SEGMENT_FILL: usize = 1024 * 1024;
        let engine = Engine::open(cfg_manual(dir)).expect("open the fixture");
        let prefix = {
            let snap = engine.kernel().snapshot();
            snap.world().m3().next_account_prefix(&node1()).expect("a delegable prefix")
        };
        let (acct, _) = engine
            .namespace()
            .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), USER)
            .expect("delegate");
        let (doc, _) = engine
            .namespace()
            .create_new_document(USER, &acct, Some(false))
            .expect("create a draft");
        let (_, filled) = engine
            .vstream()
            .insert(
                OWNER,
                &doc,
                vp(1, 1),
                vec![Val::new(vec![0x5A; SEGMENT_FILL])],
                Deposit::Undeclared,
            )
            .expect("the ~1 MiB insert");
        let base = filled.0;
        assert_eq!(segment_count(dir), 1, "the fill lands in seg-1");
        let mut chains = BTreeMap::new();
        chains.insert(base, engine.kernel().chain_head());
        let dump_at_base = engine.world_dump();
        let taken = engine.kernel().checkpoint().expect("the checkpoint at the fill's boundary");
        assert_eq!(taken, Seq(base));
        assert_eq!(segment_count(dir), 1, "a checkpoint rotates nothing");
        let (_, b) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 2), vec![Val::new(vec![b'b'])], Deposit::Undeclared)
            .expect("insert b");
        assert_eq!(segment_count(dir), 2, "the commit after the fill rotates");
        chains.insert(b.0, engine.kernel().chain_head());
        let (_, c) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 3), vec![Val::new(vec![b'c'])], Deposit::Undeclared)
            .expect("insert c");
        chains.insert(c.0, engine.kernel().chain_head());
        let dump_at_head = engine.world_dump();
        drop(engine);
        let seg1 = fs::read(seg_file(dir, 1)).expect("seg-1");
        assert_eq!(
            transactions(&seg1).last().expect("a marker").last_seq,
            base,
            "seg-1's last frame is the marker closing the base's seq: what the skip rule turns on"
        );
        TwoSegments {
            dir: dir.to_path_buf(),
            base,
            above: [b.0, c.0],
            chains,
            dump_at_base,
            dump_at_head,
        }
    }

    fn case(&self, tmp: &Path, name: &str) -> PathBuf {
        let dir = tmp.join(name);
        copy_dir(&self.dir, &dir);
        dir
    }
}

/// CASE 15 — THE BOUNDARY COINCIDENCE: the base's marker segment SKIPPED. The
/// scan opens no closed segment whose inferred last seq is at or below the
/// base's, and a segment ending EXACTLY at the base's seq is one — so the
/// marker closing the base's seq is never read, and the base's own link is
/// checked vacuously (the damage model's (ii)). With the header edited
/// there, the open behaves as it did before item 4: the first transaction
/// above the base is judged against the header and fails — CAUGHT at that
/// transaction with the LINK's account, not the base's. And with NOTHING
/// above the base — the one transaction above cut away, seg-2 empty, case
/// 10's shape — the edited header OPENS: NOT CAUGHT, pinned; the root
/// carries the edit and `chain_at` at the base answers it, which a peer's
/// saved pair contradicts. Covering the coincidence is the skip rule's to
/// change, and named out of this fence.
#[test]
fn c15_the_boundary_coincidence_skips_the_bases_marker_and_the_check_is_vacuous() {
    let tmp = tempdir().expect("tempdir");
    let two = TwoSegments::build(&tmp.path().join("two-segments"));
    {
        let engine = timed_open(&two.dir, "case 15: the two-segment history before any damage");
        assert_eq!(engine.kernel().current_seq(), Seq(two.above[1]));
        assert_eq!(engine.world_dump(), two.dump_at_head);
        for (seq, chain) in &two.chains {
            chain_at_is(&engine, *seq, chain, "case 15: the clean two-segment history");
        }
    }
    let edited = [0xB1u8; 32];

    let case = two.case(tmp.path(), "c15-above");
    set_checkpoint_chain_head(&ckpt_file(&case, two.base), &edited);
    open_halts_naming(
        &case,
        two.above[0],
        CHAIN_BREAK,
        "case 15: the header edited, its marker's segment skipped — the first link above fails \
         against it, and the base's own link is not judged",
    );

    let case = two.case(tmp.path(), "c15-nothing-above");
    set_checkpoint_chain_head(&ckpt_file(&case, two.base), &edited);
    truncate_file(&segment_paths(&case)[1], 0);
    let engine = timed_open(&case, "case 15: the header edited, nothing above the base");
    assert_eq!(engine.kernel().current_seq(), Seq(two.base));
    assert_eq!(engine.world_dump(), two.dump_at_base);
    assert_eq!(
        engine.kernel().chain_head(),
        edited,
        "NOT CAUGHT BY DESIGN: the base's marker segment skipped and nothing above it, the root \
         carries the edited value"
    );
    chain_at_is(&engine, two.base, &edited, "case 15: the base answers the edit");
}

/// `Kernel::chain_at` below the reclaim floor: once a checkpoint at the head
/// retires `seg-1` — the segment ending at the older base's seq lies wholly
/// below the oldest retained checkpoint — no base at or below a boundary in
/// it remains derivable, and the chain there is `Reclaimed { floor }`, the
/// floor naming the oldest retained base, exactly as `world_at` refuses; at
/// the floor the base's own chain answers, and above it the markers'.
#[test]
fn chain_at_is_reclaimed_below_the_floor_and_answers_from_the_floor_up() {
    let tmp = tempdir().expect("tempdir");
    let two = TwoSegments::build(&tmp.path().join("two-segments"));
    let case = two.case(tmp.path(), "reclaimed");
    let engine = timed_open(&case, "the two-segment history");
    engine.kernel().checkpoint().expect("a checkpoint at the head");
    assert_eq!(segment_count(&case), 1, "seg-1, wholly below the oldest retained checkpoint, is reclaimed");
    for seq in [0, two.base - 1] {
        match engine.kernel().chain_at(Seq(seq)) {
            Err(HistoryError::Reclaimed { floor, .. }) => {
                assert_eq!(floor, Some(Seq(two.base)), "the floor is the oldest retained base")
            }
            other => panic!("chain_at({seq}) below the floor: expected Reclaimed, got {other:?}"),
        }
        assert!(
            matches!(engine.world_at(Seq(seq)), Err(HistoryError::Reclaimed { floor: Some(f), .. }) if f == Seq(two.base)),
            "world_at({seq}) refuses the same way"
        );
    }
    for (seq, chain) in &two.chains {
        chain_at_is(&engine, *seq, chain, "from the floor up, every boundary");
    }
    assert_eq!(
        engine.kernel().chain_at(Seq(two.above[1])).expect("the head"),
        engine.kernel().chain_head(),
        "at the head — now the newest base's own seq — chain_at is chain_head"
    );
}

/// `Kernel::chain_at(N)` — the chain AS OF a boundary, off the same scan as
/// `world_at` and under its refusals: every one of the golden's eighteen
/// boundaries answers its marker's chain, from genesis and over the
/// standing base alike; `0` is the seed; the base's own seq is the header's
/// value; the head equals `chain_head()`, before and after a commit; a
/// boundary beyond the head, a composite's interior seq and an in-memory
/// kernel refuse as `world_at` does. What `GET /chain?at=N` serves.
#[test]
fn chain_at_answers_every_boundarys_marker_chain_and_refuses_as_world_at_does() {
    let golden = Golden::build();
    let head = golden.head();

    let case = golden.case_from_genesis("chain-at-genesis");
    let engine = timed_open(&case, "chain_at from genesis");
    chain_at_is(&engine, 0, &CHAIN_GENESIS, "genesis is the seed");
    for op in 1..=GOLDEN_OPS {
        chain_at_is(&engine, golden.seq(op), &golden.txn(op).chain, "from genesis, every boundary");
    }
    assert_eq!(
        engine.kernel().chain_at(Seq(head)).expect("the head"),
        engine.kernel().chain_head(),
        "at the head, chain_at IS chain_head"
    );
    drop(engine);

    let case = golden.case("chain-at-standing");
    let engine = timed_open(&case, "chain_at over the standing base");
    let ckpt_seq = golden.checkpoint_seq();
    let header = checkpoint_chain_head(&ckpt_file(&case, ckpt_seq));
    assert_eq!(header, golden.txn(CHECKPOINT_AFTER_OP).chain, "the header is the marker's at 37");
    chain_at_is(&engine, ckpt_seq, &header, "the base's own seq answers the header");
    chain_at_is(&engine, 0, &CHAIN_GENESIS, "genesis, over the standing base");
    for op in 1..=GOLDEN_OPS {
        chain_at_is(
            &engine,
            golden.seq(op),
            &golden.txn(op).chain,
            "over the standing base, every boundary — below it from genesis, above it from the base",
        );
    }
    assert_eq!(engine.kernel().chain_at(Seq(head)).expect("the head"), engine.kernel().chain_head());

    match engine.kernel().chain_at(Seq(head + 1)) {
        Err(HistoryError::BeyondHead { head: found }) => assert_eq!(found, Seq(head)),
        other => panic!("beyond the head: expected BeyondHead, got {other:?}"),
    }
    let composite = golden.txn(4);
    assert!(composite.first_seq < composite.last_seq, "op 4 is a multi-record composite");
    match engine.kernel().chain_at(Seq(composite.first_seq)) {
        Err(HistoryError::NotABoundary { nearest }) => assert_eq!(nearest, Seq(golden.seq(3))),
        other => panic!("a composite's interior seq: expected NotABoundary, got {other:?}"),
    }

    engine.namespace().register_node(t(&[1, 77])).expect("one commit");
    let new_head = engine.kernel().current_seq();
    let data = fs::read(seg_file(&case, 1)).expect("segment");
    let new = transactions(&data).last().expect("the new marker").clone();
    assert_eq!(new.last_seq, new_head.0);
    chain_at_is(&engine, new_head.0, &new.chain, "after a commit, the new head");
    assert_eq!(engine.kernel().chain_at(new_head).expect("the new head"), engine.kernel().chain_head());
    chain_at_is(&engine, head, &golden.txn(GOLDEN_OPS).chain, "the old head still answers its own");
    drop(engine);

    let in_memory = Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(GOLDEN_SALT_SEED),
    })
    .expect("an in-memory engine");
    assert!(
        matches!(in_memory.kernel().chain_at(Seq(0)), Err(HistoryError::Unjournaled)),
        "no journal, no history: the same refusal as world_at's"
    );
}

/// `Kernel::chain_head()` — piece (c)'s input: the committed head's chain
/// value, read off the root. It is the golden's last marker's chain; a
/// bounded read moves it not at all; a commit moves it to the new marker's,
/// which is the link over the head it had (what a head published before the
/// commit is extended by); a checkpoint off the root names it; a reopen
/// recovers it; and in memory it is the seed at every coordinate, there
/// being no frames to hash.
#[test]
fn chain_head_is_the_committed_heads_marker_chain() {
    let golden = Golden::build();
    let case = golden.case("chain-head");
    let engine = timed_open(&case, "chain_head");
    let golden_head_chain = transactions(&fs::read(golden_segment()).expect("the golden segment"))
        .last()
        .expect("a marker")
        .chain;
    assert_eq!(engine.kernel().chain_head(), golden_head_chain);
    assert_eq!(golden_head_chain, golden.txn(GOLDEN_OPS).chain);
    assert_ne!(golden_head_chain, CHAIN_GENESIS);

    engine.world_at(Seq(2)).expect("a boundary");
    assert_eq!(engine.kernel().chain_head(), golden_head_chain, "a bounded read moves nothing");

    engine.namespace().register_node(t(&[1, 77])).expect("one commit");
    let data = fs::read(seg_file(&case, 1)).expect("segment");
    let txns = transactions(&data);
    let new = txns.last().expect("the new marker");
    assert_eq!(new.last_seq, engine.kernel().current_seq().0);
    assert_eq!(engine.kernel().chain_head(), new.chain);
    assert_eq!(
        new.chain,
        chain_over(&golden_head_chain, &data, new),
        "the link over the head it had"
    );

    let at = engine.kernel().checkpoint().expect("a checkpoint off the root");
    assert_eq!(checkpoint_chain_head(&ckpt_file(&case, at.0)), new.chain);
    drop(engine);
    let engine = timed_open(&case, "chain_head after a reopen");
    assert_eq!(engine.kernel().chain_head(), new.chain);
    drop(engine);

    let in_memory = Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(GOLDEN_SALT_SEED),
    })
    .expect("an in-memory engine");
    assert_eq!(in_memory.kernel().chain_head(), CHAIN_GENESIS);
    in_memory.namespace().register_node(t(&[1, 77])).expect("one in-memory commit");
    assert_eq!(in_memory.kernel().chain_head(), CHAIN_GENESIS, "no frames to hash");
}
