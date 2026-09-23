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
//!   recomputation over its predecessor's, the cause travelling, every file
//!   byte for byte as found (a halt cuts nothing), and the refusal
//!   repeating;
//! * REFUSED — the checkpoint's own refusal (`body_hash`), the fallback
//!   chain then reaching genesis, which re-verifies the journal;
//! * NOT CAUGHT BY DESIGN — a history the chain alone accepts, which the
//!   ruling assigns to piece 2, the PUBLISHED HEAD: a clean tail cut; a
//!   consistent re-chain, from genesis or from any point, the checkpoint's
//!   head rewritten with it; a checkpoint body forged with its hash
//!   re-fixed; a checkpoint AT the head with its chain head edited; and —
//!   pending the owner's reading of "any rewrite", case 12 — damage below a
//!   standing base. Each is asserted as such, and named in `Kernel::open`'s
//!   damage model.
//!
//! Two bases are exercised. With the golden's checkpoint REMOVED the open's
//! base is genesis and every one of the eighteen links is verified, which is
//! where the mid-history cases live; with it STANDING (`checkpoint.37`) the
//! open verifies the two transactions above it, and a `world_at` below it
//! verifies from genesis — which is what cases 9 and 12 turn on.
//!
//! A case the code does not meet at the outcome the ruling requires is a
//! STOP by name, never an assertion loosened to what the code does. None
//! arose; where the coordinate named differs from the brief's expectation
//! (case 2: one transaction later, the marker's own validation speaking
//! before the chain) the test says why and the report carries it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::hazard_util::{
    cfg_manual, ckpt_file, copy_dir, flip_byte, node1, seg_file, t, timed_open,
    timed_open_result, truncate_file, vp, Fixture, GOLDEN_OPS, OWNER, USER,
};
use crate::mutilate::{
    delete_txn, records_checksum, replace_frame_payload, reseal_frame, rewrite_frame,
    rewrite_txn, rollback_segment, swap_txns, transactions, Txn, MARKER_CHAIN_AT,
    MARKER_CHECKSUM_AT, MARKER_EMPTY_LEN, MARKER_LAST_SEQ_AT, MARKER_SIG_ALG_AT,
    MARKER_SIG_LEN_AT, RECORD_BYTES_AT,
};
use sha2::{Digest, Sha256};
use skep_arrangement::Deposit;
use skep_content::Val;
use skep_engine::dump::WorldDump;
use skep_engine::{Engine, EngineError, OpenError};
use skep_kernel::{CheckpointPolicy, Durability, HistoryError, KernelConfig, Seq};
use skep_namespace::{HasM3, BOOTSTRAP_PRINCIPAL};
use tempfile::{tempdir, TempDir};

/// The op after which the golden checkpoints — the golden suite's own
/// constant, restated: `checkpoint.37`, with ops 17 and 18 above it.
const CHECKPOINT_AFTER_OP: usize = 16;

/// The chain's seed — `CHAIN_GENESIS`, restated: the value a journal's first
/// transaction chains from, which the golden's first marker pins. The forger
/// of case 11 starts from it.
const CHAIN_SEED: [u8; 32] = [0u8; 32];

/// The checkpoint header (`SKC3`), restated for the byte-level edits of
/// cases 8, 9 and 11: `[magic 4][seq u64][crc32c(body) u32][body_len u64]
/// [chain_head 32][body_hash 32][body]`.
const CKPT_CRC_AT: usize = 12;
const CKPT_BODY_LEN_AT: usize = 16;
const CKPT_CHAIN_HEAD_AT: usize = 24;
const CKPT_BODY_HASH_AT: usize = 56;
const CKPT_HEADER_LEN: usize = 88;

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

/// CAUGHT: the open halts with a chain break at `at` — the cause travels and
/// names the break, nothing is cut or written, and the refusal repeats.
fn open_halts_with_chain_break(dir: &Path, at: u64, ctx: &str) {
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
        err.to_string().contains("chain break"),
        "FINDING ({ctx}): the account names the break: {err}"
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
    match engine.world_at(Seq(at)) {
        Err(HistoryError::Corruption { at: found, cause }) => {
            assert_eq!(
                found,
                Seq(break_at),
                "FINDING ({ctx}): world_at({at}) names the wrong coordinate"
            );
            let cause = cause.unwrap_or_else(|| {
                panic!("FINDING ({ctx}): a chain break travels with its account")
            });
            assert!(cause.to_string().contains("chain break"), "FINDING ({ctx}): {cause}");
        }
        Err(other) => panic!("FINDING ({ctx}): world_at({at}) refused for another reason: {other}"),
        Ok(_) => panic!("FINDING ({ctx}): world_at({at}) ANSWERED over a rewrite the chain must catch"),
    }
}

/// One link of the chain, recomputed exactly as the writer states it —
/// SHA-256 over the predecessor's value, the record payloads as framed, then
/// `txn`, `last_seq` and `records_checksum` in their wire form. Restated
/// here so the forger of case 11 is held to the writer's own formula: were
/// the two to drift, the forgery would be CAUGHT and that case would fail
/// loudly rather than pass. The sanity check at its head pins them equal
/// over the untouched golden.
fn chain_over(prev: &[u8; 32], data: &[u8], txn: &Txn) -> [u8; 32] {
    let mut link = Sha256::new().chain_update(prev);
    for record in &txn.records {
        link.update(&data[record.payload.clone()]);
    }
    link.chain_update(txn.txn.to_le_bytes())
        .chain_update(txn.last_seq.to_le_bytes())
        .chain_update(records_checksum(data, txn).to_le_bytes())
        .finalize()
        .into()
}

/// Flip a byte of one of a transaction's RECORD payloads, inside the
/// record's own bytes.
fn flip_record_byte(data: &mut [u8], txn: &Txn, record: usize, offset: usize) {
    let at = txn.records[record].payload.start + RECORD_BYTES_AT + offset;
    assert!(at < txn.records[record].payload.end, "the byte lies inside the record");
    data[at] ^= 0xFF;
}

/// Rewrite the checkpoint's body through `edit` and re-fix the header's CRC
/// over it — `body_hash` left as it was.
fn rewrite_checkpoint_body(path: &Path, edit: impl FnOnce(&mut [u8])) {
    let mut data = fs::read(path).expect("read the checkpoint");
    edit(&mut data[CKPT_HEADER_LEN..]);
    let crc = crc32c::crc32c(&data[CKPT_HEADER_LEN..]);
    data[CKPT_CRC_AT..CKPT_BODY_LEN_AT].copy_from_slice(&crc.to_le_bytes());
    fs::write(path, data).expect("write the checkpoint");
}

/// Write `head` into the checkpoint's `chain_head` — nothing else in the
/// header covers it, so nothing else moves.
fn set_checkpoint_chain_head(path: &Path, head: &[u8; 32]) {
    let mut data = fs::read(path).expect("read the checkpoint");
    data[CKPT_CHAIN_HEAD_AT..CKPT_BODY_HASH_AT].copy_from_slice(head);
    fs::write(path, data).expect("write the checkpoint");
}

fn checkpoint_chain_head(path: &Path) -> [u8; 32] {
    fs::read(path).expect("read the checkpoint")[CKPT_CHAIN_HEAD_AT..CKPT_BODY_HASH_AT]
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
/// payloads — with `replacement` of the same length, re-chain every link
/// from that transaction to the end, and deal with the golden's checkpoint
/// as `checkpoint` says. Answers the re-chained links by boundary.
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
    // value as the golden wrote it — the seed itself for the first.
    let mut prev = if op == 1 { CHAIN_SEED } else { golden.txn(op - 1).chain };
    let mut data = fs::read(&seg).expect("segment");
    let txns = transactions(&data);
    let mut chains = Vec::new();
    for txn in &txns[op - 1..] {
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
/// the chain — then refuses to close the group: the transaction UN-COMMITS,
/// and the chain names the NEXT committed transaction, the first whose link
/// fails, since what it follows in the file is no longer what it was chained
/// from. Caught either way; the coordinate differs.
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
    open_halts_with_chain_break(
        &case,
        golden.seq(OP + 1),
        "case 1, the weaker rewrite: the frame CRC re-fixed, records_checksum stale — the \
         transaction un-commits and the next is the first link that fails",
    );
}

/// CASE 2 — A MARKER'S `records_checksum` OR `last_seq` EDITED, CRC RE-FIXED. Both
/// are chain inputs — but they are the marker's OWN validation first, older
/// than the chain: a marker whose checksum or `last_seq` does not close its
/// group commits nothing, so the edited transaction UN-COMMITS before the
/// chain sees it, and the chain names the NEXT committed transaction — the
/// first whose link fails, chaining as it does from a predecessor the scan
/// never committed. CAUGHT, one transaction after the edit: the brief's "at
/// that transaction" holds for these two fields only when the records are
/// rewritten to match them, which is case 1.
///
/// On the LAST transaction the same edit is a tail cut in disguise: the
/// un-committed marker is the torn tail, recovery cuts it and opens one
/// transaction short — case 10's limit, the published head's to see.
#[test]
fn c02_a_markers_checksum_or_last_seq_edited_uncommits_it_and_breaks_at_the_next() {
    let golden = Golden::build();
    const OP: usize = 9;
    for (field, at) in [("records_checksum", MARKER_CHECKSUM_AT), ("last_seq", MARKER_LAST_SEQ_AT)] {
        let case = golden.case_from_genesis(&format!("c02-{field}"));
        rewrite_frame(&seg_file(&case, 1), golden.txn(OP).marker.start, |payload| {
            payload[at] ^= 0xFF
        });
        open_halts_with_chain_break(
            &case,
            golden.seq(OP + 1),
            &format!(
                "case 2: the marker's {field} edited, its CRC re-fixed — the marker no longer \
                 closes its group, the transaction un-commits, and the next is the first link \
                 that fails"
            ),
        );
    }

    let case = golden.case("c02-last");
    let seg = seg_file(&case, 1);
    rewrite_frame(&seg, golden.txn(GOLDEN_OPS).marker.start, |payload| {
        payload[MARKER_CHECKSUM_AT] ^= 0xFF
    });
    let engine = open_recovers(
        &case,
        &golden,
        golden.seq(GOLDEN_OPS - 1),
        "case 2 on the last transaction: a tail cut in disguise",
    );
    drop(engine);
    assert_eq!(
        fs::metadata(&seg).expect("segment").len(),
        golden.txn(GOLDEN_OPS - 1).bytes.end as u64,
        "the un-committed last transaction was the torn tail, and recovery cut it"
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
/// reach: the exhausted chain's account is the hash's refusal, the checksum
/// having passed.
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
        panic!("expected an exhausted chain carrying the newest refusal's account, got {err:?}")
    };
    let cause = cause.to_string();
    assert!(
        cause.contains("hash") && !cause.contains("checksum"),
        "the hash refused and the checksum passed: {cause}"
    );

    let other = Fixture::build_golden(&golden.tmp.path().join("other"), &[CHECKPOINT_AFTER_OP - 1]);
    let other_seq = other.boundaries[CHECKPOINT_AFTER_OP - 2].seq;
    let body =
        fs::read(ckpt_file(&other.dir, other_seq)).expect("the other checkpoint")[CKPT_HEADER_LEN..]
            .to_vec();
    let case = golden.case("c08-forged");
    let ckpt = ckpt_file(&case, ckpt_seq);
    let mut data = fs::read(&ckpt).expect("the checkpoint");
    data.truncate(CKPT_HEADER_LEN);
    data[CKPT_CRC_AT..CKPT_BODY_LEN_AT].copy_from_slice(&crc32c::crc32c(&body).to_le_bytes());
    data[CKPT_BODY_LEN_AT..CKPT_CHAIN_HEAD_AT].copy_from_slice(&(body.len() as u64).to_le_bytes());
    data[CKPT_BODY_HASH_AT..CKPT_HEADER_LEN]
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
/// consistent — which they are: nothing in the `SKC3` header covers that
/// field. So the code does not REFUSE — the base LOADS carrying the edited
/// value — and the open is CAUGHT at the first transaction above the base,
/// whose link fails against it.
///
/// NOT CAUGHT BY DESIGN — the checkpoint AT THE HEAD: nothing above the
/// base, no link to fail. The open succeeds, the root carries the edited
/// value, `chain_head()` reports it, and the next commit chains from it: a
/// fork the chain alone accepts, and the published head's to see (a peer
/// holding the head as it was finds the new history does not extend it).
#[test]
fn c09_a_checkpoints_chain_head_edited_breaks_at_the_first_transaction_above_it() {
    let golden = Golden::build();

    let case = golden.case("c09");
    flip_byte(&ckpt_file(&case, golden.checkpoint_seq()), (CKPT_CHAIN_HEAD_AT + 3) as u64);
    open_halts_with_chain_break(
        &case,
        golden.seq(CHECKPOINT_AFTER_OP + 1),
        "case 9: the checkpoint's chain_head edited",
    );

    let at_head = Fixture::build_golden(&golden.tmp.path().join("at-head"), &[GOLDEN_OPS]);
    let head = at_head.last_seq();
    let edited = [0xE7u8; 32];
    set_checkpoint_chain_head(&ckpt_file(&at_head.dir, head), &edited);
    let engine = timed_open(&at_head.dir, "case 9: a head checkpoint's chain_head edited");
    assert_eq!(engine.kernel().current_seq(), Seq(head));
    assert_eq!(&engine.world_dump(), at_head.dump_for(head));
    assert_eq!(engine.kernel().chain_head(), edited, "the root carries the edited value");
    engine.namespace().register_node(t(&[1, 77])).expect("one commit after the fork");
    let data = fs::read(seg_file(&at_head.dir, 1)).expect("segment");
    let txns = transactions(&data);
    let new = txns.last().expect("the new transaction");
    assert_eq!(
        new.chain,
        chain_over(&edited, &data, new),
        "the next commit chained from the edited value"
    );
    assert_eq!(engine.kernel().chain_head(), new.chain);
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
/// but its seed and the base's header. The world served is the forger's, at
/// every boundary from the forgery on; the head's chain is not the golden's
/// — which is exactly what a published head would show, and all it could.
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
        let mut prev = CHAIN_SEED;
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
    //     the golden wrote it fails its first link above the base — case 9's
    //     door, which a forger who can write the checkpoint file closes with
    //     one more write, as (a) did.
    let case = golden.case("c11-checkpoint-kept");
    forge_and_rechain(&golden, &case, 4, A, FORGED, CheckpointAfterForgery::Kept);
    open_halts_with_chain_break(
        &case,
        golden.seq(CHECKPOINT_AFTER_OP + 1),
        "case 11 with the checkpoint's head kept as the golden wrote it",
    );
}

/// CASE 12 — DAMAGE BELOW A STANDING CHECKPOINT BASE — a consistent rewrite in the
/// segment the base already covers, the segment still present. What the
/// code does today, "verified for transactions above the base only": the
/// base embodies the rewritten transaction, the scan verifies the two links
/// above it, and the open recovers the whole history at the true head with
/// the golden's world — NOT CAUGHT while the base stands, and once
/// reclamation drops the segment, beyond any replay. A bounded read BELOW
/// the base selects genesis and verifies every link, and is caught at the
/// rewritten transaction whether the boundary asked lies above it or below
/// it. Pinned as the code's reading pending the owner's; the report carries
/// both readings of the ruling's "any rewrite".
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
    let last = transactions(&fs::read(golden_segment()).expect("the golden segment"))
        .last()
        .expect("a marker")
        .chain;
    assert_eq!(engine.kernel().chain_head(), last);
    assert_eq!(last, golden.txn(GOLDEN_OPS).chain);
    assert_ne!(last, CHAIN_SEED);

    engine.world_at(Seq(2)).expect("a boundary");
    assert_eq!(engine.kernel().chain_head(), last, "a bounded read moves nothing");

    engine.namespace().register_node(t(&[1, 77])).expect("one commit");
    let data = fs::read(seg_file(&case, 1)).expect("segment");
    let txns = transactions(&data);
    let new = txns.last().expect("the new marker");
    assert_eq!(new.last_seq, engine.kernel().current_seq().0);
    assert_eq!(engine.kernel().chain_head(), new.chain);
    assert_eq!(new.chain, chain_over(&last, &data, new), "the link over the head it had");

    let at = engine.kernel().checkpoint().expect("a checkpoint off the root");
    assert_eq!(checkpoint_chain_head(&ckpt_file(&case, at.0)), new.chain);
    drop(engine);
    let engine = timed_open(&case, "chain_head after a reopen");
    assert_eq!(engine.kernel().chain_head(), new.chain);
    drop(engine);

    let mem = Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    })
    .expect("an in-memory engine");
    assert_eq!(mem.kernel().chain_head(), CHAIN_SEED);
    mem.namespace().register_node(t(&[1, 77])).expect("one in-memory commit");
    assert_eq!(mem.kernel().chain_head(), CHAIN_SEED, "no frames to hash");
}
