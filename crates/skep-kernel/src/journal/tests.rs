use super::segment::inferred_last_seq;
use super::*;
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::tempdir;

/// A record's bytes as the commit path produces them, so a fixture cannot
/// drift from the wire form the real writer uses.
pub(super) fn rec(x: u64) -> Vec<u8> {
    encode_record(&x).unwrap()
}

/// The seeded salt source these fixtures write under: deterministic, so
/// a fixture's bytes are the same on every run, and named once.
pub(super) const TEST_SEED: u64 = 0x5A17;

/// A fixed salt for the frame builder's direct callers, where the source
/// is not under test and a value with a shape beats zeros.
pub(super) const FIXED_SALT: [u8; 32] = [0xA5; 32];

/// A fresh appender at genesis: the chain seeded where a new journal's is,
/// the salts from the seeded stream.
pub(super) fn fresh_writer(dir: &Path) -> JournalWriter {
    JournalWriter::open_active(dir, 1, CHAIN_GENESIS, SaltSource::Seeded(TEST_SEED)).unwrap()
}

/// An unsigned marker whose chain is NOT under test — the fixtures that
/// hand-build a marker build one that never commits, or one with no
/// group, so the chain it carries is never read — and whose salt is
/// likewise never hashed against anything.
pub(super) fn marker(txn: Txn, last_seq: u64, records_checksum: u32) -> Marker {
    Marker {
        txn,
        last_seq,
        records_checksum,
        salt: [0u8; 32],
        chain: [0u8; 32],
        sig_alg: SIG_ALG_UNSIGNED,
        sig: Vec::new(),
    }
}

/// The committed marker closing the frame at `pos`, decoded whole.
pub(super) fn marker_at(path: &Path, pos: usize) -> Marker {
    let buf = fs::read(path).unwrap();
    let Parsed::Intact { payload } = parse_frame(&buf, pos) else {
        panic!("intact marker frame expected at {pos}")
    };
    match codec().deserialize::<FramePayload>(&buf[payload]).unwrap() {
        FramePayload::Marker(m) => m,
        FramePayload::Record(_) => panic!("a marker frame expected at {pos}"),
    }
}

/// The `chain` field of the committed marker closing the frame at `pos`.
pub(super) fn chain_of_marker_at(path: &Path, pos: usize) -> [u8; 32] {
    marker_at(path, pos).chain
}

/// Byte offset of each frame in a CLEAN journal file, via the real parser
/// — which is what a fixture aims damage with.
pub(super) fn frame_starts(path: &Path) -> Vec<usize> {
    let buf = fs::read(path).unwrap();
    let mut starts = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        match parse_frame(&buf, pos) {
            Parsed::Intact { payload } => {
                starts.push(pos);
                pos = payload.end;
            }
            Parsed::Bad { .. } => panic!("clean journal expected"),
        }
    }
    starts
}

#[test]
fn frame_roundtrip_and_a_corrupt_length_is_detected() {
    let payload = b"hello frame".to_vec();
    let mut buf = Vec::new();
    push_frame(&mut buf, &payload).unwrap();
    match parse_frame(&buf, 0) {
        Parsed::Intact { payload: p } => {
            // The frame's end IS its payload's end, and the whole frame is
            // the header plus that payload.
            assert_eq!(p.end, buf.len());
            assert_eq!(&buf[p], payload.as_slice());
        }
        Parsed::Bad { .. } => panic!("intact frame expected"),
    }
    // A flipped payload byte fails the frame crc.
    let mut bad = buf.clone();
    bad[FRAME_HEADER_LEN + 2] ^= 0xFF;
    assert!(matches!(parse_frame(&bad, 0), Parsed::Bad { .. }));
    // A corrupt len is DETECTED, not silently mis-delimiting the frame
    // that follows (§1) — the length that OVERRUNS the buffer, which the
    // bounds check refuses before any crc is computed…
    let mut bad_len = buf.clone();
    bad_len[5] ^= 0xFF;
    assert!(matches!(parse_frame(&bad_len, 0), Parsed::Bad { crc_bytes: 0 }));
    // …and the one that FITS, where nothing but the crc can reject it: a
    // reader trusting this length would take a 5-byte payload and resume
    // mid-frame. `crc_bytes` names which door refused it.
    let mut short_len = buf;
    short_len[4..8].copy_from_slice(&5u32.to_le_bytes());
    assert!(matches!(parse_frame(&short_len, 0), Parsed::Bad { crc_bytes: 5 }));
}

#[test]
fn push_frame_refuses_a_payload_past_the_frame_cap() {
    // The writer's half of the cap the reader relies on: a claimed `len`
    // above MAX_FRAME_LEN is corrupt precisely because nothing here can
    // write one (§1).
    let mut buf = Vec::new();
    let over = vec![0u8; MAX_FRAME_LEN as usize + 1];
    let e = push_frame(&mut buf, &over).expect_err("an oversize payload is refused");
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    assert!(buf.is_empty(), "a refused frame appends nothing");
    // And the frame cap itself is writable: the refusal begins one past
    // it, not at it.
    push_frame(&mut buf, &over[..MAX_FRAME_LEN as usize]).unwrap();
    assert!(matches!(parse_frame(&buf, 0), Parsed::Intact { .. }));
}

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
    let attest = Attestation::new(1, vec![0xA5; 3_373]).unwrap();
    let body = (MAX_TXN_BYTES - txn_encoded_len(&[Vec::new()], None)) as usize - prefix;
    let at_budget = vec![vec![0u8; body]];
    assert!(journal.commit_txn(1, at_budget, Some(&attest), |_| installs += 1).is_ok());
    assert_eq!(installs, 1);
    let past_budget = vec![vec![0u8; body + 1]];
    match journal.commit_txn(1, past_budget, Some(&attest), |_| installs += 1) {
        Err(CommitFail::OverBudget { bytes }) => assert_eq!(bytes, MAX_TXN_BYTES + 1),
        other => panic!("expected OverBudget, got {other:?}"),
    }
    assert_eq!(installs, 1);
}

/// The attestation's two refused spellings, held at construction: tag 0
/// (the empty slot's own) and an empty blob — so no transaction can write
/// the marker the decoder refuses, and "unsigned" is spelled only by the
/// absent value.
#[test]
fn an_attestation_holds_the_one_spelling_of_empty_at_construction() {
    assert_eq!(Attestation::new(0, vec![1]), Err(AttestationError::UnsignedTag));
    assert_eq!(Attestation::new(1, Vec::new()), Err(AttestationError::EmptyBlob));
    let a = Attestation::new(3, vec![7, 7]).unwrap();
    assert_eq!((a.sig_alg(), a.sig()), (3, &[7u8, 7][..]));
    assert_eq!(format!("{a:?}"), "Attestation { sig_alg: 3, sig_len: 2 }");
}

/// A FILLED marker's bytes are the empty layout with the tag and the blob
/// in the slot's own place — the tag at byte 88, the length prefix at
/// 89..97, the blob after — and no other marker byte moves: the layout
/// doc's claim, pinned against the encoder's own output.
#[test]
fn a_filled_marker_appends_the_blob_after_the_tag_and_moves_no_other_byte() {
    let blob = vec![0xC3u8; 5];
    let attest = Attestation::new(1, blob.clone()).unwrap();
    let records = vec![vec![9u8, 8, 7]];
    let (empty, chain_e) =
        encode_txn(2, records.clone(), &CHAIN_GENESIS, FIXED_SALT, None).unwrap();
    let (filled, chain_f) =
        encode_txn(2, records, &CHAIN_GENESIS, FIXED_SALT, Some(&attest)).unwrap();
    assert_eq!(chain_e, chain_f, "the slot is no chain input");
    let marker_of = |buf: &[u8]| -> Vec<u8> {
        let Parsed::Intact { payload: first } = parse_frame(buf, 0) else {
            panic!("record frame")
        };
        let Parsed::Intact { payload } = parse_frame(buf, first.end) else {
            panic!("marker frame")
        };
        buf[payload].to_vec()
    };
    let (e, f) = (marker_of(&empty), marker_of(&filled));
    assert_eq!(e.len(), 97);
    assert_eq!(f.len(), 97 + blob.len());
    assert_eq!(&f[..88], &e[..88], "every byte before the slot is unmoved");
    assert_eq!(f[88], 1, "the tag");
    assert_eq!(&f[89..97], &(blob.len() as u64).to_le_bytes(), "the blob's length prefix");
    assert_eq!(&f[97..], &blob[..], "the blob, whole");
    assert_eq!(e[88], SIG_ALG_UNSIGNED);
    assert_eq!(&e[89..97], &0u64.to_le_bytes());
    // …and the reader hands it back through the decoder's own door.
    let decoded = codec().deserialize::<FramePayload>(&f).unwrap();
    let FramePayload::Marker(m) = decoded else { panic!("a marker") };
    assert_eq!((m.sig_alg, m.sig), (1, blob));
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
    let mut memory = Journal::InMemory;

    // The encode: a record the serializer refuses, in the mode that would
    // otherwise never encode anything.
    let out = memory.commit_txn(1, vec![RefusesSerialization], None, |_| installed = true);
    assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");

    // The frame cap, which is a property of frames this arm never builds.
    let prefix = encode_record(&Vec::<u8>::new()).unwrap().len();
    let cap_bytes = (MAX_FRAME_LEN as u64 - RECORD_PAYLOAD_OVERHEAD) as usize;
    let over_frame = vec![vec![0u8; cap_bytes + 1 - prefix]];
    let out = memory.commit_txn(1, over_frame, None, |_| installed = true);
    assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");

    // The transaction budget, likewise.
    let half = (MAX_TXN_BYTES / 2) as usize;
    let over_budget = vec![vec![0u8; half], vec![0u8; half]];
    let out = memory.commit_txn(1, over_budget, None, |_| installed = true);
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
fn frame_payloads_spend_a_bare_u64_on_the_txn_and_carry_the_documented_chain() {
    // The on-disk payload layout (§1), spelled out: bincode fixint LE —
    // the variant index as a `u32`, then the fields in declaration order,
    // with a [`Txn`] occupying exactly the `u64` it wraps. A journal
    // written by one build is read by the next, so the layout is pinned
    // here rather than left to whatever the derives happen to produce —
    // the marker's chain included, computed here by hand from the bytes
    // `ChainLink` says it covers — the salt last — so the formula is
    // pinned beside the layout and not only by the golden fixture.
    let (buf, chain) = encode_txn(2, vec![vec![9u8, 8, 7]], &CHAIN_GENESIS, FIXED_SALT, None).unwrap();

    let mut expected_record = Vec::new();
    expected_record.extend_from_slice(&0u32.to_le_bytes()); // FramePayload::Record
    expected_record.extend_from_slice(&2u64.to_le_bytes()); // seq
    expected_record.extend_from_slice(&2u64.to_le_bytes()); // txn == the first seq
    expected_record.extend_from_slice(&3u64.to_le_bytes()); // bytes.len()
    expected_record.extend_from_slice(&[9, 8, 7]);
    let Parsed::Intact { payload } = parse_frame(&buf, 0) else {
        panic!("intact record frame expected")
    };
    let end = payload.end; // where the marker frame begins
    assert_eq!(&buf[payload], expected_record.as_slice());

    // records_checksum: over the record frames' payloads, in Seq order.
    let records_checksum = crc32c::crc32c_append(0, &expected_record);
    // The chain: SHA-256 over the genesis seed, the record payload as
    // framed, the marker's own pre-chain fields in their wire form, then
    // the salt — the last bytes before finalize.
    let expected_chain: [u8; 32] = Sha256::new()
        .chain_update(CHAIN_GENESIS)
        .chain_update(&expected_record)
        .chain_update(2u64.to_le_bytes()) // txn
        .chain_update(2u64.to_le_bytes()) // last_seq
        .chain_update(records_checksum.to_le_bytes())
        .chain_update(FIXED_SALT) // salt
        .finalize()
        .into();
    assert_eq!(chain, expected_chain, "the writer answers the chain it framed");
    // …and a link closed WITHOUT the salt is not this chain: the salt is
    // hashed, not merely stored.
    let unsalted: [u8; 32] = Sha256::new()
        .chain_update(CHAIN_GENESIS)
        .chain_update(&expected_record)
        .chain_update(2u64.to_le_bytes())
        .chain_update(2u64.to_le_bytes())
        .chain_update(records_checksum.to_le_bytes())
        .finalize()
        .into();
    assert_ne!(chain, unsalted, "the salt is a chain input");

    let mut expected_marker = Vec::new();
    expected_marker.extend_from_slice(&1u32.to_le_bytes()); // FramePayload::Marker
    expected_marker.extend_from_slice(&2u64.to_le_bytes()); // txn
    expected_marker.extend_from_slice(&2u64.to_le_bytes()); // last_seq
    expected_marker.extend_from_slice(&records_checksum.to_le_bytes());
    expected_marker.extend_from_slice(&FIXED_SALT); // salt: a 32-tuple, no prefix
    expected_marker.extend_from_slice(&expected_chain); // chain: likewise
    expected_marker.push(SIG_ALG_UNSIGNED); // sig_alg
    expected_marker.extend_from_slice(&0u64.to_le_bytes()); // sig: empty, its length alone
    assert_eq!(expected_marker.len(), 97, "the empty marker payload");
    let Parsed::Intact { payload } = parse_frame(&buf, end) else {
        panic!("intact marker frame expected")
    };
    assert_eq!(&buf[payload], expected_marker.as_slice());
}

#[test]
fn the_marker_decoder_admits_one_spelling_of_empty() {
    // The slot's rule, held at the decode door: tag 0 with no bytes is
    // EMPTY, the one spelling; tag 0 with bytes (a signature under no
    // pair) and a non-zero tag with none (a pair that signed nothing) are
    // refused, so no two readers can disagree about whether a marker is
    // signed. A filled slot under a non-zero tag DECODES — the kernel
    // never interprets the blob — and rejecting trailing bytes is what
    // keeps the length prefix the whole of the slot's extent.
    let honest = codec()
        .serialize(&FramePayload::Marker(marker(Txn(3), 3, 0)))
        .unwrap();
    assert!(codec().deserialize::<FramePayload>(&honest).is_ok());
    // Layout: tag 4 | txn 8 | last_seq 8 | checksum 4 | salt 32 | chain 32 | sig_alg @88 | len @89..97.
    let with = |sig_alg: u8, sig: &[u8]| {
        let mut bytes = honest[..88].to_vec();
        bytes.push(sig_alg);
        bytes.extend_from_slice(&(sig.len() as u64).to_le_bytes());
        bytes.extend_from_slice(sig);
        bytes
    };
    let refused = |bytes: &[u8]| {
        codec()
            .deserialize::<FramePayload>(bytes)
            .err()
            .map(|e| e.to_string())
            .expect("refused")
    };
    assert!(refused(&with(0, &[0xAA])).contains("one spelling of empty"));
    assert!(refused(&with(1, &[])).contains("one spelling of empty"));
    assert!(codec().deserialize::<FramePayload>(&with(1, &[0xAA, 0xBB])).is_ok());
    // Trailing bytes past the slot are not a longer slot: refused.
    let mut trailing = with(0, &[]);
    trailing.push(0);
    assert!(codec().deserialize::<FramePayload>(&trailing).is_err());
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

#[test]
fn only_the_name_the_writer_emits_is_a_segment() {
    // `seg-01.wal` and `seg-+7.wal` parse as 1 and 7 under a bare
    // `u64::from_str`, so without the round trip they alias live segments'
    // `firstSeq`s. Two entries at one coordinate sort adjacent, which
    // makes the first one's inferred `lastSeq` 0 — and `reclaim_below`
    // deletes every segment whose inference is at or below the floor.
    let dir = tempdir().unwrap();
    fs::write(segment_path(dir.path(), 1), b"").unwrap();
    fs::write(dir.path().join("seg-01.wal"), b"").unwrap();
    fs::write(dir.path().join("seg-+7.wal"), b"").unwrap();
    fs::write(dir.path().join("seg-0007.wal"), b"").unwrap();
    let segs = list_segments(dir.path()).unwrap();
    assert_eq!(segs.len(), 1, "only one spelling names a segment");
    assert_eq!(segs[0].first_seq, 1);
    assert_eq!(segs[0].path, segment_path(dir.path(), 1));
    // The active segment is never range-reclaimed, and it is the only one
    // here — so nothing is deleted, where an aliased name would have made
    // the real `seg-1.wal` a closed segment covering nothing.
    reclaim_below(dir.path(), 100).unwrap();
    assert!(segment_path(dir.path(), 1).exists(), "a live segment was reclaimed");
}

#[test]
fn segments_list_in_first_seq_order_across_a_digit_boundary() {
    // A closed segment's reach is read off its SUCCESSOR's name; the scan
    // skips on that inference and `reclaim_below` deletes on it. Name
    // order and `firstSeq` order agree while names have one digit — and
    // `seg-10.wal` sorts BEFORE `seg-9.wal` by name.
    let dir = tempdir().unwrap();
    for first_seq in [10, 1, 100, 9] {
        fs::write(segment_path(dir.path(), first_seq), b"").unwrap();
    }
    let segs = list_segments(dir.path()).unwrap();
    let firsts: Vec<u64> = segs.iter().map(|seg| seg.first_seq).collect();
    assert_eq!(firsts, vec![1, 9, 10, 100]);
    assert_eq!(
        inferred_last_seq(&segs, 1),
        Some(9),
        "seg-9 ends where seg-10 begins"
    );
    // …and reclamation takes exactly the closed prefix that inference
    // admits.
    reclaim_below(dir.path(), 9).unwrap();
    let left: Vec<u64> = list_segments(dir.path())
        .unwrap()
        .iter()
        .map(|seg| seg.first_seq)
        .collect();
    assert_eq!(left, vec![10, 100]);
}
