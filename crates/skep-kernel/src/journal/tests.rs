use super::*;
use tempfile::tempdir;

/// A record's bytes as the commit path produces them, so a fixture cannot
/// drift from the wire form the real writer uses.
fn rec(x: u64) -> Vec<u8> {
    encode_record(&x).unwrap()
}

/// A fixture commit. These journals stand alone — there is no root to
/// install into — so the install step is empty.
fn write_txn(writer: &mut JournalWriter, first: u64, record_bytes: Vec<Vec<u8>>) {
    writer
        .commit_txn(first, record_bytes, None, |_| {})
        .expect("fixture commit");
}

/// The seeded salt source these fixtures write under: deterministic, so
/// a fixture's bytes are the same on every run, and named once.
const TEST_SEED: u64 = 0x5A17;

/// A fixed salt for the frame builder's direct callers, where the source
/// is not under test and a value with a shape beats zeros.
const FIXED_SALT: [u8; 32] = [0xA5; 32];

/// A fresh appender at genesis: the chain seeded where a new journal's is,
/// the salts from the seeded stream.
fn fresh_writer(dir: &Path) -> JournalWriter {
    JournalWriter::open_active(dir, 1, CHAIN_GENESIS, SaltSource::Seeded(TEST_SEED)).unwrap()
}

/// An unsigned marker whose chain is NOT under test — the fixtures that
/// hand-build a marker build one that never commits, or one with no
/// group, so the chain it carries is never read — and whose salt is
/// likewise never hashed against anything.
fn marker(txn: Txn, last_seq: u64, records_checksum: u32) -> Marker {
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
fn marker_at(path: &Path, pos: usize) -> Marker {
    let buf = fs::read(path).unwrap();
    let Parsed::Intact { payload } = parse_frame(&buf, pos) else {
        panic!("intact marker frame expected at {pos}")
    };
    match codec().deserialize::<FramePayload>(&buf[payload]).unwrap() {
        FramePayload::Marker(m) => m,
        FramePayload::Record(_) => panic!("a marker frame expected at {pos}"),
    }
}

/// Every marker of a CLEAN journal file, in file order.
fn markers_in(path: &Path) -> Vec<Marker> {
    let buf = fs::read(path).unwrap();
    frame_starts(path)
        .into_iter()
        .filter_map(|pos| {
            let Parsed::Intact { payload } = parse_frame(&buf, pos) else {
                panic!("clean journal expected")
            };
            match codec().deserialize::<FramePayload>(&buf[payload]).unwrap() {
                FramePayload::Marker(m) => Some(m),
                FramePayload::Record(_) => None,
            }
        })
        .collect()
}

/// The `chain` field of the committed marker closing the frame at `pos`.
fn chain_of_marker_at(path: &Path, pos: usize) -> [u8; 32] {
    marker_at(path, pos).chain
}

/// Rewrite the payload of the intact frame at `pos` through `edit` and
/// RE-SEAL its CRC, so the frame stays intact: what a consistent rewrite
/// looks like — the thing the chain exists to catch and the CRC cannot.
fn rewrite_payload(path: &Path, pos: usize, edit: impl FnOnce(&mut [u8])) {
    let mut data = fs::read(path).unwrap();
    let Parsed::Intact { payload } = parse_frame(&data, pos) else {
        panic!("intact frame expected at {pos}")
    };
    edit(&mut data[payload.clone()]);
    let crc = crc32c::crc32c_append(crc32c::crc32c(&data[pos + 4..pos + 8]), &data[payload]);
    data[pos + 8..pos + 12].copy_from_slice(&crc.to_le_bytes());
    fs::write(path, data).unwrap();
}

/// Byte offset of each frame in a CLEAN journal file, via the real parser
/// — which is what a fixture aims damage with.
fn frame_starts(path: &Path) -> Vec<usize> {
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

fn flip_byte(path: &Path, offset: usize) {
    let mut data = fs::read(path).unwrap();
    data[offset] ^= 0xFF;
    fs::write(path, data).unwrap();
}

fn committed_seqs(out: &ScanOutcome) -> Vec<u64> {
    let mut s: Vec<u64> = out.committed_records.iter().map(|r| r.seq).collect();
    s.sort_unstable();
    s
}

/// The coordinates `records_to` hands a fold, in the order it hands them —
/// so an assertion reads as the sequence of applications it stands for.
fn folded_seqs(out: &ScanOutcome, bound: u64) -> Result<Vec<u64>, u64> {
    out.records_to(bound)
        .map(|records| records.iter().map(|entry| entry.seq).collect())
}

/// The scan aims truncation at `segment` @ `offset`, with nothing later to
/// discard (these fixtures hold one segment).
fn assert_tail(out: &ScanOutcome, segment: &Path, offset: u64) {
    let tail = out.tail.as_ref().expect("a scanned region has a cut");
    assert_eq!(tail.segment, segment);
    assert_eq!(tail.offset, offset);
    assert!(tail.discard.is_empty());
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

#[test]
fn txn_size_accounting_matches_the_encoder_to_the_byte() {
    // The accounting stands in for building the frames, so it must match
    // the encoder exactly — pinned at extreme field values, so a codec
    // change toward value-dependent widths breaks here, not the two
    // limits this accounting feeds.
    for record_bytes in [
        vec![vec![5u8; 3]],
        vec![rec(u64::MAX), vec![7u8; 300], Vec::new()],
    ] {
        let expected = txn_encoded_len(&record_bytes, None);
        let (buf, _) =
            encode_txn(u64::MAX - 3, record_bytes, &CHAIN_GENESIS, FIXED_SALT, None).unwrap();
        assert_eq!(buf.len() as u64, expected);
    }
    // The marker half, stated as the figures the layout doc promises: a
    // 97-byte payload with the slot empty (`SKJ4`: the salt's thirty-two
    // after `SKJ3`'s sixty-five), a 109-byte frame.
    let empty_marker = codec()
        .serialize(&FramePayload::Marker(marker(Txn(u64::MAX), u64::MAX, u32::MAX)))
        .unwrap();
    assert_eq!(empty_marker.len(), 97);
    assert_eq!(MARKER_FRAME_LEN, 109);
    assert_eq!(MARKER_FRAME_LEN, frame_len(empty_marker.len() as u64));
    // THE FILLED SLOT (signed ops): the accounting gains the blob's own
    // width and nothing else — the marker frame is the empty pin plus
    // the blob, the records' frames untouched — pinned at tag 1's ruled
    // width (3,373 B: ML-DSA-65's 3,309 ‖ Ed25519's 64) and at a
    // one-byte blob. The BUDGET side does not gain it, which
    // `a_filled_slot_is_outside_the_transaction_budget` pins.
    for (tag, width) in [(1u8, 3_373usize), (3u8, 730usize), (9u8, 1usize)] {
        let attest = Attestation::new(tag, vec![0xA5; width]).unwrap();
        let record_bytes = vec![rec(u64::MAX), vec![7u8; 300]];
        let expected = txn_encoded_len(&record_bytes, Some(&attest));
        assert_eq!(
            expected,
            txn_encoded_len(&record_bytes, None) + width as u64,
            "a filled slot costs its blob's width and nothing else"
        );
        let (buf, _) =
            encode_txn(u64::MAX - 3, record_bytes, &CHAIN_GENESIS, FIXED_SALT, Some(&attest))
                .unwrap();
        assert_eq!(buf.len() as u64, expected, "tag {tag}, a {width}-byte blob");
    }
    // The per-record half: what push_frame judges is the wrapped payload,
    // the record's own bytes plus RECORD_PAYLOAD_OVERHEAD exactly.
    let payload = codec()
        .serialize(&FramePayload::Record(LogRecord {
            seq: u64::MAX,
            txn: Txn(u64::MAX),
            bytes: vec![1, 2, 3],
        }))
        .unwrap();
    assert_eq!(payload.len() as u64, 3 + RECORD_PAYLOAD_OVERHEAD);

    // …and the READER charges a framed payload to the same figure, which
    // is what lets it enforce the write path's budget without a second
    // accounting: a transaction the writer emits AT the budget accounts to
    // the budget on the way back in, so recovery cannot refuse a
    // transaction this kernel acked.
    let mut group = PendingTxn::open(Txn(u64::MAX), &CHAIN_GENESIS, true);
    group.push(
        LogRecord {
            seq: u64::MAX,
            txn: Txn(u64::MAX),
            bytes: vec![1, 2, 3],
        },
        &payload,
    );
    assert_eq!(group.accounted, txn_encoded_len(&[vec![1, 2, 3]], None));
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
fn records_to_orders_the_fold_ranges_it_and_refuses_a_repeated_seq() {
    // The three facts about the derived set, settled where the set is:
    // `apply` need not be idempotent, so a coordinate applied twice is
    // silent double application answered `Ok`, and a coordinate applied
    // out of order is a fold over a state that never existed.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    // File order is NOT `Seq` order here. In-order append plus the prior
    // recovery's tail truncation normally makes the two agree, and the
    // ordering is what holds a fold together where they do not.
    write_txn(&mut writer, 5, vec![rec(50)]);
    write_txn(&mut writer, 1, vec![rec(10), rec(20)]); // seqs 1, 2
    let segs = list_segments(dir.path()).unwrap();

    let outcome = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(folded_seqs(&outcome, 5), Ok(vec![1, 2, 5]));
    // The range is INCLUSIVE at the bound — a fold to 2 applies 2.
    assert_eq!(folded_seqs(&outcome, 2), Ok(vec![1, 2]));
    // …and EXCLUSIVE at the base, whose records the base already embodies.
    assert_eq!(folded_seqs(&scan(&segs, 1, None, CHAIN_GENESIS).unwrap(), 5), Ok(vec![2, 5]));
}

#[test]
fn a_seq_the_committed_set_presents_twice_is_refused_in_range_and_ignored_below_it() {
    // Two committed transactions at ONE coordinate: a journal no sequencer
    // here wrote, since each `Seq` is minted once. Refused rather than
    // folded twice (§7) — and the range is applied FIRST, so a repeat the
    // base already embodies is harmless rather than a halt.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 1, vec![rec(20)]);
    let segs = list_segments(dir.path()).unwrap();

    assert_eq!(folded_seqs(&scan(&segs, 0, None, CHAIN_GENESIS).unwrap(), 1), Err(1));
    assert_eq!(folded_seqs(&scan(&segs, 1, None, CHAIN_GENESIS).unwrap(), 1), Ok(vec![]));
}

#[test]
#[should_panic(expected = "did not collect that far")]
fn a_fold_past_what_the_scan_collected_is_refused_as_the_callers_bug() {
    // Records above the collection bound were read and dropped, so a fold
    // past it reads a set that is missing exactly the range between —
    // which no filter here can restore, and which would otherwise be
    // answered `Ok` with a short world.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20)]);
    let segs = list_segments(dir.path()).unwrap();
    let _ = scan(&segs, 0, Some(1), CHAIN_GENESIS).unwrap().records_to(2);
}

#[test]
fn a_txn_repeating_a_seq_never_commits() {
    // Two record frames at ONE `Seq`, under a marker whose checksum covers
    // both: a transaction this writer cannot emit, and the shape that
    // would have a non-idempotent fold apply one coordinate twice. The
    // scan refuses it outright, so nothing downstream has to notice.
    let mut buf = Vec::new();
    let mut checksum = 0u32;
    for bytes in [vec![1u8], vec![2u8]] {
        let payload = codec()
            .serialize(&FramePayload::Record(LogRecord {
                seq: 2,
                txn: Txn(2),
                bytes,
            }))
            .unwrap();
        checksum = crc32c::crc32c_append(checksum, &payload);
        push_frame(&mut buf, &payload).unwrap();
    }
    let payload = codec()
        .serialize(&FramePayload::Marker(marker(Txn(2), 2, checksum)))
        .unwrap();
    push_frame(&mut buf, &payload).unwrap();

    let dir = tempdir().unwrap();
    fs::write(segment_path(dir.path(), 2), &buf).unwrap();
    let segs = list_segments(dir.path()).unwrap();
    let out = scan(&segs, 1, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.committed_head, 1, "the repeat must not commit");
    assert!(out.committed_records.is_empty());
    assert!(out.committed_boundaries.is_empty());
    // Every frame intact and the marker not closing them: the
    // edited-transaction verdict is RECORDED at the group's last seq —
    // the scan refuses nothing itself; the callers halt on it.
    assert_eq!(out.uncommitted_intact(), Some(2));
}

#[test]
fn a_marker_that_disagrees_with_its_records_never_commits() {
    // A marker whose `last_seq` sits BELOW the group it closes. Its
    // checksum validates — that field ties the records to the marker and
    // says nothing about `last_seq` — so without the third conjunct the
    // txn commits at 5, the fold silently drops the committed records at
    // 6 and 7 as out of range, and the sequencer restarts over
    // coordinates that are still on disk. A transaction this writer
    // cannot emit, refused outright.
    let mut buf = Vec::new();
    let mut checksum = 0u32;
    for seq in 5..=7u64 {
        let payload = codec()
            .serialize(&FramePayload::Record(LogRecord {
                seq,
                txn: Txn(5),
                bytes: rec(seq * 10),
            }))
            .unwrap();
        checksum = crc32c::crc32c_append(checksum, &payload);
        push_frame(&mut buf, &payload).unwrap();
    }
    // `last_seq` 5: the group reaches 7.
    let payload = codec()
        .serialize(&FramePayload::Marker(marker(Txn(5), 5, checksum)))
        .unwrap();
    push_frame(&mut buf, &payload).unwrap();

    let dir = tempdir().unwrap();
    fs::write(segment_path(dir.path(), 5), &buf).unwrap();
    let segs = list_segments(dir.path()).unwrap();
    let out = scan(&segs, 4, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.committed_head, 4, "a short marker must not commit");
    assert!(out.committed_records.is_empty());
    assert!(out.committed_boundaries.is_empty());
    // Recorded at the GROUP's last seq (7), not the marker's forged 5.
    assert_eq!(out.uncommitted_intact(), Some(7));
}

#[test]
fn a_marker_naming_another_transaction_is_the_edited_one() {
    // The marker's third pre-chain field. A marker whose `txn` names
    // another transaction closes nothing, and a clean group's next intact
    // frame is its own marker in anything a writer here emits — so the
    // group is the edited transaction, named where its marker should have
    // closed it. Left open instead, it is dropped at the scan's end, and
    // on the last transaction cut as the torn tail: an acknowledged commit
    // removed on a one-field rewrite.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // seqs 2, 3: the last transaction
    drop(writer);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker; the
    // marker's `txn` is payload bytes 4..12, after the FramePayload tag.
    rewrite_payload(&segs[0].path, starts[4], |payload| payload[4] ^= 0xFF);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert!(out.runs.is_empty(), "no frame was damaged");
    assert_eq!(out.committed_head, 1, "the rewritten marker commits nothing");
    assert_eq!(out.uncommitted_intact(), Some(3), "named at the group's own last seq");
    // …and still named off a base at 3, which claims to embody it: the
    // verdict compares a marker with its own records and needs no link
    // from the base.
    assert_eq!(scan(&segs, 3, None, CHAIN_GENESIS).unwrap().uncommitted_intact(), Some(3));
}

#[test]
fn a_group_past_the_transaction_budget_never_commits() {
    // The reader's half of the write path's own bound: `commit_txn`
    // refuses a staging past MAX_TXN_BYTES before a byte is appended, so a
    // group past it is one no writer here emits — and accepting it would
    // let a journal spread one `txn` over all its segments while the scan
    // held every record of it.
    //
    // The charge must reproduce the write side's term for term, which is
    // what the two cases below check from either side of the edge: four
    // record frames plus the marker frame land EXACTLY on the budget.
    const N: u64 = 4;
    // Four frames share the budget less the marker; the LAST absorbs the
    // division's remainder, so the sum lands on the budget exactly
    // whatever the marker's size leaves over.
    let for_records = MAX_TXN_BYTES - MARKER_FRAME_LEN;
    let payload_len = (for_records / N - FRAME_HEADER_LEN as u64) as usize;
    let last_len = payload_len + (for_records % N) as usize;
    let buf = vec![7u8; last_len + 1];
    let group_of = |last: &[u8]| {
        let mut group = PendingTxn::open(Txn(1), &CHAIN_GENESIS, true);
        for seq in 1..=N {
            let payload = if seq == N { last } else { &buf[..payload_len] };
            let record = LogRecord {
                seq,
                txn: Txn(1),
                bytes: Vec::new(),
            };
            group.push(record, payload);
        }
        group
    };
    let closed_by = |group: &PendingTxn| marker(Txn(1), N, group.checksum);

    // At the budget: a transaction this writer can emit, so it commits —
    // the refusal begins one byte past the budget, not at it.
    let at_budget = group_of(&buf[..last_len]);
    assert_eq!(at_budget.accounted, MAX_TXN_BYTES);
    assert!(at_budget.commits(&closed_by(&at_budget)));
    assert_eq!(at_budget.records.len() as u64, N);

    // One byte past: refused, however its checksum lands — and the records
    // are released where the group is known dead, which is the memory this
    // bound exists for.
    let over_budget = group_of(&buf);
    assert_eq!(over_budget.accounted, MAX_TXN_BYTES + 1);
    assert!(!over_budget.commits(&closed_by(&over_budget)));
    assert!(
        over_budget.records.is_empty(),
        "a dead group holds no records"
    );
}

#[test]
fn a_marker_at_the_seq_ceiling_classifies_without_wrapping() {
    // A marker contributes the coordinate one past its own `last_seq`. At
    // the ceiling there is no such coordinate, and the run is reported at
    // the ceiling — never wrapped to 0, which would report a run above the
    // base as one below it (§7).
    let mut buf = vec![0xABu8; 8]; // no magic: a corrupt run opens here
    let payload = codec()
        .serialize(&FramePayload::Marker(marker(Txn(u64::MAX), u64::MAX, 0)))
        .unwrap();
    push_frame(&mut buf, &payload).unwrap();

    let dir = tempdir().unwrap();
    fs::write(segment_path(dir.path(), 1), &buf).unwrap();
    let segs = list_segments(dir.path()).unwrap();
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(
        out.runs,
        vec![RunEnd::Landed {
            inferred_max: u64::MAX,
            at: u64::MAX
        }]
    );
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
fn each_commit_chains_from_its_predecessor_and_a_consistent_rewrite_breaks_the_chain() {
    // The chain links every committed transaction to the one before it,
    // from the genesis seed; the scan recomputes each link from the
    // bytes the CRC verified and answers the head's value. A rewrite that
    // keeps every frame CRC consistent — which is what a file-level
    // writer does, and what neither the CRC nor `records_checksum` can
    // see — is caught as a CHAIN BREAK at the first transaction whose
    // marker no longer follows from its predecessor.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]);
    write_txn(&mut writer, 4, vec![rec(40)]);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.chain_break(), None);
    assert_eq!(out.chain_head, chain_of_marker_at(&segs[0].path, starts[6]));
    assert_ne!(out.chain_head, CHAIN_GENESIS);
    // …and the appender continues from it: a scan from a base ABOVE T1
    // seeded with T1's own value verifies T2 and T3 against it.
    let t1 = chain_of_marker_at(&segs[0].path, starts[1]);
    let above = scan(&segs, 1, None, t1).unwrap();
    assert_eq!(above.chain_break(), None);
    assert_eq!(above.chain_head, out.chain_head);
    // …while a wrong base value is a break at the first transaction
    // above the base, and nowhere below it.
    let wrong = scan(&segs, 1, None, CHAIN_GENESIS).unwrap();
    assert_eq!(wrong.chain_break(), Some(3));

    // Rewrite T2's marker's chain — payload offset 56 under `SKJ4`, the
    // salt's thirty-two bytes sitting between the checksum and it —
    // re-sealing its frame CRC: every frame stays intact, every group
    // still commits, and the break lands on T2.
    let t2 = chain_of_marker_at(&segs[0].path, starts[4]);
    rewrite_payload(&segs[0].path, starts[4], |payload| payload[56] ^= 0xFF);
    assert_ne!(chain_of_marker_at(&segs[0].path, starts[4]), t2, "the rewrite took");
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert!(out.runs.is_empty(), "no frame was damaged");
    assert_eq!(out.committed_head, 4, "the groups still commit — the halt is the caller's");
    assert_eq!(out.chain_break(), Some(3), "T2 closes at 3");
    // A rewritten marker AT the base is not this scan's to judge: the base
    // embodies it, and T3 verifies against the value the base vouches for
    // — what T2 carried when that base was taken…
    assert_eq!(scan(&segs, 3, None, t2).unwrap().chain_break(), None);
    // …while against a base that vouches for something else, T3 is the
    // first break, and T2 below it is never named.
    assert_eq!(scan(&segs, 3, None, [0x77; 32]).unwrap().chain_break(), Some(4));
}

/// Every frame of the CLEAN segment at `path` restamped with `stamp` —
/// what a journal written under another format looks like to this parser,
/// the frame CRC not covering the sync word.
fn restamp_every_frame(path: &Path, stamp: &[u8; 4]) {
    let starts = frame_starts(path);
    let mut data = fs::read(path).unwrap();
    for pos in starts {
        data[pos..pos + 4].copy_from_slice(stamp);
    }
    fs::write(path, data).unwrap();
}

#[test]
fn a_foreign_stamp_is_told_from_damage() {
    // The probe names a FORMAT only where the first frame's well-formed
    // sync word is not this build's AND the frame after it is not this
    // build's either: a format stamps every frame, damage changes one
    // word. This build's own stamp, an empty segment, a segment shorter
    // than a sync word, and junk at offset 0 are the scan's (an empty
    // journal, the un-acked tail, a corrupt run), never a format event —
    // and ONE foreign-shaped word before a frame of this build's is
    // damage, which every one-bit flip of the numeral is.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    drop(writer);
    let segs = list_segments(dir.path()).unwrap();
    let seg = segs[0].path.clone();
    let clean = fs::read(&seg).unwrap();
    // Frames: 0 = the record, 1 = its marker.
    let clean_starts = frame_starts(&seg);
    let probe = |segs: &[SegmentMeta], s_load: u64| first_sync_word(segs, s_load).unwrap();
    // The clean segment with its first bytes replaced — damage confined to
    // the opening, every later frame this build's.
    let opened_with = |word: &[u8]| {
        let mut data = clean.clone();
        data[..word.len()].copy_from_slice(word);
        fs::write(&seg, data).unwrap();
    };

    assert_eq!(probe(&segs, 0), FirstSyncWord::Scan, "this build's own stamp");
    for stamp in [b"SKJ3", b"SKJ2", b"SKJ1", b"SKJ9"] {
        fs::write(&seg, &clean).unwrap();
        restamp_every_frame(&seg, stamp);
        assert_eq!(probe(&segs, 0), FirstSyncWord::Foreign(*stamp), "every frame restamped");
    }
    // Every one-bit flip of this build's numeral keeps the `SKJ` prefix,
    // so by its word alone each reads as another format's stamp; the
    // frame after it opens with this build's, which no other format's
    // journal does.
    for bit in 0..8 {
        let word = [b'S', b'K', b'J', MAGIC[3] ^ (1 << bit)];
        opened_with(&word);
        assert_eq!(probe(&segs, 0), FirstSyncWord::Damaged(word), "bit {bit} of the numeral");
    }
    opened_with(&[0xAB, 0xCD, 0xEF, 0x01]);
    assert_eq!(probe(&segs, 0), FirstSyncWord::Scan, "junk is damage, not a format");
    opened_with(&[0, 0, 0, 0]);
    assert_eq!(probe(&segs, 0), FirstSyncWord::Scan, "zeros are damage, not a format");
    fs::write(&seg, b"SKJ").unwrap();
    assert_eq!(probe(&segs, 0), FirstSyncWord::Scan, "shorter than a sync word");
    fs::write(&seg, b"").unwrap();
    assert_eq!(probe(&segs, 0), FirstSyncWord::Scan, "an empty segment");
    assert_eq!(probe(&[], 0), FirstSyncWord::Scan, "no segment at all");
    // A foreign-shaped word whose successor cannot be read stays foreign:
    // a header too short to say where the successor begins, and a first
    // frame with nothing after it. Scanning either would wipe it.
    fs::write(&seg, b"SKJ3\x05\x00").unwrap();
    assert_eq!(probe(&segs, 0), FirstSyncWord::Foreign(*b"SKJ3"), "a header cut short");
    opened_with(b"SKJ3");
    let lone = fs::read(&seg).unwrap()[..clean_starts[1]].to_vec();
    fs::write(&seg, lone).unwrap();
    assert_eq!(probe(&segs, 0), FirstSyncWord::Foreign(*b"SKJ3"), "no successor to read");

    // The probe looks where the scan looks: a closed segment the base
    // embodies is skipped, so a foreign stamp there is not read — and
    // the first segment the scan WOULD read is.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![vec![7u8; SEGMENT_ROTATE_BYTES as usize]]); // fills seg-1
    write_txn(&mut writer, 2, vec![rec(20)]); // rotates into seg-2
    drop(writer);
    let segs = list_segments(dir.path()).unwrap();
    assert_eq!(segs.len(), 2, "the fixture rotates");
    restamp_every_frame(&segs[0].path, b"SKJ2");
    assert_eq!(probe(&segs, 0), FirstSyncWord::Foreign(*b"SKJ2"), "seg-1 is read from genesis");
    assert_eq!(probe(&segs, 1), FirstSyncWord::Scan, "seg-1 is skipped above a base at 1");
    restamp_every_frame(&segs[1].path, b"SKJ2");
    assert_eq!(probe(&segs, 1), FirstSyncWord::Foreign(*b"SKJ2"), "seg-2 is read");
}

#[test]
fn the_chain_rides_across_a_segment_rotation() {
    // The chain is over the journal, not the segment: the first
    // transaction of a new segment links from the last of the old one,
    // and a scan across the boundary verifies every link.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![vec![7u8; SEGMENT_ROTATE_BYTES as usize]]); // fills seg-1
    write_txn(&mut writer, 2, vec![rec(20)]); // rotates into seg-2
    write_txn(&mut writer, 3, vec![rec(30)]);
    drop(writer);
    let segs = list_segments(dir.path()).unwrap();
    assert_eq!(segs.len(), 2, "the fixture rotates");
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.chain_break(), None);
    assert_eq!(out.committed_head, 3);
    let seg2_starts = frame_starts(&segs[1].path);
    assert_eq!(out.chain_head, chain_of_marker_at(&segs[1].path, seg2_starts[3]));
    // Reopened over the rotated journal, the appender continues the same
    // chain: the next commit verifies against what the scan derived.
    let mut writer =
        JournalWriter::open_active(dir.path(), 4, out.chain_head, SaltSource::Seeded(TEST_SEED))
            .unwrap();
    write_txn(&mut writer, 4, vec![rec(40)]);
    drop(writer);
    let segs = list_segments(dir.path()).unwrap();
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!((out.chain_break(), out.committed_head), (None, 4));
}

#[test]
fn the_marker_carries_the_sources_salt_and_an_edited_salt_breaks_the_chain() {
    // The writer draws each transaction's salt from its source and stores
    // it in the marker — under the seeded source, the stream's value for
    // that transaction, byte for byte — and the scan closes each link with
    // the salt it READS there. So a salt edited in place, its frame CRC
    // re-sealed, is a link that no longer verifies: a CHAIN BREAK at that
    // transaction, whatever the records say. The salt is hashed, not
    // merely stored.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]);
    write_txn(&mut writer, 4, vec![rec(40)]);
    drop(writer);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
    for (marker_frame, txn) in [(1, 1u64), (4, 2), (6, 4)] {
        let m = marker_at(&segs[0].path, starts[marker_frame]);
        assert_eq!(m.txn, Txn(txn));
        assert_eq!(
            m.salt,
            SaltSource::Seeded(TEST_SEED).draw(txn).unwrap(),
            "the marker closing transaction {txn} carries the seeded stream's salt"
        );
        assert_ne!(m.salt, [0u8; 32]);
    }
    let salts: Vec<[u8; 32]> =
        [1, 4, 6].iter().map(|&f| marker_at(&segs[0].path, starts[f]).salt).collect();
    assert!(salts[0] != salts[1] && salts[1] != salts[2], "one salt per transaction");
    assert_eq!(scan(&segs, 0, None, CHAIN_GENESIS).unwrap().chain_break(), None);

    // Edit one byte of T2's salt — payload offset 24 + 5, inside the
    // salt's thirty-two — and re-seal the frame: intact, still committed,
    // and the link fails at T2 (last seq 3); T3 is chained from T2's
    // stored value and does not mask it.
    rewrite_payload(&segs[0].path, starts[4], |payload| payload[24 + 5] ^= 0xFF);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert!(out.runs.is_empty(), "no frame was damaged");
    assert_eq!(out.committed_head, 4, "the groups still commit — the halt is the caller's");
    assert_eq!(out.chain_break(), Some(3), "the salt is a chain input: T2 closes at 3");
}

#[test]
fn a_journal_written_under_one_salt_source_replays_under_any() {
    // The salt is READ off the marker on replay, never regenerated, so a
    // reopen under a different source — or the same seed, or the OS —
    // verifies every link written before it, and the commits it adds
    // chain from the recovered head under its own source.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20)]);
    drop(writer);
    for source in [SaltSource::Os, SaltSource::Seeded(TEST_SEED + 1), SaltSource::Seeded(TEST_SEED)] {
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!(out.chain_break(), None, "reopened under {source:?}");
        let next = out.committed_head + 1;
        let mut writer = JournalWriter::open_active(dir.path(), next, out.chain_head, source).unwrap();
        write_txn(&mut writer, next, vec![rec(next * 10)]);
        drop(writer);
    }
    let segs = list_segments(dir.path()).unwrap();
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!((out.chain_break(), out.committed_head), (None, 5));
    // The OS-drawn salt at 3 is neither seeded stream's value; the seeded
    // ones at 4 and 5 are exactly their streams'.
    let markers = markers_in(&segs[0].path);
    let salt_of = |txn: u64| {
        markers
            .iter()
            .find(|m| m.txn == Txn(txn))
            .map(|m| m.salt)
            .expect("a marker per transaction")
    };
    assert_ne!(salt_of(3), SaltSource::Seeded(TEST_SEED).draw(3).unwrap());
    assert_ne!(salt_of(3), SaltSource::Seeded(TEST_SEED + 1).draw(3).unwrap());
    assert_eq!(salt_of(4), SaltSource::Seeded(TEST_SEED + 1).draw(4).unwrap());
    assert_eq!(salt_of(5), SaltSource::Seeded(TEST_SEED).draw(5).unwrap());
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
fn an_unwind_through_the_install_is_beyond_repair() {
    // The one window the writer cannot repair: durably committed, with
    // the install unaccounted for. Its record+marker tail stays —
    // removing an acked commit is what recovery may never do (§3).
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = writer.commit_txn(1, vec![rec(10)], None, |_| panic!("install unwinds"));
    }));
    assert!(unwound.is_err(), "the panic reaches the caller");
    let repair = writer.repair_after_unwind();
    assert!(matches!(repair, UnwindRepair::AfterBarrier), "got {repair:?}");
    let segs = list_segments(dir.path()).unwrap();
    assert_eq!(scan(&segs, 0, None, CHAIN_GENESIS).unwrap().committed_head, 1);
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

#[test]
fn the_skip_rule_passes_over_what_the_base_embodies_and_keeps_the_straddler_and_the_active() {
    // The one statement of which segments a scan above a base reads — the
    // scan walks them and the first-sync-word probe opens the first, so the
    // two agree by construction. A closed segment is passed over only when
    // its inferred reach lies at or below the base; one that STRADDLES the
    // base is read, and the active one always is.
    //
    // Each segment opens with a word of its own, so the probe's answer says
    // WHICH segment it opened: another format's stamp names a closed one,
    // and the empty active one is the scan's to classify.
    let dir = tempdir().unwrap();
    for (first_seq, opening) in [(1, &b"SKJ2"[..]), (5, &b"SKJ3"[..]), (9, &b""[..])] {
        fs::write(segment_path(dir.path(), first_seq), opening).unwrap();
    }
    let segs = list_segments(dir.path()).unwrap();
    let read_above = |s_load: u64| -> Vec<(usize, u64)> {
        scanned_above(&segs, s_load)
            .map(|(i, seg)| (i, seg.first_seq))
            .collect()
    };
    let probed = |s_load: u64| first_sync_word(&segs, s_load).unwrap();
    // Genesis reads every segment, and the probe opens seg-1.
    assert_eq!(read_above(0), vec![(0, 1), (1, 5), (2, 9)]);
    assert_eq!(probed(0), FirstSyncWord::Foreign(*b"SKJ2"));
    // seg-1 reaches 4, where seg-5 begins at 5: it straddles a base at 3…
    assert_eq!(read_above(3), vec![(0, 1), (1, 5), (2, 9)], "seg-1 straddles the base");
    assert_eq!(probed(3), FirstSyncWord::Foreign(*b"SKJ2"));
    // …and a base at 4 embodies it, so the scan and the probe begin at seg-5.
    assert_eq!(read_above(4), vec![(1, 5), (2, 9)], "seg-1 ends at the base");
    assert_eq!(probed(4), FirstSyncWord::Foreign(*b"SKJ3"));
    assert_eq!(read_above(8), vec![(2, 9)], "seg-5 ends at the base");
    assert_eq!(probed(8), FirstSyncWord::Scan);
    // The active segment has no successor to bound it, so it is always read.
    assert_eq!(read_above(100), vec![(2, 9)], "the active segment is always read");
    assert_eq!(probed(100), FirstSyncWord::Scan);
}

#[test]
fn scan_groups_by_txn_and_derives_the_committed_head() {
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // seqs 2, 3
    let segs = list_segments(dir.path()).unwrap();
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.committed_head, 3);
    assert!(out.runs.is_empty());
    assert_eq!(committed_seqs(&out), vec![1, 2, 3]);
    // Naming seg-1 as the cut file is also what proves it was scanned
    // rather than skipped.
    let file_len = fs::metadata(&segs[0].path).unwrap().len();
    assert_tail(&out, &segs[0].path, file_len);
}

#[test]
fn scan_tolerates_burned_seq_gaps() {
    // §7: the replayed range needs NO Seq-contiguity — a TolerateGap burn
    // folds harmlessly; a missing Seq is never corruption.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 5, vec![rec(50), rec(60)]); // burned 2..=4
    let segs = list_segments(dir.path()).unwrap();
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.committed_head, 6);
    assert!(out.runs.is_empty());
    assert_eq!(committed_seqs(&out), vec![1, 5, 6]);
}

#[test]
fn corrupt_record_classifies_by_marker_landing() {
    // T1 = seq 1, T2 = seq 2, T3 = seq 3; corrupt T2's record frame. The
    // resync lands on T2's marker — a marker landing: at = last_seq + 1,
    // inferred max = last_seq (markers carry no Seq of their own; §7).
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20)]);
    write_txn(&mut writer, 3, vec![rec(30)]);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    // Frames: 0=T1 rec, 1=T1 marker, 2=T2 rec, 3=T2 marker, 4=T3 rec, 5=T3 marker.
    flip_byte(&segs[0].path, starts[2] + FRAME_HEADER_LEN + 1);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(
        out.runs,
        vec![RunEnd::Landed {
            inferred_max: 2,
            at: 3
        }]
    );
    // T2's marker no longer validates its records_checksum → uncommitted;
    // W is still bounded by the last committed marker (T3's).
    assert_eq!(out.committed_head, 3);
    assert_eq!(committed_seqs(&out), vec![1, 3]);
    // T3 was chained from T2, which this scan never committed: a chain
    // break at 3 — recorded, so the run above names the root cause first.
    assert_eq!(out.chain_break(), Some(3));
}

#[test]
fn a_halt_names_the_run_before_the_chain_and_only_a_bounded_read_halts_above_the_head() {
    // The order the at-rest verdicts speak in has one site, which both
    // doors share: the corrupt run first — the root cause, carrying no
    // account, its own bytes being unreadable — then the chain's own
    // verdicts, each with its account. And the two doors differ only in
    // where a run is fatal: a recovery discards a run above the committed
    // head as the torn tail, while a bounded read truncates nothing and
    // halts on it.
    let journal_of_three = || {
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        write_txn(&mut writer, 3, vec![rec(30)]);
        dir
    };
    // Frames: 0=T1 rec, 1=T1 marker, 2=T2 rec, 3=T2 marker, 4=T3 rec, 5=T3 marker.

    // T2's record rotted: the run lands on T2's marker, and T3 — chained
    // from the T2 this scan never saw — breaks the chain at 3. Both
    // verdicts stand; the run speaks, without an account.
    let dir = journal_of_three();
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    flip_byte(&segs[0].path, starts[2] + FRAME_HEADER_LEN + 1);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert!(out.chain_verdict().is_some(), "the chain's verdict stands beside the run");
    assert!(matches!(out.halt_to_head(), Some((3, None))), "the run speaks first");
    assert!(matches!(out.halt_anywhere(), Some((3, None))), "the run speaks first");

    // T3's record rotted: the run lands on T3's marker ABOVE the committed
    // head (2). Recovery's door calls it the torn tail; a bounded read's
    // halts on it.
    let dir = journal_of_three();
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    flip_byte(&segs[0].path, starts[4] + FRAME_HEADER_LEN + 1);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.committed_head, 2);
    assert!(out.halt_to_head().is_none(), "a recovery discards it as the tail");
    assert!(matches!(out.halt_anywhere(), Some((4, None))), "a bounded read halts");

    // No run, one rewritten chain field: the chain's verdict speaks, with
    // its account, at either door.
    let dir = journal_of_three();
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    rewrite_payload(&segs[0].path, starts[3], |payload| payload[56] ^= 0xFF);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert!(out.runs.is_empty(), "no frame was damaged");
    for (door, halt) in [("to head", out.halt_to_head()), ("anywhere", out.halt_anywhere())] {
        match halt {
            Some((2, Some(cause))) => {
                assert!(cause.to_string().contains("chain break"), "{door}: {cause}")
            }
            other => panic!("{door}: expected the chain break at 2, got {other:?}"),
        }
    }
}

#[test]
fn corrupt_marker_lands_on_next_record() {
    // T2 = seqs 2..=3; corrupt T2's MARKER. The resync lands on T3's first
    // record (seq 4) — a record landing: at = seq, inferred max = seq − 1.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]);
    write_txn(&mut writer, 4, vec![rec(40)]);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
    flip_byte(&segs[0].path, starts[4] + FRAME_HEADER_LEN + 1);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(
        out.runs,
        vec![RunEnd::Landed {
            inferred_max: 3,
            at: 4
        }]
    );
    assert_eq!(out.committed_head, 4);
    assert_eq!(committed_seqs(&out), vec![1, 4]);
    assert_eq!(out.chain_break(), Some(4), "T3 followed the T2 this scan lost");
}

#[test]
fn resync_rejects_coincidental_magic_inside_payload() {
    // A record whose bytes contain the magic word; corrupt its frame. The
    // resync must reject the embedded magic (its crc check fails) and land
    // on the real next frame — T1's marker (§1/§7).
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    let mut embedded_magic = Vec::new();
    embedded_magic.extend_from_slice(b"xx");
    embedded_magic.extend_from_slice(&MAGIC);
    embedded_magic.extend_from_slice(b"yyyyyyyy");
    write_txn(&mut writer, 1, vec![embedded_magic]);
    write_txn(&mut writer, 2, vec![rec(20)]);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    flip_byte(&segs[0].path, starts[0] + FRAME_HEADER_LEN + 1);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(
        out.runs,
        vec![RunEnd::Landed {
            inferred_max: 1,
            at: 2
        }]
    );
    assert_eq!(out.committed_head, 2);
    assert_eq!(committed_seqs(&out), vec![2]);
    assert_eq!(out.chain_break(), Some(2), "T2 followed the T1 this scan lost");
}

#[test]
fn resynchronization_over_planted_frame_headers_is_bounded() {
    // A committed record whose own bytes plant a frame header every 16
    // bytes, each claiming a payload that fits the file. Corrupt the frame
    // carrying them and every planted header becomes a resync candidate
    // whose CRC must be computed: without a budget the scan does
    // (payload / 16) × (claimed len) bytes of work — quadratic in a record
    // whose size the caller chooses, and an `open()` that never returns.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    let mut evil = Vec::new();
    while evil.len() < 256 * 1024 {
        evil.extend_from_slice(&MAGIC);
        evil.extend_from_slice(&(64 * 1024u32).to_le_bytes()); // a len that fits
        evil.extend_from_slice(&0u32.to_le_bytes()); // a crc that will not
        evil.extend_from_slice(&[0u8; 4]);
    }
    write_txn(&mut writer, 1, vec![evil]);
    write_txn(&mut writer, 2, vec![rec(20)]);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    flip_byte(&segs[0].path, starts[0] + FRAME_HEADER_LEN + 1);

    // The scan refuses, at the base's own coordinate. That refusal is the
    // whole of what there is to check here: what such a scan derived is a
    // prefix, so it produces no outcome at all — there is no committed
    // head to read short, and no cut for a truncation to be aimed with.
    let fail = scan(&segs, 0, None, CHAIN_GENESIS).err();
    assert!(
        matches!(fail, Some(ScanFail::Unbounded { at: 0 })),
        "got {fail:?}"
    );
}

#[test]
fn resynchronization_charges_every_rejection_even_between_intact_frames() {
    // The alternation the budget's own comment names: each expensive
    // rejection is followed by an INTACT frame that closes the run it
    // opened. A budget charged only while a run is open, or kept per run,
    // sees one rejection at a time and never refuses — while the scan
    // spends (rejections) × (claimed length) bytes of CRC on content its
    // author chose. `resynchronization_over_planted_frame_headers_is_bounded`
    // plants its headers back to back, so nothing closes a run there, and
    // it cannot tell those budgets from this one.
    let marker_payload = codec()
        .serialize(&FramePayload::Marker(marker(Txn(u64::MAX), 0, 0)))
        .unwrap();
    let mut unit = Vec::new();
    unit.extend_from_slice(&MAGIC);
    unit.extend_from_slice(&(128 * 1024u32).to_le_bytes()); // a len that fits
    unit.extend_from_slice(&0u32.to_le_bytes()); // a crc that will not
    push_frame(&mut unit, &marker_payload).unwrap(); // …then a frame that closes the run
    let mut evil = Vec::new();
    while evil.len() < 256 * 1024 {
        evil.extend_from_slice(&unit);
    }
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![evil]);
    write_txn(&mut writer, 2, vec![rec(20)]);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    flip_byte(&segs[0].path, starts[0] + FRAME_HEADER_LEN + 1);

    let fail = scan(&segs, 0, None, CHAIN_GENESIS).err();
    assert!(
        matches!(fail, Some(ScanFail::Unbounded { at: 0 })),
        "got {fail:?}"
    );
}

#[test]
fn a_segment_longer_than_any_writer_produces_is_refused_before_it_is_read() {
    // A segment is read WHOLE, so its length sizes an allocation, and a
    // file's length is its own claim: damage, or a stray or concatenated
    // file bearing a segment's name, would size one as it pleased. No
    // writer here produces a segment past `MAX_SEGMENT_LEN`, so one past it
    // is refused on its length alone — the scan's refusal, fatal at any
    // height, with nothing derived from a prefix.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    drop(writer);
    let segs = list_segments(dir.path()).unwrap();
    // Sparse: the length costs no disk.
    OpenOptions::new()
        .write(true)
        .open(&segs[0].path)
        .unwrap()
        .set_len(MAX_SEGMENT_LEN + 1)
        .unwrap();
    let fail = scan(&segs, 0, None, CHAIN_GENESIS).err();
    assert!(
        matches!(fail, Some(ScanFail::Unbounded { at: 0 })),
        "got {fail:?}"
    );
}

#[test]
fn torn_tail_reaches_eof() {
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20)]);
    // Crash mid-append: a partial header at the tail.
    writer.append(&[0xAB, 0xCD, 0xEF]).unwrap();
    let segs = list_segments(dir.path()).unwrap();
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.runs, vec![RunEnd::Eof]);
    assert_eq!(out.committed_head, 2);
    assert_eq!(committed_seqs(&out), vec![1, 2]);
    // The cut sits at the last committed marker's frame end.
    let prefix_end = intact_prefix_end(&segs[0].path);
    assert_tail(&out, &segs[0].path, prefix_end);
}

#[test]
fn the_cut_names_the_segment_holding_the_last_committed_marker() {
    // A rotation, then a crash leaving the NEW segment's transaction
    // torn: the cut aims at the older segment's marker end, and the whole
    // younger segment is tail to discard (§7).
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![vec![7u8; SEGMENT_ROTATE_BYTES as usize]]); // fills seg-1
    write_txn(&mut writer, 2, vec![rec(20)]); // rotates into seg-2
    let segs = list_segments(dir.path()).unwrap();
    assert_eq!(segs.len(), 2, "the fixture rotates");
    // Tear seg-2's marker: its txn is no longer committed.
    let starts = frame_starts(&segs[1].path);
    flip_byte(&segs[1].path, starts[1] + FRAME_HEADER_LEN + 1);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.committed_head, 1);
    let tail = out.tail.as_ref().expect("a scanned region has a cut");
    assert_eq!(tail.segment, segs[0].path);
    assert_eq!(tail.offset, fs::metadata(&segs[0].path).unwrap().len());
    assert_eq!(tail.discard, vec![segs[1].path.clone()]);
}

#[test]
fn require_boundary_answers_from_the_committed_markers() {
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // a composite: boundary 3
    write_txn(&mut writer, 4, vec![rec(40)]);
    let segs = list_segments(dir.path()).unwrap();

    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.require_boundary(3), Ok(()));
    // A composite's interior Seq was never a boundary (§3).
    assert_eq!(out.require_boundary(2), Err(1));

    // The active segment is always scanned, so it reports boundaries
    // below a base too — but those have no base left to fold from, and
    // the nearest ANSWERABLE boundary is the base's own seq.
    let out = scan(&segs, 3, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.require_boundary(4), Ok(()));
    assert_eq!(out.require_boundary(2), Err(3));
}

#[test]
fn a_bound_keeps_what_a_fold_to_it_reads_and_drops_the_rest() {
    // A bounded scan collects for a fold to `bound` and nothing else, so a
    // bounded replay of one transaction above a base does not materialize
    // the whole retained window. What a fold to `bound` reads is exactly
    // `bound` itself, the boundaries below it, and the records at or below
    // it — so the edge is inclusive at all three, and a bound that dropped
    // its own coordinate would answer a short world.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // a composite: boundary 3
    write_txn(&mut writer, 4, vec![rec(40)]);
    let segs = list_segments(dir.path()).unwrap();

    let out = scan(&segs, 0, Some(3), CHAIN_GENESIS).unwrap();
    assert_eq!(committed_seqs(&out), vec![1, 2, 3], "the bound is inclusive");
    assert_eq!(out.require_boundary(3), Ok(()), "…of its own boundary too");
    assert_eq!(out.require_boundary(1), Ok(()));
    // The head and the cut are NOT bounded: recovery folds to the first and
    // truncates at the second, and both must name the whole scanned region.
    assert_eq!(out.committed_head, 4);
    assert_tail(&out, &segs[0].path, fs::metadata(&segs[0].path).unwrap().len());

    // A composite STRADDLING the bound keeps the half below it: its group
    // is filtered per record, not discarded whole.
    let out = scan(&segs, 0, Some(2), CHAIN_GENESIS).unwrap();
    assert_eq!(committed_seqs(&out), vec![1, 2]);
    // …and 3 is then a boundary nothing can ask about, so the nearest
    // answerable one is 1 — never the interior coordinate 2.
    assert_eq!(out.require_boundary(3), Err(1));
}

#[test]
fn the_chain_at_a_boundary_is_its_capture_and_its_absence_the_nearest_below() {
    // One capture answers both of `chain_at`'s questions: a scan collected
    // to a boundary holds the chain the marker closing it carries, and a
    // scan collected to an interior coordinate holds none — answered, as
    // `require_boundary` answers it, with the nearest boundary below.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // a composite: boundary 3
    write_txn(&mut writer, 4, vec![rec(40)]);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
    let at_3 = scan(&segs, 0, Some(3), CHAIN_GENESIS).unwrap();
    assert_eq!(at_3.chain_at_boundary(3), Ok(chain_of_marker_at(&segs[0].path, starts[4])));
    let at_4 = scan(&segs, 0, Some(4), CHAIN_GENESIS).unwrap();
    assert_eq!(at_4.chain_at_boundary(4), Ok(chain_of_marker_at(&segs[0].path, starts[6])));
    // A composite's interior coordinate closes no marker.
    let at_2 = scan(&segs, 0, Some(2), CHAIN_GENESIS).unwrap();
    assert_eq!(at_2.chain_at_boundary(2), Err(1));
}

#[test]
#[should_panic(expected = "keyed on the collection bound")]
fn a_chain_asked_of_a_scan_not_collected_to_it_is_refused_as_the_callers_bug() {
    // The capture is keyed on the collection bound and on nothing else, so
    // a scan collected to anything but the boundary asked would answer a
    // boundary `transact` returned as no boundary at all.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    let segs = list_segments(dir.path()).unwrap();
    let _ = scan(&segs, 0, None, CHAIN_GENESIS).unwrap().chain_at_boundary(1);
}

/// Byte offset just past the last INTACT frame (walks until a bad frame).
fn intact_prefix_end(path: &Path) -> u64 {
    let buf = fs::read(path).unwrap();
    let mut pos = 0;
    loop {
        match parse_frame(&buf, pos) {
            Parsed::Intact { payload } => pos = payload.end,
            Parsed::Bad { .. } => return pos as u64,
        }
    }
}
