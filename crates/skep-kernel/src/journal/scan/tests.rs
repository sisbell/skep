use super::*;
use crate::config::SaltSource;
use crate::journal::tests::{
    chain_of_marker_at, frame_starts, fresh_writer, marker, marker_at, rec, FIXED_SALT, TEST_SEED,
};
use crate::journal::{
    encode_txn, list_segments, push_frame, segment_path, txn_encoded_len, JournalWriter,
    UnwindRepair, CHAIN_GENESIS, MAX_SIG_BYTES, RECORD_PAYLOAD_OVERHEAD, SEGMENT_ROTATE_BYTES,
};
use tempfile::tempdir;

/// A fixture commit. These journals stand alone — there is no root to
/// install into — so the install step is empty.
fn write_txn(writer: &mut JournalWriter, first: u64, record_bytes: Vec<Vec<u8>>) {
    writer
        .commit_txn(first, record_bytes, None, |_| {})
        .expect("fixture commit");
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
    let empty_marker_payload = codec()
        .serialize(&FramePayload::Marker(marker(Txn(u64::MAX), u64::MAX, u32::MAX)))
        .unwrap();
    assert_eq!(empty_marker_payload.len(), 97);
    assert_eq!(MARKER_FRAME_LEN, 109);
    assert_eq!(MARKER_FRAME_LEN, frame_len(empty_marker_payload.len() as u64));
    // THE FILLED SLOT (signed ops): the accounting gains the blob's own
    // width and nothing else — the marker frame is the empty pin plus
    // the blob, the records' frames untouched — pinned at tag 1's ruled
    // width (3,373 B: ML-DSA-65's 3,309 ‖ Ed25519's 64) and at a
    // one-byte blob. The BUDGET side does not gain it, which
    // `a_filled_slot_is_outside_the_transaction_budget` pins.
    for (tag, width) in [(1u8, 3_373usize), (3u8, 730usize), (9u8, 1usize)] {
        let attestation = Attestation::new(tag, vec![0xA5; width]).unwrap();
        let record_bytes = vec![rec(u64::MAX), vec![7u8; 300]];
        let expected = txn_encoded_len(&record_bytes, Some(&attestation));
        assert_eq!(
            expected,
            txn_encoded_len(&record_bytes, None) + width as u64,
            "a filled slot costs its blob's width and nothing else"
        );
        let (buf, _) = encode_txn(
            u64::MAX - 3,
            record_bytes,
            &CHAIN_GENESIS,
            FIXED_SALT,
            Some(&attestation),
        )
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
    let mut group = PendingTxn::open(Txn(u64::MAX), &CHAIN_GENESIS);
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

#[test]
fn records_to_orders_the_fold_and_ranges_it() {
    // Order and range, two of the three facts about the derived set,
    // settled where the set is: a coordinate applied out of order is a fold
    // over a state that never existed. The third — each coordinate once,
    // since `apply` need not be idempotent — is the next test's.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    // File order is NOT `Seq` order here. In-order append plus the prior
    // recovery's tail truncation normally makes the two agree, and the
    // ordering is what holds a fold together where they do not.
    write_txn(&mut writer, 5, vec![rec(50)]);
    write_txn(&mut writer, 1, vec![rec(10), rec(20)]); // seqs 1, 2
    let segs = list_segments(dir.path()).unwrap();

    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(folded_seqs(&out, 5), Ok(vec![1, 2, 5]));
    // The range is INCLUSIVE at the bound — a fold to 2 applies 2.
    assert_eq!(folded_seqs(&out, 2), Ok(vec![1, 2]));
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
    // Every frame intact and the marker not closing them: the
    // edited-transaction verdict is RECORDED at the group's last seq —
    // the scan refuses nothing itself; the callers halt on it.
    assert_eq!(out.uncommitted_intact(), Some(2));
}

#[test]
fn a_marker_whose_last_seq_falls_short_of_its_group_never_commits() {
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
fn a_group_past_the_transaction_budget_never_commits_whatever_its_slot_holds() {
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
        let mut group = PendingTxn::open(Txn(1), &CHAIN_GENESIS);
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

    // THE FILLED SLOT moves the edge nowhere. The write side judges a
    // staging against the EMPTY marker's figure whatever the slot will hold
    // (`Journal::commit_txn`), so the reader must too: charging the marker a
    // group is actually closed by would refuse, on the next open, an
    // attested transaction at the budget this kernel acked — a `publish`
    // shot among them. Closed by a marker carrying tag 1's full width, the
    // two groups commit and refuse exactly as they did.
    let attested_close = |group: &PendingTxn| Marker {
        sig_alg: 1,
        sig: vec![0xA5; 3_373],
        ..closed_by(group)
    };
    assert!(
        at_budget.commits(&attested_close(&at_budget)),
        "a filled slot pushed a group the writer admits past the reader's budget"
    );
    assert!(!over_budget.commits(&attested_close(&over_budget)));
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
fn each_commit_chains_from_its_predecessor_and_a_consistent_rewrite_breaks_the_chain() {
    // The chain links every committed transaction to the one before it,
    // from the chain's genesis value; the scan recomputes each link from the
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
    let t1_chain = chain_of_marker_at(&segs[0].path, starts[1]);
    let above = scan(&segs, 1, None, t1_chain).unwrap();
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
    let t2_chain = chain_of_marker_at(&segs[0].path, starts[4]);
    rewrite_payload(&segs[0].path, starts[4], |payload| payload[56] ^= 0xFF);
    assert_ne!(chain_of_marker_at(&segs[0].path, starts[4]), t2_chain, "the rewrite took");
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert!(out.runs.is_empty(), "no frame was damaged");
    assert_eq!(out.committed_head, 4, "the groups still commit — the halt is the caller's");
    assert_eq!(out.chain_break(), Some(3), "T2 closes at 3");
    // A rewritten marker AT the base is not this scan's to judge: the base
    // embodies it, and T3 verifies against the value the base vouches for
    // — what T2 carried when that base was taken…
    assert_eq!(scan(&segs, 3, None, t2_chain).unwrap().chain_break(), None);
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
fn the_chain_and_the_salt_source_ride_across_a_segment_rotation() {
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
    // …and the salt source rides with it. The links above verify whatever
    // the salts are, since the reader takes each off its marker, so only the
    // salts themselves can say which source the rotated writer drew from:
    // under the seeded one, every marker — T2 and T3 in the new segment, as
    // T1 in the old — carries the stream's value for its own transaction.
    // T3 is the one the rotated writer salts: a commit draws its salt before
    // it rotates, so T2's came from the writer the rotation replaced.
    for (seg, marker_frame, txn) in [(0, 1, 1u64), (1, 1, 2), (1, 3, 3)] {
        let starts = frame_starts(&segs[seg].path);
        assert_eq!(
            marker_at(&segs[seg].path, starts[marker_frame]).salt,
            SaltSource::Seeded(TEST_SEED).draw(txn).unwrap(),
            "transaction {txn} was salted by a source this kernel was not configured with"
        );
    }
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
fn a_halt_names_the_run_before_the_chain_and_only_a_history_read_halts_above_the_head() {
    // The order the at-rest verdicts speak in has one site, which both
    // doors share: the corrupt run first — the root cause, carrying no
    // account, its own bytes being unreadable — then the chain's own
    // verdicts, each with its account. And the two doors differ only in
    // where a run is fatal: a recovery discards a run above the committed
    // head as the torn tail, while a history read truncates nothing and
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
    // head (2). Recovery's door calls it the torn tail; a history read's
    // halts on it.
    let dir = journal_of_three();
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    flip_byte(&segs[0].path, starts[4] + FRAME_HEADER_LEN + 1);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(out.committed_head, 2);
    assert!(out.halt_to_head().is_none(), "a recovery discards it as the tail");
    assert!(matches!(out.halt_anywhere(), Some((4, None))), "a history read halts");

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
fn a_record_a_run_lands_on_cannot_vouch_for_its_group() {
    // The run may have been the landing record's own transaction's earlier
    // frames, so the group that record opens is not clean: a marker failing
    // to close it is the run's to explain — here, above the committed head,
    // §7's torn tail — and never the edited-transaction verdict, which would
    // halt an open on a group the run may have eaten from.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // seqs 2, 3: the last transaction
    drop(writer);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker. Rot T2's
    // FIRST record: the resync lands on its second, which opens the group.
    flip_byte(&segs[0].path, starts[2] + FRAME_HEADER_LEN + 1);
    let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    assert_eq!(
        out.runs,
        vec![RunEnd::Landed {
            inferred_max: 2,
            at: 3
        }]
    );
    assert_eq!(out.committed_head, 1, "T2's marker closes a group missing a record");
    assert_eq!(out.uncommitted_intact(), None, "the landing record vouched for its group");
    assert!(out.halt_to_head().is_none(), "the run above the head is the torn tail");
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
        matches!(fail, Some(ScanFail::Unscannable { at: 0 })),
        "got {fail:?}"
    );
    // …at the base's OWN coordinate, whatever it is: above a base at 1 the
    // one (active) segment is still read, and refused at 1 — which a refusal
    // spelled `at: 0` answers only at genesis.
    let fail = scan(&segs, 1, None, CHAIN_GENESIS).err();
    assert!(
        matches!(fail, Some(ScanFail::Unscannable { at: 1 })),
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
        matches!(fail, Some(ScanFail::Unscannable { at: 0 })),
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
        matches!(fail, Some(ScanFail::Unscannable { at: 0 })),
        "got {fail:?}"
    );
    // …at the base's OWN coordinate, whatever it is: above a base at 1 the
    // one (active) segment is still read, and refused at 1 — which a refusal
    // spelled `at: 0` answers only at genesis.
    let fail = scan(&segs, 1, None, CHAIN_GENESIS).err();
    assert!(
        matches!(fail, Some(ScanFail::Unscannable { at: 1 })),
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
    {
        use std::io::Write as _;
        let mut f = OpenOptions::new()
            .append(true)
            .open(segment_path(dir.path(), 1))
            .unwrap();
        f.write_all(&[0xAB, 0xCD, 0xEF]).unwrap();
    }
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
fn a_boundary_is_what_a_committed_marker_closes_and_its_nearest_never_lies_below_the_base() {
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21), rec(22)]); // seqs 2..=4: boundary 4
    write_txn(&mut writer, 5, vec![rec(50)]);
    let segs = list_segments(dir.path()).unwrap();
    let closed = |s_load: u64, at: u64| {
        scan(&segs, s_load, Some(at), CHAIN_GENESIS)
            .unwrap()
            .closing_marker(at)
            .map(|_| ())
    };

    assert_eq!(closed(0, 4), Ok(()));
    // A composite's interior Seq was never a boundary (§3).
    assert_eq!(closed(0, 3), Err(1));

    // The active segment is always scanned, so it reports boundaries below
    // a base too — but those have no base left to fold from. Above a base
    // at 2, which no collected marker closes, the interior 3's nearest is
    // the base's own seq, never the 1 below it: the floor, not a collected
    // boundary, keeps it there.
    assert_eq!(closed(2, 5), Ok(()));
    assert_eq!(closed(2, 3), Err(2));
}

#[test]
fn a_bound_keeps_what_a_fold_to_it_reads_and_drops_the_rest() {
    // A bounded scan collects for a fold to `bound` and nothing else, so a
    // history read of one boundary above a base does not materialize
    // the whole retained window. What a read at `bound` takes from the scan
    // is the records at or below `bound`, and the judgment of `bound` itself
    // — so the edge is inclusive at both, and a bound that dropped its own
    // coordinate would answer a short world.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // a composite: boundary 3
    write_txn(&mut writer, 4, vec![rec(40)]);
    let segs = list_segments(dir.path()).unwrap();

    let out = scan(&segs, 0, Some(3), CHAIN_GENESIS).unwrap();
    assert_eq!(committed_seqs(&out), vec![1, 2, 3], "the bound is inclusive");
    assert!(out.closing_marker(3).is_ok(), "…of its own boundary too");
    // The head and the cut are NOT bounded: recovery folds to the first and
    // truncates at the second, and both must name the whole scanned region.
    assert_eq!(out.committed_head, 4);
    assert_tail(&out, &segs[0].path, fs::metadata(&segs[0].path).unwrap().len());

    // A composite STRADDLING the bound keeps the half below it: its group
    // is filtered per record, not discarded whole.
    let out = scan(&segs, 0, Some(2), CHAIN_GENESIS).unwrap();
    assert_eq!(committed_seqs(&out), vec![1, 2]);
    // …and the bound cuts the composite at its interior 2, whose judgment
    // names 1 — never 2 itself.
    assert_eq!(out.closing_marker(2).map(|_| ()), Err(1));
}

#[test]
fn the_chain_at_a_boundary_is_its_capture_and_its_absence_the_nearest_below() {
    // One capture answers both of `chain_at`'s questions: a scan collected
    // to a boundary holds the chain the marker closing it carries, and a
    // scan collected to an interior coordinate holds none — answered with
    // the nearest boundary below.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // a composite: boundary 3
    write_txn(&mut writer, 4, vec![rec(40)]);
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    let chain_closing =
        |out: &ScanOutcome, at: u64| out.closing_marker(at).map(|closing| closing.chain);
    // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
    let at_3 = scan(&segs, 0, Some(3), CHAIN_GENESIS).unwrap();
    assert_eq!(chain_closing(&at_3, 3), Ok(chain_of_marker_at(&segs[0].path, starts[4])));
    let at_4 = scan(&segs, 0, Some(4), CHAIN_GENESIS).unwrap();
    assert_eq!(chain_closing(&at_4, 4), Ok(chain_of_marker_at(&segs[0].path, starts[6])));
    // A composite's interior coordinate closes no marker.
    let at_2 = scan(&segs, 0, Some(2), CHAIN_GENESIS).unwrap();
    assert_eq!(chain_closing(&at_2, 2), Err(1));
}

#[test]
fn the_closing_marker_carries_its_slot_as_the_attestation_it_committed_under() {
    // The slot is interpreted once, where the marker closing the bound is
    // captured: the empty slot is `None`, a filled one the `Attestation` the
    // transaction committed under — for that transaction alone.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    let attestation = Attestation::new(1, vec![0xA5; 5]).unwrap();
    write_txn(&mut writer, 1, vec![rec(10)]);
    writer
        .commit_txn(2, vec![rec(20)], Some(&attestation), |_| {})
        .expect("fixture commit");
    write_txn(&mut writer, 3, vec![rec(30)]);
    let segs = list_segments(dir.path()).unwrap();
    let slot_at = |at: u64| {
        scan(&segs, 0, Some(at), CHAIN_GENESIS)
            .unwrap()
            .closing_marker(at)
            .map(|closing| closing.attestation.clone())
    };
    assert_eq!(slot_at(1), Ok(None));
    assert_eq!(slot_at(2), Ok(Some(attestation)));
    assert_eq!(slot_at(3), Ok(None));
}

#[test]
fn a_slot_past_the_cap_at_rest_closes_no_boundary_and_panics_nothing() {
    // The capture converts the slot of the marker closing a history read's
    // bound, under an `expect` that holds only because the decoder asked the
    // same rule: a marker whose blob `Attestation::new` refuses must be an
    // undecodable frame here, never a commit whose conversion panics under
    // `GET /chain?at=N`.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    drop(writer);
    // T2 by hand: its record, then a marker whose slot is one byte past the
    // cap — checksum and CRCs honest, so only the slot refuses.
    let record = codec()
        .serialize(&FramePayload::Record(LogRecord {
            seq: 2,
            txn: Txn(2),
            bytes: rec(20),
        }))
        .unwrap();
    let wide = Marker {
        sig_alg: 1,
        sig: vec![0xA5; MAX_SIG_BYTES + 1],
        ..marker(Txn(2), 2, crc32c::crc32c_append(0, &record))
    };
    let mut buf = Vec::new();
    push_frame(&mut buf, &record).unwrap();
    push_frame(&mut buf, &codec().serialize(&FramePayload::Marker(wide)).unwrap()).unwrap();
    {
        use std::io::Write as _;
        let mut f = OpenOptions::new()
            .append(true)
            .open(segment_path(dir.path(), 1))
            .unwrap();
        f.write_all(&buf).unwrap();
    }
    let segs = list_segments(dir.path()).unwrap();
    let out = scan(&segs, 0, Some(2), CHAIN_GENESIS).unwrap();
    assert_eq!(
        out.runs,
        vec![RunEnd::Eof],
        "the wide slot is a frame no writer of this stamp emits"
    );
    assert_eq!(out.committed_head, 1, "…which commits nothing");
    assert_eq!(out.closing_marker(2).map(|_| ()), Err(1), "…and closes no boundary");
}

#[test]
#[should_panic(expected = "keyed on the collection bound")]
fn a_boundary_asked_of_a_scan_not_collected_to_it_is_refused_as_the_callers_bug() {
    // The capture is keyed on the collection bound and on nothing else, so
    // a scan collected to anything but the boundary asked would answer a
    // boundary `transact` returned as no boundary at all.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    let segs = list_segments(dir.path()).unwrap();
    let _ = scan(&segs, 0, None, CHAIN_GENESIS).unwrap().closing_marker(1);
}

#[test]
fn a_boundary_scan_captures_every_committed_marker_above_the_base_and_collects_no_record() {
    // ONE PASS, BOUNDED MEMORY (§3.3 step 2 of the operations design): the
    // boundary mode walks the segments a record scan walks — the closed
    // ones above the base and the active one, each once — keeps of every
    // committed marker above the base its `last_seq` and its slot, a
    // composite as its boundary alone, and keeps NO record: the term that
    // grows with the journal is one entry per commit, never the records a
    // fold would read. A mutant that collected the records too fails here.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    let attestation = Attestation::new(1, vec![0xA5; 5]).unwrap();
    write_txn(&mut writer, 1, vec![vec![7u8; SEGMENT_ROTATE_BYTES as usize]]); // fills seg-1
    writer
        .commit_txn(2, vec![rec(20)], Some(&attestation), |_| {}) // rotates into seg-2
        .expect("fixture commit");
    write_txn(&mut writer, 3, vec![rec(30), rec(31)]); // a composite: boundary 4
    write_txn(&mut writer, 5, vec![rec(50)]);
    drop(writer);
    let segs = list_segments(dir.path()).unwrap();
    assert_eq!(segs.len(), 2, "the fixture rotates");
    // seg-1: 0=T1 rec, 1=T1 marker. seg-2: 0=T2 rec, 1=T2 marker, 2..=3=T3
    // recs, 4=T3 marker, 5=T4 rec, 6=T4 marker.
    let seg1_starts = frame_starts(&segs[0].path);
    let seg2_starts = frame_starts(&segs[1].path);

    // From genesis: both segments walked to their ends — the cut names
    // seg-2's — four commits counted, four entries with their slots as
    // committed, and no record kept, where the record scan over the same
    // region keeps every one of the five.
    let out = scan_boundaries(&segs, 0, CHAIN_GENESIS).unwrap();
    assert_eq!((out.committed_head, out.commits_above_base), (5, 4));
    assert!(out.runs.is_empty());
    assert_eq!(out.chain_break(), None, "the chain is verified in this mode too");
    assert!(out.committed_records.is_empty(), "the boundary mode keeps no record");
    let tail = out.tail.as_ref().expect("a scanned region has a cut");
    assert_eq!(tail.segment, segs[1].path);
    assert_eq!(tail.offset, fs::metadata(&segs[1].path).unwrap().len());
    assert_eq!(
        committed_seqs(&scan(&segs, 0, None, CHAIN_GENESIS).unwrap()),
        vec![1, 2, 3, 4, 5],
        "the record scan over the same region keeps every record"
    );
    assert_eq!(
        out.into_boundaries(),
        vec![(1, None), (2, Some(attestation.clone())), (4, None), (5, None)]
    );

    // Above a base at 1, the closed seg-1 — inferred to end at 1 — is
    // skipped as the record scan skips it, and the entries are seg-2's; above
    // a base at 4, the one commit above it. Each base brings its own chain,
    // and the first link above it verifies against that.
    let above_1 =
        scan_boundaries(&segs, 1, chain_of_marker_at(&segs[0].path, seg1_starts[1])).unwrap();
    assert_eq!((above_1.chain_break(), above_1.commits_above_base), (None, 3));
    assert_eq!(above_1.into_boundaries(), vec![(2, Some(attestation)), (4, None), (5, None)]);
    let above_4 =
        scan_boundaries(&segs, 4, chain_of_marker_at(&segs[1].path, seg2_starts[4])).unwrap();
    assert_eq!((above_4.chain_break(), above_4.commits_above_base), (None, 1));
    assert_eq!(above_4.into_boundaries(), vec![(5, None)]);
}

#[test]
fn a_boundary_scan_judges_the_at_rest_verdicts_as_a_record_scan_does() {
    // The verdicts are the pass's, not the mode's: a corrupt run and a
    // chain break are recorded by a boundary scan at the coordinates, and
    // with the accounts, a record scan records them — so a history read
    // halts alike whichever mode it ran, and never lists around damage.
    let halt_of = |out: &ScanOutcome| {
        out.halt_anywhere().map(|(at, cause)| (at, cause.map(|c| c.to_string())))
    };
    let journal_of_three = || {
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        write_txn(&mut writer, 3, vec![rec(30)]);
        dir
    };
    // Frames: 0=T1 rec, 1=T1 marker, 2=T2 rec, 3=T2 marker, 4=T3 rec, 5=T3 marker.

    // T2's record rotted: the run lands on T2's marker and T3's link breaks;
    // the run speaks, without an account, from either mode — and the list
    // the boundary scan holds is missing exactly the commit the run ate,
    // which is why a caller halts before reading it.
    let dir = journal_of_three();
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    flip_byte(&segs[0].path, starts[2] + FRAME_HEADER_LEN + 1);
    let records = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    let boundaries = scan_boundaries(&segs, 0, CHAIN_GENESIS).unwrap();
    assert_eq!(halt_of(&records), Some((3, None)));
    assert_eq!(halt_of(&boundaries), halt_of(&records));
    assert_eq!(boundaries.chain_break(), records.chain_break());
    assert_eq!(boundaries.runs, records.runs);
    assert_eq!(boundaries.into_boundaries(), vec![(1, None), (3, None)]);

    // No run, T2's chain field rewritten consistently: the chain's verdict,
    // with its account, from either mode.
    let dir = journal_of_three();
    let segs = list_segments(dir.path()).unwrap();
    let starts = frame_starts(&segs[0].path);
    rewrite_payload(&segs[0].path, starts[3], |payload| payload[56] ^= 0xFF);
    let records = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
    let boundaries = scan_boundaries(&segs, 0, CHAIN_GENESIS).unwrap();
    match halt_of(&records) {
        Some((2, Some(cause))) => assert!(cause.contains("chain break"), "{cause}"),
        other => panic!("expected the chain break at 2, got {other:?}"),
    }
    assert_eq!(halt_of(&boundaries), halt_of(&records));
}

#[test]
#[should_panic(expected = "collected no record at all")]
fn a_fold_asked_of_a_boundary_scan_is_refused_as_the_callers_bug() {
    // The boundary mode kept no record, so a fold over its outcome would
    // answer `Ok` with a world missing every record above the base: a
    // caller's bug, refused as a fold past the collection bound is.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    let segs = list_segments(dir.path()).unwrap();
    let _ = scan_boundaries(&segs, 0, CHAIN_GENESIS).unwrap().records_to(1);
}

#[test]
#[should_panic(expected = "keyed on the collection bound")]
fn a_boundary_asked_of_a_boundary_scan_is_refused_as_the_callers_bug() {
    // A boundary scan captures no closing marker — it lists every boundary
    // instead — so a boundary judgment asked of it would answer a boundary
    // `transact` returned as no boundary at all.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    let segs = list_segments(dir.path()).unwrap();
    let _ = scan_boundaries(&segs, 0, CHAIN_GENESIS).unwrap().closing_marker(1);
}

#[test]
#[should_panic(expected = "only a boundary scan lists them")]
fn the_boundaries_asked_of_a_record_scan_are_refused_as_the_callers_bug() {
    // A record scan captures the one marker closing its bound and lists
    // none, so asking it for the list would answer every boundary as absent.
    let dir = tempdir().unwrap();
    let mut writer = fresh_writer(dir.path());
    write_txn(&mut writer, 1, vec![rec(10)]);
    let segs = list_segments(dir.path()).unwrap();
    let _ = scan(&segs, 0, Some(1), CHAIN_GENESIS).unwrap().into_boundaries();
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
