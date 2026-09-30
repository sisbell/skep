use super::*;
use crate::error::HistoryError;
use crate::journal::JournalWriter;

// A minimal world for kernel-internal tests. WorldState is a local trait,
// so the impl on a foreign type is fine inside the crate's test cfg.
impl WorldState for Vec<u64> {
    type Record = u64;
    fn apply(&self, record: &u64) -> Self {
        let mut v = self.clone();
        v.push(*record); // non-idempotent, as the design's replay argument assumes
        v
    }
}

/// The seeded salt source these fixtures write under, named once.
const TEST_SEED: u64 = 0x2B;

fn cfg(dir: &std::path::Path, burned_seq: BurnedSeqPolicy) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    }
}

/// A fresh appender at genesis, for the journals these tests build
/// without a kernel.
fn fresh_writer(dir: &std::path::Path) -> JournalWriter {
    JournalWriter::open_active(dir, 1, journal::CHAIN_GENESIS, SaltSource::Seeded(TEST_SEED))
        .unwrap()
}

/// THE SLOT IS FILLED FOR THAT TRANSACTION AND NO OTHER (signed ops):
/// `transact_attested` writes the attestation into the marker of the one
/// transaction it is handed with, `attestation_at` reads it back at that
/// boundary and `None` at every other, genesis is no transaction, a
/// zero-step call writes no marker, and a boundary that IS a checkpoint's
/// seq is still answered from the marker below it. The chain MOVES with
/// the slot (r6-2c): the same ops under a plain `transact` chain identically
/// up to the first filled slot and part there.
#[test]
fn transact_attested_fills_the_slot_of_that_transaction_alone_and_reads_it_back() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new()).unwrap();
    let push = |n: u64| move |stg: &mut Staging<Vec<u64>>| -> Result<(), ()> {
        stg.push(n);
        Ok(())
    };
    let tag1 = Attestation::new(1, vec![0x11; 3_373]).unwrap();
    let tag3 = Attestation::new(3, vec![0x33; 730]).unwrap();
    let (_, s1) = kernel.transact(&[], push(1)).unwrap();
    let (_, s2) = kernel.transact_attested(&[], Some(&tag1), push(2)).unwrap();
    let (_, s3) = kernel.transact_attested(&[], None, push(3)).unwrap();
    // A zero-step attested call writes no marker and so no slot.
    let (_, s3_again) = kernel
        .transact_attested::<_, ()>(&[], Some(&tag1), |_| Ok(()))
        .unwrap();
    assert_eq!(s3_again, s3);
    let (_, s4) = kernel.transact_attested(&[], Some(&tag3), push(4)).unwrap();
    assert_eq!((s1, s2, s3, s4), (Seq(1), Seq(2), Seq(3), Seq(4)));

    assert_eq!(kernel.attestation_at(Seq(0)).unwrap(), None, "genesis is no transaction");
    assert_eq!(kernel.attestation_at(s1).unwrap(), None);
    assert_eq!(kernel.attestation_at(s2).unwrap(), Some(tag1.clone()));
    assert_eq!(kernel.attestation_at(s3).unwrap(), None);
    assert_eq!(kernel.attestation_at(s4).unwrap(), Some(tag3.clone()));
    assert!(matches!(
        kernel.attestation_at(Seq(5)),
        Err(HistoryError::BeyondHead { head: Seq(4) })
    ));

    // A checkpoint AT an attested boundary embodies the world and no
    // marker: the read still answers, from the segment below it.
    let at = kernel.checkpoint().unwrap();
    assert_eq!(at, s4);
    assert_eq!(kernel.attestation_at(s4).unwrap(), Some(tag3));
    assert_eq!(kernel.chain_at(s4).unwrap(), kernel.chain_head());

    // The chain the plain arm writes is this one's up to the first filled
    // slot, and another from there: the slot's digest is a chain input.
    let twin = tempfile::tempdir().unwrap();
    let plain =
        Kernel::<Vec<u64>>::open(cfg(twin.path(), BurnedSeqPolicy::Rollback), Vec::new()).unwrap();
    for n in 1..=4u64 {
        plain.transact(&[], push(n)).unwrap();
    }
    assert_eq!(plain.chain_at(s1).unwrap(), kernel.chain_at(s1).unwrap(), "unsigned alike");
    assert_ne!(plain.chain_at(s2).unwrap(), kernel.chain_at(s2).unwrap(), "the filled slot parts them");
    assert_ne!(plain.chain_head(), kernel.chain_head());
    assert_eq!(plain.attestation_at(Seq(2)).unwrap(), None);
}

/// Under `Durability::InMemory` no marker exists, so the arm drops the
/// value with the frames it would have ridden and the read-back refuses
/// `Unjournaled` — the same answer `chain_at` gives there.
#[test]
fn transact_attested_in_memory_drops_the_value_and_the_read_back_is_unjournaled() {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    };
    let kernel = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
    let attestation = Attestation::new(1, vec![1, 2, 3]).unwrap();
    let (_, s) = kernel
        .transact_attested::<_, ()>(&[], Some(&attestation), |stg| {
            stg.push(1);
            Ok(())
        })
        .unwrap();
    assert_eq!(s, Seq(1));
    assert!(matches!(kernel.attestation_at(s), Err(HistoryError::Unjournaled)));
}

/// [`Kernel::attestation_at`] runs the derivation [`Kernel::chain_at`] runs,
/// its base capped one below the boundary so that the marker closing it is
/// read: every refusal up to the boundary judgment is the same refusal at
/// the same coordinate — beyond the head, at a composite's interior, and
/// over damage at rest anywhere in the scanned region.
#[test]
fn attestation_at_refuses_as_chain_at_does() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new()).unwrap();
    kernel
        .transact::<_, ()>(&[], |stg| {
            stg.push(10);
            stg.push(20); // a composite: seqs 1..=2, boundary 2
            Ok(())
        })
        .unwrap();
    let (_, head) = kernel
        .transact::<_, ()>(&[], |stg| {
            stg.push(30);
            Ok(())
        })
        .unwrap();
    assert_eq!(head, Seq(3));
    // The two reads' answers at one boundary, side by side.
    let both = |at: Seq| {
        (
            kernel.chain_at(at).map(|_| ()),
            kernel.attestation_at(at).map(|_| ()),
        )
    };
    match both(Seq(4)) {
        (
            Err(HistoryError::BeyondHead { head: chain }),
            Err(HistoryError::BeyondHead { head: slot }),
        ) => assert_eq!((chain, slot), (head, head)),
        other => panic!("beyond the head: {other:?}"),
    }
    match both(Seq(1)) {
        (
            Err(HistoryError::NotABoundary { nearest: chain }),
            Err(HistoryError::NotABoundary { nearest: slot }),
        ) => assert_eq!((chain, slot), (Seq(0), Seq(0))),
        other => panic!("a composite's interior: {other:?}"),
    }
    // Rot in the composite's first record: a corrupt run landing on its
    // second record, which both reads halt on — at the head as well, since
    // the scan's verdicts are at any height.
    let seg = journal::segment_path(dir.path(), 1);
    let mut data = fs::read(&seg).unwrap();
    data[journal::FRAME_HEADER_LEN + 1] ^= 0xFF;
    fs::write(&seg, &data).unwrap();
    match both(head) {
        (
            Err(HistoryError::Corruption { at: chain, .. }),
            Err(HistoryError::Corruption { at: slot, .. }),
        ) => assert_eq!((chain, slot), (Seq(2), Seq(2))),
        other => panic!("over damage at rest: {other:?}"),
    }
}

/// The one place the two reads part: a checkpoint's own seq with the segment
/// below it reclaimed. The chain there is the base's own, answered from the
/// checkpoint's header; the slot is the marker's, which no checkpoint
/// carries and the journal no longer holds — so the slot's read refuses
/// where the chain's answers, naming the checkpoint as the floor.
#[test]
fn a_checkpoints_own_seq_with_the_segment_below_reclaimed_answers_the_chain_and_not_the_slot() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        Kernel::<Vec<Vec<u8>>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .unwrap(); // retain 1: the checkpoint's floor is its own seq
    for _ in 0..5 {
        // ~300 KiB each: four fill seg-1 past the rotation threshold, and
        // the fifth rotates into seg-5.
        kernel
            .transact::<_, ()>(&[], |stg| {
                stg.push(vec![7u8; 300 * 1024]);
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(kernel.checkpoint().unwrap(), Seq(5));
    assert!(
        !journal::segment_path(dir.path(), 1).exists(),
        "the checkpoint's reclamation dropped the segment holding 1..=4"
    );
    assert_eq!(kernel.chain_at(Seq(5)).unwrap(), kernel.chain_head());
    let slot = kernel.attestation_at(Seq(5));
    assert!(
        matches!(
            slot,
            Err(HistoryError::Reclaimed {
                floor: Some(Seq(5)),
                cause: None
            })
        ),
        "got {slot:?}"
    );
}

/// [`Kernel::newest_checkpoint`] (QUEUE item 10 piece 2, the head's `base`):
/// `None` until a checkpoint exists, then what its header claims — the
/// checkpointed seq, the chain at it (equal to [`Kernel::chain_head`]), and
/// the SHA-256 of the body `checkpoint()` wrote — each under its own name,
/// so no caller unpacks a position. Read off the header alone: a file cut
/// to its header answers the same, and a header under another format's
/// stamp names no base.
#[test]
fn newest_checkpoint_is_none_then_what_its_header_claims() {
    let dir = tempfile::tempdir().unwrap();
    let kernel =
        Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new()).unwrap();
    assert_eq!(kernel.newest_checkpoint(), None, "no checkpoint has been taken yet");

    kernel
        .transact::<_, ()>(&[], |stg| {
            stg.push(7u64);
            Ok(())
        })
        .unwrap();
    let s = kernel.checkpoint().expect("one checkpoint");

    let newest = kernel.newest_checkpoint().expect("a checkpoint now exists");
    assert_eq!(newest.seq, s, "the newest checkpoint's own seq");
    assert_eq!(
        newest.chain_head,
        kernel.chain_head(),
        "the header's chain_head is the chain at the checkpointed head"
    );
    // 88: the header length the checkpoint layout test pins.
    let path = dir.path().join(format!("checkpoint.{}", s.0));
    let full = fs::read(&path).unwrap();
    assert_eq!(
        newest.body_hash,
        <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&full[88..])),
        "the body hash is the SHA-256 of the body written"
    );

    // Read off the header ALONE: cut to its first 88 bytes, the file
    // claims the same — where a read through `load` would read, hash and
    // decode a body that is no longer there, and refuse.
    fs::write(&path, &full[..88]).unwrap();
    assert_eq!(
        kernel.newest_checkpoint(),
        Some(newest),
        "the claim is the header's, whatever follows it"
    );

    // …and held to what a header can be checked for without its body: under
    // another format's stamp, its bytes 24..88 are not this format's hashes,
    // and the newest checkpoint names no base at all.
    let mut foreign = full[..88].to_vec();
    foreign[..4].copy_from_slice(b"SKC3");
    fs::write(&path, &foreign).unwrap();
    assert_eq!(kernel.newest_checkpoint(), None, "another format's header names no base");
}

/// A published head's `base` is the NEWEST retained checkpoint's header, and
/// a newest whose header refuses names no base at all — the FAIL-QUIET
/// `None`, never the older base beside it. Under one retained base, newest
/// and oldest are one file and neither claim shows; skepd keeps two.
#[test]
fn newest_checkpoint_is_the_newest_retained_and_never_an_older_stand_in() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.path().to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    };
    let kernel = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
    for x in [7u64, 8] {
        kernel
            .transact::<_, ()>(&[], |stg| {
                stg.push(x);
                Ok(())
            })
            .unwrap();
        kernel.checkpoint().expect("a checkpoint");
    }
    assert_eq!(checkpoint::list(dir.path()).unwrap().len(), 2, "both bases retained");
    let newest = kernel.newest_checkpoint().expect("a newest base");
    assert_eq!(newest.seq, Seq(2), "the newest retained checkpoint, not the oldest");
    assert_eq!(newest.chain_head, kernel.chain_head());

    // The newest under another format's stamp names no base — not the older,
    // valid one still retained beside it.
    let path = dir.path().join("checkpoint.2");
    let mut data = fs::read(&path).unwrap();
    data[..4].copy_from_slice(b"SKC3");
    fs::write(&path, &data).unwrap();
    assert_eq!(kernel.newest_checkpoint(), None, "an older base stood in for the newest");
}

#[test]
fn a_journal_under_another_format_is_refused_by_name_and_left_untouched() {
    // The encoding report's §8: under `SKJ2` a foreign-stamp journal was
    // not refused but WIPED — scanned as one corrupt run reaching
    // end-of-file, classified as the un-acked tail, truncated to zero
    // bytes and served as an empty world. Under `SKJ3` it is refused
    // before the scan, naming the stamp found, the stamp expected and the
    // ruled remedy, and every byte is as it was found. The fixture is
    // this build's own journal with every sync word rewritten to `SKJ2`:
    // the frame CRC does not cover the sync word, so this is byte for
    // byte what an old-format file looks like to the parser.
    let dir = tempfile::tempdir().unwrap();
    {
        let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .unwrap();
        for x in [10u64, 20] {
            k.transact::<_, ()>(&[], |stg| {
                stg.push(x);
                Ok(())
            })
            .unwrap();
        }
    }
    let seg = journal::segment_path(dir.path(), 1);
    let mut data = fs::read(&seg).unwrap();
    let mut pos = 0usize;
    while pos + journal::FRAME_HEADER_LEN <= data.len() {
        assert_eq!(&data[pos..pos + 4], b"SKJ4", "a clean frame stream");
        data[pos..pos + 4].copy_from_slice(b"SKJ2");
        let len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        pos += journal::FRAME_HEADER_LEN + len;
    }
    fs::write(&seg, &data).unwrap();

    let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .expect_err("another format's journal is not this build's to open");
    assert!(
        matches!(
            err,
            OpenError::ForeignFormat {
                found: [b'S', b'K', b'J', b'2'],
                expected: [b'S', b'K', b'J', b'4'],
            }
        ),
        "got {err:?}"
    );
    let rendered = err.to_string();
    for named in ["`SKJ2`", "`SKJ4`", "not this build's format", "delete the data directory"] {
        assert!(rendered.contains(named), "{named} missing from: {rendered}");
    }
    assert!(std::error::Error::source(&err).is_none());
    assert_eq!(fs::read(&seg).unwrap(), data, "the refused journal was touched");
    // …and it keeps refusing: a halt writes nothing, so nothing repairs it.
    assert!(matches!(
        Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new()),
        Err(OpenError::ForeignFormat { .. })
    ));
    assert_eq!(fs::read(&seg).unwrap(), data);

    // Damage at offset 0 is NOT a format event: it stays the scan's. The junk
    // opens a corrupt run that lands on T1's marker (inferred max 1), and T2
    // committed after it, so the run lies inside the committed region and the
    // open halts there — the run's own verdict, with no account and every
    // byte as found.
    let mut junk = data.clone();
    junk[..4].copy_from_slice(&[0xAB, 0xCD, 0xEF, 0x01]);
    // Every frame back to this build's stamp but the first, which is junk.
    let mut pos = 0usize;
    while pos + journal::FRAME_HEADER_LEN <= junk.len() {
        if pos > 0 {
            junk[pos..pos + 4].copy_from_slice(b"SKJ4");
        }
        let len = u32::from_le_bytes(junk[pos + 4..pos + 8].try_into().unwrap()) as usize;
        pos += journal::FRAME_HEADER_LEN + len;
    }
    fs::write(&seg, &junk).unwrap();
    let out = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new());
    assert!(
        matches!(out, Err(OpenError::Corruption { at: Seq(2), cause: None })),
        "junk at offset 0 is the scan's corrupt run — not a format, not a damaged word: {out:?}"
    );
    assert_eq!(fs::read(&seg).unwrap(), junk, "a halted open touched the segment");
}

#[test]
fn one_damaged_sync_word_is_refused_as_damage_not_as_another_format() {
    // Every one-bit flip of this build's numeral keeps the `SKJ` prefix,
    // and the frame CRC does not cover the sync word — so one flipped bit
    // at byte 3 of the first frame reads, by its word alone, as a journal
    // of another format, whose ruled remedy is to delete the data
    // directory. The frame after it still opens with this build's stamp,
    // which no other format's journal does: the open refuses it as the
    // damage it is, before the scan and before any write, with a remedy
    // that keeps the journal.
    let dir = tempfile::tempdir().unwrap();
    {
        let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .unwrap();
        for x in [10u64, 20] {
            k.transact::<_, ()>(&[], |stg| {
                stg.push(x);
                Ok(())
            })
            .unwrap();
        }
    }
    let seg = journal::segment_path(dir.path(), 1);
    let mut data = fs::read(&seg).unwrap();
    data[3] ^= 0x01; // `SKJ4` → `SKJ5`
    fs::write(&seg, &data).unwrap();

    let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .expect_err("a damaged sync word is not a journal to open");
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(0), cause: Some(_) }),
        "got {err:?}"
    );
    let rendered = err.to_string();
    for named in ["damaged sync word", "`SKJ5`", "`SKJ4`"] {
        assert!(rendered.contains(named), "{named} missing from: {rendered}");
    }
    assert!(
        !rendered.contains("delete the data directory"),
        "one damaged word was answered with the remedy for another format: {rendered}"
    );
    assert!(std::error::Error::source(&err).is_some(), "the account travels");
    assert_eq!(fs::read(&seg).unwrap(), data, "a halted open touched the segment");
    // …and it keeps refusing: a halt writes nothing, so nothing repairs it.
    assert!(matches!(
        Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new()),
        Err(OpenError::Corruption { at: Seq(0), .. })
    ));
    assert_eq!(fs::read(&seg).unwrap(), data);
}

#[test]
fn a_chain_break_halts_the_open_and_the_history_read_and_cuts_nothing() {
    // Three commits; the second's marker rewritten consistently with its
    // frame CRC. Every frame is intact and every group commits, so
    // nothing but the chain can see it — and the open halts on it, at
    // the coordinate the rewritten transaction closes, with an account,
    // truncating nothing; the history read halts the same way.
    let dir = tempfile::tempdir().unwrap();
    // The chain at 3 as the writer left it, for the base below: a
    // checkpoint at the head carries the marker's own chain, and the
    // open judges that link.
    let chain_at_3 = {
        let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .unwrap();
        for x in [10u64, 20, 30] {
            k.transact::<_, ()>(&[], |stg| {
                stg.push(x);
                Ok(())
            })
            .unwrap();
        }
        k.chain_head()
    };
    let seg = journal::segment_path(dir.path(), 1);
    let mut data = fs::read(&seg).unwrap();
    // Frames: 0=T1 rec, 1=T1 marker, 2=T2 rec, 3=T2 marker, …
    let mut starts = Vec::new();
    let mut pos = 0usize;
    while pos + journal::FRAME_HEADER_LEN <= data.len() {
        starts.push(pos);
        let len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        pos += journal::FRAME_HEADER_LEN + len;
    }
    let marker_start = starts[3];
    let len = u32::from_le_bytes(data[marker_start + 4..marker_start + 8].try_into().unwrap())
        as usize;
    let payload = marker_start + journal::FRAME_HEADER_LEN
        ..marker_start + journal::FRAME_HEADER_LEN + len;
    // The salt's first byte — a chain input since `SKJ4`, so the link
    // breaks as it would for an edited chain field.
    data[payload.start + 24] ^= 0xFF;
    let crc = crc32c::crc32c_append(
        crc32c::crc32c(&data[marker_start + 4..marker_start + 8]),
        &data[payload.clone()],
    );
    data[marker_start + 8..marker_start + 12].copy_from_slice(&crc.to_le_bytes());
    // A torn tail past the last committed marker, so there IS something a
    // truncation would take.
    data.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
    fs::write(&seg, &data).unwrap();

    let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .expect_err("a broken chain is not something to fold");
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(2), .. }),
        "got {err:?}"
    );
    assert!(err.to_string().contains("chain break"), "got {err}");
    assert!(std::error::Error::source(&err).is_some());
    assert_eq!(fs::read(&seg).unwrap(), data, "a halted open truncated the journal");

    // The history read, off a kernel opened over a checkpoint ABOVE the
    // break — the base embodies the rewrite, so the open succeeds — halts
    // on the same break when asked for a boundary below the base.
    fs::write(&seg, &data[..data.len() - 3]).unwrap();
    checkpoint::write(dir.path(), 3, &vec![10u64, 20, 30], &chain_at_3).expect("fixture base");
    let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .expect("the base embodies the rewritten transaction");
    assert_eq!(k.current_seq(), Seq(3));
    let err = k
        .world_at(Seq(1))
        .expect_err("a genesis replay meets the break at 2, above the boundary asked");
    assert!(
        matches!(err, HistoryError::Corruption { at: Seq(2), .. }),
        "got {err:?}"
    );
    assert!(err.to_string().contains("chain break"), "got {err}");
}

// A world of raw byte records, for the size-refusal tests: `Vec<u64>`'s
// fixed 8-byte records cannot reach the frame cap or the budget.
impl WorldState for Vec<Vec<u8>> {
    type Record = Vec<u8>;
    fn apply(&self, record: &Vec<u8>) -> Self {
        let mut v = self.clone();
        v.push(record.clone());
        v
    }
}

/// Run one size-refusal test under BOTH durability modes: the limits are
/// judged above the journal's mode branch, and the parity — not either
/// mode alone — is what these tests pin (F3).
fn in_each_mode(f: impl Fn(Kernel<Vec<Vec<u8>>>, &str)) {
    let dir = tempfile::tempdir().unwrap();
    f(
        Kernel::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new()).unwrap(),
        "Fsync",
    );
    let mem = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    };
    f(Kernel::open(mem, Vec::new()).unwrap(), "InMemory");
}

#[test]
fn a_txn_at_the_budget_commits_and_one_past_is_refused_in_both_modes() {
    // The budget is judged above the mode branch (F1): a transaction at
    // MAX_TXN_BYTES commits — the refusal begins one past the budget, not
    // at it — and one byte past is OverBudget in BOTH modes, with
    // identical accounting.
    let overhead = journal::txn_encoded_len(
        &[
            journal::encode_record(&Vec::<u8>::new()).unwrap(),
            journal::encode_record(&Vec::<u8>::new()).unwrap(),
        ],
        None,
    );
    // A record's encoded length grows byte-for-byte with its body, so
    // these two bodies land the accounted total exactly on the budget.
    let body = journal::MAX_TXN_BYTES - overhead;
    let (len1, len2) = ((body / 2) as usize, (body - body / 2) as usize);
    in_each_mode(|k, mode| {
        let (_, seq) = k
            .transact::<_, ()>(&[], |stg| {
                stg.push(vec![7u8; len1]);
                stg.push(vec![7u8; len2]);
                Ok(())
            })
            .unwrap_or_else(|e| panic!("{mode}: at-budget txn must commit: {e:?}"));
        assert_eq!(seq, Seq(2), "{mode}");
        let out = k.transact::<_, ()>(&[], |stg| {
            stg.push(vec![7u8; len1]);
            stg.push(vec![7u8; len2 + 1]);
            Ok(())
        });
        match out {
            Err(TxnError::OverBudget { bytes }) => {
                assert_eq!(bytes, journal::MAX_TXN_BYTES + 1, "{mode}")
            }
            other => panic!("{mode}: expected OverBudget, got {other:?}"),
        }
    });
}

#[test]
fn a_record_past_the_frame_cap_is_unencodable_in_both_modes() {
    // F3: the frame cap used to live only in the journal's frame builder,
    // which the in-memory mode never reaches — a store whose values can
    // exceed it passed every in-memory test and met the refusal in
    // production. The cap is now judged above the mode branch; the
    // InMemory arm here is red without that.
    //
    // The record also busts the whole-txn budget, and the record's own
    // refusal speaks first: a caller fixing a value is not told to split.
    let prefix = journal::encode_record(&Vec::<u8>::new()).unwrap().len();
    let over = journal::MAX_FRAME_LEN as usize
        - journal::RECORD_PAYLOAD_OVERHEAD as usize
        - prefix
        + 1;
    in_each_mode(|k, mode| {
        let out = k.transact::<_, ()>(&[], |stg| {
            stg.push(vec![7u8; over]);
            Ok(())
        });
        assert!(
            matches!(out, Err(TxnError::Unencodable(_))),
            "{mode}: expected Unencodable, got {out:?}"
        );
    });
}

#[test]
fn a_size_refusal_is_a_true_no_op_in_both_modes() {
    // The refusal leaves what the contract already promises for
    // `Durability`: nothing installed, no Seq burned (Rollback), and the
    // caller may re-invoke — here split into two transactions, since one
    // oversized record cannot be split in place.
    let overhead = journal::txn_encoded_len(
        &[journal::encode_record(&Vec::<u8>::new()).unwrap()],
        None,
    );
    let over = (journal::MAX_TXN_BYTES - overhead) as usize + 1;
    in_each_mode(|k, mode| {
        k.transact::<_, ()>(&[], |stg| {
            stg.push(vec![1u8]);
            Ok(())
        })
        .unwrap();
        let before = k.snapshot();
        let out = k.transact::<_, ()>(&[], |stg| {
            stg.push(vec![7u8; over]);
            Ok(())
        });
        assert!(
            matches!(out, Err(TxnError::OverBudget { .. })),
            "{mode}: got {out:?}"
        );
        // State unchanged, seq not advanced.
        assert_eq!(k.current_seq(), Seq(1), "{mode}");
        assert_eq!(k.snapshot().seq(), before.seq(), "{mode}");
        assert_eq!(k.snapshot().world().len(), 1, "{mode}");
        // The caller re-invokes split, and commits at the next Seqs: the
        // refused transaction burned nothing.
        for i in 0..2u64 {
            let (_, seq) = k
                .transact::<_, ()>(&[], |stg| {
                    stg.push(vec![7u8; over / 2]);
                    Ok(())
                })
                .unwrap_or_else(|e| panic!("{mode}: split half must commit: {e:?}"));
            assert_eq!(seq, Seq(2 + i), "{mode}");
        }
    });
}

#[test]
fn the_budget_does_not_bite_a_txn_of_many_small_records() {
    // The budget exists for pathological stagings; a composite of a
    // thousand small records is the honest shape §3 recommends and stays
    // far under it, in both modes.
    in_each_mode(|k, mode| {
        let (_, seq) = k
            .transact::<_, ()>(&[], |stg| {
                for i in 0..1000u32 {
                    stg.push(i.to_le_bytes().to_vec());
                }
                Ok(())
            })
            .unwrap_or_else(|e| panic!("{mode}: {e:?}"));
        assert_eq!(seq, Seq(1000), "{mode}");
    });
}

#[test]
fn gapped_journal_replays_without_contiguity_check() {
    // §7: under TolerateGap the replayed range may contain burned-Seq
    // gaps; each present record folds exactly once, in order — a missing
    // Seq is never corruption.
    let dir = tempfile::tempdir().unwrap();
    {
        let mut writer = fresh_writer(dir.path());
        let rec = |x: u64| journal::encode_record(&x).unwrap();
        // A journal built without a kernel: no root to install into.
        writer
            .commit_txn(1, vec![rec(10)], None, |_| {})
            .expect("fixture commit");
        // burned 2..=4
        writer
            .commit_txn(5, vec![rec(50), rec(60)], None, |_| {})
            .expect("fixture commit");
    }
    let k = Kernel::<Vec<u64>>::open(
        cfg(dir.path(), BurnedSeqPolicy::TolerateGap),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(k.current_seq(), Seq(6));
    assert_eq!(k.snapshot().world().as_slice(), &[10, 50, 60]);
}

#[test]
fn two_committed_txns_at_one_seq_halt_rather_than_fold_twice() {
    // Two transactions, each committed, each claiming `Seq(1)`. The
    // sequencer mints a coordinate once, so this is a journal no kernel
    // wrote — and `apply` is not idempotent, so folding both is the one
    // outcome recovery may not have. Halt (§7).
    let dir = tempfile::tempdir().unwrap();
    {
        let mut writer = fresh_writer(dir.path());
        let rec = |x: u64| journal::encode_record(&x).unwrap();
        writer
            .commit_txn(1, vec![rec(10)], None, |_| {})
            .expect("fixture commit");
        writer
            .commit_txn(1, vec![rec(20)], None, |_| {})
            .expect("fixture commit");
    }
    // A torn tail past the last committed marker, so there IS something a
    // truncation would take — without it the cut lands at end-of-file and
    // the assertion below could not tell a halt from a truncation.
    let seg = journal::segment_path(dir.path(), 1);
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&[0xAB, 0xCD, 0xEF]).unwrap();
    }
    let before = fs::read(&seg).unwrap();

    let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .expect_err("a repeated Seq is not something to fold twice");
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(1), .. }),
        "got {err:?}"
    );
    // A halt cuts nothing: the fold's refusal precedes the tail
    // truncation, so the journal an operator images after a `Corruption`
    // is the journal that was there.
    assert_eq!(
        fs::read(&seg).unwrap(),
        before,
        "a halted open truncated the journal"
    );
    // A repeat carries no account: the journal is malformed rather than
    // unreadable, so the coordinate is the whole of what there is to say.
    assert!(std::error::Error::source(&err).is_none());
}

/// A world whose records are a four-variant enum — the narrow reader in
/// the skew below.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct NarrowWorld(Vec<u8>);

#[derive(serde::Serialize, serde::Deserialize)]
enum Narrow {
    A,
    B,
    C,
    D,
}

impl WorldState for NarrowWorld {
    type Record = Narrow;
    fn apply(&self, _: &Narrow) -> Self {
        self.clone()
    }
}

#[test]
fn an_undecodable_record_carries_the_serializers_own_account() {
    // A committed, CRC-intact record that does not decode as this
    // `W::Record`: bad media, or a binary rolled back over a record
    // format. The coordinate cannot tell those apart and the serializer's
    // account can, so it travels — this is the one of the fold's two
    // refusals that has an account at all (§7).
    let dir = tempfile::tempdir().unwrap();
    {
        let mut writer = fresh_writer(dir.path());
        // Variant index 5, written where `Narrow` has four.
        writer
            .commit_txn(1, vec![journal::encode_record(&5u32).unwrap()], None, |_| {})
            .expect("fixture commit");
    }
    let err = Kernel::<NarrowWorld>::open(
        cfg(dir.path(), BurnedSeqPolicy::Rollback),
        NarrowWorld(Vec::new()),
    )
    .expect_err("an undecodable committed record is not something to fold");
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(1), .. }),
        "got {err:?}"
    );
    let cause = std::error::Error::source(&err)
        .expect("the account is the only thing that separates a skew from rot");
    // The account IS the serializer's refusal, not a wrapper around it: a
    // caller walking the chain reaches the serializer's own error.
    assert!(
        cause.downcast_ref::<bincode::ErrorKind>().is_some(),
        "the serializer's refusal travels as itself: {cause}"
    );
    assert!(cause.to_string().contains("variant index"), "got {cause}");
    // …and it reaches an operator reading the error, not only one walking
    // the chain.
    assert!(err.to_string().contains("variant index"), "got {err}");
}

#[test]
fn a_committed_record_carrying_bytes_past_its_value_does_not_fold() {
    // The codec rejects trailing bytes at every door it guards, and a
    // record's is the one only a fold reaches: a tolerant decoder would fold
    // the value the first bytes spell and drop the rest in silence.
    let dir = tempfile::tempdir().unwrap();
    {
        let mut writer = fresh_writer(dir.path());
        let mut padded = journal::encode_record(&10u64).unwrap();
        padded.push(0);
        writer
            .commit_txn(1, vec![padded], None, |_| {})
            .expect("fixture commit");
    }
    let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .expect_err("a record with bytes past its value is not something to fold");
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(1), .. }),
        "got {err:?}"
    );
    let cause = std::error::Error::source(&err).expect("the decode's account travels");
    assert!(
        cause.downcast_ref::<bincode::ErrorKind>().is_some(),
        "the decode refused, not another check: {cause}"
    );
}

#[test]
fn world_at_carries_the_serializers_account_of_a_record_only_history_reaches() {
    // `open()` folds only above its newest base, so a committed record
    // BELOW that base is never decoded by recovery: a journal whose binary
    // retired a record variant opens cleanly, and only a bounded replay
    // from an older base meets the record. `HistoryError::Corruption`
    // promises the account `OpenError::Corruption` carries, and this is
    // the route that reaches it through `world_at`'s own mapping.
    let dir = tempfile::tempdir().unwrap();
    // The base at 2 carries the chain the marker closing 2 carries — the
    // install closure hands it over — as a checkpoint off the root would.
    let mut chain_at_2 = journal::CHAIN_GENESIS;
    {
        let mut writer = fresh_writer(dir.path());
        // Variant index 5, written where `Narrow` has four…
        writer
            .commit_txn(1, vec![journal::encode_record(&5u32).unwrap()], None, |_| {})
            .expect("fixture commit");
        // …then a record this build reads, and a base embodying both.
        writer
            .commit_txn(2, vec![journal::encode_record(&Narrow::A).unwrap()], None, |chain| {
                chain_at_2 = chain
            })
            .expect("fixture commit");
    }
    checkpoint::write(dir.path(), 2, &NarrowWorld(Vec::new()), &chain_at_2)
        .expect("fixture base");

    let k = Kernel::<NarrowWorld>::open(
        cfg(dir.path(), BurnedSeqPolicy::Rollback),
        NarrowWorld(Vec::new()),
    )
    .expect("the newest base embodies the record this build cannot read");
    assert_eq!(k.current_seq(), Seq(2));
    assert!(
        k.world_at(Seq(2)).is_ok(),
        "the base's own boundary answers from the base"
    );
    // `NarrowWorld` is not `Debug`, so not `expect_err`.
    let err = k
        .world_at(Seq(1))
        .err()
        .expect("an undecodable committed record is not something to fold");
    assert!(
        matches!(err, HistoryError::Corruption { at: Seq(1), .. }),
        "got {err:?}"
    );
    let cause = std::error::Error::source(&err)
        .expect("the account is what separates a retired variant from rot")
        .to_string();
    assert!(cause.contains("variant index"), "got {cause}");
    assert!(err.to_string().contains("variant index"), "got {err}");
    // The chain at the same boundary answers: `chain_at` folds nothing,
    // so it makes none of the fold's refusals — the chain is over the
    // framed bytes, and those verify.
    assert!(k.chain_at(Seq(1)).is_ok(), "chain_at makes none of the fold's refusals");
}

#[test]
fn a_journal_whose_frame_stream_cannot_be_enumerated_refuses_to_open() {
    // A record whose own bytes plant frame headers, and a lost sync
    // before it: the scan cannot enumerate the stream inside its
    // resynchronization budget, so it produces no outcome at all. There
    // is nothing partial for recovery to fold from and no coordinate that
    // localizes the damage, so the halt is reported at the base's own
    // coordinate — genesis here (§7).
    let dir = tempfile::tempdir().unwrap();
    {
        let mut writer = fresh_writer(dir.path());
        let mut evil = Vec::new();
        while evil.len() < 256 * 1024 {
            evil.extend_from_slice(&journal::MAGIC);
            evil.extend_from_slice(&(64 * 1024u32).to_le_bytes()); // a len that fits
            evil.extend_from_slice(&0u32.to_le_bytes()); // a crc that will not
            evil.extend_from_slice(&[0u8; 4]);
        }
        writer
            .commit_txn(1, vec![evil], None, |_| {})
            .expect("fixture commit");
        writer
            .commit_txn(2, vec![journal::encode_record(&20u64).unwrap()], None, |_| {})
            .expect("fixture commit");
    }
    // Break the frame carrying those bytes, so the scan resynchronizes
    // into them: every planted header is then a candidate whose CRC must
    // be computed.
    let seg = journal::segment_path(dir.path(), 1);
    let mut data = fs::read(&seg).unwrap();
    data[journal::FRAME_HEADER_LEN + 1] ^= 0xFF;
    fs::write(&seg, &data).unwrap();

    let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .expect_err("a stream that cannot be enumerated is not one to recover from");
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(0), .. }),
        "got {err:?}"
    );
    // A halt cuts nothing — and here there is not even an outcome a
    // truncation could be aimed with.
    assert_eq!(
        fs::read(&seg).unwrap(),
        data,
        "a halted open truncated the journal"
    );
}

#[test]
fn an_exhausted_fallback_chain_says_why_its_newest_base_refused() {
    // With the fallback chain exhausted, the refusal's account is the
    // WHOLE of what names the remedy: a base whose body will not decode is
    // a binary on the wrong side of a `W` format change — roll it forward
    // — where a failed checksum or a short file is damage. A bare "no
    // retained checkpoint loads" sends an operator to their disk for both.
    //
    // This is the only tier that can reach both halves of the fixture:
    // `checkpoint::write` mints the unusable base, and the reclamation
    // that makes genesis unreachable needs the kernel that performs it.
    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg(dir.path(), BurnedSeqPolicy::Rollback); // retain 1: no fallback
    {
        let k = Kernel::<Vec<Vec<u8>>>::open(cfg.clone(), Vec::new()).unwrap();
        for _ in 0..8 {
            k.transact::<_, ()>(&[], |stg| {
                stg.push(vec![7u8; 300 * 1024]);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(k.checkpoint().unwrap(), Seq(8));
    }
    // The checkpoint's reclamation dropped the segment that begins the
    // journal, so genesis can no longer stand in.
    assert!(!journal::segment_path(dir.path(), 1).exists());
    // Replace the sole retained base with one whose header checksum is
    // VALID and whose body is not this world: everything the header can
    // prove passes, and the decode still refuses.
    checkpoint::write(dir.path(), 8, &"not this world".to_string(), &journal::CHAIN_GENESIS)
        .expect("fixture base");

    let err = Kernel::<Vec<Vec<u8>>>::open(cfg, Vec::new())
        .expect_err("an exhausted fallback chain refuses");
    let OpenError::BadCheckpoint { cause: Some(_) } = &err else {
        panic!("the skew must travel, or an operator restores media over a rolled binary: {err:?}")
    };
    // …and reaches a reporter walking the error's source chain as well as
    // one reading the sentence, which are two different consumers.
    assert!(std::error::Error::source(&err).is_some());
    assert!(err.to_string().contains("the newest refused"), "got {err}");
}

#[test]
fn a_head_at_the_seq_ceiling_refuses_to_open() {
    // The committed head is the coordinate the next transaction is minted
    // above. A journal whose head leaves none cannot be committed onto
    // without renumbering over it, so opening it is refused rather than
    // wrapped (§2/§7).
    let dir = tempfile::tempdir().unwrap();
    {
        let mut writer = fresh_writer(dir.path());
        let record = journal::encode_record(&10u64).unwrap();
        writer
            .commit_txn(u64::MAX, vec![record], None, |_| {})
            .expect("fixture commit");
    }
    // A torn tail past the last committed marker, so there IS something a
    // truncation would take — without it the cut lands at end-of-file and
    // the assertion below could not tell a halt from a truncation.
    let seg = journal::segment_path(dir.path(), 1);
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&[0xAB, 0xCD, 0xEF]).unwrap();
    }
    let before = fs::read(&seg).unwrap();

    let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .expect_err("a head with no successor coordinate is unaccountable");
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(u64::MAX), .. }),
        "got {err:?}"
    );
    // A halt cuts nothing: the exhausted order is judged before the tail
    // truncation, so the journal an operator images after a `Corruption`
    // is the journal that was there.
    assert_eq!(
        fs::read(&seg).unwrap(),
        before,
        "a halted open truncated the journal"
    );
}

#[test]
fn a_sequencer_with_no_room_left_halts_instead_of_wrapping() {
    // The mint site's own door, reached from a live kernel: with the
    // high-water at the ceiling there is no coordinate to commit at, and
    // the order cannot be renumbered over a committed predecessor —
    // so the kernel halts, and its reads keep serving (§1/§2/§3).
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    };
    let k = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
    k.applier.acquire().seq.high_water = u64::MAX;
    let out = k.transact::<_, ()>(&[], |stg| {
        stg.push(10);
        Ok(())
    });
    assert!(matches!(out, Err(TxnError::Poisoned)), "got {out:?}");
    assert!(k.is_poisoned());
    assert_eq!(k.snapshot().world().as_slice(), &[] as &[u64]);
}

#[test]
fn the_sequencer_never_commits_a_head_recovery_would_refuse() {
    // The top coordinate leaves no successor, so recovery refuses it as a
    // committed head — and the one mint site refuses to make it one, so a
    // kernel never commits a journal it cannot reopen (§2/§7).
    let dir = tempfile::tempdir().unwrap();
    let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .unwrap();
    k.transact::<_, ()>(&[], |stg| {
        stg.push(10);
        Ok(())
    })
    .unwrap();
    k.applier.acquire().seq.high_water = u64::MAX - 1;
    let out = k.transact::<_, ()>(&[], |stg| {
        stg.push(20);
        Ok(())
    });
    assert!(matches!(out, Err(TxnError::Poisoned)), "got {out:?}");
    drop(k);
    let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .expect("a kernel reopens every journal it commits");
    assert_eq!(k.current_seq(), Seq(1));
    assert_eq!(k.snapshot().world().as_slice(), &[10]);
}

#[test]
fn an_interval_restarts_its_window_at_the_crossing() {
    // §6: a crossing resets `last_reset`, so `Interval(d)` is "every d"
    // rather than "every commit once d has first passed". No test can see
    // that through checkpoint files without sleeping, so the cadence is
    // driven directly, its window opened in the past rather than waited
    // for. The only timing this depends on: two consecutive calls take
    // under five seconds.
    let window = std::time::Duration::from_secs(5);
    let mut cadence = Cadence::new(CheckpointPolicy::Interval(window));
    cadence.last_reset = Instant::now()
        .checked_sub(window * 2)
        .expect("the monotonic clock has run for ten seconds");
    assert!(
        cadence.charge_commit(0),
        "a window opened ten seconds ago has elapsed"
    );
    assert!(
        !cadence.charge_commit(0),
        "the crossing did not restart the window"
    );
}

#[test]
fn retain_checkpoints_zero_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let bad_cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.path().to_path_buf(),
            retain_checkpoints: 0,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    };
    let err = Kernel::<Vec<u64>>::open(bad_cfg.clone(), Vec::new())
        .err()
        .unwrap();
    // A configuration this kernel does not offer, not an environmental
    // failure: it says so on its own channel, so a caller backing off and
    // retrying `Io` does not retry a caller's bug forever.
    assert!(
        matches!(err, OpenError::InvalidConfig("retain_checkpoints must be >= 1")),
        "got {err:?}"
    );

    // …and it precedes the journal lock. With a kernel already holding this
    // journal, a validation done later would answer `Io` — the acquisition
    // failure — and a caller backing off on `Io` would retry a config bug
    // forever, looking for a second process that is the wrong culprit.
    let live = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .expect("the first open holds the journal lock");
    let err = Kernel::<Vec<u64>>::open(bad_cfg, Vec::new()).err().unwrap();
    assert!(matches!(err, OpenError::InvalidConfig(_)), "got {err:?}");
    drop(live);
}

#[test]
fn a_poisoned_kernel_halts_writes_and_keeps_serving_reads() {
    // §1/§3's halt, staged directly: the transitions into it need a
    // failing fs, while what poison MEANS is four documented promises
    // (§5/Invariants). Fsync mode, so no precedence between `Poisoned`
    // and the in-memory no-ops is pinned by accident.
    let dir = tempfile::tempdir().unwrap();
    let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
        .unwrap();
    k.transact::<_, ()>(&[], |stg| {
        stg.push(10);
        Ok(())
    })
    .unwrap();
    // A healthy kernel says so, which is what makes the answer below a
    // report of the flag the three refusals are built from rather than a
    // constant.
    assert!(!k.is_poisoned());
    k.poisoned.store(true, Ordering::Release);
    assert!(k.is_poisoned());

    // Writes halt — and `f` never runs: the refusal precedes it.
    let ran = std::cell::Cell::new(false);
    let out = k.transact::<(), ()>(&[], |stg| {
        ran.set(true);
        stg.push(20);
        Ok(())
    });
    assert!(matches!(out, Err(TxnError::Poisoned)));
    assert!(!ran.get(), "a poisoned transact must not run the closure");
    // Checkpoints halt.
    assert!(matches!(k.checkpoint(), Err(CheckpointError::Poisoned)));
    // Reads keep serving the last consistent committed root: the poison
    // paths leave it a whole committed state, so reads stay sound.
    assert_eq!(k.current_seq(), Seq(1));
    assert_eq!(k.snapshot().seq(), Seq(1));
    assert_eq!(k.snapshot().world().as_slice(), &[10]);
    // …and the history read too: it is neither a write nor a checkpoint,
    // so the poison has no refusal to offer it (§5/Invariants).
    assert_eq!(k.world_at(Seq(1)).unwrap().as_slice(), &[10]);
    // flush stays a no-op Ok.
    k.flush().unwrap();
}

#[test]
fn a_poisoned_in_memory_kernel_refuses_a_checkpoint_rather_than_answering_the_no_op() {
    // §6: `Poisoned` outranks every other answer, "the in-memory no-op
    // included". Its sibling pins what poison MEANS and stays under
    // `Fsync` on purpose, so this precedence rides on no other test.
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    };
    let k = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
    k.transact::<_, ()>(&[], |stg| {
        stg.push(10);
        Ok(())
    })
    .unwrap();
    // A healthy in-memory kernel DOES answer the no-op, which is what
    // makes the refusal below a precedence rather than a constant.
    assert_eq!(k.checkpoint().unwrap(), Seq(1));

    k.poisoned.store(true, Ordering::Release);
    let out = k.checkpoint();
    assert!(matches!(out, Err(CheckpointError::Poisoned)), "got {out:?}");
}

#[test]
fn concurrent_checkpoints_each_leave_the_base_their_name_claims() {
    // §6: the API permits concurrent calls — an explicit caller call
    // racing the on-commit auto-trigger, or two callers — and the
    // dedicated checkpoint mutex is what keeps two of them off one
    // `checkpoint.tmp`. A base that fails its own header checksum is
    // useless, and under `N = 1` it would be the only one. A base that
    // loads must also be the one its name claims: the writer below pushes
    // 0, 1, 2, … one record per commit, so the world at `Seq(s)` is
    // exactly `0..s`, and a coordinate read apart from the root it names
    // publishes a later world under an earlier boundary.
    let dir = tempfile::tempdir().unwrap();
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.path().to_path_buf(),
            retain_checkpoints: 64, // keep every base a racing call wrote
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    };
    let k = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
    std::thread::scope(|s| {
        for _ in 0..4 {
            let k = &k;
            s.spawn(move || {
                for _ in 0..8 {
                    k.checkpoint().expect("concurrent checkpoint");
                }
            });
        }
        let k = &k;
        s.spawn(move || {
            for x in 0..32u64 {
                k.transact::<_, ()>(&[], |stg| {
                    stg.push(x);
                    Ok(())
                })
                .unwrap();
            }
        });
    });
    let checkpoints = checkpoint::list(dir.path()).unwrap();
    assert!(!checkpoints.is_empty(), "the fixture writes checkpoints");
    for cp in &checkpoints {
        let loaded = cp.load::<Vec<u64>>().unwrap_or_else(|refused| {
            panic!(
                "checkpoint {} does not load — two writers shared checkpoint.tmp: {refused}",
                cp.seq
            )
        });
        assert_eq!(
            loaded.world,
            (0..cp.seq).collect::<Vec<u64>>(),
            "checkpoint {} does not embody the fold its name claims",
            cp.seq
        );
        // …and names the chain at its own coordinate — the value the
        // marker closing that boundary carries on disk, which is what a
        // base at `cp.seq` hands the scan above it. Genesis's is the chain's
        // genesis value.
        assert_eq!(
            loaded.chain_head,
            chain_of_marker_closing(dir.path(), cp.seq),
            "checkpoint {} names a chain value that is not the one at its coordinate",
            cp.seq
        );
    }
}

/// The chain the marker closing `seq` STORES on disk — the claim, not
/// [`Kernel::chain_at`]'s recomputation — read off the journal's own
/// bytes: the `chain` field of the marker whose `last_seq` is `seq`, in
/// the one segment these fixtures write. What a checkpoint at `seq` must
/// carry as its `chain_head`. The chain's genesis value at genesis, which no
/// marker closes.
fn chain_of_marker_closing(dir: &std::path::Path, seq: u64) -> [u8; 32] {
    if seq == 0 {
        return journal::CHAIN_GENESIS;
    }
    let buf = fs::read(journal::segment_path(dir, 1)).unwrap();
    let mut pos = 0usize;
    while pos + journal::FRAME_HEADER_LEN <= buf.len() {
        let len = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let payload =
            &buf[pos + journal::FRAME_HEADER_LEN..pos + journal::FRAME_HEADER_LEN + len];
        // A marker payload (`SKJ4`): tag 1 (4), txn (8), last_seq (8),
        // checksum (4), the salt (32), then the chain (32).
        if payload[..4] == 1u32.to_le_bytes()
            && u64::from_le_bytes(payload[12..20].try_into().unwrap()) == seq
        {
            return payload[56..88].try_into().unwrap();
        }
        pos += journal::FRAME_HEADER_LEN + len;
    }
    panic!("no committed marker closes {seq}")
}

#[test]
fn world_at_answers_every_boundary_and_refuses_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let k =
        Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .unwrap();
    let (_, s1) = k.transact::<_, ()>(&[], |stg| {
        stg.push(10);
        Ok(())
    })
    .unwrap();
    let (_, s2) = k.transact::<_, ()>(&[], |stg| {
        stg.push(20);
        stg.push(30); // a composite: seqs 2..=3, boundary 3
        Ok(())
    })
    .unwrap();
    let (_, s3) = k.transact::<_, ()>(&[], |stg| {
        stg.push(40);
        Ok(())
    })
    .unwrap();
    assert_eq!((s1, s2, s3), (Seq(1), Seq(3), Seq(4)));

    // Every boundary answers its exact prefix; 0 is genesis.
    assert_eq!(k.world_at(Seq(0)).unwrap(), Vec::<u64>::new());
    assert_eq!(k.world_at(Seq(1)).unwrap(), vec![10]);
    assert_eq!(k.world_at(Seq(3)).unwrap(), vec![10, 20, 30]);
    assert_eq!(k.world_at(Seq(4)).unwrap(), vec![10, 20, 30, 40]);

    // The composite's interior seq was never an observable state.
    match k.world_at(Seq(2)) {
        Err(HistoryError::NotABoundary { nearest }) => assert_eq!(nearest, Seq(1)),
        other => panic!("expected NotABoundary, got {other:?}"),
    }
    match k.world_at(Seq(9)) {
        Err(HistoryError::BeyondHead { head }) => assert_eq!(head, Seq(4)),
        other => panic!("expected BeyondHead, got {other:?}"),
    }
    // head + 1 — the commonest caller mistake, asking for the commit that
    // has not happened yet — answers the same way, rather than falling
    // through to the boundary machinery.
    match k.world_at(Seq(5)) {
        Err(HistoryError::BeyondHead { head }) => assert_eq!(head, Seq(4)),
        other => panic!("expected BeyondHead at head + 1, got {other:?}"),
    }
}

#[test]
fn world_at_selects_the_base_below_the_boundary() {
    // A checkpoint above `at` must be skipped (boundaries before it still
    // fold from genesis); a checkpoint at/below `at` is a valid base and
    // yields the same value the genesis fold would (§6 consistency).
    let dir = tempfile::tempdir().unwrap();
    let k =
        Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .unwrap();
    for x in [10u64, 20, 30] {
        k.transact::<_, ()>(&[], |stg| {
            stg.push(x);
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    k.transact::<_, ()>(&[], |stg| {
        stg.push(40);
        Ok(())
    })
    .unwrap();
    assert_eq!(k.world_at(Seq(1)).unwrap(), vec![10]);
    assert_eq!(k.world_at(Seq(3)).unwrap(), vec![10, 20, 30]);
    assert_eq!(k.world_at(Seq(4)).unwrap(), vec![10, 20, 30, 40]);
}

#[test]
fn every_history_read_is_unjournaled_in_memory_at_every_boundary() {
    // `Unjournaled` is a property of the kernel that no choice of `at`
    // can avoid, so it outranks every question about `at` — including
    // the boundary judgment, which would otherwise answer `BeyondHead`
    // above the head and send a caller walking `at` down to genesis
    // before learning that no boundary here was ever answerable. Genesis
    // is the edge that needs saying: `attestation_at` answers `Seq(0)`
    // without a scan, through a branch of its own that must still refuse
    // here.
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    };
    let k = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
    for x in [10u64, 20] {
        k.transact::<_, ()>(&[], |stg| {
            stg.push(x);
            Ok(())
        })
        .unwrap();
    }
    for at in [Seq(0), Seq(1), Seq(2), Seq(3), Seq(99)] {
        for (read, out) in [
            ("world_at", k.world_at(at).map(|_| ())),
            ("chain_at", k.chain_at(at).map(|_| ())),
            ("attestation_at", k.attestation_at(at).map(|_| ())),
        ] {
            assert!(
                matches!(out, Err(HistoryError::Unjournaled)),
                "{read} at {at} answered {out:?}"
            );
        }
    }
}
