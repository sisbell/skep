use std::panic::{catch_unwind, AssertUnwindSafe};

use super::*;
use tempfile::tempdir;

/// A stand-in world: the format is generic over `W`, so what a fixture
/// needs is something that serializes, not something that resembles one.
fn world() -> Vec<u64> {
    vec![10, 20, 30]
}

/// A stand-in chain head: a value with a shape, so a header that carried
/// the wrong thing here would not carry zeros by coincidence.
const CHAIN_HEAD: [u8; 32] = [0xC4; 32];

/// The module's `write` through a seam nothing has armed — what every
/// fixture here writes through, the seam's own claims naming `super::write`
/// with the seam they arm. Shadows the glob import on purpose, so the
/// fixtures read as the writes they are.
fn write<W: Serialize>(
    dir: &Path,
    seq: u64,
    world: &W,
    chain_head: &[u8; 32],
) -> Result<(), WriteFail> {
    super::write(dir, seq, world, chain_head, &Seam::default())
}

#[test]
fn checkpoint_header_layout_is_magic_seq_crc_body_len_chain_head_and_body_hash() {
    // A checkpoint file written by one build is read by the next, so the
    // layout is pinned here rather than left to whatever `write`'s six
    // appends and `load`'s `HEADER_LEN` split happen to agree on. A field
    // added to one without the other makes `body_len` disagree with the
    // body, which makes EVERY retained base unloadable — and recovery
    // then falls silently to genesis, or refuses with `BadCheckpoint`.
    let dir = tempdir().unwrap();
    write(dir.path(), 7, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
    let data = fs::read(checkpoint_path(dir.path(), 7)).unwrap();
    let body = codec().serialize(&world()).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(b"SKC4");
    expected.extend_from_slice(&7u64.to_le_bytes()); // seq
    expected.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes()); // crc(body)
    expected.extend_from_slice(&(body.len() as u64).to_le_bytes()); // body_len
    expected.extend_from_slice(&CHAIN_HEAD); // chain_head
    expected.extend_from_slice(&<[u8; 32]>::from(Sha256::digest(&body))); // body_hash
    assert_eq!(expected.len(), HEADER_LEN, "the header is what `load` splits at");
    assert_eq!(HEADER_LEN, 88);
    assert_eq!(&data[..HEADER_LEN], expected.as_slice());
    assert_eq!(&data[HEADER_LEN..], body.as_slice());

    // …and the whole file loads back through the door every base walks
    // through, the chain head with it.
    let listed = list(dir.path()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].seq, 7);
    let loaded = listed[0].load::<Vec<u64>>().expect("the base loads");
    assert_eq!(loaded.world, world());
    assert_eq!(loaded.chain_head, CHAIN_HEAD);

    // A crash mid-write leaves a `.tmp`, which is not a base.
    fs::write(dir.path().join("checkpoint.tmp"), b"not a checkpoint").unwrap();
    assert_eq!(list(dir.path()).unwrap().len(), 1);
}

/// A checkpoint is serialized in ONE pass into a buffer sized by a hint — the
/// newest checkpoint's length — where bincode's `serialize` walks the world
/// twice, and the bytes do not depend on the hint. The three hints a
/// directory gives: none (no checkpoint yet), one SHORT of the body (the
/// world grew, as it does) and one PAST it (a world written smaller than the
/// last) — and under each the body on disk is the two-pass `serialize`'s
/// bytes exactly, under a header built from it. A fourth, which no process
/// can reserve — a header claiming every byte a `u64` counts — is dropped,
/// and the checkpoint lands.
#[test]
fn a_checkpoint_written_in_one_pass_is_the_two_pass_serializes_bytes_whatever_the_hint() {
    let dir = tempdir().unwrap();
    let small: Vec<u64> = (0..100).collect();
    let large: Vec<u64> = (0..100_000).collect();
    let two_pass = |world: &Vec<u64>| codec().serialize(world).unwrap();
    let the_file_holds = |seq: u64, world: &Vec<u64>| {
        let body = two_pass(world);
        let data = fs::read(checkpoint_path(dir.path(), seq)).unwrap();
        assert_eq!(&data[HEADER_LEN..], body.as_slice(), "seq {seq}: the body is the serialize's");
        let claimed = u64::from_le_bytes(data[BODY_LEN_AT..BODY_LEN_AT + 8].try_into().unwrap());
        assert_eq!(claimed, body.len() as u64, "seq {seq}: the header's length is the body's");
        let crc = u32::from_le_bytes(data[CRC_AT..CRC_AT + 4].try_into().unwrap());
        assert_eq!(crc, crc32c::crc32c(&body), "seq {seq}: the header's checksum is the body's");
        assert_eq!(&data[BODY_HASH_AT..BODY_HASH_AT + 32], &body_hash(&body), "seq {seq}: hash");
    };

    assert_eq!(newest_header(dir.path()), None, "no checkpoint yet: no hint");
    write(dir.path(), 1, &small, &CHAIN_HEAD).expect("the first checkpoint");
    the_file_holds(1, &small);

    let hint = newest_header(dir.path()).expect("the first is the newest").len;
    assert!(hint < two_pass(&large).len() as u64, "a hint short of the body");
    write(dir.path(), 2, &large, &CHAIN_HEAD).expect("a body past its hint");
    the_file_holds(2, &large);

    let hint = newest_header(dir.path()).expect("the second is the newest").len;
    assert!(hint > two_pass(&small).len() as u64, "a hint past the body");
    write(dir.path(), 3, &small, &CHAIN_HEAD).expect("a body short of its hint");
    the_file_holds(3, &small);

    let path = checkpoint_path(dir.path(), 3);
    let mut overclaimed = fs::read(&path).unwrap();
    overclaimed[BODY_LEN_AT..BODY_LEN_AT + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&path, &overclaimed).unwrap();
    assert_eq!(newest_header(dir.path()).map(|h| h.len), Some(u64::MAX), "the claim saturates");
    write(dir.path(), 4, &small, &CHAIN_HEAD).expect("a hint the process cannot grant is dropped");
    the_file_holds(4, &small);
}

/// A write that fails PAST the temp file's creation — here at the rename,
/// refused because a directory stands at the checkpoint's own name — leaves
/// no `checkpoint.tmp`: the temp file is removed before the failure is
/// answered, and the failure answered is the write's own, the rename's
/// refusal. The one the write's directory contract makes the kernel's
/// (M-I5 (f): a failed checkpoint leaves the journal whole and unreclaimed,
/// and keeps no room of its own on the volume).
#[test]
fn a_write_that_fails_past_the_temp_files_creation_removes_it() {
    let dir = tempdir().unwrap();
    fs::create_dir(checkpoint_path(dir.path(), 7)).unwrap();
    let refused = write(dir.path(), 7, &world(), &CHAIN_HEAD).expect_err("the rename is refused");
    assert!(matches!(refused, WriteFail::Io(_)), "the write's own failure: {refused:?}");
    assert!(!dir.path().join("checkpoint.tmp").exists(), "the temp file is gone");
    let listed = list(dir.path()).unwrap();
    assert_eq!(listed.len(), 1, "the directory at the name is listed, as any name is");
    assert!(listed[0].load::<Vec<u64>>().is_err(), "…and is no base");
    // The failure answered names the rename, not the removal.
    let text = match refused {
        WriteFail::Io(e) => e.to_string(),
        WriteFail::Serialize(_) => unreachable!("the world serializes"),
    };
    assert!(!text.contains("could not be removed"), "the removal succeeded: {text}");

    // The name cleared, the same write lands whole.
    fs::remove_dir(checkpoint_path(dir.path(), 7)).unwrap();
    write(dir.path(), 7, &world(), &CHAIN_HEAD).expect("the retry lands");
    assert!(!dir.path().join("checkpoint.tmp").exists());
    assert_eq!(list(dir.path()).unwrap()[0].load::<Vec<u64>>().unwrap().world, world());
}

/// A stray `checkpoint.tmp` — a crash's leftover — is the kernel's to remove
/// at the open: `remove_stray_tmp` answers its size and deletes it, answers
/// `None` where none stands, and leaves every base beside it untouched.
#[test]
fn a_stray_temp_file_is_removed_with_its_size_answered_and_the_bases_untouched() {
    let dir = tempdir().unwrap();
    assert_eq!(remove_stray_tmp(dir.path()).unwrap(), None, "nothing to remove");
    write(dir.path(), 3, &world(), &CHAIN_HEAD).expect("a base");
    let junk = b"\xFF\x00garbage, not a checkpoint";
    fs::write(dir.path().join("checkpoint.tmp"), junk).unwrap();
    assert_eq!(
        remove_stray_tmp(dir.path()).unwrap(),
        Some(junk.len() as u64),
        "the stray's size, as an operator line reports it"
    );
    assert!(!dir.path().join("checkpoint.tmp").exists(), "…and it is gone");
    assert_eq!(remove_stray_tmp(dir.path()).unwrap(), None, "once");
    let listed = list(dir.path()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].load::<Vec<u64>>().unwrap().world, world(), "the base stands");
}

#[test]
fn a_flipped_body_byte_refuses_the_base() {
    // The header checksum is what `load` validates before trusting a base,
    // because serde alone does not reliably detect bit-rot and a silently
    // wrong base would defeat the whole `BadCheckpoint` fallback chain —
    // so the account must say the CHECKSUM caught it, which is what tells
    // an operator to restore media rather than to roll a binary.
    let dir = tempdir().unwrap();
    write(dir.path(), 3, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
    let path = checkpoint_path(dir.path(), 3);
    let mut data = fs::read(&path).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xFF;
    fs::write(&path, &data).unwrap();
    let refused = list(dir.path()).unwrap()[0]
        .load::<Vec<u64>>()
        .expect_err("a flipped body byte is not a base");
    assert!(refused.to_string().contains("checksum"), "got {refused}");
}

#[test]
fn a_body_hash_that_disagrees_with_the_body_refuses_the_base() {
    // The hash is the header's COMMITMENT to the body — what a published
    // head names a checkpoint by — and `load` holds the file to it after
    // the checksum: a header whose hash names another body is not a base,
    // whatever its checksum says.
    let dir = tempdir().unwrap();
    write(dir.path(), 3, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
    let path = checkpoint_path(dir.path(), 3);
    let mut data = fs::read(&path).unwrap();
    data[BODY_HASH_AT] ^= 0xFF;
    fs::write(&path, &data).unwrap();
    let refused = list(dir.path()).unwrap()[0]
        .load::<Vec<u64>>()
        .expect_err("a header hashing another body is not a base");
    assert!(refused.to_string().contains("hash"), "got {refused}");
}

#[test]
fn a_body_carrying_bytes_past_its_world_is_not_a_base() {
    // Every check the header makes passes — length, checksum and hash are
    // fixed over the longer body — so what refuses is the decode, which takes
    // exactly what the encoder writes: a tolerant one would load the world
    // the first bytes spell, under a hash of bytes that are not its body.
    let dir = tempdir().unwrap();
    let mut body = codec().serialize(&world()).unwrap();
    body.push(0);
    let mut data = Vec::new();
    data.extend_from_slice(&MAGIC);
    data.extend_from_slice(&3u64.to_le_bytes()); // seq
    data.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes()); // crc(body)
    data.extend_from_slice(&(body.len() as u64).to_le_bytes()); // body_len
    data.extend_from_slice(&CHAIN_HEAD); // chain_head
    data.extend_from_slice(&body_hash(&body)); // body_hash
    data.extend_from_slice(&body);
    fs::write(checkpoint_path(dir.path(), 3), &data).unwrap();
    let refused = list(dir.path()).unwrap()[0]
        .load::<Vec<u64>>()
        .expect_err("a body with bytes past its value is not a base");
    assert!(
        refused.downcast_ref::<bincode::ErrorKind>().is_some(),
        "the decode refused, not a header check: {refused}"
    );
}

#[test]
fn a_file_and_its_header_disagreeing_on_its_length_are_refused_before_the_body_is_read() {
    // The file's length and the header's `body_len` are two claims, and the
    // body's read is sized only once they agree — so neither side of a
    // disagreement sizes anything. A file extended past its body (a hole:
    // the length costs no disk) would otherwise be read whole before its
    // refusal, every time a history read selects it; a header claiming every
    // byte a `u64` counts would otherwise overflow the sum the agreement is
    // checked by.
    let dir = tempdir().unwrap();
    write(dir.path(), 3, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
    let path = checkpoint_path(dir.path(), 3);
    let honest = fs::read(&path).unwrap();
    let load_refusal = || {
        list(dir.path()).unwrap()[0]
            .load::<Vec<u64>>()
            .expect_err("a length the file and its header disagree on is not a base")
            .to_string()
    };

    let extended = 1u64 << 27;
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(extended)
        .unwrap();
    let refused = load_refusal();
    assert!(
        refused.contains(&format!("checkpoint file is {extended} bytes")),
        "got {refused}"
    );

    let mut overclaimed = honest;
    overclaimed[BODY_LEN_AT..BODY_LEN_AT + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&path, &overclaimed).unwrap();
    let refused = load_refusal();
    assert!(
        refused.contains(&format!("its header claims {HEADER_LEN} + {}", u64::MAX)),
        "got {refused}"
    );
}

#[test]
fn a_foreign_stamp_is_refused_by_name_with_the_remedy() {
    // A checkpoint under another format names the stamp it found, the
    // stamp this build writes, and the ruled remedy — the sentence the
    // daemon prints through `BadCheckpoint` when the fallback chain is
    // exhausted. It is the FIRST check after the length, so an old-format
    // header's other fields are never read as this format's.
    let dir = tempdir().unwrap();
    write(dir.path(), 3, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
    let path = checkpoint_path(dir.path(), 3);
    let mut data = fs::read(&path).unwrap();
    data[..4].copy_from_slice(b"SKC2");
    fs::write(&path, &data).unwrap();
    let refused = list(dir.path()).unwrap()[0]
        .load::<Vec<u64>>()
        .expect_err("another format's checkpoint is not a base")
        .to_string();
    for named in ["`SKC2`", "`SKC4`", "not this build's format", "delete the data directory"] {
        assert!(refused.contains(named), "{named} missing from: {refused}");
    }
}

#[test]
fn a_header_reads_without_its_body_under_the_checks_a_header_holds() {
    // `header` is what a published head names a base by, so it must cost
    // the header and never the world: it reads HEADER_LEN bytes and stops
    // — a file cut to its header answers the same, where `load`, which
    // verifies the body, refuses — and it holds those bytes to every check
    // that needs no body: this build's stamp, and a seq the name agrees
    // with.
    let dir = tempdir().unwrap();
    write(dir.path(), 7, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
    let path = checkpoint_path(dir.path(), 7);
    let data = fs::read(&path).unwrap();
    let written_hash = <[u8; 32]>::from(Sha256::digest(&data[HEADER_LEN..]));
    let header_of = |dir: &Path| list(dir).unwrap()[0].header();

    let header = header_of(dir.path()).expect("the header reads");
    let claimed = CheckpointHeader {
        seq: Seq(7),
        chain_head: CHAIN_HEAD,
        body_hash: written_hash,
        len: data.len() as u64,
    };
    assert_eq!(header, claimed, "the coordinate, the chain there, the body's hash, the length");
    assert_eq!(
        header.len,
        fs::metadata(&path).unwrap().len(),
        "the length the header claims is the file's, for a checkpoint that is a base"
    );

    // Cut to its header: nothing after it is read, so the answer is the
    // same — the length included, which is the HEADER's claim and not a
    // `stat` of the file — and the body `load` must verify is no longer
    // there.
    fs::write(&path, &data[..HEADER_LEN]).unwrap();
    let header = header_of(dir.path()).expect("the header reads without its body");
    assert_eq!(header, claimed);
    assert!(list(dir.path()).unwrap()[0].load::<Vec<u64>>().is_err());

    // One byte short of a header is not one.
    fs::write(&path, &data[..HEADER_LEN - 1]).unwrap();
    let refused = header_of(dir.path()).expect_err("short of its own header");
    assert!(refused.to_string().contains("shorter"), "got {refused}");

    // Another format's stamp is refused by name, as `load` refuses it.
    let mut foreign = data.clone();
    foreign[..4].copy_from_slice(b"SKC3");
    fs::write(&path, &foreign).unwrap();
    let refused = header_of(dir.path()).expect_err("another format's header");
    assert!(refused.to_string().contains("`SKC3`"), "got {refused}");

    // A whole, valid file under another checkpoint's name: the seq its
    // bytes claim is not the seq its name does.
    fs::write(&path, &data).unwrap();
    fs::rename(&path, checkpoint_path(dir.path(), 8)).unwrap();
    let listed = list(dir.path()).unwrap();
    assert_eq!(listed[0].seq, 8);
    let refused = listed[0].header().expect_err("a misnamed header");
    assert!(refused.to_string().contains("claims seq 7"), "got {refused}");
}

#[test]
fn a_body_that_survives_its_checksum_and_will_not_decode_is_a_skew() {
    // The one refusal the checksum has already ruled rot out of: these ARE
    // the bytes that were written, and they still are not a `W`. That is a
    // binary on the wrong side of a `W` format change, and the
    // serializer's own account is the only thing that says so — where a
    // bare "this base does not load" sends an operator to their disk.
    //
    // `bool` is the cheapest certain wrong type: its decoder rejects any
    // byte but 0 and 1, and a `Vec`'s first byte is its length.
    let refusal_for = |len: usize| {
        let dir = tempdir().unwrap();
        write(dir.path(), 3, &vec![10u64; len], &CHAIN_HEAD).expect("fixture checkpoint");
        let refused = list(dir.path()).unwrap()[0]
            .load::<bool>()
            .expect_err("a body that is not a `bool` does not load as one");
        assert!(
            !refused.to_string().contains("checksum"),
            "the checksum passed; this is a skew, not rot: {refused}"
        );
        // …and the account IS the serializer's refusal, boxed once, so a
        // caller holding it reaches the serializer's own error.
        assert!(
            refused.downcast_ref::<bincode::ErrorKind>().is_some(),
            "the serializer's refusal travels as itself: {refused}"
        );
        refused.to_string()
    };
    // Two bodies rejected for two reasons, so what travels has to be the
    // SERIALIZER's account of these bytes: a sentence this module could
    // have written instead would be the same for both, and would leave an
    // operator with no more than "it did not load".
    assert_ne!(refusal_for(3), refusal_for(7));
}

#[test]
fn a_base_that_cannot_be_read_says_so_rather_than_looking_damaged() {
    // Unreadable is not the same remedy as damaged, and the two were once
    // one silent refusal. A directory bearing a checkpoint's name is the
    // deterministic, privilege-free injection: `list` parses names and not
    // file types, which the `journal_path` caller contract already says.
    let dir = tempdir().unwrap();
    fs::create_dir(checkpoint_path(dir.path(), 5)).unwrap();
    let listed = list(dir.path()).unwrap();
    assert_eq!(listed.len(), 1, "a name is a checkpoint, whatever the file type");
    let refused = listed[0]
        .load::<Vec<u64>>()
        .expect_err("a base that cannot be read does not load");
    // …and its account is the read's own failure, which names the remedy —
    // never a checksum's or a hash's, which would send an operator to restore
    // media that was never damaged.
    assert!(
        refused.downcast_ref::<io::Error>().is_some(),
        "the read's own failure travels, not a damage account: {refused}"
    );
}

#[test]
fn only_the_name_the_writer_emits_is_a_checkpoint() {
    // `checkpoint.07` parses as 7 under a bare `u64::from_str`, so without
    // the round trip it is a second entry at one coordinate — and
    // `retain` counts entries, so a configured `N = 2` fallback chain
    // would silently hold one real base and one alias of it.
    let dir = tempdir().unwrap();
    write(dir.path(), 7, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
    fs::copy(checkpoint_path(dir.path(), 7), dir.path().join("checkpoint.07")).unwrap();
    fs::copy(checkpoint_path(dir.path(), 7), dir.path().join("checkpoint.+7")).unwrap();
    let listed = list(dir.path()).unwrap();
    assert_eq!(listed.len(), 1, "only one spelling names a checkpoint");
    assert_eq!(listed[0].seq, 7);
}

#[test]
fn checkpoints_list_in_seq_order_across_a_digit_boundary() {
    // Every operation over `list`'s answer reads a position as an age:
    // `retain` deletes from the front as the oldest, `select_base` walks
    // from the back as the newest and reads the front as the floor. Name
    // order and seq order agree while seqs have one digit — and
    // `checkpoint.10` sorts BEFORE `checkpoint.9` by name.
    let seqs_in = |dir: &Path| -> Vec<u64> {
        list(dir).unwrap().iter().map(|cp| cp.seq).collect()
    };
    let dir = tempdir().unwrap();
    for seq in [10, 1, 100, 9, 99] {
        write(dir.path(), seq, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
    }
    assert_eq!(seqs_in(dir.path()), vec![1, 9, 10, 99, 100]);
    // …so retention keeps the numerically newest, and names the floor
    // from them.
    assert_eq!(retain(dir.path(), 2).unwrap(), Some(99));
    assert_eq!(
        seqs_in(dir.path()),
        vec![99, 100],
        "retention kept other than the newest bases"
    );
}

/// THE SEAM AT THE CHECKPOINT WRITE (`test-hooks`): each of its three steps,
/// armed to fail, answers `WriteFail::Io` of the kind armed, naming the
/// step, and leaves what the step's card says — nothing at the creation; no
/// base and no temp file at the sync, the temp file removed before the
/// failure is answered; the base ON DISK at the directory's sync after the
/// rename. Each arm fires ONCE: the same write, re-run with the step
/// unarmed, lands whole. And each of the three takes a panic arm, which
/// unwinds in the step's place and leaves what an unwind leaves — the `Err`
/// arm's removal not run: nothing at the creation, the WHOLE temp file at
/// the sync (header and body, the size the next open reports), the base at
/// the directory's sync — and fires once likewise, the write after it
/// landing over whatever was left.
#[test]
fn each_checkpoint_step_fires_its_arm_once_and_leaves_what_its_card_says() {
    let body_len = codec().serialize(&world()).unwrap().len() as u64;
    for step in [Step::CheckpointCreate, Step::CheckpointSync, Step::CheckpointDirSync] {
        let landed = step == Step::CheckpointDirSync;
        let seam = Seam::default();

        // The failure arm.
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("checkpoint.tmp");
        let base = checkpoint_path(dir.path(), 7);
        seam.fail_the_next(step, io::ErrorKind::StorageFull);
        let refused = super::write(dir.path(), 7, &world(), &CHAIN_HEAD, &seam)
            .expect_err("the armed step fails the write");
        let e = match refused {
            WriteFail::Io(e) => e,
            WriteFail::Serialize(_) => unreachable!("the world serializes"),
        };
        assert_eq!(e.kind(), io::ErrorKind::StorageFull, "{step:?}: the kind armed");
        assert!(e.to_string().contains(&format!("{step:?}")), "{step:?}: names the step: {e}");
        assert!(!tmp.exists(), "{step:?}: no temp file survives a failure");
        assert_eq!(base.exists(), landed, "{step:?}: the base is on disk iff the rename ran");
        assert!(seam.armed_steps().is_empty(), "{step:?}: fired and disarmed");
        super::write(dir.path(), 7, &world(), &CHAIN_HEAD, &seam)
            .expect("the step, unarmed, runs for real");
        assert!(!tmp.exists());
        assert_eq!(list(dir.path()).unwrap()[0].load::<Vec<u64>>().unwrap().world, world());

        // The panic arm.
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("checkpoint.tmp");
        let base = checkpoint_path(dir.path(), 7);
        seam.panic_at_the_next(step);
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            super::write(dir.path(), 7, &world(), &CHAIN_HEAD, &seam)
        }));
        assert!(unwound.is_err(), "{step:?}: the armed step unwinds the write");
        match step {
            Step::CheckpointCreate => assert!(!tmp.exists() && !base.exists(), "nothing"),
            Step::CheckpointSync => {
                assert!(!base.exists(), "no base");
                assert_eq!(
                    fs::metadata(&tmp).expect("the unwind left the temp file").len(),
                    HEADER_LEN as u64 + body_len,
                    "…whole: the header and the body, as written"
                );
            }
            Step::CheckpointDirSync => assert!(!tmp.exists() && base.exists(), "the base"),
            Step::JournalAppend | Step::JournalBarrier | Step::JournalRepair => {
                unreachable!("not a checkpoint step")
            }
        }
        assert!(seam.armed_steps().is_empty(), "{step:?}: fired and disarmed");
        super::write(dir.path(), 7, &world(), &CHAIN_HEAD, &seam)
            .expect("the step, unarmed, runs for real over what the unwind left");
        assert!(!tmp.exists());
        assert_eq!(list(dir.path()).unwrap()[0].load::<Vec<u64>>().unwrap().world, world());
    }
}
