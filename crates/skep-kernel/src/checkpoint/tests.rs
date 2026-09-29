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
    };
    assert_eq!(header, claimed, "the coordinate, the chain there, the body's hash");

    // Cut to its header: nothing after it is read, so the answer is the
    // same — and the body `load` must verify is no longer there.
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
    assert!(listed[0].load::<Vec<u64>>().is_err());
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
