use super::*;
use crate::config::SaltSource;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

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

/// An unattested marker whose chain is NOT under test — the fixtures that
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

/// The attestation's two refused spellings, held at construction: tag 0
/// (the empty slot's own) and an empty blob — so no transaction can write
/// the marker the decoder refuses, and "unattested" is spelled only by the
/// absent value.
#[test]
fn an_attestation_holds_the_one_spelling_of_empty_at_construction() {
    assert_eq!(Attestation::new(0, vec![1]), Err(AttestationError::UnsignedTag));
    assert_eq!(Attestation::new(1, Vec::new()), Err(AttestationError::EmptyBlob));
    let a = Attestation::new(3, vec![7, 7]).unwrap();
    assert_eq!((a.sig_alg(), a.sig()), (3, &[7u8, 7][..]));
    assert_eq!(format!("{a:?}"), "Attestation { sig_alg: 3, sig_len: 2 }");
    // Each refusal's sentence names the rule the value broke, since that
    // sentence may be the whole of what reaches whoever sent the value.
    assert_eq!(
        AttestationError::UnsignedTag.to_string(),
        "an attestation must name a non-zero tag: tag 0 is the empty slot's own"
    );
    assert_eq!(
        AttestationError::EmptyBlob.to_string(),
        "an attestation must carry a non-empty signature blob"
    );
}

/// A FILLED marker's bytes are the empty layout with the tag and the blob
/// in the slot's own place — the tag at byte 88, the length prefix at
/// 89..97, the blob after — and no other marker byte moves: the layout
/// doc's claim, pinned against the encoder's own output.
#[test]
fn a_filled_marker_appends_the_blob_after_the_tag_and_moves_no_other_byte() {
    let blob = vec![0xC3u8; 5];
    let attestation = Attestation::new(1, blob.clone()).unwrap();
    let records = vec![vec![9u8, 8, 7]];
    let (empty, chain_e) =
        encode_txn(2, records.clone(), &CHAIN_GENESIS, FIXED_SALT, None).unwrap();
    let (filled, chain_f) =
        encode_txn(2, records, &CHAIN_GENESIS, FIXED_SALT, Some(&attestation)).unwrap();
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
    // The chain: SHA-256 over the chain's genesis value, the record
    // payload as framed, the marker's own pre-chain fields in their wire
    // form, then the salt — the last bytes before finalize.
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
    // attested. A filled slot under a non-zero tag DECODES — the kernel
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
