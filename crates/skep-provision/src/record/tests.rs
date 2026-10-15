//! T3 — THE RECORD's ADMISSION: a canonical record admitted with its
//! anchorless fact; the hosted walk's trim exactly — every trailing run of
//! line breaks, and nothing else — and its two spellings read back from
//! `skep-client`; ONE VECTOR PER `PayloadError` VARIANT `parse_enroll`
//! raises over a form's bytes, each D-5 naming its token, and the cap first
//! over a body that is also not text; D-6, a preview key that PARSES and is
//! refused by the alg test alone; and the hosted genesis's own two
//! refusals, each D-5 — a half that does not decode, more entries than its
//! cap — in the daemon's order, read back from `skepd`. (The name's grammar,
//! the post's other field, is `name`'s suite.)

use skep_identity::{encode_enroll, parse_enroll, Enrollment, PublicKey, ALG_FNDSA512_PREVIEW_ED25519, FNDSA512_PREVIEW_ED25519_KEY_LEN, MAX_RECORD_BYTES};

use super::*;

/// A key of `alg`'s row: `raw_len` bytes of `byte`, as hex — any bytes of
/// the row's length parse (the syntax-only admission, AUTH-1.4).
fn key(alg: &str, raw_len: usize, byte: u8) -> PublicKey {
    PublicKey::parse(alg, &format!("{byte:02x}").repeat(raw_len)).expect("a key of the row's length")
}

/// A canonical one-key record over a production key, `anchor` its flag.
fn one_key(anchor: bool) -> String {
    encode_enroll(&[Enrollment::new(decodable_key(0xab), anchor, None).expect("no label")])
}

/// The refusal's token, or a panic naming the admission.
fn refused(bytes: &[u8]) -> RecordRefused {
    match admit(bytes) {
        Err(r) => r,
        Ok(r) => panic!("admitted: {r:?}"),
    }
}

/// T3: a CANONICAL one-key record — `encode_enroll` over a production key —
/// admitted, `anchorless` false with the anchor flag set and true without
/// it; its bytes handed on as they came.
#[test]
fn a_canonical_record_is_admitted_with_its_anchorless_fact() {
    let anchored = one_key(true);
    let record = admit(anchored.as_bytes()).expect("a canonical record");
    assert!(!record.anchorless());
    assert_eq!(record.bytes(), anchored.as_bytes());
    let bare = one_key(false);
    assert!(admit(bare.as_bytes()).expect("a canonical record").anchorless());
    let three = encode_enroll(&[
        Enrollment::new(decodable_key(1), false, Some("laptop".into())).expect("a label"),
        Enrollment::new(decodable_key(2), true, None).expect("no label"),
        Enrollment::new(decodable_key(3), true, None).expect("no label"),
    ]);
    assert!(!admit(three.as_bytes()).expect("the --anchors record's shape").anchorless(), "one anchor-flagged entry is enough");
}

/// T3: THE TRIM IS H2's EXACTLY, over every run: a record followed by any
/// run of `\r` and `\n` — each of the thirty of one to four, `\n`, `\r\n`
/// and `\r\n\r\n` among them — is admitted and handed on without it; the
/// same run holding a space or a tab at any place, and the run set BEFORE
/// the record, are none of the walk's to trim and are refused `bad_record`:
/// the form admits no record the walk would refuse.
#[test]
fn the_trim_takes_trailing_line_breaks_in_any_mix_and_nothing_else() {
    let canonical = one_key(true);
    let mut runs = Vec::new();
    for n in 1..=4u32 {
        for bits in 0..1u32 << n {
            runs.push((0..n).map(|i| if (bits >> i) & 1 == 1 { '\r' } else { '\n' }).collect::<String>());
        }
    }
    assert_eq!(runs.len(), 30);
    for run in &runs {
        let record = admit(format!("{canonical}{run}").as_bytes()).unwrap_or_else(|e| panic!("{run:?}: {e:?}"));
        assert_eq!(record.bytes(), canonical.as_bytes(), "{run:?}");
        for at in 0..=run.len() {
            for other in [' ', '\t'] {
                let mut spoiled = run.clone();
                spoiled.insert(at, other);
                assert_eq!(refused(format!("{canonical}{spoiled}").as_bytes()).token(), "bad_record", "{spoiled:?}");
            }
        }
        assert_eq!(refused(format!("{run}{canonical}").as_bytes()).token(), "bad_record", "{run:?} before the record");
    }
}

/// THE WALK's H2, READ BACK at test time from `skep-client`'s
/// `src/ceremony/claim/hosted.rs`: its trim and its production-kind test in
/// the spellings `admit` copies, so an edit to either there is a red test
/// here until the copy follows it.
#[test]
fn the_admission_copies_the_hosted_walks_h2_as_it_stands() {
    let walk = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../skep-client/src/ceremony/claim/hosted.rs")).expect("skep-client's hosted walk");
    for spelling in [".trim_end_matches(['\\n', '\\r'])", "e.key.alg() != skep_identity::ALG_MLDSA65_ED25519"] {
        assert!(walk.contains(spelling), "the hosted walk no longer spells H2 as `record::admit` copies it: `{spelling}`");
    }
}

/// T3: ONE VECTOR PER REACHABLE `PayloadError` VARIANT, each refused D-5
/// naming its token: a BOM, uppercase hex, a reordered member, an extra
/// member, a trailing byte and the deleted `ed25519` token (`bad_record`
/// each); two entries of one key (`duplicate_key:2`); zero entries
/// (`empty`); a byte that is not UTF-8 (`not_utf8`); one byte past the
/// record cap (`too_large`) — and the cap first, `parse_enroll`'s own order,
/// over a body past it whose first byte is not UTF-8 too.
#[test]
fn each_reachable_payload_fault_is_refused_naming_its_token() {
    let canonical = one_key(true);
    let hex = decodable_key(0xab).to_hex();
    let entry = format!(r#"{{"alg":"{ALG_MLDSA65_ED25519}","key":"{hex}","anchor":true}}"#);
    assert_eq!(canonical, format!(r#"{{"type":"skep-enroll","keys":[{entry}]}}"#), "the canonical spelling the vectors spoil");
    let twice = Enrollment::new(decodable_key(0xab), true, None).expect("no label");
    let mut not_utf8 = canonical.clone().into_bytes();
    not_utf8.insert(10, 0xff);
    let vectors: Vec<(&str, Vec<u8>, &str)> = vec![
        ("a BOM", format!("\u{feff}{canonical}").into_bytes(), "bad_record"),
        ("uppercase hex", canonical.replace(&hex, &hex.to_uppercase()).into_bytes(), "bad_record"),
        ("a reordered member", format!(r#"{{"keys":[{entry}],"type":"skep-enroll"}}"#).into_bytes(), "bad_record"),
        ("an extra member", format!(r#"{{"type":"skep-enroll","keys":[{entry}],"x":1}}"#).into_bytes(), "bad_record"),
        ("a trailing byte", format!("{canonical}x").into_bytes(), "bad_record"),
        ("the deleted ed25519 token", format!(r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{}","anchor":true}}]}}"#, "ab".repeat(32)).into_bytes(), "bad_record"),
        ("two entries of one key", encode_enroll(&[twice.clone(), twice]).into_bytes(), "duplicate_key:2"),
        ("zero entries", encode_enroll(&[]).into_bytes(), "empty"),
        ("a byte that is not UTF-8", not_utf8, "not_utf8"),
        ("one byte past the cap", vec![b'a'; MAX_RECORD_BYTES + 1], "too_large"),
        ("one byte past the cap, and not UTF-8: the cap first", [vec![0xff], vec![b'a'; MAX_RECORD_BYTES]].concat(), "too_large"),
    ];
    for (what, bytes, token) in vectors {
        let refusal = refused(&bytes);
        assert!(matches!(refusal, RecordRefused::NotARecord(_)), "{what}: D-5, not {refusal:?}");
        assert_eq!(refusal.token(), token, "{what}");
        let said: &dyn std::error::Error = &refusal;
        assert_eq!(said.to_string(), token, "{what}: Display is the token, never a second vocabulary");
    }
}

/// T3: D-6 — a one-key record over the PREVIEW kind PARSES (the assertion
/// below) and is refused by the alg test alone, naming the token; a record
/// mixing the kinds is refused the same.
#[test]
fn a_preview_key_parses_and_is_refused_by_the_alg_test_alone() {
    let preview = encode_enroll(&[Enrollment::new(key(ALG_FNDSA512_PREVIEW_ED25519, FNDSA512_PREVIEW_ED25519_KEY_LEN, 0xcd), true, None).expect("no label")]);
    assert!(parse_enroll(preview.as_bytes()).is_ok(), "the preview kind is an ALGS row: parse_enroll admits it");
    let refusal = refused(preview.as_bytes());
    assert_eq!(refusal, RecordRefused::PreviewKey { alg: ALG_FNDSA512_PREVIEW_ED25519 });
    assert_eq!(refusal.token(), "preview_key");
    assert_eq!(refusal.to_string(), "preview_key");
    let mixed = encode_enroll(&[
        Enrollment::new(decodable_key(1), true, None).expect("no label"),
        Enrollment::new(key(ALG_FNDSA512_PREVIEW_ED25519, FNDSA512_PREVIEW_ED25519_KEY_LEN, 2), false, None).expect("no label"),
    ]);
    assert!(matches!(refused(mixed.as_bytes()), RecordRefused::PreviewKey { .. }));
}

/// A RECORD THE GENESIS CAN NEVER TAKE IS REFUSED, D-5, before any docker
/// run — the daemon's two refusals of a hosted claim's genesis, in its
/// order: a half that does not decode; sixteen decodable entries admitted
/// and a seventeenth refused; an undecodable third of seventeen answering
/// `undecodable_key`, the decode first; and an undecodable eighteenth
/// answering `too_many_enrolled`, decoded no further than one past the cap.
#[test]
fn a_record_the_genesis_can_never_take_is_refused() {
    let record_of = |keys: Vec<PublicKey>| encode_enroll(&keys.into_iter().map(|k| Enrollment::new(k, false, None).expect("no label")).collect::<Vec<_>>());
    let decodable = |n: u8| (0..n).map(decodable_key).collect::<Vec<_>>();
    assert!(key_decodes(&decodable_key(0x9f)) && !key_decodes(&undecodable_key()), "the two fixtures are what they say");
    assert_eq!(refused(record_of(vec![undecodable_key()]).as_bytes()), RecordRefused::UndecodableKey);
    assert!(admit(record_of(decodable(16)).as_bytes()).is_ok(), "sixteen, the cap");
    assert_eq!(refused(record_of(decodable(17)).as_bytes()), RecordRefused::TooManyKeys);
    let mut third = decodable(17);
    third[2] = undecodable_key();
    assert_eq!(refused(record_of(third).as_bytes()).token(), "undecodable_key", "the decode before the count");
    let mut eighteenth = decodable(18);
    eighteenth[17] = undecodable_key();
    assert_eq!(refused(record_of(eighteenth).as_bytes()).token(), "too_many_enrolled", "decoded no further than one past the cap");
    for (refusal, token) in [(RecordRefused::UndecodableKey, "undecodable_key"), (RecordRefused::TooManyKeys, "too_many_enrolled")] {
        assert_eq!(refusal.to_string(), token, "Display is the daemon's own word");
    }
}

/// THE GENESIS's REFUSALS ARE THE DAEMON's, READ BACK at test time from
/// the core's `crates/skep-core/src/auth/policy/credential.rs`: the cap [`MAX_GENESIS_KEYS`]
/// restates, and the decode over one entry past it ahead of the count — so
/// an edit to either there is a red test here until the copy follows it.
#[test]
fn the_genesis_refusals_copy_the_daemons_precheck_as_it_stands() {
    let precheck = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../skep-core/src/auth/policy/credential.rs")).expect("skepd's credential precheck");
    let at = |spelling: &str| precheck.find(spelling).unwrap_or_else(|| panic!("skepd's precheck no longer spells the genesis's refusals as `record::admit` copies them: `{spelling}`"));
    at(&format!("const MAX_ENROLLED_KEYS: usize = {MAX_GENESIS_KEYS};"));
    at("const MAX_GENESIS_KEYS: usize = MAX_ENROLLED_KEYS;");
    at("const MAX_DECODED_KEYS: usize = MAX_GENESIS_KEYS + 1;");
    let decode_at = at("enrolling.iter().take(MAX_DECODED_KEYS).all(|e| skep_signature::key_decodes(&e.key))");
    let count_at = at("keys.len() > MAX_GENESIS_KEYS");
    assert!(decode_at < count_at, "skepd's precheck counts a genesis's keys before it decodes them");
}

/// The record's `Debug` carries its length and its fact, and nothing of
/// its bytes.
#[test]
fn a_records_debug_carries_none_of_its_bytes() {
    let record = admit(one_key(false).as_bytes()).expect("a canonical record");
    let shown = format!("{record:?}");
    assert!(!shown.contains("abab"), "{shown}");
    assert!(shown.contains("anchorless: true"), "{shown}");
}
