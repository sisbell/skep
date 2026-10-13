//! T3 — THE RECORD's ADMISSION: a canonical record admitted with its
//! anchorless fact; the hosted walk's trim; ONE VECTOR PER `PayloadError`
//! VARIANT `parse_enroll` raises over a form's bytes, each D-5 naming its
//! token; and D-6, a preview key that PARSES and is refused by the alg test
//! alone. (The name's grammar, the post's other field, is `name`'s suite.)

use skep_identity::{encode_enroll, parse_enroll, Enrollment, PublicKey, ALG_FNDSA512_PREVIEW_ED25519, FNDSA512_PREVIEW_ED25519_KEY_LEN, MAX_RECORD_BYTES, MLDSA65_ED25519_KEY_LEN};

use super::*;

/// A key of `alg`'s row: `raw_len` bytes of `byte`, as hex — any bytes of
/// the row's length parse (the syntax-only admission, AUTH-1.4).
fn key(alg: &str, raw_len: usize, byte: u8) -> PublicKey {
    PublicKey::parse(alg, &format!("{byte:02x}").repeat(raw_len)).expect("a key of the row's length")
}

/// A production-kind key.
fn production(byte: u8) -> PublicKey {
    key(ALG_MLDSA65_ED25519, MLDSA65_ED25519_KEY_LEN, byte)
}

/// A canonical one-key record over a production key, `anchor` its flag.
fn one_key(anchor: bool) -> String {
    encode_enroll(&[Enrollment::new(production(0xab), anchor, None).expect("no label")])
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
        Enrollment::new(production(1), false, Some("laptop".into())).expect("a label"),
        Enrollment::new(production(2), true, None).expect("no label"),
        Enrollment::new(production(3), true, None).expect("no label"),
    ]);
    assert!(!admit(three.as_bytes()).expect("the --anchors record's shape").anchorless(), "one anchor-flagged entry is enough");
}

/// T3: THE TRIM — one trailing `\n`, and a `\r\n`, admitted, the record
/// handed on without them — exactly as the hosted walk trims.
#[test]
fn a_trailing_line_break_is_trimmed_as_the_hosted_walk_trims() {
    let canonical = one_key(true);
    for ending in ["\n", "\r\n", "\r\n\r\n"] {
        let record = admit(format!("{canonical}{ending}").as_bytes()).unwrap_or_else(|e| panic!("{ending:?}: {e:?}"));
        assert_eq!(record.bytes(), canonical.as_bytes(), "{ending:?}");
    }
}

/// T3: ONE VECTOR PER REACHABLE `PayloadError` VARIANT, each refused D-5
/// naming its token: a BOM, uppercase hex, a reordered member, an extra
/// member, a trailing byte and the deleted `ed25519` token (`bad_record`
/// each); two entries of one key (`duplicate_key:2`); zero entries
/// (`empty`); a byte that is not UTF-8 (`not_utf8`); one byte past the
/// record cap (`too_large`).
#[test]
fn each_reachable_payload_fault_is_refused_naming_its_token() {
    let canonical = one_key(true);
    let hex = production(0xab).to_hex();
    let entry = format!(r#"{{"alg":"{ALG_MLDSA65_ED25519}","key":"{hex}","anchor":true}}"#);
    assert_eq!(canonical, format!(r#"{{"type":"skep-enroll","keys":[{entry}]}}"#), "the canonical spelling the vectors spoil");
    let twice = Enrollment::new(production(0xab), true, None).expect("no label");
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
        Enrollment::new(production(1), true, None).expect("no label"),
        Enrollment::new(key(ALG_FNDSA512_PREVIEW_ED25519, FNDSA512_PREVIEW_ED25519_KEY_LEN, 2), false, None).expect("no label"),
    ]);
    assert!(matches!(refused(mixed.as_bytes()), RecordRefused::PreviewKey { .. }));
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
