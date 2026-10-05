//! THE VECTOR SET at this parser (`tests/vectors/records.json`): every
//! vector meets the answer the set pins at the parse — a record, or its
//! refusal's cause — every admitted body is its own re-encoding and a
//! fixpoint, and the set pins the cap this crate does, so a parser another
//! reader of the bodies builds reads the pins from the set and not from a
//! second transcription. (`skep-resolve` builds none: it calls this crate's
//! `parse`.)
//!
//! Beside the set, the laws body.rs states for every input, each tried on
//! inputs no hand chose: THE ESCAPE TABLE at every Unicode scalar value —
//! each spelled exactly as the table states, and each read back as itself —
//! and THE ADMISSION SENTENCE with the parse's totality over every one-byte
//! mutant of every admitted vector: a mutant the parse admits is its own
//! canonical encoding, and no mutant makes the parse panic.

use std::path::Path;

use serde_json::Value;
use skep_registry::{
    encode, parse, rows, Body, BodyKind, Endpoint, Kind, Member, Origins, Record, Refusal,
    MAX_REGISTRY_RECORD_BYTES,
};

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/records.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("the vector set is JSON")
}

/// A vector's bytes: its `bytes` string, or its `bytes_hex`.
fn bytes_of(vector: &Value) -> Vec<u8> {
    if let Some(text) = vector["bytes"].as_str() {
        return text.as_bytes().to_vec();
    }
    let hex = vector["bytes_hex"].as_str().expect("a vector carries bytes or bytes_hex");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// A vector's `kind`: the kind the caller names, standing in for the link's
/// type slot.
fn kind_of(vector: &Value) -> BodyKind {
    match vector["kind"].as_str().expect("a kind") {
        "binding" => BodyKind::Binding,
        "endpoint" => BodyKind::Endpoint,
        _ => panic!("{}: an unknown kind", vector["name"]),
    }
}

/// Every vector, one answer at the parse; the admitted ones read from both
/// sides of the canonical rule.
#[test]
fn the_vector_set_meets_one_answer_at_this_parser() {
    let fixture = fixture();
    assert_eq!(fixture["cap"].as_u64(), Some(MAX_REGISTRY_RECORD_BYTES as u64));
    let vectors = fixture["vectors"].as_array().expect("vectors");
    let (mut admitted, mut refused) = (0, 0);
    for vector in vectors {
        let name = vector["name"].as_str().expect("a name");
        let kind = kind_of(vector);
        let bytes = bytes_of(vector);
        let answer = vector["parse"].as_str().expect("the parse's answer");
        match (answer, parse(kind, &bytes)) {
            ("ok", Ok(record)) => {
                assert_eq!(record.body.kind(), kind, "{name}: the body's kind is the slot's");
                assert_eq!(
                    encode(&record.body, record.sig.as_deref()).as_bytes(),
                    bytes.as_slice(),
                    "{name}: b == encode(parse(b))"
                );
                assert_eq!(
                    Some(record.canonical_sigless().as_str()),
                    vector["canonical_sigless"].as_str(),
                    "{name}: the sig-less canonical projection"
                );
                assert_eq!(record.sig.as_deref(), vector["sig"].as_str(), "{name}: the sig as found");
                let again = parse(kind, record.canonical_sigless().as_bytes()).expect("a fixpoint");
                assert_eq!(again, Record { body: record.body.clone(), sig: None }, "{name}");
                admitted += 1;
            }
            ("ok", Err(refusal)) => panic!("{name}: the set admits it, the parser refuses {refusal}"),
            (expected, Err(refusal)) => {
                assert_eq!(refusal.token(), expected, "{name}");
                refused += 1;
            }
            (expected, Ok(record)) => {
                panic!("{name}: the set refuses it ({expected}), the parser admits {record:?}")
            }
        }
    }
    assert!(admitted >= 11 && refused >= 60, "{admitted} admitted, {refused} refused");
    // The vectors the lane names and the escape table's, each present by name.
    for required in [
        "binding_canonical",
        "binding_spec_example_spaced",
        "binding_with_replaces",
        "endpoint_canonical_three_origins",
        "endpoint_spec_example_spaced",
        "endpoint_with_replaces",
        "number_as_prefix",
        "unknown_member",
        "wrong_type_endpoint_body_under_binding",
        "empty_origins",
        "prefix_twice",
        "past_the_cap",
        "with_sig",
        "strings_take_the_short_escapes_alone",
        "strings_past_ascii_stand_as_themselves",
        "escape_long_form_of_a_named_control",
        "escape_uppercase_hex",
        "escape_of_a_letter_past_ascii",
        "escape_of_an_astral_char",
        "escape_of_the_line_separator",
        "escape_of_del",
        "raw_control_in_a_string",
    ] {
        assert!(vectors.iter().any(|v| v["name"] == required), "the set names {required}");
    }
}

/// The two spec examples, in canonical form, byte for byte and in length;
/// the spaced spellings the spec shows are what the parse refuses; and the
/// endpoint's origins are the org's list in the order its bytes write them,
/// read off `into_vec` — the list the resolver walks — and never through
/// the encoder, which would undo a reordering the parse made.
#[test]
fn the_spec_examples_have_one_canonical_form_each() {
    let binding = r#"{"type":"binding","prefix":"1.5"}"#;
    let endpoint = r#"{"type":"endpoint","origins":["https://acme.example","https://acme.example.net","http://<acme's onion host>.onion"]}"#;
    assert_eq!(binding.len(), 33);
    assert_eq!(endpoint.len(), 116);
    for (kind, text, spaced) in [
        (BodyKind::Binding, binding, r#"{"type": "binding", "prefix": "1.5"}"#),
        (
            BodyKind::Endpoint,
            endpoint,
            r#"{"type": "endpoint", "origins": ["https://acme.example", "https://acme.example.net", "http://<acme's onion host>.onion"]}"#,
        ),
    ] {
        let record = parse(kind, text.as_bytes()).expect("canonical");
        assert_eq!(record.sig, None);
        assert_eq!(encode(&record.body, None), text);
        assert_eq!(parse(kind, spaced.as_bytes()).unwrap_err().token(), "not_canonical");
    }
    let Body::Binding(b) = parse(BodyKind::Binding, binding.as_bytes()).unwrap().body else {
        panic!("a binding")
    };
    assert_eq!((b.prefix.to_string(), b.replaces), ("1.5".to_owned(), None));
    let Body::Endpoint(e) = parse(BodyKind::Endpoint, endpoint.as_bytes()).unwrap().body else {
        panic!("an endpoint")
    };
    assert_eq!(e.replaces, None);
    assert_eq!(
        e.origins.into_vec(),
        ["https://acme.example", "https://acme.example.net", "http://<acme's onion host>.onion"],
        "the org's origins in the order the bytes list them"
    );
}

/// A REFUSAL NAMES THE MEMBER THAT FAULTED AS A VALUE: each member-bearing
/// cause carries its [`Member`], so a caller branches on the member it
/// matches and never on the token's text — every member, and every cause
/// that names one, here; the tokens are the vector set's.
#[test]
fn a_refusal_names_the_member_that_faulted() {
    let cases = [
        (BodyKind::Binding, r#"{"type":"binding"}"#, Refusal::MissingMember(Member::Prefix)),
        (BodyKind::Endpoint, r#"{"type":"endpoint"}"#, Refusal::MissingMember(Member::Origins)),
        (
            BodyKind::Binding,
            r#"{"type":"binding","prefix":true}"#,
            Refusal::NotAString(Member::Prefix),
        ),
        (
            BodyKind::Binding,
            r#"{"type":"binding","prefix":"1","replaces":"x"}"#,
            Refusal::NotAnAddress(Member::Replaces),
        ),
        (
            BodyKind::Binding,
            r#"{"type":"binding","prefix":"1","sig":null}"#,
            Refusal::NotAString(Member::Sig),
        ),
    ];
    for (kind, text, refusal) in cases {
        assert_eq!(parse(kind, text.as_bytes()), Err(refusal), "{text}");
    }
}

/// A BODY WITH TWO FAULTS ANSWERS THE EARLIER STAGE's, in the order
/// `parse`'s doc lists — the cap before the text, the object before the
/// number scan, the number scan before `type`, the member set before every
/// member's form (the row's own, `sig` and `replaces` each by a case of its
/// own), the members' forms one member at a time (`replaces`, then `sig`,
/// then the row's own) — and the value stage's two policies the parser
/// adopts: a member spelled twice read at its last occurrence, and a value
/// nested past 127 objects and arrays no JSON. None of these is in the
/// vector set: the set pins what every parser answers, and these pin this
/// one.
#[test]
fn a_body_answers_the_first_stage_that_faults() {
    let nested = |arrays: usize| {
        let (open, close) = ("[".repeat(arrays), "]".repeat(arrays));
        format!(r#"{{"type":"binding","prefix":"1.5","x":{open}{close}}}"#)
    };
    let (deep, too_deep) = (nested(126), nested(127));
    let bindings: [(&str, &str); 13] = [
        ("not_an_object", "[15]"),
        ("number", r#"{"type":"endpoint","prefix":15}"#),
        ("unknown_member", r#"{"type":"binding","tier":"root"}"#),
        ("not_an_address:replaces", r#"{"type":"binding","replaces":"x"}"#),
        ("not_an_address:replaces", r#"{"type":"binding","prefix":"x","replaces":"y"}"#),
        ("not_an_address:replaces", r#"{"type":"binding","prefix":"1","replaces":"x","sig":true}"#),
        ("not_canonical", r#"{"type":"binding","prefix":15,"prefix":"1.5"}"#),
        ("number", r#"{"type":"binding","prefix":"1.5","prefix":15}"#),
        ("not_canonical", r#"{"type":"endpoint","type":"binding","prefix":"1.5"}"#),
        ("unknown_member", &deep),
        ("not_json", &too_deep),
        ("unknown_member", r#"{"type":"binding","prefix":"1.5","sig":true,"tier":"root"}"#),
        ("unknown_member", r#"{"type":"binding","prefix":"1.5","replaces":"x","tier":"root"}"#),
    ];
    for (cause, text) in bindings {
        let answer = parse(BodyKind::Binding, text.as_bytes()).map_err(|r| r.token());
        assert_eq!(answer, Err(cause.to_owned()), "{text}");
    }
    let endpoint = parse(BodyKind::Endpoint, br#"{"type":"endpoint","origins":[],"sig":true}"#);
    assert_eq!(endpoint.unwrap_err().token(), "not_a_string:sig", "sig before the row's own");
    let past = vec![0xff_u8; MAX_REGISTRY_RECORD_BYTES + 1];
    assert_eq!(parse(BodyKind::Binding, &past), Err(Refusal::PastCap), "the cap before the text");
}

/// THE `type` MEMBER IS THE STRING ITS KIND's ROW HOLDS (REG-1.86 (a)): a
/// body spelled under its kind's row's string is a record of that kind, and
/// under every other row's string is `wrong_type` — so the table's column
/// is the one spelling the encoder writes and the parse holds a body to,
/// and the vector set, pinning the bytes, pins the table.
#[test]
fn the_type_member_is_the_string_its_kinds_row_holds() {
    let kinds = [
        (Kind::Binding, BodyKind::Binding, r#""prefix":"1.5""#),
        (Kind::Endpoint, BodyKind::Endpoint, r#""origins":["https://acme.example"]"#),
    ];
    for (kind, body_kind, member) in kinds {
        for r in rows() {
            let Some(ty) = r.type_value else { continue };
            let text = format!(r#"{{"type":"{ty}",{member}}}"#);
            let answer = parse(body_kind, text.as_bytes()).map_err(|refusal| refusal.token());
            if r == kind.row() {
                assert_eq!(answer.map(|record| record.canonical_sigless()), Ok(text), "{kind:?}");
            } else {
                assert_eq!(answer.err().as_deref(), Some("wrong_type"), "{ty} under {kind:?}");
            }
        }
    }
}

/// The escape table as body.rs's encoding paragraph states it (REG-1.86
/// (h)), written from the table and never from the encoder: the quote and
/// the backslash escaped, the five named C0 controls by their one-letter
/// forms, every other C0 control as `\u00` and two lowercase hex digits, and
/// every other scalar value as itself.
fn spelled(c: char) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    match c {
        '"' => "\\\"".to_owned(),
        '\\' => "\\\\".to_owned(),
        '\u{8}' => "\\b".to_owned(),
        '\u{9}' => "\\t".to_owned(),
        '\u{a}' => "\\n".to_owned(),
        '\u{c}' => "\\f".to_owned(),
        '\u{d}' => "\\r".to_owned(),
        '\u{0}'..='\u{1f}' => {
            let n = u32::from(c) as usize;
            format!("\\u00{}{}", char::from(HEX[n >> 4]), char::from(HEX[n & 0xf]))
        }
        c => c.to_string(),
    }
}

/// Every Unicode scalar value, U+0000 to U+10FFFF, in strings of 1,024 —
/// each the one origin of an endpoint whose encoding stays far under the cap.
fn every_scalar_in_strings_of_1024() -> Vec<String> {
    let scalars: Vec<char> = (0..=0x10_FFFF_u32).filter_map(char::from_u32).collect();
    scalars.chunks(1024).map(|chunk| chunk.iter().collect()).collect()
}

/// The endpoint whose one origin is `origin`.
fn endpoint_of(origin: String) -> Body {
    let origins = Origins::new(vec![origin]).expect("one origin");
    Body::Endpoint(Endpoint { origins, replaces: None })
}

/// THE ESCAPE TABLE AT EVERY SCALAR VALUE: `encode` spells each scalar
/// exactly as the table does — the short escapes and the lowercase hex
/// included, and nothing else escaped — so the bytes a signer signs are the
/// table's whatever a string holds; and the walk visits each scalar value
/// once, every code point but the 2,048 surrogates, which are none.
#[test]
fn every_scalar_value_takes_the_escape_tables_one_spelling() {
    let mut visited = 0;
    for origin in every_scalar_in_strings_of_1024() {
        let text = encode(&endpoint_of(origin.clone()), None);
        let mut rest = text
            .strip_prefix(r#"{"type":"endpoint","origins":[""#)
            .and_then(|t| t.strip_suffix(r#""]}"#))
            .expect("one string between the opening and the brace");
        for c in origin.chars() {
            let want = spelled(c);
            assert!(
                rest.starts_with(&want),
                "U+{:04X}: written {:?}, the table spells {want:?}",
                u32::from(c),
                rest.chars().take(6).collect::<String>()
            );
            rest = &rest[want.len()..];
            visited += 1;
        }
        assert_eq!(rest, "", "no byte after the last character's spelling");
    }
    assert_eq!(visited, 0x11_0000 - 0x800, "every scalar value, once");
}

/// EVERY BODY A CALLER BUILDS IS A RECORD, at every scalar value: an
/// endpoint whose origin holds any of them encodes to bytes the parse admits
/// as that same body.
#[test]
fn every_scalar_value_in_a_string_encodes_to_a_record() {
    for origin in every_scalar_in_strings_of_1024() {
        let first = origin.chars().next().map_or(0, u32::from);
        let body = endpoint_of(origin);
        let text = encode(&body, None);
        let record = parse(BodyKind::Endpoint, text.as_bytes())
            .unwrap_or_else(|refusal| panic!("the string from U+{first:04X}: refused, {refusal}"));
        assert_eq!(record, Record { body, sig: None }, "the string from U+{first:04X}");
    }
}

/// The bytes the admitted vectors' one-byte mutants are drawn with: the
/// whitespace JSON skips, its structure and escape letters, digits and
/// signs, two hex letters in capitals, NUL, DEL, a lone continuation byte,
/// and a byte no UTF-8 holds.
const SUBSTITUTES: &[u8] = b" \t\n\"\\/{}[]:,.+-019eAFbnu\x00\x7f\x80\xff";

/// Every one-byte mutant of every admitted vector, under its kind: each byte
/// deleted, each SUBSTITUTE written over it, and each inserted before it and
/// after the last. An admitted vector added later joins without an edit here.
fn one_byte_mutants() -> Vec<(BodyKind, Vec<u8>)> {
    let fixture = fixture();
    let mut mutants = Vec::new();
    for vector in fixture["vectors"].as_array().expect("vectors") {
        if vector["parse"] != "ok" {
            continue;
        }
        let (kind, bytes) = (kind_of(vector), bytes_of(vector));
        for i in 0..=bytes.len() {
            for &b in SUBSTITUTES {
                let mut inserted = bytes.clone();
                inserted.insert(i, b);
                mutants.push((kind, inserted));
            }
            if i < bytes.len() {
                let mut deleted = bytes.clone();
                deleted.remove(i);
                mutants.push((kind, deleted));
                for &b in SUBSTITUTES {
                    let mut written = bytes.clone();
                    written[i] = b;
                    mutants.push((kind, written));
                }
            }
        }
    }
    mutants
}

/// THE PARSE IS TOTAL: it answers every one-byte mutant of every admitted
/// vector — a record or a refusal — and panics on none.
#[test]
fn the_parse_answers_every_one_byte_mutant_without_a_panic() {
    let mutants = one_byte_mutants();
    assert!(mutants.len() > 10_000, "{} mutants", mutants.len());
    for (kind, bytes) in &mutants {
        let answered = std::panic::catch_unwind(|| parse(*kind, bytes));
        assert!(answered.is_ok(), "the parse panicked on {:?}", String::from_utf8_lossy(bytes));
    }
}

/// THE ADMISSION SENTENCE AS A LAW (REG-1.86 (h)): a mutant the parse admits
/// is the canonical re-encoding of what it spells, byte for byte, and a
/// record of the kind named alone — under the other kind its `type` is
/// wrong. The counts show the law was tried on both sides.
#[test]
fn every_admitted_one_byte_mutant_is_its_own_canonical_encoding() {
    let (mut admitted, mut refused) = (0, 0);
    for (kind, bytes) in one_byte_mutants() {
        let Ok(record) = parse(kind, &bytes) else {
            refused += 1;
            continue;
        };
        let shown = String::from_utf8_lossy(&bytes);
        assert_eq!(
            encode(&record.body, record.sig.as_deref()).as_bytes(),
            bytes.as_slice(),
            "admitted, and not its own encoding: {shown:?}"
        );
        let other = match kind {
            BodyKind::Binding => BodyKind::Endpoint,
            BodyKind::Endpoint => BodyKind::Binding,
        };
        assert_eq!(parse(other, &bytes), Err(Refusal::WrongType), "{shown:?}");
        admitted += 1;
    }
    assert!(admitted > 100 && refused > 100, "{admitted} admitted, {refused} refused");
}
