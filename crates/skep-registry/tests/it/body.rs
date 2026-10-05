//! THE VECTOR SET at this parser (`tests/vectors/records.json`): every
//! vector meets the answer the set pins at the parse — a record, or its
//! refusal's cause — every admitted body is its own re-encoding and a
//! fixpoint, and the set pins the cap this crate does, so a parser another
//! reader of the bodies builds reads the pins from the set and not from a
//! second transcription. (`skep-resolve` builds none: it calls this crate's
//! `parse`.)

use std::path::Path;

use serde_json::Value;
use skep_registry::{encode, parse, rows, Body, BodyKind, Kind, Record, MAX_REGISTRY_RECORD_BYTES};

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
    assert!(admitted >= 7 && refused >= 30, "{admitted} admitted, {refused} refused");
    // The vectors the lane names, each present by name.
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
    ] {
        assert!(vectors.iter().any(|v| v["name"] == required), "the set names {required}");
    }
}

/// The two spec examples, in canonical form, byte for byte and in length;
/// the spaced spellings the spec shows are what the parse refuses.
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
    assert_eq!((b.prefix.tumbler().to_string(), b.replaces), ("1.5".to_owned(), None));
}

/// A BODY WITH TWO FAULTS ANSWERS THE EARLIER STAGE's, in the order
/// `parse`'s doc lists — the object before the number scan, the number scan
/// before `type`, the member set before any member's form, the members'
/// forms one member at a time (`replaces`, then `sig`, then the row's own)
/// — and the value stage's two policies the parser adopts: a member spelled
/// twice read at its last occurrence, and a value nested past 127 objects
/// and arrays no JSON. None of these is in the vector set: the set pins
/// what every parser answers, and these pin this one.
#[test]
fn a_body_answers_the_first_stage_that_faults() {
    let nested = |arrays: usize| {
        let (open, close) = ("[".repeat(arrays), "]".repeat(arrays));
        format!(r#"{{"type":"binding","prefix":"1.5","x":{open}{close}}}"#)
    };
    let (deep, too_deep) = (nested(126), nested(127));
    let bindings: [(&str, &str); 11] = [
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
    ];
    for (cause, text) in bindings {
        let answer = parse(BodyKind::Binding, text.as_bytes()).map_err(|r| r.token());
        assert_eq!(answer, Err(cause.to_owned()), "{text}");
    }
    let endpoint = parse(BodyKind::Endpoint, br#"{"type":"endpoint","origins":[],"sig":true}"#);
    assert_eq!(endpoint.unwrap_err().token(), "not_a_string:sig", "sig before the row's own");
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
