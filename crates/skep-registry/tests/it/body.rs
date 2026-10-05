//! THE VECTOR SET at this parser (`tests/vectors/records.json`): every
//! vector meets the verdict the set pins — a record, or its refusal's cause
//! — every admitted body is its own re-encoding and a fixpoint, and the set
//! pins the cap this crate does, so a parser another reader of the bodies
//! builds reads the pins from the set and not from a second transcription.
//! (`skep-resolve` builds none: it calls this crate's `parse`.)

use std::path::Path;

use serde_json::Value;
use skep_registry::{encode, parse, Body, BodyKind, Record, MAX_REGISTRY_RECORD_BYTES};

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

/// Every vector, one verdict; the admitted ones read from both sides of the
/// canonical rule.
#[test]
fn the_vector_set_meets_one_verdict_at_this_parser() {
    let fixture = fixture();
    assert_eq!(fixture["cap"].as_u64(), Some(MAX_REGISTRY_RECORD_BYTES as u64));
    let vectors = fixture["vectors"].as_array().expect("vectors");
    let (mut admitted, mut refused) = (0, 0);
    for vector in vectors {
        let name = vector["name"].as_str().expect("a name");
        let kind = kind_of(vector);
        let bytes = bytes_of(vector);
        let verdict = vector["verdict"].as_str().expect("a verdict");
        match (verdict, parse(kind, &bytes)) {
            ("ok", Ok(record)) => {
                assert_eq!(record.body.kind(), kind, "{name}: the body's kind is the slot's");
                assert_eq!(
                    encode(&record.body, record.sig.as_deref()).as_bytes(),
                    bytes.as_slice(),
                    "{name}: b == encode(parse(b))"
                );
                assert_eq!(
                    Some(record.canonical_sigless().as_str()),
                    vector["canonical"].as_str(),
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
    assert_eq!((b.prefix.as_str(), b.replaces), ("1.5", None));
}
