//! THE VECTOR SET at this parser (`tests/vectors/records.json`): every
//! vector meets the answer the set pins at the parse — a record, or its
//! refusal's cause — every admitted body is its own re-encoding and a
//! fixpoint, and the set pins the cap this crate does, so a parser another
//! reader of the bodies builds reads the pins from the set and not from a
//! second transcription. (`skep-resolve` builds none: it calls this crate's
//! `parse`.)
//!
//! Beside the set, the spec's two examples in their one canonical form and
//! the cases that pin this parser alone: a refusal's member as a value, the
//! first stage to fault where two do, and the `type` member read off its
//! kind's row. The laws on inputs no hand chose are the child `laws`. The
//! set's readers live here — `vector_set`, `bytes_of` and `kind_of` — and
//! the child reads the set through the first two.

use std::path::Path;

use serde_json::Value;
use skep_registry::{
    encode, parse, rows, Body, BodyKind, Kind, Member, ParseRefusal, Record,
    MAX_REGISTRY_RECORD_BYTES,
};

mod laws;

/// The vector set, `tests/vectors/records.json`, as the JSON it is.
fn vector_set() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/records.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("the vector set is JSON")
}

/// A vector's bytes: its `bytes` string, or its `bytes_hex`, whole bytes
/// alone — a digit left over is a fault of the set, never a byte dropped.
fn bytes_of(vector: &Value) -> Vec<u8> {
    if let Some(text) = vector["bytes"].as_str() {
        return text.as_bytes().to_vec();
    }
    let hex = vector["bytes_hex"].as_str().expect("a vector carries bytes or bytes_hex");
    assert!(hex.len().is_multiple_of(2), "bytes_hex holds whole bytes: {hex}");
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

/// Every vector, under its own name, one answer at the parse; the admitted
/// ones read from both sides of the canonical rule. A name two vectors
/// shared would let a required name below match the wrong one, and a
/// failure that names it would point at two.
#[test]
fn the_vector_set_meets_one_answer_at_this_parser() {
    let set = vector_set();
    assert_eq!(set["cap"].as_u64(), Some(MAX_REGISTRY_RECORD_BYTES as u64));
    let vectors = set["vectors"].as_array().expect("vectors");
    let (mut admitted, mut refused) = (0, 0);
    let mut names = std::collections::BTreeSet::new();
    for vector in vectors {
        let name = vector["name"].as_str().expect("a name");
        assert!(names.insert(name), "{name}: the set names two vectors so");
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
                assert_eq!(again, Record { body: record.body, sig: None }, "{name}");
                admitted += 1;
            }
            ("ok", Err(refusal)) => panic!("{name}: the set admits it, the parser refuses {refusal}"),
            (_, Err(refusal)) => {
                assert_eq!(refusal.token(), answer, "{name}");
                refused += 1;
            }
            (_, Ok(record)) => {
                panic!("{name}: the set refuses it ({answer}), the parser admits {record:?}")
            }
        }
    }
    assert!(admitted >= 16 && refused >= 63, "{admitted} admitted, {refused} refused");
    // The vectors the lane names, the cap's two sides, the escape table's,
    // and the sizes no reader's own bound may refuse and the digits no digit
    // class may widen, each present by name.
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
        "at_the_cap_with_sig",
        "one_past_the_cap_with_sig",
        "past_the_cap",
        "binding_with_sig",
        "strings_take_the_shortest_escapes_alone",
        "strings_past_ascii_stand_as_themselves",
        "escape_long_form_of_a_named_control",
        "escape_uppercase_hex",
        "escape_of_a_letter_past_ascii",
        "escape_of_an_astral_char",
        "escape_of_the_line_separator",
        "escape_of_del",
        "raw_control_in_a_string",
        "prefix_component_past_a_machine_word",
        "prefix_component_past_the_wire_digit_cap",
        "prefix_of_257_components",
        "prefix_with_non_ascii_digits",
        "endpoint_of_257_origins",
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
        (BodyKind::Binding, r#"{"type":"binding"}"#, ParseRefusal::MissingMember(Member::Prefix)),
        (
            BodyKind::Endpoint,
            r#"{"type":"endpoint"}"#,
            ParseRefusal::MissingMember(Member::Origins),
        ),
        (
            BodyKind::Binding,
            r#"{"type":"binding","prefix":true}"#,
            ParseRefusal::NotAString(Member::Prefix),
        ),
        (
            BodyKind::Binding,
            r#"{"type":"binding","prefix":"1","replaces":"x"}"#,
            ParseRefusal::NotAnAddress(Member::Replaces),
        ),
        (
            BodyKind::Binding,
            r#"{"type":"binding","prefix":"1","sig":null}"#,
            ParseRefusal::NotAString(Member::Sig),
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
/// then the row's own) — and the value stage's choices the parser adopts,
/// where RFC 8259 leaves one: a member spelled twice read at its last
/// occurrence; and no JSON in a value nested past 127 objects and arrays, a
/// number too large for a 64-bit float (one that rounds to zero is read, and
/// is `number`), an escaped unpaired surrogate, or a text opening on a
/// byte-order mark. None of these is in the vector set: the set pins what
/// every parser answers, and these pin this one.
#[test]
fn a_body_answers_the_first_stage_that_faults() {
    let nested = |arrays: usize| {
        let (open, close) = ("[".repeat(arrays), "]".repeat(arrays));
        format!(r#"{{"type":"binding","prefix":"1.5","x":{open}{close}}}"#)
    };
    let (deep, too_deep) = (nested(126), nested(127));
    let cases: [(&str, &str); 17] = [
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
        ("not_json", r#"{"type":"binding","prefix":"1.5","x":1e400}"#),
        ("number", r#"{"type":"binding","prefix":"1.5","x":1e-400}"#),
        ("not_json", r#"{"type":"binding","prefix":"1.5","sig":"\ud800"}"#),
        ("not_json", "\u{feff}{\"type\":\"binding\",\"prefix\":\"1.5\"}"),
    ];
    for (cause, text) in cases {
        let answer = parse(BodyKind::Binding, text.as_bytes()).map_err(|r| r.token());
        assert_eq!(answer, Err(cause.to_owned()), "{text}");
    }
    let answer = parse(BodyKind::Endpoint, br#"{"type":"endpoint","origins":[],"sig":true}"#);
    assert_eq!(answer.unwrap_err().token(), "not_a_string:sig", "sig before the row's own");
    let past = vec![0xff_u8; MAX_REGISTRY_RECORD_BYTES + 1];
    assert_eq!(
        parse(BodyKind::Binding, &past),
        Err(ParseRefusal::PastCap),
        "the cap before the text"
    );
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
