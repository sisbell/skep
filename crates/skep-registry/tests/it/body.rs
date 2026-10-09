//! THE VECTOR SET at this parser (`tests/vectors/records.json`): every
//! vector meets the answer the set pins at the parse — a record, or its
//! refusal's cause — and every law of the parse, stated once in the child
//! `laws`; and the set pins the cap this crate does, so a parser another
//! reader of the bodies builds reads the pins from the set and not from a
//! second transcription. (`skep-resolve` builds none: it calls this crate's
//! `parse`.)
//!
//! Beside the set, the spec's two examples in their one canonical form, the
//! cases that pin this parser alone — a refusal's member as a value, the
//! first stage to fault where two do, the `type` member read off its kind's
//! row — and the codec's public face at cases a hand chose: the shortest
//! escapes, an address member at any size, the origins' walk. What only
//! `src/body.rs`'s privates can show — its one-spelling reader `address_of`
//! and the cases built through it — is that module's unit suite. The parse's
//! laws, and the inputs no hand chose they are driven on, are the child
//! `laws`. The set's readers live here — `vector_set`, `bytes_of` and
//! `kind_of` — and the child reads the set through the first two.

use std::path::Path;

use serde_json::Value;
use skep_registry::{
    encode, parse, rows, Body, BodyKind, Endpoint, Kind, Member, Origins, ParseRefusal,
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

/// A vector's bytes: its `bytes` string, or its `bytes_hex`, whole bytes of
/// hex digits alone — a digit left over, or a character no hex digit, is a
/// fault of the set, never a byte dropped or read as another.
fn bytes_of(vector: &Value) -> Vec<u8> {
    if let Some(text) = vector["bytes"].as_str() {
        return text.as_bytes().to_vec();
    }
    let hex = vector["bytes_hex"].as_str().expect("a vector carries bytes or bytes_hex");
    let (pairs, left_over) = hex.as_bytes().as_chunks::<2>();
    assert!(left_over.is_empty(), "bytes_hex holds whole bytes: {hex}");
    let digit = |b: u8| {
        char::from(b)
            .to_digit(16)
            .unwrap_or_else(|| panic!("bytes_hex holds hex digits alone: {hex}"))
    };
    pairs.iter().map(|&[high, low]| (16 * digit(high) + digit(low)) as u8).collect()
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

/// Every vector, under its own name: every law of the parse under both
/// kinds ([`laws::assert_the_laws_at`]), one answer at the parse under its
/// own kind, and for an admitted one the sig-less projection and the `sig`
/// the set pins. A name two vectors shared would let a required name below
/// match the wrong one, and a failure that names it would point at two.
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
        let _ = laws::assert_the_laws_at(&bytes);
        match (answer, parse(kind, &bytes)) {
            ("ok", Ok(record)) => {
                assert_eq!(
                    Some(record.canonical_sigless().as_str()),
                    vector["canonical_sigless"].as_str(),
                    "{name}: the sig-less canonical projection"
                );
                assert_eq!(record.sig.as_deref(), vector["sig"].as_str(), "{name}: the sig as found");
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
    assert!(admitted >= 17 && refused >= 67, "{admitted} admitted, {refused} refused");
    // The vectors the lane names, the cap's two sides, the escape table's,
    // the canonical member order's, admitted and refused, the sizes no
    // reader's own bound may refuse, the digits no digit class may widen,
    // and the text no lax decoder may pass, each present by name.
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
        "binding_with_replaces_and_sig",
        "endpoint_with_replaces_and_sig",
        "type_not_first",
        "replaces_before_prefix",
        "sig_not_last",
        "binding_with_sig_before_replaces",
        "strings_take_the_shortest_escapes_alone",
        "strings_past_ascii_stand_as_themselves",
        "escape_long_form_of_a_named_control",
        "escape_uppercase_hex",
        "escape_of_a_letter_past_ascii",
        "escape_of_an_astral_char",
        "escape_of_the_line_separator",
        "escape_of_del",
        "raw_control_in_a_string",
        "byte_order_mark_ahead_of_the_body",
        "surrogate_encoded_in_a_string",
        "code_point_past_u10ffff_in_a_string",
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
/// the same two with a space after each colon and comma, as REG-1.86 says a
/// specification prints a body, are what the parse refuses; and the
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
/// then the row's own, at each kind with the row's own faulty and with it
/// absent) — and the value stage's choices the parser adopts, where RFC 8259
/// leaves one: a member spelled twice read at its last occurrence; and no
/// JSON in a value nested past 127 objects and arrays, a number too large
/// for a 64-bit float (one that rounds to zero is read, and is `number`), or
/// an escaped unpaired surrogate. None of these is in the vector set: the set
/// pins what every parser answers, and these pin this one. The fourth text
/// the value stage reads as no JSON, a byte-order mark ahead of the value, is
/// the set's (`byte_order_mark_ahead_of_the_body`): unlike these, a reader
/// can turn it into an admission, its decoder dropping the mark before the
/// compare.
#[test]
fn a_body_answers_the_first_stage_that_faults() {
    let nested = |arrays: usize| {
        let (open, close) = ("[".repeat(arrays), "]".repeat(arrays));
        format!(r#"{{"type":"binding","prefix":"1.5","x":{open}{close}}}"#)
    };
    let (deep, too_deep) = (nested(126), nested(127));
    let cases: [(&str, &str); 16] = [
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
    ];
    for (cause, text) in cases {
        let answer = parse(BodyKind::Binding, text.as_bytes()).map_err(|r| r.token());
        assert_eq!(answer, Err(cause.to_owned()), "{text}");
    }
    // `sig` before the row's own member, at each kind: the member present
    // and faulty, and absent — its absence answered at its own turn.
    for (kind, text) in [
        (BodyKind::Binding, r#"{"type":"binding","prefix":"x","sig":true}"#),
        (BodyKind::Binding, r#"{"type":"binding","sig":true}"#),
        (BodyKind::Endpoint, r#"{"type":"endpoint","origins":[],"sig":true}"#),
        (BodyKind::Endpoint, r#"{"type":"endpoint","sig":true}"#),
    ] {
        let answer = parse(kind, text.as_bytes()).map_err(|r| r.token());
        assert_eq!(answer, Err("not_a_string:sig".to_owned()), "sig before the row's own: {text}");
    }
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

/// An endpoint's origins from a hand's list, one at least.
fn origins(list: &[&str]) -> Origins {
    Origins::new(list.iter().map(|o| o.to_string()).collect()).expect("at least one origin")
}

/// The escaping is the shortest JSON escape and no other, so a body
/// spelled with a longer escape of the same string is not canonical.
#[test]
fn strings_take_the_shortest_escapes_alone() {
    let body =
        Body::Endpoint(Endpoint { origins: origins(&["a\"b\\c\n\u{1}/é"]), replaces: None });
    assert_eq!(
        encode(&body, None),
        "{\"type\":\"endpoint\",\"origins\":[\"a\\\"b\\\\c\\n\\u0001/é\"]}"
    );
    let longer = "{\"type\":\"endpoint\",\"origins\":[\"a\\\"b\\\\c\\n\\u0001\\/é\"]}";
    assert_eq!(parse(BodyKind::Endpoint, longer.as_bytes()), Err(ParseRefusal::NotCanonical));
}

/// AN ADDRESS MEMBER IS THE ADDRESS IT SPELLS, at any size the cap
/// admits (wire.md §Value encodings: a component is one decimal
/// natural): a component past a machine word, one of 4,097 digits —
/// past the board's wire cap on a component, which a record's own cap
/// bounds instead — and one of 16,352, the body exactly the cap, which
/// [`MAX_REGISTRY_RECORD_BYTES`] prices: each reads as the address whose
/// rendering is the member, and the body re-encodes byte for byte.
#[test]
fn an_address_member_is_the_address_it_spells_at_any_size() {
    let filling = format!("1.{}", "9".repeat(16_352));
    let at_cap = format!(r#"{{"type":"binding","prefix":"{filling}"}}"#);
    assert_eq!(at_cap.len(), MAX_REGISTRY_RECORD_BYTES, "the priced body fills the cap");
    let prefixes =
        ["1.18446744073709551616".to_owned(), format!("1.{}", "9".repeat(4097)), filling];
    for prefix in prefixes {
        let text = format!(r#"{{"type":"binding","prefix":"{prefix}"}}"#);
        let record = parse(BodyKind::Binding, text.as_bytes()).expect("canonical");
        let Body::Binding(b) = &record.body else { panic!("a binding") };
        assert_eq!(b.prefix.to_string(), prefix);
        assert_eq!(encode(&record.body, None), text);
    }
}

/// The origins walk as the collection they are, in the org's order and
/// whole, a repeated origin two entries: by reference, as `for origin in
/// &origins` and `iter` do, by value, and whole, as `as_slice` and
/// `into_vec` hand them — `into_vec` the list the resolver walks.
#[test]
fn origins_walk_in_the_orgs_order() {
    let order = ["https://b.example", "http://a.onion", "http://a.onion", "https://a.example"];
    let list = origins(&order);
    let mut walked = Vec::new();
    for origin in &list {
        walked.push(origin.as_str());
    }
    assert_eq!(walked, order);
    assert!(list.iter().map(String::as_str).eq(order));
    assert_eq!(list.as_slice(), order);
    assert_eq!(list.clone().into_vec(), order);
    assert_eq!(list.into_iter().collect::<Vec<String>>(), order);
}
