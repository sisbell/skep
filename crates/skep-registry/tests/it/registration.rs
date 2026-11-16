//! The registration kind's six bodies at this parser
//! (`tests/vectors/registration.json`): every vector meets the answer the
//! set pins — a record, or its refusal's cause — and the parse's laws under
//! each of the six kinds; the set names every case REG-1.86 owes whose
//! cause is the parse's; and beside the set stand the rules a hand states
//! once over every kind — the cap per kind, the `type` held to its row, the
//! one number a body carries, the board's three members together, the
//! vouch's form — and the encoder's law over bodies no hand chose.
//!
//! The set's readers live here — [`vector_file`] and [`vector_bytes`] — and
//! the policy document's suite reads its own set through them.

use std::path::Path;

use serde_json::Value;
use skep_address::{validate, Address, Nat, Tumbler};
use skep_registry::{
    encode, encode_registration, parse, parse_registration, rows, Approved, Binding, Body,
    BodyKind, BoardCarriesOn, Denied, Digits, Disposition, Endpoint, Fault, Fresh, Hex64,
    HexDigits, Kind, Member, Origins, ParseRefusal, Principal, ProvisionedBoard, Refused,
    RegistrationBody, RegistrationKind, RegistrationRecord, Subtype, Vouch, MAX_EXACT_NUMBER,
    MAX_REGISTRATION_REQUEST_BYTES, MAX_REGISTRY_RECORD_BYTES,
};

/// A vector set of `tests/vectors/`, as the JSON it is.
pub(crate) fn vector_file(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("the vector set is JSON")
}

/// A vector's bytes: its `bytes` string; its `bytes_hex`, whole bytes of hex
/// digits alone; or its `bytes_filled` — the `head`, then the `fill`
/// repeated, then the `tail`, the run as long as makes the whole `len`
/// bytes. A fault of the set is a panic, never a byte dropped.
pub(crate) fn vector_bytes(vector: &Value) -> Vec<u8> {
    if let Some(text) = vector["bytes"].as_str() {
        return text.as_bytes().to_vec();
    }
    if let Some(filled) = vector.get("bytes_filled") {
        let part = |name: &str| filled[name].as_str().unwrap_or_else(|| panic!("a {name}"));
        let (head, fill, tail) = (part("head"), part("fill"), part("tail"));
        let len = filled["len"].as_u64().expect("a len") as usize;
        assert_eq!(fill.len(), 1, "the fill is one byte");
        let run = len.checked_sub(head.len() + tail.len()).expect("the head and tail fit the len");
        return [head.as_bytes(), fill.repeat(run).as_bytes(), tail.as_bytes()].concat();
    }
    let hex = vector["bytes_hex"].as_str().expect("a vector carries its bytes");
    let (pairs, left_over) = hex.as_bytes().as_chunks::<2>();
    assert!(left_over.is_empty(), "bytes_hex holds whole bytes: {hex}");
    let digit = |b: u8| {
        char::from(b)
            .to_digit(16)
            .unwrap_or_else(|| panic!("bytes_hex holds hex digits alone: {hex}"))
    };
    pairs.iter().map(|&[high, low]| (16 * digit(high) + digit(low)) as u8).collect()
}

/// The `sig` an admitted vector pins: its `sig` string, `None` where null,
/// or — `sig_filled` — the fill's own run.
fn vector_sig(vector: &Value) -> Option<String> {
    if vector["sig_filled"] == true {
        let filled = &vector["bytes_filled"];
        let part = |name: &str| filled[name].as_str().expect("a part");
        let len = filled["len"].as_u64().expect("a len") as usize;
        return Some(part("fill").repeat(len - part("head").len() - part("tail").len()));
    }
    vector["sig"].as_str().map(str::to_owned)
}

/// The kind a `type` string names, standing in for the link's type slot.
fn kind_named(name: &str) -> RegistrationKind {
    RegistrationKind::ALL
        .iter()
        .copied()
        .find(|kind| kind.row().type_value == Some(name))
        .unwrap_or_else(|| panic!("{name}: no kind of the registration's"))
}

/// THE PARSE'S LAWS, stated once — what `parse_registration` promises of
/// every input, asked at one body under each kind in turn: an answer and no
/// panic; `past_cap` exactly where the body is past that kind's cap; a
/// record only where the body is its own canonical encoding (REG-1.86 (h)),
/// of the kind named, its sig-less projection a fixpoint (REG-1.86 (e));
/// and a record under one kind at most, every other kind answering
/// `wrong_type` (REG-1.86 (a)) — or the earlier stage's where one faults
/// first: `past_cap`, where the body is past that kind's own smaller cap,
/// and `number`, where the record is an approved answer, whose principals
/// are numbers no other kind's scan admits (REG-1.86 (d)). Hands back the
/// answers in `RegistrationKind::ALL`'s order.
fn assert_the_laws_at(body: &[u8]) -> Vec<Result<(), ParseRefusal>> {
    let shown = || {
        let head: String = String::from_utf8_lossy(body).chars().take(200).collect();
        format!("{head:?} ({} bytes)", body.len())
    };
    let answers: Vec<Result<(), ParseRefusal>> = RegistrationKind::ALL
        .iter()
        .map(|&kind| {
            let past = body.len() > kind.cap();
            let answer = std::panic::catch_unwind(|| parse_registration(kind, body))
                .unwrap_or_else(|_| panic!("{kind:?}: the parse panicked on {}", shown()));
            match answer {
                Ok(record) => {
                    assert!(!past, "{kind:?}: a record past the cap: {}", shown());
                    assert_eq!(record.body.kind(), kind, "{}", shown());
                    let encoded = encode_registration(&record.body, record.sig.as_deref());
                    assert!(encoded.as_bytes() == body, "{kind:?}: not its own encoding: {}", shown());
                    let again = parse_registration(kind, record.canonical_sigless().as_bytes());
                    let sigless = RegistrationRecord { body: record.body, sig: None };
                    assert_eq!(again, Ok(sigless), "{}", shown());
                    Ok(())
                }
                Err(refusal) => {
                    assert_eq!(refusal == ParseRefusal::PastCap, past, "{kind:?}: {refusal}: {}", shown());
                    Err(refusal)
                }
            }
        })
        .collect();
    let admitted = answers.iter().filter(|a| a.is_ok()).count();
    assert!(admitted <= 1, "a record under {admitted} kinds: {}", shown());
    if admitted == 1 {
        let admitting = RegistrationKind::ALL
            .iter()
            .zip(&answers)
            .find_map(|(kind, answer)| answer.is_ok().then_some(*kind))
            .expect("one kind admits");
        for (kind, answer) in RegistrationKind::ALL.iter().zip(&answers) {
            if let Err(refusal) = answer {
                let expected = if body.len() > kind.cap() {
                    ParseRefusal::PastCap
                } else if admitting == RegistrationKind::Approved {
                    ParseRefusal::Number
                } else {
                    ParseRefusal::WrongType
                };
                assert_eq!(*refusal, expected, "{kind:?} beside the kind that admits: {}", shown());
            }
        }
    }
    answers
}

/// REG-1.86 (a), (d), (h) — EVERY VECTOR, under its own name: every law of
/// the parse under each kind, one answer at the parse under its own kind,
/// and for an admitted one the sig-less projection and the `sig` the set
/// pins — so every admitted body is canonical, `b == encode(parse(b))`, and
/// every refused one names the daemon's cause. The set pins the cap per
/// kind this crate does.
#[test]
fn the_vector_set_meets_one_answer_at_this_parser() {
    let set = vector_file("registration.json");
    for &kind in RegistrationKind::ALL {
        let name = kind.row().type_value.expect("a body-bearing row");
        assert_eq!(set["caps"][name].as_u64(), Some(kind.cap() as u64), "{name}: the set's cap");
    }
    assert_eq!(set["caps"].as_object().map(|c| c.len()), Some(RegistrationKind::ALL.len()));
    let vectors = set["vectors"].as_array().expect("vectors");
    let (mut admitted, mut refused) = (0, 0);
    let mut names = std::collections::BTreeSet::new();
    let mut causes = std::collections::BTreeSet::new();
    for vector in vectors {
        let name = vector["name"].as_str().expect("a name");
        assert!(names.insert(name), "{name}: the set names two vectors so");
        let kind = kind_named(vector["kind"].as_str().expect("a kind"));
        let bytes = vector_bytes(vector);
        let answer = vector["parse"].as_str().expect("the parse's answer");
        let _ = assert_the_laws_at(&bytes);
        match (answer, parse_registration(kind, &bytes)) {
            ("ok", Ok(record)) => {
                assert_eq!(
                    Some(record.canonical_sigless().as_str()),
                    vector["canonical_sigless"].as_str(),
                    "{name}: the sig-less canonical projection"
                );
                assert_eq!(record.sig, vector_sig(vector), "{name}: the sig as found");
                admitted += 1;
            }
            ("ok", Err(refusal)) => panic!("{name}: the set admits it, the parser refuses {refusal}"),
            (_, Err(refusal)) => {
                assert_eq!(refusal.token(), answer, "{name}");
                causes.insert(refusal.token());
                refused += 1;
            }
            (_, Ok(record)) => {
                panic!("{name}: the set refuses it ({answer}), the parser admits {record:?}")
            }
        }
    }
    assert!(admitted >= 50 && refused >= 150, "{admitted} admitted, {refused} refused");
    // Every cause the registration's parse can name is met by a vector.
    for cause in [
        "past_cap",
        "not_utf8",
        "not_json",
        "not_an_object",
        "number",
        "wrong_type",
        "unknown_member",
        "missing_member:board",
        "missing_member:fingerprints",
        "missing_member:board_principal",
        "not_a_string:sig",
        "not_a_string:door",
        "not_an_address:policy",
        "not_an_address:replaces",
        "not_a_number:node_principal",
        "not_a_number:board_principal",
        "not_hex:fresh",
        "not_hex:signer",
        "not_hex:signature",
        "not_hex:fingerprints",
        "not_digits:collection_interval",
        "not_digits:clause",
        "unknown_value:disposition",
        "unknown_value:fault",
        "not_strings:fingerprints",
        "not_canonical",
    ] {
        assert!(causes.contains(cause), "no vector is refused {cause}");
    }
}

/// REG-1.86, THE VECTORS THESE BODIES OWE — each case whose cause is the
/// parse's is a vector of the set, by name: per body, the canonical
/// spelling admitted with a `sig` and without, the same spaced, a `type`
/// that is another row's and a parent's name, a member its row does not
/// name, a required member left out and a member of another JSON type; the
/// cap per kind; the request's `board` rule and its `fresh`'s form; the
/// answers' principal, realm member, board members, `disposition`,
/// `collection_interval`, faults and denial; and the vouch with `replaces`
/// and without, out of order and repeating. The cases whose cause is the
/// board's are the daemon's suite's, and a console's are its own lane's.
#[test]
fn the_set_names_every_case_the_rule_owes_the_parse() {
    let set = vector_file("registration.json");
    let vectors = set["vectors"].as_array().expect("vectors");
    let mut required: Vec<String> = Vec::new();
    for kind in ["fresh", "board_carries_on", "approved", "refused", "denied", "vouch"] {
        for case in [
            "canonical",
            "with_sig",
            "spaced",
            "typed_another_row",
            "with_a_member_its_row_does_not_name",
            "sig_not_a_string",
        ] {
            required.push(format!("{kind}_{case}"));
        }
    }
    for kind in ["fresh", "board_carries_on", "approved", "refused", "denied"] {
        required.push(format!("{kind}_typed_its_parent"));
    }
    required.extend(
        [
            "vouch_typed_a_parent",
            "fresh_without_board",
            "fresh_without_board_is_no_fresh_body",
            "board_carries_on_with_board",
            "refused_without_fault",
            "denied_without_policy",
            "denied_without_clause",
            "vouch_without_fingerprints",
            "fresh_door_not_a_string",
            "fresh_at_the_request_cap",
            "fresh_one_past_the_request_cap",
            "board_carries_on_at_the_request_cap",
            "board_carries_on_one_past_the_request_cap",
            "approved_one_past_the_cap",
            "refused_one_past_the_cap",
            "denied_one_past_the_cap",
            "vouch_one_past_the_cap",
            "fresh_shape_naming_the_other_request_row",
            "fresh_fresh_in_capitals",
            "fresh_fresh_of_63_characters",
            "approved_node_principal_at_the_top_of_the_range",
            "approved_node_principal_past_the_range",
            "approved_with_a_realm_member",
            "approved_the_node_pair_alone",
            "approved_the_boards_three_members_together",
            "approved_board_address_alone",
            "approved_board_address_and_principal",
            "approved_disposition_neither_value",
            "approved_collection_interval_with_a_unit",
            "approved_collection_interval_a_number",
            "refused_not_this_door",
            "refused_freshness_spent",
            "refused_enrolment_not_honored",
            "refused_any_other_fault",
            "denied_policy_and_clause",
            "denied_clause_a_word",
            "vouch_first",
            "vouch_with_replaces",
            "vouch_fingerprints_out_of_order",
            "vouch_fingerprints_repeating",
            "vouch_one_fingerprint",
            "leading_byte_order_mark",
        ]
        .map(str::to_owned),
    );
    for name in required {
        assert!(vectors.iter().any(|v| v["name"] == name.as_str()), "the set names {name}");
    }
}

fn address(s: &str) -> Address {
    let comps = s.split('.').map(|c| c.parse::<Nat>().expect("a component"));
    validate(Tumbler::new(comps).expect("nonempty")).expect("T4-valid")
}

fn hex64(byte: u8) -> Hex64 {
    Hex64::new(format!("{byte:02x}").repeat(32)).expect("64 lowercase hex")
}

fn digits(s: &str) -> Digits {
    Digits::new(s).expect("decimal digits")
}

fn principal(id: u64) -> Principal {
    Principal::new(id).expect("inside the range")
}

/// A body of each kind, a hand's: the fresh request, the board-carries-on
/// request, the root's approved answer, a refusal, a denial and a vouch.
fn a_body_of_each_kind() -> Vec<RegistrationBody> {
    let door = format!("realm:{} door:1.1.0.1", "9f".repeat(32));
    vec![
        RegistrationBody::Fresh(Fresh {
            door: door.clone(),
            fresh: hex64(0x5e),
            shape: "3.54.1.1".into(),
            node: r#"{"type":"skep-enroll"}"#.into(),
            board: r#"{"type":"skep-enroll","board":true}"#.into(),
            signer: hex64(0xab),
            signature: HexDigits::new("0f1e").expect("hex"),
        }),
        RegistrationBody::BoardCarriesOn(BoardCarriesOn {
            door,
            fresh: hex64(0x5f),
            shape: "3.54.1.2".into(),
            node: r#"{"type":"skep-enroll"}"#.into(),
            signer: hex64(0xab),
            signature: HexDigits::new("0f1e").expect("hex"),
        }),
        RegistrationBody::Approved(Approved {
            prefix: address("1.5"),
            node_address: address("1.0.7"),
            node_principal: principal(7_402_918_836_251),
            board: None,
            door_origin: None,
            collection_interval: digits("1209600"),
            disposition: Disposition::Retirement,
            policy: address("1.0.1.0.5.2"),
        }),
        RegistrationBody::Refused(Refused { fault: Fault::FreshnessSpent }),
        RegistrationBody::Denied(Denied { policy: address("1.0.1.0.5.2"), clause: digits("2") }),
        RegistrationBody::Vouch(Vouch {
            fingerprints: vec![hex64(0x0a), hex64(0x1b)],
            replaces: None,
        }),
    ]
}

/// REG-1.86, the bodies SHOWN ONCE — the six examples in canonical form,
/// each read back as the body it spells and re-encoded byte for byte; and
/// the same spaced, as the rule prints a body, is what the parse refuses.
#[test]
fn the_spec_examples_have_one_canonical_form_each() {
    let texts = [
        concat!(
            r#"{"type":"fresh","door":"realm:9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f door:1.1.0.1","#,
            r#""fresh":"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e","shape":"3.54.1.1","#,
            r#""node":"{\"type\":\"skep-enroll\"}","board":"{\"type\":\"skep-enroll\",\"board\":true}","#,
            r#""signer":"abababababababababababababababababababababababababababababababab","signature":"0f1e"}"#
        ),
        concat!(
            r#"{"type":"board-carries-on","door":"realm:9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f door:1.1.0.1","#,
            r#""fresh":"5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f","shape":"3.54.1.2","#,
            r#""node":"{\"type\":\"skep-enroll\"}","#,
            r#""signer":"abababababababababababababababababababababababababababababababab","signature":"0f1e"}"#
        ),
        r#"{"type":"approved","prefix":"1.5","node_address":"1.0.7","node_principal":7402918836251,"collection_interval":"1209600","disposition":"retirement","policy":"1.0.1.0.5.2"}"#,
        r#"{"type":"refused","fault":"freshness-spent"}"#,
        r#"{"type":"denied","policy":"1.0.1.0.5.2","clause":"2"}"#,
        concat!(
            r#"{"type":"vouch","fingerprints":["0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a","#,
            r#""1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b"]}"#
        ),
    ];
    for (body, text) in a_body_of_each_kind().into_iter().zip(texts) {
        let kind = body.kind();
        assert_eq!(encode_registration(&body, None), text, "{kind:?}");
        let record = parse_registration(kind, text.as_bytes()).expect("canonical");
        assert_eq!(record, RegistrationRecord { body: body.clone(), sig: None }, "{kind:?}");
        let signed = encode_registration(&body, Some("c0ffee"));
        assert!(signed.ends_with(r#","sig":"c0ffee"}"#), "{kind:?}: sig is the last member");
        let record = parse_registration(kind, signed.as_bytes()).expect("canonical, signed");
        assert_eq!(record.sig.as_deref(), Some("c0ffee"));
        assert_eq!(record.canonical_sigless(), text, "{kind:?}: the projection carries no sig");
        let spaced = text.replace("\":\"", "\": \"");
        assert_ne!(spaced, text);
        assert_eq!(
            parse_registration(kind, spaced.as_bytes()),
            Err(ParseRefusal::NotCanonical),
            "{kind:?}: the body spaced"
        );
    }
}

/// REG-1.86 (h), the cap per kind — A REQUEST of either kind of exactly 64
/// KiB parses and one byte more is `past_cap`; AN ANSWER of each of the
/// three and A VOUCH of exactly 16 KiB parse and one byte more is
/// `past_cap`; and A BINDING and AN ENDPOINT past 16 KiB are `past_cap`
/// still: the request's larger cap is the request's alone, and
/// `MAX_REGISTRY_RECORD_BYTES` keeps its name and its figure.
#[test]
fn the_cap_is_per_kind() {
    assert_eq!(MAX_REGISTRATION_REQUEST_BYTES, 65_536);
    assert_eq!(MAX_REGISTRY_RECORD_BYTES, 16_384);
    for body in a_body_of_each_kind() {
        let kind = body.kind();
        let cap = if kind.is_request() {
            MAX_REGISTRATION_REQUEST_BYTES
        } else {
            MAX_REGISTRY_RECORD_BYTES
        };
        assert_eq!(kind.cap(), cap, "{kind:?}");
        let around_the_sig = encode_registration(&body, Some("")).len();
        let sig = "a".repeat(cap - around_the_sig);
        let at_cap = encode_registration(&body, Some(&sig));
        assert_eq!(at_cap.len(), cap, "{kind:?}");
        let record = parse_registration(kind, at_cap.as_bytes()).expect("a record at its cap");
        assert_eq!(record.sig.as_deref(), Some(sig.as_str()), "{kind:?}");
        let one_past = encode_registration(&body, Some(&format!("{sig}a")));
        assert_eq!(one_past.len(), cap + 1, "encode measures nothing");
        assert_eq!(
            parse_registration(kind, one_past.as_bytes()),
            Err(ParseRefusal::PastCap),
            "{kind:?}: one byte past its cap"
        );
    }
    let fill = |body: &Body| {
        let around = encode(body, Some("")).len();
        encode(body, Some(&"a".repeat(MAX_REGISTRY_RECORD_BYTES + 1 - around)))
    };
    let binding = Body::Binding(Binding { prefix: address("1.5"), replaces: None });
    let origins = Origins::new(vec!["https://acme.example".into()]).expect("one origin");
    let endpoint = Body::Endpoint(Endpoint { origins, replaces: None });
    for (kind, body) in [(BodyKind::Binding, binding), (BodyKind::Endpoint, endpoint)] {
        let one_past = fill(&body);
        assert_eq!(one_past.len(), MAX_REGISTRY_RECORD_BYTES + 1);
        assert_eq!(parse(kind, one_past.as_bytes()), Err(ParseRefusal::PastCap), "{kind:?}");
        assert!(parse(kind, &one_past.as_bytes()[..one_past.len() - 3]).is_err(), "cut short");
        let at_cap = one_past.replacen("\"sig\":\"a", "\"sig\":\"", 1);
        assert_eq!(at_cap.len(), MAX_REGISTRY_RECORD_BYTES);
        assert!(parse(kind, at_cap.as_bytes()).is_ok(), "{kind:?}: a record at 16 KiB");
    }
}

/// REG-1.86 (a) — THE `type` MEMBER IS ITS OWN ROW's NAME: each kind's body
/// spelled under its row's string is a record of that kind, and under every
/// other string — every other row's `type`, the names of the parent rows
/// `request` and `reply`, which are the `type` of no body, the kind's own
/// name, a row's name in capitals — is `wrong_type`. The string is read off
/// the table's row, the one spelling.
#[test]
fn a_bodys_type_agrees_with_its_row_and_no_body_is_typed_a_parent() {
    let mut names: Vec<&str> = rows().iter().filter_map(|r| r.type_value).collect();
    names.extend(["request", "reply", "registration", "approval", "Fresh", ""]);
    for body in a_body_of_each_kind() {
        let kind = body.kind();
        let own = kind.row().type_value.expect("a body-bearing row");
        let text = encode_registration(&body, None);
        assert!(text.starts_with(&format!(r#"{{"type":"{own}""#)), "{kind:?}");
        for name in &names {
            let retyped = text.replacen(&format!(r#""type":"{own}""#), &format!(r#""type":"{name}""#), 1);
            let answer = parse_registration(kind, retyped.as_bytes());
            if *name == own {
                assert!(answer.is_ok(), "{kind:?} under its own row's name");
            } else {
                assert_eq!(answer, Err(ParseRefusal::WrongType), "{kind:?} typed {name:?}");
            }
        }
    }
    for parent in [Subtype::Request, Subtype::Reply] {
        assert_eq!(parent.row().type_value, None, "{parent:?}: a parent row is the type of no body");
    }
    assert_eq!(Kind::Registration.row().type_value, None);
    assert_eq!(Subtype::Approval.row().type_value, None, "the approval is a link alone");
}

/// REG-1.86 (d); AUTH-5.20 — THE ONE NUMBER: an approved answer's
/// `node_principal` and `board_principal` are JSON numbers inside the
/// exactly-representable range — the top of it admitted, one past it
/// `number` — and a number at any other member of any body is `number`, as
/// is a principal that is negative, a fraction or in exponent form; a
/// principal that is a string is `not_a_number`.
#[test]
fn a_principal_is_the_one_number_a_body_carries() {
    assert_eq!(MAX_EXACT_NUMBER, 9_007_199_254_740_991, "2^53 − 1");
    assert_eq!(Principal::MAX, MAX_EXACT_NUMBER);
    assert_eq!(Principal::new(Principal::MAX).map(Principal::get), Some(Principal::MAX));
    assert_eq!(Principal::new(Principal::MAX + 1), None);
    let approved = |node: &str, board: &str| {
        format!(
            r#"{{"type":"approved","prefix":"1.3","node_address":"1.0.9","node_principal":{node},"board_address":"1.0.1","board_principal":{board},"board_origin":"https://b.example","collection_interval":"60","disposition":"retirement","policy":"1.0.1.0.5.2"}}"#
        )
    };
    let parse = |text: String| {
        parse_registration(RegistrationKind::Approved, text.as_bytes()).map_err(|r| r.token())
    };
    let top = Principal::MAX.to_string();
    let past = (Principal::MAX + 1).to_string();
    let record = parse(approved(&top, "0")).expect("the range's two ends");
    let RegistrationBody::Approved(a) = record.body else { panic!("an approved answer") };
    assert_eq!(a.node_principal.get(), Principal::MAX);
    assert_eq!(a.board.expect("the board's three").principal.get(), 0);
    assert!(parse(approved("0", &top)).is_ok());
    for (node, board) in [(past.as_str(), "1"), ("1", past.as_str())] {
        assert_eq!(parse(approved(node, board)), Err("number".to_owned()), "{node} / {board}");
    }
    for bad in ["-1", "1.0", "1e2", "-0", "18446744073709551616", "[1]"] {
        assert_eq!(parse(approved(bad, "1")), Err("number".to_owned()), "node_principal {bad}");
        assert_eq!(parse(approved("1", bad)), Err("number".to_owned()), "board_principal {bad}");
    }
    assert_eq!(parse(approved("\"1\"", "1")), Err("not_a_number:node_principal".to_owned()));
    assert_eq!(parse(approved("1", "true")), Err("not_a_number:board_principal".to_owned()));
    // A number at any other member, of every kind's body: one more member
    // holding a number, and each of the body's own strings turned into one.
    for body in a_body_of_each_kind() {
        let kind = body.kind();
        let text = encode_registration(&body, None);
        let with_a_number = format!("{},\"n\":7}}", &text[..text.len() - 1]);
        assert_eq!(
            parse_registration(kind, with_a_number.as_bytes()),
            Err(ParseRefusal::Number),
            "{kind:?}: a number at a member the row does not name"
        );
        let a_principal_elsewhere = format!("{},\"node_principal\":7}}", &text[..text.len() - 1]);
        if kind != RegistrationKind::Approved {
            assert_eq!(
                parse_registration(kind, a_principal_elsewhere.as_bytes()),
                Err(ParseRefusal::Number),
                "{kind:?}: a principal's member admits a number under the approved answer alone"
            );
        }
        let signed = format!("{},\"sig\":7}}", &text[..text.len() - 1]);
        assert_eq!(parse_registration(kind, signed.as_bytes()), Err(ParseRefusal::Number), "{kind:?}: sig");
    }
}

/// RES-272's call (7) — THE BOARD's THREE MEMBERS RIDE TOGETHER OR NOT AT
/// ALL: an approved answer with all three of `board_address`,
/// `board_principal` and `board_origin` parses, with none it parses, and
/// with one or two of the three it is refused, naming the first of the
/// three the body lacks.
#[test]
fn an_approved_answers_board_members_ride_together_or_not_at_all() {
    let trio = [
        (Member::BoardAddress, r#""board_address":"1.0.1","#),
        (Member::BoardPrincipal, r#""board_principal":88213,"#),
        (Member::BoardOrigin, r#""board_origin":"https://b.example","#),
    ];
    for present in 0u8..8 {
        let held = |i: usize| present & (1 << i) != 0;
        let board: String = (0..3).filter(|&i| held(i)).map(|i| trio[i].1).collect();
        let text = format!(
            r#"{{"type":"approved","prefix":"1.3","node_address":"1.0.9","node_principal":5,{board}"collection_interval":"60","disposition":"retirement","policy":"1.0.1.0.5.2"}}"#
        );
        let answer = parse_registration(RegistrationKind::Approved, text.as_bytes());
        match present.count_ones() {
            0 => {
                let RegistrationBody::Approved(a) = answer.expect("the node pair alone").body else {
                    panic!("an approved answer")
                };
                assert_eq!(a.board, None);
            }
            3 => {
                let RegistrationBody::Approved(a) = answer.expect("the three together").body else {
                    panic!("an approved answer")
                };
                let board = a.board.expect("the board's three");
                assert_eq!(
                    board,
                    ProvisionedBoard {
                        address: address("1.0.1"),
                        principal: principal(88_213),
                        origin: "https://b.example".into()
                    }
                );
            }
            _ => {
                let first_absent = (0..3).find(|&i| !held(i)).expect("one is absent");
                assert_eq!(
                    answer,
                    Err(ParseRefusal::MissingMember(trio[first_absent].0)),
                    "the three apart: {board}"
                );
            }
        }
    }
}

/// REG-1.86, REG-4.185 — THE VOUCH's FORM, AND NO MORE: each fingerprint is
/// sixty-four lowercase hex characters, and the parse holds the list to no
/// order and no count — a list out of order, one repeating a fingerprint,
/// one of a single key and an empty one each PARSE, carried as written, the
/// match against a thread's key being array equality at the reader.
#[test]
fn a_vouch_out_of_order_or_repeating_parses() {
    let (a, b, c) = ("0a".repeat(32), "1b".repeat(32), "2c".repeat(32));
    for list in [
        vec![a.clone(), b.clone(), c.clone()],
        vec![c.clone(), a.clone(), b.clone()],
        vec![a.clone(), a.clone(), b.clone()],
        vec![b.clone()],
        vec![],
    ] {
        let spelled: Vec<String> = list.iter().map(|f| format!("\"{f}\"")).collect();
        let text = format!(r#"{{"type":"vouch","fingerprints":[{}]}}"#, spelled.join(","));
        let record = parse_registration(RegistrationKind::Vouch, text.as_bytes())
            .unwrap_or_else(|r| panic!("{list:?}: refused {r}"));
        let RegistrationBody::Vouch(vouch) = record.body else { panic!("a vouch") };
        let read: Vec<&str> = vouch.fingerprints.iter().map(Hex64::as_str).collect();
        assert_eq!(read, list, "carried as written");
    }
    for bad in [a.to_uppercase(), a[..63].to_owned(), format!("{a}0"), "g".repeat(64)] {
        let text = format!(r#"{{"type":"vouch","fingerprints":["{bad}"]}}"#);
        assert_eq!(
            parse_registration(RegistrationKind::Vouch, text.as_bytes()),
            Err(ParseRefusal::NotHex(Member::Fingerprints)),
            "{bad}"
        );
    }
}

/// THE FORMS THE TYPES CARRY: each value type admits exactly its form, so a
/// body a caller builds holds no member the parse would refuse — sixty-four
/// lowercase hex characters, hex digits of either case and any count,
/// decimal digits and at least one, a principal inside the range — and
/// `Digits::value` reads the number where a machine word holds it.
#[test]
fn the_value_types_admit_their_forms_alone() {
    let fp = "ab".repeat(32);
    assert_eq!(Hex64::new(fp.clone()).as_ref().map(Hex64::as_str), Some(fp.as_str()));
    for bad in [fp.to_uppercase(), fp[..62].to_owned(), format!("{fp}ab"), "xy".repeat(32), String::new()] {
        assert_eq!(Hex64::new(bad.clone()), None, "{bad:?}");
    }
    for ok in ["", "0", "abc", "0F1e", &"ab".repeat(4000)] {
        assert_eq!(HexDigits::new(ok).as_ref().map(HexDigits::as_str), Some(ok));
    }
    for bad in ["0x1f", "g", "1 2", "ab\n"] {
        assert_eq!(HexDigits::new(bad), None, "{bad:?}");
    }
    for (ok, value) in [("0", Some(0)), ("007", Some(7)), ("1209600", Some(1_209_600))] {
        let digits = Digits::new(ok).expect("digits");
        assert_eq!((digits.as_str(), digits.value()), (ok, value));
    }
    assert_eq!(Digits::new("18446744073709551616").expect("digits").value(), None, "past u64");
    for bad in ["", "+1", "-1", "1.0", "1e3", " 1", "１"] {
        assert_eq!(Digits::new(bad), None, "{bad:?}");
    }
    assert_eq!(Fault::ALL.len(), 3, "the refused answer's three faults, and no other");
    assert_eq!(
        Fault::ALL.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
        ["not-this-door", "freshness-spent", "enrolment-not-honored"]
    );
    assert_eq!(
        Disposition::ALL.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
        ["retirement", "retirement-and-teardown"]
    );
}

/// A REQUEST's MEMBERS ARE READ OFF EITHER KIND, and THE FRAME's FIELDS ARE
/// THE BODY's MEMBERS (REG-4.73): `door`, `fresh`, `shape`, `node` and, on
/// a fresh request, `board`, in that order and as written — the field left
/// out where the member is. An answer and the vouch are no request.
#[test]
fn a_requests_frame_fields_are_its_members() {
    let bodies = a_body_of_each_kind();
    let fresh = bodies[0].request().expect("a fresh request");
    assert_eq!(fresh.board, Some(r#"{"type":"skep-enroll","board":true}"#));
    assert_eq!(
        fresh.frame_fields(),
        [fresh.door, fresh.fresh.as_str(), "3.54.1.1", fresh.node, fresh.board.expect("board")]
    );
    let carries_on = bodies[1].request().expect("a board-carries-on request");
    assert_eq!(carries_on.board, None);
    assert_eq!(
        carries_on.frame_fields(),
        [carries_on.door, carries_on.fresh.as_str(), "3.54.1.2", carries_on.node]
    );
    assert_eq!((fresh.signer.as_str().len(), fresh.signature.as_str()), (64, "0f1e"));
    for body in &bodies[2..] {
        assert_eq!(body.request(), None, "{:?}", body.kind());
    }
}

/// THE KIND IS READ OFF ITS ROW's ADDRESS, by equality: each of the six
/// kinds off its own row, in REG-1.15's order, and no kind off the
/// registration's own row, its parent rows, its approval, an address
/// beneath a row or a row of another kind. A request's signed `shape` names
/// its own row by the row's ordinal path (REG-1.86 (c)).
#[test]
fn the_kind_is_read_off_its_rows_address() {
    let expected = [
        (RegistrationKind::Fresh, Subtype::RequestFresh, "3.54.1.1", true),
        (RegistrationKind::BoardCarriesOn, Subtype::RequestBoardCarriesOn, "3.54.1.2", true),
        (RegistrationKind::Approved, Subtype::ReplyApproved, "3.54.2.1", false),
        (RegistrationKind::Refused, Subtype::ReplyRefused, "3.54.2.2", false),
        (RegistrationKind::Denied, Subtype::ReplyDenied, "3.54.2.3", false),
        (RegistrationKind::Vouch, Subtype::Vouch, "3.54.3", false),
    ];
    assert_eq!(RegistrationKind::ALL.len(), expected.len());
    for (&kind, (named, subtype, path, is_request)) in RegistrationKind::ALL.iter().zip(expected) {
        assert_eq!(kind, named);
        assert_eq!(kind.subtype(), subtype);
        assert!(std::ptr::eq(kind.row(), subtype.row()));
        assert_eq!(kind.row().ordinal_path(), path);
        assert_eq!(kind.is_request(), is_request, "{kind:?}");
        assert_eq!(RegistrationKind::at(&kind.row().address), Some(kind));
    }
    for r in rows() {
        let is_a_kind = RegistrationKind::ALL.iter().any(|k| std::ptr::eq(k.row(), r));
        assert_eq!(RegistrationKind::at(&r.address).is_some(), is_a_kind, "{}", r.address);
    }
    let beneath = skep_registry::commons_type(&[54, 1, 1, 1]);
    assert_eq!(RegistrationKind::at(&beneath), None, "beneath a row is no row");
}

/// A small seeded generator, so a failure names its round.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn any_string(rng: &mut SplitMix64, longest: usize) -> String {
    const CHARACTERS: [char; 16] =
        ['a', 'Z', '0', ' ', '"', '\\', '/', '\n', '\t', '\u{0}', '\u{1f}', '\u{7f}', 'é', '€', '𝄞', '{'];
    (0..rng.below(longest + 1)).map(|_| CHARACTERS[rng.below(CHARACTERS.len())]).collect()
}

fn any_hex64(rng: &mut SplitMix64) -> Hex64 {
    let hex: String = (0..4).map(|_| format!("{:016x}", rng.next())).collect();
    Hex64::new(hex).expect("64 lowercase hex")
}

fn any_address(rng: &mut SplitMix64) -> Address {
    const COMPONENTS: [&str; 5] = ["1", "7", "255", "18446744073709551616", "42"];
    let field = |rng: &mut SplitMix64| -> Vec<&str> {
        (0..1 + rng.below(3)).map(|_| COMPONENTS[rng.below(COMPONENTS.len())]).collect()
    };
    let mut comps = field(rng);
    for _ in 0..rng.below(4) {
        comps.push("0");
        comps.extend(field(rng));
    }
    address(&comps.join("."))
}

fn any_digits(rng: &mut SplitMix64) -> Digits {
    let digits: String = (0..1 + rng.below(24)).map(|_| char::from(b'0' + rng.below(10) as u8)).collect();
    Digits::new(digits).expect("decimal digits")
}

fn any_principal(rng: &mut SplitMix64) -> Principal {
    let id = match rng.below(4) {
        0 => 0,
        1 => Principal::MAX,
        _ => rng.next() % (Principal::MAX + 1),
    };
    Principal::new(id).expect("inside the range")
}

fn any_body(rng: &mut SplitMix64) -> RegistrationBody {
    match rng.below(6) {
        0 => RegistrationBody::Fresh(Fresh {
            door: any_string(rng, 90),
            fresh: any_hex64(rng),
            shape: any_string(rng, 12),
            node: any_string(rng, 400),
            board: any_string(rng, 400),
            signer: any_hex64(rng),
            signature: HexDigits::new("0Ab9".repeat(rng.below(40))).expect("hex"),
        }),
        1 => RegistrationBody::BoardCarriesOn(BoardCarriesOn {
            door: any_string(rng, 90),
            fresh: any_hex64(rng),
            shape: any_string(rng, 12),
            node: any_string(rng, 400),
            signer: any_hex64(rng),
            signature: HexDigits::new("f".repeat(rng.below(40))).expect("hex"),
        }),
        2 => RegistrationBody::Approved(Approved {
            prefix: any_address(rng),
            node_address: any_address(rng),
            node_principal: any_principal(rng),
            board: (rng.below(2) == 0).then(|| ProvisionedBoard {
                address: any_address(rng),
                principal: any_principal(rng),
                origin: any_string(rng, 40),
            }),
            door_origin: (rng.below(2) == 0).then(|| any_string(rng, 40)),
            collection_interval: any_digits(rng),
            disposition: Disposition::ALL[rng.below(Disposition::ALL.len())],
            policy: any_address(rng),
        }),
        3 => RegistrationBody::Refused(Refused { fault: Fault::ALL[rng.below(Fault::ALL.len())] }),
        4 => RegistrationBody::Denied(Denied { policy: any_address(rng), clause: any_digits(rng) }),
        _ => RegistrationBody::Vouch(Vouch {
            fingerprints: (0..rng.below(8)).map(|_| any_hex64(rng)).collect(),
            replaces: (rng.below(2) == 0).then(|| any_address(rng)),
        }),
    }
}

/// THE ENCODER's LAW: every body a caller builds — any strings, addresses of
/// any level, principals across the range, digits of any length, any
/// fingerprints in any order, with any `sig` or none — is the record its
/// encoding spells, under its own kind, and meets every law of the parse.
#[test]
fn every_body_a_caller_builds_is_a_record() {
    let mut rng = SplitMix64(0x5EED_2E61_5781_0D54);
    let mut kinds = std::collections::BTreeSet::new();
    for round in 0..3_000 {
        let body = any_body(&mut rng);
        let sig = match rng.below(3) {
            0 => None,
            1 => Some(String::new()),
            _ => Some(any_string(&mut rng, 60)),
        };
        let text = encode_registration(&body, sig.as_deref());
        let record = parse_registration(body.kind(), text.as_bytes())
            .unwrap_or_else(|r| panic!("round {round}: {text:?} refused {r}"));
        assert_eq!(record, RegistrationRecord { body: body.clone(), sig }, "round {round}");
        let _ = assert_the_laws_at(text.as_bytes());
        kinds.insert(format!("{:?}", body.kind()));
    }
    assert_eq!(kinds.len(), RegistrationKind::ALL.len(), "every kind was drawn");
}

/// THE PARSE's LAWS ON ONE-BYTE MUTANTS of every short admitted vector: a
/// byte written over, inserted or removed at every offset — whitespace,
/// structure, a digit, a letter in capitals, a control and a byte no UTF-8
/// holds — meets every law under each kind: an answer and no panic, a
/// record only where the mutant is its own encoding.
#[test]
fn the_parse_laws_hold_on_one_byte_mutants() {
    const ALPHABET: &[u8] = b" \n\"\\{}[]:,019aF\x00\xff";
    const MAX_SOURCE_BYTES: usize = 300;
    let set = vector_file("registration.json");
    let mut mutants = 0usize;
    let mut refused = 0usize;
    for vector in set["vectors"].as_array().expect("vectors") {
        if vector["parse"] != "ok" {
            continue;
        }
        let source = vector_bytes(vector);
        if source.len() > MAX_SOURCE_BYTES {
            continue;
        }
        for at in 0..source.len() {
            let mut removed = source.clone();
            removed.remove(at);
            let mut candidates = vec![removed];
            for &byte in ALPHABET {
                let mut over = source.clone();
                over[at] = byte;
                let mut inserted = source.clone();
                inserted.insert(at, byte);
                candidates.extend([over, inserted]);
            }
            for mutant in candidates {
                if mutant == source {
                    continue;
                }
                mutants += 1;
                refused += assert_the_laws_at(&mutant).iter().all(Result::is_err) as usize;
            }
        }
    }
    assert!(mutants > 20_000, "{mutants} mutants");
    assert!(refused * 10 > mutants * 9, "{refused} of {mutants} mutants are records of no kind");
}
