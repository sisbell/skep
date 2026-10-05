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
//! THE ADMISSION SENTENCE with the parse's totality over every one-byte
//! mutant of every admitted vector: a mutant the parse admits is its own
//! canonical encoding, and no mutant makes the parse panic — and EVERY LAW
//! AT ONCE on seeded hostile bodies several edits from any vector: an
//! answer and no panic, `past_cap` exactly past the cap, a record only
//! where the body is its own encoding, and under one kind at most, met at
//! every refusal the parse answers.

use std::path::Path;

use serde_json::Value;
use skep_registry::{
    encode, parse, rows, Body, BodyKind, Endpoint, Kind, Member, Origins, ParseRefusal, Record,
    MAX_REGISTRY_RECORD_BYTES,
};

/// The vector set, `tests/vectors/records.json`, as the JSON it is.
fn vector_set() -> Value {
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
    let set = vector_set();
    assert_eq!(set["cap"].as_u64(), Some(MAX_REGISTRY_RECORD_BYTES as u64));
    let vectors = set["vectors"].as_array().expect("vectors");
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
            (_, Err(refusal)) => {
                assert_eq!(refusal.token(), answer, "{name}");
                refused += 1;
            }
            (_, Ok(record)) => {
                panic!("{name}: the set refuses it ({answer}), the parser admits {record:?}")
            }
        }
    }
    assert!(admitted >= 12 && refused >= 61, "{admitted} admitted, {refused} refused");
    // The vectors the lane names, the cap's two sides and the escape table's,
    // each present by name.
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

/// The alphabet a one-byte mutant writes, inserting a byte or writing one
/// over another: the whitespace JSON skips, its structure and escape
/// letters, digits and signs, two hex letters in capitals, NUL, DEL, a lone
/// continuation byte, and a byte no UTF-8 holds.
const MUTANT_ALPHABET: &[u8] = b" \t\n\"\\/{}[]:,.+-019eAFbnu\x00\x7f\x80\xff";

/// The longest admitted vector the one-byte mutants are drawn from: the
/// set's vectors at the cap are pinned whole by their own answers, and the
/// one-byte mutants of one would be some 930,000 bodies of 16 KiB.
const MAX_MUTANT_SOURCE_BYTES: usize = 1024;

/// Every one-byte mutant of every admitted vector no longer than
/// [`MAX_MUTANT_SOURCE_BYTES`], under its kind: each byte deleted, each
/// byte of [`MUTANT_ALPHABET`] written over it, and each inserted before it
/// and after the last. An admitted vector within that bound added later
/// joins without an edit here.
fn one_byte_mutants() -> Vec<(BodyKind, Vec<u8>)> {
    let set = vector_set();
    let mut mutants = Vec::new();
    for vector in set["vectors"].as_array().expect("vectors") {
        if vector["parse"] != "ok" {
            continue;
        }
        let (kind, bytes) = (kind_of(vector), bytes_of(vector));
        if bytes.len() > MAX_MUTANT_SOURCE_BYTES {
            continue;
        }
        for i in 0..=bytes.len() {
            for &b in MUTANT_ALPHABET {
                let mut inserted = bytes.clone();
                inserted.insert(i, b);
                mutants.push((kind, inserted));
            }
            if i < bytes.len() {
                let mut deleted = bytes.clone();
                deleted.remove(i);
                mutants.push((kind, deleted));
                for &b in MUTANT_ALPHABET {
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
        assert_eq!(parse(other, &bytes), Err(ParseRefusal::WrongType), "{shown:?}");
        admitted += 1;
    }
    assert!(admitted > 100 && refused > 100, "{admitted} admitted, {refused} refused");
}

/// splitmix64 — the generator the hostile bodies are drawn from, seeded
/// with one constant, so every run tries the same bodies and a failure
/// names the one that broke.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A draw below `n`, which is positive.
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// One of `items`, which hold at least one.
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// The fragments a hostile body's edits write, each a structure no one byte
/// reaches: a member of every name the bodies spell and of one they never
/// do, a value of every JSON shape — a number of each spelling, and objects
/// and arrays nested under a member — escapes short, long, uppercase, of a
/// lone surrogate, unfinished and in a run, text past ASCII, bytes no UTF-8
/// holds, a whitespace run, and arrays and one-member objects nested to
/// serde_json's depth limit and past it, closed, and arrays left open.
fn fragments() -> Vec<Vec<u8>> {
    let text = [
        r#""type":"binding""#,
        r#""type":"endpoint""#,
        r#""type":"takedown""#,
        r#""prefix":"1.5""#,
        r#""prefix":"1.0.1.0.1.0.2.3""#,
        r#""origins":["https://acme.example"]"#,
        r#""origins":[]"#,
        r#""replaces":"1.0.1.0.1.0.2.1""#,
        r#""sig":"abcd""#,
        r#""tier":"root""#,
        r#""x":{"y":[true,null,"z",{"w":[]}]}"#,
        r#""":{}"#,
        "0",
        "-0",
        "15",
        "1.5e3",
        "true",
        "null",
        "[]",
        "{}",
        r#""""#,
        "\"",
        "\\",
        ",",
        ":",
        "{",
        "}",
        "\t\n\r ",
        r"\n",
        r"\u000a",
        r"\u001F",
        r"\u0000",
        r"\/",
        r"\u00e9",
        r"\ud83d\ude00",
        r"\ud83d",
        r"\u12",
        r#"\\\"\\\"\\"#,
        "é",
        "\u{7f}",
        "\u{2028}",
        "😀",
        "1.0.0.5",
        "01",
    ];
    let mut fragments: Vec<Vec<u8>> = text.iter().map(|t| t.as_bytes().to_vec()).collect();
    for raw in [&b"\x00"[..], &b"\x80"[..], &b"\xc3"[..], &b"\xed\xa0\x80"[..], &b"\xff"[..]] {
        fragments.push(raw.to_vec());
    }
    for depth in [125, 126, 127] {
        let (open, close) = ("[".repeat(depth), "]".repeat(depth));
        let chain = format!("{}{{}}{}", r#"{"":"#.repeat(depth), "}".repeat(depth));
        fragments.extend([format!("{open}{close}"), chain, open].map(String::into_bytes));
    }
    fragments
}

/// What a composed body writes under each member name: the name's own
/// shape in its one spelling and in others — the binding's and the
/// endpoint's `type` strings and another body-bearing row's; addresses
/// whole, past a machine word, and malformed; lists of origins whole,
/// repeated, empty and mixed; `sig` strings plain and holding escapes the
/// canonical form writes and ones it never does — and a name the bodies
/// never spell.
const OWN_VALUES: [(&str, &[&str]); 6] = [
    ("type", &[r#""binding""#, r#""endpoint""#, r#""takedown""#]),
    ("prefix", &[r#""1.5""#, r#""1.18446744073709551616""#, r#""01.5""#, r#""1.0.0.5""#, r#""""#]),
    (
        "origins",
        &[
            r#"["https://acme.example"]"#,
            r#"["https://acme.example","https://acme.example"]"#,
            "[]",
            r#"[""]"#,
            r#"["a",null]"#,
        ],
    ),
    ("replaces", &[r#""1.0.1.0.1.0.2.3""#, r#""1.0.2.0.1.0.2.1""#, r#""x""#]),
    ("sig", &[r#""abcd""#, r#""""#, r#""a\n\u001f\"\\""#, r#""\u0041\/""#, r#""é""#]),
    ("tier", &[r#""root""#]),
];

/// The values a composed body writes under a name not their own: every
/// name's own values, and every other JSON shape — a number of each
/// spelling, one nested in an object, `true`, `null`, empty containers, and
/// arrays at the depth limit and one past it.
fn other_values() -> Vec<String> {
    let mut values: Vec<String> = OWN_VALUES
        .iter()
        .flat_map(|(_, own)| own.iter())
        .chain(&["0", "-1", "1.5e3", "true", "null", "{}", "[[]]", r#"{"n":{"m":[1]}}"#])
        .map(|v| (*v).to_owned())
        .collect();
    for depth in [126, 127] {
        values.push(format!("{}{}", "[".repeat(depth), "]".repeat(depth)));
    }
    values
}

/// A composed body: an object of up to five members — most often `type`
/// first, under one of the two kinds' strings — the rest each a name of
/// [`OWN_VALUES`], three times in four under a value of its own and else
/// under one of [`other_values`], in the order drawn, joined canonically or,
/// one time in ten, with a space after each comma.
fn composed_body(rng: &mut SplitMix64, others: &[String]) -> Vec<u8> {
    let mut members = Vec::new();
    if rng.below(5) != 0 {
        members.push(format!(r#""type":{}"#, rng.pick(&[r#""binding""#, r#""endpoint""#])));
    }
    for _ in 0..=rng.below(4) {
        let (name, own) = rng.pick(&OWN_VALUES);
        let value = if rng.below(4) != 0 { *rng.pick(own) } else { rng.pick(others).as_str() };
        members.push(format!(r#""{name}":{value}"#));
    }
    let comma = if rng.below(10) == 0 { ", " } else { "," };
    format!("{{{}}}", members.join(comma)).into_bytes()
}

/// One edit of a hostile body, one of — a fragment written after a seam a
/// JSON parser reads on past (a brace, a bracket or a comma), with the comma
/// that keeps an object or an array going; a fragment written at any byte;
/// a range of up to 24 bytes cut, enough for a whole member; a range of up
/// to 16 doubled; a range of up to 32 carried over from an admitted vector;
/// or the whole body wrapped in an array.
fn edit(rng: &mut SplitMix64, body: &mut Vec<u8>, sources: &[Vec<u8>], fragments: &[Vec<u8>]) {
    let at = rng.below(body.len() + 1);
    match rng.below(6) {
        0 => {
            let seams: Vec<usize> =
                (0..body.len()).filter(|&i| b"{[,".contains(&body[i])).map(|i| i + 1).collect();
            let at = if seams.is_empty() { at } else { *rng.pick(&seams) };
            let mut fragment = rng.pick(fragments).clone();
            fragment.push(b',');
            body.splice(at..at, fragment);
        }
        1 => {
            let fragment = rng.pick(fragments);
            body.splice(at..at, fragment.iter().copied());
        }
        2 => {
            let end = body.len().min(at + 1 + rng.below(24));
            body.drain(at..end);
        }
        3 => {
            let end = body.len().min(at + 1 + rng.below(16));
            let doubled = body[at..end].to_vec();
            body.splice(end..end, doubled);
        }
        4 => {
            let other = rng.pick(sources);
            let from = rng.below(other.len());
            let end = other.len().min(from + 1 + rng.below(32));
            body.splice(at..at, other[from..end].iter().copied());
        }
        _ => {
            body.insert(0, b'[');
            body.push(b']');
        }
    }
}

/// One hostile body: half the time an admitted vector carried one to four
/// [`edit`]s from itself — the vector at the cap among them, so a body is
/// carried past it — and half the time a [`composed_body`], one time in
/// four carried an edit from itself.
fn hostile_body(
    rng: &mut SplitMix64,
    sources: &[Vec<u8>],
    fragments: &[Vec<u8>],
    others: &[String],
) -> Vec<u8> {
    let (mut body, edits) = if rng.below(2) == 0 {
        (rng.pick(sources).clone(), 1 + rng.below(4))
    } else {
        (composed_body(rng, others), usize::from(rng.below(4) == 0))
    };
    for _ in 0..edits {
        edit(rng, &mut body, sources, fragments);
    }
    body
}

/// Asserts the parse's laws at one body, under each kind in turn: an answer
/// and no panic; `past_cap` exactly where the body is past the cap; a record only
/// where the body is its own canonical encoding, of the kind named, its
/// sig-less projection a fixpoint; and a record under one kind at most.
/// Answers each kind's refusal, `None` where the kind admitted the body.
fn assert_the_laws_at(body: &[u8]) -> [Option<ParseRefusal>; 2] {
    let shown = || {
        let head: String = String::from_utf8_lossy(body).chars().take(240).collect();
        format!("{head:?} ({} bytes)", body.len())
    };
    let past = body.len() > MAX_REGISTRY_RECORD_BYTES;
    let answers = [BodyKind::Binding, BodyKind::Endpoint].map(|kind| {
        let answer = std::panic::catch_unwind(|| parse(kind, body))
            .unwrap_or_else(|_| panic!("{kind:?}: the parse panicked on {}", shown()));
        match answer {
            Ok(record) => {
                assert!(!past, "{kind:?}: a record past the cap: {}", shown());
                assert_eq!(record.body.kind(), kind, "{}", shown());
                let encoded = encode(&record.body, record.sig.as_deref());
                assert!(encoded.as_bytes() == body, "{kind:?}: not its own encoding: {}", shown());
                let again = parse(kind, record.canonical_sigless().as_bytes());
                assert_eq!(again, Ok(Record { body: record.body, sig: None }), "{}", shown());
                None
            }
            Err(refusal) => {
                assert_eq!(
                    refusal == ParseRefusal::PastCap,
                    past,
                    "{kind:?}: {refusal}: {}",
                    shown()
                );
                Some(refusal)
            }
        }
    });
    assert!(answers.iter().any(Option::is_some), "a record under both kinds: {}", shown());
    answers
}

/// How many hostile bodies a run draws: 20,000 in the gate, forty times as
/// many under `FUZZ_EXHAUSTIVE=1`, the workspace's deep sweep of its tier-1
/// fuzz suites.
fn hostile_rounds() -> usize {
    let deep = std::env::var_os("FUZZ_EXHAUSTIVE").is_some_and(|v| v == "1");
    if deep {
        20_000 * 40
    } else {
        20_000
    }
}

/// Every refusal the parse answers, by token — what a run of hostile bodies
/// meets, so the laws are tried at every stage of the parse.
const EVERY_CAUSE: [&str; 17] = [
    "past_cap",
    "not_utf8",
    "not_json",
    "not_an_object",
    "number",
    "wrong_type",
    "unknown_member",
    "missing_member:prefix",
    "missing_member:origins",
    "not_a_string:prefix",
    "not_a_string:replaces",
    "not_a_string:sig",
    "not_an_address:prefix",
    "not_an_address:replaces",
    "origins_not_strings",
    "empty_origins",
    "not_canonical",
];

/// THE PARSE's LAWS ON SEEDED HOSTILE BODIES: every body the generator
/// draws — an admitted vector up to four edits from itself, or an object
/// composed member by member — meets the parse's laws under both kinds
/// ([`assert_the_laws_at`]). A one-byte mutant stays one byte from a
/// vector; these reach a member beside the row's own holding a nested
/// value, a run of escapes, an array at the depth limit, a member doubled,
/// cut or out of its order, a string in a spelling the canonical form never
/// writes, and the vector at the cap carried past it. The run meets records
/// and every refusal the parse answers, and no other: each law is tried at
/// every stage.
#[test]
fn the_parse_laws_hold_on_seeded_hostile_bodies() {
    let set = vector_set();
    let sources: Vec<Vec<u8>> = set["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .filter(|v| v["parse"] == "ok")
        .map(bytes_of)
        .collect();
    let (fragments, others) = (fragments(), other_values());
    let mut rng = SplitMix64(0x5EED_2E61_5781_0D1E);
    let mut admitted = 0;
    let mut causes = std::collections::BTreeSet::new();
    for _ in 0..hostile_rounds() {
        let body = hostile_body(&mut rng, &sources, &fragments, &others);
        for answer in assert_the_laws_at(&body) {
            match answer {
                None => admitted += 1,
                Some(refusal) => {
                    causes.insert(refusal.token());
                }
            }
        }
    }
    let unmet: Vec<&str> = EVERY_CAUSE.into_iter().filter(|c| !causes.contains(*c)).collect();
    assert!(unmet.is_empty(), "no hostile body was answered {unmet:?}");
    let unlisted: Vec<&String> =
        causes.iter().filter(|c| !EVERY_CAUSE.contains(&c.as_str())).collect();
    assert!(unlisted.is_empty(), "causes the list does not name: {unlisted:?}");
    assert!(admitted > 100, "{admitted} admitted");
}
