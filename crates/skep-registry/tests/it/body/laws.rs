//! THE LAWS `src/body.rs` states for every input, each tried on inputs no
//! hand chose: THE ESCAPE TABLE at every Unicode scalar value — each
//! spelled exactly as the table states, and each read back as itself — and
//! THE PARSE'S LAWS, stated once ([`assert_the_laws_at`]): an answer and no
//! panic, `past_cap` exactly past the cap, a record only where the body is
//! its own encoding, of the kind named, its sig-less projection a fixpoint,
//! and a record under one kind at most, `wrong_type` under the other. Every
//! one-byte mutant of every admitted vector meets them, and so do seeded
//! hostile bodies several edits from any vector, at every refusal the parse
//! answers. The vector set and its readers are the parent's.

use skep_registry::{
    encode, parse, Body, BodyKind, Endpoint, Origins, ParseRefusal, Record,
    MAX_REGISTRY_RECORD_BYTES,
};

use super::{bytes_of, vector_set};

/// The escape table as `src/body.rs`'s encoding paragraph states it (REG-1.86
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

/// THE PARSE'S LAWS, stated once — what `parse` promises of every input,
/// asked at one body under each kind in turn: an answer and no panic;
/// `past_cap` exactly where the body is past the cap; a record only where
/// the body is its own canonical encoding (REG-1.86 (h)), of the kind named,
/// its sig-less projection a fixpoint (REG-1.86 (e)); and a record under one
/// kind at most, `wrong_type` under the other (REG-1.86 (a)). The one-byte
/// mutants and the hostile bodies below both drive it, so a law joins here
/// once and every input meets it. Hands back, under each kind, the parse's
/// answer with its record set aside: `Ok(())` where the kind admitted the
/// body, the refusal where it did not.
fn assert_the_laws_at(body: &[u8]) -> [Result<(), ParseRefusal>; 2] {
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
                Ok(())
            }
            Err(refusal) => {
                assert_eq!(
                    refusal == ParseRefusal::PastCap,
                    past,
                    "{kind:?}: {refusal}: {}",
                    shown()
                );
                Err(refusal)
            }
        }
    });
    match &answers {
        [Ok(()), Ok(())] => panic!("a record under both kinds: {}", shown()),
        [Ok(()), Err(other)] | [Err(other), Ok(())] => assert_eq!(
            *other,
            ParseRefusal::WrongType,
            "a record under one kind, and the other's cause: {}",
            shown()
        ),
        [Err(_), Err(_)] => {}
    }
    answers
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
/// [`MAX_MUTANT_SOURCE_BYTES`]: each byte deleted, each byte of
/// [`MUTANT_ALPHABET`] written over it, and each inserted before it and
/// after the last. A mutant carries no kind of its own: the laws ask it
/// under both. An admitted vector within that bound added later joins
/// without an edit here.
fn one_byte_mutants() -> Vec<Vec<u8>> {
    let set = vector_set();
    let mut mutants = Vec::new();
    for vector in set["vectors"].as_array().expect("vectors") {
        if vector["parse"] != "ok" {
            continue;
        }
        let bytes = bytes_of(vector);
        if bytes.len() > MAX_MUTANT_SOURCE_BYTES {
            continue;
        }
        for i in 0..=bytes.len() {
            for &b in MUTANT_ALPHABET {
                let mut inserted = bytes.clone();
                inserted.insert(i, b);
                mutants.push(inserted);
            }
            if i < bytes.len() {
                let mut deleted = bytes.clone();
                deleted.remove(i);
                mutants.push(deleted);
                for &b in MUTANT_ALPHABET {
                    let mut written = bytes.clone();
                    written[i] = b;
                    mutants.push(written);
                }
            }
        }
    }
    mutants
}

/// THE PARSE'S LAWS ON EVERY ONE-BYTE MUTANT of every admitted vector
/// ([`assert_the_laws_at`]) — the inputs no hand chose that stand nearest
/// the records. The counts show the laws were tried on both sides.
#[test]
fn the_parse_laws_hold_on_every_one_byte_mutant() {
    let mutants = one_byte_mutants();
    assert!(mutants.len() > 10_000, "{} mutants", mutants.len());
    let (mut admitted, mut refused) = (0, 0);
    for bytes in &mutants {
        if assert_the_laws_at(bytes).iter().any(Result::is_ok) {
            admitted += 1;
        } else {
            refused += 1;
        }
    }
    assert!(admitted > 100 && refused > 100, "{admitted} admitted, {refused} refused");
}

/// splitmix64 — the generator the hostile bodies are drawn from, seeded
/// with one constant, so every run tries the same bodies and a failure
/// names the one that broke.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A draw below `n`, which is positive.
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
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

/// What the hostile bodies are drawn from, each list under its own name, so
/// no draw takes one list for another.
struct Corpus {
    /// The admitted vectors whole, the one at the cap among them: what half
    /// the bodies start from, and what an edit carries a range over from.
    sources: Vec<Vec<u8>>,
    /// The fragments an edit writes ([`fragments`]).
    fragments: Vec<Vec<u8>>,
    /// The values a composed body writes under a name not their own
    /// ([`other_values`]).
    others: Vec<String>,
}

impl Corpus {
    /// The corpus every run draws from: the set's admitted vectors, the
    /// fragments and the other values.
    fn new() -> Corpus {
        let set = vector_set();
        let sources = set["vectors"]
            .as_array()
            .expect("vectors")
            .iter()
            .filter(|v| v["parse"] == "ok")
            .map(bytes_of)
            .collect();
        Corpus { sources, fragments: fragments(), others: other_values() }
    }
}

/// A composed body: an object of up to five members — most often `type`
/// first, under one of the two kinds' strings — the rest each a name of
/// [`OWN_VALUES`], three times in four under a value of its own and else
/// under one of [`other_values`], in the order drawn, joined canonically or,
/// one time in ten, with a space after each comma.
fn composed_body(rng: &mut SplitMix64, corpus: &Corpus) -> Vec<u8> {
    let mut members = Vec::new();
    if rng.below(5) != 0 {
        members.push(format!(r#""type":{}"#, rng.pick(&[r#""binding""#, r#""endpoint""#])));
    }
    for _ in 0..=rng.below(4) {
        let (name, own) = rng.pick(&OWN_VALUES);
        let value =
            if rng.below(4) != 0 { *rng.pick(own) } else { rng.pick(&corpus.others).as_str() };
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
fn edit(rng: &mut SplitMix64, body: &mut Vec<u8>, corpus: &Corpus) {
    let at = rng.below(body.len() + 1);
    match rng.below(6) {
        0 => {
            let seams: Vec<usize> =
                (0..body.len()).filter(|&i| b"{[,".contains(&body[i])).map(|i| i + 1).collect();
            let at = if seams.is_empty() { at } else { *rng.pick(&seams) };
            let mut fragment = rng.pick(&corpus.fragments).clone();
            fragment.push(b',');
            body.splice(at..at, fragment);
        }
        1 => {
            let fragment = rng.pick(&corpus.fragments);
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
            let other = rng.pick(&corpus.sources);
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
fn hostile_body(rng: &mut SplitMix64, corpus: &Corpus) -> Vec<u8> {
    let (mut body, edits) = if rng.below(2) == 0 {
        (rng.pick(&corpus.sources).clone(), 1 + rng.below(4))
    } else {
        (composed_body(rng, corpus), usize::from(rng.below(4) == 0))
    };
    for _ in 0..edits {
        edit(rng, &mut body, corpus);
    }
    body
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
    let corpus = Corpus::new();
    let mut rng = SplitMix64(0x5EED_2E61_5781_0D1E);
    let mut admitted = 0;
    let mut causes = std::collections::BTreeSet::new();
    for _ in 0..hostile_rounds() {
        let body = hostile_body(&mut rng, &corpus);
        for answer in assert_the_laws_at(&body) {
            match answer {
                Ok(()) => admitted += 1,
                Err(refusal) => {
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
