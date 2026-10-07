use std::path::Path;

use skep_address::{validate, Nat, Tumbler};

use super::*;

/// The vector set, as the fixture carries it.
fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/cells.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("the fixture is JSON")
}

/// A vector's bytes: its `body` string, or its `body_hex`.
fn body_of(vector: &Value) -> Vec<u8> {
    if let Some(text) = vector["body"].as_str() {
        return text.as_bytes().to_vec();
    }
    let hex = vector["body_hex"].as_str().expect("a vector carries body or body_hex");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// THE ONE VECTOR SET, at this parser (M-I3 (a); PATTERNS P5): every
/// vector meets the verdict the fixture pins — a cell, or none — and the
/// fact a halting reader acts on, whether it names the kind; every
/// admitted body is its own re-encoding (the canonical rule read from
/// both sides); and the fixture pins the same kind, designation and cap
/// this file does, so the shell's and the browser's parsers read the
/// pins from the set and not from a second transcription.
#[test]
fn the_vector_set_meets_one_verdict_at_this_parser() {
    let fixture = fixture();
    assert_eq!(fixture["kind"].as_str(), Some(KIND));
    assert_eq!(fixture["designation"].as_str(), Some(DESIGNATION));
    assert_eq!(fixture["cap"].as_u64(), Some(MAX_CELL_BYTES as u64));
    let vectors = fixture["vectors"].as_array().expect("vectors");
    let (mut admitted, mut refused) = (0, 0);
    for vector in vectors {
        let name = vector["name"].as_str().expect("a name");
        let body = body_of(vector);
        let names_kind = vector["names_kind"].as_bool().expect("names_kind");
        match (vector["verdict"].as_str().expect("a verdict"), parse(&body)) {
            ("cell", Ok(cell)) => {
                assert!(names_kind, "{name}: a cell names the kind");
                assert_eq!(
                    encode(&cell).as_bytes(),
                    body.as_slice(),
                    "{name}: b == encode(parse(b))"
                );
                assert_eq!(parse(encode(&cell).as_bytes()), Ok(cell), "{name}: a fixpoint");
                admitted += 1;
            }
            ("no_cell", Err(refusal)) => {
                assert_eq!(refusal.names_kind(), names_kind, "{name}: {refusal:?}");
                refused += 1;
            }
            (verdict, answer) => {
                panic!("{name}: the fixture says {verdict}, the parser {answer:?}")
            }
        }
    }
    assert!(admitted >= 3 && refused >= 20, "{admitted} admitted, {refused} refused");
    // The refusals the lane's brief names, each present by name.
    for required in [
        "two_hash_members",
        "size_as_string",
        "extent_member",
        "member_order",
        "uppercase_hex",
        "hex_63",
        "hex_65",
        "another_kind",
        "second_designation",
        "past_the_cap",
        "past_the_cap_not_naming",
        "whitespace",
        "blind_kind",
    ] {
        assert!(vectors.iter().any(|v| v["name"] == required), "the set names {required}");
    }
}

/// THE PREFIX TEST reads the canonical opening alone — past JSON
/// whitespace — and refuses prose, another kind, a longer address sharing
/// the kind's digits, and a value naming the kind in a spelling no
/// schema produces; `opens_as` reads the blind kind's opening the same
/// way, and neither reads the other's.
#[test]
fn the_prefix_test_reads_the_canonical_opening_alone() {
    let hash = "ab".repeat(32);
    let canonical = format!(r#"{{"type":"{KIND}","hash":"{hash}","size":5}}"#);
    assert!(names_kind_by_prefix(canonical.as_bytes()));
    assert!(names_kind_by_prefix(format!(" \n{canonical}").as_bytes()));
    assert!(names_kind_by_prefix(format!(r#"{{"type":"{KIND}","hash_alg":"x"}}"#).as_bytes()), "a second schema's form");
    assert!(!names_kind_by_prefix(b"prose"));
    assert!(!names_kind_by_prefix(b"{\"type\":\"1.1.0.1.0.1.0.3.1\"}"), "another kind");
    assert!(!names_kind_by_prefix(format!(r#"{{"type":"{KIND}1"}}"#).as_bytes()), "a longer address");
    assert!(!names_kind_by_prefix(format!(r#"{{ "type":"{KIND}"}}"#).as_bytes()), "a space inside");
    assert!(!names_kind_by_prefix(b""));
    assert!(!names_kind_by_prefix(b"   "));
    let blind_cell = blind::encode(&BlindCell { commitment: [0xcd; blind::COMMITMENT_BYTES] });
    assert!(!names_kind_by_prefix(blind_cell.as_bytes()), "the blind kind makes no index entry");
    assert!(opens_as(blind::KIND, blind_cell.as_bytes()));
    assert!(!opens_as(blind::KIND, canonical.as_bytes()));
}

/// THE CAP BOUNDS THE PARSE AND NEVER THE CLASSIFICATION (M-I3 (a);
/// `media.md` item 4): a body past the cap that opens as the picture
/// kind is `Picture(Err(UnknownSchema))` — the door's `unknown_cell_schema`
/// and the index's halt mark, `names_kind` true through the picture's
/// parser — one opening as the blind kind `Blind(Err(UnknownSchema))`,
/// which the picture's parser reads as not its kind (no halt mark), and
/// one opening as neither — the kind named later in the body, or no kind
/// — `None(PastCap)`, naming nothing; and no tree is built for any of
/// the three.
#[test]
fn past_the_cap_the_canonical_opening_names_the_kind_and_nothing_else_does() {
    let pad = "x".repeat(MAX_CELL_BYTES);
    let picture = format!(r#"{{"type":"{KIND}","hash":"{}","size":5,"pad":"{pad}"}}"#, "ab".repeat(32));
    assert!(picture.len() > MAX_CELL_BYTES);
    assert_eq!(classify(picture.as_bytes()), Class::Picture(Err(CellRefusal::UnknownSchema)));
    assert_eq!(parse(picture.as_bytes()), Err(CellRefusal::UnknownSchema), "the picture's parser halts on it");
    let blind_past = format!(r#"{{"type":"{}","commitment":"{}","pad":"{pad}"}}"#, blind::KIND, "cd".repeat(32));
    assert_eq!(classify(blind_past.as_bytes()), Class::Blind(Err(CellRefusal::UnknownSchema)));
    assert_eq!(parse(blind_past.as_bytes()), Err(CellRefusal::NotTheKind), "not the picture's: no halt mark");
    let later = format!(r#"{{"pad":"{pad}","type":"{KIND}"}}"#);
    assert_eq!(classify(later.as_bytes()), Class::None(CellRefusal::PastCap), "the kind named past the opening");
    assert_eq!(parse(later.as_bytes()), Err(CellRefusal::PastCap));
    let spaced = format!(r#"{{ "type":"{KIND}","pad":"{pad}"}}"#);
    assert_eq!(classify(spaced.as_bytes()), Class::None(CellRefusal::PastCap), "a spelling no schema produces");
    assert!(!CellRefusal::PastCap.names_kind());
}

/// THE ONE CLASSIFICATION (`media.md` item 4; the investigation §5 (i)):
/// a value is read by its `type` — the picture's canonical cell is
/// `Picture(Ok)`, a malformed picture body `Picture(Err(UnknownSchema))`,
/// the blind kind's canonical cell `Blind(Ok)` and a blind body with a
/// `size` member `Blind(Err(UnknownSchema))` — and a value naming neither
/// kind, a body past the cap and no-JSON are `None` with the refusal the
/// picture parser gives. Each parser answers `NotTheKind` for the OTHER
/// kind's cell, names_kind false both ways: the index's entry path and
/// the door's halt are each kind's own.
#[test]
fn the_classification_reads_either_kind_once_and_each_parser_refuses_the_other() {
    let picture = encode(&Cell { hash: [0xab; HASH_BYTES], size: 5 });
    let blind_cell = blind::encode(&BlindCell { commitment: [0xcd; blind::COMMITMENT_BYTES] });
    assert!(matches!(classify(picture.as_bytes()), Class::Picture(Ok(_))));
    assert!(matches!(classify(blind_cell.as_bytes()), Class::Blind(Ok(_))));
    let sized =
        format!(r#"{{"type":"{}","commitment":"{}","size":5}}"#, blind::KIND, "cd".repeat(32));
    assert_eq!(classify(sized.as_bytes()), Class::Blind(Err(CellRefusal::UnknownSchema)));
    let two_hash =
        format!(r#"{{"type":"{KIND}","hash":"{0}","hash":"{0}","size":5}}"#, "ab".repeat(32));
    assert_eq!(classify(two_hash.as_bytes()), Class::Picture(Err(CellRefusal::UnknownSchema)));
    assert_eq!(classify(b"prose"), Class::None(CellRefusal::NotTheKind));
    assert_eq!(classify(br#"{"type":"1.1.0.1.0.1.0.3.1"}"#), Class::None(CellRefusal::NotTheKind));
    let mut past = b"{\"type\":\"".to_vec();
    past.resize(MAX_CELL_BYTES + 1, b' ');
    assert_eq!(classify(&past), Class::None(CellRefusal::PastCap));
    assert_eq!(
        parse(blind_cell.as_bytes()),
        Err(CellRefusal::NotTheKind),
        "the picture parser: not its kind"
    );
    assert_eq!(
        blind::parse(picture.as_bytes()),
        Err(CellRefusal::NotTheKind),
        "the blind parser: not its kind"
    );
    assert!(!CellRefusal::NotTheKind.names_kind() && CellRefusal::UnknownSchema.names_kind());
}

/// The kind's interim address is a T4-valid address under the ghost
/// document's type subspace, in the commons media range; the designation
/// and the width are the ruled ones.
#[test]
fn the_kind_is_an_address_in_the_commons_media_range() {
    let comps: Vec<Nat> =
        KIND.split('.').map(|c| Nat::from(c.parse::<u32>().unwrap())).collect();
    validate(Tumbler::new(comps).expect("a tumbler")).expect("a T4-valid address");
    let (prefix, ordinal) = KIND.rsplit_once('.').unwrap();
    assert_eq!(prefix, "1.1.0.1.0.1.0.3", "the ghost document's type subspace");
    let ordinal: u32 = ordinal.parse().unwrap();
    assert!((80..=89).contains(&ordinal), "under the media range 3.80–3.89: {ordinal}");
    assert_eq!(DESIGNATION, "blake3");
    assert_eq!(HASH_BYTES, 32);
}

/// The cap bounds the parse, never a cell: the largest canonical cell is
/// far under it, a body one byte past it is refused before any tree is
/// built, and a body at the cap that opens an object is parsed.
#[test]
fn the_cap_bounds_the_parse_and_never_a_cell() {
    let largest = encode(&Cell { hash: [0xff; HASH_BYTES], size: MAX_SIZE });
    assert!(largest.len() < 140, "{}", largest.len());
    assert_eq!(MAX_CELL_BYTES, 1024);
    let mut past = b"{".to_vec();
    past.resize(MAX_CELL_BYTES + 1, b' ');
    assert_eq!(parse(&past), Err(CellRefusal::PastCap));
    past.truncate(MAX_CELL_BYTES);
    assert_eq!(parse(&past), Err(CellRefusal::NotTheKind), "at the cap: parsed, and no JSON");
    assert_eq!(parse(b"x"), Err(CellRefusal::NotTheKind), "a text value costs no parse");
}
