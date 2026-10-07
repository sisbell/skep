//! THE BLIND DOCUMENT's CELL (`media.md` §Separate data stores 2 and item 4,
//! "TWO SCHEMAS, TWO VECTOR SETS, ONE CLASSIFICATION, ONE CAP"; the
//! blind-document investigation §2, §5 (i); the rulings s6-D3 — the blind
//! document in for v1 — and bd-D1, bd-D3; the register M-I2 (e), (i), M-I7
//! (a)): the second cell kind beside the picture's. A blind document is a
//! media document whose picture is kept on its OWNER's own machine: the board
//! holds a COMMITMENT to the file and never its bytes — keyed BLAKE3 under a
//! declared tag over the file's hash, by a per-document key the owner's
//! client keeps with the bytes (bd-D1, bd-D2) — so the commitment confirms
//! nothing to a holder of a candidate file (M-I2 (i)), and the cell carries
//! no `size` (bd-D3) and no `hash`: nothing here can name a file, and NOTHING
//! THE DAEMON DOES FOR A BLIND CELL READS A FILE, A LEASE OR AN INDEX ENTRY
//! (the investigation §5). What the daemon learns about the bytes: nothing.
//! It parses one JSON object and stores it, as it stores a sentence. A leaf,
//! as `cell.rs` is.
//!
//! THE SCHEMA, v1. One JSON object of exactly two members, in this order:
//! `type`, a string, the kind's address ([`KIND`]); `commitment`, a string,
//! 32 bytes as 64 LOWERCASE hexadecimal characters. THE CANONICAL RULE is
//! the picture's (`cell.rs`): `parse(b)` answers a blind cell only
//! where `b == encode(parse(b))`, so a `size` member, a `hash` member, a
//! second `commitment`, the members reordered, uppercase hex, 63 or 65 hex
//! characters, a space, a trailing byte — each is NO CELL at every parser,
//! and a body past the cap, [`crate::limits::MAX_CELL_BYTES`], is parsed by
//! no reader of a cell at all: THE CAP IS THE KIND's, one for every media
//! cell kind. The
//! agreement of the parsers that cannot share this code is held by THE
//! VECTOR SET, `skepd`'s `tests/it/fixtures/media/blind-cells.json`, the
//! mirror of the picture's `cells.json`, run against this parser by this
//! file's test.
//!
//! NAMING THE KIND, and the classification: a value whose `type` member is
//! [`KIND`] names this kind whatever the rest of it holds, and one naming it
//! under no schema this build reads is [`CellRefusal::UnknownSchema`] — the
//! door's `unknown_cell_schema`, the fetch route's halt face — never admitted
//! as ordinary bytes (D13's carve-out, one strictness at every parser). The
//! `type` is read ONCE, by [`cell::classify`](crate::cell::classify), which
//! hands this parser the object it built; [`parse_object`] is that
//! classification's blind arm, and [`CellRefusal::NotTheKind`] for the
//! picture kind's `type` as the picture's parser is for this kind's. A
//! malformed blind body makes NO HALT MARK at the cell index: the index's
//! prefix test reads the picture kind's opening alone, and the halt exists
//! because the pruner's null is a permission to unlink — nothing of this kind
//! can name a file.
//!
//! Every pin here is INTERIM (sm-Q8): the kind's address is TEST-ONLY, the
//! commons media range's allocation beside the picture's `3.89`.

use serde_json::{Map, Value};
use skep_util::json::{hex_string, parse_lower_hex};

#[cfg(test)]
use crate::cell;
use crate::cell::{CellRefusal, HASH_BYTES};

/// The blind kind's address — INTERIM, TEST-ONLY: the commons media range's
/// allocation beside the picture's `3.89` under the ghost document's type
/// subspace, taken at the range's top with it so the first natural
/// allocations meet no squatter; the allocation lands by this one constant
/// and the fixture's `kind`.
pub(crate) const KIND: &str = "1.1.0.1.0.1.0.3.88";

/// The commitment's width: 32 bytes — 64 hex characters — the width of the
/// keyed hash the owner's client computes (bd-D1), the picture's hash width.
pub(crate) const COMMITMENT_BYTES: usize = HASH_BYTES;

/// A parsed blind cell: the commitment, and nothing else. Its `type` is no
/// field — it is the schema's fixed value, which [`encode`] writes and
/// [`parse_object`] demands — and it carries no size and no hash by design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlindCell {
    pub(crate) commitment: [u8; COMMITMENT_BYTES],
}

/// THE BLIND KIND's PARSER ALONE: the cell `bytes` spell under the canonical
/// rule, or why they are no blind cell — the classification's blind arm,
/// [`CellRefusal::NotTheKind`] for a value of any other `type`, the picture's
/// included, and the cap's and no-JSON's refusals as [`cell::parse`] gives
/// them. Total over any bytes. Compiled for the tests alone: every shipped
/// reader of a value — the door, the fetch — classifies, and no shipped
/// path reads this kind by itself (the cell index's entry path reads the
/// picture's opening alone); the vector set runs against the kind's own
/// verdict through this, as the picture's runs against [`cell::parse`].
#[cfg(test)]
pub(super) fn parse(bytes: &[u8]) -> Result<BlindCell, CellRefusal> {
    match cell::classify(bytes) {
        cell::Class::Blind(verdict) => verdict,
        cell::Class::Picture(_) => Err(CellRefusal::NotTheKind),
        cell::Class::None(refusal) => Err(refusal),
    }
}

/// The blind kind's own canonical check, past the classification: `object`
/// NAMES THE KIND, and every departure from the v1 schema is a schema this
/// parser does not know — the two-member arity, the commitment's 64
/// lowercase hex, and THE ADMISSION SENTENCE, `bytes == encode(parse(bytes))`
/// by the public encoder itself, which a second `commitment` member, a
/// `size`, a `hash`, whitespace, a trailing byte and uppercase hex each fail.
pub(super) fn parse_object(
    object: &Map<String, Value>,
    bytes: &[u8],
) -> Result<BlindCell, CellRefusal> {
    let unknown = CellRefusal::UnknownSchema;
    if object.len() != 2 {
        return Err(unknown);
    }
    let commitment = object
        .get("commitment")
        .and_then(Value::as_str)
        .and_then(parse_lower_hex::<COMMITMENT_BYTES>)
        .ok_or(unknown)?;
    let blind = BlindCell { commitment };
    if encode(&blind).as_bytes() != bytes {
        return Err(unknown);
    }
    Ok(blind)
}

/// THE CANONICAL FORM — the one byte string a blind cell has:
/// `{"type":"<KIND>","commitment":"<64 lowercase hex>"}`, no whitespace,
/// the members in that order, nothing after the brace: what the owner's
/// client composes and signs, what a reader re-spells, and what
/// [`parse_object`] holds its input to.
pub(crate) fn encode(blind: &BlindCell) -> String {
    let mut out = String::with_capacity(120);
    out.push_str("{\"type\":\"");
    out.push_str(KIND);
    out.push_str("\",\"commitment\":\"");
    out.push_str(&hex_string(&blind.commitment));
    out.push_str("\"}");
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use skep_address::{validate, Nat, Tumbler};

    use super::*;
    use crate::limits::MAX_CELL_BYTES;

    /// The vector set, as the fixture carries it.
    fn fixture() -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../skepd/tests/it/fixtures/media/blind-cells.json");
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

    /// THE BLIND KIND's VECTOR SET, at this parser (the investigation §8 test
    /// 1; M-I3 (a); PATTERNS P5): every vector meets the verdict the fixture
    /// pins and the fact a halting reader acts on; every admitted body is its
    /// own re-encoding and a fixpoint; the fixture pins the kind and the cap
    /// this file does — the cap the picture's, one for every media cell kind.
    #[test]
    fn the_blind_vector_set_meets_one_verdict_at_this_parser() {
        let fixture = fixture();
        assert_eq!(fixture["kind"].as_str(), Some(KIND));
        assert_eq!(fixture["cap"].as_u64(), Some(MAX_CELL_BYTES as u64));
        let vectors = fixture["vectors"].as_array().expect("vectors");
        let (mut admitted, mut refused) = (0, 0);
        for vector in vectors {
            let name = vector["name"].as_str().expect("a name");
            let body = body_of(vector);
            let names_kind = vector["names_kind"].as_bool().expect("names_kind");
            match (vector["verdict"].as_str().expect("a verdict"), parse(&body)) {
                ("cell", Ok(blind)) => {
                    assert!(names_kind, "{name}: a blind cell names the kind");
                    assert_eq!(
                        encode(&blind).as_bytes(),
                        body.as_slice(),
                        "{name}: b == encode(parse(b))"
                    );
                    assert_eq!(parse(encode(&blind).as_bytes()), Ok(blind), "{name}: a fixpoint");
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
        assert!(admitted >= 1 && refused >= 15, "{admitted} admitted, {refused} refused");
        for required in [
            "size_member",
            "hash_member",
            "two_commitment_members",
            "member_order",
            "uppercase_hex",
            "hex_63",
            "hex_65",
            "hex_not_hex",
            "whitespace",
            "trailing_byte",
            "extent_member",
            "designation_member",
            "empty_commitment",
            "picture_kind",
            "another_kind",
            "past_the_cap",
            "past_the_cap_not_naming",
            "round_trips_to_other_bytes",
        ] {
            assert!(vectors.iter().any(|v| v["name"] == required), "the set names {required}");
        }
    }

    /// The kind's interim address is a T4-valid address under the ghost
    /// document's type subspace, in the commons media range, and NOT the
    /// picture kind's; the commitment's width is the hash's.
    #[test]
    fn the_kind_is_an_address_in_the_commons_media_range_beside_the_pictures() {
        let comps: Vec<Nat> =
            KIND.split('.').map(|c| Nat::from(c.parse::<u32>().unwrap())).collect();
        validate(Tumbler::new(comps).expect("a tumbler")).expect("a T4-valid address");
        let (prefix, ordinal) = KIND.rsplit_once('.').unwrap();
        assert_eq!(prefix, "1.1.0.1.0.1.0.3", "the ghost document's type subspace");
        let ordinal: u32 = ordinal.parse().unwrap();
        assert!((80..=89).contains(&ordinal), "under the media range 3.80–3.89: {ordinal}");
        assert_ne!(KIND, cell::KIND, "a kind of its own");
        assert_eq!(COMMITMENT_BYTES, 32);
    }

    /// The cap bounds the parse, never a cell: the canonical blind cell is far
    /// under 140 bytes, a body one byte past the cap is refused before any
    /// tree is built, and at the cap a body that opens an object is parsed.
    #[test]
    fn the_cap_bounds_the_parse_and_never_a_blind_cell() {
        let canonical = encode(&BlindCell { commitment: [0xff; COMMITMENT_BYTES] });
        assert!(canonical.len() < 140, "{}", canonical.len());
        println!("the canonical blind cell is {} bytes", canonical.len());
        let mut past = b"{".to_vec();
        past.resize(MAX_CELL_BYTES + 1, b' ');
        assert_eq!(parse(&past), Err(CellRefusal::PastCap));
        past.truncate(MAX_CELL_BYTES);
        assert_eq!(parse(&past), Err(CellRefusal::NotTheKind), "at the cap: parsed, and no JSON");
        assert_eq!(parse(b"x"), Err(CellRefusal::NotTheKind), "a text value costs no parse");
    }
}
