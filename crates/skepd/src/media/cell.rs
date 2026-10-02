//! THE REFERENCE CELL (media lane A; `media.md` item 4 — "ONE REFERENCE
//! CELL — three fields beside D13's `type` member", "THE V1 CELL CARRIES NO
//! EXTENT MEMBER", "THE HASH IS BLAKE3"; §Open, ONE STRICTNESS AT THREE
//! PARSERS; the register M-I3 (a)): the picture cell's v1 schema, its ONE
//! parser under the ONE canonical rule, its encoder, the designation its
//! hash function carries, and the kind's address. A leaf: it knows nothing
//! of the daemon and reads nothing but the bytes it is handed.
//!
//! THE SCHEMA, v1. One JSON object of exactly three members, in this order:
//! `type`, a string, the kind's address ([`KIND`]); `hash`, a string, the
//! BLAKE3 default hash of the file's bytes — 32 bytes as 64 LOWERCASE
//! hexadecimal characters (Q-sm1, owner 2026-09-26: "keep BLAKE3", frozen
//! as an algorithm tag is; a change is a SECOND SCHEMA under the same kind,
//! never an edit to this one); `size`, a JSON number, the file's byte
//! count, an integer up to 2^53 − 1 (what every JavaScript-backed reader of
//! the wire reads exactly, wire.md §Value encodings). NO EXTENT MEMBER
//! (ms5-D2, owner 2026-10-02: "v1 - no field"): a body carrying one is no
//! cell under this schema, and a video-era schema that carries one is a
//! second schema under D13.
//!
//! THE CANONICAL RULE — AUTH-2.130's admission sentence applied to the cell,
//! the credential record's as built (`skep-identity`'s `canonical_record`
//! and `parse_record_value`, the precedent this copies): `parse(b)` answers
//! a cell only where `b == encode(parse(b))`. So the cell has ONE form, the
//! bytes a signed body carries are the bytes a reader parses, and a body
//! with two `hash` members — which would let the daemon bind one and a
//! reader check the other — is no cell at every parser. The agreement of the
//! parsers that cannot share this code (the shell's, the browser page's) is
//! held as PATTERNS P5 holds a reproduced grammar: by THE VECTOR SET,
//! `tests/it/fixtures/media/cells.json`, run against each in its own gate —
//! this file's test runs it against this parser.
//!
//! NAMING THE KIND. A value whose `type` member is [`KIND`] names the kind
//! whatever the rest of it holds (m-Q3, owner 2026-09-26: "the write path
//! RECOGNIZES A CELL BY PARSING the composite value's own `type`"). A value
//! naming the kind that parses under no pinned schema — a second schema's
//! form, a malformed body, the two-hash body — is [`Refusal::UnknownSchema`],
//! told apart from a value that does not name the kind at all, because a
//! reader whose null permits a PERMANENT act halts on a schema it does not
//! know (DOCTRINE D13's carve-out; the record's H1: admitted as absent, such
//! a value would be an unbound cell the day a second schema is pinned). The
//! daemon's write door is such a reader; a value not naming the kind is
//! ordinary to it.
//!
//! THE CAP. A body past [`MAX_CELL_BYTES`] parses as no cell and names
//! nothing: `serde_json` builds its whole tree before the first schema check
//! (the record cap's reason, `skep-identity`'s `payload.rs`), and a canonical
//! cell is under 140 bytes. The cap is the KIND's, every schema's under it —
//! a schema never raises it — so a body past it is no cell of any schema and
//! D13's halt has nothing to halt on. Every pin here is INTERIM (the board's
//! sm-Q8), confirmed at the media round; the kind's address is TEST-ONLY
//! under the commons media range 3.80–3.89, unallocated as of this lane, and
//! the allocation lands by this one constant and the fixture's `kind`.

use std::fmt::Write as _;

use serde_json::Value;

use crate::limits::MAX_CELL_BYTES;

/// The cell kind's address — INTERIM, TEST-ONLY: the last ordinal of the
/// commons media range 3.80–3.89 under the ghost document's type subspace
/// (`1.1.0.1.0.1.0.3.N`, where the credential kinds sit at `3.1`–`3.3` and
/// the grant at `3.90`), the range `media.md` names for media and no
/// allocation has filled; taken at the range's top so the first natural
/// allocations — the typing link's media types — meet no squatter.
pub(crate) const KIND: &str = "1.1.0.1.0.1.0.3.89";

/// THE DESIGNATION: the name the cell's schema gives its hash function,
/// which every sidecar key from lane B carries beside the hex —
/// `blobs/<designation>/<hex>`, the lease's, the index's — so that a second
/// schema's hash of the same width (a SHA-256 tree's root, the FIPS path the
/// record names) is never read under this schema's rule (`media.md` item 4,
/// "EVERY SIDECAR KEY NAMES ITS FUNCTION, FROM THE FIRST FILE"). Pinned here,
/// where the schema is; INTERIM in name, the hash itself ruled. Its one
/// reader in this lane is the vector test, which holds the fixture's
/// `designation` to it; lane B's store keys are its first reader in the
/// daemon, and the expectation below retires with them.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "read by lane B's store keys; the vector test holds the fixture to it")
)]
pub(crate) const DESIGNATION: &str = "blake3";

/// The hash's width: BLAKE3's default output, 32 bytes — 64 hex characters.
pub(crate) const HASH_BYTES: usize = 32;

/// The largest `size` a cell carries: 2^53 − 1, the bound every machine
/// integer of the wire keeps (wire.md §Value encodings) so a
/// JavaScript-backed reader reads the count exactly.
pub(crate) const MAX_SIZE: u64 = (1 << 53) - 1;

/// A parsed cell: the file's hash and its byte count. Its `type` is no
/// field — it is the schema's fixed value, which [`encode`] writes and
/// [`parse`] demands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cell {
    pub(crate) hash: [u8; HASH_BYTES],
    pub(crate) size: u64,
}

/// Why bytes are no cell — three classes, because the door answers each
/// differently and a halting reader acts on one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Past [`MAX_CELL_BYTES`]: parsed by no reader of a cell, naming nothing.
    PastCap,
    /// Not a JSON object whose `type` member is [`KIND`]: prose, a predicate
    /// def, a record of another kind, bytes that are no JSON — ordinary bytes.
    NotTheKind,
    /// Names the kind and is no v1 cell: a second schema's form, a malformed
    /// body, the two-hash body — what D13's carve-out halts on.
    UnknownSchema,
}

impl Refusal {
    /// Whether the refused bytes NAME THE KIND — the one fact a reader whose
    /// null permits a permanent act halts on.
    pub(crate) fn names_kind(self) -> bool {
        matches!(self, Refusal::UnknownSchema)
    }
}

/// THE ONE PARSER: the cell `bytes` spell, under the canonical rule — a cell
/// is answered only where `bytes == encode(parse(bytes))` — or why they are
/// no cell. Total over any bytes: no panic, no allocation past the cap's
/// tree, and `serde_json` answers only "is this JSON, and which" (AUTH-2.1's
/// discipline) — every verdict is this schema's own.
pub(crate) fn parse(bytes: &[u8]) -> Result<Cell, Refusal> {
    if bytes.len() > MAX_CELL_BYTES {
        return Err(Refusal::PastCap);
    }
    // A JSON object opens with `{` past any leading whitespace (RFC 8259's
    // four), and nothing else can name the kind: the one-byte test that keeps
    // the text discipline's values — one byte apiece, by the hundred thousand
    // per insert — from costing a parse each.
    let opens_an_object = bytes
        .iter()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .is_some_and(|b| *b == b'{');
    if !opens_an_object {
        return Err(Refusal::NotTheKind);
    }
    // A GENERIC value, bounded by the cap above; a body that is no JSON names
    // nothing, every schema being JSON.
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Refusal::NotTheKind)?;
    let Some(object) = value.as_object() else {
        return Err(Refusal::NotTheKind);
    };
    if object.get("type").and_then(Value::as_str) != Some(KIND) {
        return Err(Refusal::NotTheKind);
    }
    // From here the value NAMES THE KIND, and every departure from the v1
    // schema is a schema this parser does not know.
    let unknown = Refusal::UnknownSchema;
    if object.len() != 3 {
        return Err(unknown);
    }
    let hash = object.get("hash").and_then(Value::as_str).and_then(hash_of).ok_or(unknown)?;
    // `as_u64` is `None` for a fraction, an exponent form and a negative.
    let size = object.get("size").and_then(Value::as_u64).ok_or(unknown)?;
    if size > MAX_SIZE {
        return Err(unknown);
    }
    let cell = Cell { hash, size };
    // THE ADMISSION SENTENCE: admit only where the input is the canonical
    // re-encoding of what it spells — by the public encoder itself, the
    // function a signer composes with. A second `hash` member (the generic
    // parse keeps one), whitespace, a trailing byte, uppercase hex each fail
    // here.
    if encode(&cell).as_bytes() != bytes {
        return Err(unknown);
    }
    Ok(cell)
}

/// The hash member's 32 bytes, from exactly 64 LOWERCASE hex characters;
/// `None` for any other string. Lowercase is demanded here as well as by the
/// re-encoding compare, so the rule is stated where the member is read.
fn hash_of(hex: &str) -> Option<[u8; HASH_BYTES]> {
    let digits = hex.as_bytes();
    if digits.len() != 2 * HASH_BYTES {
        return None;
    }
    let nibble = |d: u8| match d {
        b'0'..=b'9' => Some(d - b'0'),
        b'a'..=b'f' => Some(d - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; HASH_BYTES];
    for (slot, pair) in out.iter_mut().zip(digits.chunks(2)) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// THE CANONICAL FORM — the one byte string a cell has:
/// `{"type":"<KIND>","hash":"<64 lowercase hex>","size":<count>}`, no
/// whitespace, the members in that order, nothing after the brace. What a
/// signer composes, what a verifier re-spells, and what [`parse`] holds its
/// input to.
pub(crate) fn encode(cell: &Cell) -> String {
    let mut out = String::with_capacity(160);
    out.push_str("{\"type\":\"");
    out.push_str(KIND);
    out.push_str("\",\"hash\":\"");
    for byte in cell.hash {
        let _ = write!(out, "{byte:02x}");
    }
    let _ = write!(out, "\",\"size\":{}}}", cell.size);
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use skep_address::{validate, Nat, Tumbler};

    use super::*;

    /// The vector set, as the fixture carries it.
    fn fixture() -> Value {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/cells.json");
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
                    assert_eq!(encode(&cell).as_bytes(), body.as_slice(), "{name}: b == encode(parse(b))");
                    assert_eq!(parse(encode(&cell).as_bytes()), Ok(cell), "{name}: a fixpoint");
                    admitted += 1;
                }
                ("no_cell", Err(refusal)) => {
                    assert_eq!(refusal.names_kind(), names_kind, "{name}: {refusal:?}");
                    refused += 1;
                }
                (verdict, answer) => panic!("{name}: the fixture says {verdict}, the parser {answer:?}"),
            }
        }
        assert!(admitted >= 3 && refused >= 20, "{admitted} admitted, {refused} refused");
        // The refusals the lane's brief names, each present by name.
        for required in [
            "two_hash_members", "size_as_string", "extent_member", "member_order",
            "uppercase_hex", "hex_63", "hex_65", "another_kind", "second_designation",
            "past_the_cap", "whitespace",
        ] {
            assert!(vectors.iter().any(|v| v["name"] == required), "the set names {required}");
        }
    }

    /// The kind's interim address is a T4-valid address under the ghost
    /// document's type subspace, in the commons media range; the designation
    /// and the width are the ruled ones.
    #[test]
    fn the_kind_is_an_address_in_the_commons_media_range() {
        let comps: Vec<Nat> = KIND.split('.').map(|c| Nat::from(c.parse::<u32>().unwrap())).collect();
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
        assert_eq!(parse(&past), Err(Refusal::PastCap));
        past.truncate(MAX_CELL_BYTES);
        assert_eq!(parse(&past), Err(Refusal::NotTheKind), "at the cap: parsed, and no JSON");
        assert_eq!(parse(b"x"), Err(Refusal::NotTheKind), "a text value costs no parse");
    }
}
