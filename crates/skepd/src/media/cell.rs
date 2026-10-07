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
//! this module's test (`media/cell/tests.rs`) runs it against this parser.
//!
//! NAMING THE KIND. A value whose `type` member is [`KIND`] names the kind
//! whatever the rest of it holds (m-Q3, owner 2026-09-26: "the write path
//! RECOGNIZES A CELL BY PARSING the composite value's own `type`"). A value
//! naming the kind that parses under no pinned schema — a second schema's
//! form, a malformed body, the two-hash body — is [`CellRefusal::UnknownSchema`],
//! told apart from a value that does not name the kind at all, because a
//! reader whose null permits a PERMANENT act halts on a schema it does not
//! know (DOCTRINE D13's carve-out; the record's H1: admitted as absent, such
//! a value would be an unbound cell the day a second schema is pinned). The
//! daemon's write door is such a reader; a value not naming the kind is
//! ordinary to it.
//!
//! TWO KINDS, ONE CLASSIFICATION (`media.md` item 4, "TWO SCHEMAS, TWO
//! VECTOR SETS, ONE CLASSIFICATION, ONE CAP"; the blind-document
//! investigation §5 (i); s6-D3 RULED): the blind document's cell
//! (`media/blind.rs`) is a second kind beside the picture's, and
//! [`classify`] reads EITHER kind by its `type` with one generic parse — the
//! cap, the `{` test, the JSON tree built once, the `type` member read once,
//! then the kind's own canonical check — so two kinds cost one JSON tree.
//! [`parse`] keeps its contract as the PICTURE kind's parser: a value of any
//! other `type`, the blind kind's included, is [`CellRefusal::NotTheKind`] to
//! it, which is what keeps the cell index's one entry path reading the
//! picture's opening alone; the door and the fetch route read
//! [`classify`].
//!
//! THE CAP BOUNDS THE PARSE AND NEVER THE CLASSIFICATION (`media.md` item
//! 4; the register M-I3 (a)). A body past [`MAX_CELL_BYTES`] is parsed by
//! no reader of a cell: `serde_json` builds its whole tree before the first
//! schema check (the record cap's reason, `skep-identity`'s `payload.rs`),
//! and a canonical cell is under 140 bytes, so the cap bounds the tree a
//! hostile body can command. But a value NAMES THE KIND by its `type`
//! member, read by the parse within the cap and, past it, by THE CANONICAL
//! OPENING every schema's canonical form writes first,
//! `{"type":"<the kind's address>"` ([`names_kind_by_prefix`], [`opens_as`];
//! D13: the carrier goes first in JSON) — so a past-cap value that opens as
//! a kind is [`CellRefusal::UnknownSchema`] of that kind, refused
//! `unknown_cell_schema` at the door and, for the picture's kind, entered a
//! halt mark by the index, whatever cap a later build pins; and one that
//! opens as neither is [`CellRefusal::PastCap`], no cell of any schema and no
//! entry. The cap is the KIND's, every schema's under it — a schema never
//! raises it. Every pin here is INTERIM (the board's sm-Q8), confirmed at
//! the media round; the kind's address is TEST-ONLY under the commons media
//! range 3.80–3.89, unallocated as of this lane, and the allocation lands by
//! this one constant and the fixture's `kind`.

use std::fmt::Write as _;

use serde_json::{Map, Value};

use super::blind::{self, BlindCell};
use crate::codec::{hex_string, parse_lower_hex};
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
/// where the schema is; INTERIM in name, the hash itself ruled. Read by
/// every sidecar key the daemon writes and reads — the blob store's paths,
/// the lease, the cell index, the pruner, the fetch, the operator's tools —
/// and held to the fixture's `designation` by the vector test.
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
/// differently and a halting reader acts on one of them. The classes are
/// every media kind's: a blind cell's parser answers the same three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CellRefusal {
    /// Past [`MAX_CELL_BYTES`] and opening as no kind: parsed by no reader
    /// of a cell, naming nothing. A past-cap body that opens as a kind is
    /// never this: it names the kind by its canonical opening and is
    /// [`CellRefusal::UnknownSchema`] of that kind.
    PastCap,
    /// Not a JSON object whose `type` member is the parser's kind: prose, a
    /// predicate def, a record of another kind — the other media kind among
    /// them — bytes that are no JSON: ordinary bytes to this parser.
    NotTheKind,
    /// Names A MEDIA KIND under no schema this build reads: a second
    /// schema's form, a malformed body, the two-hash body, a blind cell with
    /// a `size` — what D13's carve-out halts on.
    UnknownSchema,
}

impl CellRefusal {
    /// Whether the refused bytes NAME THE KIND — the one fact a reader whose
    /// null permits a permanent act halts on.
    pub(crate) fn names_kind(self) -> bool {
        matches!(self, CellRefusal::UnknownSchema)
    }
}

/// What a value is to the media kinds — [`classify`]'s answer: one kind
/// named, with that kind's own verdict under its schema (`Err` is always
/// [`CellRefusal::UnknownSchema`] there: the value named the kind and parsed
/// under no schema this build reads), or neither kind named, with why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Class {
    /// The `type` member is the picture kind's: a cell, or the halt.
    Picture(Result<Cell, CellRefusal>),
    /// The `type` member is the blind kind's: a blind cell, or the halt.
    Blind(Result<BlindCell, CellRefusal>),
    /// No media kind named: past the cap, or not a kind.
    None(CellRefusal),
}

/// THE ONE CLASSIFICATION, ahead of both parsers (`media.md` item 4; the
/// investigation §5 (i)): the cap, the `{` test, the generic parse ONCE, the
/// `type` member read ONCE, then the named kind's own canonical check — so
/// two kinds cost one JSON tree, and the cap is the KIND's, one for every
/// media cell kind, since a classification by `type` must parse before it
/// knows the kind. PAST THE CAP the classification reads the canonical
/// opening alone, one byte compare per kind ([`opens_as`]): a body opening
/// as a kind names it under no schema this build reads, and one opening as
/// neither names nothing. Total over any bytes, as [`parse`] is: no panic,
/// no allocation past the cap's tree, and `serde_json` answers only "is
/// this JSON, and which" (AUTH-2.1's discipline) — every verdict a schema's
/// own.
pub(crate) fn classify(bytes: &[u8]) -> Class {
    if bytes.len() > MAX_CELL_BYTES {
        if opens_as(KIND, bytes) {
            return Class::Picture(Err(CellRefusal::UnknownSchema));
        }
        if opens_as(blind::KIND, bytes) {
            return Class::Blind(Err(CellRefusal::UnknownSchema));
        }
        return Class::None(CellRefusal::PastCap);
    }
    // A JSON object opens with `{` past any leading whitespace (RFC 8259's
    // four), and nothing else can name a kind: the one-byte test that keeps
    // the text discipline's values — one byte apiece, by the hundred thousand
    // per insert — from costing a parse each.
    let opens_an_object = bytes
        .iter()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .is_some_and(|b| *b == b'{');
    if !opens_an_object {
        return Class::None(CellRefusal::NotTheKind);
    }
    // A GENERIC value, bounded by the cap above; a body that is no JSON names
    // nothing, every schema being JSON.
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return Class::None(CellRefusal::NotTheKind);
    };
    let Some(object) = value.as_object() else {
        return Class::None(CellRefusal::NotTheKind);
    };
    match object.get("type").and_then(Value::as_str) {
        Some(KIND) => Class::Picture(parse_picture(object, bytes)),
        Some(kind) if kind == blind::KIND => Class::Blind(blind::parse_object(object, bytes)),
        _ => Class::None(CellRefusal::NotTheKind),
    }
}

/// THE ONE PARSER of the PICTURE kind: the cell `bytes` spell, under the
/// canonical rule — a cell is answered only where
/// `bytes == encode(parse(bytes))` — or why they are no cell. The
/// classification's picture arm, and [`CellRefusal::NotTheKind`] for a value of
/// any other `type`, the blind kind's included: this parser's contract is the
/// picture's, and the cell index's one entry path reads it so.
pub(crate) fn parse(bytes: &[u8]) -> Result<Cell, CellRefusal> {
    match classify(bytes) {
        Class::Picture(verdict) => verdict,
        Class::Blind(_) => Err(CellRefusal::NotTheKind),
        Class::None(refusal) => Err(refusal),
    }
}

/// The picture kind's own canonical check, past the classification: the
/// value `object` NAMES THE KIND, and every departure from the v1 schema is
/// a schema this parser does not know.
fn parse_picture(object: &Map<String, Value>, bytes: &[u8]) -> Result<Cell, CellRefusal> {
    let unknown = CellRefusal::UnknownSchema;
    if object.len() != 3 {
        return Err(unknown);
    }
    // The hash member: exactly 64 LOWERCASE hex, the codec's own parse of
    // what `hex_string` writes — the rule stated where the member is read,
    // ahead of the re-encoding compare that holds the whole body to it.
    let hash = object
        .get("hash")
        .and_then(Value::as_str)
        .and_then(parse_lower_hex::<HASH_BYTES>)
        .ok_or(unknown)?;
    // `as_u64` is `None` for a fraction, an exponent form and a negative.
    let size = object.get("size").and_then(Value::as_u64).ok_or(unknown)?;
    if size > MAX_SIZE {
        return Err(unknown);
    }
    let cell = Cell { hash, size };
    // THE ADMISSION SENTENCE: admit only where the input is the canonical
    // re-encoding of what it spells — by the public encoder itself, the
    // function a signer composes with. A second `hash` member (the generic
    // parse keeps one), whitespace and a trailing byte each fail here; an
    // uppercase hash has failed the member's read above.
    if encode(&cell).as_bytes() != bytes {
        return Err(unknown);
    }
    Ok(cell)
}

/// THE CHEAP PREFIX TEST of the PICTURE kind, ahead of every parse the
/// cell index makes (`media/index.rs`'s walk and entries, `write_path.rs`'s
/// prefix test ahead of a commit): past leading JSON whitespace, the bytes
/// open `{"type":"<the kind's address>"` — the canonical spelling every
/// pinned schema puts first (D13: one JSON object naming its kind), so a
/// value that names the kind in that form costs a parse and every other
/// value a byte compare. A value naming the kind in a spelling no canonical
/// schema produces — the member reordered, a space inside the object — is
/// read as no cell here, as the door refuses it. The picture's alone: the
/// blind kind makes no index entry.
pub(crate) fn names_kind_by_prefix(bytes: &[u8]) -> bool {
    opens_as(KIND, bytes)
}

/// Whether `bytes` open as the kind at `kind` — past leading JSON
/// whitespace (RFC 8259's four), exactly `{"type":"<kind>"` — the one
/// reading of the canonical opening both the prefix test and the past-cap
/// classification make, so the two cannot disagree on what names a kind.
pub(crate) fn opens_as(kind: &str, bytes: &[u8]) -> bool {
    let start = bytes
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .unwrap_or(bytes.len());
    let Some(rest) = bytes[start..].strip_prefix(b"{\"type\":\"") else { return false };
    let kind = kind.as_bytes();
    rest.len() > kind.len() && rest.starts_with(kind) && rest[kind.len()] == b'"'
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
    out.push_str(&hex_string(&cell.hash));
    let _ = write!(out, "\",\"size\":{}}}", cell.size);
    out
}

#[cfg(test)]
mod tests;
