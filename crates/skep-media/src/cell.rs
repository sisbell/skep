//! The reference cell: the picture cell's v1 schema, its parser and encoder.
//!
//! Its rules are `media.md` item 4 — "one reference cell — three fields
//! beside D13's `type` member", "the v1 cell carries no extent member", "the
//! hash is BLAKE3"; §Open, one strictness at three parsers — and the
//! register M-I3 (a). The module holds the picture cell's v1 schema, its one
//! parser under the one canonical rule, its encoder, the designation its
//! hash function carries, and the kind's address. A leaf: it knows nothing
//! of the daemon and reads nothing but the bytes it is handed.
//!
//! **The schema, v1.** One JSON object of exactly three members, in this
//! order: `type`, a string, the kind's address ([`KIND`]); `hash`, a string,
//! the BLAKE3 default hash of the file's bytes — 32 bytes as 64 lowercase
//! hexadecimal characters (frozen as an algorithm tag is; a change is a
//! second schema under the same kind, never an edit to this one); `size`, a
//! JSON number, the file's byte count, an integer up to 2^53 − 1 (what every
//! JavaScript-backed reader of the wire reads exactly, wire.md §Value
//! encodings). No extent member: a body carrying one is no cell under this
//! schema, and a video-era schema that carries one is a second schema under
//! D13.
//!
//! **The canonical rule.** It is AUTH-2.130's admission sentence applied to
//! the cell, the credential record's as built (`skep-identity`'s
//! `canonical_record` and `parse_record_value`, the precedent this copies):
//! `parse(b)` answers a cell only where `b == encode(parse(b))`. So the cell
//! has one form, the bytes a signed body carries are the bytes a reader
//! parses, and a body with two `hash` members — which would let the daemon
//! bind one and a reader check the other — is no cell at every parser. The
//! agreement of the parsers that cannot share this code (the shell's, the
//! browser page's) is held as PATTERNS P5 holds a reproduced grammar: by the
//! vector set, `skepd`'s `tests/it/fixtures/media/cells.json`, run against
//! each in its own gate — this module's test (`cell/tests.rs`) runs it
//! against this parser.
//!
//! **Naming the kind.** A value whose `type` member is [`KIND`] names the
//! kind whatever the rest of it holds: the write path recognizes a cell by
//! parsing the composite value's own `type`. A value naming the kind that
//! parses under no pinned schema — a second schema's form, a malformed body,
//! the two-hash body — is `CellRefusal::UnknownSchema`, told apart from a
//! value that does not name the kind at all, because a reader whose null
//! permits a permanent act halts on a schema it does not know (DOCTRINE
//! D13's carve-out; the record's H1: admitted as absent, such a value would
//! be an unbound cell the day a second schema is pinned). The daemon's write
//! door is such a reader; a value not naming the kind is ordinary to it.
//!
//! **Two kinds, one classification** (`media.md` item 4, "two schemas, two
//! vector sets, one classification, one cap"; the blind-document
//! investigation §5 (i)). The blind document's cell — this module's child
//! `blind` (`cell/blind.rs`) — is a second kind beside the picture's, and
//! `classify` reads either kind by its `type` with one generic parse — the
//! cap, the `{` test, the JSON tree built once, the `type` member read once,
//! then the kind's own canonical check — so two kinds cost one JSON tree.
//! `parse` keeps its contract as the picture kind's parser: a value of any
//! other `type`, the blind kind's included, is `CellRefusal::NotTheKind` to
//! it, which is what keeps the cell index's one entry path reading the
//! picture's opening alone; the door and the fetch route read `classify`.
//!
//! **The cap bounds the parse and never the classification** (`media.md`
//! item 4; the register M-I3 (a)). A body past the cap,
//! `limits::MAX_CELL_BYTES`, is parsed by no reader of a cell: `serde_json`
//! builds its whole tree before the first schema check (the record cap's
//! reason, `skep-identity`'s `payload.rs`), and a canonical cell is under
//! 140 bytes, so the cap bounds the tree a hostile body can command. But a
//! value names the kind by its `type` member, read by the parse within the
//! cap and, past it, by the canonical opening every schema's canonical form
//! writes first, `{"type":"<the kind's address>"` ([`names_kind_by_prefix`],
//! `opens_as`; D13: the carrier goes first in JSON) — so a past-cap value
//! that opens as a kind is `CellRefusal::UnknownSchema` of that kind,
//! refused `unknown_cell_schema` at the door and, for the picture's kind,
//! entered a halt mark by the index, whatever cap a later build pins; and
//! one that opens as neither is `CellRefusal::PastCap`, no cell of any
//! schema and no entry. The cap is the kind's, every schema's under it — a
//! schema never raises it. Every pin here is interim; the kind's address is
//! test-only under the commons media range 3.80–3.89, which no allocation
//! has filled, and the allocation lands by this one constant and the
//! fixture's `kind`.

// The blind document's cell: the second kind, a commitment and nothing else,
// read through this module's classification alone.
pub(crate) mod blind;

use std::fmt::Write as _;

use serde_json::{Map, Value};
use skep_util::json::{hex_string, parse_lower_hex};

use self::blind::BlindCell;
use crate::limits::MAX_CELL_BYTES;

/// The cell kind's address, interim and test-only.
///
/// It is the last ordinal of the commons media range 3.80–3.89 under the
/// ghost document's type subspace (`1.1.0.1.0.1.0.3.N`, where the credential
/// kinds sit at `3.1`–`3.3` and the grant at `3.90`), the range `media.md`
/// names for media and no allocation has filled; taken at the range's top
/// so the first natural allocations — the typing link's media types — meet
/// no squatter.
pub const KIND: &str = "1.1.0.1.0.1.0.3.89";

/// The designation: the name the cell's schema gives its hash function.
///
/// Every sidecar key carries it beside the hex — `blobs/<designation>/<hex>`,
/// the lease's, the index's — so that a second schema's hash of the same
/// width (a SHA-256 tree's root, the FIPS path the record names) is never
/// read under this schema's rule (`media.md` item 4, "every sidecar key
/// names its function, from the first file"). Pinned here, where the schema
/// is; interim in name, the hash itself settled. Read by every sidecar key
/// the daemon writes and reads — the blob store's paths, the lease, the cell
/// index, the pruner, the fetch, the operator's tools — and held to the
/// fixture's `designation` by the vector test.
pub const DESIGNATION: &str = "blake3";

/// The pinned designation set: the designations this build's schemas pin.
///
/// It holds `blake3`, the picture cell schema's [`DESIGNATION`], pinned
/// beside it, so a second schema's designation joins the set where that
/// schema lands. A directory under `blobs/` named otherwise is a sidecar of
/// a build this one is not: it halts the pruner's unlink pass (`media.md` Op
/// inventory 1, "only under the designations this build's schemas pin"), and
/// the operator's inventory lists it as foreign.
pub const PINNED_DESIGNATIONS: &[&str] = &[DESIGNATION];

/// The hash's width: BLAKE3's default output, 32 bytes — 64 hex characters.
pub const HASH_BYTES: usize = 32;

/// The largest `size` a cell carries: 2^53 − 1.
///
/// It is the bound every machine integer of the wire keeps (wire.md §Value
/// encodings), so a JavaScript-backed reader reads the count exactly.
const MAX_SIZE: u64 = (1 << 53) - 1;

/// A parsed cell: the file's hash and its byte count.
///
/// Its `type` is no field — it is the schema's fixed value, which
/// [`encode`] writes and `parse` demands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cell {
    pub(crate) hash: [u8; HASH_BYTES],
    pub(crate) size: u64,
}

/// Why bytes are no cell: three classes.
///
/// The door answers the one that names a kind with its halt and the other
/// two alike, as bytes that name no kind, and a halting reader acts on that
/// one. The classes are every media kind's: a blind cell's parser answers
/// the same three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CellRefusal {
    /// Past [`MAX_CELL_BYTES`] and opening as no kind.
    ///
    /// Parsed by no reader of a cell, it names nothing. A past-cap body that
    /// opens as a kind is never this: it names the kind by its canonical
    /// opening and is `CellRefusal::UnknownSchema` of that kind.
    PastCap,
    /// Not a JSON object whose `type` member is the parser's kind.
    ///
    /// Prose, a predicate def, a record of another kind — the other media
    /// kind among them — bytes that are no JSON: ordinary bytes to this
    /// parser.
    NotTheKind,
    /// Names a media kind under no schema this build reads.
    ///
    /// A second schema's form, a malformed body, the two-hash body, a blind
    /// cell with a `size` — what D13's carve-out halts on.
    UnknownSchema,
}

impl CellRefusal {
    /// Returns whether the refused bytes name the kind.
    ///
    /// It is the one fact a reader whose null permits a permanent act halts
    /// on.
    pub(crate) fn names_kind(self) -> bool {
        matches!(self, CellRefusal::UnknownSchema)
    }
}

/// The name of D13's halt: `unknown_cell_schema`.
///
/// It is the token of the verdict [`CellRefusal::UnknownSchema`] (wire.md
/// §Media, interim in spelling): what the door answers a value naming a
/// media kind under no pinned schema (its arm 4) and what the index's halt
/// mark records as its fault. Spelled here, beside the verdict it names, and
/// nowhere else in this crate but the tests that pin it.
pub(crate) const UNKNOWN_SCHEMA_TOKEN: &str = "unknown_cell_schema";

/// What a value is to the media kinds: `classify`'s answer.
///
/// It is one kind named, with that kind's own verdict under its schema
/// (`Err` is always `CellRefusal::UnknownSchema` there: the value named the
/// kind and parsed under no schema this build reads), or neither kind named,
/// with why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Class {
    /// The `type` member is the picture kind's: a cell, or the halt.
    Picture(Result<Cell, CellRefusal>),
    /// The `type` member is the blind kind's: a blind cell, or the halt.
    Blind(Result<BlindCell, CellRefusal>),
    /// No media kind named: past the cap, or not a kind.
    None(CellRefusal),
}

/// Classifies `bytes` by the media kind they name, ahead of both parsers.
///
/// It is the one classification (`media.md` item 4; the investigation §5
/// (i)): the cap, the `{` test, the generic parse once, the `type` member
/// read once, then the named kind's own canonical check — so two kinds cost
/// one JSON tree, and the cap is the kind's, one for every media cell kind,
/// since a classification by `type` must parse before it knows the kind.
/// Past the cap the classification reads the canonical opening alone, one
/// byte compare per kind (`opens_as`): a body opening as a kind names it
/// under no schema this build reads, and one opening as neither names
/// nothing. Total over any bytes, as `parse` is: no panic, no allocation
/// past the cap's tree, and `serde_json` answers only "is this JSON, and
/// which" (AUTH-2.1's discipline) — every verdict a schema's own.
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
    // A generic value, bounded by the cap above; a body that is no JSON names
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

/// Parses the cell `bytes` spell: the one parser of the picture kind.
///
/// It parses under the canonical rule — a cell is answered only where
/// `bytes == encode(parse(bytes))`. The classification's picture arm: this
/// parser's contract is the picture's, and the cell index's one entry path
/// reads it so.
///
/// # Errors
///
/// Why the bytes are no cell: `CellRefusal::UnknownSchema` for a value
/// naming the picture kind under no pinned schema; `CellRefusal::NotTheKind`
/// for a value of any other `type`, the blind kind's included, and for bytes
/// that name no kind within the cap; `CellRefusal::PastCap` for a body past
/// the cap that opens as no kind.
pub(crate) fn parse(bytes: &[u8]) -> Result<Cell, CellRefusal> {
    match classify(bytes) {
        Class::Picture(verdict) => verdict,
        Class::Blind(_) => Err(CellRefusal::NotTheKind),
        Class::None(refusal) => Err(refusal),
    }
}

/// Runs the picture kind's own canonical check, past the classification.
///
/// The value `object` names the kind.
///
/// # Errors
///
/// `CellRefusal::UnknownSchema` for every departure from the v1 schema: it
/// is a schema this parser does not know.
fn parse_picture(object: &Map<String, Value>, bytes: &[u8]) -> Result<Cell, CellRefusal> {
    let unknown = CellRefusal::UnknownSchema;
    if object.len() != 3 {
        return Err(unknown);
    }
    // The hash member: exactly 64 lowercase hex, the codec's own parse of
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
    // The admission sentence: admit only where the input is the canonical
    // re-encoding of what it spells — by the one encoder itself, the
    // canonical form a signer composes. A second `hash` member (the generic
    // parse keeps one), whitespace and a trailing whitespace byte each fail
    // here; an uppercase hash has failed the member's read above, and any
    // other trailing byte the generic parse.
    if encode(&cell).as_bytes() != bytes {
        return Err(unknown);
    }
    Ok(cell)
}

/// Returns whether `bytes` open as the picture kind: the cheap prefix test.
///
/// It runs ahead of every parse the cell index makes (`index.rs`'s walk and
/// entries, the daemon's `commits.rs` prefix test ahead of a commit): past
/// leading JSON whitespace, the bytes open `{"type":"<the kind's address>"`
/// — the canonical spelling every pinned schema puts first (D13: one JSON
/// object naming its kind), so a value that names the kind in that form
/// costs a parse and every other value a byte compare. A value naming the
/// kind in a spelling no canonical schema produces — the member reordered, a
/// space inside the object — is read as no cell here, as the door refuses
/// it. The picture's alone: the blind kind makes no index entry.
pub fn names_kind_by_prefix(bytes: &[u8]) -> bool {
    opens_as(KIND, bytes)
}

/// Returns whether `bytes` open as the kind at `kind`.
///
/// Past leading JSON whitespace (RFC 8259's four), they open exactly
/// `{"type":"<kind>"` — the one reading of the canonical opening both the
/// prefix test and the past-cap classification make, so the two cannot
/// disagree on what names a kind.
fn opens_as(kind: &str, bytes: &[u8]) -> bool {
    let start = bytes
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .unwrap_or(bytes.len());
    let Some(rest) = bytes[start..].strip_prefix(b"{\"type\":\"") else { return false };
    let kind = kind.as_bytes();
    rest.len() > kind.len() && rest.starts_with(kind) && rest[kind.len()] == b'"'
}

/// Returns the canonical form: the one byte string a cell has.
///
/// It is `{"type":"<KIND>","hash":"<64 lowercase hex>","size":<count>}`, no
/// whitespace, the members in that order, nothing after the brace. What a
/// signer composes, what a verifier re-spells, and what `parse` holds its
/// input to.
fn encode(cell: &Cell) -> String {
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
