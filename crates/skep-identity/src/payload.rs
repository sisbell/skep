//! Credential-record constants, payload types, the pinned line grammar, and
//! the ONE payload read — AUTH-1.18–1.28, AUTH-2.3–2.19, AUTH-2.36–2.45.
//!
//! The grammar (headers, tokenization, both kinds' line forms, the parse
//! fault precedence) and the four payload pins (per-span check order, the
//! reach walk, the byte cap, home anchoring) are PERMANENT protocol pins —
//! I2 frozen constants (AUTH-2.90). A Rust non-folding reader obtains the
//! payload read by LINKING [`record_bytes`], never by re-implementing it
//! (AUTH-2.37).

use skep_address::{document_of, shift, validate, Address, Level, Nat, Span};

use crate::key::{Fingerprint, PublicKey, ALGS};
use crate::seam::Values;

/// AUTH-1.18 — the enrollment header, line 1 byte-exact (AUTH-2.7).
pub const ENROLL_HEADER: &str = "skep-enroll v1";

/// AUTH-1.18 — the retirement header, line 1 byte-exact (AUTH-2.7).
pub const RETIRE_HEADER: &str = "skep-retire v1";

/// AUTH-1.18 — the record cap. Bounds ONE record — the concatenated bytes of
/// the link's own FROM spans, never the home document (AUTH-1.19) — counted
/// in BYTES, never positions (AUTH-1.20). A PERMANENT pin: there is no fold
/// version and the constant MUST NOT change (AUTH-1.21, I2 AUTH-2.90). It
/// bounds the fold's per-record work only under the wire-codec premise that
/// every value carries ≥ 1 byte (AUTH-1.22).
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// One enrollment line's parse (AUTH-1.23): the key, the anchor flag, and
/// the informational label. `anchor` is the ANCHOR flag — part of the pinned
/// line grammar from v1 (the LEADING token `anchor`, AUTH-1.26, AUTH-2.11);
/// a fingerprint's flag is fixed for the fingerprint's lifetime by the
/// record that first enrolls it (I9, AUTH-2.104).
#[derive(Clone, PartialEq, Eq)]
pub struct Enrollment {
    /// The enrolled public key.
    pub key: PublicKey,
    /// The anchor flag (AUTH-1.26).
    pub anchor: bool,
    label: Option<String>,
}

impl Enrollment {
    /// AUTH-1.25 — the ONLY constructor. The label DOMAIN (AUTH-1.24) is
    /// `None`, or text that is non-empty and contains no `\n` — a trailing
    /// 0x20 is IN the domain. `Some("")` maps to `None`; a label containing
    /// `\n` is `Err(LabelError::Newline)`.
    pub fn new(key: PublicKey, anchor: bool, label: Option<String>) -> Result<Enrollment, LabelError> {
        let label = match label {
            Some(l) if l.contains('\n') => return Err(LabelError::Newline),
            Some(l) if l.is_empty() => None,
            other => other,
        };
        Ok(Enrollment { key, anchor, label })
    }

    /// The label, in the AUTH-1.24 domain by construction (AUTH-1.25).
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

/// [`Enrollment::new`] rejection (AUTH-1.23–1.25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelError {
    /// The label contains `\n` — outside the AUTH-1.24 domain.
    Newline,
}

/// AUTH-1.27 — a payload fault. `TooLarge`, `ForeignContent` and
/// `MissingValue` report that a record's payload could not be READ; the
/// remaining variants that it could not be PARSED. The `usize` is a 1-based
/// line number, the header being line 1; `DuplicateKey` names the REPEATING
/// line (AUTH-2.15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    /// The concatenated FROM-span bytes exceed [`MAX_RECORD_BYTES`]
    /// (AUTH-2.43).
    TooLarge,
    /// A FROM span was not minted under the link's own home — or its start
    /// is no content position at all (AUTH-2.38 items 1–3, AUTH-2.40,
    /// AUTH-2.44).
    ForeignContent,
    /// A FROM span names a position the home had not minted as of the
    /// deposit's position (AUTH-2.38 item 4, AUTH-2.45).
    MissingValue,
    /// The payload does not decode as UTF-8 (AUTH-2.19 item 1).
    NotUtf8,
    /// Line 1 is not the kind's header, byte-exact (AUTH-2.7).
    BadHeader,
    /// The named line fails the kind's line grammar (AUTH-2.8–2.14).
    BadLine(usize),
    /// Zero key/fingerprint lines after a clean scan (AUTH-2.16) — never
    /// `NothingChanged`.
    Empty,
    /// The named line repeats an earlier line's fingerprint, compared as
    /// PARSED bytes (AUTH-2.15).
    DuplicateKey(usize),
}

impl PayloadError {
    /// AUTH-1.28 — THE ONE authority for the payload fault tokens. `<n>` is
    /// the 1-based line number, which is why the return type is `String`.
    /// The wire detail for a fold refusal is `Inert::token()`, `:`, and this
    /// token — one join, written in skepd (AUTH-2.55).
    pub fn token(&self) -> String {
        match self {
            PayloadError::TooLarge => "too_large".to_owned(),
            PayloadError::ForeignContent => "foreign_content".to_owned(),
            PayloadError::MissingValue => "missing_value".to_owned(),
            PayloadError::NotUtf8 => "not_utf8".to_owned(),
            PayloadError::BadHeader => "bad_header".to_owned(),
            PayloadError::Empty => "empty".to_owned(),
            PayloadError::BadLine(n) => format!("bad_line:{n}"),
            PayloadError::DuplicateKey(n) => format!("duplicate_key:{n}"),
        }
    }
}

/// AUTH-2.6 — lines split on `\n` ONLY, nothing trimmed (`\r` is an ordinary
/// payload byte); AUTH-2.19 item 1 — UTF-8 first, else `NotUtf8`.
fn decode_lines(bytes: &[u8]) -> Result<Vec<&str>, PayloadError> {
    let text = core::str::from_utf8(bytes).map_err(|_| PayloadError::NotUtf8)?;
    Ok(text.split('\n').collect())
}

/// AUTH-2.7/AUTH-2.19 item 2 — line 1 is the header, literally, byte-exact
/// (a leading blank line, a trailing space, a CRLF header each fail here).
fn check_header(lines: &[&str], header: &str) -> Result<(), PayloadError> {
    if lines.first().copied() != Some(header) {
        return Err(PayloadError::BadHeader);
    }
    Ok(())
}

/// AUTH-2.8 — tokens separate on exactly one ASCII 0x20, with NO collapsing
/// and no other separator byte: the token before the FIRST 0x20, and the
/// remainder AFTER it (`None` when no separator exists). A doubled separator
/// therefore yields an empty token in the next position; a TAB is an
/// ordinary byte inside a token.
fn split_token(s: &str) -> (&str, Option<&str>) {
    match s.split_once(' ') {
        Some((token, rest)) => (token, Some(rest)),
        None => (s, None),
    }
}

/// AUTH-2.18 — parse an enrollment record (AUTH-2.12's grammar: line 1
/// `skep-enroll v1`, each further line `[anchor ]ed25519 <64 hex>[ <label>]`).
/// Strict: any unparseable line makes the whole record inert. Fault
/// precedence per AUTH-2.19: UTF-8, header, then lines 2..n IN ORDER (first
/// failing line wins — `BadLine(n)` or `DuplicateKey(n)`), `Empty` only
/// after a clean scan. Hex tokens are case-insensitive (AUTH-2.17); keyword
/// tokens match as bytes, lowercase (AUTH-2.9).
pub fn parse_enroll(bytes: &[u8]) -> Result<Vec<Enrollment>, PayloadError> {
    let lines = decode_lines(bytes)?;
    check_header(&lines, ENROLL_HEADER)?;
    let mut out: Vec<Enrollment> = Vec::new();
    for (idx, line) in lines.iter().enumerate().skip(1) {
        let n = idx + 1; // 1-based; the header is line 1 (AUTH-1.27)
        if line.is_empty() {
            continue; // a zero-length line is ignored (AUTH-2.6, AUTH-2.7)
        }
        // AUTH-2.12 — dispatch on the FIRST token: sig · anchor · alg · else.
        let (first, rest) = split_token(line);
        if first == "sig" {
            continue; // AUTH-2.13 — skipped, whatever follows (AUTH-2.94)
        }
        let (anchor, alg, rest) = if first == "anchor" {
            // AUTH-2.11 — the anchor flag is the LEADING token; the line
            // then continues with the alg token.
            let Some(r) = rest else {
                return Err(PayloadError::BadLine(n)); // `anchor` alone
            };
            let (alg, r2) = split_token(r);
            (true, alg, r2)
        } else {
            (false, first, rest)
        };
        // AUTH-2.9 — the alg token matches as bytes, lowercase, against ALGS
        // (an alg the build does not carry is BadLine; `anchor anchor …` and
        // `anchor sig …` also land here).
        if !ALGS.iter().any(|(token, _, _)| *token == alg) {
            return Err(PayloadError::BadLine(n));
        }
        let Some(r) = rest else {
            return Err(PayloadError::BadLine(n)); // alg token with no hex
        };
        let (hex, after_hex) = split_token(r);
        let Ok(key) = PublicKey::parse(alg, hex) else {
            return Err(PayloadError::BadLine(n));
        };
        // AUTH-2.10 — the label is the REMAINDER after the one space that
        // follows the hex token, verbatim (it may end in 0x20); an EMPTY
        // remainder after that separator is BadLine — the test is the
        // remainder, never the line's last byte.
        let label = match after_hex {
            None => None,
            Some("") => return Err(PayloadError::BadLine(n)),
            Some(l) => Some(l.to_owned()),
        };
        // AUTH-2.15 — a fingerprint repeating an earlier line's, compared as
        // PARSED bytes (hex case is no distinction), whatever its flag.
        if out.iter().any(|e| e.key == key) {
            return Err(PayloadError::DuplicateKey(n));
        }
        // The parsed label is in the AUTH-1.24 domain by construction
        // (non-empty checked above; no '\n' — lines were split on it).
        let Ok(enrollment) = Enrollment::new(key, anchor, label) else {
            return Err(PayloadError::BadLine(n));
        };
        out.push(enrollment);
    }
    if out.is_empty() {
        return Err(PayloadError::Empty); // AUTH-2.16, AUTH-2.19 item 4
    }
    Ok(out)
}

/// AUTH-2.18 — parse a retirement record (AUTH-2.14's grammar: line 1
/// `skep-retire v1`, each further line `<64 hex fingerprint>` AND NOTHING
/// ELSE — any remainder after the fingerprint token is `BadLine`; `sig`
/// lines are skipped). Both kinds share one strictness and one fault
/// precedence (AUTH-2.19).
pub fn parse_retire(bytes: &[u8]) -> Result<Vec<Fingerprint>, PayloadError> {
    let lines = decode_lines(bytes)?;
    check_header(&lines, RETIRE_HEADER)?;
    let mut out: Vec<Fingerprint> = Vec::new();
    for (idx, line) in lines.iter().enumerate().skip(1) {
        let n = idx + 1;
        if line.is_empty() {
            continue;
        }
        let (first, rest) = split_token(line);
        if first == "sig" {
            continue; // AUTH-2.13/AUTH-2.14 — skipped, whatever follows
        }
        // AUTH-2.14 — no label, no trailing separator: ANY remainder after
        // the fingerprint token (`<64 hex> ` and `<64 hex> note` alike) is
        // BadLine.
        if rest.is_some() {
            return Err(PayloadError::BadLine(n));
        }
        let Some(fp) = Fingerprint::parse_hex(first) else {
            return Err(PayloadError::BadLine(n));
        };
        // AUTH-2.15 — never `removed = {F}` twice: the repeat is named.
        if out.contains(&fp) {
            return Err(PayloadError::DuplicateKey(n));
        }
        out.push(fp);
    }
    if out.is_empty() {
        return Err(PayloadError::Empty);
    }
    Ok(out)
}

/// AUTH-2.18 — encode an enrollment record; emits lowercase hex (AUTH-2.17)
/// and the label verbatim, so `parse(encode(x)) == x` holds over the whole
/// [`Enrollment`] domain (I1, AUTH-2.89).
pub fn encode_enroll(keys: &[Enrollment]) -> Vec<u8> {
    let mut s = String::new();
    s.push_str(ENROLL_HEADER);
    s.push('\n');
    for e in keys {
        if e.anchor {
            s.push_str("anchor "); // the LEADING token (AUTH-2.11)
        }
        s.push_str(e.key.alg());
        s.push(' ');
        s.push_str(&e.key.to_hex());
        if let Some(label) = e.label() {
            s.push(' ');
            s.push_str(label);
        }
        s.push('\n');
    }
    s.into_bytes()
}

/// AUTH-2.18 — encode a retirement record; lowercase hex (AUTH-2.17).
pub fn encode_retire(fps: &[Fingerprint]) -> Vec<u8> {
    let mut s = String::new();
    s.push_str(RETIRE_HEADER);
    s.push('\n');
    for fp in fps {
        s.push_str(&fp.to_hex());
        s.push('\n');
    }
    s.into_bytes()
}

/// AUTH-2.36 — THE ONE implementation of the pinned payload read: the
/// link's own FROM endset, its I-spans' bytes read in ENDSET ORDER and
/// concatenated, verbatim (SPAN BINDING, AUTH-2.3 — nothing sorts, dedups,
/// normalizes or coalesces; spans may repeat, overlap, or split a line,
/// AUTH-2.4). Bound at [`Values`] — the one-method supertrait, never the
/// whole world seam; [`MAX_RECORD_BYTES`] is INTERNAL and not a parameter.
///
/// Per SPAN, in endset order, the checks run in THIS order — the first
/// failure is the verdict (AUTH-2.38), and the per-span INTERLEAVE is pinned
/// (AUTH-2.39: each span's checks and positions complete before the next
/// span's checks begin — never a home pass over every span first):
///
/// 1. the start VALIDATES to an `Address` (M1), else `ForeignContent`;
/// 2. the start is an element POSITION — element field EXACTLY two
///    components, a subspace and an ordinal (AUTH-2.40); a document-level
///    start, a subspace-only start, and a deeper element field are each
///    T4-valid NON-positions ⇒ `ForeignContent`, never coerced. The test
///    constrains the field's SHAPE, never which subspace it names
///    (AUTH-2.41: a link-subspace start IS a position and walks to
///    `MissingValue`);
/// 3. `document_of(start) == home` (HOME ANCHORING, AUTH-2.44), else
///    `ForeignContent` before a byte of that span is read;
///
/// then, per POSITION of the span — the reach WALK is M1 `shift(t, 1)` from
/// `span.start()`, taken while the address is still inside the span's reach,
/// NEVER a count read off `width`'s last component (AUTH-2.42):
///
/// 4. the value — `ctx.value_at(t)`; `None` ⇒ `MissingValue` (reachable:
///    an endset names addresses verbatim, AUTH-2.45);
/// 5. the cap — `TooLarge` iff the bytes appended so far plus THIS value's
///    length exceed `MAX_RECORD_BYTES`, checked BEFORE appending
///    (AUTH-2.43), so at most `MAX_RECORD_BYTES` bytes are ever copied.
///
/// Termination rides on AUTH-1.22's wire-codec premise (every value ≥ 1
/// byte, so the cap bounds the walk); a round admitting zero-byte values
/// must add a second bound.
pub fn record_bytes(
    ctx: &impl Values,
    home: &Address,
    from: &[Span],
) -> Result<Vec<u8>, PayloadError> {
    let one = Nat::from(1u32);
    let mut out: Vec<u8> = Vec::new();
    for span in from {
        // 1 — validity (checked ONCE per span, ahead of the walk: AUTH-2.30).
        let Ok(start) = validate(span.start().clone()) else {
            return Err(PayloadError::ForeignContent);
        };
        // 2 — position-hood (AUTH-2.40): element level, field = subspace·ordinal.
        let is_position = start.level() == Level::Element
            && start.element_field().is_some_and(|field| field.len() == 2);
        if !is_position {
            return Err(PayloadError::ForeignContent);
        }
        // 3 — home anchoring (AUTH-2.44), before a byte of the span is read.
        let Some(span_doc) = document_of(&start) else {
            // Unreachable: an Element-level address has a document prefix;
            // kept total rather than panicking (AUTH-2.57).
            return Err(PayloadError::ForeignContent);
        };
        if span_doc != *home {
            return Err(PayloadError::ForeignContent);
        }
        // The reach walk (AUTH-2.42).
        let mut t = span.start().clone();
        while span.contains(&t) {
            // 4 — the value, as of the ctx's position (AUTH-2.38 item 4).
            let Some(value) = ctx.value_at(&t) else {
                return Err(PayloadError::MissingValue);
            };
            // 5 — the cap, BEFORE the value is appended (AUTH-2.43).
            if out.len() + value.len() > MAX_RECORD_BYTES {
                return Err(PayloadError::TooLarge);
            }
            out.extend_from_slice(value);
            t = shift(&t, &one);
        }
    }
    Ok(out)
}
