//! Credential-record constants, payload types, and the JSON record schemas —
//! AUTH-1.18–1.28, AUTH-2.128–2.130, AUTH-2.15–2.19.
//!
//! One doorkeeper: record BYTES in, typed records out. The two schemas
//! (AUTH-2.128 enrollment, AUTH-2.129 retirement) and the CANONICAL ENCODING
//! (AUTH-2.130) are PERMANENT protocol pins, I2 frozen constants (AUTH-2.90).
//! Per AUTH-2.1 the crate uses `serde_json` to answer ONE question — is this
//! byte string a JSON value, and which — parsing to a GENERIC
//! [`serde_json::Value`], with every schema, profile and domain check written
//! IN THIS CRATE, in the spec's own order: no `serde` derive, no
//! `deny_unknown_fields`, no verdict delegated to the dependency. The bytes
//! themselves arrive from `crate::read`.
//!
//! The two kinds share one record envelope and one fault precedence
//! (AUTH-2.19), so [`scan`] holds those once and a kind's [`Schema`] carries
//! only the five rows that kind decides for itself.

use core::fmt;
use core::fmt::Write as _;
use std::collections::BTreeSet;

use serde_json::Value;

use crate::key::{Fingerprint, PublicKey};

/// AUTH-1.18 — the enrollment record's `type` member value (AUTH-2.128).
pub const ENROLL_TYPE: &str = "skep-enroll";

/// AUTH-1.18 — the retirement record's `type` member value (AUTH-2.129).
pub const RETIRE_TYPE: &str = "skep-retire";

/// AUTH-1.18 — the record cap. Bounds ONE record — the concatenated bytes of
/// the link's own FROM spans, never the home document (AUTH-1.19) — counted
/// in BYTES, never positions (AUTH-1.20). A PERMANENT pin: there is no fold
/// version and the constant MUST NOT change (AUTH-1.21, I2 AUTH-2.90), and it
/// STANDS at 64 KiB over the narrower JSON record domain (AUTH-2.130's cost
/// note). It bounds the fold's per-record work only under the wire-codec
/// premise that every value carries ≥ 1 byte (AUTH-1.22).
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// One enrollment key entry's parse (AUTH-1.23, AUTH-2.128): the key, the
/// anchor flag, and the informational label. `anchor` is the ANCHOR flag — the
/// REQUIRED BOOLEAN member `anchor` of the enrollment schema's key entry
/// (AUTH-1.26, AUTH-2.128); a fingerprint's flag is fixed for the
/// fingerprint's lifetime by the record that first enrolls it (I9,
/// AUTH-2.104).
#[derive(Debug, Clone, PartialEq, Eq)]
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
            Some(label) if label.contains('\n') => return Err(LabelError::Newline),
            Some(label) if label.is_empty() => None,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelError {
    /// The label contains `\n` — outside the AUTH-1.24 domain.
    Newline,
}

impl fmt::Display for LabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelError::Newline => f.write_str("label contains a newline"),
        }
    }
}

impl std::error::Error for LabelError {}

/// AUTH-1.27 — a payload fault. `TooLarge`, `ForeignContent` and
/// `MissingValue` report that a record's payload could not be READ; the
/// remaining variants that it could not be PARSED. The `usize` is a 1-BASED
/// INDEX INTO THE KIND'S ENTRY ARRAY — `keys` on an enrollment, `fingerprints`
/// on a retirement — and `DuplicateKey` names the REPEATING ENTRY (AUTH-2.15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadError {
    /// The concatenated FROM-span bytes exceed [`MAX_RECORD_BYTES`]
    /// (AUTH-2.43).
    TooLarge,
    /// The span's START failed one of the three per-span checks that run
    /// before a byte of it is read (AUTH-2.38 items 1–3): it does not
    /// VALIDATE to an address; or it validates to a T4-valid NON-position —
    /// an element field that is not exactly subspace·ordinal (AUTH-2.40);
    /// or its `document_of` is not the link's home (HOME ANCHORING,
    /// AUTH-2.44). The position test constrains the field's SHAPE ONLY,
    /// never WHICH subspace it names (AUTH-2.41): a start in the home's
    /// LINK subspace IS a position, and walks to [`MissingValue`] — never
    /// here.
    ///
    /// [`MissingValue`]: PayloadError::MissingValue
    ForeignContent,
    /// A FROM span names a position the home had not minted as of the
    /// deposit's commit (AUTH-2.38 item 4, AUTH-2.45).
    MissingValue,
    /// The payload does not decode as UTF-8 (AUTH-2.19 item 1).
    NotUtf8,
    /// The payload is not the kind's CANONICAL SCHEMA ENCODING (AUTH-2.128,
    /// AUTH-2.129 under AUTH-2.130's admission sentence): not JSON at all, a
    /// wrong or missing `type`, a missing/extra member, a wrong JSON type, an
    /// unadmitted alg, a wrong hex length, a label outside AUTH-1.24, or ANY
    /// non-canonical encoding — member order, insignificant whitespace,
    /// escape choices, uppercase hex, a duplicate member, a trailing byte, a
    /// BOM — none of which survives the byte-identity compare against a
    /// minimal re-encoding (AUTH-2.130, AUTH-2.19 item 2, I2 AUTH-2.90).
    BadRecord,
    /// Zero key/fingerprint entries after a clean scan (AUTH-2.16) — never
    /// `NothingChanged`; evaluated ONLY after the canonical schema check
    /// (AUTH-2.19 item 4).
    Empty,
    /// The named ENTRY repeats an earlier entry's fingerprint, compared as
    /// PARSED bytes (AUTH-2.15) — for the ENROLLMENT kind the parsed KEY,
    /// whose fingerprint is a function of it. The `usize` is the 1-based index
    /// of the REPEATING entry in the kind's array (AUTH-1.27). The canonical
    /// schema check decides FIRST (AUTH-2.19 item 2 before item 3), so a body
    /// that is both non-canonical and duplicate-bearing answers
    /// [`BadRecord`], never this.
    ///
    /// [`BadRecord`]: PayloadError::BadRecord
    DuplicateKey(usize),
}

impl PayloadError {
    /// AUTH-1.28 — THE ONE authority for the payload fault tokens. `<n>` is
    /// the 1-based ENTRY index, which is why the return type is `String`. On
    /// the wire this token is a fold refusal's payload sub-token, in the join
    /// [`Inert::token`](crate::Inert::token) states (AUTH-2.55).
    pub fn token(&self) -> String {
        match self {
            PayloadError::TooLarge => "too_large".to_owned(),
            PayloadError::ForeignContent => "foreign_content".to_owned(),
            PayloadError::MissingValue => "missing_value".to_owned(),
            PayloadError::NotUtf8 => "not_utf8".to_owned(),
            PayloadError::BadRecord => "bad_record".to_owned(),
            PayloadError::Empty => "empty".to_owned(),
            PayloadError::DuplicateKey(n) => format!("duplicate_key:{n}"),
        }
    }
}

/// AUTH-1.28's token, and only it: `Display` is a second ENTRY to [`token`]'s
/// one authority, never a second vocabulary — `format!("{e}")` and
/// `e.token()` answer the same string, so a consumer that formats is citing
/// rather than transcribing.
///
/// [`token`]: PayloadError::token
impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.token())
    }
}

impl std::error::Error for PayloadError {}

/// AUTH-2.130 clause 3 — canonical JSON string escaping: escape EXACTLY `"`,
/// `\` and U+0000–U+001F — the two-character forms where JSON defines one
/// (`\b \f \n \r \t`), `\u00xx` with LOWERCASE hex otherwise — and escape
/// NOTHING else (never `/`, never a non-ASCII character, never a `\uXXXX` for
/// any character above U+001F).
fn escape_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                // The remaining C0 controls: `\u00xx`, lowercase hex.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// AUTH-2.130 — the canonical encoding of an enrollment record VALUE: members
/// in schema order (`type` first, `keys`, `sig` last when present), each key
/// entry `{alg, key, anchor, label?}` in that order, no whitespace outside
/// strings, hex lowercase, the exact escape set, no byte after the brace. The
/// admission sentence ranges over this whole value, `sig` INCLUDED (RES-105);
/// [`encode_enroll`] is this function with `sig = None` (AUTH-2.18).
fn canonical_enroll(entries: &[Enrollment], sig: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str(r#"{"type":""#);
    out.push_str(ENROLL_TYPE);
    out.push_str(r#"","keys":["#);
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(r#"{"alg":""#);
        out.push_str(e.key.alg());
        out.push_str(r#"","key":""#);
        out.push_str(&e.key.to_hex()); // AUTH-2.17 — hex lowercase
        out.push_str(r#"","anchor":"#);
        out.push_str(if e.anchor { "true" } else { "false" });
        if let Some(label) = e.label() {
            out.push_str(r#","label":"#);
            escape_json_string(label, &mut out);
        }
        out.push('}');
    }
    out.push(']');
    if let Some(sig) = sig {
        out.push_str(r#","sig":"#);
        escape_json_string(sig, &mut out);
    }
    out.push('}');
    out
}

/// AUTH-2.130 — the canonical encoding of a retirement record VALUE:
/// `{type, fingerprints, sig?}`, each fingerprint a 64-hex lowercase string in
/// the record's own order. [`encode_retire`] is this with `sig = None`.
fn canonical_retire(fps: &[Fingerprint], sig: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str(r#"{"type":""#);
    out.push_str(RETIRE_TYPE);
    out.push_str(r#"","fingerprints":["#);
    for (i, fp) in fps.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&fp.to_hex()); // AUTH-2.17 — hex lowercase
        out.push('"');
    }
    out.push(']');
    if let Some(sig) = sig {
        out.push_str(r#","sig":"#);
        escape_json_string(sig, &mut out);
    }
    out.push('}');
    out
}

/// AUTH-2.128 — validate ONE `keys` entry against the enrollment schema, one
/// branch per member the schema names. An OBJECT of exactly `{alg, key,
/// anchor}` or `{alg, key, anchor, label}`, in any order (member ORDER is the
/// canonical encoding's, judged by AUTH-2.130's byte-identity compare, not
/// here). Any other shape is [`PayloadError::BadRecord`] (AUTH-1.28).
fn parse_key_entry(v: &Value) -> Result<Enrollment, PayloadError> {
    let obj = v.as_object().ok_or(PayloadError::BadRecord)?;
    // `alg` — STRING, an ALGS token (AUTH-2.128; admission is PublicKey::parse's,
    // AUTH-1.6, AUTH-2.9's surviving half).
    let alg = obj.get("alg").and_then(Value::as_str).ok_or(PayloadError::BadRecord)?;
    // `key` — STRING, that row's hex length, parsed case-insensitively
    // (AUTH-2.17); the case a body carries is judged by the byte-identity
    // compare, so the PARSE admits uppercase and the canonical form is lower.
    let key_hex = obj.get("key").and_then(Value::as_str).ok_or(PayloadError::BadRecord)?;
    // `anchor` — BOOLEAN, REQUIRED, never omitted (AUTH-2.128).
    let anchor = obj.get("anchor").and_then(Value::as_bool).ok_or(PayloadError::BadRecord)?;
    // `label` — STRING, OPTIONAL: present only where a label exists, never
    // `""`, never `null`, never containing `\n` (AUTH-1.24, AUTH-1.25).
    let label = match obj.get("label") {
        None => None,
        Some(Value::String(s)) if !s.is_empty() && !s.contains('\n') => Some(s.clone()),
        Some(_) => return Err(PayloadError::BadRecord),
    };
    // No other member (AUTH-2.128 "No other member"): exactly the three
    // required, plus `label` iff it is present.
    let expected = 3 + usize::from(obj.contains_key("label"));
    if obj.len() != expected {
        return Err(PayloadError::BadRecord);
    }
    let key = PublicKey::parse(alg, key_hex).map_err(|_| PayloadError::BadRecord)?;
    // The label is in the AUTH-1.24 domain (non-empty, no `\n`, checked above),
    // so `new` keeps it verbatim (AUTH-1.25); it never returns `Err` here.
    Enrollment::new(key, anchor, label).map_err(|_| PayloadError::BadRecord)
}

/// AUTH-2.129 — validate ONE `fingerprints` entry against the retirement
/// schema: a STRING of exactly 64 hex characters, parsed case-insensitively
/// (AUTH-2.17); the case a body carries is judged by AUTH-2.130's
/// byte-identity compare, not here. Any other shape is
/// [`PayloadError::BadRecord`] (AUTH-1.28).
fn parse_fingerprint_entry(v: &Value) -> Result<Fingerprint, PayloadError> {
    let hex = v.as_str().ok_or(PayloadError::BadRecord)?;
    Fingerprint::parse_hex(hex).ok_or(PayloadError::BadRecord)
}

/// AUTH-2.15 for the ENROLLMENT kind — two entries are the same entry when
/// their PARSED KEYS have one fingerprint, which is a function of the key:
/// never the entry's flag, its label, or the hex case its body spelled.
fn enrollment_key_fingerprint(e: &Enrollment) -> Fingerprint {
    Fingerprint::of(&e.key)
}

/// AUTH-2.15 for the RETIREMENT kind — two entries are the same entry when
/// they are one fingerprint.
fn retirement_fingerprint(fp: &Fingerprint) -> Fingerprint {
    *fp
}

/// One record kind's SCHEMA — everything AUTH-2.128 and AUTH-2.129 say
/// DIFFERENTLY, and nothing they say alike. Five rows; the envelope both
/// schemas state in identical words, and AUTH-2.19's fault precedence both
/// kinds keep, are [`scan`]'s and written once.
///
/// PRECONDITION — two rows must AGREE, and [`scan`] checks neither. For every
/// entry `parse_entry` admits from a canonical body, `canonical` must re-emit
/// the bytes that entry spelled: AUTH-2.130's admission sentence is spelled
/// `canonical(parsed) == text`, so a `canonical` that is not `parse_entry`'s
/// inverse refuses EVERY record of the kind — silently, permanently, and with
/// no fault to tell it from a malformed body. And `compared_by` must be the
/// kind's AUTH-2.15 sameness rule, because it is the ONLY thing standing
/// behind each parser's DUPLICATE-FREE POSTCONDITION: a `compared_by` that
/// separated two entries the kind calls one would admit a record the
/// retirement arm reads as a proper subset (AUTH-2.74), emptying a key set and
/// voiding I3 (AUTH-2.97) and AUTH-1.36. A kind is added by filling this
/// table; these are what filling it owes.
struct Schema<T> {
    /// The `type` member's ONE admitted value ([`ENROLL_TYPE`],
    /// [`RETIRE_TYPE`]).
    type_value: &'static str,
    /// The entry array's member name (`keys`, `fingerprints`).
    entries_member: &'static str,
    /// AUTH-2.128/AUTH-2.129 — ONE entry against the kind's entry schema.
    parse_entry: fn(&Value) -> Result<T, PayloadError>,
    /// AUTH-2.130 — the record VALUE's canonical encoding, `sig` included.
    canonical: fn(&[T], Option<&str>) -> String,
    /// AUTH-2.15 — the FINGERPRINT two entries are compared by:
    /// `enrollment_key_fingerprint` takes the parsed key's,
    /// `retirement_fingerprint` the entry itself. BOTH kinds compare
    /// fingerprints, so that is the type here and not a parameter.
    compared_by: fn(&T) -> Fingerprint,
}

/// AUTH-2.19 — the fault precedence BOTH kinds keep, and the record envelope
/// both schemas state alike, in ONE place: the bytes decode as UTF-8 (else
/// `NotUtf8`, item 1); the body is a JSON object of exactly `type`, the kind's
/// entry array, and an OPTIONAL `sig` — a STRING the fold IGNORES whatever it
/// holds (AUTH-2.13, AUTH-2.94), and no other member (AUTH-2.128, AUTH-2.129)
/// — whose entries each parse and whose bytes ARE the canonical re-encoding of
/// the value they spell (else `BadRecord`, AUTH-2.130 and item 2); then the
/// entries are scanned in order for a duplicate (`DuplicateKey(n)` naming the
/// 1-based REPEATING entry, item 3); and `Empty` is answered ONLY after a
/// clean scan (item 4).
///
/// Item 2 precedes item 3 BY CONSTRUCTION: the duplicate test runs only on
/// entries the canonical compare has already admitted. It is one ordered-set
/// insert per entry, never a search of the entries before it, so no record
/// length makes the scan quadratic.
///
/// No verdict is delegated to `serde_json`: it answers only "is this a JSON
/// value, and which" (AUTH-2.1). Everything a kind decides for itself is its
/// [`Schema`]'s five rows.
fn scan<T>(bytes: &[u8], schema: Schema<T>) -> Result<Vec<T>, PayloadError> {
    // AUTH-2.19 item 1 — UTF-8 before everything.
    let text = core::str::from_utf8(bytes).map_err(|_| PayloadError::NotUtf8)?;
    // AUTH-2.1/AUTH-2.19 item 2 — parse to a GENERIC value; a non-JSON body,
    // a leading BOM, a lone surrogate, a trailing non-whitespace byte each
    // fail here as `bad_record`.
    let value: Value = serde_json::from_str(text).map_err(|_| PayloadError::BadRecord)?;
    let obj = value.as_object().ok_or(PayloadError::BadRecord)?;
    // `type` — STRING, exactly the kind's admitted value (the parse is keyed
    // to the kind, so a disagreeing or foreign `type` is `bad_record` and
    // costs no daemon read).
    match obj.get("type").and_then(Value::as_str) {
        Some(t) if t == schema.type_value => {}
        _ => return Err(PayloadError::BadRecord),
    }
    // The entry array — ARRAY (AUTH-2.128 `keys`, AUTH-2.129 `fingerprints`).
    let entries_val = obj
        .get(schema.entries_member)
        .and_then(Value::as_array)
        .ok_or(PayloadError::BadRecord)?;
    // `sig` — STRING, OPTIONAL, canonically LAST, IGNORED by the fold whatever
    // it holds (AUTH-2.13, AUTH-2.94); admitted with the body and absent from
    // the answer (AUTH-2.18).
    let sig = match obj.get("sig") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(PayloadError::BadRecord),
    };
    // No other member: exactly `type`, the entry array, plus `sig` iff present.
    if obj.len() != 2 + usize::from(obj.contains_key("sig")) {
        return Err(PayloadError::BadRecord);
    }
    // Each entry against the kind's schema, IN ORDER — the first failing entry
    // is the verdict (an unadmitted alg at entry 1 precedes a duplicate at
    // entry 3, AUTH-2.19 item 2 before item 3).
    //
    // The vector is sized by what the entries PARSE to, never by what the
    // array CLAIMS: `entries_val.len()` is the depositor's count, and a body
    // whose every element is `1` refuses at entry 1 — a capacity taken from
    // that count is reserved for entries never pushed. Under the READ's cap
    // (AUTH-2.43) that costs at most a doubling of what `serde_json` already
    // holds; but the cap is the read's and not this parser's, so a caller
    // reaching here without `record_bytes` (AUTH-2.37's non-folding reader)
    // sizes the allocation from the body alone, where a large enough count
    // ABORTS rather than answering `BadRecord`. The growth given up is ten
    // reallocations under 64 KiB: no record this parser admits carries more
    // than ~975 entries, the canonical spelling's smallest entry being the
    // retirement's 67 bytes.
    let mut entries: Vec<T> = Vec::new();
    for entry in entries_val {
        entries.push((schema.parse_entry)(entry)?);
    }
    // AUTH-2.130's ADMISSION SENTENCE — the byte-identity compare over the
    // RECORD VALUE, `sig` INCLUDED (RES-105, I2 AUTH-2.90): admit only where
    // the input is the canonical re-encoding of every member it carries.
    if (schema.canonical)(&entries, sig.as_deref()) != text {
        return Err(PayloadError::BadRecord);
    }
    // AUTH-2.15/AUTH-2.19 item 3 — duplicate ENTRY, naming the 1-based
    // repeating entry index; one ordered-set insert per entry, never a search.
    let mut seen: BTreeSet<Fingerprint> = BTreeSet::new();
    for (i, entry) in entries.iter().enumerate() {
        if !seen.insert((schema.compared_by)(entry)) {
            return Err(PayloadError::DuplicateKey(i + 1));
        }
    }
    // AUTH-2.16/AUTH-2.19 item 4 — `Empty` only after a clean scan.
    if entries.is_empty() {
        return Err(PayloadError::Empty);
    }
    Ok(entries)
}

/// AUTH-2.128, AUTH-2.130 — parse an enrollment record. The bytes decode as
/// UTF-8 (else `NotUtf8`, AUTH-2.19 item 1), parse to a GENERIC
/// [`serde_json::Value`] and validate the enrollment schema and its canonical
/// encoding (else `BadRecord`, item 2), then the entries are scanned in order
/// for a duplicate (`DuplicateKey(n)`, item 3), and `Empty` is answered only
/// after a clean scan (item 4). No verdict is delegated to `serde_json`: it
/// answers only "is this a JSON value, and which" (AUTH-2.1).
///
/// POSTCONDITION — on `Ok`, the vector is NON-EMPTY (AUTH-2.16), in the
/// record's own ENTRY ORDER (which is the order `Effect::Genesis`/`Enroll`
/// carry to `apply`), and no two entries carry the same key (AUTH-2.15) — the
/// promise that fixes a fingerprint's anchor flag within one record (I9,
/// AUTH-2.104).
///
/// The record cap is the READ's, never this parser's (AUTH-2.43).
pub fn parse_enroll(bytes: &[u8]) -> Result<Vec<Enrollment>, PayloadError> {
    scan(
        bytes,
        Schema {
            type_value: ENROLL_TYPE,
            entries_member: "keys",
            parse_entry: parse_key_entry,
            canonical: canonical_enroll,
            compared_by: enrollment_key_fingerprint,
        },
    )
}

/// AUTH-2.129, AUTH-2.130 — parse a retirement record: the mirror of
/// [`parse_enroll`] over the `fingerprints` array of 64-hex strings. The scan
/// and the fault precedence are the ones BOTH kinds share (AUTH-2.19).
///
/// POSTCONDITION — on `Ok`, the vector is NON-EMPTY (AUTH-2.16), in the
/// record's ENTRY ORDER, and DUPLICATE-FREE (AUTH-2.15). The distinctness is a
/// promise the retirement arm's proof rests on: that arm reads
/// `|removed| == |enrolled|` as set equality (AUTH-2.74), and a record listing
/// one fingerprint twice beside the rest of the set would pass that test,
/// empty the set, and void I3 (AUTH-2.97) and AUTH-1.36.
pub fn parse_retire(bytes: &[u8]) -> Result<Vec<Fingerprint>, PayloadError> {
    scan(
        bytes,
        Schema {
            type_value: RETIRE_TYPE,
            entries_member: "fingerprints",
            parse_entry: parse_fingerprint_entry,
            canonical: canonical_retire,
            compared_by: retirement_fingerprint,
        },
    )
}

/// AUTH-2.18/AUTH-2.130 — encode an enrollment record in the canonical spelling,
/// emitting the record value's ENTRIES and NO `sig` member (AUTH-2.130). Hex
/// is lowercase (AUTH-2.17) and the label is escaped by the canonical rule
/// (AUTH-2.130 clause 3).
///
/// Answers TEXT, which a record is: a depositor places it in a text-valued
/// insert as it stands. The parsers take bytes because the READ hands them
/// bytes that need not be text (`NotUtf8`); nothing an encoder emits is ever
/// one of those.
///
/// PRECONDITION — `enrollments` is NON-EMPTY and no two entries carry the same
/// key: [`parse_enroll`]'s POSTCONDITION read from the other side. Outside that
/// domain this function still answers a record — it emits what it is given and
/// re-checks nothing — but NO parser admits it.
///
/// POSTCONDITION — within it, `parse_enroll(encode_enroll(x).as_bytes())` is
/// `Ok(x)` over the whole [`Enrollment`] domain per entry, and
/// `encode_enroll(parse_enroll(y)…)` reproduces the entries of any body the
/// fold admits: the round trip is a BIJECTION (I1, AUTH-2.89; AUTH-2.130).
pub fn encode_enroll(enrollments: &[Enrollment]) -> String {
    canonical_enroll(enrollments, None)
}

/// AUTH-2.18/AUTH-2.130 — encode a retirement record, as TEXT like
/// [`encode_enroll`]; lowercase hex (AUTH-2.17), no `sig` member.
///
/// PRECONDITION — `fps` is NON-EMPTY and DUPLICATE-FREE, [`parse_retire`]'s
/// POSTCONDITION read from the other side.
///
/// POSTCONDITION — within it, `parse_retire(encode_retire(x).as_bytes())` is
/// `Ok(x)` (I1, AUTH-2.89).
pub fn encode_retire(fps: &[Fingerprint]) -> String {
    canonical_retire(fps, None)
}
