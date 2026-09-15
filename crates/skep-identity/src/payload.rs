//! Credential-record constants, payload types, and the pinned line grammar —
//! AUTH-1.18–1.28, AUTH-2.6–2.19.
//!
//! One doorkeeper: record BYTES in, typed records out. The grammar — headers,
//! tokenization, both kinds' line forms, the parse fault precedence — is a
//! PERMANENT protocol pin, an I2 frozen constant (AUTH-2.90). Both kinds
//! share one strictness, one fault precedence and one duplicate rule
//! (AUTH-2.14, AUTH-2.15, AUTH-2.19), so [`scan`] holds those obligations
//! once and each kind's parser holds only its own line grammar. The bytes
//! themselves arrive from `crate::read`.
//!
//! [`scan`]: scan

use core::fmt;
use std::collections::BTreeSet;

use crate::key::{Fingerprint, PublicKey};

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
/// remaining variants that it could not be PARSED. The `usize` is a 1-based
/// line number, the header being line 1; `DuplicateKey` names the REPEATING
/// line (AUTH-2.15).
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
    /// Line 1 is not the kind's header, byte-exact (AUTH-2.7).
    BadHeader,
    /// The named line fails the kind's line grammar (AUTH-2.8–2.14).
    BadLine(usize),
    /// Zero key/fingerprint lines after a clean scan (AUTH-2.16) — never
    /// `NothingChanged`.
    Empty,
    /// The named line repeats an earlier line's fingerprint, compared as
    /// PARSED bytes (AUTH-2.15) — for the ENROLLMENT kind the parsed KEY,
    /// whose fingerprint is a function of it. WITHIN one line the kind's own
    /// line grammar decides FIRST, on both kinds: a line that repeats an
    /// earlier key AND fails its grammar (an enrollment's empty label
    /// remainder, a retirement's `<64 hex> note`) answers [`BadLine`], never
    /// this.
    ///
    /// [`BadLine`]: PayloadError::BadLine
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

/// AUTH-2.19 — the scan BOTH kinds share, in ONE implementation: UTF-8
/// first, else `NotUtf8` (item 1); line 1 the header, literally, byte-exact,
/// else `BadHeader` (AUTH-2.7, item 2 — a leading blank line, a trailing
/// space, a CRLF header each fail here); then lines 2..n IN ORDER (item 3),
/// the FIRST failing line the verdict; and `Empty` only after a clean scan
/// (AUTH-2.16, item 4).
///
/// Lines split on `\n` ONLY, nothing trimmed — `\r` is an ordinary payload
/// byte (AUTH-2.6). A zero-length line is ignored (AUTH-2.6, AUTH-2.7); a
/// `sig` line is skipped whatever follows, on both kinds (AUTH-2.13,
/// AUTH-2.14, permanent per AUTH-2.94).
///
/// AUTH-2.15 is the scan's too, since both kinds share it: a line whose
/// `compared_by` value an earlier ACCEPTED line already carried is
/// `DuplicateKey(n)`, naming the repeating line. The test runs only on a line
/// `parse_line` has accepted, so within a line the kind's grammar decides
/// first by construction. It is one ordered-set insert per line rather than a
/// search of the lines before it, so no record's length makes the scan
/// quadratic — the parsers are `pub`, and a caller's bytes need not have
/// passed the READ's cap.
///
/// `parse_line` carries the KIND'S OWN line grammar and nothing else: it
/// receives the 1-based line number (the header is line 1, AUTH-1.27) and
/// the line.
fn scan<T, K: Ord>(
    bytes: &[u8],
    header: &str,
    compared_by: impl Fn(&T) -> K,
    mut parse_line: impl FnMut(usize, &str) -> Result<T, PayloadError>,
) -> Result<Vec<T>, PayloadError> {
    let text = core::str::from_utf8(bytes).map_err(|_| PayloadError::NotUtf8)?;
    let mut lines = text.split('\n');
    if lines.next() != Some(header) {
        return Err(PayloadError::BadHeader);
    }
    let mut out: Vec<T> = Vec::new();
    let mut seen: BTreeSet<K> = BTreeSet::new();
    for (idx, line) in lines.enumerate() {
        let n = idx + 2; // 1-based, the header line 1 (AUTH-1.27)
        if line.is_empty() {
            continue;
        }
        if split_token(line).0 == "sig" {
            continue;
        }
        let item = parse_line(n, line)?;
        if !seen.insert(compared_by(&item)) {
            return Err(PayloadError::DuplicateKey(n));
        }
        out.push(item);
    }
    if out.is_empty() {
        return Err(PayloadError::Empty);
    }
    Ok(out)
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

/// AUTH-2.18 — parse an enrollment record: line 1 `skep-enroll v1`, each
/// further line `[anchor ]ed25519 <64 hex>[ <label>]` (AUTH-2.12). Strict —
/// any unparseable line makes the whole record inert; the scan and the fault
/// precedence are the ones BOTH kinds share (AUTH-2.19): UTF-8, header, then
/// lines 2..n in order with the first failing line the verdict, and `Empty`
/// only after a clean scan. Hex tokens are case-insensitive (AUTH-2.17);
/// keyword tokens match as bytes, lowercase (AUTH-2.9). Within a line the
/// grammar decides before the AUTH-2.15 duplicate test
/// ([`PayloadError::DuplicateKey`]).
///
/// POSTCONDITION — on `Ok`, the vector is NON-EMPTY (AUTH-2.16 answers
/// `Empty` otherwise), in the record's LINE ORDER (which is the order
/// `Effect::Genesis`/`Enroll` carry to `apply`), and no two entries carry
/// the same key (AUTH-2.15 answers `DuplicateKey(n)` otherwise) — the
/// promise that fixes a fingerprint's anchor flag within one record (I9,
/// AUTH-2.104).
///
/// The record cap is the READ's, never this grammar's (AUTH-2.43): bytes over
/// [`MAX_RECORD_BYTES`] parse here as any other bytes do — no length makes
/// the parse quadratic — and the fold refuses such a record before its bytes
/// reach a parser. An `Ok` over bytes that did not come from
/// `crate::record_bytes` says the record PARSES, never that it reads.
pub fn parse_enroll(bytes: &[u8]) -> Result<Vec<Enrollment>, PayloadError> {
    // AUTH-2.15 compares the PARSED key: hex case is no distinction, and
    // neither is the line's flag or label.
    scan(bytes, ENROLL_HEADER, |e: &Enrollment| e.key, |n, line| {
        // AUTH-2.12 — dispatch on the FIRST token: anchor · alg · else (the
        // scan has taken the `sig` lines already).
        let (first, rest) = split_token(line);
        let (anchor, alg, after_alg) = if first == "anchor" {
            // AUTH-2.11 — the anchor flag is the LEADING token; the line
            // then continues with the alg token.
            let Some(after_anchor) = rest else {
                return Err(PayloadError::BadLine(n)); // `anchor` alone
            };
            let (alg, after_alg) = split_token(after_anchor);
            (true, alg, after_alg)
        } else {
            (false, first, rest)
        };
        let Some(after_alg) = after_alg else {
            return Err(PayloadError::BadLine(n)); // alg token with no hex
        };
        let (hex, after_hex) = split_token(after_alg);
        // AUTH-2.9/AUTH-2.12 — the alg token is admitted by `PublicKey::parse`
        // alone, which is where `ALGS` decides admission (AUTH-1.6): the token
        // matches as BYTES, lowercase, so an alg the build does not carry,
        // `anchor anchor …` and `anchor sig …` all arrive here and all answer
        // BadLine. This grammar asks whether the pair is admitted and never
        // why — the parse's three refusals are one line fault.
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
            Some(label) => Some(label.to_owned()),
        };
        // The parsed label is in the AUTH-1.24 domain by construction
        // (non-empty checked above; no '\n' — lines were split on it).
        Enrollment::new(key, anchor, label).map_err(|_| PayloadError::BadLine(n))
    })
}

/// AUTH-2.18 — parse a retirement record: line 1 `skep-retire v1`, each
/// further line `<64 hex fingerprint>` AND NOTHING ELSE — any remainder
/// after the fingerprint token is `BadLine` (AUTH-2.14). The scan and the
/// fault precedence are the ones BOTH kinds share — the same ones the
/// enrollment kind reads under (AUTH-2.19). Within a line the grammar decides
/// before the AUTH-2.15 duplicate test ([`PayloadError::DuplicateKey`]).
///
/// POSTCONDITION — on `Ok`, the vector is NON-EMPTY (AUTH-2.16 answers
/// `Empty` otherwise), in the record's LINE ORDER, and DUPLICATE-FREE
/// (AUTH-2.15 answers `DuplicateKey(n)` otherwise). The distinctness is a
/// promise the retirement arm's proof rests on, not an implementation
/// detail: that arm reads `|removed| == |enrolled|` as set equality
/// (AUTH-2.74), and a record listing one fingerprint twice beside the rest
/// of the set would pass that test, empty the set, and void I3 (AUTH-2.97)
/// and AUTH-1.36.
///
/// The record cap is the READ's, never this grammar's — as on
/// [`parse_enroll`].
pub fn parse_retire(bytes: &[u8]) -> Result<Vec<Fingerprint>, PayloadError> {
    // AUTH-2.15 compares the PARSED fingerprint (hex case is no distinction),
    // so `removed` never names one twice.
    scan(bytes, RETIRE_HEADER, |fp: &Fingerprint| *fp, |n, line| {
        // AUTH-2.14 — no label, no trailing separator: ANY remainder after
        // the fingerprint token (`<64 hex> ` and `<64 hex> note` alike) is
        // BadLine.
        let (hex, rest) = split_token(line);
        if rest.is_some() {
            return Err(PayloadError::BadLine(n));
        }
        Fingerprint::parse_hex(hex).ok_or(PayloadError::BadLine(n))
    })
}

/// AUTH-2.18 — encode an enrollment record; emits lowercase hex (AUTH-2.17)
/// and the label verbatim.
///
/// Answers TEXT, which a record is: a depositor places it in a text-valued
/// insert as it stands. The parsers take bytes because the READ hands them
/// bytes that need not be text (`NotUtf8`); nothing an encoder emits is ever
/// one of those.
///
/// PRECONDITION — `enrollments` is NON-EMPTY and no two entries carry the
/// same key: [`parse_enroll`]'s POSTCONDITION read from the other side, since
/// a header-only record is `Empty` (AUTH-2.16) and a repeated key is
/// `DuplicateKey(n)` (AUTH-2.15). Outside that domain this function still
/// answers a record — it emits what it is given and re-checks nothing — but
/// NO parser admits it, so a depositor who writes it spends a permanent
/// record on one the fold can never honor.
///
/// POSTCONDITION — within it, `parse_enroll(encode_enroll(x).as_bytes())` is
/// `Ok(x)` over the whole [`Enrollment`] domain per entry: every anchor flag
/// and every AUTH-1.24 label, trailing 0x20 included (I1, AUTH-2.89). The
/// encoded LENGTH is a third obligation owned elsewhere — a record over
/// [`MAX_RECORD_BYTES`] round-trips here and is refused at the READ
/// (AUTH-2.43).
pub fn encode_enroll(enrollments: &[Enrollment]) -> String {
    let mut out = String::new();
    out.push_str(ENROLL_HEADER);
    out.push('\n');
    for enrollment in enrollments {
        if enrollment.anchor {
            out.push_str("anchor "); // the LEADING token (AUTH-2.11)
        }
        out.push_str(enrollment.key.alg());
        out.push(' ');
        out.push_str(&enrollment.key.to_hex());
        if let Some(label) = enrollment.label() {
            out.push(' ');
            out.push_str(label);
        }
        out.push('\n');
    }
    out
}

/// AUTH-2.18 — encode a retirement record, as TEXT like [`encode_enroll`];
/// lowercase hex (AUTH-2.17).
///
/// PRECONDITION — `fps` is NON-EMPTY and DUPLICATE-FREE, [`parse_retire`]'s
/// POSTCONDITION read from the other side (`Empty`, AUTH-2.16;
/// `DuplicateKey(n)`, AUTH-2.15); outside that domain the text is a record no
/// parser admits, and nothing here re-checks it.
///
/// POSTCONDITION — within it, `parse_retire(encode_retire(x).as_bytes())` is
/// `Ok(x)` (I1, AUTH-2.89), under the same [`MAX_RECORD_BYTES`] obligation as
/// [`encode_enroll`].
pub fn encode_retire(fps: &[Fingerprint]) -> String {
    let mut out = String::new();
    out.push_str(RETIRE_HEADER);
    out.push('\n');
    for fp in fps {
        out.push_str(&fp.to_hex());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::cmp::Ordering;

    use super::{scan, PayloadError};

    /// A line's duplicate-test key that counts every comparison made of it.
    struct Counted<'a> {
        value: u32,
        comparisons: &'a Cell<u64>,
    }

    impl Ord for Counted<'_> {
        fn cmp(&self, other: &Self) -> Ordering {
            self.comparisons.set(self.comparisons.get() + 1);
            self.value.cmp(&other.value)
        }
    }

    impl PartialOrd for Counted<'_> {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl PartialEq for Counted<'_> {
        fn eq(&self, other: &Self) -> bool {
            self.value == other.value
        }
    }

    impl Eq for Counted<'_> {}

    /// AUTH-2.15's test costs `scan` a logarithmic number of comparisons per
    /// line, never a search of the lines before it — what keeps a `pub`
    /// parser handed an uncapped record from going quadratic in its line
    /// count. Over 4096 distinct lines a search makes n(n−1)/2 ≈ 8·10⁶
    /// comparisons and an ordered-set insert at most one node's keys per tree
    /// level, well under the 128 per line allowed here; the floor of one per
    /// line after the first proves the counter is live.
    #[test]
    fn the_duplicate_rule_makes_logarithmic_comparisons_per_line() {
        const LINES: u64 = 4096;
        let comparisons = Cell::new(0);
        let record = core::iter::once("h".to_owned())
            .chain((0..LINES).map(|i| i.to_string()))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = scan(
            record.as_bytes(),
            "h",
            |value: &u32| Counted { value: *value, comparisons: &comparisons },
            |n, line| line.parse::<u32>().map_err(|_| PayloadError::BadLine(n)),
        );
        assert_eq!(parsed.map(|items| items.len() as u64), Ok(LINES));
        let made = comparisons.get();
        assert!(made >= LINES - 1, "{made} comparisons: the counter is not live");
        assert!(
            made <= LINES * 128,
            "{made} comparisons over {LINES} lines: the duplicate test searches"
        );
    }
}
