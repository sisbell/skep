//! THE POST's TWO PERSON-MADE FIELDS, judged in process before any docker
//! run (the provisioning record §2.1; Q6 (a)), so a refused post leaves
//! nothing behind:
//!
//! * THE NAME — the board's one label under the suffix, `<name>.skep.host`:
//!   lowercased first (a DNS name is case-insensitive, as this crate knows
//!   DNS — UNVERIFIED HERE), then `[a-z0-9-]` alone, 1 to 63 bytes, no
//!   hyphen at either end (a hostname label's limits as the record §8 item 6
//!   knows them — UNVERIFIED HERE). The alphabet is the daemon's own origin
//!   grammar narrowed to one label: `SKEPD_ORIGIN=https://<name>.<suffix>`
//!   must parse at the daemon, whose host admits lowercase letters, digits,
//!   `.` and `-` (the client's `host_is_canonical` reproduces it). Anything
//!   else is D-4's second clause.
//! * THE RECORD — the canonical enrollment record `skep keygen` printed on
//!   the person's own device: the text trimmed exactly as the hosted walk
//!   trims it (`skep-client`'s `hosted.rs`, H2: `trim_end_matches(['\n',
//!   '\r'])`), so a textarea's trailing line break is no `bad_record`; then
//!   `skep_identity::parse_enroll` on its bytes, the one authority for every
//!   fault it can raise over a form's bytes — `too_large`, `not_utf8`,
//!   `bad_record`, `empty`, `duplicate_key:<n>`, each D-5, its token the one
//!   word the log carries (AUTH-2.130 admits the canonical encoding and
//!   nothing else); then the walk's H2 COPIED in its own spelling — an entry
//!   whose key is not the production kind (`e.key.alg() !=
//!   ALG_MLDSA65_ED25519`) is D-6, a PREVIEW key parsing cleanly and being
//!   refused by this test alone; and the anchorless fact — no entry
//!   anchor-flagged — kept for the reply's sentence (AUTH-5.62).
//!
//! THE RECORD HOLDS NO KEY THAT SIGNS: `parse_enroll` yields `PublicKey`s,
//! and no field type in `skep-identity` can carry a private key (I1,
//! AUTH-2.89). Its bytes are the person's identifier and are NEVER logged —
//! not here, and not through [`Record`]'s `Debug`, which shows the length
//! alone.

use std::fmt;

use skep_identity::{parse_enroll, PayloadError, ALG_MLDSA65_ED25519};

/// THE LABEL's BOUND: a name is at most 63 bytes, one DNS label's limit as
/// the provisioning record §8 item 6 knows hostnames (UNVERIFIED HERE).
pub const MAX_NAME_BYTES: usize = 63;

/// A board's name, in the grammar: lowercase, one label of `[a-z0-9-]`, 1
/// to [`MAX_NAME_BYTES`] bytes, no hyphen at either end. Every docker call,
/// the snippet and the origin are built from one — so no value a person
/// typed reaches an argv unless it is a label, and none begins with `-`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

/// Why a name field is no name — each D-4's second clause; the log names
/// the reason and never the field, which may hold anything a person typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRefused {
    /// The field is empty.
    Empty,
    /// The field is longer than [`MAX_NAME_BYTES`].
    TooLong,
    /// A byte outside `[a-z0-9-]` once lowercased — a dot, an underscore, a
    /// space, anything not ASCII, or bytes that are not text at all.
    NotALabel,
    /// A hyphen begins or ends it.
    Hyphen,
}

impl fmt::Display for NameRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameRefused::Empty => "the name is empty",
            NameRefused::TooLong => "the name is longer than one label's 63 bytes",
            NameRefused::NotALabel => "the name holds a character outside letters, digits and hyphens",
            NameRefused::Hyphen => "the name begins or ends with a hyphen",
        })
    }
}

impl Name {
    /// THE GRAMMAR over the name field's bytes: lowercased, then one label.
    pub fn parse(field: &[u8]) -> Result<Name, NameRefused> {
        let text = std::str::from_utf8(field).map_err(|_| NameRefused::NotALabel)?;
        let name = text.to_ascii_lowercase();
        if name.is_empty() {
            return Err(NameRefused::Empty);
        }
        if name.len() > MAX_NAME_BYTES {
            return Err(NameRefused::TooLong);
        }
        if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(NameRefused::NotALabel);
        }
        if name.starts_with('-') || name.ends_with('-') {
            return Err(NameRefused::Hyphen);
        }
        Ok(Name(name))
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The board's host under `suffix`: `<name>.<suffix>` — the label the
    /// serving run carries and the host the snippet routes.
    pub fn host(&self, suffix: &str) -> String {
        format!("{}.{suffix}", self.0)
    }

    /// THE PUBLIC ORIGIN, `https://<name>.<suffix>`: the origin both run
    /// lines set as `SKEPD_ORIGIN` and never a loopback one (AUTH-4.57 (b)),
    /// and the one the reply relays — never the sidecar's dialed origin.
    pub fn origin(&self, suffix: &str) -> String {
        format!("https://{}", self.host(suffix))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A record the post admitted: its bytes as the sidecar will read them on
/// its stdin — the field trimmed — and whether it carried no anchor-flagged
/// entry.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    bytes: Vec<u8>,
    anchorless: bool,
}

impl Record {
    /// The record's bytes, trimmed: what the sidecar's `--hosted -` reads.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// THE ANCHORLESS FACT (AUTH-5.16's second arm; AUTH-5.62): no entry
    /// of the record carries `anchor: true` — the form's own parse, never a
    /// DATA line of the sidecar's, whose reply carries no such sentence.
    pub fn anchorless(&self) -> bool {
        self.anchorless
    }
}

/// The length and the fact, never the bytes: a `{:?}` in a log line can
/// carry nothing of the person's record.
impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record").field("bytes", &self.bytes.len()).field("anchorless", &self.anchorless).finish()
    }
}

/// Why a record field is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordRefused {
    /// D-5: not a record `skep keygen` printed — `parse_enroll`'s fault.
    NotARecord(PayloadError),
    /// D-6: an entry names a key that is not the production kind; `alg` is
    /// the token it named.
    PreviewKey {
        /// The entry's alg token.
        alg: &'static str,
    },
}

impl RecordRefused {
    /// The one word the log carries: the payload fault's token
    /// (`PayloadError::token`, AUTH-1.28's one authority), or `preview_key`.
    pub fn token(&self) -> String {
        match self {
            RecordRefused::NotARecord(e) => e.token(),
            RecordRefused::PreviewKey { .. } => "preview_key".to_owned(),
        }
    }
}

/// THE RECORD's ADMISSION: the field trimmed as the hosted walk trims it,
/// `parse_enroll` on the bytes, then H2 — every entry the production kind —
/// and the anchorless fact.
pub fn admit(field: &[u8]) -> Result<Record, RecordRefused> {
    // H2's trim, in the walk's own spelling (`hosted.rs:77`), on the text
    // where the bytes are text; bytes that are not are handed on untrimmed,
    // and `parse_enroll` answers them `not_utf8` itself — it stays the one
    // authority for every fault, in its own order (the cap first).
    let trimmed: &[u8] = match std::str::from_utf8(field) {
        Ok(text) => text.trim_end_matches(['\n', '\r']).as_bytes(),
        Err(_) => field,
    };
    let entries = parse_enroll(trimmed).map_err(RecordRefused::NotARecord)?;
    // H2, copied: refused here as the sidecar would refuse it one step
    // later, ahead of any docker run (P13; the provisioning record §2.1).
    for e in &entries {
        if e.key.alg() != ALG_MLDSA65_ED25519 {
            return Err(RecordRefused::PreviewKey { alg: e.key.alg() });
        }
    }
    let anchorless = !entries.iter().any(|e| e.anchor);
    Ok(Record { bytes: trimmed.to_vec(), anchorless })
}

#[cfg(test)]
mod tests;
