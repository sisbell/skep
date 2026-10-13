//! THE RECORD, the second of the post's two person-made fields — the first,
//! the board's name, is `name`'s — judged in process before any docker run
//! (the provisioning record §2.1; Q6 (a)), so a refused post leaves nothing
//! behind: the canonical enrollment record `skep keygen` printed on the
//! person's own device. The text is trimmed exactly as the hosted walk trims
//! it (`skep-client`'s `hosted.rs`, H2: `trim_end_matches(['\n', '\r'])`), so
//! a textarea's trailing line break is no `bad_record`; then
//! `skep_identity::parse_enroll` on its bytes, the one authority for every
//! fault it can raise over a form's bytes — `too_large`, `not_utf8`,
//! `bad_record`, `empty`, `duplicate_key:<n>`, each D-5, its token the one
//! word the log carries (AUTH-2.130 admits the canonical encoding and nothing
//! else); then the walk's H2 COPIED in its own spelling — an entry whose key
//! is not the production kind (`e.key.alg() != ALG_MLDSA65_ED25519`) is D-6,
//! a PREVIEW key parsing cleanly and being refused by this test alone; and
//! the anchorless fact — no entry anchor-flagged — kept for the reply's
//! sentence (AUTH-5.62).
//!
//! THE RECORD HOLDS NO KEY THAT SIGNS: `parse_enroll` yields `PublicKey`s,
//! and no field type in `skep-identity` can carry a private key (I1,
//! AUTH-2.89). Its bytes are the person's identifier and are NEVER logged —
//! not here, and not through [`Record`]'s `Debug`, which shows the length
//! alone.

use std::fmt;

use skep_identity::{parse_enroll, PayloadError, ALG_MLDSA65_ED25519};

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

/// The one word the log carries, and only it: `Display` is a second entry
/// to [`RecordRefused::token`], never a second vocabulary — as
/// `PayloadError`'s is to its own.
impl fmt::Display for RecordRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.token())
    }
}

impl std::error::Error for RecordRefused {}

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
