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
//! a PREVIEW key parsing cleanly and being refused by this test alone; then
//! THE GENESIS's OWN TWO REFUSALS, which skepd's credential precheck makes
//! at the hosted claim's genesis (its slots (4) and (5), in AUTH-3.44's
//! order) — after this service has made the claim run and the walk has
//! committed its delegate and its home, so a record refused by either can
//! never be claimed, and its post would fail and let its code go to fail
//! again — each D-5: a key with a half that does not decode
//! ([`key_decodes`], the daemon's own decode), and more entries than the
//! genesis's cap ([`MAX_GENESIS_KEYS`]); and the anchorless fact — no entry
//! anchor-flagged — kept for the reply's sentence (AUTH-5.62). The trim and
//! the kind test are held to the walk's own spellings, and the genesis's two
//! refusals to the daemon's, by this module's suite, which reads them back
//! from `skep-client` and from `skepd`.
//!
//! THE RECORD HOLDS NO KEY THAT SIGNS: `parse_enroll` yields `PublicKey`s,
//! and no field type in `skep-identity` can carry a private key (I1,
//! AUTH-2.89); the decode is `skep-signature`'s verify-only build, which
//! holds no signer. Its bytes are the person's identifier and are NEVER
//! logged whole — not here, and not through [`Record`]'s `Debug`, which
//! shows the length alone; the sidecar's talk, which the flow logs whole,
//! names each entry by its fingerprint and its label.

use std::fmt;

use skep_identity::{parse_enroll, PayloadError, ALG_MLDSA65_ED25519};
#[cfg(test)]
use skep_identity::{PublicKey, ED25519_KEY_LEN, MLDSA65_KEY_LEN};
use skep_signature::key_decodes;

/// THE GENESIS's KEY CAP: sixteen entries in one record — skepd's
/// `MAX_GENESIS_KEYS` (`auth/policy/credential.rs`, the seeding hand's own
/// bound), private to the daemon and restated here, held to it by this
/// module's suite, which reads it back. A hosted claim's genesis past it is
/// refused by the daemon after the claim run is made; `skep keygen
/// --anchors` prints three entries.
const MAX_GENESIS_KEYS: usize = 16;

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
    /// D-5: an entry whose key has a half that does not decode
    /// ([`key_decodes`]) — the daemon's `undecodable_key` at the hosted
    /// claim's genesis.
    UndecodableKey,
    /// D-5: more entries than [`MAX_GENESIS_KEYS`] — the daemon's
    /// `too_many_enrolled` at the same genesis.
    TooManyKeys,
}

impl RecordRefused {
    /// The one word the log carries: the payload fault's token
    /// (`PayloadError::token`, AUTH-1.28's one authority), `preview_key`, or
    /// the daemon's own word for a genesis it refuses.
    fn token(&self) -> String {
        match self {
            RecordRefused::NotARecord(e) => e.token(),
            RecordRefused::PreviewKey { .. } => "preview_key".to_owned(),
            RecordRefused::UndecodableKey => "undecodable_key".to_owned(),
            RecordRefused::TooManyKeys => "too_many_enrolled".to_owned(),
        }
    }
}

/// The one word the log carries, and only it: `Display` is the word's one
/// way out of this module — [`RecordRefused::token`] as it stands, never a
/// second vocabulary, as `PayloadError`'s is to its own.
impl fmt::Display for RecordRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.token())
    }
}

impl std::error::Error for RecordRefused {}

/// THE RECORD's ADMISSION: the field trimmed as the hosted walk trims it,
/// `parse_enroll` on the bytes, then H2 — every entry the production kind —
/// then the genesis's own two refusals — every half decoded, the entries
/// within the cap — and the anchorless fact.
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
    // THE GENESIS's OWN REFUSALS, the daemon's credential precheck's slots
    // (4) and (5) in its order: every half of the first `MAX_GENESIS_KEYS +
    // 1` entries decoded — the daemon decodes no further — then the count.
    // The daemon makes both at the hosted claim's genesis, after this
    // service has made the claim run: a record either holds can never be
    // claimed, and its post would fail and let its code go to fail again.
    if !entries.iter().take(MAX_GENESIS_KEYS + 1).all(|e| key_decodes(&e.key)) {
        return Err(RecordRefused::UndecodableKey);
    }
    if entries.len() > MAX_GENESIS_KEYS {
        return Err(RecordRefused::TooManyKeys);
    }
    let anchorless = !entries.iter().any(|e| e.anchor);
    Ok(Record { bytes: trimmed.to_vec(), anchorless })
}

/// A PRODUCTION-KIND KEY WHOSE HALVES DECODE, for the unit suites: `pq`
/// repeated as the post-quantum half — ML-DSA-65's decode admits any bytes
/// of its length — beside the Ed25519 base point's encoding (RFC 8032: `58`,
/// then thirty-one `66`), a point by construction.
#[cfg(test)]
pub fn decodable_key(pq: u8) -> PublicKey {
    let mut ed25519 = [0x66; ED25519_KEY_LEN];
    ed25519[0] = 0x58;
    PublicKey::from_halves(ALG_MLDSA65_ED25519, &[pq; MLDSA65_KEY_LEN], &ed25519).expect("the production row's widths")
}

/// A PRODUCTION-KIND KEY WHOSE ED25519 HALF IS NO POINT, for the unit
/// suites: the first constant half [`key_decodes`] refuses — found, not
/// hard-coded, as skepd's own suite finds its one; roughly half of all
/// 32-byte strings fail decompression, and the `expect` keeps a search that
/// finds nothing from passing silently.
#[cfg(test)]
pub fn undecodable_key() -> PublicKey {
    (0u8..=255)
        .map(|n| PublicKey::from_halves(ALG_MLDSA65_ED25519, &[0x9f; MLDSA65_KEY_LEN], &[n; ED25519_KEY_LEN]).expect("the production row's widths"))
        .find(|k| !key_decodes(k))
        .expect("no non-point among the 256 constant-byte candidates")
}

#[cfg(test)]
mod tests;
