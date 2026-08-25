//! Keys and fingerprints — AUTH-1.1–1.10.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::framing::{framed, KEY_TAG};

/// The Ed25519 alg token (AUTH-1.1) — the line grammar's first token and
/// `ALGS`' first row.
pub const ALG_ED25519: &str = "ed25519";

/// One [`ALGS`] row (AUTH-1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alg {
    /// The alg TOKEN — the line grammar's first token (AUTH-1.1).
    pub token: &'static str,
    /// The RAW KEY LENGTH in bytes (AUTH-1.2).
    pub raw_len: usize,
    /// The KEY FAMILY — a curve, or a PQ parameter set. No two rows may
    /// name the same family (AUTH-1.5; the assertion is AUTH-2.92's).
    pub family: &'static str,
}

/// The algorithm set (AUTH-1.5): the single declared table, three columns —
/// the TOKEN (the line grammar's first token), the RAW LENGTH, and the KEY
/// FAMILY (a curve, or a PQ parameter set) — and no two rows may name the
/// same family. [`PublicKey::parse`] and [`PublicKey::alg`] both READ this
/// table (AUTH-1.6), so carrying a new algorithm arm is ONE edit (the enum
/// arm plus its row) plus the I2 agreement assertion (AUTH-2.92). The token
/// set this table admits is an I2 frozen constant (AUTH-2.90); adding a row
/// is a coordinated grammar upgrade (AUTH-2.91) under the
/// one-canonical-raw-form-per-token obligation (AUTH-2.99).
pub const ALGS: &[Alg] = &[Alg {
    token: ALG_ED25519,
    raw_len: 32,
    family: "edwards25519",
}];

/// A public key (AUTH-1.1): v1 admits Ed25519 only, and the enum is the
/// reserved slot for a future P-256 arm. Syntax-level only — this crate never
/// decodes a curve point (AUTH-1.4) and no field type in the crate can carry
/// a private key (I1, AUTH-2.89).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PublicKey {
    /// 32 raw Ed25519 key bytes — the `ALGS` row's length (AUTH-1.2).
    Ed25519([u8; 32]),
}

impl PublicKey {
    /// AUTH-1.2 — the key's alg token, a token present in [`ALGS`] for every
    /// variant (AUTH-1.6; the both-directions agreement is the AUTH-2.92
    /// assertion).
    pub fn alg(&self) -> &'static str {
        match self {
            PublicKey::Ed25519(_) => ALG_ED25519,
        }
    }

    /// AUTH-1.2 — the raw key bytes (for `Ed25519`, 32 bytes — the `ALGS`
    /// row's length).
    pub fn raw(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(raw) => raw,
        }
    }

    /// AUTH-1.3 — lowercase hex of the raw key bytes.
    pub fn to_hex(&self) -> String {
        hex_encode(self.raw())
    }

    /// AUTH-1.4 — SYNTAX-ONLY admission: the alg token is looked up in
    /// [`ALGS`] (`UnknownAlg` when absent), the hex MUST decode (`BadHex`
    /// otherwise — case-insensitively, AUTH-1.3) to exactly that row's raw
    /// length (`BadLength` otherwise), and the curve point is never decoded.
    pub fn parse(alg: &str, hex: &str) -> Result<PublicKey, KeyParseError> {
        let row = ALGS
            .iter()
            .find(|a| a.token == alg)
            .ok_or(KeyParseError::UnknownAlg)?;
        let bytes = hex_decode(hex).ok_or(KeyParseError::BadHex)?;
        if bytes.len() != row.raw_len {
            return Err(KeyParseError::BadLength);
        }
        match alg {
            ALG_ED25519 => {
                let mut raw = [0u8; 32];
                raw.copy_from_slice(&bytes);
                Ok(PublicKey::Ed25519(raw))
            }
            // Reachable only if ALGS carries a token no arm constructs — the
            // drift the AUTH-2.92 assertion fails at test time.
            _ => Err(KeyParseError::UnknownAlg),
        }
    }
}

/// [`PublicKey::parse`] rejection (AUTH-1.1, AUTH-1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyParseError {
    /// The alg token is absent from [`ALGS`].
    UnknownAlg,
    /// The hex argument does not decode.
    BadHex,
    /// The decoded bytes are not exactly the `ALGS` row's raw length.
    BadLength,
}

/// The algorithm-agnostic identity of a key (AUTH-1.7):
/// `SHA-256(framed(KEY_TAG, [alg, raw]))` (AUTH-1.8). A FOLD INPUT, not
/// merely a display form (I2, AUTH-2.90): the fingerprint is the key-set map
/// key, the token a retirement names, and the serialized value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// AUTH-1.8 — `SHA-256(framed(KEY_TAG, [alg, raw]))`, where `alg` is the
    /// key's alg token bytes and `raw` its raw key bytes.
    pub fn of(key: &PublicKey) -> Fingerprint {
        let preimage = framed(KEY_TAG, &[key.alg().as_bytes(), key.raw()]);
        let digest = Sha256::digest(&preimage);
        Fingerprint(digest.into())
    }

    /// AUTH-1.9 — 64 lowercase hex characters; the daemon emits this flat
    /// form only (grouped rendering is a client display convention,
    /// AUTH-1.10).
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// AUTH-1.9 — accepts exactly 64 hex characters, case-insensitively;
    /// `None` for anything else.
    pub fn parse_hex(s: &str) -> Option<Fingerprint> {
        let bytes = hex_decode(s)?;
        let raw: [u8; 32] = bytes.try_into().ok()?;
        Some(Fingerprint(raw))
    }

    /// The raw digest bytes (AUTH-1.7).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Lowercase hex (AUTH-1.3, AUTH-1.9, AUTH-2.17 — every encoder emits
/// lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Case-insensitive hex decode (AUTH-1.3, AUTH-2.17); `None` on an odd
/// length or a non-hex byte.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let raw = s.as_bytes();
    if raw.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}
