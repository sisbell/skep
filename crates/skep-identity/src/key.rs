//! Keys and fingerprints — AUTH-1.1–1.10.

use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::framing::{framed, KEY_TAG};

/// The Ed25519 alg token (AUTH-1.1) — the value a key entry's `alg` member
/// carries (AUTH-2.128), and `ALGS`' first row. A key of this row opens
/// sessions and signs NO entry: no marker tag names it ([`SIG_ALGS`]).
pub const ALG_ED25519: &str = "ed25519";

/// THE PRODUCTION HYBRID's alg token (signed ops; the design record D7, the
/// owner 2026-09-23 "keep tag 1"; the seam build's TOKEN PIN): ONE `ALGS`
/// row over ONE concatenated raw value — the ML-DSA-65 (FIPS 204) public
/// key, 1,952 bytes, THEN the Ed25519 public key, 32 bytes (the KEY PIN:
/// the post-quantum half FIRST, the order the marker slot's blob takes too)
/// — one entry, one fingerprint, one label (the record §4.4). Its marker
/// tag is `1` ([`SIG_ALGS`]).
pub const ALG_MLDSA65_ED25519: &str = "mldsa65-ed25519";

/// THE PREVIEW HYBRID's alg token (signed ops; THE DUAL APPROACH, the owner
/// 2026-09-25): FN-DSA-512 + Ed25519 under Thomas Pornin's `fn-dsa` 0.4.0
/// "best guess" at the FN-DSA draft — PLANNED AND TESTED NOW under its OWN
/// tag, `3`, marked PREVIEW: tag `2` stays free for the final FIPS 206, and
/// the frozen-tag rule keeps this row's signatures verifying forever under
/// the rule they were made under, keygen-from-seed included. The raw value
/// is the FN-DSA-512 verifying key, 897 bytes, THEN the Ed25519 public key.
/// "preview" is IN the token so the final standard's row never has to share
/// a name with it.
pub const ALG_FNDSA512_PREVIEW_ED25519: &str = "fndsa512-preview-ed25519";

/// The Ed25519 public key's width — every hybrid row's LAST 32 raw bytes,
/// and the whole of [`ALG_ED25519`]'s.
pub const ED25519_KEY_LEN: usize = 32;
/// FIPS 204's ML-DSA-65 public key (`pkEncode`): the first 1,952 raw bytes
/// of [`ALG_MLDSA65_ED25519`]'s value.
pub const MLDSA65_KEY_LEN: usize = 1952;
/// `fn-dsa` 0.4.0's FN-DSA-512 verifying key encoding (header `0x09` then
/// the NTT-form public polynomial): the first 897 raw bytes of
/// [`ALG_FNDSA512_PREVIEW_ED25519`]'s value.
pub const FNDSA512_KEY_LEN: usize = 897;
/// [`ALG_MLDSA65_ED25519`]'s raw length: 1,952 + 32.
pub const MLDSA65_ED25519_KEY_LEN: usize = MLDSA65_KEY_LEN + ED25519_KEY_LEN;
/// [`ALG_FNDSA512_PREVIEW_ED25519`]'s raw length: 897 + 32.
pub const FNDSA512_ED25519_KEY_LEN: usize = FNDSA512_KEY_LEN + ED25519_KEY_LEN;

/// ONE ROW of the marker-tag table (signed ops; the design record §7.3 (i):
/// "the `u8 ↔ token` mapping is pinned beside `ALGS` AS A TWO-ROW TABLE OF
/// ITS OWN"): the commit marker's `sig_alg` byte, the [`ALGS`] token of the
/// hybrid key that signs under it, and the fixed widths the tag's frozen
/// rule pins — the post-quantum half's key and signature, the Ed25519
/// half's being [`ED25519_KEY_LEN`] and 64 at every row. The blob a marker
/// slot carries under the tag is the PQ signature THEN the Ed25519 signature
/// (the record §2.4's pin: two fixed-width fields, no length prefix, no
/// parser), so [`SigAlgRow::sig_len`] is the slot's whole width and
/// [`SigAlgRow::pq_sig_len`] is where the halves part.
///
/// Tag `0` is the EMPTY slot and has no row; tag `2` is RESERVED for the
/// final FIPS 206 and has none yet. Under the frozen-tag rule a row, once a
/// signature has been committed under it, is EDITED NEVER: a change to what
/// verifies — or to what a seed derives — is a new row.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct SigAlgRow {
    /// The marker's `sig_alg` byte.
    pub tag: u8,
    /// The `ALGS` token of the key that signs under this tag.
    pub token: &'static str,
    /// The post-quantum half's public-key width — the FIRST bytes of the
    /// row's raw key; the Ed25519 half is the last [`ED25519_KEY_LEN`].
    pub pq_key_len: usize,
    /// The post-quantum half's signature width — the FIRST bytes of the
    /// slot's blob; the Ed25519 half is the last 64.
    pub pq_sig_len: usize,
}

impl SigAlgRow {
    /// The slot's whole blob width under this tag: the PQ signature ‖ the
    /// Ed25519 signature (64).
    pub const fn sig_len(&self) -> usize {
        self.pq_sig_len + 64
    }

    /// The row's whole raw key width: the PQ key ‖ the Ed25519 key (32) —
    /// equal to its `ALGS` row's `raw_len` (the conformance assertion).
    pub const fn key_len(&self) -> usize {
        self.pq_key_len + ED25519_KEY_LEN
    }
}

/// THE MARKER-TAG TABLE (signed ops): tag `1`, the PRODUCTION hybrid
/// ML-DSA-65 + Ed25519 (3,309 ‖ 64 = 3,373-byte blob); tag `3`, the PREVIEW
/// hybrid FN-DSA-512 + Ed25519 under `fn-dsa` 0.4.0 (666 ‖ 64 = 730-byte
/// blob). Read by [`sig_alg_of`] and [`token_of_sig_alg`] — the codec's
/// lift of the wire's `attest.alg` token to the slot's tag and back — and by
/// the verifier, which dispatches on the tag to THAT tag's frozen rule.
pub const SIG_ALGS: &[SigAlgRow] = &[
    SigAlgRow { tag: 1, token: ALG_MLDSA65_ED25519, pq_key_len: MLDSA65_KEY_LEN, pq_sig_len: 3309 },
    SigAlgRow {
        tag: 3,
        token: ALG_FNDSA512_PREVIEW_ED25519,
        pq_key_len: FNDSA512_KEY_LEN,
        pq_sig_len: 666,
    },
];

/// The marker tag a wire `alg` token names, or `None` for a token no row
/// carries — `ed25519` among them: a classical key signs no entry.
pub fn sig_alg_of(token: &str) -> Option<&'static SigAlgRow> {
    SIG_ALGS.iter().find(|row| row.token == token)
}

/// The row a marker tag names, or `None` — for `0` (the empty slot), `2`
/// (reserved) and every tag no build has minted.
pub fn token_of_sig_alg(tag: u8) -> Option<&'static SigAlgRow> {
    SIG_ALGS.iter().find(|row| row.tag == tag)
}

/// One [`ALGS`] row (AUTH-1.5). Not comparable as a whole:
/// [`AlgRow::from_raw`] is a function pointer, and its ADDRESS says nothing
/// about which function it holds — one function may hold several addresses
/// across codegen units, and distinct functions may be merged onto one — so a
/// row-level `==` would answer unpredictably. The three DATA columns compare
/// directly, which is what the AUTH-2.92 assertion does.
///
/// `#[non_exhaustive]`: READ, never constructed by a caller — [`ALGS`] is the
/// single declared table and an I2 frozen constant (AUTH-2.90), so a foreign
/// row is not a thing this crate wants built, and the columns grow (the fourth
/// arrived with the CONSTRUCTOR). Field READS are unaffected, which is what
/// the AUTH-2.92 assertion takes; a fifth column is then an addition rather
/// than a broken build.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct AlgRow {
    /// The alg TOKEN — the value a key entry's `alg` member carries
    /// (AUTH-1.1, AUTH-2.128).
    pub token: &'static str,
    /// The RAW KEY LENGTH in bytes (AUTH-1.2).
    pub raw_len: usize,
    /// The KEY FAMILY — a curve, or a PQ parameter set. No two rows may
    /// name the same family (AUTH-1.5; the assertion is AUTH-2.92's).
    pub family: &'static str,
    /// AUTH-1.4 — the row's CONSTRUCTOR: this row's decoded raw bytes to a
    /// [`PublicKey`] of THIS row's variant, `None` iff they are not this row's
    /// raw length. Having it here is what makes [`ALGS`] the whole table —
    /// [`PublicKey::parse`] calls it instead of matching the token a second
    /// time, so a row with no constructor does not compile, where a `parse`
    /// that had forgotten one would compile and refuse every key of the new
    /// algorithm. NOT `from_bytes`, which is the signature crate's name for
    /// the POINT DECODE this crate never performs (AUTH-1.4; skepd's
    /// `verifying_key`). The agreement with `raw_len` is the AUTH-2.92
    /// assertion's.
    pub from_raw: fn(&[u8]) -> Option<PublicKey>,
}

/// [`ALGS`]' Ed25519 constructor (AUTH-1.4) — a CHECKED conversion, so bytes
/// of any other length answer `None`, which [`PublicKey::parse`] reports as
/// `BadLength`, rather than panicking on a length the caller chose.
fn ed25519_from_raw(raw: &[u8]) -> Option<PublicKey> {
    <[u8; 32]>::try_from(raw).ok().map(PublicKey::Ed25519)
}

/// [`ALGS`]' tag-1 hybrid constructor: exactly 1,984 bytes, checked the
/// same way — no point of either half is decoded here (AUTH-1.4).
fn mldsa65_ed25519_from_raw(raw: &[u8]) -> Option<PublicKey> {
    <[u8; MLDSA65_ED25519_KEY_LEN]>::try_from(raw)
        .ok()
        .map(|raw| PublicKey::MlDsa65Ed25519(Box::new(raw)))
}

/// [`ALGS`]' tag-3 hybrid constructor: exactly 929 bytes, checked the same
/// way.
fn fndsa512_preview_ed25519_from_raw(raw: &[u8]) -> Option<PublicKey> {
    <[u8; FNDSA512_ED25519_KEY_LEN]>::try_from(raw)
        .ok()
        .map(|raw| PublicKey::FnDsa512PreviewEd25519(Box::new(raw)))
}

/// Serde for the hybrid arms' boxed raw arrays, in the SAME form the derive
/// gives a `[u8; 32]` — a tuple of `N` bytes, no length prefix — so the
/// checkpoint-facing surface (AUTH-1.40) spells every arm's bytes one way.
/// Serde's own array impls stop at 32; these are that impl at the hybrid
/// widths, over the `Box` the arms hold.
mod raw_array {
    use core::fmt;

    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    #[allow(clippy::borrowed_box)]
    pub fn serialize<S: Serializer, const N: usize>(
        raw: &Box<[u8; N]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tuple = s.serialize_tuple(N)?;
        for b in raw.iter() {
            tuple.serialize_element(b)?;
        }
        tuple.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<Box<[u8; N]>, D::Error> {
        struct Bytes<const N: usize>;
        impl<'de, const N: usize> Visitor<'de> for Bytes<N> {
            type Value = Box<[u8; N]>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a tuple of {N} bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Box<[u8; N]>, A::Error> {
                let mut out = Box::new([0u8; N]);
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(N, Bytes::<N>)
    }
}

/// The algorithm set (AUTH-1.5): the single declared table, four columns —
/// the TOKEN (a key entry's `alg` member), the RAW LENGTH, the KEY FAMILY (a
/// curve, or a PQ parameter set), and the CONSTRUCTOR that builds the key —
/// and no two rows may name the same family. [`PublicKey::parse`] and
/// [`PublicKey::alg`] both READ this table (AUTH-1.6), so carrying a new
/// algorithm arm is the enum arm, its row, and the two exhaustive matches
/// (`alg`, `raw`) the compiler names, plus the I2 agreement assertion
/// (AUTH-2.92). Nothing dispatches on the token a second time: the row
/// carries its own [`AlgRow::from_raw`], so there is no admission path a new
/// row can be left out of. The token set this table admits is an I2 frozen
/// constant (AUTH-2.90); adding a row is a coordinated grammar upgrade
/// (AUTH-2.91) under the one-canonical-raw-form-per-token obligation
/// (AUTH-2.99).
pub const ALGS: &[AlgRow] = &[
    AlgRow {
        token: ALG_ED25519,
        raw_len: ED25519_KEY_LEN,
        family: "edwards25519",
        from_raw: ed25519_from_raw,
    },
    // Signed ops (the seam build, 2026-09-25): the two HYBRID rows, each ONE
    // row over ONE concatenated raw value (the record §4.4: one sheet, one
    // entry, one fingerprint, one label). The family names the PAIR, so no
    // two rows share one while both carry an Ed25519 half.
    AlgRow {
        token: ALG_MLDSA65_ED25519,
        raw_len: MLDSA65_ED25519_KEY_LEN,
        family: "ml-dsa-65+edwards25519",
        from_raw: mldsa65_ed25519_from_raw,
    },
    AlgRow {
        token: ALG_FNDSA512_PREVIEW_ED25519,
        raw_len: FNDSA512_ED25519_KEY_LEN,
        family: "fn-dsa-512-preview+edwards25519",
        from_raw: fndsa512_preview_ed25519_from_raw,
    },
];

/// A public key (AUTH-1.1): the classical Ed25519 arm, and — since signed
/// ops — the two HYBRID arms, each ONE key over one concatenated raw value
/// whose halves [`PublicKey::pq_half`] and [`PublicKey::ed25519_half`] read
/// out (the KEY PIN: the post-quantum key FIRST, the Ed25519 key LAST).
/// Syntax-level only — this crate never decodes a curve point or a lattice
/// key (AUTH-1.4) and no field type in the crate can carry a private key
/// (I1, AUTH-2.89).
///
/// Deliberately NOT `#[non_exhaustive]`: a consumer's exhaustive match over
/// this enum is what forces a new algorithm to be given a decode wherever a
/// key is used, where a `_` arm would silently refuse every key of it. The
/// break at each new arm IS AUTH-2.91's coordination, in the compiler.
///
/// The hybrid arms are BOXED, and the enum is no longer `Copy`: a key of
/// 1,984 bytes inline would ride every `Enrolled` value through `im`'s
/// inline-chunked map nodes and every by-value copy — the seam build's first
/// run overflowed a daemon worker's stack on exactly that — so a hybrid key
/// is one allocation and the enum stays a few words wide, cloned where it
/// was copied.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PublicKey {
    /// 32 raw Ed25519 key bytes — the `ALGS` row's length (AUTH-1.2).
    Ed25519([u8; 32]),
    /// Tag 1's hybrid: the ML-DSA-65 public key (1,952) ‖ the Ed25519 public
    /// key (32) — [`ALG_MLDSA65_ED25519`].
    MlDsa65Ed25519(#[serde(with = "raw_array")] Box<[u8; MLDSA65_ED25519_KEY_LEN]>),
    /// Tag 3's PREVIEW hybrid: the FN-DSA-512 verifying key as `fn-dsa`
    /// 0.4.0 encodes it (897) ‖ the Ed25519 public key (32) —
    /// [`ALG_FNDSA512_PREVIEW_ED25519`].
    FnDsa512PreviewEd25519(#[serde(with = "raw_array")] Box<[u8; FNDSA512_ED25519_KEY_LEN]>),
}

impl PublicKey {
    /// AUTH-1.2 — the key's alg token, a token present in [`ALGS`] for every
    /// variant (AUTH-1.6; the both-directions agreement is the AUTH-2.92
    /// assertion).
    pub fn alg(&self) -> &'static str {
        match self {
            PublicKey::Ed25519(_) => ALG_ED25519,
            PublicKey::MlDsa65Ed25519(_) => ALG_MLDSA65_ED25519,
            PublicKey::FnDsa512PreviewEd25519(_) => ALG_FNDSA512_PREVIEW_ED25519,
        }
    }

    /// AUTH-1.2 — the raw key bytes (for `Ed25519`, 32 bytes — the `ALGS`
    /// row's length; for a hybrid, the PQ half then the Ed25519 half).
    pub fn raw(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(raw) => raw,
            PublicKey::MlDsa65Ed25519(raw) => &raw[..],
            PublicKey::FnDsa512PreviewEd25519(raw) => &raw[..],
        }
    }

    /// THE ED25519 HALF — the last 32 raw bytes of a hybrid, the whole of a
    /// classical key: what a session handshake verifies under (the ruled key
    /// model: "an Ed25519 half (for sessions)"), whichever row the key is.
    pub fn ed25519_half(&self) -> &[u8; ED25519_KEY_LEN] {
        let raw = self.raw();
        let (_, tail) = raw.split_at(raw.len() - ED25519_KEY_LEN);
        tail.try_into().expect("every ALGS row's raw value ends in an Ed25519 key")
    }

    /// THE POST-QUANTUM HALF — a hybrid's first bytes (its row's
    /// [`SigAlgRow::pq_key_len`]), `None` for a classical key, which has
    /// none and signs no entry.
    pub fn pq_half(&self) -> Option<&[u8]> {
        match self {
            PublicKey::Ed25519(_) => None,
            PublicKey::MlDsa65Ed25519(raw) => Some(&raw[..MLDSA65_KEY_LEN]),
            PublicKey::FnDsa512PreviewEd25519(raw) => Some(&raw[..FNDSA512_KEY_LEN]),
        }
    }

    /// The marker tag this key signs entries under — its row in
    /// [`SIG_ALGS`] — or `None` for a classical key.
    pub fn sig_alg(&self) -> Option<&'static SigAlgRow> {
        sig_alg_of(self.alg())
    }

    /// AUTH-1.3 — lowercase hex of the raw key bytes.
    pub fn to_hex(&self) -> String {
        hex_encode(self.raw())
    }

    /// AUTH-1.4 — SYNTAX-ONLY admission, the checks in THIS order with the
    /// FIRST failure the verdict: the alg token is looked up in [`ALGS`]
    /// (`UnknownAlg` when absent), then the hex MUST decode (`BadHex`
    /// otherwise — case-insensitively, AUTH-1.3), then that row's own
    /// [`AlgRow::from_raw`] must accept the decoded bytes, which it does at
    /// exactly the row's raw length and no other (`BadLength` otherwise); the
    /// curve point is never decoded. The order is observable and pinned:
    /// `parse("rsa", "zz")` is `UnknownAlg`, `parse("ed25519", "zz")` is
    /// `BadHex` — a length test hoisted ahead of the decode would flip that
    /// second row, which is what `public_key_surface` watches.
    pub fn parse(alg: &str, hex: &str) -> Result<PublicKey, KeyParseError> {
        let row = ALGS
            .iter()
            .find(|a| a.token == alg)
            .ok_or(KeyParseError::UnknownAlg)?;
        let bytes = hex_decode(hex).ok_or(KeyParseError::BadHex)?;
        // The row decides the length, by its own CHECKED conversion: the row
        // is what says which variant these bytes are, so there is no second
        // match on `alg` and no unreachable catch-all. A row whose `from_raw`
        // disagreed with its `raw_len` would answer `BadLength` rather than
        // panic on a length the caller chose; that agreement is the AUTH-2.92
        // assertion's, and adding a row (AUTH-2.91) cannot make a hostile
        // entry panic here while it is out.
        (row.from_raw)(&bytes).ok_or(KeyParseError::BadLength)
    }
}

/// The two facts [`alg`] and [`to_hex`] already publish (AUTH-1.2,
/// AUTH-1.3), not thirty-two decimal bytes.
///
/// [`alg`]: PublicKey::alg
/// [`to_hex`]: PublicKey::to_hex
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({} {})", self.alg(), self.to_hex())
    }
}

/// [`PublicKey::parse`] rejection (AUTH-1.1, AUTH-1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyParseError {
    /// The alg token is absent from [`ALGS`].
    UnknownAlg,
    /// The hex argument does not decode.
    BadHex,
    /// The decoded bytes are not exactly the `ALGS` row's raw length.
    BadLength,
}

/// Prose, never a second wire vocabulary: a `KeyParseError` reaches no wire.
/// `parse_enroll` answers `PayloadError::BadRecord` for every one of these,
/// and that is the fault a consumer renders (AUTH-1.28).
impl fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyParseError::UnknownAlg => "alg token is absent from ALGS",
            KeyParseError::BadHex => "key hex does not decode",
            KeyParseError::BadLength => "decoded key is not the ALGS row's raw length",
        })
    }
}

impl std::error::Error for KeyParseError {}

/// The algorithm-agnostic identity of a key (AUTH-1.7):
/// `SHA-256(framed(KEY_TAG, [alg, raw]))` (AUTH-1.8). A FOLD INPUT, not
/// merely a display form (I2, AUTH-2.90): the fingerprint is the key-set map
/// key, the entry a retirement names, and the serialized value.
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
    /// `None` for anything else. The length is the FIRST test, so a caller's
    /// string sizes no allocation here: AUTH-1.9 fixes the admitted length at
    /// a constant, and every other length answers `None` whatever its bytes.
    pub fn parse_hex(s: &str) -> Option<Fingerprint> {
        if s.len() != 64 {
            return None;
        }
        let bytes = hex_decode(s)?;
        let raw: [u8; 32] = bytes.try_into().ok()?;
        Some(Fingerprint(raw))
    }

    /// The raw digest bytes (AUTH-1.7).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The AUTH-1.9 flat hex form, not thirty-two decimal bytes.
impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

/// AUTH-1.9 — the flat 64-lowercase-hex form, the only form the daemon
/// emits; grouped rendering is a client display convention (AUTH-1.10).
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
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
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let digits = s.as_bytes();
    if digits.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}
