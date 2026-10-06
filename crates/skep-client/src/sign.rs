//! The signing seam (`client.md` §1.1's `sign` row, §1.4): the `Signer`
//! trait — `public_key` the HYBRID key, `sign` the kind's BLOB over bytes
//! the library framed — and its in-memory seed arm over
//! `skep_signature::HybridSigner`, keygen from the seed under the
//! production kind's tag (AUTH-1.1; wire.md's keygen-from-seed rule); and
//! `session_payload(origin, nonce, principal, scope)`, AUTH-6.4's two
//! versioned layouts under `SESSION_TAG` and `SESSION_TAG_V2` — the
//! REFERENCE layout for every signer, REPRODUCIBLE FROM THE RULE WITH NO
//! DAEMON CRATE LINKED (AUTH-5.67; AUTH RES-61), the daemon's
//! `session_payload` the arbiter (P5); and `record_frame`, the bytes a
//! credential record's `sig` is made over at the record grade, which a
//! deposit signs and the admitted read's trial verifies.
//!
//! A `Signer` knows nothing of the wire: it signs bytes the library framed.
//! Of the key material a dropped `HybridSigner` holds, the Ed25519 half is
//! wiped and the ML-DSA-65 half released unwiped (its own doc) — AUTH-5.54
//! step 3's DROP is OPEN WORK for that half, reported and not claimed here.

use skep_address::Address;
use skep_identity::{
    entry_body_record, entry_frame, framed, BoardTerm, DocTerm, Fingerprint, PublicKey, RecordRows, SESSION_TAG,
    SESSION_TAG_V2,
};
use skep_signature::HybridSigner;

use crate::address::parse_address;
use crate::board::Scope;
use crate::origin::Origin;

/// The production kind's marker tag — `mldsa65-ed25519`, tag 1, the kind
/// every served board enrolls (wire.md §The claim ceremony and credentials).
pub const PRODUCTION_TAG: u8 = skep_signature::TAG_MLDSA65_ED25519;

/// THE SIGNER SEAM (§1.4): a custody rung is an implementation of this
/// trait and never a rewrite of the ceremony.
pub trait Signer {
    /// The HYBRID public key — one `ALGS` token over both halves.
    fn public_key(&self) -> PublicKey;

    /// The kind's BLOB — the post-quantum signature then the Ed25519
    /// signature, 3,373 bytes at tag 1 — over bytes the library framed
    /// (AUTH-6.4; the record grade's frame).
    fn sign(&self, payload: &[u8]) -> Vec<u8>;

    /// The key's fingerprint (AUTH-1.7), the value every compare reads.
    fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.public_key())
    }

    /// The marker tag the blob is made under — the key's own row's.
    fn tag(&self) -> u8 {
        self.public_key().sig_alg_row().tag
    }
}

impl Signer for HybridSigner {
    fn public_key(&self) -> PublicKey {
        HybridSigner::public_key(self).clone()
    }

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        HybridSigner::sign(self, payload)
    }
}

/// A signer behind a box is the signer it holds.
impl Signer for Box<dyn Signer> {
    fn public_key(&self) -> PublicKey {
        (**self).public_key()
    }

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        (**self).sign(payload)
    }
}

/// Keygen from a 32-byte seed under the production kind (the
/// keygen-from-seed rule: one seed, two halves through the KDF, never the
/// raw seed to either).
pub fn signer_from_seed(seed: &[u8; 32]) -> HybridSigner {
    HybridSigner::from_seed(PRODUCTION_TAG, seed).expect("tag 1 is a row this build holds")
}

/// Keygen from a seed under `tag`'s rule, `None` for a tag this build holds
/// no rule for.
pub fn signer_from_seed_under(tag: u8, seed: &[u8; 32]) -> Option<HybridSigner> {
    HybridSigner::from_seed(tag, seed)
}

/// A fresh 32-byte seed from the OS random source (`getrandom`, a
/// `CryptoRng`), fail-stop: no seed from anything weaker.
pub fn fresh_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS entropy unavailable");
    seed
}

/// `n` fresh bytes from the OS random source.
pub fn fresh_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    getrandom::fill(&mut out).expect("OS entropy unavailable");
    out
}

/// A client-minted random principal id over the wire's exactly-representable
/// range — 53 random bits, never a full `u64` and never a counter
/// (AUTH-5.20).
pub fn fresh_principal_id() -> u64 {
    let bytes = fresh_bytes(8);
    let raw = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
    (raw & ((1u64 << 53) - 1)).max(2)
}

/// AUTH-6.4 — the signed bytes, VERSIONED and never extended in place: a
/// FULL session signs `framed(SESSION_TAG, [origin, nonce, principal])`, a
/// CONTENT-scoped one `framed(SESSION_TAG_V2, [origin, nonce, principal,
/// scope])` — each over the body's OWN strings, `principal` as shortest
/// ASCII decimal, `scope` the body's own `content` bytes. `origin` is the
/// origin this client SIGNS for the board (AUTH-4.8), the one it dialed for
/// every direct client.
pub fn session_payload(origin: &Origin, nonce: &str, principal: u64, scope: Scope) -> Vec<u8> {
    let principal = principal.to_string();
    match scope {
        Scope::Full => framed(SESSION_TAG, &[origin.as_str().as_bytes(), nonce.as_bytes(), principal.as_bytes()]),
        Scope::Content => framed(
            SESSION_TAG_V2,
            &[origin.as_str().as_bytes(), nonce.as_bytes(), principal.as_bytes(), b"content"],
        ),
    }
}

/// THE RECORD FRAME a credential record's `sig` is made over (the record
/// grade; wire.md §The claim ceremony and credentials): `framed("skep-entry-v1",
/// [alg, board, account, doc, "record", body])` — `alg` the signing key's
/// token, `board` `H.1`'s pair, `account` the HOME's account, `doc` the home,
/// the body the five rows over the sig-less canonical record. Composed by
/// `skep_identity::entry_frame`, spelled by nobody here.
pub fn record_frame(alg: &str, board: BoardTerm, home_account: &str, home: &str, ty: &str, to: &[&str], sigless: &[u8]) -> Option<Vec<u8>> {
    let account = parse_address(home_account)?;
    let home = parse_address(home)?;
    let ty = parse_address(ty)?;
    let to: Vec<Address> = to.iter().map(|a| parse_address(a)).collect::<Option<_>>()?;
    let body = entry_body_record(RecordRows { ty: &ty, to: &to, replaces: None, lineage_fork_point: None, sigless_canonical_record: sigless });
    Some(entry_frame(alg, board, &account, DocTerm::One(&home), &body))
}

/// The blob as the wire carries it — lowercase hex (6,746 characters at
/// tag 1).
pub fn sig_hex(blob: &[u8]) -> String {
    crate::hex::encode(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AUTH-6.4 — the two layouts, byte for byte: the tag, then each field
    /// `be32(len) ‖ bytes`; the v2 bytes carry the scope LAST.
    #[test]
    fn the_session_payload_is_the_rules_two_layouts() {
        let origin = Origin::parse("http://127.0.0.1:8642").unwrap();
        let nonce = "ab".repeat(32);
        let v1 = session_payload(&origin, &nonce, 7, Scope::Full);
        let mut expect = b"skep-session-v1".to_vec();
        for field in [origin.as_str().as_bytes(), nonce.as_bytes(), b"7"] {
            expect.extend_from_slice(&(field.len() as u32).to_be_bytes());
            expect.extend_from_slice(field);
        }
        assert_eq!(v1, expect);
        let v2 = session_payload(&origin, &nonce, 7, Scope::Content);
        let mut expect2 = b"skep-session-v2".to_vec();
        for field in [origin.as_str().as_bytes(), nonce.as_bytes(), b"7", b"content"] {
            expect2.extend_from_slice(&(field.len() as u32).to_be_bytes());
            expect2.extend_from_slice(field);
        }
        assert_eq!(v2, expect2);
    }

    /// The seam over the hybrid signer: the blob is the row's width and
    /// verifies under the key; the fingerprint is the key's.
    #[test]
    fn a_seed_signer_signs_the_rows_blob() {
        let signer = signer_from_seed(&[9u8; 32]);
        let blob = Signer::sign(&signer, b"bytes the library framed");
        assert_eq!(blob.len(), 3373);
        assert_eq!(Signer::tag(&signer), PRODUCTION_TAG);
        assert_eq!(skep_signature::verify(PRODUCTION_TAG, &Signer::public_key(&signer), b"bytes the library framed", &blob), Ok(()));
        assert_eq!(Signer::fingerprint(&signer), Fingerprint::of(HybridSigner::public_key(&signer)));
        let id = fresh_principal_id();
        assert!(id >= 2 && id < (1 << 53));
    }
}
