//! Shared test plumbing: spawn a real daemon on an ephemeral port and speak
//! HTTP/1.1 to it over a plain TcpStream (`Connection: close`, read to EOF)
//! — the transport is the thing under test, so no client library sits in
//! the middle.
//!
//! [`http_full`] speaks exactly one well-formed request shape, which is what
//! every suite about the daemon's SEMANTICS wants. A suite about the
//! TRANSPORT itself needs bytes outside that shape — a `Transfer-Encoding`
//! header, a truncated body, a version that is not 1.1 — and reaches for
//! [`raw_exchange`], which writes what it is given.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_identity::{
    canonical_record, encode_enroll, entry_body_assert_sup, entry_body_edit_link, entry_body_emit,
    entry_body_empty, entry_body_insert, entry_body_make_link, entry_body_make_link_replacing,
    entry_body_nullify, entry_body_publish, entry_body_record, entry_frame, framed,
    parse_record_value, BoardTerm, ContentFreeOp, DocTerm, Enrollment, EntrySlot, Fingerprint,
    LinkSlots, PublicKey, RecordEntry, RecordRows, ShotBase, ShotSegmentPiece, SigAlgRow,
    SESSION_TAG, SESSION_TAG_V2,
};
use skep_signature::HybridSigner;
use skepd::{serve, AuthOptions, Daemon, MediaOptions, NodePrefix, Origin, Skepd, DEFAULT_WORKERS};

mod ops;
mod signer;

pub use ops::*;
pub use signer::*;

/// The credential type addresses this build allocates (AUTH-7.1 horn B):
/// subspace 3 of the ghost document, ordinals enroll·retire·claim.
pub const T_ENROLL: &str = "1.1.0.1.0.1.0.3.1";
pub const T_RETIRE: &str = "1.1.0.1.0.1.0.3.2";
pub const T_CLAIM: &str = "1.1.0.1.0.1.0.3.3";

/// The two shipped link classes a `nullify` and an `assert_sup` deposit
/// under — the reserved ghost tumblers M7 fixes by kind (the format's
/// `1.1.0.1.0.1.0.1.x`, x = 5 the retraction, 4 the supersedes class): the
/// type slot of the stored link each op's entry frame signs.
pub const T_RETRACTION: &str = "1.1.0.1.0.1.0.1.5";
pub const T_SUPERSEDES: &str = "1.1.0.1.0.1.0.1.4";

/// The GRANTS class type address (COMMONS DECISION 5 — 1.1.0.1.0.1.0.3.90):
/// the type a sharing grant's link carries (PUB-5.8, wire.md §The read
/// predicate).
pub const T_GRANT: &str = "1.1.0.1.0.1.0.3.90";

/// The registry's two record-deposit kinds (REG-1.14; `skep_registry`'s
/// table, the engine's ledger): the BINDING `3.55` and the ENDPOINT `3.56`
/// of the ghost document's type subspace, spelled as a client names them —
/// the deposit class's third and fourth members (wire.md §Registry).
pub const T_BINDING: &str = "1.1.0.1.0.1.0.3.55";
pub const T_ENDPOINT: &str = "1.1.0.1.0.1.0.3.56";

/// The claim ceremony's fixed test identity: a high principal id so suite
/// principals (0, 1, 2, …) never collide with it, and deterministic key
/// seeds so a reopened board verifies against the same keys.
pub const CLAIMANT_PRINCIPAL: u64 = 900;
pub const CLAIMANT_ACCOUNT: &str = "1.0.1";
pub const CLAIMANT_DOC1: &str = "1.0.1.0.1";
pub const DEVICE_SEED: [u8; 32] = [7; 32];
pub const ANCHOR_SEED: [u8; 32] = [8; 32];

pub fn device_key() -> SigningKey {
    SigningKey::from_bytes(&DEVICE_SEED)
}

pub fn anchor_key() -> SigningKey {
    SigningKey::from_bytes(&ANCHOR_SEED)
}

/// THE FIXTURES' TAG (signed ops): every key the suites enrol is a HYBRID
/// under tag 1, the production pair — ML-DSA-65 + Ed25519, deterministic
/// signing, so every fixture's signature is byte-stable.
pub const FIXTURE_TAG: u8 = skep_signature::TAG_MLDSA65_ED25519;

/// THE SEED A HELPER'S `SigningKey` CARRIES (signed ops): the suites keep
/// one 32-byte seed per principal — `DEVICE_SEED`, `ANCHOR_SEED`,
/// `distinct_key(n)` — spelled as an Ed25519 `SigningKey` since before
/// signed ops, and that spelling is kept at every one of the 231 call sites
/// as THE SEED CARRIER: what a helper signs with, and what it enrols, is
/// derived from the key's 32 bytes through the KDF PIN (`skep_signature`),
/// never the key itself — the ruled "one seed, two halves, never the raw
/// seed".
pub fn seed_of(sk: &SigningKey) -> [u8; 32] {
    sk.to_bytes()
}

/// The hybrid signer one seed carrier derives under [`FIXTURE_TAG`]: both
/// halves sign the seed's sessions (the hybrid handshake) and its entries.
pub fn hybrid_signer(sk: &SigningKey) -> HybridSigner {
    HybridSigner::from_seed(FIXTURE_TAG, &seed_of(sk)).expect("tag 1 is a row")
}

/// The ONE key entry a seed carrier enrols: the hybrid key under
/// [`FIXTURE_TAG`] — its fingerprint the one a session testifies and an
/// entry verifies under. (The classical `ed25519` row is DELETED — the
/// hybrid-only launch, AUTH-1.1/1.5 — so a seed carrier enrols nothing but
/// a hybrid key.)
pub fn public_key_of(sk: &SigningKey) -> PublicKey {
    hybrid_signer(sk).public_key().clone()
}

/// A deterministic per-principal signing key: seed `n` in every byte, the
/// first byte XORed with `0x40` so no `distinct_key(n)` collides with the
/// ceremony's [`DEVICE_SEED`]/[`ANCHOR_SEED`] (constant-byte seeds) at any
/// `n`. The suites that hire delegated principals key each one with the
/// principal's own number.
pub fn distinct_key(n: u8) -> SigningKey {
    let mut seed = [n; 32];
    seed[0] = 0x40 ^ n;
    SigningKey::from_bytes(&seed)
}

/// Arbitrary record text as its atom JSON fragment — the escape every record
/// atom the suites insert takes, so a payload no parser admits is written the
/// same way a well-formed one is.
pub fn json_atom(text: &str) -> String {
    serde_json::to_string(&Value::String(text.to_string())).expect("json string")
}

/// One enroll record of DEVICE-flagged keys (no anchor lines — AUTH-5.63's
/// rule for a machine-composed genesis), as its atom JSON fragment.
pub fn enroll_atom(keys: &[&SigningKey]) -> String {
    let flagged: Vec<(&SigningKey, bool)> = keys.iter().map(|sk| (*sk, false)).collect();
    enroll_atom_flagged(&flagged)
}

/// One enroll record with the anchor flag named per key, as its atom JSON
/// fragment.
pub fn enroll_atom_flagged(keys: &[(&SigningKey, bool)]) -> String {
    let entries: Vec<Enrollment> = keys
        .iter()
        .map(|(sk, anchor)| Enrollment::new(public_key_of(sk), *anchor, None).expect("no label"))
        .collect();
    json_atom(&encode_enroll(&entries))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The v1 session bytes (AUTH-6.4): `framed(SESSION_TAG, [origin, nonce,
/// principal-decimal])` — the UNSCOPED layout, unmoved under its name by the
/// hybrid handshake.
pub fn session_bytes_v1(origin: &str, nonce: &str, principal: u64) -> Vec<u8> {
    framed(SESSION_TAG, &[origin.as_bytes(), nonce.as_bytes(), principal.to_string().as_bytes()])
}

/// Sign the session payload (AUTH-6.4) as a SIGNER of either row does: the
/// HYBRID BLOB over the v1 bytes — the post-quantum signature then the
/// Ed25519 signature, both halves over the same bytes (AUTH-4.32, AUTH-6.3)
/// — as hex: 6,746 characters under tag 1, 1,460 under tag 3. The blob a
/// `POST /session` body's `sig` carries; the body names no `alg`, the
/// daemon trying every enrolled key under its own row.
pub fn sign_session_as(signer: &HybridSigner, origin: &str, nonce: &str, principal: u64) -> String {
    hex(&signer.sign(&session_bytes_v1(origin, nonce, principal)))
}

/// Sign the session payload (AUTH-6.4) under the seed carrier's derived
/// TAG-1 signer ([`hybrid_signer`]): the hybrid blob, both halves —
/// [`sign_session_as`] at [`FIXTURE_TAG`]. Deterministic (ML-DSA-65's
/// deterministic variant, Ed25519), so a cell can re-sign and compare.
pub fn sign_session(sk: &SigningKey, origin: &str, nonce: &str, principal: u64) -> String {
    sign_session_as(&hybrid_signer(sk), origin, nonce, principal)
}

/// THE NEGATIVE VECTOR's producer: the Ed25519 half ALONE over the v1 bytes
/// — 64 signature bytes, 128 hex — the CLASSICAL layout no served board
/// admits since the hybrid handshake. Its width is none of the hybrid blob
/// widths, so a body carrying it is `400 malformed_session_request` with the
/// nonce SURVIVING (AUTH-6.3; the hybrid-only launch's Q2) — never a 401, and
/// never a session: no half opens one alone. Made with the seed carrier's
/// DERIVED Ed25519 half, the very half of the enrolled hybrid key, so the
/// refusal is the WIDTH's and not a wrong key's.
pub fn sign_session_ed25519_half_alone(
    sk: &SigningKey,
    origin: &str,
    nonce: &str,
    principal: u64,
) -> String {
    let payload = session_bytes_v1(origin, nonce, principal);
    hex(&hybrid_signer(sk).ed25519_signing_key().sign(&payload).to_bytes())
}

/// [`sign_session`]'s SCOPED variant — the v2 bytes (AUTH-6.4):
/// `framed(SESSION_TAG_V2, [origin, nonce, principal-decimal, scope])`, the
/// layout a body carrying `"scope": <scope>` signs — the hybrid blob, both
/// halves, under the seed carrier's tag-1 signer. `scope` is a parameter
/// rather than the constant `content` so a cell can sign exactly what a
/// malformed body says — the daemon refuses that body at the parse, whatever
/// its signature.
pub fn sign_session_scoped(
    sk: &SigningKey,
    origin: &str,
    nonce: &str,
    principal: u64,
    scope: &str,
) -> String {
    let payload = framed(
        SESSION_TAG_V2,
        &[origin.as_bytes(), nonce.as_bytes(), principal.to_string().as_bytes(), scope.as_bytes()],
    );
    hex(&hybrid_signer(sk).sign(&payload))
}

/// Open a SIGNED session for `principal` under a NAMED hybrid signer — of
/// either row — over the challenge/response handshake, signing the origin
/// actually dialed with the signer's blob ([`sign_session_as`]). The token is
/// NOT registered with the test signer (which signs attests under the seed
/// carrier's TAG-1 key): a cell wanting attests attached registers it, with
/// the seed carrier, itself.
pub fn open_signed_session_as(port: u16, principal: u64, signer: &HybridSigner) -> String {
    let nonce = challenge(port, principal);
    let origin = format!("http://127.0.0.1:{port}");
    let sig = sign_session_as(signer, &origin, &nonce, principal);
    let body = format!(
        "{{\"principal\":{principal},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
    );
    let (st, resp) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(
        st,
        200,
        "signed session under tag {}: {}",
        signer.tag(),
        String::from_utf8_lossy(&resp)
    );
    json(&resp)["session"].as_str().expect("session token").to_string()
}

/// A fresh challenge for `principal`: the nonce, as issued.
pub fn challenge(port: u16, principal: u64) -> String {
    let (st, body) = http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
    assert_eq!(st, 200, "challenge: {}", String::from_utf8_lossy(&body));
    json(&body)["nonce"].as_str().expect("nonce").to_string()
}

/// The SCOPED signed body (AUTH-6.2's third form), its members in the order
/// the rule writes them — `scope` before `sig`.
pub fn scoped_session_body(principal: u64, nonce: &str, origin: &str, sig: &str) -> String {
    format!(
        "{{\"principal\":{principal},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\
         \"scope\":\"content\",\"sig\":\"{sig}\"}}"
    )
}

/// Open a CONTENT-scoped signed session for `principal` (AUTH-6.2's third
/// form, AUTH-4.39): the body carries `"scope": "content"` and is signed
/// under the v2 bytes, over the origin actually dialed. The session reads,
/// writes content and closes as a full one does, and deposits no credential.
pub fn open_content_session(port: u16, principal: u64, sk: &SigningKey) -> String {
    let nonce = challenge(port, principal);
    let origin = format!("http://127.0.0.1:{port}");
    let sig = sign_session_scoped(sk, &origin, &nonce, principal, "content");
    let body = scoped_session_body(principal, &nonce, &origin, &sig);
    let (st, resp) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 200, "content session: {}", String::from_utf8_lossy(&resp));
    let token = json(&resp)["session"].as_str().expect("session token").to_string();
    register_signer(&token, principal, sk);
    token
}

/// Open a SIGNED session for `principal` over the challenge/response
/// handshake, signing the origin actually dialed.
pub fn open_signed_session(port: u16, principal: u64, sk: &SigningKey) -> String {
    let (st, body) = http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
    assert_eq!(st, 200, "challenge: {}", String::from_utf8_lossy(&body));
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();
    let origin = format!("http://127.0.0.1:{port}");
    let sig = sign_session(sk, &origin, &nonce, principal);
    let body = format!(
        "{{\"principal\":{principal},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
    );
    let (st, resp) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 200, "signed session: {}", String::from_utf8_lossy(&resp));
    let token = json(&resp)["session"].as_str().expect("session token").to_string();
    register_signer(&token, principal, sk);
    token
}

/// One signed handshake, WHOLE and unjudged: a fresh challenge for
/// `principal`, the body signed by `sk` over the origin actually dialed, and
/// the `POST /session` answer as it came — status, headers, body bytes. For
/// the cells whose subject is a REFUSAL (the 401's bytes, the 403's), where
/// [`open_signed_session`]'s own assertion of a 200 is the wrong judge.
pub fn signed_handshake(
    port: u16,
    principal: u64,
    sk: &SigningKey,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let (st, body) = http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
    assert_eq!(st, 200, "challenge: {}", String::from_utf8_lossy(&body));
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();
    let origin = format!("http://127.0.0.1:{port}");
    let sig = sign_session(sk, &origin, &nonce, principal);
    let body = format!(
        "{{\"principal\":{principal},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
    );
    http_full(port, "POST", "/session", None, body.as_bytes())
}

/// The board claimed? — off `/health.auth.claimant`.
pub fn claimed(port: u16) -> bool {
    let (st, body) = http(port, "GET", "/health", None, b"");
    assert_eq!(st, 200);
    !json(&body)["auth"]["claimant"].is_null()
}

/// Run the notebook claim ceremony (AUTH-5.55 steps 1–5) over the wire:
/// delegate from 0, the home mint, the genesis atom + deposit, the SIGNED
/// claim. Idempotent — a reopened claimed board skips it.
///
/// THE CLAIM WRITES `H.1` (signed ops, s1; RULED 2026-09-25): the claim's
/// own request commits the board's first head — the staging draft's mint,
/// the head record's insert, the shot into `H`, eight records right after
/// the claim link, the system account's own and exempt from the check by ω
/// — so the board term every attested write's frame names (D13) is present
/// at the claim's ack and names the claim's own position. Asserted here, at
/// every claim a suite makes, and on every reopened claimed board (a claimed
/// board without `H.1` is the crash window the open closes).
pub fn claim_board(port: u16) {
    if claimed(port) {
        assert!(board_term(port).is_some(), "a reopened claimed board has its H.1");
        return;
    }
    ceremony_before_the_claim(port);
    // The claim, from a session SIGNED by the device key (step 5).
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{T_CLAIM}"]}}}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    assert!(claimed(port), "the claim link flips the board claimed");
    let h1 = board_term(port).expect("the claim's own step wrote H.1");
    assert_eq!(h1.log_position, acked_at(&v), "H.1 names the claim's own position");
}

/// The claim ceremony's first four steps (AUTH-5.55 steps 1–4) over the
/// wire — the delegate from 0, the home mint, the genesis atom and its
/// deposit — leaving the SIGNED claim, step 5, to the caller:
/// [`claim_board`] makes it at once, and a suite that needs the board as it
/// stands BEFORE the claim makes it with [`claim_frame`] when it is ready.
pub fn ceremony_before_the_claim(port: u16) {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    assert_eq!(prefix, CLAIMANT_ACCOUNT, "the ceremony must be the board's first delegate");
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{CLAIMANT_PRINCIPAL}}}"#),
    );
    expect_resp(&v, "ack_addr");
    let claimant = open_session(port, CLAIMANT_PRINCIPAL);
    let v = op(
        port,
        Some(&claimant),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    assert_eq!(acked_addr(&v), CLAIMANT_DOC1, "the home mint is doc 1");
    // The enrollment record — the anchor and the device key — as ONE ATOM.
    let record_text = encode_enroll(&[
        Enrollment::new(public_key_of(&anchor_key()), true, Some("paper-a".into()))
            .expect("a legal label"),
        Enrollment::new(public_key_of(&device_key()), false, Some("notebook".into()))
            .expect("a legal label"),
    ]);
    let atom = serde_json::to_string(&Value::String(record_text)).expect("json string");
    // The atom's insert carries the DEPOSIT DECLARATION (PUB-2.63; the
    // DECLARED horn of PUB-9.13): doc 1 is born published, and an undeclared
    // insert into it is the in-place edit the write path refuses (PUB-2.11).
    // The declaration NAMES THE CLASS (PUB-2.64): ENROLL's type, the type the
    // pair's `make_link` below carries — and the door's class test is
    // session-blind, so this BARE pre-claim insert is admitted on it (T1(b)).
    let v = op(
        port,
        Some(&claimant),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    let atom_addr = format!("{CLAIMANT_DOC1}.0.1.1");
    let v = op(
        port,
        Some(&claimant),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
}

/// The next FREE content ordinal of `doc` — one past its arranged content
/// extent, read off `retrieve_doc_v_span_set` (the content extent is the
/// `1.1`-started span, its width `0.N`; an empty document has none). Read as
/// `token` (`None` = the guest, enough for a published doc 1). The position a
/// declared deposit into a published document must land at (PUB-2.59), so
/// the helpers that deposit into a doc 1 read it rather than assume it: the
/// claimant's doc 1 already holds the claim atom at 1, and every hire and
/// every walk's deposit advances the head by one.
pub fn next_content_ordinal(port: u16, token: Option<&str>, doc: &str) -> u64 {
    let v = op(port, token, &format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{doc}"}}"#));
    let set = expect_resp(&v, "span_set")["set"].as_array().expect("a span set");
    let width = set
        .iter()
        .find(|s| s["start"].as_str() == Some("1.1"))
        .and_then(|s| s["width"].as_str())
        .and_then(|w| w.rsplit('.').next())
        .map(|n| n.parse::<u64>().expect("an extent's width ends in its count"))
        .unwrap_or(0);
    width + 1
}

/// THE HIRE (AUTH-5.58, AUTH-2.62, AUTH-2.70): key a DELEGATED, keyless
/// principal so it can open a SIGNED session — what a write into a published
/// home needs on a claimed board (AUTH-3.79; `policy/plain.rs`'s RES-26
/// gate), a grant being one such write (PUB-5.8). The agent's GENESIS enrollment is
/// homed in its GENESIS REGISTRY — its DELEGATOR's doc 1; for a
/// bootstrap-delegated account, the CLAIMANT's doc 1 (AUTH-2.62) — written
/// from the delegator's SIGNED session as the one-atom verified deposit
/// (AUTH-5.4): the enroll atom of the agent's DEVICE-flagged public key
/// (device-flagged only, AUTH-5.63) inserted into the registry doc 1 at its
/// next free position, DECLARED under `T_ENROLL` (`deposit`, PUB-2.64), then
/// the `make_link` naming the atom, the agent's account and that same type. The fold's genesis arm latches
/// the set (AUTH-2.70); the agent then opens a signed session with `key`.
///
/// `registrar_signed` is the delegator's SIGNED session and `registrar_doc1`
/// that delegator's doc 1. A refused deposit is an AUTH finding, not a
/// fixture to bend: the panic names the verdict token.
///
/// THE RECORD IS SIGNED (signed ops, 2a): above the claim the daemon verifies
/// the record's own `sig` at the deposit's `make_link`, under the set that
/// opens the registry's account, so the atom is composed with the `sig` the
/// registrar's session key makes over the record frame ([`signed_atom`]) —
/// at the grade the act needs: the key that opened `registrar_signed` is the
/// one that signs, so the ANCHOR session a handoff needs (below) signs the
/// anchor-grade record too. Below the claim, with no `H.1`, the atom lands
/// bare, as the ceremony's own do.
///
/// THE HAND AT A HANDOFF (AUTH-3.21, AUTH-5.90) is the CALLER's to pass.
/// Keying a SUBDIVISION of the claimant's — `CLAIMANT.k`, its genesis homed
/// in the claimant's doc 1 — is no hire by the address test: it is the
/// claimant's HANDOFF, anchor-grade, the ceremony's set holding a paper
/// anchor ([`claim_board`]), and a caller that needs one passes the
/// claimant's ANCHOR session as `registrar_signed` (`register.rs` does).
/// Every deposit here runs from the session as given — nothing is routed
/// around the gate in silence — so the refusal a DEVICE session meets at
/// that cell is the caller's to meet or `auth_wire`'s to pin. Every other
/// hire is device-grade from the caller's own session: a top-level
/// account's genesis enters no cone, and a subdivision of a registrar this
/// helper keyed has a set holding no anchor.
pub fn hire(
    port: u16,
    registrar_signed: &str,
    registrar_doc1: &str,
    agent_account: &str,
    agent_id: u64,
    key: &SigningKey,
) -> String {
    let ordinal = next_content_ordinal(port, Some(registrar_signed), registrar_doc1);
    let atom = signed_atom(
        port,
        registrar_signed,
        registrar_doc1,
        T_ENROLL,
        &[agent_account],
        &enroll_atom(&[key]),
    );
    let v = op(
        port,
        Some(registrar_signed),
        &format!(
            r#"{{"op":"insert","doc":"{registrar_doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    assert_eq!(
        v["resp"].as_str(),
        Some("ack_addr"),
        "hire of {agent_id}: the enroll atom's deposit into {registrar_doc1}: {v}"
    );
    let atom_addr = acked_addr(&v);
    let v = op(
        port,
        Some(registrar_signed),
        &format!(
            r#"{{"op":"make_link","home":"{registrar_doc1}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{agent_account}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
        ),
    );
    assert_eq!(
        v["resp"].as_str(),
        Some("ack_addr"),
        "hire of {agent_id} ({agent_account}) refused by the fold — an AUTH finding: {v}"
    );
    open_signed_session(port, agent_id, key)
}

/// A BINDING's body in its canonical form (REG-1.86; `skep_registry`'s
/// encoder): the prefix in address form, and `replaces` where a later
/// binding names the link's address of the one it replaces.
pub fn binding_body(prefix: &str, replaces: Option<&str>) -> String {
    let address = |s: &str| skep_resolve::parse_address(s).expect("an address");
    skep_registry::encode(
        &skep_registry::Body::Binding(skep_registry::Binding {
            prefix: address(prefix),
            replaces: replaces.map(address),
        }),
        None,
    )
}

/// An ENDPOINT's body in its canonical form (REG-1.86): the org's origins
/// in its own order, and `replaces` where a later deposit names the link's
/// address of the one it replaces.
pub fn endpoint_body(origins: &[&str], replaces: Option<&str>) -> String {
    let origins = origins.iter().map(|o| o.to_string()).collect();
    skep_registry::encode(
        &skep_registry::Body::Endpoint(skep_registry::Endpoint {
            origins: skep_registry::Origins::new(origins).expect("at least one origin"),
            replaces: replaces.map(|s| skep_resolve::parse_address(s).expect("an address")),
        }),
        None,
    )
}

/// A REGISTRY RECORD DEPOSIT (REG-2.18, REG-2.19, REG-2.23; the record grade
/// for registry records): `body` — a binding's or an endpoint's canonical
/// text — SIGNED at the record grade under the key that opened `signed`
/// ([`signed_atom`]: the body's sig-less projection framed over `home`, `ty`
/// and `to`), inserted DECLARED under `ty` at `home`'s next free content
/// position, then the `make_link` typed `ty` from the atom's verified
/// I-address — the insert's own ack — to `to`: the account bound for a
/// binding, none for a targetless one or an endpoint. Answers `(the atom's
/// address, the link's answer)`, the link UNJUDGED so a refusal cell reads
/// its token; the insert is asserted, every refusal a cell pins being the
/// link's unless the cell lands the atom itself.
pub fn deposit_registry_record(
    port: u16,
    signed: &str,
    home: &str,
    ty: &str,
    to: &[&str],
    body: &str,
) -> (String, Value) {
    let atom = signed_atom(port, signed, home, ty, to, &json_atom(body));
    let ordinal = next_content_ordinal(port, Some(signed), home);
    let v = op(
        port,
        Some(signed),
        &format!(
            r#"{{"op":"insert","doc":"{home}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
        ),
    );
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the record atom's deposit into {home}: {v}");
    let atom_addr = acked_addr(&v);
    let link = op(port, Some(signed), &typed_link_frame(home, &[atom_addr.as_str()], to, ty));
    (atom_addr, link)
}

/// THE BINDING WRITE as the registrar's console makes it (REG-4.108; the
/// console's signed write under the registrar's account): `prefix` bound to
/// `to` — the node account, or none (REG-2.21's targetless binding) — from
/// the claimant's signed session into its own doc 1, `replaces` naming the
/// link a later binding replaces. The link's address.
pub fn deposit_binding(
    port: u16,
    signed: &str,
    prefix: &str,
    to: Option<&str>,
    replaces: Option<&str>,
) -> String {
    let to: Vec<&str> = to.into_iter().collect();
    let (_, v) = deposit_registry_record(
        port,
        signed,
        CLAIMANT_DOC1,
        T_BINDING,
        &to,
        &binding_body(prefix, replaces),
    );
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the binding of {prefix}: {v}");
    acked_addr(&v)
}

/// THE ENDPOINT DEPOSIT as the org makes it (REG-1.9): into `home`, the
/// org's node account's doc 1, from that account's own signed session,
/// targetless (REG-2.26's carriage), `replaces` naming the link a later
/// deposit replaces. The link's address.
pub fn deposit_endpoint(
    port: u16,
    signed: &str,
    home: &str,
    origins: &[&str],
    replaces: Option<&str>,
) -> String {
    let (_, v) = deposit_registry_record(
        port,
        signed,
        home,
        T_ENDPOINT,
        &[],
        &endpoint_body(origins, replaces),
    );
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the endpoint deposit into {home}: {v}");
    acked_addr(&v)
}

/// `frame` — a `make_link` — carrying its `replaces` member naming `replaces`
/// (PUB-5.15), signed by `token`'s key over the entry frame WITH the member
/// (`entry_body_make_link_replacing`, which the suite's signer spells where
/// the frame carries one) and attached — the frame [`op`] would post, held
/// as a string so a cell can replay it verbatim.
pub fn signed_with_replaces(port: u16, token: &str, frame: &str, replaces: &str) -> String {
    let mut v: Value = serde_json::from_str(frame).expect("a JSON frame");
    v["replaces"] = json!(replaces);
    attach_attest(port, token, &v.to_string())
}

/// The link address one past `link` in its home — where a `make_link`'s
/// `replaces` link lands, the two mints consecutive in one transaction.
pub fn next_link_address(link: &str) -> String {
    let (head, last) = link.rsplit_once('.').expect("a dotted address");
    format!("{head}.{}", last.parse::<u64>().expect("an ordinal") + 1)
}

/// A RE-SHARE — [`deposit_grant`]'s grant carrying its signed `replaces`
/// member naming `revocation`, the revocation it follows (PUB-5.15 (iv)).
/// Returns the grant link's address.
pub fn deposit_re_share(
    port: u16,
    signed: &str,
    home_doc1: &str,
    content_prefix: &str,
    grantee: Option<&str>,
    revocation: &str,
) -> String {
    let to: Vec<&str> = grantee.into_iter().collect();
    let frame = typed_link_frame(home_doc1, &[content_prefix], &to, T_GRANT);
    acked_addr(&op_as_written(
        port,
        Some(signed),
        &signed_with_replaces(port, signed, &frame, revocation),
    ))
}

/// A GRANT link in `home_doc1`, the issuer's published doc 1, from the
/// issuer's SIGNED session `signed` — a write into the published world:
/// `from` the content-prefix shared (a document, or an account — covering
/// every document under it, later mints included), `to` the grantee account,
/// or `None` for the ANY-PRINCIPAL form (`to: []`, PUB-5.8). Returns the
/// grant link's address.
pub fn deposit_grant(
    port: u16,
    signed: &str,
    home_doc1: &str,
    content_prefix: &str,
    grantee: Option<&str>,
) -> String {
    let to = match grantee {
        Some(g) => format!(r#"{{"addrs":["{g}"]}}"#),
        None => r#"{"addrs":[]}"#.to_string(),
    };
    acked_addr(&op(
        port,
        Some(signed),
        &format!(
            r#"{{"op":"make_link","home":"{home_doc1}","from":{{"addrs":["{content_prefix}"]}},"to":{to},"ty":{{"addrs":["{T_GRANT}"]}}}}"#
        ),
    ))
}

/// Spawn with the local-trust flag NAMED and the board left UNCLAIMED —
/// [`spawn`]'s first half, and the one way to reach ENFORCING, which is
/// `local_trust: false` plus a claim. The flag is fixed at open and the
/// claim is the only runtime transition into that mode, so a caller that
/// wants it runs the ceremony itself.
///
/// A claimed board's signed arm accepts ONLY the configured origins
/// (AUTH-4.3's claim-time drop), and a production claimed board is launched
/// with `--origin` naming what it is reachable at — so this spawn mirrors
/// that shape. Origins carry the port, and configuration happens at open,
/// before any listener exists: reserve an ephemeral port first, configure
/// the loopback origin the suites dial, then serve on the reserved port.
pub fn spawn_configured(dir: &Path, local_trust: bool) -> Skepd {
    spawn_with_blocked_prefixes(dir, local_trust, None, None)
}

/// [`spawn_configured`] with the BLOCKED-PREFIX LIST's supply named — the
/// library's face of `--blocked-prefixes <FILE>` (AUTH-4.70) — and the
/// board's NODE PREFIX, the face of `--node-prefix 1.N` (REG-1.69), which
/// the list's off-board test reads. The file is read at THIS open, as at
/// every start, so it must already hold an issue ([`issue_blocked_list`]);
/// the same helper re-issues it while the daemon runs. `None, None` is the
/// daemon every other suite spawns: no supply, no list, no prefix.
pub fn spawn_with_blocked_prefixes(
    dir: &Path,
    local_trust: bool,
    blocked_prefixes: Option<&Path>,
    node_prefix: Option<&str>,
) -> Skepd {
    spawn_under(
        dir,
        local_trust,
        blocked_prefixes,
        node_prefix,
        None,
        ALLOW_PREVIEW_KEYS_IN_FIXTURES,
    )
}

/// THE FIXTURES RUN WITH `allow_preview_keys` ON (AUTH-1.44: "the test
/// fixtures run with it on"): every spawn here admits the enrollment of a
/// TAG-3 preview key, so the tag-3 cells — the goldens' row, a tag-3 session,
/// the all-halves decode — can enrol one. The ONE spawn that runs a served
/// board's setting, OFF, is [`spawn_refusing_preview_keys`].
pub const ALLOW_PREVIEW_KEYS_IN_FIXTURES: bool = true;

/// [`spawn`] with `allow_preview_keys` OFF — a served board's own setting
/// (the default; `skepd` launched without `--allow-preview-keys`): the daemon
/// REFUSES ENROLLMENT of a tag-3 key as `preview_key` (AUTH-3.56, slot (4)'s
/// first token), a genesis included. The board is claimed as [`spawn`]'s is;
/// the ceremony's own keys are tag 1 and meet no refusal.
pub fn spawn_refusing_preview_keys(dir: &Path) -> Skepd {
    let sd = spawn_under(dir, true, None, None, None, false);
    claim_board(sd.port());
    sd
}

/// [`spawn_with_blocked_prefixes`] with the kernel's SALT SOURCE named:
/// `None` is the production door (`Daemon::open_with`, OS entropy per
/// transaction — every other spawn here), `Some(seed)` the test seam
/// (`Daemon::open_seeded`, the seeded stream), which the head suite's
/// determinism pins need: two daemons over one op sequence write one chain
/// only under one seed — and the preview-key setting named (AUTH-1.44). The
/// retry loop below is the same either way.
fn spawn_under(
    dir: &Path,
    local_trust: bool,
    blocked_prefixes: Option<&Path>,
    node_prefix: Option<&str>,
    salt_seed: Option<u64>,
    allow_preview_keys: bool,
) -> Skepd {
    let node_prefix = node_prefix
        .map(|text| text.parse::<NodePrefix>().unwrap_or_else(|e| panic!("'{text}' is {e}")));
    // The reservation is held through the slow open, so only the rebind gap
    // races — and under this suite it DOES: every exchange is one
    // connection, a run leaves some thirty thousand sockets in TIME_WAIT
    // against an ephemeral range of 16 384, and with the range that full a
    // port released here is one of the few free, so the next `connect`
    // anywhere in the process is handed it. A lost race is `AddrInUse` on
    // the rebind, and costs one more attempt on a fresh port: `serve`
    // dropped the daemon with its error, so the data dir is free to reopen
    // (recovery is idempotent), and the origin is rebuilt because it names
    // the port. Bounded, so a port that can never be bound still fails loudly.
    //
    // The SECOND race, on the same loop and the same budget: the retry
    // reopens the SAME data dir, and the kernel's journal-directory flock
    // from the attempt just dropped is not always re-acquirable the instant
    // `close` returns under the parallel suite's load — a transient
    // `WouldBlock` at open ([`open_lost_the_lock_race`]). It is not a bad
    // data dir (a fresh tempdir, or one this helper itself just held), so it
    // is retried with a brief backoff to let the release land, bounded the
    // same way; any OTHER open error is a real fault and panics at once.
    const ATTEMPTS: usize = 12;
    let mut last_lock_err = None;
    for _ in 0..ATTEMPTS {
        let reserved = TcpListener::bind(("127.0.0.1", 0)).expect("reserve an ephemeral port");
        let port = reserved.local_addr().expect("reserved local addr").port();
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}"))
            .expect("a canonical loopback origin");
        let mut opts = AuthOptions::default();
        opts.local_trust = local_trust;
        opts.configured = vec![origin];
        opts.blocked_supply_path = blocked_prefixes.map(Path::to_path_buf);
        opts.node_prefix = node_prefix.clone();
        opts.allow_preview_keys = allow_preview_keys;
        let opened = match salt_seed {
            None => Daemon::open_with(dir, opts),
            Some(seed) => Daemon::open_seeded(dir, opts, seed),
        };
        let daemon = match opened {
            Ok(daemon) => daemon,
            Err(e) if open_lost_the_lock_race(&e) => {
                last_lock_err = Some(e.to_string());
                drop(reserved);
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(e) => panic!("daemon open (genesis or recover) at {}: {e}", dir.display()),
        };
        drop(reserved);
        match serve(daemon, port, DEFAULT_WORKERS) {
            Ok(sd) => {
                forget_port(sd.port());
                wait_for_the_index(&sd);
                return sd;
            }
            Err(e) if e.kind() == ErrorKind::AddrInUse => continue,
            Err(e) => panic!("bind the reserved port: {e}"),
        }
    }
    panic!(
        "spawn: lost the rebind or journal-lock race {ATTEMPTS} times running \
         (last lock error: {last_lock_err:?})"
    )
}

/// THE CELL INDEX's WALK AT OPEN runs on a thread of the daemon's, and its
/// three readers — the PUT's creation and resume, the deposit read — refuse
/// `index_rebuilding` until it completes (wire.md §Media). Every spawn here
/// waits for it, bounded, so a suite's first PUT never races the walk; the
/// suites that drive the walk's window arm the hold first and spawn through
/// [`spawn_walk_held`], which does not wait.
fn wait_for_the_index(sd: &Skepd) {
    if walk_is_held() {
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while !sd.daemon().index_is_ready() {
        assert!(Instant::now() < deadline, "the cell index's walk did not complete within 60 s");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Whether this process has asked its spawns NOT to wait for the index —
/// the walk's hold armed ([`spawn_walk_held`]) or the open-cost measure's
/// own clock running ([`spawn_not_waiting_for_the_index`]).
fn walk_is_held() -> bool {
    *WALK_HELD.lock().expect("the hold's flag")
}

static WALK_HELD: Mutex<bool> = Mutex::new(false);

/// Spawn a daemon WITH THE CELL INDEX's WALK HELD — armed before the open,
/// so the daemon serves with its index not ready until
/// [`release_the_walk`] — and claim its board (the claim is a text write,
/// served throughout). Readiness is never waited on here.
pub fn spawn_walk_held(dir: &Path) -> Skepd {
    *WALK_HELD.lock().expect("the hold's flag") = true;
    Daemon::hold_the_index_walk();
    let sd = spawn_configured(dir, true);
    claim_board(sd.port());
    sd
}

/// Release the held walk and wait for `sd`'s index to ready.
pub fn release_the_walk(sd: &Skepd) {
    *WALK_HELD.lock().expect("the hold's flag") = false;
    Daemon::release_the_index_walk();
    wait_for_the_index(sd);
}

/// [`spawn_configured`] on a board already claimed, returning the moment
/// the daemon serves and NOT waiting for the index's walk — the open-cost
/// measure's spawn, whose clock runs from the open's return to the first
/// PUT the gate admits.
pub fn spawn_not_waiting_for_the_index(dir: &Path) -> Skepd {
    *WALK_HELD.lock().expect("the hold's flag") = true;
    let sd = spawn_configured(dir, true);
    *WALK_HELD.lock().expect("the hold's flag") = false;
    sd
}

/// Does this `Daemon::open_with` failure carry a transient journal-directory
/// LOCK contention — the flock from the attempt just dropped not yet
/// re-acquirable — rather than a real fault? Walks the error's `source`
/// chain for an [`std::io::Error`] of kind [`ErrorKind::WouldBlock`], which
/// `Kernel::open` surfaces from `flock(LOCK_EX | LOCK_NB)` (`OpenError::Io`).
/// Only that one kind is retried; a bad checkpoint, a corrupt journal or any
/// other I/O failure is a real condition and stops the spawn loudly.
fn open_lost_the_lock_race(err: &skepd::DaemonError) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = source {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            return io.kind() == ErrorKind::WouldBlock;
        }
        source = e.source();
    }
    false
}

/// The list's two-field HEADER as a suite names it: the configured operator
/// account and the board's binding-writing account, each optional — `None`
/// is "the header names none", and the claimant is then the comparand
/// (AUTH-4.36 step 4b).
#[derive(Clone, Copy, Default)]
pub struct BlockedHeader<'a> {
    pub operator: Option<&'a str>,
    pub binding_writer: Option<&'a str>,
}

/// ISSUE the blocked-prefix list at `path` — the operator's act, and
/// the SAME act at the start-up supply and at every reissue: the whole list,
/// `entries` as `(prefix, the takedown record's version address)`, written
/// BESIDE the file and renamed OVER it. The atomic replace is the channel's
/// own obligation (`BlockedSupply`): no reader meets a torn issue, and each
/// issue is a new file, which is what the daemon's look at the next request
/// keys on. An empty `entries` is the explicit empty list — the LIFT of
/// everything.
pub fn issue_blocked_list(path: &Path, header: BlockedHeader<'_>, entries: &[(&str, &str)]) {
    let mut list = serde_json::Map::new();
    if let Some(operator) = header.operator {
        list.insert("operator".into(), Value::String(operator.into()));
    }
    if let Some(binding_writer) = header.binding_writer {
        list.insert("binding_writer".into(), Value::String(binding_writer.into()));
    }
    let entries: Vec<Value> = entries
        .iter()
        .map(|(prefix, record)| json!({"prefix": prefix, "record": record}))
        .collect();
    list.insert("entries".into(), Value::Array(entries));
    issue_blocked_list_bytes(path, Value::Object(list).to_string().as_bytes());
}

/// [`issue_blocked_list`] over bytes written VERBATIM — the refusal cells'
/// door: an issue that is not a list arrives by the same atomic replace a
/// good one does.
pub fn issue_blocked_list_bytes(path: &Path, bytes: &[u8]) {
    let beside = path.with_extension("next");
    std::fs::write(&beside, bytes).expect("write the issue beside the list");
    std::fs::rename(&beside, path).expect("rename the issue over the list");
}

/// Spawn a daemon and CLAIM its board: under the pre-claim admission gate
/// (RES-27) an unclaimed daemon runs nothing but the ceremony, so every
/// suite about ordinary op semantics runs post-claim (CLAIMED-PERMISSIVE —
/// local trust stays the default, so the suites' bare sessions still bind).
/// The board this returns has its `H.1`, written by the claim's own step
/// ([`claim_board`]; signed ops, s1) — the board term every attested write's
/// frame names (D13) — so it admits an attested write at once; a suite that
/// needs a LATER head drives the cadence through the daemon's clock seam.
pub fn spawn(dir: &Path) -> Skepd {
    let sd = spawn_configured(dir, true);
    claim_board(sd.port());
    sd
}

/// [`spawn`] under the SEEDED salt source (`Daemon::open_seeded`, the test
/// seam): every transaction's salt is `SHA-256(seed ‖ position)`, so two
/// boards spawned here under one seed and driven through one op sequence
/// write one journal, one chain and one head byte string, and under two
/// seeds two of each. The head suite's determinism pins are its only
/// callers; every other suite spawns the production door, whose OS-drawn
/// salts make every board's chain its own.
pub fn spawn_seeded(dir: &Path, seed: u64) -> Skepd {
    let sd = spawn_under(dir, true, None, None, Some(seed), ALLOW_PREVIEW_KEYS_IN_FIXTURES);
    claim_board(sd.port());
    sd
}

/// [`spawn`] with the UPLOAD SETTING CLOSED — `--no-uploads` (wire.md
/// §Media, THE UPLOAD SETTING): the board claimed, every other option the
/// fixtures' default; the creation and the resume answer `uploads_closed`
/// before any body byte, `/health` echoes `media.uploads` false.
pub fn spawn_uploads_closed(dir: &Path) -> Skepd {
    let mut opts = AuthOptions::default();
    opts.allow_preview_keys = ALLOW_PREVIEW_KEYS_IN_FIXTURES;
    let mut media = MediaOptions::default();
    media.uploads = false;
    let daemon = Daemon::open_configured(dir, opts, media).expect("daemon open (genesis or recover)");
    let sd = serve(daemon, 0, DEFAULT_WORKERS).expect("bind an ephemeral port");
    forget_port(sd.port());
    wait_for_the_index(&sd);
    claim_board(sd.port());
    sd
}

/// Spawn without claiming — the AUTH suites drive the window itself. The
/// fixtures' preview-key setting is on here as everywhere (AUTH-1.44); every
/// other option is the default's.
pub fn spawn_unclaimed(dir: &Path) -> Skepd {
    let mut opts = AuthOptions::default();
    opts.allow_preview_keys = ALLOW_PREVIEW_KEYS_IN_FIXTURES;
    let daemon = Daemon::open_with(dir, opts).expect("daemon open (genesis or recover)");
    let sd = serve(daemon, 0, DEFAULT_WORKERS).expect("bind an ephemeral port");
    forget_port(sd.port());
    wait_for_the_index(&sd);
    sd
}

/// Client-side socket timeout: a daemon that wedges must fail the exchange
/// loudly (panic with context) rather than hang the whole gate, whose log
/// would then carry no failure name at all. Generous — a healthy op is
/// milliseconds even under fsync.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// One HTTP exchange; returns (status, headers, body bytes).
pub fn http_full(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let ctx = |what: &str| format!("{what} ({method} {path})");
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("{}: {e}", ctx("connect to skepd")));
    stream.set_read_timeout(Some(HTTP_TIMEOUT)).expect("read timeout");
    stream.set_write_timeout(Some(HTTP_TIMEOUT)).expect("write timeout");
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(tok) = token {
        head.push_str(&format!("Skepd-Session: {tok}\r\n"));
    }
    head.push_str("Content-Type: application/json\r\n\r\n");
    stream
        .write_all(head.as_bytes())
        .unwrap_or_else(|e| panic!("{}: {e}", ctx("write request head")));
    stream.write_all(body).unwrap_or_else(|e| panic!("{}: {e}", ctx("write request body")));
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap_or_else(|e| panic!("{}: {e}", ctx("read response")));
    parse_response(&raw, &ctx("response"))
}

/// Parse one HTTP response's bytes into (status, headers, body) — the one
/// response reader these tests use, so [`http_full`] and [`raw_exchange`]
/// cannot disagree about what a header is.
pub fn parse_response(raw: &[u8], ctx: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| {
        panic!("{ctx}: no header/body separator: {:?}", String::from_utf8_lossy(raw))
    });
    let head = std::str::from_utf8(&raw[..sep]).expect("ascii response head");
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .expect("status line")
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("{ctx}: no status code in {head:?}"))
        .parse()
        .unwrap_or_else(|_| panic!("{ctx}: non-numeric status in {head:?}"));
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, headers, raw[sep + 4..].to_vec())
}

/// One exchange whose request bytes are written VERBATIM — the transport
/// itself is what these callers test, so nothing here builds a head for
/// them. Half-closes the write side (the daemon sees EOF and cannot wait on
/// a body that will never arrive), then reads to close.
///
/// Write errors are deliberately ignored: the daemon may already have
/// answered and closed (an oversized declared length, a refused method)
/// while we were still writing. The response is the judge.
pub fn raw_exchange(port: u16, raw: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let bytes = skepd::fuzz_support::http_raw_exchange(port, raw)
        .unwrap_or_else(|e| panic!("connect to skepd: {e}"));
    assert!(
        !bytes.is_empty(),
        "the daemon closed without answering: {:?}",
        String::from_utf8_lossy(raw)
    );
    parse_response(&bytes, "raw exchange")
}

/// One exchange carrying an `Origin` header — the one request header this
/// suite otherwise never sends, and the one the bare-bind rule reads
/// (wire.md §Sessions). Written verbatim through [`raw_exchange`], so
/// [`http_full`]'s signature stays as it is.
pub fn http_with_origin(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    origin: &str,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Origin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(tok) = token {
        head.push_str(&format!("Skepd-Session: {tok}\r\n"));
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    raw_exchange(port, &bytes)
}

/// One HTTP exchange; returns (status, body bytes).
pub fn http(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let (status, _headers, body) = http_full(port, method, path, token, body);
    (status, body)
}

/// Case-insensitive response-header lookup.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

pub fn options(port: u16, path: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    http_full(port, "OPTIONS", path, None, b"")
}

pub fn get(port: u16, path: &str) -> (u16, Vec<u8>) {
    http(port, "GET", path, None, b"")
}

pub fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes)
        .unwrap_or_else(|e| panic!("non-JSON body ({e}): {}", String::from_utf8_lossy(bytes)))
}

pub fn open_session(port: u16, principal: u64) -> String {
    let body = format!("{{\"principal\":{principal}}}");
    let (st, resp) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 200, "session open failed: {}", String::from_utf8_lossy(&resp));
    json(&resp)["session"].as_str().expect("session token").to_string()
}

/// POST one op frame; transport must succeed (200) — the returned document
/// may still be a rejection, which callers assert on.
///
/// THE TEST SIGNER SITS HERE (signed ops; the placement investigation §4.3):
/// where `token` is a session a seed carrier opened ([`register_signer`])
/// and the frame's op is one of the checked set's three — `insert`,
/// `make_link`, `publish` — the frame is sent with its `attest` member
/// composed and signed by that seed's hybrid key ([`attach_attest`]);
/// every other frame, and every frame under a bare or foreign token, is
/// sent as written. A cell that must send a WRONG or ABSENT `attest`, or one
/// it signed itself, posts through [`op_as_written`] or [`http`] directly, as
/// the refusal cells do.
pub fn op(port: u16, token: Option<&str>, frame: &str) -> Value {
    let frame = match token {
        Some(t) => attach_attest(port, t, frame),
        None => frame.to_string(),
    };
    op_as_written(port, token, &frame)
}

/// [`op`] with the frame sent AS WRITTEN — no `attest` attached beyond what
/// the caller composed, whatever the token: a member it signed by hand, a
/// broken one, or none at all. The refusal cells' door, and every cell that
/// signs its own frame.
pub fn op_as_written(port: u16, token: Option<&str>, frame: &str) -> Value {
    let (st, body) = http(port, "POST", "/op", token, frame.as_bytes());
    assert_eq!(st, 200, "op transport failed: {}", String::from_utf8_lossy(&body));
    json(&body)
}

/// Assert the response shape and hand the document back for field checks.
pub fn expect_resp<'a>(v: &'a Value, shape: &str) -> &'a Value {
    assert_eq!(v["resp"].as_str(), Some(shape), "unexpected response: {v}");
    v
}

/// The minted address of an ack_addr response.
pub fn acked_addr(v: &Value) -> String {
    expect_resp(v, "ack_addr")["addr"].as_str().expect("ack_addr carries addr").to_string()
}

/// The deadline every stream assertion runs under — generous for CI; the
/// daemon's own delivery is notification-driven (well under the wire's
/// ~250 ms bound).
const SSE_DEADLINE: Duration = Duration::from_secs(5);

/// The deadline a keepalive assertion runs under. The daemon's cadence is
/// 15 s of silence (wire.md §The commit stream), so this necessarily waits
/// past it — generous, since arriving late is still arriving.
const SSE_KEEPALIVE_DEADLINE: Duration = Duration::from_secs(40);

/// A raw `GET /events` subscriber: reads the SSE framing off the socket,
/// skipping `:ka` keepalive comments.
pub struct Sse {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Sse {
    pub fn connect(port: u16) -> Sse {
        Sse::open(port, None).0
    }

    /// [`Sse::connect`] presenting a token, with the stream HEAD handed
    /// back: `/events` is the one route whose death signal rides a stream
    /// head rather than a reply (wire.md §Sessions), written once, at open.
    pub fn connect_with_token(port: u16, token: &str) -> (Sse, String) {
        Sse::open(port, Some(token))
    }

    fn open(port: u16, token: Option<&str>) -> (Sse, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect /events");
        stream.set_read_timeout(Some(Duration::from_millis(100))).expect("read timeout");
        let mut req = String::from(
            "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n",
        );
        if let Some(tok) = token {
            req.push_str(&format!("Skepd-Session: {tok}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).expect("write /events request");
        let mut sse = Sse { stream, buf: Vec::new() };
        let head = sse.read_until(b"\r\n\r\n");
        let head = String::from_utf8(head).expect("ascii stream head");
        assert!(head.starts_with("HTTP/1.1 200 "), "the event stream must open 200: {head}");
        let lower = head.to_ascii_lowercase();
        assert!(
            lower.contains("content-type: text/event-stream"),
            "the event stream is text/event-stream: {head}"
        );
        assert!(
            lower.contains("access-control-allow-origin: *"),
            "the event stream carries the CORS header: {head}"
        );
        assert!(
            lower.contains("access-control-expose-headers: skepd-session"),
            "the stream head exposes the death signal it may carry — without \
             it a page on a configured origin cannot read `Skepd-Session: \
             closed` and sees a dead token behave as a silent guest: {head}"
        );
        assert!(
            lower.contains("connection: close"),
            "the event stream declares Connection: close (wire.md §Transport): {head}"
        );
        assert!(
            lower.contains("cache-control: no-cache"),
            "the event stream forbids caching — an intermediary that buffers it \
             delivers nothing until close, so the stream looks dead while the \
             daemon is healthy: {head}"
        );
        (sse, head)
    }

    /// Read (appending to the persistent buffer) until `delim`; returns the
    /// bytes before it and consumes through it.
    fn read_until(&mut self, delim: &[u8]) -> Vec<u8> {
        self.read_until_within(delim, SSE_DEADLINE)
    }

    /// [`Sse::read_until`] under a caller-chosen deadline — the keepalive
    /// assertion necessarily waits longer than a commit ever should.
    fn read_until_within(&mut self, delim: &[u8], within: Duration) -> Vec<u8> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(i) = self.buf.windows(delim.len()).position(|w| w == delim) {
                let mut taken: Vec<u8> = self.buf.drain(..i + delim.len()).collect();
                taken.truncate(i);
                return taken;
            }
            assert!(
                Instant::now() < deadline,
                "no stream data within {within:?}; buffered: {:?}",
                String::from_utf8_lossy(&self.buf)
            );
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => panic!(
                    "stream closed while waiting; buffered: {:?}",
                    String::from_utf8_lossy(&self.buf)
                ),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) => panic!("read /events: {e}"),
            }
        }
    }

    /// The next event's `log_position`, asserting the `commit` framing;
    /// keepalive comment blocks are skipped.
    pub fn expect_commit(&mut self) -> u64 {
        loop {
            let block = self.read_until(b"\n\n");
            let text = String::from_utf8(block).expect("utf-8 event block");
            if text.trim_start().starts_with(':') {
                continue;
            }
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 2, "one event line + one data line: {text:?}");
            assert_eq!(lines[0], "event: commit", "event name: {text:?}");
            let data = lines[1].strip_prefix("data: ").expect("data line");
            let v: Value = serde_json::from_str(data).expect("event data is JSON");
            let obj = v.as_object().expect("event data object");
            assert_eq!(obj.len(), 1, "v1 payload is the position alone: {data}");
            return obj["log_position"].as_u64().expect("log_position number");
        }
    }

    /// The documented keepalive (wire.md §The commit stream): after each
    /// silent interval the daemon writes the comment line `:ka` and a blank
    /// line, which is how a client tells a live stream from a dead peer.
    /// Necessarily slow — it waits out the daemon's 15 s cadence.
    pub fn expect_keepalive(&mut self) {
        let block = self.read_until_within(b"\n\n", SSE_KEEPALIVE_DEADLINE);
        let text = String::from_utf8(block).expect("utf-8 stream block");
        assert_eq!(text, ":ka", "a silent stream's next block is the documented keepalive");
    }

    /// Assert the daemon closes the stream (draining any trailing events).
    pub fn expect_eof(&mut self) {
        let deadline = Instant::now() + SSE_DEADLINE;
        loop {
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => return,
                // Reset counts as closed: the daemon is gone either way.
                Err(e)
                    if e.kind() == ErrorKind::ConnectionReset
                        || e.kind() == ErrorKind::BrokenPipe =>
                {
                    return
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) => panic!("read at stream end: {e}"),
            }
            assert!(Instant::now() < deadline, "stream not closed within {SSE_DEADLINE:?}");
        }
    }
}

// ── the blob upload (media lane B; wire.md §Media) ───────────────────────

/// The blob upload's path family, as wire.md §Media pins it.
pub const BLOB_UPLOAD: &str = "/blob/upload";

/// BLAKE3 of `bytes` as the 64 lowercase hex the PUT answers — the suites'
/// OWN hash, judged against the daemon's and never adopted from it (Q-sm2).
pub fn blob_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// `n` seeded pseudo-random bytes (SplitMix64), so a suite sends a large
/// body it never has to store in a fixture and two suites agree on it.
pub fn seeded_bytes(n: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
    while out.len() < n {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let take = (n - out.len()).min(8);
        out.extend_from_slice(&z.to_le_bytes()[..take]);
    }
    out
}

/// One exchange of the blob family: the request written WHOLE, every
/// write error ignored — the daemon refuses a creation on its declared
/// total, and ends a refused upload mid-body, BEFORE it has read the body,
/// and closes, so a client still writing meets a broken pipe, which is
/// the refusal working — then the answer read to any end. Unlike
/// [`http_full`], which panics on a write the daemon declined to read;
/// unlike [`raw_exchange`], under deadlines a body at the cap and its
/// finish's fsyncs fit. THE RETRY-CLASS REFUSAL IS RETRIED: an
/// `index_rebuilding` answer — the cell index's walk at open unfinished —
/// is what a client retries, and this helper does, bounded; a suite that
/// wants to SEE that answer sends through [`blob_exchange_once`].
pub fn blob_exchange(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let answer = blob_exchange_once(port, method, path, token, body);
        if answer.0 != 503 || !String::from_utf8_lossy(&answer.2).contains("\"index_rebuilding\"") {
            return answer;
        }
        assert!(Instant::now() < deadline, "{method} {path}: index_rebuilding for 60 s");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// [`blob_exchange`] sent ONCE — the answer as given, a retry-class refusal
/// included.
pub fn blob_exchange_once(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let ctx = format!("{method} {path}");
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("{ctx}: connect to skepd: {e}"));
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(Duration::from_secs(120))).expect("read timeout");
    stream.set_write_timeout(Some(Duration::from_secs(120))).expect("write timeout");
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(tok) = token {
        head.push_str(&format!("Skepd-Session: {tok}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            // A reset after the answer (the daemon closed with our body
            // unread) ends the read as EOF does; the bytes before it are
            // the answer.
            Err(_) => break,
        }
    }
    assert!(!raw.is_empty(), "{ctx}: the daemon closed without answering");
    parse_response(&raw, &ctx)
}

/// THE CREATION: `POST /blob/upload?length=<length>` with `body` — empty
/// for the two-step shape, the first bytes (or all of them) for the
/// creation-with-upload. Answers the exchange whole.
pub fn blob_create(
    port: u16,
    token: Option<&str>,
    length: u64,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    blob_exchange(port, "POST", &format!("{BLOB_UPLOAD}?length={length}"), token, body)
}

/// THE RESUME: `PATCH /blob/upload/<id>?offset=<offset>` with `body`.
pub fn blob_append(
    port: u16,
    token: Option<&str>,
    id: &str,
    offset: u64,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    blob_exchange(port, "PATCH", &format!("{BLOB_UPLOAD}/{id}?offset={offset}"), token, body)
}

/// THE PROGRESS: `GET /blob/upload/<id>`.
pub fn blob_progress(
    port: u16,
    token: Option<&str>,
    id: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    blob_exchange(port, "GET", &format!("{BLOB_UPLOAD}/{id}"), token, b"")
}

/// THE DEPOSIT READ: `GET /blob/upload`.
pub fn blob_read(port: u16, token: Option<&str>) -> (u16, Vec<(String, String)>, Vec<u8>) {
    blob_exchange(port, "GET", BLOB_UPLOAD, token, b"")
}

/// THE END: `DELETE /blob/upload/<id>`.
pub fn blob_end(port: u16, token: Option<&str>, id: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    blob_exchange(port, "DELETE", &format!("{BLOB_UPLOAD}/{id}"), token, b"")
}

/// One whole PUT — the creation-with-upload of `bytes` in one request —
/// asserting the finish and judging the daemon's hash against the suite's
/// own. Answers the finish's body.
pub fn put_whole(port: u16, token: &str, bytes: &[u8]) -> Value {
    let (st, _, body) = blob_create(port, Some(token), bytes.len() as u64, bytes);
    assert_eq!(st, 200, "the PUT: {}", String::from_utf8_lossy(&body));
    let v = json(&body);
    assert_eq!(
        v["hash"].as_str(),
        Some(blob_hex(bytes).as_str()),
        "the daemon's hash is the suite's own: {v}"
    );
    assert_eq!(v["size"].as_u64(), Some(bytes.len() as u64));
    assert_eq!(v["designation"].as_str(), Some("blake3"));
    v
}

/// The deposits a principal's read lists, as `(hash, size, lapsed)`.
pub fn deposits_of(port: u16, token: &str) -> Vec<(String, u64, bool)> {
    let (st, _, body) = blob_read(port, Some(token));
    assert_eq!(st, 200, "the deposit read: {}", String::from_utf8_lossy(&body));
    json(&body)["deposits"]
        .as_array()
        .expect("deposits")
        .iter()
        .map(|d| {
            (
                d["hash"].as_str().expect("hash").to_string(),
                d["size"].as_u64().expect("size"),
                d["lapsed"].as_bool().expect("lapsed"),
            )
        })
        .collect()
}

/// The canonical cell of `bytes` at `size` — the form the daemon's parser
/// admits (wire.md §Media), the hash the suite's own.
pub fn cell_of(bytes: &[u8], size: u64) -> String {
    format!(r#"{{"type":"1.1.0.1.0.1.0.3.89","hash":"{}","size":{size}}}"#, blob_hex(bytes))
}

/// Insert the cell of `bytes` into `draft` at ordinal 1 and answer the
/// verdict (`ok`, or `credential_refused:<token>`).
pub fn insert_cell(port: u16, token: &str, draft: &str, bytes: &[u8], size: u64) -> String {
    let frame = json!({
        "op": "insert",
        "doc": draft,
        "at": {"subspace": "1", "ordinal": "1"},
        "values": [{"atom": cell_of(bytes, size)}],
    })
    .to_string();
    verdict(&op(port, Some(token), &frame))
}

// ── the blob fetch and the blind cell (media lane D; wire.md §Media) ─────

/// The blob fetch's path, as wire.md §Media pins it: `GET /blob?i=<address>`.
pub const BLOB_FETCH: &str = "/blob";

/// The blind document's kind, INTERIM (wire.md §Media), as the fixture
/// `fixtures/media/blind-cells.json` pins it.
pub const BLIND_KIND: &str = "1.1.0.1.0.1.0.3.88";

/// The canonical blind cell over `commitment` — 32 bytes as 64 lowercase
/// hex — the one form the daemon's parser admits: a `type` and a
/// `commitment`, and nothing the board can read a file by.
pub fn blind_cell_of(commitment: &[u8; 32]) -> String {
    format!(r#"{{"type":"{BLIND_KIND}","commitment":"{}"}}"#, hex(commitment))
}

/// An `insert` of ONE composite value `text` into `doc` at `ordinal` — the
/// write a cell of either kind rides.
pub fn atom_frame(doc: &str, ordinal: u64, text: &str) -> String {
    json!({
        "op": "insert",
        "doc": doc,
        "at": {"subspace": "1", "ordinal": ordinal.to_string()},
        "values": [{"atom": text}],
    })
    .to_string()
}

/// How a fetch's connection ended, as the client saw it: the daemon's
/// clean close, a RESET (the mid-stream refusal, the idle or transfer
/// bound), or the client's own read deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    Eof,
    Reset,
    Timeout,
}

/// The request line and head of one fetch — `GET` or `HEAD` of `/blob?i=`
/// as `token`, with `extra` headers written verbatim (a `Range`, an
/// `If-None-Match`, a second token).
fn fetch_request(head: bool, token: Option<&str>, i: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let method = if head { "HEAD" } else { "GET" };
    let mut req =
        format!("{method} {BLOB_FETCH}?i={i} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some(tok) = token {
        req.push_str(&format!("Skepd-Session: {tok}\r\n"));
    }
    for (name, value) in extra {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    req.into_bytes()
}

/// One fetch exchange, whole: the status, the headers and the body, read to
/// the connection's end — a reset after the answer ends the read as EOF
/// does. `head` sends the `HEAD`.
pub fn fetch_full(
    port: u16,
    head: bool,
    token: Option<&str>,
    i: &str,
    extra: &[(&str, &str)],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let (raw, _) = fetch_bytes(port, &fetch_request(head, token, i, extra));
    assert!(
        !raw.is_empty(),
        "{} {BLOB_FETCH}?i={i}: the daemon closed without answering",
        if head { "HEAD" } else { "GET" }
    );
    parse_response(&raw, &format!("{} {BLOB_FETCH}?i={i}", if head { "HEAD" } else { "GET" }))
}

/// `GET /blob?i=<i>` as `token`.
pub fn fetch(port: u16, token: Option<&str>, i: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    fetch_full(port, false, token, i, &[])
}

/// `HEAD /blob?i=<i>` as `token`.
pub fn fetch_head(
    port: u16,
    token: Option<&str>,
    i: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    fetch_full(port, true, token, i, &[])
}

/// Write `raw` and read to the connection's end under a bounded deadline:
/// the bytes received and how it ended.
pub fn fetch_bytes(port: u16, raw: &[u8]) -> (Vec<u8>, StreamEnd) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to skepd");
    stream.set_read_timeout(Some(Duration::from_secs(60))).expect("read timeout");
    stream.set_write_timeout(Some(Duration::from_secs(60))).expect("write timeout");
    stream.write_all(raw).expect("write the fetch");
    let mut out = Vec::new();
    let end = read_to_stream_end(&mut stream, &mut out);
    (out, end)
}

/// Read `stream` to its end into `out`: how it ended.
fn read_to_stream_end(stream: &mut TcpStream, out: &mut Vec<u8>) -> StreamEnd {
    let mut chunk = [0u8; 65536];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return StreamEnd::Eof,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted
                ) =>
            {
                return StreamEnd::Reset
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return StreamEnd::Timeout
            }
            Err(e) => panic!("read the fetch: {e}"),
        }
    }
}

/// A fetch read LAZILY, so a suite can act while the stream stands — the
/// daemon's stream parked at its hold between two chunks — and then read
/// it to its end and judge how it ended.
pub struct FetchStream {
    stream: TcpStream,
    /// Every byte received so far, the head included.
    pub raw: Vec<u8>,
}

impl FetchStream {
    /// Open the connection and send `GET /blob?i=<i>` as `token`; nothing
    /// is read yet.
    pub fn open(port: u16, token: Option<&str>, i: &str) -> FetchStream {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to skepd");
        stream.set_write_timeout(Some(Duration::from_secs(30))).expect("write timeout");
        stream.write_all(&fetch_request(false, token, i, &[])).expect("write the fetch");
        FetchStream { stream, raw: Vec::new() }
    }

    /// The byte offset of the body: one past the head's terminator, where
    /// the head has arrived.
    fn body_at(&self) -> Option<usize> {
        self.raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
    }

    /// Read until the head and at least `body_bytes` of the body have
    /// arrived, within `within`.
    pub fn read_until_body(&mut self, body_bytes: usize, within: Duration) {
        let deadline = Instant::now() + within;
        self.stream.set_read_timeout(Some(Duration::from_millis(100))).expect("read timeout");
        loop {
            if self.body_at().is_some_and(|at| self.raw.len() - at >= body_bytes) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "no head and {body_bytes} body bytes within {within:?}; received {} bytes",
                self.raw.len()
            );
            let mut chunk = [0u8; 65536];
            match self.stream.read(&mut chunk) {
                Ok(0) => panic!(
                    "the stream closed before {body_bytes} body bytes; received {}",
                    self.raw.len()
                ),
                Ok(n) => self.raw.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => panic!("read the fetch: {e}"),
            }
        }
    }

    /// Read to the connection's end: how it ended. The deadline is short —
    /// a reset or a clean close lands in well under a second over loopback,
    /// so a stream still silent past it is a cut the client gives up on (a
    /// reset macOS does not surface promptly after a large drain reads as
    /// `Timeout`, the file cut all the same), never a wait worth seconds.
    pub fn read_to_end(&mut self) -> StreamEnd {
        self.stream.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
        let mut rest = Vec::new();
        let end = read_to_stream_end(&mut self.stream, &mut rest);
        self.raw.extend_from_slice(&rest);
        end
    }

    /// The head as received: the status and the headers.
    pub fn head(&self) -> (u16, Vec<(String, String)>) {
        let at = self.body_at().expect("the head has arrived");
        let (status, headers, _) = parse_response(&self.raw[..at], "the fetch's head");
        (status, headers)
    }

    /// The body bytes received so far.
    pub fn body(&self) -> &[u8] {
        match self.body_at() {
            Some(at) => &self.raw[at..],
            None => &[],
        }
    }
}

/// `POST /session/close` with `token`: the binding retired, `204`.
pub fn close_session(port: u16, token: &str) {
    let (st, body) = http(port, "POST", "/session/close", Some(token), b"");
    assert_eq!(st, 204, "the close: {}", String::from_utf8_lossy(&body));
}

/// REVOKE the grant at `grant` (wire.md §The read predicate: a later grant
/// whose `from` names an earlier grant's own address revokes it), from the
/// issuer's signed session `signed`; the revocation's address. The `/op-at`
/// helper is `common::ops`' own [`op_at`](ops::op_at), which answers the
/// `(status, document)` pair the history suites read.
pub fn revoke_grant(port: u16, signed: &str, grant: &str) -> String {
    acked_addr(&op(port, Some(signed), &typed_link_frame(CLAIMANT_DOC1, &[grant], &[], T_GRANT)))
}
