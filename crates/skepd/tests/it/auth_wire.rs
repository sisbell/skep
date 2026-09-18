//! The AUTH surface over real HTTP: the challenge→signed-session→op
//! lifecycle, close and the death signal, the enrolled-set cap (16,
//! Genesis exempt), the publish and pre-claim gates' accept AND refuse
//! cells, `key_set` on `/op` and `/op-at`, `/health.auth`, and restart
//! carrying the identity fold back (recovery = the canonical rebuild).
//!
//! And the refusals a credential deposit can be handed, which is where the
//! one-way doors are: the claim's three eligibility laws (keyless,
//! first-wins, tier) — each of which, once wrong, is unrecoverable because
//! a claimant never moves — the home pin and the precedence that decides
//! which token a wrong-home deposit gets, the `malformed_payload:<sub>`
//! join this crate composes rather than delegates, `undecodable_key`, and
//! the credential idempotency memo, whose contract differs from M10's on
//! exactly one point (the hit is kind-BLIND).

use crate::common;

use common::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::Value;
use skep_identity::{encode_enroll, encode_retire, Enrollment, Fingerprint, PublicKey};

// `distinct_key`, `public_key_of`, `json_atom`, `enroll_atom` and
// `enroll_atom_flagged` are the shared helpers in `common` (lane 3.3c
// promoted them: the hire helper and the source-gate suite key delegated
// principals with the same deterministic seeds).

/// The fingerprint hex `key_set` publishes for a signing key.
fn fingerprint_hex(sk: &SigningKey) -> String {
    Fingerprint::of(&public_key_of(sk)).to_hex()
}

/// One enroll record of `n` real keys with a valid-hex NON-POINT key
/// appended last, as its atom JSON fragment — the shape that asks where
/// slot (4)'s decode stops, since the undecodable key sits at the end.
fn enroll_atom_with_trailing_non_point(n: usize) -> String {
    let real: Vec<SigningKey> = (0..n as u8).map(distinct_key).collect();
    let mut entries: Vec<Enrollment> = real
        .iter()
        .map(|sk| Enrollment::new(public_key_of(sk), false, None).expect("no label"))
        .collect();
    let bad = PublicKey::parse("ed25519", &non_point_hex())
        .expect("64 hex parses — the fold admits syntax and never decodes the point");
    entries.push(Enrollment::new(bad, false, None).expect("no label"));
    json_atom(&encode_enroll(&entries))
}

/// One retire record naming fingerprints, as its atom JSON fragment.
fn retire_atom(fps: &[&str]) -> String {
    let parsed: Vec<Fingerprint> =
        fps.iter().map(|h| Fingerprint::parse_hex(h).expect("64 hex")).collect();
    json_atom(&encode_retire(&parsed))
}

/// Land one credential record atom at `ordinal` of the claimant's doc 1 and
/// answer its address. The atom is a write into a published home, so it
/// needs a session the publish gate admits — a signed one on a claimed
/// board — and it carries the DEPOSIT DECLARATION (PUB-2.63; PUB-9.13's
/// DECLARED horn), since an undeclared insert into a published document is
/// the in-place edit the write path refuses (PUB-2.11). Kept apart from
/// [`deposit`] for exactly that reason: the two writes meet different gates,
/// and only the second is the credential path's.
fn record_atom(port: u16, signed_token: &str, ordinal: u64, atom: &str) -> String {
    let v = op(
        port,
        Some(signed_token),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":true}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    format!("{CLAIMANT_DOC1}.0.1.{ordinal}")
}

/// The deposit naming an already-landed record — the credential write under
/// test, and the one the precheck's ordered slots judge.
fn deposit(port: u16, token: &str, atom_addr: &str, ty: &str) -> Value {
    op(port, Some(token), &deposit_frame(None, atom_addr, ty))
}

/// [`deposit`]'s frame, optionally carrying an idempotency `id` — spelled
/// out because the credential memo is keyed on that field, so a test about
/// the memo must set it and a test about the slots must not.
fn deposit_frame(id: Option<&str>, atom_addr: &str, ty: &str) -> String {
    let id = id.map(|id| format!(r#""id":"{id}","#)).unwrap_or_default();
    format!(
        r#"{{"op":"make_link",{id}"home":"{CLAIMANT_DOC1}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{ty}"]}}}}"#
    )
}

/// The claim ceremony's own last step, parameterized: `from` names the
/// claiming account, `to` is empty, and the deposit carries no payload at
/// all (AUTH-2.48), so — unlike [`deposit`] — it needs no record atom.
/// Every eligibility law refuses exactly this frame.
fn claim_deposit(port: u16, token: &str, doc1: &str, account: &str) -> Value {
    op(
        port,
        Some(token),
        &format!(
            r#"{{"op":"make_link","home":"{doc1}","from":{{"addrs":["{account}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{T_CLAIM}"]}}}}"#
        ),
    )
}

/// Delegate a fresh account under `parent` from `by`'s session, mint its
/// doc 1 (the MINT-FIRST home), and answer `(account, doc 1, a session
/// bound to it)` — the seat every claim-eligibility cell below is judged
/// against.
fn seat_account(port: u16, by: &str, parent: &str, id: u64) -> (String, String, String) {
    let v = op(port, Some(by), &format!(r#"{{"op":"next_account_prefix","parent":"{parent}"}}"#));
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    let v = op(
        port,
        Some(by),
        &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#),
    );
    expect_resp(&v, "ack_addr");
    let session = open_session(port, id);
    let v = op(
        port,
        Some(&session),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    );
    let doc1 = acked_addr(&v);
    (account, doc1, session)
}

/// Delegate a fresh EMPTY account under principal 0 — no home mint — and
/// answer `(account, a bare session bound to it)`. The seat every first-mint
/// cell is judged against, before its home exists.
fn delegate_empty_account(port: u16, boot: &str, id: u64) -> (String, String) {
    let v = op(port, Some(boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    let v = op(port, Some(boot), &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#));
    expect_resp(&v, "ack_addr");
    (account, open_session(port, id))
}

fn rejected_detail(v: &Value) -> String {
    assert_eq!(v["resp"].as_str(), Some("rejected"), "expected a rejection: {v}");
    format!(
        "{}:{}",
        v["code"].as_str().unwrap_or("?"),
        v["detail"].as_str().unwrap_or("-")
    )
}

/// The pre-claim admission gate (RES-27): an unclaimed daemon runs nothing
/// but the ceremony — refuse cells before the claim, the ceremony's own
/// accept cells inside `claim_board`, and ordinary ops after it.
#[test]
fn pre_claim_gate_admits_only_the_ceremony() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    // Refuse cell: an ordinary write, bare 0 session — claim_first with the
    // pinned shape (credential_refused, permanent).
    let v = op(port, Some(&boot), r#"{"op":"register_node","addr":"1.2"}"#);
    assert_eq!(rejected_detail(&v), "credential_refused:claim_first");
    assert_eq!(v["disposition"].as_str(), Some("permanent"));
    // Refuse cell: a guest write answers unauthenticated AHEAD of the gate
    // (slot 0 of every order).
    let v = op(port, None, r#"{"op":"register_node","addr":"1.2"}"#);
    assert_eq!(v["code"].as_str(), Some("unauthenticated"), "{v}");
    // Reads stand untouched pre-claim.
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    expect_resp(&v, "maybe_addr");
    // The accept cells ARE the ceremony (delegate-from-0, the home mint,
    // the genesis insert + deposit, the signed claim).
    claim_board(port);
    // …and the same ordinary write commits once claimed.
    let v = op(port, Some(&boot), r#"{"op":"register_node","addr":"1.2"}"#);
    expect_resp(&v, "ack_addr");
    sd.shutdown();
}

/// The claim's KEYLESS law (wire.md §The claim ceremony: only an account
/// "with a non-empty key set" may claim), and the first of the three
/// one-way doors the ceremony carries.
///
/// The failure is unrecoverable rather than merely wrong. A claimant is set
/// once and never moves (I6), so a board claimed by a keyless account can
/// never establish a signed session for it: `signed_origins` drops to the
/// configured set, `--local-trust off` then admits nothing at all, and no
/// enrollment can reach that account either, since slot (7) is arm-blind
/// and its own genesis would need the signed session it cannot have.
#[test]
fn a_keyless_top_level_account_cannot_claim_the_board() {
    let dir = tempfile::tempdir().expect("tempdir");
    // UNCLAIMED and never claimed by the ceremony: this account must be the
    // board's first delegate, which is the seat `claim_board` would take.
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    let (account, doc1, session) = seat_account(port, &boot, "1", 701);

    let v = claim_deposit(port, &session, &doc1, &account);
    assert_eq!(rejected_detail(&v), "credential_refused:claimant_keyless");
    assert!(
        !claimed(port),
        "and the board is still unclaimed — the refusal is the whole point, since \
         a claimant that cannot sign is permanent"
    );
    sd.shutdown();
}

/// The claim's FIRST-WINS law (wire.md §The claim ceremony: "first claim
/// wins, permanently"). The frame is the ceremony's own, byte for byte, so
/// what refuses it is the board's state and nothing about the deposit.
#[test]
fn first_claim_wins_permanently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    let v = claim_deposit(port, &signed, CLAIMANT_DOC1, CLAIMANT_ACCOUNT);
    assert_eq!(rejected_detail(&v), "credential_refused:already_claimed");
    assert_eq!(
        json(&get(port, "/health").1)["auth"]["claimant"].as_str(),
        Some(CLAIMANT_ACCOUNT),
        "and the claimant did not move"
    );
    sd.shutdown();
}

/// The claim's TIER law (wire.md §The claim ceremony: only a "top-level
/// (bootstrap-delegated) account" may claim) — and, in the same answer, the
/// order the fold pins among the three: the delegator test runs AHEAD of
/// first-wins (AUTH-2.68), so on a CLAIMED board a nested account's claim
/// answers `claimant_not_top_level` and never `already_claimed`.
#[test]
fn only_a_bootstrap_delegated_account_can_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // A sub-account UNDER the claimant: its delegator is an account
    // principal rather than the bootstrap one, so its tier is the law's.
    let (nested, nested_doc1, nested_session) =
        seat_account(port, &signed, CLAIMANT_ACCOUNT, 702);

    let v = claim_deposit(port, &nested_session, &nested_doc1, &nested);
    assert_eq!(
        rejected_detail(&v),
        "credential_refused:claimant_not_top_level",
        "the delegator test precedes first-wins, so this is not already_claimed"
    );
    assert_eq!(
        json(&get(port, "/health").1)["auth"]["claimant"].as_str(),
        Some(CLAIMANT_ACCOUNT)
    );
    sd.shutdown();
}

/// The publish gate (RES-26) on a claimed board: a bare session's write
/// into a published home (an account's doc 1) refuses
/// `signed_session_required`; its draft mints and draft-homed writes stand
/// (CLAIMED-PERMISSIVE's disclosed cost); the signed session passes.
#[test]
fn publish_gate_shuts_bare_published_writes_and_admits_signed_ones() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    // Refuse: a bare write homed in the published doc 1 (ordinal 2 — the
    // one legal insert slot after the ceremony's atom, so the gate is what
    // refuses it, not the arrangement's bounds).
    let v = op(
        port,
        Some(&bare),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["x"]}}"#
        ),
    );
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    // Refuse: a bare flagless version of the published doc 1.
    let v = op(port, Some(&bare), &format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}"}}"#));
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    // Accept: a bare DRAFT mint and a write homed in it.
    let v = op(
        port,
        Some(&bare),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    let draft = acked_addr(&v);
    let v = op(
        port,
        Some(&bare),
        &format!(
            r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["d"]}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    // Accept: the SIGNED session writes the SAME position into the
    // published home — as the DECLARED deposit the write path admits there
    // (PUB-2.59; an undeclared insert is the refused in-place edit, PUB-2.11,
    // which is the store's cell, `tests/version_chain.rs`).
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["y"],"deposit":true}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    sd.shutdown();
}

/// The MINT-FIRST gate: fork/version into an empty account refuse
/// `mint_home_first`; the home mint clears it.
#[test]
fn mint_home_first_refuses_until_the_home_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":77}}"#),
    );
    expect_resp(&v, "ack_addr");
    let account_token = open_session(port, 77);
    let v = op(port, Some(&account_token), r#"{"op":"fork"}"#);
    assert_eq!(rejected_detail(&v), "credential_refused:mint_home_first");
    // version into the empty account refuses the same way (§4.3): MINT-FIRST
    // reads the caller's account, never the source, so any registered source
    // meets it — the mint slot stands ahead of the board-state gate, so this
    // is `mint_home_first`, not the published-source `signed_session_required`.
    let v =
        op(port, Some(&account_token), &format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}"}}"#));
    assert_eq!(rejected_detail(&v), "credential_refused:mint_home_first");
    let v = op(
        port,
        Some(&account_token),
        &format!(r#"{{"op":"create_new_document","account":"{prefix}"}}"#),
    );
    expect_resp(&v, "ack_addr");
    let v = op(port, Some(&account_token), r#"{"op":"fork"}"#);
    expect_resp(&v, "ack_addr");
    sd.shutdown();
}

/// Challenge → signed session → op, and the strict body boundary: a reused
/// nonce is the ONE 401; an uppercase nonce is a 400 whose nonce SURVIVES.
#[test]
fn the_handshake_lifecycle_and_a_400_that_spends_no_nonce() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let p = CLAIMANT_PRINCIPAL;
    let (st, body) = http(port, "GET", &format!("/challenge?principal={p}"), None, b"");
    assert_eq!(st, 200);
    let ch = json(&body);
    assert_eq!(ch["ttl_ms"].as_u64(), Some(60_000), "the TTL is a byte pin");
    let nonce = ch["nonce"].as_str().expect("nonce").to_string();
    // The uppercase-nonce vector: 400, and the nonce is NOT burned.
    let sig = sign_session(&device_key(), &origin, &nonce, p);
    let upper = format!(
        "{{\"principal\":{p},\"nonce\":\"{}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}",
        nonce.to_uppercase()
    );
    let (st, body) = http(port, "POST", "/session", None, upper.as_bytes());
    assert_eq!(st, 400, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("malformed_session_request"));
    // The lowercased retry with the SAME nonce answers 200…
    let ok = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
    );
    let (st, body) = http(port, "POST", "/session", None, ok.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let token = json(&body)["session"].as_str().expect("token").to_string();
    // …and that session writes.
    let v = op(
        port,
        Some(&token),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    expect_resp(&v, "ack_addr");
    // A REUSED nonce is the one permanent 401, byte-identical.
    let (st, body) = http(port, "POST", "/session", None, ok.as_bytes());
    assert_eq!(st, 401);
    assert_eq!(
        String::from_utf8(body).expect("utf-8"),
        r#"{"error":"session_rejected"}"#,
        "one code, no detail"
    );
    // A malformed challenge query is its own 400.
    let (st, body) = http(port, "GET", "/challenge?nope=1", None, b"");
    assert_eq!(st, 400);
    assert_eq!(json(&body)["error"].as_str(), Some("malformed_challenge"));
    sd.shutdown();
}

/// Close discipline (AUTH-4.47) and the death signal (AUTH-6.7): a live
/// close is a bare 204; re-presenting the dead token signals on every
/// token-accepting route, beside the exposed header.
#[test]
fn close_is_idempotent_and_the_dead_token_signals() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (st, headers, _) = http_full(port, "POST", "/session/close", Some(&signed), b"");
    assert_eq!(st, 204);
    assert!(
        header(&headers, "Skepd-Session").is_none(),
        "a live close is the person's own act — no death signal"
    );
    // Idempotent: the same token again is 204 WITH the signal.
    let (st, headers, _) = http_full(port, "POST", "/session/close", Some(&signed), b"");
    assert_eq!(st, 204);
    assert_eq!(header(&headers, "Skepd-Session"), Some("closed"));
    // The dead token on /op: unauthenticated + the signal, and the
    // expose header rides every response.
    let (st, headers, body) = http_full(
        port,
        "POST",
        "/op",
        Some(&signed),
        br#"{"op":"register_node","addr":"1.4"}"#,
    );
    assert_eq!(st, 200);
    assert_eq!(json(&body)["code"].as_str(), Some("unauthenticated"));
    assert_eq!(header(&headers, "Skepd-Session"), Some("closed"));
    assert_eq!(
        header(&headers, "Access-Control-Expose-Headers"),
        Some("Skepd-Session"),
        "the death signal must be readable cross-origin (AUTH-6.12)"
    );
    sd.shutdown();
}

/// The enrolled-set cap (RES-57): refused at 16 on the Enroll arm; the
/// ceremony's Genesis was exempt. Driven from the signed device session.
#[test]
fn the_enrolled_cap_refuses_at_sixteen_and_genesis_is_exempt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // The set holds 2 (the ceremony's genesis — exempt from the cap by
    // arm). An enroll of 15 more would land at 17 > 16: refused, whole.
    let extra_keys: Vec<SigningKey> = (0..15).map(distinct_key).collect();
    let record_keys: Vec<&SigningKey> = extra_keys.iter().collect();
    let enroll = |atom_ordinal: u64, atom: &str| {
        let v = op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{atom_ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":true}}"#
            ),
        );
        expect_resp(&v, "ack_addr");
        let addr = format!("{CLAIMANT_DOC1}.0.1.{atom_ordinal}");
        op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{addr}"]}},"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
            ),
        )
    };
    let v = enroll(2, &enroll_atom(&record_keys));
    assert_eq!(rejected_detail(&v), "credential_refused:too_many_enrolled");
    // 14 more (16 total) clears the cap exactly.
    let v = enroll(3, &enroll_atom(&record_keys[..14]));
    expect_resp(&v, "ack_addr");
    // …and the 17th key alone now refuses.
    let v = enroll(4, &enroll_atom(&record_keys[14..]));
    assert_eq!(rejected_detail(&v), "credential_refused:too_many_enrolled");
    // key_set shows exactly 16 enrolled.
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    assert_eq!(v["resp"].as_str(), Some("key_set"), "{v}");
    assert_eq!(v["enrolled"].as_array().expect("enrolled").len(), 16);
    sd.shutdown();
}

/// The daemon's `MAX_GENESIS_KEYS`, restated so that moving it is a visible
/// decision — the discipline `SMALL_BODY_CAP` and `HEAD_CAP` already keep
/// in the transport suite.
const GENESIS_KEY_CAP: usize = 16;

/// The seeding hand's own record cap, both ends. RES-57 exempts `Genesis`
/// from the enrolled SET's cap, so what is bounded here is a different
/// quantity: ONE RECORD's key count — which is what the handshake walks in
/// full, with no cutoff (AUTH-4.33), on every signed `POST /session`
/// attempt, and that route is unauthenticated and reachable from any page.
///
/// PRE-CLAIM, because that is the reachable window and the permanent one:
/// slot (7) is arm-blind, so a bare genesis plant on a claimed board dies
/// there, while anything seeded before the claim can be retired only by an
/// anchor session of that account — whose keys the planter chose.
///
/// The at-cap half is load-bearing: a `>` that became a `>=` would refuse
/// a seeding a deployment legitimately performs.
#[test]
fn a_genesis_record_meets_its_key_cap_at_both_ends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();

    // A fresh KEYLESS account, seeded through the ceremony's own admitted
    // shapes: the delegate from principal 0, then its home mint.
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let account = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":700}}"#),
    );
    expect_resp(&v, "ack_addr");
    let account_token = open_session(port, 700);
    let v = op(
        port,
        Some(&account_token),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    );
    let doc1 = acked_addr(&v);

    // One genesis attempt: the record atom into the account's own doc 1
    // (the genesis registry), then the deposit naming it.
    let genesis = |ordinal: u64, keys: &[&SigningKey]| -> Value {
        let v = op(
            port,
            Some(&account_token),
            &format!(
                r#"{{"op":"insert","doc":"{doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
                enroll_atom(keys)
            ),
        );
        expect_resp(&v, "ack_addr");
        op(
            port,
            Some(&account_token),
            &format!(
                r#"{{"op":"make_link","home":"{doc1}","from":{{"addrs":["{doc1}.0.1.{ordinal}"]}},"to":{{"addrs":["{account}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
            ),
        )
    };
    let enrolled_count = || -> usize {
        let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{account}"}}"#));
        assert_eq!(v["resp"].as_str(), Some("key_set"), "{v}");
        v["enrolled"].as_array().expect("enrolled").len()
    };

    let keys: Vec<SigningKey> = (0..=GENESIS_KEY_CAP as u8).map(distinct_key).collect();
    let record_keys: Vec<&SigningKey> = keys.iter().collect();

    // One key past the cap: refused, and it seeds nothing.
    let v = genesis(1, &record_keys);
    assert_eq!(rejected_detail(&v), "credential_refused:too_many_enrolled");
    assert_eq!(enrolled_count(), 0, "the refused genesis seeded nothing");

    // Exactly the cap: admitted, and the whole record lands.
    let v = genesis(2, &record_keys[..GENESIS_KEY_CAP]);
    expect_resp(&v, "ack_addr");
    assert_eq!(enrolled_count(), GENESIS_KEY_CAP, "a genesis AT the cap seeds every key");

    sd.shutdown();
}

/// Where slot (4)'s point decode stops. The decode is per key and the key
/// count is the RECORD's, bounded upstream at 64 KiB and so at order 800
/// keys — held under the credential write lock and the serialization lock,
/// bought by one small deposit. So the decode is bounded at one key past
/// the cap slot (5) applies, and the two ends of that bound are:
///
/// AT the cap, every key is decoded wherever the undecodable one sits —
/// the load-bearing half, since a shorter bound would miss a trailing bad
/// key and SEAT it, which is the permanent harm slot (4) exists to
/// prevent. ONE PAST the cap, the trailing key is still reached, because
/// the scan's bound is one key wider than the cap and not equal to it —
/// which is what makes the boundary the scan's rather than slot (5)'s, and
/// what a comment naming the cap in its place gets wrong by one key. PAST
/// the scan, the count refuses first and the trailing key is never
/// reached, which is the one answer this bound moves: `undecodable_key`
/// becomes `too_many_enrolled`, both true, both permanent, both refusals.
#[test]
fn the_undecodable_key_scan_stops_one_key_past_the_cap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();

    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let account = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":703}}"#),
    );
    expect_resp(&v, "ack_addr");
    let account_token = open_session(port, 703);
    let v = op(
        port,
        Some(&account_token),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    );
    let doc1 = acked_addr(&v);

    // One genesis attempt whose record's LAST key is a valid-hex non-point.
    let genesis_with_bad_tail = |ordinal: u64, real_keys: usize| -> Value {
        let v = op(
            port,
            Some(&account_token),
            &format!(
                r#"{{"op":"insert","doc":"{doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
                enroll_atom_with_trailing_non_point(real_keys)
            ),
        );
        expect_resp(&v, "ack_addr");
        op(
            port,
            Some(&account_token),
            &format!(
                r#"{{"op":"make_link","home":"{doc1}","from":{{"addrs":["{doc1}.0.1.{ordinal}"]}},"to":{{"addrs":["{account}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
            ),
        )
    };
    let enrolled_count = || -> usize {
        let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{account}"}}"#));
        assert_eq!(v["resp"].as_str(), Some("key_set"), "{v}");
        v["enrolled"].as_array().expect("enrolled").len()
    };

    // AT the cap: 15 real keys plus the bad one is exactly the cap, so the
    // count admits it and slot (4) must still reach the last key.
    let v = genesis_with_bad_tail(1, GENESIS_KEY_CAP - 1);
    assert_eq!(
        rejected_detail(&v),
        "credential_refused:undecodable_key",
        "a record AT the cap has every key decoded, wherever the bad one sits"
    );
    assert_eq!(enrolled_count(), 0, "and it seeded nothing");

    // ONE PAST the cap, which is exactly where the scan stops: 17 keys, the
    // bad one 17th. Slot (5) would refuse this record on its count, and
    // slot (4) runs first and still reaches that key — so the boundary
    // belongs to the SCAN and not to the cap, and the answer here is
    // `undecodable_key` rather than `too_many_enrolled`.
    let v = genesis_with_bad_tail(2, GENESIS_KEY_CAP);
    assert_eq!(
        rejected_detail(&v),
        "credential_refused:undecodable_key",
        "the scan reaches one key past the cap, so slot (4) answers at that position"
    );
    assert_eq!(enrolled_count(), 0);

    // PAST the scan: the count refuses before the trailing key is reached.
    let v = genesis_with_bad_tail(3, GENESIS_KEY_CAP + 3);
    assert_eq!(
        rejected_detail(&v),
        "credential_refused:too_many_enrolled",
        "past the scan the count answers, so the decode never runs the tail"
    );
    assert_eq!(enrolled_count(), 0);

    sd.shutdown();
}

/// The credential idempotency memo (wire.md §Correlation and idempotency):
/// the ORIGINAL acknowledgment, byte-identical, with no re-execution; the
/// hit KIND-BLIND on the `id` alone; and the memo per session.
///
/// Its absence is not silence but a wrong answer that looks right. A client
/// that lost an ack and retries meets a deposit that re-executes and
/// classifies `nothing_changed` — a PERMANENT-disposition refusal for a
/// write that in fact committed — so the client concludes its enrollment
/// failed. And the kind-blindness is the opposite of M10's op-kind-matched
/// memo one route away, so the module runs two memos whose rules differ on
/// exactly this point.
///
/// What (c) does NOT prove, said here rather than left to be inferred: a
/// reopened session carries a fresh `SessionId`, so no exchange can tell
/// "purged when its session closed" from "keyed by session". The purge
/// half of the contract is unobservable from the wire and stays unwatched.
#[test]
fn a_credential_retry_replays_the_original_ack_kind_blind_and_per_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let record = record_atom(port, &signed, 2, &enroll_atom(&[&distinct_key(5)]));
    let frame = deposit_frame(Some("k1"), &record, T_ENROLL);

    let (st, first) = http(port, "POST", "/op", Some(&signed), frame.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&first));
    expect_resp(&json(&first), "ack_addr");

    // (a) Byte-identical — and that IS the proof no execution happened: a
    // re-executed identical enroll adds no key and answers
    // `nothing_changed`, so an equal ack could not have come from one.
    let (_, again) = http(port, "POST", "/op", Some(&signed), frame.as_bytes());
    assert_eq!(
        String::from_utf8_lossy(&again),
        String::from_utf8_lossy(&first),
        "the ORIGINAL ack, byte-identical"
    );

    // (b) KIND-BLIND — the id alone. A RETIRE deposit under the same id
    // answers the enroll's ack; executed, it would read that enrollment
    // record as a retirement and answer `malformed_payload:bad_record` (the
    // `type` disagrees with the link's kind).
    let other = deposit_frame(Some("k1"), &record, T_RETIRE);
    let (_, blind) = http(port, "POST", "/op", Some(&signed), other.as_bytes());
    assert_eq!(
        String::from_utf8_lossy(&blind),
        String::from_utf8_lossy(&first),
        "the hit is on the id, not on the frame or its kind"
    );

    // (c) PER-SESSION: another session recalls nothing, so the identical
    // frame executes — and answers what a re-execution answers.
    let second = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(port, Some(&second), &frame);
    assert_eq!(
        rejected_detail(&v),
        "credential_refused:nothing_changed",
        "another session's memo is empty, so the deposit re-executes"
    );

    // (d) A refusal is never memoized: after one under `kr`, the same id
    // carries the next frame through.
    let bad = record_atom(port, &signed, 3, &json_atom("nonsense"));
    let v = op(port, Some(&signed), &deposit_frame(Some("kr"), &bad, T_ENROLL));
    assert_eq!(rejected_detail(&v), "credential_refused:malformed_payload:bad_record");
    let good = record_atom(port, &signed, 4, &enroll_atom(&[&distinct_key(6)]));
    expect_resp(&op(port, Some(&signed), &deposit_frame(Some("kr"), &good, T_ENROLL)), "ack_addr");

    sd.shutdown();
}

/// The payload family's `malformed_payload:<sub>` join (wire.md §Credential
/// refusals) — the one wire detail this crate COMPOSES rather than
/// delegates. `Inert::token()` answers the bare `malformed_payload`, and
/// the sub exists only because `CredentialRefusal::token()` carries an arm
/// of its own for it; the two arms look redundant, and collapsing them
/// emits a token that is not in the documented set at all, on the family
/// that tells an operator WHY their record was rejected.
#[test]
fn a_malformed_record_names_its_payload_fault_after_the_join() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // A body that is not the canonical schema dies as `bad_record`.
    let bad_record = record_atom(port, &signed, 2, &json_atom("nonsense"));
    assert_eq!(
        rejected_detail(&deposit(port, &signed, &bad_record, T_ENROLL)),
        "credential_refused:malformed_payload:bad_record"
    );
    // A PARAMETERIZED sub survives the join — a duplicate entry names its
    // 1-based ENTRY index (AUTH-2.15, AUTH-1.28), two colons and all.
    let dup = record_atom(port, &signed, 3, &enroll_atom(&[&distinct_key(5), &distinct_key(5)]));
    assert_eq!(
        rejected_detail(&deposit(port, &signed, &dup, T_ENROLL)),
        "credential_refused:malformed_payload:duplicate_key:2"
    );

    sd.shutdown();
}

/// Thirty-two bytes that are valid hex and are NOT a canonical Ed25519
/// point, derived from the verifier's own answer rather than hardcoded:
/// roughly half of all 32-byte strings fail decompression, and the panic
/// below is what keeps a search that finds nothing from passing silently.
fn non_point_hex() -> String {
    for n in 0u8..=255 {
        if VerifyingKey::from_bytes(&[n; 32]).is_err() {
            return hex(&[n; 32]);
        }
    }
    panic!("no non-point among the 256 constant-byte candidates");
}

/// wire.md §Credential refusals: a valid-hex key that decodes to no
/// Ed25519 point is "refused at enrollment rather than discovered at a
/// handshake". The fold is syntax-only by contract (AUTH-1.4 — the curve
/// point is never decoded), so such a record parses and classifies
/// honored: `precheck`'s slot (4) is the ONLY thing standing between it
/// and a permanently seated key that occupies a slot against the enrolled
/// cap and that `find_signer` walks on every unauthenticated handshake
/// attempt — retirable only by an anchor session of that account.
#[test]
fn a_valid_hex_non_point_key_is_refused_at_enrollment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    let key = PublicKey::parse("ed25519", &non_point_hex())
        .expect("64 hex parses — the fold admits syntax and never decodes the point");
    let text = encode_enroll(&[Enrollment::new(key, false, None).expect("no label")]);
    let record = record_atom(port, &signed, 2, &json_atom(&text));
    assert_eq!(
        rejected_detail(&deposit(port, &signed, &record, T_ENROLL)),
        "credential_refused:undecodable_key"
    );

    // …and it seated nothing: the set is still the ceremony's two.
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    assert_eq!(v["enrolled"].as_array().expect("enrolled").len(), 2, "{v}");

    sd.shutdown();
}

/// The fold's publication read is the engine's ONE definition (owner ruling
/// D1, 2026-09-05; `conformance/adjudication/decisions.md`): a credential
/// deposited in a DRAFT-homed document answers `unpublished` — AUTH-2.66
/// item 3, ahead of the per-kind arm — where the constant-true v1 wiring let
/// it fall through to the home pin's `not_doc_one`. THE CELL THAT FLIPS; no
/// golden moves. Item 3 precedes the payload parse too, so an unparseable
/// record in a draft answers `unpublished` and never `malformed_payload`.
///
/// The home pin (RES-17) and AUTH-2.127's parse-before-pin precedence
/// therefore need a PUBLISHED home that is not doc 1 to stay observable, and
/// this build has one: doc 1's own version, born published by inheritance
/// (PUB-8.17). A well-formed record there answers `not_doc_one`; an
/// unparseable one answers the PAYLOAD fault, the parse preceding the pin.
#[test]
fn a_draft_homed_credential_refuses_unpublished_and_the_home_pin_needs_a_published_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // An enroll deposit homed in `home`, its record atom landed first at the
    // V-position `ordinal`. The atom's I-address is the insert's own ack —
    // a version's content chain is its own, so the I-ordinal is not the
    // V-ordinal there — and home anchoring puts the record in `home`. The
    // atom's insert is DECLARED (PUB-2.63): into the published member it is
    // the deposit the write path admits, and into the draft the flag is
    // inert.
    let enroll_in = |home: &str, ordinal: u64, atom: &str| -> Value {
        let v = op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"insert","doc":"{home}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":true}}"#
            ),
        );
        let atom_addr = acked_addr(&v);
        op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"make_link","home":"{home}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
            ),
        )
    };

    // A DRAFT of the claimant's — a second mint into its account, born
    // private (PUB-1.1).
    let v = op(
        port,
        Some(&signed),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    let draft = acked_addr(&v);
    assert_eq!(
        rejected_detail(&enroll_in(&draft, 1, &enroll_atom(&[&distinct_key(7)]))),
        "credential_refused:unpublished",
        "D1's flipped cell: item 3 answers ahead of the home pin"
    );
    assert_eq!(
        rejected_detail(&enroll_in(&draft, 2, &json_atom("nonsense"))),
        "credential_refused:unpublished",
        "publication precedes the payload parse"
    );

    // A PUBLISHED home that is not doc 1: doc 1's own version. The version
    // snapshots doc 1's one content position (the ceremony's atom), so its
    // first free insert slot is 2.
    let v = op(port, Some(&signed), &format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}"}}"#));
    let version = acked_addr(&v);
    assert_eq!(version, format!("{CLAIMANT_DOC1}.1"), "the version chain opens at the member 1");
    assert_eq!(
        rejected_detail(&enroll_in(&version, 2, &enroll_atom(&[&distinct_key(7)]))),
        "credential_refused:not_doc_one",
        "a published non-doc-1 home reaches the home pin"
    );
    assert_eq!(
        rejected_detail(&enroll_in(&version, 3, &json_atom("nonsense"))),
        "credential_refused:malformed_payload:bad_record",
        "the parse precedes the pin (AUTH-2.127)"
    );

    sd.shutdown();
}

/// PUB-2.15 — the publish gate projects a VERSION member to its DOCUMENT
/// before the read: a bare write homed in doc 1's version, and a bare version
/// of that member, both refuse `signed_session_required`. The drift sweep's
/// claim-2 defect: the retired equality compare read doc 1's versions as
/// unpublished and ADMITTED both. The signed session performs both.
#[test]
fn the_publish_gate_projects_a_version_member_to_its_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(port, Some(&signed), &format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}"}}"#));
    let version = acked_addr(&v);
    assert_eq!(version, format!("{CLAIMANT_DOC1}.1"));

    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    // A bare write homed in the member: refused — the member projects to the
    // published doc 1. (Declared, and at the member's fresh position, so
    // the store's in-place refusal is not what answers below: the write is
    // the deposit a published head admits, PUB-2.59.)
    let insert = format!(
        r#"{{"op":"insert","doc":"{version}","at":{{"subspace":"1","ordinal":"2"}},"values":["x"],"deposit":true}}"#
    );
    assert_eq!(rejected_detail(&op(port, Some(&bare), &insert)), "credential_refused:signed_session_required");
    // A bare version OF the member: refused the same way.
    let version_of_version = format!(r#"{{"op":"version","d_src":"{version}"}}"#);
    assert_eq!(
        rejected_detail(&op(port, Some(&bare), &version_of_version)),
        "credential_refused:signed_session_required"
    );
    // The signed session lands both.
    expect_resp(&op(port, Some(&signed), &insert), "ack_addr");
    let v = op(port, Some(&signed), &version_of_version);
    assert_eq!(acked_addr(&v), format!("{CLAIMANT_DOC1}.1.1"));

    sd.shutdown();
}

/// PUB-6.37 — `published()` is evaluated only on REGISTERED addresses: a
/// membership miss is the published fast path, so an unregistered argument
/// would otherwise read PUBLISHED and meet the gate as
/// `signed_session_required`, a code named for nothing the op could have
/// done. Registration stands ahead: a bare write to a never-minted slot of
/// the claimant's own account answers the registration refusal, and so does
/// a bare version of one.
#[test]
fn the_publish_gate_reads_publication_only_on_registered_addresses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    // A document slot of the claimant's own chain that no mint has reached.
    let never = format!("{CLAIMANT_ACCOUNT}.0.99");

    let v = op(
        port,
        Some(&bare),
        &format!(
            r#"{{"op":"insert","doc":"{never}","at":{{"subspace":"1","ordinal":"1"}},"values":["x"]}}"#
        ),
    );
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"), "{v}");
    let v = op(port, Some(&bare), &format!(r#"{{"op":"version","d_src":"{never}"}}"#));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("source_not_registered"), "{v}");

    sd.shutdown();
}

/// PUB-8.20 / the H1 first-mint pair (PUB-6.58): an explicit `published:false`
/// on an account's FIRST document is REFUSED at the daemon's door
/// (`mint_home_public`, permanent, nothing committed), and a FLAGLESS first
/// mint is HONORED — the home born PUBLISHED. Also the door's neighbours
/// (PUB-8.21, §4.2): explicit `true` on a first mint is honored public, and
/// once the home exists a flagless or explicit-`false` mint is an ordinary
/// private draft that refuses nothing.
///
/// "Born published" is read behaviourally: a bare session's write into a
/// published home hits the publish gate (`signed_session_required`), while a
/// write into a draft it owns commits — so the gate's verdict on a bare
/// insert reports the mint's resolved publication state.
#[test]
fn the_first_mint_door_refuses_explicit_false_and_a_flagless_first_mint_is_public() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path()); // claimed, CLAIMED-PERMISSIVE (bare binds honored)
    let port = sd.port();
    let boot = open_session(port, 0);

    let (account, session) = delegate_empty_account(port, &boot, 808);
    let create = |flag: &str| {
        op(port, Some(&session), &format!(r#"{{"op":"create_new_document","account":"{account}"{flag}}}"#))
    };
    // A bare write into `doc` at `ord`: published ⇒ the publish gate refuses;
    // draft ⇒ it commits. `ord` is chosen free so the arrangement is silent.
    let bare_write_published = |doc: &str, ord: u64| -> bool {
        let v = op(port, Some(&session), &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ord}"}},"values":["p"]}}"#
        ));
        match v["resp"].as_str() {
            Some("rejected") => {
                assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required",
                    "a bare write into {doc} refused for another reason: {v}");
                true
            }
            Some("ack_addr") => false,
            _ => panic!("unexpected insert response for {doc}: {v}"),
        }
    };

    // H1 cell 1: explicit `false` on the FIRST mint is refused, nothing commits.
    let v = create(r#","published":false"#);
    assert_eq!(rejected_detail(&v), "credential_refused:mint_home_public");
    assert_eq!(v["disposition"].as_str(), Some("permanent"));

    // H1 cell 2: a FLAGLESS first mint is honored, the home born PUBLISHED.
    let home = acked_addr(&create(""));
    assert!(bare_write_published(&home, 1), "a flagless first mint is born published");

    // Once the home exists, a flagless mint is a PRIVATE draft (§4.2).
    let draft = acked_addr(&create(""));
    assert!(!bare_write_published(&draft, 1), "a later flagless mint is a private draft");

    // …and an explicit `false` on a non-first mint refuses nothing — private.
    let priv2 = acked_addr(&create(r#","published":false"#));
    assert!(!bare_write_published(&priv2, 1), "a non-first explicit-false mint is private, not refused");

    // §4.2 empty + `true`: a fresh account's first mint with explicit `true`
    // is honored public (the exemption admits the content-empty home under
    // any flag).
    let (account2, session2) = delegate_empty_account(port, &boot, 809);
    let v = op(port, Some(&session2), &format!(r#"{{"op":"create_new_document","account":"{account2}","published":true}}"#));
    let home2 = acked_addr(&v);
    let v = op(port, Some(&session2), &format!(
        r#"{{"op":"insert","doc":"{home2}","at":{{"subspace":"1","ordinal":"1"}},"values":["p"]}}"#
    ));
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required",
        "an explicit-true first mint is honored public");

    sd.shutdown();
}

/// The publish gate's EXPLICIT-FLAG row (PUB-6.43, §4.5): on a claimed board a
/// bare session's `published:true` mint into a NON-empty account lands in the
/// published world and is refused `signed_session_required`; a draft mint
/// (flagless or explicit `false`) from the same bare session is accepted; and
/// a signed session publishes.
#[test]
fn the_publish_gate_refuses_an_explicit_true_mint_from_a_bare_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let create = |token: &str, flag: &str| {
        op(port, Some(token), &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"{flag}}}"#))
    };

    // Explicit `true` into the claimant's non-empty account → published write.
    let v = create(&bare, r#","published":true"#);
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    // Draft mints from the same bare session are accepted.
    expect_resp(&create(&bare, ""), "ack_addr");
    expect_resp(&create(&bare, r#","published":false"#), "ack_addr");
    // A signed session publishes it.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    expect_resp(&create(&signed, r#","published":true"#), "ack_addr");

    sd.shutdown();
}

/// The dump's exception set — the `publication.drafts` hint, draft document →
/// owner account (PUB-7.5) — as its rendered text. The one wire surface that
/// shows a version MEMBER's own journaled bit: the publish gate reads the
/// DOCUMENT a member projects to (PUB-2.15), so a bare-write probe answers
/// the document's state and never the member's.
///
/// Read at `token`'s CLASS (lane 3.4 §4): the dump filters at the presented
/// principal, so this probe presents the OWNER's session — a guest sees an
/// empty slice — to read the owner's own drafts back.
fn drafts_section(port: u16, token: &str) -> String {
    let (st, body) = http(port, "GET", "/dump", Some(token), b"");
    assert_eq!(st, 200);
    let text = String::from_utf8(body).expect("dump is utf-8 text");
    let start = text
        .find(r#""publication.drafts": {"#)
        .expect("the dump's hints section renders the exception set");
    let rest = &text[start..];
    // The map's values are quoted addresses, so the first brace closes it.
    let end = rest.find('}').expect("a rendered map closes");
    rest[..=end].to_string()
}

/// PUB-8.17 (§4.4): `version`'s ABSENT flag INHERITS the source's publication
/// state — in the RECORD: the resolved bit is what the member's `Allocate`
/// journals (PUB-8.18), and the dump's exception set shows it. Since lane 3.1
/// the write path's own two refusals bound what an OWNER may resolve (owner
/// ruling D2b, PUB-8.2): a version of the owner's PRIVATE source is
/// versionless whatever the flag (PUB-2.9, `private_source_versionless`),
/// and an explicit `false` over the owner's PUBLISHED source is the private
/// member the chain admits nothing of (PUB-2.7,
/// `private_version_of_published`) — so the record never holds a private
/// member, and the publish gate's projection of a member to its document
/// (PUB-2.15) and the record agree. Over empty published/private sources so
/// the version snapshots no content and ordinal 1 is always free.
#[test]
fn version_inherits_publication_and_the_write_path_refuses_the_private_arms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    // A bare insert into `doc` at ordinal 1: `Ok` ⇒ its document is private
    // (it commits), the publish refusal ⇒ its document is published.
    let bare_write_published = |doc: &str| -> bool {
        let v = op(port, Some(&bare), &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["p"]}}"#
        ));
        match v["resp"].as_str() {
            Some("rejected") => {
                assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required", "{v}");
                true
            }
            Some("ack_addr") => false,
            _ => panic!("unexpected response for {doc}: {v}"),
        }
    };
    let create = |flag: &str| {
        acked_addr(&op(port, Some(&signed), &format!(
            r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"{flag}}}"#
        )))
    };
    let head = |port: u16| json(&get(port, "/health").1)["log_position"].as_u64().expect("head");
    // Empty PRIVATE and empty PUBLISHED sources (signed, non-first mints).
    let priv_src = create(""); // flagless non-first → private
    let pub_src = create(r#","published":true"#); // explicit true → published

    // PUB-2.9: a version of the owner's PRIVATE source refuses, whatever the
    // flag and whatever the session — the refusal is the store's, behind
    // every daemon gate — and nothing mints. ONE code; the face splits on
    // the flag the client sent, which is the client's to render (PUB-8.3).
    let before = head(port);
    for (token, flag) in [
        (&bare, ""),
        (&bare, r#","published":false"#),
        (&signed, ""),
        (&signed, r#","published":false"#),
        (&signed, r#","published":true"#),
    ] {
        let v = op(port, Some(token), &format!(r#"{{"op":"version","d_src":"{priv_src}"{flag}}}"#));
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["code"].as_str(), Some("private_source_versionless"), "flag {flag:?}: {v}");
        assert_eq!(rej["disposition"].as_str(), Some("permanent"), "a permanent class: {v}");
        assert!(rej.get("detail").is_none(), "the face keys on the code and the flag sent: {v}");
    }
    // …and a BARE `published:true` meets the publish-class gate FIRST
    // (PUB-6.36 slot 4 ahead of slot 5): the face's split arm names the
    // versionless act there (RES-195), the daemon's code being the gate's.
    let v = op(port, Some(&bare), &format!(r#"{{"op":"version","d_src":"{priv_src}","published":true}}"#));
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    assert_eq!(head(port), before, "a refused version mints nothing");

    // Flagless version of a PUBLISHED source → published (inherit). Needs a
    // signed session (bare would meet the publish gate at the version itself).
    let v_pub = acked_addr(&op(port, Some(&signed), &format!(r#"{{"op":"version","d_src":"{pub_src}"}}"#)));
    assert!(bare_write_published(&v_pub), "flagless version of an edition inherits published");
    // An explicit `true` is the same act spelled out.
    let v_true = acked_addr(&op(port, Some(&signed), &format!(r#"{{"op":"version","d_src":"{pub_src}","published":true}}"#)));
    assert!(bare_write_published(&v_true));

    // PUB-2.7: an explicit `false` over the owner's PUBLISHED source refuses
    // — from the bare session (a draft mint, which the publish-class gate
    // does not take) and the signed one alike — so no private member of a
    // published chain is ever minted, and the record has none to show.
    let before = head(port);
    for token in [&bare, &signed] {
        let v = op(port, Some(token), &format!(r#"{{"op":"version","d_src":"{pub_src}","published":false}}"#));
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["code"].as_str(), Some("private_version_of_published"), "{v}");
        assert_eq!(rej["disposition"].as_str(), Some("permanent"));
        assert!(rej.get("detail").is_none(), "{v}");
    }
    assert_eq!(head(port), before, "a refused version mints nothing");
    // A member the owner mints is itself a source whose private arm refuses
    // the same way (PUB-2.10: every version address names a published state).
    let v = op(port, Some(&signed), &format!(r#"{{"op":"version","d_src":"{v_pub}","published":false}}"#));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("private_version_of_published"));

    // The RECORD's bits, off the dump's exception set at the OWNER's class
    // (the guest's slice is empty since lane 3.4): the private source is a
    // draft of the claimant's account; the inherited members are not, and no
    // member of the published chain is.
    let drafts = drafts_section(port, &signed);
    assert!(
        drafts.contains(&format!(r#""{priv_src}": "{CLAIMANT_ACCOUNT}""#)),
        "the flagless non-first mint is a draft in the record: {drafts}"
    );
    assert!(
        !drafts.contains(&format!(r#""{v_pub}""#)) && !drafts.contains(&format!(r#""{v_true}""#)),
        "the versions of an edition inherit published in the record: {drafts}"
    );
    assert!(
        !drafts.contains(&format!(r#""{pub_src}."#)),
        "no member of the published chain is a draft: {drafts}"
    );

    sd.shutdown();
}

/// The NULLIFY class (AUTH-3.7–3.9) and RES-32's entitlement scope in one
/// producer: a credential-typed link's retraction is refused
/// `nullify_not_retraction` to the owner of the home it would land in, and
/// on a CLAIMED board the shape token reaches nobody else — anyone else
/// falls through to execute and answers ω's own `not_owner`,
/// indistinguishable from its non-credential answer.
///
/// Both arms are one producer's, so a reader auditing RES-32 finds the
/// whole rule where the code that enforces it is, and the two verdicts a
/// caller can receive are pinned side by side.
#[test]
fn a_credential_nullify_refuses_the_home_owner_and_masks_everyone_else() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // One fresh credential-typed link in the owner's own doc 1.
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
            enroll_atom(&[&distinct_key(3)])
        ),
    );
    expect_resp(&v, "ack_addr");
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{CLAIMANT_DOC1}.0.1.2"]}},"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
        ),
    );
    let credential = acked_addr(&v);

    // The home's owner gets the shape token.
    let v = op(
        port,
        Some(&signed),
        &format!(r#"{{"op":"nullify","home":"{CLAIMANT_DOC1}","target":"{credential}"}}"#),
    );
    assert_eq!(rejected_detail(&v), "credential_refused:nullify_not_retraction");

    // A stranger naming the same home does not: masked, the op reaches
    // execute, and ω answers. Seated post-claim, which the publish gate
    // admits (delegate presents no input form).
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":31}}"#),
    );
    expect_resp(&v, "ack_addr");
    let stranger = open_session(port, 31);
    let v = op(
        port,
        Some(&stranger),
        &format!(r#"{{"op":"nullify","home":"{CLAIMANT_DOC1}","target":"{credential}"}}"#),
    );
    let rej = expect_resp(&v, "rejected");
    assert_eq!(
        rej["code"].as_str(),
        Some("not_owner"),
        "the shape token is masked, so ω answers as it would for any link: {v}"
    );

    // …and the credential link is untouched by either refusal.
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{credential}"}}"#));
    assert!(
        !expect_resp(&v, "link_value")["link"].is_null(),
        "neither refusal retracted anything"
    );
    sd.shutdown();
}

/// The plain path's slot order (PUB-6.36 as RES-195 places it): the
/// credential-typed `nullify` cell takes slot 5's position, BEHIND the
/// board-state gate in slot 4's — so on an UNCLAIMED board the pre-claim
/// admission gate (PUB-6.35; RES-27) answers `claim_first` and the shape
/// token is never reached, for the home's own owner as for a signed
/// session. Post-claim the order is observable too, since lane 3.5 gave the
/// publish-class gate PUB-6.43's `nullify` row (a retraction lands at its
/// target, so a record against a link in the published doc 1 is a
/// published write): the SAME frame from the SAME bare session answers
/// `signed_session_required` once the board is claimed — slot 4 still ahead
/// of slot 5 — and the SIGNED session, which the gate admits, reaches the
/// cell: `nullify_not_retraction`. The cell moved behind the gate; it did
/// not go away.
#[test]
fn pre_claim_a_credential_nullify_answers_claim_first_ahead_of_the_nullify_cell() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();

    // The ceremony's first four steps (AUTH-5.55 1–4) with the signed claim
    // WITHHELD: delegate from 0, the home mint, the genesis atom and its
    // deposit — which leaves one credential-typed link on an unclaimed
    // board. Spelled out rather than borrowed from `claim_board`, whose
    // fifth step is the one this cell must not take yet.
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
    let v = op(
        port,
        Some(&claimant),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
            enroll_atom_flagged(&[(&anchor_key(), true), (&device_key(), false)])
        ),
    );
    expect_resp(&v, "ack_addr");
    let credential =
        acked_addr(&deposit(port, &claimant, &format!("{CLAIMANT_DOC1}.0.1.1"), T_ENROLL));
    assert!(!claimed(port), "the genesis deposit alone claims nothing");

    let retract = format!(r#"{{"op":"nullify","home":"{CLAIMANT_DOC1}","target":"{credential}"}}"#);

    // The home's owner, bare: the admission gate answers first, in the
    // pinned shape (credential_refused, permanent).
    let v = op(port, Some(&claimant), &retract);
    assert_eq!(rejected_detail(&v), "credential_refused:claim_first");
    assert_eq!(v["disposition"].as_str(), Some("permanent"));
    // A signed session fares no better: pre-claim the gate is session-blind
    // (RES-27: "bare and signed sessions alike").
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(port, Some(&signed), &retract);
    assert_eq!(rejected_detail(&v), "credential_refused:claim_first");
    // The credential link is untouched by either refusal.
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{credential}"}}"#));
    assert!(!expect_resp(&v, "link_value")["link"].is_null(), "nothing was retracted");

    // Step 5 — the signed claim. The SAME frame from the SAME bare session
    // now meets the publish-class gate (slot 4, its claimed arm: the
    // retraction lands in the published doc 1, PUB-6.43's `nullify` row),
    // still ahead of the cell…
    let v = claim_deposit(port, &signed, CLAIMANT_DOC1, CLAIMANT_ACCOUNT);
    expect_resp(&v, "ack_addr");
    assert!(claimed(port), "the claim link flips the board claimed");
    let v = op(port, Some(&claimant), &retract);
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    // …and the signed session, which that gate admits, reaches the cell
    // behind it.
    let v = op(port, Some(&signed), &retract);
    assert_eq!(rejected_detail(&v), "credential_refused:nullify_not_retraction");
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{credential}"}}"#));
    assert!(!expect_resp(&v, "link_value")["link"].is_null(), "nothing was retracted");
    sd.shutdown();
}

/// `key_set` (AUTH-6.18–6.20): fingerprint-ordered entries with flags on
/// `/op`; `not_an_account` on a non-account; the SAME dispatcher as of a
/// historical position on `/op-at` (empty before the genesis).
#[test]
fn key_set_reads_head_and_history_identically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    assert_eq!(v["resp"].as_str(), Some("key_set"), "{v}");
    let enrolled = v["enrolled"].as_array().expect("enrolled");
    assert_eq!(enrolled.len(), 2, "the ceremony's anchor + device key");
    let fps: Vec<&str> =
        enrolled.iter().map(|e| e["fingerprint"].as_str().expect("fp")).collect();
    let mut sorted = fps.clone();
    sorted.sort_unstable();
    assert_eq!(fps, sorted, "fingerprint order");
    assert!(
        enrolled.iter().any(|e| e["anchor"] == Value::Bool(true))
            && enrolled.iter().any(|e| e["anchor"] == Value::Bool(false)),
        "flags as enrolled: {v}"
    );
    assert_eq!(v["retired"].as_array().expect("retired").len(), 0);
    // A non-account address answers the EXISTING code.
    let v = op(port, None, r#"{"op":"key_set","account":"1"}"#);
    assert_eq!(v["code"].as_str(), Some("not_an_account"), "{v}");
    assert_eq!(v["op"].as_str(), Some("key_set"));
    // /op-at at position 2 (the delegate's boundary — mid-ceremony, before
    // the genesis): empty sets, as_of stamped.
    let (st, body) = http(
        port,
        "POST",
        "/op-at",
        None,
        format!(
            r#"{{"at":2,"frame":{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}}}"#
        )
        .as_bytes(),
    );
    assert_eq!(st, 200);
    let v = json(&body);
    assert_eq!(v["resp"].as_str(), Some("key_set"), "{v}");
    assert_eq!(v["as_of"].as_u64(), Some(2));
    assert_eq!(v["enrolled"].as_array().expect("enrolled").len(), 0);
    sd.shutdown();
}

/// `/health.auth` (AUTH-6.13): claimant, local_trust, the two verbatim
/// origin lists — and NO `.mode` field (the negative pin).
#[test]
fn health_auth_publishes_the_pair_and_no_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let auth = json(&get(port, "/health").1)["auth"].clone();
    assert!(auth["claimant"].is_null(), "unclaimed: claimant null");
    assert_eq!(auth["local_trust"].as_bool(), Some(true), "the Phase A default");
    assert!(auth.get("mode").is_none(), "NO .mode field — clients derive the mode");
    let origins = auth["origins"].as_array().expect("origins");
    let dialed = format!("http://127.0.0.1:{port}");
    assert!(origins.iter().any(|o| o.as_str() == Some(dialed.as_str())), "{origins:?}");
    assert_eq!(
        auth["signed_origins"], auth["origins"],
        "unclaimed: the signed set IS the bare set"
    );
    claim_board(port);
    let auth = json(&get(port, "/health").1)["auth"].clone();
    assert_eq!(auth["claimant"].as_str(), Some(CLAIMANT_ACCOUNT), "the claim flips the claimant");
    assert_eq!(
        auth["signed_origins"].as_array().expect("signed").len(),
        0,
        "claimed with no configured origin: the signed set drops to configured alone"
    );
    assert!(
        !auth["origins"].as_array().expect("bare").is_empty(),
        "the bare set keeps the defaults"
    );
    sd.shutdown();
}

/// Restart carries the identity fold back (recovery = the canonical
/// rebuild from the recovered world): the claim, the keys, and a working
/// signed handshake all survive reopen.
#[test]
fn restart_recovers_the_identity_fold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let before = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
        assert_eq!(v["resp"].as_str(), Some("key_set"));
        sd.shutdown();
        v
    };
    let sd = spawn(dir.path()); // recovery; claim_board sees claimed and skips
    let port = sd.port();
    assert!(claimed(port), "the claimant survives restart");
    let after = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    assert_eq!(
        before["enrolled"], after["enrolled"],
        "the rebuilt key table equals the live fold's"
    );
    // The recovered fold verifies a fresh signed handshake, and the signed
    // session deposits into the published home (ordinal 2 — the one legal
    // insert slot after the ceremony's atom, and a declared deposit there is
    // the one insert a published head admits, PUB-2.59).
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["r"],"deposit":true}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    sd.shutdown();
}

/// The op-shape slots ahead of the lock: a credential-typed `emit` is
/// `emit_not_make_link`; a credential `make_link` with a V-spec entity
/// slot is `resolved_from` — and from NO session both are
/// `unauthenticated` (slot 0 first).
#[test]
fn op_shape_slots_fire_ahead_of_the_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let emit = format!(
        r#"{{"op":"emit","home":"{CLAIMANT_DOC1}","ty":[{{"start":"{T_ENROLL}","width":"0.0.0.0.0.0.0.0.1"}}],"from":"{CLAIMANT_ACCOUNT}","to":[]}}"#
    );
    let v = op(port, Some(&signed), &emit);
    assert_eq!(rejected_detail(&v), "credential_refused:emit_not_make_link");
    let v = op(port, None, &emit);
    assert_eq!(v["code"].as_str(), Some("unauthenticated"), "slot 0 masks slot 1: {v}");
    let vspec_from = format!(
        r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":[{{"source":"{CLAIMANT_DOC1}","span":{{"start":"1.1","width":"0.1"}}}}],"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
    );
    let v = op(port, Some(&signed), &vspec_from);
    assert_eq!(rejected_detail(&v), "credential_refused:resolved_from");
    sd.shutdown();
}

/// The `Origin` header at the wire — the bare-bind rule's other conjunct,
/// and the fence wire.md's `Access-Control-Allow-Origin: *` rests on
/// (§Cross-origin access: a foreign page's POST is fenced by the daemon,
/// not by what the browser lets it read back). No other test in this suite
/// sends the header, so the path from `read_request` to `bare_bind_allowed`
/// was carried by nothing: with it cut, `origin` is `None` everywhere and
/// every foreign origin is admitted.
///
/// The second half is the rule the three-valued answer exists for: a
/// refused origin runs THAT REQUEST as a guest and the binding LIVES — no
/// death, no signal.
#[test]
fn the_origin_header_fences_the_bare_bind_without_killing_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let dialed = format!("http://127.0.0.1:{port}");
    let sibling = format!("http://localhost:{port}"); // a loopback default
    let bare_body = format!("{{\"principal\":{CLAIMANT_PRINCIPAL}}}");
    let draft = format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#);

    // POST /session, bare: the dialed origin and its loopback sibling bind;
    // a foreign one is the ONE 401.
    for ok in [&dialed, &sibling] {
        let (st, _, body) =
            http_with_origin(port, "POST", "/session", None, ok, bare_body.as_bytes());
        assert_eq!(st, 200, "'{ok}' is in the bare set: {}", String::from_utf8_lossy(&body));
    }
    for bad in ["https://evil.example", "null", "http://127.0.0.1:9999"] {
        let (st, _, body) =
            http_with_origin(port, "POST", "/session", None, bad, bare_body.as_bytes());
        assert_eq!(st, 401, "'{bad}' is outside the bare set: {}", String::from_utf8_lossy(&body));
        assert_eq!(json(&body)["error"].as_str(), Some("session_rejected"));
    }

    // A LIVE bare session, presented from a foreign origin: that request
    // runs as a guest…
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, headers, body) = http_with_origin(
        port,
        "POST",
        "/op",
        Some(&bare),
        "https://evil.example",
        draft.as_bytes(),
    );
    assert_eq!(st, 200);
    assert_eq!(
        json(&body)["code"].as_str(),
        Some("unauthenticated"),
        "a bare session off the bare set writes nothing: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        header(&headers, "Skepd-Session").is_none(),
        "refused-for-this-request is NOT death: the binding lives and nothing signals"
    );
    // …and the SAME token still writes, which is what makes the line above
    // a statement about the request rather than about the session.
    expect_resp(&op(port, Some(&bare), &draft), "ack_addr");
    let (st, _, body) =
        http_with_origin(port, "POST", "/op", Some(&bare), &dialed, draft.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    expect_resp(&json(&body), "ack_addr");

    sd.shutdown();
}

/// Retirement, whole: the anchor gate on both its triggers, and the session
/// death a retirement produces. `T_RETIRE` was declared and used by no
/// test, so the retire kind, `anchor_session_required`, and one of the four
/// documented ways a session ends were all unwatched — on the path that IS
/// credential revocation.
#[test]
fn retiring_a_key_needs_an_anchor_session_and_kills_that_keys_sessions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let device_fp = fingerprint_hex(&device_key());
    let anchor_fp = fingerprint_hex(&anchor_key());
    let device_token = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let anchor_token = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());

    // Trigger 1 — an ANCHOR retirement from a non-anchor session refuses.
    let anchor_retire = record_atom(port, &device_token, 2, &retire_atom(&[&anchor_fp]));
    let v = deposit(port, &device_token, &anchor_retire, T_RETIRE);
    assert_eq!(rejected_detail(&v), "credential_refused:anchor_session_required");
    // …and a BARE session never satisfies it either (§Credential refusals),
    // which is slot (6) answering ahead of slot (7)'s
    // `signed_session_required` — the order wire.md pins. The record atom is
    // the signed session's, since a bare write into the published home dies
    // at the publish gate before the credential path is reached at all.
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let v = deposit(port, &bare, &anchor_retire, T_RETIRE);
    assert_eq!(rejected_detail(&v), "credential_refused:anchor_session_required");

    // Trigger 2 — a post-genesis ANCHOR-FLAGGED enrollment, same gate.
    let fresh = distinct_key(9);
    let flagged_enroll =
        record_atom(port, &device_token, 3, &enroll_atom_flagged(&[(&fresh, true)]));
    let v = deposit(port, &device_token, &flagged_enroll, T_ENROLL);
    assert_eq!(rejected_detail(&v), "credential_refused:anchor_session_required");
    // The same enrollment UNFLAGGED passes, so the gate is the FLAG and not
    // the act.
    let plain_enroll =
        record_atom(port, &device_token, 4, &enroll_atom_flagged(&[(&fresh, false)]));
    expect_resp(&deposit(port, &device_token, &plain_enroll, T_ENROLL), "ack_addr");

    // The anchor's own session retires the device key.
    let device_retire = record_atom(port, &anchor_token, 5, &retire_atom(&[&device_fp]));
    expect_resp(&deposit(port, &anchor_token, &device_retire, T_RETIRE), "ack_addr");

    // key_set moves the fingerprint from enrolled to retired.
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    let names = |field: &str| -> Vec<String> {
        v[field]
            .as_array()
            .unwrap_or_else(|| panic!("{field}: {v}"))
            .iter()
            .map(|e| e["fingerprint"].as_str().expect("fp").to_string())
            .collect()
    };
    assert!(!names("enrolled").contains(&device_fp), "the retired key leaves enrolled: {v}");
    assert!(names("retired").contains(&device_fp), "and appears retired: {v}");
    assert!(names("enrolled").contains(&anchor_fp), "the anchor is untouched: {v}");

    // THE POINT: the session that key established is dead — closed and
    // signalled, not silently a guest.
    let (st, headers, body) = http_full(
        port,
        "POST",
        "/op",
        Some(&device_token),
        format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#).as_bytes(),
    );
    assert_eq!(st, 200);
    assert_eq!(
        json(&body)["code"].as_str(),
        Some("unauthenticated"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        header(&headers, "Skepd-Session"),
        Some("closed"),
        "a retirement kills the sessions its key established"
    );
    // And no NEW session can be established with it: the handshake reads
    // the same enrolled set.
    let (st, body) =
        http(port, "GET", &format!("/challenge?principal={CLAIMANT_PRINCIPAL}"), None, b"");
    assert_eq!(st, 200);
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();
    let origin = format!("http://127.0.0.1:{port}");
    let sig = sign_session(&device_key(), &origin, &nonce, CLAIMANT_PRINCIPAL);
    let (st, _) = http(
        port,
        "POST",
        "/session",
        None,
        format!(
            "{{\"principal\":{CLAIMANT_PRINCIPAL},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
        )
        .as_bytes(),
    );
    assert_eq!(st, 401, "a retired key signs nothing");

    // The anchor's own session is untouched by the retirement it made.
    let v = op(
        port,
        Some(&anchor_token),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    expect_resp(&v, "ack_addr");

    sd.shutdown();
}

/// ENFORCING (§Identity) — the mode no other test instantiates, and the
/// claim flip as the one runtime transition that reaches it, since
/// `--local-trust` is fixed at open and pre-claim the flag is not consulted.
///
/// The load-bearing half is that a bare binding DIES rather than being
/// refused: `BareBind::ModeRefused` maps to `BindingDead` and
/// `RequestRefused` to a live binding, which is the whole reason that enum
/// has three arms, and no test at any level had covered the first.
#[test]
fn the_claim_flip_into_enforcing_kills_every_bare_binding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), false);
    let port = sd.port();
    // Pre-claim the flag is not consulted, so the bare bind binds and the
    // ceremony — which is bare work until its last step — runs.
    let bare = open_session(port, 0);
    expect_resp(&op(port, Some(&bare), r#"{"op":"next_account_prefix","parent":"1"}"#), "maybe_addr");
    claim_board(port);
    assert!(claimed(port));

    // The flip retires it: closed and signalled, not a live binding refused
    // for this request.
    let (st, headers, body) =
        http_full(port, "POST", "/op", Some(&bare), br#"{"op":"register_node","addr":"1.7"}"#);
    assert_eq!(st, 200);
    assert_eq!(
        json(&body)["code"].as_str(),
        Some("unauthenticated"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        header(&headers, "Skepd-Session"),
        Some("closed"),
        "ENFORCING kills a bare binding at presentation; it does not merely refuse it"
    );

    // No new bare session opens…
    let (st, body) = http(port, "POST", "/session", None, br#"{"principal":0}"#);
    assert_eq!(st, 401, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("session_rejected"));
    // …and the signed arm is unaffected: only signed sessions write.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    expect_resp(&v, "ack_addr");

    // /health publishes the pair the mode derives from — there is no
    // `.mode` field, so this is what a client reads it off.
    let auth = json(&get(port, "/health").1)["auth"].clone();
    assert_eq!(auth["local_trust"].as_bool(), Some(false));
    assert!(!auth["claimant"].is_null(), "claimed + !local_trust IS enforcing: {auth}");

    sd.shutdown();
}

/// wire.md §Sessions fixes the death signal's routes as a table: six carry
/// it, four are token-blind. Two rows were watched. The negative half
/// matters as much — `/health` is what a client polls, and a signal there
/// says a session died that did not.
#[test]
fn the_death_signal_rides_exactly_the_documented_routes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    // A token whose binding this daemon has closed.
    let dead = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (st, _, _) = http_full(port, "POST", "/session/close", Some(&dead), b"");
    assert_eq!(st, 204);

    let signalled = |method: &str, path: &str, body: &[u8]| -> Option<String> {
        let (_, headers, _) = http_full(port, method, path, Some(&dead), body);
        header(&headers, "Skepd-Session").map(str::to_string)
    };

    let mut carries: Vec<(&str, &str, &[u8])> = vec![
        ("POST", "/op", br#"{"op":"next_account_prefix","parent":"1"}"#),
        ("POST", "/op-at", br#"{"at":0,"frame":{"op":"next_account_prefix","parent":"1"}}"#),
        ("GET", "/changes?since=0", b""),
        ("POST", "/session/close", b""),
    ];
    #[cfg(feature = "observe")]
    carries.push(("GET", "/dump", b""));
    for (method, path, body) in carries {
        assert_eq!(
            signalled(method, path, body).as_deref(),
            Some("closed"),
            "{method} {path} carries the death signal"
        );
    }

    // Token-blind: presenting the same dead token changes nothing.
    let blind: [(&str, &str, &[u8]); 3] = [
        ("GET", "/health", b""),
        ("GET", "/challenge?principal=1", b""),
        ("POST", "/session", br#"{"principal":1}"#),
    ];
    for (method, path, body) in blind {
        assert_eq!(
            signalled(method, path, body),
            None,
            "{method} {path} is token-blind: no signal, however dead the token"
        );
    }

    // `/events` — the one signal that rides a STREAM HEAD rather than a
    // reply, written once, at open.
    let (mut stream, head) = Sse::connect_with_token(port, &dead);
    assert!(
        head.to_ascii_lowercase().contains("skepd-session: closed"),
        "a dead token meets the signal on the stream's own head: {head}"
    );
    stream.expect_commit(); // and the stream still serves
    let live = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (mut alive, head) = Sse::connect_with_token(port, &live);
    assert!(
        !head.to_ascii_lowercase().contains("skepd-session: closed"),
        "a live token's stream head carries no death signal: {head}"
    );
    alive.expect_commit();

    sd.shutdown();
}

/// AUTH-4.33 / wire.md §Sessions: every enrolled key is tried in
/// fingerprint order, "no cutoff, ever". Every signed handshake in this
/// suite signs with the device key, and whether that key sorts first is an
/// accident of SHA-256 over two fixed seeds — so a cutoff-after-first was
/// caught by chance or not at all. The signer is CHOSEN here from
/// `key_set`'s own published order, which makes both ends instances of the
/// law whatever the seeds hash to.
#[test]
fn every_enrolled_key_signs_including_the_last_in_fingerprint_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    let fps: Vec<String> = v["enrolled"]
        .as_array()
        .expect("enrolled")
        .iter()
        .map(|e| e["fingerprint"].as_str().expect("fp").to_string())
        .collect();
    assert_eq!(fps.len(), 2, "the ceremony enrolls the anchor and the device key: {v}");
    let by_fp = |want: &str| -> SigningKey {
        for k in [anchor_key(), device_key()] {
            if fingerprint_hex(&k) == want {
                return k;
            }
        }
        panic!("{want} is one of the ceremony's keys");
    };
    for (which, fp) in [("first", &fps[0]), ("last", &fps[1])] {
        let token = open_signed_session(port, CLAIMANT_PRINCIPAL, &by_fp(fp));
        let v = op(
            port,
            Some(&token),
            &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
        );
        assert_eq!(
            v["resp"].as_str(),
            Some("ack_addr"),
            "{which}-in-fingerprint-order established a session that writes: {v}"
        );
    }
    sd.shutdown();
}

/// The ONE 401 (AUTH-6.5), over the FAMILY of causes rather than one point:
/// every handshake failure answers the same bytes, because the whole design
/// of `SessionRejected` is that a client learns nothing about WHICH check
/// failed. Each row is a different arm of `handshake`.
///
/// Expiry is the one cause deliberately omitted: reaching it needs the 60 s
/// TTL, and a sleeping test is the wrong trade.
#[test]
fn every_handshake_failure_answers_the_same_401_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let origin = format!("http://127.0.0.1:{port}");
    let nonce_for = |principal: u64| {
        let (st, body) =
            http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
        assert_eq!(st, 200);
        json(&body)["nonce"].as_str().expect("nonce").to_string()
    };
    let signed_body = |principal: u64, nonce: &str, org: &str, sk: &SigningKey| {
        let sig = sign_session(sk, org, nonce, principal);
        format!(
            "{{\"principal\":{principal},\"nonce\":\"{nonce}\",\"origin\":\"{org}\",\"sig\":\"{sig}\"}}"
        )
    };

    // The nonce this row reuses must first be SPENT on a success.
    let reused = nonce_for(p);
    let (st, _) = http(
        port,
        "POST",
        "/session",
        None,
        signed_body(p, &reused, &origin, &device_key()).as_bytes(),
    );
    assert_eq!(st, 200, "the first use of a nonce succeeds");

    let rows: Vec<(&str, String)> = vec![
        (
            "an origin outside the signed set",
            signed_body(p, &nonce_for(p), "https://evil.example", &device_key()),
        ),
        ("an unknown nonce", signed_body(p, &"ab".repeat(32), &origin, &device_key())),
        ("a reused nonce", signed_body(p, &reused, &origin, &device_key())),
        (
            "a nonce issued for another principal",
            signed_body(p, &nonce_for(p + 1), &origin, &device_key()),
        ),
        (
            "a principal with no account",
            signed_body(p + 77, &nonce_for(p + 77), &origin, &device_key()),
        ),
        (
            "a signature from an unenrolled key",
            signed_body(p, &nonce_for(p), &origin, &distinct_key(21)),
        ),
        (
            "principal 0, whose subject is the claimant, signing with a foreign key",
            signed_body(0, &nonce_for(0), &origin, &distinct_key(22)),
        ),
    ];
    for (what, body) in rows {
        let (st, headers, body) = http_full(port, "POST", "/session", None, body.as_bytes());
        assert_eq!(st, 401, "{what}");
        assert_eq!(
            String::from_utf8(body).expect("utf-8"),
            r#"{"error":"session_rejected"}"#,
            "{what}: one code, byte-identical, no detail"
        );
        assert!(header(&headers, "Skepd-Session").is_none(), "{what}: /session is token-blind");
    }
    // The BARE arm answers the same bytes: its refusal needs an origin
    // outside the bare set, which only the header can supply.
    let (st, _, body) = http_with_origin(
        port,
        "POST",
        "/session",
        None,
        "https://evil.example",
        format!("{{\"principal\":{p}}}").as_bytes(),
    );
    assert_eq!(st, 401);
    assert_eq!(
        String::from_utf8(body).expect("utf-8"),
        r#"{"error":"session_rejected"}"#,
        "the bare arm's refusal is the same one code"
    );

    sd.shutdown();
}

/// AUTH-4.36's pinned order at the ONE point it is observable: the signed
/// arm tests the ORIGIN SET before it BURNS, so a body refused for its
/// origin leaves its nonce spendable. Every other 401 cause sits at or
/// behind the burn and spends one.
///
/// The row list above cannot see this. It gives each cause a nonce of its
/// own, so a burn moved ahead of the origin check answers every row
/// identically — and the module values the property elsewhere in the same
/// file, `Nonce::parse_hex` refusing uppercase precisely so the fault is "a
/// 400 syntax fault whose nonce SURVIVES, never a burned 401". Inverted,
/// the board spends a nonce on every attempt from a misconfigured origin,
/// which is the case `ClaimedWithEmptyConfigured` exists to warn about, and
/// a client that fetched one nonce and fixed its origin cannot retry.
#[test]
fn an_origin_refusal_precedes_the_burn_and_spends_no_nonce() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let origin = format!("http://127.0.0.1:{port}");
    let (st, body) = http(port, "GET", &format!("/challenge?principal={p}"), None, b"");
    assert_eq!(st, 200);
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();

    // Refused at step 2, and signed FOR that origin, so nothing else about
    // the body is wrong and no later step could be what refused it.
    let bad = "https://evil.example";
    let sig = sign_session(&device_key(), bad, &nonce, p);
    let refused = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{bad}\",\"sig\":\"{sig}\"}}"
    );
    let (st, body) = http(port, "POST", "/session", None, refused.as_bytes());
    assert_eq!(st, 401, "an origin outside the signed set: {}", String::from_utf8_lossy(&body));

    // The SAME nonce, signed for an admitted origin, still opens a session.
    let sig = sign_session(&device_key(), &origin, &nonce, p);
    let retry = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
    );
    let (st, body) = http(port, "POST", "/session", None, retry.as_bytes());
    assert_eq!(
        st, 200,
        "the origin refusal never reached the burn: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(json(&body)["session"].is_string());

    sd.shutdown();
}

/// The four hex case policies are documented as the ONE thing the crate's
/// hex parsers differ by, and three are pinned: the nonce and the token
/// REFUSE uppercase (`the_handshake_lifecycle_and_a_400_that_spends_no_nonce`
/// and the codec's own token round trip), the content forms FOLD it. The
/// signature folds too — it is decoded and never framed — and nothing
/// watched it, because every signature in this suite comes from
/// `sign_session`, which encodes lowercase.
///
/// So merging `parse_sig` onto the nonce's strict `parse_lower_hex` — the
/// obvious cleanup of two near-identical two-characters-per-byte loops in
/// one file — refuses a signature a client legitimately sent, as `400
/// malformed_session_request`.
#[test]
fn an_uppercase_signature_is_folded_where_an_uppercase_nonce_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let origin = format!("http://127.0.0.1:{port}");
    let (st, body) = http(port, "GET", &format!("/challenge?principal={p}"), None, b"");
    assert_eq!(st, 200);
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();
    let sig = sign_session(&device_key(), &origin, &nonce, p);
    assert_eq!(
        sig,
        sig.to_lowercase(),
        "the fixture's encoder is lowercase: that is why this cell needs writing"
    );
    let upper = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{}\"}}",
        sig.to_uppercase()
    );
    let (st, body) = http(port, "POST", "/session", None, upper.as_bytes());
    assert_eq!(st, 200, "an uppercase signature decodes: {}", String::from_utf8_lossy(&body));
    assert!(json(&body)["session"].is_string());

    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════
// THE BLOCKED-PREFIX LIST (AUTH-1.44, AUTH-4.36 step 4b, AUTH-4.63/4.64 item
// 11, AUTH-4.70, AUTH-6.5) and THE TWO ACCESSORS (AUTH-4.30) — the vectors
// RES-65 item 7 (n), RES-66 item 4 (i), RES-67 item 5 (l), RES-68 item 7 (m),
// RES-115 and RES-140 record for the skepd lane.
//
// The list is CONFIG: every cell here moves it the way a serving layer does —
// an issue written beside the supply file and renamed over it
// (`issue_blocked_list`) — and never through the wire, which has no door for
// it. The daemon looks at the file at the head of every request, so an issue
// is in force at the first request after it.
// ═══════════════════════════════════════════════════════════════════════════

/// Takedown records' version addresses, as entries cite them. The daemon
/// reads no record and knows no takedown — it echoes the address — so these
/// name nothing on the board; each is distinct so a 403 says WHICH entry
/// answered.
const RECORD_MEMBER: &str = "1.0.1.0.7.1";
const RECORD_UNDER: &str = "1.0.1.0.8.1";
const RECORD_CLAIMANT: &str = "1.0.1.0.9.1";
const RECORD_SEAT: &str = "1.0.1.0.10.1";
const RECORD_HOST: &str = "1.0.1.0.11.1";
const RECORD_NODE: &str = "1.0.1.0.12.1";

/// The bootstrap principal, which maps to the CLAIMANT on both accessors
/// (AUTH-4.30) — so it signs with the claimant's keys, and an entry that
/// covers the claimant covers it.
const PRINCIPAL_ZERO: u64 = 0;

/// An OFF-BOARD host's account — not under the board's own local `1`
/// (REG-1.66), which is the test AUTH-4.36 step 4b names for "not an account
/// of this board".
const OFF_BOARD_HOST: &str = "2.0.7";

/// A CLAIMED board (CLAIMED-PERMISSIVE) with the list's supply named: the
/// data dir and the supply file sit side by side under `root`, so a restart
/// over the same `root` meets the same file. The first issue is the EMPTY
/// list unless the file is already there — the restart cells' case.
fn spawn_listed(root: &std::path::Path) -> (skepd::Skepd, std::path::PathBuf) {
    let list = root.join("blocked.json");
    if !list.exists() {
        issue_blocked_list(&list, BlockedHeader::default(), &[]);
    }
    let data = root.join("data");
    std::fs::create_dir_all(&data).expect("the data dir");
    let sd = spawn_with_blocked_prefixes(&data, true, Some(&list));
    claim_board(sd.port());
    (sd, list)
}

/// A top-level member: delegated from the bootstrap principal and KEYED by a
/// hire into its genesis registry, the claimant's doc 1 (AUTH-2.62). The
/// registrar's session is the ANCHOR's, so the genesis commits whatever
/// grade the anchor gate asks of it.
fn keyed_member(port: u16, anchor: &str, id: u64, key: &SigningKey) -> String {
    let (account, _) = bootstrap_delegate(port, id);
    hire(port, anchor, CLAIMANT_DOC1, &account, id, key);
    account
}

/// The exact bytes AUTH-6.5 pins for the blocked handshake.
fn prefix_blocked_body(record: &str) -> String {
    format!(r#"{{"error":"prefix_blocked","record":"{record}"}}"#)
}

/// Assert one signed handshake answers the 403 with `record` — the status,
/// the BYTES, and no death signal (a blocked handshake is a refusal with no
/// entry: nothing to close).
fn assert_blocked(port: u16, principal: u64, sk: &SigningKey, record: &str, what: &str) {
    let (st, headers, body) = signed_handshake(port, principal, sk);
    assert_eq!(st, 403, "{what}: {}", String::from_utf8_lossy(&body));
    assert_eq!(String::from_utf8(body).expect("utf-8"), prefix_blocked_body(record), "{what}");
    assert!(header(&headers, "Skepd-Session").is_none(), "{what}: /session is token-blind");
}

/// Present `token` on a read and answer whether the daemon signalled its
/// death — the lazy kill's observable, on the cheapest route of the set.
fn presented_dead(port: u16, token: &str) -> bool {
    let (st, headers, _) = http_full(
        port,
        "POST",
        "/op",
        Some(token),
        br#"{"op":"next_account_prefix","parent":"1"}"#,
    );
    assert_eq!(st, 200);
    header(&headers, "Skepd-Session") == Some("closed")
}

/// RES-65 item 7 (n), the handshake's own cells: a signed body under a
/// listed prefix answers `403 prefix_blocked` with the record's address — the
/// nonce SPENT, the same 403 under a garbage `sig` (not a 400, not a 401:
/// the signature is never reached) — while a sibling prefix's body answers
/// 200; `X.1` under listed `X` is refused (the prefix test); the address
/// carried is the LONGEST covering prefix's and a party under two entries is
/// admitted only when both are lifted; a LIFT admits.
///
/// And step 4b's POSITION (AUTH-4.36): behind the origin set and the burn,
/// ahead of the key set — so an origin refusal still precedes it and spends
/// no nonce, and an unknown principal is never told a prefix is blocked.
#[test]
fn a_listed_prefix_answers_the_403_with_its_record_after_the_burn_and_before_the_key_set() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let (member_key, sibling_key) = (distinct_key(31), distinct_key(32));
    let member = keyed_member(port, &anchor, 931, &member_key);
    let sibling = keyed_member(port, &anchor, 932, &sibling_key);
    // The member's first sub-account holds no set of its own: it opens BY
    // REFERENCE against the member's, and it sits UNDER the member's prefix.
    let (under, _) = delegate_under(port, &open_session(port, 931), &member, 933);
    assert!(under.starts_with(&format!("{member}.")), "{under} sits under {member}");

    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);

    // The 403, its bytes, and the nonce SPENT: the same body again dies at
    // the burn (step 3 stands ahead of 4b) and is the ordinary 401.
    let nonce_for = |principal: u64| {
        let (st, body) =
            http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
        assert_eq!(st, 200);
        json(&body)["nonce"].as_str().expect("nonce").to_string()
    };
    let body_with = |principal: u64, nonce: &str, org: &str, sig: &str| {
        format!(
            "{{\"principal\":{principal},\"nonce\":\"{nonce}\",\"origin\":\"{org}\",\"sig\":\"{sig}\"}}"
        )
    };
    let nonce = nonce_for(931);
    let honest = body_with(931, &nonce, &origin, &sign_session(&member_key, &origin, &nonce, 931));
    let (st, headers, body) = http_full(port, "POST", "/session", None, honest.as_bytes());
    assert_eq!(st, 403, "{}", String::from_utf8_lossy(&body));
    assert_eq!(String::from_utf8(body).expect("utf-8"), prefix_blocked_body(RECORD_MEMBER));
    assert!(header(&headers, "Skepd-Session").is_none(), "a refusal with no entry: no signal");
    let (st, body) = http(port, "POST", "/session", None, honest.as_bytes());
    assert_eq!(st, 401, "the 403 SPENT the nonce: {}", String::from_utf8_lossy(&body));
    assert_eq!(String::from_utf8(body).expect("utf-8"), r#"{"error":"session_rejected"}"#);

    // A garbage `sig` — well-formed, signing nothing — and a foreign key's:
    // the SAME 403, because no key set is read and no signature verified.
    let nonce = nonce_for(931);
    let garbage = body_with(931, &nonce, &origin, &"00".repeat(64));
    let (st, body) = http(port, "POST", "/session", None, garbage.as_bytes());
    assert_eq!(st, 403, "not a 400 and not a 401: {}", String::from_utf8_lossy(&body));
    assert_eq!(String::from_utf8(body).expect("utf-8"), prefix_blocked_body(RECORD_MEMBER));
    assert_blocked(port, 931, &distinct_key(99), RECORD_MEMBER, "a foreign key's signature");

    // Step 2 still stands AHEAD: a listed principal at a foreign origin is
    // the 401, and its nonce SURVIVES to meet the 403 at the right origin.
    let nonce = nonce_for(931);
    let evil = "https://evil.example";
    let foreign = body_with(931, &nonce, evil, &sign_session(&member_key, evil, &nonce, 931));
    let (st, _) = http(port, "POST", "/session", None, foreign.as_bytes());
    assert_eq!(st, 401, "the origin set is tested before the burn and before the block");
    let retry = body_with(931, &nonce, &origin, &sign_session(&member_key, &origin, &nonce, 931));
    let (st, _) = http(port, "POST", "/session", None, retry.as_bytes());
    assert_eq!(st, 403, "and the origin refusal spent nothing");
    // …and a principal the board does not know is never told of a block:
    // there is no account to test, so step 4's own refusal answers.
    let (st, _, body) = signed_handshake(port, 931_931, &member_key);
    assert_eq!(st, 401);
    assert_eq!(String::from_utf8(body).expect("utf-8"), r#"{"error":"session_rejected"}"#);

    // A SIBLING prefix is admitted, and its session writes.
    let sibling_token = open_signed_session(port, 932, &sibling_key);
    expect_resp(&op(port, Some(&sibling_token), &create_frame(&sibling, None)), "ack_addr");

    // `X.1` under listed `X`: refused with X's record — the prefix test.
    assert_blocked(port, 933, &member_key, RECORD_MEMBER, "the account under the listed prefix");

    // TWO covering entries: the LONGEST prefix's record answers, and lifting
    // it alone leaves the party under the other.
    issue_blocked_list(
        &list,
        BlockedHeader::default(),
        &[(&member, RECORD_MEMBER), (&under, RECORD_UNDER)],
    );
    assert_blocked(port, 933, &member_key, RECORD_UNDER, "the longest covering prefix");
    assert_blocked(port, 931, &member_key, RECORD_MEMBER, "the shorter entry's own party");
    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    assert_blocked(port, 933, &member_key, RECORD_MEMBER, "one of two lifted: still covered");

    // THE LIFT — an issue in which the entry is absent — admits both.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    let member_token = open_signed_session(port, 931, &member_key);
    expect_resp(&op(port, Some(&member_token), &create_frame(&member, None)), "ack_addr");
    open_signed_session(port, 933, &member_key);

    sd.shutdown();
}

/// AUTH-4.64 item 11 — THE KILL. A live session under prefix `X`, the list
/// re-issued with an entry covering `X`: its next request of EITHER kind
/// carries `Skepd-Session: closed` on EACH route of the enumerated set, its
/// next write answers `unauthenticated` with the header on that SAME
/// response, and no `/changes` entry of it carries a position after the
/// install. ARM-BLIND (a bare binding dies as a signed one does) and BY THE
/// PREFIX TEST (a session under `X.1` dies with `X`'s entry). A sibling
/// prefix's session is untouched — its M10 session and memo intact. After
/// the LIFT the same principal's fresh handshake answers 200, and nothing
/// is resurrected.
#[test]
fn a_reissued_entry_kills_the_live_sessions_under_it_on_every_route_of_the_set() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let (member_key, sibling_key) = (distinct_key(31), distinct_key(32));
    let member = keyed_member(port, &anchor, 931, &member_key);
    let sibling = keyed_member(port, &anchor, 932, &sibling_key);
    delegate_under(port, &open_session(port, 931), &member, 933);

    // One LIVE binding per route, opened before the install: a dead token is
    // closed at its first presentation, and an UNKNOWN token signals too, so
    // a binding presented twice would prove nothing about the second route.
    let live = || open_signed_session(port, 931, &member_key);
    let (on_read, on_write, on_op_at, on_changes, on_close, on_events) =
        (live(), live(), live(), live(), live(), live());
    #[cfg(feature = "observe")]
    let on_dump = live();
    let bare = open_session(port, 931);
    let under = open_signed_session(port, 933, &member_key);
    // The sibling's session holds a MEMOIZED ack — what "its M10 session and
    // memo intact" is judged against afterwards.
    let sibling_token = open_signed_session(port, 932, &sibling_key);
    let memoized = format!(r#"{{"op":"create_new_document","id":"s1","account":"{sibling}"}}"#);
    let original = op(port, Some(&sibling_token), &memoized);
    expect_resp(&original, "ack_addr");
    // The member writes while it still can.
    expect_resp(&op(port, Some(&on_write), &create_frame(&member, None)), "ack_addr");

    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    // The first request after the issue installs it; the head it reports is
    // the position the install stands at.
    let installed_at = head_position(port);
    // The list is CONFIG and is published nowhere: `/health.auth` keeps its
    // four members with a list in force (AUTH-6.13's negative pin).
    let auth = json(&get(port, "/health").1)["auth"].clone();
    let members: Vec<&str> = auth.as_object().expect("auth").keys().map(String::as_str).collect();
    assert_eq!(members, ["claimant", "local_trust", "origins", "signed_origins"], "{auth}");

    // The next WRITE: `unauthenticated`, the signal on that SAME response.
    let (st, headers, body) =
        http_full(port, "POST", "/op", Some(&on_write), create_frame(&member, None).as_bytes());
    assert_eq!(st, 200);
    assert_eq!(json(&body)["code"].as_str(), Some("unauthenticated"), "{:?}", json(&body));
    assert_eq!(header(&headers, "Skepd-Session"), Some("closed"));
    assert_eq!(header(&headers, "Access-Control-Expose-Headers"), Some("Skepd-Session"));
    assert_eq!(head_position(port), installed_at, "and the refused write committed nothing");

    // EACH route of the enumerated set (AUTH-4.43), a live binding apiece.
    let mut routes: Vec<(&str, &str, &str, &[u8])> = vec![
        ("POST", "/op", &on_read, br#"{"op":"next_account_prefix","parent":"1"}"#),
        ("POST", "/op-at", &on_op_at, br#"{"at":0,"frame":{"op":"next_account_prefix","parent":"1"}}"#),
        ("GET", "/changes?since=0", &on_changes, b""),
        ("POST", "/session/close", &on_close, b""),
    ];
    #[cfg(feature = "observe")]
    routes.push(("GET", "/dump", &on_dump, b""));
    for (method, path, token, body) in routes {
        let (_, headers, _) = http_full(port, method, path, Some(token), body);
        assert_eq!(
            header(&headers, "Skepd-Session"),
            Some("closed"),
            "{method} {path}: a binding under the listed prefix dies at its presentation"
        );
    }
    let (mut stream, head) = Sse::connect_with_token(port, &on_events);
    assert!(
        head.to_ascii_lowercase().contains("skepd-session: closed"),
        "/events meets the block before the stream opens: {head}"
    );

    // ARM-BLIND, and BY THE PREFIX TEST.
    assert!(presented_dead(port, &bare), "a BARE binding under the prefix dies as a signed one does");
    assert!(presented_dead(port, &under), "a session under X.1 dies with X's entry");

    // The sibling prefix is UNTOUCHED: its session lives, and M10's memo
    // still holds its ack — the ORIGINAL answer, not a second mint.
    assert!(!presented_dead(port, &sibling_token), "a sibling prefix's session is untouched");
    assert_eq!(
        op(port, Some(&sibling_token), &memoized),
        original,
        "the sibling's memoized ack replays: its M10 session and memo are intact"
    );
    stream.expect_commit(); // the dead token's stream still serves, as a guest's
    expect_resp(&op(port, Some(&sibling_token), &create_frame(&sibling, None)), "ack_addr");

    // No `/changes` entry of the killed key stands after the install.
    let member_fp = fingerprint_hex(&member_key);
    let page = json(&http(port, "GET", &format!("/changes?since={installed_at}"), Some(&anchor), b"").1);
    for entry in page["changes"].as_array().expect("changes") {
        assert_ne!(entry["key"].as_str(), Some(member_fp.as_str()), "after the install: {entry}");
    }

    // THE LIFT admits the next handshake and resurrects nothing.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    let again = open_signed_session(port, 931, &member_key);
    expect_resp(&op(port, Some(&again), &create_frame(&member, None)), "ack_addr");
    assert!(presented_dead(port, &on_write), "a killed binding stays gone: the closed entry is no entry");

    sd.shutdown();
}

/// THE HEADER ROWS (RES-66 item 4 (i), RES-67 item 5 (l), RES-68 item 7 (m);
/// AUTH-4.64 item 11) — the install's two INERT comparands, at the four A3
/// cells. An entry covering (a) the configured OPERATOR account (the claimant
/// where the header names none), or (b) — where that account is NOT an
/// account of this board — the board's BINDING-WRITING account (the claimant
/// where the header omits it), is ignored at install: its party's sessions
/// live and its handshakes are admitted, principal 0's with them where the
/// comparand is the claimant. Every other entry installs.
///
/// One board, one reissue per row: the header is config, and the claimant —
/// "the OLD REGISTRAR" of the two fork rows — is whoever claimed it.
#[test]
fn the_headers_two_comparands_are_inert_at_the_four_lineage_cells() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let (seat_key, member_key) = (distinct_key(41), distinct_key(42));
    let seat = keyed_member(port, &anchor, 941, &seat_key);
    let member = keyed_member(port, &anchor, 942, &member_key);
    let claimant = CLAIMANT_ACCOUNT;
    let zero = PRINCIPAL_ZERO;

    // THE ROOT (and every unforked self-served board): the header names
    // none, so (a) and (b) are ONE account, the claimant. An entry over it —
    // or over any prefix ABOVE it, the board's own node included — is inert;
    // a member's installs.
    let claimant_live = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let zero_live = open_signed_session(port, zero, &device_key());
    issue_blocked_list(
        &list,
        BlockedHeader::default(),
        &[(claimant, RECORD_CLAIMANT), ("1", RECORD_NODE), (&member, RECORD_MEMBER)],
    );
    assert_blocked(port, 942, &member_key, RECORD_MEMBER, "the root: a member's entry installs");
    assert!(!presented_dead(port, &claimant_live), "the root: the claimant's session lives");
    assert!(!presented_dead(port, &zero_live), "the root: principal 0's session lives");
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    open_signed_session(port, zero, &device_key());
    open_signed_session(port, 941, &seat_key);
    // …and a header that NAMES the claimant is the same row as one naming
    // none (RES-66 item 4 (i)).
    let names_the_claimant = BlockedHeader { operator: Some(claimant), binding_writer: None };
    issue_blocked_list(&list, names_the_claimant, &[(claimant, RECORD_CLAIMANT)]);
    assert!(!presented_dead(port, &claimant_live), "the root, the claimant named: it lives");
    open_signed_session(port, zero, &device_key());

    // A HOSTED TIER: the header names an OFF-BOARD host and omits the second
    // field, so (b) is LIVE and the claimant is taken in the field's place —
    // an entry over the served board's claimant is ignored, one over the
    // host's own account covers no account of this board, and a MEMBER's
    // installs and its session dies.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    let member_live = open_signed_session(port, 942, &member_key);
    let hosted = BlockedHeader { operator: Some(OFF_BOARD_HOST), binding_writer: None };
    issue_blocked_list(
        &list,
        hosted,
        &[(claimant, RECORD_CLAIMANT), (OFF_BOARD_HOST, RECORD_HOST), (&member, RECORD_MEMBER)],
    );
    assert!(presented_dead(port, &member_live), "hosted: a member's session dies");
    assert_blocked(port, 942, &member_key, RECORD_MEMBER, "hosted: a member's entry installs");
    assert!(!presented_dead(port, &claimant_live), "hosted: the served board's claimant lives");
    assert!(!presented_dead(port, &zero_live), "hosted: principal 0's session lives");
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    open_signed_session(port, zero, &device_key());

    // A FORK THE COMMUNITY ITSELF SERVES: the header names the SEAT, an
    // account of the copy — so (b) is SILENT and the old claimant stays
    // blockable (RES-66). The entry over the OLD CLAIMANT installs and its
    // sessions die, principal 0's among them (0 ↦ the claimant); the entry
    // over the SEAT is ignored.
    let seat_live = open_signed_session(port, 941, &seat_key);
    let self_served = BlockedHeader { operator: Some(&seat), binding_writer: None };
    issue_blocked_list(&list, self_served, &[(claimant, RECORD_CLAIMANT), (&seat, RECORD_SEAT)]);
    assert!(presented_dead(port, &claimant_live), "fork: the old claimant's session dies");
    assert!(presented_dead(port, &zero_live), "fork: principal 0's dies with it");
    assert_blocked(port, CLAIMANT_PRINCIPAL, &device_key(), RECORD_CLAIMANT, "fork: the old claimant");
    assert_blocked(port, zero, &device_key(), RECORD_CLAIMANT, "fork: principal 0 ↦ the claimant");
    assert!(!presented_dead(port, &seat_live), "fork: the seat's session lives");
    open_signed_session(port, 941, &seat_key);

    // A FORK A THIRD PARTY SERVES: the operator off-board, the second field
    // naming the SEAT — which is exempted, and NEVER the old claimant, as
    // blockable here as on the self-served fork. The host's own entry is
    // ignored.
    let third_party =
        BlockedHeader { operator: Some(OFF_BOARD_HOST), binding_writer: Some(&seat) };
    issue_blocked_list(
        &list,
        third_party,
        &[(claimant, RECORD_CLAIMANT), (&seat, RECORD_SEAT), (OFF_BOARD_HOST, RECORD_HOST)],
    );
    assert_blocked(port, CLAIMANT_PRINCIPAL, &device_key(), RECORD_CLAIMANT, "hosted fork: the old claimant");
    assert_blocked(port, zero, &device_key(), RECORD_CLAIMANT, "hosted fork: principal 0");
    assert!(!presented_dead(port, &seat_live), "hosted fork: the seat's session lives");
    open_signed_session(port, 941, &seat_key);
    open_signed_session(port, 942, &member_key);

    sd.shutdown();
}

/// RES-115 — THE LIST IS SUPPLIED AT EVERY START: a restart re-installs it
/// from the start-up supply, so no restart lapses a standing block — and an
/// issue made while the daemon was DOWN is the one the next start installs.
/// The two refusals beside it: a supply that is not a list STOPS the start
/// (never an empty list in its place), and a reissue that is not a list
/// installs NOTHING — the list in force stands until a good issue replaces
/// it WHOLE.
#[test]
fn a_restart_reinstalls_the_list_and_a_bad_issue_installs_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let member_key = distinct_key(31);
    let member = {
        let (sd, list) = spawn_listed(root.path());
        let port = sd.port();
        let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
        let member = keyed_member(port, &anchor, 931, &member_key);
        issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
        assert_blocked(port, 931, &member_key, RECORD_MEMBER, "blocked before the restart");
        sd.shutdown();
        member
    };

    // The restart: the same supply, and the block holds at the FIRST request
    // — installed at open, with no reissue in between.
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    assert_blocked(port, 931, &member_key, RECORD_MEMBER, "the block holds across the restart");

    // A reissue that is not a list — torn JSON, an unknown field, an address
    // no tumbler spells — installs nothing: the block stands.
    for bad in [
        &br#"{"entries":[{"prefix":"1.0.2","#[..],
        br#"{"entries":[],"lifted":true}"#,
        br#"{"entries":[{"prefix":"1..2","record":"1.0.1.0.7.1"}]}"#,
        br#"{"operator":null,"entries":[]}"#,
        br#"[]"#,
    ] {
        issue_blocked_list_bytes(&list, bad);
        assert_blocked(port, 931, &member_key, RECORD_MEMBER, "a refused issue moves nothing");
    }
    // …and the next GOOD issue replaces the list whole.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    open_signed_session(port, 931, &member_key);
    sd.shutdown();

    // An issue made while the daemon is DOWN is what the next start installs.
    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_UNDER)]);
    let (sd, list) = spawn_listed(root.path());
    assert_blocked(sd.port(), 931, &member_key, RECORD_UNDER, "the start-up supply's current issue");
    sd.shutdown();

    // A supply that is NOT a list stops the start: `DaemonError`, not a
    // daemon serving an empty list the standing records do not support.
    issue_blocked_list_bytes(&list, b"not a list");
    let mut opts = skepd::AuthOptions::default();
    opts.blocked_prefixes = Some(list.clone());
    let refused = skepd::Daemon::open_with(&root.path().join("data"), opts);
    assert!(
        matches!(refused, Err(skepd::DaemonError::BlockedPrefixes(_))),
        "a malformed start-up supply refuses the open"
    );
    let mut opts = skepd::AuthOptions::default();
    opts.blocked_prefixes = Some(root.path().join("no-such-file.json"));
    let refused = skepd::Daemon::open_with(&root.path().join("data"), opts);
    assert!(
        matches!(refused, Err(skepd::DaemonError::BlockedPrefixes(_))),
        "and so does a supply that is not there"
    );
}

/// The accounts the accessor cells stand on, under the claimant `X`: `X.1`
/// (the agent space, which takes no genesis — RES-80), `X.2` (a later child,
/// unseeded), and `X.2.7` (unseeded, beneath it). None holds a key set of
/// its own, so each opens BY REFERENCE.
struct ByReference {
    x1: u64,
    x2: u64,
    x2_account: String,
    x2_7: u64,
}

fn by_reference_accounts(port: u16) -> ByReference {
    let (x1, x2) = (951, 952);
    let x = open_session(port, CLAIMANT_PRINCIPAL);
    let (x1_account, _) = delegate_under(port, &x, CLAIMANT_ACCOUNT, x1);
    assert_eq!(x1_account, format!("{CLAIMANT_ACCOUNT}.1"));
    let (x2_account, x2_session) = delegate_under(port, &x, CLAIMANT_ACCOUNT, x2);
    assert_eq!(x2_account, format!("{CLAIMANT_ACCOUNT}.2"));
    // Next-form is mandatory, so `X.2.7` is the SEVENTH delegation under
    // `X.2`, and its principal the seventh id.
    let mut seventh = (String::new(), 0);
    for id in 9_571..=9_577u64 {
        seventh = (delegate_under(port, &x2_session, &x2_account, id).0, id);
    }
    assert_eq!(seventh.0, format!("{x2_account}.7"));
    ByReference { x1, x2, x2_account, x2_7: seventh.1 }
}

/// AUTH-4.30 (i) — `key_subject` walks to the nearest keyed account above:
/// a device key of `X` opens a SIGNED session AS an unseeded `X.2` (200), AS
/// `X.1`, and AS `X.2.7` two levels down — and each writes, its testimony
/// the key that opened it. The session authenticates against `X`'s set and
/// is re-resolved per request, so a RETIREMENT AT `X` kills it at its next
/// presentation (`Skepd-Session: closed`), exactly as it kills `X`'s own.
#[test]
fn a_key_of_the_holder_opens_its_unseeded_accounts_and_a_retirement_at_the_holder_kills_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let accounts = by_reference_accounts(port);
    let device_fp = fingerprint_hex(&device_key());

    let as_x1 = open_signed_session(port, accounts.x1, &device_key());
    let as_x2 = open_signed_session(port, accounts.x2, &device_key());
    let as_x2_7 = open_signed_session(port, accounts.x2_7, &device_key());
    // A token that WRITES, as the account it names: the home mint of X.2,
    // testified under the holder's key.
    let minted = op(port, Some(&as_x2), &create_frame(&accounts.x2_account, None));
    let at = acked_at(&minted);
    let page = json(&http(port, "GET", &format!("/changes?since={}", at - 1), Some(&as_x2), b"").1);
    let entry = page["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .find(|e| e["at"].as_u64() == Some(at))
        .unwrap_or_else(|| panic!("the mint's own entry: {page}"))
        .clone();
    assert_eq!(entry["key"].as_str(), Some(device_fp.as_str()), "the opening key testifies");
    // A key NO set above holds opens nothing: the walk chose X's set, and
    // the signature is verified against it.
    let (st, _, _) = signed_handshake(port, accounts.x2, &distinct_key(77));
    assert_eq!(st, 401, "a key outside the holder's set");
    // `key_set` answers the unseeded account its OWN, EMPTY set — never the
    // set that opens it (AUTH-6.19).
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{}"}}"#, accounts.x2_account));
    assert_eq!(v["enrolled"].as_array().map(Vec::len), Some(0), "{v}");

    // The retirement at X, from X's anchor session.
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let ordinal = next_content_ordinal(port, Some(&anchor), CLAIMANT_DOC1);
    let retire = record_atom(port, &anchor, ordinal, &retire_atom(&[&device_fp]));
    expect_resp(&deposit(port, &anchor, &retire, T_RETIRE), "ack_addr");
    for (what, token) in [("X.1", &as_x1), ("X.2", &as_x2), ("X.2.7", &as_x2_7)] {
        assert!(presented_dead(port, token), "a retirement at X kills the session as {what}");
    }
    // The anchor still opens them: the set, not the key, is what they share.
    open_signed_session(port, accounts.x2, &anchor_key());

    sd.shutdown();
}

/// E2's THIRD TRIGGER (RES-128 C-4, RES-140; conformance T-E2(12)): a session
/// opened by reference DIES at the genesis of the account it acts as, or of
/// any account between it and the set it authenticated against — a genesis
/// at `X.2` kills the session as `X.2` AND the one as `X.2.7`, `closed` at
/// the next presentation — while the GIVER's session as `X`, and a session
/// as `X.1` that the genesis is not above, are untouched. No code of its
/// own: `key_subject` is re-run per request and now answers `X.2`.
#[test]
fn a_genesis_kills_the_sessions_opened_by_reference_at_and_beneath_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let accounts = by_reference_accounts(port);
    let giver = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let as_x1 = open_signed_session(port, accounts.x1, &device_key());
    let as_x2 = open_signed_session(port, accounts.x2, &device_key());
    let as_x2_7 = open_signed_session(port, accounts.x2_7, &device_key());

    // THE HANDOFF: X.2's genesis, homed in its registry — X's doc 1 — under
    // a FRESH key (the latch refuses one the set above holds), from X's
    // anchor session.
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let recipient_key = distinct_key(52);
    let recipient =
        hire(port, &anchor, CLAIMANT_DOC1, &accounts.x2_account, accounts.x2, &recipient_key);

    assert!(presented_dead(port, &as_x2), "the session as X.2 dies at X.2's genesis");
    assert!(presented_dead(port, &as_x2_7), "and the one as X.2.7: X.2 now stands between");
    assert!(!presented_dead(port, &giver), "the giver's session as X is untouched");
    assert!(!presented_dead(port, &as_x1), "and one as X.1, which the genesis is not above");
    assert!(!presented_dead(port, &recipient), "the recipient's own session lives");

    // The door has moved with the set: X's key opens neither any more, and
    // the RECIPIENT's opens both — at a handed-off account's children the
    // nearest keyed account above is the recipient's (RES-154).
    for p in [accounts.x2, accounts.x2_7] {
        let (st, _, body) = signed_handshake(port, p, &device_key());
        assert_eq!(st, 401, "the giver's key no longer opens {p}");
        assert_eq!(String::from_utf8(body).expect("utf-8"), r#"{"error":"session_rejected"}"#);
        open_signed_session(port, p, &recipient_key);
    }

    sd.shutdown();
}

/// THE BLOCKED-PREFIX COMPARAND IS `session_account`'s, never `key_subject`'s
/// (AUTH-4.30 (ii)): an entry over exactly `X.1` still covers a session as
/// `X.1` — whose set is `X`'s, which the entry does not cover — at the
/// handshake and at the kill alike; and REACH IS BY COVER, never by descent
/// (AUTH-4.70): the entry over `X.1` reaches neither `X` nor `X.2`.
#[test]
fn an_entry_over_exactly_the_agent_space_covers_it_whosever_set_opens_it() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let accounts = by_reference_accounts(port);
    let x1_account = format!("{CLAIMANT_ACCOUNT}.1");
    let as_x = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let as_x1 = open_signed_session(port, accounts.x1, &device_key());
    let as_x2 = open_signed_session(port, accounts.x2, &device_key());

    issue_blocked_list(&list, BlockedHeader::default(), &[(&x1_account, RECORD_UNDER)]);

    assert!(presented_dead(port, &as_x1), "the live session as X.1 is covered by its OWN account");
    assert_blocked(port, accounts.x1, &device_key(), RECORD_UNDER, "a handshake as X.1");
    assert!(!presented_dead(port, &as_x), "the entry over X.1 does not reach X");
    assert!(!presented_dead(port, &as_x2), "nor its sibling X.2");
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    open_signed_session(port, accounts.x2, &device_key());

    sd.shutdown();
}

/// AUTH-4.62 item 1 — the 401 body is BYTE-IDENTICAL across the thirteen
/// arms, and the 403 sits OUTSIDE them by status. Driven here are the arms
/// `every_handshake_failure_answers_the_same_401_bytes` does not reach: the
/// RETIRED key, the MIS-SIGNED body (an enrolled key over other bytes), the
/// bare bind where DISALLOWED (ENFORCING), principal 0 on an UNCLAIMED board,
/// and the thirteenth — a principal whose KEY SUBJECT's set is EMPTY, which
/// since the walk is the OWN-ADDRESS TERMINUS: a never-keyed top-level
/// delegate, and an unseeded account under never-keyed ancestors, where no
/// account above holds a set and step 5 refuses at the account's own
/// address. (Expiry needs the 60 s TTL and is pinned at `handshake` itself.)
#[test]
fn the_thirteen_401_arms_stay_byte_identical_and_the_403_stands_outside_them() {
    const REJECTED: &str = r#"{"error":"session_rejected"}"#;
    let rejected = |what: &str, (st, headers, body): (u16, Vec<(String, String)>, Vec<u8>)| {
        assert_eq!(st, 401, "{what}");
        assert_eq!(String::from_utf8(body).expect("utf-8"), REJECTED, "{what}: the one code");
        assert!(header(&headers, "Skepd-Session").is_none(), "{what}: /session is token-blind");
    };

    // Principal 0 on an UNCLAIMED board: no claimant, so nothing to sign
    // with — exactly as an unknown principal (E6).
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let sd = spawn_unclaimed(dir.path());
        rejected(
            "principal 0 on an unclaimed board",
            signed_handshake(sd.port(), PRINCIPAL_ZERO, &device_key()),
        );
        sd.shutdown();
    }
    // The bare bind where DISALLOWED: ENFORCING.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let sd = spawn_configured(dir.path(), false);
        claim_board(sd.port());
        let body = format!("{{\"principal\":{CLAIMANT_PRINCIPAL}}}");
        rejected(
            "a bare bind on an ENFORCING board",
            http_full(sd.port(), "POST", "/session", None, body.as_bytes()),
        );
        sd.shutdown();
    }

    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let p = CLAIMANT_PRINCIPAL;

    // THE THIRTEENTH ARM, at the own-address terminus: a never-keyed
    // top-level delegate, and an unseeded account beneath it — the walk
    // finds no keyed account above, answers the account's OWN address, and
    // step 5 refuses its empty set.
    let (never_keyed, never_keyed_session) = bootstrap_delegate(port, 961);
    delegate_under(port, &never_keyed_session, &never_keyed, 962);
    rejected("a never-keyed top-level delegate", signed_handshake(port, 961, &device_key()));
    rejected(
        "an unseeded account under never-keyed ancestors",
        signed_handshake(port, 962, &device_key()),
    );

    // MIS-SIGNED: an ENROLLED key, over bytes that are not this body's.
    let (st, body) = http(port, "GET", &format!("/challenge?principal={p}"), None, b"");
    assert_eq!(st, 200);
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();
    let sig = sign_session(&device_key(), &origin, &"ab".repeat(32), p);
    let body = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
    );
    rejected("an enrolled key's signature over other bytes", http_full(port, "POST", "/session", None, body.as_bytes()));

    // The RETIRED key.
    let anchor = open_signed_session(port, p, &anchor_key());
    let device_fp = fingerprint_hex(&device_key());
    let ordinal = next_content_ordinal(port, Some(&anchor), CLAIMANT_DOC1);
    let retire = record_atom(port, &anchor, ordinal, &retire_atom(&[&device_fp]));
    expect_resp(&deposit(port, &anchor, &retire, T_RETIRE), "ack_addr");
    rejected("a retired key", signed_handshake(port, p, &device_key()));

    // THE 403 — outside the thirteen BY STATUS, its shape pinned: exactly
    // two members, `error` and the one public datum `record`, no `detail`.
    let member_key = distinct_key(31);
    let member = keyed_member(port, &anchor, 931, &member_key);
    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    let (st, _, body) = signed_handshake(port, 931, &member_key);
    assert_eq!(st, 403);
    assert_eq!(String::from_utf8(body.clone()).expect("utf-8"), prefix_blocked_body(RECORD_MEMBER));
    let shape = json(&body);
    let members: Vec<&str> = shape.as_object().expect("an object").keys().map(String::as_str).collect();
    assert_eq!(members, ["error", "record"], "one public datum beside the name: {shape}");
    // …and the 401 beside it is unmoved by a list being in force.
    rejected("a foreign key, under a list in force", signed_handshake(port, p, &distinct_key(98)));

    sd.shutdown();
}
