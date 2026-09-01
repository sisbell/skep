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

mod common;

use common::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::Value;
use skep_identity::{encode_enroll, encode_retire, Enrollment, Fingerprint, PublicKey};

fn distinct_key(n: u8) -> SigningKey {
    let mut seed = [n; 32];
    seed[0] = 0x40 ^ n;
    SigningKey::from_bytes(&seed)
}

fn pubkey(sk: &SigningKey) -> PublicKey {
    PublicKey::parse("ed25519", &hex(&sk.verifying_key().to_bytes())).expect("a real point")
}

/// The fingerprint hex `key_set` publishes for a signing key.
fn fingerprint_hex(sk: &SigningKey) -> String {
    Fingerprint::of(&pubkey(sk)).to_hex()
}

/// Arbitrary record text as its atom JSON fragment — the escape every
/// record atom in this file takes, so a payload no parser admits is written
/// the same way a well-formed one is.
fn json_atom(text: &str) -> String {
    serde_json::to_string(&Value::String(text.to_string())).expect("json string")
}

/// One enroll record (device-flagged keys) as its atom JSON fragment.
fn enroll_atom(keys: &[&SigningKey]) -> String {
    let flagged: Vec<(&SigningKey, bool)> = keys.iter().map(|sk| (*sk, false)).collect();
    enroll_atom_flagged(&flagged)
}

/// One enroll record with the anchor flag named per key.
fn enroll_atom_flagged(keys: &[(&SigningKey, bool)]) -> String {
    let entries: Vec<Enrollment> = keys
        .iter()
        .map(|(sk, anchor)| Enrollment::new(pubkey(sk), *anchor, None).expect("no label"))
        .collect();
    json_atom(&String::from_utf8(encode_enroll(&entries)).expect("utf-8"))
}

/// One retire record naming fingerprints, as its atom JSON fragment.
fn retire_atom(fps: &[&str]) -> String {
    let parsed: Vec<Fingerprint> =
        fps.iter().map(|h| Fingerprint::parse_hex(h).expect("64 hex")).collect();
    json_atom(&String::from_utf8(encode_retire(&parsed)).expect("utf-8"))
}

/// Land one credential record atom at `ordinal` of the claimant's doc 1 and
/// answer its address. The atom is an ORDINARY write into a published home,
/// so it needs a session the publish gate admits — a signed one on a
/// claimed board. Kept apart from [`deposit`] for exactly that reason: the
/// two writes meet different gates, and only the second is the credential
/// path's.
fn record_atom(port: u16, signed_token: &str, ordinal: u64, atom: &str) -> String {
    let v = op(
        port,
        Some(signed_token),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}]}}"#
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
    // published home.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["y"]}}"#
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
    let too_many: Vec<SigningKey> = (0..15).map(distinct_key).collect();
    let refs: Vec<&SigningKey> = too_many.iter().collect();
    let enroll = |atom_ordinal: u64, atom: &str| {
        let v = op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{atom_ordinal}"}},"values":[{{"atom":{atom}}}]}}"#
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
    let v = enroll(2, &enroll_atom(&refs));
    assert_eq!(rejected_detail(&v), "credential_refused:too_many_enrolled");
    // 14 more (16 total) clears the cap exactly.
    let v = enroll(3, &enroll_atom(&refs[..14]));
    expect_resp(&v, "ack_addr");
    // …and the 17th key alone now refuses.
    let v = enroll(4, &enroll_atom(&refs[14..]));
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
                r#"{{"op":"insert","doc":"{doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}]}}"#,
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
    let enrolled = || -> usize {
        let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{account}"}}"#));
        assert_eq!(v["resp"].as_str(), Some("key_set"), "{v}");
        v["enrolled"].as_array().expect("enrolled").len()
    };

    let keys: Vec<SigningKey> = (0..=GENESIS_KEY_CAP as u8).map(distinct_key).collect();
    let refs: Vec<&SigningKey> = keys.iter().collect();

    // One key past the cap: refused, and it seeds nothing.
    let v = genesis(1, &refs);
    assert_eq!(rejected_detail(&v), "credential_refused:too_many_enrolled");
    assert_eq!(enrolled(), 0, "the refused genesis seeded nothing");

    // Exactly the cap: admitted, and the whole record lands.
    let v = genesis(2, &refs[..GENESIS_KEY_CAP]);
    expect_resp(&v, "ack_addr");
    assert_eq!(enrolled(), GENESIS_KEY_CAP, "a genesis AT the cap seeds every key");

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
    // record as a retirement and answer `malformed_payload:bad_header`.
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
    assert_eq!(rejected_detail(&v), "credential_refused:malformed_payload:bad_header");
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

    // The header is byte-exact, so a record that is not one dies at line 1.
    let bad_header = record_atom(port, &signed, 2, &json_atom("nonsense"));
    assert_eq!(
        rejected_detail(&deposit(port, &signed, &bad_header, T_ENROLL)),
        "credential_refused:malformed_payload:bad_header"
    );
    // A PARAMETERIZED sub — two colons, and the 1-based line number the
    // document fixes (the header is line 1, so a bad first key line is 2).
    let bad_line = record_atom(port, &signed, 3, &json_atom("skep-enroll v1\nnope"));
    assert_eq!(
        rejected_detail(&deposit(port, &signed, &bad_line, T_ENROLL)),
        "credential_refused:malformed_payload:bad_line:2"
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
    let text = String::from_utf8(encode_enroll(&[
        Enrollment::new(key, false, None).expect("no label")
    ]))
    .expect("utf-8");
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

/// The home pin (RES-17, wire.md §The claim ceremony): a credential link
/// homed in any document of its account other than doc 1 refuses
/// `not_doc_one` — which is what confines an account's credential state to
/// one address, and what two of `policy.rs`'s arguments (`is_published_v1`'s
/// agreement with the fold's constant, and `key_set`'s one home) rest on.
///
/// The second cell is the precedence AUTH-2.127 pins and the only place it
/// is observable: the payload is parsed BEFORE the pin, so a wrong-home
/// deposit whose record is unparseable answers `malformed_payload`, never
/// `not_doc_one`.
#[test]
fn a_credential_homed_outside_doc_1_refuses_not_doc_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // A DRAFT of the claimant's — a document of its account that is not
    // doc 1. Home anchoring puts the record atom in the same document.
    let v = op(
        port,
        Some(&signed),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    let draft = acked_addr(&v);
    let deposit_in_draft = |ordinal: u64, atom: &str| -> Value {
        let v = op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}]}}"#
            ),
        );
        expect_resp(&v, "ack_addr");
        op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"make_link","home":"{draft}","from":{{"addrs":["{draft}.0.1.{ordinal}"]}},"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
            ),
        )
    };

    // A WELL-FORMED record in the wrong home: the pin answers.
    assert_eq!(
        rejected_detail(&deposit_in_draft(1, &enroll_atom(&[&distinct_key(7)]))),
        "credential_refused:not_doc_one"
    );
    // The same wrong home with an unparseable record answers the PAYLOAD
    // fault instead — the parse precedes the pin.
    assert_eq!(
        rejected_detail(&deposit_in_draft(2, &json_atom("nonsense"))),
        "credential_refused:malformed_payload:bad_header"
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
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":[{{"atom":{}}}]}}"#,
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
    let a = json(&get(port, "/health").1)["auth"].clone();
    assert!(a["claimant"].is_null(), "unclaimed: claimant null");
    assert_eq!(a["local_trust"].as_bool(), Some(true), "the Phase A default");
    assert!(a.get("mode").is_none(), "NO .mode field — clients derive the mode");
    let origins = a["origins"].as_array().expect("origins");
    let dialed = format!("http://127.0.0.1:{port}");
    assert!(origins.iter().any(|o| o.as_str() == Some(dialed.as_str())), "{origins:?}");
    assert_eq!(
        a["signed_origins"], a["origins"],
        "unclaimed: the signed set IS the bare set"
    );
    claim_board(port);
    let a = json(&get(port, "/health").1)["auth"].clone();
    assert_eq!(a["claimant"].as_str(), Some(CLAIMANT_ACCOUNT), "the claim flips the claimant");
    assert_eq!(
        a["signed_origins"].as_array().expect("signed").len(),
        0,
        "claimed with no configured origin: the signed set drops to configured alone"
    );
    assert!(!a["origins"].as_array().expect("bare").is_empty(), "the bare set keeps the defaults");
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
    // session writes into the published home (ordinal 2 — the one legal
    // insert slot after the ceremony's atom).
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["r"]}}"#
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
    let record = record_atom(port, &device_token, 2, &retire_atom(&[&anchor_fp]));
    let v = deposit(port, &device_token, &record, T_RETIRE);
    assert_eq!(rejected_detail(&v), "credential_refused:anchor_session_required");
    // …and a BARE session never satisfies it either (§Credential refusals),
    // which is slot (6) answering ahead of slot (7)'s
    // `signed_session_required` — the order wire.md pins. The record atom is
    // the signed session's, since a bare write into the published home dies
    // at the publish gate before the credential path is reached at all.
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let v = deposit(port, &bare, &record, T_RETIRE);
    assert_eq!(rejected_detail(&v), "credential_refused:anchor_session_required");

    // Trigger 2 — a post-genesis ANCHOR-FLAGGED enrollment, same gate.
    let fresh = distinct_key(9);
    let flagged = record_atom(port, &device_token, 3, &enroll_atom_flagged(&[(&fresh, true)]));
    let v = deposit(port, &device_token, &flagged, T_ENROLL);
    assert_eq!(rejected_detail(&v), "credential_refused:anchor_session_required");
    // The same enrollment UNFLAGGED passes, so the gate is the FLAG and not
    // the act.
    let plain = record_atom(port, &device_token, 4, &enroll_atom_flagged(&[(&fresh, false)]));
    expect_resp(&deposit(port, &device_token, &plain, T_ENROLL), "ack_addr");

    // The anchor's own session retires the device key.
    let retire = record_atom(port, &anchor_token, 5, &retire_atom(&[&device_fp]));
    expect_resp(&deposit(port, &anchor_token, &retire, T_RETIRE), "ack_addr");

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
    let a = json(&get(port, "/health").1)["auth"].clone();
    assert_eq!(a["local_trust"].as_bool(), Some(false));
    assert!(!a["claimant"].is_null(), "claimed + !local_trust IS enforcing: {a}");

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
