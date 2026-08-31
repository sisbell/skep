//! The AUTH surface over real HTTP: the challenge→signed-session→op
//! lifecycle, close and the death signal, the enrolled-set cap (16,
//! Genesis exempt), the publish and pre-claim gates' accept AND refuse
//! cells, `key_set` on `/op` and `/op-at`, `/health.auth`, and restart
//! carrying the identity fold back (recovery = the canonical rebuild).

mod common;

use common::*;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use skep_identity::{encode_enroll, Enrollment, PublicKey};

fn distinct_key(n: u8) -> SigningKey {
    let mut seed = [n; 32];
    seed[0] = 0x40 ^ n;
    SigningKey::from_bytes(&seed)
}

fn pubkey(sk: &SigningKey) -> PublicKey {
    PublicKey::parse("ed25519", &hex(&sk.verifying_key().to_bytes())).expect("a real point")
}

/// One enroll record (device-flagged keys) as its atom JSON fragment.
fn enroll_atom(keys: &[&SigningKey]) -> String {
    let entries: Vec<Enrollment> = keys
        .iter()
        .map(|sk| Enrollment::new(pubkey(sk), false, None).expect("no label"))
        .collect();
    let text = String::from_utf8(encode_enroll(&entries)).expect("utf-8");
    serde_json::to_string(&Value::String(text)).expect("json string")
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

/// The publish gate (RES-26) on a claimed board: a bare session's write
/// into a published home (an account's doc 1) refuses
/// `signed_session_required`; its draft mints and draft-homed writes stand
/// (CLAIMED-PERMISSIVE's disclosed cost); the signed session passes.
#[test]
fn publish_gate_shuts_bare_published_writes_and_admits_signed_ones() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, OWNER_PRINCIPAL);
    // Refuse: a bare write homed in the published doc 1 (ordinal 2 — the
    // one legal insert slot after the ceremony's atom, so the gate is what
    // refuses it, not the arrangement's bounds).
    let v = op(
        port,
        Some(&bare),
        &format!(
            r#"{{"op":"insert","doc":"{OWNER_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["x"]}}"#
        ),
    );
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    // Refuse: a bare flagless version of the published doc 1.
    let v = op(port, Some(&bare), &format!(r#"{{"op":"version","d_src":"{OWNER_DOC1}"}}"#));
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    // Accept: a bare DRAFT mint and a write homed in it.
    let v = op(
        port,
        Some(&bare),
        &format!(r#"{{"op":"create_new_document","account":"{OWNER_ACCOUNT}"}}"#),
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
    let signed = open_signed_session(port, OWNER_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{OWNER_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["y"]}}"#
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
    let s = open_session(port, 77);
    let v = op(port, Some(&s), r#"{"op":"fork"}"#);
    assert_eq!(rejected_detail(&v), "credential_refused:mint_home_first");
    let v = op(
        port,
        Some(&s),
        &format!(r#"{{"op":"create_new_document","account":"{prefix}"}}"#),
    );
    expect_resp(&v, "ack_addr");
    let v = op(port, Some(&s), r#"{"op":"fork"}"#);
    expect_resp(&v, "ack_addr");
    sd.shutdown();
}

/// Challenge → signed session → op, and the strict body boundary: a reused
/// nonce is the ONE 401; an uppercase nonce is a 400 whose nonce SURVIVES.
#[test]
fn handshake_lifecycle_and_the_400_vs_401_boundary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let p = OWNER_PRINCIPAL;
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
        &format!(r#"{{"op":"create_new_document","account":"{OWNER_ACCOUNT}"}}"#),
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
    let signed = open_signed_session(port, OWNER_PRINCIPAL, &device_key());
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
    let signed = open_signed_session(port, OWNER_PRINCIPAL, &device_key());
    // The set holds 2 (the ceremony's genesis — exempt from the cap by
    // arm). An enroll of 15 more would land at 17 > 16: refused, whole.
    let too_many: Vec<SigningKey> = (0..15).map(distinct_key).collect();
    let refs: Vec<&SigningKey> = too_many.iter().collect();
    let deposit = |atom_ordinal: u64, atom: &str| {
        let v = op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"insert","doc":"{OWNER_DOC1}","at":{{"subspace":"1","ordinal":"{atom_ordinal}"}},"values":[{{"atom":{atom}}}]}}"#
            ),
        );
        expect_resp(&v, "ack_addr");
        let addr = format!("{OWNER_DOC1}.0.1.{atom_ordinal}");
        op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"make_link","home":"{OWNER_DOC1}","from":{{"addrs":["{addr}"]}},"to":{{"addrs":["{OWNER_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
            ),
        )
    };
    let v = deposit(2, &enroll_atom(&refs));
    assert_eq!(rejected_detail(&v), "credential_refused:too_many_enrolled");
    // 14 more (16 total) clears the cap exactly.
    let v = deposit(3, &enroll_atom(&refs[..14]));
    expect_resp(&v, "ack_addr");
    // …and the 17th key alone now refuses.
    let v = deposit(4, &enroll_atom(&refs[14..]));
    assert_eq!(rejected_detail(&v), "credential_refused:too_many_enrolled");
    // key_set shows exactly 16 enrolled.
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{OWNER_ACCOUNT}"}}"#));
    assert_eq!(v["resp"].as_str(), Some("key_set"), "{v}");
    assert_eq!(v["enrolled"].as_array().expect("enrolled").len(), 16);
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
    let signed = open_signed_session(port, OWNER_PRINCIPAL, &device_key());

    // One fresh credential-typed link in the owner's own doc 1.
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{OWNER_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":[{{"atom":{}}}]}}"#,
            enroll_atom(&[&distinct_key(3)])
        ),
    );
    expect_resp(&v, "ack_addr");
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{OWNER_DOC1}","from":{{"addrs":["{OWNER_DOC1}.0.1.2"]}},"to":{{"addrs":["{OWNER_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
        ),
    );
    let credential = acked_addr(&v);

    // The home's owner gets the shape token.
    let v = op(
        port,
        Some(&signed),
        &format!(r#"{{"op":"nullify","home":"{OWNER_DOC1}","target":"{credential}"}}"#),
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
        &format!(r#"{{"op":"nullify","home":"{OWNER_DOC1}","target":"{credential}"}}"#),
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
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{OWNER_ACCOUNT}"}}"#));
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
            r#"{{"at":2,"frame":{{"op":"key_set","account":"{OWNER_ACCOUNT}"}}}}"#
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
    assert_eq!(a["claimant"].as_str(), Some(OWNER_ACCOUNT), "the claim flips the claimant");
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
        let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{OWNER_ACCOUNT}"}}"#));
        assert_eq!(v["resp"].as_str(), Some("key_set"));
        sd.shutdown();
        v
    };
    let sd = spawn(dir.path()); // recovery; claim_board sees claimed and skips
    let port = sd.port();
    assert!(claimed(port), "the claimant survives restart");
    let after = op(port, None, &format!(r#"{{"op":"key_set","account":"{OWNER_ACCOUNT}"}}"#));
    assert_eq!(
        before["enrolled"], after["enrolled"],
        "the rebuilt key table equals the live fold's"
    );
    // The recovered fold verifies a fresh signed handshake, and the signed
    // session writes into the published home (ordinal 2 — the one legal
    // insert slot after the ceremony's atom).
    let signed = open_signed_session(port, OWNER_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{OWNER_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["r"]}}"#
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
    let signed = open_signed_session(port, OWNER_PRINCIPAL, &device_key());
    let emit = format!(
        r#"{{"op":"emit","home":"{OWNER_DOC1}","ty":[{{"start":"{T_ENROLL}","width":"0.0.0.0.0.0.0.0.1"}}],"from":"{OWNER_ACCOUNT}","to":[]}}"#
    );
    let v = op(port, Some(&signed), &emit);
    assert_eq!(rejected_detail(&v), "credential_refused:emit_not_make_link");
    let v = op(port, None, &emit);
    assert_eq!(v["code"].as_str(), Some("unauthenticated"), "slot 0 masks slot 1: {v}");
    let vspec_from = format!(
        r#"{{"op":"make_link","home":"{OWNER_DOC1}","from":[{{"source":"{OWNER_DOC1}","span":{{"start":"1.1","width":"0.1"}}}}],"to":{{"addrs":["{OWNER_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
    );
    let v = op(port, Some(&signed), &vspec_from);
    assert_eq!(rejected_detail(&v), "credential_refused:resolved_from");
    sd.shutdown();
}
