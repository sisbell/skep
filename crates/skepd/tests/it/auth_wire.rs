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
//!
//! And slot (6) whole: the anchor gate's HANDOFF exception, told by address
//! at the walk's terminus (AUTH-3.21) with the seat carve's one input,
//! and the CONTENT-scoped session — the third body form, the v2 bytes, and
//! `content_session` at the head of the slot (RES-63).

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
    // CLASSICAL entries (signed ops): the cell counts keys against the cap,
    // and sixteen hybrid entries would fill the 64 KiB record cap first.
    let real: Vec<SigningKey> = (0..n as u8).map(distinct_key).collect();
    let mut entries: Vec<Enrollment> = real
        .iter()
        .map(|sk| Enrollment::new(ed25519_public_key_of(sk), false, None).expect("no label"))
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
/// the in-place edit the write path refuses (PUB-2.11). The declaration
/// names the record's CLASS (PUB-2.64): `ty` is the type the pair's
/// [`deposit`] then carries — `T_ENROLL` for an enrollment record, a
/// malformed one included, `T_RETIRE` for a retire record. Kept apart from
/// [`deposit`] for exactly that reason: the two writes meet different gates,
/// and only the second is the credential path's.
fn record_atom(port: u16, signed_token: &str, ordinal: u64, atom: &str, ty: &str) -> String {
    let v = op(
        port,
        Some(signed_token),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
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
    // which is the store's cell, `tests/version_chain.rs`). The byte is
    // prose, PUB-2.60's residue, declared under a MEMBER type — ENROLL's.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["y"],"deposit":"{T_ENROLL}"}}"#
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
                r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{atom_ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
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
    // CLASSICAL entries (signed ops): the cell is about the record's KEY
    // COUNT, and sixteen hybrid entries fill the 64 KiB record cap where
    // sixteen classical ones fit — the design record's E7 arithmetic.
    let genesis = |ordinal: u64, keys: &[&SigningKey]| -> Value {
        let v = op(
            port,
            Some(&account_token),
            &format!(
                r#"{{"op":"insert","doc":"{doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
                enroll_atom_ed25519(keys)
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
                r#"{{"op":"insert","doc":"{doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
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
    let record = record_atom(port, &signed, 2, &enroll_atom(&[&distinct_key(5)]), T_ENROLL);
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
    let bad = record_atom(port, &signed, 3, &json_atom("nonsense"), T_ENROLL);
    let v = op(port, Some(&signed), &deposit_frame(Some("kr"), &bad, T_ENROLL));
    assert_eq!(rejected_detail(&v), "credential_refused:malformed_payload:bad_record");
    let good = record_atom(port, &signed, 4, &enroll_atom(&[&distinct_key(6)]), T_ENROLL);
    expect_resp(&op(port, Some(&signed), &deposit_frame(Some("kr"), &good, T_ENROLL)), "ack_addr");

    sd.shutdown();
}

/// The payload family's `malformed_payload:<sub>` join (wire.md §Credential
/// refusals). `Inert::detail()` writes it and `CredentialRefusal::token()`
/// cites that one method, so this crate composes no wire token — what these
/// assertions watch is that the join survives the marshal, sub and all, on
/// the family that tells an operator WHY their record was rejected.
#[test]
fn a_malformed_record_names_its_payload_fault_after_the_join() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // A body that is not the canonical schema dies as `bad_record`.
    let bad_record = record_atom(port, &signed, 2, &json_atom("nonsense"), T_ENROLL);
    assert_eq!(
        rejected_detail(&deposit(port, &signed, &bad_record, T_ENROLL)),
        "credential_refused:malformed_payload:bad_record"
    );
    // A PARAMETERIZED sub survives the join — a duplicate entry names its
    // 1-based ENTRY index (AUTH-2.15, AUTH-1.28), two colons and all.
    let dup = record_atom(port, &signed, 3, &enroll_atom(&[&distinct_key(5), &distinct_key(5)]), T_ENROLL);
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
    let record = record_atom(port, &signed, 2, &json_atom(&text), T_ENROLL);
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
    // atom's insert is DECLARED under ENROLL's type (PUB-2.63, PUB-2.64):
    // into the published member it is the deposit the write path admits, and
    // into the draft the declaration is inert.
    let enroll_in = |home: &str, ordinal: u64, atom: &str| -> Value {
        let v = op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"insert","doc":"{home}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
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
    // published doc 1. (Declared under a member type — ENROLL's, the byte
    // being prose — and at the member's fresh position, so the store's
    // in-place refusal is not what answers below: the write is the deposit a
    // published head admits, PUB-2.59.)
    let insert = format!(
        r#"{{"op":"insert","doc":"{version}","at":{{"subspace":"1","ordinal":"2"}},"values":["x"],"deposit":"{T_ENROLL}"}}"#
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

/// The first-mint pair's THIRD vector ((c) row 9 (ii)): TWO CONCURRENT FIRST
/// MINTS into ONE empty account — both ACKED, EXACTLY ONE born published. The
/// flagless default is resolved off WORKING state inside the mint's own
/// transaction (PUB-8.21), under the kernel's single applier lock, taken
/// before the base root is loaded — and the daemon stands AHEAD of that, its
/// gates and the execute they gate under one serialization lock (AUTH-3.35's
/// plain sequence). So the two serialize: the second mint's base already
/// holds the first's document, and it is born a PRIVATE draft — never a
/// second home, and never refused (the door refuses an explicit `false`
/// alone). What is pinned here is the OUTCOME at the wire, whichever layer
/// holds it: a daemon that resolved the default ahead of its serialization
/// lock hands both mints `true`, and only a real race shows it.
///
/// The race is REAL: one daemon; per round one fresh EMPTY account, TWO live
/// sessions of its principal, two threads released off one barrier, each
/// sending the flagless `create_new_document`. Which session's mint commits
/// first is the scheduler's to say, so the rounds run until BOTH orders have
/// occurred, and never fewer than `MIN_ROUNDS`: the pin holds whichever wins.
///
/// "Born published" is read three ways — `doc_metadata.published` as the owner,
/// the guest's read (served the home, `withheld` the draft), and the
/// behavioural read of the door's own vector above: a bare write into the home
/// meets the publish gate, a bare write into the draft commits.
#[test]
fn two_concurrent_first_mints_bear_exactly_one_published_home() {
    use std::sync::{Arc, Barrier};

    const MIN_ROUNDS: usize = 16;
    const MAX_ROUNDS: usize = 256;

    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path()); // claimed, CLAIMED-PERMISSIVE (bare binds honored)
    let port = sd.port();
    let boot = open_session(port, 0);

    // `won[i]`: the rounds in which session `i`'s mint committed FIRST.
    let mut won = [0usize; 2];
    let mut rounds = 0;
    while rounds < MAX_ROUNDS && (rounds < MIN_ROUNDS || won.contains(&0)) {
        let id = 810_000 + rounds as u64;
        let (account, first) = delegate_empty_account(port, &boot, id);
        let sessions = [first, open_session(port, id)];
        assert_ne!(sessions[0], sessions[1], "two live sessions of the one principal");

        let barrier = Arc::new(Barrier::new(sessions.len()));
        let mints: Vec<_> = sessions
            .iter()
            .map(|session| {
                let (barrier, session) = (Arc::clone(&barrier), session.clone());
                let frame = create_frame(&account, None);
                std::thread::spawn(move || {
                    barrier.wait();
                    op(port, Some(&session), &frame)
                })
            })
            .collect();
        // Both ACKED — neither is refused, neither is lost.
        let minted: Vec<String> =
            mints.into_iter().map(|mint| acked_addr(&mint.join().expect("a mint thread"))).collect();

        // The chain's first two documents, one each: the account's doc 1 went
        // to the mint that committed first.
        let (home, draft) = (format!("{account}.0.1"), format!("{account}.0.2"));
        let winner = minted.iter().position(|doc| *doc == home).unwrap_or_else(|| {
            panic!("round {rounds}: neither mint is {home}: {minted:?}")
        });
        assert_eq!(minted[1 - winner], draft, "round {rounds}: two distinct addresses: {minted:?}");

        // EXACTLY ONE born published — and it is the home.
        let published = |doc: &str| {
            let meta = doc_metadata(port, Some(&sessions[0]), doc);
            expect_resp(&meta, "doc_metadata")["published"].as_bool().expect("a boolean")
        };
        assert!(published(&home), "round {rounds}: the first committed mint is born published");
        assert!(!published(&draft), "round {rounds}: the second is born PRIVATE, never a second home");
        // The guest is served the one and withheld the other.
        let meta = doc_metadata(port, None, &home);
        assert_eq!(expect_resp(&meta, "doc_metadata")["published"].as_bool(), Some(true), "{meta}");
        assert_withheld(&doc_metadata(port, None, &draft), &draft);
        // The door's behavioural read, from the LOSING session: the home is
        // behind the publish gate, the draft takes a bare write.
        let bare_write = |doc: &str| {
            op(port, Some(&sessions[1 - winner]), &insert_frame(doc, 1, "p", false))
        };
        assert_eq!(rejected_detail(&bare_write(&home)), GATED, "round {rounds}");
        expect_resp(&bare_write(&draft), "ack_addr");

        won[winner] += 1;
        rounds += 1;
    }
    eprintln!("concurrent first mints: {rounds} rounds; committed first — session 0: {}, session 1: {}", won[0], won[1]);
    assert!(
        !won.contains(&0),
        "both orders must occur — {rounds} rounds, committed first {won:?}"
    );

    sd.shutdown();
}

/// The first-mint pair's FOURTH vector ((c) row 9 (iii); the conformance
/// pack's §2.13 row 4; AUTH RES-182) — THE CORPUS ROW "REACHED ONLY OUTSIDE A
/// CONFORMING DAEMON" (AUTH-3.58): a board built WITHOUT the daemon's refusal
/// producer serves a private "home", and AUTH-3.58's and AUTH-3.72's
/// NO-CLEARING-ACT cells stand on it.
///
/// The explicit-`false` FIRST mint is written BELOW the door — by the engine
/// directly, through `OperationSurface`, no daemon in the path — since M3 mints
/// it private and refuses nothing (the door is the daemon's alone, PUB-8.20).
/// The account is seated on a claimed board first, by the daemon, and keyed
/// after, by the claimant's hire into the claimant's own PUBLISHED doc 1, so
/// the account is a HOLDER whose one honored home is a draft. skepd over that
/// dir serves doc 1 PRIVATE, and then:
///
/// - the HOLDER cell: an enrolment and a retirement homed in doc 1 answer
///   `unpublished`; the same record in a published second document answers
///   `not_doc_one`; written again in doc 1 it re-fires `unpublished` — no
///   clearing act, the set unmoved;
/// - the GENESIS cell (AUTH-3.72): the genesis this delegator writes for its
///   own delegate, homed in its doc 1 — the one legal genesis home — answers
///   `unpublished`, and `not_doc_one` anywhere else: a keyless subtree.
#[test]
fn a_home_minted_private_below_the_door_is_served_private_and_has_no_clearing_act() {
    use skep_engine::{Engine, KernelConfig};
    use skep_febe::{Codec, OperationSurface, Response};
    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, SaltSource};
    use skep_namespace::PrincipalId;
    use skepd::JsonCodec;

    const HOLDER: u64 = 820;
    let dir = tempfile::tempdir().expect("tempdir");

    // Phase 1 — the daemon: a claimed board, and one EMPTY account seated on it.
    let account = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let boot = open_session(port, 0);
        let (account, _) = delegate_empty_account(port, &boot, HOLDER);
        sd.shutdown();
        account
    };
    let home = format!("{account}.0.1");

    // Phase 2 — BELOW THE DOOR: the engine directly, the account's own
    // principal, its FIRST mint carrying the explicit `false`.
    {
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.path().to_path_buf(),
                retain_checkpoints: 2,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::EveryN(1024),
            salt: SaltSource::Seeded(0),
        };
        let engine = Engine::open(cfg).expect("engine recover");
        let febe = OperationSurface::new(Box::new(engine.stores()));
        let codec = JsonCodec;
        let req = codec
            .parse(create_frame(&account, Some(false)).as_bytes())
            .unwrap_or_else(|e| panic!("test frame does not parse: {:?}", e.detail));
        match febe.execute(febe.open_session(PrincipalId(HOLDER)), req) {
            Response::AckAddr { addr, .. } => {
                assert_eq!(addr.tumbler().to_string(), home, "the first mint IS doc 1")
            }
            other => panic!(
                "M3 mints an explicit-false first document private and refuses nothing: {}",
                String::from_utf8_lossy(&codec.marshal(&other))
            ),
        }
        drop(febe);
        drop(engine); // releases the journal-directory lock for the daemon
    }

    // Phase 3 — skepd over that dir.
    let sd = spawn(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    // The door stands on this very daemon: the same mint through it is refused,
    // so the private home came from nowhere a conforming daemon reaches.
    let (other_account, other) = delegate_empty_account(port, &boot, HOLDER + 1);
    assert_eq!(
        rejected_detail(&op(port, Some(&other), &create_frame(&other_account, Some(false)))),
        "credential_refused:mint_home_public"
    );

    // Doc 1 is served PRIVATE: `published: false` to its owner, withheld from
    // the guest.
    let bare = open_session(port, HOLDER);
    let meta = doc_metadata(port, Some(&bare), &home);
    let meta = expect_resp(&meta, "doc_metadata");
    assert_eq!(meta["published"].as_bool(), Some(false), "a private \"home\": {meta}");
    assert_eq!(meta["owner"].as_str(), Some(account.as_str()), "{meta}");
    assert_withheld(&doc_metadata(port, None, &home), &home);

    // The claimant keys the account — its genesis homed in the CLAIMANT's doc 1
    // (AUTH-2.62), which is published — so the account is a HOLDER.
    let claimant = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let holder_key = distinct_key(21);
    let holder = hire(port, &claimant, CLAIMANT_DOC1, &account, HOLDER, &holder_key);
    let enrolled = |of: &str| {
        let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{of}"}}"#));
        expect_resp(&v, "key_set")["enrolled"].as_array().expect("enrolled").len()
    };
    assert_eq!(enrolled(&account), 1);

    // A credential deposit for `subject` homed in `doc`, from the holder's
    // SIGNED session: the record atom at `ordinal`, then the link naming it.
    // The atom's insert is DECLARED (PUB-2.63): the published second document
    // admits no other, and into a draft the declaration is inert.
    let deposit_in = |doc: &str, ordinal: u64, atom: &str, subject: &str, ty: &str| -> Value {
        let v = op(
            port,
            Some(&holder),
            &format!(
                r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
            ),
        );
        let atom_addr = acked_addr(&v);
        op(
            port,
            Some(&holder),
            &format!(
                r#"{{"op":"make_link","home":"{doc}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{subject}"]}},"ty":{{"addrs":["{ty}"]}}}}"#
            ),
        )
    };
    // The one other home a holder can publish: a second document, minted
    // `published: true` from its signed session.
    let second = acked_addr(&op(port, Some(&holder), &create_frame(&account, Some(true))));
    assert_eq!(second, format!("{account}.0.2"));

    // THE HOLDER CELL (AUTH-3.58).
    let another_key = enroll_atom(&[&distinct_key(22)]);
    assert_eq!(
        rejected_detail(&deposit_in(&home, 1, &another_key, &account, T_ENROLL)),
        "credential_refused:unpublished",
        "the holder's one honored home is a draft"
    );
    assert_eq!(
        rejected_detail(&deposit_in(&second, 1, &another_key, &account, T_ENROLL)),
        "credential_refused:not_doc_one",
        "every other home answers the home pin"
    );
    assert_eq!(
        rejected_detail(&deposit_in(&home, 2, &another_key, &account, T_ENROLL)),
        "credential_refused:unpublished",
        "written again in doc 1, it re-fires: no clearing act"
    );
    let holder_fp = fingerprint_hex(&holder_key);
    let retirement = retire_atom(&[holder_fp.as_str()]);
    assert_eq!(
        rejected_detail(&deposit_in(&home, 3, &retirement, &account, T_RETIRE)),
        "credential_refused:unpublished",
        "a retirement included"
    );
    assert_eq!(enrolled(&account), 1, "the set is unmoved");

    // THE GENESIS CELL (AUTH-3.72): this account's doc 1 is its delegates'
    // genesis registry. A LATER child — the first is the agent space, which
    // takes no genesis from any hand (RES-80).
    reserve_agent_space(port, &holder, &account, HOLDER + 2);
    let (delegate, _) = delegate_under(port, &holder, &account, HOLDER + 3);
    let genesis = enroll_atom(&[&distinct_key(23)]);
    assert_eq!(
        rejected_detail(&deposit_in(&home, 4, &genesis, &delegate, T_ENROLL)),
        "credential_refused:unpublished",
        "the one legal genesis home is a draft"
    );
    assert_eq!(
        rejected_detail(&deposit_in(&second, 2, &genesis, &delegate, T_ENROLL)),
        "credential_refused:not_doc_one"
    );
    assert_eq!(enrolled(&delegate), 0, "a keyless subtree");

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
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
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
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
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
    // the one insert a published head admits, PUB-2.59; the byte is prose,
    // declared under a member type, ENROLL's — PUB-2.60's residue).
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["r"],"deposit":"{T_ENROLL}"}}"#
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
    let anchor_retire = record_atom(port, &device_token, 2, &retire_atom(&[&anchor_fp]), T_RETIRE);
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
        record_atom(port, &device_token, 3, &enroll_atom_flagged(&[(&fresh, true)]), T_ENROLL);
    let v = deposit(port, &device_token, &flagged_enroll, T_ENROLL);
    assert_eq!(rejected_detail(&v), "credential_refused:anchor_session_required");
    // The same enrollment UNFLAGGED passes, so the gate is the FLAG and not
    // the act.
    let plain_enroll =
        record_atom(port, &device_token, 4, &enroll_atom_flagged(&[(&fresh, false)]), T_ENROLL);
    expect_resp(&deposit(port, &device_token, &plain_enroll, T_ENROLL), "ack_addr");

    // The anchor's own session retires the device key.
    let device_retire = record_atom(port, &anchor_token, 5, &retire_atom(&[&device_fp]), T_RETIRE);
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

/// THE RETIRE OF A LAST ANCHOR, over the wire (the conformance pack's row 14;
/// AUTH-5.46's last-anchor arm, AUTH-3.20, AUTH-3.21's "where it holds none
/// the act stays device-grade"). An anchor session retires EVERY enrolled
/// anchor in one record — a second anchor it enrolled, and its own key — a
/// device key remaining: the act COMMITS (slot (6) reads the session's key,
/// an anchor of the set; the fold's whole-set test sees the device key
/// stand), and both anchors' sessions are dead at their next presentation,
/// the retiring one included. From then on the account is device-grade for
/// good: a retired anchor signs no handshake; an anchor-flagged enrolment
/// answers `anchor_session_required` from the device session and from a bare
/// one, there being no key left that could open the session the gate asks
/// for, while the same key UNFLAGGED enrols; and a HANDOFF genesis beneath
/// the account — refused `anchor_session_required` from the device session
/// while an anchor stood — now COMMITS from it: the downgrade AUTH-5.46 names
/// beside the permanence, AUTH-3.21's anchorless arm.
#[test]
fn retiring_the_last_anchor_commits_kills_the_retiring_session_and_leaves_the_account_device_grade() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let device_fp = fingerprint_hex(&device_key());
    let anchor_fp = fingerprint_hex(&anchor_key());
    let device = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    // A SECOND anchor, enrolled from the anchor's session — the gate admits an
    // anchor-flagged enrolment from an anchor session — and a session it opens.
    let second = distinct_key(64);
    let second_fp = fingerprint_hex(&second);
    let ordinal = next_content_ordinal(port, Some(&anchor), CLAIMANT_DOC1);
    let flagged =
        record_atom(port, &anchor, ordinal, &enroll_atom_flagged(&[(&second, true)]), T_ENROLL);
    expect_resp(&deposit(port, &anchor, &flagged, T_ENROLL), "ack_addr");
    let second_session = open_signed_session(port, CLAIMANT_PRINCIPAL, &second);

    // The subdivision X.2 the handoff cell is read at (X.1 is the held agent
    // space, which takes no genesis). While an anchor stands in X's set, X's
    // handoff is anchor-grade: the device session's genesis there is refused.
    delegate_under(port, &bare, CLAIMANT_ACCOUNT, 951);
    let (x2, _) = delegate_under(port, &bare, CLAIMANT_ACCOUNT, 952);
    let handoff = land_record(port, &device, CLAIMANT_DOC1, &fresh_member(65), T_ENROLL);
    let v = enroll_for(port, &device, CLAIMANT_DOC1, &handoff, &x2);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "an anchor enrolled: X's handoff is anchor-grade: {v}");
    assert_eq!(enrolled_count(port, &x2), 0, "a refused handoff commits nothing");

    // THE ACT: every enrolled anchor retired in one record, from the first
    // anchor's own session, the device key remaining — it COMMITS.
    let ordinal = next_content_ordinal(port, Some(&anchor), CLAIMANT_DOC1);
    let last_anchors =
        record_atom(port, &anchor, ordinal, &retire_atom(&[&anchor_fp, &second_fp]), T_RETIRE);
    expect_resp(&deposit(port, &anchor, &last_anchors, T_RETIRE), "ack_addr");

    // `key_set`: the device key alone enrolled, no anchor flag left; both
    // anchors retired, each under the flag it was enrolled with.
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    let enrolled = v["enrolled"].as_array().expect("enrolled");
    assert_eq!(enrolled.len(), 1, "{v}");
    assert_eq!(enrolled[0]["fingerprint"].as_str(), Some(device_fp.as_str()), "{v}");
    assert_eq!(enrolled[0]["anchor"].as_bool(), Some(false), "no anchor stands enrolled: {v}");
    let retired: Vec<(String, bool)> = v["retired"]
        .as_array()
        .expect("retired")
        .iter()
        .map(|e| (e["fingerprint"].as_str().expect("fp").to_string(), e["anchor"].as_bool().expect("flag")))
        .collect();
    assert_eq!(retired.len(), 2, "{v}");
    for fp in [&anchor_fp, &second_fp] {
        assert!(retired.contains(&(fp.clone(), true)), "{fp} retired under its anchor flag: {v}");
    }

    // THE DEATH: the retiring session and the second anchor's are dead at
    // the commit — `closed` at their next presentation — the device's lives,
    // and a retired anchor signs no handshake.
    assert!(presented_dead(port, &anchor), "the retiring anchor's session dies at the commit");
    assert!(presented_dead(port, &second_session), "the second anchor's session dies with its key");
    assert!(!presented_dead(port, &device), "the device session is untouched");
    let (st, _, _) = signed_handshake(port, CLAIMANT_PRINCIPAL, &anchor_key());
    assert_eq!(st, 401, "a retired anchor signs no handshake");

    // THE PERMANENCE (AUTH-5.46): no anchor can ever be enrolled on this
    // account again. The gate asks for a session an anchor of the account
    // established (AUTH-3.20), and no enrolled key could open one.
    let fresh = distinct_key(66);
    let ordinal = next_content_ordinal(port, Some(&device), CLAIMANT_DOC1);
    let flagged =
        record_atom(port, &device, ordinal, &enroll_atom_flagged(&[(&fresh, true)]), T_ENROLL);
    for (hand, token) in [("the device session", &device), ("a bare session", &bare)] {
        let v = deposit(port, token, &flagged, T_ENROLL);
        assert_eq!(rejected_detail(&v), "credential_refused:anchor_session_required", "{hand}: {v}");
    }
    // …while the account stays usable at DEVICE grade: the same key,
    // unflagged, enrols from the device session.
    let ordinal = next_content_ordinal(port, Some(&device), CLAIMANT_DOC1);
    let plain =
        record_atom(port, &device, ordinal, &enroll_atom_flagged(&[(&fresh, false)]), T_ENROLL);
    expect_resp(&deposit(port, &device, &plain, T_ENROLL), "ack_addr");

    // THE DOWNGRADE beside the permanence: X's set holds no anchor, so X's
    // handoff — the SAME record, the SAME frame, refused from this session
    // above — is device-grade now and COMMITS from it.
    expect_resp(&enroll_for(port, &device, CLAIMANT_DOC1, &handoff, &x2), "ack_addr");
    assert_eq!(enrolled_count(port, &x2), 1, "the recipient's key, latched from a device session");

    sd.shutdown();
}

/// `would_empty`, `no_holder` and `not_holder_retirement` OVER THE WIRE (the
/// conformance pack's row 15; AUTH-3.56's three rows — AUTH-2.74; AUTH-2.71,
/// AUTH-2.76): the fold's own retirement verdicts as the `credential_refused`
/// details a live daemon answers at slot (3), each from the hand best placed
/// to make the act — a SIGNED session, an anchor's where the claimant acts,
/// so no gate behind (3) could be what refuses — and `key_set` unmoved after
/// each. The fold corpus pins the three at the crate; this is the join the
/// daemon writes and the wire spells.
///
/// * `would_empty` — the claimant retires its WHOLE enrolled set, the anchor
///   and the device key, in one record: the record is inert whole, both keys
///   stand, and the device key still opens a session;
/// * `not_holder_retirement` — the claimant, whose doc 1 is a member's
///   genesis registry, retires the member's key from THAT registry: the
///   retirement arms never read the delegator, no ancestor retires a
///   holder's keys, and the member's key still opens the member's session;
/// * `no_holder` — an own-space retirement at `X.2`, a subdivision that opens
///   BY REFERENCE and has never held a key of its own, written from the
///   session as `X.2` the holder's device key opened and naming that key: the
///   account's own set is empty, and the key stands at `X` as `X`'s own.
#[test]
fn the_fold_s_three_retirement_refusals_are_answered_over_the_wire_and_move_no_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let device_fp = fingerprint_hex(&device_key());
    let anchor_fp = fingerprint_hex(&anchor_key());
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let key_set =
        |account: &str| op(port, None, &format!(r#"{{"op":"key_set","account":"{account}"}}"#));
    // The two tables of a `key_set` answer — `as_of` aside, which every commit
    // (a landed record atom included) moves.
    let tables = |v: &Value| (v["enrolled"].clone(), v["retired"].clone());
    let fingerprints = |v: &Value, field: &str| -> Vec<String> {
        v[field]
            .as_array()
            .unwrap_or_else(|| panic!("{field}: {v}"))
            .iter()
            .map(|e| e["fingerprint"].as_str().expect("fp").to_string())
            .collect()
    };

    // `would_empty` — every enrolled key of the claimant in one retirement.
    let before = key_set(CLAIMANT_ACCOUNT);
    assert_eq!(fingerprints(&before, "enrolled").len(), 2, "the ceremony's two keys: {before}");
    let ordinal = next_content_ordinal(port, Some(&anchor), CLAIMANT_DOC1);
    let whole_set =
        record_atom(port, &anchor, ordinal, &retire_atom(&[&anchor_fp, &device_fp]), T_RETIRE);
    let v = deposit(port, &anchor, &whole_set, T_RETIRE);
    assert_eq!(rejected_detail(&v), "credential_refused:would_empty", "{v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(tables(&key_set(CLAIMANT_ACCOUNT)), tables(&before), "the claimant's table is unchanged");
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // `not_holder_retirement` — the member's key, retired from the claimant's
    // doc 1: the member's genesis registry, and not its own space.
    let member_key = distinct_key(67);
    let member_fp = fingerprint_hex(&member_key);
    let member = keyed_member(port, &anchor, 967, &member_key);
    let member_before = key_set(&member);
    assert_eq!(fingerprints(&member_before, "enrolled"), vec![member_fp.clone()], "{member_before}");
    let ordinal = next_content_ordinal(port, Some(&anchor), CLAIMANT_DOC1);
    let from_the_registry = record_atom(port, &anchor, ordinal, &retire_atom(&[&member_fp]), T_RETIRE);
    let v = typed_link(port, &anchor, CLAIMANT_DOC1, &[from_the_registry.as_str()], &[member.as_str()], T_RETIRE);
    assert_eq!(rejected_detail(&v), "credential_refused:not_holder_retirement", "{v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(tables(&key_set(&member)), tables(&member_before), "the member's table is unchanged");
    open_signed_session(port, 967, &member_key);

    // `no_holder` — an own-space retirement at X.2, which opens by reference:
    // its home minted and the record landed from the session as X.2.
    delegate_under(port, &bare, CLAIMANT_ACCOUNT, 951);
    let (x2, _) = delegate_under(port, &bare, CLAIMANT_ACCOUNT, 952);
    let as_x2 = open_signed_session(port, 952, &device_key());
    let x2_doc1 = create_doc(port, &as_x2, &x2);
    let own_space = land_record(port, &as_x2, &x2_doc1, &retire_atom(&[&device_fp]), T_RETIRE);
    let v = typed_link(port, &as_x2, &x2_doc1, &[own_space.as_str()], &[x2.as_str()], T_RETIRE);
    assert_eq!(rejected_detail(&v), "credential_refused:no_holder", "{v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");
    let x2_set = key_set(&x2);
    assert!(
        fingerprints(&x2_set, "enrolled").is_empty() && fingerprints(&x2_set, "retired").is_empty(),
        "X.2's own set is empty both ways: {x2_set}"
    );
    assert!(
        fingerprints(&key_set(CLAIMANT_ACCOUNT), "enrolled").contains(&device_fp),
        "the key named stands at X, as X's own"
    );
    open_signed_session(port, 952, &device_key());

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
/// it; `/health`, `/challenge`, `/session` and — in `client` builds — `/`
/// are token-blind, and §Reading history adds `/chain` ("token-blind and
/// class-invariant like `/health`"). The negative half matters as much —
/// `/health` is what a client polls, and a signal there says a session died
/// that did not.
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
    let mut blind: Vec<(&str, &str, &[u8])> = vec![
        ("GET", "/health", b""),
        ("GET", "/chain?at=0", b""),
        ("GET", "/challenge?principal=1", b""),
        ("POST", "/session", br#"{"principal":1}"#),
    ];
    if cfg!(feature = "client") {
        blind.push(("GET", "/", b""));
    }
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
/// The last two rows are E6's NEGATIVE half (AUTH-4.68: principal 0's set is
/// the claimant's — "signed with a non-claimant ENROLLED key it fails"): a
/// key enrolled NOWHERE, which would fail under any reading of 0's subject,
/// and a key ENROLLED at a member account of this board, which fails only
/// because 0 reads the claimant's set alone (AUTH-4.30 (i)'s first arm) and
/// never "any account's".
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

    // E6's enrolled non-claimant key: a member hired into the claimant's doc 1
    // — `keyed_member` opens the member's own session with it, so the key is
    // live on this board — and, the positive half beside it, a CLAIMANT key
    // opens principal 0.
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let member_key = distinct_key(23);
    keyed_member(port, &anchor, 923, &member_key);
    open_signed_session(port, 0, &device_key());

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
        (
            "principal 0, whose subject is the claimant, signing with a key ENROLLED at a member account",
            signed_body(0, &nonce_for(0), &origin, &member_key),
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

/// E6's POSITIVE cell carried THROUGH TO A WRITE (the conformance pack's row
/// 16; AUTH-4.68, AUTH-4.30 (i)'s first arm, AUTH-5.10): after the claim, a
/// session as principal 0 opened with a CLAIMANT key — 0's subject is the
/// claimant's set — runs the top-tier `delegate`, "0's whole reach", and it
/// COMMITS: the new seat answers `effective_owner` with its own prefix and
/// the id minted, the frontier moves, and the seated principal's bare
/// session mints its home. Every other `delegate` from 0 in these suites
/// rides a BARE session (`common::bootstrap_delegate`). And the reach is the
/// PRINCIPAL's, never the key's: the SAME key opened as the claimant is
/// refused by M3 on the SAME frame — `not_ancestor`, the prefix asked lying
/// outside the caller's own, H1's `delegate` row (`authz.rs`) — top-tier
/// seeding runs AS principal 0 and M3 refuses any other caller (AUTH-5.10).
#[test]
fn a_signed_principal_0_session_runs_the_top_tier_delegate_and_it_commits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let as_zero = open_signed_session(port, PRINCIPAL_ZERO, &device_key());
    let as_claimant = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let prefix = next_prefix_under(port, Some(&as_zero), "1");
    let frame = format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":978}}"#);

    // The same key, as the CLAIMANT: not principal 0, so not 0's reach — M3's
    // own refusal, the daemon's register spelling it, and nothing commits.
    let v = op(port, Some(&as_claimant), &frame);
    assert_eq!(verdict(&v), "not_ancestor", "the claimant's principal owns no top-level frontier: {v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(next_prefix_under(port, None, "1"), prefix, "nothing committed");

    // As principal 0, SIGNED with the claimant's key: the delegate commits.
    expect_resp(&op(port, Some(&as_zero), &frame), "ack_addr");
    assert_eq!(
        effective_owner(port, None, &prefix),
        Some((prefix.clone(), 978)),
        "a seat of its own, the id minted"
    );
    assert_ne!(next_prefix_under(port, None, "1"), prefix, "the frontier moved");
    let seated = open_session(port, 978);
    assert_eq!(create_doc(port, &seated, &prefix), format!("{prefix}.0.1"), "the seated principal's home mint");
    assert!(!presented_dead(port, &as_zero), "the signed 0 session lives across its own write");

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
/// obvious cleanup of two near-identical two-characters-per-byte loops —
/// refuses a signature a client legitimately sent, as `400
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
// The list is CONFIG: every cell here moves it the way an operator does —
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

/// An OFF-BOARD host's account, lexically: `2` is no root the registry
/// assigns (REG-1.67), so it sits under no `1.N` and the off-board test —
/// the header's operator read against the board's NODE PREFIX (REG-1.69;
/// AUTH-4.36 step 4b as ruled 2026-09-18) — refuses it under any prefix.
/// The host in the registry's own global form, `1.N.0.k`, is the new
/// vector's (`the_off_board_test_runs_against_the_node_prefix…`).
const OFF_BOARD_HOST: &str = "2.0.7";

/// The suite's board in the registry: `--node-prefix 1.3` (REG-1.69), which
/// every listed board is launched with — so the off-board test is LIVE in
/// every vector, and a header's operator is on-board iff it sits under it.
const NODE_PREFIX: &str = "1.3";

/// `local`'s GLOBAL form on the suite's board: the local `1` replaced by
/// [`NODE_PREFIX`] (REG-1.66: "egress replaces the local `1` with the
/// board's full node prefix") — the spelling the header's OPERATOR field
/// carries, since the off-board test reads it against that prefix.
fn global_form(local: &str) -> String {
    let rest = local.strip_prefix('1').expect("a local-form address begins with 1");
    format!("{NODE_PREFIX}{rest}")
}

/// A CLAIMED board (CLAIMED-PERMISSIVE) with the list's supply named and
/// the suite's node prefix: [`spawn_listed_at`] at [`NODE_PREFIX`].
fn spawn_listed(root: &std::path::Path) -> (skepd::Skepd, std::path::PathBuf) {
    spawn_listed_at(root, Some(NODE_PREFIX))
}

/// The supply file and the data dir, side by side under `root` — so a
/// restart over the same `root` meets the same file. The first issue is the
/// EMPTY list unless the file is already there, which is the restart cells'
/// case.
fn listed_dirs(root: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let list = root.join("blocked.json");
    if !list.exists() {
        issue_blocked_list(&list, BlockedHeader::default(), &[]);
    }
    let data = root.join("data");
    std::fs::create_dir_all(&data).expect("the data dir");
    (list, data)
}

/// A CLAIMED board (CLAIMED-PERMISSIVE) with the list's supply named and
/// `node_prefix` in force, or none.
fn spawn_listed_at(
    root: &std::path::Path,
    node_prefix: Option<&str>,
) -> (skepd::Skepd, std::path::PathBuf) {
    let (list, data) = listed_dirs(root);
    let sd = spawn_with_blocked_prefixes(&data, true, Some(&list), node_prefix);
    claim_board(sd.port()); // …whose own step writes H.1, for the attested writes below
    (sd, list)
}

/// [`spawn_listed`]'s board WITHOUT the claim — the pre-claim window, where
/// the list has no claimant to take as its comparand.
fn spawn_listed_unclaimed(root: &std::path::Path) -> (skepd::Skepd, std::path::PathBuf) {
    let (list, data) = listed_dirs(root);
    (spawn_with_blocked_prefixes(&data, true, Some(&list), Some(NODE_PREFIX)), list)
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

/// AUTH-4.44 and `Daemon::route`'s own rule — THE REISSUE STANDS AHEAD OF
/// DISPATCH ON EVERY REQUEST, `/events` INCLUDED: a stream opening as the
/// FIRST request after an issue installs that issue before it resolves its
/// own actor, so a covered token meets `Skepd-Session: closed` on the
/// stream's own head.
///
/// `/events` is the one route where a missed install is never corrected: a
/// stream resolves ONCE, at open, and the binding it opened under lives for
/// the connection. Put the look below dispatch — the natural place for a
/// per-request `stat`, since `Routed::EventStream` returns before `reply`
/// and a stream is not a reply — and this connect reads the PRE-issue list,
/// the stream opens with no signal, and a party the operator ordered dead
/// holds a live subscription for as long as it cares to.
///
/// The kill suite's own stream connects only after eight requests have
/// already installed the issue, and the one cell whose blocking request IS
/// its installing request drives `/session`, which goes through `reply`. So
/// this is the position neither of them puts `/events` in.
#[test]
fn a_stream_opening_first_after_an_issue_installs_it_before_it_resolves() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let member_key = distinct_key(35);
    let member = keyed_member(port, &anchor, 935, &member_key);
    let live = open_signed_session(port, 935, &member_key);

    // A stream opened BEFORE the issue carries no signal — the control that
    // makes the assertion below a statement about the install rather than
    // about this token.
    let (mut before, head) = Sse::connect_with_token(port, &live);
    assert!(
        !head.to_ascii_lowercase().contains("skepd-session: closed"),
        "no entry covers this binding yet: {head}"
    );
    before.expect_commit();

    // THE ISSUE, and then NOTHING but the stream: the connect is the request
    // that notices the file moved.
    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    let (_after, head) = Sse::connect_with_token(port, &live);
    assert!(
        head.to_ascii_lowercase().contains("skepd-session: closed"),
        "/events installed the reissue ahead of its own resolve: {head}"
    );

    sd.shutdown();
}

/// AUTH-4.63's second trigger against AUTH-4.27's order — THE BLOCK IS AHEAD
/// OF THE BARE ARM'S PER-REQUEST CONJUNCT: a BARE binding under a listed
/// prefix, presented from an origin OUTSIDE the bare set, answers DEATH and
/// never `RequestRefused`. It is the one cell where both would refuse, and so
/// the only one that tells their order apart.
///
/// The fear is the tidy inversion — test the cheap set membership first and
/// spend the list's linear scan only where the request would otherwise be
/// admitted, a cost `covers`' own card discloses per consult. Under it this
/// presentation is "refused for this request", which the rule reserves for a
/// binding that LIVES: no signal, nothing closed, and the M10 session and its
/// memo retained for a party the operator ordered dead.
///
/// The proof that it is death and not a refusal is that a LIFT does not bring
/// it back. `the_origin_header_fences_the_bare_bind_without_killing_it` is
/// this cell's other half, on a board with no list: there the same
/// presentation must NOT kill, and `a_reissued_entry_kills…` sends no
/// `Origin` at all, so the inversion is invisible to both.
#[test]
fn the_block_outranks_a_refused_origin_and_kills_the_bare_binding() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let member_key = distinct_key(36);
    let member = keyed_member(port, &anchor, 936, &member_key);
    let bare = open_session(port, 936);
    let draft = create_frame(&member, None);
    let evil = "https://evil.example";
    // The binding writes: the foreign origin alone would refuse it for THAT
    // request and leave it alive, which is what the block is about to outrank.
    expect_resp(&op(port, Some(&bare), &draft), "ack_addr");

    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    let (st, headers, body) =
        http_with_origin(port, "POST", "/op", Some(&bare), evil, draft.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        json(&body)["code"].as_str(),
        Some("unauthenticated"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        header(&headers, "Skepd-Session"),
        Some("closed"),
        "the cell where BOTH would refuse answers death, never refused-for-this-request"
    );

    // …and death is permanent, which is what tells it from a request refusal:
    // after the LIFT the same token is still gone, where a binding merely
    // refused for one request would write again the moment the entry went.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    assert!(presented_dead(port, &bare), "a killed bare binding stays gone after the lift");
    let (st, _, body) = http_full(port, "POST", "/op", Some(&bare), draft.as_bytes());
    assert_eq!(st, 200);
    assert_eq!(
        json(&body)["code"].as_str(),
        Some("unauthenticated"),
        "and it writes nothing: {}",
        String::from_utf8_lossy(&body)
    );
    // The PRINCIPAL is admitted again — the lift is a lift, not a ban.
    let fresh = open_session(port, 936);
    expect_resp(&op(port, Some(&fresh), &draft), "ack_addr");

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
/// "the OLD REGISTRAR" of the two fork rows — is whoever claimed it. The
/// board is launched `--node-prefix 1.3`, so "NOT an account of this board"
/// is read against that prefix (REG-1.69; the ruled form of step 4b): the
/// lexically foreign host is off-board under it, and the seat a self-served
/// fork names is spelled in the GLOBAL form the header carries.
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
    // none (RES-66 item 4 (i)): the same inert set. Named here in the LOCAL
    // form, under no `1.N`, it reads OFF-board under the ruled test, and (b)
    // — the claimant, the field omitted — is the one account (a) already
    // is; the verdicts are the row above's, by the other comparand.
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
    // account of the copy — in the GLOBAL form under the board's node
    // prefix, `1.3.0.k`, the form that reads ON-board — so (b) is SILENT
    // and the old claimant stays blockable (RES-66). The entry over the OLD
    // CLAIMANT installs and its sessions die, principal 0's among them (0 ↦
    // the claimant); the entry over the SEAT — spelled as the header spells
    // it, the operator being read as spelled — is ignored.
    let seat_live = open_signed_session(port, 941, &seat_key);
    let seat_global = global_form(&seat);
    let self_served = BlockedHeader { operator: Some(&seat_global), binding_writer: None };
    issue_blocked_list(
        &list,
        self_served,
        &[(claimant, RECORD_CLAIMANT), (&seat_global, RECORD_SEAT)],
    );
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

/// THE OFF-BOARD TEST RUNS AGAINST THE NODE PREFIX (REG-1.69; AUTH-4.36 step
/// 4b's comparand (b) as ruled 2026-09-18), never against the local root `1`
/// — under which a host's account in the registry's GLOBAL form (`1.3.0.7`:
/// every global address begins with the root, REG-1.66) read as on-board,
/// (b) went silent, and the hosted board's claimant became blockable (W2a's
/// escalation 3). ONE header — operator `1.3.0.7`, the second field omitted
/// — installed on three boards:
///
/// * `--node-prefix 1.3`: the operator is ON-BOARD, under the prefix; (b) is
///   SILENT, and the entry over the claimant — the binding-writing account —
///   is LIVE: the claimant's session dies and its handshake is the 403;
/// * `--node-prefix 1.5`: the same operator is OFF-BOARD; (b) is LIVE, and
///   the entry over the served board's claimant is INERT (and logged): its
///   session lives and its handshake is admitted, principal 0's with it;
/// * no node prefix: the daemon cannot tell, the test is OFF and every
///   operator reads as on-board — the claimant blockable, as on the first
///   board — and the install log says so once (pinned at the unit level,
///   the log being stderr).
///
/// On every board a MEMBER's entry installs: the list is in force, and only
/// the exemption moves.
#[test]
fn the_off_board_test_runs_against_the_node_prefix_and_is_off_without_one() {
    // Board `1.3`'s account `0.7`, in the registry's global form.
    const OPERATOR: &str = "1.3.0.7";
    let header = BlockedHeader { operator: Some(OPERATOR), binding_writer: None };
    for (node_prefix, claimant_blockable, what) in [
        (Some("1.3"), true, "--node-prefix 1.3: the operator on-board, (b) silent"),
        (Some("1.5"), false, "--node-prefix 1.5: the operator off-board, (b) live"),
        (None, true, "no --node-prefix: the test off, every operator on-board"),
    ] {
        let root = tempfile::tempdir().expect("tempdir");
        let (sd, list) = spawn_listed_at(root.path(), node_prefix);
        let port = sd.port();
        let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
        let member_key = distinct_key(51);
        let member = keyed_member(port, &anchor, 951, &member_key);
        let claimant_live = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let zero_live = open_signed_session(port, PRINCIPAL_ZERO, &device_key());
        let member_live = open_signed_session(port, 951, &member_key);
        issue_blocked_list(
            &list,
            header,
            &[(CLAIMANT_ACCOUNT, RECORD_CLAIMANT), (&member, RECORD_MEMBER)],
        );
        assert!(presented_dead(port, &member_live), "{what}: a member's session dies");
        assert_blocked(port, 951, &member_key, RECORD_MEMBER, what);
        if claimant_blockable {
            assert!(presented_dead(port, &claimant_live), "{what}: the claimant's session dies");
            assert!(presented_dead(port, &zero_live), "{what}: principal 0's dies with it");
            assert_blocked(port, CLAIMANT_PRINCIPAL, &device_key(), RECORD_CLAIMANT, what);
            assert_blocked(port, PRINCIPAL_ZERO, &device_key(), RECORD_CLAIMANT, what);
        } else {
            assert!(!presented_dead(port, &claimant_live), "{what}: the served claimant lives");
            assert!(!presented_dead(port, &zero_live), "{what}: principal 0's session lives");
            open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
            open_signed_session(port, PRINCIPAL_ZERO, &device_key());
        }
        sd.shutdown();
    }
}

/// REG-1.69/1.70 — THE NODE PREFIX IS PER-DAEMON CONFIG, SUPPLIED AT EVERY
/// START AND IN NO RECORD, JOURNAL, SIDECAR OR FOLD: one board, one journal,
/// one supply file, one header — and the off-board test follows the FLAG
/// across a restart, which is how a board answers to a successor prefix.
///
/// Under `1.3` the header's operator is an account of this board, so (b) is
/// silent and the entry over the claimant is LIVE. Restarted under `1.5` —
/// the same data dir, the same list, the same recovered claimant — the
/// operator is off-board, (b) goes live, and that entry is INERT. Remember
/// the prefix anywhere and the documented reconfigure does nothing: the
/// served claimant stays blockable, or a standing block stays lifted.
///
/// The three-board table above cannot see this — each board writes its own
/// state under its own flag, so anything remembered at first start agrees
/// with the flag on every row — and it is also the one cell where BOTH
/// start-up comparands resolve live at once: the recovered claimant standing
/// as (b) because a named operator is off-board.
#[test]
fn a_restart_under_a_fresh_node_prefix_moves_the_off_board_test() {
    // Board `1.3`'s account `0.7`, in the registry's global form.
    const OPERATOR: &str = "1.3.0.7";
    let header = BlockedHeader { operator: Some(OPERATOR), binding_writer: None };
    let root = tempfile::tempdir().expect("tempdir");
    let member_key = distinct_key(37);
    {
        let (sd, list) = spawn_listed_at(root.path(), Some("1.3"));
        let port = sd.port();
        let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
        let member = keyed_member(port, &anchor, 937, &member_key);
        issue_blocked_list(
            &list,
            header,
            &[(CLAIMANT_ACCOUNT, RECORD_CLAIMANT), (&member, RECORD_MEMBER)],
        );
        // Under the board's OWN prefix the operator is on-board: (b) silent,
        // the claimant blockable, principal 0 with it.
        assert_blocked(port, CLAIMANT_PRINCIPAL, &device_key(), RECORD_CLAIMANT, "under 1.3");
        assert_blocked(port, PRINCIPAL_ZERO, &device_key(), RECORD_CLAIMANT, "under 1.3");
        assert_blocked(port, 937, &member_key, RECORD_MEMBER, "under 1.3");
        sd.shutdown();
    }

    // THE RECONFIGURE: the same root, so the same data dir and the same
    // supply file — only the flag moves.
    let (sd, _) = spawn_listed_at(root.path(), Some("1.5"));
    let port = sd.port();
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    open_signed_session(port, PRINCIPAL_ZERO, &device_key());
    // The MEMBER's entry is the pairing: it covers no comparand under either
    // prefix, so the list being in force is not in question — only (b) moved.
    assert_blocked(port, 937, &member_key, RECORD_MEMBER, "the list is still in force under 1.5");
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
    opts.blocked_supply_path = Some(list.clone());
    let refused = skepd::Daemon::open_with(root.path().join("data"), opts);
    assert!(
        matches!(refused, Err(skepd::DaemonError::BlockedPrefixes(_))),
        "a malformed start-up supply refuses the open"
    );
    let mut opts = skepd::AuthOptions::default();
    opts.blocked_supply_path = Some(root.path().join("no-such-file.json"));
    let refused = skepd::Daemon::open_with(root.path().join("data"), opts);
    assert!(
        matches!(refused, Err(skepd::DaemonError::BlockedPrefixes(_))),
        "and so does a supply that is not there"
    );
}

/// RES-115's RUNTIME half, on the accident the operator is likeliest to have:
/// the supply file DELETED while the daemon runs. Its identity moved, so the
/// channel looks — and the read fails, which installs NOTHING (the list is
/// replaced WHOLE or not at all), so an absent file is NO LIFT: a lift of
/// everything is an ISSUE, the explicit empty list.
///
/// The bad-bytes cells above fail inside the supply's parse; a deletion fails
/// one layer earlier, at the open, and stamps no file where they stamp one —
/// so "no file, no blocks", the natural reading, lifts every standing
/// takedown at the next request and passes every one of those cells.
///
/// And the channel is not stuck by the accident: the next good issue installs,
/// so the operator's own lift still works afterwards.
#[test]
fn deleting_the_supply_installs_nothing_and_the_list_in_force_stands() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let member_key = distinct_key(34);
    let member = keyed_member(port, &anchor, 934, &member_key);
    let live = open_signed_session(port, 934, &member_key);

    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    assert!(presented_dead(port, &live), "the entry is in force");
    assert_blocked(port, 934, &member_key, RECORD_MEMBER, "the entry is in force");

    std::fs::remove_file(&list).expect("remove the supply");
    assert_blocked(port, 934, &member_key, RECORD_MEMBER, "the file gone: the block stands");
    // The second look rules out a first request that happened not to reach
    // the channel, and pins that the refusal is remembered without the list
    // moving under it.
    assert_blocked(port, 934, &member_key, RECORD_MEMBER, "…and at the next look too");

    // The next GOOD issue installs: the failed look stopped nothing.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    open_signed_session(port, 934, &member_key);

    sd.shutdown();
}

/// RES-115 and AUTH-4.36 step 4b together, at the ONE install the reissue
/// cells cannot reach: the START-UP install reads the claimant the canonical
/// rebuild has just recovered, so an entry over the claimant is INERT again
/// after a restart. Installed without it — the "there is no fold yet at open"
/// reading — comparand (a) is absent, `covers` answers nobody, the entry goes
/// LIVE, and the board's owner is locked out of their own board on every
/// restart, principal 0 with it: the cell REG-4.198 rules out, appearing at
/// the moment nobody is watching.
///
/// The member's entry is the PAIRING that makes the claimant's admission mean
/// anything: the same install put it in force, so the claimant being admitted
/// is not merely a list that failed to install at all.
#[test]
fn a_restart_installs_the_list_against_the_recovered_claimant() {
    let root = tempfile::tempdir().expect("tempdir");
    let member_key = distinct_key(33);
    {
        let (sd, list) = spawn_listed(root.path());
        let port = sd.port();
        let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
        let member = keyed_member(port, &anchor, 933, &member_key);
        issue_blocked_list(
            &list,
            BlockedHeader::default(),
            &[(CLAIMANT_ACCOUNT, RECORD_CLAIMANT), (&member, RECORD_MEMBER)],
        );
        assert_blocked(port, 933, &member_key, RECORD_MEMBER, "before the restart: the member");
        open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        sd.shutdown();
    }

    let (sd, _) = spawn_listed(root.path());
    let port = sd.port();
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // Principal 0 is the second witness of the same comparand: it maps to the
    // claimant on both accessors (AUTH-4.30), so it is exempt with it.
    open_signed_session(port, PRINCIPAL_ZERO, &device_key());
    assert_blocked(port, 933, &member_key, RECORD_MEMBER, "the restart installed the list");
    sd.shutdown();
}

/// RES-65 item 4's residue and item 3's, in the window no other listed board
/// is in: UNCLAIMED. The header names none and there is NO CLAIMANT to take in
/// its place, so there is no comparand and every entry STANDS AS ISSUED — over
/// the very account the ceremony would have claimed with, which is what makes
/// the residue a residue. It reaches its own prefix and no other, so the kill
/// is by coverage and not by a list merely being in force.
///
/// And the BARE ARM is untouched by the list (AUTH-4.37): a bare bind naming a
/// covered principal is admitted as written — never the 403, which the signed
/// arm alone answers — and `resolve`'s arm-blind kill is what ends it, at the
/// first presentation.
///
/// The claimed-board contrast for the same entry is
/// [`the_headers_two_comparands_are_inert_at_the_four_lineage_cells`], where
/// the claimant IS the comparand and the entry over it is inert. It cannot be
/// run on this board: the ceremony must be the board's first delegate, and
/// this cell has already spent that address.
#[test]
fn an_unclaimed_board_has_no_comparand_so_every_entry_stands_as_issued() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed_unclaimed(root.path());
    let port = sd.port();
    assert!(!claimed(port), "the pre-claim window");

    let (covered, covered_session) = bootstrap_delegate(port, 961);
    let (_, sibling_session) = bootstrap_delegate(port, 962);
    assert_eq!(covered, CLAIMANT_ACCOUNT, "the first delegate takes the claimant's address");

    issue_blocked_list(&list, BlockedHeader::default(), &[(&covered, RECORD_CLAIMANT)]);
    assert!(presented_dead(port, &covered_session), "no claimant, no comparand: the entry stands");
    assert!(!presented_dead(port, &sibling_session), "and it reaches its own prefix and no other");

    let (st, headers, body) =
        http_full(port, "POST", "/session", None, br#"{"principal":961}"#);
    assert_eq!(st, 200, "the bare arm reads no list: {}", String::from_utf8_lossy(&body));
    assert!(header(&headers, "Skepd-Session").is_none(), "/session is token-blind");
    let fresh = json(&body)["session"].as_str().expect("session").to_string();
    assert!(presented_dead(port, &fresh), "…and the fresh binding dies at its first presentation");

    sd.shutdown();
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
    let retire = record_atom(port, &anchor, ordinal, &retire_atom(&[&device_fp]), T_RETIRE);
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
    let retire = record_atom(port, &anchor, ordinal, &retire_atom(&[&device_fp]), T_RETIRE);
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

// ═══════════════════════════════════════════════════════════════════════════
// THE ANCHOR GATE'S HANDOFF EXCEPTION AT SLOT (6) (AUTH-3.21; RES-165, 170,
// 171, 172, 175) — the conformance pack's §2.4 table BY TERMINUS, row by row —
// THE SEAT CARVE's one input (AUTH-3.15; RES-195), and THE
// CONTENT-SCOPED SESSION (AUTH-6.2–6.4, AUTH-4.39, AUTH-3.44; RES-63 item 7).
//
// A genesis is a record landed in its REGISTRY's doc 1 and an enroll-typed
// deposit naming the account it seeds. Every cell below lands the record
// from a session the publish gate admits and then judges the DEPOSIT, which
// is the credential path's and the one slot (6) reads. The cells are chosen
// so the address test is what decides them: where a cell COMMITS from a
// device session, the set that opens the account holds an ANCHOR, so the
// same deposit read a handoff would have been refused.
// ═══════════════════════════════════════════════════════════════════════════

const ANCHOR_SESSION_REQUIRED: &str = "credential_refused:anchor_session_required";
const CONTENT_SESSION: &str = "credential_refused:content_session";
const SIGNED_SESSION_REQUIRED: &str = "credential_refused:signed_session_required";

/// Land one credential record atom at the next free position of `doc1` and
/// answer its address — [`record_atom`] for a registry that is not the
/// claimant's, declared under the record's class type `ty` as that one is.
/// `session` is one the publish gate admits into a published home: a signed
/// one, of either scope.
fn land_record(port: u16, session: &str, doc1: &str, atom: &str, ty: &str) -> String {
    let ordinal = next_content_ordinal(port, Some(session), doc1);
    acked_addr(&op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"insert","doc":"{doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
        ),
    ))
}

/// The enroll-typed deposit of an already-landed record, homed in `doc1` and
/// naming `account` — a GENESIS wherever `account` holds no set. UNJUDGED:
/// the answer is the cell.
fn enroll_for(port: u16, session: &str, doc1: &str, record: &str, account: &str) -> Value {
    typed_link(port, session, doc1, &[record], &[account], T_ENROLL)
}

/// How many keys `account`'s OWN set holds now, off the public read.
fn enrolled_count(port: u16, account: &str) -> usize {
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{account}"}}"#));
    expect_resp(&v, "key_set")["enrolled"].as_array().expect("enrolled").len()
}

/// One enroll record of a single fresh DEVICE-flagged key, by seed.
fn fresh_member(seed: u8) -> String {
    enroll_atom(&[&distinct_key(seed)])
}

/// §2.4 rows 5, 6 and 7, and AUTH-3.44's order across (6) and (7): under an
/// ANCHORED `X`, a genesis at `X.2` is `X`'s HANDOFF — refused
/// `anchor_session_required` from a device session and from a bare one (the
/// specific token masks slot (7)'s), committed from an ANCHOR session of the
/// set that opens the account; a TOP-LEVEL account's own genesis enters NO
/// cone — slot (6) is silent, so `X`'s device session commits it and `X`'s
/// BARE session meets slot (7), `signed_session_required`, still LAST on a
/// claimed board; and an ANCHORLESS giver's handoff stays device-grade.
#[test]
fn a_handoff_is_anchor_grade_wherever_the_set_that_opens_the_account_holds_an_anchor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let device = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    delegate_under(port, &bare, CLAIMANT_ACCOUNT, 951); // X.1, the held agent space
    let (x2, _) = delegate_under(port, &bare, CLAIMANT_ACCOUNT, 952);
    assert_eq!(x2, format!("{CLAIMANT_ACCOUNT}.2"));

    // ROW 5 — a by-reference descendant of S = X that is neither a hire's nor
    // a spawn's address: X's HANDOFF, and X's set holds the ceremony's anchor.
    let record = land_record(port, &device, CLAIMANT_DOC1, &fresh_member(61), T_ENROLL);
    for (hand, token) in [("a device session", &device), ("a bare session", &bare)] {
        let v = enroll_for(port, token, CLAIMANT_DOC1, &record, &x2);
        assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "{hand}'s genesis at X.2: {v}");
    }
    assert_eq!(enrolled_count(port, &x2), 0, "a refused handoff commits nothing");
    // …and an ANCHOR session's commits: the same record, the same frame.
    expect_resp(&enroll_for(port, &anchor, CLAIMANT_DOC1, &record, &x2), "ack_addr");
    assert_eq!(enrolled_count(port, &x2), 1, "the recipient's key, latched");

    // ROW 6 — a top-level account's own genesis enters NO cone: no keyed
    // ACCOUNT stands above it, its registry being the claimant's doc 1 by the
    // bootstrap tier's rule and not by descent. Slot (6) is silent, so the
    // bare session's plant dies at slot (7) — the generic token, LAST — where
    // the same session's handoff above died at (6); and the device session,
    // no anchor of X's, commits it.
    let (member, _) = bootstrap_delegate(port, 961);
    let member_key = distinct_key(62);
    let record = land_record(port, &device, CLAIMANT_DOC1, &enroll_atom(&[&member_key]), T_ENROLL);
    let v = enroll_for(port, &bare, CLAIMANT_DOC1, &record, &member);
    assert_eq!(verdict(&v), SIGNED_SESSION_REQUIRED, "a bare genesis in no cone meets (7): {v}");
    expect_resp(&enroll_for(port, &device, CLAIMANT_DOC1, &record, &member), "ack_addr");

    // ROW 7 — the same act under an ANCHORLESS giver stays device-grade
    // (AUTH-5.16's standing price): the member's set is its one device key.
    let giver = open_signed_session(port, 961, &member_key);
    let member_doc1 = create_doc(port, &giver, &member);
    reserve_agent_space(port, &giver, &member, 9611);
    let (handed, _) = delegate_under(port, &giver, &member, 9612);
    let record = land_record(port, &giver, &member_doc1, &fresh_member(63), T_ENROLL);
    expect_resp(&enroll_for(port, &giver, &member_doc1, &record, &handed), "ack_addr");
    assert_eq!(enrolled_count(port, &handed), 1);

    sd.shutdown();
}

/// §2.4 rows 1, 2 and 5 down one chain, each measured at the walk's TERMINUS
/// (RES-172). `Y = X.2` is handed to a recipient whose set holds an ANCHOR and
/// who works from a DEVICE session throughout:
///
/// * `inc(Y, 1)` ITSELF — the agents' home — is a HANDOFF (`Y` is not
///   bootstrap-tier, so the fold honors the genesis and slot (6) is reached):
///   `anchor_session_required`;
/// * a child of `inc(Y, 1)` is a HIRE — device-grade, COMMITS;
/// * a genesis beneath that AGENT — which stands at `inc(inc(Y, 1), 1)`
///   beneath its own nearest keyed ancestor `Y`, and holds an anchor of its
///   own — is a SPAWN: device-grade, COMMITS, its first sub-account included;
/// * and the terminus is read ALONE: the WORKER that spawn keyed stands at no
///   agent's position, so a genesis beneath it is the worker's own HANDOFF,
///   graded at the worker's set — an agent further up the chain is not read.
#[test]
fn a_hire_and_a_spawn_are_device_grade_and_the_agents_home_itself_is_a_handoff() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    delegate_under(port, &bare, CLAIMANT_ACCOUNT, 951);
    let (y, _) = delegate_under(port, &bare, CLAIMANT_ACCOUNT, 952);
    // The handoff of Y, from X's anchor session: the recipient's paper and
    // device keys.
    let x_anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let (r_paper, r_device) = (distinct_key(61), distinct_key(62));
    let record = land_record(
        port,
        &x_anchor,
        CLAIMANT_DOC1,
        &enroll_atom_flagged(&[(&r_paper, true), (&r_device, false)]),
        T_ENROLL,
    );
    expect_resp(&enroll_for(port, &x_anchor, CLAIMANT_DOC1, &record, &y), "ack_addr");
    let r = open_signed_session(port, 952, &r_device);
    let y_doc1 = create_doc(port, &r, &y);

    // ROW 5 — the agents' home itself.
    let (home, _) = delegate_under(port, &r, &y, 9521);
    assert_eq!(home, format!("{y}.1"));
    let home_record = land_record(port, &r, &y_doc1, &fresh_member(63), T_ENROLL);
    let v = enroll_for(port, &r, &y_doc1, &home_record, &home);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "the agents' home is a handoff: {v}");

    // ROW 1 — THE HIRE. The home holds no set, so a session AS it opens by
    // reference against Y's (AUTH-4.30 (i)) — under the recipient's DEVICE
    // key, no anchor of Y's — and the hire's registry is the home's doc 1.
    let as_home = open_signed_session(port, 9521, &r_device);
    let home_doc1 = create_doc(port, &as_home, &home);
    let agent = next_prefix_under(port, Some(&as_home), &home);
    assert_eq!(agent, format!("{home}.1"));
    // THE LAYOUT'S FIFTH VECTOR, its second half (RES-64 item 8; (c) row 1):
    // the hire's `delegate` from the HOLDER's own session AS `Y` is
    // `not_authorized` and commits nothing. R's keys OPEN `Y.1` by reference,
    // but the principal bound to a session as `Y` does not OWN it — the
    // agents' home is its own seat — so M3's ownership guard answers. The SAME
    // frame from the session as `Y.1` acks.
    let hire_delegate = format!(r#"{{"op":"delegate","new_prefix":"{agent}","new_id":95211}}"#);
    let before = head_position(port);
    let v = op(port, Some(&r), &hire_delegate);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("delegate"), "{v}");
    assert_eq!(rej["code"].as_str(), Some("not_authorized"), "the holder's session as Y: {v}");
    assert_eq!(head_position(port), before, "the refused delegate committed nothing");
    assert_eq!(next_prefix_under(port, None, &home), agent, "and seated nobody");
    assert_eq!(acked_addr(&op(port, Some(&as_home), &hire_delegate)), agent);
    let (g_paper, g_device) = (distinct_key(64), distinct_key(65));
    let record = land_record(
        port,
        &as_home,
        &home_doc1,
        &enroll_atom_flagged(&[(&g_paper, true), (&g_device, false)]),
        T_ENROLL,
    );
    expect_resp(&enroll_for(port, &as_home, &home_doc1, &record, &agent), "ack_addr");

    // ROW 2 — THE SPAWN, beneath the agent, from the agent's DEVICE session:
    // its first sub-account, which beneath any account that is no agent is
    // that account's agents' home and a handoff.
    let g = open_signed_session(port, 95_211, &g_device);
    let agent_doc1 = create_doc(port, &g, &agent);
    let (worker, _) = delegate_under(port, &g, &agent, 952_111);
    assert_eq!(worker, format!("{agent}.1"));
    let (w_paper, w_device) = (distinct_key(66), distinct_key(67));
    let record = land_record(
        port,
        &g,
        &agent_doc1,
        &enroll_atom_flagged(&[(&w_paper, true), (&w_device, false)]),
        T_ENROLL,
    );
    expect_resp(&enroll_for(port, &g, &agent_doc1, &record, &worker), "ack_addr");

    // THE TERMINUS, ALONE. The worker is keyed and stands at `inc(agent, 1)`
    // beneath its own nearest keyed ancestor, the agent — no agent's
    // position — so what lies beneath it is measured at the WORKER: its own
    // handoff, anchor-grade, its set holding an anchor.
    let w = open_signed_session(port, 952_111, &w_device);
    let worker_doc1 = create_doc(port, &w, &worker);
    let (below, _) = delegate_under(port, &w, &worker, 9_521_111);
    let record = land_record(port, &w, &worker_doc1, &fresh_member(68), T_ENROLL);
    let v = enroll_for(port, &w, &worker_doc1, &record, &below);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "measured at the worker alone: {v}");
    let w_anchor = open_signed_session(port, 952_111, &w_paper);
    expect_resp(&enroll_for(port, &w_anchor, &worker_doc1, &record, &below), "ack_addr");

    // …and the recipient's PAPER hands the agents' home away, as a device
    // session could not.
    let r_anchor = open_signed_session(port, 952, &r_paper);
    expect_resp(&enroll_for(port, &r_anchor, &y_doc1, &home_record, &home), "ack_addr");

    sd.shutdown();
}

/// §2.4 rows 3 and 4 — THE SEAT CARVE, and AUTH-3.15's ONE INPUT: the
/// list header's SECOND field, compared with the claimant. Where it names an
/// account that is NOT the claimant — the SEAT of a forked lineage — a
/// genesis into that account's DIRECT CHILD is an ADMISSION, device-grade;
/// `inc(seat, 1)` itself, the seat's own first sub-account, stays a HANDOFF; and
/// with no header, or one naming the claimant, the carve is SILENT. The field
/// is config, read per request: re-issue it and the carve moves with it.
#[test]
fn the_seat_carve_admits_into_the_seats_direct_child_and_is_silent_without_the_header() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let device = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // T — a top-level account whose set holds an ANCHOR, working from a
    // DEVICE session throughout.
    let (t, _) = bootstrap_delegate(port, 941);
    let (t_paper, t_device) = (distinct_key(41), distinct_key(42));
    let record = land_record(
        port,
        &device,
        CLAIMANT_DOC1,
        &enroll_atom_flagged(&[(&t_paper, true), (&t_device, false)]),
        T_ENROLL,
    );
    expect_resp(&enroll_for(port, &device, CLAIMANT_DOC1, &record, &t), "ack_addr");
    let seat = open_signed_session(port, 941, &t_device);
    let t_doc1 = create_doc(port, &seat, &t);
    let (t1, _) = delegate_under(port, &seat, &t, 9411);
    let (t2, _) = delegate_under(port, &seat, &t, 9412);
    let (t3, _) = delegate_under(port, &seat, &t, 9413);
    // The header's SECOND field alone: the carve reads it as issued, whatever
    // the first says of the operator.
    fn header(binding_writer: Option<&str>) -> BlockedHeader<'_> {
        BlockedHeader { operator: None, binding_writer }
    }

    // SILENT: no header, and a header whose second field names the CLAIMANT
    // — on an unforked lineage the two are one account. T.2 is T's handoff.
    let t2_record = land_record(port, &seat, &t_doc1, &fresh_member(43), T_ENROLL);
    for silent in [header(None), header(Some(CLAIMANT_ACCOUNT))] {
        issue_blocked_list(&list, silent, &[]);
        let v = enroll_for(port, &seat, &t_doc1, &t2_record, &t2);
        assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "the carve is silent: {v}");
    }
    // ROW 3 — THE CARVE: the field names T, which is not the claimant, and
    // the same deposit is an ADMISSION.
    issue_blocked_list(&list, header(Some(&t)), &[]);
    expect_resp(&enroll_for(port, &seat, &t_doc1, &t2_record, &t2), "ack_addr");
    // The seat's own first sub-account is no admission. At a TOP-LEVEL seat the
    // fold refuses it first: `inc(B, 1)` of a bootstrap-tier account takes no
    // genesis (AUTH-2.62), slot (3) ahead of slot (6).
    let t1_record = land_record(port, &seat, &t_doc1, &fresh_member(44), T_ENROLL);
    let v = enroll_for(port, &seat, &t_doc1, &t1_record, &t1);
    assert_eq!(verdict(&v), "credential_refused:not_genesis_registry", "{v}");

    // ROW 4 — so the cell slot (6) ITSELF answers is a seat that is not
    // bootstrap-tier: T.3, admitted into under the carve with an anchored set
    // of its own, then named the seat in its turn.
    let (q_paper, q_device) = (distinct_key(45), distinct_key(46));
    let record = land_record(
        port,
        &seat,
        &t_doc1,
        &enroll_atom_flagged(&[(&q_paper, true), (&q_device, false)]),
        T_ENROLL,
    );
    expect_resp(&enroll_for(port, &seat, &t_doc1, &record, &t3), "ack_addr");
    let q = open_signed_session(port, 9413, &q_device);
    let q_doc1 = create_doc(port, &q, &t3);
    let (q1, _) = delegate_under(port, &q, &t3, 94_131);
    let (q2, _) = delegate_under(port, &q, &t3, 94_132);
    let q1_record = land_record(port, &q, &q_doc1, &fresh_member(47), T_ENROLL);
    let q2_record = land_record(port, &q, &q_doc1, &fresh_member(48), T_ENROLL);
    // While T is the seat the carve reaches T's DIRECT children and no
    // deeper: T.3's own child is T.3's handoff.
    let v = enroll_for(port, &q, &q_doc1, &q2_record, &q2);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "beneath the seat's child: {v}");
    issue_blocked_list(&list, header(Some(&t3)), &[]);
    let v = enroll_for(port, &q, &q_doc1, &q1_record, &q1);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "inc(seat, 1) stays a handoff: {v}");
    expect_resp(&enroll_for(port, &q, &q_doc1, &q2_record, &q2), "ack_addr");
    // …and T, the seat no longer, is a giver again: its device session is
    // refused where its paper commits.
    let (t4, _) = delegate_under(port, &seat, &t, 9414);
    let t4_record = land_record(port, &seat, &t_doc1, &fresh_member(49), T_ENROLL);
    let v = enroll_for(port, &seat, &t_doc1, &t4_record, &t4);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "the carve moved with the header: {v}");
    let t_anchor = open_signed_session(port, 941, &t_paper);
    expect_resp(&enroll_for(port, &t_anchor, &t_doc1, &t4_record, &t4), "ack_addr");

    sd.shutdown();
}

/// THE SEIZED CLASS (RES-155; AUTH-5.89) — the walk ENDS AT SLOT (6). A thief
/// holding one DEVICE key of `X`'s set writes, from a session as `X`, one
/// genesis for the person's own content-bearing topic `X.2`, homed in `X`'s
/// doc 1 and naming fresh keys of its own: ω passes, the fold previews it
/// `Honored(Genesis)`, the latch finds the keys disjoint — and the anchor
/// gate refuses it, `X`'s set holding an anchor. Nor does a device key the
/// thief ENROLS for itself climb past it (AUTH-3.65's thief-enrolled row).
/// Nothing is taken: `X.2` holds no set, the person's by-reference session
/// there lives and still reads its draft, and the thief's key opens nothing.
#[test]
fn a_stolen_device_key_cannot_seize_a_subdivision_the_walk_ends_at_slot_6() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let accounts = by_reference_accounts(port);
    let topic = &accounts.x2_account;
    // The person's topic: its home, and a draft filed from a session AS it.
    let person = open_signed_session(port, accounts.x2, &device_key());
    create_doc(port, &person, topic);
    let draft = create_doc(port, &person, topic);
    expect_resp(&insert_text(port, &person, &draft, 1, "mine"), "ack_addr");

    let thief = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let thief_key = distinct_key(91);
    let record = land_record(port, &thief, CLAIMANT_DOC1, &enroll_atom(&[&thief_key]), T_ENROLL);
    let v = enroll_for(port, &thief, CLAIMANT_DOC1, &record, topic);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "the seizure: {v}");
    // The climb: a device-flagged enrollment at X is device-grade and
    // commits, and the session that key opens is no anchor's either.
    let climber = distinct_key(92);
    let own = land_record(port, &thief, CLAIMANT_DOC1, &enroll_atom(&[&climber]), T_ENROLL);
    expect_resp(&deposit(port, &thief, &own, T_ENROLL), "ack_addr");
    let climbed = open_signed_session(port, CLAIMANT_PRINCIPAL, &climber);
    let v = enroll_for(port, &climbed, CLAIMANT_DOC1, &record, topic);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "the thief-enrolled key: {v}");

    assert_eq!(enrolled_count(port, topic), 0, "the topic holds no set: nothing was seeded");
    assert!(!presented_dead(port, &person), "the person's session as the topic lives");
    assert_eq!(text_of(port, Some(&person), &draft, 1, 4), "mine", "and reads its draft");
    let (st, _, _) = signed_handshake(port, accounts.x2, &thief_key);
    assert_eq!(st, 401, "the thief's key opens nothing");

    sd.shutdown();
}

/// RES-63 item 7, the HANDSHAKE's cells (AUTH-6.2–6.4): a SCOPED body opens
/// (200, the base's two members — the scope is not echoed); a wrong `scope`
/// value or type is `400 malformed_session_request` AHEAD of the burn, so the
/// nonce SURVIVES and the same nonce then opens; `scope` on the BARE body is
/// the 400; a v1 signature over a scoped body is the one 401 — and a v2
/// signature over an UNSCOPED body likewise: each layout verifies under its
/// own tag only. `/health.auth` gains no field.
#[test]
fn a_scoped_body_opens_under_the_v2_bytes_and_a_scope_fault_spends_no_nonce() {
    const REJECTED: &str = r#"{"error":"session_rejected"}"#;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let origin = format!("http://127.0.0.1:{port}");
    let post = |body: &str| http_full(port, "POST", "/session", None, body.as_bytes());
    let malformed = |what: &str, (st, _, body): (u16, Vec<(String, String)>, Vec<u8>)| {
        assert_eq!(st, 400, "{what}: {}", String::from_utf8_lossy(&body));
        assert_eq!(json(&body)["error"].as_str(), Some("malformed_session_request"), "{what}");
    };
    let rejected = |what: &str, (st, _, body): (u16, Vec<(String, String)>, Vec<u8>)| {
        assert_eq!(st, 401, "{what}");
        assert_eq!(String::from_utf8(body).expect("utf-8"), REJECTED, "{what}: the one code");
    };

    // A WRONG SCOPE — every other value, type and case — signed exactly as
    // it says (so nothing but the field is at fault): the 400, and the nonce
    // survives every one of them…
    let nonce = challenge(port, p);
    for bad in [r#""full""#, r#""Content""#, r#""""#, "null", "true", "1", r#"["content"]"#] {
        let said = bad.trim_matches('"');
        let sig = sign_session_scoped(&device_key(), &origin, &nonce, p, said);
        let body = format!(
            "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"scope\":{bad},\"sig\":\"{sig}\"}}"
        );
        malformed(&format!("scope {bad}"), post(&body));
    }
    // …and `scope` on the BARE body, the one admitted value included.
    malformed("scope on the bare body", post(&format!("{{\"principal\":{p},\"scope\":\"content\"}}")));
    // …so THE SAME NONCE then opens: the scoped body, signed under v2.
    let sig = sign_session_scoped(&device_key(), &origin, &nonce, p, "content");
    let (st, _, body) = post(&scoped_session_body(p, &nonce, &origin, &sig));
    assert_eq!(st, 200, "a scoped body opens: {}", String::from_utf8_lossy(&body));
    let opened = json(&body);
    let members: Vec<&str> =
        opened.as_object().expect("an object").keys().map(String::as_str).collect();
    assert_eq!(members, ["principal", "session"], "the base's answer, no scope echoed: {opened}");
    // The opening spent it, as any opening does.
    rejected("a spent nonce", post(&scoped_session_body(p, &nonce, &origin, &sig)));

    // A v1 SIGNATURE OVER A SCOPED BODY is the one 401 — a failure of the
    // credential, so its nonce is spent: the right signature cannot follow.
    let nonce = challenge(port, p);
    let v1 = sign_session(&device_key(), &origin, &nonce, p);
    rejected("a v1 signature over a scoped body", post(&scoped_session_body(p, &nonce, &origin, &v1)));
    let v2 = sign_session_scoped(&device_key(), &origin, &nonce, p, "content");
    rejected("and its nonce is spent", post(&scoped_session_body(p, &nonce, &origin, &v2)));
    // …and a v2 signature never opens an UNSCOPED body.
    let nonce = challenge(port, p);
    let v2 = sign_session_scoped(&device_key(), &origin, &nonce, p, "content");
    let unscoped = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{v2}\"}}"
    );
    rejected("a v2 signature over an unscoped body", post(&unscoped));

    // `/health.auth` says nothing of a scope, a content session being open.
    let health = json(&get(port, "/health").1);
    let auth: Vec<&str> =
        health["auth"].as_object().expect("auth").keys().map(String::as_str).collect();
    assert_eq!(auth, ["claimant", "local_trust", "origins", "signed_origins"], "{health}");

    sd.shutdown();
}

/// RES-63 item 7, the WRITE PATH's cells (AUTH-4.39, AUTH-3.44 slot (6)): a
/// content session's enrol and retirement answer `content_session`; so does
/// an ANCHOR key's content session's anchor act — ahead of the anchor gate,
/// the key not consulted; its content insert, publish and grant LAND, read
/// and testified as a full session's are; and `/session/close` is the 204.
/// THE ORDER, pinned on one anchor-flagged record: `content_session`, then
/// `anchor_session_required` — and slots (3)–(5) still AHEAD of both, a
/// content session's retry of a committed act answering the head's preview
/// token. A refusal is request-refused on a LIVE entry: no death signal.
#[test]
fn a_content_session_writes_content_and_deposits_no_credential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let content = open_content_session(port, p, &device_key());
    let paper_content = open_content_session(port, p, &anchor_key());
    let device = open_signed_session(port, p, &device_key());
    let device_fp = fingerprint_hex(&device_key());

    // CONTENT LANDS. A declared deposit into the published home — the write
    // a bare session is refused — testified under the key that opened the
    // session, the scope being nowhere in the record.
    let ordinal = next_content_ordinal(port, Some(&content), CLAIMANT_DOC1);
    let v = op(port, Some(&content), &insert_frame(CLAIMANT_DOC1, ordinal, "z", true));
    let at = acked_at(&v);
    let page = json(&http(port, "GET", &format!("/changes?since={}", at - 1), Some(&content), b"").1);
    let entry = page["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .find(|e| e["at"].as_u64() == Some(at))
        .unwrap_or_else(|| panic!("the insert's own entry: {page}"))
        .clone();
    assert_eq!(entry["key"].as_str(), Some(device_fp.as_str()), "the opening key testifies");
    assert!(entry.get("scope").is_none(), "the scope is in no record: {entry}");
    // A private draft, its bytes, and the session's own draft visibility.
    let draft = create_doc(port, &content, CLAIMANT_ACCOUNT);
    expect_resp(&insert_text(port, &content, &draft, 1, "abcde"), "ack_addr");
    assert_eq!(text_of(port, Some(&content), &draft, 1, 5), "abcde");
    assert_withheld(&op(port, None, &read1_frame(&draft)), &draft);
    // A GRANT — a non-credential `make_link` into the published home.
    let (stranger, _) = bootstrap_delegate(port, 961);
    deposit_grant(port, &content, CLAIMANT_DOC1, &draft, Some(&stranger));
    // THE SHOT — a published edition minted and published into.
    let edition = published_edition(port, &content);
    shot(port, &content, &edition, None, None, &[run(&draft, &format!("{draft}.0.1.1"), 2)]);

    // A DEVICE ENROL and a RETIREMENT — each previewed Honored, each
    // device-grade, each committed below by a FULL device session.
    let enrol = land_record(port, &content, CLAIMANT_DOC1, &fresh_member(71), T_ENROLL);
    let retire =
        land_record(port, &content, CLAIMANT_DOC1, &retire_atom(&[&fingerprint_hex(&distinct_key(71))]), T_RETIRE);
    // AN ANCHOR ACT — an anchor-flagged enrollment.
    let anchor_act =
        land_record(port, &content, CLAIMANT_DOC1, &enroll_atom_flagged(&[(&distinct_key(72), true)]), T_ENROLL);

    for (whose, token) in [("a device key's", &content), ("an anchor key's", &paper_content)] {
        for (act, record, ty) in [
            ("enrol", &enrol, T_ENROLL),
            ("anchor enrol", &anchor_act, T_ENROLL),
        ] {
            let (st, headers, body) = http_full(
                port,
                "POST",
                "/op",
                Some(token),
                deposit_frame(None, record, ty).as_bytes(),
            );
            assert_eq!(st, 200);
            assert_eq!(verdict(&json(&body)), CONTENT_SESSION, "{whose} content session's {act}");
            assert!(
                header(&headers, "Skepd-Session").is_none(),
                "{whose} content session's {act}: refused for this request, nothing died"
            );
        }
    }
    assert_eq!(enrolled_count(port, CLAIMANT_ACCOUNT), 2, "the ceremony's two keys, unmoved");

    // THE ORDER at slot (6), on the anchor act: the scope's token first,
    // then the anchor gate's — a FULL device session meets the second.
    assert_eq!(verdict(&deposit(port, &device, &anchor_act, T_ENROLL)), ANCHOR_SESSION_REQUIRED);
    // The full session commits the device enrol; the retirement of that key
    // is then a live act, which the content session is refused and the full
    // session commits.
    expect_resp(&deposit(port, &device, &enrol, T_ENROLL), "ack_addr");
    assert_eq!(verdict(&deposit(port, &content, &retire, T_RETIRE)), CONTENT_SESSION);
    // Slots (3)–(5) stand AHEAD: the content session's retry of the act the
    // full session committed answers the head's preview token.
    assert_eq!(
        verdict(&deposit(port, &content, &enrol, T_ENROLL)),
        "credential_refused:nothing_changed",
        "the preview token masks the scope's"
    );
    expect_resp(&deposit(port, &device, &retire, T_RETIRE), "ack_addr");

    // The content sessions outlived every refusal, and CLOSE as any session
    // does: the bare 204, the token then dead.
    for token in [&content, &paper_content] {
        assert!(!presented_dead(port, token), "a refusal is not a death");
        let (st, headers, body) = http_full(port, "POST", "/session/close", Some(token), b"");
        assert_eq!((st, body.len()), (204, 0), "close on a content session");
        assert!(header(&headers, "Skepd-Session").is_none(), "a live close carries no signal");
        assert!(presented_dead(port, token), "and the token is closed");
    }

    sd.shutdown();
}

/// RES-63 item 7's CLAIM cell. The claim link is credential-typed, so the
/// ceremony's step 5 runs on a FULL session: a content session's claim — on
/// an UNCLAIMED board, where the fold previews it Honored — answers
/// `content_session`, the board stays unclaimed, and the full session's
/// claim then lands.
#[test]
fn a_content_sessions_claim_is_refused_and_the_board_stays_unclaimed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let key = distinct_key(11);
    let partial = seed_partial(port, CLAIMANT_PRINCIPAL, &[(&key, false)]);

    let content = open_content_session(port, CLAIMANT_PRINCIPAL, &key);
    let v = claim_deposit(port, &content, &partial.doc1, &partial.account);
    assert_eq!(verdict(&v), CONTENT_SESSION, "a content session's claim: {v}");
    assert!(!claimed(port), "a refused claim commits nothing");

    let full = open_signed_session(port, CLAIMANT_PRINCIPAL, &key);
    expect_resp(&claim_deposit(port, &full, &partial.doc1, &partial.account), "ack_addr");
    assert!(claimed(port));
    // Once claimed the fold's own verdict stands AHEAD of the scope's.
    let v = claim_deposit(port, &content, &partial.doc1, &partial.account);
    assert_eq!(verdict(&v), "credential_refused:already_claimed", "slot (3) before (6): {v}");

    sd.shutdown();
}
