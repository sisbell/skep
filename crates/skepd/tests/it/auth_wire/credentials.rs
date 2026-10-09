//! The refusals a credential deposit can be handed, over real HTTP, which is
//! where the one-way doors are: the claim's three eligibility laws (keyless,
//! first-wins, tier) — each of which, once wrong, is unrecoverable because a
//! claimant never moves — the home pin and the precedence that decides which
//! token a wrong-home deposit gets, the `malformed_payload:<sub>` join this
//! crate composes rather than delegates, the enrolled-set and record caps,
//! `preview_key` and `undecodable_key`, the credential idempotency memo,
//! whose contract differs from M10's on exactly one point (the hit is
//! kind-BLIND), retirement, `key_set` on `/op` and `/op-at`, and restart
//! carrying the identity table back (the World's own slice, recovered with
//! it; the suite `identity_slice` holds the rest of that).

use skep_address::{Address, Nat, Tumbler};
use skep_identity::{canonical_record, entry_body_record, framed, BoardTerm, RecordRows, ENTRY_TAG};

use super::*;

/// One enroll record of `n` real keys with a valid-hex key whose Ed25519 half
/// is NO POINT appended last, as its atom JSON fragment — the shape that asks
/// where slot (4)'s decode stops, since the undecodable key sits at the end.
/// HYBRID entries throughout (the classical row is gone): at the 128 KiB
/// record cap twenty tag-1 entries are 80,391 B, with room to spare.
fn enroll_atom_with_trailing_non_point(n: usize) -> String {
    let real: Vec<SigningKey> = (0..n as u8).map(distinct_key).collect();
    let mut entries: Vec<Enrollment> = real
        .iter()
        .map(|sk| Enrollment::new(public_key_of(sk), false, None).expect("no label"))
        .collect();
    entries.push(Enrollment::new(non_point_hybrid_key(), false, None).expect("no label"));
    json_atom(&encode_enroll(&entries))
}

/// A TAG-1 hybrid key of the row's exact width whose ED25519 HALF decodes to
/// no point — a real derived key's post-quantum half beside the first
/// constant-byte Ed25519 half the precheck's own decode refuses
/// (`skep_signature::key_decodes`): ML-DSA-65's half decodes at any byte
/// string of its length, so the refusal is the Ed25519 half's. Found, not
/// hardcoded — roughly half of all 32-byte strings fail decompression, and
/// the `expect` keeps a search that finds nothing from passing silently. The
/// fold admits it (syntax alone, AUTH-1.4); the precheck's all-halves decode
/// refuses it on that half.
fn non_point_hybrid_key() -> PublicKey {
    let real = public_key_of(&distinct_key(200));
    (0u8..=255)
        .map(|n| {
            PublicKey::from_halves(ALG_MLDSA65_ED25519, real.pq_half(), &[n; 32])
                .expect("the row's widths — the fold admits syntax and never decodes a half")
        })
        .find(|key| !skep_signature::key_decodes(key))
        .expect("no non-point among the 256 constant-byte candidates")
}

/// A TAG-3 key of the row's exact width whose FN-DSA HALF does not decode:
/// the verifying key's header byte — `0x09` for degree 512 under `fn-dsa`
/// 0.4.0 — replaced, so `VerifyingKeyStandard::decode` answers `None`. The
/// fold admits it (syntax alone); the precheck's all-halves decode refuses
/// it on that half, where the Ed25519 half is a real point.
fn bad_header_tag3_key(signer: &HybridSigner) -> PublicKey {
    let key = signer.public_key();
    let mut pq = key.pq_half().to_vec();
    assert_eq!(pq[0], 0x09, "fn-dsa 0.4.0's degree-512 header byte");
    pq[0] = 0x0a;
    PublicKey::from_halves(ALG_FNDSA512_PREVIEW_ED25519, &pq, key.ed25519_half())
        .expect("the row's widths — the fold admits syntax and never decodes a half")
}

/// A GENESIS deposit of `entries` for `agent_account`, homed in the
/// registrar's doc 1 — the hire's own shape (`common::hire`) with the RECORD
/// named rather than derived from a seed carrier, and the deposit's answer
/// returned UNJUDGED, so a refusal cell can read its token where the hire
/// helper would panic.
fn genesis_of(
    port: u16,
    registrar_signed: &str,
    registrar_doc1: &str,
    agent_account: &str,
    entries: &[Enrollment],
) -> Value {
    let ordinal = next_content_ordinal(port, Some(registrar_signed), registrar_doc1);
    // The record signed for the deposit (2a), as the hire signs it.
    let atom = signed_atom(
        port,
        registrar_signed,
        registrar_doc1,
        T_ENROLL,
        &[agent_account],
        &json_atom(&encode_enroll(entries)),
    );
    let v = op(
        port,
        Some(registrar_signed),
        &format!(
            r#"{{"op":"insert","doc":"{registrar_doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    let atom_addr = acked_addr(&v);
    op(
        port,
        Some(registrar_signed),
        &format!(
            r#"{{"op":"make_link","home":"{registrar_doc1}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{agent_account}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
        ),
    )
}

/// An ENROLLMENT of `entries` into the CLAIMANT's own set from `signed`, the
/// claimant's device session: the record atom landed at doc 1's next free
/// position, then the deposit naming it — the answer UNJUDGED.
fn enroll_into_claimant(port: u16, signed: &str, entries: &[Enrollment]) -> Value {
    let ordinal = next_content_ordinal(port, Some(signed), CLAIMANT_DOC1);
    let record = land_claimant_record(port, signed, ordinal, &json_atom(&encode_enroll(entries)), T_ENROLL);
    deposit(port, signed, &record, T_ENROLL)
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
        // Signed for the deposit (2a): the cap is slot (5)'s, behind the
        // fold's verdict and ahead of the record grade's check, so an
        // over-cap record is refused whatever its `sig` — and the one that
        // clears it must verify.
        let atom = signed_atom(port, &signed, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], atom);
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
    // HYBRID entries, the only kind there is: the cell is about the record's
    // KEY COUNT, and seventeen tag-1 entries are 68,337 B — under the 128 KiB
    // record cap (the record-cap measurements §5.2; the design record's E7
    // arithmetic at the old 64 KiB cap is what kept this cell classical).
    let genesis = |ordinal: u64, keys: &[&SigningKey]| -> Value {
        let v = op(
            port,
            Some(&account_token),
            &format!(
                r#"{{"op":"insert","doc":"{doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
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

/// Where slot (4)'s decode stops. The decode is per key — every half the
/// key's row names — and the key count is the RECORD's, bounded upstream at
/// 128 KiB and so at 32 tag-1 keys (68 under tag 3) — held under the
/// credential write lock and the serialization lock, bought by one small
/// deposit. So the decode is bounded at one key past the cap slot (5)
/// applies, and the two ends of that bound are:
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
    let record = land_claimant_record(port, &signed, 2, &enroll_atom(&[&distinct_key(5)]), T_ENROLL);
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
    let bad = land_claimant_record(port, &signed, 3, &json_atom("nonsense"), T_ENROLL);
    let v = op(port, Some(&signed), &deposit_frame(Some("kr"), &bad, T_ENROLL));
    assert_eq!(rejected_detail(&v), "credential_refused:malformed_payload:bad_record");
    let good = land_claimant_record(port, &signed, 4, &enroll_atom(&[&distinct_key(6)]), T_ENROLL);
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
    let bad_record = land_claimant_record(port, &signed, 2, &json_atom("nonsense"), T_ENROLL);
    assert_eq!(
        rejected_detail(&deposit(port, &signed, &bad_record, T_ENROLL)),
        "credential_refused:malformed_payload:bad_record"
    );
    // A PARAMETERIZED sub survives the join — a duplicate entry names its
    // 1-based ENTRY index (AUTH-2.15, AUTH-1.28), two colons and all.
    let dup = land_claimant_record(port, &signed, 3, &enroll_atom(&[&distinct_key(5), &distinct_key(5)]), T_ENROLL);
    assert_eq!(
        rejected_detail(&deposit(port, &signed, &dup, T_ENROLL)),
        "credential_refused:malformed_payload:duplicate_key:2"
    );

    sd.shutdown();
}

/// wire.md §Credential refusals: a valid-hex key any half of which does not
/// decode — here a tag-1 key whose Ed25519 half is no point — is "refused at
/// enrollment rather than discovered at a handshake". The fold is syntax-only
/// by contract (AUTH-1.4 — no half is ever decoded there), so such a record
/// parses and classifies honored: `precheck`'s slot (4) is the ONLY thing
/// standing between it and a permanently seated key that occupies a slot
/// against the enrolled cap and that `find_signer` walks on every
/// unauthenticated handshake attempt — retirable only by an anchor session of
/// that account.
#[test]
fn a_valid_hex_non_point_key_is_refused_at_enrollment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    let text = encode_enroll(&[Enrollment::new(non_point_hybrid_key(), false, None).expect("no label")]);
    let record = land_claimant_record(port, &signed, 2, &json_atom(&text), T_ENROLL);
    assert_eq!(
        rejected_detail(&deposit(port, &signed, &record, T_ENROLL)),
        "credential_refused:undecodable_key"
    );

    // …and it seated nothing: the set is still the ceremony's two.
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    assert_eq!(v["enrolled"].as_array().expect("enrolled").len(), 2, "{v}");

    sd.shutdown();
}

/// THE ALL-HALVES PRECHECK (AUTH-3.56 as RES-206 landed it; the hybrid-only
/// launch's Q9): `undecodable_key` decodes EVERY half the key's row names.
/// A tag-3 key whose FN-DSA half's HEADER BYTE is wrong is refused — on a
/// daemon that admits preview keys, so slot (4)'s first token stands aside
/// and the decode courtesy answers; a tag-1 key whose Ed25519 half is no
/// point is refused (the cell above); and a good key of EACH row is honored
/// — tag 1 at every ceremony, tag 3 here, enrolled into the claimant's set
/// and then opening a session under its own row.
#[test]
fn undecodable_key_decodes_every_half_the_keys_row_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let tag3 = tag3_signer(&distinct_key(70));

    // The FN-DSA half's header byte: undecodable, on the post-quantum half.
    let v = enroll_into_claimant(port, &signed, &[Enrollment::new(bad_header_tag3_key(&tag3), false, None).unwrap()]);
    assert_eq!(rejected_detail(&v), "credential_refused:undecodable_key", "{v}");
    assert_eq!(enrolled_count(port, CLAIMANT_ACCOUNT), 2, "nothing seated");

    // The same key with its header intact: a good key of the tag-3 row,
    // honored — and it opens a session under its own row, the 730-byte blob.
    let v = enroll_into_claimant(port, &signed, &[Enrollment::new(tag3.public_key().clone(), false, None).unwrap()]);
    expect_resp(&v, "ack_addr");
    assert_eq!(enrolled_count(port, CLAIMANT_ACCOUNT), 3, "the tag-3 key is seated");
    let as_tag3 = open_signed_session_as(port, CLAIMANT_PRINCIPAL, &tag3);
    let v = op(port, Some(&as_tag3), &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#));
    expect_resp(&v, "ack_addr");

    // A record naming a good tag-1 key beside the bad-header tag-3 key is
    // refused whole — the courtesy reads every entry.
    let v = enroll_into_claimant(
        port,
        &signed,
        &[
            Enrollment::new(public_key_of(&distinct_key(71)), false, None).unwrap(),
            Enrollment::new(bad_header_tag3_key(&tag3_signer(&distinct_key(72))), false, None).unwrap(),
        ],
    );
    assert_eq!(rejected_detail(&v), "credential_refused:undecodable_key", "{v}");
    assert_eq!(enrolled_count(port, CLAIMANT_ACCOUNT), 3);

    sd.shutdown();
}

/// `preview_key` (AUTH-3.44 slot (4)'s FIRST token, AUTH-3.56's row,
/// AUTH-1.44's setting; the hybrid-only launch's Q5, owner 2026-09-26 "b"):
/// on a daemon with `allow_preview_keys` OFF — a served board's setting —
/// an enrolment record naming ANY key of the tag-3 preview row is refused
/// `preview_key`, a GENESIS included and an ordinary enrollment alike; a
/// tag-1 record on the same daemon is unaffected; a tag-3 key that is ALSO
/// undecodable answers `preview_key` — the slot's order, the test reading the
/// entry's `alg` and decoding nothing; and a record naming a tag-1 key BESIDE
/// a tag-3 key is refused whole. With the setting ON (the fixtures'), the same
/// tag-3 genesis is honored (`an_account_with_no_key_of_the_tag_…` in
/// `signed_ops`, and the cell above). Nothing else moves: the fold admits the
/// row as syntax, tag-3 VERIFICATION stays compiled in.
#[test]
fn a_preview_key_is_refused_at_enrollment_unless_the_daemon_allows_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_refusing_preview_keys(dir.path());
    let port = sd.port();
    let registrar = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let tag3 = tag3_signer(&distinct_key(73));
    const PREVIEW_KEY: &str = "credential_refused:preview_key";

    // A GENESIS naming a preview key: refused, and it seeds nothing.
    let (agent, _bare) = bootstrap_delegate(port, 73);
    let v = genesis_of(
        port,
        &registrar,
        CLAIMANT_DOC1,
        &agent,
        &[Enrollment::new(tag3.public_key().clone(), false, None).unwrap()],
    );
    assert_eq!(rejected_detail(&v), PREVIEW_KEY, "a genesis is INSIDE the refusal: {v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(enrolled_count(port, &agent), 0, "the refused genesis seeded nothing");

    // An ENROLLMENT into the claimant's own set naming one: refused.
    let v = enroll_into_claimant(port, &registrar, &[Enrollment::new(tag3.public_key().clone(), false, None).unwrap()]);
    assert_eq!(rejected_detail(&v), PREVIEW_KEY, "{v}");
    assert_eq!(enrolled_count(port, CLAIMANT_ACCOUNT), 2);

    // A tag-3 key that is ALSO undecodable: `preview_key`, never
    // `undecodable_key` — the slot's two tokens in THIS order.
    let v = enroll_into_claimant(port, &registrar, &[Enrollment::new(bad_header_tag3_key(&tag3), false, None).unwrap()]);
    assert_eq!(rejected_detail(&v), PREVIEW_KEY, "the order inside slot (4): {v}");

    // A tag-1 key BESIDE a tag-3 key: refused whole — ANY key of the row.
    let v = enroll_into_claimant(
        port,
        &registrar,
        &[
            Enrollment::new(public_key_of(&distinct_key(74)), false, None).unwrap(),
            Enrollment::new(tag3.public_key().clone(), false, None).unwrap(),
        ],
    );
    assert_eq!(rejected_detail(&v), PREVIEW_KEY, "{v}");
    assert_eq!(enrolled_count(port, CLAIMANT_ACCOUNT), 2);

    // A tag-1 record on the same daemon: unaffected — honored, as a genesis
    // (the hire) and as an enrollment.
    let v = genesis_of(
        port,
        &registrar,
        CLAIMANT_DOC1,
        &agent,
        &[Enrollment::new(public_key_of(&distinct_key(73)), false, None).unwrap()],
    );
    expect_resp(&v, "ack_addr");
    assert_eq!(enrolled_count(port, &agent), 1);
    let v = enroll_into_claimant(port, &registrar, &[Enrollment::new(public_key_of(&distinct_key(75)), false, None).unwrap()]);
    expect_resp(&v, "ack_addr");
    assert_eq!(enrolled_count(port, CLAIMANT_ACCOUNT), 3);

    // The tag-1 key the hire seated opens a session, the tag-3 signer of the
    // same seed opens none — its key was never enrolled.
    open_signed_session(port, 73, &distinct_key(73));
    let nonce = challenge(port, 73);
    let origin = format!("http://127.0.0.1:{port}");
    let body = format!(
        "{{\"principal\":73,\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{}\"}}",
        sign_session_as(&tag3, &origin, &nonce, 73)
    );
    let (st, _) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 401, "a well-formed tag-3 blob no enrolled key verifies: the one 401");

    sd.shutdown();
}

/// m5 (the register's F2) — THE DEV SETTING IS ECHOED: a daemon that admits
/// preview keys — the fixtures' spawn — says so at start, ONE `warning (at
/// start):` line naming the flag, the consequence and the act, and nothing
/// else to warn of on an unclaimed board under the defaults; one refusing
/// them — a served board's setting, `spawn_refusing_preview_keys` — says no
/// such line at its start or at its claim. Read through the daemon's record
/// of what it said, since no suite captures stderr in-process.
#[test]
fn a_daemon_allowing_preview_keys_says_so_at_start_and_one_refusing_them_says_nothing() {
    let allowing = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(allowing.path(), true);
    let said = sd.daemon().lines_said();
    let warned: Vec<&String> = said.iter().filter(|l| l.starts_with("warning (at start): ")).collect();
    assert_eq!(
        warned,
        [&"warning (at start): the dev setting --allow-preview-keys is on: the enrollment of a \
           preview key (the tag-3 row, fndsa512-preview-ed25519) is admitted, a genesis included \
           — a served board runs without it; drop the flag and restart"
            .to_string()],
        "FINDING (m5): the one warning at start:\n{}",
        said.join("\n")
    );
    sd.shutdown();

    let refusing = tempfile::tempdir().expect("tempdir");
    let sd = spawn_refusing_preview_keys(refusing.path());
    let said = sd.daemon().lines_said();
    assert!(
        !said.iter().any(|l| l.contains("--allow-preview-keys")),
        "a served board's setting: no such line at start or at the claim:\n{}",
        said.join("\n")
    );
    sd.shutdown();
}

/// AUTH-1.44 — `allow_preview_keys` GATES ENROLLMENT AND NOTHING ELSE: a
/// tag-3 key enrolled while the daemon allowed preview keys stays a key when
/// the same board restarts refusing them — `key_set` still lists it and it
/// opens a session under its own row — while a NEW tag-3 enrollment on that
/// restart is refused `preview_key`. The refusing daemon above never holds an
/// enrolled tag-3 key, so a setting read at the handshake as well — the one
/// place the config is in a verify's reach — passes every other test.
#[test]
fn a_preview_key_enrolled_before_the_setting_turned_off_still_opens_sessions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tag3 = tag3_signer(&distinct_key(76));
    let tag3_fp = Fingerprint::of(tag3.public_key()).to_hex();
    {
        let sd = spawn(dir.path()); // the fixtures' setting: preview keys allowed
        let port = sd.port();
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let v = enroll_into_claimant(port, &signed, &[Enrollment::new(tag3.public_key().clone(), false, None).unwrap()]);
        expect_resp(&v, "ack_addr");
        sd.shutdown();
    }
    let sd = spawn_refusing_preview_keys(dir.path());
    let port = sd.port();
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    assert!(
        v["enrolled"]
            .as_array()
            .expect("enrolled")
            .iter()
            .any(|e| e["fingerprint"].as_str() == Some(tag3_fp.as_str())),
        "the preview key is still enrolled after the restart: {v}"
    );
    open_signed_session_as(port, CLAIMANT_PRINCIPAL, &tag3); // asserts the 200
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = enroll_into_claimant(
        port,
        &signed,
        &[Enrollment::new(tag3_signer(&distinct_key(77)).public_key().clone(), false, None).unwrap()],
    );
    assert_eq!(rejected_detail(&v), "credential_refused:preview_key", "a NEW preview key: {v}");
    sd.shutdown();
}

/// THE RECORD CAP OVER THE WIRE (AUTH-1.18/1.21 as re-pinned — 128 KiB;
/// AUTH-2.96's `a 128 KiB record · a 128 KiB+1 record` row): a genesis record
/// of EXACTLY 131,072 bytes AS DEPOSITED — thirty label-free tag-1 entries,
/// 120,571 B, and the record's own `sig` above the claim (2a: the hybrid
/// blob in hex, the 6,755-byte member AUTH-2.130's cost note prices), padded
/// onto the mark with labels of at most 128 bytes — is READ whole, its
/// verdict the KEY COUNT's (`too_many_enrolled`, slot (5): 30 is over the
/// genesis cap of 16) and never `too_large`; one byte more is inert at the
/// read, `malformed_payload:too_large`, ahead of every later slot. The
/// honored cell at exactly the cap is the identity suite's
/// (`record_at_exactly_the_cap_folds_and_one_more_byte_inerts`): no record a
/// wire deposit can seat carries 30 keys. (Thirty-two label-free entries,
/// 128,607 B, stood here while records were bare; with the `sig` counted no
/// signed record of that many keys fits the cap at all.)
#[test]
fn the_record_cap_is_128_kib_at_the_fold_over_the_wire() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let registrar = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (agent, _bare) = bootstrap_delegate(port, 76);

    // The `sig` member a tag-1 signer appends, `,"sig":"<6,746 hex>"`: its
    // width is the row's and never the record's, so the sig-less record is
    // sized short of the mark by exactly it.
    const SIG_MEMBER: usize = 8 + 2 * 3373 + 1;
    // Thirty distinct tag-1 keys, label-free: the base the record-cap
    // measurements' arithmetic gives (32 + 30·4,017 + 29 = 120,571 B).
    let keys: Vec<PublicKey> = (100u8..130).map(|n| public_key_of(&distinct_key(n))).collect();
    let cap_sized = |over: usize| -> Vec<Enrollment> {
        let mut entries: Vec<Enrollment> =
            keys.iter().map(|k| Enrollment::new(k.clone(), false, None).unwrap()).collect();
        let base = encode_enroll(&entries).len();
        assert_eq!(base, 120_571, "the label-free base");
        let mut pad = MAX_RECORD_BYTES - SIG_MEMBER - base + over;
        let mut i = 0;
        while pad > 0 {
            // A label adds 11 + L bytes, L at most 128; keep the last legal.
            let take = if pad <= 139 { pad } else if pad - 139 <= 11 { pad - 12 } else { 139 };
            entries[i] = Enrollment::new(keys[i].clone(), false, Some("x".repeat(take - 11))).unwrap();
            pad -= take;
            i += 1;
        }
        assert_eq!(encode_enroll(&entries).len() + SIG_MEMBER, MAX_RECORD_BYTES + over);
        entries
    };

    let v = genesis_of(port, &registrar, CLAIMANT_DOC1, &agent, &cap_sized(0));
    assert_eq!(
        rejected_detail(&v),
        "credential_refused:too_many_enrolled",
        "exactly 128 KiB is READ — the verdict is the count's, never too_large: {v}"
    );
    let v = genesis_of(port, &registrar, CLAIMANT_DOC1, &agent, &cap_sized(1));
    assert_eq!(
        rejected_detail(&v),
        "credential_refused:malformed_payload:too_large",
        "128 KiB+1 is inert at the read: {v}"
    );
    assert_eq!(enrolled_count(port, &agent), 0);

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
/// Since round 7 (as7-E1 ARM (a), bu7-E1 ARM (a)) the record landed in the
/// version CARRIES its `sig` — a sig-less record-kind atom is refused at its
/// `insert`, `record_sig_required` — and, homed outside a doc 1, it is no
/// exempt atom: it lands attested, as the unparseable bytes beside it do.
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
    let carrying = signed_atom(port, &signed, &version, T_ENROLL, &[CLAIMANT_ACCOUNT], &enroll_atom(&[&distinct_key(7)]));
    assert_eq!(
        rejected_detail(&enroll_in(&version, 2, &carrying)),
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

/// Restart carries the identity table back (the World's own slice,
/// checkpointed with it and replayed by the open): the claim, the keys, and
/// a working signed handshake all survive reopen.
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
        "the recovered key table equals the live fold's"
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
/// `unauthenticated` (slot 0 first). And a frame carrying both slot (2)'s
/// fault and a `replaces` member answers slot (2)'s: the fence stands behind
/// it, in `op_shape_refusal`'s order and wire.md's.
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
    let both = format!(
        r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":[{{"source":"{CLAIMANT_DOC1}","span":{{"start":"1.1","width":"0.1"}}}}],"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}},"replaces":"{CLAIMANT_DOC1}"}}"#
    );
    let v = op(port, Some(&signed), &both);
    assert_eq!(rejected_detail(&v), "credential_refused:resolved_from", "slot (2) before the fence: {v}");
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
    let anchor_retire = land_claimant_record(port, &device_token, 2, &retire_atom(&[&anchor_fp]), T_RETIRE);
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
    // …and the RECORD's grade is the act's: the same device-signed record from
    // the ANCHOR session passes slot (6) and is refused at the record grade —
    // a retire record names fingerprints and flags nothing.
    let v = deposit(port, &anchor_token, &anchor_retire, T_RETIRE);
    assert_eq!(rejected_detail(&v), "credential_refused:attestation_invalid:signature", "{v}");

    // Trigger 2 — a post-genesis ANCHOR-FLAGGED enrollment, same gate.
    let fresh = distinct_key(9);
    let flagged_enroll =
        land_claimant_record(port, &device_token, 3, &enroll_atom_flagged(&[(&fresh, true)]), T_ENROLL);
    let v = deposit(port, &device_token, &flagged_enroll, T_ENROLL);
    assert_eq!(rejected_detail(&v), "credential_refused:anchor_session_required");
    // The same enrollment UNFLAGGED passes, so the gate is the FLAG and not
    // the act.
    let plain_enroll =
        land_claimant_record(port, &device_token, 4, &enroll_atom_flagged(&[(&fresh, false)]), T_ENROLL);
    expect_resp(&deposit(port, &device_token, &plain_enroll, T_ENROLL), "ack_addr");

    // The anchor's own session retires the device key.
    let device_retire = land_claimant_record(port, &anchor_token, 5, &retire_atom(&[&device_fp]), T_RETIRE);
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
        land_claimant_record(port, &anchor, ordinal, &enroll_atom_flagged(&[(&second, true)]), T_ENROLL);
    expect_resp(&deposit(port, &anchor, &flagged, T_ENROLL), "ack_addr");
    let second_session = open_signed_session(port, CLAIMANT_PRINCIPAL, &second);

    // The subdivision X.2 the handoff cell is read at (X.1 is the held agent
    // space, which takes no genesis). While an anchor stands in X's set, X's
    // handoff is anchor-grade: the device session's genesis there is refused.
    delegate_under(port, &bare, CLAIMANT_ACCOUNT, 951);
    let (x2, _) = delegate_under(port, &bare, CLAIMANT_ACCOUNT, 952);
    // The record is signed by the DEVICE key at its landing: refused now at
    // slot (6), it is the same record the downgrade below commits from the
    // same session — device-grade then, and the device's `sig` verifies.
    let handoff = land_record(port, &device, CLAIMANT_DOC1, &fresh_key_atom(65), T_ENROLL, &x2);
    let v = enroll_for(port, &device, CLAIMANT_DOC1, &handoff, &x2);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "an anchor enrolled: X's handoff is anchor-grade: {v}");
    assert_eq!(enrolled_count(port, &x2), 0, "a refused handoff commits nothing");

    // THE ACT: every enrolled anchor retired in one record, from the first
    // anchor's own session, the device key remaining — it COMMITS.
    let ordinal = next_content_ordinal(port, Some(&anchor), CLAIMANT_DOC1);
    let last_anchors =
        land_claimant_record(port, &anchor, ordinal, &retire_atom(&[&anchor_fp, &second_fp]), T_RETIRE);
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
        land_claimant_record(port, &device, ordinal, &enroll_atom_flagged(&[(&fresh, true)]), T_ENROLL);
    for (hand, token) in [("the device session", &device), ("a bare session", &bare)] {
        let v = deposit(port, token, &flagged, T_ENROLL);
        assert_eq!(rejected_detail(&v), "credential_refused:anchor_session_required", "{hand}: {v}");
    }
    // …while the account stays usable at DEVICE grade: the same key,
    // unflagged, enrols from the device session.
    let ordinal = next_content_ordinal(port, Some(&device), CLAIMANT_DOC1);
    let plain =
        land_claimant_record(port, &device, ordinal, &enroll_atom_flagged(&[(&fresh, false)]), T_ENROLL);
    expect_resp(&deposit(port, &device, &plain, T_ENROLL), "ack_addr");

    // THE DOWNGRADE beside the permanence: X's set holds no anchor, so X's
    // handoff — the SAME record, the SAME frame, refused from this session
    // above — is device-grade now and COMMITS from it.
    expect_resp(&enroll_for(port, &device, CLAIMANT_DOC1, &handoff, &x2), "ack_addr");
    assert_eq!(enrolled_count(port, &x2), 1, "the recipient's key, latched from a device session");

    sd.shutdown();
}

/// THE SYSTEM ACCOUNT HOLDS NO KEY (SO-I2 (g)(iv); SO-I4 (c); PUB-6.65 —
/// round 7's as7-F2 = reg-S3, the F2 sequence of
/// `sweep-7/auth-security.md`): on an UNCLAIMED board a loopback bare
/// session bound as the SYSTEM principal — the bare form binds any
/// principal — inserts a `T_enroll` atom into the system account's own doc 1
/// and is refused `system_account_keyless`, PERMANENT, at the plain path's
/// pre-claim gate; its genesis `make_link` into that home is refused the same
/// at the credential precheck's head, ahead of the fold's own payload read;
/// nothing lands, and the board claims normally afterwards (no residue — the
/// one pre-claim plant `claim_residue` cannot count, the account sitting at
/// the genesis floor). On the CLAIMED board a signed session's enrollment
/// naming the system account as its SUBJECT — the record landed in the
/// claimant's own doc 1, exempt — is refused the same at the link, and the
/// system account's key set stays empty. The register's corpus row ("a
/// credential record whose subject or home is the system account, refused").
#[test]
fn the_system_account_takes_no_credential_deposit_on_either_board() {
    const SYSTEM_PRINCIPAL: u64 = 9_000_000_000_000_000;
    const SYSTEM_ACCOUNT: &str = "1.1.0.1";
    const SYSTEM_DOC1: &str = "1.1.0.1.0.1";
    let dir = tempfile::tempdir().expect("tempdir");
    // Unclaimed, with the loopback origin configured (as every claimed
    // fixture is), so the signed arm admits the claimant's session once the
    // board is claimed below.
    let sd = spawn_configured(dir.path(), true);
    let port = sd.port();
    let keyless = |v: &Value, what: &str| {
        assert_eq!(rejected_detail(v), "credential_refused:system_account_keyless", "{what}: {v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"), "{what}: {v}");
    };
    let system = open_session(port, SYSTEM_PRINCIPAL);
    let before = head_position(port);
    let atom = enroll_atom(&[&distinct_key(70)]);
    let v = op(
        port,
        Some(&system),
        &format!(
            r#"{{"op":"insert","doc":"{SYSTEM_DOC1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    keyless(&v, "the plant's insert, at the pre-claim gate");
    let v = typed_link(port, &system, SYSTEM_DOC1, &[&format!("{SYSTEM_DOC1}.0.1.1")], &[SYSTEM_ACCOUNT], T_ENROLL);
    keyless(&v, "the plant's genesis link, at the precheck's head");
    assert_eq!(head_position(port), before, "nothing landed");

    // No residue: the board claims normally.
    claim_board(port);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let entries = [Enrollment::new(public_key_of(&distinct_key(71)), false, None).expect("no label")];
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let record = signed_atom(port, &signed, CLAIMANT_DOC1, T_ENROLL, &[SYSTEM_ACCOUNT], &json_atom(&encode_enroll(&entries)));
    let landed = land_claimant_record(port, &signed, ordinal, &record, T_ENROLL);
    let v = typed_link(port, &signed, CLAIMANT_DOC1, &[&landed], &[SYSTEM_ACCOUNT], T_ENROLL);
    keyless(&v, "an enrollment naming the system account as its subject, on the claimed board");
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{SYSTEM_ACCOUNT}"}}"#));
    assert_eq!(v["enrolled"].as_array().map(Vec::len), Some(0), "the system account holds no key: {v}");
    sd.shutdown();
}

/// THE WRONG-ONCE CORPUS AT THE RECORD GRADE (SO-I1 — EVERY AXIS BOUND;
/// SO-I6; AUTH-2.96's form; round 7's `owed-test-instruments-without-lane`):
/// over ONE valid signed enrollment, one vector per frame member — `board`'s
/// position, `board`'s chain, `account`, `doc`, `op` — and per `record` body
/// row — the type, `to`, `replaces` (named where the kind leaves it EMPTY),
/// the lineage (the same), the sig-less record's bytes — altered ONCE in the
/// bytes the `sig` is made over, the deposit sent as the valid one is:
/// every one is refused `attestation_invalid:signature`, PERMANENT; plus the
/// `alg` tag swapped — the tag-1 key signing over a frame naming tag 3's
/// token — which the trial under the key's own row fails. The control, the
/// frame composed as the daemon composes it, commits. Each refused vector
/// leaves its atom an orphan in doc 1, as a refused link does.
#[test]
fn altering_any_one_member_of_a_signed_record_frame_fails_the_record_grade() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let signer = hybrid_signer(&device_key());
    let address = |s: &str| -> Address {
        let comps: Vec<Nat> = s.split('.').map(|c| Nat::from(c.parse::<u64>().expect("a component"))).collect();
        skep_address::validate(Tumbler::new(comps).expect("a tumbler")).expect("an address")
    };
    let board = board_term(port).expect("H.1");
    let (account, doc) = (address(CLAIMANT_ACCOUNT), address(CLAIMANT_DOC1));
    let (ty, subject) = (address(T_ENROLL), [address(CLAIMANT_ACCOUNT)]);
    let entries = [Enrollment::new(public_key_of(&distinct_key(72)), false, Some("right".into())).expect("a label")];
    let canonical = canonical_record(&entries, None);
    let other = address("1.0.1.0.1.0.2.9");
    let rows = |ty: &Address, to: &[Address], replaces: Option<&Address>, lineage: Option<&Address>, canonical: &[u8]| -> Vec<u8> {
        entry_body_record(RecordRows { ty, to, replaces, lineage_fork_point: lineage, sigless_canonical_record: canonical })
            .as_bytes()
            .to_vec()
    };
    let right_body = rows(&ty, &subject, None, None, canonical.as_bytes());
    let frame = |alg: &str, board: BoardTerm, account: &Address, doc: &Address, body: &[u8]| -> Vec<u8> {
        let mut board_row = board.log_position.to_be_bytes().to_vec();
        board_row.extend_from_slice(&board.chain);
        framed(
            ENTRY_TAG,
            &[alg.as_bytes(), &board_row, account.to_string().as_bytes(), doc.to_string().as_bytes(), b"record", body],
        )
    };
    let right = frame(ALG_MLDSA65_ED25519, board, &account, &doc, &right_body);
    assert_eq!(
        right,
        record_frame_for(port, ALG_MLDSA65_ED25519, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], canonical.as_bytes()).expect("composable"),
        "the hand-framed control is the signer's own frame"
    );
    let mut moved_chain = board;
    moved_chain.chain[0] ^= 0x01;
    let another_label = canonical_record(
        &[Enrollment::new(public_key_of(&distinct_key(72)), false, Some("wrong".into())).expect("a label")],
        None,
    );
    let vectors: Vec<(&str, Vec<u8>)> = vec![
        ("board's position", frame(ALG_MLDSA65_ED25519, BoardTerm { log_position: board.log_position + 1, ..board }, &account, &doc, &right_body)),
        ("board's chain", frame(ALG_MLDSA65_ED25519, moved_chain, &account, &doc, &right_body)),
        ("account", frame(ALG_MLDSA65_ED25519, board, &address("1.0.2"), &doc, &right_body)),
        ("doc", frame(ALG_MLDSA65_ED25519, board, &account, &address("1.0.1.0.2"), &right_body)),
        ("op", {
            let mut board_row = board.log_position.to_be_bytes().to_vec();
            board_row.extend_from_slice(&board.chain);
            framed(ENTRY_TAG, &[ALG_MLDSA65_ED25519.as_bytes(), &board_row, CLAIMANT_ACCOUNT.as_bytes(), CLAIMANT_DOC1.as_bytes(), b"make_link", &right_body])
        }),
        ("row 1, the type", frame(ALG_MLDSA65_ED25519, board, &account, &doc, &rows(&address(T_RETIRE), &subject, None, None, canonical.as_bytes()))),
        ("row 2, to", frame(ALG_MLDSA65_ED25519, board, &account, &doc, &rows(&ty, &[address("1.0.2")], None, None, canonical.as_bytes()))),
        ("row 3, replaces named", frame(ALG_MLDSA65_ED25519, board, &account, &doc, &rows(&ty, &subject, Some(&other), None, canonical.as_bytes()))),
        ("row 4, the lineage named", frame(ALG_MLDSA65_ED25519, board, &account, &doc, &rows(&ty, &subject, None, Some(&other), canonical.as_bytes()))),
        ("row 5, the sig-less bytes", frame(ALG_MLDSA65_ED25519, board, &account, &doc, &rows(&ty, &subject, None, None, another_label.as_bytes()))),
        ("the alg tag swapped", frame(ALG_FNDSA512_PREVIEW_ED25519, board, &account, &doc, &right_body)),
    ];
    assert_eq!(vectors.len(), 11, "five frame members, five body rows, the tag");
    // The atom landed AS SIGNED HERE — never through the suite's re-signing
    // helper — exempt at its insert (a record carrying a `sig`, into doc 1).
    let land = |text: &str| -> String {
        let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
        let v = op_as_written(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
                json_atom(text)
            ),
        );
        acked_addr(&v)
    };
    for (member, wrong) in &vectors {
        assert_ne!(wrong, &right, "{member}: the vector moves the bytes");
        let atom = land(&canonical_record(&entries, Some(&hex(&signer.sign(wrong)))));
        let v = deposit(port, &signed, &atom, T_ENROLL);
        assert_eq!(rejected_detail(&v), "credential_refused:attestation_invalid:signature", "{member}: {v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"), "{member}: {v}");
    }
    // The control: the right frame, signed, commits.
    let atom = land(&canonical_record(&entries, Some(&hex(&signer.sign(&right)))));
    expect_resp(&deposit(port, &signed, &atom, T_ENROLL), "ack_addr");
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
        land_claimant_record(port, &anchor, ordinal, &retire_atom(&[&anchor_fp, &device_fp]), T_RETIRE);
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
    let from_the_registry = land_claimant_record(port, &anchor, ordinal, &retire_atom(&[&member_fp]), T_RETIRE);
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
    let own_space = land_record(port, &as_x2, &x2_doc1, &retire_atom(&[&device_fp]), T_RETIRE, &x2);
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
