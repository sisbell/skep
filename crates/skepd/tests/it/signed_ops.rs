//! SIGNED OPS — THE SEAM (the seam build 2026-09-25): one signed write, end
//! to end, for the three ops of the checked set — `insert`, `make_link`,
//! `publish` — under the two tags: the hybrid key enrolled, the entry frame
//! composed and signed by the test signer, the `attest` member on the wire,
//! the claimed-board check before the transaction, the attestation into the
//! commit marker's reserved slot and read back off the kernel.
//!
//! THE CLAIM TEST (the design record §7.6's row; A1–A6): at or below the
//! claim unsigned and an `attest` DROPPED; above it refused
//! (`attestation_required`), admitted (the slot filled) — by ANY enrolled
//! key of the row, under either tag, over `H.1`'s pair for the life of the
//! board, the entry frame naming the trunk a member-addressed write belongs
//! to — and invalid at each of its causes; a shot placing a value its author
//! may not read answered by the store's own gates or refused unread, never
//! by the value (PUB-8.4), and a shot's body bounded at parity with the
//! request-body cap; the system account's own writes landing unsigned (A3's
//! ω exemption for a DISPATCHED write is pinned in `policy/attestation.rs`,
//! the one place such a write reaches the check); a credential deposit's two
//! positions taking no entry signature (D26).
//!
//! THE GOLDENS (the frozen-tag rule's pin): per tag, one seed through the
//! KDF to both public keys and the fingerprint; the three ops' entry frames
//! at fixed instances; tag 1's signatures byte-stable (FIPS 204's
//! deterministic variant), tag 3's under the fixtures' seeded RNG; the
//! hybrid cross-check; and tag 1 DIFFERENTIAL against a second pure-Rust
//! FIPS 204 crate — keys-from-seed and signatures byte-equal.

use crate::common::*;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use skep_febe::Codec;
use skep_identity::{
    entry_body_insert, entry_body_link, entry_body_publish, entry_frame, Enrollment, EntrySlot,
    Fingerprint, PublicKey, SigAlgRow, ALG_FNDSA512_PREVIEW_ED25519, ALG_MLDSA65_ED25519,
};
use skepd::hybrid::{self, HybridSigner, SeededRng06};
use skepd::{JsonCodec, Seq};
use tempfile::tempdir;

/// A refusal's `(code:detail, disposition)`.
fn refusal(v: &Value) -> (String, String) {
    (verdict(v), v["disposition"].as_str().unwrap_or("?").to_string())
}

/// Opens the seat every claimed-board cell writes from: a fresh SIGNED
/// device session of the claimant (registered with the test signer), its
/// doc 1 the published home.
fn open_owner_session(port: u16) -> String {
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key())
}

fn sha_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The claimant's grant — `make_link` homed in its doc 1, `from` its
/// account, `to` empty, typed `T_GRANT` — the one frame the cells below sign
/// by hand.
fn claimant_grant() -> String {
    typed_link_frame(CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[], T_GRANT)
}

/// [`claimant_grant`]'s ENTRY frame under `alg` over the board term
/// `(position, chain)`, composed from its members' values — for the cells
/// that sign over a pair, or under a token, the test signer never would.
fn claimant_grant_entry_frame(alg: &str, board: (u64, [u8; 32])) -> Vec<u8> {
    let ty = [addr(T_GRANT)];
    let from = [addr(CLAIMANT_ACCOUNT)];
    let to: [skep_address::Address; 0] = [];
    let body =
        entry_body_link(&EntrySlot::Addrs(&ty), &EntrySlot::Addrs(&from), &EntrySlot::Addrs(&to));
    entry_frame(alg, board, &addr(CLAIMANT_ACCOUNT), &addr(CLAIMANT_DOC1), &body)
}

/// [`claimant_grant`] carrying `sig` under `alg` as its `attest` member.
fn claimant_grant_attested(alg: &str, sig: &[u8]) -> String {
    let mut v: Value = serde_json::from_str(&claimant_grant()).unwrap();
    v["attest"] = json!({"alg": alg, "sig": hex(sig)});
    v.to_string()
}

/// A head member's recorded `(position, chain)`, read as a guest reads it —
/// `retrieve_v` on the member, the `skep-head` record's own members.
fn recorded_pair(port: u16, member: &str) -> (u64, [u8; 32]) {
    let v = op_unattested(port, None, &retrieve_frame(member, 1, 1));
    let rec: Value = serde_json::from_str(v["items"][0]["atom"].as_str().expect("a head record"))
        .expect("the record is JSON");
    let chain: [u8; 32] =
        hex_to_bytes(rec["chain"].as_str().expect("chain")).try_into().expect("32 bytes");
    (rec["position"].as_u64().expect("position"), chain)
}

// ── the claim test ──────────────────────────────────────────────────────────

/// A1 / A5: AT OR BELOW THE CLAIM nothing is demanded and an `attest` is
/// DROPPED — never verified, never written. The ceremony's own deposit,
/// bare, admits a second declared insert into the claimant's doc 1 whose
/// `attest` is garbage under a real token: admitted, and its slot empty.
/// Then THE CLAIM WRITES `H.1` (s1, RULED 2026-09-25): the claim's own ack
/// finds the board term present, naming the claim's own position — no
/// forced head, no wait on the cadence.
#[test]
fn at_or_below_the_claim_an_attest_is_dropped_unverified_and_unwritten() {
    let dir = tempdir().unwrap();
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    let claimant = open_session(port, CLAIMANT_PRINCIPAL);
    let garbage = json!({"alg": ALG_MLDSA65_ED25519, "sig": "aa"});
    let frame = json!({
        "op": "insert", "doc": CLAIMANT_DOC1,
        "at": {"subspace": "1", "ordinal": "2"},
        "values": [{"atom": "a second atom, pre-claim"}],
        "deposit": T_ENROLL, "attest": garbage,
    });
    let v = op_unattested(port, Some(&claimant), &frame.to_string());
    let at = acked_at(&v);
    assert_eq!(sd.daemon().attestation_at(Seq(at)).unwrap(), None, "dropped, never written");
    // The claim itself — the last unchecked write, from the device's signed
    // session; the test signer finds no `H.1` yet and attaches nothing.
    assert!(board_term(port).is_none(), "no H.1 before the claim");
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT));
    let claim_at = acked_at(&v);
    assert!(claimed(port));
    assert_eq!(sd.daemon().attestation_at(Seq(claim_at)).unwrap(), None, "the claim's slot is empty");
    // THE CLAIM WROTE `H.1` in its own step: present at the claim's ack and
    // naming the claim's own position, with nothing forced.
    let (position, _) = board_term(port).expect("H.1 stands at the claim's ack");
    assert_eq!(position, claim_at, "H.1 names the claim's own position");
    assert_eq!(filled_slots(&sd, 1, head_position(port)), Vec::<u64>::new(), "the head's commits: unsigned");
}

/// THE CLAIM WRITES `H.1` (s1, RULED 2026-09-25): a fresh claimed board
/// admits a correctly attested `publish` IMMEDIATELY after the claim — no
/// forced head, no 64 commits, no checkpoint, no hour. The board term the
/// frame names is `H.1`'s pair, present at the claim's own ack and naming
/// the claim's position; the head's three commits are the only ones between
/// the claim and the shot's staging (a private draft, off-class); the first
/// publish-class write on the board is the shot, and its slot holds the
/// blob. A board the claim left without `H.1` would answer this write
/// `attestation_invalid:board_unavailable` — the seam build's finding, the
/// state this rule removes.
#[test]
fn a_fresh_claimed_board_admits_an_attested_publish_right_after_the_claim() {
    let dir = tempdir().unwrap();
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let claim_at = acked_at(&op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT)));
    let (position, _) = board_term(port).expect("H.1 at the claim's ack");
    assert_eq!(position, claim_at, "H.1 names the claim's own position");
    let head = head_position(port);
    assert!(head > claim_at, "the head's own commits landed above the claim");
    assert_eq!(filled_slots(&sd, 1, head), Vec::<u64>::new(), "no slot filled: the head's commits are unsigned");
    // The shot: doc 1 as the base at its one-atom extent (the version's
    // provenance), a private draft's two bytes as the runs — the member's
    // content — signed by the test signer over the body the daemon composes
    // off its snapshot, the first publish-class write on the board.
    let draft = draft_with(port, &signed, "de");
    let runs = shot_runs(port, Some(&signed), &draft, 1, 2);
    let v = op(port, Some(&signed), &publish_frame(CLAIMANT_DOC1, Some((CLAIMANT_DOC1, 1)), Some(&draft), &runs));
    let member_at = acked_at(&v);
    let slot = sd.daemon().attestation_at(Seq(member_at)).unwrap().expect("the shot's slot is filled");
    assert_eq!(slot.sig_alg(), hybrid::TAG_MLDSA65_ED25519);
    assert_eq!(filled_slots(&sd, 1, member_at), vec![member_at], "the shot's slot alone");
    assert_eq!(text_of(port, None, &acked_addr(&v), 1, 2), "de", "the member's content is the shot's runs");
}

/// The boundaries in `lo..=hi` whose slot is FILLED — an interior position
/// of a multi-record commit is no boundary and is skipped.
fn filled_slots(sd: &skepd::Skepd, lo: u64, hi: u64) -> Vec<u64> {
    (lo..=hi)
        .filter(|at| matches!(sd.daemon().attestation_at(Seq(*at)), Ok(Some(_))))
        .collect()
}

/// THE CLAIM TEST ABOVE THE CLAIM — the three codes at every cause, on a
/// grant link into the published doc 1 from the claimant's signed session:
/// absent → `attestation_required` (reorder); present and verifying →
/// admitted, the slot filled with the very blob attached; wrong bytes →
/// `attestation_invalid:signature` (reorder); the wrong width →
/// `:malformed`; a bare session → `signed_session_required` as before; an
/// unknown `alg` token → unparseable; the member on an op outside the three
/// → unparseable (the unknown-field rule); and a signed write OUTSIDE the
/// publish class carrying an `attest` → admitted with the member dropped.
#[test]
fn above_the_claim_the_check_refuses_admits_and_names_each_cause() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let grant = || typed_link_frame(CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &["1.0.2"], T_GRANT);

    // Absent: refused, reorder.
    let v = op_unattested(port, Some(&signed), &grant());
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_required".to_string(), "reorder".to_string()),
        "{v}"
    );
    // A bare session: the gate as before, ahead of the check.
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    assert_eq!(verdict(&op(port, Some(&bare), &grant())), GATED);

    // Present and verifying: admitted, and the slot holds exactly the blob.
    let attached: Value = serde_json::from_str(&attach_attest(port, &signed, &grant())).unwrap();
    let sig_hex = attached["attest"]["sig"].as_str().unwrap().to_string();
    assert_eq!(sig_hex.len(), 2 * 3373, "tag 1's blob: 3,309 ‖ 64");
    let v = op_unattested(port, Some(&signed), &attached.to_string());
    let at = acked_at(&v);
    let slot = sd.daemon().attestation_at(Seq(at)).unwrap().expect("the slot is filled");
    assert_eq!(slot.sig_alg(), hybrid::TAG_MLDSA65_ED25519);
    assert_eq!(hex(slot.sig()), sig_hex, "the marker carries the attached blob, whole");
    // …and the transactions around it stay empty.
    assert_eq!(sd.daemon().attestation_at(Seq(at - 1)).ok().flatten(), None);

    // Wrong bytes (the Ed25519 half flipped): signature, reorder.
    let mut tampered = attached.clone();
    let mut bytes = hex_to_bytes(&sig_hex);
    bytes[3309] ^= 1;
    tampered["attest"]["sig"] = Value::String(hex(&bytes));
    let v = op_unattested(port, Some(&signed), &tampered.to_string());
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:signature".to_string(), "reorder".to_string()),
        "{v}"
    );
    // The PQ half flipped: the same verdict — both halves verify or none.
    let mut tampered = attached.clone();
    let mut bytes = hex_to_bytes(&sig_hex);
    bytes[7] ^= 1;
    tampered["attest"]["sig"] = Value::String(hex(&bytes));
    let v = op_unattested(port, Some(&signed), &tampered.to_string());
    assert_eq!(verdict(&v), "credential_refused:attestation_invalid:signature");
    // The wrong width: malformed, reorder.
    let mut short = attached.clone();
    short["attest"]["sig"] = Value::String(sig_hex[2..].to_string());
    let v = op_unattested(port, Some(&signed), &short.to_string());
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:malformed".to_string(), "reorder".to_string()),
        "{v}"
    );
    // A signature by a key the account never enrolled: no candidate verifies.
    let stranger = HybridSigner::from_seed(FIXTURE_TAG, &[0x77; 32]).unwrap();
    let frame_bytes =
        entry_frame_for(port, &signed, CLAIMANT_PRINCIPAL, &attached).expect("composable");
    let mut foreign = attached.clone();
    foreign["attest"] = attest_member(&stranger.sign(&frame_bytes));
    let v = op_unattested(port, Some(&signed), &foreign.to_string());
    assert_eq!(verdict(&v), "credential_refused:attestation_invalid:signature");
    // An unknown token: the grammar refuses it.
    let mut unknown = attached.clone();
    unknown["attest"]["alg"] = Value::String("rsa".into());
    let v = op_unattested(port, Some(&signed), &unknown.to_string());
    assert_eq!(v["op"].as_str(), Some("unparseable"), "{v}");
    assert!(v["detail"].as_str().unwrap().contains("unknown algorithm token"), "{v}");
    // An empty blob: one spelling of absent.
    let mut empty = attached.clone();
    empty["attest"]["sig"] = Value::String(String::new());
    let v = op_unattested(port, Some(&signed), &empty.to_string());
    assert_eq!(v["op"].as_str(), Some("unparseable"), "{v}");
    // The member on an op outside the three: unknown field.
    let v = op_unattested(
        port,
        Some(&signed),
        &json!({"op": "delete", "doc": CLAIMANT_DOC1, "p": {"subspace": "1", "ordinal": "1"},
                "width": "1", "attest": attached["attest"]})
        .to_string(),
    );
    assert_eq!(v["op"].as_str(), Some("unparseable"), "{v}");
    assert!(v["detail"].as_str().unwrap().contains("unknown field 'attest'"), "{v}");
    // Outside the publish class (a private draft), signed, with an attest:
    // admitted, the member dropped.
    let draft = owner_draft(port, &signed);
    let mut frame: Value = serde_json::from_str(&insert_frame(&draft, 1, "x", false)).unwrap();
    frame["attest"] = attached["attest"].clone();
    let v = op_unattested(port, Some(&signed), &frame.to_string());
    let at = acked_at(&v);
    assert_eq!(sd.daemon().attestation_at(Seq(at)).unwrap(), None, "off-class: dropped");
}

/// A2 / `not_enrolled_at_position`: an account whose set holds a key of ONE
/// row alone — the TAG-3 preview row, admitted since the fixture daemon runs
/// with `allow_preview_keys` on — opens its session under that key (the
/// hybrid handshake: a tag-3 session opens, its `sig` the 730-byte blob,
/// both halves under the key's own row) and can attest nothing under TAG 1:
/// no key of that tag's row is enrolled as of the write's base, and the
/// verdict is PERMANENT. The same seed's tag-1 key, never enrolled, is what
/// the test signer signs attests with. (This cell held a CLASSICAL-only set
/// until the hybrid-only launch deleted the classical row; no such account
/// can be hired now, and a 64-byte session signature is the door's own 400 —
/// `auth_wire`'s width cell.)
#[test]
fn an_account_with_no_key_of_the_tag_is_refused_not_enrolled_at_position() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let registrar = open_owner_session(port);
    let key = distinct_key(41);
    let tag3 = HybridSigner::from_seed(hybrid::TAG_FNDSA512_PREVIEW_ED25519, &seed_of(&key))
        .expect("tag 3 is a row");
    // A top-level stranger, hired with the TAG-3 row alone: its genesis
    // enters no cone, so the claimant's device session seeds it (a
    // subdivision of the claimant's would be a handoff, anchor-grade).
    let (agent, _bare) = bootstrap_delegate(port, 41);
    let ordinal = next_content_ordinal(port, Some(&registrar), CLAIMANT_DOC1);
    let entries = vec![Enrollment::new(tag3.public_key().clone(), false, None).unwrap()];
    let atom = json_atom(&skep_identity::encode_enroll(&entries));
    let v = op(
        port,
        Some(&registrar),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    let atom_addr = acked_addr(&v);
    let v = op(port, Some(&registrar), &typed_link_frame(CLAIMANT_DOC1, &[&atom_addr], &[&agent], T_ENROLL));
    expect_resp(&v, "ack_addr");
    // The agent opens a session under its tag-3 key — the 730-byte blob…
    let agent_signed = open_signed_session_as(port, 41, &tag3);
    // …mints its published home, then a grant into it with an attest under
    // the seed's TAG-1 key, which the set does not hold.
    let home = acked_addr(&op(port, Some(&agent_signed), &create_frame(&agent, None)));
    register_signer(&agent_signed, 41, &key);
    let v = op(port, Some(&agent_signed), &typed_link_frame(&home, &[&agent], &["1.0.2"], T_GRANT));
    assert_eq!(
        refusal(&v),
        (
            "credential_refused:attestation_invalid:not_enrolled_at_position".to_string(),
            "permanent".to_string()
        ),
        "{v}"
    );
    // The same grant with no attest at all: required, reorder.
    let v = op_unattested(port, Some(&agent_signed), &typed_link_frame(&home, &[&agent], &["1.0.2"], T_GRANT));
    assert_eq!(verdict(&v), "credential_refused:attestation_required");
}

/// A2's walk has no cutoff — ANY KEY OF THE ROW ATTESTS (the design record
/// §4.5 (2)): a grant attested by the FIRST key of the claimant's set in
/// fingerprint order is admitted, and so is one attested by the LAST, each
/// slot that key's own attestation. Every other attested write in the suite
/// is the device key's, and where it sorts is an accident of SHA-256 over two
/// fixed seeds: it sorts LAST, so a check that tried only the last candidate
/// passes every other test — the gap
/// `every_enrolled_key_signs_including_the_last_in_fingerprint_order` closed
/// for the handshake, open here. The keys are CHOSEN from `key_set`'s own
/// published order, so both ends are instances of the law whatever the seeds
/// hash to.
#[test]
fn every_enrolled_key_of_the_row_attests_including_the_last_in_fingerprint_order() {
    let dir = tempdir().unwrap();
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
        [anchor_key(), device_key()]
            .into_iter()
            .find(|k| Fingerprint::of(&public_key_of(k)).to_hex() == want)
            .unwrap_or_else(|| panic!("{want} is one of the ceremony's keys"))
    };
    for (which, fp) in [("first", &fps[0]), ("last", &fps[1])] {
        let key = by_fp(fp);
        // A session the key opens registers it with the test signer, so the
        // grant below is attested by THAT key.
        let session = open_signed_session(port, CLAIMANT_PRINCIPAL, &key);
        let grant: Value = serde_json::from_str(&claimant_grant()).unwrap();
        let frame = entry_frame_for(port, &session, CLAIMANT_PRINCIPAL, &grant).expect("composable");
        let v = op(port, Some(&session), &claimant_grant());
        assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the {which} key in fingerprint order attests: {v}");
        let slot = sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().expect("the slot is filled");
        assert_eq!(
            hybrid::verify(FIXTURE_TAG, &public_key_of(&key), &frame, slot.sig()),
            Ok(()),
            "the {which} key's slot is that key's own attestation"
        );
    }
}

/// THE ENTRY FRAME SPELLS THE ADDRESS, NEVER THE STRING: a grant whose frame
/// names doc 1 and the claimant's account with a LEADING ZERO — `1.0.1.0.01`
/// and `1.0.01`, the very addresses `1.0.1.0.1` and `1.0.1`, as the wire
/// reads them — is ADMITTED, its slot filled, when the signer attests the
/// frame `skep_identity::entry_frame` composes over the addresses it named:
/// the daemon spells each address in its one dotted-decimal form, and so
/// does the signer, whichever spelling the wire carried. A signer that framed
/// the strings it sent would sign `1.0.1.0.01`, a preimage the daemon never
/// builds, and every attested write it made would be refused `signature`.
#[test]
fn an_address_named_with_a_leading_zero_is_attested_over_its_one_spelling() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let spelled = typed_link_frame("1.0.1.0.01", &["1.0.01"], &[], T_GRANT);
    let v = op(port, Some(&signed), &spelled);
    let at = acked_at(&v);
    assert!(sd.daemon().attestation_at(Seq(at)).unwrap().is_some(), "the slot is filled: {v}");
    // The frame composed over the leading-zero spelling IS the canonical
    // frame, byte for byte.
    let named: Value = serde_json::from_str(&spelled).unwrap();
    let canonical: Value = serde_json::from_str(&claimant_grant()).unwrap();
    assert_eq!(
        entry_frame_for(port, &signed, CLAIMANT_PRINCIPAL, &named).expect("composable"),
        entry_frame_for(port, &signed, CLAIMANT_PRINCIPAL, &canonical).expect("composable"),
        "one address, one frame"
    );
}

/// THE PREVIEW ROW ATTESTS AS THE PRODUCTION ROW DOES (AUTH-1.44: "a tag-3
/// key already enrolled opens sessions and signs entries as any other"; this
/// file's charter: one signed write "under the two tags"): the claimant
/// enrols a tag-3 key beside its two tag-1 keys, and a grant that key
/// attests — the entry frame's `alg` the PREVIEW token, the blob FN-DSA-512's
/// 666 bytes then Ed25519's 64 — is admitted from a session it opened, the
/// slot carrying tag 3 and that very blob. The test signer signs under tag 1
/// alone, so every other admitted attestation in the suite is tag 1's: a
/// check framing every entry under tag 1's token, or verifying every blob
/// under tag 1's rule, passes all of them and refuses this one
/// `attestation_invalid:signature` — REORDER, a re-compose that never lands.
#[test]
fn a_tag_3_key_attests_a_write_as_a_tag_1_key_does() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let tag3 = HybridSigner::from_seed(hybrid::TAG_FNDSA512_PREVIEW_ED25519, &seed_of(&distinct_key(61)))
        .expect("tag 3 is a row");
    // The preview key joins the claimant's set — the fixtures allow it.
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let entries = vec![Enrollment::new(tag3.public_key().clone(), false, None).unwrap()];
    let atom = json_atom(&skep_identity::encode_enroll(&entries));
    let atom_addr = acked_addr(&op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    ));
    expect_resp(
        &op(port, Some(&signed), &typed_link_frame(CLAIMANT_DOC1, &[&atom_addr], &[CLAIMANT_ACCOUNT], T_ENROLL)),
        "ack_addr",
    );
    // A session the preview key opens, and a grant it attests.
    let as_tag3 = open_signed_session_as(port, CLAIMANT_PRINCIPAL, &tag3);
    let h1 = board_term(port).expect("H.1");
    let sig = tag3.sign(&claimant_grant_entry_frame(ALG_FNDSA512_PREVIEW_ED25519, h1));
    assert_eq!(sig.len(), 730, "tag 3's blob: 666 ‖ 64");
    let v = op_unattested(port, Some(&as_tag3), &claimant_grant_attested(ALG_FNDSA512_PREVIEW_ED25519, &sig));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "a tag-3 attestation is admitted: {v}");
    let slot = sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().expect("the slot is filled");
    assert_eq!(slot.sig_alg(), hybrid::TAG_FNDSA512_PREVIEW_ED25519, "the slot carries tag 3");
    assert_eq!(slot.sig(), &sig[..], "and the blob attached, whole");
}

/// THE THREE OPS END TO END: `make_link` (a grant) and `publish` (a shot)
/// commit attested, their slots holding the attached blobs and no other
/// commit's; `insert` — whose only published-document form in this build is
/// a declared deposit under a credential kind — is EXEMPT (the record's own
/// `sig` is its carrier, D26), commits with its slot empty, and an
/// UNDECLARED insert into the published home passes the check with a valid
/// attest and meets the store's `published_target`, which is the order the
/// design states: the check before the transaction, the store's gates
/// inside it.
#[test]
fn the_three_ops_commit_attested_where_the_check_demands_it() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);

    // make_link: a grant, attested.
    let v = op(port, Some(&signed), &typed_link_frame(CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[], T_GRANT));
    let link_at = acked_at(&v);
    let slot = sd.daemon().attestation_at(Seq(link_at)).unwrap().expect("the grant's slot");
    assert_eq!(slot.sig().len(), 3373);

    // publish: an edition published, then a shot re-supplying its bytes plus
    // a draft's — the body the signer composed off the wire equals the one
    // the daemon composed off its snapshot, or the check refuses.
    let edition = edition_with(port, &signed, "abc");
    let draft = draft_with(port, &signed, "de");
    let mut runs = shot_runs(port, Some(&signed), &edition, 1, 3);
    runs.extend(shot_runs(port, Some(&signed), &draft, 1, 2));
    let frame = publish_frame(&edition, Some((&edition, 3)), Some(&draft), &runs);
    let v = op(port, Some(&signed), &frame);
    let member_at = acked_at(&v);
    let slot = sd.daemon().attestation_at(Seq(member_at)).unwrap().expect("the shot's slot");
    assert_eq!(slot.sig_alg(), 1);
    assert_eq!(text_of(port, None, &acked_addr(&v), 1, 5), "abcde");
    // The same shot unattested: required.
    let v = op_unattested(port, Some(&signed), &frame);
    assert_eq!(verdict(&v), "credential_refused:attestation_required");

    // insert: the declared deposit is exempt — no attest demanded, the slot
    // empty whether or not one is attached.
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let v = op_unattested(port, Some(&signed), &insert_frame(CLAIMANT_DOC1, ordinal, "r", true));
    let dep_at = acked_at(&v);
    assert_eq!(sd.daemon().attestation_at(Seq(dep_at)).unwrap(), None, "exempt: the record's sig is its carrier");
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let v = op(port, Some(&signed), &insert_frame(CLAIMANT_DOC1, ordinal, "s", true));
    let dep_at = acked_at(&v);
    assert_eq!(sd.daemon().attestation_at(Seq(dep_at)).unwrap(), None, "attached, dropped: exempt");
    // An UNDECLARED insert into the published home: the check demands and
    // verifies, then the store refuses — the check's order.
    let v = op_unattested(port, Some(&signed), &insert_frame(CLAIMANT_DOC1, ordinal, "t", false));
    assert_eq!(verdict(&v), "credential_refused:attestation_required");
    let v = op(port, Some(&signed), &insert_frame(CLAIMANT_DOC1, ordinal, "t", false));
    assert_eq!(verdict(&v), "published_target", "the check passed; the store's own refusal");
}

/// THE ENTRY FRAME NAMES THE TRUNK (wire.md: for `insert`, "`doc` the
/// document's trunk"; for `publish`, "the frame whose `doc` is the trunk
/// document"; M5's one truncation, PUB-2.15). A shot ADDRESSED TO A MEMBER —
/// the edition's first member, which M5 gates as named and projects to its
/// document — is attested over the edition, admitted, and mints the trunk's
/// next member; an insert addressed to that member is framed over the
/// edition too, the check passing and the store refusing it
/// `published_target`. Every other attested shot in the suite names its
/// trunk, so the publish arm's truncation is watched by nothing else.
#[test]
fn a_member_addressed_write_is_framed_over_its_trunk() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let edition = edition_with(port, &signed, "abc");
    let runs = shot_runs(port, Some(&signed), &edition, 1, 3);
    let m1 = acked_addr(&op(port, Some(&signed), &publish_frame(&edition, Some((&edition, 3)), None, &runs)));
    assert_eq!(m1, format!("{edition}.1"));
    // The shot addressed to the member: framed over the edition, admitted.
    let v = op(port, Some(&signed), &publish_frame(&m1, Some((&m1, 3)), None, &runs));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "a member-addressed shot is admitted: {v}");
    let m2 = acked_addr(&v);
    assert_eq!(m2, format!("{edition}.2"), "the trunk's next member");
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some(), "attested over the trunk");
    assert_eq!(text_of(port, None, &m2, 1, 3), "abc");
    // The insert addressed to the member: the check passes, the store refuses.
    let v = op(port, Some(&signed), &insert_frame(&m1, 4, "d", false));
    assert_eq!(verdict(&v), "published_target", "framed over the trunk, refused by the store: {v}");
}

/// Per-byte values of `s`, as a per-byte insert of it mints them — the
/// bytes a client knows it is placing.
fn per_byte(s: &str) -> Vec<&[u8]> {
    s.as_bytes().chunks(1).collect()
}

/// THE CHECK READS NO VALUE ITS PRINCIPAL MAY NOT READ (PUB-6.9; PUB-8.4:
/// `withheld` "before any existence answer"). B, granted the claimant's
/// private draft D, versions it — F, B's own published document arranging
/// D's first five addresses by reference — and is revoked; D then grows a
/// sixth address B never could read. From B's signed session every shot
/// naming D's addresses is answered the same whatever it carries —
/// unattested, signed over D's true bytes, or over a wrong guess:
/// A — a run onto D's sixth address, which F does not carry: `withheld`;
/// B — one run spanning addresses F carries AND the one it does not: the
///     same;
/// C — D ITSELF named as the base, outside F's chain: `base_not_in_chain`,
///     the store's refusal ahead of its source gate — a base the client
///     names carries nothing from outside the document's own chain;
/// D — a run F's own base CARRIES: the store's gate would admit it ungated
///     (PUB-6.24), and a revoked grantee attests no bytes it may no longer
///     read — `attestation_invalid:withheld`, REORDER, the bytes unread.
/// Nothing commits. A check that composed D's values would answer A and B
/// BY them — `attestation_required` for an address that holds a value,
/// `signature` for a wrong guess — and admit D's shot signed over the right
/// one; one that passed every such shot through would commit D's carried
/// shot UNATTESTED; one that refused them all would answer A, B and C with
/// its own refusal where the store's is owed.
#[test]
fn a_run_its_principal_may_not_read_is_answered_the_same_whatever_is_attached() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &bare, "abcde");
    let b = seat_stranger(port, 961);
    let b_signed = hire(port, &signed, CLAIMANT_DOC1, &b.account, 961, &distinct_key(62));
    let grant = deposit_grant(port, &signed, CLAIMANT_DOC1, &d, Some(&b.account));
    let f = acked_addr(&version_of(port, &b_signed, &d, Some(true)));
    expect_resp(
        &typed_link(port, &signed, CLAIMANT_DOC1, &[grant.as_str()], &[b.account.as_str()], T_GRANT),
        "ack_addr",
    );
    assert_withheld(&op(port, Some(&b_signed), &read1_frame(&d)), &d);
    expect_resp(&insert_text(port, &bare, &d, 6, "f"), "ack_addr");
    let d_addr = |k: u64| format!("{d}.0.1.{k}");
    let into_f = |base: &str, runs: &[String]| publish_frame(&f, Some((base, 5)), None, runs);
    // One shot, three ways: unattested, then signed over each guess.
    let answers = |frame: &str, guesses: [&str; 2]| -> Vec<Value> {
        let mut out = vec![op_unattested(port, Some(&b_signed), frame)];
        for guess in guesses {
            out.push(op_with_publish_values(port, &b_signed, frame, &per_byte(guess)));
        }
        out
    };
    let before = head_position(port);

    // A — an address F never carried.
    for v in answers(&into_f(&f, &[run(&d, &d_addr(6), 1)]), ["f", "g"]) {
        assert_withheld(&v, &d);
    }
    // B — carried and uncarried in one run.
    for v in answers(&into_f(&f, &[run(&d, &d_addr(4), 3)]), ["def", "deg"]) {
        assert_withheld(&v, &d);
    }
    // C — D named as the base: outside F's chain, it carries nothing.
    for v in answers(&into_f(&d, &[run(&d, &d_addr(1), 5)]), ["abcde", "abcdz"]) {
        assert_eq!(verdict(&v), "base_not_in_chain", "{v}");
    }
    // D — F's own carried run: the store's gate would admit it; refused here,
    //     unread, whatever is attached.
    for v in answers(&into_f(&f, &[run(&d, &d_addr(1), 5)]), ["abcde", "abcdz"]) {
        assert_eq!(
            refusal(&v),
            ("credential_refused:attestation_invalid:withheld".to_string(), "reorder".to_string()),
            "a carried run its author may no longer read: {v}"
        );
    }
    assert_eq!(head_position(port), before, "nothing committed");
}

/// A CARRIED RUN ITS PRINCIPAL NEVER COULD READ IS REFUSED UNREAD. The
/// claimant publishes a member of its doc 1 windowing its own private draft
/// D, masked to every reader who may not read D (PUB-6.41). C, a stranger
/// holding no grant, versions that member — a published source, so the
/// version is admitted — and F, C's own published document, arranges D's
/// addresses by reference, masked to C as to everyone. A shot into F
/// re-supplying those runs is CARRIED by F, so the store's source gate would
/// admit it ungated (PUB-6.24), though C never read a byte of D. The check
/// composes nothing over them: `attestation_invalid:withheld`, unattested
/// and signed over the true bytes or a wrong guess alike, and nothing
/// commits. A check that composed carried values would hand C an oracle over
/// D — `attestation_required` for an address that holds a value, `signature`
/// for a wrong guess, admission for the right one.
#[test]
fn a_carried_run_its_principal_never_could_read_is_refused_unread() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = seat_stranger(port, 971);
    let c_signed = hire(port, &signed, CLAIMANT_DOC1, &c.account, 971, &distinct_key(63));
    let d = draft_with(port, &bare, "secret");
    let d_run = run(&d, &format!("{d}.0.1.1"), 6);
    let member = shot(port, &signed, CLAIMANT_DOC1, None, None, std::slice::from_ref(&d_run));
    let masked = json!([withheld_item(&d, 6)]);
    assert_eq!(delivery(port, Some(&c_signed), &member, 1, 6), masked, "the member windows D, masked to C");
    let f = acked_addr(&version_of(port, &c_signed, &member, Some(true)));
    assert!(f.starts_with(&format!("{}.0.", c.account)), "the version is C's own document: {f}");
    assert_eq!(delivery(port, Some(&c_signed), &f, 1, 6), masked, "and F carries D's runs, masked");
    let carried = publish_frame(&f, Some((&f, 6)), None, &[d_run]);
    let before = head_position(port);
    for v in [
        op_unattested(port, Some(&c_signed), &carried),
        op_with_publish_values(port, &c_signed, &carried, &per_byte("secret")),
        op_with_publish_values(port, &c_signed, &carried, &per_byte("secreT")),
    ] {
        assert_eq!(
            refusal(&v),
            ("credential_refused:attestation_invalid:withheld".to_string(), "reorder".to_string()),
            "a carried run its author never could read: {v}"
        );
    }
    assert_eq!(head_position(port), before, "nothing committed");
}

/// A SHOT'S ENTRY-FRAME BODY IS BOUNDED, at parity with the request-body
/// cap (`skepd::body_cap("/op")`): the body `entry_body_publish` would build
/// is measured as the check reads each value, and a shot whose runs name one
/// byte more is refused `attestation_invalid:frame_too_large`, PERMANENT,
/// before the body is built — attested or not, since a body that is never
/// built verifies nothing. At the budget exactly the shot is admitted and
/// commits attested. A run names one stored value as often as the wire's run
/// list admits, so no cap on the request bounds the body the check reads:
/// four runs over one two-megabyte atom fill it here.
#[test]
fn a_shot_body_past_the_budget_is_refused_before_it_is_built() {
    let budget = skepd::body_cap("/op");
    // The body is a be64 count, then a be32 length and the bytes per value:
    // four values of `width` bytes each fill `8 + 4 × (4 + width)` — the
    // budget exactly.
    let width = (budget - 8) / 4 - 4;
    assert_eq!(8 + 4 * (4 + width), budget, "four atoms fill the body to the byte");
    let (xs, ys) = ("x".repeat(width), "y".repeat(width + 1));
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let d = owner_draft(port, &signed);
    let insert_atom = |at: u64, text: &str| {
        format!(
            r#"{{"op":"insert","doc":"{d}","at":{{"subspace":"1","ordinal":"{at}"}},"values":[{{"atom":"{text}"}}]}}"#
        )
    };
    let x = acked_addr(&op_unattested(port, Some(&signed), &insert_atom(1, &xs)));
    let y = acked_addr(&op_unattested(port, Some(&signed), &insert_atom(2, &ys)));
    let (x_run, y_run) = (run(&d, &x, 1), run(&d, &y, 1));
    let base = Some((CLAIMANT_DOC1, 1));
    let before = head_position(port);

    // One byte past the budget: refused before the body is built.
    let over = publish_frame(CLAIMANT_DOC1, base, None, &[x_run.clone(), x_run.clone(), x_run.clone(), y_run]);
    let over_values = [xs.as_bytes(), xs.as_bytes(), xs.as_bytes(), ys.as_bytes()];
    for v in [
        op_unattested(port, Some(&signed), &over),
        op_with_publish_values(port, &signed, &over, &over_values),
    ] {
        assert_eq!(
            refusal(&v),
            (
                "credential_refused:attestation_invalid:frame_too_large".to_string(),
                "permanent".to_string()
            ),
            "one byte past the shot-body budget: {v}"
        );
    }
    assert_eq!(head_position(port), before, "a refused shot commits nothing");

    // At the budget exactly: the body is built, the check admits, the shot
    // commits attested.
    let at_cap = publish_frame(CLAIMANT_DOC1, base, None, &[x_run.clone(), x_run.clone(), x_run.clone(), x_run]);
    let v = op_with_publish_values(port, &signed, &at_cap, &[xs.as_bytes(); 4]);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "a shot at the budget is admitted: {v}");
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some(), "and attested");
}

/// A3 as the wire sees it: the head writer's own commits — the system
/// account's — never pass dispatch, so they never reach the check: they land
/// UNSIGNED, their slots empty, before and after an attested write whose slot
/// alone is filled, and a second head lands the same way. A5 beside it: the
/// head's three commits after the claim are exactly where the claim's own
/// step put them (s1). The ω exemption for a DISPATCHED write is pinned where
/// it can fail: `policy/attestation.rs`'s
/// `a_board_with_no_h1_answers_board_unavailable_except_where_the_check_stands_aside`.
#[test]
fn the_head_writers_own_commits_land_unsigned_beside_an_attested_write() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let (position, _chain) = board_term(port).expect("H.1");
    assert_eq!(position, 12, "H.1 names the claim's own position");
    // The head's three commits: the staging draft's mint, the record's
    // insert, the shot into H — all above the claim, all unsigned.
    let head = head_position(port);
    assert!(head > 12, "the head's commits landed above the claim");
    assert_eq!(filled_slots(&sd, 1, head), Vec::<u64>::new(), "no slot filled yet");
    // A signed write with the hour passed, so the head writer's turn after it
    // writes the second head — the cadence's (trigger (c)), through the clock
    // seam: the write's marker slot filled, the head's commits after it
    // unsigned, H.2 present.
    let signed = open_owner_session(port);
    sd.daemon().set_head_writer_clock_millis(wall_clock_millis() + WELL_PAST_THE_HOUR_MILLIS);
    let v = op(port, Some(&signed), &typed_link_frame(CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[], T_GRANT));
    let link_at = acked_at(&v);
    let head = head_position(port);
    assert!(head > link_at, "a second head landed in the head writer's turn after the write");
    assert_eq!(filled_slots(&sd, 1, head), vec![link_at], "the one signed write's slot alone");
    let rec = op_unattested(port, None, &retrieve_frame("1.1.0.1.0.2.2", 1, 1));
    assert_eq!(rec["resp"].as_str(), Some("delivery"), "H.2 exists: {rec}");
}

/// A well past-the-hour clock jump for the head writer's clock seam — the
/// bound is one hour and this is many.
const WELL_PAST_THE_HOUR_MILLIS: u64 = 10_000_000;

/// The wall clock now, in unix milliseconds — the head writer's own domain,
/// which its clock seam reads relative to.
fn wall_clock_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64
}

/// D13 — THE BOARD TERM IS `H.1`'s PAIR FOR THE LIFE OF THE BOARD (RULED
/// 2026-09-25; wire.md: "`board` the head document `H.1`'s `(position,
/// chain)` pair"). After a SECOND head lands, a grant signed over `H.1`'s
/// pair is admitted and its slot is that blob; the same grant signed over the
/// LATEST head's pair, or over the live `/health` pair, is refused
/// `attestation_invalid:signature`. Fixed from the claim on is what lets a
/// client sign before the commit with no round trip. A daemon naming the
/// latest head — `board_term` reading `read_latest_head`, the helper beside
/// it — refuses every client from the board's second head on, REORDER, a
/// re-compose that can never succeed; no other test writes attested after
/// `H.2`, so every other test passes it.
#[test]
fn the_board_term_stays_h1s_pair_after_a_second_head_lands() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let signer = hybrid_signer(&device_key());
    let h1 = board_term(port).expect("H.1 at the claim");

    // A second head: the hour passes, and the head writer's turn after an
    // attested grant writes H.2 naming that grant.
    sd.daemon().set_head_writer_clock_millis(wall_clock_millis() + WELL_PAST_THE_HOUR_MILLIS);
    let trigger = acked_at(&op(port, Some(&signed), &claimant_grant()));
    let h2 = recorded_pair(port, "1.1.0.1.0.2.2");
    assert_eq!(h2.0, trigger, "H.2 names the grant its turn followed");
    assert_ne!(h2, h1, "a second head, a second pair");

    // Over the LATEST head's pair: refused.
    let over_h2 = signer.sign(&claimant_grant_entry_frame(ALG_MLDSA65_ED25519, h2));
    let v = op_unattested(port, Some(&signed), &claimant_grant_attested(ALG_MLDSA65_ED25519, &over_h2));
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:signature".to_string(), "reorder".to_string()),
        "the latest head's pair is not the board term: {v}"
    );
    // Over the LIVE pair: refused.
    let health = json(&get(port, "/health").1);
    let live_chain: [u8; 32] =
        hex_to_bytes(health["chain_head"].as_str().expect("chain_head")).try_into().expect("32 bytes");
    let live = (health["log_position"].as_u64().expect("log_position"), live_chain);
    let over_live = signer.sign(&claimant_grant_entry_frame(ALG_MLDSA65_ED25519, live));
    let v = op_unattested(port, Some(&signed), &claimant_grant_attested(ALG_MLDSA65_ED25519, &over_live));
    assert_eq!(verdict(&v), "credential_refused:attestation_invalid:signature", "the live pair: {v}");
    // Over H.1's: admitted, the slot that very blob.
    let over_h1 = signer.sign(&claimant_grant_entry_frame(ALG_MLDSA65_ED25519, h1));
    let v = op_unattested(port, Some(&signed), &claimant_grant_attested(ALG_MLDSA65_ED25519, &over_h1));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "H.1's pair is the board term after H.2: {v}");
    let slot = sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().expect("the slot is filled");
    assert_eq!(slot.sig(), &over_h1[..], "H.1's pair, after the second head as before it");
}

/// D26: a credential deposit is TWO POSITIONS — the atom `insert` and its
/// `make_link` — and neither takes the entry signature: the atom by its
/// declared credential type, the link by its route (the credential route,
/// to which a presented `attest` is never handed). Both slots stay empty;
/// the hire's agent opens a signed session and attests its own writes.
#[test]
fn d26_a_credential_deposits_two_positions_take_no_entry_signature() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let registrar = open_owner_session(port);
    let key = distinct_key(51);
    // Top-level strangers: their genesis enters no cone, so the claimant's
    // device session seeds them into its own doc 1 (AUTH-2.62).
    let (agent, _) = bootstrap_delegate(port, 51);
    let before = head_position(port);
    let agent_signed = hire(port, &registrar, CLAIMANT_DOC1, &agent, 51, &key);
    let after = head_position(port);
    assert!(after > before, "the atom's insert and the link committed");
    assert_eq!(filled_slots(&sd, before + 1, after), Vec::<u64>::new(), "both slots empty");
    // The link half posted WITH an attest, by hand: routed to the credential
    // sequence, the member dropped — on a fresh agent's deposit.
    let key2 = distinct_key(52);
    let (agent2, _) = bootstrap_delegate(port, 52);
    let ordinal = next_content_ordinal(port, Some(&registrar), CLAIMANT_DOC1);
    let v = op(
        port,
        Some(&registrar),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
            enroll_atom(&[&key2])
        ),
    );
    let atom = acked_addr(&v);
    let mut link: Value =
        serde_json::from_str(&typed_link_frame(CLAIMANT_DOC1, &[&atom], &[&agent2], T_ENROLL)).unwrap();
    link["attest"] = json!({"alg": ALG_MLDSA65_ED25519, "sig": hex(&[0xAB; 3373])});
    let v = op_unattested(port, Some(&registrar), &link.to_string());
    let link_at = acked_at(&v);
    assert_eq!(sd.daemon().attestation_at(Seq(link_at)).unwrap(), None, "dropped by route");
    // The agent, keyed, attests its own publish-class write.
    let home = acked_addr(&op(port, Some(&agent_signed), &create_frame(&agent, None)));
    let v = op(port, Some(&agent_signed), &typed_link_frame(&home, &[&agent], &[], T_GRANT));
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some());
}

// ── the frames and the goldens ──────────────────────────────────────────────

fn addr(s: &str) -> skep_address::Address {
    let comps: Vec<skep_address::Nat> =
        s.split('.').map(|c| skep_address::Nat::from(c.parse::<u64>().unwrap())).collect();
    skep_address::validate(skep_address::Tumbler::new(comps).unwrap()).unwrap()
}

/// The three fixed instances every golden signs: the frames of an
/// `insert` (undeclared, two values), a `make_link` (three address-form
/// slots) and a `publish` (three values) on a board whose `H.1` pair is
/// `(12, 0xAB…)`, by account `1.0.1`.
fn fixed_frames(alg: &str) -> [(&'static str, Vec<u8>); 3] {
    let (account, doc) = (addr("1.0.1"), addr("1.0.1.0.1"));
    let insert = entry_body_insert(None, [&b"a"[..], &b"b"[..]]);
    let ty = [addr("1.1.0.1.0.1.0.3.90")];
    let from = [addr("1.0.1")];
    let to: [skep_address::Address; 0] = [];
    let link = entry_body_link(&EntrySlot::Addrs(&ty), &EntrySlot::Addrs(&from), &EntrySlot::Addrs(&to));
    let publish = entry_body_publish([&b"x"[..], &b"y"[..], &b"z"[..]]);
    [insert, link, publish]
        .map(|body| (body.op(), entry_frame(alg, (12, [0xAB; 32]), &account, &doc, &body)))
}

/// THE FRAME REGRESSION per op: the bytes, spelled out by hand once — the
/// D24 interim pins as the seam build made them.
#[test]
fn the_entry_frames_bytes_per_op_are_pinned() {
    let [(_, insert), (_, link), (_, publish)] = fixed_frames(ALG_MLDSA65_ED25519);
    // The members all three frames share: the framing tag, then `alg`,
    // `board`, `account` and `doc`.
    let mut prefix = b"skep-entry-v1".to_vec();
    let member = |m: &[u8]| [&(m.len() as u32).to_be_bytes()[..], m].concat();
    prefix.extend(member(b"mldsa65-ed25519"));
    prefix.extend(member(&[&[0u8, 0, 0, 0, 0, 0, 0, 12][..], &[0xAB; 32][..]].concat()));
    prefix.extend(member(b"1.0.1"));
    prefix.extend(member(b"1.0.1.0.1"));
    // insert: op, then body = be32(0) (undeclared) ‖ be64(2) ‖ 4:1:a ‖ 4:1:b
    let mut want = prefix.clone();
    want.extend(member(b"insert"));
    want.extend(member(
        &[&[0u8, 0, 0, 0][..], &[0, 0, 0, 0, 0, 0, 0, 2][..], &[0, 0, 0, 1, b'a'][..], &[0, 0, 0, 1, b'b'][..]].concat(),
    ));
    assert_eq!(insert, want, "insert");
    // make_link: op, then body = ty slot ‖ from slot ‖ to slot.
    let slot = |addrs: &[&[u8]]| {
        let mut s = vec![0x01u8];
        s.extend((addrs.len() as u64).to_be_bytes());
        for a in addrs {
            s.extend(member(a));
        }
        s
    };
    let mut want = prefix.clone();
    want.extend(member(b"make_link"));
    want.extend(member(
        &[slot(&[b"1.1.0.1.0.1.0.3.90"]), slot(&[b"1.0.1"]), slot(&[])].concat(),
    ));
    assert_eq!(link, want, "make_link");
    // publish: op, then body = be64(3) ‖ x ‖ y ‖ z
    let mut want = prefix;
    want.extend(member(b"publish"));
    want.extend(member(
        &[&[0u8, 0, 0, 0, 0, 0, 0, 3][..], &[0, 0, 0, 1, b'x'][..], &[0, 0, 0, 1, b'y'][..], &[0, 0, 0, 1, b'z'][..]]
            .concat(),
    ));
    assert_eq!(publish, want, "publish");
}

/// The golden's seed: one 32-byte seed, the paper backup's one 64-hex line.
const GOLDEN_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// One tag's golden, in the documented form: the SHA-256 of the PQ public
/// half, of the Ed25519 public half, of the whole raw key; the fingerprint;
/// and per op the SHA-256 of the signature blob — the frames themselves
/// pinned byte for byte by [`the_entry_frames_bytes_per_op_are_pinned`].
struct TagGolden {
    tag: u8,
    pq_pk: &'static str,
    ed_pk: &'static str,
    raw_key: &'static str,
    fingerprint: &'static str,
    sigs: [&'static str; 3],
}

/// Per op: its name, its frame's bytes, its signature blob.
type SignedFrames = Vec<(String, Vec<u8>, Vec<u8>)>;

fn golden_of(tag: u8) -> (HybridSigner, SignedFrames) {
    let signer = HybridSigner::from_seed(tag, &GOLDEN_SEED).unwrap();
    let alg = SigAlgRow::of_tag(tag).unwrap().token;
    let mut out = Vec::new();
    for (op, frame) in fixed_frames(alg) {
        // Tag 3's signature draws its seed from the fixtures' seeded RNG,
        // reseeded per op so each signature is a function of its frame alone.
        let mut rng = SeededRng06::new(GOLDEN_SEED);
        let sig = signer.sign_with_rng(&frame, &mut rng);
        assert_eq!(hybrid::verify(tag, signer.public_key(), &frame, &sig), Ok(()));
        out.push((op.to_string(), frame, sig));
    }
    (signer, out)
}

fn check_golden(g: &TagGolden) {
    let (signer, signed) = golden_of(g.tag);
    let key = signer.public_key();
    let pq = sha_hex(key.pq_half());
    let ed = sha_hex(key.ed25519_half());
    let raw = sha_hex(key.raw());
    let fp = Fingerprint::of(key).to_hex();
    let sigs: Vec<String> = signed.iter().map(|(_, _, sig)| sha_hex(sig)).collect();
    let report = format!(
        "tag {}: pq_pk {pq}\n ed_pk {ed}\n raw_key {raw}\n fingerprint {fp}\n sigs {} {} {}",
        g.tag, sigs[0], sigs[1], sigs[2]
    );
    assert_eq!(pq, g.pq_pk, "the PQ public half moved — a keygen change is a NEW tag\n{report}");
    assert_eq!(ed, g.ed_pk, "the Ed25519 half moved — the KDF is a frozen pin\n{report}");
    assert_eq!(raw, g.raw_key, "{report}");
    assert_eq!(fp, g.fingerprint, "{report}");
    for (i, (op, _, _)) in signed.iter().enumerate() {
        assert_eq!(sigs[i], g.sigs[i], "the {op} signature moved under tag {}\n{report}", g.tag);
    }
}

/// TAG 1's GOLDEN: the KEY-DERIVATION golden (seed → KDF → both public
/// keys → fingerprint) and the three ops' signatures, byte-stable under
/// FIPS 204's deterministic variant and Ed25519's own determinism.
#[test]
fn golden_tag_1_mldsa65_ed25519() {
    check_golden(&TagGolden {
        tag: 1,
        pq_pk: "41b2f17766cec1a3ccc6b4c8a661e07c5ebc1d1503ec4c95f4a283aa750d5a4e",
        ed_pk: "427a61d4297fffd61db5ada0dc592fa22858b6b8dbb19219b2f55437e2b671d2",
        raw_key: "21ee44a4d3a59b86fafc6ef131e2bfb63688023f6101f392a34c17a41fefe27b",
        fingerprint: "8c7d0b0e21969ffa5039ccebce2c857614740c3be9498ab8c697bc9320c30623",
        sigs: [
            "2892943416a13f80eeb95f4c8bd55f115d7248324c433bffbeaf7f0501828148",
            "7fd029f5cad3498cd5321332c6d0dba23e326d5603781ee19ec00f2c70d3f940",
            "50d83bfcc18792e51073852113df636c4d6f3aa86391f7fd970b5738b5737879",
        ],
    });
}

/// TAG 3's GOLDEN (the PREVIEW): the KEY-DERIVATION golden — `fn-dsa`
/// 0.4.0's keygen from the KDF's seed IS the tag's frozen keygen rule — and
/// the three signatures under the fixtures' seeded RNG (FN-DSA signing is
/// randomized by the draft's own rule; what the tag freezes is the key, the
/// frame and the verify, and the fixture's RNG makes the bytes reproducible
/// here).
#[test]
fn golden_tag_3_fndsa512_preview_ed25519() {
    check_golden(&TagGolden {
        tag: 3,
        pq_pk: "0e70d565dce4eaf0da8790ca44478f85587b3e77322359ac65fc7ab3f6848571",
        ed_pk: "43ac1d6774e9a307df9ca5d82c010bb99c3c4ef42439e78fc09b133f401bbf10",
        raw_key: "c259e2fd41a3534528a7edf6550befa1fa134a3371aca0cccfe5caf28c90c886",
        fingerprint: "d38e5be29f0c62fe1a51cb09d00250ea18bfd2ba799536c0596077d1d1d65fca",
        sigs: [
            "da92e3fc0247d5f39ed149f574a6c18cc1bf959a4f167ba33d381a955ed95779",
            "20c93bb2e587c2139fd47bfe48fb4738e9f761862d66908c4e26d2f237d292e7",
            "4a5bc2ebd6345adf18bbe073e21f5d02815d4ca5625d1ba2751461e6a1fe9c64",
        ],
    });
}

/// THE HYBRID CROSS-CHECK at the frame: each half alone fails — a valid PQ
/// half with a foreign Ed25519 half, and the reverse — under both tags.
#[test]
fn each_half_alone_fails_under_both_tags() {
    for tag in [1u8, 3] {
        let (signer, signed) = golden_of(tag);
        let row = SigAlgRow::of_tag(tag).unwrap();
        let other = HybridSigner::from_seed(tag, &[0x99; 32]).unwrap();
        let (_, frame, sig) = &signed[0];
        let mut rng = SeededRng06::new([1; 32]);
        let foreign = other.sign_with_rng(frame, &mut rng);
        // The PQ half ours, the Ed25519 half theirs.
        let mut mixed = sig[..row.pq_sig_len].to_vec();
        mixed.extend_from_slice(&foreign[row.pq_sig_len..]);
        assert!(hybrid::verify(tag, signer.public_key(), frame, &mixed).is_err(), "tag {tag}: ed half");
        // The Ed25519 half ours, the PQ half theirs.
        let mut mixed = foreign[..row.pq_sig_len].to_vec();
        mixed.extend_from_slice(&sig[row.pq_sig_len..]);
        assert!(hybrid::verify(tag, signer.public_key(), frame, &mixed).is_err(), "tag {tag}: pq half");
        assert_eq!(hybrid::verify(tag, signer.public_key(), frame, sig), Ok(()));
    }
}

/// THE DIFFERENTIAL TEST for tag 1 (the PQ investigation §8.4 (4), §8.5
/// (ii)): `ml-dsa` 0.1.1's keys from ξ and its deterministic signatures are
/// byte-equal to `fips204` 0.4.6's, a second pure-Rust FIPS 204, over
/// sixteen seeds and the three fixed frames — the gate every future bump of
/// the pinned crate must pass, since FIPS 204 fixes `KeyGen_internal(ξ)`
/// and the deterministic variant.
#[test]
fn tag_1_is_byte_equal_to_a_second_fips_204_implementation() {
    use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
    for i in 0..16u8 {
        let seed = [i; 32];
        let halves = hybrid::derive_seeds(1, &seed).unwrap();
        // `ml-dsa`'s side: the PQ half of the hybrid key and its signature.
        let ours = HybridSigner::from_seed(1, &seed).unwrap();
        let our_pk = ours.public_key().pq_half().to_vec();
        // `fips204`'s side, from the same ξ.
        let (their_pk, their_sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&halves.pq);
        assert_eq!(our_pk, their_pk.clone().into_bytes().to_vec(), "seed {i}: the public key");
        for (op, frame) in fixed_frames(ALG_MLDSA65_ED25519) {
            let our_sig = ours.sign(&frame);
            let our_pq = &our_sig[..3309];
            let their_sig = their_sk.try_sign_with_seed(&[0u8; 32], &frame, &[]).unwrap();
            assert_eq!(our_pq, &their_sig[..], "seed {i}, {op}: the deterministic signature");
            assert!(their_pk.verify(&frame, &their_sig, &[]), "their verify of their own");
            let as_theirs: [u8; 3309] = our_pq.try_into().unwrap();
            assert!(their_pk.verify(&frame, &as_theirs, &[]), "their verify of ours");
        }
    }
}

/// THE SIZES AND TIMINGS the report takes back: per tag the public key, the
/// signature blob and the FILLED marker payload (97 + the blob), and the
/// median sign and verify on this machine — printed, and the sizes pinned.
#[test]
fn sizes_and_timings_per_tag() {
    use std::time::Instant;
    for tag in [1u8, 3] {
        let row = SigAlgRow::of_tag(tag).unwrap();
        let (signer, signed) = golden_of(tag);
        let key_len = signer.public_key().raw().len();
        let sig_len = signed[0].2.len();
        assert_eq!(key_len, row.key_len());
        assert_eq!(sig_len, row.sig_len());
        let hybrid::PqWidths { key: pq_key, sig: pq_sig, signing_key: pq_sk } =
            hybrid::pq_widths(tag).unwrap();
        let frame = &signed[0].1;
        let n = 40;
        let mut sign_us = Vec::new();
        let mut verify_us = Vec::new();
        let mut keygen_us = Vec::new();
        for k in 0..n {
            let t = Instant::now();
            let s = HybridSigner::from_seed(tag, &[k as u8; 32]).unwrap();
            keygen_us.push(t.elapsed().as_micros());
            let t = Instant::now();
            let sig = s.sign(frame);
            sign_us.push(t.elapsed().as_micros());
            let t = Instant::now();
            assert_eq!(hybrid::verify(tag, s.public_key(), frame, &sig), Ok(()));
            verify_us.push(t.elapsed().as_micros());
        }
        let median = |v: &mut Vec<u128>| {
            v.sort();
            v[v.len() / 2]
        };
        eprintln!(
            "SIGNED-OPS SIZES tag {tag} ({}): public key {key_len} B (pq {pq_key} + ed 32), \
             signature {sig_len} B (pq {pq_sig} + ed 64), filled marker payload {} B \
             (97 + {sig_len}), pq signing key {pq_sk} B; medians over {n}: keygen {} µs, \
             sign {} µs, verify {} µs",
            row.token,
            97 + sig_len,
            median(&mut keygen_us),
            median(&mut sign_us),
            median(&mut verify_us)
        );
    }
    // `ml-dsa` 0.1.1's ML-DSA-65 — FIPS 204's verifying key, signature and
    // expanded signing key — read off the crate by `pq_widths` and pinned here
    // by hand.
    assert_eq!(
        hybrid::pq_widths(1),
        Some(hybrid::PqWidths { key: 1952, sig: 3309, signing_key: 4032 })
    );
    // `fn-dsa` 0.4.0's signing key at degree 9: 65 + (6 << 7) + 512 = 1,345
    // (its `f, g, F` and the hashed verifying key), the PQ investigation's
    // measured figure.
    assert_eq!(
        hybrid::pq_widths(3),
        Some(hybrid::PqWidths { key: 897, sig: 666, signing_key: 1345 })
    );
}

/// THE FN-DSA PREVIEW's signer backend on this machine (the owner's added
/// question): `fn-dsa` 0.4.0 selects its floating-point backend by
/// `target_arch` alone — the native `f64` on `x86_64`, `aarch64`, `arm64ec`
/// and `riscv64`, the INTEGER-EMULATED IEEE-754 backend everywhere else —
/// with no feature to force the emulation, so on this `aarch64` machine the
/// native backend signs; the emulated signer is compiled for no installed
/// target here and could not be run. This test records which backend signed
/// the goldens, and that it signs and verifies.
#[test]
fn the_fn_dsa_preview_signs_and_verifies_on_this_target() {
    let native = cfg!(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm64ec",
        target_arch = "riscv64"
    ));
    eprintln!(
        "SIGNED-OPS FN-DSA backend on {}: {}",
        std::env::consts::ARCH,
        if native { "native f64 (fn-dsa 0.4.0 flr_native)" } else { "integer-emulated IEEE-754 (flr_emu)" }
    );
    let (signer, signed) = golden_of(3);
    for (op, frame, sig) in &signed {
        assert_eq!(hybrid::verify(3, signer.public_key(), frame, sig), Ok(()), "{op}");
        assert_eq!(sig.len(), 730);
    }
}

/// The codec's round trip carries the member: `parse(marshal(r))` reproduces
/// a request with an `attest`, and the tag-3 token rides the wire too.
#[test]
fn the_codec_round_trips_the_attest_member_under_both_tokens() {
    let codec = JsonCodec;
    for (tag, token) in [(1u8, ALG_MLDSA65_ED25519), (3u8, ALG_FNDSA512_PREVIEW_ED25519)] {
        let width = SigAlgRow::of_token(token).unwrap().sig_len();
        let frame = json!({
            "op": "make_link", "home": "1.0.1.0.1",
            "from": {"addrs": ["1.0.1"]}, "to": {"addrs": []}, "ty": {"addrs": [T_GRANT]},
            "attest": {"alg": token, "sig": hex(&vec![0x5A; width])}
        });
        let req = codec.parse(frame.to_string().as_bytes()).expect("parses");
        let a = req.attest.as_ref().expect("the member");
        assert_eq!((a.sig_alg(), a.sig().len()), (tag, width));
        let again = codec.parse(&codec.marshal_request(&req)).expect("re-parses");
        assert!(again == req, "the round trip is a fixpoint");
    }
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// The seed carrier's derived halves differ from the raw key and from each
/// other, and the enrolled hybrid's fingerprint is the session's testimony:
/// the ruled "one seed, two halves" at the fixtures.
#[test]
fn the_fixtures_seed_carrier_derives_both_halves() {
    let sk: SigningKey = device_key();
    let signer = hybrid_signer(&sk);
    assert_ne!(signer.ed25519_signing_key().to_bytes(), sk.to_bytes(), "never the raw seed");
    let enrolled: PublicKey = public_key_of(&sk);
    assert_eq!(enrolled.alg(), ALG_MLDSA65_ED25519);
    assert_eq!(enrolled.raw().len(), 1984);
    assert_eq!(enrolled.ed25519_half(), &signer.ed25519_signing_key().verifying_key().to_bytes());
}
