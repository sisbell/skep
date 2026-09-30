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
//! THE REPLAY RULE AT THE GRANT (PUB-5.15 (iv)): a signed share replayed
//! byte for byte after its revocation verifies, lands, and grants nothing;
//! a re-share naming the standing revocation in its signed `replaces`
//! member is honored; its own request replayed after a later revocation
//! grants nothing.
//!
//! THE FRAMES (the frozen-tag rule's pin): the three ops' entry frames at
//! fixed instances, their bytes spelled out by hand. The key-derivation and
//! signature goldens that sign them live beside the rules they pin, in
//! `skep-signature`'s suite (`tests/it/golden.rs`).

use crate::common::*;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use skep_febe::Codec;
use skep_identity::{
    entry_body_insert, entry_body_make_link, entry_body_make_link_replacing, entry_body_publish,
    entry_body_record, entry_frame, BoardTerm, Enrollment, EntrySlot, Fingerprint, LinkSlots,
    PublicKey, ShotSegment, SigAlgRow, ALG_FNDSA512_PREVIEW_ED25519, ALG_MLDSA65_ED25519,
};
use skep_signature::HybridSigner;
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

/// The claimant's grant — `make_link` homed in its doc 1, `from` its
/// account, `to` empty, typed `T_GRANT` — the one frame the cells below sign
/// by hand.
fn claimant_grant() -> String {
    typed_link_frame(CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[], T_GRANT)
}

/// [`claimant_grant`]'s ENTRY frame under `alg` over `board`, composed from
/// its members' values — for the cells that sign over a term, or under a
/// token, the test signer never would.
fn claimant_grant_entry_frame(alg: &str, board: BoardTerm) -> Vec<u8> {
    let ty = [addr(T_GRANT)];
    let from = [addr(CLAIMANT_ACCOUNT)];
    let to: [skep_address::Address; 0] = [];
    let body = entry_body_make_link(LinkSlots {
        from: EntrySlot::Addrs(&from),
        to: EntrySlot::Addrs(&to),
        ty: EntrySlot::Addrs(&ty),
    });
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
    let h1 = board_term(port).expect("H.1 stands at the claim's ack");
    assert_eq!(h1.log_position, claim_at, "H.1 names the claim's own position");
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
    let h1 = board_term(port).expect("H.1 at the claim's ack");
    assert_eq!(h1.log_position, claim_at, "H.1 names the claim's own position");
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
    assert_eq!(slot.sig_alg(), skep_signature::TAG_MLDSA65_ED25519);
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
/// `attestation_invalid:signature` (permanent — the board's r6-6: the same
/// request is refused the same, the client's next act a re-composed one);
/// the wrong width → `:malformed` (permanent, the same); a bare session →
/// `signed_session_required` as before; an
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
    assert_eq!(slot.sig_alg(), skep_signature::TAG_MLDSA65_ED25519);
    assert_eq!(hex(slot.sig()), sig_hex, "the marker carries the attached blob, whole");
    // …and the transactions around it stay empty.
    assert_eq!(sd.daemon().attestation_at(Seq(at - 1)).ok().flatten(), None);

    // Wrong bytes (the Ed25519 half flipped): signature, permanent.
    let mut tampered = attached.clone();
    let mut bytes = hex_to_bytes(&sig_hex);
    bytes[3309] ^= 1;
    tampered["attest"]["sig"] = Value::String(hex(&bytes));
    let v = op_unattested(port, Some(&signed), &tampered.to_string());
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:signature".to_string(), "permanent".to_string()),
        "{v}"
    );
    // The PQ half flipped: the same verdict — both halves verify or none.
    let mut tampered = attached.clone();
    let mut bytes = hex_to_bytes(&sig_hex);
    bytes[7] ^= 1;
    tampered["attest"]["sig"] = Value::String(hex(&bytes));
    let v = op_unattested(port, Some(&signed), &tampered.to_string());
    assert_eq!(verdict(&v), "credential_refused:attestation_invalid:signature");
    // The wrong width: malformed, permanent.
    let mut short = attached.clone();
    short["attest"]["sig"] = Value::String(sig_hex[2..].to_string());
    let v = op_unattested(port, Some(&signed), &short.to_string());
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:malformed".to_string(), "permanent".to_string()),
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
    let tag3 = HybridSigner::from_seed(skep_signature::TAG_FNDSA512_PREVIEW_ED25519, &seed_of(&key))
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
            skep_signature::verify(FIXTURE_TAG, &public_key_of(&key), &frame, slot.sig()),
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
/// `attestation_invalid:signature` — PERMANENT, a re-compose that never
/// lands.
#[test]
fn a_tag_3_key_attests_a_write_as_a_tag_1_key_does() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let tag3 =
        HybridSigner::from_seed(skep_signature::TAG_FNDSA512_PREVIEW_ED25519, &seed_of(&distinct_key(61)))
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
    assert_eq!(slot.sig_alg(), skep_signature::TAG_FNDSA512_PREVIEW_ED25519, "the slot carries tag 3");
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
/// `withheld` "before any existence answer") — and under the ADDRESS FORM
/// (fam2-Q's arm A, l6-A4, 2026-09-29) a WINDOW is read by nobody: it is
/// signed by its address, the check composes it unread, and the store's
/// own gate decides it after the signature. B, granted the claimant's
/// private draft D, versions it — F, B's own published document arranging
/// D's first five addresses by reference — and is revoked; D then grows a
/// sixth address B never could read. From B's signed session every shot
/// naming D's addresses is answered VALUE-BLIND — unattested it is the
/// check's `attestation_required`, whatever the shot names; signed over
/// D's true bytes or over a wrong guess it is the same answer, since the
/// guess enters no frame:
/// A — a run onto D's sixth address, which F does not carry: `withheld`,
///     the store's gate;
/// B — one run spanning addresses F carries AND the one it does not: the
///     same;
/// C — D ITSELF named as the base, outside F's chain: `base_not_in_chain`,
///     the store's refusal ahead of its source gate — a base the client
///     names carries nothing from outside the document's own chain;
/// D — a run F's own base CARRIES: the store's gate admits it ungated
///     (PUB-6.24), and the revoked grantee's signature over the run's
///     ADDRESS verifies — the re-shoot commits, attested, and F's member
///     windows D masked to B as before. (Until the address form the check
///     refused this cell `attestation_invalid:withheld`, unread: the body was
///     composed of values, and a lapsed grantee could attest none — fam2-Q's
///     finding (c), which arm A closes.)
/// A check that composed D's values would answer A and B BY them —
/// `attestation_required` for an address that holds a value, `signature`
/// for a wrong guess.
#[test]
fn a_run_its_principal_may_not_read_is_answered_value_blind_and_a_carried_window_is_re_shot() {
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
    // One shot, three ways: unattested, then signed over each guess. The
    // unattested send is refused by the check, the member absent; the signed
    // ones by the store, the same whatever the guess.
    let answers = |frame: &str, guesses: [&str; 2]| -> (Value, Vec<Value>) {
        let unattested = op_unattested(port, Some(&b_signed), frame);
        let signed: Vec<Value> = guesses
            .iter()
            .map(|guess| op_with_publish_values(port, &b_signed, frame, &per_byte(guess)))
            .collect();
        (unattested, signed)
    };
    let required = ("credential_refused:attestation_required".to_string(), "reorder".to_string());
    let before = head_position(port);

    // A — an address F never carried.
    let (unattested, signed_twice) = answers(&into_f(&f, &[run(&d, &d_addr(6), 1)]), ["f", "g"]);
    assert_eq!(refusal(&unattested), required, "{unattested}");
    for v in signed_twice {
        assert_withheld(&v, &d);
    }
    // B — carried and uncarried in one run.
    let (unattested, signed_twice) = answers(&into_f(&f, &[run(&d, &d_addr(4), 3)]), ["def", "deg"]);
    assert_eq!(refusal(&unattested), required, "{unattested}");
    for v in signed_twice {
        assert_withheld(&v, &d);
    }
    // C — D named as the base: outside F's chain, it carries nothing.
    let (unattested, signed_twice) =
        answers(&into_f(&d, &[run(&d, &d_addr(1), 5)]), ["abcde", "abcdz"]);
    assert_eq!(refusal(&unattested), required, "{unattested}");
    for v in signed_twice {
        assert_eq!(verdict(&v), "base_not_in_chain", "{v}");
    }
    assert_eq!(head_position(port), before, "nothing committed so far");
    // D — F's own carried run: unattested, the check's answer; signed over a
    //     WRONG guess, admitted all the same — the guess is no part of the
    //     frame, the window's address is — and attested; the member windows
    //     D, masked to B as F's own positions were.
    let carried = into_f(&f, &[run(&d, &d_addr(1), 5)]);
    let v = op_unattested(port, Some(&b_signed), &carried);
    assert_eq!(refusal(&v), required, "{v}");
    let v = op_with_publish_values(port, &b_signed, &carried, &per_byte("abcdz"));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the carried window, re-shot by address: {v}");
    let member = acked_addr(&v);
    assert_eq!(member, format!("{f}.1"));
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some(), "attested");
    assert_eq!(
        delivery(port, Some(&b_signed), &member, 1, 5),
        json!([withheld_item(&d, 5)]),
        "the member windows D, masked to B"
    );
    assert_eq!(text_of(port, Some(&bare), &member, 1, 5), "abcde", "…and D's owner reads it");
}

/// A CARRIED RUN ITS PRINCIPAL NEVER COULD READ IS RE-SHOT BY ADDRESS,
/// UNREAD (l6-A4). The claimant publishes a member of its doc 1 windowing
/// its own private draft D, masked to every reader who may not read D
/// (PUB-6.41). C, a stranger holding no grant, versions that member — a
/// published source, so the version is admitted — and F, C's own published
/// document, arranges D's addresses by reference, masked to C as to
/// everyone. A shot into F re-supplying those runs is CARRIED by F, so the
/// store's source gate admits it ungated (PUB-6.24), though C never read a
/// byte of D — and the check composes the run by its ADDRESS, reading
/// nothing: unattested it answers `attestation_required`; signed over a
/// wrong guess at D's bytes it verifies (the guess enters no frame) and the
/// shot commits, attested, its member windowing D masked to C as before. A
/// check that composed carried values would hand C an oracle over D —
/// `attestation_required` for an address that holds a value, `signature`
/// for a wrong guess, admission for the right one; this one answers the
/// same whatever the guess, and reads no byte.
#[test]
fn a_carried_run_its_principal_never_could_read_is_re_shot_by_address_unread() {
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
    let v = op_unattested(port, Some(&c_signed), &carried);
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_required".to_string(), "reorder".to_string()),
        "unattested, the check's own answer, the run unread: {v}"
    );
    assert_eq!(head_position(port), before, "nothing committed");
    let v = op_with_publish_values(port, &c_signed, &carried, &per_byte("secreT"));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "signed over a wrong guess, admitted: {v}");
    let re_shot = acked_addr(&v);
    assert_eq!(re_shot, format!("{f}.1"));
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some(), "attested");
    assert_eq!(delivery(port, Some(&c_signed), &re_shot, 1, 6), masked, "still masked to C");
    assert_eq!(text_of(port, Some(&bare), &re_shot, 1, 6), "secret", "D's owner reads D's bytes");
}

/// A SHOT'S ENTRY-FRAME BODY IS BOUNDED, at parity with the request-body
/// cap (`skepd::body_cap("/op")`): the body is measured as the check reads
/// each value (`PublishBody`, in the layout `entry_body_publish` spells), and
/// a shot whose runs name one byte more is refused
/// `attestation_invalid:frame_too_large`, PERMANENT, before the body is built
/// past the budget — attested or not, since a body never built whole
/// verifies nothing. At the budget exactly the shot is admitted and commits
/// attested. A run names one stored value as often as the wire's run list
/// admits, so no cap on the request bounds the body the check reads: four
/// runs over one two-megabyte atom fill it here.
#[test]
fn a_shot_body_is_refused_before_it_is_built_past_its_budget() {
    let budget = skepd::body_cap("/op");
    // The body is `be64(placed)`, then — four values copied in, one stretch
    // — the stretch's class byte and `be64(count)`, then a be32 length and
    // the bytes per value, then the base-extent group of twelve bytes (the
    // shot names a base): three atoms of `width` bytes and one of `last`
    // fill `8 + 9 + 3 × (4 + width) + (4 + last) + 12` — the budget exactly.
    let fixed = 8 + 9 + 4 * 4 + 12;
    let width = (budget - fixed) / 4;
    let last = budget - fixed - 3 * width;
    assert_eq!(8 + 9 + 3 * (4 + width) + (4 + last) + 12, budget, "four atoms fill the body to the byte");
    let (xs, ys, zs) = ("x".repeat(width), "y".repeat(last + 1), "z".repeat(last));
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
    let z = acked_addr(&op_unattested(port, Some(&signed), &insert_atom(3, &zs)));
    let (x_run, y_run, z_run) = (run(&d, &x, 1), run(&d, &y, 1), run(&d, &z, 1));
    let base = Some((CLAIMANT_DOC1, 1));
    let before = head_position(port);

    // One byte past the budget: refused before the body is built past it.
    let over = publish_frame(CLAIMANT_DOC1, base, Some(&d), &[x_run.clone(), x_run.clone(), x_run.clone(), y_run]);
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
    let at_cap = publish_frame(CLAIMANT_DOC1, base, Some(&d), &[x_run.clone(), x_run.clone(), x_run.clone(), z_run]);
    let v = op_with_publish_values(port, &signed, &at_cap, &[xs.as_bytes(), xs.as_bytes(), xs.as_bytes(), zs.as_bytes()]);
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
    let h1 = board_term(port).expect("H.1");
    assert_eq!(h1.log_position, 12, "H.1 names the claim's own position");
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
    assert_ne!(h2, (h1.log_position, h1.chain), "a second head, a second pair");

    // Over the LATEST head's pair, posed as the board term: refused.
    let h2_as_term = BoardTerm { log_position: h2.0, chain: h2.1 };
    let over_h2 = signer.sign(&claimant_grant_entry_frame(ALG_MLDSA65_ED25519, h2_as_term));
    let v = op_unattested(port, Some(&signed), &claimant_grant_attested(ALG_MLDSA65_ED25519, &over_h2));
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:signature".to_string(), "permanent".to_string()),
        "the latest head's pair is not the board term: {v}"
    );
    // Over the LIVE pair, posed as the board term: refused.
    let health = json(&get(port, "/health").1);
    let live_chain: [u8; 32] =
        hex_to_bytes(health["chain_head"].as_str().expect("chain_head")).try_into().expect("32 bytes");
    let live = BoardTerm {
        log_position: health["log_position"].as_u64().expect("log_position"),
        chain: live_chain,
    };
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

// ── the replay rule at the grant ────────────────────────────────────────────

/// THE REPLAY RULE AT THE GRANT, END TO END — the authority link type
/// investigation's walk 1 (PUB-5.15 (iv); rr-Q2's accepted risk, closed), over
/// the wire with real signatures on a claimed board. The claimant shares a
/// draft with every principal — an attested `make_link`, no `replaces`
/// member — and a stranger reads it; it revokes the share, and the stranger
/// is withheld. Then the share's request is REPLAYED, byte for byte, its
/// `attest` included: the entry frame names no position, so the signature
/// verifies and the write lands at a fresh address with its slot filled —
/// and grants nothing, its EMPTY state no longer its key's current one. The
/// claimant RE-SHARES, its signed `replaces` naming the standing revocation,
/// and the stranger reads again; it revokes the re-share, and the re-share's
/// own request, replayed, names a revocation the key has passed and grants
/// nothing. The any-principal read agrees at every step.
#[test]
fn a_replayed_signed_share_grants_nothing_and_a_re_share_naming_the_standing_revocation_does() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let draft = draft_with(port, &signed, "shared");
    let stranger = seat_stranger(port, 4242);
    let reads = || {
        let v = op(port, Some(&stranger.session), &retrieve_frame(&draft, 1, 6));
        if v["resp"].as_str() == Some("delivery") {
            return true;
        }
        assert_withheld(&v, &draft);
        false
    };
    let attested = |v: &Value| sd.daemon().attestation_at(Seq(acked_at(v))).unwrap().is_some();
    assert!(!reads(), "the draft is private until shared");

    // The share — ANY-PRINCIPAL over the draft — signed, and kept verbatim.
    let share =
        attach_attest(port, &signed, &typed_link_frame(CLAIMANT_DOC1, &[&draft], &[], T_GRANT));
    let v = op_unattested(port, Some(&signed), &share);
    let grant = acked_addr(&v);
    assert!(attested(&v), "the share is attested");
    assert!(reads(), "shared");

    // The revocation: a record naming the grant.
    let revoke = typed_link_frame(CLAIMANT_DOC1, &[&grant], &[], T_GRANT);
    let revocation = acked_addr(&op(port, Some(&signed), &revoke));
    assert!(!reads(), "revoked");

    // THE REPLAY: the byte-identical signed share.
    let v = op_unattested(port, Some(&signed), &share);
    assert_ne!(acked_addr(&v), grant, "a replay lands at a fresh address");
    assert!(attested(&v), "the replayed signature verifies — the frame names no position");
    assert!(!reads(), "a replayed share grants nothing");
    assert!(universal_grants(port, Some(&signed)).is_empty(), "…and serves no row");

    // THE RE-SHARE: `replaces` names the standing revocation, inside the
    // signed bytes.
    let re_share = signed_with_replaces(
        port,
        &signed,
        &typed_link_frame(CLAIMANT_DOC1, &[&draft], &[], T_GRANT),
        &revocation,
    );
    let v = op_unattested(port, Some(&signed), &re_share);
    let again = acked_addr(&v);
    assert!(attested(&v), "the re-share is attested");
    assert!(reads(), "a re-share naming the standing revocation is honored");
    let pair = read_link(port, Some(&signed), &next_link_address(&again));
    let start = |slot: usize| pair["slots"][slot][0]["start"].as_str().map(str::to_string);
    assert_eq!(
        (start(0), start(1), start(2)),
        (Some(again.clone()), Some(revocation.clone()), Some(T_REPLACES.to_string())),
        "the replaces link beside the re-share: from it, to the revocation, typed the class: {pair}"
    );

    // Revoked again; the re-share's own request, replayed, names a stale
    // state.
    op(port, Some(&signed), &typed_link_frame(CLAIMANT_DOC1, &[&again], &[], T_GRANT));
    assert!(!reads(), "the re-share revoked");
    let v = op_unattested(port, Some(&signed), &re_share);
    assert_eq!(verdict(&v), "ok", "the replayed re-share lands: {v}");
    assert!(attested(&v), "…signed as it was");
    assert!(!reads(), "a replayed re-share names a revocation the key has passed");
    assert!(universal_grants(port, Some(&signed)).is_empty());
}

// ── the publish re-pin: V, the address form, the terms (2026-09-29) ────────

/// V — A REPLAYED OLD SHOT MINTS ITS BASE'S DAUGHTER, NEVER THE TRUNK'S
/// NEXT (fam1-Q part (1), owner-ruled 2026-09-27; D25's (c′) as its
/// carrier): the `publish` signature binds the shot's base EXTENT and its
/// runs in the address form, and `base` is derived from the minted member's
/// address. D.1 is minted from the memberless edition; D.2 over D.1 by a
/// signed request kept byte for byte; D.3 over D.2. The same D.2 request
/// sent again verifies as it did — nothing it signed has moved — and its
/// commit names `base` D.1, no longer the head, so the store's own rule
/// mints D.1's DAUGHTER `D.1.1` (PUB-2.39), attested; the trunk's current
/// version stays D.3, and every floating reader still answers D.3's text.
/// The side-copy remains, as the ruling accepts.
#[test]
fn a_replayed_shot_mints_its_bases_daughter_and_the_current_version_stands() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let edition = edition_with(port, &signed, "abc");
    let runs = shot_runs(port, Some(&signed), &edition, 1, 3);
    let d1 = shot(port, &signed, &edition, Some((&edition, 3)), None, &runs);
    assert_eq!(d1, format!("{edition}.1"), "the birth version");
    // D.2 over D.1: the edition's three by reference and a draft's two as
    // fresh identity — one signed request, kept verbatim.
    let draft = draft_with(port, &signed, "xy");
    let mut runs2 = shot_runs(port, Some(&signed), &d1, 1, 3);
    runs2.extend(shot_runs(port, Some(&signed), &draft, 1, 2));
    let d2_request =
        attach_attest(port, &signed, &publish_frame(&edition, Some((&d1, 3)), Some(&draft), &runs2));
    assert!(d2_request.contains("\"attest\""), "the request carries its signature");
    let v = op_unattested(port, Some(&signed), &d2_request);
    let d2 = acked_addr(&v);
    assert_eq!(d2, format!("{edition}.2"), "the trunk's next: {v}");
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some(), "attested");
    assert_eq!(text_of(port, None, &edition, 1, 5), "abcxy", "the head is D.2");
    // D.3 over D.2.
    let runs3 = shot_runs(port, Some(&signed), &d2, 1, 5);
    let d3 = shot(port, &signed, &edition, Some((&d2, 5)), None, &runs3);
    assert_eq!(d3, format!("{edition}.3"));
    let head_image = image_runs(port, None, &edition, 1, 5);
    assert_eq!(head_image, image_runs(port, None, &d3, 1, 5), "the head is D.3");
    // THE REPLAY: D.2's request again, byte for byte.
    let v = op_unattested(port, Some(&signed), &d2_request);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the replay commits: {v}");
    let replayed = acked_addr(&v);
    assert_eq!(replayed, format!("{d1}.1"), "D.1's daughter, never D.4");
    assert!(
        sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some(),
        "the replayed signature verifies: nothing it bound has moved"
    );
    assert_eq!(text_of(port, None, &replayed, 1, 5), "abcxy", "the author's old content, at a second address");
    assert_eq!(image_runs(port, None, &edition, 1, 5), head_image, "the current version is still D.3");
    assert_eq!(
        expect_resp(&doc_metadata(port, None, &replayed), "doc_metadata")["placed"].as_str(),
        Some("5"),
        "the daughter carries the replayed shot's own terms"
    );
}

/// THE FRAME IS CHECKABLE LATER (l6-A4; D25's (c′); fam1-L1): a verifier
/// holding the MEMBER and no request — a mirror, a reader beside the table
/// — composes the shot's signed body byte for byte from what the board
/// serves about the member: its terms off `doc_metadata` (`placed`,
/// `base_extent`), its runs off the member's own arrangement over the first
/// `placed` positions (the image, maximally merged), each classed by its
/// origin — the edition's own trunk BY VALUE, the values read at the member;
/// any other document BY ADDRESS — and `base` off the member's address. Over
/// a shot holding all three run classes, with two I-adjacent windows the
/// placement merged into one: the frame composed at the request (the test
/// signer's, which the daemon's check verified) and the frame composed off
/// the member are one byte string, and the marker's attestation verifies
/// over it under the author's enrolled key.
#[test]
fn a_publish_frame_composed_from_the_member_is_the_frame_composed_from_the_request() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let other = edition_with(port, &signed, "pq");
    let edition = edition_with(port, &signed, "abc");
    let draft = draft_with(port, &signed, "xy");
    // Own runs by reference, two adjacent windows onto `other` (one run at
    // the member), the draft's two re-inserted; the base taken whole.
    let mut runs = shot_runs(port, Some(&signed), &edition, 1, 3);
    runs.push(run(&other, &format!("{other}.0.1.1"), 1));
    runs.push(run(&other, &format!("{other}.0.1.2"), 1));
    runs.extend(shot_runs(port, Some(&signed), &draft, 1, 2));
    let frame = publish_frame(&edition, Some((&edition, 3)), Some(&draft), &runs);
    let parsed: Value = serde_json::from_str(&frame).unwrap();
    let at_request = entry_frame_for(port, &signed, CLAIMANT_PRINCIPAL, &parsed).expect("composable");
    let v = op(port, Some(&signed), &frame);
    let member = acked_addr(&v);
    assert_eq!(member, format!("{edition}.1"));
    let slot = sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().expect("attested");

    // THE LATER VERIFIER, off the member alone.
    let answer = doc_metadata(port, None, &member);
    let meta = expect_resp(&answer, "doc_metadata");
    let placed: u64 = meta["placed"].as_str().expect("placed").parse().unwrap();
    let base_extent: Option<u64> = meta["base_extent"].as_str().map(|s| s.parse().unwrap());
    assert_eq!((placed, base_extent), (7, Some(3)), "{meta}");
    let trunk = trunk_of_str(&member);
    assert_eq!(trunk, edition, "`base` is derived from the member's address: D.1's is the document");
    let mut segments: Vec<SignerSegment> = Vec::new();
    let mut ordinal = 1;
    for (i_start, width) in image_runs(port, None, &member, 1, placed) {
        if trunk_of_str(&origin_of(&i_start)) == trunk {
            segments.extend(values_of(port, None, &member, ordinal, width).into_iter().map(SignerSegment::Value));
        } else {
            segments.push(SignerSegment::Window(addr(&i_start), width));
        }
        ordinal += width;
    }
    assert_eq!(segments.len(), 6, "three values, one merged window, two values");
    assert!(matches!(&segments[3], SignerSegment::Window(w, 2) if *w == addr(&format!("{other}.0.1.1"))));
    let body = entry_body_publish(segments.iter().map(SignerSegment::as_shot), base_extent);
    let board = board_term(port).expect("H.1");
    let account = addr(&account_of(port, &signed, CLAIMANT_PRINCIPAL).expect("the account"));
    let at_member = entry_frame(ALG_MLDSA65_ED25519, board, &account, &addr(&trunk), &body);
    assert_eq!(at_member, at_request, "one preimage, composed from the request and from the member");
    let (_, seed) = signer_of(&signed).expect("a signed session");
    let key = HybridSigner::from_seed(FIXTURE_TAG, &seed).unwrap();
    assert_eq!(
        skep_signature::verify(slot.sig_alg(), key.public_key(), &at_member, slot.sig()),
        Ok(()),
        "the marker's attestation verifies over the member-composed frame"
    );
}

/// `doc_metadata` SERVES THE TERMS (d25-S1, the member read): asked of a
/// version member the shot minted, `placed` is Σ width of the shot's runs
/// and `base_extent` the extent its copy took — `null` in the birth shape,
/// the base absent — beside the document's `birth`/`birth_extent`; asked of
/// the trunk, both are `null`; a birth version an owned `version` minted
/// carries none.
#[test]
fn doc_metadata_serves_a_shot_minted_members_terms_and_null_where_none() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let terms = |doc: &str| -> (Option<String>, Option<String>) {
        let answer = doc_metadata(port, None, doc);
        let meta = expect_resp(&answer, "doc_metadata");
        (
            meta["placed"].as_str().map(str::to_string),
            meta["base_extent"].as_str().map(str::to_string),
        )
    };
    // A birth version by `version`: the memo notes it, no shot record does.
    let edition = edition_with(port, &signed, "abc");
    let by_version = acked_addr(&version_of(port, &signed, &edition, None));
    assert_eq!(by_version, format!("{edition}.1"));
    assert_eq!(terms(&by_version), (None, None), "no shot minted it");
    // A shot over it: D.2 with the three by reference and a draft's two.
    let draft = draft_with(port, &signed, "xy");
    let mut runs = shot_runs(port, Some(&signed), &by_version, 1, 3);
    runs.extend(shot_runs(port, Some(&signed), &draft, 1, 2));
    let d2 = shot(port, &signed, &edition, Some((&by_version, 3)), Some(&draft), &runs);
    assert_eq!(terms(&d2), (Some("5".into()), Some("3".into())), "the shot's two terms");
    assert_eq!(terms(&edition), (None, None), "the trunk answers the address named: none");
    let answer = doc_metadata(port, None, &d2);
    let meta = expect_resp(&answer, "doc_metadata");
    assert_eq!(meta["birth"].as_str(), Some(by_version.as_str()), "the document's birth beside them");
    // The birth shape: a shot with no base into a memberless edition.
    let second = edition_with(port, &signed, "de");
    let d1 = shot(port, &signed, &second, None, None, &shot_runs(port, Some(&signed), &second, 1, 2));
    assert_eq!(d1, format!("{second}.1"));
    assert_eq!(terms(&d1), (Some("2".into()), None), "the count, and the birth bit as null");
    let answer = doc_metadata(port, None, &d1);
    let meta = expect_resp(&answer, "doc_metadata");
    assert_eq!(meta["birth_extent"].as_str(), Some("2"), "there the count is the birth extent");
}

// ── the frames ──────────────────────────────────────────────────────────────
//
// TWINS: `addr` and `fixed_frames` have copies in skep-signature's
// `tests/it/golden.rs`, whose goldens sign these frames; the test below pins
// their bytes here, so a copy that drifts from its twin fails a golden there.

fn addr(s: &str) -> skep_address::Address {
    let comps: Vec<skep_address::Nat> =
        s.split('.').map(|c| skep_address::Nat::from(c.parse::<u64>().unwrap())).collect();
    skep_address::validate(skep_address::Tumbler::new(comps).unwrap()).unwrap()
}

/// The four fixed instances every golden signs: the frames of an `insert`
/// (undeclared, two values), a `make_link` (three address-form slots), a
/// `publish` (three values copied in, one window of two positions onto
/// another document, the base taken at three — the address form, l6-A4)
/// and a `record` (an enrol's kind: its type slot, one subject, neither
/// optional row named, a short canonical body — the frame merge, fm-I) on a
/// board whose `H.1` pair is `(12, 0xAB…)`, by account `1.0.1`.
fn fixed_frames(alg: &str) -> [(&'static str, Vec<u8>); 4] {
    let (account, doc) = (addr("1.0.1"), addr("1.0.1.0.1"));
    let insert = entry_body_insert(None, [&b"a"[..], &b"b"[..]]);
    let ty = [addr("1.1.0.1.0.1.0.3.90")];
    let from = [addr("1.0.1")];
    let to: [skep_address::Address; 0] = [];
    let link = entry_body_make_link(LinkSlots {
        from: EntrySlot::Addrs(&from),
        to: EntrySlot::Addrs(&to),
        ty: EntrySlot::Addrs(&ty),
    });
    let window = addr("1.0.1.0.2.0.1.1");
    let publish = entry_body_publish(
        [
            ShotSegment::Value(b"x"),
            ShotSegment::Value(b"y"),
            ShotSegment::Value(b"z"),
            ShotSegment::Window { start: &window, width: 2 },
        ],
        Some(3),
    );
    let subject = [addr("1.0.2")];
    let record = entry_body_record(
        &addr("1.1.0.1.0.1.0.3.1"),
        &subject,
        None,
        None,
        br#"{"type":"skep-enroll"}"#,
    );
    let board = BoardTerm { log_position: 12, chain: [0xAB; 32] };
    [insert, link, publish, record]
        .map(|body| (body.op(), entry_frame(alg, board, &account, &doc, &body)))
}

/// THE FRAME REGRESSION per grammar: the bytes, spelled out by hand once —
/// the D24 pins as the seam build made them; the `make_link` body's
/// `replaces` row since the replay fix moved it in place under
/// `skep-entry-v1` (l6-A3): an EMPTY group where the member is absent, the
/// member's address-form slot row, delimited, where it is present; the
/// `publish` body since the re-pin of 2026-09-29 (V, l6-A4, D25's (c′)):
/// the count, the segments in the address form, the base-extent group; and
/// the `record` body since the frame merge (fm-I): five rows under a token
/// no wire op spells.
#[test]
fn the_entry_frames_bytes_per_op_are_pinned() {
    let [(_, insert), (_, link), (_, publish), (_, record)] = fixed_frames(ALG_MLDSA65_ED25519);
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
    // make_link: op, then body = ty slot ‖ from slot ‖ to slot ‖ the
    // `replaces` row — absent here, so the EMPTY group `be32(0)`.
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
        &[slot(&[b"1.1.0.1.0.1.0.3.90"]), slot(&[b"1.0.1"]), slot(&[]), vec![0, 0, 0, 0]].concat(),
    ));
    assert_eq!(link, want, "make_link");
    // …and a re-share: the same slots with the member PRESENT, naming the
    // revocation at `1.0.1.0.1.0.2.9` — its slot row, delimited as one group.
    let (ty, from, to) = ([addr("1.1.0.1.0.1.0.3.90")], [addr("1.0.1")], []);
    let re_share = entry_body_make_link_replacing(
        LinkSlots {
            from: EntrySlot::Addrs(&from),
            to: EntrySlot::Addrs(&to),
            ty: EntrySlot::Addrs(&ty),
        },
        &addr("1.0.1.0.1.0.2.9"),
    );
    let frame = entry_frame(
        ALG_MLDSA65_ED25519,
        BoardTerm { log_position: 12, chain: [0xAB; 32] },
        &addr("1.0.1"),
        &addr("1.0.1.0.1"),
        &re_share,
    );
    let mut want = prefix.clone();
    want.extend(member(b"make_link"));
    want.extend(member(
        &[
            slot(&[b"1.1.0.1.0.1.0.3.90"]),
            slot(&[b"1.0.1"]),
            slot(&[]),
            member(&slot(&[b"1.0.1.0.1.0.2.9"])),
        ]
        .concat(),
    ));
    assert_eq!(frame, want, "make_link with its replaces member");
    // publish: op, then body = be64(5) — five positions placed — ‖ the
    // value stretch: its class byte 0x02, be64(3), x, y, z ‖ the window:
    // its class byte 0x01, the start's spelling delimited, be64(2) ‖ the
    // base-extent group: be32(8) ‖ be64(3).
    let mut want = prefix.clone();
    want.extend(member(b"publish"));
    want.extend(member(
        &[
            &[0u8, 0, 0, 0, 0, 0, 0, 5][..],
            &[0x02][..],
            &[0, 0, 0, 0, 0, 0, 0, 3][..],
            &[0, 0, 0, 1, b'x'][..],
            &[0, 0, 0, 1, b'y'][..],
            &[0, 0, 0, 1, b'z'][..],
            &[0x01][..],
            &member(b"1.0.1.0.2.0.1.1")[..],
            &[0, 0, 0, 0, 0, 0, 0, 2][..],
            &[0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3][..],
        ]
        .concat(),
    ));
    assert_eq!(publish, want, "publish");
    // record: op `record` — no wire op spells it — then body = the type
    // slot row ‖ the `to` slot row ‖ the `replaces` row EMPTY ‖ the lineage
    // row EMPTY ‖ the canonical bytes, delimited.
    let mut want = prefix;
    want.extend(member(b"record"));
    want.extend(member(
        &[
            slot(&[b"1.1.0.1.0.1.0.3.1"]),
            slot(&[b"1.0.2"]),
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 0],
            member(br#"{"type":"skep-enroll"}"#),
        ]
        .concat(),
    ));
    assert_eq!(record, want, "record");
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
