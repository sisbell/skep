//! SIGNED OPS — THE SEAM (the seam build 2026-09-25) AND THE WIDENING: one
//! signed write, end to end, for each of the ten op kinds of the checked set
//! — the three mints, `insert`, `publish`, `make_link`, `emit`, `nullify`,
//! `assert_sup`, `edit_link` — under the two tags: the hybrid key enrolled,
//! the entry frame composed and signed by the test signer, the `attest`
//! member on the wire, the claimed-board check before the transaction, the
//! attestation into the commit marker's reserved slot and read back off the
//! kernel; and for every cell, the frame composed from the REQUEST at the
//! check equal to the frame a verifier composes from the STORED result —
//! the minted document's owner, the stored link's slots off `read_link` and
//! `find_links`, the member's runs and terms — the slot row signing the
//! endset AS STORED (SO-I6 (h); the design record §7.6's vector (vii)).
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
use skep_address::Span;
use skep_febe::Codec;
use skep_identity::{
    canonical_record, encode_enroll, encode_retire, entry_body_assert_sup, entry_body_edit_link,
    entry_body_emit, entry_body_empty, entry_body_insert, entry_body_make_link,
    entry_body_make_link_replacing, entry_body_nullify, entry_body_publish, entry_body_record,
    entry_frame, parse_record_value, unit_span as unit, BoardTerm, ContentFreeOp, DocTerm,
    Enrollment, EntryBody, EntrySlot, Fingerprint, LinkSlots, PublicKey, RecordRows, RecordValue,
    ShotBase, ShotSegmentPiece, SigAlgRow, ALG_FNDSA512_PREVIEW_ED25519, ALG_MLDSA65_ED25519,
};
use skep_signature::HybridSigner;
use skepd::{JsonCodec, Seq};
use tempfile::tempdir;

/// A refusal's `(code:detail, disposition)`.
fn refusal(v: &Value) -> (String, String) {
    (verdict(v), v["disposition"].as_str().unwrap_or("?").to_string())
}

/// A V-spec array over `doc`'s content ordinals `from ..+width` — the
/// resolve form of a `make_link` slot and of an `edit_link` successor's
/// `from`/`to`.
fn vspecs(doc: &str, from: u64, width: u64) -> String {
    format!(r#"[{{"source":"{doc}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]"#)
}

/// A ghost type under `home` — the address form, one name.
fn ghost_ty(home: &str, n: u64) -> String {
    format!(r#"{{"addrs":["{home}.0.3.6.{n}"]}}"#)
}

/// A stored span as `read_link` serves one — `{"start", "width"}`.
fn span_of(v: &Value) -> Span {
    let tum = |s: &str| {
        skep_address::Tumbler::new(s.split('.').map(|c| skep_address::Nat::from(c.parse::<u64>().unwrap()))).unwrap()
    };
    Span::new(tum(v["start"].as_str().expect("start")), tum(v["width"].as_str().expect("width")))
        .expect("a served span is well-formed")
}

/// THE STORED LINK, as `read_link` serves it: its three slots' spans,
/// verbatim and in stored order, as `(from, to, ty)`.
fn stored_slots(port: u16, link: &str) -> (Vec<Span>, Vec<Span>, Vec<Span>) {
    let value = read_link(port, None, link);
    assert!(!value.is_null(), "{link} is a link");
    let slot = |i: usize| -> Vec<Span> { value["slots"][i].as_array().expect("a slot").iter().map(span_of).collect() };
    (slot(0), slot(1), slot(2))
}

/// The home of a link at `<home>.0.2.<n>`.
fn home_of(link: &str) -> String {
    let parts: Vec<&str> = link.split('.').collect();
    parts[..parts.len() - 3].join(".")
}

/// THE VERIFIER'S FRAME for a link write, from the stored link alone: its
/// home off its own address, the account by ω over the home (the writer owns
/// what it deposits into), the slots off `read_link`, the body under the
/// row's op token, `H.1`'s pair — nothing from the request.
fn frame_from_stored_link(port: u16, op: &str, link: &str) -> Vec<u8> {
    let (from, to, ty) = stored_slots(port, link);
    let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
    let body = match op {
        "make_link" => entry_body_make_link(slots),
        "emit" => entry_body_emit(slots),
        "nullify" => entry_body_nullify(slots),
        "assert_sup" => entry_body_assert_sup(slots),
        other => panic!("{other} deposits no one link"),
    };
    let home = home_of(link);
    let (account, _) = effective_owner(port, None, &home).expect("the home's owner");
    let board = board_term(port).expect("H.1");
    entry_frame(ALG_MLDSA65_ED25519, board, &addr(&account), DocTerm::One(&addr(&home)), &body)
}

/// Whether `sig` — a marker's blob — verifies over `frame` under the
/// claimant's device key, which signs every attested write of the suite.
fn verifies(frame: &[u8], sig: &[u8]) -> bool {
    skep_signature::verify(FIXTURE_TAG, &public_key_of(&device_key()), frame, sig).is_ok()
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
    let ty = [unit(&addr(T_GRANT))];
    let from = [unit(&addr(CLAIMANT_ACCOUNT))];
    let body = entry_body_make_link(LinkSlots {
        from: EntrySlot(&from),
        to: EntrySlot(&[]),
        ty: EntrySlot(&ty),
    });
    entry_frame(alg, board, &addr(CLAIMANT_ACCOUNT), DocTerm::One(&addr(CLAIMANT_DOC1)), &body)
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
    let v = op_as_written(port, None, &retrieve_frame(member, 1, 1));
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
    let v = op_as_written(port, Some(&claimant), &frame.to_string());
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
/// unknown `alg` token → unparseable; the member on an op outside the ten
/// (a `delete`) → unparseable (the unknown-field rule); and a signed write
/// OUTSIDE the publish class carrying an `attest` → admitted with the member
/// dropped.
#[test]
fn above_the_claim_the_check_refuses_admits_and_names_each_cause() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let grant = || typed_link_frame(CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &["1.0.2"], T_GRANT);

    // Absent: refused, reorder.
    let v = op_as_written(port, Some(&signed), &grant());
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
    let v = op_as_written(port, Some(&signed), &attached.to_string());
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
    let v = op_as_written(port, Some(&signed), &tampered.to_string());
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
    let v = op_as_written(port, Some(&signed), &tampered.to_string());
    assert_eq!(verdict(&v), "credential_refused:attestation_invalid:signature");
    // The wrong width: malformed, permanent.
    let mut short = attached.clone();
    short["attest"]["sig"] = Value::String(sig_hex[2..].to_string());
    let v = op_as_written(port, Some(&signed), &short.to_string());
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
    let v = op_as_written(port, Some(&signed), &foreign.to_string());
    assert_eq!(verdict(&v), "credential_refused:attestation_invalid:signature");
    // An unknown token: the grammar refuses it.
    let mut unknown = attached.clone();
    unknown["attest"]["alg"] = Value::String("rsa".into());
    let v = op_as_written(port, Some(&signed), &unknown.to_string());
    assert_eq!(v["op"].as_str(), Some("unparseable"), "{v}");
    assert!(v["detail"].as_str().unwrap().contains("unknown algorithm token"), "{v}");
    // An empty blob: one spelling of absent.
    let mut empty = attached.clone();
    empty["attest"]["sig"] = Value::String(String::new());
    let v = op_as_written(port, Some(&signed), &empty.to_string());
    assert_eq!(v["op"].as_str(), Some("unparseable"), "{v}");
    // The member on an op outside the ten: unknown field.
    let v = op_as_written(
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
    let v = op_as_written(port, Some(&signed), &frame.to_string());
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
    // The genesis record signed for its deposit by the registrar's key (2a).
    let atom = signed_atom(port, &registrar, CLAIMANT_DOC1, T_ENROLL, &[&agent], &json_atom(&encode_enroll(&entries)));
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
    let v = op_as_written(port, Some(&agent_signed), &typed_link_frame(&home, &[&agent], &["1.0.2"], T_GRANT));
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
    // The preview key joins the claimant's set — the fixtures allow it; the
    // record signed for its deposit by the device key (2a).
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let entries = vec![Enrollment::new(tag3.public_key().clone(), false, None).unwrap()];
    let atom = signed_atom(
        port,
        &signed,
        CLAIMANT_DOC1,
        T_ENROLL,
        &[CLAIMANT_ACCOUNT],
        &json_atom(&encode_enroll(&entries)),
    );
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
    let v = op_as_written(port, Some(&as_tag3), &claimant_grant_attested(ALG_FNDSA512_PREVIEW_ED25519, &sig));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "a tag-3 attestation is admitted: {v}");
    let slot = sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().expect("the slot is filled");
    assert_eq!(slot.sig_alg(), skep_signature::TAG_FNDSA512_PREVIEW_ED25519, "the slot carries tag 3");
    assert_eq!(slot.sig(), &sig[..], "and the blob attached, whole");
}

/// THE TEN OPS END TO END (SO-I4: every publishing act above the claim is
/// signed): each publish-class kind, from the claimant's signed session into
/// its published world — a `create_new_document` born published (not the
/// account's first), a `fork` born published, a `version` of the published
/// edition, an `emit` of the retired class, a `nullify`, an `assert_sup` and
/// an `edit_link` over ghost links in doc 1 — answers `attestation_required`
/// unattested and commits attested with its own slot holding the attached
/// blob; `make_link` (a grant) and `publish` (a shot) as before; `insert` —
/// a DECLARED deposit under a credential kind whose atom is NO record of
/// that kind, prose under `T_enroll` — takes the check like any insert since
/// round 7 (as7-E1 ARM (a), s2's fact's third case): unattested it answers
/// `attestation_required`, attested it commits SIGNED with its slot filled
/// (the one exempt insert is a signed record into a doc 1,
/// `the_record_deposit_exemption_reaches_a_signed_record_in_a_doc_1_alone`);
/// and an UNDECLARED insert into the published home passes the check with
/// a valid attest and meets the store's `published_target`, which is the
/// order the design states: the check before the transaction, the store's
/// gates inside it.
#[test]
fn the_ten_ops_commit_attested_where_the_check_demands_it() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    // Unattested, the check's (1); attested, an ack whose own slot holds the
    // tag-1 blob and whose predecessor's stays empty.
    let demanded = |frame: &str, what: &str| -> Value {
        let v = op_as_written(port, Some(&signed), frame);
        assert_eq!(verdict(&v), "credential_refused:attestation_required", "{what}, unattested: {v}");
        let v = op(port, Some(&signed), frame);
        assert!(
            matches!(v["resp"].as_str(), Some("ack_addr" | "ack_edit")),
            "{what}, attested: {v}"
        );
        let at = acked_at(&v);
        let slot = sd.daemon().attestation_at(Seq(at)).unwrap().unwrap_or_else(|| panic!("{what}: its slot is filled"));
        assert_eq!(slot.sig().len(), 3373, "{what}: tag 1's blob");
        v
    };

    // The three mints: a second document born published, a published fork,
    // a version of the published edition — each the EMPTY body over the
    // parent account.
    let edition = acked_addr(&demanded(&create_frame(CLAIMANT_ACCOUNT, Some(true)), "create_new_document"));
    demanded(&fork_frame(Some(true)), "fork");
    let member = acked_addr(&demanded(&version_frame(&edition, None), "version"));
    assert_eq!(member, format!("{edition}.1"), "the version is the edition's first member");

    // The other link writes, over ghost links in the published doc 1.
    let (l1, l2, l3) = (
        ghost_link(port, &signed, CLAIMANT_DOC1, 11),
        ghost_link(port, &signed, CLAIMANT_DOC1, 12),
        ghost_link(port, &signed, CLAIMANT_DOC1, 13),
    );
    demanded(&emit_frame(CLAIMANT_DOC1), "emit");
    demanded(&assert_sup_frame(CLAIMANT_DOC1, &l1, &l2), "assert_sup");
    demanded(&edit_link_frame(&l3, CLAIMANT_DOC1, CLAIMANT_DOC1, "[]", &ghost_ty(CLAIMANT_DOC1, 14)), "edit_link");
    demanded(&nullify_frame(CLAIMANT_DOC1, &l1), "nullify");

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
    let v = op_as_written(port, Some(&signed), &frame);
    assert_eq!(verdict(&v), "credential_refused:attestation_required");

    // insert: prose declared under a record kind is NO record of that kind,
    // so the narrowed exemption does not reach it (as7-E1 (a)) — unattested,
    // the check's (1); attested, it commits SIGNED, its slot filled.
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let v = op_as_written(port, Some(&signed), &insert_frame(CLAIMANT_DOC1, ordinal, "r", true));
    assert_eq!(verdict(&v), "credential_refused:attestation_required", "prose under a record kind, unattested: {v}");
    let v = op(port, Some(&signed), &insert_frame(CLAIMANT_DOC1, ordinal, "s", true));
    let dep_at = acked_at(&v);
    assert!(
        sd.daemon().attestation_at(Seq(dep_at)).unwrap().is_some(),
        "prose under a record kind, attested: committed SIGNED, the slot filled"
    );
    // An UNDECLARED insert into the published home: the check demands and
    // verifies, then the store refuses — the check's order.
    let v = op_as_written(port, Some(&signed), &insert_frame(CLAIMANT_DOC1, ordinal, "t", false));
    assert_eq!(verdict(&v), "credential_refused:attestation_required");
    let v = op(port, Some(&signed), &insert_frame(CLAIMANT_DOC1, ordinal, "t", false));
    assert_eq!(verdict(&v), "published_target", "the check passed; the store's own refusal");
}

/// THE MINTS' FRAMES ARE CHECKABLE FROM THE MINTED DOCUMENT (SO-I6 (e); the
/// design record §2.5's cell for the content-free ops): a verifier holding
/// the minted document and no request — its address off the feed's `docs`,
/// its parent account by ω, `effective_owner`, over it — composes the EMPTY
/// body over that account under the row's op token, and the frame it
/// composes is byte for byte the frame the signer composed from the request;
/// the marker's attestation verifies over it under the author's enrolled
/// key. For all three: a `create_new_document` born published into an
/// account that already holds documents, a published `fork`, a `version` of
/// the edition (the member's ω is the account — never the trunk of `d_src`,
/// d24-3).
#[test]
fn a_mints_frame_composed_from_the_minted_document_is_the_frame_composed_from_the_request() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let edition = published_edition(port, &signed);
    for (frame, op_token) in [
        (create_frame(CLAIMANT_ACCOUNT, Some(true)), ContentFreeOp::CreateNewDocument),
        (fork_frame(Some(true)), ContentFreeOp::Fork),
        (version_frame(&edition, None), ContentFreeOp::Version),
    ] {
        let parsed: Value = serde_json::from_str(&frame).unwrap();
        let frame_from_request = entry_frame_for(port, &signed, CLAIMANT_PRINCIPAL, &parsed).expect("composable");
        let v = op(port, Some(&signed), &frame);
        let minted = acked_addr(&v);
        let slot = sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().expect("attested");
        // THE LATER VERIFIER: the parent account by ω over the minted
        // document, the EMPTY body under the op's token.
        let (account, _) = effective_owner(port, None, &minted).expect("the minted document's owner");
        assert_eq!(account, CLAIMANT_ACCOUNT, "{op_token:?}: ω over the minted document is the parent account");
        let body = entry_body_empty(op_token);
        assert!(body.as_bytes().is_empty(), "the EMPTY body");
        let board = board_term(port).expect("H.1");
        let frame_from_store =
            entry_frame(ALG_MLDSA65_ED25519, board, &addr(&account), DocTerm::One(&addr(&account)), &body);
        assert_eq!(frame_from_store, frame_from_request, "{op_token:?}: one preimage, from the request and from the store");
        assert!(verifies(&frame_from_store, slot.sig()), "{op_token:?}: the marker's attestation verifies over it");
    }
}

/// THE LINK WRITES' FRAMES ARE CHECKABLE FROM THE STORED LINK (SO-I6 (h);
/// the design record §7.6's vector (vii), MET): a verifier holding the
/// stored link alone — found by `find_links` and read by `read_link`, its
/// home off its own address and the account by ω — composes each slot row
/// from the endset the store serves, and the frame it composes is byte for
/// byte the frame the signer composed from the request, the marker's
/// attestation verifying over it. Four cells: the any-principal GRANT, whose
/// `to` is EMPTY (`0x03 ‖ be64(0)`); a `make_link` whose `from` was SENT IN
/// THE RESOLVE FORM over a draft's two positions — the row the stored
/// I-extent's, the signer having resolved it through `image` before signing
/// — found by `find_links_v` over the draft; an `emit` of the retired class
/// with its `to` EMPTY; a `nullify` and an `assert_sup` over ghost links,
/// each verified end to end over the wire — the stored tuple's type slot
/// the class's reserved ghost address, its one unit span.
#[test]
fn a_link_writes_frame_composed_from_the_stored_link_is_the_frame_composed_from_the_request() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let draft = draft_with(port, &signed, "abcd");
    let (l1, l2) = (ghost_link(port, &signed, CLAIMANT_DOC1, 21), ghost_link(port, &signed, CLAIMANT_DOC1, 22));
    let check = |frame: &str, op_token: &str, find: &dyn Fn(&Value) -> String| {
        let parsed: Value = serde_json::from_str(frame).unwrap();
        let frame_from_request = entry_frame_for(port, &signed, CLAIMANT_PRINCIPAL, &parsed).expect("composable");
        let v = op(port, Some(&signed), frame);
        let slot = sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().expect("attested");
        let link = find(&v);
        let frame_from_store = frame_from_stored_link(port, op_token, &link);
        assert_eq!(frame_from_store, frame_from_request, "{op_token}: one preimage, from the request and from the stored link {link}");
        assert!(verifies(&frame_from_store, slot.sig()), "{op_token}: the marker's attestation verifies over the stored-composed frame");
        link
    };
    let acked = |v: &Value| acked_addr(v);
    // The any-principal grant: `to` EMPTY.
    let grant = check(&typed_link_frame(CLAIMANT_DOC1, &[&draft], &[], T_GRANT), "make_link", &acked);
    let (_, to, _) = stored_slots(port, &grant);
    assert!(to.is_empty(), "the grant's to slot is EMPTY as stored");
    // The resolve form: `from` over the draft's first two positions, found
    // by `find_links` — the four-set query keyed on the link's type, since a
    // query by the draft's positions alone also matches the account-wide
    // slots of the ceremony's links and the grant's — the stored extent,
    // never the V-spec.
    let resolved = check(
        &link_frame(CLAIMANT_DOC1, &vspecs(&draft, 1, 2), r#"{"addrs":[]}"#, &ghost_ty(CLAIMANT_DOC1, 23)),
        "make_link",
        &|_| {
            let found = addrs_of(&op(
                port,
                Some(&signed),
                &ftt_frame("find_links_ftt", r#""any""#, r#""any""#, r#""any""#, &unit_span(&format!("{CLAIMANT_DOC1}.0.3.6.23"))),
            ));
            assert_eq!(found.len(), 1, "one link of the ghost type: {found:?}");
            assert!(find_links_v(port, Some(&signed), &draft, 1, 2).contains(&found[0]), "found by the draft's positions too");
            found[0].clone()
        },
    );
    let (from, _, _) = stored_slots(port, &resolved);
    assert_eq!(from, vec![span_of(&json!({"start": format!("{draft}.0.1.1"), "width": "0.0.0.0.0.0.0.2"}))], "the stored I-extent");
    // The emit: the retired class, `to` EMPTY.
    check(&emit_frame(CLAIMANT_DOC1), "emit", &acked);
    // The assert_sup and the nullify, over the ghost links.
    check(&assert_sup_frame(CLAIMANT_DOC1, &l1, &l2), "assert_sup", &acked);
    let retraction = check(&nullify_frame(CLAIMANT_DOC1, &l2), "nullify", &acked);
    let (from, to, ty) = stored_slots(port, &retraction);
    assert_eq!(
        (from, to, ty),
        (vec![unit(&addr(CLAIMANT_DOC1))], vec![unit(&addr(&l2))], vec![unit(&addr(T_RETRACTION))]),
        "the stored retraction: the home's, the target's and the class's unit spans"
    );
}

/// AN EDIT_LINK'S FRAME IS CHECKABLE FROM ITS TWO STORED LINKS (SO-I6 (h);
/// D24's cell (7), d24-1 and d24-6): a verifier holding the successor off
/// `read_link` at `d_s` and the claim off `read_link` at `d_a` composes the
/// successor's rows AS STORED — its `to` sent as a V-SPEC over the draft and
/// its type `{"resolve": …}` over a third position, each the stored I-extent
/// — then the claim's `from`, the original's unit span, under the pair's
/// row `(d_s, d_a)` read off the two links' own addresses, and the frame is
/// byte for byte the signer's, the marker's attestation verifying over it.
/// The two homes differ, so the pair's order is watched.
#[test]
fn an_edit_links_frame_composed_from_its_two_stored_links_is_the_frame_composed_from_the_request() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let edition = published_edition(port, &signed);
    let draft = draft_with(port, &signed, "abcd");
    let original = ghost_link(port, &signed, CLAIMANT_DOC1, 31);
    let frame = edit_link_frame(&original, &edition, CLAIMANT_DOC1, &vspecs(&draft, 1, 2), &resolve_slot(&vspecs(&draft, 3, 1)));
    let parsed: Value = serde_json::from_str(&frame).unwrap();
    let frame_from_request = entry_frame_for(port, &signed, CLAIMANT_PRINCIPAL, &parsed).expect("composable");
    let v = op(port, Some(&signed), &frame);
    let edit = expect_resp(&v, "ack_edit");
    let (successor, claim) = (edit["successor"].as_str().unwrap().to_string(), edit["claim"].as_str().unwrap().to_string());
    let slot = sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().expect("attested");
    // THE LATER VERIFIER: the successor's slots and the claim's `from`.
    let (from, to, ty) = stored_slots(port, &successor);
    assert!(from.is_empty());
    assert_eq!(to, vec![span_of(&json!({"start": format!("{draft}.0.1.1"), "width": "0.0.0.0.0.0.0.2"}))]);
    assert_eq!(ty, vec![span_of(&json!({"start": format!("{draft}.0.1.3"), "width": "0.0.0.0.0.0.0.1"}))]);
    let (claim_from, claim_to, claim_ty) = stored_slots(port, &claim);
    assert_eq!(claim_from, vec![unit(&addr(&original))], "the claim's from: the original's unit span");
    assert_eq!(claim_to, vec![unit(&addr(&successor))], "the claim's to: the successor, minted inside the transaction — no row");
    assert_eq!(claim_ty, vec![unit(&addr(T_SUPERSEDES))], "the claim's type: the supersedes constant — no row");
    let (d_s, d_a) = (home_of(&successor), home_of(&claim));
    assert_eq!((d_s.as_str(), d_a.as_str()), (edition.as_str(), CLAIMANT_DOC1), "the pair, off the two links' addresses");
    let body = entry_body_edit_link(
        LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) },
        &claim_from[0],
    );
    let (account, _) = effective_owner(port, None, &d_s).expect("the owner");
    let board = board_term(port).expect("H.1");
    let frame_from_store =
        entry_frame(ALG_MLDSA65_ED25519, board, &addr(&account), DocTerm::Pair { d_s: &addr(&d_s), d_a: &addr(&d_a) }, &body);
    assert_eq!(frame_from_store, frame_from_request, "one preimage, from the request and from the two stored links");
    assert!(verifies(&frame_from_store, slot.sig()));
    // The pair's order is signed: the same body under the homes swapped is
    // another preimage, which the blob does not verify over.
    let swapped =
        entry_frame(ALG_MLDSA65_ED25519, board, &addr(&account), DocTerm::Pair { d_s: &addr(&d_a), d_a: &addr(&d_s) }, &body);
    assert!(!verifies(&swapped, slot.sig()), "the homes swapped: another preimage");
}

/// A STALE RESOLUTION IS REFUSED, THE RE-SIGNED FRAME ADMITTED (SO-I6 (h);
/// the design record §2.5's slot row, d24-5: the daemon composes the row
/// from the endset its own transaction deposits, and "the daemon cannot tell
/// a stale resolution from a forgery"): the signer resolves a `make_link`'s
/// V-spec over a draft's first position — the draft's first I-address —
/// and signs; the draft's owner then PREPENDS a byte, so the same V-position
/// now names a later I-address; the signed request, posted as it was, is
/// refused `attestation_invalid:signature`, PERMANENT, nothing committed;
/// re-composed and re-signed over the base as it now stands, it is admitted,
/// and the stored slot is the new extent.
#[test]
fn a_make_link_signed_over_a_stale_resolution_is_refused_and_the_re_signed_frame_admitted() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let draft = draft_with(port, &signed, "ab");
    let frame = link_frame(CLAIMANT_DOC1, &vspecs(&draft, 1, 1), r#"{"addrs":[]}"#, &ghost_ty(CLAIMANT_DOC1, 41));
    let stale = attach_attest(port, &signed, &frame);
    assert!(stale.contains("\"attest\""), "signed over the draft's first I-address");
    // The base moves: a prepend, so V-position 1 is a fresh I-address.
    expect_resp(&insert_text(port, &signed, &draft, 1, "z"), "ack_addr");
    let before = head_position(port);
    let v = op_as_written(port, Some(&signed), &stale);
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:signature".to_string(), "permanent".to_string()),
        "the row signed is not the row the transaction would deposit: {v}"
    );
    assert_eq!(head_position(port), before, "nothing committed");
    // Re-composed over the moved base: admitted, the stored slot the new extent.
    let v = op(port, Some(&signed), &frame);
    let link = acked_addr(&v);
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some(), "attested");
    let (from, _, _) = stored_slots(port, &link);
    assert_eq!(from, vec![span_of(&json!({"start": format!("{draft}.0.1.3"), "width": "0.0.0.0.0.0.0.1"}))], "the prepended byte's I-address");
}

/// THE PASS-THROUGH'S PAIRING (reg-S2; SO-I4 (b), SO-I9): every fault the
/// check passes through UNATTESTED rests on the premise that the store or
/// the door then refuses the write, so each is paired here with the refusal
/// it defers to — the three link-write faults the widening adds, each sent
/// with an attestation that verifies over no frame, so the answer cannot be
/// a signature's, and unattested first, where (1) speaks ahead of every
/// composition: a `make_link` whose `to` RESOLVES a stranger's private draft
/// → the door's `withheld` naming it (`UnreadableSlotSource`); an
/// `edit_link` whose successor `to` names the same draft → the same; an
/// `edit_link` whose successor names an UNREGISTERED source →
/// `source_not_registered`, and one whose spec is ILL-FORMED (a link-subspace
/// span) → `ill_formed_spec` (`SuccessorRefused`); a `make_link` whose
/// `from` is 4,096 V-specs — the most the wire admits — over a draft of
/// sixty-five runs, which command more run-list steps than M7's work
/// budget admits → `slot_too_large` (`SlotTooLarge`; the span budget is
/// unreachable through the wire, whose list cap is M7's span cap). The three
/// `publish` faults are paired by their own cells: `dangling_source`
/// (`MissingValue`; `publish.rs`), `base_extent_too_large` /
/// `dangling_source` (`Unspellable`;
/// `a_term_past_the_frames_eight_bytes_passes_unattested_to_the_stores_refusal`)
/// and `too_many_values` (`PastReinsertBudget`;
/// `a_shot_past_the_stores_re_insert_budget_passes_unattested_to_its_refusal`).
/// Nothing commits in any cell.
#[test]
fn each_pass_through_of_the_composer_is_paired_with_the_refusal_it_defers_to() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let stranger = seat_stranger(port, 981);
    // The stranger's own private draft, holding two bytes.
    let private = create_doc(port, &stranger.session, &stranger.account);
    expect_resp(&insert_text(port, &stranger.session, &private, 1, "pq"), "ack_addr");
    let original = ghost_link(port, &signed, CLAIMANT_DOC1, 51);
    // A draft of sixty-five runs: sixty-four prepends, each a fresh
    // I-address placed ahead of the rest, so no run merges.
    let fragmented = draft_with(port, &signed, "ab");
    for _ in 0..64 {
        expect_resp(&insert_text(port, &signed, &fragmented, 1, "x"), "ack_addr");
    }
    let required = ("credential_refused:attestation_required".to_string(), "reorder".to_string());
    let before = head_position(port);
    let paired = |frame: &str, code: &str, disposition: &str, why: &str| {
        let v = op_as_written(port, Some(&signed), frame);
        assert_eq!(refusal(&v), required, "{why}, unattested: (1) first: {v}");
        let v = op_as_written(port, Some(&signed), &with_unverifiable_attest(frame));
        assert_eq!(refusal(&v), (code.to_string(), disposition.to_string()), "{why}: passed through, whatever is attached: {v}");
        v
    };
    // An unreadable slot source: the door's `withheld`, naming the draft.
    let v = paired(
        &link_frame(CLAIMANT_DOC1, r#"{"addrs":[]}"#, &vspecs(&private, 1, 1), &ghost_ty(CLAIMANT_DOC1, 52)),
        "withheld",
        "reorder",
        "a make_link resolving a stranger's draft",
    );
    assert_eq!(v["site"]["addr"].as_str(), Some(private.as_str()), "the door names the source: {v}");
    let v = paired(
        &edit_link_frame(&original, CLAIMANT_DOC1, CLAIMANT_DOC1, &vspecs(&private, 1, 1), &ghost_ty(CLAIMANT_DOC1, 53)),
        "withheld",
        "reorder",
        "an edit_link whose successor resolves a stranger's draft",
    );
    assert_eq!(v["site"]["addr"].as_str(), Some(private.as_str()), "{v}");
    // A successor M10's own build refuses.
    paired(
        &edit_link_frame(&original, CLAIMANT_DOC1, CLAIMANT_DOC1, &vspecs("1.0.1.0.99", 1, 1), &ghost_ty(CLAIMANT_DOC1, 54)),
        "source_not_registered",
        "reorder",
        "an edit_link whose successor names an unregistered source",
    );
    let ill_formed = format!(r#"[{{"source":"{CLAIMANT_DOC1}","span":{{"start":"2.1","width":"0.1"}}}}]"#);
    paired(
        &edit_link_frame(&original, CLAIMANT_DOC1, CLAIMANT_DOC1, &ill_formed, &ghost_ty(CLAIMANT_DOC1, 55)),
        "ill_formed_spec",
        "permanent",
        "an edit_link whose successor spec is ill-formed",
    );
    // A slot past M7's work budget: 4,096 specs, each over the fragmented
    // draft's first position, command 4,096 × 65 run-list steps — past the
    // 64 × 4,096 M7 admits — while keeping one span each.
    let spec = format!(r#"{{"source":"{fragmented}","span":{{"start":"1.1","width":"0.1"}}}}"#);
    let from = format!("[{}]", vec![spec; skep_links::MAX_SLOT_SPANS].join(","));
    paired(
        &link_frame(CLAIMANT_DOC1, &from, r#"{"addrs":[]}"#, &ghost_ty(CLAIMANT_DOC1, 56)),
        "slot_too_large",
        "permanent",
        "a make_link whose from passes the per-slot work budget",
    );
    assert_eq!(head_position(port), before, "nothing committed");
}

/// THE EXEMPTION NARROWED (SO-I4; SO-I7 — round 7's as7-E1 ARM (a) with
/// bu7-E1 ARM (a), owner 2026-10-01): the one `insert` the check demands no
/// `attest` of is a record of its declared kind, carrying its `sig`, into a
/// doc 1 — lane D's path, unchanged. Beside it, three outcomes: (a) prose
/// declared `T_enroll` into a published document that is no doc 1 takes the
/// check — unattested, `attestation_required`, nothing landed; attested, it
/// commits with its slot filled; (b) a record of the kind carrying NO `sig`
/// into doc 1 is refused at its `insert`, `record_sig_required`, PERMANENT,
/// the journal's position unmoved and no orphan minted; (c) a record WITH
/// its `sig` into the published non-doc-1 document, unattested, answers
/// `attestation_required` — no credential link can name it there, so the
/// exemption does not reach it. The record deposit's own atom — the signed
/// record into doc 1 — lands exempt, its slot empty, as every hire in the
/// suite does.
#[test]
fn the_record_deposit_exemption_reaches_a_signed_record_in_a_doc_1_alone() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let edition = edition_with(port, &signed, "abc");
    let permanent = |v: &Value| v["disposition"].as_str() == Some("permanent");
    let declared = |doc: &str, ordinal: u64, atom: &str| {
        format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        )
    };
    let entries = [Enrollment::new(public_key_of(&distinct_key(71)), false, None).expect("no label")];

    // (a) Prose under the kind, into the edition: the check, not the exemption.
    let ordinal = next_content_ordinal(port, Some(&signed), &edition);
    let before = head_position(port);
    let v = op_as_written(port, Some(&signed), &insert_frame(&edition, ordinal, "p", true));
    assert_eq!(verdict(&v), "credential_refused:attestation_required", "{v}");
    assert_eq!(head_position(port), before, "nothing landed");
    let v = op(port, Some(&signed), &insert_frame(&edition, ordinal, "p", true));
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some(), "attested, committed SIGNED: {v}");

    // (b) A record of the kind with NO `sig` into doc 1: refused at the
    // insert, permanent, the journal unmoved.
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let sig_less = json_atom(&encode_enroll(&entries));
    let before = head_position(port);
    for attested in [false, true] {
        let frame = declared(CLAIMANT_DOC1, ordinal, &sig_less);
        let v = if attested { op(port, Some(&signed), &frame) } else { op_as_written(port, Some(&signed), &frame) };
        assert_eq!(verdict(&v), "credential_refused:record_sig_required", "attested={attested}: {v}");
        assert!(permanent(&v), "PERMANENT: the same bytes are never admitted: {v}");
    }
    assert_eq!(head_position(port), before, "no orphan: the journal's position is unmoved");

    // (c) A record WITH its `sig` into the edition — no doc 1 — unattested:
    // the check's (1); with a valid attest it commits SIGNED.
    let ordinal = next_content_ordinal(port, Some(&signed), &edition);
    let carrying = signed_atom(port, &signed, &edition, T_ENROLL, &[CLAIMANT_ACCOUNT], &json_atom(&encode_enroll(&entries)));
    assert_ne!(carrying, json_atom(&encode_enroll(&entries)), "the fixture signed the record");
    let v = op_as_written(port, Some(&signed), &declared(&edition, ordinal, &carrying));
    assert_eq!(verdict(&v), "credential_refused:attestation_required", "a signed record outside a doc 1, unattested: {v}");
    let v = op(port, Some(&signed), &declared(&edition, ordinal, &carrying));
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some(), "attested: committed SIGNED: {v}");

    // (d) A record WITH its `sig` into doc 1: exempt — lane D's path.
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let carrying = signed_atom(port, &signed, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &json_atom(&encode_enroll(&entries)));
    let v = op_as_written(port, Some(&signed), &declared(CLAIMANT_DOC1, ordinal, &carrying));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "exempt, no attest demanded: {v}");
    assert_eq!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap(), None, "the record's sig is its carrier");
}

/// THE SIGNATURE BINDS THE BASE (SO-I1 (c); SO-I3 — V's change-the-base
/// half, round 7's bu7-E2 ARM (a), owner 2026-10-01; the BLOCKER
/// `publish-body-binds-no-base`): a signed shot's `publish` body carries the
/// base MEMBER's address beside the extent, so the same signed shot
/// re-submitted naming the trunk's CURRENT head as its base — D.2's request,
/// kept byte for byte, its `base` moved from D.1 to D.3 — spells another
/// preimage and is refused `attestation_invalid:signature`, PERMANENT;
/// nothing is minted, D.3 stays the head. Before the base joined the group
/// such a re-submission passed every check and minted D.4 with the author's
/// old runs as the document's current text. The keep-the-base replay beside
/// it (`a_replayed_shot_mints_its_bases_daughter_and_the_current_version_stands`)
/// still mints D.1's daughter.
#[test]
fn a_signed_shot_re_submitted_over_another_base_is_refused_signature_and_mints_nothing() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let edition = edition_with(port, &signed, "abc");
    let runs = shot_runs(port, Some(&signed), &edition, 1, 3);
    let d1 = shot(port, &signed, &edition, Some((&edition, 3)), None, &runs);
    let draft = draft_with(port, &signed, "xy");
    let mut runs2 = shot_runs(port, Some(&signed), &d1, 1, 3);
    runs2.extend(shot_runs(port, Some(&signed), &draft, 1, 2));
    let d2_request =
        attach_attest(port, &signed, &publish_frame(&edition, Some((&d1, 3)), Some(&draft), &runs2));
    let d2 = acked_addr(&op_as_written(port, Some(&signed), &d2_request));
    assert_eq!(d2, format!("{edition}.2"));
    let runs3 = shot_runs(port, Some(&signed), &d2, 1, 5);
    let d3 = shot(port, &signed, &edition, Some((&d2, 5)), None, &runs3);
    assert_eq!(d3, format!("{edition}.3"));
    let head_image = image_runs(port, None, &edition, 1, 5);
    let before = head_position(port);

    // THE CHANGED BASE: the same signed request, its base the current head.
    let mut moved: Value = serde_json::from_str(&d2_request).unwrap();
    moved["base"] = Value::String(d3.clone());
    moved["base_extent"] = Value::String("5".into());
    let v = op_as_written(port, Some(&signed), &moved.to_string());
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:signature".to_string(), "permanent".to_string()),
        "the signature was made over the base it named, and verifies over no other: {v}"
    );
    assert_eq!(head_position(port), before, "nothing minted");
    assert_eq!(image_runs(port, None, &edition, 1, 5), head_image, "the current version is still D.3");
    let v = op(port, None, &format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{edition}.4"}}"#));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"), "no D.4: {v}");
    // The same signed shot over the base it named — the extent moved alone —
    // is another preimage too.
    let mut narrowed: Value = serde_json::from_str(&d2_request).unwrap();
    narrowed["base_extent"] = Value::String("2".into());
    let v = op_as_written(port, Some(&signed), &narrowed.to_string());
    assert_eq!(verdict(&v), "credential_refused:attestation_invalid:signature", "{v}");
    assert_eq!(head_position(port), before);
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
        let unattested = op_as_written(port, Some(&b_signed), frame);
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
    let v = op_as_written(port, Some(&b_signed), &carried);
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
    let v = op_as_written(port, Some(&c_signed), &carried);
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

/// A STAGING DRAFT ITS PRINCIPAL MAY NOT READ IS NEVER COPIED IN (the check's
/// own `attestation_invalid:withheld`; `policy/attestation.rs`'s doc item 6;
/// PUB-2.40, PUB-6.24). Naming a draft as a shot's STAGING DRAFT makes every
/// run onto it a run the commit COPIES IN — re-inserted BY VALUE as fresh
/// identity under the shot document's own I-space — and M5's source gate
/// skips a run the base already carries. B, granted the claimant's private
/// draft D, versioned it into F, its own published document, and was revoked.
/// A shot into F naming D as its staging draft, over runs F CARRIES, is one
/// the store would admit, D's bytes becoming F's published text. The check
/// composes no body over a value B may not read: it asks the store's own
/// gates, and where they would admit the shot it refuses
/// `attestation_invalid:withheld`, REORDER — signed over D's true bytes or
/// over a wrong guess, alike — and nothing commits. Where the gates refuse
/// it — a run onto D's sixth address, which F does not carry — the signed
/// shot passes through UNATTESTED to the store's own `withheld`, naming D.
/// Unattested, either shot meets (1) first, `attestation_required`, ahead of
/// any composition (the design record §4.5's ratified order) — m1's SECOND
/// ORDER VECTOR (SO-I7 (f), SO-I9 (a); round 7's `m1-reorder-has-no-lane`,
/// the code landed at `37f611a`): an unsigned `publish` copying an
/// unreadable origin answers `attestation_required`, never `withheld`.
/// Every other shot in the suite names no staging draft, or its author's
/// own, so this cell alone reaches the check's own refusal.
#[test]
fn a_staging_draft_its_principal_may_not_read_is_refused_unread_and_never_copied_in() {
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
    let before = head_position(port);

    // CARRIED, D the staging draft: the store would re-insert D's five values
    // into F's next member. Refused, whatever is attached.
    let carried = publish_frame(&f, Some((&f, 5)), Some(&d), &[run(&d, &d_addr(1), 5)]);
    let withheld =
        ("credential_refused:attestation_invalid:withheld".to_string(), "reorder".to_string());
    let required = ("credential_refused:attestation_required".to_string(), "reorder".to_string());
    let v = op_as_written(port, Some(&b_signed), &carried);
    assert_eq!(refusal(&v), required, "unattested: (1), ahead of the composition: {v}");
    let v = op_with_publish_values(port, &b_signed, &carried, &per_byte("abcde"));
    assert_eq!(refusal(&v), withheld, "signed over D's true bytes: {v}");
    let v = op_with_publish_values(port, &b_signed, &carried, &per_byte("abcdz"));
    assert_eq!(refusal(&v), withheld, "signed over a wrong guess: {v}");
    // NOT CARRIED: D's sixth address — the store's own gate answers.
    let uncarried = publish_frame(&f, Some((&f, 5)), Some(&d), &[run(&d, &d_addr(6), 1)]);
    let v = op_as_written(port, Some(&b_signed), &uncarried);
    assert_eq!(refusal(&v), required, "unattested: {v}");
    assert_withheld(&op_with_publish_values(port, &b_signed, &uncarried, &per_byte("f")), &d);
    assert_eq!(head_position(port), before, "nothing committed: D's bytes reached no member of F");
}

/// A SHOT'S ENTRY-FRAME BODY IS BOUNDED, at parity with the request-body
/// cap (`skepd::body_cap("/op")`): the body is measured as the check reads
/// each value (`PublishBody`, in the layout `entry_body_publish` spells), and
/// a shot whose runs name one byte more is refused
/// `attestation_invalid:frame_too_large`, PERMANENT, before the body is built
/// past the budget — whatever its signature was made over, since a body never
/// built whole verifies nothing; unattested, (1) answers first and no value
/// is walked — m1's THIRD ORDER VECTOR (SO-I7 (f), SO-I9 (a); round 7's
/// `m1-reorder-has-no-lane`, the code landed at `37f611a`): an unsigned
/// `publish` whose frame would pass `MAX_SHOT_BODY_BYTES` answers
/// `attestation_required`, never `frame_too_large`. At the budget exactly
/// the shot is admitted and commits attested. A run names one stored value
/// as often as the wire's run list admits, so no cap on the request bounds
/// the body the check reads: four runs over one two-megabyte atom fill it
/// here.
#[test]
fn a_shot_body_is_refused_before_it_is_built_past_its_budget() {
    let budget = skepd::body_cap("/op");
    // The body is `be64(placed)`, then — four values copied in, one stretch
    // — the stretch's class byte and `be64(count)`, then a be32 length and
    // the bytes per value, then the base group of thirty-four bytes (the
    // shot names `1.0.1.0.1` as its base — bu7-E2: the group's length, the
    // member's slot row of one element over the nine-byte address, and the
    // extent): three atoms of `width` bytes and one of `last` fill
    // `8 + 9 + 3 × (4 + width) + (4 + last) + 34` — the budget exactly.
    let base_group = 4 + 1 + 8 + 4 + CLAIMANT_DOC1.len() + 8;
    assert_eq!(base_group, 34);
    let fixed = 8 + 9 + 4 * 4 + base_group;
    let width = (budget - fixed) / 4;
    let last = budget - fixed - 3 * width;
    assert_eq!(8 + 9 + 3 * (4 + width) + (4 + last) + base_group, budget, "four atoms fill the body to the byte");
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
    let x = acked_addr(&op_as_written(port, Some(&signed), &insert_atom(1, &xs)));
    let y = acked_addr(&op_as_written(port, Some(&signed), &insert_atom(2, &ys)));
    let z = acked_addr(&op_as_written(port, Some(&signed), &insert_atom(3, &zs)));
    let (x_run, y_run, z_run) = (run(&d, &x, 1), run(&d, &y, 1), run(&d, &z, 1));
    let base = Some((CLAIMANT_DOC1, 1));
    let before = head_position(port);

    // One byte past the budget: refused before the body is built past it.
    let over = publish_frame(CLAIMANT_DOC1, base, Some(&d), &[x_run.clone(), x_run.clone(), x_run.clone(), y_run]);
    let over_values = [xs.as_bytes(), xs.as_bytes(), xs.as_bytes(), ys.as_bytes()];
    let v = op_as_written(port, Some(&signed), &over);
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_required".to_string(), "reorder".to_string()),
        "unattested: (1), ahead of the composition: {v}"
    );
    let v = op_with_publish_values(port, &signed, &over, &over_values);
    assert_eq!(
        refusal(&v),
        (
            "credential_refused:attestation_invalid:frame_too_large".to_string(),
            "permanent".to_string()
        ),
        "one byte past the shot-body budget: {v}"
    );
    assert_eq!(head_position(port), before, "a refused shot commits nothing");

    // At the budget exactly: the body is built, the check admits, the shot
    // commits attested.
    let at_cap = publish_frame(CLAIMANT_DOC1, base, Some(&d), &[x_run.clone(), x_run.clone(), x_run.clone(), z_run]);
    let v = op_with_publish_values(port, &signed, &at_cap, &[xs.as_bytes(), xs.as_bytes(), xs.as_bytes(), zs.as_bytes()]);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "a shot at the budget is admitted: {v}");
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some(), "and attested");
}

/// A TERM PAST THE FRAME'S EIGHT BYTES PASSES UNATTESTED TO THE STORE'S OWN
/// REFUSAL (the check's doc item 6; `ComposeFault::Unspellable`): a base
/// extent, a window's width or the count a shot places past 2^64 − 1 names
/// positions no store holds, so no frame is composed and the store refuses the
/// shot as its own — `base_extent_too_large`, `dangling_source`, PERMANENT —
/// whatever `attest` it carries, one no frame verifies included. Unattested,
/// every such shot meets (1) first, `attestation_required` (REORDER), ahead of
/// the composition (the design record §4.5's ratified order). At 2^64 − 1 the
/// term is spellable: attested, the check verifies and the store's same
/// refusal answers. Two windows of 2^63 — each spellable, their count not —
/// are the pre-sum's own cell: without it the builder's overflow reads as the
/// budget's.
#[test]
fn a_term_past_the_frames_eight_bytes_passes_unattested_to_the_stores_refusal() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let d = draft_with(port, &signed, "pq");
    let shot_frame = |extent: &str, runs: &[String]| {
        format!(
            r#"{{"op":"publish","doc":"{CLAIMANT_DOC1}","base":"{CLAIMANT_DOC1}","base_extent":"{extent}","runs":[{}]}}"#,
            runs.join(",")
        )
    };
    let window = |width: &str| format!(r#"{{"origin":"{d}","i_start":"{d}.0.1.1","width":"{width}"}}"#);
    let (top, past, half) = (u64::MAX.to_string(), "18446744073709551616", "9223372036854775808");
    let store = |code: &str| (code.to_string(), "permanent".to_string());
    let before = head_position(port);

    let required = ("credential_refused:attestation_required".to_string(), "reorder".to_string());
    let top_frame = shot_frame(&top, &[]);
    assert_eq!(
        refusal(&op_as_written(port, Some(&signed), &top_frame)),
        required,
        "unattested: (1) first"
    );
    assert_eq!(
        refusal(&op(port, Some(&signed), &top_frame)),
        store("base_extent_too_large"),
        "attested: 2^64 − 1 is a term the frame spells"
    );
    for (frame, code, why) in [
        (shot_frame(past, &[]), "base_extent_too_large", "an extent past the row"),
        (shot_frame("1", &[window(past)]), "dangling_source", "a window past the row"),
        (
            shot_frame("1", &[window(half), window(half)]),
            "dangling_source",
            "two windows whose count passes the row",
        ),
    ] {
        assert_eq!(
            refusal(&op_as_written(port, Some(&signed), &frame)),
            required,
            "{why}, unattested"
        );
        assert_eq!(
            refusal(&op_as_written(port, Some(&signed), &with_unverifiable_attest(&frame))),
            store(code),
            "{why}: passed through to the store, whatever is attached"
        );
    }
    assert_eq!(head_position(port), before, "nothing committed");
}

/// A SHOT PAST THE STORE'S RE-INSERT BUDGET IS NEVER WALKED (the check's doc
/// item 6; `ComposeFault::PastReinsertBudget`): M5 refuses a shot whose
/// staging-draft runs re-insert more than `MAX_REINSERTED_VALUES` values by
/// request arithmetic before it probes an address, so the check reads none
/// of them and an ATTESTED shot passes UNATTESTED to the store's own
/// `too_many_values`, whatever its signature was made over, nothing
/// committed; unattested, it meets (1) first. Every value the runs name
/// exists, so a check walking past the budget would compose the body and
/// answer an unverifiable signature `attestation_invalid:signature` instead.
/// AT the budget the shot is one the store admits: its values are walked and
/// its attest judged — refused `attestation_invalid:signature` over a
/// signature no frame verifies; a check that refused it at the budget would
/// pass it through UNATTESTED, and the store would commit it with its marker
/// slot empty. The runs repeat one stretch of the draft, as a run list may,
/// so a draft of a thousand values carries a shot of a hundred and thirty
/// thousand.
#[test]
fn a_shot_past_the_stores_re_insert_budget_passes_unattested_to_its_refusal() {
    let budget = skep_arrangement::MAX_REINSERTED_VALUES as u64;
    let stretch = 1024u64;
    assert_eq!(budget % stretch, 0, "the stretch divides the budget");
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let d = draft_with(port, &signed, &"x".repeat(stretch as usize));
    let first = format!("{d}.0.1.1");
    // `count` draft-native values: the stretch, again and again, then a tail.
    let shot_frame = |count: u64| {
        let mut runs = vec![run(&d, &first, stretch); (count / stretch) as usize];
        if count % stretch > 0 {
            runs.push(run(&d, &first, count % stretch));
        }
        publish_frame(CLAIMANT_DOC1, Some((CLAIMANT_DOC1, 1)), Some(&d), &runs)
    };
    let store = ("too_many_values".to_string(), "permanent".to_string());
    let before = head_position(port);

    let required = ("credential_refused:attestation_required".to_string(), "reorder".to_string());
    let past = shot_frame(budget + 1);
    assert_eq!(
        refusal(&op_as_written(port, Some(&signed), &past)),
        required,
        "unattested: (1) first"
    );
    assert_eq!(
        refusal(&op_as_written(port, Some(&signed), &with_unverifiable_attest(&past))),
        store,
        "never walked: passed through to the store, whatever is attached"
    );
    let values = vec![&b"x"[..]; budget as usize + 1];
    assert_eq!(
        refusal(&op_with_publish_values(port, &signed, &past, &values)),
        store,
        "attested over the true bytes: no signature changes the store's answer"
    );
    let at_budget = with_unverifiable_attest(&shot_frame(budget));
    assert_eq!(
        refusal(&op_as_written(port, Some(&signed), &at_budget)),
        ("credential_refused:attestation_invalid:signature".to_string(), "permanent".to_string()),
        "at the budget the values are walked and the attest judged"
    );
    assert_eq!(head_position(port), before, "nothing committed");
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
    let rec = op_as_written(port, None, &retrieve_frame("1.1.0.1.0.2.2", 1, 1));
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
    let v = op_as_written(port, Some(&signed), &claimant_grant_attested(ALG_MLDSA65_ED25519, &over_h2));
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
    let v = op_as_written(port, Some(&signed), &claimant_grant_attested(ALG_MLDSA65_ED25519, &over_live));
    assert_eq!(verdict(&v), "credential_refused:attestation_invalid:signature", "the live pair: {v}");
    // Over H.1's: admitted, the slot that very blob.
    let over_h1 = signer.sign(&claimant_grant_entry_frame(ALG_MLDSA65_ED25519, h1));
    let v = op_as_written(port, Some(&signed), &claimant_grant_attested(ALG_MLDSA65_ED25519, &over_h1));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "H.1's pair is the board term after H.2: {v}");
    let slot = sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().expect("the slot is filled");
    assert_eq!(slot.sig(), &over_h1[..], "H.1's pair, after the second head as before it");
}

/// D26: a credential deposit is TWO POSITIONS — the atom `insert` and its
/// `make_link` — and neither takes the entry signature: the atom by its
/// declared credential type, the link by its route (the credential route,
/// to which a presented `attest` is never handed). Both slots stay empty —
/// the record's one carrier is its own `sig`, inside the atom (2a), which
/// the hire signs; the hire's agent opens a signed session and attests its
/// own writes.
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
    // sequence, the member dropped — on a fresh agent's deposit, its record
    // signed as the hire signs one.
    let key2 = distinct_key(52);
    let (agent2, _) = bootstrap_delegate(port, 52);
    let ordinal = next_content_ordinal(port, Some(&registrar), CLAIMANT_DOC1);
    let atom2 = signed_atom(port, &registrar, CLAIMANT_DOC1, T_ENROLL, &[&agent2], &enroll_atom(&[&key2]));
    let v = op(
        port,
        Some(&registrar),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom2}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    let atom2_addr = acked_addr(&v);
    let mut link: Value =
        serde_json::from_str(&typed_link_frame(CLAIMANT_DOC1, &[&atom2_addr], &[&agent2], T_ENROLL)).unwrap();
    link["attest"] = json!({"alg": ALG_MLDSA65_ED25519, "sig": hex(&[0xAB; 3373])});
    let v = op_as_written(port, Some(&registrar), &link.to_string());
    let link_at = acked_at(&v);
    assert_eq!(sd.daemon().attestation_at(Seq(link_at)).unwrap(), None, "dropped by route");
    // The agent, keyed, attests its own publish-class write.
    let home = acked_addr(&op(port, Some(&agent_signed), &create_frame(&agent, None)));
    let v = op(port, Some(&agent_signed), &typed_link_frame(&home, &[&agent], &[], T_GRANT));
    assert!(sd.daemon().attestation_at(Seq(acked_at(&v))).unwrap().is_some());
}

// ── the record grade (2a) ───────────────────────────────────────────────────

/// One credential record's atom, deposited from `token` into `home` for
/// `subject` under `ty`: the declared insert at the home's next free
/// position, then the `make_link` naming it. Answers the atom's commit
/// position (the link's BASE, this suite writing nothing between the two),
/// the atom's address, and the link's answer UNJUDGED — a refusal cell reads
/// its token where a hire would panic.
fn deposit_record(port: u16, token: &str, home: &str, subject: &str, ty: &str, atom: &str) -> (u64, String, Value) {
    let ordinal = next_content_ordinal(port, Some(token), home);
    let v = op(
        port,
        Some(token),
        &format!(
            r#"{{"op":"insert","doc":"{home}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
        ),
    );
    let (atom_at, atom_addr) = (acked_at(&v), acked_addr(&v));
    let link = op(port, Some(token), &typed_link_frame(home, &[&atom_addr], &[subject], ty));
    (atom_at, atom_addr, link)
}

/// The fingerprints `key_set` lists under `field` for `account`, as of the
/// head, or as of `at` through `/op-at`.
fn fingerprints(port: u16, account: &str, field: &str, at: Option<u64>) -> Vec<String> {
    let frame = format!(r#"{{"op":"key_set","account":"{account}"}}"#);
    let v = match at {
        None => op(port, None, &frame),
        Some(at) => op_at_ok(port, None, at, &frame),
    };
    expect_resp(&v, "key_set")[field]
        .as_array()
        .expect(field)
        .iter()
        .map(|e| e["fingerprint"].as_str().expect("fingerprint").to_string())
        .collect()
}

/// THE MIRROR'S READ of one committed credential record (the design record
/// §4.2 (C): "a mirror verifies it from the two reads a client already
/// makes"): from the stored LINK and ATOM alone — `read_link` for the slots
/// (the atom's address, the subject, the type), `retrieve_v` for the atom's
/// text, the home being the link's own document — the record VALUE and the
/// members the `record` frame takes.
struct StoredRecord {
    home: String,
    ty: String,
    to: Vec<String>,
    canonical: String,
    sig: Option<String>,
}

fn stored_record(port: u16, link: &str) -> StoredRecord {
    let value = read_link(port, None, link);
    assert!(!value.is_null(), "{link} is a link");
    let starts = |slot: usize| -> Vec<String> {
        value["slots"][slot]
            .as_array()
            .expect("a slot")
            .iter()
            .map(|s| s["start"].as_str().expect("a span start").to_string())
            .collect()
    };
    let (from, to, ty) = (starts(0), starts(1), starts(2));
    let ty = ty.into_iter().next().expect("the type slot");
    let atom_addr = from.into_iter().next().expect("the record's atom");
    // The link is `<home>.0.2.<n>`, the atom `<home>.0.1.<ordinal>`.
    let parts: Vec<&str> = link.split('.').collect();
    let home = parts[..parts.len() - 3].join(".");
    let ordinal: u64 = atom_addr.rsplit('.').next().expect("an ordinal").parse().expect("a count");
    let items = delivery(port, None, &home, ordinal, 1);
    let text = items[0]["atom"].as_str().expect("the record atom").to_string();
    let (canonical, sig) = match ty.as_str() {
        T_ENROLL => {
            let v: RecordValue<Enrollment> = parse_record_value(text.as_bytes()).expect("admitted");
            (canonical_record(&v.entries, None), v.sig)
        }
        T_RETIRE => {
            let v: RecordValue<Fingerprint> = parse_record_value(text.as_bytes()).expect("admitted");
            (canonical_record(&v.entries, None), v.sig)
        }
        other => panic!("{other} is no record-bearing kind"),
    };
    StoredRecord { home, ty, to, canonical, sig }
}

impl StoredRecord {
    /// The `record` frame under `alg`, composed from the stored members and
    /// the board's `H.1` — the signer's own composition, over the same values.
    fn frame(&self, port: u16, alg: &str) -> Vec<u8> {
        let to: Vec<&str> = self.to.iter().map(String::as_str).collect();
        record_frame_for(port, alg, &self.home, &self.ty, &to, self.canonical.as_bytes())
            .expect("H.1 stands and the home has an owner")
    }

    /// THE MIRROR'S TRIAL: whether the record's `sig` verifies, both halves,
    /// under some key of `set` — a `key_set` answer's `enrolled`, each key
    /// rebuilt from its `alg` and `key` — the frame under that key's own row.
    fn verifies_under(&self, port: u16, set: &Value) -> bool {
        let Some(sig) = &self.sig else { return false };
        let blob = hex_to_bytes(sig);
        set["enrolled"].as_array().expect("enrolled").iter().any(|e| {
            let key = PublicKey::parse(e["alg"].as_str().expect("alg"), e["key"].as_str().expect("key"))
                .expect("a served key parses");
            skep_signature::verify(key.sig_alg_row().tag, &key, &self.frame(port, key.alg()), &blob).is_ok()
        })
    }
}

/// THE KEY TABLE IS VERIFIABLE FROM GENESIS (the record grade, 2a; the design
/// record §4.5 (4) and its table clauses (a)–(c); BW-02's equality): above
/// the claim, every credential record the fold honors carries a `sig` that
/// verifies under the set that opened its home at its link's base — end to
/// end over the wire, on a claimed board. The claimant ENROLS a second key
/// SIGNED by its device key (honored: the table gains it, both positions'
/// marker slots empty, D26), RETIRES it SIGNED (honored); an UNSIGNED
/// enrolment is refused at its INSERT, `record_sig_required` (PERMANENT —
/// round 7's bu7-E1: nothing lands, no orphan), one signed by a key NOT in
/// the opening set
/// `attestation_invalid:signature`, one signed by a key of a ROW the set
/// holds none of `not_enrolled_at_position`, one whose `sig` is no blob's hex
/// `malformed` — each PERMANENT, each committing no link; and THE GRADE: an
/// anchor-flagged enrolment deposited from the ANCHOR session but signed by
/// the DEVICE key is `signature` — an anchor-grade record admits an anchor's
/// `sig` alone — and the same record signed by the anchor is honored. At
/// every step the fold's table is the filtered table: the set of honored
/// records is the set of records whose `sig` verifies under the opening set
/// as of their base (read back through `/op-at`), and every refused deposit
/// left the table where it stood.
#[test]
fn above_the_claim_every_honored_credential_record_carries_a_sig_the_opening_set_verifies() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let device = open_owner_session(port);
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let fp = |k: &SigningKey| Fingerprint::of(&public_key_of(k)).to_hex();
    let enrolled = |at: Option<u64>| fingerprints(port, CLAIMANT_ACCOUNT, "enrolled", at);
    let mut expected: Vec<String> = enrolled(None);
    expected.sort();
    assert_eq!(expected, { let mut c = vec![fp(&anchor_key()), fp(&device_key())]; c.sort(); c }, "the ceremony's two");
    // The filtered table's other half: every honored record, verified at its
    // base by the mirror's own read.
    let mut honored: Vec<(u64, String)> = Vec::new();
    let assert_table_is_filtered = |expected: &Vec<String>, honored: &[(u64, String)]| {
        let mut live = enrolled(None);
        live.sort();
        assert_eq!(&live, expected, "the fold's table");
        for (base, link) in honored {
            let record = stored_record(port, link);
            let set = op_at_ok(port, None, *base, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
            assert!(record.verifies_under(port, &set), "{link} verifies under the opening set as of its base {base}");
        }
    };

    // 1 — ENROL K2, signed by the device key: honored, both slots empty.
    let k2 = distinct_key(21);
    let atom = signed_atom(port, &device, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &enroll_atom(&[&k2]));
    assert!(atom.contains(r#"\"sig\":\""#), "the record carries its sig: {atom}");
    let (base, _, v) = deposit_record(port, &device, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &atom);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "a signed enrolment is honored: {v}");
    let link_at = acked_at(&v);
    assert_eq!(filled_slots(&sd, base, link_at), Vec::<u64>::new(), "D26: neither position's slot");
    honored.push((base, acked_addr(&v)));
    expected.push(fp(&k2));
    expected.sort();
    assert_table_is_filtered(&expected, &honored);

    // 2 — RETIRE K2, signed by the device key: honored.
    let retire = json_atom(&encode_retire(&[Fingerprint::of(&public_key_of(&k2))]));
    let atom = signed_atom(port, &device, CLAIMANT_DOC1, T_RETIRE, &[CLAIMANT_ACCOUNT], &retire);
    let (base, _, v) = deposit_record(port, &device, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_RETIRE, &atom);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "a signed retirement is honored: {v}");
    honored.push((base, acked_addr(&v)));
    expected.retain(|f| *f != fp(&k2));
    assert!(fingerprints(port, CLAIMANT_ACCOUNT, "retired", None).contains(&fp(&k2)));
    assert_table_is_filtered(&expected, &honored);

    // 3 — UNSIGNED: refused at the atom's INSERT (bu7-E1 — the sig-less
    // record-kind atom lands nowhere), PERMANENT, committing nothing.
    let k3 = distinct_key(22);
    let head = head_position(port);
    let ordinal = next_content_ordinal(port, Some(&device), CLAIMANT_DOC1);
    let v = op(
        port,
        Some(&device),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
            enroll_atom(&[&k3])
        ),
    );
    assert_eq!(
        refusal(&v),
        ("credential_refused:record_sig_required".to_string(), "permanent".to_string()),
        "an unsigned enrolment above the claim, at its insert: {v}"
    );
    assert_eq!(head_position(port), head, "nothing committed: no atom, no orphan");
    assert_table_is_filtered(&expected, &honored);

    // 4 — signed by a key NOT in the opening set: a stranger's tag-1 key.
    let entries = [Enrollment::new(public_key_of(&k3), false, None).unwrap()];
    let stranger = HybridSigner::from_seed(FIXTURE_TAG, &[0x66; 32]).unwrap();
    let foreign = signed_record_text(port, &stranger, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &entries).unwrap();
    let (_, _, v) = deposit_record(port, &device, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &json_atom(&foreign));
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:signature".to_string(), "permanent".to_string()),
        "a stranger's sig: {v}"
    );
    // …by a key of a ROW the opening set holds no key of: a tag-3 blob.
    let tag3 = HybridSigner::from_seed(skep_signature::TAG_FNDSA512_PREVIEW_ED25519, &[0x66; 32]).unwrap();
    let other_row = signed_record_text(port, &tag3, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &entries).unwrap();
    let (_, _, v) = deposit_record(port, &device, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &json_atom(&other_row));
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:not_enrolled_at_position".to_string(), "permanent".to_string()),
        "no key of the blob's row: {v}"
    );
    // …and a `sig` that is no blob's hex at all.
    let garbage = json_atom(&canonical_record(&entries, Some("zz")));
    let (_, _, v) = deposit_record(port, &device, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &garbage);
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:malformed".to_string(), "permanent".to_string()),
        "a sig of no row's width: {v}"
    );
    assert_table_is_filtered(&expected, &honored);

    // 5 — THE GRADE: an anchor-flagged enrolment is anchor-grade, so it
    // admits an anchor's `sig` alone — the device key's, deposited from the
    // anchor's own session (slot (6) passed), is `signature`; the anchor's
    // is honored, and the new anchor stands.
    let k4 = distinct_key(23);
    let flagged = [Enrollment::new(public_key_of(&k4), true, None).unwrap()];
    let by_device = signed_record_text(port, &hybrid_signer(&device_key()), CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &flagged).unwrap();
    let (_, _, v) = deposit_record(port, &anchor, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &json_atom(&by_device));
    assert_eq!(verdict(&v), "credential_refused:attestation_invalid:signature", "an anchor-grade record, a device's sig: {v}");
    assert_table_is_filtered(&expected, &honored);
    let by_anchor = signed_record_text(port, &hybrid_signer(&anchor_key()), CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &flagged).unwrap();
    let (base, _, v) = deposit_record(port, &anchor, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &json_atom(&by_anchor));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the anchor's sig: {v}");
    honored.push((base, acked_addr(&v)));
    expected.push(fp(&k4));
    expected.sort();
    assert_table_is_filtered(&expected, &honored);
    // The new anchor opens a session and signs an anchor act of its own.
    let as_k4 = open_signed_session(port, CLAIMANT_PRINCIPAL, &k4);
    let k5 = distinct_key(24);
    let atom = signed_atom(port, &as_k4, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &enroll_atom_flagged(&[(&k5, true)]));
    let (_, _, v) = deposit_record(port, &as_k4, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &atom);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the new anchor's own anchor act: {v}");
}

/// A LIFTED RECORD FAILS (the design record §4.5's table clause (a): "a
/// record LIFTED into a stranger's doc 1 is refused by this same lookup, its
/// `sig` verifying under no key of THAT home's account"): the claimant's
/// signed enrolment of K — honored in the claimant's doc 1 — copied byte for
/// byte into a stranger B's doc 1 and deposited as B's own holder act (the
/// fold would honor it: K is new to B's set) is refused
/// `attestation_invalid:signature`, PERMANENT: the frame names B's home and
/// B's account, and the `sig` was made over the claimant's. B's table is
/// unmoved, and the same record freshly signed by B's own key for B's home
/// is honored — the lift is what fails, not the record. The lineage row is
/// EMPTY at every position on this board (l6-A5), so it separates nothing
/// here; the home and its account do.
#[test]
fn a_record_lifted_into_a_strangers_doc_1_verifies_under_no_key_of_that_home() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let b = seat_stranger(port, 971);
    let b_key = distinct_key(71);
    let b_signed = hire(port, &signed, CLAIMANT_DOC1, &b.account, 971, &b_key);
    let k = distinct_key(72);
    let k_fp = Fingerprint::of(&public_key_of(&k)).to_hex();
    // The claimant's own, signed for its home: honored.
    let atom = signed_atom(port, &signed, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &enroll_atom(&[&k]));
    let (_, _, v) = deposit_record(port, &signed, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &atom);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "{v}");
    assert!(fingerprints(port, CLAIMANT_ACCOUNT, "enrolled", None).contains(&k_fp));
    // THE LIFT: the very atom into B's doc 1, deposited for B.
    let before = fingerprints(port, &b.account, "enrolled", None);
    let (_, _, v) = deposit_record(port, &b_signed, &b.doc1, &b.account, T_ENROLL, &atom);
    assert_eq!(
        refusal(&v),
        ("credential_refused:attestation_invalid:signature".to_string(), "permanent".to_string()),
        "a lifted record verifies under no key of B's: {v}"
    );
    assert_eq!(fingerprints(port, &b.account, "enrolled", None), before, "B's table is unmoved");
    // The same record, signed by B for B's home: honored.
    let own = signed_atom(port, &b_signed, &b.doc1, T_ENROLL, &[&b.account], &enroll_atom(&[&k]));
    let (_, _, v) = deposit_record(port, &b_signed, &b.doc1, &b.account, T_ENROLL, &own);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "B's own signature over the same entries: {v}");
    assert!(fingerprints(port, &b.account, "enrolled", None).contains(&k_fp));
}

/// THE RECORD GRADE TRIES EACH CANDIDATE UNDER ITS OWN ROW (the record grade's
/// step 6: "the frame under ITS row's token as `alg`, both halves"; AUTH-1.44:
/// a tag-3 key already enrolled signs as any other): the claimant enrols a
/// PREVIEW key, and an enrolment record that key SIGNS — the `record` frame
/// under the preview token, the 730-byte blob — is honored, its key joining
/// the table, the stored record verifying under the served set. Every other
/// record whose `sig` reaches the trial is signed under tag 1 — the stranger's
/// tag-3 blob above meets an opening set holding no key of its row and is
/// refused before it — so a record grade framing every candidate under tag 1's
/// token, or verifying under tag 1's rule, passes them all and refuses this one
/// `attestation_invalid:signature`, PERMANENT.
#[test]
fn a_tag_3_key_signs_a_credential_record_as_a_tag_1_key_does() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let device = open_owner_session(port);
    let tag3 =
        HybridSigner::from_seed(skep_signature::TAG_FNDSA512_PREVIEW_ED25519, &seed_of(&distinct_key(75)))
            .expect("tag 3 is a row");
    // The preview key joins, its record signed by the device key.
    let joins = [Enrollment::new(tag3.public_key().clone(), false, None).unwrap()];
    let atom =
        signed_atom(port, &device, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &json_atom(&encode_enroll(&joins)));
    let (_, _, v) = deposit_record(port, &device, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &atom);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the preview key joins: {v}");
    // A record the PREVIEW key signs.
    let k = distinct_key(76);
    let entries = [Enrollment::new(public_key_of(&k), false, None).unwrap()];
    let text = signed_record_text(port, &tag3, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &entries)
        .expect("composable");
    let (_, _, v) = deposit_record(port, &device, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &json_atom(&text));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "a record the preview key signs is honored: {v}");
    let fp = Fingerprint::of(&public_key_of(&k)).to_hex();
    assert!(fingerprints(port, CLAIMANT_ACCOUNT, "enrolled", None).contains(&fp), "its key joins");
    let record = stored_record(port, &acked_addr(&v));
    assert_eq!(record.sig.as_deref().map(str::len), Some(2 * 730), "tag 3's blob");
    let set = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    assert!(record.verifies_under(port, &set), "it verifies under the served set");
}

/// THE MIRROR COMPOSES THE SAME BYTES (the design record §4.2 (C), §7.2; the
/// frame merge's "what a verifier composes"): a verifier holding the STORED
/// atom and link alone — `find_links_v` at the record's positions, then
/// `read_link` for the slots and `retrieve` for the atom, `H.1`'s pair, the
/// home off the link's own address and its account by ω — composes the
/// `record` frame byte for byte as the signer composed it at the request,
/// and the record's `sig` verifies over it under the fold's key set as the
/// wire serves it. The write path verified the same bytes: one preimage,
/// composed from the request and from the store.
#[test]
fn a_record_frame_composed_from_the_stored_atom_and_link_is_the_frame_the_signer_made() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let k = distinct_key(73);
    let entries = [Enrollment::new(public_key_of(&k), false, Some("mirror".into())).unwrap()];
    let frame_from_request = record_frame_for(
        port,
        ALG_MLDSA65_ED25519,
        CLAIMANT_DOC1,
        T_ENROLL,
        &[CLAIMANT_ACCOUNT],
        canonical_record(&entries, None).as_bytes(),
    )
    .expect("composable");
    let text = signed_record_text(port, &hybrid_signer(&device_key()), CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &entries).unwrap();
    let (_, atom_addr, v) = deposit_record(port, &signed, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, T_ENROLL, &json_atom(&text));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "{v}");
    let link = acked_addr(&v);

    // THE LATER VERIFIER: the link found by the record's positions and its
    // kind — the four-set query, FROM the atom and typed enroll (a query by
    // positions alone matches the account-wide slots of the ceremony's own
    // links too, which contain every position of doc 1)…
    let found = addrs_of(&op(
        port,
        None,
        &ftt_frame("find_links_ftt", r#""any""#, &unit_span(&atom_addr), r#""any""#, &unit_span(T_ENROLL)),
    ));
    assert_eq!(found, vec![link.clone()], "the record's one link, by its atom and its kind");
    // …its slots and its atom read off the store, and the frame composed.
    let record = stored_record(port, &link);
    assert_eq!((record.home.as_str(), record.ty.as_str()), (CLAIMANT_DOC1, T_ENROLL));
    assert_eq!(record.to, vec![CLAIMANT_ACCOUNT.to_string()]);
    assert_eq!(record.canonical, canonical_record(&entries, None), "the sig-less projection");
    let frame_from_store = record.frame(port, ALG_MLDSA65_ED25519);
    assert_eq!(
        frame_from_store, frame_from_request,
        "one preimage, composed from the request and from the store"
    );
    // …and the sig verifies under the fold's set as served.
    let set = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    assert!(record.verifies_under(port, &set), "the record's sig verifies under the served key set");
    let blob = hex_to_bytes(record.sig.as_deref().expect("the sig"));
    assert_eq!(
        skep_signature::verify(FIXTURE_TAG, &public_key_of(&device_key()), &frame_from_store, &blob),
        Ok(()),
        "under the device key that signed it"
    );
    assert_ne!(
        skep_signature::verify(FIXTURE_TAG, &public_key_of(&anchor_key()), &frame_from_store, &blob),
        Ok(()),
        "and under no other"
    );
}

/// THE CREDENTIAL DEPOSIT'S `replaces` FENCE (BW-04, owner-ruled 2026-09-29):
/// a credential-typed `make_link` carrying a `replaces` member is refused
/// `replaces_not_credential`, PERMANENT — a shape slot ahead of the lock,
/// beside `resolved_from`, so it answers before any gate behind it: from the
/// device session whose record is signed and would otherwise be honored,
/// and from a BARE session that slot (7) would refuse. Nothing commits, and
/// the same frame without the member is honored. The record's `replaces`
/// row is EMPTY by kind: the frame the `sig` covers has no place for one.
#[test]
fn a_replaces_member_on_a_credential_typed_make_link_is_refused_ahead_of_the_lock() {
    let dir = tempdir().unwrap();
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_owner_session(port);
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let k = distinct_key(74);
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let atom = signed_atom(port, &signed, CLAIMANT_DOC1, T_ENROLL, &[CLAIMANT_ACCOUNT], &enroll_atom(&[&k]));
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    let atom_addr = acked_addr(&v);
    let mut with_member: Value =
        serde_json::from_str(&typed_link_frame(CLAIMANT_DOC1, &[&atom_addr], &[CLAIMANT_ACCOUNT], T_ENROLL)).unwrap();
    with_member["replaces"] = json!(CEREMONY_ATOM);
    let head = head_position(port);
    for (hand, token) in [("the device session", &signed), ("a bare session", &bare)] {
        let v = op(port, Some(token), &with_member.to_string());
        assert_eq!(
            refusal(&v),
            ("credential_refused:replaces_not_credential".to_string(), "permanent".to_string()),
            "{hand}: {v}"
        );
    }
    assert_eq!(head_position(port), head, "nothing committed");
    let v = op(port, Some(&signed), &typed_link_frame(CLAIMANT_DOC1, &[&atom_addr], &[CLAIMANT_ACCOUNT], T_ENROLL));
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "without the member, honored: {v}");
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
    let v = op_as_written(port, Some(&signed), &share);
    let grant = acked_addr(&v);
    assert!(attested(&v), "the share is attested");
    assert!(reads(), "shared");

    // The revocation: a record naming the grant.
    let revoke = typed_link_frame(CLAIMANT_DOC1, &[&grant], &[], T_GRANT);
    let revocation = acked_addr(&op(port, Some(&signed), &revoke));
    assert!(!reads(), "revoked");

    // THE REPLAY: the byte-identical signed share.
    let v = op_as_written(port, Some(&signed), &share);
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
    let v = op_as_written(port, Some(&signed), &re_share);
    let re_share_addr = acked_addr(&v);
    assert!(attested(&v), "the re-share is attested");
    assert!(reads(), "a re-share naming the standing revocation is honored");
    let replaces_link = read_link(port, Some(&signed), &next_link_address(&re_share_addr));
    let start = |slot: usize| replaces_link["slots"][slot][0]["start"].as_str().map(str::to_string);
    assert_eq!(
        (start(0), start(1), start(2)),
        (Some(re_share_addr.clone()), Some(revocation.clone()), Some(T_REPLACES.to_string())),
        "the replaces link beside the re-share: from it, to the revocation, typed the class: {replaces_link}"
    );

    // Revoked again; the re-share's own request, replayed, names a stale
    // state.
    op(port, Some(&signed), &typed_link_frame(CLAIMANT_DOC1, &[&re_share_addr], &[], T_GRANT));
    assert!(!reads(), "the re-share revoked");
    let v = op_as_written(port, Some(&signed), &re_share);
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
    let v = op_as_written(port, Some(&signed), &d2_request);
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
    let v = op_as_written(port, Some(&signed), &d2_request);
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

/// THE FRAME IS CHECKABLE LATER (l6-A4; D25's (c′); fam1-L1; the base
/// member in the group since round 7, bu7-E2 — SO-I1 (c), SO-I6 (e)): a
/// verifier holding the MEMBER and no request — a mirror, a reader beside
/// the table — composes the shot's signed body byte for byte from what the
/// board serves about the member: its terms off `doc_metadata` (`placed`,
/// `base_extent`), its runs off the member's own arrangement over the first
/// `placed` positions (the image, maximally merged), each classed by its
/// origin — the edition's own trunk BY VALUE, the values read at the member;
/// any other document BY ADDRESS — and the BASE MEMBER DERIVED from the
/// member's own address and composed INTO the base group: `D.1` was minted
/// against the memberless document `D`. Over a shot holding all three run
/// classes, with two I-adjacent windows the placement merged into one: the
/// frame composed at the request (the test signer's, which the daemon's
/// check verified) and the frame composed off the member are one byte
/// string — the byte-equality vector, the daemon's composed body equal to
/// the signer's over one request — and the marker's attestation verifies
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
    let frame_from_request = entry_frame_for(port, &signed, CLAIMANT_PRINCIPAL, &parsed).expect("composable");
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
    // THE DERIVATION: the member `D.1` was minted against the memberless
    // document `D` — the base member is the trunk — at the extent
    // `doc_metadata` serves; composed INTO the preimage (bu7-E2 ARM (a)).
    let base_member = addr(&trunk);
    let base = base_extent.map(|extent| ShotBase { member: &base_member, extent });
    let body = entry_body_publish(segments.iter().map(SignerSegment::as_shot), base);
    let board = board_term(port).expect("H.1");
    let account = addr(&account_of(port, &signed, CLAIMANT_PRINCIPAL).expect("the account"));
    let frame_from_member =
        entry_frame(ALG_MLDSA65_ED25519, board, &account, DocTerm::One(&addr(&trunk)), &body);
    assert_eq!(
        frame_from_member, frame_from_request,
        "one preimage, composed from the request and from the member"
    );
    let (_, seed) = signer_of(&signed).expect("a signed session");
    let key = HybridSigner::from_seed(FIXTURE_TAG, &seed).unwrap();
    assert_eq!(
        skep_signature::verify(slot.sig_alg(), key.public_key(), &frame_from_member, slot.sig()),
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

/// A stored content extent — a resolved slot's span — from its I-start and
/// its width in positions, as a run's `iextent` spells one.
fn extent(start: &str, width: u64) -> Span {
    let start = addr(start);
    let depth = start.tumbler().len();
    let mut comps = vec![skep_address::Nat::from(0u64); depth];
    comps[depth - 1] = skep_address::Nat::from(width);
    Span::new(start.tumbler().clone(), skep_address::Tumbler::new(comps).unwrap()).unwrap()
}

/// The thirteen fixed instances every golden signs, on a board whose `H.1`
/// pair is `(12, 0xAB…)`, by account `1.0.1`: the frames of an `insert`
/// (undeclared, two values), a `make_link` (three slots as stored: a unit
/// type span, a unit `from`, the `to` EMPTY), a `publish` (three values
/// copied in, one window of two positions onto another document, the base
/// `1.0.1.0.1.1` taken at three — the address form, l6-A4; the base member
/// in the group since round 7, bu7-E2) and three `record`s (the frame
/// merge, fm-I; the record grade, 2a): an enrol's kind — its type slot, one
/// subject, neither optional row named, a short canonical body — a retire's
/// kind beside it over the same subject, and the claim's — its type slot,
/// the EMPTY target slot, no record at all (a claim carries none,
/// AUTH-2.48), the body-bytes row empty; then the seven cells D24 pinned: a
/// `create_new_document`, a `fork` and a `version`, each the EMPTY body
/// over the parent account `1.0.1`; a `nullify` of the link `…0.2.1` from
/// its home, a `assert_sup` of that link by `…0.2.2`, an `emit` of the
/// retired class over `1.0.1.0.2` with its `to` EMPTY (Unary), each the
/// stored link's rows; and an `edit_link` of `…0.2.1` whose successor is
/// homed in `1.0.1.0.2` with two resolved content extents and a named
/// type, its claim homed in `1.0.1.0.1` — the pair's row as its `doc`.
fn fixed_frames(alg: &str) -> [(&'static str, Vec<u8>); 13] {
    let (account, doc, other) = (addr("1.0.1"), addr("1.0.1.0.1"), addr("1.0.1.0.2"));
    let board = BoardTerm { log_position: 12, chain: [0xAB; 32] };
    let insert = entry_body_insert(None, [&b"a"[..], &b"b"[..]]);
    let ty = [unit(&addr("1.1.0.1.0.1.0.3.90"))];
    let from = [unit(&addr("1.0.1"))];
    let link = entry_body_make_link(LinkSlots {
        from: EntrySlot(&from),
        to: EntrySlot(&[]),
        ty: EntrySlot(&ty),
    });
    let window = addr("1.0.1.0.2.0.1.1");
    let base_member = addr("1.0.1.0.1.1");
    let publish = entry_body_publish(
        [
            ShotSegmentPiece::Value(b"x"),
            ShotSegmentPiece::Value(b"y"),
            ShotSegmentPiece::Value(b"z"),
            ShotSegmentPiece::Window {
                start: &window,
                width: std::num::NonZeroU64::new(2).expect("2 is not zero"),
            },
        ],
        Some(ShotBase { member: &base_member, extent: 3 }),
    );
    let subject = [addr("1.0.2")];
    let enrol = entry_body_record(RecordRows {
        ty: &addr("1.1.0.1.0.1.0.3.1"),
        to: &subject,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: br#"{"type":"skep-enroll"}"#,
    });
    let retire = entry_body_record(RecordRows {
        ty: &addr("1.1.0.1.0.1.0.3.2"),
        to: &subject,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: br#"{"type":"skep-retire"}"#,
    });
    let claim = entry_body_record(RecordRows {
        ty: &addr("1.1.0.1.0.1.0.3.3"),
        to: &[],
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: b"",
    });
    let (l1, l2) = (unit(&addr("1.0.1.0.1.0.2.1")), unit(&addr("1.0.1.0.1.0.2.2")));
    let (home, retraction) = (unit(&doc), unit(&addr("1.1.0.1.0.1.0.1.5")));
    let supersedes = unit(&addr("1.1.0.1.0.1.0.1.4"));
    let (retired, retired_doc) = (unit(&addr("1.1.0.1.0.1.0.1.3")), unit(&other));
    let nullify = entry_body_nullify(LinkSlots {
        from: EntrySlot(std::slice::from_ref(&home)),
        to: EntrySlot(std::slice::from_ref(&l1)),
        ty: EntrySlot(std::slice::from_ref(&retraction)),
    });
    let assert_sup = entry_body_assert_sup(LinkSlots {
        from: EntrySlot(std::slice::from_ref(&l1)),
        to: EntrySlot(std::slice::from_ref(&l2)),
        ty: EntrySlot(std::slice::from_ref(&supersedes)),
    });
    let emit = entry_body_emit(LinkSlots {
        from: EntrySlot(std::slice::from_ref(&retired_doc)),
        to: EntrySlot(&[]),
        ty: EntrySlot(std::slice::from_ref(&retired)),
    });
    let (s_from, s_to) = (extent("1.0.1.0.2.0.1.1", 5), extent("1.0.1.0.2.0.1.6", 2));
    let s_ty = unit(&addr("1.0.1.0.3.0.2.1"));
    let edit = entry_body_edit_link(
        LinkSlots {
            from: EntrySlot(std::slice::from_ref(&s_from)),
            to: EntrySlot(std::slice::from_ref(&s_to)),
            ty: EntrySlot(std::slice::from_ref(&s_ty)),
        },
        &l1,
    );
    let frame = |body: &EntryBody, term: DocTerm<'_>| (body.op(), entry_frame(alg, board, &account, term, body));
    [
        frame(&insert, DocTerm::One(&doc)),
        frame(&link, DocTerm::One(&doc)),
        frame(&publish, DocTerm::One(&doc)),
        frame(&enrol, DocTerm::One(&doc)),
        frame(&retire, DocTerm::One(&doc)),
        frame(&claim, DocTerm::One(&doc)),
        frame(&entry_body_empty(ContentFreeOp::CreateNewDocument), DocTerm::One(&account)),
        frame(&entry_body_empty(ContentFreeOp::Fork), DocTerm::One(&account)),
        frame(&entry_body_empty(ContentFreeOp::Version), DocTerm::One(&account)),
        frame(&nullify, DocTerm::One(&doc)),
        frame(&assert_sup, DocTerm::One(&doc)),
        frame(&emit, DocTerm::One(&doc)),
        frame(&edit, DocTerm::Pair { d_s: &other, d_a: &doc }),
    ]
}

/// THE FRAME REGRESSION per op cell: the bytes, spelled out by hand once —
/// the D24 pins as the seam build made them; the `make_link` body's
/// `replaces` row since the replay fix moved it in place under
/// `skep-entry-v1` (l6-A3): an EMPTY group where the member is absent, the
/// member's address-list row, delimited, where it is present; its three
/// slots since the slot row's re-pin (ap6-3, d24-2): each `0x03`, the span
/// count, then every span's start and width delimited — a unit span per
/// address named, the EMPTY slot `0x03 ‖ be64(0)`; the `publish` body since
/// the re-pin of 2026-09-29 (V, l6-A4, D25's (c′)): the count, the segments
/// in the address form, the base-extent group; the `record` body since the
/// frame merge (fm-I): five rows under a token no wire op spells — the
/// enrol's kind as B+C pinned it, unmoved by the record grade's build (2a),
/// which pinned the retire's and the claim's beside it, its two slot rows
/// under `0x01` still (d24-4); and the seven cells D24 pinned — the EMPTY
/// body, `be32(0)` with the member present, over the parent account; the
/// stored tuple's four rows for `nullify`, `assert_sup` and `emit`; the
/// successor's four rows, the claim's `from` and the pair's row for
/// `edit_link`.
#[test]
fn the_entry_frames_bytes_per_op_are_pinned() {
    let [(_, insert), (_, link), (_, publish), (_, enrol), (_, retire), (_, claim), (_, create), (_, fork), (_, version), (_, nullify), (_, assert_sup), (_, emit), (_, edit)] =
        fixed_frames(ALG_MLDSA65_ED25519);
    // The members every frame shares: the framing tag, then `alg`, `board`
    // and `account`; then `doc` — the document, the parent account at the
    // mints, the pair's row at the edit.
    let mut head = b"skep-entry-v1".to_vec();
    let member = |m: &[u8]| [&(m.len() as u32).to_be_bytes()[..], m].concat();
    head.extend(member(b"mldsa65-ed25519"));
    head.extend(member(&[&[0u8, 0, 0, 0, 0, 0, 0, 12][..], &[0xAB; 32][..]].concat()));
    head.extend(member(b"1.0.1"));
    // THE ADDRESS-LIST ROW: `0x01`, `be64(n)`, each address delimited.
    let list = |addrs: &[&[u8]]| {
        let mut s = vec![0x01u8];
        s.extend((addrs.len() as u64).to_be_bytes());
        for a in addrs {
            s.extend(member(a));
        }
        s
    };
    // THE SLOT ROW, as stored: `0x03`, `be64(n)`, each span's start and
    // width delimited.
    let stored = |spans: &[(&[u8], &[u8])]| {
        let mut s = vec![0x03u8];
        s.extend((spans.len() as u64).to_be_bytes());
        for (start, width) in spans {
            s.extend(member(start));
            s.extend(member(width));
        }
        s
    };
    let prefix = [head.clone(), member(b"1.0.1.0.1")].concat();
    // insert: op, then body = be32(0) (undeclared) ‖ be64(2) ‖ 4:1:a ‖ 4:1:b
    let mut want = prefix.clone();
    want.extend(member(b"insert"));
    want.extend(member(
        &[&[0u8, 0, 0, 0][..], &[0, 0, 0, 0, 0, 0, 0, 2][..], &[0, 0, 0, 1, b'a'][..], &[0, 0, 0, 1, b'b'][..]].concat(),
    ));
    assert_eq!(insert, want, "insert");
    // make_link: op, then body = ty slot ‖ from slot ‖ to slot ‖ the
    // `replaces` row — absent here, so the EMPTY group `be32(0)`. Each slot
    // a unit span: the address as the start, the unit at its length as the
    // width; the `to` EMPTY.
    let grant_ty: (&[u8], &[u8]) = (b"1.1.0.1.0.1.0.3.90", b"0.0.0.0.0.0.0.0.1");
    let grant_from: (&[u8], &[u8]) = (b"1.0.1", b"0.0.1");
    let mut want = prefix.clone();
    want.extend(member(b"make_link"));
    want.extend(member(&[stored(&[grant_ty]), stored(&[grant_from]), stored(&[]), vec![0, 0, 0, 0]].concat()));
    assert_eq!(link, want, "make_link");
    // …and a re-share: the same slots with the member PRESENT, naming the
    // revocation at `1.0.1.0.1.0.2.9` — its list row, delimited as one group.
    let (ty, from) = ([unit(&addr("1.1.0.1.0.1.0.3.90"))], [unit(&addr("1.0.1"))]);
    let re_share = entry_body_make_link_replacing(
        LinkSlots { from: EntrySlot(&from), to: EntrySlot(&[]), ty: EntrySlot(&ty) },
        &addr("1.0.1.0.1.0.2.9"),
    );
    let frame = entry_frame(
        ALG_MLDSA65_ED25519,
        BoardTerm { log_position: 12, chain: [0xAB; 32] },
        &addr("1.0.1"),
        DocTerm::One(&addr("1.0.1.0.1")),
        &re_share,
    );
    let mut want = prefix.clone();
    want.extend(member(b"make_link"));
    want.extend(member(
        &[stored(&[grant_ty]), stored(&[grant_from]), stored(&[]), member(&list(&[b"1.0.1.0.1.0.2.9"]))].concat(),
    ));
    assert_eq!(frame, want, "make_link with its replaces member");
    // publish: op, then body = be64(5) — five positions placed — ‖ the
    // value stretch: its class byte 0x02, be64(3), x, y, z ‖ the window:
    // its class byte 0x01, the start's spelling delimited, be64(2) ‖ the
    // base group (bu7-E2): be32(32) ‖ the base member as an address-list
    // row of one element — 0x01, be64(1), the eleven bytes of
    // `1.0.1.0.1.1` delimited — ‖ be64(3), the extent.
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
            &[0, 0, 0, 32][..],
            &list(&[b"1.0.1.0.1.1"])[..],
            &[0, 0, 0, 0, 0, 0, 0, 3][..],
        ]
        .concat(),
    ));
    assert_eq!(publish, want, "publish");
    // record: op `record` — no wire op spells it — then body = the type
    // slot row ‖ the `to` slot row — list rows both — ‖ the `replaces` row
    // EMPTY ‖ the lineage row EMPTY ‖ the canonical bytes, delimited. The
    // enrol's kind…
    let mut want = prefix.clone();
    want.extend(member(b"record"));
    want.extend(member(
        &[
            list(&[b"1.1.0.1.0.1.0.3.1"]),
            list(&[b"1.0.2"]),
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 0],
            member(br#"{"type":"skep-enroll"}"#),
        ]
        .concat(),
    ));
    assert_eq!(enrol, want, "record, the enrol's kind");
    // …the retire's: its own type slot, the same subject, its own bytes…
    let mut want = prefix.clone();
    want.extend(member(b"record"));
    want.extend(member(
        &[
            list(&[b"1.1.0.1.0.1.0.3.2"]),
            list(&[b"1.0.2"]),
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 0],
            member(br#"{"type":"skep-retire"}"#),
        ]
        .concat(),
    ));
    assert_eq!(retire, want, "record, the retire's kind");
    // …and the claim's: its type slot, the `to` slot EMPTY (nine bytes, never
    // absent), both optional rows EMPTY, and the body-bytes row EMPTY — a
    // claim carries no record (AUTH-2.48), so its row delimits nothing.
    let mut want = prefix.clone();
    want.extend(member(b"record"));
    want.extend(member(
        &[
            list(&[b"1.1.0.1.0.1.0.3.3"]),
            list(&[]),
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 0],
        ]
        .concat(),
    ));
    assert_eq!(claim, want, "record, the claim's kind");
    // THE THREE MINTS: `doc` the parent account, the body EMPTY — the
    // member present, `be32(0)`, and nothing else.
    for (frame, token) in [(create, "create_new_document"), (fork, "fork"), (version, "version")] {
        let mut want = [head.clone(), member(b"1.0.1")].concat();
        want.extend(member(token.as_bytes()));
        want.extend(member(b""));
        assert_eq!(frame, want, "{token}: the EMPTY body over the parent account");
    }
    // THE OTHER LINK WRITES: the stored tuple's four rows, each slot a unit
    // span — the type the class's reserved ghost address — under the op's
    // own token.
    let (link_1, link_2): ((&[u8], &[u8]), (&[u8], &[u8])) =
        ((b"1.0.1.0.1.0.2.1", b"0.0.0.0.0.0.0.1"), (b"1.0.1.0.1.0.2.2", b"0.0.0.0.0.0.0.1"));
    let home: (&[u8], &[u8]) = (b"1.0.1.0.1", b"0.0.0.0.1");
    let mut want = prefix.clone();
    want.extend(member(b"nullify"));
    want.extend(member(
        &[
            stored(&[(b"1.1.0.1.0.1.0.1.5", b"0.0.0.0.0.0.0.0.1")]),
            stored(&[home]),
            stored(&[link_1]),
            vec![0, 0, 0, 0],
        ]
        .concat(),
    ));
    assert_eq!(nullify, want, "nullify: the retraction's unit span, the home's, the target's");
    let mut want = prefix.clone();
    want.extend(member(b"assert_sup"));
    want.extend(member(
        &[
            stored(&[(b"1.1.0.1.0.1.0.1.4", b"0.0.0.0.0.0.0.0.1")]),
            stored(&[link_1]),
            stored(&[link_2]),
            vec![0, 0, 0, 0],
        ]
        .concat(),
    ));
    assert_eq!(assert_sup, want, "assert_sup: the supersedes class's unit span, old's, new's");
    let mut want = prefix.clone();
    want.extend(member(b"emit"));
    want.extend(member(
        &[
            stored(&[(b"1.1.0.1.0.1.0.1.3", b"0.0.0.0.0.0.0.0.1")]),
            stored(&[(b"1.0.1.0.2", b"0.0.0.0.1")]),
            stored(&[]),
            vec![0, 0, 0, 0],
        ]
        .concat(),
    ));
    assert_eq!(emit, want, "emit: the retired class's unit span, from's, the to EMPTY");
    // THE EDIT: `doc` the pair's row — `1.0.1.0.2` then `1.0.1.0.1`, a list
    // row of two — then the successor's four rows (two resolved extents and
    // a named type) and the fifth, the claim's `from`: the original's unit
    // span.
    let mut want = [head, member(&list(&[b"1.0.1.0.2", b"1.0.1.0.1"]))].concat();
    want.extend(member(b"edit_link"));
    want.extend(member(
        &[
            stored(&[(b"1.0.1.0.3.0.2.1", b"0.0.0.0.0.0.0.1")]),
            stored(&[(b"1.0.1.0.2.0.1.1", b"0.0.0.0.0.0.0.5")]),
            stored(&[(b"1.0.1.0.2.0.1.6", b"0.0.0.0.0.0.0.2")]),
            vec![0, 0, 0, 0],
            stored(&[link_1]),
        ]
        .concat(),
    ));
    assert_eq!(edit, want, "edit_link: the pair's row, the successor's rows, the claim's from");
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
