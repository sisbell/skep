//! THE WELL-KNOWN CREATION against the real daemon (wire.md §Namespace; the
//! mailbox design §2, §3; REG-4.131): `ceremony::create_well_known_document`
//! over an ENFORCING board its owner claimed, from the owner's signed
//! session. The call creates each of the four slots at its own address and
//! in its own state — the mailbox private and unsigned, the bio, the link
//! page and the policy document published, each under the attest this crate
//! composes over the slot document's own address, which the board verifies
//! — once per slot, and says whose act the answer is; the board's refusals
//! reach the caller verbatim; and a number no slot has is this client's own
//! halt, nothing written.

use serde_json::Value;
use skep_client::address::{well_known_of, MAILBOX_SLOT, POLICY_SLOT, WELL_KNOWN_SLOTS};
use skep_client::board::{frames, Answer, Scope};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::ceremony::{create_well_known_document, WellKnownDocument};
use skep_client::store::FileStore;
use skep_client::Halt;
use skep_signature::HybridSigner;

use crate::common::{board, claim, key_file, keygen, spawn};

/// An ENFORCING board its owner claimed, the owner's device key and the
/// account the claim made.
struct Rig {
    _dir: tempfile::TempDir,
    sd: skepd::Skepd,
    device: HybridSigner,
    account: String,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let owner = FileStore::open(dir.path().join("owner"));
    let fp = keygen(&owner, "owner laptop");
    let (claimed, _) = claim(&board(sd.port()), &owner, &dir.path().join("anchors"));
    Rig { device: key_file(&owner, &fp).signer(), account: claimed.account, _dir: dir, sd }
}

/// A metadata read's document, whoever asked.
fn document(answer: Result<Answer, Halt>) -> Value {
    match answer.expect("the metadata read") {
        Answer::Document(v) => v,
        Answer::Closed => panic!("the session ended at the metadata read"),
    }
}

/// Checks the call at every slot, on a claimed board that enforces.
///
/// From the owner's signed session each slot's document is created at
/// `<account>.0.<slot>` and the answer says this call created it. The slot
/// fixes the state: the mailbox is private — its owner reads it, a guest is
/// withheld it — and the bio, the link page and the policy document are
/// published and empty, a guest reading each. At the three published slots
/// the board is ENFORCING, so the creation lands only because the attest
/// this crate composed verified: a frame signed over the parent account, or
/// under another op's token, is refused `attestation_invalid` and the call
/// halts. A second call under another `id` is answered the same address and
/// says it created nothing; a re-send under the first `id` is the first
/// acknowledgment whole, so it still says created.
#[test]
fn the_call_creates_each_slot_once_in_its_own_state_and_signs_the_published_three() {
    let rig = rig();
    let board = board(rig.sd.port());
    let session = handshake(&board, Scope::Content, &rig.device, 1, Site::Session).expect("the owner's signed session");
    for slot in WELL_KNOWN_SLOTS {
        let addr = well_known_of(&rig.account, slot);
        let call = |id: &str| create_well_known_document(&board, &session, &rig.account, slot, &rig.device, id).unwrap_or_else(|halt| panic!("slot {slot} under `{id}`: {halt}"));
        assert_eq!(call(&format!("wk-{slot}")), WellKnownDocument { addr: addr.clone(), created: true }, "slot {slot}: created at its own address");

        let (owners, guests) = (document(session.op(&frames::doc_metadata(&addr))), document(board.op(None, &frames::doc_metadata(&addr))));
        if slot == MAILBOX_SLOT {
            assert_eq!((owners["published"].as_bool(), guests["code"].as_str()), (Some(false), Some("withheld")), "the mailbox is private: {owners} / {guests}");
        } else {
            assert_eq!((owners["published"].as_bool(), guests["published"].as_bool(), guests["birth"].is_null()), (Some(true), Some(true), true), "slot {slot} is published and empty: {owners} / {guests}");
        }

        assert_eq!(call(&format!("wk-{slot}-again")), WellKnownDocument { addr: addr.clone(), created: false }, "slot {slot}: a second call creates nothing");
        assert_eq!(call(&format!("wk-{slot}")), WellKnownDocument { addr, created: true }, "slot {slot}: a re-send under the first id is the first acknowledgment");
    }
    session.close().expect("close");
}

/// Checks what the call refuses, and that none of it writes.
///
/// A number no slot has — the home page's 1, the first unnamed 6, the
/// block's last 63, the first ordinary 64 — is this client's own halt: no
/// frame is composed and none is sent. The board's refusals reach the
/// caller verbatim, as a refusal and never a halt of this client's: the
/// system account at every slot, `system_account_no_well_known`, and an
/// account that is not the session's, `not_owner`, at the mailbox's slot
/// and at a published one alike. The board's head stands where it stood.
#[test]
fn a_number_no_slot_has_halts_here_and_the_boards_refusals_arrive_verbatim() {
    let rig = rig();
    let board = board(rig.sd.port());
    let session = handshake(&board, Scope::Content, &rig.device, 1, Site::Session).expect("the owner's signed session");
    let head = || board.health().unwrap().log_position();
    let before = head();

    for number in [1, 6, 63, 64] {
        let halt = create_well_known_document(&board, &session, &rig.account, number, &rig.device, &format!("no-slot-{number}")).expect_err("no well-known slot");
        assert!(matches!(halt, Halt::Halt(_)), "document {number}: this client's own halt, {halt}");
    }
    let refused = |account: &str, slot: u64| match create_well_known_document(&board, &session, account, slot, &rig.device, &format!("refused-{account}-{slot}")) {
        Err(Halt::Refused(refusal)) => refusal.token(),
        other => panic!("{account} at slot {slot}: the board's refusal, not {other:?}"),
    };
    for slot in WELL_KNOWN_SLOTS {
        assert_eq!(refused("1.1.0.1", slot), "credential_refused:system_account_no_well_known", "the system account at slot {slot}");
    }
    for slot in [MAILBOX_SLOT, POLICY_SLOT] {
        assert_eq!(refused("1.0.2", slot), "not_owner", "another's account at slot {slot}");
    }
    assert_eq!(head(), before, "no refused call wrote");
    session.close().expect("close");
}
