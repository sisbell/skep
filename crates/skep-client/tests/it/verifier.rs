//! THE READER's VERIFIER against the real daemon (D14; the signed-ops
//! record §3.5): an entry the daemon ADMITTED with an `attest` reads SIGNED
//! by the same key under the filtered table as of its base; an entry above
//! the claim with no `attest` reads UNSIGNED; the claim entry and the rows
//! below it read BEFORE ATTESTATION. The planted-key case — a `sig` no key
//! of the filtered set verifies — is unreachable over the wire of a
//! conforming daemon and is the unit test's (`verify::tests`).

use serde_json::{json, Value};
use skep_client::board::{acked_addr, acked_at, Answer, Authed, Scope, Token};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::derive::records::credential_records;
use skep_client::dial::Request;
use skep_client::store::FileStore;
use skep_client::verify::{Entry, FilteredTable, Verdict};
use skep_identity::{entry_body_empty, entry_frame, ContentFreeOp, DocTerm};

use crate::common::{board, claim, keygen, spawn};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The `/changes` row at `at`, read under `token` — the feed is REDUCED to
/// the documents the reader may read (wire.md §The change feed), so a row
/// over the owner's own documents is read as the owner.
fn row_at(board: &skep_client::board::Board, token: &Token, at: u64) -> Value {
    let req = Request::get(format!("/changes?since={}&limit=50", at.saturating_sub(1)));
    let Authed::Response(resp) = board.authed(Some(token), req).unwrap() else { panic!("the session closed") };
    assert_eq!(resp.status, 200);
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    v["changes"].as_array().unwrap().iter().find(|r| r["at"].as_u64() == Some(at)).cloned().unwrap_or_else(|| panic!("no row at {at}: {v}"))
}

#[test]
fn the_verdict_follows_the_daemons_admission_and_an_unattested_entry_reads_unsigned() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    let (done, _) = claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).unwrap().signer();
    let term = board.board_term().unwrap().expect("H.1 stands on a claimed board");

    // A publish-class mint from the device key's FULL session: a document
    // born published into an account that already holds one carries the
    // entry signature over the frame whose `doc` is the parent account and
    // whose body is EMPTY (wire.md §Operations).
    let full = handshake(&board, Scope::Full, &device, 1, Site::Session).unwrap();
    let account = skep_client::address::parse_address(&done.account).unwrap();
    let frame = entry_frame(device.public_key().alg(), term, &account, DocTerm::One(&account), &entry_body_empty(ContentFreeOp::CreateNewDocument));
    let sig = device.sign(&frame);
    let op = json!({"op": "create_new_document", "account": done.account, "published": true, "attest": {"alg": device.public_key().alg(), "sig": hex(&sig)}});
    let Answer::Document(v) = full.op(&op).unwrap() else { panic!("closed") };
    let minted = acked_addr(&v).unwrap_or_else(|| panic!("the attested mint: {v}")).to_string();
    let attested_at = acked_at(&v).expect("the position");
    // The same mint WITHOUT the attest is refused: the daemon judges the
    // class the same way this reader will.
    let Answer::Document(r) = full.op(&json!({"op": "create_new_document", "account": done.account, "published": true})).unwrap() else { panic!() };
    assert!(r.to_string().contains("attestation_required"), "{r}");
    // An op OUTSIDE the publish class from the same signed session: a draft
    // mint, which takes no attest and commits unsigned in its marker.
    let Answer::Document(d) = full.op(&json!({"op": "create_new_document", "account": done.account})).unwrap() else { panic!() };
    let draft_at = acked_at(&d).unwrap_or_else(|| panic!("{d}"));

    // The feed's rows, read as the owner: the attested one carries `attest`
    // and no `key`; the draft's carries `key` (the fingerprint) and no
    // `attest`.
    let row = row_at(&board, &full.token, attested_at);
    assert!(row.get("key").is_none(), "ABSENT on a signed row: {row}");
    let attest = row["attest"].clone();
    assert_eq!(attest["alg"].as_str(), Some(device.public_key().alg()));
    assert_eq!(attest["sig"].as_str(), Some(hex(&sig).as_str()), "byte-equal to the attest presented");
    assert!(row["docs"].as_array().is_some_and(|d| d.iter().any(|x| x.as_str() == Some(minted.as_str()))));
    let draft_row = row_at(&board, &full.token, draft_at);
    assert_eq!(draft_row["key"].as_str(), Some(fp.to_hex().as_str()), "{draft_row}");
    assert!(draft_row.get("attest").is_none());
    full.close().unwrap();

    // THE READER: the filtered table over the admitted read, as of the
    // entry's base; the frame re-composed from the row and the parent.
    let records = credential_records(&board, &done.account, &[]).unwrap();
    let boundary = records.claim_entry.expect("the claim entry");
    assert!(boundary < attested_at);
    let table = FilteredTable::build(&records, Some(term));
    assert_eq!(table.current().len(), 3, "two anchors and the device key, host-trusted at the genesis");
    assert!(table.inert.is_empty());
    let blob = unhex(attest["sig"].as_str().unwrap());
    let entry = Entry { position: attested_at, frame: &frame, attest: Some((attest["alg"].as_str().unwrap(), &blob)) };
    assert_eq!(Verdict::Signed(fp), skep_client::verify::verdict(&entry, &table, Some(boundary), records.floor), "the reader's verdict equals the daemon's admission");
    // The draft: no attest ⇒ UNSIGNED above the claim.
    let entry = Entry { position: draft_at, frame: &frame, attest: None };
    assert_eq!(Verdict::Unsigned, skep_client::verify::verdict(&entry, &table, Some(boundary), records.floor));
    // At and below the claim: BEFORE ATTESTATION.
    let entry = Entry { position: boundary, frame: &frame, attest: None };
    assert_eq!(Verdict::BeforeAttestation, skep_client::verify::verdict(&entry, &table, Some(boundary), records.floor));
    // A key outside the filtered set signing the same frame: UNSIGNED — the
    // verifier judges against the FILTERED set, never the served `key_set`.
    let stranger = skep_client::sign::signer_from_seed(&[8; 32]);
    let forged = stranger.sign(&frame);
    let entry = Entry { position: attested_at, frame: &frame, attest: Some((stranger.public_key().alg(), &forged)) };
    assert_eq!(Verdict::Unsigned, skep_client::verify::verdict(&entry, &table, Some(boundary), records.floor));
    // No boundary derivable: UNDETERMINABLE, never judged.
    assert!(matches!(skep_client::verify::verdict(&entry, &table, None, None), Verdict::Undeterminable(_)));
}
