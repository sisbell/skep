//! THE HANDOFF DOOR (`client.md` §4c; AUTH-5.90): the giver's beat (a)
//! idempotent; the recipient's beat with its backup moment in the HANDOFF
//! venue, at a notebook and at a served board; `accept`'s halts at an
//! undelegated and a seeded address; the decline arm; `--reprint`; the
//! giver's genesis homed in X's doc 1 at the anchor grade; the latch's test
//! client-side first; the ownership halt; the depth-2 genesis by reference;
//! G5's retry, and a genesis sent again reconciled by containment beside a
//! second genesis's neither arm; the giver's session as the given account
//! dead; the giver's and the given account's records read apart; the
//! recipient's `bind`; the setup act sent not at all where the first child is
//! another party's; the top-level halt; the anchorless line.

use std::path::{Path, PathBuf};

use skep_client::board::{Board, KeySetAnswer, Scope};
use skep_client::ceremony::accept::{accept, reprint, AcceptOptions, Accepted};
use skep_client::ceremony::deposit::{deposit, Deposit, DepositHalt, DepositKind, DepositOutcome};
use skep_client::ceremony::first_session::{document_present, first_session, FirstSessionReads};
use skep_client::ceremony::handoff::{handoff, Grade, HandoffOptions, HandoffOutcome};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::derive::records::{credential_records, Hand};
use skep_client::derive::{principal_of, KeyDiagnosis};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::person::KeptOrPlaced;
use skep_client::sign::signer_from_seed;
use skep_client::store::{Binding, FileStore, KeyStore};
use skep_client::Origin;
use skep_identity::{encode_enroll, parse_enroll, Enrollment, Fingerprint};

use crate::common::{anchor_file, board, claim, entry_of, files_in, key_file, keygen, origin_of, recording_board, spawn, token_dead, wire_session, Redirect};

fn give(account: &str, payload: Option<String>, anchor: Option<std::path::PathBuf>) -> HandoffOptions {
    HandoffOptions { principal: 1, account: account.into(), payload: payload.map(|p| format!("{p}\n").into_bytes()), anchor }
}

fn take(account: &str, out: &std::path::Path, no_anchors: bool) -> AcceptOptions {
    AcceptOptions { account: account.into(), label: None, anchor_out: vec![out.join("ra"), out.join("rb")], paper: false, no_anchors, hosted: None, host_name: "testhost".into(), date: "2026-10-04".into() }
}

#[test]
fn the_door_delegates_idempotently_the_recipient_accepts_the_giver_seeds_and_bind_lands_the_reply() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let giver = FileStore::open(dir.path().join("giver"));
    let giver_fp = keygen(&giver, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &giver, &anchors);
    // A top-level address: no door.
    let mut p = Scripted::new(vec![]);
    let err = handoff(&board, &giver, &mut p, &give("1.0.2", None, None)).expect_err("no door");
    assert!(err.to_string().contains("no handoff and no door"), "{err}");
    // Beat (a): delegate, then again — the address printed again.
    let mut p = Scripted::new(vec![]);
    let HandoffOutcome::Delegated { account, principal, already } = handoff(&board, &giver, &mut p, &give("1.0.1.2", None, None)).unwrap() else { panic!() };
    assert!((account.as_str(), already) == ("1.0.1.2", false) && principal >= 2);
    assert_eq!(principal_of(&board, "1.0.1.2").unwrap(), Some(principal));
    let mut p = Scripted::new(vec![]);
    let HandoffOutcome::Delegated { principal: again, already, .. } = handoff(&board, &giver, &mut p, &give("1.0.1.2", None, None)).unwrap() else { panic!() };
    assert!(already && again == principal, "no second delegate; the address again");
    assert!(p.said("AUTH RES-187"), "the precondition is said ahead of beat (a) on every run:\n{}", p.transcript.join("\n"));
    assert_eq!(board.next_account_prefix("1.0.1").unwrap().as_deref(), Some("1.0.1.3"), "exactly one delegation");
    // The giver's own session AS 1.0.1.2, open before the genesis.
    let giver_key = key_file(&giver, &giver_fp).signer();
    let as_given = wire_session(&board, principal, &giver_key);

    // THE RECIPIENT'S BEAT.
    let recipient = FileStore::open(dir.path().join("recipient"));
    // Not yet delegated: beat (a) owed.
    let mut p = Scripted::new(vec![]);
    let err = accept(&board, &recipient, &mut p, &take("1.0.1.3", dir.path(), false)).expect_err("beat (a) owed");
    assert!(err.to_string().contains("beat (a) is still owed") && err.to_string().contains("GIVER's"), "{err}");
    assert!(recipient.list().unwrap().is_empty(), "nothing generated");
    let mut p = Scripted::new(vec![Script::Label("phone".into()), Script::LabelDefault, Script::LabelDefault]);
    let taken = accept(&board, &recipient, &mut p, &take("1.0.1.2", dir.path(), false)).unwrap_or_else(|h| panic!("{h}\n{}", p.transcript.join("\n")));
    let t = p.transcript.join("\n");
    assert_eq!((taken.facts.account.as_str(), taken.facts.principal), ("1.0.1.2", principal));
    assert_eq!(taken.anchors.len(), 2);
    assert!(!taken.declined_pair);
    let entries = parse_enroll(taken.record.as_bytes()).expect("the three-key record");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries.iter().filter(|e| e.anchor).count(), 2);
    assert_eq!(Fingerprint::of(&entries[2].key), taken.device);
    // The strings and the venue.
    assert!(p.said("AUTH-5.90 (vi)") && p.said("Make a new key and two anchor sheets FOR THIS ACCOUNT"), "{t}");
    assert!(p.said("AUTH-5.44 (handoff)") && p.said("keep the papers — they are the way back into 1.0.1.2"), "{t}");
    assert_eq!(p.transcript.iter().filter(|l| l.contains("1.0.1 runs this board")).count(), 2, "the operator sentence at (a) and at (v), the recipient's own, never the hosted one:\n{t}");
    assert!(!p.said("your host runs the daemon"), "{t}");
    assert!(p.said("AUTH-5.90 (v)") && p.said("What you write here can be read by 1.0.1 and by everyone above them, forever"), "{t}");
    assert!(p.said("(viii) Your agents' home will be 1.0.1.2.1"), "{t}");
    assert!(p.said("creating your account will also create a space for your agents"), "the future tense:\n{t}");
    assert!(p.said("[AUTH-5.85]: every edit to this page") && p.said("this notebook's history is permanent"), "the notebook venue:\n{t}");
    assert!(p.said("(vii) the giver will return: \"Keep this with your papers: 1.0.1.2, principal") && p.said("skep bind") && p.said("NO DOC 1"), "{t}");
    assert!(p.said("the GIVER's own doc 1"), "AUTH-5.42's consequence keyed to this door:\n{t}");
    assert!(!p.said("AUTH-5.44 (create-org)"), "the org-door artifact line dropped");
    for which in ["ra", "rb"] {
        let file = anchor_file(dir.path(), which).1;
        assert_eq!((file.account.as_deref(), file.principal), (Some("1.0.1.2"), Some(principal)), "the artifact carries the recipient's facts");
    }
    // `--reprint` re-composes the same record from the files.
    let paths: Vec<std::path::PathBuf> = ["ra", "rb"].iter().map(|w| files_in(&dir.path().join(w))[0].clone()).collect();
    assert_eq!(reprint(&recipient, None, &paths, None).unwrap(), taken.record);
    let err = reprint(&recipient, None, &[dir.path().join("gone.skep-key")], None).expect_err("destroyed");
    assert!(err.to_string().contains("no artifact remains"), "{err}");

    // THE GIVER SEEDS — anchor-grade (the set holds anchors): the anchor
    // imported (kept), the comparison, G1's strings, the confirmation.
    let (kept, _) = anchor_file(&anchors, "a");
    let mut p = Scripted::new(vec![Script::Confirm(true), Script::Typed("1.0.1.2".into()), Script::KeptOrPlaced(KeptOrPlaced::Kept), Script::YesNo(true)]);
    let HandoffOutcome::Seeded { facts, grade, reconciled, .. } = handoff(&board, &giver, &mut p, &give("1.0.1.2", Some(taken.record.clone()), Some(kept.clone()))).unwrap_or_else(|h| panic!("{h}\n{}", p.transcript.join("\n"))) else { panic!() };
    let t = p.transcript.join("\n");
    assert_eq!((facts.account.as_str(), facts.principal, grade, reconciled), ("1.0.1.2", principal, Grade::Anchor, false));
    assert_eq!(grade.to_string(), "anchor", "the grade as the reply names it");
    assert!(p.said("AUTH RES-187") && p.said("LOOPBACK-BOUND notebook"), "{t}");
    assert!(p.said("CONSENT confirm: `skep handoff`"), "G0's comparison:\n{t}");
    for s in ["AUTH-5.90 (i)", "AUTH-5.90 (ii)", "AUTH-5.90 (iii)", "AUTH-5.90 (iv)"] {
        assert!(p.said(s), "{s}:\n{t}");
    }
    assert!(p.said("Handing this off is an anchor act"), "{t}");
    assert!(p.said("Everything already filed under 1.0.1.2 goes with it, including 0 space(s)"), "{t}");
    assert!(!p.said("THE ANCHORLESS LINE"), "the payload carries anchors");
    assert!(p.said("CONFIRM THE HANDOFF of 1.0.1.2"), "{t}");
    assert!(p.said("the kept artifact") && kept.is_file(), "{t}");
    // The genesis: homed in X's doc 1, signed by the anchor.
    let records = credential_records(&board, "1.0.1.2", &[]).unwrap();
    let genesis = records.genesis().expect("the genesis");
    assert_eq!(genesis.home, "1.0.1.0.1", "HOMED IN X's DOC 1 at depth 1");
    assert!(genesis.anchor_grade, "the record names anchors: anchor-grade");
    assert_eq!(genesis.sigless, taken.record, "the payload verbatim");
    let KeySetAnswer::Set(anchor_set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(matches!(&genesis.hand, Hand::Key(fp) if anchor_set.enrolled(fp).is_some_and(|e| e.anchor)), "signed by the giver's anchor: {:?}", genesis.hand);
    let KeySetAnswer::Set(set) = board.key_set("1.0.1.2").unwrap() else { panic!() };
    assert_eq!(set.enrolled.len(), 3);
    // The giver's session AS 1.0.1.2 is dead from the commit (AUTH-4.63).
    assert!(token_dead(&board, &as_given), "the giver's session as the given account died at the genesis");
    // G5: a re-sent frame reconciled by containment.
    let mut p = Scripted::new(vec![Script::Confirm(true), Script::Typed("1.0.1.2".into()), Script::KeptOrPlaced(KeptOrPlaced::Kept), Script::YesNo(true)]);
    let err = handoff(&board, &giver, &mut p, &give("1.0.1.2", Some(taken.record.clone()), Some(kept.clone()))).expect_err("already another party's");
    assert!(err.to_string().contains("already another party's"), "G0's own read stops a re-run: {err}");
    // A seeded address at `accept`: halt before anything is generated.
    // MUTATION 4: with the empty-set halt removed a pair is generated.
    let other = FileStore::open(dir.path().join("other"));
    let mut p = Scripted::new(vec![Script::Label("x".into()), Script::LabelDefault, Script::LabelDefault]);
    let err = accept(&board, &other, &mut p, &take("1.0.1.2", &dir.path().join("o"), false)).expect_err("seeded");
    assert!(err.to_string().contains("already been handed away"), "{err}");
    assert!(other.list().unwrap().is_empty() && !dir.path().join("o").exists(), "nothing generated");
    // The ownership halt: 1.0.1.2.1 beneath the handed-off 1.0.1.2.
    let mut p = Scripted::new(vec![]);
    let err = handoff(&board, &giver, &mut p, &give("1.0.1.2.1", None, None)).expect_err("another party's");
    assert!(err.to_string().contains("not yours to give") && err.to_string().contains("1.0.1.2"), "{err}");

    // THE RECIPIENT's `bind`: the first signed session's doc-1 mint and the
    // setup act, `inc(1.0.1.2, 1)` seated.
    let device = key_file(&recipient, &taken.device);
    recipient.bind(&Binding::Enrollment { origin: board.dialed().clone(), principal, account: "1.0.1.2".into(), fingerprint: taken.device }).unwrap();
    let reads = FirstSessionReads::take(&board, "1.0.1.2", &taken.device, Some(&recipient)).unwrap();
    assert!(reads.mint_owed() && reads.setup_owed());
    let session = handshake(&board, Scope::Content, &device.signer(), principal, Site::Tail).unwrap();
    let done = first_session(&board, &reads, &session, &device.signer(), Some(&recipient)).unwrap();
    session.close().unwrap();
    assert!(done.minted_home && done.agent_space_principal.is_some() && done.minted_agent_space_home);
    assert!(document_present(&board, "1.0.1.2.0.1").unwrap());
    assert!(principal_of(&board, "1.0.1.2.1").unwrap().is_some(), "inc(X.2, 1) seated");
}

/// The depth-2 genesis: `--account 1.0.1.3.1` of the giver's own unseeded
/// `1.0.1.3` is homed in 1.0.1.3's doc 1 (minted by beat (b)) from a session
/// AS 1.0.1.3 by reference; the decline arm's one-key record and G1's
/// anchorless line; a device-grade giver on an anchorless account.
#[test]
fn a_depth_two_genesis_is_homed_in_the_giving_accounts_doc_one_and_the_decline_arm_draws_the_anchorless_line() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let giver = FileStore::open(dir.path().join("giver"));
    keygen(&giver, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &giver, &anchors);
    // 1.0.1.2 handed to a recipient (so the giver's own unseeded 1.0.1.3
    // is the next); then 1.0.1.3 delegated (beat (a)) and 1.0.1.3.1 beneath it.
    let mut p = Scripted::new(vec![]);
    let HandoffOutcome::Delegated { .. } = handoff(&board, &giver, &mut p, &give("1.0.1.2", None, None)).unwrap() else { panic!() };
    let mut p = Scripted::new(vec![]);
    let HandoffOutcome::Delegated { principal: principal3, .. } = handoff(&board, &giver, &mut p, &give("1.0.1.3", None, None)).unwrap() else { panic!() };
    let mut p = Scripted::new(vec![]);
    let HandoffOutcome::Delegated { account, principal: principal31, already } = handoff(&board, &giver, &mut p, &give("1.0.1.3.1", None, None)).unwrap_or_else(|h| panic!("{h}")) else { panic!() };
    assert!((account.as_str(), already) == ("1.0.1.3.1", false));
    assert_ne!(principal3, principal31);
    assert!(!document_present(&board, "1.0.1.3.0.1").unwrap(), "the topic's home is not minted at the delegate");
    // The recipient DECLINES the pair: the cost as its confirmation; a
    // one-key record.
    let recipient = FileStore::open(dir.path().join("recipient"));
    let mut p = Scripted::new(vec![Script::Label("tablet".into()), Script::Typed("decline".into())]);
    let taken = accept(&board, &recipient, &mut p, &take("1.0.1.3.1", dir.path(), true)).unwrap_or_else(|h| panic!("{h}\n{}", p.transcript.join("\n")));
    let t = p.transcript.join("\n");
    assert!(taken.declined_pair && taken.anchors.is_empty());
    assert_eq!(parse_enroll(taken.record.as_bytes()).unwrap().len(), 1, "a one-key record");
    assert!(p.said("THE DECLINE (`--no-anchors`)") && p.said("CONFIRM THE DECLINE"), "{t}");
    assert!(!p.said("AUTH-5.54 (a)"), "no backup moment on the decline arm");
    assert!(p.said("Keep this somewhere you control: 1.0.1.3.1"), "string (vii)'s decline form:\n{t}");
    assert!(p.said("What you write here can be read by 1.0.1 and by everyone above them"), "the walk's terminus is the giver, at depth:\n{t}");
    // The giver seeds it: beat (b) mints 1.0.1.3's doc 1 from a session AS
    // 1.0.1.3 by reference; G4 homes the genesis there; the anchorless line.
    let (kept, _) = anchor_file(&anchors, "a");
    let mut p = Scripted::new(vec![Script::Confirm(true), Script::Typed("1.0.1.3.1".into()), Script::KeptOrPlaced(KeptOrPlaced::Placed), Script::YesNo(true)]);
    let placed = dir.path().join("placed.skep-key");
    std::fs::copy(&kept, &placed).unwrap();
    let HandoffOutcome::Seeded { facts, grade, .. } = handoff(&board, &giver, &mut p, &give("1.0.1.3.1", Some(taken.record.clone()), Some(placed.clone()))).unwrap_or_else(|h| panic!("{h}\n{}", p.transcript.join("\n"))) else { panic!() };
    let t = p.transcript.join("\n");
    assert_eq!((facts.account.as_str(), facts.principal, grade), ("1.0.1.3.1", principal31, Grade::Anchor));
    assert!(p.said("THE ANCHORLESS LINE") && p.said("re-run `skep accept` with an anchor pair"), "{t}");
    assert!(p.said("beat (b) is owed: 1.0.1.3 has no doc 1") && p.said("beat (b): 1.0.1.3.0.1 minted"), "{t}");
    assert!(!placed.is_file(), "the placed copy destroyed at the close");
    let records = credential_records(&board, "1.0.1.3.1", &[]).unwrap();
    let genesis = records.genesis().unwrap();
    assert_eq!(genesis.home, "1.0.1.3.0.1", "homed in the GIVING account's doc 1, never X's");
    assert_eq!(genesis.home_account, "1.0.1.3");
    let KeySetAnswer::Set(set) = board.key_set("1.0.1.3.1").unwrap() else { panic!() };
    assert_eq!(set.enrolled.len(), 1);
    // The recipient signs in at the depth-2 account.
    let device = key_file(&recipient, &taken.device);
    handshake(&board, Scope::Content, &device.signer(), principal31, Site::Tail).expect("the recipient's session").close().unwrap();

    // A DEVICE-GRADE giver: an anchorless hosted account hands off a
    // subdivision with its device key alone.
    let dir2 = tempfile::tempdir().unwrap();
    let sd2 = spawn(&dir2.path().join("board"), false);
    let board2 = crate::common::board(sd2.port());
    let giver2 = FileStore::open(dir2.path().join("giver"));
    let fp2 = keygen(&giver2, "lone");
    let payload2 = encode_enroll(&[Enrollment::new(key_file(&giver2, &fp2).public.clone(), false, Some("lone".into())).unwrap()]);
    let skep_client::ceremony::claim::HostedOutcome::Claimed(_) = skep_client::ceremony::claim::hosted(&board2, payload2.as_bytes(), 1).unwrap() else { panic!() };
    giver2.bind(&Binding::Enrollment { origin: board2.dialed().clone(), principal: 1, account: "1.0.1".into(), fingerprint: fp2 }).unwrap();
    // The hosted cascade runs no agent space: the setup act first (`bind`'s
    // arm), so the next delegable address is the giver's own `1.0.1.2`.
    let lone = key_file(&giver2, &fp2).signer();
    let reads = FirstSessionReads::take(&board2, "1.0.1", &fp2, Some(&giver2)).unwrap();
    let setup = handshake(&board2, Scope::Content, &lone, 1, Site::Tail).unwrap();
    first_session(&board2, &reads, &setup, &lone, Some(&giver2)).unwrap();
    setup.close().unwrap();
    let mut p = Scripted::new(vec![]);
    let HandoffOutcome::Delegated { principal: principal2, .. } = handoff(&board2, &giver2, &mut p, &give("1.0.1.2", None, None)).unwrap_or_else(|h| panic!("{h}")) else { panic!() };
    let recipient2 = FileStore::open(dir2.path().join("recipient"));
    let mut p = Scripted::new(vec![Script::Label("r".into()), Script::LabelDefault, Script::LabelDefault]);
    let taken2 = accept(&board2, &recipient2, &mut p, &take("1.0.1.2", dir2.path(), false)).unwrap_or_else(|h| panic!("{h}\n{}", p.transcript.join("\n")));
    let mut p = Scripted::new(vec![Script::Confirm(true), Script::Typed("1.0.1.2".into())]);
    let HandoffOutcome::Seeded { grade, facts, .. } = handoff(&board2, &giver2, &mut p, &give("1.0.1.2", Some(taken2.record.clone()), None)).unwrap_or_else(|h| panic!("{h}\n{}", p.transcript.join("\n"))) else { panic!() };
    assert_eq!((grade, facts.principal), (Grade::Device, principal2));
    assert_eq!(grade.to_string(), "device");
    assert!(!p.said("Handing this off is an anchor act") && !p.said("SECRET kept-or-placed"), "no import at the device grade");
}

/// A board whose claimant `1.0.1` handed `1.0.1.2` off: beat (a), the
/// recipient's beat (a phone and two anchors under `ra` and `rb`), and the
/// giver's anchor-grade genesis under its kept anchor a — the recipient's
/// store, the principal seated at `1.0.1.2`, and no `skep bind` run.
struct HandedOff {
    _daemon: skepd::Skepd,
    board: Board,
    anchors: PathBuf,
    recipient: FileStore,
    principal: u64,
    taken: Accepted,
}

fn handed_off(dir: &Path) -> HandedOff {
    let daemon = spawn(&dir.join("board"), false);
    let board = board(daemon.port());
    let giver = FileStore::open(dir.join("giver"));
    keygen(&giver, "notebook");
    let anchors = dir.join("anchors");
    claim(&board, &giver, &anchors);
    let HandoffOutcome::Delegated { principal, .. } = handoff(&board, &giver, &mut Scripted::new(vec![]), &give("1.0.1.2", None, None)).unwrap() else { panic!("beat (a)") };
    let recipient = FileStore::open(dir.join("recipient"));
    let script = vec![Script::Label("phone".into()), Script::LabelDefault, Script::LabelDefault];
    let taken = accept(&board, &recipient, &mut Scripted::new(script), &take("1.0.1.2", dir, false)).unwrap();
    let (kept, _) = anchor_file(&anchors, "a");
    let mut p = Scripted::new(vec![Script::Confirm(true), Script::Typed("1.0.1.2".into()), Script::KeptOrPlaced(KeptOrPlaced::Kept), Script::YesNo(true)]);
    let seeded = handoff(&board, &giver, &mut p, &give("1.0.1.2", Some(taken.record.clone()), Some(kept))).unwrap_or_else(|h| panic!("{h}\n{}", p.transcript.join("\n")));
    assert!(matches!(seeded, HandoffOutcome::Seeded { .. }), "{seeded:?}");
    HandedOff { _daemon: daemon, board, anchors, recipient, principal, taken }
}

/// A seeded account's enrolled and retired lists.
fn set_of(board: &Board, account: &str) -> (Vec<Fingerprint>, Vec<Fingerprint>) {
    let KeySetAnswer::Set(set) = board.key_set(account).unwrap() else { panic!("{account} is no account") };
    (set.enrolled.iter().map(|e| e.fingerprint).collect(), set.retired.iter().map(|r| r.fingerprint).collect())
}

/// G5 = beat (d), AUTH-5.18's CONTAINMENT: the handoff's genesis sent again
/// — its ack lost — meets `not_genesis_registry` at the latch and is read
/// against the set: every key of the record stands there, so the act
/// COMMITTED and this retry is its ack; nothing changes.
#[test]
fn a_handoff_genesis_sent_again_is_reconciled_by_containment() {
    let dir = tempfile::tempdir().unwrap();
    let h = handed_off(dir.path());
    let anchor = anchor_file(&h.anchors, "a").1.signer();
    let before = set_of(&h.board, "1.0.1.2");
    let token = wire_session(&h.board, 1, &anchor);
    let again = Deposit { home: "1.0.1.0.1", subject: "1.0.1.2", kind: DepositKind::EnrollVerbatim(h.taken.record.clone()), hand: Some(&anchor), id: "test.genesis-again" };
    let outcome = deposit(&h.board, &token, &again);
    h.board.session_close(&token).unwrap();
    let Ok(DepositOutcome::Committed { reason }) = outcome else { panic!("{outcome:?}") };
    assert!(reason.contains("not_genesis_registry") && reason.contains("contained"), "{reason}");
    assert_eq!(set_of(&h.board, "1.0.1.2"), before, "nothing changed");
}

/// AUTH-5.18's NEITHER arm: a second genesis naming keys the seeded set
/// holds none of is never the first one's ack — `not_genesis_registry`,
/// read against the set, is the arm a walk acts on, faced as the account
/// another key set already holds.
#[test]
fn a_second_genesis_of_other_keys_is_the_neither_arm() {
    let dir = tempfile::tempdir().unwrap();
    let h = handed_off(dir.path());
    let anchor = anchor_file(&h.anchors, "a").1.signer();
    let before = set_of(&h.board, "1.0.1.2");
    let other = encode_enroll(&[Enrollment::new(signer_from_seed(&[61; 32]).public_key().clone(), false, Some("other".into())).unwrap()]);
    let token = wire_session(&h.board, 1, &anchor);
    let second = Deposit { home: "1.0.1.0.1", subject: "1.0.1.2", kind: DepositKind::EnrollVerbatim(other), hand: Some(&anchor), id: "test.genesis-other" };
    let outcome = deposit(&h.board, &token, &second);
    h.board.session_close(&token).unwrap();
    let Err(DepositHalt::NotGenesisRegistry(face)) = outcome else { panic!("{outcome:?}") };
    assert!(face.to_string().contains("1.0.1.2 already holds a key set and it is not this record's"), "{face}");
    assert_eq!(set_of(&h.board, "1.0.1.2"), before);
}

/// AUTH-2.113's residence read is PER SUBJECT: the given account's genesis
/// is homed in the giver's own doc 1 and lies within the giver's span, yet
/// the giver's records name none of its keys; and the given account's
/// records are its genesis alone, never the giver's above it.
#[test]
fn the_givers_read_holds_none_of_the_given_accounts_records() {
    let dir = tempfile::tempdir().unwrap();
    let h = handed_off(dir.path());
    let given: Vec<Fingerprint> = parse_enroll(h.taken.record.as_bytes()).unwrap().iter().map(|e| Fingerprint::of(&e.key)).collect();
    let giver = credential_records(&h.board, "1.0.1", &[]).unwrap();
    let named: Vec<Fingerprint> = giver.records.iter().flat_map(|r| r.enrolled.iter().map(|e| Fingerprint::of(&e.key)).chain(r.retired.iter().copied())).collect();
    assert!(!given.iter().any(|fp| named.contains(fp)), "the giver's read names the given account's keys: {:?}", giver.records.iter().map(|r| &r.link).collect::<Vec<_>>());
    let recipient = credential_records(&h.board, "1.0.1.2", &[]).unwrap();
    assert_eq!(recipient.records.iter().map(|r| r.sigless.as_str()).collect::<Vec<_>>(), [h.taken.record.as_str()]);
}

/// THE LATCH's test, client-side FIRST (AUTH-2.71): a payload naming a key
/// of the set that opens the subdivision is refused before anything is
/// compared or written — the board's own latch refuses only at the link,
/// the atom already inserted into the giver's published doc 1 for good.
#[test]
fn a_payload_naming_a_key_of_the_set_above_is_refused_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let giver = FileStore::open(dir.path().join("giver"));
    let giver_fp = keygen(&giver, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &giver, &anchors);
    let HandoffOutcome::Delegated { .. } = handoff(&board, &giver, &mut Scripted::new(vec![]), &give("1.0.1.2", None, None)).unwrap() else { panic!("beat (a)") };
    let own = encode_enroll(&[entry_of(&key_file(&giver, &giver_fp), "notebook")]);
    let (kept, _) = anchor_file(&anchors, "a");
    let before = board.health().unwrap().log_position();
    // The answers the walk would ask for, every one, were it to go on.
    let mut p = Scripted::new(vec![Script::Confirm(true), Script::Typed("1.0.1.2".into()), Script::KeptOrPlaced(KeptOrPlaced::Kept), Script::YesNo(true)]);
    let err = handoff(&board, &giver, &mut p, &give("1.0.1.2", Some(own), Some(kept))).expect_err("the latch");
    let text = err.to_string();
    assert_eq!(err.exit_code(), 3, "{text}");
    assert!(text.contains("already stands in the set that opens 1.0.1.2") && text.contains("use THEIR keys"), "{text}");
    assert_eq!(board.health().unwrap().log_position(), before, "nothing was written");
    assert!(!p.said("CONSENT"), "nothing was compared:\n{}", p.transcript.join("\n"));
}

/// The recipient at a SERVED board (AUTH-5.60 step 4's table): no read
/// tells a hosted host from the giver's own org, so the beat ASKS (RES-45)
/// where `--hosted` says neither and renders each answer's operator
/// sentence; the history statement is the PUBLIC one (AUTH-5.85), never the
/// notebook's, and the giver is never named as the board's runner.
#[test]
fn the_recipient_at_a_served_board_is_asked_who_runs_it_and_told_the_history_is_public() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let local = board(sd.port());
    let giver = FileStore::open(dir.path().join("giver"));
    keygen(&giver, "notebook");
    claim(&local, &giver, &dir.path().join("anchors"));
    let HandoffOutcome::Delegated { .. } = handoff(&local, &giver, &mut Scripted::new(vec![]), &give("1.0.1.2", None, None)).unwrap() else { panic!("beat (a)") };
    let served = Board::new(Origin::parse("https://board.example").unwrap(), Redirect::to(origin_of(sd.port())));
    let asked = vec![Script::YesNo(true), Script::Label("phone".into()), Script::LabelDefault, Script::LabelDefault];
    let flagged = vec![Script::Label("tablet".into()), Script::LabelDefault, Script::LabelDefault];
    for (name, hosted, script, operator) in [
        ("asked", None, asked, "Whoever runs this board can read what you write here"),
        ("flagged", Some(false), flagged, "1.0.1's org runs this board"),
    ] {
        let out = dir.path().join(name);
        let mut p = Scripted::new(script);
        let opts = AcceptOptions { hosted, ..take("1.0.1.2", &out, false) };
        accept(&served, &FileStore::open(out.join("store")), &mut p, &opts).unwrap_or_else(|h| panic!("{name}: {h}\n{}", p.transcript.join("\n")));
        let t = p.transcript.join("\n");
        assert_eq!(p.said("this is a SERVED board"), hosted.is_none(), "{name}: asked only where `--hosted` says neither:\n{t}");
        assert!(p.said(operator), "{name}:\n{t}");
        assert!(p.said("is public history") && !p.said("this notebook's history is permanent"), "{name}:\n{t}");
        assert!(!p.said("1.0.1 runs this board"), "{name}:\n{t}");
    }
}

/// P13 in the first signed session (AUTH-5.87; AUTH-5.90 (iii)): where the
/// agent space `inc(account, 1)` was handed away before the account's first
/// signed session ran — the recipient of `1.0.1.2` handing `1.0.1.2.1` on
/// before its own `skep bind` — op (3)'s key stands in neither list of the
/// set that opens it, and the setup state is sent NOT AT ALL: no
/// `delegate`, no mint, no session as the agent space.
#[test]
fn the_setup_act_is_sent_not_at_all_where_the_first_child_is_another_partys() {
    let dir = tempfile::tempdir().unwrap();
    let h = handed_off(dir.path());
    h.recipient.bind(&Binding::Enrollment { origin: h.board.dialed().clone(), principal: h.principal, account: "1.0.1.2".into(), fingerprint: h.taken.device }).unwrap();
    let hand_on = |payload: Option<String>, anchor: Option<PathBuf>| HandoffOptions { principal: h.principal, account: "1.0.1.2.1".into(), payload: payload.map(|p| format!("{p}\n").into_bytes()), anchor };
    let beat_a = handoff(&h.board, &h.recipient, &mut Scripted::new(vec![]), &hand_on(None, None)).unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(beat_a, HandoffOutcome::Delegated { .. }), "{beat_a:?}");
    let third = FileStore::open(dir.path().join("third"));
    let script = vec![Script::Label("tablet".into()), Script::LabelDefault, Script::LabelDefault];
    let handed = accept(&h.board, &third, &mut Scripted::new(script), &take("1.0.1.2.1", &dir.path().join("third-papers"), false)).unwrap();
    let (paper, _) = anchor_file(dir.path(), "ra");
    let mut p = Scripted::new(vec![Script::Confirm(true), Script::Typed("1.0.1.2.1".into()), Script::KeptOrPlaced(KeptOrPlaced::Kept), Script::YesNo(true)]);
    let seeded = handoff(&h.board, &h.recipient, &mut p, &hand_on(Some(handed.record), Some(paper))).unwrap_or_else(|e| panic!("{e}\n{}", p.transcript.join("\n")));
    assert!(matches!(seeded, HandoffOutcome::Seeded { .. }), "{seeded:?}");
    // The recipient's first signed session, at last.
    let reads = FirstSessionReads::take(&h.board, "1.0.1.2", &h.taken.device, Some(&h.recipient)).unwrap();
    assert_eq!(reads.key_opens_agent_space, Some(KeyDiagnosis::Neither));
    assert!(reads.setup_owed(), "the agent space's home stands nowhere");
    let device = key_file(&h.recipient, &h.taken.device).signer();
    let (rb, log) = recording_board(h.board.dialed().clone());
    let session = handshake(&rb, Scope::Content, &device, h.principal, Site::Tail).unwrap();
    log.lock().unwrap().clear();
    let done = first_session(&rb, &reads, &session, &device, Some(&h.recipient)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((done.setup_skipped, done.minted_home, done.minted_agent_space_home), (Some(KeyDiagnosis::Neither), false, false));
    let lines = log.lock().unwrap().clone();
    assert!(!lines.iter().any(|l| l.starts_with("GET /challenge") || l == "POST /op create_new_document" || l == "POST /op delegate"), "{lines:?}");
    session.close().unwrap();
}
