//! THE HANDOFF DOOR (`client.md` §4c; AUTH-5.90): the giver's beat (a)
//! idempotent; the recipient's beat with its backup moment in the HANDOFF
//! venue; `accept`'s halts at an undelegated and a seeded address; the
//! decline arm; `--reprint`; the giver's genesis homed in X's doc 1 at the
//! anchor grade; the ownership halt; the depth-2 genesis by reference; G5's
//! retry; the giver's session as the given account dead; the recipient's
//! `bind`; the top-level halt; the anchorless line.

use skep_client::board::{KeySetAnswer, Scope};
use skep_client::ceremony::accept::{accept, reprint, AcceptOptions};
use skep_client::ceremony::first_session::{document_present, first_session, FirstSessionReads};
use skep_client::ceremony::handoff::{handoff, Grade, HandoffOptions, HandoffOutcome};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::derive::records::{credential_records, Hand};
use skep_client::derive::principal_of;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::person::KeptOrPlaced;
use skep_client::store::{Binding, FileStore, KeyStore};
use skep_identity::{encode_enroll, parse_enroll, Enrollment, Fingerprint};

use crate::common::{anchor_file, board, claim, files_in, key_file, keygen, spawn, token_dead, wire_session};

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
