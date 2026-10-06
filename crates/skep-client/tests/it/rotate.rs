//! `rotate` (`client.md` §4a.8 T0–T5; AUTH-5.59's device arm): the new key
//! enrolled, the trail from the OLD enroll link (the genesis link at the
//! notebook) to the new, the old key retired with no close sent, the binding
//! appended; a re-run after T3 writes NO second trail; the `--payload` arm;
//! the box prefilled from the retiring key's label; the reach naming an
//! account the gesture will not close; a `closed` before T4 faced with the
//! hand named.

use skep_client::board::{frames, Answer, KeySetAnswer, Scope, T_SUPERSEDES};
use skep_client::ceremony::deposit::{deposit, Deposit, DepositKind, DepositOutcome};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::ceremony::rotate::{rotate, RotateOptions};
use skep_client::ceremony::trail::write_trail;
use skep_client::derive::records::credential_records;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::Label;
use skep_client::store::{Binding, FileStore, KeyStore};
use skep_identity::{encode_enroll, Enrollment, Fingerprint};
use skep_signature::HybridSigner;

use crate::common::{anchor_file, board, claim, entry_of, fp_of, key_file, keygen, recording_board, spawn, wire_delegate, wire_enroll, wire_retire, wire_session, Hooked};

fn opts(label: Option<&str>, payload: Option<&str>) -> RotateOptions {
    RotateOptions { principal: 1, label: label.map(str::to_string), payload: payload.map(|p| format!("{p}\n").into_bytes()) }
}

/// The supersession claims FROM `old`.
fn claims_from(board: &skep_client::board::Board, old: &str) -> Vec<String> {
    let Answer::Document(v) = board.op(None, &frames::find_links_ftt_from(T_SUPERSEDES, old)).unwrap() else { panic!() };
    v["addrs"].as_array().unwrap().iter().filter_map(|a| a.as_str().map(str::to_string)).collect()
}

#[test]
fn rotate_runs_t0_to_t5_and_a_re_run_after_t3_writes_no_second_trail() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let plain = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let old_fp = keygen(&store, "notebook");
    claim(&plain, &store, &dir.path().join("anchors"));
    let genesis_link = credential_records(&plain, "1.0.1", &[]).unwrap().genesis().unwrap().link.clone();
    let (rb, log) = recording_board(plain.dialed.clone());
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::Confirm(true)]);
    let done = rotate(&rb, &store, &mut person, &opts(None, None)).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    let t = person.transcript.join("\n");
    // T1: the box prefilled from the retiring key's label.
    assert!(person.said("prefilled from the retiring key's label (`notebook`)"), "{t}");
    assert!(person.said("PUBLIC label [name the NEW device]"), "{t}");
    assert!(!person.said("ENROLLMENT PREVIEW"), "no enrollment preview beside the retirement's (the asymmetry with R3)");
    for clause in ["AUTH-5.46 (1)", "AUTH-5.46 (2)", "AUTH-5.46 (3)", "AUTH-5.46 (4)"] {
        assert!(person.said(clause), "{clause}:\n{t}");
    }
    // T2–T5.
    assert_eq!(done.old, old_fp);
    let KeySetAnswer::Set(set) = plain.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.enrolled(&done.new).is_some_and(|e| !e.anchor) && set.retired(&old_fp).is_some());
    let records = credential_records(&plain, "1.0.1", &[]).unwrap();
    assert_eq!(records.label_of(&done.new).as_deref(), Some("notebook"), "the label the box fixed (prefilled, taken)");
    let new_link = records.records.iter().find(|r| r.enrolled.iter().any(|e| Fingerprint::of(&e.key) == done.new)).unwrap().link.clone();
    let claims = claims_from(&plain, &genesis_link);
    assert_eq!(claims, vec![done.trail.clone()], "ONE trail from the genesis link");
    let Answer::Document(lv) = plain.op(None, &frames::read_link(&done.trail)).unwrap() else { panic!() };
    assert_eq!(lv["link"]["slots"][1][0]["start"].as_str(), Some(new_link.as_str()), "to the NEW enroll link: {lv}");
    assert!(person.said("the supersession trail is written") && person.said("attested by the old key"), "{t}");
    let lines = log.lock().unwrap().clone();
    assert!(lines.iter().any(|l| l == "POST /op assert_sup"), "{lines:?}");
    assert!(!lines.iter().any(|l| l == "POST /session/close"), "no close sent: {lines:?}");
    assert!(person.said("ROTATION'S EXPECTED END"), "{t}");
    assert_eq!(store.enrollment_for(&plain.dialed, 1).unwrap().map(|(_, fp)| fp), Some(done.new), "the binding appended for the new key");
    assert!(store.key_path(&old_fp).is_file(), "the retired key's file left in place");
    handshake(&plain, Scope::Content, &key_file(&store, &done.new).signer(), 1, Site::Session).expect("the new key signs in").close().unwrap();

    // THE RE-RUN AFTER T3: a board where T2 and T3 stand and T4 does not —
    // the walk resumes, writes NO second trail, retires the old key.
    // MUTATION 3: with the trail-presence read removed a second assert_sup
    // lands and `claims_from` answers two.
    let dir2 = tempfile::tempdir().unwrap();
    let sd2 = spawn(&dir2.path().join("board"), false);
    let board2 = board(sd2.port());
    let store2 = FileStore::open(dir2.path().join("store"));
    let old2 = keygen(&store2, "desk");
    claim(&board2, &store2, &dir2.path().join("anchors"));
    let old_signer = key_file(&store2, &old2).signer();
    let genesis2 = credential_records(&board2, "1.0.1", &[]).unwrap().genesis().unwrap().link.clone();
    let new2 = store2.generate(Some(Label::new("desk").unwrap())).unwrap().0;
    let full = handshake(&board2, Scope::Full, &old_signer, 1, Site::Session).unwrap();
    let DepositOutcome::Deposited { link: new_link2, .. } = deposit(&board2, &full.token, &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Enroll(vec![entry_of(&key_file(&store2, &new2), "desk")]), hand: Some(&old_signer), id: "test.t2" }).unwrap() else { panic!() };
    let trail2 = write_trail(&board2, &full, &old_signer, "1.0.1.0.1", &genesis2, &new_link2, "test.t3").expect("T3 by hand");
    full.close().unwrap();
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let done2 = rotate(&board2, &store2, &mut person, &opts(None, None)).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    let t = person.transcript.join("\n");
    assert!(person.said("T2 stands done, read off `key_set`"), "{t}");
    assert!(person.said("the trail already stands") && person.said("no second trail is written"), "{t}");
    assert!(!person.said("PUBLIC label"), "the box is not asked on a resume");
    assert_eq!((done2.old, done2.new, done2.trail.as_str()), (old2, new2, trail2.as_str()));
    assert_eq!(claims_from(&board2, &genesis2).len(), 1, "NO second trail");
    let KeySetAnswer::Set(set) = board2.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.retired(&old2).is_some());
}

/// The `--payload` arm: the new key carried in from another device,
/// compared as `enroll` compares it, no binding appended here, the facts
/// answered for `skep bind`; and THE REACH naming an account handed off
/// beneath whose set holds the old key as the act that exists there.
#[test]
fn the_payload_arm_appends_no_binding_and_the_reach_names_an_admitted_account() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let old_fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let old = key_file(&store, &old_fp).signer();
    // A subdivision handed off beneath (anchor-grade), whose holder then
    // enrolled the OLD key there as a co-holder: the closure admits it.
    let as_owner = wire_session(&board, 1, &old);
    wire_delegate(&board, &as_owner, "1.0.1.2", 777).unwrap();
    board.session_close(&as_owner).unwrap();
    let (_, kept) = anchor_file(&dir.path().join("anchors"), "a");
    let anchor = kept.signer();
    let as_anchor = wire_session(&board, 1, &anchor);
    let friend = HybridSigner::from_seed(1, &[91; 32]).unwrap();
    wire_enroll(&board, &as_anchor, &anchor, "1.0.1.0.1", "1.0.1.2", &[Enrollment::new(HybridSigner::public_key(&friend).clone(), false, Some("friend".into())).unwrap()]).expect("the handoff");
    board.session_close(&as_anchor).unwrap();
    let as_friend = wire_session(&board, 777, &friend);
    let Answer::Document(_) = board.op(Some(&as_friend), &frames::create_home("1.0.1.2", None)).unwrap() else { panic!() };
    wire_enroll(&board, &as_friend, &friend, "1.0.1.2.0.1", "1.0.1.2", &[Enrollment::new(HybridSigner::public_key(&old).clone(), false, Some("the giver's old key".into())).unwrap()]).expect("the co-holder");
    board.session_close(&as_friend).unwrap();
    // The payload from the new device.
    let store_b = FileStore::open(dir.path().join("b"));
    let fp_b = keygen(&store_b, "new laptop");
    let payload = encode_enroll(&[entry_of(&key_file(&store_b, &fp_b), "new laptop")]);
    let lines_before = store.all_bindings().unwrap().len();
    let mut person = Scripted::new(vec![Script::Confirm(true), Script::Confirm(true)]);
    let done = rotate(&board, &store, &mut person, &opts(None, Some(&payload))).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    let t = person.transcript.join("\n");
    assert_eq!((done.old, done.new), (old_fp, fp_b));
    assert!(done.binding_line.is_none() && store.all_bindings().unwrap().len() == lines_before, "no binding on the payload arm");
    assert_eq!((done.facts.account.as_str(), done.facts.principal), ("1.0.1", 1));
    assert!(person.said("key to enroll — fingerprint re-derived") && person.said("new laptop") && person.said("CONSENT confirm: `skep rotate --payload`"), "{t}");
    assert!(person.said("uncorrectable once enrolled"), "{t}");
    assert!(person.said("THE REACH: this gesture will NOT close 1.0.1.2") && person.said("retire the key THERE"), "the admitted account named:\n{t}");
    // B binds and signs in.
    store_b.bind(&Binding::Enrollment { origin: board.dialed.clone(), principal: 1, account: "1.0.1".into(), fingerprint: fp_b }).unwrap();
    handshake(&board, Scope::Content, &key_file(&store_b, &fp_b).signer(), 1, Site::Session).expect("B signs in").close().unwrap();
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.retired(&old_fp).is_some() && set.enrolled(&fp_b).is_some());
}

/// A `closed` BEFORE T4 — the old key retired by another hand under the
/// walk — is faced per AUTH-5.77 with that hand named.
#[test]
fn a_closed_before_t4_names_the_other_hand() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let old_fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let old = key_file(&store, &old_fp).signer();
    // Another device of the person's, enrolled.
    let other = HybridSigner::from_seed(1, &[77; 32]).unwrap();
    let other_fp = fp_of(&other);
    let full = handshake(&board, Scope::Full, &old, 1, Site::Session).unwrap();
    deposit(&board, &full.token, &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Enroll(vec![Enrollment::new(HybridSigner::public_key(&other).clone(), false, Some("tablet".into())).unwrap()]), hand: Some(&old), id: "test.other" }).unwrap();
    full.close().unwrap();
    // Under the walk — the OLD key's session open, the new key's file just
    // written, T2's insert not yet sent — the other hand retires the old key.
    let hand_board = crate::common::board(sd.port());
    let mut person = Hooked::new(vec![Script::LabelDefault, Script::Confirm(true)]);
    person.on_say = Box::new(move |rule, _| {
        if rule == "§3a" {
            let token = wire_session(&hand_board, 1, &other);
            wire_retire(&hand_board, &token, &other, "1.0.1.0.1", "1.0.1", &[old_fp]).expect("the other hand's retirement");
        }
    });
    let err = rotate(&board, &store, &mut person, &opts(None, None)).expect_err("closed before T4");
    let text = err.to_string();
    assert!(text.contains("retired under this walk") && text.contains("ANOTHER hand (AUTH-5.77)") && text.contains(&other_fp.to_string()) && text.contains("tablet"), "{text}");
    assert!(!person.inner.said("the supersession trail is written"), "halted at the first undone state");
}
