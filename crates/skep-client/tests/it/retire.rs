//! `retire` (`client.md` §4a.4; §2.2): another device's key retired from
//! this one's session with its label shown; the session's OWN key retired
//! with no close sent and the expected end's fork; an anchor prefix refused
//! ahead of any frame; an ambiguous prefix listed; the LAST-DEVICE line; the
//! ANCHORLESS account's unwritable preview with no confirmation; the store
//! unchanged; `no` and a wrong row; a retirement sent again reconciled; the
//! redirect from an account that opens by reference.

use skep_client::board::{KeySetAnswer, Scope};
use skep_client::ceremony::claim::{hosted, HostedOutcome};
use skep_client::ceremony::deposit::{deposit, Deposit, DepositKind, DepositOutcome};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::ceremony::retire::{retire, RetireEnd, RetireOptions};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::store::{Binding, FileStore, KeyStore};
use skep_identity::{encode_enroll, Enrollment};

use crate::common::{board, claim, entry_of, key_file, keygen, recording_board, spawn};

fn opts(prefix: &str) -> RetireOptions {
    RetireOptions { principal: 1, fingerprint_prefix: prefix.into() }
}

fn store_snapshot(store: &FileStore) -> (usize, usize) {
    (store.list().unwrap().len(), store.all_bindings().unwrap().len())
}

#[test]
fn retire_another_devices_key_then_the_sessions_own_without_a_close() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let plain = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&plain, &store, &dir.path().join("anchors"));
    let a = key_file(&store, &fp).signer();
    // A second device's key, enrolled from A's session (the hop's shape).
    let store_b = FileStore::open(dir.path().join("b"));
    let fp_b = keygen(&store_b, "phone");
    let full = handshake(&plain, Scope::Full, &a, 1, Site::Session).unwrap();
    deposit(&plain, full.token(), &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Enroll(vec![entry_of(&key_file(&store_b, &fp_b), "phone")]), hand: Some(&a), id: "test.enroll-b" }).unwrap();
    full.close().unwrap();
    let snapshot = store_snapshot(&store);

    // An ambiguous prefix: every match listed, never a pick.
    let mut person = Scripted::new(vec![]);
    let err = retire(&plain, &store, &mut person, &opts("")).expect_err("ambiguous");
    assert!(err.to_string().contains("matches more than one enrolled key") && err.to_string().contains("phone") && err.to_string().contains("notebook"), "{err}");
    // An anchor prefix: refused ahead of any frame.
    let (rb, log) = recording_board(plain.dialed().clone());
    let KeySetAnswer::Set(set) = plain.key_set("1.0.1").unwrap() else { panic!() };
    let anchor_fp = set.enrolled.iter().find(|e| e.anchor).unwrap().fingerprint;
    let mut person = Scripted::new(vec![]);
    let err = retire(&rb, &store, &mut person, &opts(&anchor_fp.to_hex()[..8])).expect_err("an anchor");
    assert!(err.to_string().contains("is an ANCHOR") && err.to_string().contains("--anchor-lost") && err.to_string().contains("LATER"), "{err}");
    assert!(!log.lock().unwrap().iter().any(|l| l.starts_with("GET /challenge")), "ahead of any frame: {:?}", log.lock().unwrap());
    // `no` writes nothing; a wrong row is re-asked.
    let mut person = Scripted::new(vec![Script::Typed("deadbeef".into()), Script::Confirm(false)]);
    let err = retire(&plain, &store, &mut person, &opts(&fp_b.to_hex()[..8])).expect_err("declined");
    assert!(err.to_string().contains("declined at the preview"), "{err}");
    assert!(person.said("is not the row this act names"), "a wrong row re-asked:\n{}", person.transcript.join("\n"));
    let KeySetAnswer::Set(set) = plain.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.enrolled(&fp_b).is_some(), "nothing written");

    // Another device's key retired from this one's session, its label shown.
    let (rb, log) = recording_board(plain.dialed().clone());
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let done = retire(&rb, &store, &mut person, &opts(&fp_b.to_hex()[..8])).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert_eq!((done.fingerprint, done.label.as_deref(), done.end.clone()), (fp_b, Some("phone"), RetireEnd::CloseSent));
    let t = person.transcript.join("\n");
    assert!(person.said("label: phone"), "{t}");
    for clause in ["AUTH-5.46 (1)", "AUTH-5.46 (2)", "AUTH-5.46 (3)", "AUTH-5.46 (4)"] {
        assert!(person.said(clause), "{clause}:\n{t}");
    }
    assert!(person.said("THE REACH: the board names no other set"), "{t}");
    assert!(log.lock().unwrap().iter().any(|l| l == "POST /session/close"), "the session closed");
    assert_eq!(store_snapshot(&store), snapshot, "the store unchanged (§9 item 36)");
    let KeySetAnswer::Set(set) = plain.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.retired(&fp_b).is_some());

    // The session's OWN key — the last device key: the last-device line in
    // the preview, no close sent, the keyless face named.
    let (rb, log) = recording_board(plain.dialed().clone());
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let done = retire(&rb, &store, &mut person, &opts(&fp.to_hex()[..8])).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert_eq!(done.end, RetireEnd::EndedByCommit { another_held: false });
    let t = person.transcript.join("\n");
    assert!(person.said("THE LAST DEVICE KEY") && person.said("skep recover"), "{t}");
    assert!(person.said("this session's own key was retired") && person.said("skep keygen`, then `skep recover`"), "{t}");
    let lines = log.lock().unwrap().clone();
    assert!(!lines.iter().any(|l| l == "POST /session/close"), "NO close sent: {lines:?}");
    assert_eq!(store_snapshot(&store), snapshot);
    let KeySetAnswer::Set(set) = plain.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.retired(&fp).is_some() && set.enrolled.iter().all(|e| e.anchor));
    // The dead token: the next request's `closed` is the expected end; a
    // new session with the retired key never opens.
    let err = handshake(&plain, Scope::Content, &a, 1, Site::Session).expect_err("retired");
    assert!(err.to_string().contains("is retired"), "{err}");
}

/// The fork where another enrolled key IS held: `skep session` named; and
/// the ANCHORLESS one-key account: the preview says the write is unreachable,
/// names the hop, and takes NO confirmation.
#[test]
fn the_own_key_fork_names_session_where_another_key_is_held_and_an_anchorless_account_takes_no_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let a = key_file(&store, &fp).signer();
    let fp2 = keygen(&store, "second laptop");
    let full = handshake(&board, Scope::Full, &a, 1, Site::Session).unwrap();
    deposit(&board, full.token(), &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Enroll(vec![entry_of(&key_file(&store, &fp2), "second laptop")]), hand: Some(&a), id: "test.enroll-2" }).unwrap();
    full.close().unwrap();
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let done = retire(&board, &store, &mut person, &opts(&fp.to_hex()[..8])).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert_eq!(done.end, RetireEnd::EndedByCommit { another_held: true });
    assert!(person.said("the next act is a sign-in with the key you still hold: `skep session`"), "{}", person.transcript.join("\n"));
    assert!(!person.said("THE LAST DEVICE KEY"), "another device key stands");

    // The anchorless account: a `--hosted` one-key claim.
    let dir2 = tempfile::tempdir().unwrap();
    let sd2 = spawn(&dir2.path().join("board"), false);
    let board2 = crate::common::board(sd2.port());
    let store2 = FileStore::open(dir2.path().join("store"));
    let lone = keygen(&store2, "lone");
    let payload = encode_enroll(&[Enrollment::new(key_file(&store2, &lone).public.clone(), false, Some("lone".into())).unwrap()]);
    let HostedOutcome::Claimed(_) = hosted(&board2, payload.as_bytes(), 1).unwrap() else { panic!() };
    store2.bind(&Binding::Enrollment { origin: board2.dialed().clone(), principal: 1, account: "1.0.1".into(), fingerprint: lone }).unwrap();
    let mut person = Scripted::new(vec![]);
    let err = retire(&board2, &store2, &mut person, &opts(&lone.to_hex()[..8])).expect_err("unwritable");
    let t = person.transcript.join("\n");
    assert!(person.said("THIS RETIREMENT CANNOT BE WRITTEN AT ALL") && person.said("skep keygen --payload"), "the hop named:\n{t}");
    assert!(!person.said("CONSENT confirm"), "NO confirmation taken:\n{t}");
    assert!(err.to_string().contains("would_empty"), "{err}");
    assert_eq!(err.exit_code(), 3);
    let KeySetAnswer::Set(set) = board2.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.enrolled(&lone).is_some(), "nothing written");
}

/// AUTH-5.17's reconcile at a retirement's resume: a retirement sent again
/// after its commit — its ack lost — meets `nothing_changed`, read against
/// the set: the key stands retired, so the act COMMITTED, never "failed".
#[test]
fn a_retirement_sent_again_after_its_commit_is_reconciled() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let a = key_file(&store, &fp).signer();
    let store_b = FileStore::open(dir.path().join("b"));
    let fp_b = keygen(&store_b, "phone");
    let full = handshake(&board, Scope::Full, &a, 1, Site::Session).unwrap();
    deposit(&board, full.token(), &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Enroll(vec![entry_of(&key_file(&store_b, &fp_b), "phone")]), hand: Some(&a), id: "test.enroll-b" }).unwrap();
    let retire_b = |id: &str| deposit(&board, full.token(), &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Retire(vec![fp_b]), hand: Some(&a), id });
    let first = retire_b("test.retire-b");
    assert!(matches!(first, Ok(DepositOutcome::Deposited { .. })), "{first:?}");
    let again = retire_b("test.retire-b-again");
    let Ok(DepositOutcome::Committed { reason }) = again else { panic!("{again:?}") };
    assert!(reason.contains("nothing_changed") && reason.contains("the fingerprints stand retired"), "{reason}");
    full.close().unwrap();
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.retired(&fp_b).is_some());
}

/// The REDIRECT of a retirement at an account that opens by reference
/// (`not_holder_retirement`'s, AUTH-3.56): named as the agent space, which
/// holds no set of its own, the walk retires the key at `1.0.1`, where it
/// stands as that account's own, from a session AS `1.0.1`.
#[test]
fn a_retirement_from_an_account_that_opens_by_reference_is_made_at_the_set_account() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let a = key_file(&store, &fp).signer();
    let store_b = FileStore::open(dir.path().join("b"));
    let fp_b = keygen(&store_b, "phone");
    let full = handshake(&board, Scope::Full, &a, 1, Site::Session).unwrap();
    deposit(&board, full.token(), &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Enroll(vec![entry_of(&key_file(&store_b, &fp_b), "phone")]), hand: Some(&a), id: "test.enroll-b" }).unwrap();
    full.close().unwrap();
    let agent_space = store.persisted_new_id(board.dialed(), "1.0.1.1").unwrap().expect("the agent space's line");
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let done = retire(&board, &store, &mut person, &RetireOptions { principal: agent_space, fingerprint_prefix: fp_b.to_hex()[..8].to_string() })
        .unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert_eq!((done.account.as_str(), done.fingerprint, done.end), ("1.0.1", fp_b, RetireEnd::CloseSent));
    assert!(person.said("`not_holder_retirement`'s redirect"), "{}", person.transcript.join("\n"));
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.retired(&fp_b).is_some());
}
