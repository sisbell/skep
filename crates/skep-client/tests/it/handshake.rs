//! THE HANDSHAKE against the real daemon: AUTH-5.65's pre-check AHEAD OF
//! EVERY `/challenge` (both arms; the recording dialer pins the order), and
//! the key arm's three states — the retired state's hand read from the
//! records written at the RECORD GRADE.

use skep_client::board::{KeySetAnswer, Scope};
use skep_client::ceremony::deposit::{deposit, Deposit, DepositKind, DepositOutcome, Grade};
use skep_client::ceremony::handshake::{handshake, key_face, Site};
use skep_client::derive::records::{credential_records, Hand, Kind};
use skep_client::derive::{precheck, KeyDiagnosis};
use skep_client::sign::signer_from_seed;
use skep_client::store::FileStore;
use skep_client::Origin;
use skep_identity::{Enrollment, Fingerprint};
use skep_signature::HybridSigner;

use crate::common::{board, claim, keygen, recording_board, spawn};

/// AUTH-5.65: the pre-check's two reads run AHEAD of the `/challenge`, and a
/// key in neither list — or an origin the signed list lacks — fetches NO
/// challenge: no nonce is spent on a sign-in that cannot succeed.
/// MUTATION 2: with the pre-check removed the failing arms fetch a challenge
/// and this test fails on the dial log.
#[test]
fn the_pre_check_runs_ahead_of_every_challenge_and_a_failing_arm_spends_no_nonce() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), false);
    let plain = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&plain, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).unwrap().signer();

    // The enrolled key: health, principal_prefix, key_set, THEN the challenge.
    let (rb, log) = recording_board(plain.dialed.clone());
    let session = handshake(&rb, Scope::Content, &device, 1, Site::Session).expect("a session");
    let lines = log.lock().unwrap().clone();
    let at = |needle: &str| lines.iter().position(|l| l.starts_with(needle)).unwrap_or_else(|| panic!("{needle} missing from {lines:?}"));
    assert!(at("GET /health") < at("POST /op principal_prefix"), "{lines:?}");
    assert!(at("POST /op principal_prefix") < at("POST /op key_set"), "{lines:?}");
    assert!(at("POST /op key_set") < at("GET /challenge"), "the reads AHEAD of the challenge: {lines:?}");
    assert!(at("GET /challenge") < at("POST /session"), "{lines:?}");
    assert_eq!(lines.iter().filter(|l| l.starts_with("GET /challenge")).count(), 1, "one challenge, one session");
    session.close(&rb).unwrap();

    // The key arm's third state: a key in neither list — no challenge.
    let stranger = signer_from_seed(&[77; 32]);
    let (rb, log) = recording_board(plain.dialed.clone());
    let err = handshake(&rb, Scope::Content, &stranger, 1, Site::Session).expect_err("neither list");
    let text = err.to_string();
    assert!(text.contains("records do not list this key") && text.contains("AUTH-5.25 cell (iii)"), "{text}");
    let lines = log.lock().unwrap().clone();
    assert!(lines.iter().any(|l| l.starts_with("POST /op key_set")), "the set was read: {lines:?}");
    assert!(!lines.iter().any(|l| l.starts_with("GET /challenge")), "NO nonce spent: {lines:?}");
    assert!(!lines.iter().any(|l| l.starts_with("POST /session")), "{lines:?}");

    // The origin arm FIRST (AUTH-5.24): a loopback alias the signed list
    // lacks halts with the ORIGIN STATE before any read of the principal.
    let alias = Origin::parse(&format!("http://localhost:{}", sd.port())).unwrap();
    let (rb, log) = recording_board(alias);
    let err = handshake(&rb, Scope::Content, &device, 1, Site::Session).expect_err("origin arm");
    let text = err.to_string();
    assert!(text.contains("does not accept signed sessions at this origin") && text.contains("signed_origins"), "{text}");
    let lines = log.lock().unwrap().clone();
    assert_eq!(lines, vec!["GET /health".to_string()], "the origin arm halts off /health alone: {lines:?}");

    // A principal never delegated: the delegation-never-committed cell.
    let err = handshake(&plain, Scope::Content, &device, 77, Site::Session).expect_err("no such principal");
    assert!(err.to_string().contains("not a registered account"), "{err}");
}

/// THE RECORD GRADE against the daemon: a second key enrolled from a FULL
/// session (the record's `sig` over the entry frame with `H.1`'s pair) and
/// retired the same way; the retired state's face names THE HAND and THE
/// POSITION from the admitted read (AUTH-5.28's own-key chrome).
#[test]
fn a_retired_key_is_diagnosed_with_its_hand_read_from_the_records() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let file = store.load(&store.key_path(&fp)).unwrap();
    let device = file.signer();
    let second = signer_from_seed(&[5; 32]);
    let second_fp = Fingerprint::of(HybridSigner::public_key(&second));

    let full = handshake(&board, Scope::Full, &device, 1, Site::Session).expect("a full session");
    // ENROL the second key, device grade, the device key's hand.
    let out = deposit(
        &board,
        &full.token,
        &Deposit {
            home: "1.0.1.0.1",
            subject: "1.0.1",
            kind: DepositKind::Enroll(vec![Enrollment::new(HybridSigner::public_key(&second).clone(), false, Some("second device".into())).unwrap()]),
            grade: Grade::Device,
            hand: Some(&device),
            id: "test.enroll",
        },
    )
    .expect("the enrolment");
    let DepositOutcome::Deposited { at: enrolled_at, .. } = out else { panic!("{out:?}") };
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.enrolled(&second_fp).is_some(), "enrolled");
    // The second key opens a session now.
    let as_second = handshake(&board, Scope::Content, &second, 1, Site::Session).expect("the second key signs in");
    as_second.close(&board).unwrap();
    // RETIRE it.
    let out = deposit(&board, &full.token, &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Retire(vec![second_fp]), grade: Grade::Device, hand: Some(&device), id: "test.retire" }).expect("the retirement");
    let DepositOutcome::Deposited { at: retired_at, .. } = out else { panic!("{out:?}") };
    assert!(retired_at > enrolled_at);
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.retired(&second_fp).is_some() && set.enrolled(&second_fp).is_none(), "retired");
    full.close(&board).unwrap();

    // The pre-check's diagnosis and the face.
    let pre = precheck(&board, 1, &second_fp).unwrap();
    assert_eq!(pre.diagnosis, KeyDiagnosis::Retired { anchor: false });
    let err = key_face(&board, &pre, &second_fp, &[(fp, file.public.clone())], Site::Session).expect_err("retired");
    let text = err.to_string();
    assert!(text.contains("is retired at account 1.0.1"), "{text}");
    assert!(text.contains(&format!("retired at position {retired_at} by {fp} (notebook)")), "the hand and the position from the records: {text}");
    assert!(text.contains("this store's own key — the person did this (AUTH-5.28)"), "{text}");
    assert!(text.contains("second device"), "the retired key's label (AUTH-5.69): {text}");
    assert!(text.contains("I4 (AUTH-2.98)") && text.contains("fresh keypair under a new byline"), "{text}");
    // The handshake composition halts the same way, and spends no nonce.
    let err = handshake(&board, Scope::Content, &second, 1, Site::Session).expect_err("retired keys never re-enter");
    assert!(err.to_string().contains("is retired"), "{err}");

    // THE ADMITTED READ: three records, hands and positions.
    let records = credential_records(&board, "1.0.1", &[(fp, file.public.clone())]).expect("the read");
    assert!(records.claimed && records.claim_entry.is_some());
    let kinds: Vec<Kind> = records.records.iter().map(|r| r.kind).collect();
    assert_eq!(kinds, [Kind::Enroll, Kind::Enroll, Kind::Retire]);
    let genesis = records.genesis().unwrap();
    assert_eq!(genesis.hand, Hand::Bare, "the ceremony's genesis: a bare session's testimony");
    assert!(genesis.sig.is_none() && genesis.anchor_grade);
    assert!(genesis.position.is_some_and(|p| p < records.claim_entry.unwrap()), "the genesis lies below the claim entry");
    let enroll = &records.records[1];
    assert_eq!((enroll.hand.clone(), enroll.position), (Hand::Key(fp), Some(enrolled_at)));
    assert!(enroll.sig.is_some() && !enroll.anchor_grade);
    let retire = &records.records[2];
    assert_eq!((retire.hand.clone(), retire.position, retire.retired.clone()), (Hand::Key(fp), Some(retired_at), vec![second_fp]));
    assert_eq!(records.label_of(&second_fp).as_deref(), Some("second device"));
}
