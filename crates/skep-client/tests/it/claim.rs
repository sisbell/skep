//! THE CLAIM against the real daemon (`client.md` §4; the build brief §3):
//! THE LOOP, RESUME BY READING at AUTH-5.56's boundaries, the residue halt
//! that delegates nothing, the persisted `new_id` read back — or, spent on
//! another address, replaced — and the unclaimed board's `claim_first` met
//! by its own face.

use std::path::Path;

use skep_client::board::{acked_addr, frames, Answer, Board, KeySetAnswer, Opened, Scope, SessionBody, Token, T_CLAIM};
use skep_client::ceremony::backup::{backup_moment, BackupOptions, Venue};
use skep_client::ceremony::claim::{self, ClaimOutcome};
use skep_client::ceremony::deposit::{deposit, Deposit, DepositKind};
use skep_client::ceremony::handoff::{handoff, HandoffOptions};
use skep_client::ceremony::handshake::{handshake, key_face, Site};
use skep_client::derive::{precheck, principal_of, KeyDiagnosis, Mode};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::{Facts, KeyFile};
use skep_client::sign::signer_from_seed;
use skep_client::store::{Binding, FileStore, KeyStore};
use skep_identity::{Enrollment, Fingerprint};
use skep_signature::HybridSigner;

use crate::common::{board, claim, files_in, keygen, opts, spawn};

fn bare(board: &skep_client::board::Board, principal: u64) -> Token {
    match board.session_open(SessionBody::Bare { principal }).expect("bare session") {
        Opened::Token(t) => t,
        other => panic!("the bare bind answered {other:?}"),
    }
}

/// THE LOOP: keygen → claim → the claimant is ours; a second claim is the
/// OURS tail with the same facts; a CONTENT-scoped session opens and a
/// credential deposit under it answers `content_session`; the pre-check
/// passes; the mode derives from the pair.
#[test]
fn the_loop_claims_the_board_and_a_second_run_is_the_ours_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    let anchors = dir.path().join("anchors");

    let (done, person) = claim(&board, &store, &anchors);
    assert_eq!((done.account.as_str(), done.principal, done.fingerprint), ("1.0.1", 1, fp));
    assert_eq!(done.agent_space.as_deref(), Some("1.0.1.1"), "the setup act ran in the claim's own session (AUTH-5.87)");
    assert_eq!(done.display_name.as_deref(), Some("a display name"), "S9: collected and HELD");
    let health = board.health().expect("health");
    assert_eq!(health.claimant(), Some("1.0.1"));
    assert_eq!(Mode::of(&health), Mode::Enforcing, "local_trust false ⇒ ENFORCING (AUTH-5.86)");
    // The statements, in AUTH-5.55's order: S0′ before step 1, the three of
    // AUTH-5.54 at the backup's head, the boxes, the ladder, the per-site
    // line, the account-creation sentence.
    let order = ["AUTH-5.85", "AUTH-5.74", "AUTH-5.55 step 1", "AUTH-5.54 (a)", "AUTH-5.54 (b)", "AUTH-5.54 (c)", "name anchor a", "name anchor b", "AUTH-5.40", "AUTH-5.44 (notebook)", "AUTH-5.87"];
    let mut last = 0;
    for needle in order {
        let at = person.transcript.iter().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("{needle} missing from\n{}", person.transcript.join("\n")));
        assert!(at >= last, "{needle} out of order in\n{}", person.transcript.join("\n"));
        last = at;
    }
    assert!(person.said("(a) THIS KEY SET IS THIS IDENTITY AND THERE IS NO RESET"));
    assert!(person.said("TWO FILES, TWO PLACES YOU CONTROL"), "(b) keyed to the file path");
    assert!(person.sheets.is_empty() && person.dismissed == 0, "the file form prints no sheet");
    // The anchor files: anchors, with the three facts (AUTH-5.38).
    for which in ["a", "b"] {
        let files = files_in(&anchors.join(which));
        assert_eq!(files.len(), 1, "one anchor file in {which}");
        let name = files[0].file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("anchor-testhost-2026-10-04-") && name.ends_with(".skep-key"), "{name}");
        let file = KeyFile::parse(&std::fs::read(&files[0]).unwrap()).expect("a key file");
        assert!(file.anchor);
        assert_eq!((file.account.as_deref(), file.principal, file.origin.as_ref().map(|o| o.as_str().to_string())), (Some("1.0.1"), Some(1), Some(board.dialed.as_str().to_string())));
    }
    // The set: two anchors and the device key.
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!("not an account") };
    assert_eq!(set.enrolled.len(), 3);
    assert_eq!(set.enrolled.iter().filter(|e| e.anchor).count(), 2);
    assert!(set.enrolled(&fp).is_some_and(|e| !e.anchor));
    // The bindings: the account's line, and the agent space's persisted id.
    let bindings = store.all_bindings().unwrap();
    assert!(bindings.iter().any(|b| matches!(b, Binding::Enrollment { principal: 1, account, fingerprint, .. } if account == "1.0.1" && *fingerprint == fp)));
    let space_id = bindings
        .iter()
        .find_map(|b| match b {
            Binding::Enrollment { account, principal, .. } if account == "1.0.1.1" => Some(*principal),
            _ => None,
        })
        .expect("the agent space's binding line");
    assert_eq!(board.principal_prefix(space_id).unwrap().as_deref(), Some("1.0.1.1"), "the persisted new_id is the principal seated at the agent space");

    // THE SECOND RUN: the OURS tail — same facts, no backup moment, exit 0.
    let mut again = Scripted::new(vec![]);
    let outcome = claim::notebook(&board, &store, &mut again, &opts(&anchors)).expect("the tail");
    let ClaimOutcome::Ours(tail) = outcome else { panic!("{outcome:?}") };
    assert_eq!((tail.account.as_str(), tail.principal, tail.fingerprint, tail.agent_space.as_deref()), ("1.0.1", 1, fp, Some("1.0.1.1")));
    assert!(again.said("this board is already yours"));
    assert!(!again.said("name anchor") && !again.said("AUTH-5.54 (a)"), "no backup moment on the tail");
    assert_eq!(store.all_bindings().unwrap().len(), bindings.len(), "the tail binds nothing twice");
    assert_eq!(board.principal_prefix(space_id).unwrap().as_deref(), Some("1.0.1.1"));

    // A CONTENT-scoped session, and a credential deposit under it.
    let file = store.load(&store.key_path(&fp)).unwrap();
    let device = file.signer();
    let session = handshake(&board, Scope::Content, &device, 1, Site::Session).expect("a content session");
    assert_eq!(session.scope, Scope::Content);
    let extra = signer_from_seed(&[9; 32]);
    let err = deposit(
        &board,
        &session.token,
        &Deposit {
            home: "1.0.1.0.1",
            subject: "1.0.1",
            kind: DepositKind::Enroll(vec![Enrollment::new(HybridSigner::public_key(&extra).clone(), false, Some("second".into())).unwrap()]),
            hand: Some(&device),
            id: "test.enroll-under-content",
        },
    )
    .expect_err("a content session deposits nothing");
    assert!(err.to_string().contains("content_session"), "{err}");
    // The pre-check and the key face pass for the enrolled key.
    let pre = precheck(&board, 1, &fp).expect("pre-check");
    assert_eq!(pre.diagnosis, KeyDiagnosis::Enrolled { anchor: false });
    key_face(&board, &pre, &fp, &[(fp, file.public.clone())], Site::Session).expect("enrolled");
    session.close().expect("close");
}

/// AUTH-5.56 boundary 1: a walk interrupted after S1 (the delegate landed,
/// nothing else) RESUMES OVER THE DELEGATED ACCOUNT BY ADDRESS — nothing is
/// delegated again.
#[test]
fn a_claim_interrupted_after_s1_resumes_over_the_delegated_account_by_reading() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    // S1 by hand.
    let boot = bare(&board, 0);
    let Answer::Document(v) = board.op(Some(&boot), &frames::delegate("1.0.1", 1, None)).unwrap() else { panic!("closed") };
    assert_eq!(acked_addr(&v), Some("1.0.1"), "{v}");
    assert_eq!(board.next_account_prefix("1").unwrap().as_deref(), Some("1.0.2"));
    let (done, person) = claim(&board, &store, &dir.path().join("anchors"));
    assert_eq!((done.account.as_str(), done.principal, done.fingerprint), ("1.0.1", 1, fp));
    assert!(person.said("resuming over the delegated account 1.0.1 (principal 1) by reading"), "{}", person.transcript.join("\n"));
    assert_eq!(board.next_account_prefix("1").unwrap().as_deref(), Some("1.0.2"), "nothing delegated again");
    assert_eq!(board.health().unwrap().claimant(), Some("1.0.1"));
}

/// THE RESIDUE HALT (§4.4; the NO-DELEGATE-TWICE halt KEPT): past `1.0.2`
/// the walk halts naming the cure and DELEGATES NOTHING — the retry that
/// delegates again is the one that makes the board claimable by nobody.
/// MUTATION 1: with the halt removed this test fails on the frontier.
#[test]
fn pre_claim_residue_halts_and_delegates_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    keygen(&store, "notebook");
    let boot = bare(&board, 0);
    for (prefix, id) in [("1.0.1", 1u64), ("1.0.2", 2)] {
        let Answer::Document(v) = board.op(Some(&boot), &frames::delegate(prefix, id, None)).unwrap() else { panic!("closed") };
        assert_eq!(acked_addr(&v), Some(prefix), "{v}");
    }
    assert_eq!(board.next_account_prefix("1").unwrap().as_deref(), Some("1.0.3"));
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let err = claim::notebook(&board, &store, &mut person, &opts(&dir.path().join("anchors"))).expect_err("the residue halts");
    let text = err.to_string();
    assert!(text.contains("pre-claim residue") && text.contains("remove its data directory"), "{text}");
    assert_eq!(err.exit_code(), 3);
    assert_eq!(board.next_account_prefix("1").unwrap().as_deref(), Some("1.0.3"), "NOTHING was delegated");
    assert_eq!(board.health().unwrap().claimant(), None);
    assert!(!person.said("name anchor"), "no backup moment ran");
}

/// AUTH-5.56 boundary 3: a walk interrupted after S4 (the genesis landed, the
/// claim did not) RESUMES AT S5 off `key_set` — no backup moment, no second
/// genesis.
#[test]
fn a_claim_interrupted_after_s4_resumes_at_s5_off_key_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    let file = store.load(&store.key_path(&fp)).unwrap();
    // S1–S4 by hand, through the library's own compositions.
    let boot = bare(&board, 0);
    let Answer::Document(v) = board.op(Some(&boot), &frames::delegate("1.0.1", 1, None)).unwrap() else { panic!() };
    assert_eq!(acked_addr(&v), Some("1.0.1"));
    let owner = bare(&board, 1);
    let Answer::Document(v) = board.op(Some(&owner), &frames::create_home("1.0.1", None)).unwrap() else { panic!() };
    assert_eq!(acked_addr(&v), Some("1.0.1.0.1"), "{v}");
    let anchors = dir.path().join("anchors");
    let mut p = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let facts = Facts { account: "1.0.1".into(), principal: 1, origin: board.dialed.clone() };
    let backup = backup_moment(
        &mut p,
        &Venue::Notebook { facts },
        &BackupOptions { labels: vec![], destinations: vec![anchors.join("a"), anchors.join("b")], paper: false, store: Some(store.root().to_path_buf()), host_name: "h".into(), date: "d".into() },
    )
    .expect("the backup moment");
    let mut entries: Vec<Enrollment> = backup.anchors.iter().map(|a| Enrollment::new(a.public.clone(), true, Some(a.label.as_str().into())).unwrap()).collect();
    entries.push(Enrollment::new(file.public.clone(), false, Some("notebook".into())).unwrap());
    deposit(&board, &owner, &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Enroll(entries), hand: None, id: "test.genesis" }).expect("the genesis");
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert_eq!(set.enrolled.len(), 3);
    assert_eq!(board.health().unwrap().claimant(), None, "still unclaimed");
    // The walk, resumed.
    let mut person = Scripted::new(vec![]);
    let outcome = claim::notebook(&board, &store, &mut person, &opts(&anchors)).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    let ClaimOutcome::Ours(done) = outcome else { panic!("{outcome:?}") };
    assert_eq!((done.account.as_str(), done.principal, done.fingerprint), ("1.0.1", 1, fp));
    assert!(!person.said("name anchor") && !person.said("AUTH-5.54 (a)"), "S3 is not re-run:\n{}", person.transcript.join("\n"));
    assert!(person.said("AUTH-5.87"), "S5a's sentence");
    assert_eq!(board.health().unwrap().claimant(), Some("1.0.1"));
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert_eq!(set.enrolled.len(), 3, "no second genesis");
}

/// S1–S4 by hand, through the library's own compositions: the genesis lands
/// under the store's one device key, and the board stays UNCLAIMED.
fn genesis_without_its_claim(dir: &Path) -> (skepd::Skepd, Board, FileStore, Fingerprint) {
    let sd = spawn(&dir.join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.join("store"));
    let fp = keygen(&store, "notebook");
    let file = store.load(&store.key_path(&fp)).unwrap();
    let boot = bare(&board, 0);
    let Answer::Document(v) = board.op(Some(&boot), &frames::delegate("1.0.1", 1, None)).unwrap() else { panic!() };
    assert_eq!(acked_addr(&v), Some("1.0.1"));
    let owner = bare(&board, 1);
    let Answer::Document(v) = board.op(Some(&owner), &frames::create_home("1.0.1", None)).unwrap() else { panic!() };
    assert_eq!(acked_addr(&v), Some("1.0.1.0.1"));
    let entries = vec![Enrollment::new(file.public.clone(), false, Some("notebook".into())).unwrap()];
    deposit(&board, &owner, &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Enroll(entries), hand: None, id: "test.genesis" }).expect("genesis");
    assert_eq!(board.health().unwrap().claimant(), None);
    (sd, board, store, fp)
}

/// S1–S5 by hand: `genesis_without_its_claim`, then the claim under the
/// store's one device key; the tail — the agent space — does not run.
fn claimed_without_its_tail(dir: &Path) -> (skepd::Skepd, Board, FileStore, Fingerprint) {
    let (sd, board, store, fp) = genesis_without_its_claim(dir);
    let device = store.load(&store.key_path(&fp)).unwrap().signer();
    let signed = handshake(&board, Scope::Full, &device, 1, Site::Claim).expect("the claim's session");
    let Answer::Document(v) = signed.op(&frames::make_link("1.0.1.0.1", &["1.0.1"], &[], T_CLAIM, None)).unwrap() else { panic!() };
    assert!(acked_addr(&v).is_some(), "the claim: {v}");
    let _ = signed.close();
    assert_eq!(board.health().unwrap().claimant(), Some("1.0.1"));
    (sd, board, store, fp)
}

/// The persist-first `new_id` (§4.3; AUTH-5.20): a binding line written
/// BEFORE the delegate is READ BACK by `principal_prefix(new_id)` and the
/// same id is sent — never a fresh one.
#[test]
fn the_persisted_new_id_is_read_back_and_the_space_is_delegated_under_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_sd, board, store, fp) = claimed_without_its_tail(dir.path());
    // The persisted line, as an interrupted run leaves it: the id chosen,
    // the frame never sent.
    let chosen: u64 = 424_242;
    store.bind(&Binding::Enrollment { origin: board.dialed.clone(), principal: chosen, account: "1.0.1.1".into(), fingerprint: fp }).unwrap();
    assert_eq!(board.principal_prefix(chosen).unwrap(), None, "not yet delegated");
    // The tail resumes and delegates UNDER THE PERSISTED ID.
    let mut person = Scripted::new(vec![]);
    let outcome = claim::notebook(&board, &store, &mut person, &opts(&dir.path().join("anchors"))).unwrap_or_else(|h| panic!("{h}"));
    let ClaimOutcome::Ours(done) = outcome else { panic!("{outcome:?}") };
    assert_eq!(done.agent_space.as_deref(), Some("1.0.1.1"));
    assert_eq!(board.principal_prefix(chosen).unwrap().as_deref(), Some("1.0.1.1"), "the persisted id seats the space");
    let lines = store.all_bindings().unwrap();
    assert_eq!(lines.iter().filter(|b| matches!(b, Binding::Enrollment { account, .. } if account == "1.0.1.1")).count(), 1, "no second id was minted for the space");
    // And the space's home stands.
    assert!(skep_client::ceremony::first_session::document_present(&board, "1.0.1.1.0.1").unwrap());
}

/// A persisted `new_id` SPENT on another address (§4.3; AUTH-5.20): its
/// read-back finds it registered to an account that is not this space, so a
/// FRESH `new_id` is minted, persisted ahead of the frame, and seats the
/// space — never a resume onto the spent one, whose `duplicate_id` would
/// answer every re-run. MUTATION: with the spent `new_id` sent again, the
/// tail halts `duplicate_id`.
#[test]
fn a_persisted_new_id_spent_on_another_address_is_replaced_by_a_fresh_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_sd, board, store, fp) = claimed_without_its_tail(dir.path());
    // The cached line names principal 1 — registered, at 1.0.1.
    store.bind(&Binding::Enrollment { origin: board.dialed.clone(), principal: 1, account: "1.0.1.1".into(), fingerprint: fp }).unwrap();
    let mut person = Scripted::new(vec![]);
    let outcome = claim::notebook(&board, &store, &mut person, &opts(&dir.path().join("anchors"))).unwrap_or_else(|h| panic!("{h}"));
    let ClaimOutcome::Ours(done) = outcome else { panic!("{outcome:?}") };
    assert_eq!(done.agent_space.as_deref(), Some("1.0.1.1"));
    let principal = principal_of(&board, "1.0.1.1").unwrap().expect("the space is seated");
    assert_ne!(principal, 1, "never the spent new_id");
    assert_eq!(board.principal_prefix(1).unwrap().as_deref(), Some("1.0.1"), "the spent id's own account is untouched");
    assert_eq!(store.persisted_new_id(&board.dialed, "1.0.1.1").unwrap(), Some(principal), "the fresh new_id persisted, the newest line");
}

/// wire.md §Rejections: a walk keys on the token `credential_refused`
/// carries in its DETAIL. Between its genesis and its claim a board admits a
/// `delegate` from principal 0 alone (wire.md §Credential refusals' unclaimed
/// arm), so the handoff's beat (a) there is refused `claim_first` — and
/// meets the persist-first form's own face, exit 3, nothing delegated.
/// MUTATION: keyed on the `code`, the arm never fires and the refusal
/// surfaces raw, exit 1.
#[test]
fn a_delegate_refused_claim_first_meets_its_own_face() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_sd, board, store, _fp) = genesis_without_its_claim(dir.path());
    let mut person = Scripted::new(vec![]);
    let opts = HandoffOptions { principal: 1, account: "1.0.1.2".into(), payload: None, anchor: None };
    let err = handoff(&board, &store, &mut person, &opts).expect_err("the board is unclaimed");
    let text = err.to_string();
    assert_eq!(err.exit_code(), 3, "{text}");
    assert!(text.contains("the board is unclaimed") && text.contains("re-run `skep claim`"), "{text}");
    assert_eq!(principal_of(&board, "1.0.1.2").unwrap(), None, "nothing was delegated");
    assert_eq!(board.health().unwrap().claimant(), None);
}
