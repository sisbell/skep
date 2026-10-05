//! THE DEVICE RECOVERY (`client.md` §4a.2 R0–R6; AUTH-5.60 steps 1–2;
//! AUTH-5.47): the kept file imported, the new key enrolled, the lost one
//! retired, the session closed, the binding appended; the resume at R4 off
//! `key_set`; the paper path; the artifact's facts against the board before
//! any `/challenge`; "I hold neither"; the store path refused; the keyless
//! and `claimant == null` halts; the agent's containment act — and THE
//! STOLEN ARM with its re-read rounds and the recovery read.

use skep_client::board::{KeySetAnswer, Scope};
use skep_client::ceremony::claim::{hosted, HostedOutcome};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::ceremony::recover::{recover, RecoverOptions};
use skep_client::derive::principal_of;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::person::Custody;
use skep_client::sheet::{Facts, KeyFile, Seed};
use skep_client::sign::{fresh_seed, signer_from_seed};
use skep_client::store::FileStore;
use skep_identity::{encode_enroll, Enrollment, Fingerprint};
use skep_signature::HybridSigner;

use crate::common::{anchor_file, board, claim, entry_of, fp_of, key_file, keygen, recording_board, spawn, wire_delegate, wire_enroll, wire_session, Hooked};

fn options(anchor: Option<std::path::PathBuf>, stolen: Option<bool>) -> RecoverOptions {
    RecoverOptions { principal: 1, anchor, lost: vec![], stolen, anchor_lost: false, anchor_out: vec![], paper: false, host: "testhost".into(), date: "2026-10-04".into() }
}

/// A claimed board with the device key LOST: the old file copied aside,
/// removed from the store, a fresh key generated.
struct Loss {
    dir: tempfile::TempDir,
    sd: skepd::Skepd,
    store: FileStore,
    old: KeyFile,
    old_fp: Fingerprint,
    new_fp: Fingerprint,
    anchors: std::path::PathBuf,
}

fn lose_the_device() -> Loss {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let old_fp = keygen(&store, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &store, &anchors);
    let old = key_file(&store, &old_fp);
    std::fs::remove_file(store.key_path(&old_fp)).unwrap();
    let new_fp = keygen(&store, "notebook again");
    Loss { dir, sd, store, old, old_fp, new_fp, anchors }
}

/// R0–R6 on the LOST arm with the kept file: the enrollment preview, the
/// one default retirement, the close, the binding; then a run interrupted
/// after R3 RESUMES at R4 off `key_set`.
#[test]
fn the_device_recovery_enrolls_the_new_key_retires_the_lost_one_and_resumes_at_r4() {
    let l = lose_the_device();
    let (board, log) = recording_board(crate::common::origin_of(l.sd.port()));
    let (kept, kept_file) = anchor_file(&l.anchors, "a");
    let script = vec![Script::YesNo(true), Script::Custody(Custody::Kept), Script::YesNo(true), Script::Confirm(true), Script::Confirm(true)];
    let mut person = Scripted::new(script);
    let done = recover(&board, &l.store, &mut person, &options(Some(kept.clone()), Some(false))).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    let lines = log.lock().unwrap().clone();
    let t = person.transcript.join("\n");
    assert_eq!((done.facts.account.as_str(), done.facts.principal), ("1.0.1", 1));
    assert_eq!(done.enrolled, vec![l.new_fp]);
    assert_eq!(done.retired, vec![l.old_fp]);
    assert!(!done.containment);
    // R0's order: the admitted read priced before the first face.
    assert!(person.said("AUTH-5.68 (cost)"), "{t}");
    // R1: whose account, kept-or-placed, the other paper.
    assert!(person.said("is this account your OWN"), "{t}");
    assert!(person.said("SECRET custody of") && person.said("PLACED copy is DESTROYED"), "{t}");
    assert!(person.said("is that paper still held?"), "{t}");
    assert!(person.said(&format!("anchor {} ({}) imported: fingerprint first", kept_file.fingerprint, kept_file.label.as_deref().unwrap())), "{t}");
    // R3: the enrollment preview names the account, the artifact's label,
    // the fingerprint and label to be enrolled.
    assert!(person.said("ENROLLMENT PREVIEW") && person.said("under the anchor") && person.said("notebook again"), "{t}");
    // R4: the default retirement with the four clauses and the label.
    assert!(person.said("the DEFAULT: the one enrolled non-anchor fingerprint this store does not hold"), "{t}");
    for clause in ["AUTH-5.46 (1)", "AUTH-5.46 (2)", "AUTH-5.46 (3)", "AUTH-5.46 (4)"] {
        assert!(person.said(clause), "{clause} missing:\n{t}");
    }
    assert!(person.said("label: notebook"), "the lost key's label from the records (AUTH-5.69):\n{t}");
    // The set.
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.enrolled(&l.new_fp).is_some_and(|e| !e.anchor));
    assert!(set.retired(&l.old_fp).is_some());
    assert_eq!(set.enrolled.iter().filter(|e| e.anchor).count(), 2, "both anchors stand");
    // R5: the session CLOSED after the last write; the kept file retained.
    let last_op = lines.iter().rposition(|l| l.starts_with("POST /op ")).unwrap();
    let close = lines.iter().rposition(|l| l == "POST /session/close").unwrap();
    assert!(close > last_op, "the close after the last write: {lines:?}");
    assert!(kept.is_file(), "the KEPT artifact is retained");
    assert!(person.said("the imported seed dropped"), "{t}");
    // R6: the binding appended, the newest line for the pair.
    assert_eq!(l.store.enrollment_for(&board.dialed, 1).unwrap().map(|(_, fp)| fp), Some(l.new_fp));
    assert!(person.said("THE EXPECTED END: sign in with the new key"), "{t}");
    // The new key signs in.
    handshake(&board, Scope::Content, &key_file(&l.store, &l.new_fp).signer(), 1, Site::Session).expect("the new key").close(&board).unwrap();

    // THE RESUME: a second board, the new key enrolled by hand (R3 done),
    // the walk re-run resumes at R4.
    let l2 = lose_the_device();
    let board2 = board_of(&l2);
    let (kept2, kept_file2) = anchor_file(&l2.anchors, "a");
    let anchor = kept_file2.signer();
    let token = wire_session(&board2, 1, &anchor);
    wire_enroll(&board2, &token, &anchor, "1.0.1.0.1", "1.0.1", &[entry_of(&key_file(&l2.store, &l2.new_fp), "notebook again")]).expect("R3 by hand");
    let mut person = Scripted::new(vec![Script::YesNo(true), Script::Custody(Custody::Kept), Script::YesNo(true), Script::Confirm(true)]);
    let done = recover(&board2, &l2.store, &mut person, &options(Some(kept2), Some(false))).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert!(person.said("R3 stands done, read off `key_set`"), "{}", person.transcript.join("\n"));
    assert!(!person.said("ENROLLMENT PREVIEW"), "no second enrollment");
    assert_eq!(done.retired, vec![l2.old_fp]);
    let KeySetAnswer::Set(set) = board2.key_set("1.0.1").unwrap() else { panic!() };
    assert_eq!(set.enrolled.iter().filter(|e| !e.anchor).count(), 1, "one device key, no second enrollment");
}

fn board_of(l: &Loss) -> skep_client::board::Board {
    board(l.sd.port())
}

/// The PAPER path: the 64 hex typed from the print with a fingerprint
/// prefix, the facts confirmed against the paper; a wrong re-type re-scans.
#[test]
fn the_paper_path_types_the_hex_and_a_prefix() {
    let l = lose_the_device();
    let board = board_of(&l);
    let (_, kept) = anchor_file(&l.anchors, "a");
    let seed_hex = kept.seed_hex();
    let prefix = kept.fingerprint.to_hex()[..8].to_string();
    let script = vec![
        Script::YesNo(true),
        Script::ImportTyped { seed_hex: "00".repeat(32), fingerprint_prefix: prefix.clone() },
        Script::ImportTyped { seed_hex: seed_hex.clone(), fingerprint_prefix: "abcdef".into() },
        Script::ImportTyped { seed_hex, fingerprint_prefix: prefix },
        Script::YesNo(true),
        Script::YesNo(true),
        Script::Confirm(true),
        Script::Confirm(true),
    ];
    let mut person = Scripted::new(script);
    let done = recover(&board, &l.store, &mut person, &options(None, Some(false))).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    let t = person.transcript.join("\n");
    assert_eq!(person.transcript.iter().filter(|l| l.contains("re-scan")).count(), 2, "a wrong seed and a short/wrong prefix each re-scan:\n{t}");
    assert!(person.said("the paper should name account 1.0.1, principal 1"), "the typed path's facts confirmed (AUTH-5.22):\n{t}");
    assert_eq!(done.enrolled, vec![l.new_fp]);
    assert!(person.said("the paper stays the kept artifact"), "{t}");
}

/// AUTH-5.22: the artifact's facts disagree with `--board`/n ⇒ a halt naming
/// both before any `/challenge`; "I hold neither" ⇒ the no-artifact face
/// with its fork, nothing written; a path inside the store refused; the
/// KEYLESS halt names the two commands in order; `claimant == null` names
/// `skep claim`.
#[test]
fn the_import_halts_name_their_state_and_spend_no_nonce() {
    let l = lose_the_device();
    let (board, log) = recording_board(crate::common::origin_of(l.sd.port()));
    // Another board's anchor file.
    let other = KeyFile::new(Seed::new(fresh_seed()), true, Some("elsewhere".into()), Some(&Facts { account: "1.0.1".into(), principal: 9, origin: skep_client::Origin::parse("http://127.0.0.1:9").unwrap() }));
    let other_path = l.dir.path().join("other.skep-key");
    std::fs::write(&other_path, other.to_json()).unwrap();
    let mut person = Scripted::new(vec![Script::YesNo(true), Script::Custody(Custody::Kept)]);
    let err = recover(&board, &l.store, &mut person, &options(Some(other_path), Some(false))).expect_err("the facts disagree");
    assert!(err.to_string().contains("principal 9") && err.to_string().contains("http://127.0.0.1:9") && err.to_string().contains("AUTH-5.22"), "{err}");
    assert!(!log.lock().unwrap().iter().any(|l| l.starts_with("GET /challenge")), "no nonce spent: {:?}", log.lock().unwrap());
    // "I hold neither" — the no-artifact face, DESTROYED: the three acts.
    let before = board.health().unwrap().log_position();
    let mut person = Scripted::new(vec![Script::YesNo(true), Script::ImportNeither, Script::YesNo(true)]);
    let err = recover(&board, &l.store, &mut person, &options(None, Some(false))).expect_err("no artifact");
    let text = err.to_string();
    assert!(person.said("NO ARTIFACT") && person.said("senior credentials nobody holds"), "{}", person.transcript.join("\n"));
    assert!(text.contains("DESTROYED") && text.contains("ENROLL A SECOND DEVICE NOW") && text.contains("COPY THE VOLUME") && text.contains("this client does not perform them"), "{text}");
    assert!(text.contains("a `delegate` from 0"), "the bootstrap tier names the OPS: {text}");
    assert_eq!(board.health().unwrap().log_position(), before, "nothing written");
    // FINDABLE.
    let mut person = Scripted::new(vec![Script::YesNo(true), Script::ImportNeither, Script::YesNo(false)]);
    let err = recover(&board, &l.store, &mut person, &options(None, Some(false))).expect_err("findable");
    assert!(err.to_string().contains("FINDABLE") && err.to_string().contains("abandon this account"), "{err}");
    // A path INSIDE the store.
    let (kept, _) = anchor_file(&l.anchors, "a");
    let inside = l.store.root().join("anchor.skep-key");
    std::fs::copy(&kept, &inside).unwrap();
    let mut person = Scripted::new(vec![Script::YesNo(true)]);
    let err = recover(&board, &l.store, &mut person, &options(Some(inside.clone()), Some(false))).expect_err("inside the store");
    assert!(err.to_string().contains("lies inside the key store"), "{err}");
    assert!(!person.said("SECRET custody"), "refused ahead of the kept-or-placed question");
    std::fs::remove_file(inside).unwrap();
    // KEYLESS at R0: the two commands in order.
    let empty = FileStore::open(l.dir.path().join("empty"));
    let mut person = Scripted::new(vec![]);
    let err = recover(&board, &empty, &mut person, &options(Some(kept.clone()), Some(false))).expect_err("keyless");
    let text = err.to_string();
    assert!(text.contains("holds no device key"), "{text}");
    let (a, b) = (text.find("skep keygen").unwrap(), text.find("then `skep recover`").unwrap());
    assert!(a < b, "keygen then recover: {text}");
    // `claimant == null` ⇒ `skep claim`.
    let dir2 = tempfile::tempdir().unwrap();
    let sd2 = spawn(&dir2.path().join("board"), false);
    let board2 = crate::common::board(sd2.port());
    let store2 = FileStore::open(dir2.path().join("store"));
    keygen(&store2, "fresh");
    let mut person = Scripted::new(vec![]);
    let err = recover(&board2, &store2, &mut person, &options(Some(kept), Some(false))).expect_err("unclaimed");
    assert!(err.to_string().contains("UNCLAIMED") && err.to_string().contains("run `skep claim`"), "{err}");
}

/// "An agent's" at R1 ⇒ R3 refuses the enrollment and OFFERS the containment
/// act (AUTH-5.64's anchored arm); taken, the non-anchor set is retired and
/// nothing enrolled; `inc(A, 1)` is NOT delegated (the setup state never
/// runs — RULED 2026-10-04).
#[test]
fn an_agents_account_takes_the_containment_act_and_enrolls_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    // A hosted account: two custody anchors and a working device key, no
    // agent space (the hosted cascade runs none).
    let working = signer_from_seed(&[31; 32]);
    let a = KeyFile::new(Seed::new(fresh_seed()), true, Some("custody a".into()), None);
    let b = KeyFile::new(Seed::new(fresh_seed()), true, Some("custody b".into()), None);
    let payload = encode_enroll(&[
        Enrollment::new(a.public.clone(), true, Some("custody a".into())).unwrap(),
        Enrollment::new(b.public.clone(), true, Some("custody b".into())).unwrap(),
        Enrollment::new(HybridSigner::public_key(&working).clone(), false, Some("agent host".into())).unwrap(),
    ]);
    let HostedOutcome::Claimed(_) = hosted(&board, payload.as_bytes(), 1).unwrap() else { panic!() };
    let sheet = dir.path().join("custody-a.skep-key");
    std::fs::write(&sheet, a.to_json()).unwrap();
    // The owner's store holds a fresh device key of its own.
    let store = FileStore::open(dir.path().join("owner"));
    let own_fp = keygen(&store, "owner laptop");
    let script = vec![Script::YesNo(false), Script::Custody(Custody::Kept), Script::YesNo(true), Script::YesNo(true), Script::Confirm(true)];
    let mut person = Scripted::new(script);
    let done = recover(&board, &store, &mut person, &options(Some(sheet), Some(false))).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    let t = person.transcript.join("\n");
    assert!(done.containment && done.enrolled.is_empty());
    assert_eq!(done.retired, vec![fp_of(&working)]);
    assert!(person.said("THE ENROLLMENT IS REFUSED") && person.said("RETIRE THE NON-ANCHOR SET AND ENROLL NOTHING"), "{t}");
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.enrolled.iter().all(|e| e.anchor), "the non-anchor set is retired");
    assert!(set.enrolled(&own_fp).is_none() && set.retired(&own_fp).is_none(), "the owner's key never enters the agent's set");
    assert_eq!(principal_of(&board, "1.0.1.1").unwrap(), None, "inc(A, 1) is NOT delegated: the setup state never ran");
    assert!(store.enrollment_for(&board.dialed, 1).unwrap().is_none(), "no binding appended");
    // Declined: nothing written.
    let mut person = Scripted::new(vec![Script::YesNo(false), Script::Custody(Custody::Kept), Script::YesNo(true), Script::YesNo(false)]);
    let sheet_b = dir.path().join("custody-b.skep-key");
    std::fs::write(&sheet_b, b.to_json()).unwrap();
    let err = recover(&board, &store, &mut person, &options(Some(sheet_b), Some(false))).expect_err("declined");
    assert!(err.to_string().contains("containment act was declined"), "{err}");
}

/// THE STOLEN ARM: R4 runs ahead of R3; between R4's rounds the thief
/// enrolls a fresh key from the stolen key's session; the re-read finds it,
/// lists it as enrolled-since with its label, retires it, and completes on
/// the read after R3; the recovery read lists the person's own earlier
/// handoff, the witness marks it, and at a loopback notebook no report is
/// made save a seized account. MUTATION 2: with the re-read loop removed the
/// planted key survives the walk.
#[test]
fn the_stolen_arm_retires_what_the_thief_enrolls_between_rounds() {
    let l = lose_the_device();
    let board = board_of(&l);
    let (kept, kept_file) = anchor_file(&l.anchors, "a");
    // Before the theft: the person handed 1.0.1.2 off (an anchor-grade
    // genesis in their own doc 1).
    let owner = l.old.signer();
    let as_owner = wire_session(&board, 1, &owner);
    wire_delegate(&board, &as_owner, "1.0.1.2", 777).expect("1.0.1.2 delegated");
    let recipient = signer_from_seed(&[55; 32]);
    let anchor = kept_file.signer();
    let as_anchor = wire_session(&board, 1, &anchor);
    wire_enroll(&board, &as_anchor, &anchor, "1.0.1.0.1", "1.0.1.2", &[Enrollment::new(HybridSigner::public_key(&recipient).clone(), false, Some("friend".into())).unwrap()]).expect("the handoff's genesis");
    board.session_close(&as_anchor).unwrap();
    // The thief, holding the stolen key: a delegation of its own (unseeded).
    wire_delegate(&board, &as_owner, "1.0.1.3", 778).expect("the thief's delegation");
    board.session_close(&as_owner).unwrap();
    // The hook: at R4's FIRST confirmation the thief plants a fresh key from
    // the stolen key's session.
    let planted = signer_from_seed(&[66; 32]);
    let planted_fp = fp_of(&planted);
    let thief_key = l.old.signer();
    let thief_board = board_of(&l);
    let mut person = Hooked::new(vec![Script::YesNo(true), Script::Custody(Custody::Kept), Script::YesNo(true), Script::Confirm(true), Script::Confirm(true), Script::Confirm(true), Script::Answer("1.0.1.2".into())]);
    person.on_confirm = Box::new(move |i, _| {
        if i == 0 {
            let token = wire_session(&thief_board, 1, &thief_key);
            wire_enroll(&thief_board, &token, &thief_key, "1.0.1.0.1", "1.0.1", &[Enrollment::new(HybridSigner::public_key(&planted).clone(), false, Some("thief phone".into())).unwrap()]).expect("the plant");
        }
    });
    let done = recover(&board, &l.store, &mut person, &options(Some(kept), Some(true))).unwrap_or_else(|h| panic!("{h}\n{}", person.inner.transcript.join("\n")));
    let t = person.inner.transcript.join("\n");
    assert_eq!(done.retired, vec![l.old_fp, planted_fp], "the stolen key, then the planted one");
    assert_eq!(done.enrolled, vec![l.new_fp]);
    // R4 ahead of R3: the first retirement's preview before the enrollment preview.
    let first_retire = person.inner.transcript.iter().position(|l| l.contains("RETIREMENT PREVIEW")).unwrap();
    let enroll_preview = person.inner.transcript.iter().position(|l| l.contains("ENROLLMENT PREVIEW")).unwrap();
    assert!(first_retire < enroll_preview, "R4 runs ahead of R3:\n{t}");
    assert!(person.inner.said("ENROLLED SINCE THIS WALK BEGAN") && person.inner.said("thief phone"), "the planted key listed with its label:\n{t}");
    assert!(person.inner.said("TERMINATION IS NOT GUARANTEED"), "{t}");
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.retired(&planted_fp).is_some() && set.retired(&l.old_fp).is_some(), "both retired");
    assert!(set.enrolled(&l.new_fp).is_some());
    // The recovery read: the person's own handoff returned and marked; the
    // thief's delegation stands in the cone; the loopback cell's report.
    assert!(person.inner.said("GENESES RETURNED") && person.inner.said("1.0.1.2: genesis written by"), "{t}");
    assert!(person.inner.said("WHICH OF THESE ARE ACTS OF YOUR OWN"), "the witness question (RES-184):\n{t}");
    assert!(person.inner.said("THE BOUNDARY LINE"), "{t}");
    assert!(done.report.iter().any(|l| l.contains("NO REPORT at a loopback-bound notebook")), "{:?}", done.report);
    assert!(!done.report.iter().any(|l| l.contains("1.0.1.2 (genesis in")), "the marked handoff is not reported: {:?}", done.report);
}
