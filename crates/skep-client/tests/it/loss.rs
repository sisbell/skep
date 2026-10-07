//! THE LOSS ARM (`client.md` §4a.6 L0–L7; AUTH-5.59's LOSS arm; AUTH-5.47):
//! two fresh anchors enrolled as ONE record under the surviving paper, the
//! trail from the lost anchor's link to the new one, the lost anchor
//! retired, the surviving one still enrolled, L1's boxes prefilled from the
//! lost paper's label, L5's failure arm, the end face — and the imported
//! paper's PLACED copy and the `closed` face, each at a halt.

use skep_client::board::{frames, Answer, KeySetAnswer, T_SUPERSEDES};
use skep_client::ceremony::recover::{recover, RecoverOptions};
use skep_client::ceremony::trail::trail_present;
use skep_client::derive::records::{credential_records, Kind};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::person::KeptOrPlaced;
use skep_client::sheet::KeyFile;
use skep_client::sign::signer_from_seed;
use skep_client::store::FileStore;
use skep_identity::{Enrollment, Fingerprint};
use skep_signature::HybridSigner;

use crate::common::{anchor_file, board, claim, files_in, key_file, keygen, spawn, wire_enroll, wire_retire, wire_session, Hooked};

fn options(anchor: std::path::PathBuf, lost: &str, out: &std::path::Path) -> RecoverOptions {
    RecoverOptions {
        principal: 1,
        anchor: Some(anchor),
        lost: vec![lost.to_string()],
        stolen: Some(false),
        anchor_lost: true,
        anchor_out: vec![out.join("fresh-a"), out.join("fresh-b")],
        paper: false,
        host_name: "testhost".into(),
        date: "2026-10-04".into(),
    }
}

/// L0–L7 end to end.
#[test]
fn the_loss_arm_enrolls_a_fresh_pair_as_one_record_writes_the_trail_and_retires_the_lost_paper() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let device_fp = keygen(&store, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &store, &anchors);
    let (surviving_path, surviving) = anchor_file(&anchors, "a");
    let (_, lost) = anchor_file(&anchors, "b");
    let records_before = credential_records(&board, "1.0.1", &[]).unwrap();
    let lost_link = records_before.genesis().unwrap().link.clone();
    // L0 finder: no; L1 two boxes; L2 whose + kept-or-placed + the other paper
    // (lost: no); L3–L5 file default; the trail; L6 one confirmation; L7.
    let script = vec![Script::YesNo(false), Script::LabelDefault, Script::LabelDefault, Script::YesNo(true), Script::KeptOrPlaced(KeptOrPlaced::Kept), Script::YesNo(false), Script::Confirm(true)];
    let mut person = Scripted::new(script);
    let done = recover(&board, &store, &mut person, &options(surviving_path.clone(), &lost.fingerprint.to_hex()[..8], dir.path())).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    let t = person.transcript.join("\n");
    assert_eq!(done.enrolled.len(), 2, "the fresh pair");
    assert_eq!(done.retired, vec![lost.fingerprint]);
    // L0: every enrolled anchor shown with its enrolling record; the finder
    // question; AUTH-5.47's urgency.
    assert!(person.said("ENROLLED ANCHORS") && person.said("the genesis, at position"), "{t}");
    assert!(person.said("could the lost sheet") && person.said("LOSS IS NOT RETIREMENT"), "{t}");
    // L1: the boxes PREFILLED from the LOST paper's label, the surviving
    // file's label shown as the other name to avoid.
    let lost_label = lost.label.as_deref().unwrap();
    assert!(person.said(&format!("prefilled from the LOST paper's label (`{lost_label}`); the surviving file's label is `{}`", surviving.label.as_deref().unwrap())), "{t}");
    assert!(done.enrolled.iter().all(|fp| records_before.label_of(fp).is_none()));
    let records = credential_records(&board, "1.0.1", &[]).unwrap();
    for fp in &done.enrolled {
        assert!(records.label_of(fp).unwrap().starts_with(lost_label), "the fresh label carries the lost paper's: {:?}", records.label_of(fp));
    }
    // L3: (b) alone re-rendered in its file form; no (a), no (c).
    let l3 = person.transcript.iter().filter(|l| l.contains("AUTH-5.54 (b)")).count();
    assert!(l3 >= 1 && !person.said("AUTH-5.54 (a)") && !person.said("AUTH-5.54 (c)"), "statement (b) alone:\n{t}");
    // L4: BOTH fresh anchors as ONE anchor-flagged record.
    let pair = records.records.iter().find(|r| r.kind == Kind::Enroll && r.enrolled.len() == 2).expect("one record of two");
    assert!(pair.enrolled.iter().all(|e| e.anchor) && pair.anchor_grade, "two `anchor: true` entries, anchor-grade");
    assert_eq!(pair.hand, skep_client::derive::records::Hand::Key(surviving.fingerprint), "signed by the surviving anchor");
    // L5: each re-imported, probed and wiped.
    assert_eq!(person.transcript.iter().filter(|l| l.contains("a probe session opened and closed")).count(), 2, "{t}");
    // The trail: readable as a link from the lost anchor's enroll link.
    let claim = trail_present(&board, &lost_link, &pair.link).unwrap().expect("the trail");
    let Answer::Document(lv) = board.op(None, &frames::read_link(&claim)).unwrap() else { panic!() };
    assert!(lv["link"]["slots"].as_array().is_some(), "{lv}");
    assert!(lv["link"]["slots"][2][0]["start"].as_str() == Some(T_SUPERSEDES), "the supersedes class: {lv}");
    // L6/L7: the lost anchor retired, the surviving still enrolled, three
    // anchors; the end face.
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.retired(&lost.fingerprint).is_some_and(|r| r.anchor));
    assert!(set.enrolled(&surviving.fingerprint).is_some_and(|e| e.anchor));
    assert_eq!(set.enrolled.iter().filter(|e| e.anchor).count(), 3, "THREE anchors stand");
    assert!(set.enrolled(&device_fp).is_some(), "the device key untouched");
    assert!(person.said("THREE anchors stand enrolled") && person.said("NO COMMAND IN THIS VERSION RETIRES THE SURVIVING OLD PAPER"), "{t}");
    assert!(files_in(&dir.path().join("fresh-a")).len() == 1 && files_in(&dir.path().join("fresh-b")).len() == 1);
    assert!(surviving_path.is_file(), "the kept artifact retained");
    // Re-run: the lost anchor stands retired; nothing re-enrolled twice.
    let mut person = Scripted::new(vec![Script::YesNo(false), Script::LabelDefault, Script::LabelDefault, Script::YesNo(true), Script::KeptOrPlaced(KeptOrPlaced::Kept)]);
    let err = recover(&board, &store, &mut person, &options(surviving_path, &lost.fingerprint.to_hex()[..8], dir.path())).expect_err("the lost paper is retired: not an enrolled anchor");
    assert!(err.to_string().contains("no enrolled anchor starts with"), "{err}");
}

/// L5's FAILURE ARM: a fresh anchor's file removed before its read-back ⇒
/// its fingerprint (and its twin's) retired from the surviving session and
/// the walk re-runs from step 1 under a fresh pair, the dead pair's labels
/// distinct; the end face names the three anchors.
#[test]
fn a_fresh_anchor_that_does_not_read_back_is_retired_and_the_pair_re_run() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    keygen(&store, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &store, &anchors);
    let (surviving_path, surviving) = anchor_file(&anchors, "a");
    let (_, lost) = anchor_file(&anchors, "b");
    let script = vec![
        Script::YesNo(false),
        Script::LabelDefault,
        Script::LabelDefault,
        Script::YesNo(true),
        Script::KeptOrPlaced(KeptOrPlaced::Kept),
        Script::YesNo(false),
        Script::Confirm(true), // the dead pair's a
        Script::Confirm(true), // the dead pair's b
        Script::LabelDefault,  // the re-run's boxes
        Script::LabelDefault,
        Script::Confirm(true), // L6
    ];
    let mut person = Hooked::new(script);
    let fresh_a = dir.path().join("fresh-a");
    let mut pulled = false;
    person.on_say = Box::new(move |rule, text| {
        if rule == "AUTH-5.59 step 1" && text.starts_with("BOTH fresh anchors enrolled") && !pulled {
            pulled = true;
            for f in files_in(&fresh_a) {
                std::fs::remove_file(f).unwrap();
            }
        }
    });
    let done = recover(&board, &store, &mut person, &options(surviving_path, &lost.fingerprint.to_hex()[..8], dir.path())).unwrap_or_else(|h| panic!("{h}\n{}", person.inner.transcript.join("\n")));
    let t = person.inner.transcript.join("\n");
    assert!(person.inner.said("did not re-import from its artifact") && person.inner.said("re-runs from step 1 under a fresh pair"), "{t}");
    assert_eq!(done.enrolled.len(), 2);
    assert_eq!(done.retired.len(), 3, "the dead pair and the lost paper: {:?}", done.retired);
    assert!(done.retired.contains(&lost.fingerprint));
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert_eq!(set.enrolled.iter().filter(|e| e.anchor).count(), 3, "the surviving paper and the live pair");
    assert_eq!(set.retired.iter().filter(|r| r.anchor).count(), 3, "the lost paper and the dead pair");
    let records = credential_records(&board, "1.0.1", &[]).unwrap();
    let dead: Vec<Fingerprint> = done.retired.iter().filter(|f| **f != lost.fingerprint).copied().collect();
    let dead_labels: Vec<String> = dead.iter().map(|f| records.label_of(f).unwrap()).collect();
    let live_labels: Vec<String> = done.enrolled.iter().map(|f| records.label_of(f).unwrap()).collect();
    assert!(dead_labels.iter().all(|d| !live_labels.contains(d)), "the dead pair's labels are distinct: {dead_labels:?} vs {live_labels:?}");
    assert!(person.inner.said("re-run 1, a fresh pair"), "{t}");
    assert!(person.inner.said("THREE anchors stand enrolled"), "{t}");
    assert!(set.enrolled(&surviving.fingerprint).is_some());
}

/// AUTH-5.54 step 3: an imported anchor's PLACED copy is destroyed when the
/// ceremony it was imported for ends — at a halt as at the close. Handed a
/// placed copy of the LOST paper, the walk halts after the import and ahead
/// of its session; the copy is gone and the kept file stands.
/// MUTATION: with no drop on the imported anchor, the copy survives the halt.
#[test]
fn a_placed_copy_is_destroyed_where_the_walk_halts_after_the_import() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    keygen(&store, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &store, &anchors);
    let (kept, paper) = anchor_file(&anchors, "a");
    let placed = dir.path().join("placed.skep-key");
    std::fs::copy(&kept, &placed).unwrap();
    // L0 finder: no; L1 two boxes; L2 whose, kept-or-placed, the other paper.
    let script = vec![Script::YesNo(false), Script::LabelDefault, Script::LabelDefault, Script::YesNo(true), Script::KeptOrPlaced(KeptOrPlaced::Placed), Script::YesNo(true)];
    let mut person = Scripted::new(script);
    let err = recover(&board, &store, &mut person, &options(placed.clone(), &paper.fingerprint.to_hex()[..8], dir.path())).expect_err("the lost paper's own copy");
    assert!(err.to_string().contains("the LOST paper's own key"), "{err}");
    assert!(person.said("SECRET kept-or-placed"), "{}", person.transcript.join("\n"));
    assert!(!placed.exists(), "the placed copy is destroyed at the halt");
    assert!(kept.is_file(), "the kept artifact stands");
}

/// AUTH-4.63: a retirement ends a session only where it names the key that
/// OPENED it, so the `closed` face reads that key alone. On the race arm the
/// walk retires the LOST paper itself at L6; a finder holding a fresh anchor
/// then retires the SURVIVING paper under the walk, the race round's deposit
/// meets `closed`, and the face names the surviving anchor and the finder's
/// hand — never the lost paper the walk retired itself.
/// MUTATION: with the face taking the first anchor of R0's set that now
/// stands retired, it names the lost paper, whose fingerprint sorts first.
#[test]
fn the_closed_face_names_the_key_that_opened_the_session() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let device_fp = keygen(&store, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &store, &anchors);
    // The LOST paper is the one whose fingerprint sorts first.
    let (mut lost, mut surviving) = (anchor_file(&anchors, "a"), anchor_file(&anchors, "b"));
    if surviving.1.fingerprint.to_hex() < lost.1.fingerprint.to_hex() {
        std::mem::swap(&mut lost, &mut surviving);
    }
    let (surviving_path, surviving) = surviving;
    let lost = lost.1;
    // At L0's statement a device key is enrolled from the store's own
    // device-key session — unaccounted at L0, so the race round runs.
    let (early, device, extra) = (crate::common::board(sd.port()), key_file(&store, &device_fp).signer(), signer_from_seed(&[44; 32]));
    let mut planted = false;
    // At the race round's confirmation, a finder holding fresh anchor a
    // retires the surviving paper.
    let (late, fresh_a, surviving_fp) = (crate::common::board(sd.port()), dir.path().join("fresh-a"), surviving.fingerprint);
    let script = vec![
        Script::YesNo(true), // the finder: yes, the race arm
        Script::LabelDefault,
        Script::LabelDefault,
        Script::YesNo(true),
        Script::KeptOrPlaced(KeptOrPlaced::Kept),
        Script::YesNo(false),
        Script::Confirm(true), // L6: the lost paper
        Script::Confirm(true), // the race round: the extra key
    ];
    let mut person = Hooked::new(script);
    person.on_say = Box::new(move |rule, text| {
        if rule == "AUTH-5.59 step 1" && text.starts_with("ENROLLED ANCHORS") && !planted {
            planted = true;
            let token = wire_session(&early, 1, &device);
            wire_enroll(&early, &token, &device, "1.0.1.0.1", "1.0.1", &[Enrollment::new(HybridSigner::public_key(&extra).clone(), false, Some("extra".into())).unwrap()]).expect("the extra key");
            early.session_close(&token).unwrap();
        }
    });
    person.on_confirm = Box::new(move |i, _| {
        if i == 1 {
            let fresh = KeyFile::parse(&std::fs::read(&files_in(&fresh_a)[0]).unwrap()).unwrap().signer();
            let token = wire_session(&late, 1, &fresh);
            wire_retire(&late, &token, &fresh, "1.0.1.0.1", "1.0.1", &[surviving_fp]).expect("the finder retires the surviving paper");
        }
    });
    let err = recover(&board, &store, &mut person, &options(surviving_path, &lost.fingerprint.to_hex()[..8], dir.path())).expect_err("the session died under the walk");
    let text = err.to_string();
    let fresh_fp = anchor_file(dir.path(), "fresh-a").1.fingerprint;
    assert!(person.inner.said("race round 1"), "{}", person.inner.transcript.join("\n"));
    assert!(text.contains("the anchor session died under the walk") && text.contains(&surviving.fingerprint.to_string()), "{text}");
    assert!(text.contains(&fresh_fp.to_string()), "the finder's hand, from the records: {text}");
    assert!(!text.contains(&lost.fingerprint.to_string()), "never the paper the walk retired itself: {text}");
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.retired(&lost.fingerprint).is_some() && set.retired(&surviving.fingerprint).is_some());
}
