//! THE REMOVALS OF ANCHOR FILES WITH THEIR ANSWERS READ (AUTH-5.40): a
//! placed copy's removal at the close and at a halt after the import, and
//! the loss arm's dead pair, each said STANDING by its path where the
//! volume refuses the unlink — never "destroyed", never "already gone" —
//! the file still there for the person to remove. The backup moment's two
//! sites, the failed read-back's pair and the paper offer's file, are the
//! `backup` suite's. Every cell seals a directory against the unlink, so
//! the suite runs where modes hold.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use skep_client::ceremony::recover::{recover, RecoverOptions};
use skep_client::person::scripted::Script;
use skep_client::person::KeptOrPlaced;
use skep_client::store::FileStore;

use crate::common::{anchor_file, board, claim, files_in, keygen, spawn, Hooked};

fn options(anchor: PathBuf, lost: &str, out: &Path) -> RecoverOptions {
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

/// Seals `dir` against the unlink of its files: readable, not writable.
fn seal(dir: &Path) {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o500)).unwrap();
}

fn unseal(dir: &Path) {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
}

/// The transcript line that says `path` could not be destroyed, or every
/// line where none does.
fn standing_line<'a>(transcript: &'a [String], path: &Path) -> &'a str {
    let name = path.display().to_string();
    transcript
        .iter()
        .find(|l| l.contains("could not be destroyed") && l.contains(&name))
        .unwrap_or_else(|| panic!("no line says {name} could not be destroyed:\n{}", transcript.join("\n")))
}

/// AUTH-5.54 step 3; AUTH-5.40 — A PLACED COPY THE CLOSE CANNOT DESTROY is
/// said STANDING by its path at the close, never "destroyed" or "already
/// gone": the loss arm run under a placed copy of the surviving paper whose
/// directory refuses the unlink completes, and its close says the copy
/// could not be destroyed and still stands (the mutant that drops the
/// removal's answer says "already gone" of a file that is there).
#[test]
fn a_placed_copy_the_close_cannot_destroy_is_said_standing() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    keygen(&store, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &store, &anchors);
    let (kept, _) = anchor_file(&anchors, "a");
    let (_, lost) = anchor_file(&anchors, "b");
    let placed_dir = dir.path().join("placed");
    fs::create_dir(&placed_dir).unwrap();
    let placed = placed_dir.join("placed.skep-key");
    fs::copy(&kept, &placed).unwrap();
    let script = vec![Script::YesNo(false), Script::LabelDefault, Script::LabelDefault, Script::YesNo(true), Script::KeptOrPlaced(KeptOrPlaced::Placed), Script::YesNo(false), Script::Confirm(true)];
    let mut person = Hooked::new(script);
    seal(&placed_dir);
    let done = recover(&board, &store, &mut person, &options(placed.clone(), &lost.fingerprint.to_hex()[..8], dir.path()));
    unseal(&placed_dir);
    let done = done.unwrap_or_else(|h| panic!("{h}\n{}", person.inner.transcript.join("\n")));
    assert_eq!(done.enrolled.len(), 2, "the walk completed");
    let line = standing_line(&person.inner.transcript, &placed);
    assert!(line.contains("the placed copy") && line.contains("STILL STANDS"), "{line}");
    assert!(placed.is_file(), "the copy stands for the person to remove");
    let name = placed.display().to_string();
    assert!(!person.inner.transcript.iter().any(|l| l.contains(&name) && (l.contains("is destroyed") || l.contains("already gone"))), "{}", person.inner.transcript.join("\n"));
}

/// AUTH-5.54 step 3; AUTH-5.40 — A PLACED COPY A HALT CANNOT DESTROY is said
/// STANDING by its path at the halt: handed a placed copy of the LOST paper
/// in a directory that refuses the unlink, the loss arm halts after the
/// import, disposing of the anchor with the person first, so the refused
/// removal is said and never left to the drop, which can say nothing (the
/// mutant that returns the halt over the drop leaves the copy standing
/// unsaid).
#[test]
fn a_placed_copy_a_halt_cannot_destroy_is_said_standing() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    keygen(&store, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &store, &anchors);
    let (kept, paper) = anchor_file(&anchors, "a");
    let placed_dir = dir.path().join("placed");
    fs::create_dir(&placed_dir).unwrap();
    let placed = placed_dir.join("placed.skep-key");
    fs::copy(&kept, &placed).unwrap();
    let script = vec![Script::YesNo(false), Script::LabelDefault, Script::LabelDefault, Script::YesNo(true), Script::KeptOrPlaced(KeptOrPlaced::Placed), Script::YesNo(true)];
    let mut person = Hooked::new(script);
    seal(&placed_dir);
    let err = recover(&board, &store, &mut person, &options(placed.clone(), &paper.fingerprint.to_hex()[..8], dir.path()));
    unseal(&placed_dir);
    let err = err.expect_err("the lost paper's own copy halts");
    assert!(err.to_string().contains("the LOST paper's own key"), "{err}");
    let line = standing_line(&person.inner.transcript, &placed);
    assert!(line.contains("the placed copy") && line.contains("STILL STANDS"), "{line}");
    assert!(placed.is_file(), "the copy stands for the person to remove");
    assert!(kept.is_file(), "the kept artifact stands");
}

/// AUTH-5.59 step 3; AUTH-5.40 — THE DEAD PAIR'S FILE THE UNLINK REFUSES is
/// said STANDING by its path: a fresh anchor's file damaged and its
/// directory sealed before the re-import, the failure arm retires the pair
/// and destroys its files — the sealed one said standing with its cause,
/// the other said destroyed — then re-runs under a fresh pair once the
/// directory takes writes again (the mutant that drops the unlink's answer
/// leaves a retired key's seed on the media unsaid).
#[test]
fn a_dead_pairs_file_the_unlink_refuses_is_said_standing() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    keygen(&store, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &store, &anchors);
    let (surviving_path, _) = anchor_file(&anchors, "a");
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
    let sealed_dir = fresh_a.clone();
    let mut damaged: Option<PathBuf> = None;
    person.on_say = Box::new(move |rule, text| {
        if rule == "AUTH-5.59 step 1" && text.starts_with("BOTH fresh anchors enrolled") && damaged.is_none() {
            let file = files_in(&sealed_dir).into_iter().next().expect("fresh anchor a's file");
            fs::write(&file, b"{\"type\":\"skep-key\",\"v\":1").unwrap();
            seal(&sealed_dir);
            damaged = Some(file);
        }
        if rule == "AUTH-5.40" && text.contains("could not be destroyed") {
            unseal(&sealed_dir);
        }
    });
    let done = recover(&board, &store, &mut person, &options(surviving_path, &lost.fingerprint.to_hex()[..8], dir.path()));
    unseal(&fresh_a);
    let done = done.unwrap_or_else(|h| panic!("{h}\n{}", person.inner.transcript.join("\n")));
    let t = person.inner.transcript.join("\n");
    assert!(person.inner.said("did not re-import from its artifact"), "{t}");
    let files = files_in(&fresh_a);
    assert_eq!(files.len(), 2, "the damaged file stands beside the re-run's: {files:?}");
    let line = person
        .inner
        .transcript
        .iter()
        .find(|l| l.contains("the dead pair's file") && l.contains("could not be destroyed"))
        .unwrap_or_else(|| panic!("no line says the dead pair's file could not be destroyed:\n{t}"));
    assert!(files.iter().any(|f| line.contains(&f.display().to_string())), "the standing file named: {line}\n{files:?}");
    assert!(line.contains("STILL STANDS") && line.contains("its key is retired"), "{line}");
    assert!(person.inner.transcript.iter().any(|l| l.contains("the dead pair's file") && l.contains("is destroyed") && l.contains("fresh-b")), "b's file destroyed, said:\n{t}");
    assert_eq!(files_in(&dir.path().join("fresh-b")).len(), 1, "the re-run's b alone");
    assert_eq!(done.retired.len(), 3, "the dead pair and the lost paper");
}
