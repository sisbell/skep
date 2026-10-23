//! A CUT-SHORT ANCHOR FILE HANDED IN (`client.md` §4.2): the front of a key
//! file an export killed inside its write left at its final name, named at
//! `--anchor`, is faced as that state — the export that did not finish, the
//! key enrolled nowhere, the other artifact to use — and never as a file of
//! another kind.

use std::fs;

use skep_client::ceremony::recover::{recover, RecoverOptions};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::person::KeptOrPlaced;
use skep_client::store::FileStore;

use crate::common::{anchor_file, board, claim, keygen, spawn};

/// §4.2; AUTH-5.67 — A CUT-SHORT ANCHOR FILE at `--anchor` is faced as the
/// export that did not finish, naming the path, the key enrolled nowhere and
/// the other artifact to use — never as "not a skep key file" (the mutant
/// that keeps one face for every unparseable file sends the person to hand
/// in the file they just handed in); a file that is no JSON at all keeps
/// the plain refusal.
#[test]
fn a_cut_short_anchor_file_is_faced_as_the_export_that_did_not_finish() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    keygen(&store, "notebook");
    let anchors = dir.path().join("anchors");
    claim(&board, &store, &anchors);
    let (kept, _) = anchor_file(&anchors, "a");
    let (_, lost) = anchor_file(&anchors, "b");
    let whole = fs::read(&kept).unwrap();
    let options = |anchor: std::path::PathBuf| RecoverOptions {
        principal: 1,
        anchor: Some(anchor),
        lost: vec![lost.fingerprint.to_hex()[..8].to_string()],
        stolen: Some(false),
        anchor_lost: true,
        anchor_out: vec![dir.path().join("fresh-a"), dir.path().join("fresh-b")],
        paper: false,
        host_name: "testhost".into(),
        date: "2026-10-04".into(),
    };
    // L0 finder: no; L1 two boxes; L2 whose, then the file's kept-or-placed.
    let script = || vec![Script::YesNo(false), Script::LabelDefault, Script::LabelDefault, Script::YesNo(true), Script::KeptOrPlaced(KeptOrPlaced::Kept)];
    for cut in [0, 1, whole.len() / 2, whole.len() - 2] {
        let partial = dir.path().join(format!("partial-{cut}.skep-key"));
        fs::write(&partial, &whole[..cut]).unwrap();
        let mut person = Scripted::new(script());
        let err = recover(&board, &store, &mut person, &options(partial.clone())).expect_err("a cut-short anchor opens nothing");
        let text = err.to_string();
        assert!(text.contains(&format!("the anchor file {} is cut short: the export that wrote it did not finish", partial.display())), "cut {cut}: {text}");
        assert!(text.contains("enrolled nowhere") && text.contains("use the other artifact"), "cut {cut}: {text}");
        assert!(!text.contains("not a skep key file") && !text.contains("point `--key`"), "cut {cut}: the plain refusal, or a device key's face: {text}");
    }
    // No JSON at all is no cut: the plain refusal stands.
    let garbage = dir.path().join("garbage.skep-key");
    fs::write(&garbage, b"not json\n").unwrap();
    let mut person = Scripted::new(script());
    let text = recover(&board, &store, &mut person, &options(garbage.clone())).expect_err("no key file").to_string();
    assert!(text.contains(&format!("the anchor file {} is refused", garbage.display())) && !text.contains("cut short"), "{text}");
}
