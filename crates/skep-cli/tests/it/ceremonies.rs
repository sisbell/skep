//! THE SIX COMMANDS through the binary (`client.md` §2; the build brief §3):
//! the help lists thirteen and `--yes` is exit 2; each person door refuses
//! without a controlling terminal while `accept --reprint`, `enroll --reply`
//! and `handoff` without `--payload` run without one; THE HOP (store B's
//! `keygen --payload`, A's enrollment, `enroll --reply`, B's `bind` and
//! `session`); THE ONE-BINDING TEST after a claim; beat (a) through the
//! binary, idempotent; `accept --reprint` from the files.

use std::path::Path;

use skep_client::board::Board;
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::enroll::{enroll, EnrollOptions};
use skep_client::dial::PlainHttp;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::{KeyFile, Label, Seed};
use skep_client::store::{FileStore, KeyStore};
use skep_client::Origin;
use skep_identity::parse_enroll;

use crate::common::{origin, skep, spawn};

const THIRTEEN: [&str; 13] = ["keygen", "claim", "session", "fingerprint", "verify", "health", "bind", "enroll", "recover", "retire", "rotate", "handoff", "accept"];

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A claimed board through the LIBRARY (the notebook arm is a person door
/// the binary refuses without a terminal): the store holds the device key,
/// the account's line and the agent space's persist-first line.
fn claim_board(board_origin: &str, store: &Path, anchors: &Path) {
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let store = FileStore::open(store);
    store.generate(Some(Label::new("notebook").unwrap())).unwrap();
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions { principal: None, display_name: Some("a name".into()), anchor_out: vec![anchors.join("a"), anchors.join("b")], paper: false, host_name: "testhost".into(), date: "2026-10-04".into() };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, &store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
}

#[test]
fn help_lists_thirteen_and_names_none_as_not_in_this_build_and_yes_is_exit_2() {
    let run = skep(&["--help"], &[], None);
    assert_eq!(run.code, 0, "{run:?}");
    for c in THIRTEEN {
        assert!(run.out.contains(&format!("\n  {c} ")), "{c} listed:\n{}", run.out);
    }
    assert!(!run.out.contains("not in this build"), "{}", run.out);
    for c in ["enroll", "recover", "retire", "rotate", "handoff", "accept"] {
        let r = skep(&[c], &[], None);
        assert!(!r.err.contains("not in this build") && !r.err.contains("unknown command"), "{c}: {}", r.err);
    }
    let r = skep(&["retire", "--yes", "--board", "http://127.0.0.1:1"], &[], None);
    assert_eq!(r.code, 2, "--yes does not exist: {r:?}");
    assert!(r.err.contains("unknown argument `--yes`"), "{}", r.err);
}

/// THE TTY: each person door without a controlling terminal is exit 3;
/// `accept --reprint`, `enroll --reply` and `handoff` without `--payload`
/// run without one (they may halt on their state, never on the terminal).
#[test]
fn the_person_doors_refuse_without_a_terminal_and_the_three_non_doors_run() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    let payload = dir.path().join("p.json");
    std::fs::write(&payload, "{}").unwrap();
    let doors: Vec<Vec<&str>> = vec![
        vec!["enroll", "--board", &board, "--dir", s(&store), "--principal", "1", "--payload", s(&payload)],
        vec!["recover", "--board", &board, "--dir", s(&store), "--principal", "1"],
        vec!["retire", "--board", &board, "--dir", s(&store), "--principal", "1", "--fingerprint", "ab"],
        vec!["rotate", "--board", &board, "--dir", s(&store), "--principal", "1"],
        vec!["handoff", "--board", &board, "--dir", s(&store), "--principal", "1", "--account", "1.0.1.2", "--payload", s(&payload)],
        vec!["accept", "--board", &board, "--dir", s(&store), "--account", "1.0.1.2"],
    ];
    for args in doors {
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 3, "{args:?}: {r:?}");
        assert!(r.err.contains("requires a controlling terminal"), "{args:?}: {}", r.err);
    }
    assert!(!store.exists(), "nothing generated before the check");
    for args in [
        vec!["accept", "--dir", s(&store), "--reprint"],
        vec!["enroll", "--board", &board, "--dir", s(&store), "--principal", "1", "--reply", "ab"],
        vec!["handoff", "--board", &board, "--dir", s(&store), "--principal", "1", "--account", "1.0.1.2"],
    ] {
        let r = skep(&args, &[], None);
        assert!(!r.err.contains("requires a controlling terminal"), "{args:?} runs without a terminal: {}", r.err);
        assert_eq!(r.code, 3, "halts on its state, not the terminal: {args:?}: {r:?}");
    }
}

/// THE HOP and THE ONE-BINDING TEST: after `claim` the store holds two lines
/// and `session`/`verify` run WITHOUT `--principal`; store B's `keygen
/// --payload`, A's `enroll` (the library's walk, the terminal's door), the
/// three facts, NO line in A's bindings; `enroll --reply` through the
/// binary; B's `bind` with the facts, then B's `session` opens; a second
/// ACCOUNT bound at the same board makes the omission a halt listing both.
#[test]
fn the_hop_through_the_binary_and_the_one_binding_test_after_a_claim() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store_a = dir.path().join("a");
    claim_board(&board, &store_a, &dir.path().join("anchors"));
    let lines = std::fs::read_to_string(store_a.join("bindings")).unwrap();
    assert_eq!(lines.lines().count(), 2, "the account's line and the agent space's: {lines}");
    // THE ONE-BINDING TEST (cl-W1): `--principal` omitted.
    let r = skep(&["session", "--board", &board, "--dir", s(&store_a)], &[], None);
    assert_eq!(r.code, 0, "the agent space's line does not count: {r:?}");
    let token = r.out.trim().to_string();
    assert_eq!(token.len(), 32);
    let r = skep(&["session", "--close", "-", "--board", &board], &[], Some(token.as_bytes()));
    assert_eq!(r.code, 0);
    let r = skep(&["verify", "--board", &board, "--dir", s(&store_a)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.lines().contains(&"account 1.0.1"), "{}", r.out);

    // Store B: `keygen --payload`.
    let store_b = dir.path().join("b");
    let r = skep(&["keygen", "--label", "phone", "--payload", "--dir", s(&store_b)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let payload = r.lines()[0].to_string();
    let fp_b = r.lines()[1].to_string();
    assert_eq!(parse_enroll(payload.as_bytes()).unwrap().len(), 1);
    // A's enrollment: the walk under the scripted person (the binary's door
    // needs a terminal, §2.4).
    let a_board = Board::new(Origin::parse(&board).unwrap(), PlainHttp::new());
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let done = enroll(&a_board, &FileStore::open(&store_a), &mut person, &EnrollOptions { principal: 1, payload: format!("{payload}\n").into_bytes() }).unwrap_or_else(|h| panic!("{h}"));
    assert_eq!(done.facts.account, "1.0.1");
    assert_eq!(std::fs::read_to_string(store_a.join("bindings")).unwrap(), lines, "NO line in A's bindings");
    // `enroll --reply` through the binary: the facts, no write.
    let r = skep(&["enroll", "--board", &board, "--dir", s(&store_a), "--reply", &fp_b[..8]], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.lines(), vec!["account 1.0.1", "principal 1", format!("origin {board}").as_str()]);
    assert!(r.err.contains("stands ENROLLED"), "{}", r.err);
    let reply = r.out.clone();
    // B binds with the facts, then B's session opens.
    let r = skep(&["bind", "--board", &board, "--dir", s(&store_b), "--payload", "-"], &[], Some(reply.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    let r = skep(&["session", "--board", &board, "--dir", s(&store_b)], &[], None);
    assert_eq!(r.code, 0, "B's session opens with one binding: {r:?}");
    let token = r.out.trim().to_string();
    assert_eq!(token.len(), 32);
    let r = skep(&["session", "--close", "-", "--board", &board], &[], Some(token.as_bytes()));
    assert_eq!(r.code, 0);
    // A second ACCOUNT bound at the same board: the omission is a halt
    // listing both — never a pick.
    let line = format!("{board} 7 1.0.2 {}\n", "ab".repeat(32));
    let mut text = std::fs::read_to_string(store_a.join("bindings")).unwrap();
    text.push_str(&line);
    std::fs::write(store_a.join("bindings"), text).unwrap();
    let r = skep(&["session", "--board", &board, "--dir", s(&store_a)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("bindings for several principals"), "{}", r.err);
    let r = skep(&["session", "--board", &board, "--dir", s(&store_a), "--principal", "1"], &[], None);
    assert_eq!(r.code, 0, "named, it opens: {r:?}");
}

/// Beat (a) through the binary, idempotent — the address printed, then
/// printed again — and `accept --reprint` composing the record from the
/// files with the store's lone unbound key.
#[test]
fn handoff_beat_a_prints_the_address_twice_and_reprint_composes_from_the_files() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("giver");
    claim_board(&board, &store, &dir.path().join("anchors"));
    let r = skep(&["handoff", "--board", &board, "--dir", s(&store), "--account", "1.0.1.2"], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.lines()[0], "account 1.0.1.2");
    let principal_line = r.lines()[1].to_string();
    assert!(principal_line.starts_with("principal "));
    assert!(r.err.contains("beat (a) done"), "{}", r.err);
    // The persist-first line for 1.0.1.2 now stands beside the account's:
    // two accounts at this board, so the omission halts and the principal is
    // named (§3.5 as ruled: only the first child's line is excluded).
    let omitted = skep(&["handoff", "--board", &board, "--dir", s(&store), "--account", "1.0.1.2"], &[], None);
    assert_eq!(omitted.code, 3, "{omitted:?}");
    assert!(omitted.err.contains("bindings for several principals"), "{}", omitted.err);
    let again = skep(&["handoff", "--board", &board, "--dir", s(&store), "--principal", "1", "--account", "1.0.1.2"], &[], None);
    assert_eq!(again.code, 0, "{again:?}");
    assert_eq!(again.lines()[..2], r.lines()[..2], "the address again");
    assert!(again.err.contains("printed again"), "{}", again.err);
    // A top-level address: no door.
    let r = skep(&["handoff", "--board", &board, "--dir", s(&store), "--principal", "1", "--account", "1.0.2"], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("no handoff and no door"), "{}", r.err);
    // `accept --reprint`: the anchors from two files, the device key the
    // store's lone unbound one; no seed is loaded, nothing written.
    let recipient = dir.path().join("recipient");
    let r = skep(&["keygen", "--label", "tablet", "--dir", s(&recipient)], &[], None);
    assert_eq!(r.code, 0);
    let a = KeyFile::new(Seed::fresh(), true, Some(Label::new("sheet a").unwrap()), None);
    let b = KeyFile::new(Seed::fresh(), true, Some(Label::new("sheet b").unwrap()), None);
    let (pa, pb) = (dir.path().join("a.skep-key"), dir.path().join("b.skep-key"));
    std::fs::write(&pa, a.to_json()).unwrap();
    std::fs::write(&pb, b.to_json()).unwrap();
    let r = skep(&["accept", "--dir", s(&recipient), "--reprint", "--anchor", s(&pa), "--anchor", s(&pb)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let entries = parse_enroll(r.lines()[0].as_bytes()).expect("a canonical record");
    assert_eq!(entries.len(), 3);
    assert!(entries[0].anchor && entries[1].anchor && !entries[2].anchor);
    assert_eq!(entries[2].label(), Some("tablet"));
    let r = skep(&["accept", "--dir", s(&recipient), "--reprint", "--anchor", s(&dir.path().join("gone.skep-key"))], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("no artifact remains"), "{}", r.err);
}
