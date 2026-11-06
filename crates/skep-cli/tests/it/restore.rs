//! THE SIXTEENTH COMMAND through the binary (`skep restore`; B3-S7): THE
//! USAGE FORMS refused before any socket opens, exit 2 — no `--draft`, no
//! `--at`, an `--at` that is no position, a `--draft` that is no address,
//! another command's flag — while the whole form reaches the dead board; THE
//! WHOLE WALK on the real daemon — a draft typed in two bursts put back to
//! the state after the first, the talk saying what the draft held and the
//! way back, the report one JSON document with nothing else on stdout, the
//! draft's image the state's run; then `--at` at the head refused
//! `not_past`, exit 1, nothing on stdout, nothing written.

use serde_json::json;

use crate::common::{s, skep, Run};
use crate::merge::{report, Rig};

/// A port nothing listens at: a run that reaches it is exit 4, so a usage
/// refusal judged ahead of it is seen to open no socket.
const DEAD: &str = "http://127.0.0.1:1";

/// `skep restore --board … --dir …` with `extra`; `--principal` omitted,
/// the store's one binding standing in for it.
fn restore(rig: &Rig, extra: &[&str]) -> Run {
    let mut args = vec!["restore", "--board", &rig.origin, "--dir", s(&rig.store)];
    args.extend_from_slice(extra);
    skep(&args, &[], None)
}

/// THE USAGE FORMS are judged whole before any socket opens (§2.3's exit 2):
/// each refusal names what is wrong with the help beneath it, stdout empty,
/// against a dead port; the whole form reaches the dead board.
#[test]
fn the_usage_forms_are_refused_before_any_socket() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let draft = "1.0.1.0.4";
    let refused = |extra: &[&str], words: &str| {
        let mut args = vec!["restore", "--board", DEAD, "--dir", s(&store)];
        args.extend_from_slice(extra);
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 2, "{extra:?}: {r:?}");
        assert!(r.err.contains(words), "{extra:?}: {}", r.err);
        assert!(r.err.contains("\n\nusage: skep <command> [flags]\n"), "the help beneath the refusal: {}", r.err);
        assert!(r.out.is_empty(), "{extra:?}: {}", r.out);
    };
    refused(&["--at", "3"], "--draft <S> is required");
    refused(&["--draft", draft], "--at <n> is required");
    refused(&["--draft", draft, "--at", "x"], "--at: 'x' is not a position");
    refused(&["--draft", draft, "--at", "-1"], "--at: '-1' is not a position");
    refused(&["--draft", "not-an-address", "--at", "3"], "--draft: 'not-an-address' is not an address");
    refused(&["--draft", draft, "--at", "3", "--kind", "1.0.1.0.3"], "`--kind` is not a flag of `restore`");
    refused(&["--draft", draft, "--at", "3", "--at", "4"], "`--at` is given at most once at `restore`");
    let r = skep(&["restore", "--board", DEAD, "--dir", s(&store), "--principal", "1", "--draft", draft, "--at", "3"], &[], None);
    assert_eq!(r.code, 4, "the whole form reaches the dead board: {r:?}");
    assert!(!store.exists(), "nothing written");
}

/// THE WHOLE WALK: a draft typed in two bursts — "the cat", " sat" — put
/// back to the first by `--at` its position; the talk before and after the
/// write; the report; the image; then `--at` at the head refused `not_past`.
#[test]
fn the_whole_walk_puts_a_draft_back_and_prints_one_report() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let session = rig.session();
    let token = session.token().clone();
    let position = || rig.board.health().unwrap().log_position();
    let d = rig.draft();
    let d_s = d.to_string();
    let typed_insert = |ordinal: u64, text: &str| -> u64 {
        let as_of = position();
        let ack = Rig::acked(rig.board.op(Some(&rig.bare), &json!({"op": "insert", "doc": d_s, "at": {"subspace": "1", "ordinal": ordinal.to_string()}, "values": [text], "as_of": as_of})));
        ack["at"].as_u64().expect("the insert's position")
    };
    let p1 = typed_insert(1, "the cat");
    typed_insert(8, " sat");
    assert_eq!(rig.image(&token, &d, 11), vec![(format!("{d}.0.1.1"), "11".into())], "the premise: two bursts at one caret, one run");
    let as_of = position();
    let r = restore(&rig, &["--draft", &d_s, "--at", &p1.to_string()]);
    let v = report(&r);
    let landed_at = v["position"].as_u64().expect("the write's position");
    assert!(landed_at > as_of, "{v}");
    assert_eq!(
        v,
        json!({"act": "restore", "draft": d_s, "at": p1, "as_of": as_of, "position": landed_at, "runs": [{"origin": d_s, "i_start": format!("{d}.0.1.1"), "width": "7"}], "extent": 7, "covered": 0, "marker": null}),
        "the report"
    );
    assert_eq!(rig.image(&token, &d, 7), vec![(format!("{d}.0.1.1"), "7".into())], "the draft holds the first burst");
    assert!(r.err.contains(&format!("restoring {d} to how it stood at position {p1}, at {}", rig.origin)), "the entry line: {}", r.err);
    assert!(r.err.contains(&format!("at position {p1} {d} held 7 positions in 1 run")), "the statement before the write: {}", r.err);
    assert!(!r.err.contains("carries a merge"), "no marker, nothing said of one: {}", r.err);
    assert!(r.err.contains(&format!("restored {d} at position {landed_at}: it holds what it held at position {p1}; to put it back as it stood before this restore, run `skep restore --draft {d} --at {as_of}`")), "the way back: {}", r.err);
    // AT THE HEAD: no past state lies there.
    let head = position();
    let r = restore(&rig, &["--draft", &d_s, "--at", &head.to_string()]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.out.is_empty(), "nothing on stdout: {}", r.out);
    assert!(r.err.contains(&format!("the board refused: not_past:position {head} is not before the state {d} stands at (position {head})")), "{}", r.err);
    assert_eq!(position(), head, "nothing written");
    session.close().expect("close");
}
