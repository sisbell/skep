//! The text edit, `text.replace` (skep #1070), through `Shell::call`.
//!
//! The suite checks the row's own order with no daemon behind the shell —
//! its members read before the session, a bare session refused naming the
//! call before any read (the door's other questions are `door`'s) — and,
//! against the real daemon, the edit end to end: one word changed by the
//! bytes that differ alone, the answer as the shapes declare it with no
//! error member, every byte outside the change at the I-address it had, and
//! one `text.replace` entry in the call log, the rows it is made of logged
//! by none; a write the shell holds and cannot get to the board — its own
//! node stopped — answered `refused` with the error member, nothing written
//! and nothing held; and a session whose token the board closed under the
//! edit, the edit made under the restart arm's re-open and answered as one
//! no death met.

use super::publication::{ground, register};
use super::*;
use crate::sessions::Facts;

/// Returns the draft's text, read under `session`.
fn text_of(shell: &Shell, session: &str, draft: &str) -> String {
    let extent = addresses(shell, session, draft).len() as u64;
    if extent == 0 {
        return String::new();
    }
    let read = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(draft, 1, extent)})).unwrap();
    read["items"].as_array().unwrap().iter().map(|item| item["content"].as_str().unwrap_or("")).collect()
}

/// Returns the I-address each of the draft's content positions holds, in
/// order, read off its image under `session`.
fn addresses(shell: &Shell, session: &str, draft: &str) -> Vec<String> {
    let image = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::image(draft, 1, u64::MAX)})).unwrap();
    let mut addresses = Vec::new();
    for run in image["runs"].as_array().unwrap_or_else(|| panic!("the draft's image: {image}")) {
        let width = run["width"].as_str().and_then(|w| w.parse::<u64>().ok()).or_else(|| run["width"].as_u64()).unwrap_or_else(|| panic!("a run's width: {run}"));
        let (prefix, first) = run["i_start"].as_str().and_then(|i| i.rsplit_once('.')).unwrap_or_else(|| panic!("a run's I-address: {run}"));
        let first: u64 = first.parse().unwrap();
        addresses.extend((0..width).map(|k| format!("{prefix}.{}", first + k)));
    }
    addresses
}

/// Returns a fresh draft of the account `1.0.1` holding `text`, under
/// `session`.
fn draft_holding(shell: &Shell, session: &str, text: &str) -> String {
    let minted = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    let (draft, at) = (minted["addr"].as_str().unwrap().to_string(), minted["at"].as_u64().unwrap());
    shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::insert_text(&draft, 1, text, at, None)})).unwrap();
    draft
}

/// Returns the calls the shell's log holds, in order.
fn calls_logged(shell: &Shell) -> Vec<String> {
    shell.log().entries().iter().filter(|e| e["kind"] == "call").filter_map(|e| e["call"].as_str().map(str::to_string)).collect()
}

/// Checks the row's own order, with no daemon behind the shell.
///
/// `text.replace` reads its members before the session — `doc` missing or no
/// address in its one spelling, `old` missing, empty or no string, `new`
/// missing or `null` — each `malformed_args` naming the member, the session
/// a reference that names nothing; in their form the call goes on to the
/// session, which is gone; and a bare session is refused
/// `write_in_bare_session` naming the call, the write door asked before any
/// read, so the board's silence is never met (the mutants that look the
/// session up first, ask the door after the reads, or leave the edit to its
/// frames' door, which reads the draft first and meets that silence).
#[test]
fn the_row_reads_its_members_first_and_asks_the_door_before_any_read() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let what = |args: Value| {
        let refused = shell.call("text.replace", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    assert_eq!(what(json!({"session": "s-gone", "old": "a", "new": "b"})), "doc", "missing");
    assert_eq!(what(json!({"session": "s-gone", "doc": "01.0.1", "old": "a", "new": "b"})), "doc", "another spelling");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "new": "b"})), "old", "missing");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "old": "", "new": "b"})), "old", "empty");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "old": 7, "new": "b"})), "old", "no string");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "old": "a", "new": null})), "new", "`null` is no text");
    let in_form = json!({"session": "s-gone", "doc": "1.0.1.0.66", "old": "a", "new": ""});
    assert_eq!(shell.call("text.replace", &in_form).unwrap_err().name(), "session_ended", "in their form, the members pass to the session");
    let keyless = shell.call("text.replace", &json!({"session": bare, "doc": "1.0.1.0.66", "old": "a", "new": "b"})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("text.replace")), "{keyless}");
}

/// Checks an edit end to end: the bytes that differ replaced alone, and the
/// rest of the draft at the I-addresses it had.
///
/// `brave` → `grave` in `hello brave world` shares its last four bytes, so
/// one byte is inserted after the old and the old one removed, two commits;
/// the answer is `TextReplaced` exactly — the ordinal, the widths, the new
/// byte's I-address and the commit — with no error member; the draft reads
/// the new text, every byte outside the change at the I-address it had and
/// the new one at the answer's; and the call log holds one `text.replace`
/// entry, the rows it is made of logged by none (the mutants that trim
/// nothing, take the edit's I-address from a read, or log the rows).
/// Under the shell's own node stopped, the insert is held `stopped`: the
/// edit drops its line and answers `refused` with that cause and the error
/// member, nothing written and nothing held (the mutant that leaves the
/// member off tells a transport the board refused the edit).
#[test]
fn an_edit_replaces_the_bytes_that_differ_and_a_write_the_shell_holds_is_an_error() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let draft = draft_holding(&g.shell, &g.session, "hello brave world");
    let before = addresses(&g.shell, &g.session, &draft);
    assert_eq!(before.len(), 17, "premise: one byte a position");
    let logged = calls_logged(&g.shell).len();
    let answer = g.shell.call("text.replace", &json!({"session": g.session, "doc": draft, "old": "brave", "new": "grave"})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(calls_logged(&g.shell)[logged..], ["text.replace"], "one entry, the rows the edit is made of logged by none");
    crate::shapes::assert_declared("TextReplaced", &answer);
    let (addr, at) = (answer["addr"].as_str().expect("the new byte's I-address").to_string(), answer["at"].as_u64().expect("the commit"));
    assert_eq!(answer, json!({"outcome": "replaced", "doc": draft, "ordinal": "7", "removed": "1", "inserted": "1", "addr": addr, "at": at}), "no error member");
    assert_eq!(text_of(&g.shell, &g.session, &draft), "hello grave world");
    let after = addresses(&g.shell, &g.session, &draft);
    assert_eq!(after, [&before[..6], &[addr][..], &before[7..]].concat(), "every byte outside the change at the I-address it had");
    g.shell.set_node_state(NodeState::Stopped);
    let answer = g.shell.call("text.replace", &json!({"session": g.session, "doc": draft, "old": "grave", "new": "brave"})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextRefused", &answer);
    assert_eq!(answer, json!({"outcome": "refused", "cause": "stopped", "doc": draft, "error": true}));
    g.shell.set_node_state(NodeState::Running);
    assert!(g.shell.call("held", &json!({"session": g.session})).unwrap().as_array().unwrap().is_empty(), "the edit's line dropped, nothing held");
    assert_eq!(text_of(&g.shell, &g.session, &draft), "hello grave world", "nothing written");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that an edit whose session the board ended is made under the
/// restart arm's re-open, and answered as one no death met.
///
/// The feed quiet, the session's token is closed at the board, so the edit's
/// first read is the first caller to meet the death: the shell ends the
/// session and re-opens one, and the edit makes that read again under the
/// re-open and every call after it, landing whole — `replaced`, no error
/// member, never `session_died` and never `held` — the draft read under the
/// re-opened session holding the edit and no line of it held there (the
/// mutant that follows no death answers the read's `session_died`; the one
/// that goes back to the dead session holds the edit's write `session_died`).
#[test]
fn an_edit_whose_session_the_board_ended_is_made_under_the_re_open() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (signed, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let rx = signed.subscribe();
    let board = signed.board_references().remove(0);
    let session = signed.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let draft = draft_holding(&signed, &session, "hello brave world");
    // The feed widens the session's supplement and reads the draft's rows,
    // then falls quiet: nothing commits, so the edit is the first caller to
    // meet the death.
    let deadline = Instant::now() + Duration::from_secs(30);
    let (mut widened, mut quiet_since) = (false, Instant::now());
    while !(widened && quiet_since.elapsed() > Duration::from_millis(500)) {
        assert!(Instant::now() < deadline, "the session's supplement was never widened");
        for event in rx.try_iter() {
            widened |= event.name == EventName::Index && event.data["session"] == session;
            quiet_since = Instant::now();
        }
        thread::sleep(Duration::from_millis(20));
    }
    let token = signed.sessions.get(&session).unwrap().token.clone();
    Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new()).session_close(&token).unwrap();
    let answer = signed.call("text.replace", &json!({"session": session, "doc": draft, "old": "brave", "new": "grave"})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!((answer["outcome"].as_str(), answer.get("error")), (Some("replaced"), None), "{answer}");
    let gone = signed.call("held", &json!({"session": session})).unwrap_err().to_value();
    let reopened = gone["reason"]["session"].as_str().unwrap_or_else(|| panic!("the restart arm re-opened the session: {gone}")).to_string();
    assert_eq!(text_of(&signed, &reopened, &draft), "hello grave world", "the edit landed under the re-open");
    assert!(signed.call("held", &json!({"session": reopened})).unwrap().as_array().unwrap().is_empty(), "no line of the edit's held");
    signed.shutdown();
    sd.shutdown();
}
