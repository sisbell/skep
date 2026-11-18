//! The text family's two rows, through `Shell::call`.
//!
//! They are `text.replace` (skep #1070) and `text.edit` (skep #1079). The
//! suite checks each row's own order with no daemon behind the shell —
//! its members read before the session, a bare session refused naming the
//! call before any read (the door's other questions are `door`'s) — and,
//! against the real daemon, `text.replace` end to end: one word changed by
//! the bytes that differ alone, the answer as the shapes declare it with no
//! error member, every byte outside the change at the I-address it had, and
//! one `text.replace` entry in the call log, the rows it is made of logged
//! by none; a write the shell holds and cannot get to the board — its own
//! node stopped — answered `refused` with the error member, nothing written
//! and nothing held; and a session whose token the board closed under the
//! edit, the edit made under the restart arm's re-open and answered as one
//! no death met. Of `text.edit`, against the daemon: two pairs landed in
//! one call, the text an old text spans between two changes at the
//! I-addresses it had; a write of the call's refused past the first, at
//! each place one can be, the draft then exactly as it stood, every byte at
//! its own address; and another writer's change landed between two of the
//! call's writes, nothing taken back over it and each change that stands
//! named (the shell's rows with one write meddled with, `Meddled`).

use std::cell::Cell;

use super::super::text::{edit_through, Row, Rows};
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

/// The draft the `text.edit` cells edit: four lines, 54 bytes.
const LINES: &str = "alpha = 1\nkeep this line as it is\nbeta = 2\ntail stays\n";

/// The two pairs the `text.edit` cells send over [`LINES`].
///
/// The first spans three lines and two changes — `alph` gives way to `gamm`,
/// two writes, and a `0` goes in after the `2`, one — with the line between
/// them unchanged; the second replaces `tail` by `end`, two writes: five
/// writes, in this order.
fn edits() -> Value {
    json!([
        {"old": "alpha = 1\nkeep this line as it is\nbeta = 2\n", "new": "gamma = 1\nkeep this line as it is\nbeta = 20\n"},
        {"old": "tail", "new": "end"},
    ])
}

/// [`LINES`] as [`edits`] leaves it.
const EDITED: &str = "gamma = 1\nkeep this line as it is\nbeta = 20\nend stays\n";

/// Returns the `width` I-addresses from `addr` on, in order.
fn minted(addr: &Value, width: u64) -> Vec<String> {
    let (prefix, first) = addr.as_str().and_then(|addr| addr.rsplit_once('.')).unwrap_or_else(|| panic!("an I-address: {addr}"));
    let first: u64 = first.parse().unwrap();
    (0..width).map(|k| format!("{prefix}.{}", first + k)).collect()
}

/// The shell's own rows, with one write of an edit's meddled with.
///
/// Every call goes to the shell as the row sends it, but the `nth` write
/// frame (from 1) the edit sends through `op`: `act` is handed that frame
/// and the session first, and the write is refused with what it answers, or
/// sent on where it answers none.
struct Meddled<'s, F> {
    shell: &'s Shell,
    nth: usize,
    writes: Cell<usize>,
    act: F,
}

impl<'s, F: Fn(&Value, &str) -> Option<Refusal>> Meddled<'s, F> {
    /// Returns the rows of `shell`, `act` run at the `nth` write.
    fn at(shell: &'s Shell, nth: usize, act: F) -> Meddled<'s, F> {
        Meddled { shell, nth, writes: Cell::new(0), act }
    }
}

impl<F: Fn(&Value, &str) -> Option<Refusal>> Rows for Meddled<'_, F> {
    fn answer(&self, row: Row, args: &Value) -> Result<Value, Refusal> {
        let frame = &args["frame"];
        if row == Row::Op && ["insert", "delete"].contains(&frame["op"].as_str().unwrap_or_default()) {
            self.writes.set(self.writes.get() + 1);
            if self.writes.get() == self.nth {
                if let Some(refusal) = (self.act)(frame, args["session"].as_str().unwrap()) {
                    return Err(refusal);
                }
            }
        }
        Rows::answer(self.shell, row, args)
    }

    fn stands(&self, session: &str) -> bool {
        Rows::stands(self.shell, session)
    }
}

/// Checks `text.edit`'s own order, with no daemon behind the shell.
///
/// The members are read before the session — `doc`, then the list, then
/// each pair by its index, its `old` before its `new` — each
/// `malformed_args` naming the member under a session that names nothing;
/// in their form the call goes on to the session, which is gone; and a bare
/// session is refused `write_in_bare_session` naming the call, the write
/// door asked before any read, so the board's silence is never met.
#[test]
fn text_edit_reads_its_members_first_and_asks_the_door_before_any_read() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let what = |args: Value| {
        let refused = shell.call("text.edit", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    let pair = json!({"old": "a", "new": "b"});
    assert_eq!(what(json!({"session": "s-gone", "edits": [pair]})), "doc", "missing");
    assert_eq!(what(json!({"session": "s-gone", "doc": "01.0.1", "edits": [pair]})), "doc", "another spelling");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66"})), "edits", "missing");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "edits": []})), "edits", "no pair");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "edits": [pair, {"old": "", "new": "b"}]})), "edits[1].old", "empty");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "edits": [{"old": "a", "new": null}]})), "edits[0].new", "`null` is no text");
    let in_form = json!({"session": "s-gone", "doc": "1.0.1.0.66", "edits": [{"old": "a", "new": ""}]});
    assert_eq!(shell.call("text.edit", &in_form).unwrap_err().name(), "session_ended", "in their form, the members pass to the session");
    let keyless = shell.call("text.edit", &json!({"session": bare, "doc": "1.0.1.0.66", "edits": [pair]})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("text.edit")), "{keyless}");
}

/// Checks that several edits land in one call, identity kept between.
///
/// The first pair's old text spans three lines of which two change: the
/// call makes the two changes and writes nothing of the line between them,
/// and a second pair lands behind it in the same call. The answer is
/// `TextEdited` exactly, each change with the address its new bytes were
/// minted at; the draft reads the new text; every byte no change removed
/// stands at the I-address it had, the new ones at the answer's; and the
/// call log holds one `text.edit` entry (the mutant that makes a pair as one
/// stretch re-types the line between, which then stands at new addresses).
/// Under the shell's own node stopped the first write is held `stopped`:
/// its line is dropped, and the call answers `refused` naming the change,
/// with the error member, nothing written and nothing held.
#[test]
fn several_edits_land_in_one_call_and_the_text_between_two_changes_keeps_its_identity() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let draft = draft_holding(&g.shell, &g.session, LINES);
    let before = addresses(&g.shell, &g.session, &draft);
    assert_eq!(before.len(), LINES.len(), "premise: one byte a position");
    let logged = calls_logged(&g.shell).len();
    let answer = g.shell.call("text.edit", &json!({"session": g.session, "doc": draft, "edits": edits()})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(calls_logged(&g.shell)[logged..], ["text.edit"], "one entry, the rows the call is made of logged by none");
    crate::shapes::assert_declared("TextEdited", &answer);
    let pairs = answer["pairs"].as_array().expect("the pairs");
    let change = |pair: usize, change: usize| &pairs[pair][change];
    let shape = |change: &Value| (change["ordinal"].as_str().map(str::to_string), change["removed"].as_str().map(str::to_string), change["inserted"].as_str().map(str::to_string));
    let spelled = |ordinal: &str, removed: &str, inserted: &str| (Some(ordinal.to_string()), Some(removed.to_string()), Some(inserted.to_string()));
    assert_eq!((pairs.len(), pairs[0].as_array().map(Vec::len), pairs[1].as_array().map(Vec::len)), (2, Some(2), Some(1)), "{answer}");
    assert_eq!((shape(change(0, 0)), shape(change(0, 1)), shape(change(1, 0))), (spelled("1", "4", "4"), spelled("43", "0", "1"), spelled("45", "4", "3")), "{answer}");
    assert_eq!(answer["at"], change(1, 0)["at"], "the call is whole at its last change's commit");
    assert_eq!(text_of(&g.shell, &g.session, &draft), EDITED);
    let after = addresses(&g.shell, &g.session, &draft);
    let expected = [&minted(&change(0, 0)["addr"], 4)[..], &before[4..42], &minted(&change(0, 1)["addr"], 1)[..], &before[42..43], &minted(&change(1, 0)["addr"], 3)[..], &before[47..]].concat();
    assert_eq!(after, expected, "every byte no change removed at the I-address it had, the line between the two changes among them");
    g.shell.set_node_state(NodeState::Stopped);
    let answer = g.shell.call("text.edit", &json!({"session": g.session, "doc": draft, "edits": [{"old": "gamma", "new": "delta"}, {"old": "end", "new": "tail"}]})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextRefused", &answer);
    assert_eq!(answer, json!({"outcome": "refused", "cause": "stopped", "doc": draft, "pair": 0, "change": 0, "error": true}));
    g.shell.set_node_state(NodeState::Running);
    assert!(g.shell.call("held", &json!({"session": g.session})).unwrap().as_array().unwrap().is_empty(), "the call's line dropped, nothing held");
    assert_eq!(text_of(&g.shell, &g.session, &draft), EDITED, "nothing written");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a write refused past the first leaves the draft as it was.
///
/// The call's five writes go to the real board through the shell's own
/// rows, but one, which the rows refuse outright: the second, the removal
/// of a change whose new bytes just landed, the third and fourth, each the
/// first write of a later change, and the fifth, the call's last. Each
/// time the call answers that refusal, and the draft reads its old text
/// with every byte at the I-address it had — the take-back's one
/// `set_arrangement` landed on the board, the bytes the call minted
/// arranged nowhere. The same call then lands whole through the row itself
/// (the mutants that take nothing back, or take back by text, leave the
/// landed changes or new addresses).
#[test]
fn a_write_refused_past_the_first_leaves_the_draft_exactly_as_it_stood() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let draft = draft_holding(&g.shell, &g.session, LINES);
    let before = addresses(&g.shell, &g.session, &draft);
    let args = json!({"doc": draft, "edits": edits()});
    let refusal = || Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": "insert"}));
    for nth in 2..=5 {
        let rows = Meddled::at(&g.shell, nth, |_: &Value, _: &str| Some(refusal()));
        let refused = edit_through(&rows, &g.session, &args).expect_err("the refusal of the write");
        assert_eq!(refused.to_value(), refusal().to_value(), "write {nth}");
        assert_eq!(rows.writes.get(), nth, "write {nth}: no write follows the one refused");
        assert_eq!(text_of(&g.shell, &g.session, &draft), LINES, "write {nth}: the old text");
        assert_eq!(addresses(&g.shell, &g.session, &draft), before, "write {nth}: every byte at its own address again");
    }
    assert!(g.shell.call("held", &json!({"session": g.session})).unwrap().as_array().unwrap().is_empty(), "nothing held");
    let landed = g.shell.call("text.edit", &json!({"session": g.session, "doc": draft, "edits": edits()})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((landed["outcome"].as_str(), text_of(&g.shell, &g.session, &draft).as_str()), (Some("edited"), EDITED), "{landed}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that another writer's change is never taken back over.
///
/// Another write lands on the draft just ahead of the call's third — typed
/// against the commit the call's own write is — so the board refuses that
/// write as typed against an older state: the call takes nothing back and
/// answers `partial`, naming the one change that stands by its address and
/// commit, and the draft holds the other writer's byte, the change that
/// landed and nothing else of the call. Ahead of the call's second write —
/// the removal of a change whose new bytes just landed — the same leaves
/// that change in part: its new bytes are removed by identity, where the
/// other writer's byte moved them, and the call answers the board's verdict
/// with nothing of it standing (the mutants that set the draft back over
/// the other writer's byte, or leave the new bytes beside the old, read
/// otherwise).
#[test]
fn another_writers_change_between_two_writes_is_never_taken_back_over() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let other = |frame: &Value, session: &str| {
        let ahead = skep_client::board::frames::insert_text(frame["doc"].as_str().unwrap(), 1, "X", frame["as_of"].as_u64().unwrap(), None);
        g.shell.call("op", &json!({"session": session, "frame": ahead})).unwrap_or_else(|r| panic!("the other writer's insert: {r}"));
        None
    };
    let draft = draft_holding(&g.shell, &g.session, LINES);
    let before = addresses(&g.shell, &g.session, &draft);
    let answer = edit_through(&Meddled::at(&g.shell, 3, other), &g.session, &json!({"doc": draft, "edits": edits()})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextEditPartial", &answer);
    let stands = answer["stands"].as_array().expect("the changes that stand");
    assert_eq!(
        (answer["outcome"].as_str(), answer["cause"].as_str(), answer["pair"].as_u64(), answer["change"].as_u64(), stands.len(), answer.get("take_back")),
        (Some("partial"), Some("arrangement_moved"), Some(0), Some(1), 1, None),
        "{answer}"
    );
    crate::shapes::assert_declared("TextEditStanding", &stands[0]);
    assert_eq!(
        (stands[0]["pair"].as_u64(), stands[0]["change"].as_u64(), stands[0]["ordinal"].as_str(), stands[0]["removed"].as_str(), stands[0]["inserted"].as_str()),
        (Some(0), Some(0), Some("1"), Some("4"), Some("4")),
        "{answer}"
    );
    assert_eq!(text_of(&g.shell, &g.session, &draft), format!("X{}", LINES.replacen("alph", "gamm", 1)), "the other writer's byte, the change that landed, and no more");
    let after = addresses(&g.shell, &g.session, &draft);
    assert_eq!(after[1..], [&minted(&stands[0]["addr"], 4)[..], &before[4..]].concat()[..], "found by the address the answer names");
    assert!(g.shell.call("held", &json!({"session": g.session})).unwrap().as_array().unwrap().is_empty(), "the refused write's line dropped");
    let draft = draft_holding(&g.shell, &g.session, LINES);
    let before = addresses(&g.shell, &g.session, &draft);
    let answer = edit_through(&Meddled::at(&g.shell, 2, other), &g.session, &json!({"doc": draft, "edits": edits()})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextRefused", &answer);
    assert_eq!(
        (answer["outcome"].as_str(), answer["cause"].as_str(), answer["refusal"]["code"].as_str(), answer.get("error")),
        (Some("refused"), Some("arrangement_moved"), Some("arrangement_moved"), None),
        "{answer}"
    );
    assert_eq!(text_of(&g.shell, &g.session, &draft), format!("X{LINES}"), "the other writer's byte, and nothing of the call");
    assert_eq!(addresses(&g.shell, &g.session, &draft)[1..], before[..], "the old text at its own addresses");
    g.shell.shutdown();
    sd.shutdown();
}
