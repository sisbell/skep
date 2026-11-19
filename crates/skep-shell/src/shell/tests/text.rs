//! The text family's five rows, through `Shell::call`.
//!
//! They are `text.replace` (skep #1070), `text.edit` (skep #1079),
//! `text.move` (skep #1085), and `text.mark` and `text.diff` (skep #1091),
//! each made of the shell's own rows. The
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
//! I-addresses it had and the answer's rows on the lines the board's
//! `line_numbers` numbers; a write of the call's refused past the first, at
//! each place one can be, the draft then exactly as it stood, every byte at
//! its own address; and another writer's change landed between two of the
//! call's writes, nothing taken back over it and each change that stands
//! named (the shell's rows with one write meddled with, `Meddled`). Of
//! `text.move`, against the daemon: lines moved up by one `rearrange`, every
//! byte at the I-address it had and the answer's rows on the lines the
//! board's `line_numbers` numbers; the last line of a text that ends in no
//! line break moved by four cuts, and across one empty line by three, the
//! board then counting one line fewer; and another writer's change landed
//! between the call's read and its write, the move refused
//! `arrangement_moved` with nothing written. Of `text.mark` and
//! `text.diff`, against the daemon: a mark holding its draft's content at
//! the draft's own I-addresses, its one link found from the draft and
//! stored as the mark's image, an edit and a move then told by the diff
//! since it, the move as a move, with what the diff reads and does not; a
//! mark that records no base and no source, left behind by no publication
//! and offered by none, and a diff since the version a draft was staged
//! from; the mark of an empty draft; a link refused after the copy, the
//! mark standing and diffed against; and a draft changed between the diff's
//! two images, read again, and one that keeps changing refused (the
//! shell's rows watched, and meddled with at a frame, `Watched`).

use std::cell::Cell;

use super::super::text::{diff_through, edit_through, mark_through, move_through, Row, Rows};
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
/// frame (from 1) the edit sends through `op` — an `insert`, a `delete` or a
/// `rearrange`: `act` is handed that frame and the session first, and the
/// write is refused with what it answers, or sent on where it answers none.
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
        if row == Row::Op && ["insert", "delete", "rearrange"].contains(&frame["op"].as_str().unwrap_or_default()) {
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
/// minted at, and its rows the three lines changed with the one between,
/// each `+` row on the line the board's own `line_numbers` puts that
/// change's first new byte on at the call's commit; the draft reads the
/// new text; every byte no change removed stands at the I-address it had,
/// the new ones at the answer's; and the call log holds one `text.edit`
/// entry (the mutant that makes a pair as one stretch re-types the line
/// between, which then stands at new addresses).
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
    assert_eq!(answer["lines"], json!(["+1\tgamma = 1", " 2\tkeep this line as it is", "+3\tbeta = 20", "+4\tend stays"]), "the lines the call changed, and the one between: {answer}");
    let at = answer["at"].as_u64().expect("the call's commit");
    let numbered = g.shell.call("op", &json!({"session": g.session, "at": at, "frame": skep_client::board::frames::line_numbers(&draft, &[1, 43, 45], &[])})).unwrap_or_else(|r| panic!("{r}"));
    let lines: Vec<&str> = numbered["positions"].as_array().expect("the positions' lines").iter().map(|position| position["line"].as_str().expect("a line")).collect();
    assert_eq!(lines, ["1", "3", "4"], "the board numbers each change's first new byte, at the call's commit, on its `+` row's line: {numbered}");
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

/// Checks `text.move`'s own order, with no daemon behind the shell.
///
/// The members are read before the session — `doc`, then `first`, then
/// `last` and `before` where they are present, then the two orders, `last`
/// before `first` and `before` inside the block — each `malformed_args`
/// naming the member under a session that names nothing; in their form, a
/// `null` for an absent member among them, the call goes on to the session,
/// which is gone; and a bare session is refused `write_in_bare_session`
/// naming the call, the write door asked before any read, so the board's
/// silence is never met.
#[test]
fn text_move_reads_its_members_first_and_asks_the_door_before_any_read() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let what = |args: Value| {
        let refused = shell.call("text.move", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    assert_eq!(what(json!({"session": "s-gone", "first": 2})), "doc", "missing");
    assert_eq!(what(json!({"session": "s-gone", "doc": "01.0.1", "first": 2})), "doc", "another spelling");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66"})), "first", "missing");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "first": 0})), "first", "lines are numbered from 1");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "first": 2, "last": "3"})), "last", "no number");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "first": 2, "before": 1.5})), "before", "no whole number");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "first": 3, "last": 2})), "last", "before `first`");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.1.0.66", "first": 2, "last": 4, "before": 3})), "before", "inside the block");
    let in_form = json!({"session": "s-gone", "doc": "1.0.1.0.66", "first": 2, "last": null, "before": 1});
    assert_eq!(shell.call("text.move", &in_form).unwrap_err().name(), "session_ended", "in their form, the members pass to the session");
    let keyless = shell.call("text.move", &json!({"session": bare, "doc": "1.0.1.0.66", "first": 2, "before": 1})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("text.move")), "{keyless}");
}

/// Returns the board's line for each of `positions`, and its line count.
///
/// They are the draft's as the board's `line_numbers` numbers them now.
fn numbered(shell: &Shell, session: &str, draft: &str, positions: &[u64]) -> (Vec<String>, String) {
    let answer = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::line_numbers(draft, positions, &[])})).unwrap_or_else(|r| panic!("{r}"));
    let lines = answer["positions"].as_array().expect("the positions' lines").iter().map(|position| position["line"].as_str().expect("a line").to_string()).collect();
    (lines, answer["count"]["n"].as_str().expect("the count").to_string())
}

/// Checks that lines moved keep every byte's identity.
///
/// The last two of [`LINES`] move up to stand before the second, by one
/// `rearrange` about the three lines' starts: the answer is `TextMoved`
/// exactly — the lines as asked, where they now stand, the cuts, the commit
/// and the rows — the draft reads the lines in their new order, every byte
/// at the I-address it had, none minted; the board's own `line_numbers`
/// puts the block's first byte, and the first byte of the line it crossed,
/// on the lines the rows name; and the call log holds one `text.move` entry
/// (the mutant that retypes the lines mints them anew). The last line of a
/// text that ends in no line break moves up by four cuts, the board keeping
/// every line whole, and across one empty line by three, the board then
/// counting two lines for three, as the rows number them. Under the shell's
/// own node stopped the write is held `stopped`: its line is dropped, and
/// the call answers `refused` with the error member, nothing written and
/// nothing held.
#[test]
fn lines_moved_keep_every_bytes_identity_and_the_rows_stand_where_the_board_numbers_them() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let draft = draft_holding(&g.shell, &g.session, LINES);
    let before = addresses(&g.shell, &g.session, &draft);
    assert_eq!(before.len(), LINES.len(), "premise: one byte a position");
    let logged = calls_logged(&g.shell).len();
    let answer = g.shell.call("text.move", &json!({"session": g.session, "doc": draft, "first": 3, "last": 4, "before": 2})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(calls_logged(&g.shell)[logged..], ["text.move"], "one entry, the rows the call is made of logged by none");
    crate::shapes::assert_declared("TextMoved", &answer);
    let at = answer["at"].as_u64().expect("the commit");
    let rows = json!([" 1\talpha = 1", "+2\tbeta = 2", "+3\ttail stays", " 4\tkeep this line as it is", "-\t(lines 3–4 moved to 2–3)"]);
    assert_eq!(answer, json!({"outcome": "moved", "doc": draft, "first": 3, "last": 4, "to_first": 2, "to_last": 3, "cuts": ["11", "35", "55"], "at": at, "lines": rows}), "no error member");
    assert_eq!(text_of(&g.shell, &g.session, &draft), "alpha = 1\nbeta = 2\ntail stays\nkeep this line as it is\n");
    assert_eq!(addresses(&g.shell, &g.session, &draft), [&before[..10], &before[34..], &before[10..34]].concat(), "every byte at the I-address it had");
    assert_eq!(numbered(&g.shell, &g.session, &draft, &[11, 31]), (vec!["2".to_string(), "4".to_string()], "4".to_string()), "the board numbers the block and the line it crossed as the rows do");
    let typed = g.shell.call("op", &json!({"session": g.session, "frame": skep_client::board::frames::delete(&draft, 1, 1, at, None)})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(typed["resp"], "ack", "the answer's commit is the draft's typed state: {typed}");
    let open = draft_holding(&g.shell, &g.session, "a\nbb\nccc");
    let before = addresses(&g.shell, &g.session, &open);
    let answer = g.shell.call("text.move", &json!({"session": g.session, "doc": open, "first": 3, "before": 1})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((&answer["cuts"], &answer["lines"]), (&json!(["1", "5", "6", "9"]), &json!(["+1\tccc", " 2\ta", " 3\tbb", "-\t(line 3 moved to 1)"])), "four cuts: {answer}");
    assert_eq!(text_of(&g.shell, &g.session, &open), "ccc\na\nbb", "every line whole, the text ending as it did");
    assert_eq!(addresses(&g.shell, &g.session, &open), [&before[5..], &before[4..5], &before[..4]].concat(), "the line break between the two stayed in the middle");
    let gapped = draft_holding(&g.shell, &g.session, "abc\n\nxyz");
    let answer = g.shell.call("text.move", &json!({"session": g.session, "doc": gapped, "first": 3, "before": 2})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((&answer["cuts"], &answer["lines"]), (&json!(["5", "6", "9"]), &json!([" 1\tabc", "+2\txyz", "-\t(line 3 moved to 2)"])), "three cuts across one empty line: {answer}");
    assert_eq!(text_of(&g.shell, &g.session, &gapped), "abc\nxyz\n");
    assert_eq!(numbered(&g.shell, &g.session, &gapped, &[5]), (vec!["2".to_string()], "2".to_string()), "the board counts one line fewer, as the rows number them");
    g.shell.set_node_state(NodeState::Stopped);
    let answer = g.shell.call("text.move", &json!({"session": g.session, "doc": gapped, "first": 2, "before": 1})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextRefused", &answer);
    assert_eq!(answer, json!({"outcome": "refused", "cause": "stopped", "doc": gapped, "error": true}));
    g.shell.set_node_state(NodeState::Running);
    assert!(g.shell.call("held", &json!({"session": g.session})).unwrap().as_array().unwrap().is_empty(), "the call's line dropped, nothing held");
    assert_eq!(text_of(&g.shell, &g.session, &gapped), "abc\nxyz\n", "nothing written");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a draft changed between the read and the write is refused.
///
/// Another write lands on the draft just ahead of the call's one write —
/// typed against the position the call read the draft at — so the board
/// refuses the `rearrange` as typed against an older state: the call drops
/// its line and answers the board's verdict as data, `refused`,
/// `arrangement_moved`, and the draft holds the other writer's byte and the
/// lines where they stood, every byte at its own address and nothing held.
/// The same call then lands through the row itself, against the draft as it
/// stands (the mutants that type the write against no state, or against a
/// read made at the write, move the lines over the other writer's change).
#[test]
fn a_draft_changed_between_the_read_and_the_write_is_refused_arrangement_moved_with_nothing_written() {
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
    let rows = Meddled::at(&g.shell, 1, other);
    let answer = move_through(&rows, &g.session, &json!({"doc": draft, "first": 3, "last": 4, "before": 2})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(rows.writes.get(), 1, "the one write, and no other");
    crate::shapes::assert_declared("TextRefused", &answer);
    assert_eq!(
        (answer["outcome"].as_str(), answer["cause"].as_str(), answer["refusal"]["code"].as_str(), answer.get("error")),
        (Some("refused"), Some("arrangement_moved"), Some("arrangement_moved"), None),
        "{answer}"
    );
    assert_eq!(text_of(&g.shell, &g.session, &draft), format!("X{LINES}"), "the other writer's byte, and the lines where they stood");
    assert_eq!(addresses(&g.shell, &g.session, &draft)[1..], before[..], "every byte at its own address");
    assert!(g.shell.call("held", &json!({"session": g.session})).unwrap().as_array().unwrap().is_empty(), "the refused write's line dropped");
    let landed = g.shell.call("text.move", &json!({"session": g.session, "doc": draft, "first": 3, "last": 4, "before": 2})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((landed["outcome"].as_str(), landed["cuts"].clone()), (Some("moved"), json!(["12", "36", "56"])), "the cuts of the draft as it stands: {landed}");
    assert_eq!(text_of(&g.shell, &g.session, &draft), "Xalpha = 1\nbeta = 2\ntail stays\nkeep this line as it is\n");
    g.shell.shutdown();
    sd.shutdown();
}

/// The shell's own rows, every frame through `op` kept and handed to `act`.
///
/// Every call goes to the shell as the row sends it; `act` is handed each
/// frame sent through `op`, and the session, first, and the frame is refused
/// with what it answers, or sent on where it answers none.
struct Watched<'s, F> {
    shell: &'s Shell,
    frames: std::cell::RefCell<Vec<Value>>,
    act: F,
}

impl<'s, F: Fn(&Value, &str) -> Option<Refusal>> Watched<'s, F> {
    /// Returns the rows of `shell`, `act` run at each frame.
    fn over(shell: &'s Shell, act: F) -> Watched<'s, F> {
        Watched { shell, frames: std::cell::RefCell::new(Vec::new()), act }
    }

    /// Returns the ops of the frames sent, in order.
    fn ops(&self) -> Vec<String> {
        self.frames.borrow().iter().map(|frame| frame["op"].as_str().unwrap_or_default().to_string()).collect()
    }
}

impl<F: Fn(&Value, &str) -> Option<Refusal>> Rows for Watched<'_, F> {
    fn answer(&self, row: Row, args: &Value) -> Result<Value, Refusal> {
        if row == Row::Op {
            self.frames.borrow_mut().push(args["frame"].clone());
            if let Some(refusal) = (self.act)(&args["frame"], args["session"].as_str().unwrap()) {
                return Err(refusal);
            }
        }
        Rows::answer(self.shell, row, args)
    }

    fn stands(&self, session: &str) -> bool {
        Rows::stands(self.shell, session)
    }
}

/// Returns the links typed `marks` whose `to` is `draft`, read under `session`.
fn marks_of(shell: &Shell, session: &str, draft: &str) -> Vec<String> {
    let found = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::find_links_ftt(skep_client::board::frames::T_MARKS, draft)})).unwrap_or_else(|r| panic!("{r}"));
    found["addrs"].as_array().expect("the links found").iter().map(|addr| addr.as_str().expect("an address").to_string()).collect()
}

/// Checks `text.mark`'s and `text.diff`'s own order, with no daemon.
///
/// Each reads its members before the session — `text.mark` its `doc`,
/// `text.diff` its `doc`, its `since`, then `stat` and `hunk` where they are
/// present — each `malformed_args` naming the member under a session that
/// names nothing; in their form the call goes on to the session, which is
/// gone. A bare session's `text.mark` is refused `write_in_bare_session`
/// naming the call, the write door asked before any read; its `text.diff`,
/// which writes nothing, goes on to the board, whose silence it meets (the
/// mutant that asks the write door of a diff refuses a read as a write).
#[test]
fn text_mark_and_text_diff_read_their_members_first_and_the_diff_asks_no_write_door() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let what = |call: &str, args: Value| {
        let refused = shell.call(call, &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{call} {args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    assert_eq!(what("text.mark", json!({"session": "s-gone"})), "doc", "missing");
    assert_eq!(what("text.mark", json!({"session": "s-gone", "doc": "01.0.1"})), "doc", "another spelling");
    assert_eq!(shell.call("text.mark", &json!({"session": "s-gone", "doc": "1.0.1.0.66"})).unwrap_err().name(), "session_ended", "in its form, the member passes to the session");
    let keyless = shell.call("text.mark", &json!({"session": bare, "doc": "1.0.1.0.66"})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("text.mark")), "{keyless}");
    assert_eq!(what("text.diff", json!({"session": "s-gone", "since": "1.0.1.0.67"})), "doc", "missing");
    assert_eq!(what("text.diff", json!({"session": "s-gone", "doc": "1.0.1.0.66"})), "since", "missing");
    assert_eq!(what("text.diff", json!({"session": "s-gone", "doc": "1.0.1.0.66", "since": "1..2"})), "since", "no address");
    assert_eq!(what("text.diff", json!({"session": "s-gone", "doc": "1.0.1.0.66", "since": "1.0.1.0.67", "stat": "true"})), "stat", "no boolean");
    assert_eq!(what("text.diff", json!({"session": "s-gone", "doc": "1.0.1.0.66", "since": "1.0.1.0.67", "hunk": 0})), "hunk", "hunks are numbered from 1");
    let in_form = json!({"session": "s-gone", "doc": "1.0.1.0.66", "since": "1.0.1.0.67", "stat": null, "hunk": 1});
    assert_eq!(shell.call("text.diff", &in_form).unwrap_err().name(), "session_ended", "in their form, the members pass to the session");
    let read = shell.call("text.diff", &json!({"session": bare, "doc": "1.0.1.0.66", "since": "1.0.1.0.67"})).unwrap_err();
    assert_eq!(read.name(), "unreachable", "a bare session's diff is dialed, and meets the board's silence: {read}");
}

/// Checks a mark, and an edit and a move told by the diff since it.
///
/// The mark is a private document holding [`LINES`] at the draft's own
/// I-addresses, none minted, made by one `text.mark` entry of the call log;
/// its one link is typed `marks`, found from the draft by a link read `to`
/// it by type, and stored with the mark's image as its `from` and the draft
/// as its `to`. A digit typed into one line and the last line moved up, the
/// diff since the mark is `TextDiffed` exactly: the changed line gone and
/// new, the moved line `>` where it stands with one `<` row where it left
/// and its note, and the counts by identity. It reads the two images, the
/// draft's text and one more image, and nothing of the mark's text: every
/// line of the text before is told from the draft's own. With a line
/// deleted, that line is read by identity and no other; `stat` reads no
/// text; and against a document sharing nothing the diff answers `shared`
/// `"0"` with no row and nothing of it read (the mutants that copy by
/// minting, write the link's `from` by address, read the mark's text by
/// position, or diff with no second image answer otherwise).
#[test]
fn a_mark_holds_its_drafts_identity_and_an_edit_and_a_move_are_told_by_the_diff_since_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let draft = draft_holding(&g.shell, &g.session, LINES);
    let before = addresses(&g.shell, &g.session, &draft);
    let logged = calls_logged(&g.shell).len();
    let marked = g.shell.call("text.mark", &json!({"session": g.session, "doc": draft})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(calls_logged(&g.shell)[logged..], ["text.mark"], "one entry, the rows the call is made of logged by none");
    crate::shapes::assert_declared("TextMarked", &marked);
    let (mark, link, at) = (marked["mark"].as_str().expect("the mark").to_string(), marked["link"].as_str().expect("the link").to_string(), marked["at"].as_u64().expect("the commit"));
    assert_eq!(marked, json!({"outcome": "marked", "doc": draft, "mark": mark, "link": link, "at": at}), "no error member");
    assert!(mark.starts_with("1.0.1.0.") && link.starts_with(&format!("{mark}.0.2.")), "a document of the session's account, the link homed in it: {marked}");
    assert_eq!(text_of(&g.shell, &g.session, &mark), LINES);
    assert_eq!(addresses(&g.shell, &g.session, &mark), before, "the draft's own bytes, none minted");
    let metadata = g.op(skep_client::board::frames::doc_metadata(&mark));
    assert_eq!((metadata["published"].as_bool(), metadata["owner"].as_str()), (Some(false), Some("1.0.1")), "{metadata}");
    // The link: found from the draft, its `from` the mark's image.
    assert_eq!(marks_of(&g.shell, &g.session, &draft), [link.as_str()], "found by a link read `to` the draft, by type");
    let stored = g.op(skep_client::board::frames::read_link(&link));
    let image = g.op(skep_client::board::frames::image(&mark, 1, u64::MAX));
    let spans: Vec<Value> =
        image["runs"].as_array().expect("runs").iter().map(|run| skep_client::board::frames::i_span(run["i_start"].as_str().unwrap(), run["width"].as_str().unwrap().parse().unwrap())).collect();
    assert_eq!(stored["link"]["slots"][0], json!(spans), "the stored `from` is the mark's image as I-spans");
    assert_eq!(stored["link"]["slots"][1], skep_client::board::frames::unit_span(&draft), "`to` the draft, by address");
    assert_eq!(stored["link"]["slots"][2], skep_client::board::frames::unit_span("1.1.0.1.0.1.0.3.25"), "typed `marks`");
    assert_eq!(
        g.shell.call("text.diff", &json!({"session": g.session, "doc": draft, "since": mark})).unwrap(),
        json!({"outcome": "unchanged", "doc": draft, "since": mark, "as_of": at}),
        "nothing changed since the mark"
    );

    // An edit and a move, then the diff since the mark.
    g.shell.call("text.edit", &json!({"session": g.session, "doc": draft, "edits": [{"old": "beta = 2", "new": "beta = 20"}]})).unwrap_or_else(|r| panic!("{r}"));
    let moved = g.shell.call("text.move", &json!({"session": g.session, "doc": draft, "first": 4, "before": 2})).unwrap_or_else(|r| panic!("{r}"));
    let logged = calls_logged(&g.shell).len();
    let watched = Watched::over(&g.shell, |_, _| None);
    let answer = diff_through(&watched, &g.session, &json!({"doc": draft, "since": mark})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextDiffed", &answer);
    assert_eq!(
        answer,
        json!({
            "outcome": "diffed", "doc": draft, "since": mark, "as_of": moved["at"], "shared": LINES.len().to_string(), "bytes": {"new": "1", "gone": "0", "moved": "11"},
            "lines": {"added": "1", "removed": "1", "moved": "1"},
            "rows": ["@@ -1,4 +1,4 @@", " 1\talpha = 1", ">2\ttail stays", " 3\tkeep this line as it is", "-3\tbeta = 2", "<\t(line 4 moved to 2)", "+4\tbeta = 20"],
            "notes": [{"kind": "moved", "before": [4, 4], "now": [2, 2]}],
        }),
        "no error member"
    );
    assert_eq!(watched.ops(), ["image", "image", "retrieve_doc_v_span_set", "retrieve_v", "image"], "nothing of the mark's text read: every line before is told from the draft's own");
    assert!(watched.frames.borrow().iter().all(|frame| frame["op"] != "retrieve_v" || frame["specs"][0]["doc"] == draft), "the one text read is the draft's");
    let through_the_row = g.shell.call("text.diff", &json!({"session": g.session, "doc": draft, "since": mark})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(through_the_row, answer, "the row answers as its reads do");
    assert_eq!(calls_logged(&g.shell)[logged..], ["text.diff"], "one entry");

    // A line deleted: read by identity, at the draft's own addresses.
    g.shell.call("text.edit", &json!({"session": g.session, "doc": draft, "edits": [{"old": "keep this line as it is\n", "new": ""}]})).unwrap_or_else(|r| panic!("{r}"));
    let watched = Watched::over(&g.shell, |_, _| None);
    let answer = diff_through(&watched, &g.session, &json!({"doc": draft, "since": mark})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(
        answer["rows"],
        json!(["@@ -1,4 +1,3 @@", " 1\talpha = 1", "-2\tkeep this line as it is", "-3\tbeta = 2", " 2\ttail stays", "+3\tbeta = 20"]),
        "the moved line now outweighs what it crossed, so it stays and the changed line's bytes are the ones out of order: {answer}"
    );
    assert_eq!(answer["notes"], json!([{"kind": "moved_within_lines", "bytes": "9"}]), "`beta = 2` and its line break, kept by identity inside a changed line");
    assert_eq!(watched.ops().last().map(String::as_str), Some("retrieve_i"));
    assert_eq!(watched.frames.borrow().last(), Some(&skep_client::board::frames::retrieve_i(&[(&before[10], 24)])), "the gone line alone, by the addresses the mark holds it at");
    assert!(watched.frames.borrow().iter().all(|frame| frame["op"] != "retrieve_v" || frame["specs"][0]["doc"] == draft), "no text of the mark read by position");
    // The counts alone read no text.
    let watched = Watched::over(&g.shell, |_, _| None);
    let stat = diff_through(&watched, &g.session, &json!({"doc": draft, "since": mark, "stat": true})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextDiffed", &stat);
    assert_eq!((stat["bytes"].clone(), stat["shared"].as_str(), stat.get("rows"), stat.get("lines")), (json!({"new": "1", "gone": "24", "moved": "9"}), Some("30"), None, None), "{stat}");
    assert_eq!(watched.ops(), ["image", "image"], "one image of each document");
    // A document sharing nothing with the draft.
    let apart = draft_holding(&g.shell, &g.session, "other words\n");
    let watched = Watched::over(&g.shell, |_, _| None);
    let answer = diff_through(&watched, &g.session, &json!({"doc": draft, "since": apart})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((answer["shared"].as_str(), answer["bytes"]["gone"].as_str(), answer.get("rows")), (Some("0"), Some("12"), None), "{answer}");
    assert!(!watched.ops().contains(&"retrieve_i".to_string()), "nothing of it read");
    // A document the board does not register is the call's refusal.
    let refused = g.shell.call("text.diff", &json!({"session": g.session, "doc": draft, "since": "1.0.1.0.4000"})).unwrap_err();
    assert_eq!(refused.name(), "doc_not_registered", "{refused}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a mark is no staged draft, and no publication's to offer.
///
/// A draft staged from the edition's first version is marked: the mark's
/// `doc_metadata` answers no base and no source, the draft's standing lists
/// no mark among the drafts its publication leaves behind though the index
/// lists the mark beside them, and the panel the draft opens holds no row
/// for the mark and offers no link of it. The diff since the version the
/// draft was staged from tells the line the draft added, its other words
/// held by identity (the mutants that stage the mark, or drop the `marks`
/// type from the record classes, list it or offer its link).
#[test]
fn a_mark_records_no_base_and_no_publication_lists_or_offers_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let first = g.staged(&edition, "the quick brown fox\n");
    g.call("publication.open", json!({"session": g.session, "draft": first, "doc": edition, "readable_drafts": [first], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let e1 = format!("{edition}.1");
    assert_eq!(g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"))["member"].as_str(), Some(e1.as_str()));
    let draft = g.staged(&e1, "a line of its own\n");
    let marked = g.call("text.mark", json!({"session": g.session, "doc": draft})).unwrap_or_else(|r| panic!("{r}"));
    let mark = marked["mark"].as_str().expect("the mark").to_string();
    let metadata = g.op(skep_client::board::frames::doc_metadata(&mark));
    assert!(metadata.get("base").is_none_or(Value::is_null) && metadata.get("source").is_none_or(Value::is_null), "no base and no source: {metadata}");
    let staged = g.op(skep_client::board::frames::doc_metadata(&draft));
    assert_eq!(staged["base"].as_str(), Some(e1.as_str()), "premise: the draft it marks records its base: {staged}");
    g.listed(&[first.as_str(), draft.as_str(), mark.as_str()]);
    let standing = g.call("publication.standing", json!({"session": g.session, "draft": draft, "doc": edition})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(standing["left_behind"], json!([first]), "the draft on this base, and no mark: {standing}");
    let panel = g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft, mark], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let text = panel.to_string();
    assert!(
        !text.contains(&format!("{mark}.0.2.")) && panel["rows"].as_array().expect("rows").iter().all(|row| row["home"] != mark.as_str()),
        "no row for the mark, and no link of it anywhere on the panel: {panel}"
    );
    g.call("publication.cancel", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    // The diff since the member the draft was staged from.
    let answer = g.call("text.diff", json!({"session": g.session, "doc": draft, "since": e1})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextDiffed", &answer);
    assert_eq!(
        (&answer["rows"], &answer["bytes"], answer["shared"].as_str()),
        (&json!(["@@ -1,1 +1,2 @@", "+1\ta line of its own", " 2\tthe quick brown fox"]), &json!({"new": "18", "gone": "0", "moved": "0"}), Some("20")),
        "{answer}"
    );
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks an empty draft's mark, a refused link and the mark's refusals.
///
/// An empty draft's mark holds nothing, and its link's stored `from` is
/// empty, its `to` the draft. A link refused after the copy landed answers
/// `partial`, an error naming the mark and the copy's commit: the mark holds
/// the draft's text at its own addresses, no `marks` link names the draft
/// from it, the link was sent once, and the diff since it stands. A
/// document the board does not register refuses the call at its read with
/// no document minted, and under the shell's own node stopped the call is
/// refused `stopped` at the door, naming the mint, nothing read or minted
/// (the mutants that mint before the read, or send the link again, leave a
/// document or a second link).
#[test]
fn the_mark_of_an_empty_draft_and_a_link_refused_after_the_copy_and_the_marks_refusals() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let empty = g.addr(json!({"op": "create_new_document", "account": "1.0.1"}));
    let marked = g.call("text.mark", json!({"session": g.session, "doc": empty})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextMarked", &marked);
    let (mark, link) = (marked["mark"].as_str().expect("the mark").to_string(), marked["link"].as_str().expect("the link").to_string());
    assert!(addresses(&g.shell, &g.session, &mark).is_empty(), "nothing copied");
    let stored = g.op(skep_client::board::frames::read_link(&link));
    assert_eq!((&stored["link"]["slots"][0], &stored["link"]["slots"][1]), (&json!([]), &skep_client::board::frames::unit_span(&empty)), "an empty `from`: {stored}");
    assert_eq!(g.call("text.diff", json!({"session": g.session, "doc": empty, "since": mark})).unwrap()["outcome"], "unchanged");

    // The link refused once the copy has landed.
    let draft = draft_holding(&g.shell, &g.session, LINES);
    let slot_too_large = || {
        Refusal::Board(skep_client::halt::Refused {
            status: 200,
            code: "slot_too_large".into(),
            detail: None,
            op: Some("make_link".into()),
            body: json!({"resp": "rejected", "op": "make_link", "code": "slot_too_large", "disposition": "permanent"}),
        })
    };
    let watched = Watched::over(&g.shell, |frame, _| (frame["op"] == "make_link").then(slot_too_large));
    let partial = mark_through(&watched, &g.session, "1.0.1", &json!({"doc": draft})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextMarkPartial", &partial);
    let (copy, copied_at) = (partial["mark"].as_str().expect("the mark").to_string(), partial["at"].as_u64().expect("the copy's commit"));
    assert_eq!(
        (partial["outcome"].as_str(), partial["error"].as_bool(), partial["cause"].as_str(), partial["refusal"]["kind"].as_str()),
        (Some("partial"), Some(true), Some("slot_too_large"), Some("refused")),
        "{partial}"
    );
    assert_eq!(watched.ops(), ["retrieve_doc_v_span_set", "create_new_document", "copy", "make_link"], "the link sent once");
    assert_eq!(watched.frames.borrow()[3]["from"], json!([{"source": copy, "span": {"start": "1.1", "width": format!("0.{}", u64::MAX)}}]), "the mark's whole content, by the span the copy named");
    assert_eq!(addresses(&g.shell, &g.session, &copy), addresses(&g.shell, &g.session, &draft), "the copy stands, the draft's own bytes");
    assert!(marks_of(&g.shell, &g.session, &draft).is_empty(), "and carries no `marks` link");
    let answer = g.call("text.diff", json!({"session": g.session, "doc": draft, "since": copy})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(answer["outcome"], "unchanged", "taken as `since`: the draft holds what the copy took: {answer}");
    let typed = g.op(skep_client::board::frames::delete(&copy, 1, 1, copied_at, None));
    assert_eq!(typed["resp"], "ack", "`at` is the copy's commit, the mark's typed state: {typed}");

    // Nothing minted where the read or the door refuses.
    let next = || g.addr(json!({"op": "create_new_document", "account": "1.0.1"}));
    let ordinal = |doc: &str| doc.rsplit('.').next().and_then(|n| n.parse::<u64>().ok()).expect("a document's ordinal");
    let last = ordinal(&next());
    let refused = g.call("text.mark", json!({"session": g.session, "doc": "1.0.1.0.4000"})).unwrap_err();
    assert_eq!(refused.name(), "doc_not_registered", "{refused}");
    g.shell.set_node_state(NodeState::Stopped);
    let stopped = g.call("text.mark", json!({"session": g.session, "doc": draft})).unwrap_err().to_value();
    assert_eq!((stopped["name"].as_str(), stopped["op"].as_str()), (Some("stopped"), Some("create_new_document")), "{stopped}");
    g.shell.set_node_state(NodeState::Running);
    assert_eq!(ordinal(&next()), last + 1, "no document minted by either refused call");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a draft changed between the diff's two images is read again.
///
/// Another writer's byte lands on the draft after the call's first image of
/// it: the text read and the second image find the draft changed, the three
/// are made again, and the diff is of the draft as it then stands, the
/// other writer's byte on its changed line. A draft another writer changes
/// before every read of its text is refused `arrangement_moved` after three
/// rounds, nothing written (the mutant that drops the second image draws
/// the first image's pairs over the second text).
#[test]
fn a_draft_changed_between_the_diffs_two_images_is_read_again_and_one_that_keeps_changing_is_refused() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let draft = draft_holding(&g.shell, &g.session, LINES);
    let mark = g.call("text.mark", json!({"session": g.session, "doc": draft})).unwrap_or_else(|r| panic!("{r}"))["mark"].as_str().expect("the mark").to_string();
    // Another writer types one byte at the draft's head, typed against the
    // board's position as it stands.
    let other = |session: &str| {
        let at = g.shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::span_set(&draft)})).unwrap()["as_of"].as_u64().unwrap();
        g.shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::insert_text(&draft, 1, "X", at, None)})).unwrap_or_else(|r| panic!("the other writer's insert: {r}"));
    };
    let reads = Cell::new(0);
    let once = Watched::over(&g.shell, |frame, session| {
        if frame["op"] == "retrieve_v" {
            reads.set(reads.get() + 1);
            if reads.get() == 1 {
                other(session);
            }
        }
        None
    });
    let answer = diff_through(&once, &g.session, &json!({"doc": draft, "since": mark})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(reads.get(), 2, "the draft read again");
    assert_eq!(answer["rows"], json!(["@@ -1,3 +1,3 @@", "-1\talpha = 1", "+1\tXalpha = 1", " 2\tkeep this line as it is", " 3\tbeta = 2"]), "the draft as the second round found it: {answer}");
    assert_eq!(answer["bytes"], json!({"new": "1", "gone": "0", "moved": "0"}));
    let always = Watched::over(&g.shell, |frame, session| {
        if frame["op"] == "retrieve_v" {
            other(session);
        }
        None
    });
    let answer = diff_through(&always, &g.session, &json!({"doc": draft, "since": mark})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("TextRefused", &answer);
    assert_eq!(answer, json!({"outcome": "refused", "cause": "arrangement_moved", "doc": draft, "reads": 3}), "data: the draft kept moving");
    assert_eq!(text_of(&g.shell, &g.session, &draft), format!("XXXX{LINES}"), "the other writer's bytes, and nothing of the call's");
    g.shell.shutdown();
    sd.shutdown();
}
