//! The past state's read and its restore (`history.past`, skep #853, and
//! `client.md` §4b.1's `history.restore` row; B3-S7).
//!
//! The suite checks the rules the shell alone keeps, with no daemon behind it —
//! each row's members read before the session, a bare session refused naming
//! the restore and reading the past state, a session with no account refused
//! the read before any dial, and a hold standing at the board refusing the
//! write before any read and stopping no read — and, against the real daemon,
//! the read answering the state as read and as mapped, the board's position and
//! the marker with nothing written or noted, and the restore end to end: a
//! restore over the draft's held line refused `held_lines` and landing once the
//! line is kept; a draft put back to a past state by one `set_arrangement`
//! naming no base and no merge, and back again through the answer's `as_of`, a
//! position at the head refused `not_past` with nothing written; the write
//! typed against the page's state — refused `arrangement_moved` past another
//! hand's change, landing once the page's state is past it — and landing across
//! the person's own publication, the words back as the trunk's; and the restore
//! noted in the hold as the editor's own arrangement write, so `merge.undo`
//! after a restore and its way back lands.

use skep_client::board::frames::{doc_metadata, image, stage};
use skep_client::store::{FileStore, KeyId, KeyStore};

use super::merge::{arrangement_rows, family};
use super::publication::{ground, register, second_device};
use super::*;
use crate::sessions::Facts;

/// Checks the row's own members and a bare session, with no daemon behind
/// the shell.
///
/// `history.restore` reads its members before the session — `draft`
/// missing or no address, `at` missing or no non-negative integer, `as_of`
/// missing or `null` — each `malformed_args` naming the member, the session
/// a reference that names nothing; in their form the call goes on to the
/// session, which is gone; and a bare session is refused
/// `write_in_bare_session` naming the call, the keyless session reading
/// alone (the mutants that look the session up first, read a missing
/// `as_of` as the shell's own state, or let a bare session read).
#[test]
fn the_row_reads_its_members_first_and_refuses_a_bare_session() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let what = |args: Value| {
        let refused = shell.call("history.restore", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    assert_eq!(what(json!({"session": "s-gone", "at": 3, "as_of": 5})), "draft", "missing");
    assert_eq!(what(json!({"session": "s-gone", "draft": 7, "at": 3, "as_of": 5})), "draft", "no address");
    assert_eq!(what(json!({"session": "s-gone", "draft": "1.0.2.0.4", "as_of": 5})), "at", "missing");
    assert_eq!(what(json!({"session": "s-gone", "draft": "1.0.2.0.4", "at": "3", "as_of": 5})), "at", "another form");
    assert_eq!(what(json!({"session": "s-gone", "draft": "1.0.2.0.4", "at": -1, "as_of": 5})), "at", "no non-negative integer");
    assert_eq!(what(json!({"session": "s-gone", "draft": "1.0.2.0.4", "at": 3})), "as_of", "missing: the typed state is the page's");
    assert_eq!(what(json!({"session": "s-gone", "draft": "1.0.2.0.4", "at": 3, "as_of": null})), "as_of", "`null` is no state");
    let in_form = json!({"session": "s-gone", "draft": "1.0.2.0.4", "at": 3, "as_of": 5});
    assert_eq!(shell.call("history.restore", &in_form).unwrap_err().name(), "session_ended", "in their form, the members pass to the session");
    let keyless = shell.call("history.restore", &json!({"session": bare, "draft": "1.0.1.0.4", "at": 3, "as_of": 5})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("history.restore")), "{keyless}");
}

/// Checks the past state's read alone, with no daemon behind the shell.
///
/// `history.past` reads its members before the session — `draft` missing
/// or no address, `at` missing or no non-negative integer — each
/// `malformed_args` naming the member; in their form, with no `as_of`, the
/// call goes on to the session, which is gone; a session the board answered
/// no account for is refused `no_account` before any dial, where the
/// board's silence would answer `unreachable`; and a bare session's read
/// dials, never refused `write_in_bare_session`, and meets that silence (the
/// mutants that look the session up first, ask the read for a typed state,
/// dial with no account, or ask the write door of a read).
#[test]
fn the_past_states_read_takes_its_members_first_and_a_bare_session_reads_it() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let accountless = register(&shell, "8e", Facts { principal: 3, account: None, kind: SessionKind::Bare });
    let what = |args: Value| {
        let refused = shell.call("history.past", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    assert_eq!(what(json!({"session": "s-gone", "at": 3})), "draft", "missing");
    assert_eq!(what(json!({"session": "s-gone", "draft": 7, "at": 3})), "draft", "no address");
    assert_eq!(what(json!({"session": "s-gone", "draft": "1.0.2.0.4"})), "at", "missing");
    assert_eq!(what(json!({"session": "s-gone", "draft": "1.0.2.0.4", "at": "3"})), "at", "another form");
    assert_eq!(what(json!({"session": "s-gone", "draft": "1.0.2.0.4", "at": -1})), "at", "no non-negative integer");
    let in_form = json!({"session": "s-gone", "draft": "1.0.2.0.4", "at": 3});
    assert_eq!(shell.call("history.past", &in_form).unwrap_err().name(), "session_ended", "in their form, the members pass to the session");
    let no_account = shell.call("history.past", &json!({"session": accountless, "draft": "1.0.2.0.4", "at": 3})).unwrap_err();
    assert_eq!(no_account.name(), "no_account", "refused before any dial: {no_account}");
    let read = shell.call("history.past", &json!({"session": bare, "draft": "1.0.1.0.4", "at": 3})).unwrap_err();
    assert_eq!(read.name(), "unreachable", "the bare session's read dials: {read}");
}

/// Checks that a hold standing at the board refuses the restore before any
/// read (§3c.4), and stops no read of the past state.
///
/// The own node stopped, a signed session's `history.restore` — its key in
/// the store, so the write door and the hand admit it — is refused `stopped`
/// naming `set_arrangement`, and nothing reaches the board: the listener
/// keeps no frame past the shell's own, measured as the publication suite's
/// stop cell measures them; `history.past` under the same stop, which sends
/// no write, reads the draft and meets the board's silence, `unreachable`;
/// the node running, the restore reads the draft first, its read measured
/// past the past state's, and meets that silence too (the mutant that asks
/// no hold reads under the stop and answers `unreachable`; the one that
/// asks it under another op than the write's lets the restore through; the
/// one that asks the hold of the read answers it `stopped`).
#[test]
fn a_hold_standing_at_the_board_refuses_the_restore_before_any_read() {
    let dir = TempDir::new().unwrap();
    let (origin, frames) = super::door::recording_listener();
    let (talk, _) = talk();
    let store = dir.path().join("store");
    let mut opts = ShellOptions::new(vec![Origin::parse(&origin).unwrap()], store.clone(), SessionMode::Bare { principal: 1 }, talk);
    opts.own_node = Some(Origin::parse(&origin).unwrap());
    let shell = Shell::open(opts);
    let board = shell.board_references().remove(0);
    let KeyId(fingerprint) = FileStore::open(&store).generate(None).unwrap();
    let session = register(&shell, "8e", Facts { principal: 2, account: Some("1.0.2".into()), kind: SessionKind::Signed { fingerprint, set_account: "1.0.2".into() } });
    shell.call("places", &json!({"guest": true, "board": board})).unwrap();
    let own = frames.lock().unwrap().len();
    let restore = json!({"session": session, "draft": "1.0.2.0.4", "at": 3, "as_of": 5});
    shell.set_node_state(NodeState::Stopped);
    let refused = shell.call("history.restore", &restore).unwrap_err();
    let v = refused.to_value();
    assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), ("stopped", Some("shell"), Some("set_arrangement")), "{v}");
    let under_the_stop = frames.lock().unwrap()[own..].to_vec();
    assert!(under_the_stop.is_empty(), "nothing read or sent under the stop: {under_the_stop:?}");
    // The past state's read asks no hold: it reads under the stop.
    let past = shell.call("history.past", &json!({"session": session, "draft": "1.0.2.0.4", "at": 3})).unwrap_err();
    assert_eq!(past.name(), "unreachable", "the read dials under the stop: {past}");
    let read = frames.lock().unwrap()[own..].to_vec();
    assert!(read.contains(&doc_metadata("1.0.2.0.4")), "the read reached the board: {read:?}");
    let own = frames.lock().unwrap().len();
    shell.set_node_state(NodeState::Running);
    let refused = shell.call("history.restore", &restore).unwrap_err();
    assert_eq!(refused.name(), "unreachable", "the node running, the reads dial: {refused}");
    let dialed = frames.lock().unwrap()[own..].to_vec();
    assert!(dialed.contains(&doc_metadata("1.0.2.0.4")), "the draft's read reached the board: {dialed:?}");
}

/// Checks that a restore over the draft's held line is refused
/// `held_lines` and lands once the line is kept, against the daemon (§3c.4,
/// THE HELD-LINES GATE; skep #854).
///
/// A draft minted — the mint acknowledged on the running board (skep #868)
/// — and typed in two bursts; the board stopped, a third burst is held
/// `unreachable`, unsent. `history.restore` to the state after the first
/// burst, typed at the page's state, is refused `held_lines` naming the
/// draft and the one line, the line standing untouched (a restore landing
/// first would have the held burst replay over the restored state). The
/// board back at its port, the session re-opened and the line resent and
/// kept, the same restore — typed at the page's state past the kept line —
/// lands, the text the first burst's (the mutant that asks the standing
/// cause alone lets the restore through under a running node; the one that
/// counts another draft's lines refuses a draft holding none).
#[test]
fn a_restore_over_the_drafts_held_line_is_refused_held_lines_and_lands_once_the_line_is_kept() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let g = ground(&dir, &sd);
    let minted = g.op(json!({"op": "create_new_document", "account": "1.0.1"}));
    assert_eq!(minted["resp"], "ack_addr", "the mint on a running board is acknowledged as before: {minted}");
    let d = minted["addr"].as_str().expect("an ack_addr").to_string();
    let p1 = g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "1"}, "values": ["the cat"], "as_of": minted["at"]}))["at"].clone();
    let typed = g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "8"}, "values": [" sat"], "as_of": p1}))["at"].as_u64().expect("the page's state");
    // The board stopped: the next burst is held, unsent.
    sd.shutdown();
    let held = g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "12"}, "values": ["!"], "as_of": typed}));
    assert_eq!((held["resp"].as_str(), held["cause"].as_str(), g.call("held", json!({"session": g.session})).unwrap().as_array().unwrap().len()), (Some("held"), Some("unreachable"), 1), "premise: one line stands held on the draft: {held}");
    let refused = g.call("history.restore", json!({"session": g.session, "draft": d, "at": p1, "as_of": typed})).unwrap_err();
    let v = refused.to_value();
    assert_eq!((refused.name(), v["kind"].as_str(), v["doc"].as_str(), v["held"].as_u64()), ("held_lines", Some("shell"), Some(d.as_str()), Some(1)), "{v}");
    let standing = g.call("held", json!({"session": g.session})).unwrap();
    assert_eq!((standing.as_array().unwrap().len(), standing[0]["cause"].as_str(), standing[0]["sent"].as_bool()), (1, Some("unreachable"), Some(false)), "the line stands as it stood, nothing moved: {standing}");
    // The board back: the session dies and is re-opened, the line resent and
    // kept under the fresh session.
    let sd = spawn_at(&dir.path().join("board"), true, port);
    wait_for(&g.seen, |e| e.name == EventName::SessionDied && e.data["session"] == g.session);
    let session2 = g.call("session", json!({"board": g.board})).unwrap()["session"].as_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !g.seen.lock().unwrap().iter().any(|e| e.name == EventName::Held && e.data["doc"] == d && e.data["state"] == "kept") {
        assert!(Instant::now() < deadline, "the held line was not kept: {:?}", g.call("held", json!({"session": session2})));
        thread::sleep(Duration::from_millis(50));
    }
    assert!(g.call("held", json!({"session": session2})).unwrap().as_array().unwrap().is_empty(), "the line kept, the file compacted away");
    // The same restore, typed at the page's state past the kept line, lands.
    let read = g.position();
    let restored = g.call("history.restore", json!({"session": session2, "draft": d, "at": p1, "as_of": read})).unwrap_or_else(|r| panic!("the line kept, the restore lands: {r}"));
    crate::shapes::assert_declared("Restored", &restored);
    let text = g.shell.call("op", &json!({"session": session2, "frame": skep_client::board::frames::retrieve_v(&d, 1, 14)})).unwrap();
    assert_eq!(text["items"].as_array().into_iter().flatten().map(|i| i["content"].as_str().unwrap_or("")).collect::<String>(), "the cat", "{restored}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks a draft put back to a past state and back again, against the
/// daemon.
///
/// A draft typed in three bursts — "the cat", " sat", "!!!" — and another
/// document minted after, so the board's position stands past the page's
/// state of the draft, has its state after the first burst read by
/// `history.past`: the answer declared, `at` the state's position, `as_of`
/// the board's position, `state` and `sent` the first burst's one run,
/// nothing covered, `marker` null — the board's position unmoved, no
/// arrangement row, the hold's last arrangement write on the draft as it
/// was. The draft is then restored to that state, typed at the page's
/// state, the last burst's ack: the answer declared, `at` the state's
/// position, `as_of` the board's position as the read found it — never the
/// page's state — `marker` null; the text "the cat"; ONE `set_arrangement`
/// row under the draft, naming no base and no merge; the hold's last
/// arrangement write on the draft the restore's. Restored again at the
/// answer's `as_of`, typed at its `position`, the whole text is back. A
/// position at the head is refused `merge_refused` with `not_past` by both
/// rows, its `current` the draft's position, nothing written; a published
/// document `not_owner`, `published` true, by both, and one the board never
/// registered `no_such_document` (the mutants that answer the read's `at`
/// as its `as_of` or the extent as `covered`, write or note at the read,
/// send a second write, name a base or a merge, answer the page's state as
/// the way back, or note no restore).
#[test]
fn a_draft_is_restored_to_a_past_state_by_one_write_and_back_through_the_answers_as_of() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let minted = g.op(json!({"op": "create_new_document", "account": "1.0.1"}));
    let d = minted["addr"].as_str().expect("an ack_addr").to_string();
    let burst = |ordinal: &str, text: &str, as_of: &Value| g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": ordinal}, "values": [text], "as_of": as_of}))["at"].clone();
    let p1 = burst("1", "the cat", &minted["at"]);
    let p2 = burst("8", " sat", &p1);
    let typed = burst("12", "!!!", &p2);
    assert_eq!(g.text(&d, 14), "the cat sat!!!", "the premise");
    g.op(json!({"op": "create_new_document", "account": "1.0.1"}));
    let restore = |at: &Value, as_of: &Value| g.call("history.restore", json!({"session": g.session, "draft": d, "at": at, "as_of": as_of})).unwrap_or_else(|r| panic!("{r}"));
    let before = g.position();
    assert!(typed.as_u64().is_some_and(|at| at < before), "the premise: the board's position past the page's state of the draft");
    // The past state read first: the state and its mapping answered at the
    // board's position, nothing written and nothing noted.
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let arranged = g.shell.holds.last_arranged(&entry, &d);
    let past = g.call("history.past", json!({"session": g.session, "draft": d, "at": p1})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Past", &past);
    let first_burst = json!([{"origin": d, "i_start": 1, "width": 7}]);
    assert_eq!(
        (past["draft"].as_str(), &past["at"], past["as_of"].as_u64(), &past["state"], &past["sent"], past["covered"].as_u64(), past["marker"].is_null()),
        (Some(d.as_str()), &p1, Some(before), &first_burst, &first_burst, Some(0), true),
        "the state after the first burst, no record to map it through: {past}"
    );
    assert!(g.position() == before && arrangement_rows(&g, &d, before).is_empty(), "the read wrote nothing");
    assert_eq!(g.shell.holds.last_arranged(&entry, &d), arranged, "the read noted nothing");
    let restored = restore(&p1, &typed);
    crate::shapes::assert_declared("Restored", &restored);
    let position = restored["position"].as_u64().expect("the write's commit");
    assert_eq!((restored["draft"].as_str(), &restored["at"], restored["as_of"].as_u64(), restored["marker"].is_null()), (Some(d.as_str()), &p1, Some(before), true), "{restored}");
    assert!(position > before, "{restored}");
    assert_eq!(g.text(&d, 14), "the cat", "the state after the first burst");
    assert_eq!(arrangement_rows(&g, &d, before), [(false, false)], "one arrangement row, no base and no merge");
    assert_eq!(g.shell.holds.last_arranged(&entry, &d), Some(position), "the restore noted as the principal's latest arrangement write");
    // The way back: the state the read found, typed at the restore's ack.
    let back = restore(&restored["as_of"], &restored["position"]);
    assert!(back["position"].as_u64().is_some_and(|at| at > position), "{back}");
    assert_eq!(g.text(&d, 14), "the cat sat!!!", "the whole text again");
    // At the head: no past position.
    let head = g.position();
    let refused = g.call("history.restore", json!({"session": g.session, "draft": d, "at": head, "as_of": back["position"]})).unwrap_err();
    let v = refused.to_value();
    assert_eq!((refused.name(), v["arm"].as_str(), v["draft"].as_str(), v["at"].as_u64(), v["current"].as_u64()), ("merge_refused", Some("not_past"), Some(d.as_str()), Some(head), Some(head)), "{v}");
    let read = g.call("history.past", json!({"session": g.session, "draft": d, "at": head})).unwrap_err().to_value();
    assert_eq!((read["name"].as_str(), read["arm"].as_str(), read["at"].as_u64(), read["current"].as_u64()), (Some("merge_refused"), Some("not_past"), Some(head), Some(head)), "the read too: {read}");
    assert_eq!(g.position(), head, "nothing written");
    // A published document, and one the board never registered: refused at
    // the first read.
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let published = g.call("history.restore", json!({"session": g.session, "draft": edition, "at": 1, "as_of": head})).unwrap_err().to_value();
    assert_eq!((published["name"].as_str(), published["addr"].as_str(), published["published"].as_bool()), (Some("not_owner"), Some(edition.as_str()), Some(true)), "{published}");
    let read = g.call("history.past", json!({"session": g.session, "draft": edition, "at": 1})).unwrap_err().to_value();
    assert_eq!((read["name"].as_str(), read["addr"].as_str(), read["published"].as_bool()), (Some("not_owner"), Some(edition.as_str()), Some(true)), "the read too: {read}");
    let unregistered = "1.0.1.0.999";
    let none = g.call("history.restore", json!({"session": g.session, "draft": unregistered, "at": 1, "as_of": head})).unwrap_err().to_value();
    assert_eq!((none["name"].as_str(), none["doc"].as_str()), (Some("no_such_document"), Some(unregistered)), "{none}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that the restore is typed against the page's state, against the
/// daemon (B3-S7).
///
/// A draft typed in two bursts, the page's state the second's ack; a SECOND
/// DEVICE's write lands on it after — another hand's. `history.past` then
/// answers the state after the first burst with its `as_of` the board's
/// position, past that write, and changes nothing the restore does: the
/// restore typed at the page's state is the board's `arrangement_moved`,
/// `site.as_of` the page's state and `site.current` the other hand's write,
/// nothing changed; typed at a read past that write — the page's state once
/// it has read the change — it lands (the mutant that types at the shell's
/// own read lands the first and writes over a change the page never showed;
/// the one that types at the shell's last acknowledgment on the draft
/// refuses the second, the other hand's write past every ack of this
/// shell's).
#[test]
fn the_restore_is_typed_at_the_pages_state_refused_past_another_hands_change_and_landing_past_a_read_of_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let minted = g.op(json!({"op": "create_new_document", "account": "1.0.1"}));
    let d = minted["addr"].as_str().expect("an ack_addr").to_string();
    let p1 = g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "1"}, "values": ["the cat"], "as_of": minted["at"]}))["at"].clone();
    let typed = g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "8"}, "values": [" sat"], "as_of": p1}))["at"].as_u64().expect("the page's state");
    let second = second_device(&dir, &sd);
    let theirs = second.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "1"}, "values": ["#"], "as_of": second.position()}));
    let theirs_at = theirs["at"].as_u64().expect("the other hand's position");
    second.shell.shutdown();
    assert!(typed < theirs_at, "the premise: the other hand's write past the page's state");
    let before = g.position();
    // The past state's read is made at the board's position, past the other
    // hand's write: its `as_of` is no typed state.
    let past = g.call("history.past", json!({"session": g.session, "draft": d, "at": p1})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((past["as_of"].as_u64(), &past["state"]), (Some(before), &json!([{"origin": d, "i_start": 1, "width": 7}])), "{past}");
    assert!(theirs_at <= before, "the premise: the read past the other hand's write");
    let moved = g.call("history.restore", json!({"session": g.session, "draft": d, "at": p1, "as_of": typed})).unwrap_err();
    let v = moved.to_value();
    assert_eq!(
        (moved.name(), v["kind"].as_str(), v["site"]["as_of"].as_u64(), v["site"]["current"].as_u64()),
        ("arrangement_moved", Some("refused"), Some(typed), Some(theirs_at)),
        "typed at the page's state: {v}"
    );
    assert_eq!((g.text(&d, 12), g.position()), ("#the cat sat".to_string(), before), "nothing changed");
    // The page reads the change: its state past the other hand's write.
    let read = g.position();
    let restored = g.call("history.restore", json!({"session": g.session, "draft": d, "at": p1, "as_of": read})).unwrap_or_else(|r| panic!("typed past the change, the restore lands: {r}"));
    crate::shapes::assert_declared("Restored", &restored);
    assert_eq!(g.text(&d, 12), "the cat", "{restored}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks a restore across the person's own publication, against the
/// daemon (B3-S7).
///
/// A draft staged from a memberless edition holds "the quick brown fox",
/// then " jumps"; its publication (E.1) re-windows it onto the member's
/// words, a change to its arrangement that no ack through `op` carries.
/// `history.past` at the state before " jumps" answers that state as the
/// draft's own words and `sent` as the trunk's, every position covered. A
/// restore typed at the shell's last acknowledgment on the draft — the
/// second burst's — is the board's `arrangement_moved`, `site.current` the
/// publication's position. Typed at the page's state — the publication's
/// acknowledged position, the page's own act on the draft — the restore to
/// that state lands: the text "the quick brown fox", its run the TRUNK's
/// identity by the records' mapping, never the draft's own words back (the
/// mutant that sends the state unmapped is the board's `already_published`;
/// the one that answers the read's `state` as its `sent` names the draft's
/// words where the trunk's come back).
#[test]
fn a_restore_across_the_persons_own_publication_lands_and_brings_the_words_back_as_the_trunks() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let d = g.staged(&edition, "the quick brown fox");
    let before_jumps = g.position();
    let jumps_at = g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "20"}, "values": [" jumps"], "as_of": before_jumps}))["at"].as_u64().expect("the burst's position");
    g.call("publication.open", json!({"session": g.session, "draft": d, "doc": edition, "readable_drafts": [d], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let published_at = acked["at"].as_u64().expect("the publication's position");
    let runs = |width: u64| -> Vec<(String, String)> {
        g.op(image(&d, 1, width))["runs"].as_array().expect("runs").iter().map(|r| (r["i_start"].as_str().unwrap().to_string(), r["width"].as_str().unwrap().to_string())).collect()
    };
    assert_eq!(runs(25), vec![(format!("{edition}.0.1.1"), "25".to_string())], "the premise: the draft re-windowed onto the member's words");
    let past = g.call("history.past", json!({"session": g.session, "draft": d, "at": before_jumps})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Past", &past);
    assert_eq!(
        (&past["state"], &past["sent"], past["covered"].as_u64()),
        (&json!([{"origin": d, "i_start": 1, "width": 19}]), &json!([{"origin": edition, "i_start": 1, "width": 19}]), Some(19)),
        "the state the draft's own words, sent as the trunk's: {past}"
    );
    let restore = |as_of: u64| g.call("history.restore", json!({"session": g.session, "draft": d, "at": before_jumps, "as_of": as_of}));
    let moved = restore(jumps_at).unwrap_err();
    let v = moved.to_value();
    assert_eq!((moved.name(), v["site"]["current"].as_u64()), ("arrangement_moved", Some(published_at)), "the shell's last ack on the draft is behind the publication: {v}");
    let restored = restore(published_at).unwrap_or_else(|r| panic!("typed at the publication's ack, the restore lands: {r}"));
    crate::shapes::assert_declared("Restored", &restored);
    assert_eq!(g.text(&d, 25), "the quick brown fox", "{restored}");
    assert_eq!(runs(19), vec![(format!("{edition}.0.1.1"), "19".to_string())], "the words back as the trunk's identity");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a restore is noted as the editor's own arrangement write,
/// against the daemon (P3).
///
/// L, staged from E.2, takes the merge of E.2 with E.1.1; the editor reads
/// L's state as staged — `history.past` answering L's marker as the restore
/// after it does — and restores L to it — the answer carrying L's marker,
/// declared, its `head_copied` the decimal string the board serves, which
/// the restore leaves standing — then back through the answer's `as_of`, L
/// holding M again. `merge.undo`, typed at the editor's own last
/// arrangement write on L, the way back's, lands: L's text E.2's again, its
/// marker gone (the mutant that notes no restore types the undo at the
/// landing, below both restores, and the board refuses it
/// `arrangement_moved` as another hand's change).
#[test]
fn a_restore_is_noted_as_the_editors_own_so_merge_undo_after_it_and_its_way_back_lands() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let staged = g.op(stage(&f.e2, None));
    let l = staged["addr"].as_str().expect("an ack_addr").to_string();
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let landed_at = landed["position"].as_u64().expect("the landing's position");
    assert_eq!(g.text(&l, 20).len(), 19, "the premise: L holds M");
    let restore = |at: &Value, as_of: u64| g.call("history.restore", json!({"session": g.session, "draft": l, "at": at, "as_of": as_of})).unwrap_or_else(|r| panic!("{r}"));
    let past = g.call("history.past", json!({"session": g.session, "draft": l, "at": staged["at"]})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Past", &past);
    crate::shapes::assert_declared("MergeMarker", &past["marker"]);
    let first = restore(&staged["at"], landed_at);
    crate::shapes::assert_declared("Restored", &first);
    crate::shapes::assert_declared("MergeMarker", &first["marker"]);
    assert_eq!(
        (&first["marker"]["sides"], first["marker"]["head"].as_str(), first["marker"]["head_copied"].as_str(), first["marker"]["at"].as_u64()),
        (&json!([f.e11]), Some(f.e2.as_str()), Some("13"), Some(landed_at)),
        "the marker as it stands: {first}"
    );
    assert_eq!(past["marker"], first["marker"], "the past state's read answers the marker the restore answers: {past}");
    assert_eq!(g.text(&l, 20), "the fox jumps", "L as staged");
    assert_eq!(g.op(doc_metadata(&l))["merge"]["at"].as_u64(), Some(landed_at), "the marker stands");
    restore(&first["as_of"], first["position"].as_u64().unwrap());
    assert_eq!(g.text(&l, 20).len(), 19, "L holds M again");
    let undone = g.call("merge.undo", json!({"session": g.session})).unwrap_or_else(|r| panic!("typed at the way back, the undo lands: {r}"));
    crate::shapes::assert_declared("Undone", &undone);
    assert_eq!(g.text(&l, 20), "the fox jumps", "{undone}");
    assert!(g.op(doc_metadata(&l))["merge"].is_null(), "the marker gone");
    g.shell.shutdown();
    sd.shutdown();
}
