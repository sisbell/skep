//! THE HELD-BURST STORE against the real daemon in-process: a burst held
//! while the daemon is stopped and resent `kept` after a restart, the
//! kernel poison holding a burst `poisoned` then `halted`, the poisoned
//! burst that lands at the restart and is kept, the signed session's own
//! attested row kept by the resend, a refused run with its `behind` lines
//! and `resolve`'s two acts, the close order and the relaunch listing its
//! held line, a second principal's file untouched and unlisted, a burst on
//! a draft just minted kept across a restart, a relaunch with its board
//! down listing and resending its held line, and the probe keeping its
//! cadence while the board keeps committing.

use super::*;

/// A claimed board, a bare shell opened over it, a session and a draft with one
/// insert acked — the ground every hold cell stands on.
fn held_ground(dir: &TempDir, sd: &Skepd) -> (Shell, Arc<Mutex<Vec<Event>>>, String, String, String) {
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _lines) = shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let draft = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["addr"].as_str().unwrap().to_string();
    shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["a"]}})).unwrap();
    (shell, seen, board, session, draft)
}

/// T7: a burst POISONED by the kernel (`JournalBarrier` + `JournalRepair`) is
/// held `poisoned`, `held(session)` lists it; the daemon restarted at the same
/// port, a fresh session re-acquired, the resend acked, the `held` event
/// `kept`, the row read back from the board, and the file compacted away. The
/// hold here is driven by STOPPING the daemon (the burst's dial `unreachable`,
/// `sent: false`, so it did not land) — deterministic across a restart; the
/// daemon's halt doors are exercised as hold triggers in the two cells below.
#[test]
fn a_held_burst_is_resent_after_a_restart_and_kept() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let (shell, seen, board, session, draft) = held_ground(&dir, &sd);
    // Stop the daemon; the next burst's dial fails `unreachable` and is held.
    sd.shutdown();
    let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"]}})).unwrap();
    assert_eq!(held["resp"], "held", "{held}");
    assert_eq!(held["cause"], "unreachable", "{held}");
    let rows = shell.call("held", &json!({"session": session})).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1, "held(session) lists the burst: {rows}");
    assert_eq!((rows[0]["doc"].as_str(), rows[0]["cause"].as_str()), (Some(draft.as_str()), Some("unreachable")));
    // Restart at the same port; the bare session dies, a fresh one re-acquired.
    let sd = spawn_at(&dir.path().join("board"), true, port);
    wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let session2 = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    // The resend runs under the fresh session (the feed's probe/daemon-running):
    // the held event reaches `kept`.
    let deadline = Instant::now() + Duration::from_secs(20);
    while !seen.lock().unwrap().iter().any(|e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept") {
        if Instant::now() >= deadline {
            let held: Vec<Value> = seen.lock().unwrap().iter().filter(|e| e.name == EventName::Held).map(|e| e.data.clone()).collect();
            let rows = shell.call("held", &json!({"session": session2})).unwrap();
            panic!("no kept; held events {held:?}; held(session2) {rows}");
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(shell.call("held", &json!({"session": session2})).unwrap().as_array().unwrap().is_empty(), "the file compacted away");
    let read = shell.call("op", &json!({"session": session2, "frame": skep_client::board::frames::retrieve_v(&draft, 2, 1)})).unwrap();
    assert_eq!(read["items"][0]["content"], "b", "the resent burst is on the board: {read}");
    shell.shutdown();
    sd.shutdown();
}

/// T7's named door `fail_the_attest_stores_next_write` fails the attest store's
/// DURABLE COPY, which a board writes only for a signed commit BELOW the
/// reclaim floor; a fresh test board does not reach it without advancing the
/// floor, so the write-path halt is driven instead by the kernel poison below,
/// which sets `writes.halted` identically (every write then `poisoned`, §The
/// other endpoints). Here the POISON door holds a burst `poisoned` at the
/// direct refusal, and once the feed's tick reads `writes.halted` true, a
/// further burst holds `halted` — the two causes §3c.4 draws.
#[test]
fn the_poisoned_write_path_holds_bursts_poisoned_then_halted() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let (shell, _seen, _board, session, draft) = held_ground(&dir, &sd);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalBarrier, std::io::ErrorKind::Other);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalRepair, std::io::ErrorKind::Other);
    // The poisoning burst is refused `poisoned` directly and held.
    let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"]}})).unwrap();
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("poisoned")), "{held}");
    assert_eq!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().len(), 1, "held(session) lists it");
    // Once the feed's probe reads `writes.halted` true, a further burst holds
    // `halted` (before any dial).
    let deadline = Instant::now() + Duration::from_secs(20);
    let halted = loop {
        let answer = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "3"}, "values": ["c"]}})).unwrap();
        if answer["cause"] == "halted" {
            break answer;
        }
        assert!(Instant::now() < deadline, "no burst held `halted`: {answer}");
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(halted["resp"], "held", "{halted}");
    shell.shutdown();
    sd.shutdown();
}

/// The acting principal's held file under `store`, where one stands.
fn held_path(store: &Path) -> Option<PathBuf> {
    std::fs::read_dir(store.join("held")).ok()?.flatten().map(|e| e.path().join("principal-1.held")).find(|p| p.is_file())
}

/// A delivery's text, its items joined (adjacent text comes as one item).
fn text_of(delivery: &Value) -> String {
    delivery["items"].as_array().unwrap().iter().map(|i| i["content"].as_str().unwrap_or("")).collect()
}

/// THE POISONED BURST LANDS AND IS KEPT (§3c.2): the kernel poisoned as the
/// cell above poisons it, a burst of two characters held `poisoned` — its
/// line on disk `sent: true`, since the failed repair keeps its frames in the
/// journal — then the daemon restarted at the same port, whose open replays
/// them: the resend's read finds the landed row, the site holds the burst's
/// two values, the `held` event reaches `kept` and never `moved`, the board
/// holds the burst's row exactly once, and the file compacts away (the
/// mutant that leaves `poisoned` at `sent: false`, and the one that holds the
/// frame's one string to one position's value, face the person's own text
/// `moved`).
#[test]
fn a_poisoned_burst_lands_at_the_restart_and_is_kept() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let (shell, seen, board, session, draft) = held_ground(&dir, &sd);
    let store = dir.path().join("store");
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalBarrier, std::io::ErrorKind::Other);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalRepair, std::io::ErrorKind::Other);
    let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["bc"]}})).unwrap();
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("poisoned")), "{held}");
    let rows = shell.call("held", &json!({"session": session})).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1, "held(session) lists it: {rows}");
    assert_eq!(rows[0]["sent"], true, "a poisoned burst may have landed: {rows}");
    let line = std::fs::read_to_string(held_path(&store).expect("the held file stands")).unwrap();
    assert!(line.contains("\"cause\":\"poisoned\"") && line.contains("\"sent\":true"), "the line on disk says so: {line}");
    // The restart at the same port replays the journal: the burst lands.
    sd.shutdown();
    let sd = spawn_at(&dir.path().join("board"), true, port);
    wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let session2 = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept");
    let states: Vec<String> = seen.lock().unwrap().iter().filter(|e| e.name == EventName::Held && e.data["doc"] == draft).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect();
    assert!(!states.contains(&"moved".to_string()), "the own burst is never faced moved: {states:?}");
    assert!(shell.call("held", &json!({"session": session2})).unwrap().as_array().unwrap().is_empty(), "the lines are done");
    assert!(held_path(&store).is_none(), "the file compacted away");
    // The board holds the burst ONCE: the draft reads `a`, `bc` and the rows
    // under it since genesis are the mint, the first insert and the burst.
    let read = shell.call("op", &json!({"session": session2, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 3)})).unwrap();
    assert_eq!(text_of(&read), "abc", "{read}");
    let token = shell.sessions.get(&session2).unwrap().token.clone();
    let rows = changes_under(&shell.boards[0].board, &token, &draft, 0);
    assert_eq!(rows.len(), 3, "the mint, the first insert, the burst once: {rows:?}");
    assert_eq!((rows[0]["op"].as_str(), rows[1]["op"].as_str()), (Some("create_new_document"), Some("insert")), "{rows:?}");
    // The daemon fact the read rests on: the write path records acks alone,
    // so the replayed commit's row carries LOST testimony — its hand and kind
    // the reserved null — and the arrangement alone could keep it.
    assert!(rows[2]["key"].is_null() && rows[2]["op"].is_null() && rows[2]["docs"].is_null(), "the replayed commit's testimony is lost: {:?}", rows[2]);
    shell.shutdown();
    sd.shutdown();
}

/// THE SIGNED MODE's OWN ROW: a held burst whose line says `sent: true` has
/// LANDED by the signed session's own hand, and the resend's read after the
/// daemon's restart — under the session the restart arm re-opened —
/// recognises it: the `held` event reaches `kept`, never `moved`, nothing is
/// re-sent, and the board holds the row once. The row's shape is pinned as
/// the daemon serves it: the shell attests every insert, but the daemon
/// DROPS an attest on a write outside the publish class (wire.md §The two
/// attestation codes), and a burst lands on a draft, so its row is an
/// UNSIGNED entry whose `key` is the session key's fingerprint — no burst
/// row is a signed entry on a conforming daemon; the own-row test's signed
/// arm (`attest`, no `key`) is fenced by `hold`'s suite over a fake board.
/// The in-flight landing is forced by hand: the attested burst of two
/// characters written through the board under the session's token, so the
/// shell saw no ack, then held `sent: true` as a lost answer is.
#[test]
fn a_signed_sessions_landed_burst_is_kept_by_the_resend() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (signed, lines) = shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answerer = answer_moments(signed.subscribe(), Arc::clone(&signed.pending), Arc::clone(&seen));
    let board = signed.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = signed.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let draft = signed.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["addr"].as_str().unwrap().to_string();
    let first = signed.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["a"]}})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    let base = first["at"].as_u64().expect("the ack's position");
    // The in-flight burst: composed and signed as the shell composes it,
    // written under the session's token through the board itself.
    let entry = signed.sessions.get(&session).unwrap();
    let Kind::Signed { fingerprint: fp, .. } = entry.facts.kind.clone() else { panic!("a signed session holds a key") };
    let frame = json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["bc"]});
    let board_entry = Arc::clone(&signed.boards[0]);
    let term = board_entry.board.board_term().unwrap().expect("H.1 stands on a claimed board");
    let signer = sessions::signer(&signed.store, &signed.store.key_path(&fp)).unwrap();
    let mut attested = frame.clone();
    Composer { board: &board_entry.board, token: &entry.token, signer: &*signer, account: entry.facts.account.as_deref().unwrap(), term }.attach(&mut attested).unwrap();
    assert!(attested.get("attest").is_some(), "the shell attests every insert");
    let Answer::Document(landed) = board_entry.board.op(Some(&entry.token), &attested).unwrap() else { panic!("the dial closed") };
    assert!(landed["resp"].as_str().is_some_and(|r| r.starts_with("ack")), "the burst landed by the own hand: {landed}");
    let rows = changes_under(&board_entry.board, &entry.token, &draft, base);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["key"].as_str(), Some(fp.to_hex().as_str()), "a draft's insert is outside the publish class: the attest dropped, the row unsigned under the key's fingerprint: {rows:?}");
    assert!(rows[0].get("attest").is_none(), "{rows:?}");
    // Held as a lost answer is: the line `sent: true`.
    let held = signed.holds.hold(&board_entry.reference, &entry, &Burst::admit(frame.clone(), &entry).unwrap(), Reason::of("unreachable", true)).unwrap();
    assert_eq!(held["resp"], "held", "{held}");
    assert_eq!(signed.call("held", &json!({"session": session})).unwrap()[0]["sent"], true);
    // The restart: the session re-opened under a fresh reference, the resend
    // run under it — the read recognises the row, nothing is re-sent.
    sd.shutdown();
    let sd = spawn_at(&dir.path().join("board"), true, port);
    let died = wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let reopened = died.data["reason"]["session"].as_str().expect("the restart arm names the re-opened session").to_string();
    wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept");
    let states: Vec<String> = seen.lock().unwrap().iter().filter(|e| e.name == EventName::Held && e.data["doc"] == draft).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect();
    assert!(!states.contains(&"moved".to_string()), "the own signed row is never faced moved: {states:?}");
    assert!(signed.call("held", &json!({"session": reopened})).unwrap().as_array().unwrap().is_empty(), "the line is done kept");
    let token = signed.sessions.get(&reopened).unwrap().token.clone();
    let rows = changes_under(&board_entry.board, &token, &draft, base);
    assert_eq!(rows.len(), 1, "the burst's row once, nothing re-sent: {rows:?}");
    let read = signed.call("op", &json!({"session": reopened, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 3)})).unwrap();
    assert_eq!(text_of(&read), "abc", "{read}");
    signed.shutdown();
    drop(signed);
    answerer.join().unwrap();
    sd.shutdown();
}

/// T10: a REFUSED run — `out_of_bounds` (a `permanent` refusal) on a burst, two
/// bursts behind it on the same document held `behind`, the `held` event
/// `refused`; a `resolve` on a holding line is `not_resolvable`, an unknown
/// ordinal `no_such_held`; `resolve(drop)` drops the run and its two behind
/// lines; `resolve(send)` re-faces the run where the refusal recurs.
#[test]
fn a_refused_run_holds_behind_it_and_resolve_acts_on_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let (shell, seen, _board, session, draft) = held_ground(&dir, &sd);
    // A burst past the draft's head: `out_of_bounds`, a permanent refusal → a
    // refused run (an insert at a far ordinal the draft has no room for).
    let far = json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "900000"}, "values": ["r"]}});
    let refused = shell.call("op", &far).unwrap();
    assert_eq!(refused["resp"], "held", "a permanent refusal is a refused run: {refused}");
    let k = refused["held"].as_u64().unwrap();
    assert!(refused["cause"].as_str().unwrap().starts_with("out_of_bounds"), "{refused}");
    wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "refused");
    // Two more bursts on the document while the run stands → held `behind`.
    for v in ["s", "t"] {
        let behind = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "900001"}, "values": [v]}})).unwrap();
        assert_eq!(behind["cause"], "behind", "{behind}");
    }
    assert_eq!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().len(), 3);
    // A `resolve` on a holding line, and an unknown ordinal.
    let behind_k = shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().iter().find(|r| r["cause"] == "behind").unwrap()["held"].as_u64().unwrap();
    assert_eq!(shell.call("resolve", &json!({"session": session, "held": behind_k, "act": "drop"})).unwrap_err().name(), "not_resolvable");
    assert_eq!(shell.call("resolve", &json!({"session": session, "held": 9999, "act": "drop"})).unwrap_err().name(), "no_such_held");
    // `send` re-faces the run where the refusal recurs.
    let refused_count = || seen.lock().unwrap().iter().filter(|e| e.name == EventName::Held && e.data["state"] == "refused").count();
    let before_send = refused_count();
    shell.call("resolve", &json!({"session": session, "held": k, "act": "send"})).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while refused_count() <= before_send {
        assert!(Instant::now() < deadline, "the send did not re-face the refused run");
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().len(), 3, "the refusal recurs, the run still stands");
    // `drop` the run: all three go.
    shell.call("resolve", &json!({"session": session, "held": k, "act": "drop"})).unwrap();
    assert!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().is_empty(), "the run and its behind lines are dropped");
    shell.shutdown();
    sd.shutdown();
}

/// T11: the close order — a held burst's line is on disk and listed by
/// `held(session)` before `shutdown`, which writes nothing of the store; the
/// next `Shell::open` over the same store lists the line at its first
/// session's open.
#[test]
fn the_close_persists_the_held_line_and_the_relaunch_lists_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    let draft;
    {
        let (shell, _seen, _board, session, d) = held_ground(&dir, &sd);
        draft = d;
        // Stop the node under the shell's feet, then a burst holds `unreachable`.
        sd.shutdown();
        let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"]}})).unwrap();
        assert_eq!(held["resp"], "held", "{held}");
        assert_eq!(held["cause"], "unreachable");
        // The line is on disk before any close: `held(session)` lists it.
        assert_eq!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().len(), 1);
        let path = store.join("held");
        let before = dir_signature(&path);
        assert!(before.iter().any(|(n, _)| n.ends_with("principal-1.held")), "the held line is on disk: {before:?}");
        shell.shutdown();
        assert_eq!(dir_signature(&path), before, "shutdown writes nothing of the store");
        drop(shell);
    }
    // A fresh daemon and a fresh shell over the same store: the first
    // session's open reads the principal's file and lists its line.
    let sd = spawn_at(&dir.path().join("board"), true, port);
    let (shell, _lines) = shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let rows = shell.call("held", &json!({"session": session})).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1, "the relaunch lists the held line: {rows}");
    assert_eq!(rows[0]["doc"], draft);
    shell.shutdown();
    sd.shutdown();
}

/// A directory's shape — the file names and sizes under it, sorted — so a test
/// can pin that nothing changed.
fn dir_signature(root: &Path) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, u64)>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let name = format!("{prefix}{}", e.file_name().to_string_lossy());
            let meta = e.metadata().unwrap();
            if meta.is_dir() {
                walk(&e.path(), &format!("{name}/"), out);
            } else {
                out.push((name, meta.len()));
            }
        }
    }
    walk(root, "", &mut out);
    out.sort();
    out
}

/// T12: a second principal's file is untouched and unlisted under the first's
/// session — no answer and no event names a path, a directory or the other
/// principal.
#[test]
fn a_second_principals_file_is_untouched_and_unlisted() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    // ONE shell (so one lock on `held/<chain>/`) opening a session for each of
    // two principals; principal 1 owns the draft, principal 2 holds its own
    // burst against it while the board is down.
    let (shell, _lines) = shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let s1 = shell.call("session", &json!({"board": board, "principal": 1})).unwrap()["session"].as_str().unwrap().to_string();
    let s2 = shell.call("session", &json!({"board": board, "principal": 2})).unwrap()["session"].as_str().unwrap().to_string();
    let d1 = shell.call("op", &json!({"session": s1, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["addr"].as_str().unwrap().to_string();
    // The board goes down: each principal's next burst is held `unreachable`,
    // each in its own file — `principal-1.held` and `principal-2.held`.
    sd.shutdown();
    let h1 = shell.call("op", &json!({"session": s1, "frame": {"op": "insert", "doc": d1, "at": {"subspace": "1", "ordinal": "2"}, "values": ["one"]}})).unwrap();
    assert_eq!(h1["resp"], "held");
    let h2 = shell.call("op", &json!({"session": s2, "frame": {"op": "insert", "doc": d1, "at": {"subspace": "1", "ordinal": "3"}, "values": ["two"]}})).unwrap();
    assert_eq!(h2["resp"], "held");
    assert!(store.join("held").exists(), "the directory stands");
    // Principal 1's `held(session)` lists principal 1's line alone; no answer
    // names a path, a directory or principal 2 (the token-/path-shaped run).
    let rows1 = shell.call("held", &json!({"session": s1})).unwrap();
    assert_eq!(rows1.as_array().unwrap().len(), 1, "principal 1's lines alone: {rows1}");
    let rows2 = shell.call("held", &json!({"session": s2})).unwrap();
    assert_eq!(rows2.as_array().unwrap().len(), 1, "principal 2's own line, read under principal 2 alone");
    let text = format!("{rows1}{h1}");
    assert!(!text.contains("principal-2") && !text.contains("principal-1") && !text.contains("/held/") && !text.contains(&store.display().to_string()), "no path, directory or principal file name crosses: {text}");
    shell.shutdown();
}

/// A BURST ON A DRAFT JUST MINTED (§3c.2's `base`): the mint's ack is noted
/// as every write's is, so a burst held on the draft before any burst of it
/// was acked reads from the mint's position — the daemon stopped under it,
/// restarted at the same port, a fresh session re-acquired: the burst is
/// resent and kept, never faced `moved` (the mutant that notes a burst's
/// acks alone reads the mint's own row and faces the person's text).
#[test]
fn a_burst_held_on_a_draft_just_minted_is_kept_after_a_restart() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _lines) = shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let draft = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["addr"].as_str().unwrap().to_string();
    sd.shutdown();
    let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hi"]}})).unwrap();
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("unreachable")), "{held}");
    let sd = spawn_at(&dir.path().join("board"), true, port);
    wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let session2 = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept");
    let states: Vec<String> = seen.lock().unwrap().iter().filter(|e| e.name == EventName::Held && e.data["doc"] == draft).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect();
    assert!(!states.contains(&"moved".to_string()), "the burst is never faced moved: {states:?}");
    let read = shell.call("op", &json!({"session": session2, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 2)})).unwrap();
    assert_eq!(text_of(&read), "hi", "{read}");
    shell.shutdown();
    sd.shutdown();
}

/// A RELAUNCH WITH ITS BOARD DOWN (§3c.7): the held file is read at a
/// session's open, never only at the shell's — a shell opened while its
/// board's port is closed, the daemon started there before the first
/// `session`: `held(session)` lists the line the store already holds, and the
/// probe resends it `kept` (the mutant that reads the store at the shell's
/// open alone lists nothing and resends nothing). And a file written after
/// a relaunch whose board was up names the session's account in its header,
/// never an empty one.
#[test]
fn a_relaunch_with_its_board_down_lists_and_resends_the_held_line() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    let draft;
    {
        let (shell, _seen, _board, session, d) = held_ground(&dir, &sd);
        draft = d;
        sd.shutdown();
        let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"]}})).unwrap();
        assert_eq!(held["cause"], "unreachable", "{held}");
        shell.shutdown();
    }
    // The relaunch: the shell opened over the store while its board is down.
    let (relaunched, lines) = shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(relaunched.subscribe(), Arc::clone(&relaunched.pending), Arc::clone(&seen));
    let sd = spawn_at(&dir.path().join("board"), true, port);
    let board = relaunched.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = relaunched.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let rows = relaunched.call("held", &json!({"session": session})).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1, "the session's open lists the held line: {rows}\n{}", lines.lock().unwrap().join("\n"));
    assert_eq!(rows[0]["doc"], draft);
    wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept");
    let read = relaunched.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 2)})).unwrap();
    assert_eq!(text_of(&read), "ab", "the resent burst is on the board: {read}");
    relaunched.shutdown();
    drop(relaunched);
    // A relaunch with the board up, then a burst held: its file's header
    // names the session's account.
    let (again, _lines) = shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let board = again.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = again.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    sd.shutdown();
    let held = again.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "3"}, "values": ["c"]}})).unwrap();
    assert_eq!(held["resp"], "held", "{held}");
    let file = std::fs::read_to_string(held_path(&store).expect("the held file stands")).unwrap();
    let header = file.lines().next().unwrap();
    assert!(header.contains("\"account\":\"1.0.1\""), "the header names the session's account: {header}");
    again.shutdown();
}

/// THE PROBE KEEPS ITS CADENCE while the board keeps committing (§3c.4): a
/// line held `unreachable`, `sent: true` — a lost answer's — at a board that
/// answers, while a second session mints a draft every 500 ms and each
/// commit wakes the board's feed, is resent and kept within three cadences
/// (the mutant that counts the cadence from the feed's last wake never
/// probes while the commits come).
#[test]
fn the_probe_keeps_its_cadence_while_the_board_keeps_committing() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let (shell, seen, board, session, draft) = held_ground(&dir, &sd);
    let writer = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let entry = shell.sessions.get(&session).unwrap();
    let stop = AtomicBool::new(false);
    let kept = thread::scope(|s| {
        s.spawn(|| {
            while !stop.load(Ordering::SeqCst) {
                let _ = shell.call("op", &json!({"session": writer, "frame": {"op": "create_new_document", "account": "1.0.1"}}));
                thread::sleep(Duration::from_millis(500));
            }
        });
        let frame = json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"]});
        shell.holds.hold(&shell.boards[0].reference, &entry, &Burst::admit(frame, &entry).unwrap(), Reason::of("unreachable", true)).unwrap();
        let deadline = Instant::now() + PROBE_CADENCE * 3;
        let kept = loop {
            if seen.lock().unwrap().iter().any(|e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept") {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(50));
        };
        stop.store(true, Ordering::SeqCst);
        kept
    });
    assert!(kept, "the line was not kept within three probe cadences while the board kept committing");
    let read = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 2)})).unwrap();
    assert_eq!(text_of(&read), "ab", "{read}");
    shell.shutdown();
    sd.shutdown();
}
