//! The held-burst store against the real daemon in-process.
//!
//! Its bursts are a signed session's — a bare session reads alone. The suite
//! checks a burst held while the daemon is stopped and resent `kept` after a
//! restart, a burst whose dial meets the death signal held `session_died`
//! and kept under the session the restart arm re-opened, a burst whose
//! reissue meets `write_busy` again held `unreachable` unsent and kept once
//! the board takes writes, the kernel poison
//! holding a burst `poisoned` then `halted`, the
//! poisoned burst that lands at the restart and is kept, a burst that
//! committed and then panicked — answered `500 internal_panic` — held and
//! kept off the read, sent once, the signed session's own attested row kept
//! by the resend, a refused run with its `behind` lines and `resolve`'s two
//! acts, a burst typed against an older state held moved with the board's
//! verdict and nothing of it landing where it carries no anchors, and one
//! carrying them shifted through another writer's change and landing once
//! at the displaced place — a delete and a rearrange by their span's own
//! units, and a delete whose span another writer refilled held moved, the
//! other writer's words untouched — the person's `send` on a moved
//! document raising its base through the changes that moved it, a face
//! after it naming only the changes since — the close order and the relaunch
//! listing its held line, a second principal's file untouched and unlisted,
//! a halted file's path crossing the bridge never and the file shown in the
//! shell's own window as often as the page asks,
//! a burst on a draft just minted kept across a restart, a relaunch with its
//! board down listing its held line — the bare mode's resending none of it,
//! the signed mode's keeping it — the probe keeping its cadence while the
//! board keeps committing, a second shell over the data directory refusing
//! every write and holding nothing, told so by its session's answer and by
//! an event at each edge of the state (skep #789, #827), and two windows
//! across a board's two locks leaving one writer, never none (skep #828).

use super::*;
use crate::held::Opened;
use crate::sessions::open_bare;

/// The ground most hold cells stand on.
///
/// It is the shell over a claimed board, the events seen, the board's
/// reference, a signed session's, and a draft with one insert acked — each
/// by its name, so no cell takes one reference for another.
struct HeldGround {
    shell: Shell,
    seen: Arc<Mutex<Vec<Event>>>,
    board: String,
    session: String,
    draft: String,
    /// The draft's state as the ground leaves it: the `at` of its one acked
    /// insert, which every burst on the draft is typed against (`as_of`,
    /// wire.md §Arrangement) until one of them is acked.
    at: u64,
}

/// Builds the ground: a claimed board and a signed shell opened over it.
///
/// The store's key is the claim's, and the shell holds a session and a draft
/// with one insert acked.
fn held_ground(dir: &TempDir, sd: &Skepd) -> HeldGround {
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let minted = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    let draft = minted["addr"].as_str().unwrap().to_string();
    let acked = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["a"], "as_of": minted["at"]}})).unwrap();
    let at = acked["at"].as_u64().unwrap_or_else(|| panic!("the ground's insert is acked: {acked}"));
    HeldGround { shell, seen, board, session, draft, at }
}

/// Checks that a held burst is resent after a restart and kept.
///
/// A burst held while the daemon is stopped — its dial `unreachable`,
/// `sent: false`, so it did not land — is listed by `held(session)`; the
/// daemon restarted at the same port, a fresh session re-acquired, the
/// resend acked, the `held` event `kept`, the row read back from the board,
/// and the file compacted away. Stopping the daemon is deterministic across
/// a restart; the daemon's halt doors are exercised as hold triggers in the
/// two cells below.
#[test]
fn a_held_burst_is_resent_after_a_restart_and_kept() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let HeldGround { shell, seen, board, session, draft, at } = held_ground(&dir, &sd);
    // Stop the daemon; the next burst's dial fails `unreachable` and is held.
    sd.shutdown();
    let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"], "as_of": at}})).unwrap();
    assert_eq!(held["resp"], "held", "{held}");
    assert_eq!(held["cause"], "unreachable", "{held}");
    let rows = shell.call("held", &json!({"session": session})).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1, "held(session) lists the burst: {rows}");
    assert_eq!(
        (rows[0]["doc"].as_str(), rows[0]["cause"].as_str(), rows[0]["sent"].as_bool()),
        (Some(draft.as_str()), Some("unreachable"), Some(false)),
        "the connection refused, nothing of the burst landed: {rows}"
    );
    // Restart at the same port; the session dies — the restart arm re-opening
    // it — and a fresh one is opened beside it.
    let sd = spawn_at(&dir.path().join("board"), true, port);
    wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let session2 = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    // The resend runs under the fresh session (the feed's
    // probe/daemon-running): the held event reaches `kept`.
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

/// Checks that a burst whose dial meets the death signal is held, and kept
/// under the re-opened session.
///
/// A signed session's token closed at the board while its feed stands
/// quiet, the next burst on its draft meets the death at its own dial (§3c.4;
/// skep #786): the call answers `held`, cause `session_died` — never the
/// `session_died` refusal, and never `unreachable` while the board answers —
/// and its `held` event goes out under the dying session before the
/// session's end, whose `session-died` names the restart arm that re-opened
/// it; `held` under the re-opened session lists the line, its refusal the
/// death's with that arm — read before the probe's cadence, counted from a
/// probe handed to the feed thread just before the call, comes round; the
/// probe resends it under the re-opened session, the `held` event reaching
/// `kept`; and the board holds the burst's text once, the dead token's dial
/// having committed nothing (the mutant that answers the burst
/// `session_died` leaves the person's text to the page; the one that holds
/// it `unreachable` says the board is away while it answers).
#[test]
fn a_burst_whose_dial_meets_the_death_is_held_and_kept_under_the_reopened_session() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let HeldGround { shell, seen, board, session, draft, at } = held_ground(&dir, &sd);
    // The feed widens the session's supplement, then falls quiet: nothing
    // commits, so the burst's dial is the first to meet the death.
    let deadline = Instant::now() + Duration::from_secs(30);
    let (mut events, mut quiet_since) = (0, Instant::now());
    loop {
        let (now, widened) = {
            let seen = seen.lock().unwrap();
            (seen.len(), seen.iter().any(|e| e.name == EventName::Index && e.data["session"] == session))
        };
        if now != events {
            (events, quiet_since) = (now, Instant::now());
        }
        if widened && quiet_since.elapsed() > Duration::from_millis(500) {
            break;
        }
        assert!(Instant::now() < deadline, "the board never fell quiet");
        thread::sleep(Duration::from_millis(20));
    }
    let token = shell.sessions.get(&session).unwrap().token.clone();
    Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new()).session_close(&token).unwrap();
    shell.feed(&board).probe();
    let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"], "as_of": at}})).unwrap();
    crate::shapes::assert_declared("HeldAnswer", &held);
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("session_died")), "{held}");
    let died = wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    assert_eq!(died.data["reason"]["arm"], "restart", "{:?}", died.data);
    let reopened = died.data["reason"]["session"].as_str().expect("the restart arm re-opened the session").to_string();
    let rows = shell.call("held", &json!({"session": reopened})).unwrap();
    assert_eq!(rows.as_array().map(Vec::len), Some(1), "{rows}");
    assert_eq!(
        (rows[0]["cause"].as_str(), rows[0]["refusal"]["name"].as_str(), rows[0]["refusal"]["reason"]["arm"].as_str(), rows[0]["refusal"]["reason"]["session"].as_str()),
        (Some("session_died"), Some("session_died"), Some("restart"), Some(reopened.as_str())),
        "the line carries the death's arm: {rows}"
    );
    {
        let seen = seen.lock().unwrap();
        let holding = seen.iter().position(|e| e.name == EventName::Held && e.data["doc"] == draft && e.data["session"] == session && e.data["state"] == "holding" && e.data["cause"] == "session_died");
        let death = seen.iter().position(|e| e.name == EventName::SessionDied && e.data["session"] == session);
        assert!(matches!((holding, death), (Some(h), Some(d)) if h < d), "the hold is said under the dying session before its end: {holding:?} {death:?}");
    }
    let kept = wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept");
    assert_eq!(kept.data["session"].as_str(), Some(reopened.as_str()), "resent under the re-opened session: {:?}", kept.data);
    let entry = shell.sessions.get(&reopened).unwrap();
    let read = shell.call("op", &json!({"session": reopened, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 2)})).unwrap();
    assert_eq!(text_of(&read), "ab", "the burst is on the board: {read}");
    let rows = changes_under(&entry.board, &entry.token, &draft, at);
    assert_eq!(rows.len(), 1, "the burst landed once: {rows:?}");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a burst whose reissue meets `write_busy` again is held, and
/// kept once the board takes writes.
///
/// The daemon's write permits all held, a signed session's burst on its
/// draft is dialed and reissued once after the short wait, and the reissue's
/// own `write_busy` holds it (§3c.4; skep #786): the call answers `held`,
/// cause `unreachable`, its line `sent: false`, the board having committed
/// nothing — read before the probe's cadence, counted from a probe handed to
/// the feed thread just before the call, comes round; the permits let go,
/// the probe resends it, the `held` event reaching `kept`, and the board
/// holds its text once (the mutant that faces the burst's second
/// `write_busy` hands the page a burst a board briefly full takes a moment
/// later).
#[test]
fn a_burst_whose_reissue_meets_write_busy_again_is_held_and_kept_once_the_board_takes_writes() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let HeldGround { shell, seen, board, session, draft, at } = held_ground(&dir, &sd);
    let mut permits = Vec::new();
    while let Some(permit) = sd.daemon().try_hold_write_permit() {
        permits.push(permit);
    }
    shell.feed(&board).probe();
    let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"], "as_of": at}})).unwrap();
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("unreachable")), "{held}");
    let rows = shell.call("held", &json!({"session": session})).unwrap();
    assert_eq!((rows.as_array().map(Vec::len), rows[0]["sent"].as_bool()), (Some(1), Some(false)), "the board committed nothing: {rows}");
    drop(permits);
    wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept");
    let read = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 2)})).unwrap();
    assert_eq!(text_of(&read), "ab", "the burst is on the board: {read}");
    let entry = shell.sessions.get(&session).unwrap();
    assert_eq!(changes_under(&entry.board, &entry.token, &draft, at).len(), 1, "the burst landed once");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that the poisoned write path holds bursts `poisoned`, then `halted`.
///
/// The named door `fail_the_attest_stores_next_write` fails the attest
/// store's next line, which a board writes at every commit whose marker slot
/// is filled — a signed write of the publish class, and so never a burst's
/// on a draft — so the write-path halt is driven here by the kernel poison
/// instead, which sets `writes.halted` identically (every write then
/// `poisoned`, §The other endpoints). The poison door holds a burst
/// `poisoned` at the direct refusal, and once the feed's tick reads
/// `writes.halted` true, a further burst holds `halted` — the two causes
/// §3c.4 draws.
#[test]
fn the_poisoned_write_path_holds_bursts_poisoned_then_halted() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let HeldGround { shell, session, draft, at, .. } = held_ground(&dir, &sd);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalBarrier, std::io::ErrorKind::Other);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalRepair, std::io::ErrorKind::Other);
    // The poisoning burst is refused `poisoned` directly and held.
    let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"], "as_of": at}})).unwrap();
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("poisoned")), "{held}");
    assert_eq!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().len(), 1, "held(session) lists it");
    // Once the feed's probe reads `writes.halted` true, a further burst holds
    // `halted` (before any dial).
    let deadline = Instant::now() + Duration::from_secs(20);
    let halted = loop {
        let answer = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "3"}, "values": ["c"], "as_of": at}})).unwrap();
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

/// Returns the acting principal's held file under `store`, where one stands.
fn held_path(store: &Path) -> Option<PathBuf> {
    std::fs::read_dir(store.join("held")).ok()?.flatten().map(|e| e.path().join("principal-1.held")).find(|p| p.is_file())
}

/// Returns a delivery's text, its items joined.
///
/// Adjacent text comes as one item.
fn text_of(delivery: &Value) -> String {
    delivery["items"].as_array().unwrap().iter().map(|i| i["content"].as_str().unwrap_or("")).collect()
}

/// Checks that a poisoned burst lands at the restart and is kept (§3c.2).
///
/// The kernel poisoned as the cell above poisons it, a burst of two
/// characters is held `poisoned` — its line on disk `sent: true`, since the
/// failed repair keeps its frames in the journal — then the daemon restarted
/// at the same port, whose open replays them: the resend's read finds the
/// landed row, the site holds the burst's two values, the `held` event
/// reaches `kept` and never `moved`, the board holds the burst's row exactly
/// once, and the file compacts away (the mutant that leaves `poisoned` at
/// `sent: false`, and the one that holds the frame's one string to one
/// position's value, face the person's own text `moved`).
#[test]
fn a_poisoned_burst_lands_at_the_restart_and_is_kept() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let HeldGround { shell, seen, board, session, draft, at } = held_ground(&dir, &sd);
    let store = dir.path().join("store");
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalBarrier, std::io::ErrorKind::Other);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalRepair, std::io::ErrorKind::Other);
    let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["bc"], "as_of": at}})).unwrap();
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
    // The board holds the burst once: the draft reads `a`, `bc` and the rows
    // under it since genesis are the mint, the first insert and the burst.
    let read = shell.call("op", &json!({"session": session2, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 3)})).unwrap();
    assert_eq!(text_of(&read), "abc", "{read}");
    let token = shell.sessions.get(&session2).unwrap().token.clone();
    let rows = changes_under(&shell.boards[0].board, &token, &draft, 0);
    assert_eq!(rows.len(), 3, "the mint, the first insert, the burst once: {rows:?}");
    assert_eq!((rows[0]["op"].as_str(), rows[1]["op"].as_str()), (Some("create_new_document"), Some("insert")), "{rows:?}");
    // The daemon fact the read rests on: the write path records no row for a
    // write it refused `poisoned`, so the replayed commit's row carries lost
    // testimony — its hand and kind the reserved null — and the arrangement
    // alone could keep it.
    assert!(rows[2]["key"].is_null() && rows[2]["op"].is_null() && rows[2]["docs"].is_null(), "the replayed commit's testimony is lost: {:?}", rows[2]);
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a burst that committed, then panicked, is kept and sent once.
///
/// It is §3c.2's and §3c.5's case: the board's inline checkpoint armed to
/// panic at its first step and forced to run on the committing thread — the
/// checkpoint thread held, every commit crossing the cadence — so a burst's
/// write commits and its handler panics past the commit, the board
/// answering `500 internal_panic` and recording the position as a bare entry
/// (`operations.md` §4 row 34). The burst is answered `held`, cause
/// `unreachable`; the resend's read finds the bare row since the burst's
/// base, the site holds the burst's value, and the line is kept with nothing
/// sent again — the document's `held` events `holding` then `kept` alone,
/// the draft reading `abc`, the board holding the burst's row once (the
/// mutant that faces the 500 answers the page an error for text that is on
/// the board; the one that holds it `sent: false` faces the person's own
/// text `moved`).
#[test]
fn a_burst_that_committed_then_panicked_is_kept_and_sent_once() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let HeldGround { shell, seen, session, draft, at, .. } = held_ground(&dir, &sd);
    let insert = |ordinal: &str, value: &str, as_of: u64| json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": ordinal}, "values": [value], "as_of": as_of}});
    // The thread held and every commit crossing: the next commit sets the
    // flag and runs nothing, the one after runs the checkpoint inline.
    sd.daemon().hold_the_checkpoint_thread();
    sd.daemon().set_checkpoint_bytes_bound(1);
    let acked = shell.call("op", &insert("2", "b", at)).unwrap();
    let base = acked["at"].as_u64().unwrap_or_else(|| panic!("the burst before is acked: {acked}"));
    assert!(sd.daemon().checkpoint_is_due_now(), "the crossing's flag stands, so the next commit runs the checkpoint inline");
    sd.daemon().panic_at_the_next_kernel_step(Step::CheckpointCreate);
    let held = shell.call("op", &insert("3", "c", base)).unwrap();
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("unreachable")), "{held}");
    wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept");
    let states: Vec<String> = seen.lock().unwrap().iter().filter(|e| e.name == EventName::Held && e.data["doc"] == draft).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect();
    assert_eq!(states, ["holding", "kept"], "kept off the read, never sent again, never faced moved");
    assert!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().is_empty(), "the line is done kept");
    let read = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 3)})).unwrap();
    assert_eq!(text_of(&read), "abc", "{read}");
    let token = shell.sessions.get(&session).unwrap().token.clone();
    let rows = changes_under(&shell.boards[0].board, &token, &draft, base);
    assert_eq!(rows.len(), 1, "the burst's row once, nothing sent again: {rows:?}");
    // The daemon fact the read rests on: the write path's catch records a
    // write that panicked past its commit bare, its testimony lost.
    assert!(rows[0]["key"].is_null() && rows[0]["op"].is_null() && rows[0]["docs"].is_null(), "the panicked commit's testimony is lost: {:?}", rows[0]);
    sd.daemon().release_the_checkpoint_thread();
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a signed session's landed burst is kept by the resend.
///
/// It is the signed mode's own row: a held burst whose line says
/// `sent: true` has landed by the signed session's own hand, and the
/// resend's read after the daemon's restart — under the session the restart
/// arm re-opened — recognises it: the `held` event reaches `kept`, never
/// `moved`, nothing is re-sent, and the board holds the row once. The row's
/// shape is pinned as the daemon serves it: the shell attests every insert,
/// but the daemon drops an attest on a write outside the publish class
/// (wire.md §The two attestation codes), and a burst lands on a draft, so
/// its row is an unsigned entry whose `key` is the session key's fingerprint
/// — no burst row is a signed entry on a conforming daemon; the own-row
/// test's signed arm (`attest`, no `key`) is fenced by `hold`'s suite over a
/// fake board. The in-flight landing is forced by hand: the attested burst
/// of two characters written through the board under the session's token,
/// so the shell saw no ack, then held `sent: true` as a lost answer is.
#[test]
fn a_signed_sessions_landed_burst_is_kept_by_the_resend() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (signed, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answerer = answer_moments(signed.subscribe(), Arc::clone(&signed.pending), Arc::clone(&seen));
    let board = signed.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = signed.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let minted = signed.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    let draft = minted["addr"].as_str().unwrap().to_string();
    let first = signed.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["a"], "as_of": minted["at"]}})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    let base = first["at"].as_u64().expect("the ack's position");
    // The in-flight burst: attested as the shell attests it, written under
    // the session's token through the board itself.
    let entry = signed.sessions.get(&session).unwrap();
    let SessionKind::Signed { fingerprint: fp, .. } = entry.facts.kind.clone() else { panic!("a signed session holds a key") };
    let frame = json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["bc"], "as_of": base});
    let attested = entry.attest(&signed.store, &frame).unwrap();
    assert!(attested.get("attest").is_some(), "the shell attests every insert");
    let Answer::Document(landed) = entry.board.op(Some(&entry.token), &attested).unwrap() else { panic!("the dial closed") };
    assert!(landed["resp"].as_str().is_some_and(|r| r.starts_with("ack")), "the burst landed by the own hand: {landed}");
    let rows = changes_under(&entry.board, &entry.token, &draft, base);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["key"].as_str(), Some(fp.to_hex().as_str()), "a draft's insert is outside the publish class: the attest dropped, the row unsigned under the key's fingerprint: {rows:?}");
    assert!(rows[0].get("attest").is_none(), "{rows:?}");
    // Held as a lost answer is: the line `sent: true`, at the base the shell
    // knew before the dial — the first insert's ack.
    let held = signed.holds.hold(&entry, Burst::admit(frame.clone(), &entry).unwrap(), Reason::of("unreachable", true), Some("unreachable".into()), base).answered().unwrap();
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
    let rows = changes_under(&entry.board, &token, &draft, base);
    assert_eq!(rows.len(), 1, "the burst's row once, nothing re-sent: {rows:?}");
    let read = signed.call("op", &json!({"session": reopened, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 3)})).unwrap();
    assert_eq!(text_of(&read), "abc", "{read}");
    signed.shutdown();
    drop(signed);
    answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that a refused run holds behind it and `resolve` acts on it.
///
/// A refused run — `out_of_bounds` (a `permanent` refusal) on a burst, two
/// bursts behind it on the same document held `behind`, the `held` event
/// `refused`; a `resolve` on a holding line is `not_resolvable`, an unknown
/// ordinal `no_such_held`; an act the row does not spell is refused
/// `malformed_args` naming `act` — the argument checked before the line, at
/// an ordinal of the run and at one of no line alike, the run standing whole
/// (the mutant that reads the act after the line answers the line's
/// refusal); `resolve(drop)` drops the run and its two behind lines;
/// `resolve(send)` re-faces the run where the refusal recurs.
#[test]
fn a_refused_run_holds_behind_it_and_resolve_acts_on_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let HeldGround { shell, seen, session, draft, at, .. } = held_ground(&dir, &sd);
    // A burst past the draft's head: `out_of_bounds`, a permanent refusal → a
    // refused run (an insert at a far ordinal the draft has no room for).
    let far = json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "900000"}, "values": ["r"], "as_of": at}});
    let refused = shell.call("op", &far).unwrap();
    assert_eq!(refused["resp"], "held", "a permanent refusal is a refused run: {refused}");
    let k = refused["held"].as_u64().unwrap();
    assert!(refused["cause"].as_str().unwrap().starts_with("out_of_bounds"), "{refused}");
    wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "refused");
    // Two more bursts on the document while the run stands → held `behind`.
    for v in ["s", "t"] {
        let behind = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "900001"}, "values": [v], "as_of": at}})).unwrap();
        assert_eq!(behind["cause"], "behind", "{behind}");
    }
    assert_eq!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().len(), 3);
    // A `resolve` on a holding line, and an unknown ordinal.
    let behind_k = shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().iter().find(|r| r["cause"] == "behind").unwrap()["held"].as_u64().unwrap();
    assert_eq!(shell.call("resolve", &json!({"session": session, "held": behind_k, "act": "drop"})).unwrap_err().name(), "not_resolvable");
    assert_eq!(shell.call("resolve", &json!({"session": session, "held": 9999, "act": "drop"})).unwrap_err().name(), "no_such_held");
    // An act the row does not spell is the argument it is, refused before
    // any line is asked; the run stands whole.
    for held in [k, 9999] {
        let refused = shell.call("resolve", &json!({"session": session, "held": held, "act": "dropp"})).unwrap_err().to_value();
        assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some("act")), "held {held}: {refused}");
    }
    assert_eq!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().len(), 3, "an act of no name drops nothing");
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

/// Checks the close order: the held line persists and the relaunch lists it.
///
/// A held burst's line is on disk and listed by `held(session)` before
/// `shutdown`, which writes nothing of the store; the next `Shell::open`
/// over the same store, in the bare mode — a session that reads alone, its
/// held lines among what it reads — lists the line at its first session's
/// open.
#[test]
fn the_close_persists_the_held_line_and_the_relaunch_lists_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    let draft;
    {
        let HeldGround { shell, session, draft: d, at, .. } = held_ground(&dir, &sd);
        draft = d;
        // Stop the node under the shell's feet, then a burst holds
        // `unreachable`.
        sd.shutdown();
        let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"], "as_of": at}})).unwrap();
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
    let (shell, _lines) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
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

/// Returns a directory's shape: the file names and sizes under it, sorted.
///
/// A test pins by it that nothing changed.
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

/// Checks that a second principal's file is untouched and unlisted.
///
/// It is untouched and unlisted under the first's session — the first's own
/// acts, a burst held behind its line and a `resolve` among them, leave its
/// bytes as they were — and no answer and no event names a path, a
/// directory or the other principal (the mutant that opens the first
/// principal's acts on the second's file writes the person's text into
/// another principal's store). The second principal's file holds the line
/// an earlier session of its own held, read under a bare session of its
/// now, which resends none of it.
#[test]
fn a_second_principals_file_is_untouched_and_unlisted() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    // Principal 2's file, held before this shell opened: one line.
    let term = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new()).board_term().unwrap().expect("H.1 stands on a claimed board");
    let held_dir = HeldDir::new(&store, skep_search::Chain::from_bytes(term.chain));
    held_dir.ensure().unwrap();
    let Opened::Live { mut queue, .. } = held_dir.open_file(2, "1.0.2").unwrap() else { panic!("a fresh file") };
    let two = json!({"op": "insert", "doc": "1.0.2.0.1", "at": {"subspace": "1", "ordinal": "1"}, "values": ["two"], "as_of": 0});
    assert!(queue.hold_next("1.0.2.0.1", None, 0, two, None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    drop(queue);
    // One shell (so one lock on `held/<chain>/`) holding a session for each of
    // two principals: principal 1's signed, owning the draft; principal 2's
    // bare, opened beside it.
    let (shell, _lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let s1 = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let second = shell.sessions.register(&shell.boards[0], open_bare(&shell.boards[0].board, 2).unwrap(), &mut shell.feed(&board));
    shell.holds.open_session(&second);
    let s2 = second.reference.clone();
    let minted = shell.call("op", &json!({"session": s1, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    let d1 = minted["addr"].as_str().unwrap().to_string();
    let typed = minted["at"].as_u64().unwrap();
    // The board goes down: principal 1's next burst is held `unreachable` in
    // its own file, `principal-1.held`, beside `principal-2.held`.
    sd.shutdown();
    let h1 = shell.call("op", &json!({"session": s1, "frame": {"op": "insert", "doc": d1, "at": {"subspace": "1", "ordinal": "2"}, "values": ["one"], "as_of": typed}})).unwrap();
    assert_eq!(h1["resp"], "held");
    assert!(store.join("held").exists(), "the directory stands");
    let p2 = std::fs::read_dir(store.join("held")).unwrap().flatten().map(|e| e.path().join("principal-2.held")).find(|p| p.is_file()).expect("principal 2's file stands");
    let p2_bytes = std::fs::read(&p2).unwrap();
    let rx = shell.subscribe();
    // Principal 1's `held(session)` lists principal 1's line alone; no answer
    // names a path, a directory or principal 2 (the token-/path-shaped run).
    let rows1 = shell.call("held", &json!({"session": s1})).unwrap();
    assert_eq!(rows1.as_array().unwrap().len(), 1, "principal 1's lines alone: {rows1}");
    let rows2 = shell.call("held", &json!({"session": s2})).unwrap();
    assert_eq!(rows2.as_array().unwrap().len(), 1, "principal 2's own line, read under principal 2 alone");
    let text = format!("{rows1}{h1}");
    assert!(!text.contains("principal-2") && !text.contains("principal-1") && !text.contains("/held/") && !text.contains(&store.display().to_string()), "no path, directory or principal file name crosses: {text}");
    // Principal 1's own acts touch principal 1's file alone.
    let behind = shell.call("op", &json!({"session": s1, "frame": {"op": "insert", "doc": d1, "at": {"subspace": "1", "ordinal": "4"}, "values": ["three"], "as_of": typed}})).unwrap();
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert_eq!(shell.call("resolve", &json!({"session": s1, "held": 1, "act": "drop"})).unwrap_err().name(), "not_resolvable");
    assert_eq!(std::fs::read(&p2).unwrap(), p2_bytes, "principal 2's file is untouched by principal 1's acts");
    let said: Vec<String> = rx.try_iter().map(|e| e.data.to_string()).collect();
    assert!(said.iter().all(|data| !data.contains("principal-2") && !data.contains(&store.display().to_string())), "no event names the other principal's file: {said:?}");
    shell.shutdown();
}

/// Checks that a halted file's path never crosses and the page asks to show it.
///
/// It is §3c.3's halt under §4b.3's rule. Principal 1's held file, written
/// by a newer skep before the shell opened, halts the principal at the
/// board: `held(session)`, a burst's `op` and `resolve` each answer
/// `store_halted` carrying its `why` alone (the mutant that puts the path
/// back on the detail hands the page the data directory). `held.show` shows
/// the file in the shell's own window, once each time it is asked, and
/// answers `{shown: true}` and nothing more; the native side reads the same
/// file by `Shell::halted_file`, `unknown_board` for a reference this shell
/// never issued and nothing for a principal whose file is not halted; a
/// principal whose file stands is shown nothing and answered `{shown:
/// false}`; and a `held.show` naming no session is refused naming it. No
/// answer, refusal or event names the store, the held directory or the
/// file.
#[test]
fn a_halted_files_path_crosses_the_bridge_never_and_the_page_asks_to_show_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let term = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new()).board_term().unwrap().expect("H.1 stands on a claimed board");
    let chain = skep_search::Chain::from_bytes(term.chain);
    HeldDir::new(&store, chain).ensure().unwrap();
    let file = store.join("held").join(chain.to_string()).join("principal-1.held");
    std::fs::write(&file, format!("{{\"type\":\"skep-held-bursts\",\"v\":2,\"board\":\"{chain}\",\"principal\":1,\"account\":\"1.0.1\"}}\n")).unwrap();
    let (shell, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let rx = shell.subscribe();
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let burst = json!({"op": "insert", "doc": "1.0.1.0.1", "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"], "as_of": 0});
    let refusals = [
        shell.call("held", &json!({"session": session})).unwrap_err().to_value(),
        shell.call("op", &json!({"session": session, "frame": burst})).unwrap_err().to_value(),
        shell.call("resolve", &json!({"session": session, "held": 1, "act": "drop"})).unwrap_err().to_value(),
    ];
    for refused in &refusals {
        assert_eq!(*refused, json!({"kind": "shell", "name": "store_halted", "why": "newer"}), "the why alone");
    }
    let showing = format!("principal 1's held file {} is halted (written by a newer skep)", file.display());
    let shown = || lines.lock().unwrap().iter().filter(|line| line.contains(&showing)).count();
    assert_eq!(shown(), 0, "nothing shows the file before the page asks: {:?}", lines.lock().unwrap());
    let answers = [shell.call("held.show", &json!({"session": session})).unwrap(), shell.call("held.show", &json!({"session": session})).unwrap()];
    assert_eq!(answers, [json!({"shown": true}), json!({"shown": true})], "shown, and nothing more crosses");
    assert_eq!(shown(), 2, "shown in the shell's own window each time it is asked: {:?}", lines.lock().unwrap());
    assert_eq!(shell.halted_file(&board, 1).unwrap(), Some(file.clone()), "the native side reads the halted file");
    assert_eq!(shell.halted_file("b-nowhere", 1).unwrap_err().name(), "unknown_board");
    // Principal 2, its file unhalted: nothing to show.
    let second = shell.sessions.register(&shell.boards[0], open_bare(&shell.boards[0].board, 2).unwrap(), &mut shell.feed(&board));
    shell.holds.open_session(&second);
    let said_before = lines.lock().unwrap().len();
    assert_eq!(shell.call("held.show", &json!({"session": second.reference})).unwrap(), json!({"shown": false}));
    assert!(lines.lock().unwrap()[said_before..].iter().all(|line| !line.contains("is halted")), "nothing is shown: {:?}", lines.lock().unwrap());
    assert_eq!(shell.halted_file(&board, 2).unwrap(), None, "no halted file of principal 2's stands");
    assert_eq!(shell.call("held.show", &json!({})).unwrap_err().to_value()["what"], "session", "a call naming no session is refused naming it");
    let crossed: Vec<String> = refusals.iter().chain(&answers).map(Value::to_string).chain(rx.try_iter().map(|e| e.data.to_string())).collect();
    let store_dir = store.display().to_string();
    assert!(crossed.iter().all(|text| !text.contains(&store_dir) && !text.contains("/held/") && !text.contains("principal-1.held")), "no path crosses: {crossed:?}");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a burst on a draft just minted is kept after a restart.
///
/// It is §3c.2's `base`: the mint's ack is noted as every write's is, so a
/// burst held on the draft before any burst of it was acked reads from the
/// mint's position — the daemon stopped under it, restarted at the same
/// port, a fresh signed session re-acquired: the burst is resent and kept,
/// never faced `moved` (the mutant that notes a burst's acks alone reads the
/// mint's own row and faces the person's text).
#[test]
fn a_burst_held_on_a_draft_just_minted_is_kept_after_a_restart() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let minted = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    let draft = minted["addr"].as_str().unwrap().to_string();
    sd.shutdown();
    let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hi"], "as_of": minted["at"]}})).unwrap();
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

/// Checks that a relaunch with its board down lists and resends its line.
///
/// It is §3c.7's: the held file is read at a session's open, never only at
/// the shell's — a shell opened while its board's port is closed, the daemon
/// started there before the first `session`: `held(session)` lists the line
/// the store already holds (the mutant that reads the store at the shell's
/// open alone lists nothing and resends nothing). A bare relaunch, the
/// keyless session that reads alone, lists it and resends none of it —
/// three probe cadences on, the line stands and the board holds no row of it
/// (the mutant whose drain resends under any session commits the person's
/// text under the bare hand); a signed relaunch resends it `kept`. And a
/// file written after a relaunch whose board was up names the session's
/// account in its header, never an empty one.
#[test]
fn a_relaunch_with_its_board_down_lists_and_resends_the_held_line() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    let draft;
    {
        let HeldGround { shell, session, draft: d, at, .. } = held_ground(&dir, &sd);
        draft = d;
        sd.shutdown();
        let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"], "as_of": at}})).unwrap();
        assert_eq!(held["cause"], "unreachable", "{held}");
        shell.shutdown();
    }
    // The relaunch: the shell opened over the store while its board is down,
    // in the bare mode.
    let (relaunched, lines) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(relaunched.subscribe(), Arc::clone(&relaunched.pending), Arc::clone(&seen));
    let sd = spawn_at(&dir.path().join("board"), true, port);
    let board = relaunched.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = relaunched.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let rows = relaunched.call("held", &json!({"session": session})).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1, "the session's open lists the held line: {rows}\n{}", lines.lock().unwrap().join("\n"));
    assert_eq!(rows[0]["doc"], draft);
    thread::sleep(PROBE_CADENCE * 3);
    assert_eq!(relaunched.call("held", &json!({"session": session})).unwrap().as_array().unwrap().len(), 1, "the bare session resends none of it");
    assert!(!seen.lock().unwrap().iter().any(|e| e.name == EventName::Held && e.data["state"] == "kept"), "nothing is kept under the bare session");
    let token = relaunched.sessions.get(&session).unwrap().token.clone();
    let rows = changes_under(&relaunched.boards[0].board, &token, &draft, 0);
    assert_eq!(rows.len(), 2, "the mint and the first insert, and no row of the held burst: {rows:?}");
    relaunched.shutdown();
    drop(relaunched);
    // A signed relaunch with the board up resends it; then, the board down, a
    // burst held: its file's header names the session's account.
    let (again, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(again.subscribe(), Arc::clone(&again.pending), Arc::clone(&seen));
    let board = again.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = again.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept");
    let read = again.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 2)})).unwrap();
    assert_eq!(text_of(&read), "ab", "the resent burst is on the board: {read}\n{}", lines.lock().unwrap().join("\n"));
    sd.shutdown();
    let held = again.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "3"}, "values": ["c"], "as_of": read["as_of"]}})).unwrap();
    assert_eq!(held["resp"], "held", "{held}");
    let file = std::fs::read_to_string(held_path(&store).expect("the held file stands")).unwrap();
    let header = file.lines().next().unwrap();
    assert!(header.contains("\"account\":\"1.0.1\""), "the header names the session's account: {header}");
    again.shutdown();
}

/// Checks that the probe keeps its cadence while the board keeps committing.
///
/// It is §3c.4's: a line held `unreachable`, `sent: true` — a lost answer's
/// — at a board that answers, while a second session mints a draft every
/// 500 ms and each commit wakes the board's feed, is resent and kept within
/// three cadences (the mutant that counts the cadence from the feed's last
/// wake never probes while the commits come).
#[test]
fn the_probe_keeps_its_cadence_while_the_board_keeps_committing() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let HeldGround { shell, seen, board, session, draft, at } = held_ground(&dir, &sd);
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
        let frame = json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"], "as_of": at});
        shell.holds.hold(&entry, Burst::admit(frame, &entry).unwrap(), Reason::of("unreachable", true), Some("unreachable".into()), at).answered().unwrap();
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

/// Checks that a burst typed against an older state is held moved, and
/// nothing of it lands (skep #442).
///
/// The board's `arrangement_moved` — a `permanent` refusal — holds the burst
/// as a MOVED document, never a refused run whose resend meets the same
/// refusal. Another write lands on the draft after the ground's insert; a
/// burst typed against the ground's state, sent without anchors as an
/// agent's is, is refused, answered `held` with
/// cause `moved`, its line listed with the board's verdict naming the typed
/// state and the current one, and the `held` event says `moved`, naming the
/// hand of the write that moved the draft — this store's own; nothing of it
/// lands — the draft reads what the other write left, and no row stands
/// above that write. The same text typed against the current state lands
/// once the moved line is discarded (the mutant that lands the stale burst
/// writes the text a position off; the one that holds it a refused run
/// faces an act that can never succeed; the one that names no hand draws
/// the moved face with none).
#[test]
fn a_burst_typed_against_an_older_state_is_held_moved_and_nothing_lands() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let HeldGround { shell, seen, session, draft, at, .. } = held_ground(&dir, &sd);
    // Another write on the draft: the ground's state `at` is older now.
    let moved = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"], "as_of": at}})).unwrap();
    let current = moved["at"].as_u64().unwrap_or_else(|| panic!("the second insert is acked: {moved}"));
    assert!(current > at);
    // The stale burst: typed against `at`, refused `arrangement_moved` — held
    // as a moved document, the line listing the board's verdict.
    let stale = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["x"], "as_of": at}})).unwrap();
    assert_eq!((stale["resp"].as_str(), stale["cause"].as_str()), (Some("held"), Some("moved")), "a burst typed against an older state is held moved: {stale}");
    let k = stale["held"].as_u64().unwrap();
    let faced = wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "moved");
    let SessionKind::Signed { fingerprint, .. } = shell.sessions.get(&session).unwrap().facts.kind.clone() else { panic!("a signed session holds a key") };
    assert_eq!(faced.data["hands"], json!([{"key": "own", "fingerprint": fingerprint.to_hex()}]), "the hand of the second insert, this store's own: {}", faced.data);
    assert!(!seen.lock().unwrap().iter().any(|e| e.name == EventName::Held && e.data["state"] == "refused"), "never a refused run");
    let rows = shell.call("held", &json!({"session": session})).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1, "{rows}");
    assert_eq!(rows[0]["cause"], "moved", "{rows}");
    let verdict = &rows[0]["refusal"];
    assert_eq!(verdict["code"], "arrangement_moved", "the board's verdict rides the line: {rows}");
    assert_eq!(verdict["disposition"], "permanent", "{rows}");
    assert_eq!((verdict["site"]["as_of"].as_u64(), verdict["site"]["current"].as_u64()), (Some(at), Some(current)), "the two positions: {rows}");
    // Nothing landed: the draft reads `ab`, and no row stands above the
    // other write.
    let read = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 3)})).unwrap();
    assert_eq!(text_of(&read), "ab", "{read}");
    let token = shell.sessions.get(&session).unwrap().token.clone();
    assert!(changes_under(&shell.boards[0].board, &token, &draft, current).is_empty(), "a refusal commits nothing");
    // Discarded, then typed against the current state, the text lands.
    shell.call("resolve", &json!({"session": session, "held": k, "act": "drop"})).unwrap();
    let landed = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["x"], "as_of": current}})).unwrap();
    assert_eq!(landed["resp"], "ack_addr", "{landed}");
    let read = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 3)})).unwrap();
    assert_eq!(text_of(&read), "axb", "{read}");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a stale burst carrying its anchors is shifted through another
/// writer's change and lands once, at the displaced place (skep #442).
///
/// The draft reads `a`; another write puts `b` before it — the ground's
/// state is older now, and `a` stands one position later. A burst typed
/// against the ground's state to put `x` after `a`, carrying `a`'s identity
/// as its `before` anchor and no `after` (the draft ended at `a`), is refused
/// `arrangement_moved` at its first dial and shifted within the call: one
/// image read, `a` found one position later with nothing after it, the
/// insert moved by one and typed at the read's state, sent again and acked
/// — the page's one answer the ack, its position above the other write's,
/// the draft reading `bax`, one row above the other write, no line held, the
/// held file gone and no `held` event said (the mutant that holds the burst
/// moved asks the person to place text the shell could place; the one that
/// sends the stale frame again meets the same refusal; the one that moves
/// by nothing lands `x` before `a`).
#[test]
fn a_stale_burst_carrying_its_anchors_is_shifted_through_another_writers_change_and_lands_once() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let HeldGround { shell, seen, session, draft, at, .. } = held_ground(&dir, &sd);
    let image = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::image(&draft, 1, 1)})).unwrap();
    let a = image["runs"][0]["i_start"].as_str().unwrap_or_else(|| panic!("the identity of `a`: {image}")).to_string();
    let moved = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["b"], "as_of": at}})).unwrap();
    let current = moved["at"].as_u64().unwrap_or_else(|| panic!("the other write is acked: {moved}"));
    let stale = json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["x"], "as_of": at});
    let landed = shell.call("op", &json!({"session": session, "frame": stale, "anchors": {"before": a, "after": null}})).unwrap();
    assert_eq!(landed["resp"], "ack_addr", "the shifted burst is acked within the call: {landed}");
    assert!(landed["at"].as_u64().is_some_and(|l| l > current), "{landed}");
    let read = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 3)})).unwrap();
    assert_eq!(text_of(&read), "bax", "the text lands after `a`, one position later than typed: {read}");
    let token = shell.sessions.get(&session).unwrap().token.clone();
    assert_eq!(changes_under(&shell.boards[0].board, &token, &draft, current).len(), 1, "the shifted burst's row once");
    assert!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().is_empty(), "no line stands");
    assert!(!seen.lock().unwrap().iter().any(|e| e.name == EventName::Held), "no held event for a line entered, shifted and settled within one call");
    assert!(held_path(&dir.path().join("store")).is_none(), "the held file is gone");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a stale delete or rearrange is shifted by its span's units.
///
/// It lands once, and one whose span another writer refilled is held moved
/// (skep #751). Each draft reads `abcd`, its anchors and its span read off the
/// board's own `image` as a page reads them: `a` and `d`, and the run of `b`
/// and `c`. Another write puts `X` before the text; a delete of `b` and `c`
/// typed against the older state is refused `arrangement_moved` at its first
/// dial, shifted within the call — the run of `b` and `c` standing between `a`
/// and `d` in the shell's one read of the whole image — and lands once, the
/// draft reading `Xad`; a rearrange swapping them lands once, the draft reading
/// `Xacbd`. Another write then takes `b` and `c` out of a third draft and puts
/// `XY` in their place, as many units: the stale delete is held moved, nothing
/// of it lands, and the draft reads `aXYd` (the mutant that judges the span by
/// its count alone deletes `XY`, the other writer's words; the one that holds a
/// delete with its span moved asks the person to place what the shell could
/// place).
#[test]
fn a_stale_delete_or_rearrange_is_shifted_by_its_spans_own_units_and_lands_once() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let HeldGround { shell, session, .. } = held_ground(&dir, &sd);
    let op = |frame: Value, anchors: Option<&Value>| {
        let mut args = json!({"session": session, "frame": frame});
        if let Some(anchors) = anchors {
            args["anchors"] = anchors.clone();
        }
        shell.call("op", &args).unwrap()
    };
    let at = |answer: &Value| answer["at"].as_u64().unwrap_or_else(|| panic!("acked: {answer}"));
    let text = |draft: &str| text_of(&op(skep_client::board::frames::retrieve_v(draft, 1, 6), None));
    // A draft reading `abcd`, the state it was written at, and the anchors a
    // page sends for `b` and `c`, read off the board's own image.
    let abcd = || -> (String, u64, Value) {
        let minted = op(json!({"op": "create_new_document", "account": "1.0.1"}), None);
        let draft = minted["addr"].as_str().unwrap().to_string();
        let written = at(&op(json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["abcd"], "as_of": minted["at"]}), None));
        let image = |from: u64, width: u64| op(skep_client::board::frames::image(&draft, from, width), None)["runs"].clone();
        let unit = |v: u64| image(v, 1)[0]["i_start"].as_str().unwrap_or_else(|| panic!("the identity of position {v}")).to_string();
        let span: Vec<Value> = image(2, 2).as_array().unwrap().iter().map(|run| json!({"start": run["i_start"], "width": run["width"]})).collect();
        let anchors = json!({"before": unit(1), "after": unit(4), "span": span});
        (draft, written, anchors)
    };
    let position = |n: u64| json!({"subspace": "1", "ordinal": n.to_string()});
    let delete = |draft: &str, typed: u64| json!({"op": "delete", "doc": draft, "p": position(2), "width": "2", "as_of": typed});
    let rearrange = |draft: &str, typed: u64| json!({"op": "rearrange", "doc": draft, "cuts": [position(2), position(3), position(4)], "as_of": typed});
    for (burst, landed) in [(&delete as &dyn Fn(&str, u64) -> Value, "Xad"), (&rearrange, "Xacbd")] {
        let (draft, typed, anchors) = abcd();
        let moved = at(&op(json!({"op": "insert", "doc": draft, "at": position(1), "values": ["X"], "as_of": typed}), None));
        let shifted = op(burst(&draft, typed), Some(&anchors));
        assert!(at(&shifted) > moved, "the shifted burst is acked within the call, above the other write: {shifted}");
        assert_eq!(text(&draft), landed, "the burst lands once, one position later than typed");
    }
    assert!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().is_empty(), "no line stands");
    // The span refilled: `b` and `c` out, `XY` in their place, as many units.
    let (draft, typed, anchors) = abcd();
    let emptied = at(&op(json!({"op": "delete", "doc": draft, "p": position(2), "width": "2", "as_of": typed}), None));
    let refilled = at(&op(json!({"op": "insert", "doc": draft, "at": position(2), "values": ["XY"], "as_of": emptied}), None));
    let held = op(delete(&draft, typed), Some(&anchors));
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("moved")), "a delete whose span another writer refilled is held moved: {held}");
    assert_eq!(text(&draft), "aXYd", "nothing of it lands: the other writer's words stand");
    let token = shell.sessions.get(&session).unwrap().token.clone();
    assert!(changes_under(&shell.boards[0].board, &token, &draft, refilled).is_empty(), "a refusal commits nothing");
    let rows = shell.call("held", &json!({"session": session})).unwrap();
    assert_eq!((rows.as_array().unwrap().len(), rows[0]["cause"].as_str(), &rows[0]["anchors"]), (1, Some("moved"), &anchors), "{rows}");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that the shift reads a run placed twice at each place (skep #753).
///
/// A second draft reads `z`, the unit another writer copies — one `copy`,
/// its specs naming that unit twice — so the document arranges one
/// I-address at two places and the board's image answers both. Two arms. A
/// draft reads `abcd`; an insert of `x` before `d`, carrying `c` and `d` as
/// its anchors, is typed against that state; the other writer copies `z`
/// twice at the front, `zzabcd`; the stale insert is shifted within the call
/// by both units and lands once, the draft reading `zzabcxd` (the mutant
/// that images the doubled run once finds `c` a position early and lands
/// `zzabxcd`). A draft reads `zabcd`, its one `z` copied in before the
/// anchors are read — `a` and `d`, with the run of `b` and `c`; the other
/// writer copies `z` again between `b` and `c`, `zabzcd`; a delete of `b`
/// and `c` typed against the older state is held moved and nothing of it
/// lands (the mutant that images the doubled run once counts the span
/// whole, `b` and `c` again, and deletes `b` and the other writer's `z`).
#[test]
fn a_stale_burst_is_shifted_through_a_run_the_document_places_twice() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let HeldGround { shell, session, .. } = held_ground(&dir, &sd);
    let op = |frame: Value, anchors: Option<&Value>| {
        let mut args = json!({"session": session, "frame": frame});
        if let Some(anchors) = anchors {
            args["anchors"] = anchors.clone();
        }
        shell.call("op", &args).unwrap()
    };
    let at = |answer: &Value| answer["at"].as_u64().unwrap_or_else(|| panic!("acked: {answer}"));
    let text = |draft: &str| text_of(&op(skep_client::board::frames::retrieve_v(draft, 1, 8), None));
    let position = |n: u64| json!({"subspace": "1", "ordinal": n.to_string()});
    // A draft reading `text`, and the state it was written at.
    let draft = |text: &str| -> (String, u64) {
        let minted = op(json!({"op": "create_new_document", "account": "1.0.1"}), None);
        let draft = minted["addr"].as_str().unwrap().to_string();
        let written = at(&op(json!({"op": "insert", "doc": draft, "at": position(1), "values": [text], "as_of": minted["at"]}), None));
        (draft, written)
    };
    // The anchors a page sends, read off the board's own image: the unit at
    // position `v` of `draft`, and the span of `width` units from `from`.
    let image = |draft: &str, from: u64, width: u64| op(skep_client::board::frames::image(draft, from, width), None)["runs"].clone();
    let unit = |draft: &str, v: u64| image(draft, v, 1)[0]["i_start"].as_str().unwrap_or_else(|| panic!("the identity of position {v}")).to_string();
    let span = |draft: &str, from: u64, width: u64| -> Vec<Value> { image(draft, from, width).as_array().unwrap().iter().map(|run| json!({"start": run["i_start"], "width": run["width"]})).collect() };
    // The other writer's copy of `z` into `draft` at `v`, `times` over in one
    // frame, typed against `as_of`: the position it is acked at.
    let (z, _) = draft("z");
    let copy_z = |draft: &str, v: u64, times: usize, as_of: u64| {
        let spec = json!({"source": z, "span": {"start": "1.1", "width": "0.1"}});
        at(&op(json!({"op": "copy", "doc": draft, "at": position(v), "specs": vec![spec; times], "as_of": as_of}), None))
    };

    // The insert: `c` and `d` found past both copies, the burst landing
    // between them.
    let (abcd, typed) = draft("abcd");
    let anchors = json!({"before": unit(&abcd, 3), "after": unit(&abcd, 4)});
    let moved = copy_z(&abcd, 1, 2, typed);
    assert_eq!(text(&abcd), "zzabcd");
    let shifted = op(json!({"op": "insert", "doc": abcd, "at": position(4), "values": ["x"], "as_of": typed}), Some(&anchors));
    assert!(at(&shifted) > moved, "the shifted burst is acked within the call, above the other write: {shifted}");
    assert_eq!(text(&abcd), "zzabcxd", "the burst lands once, two positions later than typed");
    assert!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().is_empty(), "no line stands");

    // The delete: the span between `a` and `d` holds one unit more than it
    // held, the other writer's `z`.
    let (zabcd, written) = draft("abcd");
    let typed = copy_z(&zabcd, 1, 1, written);
    assert_eq!(text(&zabcd), "zabcd");
    let anchors = json!({"before": unit(&zabcd, 2), "after": unit(&zabcd, 5), "span": span(&zabcd, 3, 2)});
    copy_z(&zabcd, 4, 1, typed);
    assert_eq!(text(&zabcd), "zabzcd");
    let held = op(json!({"op": "delete", "doc": zabcd, "p": position(3), "width": "2", "as_of": typed}), Some(&anchors));
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("moved")), "a delete whose span the other writer's copy cut is held moved: {held}");
    assert_eq!(text(&zabcd), "zabzcd", "nothing of it lands: the other writer's unit stands");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that the person's `send` on a moved document acknowledges the
/// changes that moved it (§3c.4; skep #757).
///
/// The person's own other write — dialed under the session's token past the
/// shell's hold, as the `skep` command dials — moves the draft after the
/// ground's insert, and a burst typed against the ground's state, sent
/// without anchors as an agent's is, is held moved, its face naming the own
/// hand. The person's `send` raises the line's base to the position the
/// board's verdict read through, that write's own, in the held file too; the
/// next probe resends the line, the board refuses it again, and it is held
/// moved again naming no hand — the change the person acknowledged named no
/// more. A further change by another hand, a bare session's under local
/// trust, and the person's `send` again: held moved once more, naming that
/// hand alone; nothing of the burst lands (the mutant that reads the hands
/// since the typed state at every face names the acknowledged change at each
/// of them, and the person meets the face they sent past again; the one that
/// leaves the base reads the acknowledged rows at every resend).
#[test]
fn the_persons_send_on_a_moved_document_names_only_the_changes_since_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let HeldGround { shell, seen, session, draft, at, .. } = held_ground(&dir, &sd);
    let entry = shell.sessions.get(&session).unwrap();
    let SessionKind::Signed { fingerprint, .. } = entry.facts.kind.clone() else { panic!("a signed session holds a key") };
    let insert = |ordinal: u64, value: &str, as_of: u64| json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": ordinal.to_string()}, "values": [value], "as_of": as_of});
    // The document's faces `moved`, waited for until there are `n`.
    let faces = |n: usize| -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let faces: Vec<Value> = seen.lock().unwrap().iter().filter(|e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "moved").map(|e| e.data.clone()).collect();
            if faces.len() >= n {
                return faces;
            }
            assert!(Instant::now() < deadline, "the document was faced moved {} times, not {n}", faces.len());
            thread::sleep(Duration::from_millis(20));
        }
    };
    // The person's own other write, past the shell's hold: the draft moves.
    let other_write = insert(2, "b", at);
    let attested = entry.attest(&shell.store, &other_write).unwrap();
    let Answer::Document(own) = entry.board.op(Some(&entry.token), &attested).unwrap() else { panic!("the dial closed") };
    let moved_at = own["at"].as_u64().unwrap_or_else(|| panic!("the own write is acked: {own}"));
    // The stale burst, without anchors: held moved, its face naming the own
    // hand, the line at the ground's ack.
    let stale = shell.call("op", &json!({"session": session, "frame": insert(2, "x", at)})).unwrap();
    assert_eq!((stale["resp"].as_str(), stale["cause"].as_str()), (Some("held"), Some("moved")), "{stale}");
    let k = stale["held"].as_u64().unwrap();
    assert_eq!(faces(1)[0]["hands"], json!([{"key": "own", "fingerprint": fingerprint.to_hex()}]), "the first face names the write that moved the draft");
    assert_eq!(shell.call("held", &json!({"session": session})).unwrap()[0]["base"].as_u64(), Some(at));
    // The person's send: the base raised through the own write, the resend
    // refused again and held moved, naming no hand.
    shell.call("resolve", &json!({"session": session, "held": k, "act": "send"})).unwrap();
    let second = faces(2)[1].clone();
    assert!(second.get("hands").is_none(), "the change the person acknowledged is named no more: {second}");
    let rows = shell.call("held", &json!({"session": session})).unwrap();
    assert_eq!((rows[0]["cause"].as_str(), rows[0]["base"].as_u64()), (Some("moved"), Some(moved_at)), "the base raised to the verdict's `site.current`: {rows}");
    let text = std::fs::read_to_string(held_path(&dir.path().join("store")).expect("the held file stands")).unwrap();
    let last = text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).rfind(|l| l["held"] == k).expect("the line on disk");
    assert_eq!(last["base"].as_u64(), Some(moved_at), "the raise on disk: {text}");
    // A further change by another hand — a bare session's, under local
    // trust — and the person's send again: the further change alone named.
    let bare = open_bare(&entry.board, 1).unwrap();
    let Answer::Document(further) = entry.board.op(Some(&bare.token), &insert(3, "c", moved_at)).unwrap() else { panic!("the bare session stands") };
    assert!(further["at"].as_u64().is_some_and(|f| f > moved_at), "the bare write is acked: {further}");
    shell.call("resolve", &json!({"session": session, "held": k, "act": "send"})).unwrap();
    let third = faces(3)[2].clone();
    assert_eq!(third["hands"], json!([{"key": "bare"}]), "the change since the person's send alone: {third}");
    // Nothing of the burst landed.
    let read = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 4)})).unwrap();
    assert_eq!(text_of(&read), "abc", "{read}");
    shell.shutdown();
    sd.shutdown();
}

/// Claims the board at `origin` with the store at `store` by hand, the claim's
/// own `H.1` refused by the daemon's seam: a running claimed board with no
/// head record.
///
/// The shell's `claim` call runs the whole walk in one breath, and the walk
/// writes after the claim — the agent-space step — each write's turn paying
/// the head the seam refused, so the seam cannot hold through it; the steps
/// are taken here one by one, as the daemon's own suite takes them: the
/// device key generated into the store and bound for (origin, 1); the
/// delegate of `1.0.1` to principal 1 from the boot session; the home's mint;
/// the genesis deposit of the device key; and, the seam armed just before
/// it, the claim link under a signed full session. The daemon's own retry of
/// the owed head is held first, for good, so only a write's turn can land
/// it: nothing is written after, so the head stays owed. Answers the
/// library's board and the owner's bare session, alive on the permissive
/// board, for the writes a cell makes after.
fn claim_with_the_head_refused(sd: &Skepd, origin: &str, store: &Path) -> (Board, Token) {
    use skep_client::board::{acked_addr, frames, Opened as SessionOpened, Scope, SessionBody, T_CLAIM};
    use skep_client::ceremony::deposit::{deposit, Deposit, DepositKind};
    use skep_client::ceremony::handshake::{handshake_prechecked, Site};
    use skep_client::derive::precheck;
    use skep_client::sheet::Label;
    use skep_client::store::{Binding, FileStore, KeyId, KeySelector, KeyStore};
    use skep_identity::Enrollment;
    let board = Board::new(Origin::parse(origin).unwrap(), skep_client::PlainHttp::new());
    let keys = FileStore::open(store);
    let KeyId(fp) = keys.generate(Some(Label::new("notebook").unwrap())).unwrap();
    let key = keys.list().unwrap().into_iter().find(|k| k.fingerprint == fp).expect("the key generated");
    let signer = keys.signer(&KeySelector::Path(&key.path)).unwrap();
    let bare = |principal: u64| -> Token {
        match board.session_open(SessionBody::Bare { principal }).unwrap() {
            SessionOpened::Token(token) => token,
            other => panic!("a bare session as principal {principal} on the unclaimed board: {other:?}"),
        }
    };
    let acked = |answer: Answer| -> Value {
        let Answer::Document(v) = answer else { panic!("the session stands") };
        assert!(acked_addr(&v).is_some(), "acked: {v}");
        v
    };
    let boot = bare(0);
    acked(board.op(Some(&boot), &frames::delegate("1.0.1", 1, None)).unwrap());
    let owner = bare(1);
    let minted = acked(board.op(Some(&owner), &frames::create_home("1.0.1", None)).unwrap());
    let home = acked_addr(&minted).unwrap().to_string();
    let entries = vec![Enrollment::new(key.public.clone(), false, key.label.clone()).unwrap()];
    deposit(&board, &owner, &Deposit { home: &home, subject: "1.0.1", kind: DepositKind::Enroll(entries), hand: None, id: "test.genesis" }).unwrap();
    let pre = precheck(&board, 1, &fp).unwrap();
    let signed = handshake_prechecked(&board, Scope::Full, &*signer, &pre, Site::Claim).unwrap();
    sd.daemon().hold_the_head_retry();
    sd.daemon().refuse_the_next_head_once();
    acked(signed.op(&frames::make_link(&home, &["1.0.1"], &[], T_CLAIM, None)).unwrap());
    let _ = signed.close();
    keys.bind(&Binding::Enrollment { origin: board.dialed().clone(), principal: 1, account: "1.0.1".into(), fingerprint: fp }).unwrap();
    (board, owner)
}

/// Checks that a burst held while the board's head will not read survives a
/// relaunch and is sent once the head reads (skep #725, #727).
///
/// The daemon's claim lands with its `H.1` refused (the seam
/// `refuse_the_next_head_once`, armed just before the claim link — the claim
/// driven by hand, since the shell's own walk writes after the claim and each
/// write's turn would pay the owed head ([`claim_with_the_head_refused`]) —
/// and again before the one bare write that mints the draft): a running
/// claimed board with no head record. A signed shell
/// over it: the session's open names the pending directory under the
/// origin's hash and says the head's state once; a burst into the draft is
/// held `head_unreadable` in the pending file, its answer carrying no
/// `unwritable`, and listed. The shell closed and relaunched while the head
/// is still refused lists the line from the pending file — not from memory,
/// which the close emptied. The head then lands — a bare write's turn pays
/// it, the daemon's own retry of the owed head held by the helper so the
/// cell decides when — and the next probe joins the line into the board's
/// own file and sends it once, kept, the pending file gone and the board's
/// file compacted away (the mutant that keeps the line in memory loses it at
/// the close; the one that never joins resends nothing; the one that joins
/// without removing the pending file sends it again at the next launch).
#[test]
fn a_burst_held_while_the_head_will_not_read_survives_a_relaunch_and_is_sent_once_it_reads() {
    use sha2::{Digest, Sha256};
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    let (library, bare) = claim_with_the_head_refused(&sd, &origin, &store);
    assert!(library.board_term().unwrap().is_none(), "the claim stands, its H.1 refused");
    // The draft, minted by a bare write whose turn would pay the owed head:
    // the seam armed again, so the head stays owed.
    sd.daemon().refuse_the_next_head_once();
    let Answer::Document(minted) = library.op(Some(&bare), &skep_client::board::frames::create_document("1.0.1", false, None)).unwrap() else { panic!("the bare session stands") };
    let draft = minted["addr"].as_str().unwrap_or_else(|| panic!("the draft is minted: {minted}")).to_string();
    let typed = minted["at"].as_u64().unwrap();
    assert!(library.board_term().unwrap().is_none(), "the mint's turn met the seam: still no H.1");
    let hash = skep_search::Chain::from_bytes(Sha256::digest(origin.as_bytes()).into()).to_string();
    let pending = store.join("held").join("pending").join(&hash).join("principal-1.held");
    let k = {
        let (shell, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
        let seen = Arc::new(Mutex::new(Vec::new()));
        let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
        let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
        let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
        let held = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["b"], "as_of": typed}})).unwrap();
        assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("head_unreadable")), "{held}\n{}", lines.lock().unwrap().join("\n"));
        assert!(held.get("unwritable").is_none(), "on disk, in the pending file: {held}");
        assert!(pending.is_file(), "the pending file stands at {}", pending.display());
        assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"b\"]"), "the pending file holds the line");
        let rows = shell.call("held", &json!({"session": session})).unwrap();
        assert_eq!((rows.as_array().unwrap().len(), rows[0]["cause"].as_str()), (1, Some("head_unreadable")), "{rows}");
        assert_eq!(lines.lock().unwrap().iter().filter(|l| l.contains("cannot be read")).count(), 1, "the head's state said once: {}", lines.lock().unwrap().join("\n"));
        shell.shutdown();
        held["held"].as_u64().unwrap()
    };
    // The relaunch, the head still refused: the line is listed from the
    // pending file.
    let (shell, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let rows = shell.call("held", &json!({"session": session})).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1, "the relaunch lists the line from the pending file: {rows}\n{}", lines.lock().unwrap().join("\n"));
    assert_eq!((rows[0]["doc"].as_str(), rows[0]["cause"].as_str(), rows[0]["held"].as_u64()), (Some(draft.as_str()), Some("head_unreadable"), Some(k)), "{rows}");
    // The head lands: another bare write's turn pays it.
    let Answer::Document(_) = library.op(Some(&bare), &skep_client::board::frames::create_document("1.0.1", false, None)).unwrap() else { panic!("the bare session stands") };
    assert!(library.board_term().unwrap().is_some(), "H.1 landed at the write's turn");
    // The next probe joins the pending line into the board's file and sends
    // it once.
    wait_for(&seen, |e| e.name == EventName::Held && e.data["doc"] == draft && e.data["state"] == "kept");
    let read = shell.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 1)})).unwrap();
    assert_eq!(text_of(&read), "b", "the burst is on the board once: {read}");
    let token = shell.sessions.get(&session).unwrap().token.clone();
    assert_eq!(changes_under(&shell.boards[0].board, &token, &draft, typed).len(), 1, "one row of the burst, never two");
    assert!(shell.call("held", &json!({"session": session})).unwrap().as_array().unwrap().is_empty(), "no line stands");
    assert!(!pending.exists(), "the pending file joined the board's file and is gone");
    assert!(held_path(&store).is_none(), "the board's file compacted away");
    let talk = lines.lock().unwrap().join("\n");
    assert!(talk.contains("1 held line joined the board's held file"), "the join said once: {talk}");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a second shell over the data directory reads alone at a
/// board whose held store the first holds (§3c.3; skep #789).
///
/// ONE SHELL PER DATA DIRECTORY, until a second launch hands its address to
/// the running client: a second signed shell over the first's store opens a
/// session at the board, finds the store the first's and says so once on
/// `Talk`; every write it is asked for — a burst, a burst through `/op-at`,
/// a mint, a link, a publication's open, a merge's withdrawal, a restore —
/// is refused `another_window` naming its `op` or its `call`, nothing sent
/// (the board's position unmoved) and nothing held (`held` lists nothing,
/// no held file stands); a read and the change feed still answer. The first
/// shell gone, the second's next session takes the store, says so once, and
/// its burst is acked (the mutant that keeps a second shell's bursts in
/// memory loses them at its close; the one that refuses at the hold alone
/// dials the non-burst writes; the one that never tries the lock again
/// leaves the window reading alone for its life).
#[test]
fn a_second_shell_over_the_data_directory_refuses_every_write_and_holds_nothing() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    let HeldGround { shell, draft, at, .. } = held_ground(&dir, &sd);
    let (second, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let board = second.board_references().remove(0);
    let session = second.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let said = |text: &str| lines.lock().unwrap().iter().filter(|line| line.contains(text)).count();
    assert_eq!(said("another shell holds this board's held store"), 1, "said once at the session's open: {:?}", lines.lock().unwrap());
    let position = || second.call("health", &json!({"board": board})).unwrap()["health"]["log_position"].as_u64().unwrap();
    let before = position();
    let burst = json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"], "as_of": at});
    let writes = [
        burst.clone(),
        json!({"at": before, "frame": burst.clone()}),
        json!({"op": "create_new_document", "account": "1.0.1"}),
        json!({"op": "make_link", "home": draft, "from": {"addrs": [draft]}, "to": {"addrs": [draft]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}),
    ];
    for frame in writes {
        let refused = second.call("op", &json!({"session": session, "frame": frame})).unwrap_err();
        let v = refused.to_value();
        let op = frame["op"].as_str().or(frame["frame"]["op"].as_str());
        assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), ("another_window", Some("shell"), op), "{frame}: {v}");
    }
    for (call, args) in [
        ("publication.open", json!({"session": session, "draft": draft, "doc": "1.0.1.0.1"})),
        ("merge.withdraw", json!({"session": session, "draft": draft})),
        ("history.restore", json!({"session": session, "draft": draft, "at": at, "as_of": before})),
    ] {
        let refused = second.call(call, &args).unwrap_err();
        assert_eq!((refused.name(), refused.to_value()["call"].as_str()), ("another_window", Some(call)), "{refused}");
    }
    assert_eq!(position(), before, "nothing is sent");
    assert!(second.call("held", &json!({"session": session})).unwrap().as_array().unwrap().is_empty(), "nothing is held");
    assert!(held_path(&store).is_none(), "no held file stands");
    let read = second.call("op", &json!({"session": session, "frame": skep_client::board::frames::retrieve_v(&draft, 1, 1)})).unwrap();
    assert_eq!(text_of(&read), "a", "a read answers: {read}");
    second.call("changes", &json!({"session": session, "since": 0})).unwrap();
    // The first shell gone, the next session takes the store.
    shell.shutdown();
    drop(shell);
    let next = second.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    assert_eq!(said("this shell holds this board's held store now"), 1, "said once as it ends: {:?}", lines.lock().unwrap());
    let acked = second.call("op", &json!({"session": next, "frame": burst})).unwrap();
    assert!(acked["at"].as_u64().is_some() && acked["resp"] != "held", "the burst goes out and is acked: {acked}");
    assert_eq!(said("another shell holds this board's held store"), 1, "the beginning said no second time");
    second.shutdown();
    sd.shutdown();
}

/// Checks that a second shell is told another shell holds the board's held
/// store, at its session's open and at each edge (§3c.3; skep #827).
///
/// The first shell's open takes the store: its answer carries no
/// `another_window`, and nothing is emitted. A second shell over its data
/// directory opens a session whose answer carries `writes`, the session's
/// own right, and `another_window: true` beside it, and emits
/// `another-window` once, `true`; a later open while the first stands
/// carries the member and emits nothing. The first shell gone, the next open
/// takes the store, carries no member and emits `another-window` once,
/// `false`; an open after it, nothing. Every answer is held to
/// `SessionOpened` and every event to its declaration (the mutant that reads
/// the state before the open answers each open the state as it stood before
/// it, the open that finds another shell's store among them; the one that
/// emits at every try tells the page an edge at each open; the one that
/// drops the member leaves the page to learn the state at its first refused
/// write).
#[test]
fn a_second_shell_is_told_another_shells_store_at_the_open_and_at_each_edge() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let open = |shell: &Shell, board: &str| -> Value {
        let opened = shell.call("session", &json!({"board": board})).unwrap();
        crate::shapes::assert_declared("SessionOpened", &opened);
        opened
    };
    // The events a call emitted, read off a subscriber taken before it: the
    // emit is the call's own, made before it answers.
    let edges = |rx: &std::sync::mpsc::Receiver<Event>| -> Vec<Value> {
        let seen: Vec<Event> = rx.try_iter().collect();
        assert_events_declared(&seen);
        seen.into_iter().filter(|e| e.name == EventName::AnotherWindow).map(|e| e.data).collect()
    };
    let (first, _) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let first_rx = first.subscribe();
    let opened = open(&first, &first.board_references().remove(0));
    assert!(opened.get("another_window").is_none(), "the shell whose open takes the store is told nothing: {opened}");
    assert!(edges(&first_rx).is_empty(), "and emits nothing");
    let (second, _) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let rx = second.subscribe();
    let board = second.board_references().remove(0);
    let opened = open(&second, &board);
    assert_eq!((opened["writes"].as_bool(), opened["another_window"].as_bool()), (Some(true), Some(true)), "the session's own right, and the board's state beside it: {opened}");
    assert_eq!(edges(&rx), [json!({"board": board, "another_window": true})], "emitted once as it begins");
    let again = open(&second, &board);
    assert_eq!(again["another_window"], true, "a later open while the first stands: {again}");
    assert!(edges(&rx).is_empty(), "a try that finds no change emits nothing");
    first.shutdown();
    drop(first);
    let taken = open(&second, &board);
    assert!(taken.get("another_window").is_none(), "the open that takes the store answers no member: {taken}");
    assert_eq!(edges(&rx), [json!({"board": board, "another_window": false})], "emitted once as it ends");
    let after = open(&second, &board);
    assert!(after.get("another_window").is_none() && edges(&rx).is_empty(), "nothing once the store is this shell's: {after}");
    second.shutdown();
    sd.shutdown();
}

/// Checks that two windows across a board's two locks leave one writer, and
/// never none (§3c.3; skep #828).
///
/// The claim lands with its `H.1` refused, and the draft is minted with the
/// seam armed again ([`claim_with_the_head_refused`]): a claimed board
/// serving no head record. Window B's session opens while the head is owed
/// and takes the PENDING directory's lock; B holds no burst, so no probe of
/// B's tries a lock after. The head then lands. Window A over the same store
/// opens a session whose read of the head names the board's own directory:
/// the pending lock, tried first, is B's, so the store is another's — A's
/// answer carries `another_window: true`, its burst is refused
/// `another_window`, nothing sent (the board's position unmoved) and nothing
/// held. B's next session reads the head and takes the board's own lock:
/// its answer carries no `another_window`, and its burst is acked. A's next
/// session still answers `another_window: true`, the board's own lock B's
/// (the mutant that takes the board's own lock first leaves two writers,
/// A's burst going out beside B's; the one that refuses on the pending lock
/// found held beside the board's own leaves none, B refused at its step to
/// a lock A holds).
#[test]
fn two_windows_across_a_boards_two_locks_leave_one_writer_and_never_none() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    let (library, bare) = claim_with_the_head_refused(&sd, &origin, &store);
    sd.daemon().refuse_the_next_head_once();
    let Answer::Document(minted) = library.op(Some(&bare), &skep_client::board::frames::create_document("1.0.1", false, None)).unwrap() else { panic!("the bare session stands") };
    let draft = minted["addr"].as_str().unwrap_or_else(|| panic!("the draft is minted: {minted}")).to_string();
    let typed = minted["at"].as_u64().unwrap();
    assert!(library.board_term().unwrap().is_none(), "premise: the mint's turn met the seam, the head owed");
    let open = |shell: &Shell, board: &str| -> Value {
        let opened = shell.call("session", &json!({"board": board})).unwrap();
        crate::shapes::assert_declared("SessionOpened", &opened);
        opened
    };
    let burst = |value: &str| json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": [value], "as_of": typed});
    // Window B, the head owed: its open takes the pending lock.
    let (b, b_lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let b_board = b.board_references().remove(0);
    let opened = open(&b, &b_board);
    assert!(opened.get("another_window").is_none(), "B's open takes the pending store: {opened}\n{}", b_lines.lock().unwrap().join("\n"));
    // The head lands: a bare write's turn pays it.
    let Answer::Document(_) = library.op(Some(&bare), &skep_client::board::frames::create_document("1.0.1", false, None)).unwrap() else { panic!("the bare session stands") };
    assert!(library.board_term().unwrap().is_some(), "H.1 landed at the write's turn");
    // Window A, the head read: the pending lock B holds makes the store
    // another's, and A reads alone.
    let (a, a_lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let a_board = a.board_references().remove(0);
    let opened = open(&a, &a_board);
    assert_eq!(opened["another_window"], true, "A finds the pending lock B's: {opened}\n{}", a_lines.lock().unwrap().join("\n"));
    let a_session = opened["session"].as_str().unwrap().to_string();
    let position = || a.call("health", &json!({"board": a_board})).unwrap()["health"]["log_position"].as_u64().unwrap();
    let before = position();
    let refused = a.call("op", &json!({"session": a_session, "frame": burst("a")})).unwrap_err();
    assert_eq!(refused.name(), "another_window", "{refused}");
    assert_eq!(position(), before, "nothing is sent");
    assert!(a.call("held", &json!({"session": a_session})).unwrap().as_array().unwrap().is_empty(), "nothing is held");
    // B's next open reads the head and takes the board's own lock: B writes.
    let opened = open(&b, &b_board);
    assert!(opened.get("another_window").is_none(), "B takes the board's own lock: {opened}\n{}", b_lines.lock().unwrap().join("\n"));
    let b_session = opened["session"].as_str().unwrap().to_string();
    let acked = b.call("op", &json!({"session": b_session, "frame": burst("b")})).unwrap();
    assert!(acked["at"].as_u64().is_some() && acked["resp"] != "held", "B's burst goes out and is acked: {acked}");
    // A's next open finds the store B's still.
    let again = open(&a, &a_board);
    assert_eq!(again["another_window"], true, "the board's own lock is B's: {again}");
    a.shutdown();
    b.shutdown();
    sd.shutdown();
}
