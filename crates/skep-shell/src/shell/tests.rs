//! THE CORE against a real daemon in-process: the bare mode's claim through
//! the shell's own `claim` call (every PUBLIC moment answered as the page
//! would), a session in the token's place, a draft write acked and its
//! `feed` event seen with the board's reference, a publish-class write
//! refused `signed_session_required` verbatim, a history read past the head
//! refused `beyond_head` under the board's own status, `accept`'s armed
//! name read off the real walk, the stale and foreign references, the
//! token's text in no answer and no event; then the signed mode over the
//! same store: a publish-class write acked — the attest the shell composed
//! — and the same write under the bare mode refused; the daemon's restart
//! under the signed mode: the session it ended, ended once, re-opened under
//! a fresh reference its arm names, and written under; and the own node's
//! state announced at its board — a deliberate stop said once, its feed
//! adding no `unreachable` while it stands. Then the HELD-BURST STORE: the
//! holds against the real daemon, the poisoned burst that lands at the
//! restart and is kept, the signed session's own attested row, a burst on a
//! draft just minted kept across a restart, a relaunch with its board down
//! listing and resending its held line, and the probe keeping its cadence
//! while the board keeps committing.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::board::{Answer, Board, ChangesAnswer, ChangesQuery, Token};
use skep_kernel::Step;
use skepd::{embed, AuthOptions, MediaOptions, Skepd, DEFAULT_WORKERS};
use tempfile::TempDir;

use super::*;
use crate::attest::Composer;
use crate::events::Event;
use crate::held::Reason;
use crate::hold::PROBE_CADENCE;

/// The daemon over `dir` at an ephemeral port.
fn spawn(dir: &Path, local_trust: bool) -> Skepd {
    spawn_at(dir, local_trust, 0)
}

/// The daemon over `dir` at `port` (0 for an ephemeral one), its own
/// loopback origin configured: the daemon's own start (`skepd::embed`),
/// then the wait for its cell index.
fn spawn_at(dir: &Path, local_trust: bool, port: u16) -> Skepd {
    let own = |port: u16| {
        let mut opts = AuthOptions::default();
        opts.local_trust = local_trust;
        opts.configured = vec![skepd::Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap()];
        opts
    };
    let sd = embed(dir, port, own, MediaOptions::default(), DEFAULT_WORKERS).expect("the daemon starts");
    sd.wait_for_the_index(Duration::from_secs(60)).unwrap_or_else(|e| panic!("{e}"));
    sd
}

fn talk() -> (Talk, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&lines);
    (Arc::new(move |l: &str| kept.lock().unwrap().push(l.to_string())), lines)
}

fn shell(origin: &str, store: &Path, mode: SessionMode) -> (Shell, Arc<Mutex<Vec<String>>>) {
    let (talk, lines) = talk();
    let opts = ShellOptions { boards: vec![Origin::parse(origin).unwrap()], store_dir: store.to_path_buf(), mode, arm: ArmConfig::Auto, talk, own_node: None };
    (Shell::open(opts), lines)
}

/// The page's side of a walk: every answerable moment answered — a label
/// box with its default or `phone`, a question with `yes` — until the
/// events end or `stop` is seen.
fn answer_moments(rx: std::sync::mpsc::Receiver<Event>, pending: Arc<crate::person::Pending>, seen: Arc<Mutex<Vec<Event>>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while let Ok(event) = rx.recv() {
            seen.lock().unwrap().push(event.clone());
            if event.name == "moment" && event.data["answerable"] == true {
                let id = event.data["id"].as_str().unwrap();
                let answer = match event.data["kind"].as_str() {
                    Some("label") => event.data["data"]["default"].as_str().map(Value::from).unwrap_or(Value::from("phone")),
                    Some("yes_no") => Value::from(true),
                    _ => Value::from("yes"),
                };
                pending.answer(id, answer);
            }
        }
    })
}

/// The board at `origin` claimed by the store at `store` through a
/// bare-mode shell's own `claim` call — the mode names the session kind,
/// not the walk's.
fn claim_board(origin: &str, store: &Path) {
    let (shell, lines) = shell(origin, store, SessionMode::Bare { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), seen);
    shell.call("keygen", &json!({"label": "notebook"})).unwrap();
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    shell.call("claim", &json!({"board": board})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    shell.shutdown();
    drop(shell);
    answerer.join().unwrap();
}

fn wait_for(seen: &Arc<Mutex<Vec<Event>>>, pred: impl Fn(&Event) -> bool) -> Event {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(e) = seen.lock().unwrap().iter().find(|e| pred(e)).cloned() {
            return e;
        }
        assert!(Instant::now() < deadline, "the event did not arrive: {:?}", seen.lock().unwrap().iter().map(|e| e.name).collect::<Vec<_>>());
        thread::sleep(Duration::from_millis(20));
    }
}

/// THE BARE MODE, end to end.
#[test]
fn the_bare_mode_claims_opens_writes_and_names_no_token() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    let (shell, lines) = shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    // boards(), and the unknown board.
    let boards = shell.call("boards", &json!({})).unwrap();
    let board = boards[0]["board"].as_str().unwrap().to_string();
    assert!(board.starts_with("b-"));
    assert_eq!(boards[0]["origin"], origin);
    assert_eq!(shell.call("health", &json!({"board": "b-nowhere"})).unwrap_err().name(), "unknown_board");
    // The claim needs a key: `no_key` before one is made.
    assert_eq!(shell.call("claim", &json!({"board": board})).unwrap_err().name(), "no_key");
    let keygen = shell.call("keygen", &json!({"label": "notebook"})).unwrap();
    assert_eq!(keygen["fingerprint"].as_str().unwrap().len(), 64);
    let rows = shell.call("fingerprint", &json!({"payload": true})).unwrap();
    assert_eq!(rows[0]["unbound"], true);
    assert!(skep_identity::parse_enroll(rows[0]["payload"].as_str().unwrap().as_bytes()).is_ok());
    // The claim through the shell: the label boxes answered by the "page".
    let claimed = shell.call("claim", &json!({"board": board, "name": "a name"})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(claimed["account"], "1.0.1");
    assert_eq!(claimed["principal"], 1);
    let health = shell.call("health", &json!({"board": board})).unwrap();
    assert_eq!(health["mode"], "CLAIMED-PERMISSIVE");
    assert_eq!(health["health"]["auth"]["claimant"], "1.0.1");
    let moments: Vec<Event> = seen.lock().unwrap().iter().filter(|e| e.name == "moment").cloned().collect();
    assert!(moments.iter().any(|m| m.data["kind"] == "label"), "the anchor boxes crossed as moments");
    assert!(moments.iter().all(|m| m.data["walk"] == "claim"));
    assert!(!lines.lock().unwrap().iter().any(|l| l.contains("seed")), "nothing of a seed on TALK");
    wait_for(&seen, |e| e.name == "mode" && e.data["mode"] == "CLAIMED-PERMISSIVE");
    // A second claim on the claimed board, this store's: the idempotent answer.
    let again = shell.call("claim", &json!({"board": board})).unwrap();
    assert_eq!(again["account"], "1.0.1");
    // The session, in the token's place.
    let opened = shell.call("session", &json!({"board": board, "principal": 1})).unwrap();
    let session = opened["session"].as_str().unwrap().to_string();
    assert!(session.starts_with("s-"));
    assert_eq!(opened["account"], "1.0.1");
    let token = shell.sessions.get(&session).unwrap().token.as_str().to_string();
    assert_ne!(session, token);
    assert!(!session.contains(&token[..8]), "the reference is not derived from the token");
    // A draft write: acked; its feed event carries the board reference.
    let minted = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    let draft = minted["addr"].as_str().unwrap().to_string();
    let acked = shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}})).unwrap();
    assert!(acked["resp"].as_str().unwrap().starts_with("ack"), "{acked}");
    let feed = wait_for(&seen, |e| e.name == "feed" && e.data["update"]["op"] == "insert");
    assert_eq!(feed.data["board"], board);
    assert_eq!(feed.data["update"]["position"], feed.data["update"]["at"]);
    assert!(feed.data["update"]["class"].is_string());
    // A publish-class write: refused `signed_session_required`, verbatim.
    let refused = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}})).unwrap_err();
    assert_eq!(refused.name(), "signed_session_required");
    assert_eq!(refused.to_value()["kind"], "refused");
    // The guest form: a read answers, a write is refused without a dial.
    let guest = shell.call("op", &json!({"guest": true, "board": board, "frame": {"op": "doc_metadata", "doc": draft}})).unwrap_err();
    assert_eq!(guest.name(), "withheld", "a draft is withheld from a guest");
    let position = |v: &Value| v["health"]["log_position"].as_u64().unwrap();
    let before = position(&shell.call("health", &json!({"board": board})).unwrap());
    let dials = shell.log().entries().into_iter().filter(|e| e["kind"] == "dial" && e["path"] == "/op").count();
    let write = shell.call("op", &json!({"guest": true, "board": board, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap_err();
    assert_eq!(write.name(), "write_in_guest_form");
    assert_eq!(position(&shell.call("health", &json!({"board": board})).unwrap()), before, "the refused write committed nothing");
    // The write by identity is a write of the wire (`reinstate`): the guest
    // form refuses it without a dial, as it refuses every `WRITE_OPS` member.
    let reinstate = shell.call("op", &json!({"guest": true, "board": board, "frame": {"op": "reinstate", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "runs": [{"origin": draft, "i_start": format!("{draft}.0.1.1"), "width": "1"}]}})).unwrap_err();
    assert_eq!(reinstate.name(), "write_in_guest_form");
    assert_eq!(position(&shell.call("health", &json!({"board": board})).unwrap()), before, "the refused reinstate committed nothing");
    // The feed thread dials `/op` for its own reads, so the dial count is
    // no oracle here; the position is (the provider's suite reads the log).
    assert!(shell.log().entries().iter().filter(|e| e["kind"] == "dial" && e["path"] == "/op").count() >= dials);
    // History past the head: the board's own `beyond_head` under its own
    // status, in the session form and the guest form alike — a refusal,
    // never a result.
    let past = before + 1_000_000;
    let key_set = json!({"op": "key_set", "account": "1.0.1"});
    for args in [json!({"session": session, "frame": {"at": past, "frame": key_set}}), json!({"guest": true, "board": board, "frame": {"at": past, "frame": key_set}})] {
        let refused = shell.call("op", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name().as_str(), v["kind"].as_str(), v["status"].as_u64()), ("beyond_head", Some("refused"), Some(400)), "{v}");
        assert!(v["body"]["head"].is_u64(), "the head the board named rides its verdict: {v}");
    }
    // `accept` at an address the giver has not delegated: the armed name,
    // read off the real walk's halt.
    assert_eq!(shell.call("accept", &json!({"board": board, "address": "1.0.1.7"})).unwrap_err().name(), "not_delegated");
    // Search: the index is the consumer's; the guest form over the board.
    let answer = shell.call("search", &json!({"session": session, "board": board, "query": "hello", "opts": {"limit": 5}})).unwrap();
    assert!(answer["state"]["arm"].is_string());
    assert_eq!(shell.call("search", &json!({"session": session, "query": "x".repeat(2000)})).unwrap_err().name(), "query_too_long");
    // Close: `{}`, the event, then the stale reference.
    assert_eq!(shell.call("close", &json!({"session": session})).unwrap(), json!({}));
    let died = wait_for(&seen, |e| e.name == "session-died");
    assert_eq!(died.data["session"], session);
    assert_eq!(died.data["reason"]["arm"], "closed");
    assert_eq!(shell.call("op", &json!({"session": session, "frame": {"op": "doc_metadata", "doc": draft}})).unwrap_err().name(), "session_ended");
    assert_eq!(shell.call("close", &json!({"session": session})).unwrap_err().name(), "session_ended");
    // The token's text in no answer and no event.
    let all = format!("{boards}{opened}{minted}{acked}{:?}", seen.lock().unwrap());
    assert!(!all.contains(&token), "the token never crosses");
    // The log holds every call.
    assert!(shell.log().calls() >= 12);
    assert_eq!(shell.call("upload", &json!({"session": "s-gone"})).unwrap_err().name(), "session_ended");
    shell.shutdown();
    drop(shell);
    answerer.join().unwrap();
    sd.shutdown();
}

/// THE CLOSE's ORDER: the drafts rows a session committed are `feed` events
/// ahead of the `session-died` its close emits — read under its token at
/// the close, however far the board's feed thread trails the commits — so a
/// page that closes straight after a write still sees the write, and every
/// subscriber sees one sequence.
#[test]
fn a_closed_sessions_drafts_rows_precede_its_session_died() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let rx = shell.subscribe();
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let draft = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["addr"].as_str().unwrap().to_string();
    shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"]}})).unwrap();
    shell.call("close", &json!({"session": session})).unwrap();
    // The close has answered: everything it emitted is on the stream.
    let seen: Vec<Event> = rx.try_iter().filter(|e| e.name == "feed" || e.name == "session-died").collect();
    let sequence: Vec<&str> = seen.iter().map(|e| if e.name == "feed" { e.data["update"]["op"].as_str().unwrap_or("?") } else { e.name }).collect();
    assert_eq!(sequence, ["create_new_document", "insert", "session-died"], "{seen:?}");
    assert!(seen[..2].iter().all(|e| e.data["update"]["class"] == "drafts" && e.data["update"]["session"] == session), "{seen:?}");
    shell.shutdown();
    sd.shutdown();
}

/// THE SIGNED MODE: the store that claimed the board opens a content-scoped
/// session and a publish-class write is acked — the attest the shell
/// composed; the same write under the bare mode is refused.
#[test]
fn the_signed_mode_composes_the_attest_a_publish_class_write_needs() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (signed, lines) = shell(&origin, &store, SessionMode::Signed { principal: 1 });
    assert_eq!(signed.check_signed_key().unwrap().len(), 1);
    let board = signed.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let opened = signed.call("session", &json!({"board": board})).unwrap();
    let session = opened["session"].as_str().unwrap().to_string();
    let edition = signed.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(edition["resp"], "ack_addr", "{edition}");
    let doc = edition["addr"].as_str().unwrap().to_string();
    // A draft, filled, then THE SHOT into the edition: the body read back.
    let draft = signed.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["addr"].as_str().unwrap().to_string();
    signed.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["abc"]}})).unwrap();
    let image = signed.call("op", &json!({"session": session, "frame": skep_client::board::frames::image(&draft, 1, 3)})).unwrap();
    let run = &image["runs"][0];
    let shot = signed
        .call("op", &json!({"session": session, "frame": {"op": "publish", "doc": doc, "draft": draft, "runs": [{"origin": draft, "i_start": run["i_start"], "width": run["width"]}]}}))
        .unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(shot["resp"], "ack_addr", "{shot}");
    let member = shot["addr"].as_str().unwrap();
    let read = signed.call("op", &json!({"guest": true, "board": board, "frame": skep_client::board::frames::retrieve_v(member, 1, 3)})).unwrap();
    assert_eq!(read["items"][0]["content"], "abc");
    // A link homed in the edition, the from-end a V-spec: attested too.
    let link = signed
        .call("op", &json!({"session": session, "frame": {"op": "make_link", "home": doc, "from": [{"source": member, "span": {"start": "1.1", "width": "0.2"}}], "to": {"addrs": [draft]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}}))
        .unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(link["resp"], "ack_addr", "{link}");
    signed.call("close", &json!({"session": session})).unwrap();
    signed.shutdown();
    // The same write under the bare mode: refused.
    let (bare, _) = shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let board = bare.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = bare.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let refused = bare.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}})).unwrap_err();
    assert_eq!(refused.name(), "signed_session_required");
    bare.shutdown();
    sd.shutdown();
}

/// THE RESTART under the signed mode: the session the daemon's restart
/// ended is met by the hand that meets it first — the board's feed thread,
/// here, before any call — and ENDED ONCE: one `session-died` on the
/// restart arm, re-opened under a fresh reference the arm names and
/// registered, its supplement widened (an `index` event names it), and a
/// publish-class write acked under it; the old reference names nothing.
#[test]
fn a_session_the_restart_ended_is_reopened_under_a_fresh_reference() {
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
    wait_for(&seen, |e| e.name == "index" && e.data["session"] == session);
    sd.shutdown();
    let sd = spawn_at(&dir.path().join("board"), true, port);
    let died = wait_for(&seen, |e| e.name == "session-died" && e.data["session"] == session);
    let reason = &died.data["reason"];
    assert_eq!((reason["arm"].as_str(), reason["reopened"].as_bool()), (Some("restart"), Some(true)), "{reason}\n{}", lines.lock().unwrap().join("\n"));
    let reopened = reason["session"].as_str().expect("the arm names the re-opened session").to_string();
    assert!(reopened.starts_with("s-") && reopened != session, "{reopened}");
    assert!(signed.sessions.get(&reopened).is_some(), "the re-opened session is registered");
    wait_for(&seen, |e| e.name == "index" && e.data["session"] == reopened);
    let edition = signed
        .call("op", &json!({"session": reopened, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}}))
        .unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(edition["resp"], "ack_addr", "{edition}");
    assert_eq!(signed.call("op", &json!({"session": session, "frame": {"op": "key_set", "account": "1.0.1"}})).unwrap_err().name(), "session_ended");
    assert_eq!(seen.lock().unwrap().iter().filter(|e| e.name == "session-died").count(), 1, "the session ended once");
    signed.shutdown();
    drop(signed);
    answerer.join().unwrap();
    sd.shutdown();
}

/// The `/op-at` refusals `skep-client` answers as values are the board's
/// verdicts again, each under the status and error document the wire
/// gives it, a member the variant knows riding the body and one it does
/// not left out.
#[test]
fn an_op_at_refusal_is_the_boards_verdict_under_the_wires_status() {
    let verdict = |a: AtAnswer| {
        let v = at_refusal(a).to_value();
        (v["kind"].as_str().map(str::to_string), v["status"].as_u64(), v["body"].clone())
    };
    let refused = |status: u64, body: Value| (Some("refused".to_string()), Some(status), body);
    assert_eq!(verdict(AtAnswer::HistoryReclaimed { floor: Some(5) }), refused(410, json!({"error": "history_reclaimed", "floor": 5})));
    assert_eq!(verdict(AtAnswer::HistoryReclaimed { floor: None }), refused(410, json!({"error": "history_reclaimed"})));
    assert_eq!(verdict(AtAnswer::BeyondHead { head: Some(12) }), refused(400, json!({"error": "beyond_head", "head": 12})));
    assert_eq!(verdict(AtAnswer::NotAPosition { nearest: Some(7) }), refused(400, json!({"error": "not_a_position", "nearest": 7})));
    assert_eq!(verdict(AtAnswer::Busy), refused(503, json!({"error": "history_busy"})));
    assert_eq!(at_refusal(AtAnswer::Busy).name(), "history_busy");
}

/// THE OWN NODE's STATE: a shell that runs the node announces each state
/// its owner reports on the `daemon` event at the node's board, and `probe`
/// answers it; a shell that runs none has none to report.
#[test]
fn the_own_nodes_state_is_announced_at_its_board() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let (talk, _) = talk();
    let own = Shell::open(ShellOptions { boards: vec![Origin::parse(&origin).unwrap()], store_dir: dir.path().join("own-store"), mode: SessionMode::Bare { principal: 1 }, arm: ArmConfig::Auto, talk, own_node: Some(Origin::parse(&origin).unwrap()) });
    let rx = own.subscribe();
    let board = own.board_references().remove(0);
    let daemon = |rx: &Receiver<Event>| -> Vec<Value> { rx.try_iter().filter(|e| e.name == "daemon").map(|e| e.data).collect() };
    own.set_node_state(NodeState::Stopped);
    assert_eq!(daemon(&rx), [json!({"board": board, "state": "stopped"})]);
    assert_eq!(own.call("probe", &json!({})).unwrap()["daemon"], "stopped");
    own.set_node_state(NodeState::Running);
    assert_eq!(daemon(&rx), [json!({"board": board, "state": "running"})]);
    assert_eq!(own.call("probe", &json!({})).unwrap()["daemon"], "running");
    own.shutdown();
    let (other, _) = shell(&origin, &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let rx = other.subscribe();
    other.set_node_state(NodeState::Stopped);
    assert!(daemon(&rx).is_empty(), "a shell that runs no node announces none");
    assert_eq!(other.call("probe", &json!({})).unwrap()["daemon"], "running", "its probe reads the first board, and no stop it was told of");
    other.shutdown();
    sd.shutdown();
}

/// A DELIBERATE STOP IS SAID ONCE: with the own node running and its feed
/// live, `set_node_state(Stopped)` and then the node's shutdown — within
/// three probe cadences the board's `daemon` events are EXACTLY one `stopped`
/// and no `unreachable` (the mutant that keeps the feed's emit under the
/// stop); the node back at the same port and `set_node_state(Running)`:
/// exactly one `running`, the feed's first tick after the restart adding none
/// of its own (the mutant that marks the stream unreachable under the stop
/// and so says `running` twice). A second board that is NOT the own node,
/// shut down the same way, still announces `unreachable`: the `daemon` event
/// reaches every board the shell dials, each naming its board.
#[test]
fn a_deliberate_stop_of_the_own_node_is_said_once() {
    let dir = TempDir::new().unwrap();
    let own_sd = spawn(&dir.path().join("own"), true);
    let other_sd = spawn(&dir.path().join("other"), true);
    let port = own_sd.port();
    let own_origin = format!("http://127.0.0.1:{port}");
    let other_origin = format!("http://127.0.0.1:{}", other_sd.port());
    let store = dir.path().join("store");
    claim_board(&own_origin, &store);
    let (talk, lines) = talk();
    let boards = vec![Origin::parse(&own_origin).unwrap(), Origin::parse(&other_origin).unwrap()];
    let shell = Shell::open(ShellOptions { boards, store_dir: store, mode: SessionMode::Bare { principal: 1 }, arm: ArmConfig::Auto, talk, own_node: Some(Origin::parse(&own_origin).unwrap()) });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let refs = shell.board_references();
    let (own, other) = (refs[0].clone(), refs[1].clone());
    let daemon_states = |board: &str| -> Vec<String> { seen.lock().unwrap().iter().filter(|e| e.name == "daemon" && e.data["board"] == board).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect() };
    // The own node's feed is live: a session's supplement widened on its thread.
    let session = shell.call("session", &json!({"board": own})).unwrap()["session"].as_str().unwrap().to_string();
    wait_for(&seen, |e| e.name == "index" && e.data["session"] == session);
    // The stop, deliberate: said once; then both nodes go down.
    shell.set_node_state(NodeState::Stopped);
    let stopped_at = Instant::now();
    own_sd.shutdown();
    other_sd.shutdown();
    // The other board's stream fails: `unreachable`, as every board's does.
    wait_for(&seen, |e| e.name == "daemon" && e.data["board"] == other && e.data["state"] == "unreachable");
    thread::sleep((stopped_at + PROBE_CADENCE * 3).saturating_duration_since(Instant::now()));
    assert_eq!(daemon_states(&own), ["stopped"], "a deliberate stop is said once, no unreachable beside it:\n{}", lines.lock().unwrap().join("\n"));
    assert!(lines.lock().unwrap().iter().any(|l| l.contains("the commit stream is not answering")), "TALK still says the stream is down:\n{}", lines.lock().unwrap().join("\n"));
    // The node back at the same port, `running` said once by its owner; the
    // old session dies, a fresh one's write makes the stream tick, and the
    // tick adds no `running` of its own.
    let own_sd = spawn_at(&dir.path().join("own"), true, port);
    shell.set_node_state(NodeState::Running);
    wait_for(&seen, |e| e.name == "session-died" && e.data["session"] == session);
    let session2 = shell.call("session", &json!({"board": own})).unwrap()["session"].as_str().unwrap().to_string();
    shell.call("op", &json!({"session": session2, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    wait_for(&seen, |e| e.name == "feed" && e.data["board"] == own && e.data["update"]["class"] == "drafts");
    assert_eq!(daemon_states(&own), ["stopped", "running"], "the restart's running is said once");
    assert_eq!(daemon_states(&other), ["unreachable"], "the other board's stream failure is announced, and nothing more");
    shell.shutdown();
    own_sd.shutdown();
}

/// The declarations name the shell's own answers: every field a real
/// `boards`, `session`, `health` and `probe` answer carries is declared.
#[test]
fn the_real_answers_carry_the_declared_fields() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let (shell, _) = shell(&origin, &dir.path().join("store"), SessionMode::Bare { principal: 0 });
    let fields = |name: &str| -> std::collections::BTreeSet<String> { crate::shapes::shape(name).unwrap().fields.iter().map(|f| f.name.to_string()).collect() };
    let keys = |v: &Value| -> std::collections::BTreeSet<String> { v.as_object().unwrap().keys().cloned().collect() };
    let boards = shell.call("boards", &json!({})).unwrap();
    assert_eq!(keys(&boards[0]), fields("BoardRow"));
    let board = boards[0]["board"].as_str().unwrap().to_string();
    let opened = shell.call("session", &json!({"board": board, "principal": 0})).unwrap();
    assert_eq!(keys(&opened), fields("SessionOpened"));
    assert_eq!(keys(&shell.call("health", &json!({"board": board})).unwrap()), fields("Health"));
    assert_eq!(keys(&shell.call("probe", &json!({})).unwrap()), fields("Probe"));
    assert_eq!(keys(&shell.call("keygen", &json!({"label": "k"})).unwrap()), fields("Keygen"));
    assert_eq!(keys(&shell.call("fingerprint", &json!({})).unwrap()[0]), fields("FingerprintRow"));
    shell.shutdown();
    sd.shutdown();
}

// ── THE HELD-BURST STORE, against the real daemon in-process ─────────────────

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
    wait_for(&seen, |e| e.name == "session-died" && e.data["session"] == session);
    let session2 = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    // The resend runs under the fresh session (the feed's probe/daemon-running):
    // the held event reaches `kept`.
    let deadline = Instant::now() + Duration::from_secs(20);
    while !seen.lock().unwrap().iter().any(|e| e.name == "held" && e.data["doc"] == draft && e.data["state"] == "kept") {
        if Instant::now() >= deadline {
            let held: Vec<Value> = seen.lock().unwrap().iter().filter(|e| e.name == "held").map(|e| e.data.clone()).collect();
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

/// The rows of `doc`'s drafts supplement since `since`, read under `token`.
fn changes_under(board: &Board, token: &Token, doc: &str, since: u64) -> Vec<Value> {
    match board.changes(Some(token), &ChangesQuery { since, under: Some(doc), drafts: true, limit: None }).unwrap() {
        ChangesAnswer::Page(page) => page.changes,
        _ => panic!("no page under {doc} since {since}"),
    }
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
    wait_for(&seen, |e| e.name == "session-died" && e.data["session"] == session);
    let session2 = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    wait_for(&seen, |e| e.name == "held" && e.data["doc"] == draft && e.data["state"] == "kept");
    let states: Vec<String> = seen.lock().unwrap().iter().filter(|e| e.name == "held" && e.data["doc"] == draft).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect();
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
    let fp = entry.facts.fingerprint.expect("a signed session holds a key");
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
    let held = signed.holds.hold(&board_entry.reference, &entry, &frame, Reason::of("unreachable", true)).unwrap();
    assert_eq!(held["resp"], "held", "{held}");
    assert_eq!(signed.call("held", &json!({"session": session})).unwrap()[0]["sent"], true);
    // The restart: the session re-opened under a fresh reference, the resend
    // run under it — the read recognises the row, nothing is re-sent.
    sd.shutdown();
    let sd = spawn_at(&dir.path().join("board"), true, port);
    let died = wait_for(&seen, |e| e.name == "session-died" && e.data["session"] == session);
    let reopened = died.data["reason"]["session"].as_str().expect("the restart arm names the re-opened session").to_string();
    wait_for(&seen, |e| e.name == "held" && e.data["doc"] == draft && e.data["state"] == "kept");
    let states: Vec<String> = seen.lock().unwrap().iter().filter(|e| e.name == "held" && e.data["doc"] == draft).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect();
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
    wait_for(&seen, |e| e.name == "held" && e.data["doc"] == draft && e.data["state"] == "refused");
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
    let refused_count = || seen.lock().unwrap().iter().filter(|e| e.name == "held" && e.data["state"] == "refused").count();
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
    wait_for(&seen, |e| e.name == "session-died" && e.data["session"] == session);
    let session2 = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    wait_for(&seen, |e| e.name == "held" && e.data["doc"] == draft && e.data["state"] == "kept");
    let states: Vec<String> = seen.lock().unwrap().iter().filter(|e| e.name == "held" && e.data["doc"] == draft).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect();
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
    wait_for(&seen, |e| e.name == "held" && e.data["doc"] == draft && e.data["state"] == "kept");
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
        shell.holds.hold(&shell.boards[0].reference, &entry, &frame, Reason::of("unreachable", true)).unwrap();
        let deadline = Instant::now() + PROBE_CADENCE * 3;
        let kept = loop {
            if seen.lock().unwrap().iter().any(|e| e.name == "held" && e.data["doc"] == draft && e.data["state"] == "kept") {
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
