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
//! state announced at its board.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skepd::{embed, AuthOptions, MediaOptions, Skepd, DEFAULT_WORKERS};
use tempfile::TempDir;

use super::*;
use crate::events::Event;

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
