//! THE CORE against a real daemon in-process: the bare mode's claim through
//! the shell's own `claim` call (every PUBLIC moment answered as the page
//! would), a session in the token's place, a draft write acked and its
//! `feed` event seen with the board's reference, a publish-class write
//! refused `signed_session_required` verbatim, the stale and foreign
//! references, the token's text in no answer and no event; then the signed
//! mode over the same store: a publish-class write acked — the attest the
//! shell composed — and the same write under the bare mode refused.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skepd::{embed, AuthOptions, MediaOptions, Skepd, DEFAULT_WORKERS};
use tempfile::TempDir;

use super::*;
use crate::events::Event;

/// The daemon over `dir`, its own loopback origin configured: the daemon's
/// own start (`skepd::embed`), then the wait for its cell index.
fn spawn(dir: &Path, local_trust: bool) -> Skepd {
    let own = |port: u16| {
        let mut opts = AuthOptions::default();
        opts.local_trust = local_trust;
        opts.configured = vec![skepd::Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap()];
        opts
    };
    let sd = embed(dir, 0, own, MediaOptions::default(), DEFAULT_WORKERS).expect("the daemon starts");
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
    (Shell::open(opts).unwrap(), lines)
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
    let answerer = answer_moments(shell.subscribe(), Arc::clone(shell.pending()), Arc::clone(&seen));
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
    // The feed thread dials `/op` for its own reads, so the dial count is
    // no oracle here; the position is (the provider's suite reads the log).
    assert!(shell.log().entries().iter().filter(|e| e["kind"] == "dial" && e["path"] == "/op").count() >= dials);
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

/// THE SIGNED MODE: the store that claimed the board opens a content-scoped
/// session and a publish-class write is acked — the attest the shell
/// composed; the same write under the bare mode is refused.
#[test]
fn the_signed_mode_composes_the_attest_a_publish_class_write_needs() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    // The claim, under a bare-mode shell (the mode names the session kind,
    // not the walk's).
    {
        let (shell, lines) = shell(&origin, &store, SessionMode::Bare { principal: 1 });
        let seen = Arc::new(Mutex::new(Vec::new()));
        let answerer = answer_moments(shell.subscribe(), Arc::clone(shell.pending()), seen);
        shell.call("keygen", &json!({"label": "notebook"})).unwrap();
        let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
        shell.call("claim", &json!({"board": board})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
        shell.shutdown();
        drop(shell);
        answerer.join().unwrap();
    }
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
