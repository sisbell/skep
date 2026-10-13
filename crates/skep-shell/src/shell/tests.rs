//! THE SHELL's SUITE, its cells in four children over the ground shared
//! here: a real daemon spawned in-process over a temp data dir and started
//! again at its port (`spawn`, `spawn_at`), a shell opened over it as a
//! transport opens one (`shell`), the board claimed through the shell's own
//! `claim` call (`claim_board`), the page's side of a walk — every
//! answerable moment answered in its own form (`answer_moments`) — the wait
//! for an event, and a drafts page read under a token (`changes_under`).
//! `door` holds the shell's own frame, with no daemon behind it; `modes`
//! the bare and the signed session modes end to end; `boards` each board's
//! own node, wait and stop beside another's; `held` the held-burst store
//! against the real daemon.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::board::{Answer, Board, ChangesAnswer, ChangesQuery, Token};
use skep_kernel::Step;
use skepd::{embed, AuthOptions, MediaOptions, Skepd, DEFAULT_WORKERS};
use tempfile::TempDir;

use super::*;
use crate::events::Event;
use crate::held::{HeldDir, Reason};
use crate::hold::{Burst, PROBE_CADENCE};
use crate::sessions::Kind;

mod boards;
mod door;
mod held;
mod modes;

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

fn shell(origin: &str, store: &Path, session_mode: SessionMode) -> (Shell, Arc<Mutex<Vec<String>>>) {
    let (talk, lines) = talk();
    (Shell::open(ShellOptions::new(vec![Origin::parse(origin).unwrap()], store.to_path_buf(), session_mode, talk)), lines)
}

/// The page's side of a walk: every answerable moment answered — a label
/// box with its default or `phone`, a question with `yes` — until the
/// events end or `stop` is seen.
fn answer_moments(rx: std::sync::mpsc::Receiver<Event>, pending: Arc<crate::person::Pending>, seen: Arc<Mutex<Vec<Event>>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while let Ok(event) = rx.recv() {
            seen.lock().unwrap().push(event.clone());
            if event.name == EventName::Moment && event.data["answerable"] == true {
                let id = event.data["id"].as_str().unwrap();
                let answer = match event.data["kind"].as_str() {
                    Some("label") => event.data["data"]["default"].as_str().map(Value::from).unwrap_or(Value::from("phone")),
                    Some("yes_no") => Value::from(true),
                    _ => Value::from("yes"),
                };
                // The page answers in its moment's own form; a moment the
                // shell's stop cancelled first waits no more.
                if let Err(refused) = pending.answer(id, answer) {
                    assert_eq!(refused.name(), "no_such_moment", "{refused}");
                }
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

/// The rows of `doc`'s drafts supplement since `since`, read under `token`.
fn changes_under(board: &Board, token: &Token, doc: &str, since: u64) -> Vec<Value> {
    match board.changes(Some(token), &ChangesQuery { since, under: Some(doc), drafts: true, limit: None }).unwrap() {
        ChangesAnswer::Page(page) => page.changes,
        _ => panic!("no page under {doc} since {since}"),
    }
}
