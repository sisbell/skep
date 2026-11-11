//! The shell's suite: its cells in eleven children, its ground shared here.
//!
//! The ground is a real daemon spawned in-process over a temp data dir and
//! started again at its port (`spawn`, `spawn_at`), a shell opened over it
//! as a transport opens one (`open_shell`), the board claimed through the
//! shell's own `claim` call (`claim_board`), the page's side of a walk —
//! every answerable moment answered in its own form (`page_answer`,
//! `answer_moments`) — this machine's notebook started, stopped and
//! restarted by the shell through a control over an in-process daemon, and
//! lost or poisoned behind it (`Control`, `notebook_shell`), the wait for
//! an event, a drafts page read under a token (`changes_under`), every seed
//! a walk made (`seeds_of`), and every event held to its declaration
//! (`assert_events_declared`).
//!
//! `door` holds the shell alone, with no daemon behind it; `modes` the bare
//! and the signed session modes end to end, and the refusing arm;
//! `ceremonies` the ceremonial rows end to end, each death they cause read
//! for its hand; `boards` each board's own node, wait and stop beside
//! another's, and this machine's notebook started at the door's act,
//! stopped at its claim's cancel and at the person's stop, and restarted
//! out of a silence or a halt; `held` the held-burst store against the
//! real daemon; `changes` the catch-up call, against the daemon and over a
//! scripted board; `publication` the publication family — the rules the
//! shell alone keeps, and the panel, the count, the confirm and the cancel
//! against the daemon; `merge` the merge family — the compose, the land,
//! the undo and the withdrawal against the daemon, and the rules the shell
//! alone keeps; `history` the past state's read and its restore — the
//! read's state, its mapping and its marker with nothing written, the
//! restore's typing, its way back and its note in the hold against the
//! daemon, and the rules the shell alone keeps; `follow` the follower write
//! — a mark landing on its insert's words, refused where its burst is held,
//! following a delete, overtaking its insert, and finished by the stop
//! before its session closes — against the daemon; `classes` the held
//! store's defect classes over a `Shell` — one writer per board, a
//! whole-draft write past a draft's held lines — each pinned against the
//! daemon as an expected failure until the brief that closed it landed, and
//! as the invariant from then.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
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
use crate::sessions::SessionKind;

mod boards;
mod ceremonies;
mod changes;
mod classes;
mod door;
mod follow;
mod held;
mod history;
mod merge;
mod modes;
mod publication;

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

/// A shell opened over the board at `origin`, its key store at `store`, in
/// `session_mode`, and its TALK lines beside it.
fn open_shell(origin: &str, store: &Path, session_mode: SessionMode) -> (Shell, Arc<Mutex<Vec<String>>>) {
    let (talk, lines) = talk();
    (Shell::open(ShellOptions::new(vec![Origin::parse(origin).unwrap()], store.to_path_buf(), session_mode, talk)), lines)
}

/// Returns the page's answer to an answerable moment, in its kind's form.
///
/// It is a label box's default or `phone`, a yes-or-no's yes, a question's
/// `yes`.
fn page_answer(moment: &Event) -> Value {
    match moment.data["kind"].as_str() {
        Some("label") => moment.data["data"]["default"].as_str().map(Value::from).unwrap_or(Value::from("phone")),
        Some("yes_no") => Value::from(true),
        _ => Value::from("yes"),
    }
}

/// Returns the page's side of a walk, on a thread of its own.
///
/// Every answerable moment is answered as [`page_answer`] answers it, until
/// the events end.
fn answer_moments(rx: std::sync::mpsc::Receiver<Event>, pending: Arc<crate::person::Pending>, seen: Arc<Mutex<Vec<Event>>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while let Ok(event) = rx.recv() {
            seen.lock().unwrap().push(event.clone());
            if event.name == EventName::Moment && event.data["answerable"] == true {
                let id = event.data["id"].as_str().unwrap();
                // The page answers in its moment's own form; a moment the
                // shell's stop cancelled first waits no more.
                if let Err(refused) = pending.answer(id, page_answer(&event)) {
                    assert_eq!(refused.name(), "no_such_moment", "{refused}");
                }
            }
        }
    })
}

/// A node control a suite drives, each start and stop the shell makes counted.
///
/// It starts the daemon in-process over `dir` at `port`, local trust on,
/// and shuts it down at the stop, which returns `stop_pause` after the
/// daemon is down — or, once given a refusal, refuses every start with it.
struct Control {
    dir: PathBuf,
    port: u16,
    refusal: Mutex<Option<Halt>>,
    stop_pause: Duration,
    node: Mutex<Option<Skepd>>,
    starts: AtomicUsize,
    stops: AtomicUsize,
}

impl Control {
    /// Returns a control over the daemon at `dir`, the daemon not started.
    ///
    /// Its port is one reserved and let go.
    fn over(dir: &Path) -> Arc<Control> {
        Control::at(dir, None, Duration::ZERO)
    }

    /// Returns a control over `dir` whose every stop takes `pause` longer.
    ///
    /// The pause runs past the daemon's going down: an orderly stop that
    /// lets a checkpoint in flight finish.
    fn stopping_slowly(dir: &Path, pause: Duration) -> Arc<Control> {
        Control::at(dir, None, pause)
    }

    /// Returns a control whose every start is refused with `refusal`.
    ///
    /// Its port is one nothing answers at.
    fn refusing(refusal: Halt) -> Arc<Control> {
        Control::at(Path::new("/nonexistent/notebook"), Some(refusal), Duration::ZERO)
    }

    /// Returns a control over `dir` at a port reserved and let go.
    fn at(dir: &Path, refusal: Option<Halt>, stop_pause: Duration) -> Arc<Control> {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
        Arc::new(Control { dir: dir.to_path_buf(), port, refusal: Mutex::new(refusal), stop_pause, node: Mutex::new(None), starts: AtomicUsize::new(0), stops: AtomicUsize::new(0) })
    }

    /// Refuses every start from now on with `refusal`.
    fn refuse(&self, refusal: Halt) {
        *self.refusal.lock().unwrap_or_else(PoisonError::into_inner) = Some(refusal);
    }

    /// Shuts the running daemon down behind the shell, no stop asked.
    ///
    /// The node stops answering, as a crash leaves it.
    fn lose_node(&self) {
        if let Some(sd) = self.node.lock().unwrap_or_else(PoisonError::into_inner).take() {
            sd.shutdown();
        }
    }

    /// Poisons the running daemon's kernel at its next commit (§3c.2).
    ///
    /// The commit's barrier fails, then the repair that would undo it, so
    /// that write answers `poisoned`, its frames landing at the next start.
    ///
    /// # Panics
    ///
    /// Panics where the daemon is not running.
    fn poison(&self) {
        let node = self.node.lock().unwrap_or_else(PoisonError::into_inner);
        let daemon = node.as_ref().expect("the daemon runs").daemon();
        daemon.fail_the_next_checkpoint_step(Step::JournalBarrier, std::io::ErrorKind::Other);
        daemon.fail_the_next_checkpoint_step(Step::JournalRepair, std::io::ErrorKind::Other);
    }

    /// Returns the origin the control starts its daemon at.
    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Returns the starts and the stops the shell made of the node.
    fn counts(&self) -> (usize, usize) {
        (self.starts.load(Ordering::SeqCst), self.stops.load(Ordering::SeqCst))
    }
}

impl NodeControl for Control {
    fn start(&self) -> Result<(), Halt> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        if let Some(refusal) = self.refusal.lock().unwrap_or_else(PoisonError::into_inner).clone() {
            return Err(refusal);
        }
        let mut node = self.node.lock().unwrap_or_else(PoisonError::into_inner);
        if node.is_none() {
            *node = Some(spawn_at(&self.dir, true, self.port));
        }
        Ok(())
    }

    fn stop(&self) {
        self.stops.fetch_add(1, Ordering::SeqCst);
        if let Some(sd) = self.node.lock().unwrap_or_else(PoisonError::into_inner).take() {
            sd.shutdown();
            thread::sleep(self.stop_pause);
        }
    }
}

impl Drop for Control {
    /// Shuts a daemon the control left running down.
    fn drop(&mut self) {
        if let Some(sd) = self.node.get_mut().unwrap_or_else(PoisonError::into_inner).take() {
            sd.shutdown();
        }
    }
}

/// Returns a shell over this machine's notebook alone, in the bare mode.
///
/// Its node is `control`'s and its key store at `store`, and its TALK lines
/// stand beside it.
fn notebook_shell(control: &Arc<Control>, store: &Path) -> (Shell, Arc<Mutex<Vec<String>>>) {
    notebook_shell_in(control, store, SessionMode::Bare { principal: 1 })
}

/// Returns a shell over this machine's notebook alone, in `session_mode`.
///
/// It is [`notebook_shell`]'s, its sessions opened in the mode named.
fn notebook_shell_in(control: &Arc<Control>, store: &Path, session_mode: SessionMode) -> (Shell, Arc<Mutex<Vec<String>>>) {
    let (talk, lines) = talk();
    let origin = Origin::parse(&control.origin()).unwrap();
    let mut opts = ShellOptions::new(vec![origin.clone()], store.to_path_buf(), session_mode, talk);
    opts.own_node = Some(origin);
    opts.node_control = Some(Arc::clone(control) as Arc<dyn NodeControl>);
    (Shell::open(opts), lines)
}

/// The board at `origin` claimed by the store at `store` through a
/// bare-mode shell's own `claim` call — the mode names the session kind,
/// not the walk's.
fn claim_board(origin: &str, store: &Path) {
    let (shell, lines) = open_shell(origin, store, SessionMode::Bare { principal: 1 });
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

/// Every seed the walks under `store` made, in hex: each key file's in the
/// store, and each anchor file's under `<store>-anchors/` — what no answer,
/// event or log entry the page reads, and no TALK line, may carry.
fn seeds_of(store: &Path) -> Vec<String> {
    let keys = skep_client::store::FileStore::open(store);
    let mut seeds: Vec<String> = keys.list().unwrap().iter().map(|key| keys.load(&key.path).unwrap().seed_hex()).collect();
    let mut anchors = store.as_os_str().to_owned();
    anchors.push("-anchors");
    for dir in std::fs::read_dir(PathBuf::from(anchors)).into_iter().flatten().flatten() {
        for file in std::fs::read_dir(dir.path()).into_iter().flatten().flatten() {
            seeds.push(skep_client::sheet::KeyFile::parse(&std::fs::read(file.path()).unwrap()).unwrap().seed_hex());
        }
    }
    seeds
}

/// Every event in `seen` held to its declaration (`shapes`): the event's own
/// shape by its name — a match the compiler holds to every name — and the
/// value its data carries: a `feed` update to `FeedUpdate`, a death's reason
/// to `DeathReason`, an index's state to `IndexState`.
fn assert_events_declared(seen: &[Event]) {
    for event in seen {
        let shape = match event.name {
            EventName::Mode => "ModeEvent",
            EventName::SessionDied => "SessionDiedEvent",
            EventName::Daemon => "DaemonEvent",
            EventName::Feed => "FeedEvent",
            EventName::Index => "IndexEvent",
            EventName::Moment => "MomentEvent",
            EventName::Held => "HeldEvent",
            EventName::Publication => "PublicationEvent",
            EventName::AnotherWindow => "AnotherWindowEvent",
        };
        crate::shapes::assert_declared(shape, &event.data);
        match event.name {
            EventName::Feed => crate::shapes::assert_declared("FeedUpdate", &event.data["update"]),
            EventName::SessionDied => crate::shapes::assert_declared("DeathReason", &event.data["reason"]),
            EventName::Index => crate::shapes::assert_declared("IndexState", &event.data["state"]),
            EventName::Held => {
                for hand in event.data["hands"].as_array().into_iter().flatten() {
                    crate::shapes::assert_declared("Hand", hand);
                }
            }
            _ => {}
        }
    }
}
