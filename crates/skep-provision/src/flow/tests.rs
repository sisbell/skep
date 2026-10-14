//! THE FLOW's SUITES over the two fakes, and what they share: the rig —
//! the service over the scripted Docker fake and a probe in the mailer's
//! place, its log kept and tapped — the gate a hook pauses at, the poll,
//! the canned answers the sidecar and `/health` give, and the script lines
//! a name's flow is built from. One suite per way into the flow:
//!
//! * `desk` — what the pages ask: the desk's halves of T8, T9 and T10, the
//!   book's rules and the looks' cap;
//! * `pool` — THE POOL's FENCE, T15 to T18: workers on threads of their
//!   own, as `serve` runs them;
//! * `provision` — T13 and T12's flow half: one post provisioned on the
//!   test's own thread, to live or through the cleanup's table;
//! * `start` — the service's start: the status map rebuilt from the
//!   snippets, and THE SWEEP, T20.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use skep_identity::{encode_enroll, Enrollment, PublicKey};

use super::*;
use crate::docker::fake::{line, FakeDocker};
use crate::invites::{lookup, mint};
use crate::mail_address::MailAddress;
use crate::scratch::Scratch;
use crate::sender::fake::FakeSender;
use crate::sender::{Message, Sender};

mod desk;
mod pool;
mod provision;
mod start;

/// The six DATA lines a fresh board's dark claim prints (`sidecar/tests.rs`
/// holds them whole beside the `skep` command's pins).
const SIX: &str = "claimant 1.0.1\naccount 1.0.1\nprincipal 1\norigin http://127.0.0.1:8642\nfirst act: from the device …\nsecond act: in your first signed session …\n";

/// The sidecar's TALK: the operator's lines, logged whole.
const TALK: &str = "payload entry: 9f86d081884c7d65 anchor=true label=(none)\nthe genesis stands: committed\n";

/// A claimed alpha board's `/health`, keys sorted.
const PAIRED: &str = r#"{"auth":{"claimant":"1.0.1","local_trust":false,"origins":[],"signed_origins":["https://alice.skep.host"]},"chain_head":"00","head_time":null,"log_position":0,"media":{"uploads":true},"ok":true,"writes":{"halted":false}}"#;

/// An unclaimed board's.
const UNPAIRED: &str = r#"{"auth":{"claimant":null,"local_trust":false,"origins":[],"signed_origins":[]},"ok":true}"#;

/// A record as the person's device printed it: one production key whose
/// halves decode, its anchor flag as given, and the textarea's CRLF after
/// it.
fn record(anchor: bool) -> String {
    let key = crate::record::decodable_key(0x9f);
    format!("{}\r\n", encode_enroll(&[Enrollment::new(key, anchor, None).expect("no label")]))
}

/// THE PROBE in the mailer's place: the fake sender, which at every try
/// also reads the post's status off the service — so the order of a send
/// against the status turning live is what the test reads.
struct Probe {
    fake: FakeSender,
    service: OnceLock<Weak<Service>>,
    token: Mutex<Option<String>>,
    seen: Mutex<Vec<Option<Shown>>>,
}

impl Sender for Probe {
    fn send(&self, message: &Message) -> io::Result<Exit> {
        let token = self.token.lock().unwrap().clone();
        let shown = match (self.service.get().and_then(Weak::upgrade), token) {
            (Some(service), Some(token)) => service.status(&token),
            _ => None,
        };
        self.seen.lock().unwrap().push(shown);
        self.fake.send(message)
    }
}

/// A test's tap on the log: called with every line once it is kept.
type Tap = Box<dyn Fn(&str) + Send + Sync>;

/// The service over the two fakes, its log kept — and tapped, where a test
/// sets a tap — its mail through the probe on the worker's own thread.
struct Rig {
    dir: Scratch,
    boards: PathBuf,
    state_dir: StateDir,
    fake: Arc<FakeDocker>,
    probe: Arc<Probe>,
    lines: Arc<Mutex<Vec<String>>>,
    tap: Arc<OnceLock<Tap>>,
    service: Arc<Service>,
}

fn rig(script: &str, mail_script: Option<Vec<i32>>) -> Rig {
    rig_with(script, mail_script, Arc::new(|_| {}))
}

/// The rig with the sleep hook `sleep` — a gate's pause, where a test pauses
/// a worker inside its sidecar wait.
fn rig_with(script: &str, mail_script: Option<Vec<i32>>, sleep: Sleep) -> Rig {
    let dir = Scratch::new();
    let boards = dir.path().join("boards");
    fs::create_dir(&boards).expect("the snippet directory");
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let fake = Arc::new(FakeDocker::parse(script).expect("a script"));
    let lines = Arc::new(Mutex::new(Vec::new()));
    let tap: Arc<OnceLock<Tap>> = Arc::new(OnceLock::new());
    let (into, tapped) = (Arc::clone(&lines), Arc::clone(&tap));
    let log: Log = Arc::new(move |line: &str| {
        into.lock().unwrap().push(line.to_owned());
        if let Some(tap) = tapped.get() {
            tap(line);
        }
    });
    let probe = Arc::new(Probe {
        fake: FakeSender::new(dir.path().join("mail.log"), mail_script.clone().unwrap_or_default()),
        service: OnceLock::new(),
        token: Mutex::new(None),
        seen: Mutex::new(Vec::new()),
    });
    let address = |text: &str| MailAddress::parse(text).expect("an address");
    let outbox = mail_script.map(|_| Outbox::inline(Box::new(Arc::clone(&probe)), address("noreply@skep.host"), address("owner@skep.host"), Arc::clone(&log), Arc::new(|_| {})));
    let mailing = outbox.is_some();
    let config = Config { boards_dir: boards.clone(), suffix: suffix() };
    let service = Arc::new(Service::new(config, state_dir.clone(), Box::new(Arc::clone(&fake)), outbox, log, sleep).expect("the service"));
    // The probe reads the service where it is the outbox's sender alone: a
    // rig with no mail hands out no handle on its service, which the sweep
    // then takes whole (`Rig::sweep`).
    if mailing {
        probe.service.set(Arc::downgrade(&service)).ok();
    }
    Rig { dir, boards, state_dir, fake, probe, lines, tap, service }
}

/// A GATE a hook pauses at: the hook counts itself in and waits until the
/// test opens the gate, for good; the test waits for the count.
#[derive(Default)]
struct Gate {
    pauses: Mutex<Pauses>,
    changed: Condvar,
}

/// What a gate has seen: the pauses entered, and whether it is open.
#[derive(Default)]
struct Pauses {
    entered: u32,
    open: bool,
}

impl Gate {
    fn new() -> Arc<Gate> {
        Arc::new(Gate::default())
    }

    /// The hook's side: counted in, then paused until the gate is open.
    fn pause(&self) {
        let mut pauses = self.pauses.lock().unwrap();
        pauses.entered += 1;
        self.changed.notify_all();
        drop(self.changed.wait_while(pauses, |seen| !seen.open).unwrap());
    }

    /// The test's side: waited until `n` pauses have been entered, thirty
    /// seconds at most.
    fn entered(&self, n: u32) {
        let (pauses, waited) = self.changed.wait_timeout_while(self.pauses.lock().unwrap(), Duration::from_secs(30), |seen| seen.entered < n).unwrap();
        drop(pauses);
        assert!(!waited.timed_out(), "pause {n} never entered");
    }

    /// The test's side: the gate opened, for good.
    fn open(&self) {
        self.pauses.lock().unwrap().open = true;
        self.changed.notify_all();
    }
}

/// Polled until `done` answers `Some`, or thirty seconds pass.
fn until<T>(what: &str, mut done: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(t) = done() {
            return t;
        }
        assert!(Instant::now() < deadline, "{what} never came");
        thread::sleep(Duration::from_millis(10));
    }
}

impl Rig {
    /// One invite minted to the person's address.
    fn invite(&self) -> InviteCode {
        mint(&self.state_dir, &MailAddress::parse("person@example.com").expect("an address"), None).expect("minted")
    }

    /// One post to the claim form.
    fn post(&self, name: &str, record: &str, code: &str) -> Result<String, Refusal> {
        self.service.admit(&Post { name: name.as_bytes(), record: record.as_bytes(), invite: code.as_bytes() })
    }

    /// A post admitted, its token the probe's.
    fn admitted(&self, name: &str, code: &InviteCode) -> String {
        let token = self.post(name, &record(true), code.as_str()).unwrap_or_else(|r| panic!("{name}: refused {r:?}: {:?}", self.log()));
        *self.probe.token.lock().unwrap() = Some(token.clone());
        token
    }

    fn log(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    fn snippet(&self, name: &str) -> PathBuf {
        self.boards.join(format!("{name}.caddy"))
    }

    fn issued(&self, code: &InviteCode) -> bool {
        lookup(&self.state_dir, code).expect("read").expect("held").issued()
    }

    /// THE SWEEP as `serve` runs it: over the rig's one handle on the
    /// service, before any thread holds it — `Service::sweep` takes the
    /// service whole.
    fn sweep(&mut self) -> usize {
        Arc::get_mut(&mut self.service).expect("the rig's one handle on the service: no worker spawned, no mail's probe").sweep()
    }

    /// THE POOL as `serve` spawns it: `n` workers over this service, each on
    /// a thread of its own that runs until the test's process ends.
    fn spawn_workers(&self, n: usize) {
        for _ in 0..n {
            let service = Arc::clone(&self.service);
            thread::spawn(move || service.work());
        }
    }

    /// Whether `token`'s page shows the live reply.
    fn live(&self, token: &str) -> bool {
        matches!(self.service.status(token), Some(Shown::Live(_)))
    }

    /// Whether the fake has recorded `call`.
    fn called(&self, call: &str) -> bool {
        self.fake.said().iter().any(|c| c == call)
    }

    /// Whether the log holds `line`.
    fn logged(&self, line: &str) -> bool {
        self.log().iter().any(|l| l == line)
    }

    /// THE TAP set: `tap` is called with every log line once it is kept,
    /// no lock of the rig's held — the test's way to pause a worker, or
    /// change what it meets, between two steps no docker call separates.
    /// Set once.
    fn on_log(&self, tap: impl Fn(&str) + Send + Sync + 'static) {
        assert!(self.tap.set(Box::new(tap)).is_ok(), "the tap is set once");
    }
}

/// One name's whole flow but the reload: the post's inspects, the worker's,
/// `volume_create`, `run_claim`, the dark claim — answering exit 4 once
/// first where `retry`, which puts the worker into its sidecar wait —
/// `rm_force`, `run_serving`, one `health` with the pair. The reload is a
/// line under no name, added apart ([`reloads`]).
fn flow_of(name: &str, retry: bool) -> String {
    let mut script = inspects(name) + &inspects(name) + &line("volume_create", Some(name), 0, "", "") + &line("run_claim", Some(name), 0, "", "");
    if retry {
        script += &line("sidecar_claim", Some(name), 4, "", "skep: the board could not be dialed\n");
    }
    script + &line("sidecar_claim", Some(name), 0, SIX, "") + &line("rm_force", Some(name), 0, "", "") + &line("run_serving", Some(name), 0, "", "") + &line("health", Some(name), 0, PAIRED, "")
}

/// `n` reloads, each exit 0.
fn reloads(n: usize) -> String {
    line("caddy_reload", None, 0, "", "").repeat(n)
}

/// The two inspects, both answering "not standing".
fn inspects(name: &str) -> String {
    line("volume_inspect", Some(name), 1, "", "") + &line("container_inspect", Some(name), 1, "", "")
}

fn said(calls: &[&str]) -> Vec<String> {
    calls.iter().map(|c| (*c).to_owned()).collect()
}

/// The suffix every rig's boards are under.
fn suffix() -> Domain {
    Domain::parse("skep.host").expect("a domain")
}

/// The steps that reach the dark claim.
fn to_the_claim() -> String {
    line("volume_create", Some("alice"), 0, "", "") + &line("run_claim", Some("alice"), 0, "", "")
}

/// The steps that reach the serving run.
fn to_the_serving_run() -> String {
    to_the_claim() + &line("sidecar_claim", Some("alice"), 0, SIX, "") + &line("rm_force", Some("alice"), 0, "", "")
}

/// A failure's cleanup of a claim run or a serving run and the volume: the
/// run's last lines read — answering nothing — then the run and the volume
/// removed.
fn run_and_volume_removed() -> String {
    line("run_logs", Some("alice"), 0, "", "") + &line("rm_force", Some("alice"), 0, "", "") + &line("volume_rm", Some("alice"), 0, "", "")
}
