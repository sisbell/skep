//! The fixture: a daemon in-process on an ephemeral port (skepd's own
//! spawn pattern — the port reserved through the slow open, the rebind race
//! retried), a `Board` over the one dialer, a recording dialer for the tests
//! that pin WHAT WAS DIALED AND IN WHAT ORDER, and the scripts the claim
//! walk's person answers.

#![allow(dead_code)]

use std::io::{ErrorKind, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use skep_client::board::Board;
use skep_client::ceremony::claim::{self, ClaimOutcome, Claimed, NotebookOptions};
use skep_client::dial::{DialError, Dialer, Headers, PlainHttp, Request, RequestHead, Response, StreamedResponse};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::store::{FileStore, KeyStore, Label};
use skep_client::Origin;
use skep_identity::Fingerprint;
use skepd::{serve, AuthOptions, Daemon, Skepd, DEFAULT_WORKERS};

/// Spawn a daemon over `dir` with ONE configured origin — its own loopback
/// port — and `local_trust` as given: `false` flips the board into ENFORCING
/// at the claim, `true` into CLAIMED-PERMISSIVE.
pub fn spawn(dir: &Path, local_trust: bool) -> Skepd {
    const ATTEMPTS: usize = 12;
    for _ in 0..ATTEMPTS {
        let reserved = TcpListener::bind(("127.0.0.1", 0)).expect("reserve an ephemeral port");
        let port = reserved.local_addr().expect("reserved local addr").port();
        let origin = skepd::Origin::parse(&format!("http://127.0.0.1:{port}")).expect("a canonical loopback origin");
        let mut opts = AuthOptions::default();
        opts.local_trust = local_trust;
        opts.configured = vec![origin];
        let daemon = match Daemon::open_with(dir, opts) {
            Ok(d) => d,
            Err(e) => {
                let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
                let mut lock_race = false;
                while let Some(err) = source {
                    if let Some(io) = err.downcast_ref::<std::io::Error>() {
                        lock_race = io.kind() == ErrorKind::WouldBlock;
                        break;
                    }
                    source = err.source();
                }
                if lock_race {
                    drop(reserved);
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                panic!("daemon open at {}: {e}", dir.display());
            }
        };
        drop(reserved);
        match serve(daemon, port, DEFAULT_WORKERS) {
            Ok(sd) => {
                let deadline = Instant::now() + Duration::from_secs(60);
                while !sd.daemon().index_is_ready() {
                    assert!(Instant::now() < deadline, "the cell index's walk did not complete within 60 s");
                    std::thread::sleep(Duration::from_millis(5));
                }
                return sd;
            }
            Err(e) if e.kind() == ErrorKind::AddrInUse => continue,
            Err(e) => panic!("bind the reserved port: {e}"),
        }
    }
    panic!("spawn: lost the rebind race {ATTEMPTS} times running")
}

/// The daemon's own origin.
pub fn origin_of(port: u16) -> Origin {
    Origin::parse(&format!("http://127.0.0.1:{port}")).expect("canonical")
}

/// A board over the plain dialer.
pub fn board(port: u16) -> Board {
    Board::new(origin_of(port), Box::new(PlainHttp::new()))
}

/// THE RECORDING DIALER: every exchange logged as `METHOD path[ op]`, the
/// frame's `op` member appended for a `/op`, so a test can pin the ORDER of
/// what was dialed — the pre-check's reads AHEAD of the `/challenge`.
pub struct Recording {
    inner: PlainHttp,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Dialer for Recording {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        let mut line = format!("{} {}", req.method.as_str(), req.path);
        if req.path == "/op" || req.path == "/op-at" {
            if let Ok(v) = serde_json::from_slice::<Value>(&req.body) {
                let op = v["op"].as_str().or_else(|| v["frame"]["op"].as_str()).unwrap_or("?");
                line.push(' ');
                line.push_str(op);
            }
        }
        self.log.lock().expect("log").push(line);
        self.inner.exchange(origin, req)
    }

    fn stream(&self, origin: &Origin, head: &RequestHead, body: &mut dyn Read, on_interim: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        self.log.lock().expect("log").push(format!("{} {} (stream)", head.method.as_str(), head.path));
        self.inner.stream(origin, head, body, on_interim)
    }
}

/// A board over the recording dialer, and its log.
pub fn recording_board(origin: Origin) -> (Board, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let board = Board::new(origin, Box::new(Recording { inner: PlainHttp::new(), log: log.clone() }));
    (board, log)
}

/// One DEVICE key generated into `store` under `label`.
pub fn keygen(store: &FileStore, label: &str) -> Fingerprint {
    store.generate(Some(Label::new(label).expect("a label in the domain"))).expect("generate").0
}

/// The notebook walk's options: the two anchor destinations under
/// `anchors`, no paper, the display name given so no question is asked.
pub fn opts(anchors: &Path) -> NotebookOptions {
    NotebookOptions {
        principal: None,
        name: Some("a display name".into()),
        anchor_out: vec![anchors.join("a"), anchors.join("b")],
        paper: false,
        host: "testhost".into(),
        date: "2026-10-04".into(),
    }
}

/// The script a plain claim's person needs: the two anchor boxes, answered
/// with their per-run defaults.
pub fn claim_script() -> Vec<Script> {
    vec![Script::LabelDefault, Script::LabelDefault]
}

/// The notebook walk run to its OURS end.
pub fn claim(board: &Board, store: &FileStore, anchors: &Path) -> (Claimed, Scripted) {
    let mut person = Scripted::new(claim_script());
    let outcome = claim::notebook(board, store, &mut person, &opts(anchors)).unwrap_or_else(|h| panic!("the claim halted: {h}\n{}", person.transcript.join("\n")));
    match outcome {
        ClaimOutcome::Ours(done) => (done, person),
        ClaimOutcome::Stranger { claimant } => panic!("a stranger's board: {claimant}"),
    }
}

/// The key files written under `dir`, by name.
pub fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir).map(|rd| rd.filter_map(Result::ok).map(|e| e.path()).collect()).unwrap_or_default();
    v.sort();
    v
}
