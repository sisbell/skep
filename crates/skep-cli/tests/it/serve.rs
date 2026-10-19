//! THE DEV PROVIDER's FENCE: `skep-dev serve` driven through argv against
//! boards the suite spawns in-process, the suite standing in for the page
//! over loopback HTTP with the admission headers. F1 every call of
//! `client.md` §4b.1 and the document index's listing in the bare mode, the
//! keyless session that reads alone — the reads answered, and a draft's
//! mint, an insert and a publish-class write each refused
//! `write_in_bare_session` with the board's position unmoved, the three
//! guest forms, `keygen` and `fingerprint`, `search` and `places`, the
//! ceremonial calls to their first refusal, the stale session and the
//! foreign board, the token in no answer and no event, the log listing
//! every call; F2 the events — `feed` with the board reference and the
//! entry the library wrote and the bare session reads, `index`, `mode` at
//! a claim's landing, `session-died` on `close`
//! and on the daemon's restart with the arm named, `daemon` on the
//! stream's loss; F3 the person over the bridge — a claim on an unclaimed
//! board with every PUBLIC moment arriving as a `moment` event and answered
//! by `/bridge/answer`, the board claimed, and a second run cancelled at
//! the first moment answering the abandonment with the board unclaimed;
//! F4 the admission — a foreign origin, no secret, a wrong host, each 403
//! naming the check with no dial made, each kind said once with its route
//! and counted to the stop, the secret on no line, the preflight for the
//! one origin and never `*`, the listener on 127.0.0.1 alone; F5 the signed
//! mode — a content-scoped session, a publish-class write acked under the
//! attest the provider composed, the same write refused under bare before
//! any dial; F6 the fault doors under `dev-hooks` with `--own` in the
//! signed mode, and `not_built_in` without; F7 the isolation, `cargo tree`
//! naming no `skepd` without the
//! feature and one with it; F8 the declarations served equal to the
//! crate's; F9 the conformance — one sequence on the crate and through the
//! provider, deep-equal results and the same events in order.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::board::Board;
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::dial::PlainHttp;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::Label;
use skep_client::store::{FileStore, KeyStore};
use skep_client::Origin;
use skep_shell::{SessionMode, Shell, ShellOptions};
use skepd::{embed, AuthOptions, MediaOptions, Skepd, DEFAULT_WORKERS};

use crate::common::{origin, s, scrub, spawn};

/// The page origin every provider here is started for.
const PAGE: &str = "http://127.0.0.1:8731";

/// The admission header and the query key, as the provider spells them.
const SECRET_HEADER: &str = "Skep-Provider";
const SECRET_QUERY: &str = "provider";

// ── THE BOARD ──────────────────────────────────────────────────────────────

/// A claimed board through the LIBRARY, as `dev.rs` claims one: the store
/// holds the device key and the account's line.
fn claim_board(board_origin: &str, store: &Path, anchors: &Path) {
    let store = FileStore::open(store);
    store.generate(Some(Label::new("notebook").unwrap())).unwrap();
    claim_with(board_origin, &store, anchors);
}

/// The board at `board_origin` claimed through the LIBRARY under the one key
/// `store` holds already, the account's line appended to it.
fn claim_with(board_origin: &str, store: &FileStore, anchors: &Path) {
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions { principal: None, display_name: Some("a name".into()), anchor_out: vec![anchors.join("a"), anchors.join("b")], paper: false, host_name: "testhost".into(), date: "2026-10-10".into() };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
}

/// A draft of account `1.0.1` holding `hello`, written by the LIBRARY under
/// a bare session of its own as principal 1 — the provider commits no write
/// of a bare session's, which reads alone — for a bare provider's session of
/// that principal to read.
fn library_draft(board_origin: &str) -> String {
    use skep_client::board::{frames, Answer, Opened, SessionBody};
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let Opened::Token(token) = board.session_open(SessionBody::Bare { principal: 1 }).unwrap() else { panic!("a bare session on the permissive board") };
    let written = |frame: &Value| -> Value {
        let Answer::Document(v) = board.op(Some(&token), frame).unwrap() else { panic!("the library's session stands") };
        assert!(v["resp"].as_str().is_some_and(|r| r.starts_with("ack")), "the library's write: {v}");
        v
    };
    let draft = written(&frames::create_document("1.0.1", false, None))["addr"].as_str().unwrap().to_string();
    written(&json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}));
    let _ = board.session_close(&token);
    draft
}

/// A daemon at `port` exactly — the restart's twin of `common::spawn`: the
/// daemon's own start (`skepd::embed`) at that port, the open retried where
/// the stopped daemon's lock has yet to release, then the wait for its cell
/// index.
fn spawn_at(dir: &Path, local_trust: bool, port: u16) -> Skepd {
    let configured = |port: u16| {
        let mut opts = AuthOptions::default();
        opts.local_trust = local_trust;
        opts.configured = vec![skepd::Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap()];
        opts
    };
    let sd = embed(dir, port, configured, MediaOptions::default(), DEFAULT_WORKERS).unwrap_or_else(|e| panic!("the board did not reopen at {port}: {e}"));
    sd.wait_for_the_index(Duration::from_secs(60)).unwrap_or_else(|e| panic!("{e}"));
    sd
}

/// A free loopback port, reserved and released.
fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

// ── THE PROVIDER ───────────────────────────────────────────────────────────

/// A running `skep-dev serve`: the child, its stdin held open, the port,
/// the secret read off stdout, and its TALK collected.
struct Provider {
    child: Child,
    stdin: Option<ChildStdin>,
    port: u16,
    secret: String,
    talk: Arc<Mutex<String>>,
}

impl Provider {
    /// `skep-dev serve` with `args` beside `--page-origin` and `--listen`,
    /// its environment cleared of the settings a developer's shell may hold
    /// ([`scrub`]), waited for until its port answers.
    fn start(args: &[&str]) -> Provider {
        Provider::start_under(args, None)
    }

    /// [`Provider::start`], the process held to `fd_limit` open descriptors
    /// where one is given — `/bin/sh`'s `ulimit -n`, then `exec`, so the
    /// child is the provider itself.
    fn start_under(args: &[&str], fd_limit: Option<u32>) -> Provider {
        for _ in 0..8 {
            let port = free_port();
            let listen = port.to_string();
            let mut cmd = match fd_limit {
                None => Command::new(env!("CARGO_BIN_EXE_skep-dev")),
                Some(n) => {
                    let mut sh = Command::new("/bin/sh");
                    sh.args(["-c", &format!("ulimit -n {n} && exec \"$0\" \"$@\""), env!("CARGO_BIN_EXE_skep-dev")]);
                    sh
                }
            };
            cmd.arg("serve").args(["--page-origin", PAGE, "--listen", &listen]).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            scrub(&mut cmd);
            let mut child = cmd.spawn().expect("spawn skep-dev serve");
            let stdin = child.stdin.take();
            let talk = Arc::new(Mutex::new(String::new()));
            let kept = Arc::clone(&talk);
            let stderr = child.stderr.take().unwrap();
            thread::spawn(move || {
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                while let Ok(n @ 1..) = reader.read_line(&mut line) {
                    let _ = n;
                    kept.lock().unwrap().push_str(&line);
                    line.clear();
                }
            });
            let mut stdout = BufReader::new(child.stdout.take().unwrap());
            let mut secret = String::new();
            let _ = stdout.read_line(&mut secret);
            let secret = secret.trim().to_string();
            if secret.is_empty() {
                // The verb stopped before serving: its code and its talk.
                let status = child.wait().unwrap();
                let said = talk.lock().unwrap().clone();
                if said.contains("could not be bound") {
                    continue;
                }
                panic!("skep-dev serve stopped before serving (exit {status}):\n{said}");
            }
            let provider = Provider { child, stdin, port, secret, talk };
            let deadline = Instant::now() + Duration::from_secs(30);
            while provider.get("/bridge/log").0 != 200 {
                assert!(Instant::now() < deadline, "the provider's port did not answer:\n{}", provider.talk());
                thread::sleep(Duration::from_millis(20));
            }
            return provider;
        }
        panic!("the provider lost the port race eight times")
    }

    fn talk(&self) -> String {
        self.talk.lock().unwrap().clone()
    }

    fn headers(&self) -> Vec<(String, String)> {
        vec![("Origin".into(), PAGE.into()), (SECRET_HEADER.into(), self.secret.clone())]
    }

    /// One raw request to the provider: the status, the headers, the body.
    fn request(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
        request_at(self.port, method, path, headers, body, true)
    }

    fn get(&self, path: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
        self.request("GET", path, &self.headers(), b"")
    }

    /// `POST /bridge/<call>` with the admission headers: the answer object.
    fn call(&self, name: &str, args: Value) -> Value {
        let (status, _, body) = self.request("POST", &format!("/bridge/{name}"), &self.headers(), args.to_string().as_bytes());
        assert_eq!(status, 200, "{name}: {}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap_or_else(|e| panic!("{name}: not JSON ({e}): {}", String::from_utf8_lossy(&body)))
    }

    /// The call's result, or a panic naming the refusal.
    fn result(&self, name: &str, args: Value) -> Value {
        let answer = self.call(name, args);
        assert!(answer.get("result").is_some(), "{name} refused: {answer}\n{}", self.talk());
        answer["result"].clone()
    }

    /// The call's refusal name, or a panic naming the result.
    fn refused(&self, name: &str, args: Value) -> Value {
        let answer = self.call(name, args);
        assert!(answer.get("refused").is_some(), "{name} answered a result: {answer}");
        answer["refused"].clone()
    }

    /// The event stream opened, every event parsed on a thread.
    fn events(&self) -> Receiver<(String, Value)> {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        let head = format!("GET /bridge/events?{SECRET_QUERY}={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: {PAGE}\r\nAccept: text/event-stream\r\n\r\n", self.secret, self.port);
        stream.write_all(head.as_bytes()).unwrap();
        let (tx, rx) = channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            let mut in_head = true;
            let mut event = String::new();
            while let Ok(n @ 1..) = reader.read_line(&mut line) {
                let _ = n;
                let text = line.trim_end_matches(['\r', '\n']).to_string();
                line.clear();
                if in_head {
                    if text.is_empty() {
                        in_head = false;
                    }
                    continue;
                }
                if let Some(name) = text.strip_prefix("event:") {
                    event = name.trim().to_string();
                } else if let Some(data) = text.strip_prefix("data:") {
                    let v: Value = serde_json::from_str(data.trim()).unwrap_or(Value::Null);
                    if tx.send((event.clone(), v)).is_err() {
                        return;
                    }
                } else if text.is_empty() {
                    event.clear();
                }
            }
        });
        rx
    }

    /// The clean stop: stdin closed, the exit code.
    fn stop(mut self) -> i32 {
        drop(self.stdin.take());
        let status = self.child.wait().unwrap();
        status.code().unwrap_or(-1)
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One raw HTTP request to `port`: the status, the headers, the body.
fn request_at(port: u16, method: &str, path: &str, headers: &[(String, String)], body: &[u8], with_host: bool) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    if with_host && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Host")) {
        head.push_str(&format!("Host: 127.0.0.1:{port}\r\n"));
    }
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let _ = stream.shutdown(Shutdown::Write);
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap_or_else(|e| panic!("{method} {path}: the answer did not arrive: {e}; body {}", String::from_utf8_lossy(body)));
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a head");
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let mut lines = head.lines();
    let status: u16 = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
    (status, headers, raw[head_end + 4..].to_vec())
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// The crate's README names every fault door the provider's refusal lists
/// after `lead` — the doors' one list, `serve/node.rs`'s `DOORS`, as the
/// binary itself says it — so the README a developer reads them from never
/// runs short of the build.
fn readme_names_every_door(detail: &str, lead: &str) {
    let (_, list) = detail.split_once(lead).unwrap_or_else(|| panic!("the refusal lists the doors after `{lead}`: {detail}"));
    let doors: Vec<&str> = list.split(", ").map(str::trim).collect();
    assert!(doors.len() > 1 && doors.contains(&"poison"), "the list read whole: {doors:?}");
    let readme = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md")).expect("the crate's README");
    for door in doors {
        assert!(readme.contains(&format!("`{door}`")), "README.md names the fault door `{door}`");
    }
}

/// The provider's talk once it holds every one of `needles`, within the
/// deadline: its stderr reader trails the answer that a line preceded.
fn talk_holding(provider: &Provider, needles: &[&str]) -> String {
    said_holding(&provider.talk, needles)
}

/// [`talk_holding`] over the talk a provider kept — read on past its stop,
/// whose last lines its stderr reader trails.
fn said_holding(talk: &Arc<Mutex<String>>, needles: &[&str]) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let said = talk.lock().unwrap().clone();
        if needles.iter().all(|n| said.contains(n)) {
            return said;
        }
        assert!(Instant::now() < deadline, "the provider never said all of {needles:?}:\n{said}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// The next event named `name` meeting `pred`, within the deadline.
fn next_event(rx: &Receiver<(String, Value)>, name: &str, pred: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "no `{name}` event arrived; seen {seen:?}");
        match rx.recv_timeout(left) {
            Ok((n, v)) => {
                if n == name && pred(&v) {
                    return v;
                }
                seen.push(n);
            }
            Err(e) => panic!("the stream ended ({e}); seen {seen:?}"),
        }
    }
}

/// A ceremonial call run to its FIRST refusal or its FIRST moment: the call
/// on a thread, the first answerable moment cancelled, the refusal the call
/// then answers — `abandoned` where a moment was reached, the walk's own
/// refusal where it stopped before one.
fn first_refusal(provider: &Arc<Provider>, rx: &Receiver<(String, Value)>, call: &'static str, args: Value) -> Value {
    let p = Arc::clone(provider);
    let walk = thread::spawn(move || p.call(call, args));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if walk.is_finished() {
            let answer = walk.join().unwrap();
            assert!(answer.get("refused").is_some(), "{call} answered a result: {answer}");
            return answer["refused"].clone();
        }
        assert!(Instant::now() < deadline, "{call} neither refused nor asked within the deadline:\n{}", provider.talk());
        if let Ok((name, v)) = rx.recv_timeout(Duration::from_millis(50)) {
            if name == "moment" && v["answerable"] == true {
                assert_eq!(v["walk"], call);
                provider.result("cancel", json!({"id": v["id"]}));
            }
        }
    }
}

/// Whether `text` holds a 32-lowercase-hex run that is no part of a longer
/// one — the shape of a session token.
fn holds_a_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    let hexish = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    let mut i = 0;
    while i < bytes.len() {
        if hexish(bytes[i]) {
            let start = i;
            while i < bytes.len() && hexish(bytes[i]) {
                i += 1;
            }
            if i - start == 32 {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

/// A provider over a claimed board, bare as principal 1, its own store.
fn bare_provider(dir: &Path) -> (Skepd, Provider) {
    let sd = spawn(&dir.join("board"), true);
    let board = origin(sd.port());
    claim_board(&board, &dir.join("claimant"), &dir.join("anchors"));
    let store = dir.join("provider-store");
    let provider = Provider::start(&["--board", &board, "--session", "bare", "--principal", "1", "--dir", s(&store)]);
    (sd, provider)
}

// ── F1 ─────────────────────────────────────────────────────────────────────

/// F1: every call over HTTP in the bare mode.
#[test]
fn f1_every_call_over_http_in_the_bare_mode() {
    let dir = tempfile::tempdir().unwrap();
    let (sd, provider) = bare_provider(dir.path());
    let provider = Arc::new(provider);
    let rx = provider.events();
    let mut answers: Vec<Value> = Vec::new();
    let mut keep = |v: Value| -> Value {
        answers.push(v.clone());
        v
    };
    // boards, health, probe.
    let boards = keep(provider.result("boards", json!({})));
    let board = boards[0]["board"].as_str().unwrap().to_string();
    assert!(board.starts_with("b-"));
    assert_eq!(boards[0]["origin"], origin(sd.port()));
    // The board's line names it by its origin and by the reference the
    // shell's own lines name it by, so the two join.
    talk_holding(&provider, &[&format!("board {} (reference {board}): mode CLAIMED-PERMISSIVE (claimant 1.0.1", origin(sd.port()))]);
    let health = keep(provider.result("health", json!({"board": board})));
    assert_eq!(health["mode"], "CLAIMED-PERMISSIVE");
    let probe = keep(provider.result("probe", json!({})));
    assert_eq!(probe["daemon"], "running");
    // session, a read, and every write refused before any dial: the bare
    // session is the keyless session, which reads alone.
    let opened = keep(provider.result("session", json!({"board": board, "principal": 1})));
    let session = opened["session"].as_str().unwrap().to_string();
    assert!(session.starts_with("s-"));
    assert_eq!(opened["account"], "1.0.1");
    let set = keep(provider.result("op", json!({"session": session, "frame": {"op": "key_set", "account": "1.0.1"}})));
    assert_eq!(set["resp"], "key_set");
    let draft = library_draft(&origin(sd.port()));
    let position = || provider.result("health", json!({"board": board}))["health"]["log_position"].as_u64().unwrap();
    let before = position();
    for frame in [
        json!({"op": "create_new_document", "account": "1.0.1"}),
        json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}),
        json!({"op": "create_new_document", "account": "1.0.1", "published": true}),
    ] {
        let refused = keep(provider.refused("op", json!({"session": session, "frame": frame})));
        assert_eq!((refused["name"].as_str(), refused["kind"].as_str(), refused["op"].as_str()), (Some("write_in_bare_session"), Some("shell"), frame["op"].as_str()), "{refused}");
    }
    assert_eq!(position(), before, "the refused writes committed nothing");
    // The op-at form.
    let at = health["health"]["log_position"].as_u64().unwrap();
    let at_answer = keep(provider.result("op", json!({"session": session, "frame": {"at": at, "frame": {"op": "key_set", "account": "1.0.1"}}})));
    assert_eq!(at_answer["resp"], "key_set");
    // The three guest forms: by reference, by origin, and a write refused.
    let by_ref = keep(provider.result("op", json!({"guest": true, "board": board, "frame": {"op": "key_set", "account": "1.0.1"}})));
    assert_eq!(by_ref["resp"], "key_set");
    let by_origin = keep(provider.result("op", json!({"guest": true, "origin": origin(sd.port()), "frame": {"op": "principal_prefix", "principal": 1}})));
    assert_eq!(by_origin["addr"], "1.0.1");
    let guest_write = keep(provider.refused("op", json!({"guest": true, "board": board, "frame": {"op": "create_new_document", "account": "1.0.1"}})));
    assert_eq!(guest_write["name"], "write_in_guest_form");
    let withheld = keep(provider.refused("op", json!({"guest": true, "board": board, "frame": {"op": "doc_metadata", "doc": draft}})));
    assert_eq!(withheld["name"], "withheld");
    // The claim on a claimed board from a keyless store: `no_key` first.
    assert_eq!(keep(provider.refused("claim", json!({"board": board})))["name"], "no_key", "the provider's store is keyless for this board");
    // keygen and fingerprint.
    let keygen = keep(provider.result("keygen", json!({"label": "phone"})));
    assert_eq!(keygen["fingerprint"].as_str().unwrap().len(), 64);
    assert!(keygen["payload"].as_str().unwrap().contains("mldsa65-ed25519"));
    let rows = keep(provider.result("fingerprint", json!({"payload": true})));
    assert_eq!(rows[0]["unbound"], true);
    assert_eq!(rows[0]["label"], "phone");
    assert_eq!(keep(provider.refused("fingerprint", json!({"select": "zz"})))["name"], "not_found");
    assert_eq!(keep(provider.refused("keygen", json!({"label": ""})))["name"], "empty_label");
    // search: the session form and the guest form.
    let found = keep(provider.result("search", json!({"session": session, "board": board, "query": "hello", "opts": {"limit": 3}})));
    assert!(found["state"]["arm"].is_string());
    let guest_search = keep(provider.result("search", json!({"guest": true, "board": board, "query": "hello"})));
    assert!(guest_search["hits"].is_array());
    assert_eq!(keep(provider.refused("search", json!({"session": session, "query": "x".repeat(1025)})))["name"], "query_too_long");
    // places, the document index's listing: the session form and the guest
    // form under the claimant's account, which lists no draft.
    let listed = keep(provider.result("places", json!({"session": session})));
    assert!(listed["docs"].is_array() && listed["counts"].is_array() && listed["state"]["arm"].is_string(), "{listed}");
    let guest_listed = keep(provider.result("places", json!({"guest": true, "board": board, "opts": {"under": "1.0.1"}})));
    assert!(guest_listed["docs"].as_array().unwrap().iter().all(|p| p["kind"] == "edition"), "{guest_listed}");
    let not_an_address = keep(provider.refused("places", json!({"guest": true, "board": board, "opts": {"under": "not an address"}})));
    assert_eq!((not_an_address["name"].as_str(), not_an_address["what"].as_str()), (Some("malformed_args"), Some("opts.under")), "{not_an_address}");
    // changes, the change feed's page at the session's class: `entries`,
    // `next` and `head` — the library's draft rows under the claimant's own
    // class ride it as `drafts` under the session, the claim's rows as
    // `published`, each with its position; a `since` of another form
    // refused by name.
    let caught_up = keep(provider.result("changes", json!({"session": session, "since": 0})));
    let members: std::collections::BTreeSet<&str> = caught_up.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(members, ["entries", "head", "next"].into(), "{caught_up}");
    let entries = caught_up["entries"].as_array().unwrap();
    assert!(entries.iter().all(|e| e["position"] == e["at"] && e["at"].is_u64() && (e["class"] == "published" || e["class"] == "drafts")), "{caught_up}");
    assert!(entries.iter().any(|e| e["class"] == "drafts" && e["docs"][0] == draft && e["session"] == session), "the draft's rows at the session's class: {caught_up}");
    assert!(entries.iter().any(|e| e["class"] == "published" && e.get("session").is_none()), "the claim's published rows: {caught_up}");
    assert!(caught_up["next"].as_u64().unwrap() >= entries.last().unwrap()["at"].as_u64().unwrap() && caught_up["head"].is_u64(), "{caught_up}");
    let since_of_no_form = keep(provider.refused("changes", json!({"session": session, "since": "x"})));
    assert_eq!((since_of_no_form["name"].as_str(), since_of_no_form["what"].as_str()), (Some("malformed_args"), Some("since")), "{since_of_no_form}");
    // held and resolve: no burst is held on this up board, so `held` is empty
    // and `resolve` of an ordinal that does not stand is `no_such_held`.
    assert_eq!(keep(provider.result("held", json!({"session": session}))), json!([]));
    assert_eq!(keep(provider.refused("resolve", json!({"session": session, "held": 1, "act": "drop"})))["name"], "no_such_held");
    // The ceremonial calls, each to its first refusal or its first moment:
    // the claim on a board another store claimed.
    let claimed_by_another = keep(first_refusal(&provider, &rx, "claim", json!({"board": board})));
    assert_eq!(claimed_by_another["name"], "already_claimed", "{claimed_by_another}");
    assert_eq!(claimed_by_another["claimant"], "1.0.1");
    let enroll = keep(first_refusal(&provider, &rx, "enroll", json!({"board": board, "payload": "not a record"})));
    assert!(enroll["kind"].is_string(), "{enroll}");
    let bind = keep(provider.refused("bind", json!({"board": board, "principal": 1, "account": "1.0.9", "origin": origin(sd.port())})));
    assert_eq!(bind["name"], "account_disagrees", "{bind}");
    let mut reached: Vec<(&str, String)> = Vec::new();
    for (call, args) in [
        ("recover", json!({"board": board, "principal": 1, "lost": [], "stolen": false})),
        ("rotate", json!({"board": board, "principal": 1})),
        ("retire", json!({"board": board, "principal": 1, "fingerprint": "ab"})),
        ("handoff", json!({"board": board, "account": "1.0.1.2"})),
        ("accept", json!({"board": board, "address": "1.0.1.2"})),
    ] {
        let r = keep(first_refusal(&provider, &rx, call, args));
        assert!(r["name"].is_string(), "{call}: {r}");
        reached.push((call, r["name"].as_str().unwrap().to_string()));
    }
    assert!(reached.iter().any(|(_, name)| name == "abandoned"), "at least one walk reached a PUBLIC moment the page cancelled: {reached:?}");
    assert_eq!(keep(provider.refused("accept", json!({"board": board})))["name"], "no_address");
    // The media rows: where the library stops.
    assert_eq!(keep(provider.refused("upload", json!({"session": session, "target": draft, "path": "/tmp/x.png"})))["name"], "not_reached");
    assert_eq!(keep(provider.refused("restore", json!({"session": session, "i": "1.0.1.0.1.0.1.1"})))["name"], "not_reached");
    let (status, _, body) = provider.request("POST", "/bridge/fetch", &provider.headers(), json!({"guest": true, "board": board, "i": "1.0.1.0.1.0.1.1"}).to_string().as_bytes());
    assert_eq!(status, 200);
    let fetch: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(fetch["refused"]["kind"], "refused", "the daemon's own refusal of a cell that is none: {fetch}");
    // A stale session reference, a foreign board reference.
    assert_eq!(keep(provider.result("close", json!({"session": session}))), json!({}));
    assert_eq!(keep(provider.refused("op", json!({"session": session, "frame": {"op": "key_set", "account": "1.0.1"}})))["name"], "session_ended");
    assert_eq!(keep(provider.refused("close", json!({"session": session})))["name"], "session_ended");
    assert_eq!(keep(provider.refused("health", json!({"board": "b-000000000000000000000000"})))["name"], "unknown_board");
    assert_eq!(keep(provider.refused("session", json!({"board": session, "principal": 1})))["name"], "unknown_board", "a session reference is no board reference");
    // An unknown call is the provider's own 404.
    let (status, _, _) = provider.request("POST", "/bridge/verify", &provider.headers(), b"{}");
    assert_eq!(status, 404);
    // The token's text in no answer.
    for a in &answers {
        assert!(!holds_a_token(&a.to_string()), "a token-shaped run in an answer: {a}");
    }
    // The log lists every call made.
    let (status, _, body) = provider.get("/bridge/log");
    assert_eq!(status, 200);
    let log: Value = serde_json::from_slice(&body).unwrap();
    let calls: Vec<&str> = log.as_array().unwrap().iter().filter(|e| e["kind"] == "call").filter_map(|e| e["call"].as_str()).collect();
    for name in [
        "boards",
        "health",
        "probe",
        "session",
        "op",
        "keygen",
        "fingerprint",
        "search",
        "places",
        "changes",
        "claim",
        "enroll",
        "bind",
        "recover",
        "rotate",
        "retire",
        "handoff",
        "accept",
        "upload",
        "restore",
        "fetch",
        "close",
    ] {
        assert!(calls.contains(&name), "the log lists {name}: {calls:?}");
    }
    assert!(log.as_array().unwrap().iter().any(|e| e["kind"] == "dial" && e["path"] == "/op"), "the dials are logged");
    assert!(!holds_a_token(&body.iter().map(|b| *b as char).collect::<String>()), "no token in the log");
    // The token's text in no event.
    for (name, v) in rx.try_iter() {
        assert!(!holds_a_token(&v.to_string()), "a token-shaped run in the `{name}` event: {v}");
    }
    drop(rx);
    assert_eq!(Arc::try_unwrap(provider).ok().expect("the one holder").stop(), 0, "a clean stop");
    sd.shutdown();
}

// ── F2 ─────────────────────────────────────────────────────────────────────

/// F2: the events over the stream.
#[test]
fn f2_the_events_arrive_on_the_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (sd, provider) = bare_provider(dir.path());
    let port = sd.port();
    let rx = provider.events();
    let board = provider.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    let session = provider.result("session", json!({"board": board, "principal": 1}))["session"].as_str().unwrap().to_string();
    let draft = library_draft(&origin(port));
    // `feed` with the board reference and the entry — the draft's insert,
    // which the library wrote under a bare session of the principal's own,
    // rides the session's drafts supplement.
    let feed = next_event(&rx, "feed", |v| v["update"]["op"] == "insert" && v["update"]["docs"][0] == draft);
    assert_eq!(feed["board"], board);
    assert_eq!(feed["update"]["position"], feed["update"]["at"]);
    assert_eq!(feed["update"]["class"], "drafts");
    assert_eq!(feed["update"]["session"], session);
    assert_eq!(feed["update"]["key"], "bare");
    // `index` as the consumer mounts.
    let index = next_event(&rx, "index", |v| v["board"] == board);
    assert!(index["state"]["arm"].is_string());
    // `session-died` on close, the arm named.
    provider.result("close", json!({"session": session}));
    let died = next_event(&rx, "session-died", |v| v["session"] == session);
    assert_eq!(died["reason"]["arm"], "closed");
    // The daemon's restart at the same port: the stream's loss is said as
    // `daemon`, a session opened before dies with the restart arm named.
    let session2 = provider.result("session", json!({"board": board, "principal": 1}))["session"].as_str().unwrap().to_string();
    sd.shutdown();
    let unreachable = next_event(&rx, "daemon", |v| v["state"] == "unreachable");
    assert_eq!(unreachable["board"], board);
    let sd = spawn_at(&dir.path().join("board"), true, port);
    next_event(&rx, "daemon", |v| v["state"] == "running");
    let refused = provider.refused("op", json!({"session": session2, "frame": {"op": "key_set", "account": "1.0.1"}}));
    assert_eq!(refused["name"], "session_died", "{refused}");
    assert_eq!(refused["reason"]["arm"], "restart");
    let died = next_event(&rx, "session-died", |v| v["session"] == session2);
    assert_eq!(died["reason"]["arm"], "restart");
    assert_eq!(provider.refused("op", json!({"session": session2, "frame": {"op": "key_set", "account": "1.0.1"}}))["name"], "session_ended");
    // `mode` at a claim's landing: a second, unclaimed daemon served by a
    // second provider, claimed through the library while the suite listens.
    let sd2 = spawn(&dir.path().join("board2"), true);
    let provider2 = Provider::start(&["--board", &origin(sd2.port()), "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("store2"))]);
    let rx2 = provider2.events();
    let board2 = provider2.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    assert_eq!(provider2.result("health", json!({"board": board2}))["mode"], "UNCLAIMED");
    claim_board(&origin(sd2.port()), &dir.path().join("claimant2"), &dir.path().join("anchors2"));
    let mode = next_event(&rx2, "mode", |v| v["board"] == board2);
    assert_eq!(mode["mode"], "CLAIMED-PERMISSIVE");
    assert_eq!(mode["claimant"], "1.0.1");
    assert_eq!(provider2.stop(), 0);
    assert_eq!(provider.stop(), 0);
    sd.shutdown();
    sd2.shutdown();
}

// ── F3 ─────────────────────────────────────────────────────────────────────

/// F3: the person over the bridge — the claim's PUBLIC moments as events,
/// answered by the page; a cancel at the first moment.
#[test]
fn f3_the_person_over_the_bridge_claims_and_a_cancel_abandons() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let script = dir.path().join("script.txt");
    let (a, b) = (dir.path().join("anchor-a"), dir.path().join("anchor-b"));
    std::fs::write(&script, format!("# the anchors' two directories, then the re-types off the sheets shown, in order\ndestination {}\ndestination {}\nretype sheet 0\nretype sheet 1\n", a.display(), b.display())).unwrap();
    let provider = Provider::start(&["--board", &origin(sd.port()), "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("store")), "--script", s(&script)]);
    let rx = provider.events();
    let board = provider.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    provider.result("keygen", json!({"label": "notebook"}));
    let provider = Arc::new(provider);
    let (p, b) = (Arc::clone(&provider), board.clone());
    let walk = thread::spawn(move || p.call("claim", json!({"board": b, "name": "a name", "paper": true})));
    let mut moments: Vec<Value> = Vec::new();
    let claimed = loop {
        if walk.is_finished() {
            break walk.join().unwrap();
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((name, v)) if name == "moment" => {
                assert!(v["id"].as_str().unwrap().starts_with("m-"));
                assert_eq!(v["walk"], "claim");
                assert_eq!(v["board"], board);
                if v["answerable"] == true {
                    let answer = match v["kind"].as_str() {
                        Some("label") => v["data"]["default"].clone(),
                        Some("yes_no") => Value::from(true),
                        _ => Value::from("yes"),
                    };
                    let id = v["id"].as_str().unwrap();
                    assert_eq!(provider.result("answer", json!({"id": id, "value": answer})), json!({}));
                    assert_eq!(provider.refused("answer", json!({"id": id, "value": answer}))["name"], "no_such_moment", "answered once");
                }
                moments.push(v);
            }
            _ => {}
        }
    };
    assert!(claimed.get("result").is_some(), "the walk completed: {claimed}\n{}", provider.talk());
    assert_eq!(claimed["result"]["account"], "1.0.1");
    assert_eq!(provider.result("health", json!({"board": board}))["mode"], "CLAIMED-PERMISSIVE");
    let kinds: Vec<&str> = moments.iter().filter_map(|m| m["kind"].as_str()).collect();
    assert!(kinds.contains(&"statement") && kinds.contains(&"label"), "{kinds:?}");
    assert!(moments.iter().filter(|m| m["kind"] == "label").count() >= 2, "the two anchor boxes");
    let said = provider.talk();
    assert!(
        said.contains(&format!(
            "the dev arm answers the SECRET and CONSENT moments from the script {}: 4 answers read at start, in order — an edit to the file takes a restart",
            script.display()
        )),
        "the script's start line names the file, its answers and when it is read:\n{said}"
    );
    assert!(said.contains("dev arm: the sheet for fingerprint"), "the SECRET sheet went to the dev arm:\n{said}");
    assert!(said.contains(&format!("anchor 0 is placed under {}", a.display())), "the script placed the anchor:\n{said}");
    assert!(said.contains("the re-type is typed off sheet 0"), "the script answered the re-type:\n{said}");
    assert!(!said.contains("seed_grouped") && moments.iter().all(|m| !m.to_string().contains("seed")), "no seed crossed");
    // The second run: cancelled at the first answerable moment.
    let sd2 = spawn(&dir.path().join("board2"), true);
    let provider2 = Provider::start(&["--board", &origin(sd2.port()), "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("store2"))]);
    let rx2 = provider2.events();
    let board2 = provider2.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    provider2.result("keygen", json!({"label": "notebook"}));
    let provider2 = Arc::new(provider2);
    let (p, b) = (Arc::clone(&provider2), board2.clone());
    let walk = thread::spawn(move || p.call("claim", json!({"board": b})));
    let first = next_event(&rx2, "moment", |v| v["answerable"] == true);
    assert_eq!(provider2.result("cancel", json!({"id": first["id"]})), json!({}));
    let abandoned = walk.join().unwrap();
    assert_eq!(abandoned["refused"]["name"], "abandoned", "{abandoned}");
    assert_eq!(provider2.result("health", json!({"board": board2}))["health"]["auth"]["claimant"], Value::Null, "the board stays unclaimed");
    drop(rx2);
    assert_eq!(Arc::try_unwrap(provider2).ok().expect("the one holder").stop(), 0);
    assert_eq!(Arc::try_unwrap(provider).ok().expect("the one holder").stop(), 0);
    sd.shutdown();
    sd2.shutdown();
}

/// A MOMENT PENDING AT THE STOP IS CANCELLED, AND THE STOP COMPLETES: stdin
/// closed while a `claim` waits on a moment the page has not answered — a
/// tab closed mid-walk — the provider's clean stop cancels the moment before
/// it joins the call's connection, so the call answers `abandoned` and the
/// provider exits 0, its stop said from its cause to its seconds; never a
/// stop parked behind the moment, with an interrupt, which skips the clean
/// stop, the one way out.
#[test]
fn a_moment_pending_at_the_stop_is_cancelled_and_the_stop_completes() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let mut provider = Provider::start(&["--board", &origin(sd.port()), "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("store"))]);
    let stdin = provider.stdin.take().expect("the provider's stdin, held open");
    let rx = provider.events();
    let board = provider.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    provider.result("keygen", json!({"label": "notebook"}));
    let talk = Arc::clone(&provider.talk);
    let provider = Arc::new(provider);
    let p = Arc::clone(&provider);
    let walk = thread::spawn(move || p.call("claim", json!({"board": board})));
    next_event(&rx, "moment", |v| v["answerable"] == true);
    drop(stdin);
    let answer = walk.join().expect("the call answered, never left waiting on the moment");
    assert_eq!(answer["refused"]["name"], "abandoned", "{answer}");
    let mut provider = Arc::try_unwrap(provider).ok().expect("the one holder");
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = provider.child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the provider never stopped:\n{}", provider.talk());
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(0), "{}", provider.talk());
    said_holding(&talk, &["stopping (stdin closed)", "stopped: the shell's stop took "]);
    drop(rx);
    sd.shutdown();
}

/// A BOARD WHOSE WRITES ARE HALTED IS SAID SO AT THE PROVIDER'S START
/// (wire.md §Rejection codes, `poisoned`): the daemon's durability barrier
/// and the truncation that would repair it both armed to fail, one bare
/// write halts its kernel; a provider started over that board says on its
/// board line that every write the page makes is refused `poisoned` until
/// the board restarts — where the mode alone reads a claimed board serving.
#[test]
fn a_provider_over_a_halted_board_says_so_at_its_start() {
    use skep_client::board::{Answer, Opened, SessionBody};
    use skepd::Step;
    use std::io::ErrorKind;

    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let board_origin = origin(sd.port());
    claim_board(&board_origin, &dir.path().join("claimant"), &dir.path().join("anchors"));
    let board = Board::new(Origin::parse(&board_origin).unwrap(), PlainHttp::new());
    let Opened::Token(token) = board.session_open(SessionBody::Bare { principal: 1 }).unwrap() else { panic!("a bare session on the permissive board") };
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalBarrier, ErrorKind::StorageFull);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalRepair, ErrorKind::StorageFull);
    let Answer::Document(v) = board.op(Some(&token), &json!({"op": "create_new_document", "account": "1.0.1"})).unwrap() else { panic!("an answer, not the death signal") };
    assert_eq!(v["code"], "poisoned", "the kernel halted: {v}");
    let provider = Provider::start(&["--board", &board_origin, "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("store"))]);
    talk_holding(&provider, &[&format!("board {board_origin} (reference "), "; writes HALTED: every write is refused `poisoned` until the board restarts"]);
    assert_eq!(provider.stop(), 0);
    sd.shutdown();
}

// ── F4 ─────────────────────────────────────────────────────────────────────

/// F4: the admission.
#[test]
fn f4_the_admission_refuses_before_any_dial() {
    let dir = tempfile::tempdir().unwrap();
    let (sd, provider) = bare_provider(dir.path());
    let board = origin(sd.port());
    let daemon = Board::new(Origin::parse(&board).unwrap(), PlainHttp::new());
    let position = || daemon.health().unwrap().log_position();
    let calls = || {
        let (_, _, body) = provider.get("/bridge/log");
        serde_json::from_slice::<Value>(&body).unwrap().as_array().unwrap().iter().filter(|e| e["kind"] == "call").count()
    };
    let (before, calls_before) = (position(), calls());
    let body = json!({"frame": {"op": "create_new_document", "account": "1.0.1"}, "guest": true, "board": "b-x"}).to_string();
    // A foreign origin.
    let (status, headers, text) = provider.request("POST", "/bridge/boards", &[("Origin".into(), "http://evil.example".into()), (SECRET_HEADER.into(), provider.secret.clone())], body.as_bytes());
    assert_eq!(status, 403);
    assert!(String::from_utf8_lossy(&text).contains("origin"), "{}", String::from_utf8_lossy(&text));
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some(PAGE), "never `*`");
    // No origin at all.
    let (status, _, text) = provider.request("POST", "/bridge/boards", &[(SECRET_HEADER.into(), provider.secret.clone())], body.as_bytes());
    assert_eq!(status, 403);
    assert!(String::from_utf8_lossy(&text).contains("origin"));
    // No secret, and a wrong secret.
    let (status, _, text) = provider.request("POST", "/bridge/boards", &[("Origin".into(), PAGE.into())], body.as_bytes());
    assert_eq!(status, 403);
    assert!(String::from_utf8_lossy(&text).contains("secret"), "{}", String::from_utf8_lossy(&text));
    let (status, _, _) = provider.request("POST", "/bridge/boards", &[("Origin".into(), PAGE.into()), (SECRET_HEADER.into(), "0000".into())], body.as_bytes());
    assert_eq!(status, 403);
    // A wrong host.
    let (status, _, text) = provider.request("POST", "/bridge/boards", &[("Host".into(), "evil.example:80".into()), ("Origin".into(), PAGE.into()), (SECRET_HEADER.into(), provider.secret.clone())], body.as_bytes());
    assert_eq!(status, 403);
    assert!(String::from_utf8_lossy(&text).contains("host"), "{}", String::from_utf8_lossy(&text));
    // The event stream is admitted the same way: no secret in the query.
    let (status, _, _) = provider.request("GET", "/bridge/events", &[("Origin".into(), PAGE.into())], b"");
    assert_eq!(status, 403);
    // No dial was made: the daemon's position and the provider's calls.
    assert_eq!((position(), calls()), (before, calls_before), "a refused request made no call and committed nothing");
    // The preflight: the one origin, never `*`; a foreign one refused.
    let (status, headers, _) = provider.request("OPTIONS", "/bridge/boards", &[("Origin".into(), PAGE.into()), ("Access-Control-Request-Method".into(), "POST".into())], b"");
    assert_eq!(status, 204);
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some(PAGE));
    assert!(header(&headers, "Access-Control-Allow-Headers").unwrap().contains(SECRET_HEADER));
    assert!(headers.iter().all(|(_, v)| v != "*"), "{headers:?}");
    let (status, _, _) = provider.request("OPTIONS", "/bridge/boards", &[("Origin".into(), "http://evil.example".into())], b"");
    assert_eq!(status, 403);
    // Each refusal kind is said on the provider's stream once, the first
    // met naming what it presented — the origin a browser hides from the
    // page as a CORS failure, the host — and the route it was met at; and the
    // secret never, presented or this run's.
    let said = talk_holding(&provider, &["is refused (origin)", "is refused (secret)", "is refused (host)"]);
    for (kind, times) in [("is refused (origin)", 1), ("is refused (secret)", 1), ("is refused (host)", 1)] {
        assert_eq!(said.matches(kind).count(), times, "`{kind}` said once: {said}");
    }
    assert!(said.contains(&format!("a request from Origin `http://evil.example` is refused (origin) — this provider admits {PAGE} alone (--page-origin)")), "{said}");
    assert!(said.contains(&format!("a request naming Host `evil.example:80` is refused (host) — the page reaches this provider as http://127.0.0.1:{}", provider.port)), "{said}");
    assert!(said.contains("CORS failure; first met at POST /bridge/boards; said once, every one counted at the stop"), "the route the first was met at: {said}");
    assert!(!said.contains("`0000`"), "the presented secret is never said: {said}");
    assert!(!said.contains(&provider.secret), "this run's secret is never said: its one carrier is stdout: {said}");
    // The listener is bound to 127.0.0.1 alone: this machine's non-loopback
    // address refuses the connect.
    let host = std::process::Command::new("hostname").output().ok().and_then(|o| String::from_utf8(o.stdout).ok()).unwrap_or_default();
    let foreign: Vec<_> = (host.trim(), provider.port).to_socket_addrs().map(|a| a.filter(|a| !a.ip().is_loopback() && a.is_ipv4()).collect()).unwrap_or_default();
    for addr in foreign {
        assert!(TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_err(), "{addr} must not reach the provider");
    }
    // The admitted request, for contrast, answers.
    let (status, _, _) = provider.request("POST", "/bridge/boards", &provider.headers(), b"{}");
    assert_eq!(status, 200);
    // The stop says how many each kind of refusal came to — the page
    // refused three times by its origin read apart from the host refused
    // once — the connections the run accepted, and when its stop completed.
    let (talk, secret) = (Arc::clone(&provider.talk), provider.secret.clone());
    assert_eq!(provider.stop(), 0);
    let said = said_holding(
        &talk,
        &["the provider refused 7 requests over the run: host 1, origin 3, secret 3", "connections accepted", "stopped: the shell's stop took "],
    );
    assert!(!said.contains(&secret), "this run's secret is never said: {said}");
    sd.shutdown();
}

// ── F5 ─────────────────────────────────────────────────────────────────────

/// F5: the signed mode composes the attest a publish-class write needs.
#[test]
fn f5_the_signed_mode_acks_a_publish_class_write() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let board_origin = origin(sd.port());
    let store = dir.path().join("claimant");
    claim_board(&board_origin, &store, &dir.path().join("anchors"));
    // The signed mode over the store that holds the claimant's dev key.
    let signed = Provider::start(&["--board", &board_origin, "--session", "signed", "--principal", "1", "--dir", s(&store)]);
    assert!(signed.talk().contains("signed: the store"), "{}", signed.talk());
    let board = signed.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    let opened = signed.result("session", json!({"board": board}));
    let session = opened["session"].as_str().unwrap().to_string();
    assert_eq!(opened["account"], "1.0.1");
    let edition = signed.result("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}}));
    assert_eq!(edition["resp"], "ack_addr", "{edition}");
    // A content-scoped session: a credential deposit refuses `content_session`.
    let draft = signed.result("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}}))["addr"].as_str().unwrap().to_string();
    signed.result("op", json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["abc"]}}));
    let image = signed.result("op", json!({"session": session, "frame": skep_client::board::frames::image(&draft, 1, 3)}));
    let run = &image["runs"][0];
    let shot = signed.result("op", json!({"session": session, "frame": {"op": "publish", "doc": edition["addr"], "draft": draft, "runs": [{"origin": draft, "i_start": run["i_start"], "width": run["width"]}]}}));
    assert_eq!(shot["resp"], "ack_addr", "the shot, attested: {shot}");
    let read = signed.result("op", json!({"guest": true, "board": board, "frame": skep_client::board::frames::retrieve_v(shot["addr"].as_str().unwrap(), 1, 3)}));
    assert_eq!(read["items"][0]["content"], "abc");
    signed.result("close", json!({"session": session}));
    assert_eq!(signed.stop(), 0);
    // The same write under the bare mode, the keyless session that reads
    // alone: refused before any dial, a draft's mint beside it, the board's
    // position unmoved.
    let bare = Provider::start(&["--board", &board_origin, "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("bare-store"))]);
    let board = bare.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    let session = bare.result("session", json!({"board": board}))["session"].as_str().unwrap().to_string();
    let position = || bare.result("health", json!({"board": board}))["health"]["log_position"].as_u64().unwrap();
    let before = position();
    for frame in [json!({"op": "create_new_document", "account": "1.0.1", "published": true}), json!({"op": "create_new_document", "account": "1.0.1"})] {
        let refused = bare.refused("op", json!({"session": session, "frame": frame}));
        assert_eq!((refused["name"].as_str(), refused["op"].as_str()), (Some("write_in_bare_session"), Some("create_new_document")), "{refused}");
    }
    assert_eq!(position(), before, "the refused writes committed nothing");
    talk_holding(&bare, &["read alone, every write in them refused"]);
    assert_eq!(bare.stop(), 0);
    // The signed mode over a keyless store halts before serving (exit 3).
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep-dev"));
    let out = cmd.args(["serve", "--page-origin", PAGE, "--board", &board_origin, "--session", "signed", "--principal", "1", "--dir", s(&dir.path().join("empty"))]).stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no_key"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stdout.is_empty(), "no secret printed before serving");
    sd.shutdown();
}

// ── F6 ─────────────────────────────────────────────────────────────────────

/// F6 without the feature: the fault route says it is not built in, and
/// `--own` halts before serving.
#[cfg(not(feature = "dev-hooks"))]
#[test]
fn f6_without_dev_hooks_the_fault_door_is_not_built_in() {
    let dir = tempfile::tempdir().unwrap();
    let (sd, provider) = bare_provider(dir.path());
    let refused = provider.refused("fault/write_busy", json!({}));
    assert_eq!(refused["name"], "not_built_in", "{refused}");
    readme_names_every_door(refused["detail"].as_str().unwrap(), "the doors are ");
    assert_eq!(provider.stop(), 0);
    let out = Command::new(env!("CARGO_BIN_EXE_skep-dev"))
        .args(["serve", "--page-origin", PAGE, "--own", "--data-dir", s(&dir.path().join("own")), "--session", "bare"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("dev-hooks"));
    sd.shutdown();
}

/// F6 under the feature: the daemon in-process with `--own`, in the signed
/// mode — the store's one key the provider signs with, the board claimed
/// under it — the fault doors forcing `write_busy` and `scan_busy` live, the
/// `daemon` event; the `poison` door poisoning the kernel, so a burst `op`
/// answers `held` with `cause: poisoned` — its line `sent: true`, since the
/// frames land at a restart — and `held(session)` lists it; a door that is
/// no door refused naming the eleven.
#[cfg(feature = "dev-hooks")]
#[test]
fn f6_under_dev_hooks_the_fault_doors_force_the_daemons_states_live() {
    let dir = tempfile::tempdir().unwrap();
    let node_port = free_port().to_string();
    let store = dir.path().join("store");
    let keys = FileStore::open(&store);
    keys.generate(Some(Label::new("notebook").unwrap())).unwrap();
    let provider = Provider::start(&["--own", "--data-dir", s(&dir.path().join("own")), "--port", &node_port, "--session", "signed", "--principal", "1", "--dir", s(&store)]);
    let rx = provider.events();
    let board = provider.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    let board_origin = provider.result("boards", json!({}))[0]["origin"].as_str().unwrap().to_string();
    assert!(provider.talk().contains("runs in-process"), "{}", provider.talk());
    assert_eq!(provider.result("probe", json!({}))["daemon"], "running");
    // The board is claimed through the library under the provider's key, so
    // its signed session opens and its writes stand.
    claim_with(&board_origin, &keys, &dir.path().join("anchors"));
    next_event(&rx, "mode", |v| v["board"] == board);
    let session = provider.result("session", json!({"board": board, "principal": 1}))["session"].as_str().unwrap().to_string();
    let held = provider.result("fault/write_busy", json!({}));
    assert!(held["held"].as_u64().unwrap() >= 1, "{held}");
    let refused = provider.refused("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}}));
    assert_eq!(refused["name"], "write_busy", "carried verbatim: {refused}");
    assert_eq!(refused["status"], 503);
    provider.result("fault/release", json!({}));
    let minted = provider.result("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}}));
    assert_eq!(minted["resp"], "ack_addr");
    // The second door: the class-scan pool held.
    let held = provider.result("fault/scan_busy", json!({}));
    assert!(held["held"].as_u64().unwrap() >= 1);
    let scan = provider.refused("op", json!({"guest": true, "board": board, "frame": skep_client::board::frames::find_links_ftt("1.1.0.1.0.1.0.3.13", "1.0.1")}));
    assert_eq!(scan["name"], "scan_busy", "{scan}");
    provider.result("fault/release", json!({}));
    // The hold door `halt_writes` arms the attest store's next-write failure:
    // the door answers its name. (A hold from it needs a signed commit below
    // the reclaim floor, which this fresh board does not reach; the shell's own
    // suite drives the write-path halt in-process, and the stop/restart test
    // below drives a live hold through the provider.)
    assert_eq!(provider.result("fault/halt_writes", json!({}))["door"], "halt_writes");
    let refused = provider.refused("fault/no_such_door", json!({}));
    assert_eq!(refused["name"], "not_built_in");
    assert!(refused["detail"].as_str().unwrap().contains("poison"), "the refusal names the doors, `poison` among them: {refused}");
    readme_names_every_door(refused["detail"].as_str().unwrap(), "the doors are ");
    // The poison door: the kernel's next commit poisoned, so a burst on the
    // draft minted above answers `held` with `cause: poisoned` (§3c.4), its
    // line `sent: true` (§3c.2: the frames stay in the journal and land at a
    // restart), and `held(session)` lists it.
    assert_eq!(provider.result("fault/poison", json!({}))["door"], "poison");
    let held = provider.result("op", json!({"session": session, "frame": {"op": "insert", "doc": minted["addr"], "at": {"subspace": "1", "ordinal": "1"}, "values": ["p"]}}));
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("poisoned")), "{held}");
    let rows = provider.result("held", json!({"session": session}));
    assert_eq!(rows.as_array().unwrap().len(), 1, "held(session) lists the burst: {rows}");
    assert_eq!((rows[0]["cause"].as_str(), rows[0]["sent"].as_bool()), (Some("poisoned"), Some(true)), "{rows}");
    let (said, talk) = (provider.talk(), Arc::clone(&provider.talk));
    assert_eq!(provider.stop(), 0, "{said}");
    // The in-process daemon's orderly shutdown said once it completes, the
    // board named: its own stream marks no stop.
    said_holding(&talk, &[&format!("the in-process daemon at {board_origin} is stopped")]);
}

/// Checks that `--own --no-local-trust` names the flag on the `auth:` line.
///
/// The in-process daemon's open says the line on the provider's stream. Off
/// is the tool's own `--no-local-trust`, so the line names that flag as the
/// arm that set it and never calls off the daemon's default; without the
/// flag the line says the default, which on is.
#[cfg(feature = "dev-hooks")]
#[test]
fn own_no_local_trust_is_named_as_the_flag_on_the_daemons_auth_line() {
    let dir = tempfile::tempdir().unwrap();
    for (flags, arm) in [(&["--no-local-trust"][..], "(--local-trust off, --no-local-trust)"), (&[][..], "(--local-trust on, the default)")] {
        let node_port = free_port().to_string();
        let (own, store) = (dir.path().join(format!("own-{}", flags.len())), dir.path().join(format!("store-{}", flags.len())));
        let mut args = vec!["--own", "--data-dir", s(&own), "--port", &node_port, "--session", "bare", "--principal", "1", "--dir", s(&store)];
        args.extend_from_slice(flags);
        let provider = Provider::start(&args);
        let said = said_holding(&provider.talk, &[&format!("open: auth: unclaimed {arm};")]);
        assert_eq!(provider.stop(), 0, "{said}");
    }
}

// ── THE HELD-BURST STORE through the provider ────────────────────────────────

/// A burst held `unreachable` when the daemon the provider dials stops, the
/// daemon restarted at the same port, and the held burst resent and `kept` —
/// the `held` event on the provider's stream and the row read back. The
/// provider runs in the signed mode over the claimant's store: a bare one
/// reads alone, and its held bursts wait for a session that writes.
#[test]
fn a_held_burst_is_resent_through_the_provider_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let board_origin = origin(port);
    claim_board(&board_origin, &dir.path().join("claimant"), &dir.path().join("anchors"));
    let provider = Provider::start(&["--board", &board_origin, "--session", "signed", "--principal", "1", "--dir", s(&dir.path().join("claimant"))]);
    let rx = provider.events();
    let board = provider.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    let session = provider.result("session", json!({"board": board}))["session"].as_str().unwrap().to_string();
    let draft = provider.result("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}}))["addr"].as_str().unwrap().to_string();
    provider.result("op", json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["a"]}}));
    // The daemon stops: the next burst is held `unreachable`.
    sd.shutdown();
    let held = provider.result("op", json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"]}}));
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("unreachable")), "{held}");
    assert_eq!(provider.result("held", json!({"session": session})).as_array().unwrap().len(), 1);
    // Restart at the same port; the session ends — the restart arm re-opening
    // it — a fresh one is opened beside it, and the resend is `kept`.
    let sd = spawn_at(&dir.path().join("board"), true, port);
    next_event(&rx, "session-died", |v| v["session"] == session);
    let session2 = provider.result("session", json!({"board": board}))["session"].as_str().unwrap().to_string();
    let kept = next_event(&rx, "held", |v| v["doc"] == draft && v["state"] == "kept");
    assert_eq!(kept["board"], board);
    assert_eq!(provider.result("held", json!({"session": session2})), json!([]), "the file compacted away");
    let read = provider.result("op", json!({"session": session2, "frame": skep_client::board::frames::retrieve_v(&draft, 2, 1)}));
    assert_eq!(read["items"][0]["content"], "b", "the resent burst is on the board: {read}");
    assert_eq!(provider.stop(), 0);
    sd.shutdown();
}

// ── F7 ─────────────────────────────────────────────────────────────────────

/// F7: the isolation — the dependency tree at the default and the empty
/// feature sets names no `skepd`; under `dev-hooks` it does.
#[test]
fn f7_the_shipped_builds_carry_no_skepd() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let tree = |features: &[&str]| -> String {
        let mut cmd = Command::new(env!("CARGO"));
        cmd.args(["tree", "--manifest-path", s(&manifest), "-e", "normal", "--prefix", "none"]).args(features);
        let out = cmd.output().expect("cargo tree");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let names = |text: &str| -> Vec<String> { text.lines().filter_map(|l| l.split(' ').next()).map(str::to_string).collect() };
    let plain = names(&tree(&["--no-default-features"]));
    assert!(!plain.iter().any(|n| n == "skepd"), "no skepd without the feature: {plain:?}");
    assert!(plain.iter().any(|n| n == "skep-shell"), "the shell's core is a normal dependency");
    let default = names(&tree(&[]));
    assert!(!default.iter().any(|n| n == "skepd"), "no skepd at the default features: {default:?}");
    let hooked = names(&tree(&["--features", "dev-hooks"]));
    assert!(hooked.iter().any(|n| n == "skepd"), "skepd under dev-hooks: {hooked:?}");
}

// ── F8 ─────────────────────────────────────────────────────────────────────

/// F8: the declarations served are the crate's, and the real answers carry
/// the declared fields.
#[test]
fn f8_the_shapes_route_serves_the_declarations() {
    let dir = tempfile::tempdir().unwrap();
    let (sd, provider) = bare_provider(dir.path());
    let (status, headers, body) = provider.get("/bridge/shapes");
    assert_eq!(status, 200);
    assert!(header(&headers, "Content-Type").unwrap().starts_with("text/plain"));
    assert_eq!(String::from_utf8(body).unwrap(), skep_shell::shapes::declarations());
    let declared = |name: &str| -> std::collections::BTreeSet<String> { skep_shell::shapes::shape(name).unwrap().fields.iter().map(|f| f.name.to_string()).collect() };
    let keys = |v: &Value| -> std::collections::BTreeSet<String> { v.as_object().unwrap().keys().cloned().collect() };
    let boards = provider.result("boards", json!({}));
    assert_eq!(keys(&boards[0]), declared("BoardRow"));
    let board = boards[0]["board"].as_str().unwrap().to_string();
    assert_eq!(keys(&provider.result("session", json!({"board": board, "principal": 1}))), declared("SessionOpened"));
    assert_eq!(keys(&provider.result("health", json!({"board": board}))), declared("Health"));
    assert_eq!(keys(&provider.result("probe", json!({}))), declared("Probe"));
    let refused = provider.refused("op", json!({"guest": true, "board": board, "frame": {"op": "insert", "doc": "1.0.1.0.1"}}));
    assert_eq!(keys(&refused), declared("ShellRefusal").into_iter().chain(["op".to_string()]).collect());
    assert_eq!(provider.stop(), 0);
    sd.shutdown();
}

// ── F9 ─────────────────────────────────────────────────────────────────────

/// F9: the conformance — the same sequence on the crate and through the
/// provider, each in the signed mode over the claimant's store, yields
/// deep-equal results (the references normalized) and the same events in
/// the same order.
#[test]
fn f9_the_crate_and_the_provider_answer_one_sequence_alike() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let board_origin = origin(sd.port());
    let store = dir.path().join("claimant");
    claim_board(&board_origin, &store, &dir.path().join("anchors"));
    /// The sequence, over any `call`: boards, a signed session, a read, a
    /// draft minted and written, a guest read the draft withholds, close —
    /// the answers normalized.
    fn sequence(call: &dyn Fn(&str, Value) -> Value) -> Vec<Value> {
        let mut out = Vec::new();
        let boards = call("boards", json!({}));
        let board = boards["result"][0]["board"].as_str().unwrap().to_string();
        out.push(boards);
        let opened = call("session", json!({"board": board, "principal": 1}));
        let session = opened["result"]["session"].as_str().unwrap().to_string();
        out.push(opened);
        out.push(call("op", json!({"session": session, "frame": {"op": "principal_prefix", "principal": 1}})));
        let minted = call("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}}));
        let draft = minted["result"]["addr"].as_str().unwrap().to_string();
        out.push(minted);
        out.push(call("op", json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["same"]}})));
        out.push(call("op", json!({"guest": true, "board": board, "frame": {"op": "doc_metadata", "doc": draft}})));
        out.push(call("close", json!({"session": session})));
        out.push(call("op", json!({"session": session, "frame": {"op": "principal_prefix", "principal": 1}})));
        out.into_iter().map(normalize).collect()
    }
    /// Every reference, address and position replaced by a placeholder:
    /// the two runs mint their own, and the board moves between them.
    fn normalize(v: Value) -> Value {
        match v {
            Value::String(s) if s.starts_with("b-") || s.starts_with("s-") => Value::from("<ref>"),
            Value::String(s) if s.contains('.') && s.bytes().all(|b| b.is_ascii_digit() || b == b'.') => Value::from("<addr>"),
            Value::Number(n) if n.as_u64().is_some_and(|x| x > 5) => Value::from("<n>"),
            Value::Array(a) => Value::Array(a.into_iter().map(normalize).collect()),
            Value::Object(m) => Value::Object(m.into_iter().filter(|(k, _)| !matches!(k.as_str(), "at" | "as_of" | "position" | "time" | "head_time" | "log_position" | "chain_head" | "session")).map(|(k, v)| (k, normalize(v))).collect()),
            other => other,
        }
    }
    // (a) directly on the crate.
    let talk: skep_shell::Talk = Arc::new(|_| {});
    let shell = Shell::open(ShellOptions::new(vec![Origin::parse(&board_origin).unwrap()], store.clone(), SessionMode::Signed { principal: 1 }, talk));
    let direct_rx = shell.subscribe();
    let direct = sequence(&|name, args| match shell.call(name, &args) {
        Ok(v) => json!({"result": v}),
        Err(r) => json!({"refused": r.to_value()}),
    });
    thread::sleep(Duration::from_millis(500));
    let direct_events: Vec<String> = direct_rx.try_iter().map(|e| e.name.to_string()).filter(|n| n == "session-died" || n == "feed").collect();
    // Dropped as well as stopped, so its locks on the store's directories are
    // the provider's to take.
    shell.shutdown();
    drop(shell);
    // (b) through the provider.
    let provider = Provider::start(&["--board", &board_origin, "--session", "signed", "--principal", "1", "--dir", s(&store)]);
    let rx = provider.events();
    let served = sequence(&|name, args| provider.call(name, args));
    thread::sleep(Duration::from_millis(500));
    let served_events: Vec<String> = rx.try_iter().map(|(n, _)| n).filter(|n| n == "session-died" || n == "feed").collect();
    assert_eq!(direct, served, "deep-equal answers");
    assert_eq!(direct_events, served_events, "the same events in the same order");
    assert!(direct_events.contains(&"session-died".to_string()) && direct_events.contains(&"feed".to_string()), "{direct_events:?}");
    assert_eq!(provider.stop(), 0);
    sd.shutdown();
}

/// THE THROWAWAY STORE: a bare run that names no `--dir` makes its store
/// under the system temp dir and removes it at the clean stop — the key made
/// in it and the index saved there with it — and says so; a run that names
/// its `--dir` keeps that store, and the key made in it.
#[test]
fn the_throwaway_store_is_removed_at_the_clean_stop_and_a_named_one_kept() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let board = origin(sd.port());
    // The provider's talk once it holds `needle`, within the deadline: the
    // stderr reader may trail the exit.
    let said = |talk: &Arc<Mutex<String>>, needle: &str| -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let text = talk.lock().unwrap().clone();
            if text.contains(needle) {
                return text;
            }
            assert!(Instant::now() < deadline, "the provider never said {needle:?}:\n{text}");
            thread::sleep(Duration::from_millis(20));
        }
    };
    // No `--dir`: the store is the throwaway the bare line names.
    let provider = Provider::start(&["--board", &board, "--session", "bare", "--principal", "1"]);
    let talk = Arc::clone(&provider.talk);
    let store = said(&talk, "; the store is ").lines().find_map(|l| l.split_once("; the store is ")).map(|(_, path)| PathBuf::from(path)).unwrap();
    let name = store.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
    assert!(store.starts_with(std::env::temp_dir()) && name.starts_with("skep-dev-serve-"), "a throwaway under the system temp dir: {}", store.display());
    // The serving line says how the clean stop is asked, and what an
    // interrupt, which skips it, leaves — the throwaway among it; and how
    // the page carries the secret, never the secret itself, whose one
    // carrier is the run's one line on stdout.
    let serving = said(
        &talk,
        "the provider stops cleanly when stdin closes (Ctrl-D at a terminal) — an interrupt (Ctrl-C) ends it with none of the clean stop: its sessions live on at the board until it restarts, and the throwaway store stays in place",
    );
    assert!(serving.contains(&format!("?{SECRET_QUERY}=<the secret, this run's one line on stdout>")), "{serving}");
    assert!(!serving.contains(&provider.secret), "the secret is never said: {serving}");
    provider.result("keygen", json!({"label": "phone"}));
    assert!(store.is_dir(), "the throwaway stands while the provider serves");
    assert_eq!(provider.stop(), 0, "a clean stop");
    let gone = !store.exists();
    // A red run leaves nothing behind either.
    let _ = std::fs::remove_dir_all(&store);
    assert!(gone, "the throwaway store is removed at the clean stop: {}", store.display());
    said(&talk, &format!("the throwaway store {} is removed", store.display()));
    // The stop's cause and the connections the run accepted said ahead of
    // it, its seconds once it completes, and before the throwaway goes.
    let stopped = said(&talk, "stopped: the shell's stop took ");
    let at = |needle: &str| stopped.find(needle).unwrap_or_else(|| panic!("`{needle}` said: {stopped}"));
    let removed = format!("the throwaway store {} is removed", store.display());
    assert!(
        at("stopping (stdin closed): cancelling every pending moment, closing every session, saving every index — after ")
            < at("stopped: the shell's stop took ")
            && at("stopped: the shell's stop took ") < at(&removed),
        "{stopped}"
    );
    // `--dir`: the person's store, kept with the key made in it.
    let named = dir.path().join("named-store");
    let provider = Provider::start(&["--board", &board, "--session", "bare", "--principal", "1", "--dir", s(&named)]);
    let talk = Arc::clone(&provider.talk);
    assert!(!said(&talk, "an interrupt (Ctrl-C)").contains("throwaway"), "a named store is no throwaway");
    let fingerprint = provider.result("keygen", json!({"label": "phone"}))["fingerprint"].as_str().unwrap().to_string();
    assert_eq!(provider.stop(), 0, "a clean stop");
    assert!(named.is_dir(), "a store the person named is never removed");
    assert!(FileStore::open(&named).list().unwrap().iter().any(|k| k.fingerprint.to_hex() == fingerprint), "the key made in it stays");
    sd.shutdown();
}

/// AN ACCEPT THE LISTENER REFUSES IS SAID ONCE PER EDGE: under a descriptor
/// limit the connections held open exhaust, every accept past it fails at
/// once and again; the provider says its listener's refusal once, keeps
/// accepting, says when it accepts again once they close, and serves on.
#[cfg(unix)]
#[test]
fn a_listener_out_of_descriptors_says_so_once_and_when_it_accepts_again() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let board = origin(sd.port());
    let provider = Provider::start_under(&["--board", &board, "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("store"))], Some(48));
    let refused = "the provider's listener refused a connection: ";
    let mut held = Vec::new();
    while !provider.talk().contains(refused) {
        assert!(held.len() < 100, "{} connections held, and no accept refused:\n{}", held.len(), provider.talk());
        held.push(TcpStream::connect(("127.0.0.1", provider.port)).expect("the listener's queue takes the connect"));
        thread::sleep(Duration::from_millis(5));
    }
    // Every connection past the limit meets a refused accept — on every retry
    // while it waits, where the platform keeps it queued; the line stands
    // once.
    for _ in 0..20 {
        held.push(TcpStream::connect(("127.0.0.1", provider.port)).expect("the listener's queue takes the connect"));
        thread::sleep(Duration::from_millis(15));
    }
    thread::sleep(Duration::from_millis(300));
    assert_eq!(provider.talk().matches(refused).count(), 1, "{}", provider.talk());
    // The held connections closed, the next request is accepted and served,
    // and the edge back is said.
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(30);
    while provider.get("/bridge/log").0 != 200 {
        assert!(Instant::now() < deadline, "the provider serves again:\n{}", provider.talk());
        thread::sleep(Duration::from_millis(20));
    }
    let said = talk_holding(&provider, &["the provider's listener accepts connections again"]);
    assert_eq!(said.matches(refused).count(), 1, "{said}");
    // The edge back carries the episode's size: its seconds, and the
    // accepts refused across it — the one the first line said and those the
    // twenty connections past it met, said on no line of their own.
    let back = said.lines().find(|l| l.contains("the provider's listener accepts connections again")).unwrap();
    let refusals: u64 = back
        .split(" s and ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("the episode's refused accepts: {back}"));
    assert!(back.contains("accepts connections again, after ") && back.contains(" refused accepts") && refusals > 1, "{back}");
    assert_eq!(provider.stop(), 0);
    sd.shutdown();
}

/// The usage refusals: an unknown flag, a missing page origin, a missing
/// session mode, `--own` beside `--board`, a key file the verb never reads,
/// a missing board or board directory, a secret the page's URL cannot carry
/// (never echoed), a secret given empty, a listen port of `0`, a bad
/// script — each exit 2 before anything is made, a socket or the throwaway
/// store; and `--help` lists the verb. A halt past them — a board that does
/// not answer — removes the throwaway it made, and says so.
#[test]
fn the_verbs_usage_is_judged_before_any_socket() {
    // The child's temp dir is this test's own, so a throwaway it makes is
    // seen here and no other run's is.
    let temp = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| -> (i32, String, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep-dev"));
        cmd.args(args).stdin(Stdio::null());
        scrub(&mut cmd).env("TMPDIR", temp.path());
        let out = cmd.output().unwrap();
        (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    let throwaways = || std::fs::read_dir(temp.path()).unwrap().filter_map(Result::ok).filter(|e| e.file_name().to_string_lossy().starts_with("skep-dev-serve-")).count();
    let (code, out, _) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("\n  serve ") && out.contains("--page-origin <origin>") && out.contains("--session bare|signed"), "{out}");
    for (args, needle) in [
        (vec!["serve", "--board", "http://127.0.0.1:1", "--session", "bare"], "--page-origin is required"),
        (vec!["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1"], "--session bare|signed is required"),
        (vec!["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "full"], "neither bare nor signed"),
        (vec!["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "bare", "--bogus"], "unknown argument `--bogus`"),
        (vec!["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "bare", "--own"], "belong to two forms"),
        (vec!["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "signed"], "--dir (or SKEP_KEYSTORE) is required under --session signed"),
        (vec!["serve", "--page-origin", "localhost:5173", "--board", "http://127.0.0.1:1", "--session", "bare"], "--page-origin:"),
        (vec!["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "bare", "--data-dir", "/tmp/x"], "belongs to `serve --own`"),
        (
            vec!["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "bare", "--key", "/x"],
            "`--key` (or SKEP_KEY) names a key file, and `skep-dev serve` signs with the key its --dir store holds",
        ),
        (vec!["serve", "--page-origin", PAGE, "--session", "bare"], "--board (or SKEP_BOARD) is required"),
        (vec!["serve", "--page-origin", PAGE, "--session", "bare", "--own"], "--data-dir is required with --own"),
        (vec!["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "bare", "--secret", "a&b"], "--secret: a secret is one or more of A-Z a-z 0-9 - . _ ~"),
        (vec!["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "bare", "--secret", ""], "--secret: an empty value names nothing"),
        (vec!["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "bare", "--listen", "0"], "--listen: '0' is not a port the page can be pointed at"),
    ] {
        let (code, out, err) = run(&args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(err.contains(needle), "{args:?}: {err}");
        assert!(!err.contains("a&b"), "a secret refused is never echoed: {err}");
        assert!(out.is_empty(), "nothing on stdout: {out}");
        assert_eq!(throwaways(), 0, "a usage refusal makes no throwaway: {args:?}");
    }
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("bad.txt");
    std::fs::write(&script, "confirm maybe\n").unwrap();
    let (code, _, err) = run(&["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "bare", "--script", s(&script)]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("script line 1"), "{err}");
    // A board that does not answer: a halt before serving, exit 3, and the
    // throwaway made for the run removed on the way out, said so.
    let port = free_port();
    let (code, out, err) = run(&["serve", "--page-origin", PAGE, "--board", &format!("http://127.0.0.1:{port}"), "--session", "bare"]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("unreachable"), "{err}");
    assert!(out.is_empty());
    assert!(err.contains(&format!("the throwaway store {}", temp.path().display())) && err.contains(" is removed"), "{err}");
    assert_eq!(throwaways(), 0, "the halt leaves no throwaway behind");
}
