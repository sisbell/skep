//! THE DEV PROVIDER's FENCE: `skep-dev serve` driven through argv against
//! boards the suite spawns in-process, the suite standing in for the page
//! over loopback HTTP with the admission headers. F1 every call of
//! `client.md` §4b.1 in the bare mode — the reads and the draft write
//! acked, the publish-class write refused `signed_session_required`
//! verbatim, the three guest forms, `keygen` and `fingerprint`, `search`,
//! the ceremonial calls to their first refusal, the stale session and the
//! foreign board, the token in no answer and no event, the log listing
//! every call; F2 the events — `feed` with the board reference and the
//! entry, `index`, `mode` at a claim's landing, `session-died` on `close`
//! and on the daemon's restart with the arm named, `daemon` on the
//! stream's loss; F3 the person over the bridge — a claim on an unclaimed
//! board with every PUBLIC moment arriving as a `moment` event and answered
//! by `/bridge/answer`, the board claimed, and a second run cancelled at
//! the first moment answering the abandonment with the board unclaimed;
//! F4 the admission — a foreign origin, no secret, a wrong host, each 403
//! naming the check with no dial made, the preflight for the one origin
//! and never `*`, the listener on 127.0.0.1 alone; F5 the signed mode — a
//! content-scoped session, a publish-class write acked under the attest
//! the provider composed, the same write refused under bare; F6 the fault
//! doors under `dev-hooks` with `--own`, and `not_built_in` without; F7
//! the isolation, `cargo tree` naming no `skepd` without the feature and
//! one with it; F8 the declarations served equal to the crate's; F9 the
//! conformance — one sequence on the crate and through the provider,
//! deep-equal results and the same events in order.

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
use skep_shell::{ArmConfig, SessionMode, Shell, ShellOptions};
use skepd::{embed, AuthOptions, MediaOptions, Skepd, DEFAULT_WORKERS};

use crate::common::{origin, s, spawn};

/// The page origin every provider here is started for.
const PAGE: &str = "http://127.0.0.1:8731";

/// The admission header and the query key, as the provider spells them.
const SECRET_HEADER: &str = "Skep-Provider";
const SECRET_QUERY: &str = "provider";

// ── THE BOARD ──────────────────────────────────────────────────────────────

/// A claimed board through the LIBRARY, as `dev.rs` claims one: the store
/// holds the device key and the account's line.
fn claim_board(board_origin: &str, store: &Path, anchors: &Path) {
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let store = FileStore::open(store);
    store.generate(Some(Label::new("notebook").unwrap())).unwrap();
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions { principal: None, display_name: Some("a name".into()), anchor_out: vec![anchors.join("a"), anchors.join("b")], paper: false, host_name: "testhost".into(), date: "2026-10-10".into() };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, &store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
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
    /// every `SKEP_*` variable and `HOME` scrubbed, waited for until its
    /// port answers.
    fn start(args: &[&str]) -> Provider {
        for _ in 0..8 {
            let port = free_port();
            let listen = port.to_string();
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep-dev"));
            cmd.arg("serve").args(["--page-origin", PAGE, "--listen", &listen]).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            for var in ["SKEP_BOARD", "SKEP_KEYSTORE", "SKEP_KEY", "SKEP_PRINCIPAL", "SKEP_SESSION", "SKEP_SEARCH_CORPUS", "HOME", "USERPROFILE"] {
                cmd.env_remove(var);
            }
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
    let health = keep(provider.result("health", json!({"board": board})));
    assert_eq!(health["mode"], "CLAIMED-PERMISSIVE");
    let probe = keep(provider.result("probe", json!({})));
    assert_eq!(probe["daemon"], "running");
    // session, a read, a draft write, the publish-class refusal.
    let opened = keep(provider.result("session", json!({"board": board, "principal": 1})));
    let session = opened["session"].as_str().unwrap().to_string();
    assert!(session.starts_with("s-"));
    assert_eq!(opened["account"], "1.0.1");
    let set = keep(provider.result("op", json!({"session": session, "frame": {"op": "key_set", "account": "1.0.1"}})));
    assert_eq!(set["resp"], "key_set");
    let minted = keep(provider.result("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})));
    let draft = minted["addr"].as_str().unwrap().to_string();
    let acked = keep(provider.result("op", json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}})));
    assert!(acked["resp"].as_str().unwrap().starts_with("ack"));
    let refused = keep(provider.refused("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}})));
    assert_eq!(refused["name"], "signed_session_required");
    assert_eq!(refused["kind"], "refused");
    assert_eq!(refused["code"], "credential_refused");
    assert_eq!(refused["body"]["detail"], "signed_session_required", "carried verbatim");
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
    for name in ["boards", "health", "probe", "session", "op", "keygen", "fingerprint", "search", "claim", "enroll", "bind", "recover", "rotate", "retire", "handoff", "accept", "upload", "restore", "fetch", "close"] {
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
    let draft = provider.result("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}}))["addr"].as_str().unwrap().to_string();
    provider.result("op", json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}}));
    // `feed` with the board reference and the entry — the draft's insert
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
    std::fs::write(&script, "# the re-types off the sheets shown, in order\nretype sheet 0\nretype sheet 1\n").unwrap();
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
    assert!(said.contains("dev arm: the sheet for fingerprint"), "the SECRET sheet went to the dev arm:\n{said}");
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
    assert_eq!(provider.stop(), 0);
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
    // The same write under the bare mode: refused `signed_session_required`.
    let bare = Provider::start(&["--board", &board_origin, "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("bare-store"))]);
    let board = bare.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    let session = bare.result("session", json!({"board": board}))["session"].as_str().unwrap().to_string();
    assert_eq!(bare.refused("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}}))["name"], "signed_session_required");
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

/// F6 under the feature: the daemon in-process with `--own`, the fault
/// doors forcing `write_busy` and `scan_busy` live, the `daemon` event; the
/// `poison` door poisoning the kernel, so a burst `op` answers `held` with
/// `cause: poisoned` — its line `sent: true`, since the frames land at a
/// restart — and `held(session)` lists it; a door that is no door refused
/// naming the eleven.
#[cfg(feature = "dev-hooks")]
#[test]
fn f6_under_dev_hooks_the_fault_doors_force_the_daemons_states_live() {
    let dir = tempfile::tempdir().unwrap();
    let node_port = free_port().to_string();
    let provider = Provider::start(&["--own", "--data-dir", s(&dir.path().join("own")), "--port", &node_port, "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("store"))]);
    let rx = provider.events();
    let board = provider.result("boards", json!({}))[0]["board"].as_str().unwrap().to_string();
    let board_origin = provider.result("boards", json!({}))[0]["origin"].as_str().unwrap().to_string();
    assert!(provider.talk().contains("runs in-process"), "{}", provider.talk());
    assert_eq!(provider.result("probe", json!({}))["daemon"], "running");
    // The board is claimed through the library, so writes stand.
    claim_board(&board_origin, &dir.path().join("claimant"), &dir.path().join("anchors"));
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
    let said = provider.talk();
    assert_eq!(provider.stop(), 0, "{said}");
}

// ── THE HELD-BURST STORE through the provider ────────────────────────────────

/// A burst held `unreachable` when the daemon the provider dials stops, the
/// daemon restarted at the same port, and the held burst resent and `kept` —
/// the `held` event on the provider's stream and the row read back.
#[test]
fn a_held_burst_is_resent_through_the_provider_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let board_origin = origin(port);
    claim_board(&board_origin, &dir.path().join("claimant"), &dir.path().join("anchors"));
    let provider = Provider::start(&["--board", &board_origin, "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("store"))]);
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
    // Restart at the same port; a fresh session re-acquired; the resend `kept`.
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
/// provider yields deep-equal results (the references normalized) and the
/// same events in the same order.
#[test]
fn f9_the_crate_and_the_provider_answer_one_sequence_alike() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let board_origin = origin(sd.port());
    claim_board(&board_origin, &dir.path().join("claimant"), &dir.path().join("anchors"));
    /// The sequence, over any `call`: boards, session, a read, a draft
    /// write, a publish-class refusal, close — the answers normalized.
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
        out.push(call("op", json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}})));
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
    let shell = Shell::open(ShellOptions { boards: vec![Origin::parse(&board_origin).unwrap()], store_dir: dir.path().join("direct-store"), mode: SessionMode::Bare { principal: 1 }, arm: ArmConfig::Auto, talk, own_node: None });
    let direct_rx = shell.subscribe();
    let direct = sequence(&|name, args| match shell.call(name, &args) {
        Ok(v) => json!({"result": v}),
        Err(r) => json!({"refused": r.to_value()}),
    });
    thread::sleep(Duration::from_millis(500));
    let direct_events: Vec<String> = direct_rx.try_iter().map(|e| e.name.to_string()).filter(|n| n == "session-died" || n == "feed").collect();
    shell.shutdown();
    // (b) through the provider.
    let provider = Provider::start(&["--board", &board_origin, "--session", "bare", "--principal", "1", "--dir", s(&dir.path().join("provider-store"))]);
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
    provider.result("keygen", json!({"label": "phone"}));
    assert!(store.is_dir(), "the throwaway stands while the provider serves");
    assert_eq!(provider.stop(), 0, "a clean stop");
    let gone = !store.exists();
    // A red run leaves nothing behind either.
    let _ = std::fs::remove_dir_all(&store);
    assert!(gone, "the throwaway store is removed at the clean stop: {}", store.display());
    said(&talk, &format!("the throwaway store {} is removed", store.display()));
    // `--dir`: the person's store, kept with the key made in it.
    let named = dir.path().join("named-store");
    let provider = Provider::start(&["--board", &board, "--session", "bare", "--principal", "1", "--dir", s(&named)]);
    let fingerprint = provider.result("keygen", json!({"label": "phone"}))["fingerprint"].as_str().unwrap().to_string();
    assert_eq!(provider.stop(), 0, "a clean stop");
    assert!(named.is_dir(), "a store the person named is never removed");
    assert!(FileStore::open(&named).list().unwrap().iter().any(|k| k.fingerprint.to_hex() == fingerprint), "the key made in it stays");
    sd.shutdown();
}

/// The usage refusals: an unknown flag, a missing page origin, a missing
/// session mode, `--own` beside `--board`, a bad script — each exit 2
/// before any socket; and `--help` lists the verb.
#[test]
fn the_verbs_usage_is_judged_before_any_socket() {
    let run = |args: &[&str]| -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_skep-dev")).args(args).stdin(Stdio::null()).output().unwrap();
        (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
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
    ] {
        let (code, out, err) = run(&args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(err.contains(needle), "{args:?}: {err}");
        assert!(out.is_empty(), "nothing on stdout: {out}");
    }
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("bad.txt");
    std::fs::write(&script, "confirm maybe\n").unwrap();
    let (code, _, err) = run(&["serve", "--page-origin", PAGE, "--board", "http://127.0.0.1:1", "--session", "bare", "--script", s(&script)]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("script line 1"), "{err}");
    // A board that does not answer: a halt before serving, exit 3.
    let port = free_port();
    let (code, out, err) = run(&["serve", "--page-origin", PAGE, "--board", &format!("http://127.0.0.1:{port}"), "--session", "bare"]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("unreachable"), "{err}");
    assert!(out.is_empty());
    let _ = PathBuf::new();
}
