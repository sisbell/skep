//! Startup: what the adapter reads before it serves, and what it refuses.
//!
//! The flags answered before anything else is read (`--version`, `--help`), and
//! a usage error; the log opening on the version it runs and the process; each
//! setting refused by name where it is missing, set empty or malformed — the
//! principal, the board (an `https://` one among them), the key store (one
//! that does not stand, or that this process cannot write, among them), the
//! commons (any address but the commons' among them), a value that is not
//! UTF-8 — and served where it is given: a flag beating its variable, said
//! where both are set, a board off the loopback warned of, the `settings:`
//! line naming each setting and its source, the commons sentence, a tools
//! file in the embedded catalog's place, named where it is served and said
//! where its text differs, and a drifted one refused naming it; the board's
//! refusals of the open, a board said halted exactly where its writes are, the
//! log inert and no token in it, nor a document's text an answer the client
//! cannot parse quoted; and what the start finds under the store: an earlier
//! run's held bursts, a halted held file, another adapter still holding it.
//! Most run the built binary with no board, or a stand-in one answering what a
//! real board never does; the rest over a claimed board (`common`'s
//! `Fixture`). The fence's startup cases — no key, `SKEP_BOARD`, a retired
//! key's relaunch — are `agent.rs`'s.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::json;
use skep_client::store::{FileStore, KeyFacts, KeySelector, KeyStore, Purpose};

use crate::common::{draft_of, embedded_catalog, stamped, Fixture, Launch, TempDir, CLAIMANT_ACCOUNT, VARIABLES};

/// `--version` is answered before the catalog, the environment or stdin is
/// consulted: ONE line on stdout — `skep-mcp <crate version> (<commit>)`,
/// the version this test's own `CARGO_PKG_VERSION` and the commit
/// `SKEP_GIT_SHA` named at build time, `unknown` where it named none —
/// nothing on stderr, exit 0, with no setting set (a start would refuse
/// that) and stdin held open by the test, which a read of it would wait on.
#[test]
fn version_is_one_line_on_stdout_before_the_environment_or_stdin_is_read() {
    let (code, stdout, stderr) = answered_up_front(&["--version"]);
    assert_eq!(code, Some(0), "exit 0: {stderr}");
    assert_eq!(stdout, format!("skep-mcp {} ({})\n", env!("CARGO_PKG_VERSION"), option_env!("SKEP_GIT_SHA").unwrap_or("unknown")), "the one line");
    assert!(stderr.is_empty(), "nothing on stderr: {stderr}");
}

/// `--help` is the usage on stdout, answered before anything is consulted.
///
/// Exit 0, the usage whole, nothing on stderr — `-h` the same, and what
/// follows the flag unread.
#[test]
fn help_is_the_usage_on_stdout_before_the_environment_or_stdin_is_read() {
    let (code, usage, stderr) = answered_up_front(&["--help"]);
    assert_eq!(code, Some(0), "exit 0: {stderr}");
    assert!(usage.starts_with("usage: skep-mcp [--board <ORIGIN>]") && usage.ends_with("with the store's key for it.\n"), "the usage whole on stdout: {usage:?}");
    assert!(stderr.is_empty(), "nothing on stderr: {stderr}");
    for args in [&["-h"][..], &["--help", "--no-such-flag"][..]] {
        assert_eq!(answered_up_front(args), (Some(0), usage.clone(), String::new()), "{args:?}");
    }
}

/// Returns a run of the binary on `args` alone: its exit code, stdout, stderr.
///
/// No setting is set and stdin is held open, which a read of it would wait on.
fn answered_up_front(args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep-mcp"));
    cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for var in VARIABLES {
        cmd.env_remove(var);
    }
    let mut child = cmd.spawn().expect("spawn skep-mcp");
    let held_open = child.stdin.take().expect("child stdin");
    let status = child.wait().expect("wait for skep-mcp");
    drop(held_open);
    let (mut stdout, mut stderr) = (String::new(), String::new());
    child.stdout.take().expect("child stdout").read_to_string(&mut stdout).expect("read stdout");
    child.stderr.take().expect("child stderr").read_to_string(&mut stderr).expect("read stderr");
    (status.code(), stdout, stderr)
}

/// Returns the port of a stand-in board answering each request by `answer`.
///
/// `answer` is handed the request's head and body as text, and its answer's
/// bytes are written whole before the connection closes.
fn stand_in(answer: impl Fn(&str, &str) -> String + Send + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a stand-in board");
    let port = listener.local_addr().expect("its port").port();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
            while !head.ends_with(b"\r\n\r\n") && conn.read(&mut byte).is_ok_and(|n| n == 1) {
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let length = head.lines().find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").and_then(|n| n.trim().parse::<usize>().ok())).unwrap_or(0);
            let mut body = vec![0u8; length];
            let _ = conn.read_exact(&mut body);
            let _ = conn.write_all(answer(&head, &String::from_utf8_lossy(&body)).as_bytes());
        }
    });
    port
}

/// Returns a `200` answer carrying `body`, its length declared.
fn answered(body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

/// Returns the `404` a stand-in board answers a request it does not serve.
fn not_found() -> String {
    let body = r#"{"error":"not_found"}"#;
    format!("HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

/// Returns a store holding one fresh key, and the key's facts.
fn keyed_store(tag: &str) -> (TempDir, KeyFacts) {
    let dir = TempDir::new(tag);
    let store = FileStore::open(dir.path());
    let id = store.generate(None).expect("keygen");
    let key = store.select(&KeySelector::Path(&store.key_path(&id.0)), Purpose::Read).expect("the key's facts");
    (dir, key)
}

/// Returns the port of a stand-in board `key` opens a signed session at.
///
/// It passes every check the signed open makes — `/health` naming the origin
/// it is dialed at as signed, the principal's account, a key set `key` is
/// enrolled in, a challenge — and answers `POST /session` by `session`, any
/// other `/op` frame by `other`, handed the frame, and every other request
/// `404`.
fn signing_stand_in(key: &KeyFacts, session: impl Fn() -> String + Send + 'static, other: impl Fn(&str) -> String + Send + 'static) -> u16 {
    let enrolled = json!({"resp": "key_set", "as_of": 0, "enrolled": [{"alg": key.public.alg(), "key": key.public.to_hex(), "fingerprint": key.fingerprint.to_hex(), "anchor": false}], "retired": []});
    stand_in(move |head, body| {
        let host = head.lines().find_map(|line| line.strip_prefix("Host: ")).unwrap_or_default();
        if head.starts_with("GET /health ") {
            answered(&json!({"ok": true, "log_position": 0, "auth": {"claimant": CLAIMANT_ACCOUNT, "local_trust": true, "signed_origins": [format!("http://{host}")]}}).to_string())
        } else if head.starts_with("POST /op ") && body.contains("\"principal_prefix\"") {
            answered(&json!({"resp": "maybe_addr", "addr": CLAIMANT_ACCOUNT, "as_of": 0}).to_string())
        } else if head.starts_with("POST /op ") && body.contains("\"key_set\"") {
            answered(&enrolled.to_string())
        } else if head.starts_with("GET /challenge?principal=1 ") {
            answered(r#"{"nonce":"n-1","principal":1,"ttl_ms":60000}"#)
        } else if head.starts_with("POST /session ") {
            session()
        } else if head.starts_with("POST /op ") {
            other(body)
        } else {
            not_found()
        }
    })
}

/// A board's text reaches the log inert.
///
/// A stand-in board answers every request with one `/health` reading whose
/// claimant carries a terminal sequence and a forged line; the adapter says
/// the board's line and stops before serving, its store keyless: no control
/// byte reaches stderr, the claimant is shown by its code points, and no line
/// opens as the adapter's but the adapter's own.
#[test]
fn a_boards_text_reaches_the_log_inert() {
    let health = r#"{"ok":true,"log_position":0,"auth":{"claimant":"\u001b]0;owned\u0007\nskep-mcp: forged","local_trust":false}}"#;
    let port = stand_in(move |_, _| answered(health));
    let keyless = TempDir::new("inert");
    let (code, err) = Launch::new().env("SKEP_BOARD", format!("http://127.0.0.1:{port}")).env("SKEP_KEYSTORE", keyless.path()).env("SKEP_PRINCIPAL", "1").refusal();
    assert_eq!(code, Some(1), "the keyless store stops startup: {err}");
    assert!(err.contains("claimant <U+001B>]0;owned<U+0007>"), "the claimant, shown by its code points: {err:?}");
    assert!(!err.contains(['\u{1b}', '\u{7}']), "no control byte reaches the log: {err:?}");
    assert!(!err.lines().any(|l| l.starts_with("skep-mcp: forged")), "a line the board wrote opens as the adapter's: {err:?}");
}

/// A board is said halted at startup exactly where its writes are halted.
///
/// A stand-in board's `/health` reports its writes halted, running, or says
/// nothing of them; the adapter says the board's line, naming the position it
/// attaches at, before its keyless store stops startup, and the halted board's
/// line alone says what a write meets through the shell until the board
/// restarts: a burst held for the shell's resend, any other write refused
/// `poisoned`.
#[test]
fn a_board_is_said_halted_at_startup_exactly_where_its_writes_are_halted() {
    let halted = "; writes HALTED until the board restarts: a burst is held for the shell's resend, and any other write refused `poisoned`";
    for (writes, said) in [(r#","writes":{"halted":true}"#, true), (r#","writes":{"halted":false}"#, false), ("", false)] {
        let health = format!(r#"{{"ok":true,"log_position":0,"auth":{{"claimant":"1.0.1","local_trust":false}}{writes}}}"#);
        let port = stand_in(move |_, _| answered(&health));
        let keyless = TempDir::new("halted");
        let (code, err) = Launch::new().env("SKEP_BOARD", format!("http://127.0.0.1:{port}")).env("SKEP_KEYSTORE", keyless.path()).env("SKEP_PRINCIPAL", "1").refusal();
        assert_eq!(code, Some(1), "the keyless store stops startup: {err}");
        assert!(err.contains(&format!("board http://127.0.0.1:{port} (reference ")), "premise: the board's line is said: {err}");
        assert!(err.contains(") at position 0: mode "), "the board's line names the position the adapter attaches at: {err}");
        assert_eq!(err.contains(halted), said, "{writes:?}: {err}");
    }
}

/// A token in a session answer the client cannot read reaches no log line.
///
/// A stand-in board passes every check the signed open makes — the origin, the
/// principal's account, the store's one key enrolled — and answers its `POST
/// /session` with a `200` the client cannot read, a byte short with no length
/// to catch it, as a connection an intermediary re-framed and then lost, whose
/// text holds the session's token: startup stops naming the open's refusal,
/// and no line on stderr carries the token.
#[test]
fn a_token_in_a_session_answer_the_client_cannot_read_reaches_no_log_line() {
    const TOKEN: &str = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
    let (dir, key) = keyed_store("unreadable-session");
    let (opened, opens) = std::sync::mpsc::channel::<()>();
    let session = move || {
        let _ = opened.send(());
        format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{{\"principal\":1,\"session\":\"{TOKEN}\"")
    };
    let port = signing_stand_in(&key, session, |_| not_found());
    let (code, err) = Launch::new().env("SKEP_BOARD", format!("http://127.0.0.1:{port}")).env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").refusal();
    assert!(opens.try_recv().is_ok(), "premise: the open's POST /session was answered:\n{err}");
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("stopped before serving: the signed session did not open: unreachable"), "{err}");
    assert!(!err.contains(TOKEN), "the session's token reaches the log:\n{err}");
}

/// A document's text in an answer the client cannot parse reaches no log line.
///
/// A stand-in board opens the adapter's signed session, and answers the feed
/// thread's first read of a document's text — the head document's, which the
/// index's open reads — with a delivery an intermediary cut short, its length
/// undeclared, whose text holds a sentence of the document's: the feed says
/// the index could not open in skep-client's words, the parse error kept and
/// the answer's text cut, its bytes counted, and no line carries the
/// sentence (D9).
#[test]
fn a_documents_text_in_an_answer_the_client_cannot_parse_reaches_no_log_line() {
    const SENTENCE: &str = "a sentence of the document's own";
    let (dir, key) = keyed_store("quoted-answer");
    let session = || answered(r#"{"principal":1,"session":"0123456789abcdef0123456789abcdef"}"#);
    let read = |frame: &str| {
        if frame.contains("\"retrieve_v\"") {
            format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{{\"resp\":\"delivery\",\"items\":[{{\"content\":\"{SENTENCE}")
        } else {
            not_found()
        }
    };
    let port = signing_stand_in(&key, session, read);
    let mut mcp = Launch::new().env("SKEP_BOARD", format!("http://127.0.0.1:{port}")).env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").logged().spawn();
    mcp.initialize();
    let log = mcp.log_holding(&["the index could not open: "], Duration::from_secs(30));
    let line = log.lines().find(|line| line.contains("the index could not open: ")).expect("the feed's line");
    assert!(line.contains(": the answer was not JSON (") && line.contains(" at line 1 column "), "the parse error kept: {line}");
    assert!(line.contains("): the answer's text and the rest of this line not shown ("), "the answer's text cut, counted: {line}");
    let (status, log) = mcp.finish_logged();
    assert!(status.success(), "{status:?}\n{log}");
    assert!(!log.contains(SENTENCE), "the document's text reaches the log:\n{log}");
}

/// A board the adapter cannot reach stops startup, and nothing is served.
///
/// The session cannot open: exit 1, the plain line naming the stop, the
/// refusal's kind and the board, nothing on stdout; a loopback board is warned
/// of not at all. Port 1 sits below 1024, where no unprivileged process can
/// listen, so the connect is refused.
#[test]
fn a_board_that_does_not_answer_stops_startup() {
    let dir = TempDir::new("noboard");
    let out = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").output();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("stopped before serving: the board's health was not read: unreachable"), "{err}");
    assert!(err.contains("http://127.0.0.1:1"), "the board named: {err}");
    assert!(!err.contains("plaintext non-loopback"), "a loopback board is warned of not at all: {err}");
    assert!(out.stdout.is_empty(), "nothing served: {:?}", String::from_utf8_lossy(&out.stdout));
}

/// The log opens on the build it runs and the process, before anything else.
///
/// Its first line is `skep-mcp: <moment> version <crate version> (<commit>),
/// pid <id>`, the version line's build beside the process's id, so every line
/// after it is read as that binary's, and joins by the id what the host says
/// of the process.
#[test]
fn the_log_opens_on_the_version_it_runs() {
    let dir = TempDir::new("version-first");
    let child = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").stderr(Stdio::piped()).child();
    let pid = child.id();
    let out = child.wait_with_output().expect("the adapter's run");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    let first = err.lines().next().and_then(stamped).map(|(_, text)| text);
    let version = format!("version {} ({}), pid {pid}", env!("CARGO_PKG_VERSION"), option_env!("SKEP_GIT_SHA").unwrap_or("unknown"));
    assert_eq!(first, Some(version.as_str()), "the first line names the build and the process: {err}");
}

/// A board off this machine's loopback is warned of where the setting is read.
///
/// An `http://` origin whose host is no loopback carries the session's token in
/// the clear unless a tunnel carries it (AUTH-4.53): the start says so ahead of
/// everything the session needs — a warning, never a refusal: the stop that
/// follows here is the unanswering board's.
#[test]
fn a_board_off_the_loopback_is_warned_of_where_the_setting_is_read() {
    let dir = TempDir::new("plaintext");
    let (code, err) = Launch::new().env("SKEP_BOARD", "http://0.0.0.0:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").refusal();
    assert_eq!(code, Some(1), "{err}");
    let warned = err.find("warning: http://0.0.0.0:1 is a plaintext non-loopback origin").unwrap_or_else(|| panic!("the warning: {err}"));
    let stopped = err.find("stopped before serving: the board's health was not read").unwrap_or_else(|| panic!("the board's own stop: {err}"));
    assert!(warned < stopped, "the warning ahead of what the session needs: {err}");
}

/// An `https://` board is refused where the setting is read.
///
/// The adapter dials plain `http://` alone and signs for the origin it dials,
/// so the refusal names the setting, the origin and what serves instead — an
/// `http://` origin the board signs sessions for, never a hosted board's — by
/// variable and by flag alike, before any dial: no health read is tried, and
/// no line names a transport feature.
#[test]
fn an_https_board_is_refused_where_the_setting_is_read() {
    let dir = TempDir::new("https");
    for launch in [Launch::new().env("SKEP_BOARD", "https://127.0.0.1:1"), Launch::new().args(["--board", "https://127.0.0.1:1"])] {
        let (code, err) = launch.env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").refusal();
        assert_eq!(code, Some(1), "{err}");
        assert!(err.contains("--board (or SKEP_BOARD): 'https://127.0.0.1:1' is an https:// origin, and this adapter dials plain http:// alone"), "{err}");
        assert!(err.contains("an http:// origin the board signs sessions for") && err.contains("a hosted board signs its https:// origin alone"), "what serves instead: {err}");
        assert!(!err.contains("health was not read") && !err.contains("`tls`"), "refused before any dial: {err}");
    }
}

/// The principal is required, an integer from 0 to 2^53 − 1 the board seats.
///
/// Unset, or set empty — a variable set empty is unset, as the `skep` command
/// reads it — startup refuses by name; set to anything that is no integer in
/// that range, it refuses quoting the value, while 0, the range's floor,
/// passes and startup goes on to the board; set to an id the board seats no
/// account for — 2^53 − 1, the largest a board registers, and an undelegated
/// 2 — the session's pre-check stops startup `not_registered`, exit 1, with
/// nothing served. A flag beats its variable.
#[test]
fn the_principal_is_required_and_one_the_board_seats() {
    let fixture = Fixture::new("principal");
    for set in [None, Some("")] {
        let mut launch = Launch::new().env("SKEP_BOARD", fixture.origin()).env("SKEP_KEYSTORE", &fixture.store);
        if let Some(value) = set {
            launch = launch.env("SKEP_PRINCIPAL", value);
        }
        let (code, err) = launch.refusal();
        assert_eq!(code, Some(1), "{set:?}: {err}");
        assert!(err.contains("--principal (or SKEP_PRINCIPAL) is required"), "{set:?}: {err}");
    }
    for bad in ["abc", "-1", "1.5", "9007199254740992", "18446744073709551616"] {
        let (code, err) = Launch::over(&fixture, 1).env("SKEP_PRINCIPAL", bad).refusal();
        assert_eq!(code, Some(1), "'{bad}': {err}");
        assert!(err.contains(&format!("'{bad}' is not a principal")), "{err}");
    }
    let (_, err) = Launch::over(&fixture, 1).env("SKEP_PRINCIPAL", "0").refusal();
    assert!(!err.contains("is not a principal") && err.contains(&format!("board {} (reference ", fixture.origin())), "0, the range's floor, is a principal: startup goes on to the board: {err}");
    for unseated in ["9007199254740991", "2"] {
        let (code, err) = Launch::over(&fixture, 1).env("SKEP_PRINCIPAL", unseated).refusal();
        assert_eq!(code, Some(1), "{unseated}: {err}");
        assert!(err.contains("stopped before serving: the signed session did not open: not_registered"), "{unseated}: {err}");
    }
    let mut mcp = Launch::over(&fixture, 1).env("SKEP_PRINCIPAL", "2").args(["--principal", "1"]).spawn();
    mcp.initialize();
    assert_eq!(mcp.call_json("session_info", json!({}))["principal"], json!(1), "the flag beats the variable");
    assert!(mcp.finish().success());
}

/// The key store is required, a directory that stands, and never the person's.
///
/// Unset, set empty, or given empty by its flag, startup refuses naming the
/// setting — ~/.skep is never consulted — before any dial: an agent never
/// signs with its person's store, nor keeps its index where it was launched.
/// Set to a path that names nothing, or to a file, it is refused naming the
/// path, before any dial, and nothing is made at the path.
#[test]
fn the_key_store_is_required_and_never_the_persons_own() {
    let cases: [(&[&str], Option<&str>); 3] = [(&[], None), (&[], Some("")), (&["--dir", ""], None)];
    for (args, store) in cases {
        let mut launch = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_PRINCIPAL", "1").args(args);
        if let Some(value) = store {
            launch = launch.env("SKEP_KEYSTORE", value);
        }
        let (code, err) = launch.refusal();
        assert_eq!(code, Some(1), "{args:?} {store:?}: {err}");
        assert!(err.contains("--dir (or SKEP_KEYSTORE) is required") && err.contains("~/.skep is never consulted"), "{args:?} {store:?}: {err}");
        assert!(!err.contains("health was not read"), "refused before any dial: {err}");
    }
    let dir = TempDir::new("store-absent");
    let absent = dir.path().join("mistyped").join("store");
    let file = dir.path().join("a-file");
    std::fs::write(&file, b"").expect("a file in the store's place");
    for (store, says) in [(&absent, "cannot be read"), (&file, "is no directory")] {
        let (code, err) = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_PRINCIPAL", "1").env("SKEP_KEYSTORE", store).refusal();
        assert_eq!(code, Some(1), "{}: {err}", store.display());
        assert!(err.contains(&format!("--dir (or SKEP_KEYSTORE): '{}' {says}", store.display())), "{err}");
        assert!(!err.contains("health was not read"), "refused before any dial: {err}");
    }
    assert!(!dir.path().join("mistyped").exists(), "nothing is made at a path that names nothing");
}

/// A word the usage does not name, a flag without its value, or a flag
/// given twice, is a usage error — exit 2, the usage on stderr — never
/// ignored: a mistyped `--tools-file` must not quietly serve the embedded
/// catalog instead, nor a second `--board` quietly win.
#[test]
fn an_unknown_word_or_a_flag_without_its_value_or_given_twice_is_a_usage_error() {
    let dir = TempDir::new("usage");
    let settings = [("SKEP_BOARD", "http://127.0.0.1:1"), ("SKEP_KEYSTORE", dir.path().to_str().expect("a UTF-8 path")), ("SKEP_PRINCIPAL", "1")];
    for (args, says) in [
        (&["--tool-file", "mine.json"][..], "unknown argument '--tool-file'"),
        (&["--tools-file"][..], "--tools-file needs a value"),
        (&["--tools-file", "a.json", "--tools-file", "b.json"][..], "--tools-file is given at most once"),
        (&["--board"][..], "--board needs a value"),
        (&["--board", "http://127.0.0.1:1", "--board", "http://127.0.0.1:2"][..], "--board is given at most once"),
        (&["--principal", "1", "--principal", "2"][..], "--principal is given at most once"),
        (&["--dir"][..], "--dir needs a value"),
    ] {
        let mut launch = Launch::new().args(args);
        for (var, value) in settings {
            launch = launch.env(var, value);
        }
        let (code, err) = launch.refusal();
        assert_eq!(code, Some(2), "{args:?}: {err}");
        assert!(err.contains(says) && err.contains("usage: skep-mcp"), "{args:?}: {err}");
    }
}

/// SKEP_COMMONS set to the commons appends the commons sentence.
///
/// The instructions carry the commons sentence with the commons' address,
/// `1.1.0.1.0.1`, substituted, and the serving line names the commons. Unset,
/// the instructions are byte-identical to the tools file's.
#[test]
fn skep_commons_appends_the_commons_sentence() {
    let fixture = Fixture::new("commons");
    let file = embedded_catalog();
    let base = file["instructions"].as_str().expect("instructions").to_string();
    let template = file["commons_instructions"].as_str().expect("template").to_string();

    let commons = "1.1.0.1.0.1";
    let mut mcp = Launch::over(&fixture, 1).env("SKEP_COMMONS", commons).logged().spawn();
    let init = mcp.initialize();
    let expected = format!("{base}\n\n{}", template.replace("{addr}", commons));
    assert_eq!(init["instructions"].as_str(), Some(expected.as_str()), "the sentence is appended with the address substituted");
    assert!(expected.contains(&format!("{commons}.0.3.50")), "the defines-type address rides in the sentence: {expected}");
    let (status, log) = mcp.finish_logged();
    assert!(status.success());
    assert!(log.contains(", commons 1.1.0.1.0.1"), "the serving line names the commons:\n{log}");

    let mut mcp = Launch::over(&fixture, 1).spawn();
    let init = mcp.initialize();
    assert_eq!(init["instructions"].as_str(), Some(base.as_str()), "unset leaves the instructions byte-identical");
    assert!(mcp.finish().success());
}

/// A SKEP_COMMONS that is not the commons refuses startup naming it.
///
/// A malformed address and a well-formed address that is not the commons are
/// each refused naming the variable, the second naming the commons' one
/// address, before any dial: the board here answers nothing, and the refusal
/// is the commons' own. Set empty, it is unset, and startup goes on to the
/// board.
#[test]
fn a_skep_commons_that_is_not_the_commons_refuses_startup() {
    let dir = TempDir::new("badcommons");
    for bad in ["banana", "1..2", "0.1", "1.0", "1.0.0.1", "1.0.1.0.1.0.1.0.2", "1.0.2.0.9", "1.1.0.1.0.2"] {
        let (code, err) = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").env("SKEP_COMMONS", bad).refusal();
        assert_eq!(code, Some(1), "'{bad}' must refuse startup: {err}");
        assert!(err.contains(&format!("SKEP_COMMONS: '{bad}' is not ")), "stderr names the variable for '{bad}': {err}");
        assert!(!err.contains("health was not read"), "refused before any dial: {err}");
    }
    let (_, err) = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").env("SKEP_COMMONS", "1.0.2.0.9").refusal();
    assert!(err.contains("SKEP_COMMONS: '1.0.2.0.9' is not the commons: every board's link types are addresses in subspace 3 of 1.1.0.1.0.1"), "{err}");
    let (code, err) = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").env("SKEP_COMMONS", "").refusal();
    assert_eq!(code, Some(1), "{err}");
    assert!(!err.contains("SKEP_COMMONS:") && err.contains("no commons (SKEP_COMMONS unset)"), "set empty, it is unset: {err}");
    assert!(err.contains("stopped before serving: the board's health was not read"), "startup goes on to the board: {err}");
}

/// A variable set to bytes that are not UTF-8 is refused by name, never
/// read as unset: an unreadable SKEP_BOARD must not fall back to anything.
#[cfg(unix)]
#[test]
fn non_utf8_environment_refuses_startup() {
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("nonutf8");
    let bytes = std::ffi::OsStr::from_bytes(b"\xff");
    for var in ["SKEP_PRINCIPAL", "SKEP_BOARD", "SKEP_KEYSTORE", "SKEP_COMMONS"] {
        let (code, err) = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").env(var, bytes).refusal();
        assert_eq!(code, Some(1), "a non-UTF-8 {var} must refuse startup: {err}");
        assert!(err.contains(&format!("{var}: the value is not UTF-8 text")), "{var}: {err}");
    }
}

/// `SKEPD_URL` is read no longer, so its value is never decoded.
///
/// Set to bytes that are not UTF-8, with no board named, the missing board's
/// refusal speaks and says the old variable is set — never a refusal of the
/// old variable's own by its name.
#[cfg(unix)]
#[test]
fn skepd_url_is_never_decoded() {
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("skepd-url");
    let (code, err) = Launch::new().env("SKEPD_URL", std::ffi::OsStr::from_bytes(b"\xff")).env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").refusal();
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("--board (or SKEP_BOARD) is required") && err.contains("SKEPD_URL is set and no longer read"), "{err}");
    assert!(!err.contains("SKEPD_URL: the value is not UTF-8 text"), "{err}");
}

/// A flag set to bytes that are not UTF-8 is refused by name, never decoded.
#[cfg(unix)]
#[test]
fn a_flag_that_is_not_utf8_refuses_startup_by_name() {
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("nonutf8-flag");
    for flag in ["--principal", "--board", "--dir"] {
        let (code, err) =
            Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").arg(flag).arg(std::ffi::OsStr::from_bytes(b"\xff")).refusal();
        assert_eq!(code, Some(1), "{flag}: {err}");
        assert!(err.contains(&format!("{flag}: the value is not UTF-8 text")), "{flag}: {err}");
    }
}

/// A path is an OS string: a `--tools-file` that is not UTF-8 is read as a
/// path — here one that does not exist, a refusal naming the flag — never a
/// panic in argument parsing.
#[cfg(unix)]
#[test]
fn non_utf8_tools_file_path_is_a_path() {
    use std::os::unix::ffi::OsStrExt;
    let (code, err) = Launch::new().arg("--tools-file").arg(std::ffi::OsStr::from_bytes(b"/nonexistent/\xff.json")).refusal();
    assert_eq!(code, Some(1), "a refusal, not a panic: {err}");
    assert!(err.contains("--tools-file"), "{err}");
}

/// The catalog is checked against the dispatch's two kinds in both
/// directions before any setting or dial: a file entry the dispatch
/// doesn't know — a stranger, a ceremony's name — refuses startup naming
/// it; a dispatch tool with no file entry — a wire op, an adapter tool —
/// refuses naming it; and the undoctored file starts, then exits cleanly on
/// immediate EOF.
#[test]
fn tools_file_dispatch_drift_refuses_startup_both_directions() {
    let dir = TempDir::new("drift");
    let real = embedded_catalog();

    for stranger in ["frobnicate", "retire"] {
        let mut extra = real.clone();
        extra["tools"].as_array_mut().expect("tools").push(json!({"name": stranger, "description": "no tool of the dispatch", "inputSchema": {"type": "object"}}));
        let path = dir.path().join(format!("extra-{stranger}.json"));
        std::fs::write(&path, extra.to_string()).expect("write doctored file");
        let err = tools_file_refusal(&path);
        assert!(err.contains(stranger), "stderr names the unknown tool: {err}");
    }

    for missing in ["insert", "changes_since"] {
        let mut doctored = real.clone();
        doctored["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != missing);
        let path = dir.path().join(format!("missing-{missing}.json"));
        std::fs::write(&path, doctored.to_string()).expect("write doctored file");
        let err = tools_file_refusal(&path);
        assert!(err.contains(missing), "stderr names the uncovered tool: {err}");
    }

    let fixture = Fixture::new("drift-real");
    let path = dir.path().join("real.json");
    std::fs::write(&path, real.to_string()).expect("write real file");
    let out = Launch::over(&fixture, 1).args(["--tools-file", path.to_str().expect("utf-8 path")]).output();
    assert!(out.status.success(), "the real catalog must start: {}", String::from_utf8_lossy(&out.stderr));
}

/// A tools file is the catalog served, in place of the embedded one.
///
/// Its instructions and its tools are what `initialize` and `tools/list`
/// answer, the start says where its text differs from the catalog this
/// release embeds, and the serving line names the file it counts the tools
/// of.
#[test]
fn a_tools_file_is_the_catalog_served_in_place_of_the_embedded_one() {
    let fixture = Fixture::new("tools-file");
    let mut catalog = embedded_catalog();
    catalog["instructions"] = json!("These instructions are the tools file's own.");
    let fork = catalog["tools"].as_array_mut().expect("tools").iter_mut().find(|t| t["name"] == "fork").expect("fork");
    fork["description"] = json!("The tools file's own description of fork.");
    let path = fixture.dir.path().join("own.json");
    std::fs::write(&path, catalog.to_string()).expect("write the tools file");
    let mut mcp = Launch::over(&fixture, 1).args(["--tools-file", path.to_str().expect("a UTF-8 path")]).logged().spawn();
    assert_eq!(mcp.initialize()["instructions"], catalog["instructions"], "the file's instructions are served");
    assert_eq!(mcp.request("tools/list", json!({}))["result"]["tools"], catalog["tools"], "the file's tools are listed");
    let (status, log) = mcp.finish_logged();
    assert!(status.success(), "{status:?}\n{log}");
    assert!(log.contains(&format!("tools of the tools file {} on stdio", path.display())), "the serving line names the file:\n{log}");
    let differs = format!("the tools file {} differs from the catalog this release embeds (its instructions, and 1 of its ", path.display());
    assert!(log.contains(&differs) && log.contains("every agent is told that file's text, not this release's"), "the start says the file's text differs:\n{log}");
}

/// The adapter run to completion on `tools_file`, which startup must
/// refuse before any setting is read: its stderr, the refusal.
///
/// The refusal names the file, and the act a drifted one asks: written afresh
/// from this release's catalog, or the override dropped.
fn tools_file_refusal(tools_file: &Path) -> String {
    let (code, err) = Launch::new().args(["--tools-file", tools_file.to_str().expect("utf-8 path")]).refusal();
    assert_eq!(code, Some(1), "a drifted tools file must refuse startup: {err}");
    assert!(err.contains(&format!("the tools file {}: ", tools_file.display())), "the file named: {err}");
    assert!(err.contains("write it afresh from this release's tools.json") && err.contains("or drop --tools-file"), "the act: {err}");
    err
}

/// What an earlier run's held bursts left, and a halted held file, are said.
///
/// A burst the board refuses is held as a refused run, and stands in the
/// principal's held file once the adapter that held it has stopped: its stop
/// says it leaves one burst held, and the next start says one burst is left,
/// waiting on the agent's `resolve`. A held file a newer skep wrote halts the
/// principal's bursts at the board: the start says the file is halted and
/// why, and a burst is refused `store_halted`.
#[test]
fn an_earlier_runs_held_bursts_and_a_halted_held_file_are_said_at_the_start() {
    let fixture = Fixture::new("held-at-start");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let draft = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let refused = mcp.call_json("insert", json!({"doc": draft, "at": {"subspace": "1", "ordinal": "900000"}, "values": ["r"]}));
    assert_eq!(refused["resp"], "held", "premise: a refused run is held: {refused}");
    let (status, log) = mcp.finish_logged();
    assert!(status.success(), "{status:?}\n{log}");
    assert!(log.contains("; it leaves 1 burst held at this board (0 sent and so perhaps landed), which the next start counts"), "the stop says what it leaves held:\n{log}");
    let mut again = Launch::over(&fixture, 1).logged().spawn();
    again.initialize();
    again.log_holding(&["held: an earlier run left 1 burst held at this board (0 sent and so perhaps landed, 1 waiting on the agent's `resolve`"], Duration::from_secs(10));
    assert!(again.finish().success());
    let chains: Vec<PathBuf> = std::fs::read_dir(fixture.store.join("held")).expect("the held store").filter_map(Result::ok).map(|entry| entry.path()).filter(|path| path.is_dir()).collect();
    let [chain] = &chains[..] else { panic!("one board's held directory: {chains:?}") };
    let file = chain.join("principal-1.held");
    std::fs::write(&file, "{\"type\":\"skep-held-bursts\",\"v\":2}\n").expect("a newer skep's held file");
    let mut halted = Launch::over(&fixture, 1).logged().spawn();
    halted.initialize();
    halted.log_holding(&[&format!("held: the held file {} is halted (written by a newer skep)", file.display())], Duration::from_secs(10));
    let refusal = halted.call_error("insert", json!({"doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["s"]}));
    assert_eq!(refusal["name"], "store_halted", "{refusal}");
    assert!(halted.finish().success());
}

/// A second start over one store waits for the first adapter to end.
///
/// The key store is one directory per adapter process: a second adapter
/// started over a running one's store says the store is held, naming the first
/// by its pid, and waits before it opens anything; once the first has ended it
/// serves, its search index its own — never `busy`, as an index two processes
/// share answers.
#[test]
fn a_second_start_over_one_store_waits_for_the_first_to_end() {
    let fixture = Fixture::new("held-store");
    let mut first = Launch::over(&fixture, 1).spawn();
    first.initialize();
    let mut second = Launch::over(&fixture, 1).logged().spawn();
    let held = format!("is held by another skep-mcp process (pid {}): waiting up to 30 s for it to end", first.pid());
    second.log_holding(&[&held], Duration::from_secs(10));
    assert!(!second.log().contains("serving "), "premise: the second waits before it serves:\n{}", second.log());
    assert!(first.finish().success());
    second.initialize();
    second.log_holding(&["serving "], Duration::from_secs(30));
    let listed = second.call_json("places", json!({}));
    assert_ne!(listed["state"]["arm"], "busy", "the second's index is its own: {listed}");
    let (status, log) = second.finish_logged();
    assert!(status.success(), "{status:?}\n{log}");
    assert!(!log.contains("answers busy"), "no busy index is said:\n{log}");
}

/// A search index another process holds is said busy, naming its directory.
///
/// A dev provider over the adapter's store locks the search index and not the
/// store; the suite holds the index's lock in its place, once an adapter has
/// made the index and stopped: the next adapter serves, and its log says the
/// index answers busy — the index's directory under the store, where
/// skep-client's `SearchDir` puts it, the cause and the act.
#[test]
fn a_search_index_another_process_holds_is_said_busy_naming_its_directory() {
    use skep_client::search::{SearchDir, LOCK_NAME};
    let fixture = Fixture::new("busy-index");
    let mut first = Launch::over(&fixture, 1).spawn();
    first.initialize();
    // Answered on the board's feed thread, which mounts the index first.
    let listed = first.call_json("places", json!({}));
    assert_ne!(listed["state"]["arm"], "busy", "premise: the first adapter mounts the index: {listed}");
    assert!(first.finish().success());
    let index = SearchDir::new(&fixture.store).root().to_path_buf();
    let boards: Vec<PathBuf> = std::fs::read_dir(&index).expect("the index's root").filter_map(Result::ok).map(|entry| entry.path()).filter(|path| path.is_dir()).collect();
    let [board] = &boards[..] else { panic!("one board's index directory: {boards:?}") };
    let lock = std::fs::OpenOptions::new().read(true).write(true).open(board.join(LOCK_NAME)).expect("the index's lock file");
    lock.try_lock().expect("the suite holds the index's lock in a dev provider's place");
    let mut second = Launch::over(&fixture, 1).logged().spawn();
    second.initialize();
    let log = second.log_holding(&[&format!("the search index at {} answers busy: another process holds this directory", index.display())], Duration::from_secs(10));
    assert!(log.contains("stop the other and start this one again"), "the act:\n{log}");
    assert!(second.finish().success());
    drop(lock);
}

/// A key store this process cannot write is refused before any dial.
///
/// The shell keeps its search index and its held bursts under the store, and
/// a burst held where it cannot be written is lost at the process's end: a
/// store whose mode lets this process read it and not write it is refused
/// naming the path, exit 1, with no health read tried. A process every mode
/// lets write — one run as root — proves nothing here, and the case passes.
#[cfg(unix)]
#[test]
fn a_key_store_this_process_cannot_write_is_refused_before_any_dial() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("store-unwritable");
    let store = dir.path().join("store");
    std::fs::create_dir(&store).expect("the store");
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500)).expect("the store made read-only");
    let writes_anyway = std::fs::write(store.join("probe"), b"").is_ok();
    let outcome = (!writes_anyway).then(|| Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_PRINCIPAL", "1").env("SKEP_KEYSTORE", &store).refusal());
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).expect("the store's mode restored");
    let Some((code, err)) = outcome else { return };
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains(&format!("--dir (or SKEP_KEYSTORE): '{}' cannot be written (", store.display())), "{err}");
    assert!(err.contains("a burst held where it cannot be written is lost at the process's end"), "why: {err}");
    assert!(!err.contains("health was not read"), "refused before any dial: {err}");
}

/// The start names each setting in force and where it came from.
///
/// One `settings:` line, said before the board is dialed, names the board,
/// the store, the principal, the catalog and the commons, each with its
/// source; a flag given beside its variable set to another value is said to
/// beat it; `SKEPD_URL` set beside a named board is said to be read no
/// longer; a store that is the person's own, `~/.skep`, is warned of; and a
/// store given as a relative path is named absolute, beside the path given
/// and the working directory it was read against.
#[test]
fn the_start_names_each_setting_in_force_and_where_it_came_from() {
    let home = TempDir::new("settings-home");
    let store = home.path().join(".skep");
    std::fs::create_dir(&store).expect("the person's own store");
    let launch = Launch::new().env("HOME", home.path()).env("SKEP_BOARD", "http://127.0.0.1:2").env("SKEPD_URL", "http://127.0.0.1:3").env("SKEP_PRINCIPAL", "1");
    let (code, err) = launch.env("SKEP_KEYSTORE", &store).args(["--board", "http://127.0.0.1:1"]).refusal();
    assert_eq!(code, Some(1), "the unanswering board stops it: {err}");
    let settings = format!(
        "settings: board http://127.0.0.1:1 (--board), store {} (SKEP_KEYSTORE), principal 1 (SKEP_PRINCIPAL), the embedded catalog, no commons (SKEP_COMMONS unset) — each read once, at this start, save the store's key, which the shell selects anew at each session it opens",
        store.display()
    );
    let said = err.find(&settings).unwrap_or_else(|| panic!("the settings line: {err}"));
    let dialed = err.find("stopped before serving: the board's health was not read").unwrap_or_else(|| panic!("the board's own stop: {err}"));
    assert!(said < dialed, "the settings said before the board is dialed: {err}");
    assert!(err.contains("--board 'http://127.0.0.1:1' beats SKEP_BOARD, set beside it to 'http://127.0.0.1:2': the variable is not read"), "{err}");
    assert!(err.contains("SKEPD_URL is set and no longer read: the board is http://127.0.0.1:1 (--board)"), "{err}");
    assert!(err.contains(&format!("warning: --dir (or SKEP_KEYSTORE) '{}' is the person's own store, ~/.skep", store.display())), "{err}");
    let working = std::fs::canonicalize(home.path()).expect("the working directory");
    let (_, err) = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_PRINCIPAL", "1").args(["--dir", ".skep"]).current_dir(home.path()).refusal();
    let given = format!("store {} (--dir, given as .skep against the working directory {})", working.join(".skep").display(), working.display());
    assert!(err.contains(&given), "a relative store, named absolute: {err}");
}
