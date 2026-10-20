//! Startup: what the adapter reads before it serves, and what it refuses.
//!
//! The flags answered before anything else is read (`--version`, `--help`), and
//! a usage error; each setting refused by name where it is missing or
//! malformed — the principal, the board, the key store, the commons, a value
//! that is not UTF-8 — and served where it is given: a flag beating its
//! variable, the commons sentence, a tools file in the embedded catalog's place
//! and a drifted one refused; and the board's refusals of the open, a halted
//! board's line, the log inert and no token in it. Most run the built binary
//! with no board, or a stand-in one answering what a real board never does;
//! the rest over a claimed board (`common`'s `Fixture`). The fence's startup
//! cases — no key, `SKEP_BOARD`, a retired key's relaunch — are `agent.rs`'s.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::json;
use skep_client::store::{FileStore, KeySelector, KeyStore, Purpose};

use crate::common::{embedded_catalog, Fixture, Launch, TempDir, CLAIMANT_ACCOUNT, VARIABLES};

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

/// A halted board is said at startup with what a write then meets.
///
/// A stand-in board's `/health` reports its writes halted; the adapter says
/// the board's line before its keyless store stops startup, and the line says
/// what a write meets through the shell until the board restarts: a burst
/// held for the shell's resend, any other write refused `poisoned`.
#[test]
fn a_halted_board_is_said_at_startup_with_what_a_write_then_meets() {
    let health = r#"{"ok":true,"log_position":0,"auth":{"claimant":"1.0.1","local_trust":false},"writes":{"halted":true}}"#;
    let port = stand_in(move |_, _| answered(health));
    let keyless = TempDir::new("halted");
    let (code, err) = Launch::new().env("SKEP_BOARD", format!("http://127.0.0.1:{port}")).env("SKEP_KEYSTORE", keyless.path()).env("SKEP_PRINCIPAL", "1").refusal();
    assert_eq!(code, Some(1), "the keyless store stops startup: {err}");
    assert!(err.contains("; writes HALTED until the board restarts: a burst is held for the shell's resend, and any other write refused `poisoned`"), "the halt said, and what a write meets: {err}");
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
    let dir = TempDir::new("unreadable-session");
    let store = FileStore::open(dir.path());
    let id = store.generate(None).expect("keygen");
    let key = store.select(&KeySelector::Path(&store.key_path(&id.0)), Purpose::Read).expect("the key's facts");
    let enrolled = json!({"resp": "key_set", "as_of": 0, "enrolled": [{"alg": key.public.alg(), "key": key.public.to_hex(), "fingerprint": key.fingerprint.to_hex(), "anchor": false}], "retired": []});
    let (opened, opens) = std::sync::mpsc::channel::<()>();
    let port = stand_in(move |head, body| {
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
            let _ = opened.send(());
            format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{{\"principal\":1,\"session\":\"{TOKEN}\"")
        } else {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"error\":\"not_found\"}".to_string()
        }
    });
    let (code, err) = Launch::new().env("SKEP_BOARD", format!("http://127.0.0.1:{port}")).env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").refusal();
    assert!(opens.try_recv().is_ok(), "premise: the open's POST /session was answered:\n{err}");
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("stopped before serving: the signed session did not open: unreachable"), "{err}");
    assert!(!err.contains(TOKEN), "the session's token reaches the log:\n{err}");
}

/// A board the adapter cannot reach stops startup, and nothing is served.
///
/// The session cannot open: exit 1, the plain line naming the stop, the
/// refusal's kind and the board, nothing on stdout. Port 1 sits below 1024,
/// where no unprivileged process can listen, so the connect is refused.
#[test]
fn a_board_that_does_not_answer_stops_startup() {
    let dir = TempDir::new("noboard");
    let out = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").output();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("stopped before serving: the board's health was not read: unreachable"), "{err}");
    assert!(err.contains("http://127.0.0.1:1"), "the board named: {err}");
    assert!(out.stdout.is_empty(), "nothing served: {:?}", String::from_utf8_lossy(&out.stdout));
}

/// The principal is required and one the board seats: unset, startup
/// refuses by name; set to anything that is no integer from 0 to 2^53 − 1,
/// it refuses quoting the value; set to an id the board seats no account
/// for — 2^53 − 1, the largest a board registers, and an undelegated 2 —
/// the session's pre-check stops startup `not_registered`, exit 1, with
/// nothing served. A flag beats its variable.
#[test]
fn the_principal_is_required_and_one_the_board_seats() {
    let fixture = Fixture::new("principal");
    let (code, err) = Launch::new().env("SKEP_BOARD", fixture.origin()).env("SKEP_KEYSTORE", &fixture.store).refusal();
    assert_eq!(code, Some(1), "unset: {err}");
    assert!(err.contains("--principal (or SKEP_PRINCIPAL) is required"), "{err}");
    for bad in ["", "abc", "-1", "1.5", "9007199254740992", "18446744073709551616"] {
        let (code, err) = Launch::over(&fixture, 1).env("SKEP_PRINCIPAL", bad).refusal();
        assert_eq!(code, Some(1), "'{bad}': {err}");
        assert!(err.contains(&format!("'{bad}' is not a principal")), "{err}");
    }
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

/// The key store is required, and never the person's own.
///
/// Unset, set empty, or given empty by its flag, startup refuses naming the
/// setting — ~/.skep is never consulted — before any dial: an agent never
/// signs with its person's store, nor keeps its index where it was launched.
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

/// SKEP_COMMONS set: the instructions carry the commons sentence with the
/// address substituted, and the serving line names the commons. Unset:
/// byte-identical to the tools file's instructions.
#[test]
fn skep_commons_appends_the_commons_sentence() {
    let fixture = Fixture::new("commons");
    let file = embedded_catalog();
    let base = file["instructions"].as_str().expect("instructions").to_string();
    let template = file["commons_instructions"].as_str().expect("template").to_string();

    let commons = "1.0.2.0.9";
    let mut mcp = Launch::over(&fixture, 1).env("SKEP_COMMONS", commons).logged().spawn();
    let init = mcp.initialize();
    let expected = format!("{base}\n\n{}", template.replace("{addr}", commons));
    assert_eq!(init["instructions"].as_str(), Some(expected.as_str()), "the sentence is appended with the address substituted");
    assert!(expected.contains(&format!("{commons}.0.3.50")), "the defines-type address rides in the sentence: {expected}");
    let (status, log) = mcp.finish_logged();
    assert!(status.success());
    assert!(log.contains(", commons 1.0.2.0.9"), "the serving line names the commons:\n{log}");

    let mut mcp = Launch::over(&fixture, 1).spawn();
    let init = mcp.initialize();
    assert_eq!(init["instructions"].as_str(), Some(base.as_str()), "unset leaves the instructions byte-identical");
    assert!(mcp.finish().success());
}

/// A malformed SKEP_COMMONS refuses startup naming the variable — before
/// any dial: the board here answers nothing, and the refusal is the
/// commons' own.
#[test]
fn malformed_skep_commons_refuses_startup() {
    let dir = TempDir::new("badcommons");
    for bad in ["", "banana", "1..2", "0.1", "1.0", "1.0.0.1", "1.0.1.0.1.0.1.0.2"] {
        let (code, err) = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").env("SKEP_COMMONS", bad).refusal();
        assert_eq!(code, Some(1), "'{bad}' must refuse startup: {err}");
        assert!(err.contains("SKEP_COMMONS"), "stderr names the variable for '{bad}': {err}");
        assert!(!err.contains("health was not read"), "refused before any dial: {err}");
    }
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
#[test]
fn a_tools_file_is_the_catalog_served_in_place_of_the_embedded_one() {
    let fixture = Fixture::new("tools-file");
    let mut catalog = embedded_catalog();
    catalog["instructions"] = json!("These instructions are the tools file's own.");
    let fork = catalog["tools"].as_array_mut().expect("tools").iter_mut().find(|t| t["name"] == "fork").expect("fork");
    fork["description"] = json!("The tools file's own description of fork.");
    let path = fixture.dir.path().join("own.json");
    std::fs::write(&path, catalog.to_string()).expect("write the tools file");
    let mut mcp = Launch::over(&fixture, 1).args(["--tools-file", path.to_str().expect("a UTF-8 path")]).spawn();
    assert_eq!(mcp.initialize()["instructions"], catalog["instructions"], "the file's instructions are served");
    assert_eq!(mcp.request("tools/list", json!({}))["result"]["tools"], catalog["tools"], "the file's tools are listed");
    assert!(mcp.finish().success());
}

/// The adapter run to completion on `tools_file`, which startup must
/// refuse before any setting is read: its stderr, the refusal.
fn tools_file_refusal(tools_file: &Path) -> String {
    let (code, err) = Launch::new().args(["--tools-file", tools_file.to_str().expect("utf-8 path")]).refusal();
    assert_eq!(code, Some(1), "a drifted tools file must refuse startup: {err}");
    assert!(err.contains("tools file:"), "{err}");
    err
}
