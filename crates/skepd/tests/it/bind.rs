//! THE BIND IS THE ADDRESS GIVEN (AUTH-4.57 (a); the deployment ruling: the
//! daemon gains a bind flag and listens on the container's address in the
//! hosted image, the flag's DEFAULT loopback), judged on the REAL BINARY in
//! `open.rs`'s harness — spawned with its two streams piped and read on
//! threads of the test's own, killed and reaped by the [`Spawned`] guard on
//! a passing claim's return and a failing one's unwind alike:
//!
//! * `--bind 0.0.0.0 --port 0` SERVES: `GET /health` over `127.0.0.1`
//!   answers `ok`, and the serving line names the bound address and the
//!   bound port, `skepd: serving http://0.0.0.0:{port}/ …` — both read back
//!   off the socket, so a line that printed the default whatever was bound,
//!   and a bind that ignored its address, fail here alike. The client
//!   connects over loopback and needs no second interface: this exercises
//!   the BIND, not the peer rule, whose Remote arm no socket-level test of
//!   this gate reaches (the smoke script's published port is that arm's
//!   first real socket; `auth/session/tests.rs` its in-gate cells).
//! * The variable binds the same: `SKEPD_BIND=0.0.0.0` on the command serves
//!   over loopback with the same line, and `/health`'s `auth` object carries
//!   its four members and nothing of the bind — the address enters no origin
//!   set, and the serving line is its one echo.
//! * A HELD WILDCARD PORT refuses with the address NAMED: the test holds
//!   `0.0.0.0:P`; the binary on `--bind 0.0.0.0 --port P` exits 1 at once,
//!   stderr the one line `skepd: bind 0.0.0.0:P: …`, nothing on stdout, the
//!   data directory never created.
//! * The DEFAULT is what every other suite runs under: with no flag the line
//!   reads `http://127.0.0.1:{port}/`, byte for byte as before the flag.

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::process::Child;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::common::{get, json};
use crate::open::{skepd, Spawned, Stderr, PATIENCE};

/// The serving line — stdout's first line — read under a deadline on a
/// thread, so a child that never serves fails by name; the WHOLE line, since
/// the address it names is what this suite judges.
fn serving_line(child: &mut Child, within: Duration) -> String {
    let stdout = child.stdout.take().expect("the child's stdout is piped");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    rx.recv_timeout(within).unwrap_or_else(|_| panic!("no serving line within {within:?}"))
}

/// The port off a serving line that names `addr` — `skepd: serving
/// http://{addr}:{port}/ …` — or a panic quoting the line where it names
/// another address.
fn port_named_after(line: &str, addr: &str) -> u16 {
    let prefix = format!("skepd: serving http://{addr}:");
    line.strip_prefix(&prefix)
        .and_then(|rest| rest.split('/').next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or_else(|| {
            panic!("FINDING (the bind): the serving line does not read {prefix:?}…: {line:?}")
        })
}

/// A binary over a fresh directory with `flags` after the floor's worker
/// count and `env` on the command: the child, its stderr and the whole
/// serving line.
fn serve_with(
    dir: &std::path::Path,
    flags: &[&str],
    env: &[(&str, &str)],
) -> (Spawned, Stderr, String) {
    let workers = skepd::MIN_WORKERS.to_string();
    let mut args = vec!["--port", "0", "--workers", workers.as_str()];
    args.extend_from_slice(flags);
    let mut cmd = skepd(dir, &args);
    for (name, value) in env {
        cmd.env(name, value);
    }
    let mut child = Spawned::launch(&mut cmd);
    let stderr = Stderr::of(&mut child.child);
    let line = serving_line(&mut child.child, PATIENCE);
    (child, stderr, line)
}

/// THE WILDCARD BIND SERVES OVER LOOPBACK, AND THE LINE NAMES IT: the binary
/// on `--bind 0.0.0.0 --port 0` writes `skepd: serving http://0.0.0.0:{port}/
/// …`, and `GET /health` over `127.0.0.1` at that port answers `ok` — the
/// bound address read back off the socket, so neither a line printing the
/// default nor a bind ignoring its address passes. Then the same by the
/// variable, `SKEPD_BIND=0.0.0.0`, with the health answer's `auth` object
/// its four members and the body carrying nothing of the bind.
#[test]
fn the_binary_bound_to_the_wildcard_serves_over_loopback_and_its_line_names_the_address() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // BY THE FLAG.
    let (mut by_flag, _stderr, line) =
        serve_with(&tmp.path().join("flag"), &["--bind", "0.0.0.0"], &[]);
    let port = port_named_after(&line, "0.0.0.0");
    assert!(
        line.contains(&format!(" workers {}", skepd::MIN_WORKERS)),
        "the rest of the line stands as it was: {line:?}"
    );
    let (st, body) = get(port, "/health");
    assert_eq!(
        (st, json(&body)["ok"].as_bool()),
        (200, Some(true)),
        "served over 127.0.0.1 at the port the line named: {}",
        String::from_utf8_lossy(&body)
    );
    by_flag.kill();

    // BY THE VARIABLE — and nothing of the bind on the wire.
    let (mut by_variable, _stderr, line) =
        serve_with(&tmp.path().join("variable"), &[], &[("SKEPD_BIND", "0.0.0.0")]);
    let port = port_named_after(&line, "0.0.0.0");
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let v = json(&body);
    assert_eq!(v["ok"], serde_json::Value::Bool(true));
    let auth = v["auth"].as_object().expect("the auth object");
    let mut members: Vec<&str> = auth.keys().map(String::as_str).collect();
    members.sort_unstable();
    assert_eq!(
        members,
        ["claimant", "local_trust", "origins", "signed_origins"],
        "the auth object is its four members, the bind among none of them"
    );
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains("0.0.0.0"),
        "the bind enters no set and /health echoes nothing of it: {text}"
    );
    assert_eq!(
        v["auth"]["origins"],
        serde_json::json!([
            format!("http://127.0.0.1:{port}"),
            format!("http://[::1]:{port}"),
            format!("http://localhost:{port}")
        ]),
        "the bare set is the bound PORT's three loopback defaults, whatever the address"
    );
    by_variable.kill();
}

/// THE DEFAULT IS LOOPBACK, BYTE FOR BYTE: with no flag and no variable the
/// serving line reads `skepd: serving http://127.0.0.1:{port}/ …`, the line
/// every other suite parses — so the flag changed nothing for a notebook.
#[test]
fn the_binary_with_no_bind_serves_the_loopback_line_as_before() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut child, _stderr, line) = serve_with(&tmp.path().join("data"), &[], &[]);
    let port = port_named_after(&line, "127.0.0.1");
    let (st, body) = get(port, "/health");
    assert_eq!(
        (st, json(&body)["ok"].as_bool()),
        (200, Some(true)),
        "{}",
        String::from_utf8_lossy(&body)
    );
    child.kill();
}

/// A HELD WILDCARD PORT REFUSES WITH THE ADDRESS NAMED (§4 row 22's refusal
/// under the flag): the test holds `0.0.0.0:P`; the binary on `--bind
/// 0.0.0.0 --port P` over a fresh directory exits 1 with stderr the one bind
/// line, `skepd: bind 0.0.0.0:P: ` and the OS's text, nothing on stdout, and
/// the data directory never created.
#[test]
fn a_held_wildcard_port_refuses_with_the_bind_line_naming_the_address() {
    let held = TcpListener::bind(("0.0.0.0", 0)).expect("hold a wildcard port");
    let port = held.local_addr().expect("the held port").port();
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let mut child =
        Spawned::launch(&mut skepd(&dir, &["--bind", "0.0.0.0", "--port", &port.to_string()]));
    let status = child.wait_within(PATIENCE);
    let mut stderr = String::new();
    child.child.stderr.take().expect("piped").read_to_string(&mut stderr).expect("read stderr");
    let mut stdout = String::new();
    child.child.stdout.take().expect("piped").read_to_string(&mut stdout).expect("read stdout");
    assert_eq!(status.code(), Some(1), "exit 1; stderr: {stderr:?}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 1, "stderr is the bind line alone: {stderr:?}");
    let prefix = format!("skepd: bind 0.0.0.0:{port}: ");
    assert!(
        lines[0].starts_with(&prefix),
        "FINDING (the bind): the refusal does not name the address it asked for: {stderr:?}"
    );
    assert!(lines[0].len() > prefix.len(), "the OS's text: {stderr:?}");
    assert!(stdout.is_empty(), "no serving line: {stdout:?}");
    assert!(!dir.exists(), "the data directory was created — an open ran before the bind refused");
    drop(held);
}
