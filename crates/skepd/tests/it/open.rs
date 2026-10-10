//! THE OPEN's ORDER AND THE EXITS (`operations.md` §0 facts 1 and 10; §1.1
//! rows 3 and 41, m7 and m16; §3.1 step 3; §4 rows 22 and 32), judged on
//! the REAL BINARY: spawned as `hazard.rs` spawns it, on `--port 0` or a
//! port the test holds, its two streams piped and read on threads of the
//! test's own, and ALWAYS killed and reaped before a claim returns, pass or
//! fail — the [`Spawned`] guard — so a red leaks no daemon.
//!
//! * A HELD PORT refuses before the open: the bind line, exit 1, in
//!   milliseconds, and the data directory is never created — no
//!   `kernel.lock`, nothing read, nothing written.
//! * THE OPEN's THREE LINES, in order: `open: version {v}; this build reads
//!   journal format {SKJ4}, checkpoint format {SKC4} and world format
//!   {0x…}` is the first line on stderr — the build's version and the
//!   three format stamps, each from its crate's constant — `open: data-dir
//!   {path}` the second, and `open: recovered from {checkpoint.n |
//!   genesis}, {k} commits replayed, in {d} ms` stands on stderr before the
//!   serving line — `{k}` the kernel's count across a reopen with no
//!   checkpoint and one with a checkpoint at a known position.
//! * THE HOOK: a worker's panic inside its handler's catch is ONE prefixed,
//!   timed `failure:` line naming `skepd-worker` and the site, nothing of
//!   Rust's own hook's text, and the worker serves its next request.
//! * THE WORKERS' END: the floor's workers, a panic past the catch in each
//!   after its one reply — the hook's line per death, then `failure: every
//!   worker thread has ended; the board serves nothing`, and exit 1.
//! * THE SIX LINES SURVIVE A LOST READER: a stdout with no reader costs the
//!   serving line and never the daemon, which serves on; a stderr with no
//!   reader costs a refusal's line and never its exit code — 2 stays 2, 1
//!   stays 1, never 101.
//! * THE OPEN's-REPORT `auth:` LINE (`operations.md` §1.1 m14): after the
//!   bind and the warnings, `open: auth: {mode} (--local-trust {on|off},
//!   {source}); configured origins {list | none}; signed origins {list}` on
//!   every start — an unclaimed board under the defaults, a board claimed
//!   in a prior run started ENFORCING by flag, and the same board started
//!   PERMISSIVE by its variable.
//! * ROWS 8 AND 19 NAME THEIR SOURCE: `media uploads: … ({source})` and
//!   `node prefix {p} ({source}): …` read the arm that set each — the flag,
//!   the variable on the command, or the default.
//!
//! The daemon's fault door (`Daemon::panic_the_next_worker`) reaches the
//! child through the variable `main.rs` reads under `test-hooks`, the
//! feature every test build compiles the binary with.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::common::{
    acked_addr, claim_board, expect_resp, get, json, op, open_session, parse_response,
    spawn_unclaimed, T_ENROLL,
};

/// THE WORKER FAULT's VARIABLE — the binary's test door (`main.rs`, read
/// under `test-hooks` alone): its value names the arm, `inside` the
/// handler's catch or `outside` it, once, or `every` — the outside arm's
/// panic in every worker that reaches it.
const WORKER_FAULT: &str = "SKEPD_TEST_WORKER_FAULT";

/// How long a claim waits for the binary to serve, to say a line or to
/// exit: an open on a fresh directory is a fraction of a second and a
/// refusal milliseconds, so a minute is the room machine weather gets.
pub(crate) const PATIENCE: Duration = Duration::from_secs(60);

/// THE REFUSAL's CEILING (§4 row 22, "milliseconds, not after a minute's
/// open"): what a held port's refusal may take from spawn to exit. The act
/// it bounds is a spawn, a parse and a refused bind — tens of milliseconds
/// idle, a second or two under this machine's load — and what it must NOT
/// contain is an open, sixty seconds at ten million positions and never
/// under a tenth of one here; ten seconds is an order of magnitude above
/// the act and well under the open the order exists to skip. The open's
/// absence is proved structurally beside it — no directory was created —
/// so the bound is loose on purpose: a flaky bound is wrong, a loose one is
/// honest. The figure is printed for the record.
const REFUSAL_CEILING: Duration = Duration::from_secs(10);

/// The binary over `dir` with `flags` after `--data-dir`, both streams
/// piped — what every spawn here starts from.
pub(crate) fn skepd(dir: &Path, flags: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_skepd"));
    cmd.arg("--data-dir").arg(dir).args(flags).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd
}

/// A pipe whose read end is already gone: a child handed its write end has
/// a stream with NO reader from its first byte, so every write on it fails
/// `EPIPE` — deterministically, not by a race with the child's first line.
fn reader_less_pipe() -> io::PipeWriter {
    let (reader, writer) = io::pipe().expect("a pipe");
    drop(reader);
    writer
}

/// A spawned binary, KILLED AND REAPED when dropped — on a passing claim's
/// return and on a failing one's unwind alike — so no red leaks a daemon.
pub(crate) struct Spawned {
    pub(crate) child: Child,
}

impl Spawned {
    pub(crate) fn launch(cmd: &mut Command) -> Spawned {
        Spawned { child: cmd.spawn().expect("spawn the skepd binary") }
    }

    /// The child's exit, polled under a deadline: a wedge fails by name,
    /// and the guard then kills it.
    pub(crate) fn wait_within(&mut self, within: Duration) -> ExitStatus {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().expect("the child's state") {
                return status;
            }
            assert!(Instant::now() < deadline, "the child did not exit within {within:?}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Kill the child and answer its exit — by the signal, where it was
    /// still running.
    pub(crate) fn kill(&mut self) -> ExitStatus {
        let _ = self.child.kill();
        self.child.wait().expect("reap the child")
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The child's stderr, read on a thread of this test's: every line is sent
/// down a channel as it arrives and kept here as it is received, so a claim
/// waits for a line by its words under a deadline, and reads the whole
/// stream once the child is gone.
pub(crate) struct Stderr {
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Stderr {
    pub(crate) fn of(child: &mut Child) -> Stderr {
        let stderr = child.stderr.take().expect("the child's stderr is piped");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Stderr { lines: rx, seen: Vec::new() }
    }

    /// The next line `wanted` admits, every line before it kept; past
    /// `within` with none, or the stream closed first, a panic naming
    /// `what` and what was read.
    pub(crate) fn wait_for(&mut self, what: &str, within: Duration, wanted: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let hit = wanted(&line);
                    self.seen.push(line);
                    if hit {
                        return self.seen.last().expect("just kept").clone();
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    panic!("no {what} within {within:?}; stderr so far:\n{}", self.seen.join("\n"))
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
                    "the child's stderr closed before {what}; stderr:\n{}",
                    self.seen.join("\n")
                ),
            }
        }
    }

    /// Every line, to the stream's close — read once the child is gone.
    pub(crate) fn whole(mut self) -> Vec<String> {
        while let Ok(line) = self.lines.recv() {
            self.seen.push(line);
        }
        self.seen
    }
}

/// The grammar's head on a line — `skepd: {RFC 3339 UTC to the millisecond}
/// {class}: ` — and what follows it, or `None` where the line is not a
/// timed line of `class`.
pub(crate) fn after_the_head<'a>(line: &'a str, class: &str) -> Option<&'a str> {
    let rest = line.strip_prefix("skepd: ")?;
    let (time, rest) = rest.split_once(' ')?;
    let timed = time.len() == 24 && time.ends_with('Z') && time.as_bytes()[10] == b'T';
    if !timed {
        return None;
    }
    rest.strip_prefix(class)?.strip_prefix(": ")
}

/// The port off the serving line — stdout's first line, as `hazard.rs`
/// reads it — under a deadline on a thread, so a child that never serves
/// fails by name rather than hanging the claim.
pub(crate) fn serving_port(child: &mut Child, within: Duration) -> u16 {
    let stdout = child.stdout.take().expect("the child's stdout is piped");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx.recv_timeout(within).unwrap_or_else(|_| panic!("no serving line within {within:?}"));
    line.split_once("http://127.0.0.1:")
        .and_then(|(_, rest)| rest.split('/').next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no port in skepd's serving line {line:?}"))
}

/// A binary serving over `dir`, its open read: the child, still running;
/// its stderr, read up to the recovery's landing; the port; and the open's
/// three lines after their heads.
struct Served {
    child: Spawned,
    stderr: Stderr,
    port: u16,
    version_line: String,
    data_dir_line: String,
    recovered_line: String,
}

/// Spawn the binary over `dir` on `--port 0` with the floor's workers
/// (`skepd::MIN_WORKERS`, the count the parse admits) and `env` set, read
/// the serving line off stdout FIRST — the binary writes it only once the
/// open's report has reached the stream — then the open's three lines off
/// stderr: the version line as the first line of the stream, the
/// directory's line as the second, and the recovery's landing after them.
fn serve_and_read_the_open(dir: &Path, env: &[(&str, &str)]) -> Served {
    serve_and_read_the_open_with(dir, &[], env)
}

/// [`serve_and_read_the_open`] with `flags` after the port and the worker
/// count — the setting flags whose lines the open's report names.
fn serve_and_read_the_open_with(dir: &Path, flags: &[&str], env: &[(&str, &str)]) -> Served {
    let workers = skepd::MIN_WORKERS.to_string();
    let mut args = vec!["--port", "0", "--workers", workers.as_str()];
    args.extend_from_slice(flags);
    let mut cmd = skepd(dir, &args);
    for (name, value) in env {
        cmd.env(name, value);
    }
    let mut child = Spawned::launch(&mut cmd);
    let mut stderr = Stderr::of(&mut child.child);
    let port = serving_port(&mut child.child, PATIENCE);
    let recovered = stderr.wait_for("the recovery's landing", Duration::from_secs(5), |l| {
        after_the_head(l, "open").is_some_and(|said| said.starts_with("recovered from "))
    });
    let first = stderr.seen.first().expect("a line was read").clone();
    let version_line = after_the_head(&first, "open")
        .filter(|said| said.starts_with("version "))
        .unwrap_or_else(|| {
            panic!("the first line on stderr is not the open's version line: {first:?}")
        })
        .to_string();
    let second = stderr.seen.get(1).expect("a second line was read").clone();
    let data_dir_line = after_the_head(&second, "open")
        .filter(|said| said.starts_with("data-dir "))
        .unwrap_or_else(|| {
            panic!("the second line on stderr is not the open's directory line: {second:?}")
        })
        .to_string();
    let recovered_line =
        after_the_head(&recovered, "open").expect("the landing's head").to_string();
    Served { child, stderr, port, version_line, data_dir_line, recovered_line }
}

/// A stderr line of `class` whose text opens with `prefix`.
fn said(line: &str, class: &str, prefix: &str) -> bool {
    after_the_head(line, class).is_some_and(|text| text.starts_with(prefix))
}

/// The text after the head of the first line of `class` opening with
/// `prefix`, awaited on `stderr`.
fn await_said(stderr: &mut Stderr, class: &str, prefix: &str) -> String {
    let line = stderr.wait_for(prefix, Duration::from_secs(10), |l| said(l, class, prefix));
    after_the_head(&line, class).expect("the awaited head").to_string()
}

/// A binary serving over `dir` on a port RESERVED for it — bound and
/// released here, so a flag can name it (`--origin` carries the port) —
/// with the floor's workers, `flags(port)` after the port and the count,
/// and `env` on the command; retried on a fresh port where another process
/// took the reserved one between the release and the child's bind, as the
/// lost reader's claim retries. The child, its stderr read up to its first
/// line, and the port off the serving line.
fn serve_on_a_reserved_port(
    dir: &Path,
    flags: impl Fn(u16) -> Vec<String>,
    env: &[(&str, &str)],
) -> (Spawned, Stderr, u16) {
    const ATTEMPTS: usize = 12;
    for _ in 0..ATTEMPTS {
        let reserved = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a port");
        let port = reserved.local_addr().expect("the port").port();
        drop(reserved);
        let mut args = vec![
            "--port".to_string(),
            port.to_string(),
            "--workers".into(),
            skepd::MIN_WORKERS.to_string(),
        ];
        args.extend(flags(port));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut cmd = skepd(dir, &args);
        for (name, value) in env {
            cmd.env(name, value);
        }
        let mut child = Spawned::launch(&mut cmd);
        let mut stderr = Stderr::of(&mut child.child);
        let first = stderr.wait_for("the first line", PATIENCE, |_| true);
        if first.starts_with(&format!("skepd: bind 127.0.0.1:{port}: ")) {
            continue;
        }
        assert!(after_the_head(&first, "open").is_some(), "the open's first line: {first:?}");
        let served = serving_port(&mut child.child, PATIENCE);
        assert_eq!(served, port, "the serving line names the reserved port");
        return (child, stderr, port);
    }
    panic!("the binary bound a reserved port within no {ATTEMPTS} attempts")
}

/// The landing's figures off its words — `recovered from {base}, {k}
/// commits replayed, in {d} ms` — as (base, k, d).
fn recovered_figures(line: &str) -> (String, u64, u64) {
    let rest = line.strip_prefix("recovered from ").unwrap_or_else(|| panic!("{line:?}"));
    let (base, rest) = rest.split_once(", ").unwrap_or_else(|| panic!("{line:?}"));
    let (replayed, rest) = rest.split_once(" commits replayed, in ").unwrap_or_else(|| panic!("{line:?}"));
    let duration = rest.strip_suffix(" ms").unwrap_or_else(|| panic!("{line:?}"));
    (
        base.to_string(),
        replayed.parse().unwrap_or_else(|_| panic!("{line:?}")),
        duration.parse().unwrap_or_else(|_| panic!("{line:?}")),
    )
}

/// An account's home over the wire on an unclaimed board — TWO commits,
/// the delegate from 0 and the home's mint by principal 1 (the one mint an
/// unclaimed board admits; every later mint waits on the claim) — and the
/// session the home's writes ride.
pub(crate) fn delegate_a_home(port: u16) -> (String, String) {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(port, Some(&boot), &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#));
    let account = acked_addr(&v);
    let session = open_session(port, 1);
    let v = op(
        port,
        Some(&session),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    );
    (acked_addr(&v), session)
}

/// The commits a home takes before the claim, as the hazard suite makes
/// them: one declared deposit per ordinal from `first`, `n` of them — `n`
/// commits, and no head writer's among them on an unclaimed board.
fn insert_into_the_home(port: u16, session: &str, home: &str, first: u64, n: u64) {
    for ordinal in first..first + n {
        let v = op(
            port,
            Some(session),
            &format!(
                r#"{{"op":"insert","doc":"{home}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":["x"],"deposit":"{T_ENROLL}"}}"#
            ),
        );
        acked_addr(&v);
    }
}

/// The commits above `position` as the daemon's own feed testifies to them
/// to a guest — `GET /changes?since={position}`, every row one commit the
/// guest's class may see — each as `{op} at {position}`: the independent
/// count the landing's `{k}` is held to where no commit is masked, which
/// is a board the head writer has not written on.
fn commits_above(port: u16, position: u64) -> Vec<String> {
    let (st, body) = get(port, &format!("/changes?since={position}"));
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let v = json(&body);
    assert_eq!(v["more"], serde_json::Value::Bool(false), "one page: {v}");
    v["changes"]
        .as_array()
        .expect("the changes array")
        .iter()
        .map(|row| format!("{} at {}", row["op"], row["at"]))
        .collect()
}

/// The commits above `position` as the daemon's KERNEL holds them: every
/// position in `(position, head]` that is a transaction's boundary — the
/// kernel's own history read, one probe per position — the independent
/// count the landing's `{k}` is held to where the feed's would mask a row:
/// the head writer's own commits, the staging draft's mint and the record's
/// insert among them, are a draft's and no guest's to see.
fn boundaries_above(sd: &skepd::Skepd, position: u64) -> u64 {
    let head = sd.daemon().log_position().0;
    (position + 1..=head).filter(|&at| sd.daemon().attestation_at(skepd::Seq(at)).is_ok()).count() as u64
}

/// §4 ROW 22 — A HELD PORT REFUSES BEFORE THE OPEN: the binary spawned on a
/// port the test holds, over a FRESH data directory, exits 1 at once with
/// stderr's one line the bind's, naming the port and the OS's text; nothing
/// on stdout; the data directory NOT created — no `kernel.lock`, no file,
/// no open; and the refusal's wall time, spawn to exit, under
/// [`REFUSAL_CEILING`] and printed beside the same binary's `--help` for
/// scale.
#[test]
fn a_held_port_refuses_in_milliseconds_with_the_bind_line_and_creates_no_directory() {
    let held = TcpListener::bind(("127.0.0.1", 0)).expect("hold a port");
    let port = held.local_addr().expect("the held port").port();
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let started = Instant::now();
    let mut child = Spawned::launch(&mut skepd(&dir, &["--port", &port.to_string()]));
    let status = child.wait_within(PATIENCE);
    let refusal = started.elapsed();
    let mut stderr = String::new();
    child.child.stderr.take().expect("piped").read_to_string(&mut stderr).expect("read stderr");
    let mut stdout = String::new();
    child.child.stdout.take().expect("piped").read_to_string(&mut stdout).expect("read stdout");
    assert_eq!(status.code(), Some(1), "exit 1; stderr: {stderr:?}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 1, "stderr is the bind line alone: {stderr:?}");
    assert!(
        lines[0].starts_with(&format!("skepd: bind 127.0.0.1:{port}: ")),
        "the bind line names the port and the OS's text: {stderr:?}"
    );
    assert!(lines[0].len() > format!("skepd: bind 127.0.0.1:{port}: ").len(), "the OS's text: {stderr:?}");
    assert!(stdout.is_empty(), "no serving line: {stdout:?}");
    assert!(
        !dir.exists(),
        "FINDING (§4 row 22): the data directory was created — an open ran before the bind refused"
    );
    let help_started = Instant::now();
    let help = Command::new(env!("CARGO_BIN_EXE_skepd"))
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run --help");
    let help_took = help_started.elapsed();
    assert!(help.success(), "--help exits 0: {help:?}");
    println!(
        "the held port's refusal took {} ms from spawn to exit (the same binary's --help: {} ms)",
        refusal.as_millis(),
        help_took.as_millis()
    );
    assert!(
        refusal < REFUSAL_CEILING,
        "FINDING (§4 row 22): the refusal took {refusal:?}, past {REFUSAL_CEILING:?} — an open before the bind?"
    );
    drop(held);
}

/// §3.4 STEP 6's GAP, CLOSED — THE VERSION LINE FIRST: the child's FIRST
/// stderr line is `open: version {v}; this build reads journal format
/// {SKJ4}, checkpoint format {SKC4} and world format {0x…}` — `{v}` this
/// build's `CARGO_PKG_VERSION` and the three stamps spelled FROM THE
/// CRATES' CONSTANTS, the kernel's two as text and the engine's as its
/// refusal renders it — `open: data-dir {path}` the second, and `open:
/// recovered from …` after both; the same three, in the same order, on the
/// board's reopen. Each child killed by the test.
#[test]
fn the_open_says_its_version_and_the_formats_it_reads_first_then_its_directory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let expected = format!(
        "version {}; this build reads journal format {}, checkpoint format {} and world format \
         {:#018x}",
        env!("CARGO_PKG_VERSION"),
        skep_kernel::JOURNAL_FORMAT.escape_ascii(),
        skep_kernel::CHECKPOINT_FORMAT.escape_ascii(),
        skep_engine::WORLD_FORMAT
    );
    for life in ["first", "second"] {
        let mut served = serve_and_read_the_open(&dir, &[]);
        assert_eq!(
            served.version_line, expected,
            "FINDING (§3.4 step 6): the {life} life's version line"
        );
        assert_eq!(served.data_dir_line, format!("data-dir {}", dir.display()));
        let at = |prefix: &str| served.stderr.seen.iter().position(|l| said(l, "open", prefix));
        let whole = served.stderr.seen.join("\n");
        assert_eq!(at("version "), Some(0), "the version line is stderr's first:\n{whole}");
        assert_eq!(at("data-dir "), Some(1), "the directory's line is the second:\n{whole}");
        assert!(
            matches!(at("recovered from "), Some(n) if n > 1),
            "the landing comes after both:\n{whole}"
        );
        served.child.kill();
    }
}

/// §3.1 STEP 3 — THE TWO RULED OPEN LINES, IN ORDER, WITH THE KERNEL's
/// FIGURES: a fresh board's child writes `open: data-dir {path}` as its
/// first stderr line after the version line and `open: recovered from
/// genesis, 0 commits replayed, in {d} ms` before the serving line; the
/// same board reopened after N commits with no checkpoint says `{k} = N`;
/// a board checkpointed at position P with M commits above it — built
/// in-process through the checkpoint seam — says `checkpoint.P` and
/// `{k} = M`, the count the kernel pins. Each child killed by the test.
#[test]
fn the_open_says_its_directory_first_and_its_recovery_with_the_kernels_figures() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");

    // FIRST LIFE: a fresh board — genesis, nothing replayed.
    let mut first = serve_and_read_the_open(&dir, &[]);
    assert_eq!(first.data_dir_line, format!("data-dir {}", dir.display()));
    let (base, replayed, _) = recovered_figures(&first.recovered_line);
    assert_eq!((base.as_str(), replayed), ("genesis", 0), "{}", first.recovered_line);
    // N commits over the wire: the delegate, the home's mint, three inserts
    // — five, as the feed testifies.
    let (home, session) = delegate_a_home(first.port);
    insert_into_the_home(first.port, &session, &home, 1, 3);
    let commits = commits_above(first.port, 0);
    assert_eq!(commits.len(), 5, "the five commits made: {commits:?}");
    first.child.kill();

    // SECOND LIFE: the same board, no checkpoint — genesis, N replayed.
    let mut second = serve_and_read_the_open(&dir, &[]);
    assert_eq!(second.data_dir_line, format!("data-dir {}", dir.display()));
    let (base, replayed, _) = recovered_figures(&second.recovered_line);
    assert_eq!(
        (base.as_str(), replayed),
        ("genesis", commits.len() as u64),
        "FINDING (m7): the landing's count is not the commits the open replayed: {}",
        second.recovered_line
    );
    second.child.kill();

    // THE CHECKPOINT CASE: a board checkpointed at P, M commits above it —
    // built in-process (the seam `checkpoint_now`, which no wire reaches),
    // closed, and reopened by the binary.
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let (position, above) = {
        let sd = spawn_unclaimed(&dir);
        let port = sd.port();
        let (home, session) = delegate_a_home(port);
        insert_into_the_home(port, &session, &home, 1, 2);
        sd.daemon().checkpoint_now();
        let position = sd.daemon().newest_checkpoint().expect("a checkpoint landed").seq.0;
        insert_into_the_home(port, &session, &home, 3, 3);
        // The commits above the checkpoint as the kernel holds them: the
        // three inserts and the head writer's own — a checkpoint moved is
        // one of the published head's triggers, so the next write's turn
        // commits the head's three, which a guest's feed shows one of.
        let above = boundaries_above(&sd, position);
        let seen = commits_above(port, position);
        println!("above checkpoint.{position}: {above} boundaries; the guest's feed shows {seen:?}");
        assert!(above >= 3, "the three inserts at least: {above}");
        sd.shutdown();
        (position, above)
    };
    let mut third = serve_and_read_the_open(&dir, &[]);
    let (base, replayed, _) = recovered_figures(&third.recovered_line);
    assert_eq!(
        (base.as_str(), replayed),
        (format!("checkpoint.{position}").as_str(), above),
        "FINDING (m7): the landing names another base or count: {}",
        third.recovered_line
    );
    third.child.kill();
}

/// m14 — THE OPEN's-REPORT `auth:` LINE AT EVERY START, on the real binary:
/// a fresh UNCLAIMED board under the defaults says `open: auth: unclaimed
/// (--local-trust on, the default); configured origins none; signed origins
/// {the bound port's three loopback defaults}` — the bare set, since
/// unclaimed the signed set is the bare one; the board CLAIMED over the
/// wire in that life and started again `--no-local-trust --origin
/// http://127.0.0.1:{port}` says `CLAIMED-ENFORCING (--local-trust off,
/// --no-local-trust); configured origins {that origin}; signed origins
/// {that origin}` — the configured set ALONE once claimed, the mode derived
/// from the pair as AUTH-5.86 derives it — with no warning, since the origin
/// names the bound port, and before the node prefix's line; and the same
/// board started with `SKEPD_LOCAL_TRUST=true` on the command says
/// `CLAIMED-PERMISSIVE (--local-trust on, SKEPD_LOCAL_TRUST=true) …`, the
/// permissive warning said before it. Each child killed by the test.
#[test]
fn the_auth_line_names_the_mode_the_flag_with_its_source_and_the_two_sets_at_every_start() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");

    // FIRST LIFE: unclaimed, the defaults — the bare set is the signed set;
    // the upload setting reads the default's source beside it.
    let mut first = serve_and_read_the_open(&dir, &[]);
    let port = first.port;
    assert_eq!(
        await_said(&mut first.stderr, "open", "media uploads: "),
        "media uploads: open (the default)"
    );
    assert_eq!(
        await_said(&mut first.stderr, "open", "auth: "),
        format!(
            "auth: unclaimed (--local-trust on, the default); configured origins none; signed \
             origins http://127.0.0.1:{port}, http://[::1]:{port}, http://localhost:{port}"
        ),
        "FINDING (m14): the unclaimed board's auth line"
    );
    claim_board(port);
    first.child.kill();

    // SECOND LIFE: claimed, ENFORCING by flag, its origin configured for the
    // bound port — the one line that would catch a mistyped origin.
    let origin = |port: u16| format!("http://127.0.0.1:{port}");
    let (mut second, mut stderr, port) = serve_on_a_reserved_port(
        &dir,
        |port| vec!["--no-local-trust".into(), "--origin".into(), origin(port)],
        &[],
    );
    assert_eq!(
        await_said(&mut stderr, "open", "auth: "),
        format!(
            "auth: CLAIMED-ENFORCING (--local-trust off, --no-local-trust); configured origins \
             {o}; signed origins {o}",
            o = origin(port)
        ),
        "FINDING (m14): the enforcing board's auth line"
    );
    await_said(&mut stderr, "open", "no --node-prefix");
    let at = |stderr: &Stderr, class: &str, prefix: &str| {
        stderr.seen.iter().position(|l| said(l, class, prefix))
    };
    assert!(
        at(&stderr, "open", "auth: ") < at(&stderr, "open", "no --node-prefix"),
        "the auth line comes before the node prefix's:\n{}",
        stderr.seen.join("\n")
    );
    assert!(
        !stderr.seen.iter().any(|l| after_the_head(l, "warning (at start)").is_some_and(|w| w.starts_with("board is claimed"))),
        "well configured: no lockout warning\n{}",
        stderr.seen.join("\n")
    );
    second.kill();

    // THIRD LIFE: the same board, PERMISSIVE by its variable, warned first.
    let (mut third, mut stderr, port) = serve_on_a_reserved_port(
        &dir,
        |port| vec!["--origin".into(), origin(port)],
        &[("SKEPD_LOCAL_TRUST", "true")],
    );
    assert_eq!(
        await_said(&mut stderr, "open", "auth: "),
        format!(
            "auth: CLAIMED-PERMISSIVE (--local-trust on, SKEPD_LOCAL_TRUST=true); configured \
             origins {o}; signed origins {o}",
            o = origin(port)
        ),
        "FINDING (m14): the permissive board's auth line"
    );
    let warned = at(&stderr, "warning (at start)", "board is claimed with --local-trust still on");
    assert!(
        warned.is_some() && warned < at(&stderr, "open", "auth: "),
        "the permissive warning is said before the auth line:\n{}",
        stderr.seen.join("\n")
    );
    third.kill();
}

/// ROWS 8 AND 19 — THE SOURCE WORDS on the real binary: `--no-uploads` reads
/// `media uploads: CLOSED (--no-uploads): …` and `SKEPD_NODE_PREFIX` on the
/// command `node prefix 1.3 (SKEPD_NODE_PREFIX): …`; `SKEPD_UPLOADS=true`
/// reads `media uploads: open (SKEPD_UPLOADS=true)` and no prefix its one
/// sentence; `--uploads --node-prefix 1.5` read the flags. The default's
/// phrase is the auth line claim's first child's.
#[test]
fn the_upload_setting_and_the_node_prefix_name_the_arm_that_set_each() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let rest = ": egress and assertion config, never journaled; the blocked-prefix list's \
                off-board test runs against it";
    let closed = "the creation and the resume are refused uploads_closed";

    let mut by_flag_and_variable =
        serve_and_read_the_open_with(&tmp.path().join("a"), &["--no-uploads"], &[("SKEPD_NODE_PREFIX", "1.3")]);
    assert_eq!(
        await_said(&mut by_flag_and_variable.stderr, "open", "media uploads: "),
        format!("media uploads: CLOSED (--no-uploads): {closed}"),
        "FINDING (row 8): the flag's source"
    );
    assert_eq!(
        await_said(&mut by_flag_and_variable.stderr, "open", "node prefix "),
        format!("node prefix 1.3 (SKEPD_NODE_PREFIX){rest}"),
        "FINDING (row 19): the variable's source"
    );
    by_flag_and_variable.child.kill();

    let mut by_variable =
        serve_and_read_the_open_with(&tmp.path().join("b"), &[], &[("SKEPD_UPLOADS", "true")]);
    assert_eq!(
        await_said(&mut by_variable.stderr, "open", "media uploads: "),
        "media uploads: open (SKEPD_UPLOADS=true)",
        "FINDING (row 8): the variable's source"
    );
    assert_eq!(
        await_said(&mut by_variable.stderr, "open", "no --node-prefix"),
        "no --node-prefix: the off-board test is off (every operator account reads as this \
         board's own); a hosted board must supply one"
    );
    by_variable.child.kill();

    let mut by_flags =
        serve_and_read_the_open_with(&tmp.path().join("c"), &["--uploads", "--node-prefix", "1.5"], &[]);
    assert_eq!(
        await_said(&mut by_flags.stderr, "open", "media uploads: "),
        "media uploads: open (--uploads)",
        "FINDING (row 8): an explicit --uploads is the flag's, not the default's"
    );
    assert_eq!(
        await_said(&mut by_flags.stderr, "open", "node prefix "),
        format!("node prefix 1.5 (--node-prefix){rest}"),
        "FINDING (row 19): the flag's source"
    );
    by_flags.child.kill();
}

/// ROW 41 — THE HOOK's LINE: the child with the door's INSIDE arm armed
/// answers one request `500 internal_panic`, its one worker serves the
/// next, and stderr carries ONE prefixed, timed `failure:` line naming
/// `skepd-worker`, the site in `listen.rs` and the literal payload — and
/// NOTHING of Rust's own hook's text, which the installed hook replaces.
#[test]
fn a_workers_panic_inside_its_catch_is_one_prefixed_line_of_the_hooks_and_the_worker_serves_on() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let mut served = serve_and_read_the_open(&dir, &[(WORKER_FAULT, "inside")]);
    let port = served.port;
    let (st, body) = get(port, "/health");
    assert_eq!(st, 500, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("internal_panic"), "{}", String::from_utf8_lossy(&body));
    let (st, body) = get(port, "/health");
    assert_eq!(
        (st, json(&body)["ok"].as_bool()),
        (200, Some(true)),
        "the one worker serves its next request: {}",
        String::from_utf8_lossy(&body)
    );
    let line = served.stderr.wait_for("the hook's line", Duration::from_secs(10), |l| {
        l.contains("a thread panicked at")
    });
    let said = after_the_head(&line, "failure").unwrap_or_else(|| {
        panic!("FINDING (row 41): the panic's line is not a timed failure: {line:?}")
    });
    assert!(
        said.starts_with("skepd-worker: a thread panicked at "),
        "the thread by name: {said:?}"
    );
    assert!(said.contains("listen.rs:"), "the location names the site: {said:?}");
    assert!(
        said.ends_with(": the test seam's worker fault, inside the handler's catch"),
        "the literal payload rides the line: {said:?}"
    );
    served.child.kill();
    let whole = served.stderr.whole();
    assert_eq!(
        whole.iter().filter(|l| l.contains("panicked at")).count(),
        1,
        "ONE line for one panic:\n{}",
        whole.join("\n")
    );
    assert!(
        !whole.iter().any(|l| l.starts_with("thread '") || l.contains("RUST_BACKTRACE")),
        "FINDING (row 41): Rust's own hook's text reached stderr:\n{}",
        whole.join("\n")
    );
}

/// `GET /health` on a connection of its own, as the harness's `get` makes
/// it — `Connection: close`, one request — with the CONNECT retried under
/// `within` where the OS refuses it, which the harness's `get` fails on at
/// once; the status and the body. For the every-arm claim alone, where a
/// bare connect is no probe: a connection closed with no request reaches
/// the outside site and ends a worker with no reply, so the retry is of the
/// whole request, never of a connect ahead of it.
fn get_health_retrying_the_connect(port: u16, within: Duration) -> (u16, Vec<u8>) {
    let deadline = Instant::now() + within;
    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(e) => {
                assert!(Instant::now() < deadline, "no connect to skepd within {within:?}: {e}");
                thread::sleep(Duration::from_millis(5));
            }
        }
    };
    stream.set_read_timeout(Some(within)).expect("read timeout");
    stream.set_write_timeout(Some(within)).expect("write timeout");
    stream
        .write_all(
            b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n\
              Content-Type: application/json\r\n\r\n",
        )
        .expect("write the request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read the reply");
    let (status, _headers, body) = parse_response(&raw, "GET /health");
    (status, body)
}

/// m16 — EVERY WORKER GONE → THE LINE AND EXIT 1, under the real worker
/// floor: the child spawned with `skepd::MIN_WORKERS` workers and the door's
/// EVERY arm armed answers `MIN_WORKERS` requests to `/health`, each on a
/// connection of its own (`Connection: close`) and each 200 — a worker dies
/// only AFTER its reply, past the catch, and the rest serve the next; an
/// idle worker never reaches the outside site, so one request per worker is
/// what ends them all — and after the last reply exits 1 within
/// [`PATIENCE`], its stderr carrying the hook's line ONCE PER WORKER and,
/// after the last of them, `failure: every worker thread has ended; the
/// board serves nothing`. No worker takes two requests: the accept loop
/// hands each connection to one worker blocked in `accept`, and a worker
/// that has served is dead before it could accept again — which the count
/// of the hook's lines pins. A connect the OS refuses while workers remain
/// — none is expected, the listener standing until the server drops — is
/// retried within [`PATIENCE`] ([`get_health_retrying_the_connect`]).
#[test]
fn every_worker_gone_is_said_after_the_hooks_line_and_the_binary_exits_1() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let served = serve_and_read_the_open(&dir, &[(WORKER_FAULT, "every")]);
    let workers = skepd::MIN_WORKERS;
    for n in 1..=workers {
        let (st, body) = get_health_retrying_the_connect(served.port, PATIENCE);
        assert_eq!(
            (st, json(&body)["ok"].as_bool()),
            (200, Some(true)),
            "request {n} of {workers}: the reply is written before the fault fires: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let last_reply = Instant::now();
    let Served { mut child, stderr, .. } = served;
    let status = child.wait_within(PATIENCE);
    let exit_after = last_reply.elapsed();
    assert_eq!(status.code(), Some(1), "FINDING (m16): the exit is {status:?}, not 1");
    let whole = stderr.whole();
    let hooks_line = |l: &String| {
        after_the_head(l, "failure").is_some_and(|said| {
            said.starts_with("skepd-worker: a thread panicked at ")
                && said.ends_with(": the test seam's worker fault, outside the handler's catch")
        })
    };
    let hook_at = whole
        .iter()
        .position(hooks_line)
        .unwrap_or_else(|| panic!("FINDING (row 41): no hook's line:\n{}", whole.join("\n")));
    let last_hook_at = whole.iter().rposition(hooks_line).expect("the first hook's line is one");
    let hook_lines = whole.iter().filter(|l| hooks_line(l)).count();
    assert_eq!(
        hook_lines,
        workers,
        "one hook's line per worker, {workers} workers:\n{}",
        whole.join("\n")
    );
    let exit_at = whole
        .iter()
        .position(|l| {
            after_the_head(l, "failure")
                == Some("every worker thread has ended; the board serves nothing")
        })
        .unwrap_or_else(|| panic!("FINDING (m16): no exit line:\n{}", whole.join("\n")));
    assert!(hook_at < exit_at, "the hook's line comes first:\n{}", whole.join("\n"));
    assert!(last_hook_at < exit_at, "every hook's line comes first:\n{}", whole.join("\n"));
    println!(
        "{workers} workers ended on {workers} requests, {hook_lines} hook lines; the exit came \
         {} ms after the last reply",
        exit_after.as_millis()
    );
}

/// §0 FACT 1 — THE SIX LINES SURVIVE A LOST READER. (i) The serving line's
/// reader gone before the line is written — the child's stdout a pipe with
/// no read end, on a port the test chose, a lost bind race retried as the
/// suite's spawn retries it: the daemon serves on (`GET /health` answers
/// `ok`) and is killed by the test, an exit by signal and never 101. (ii)
/// A stderr with no reader: a refused command line exits 2; a refused bind
/// exits 1; a refused open exits 1; a tool's refusal exits 1.
#[test]
fn the_binarys_lines_survive_a_lost_reader_and_the_daemon_serves_on() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");

    // (i) THE SERVING LINE's READER GONE.
    const ATTEMPTS: usize = 12;
    let mut won = None;
    for _ in 0..ATTEMPTS {
        let reserved = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a port");
        let port = reserved.local_addr().expect("the port").port();
        drop(reserved);
        let workers = skepd::MIN_WORKERS.to_string();
        let mut cmd = skepd(&dir, &["--port", &port.to_string(), "--workers", &workers]);
        cmd.stdout(reader_less_pipe());
        let mut child = Spawned::launch(&mut cmd);
        let mut stderr = Stderr::of(&mut child.child);
        // The first line tells: the bind refused — a lost race, a fresh port
        // next — or the open begun.
        let first = stderr.wait_for("the first line", PATIENCE, |_| true);
        if first.starts_with(&format!("skepd: bind 127.0.0.1:{port}: ")) {
            continue;
        }
        assert!(after_the_head(&first, "open").is_some(), "the open's first line: {first:?}");
        won = Some((child, stderr, port));
        break;
    }
    let (mut child, stderr, port) =
        won.expect("the binary bound a reserved port within the attempts");
    let (st, body) = get(port, "/health");
    assert_eq!(
        (st, json(&body)["ok"].as_bool()),
        (200, Some(true)),
        "FINDING (§0 fact 1): the daemon does not serve after its serving line met no reader"
    );
    let status = child.kill();
    assert_eq!(status.signal(), Some(9), "killed by the test, an exit by signal: {status:?}");
    assert_eq!(status.code(), None, "never a code, 101 least of all: {status:?}");
    let whole = stderr.whole();
    assert!(
        !whole.iter().any(|l| l.contains("panicked at")),
        "FINDING (§0 fact 1): the lost reader panicked the binary:\n{}",
        whole.join("\n")
    );

    // (ii) A STDERR WITH NO READER: each refusal keeps its exit code.
    let mut refused_line = skepd(&dir, &["--frobnicate"]);
    refused_line.stderr(reader_less_pipe());
    let status = Spawned::launch(&mut refused_line).wait_within(PATIENCE);
    assert_eq!(status.code(), Some(2), "a refused command line: {status:?}");

    let held = TcpListener::bind(("127.0.0.1", 0)).expect("hold a port");
    let mut refused_bind = skepd(&dir, &["--port", &held.local_addr().expect("the port").port().to_string()]);
    refused_bind.stderr(reader_less_pipe());
    let status = Spawned::launch(&mut refused_bind).wait_within(PATIENCE);
    assert_eq!(status.code(), Some(1), "a refused bind: {status:?}");
    drop(held);

    let not_a_dir = tmp.path().join("a-file");
    std::fs::write(&not_a_dir, b"not a board").expect("a file where a directory is named");
    let mut refused_open = skepd(&not_a_dir, &["--port", "0"]);
    refused_open.stderr(reader_less_pipe());
    let status = Spawned::launch(&mut refused_open).wait_within(PATIENCE);
    assert_eq!(status.code(), Some(1), "a refused open: {status:?}");

    let mut refused_tool = Command::new(env!("CARGO_BIN_EXE_skepd"));
    refused_tool
        .args(["inventory", "--data-dir"])
        .arg(tmp.path().join("no-board"))
        .stdout(Stdio::piped())
        .stderr(reader_less_pipe());
    let status = Spawned::launch(&mut refused_tool).wait_within(PATIENCE);
    assert_eq!(status.code(), Some(1), "a tool's refusal: {status:?}");
}
