//! THE OPEN's ORDER AND THE EXITS (`operations.md` §0 facts 1 and 10; §1.1
//! rows 3 and 41, m3, m7 and m16; §3.1 step 3; §4 rows 8, 22 and 32),
//! judged on the REAL BINARY: spawned as `hazard.rs` spawns it, on `--port 0` or a
//! port the test holds, its two streams piped and read on threads of the
//! test's own, and ALWAYS killed and reaped before a claim returns, pass or
//! fail — the [`Spawned`] guard — so a red leaks no daemon.
//!
//! * A HELD PORT refuses before the open: the bind line, exit 1, in
//!   milliseconds, and the data directory is never created — no
//!   `kernel.lock`, nothing read, nothing written.
//! * THE OPEN's THREE LINES, in order: `open: version {v} ({commit}); this
//!   build reads journal format {SKJ4}, checkpoint format {SKC4} and world
//!   format {0x…}; built with {features}` is the first line on stderr — the
//!   build's version and commit as `skepd --version` names them, the three
//!   format stamps, each from its crate's constant, and the optional
//!   features the binary was built with — `open: data-dir
//!   {path}` the second, and `open: recovered from {checkpoint.n |
//!   genesis} to position {head}, {k} commits replayed, in {d} ms` stands on
//!   stderr before the serving line — `{head}` the position the board was
//!   left at and `{k}` the kernel's count, across a reopen with no
//!   checkpoint and one with a checkpoint at a known position. A fresh
//!   board's first open says, after its landing, `open: no journal stood in
//!   the data directory: this open began a new board at genesis — …`; a
//!   reopen says none.
//! * THE HOOK: a worker's panic inside its handler's catch is ONE prefixed,
//!   timed `failure:` line naming `skepd-worker` and the site, nothing of
//!   Rust's own hook's text, and the worker serves its next request.
//! * THE WORKERS' END: the floor's workers, a panic past the catch in each
//!   after its one reply — the hook's line per death, then `failure: every
//!   worker thread has ended; the board serves nothing`, and exit 1.
//! * A panic on `main`, the open's lines queued, reaches the stream with
//!   them before exit 101: the hook drains the stream on `main`.
//! * THE SIX LINES SURVIVE A LOST READER: a stdout with no reader costs the
//!   serving line and never the daemon, which serves on; a stderr with no
//!   reader costs a refusal's line and never its exit code — 2 stays 2, 1
//!   stays 1, never 101.
//! * NO EXIT WAITS ON A READER THAT HAS STOPPED: on a stderr whose pipe is
//!   full and never read, a refused open exits 1 with its refusal unwritten,
//!   the workers' end exits 1 and a panic on `main` exits 101, each once
//!   the drain has given up at the binary's bound; no byte of the child's
//!   reaches the reader (gate-full: each waits the bound out).
//! * A COMMAND LINE THE BINARY CANNOT READ, on a stderr that is no
//!   terminal, is one line naming the cause and `--help`, exit 2 — never the
//!   usage text a unit restarting on failure would write at every attempt.
//! * A misspelled `SKEPD_` variable stops the start the same way, its one
//!   line naming the variable, before the data directory is touched.
//! * THE OPEN's-REPORT `auth:` LINE (`operations.md` §1.1 m14): after the
//!   bind and the warnings, `open: auth: {mode} (--local-trust {on|off},
//!   {source}); configured origins {list | none} ({source}); signed origins
//!   {list}` on every start — an unclaimed board under the defaults, a board claimed
//!   in a prior run started ENFORCING by flag, and the same board started
//!   PERMISSIVE by its variable.
//! * ROWS 8 AND 19 NAME THEIR SOURCE: `media uploads: … ({source})` and
//!   `node prefix {p} ({source}): …` read the arm that set each — the flag,
//!   the variable on the command, or the default.
//! * EVERY LINE CARRIES ITS CLASS WORD: the whole of a served open's
//!   stderr — the stray `checkpoint.tmp`'s line and the cell index's
//!   landing among it — is lines of the grammar's head, `skepd: {time}
//!   {class}: `, for a class the door spells; no line through no door.
//! * THE TAIL CUT IS SAID (m3; §4 row 8): bytes past the journal's last
//!   committed marker are cut at the next open, which says `open: journal
//!   tail cut ({n} bytes): …` ONCE, `{n}` the inventory's
//!   `journal.tail_cut` over a copy of the same directory; a clean close
//!   says none.
//! * A START REFUSED AT THE BLOCKED-PREFIX LIST TOUCHES NOTHING (#408;
//!   PATTERNS P13): one line naming the list's file, exit 1, no recovery
//!   and no tail cut said, every file under the data directory as it stood;
//!   the start that serves once the list is mended is the one that cuts the
//!   torn tail, and says so once.
//!
//! The daemon's fault door (`Daemon::panic_the_next_worker`) reaches the
//! child through the variable `main.rs` reads under `test-hooks`, the
//! feature every test build compiles the binary with.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use skep_util::notice::{Class, Moment};
use skepd::tools::{self, HoleCheck};

use crate::common::{
    acked_addr, claim_board, expect_resp, get, head_position, json, op, open_session,
    parse_response, spawn_unclaimed, T_ENROLL,
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

/// The byte a [`StalledPipe`]'s filler writes — one no line of the daemon's
/// is made of alone, so any other byte read back is the child's.
const FILLER: u8 = b'.';

/// A stream whose reader has STOPPED: a pipe filled by a thread of the
/// test's own and never read while the child runs, so every write the child
/// makes on it blocks — and never fails — from its first line, as it does
/// under a log driver that has stopped reading. The filler writes chunks of
/// 64 KiB, so macOS grows the pipe to its largest before it is full and a
/// line of the child's cannot grow it again; the pipe is full once a write
/// of the filler's has stood parked, its count still, for half a second.
struct StalledPipe {
    reader: io::PipeReader,
    stop: Arc<AtomicBool>,
    filler: thread::JoinHandle<()>,
}

impl StalledPipe {
    /// The pipe, full, and its write end for the child.
    fn full() -> (StalledPipe, io::PipeWriter) {
        let (reader, writer) = io::pipe().expect("a pipe");
        let mut end = writer.try_clone().expect("the filler's end");
        let stop = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let filler = {
            let (stop, started, finished) =
                (Arc::clone(&stop), Arc::clone(&started), Arc::clone(&finished));
            thread::spawn(move || {
                let chunk = vec![FILLER; 64 * 1024];
                while !stop.load(Ordering::SeqCst) {
                    started.fetch_add(1, Ordering::SeqCst);
                    if end.write_all(&chunk).is_err() {
                        return;
                    }
                    finished.fetch_add(1, Ordering::SeqCst);
                }
            })
        };
        let deadline = Instant::now() + PATIENCE;
        let (mut chunks, mut still_since) = (0, Instant::now());
        loop {
            thread::sleep(Duration::from_millis(10));
            let done = finished.load(Ordering::SeqCst);
            if done != chunks {
                (chunks, still_since) = (done, Instant::now());
            } else if started.load(Ordering::SeqCst) > done
                && still_since.elapsed() >= Duration::from_millis(500)
            {
                break;
            }
            assert!(Instant::now() < deadline, "the filler's write never parked: {done} chunks in");
        }
        (StalledPipe { reader, stop, filler }, writer)
    }

    /// Every byte the pipe holds that the filler did not write — the
    /// child's, which a reader that had stopped never took. Read once the
    /// child is reaped and its command dropped ([`launch_onto`]), so the
    /// filler's is the one write end left: its parked write lands as this
    /// reads, and it stops.
    fn childs_bytes(self) -> Vec<u8> {
        self.stop.store(true, Ordering::SeqCst);
        let mut held = Vec::new();
        let mut reader = self.reader;
        reader.read_to_end(&mut held).expect("read the pipe out");
        self.filler.join().expect("the filler stops");
        held.retain(|&b| b != FILLER);
        held
    }
}

/// `cmd` spawned with `stderr` as its stderr, the command dropped at once,
/// so the child holds that write end and this test holds none.
fn launch_onto(mut cmd: Command, stderr: io::PipeWriter) -> Spawned {
    cmd.stderr(stderr);
    Spawned::launch(&mut cmd)
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

/// The landing's figures off its words — `recovered from {base} to position
/// {head}, {k} commits replayed, in {d} ms` — as (base, head, k, d).
fn recovered_figures(line: &str) -> (String, u64, u64, u64) {
    let rest = line.strip_prefix("recovered from ").unwrap_or_else(|| panic!("{line:?}"));
    let (base, rest) = rest.split_once(" to position ").unwrap_or_else(|| panic!("{line:?}"));
    let (head, rest) = rest.split_once(", ").unwrap_or_else(|| panic!("{line:?}"));
    let (replayed, rest) = rest.split_once(" commits replayed, in ").unwrap_or_else(|| panic!("{line:?}"));
    let duration = rest.strip_suffix(" ms").unwrap_or_else(|| panic!("{line:?}"));
    (
        base.to_string(),
        head.parse().unwrap_or_else(|_| panic!("{line:?}")),
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

/// The board's ACTIVE segment under `dir`: the `seg-<n>.wal` with the
/// highest `n`, the one file the open's tail cut can shorten.
fn active_segment(dir: &Path) -> PathBuf {
    fs::read_dir(dir)
        .expect("the board")
        .map(|e| e.expect("an entry").path())
        .filter_map(|p| {
            let name = p.file_name()?.to_str()?.to_string();
            let n: u64 = name.strip_prefix("seg-")?.strip_suffix(".wal")?.parse().ok()?;
            Some((n, p))
        })
        .max_by_key(|(n, _)| *n)
        .map(|(_, p)| p)
        .expect("a segment")
}

/// `src` copied whole under `dst` — the copy the runbook has the inventory
/// run over, so its open cuts the copy's tail and never the board's.
fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("the copy's directory");
    for entry in fs::read_dir(src).expect("the board lists") {
        let entry = entry.expect("an entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("a file type").is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).expect("copy a file");
        }
    }
}

/// The beginning's line, after its head: the open found no journal in the
/// directory and began a board rather than recovering one.
const BEGAN: &str =
    "no journal stood in the data directory: this open began a new board at genesis";

/// The `open:` lines of `whole` that say a tail cut, after their heads.
fn tail_cut_lines(whole: &[String]) -> Vec<String> {
    whole
        .iter()
        .filter_map(|l| after_the_head(l, "open"))
        .filter(|text| text.starts_with("journal tail cut ("))
        .map(str::to_string)
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

/// THE VERSION LINE ON THE REAL BINARY: `skepd --version` prints ONE line
/// on stdout — `skepd <crate version> (<commit>)`, the version this test's
/// own `CARGO_PKG_VERSION` and the commit `SKEP_GIT_SHA` named at build
/// time, `unknown` where it named none, which the gate's build never does
/// — nothing on stderr, exit 0; and it answers under a variable the
/// daemon's own line refuses (`SKEPD_PORT` set to no port) and under
/// `SKEPD_PORTS`, a name the daemon does not read, consulting no
/// environment, so a release's check runs in whatever environment a person
/// has.
#[test]
fn the_version_line_is_one_line_on_stdout_under_any_environment() {
    let expected = format!(
        "skepd {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        option_env!("SKEP_GIT_SHA").unwrap_or("unknown")
    );
    for refused_port in [None, Some("no port")] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_skepd"));
        cmd.arg("--version").env_remove("SKEPD_PORT").env_remove("SKEPD_PORTS");
        if let Some(value) = refused_port {
            cmd.env("SKEPD_PORT", value).env("SKEPD_PORTS", "8642");
        }
        let out = cmd.output().expect("run --version");
        assert_eq!(out.status.code(), Some(0), "exit 0 (SKEPD_PORT {refused_port:?}): {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), expected, "the one line");
        assert!(out.stderr.is_empty(), "nothing on stderr: {:?}", String::from_utf8_lossy(&out.stderr));
    }
}

/// A COMMAND LINE THE BINARY CANNOT READ, OFF A TERMINAL: the real binary's
/// stderr, piped as a service manager's log is, carries ONE line naming the
/// cause and `--help` — never the usage text, which a unit that restarts on
/// failure would write at every attempt — and stdout nothing; exit 2.
#[test]
fn a_refused_command_line_off_a_terminal_is_one_line_naming_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_skepd"))
        .arg("--frobnicate")
        .env_clear()
        .output()
        .expect("run the binary");
    assert_eq!(out.status.code(), Some(2), "a refused command line: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "skepd: unknown argument '--frobnicate'; skepd --help prints the usage\n",
        "one line on a stderr that is no terminal"
    );
    assert!(out.stdout.is_empty(), "nothing on stdout: {:?}", String::from_utf8_lossy(&out.stdout));
}

/// Checks that a misspelled variable stops the start, touching nothing.
///
/// The real binary under `SKEPD_BLOCKED_PREFIX`, its last letter dropped,
/// writes one line naming it beside the variables the daemon reads, exit 2,
/// and creates nothing under the data directory (`operations.md` §2,
/// validated at start), where it would otherwise start the board with no
/// blocked-prefix list, its open saying only that none was named. The child
/// runs under the [`Spawned`] guard on an ephemeral port, so a binary that
/// starts after all fails this claim at [`PATIENCE`] and is killed, never
/// left serving.
#[test]
fn a_misspelled_variable_stops_the_start_before_the_directory_is_touched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("board");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_skepd"));
    cmd.args(["--port", "0"])
        .env_clear()
        .env("SKEPD_DATA_DIR", &dir)
        .env("SKEPD_BLOCKED_PREFIX", tmp.path().join("blocked.json"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = Spawned::launch(&mut cmd);
    let status = child.wait_within(PATIENCE);
    let mut stderr = String::new();
    child.child.stderr.take().expect("piped").read_to_string(&mut stderr).expect("read stderr");
    let mut stdout = String::new();
    child.child.stdout.take().expect("piped").read_to_string(&mut stdout).expect("read stdout");
    assert_eq!(status.code(), Some(2), "a refused variable; stderr: {stderr:?}");
    let line = stderr.strip_suffix('\n').unwrap_or(&stderr);
    assert!(!line.contains('\n'), "one line on a stderr that is no terminal: {stderr:?}");
    assert!(
        line.starts_with(
            "skepd: SKEPD_BLOCKED_PREFIX: the daemon reads no such variable — it reads "
        ),
        "the line names the variable: {line:?}"
    );
    assert!(
        line.contains(" SKEPD_BLOCKED_PREFIXES,") && line.ends_with("; skepd --help prints the usage"),
        "…beside the names the daemon reads, the list's own among them: {line:?}"
    );
    assert!(stdout.is_empty(), "nothing on stdout: {stdout:?}");
    assert!(!dir.exists(), "nothing created under the data directory");
}

/// §3.4 STEP 6's GAP, CLOSED — THE VERSION LINE FIRST: the child's FIRST
/// stderr line is `open: version {v} ({commit}); this build reads journal
/// format {SKJ4}, checkpoint format {SKC4} and world format {0x…}; built
/// with {features}` — `{v}` this build's `CARGO_PKG_VERSION` and `{commit}`
/// its `SKEP_GIT_SHA`, the two exactly as `skepd --version` names them, the
/// three stamps spelled FROM THE CRATES' CONSTANTS, the kernel's two as text
/// and the engine's as its refusal renders it, and `{features}` the optional
/// features the binary under test was built with: `observe` and `client` as
/// this build's cfgs say, and `test-hooks`, which every test build compiles
/// the binary with — `open: data-dir {path}` the second, and `open:
/// recovered from …` after both; the same three, in the same order, on the
/// board's reopen. Each child killed by the test.
#[test]
fn the_open_says_its_version_and_the_formats_it_reads_first_then_its_directory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let features: Vec<&str> = [
        ("observe", cfg!(feature = "observe")),
        ("client", cfg!(feature = "client")),
        ("test-hooks", true),
    ]
    .into_iter()
    .filter_map(|(feature, on)| on.then_some(feature))
    .collect();
    let expected = format!(
        "version {} ({}); this build reads journal format {}, checkpoint format {} and world \
         format {:#018x}; built with {}",
        env!("CARGO_PKG_VERSION"),
        option_env!("SKEP_GIT_SHA").unwrap_or("unknown"),
        skep_kernel::JOURNAL_FORMAT.escape_ascii(),
        skep_kernel::CHECKPOINT_FORMAT.escape_ascii(),
        skep_engine::WORLD_FORMAT,
        features.join(", ")
    );
    let version = Command::new(env!("CARGO_BIN_EXE_skepd")).arg("--version").output();
    let version = String::from_utf8_lossy(&version.expect("run --version").stdout).to_string();
    let named = version.trim_end().strip_prefix("skepd ").expect("the --version line");
    assert!(
        expected.starts_with(&format!("version {named}; ")),
        "the open names the build as `skepd --version` does: {named:?}"
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
/// genesis to position 0, 0 commits replayed, in {d} ms` before the serving
/// line; the same board reopened after N commits with no checkpoint says
/// `{k} = N` and the head `/health` reported before the kill — every write
/// acknowledged at or below it stands, which the line is the stream's one
/// word of; a board checkpointed at position P with M commits above it —
/// built in-process through the checkpoint seam — says `checkpoint.P`,
/// `{k} = M`, the count the kernel pins, and the head it was closed at. Each
/// child killed by the test.
#[test]
fn the_open_says_its_directory_first_and_its_recovery_with_the_kernels_figures() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");

    // FIRST LIFE: a fresh board — genesis, nothing replayed, and a board
    // BEGUN, said after the landing, which reads alike either way.
    let mut first = serve_and_read_the_open(&dir, &[]);
    assert_eq!(first.data_dir_line, format!("data-dir {}", dir.display()));
    let (base, head, replayed, _) = recovered_figures(&first.recovered_line);
    assert_eq!((base.as_str(), head, replayed), ("genesis", 0, 0), "{}", first.recovered_line);
    let began = await_said(&mut first.stderr, "open", BEGAN);
    assert!(
        began.contains("the directory named above is not where it lives"),
        "the beginning says what it means on a board that had a journal: {began}"
    );
    let at = |seen: &[String], prefix: &str| seen.iter().position(|l| said(l, "open", prefix));
    assert!(
        at(&first.stderr.seen, "recovered from ") < at(&first.stderr.seen, BEGAN),
        "the beginning follows the landing it qualifies:\n{}",
        first.stderr.seen.join("\n")
    );
    // N commits over the wire: the delegate, the home's mint, three inserts
    // — five, as the feed testifies.
    let (home, session) = delegate_a_home(first.port);
    insert_into_the_home(first.port, &session, &home, 1, 3);
    let commits = commits_above(first.port, 0);
    assert_eq!(commits.len(), 5, "the five commits made: {commits:?}");
    let killed_at = head_position(first.port);
    first.child.kill();

    // SECOND LIFE: the same board, no checkpoint — genesis, N replayed, and
    // the head the first life was killed at.
    let mut second = serve_and_read_the_open(&dir, &[]);
    assert_eq!(second.data_dir_line, format!("data-dir {}", dir.display()));
    let (base, head, replayed, _) = recovered_figures(&second.recovered_line);
    assert_eq!(
        (base.as_str(), replayed),
        ("genesis", commits.len() as u64),
        "FINDING (m7): the landing's count is not the commits the open replayed: {}",
        second.recovered_line
    );
    assert_eq!(
        head, killed_at,
        "the landing names the head the open came back at, the one the first life last \
         reported: {}",
        second.recovered_line
    );
    // A journal stood, so nothing was begun: read on past where the line
    // would stand — the media limits are said after it — and none was said.
    await_said(&mut second.stderr, "open", "media limits: ");
    assert_eq!(
        at(&second.stderr.seen, BEGAN),
        None,
        "a reopen recovered its journal and began none:\n{}",
        second.stderr.seen.join("\n")
    );
    second.child.kill();

    // THE CHECKPOINT CASE: a board checkpointed at P, M commits above it —
    // built in-process (the seam `checkpoint_now`, which no wire reaches),
    // closed, and reopened by the binary.
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let (position, above, closed_at) = {
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
        let closed_at = sd.daemon().log_position().0;
        sd.shutdown();
        (position, above, closed_at)
    };
    let mut third = serve_and_read_the_open(&dir, &[]);
    let (base, head, replayed, _) = recovered_figures(&third.recovered_line);
    assert_eq!(
        (base.as_str(), head, replayed),
        (format!("checkpoint.{position}").as_str(), closed_at, above),
        "FINDING (m7): the landing names another base, head or count: {}",
        third.recovered_line
    );
    third.child.kill();
}

/// THE CLASSED DOOR IS THE ONLY DOOR: every line on the binary's stderr
/// carries the grammar's head, `skepd: {time} {class}: `, for a class the
/// door spells — judged over the WHOLE stream of a served open, the cell
/// index's landing awaited so the walk thread's line is among the lines
/// judged, on a fresh board and again on the same board with a stray
/// `checkpoint.tmp` planted before the open, whose report (`open:
/// checkpoint.tmp found ({bytes} bytes) and removed: …`) is then judged
/// too. One claim over every line: a line through no door, or a head spelled
/// by hand at its site, fails it. The class words come from the door's own
/// type, so a word the door spells one way and a site another fails here.
#[test]
fn every_line_of_a_served_open_carries_a_class_word_the_door_spells() {
    let classes: Vec<String> = [
        Class::Failure,
        Class::Landing,
        Class::Open,
        Class::Warning(Moment::AtStart),
        Class::Warning(Moment::AtClaim),
        Class::Warning(Moment::AtOpen),
        Class::Warning(Moment::AtReissue),
        Class::Standing,
        Class::Progress,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let classed = |line: &str| classes.iter().any(|class| after_the_head(line, class).is_some());
    let every_line_classed = |whole: &[String], life: &str| {
        assert!(!whole.is_empty(), "the {life} life said nothing");
        for line in whole {
            assert!(
                classed(line),
                "FINDING (CUT 1): the {life} life's line carries no class word the door spells: \
                 {line:?}\n{}",
                whole.join("\n")
            );
        }
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");

    // FIRST LIFE: a fresh board, served; the walk's landing awaited, the
    // media gate's limits line — once un-classed — among the lines read.
    let mut first = serve_and_read_the_open(&dir, &[]);
    await_said(&mut first.stderr, "landing", "cell index rebuilt at open: ");
    first.child.kill();
    let whole = first.stderr.whole();
    every_line_classed(&whole, "first");
    assert!(
        whole.iter().any(|l| said(l, "open", "media limits")),
        "the media gate's limits line, under `open:`:\n{}",
        whole.join("\n")
    );

    // SECOND LIFE: a checkpoint a crash left half-written, planted; its
    // report is an `open:` line among the lines judged.
    let stray = b"a checkpoint a crash left half-written";
    fs::write(dir.join("checkpoint.tmp"), stray).expect("plant the stray file");
    let mut second = serve_and_read_the_open(&dir, &[]);
    let said_stray = await_said(&mut second.stderr, "open", "checkpoint.tmp found (");
    assert_eq!(
        said_stray,
        format!(
            "checkpoint.tmp found ({} bytes) and removed: a checkpoint a crash or the journal's \
             own full volume left half-written, no base, its room on the volume reclaimed by the \
             open",
            stray.len()
        )
    );
    assert!(!dir.join("checkpoint.tmp").exists(), "the open removed the stray file");
    await_said(&mut second.stderr, "landing", "cell index rebuilt at open: ");
    second.child.kill();
    let whole = second.stderr.whole();
    every_line_classed(&whole, "second");
    assert!(
        !whole.iter().any(|l| l.contains(" warning (at open): warning (at open): ")),
        "a head spelled twice:\n{}",
        whole.join("\n")
    );
}

/// m3 — THE TAIL CUT IS SAID, ONCE, ONLY WHEN CUT: a board closed cleanly
/// in-process — its last committed marker ending the journal — is opened by
/// the binary and says no `journal tail cut` line; killed idle, and bytes
/// that spell no frame appended past that marker (a copy taken mid-write's
/// shape, the inventory suite's own fixture), the next open says ONE `open:
/// journal tail cut ({n} bytes, beginning at byte {b} of {segment}, past
/// position {p}): …` line after the recovery's landing, `{n}` the bytes
/// appended and the inventory's `journal.tail_cut` over a copy of the same
/// torn directory, `{b}` and `{segment}` the active segment's clean length and
/// its name, where the appended bytes begin, and `{p}` the committed head the
/// inventory's `journal.log_position` reads off that copy, the segment back
/// at its clean length; and the open after that, the tail gone, says none
/// again. Each child killed by the test.
#[test]
fn the_open_says_the_bytes_it_cut_off_a_torn_tail_once_and_nothing_after_a_clean_close() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    {
        let sd = spawn_unclaimed(&dir);
        let (home, session) = delegate_a_home(sd.port());
        insert_into_the_home(sd.port(), &session, &home, 1, 2);
        sd.shutdown();
    }
    let segment = active_segment(&dir);
    let len_of = |segment: &Path| fs::metadata(segment).expect("the segment").len();
    let clean_len = len_of(&segment);

    // A CLEAN CLOSE: nothing above the last marker, nothing cut, no line.
    let mut first = serve_and_read_the_open(&dir, &[]);
    await_said(&mut first.stderr, "open", "media uploads: ");
    first.child.kill();
    let whole = first.stderr.whole();
    assert!(
        tail_cut_lines(&whole).is_empty(),
        "FINDING (m3): a clean close, and the open says a cut:\n{}",
        whole.join("\n")
    );
    assert_eq!(len_of(&segment), clean_len, "nothing cut off a clean close");

    // GARBAGE PAST THE LAST MARKER — bytes that spell no frame, no sync word
    // among them, so the scan reads one run to the end of the file above the
    // committed head: the tail, cut whole. The inventory's figure is read
    // over a COPY, as the runbook has it run, since its open cuts too.
    const GARBAGE: u64 = 777;
    let mut f = fs::OpenOptions::new().append(true).open(&segment).expect("open the segment");
    f.write_all(&vec![0xA5u8; GARBAGE as usize]).expect("append the garbage");
    drop(f);
    assert_eq!(len_of(&segment), clean_len + GARBAGE);
    let copy = tmp.path().join("copy");
    copy_dir(&dir, &copy);
    let v = tools::inventory(&copy, HoleCheck::LengthOnly).expect("the inventory over the copy");
    let inventoried = v["journal"]["tail_cut"].as_u64().expect("a count, never null");
    assert_eq!(
        inventoried, GARBAGE,
        "the inventory's count is the bytes past the last marker: {v}"
    );
    let head = v["journal"]["log_position"].as_u64().expect("the committed head");
    let name = segment.file_name().and_then(|n| n.to_str()).expect("the segment's name");

    let mut second = serve_and_read_the_open(&dir, &[]);
    await_said(&mut second.stderr, "open", "media uploads: ");
    second.child.kill();
    let whole = second.stderr.whole();
    let cut = tail_cut_lines(&whole);
    assert_eq!(cut.len(), 1, "FINDING (m3): ONE line for the cut:\n{}", whole.join("\n"));
    assert_eq!(
        cut[0],
        format!(
            "journal tail cut ({inventoried} bytes, beginning at byte {clean_len} of {name}, past \
             position {head}): the un-acked tail a crash or a kill left past the last committed \
             marker — a write caught before its commit was durable, never acknowledged — removed \
             by the open; every acknowledged write stands"
        ),
        "the line names the inventory's figure, the file and byte the cut began at, and the head"
    );
    let at = |prefix: &str| whole.iter().position(|l| said(l, "open", prefix));
    assert!(
        at("recovered from ") < at("journal tail cut ("),
        "the cut is said after the recovery's landing:\n{}",
        whole.join("\n")
    );
    assert_eq!(len_of(&segment), clean_len, "the open cut the segment back to its last marker");

    // THE OPEN AFTER THE CUT: a clean close's answer, no line.
    let mut third = serve_and_read_the_open(&dir, &[]);
    await_said(&mut third.stderr, "open", "media uploads: ");
    third.child.kill();
    let whole = third.stderr.whole();
    assert!(
        tail_cut_lines(&whole).is_empty(),
        "FINDING (m3): the cut is said again at an open that cut nothing:\n{}",
        whole.join("\n")
    );
}

/// #408 — A START REFUSED AT THE BLOCKED-PREFIX LIST TOUCHES NOTHING
/// (PATTERNS P13; AUTH-4.70): a board closed in-process, 777 bytes that
/// spell no frame appended past its last marker (the tail cut's own
/// fixture), and a list file that is not a list. The binary started under
/// `--blocked-prefixes` exits 1, its stderr the open's version and
/// directory lines and then the list's refusal naming the file — no
/// recovery and no tail cut said — and every file under the data directory
/// stands as it stood, the torn tail included.
/// The list mended, the next start serves, and it is THAT start — the one
/// an operator reads — that cuts the tail and says so, once.
#[test]
fn a_start_refused_at_the_list_touches_nothing_and_the_serving_start_says_the_cut() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    {
        let sd = spawn_unclaimed(&dir);
        let (home, session) = delegate_a_home(sd.port());
        insert_into_the_home(sd.port(), &session, &home, 1, 2);
        sd.shutdown();
    }
    let segment = active_segment(&dir);
    let clean_len = fs::metadata(&segment).expect("the segment").len();
    let mut f = fs::OpenOptions::new().append(true).open(&segment).expect("open the segment");
    f.write_all(&[0xA5u8; 777]).expect("append the garbage");
    drop(f);
    let before = crate::tools::tree(&dir);
    let list = tmp.path().join("blocked.json");
    fs::write(&list, b"not a list").expect("a list that is not one");
    let list_flag = list.to_str().expect("a UTF-8 path");

    let mut cmd = skepd(&dir, &["--port", "0", "--blocked-prefixes", list_flag]);
    let mut refused = Spawned::launch(&mut cmd);
    let stderr = Stderr::of(&mut refused.child);
    let status = refused.wait_within(PATIENCE);
    let whole = stderr.whole();
    assert_eq!(status.code(), Some(1), "the list stops the start:\n{}", whole.join("\n"));
    let last = whole.last().expect("the refusal");
    assert!(
        last.starts_with(&format!("skepd: blocked-prefix list: {}: ", list.display())),
        "the refusal names the list's file: {last:?}"
    );
    assert!(
        !whole.iter().any(|l| said(l, "open", "recovered from "))
            && tail_cut_lines(&whole).is_empty(),
        "FINDING (#408): the refused start opened the journal and cut its tail:\n{}",
        whole.join("\n")
    );
    assert!(
        whole.len() == 3
            && said(&whole[0], "open", "version ")
            && said(&whole[1], "open", "data-dir "),
        "the refusal follows the version and directory lines, nothing between:\n{}",
        whole.join("\n")
    );
    assert_eq!(
        crate::tools::tree(&dir),
        before,
        "FINDING (#408): the refused start changed the data directory"
    );

    // THE LIST MENDED: the start that serves is the one that cuts, and says
    // so.
    fs::write(&list, br#"{"entries": []}"#).expect("the empty list");
    let mut served = serve_and_read_the_open_with(&dir, &["--blocked-prefixes", list_flag], &[]);
    await_said(&mut served.stderr, "open", "media uploads: ");
    served.child.kill();
    let whole = served.stderr.whole();
    assert_eq!(
        tail_cut_lines(&whole).len(),
        1,
        "the serving start says the cut the refused one left standing:\n{}",
        whole.join("\n")
    );
    assert_eq!(
        fs::metadata(&segment).expect("the segment").len(),
        clean_len,
        "the serving start cut the segment back to its last marker"
    );
}

/// Checks the open's `auth:` line at every start, on the real binary (m14).
///
/// A fresh unclaimed board under the defaults says `open: auth: unclaimed
/// (--local-trust on, the default); configured origins none (the default);
/// signed origins {the bound port's three loopback defaults}` — the bare
/// set, since unclaimed the signed set is the bare one. The board, claimed
/// over the wire in that life and started again `--no-local-trust --origin
/// http://127.0.0.1:{port}`, says `CLAIMED-ENFORCING (--local-trust off,
/// --no-local-trust); configured origins {that origin} (--origin); signed
/// origins {that origin}` — the configured set alone once claimed, the mode
/// derived from the pair as AUTH-5.86 derives it — with no warning, since
/// the origin names the bound port, and before the node prefix's line,
/// which the blocked list's absence follows, no file being named (row 20).
/// The same board started with `SKEPD_LOCAL_TRUST=true` on the command says
/// `CLAIMED-PERMISSIVE (--local-trust on, SKEPD_LOCAL_TRUST=true) …`, the
/// permissive warning said before it. Each child is killed by the test.
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
            "auth: unclaimed (--local-trust on, the default); configured origins none (the \
             default); signed origins http://127.0.0.1:{port}, http://[::1]:{port}, \
             http://localhost:{port}"
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
             {o} (--origin); signed origins {o}",
            o = origin(port)
        ),
        "FINDING (m14): the enforcing board's auth line"
    );
    await_said(&mut stderr, "open", "no --node-prefix");
    assert_eq!(
        await_said(&mut stderr, "open", "no --blocked-prefixes"),
        "no --blocked-prefixes (or SKEPD_BLOCKED_PREFIXES): no prefix is blocked, and none can be \
         until a restart names a file — a board that may need a takedown starts with one holding \
         {\"entries\": []}",
        "row 20: a board started with no list says so, and what a takedown then costs"
    );
    let at = |stderr: &Stderr, class: &str, prefix: &str| {
        stderr.seen.iter().position(|l| said(l, class, prefix))
    };
    assert!(
        at(&stderr, "open", "auth: ") < at(&stderr, "open", "no --node-prefix")
            && at(&stderr, "open", "no --node-prefix")
                < at(&stderr, "open", "no --blocked-prefixes"),
        "the auth line, then the node prefix's, then the list's absence:\n{}",
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
             origins {o} (--origin); signed origins {o}",
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
         board's own); a hosted board must supply one (--node-prefix or SKEPD_NODE_PREFIX) at a \
         restart"
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

/// Checks that a panic on `main` reaches the stream before exit 101.
///
/// The main fault armed (`SKEPD_TEST_MAIN_FAULT`, read under `test-hooks`),
/// `main` panics with the open's lines queued: the binary exits 101, its
/// stderr holding the open's version line and, after it, the hook's —
/// `main: a thread panicked at {location}: the test seam's fault on main` —
/// and nothing on stdout (`operations.md` §0 fact 1). Without the hook's
/// drain, the exit races the stream's thread, and whenever it wins every
/// line is lost.
#[test]
fn a_panic_on_main_reaches_the_stream_before_exit_101() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = skepd(&tmp.path().join("data"), &["--port", "0"]);
    cmd.env("SKEPD_TEST_MAIN_FAULT", "1");
    let mut child = Spawned::launch(&mut cmd);
    let stderr = Stderr::of(&mut child.child);
    let status = child.wait_within(PATIENCE);
    let mut stdout = String::new();
    child.child.stdout.take().expect("piped").read_to_string(&mut stdout).expect("read stdout");
    let whole = stderr.whole();
    assert_eq!(status.code(), Some(101), "a panic on main:\n{}", whole.join("\n"));
    let version_at = whole
        .iter()
        .position(|l| after_the_head(l, "open").is_some_and(|said| said.starts_with("version ")))
        .unwrap_or_else(|| panic!("the open's lines reached the stream:\n{}", whole.join("\n")));
    let hook_at = whole
        .iter()
        .position(|l| {
            after_the_head(l, "failure").is_some_and(|said| {
                said.starts_with("main: a thread panicked at ")
                    && said.ends_with(": the test seam's fault on main")
            })
        })
        .unwrap_or_else(|| panic!("the hook's line reached the stream:\n{}", whole.join("\n")));
    assert!(version_at < hook_at, "the open's lines come first:\n{}", whole.join("\n"));
    assert!(stdout.is_empty(), "no serving line: {stdout:?}");
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

/// Asserts that no byte of the child's reached `pipe`'s reader, which had
/// stopped: what the claim holds an exit to was a stall the whole run.
fn assert_the_reader_took_nothing(pipe: StalledPipe) {
    let said = pipe.childs_bytes();
    assert!(
        said.is_empty(),
        "the reader took the child's lines, so it never stood still and nothing was proved: {}",
        String::from_utf8_lossy(&said)
    );
}

/// §0 FACT 1, A READER THAT HAS STOPPED — A REFUSED OPEN STILL EXITS 1: the
/// child's stderr a [`StalledPipe`], a file where the data directory is
/// named. The open's first two lines reach the stream's queue, whose thread
/// parks writing the first; the drain gives up at the binary's bound, and
/// the refusal — which would wait behind that thread on stderr's lock — is
/// not written: exit 1, no byte of the child's taken. Necessarily slow: it
/// waits the bound out.
#[test]
#[ignore = "timing test - gate-full only"]
fn a_refused_open_exits_1_on_a_stderr_whose_reader_has_stopped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let not_a_dir = tmp.path().join("a-file");
    fs::write(&not_a_dir, b"not a board").expect("a file where a directory is named");
    let (pipe, stderr) = StalledPipe::full();
    let mut child = launch_onto(skepd(&not_a_dir, &["--port", "0"]), stderr);
    let status = child.wait_within(PATIENCE);
    assert_eq!(status.code(), Some(1), "FINDING (§0 fact 1): a refused open: {status:?}");
    assert_the_reader_took_nothing(pipe);
}

/// §0 FACT 1, A READER THAT HAS STOPPED — THE WORKERS' END STILL EXITS 1
/// (m16): the child's stderr a [`StalledPipe`], the floor's workers and the
/// worker fault's every arm. The start's drain gives up at the binary's
/// bound and the serving line follows on stdout; each worker answers one
/// `/health` and dies past its catch, its hook's line queued behind the
/// parked write, and the workers' end drains for the bound and exits 1 — no
/// byte of the child's taken. Necessarily slow: it waits the bound out
/// twice.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_workers_end_exits_1_on_a_stderr_whose_reader_has_stopped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let workers = skepd::MIN_WORKERS.to_string();
    let mut cmd = skepd(&tmp.path().join("data"), &["--port", "0", "--workers", &workers]);
    cmd.env(WORKER_FAULT, "every");
    let (pipe, stderr) = StalledPipe::full();
    let mut child = launch_onto(cmd, stderr);
    let port = serving_port(&mut child.child, PATIENCE);
    for n in 1..=skepd::MIN_WORKERS {
        let (st, body) = get_health_retrying_the_connect(port, PATIENCE);
        assert_eq!(
            (st, json(&body)["ok"].as_bool()),
            (200, Some(true)),
            "request {n}: the board serves while its stderr takes nothing: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let status = child.wait_within(PATIENCE);
    assert_eq!(status.code(), Some(1), "FINDING (m16): the workers' end: {status:?}");
    assert_the_reader_took_nothing(pipe);
}

/// §0 FACT 1, A READER THAT HAS STOPPED — A PANIC ON `main` STILL EXITS
/// 101: the child's stderr a [`StalledPipe`] and the main fault armed. The
/// hook's drain gives up at the binary's bound and the unwind goes on: exit
/// 101, no byte of the child's taken. Necessarily slow: it waits the bound
/// out.
#[test]
#[ignore = "timing test - gate-full only"]
fn a_panic_on_main_exits_101_on_a_stderr_whose_reader_has_stopped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = skepd(&tmp.path().join("data"), &["--port", "0"]);
    cmd.env("SKEPD_TEST_MAIN_FAULT", "1");
    let (pipe, stderr) = StalledPipe::full();
    let mut child = launch_onto(cmd, stderr);
    let status = child.wait_within(PATIENCE);
    assert_eq!(status.code(), Some(101), "FINDING (§0 fact 1): a panic on main: {status:?}");
    assert_the_reader_took_nothing(pipe);
}
