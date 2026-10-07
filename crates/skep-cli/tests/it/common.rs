//! The fixture: a daemon in-process (skepd's spawn pattern) — alone, or
//! behind a [`Tap`] that keeps what a client put on the wire — and the built
//! `skep` binary run with its environment scrubbed of every `SKEP_*`
//! variable and of `HOME`, stdin fed, stdout and stderr captured — or one of
//! them closed, its reader gone before the run writes, or all three a
//! pseudo-terminal; and [`tree`], a directory's state, for the commands that
//! write nothing.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use skepd::{serve, AuthOptions, Daemon, Skepd, DEFAULT_WORKERS};

pub fn spawn(dir: &Path, local_trust: bool) -> Skepd {
    spawn_also_at(dir, local_trust, &[])
}

/// [`spawn`], the daemon accepting signed sessions at each of `also` beside
/// its own origin — a [`Tap`]'s.
fn spawn_also_at(dir: &Path, local_trust: bool, also: &[String]) -> Skepd {
    const ATTEMPTS: usize = 12;
    for _ in 0..ATTEMPTS {
        let reserved = TcpListener::bind(("127.0.0.1", 0)).expect("reserve an ephemeral port");
        let port = reserved.local_addr().expect("reserved local addr").port();
        let origin = skepd::Origin::parse(&format!("http://127.0.0.1:{port}")).expect("a canonical loopback origin");
        let mut opts = AuthOptions::default();
        opts.local_trust = local_trust;
        opts.configured = std::iter::once(origin).chain(also.iter().map(|o| skepd::Origin::parse(o).expect("a canonical origin"))).collect();
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

pub fn origin(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// A recording proxy in front of a daemon: every connection made to
/// [`Tap::origin`] is piped to the daemon both ways, and the bytes the
/// clients sent are kept in arrival order — what a request carried on the
/// wire, a session's scope among it, which no read of the board can see.
pub struct Tap {
    pub origin: String,
    sent: Arc<Mutex<Vec<u8>>>,
}

impl Tap {
    /// The requests the clients sent through the tap so far, in order: each
    /// one's request line, and its body as its `Content-Length` measures it.
    pub fn requests(&self) -> Vec<(String, String)> {
        let sent = self.sent.lock().expect("the tap's record").clone();
        let mut requests = Vec::new();
        let mut at = 0;
        while let Some(end) = sent[at..].windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&sent[at..at + end]).into_owned();
            let length: usize =
                head.lines().find_map(|l| l.split_once(':').filter(|(name, _)| name.eq_ignore_ascii_case("content-length")).and_then(|(_, n)| n.trim().parse().ok())).unwrap_or(0);
            let body = at + end + 4;
            let close = (body + length).min(sent.len());
            requests.push((head.lines().next().unwrap_or_default().to_string(), String::from_utf8_lossy(&sent[body..close]).into_owned()));
            at = close;
        }
        requests
    }
}

/// A daemon that accepts signed sessions at a second origin, a [`Tap`]'s,
/// and the tap in front of it. Each request is one connection
/// (`Connection: close`) and a client makes them one after another, so the
/// tap pipes each connection whole and its record holds the requests in
/// turn, which [`Tap::requests`] reads apart.
pub fn spawn_tapped(dir: &Path) -> (Skepd, Tap) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("the tap's port");
    let tapped = origin(listener.local_addr().expect("the tap's address").port());
    let sd = spawn_also_at(dir, false, std::slice::from_ref(&tapped));
    let upstream = sd.port();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&sent);
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let (Ok(client), Ok(server)) = (client, TcpStream::connect(("127.0.0.1", upstream))) else { continue };
            let (mut from_client, mut to_server) = (client.try_clone().expect("the client's half"), server.try_clone().expect("the server's half"));
            let kept = Arc::clone(&kept);
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                while let Ok(n @ 1..) = from_client.read(&mut buf) {
                    kept.lock().expect("the tap's record").extend_from_slice(&buf[..n]);
                    if to_server.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                let _ = to_server.shutdown(Shutdown::Write);
            });
            let (mut from_server, mut to_client) = (server, client);
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut from_server, &mut to_client);
                let _ = to_client.shutdown(Shutdown::Write);
            });
        }
    });
    (sd, Tap { origin: tapped, sent })
}

/// A path as the `&str` an argv takes.
pub fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// One run of the binary: exit code, stdout, stderr.
#[derive(Debug)]
pub struct Run {
    pub code: i32,
    pub out: String,
    pub err: String,
}

impl Run {
    pub fn lines(&self) -> Vec<&str> {
        self.out.lines().collect()
    }
}

/// Run `skep` with `args`, the environment scrubbed ([`scrub`]) then `envs`
/// set, `stdin` fed (closed at once where `None`).
pub fn skep(args: &[&str], envs: &[(&str, &str)], stdin: Option<&[u8]>) -> Run {
    skep_os(args, &text_envs(envs), stdin)
}

/// [`skep`], each argument and each variable's value whatever the platform
/// carries — bytes that are not UTF-8 text among them.
pub fn skep_os<A: AsRef<OsStr>>(args: &[A], envs: &[(&str, &OsStr)], stdin: Option<&[u8]>) -> Run {
    let mut child = command(args, envs).spawn().expect("spawn skep");
    feed(&mut child, stdin);
    run_of(child.wait_with_output().expect("wait"))
}

/// [`skep`] run from `cwd` — where a store at an empty path would land.
pub fn skep_in(cwd: &Path, args: &[&str], envs: &[(&str, &str)], stdin: Option<&[u8]>) -> Run {
    let mut child = command(args, &text_envs(envs)).current_dir(cwd).spawn().expect("spawn skep");
    feed(&mut child, stdin);
    run_of(child.wait_with_output().expect("wait"))
}

/// [`skep`] with stdout a pipe whose reader is gone before the run starts:
/// every write the run makes to stdout meets a pipe with no reader, with no
/// race against the run. `out` is empty — nothing reads it.
pub fn skep_stdout_closed(args: &[&str], stdin: &[u8]) -> Run {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    let mut child = command(args, &[]).stdout(writer).spawn().expect("spawn skep");
    feed(&mut child, Some(stdin));
    run_of(child.wait_with_output().expect("wait"))
}

/// [`skep`] with stderr a pipe whose reader is gone before the run starts:
/// every line the run says meets a pipe with no reader. `err` is empty —
/// nothing reads it.
pub fn skep_stderr_closed(args: &[&str], stdin: Option<&[u8]>) -> Run {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    let mut child = command(args, &[]).stderr(writer).spawn().expect("spawn skep");
    feed(&mut child, stdin);
    run_of(child.wait_with_output().expect("wait"))
}

/// `inner`, one `/bin/sh` command line, run under script(1)'s pseudo-
/// terminal — its stdin, stdout and stderr that terminal unless `inner`
/// redirects one — the environment scrubbed as [`skep`]'s. Answers what the
/// run wrote to the terminal (`\r\n`-ended). Every other run's streams are
/// pipes, so this is the one place a person door can be seen to open.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn on_a_terminal(inner: &str) -> String {
    let mut cmd = Command::new("script");
    if cfg!(target_os = "macos") {
        cmd.args(["-q", "/dev/null", "/bin/sh", "-c", inner]);
    } else {
        cmd.args(["-q", "-e", "-c", inner, "/dev/null"]).env("SHELL", "/bin/sh");
    }
    let out = scrub(&mut cmd).stdin(Stdio::null()).output().expect("script(1): the pseudo-terminal these runs need");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `text` as one `/bin/sh` word.
pub fn sh(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Every entry under `dir` by its path relative to `dir`, a file's bytes
/// beside it and `None` beside a directory — empty where `dir` is absent:
/// the state a command that writes nothing leaves as it found it.
pub fn tree(dir: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        let Ok(entries) = std::fs::read_dir(at) else { return };
        for entry in entries {
            let path = entry.expect("a readable entry").path();
            let relative = path.strip_prefix(root).expect("under the root").to_path_buf();
            if path.is_dir() {
                out.insert(relative, None);
                walk(root, &path, out);
            } else {
                out.insert(relative, Some(std::fs::read(&path).expect("a readable file")));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

/// The built `skep` with `args`, the environment scrubbed then `envs` set,
/// its three streams piped.
fn command<A: AsRef<OsStr>>(args: &[A], envs: &[(&str, &OsStr)]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep"));
    cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    scrub(&mut cmd);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd
}

/// `cmd` without the settings a developer's shell may hold: every `SKEP_*`
/// variable, and `HOME` and `USERPROFILE`, whose `.skep` is the default
/// store — a run that means `~/.skep` names its own HOME.
fn scrub(cmd: &mut Command) -> &mut Command {
    for var in ["SKEP_BOARD", "SKEP_KEYSTORE", "SKEP_KEY", "SKEP_PRINCIPAL", "SKEP_SESSION", "HOME", "USERPROFILE"] {
        cmd.env_remove(var);
    }
    cmd
}

/// Variables given as text, as [`skep_os`] takes them.
fn text_envs<'a>(envs: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a OsStr)> {
    envs.iter().map(|(k, v)| (*k, OsStr::new(*v))).collect()
}

/// `stdin` fed to the run, then closed — EOF; closed at once where `None`.
fn feed(child: &mut Child, stdin: Option<&[u8]>) {
    let mut si = child.stdin.take().expect("stdin");
    if let Some(bytes) = stdin {
        si.write_all(bytes).expect("feed stdin");
    }
}

/// A finished run: its exit code and both streams as text.
fn run_of(out: Output) -> Run {
    Run { code: out.status.code().unwrap_or(-1), out: String::from_utf8_lossy(&out.stdout).to_string(), err: String::from_utf8_lossy(&out.stderr).to_string() }
}
