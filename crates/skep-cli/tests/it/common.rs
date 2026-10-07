//! The fixture: a daemon in-process (skepd's spawn pattern), and the built
//! `skep` binary run with its environment scrubbed of every `SKEP_*`
//! variable, stdin fed, stdout and stderr captured.

#![allow(dead_code)]

use std::io::{ErrorKind, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use skepd::{serve, AuthOptions, Daemon, Skepd, DEFAULT_WORKERS};

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

pub fn origin(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
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

/// Run `skep` with `args`, the `SKEP_*` environment scrubbed then `envs`
/// set, `stdin` fed (closed at once where `None`).
pub fn skep(args: &[&str], envs: &[(&str, &str)], stdin: Option<&[u8]>) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep"));
    cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for var in ["SKEP_BOARD", "SKEP_KEYSTORE", "SKEP_KEY", "SKEP_PRINCIPAL", "SKEP_SESSION"] {
        cmd.env_remove(var);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn skep");
    {
        let mut si = child.stdin.take().expect("stdin");
        if let Some(bytes) = stdin {
            si.write_all(bytes).expect("feed stdin");
        }
        // Dropped here: EOF.
    }
    let out = child.wait_with_output().expect("wait");
    Run { code: out.status.code().unwrap_or(-1), out: String::from_utf8_lossy(&out.stdout).to_string(), err: String::from_utf8_lossy(&out.stderr).to_string() }
}
