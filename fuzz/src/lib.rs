//! Shared boot for the socket targets: one real daemon on a temp dir, stood
//! up once and kept alive for the fuzzer's whole lifetime, so each input is
//! just a socket exchange. The daemon (and its temp dir) are deliberately
//! leaked — the process is the fuzzer, and it exits when the run ends.

use std::sync::OnceLock;

use skepd::{serve, Daemon};

static PORT: OnceLock<u16> = OnceLock::new();

/// The port of the shared fuzzing daemon (booted on first call).
pub fn daemon_port() -> u16 {
    *PORT.get_or_init(|| {
        let dir = tempfile::tempdir().expect("temp data dir");
        let daemon = Daemon::open(dir.path()).expect("daemon open (genesis)");
        let running = serve(daemon, 0, 4).expect("bind an ephemeral port");
        let port = running.port();
        // Keep both alive for the run: no shutdown, no cleanup.
        std::mem::forget(running);
        std::mem::forget(dir);
        port
    })
}
