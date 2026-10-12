//! THE EMBEDDING HELPER, judged where an embedding program meets it: the
//! start (`skepd::embed`) and the wait (`Skepd::wait_for_the_index`) over
//! real directories and real ports, in this process. The wait reads the
//! index — refused while the walk is held, answered once it is released; an
//! open refused for any cause but the lock is answered at once, naming the
//! open; a start after the orderly stop over the same directory serves; and
//! the bind comes first — an ephemeral port serves, and a held one is
//! refused by the bind with nothing opened. The retry's one condition is the
//! unit suite's (`server/embed/tests.rs`): the lock race is transient, and
//! no claim here could force it.

use std::error::Error;
use std::io;
use std::net::TcpListener;
use std::time::{Duration, Instant};

use skepd::{embed, AuthOptions, EmbedError, MediaOptions, DEFAULT_WORKERS};

use crate::common::{get, release_the_walk, spawn_walk_held};

/// The session layer's options at any port: the default's, no origin named.
fn defaults(_port: u16) -> AuthOptions {
    AuthOptions::default()
}

/// The kind of the first `io::Error` in `e`'s `source` chain, `e` included.
fn first_io_kind(e: &(dyn Error + 'static)) -> Option<io::ErrorKind> {
    let mut cause = Some(e);
    while let Some(e) = cause {
        if let Some(io) = e.downcast_ref::<io::Error>() {
            return Some(io.kind());
        }
        cause = e.source();
    }
    None
}

/// THE WAIT READS THE INDEX: with the cell index's walk HELD under the
/// walk's fence (`spawn_walk_held`, whose start is the helper's), the wait
/// given 200 ms answers `IndexNotReady` naming that deadline — having waited
/// it out, not refused at once — and the index is still not ready; once the
/// walk is released (`release_the_walk`, which waits through the daemon's
/// own wait), the same wait answers within its deadline.
#[test]
fn the_wait_answers_not_ready_while_the_walk_is_held_and_ready_once_released() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (sd, seam) = spawn_walk_held(dir.path());
    let deadline = Duration::from_millis(200);
    let began = Instant::now();
    let refused =
        sd.wait_for_the_index(deadline).expect_err("the walk is held: the index is not ready");
    let waited = began.elapsed();
    assert_eq!(refused.deadline(), deadline, "{refused}");
    assert!(waited >= deadline, "the wait ran out its deadline before it refused: {waited:?}");
    assert!(!sd.daemon().index_is_ready(), "nothing readied the index");
    release_the_walk(&sd, seam);
    sd.wait_for_the_index(deadline).expect("the walk released: ready within the deadline");
    sd.shutdown();
}

/// THE RETRY IS THE LOCK's ALONE: a start over a path that is a FILE is
/// refused by the open — the kernel's open of its journal directory there
/// failing with an `io::Error` of kind `AlreadyExists`, no lock in it — at
/// the FIRST attempt: the refusal names the open step, carries the kernel's
/// error, and comes back well inside the eleven pauses of 25 ms a retry of
/// it would have slept between twelve attempts.
#[test]
fn an_open_refused_for_any_cause_but_the_lock_is_answered_at_once_naming_the_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("a-file");
    std::fs::write(&file, b"no board").expect("write the file");
    let began = Instant::now();
    let refused = embed(&file, 0, defaults, MediaOptions::default(), DEFAULT_WORKERS)
        .expect_err("a file is no board's directory");
    let elapsed = began.elapsed();
    assert!(matches!(refused, EmbedError::Open(_)), "the open's step: {refused}");
    assert!(refused.to_string().starts_with("open: "), "the refusal names the open: {refused}");
    assert_eq!(
        first_io_kind(&refused),
        Some(io::ErrorKind::AlreadyExists),
        "the kernel's refusal of a file, never the lock's `WouldBlock`: {refused}"
    );
    assert!(elapsed < Duration::from_millis(250), "answered at once, nothing retried: {elapsed:?}");
}

/// THE START AFTER THE STOP, IN ONE PROCESS: a start, its orderly stop and a
/// start again over the SAME directory serves — the stop released the
/// journal directory's lock, the retry riding out the release where it lags
/// — and recovers the board the first start made, at its position.
#[test]
fn a_start_after_the_stop_over_the_same_directory_serves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = embed(dir.path(), 0, defaults, MediaOptions::default(), DEFAULT_WORKERS)
        .expect("the first start");
    let position = first.daemon().log_position();
    first.shutdown();
    let again = embed(dir.path(), 0, defaults, MediaOptions::default(), DEFAULT_WORKERS)
        .expect("the start after the stop");
    assert_eq!(again.daemon().log_position(), position, "the same board, recovered");
    let (status, body) = get(again.port(), "/health");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    again.shutdown();
}

/// THE BIND COMES FIRST: a start on port 0 serves on the ephemeral port it
/// bound — `/health` answers there — and a start on a port the test holds is
/// refused by the BIND, naming that step with the OS's `AddrInUse`, nothing
/// opened: no `kernel.lock`, nor anything else, written under the directory.
#[test]
fn the_bind_comes_first_an_ephemeral_port_serves_and_a_held_one_opens_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let served = dir.path().join("served");
    let sd = embed(&served, 0, defaults, MediaOptions::default(), DEFAULT_WORKERS)
        .expect("a start on an ephemeral port");
    assert_ne!(sd.port(), 0, "the port bound, read back");
    let (status, body) = get(sd.port(), "/health");
    assert_eq!(status, 200, "/health at the bound port: {}", String::from_utf8_lossy(&body));
    sd.shutdown();

    let held = TcpListener::bind(("127.0.0.1", 0)).expect("hold a port");
    let port = held.local_addr().expect("the held port").port();
    let untouched = dir.path().join("untouched");
    std::fs::create_dir(&untouched).expect("an empty directory");
    let refused = embed(&untouched, port, defaults, MediaOptions::default(), DEFAULT_WORKERS)
        .expect_err("the port is held");
    match &refused {
        EmbedError::Bind(e) => assert_eq!(e.kind(), io::ErrorKind::AddrInUse, "{refused}"),
        other => panic!("the bind's step: {other}"),
    }
    assert!(refused.to_string().starts_with("bind: "), "the refusal names the bind: {refused}");
    assert!(!untouched.join("kernel.lock").exists(), "no lock taken");
    let written: Vec<_> = std::fs::read_dir(&untouched).expect("read the directory").collect();
    assert!(written.is_empty(), "nothing written under the directory: {written:?}");
    drop(held);
}
