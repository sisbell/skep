//! Wire v4 commit stream over a real socket: the initial head on connect,
//! push on commit to every subscriber, survivor independence when one
//! disconnects, no starvation of the op surface, and bounded shutdown that
//! closes open streams. Transport behavior only — the writes are the
//! smallest committing operations available.

mod common;

use std::time::{Duration, Instant};

use common::*;

/// Bootstrap one delegated principal: π₀ session → next prefix under node
/// [1] → delegate → (session, account). Two ops, one commit (the delegate).
fn delegate_first_principal(port: u16) -> (String, String) {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"]
        .as_str()
        .expect("node [1] has a delegable prefix")
        .to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
    );
    let account = acked_addr(&v);
    (open_session(port, 1), account)
}

#[test]
fn commit_stream_pushes_the_head_to_every_subscriber() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // On connect: one event carrying the current committed head, agreeing
    // with /health.
    let mut a = Sse::connect(port);
    let initial = a.expect_commit();
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    assert_eq!(
        json(&body)["log_position"].as_u64().expect("health log_position"),
        initial,
        "the initial event is the committed head"
    );

    let mut b = Sse::connect(port);
    assert_eq!(b.expect_commit(), initial, "every subscriber starts at the same head");

    // One committing write → both subscribers see a strictly greater
    // position (reads along the way emit nothing they could mistake for
    // one: positions only move forward).
    let (s1, account) = delegate_first_principal(port);
    let after_delegate_a = a.expect_commit();
    let after_delegate_b = b.expect_commit();
    assert!(after_delegate_a > initial, "the head advanced: {after_delegate_a} > {initial}");
    assert_eq!(after_delegate_a, after_delegate_b, "both subscribers converge on the head");

    // A subscriber disconnecting mid-stream leaks nothing: the survivor
    // still gets the next commit.
    drop(a);
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    );
    acked_addr(&v);
    let after_create = b.expect_commit();
    assert!(after_create > after_delegate_b, "the survivor keeps receiving");

    // Shutdown ends the stream from the daemon's side.
    sd.shutdown();
    b.expect_eof();
}

#[test]
fn open_streams_do_not_starve_the_op_surface() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // More open streams than the daemon has op workers (spawn uses 4):
    // if a stream held a worker, the ops below could never all answer.
    let mut streams: Vec<Sse> = (0..6).map(|_| Sse::connect(port)).collect();
    for s in &mut streams {
        s.expect_commit();
    }

    let v = op(port, None, r#"{"op":"next_account_prefix","parent":"1"}"#);
    expect_resp(&v, "maybe_addr");
    let (st, body) = http(
        port,
        "POST",
        "/op-at",
        None,
        br#"{"at":0,"frame":{"op":"next_account_prefix","parent":"1"}}"#,
    );
    assert_eq!(st, 200, "/op-at still answers: {}", String::from_utf8_lossy(&body));
    expect_resp(&json(&body), "maybe_addr");
    let (st, _) = get(port, "/health");
    assert_eq!(st, 200, "/health still answers");

    sd.shutdown();
}

#[test]
fn shutdown_with_open_streams_is_bounded_and_closes_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let mut a = Sse::connect(port);
    let mut b = Sse::connect(port);
    a.expect_commit();
    b.expect_commit();

    let t0 = Instant::now();
    sd.shutdown();
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "shutdown must not hang on open streams (took {:?})",
        t0.elapsed()
    );
    a.expect_eof();
    b.expect_eof();
}

/// A stream with nothing to report is kept alive by the documented `:ka`
/// comment, and still works afterwards. Nothing watched this — the helper's
/// `expect_commit` SKIPS any block beginning with `:`, so a daemon emitting
/// the wrong bytes, or none, looked exactly like one behaving. Deliberately
/// slow: it waits out the daemon's 15 s cadence.
#[test]
fn a_silent_stream_is_kept_alive_by_the_documented_ka_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let mut s = Sse::connect(port);
    let initial = s.expect_commit();
    // Nothing commits from here, so the next thing on the wire is the
    // keepalive or nothing at all.
    s.expect_keepalive();

    // Alive, not merely noisy: a commit still reaches the subscriber.
    let _ = delegate_first_principal(port);
    let after = s.expect_commit();
    assert!(
        after > initial,
        "the stream still delivers commits past a keepalive: {after} > {initial}"
    );

    sd.shutdown();
    s.expect_eof();
}
