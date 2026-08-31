//! Wire v4 commit stream over a real socket: the initial head on connect,
//! push on commit to every subscriber, survivor independence when one
//! disconnects, no starvation of the op surface, and bounded shutdown that
//! closes open streams. Transport behavior only — the writes are the
//! smallest committing operations available.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::*;

/// The daemon's live-stream budget (its `MAX_SUBSCRIBERS`), restated here
/// on purpose — the same discipline `http_lifecycle.rs` applies to the body
/// cap. A restatement is what makes the constant moving a visible event
/// rather than a test that quietly exercises less than it says.
const SUBSCRIBER_CAP: usize = 64;

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

    // On connect: one event carrying the last ANNOUNCED position, which on
    // a quiescent daemon IS the committed head — that equality is what
    // makes the /health comparison legitimate here. The two differ only
    // between a write's commit and its change-feed record, which
    // `server.rs`'s
    // `a_connecting_subscriber_is_told_the_announced_position_not_the_head`
    // opens deliberately rather than racing for.
    let mut a = Sse::connect(port);
    let initial = a.expect_commit();
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    assert_eq!(
        json(&body)["log_position"].as_u64().expect("health log_position"),
        initial,
        "with nothing in flight, the announced position is the committed head"
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
#[ignore = "timing test - gate-full only"]
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

/// One raw `GET /events` connection, returning the first bytes the daemon
/// sends. A served stream opens with its `200` head; a refused one is a
/// clean close with nothing at all, which is the same end a subscriber
/// meets at shutdown and the one a reconnecting client already handles.
fn raw_events(port: u16) -> (TcpStream, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect /events");
    s.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
    s.write_all(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").expect("write request");
    let mut head = [0u8; 256];
    // A read error counts as a refusal: a reset means the daemon dropped
    // the socket, which is the same answer as a clean close with no head.
    let n: usize = s.read(&mut head).unwrap_or_default();
    (s, head[..n].to_vec())
}

/// Live streams are budgeted, and the surplus is refused rather than
/// spawned. The assertion that matters most is the last one: the spawn a
/// stream needs sits OUTSIDE the handler's `catch_unwind`, so a worker that
/// died refusing one would leave the daemon bound, up, and permanently
/// unable to answer — a failure `/health` is the only witness to.
#[test]
fn live_streams_are_budgeted_and_the_surplus_is_refused_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let held: Vec<(TcpStream, Vec<u8>)> = (0..SUBSCRIBER_CAP).map(|_| raw_events(port)).collect();
    for (i, (_, head)) in held.iter().enumerate() {
        assert!(
            head.starts_with(b"HTTP/1.1 200 "),
            "stream {i} of the budget must be served: {:?}",
            String::from_utf8_lossy(head)
        );
    }

    // One past the budget: refused with a clean close, no stream head.
    let (_surplus, head) = raw_events(port);
    assert!(
        head.is_empty(),
        "a stream past the budget is refused, not served: {:?}",
        String::from_utf8_lossy(&head)
    );

    // The refusal cost one stream and nothing else: the op surface still
    // answers, which is what a retired worker would break.
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "the daemon survives a refused stream");
    assert_eq!(json(&body)["ok"].as_bool(), Some(true));
    let v = op(port, None, r#"{"op":"next_account_prefix","parent":"1"}"#);
    expect_resp(&v, "maybe_addr");

    // A departed subscriber's slot returns to the budget by the mechanism
    // the daemon documents rather than at the moment the client walks away:
    // a parked subscriber is woken by a commit and learns its peer is gone
    // from the failed write. ONE commit does not settle it — a write to a
    // peer that closed with nothing left unread still succeeds, and only the
    // reset behind it fails the write after — so the loop commits as it
    // polls, driving that mechanism instead of racing the kernel for which
    // of the two closes each client happened to make. `register_node` is
    // the commit: it needs a bound session and nothing else, so it can be
    // repeated with a fresh node address as many times as the poll needs.
    drop(held);
    let boot = open_session(port, 0);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut node = 1_000u64;
    let mut reclaimed = Vec::new();
    while reclaimed.is_empty() && Instant::now() < deadline {
        node += 1;
        let v = op(port, Some(&boot), &format!(r#"{{"op":"register_node","addr":"1.{node}"}}"#));
        assert!(v["at"].is_u64(), "the poll's commit must actually commit: {v}");
        reclaimed = raw_events(port).1;
    }
    assert!(
        reclaimed.starts_with(b"HTTP/1.1 200 "),
        "slots freed by departed subscribers must return to the budget"
    );

    sd.shutdown();
}
