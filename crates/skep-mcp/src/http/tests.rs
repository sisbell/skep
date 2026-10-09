use std::net::TcpListener;

use super::*;

#[test]
fn only_an_http_origin_without_a_path_parses() {
    let h = Http::parse("http://127.0.0.1:8642").expect("default form");
    assert_eq!(h.authority(), "127.0.0.1:8642");
    let h = Http::parse("http://localhost").expect("portless form");
    assert_eq!((h.host.as_str(), h.port), ("localhost", 80));
    let h = Http::parse("http://127.0.0.1:8642/").expect("bare trailing slash");
    assert_eq!(h.port, 8642);
    for bad in [
        "https://127.0.0.1:8642",
        "127.0.0.1:8642",
        "http://",
        "http://:8642",
        "http://127.0.0.1:notaport",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:8642/op",
    ] {
        assert!(Http::parse(bad).is_err(), "'{bad}' must not parse");
    }
}

/// Bracketed IPv6 sheds its brackets for the resolver, with a port and
/// without one — the colons inside the brackets are the address's own —
/// while the authority keeps them for the `Host` header.
#[test]
fn bracketed_ipv6_sheds_its_brackets() {
    let h = Http::parse("http://[::1]:8642").expect("bracketed, with a port");
    assert_eq!((h.host.as_str(), h.port, h.authority()), ("::1", 8642, "[::1]:8642"));
    let h = Http::parse("http://[::1]").expect("bracketed, without a port");
    assert_eq!((h.host.as_str(), h.port, h.authority()), ("::1", 80, "[::1]"));
}

#[test]
fn a_response_splits_at_its_head_and_a_short_body_is_a_break() {
    let (st, body) =
        parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").expect("parse");
    assert_eq!((st, body.as_slice()), (200, &b"{}"[..]));
    let (_, body) = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}tail")
        .expect("a body with bytes past its length");
    assert_eq!(body, b"{}", "bytes past the stated length are no part of the answer");
    assert!(
        parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}").is_err(),
        "a short body is a broken connection, not an answer"
    );
    assert!(parse_response(b"garbage").is_err());
}

/// A failed exchange names the origin and the step, never the request:
/// a daemon that answers garbage, or hangs up unanswered, is reported
/// without the header value that rode the request.
#[test]
fn failures_never_quote_the_request() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a stub daemon");
    let port = listener.local_addr().expect("stub address").port();
    let answers: [&[u8]; 2] = [b"garbage", b""];
    let stub = std::thread::spawn(move || {
        for answer in answers {
            let (mut conn, _) = listener.accept().expect("accept");
            let _ = conn.read(&mut [0u8; 1024]);
            let _ = conn.write_all(answer);
        }
    });
    let http = Http::parse(&format!("http://127.0.0.1:{port}")).expect("stub url");
    for _ in answers {
        let err = http
            .exchange(Method::Post, "/op", &[("Skepd-Session", "s3cr3t")], b"{}")
            .expect_err("no answer to read");
        assert!(!err.contains("s3cr3t"), "the failure quotes the request: {err}");
        assert!(err.starts_with(&format!("skepd at http://127.0.0.1:{port}: ")), "{err}");
    }
    stub.join().expect("the stub daemon");
}

/// A daemon that takes the request and never answers is a clear failure
/// within the read bound, not a stall: the exchange ends `Err`, naming
/// the origin and the read step. Takes `IO_TIMEOUT` by construction.
#[test]
fn a_daemon_that_never_answers_fails_the_read_within_its_bound() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a stub daemon");
    let port = listener.local_addr().expect("stub address").port();
    let (release, held) = std::sync::mpsc::channel::<()>();
    let stub = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        let _ = conn.read(&mut [0u8; 1024]);
        let _ = held.recv(); // open, unanswered, until the test lets go
    });
    let http = Http::parse(&format!("http://127.0.0.1:{port}")).expect("stub url");
    let (done, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(http.exchange(Method::Post, "/op", &[], b"{}"));
    });
    let err = outcome
        .recv_timeout(IO_TIMEOUT * 3)
        .expect("the exchange outlived three read bounds: a hung daemon stalls the adapter")
        .expect_err("no answer came");
    assert!(err.starts_with(&format!("skepd at http://127.0.0.1:{port}: read: ")), "{err}");
    drop(release);
    stub.join().expect("the stub daemon");
}

/// One connection's peer, served by `serve` on an ephemeral port.
fn stub(serve: impl FnOnce(TcpStream) + Send + 'static) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a stub peer");
    let port = listener.local_addr().expect("stub address").port();
    (port, std::thread::spawn(move || serve(listener.accept().expect("accept").0)))
}

/// The request off a stub peer's connection, read whole — every request
/// here carries the body `{}` — so the peer's close is a clean end of
/// stream, never a reset that drops the answer's tail over bytes it left
/// unread.
fn take_request(conn: &mut TcpStream) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    while !raw.ends_with(b"\r\n\r\n{}") {
        match conn.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
}

/// An answer is read to the cap and no further: one of exactly
/// `MAX_ANSWER_BYTES`, head and body, is the answer; one byte more is the
/// read step's refusal naming the cap, whatever the board rendered.
#[test]
fn an_answer_is_read_to_the_cap_and_one_byte_past_it_is_refused() {
    let head = |n: usize| format!("HTTP/1.1 200 OK\r\nContent-Length: {n:08}\r\n\r\n");
    let head_len = head(0).len();
    for (total, whole) in [(MAX_ANSWER_BYTES, true), (MAX_ANSWER_BYTES + 1, false)] {
        let mut answer = head(total - head_len).into_bytes();
        answer.resize(total, b'x');
        let (port, peer) = stub(move |mut conn| {
            take_request(&mut conn);
            let _ = conn.write_all(&answer);
        });
        let http = Http::parse(&format!("http://127.0.0.1:{port}")).expect("stub url");
        match http.exchange(Method::Post, "/op", &[], b"{}") {
            Ok((_, body)) => assert!(whole && body.len() == total - head_len, "{total} read whole"),
            Err(e) => assert!(!whole && e.contains(": read: answer past the "), "{total}: {e}"),
        }
        peer.join().expect("the stub peer");
    }
}

/// A paced answer — a byte every half second, each renewing the per-call
/// timeout — is cut at its deadline, within the read in flight: slowness
/// ends a read as silence does. Two seconds here; `exchange` passes
/// `TRANSFER_DEADLINE`.
#[test]
fn a_paced_answer_is_cut_at_its_deadline() {
    let (port, peer) = stub(|mut conn| {
        while conn.write_all(b"x").is_ok() {
            std::thread::sleep(Duration::from_millis(500));
        }
    });
    let mut conn = TcpStream::connect(("127.0.0.1", port)).expect("connect to the stub");
    conn.set_read_timeout(Some(IO_TIMEOUT)).expect("a read timeout");
    let (done, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let started = Instant::now();
        let cut = read_bounded(&mut conn, started + Duration::from_secs(2));
        let _ = done.send((cut, started.elapsed()));
    });
    let (cut, took) = outcome
        .recv_timeout(Duration::from_secs(2) + IO_TIMEOUT)
        .expect("the read outlived its deadline and one read: a paced peer stalls the adapter");
    let err = cut.expect_err("a paced answer is cut");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    // The deadline, the one paced read in flight, a second's slack.
    assert!(took < Duration::from_millis(2_000 + 500 + 1_000), "cut late: {took:?}");
    peer.join().expect("the stub peer");
}

/// A request drained slowly — 256 KiB every quarter second, each taken
/// byte renewing the silence bound — is cut at its deadline, within one
/// `WRITE_POLL`: 32 MiB outruns any loopback buffer, so the write is still
/// waiting on the peer when the deadline passes. Two seconds here;
/// `exchange` passes `TRANSFER_DEADLINE`.
#[test]
fn a_slowly_drained_request_is_cut_at_its_deadline() {
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    let (port, peer) = stub(move |mut conn| {
        let mut sip = vec![0u8; 256 * 1024];
        while stopped.try_recv() == Err(std::sync::mpsc::TryRecvError::Empty)
            && conn.read(&mut sip).is_ok_and(|n| n > 0)
        {
            std::thread::sleep(Duration::from_millis(250));
        }
    });
    let mut conn = TcpStream::connect(("127.0.0.1", port)).expect("connect to the stub");
    let (done, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let body = vec![b' '; 32 * 1024 * 1024];
        let started = Instant::now();
        let cut = write_bounded(&mut conn, &body, started + Duration::from_secs(2));
        let _ = done.send((cut, started.elapsed()));
    });
    let (cut, took) = outcome
        .recv_timeout(Duration::from_secs(2) + IO_TIMEOUT)
        .expect("the write outlived its deadline: a slow drain stalls the adapter");
    let err = cut.expect_err("a slowly drained request is cut");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    assert!(err.to_string().contains("transfer deadline"), "{err}");
    // The deadline, one `WRITE_POLL`, a second's slack.
    assert!(took < Duration::from_secs(2) + WRITE_POLL + Duration::from_secs(1), "{took:?}");
    drop(stop);
    peer.join().expect("the stub peer");
}

/// A request the peer stops taking — nothing read, its buffers full — is
/// cut by the silence bound, long before its deadline: a dead peer ends a
/// write as it ends a read. The bound counts from the last byte the socket
/// took, and a kernel's own zero-window probe can take a few after the
/// peer has stopped reading (macOS's, five seconds in), so this takes
/// `IO_TIMEOUT` and up to one probe interval by construction.
#[test]
fn a_request_the_peer_stops_taking_is_cut_at_the_silence_bound() {
    let (release, held) = std::sync::mpsc::channel::<()>();
    let (port, peer) = stub(move |_conn| {
        let _ = held.recv(); // open, never read, until the test lets go
    });
    let mut conn = TcpStream::connect(("127.0.0.1", port)).expect("connect to the stub");
    let deadline = IO_TIMEOUT * 4;
    let (done, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let body = vec![b' '; 32 * 1024 * 1024];
        let started = Instant::now();
        let cut = write_bounded(&mut conn, &body, started + deadline);
        let _ = done.send((cut, started.elapsed()));
    });
    let (cut, took) = outcome
        .recv_timeout(deadline + IO_TIMEOUT)
        .expect("the write outlived its deadline: a dead peer stalls the adapter");
    let err = cut.expect_err("a request nobody takes is cut");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    assert!(err.to_string().contains("stopped draining"), "the silence bound cut it: {err}");
    assert!(took >= IO_TIMEOUT && took < deadline, "cut at {took:?}");
    drop(release);
    peer.join().expect("the stub peer");
}

/// A head is recognized whole or not at all: a status line that is not
/// HTTP/1.x, or a Content-Length missing, repeated, signed, or unreadable
/// as a usize, is no answer — each would skip or misapply the one check
/// that tells a broken connection from a whole body.
#[test]
fn a_head_that_cannot_state_its_length_is_no_answer() {
    let heads: [&[u8]; 6] = [
        b"ICY 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 1\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: two\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n{}",
    ];
    for bad in heads {
        let shown = String::from_utf8_lossy(bad);
        assert!(parse_response(bad).is_err(), "relayed as an answer: {shown:?}");
    }
}
