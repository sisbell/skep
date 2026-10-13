use std::io::Write;
use std::net::TcpListener;
use std::thread;

use super::*;

/// A response splits into status, headers and body; a body short of its
/// `Content-Length` is a broken connection; garbage is no response.
#[test]
fn a_response_parses_and_a_short_body_is_a_break() {
    let (st, headers, at) = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSkepd-Session: closed\r\n\r\n{}").expect("parse");
    assert_eq!((st, at), (200, 61));
    assert_eq!(headers.get("skepd-session"), Some("closed"));
    assert!(parse_head(b"garbage").is_err());
    let resp = Response { status: 200, headers, body: b"{}".to_vec() };
    assert!(resp.session_closed());
}

/// The answer cap: read no further than the byte past it.
#[test]
fn an_answer_past_the_cap_is_read_no_further() {
    assert_eq!(read_to_close(&mut &[7u8; 10][..], 10).unwrap(), Some(vec![7u8; 10]));
    assert_eq!(read_to_close(&mut &[7u8; 11][..], 10).unwrap(), None);
}

/// One whole request off `s`: the head to its blank line, then exactly
/// the body its `Content-Length` declares. The dialer writes the head
/// and the body in two calls, so a single `read` may answer with the
/// head alone and the body still in flight.
fn read_request(s: &mut TcpStream) -> String {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let body_at = loop {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "the peer closed before the head's blank line");
        got.extend_from_slice(&buf[..n]);
        if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let declared: usize = String::from_utf8_lossy(&got[..body_at])
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: ").map(|v| v.trim().parse().unwrap()))
        .unwrap_or(0);
    while got.len() < body_at + declared {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "the peer closed before the declared body was in");
        got.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&got).to_string()
}

/// One request, one connection, `Connection: close`, the `Host` the
/// authority with brackets kept, no redirect followed — against a
/// listener that answers a redirect and a short body.
#[test]
fn the_plain_arm_writes_one_head_and_checks_the_length() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let mut heads = Vec::new();
        for answer in [
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 2\r\n\r\nok".to_string(),
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}".to_string(),
        ] {
            let (mut s, _) = listener.accept().unwrap();
            heads.push(read_request(&mut s));
            s.write_all(answer.as_bytes()).unwrap();
        }
        heads
    });
    let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let dialer = PlainHttp::new();
    let resp = dialer.exchange(&origin, &Request::post("/op", b"{}".to_vec()).header("Skepd-Session", "abc")).unwrap();
    assert_eq!((resp.status, resp.body.as_slice()), (302, &b"ok"[..]), "a redirect is an answer, never followed");
    let err = dialer.exchange(&origin, &Request::get("/health")).unwrap_err();
    assert_eq!(err, DialError::Truncated { declared: 5, got: 2 });
    let heads = server.join().unwrap();
    assert!(heads[0].starts_with("POST /op HTTP/1.1\r\n"), "{}", heads[0]);
    assert!(heads[0].contains(&format!("Host: 127.0.0.1:{port}\r\n")));
    assert!(heads[0].contains("Connection: close\r\n"));
    assert!(heads[0].contains("Content-Length: 2\r\n"));
    assert!(heads[0].contains("Skepd-Session: abc\r\n"));
    assert!(heads[0].ends_with("\r\n\r\n{}"));
    assert!(heads[1].starts_with("GET /health HTTP/1.1\r\n"));
    assert!(!heads[1].contains("Content-Type"), "a bodiless GET declares no content type");
}

/// The streamed form: `Expect: 100-continue` on the head where a body
/// follows, the interim head handed on before any body byte, the body
/// written after it, the final head returned with a reader over its body.
#[test]
fn the_streamed_form_waits_for_the_interim_head_before_the_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let mut got = Vec::new();
        loop {
            let n = s.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
            if got.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&got).to_string();
        assert!(!head.contains("hello"), "no body byte before the interim head");
        s.write_all(b"HTTP/1.1 100 Continue\r\nUpload-Id: u1\r\n\r\n").unwrap();
        let mut body = vec![0u8; 5];
        s.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"hello");
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone").unwrap();
        head
    });
    let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let head = RequestHead { method: Method::Post, path: "/blob/upload?length=5".into(), headers: vec![], content_length: Some(5) };
    let mut interim = Vec::new();
    let mut body = &b"hello"[..];
    let resp = PlainHttp::new().stream(&origin, &head, &mut body, &mut |h: &Headers| interim.push(h.get("Upload-Id").map(str::to_string))).unwrap();
    assert_eq!(resp.status, 200);
    let mut out = String::new();
    let mut reader = resp.body;
    reader.read_to_string(&mut out).unwrap();
    assert_eq!(out, "done");
    assert_eq!(interim, vec![Some("u1".to_string())]);
    let sent = server.join().unwrap();
    assert!(sent.contains("Expect: 100-continue\r\n"), "{sent}");
}

/// The plaintext warning fires on a plaintext non-loopback origin alone.
#[test]
fn the_plaintext_warning_keys_on_scheme_and_host() {
    assert!(plaintext_non_loopback_warning(&Origin::parse("http://127.0.0.1:8642").unwrap()).is_none());
    assert!(plaintext_non_loopback_warning(&Origin::parse("https://board.example").unwrap()).is_none());
    assert!(plaintext_non_loopback_warning(&Origin::parse("http://board.example:8642").unwrap()).is_some());
}

/// Without the `tls` arm an `https` origin is refused BY NAME BEFORE ANY
/// CONNECTION OPENS: a listening port and a closed one answer the same
/// refusal in both forms of the dial, and nothing reaches the listener.
#[cfg(not(feature = "tls"))]
#[test]
fn an_https_origin_without_the_tls_arm_is_refused_before_any_connection() {
    let listening = TcpListener::bind("127.0.0.1:0").unwrap();
    listening.set_nonblocking(true).unwrap();
    let open = listening.local_addr().unwrap().port();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let https = |port: u16| Origin::parse(&format!("https://127.0.0.1:{port}")).unwrap();
    let not_held = DialError::NotHeld("https".into());
    for port in [open, closed] {
        assert_eq!(PlainHttp::new().exchange(&https(port), &Request::get("/health")).unwrap_err(), not_held, "port {port}");
    }
    let head = RequestHead { method: Method::Get, path: "/events".into(), headers: Vec::new(), content_length: None };
    assert_eq!(PlainHttp::new().stream(&https(open), &head, &mut io::empty(), &mut |_: &Headers| {}).unwrap_err(), not_held);
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    while std::time::Instant::now() < deadline {
        match listening.accept() {
            Ok((_, peer)) => panic!("a connection from {peer} reached the listener"),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
            Err(e) => panic!("accept: {e}"),
        }
    }
}

/// With the `tls` arm an `https` origin puts no plaintext on the wire:
/// what reaches a plain listener is a TLS record or nothing — never a
/// request line, never the session header.
#[cfg(feature = "tls")]
#[test]
fn an_https_origin_puts_no_plaintext_request_on_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut got = vec![0u8; 16 * 1024];
        let n = s.read(&mut got).unwrap_or(0);
        got.truncate(n);
        got
    });
    let origin = Origin::parse(&format!("https://127.0.0.1:{port}")).unwrap();
    let req = Request::post("/op", b"{}".to_vec()).header("Skepd-Session", "9f3a6c21d4b8e07a5c1b2d4e6f708192");
    PlainHttp::new().exchange(&origin, &req).expect_err("no TLS server answers");
    let got = server.join().unwrap();
    assert!(!got.windows(8).any(|w| w == b"HTTP/1.1") && !got.windows(13).any(|w| w == b"Skepd-Session"), "plaintext on the wire: {got:?}");
    assert!(got.first().is_none_or(|b| *b == 0x16), "not a TLS handshake record: {got:?}");
}

/// A board that trickles its answer a byte at a time, each inside the
/// per-call bound, is cut off at the exchange's DEADLINE: the dialer arms
/// every read with the time left, and answers `Timeout` once it is spent —
/// here a deadline of one second against an answer that would take a
/// hundred.
#[test]
fn a_trickling_board_is_cut_off_at_the_exchanges_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n");
        for _ in 0..50 {
            if s.write_all(b"x").is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let dialer = PlainHttp { exchange_bound: Duration::from_secs(1), ..PlainHttp::new() };
    let began = std::time::Instant::now();
    let err = dialer.exchange(&origin, &Request::get("/health")).expect_err("the deadline passed");
    assert!(matches!(err, DialError::Timeout(_)), "{err}");
    assert!(began.elapsed() < Duration::from_secs(2), "cut off after {:?}", began.elapsed());
    server.join().unwrap();
}

/// The request target and the headers are written as given, so a line
/// break in either — the bytes that would end the request line or a header
/// and write one of their own choosing — is refused before any connection
/// opens, in both forms of the dial; nothing reaches the listener.
#[test]
fn a_target_or_header_that_would_end_its_line_is_refused_before_any_connection() {
    let listening = TcpListener::bind("127.0.0.1:0").unwrap();
    listening.set_nonblocking(true).unwrap();
    let origin = Origin::parse(&format!("http://127.0.0.1:{}", listening.local_addr().unwrap().port())).unwrap();
    let refused = |r: Result<Response, DialError>| matches!(r, Err(DialError::Request(_)));
    // Short bounds, so a request that did reach the listener would fail
    // fast — unanswered — rather than wait out the pinned ones.
    let dialer = PlainHttp { io_timeout: Duration::from_millis(300), exchange_bound: Duration::from_millis(300), ..PlainHttp::new() };
    assert!(refused(dialer.exchange(&origin, &Request::get("/health\r\nInjected: yes"))));
    assert!(refused(dialer.exchange(&origin, &Request::get("/a b"))));
    assert!(refused(dialer.exchange(&origin, &Request::get("/health").header("Skepd-Session", "abc\r\nInjected: yes"))));
    assert!(refused(dialer.exchange(&origin, &Request::get("/health").header("Bad Name", "v"))));
    assert!(refused(dialer.exchange(&origin, &Request::get("/health").header("", "v"))));
    let head = RequestHead { method: Method::Get, path: "/events\n".into(), headers: Vec::new(), content_length: None };
    assert!(matches!(dialer.stream(&origin, &head, &mut io::empty(), &mut |_: &Headers| {}), Err(DialError::Request(_))));
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    while std::time::Instant::now() < deadline {
        match listening.accept() {
            Ok((_, peer)) => panic!("a connection from {peer} reached the listener"),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
            Err(e) => panic!("accept: {e}"),
        }
    }
}
