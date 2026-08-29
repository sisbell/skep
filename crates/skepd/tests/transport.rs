//! wire.md §Transport — the HTTP/1.1 subset skepd speaks, asserted over a
//! real socket.
//!
//! These claims are invisible to every other suite: `tests/common`'s
//! `http_full` sends one well-formed 1.1 head with `Connection: close` and
//! an exact `Content-Length`, then reads to EOF — so it can neither observe
//! the daemon's own framing headers nor produce a request outside the
//! subset. Every test here writes request bytes verbatim.

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use common::*;

/// Client-side socket timeout for the hand-rolled exchange below. Well under
/// the daemon's own 30 s request read timeout, so a daemon that fails to
/// answer fails this test rather than the gate's patience.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// A complete, well-formed request with a JSON body.
fn post(path: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Every response the daemon writes declares `Connection: close` — wire.md
/// §Transport's "one request per connection", which is how a client knows
/// not to hold the socket for a second exchange. Both branches of the reply
/// writer are covered (a bodied answer and the bodiless 204), and both
/// paths that write one: routed replies, and the refusals answered before
/// routing ever happens.
#[test]
fn every_response_declares_connection_close() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let cases: Vec<(&str, Vec<u8>, u16)> = vec![
        ("a bodied 200", b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(), 200),
        (
            "the bodiless 204 preflight",
            b"OPTIONS /op HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(),
            204,
        ),
        ("an unknown path", b"GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(), 404),
        ("a refused method", b"PUT /op HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(), 405),
        ("a routed transport error", post("/session", r#"{"user":"alice"}"#), 400),
        (
            "a refusal answered before routing",
            b"POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
            400,
        ),
        (
            "the body-cap refusal",
            format!(
                "POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
                8 * 1024 * 1024 + 1
            )
            .into_bytes(),
            413,
        ),
    ];
    for (what, raw, expect) in cases {
        let (status, headers, _) = raw_exchange(port, &raw);
        assert_eq!(status, expect, "{what}");
        assert_eq!(
            header(&headers, "Connection"),
            Some("close"),
            "{what} ({status}) must declare Connection: close"
        );
    }

    sd.shutdown();
}

/// The accepted protocol versions are exactly `HTTP/1.1` and `HTTP/1.0`
/// (wire.md §Transport); anything else is outside the subset and gets the
/// documented `400 malformed_http`, never a silent best effort.
#[test]
fn the_accepted_http_versions_are_exactly_1_1_and_1_0() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    for version in ["HTTP/1.1", "HTTP/1.0"] {
        let raw = format!("GET /health {version}\r\nHost: 127.0.0.1\r\n\r\n").into_bytes();
        let (status, _, body) = raw_exchange(port, &raw);
        assert_eq!(status, 200, "{version} is accepted: {}", String::from_utf8_lossy(&body));
        assert_eq!(json(&body)["ok"].as_bool(), Some(true), "{version}");
    }
    for version in ["HTTP/0.9", "HTTP/2.0", "HTTP/1.2", "ICY/1.0", ""] {
        let raw = format!("GET /health {version}\r\nHost: 127.0.0.1\r\n\r\n").into_bytes();
        let (status, _, body) = raw_exchange(port, &raw);
        assert_eq!(status, 400, "{version:?} is outside the subset");
        assert_eq!(json(&body)["error"].as_str(), Some("malformed_http"), "{version:?}");
    }

    sd.shutdown();
}

/// A `Transfer-Encoding` request body is REFUSED, not read (wire.md
/// §Transport). The fear is a wrong diagnosis: a daemon that ignored the
/// header would frame the body by the absent `Content-Length`, read
/// nothing, and answer a well-formed chunked request with `unparseable` —
/// telling the client its JSON was bad when the framing was unsupported.
#[test]
fn a_chunked_request_body_is_refused_rather_than_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let frame = r#"{"op":"next_account_prefix","parent":"1"}"#;
    let raw = format!(
        "POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Transfer-Encoding: chunked\r\n\r\n{:x}\r\n{frame}\r\n0\r\n\r\n",
        frame.len()
    )
    .into_bytes();
    let (status, _, body) = raw_exchange(port, &raw);
    assert_eq!(status, 400, "chunked framing is refused: {}", String::from_utf8_lossy(&body));
    let v = json(&body);
    assert_eq!(v["error"].as_str(), Some("malformed_http"));
    assert!(v["detail"].is_string(), "the refusal names what was unsupported: {v}");

    sd.shutdown();
}

/// Everything else outside the subset is the same honest refusal — `400
/// malformed_http` with a detail (wire.md §HTTP status codes: "bad head,
/// chunked body, a body cut short") — and a pre-routing refusal still
/// carries the universal CORS header, since it is written before
/// `Daemon::route` ever runs.
#[test]
fn requests_outside_the_http_subset_are_refused_malformed_http() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let cut_short =
        format!("POST /op HTTP/1.1\r\nContent-Length: 100\r\n\r\n{}", r#"{"op":"fork"}"#);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("a request line with no version", b"GET /health\r\nHost: 127.0.0.1\r\n\r\n".to_vec()),
        ("a request line with no target", b"GET\r\nHost: 127.0.0.1\r\n\r\n".to_vec()),
        ("a request line with a stray field", b"GET /health HTTP/1.1 extra\r\n\r\n".to_vec()),
        ("a lowercase method token", b"get /health HTTP/1.1\r\n\r\n".to_vec()),
        (
            "a header line with no colon",
            b"GET /health HTTP/1.1\r\nHost 127.0.0.1\r\n\r\n".to_vec(),
        ),
        (
            "a non-numeric Content-Length",
            b"POST /op HTTP/1.1\r\nContent-Length: ten\r\n\r\n".to_vec(),
        ),
        ("a body cut short of its declared length", cut_short.into_bytes()),
        // A header this daemon READS, twice. Silently taking the last would
        // pick between a stalled read and a truncated frame by which line
        // came last, and answer one malformed head with two diagnoses.
        (
            "two Content-Length headers",
            b"POST /op HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 9\r\n\r\n".to_vec(),
        ),
        (
            "two Skepd-Session headers",
            b"POST /op HTTP/1.1\r\nSkepd-Session: a\r\nskepd-session: b\r\n\r\n".to_vec(),
        ),
        (
            "two Expect headers",
            b"POST /op HTTP/1.1\r\nExpect: 100-continue\r\nExpect: nonsense\r\n\r\n".to_vec(),
        ),
    ];
    for (what, raw) in cases {
        let (status, headers, body) = raw_exchange(port, &raw);
        assert_eq!(status, 400, "{what}: {}", String::from_utf8_lossy(&body));
        let v = json(&body);
        assert_eq!(v["error"].as_str(), Some("malformed_http"), "{what}");
        assert!(v["detail"].is_string(), "{what}: the refusal says what failed: {v}");
        assert_eq!(
            header(&headers, "Access-Control-Allow-Origin"),
            Some("*"),
            "{what}: a pre-routing refusal still carries the universal CORS header"
        );
    }

    sd.shutdown();
}

/// An absent `Content-Length` is an EMPTY body, not a body read to EOF
/// (wire.md §Transport) — the shape every browser `fetch` GET takes. A
/// `POST /op` so framed carries no frame, so it gets the never-silent
/// answer: one `unparseable` rejection on the operation channel, at 200.
#[test]
fn an_absent_content_length_is_an_empty_body() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let (status, _, body) =
        raw_exchange(port, b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    assert_eq!(status, 200, "a bodyless GET is served: {}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["ok"].as_bool(), Some(true));

    let (status, _, body) = raw_exchange(port, b"POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    assert_eq!(status, 200, "an empty frame is an operation answer, not a transport error");
    assert_eq!(expect_resp(&json(&body), "rejected")["op"].as_str(), Some("unparseable"));

    sd.shutdown();
}

/// Read from `stream` until the buffer holds a CRLFCRLF; returns its index.
/// Panics rather than hanging — a daemon that never answers must name
/// itself in the failure, not stall the gate.
fn read_head(stream: &mut TcpStream, buf: &mut Vec<u8>, what: &str) -> usize {
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return i;
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => panic!(
                "{what}: the daemon closed without a complete head; got {:?}",
                String::from_utf8_lossy(buf)
            ),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => panic!(
                "{what}: nothing within {CLIENT_TIMEOUT:?} ({e}); got {:?}",
                String::from_utf8_lossy(buf)
            ),
        }
    }
}

/// `Expect: 100-continue` is honored (wire.md §Transport): a client that
/// withholds its body until invited gets the interim `100 Continue` BEFORE
/// it sends a byte, then the ordinary answer. curl does this for large
/// payloads; a daemon that ignored the header would sit waiting for a body
/// the client is waiting to be asked for, and this read would time out.
#[test]
fn expect_100_continue_is_answered_before_the_body_is_sent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let frame = br#"{"op":"next_account_prefix","parent":"1"}"#;
    let head = format!(
        "POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Expect: 100-continue\r\nContent-Length: {}\r\n\r\n",
        frame.len()
    );

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to skepd");
    stream.set_read_timeout(Some(CLIENT_TIMEOUT)).expect("read timeout");
    stream.set_write_timeout(Some(CLIENT_TIMEOUT)).expect("write timeout");
    // The head alone — the body is withheld exactly as curl withholds it.
    stream.write_all(head.as_bytes()).expect("write the request head");

    let mut buf: Vec<u8> = Vec::new();
    let end = read_head(&mut stream, &mut buf, "the 100-continue invitation");
    assert_eq!(
        &buf[..end + 4],
        b"HTTP/1.1 100 Continue\r\n\r\n",
        "the interim answer must invite the body: {:?}",
        String::from_utf8_lossy(&buf[..end + 4])
    );
    buf.drain(..end + 4);

    // Invited, the body goes; the ordinary answer follows it.
    stream.write_all(frame).expect("write the withheld body");
    stream.shutdown(Shutdown::Write).expect("half-close");
    stream.read_to_end(&mut buf).expect("read the final response");
    let (status, headers, body) = parse_response(&buf, "the answer behind 100-continue");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(header(&headers, "Connection"), Some("close"));
    assert_eq!(json(&body)["resp"].as_str(), Some("maybe_addr"));

    sd.shutdown();
}

/// The body cap for a route that carries no frame — the daemon's own
/// `MAX_SMALL_BODY`, restated so that moving it is a visible decision.
const SMALL_BODY_CAP: usize = 8 * 1024;

/// The body cap is the ROUTE's, not the daemon's: only `/op` and `/op-at`
/// carry a frame, and every other route's body is read whole and then never
/// looked at — so offering them the frame ceiling offers the `serde_json`
/// tree that rides on it, for bytes nothing will read.
#[test]
fn the_body_cap_is_scoped_to_the_routes_that_carry_frames() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // Declared, never sent: the refusal must arrive on the declared length
    // alone, so nothing here depends on writing a megabyte.
    let declare = |path: &str, n: usize| {
        let raw =
            format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {n}\r\n\r\n")
                .into_bytes();
        raw_exchange(port, &raw)
    };

    // A route that carries no frame is held to the small cap. The number is
    // restated here rather than read from the daemon, the same discipline
    // `http_lifecycle.rs` applies to the frame cap: it moving is a decision,
    // and a decision should fail a test rather than pass one silently.
    for path in ["/session", "/health", "/changes", "/nope"] {
        let (status, _, body) = declare(path, 1024 * 1024);
        assert_eq!(status, 413, "{path}: {}", String::from_utf8_lossy(&body));
        let v = json(&body);
        assert_eq!(v["error"].as_str(), Some("payload_too_large"), "{path}");
        assert!(
            v["detail"].as_str().is_some_and(|d| d.contains(&SMALL_BODY_CAP.to_string())),
            "{path}: the refusal names the cap that actually bound it: {v}"
        );
    }
    // …and still admits what it legitimately carries.
    let (status, _, body) = raw_exchange(port, &post("/session", r#"{"principal":3}"#));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(json(&body)["session"].is_string());

    // A frame route keeps the frame ceiling: a megabyte is admitted, and
    // this exchange ends on the body it never received, not on the cap.
    let (status, _, body) = declare("/op", 1024 * 1024);
    assert_eq!(status, 400, "a frame route admits a megabyte: {}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("malformed_http"));

    sd.shutdown();
}

/// A peer that PACES its bytes is refused at the transfer deadline. The
/// socket's own read timeout bounds SILENCE and is renewed by every byte,
/// so without a deadline this connection holds its worker for as long as it
/// cares to drip — and `workers` such peers retire the daemon with nothing
/// inside it wrong and `/health` unreachable, since reaching it needs a
/// worker. Necessarily slow: it waits the deadline out.
#[test]
fn a_paced_peer_is_refused_at_the_transfer_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // The read timeout doubles as the pacing interval: each attempt either
    // collects the daemon's answer or times out and drips one more byte.
    // Reading between writes is what keeps this honest — the moment an
    // answer arrives we stop writing, so a write to a closed socket can
    // never reset the connection and discard the response we are judging.
    stream.set_read_timeout(Some(Duration::from_millis(500))).expect("read timeout");
    stream
        .write_all(b"POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        .expect("the partial head is accepted");

    let start = Instant::now();
    let mut raw = Vec::new();
    let mut paced: usize = 0;
    // Generously past the daemon's 30 s deadline: arriving late is still
    // arriving, and the assertion below is what judges the timing.
    while start.elapsed() < Duration::from_secs(90) {
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                // The refusal is complete only when its BODY has landed too:
                // `write_reply` writes the head and the body as two separate
                // calls, so any scheduling delay between them puts the head
                // in one read and the body in the next. Stopping at the
                // header terminator would judge a body still in flight, and
                // the pacing above must stop the moment the head arrives —
                // a further write to the closed socket would reset the
                // connection and discard the answer under test.
                if response_is_complete(&raw) {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                // Never silent, never finished: one more header byte, which
                // renews the socket's own deadline and nothing else.
                if stream.write_all(b"X").is_err() {
                    break;
                }
                paced += 1;
            }
            Err(_) => break,
        }
    }
    let held = start.elapsed();
    assert!(
        paced > 4,
        "the peer must actually have paced its bytes rather than stalled: {paced} sent"
    );
    assert!(
        held < Duration::from_secs(75),
        "a paced peer must be released at the deadline, not served indefinitely (held {held:?})"
    );
    let (status, _, body) = parse_response(&raw, "the paced peer's refusal");
    assert_eq!(status, 400, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("malformed_http"));

    // The refusal cost one connection and nothing else.
    let (status, body) = get(port, "/health");
    assert_eq!(status, 200, "the daemon still serves");
    assert_eq!(json(&body)["ok"].as_bool(), Some(true));

    sd.shutdown();
}

/// Whether `raw` holds a complete response — the head AND the body its
/// `Content-Length` declares. The daemon writes the two separately, so a
/// caller that stops at the header terminator can be judging a body that
/// has not arrived; the length is what says when there is nothing more to
/// wait for.
fn response_is_complete(raw: &[u8]) -> bool {
    let Some(sep) = raw.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
    let Ok(head) = std::str::from_utf8(&raw[..sep]) else { return false };
    let declared: usize = head
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        // A refusal always declares its length; anything that does not is
        // complete at its head, which is what a bodiless answer is.
        .unwrap_or(0);
    raw.len() - (sep + 4) >= declared
}

/// The daemon's own request-head cap, restated so that moving it is a
/// visible decision — the discipline `SMALL_BODY_CAP` above already gets.
const HEAD_CAP: usize = 64 * 1024;

/// The head cap is the only bound on what one connection's headers may
/// allocate: the socket timeouts bound silence, the transfer deadline
/// bounds slowness, and loopback delivers gigabytes inside thirty seconds
/// — so `workers` peers against an uncapped reader is the whole memory of
/// the process.
///
/// The refusal must NAME the cap, because the connection-closed path
/// answers the same `malformed_http`: a daemon that had lost the cap would
/// still 400 here, on the EOF, after buffering everything first. A
/// status-only assertion cannot tell the two apart.
#[test]
fn a_head_at_the_cap_is_read_and_one_byte_past_it_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // Far past any ordinary request and well under the cap: served.
    let mut head = String::from("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    while head.len() < HEAD_CAP / 2 {
        head.push_str(&format!("X-Fill-{:05}: {}\r\n", head.len(), "f".repeat(64)));
    }
    head.push_str("\r\n");
    let (status, _, body) = raw_exchange(port, head.as_bytes());
    assert_eq!(
        status,
        200,
        "a large admissible head is served: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json(&body)["ok"].as_bool(), Some(true));

    // Exactly the cap, and not a byte more, with no terminator: the daemon
    // is still waiting for one, so nothing has come back. This is the
    // load-bearing half — a `>` that became a `>=` refuses a head the
    // daemon is documented to read.
    let mut head = String::from("POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Fill: ");
    while head.len() < HEAD_CAP {
        head.push('f');
    }
    assert_eq!(head.len(), HEAD_CAP, "the first write is exactly the cap");

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_millis(200))).expect("read timeout");
    stream.set_write_timeout(Some(CLIENT_TIMEOUT)).expect("write timeout");
    stream.write_all(head.as_bytes()).expect("a head at the cap is accepted");
    // Long enough for the daemon to drain 64 KiB of loopback and block on
    // its next read, which is what leaves its receive queue empty below.
    std::thread::sleep(Duration::from_millis(250));
    let mut probe = [0u8; 512];
    match stream.read(&mut probe) {
        Ok(0) => panic!("the daemon closed on a head that is only AT the cap"),
        Ok(n) => panic!(
            "a head at the cap was refused: {:?}",
            String::from_utf8_lossy(&probe[..n])
        ),
        Err(_) => {} // nothing came back, which is the claim
    }

    // One byte more crosses it. The daemon has already consumed everything
    // we sent, so it refuses with an empty receive queue and closes
    // cleanly — no reset, so the refusal reaches us intact.
    stream.write_all(b"f").expect("write the byte past the cap");
    stream.shutdown(Shutdown::Write).expect("half-close");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read the refusal");
    let (status, _, body) = parse_response(&raw, "the over-cap head's refusal");
    assert_eq!(status, 400, "{}", String::from_utf8_lossy(&body));
    let v = json(&body);
    assert_eq!(v["error"].as_str(), Some("malformed_http"));
    let detail = v["detail"].as_str().expect("the refusal says what failed");
    assert!(
        detail.contains(&HEAD_CAP.to_string()),
        "the refusal names the cap it met, not the close it never reached: {detail}"
    );

    // The refusal cost one connection and nothing else.
    let (status, body) = get(port, "/health");
    assert_eq!(status, 200, "the daemon still serves");
    assert_eq!(json(&body)["ok"].as_bool(), Some(true));

    sd.shutdown();
}

/// A body is framed by `Content-Length` and whatever follows is dropped
/// unread. A daemon that read to the head/body boundary instead would hand
/// the codec `{…}XXXX` and answer `unparseable`, telling a client that
/// appended a byte — or a proxy that coalesced — that its JSON was bad when
/// its framing was merely generous.
///
/// The one test that sends such bytes (`fuzz_http`'s pipelined recipe)
/// judges only that the answer is well formed, which a wrong `unparseable`
/// is.
#[test]
fn bytes_past_content_length_are_dropped_rather_than_read_as_body() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let frame = r#"{"op":"next_account_prefix","parent":"1"}"#;
    for (what, trailing) in [
        ("trailing junk", "XXXXXXXX"),
        ("a pipelined second request", "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
    ] {
        let raw = format!(
            "POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{frame}{trailing}",
            frame.len()
        )
        .into_bytes();
        let (status, _, body) = raw_exchange(port, &raw);
        assert_eq!(status, 200, "{what}: {}", String::from_utf8_lossy(&body));
        // Non-JSON here is either the codec having been handed the extra
        // bytes, or a second answer appended to the first.
        assert_eq!(
            json(&body)["resp"].as_str(),
            Some("maybe_addr"),
            "{what}: the declared body is the frame, and this connection answers once"
        );
    }

    sd.shutdown();
}
