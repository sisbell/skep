use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde_json::Value;
use skep_febe::{Codec, Response};

use super::reply::SESSION_HEADER;
use super::*;

/// Every path the router serves. The list is the test's own — an
/// independent restatement, so a route added to [`path_is_known`] alone
/// (with no dispatch arm) is caught here rather than answering 405 for
/// every method.
const ROUTES: &[&str] = &[
    "/session",
    "/session/close",
    "/challenge",
    "/op",
    "/op-at",
    "/health",
    "/chain",
    "/events",
    "/changes",
    #[cfg(feature = "observe")]
    "/dump",
    #[cfg(feature = "client")]
    "/",
];

/// The methods this test asks every route about. Deliberately wider than
/// the set the daemon serves: the point is to DISCOVER which methods
/// dispatch rather than to restate them, so a method added to
/// [`Daemon::reply`] is caught here without anyone remembering to add it.
const PROBE_METHODS: &[&str] =
    &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// One route set, five consequences. A known path preflights `204`;
/// refuses an unsupported method with `405` and never `404`; dispatches
/// at least one method; refuses at least one, so the `405` arm is
/// exercised somewhere; and has every method it dispatches named by the
/// CORS preflight. An unknown path is `404` for every method including
/// `OPTIONS`.
///
/// The first four are the invariant [`path_is_known`] exists to keep — a
/// route stated in one table and forgotten in another breaks exactly one
/// of them. The last is [`Reply::preflight`]'s: a method the preflight
/// omits is one a browser will not send, which fails only cross-origin,
/// where every client in this suite writes onto a socket directly and so
/// never looks.
///
/// Every method is DISCOVERED rather than restated, so a route that
/// starts serving one — the blob upload [`MAX_REQUEST_BODY`] already
/// anticipates — is caught by the preflight check rather than by a
/// hardcoded expectation that the method is unsupported.
#[test]
fn the_route_set_agrees_across_preflight_dispatch_and_refusal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let daemon = Daemon::open(dir.path()).expect("genesis open");
    let bare = |method: &str, path: &str| HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        query: None,
        session_token: None,
        origin: None,
        peer: Peer::Loopback,
        body: Vec::new(),
    };
    let status = |method: &str, path: &str| match daemon.route(&bare(method, path)) {
        Routed::Reply(r) => r.status,
        // The one non-reply route; reached only by GET /events, which
        // this test never asks for.
        Routed::EventStream => 200,
    };
    let allow = Reply::preflight()
        .headers
        .iter()
        .find(|(k, _)| *k == "Access-Control-Allow-Methods")
        .map(|&(_, v)| v)
        .expect("the preflight names its allowed methods");
    for path in ROUTES {
        assert!(path_is_known(path), "{path} is served but not known");
        assert_eq!(status("OPTIONS", path), 204, "{path} must answer the CORS preflight");
        let mut served = false;
        let mut refused = false;
        for method in PROBE_METHODS {
            let answered = status(method, path);
            assert_ne!(
                answered, 404,
                "{path} is known, so {method} must be refused with 405, not 404"
            );
            // 405 is the daemon saying it does not serve this method
            // here; anything else is a dispatch, which the preflight
            // owes a name.
            if answered == 405 {
                refused = true;
                continue;
            }
            served = true;
            assert!(
                allow.split(',').any(|a| a.trim() == *method),
                "{path} dispatches {method}, which the preflight does not allow ({allow})"
            );
        }
        assert!(served, "{path} is known but no method dispatches");
        assert!(refused, "{path} serves every probed method; none exercises the 405 arm");
    }
    for unknown in ["/nope", "/op/", "/Health"] {
        assert!(!path_is_known(unknown), "{unknown} must not be known");
        assert_eq!(status("GET", unknown), 404, "{unknown}");
        assert_eq!(status("OPTIONS", unknown), 404, "an unknown path preflights nothing");
    }
}

/// The guest policy at the route level: an absent token serves reads
/// and meets M10's own `Unauthenticated` on writes; an unknown token
/// additionally carries the death signal (AUTH-6.7) — an evicted or
/// stale token is never silently a guest.
#[test]
fn a_guest_reads_and_an_unknown_token_is_signalled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let daemon = Daemon::open(dir.path()).expect("genesis open");
    let post = |token: Option<&str>, body: &str| {
        let Routed::Reply(r) = daemon.route(&HttpRequest {
            method: "POST".to_string(),
            path: "/op".to_string(),
            query: None,
            session_token: token.map(str::to_string),
            origin: None,
            peer: Peer::Loopback,
            body: body.as_bytes().to_vec(),
        }) else {
            panic!("POST /op is not the event stream")
        };
        r
    };
    let read = post(None, r#"{"op":"next_account_prefix","parent":"1"}"#);
    let v: Value = serde_json::from_slice(read.bytes()).expect("json");
    assert_eq!(v["resp"].as_str(), Some("maybe_addr"), "a guest read serves: {v}");
    let write = post(None, r#"{"op":"fork"}"#);
    let v: Value = serde_json::from_slice(write.bytes()).expect("json");
    assert_eq!(v["code"].as_str(), Some("unauthenticated"), "a guest write refuses: {v}");
    assert!(
        !write.headers.iter().any(|(k, _)| *k == SESSION_HEADER),
        "no token presented, so nothing died and nothing signals"
    );
    // A well-formed but unknown token: the same refusal, WITH the
    // signal — a stale token is never silently a guest.
    let stale = "0123456789abcdef0123456789abcdef";
    let write = post(Some(stale), r#"{"op":"fork"}"#);
    let v: Value = serde_json::from_slice(write.bytes()).expect("json");
    assert_eq!(v["code"].as_str(), Some("unauthenticated"), "{v}");
    assert!(
        write.headers.iter().any(|(k, v)| *k == SESSION_HEADER && *v == "closed"),
        "an unknown token carries Skepd-Session: closed"
    );
    // An unparseable header value IS no token (AUTH-4.18): no signal.
    let junk = post(Some("not-a-token"), r#"{"op":"fork"}"#);
    assert!(
        !junk.headers.iter().any(|(k, _)| *k == SESSION_HEADER),
        "a value Token::parse refuses resolves NoToken — nothing to close"
    );
}

/// The two constructors take a path the std way — anything
/// `AsRef<Path>` — so a caller holding a `String` or a `&str` (a config
/// value, a CLI argument before conversion) opens without converting
/// first. Every other test in this crate hands them a `&Path`, which is
/// the same door; this is the half of it those do not exercise.
#[test]
fn a_daemon_opens_from_any_path_like() {
    let owned_dir = tempfile::tempdir().expect("tempdir");
    let borrowed_dir = tempfile::tempdir().expect("tempdir");
    let owned: String = owned_dir.path().to_str().expect("a UTF-8 temp path").to_string();
    let borrowed: &str = borrowed_dir.path().to_str().expect("a UTF-8 temp path");
    let from_string = Daemon::open(owned).expect("genesis open from a String");
    let from_str = Daemon::open(borrowed).expect("genesis open from a &str");
    assert_eq!(
        from_string.log_position().0,
        from_str.log_position().0,
        "two fresh data dirs open at one position, whatever kind of value named them"
    );
}

/// A server with no workers serves nothing, so asking for one is the
/// caller's bug and stops here — never a silent repair into a
/// one-worker server, which would teach callers that the stated
/// precondition is not the real one.
#[test]
#[should_panic(expected = "at least one worker")]
fn zero_workers_is_a_callers_bug() {
    let dir = tempfile::tempdir().expect("tempdir");
    let daemon = Daemon::open(dir.path()).expect("genesis open");
    let _ = serve(daemon, 0, 0);
}

/// The operator stream's moments, as a line spells each: the closed set the
/// config-lockout warnings and the blocked-prefix list are labelled by, one
/// label per moment and no two alike.
#[test]
fn every_moment_spells_its_own_label() {
    let labels: Vec<String> = [Moment::AtStart, Moment::Reissued, Moment::AtClaim]
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(labels, ["at start", "reissued", "at claim"]);
}

/// A bare session's token for `principal`, opened through the route itself.
fn bare_session(daemon: &Daemon, principal: u64) -> String {
    let Routed::Reply(r) = daemon.route(&HttpRequest {
        method: "POST".to_string(),
        path: "/session".to_string(),
        query: None,
        session_token: None,
        origin: None,
        peer: Peer::Loopback,
        body: format!("{{\"principal\":{principal}}}").into_bytes(),
    }) else {
        panic!("POST /session is not the event stream")
    };
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(r.bytes()));
    let v: Value = serde_json::from_slice(r.bytes()).expect("json");
    v["session"].as_str().expect("token").to_string()
}

/// The commit stream announces a position only from the section that
/// recorded it: a committing write announces ITS OWN position, and
/// nothing else announces at all.
///
/// The read is the load-bearing half, and the head is deliberately
/// pushed ahead of the stream first — through `febe` directly, the one
/// path that commits without announcing — because a daemon that
/// announced the CURRENT HEAD from any `/op` request would look
/// correct on a quiet socket and wrong under concurrency, leaking a
/// write another thread had committed but not yet recorded. Here that
/// gap is opened deliberately instead of raced for.
#[test]
fn only_a_committing_write_announces_and_only_its_own_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let daemon = Daemon::open(dir.path()).expect("genesis open");
    let token = bare_session(&daemon, 0);
    let announced = || daemon.writes.announced();
    let post = |body: &str| match daemon.route(&HttpRequest {
        method: "POST".to_string(),
        path: "/op".to_string(),
        query: None,
        session_token: Some(token.clone()),
        origin: None,
        peer: Peer::Loopback,
        body: body.as_bytes().to_vec(),
    }) {
        Routed::Reply(r) => serde_json::from_slice::<Value>(r.bytes()).expect("json"),
        Routed::EventStream => panic!("POST /op is not the event stream"),
    };

    // Commit past the stream without announcing: this is the state a
    // concurrent write leaves behind between its commit and its record.
    // Driven through `febe` directly — the one path that commits
    // without announcing — so the daemon's own gates are deliberately
    // bypassed.
    let frame = br#"{"op":"register_node","addr":"1.9001"}"#;
    let req = daemon.codec.parse(frame).unwrap_or_else(|_| panic!("test frame parses"));
    let sid = daemon.febe.bootstrap_session();
    let ahead = match daemon.febe.execute(sid, req) {
        Response::AckAddr { at, .. } => at,
        // `Response` derives no Debug upstream; marshal to say what came back.
        other => panic!(
            "register_node acks an address: {}",
            String::from_utf8_lossy(&daemon.codec.marshal(&other))
        ),
    };
    assert!(ahead > announced(), "the head is now ahead of the commit stream");

    let read = post(r#"{"op":"next_account_prefix","parent":"1"}"#);
    assert_eq!(read["resp"].as_str(), Some("maybe_addr"), "a read was served: {read}");
    assert!(
        announced() < ahead,
        "a read commits nothing and must announce nothing — announcing the current \
         head would name a commit whose change-feed entry may not exist yet"
    );

    let bad = post(r#"{"op":"frobnicate"}"#);
    assert_eq!(bad["op"].as_str(), Some("unparseable"));
    assert!(announced() < ahead, "an unparseable frame announces nothing either");

    // A route-level write that commits pre-claim: the ceremony's own
    // delegate from principal 0 (the pre-claim gate admits it).
    let prefix = read["addr"].as_str().expect("a delegable prefix").to_string();
    let write =
        post(&format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":41}}"#));
    let at = write["at"].as_u64().unwrap_or_else(|| panic!("delegate commits: {write}"));
    assert_eq!(
        announced().0,
        at,
        "a committing write announces the position it committed, not the head"
    );
}

/// A connecting subscriber is told the last ANNOUNCED position, not the
/// kernel's head — `write_path/`'s guarantee (every position a
/// subscriber hears is one `/changes` already carries) applied to the
/// connect event.
///
/// The two differ only between a write's commit and its change-feed
/// record, so the gap is opened deliberately rather than raced for: a
/// direct `febe.execute` is the one path that commits without
/// announcing, and nothing announces afterwards, so the state holds.
/// Told the head there, a client would ask `/changes` for a delta not
/// yet containing the position it was handed and show a stale view
/// until the next write.
#[test]
fn a_connecting_subscriber_is_told_the_announced_position_not_the_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let daemon = Daemon::open(dir.path()).expect("genesis open");
    let server = serve(daemon, 0, 1).expect("bind an ephemeral port");
    let port = server.port();

    let (announced, ahead) = {
        let d = server.daemon();
        let sid = d.febe.bootstrap_session();
        let req = d
            .codec
            .parse(br#"{"op":"register_node","addr":"1.9001"}"#)
            .unwrap_or_else(|_| panic!("test frame parses"));
        let ahead = match d.febe.execute(sid, req) {
            Response::AckAddr { at, .. } => at,
            // `Response` derives no Debug upstream; marshal to say what came back.
            other => panic!(
                "register_node acks an address: {}",
                String::from_utf8_lossy(&d.codec.marshal(&other))
            ),
        };
        (d.writes.announced(), ahead)
    };
    assert!(announced < ahead, "the head is now ahead of the commit stream");

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect /events");
    stream.set_read_timeout(Some(Duration::from_secs(5))).expect("read timeout");
    stream
        .write_all(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .expect("write the stream request");
    let mut buf: Vec<u8> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let first = loop {
        if let Some(i) = buf.windows(6).position(|w| w == b"data: ") {
            if let Some(nl) = buf[i..].iter().position(|&b| b == b'\n') {
                let v: Value =
                    serde_json::from_slice(&buf[i + 6..i + nl]).expect("event data is JSON");
                break v["log_position"].as_u64().expect("log_position");
            }
        }
        assert!(
            Instant::now() < deadline,
            "no initial event: {:?}",
            String::from_utf8_lossy(&buf)
        );
        let mut chunk = [0u8; 1024];
        match stream.read(&mut chunk) {
            Ok(0) => panic!("the stream closed before its first event"),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => {}
        }
    };
    assert_eq!(
        first, announced.0,
        "the connect event carries the announced position, which `/changes` already covers"
    );
    assert!(first < ahead.0, "and NOT the head, whose change-feed record does not exist yet");

    server.shutdown();
}
