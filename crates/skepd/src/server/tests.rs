use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
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
    "/blob",
    #[cfg(feature = "observe")]
    "/dump",
    #[cfg(feature = "client")]
    "/",
];

/// The methods this test asks every route about. Deliberately wider than
/// the set the daemon serves: the point is to DISCOVER which methods
/// dispatch rather than to restate them, so a method added to
/// [`Daemon::reply`] is caught here without anyone remembering to add it.
const PROBE_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

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
        // The non-reply routes: GET /events, which this test never asks
        // for, and an ADMITTED blob fetch, which a bare `/blob` with no
        // query never is — its refusal is a reply like any other.
        Routed::EventStream => 200,
        Routed::Fetch(fetch) => fetch.status(),
    };
    // Each path's OWN preflight: the fetch names its two methods, every
    // other known path the common three — read off the route rather than
    // restated, so a preflight that drifts from its dispatch is caught here.
    let allow_for = |path: &str| {
        let pre = if blob_routes::is_fetch_path(path) {
            Reply::preflight_fetch()
        } else {
            Reply::preflight()
        };
        pre.headers
            .iter()
            .find(|(k, _)| *k == "Access-Control-Allow-Methods")
            .map(|&(_, v)| v)
            .expect("the preflight names its allowed methods")
    };
    for path in ROUTES {
        let allow = allow_for(path);
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
    for unknown in ["/nope", "/op/", "/Health", "/blob/", "/blobs"] {
        assert!(!path_is_known(unknown), "{unknown} must not be known");
        assert_eq!(status("GET", unknown), 404, "{unknown}");
        assert_eq!(status("OPTIONS", unknown), 404, "an unknown path preflights nothing");
    }
}

/// `body_cap` is the cap the daemon's own transport applies, for every
/// method and path, so a caller over its own transport that takes the bound
/// from here answers what the socket reader answers: the frame routes'
/// whatever the method, the blob upload's creation and resume at the blob
/// cap, and every other request — the rest of the blob family's included —
/// at the small cap.
#[test]
fn the_body_cap_is_the_transports_for_every_method_and_path() {
    let upload = "/blob/upload/0123456789abcdef0123456789abcdef";
    for (method, path, cap) in [
        ("POST", "/op", MAX_REQUEST_BODY),
        ("GET", "/op", MAX_REQUEST_BODY),
        ("POST", "/op-at", MAX_REQUEST_BODY),
        ("POST", "/blob/upload", MAX_BLOB_BYTES as usize),
        ("PATCH", upload, MAX_BLOB_BYTES as usize),
        ("GET", "/blob/upload", MAX_SMALL_BODY),
        ("GET", upload, MAX_SMALL_BODY),
        ("DELETE", upload, MAX_SMALL_BODY),
        ("OPTIONS", "/blob/upload", MAX_SMALL_BODY),
        ("GET", "/blob", MAX_SMALL_BODY),
        ("POST", "/session", MAX_SMALL_BODY),
    ] {
        assert_eq!(body_cap(method, path), cap, "{method} {path}");
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
    // EXACTLY ONCE, though two sites saw the death on this write — the
    // route's own resolution at the head, and the plain sequence's under the
    // lock — which is `with_signal`'s promise ("once, however many resolution
    // sites observed the death"). Doubled, a client reading the header through
    // `fetch` is handed `closed, closed`, never the `closed` wire.md specifies.
    let signals: Vec<&str> =
        write.headers.iter().filter(|(k, _)| *k == SESSION_HEADER).map(|&(_, v)| v).collect();
    assert_eq!(signals, ["closed"], "an unknown token's write carries Skepd-Session: closed, once");
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

/// `serve`'s SECOND precondition: a daemon whose auth port is ALREADY BOUND —
/// a socket-free embedder's `bind_auth_port`, with which `serve` is exclusive
/// — stops here loudly, as a zero worker count does, and never serves under
/// loopback defaults derived from a port its listener is not on, where the
/// dialed origin is outside the bare set and a browser at it is refused every
/// session.
#[test]
#[should_panic(expected = "serve binds the auth port once")]
fn serving_a_daemon_whose_auth_port_is_bound_is_a_callers_bug() {
    let dir = tempfile::tempdir().expect("tempdir");
    let daemon = Daemon::open(dir.path()).expect("genesis open");
    daemon.bind_auth_port(1).expect("a fresh daemon binds once");
    let _server = serve(daemon, 0, 1);
}

/// THE BIND BEFORE THE OPEN (`operations.md` §4 row 22): the bind is a door
/// of its own, so a held port is refused there — `AddrInUse`, the kind a
/// caller dispatches on — with no daemon opened and nothing created under
/// the data directory; released, the same port binds, and the listener
/// carries the number it bound.
#[test]
fn a_held_port_is_refused_at_the_bind_with_no_open_run() {
    let held = TcpListener::bind(("127.0.0.1", 0)).expect("hold a port");
    let port = held.local_addr().expect("the held port").port();
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    let refused = bind(port).expect_err("a held port is refused at the bind");
    assert_eq!(refused.kind(), ErrorKind::AddrInUse, "{refused}");
    assert!(!data_dir.exists(), "the bind touches no directory: no open ran");
    drop(held);
    let listener = bind(port).expect("the released port binds");
    assert_eq!(listener.port(), port, "the listener carries the port it bound");
}

/// `serve` IS `bind` THEN `serve_bound` (§4 row 22's split): a listener
/// bound before the open holds its port through it — a connect meanwhile is
/// not refused but waits in the backlog, its request answered by the first
/// worker — and the server serves on that port.
#[test]
fn serve_bound_serves_over_the_listener_the_bind_answered_and_a_connect_during_the_open_waits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let listener = bind(0).expect("an ephemeral port");
    let port = listener.port();
    // A client during the open: the connect completes, the request is
    // written, and nothing answers it yet — no worker exists.
    let mut early = TcpStream::connect(("127.0.0.1", port))
        .expect("a connect while the port is bound and nothing accepts completes");
    early
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .expect("the request waits in the backlog");
    let daemon = Daemon::open(dir.path()).expect("genesis open");
    let server = serve_bound(daemon, listener, 1).expect("the workers over the bound listener");
    assert_eq!(server.port(), port, "the server serves on the port the bind answered");
    early.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
    let mut raw = Vec::new();
    early.read_to_end(&mut raw).expect("the queued request is answered once a worker accepts");
    assert!(raw.starts_with(b"HTTP/1.1 200 "), "{}", String::from_utf8_lossy(&raw));
    server.shutdown();
}

/// THE OPEN's TWO LINES' WORDS (`operations.md` §1.1 m7; §3.1 step 3),
/// pinned at fixed figures: the directory as the operator named it; the
/// base as the two warnings name it — `genesis` at `Seq(0)`, else the
/// checkpoint's file name — the commits replayed and the engine's open in
/// milliseconds; and an engine that gave no account, said as a genesis that
/// replayed nothing.
#[test]
fn the_opens_two_lines_carry_the_directory_the_base_the_replay_and_the_duration_in_their_words() {
    use skep_engine::Recovery;

    assert_eq!(
        DataDirLine(Path::new("/var/lib/skep/board")).to_string(),
        "data-dir /var/lib/skep/board"
    );
    assert_eq!(
        RecoveredLine { start_point: Seq(0), replayed: 0, duration_ms: 12 }.to_string(),
        "recovered from genesis, 0 commits replayed, in 12 ms"
    );
    assert_eq!(
        RecoveredLine { start_point: Seq(4096), replayed: 317, duration_ms: 60_301 }.to_string(),
        "recovered from checkpoint.4096, 317 commits replayed, in 60301 ms"
    );
    let account = Recovery {
        start_point: Seq(2048),
        skipped: vec![],
        replayed: 9,
        tail_cut: 0,
        identity_resolved_empty: false,
    };
    assert_eq!(
        RecoveredLine::of(Some(&account), 5).to_string(),
        "recovered from checkpoint.2048, 9 commits replayed, in 5 ms"
    );
    assert_eq!(
        RecoveredLine::of(None, 5).to_string(),
        "recovered from genesis, 0 commits replayed, in 5 ms",
        "no account — an in-memory engine, which no daemon opens — is a genesis that replayed nothing"
    );
    // ONE rendering of the base: the landing's and the warnings' alike.
    assert_eq!(Base(Seq(0)).to_string(), "genesis");
    assert_eq!(Base(Seq(77)).to_string(), "checkpoint.77");
}

/// THE CLASSED DOOR for the open's own lines (CUT 1 (a)): both go out
/// through `say_open_line`, which emits under `Class::Open` — read off the
/// source, since no suite captures the stream in-process; the class word on
/// the stream itself is pinned by the child-process suite
/// (`tests/it/open.rs`), which reads `open:` on the binary's stderr.
#[test]
fn the_opens_two_lines_go_through_the_classed_door() {
    let source = include_str!("../server.rs");
    let start = source.find("fn open_under(").expect("open_under");
    let end =
        source[start..].find("fn write_the_claims_head_if_owed(").expect("the next fn") + start;
    let open_under = &source[start..end];
    assert_eq!(
        open_under.matches("say_open_line(").count(),
        2,
        "the two lines, each through the door"
    );
    assert!(
        open_under.find("say_open_line(DataDirLine(").expect("the directory's line")
            < open_under.find("Engine::open(").expect("the engine's open"),
        "the directory's line comes before the engine's open"
    );
    let door = source.find("fn say_open_line(").expect("the door");
    assert!(
        source[door..door + 160].contains("notice::emit(Class::Open,"),
        "the door emits under Class::Open"
    );
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
        Routed::Fetch(_) => panic!("POST /op is not the blob fetch"),
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
    let write = post(&format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":41}}"#));
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
        assert!(Instant::now() < deadline, "no initial event: {:?}", String::from_utf8_lossy(&buf));
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

/// AUTH-2.86's two startup warnings, rendered from the open's report
/// ([`recovery_warnings`]): nothing for an in-memory engine or a start point
/// that carried its slice with nothing skipped; one line per SKIPPED
/// checkpoint, naming it by name, why, and the start point the world was
/// resolved from — genesis, or the checkpoint that stood in; and one line
/// where the start point carried no identity slice and RESOLVED EMPTY,
/// naming that checkpoint and the empty resolution. The daemon writes each
/// through the operator stream at open, which no test can read back, so the
/// rendering is pinned here against the report the daemon renders it from.
#[test]
fn the_recovery_warnings_name_the_skipped_checkpoint_the_start_point_and_the_empty_resolution() {
    use skep_engine::{Recovery, SkippedBase};

    assert!(recovery_warnings(None).is_empty(), "in memory, nothing to say");
    let carried = Recovery {
        start_point: Seq(2048),
        skipped: vec![],
        replayed: 0,
        tail_cut: 0,
        identity_resolved_empty: false,
    };
    assert!(recovery_warnings(Some(&carried)).is_empty(), "a carried start point: nothing to say");

    let stepped_back = Recovery {
        start_point: Seq(0),
        skipped: vec![SkippedBase {
            seq: Seq(2048),
            why: "the `identity` slice could not be resolved from this checkpoint".into(),
        }],
        replayed: 2048,
        tail_cut: 0,
        identity_resolved_empty: false,
    };
    let lines = recovery_warnings(Some(&stepped_back));
    assert_eq!(lines.len(), 1, "{lines:?}");
    for needle in ["checkpoint.2048", "SKIPPED", "`identity` slice", "resolved from genesis"] {
        assert!(lines[0].contains(needle), "{needle:?} missing from {:?}", lines[0]);
    }

    let two_skipped_one_stood = Recovery {
        start_point: Seq(1024),
        skipped: vec![
            SkippedBase {
                seq: Seq(3072),
                why: "the `identity` slice could not be resolved".into(),
            },
            SkippedBase {
                seq: Seq(2048),
                why: "checkpoint body failed its header checksum".into(),
            },
        ],
        replayed: 2048,
        tail_cut: 0,
        identity_resolved_empty: false,
    };
    let lines = recovery_warnings(Some(&two_skipped_one_stood));
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[0].contains("checkpoint.3072") && lines[0].contains("resolved from checkpoint.1024"),
        "{:?}",
        lines[0]
    );
    assert!(
        lines[1].contains("checkpoint.2048") && lines[1].contains("header checksum"),
        "{:?}",
        lines[1]
    );

    let resolved_empty = Recovery {
        start_point: Seq(1024),
        skipped: vec![],
        replayed: 0,
        tail_cut: 0,
        identity_resolved_empty: true,
    };
    let lines = recovery_warnings(Some(&resolved_empty));
    assert_eq!(lines.len(), 1, "{lines:?}");
    for needle in
        ["checkpoint.1024", "no identity slice", "RESOLVED EMPTY", "wrote no identity slice"]
    {
        assert!(lines[0].contains(needle), "{needle:?} missing from {:?}", lines[0]);
    }
}

/// THE CADENCE's BYTE BOUND (jw-R1): a quarter of the newest checkpoint's
/// size, never below the 24 MiB floor — the bound the media floor's
/// guarantee rests on (`MediaGate`'s `FLOOR_BYTES` card). No checkpoint yet,
/// and an empty one, are the floor alone; the crossover is at four times the
/// floor, one byte of share past it raising the bound; a large board's bound
/// is its share.
#[test]
fn the_cadence_byte_bound_is_a_quarter_of_the_newest_checkpoint_and_never_below_its_floor() {
    let mib = 1024 * 1024u64;
    for (newest, bound) in [
        (None, 24 * mib),
        (Some(0), 24 * mib),
        (Some(96 * mib), 24 * mib),
        (Some(96 * mib + 4), 24 * mib + 1),
        (Some(400 * mib), 100 * mib),
    ] {
        assert_eq!(cadence_bytes_for(newest).get(), bound, "newest checkpoint {newest:?}");
    }
}

/// LINE 25's WORDS (`operations.md` §1.1 row 25), pinned at fixed figures:
/// the position and the size, the duration in milliseconds, the journal
/// bytes reclaimed — or "nothing reclaimed" at zero — both bounds, the
/// volume's free space, the resident set's peak, the compaction's fence
/// with each file that stood named, and the inline clause present only
/// where the count moved. A header that did not answer reads "size unread";
/// a resident set never read reads "unread"; a landing with nothing below
/// the floor says so.
#[test]
fn the_landing_line_carries_row_25s_figures_in_its_words() {
    let full = LandingLine {
        position: Seq(4200),
        bytes: Some(1_048_576),
        duration_ms: 17,
        reclaimed: 2_097_152,
        bytes_bound: 25_165_824,
        floor: 268_435_456,
        free_space: 9_000_000_000,
        resident_peak: Some(123_456_789),
        compaction: FeedCompaction {
            fence: Some(4095),
            standing: vec!["commits.log", "feed-index.log"],
        },
        inline: Some(InlineRuns { runs: 2, since: Seq(3100) }),
    };
    assert_eq!(
        full.to_string(),
        "checkpoint at position 4200 landed (1048576 bytes) in 17 ms; 2097152 journal bytes \
         reclaimed; the cadence's byte bound 25165824, the media floor in force 268435456, the \
         volume's free space 9000000000; the process's resident set peaked at 123456789 bytes; \
         the change feed's files compacted below position 4096, commits.log standing as it \
         was, feed-index.log standing as it was; 2 checkpoints ran inline on a writer since \
         position 3100"
    );
    let quiet = LandingLine {
        position: Seq(7),
        bytes: None,
        duration_ms: 0,
        reclaimed: 0,
        bytes_bound: 24 * 1024 * 1024,
        floor: 256 * 1024 * 1024,
        free_space: 0,
        resident_peak: None,
        compaction: FeedCompaction::default(),
        inline: None,
    };
    assert_eq!(
        quiet.to_string(),
        "checkpoint at position 7 landed (size unread) in 0 ms; nothing reclaimed; the \
         cadence's byte bound 25165824, the media floor in force 268435456, the volume's free \
         space 0; the process's resident set unread; the change feed's files hold nothing \
         below the reclaim floor"
    );
}

/// LINE 26's WORDS (row 26; §4 row 2) at each cause: the head's position as
/// an ordering, a full volume in the operator's words beside the OS's text,
/// every other cause its own text, and the trailer keyed to the cause — an
/// I/O cause retries at the next crossing, a poisoned kernel takes no
/// checkpoint until a restart, a world that will not serialize refuses the
/// same way until the build fixes it. A base that LANDED opens the line on
/// its position and names which of the three steps failed, in the daemon's
/// words and never the kernel's, the volume's words re-applied to its cause;
/// a landed base whose header did not answer is placed at or above the head
/// the run began at.
#[test]
fn the_failure_line_keys_its_trailer_to_the_cause_and_names_a_landed_bases_step() {
    use std::io::{Error, ErrorKind};

    let at = Seq(90);
    let retry = "; the journal is not reclaimed and holds every commit; the next attempt is at \
                 the cadence's next crossing";
    let full = CheckpointError::Io(Error::new(ErrorKind::StorageFull, "No space left on device"));
    assert_eq!(
        FailureLine { at, landed_at: None, error: &full }.to_string(),
        format!(
            "checkpoint FAILED (the head stood at position 90 when the run began): the volume \
             is full (No space left on device){retry}"
        )
    );
    let denied = CheckpointError::Io(Error::new(ErrorKind::PermissionDenied, "denied"));
    assert_eq!(
        FailureLine { at, landed_at: None, error: &denied }.to_string(),
        format!(
            "checkpoint FAILED (the head stood at position 90 when the run began): denied{retry}"
        )
    );
    assert_eq!(
        FailureLine { at, landed_at: None, error: &CheckpointError::Poisoned }.to_string(),
        "checkpoint FAILED (the head stood at position 90 when the run began): kernel is \
         poisoned; no checkpoint taken; no checkpoint is taken until a restart (the kernel's \
         halt, said above)"
    );
    let refused = CheckpointError::Serialize("the `m5` slice refused".into());
    assert_eq!(
        FailureLine { at, landed_at: None, error: &refused }.to_string(),
        "checkpoint FAILED (the head stood at position 90 when the run began): checkpoint \
         world serialization failed: the `m5` slice refused; every crossing refuses the same \
         way until the world encodes: the build's to fix"
    );
    for (step, words) in [
        (LandedStep::DirectorySync, "the directory's sync"),
        (LandedStep::Retention, "retention"),
        (LandedStep::Reclamation, "the journal's reclamation"),
    ] {
        let landed = CheckpointError::Landed {
            step,
            cause: Error::new(ErrorKind::StorageFull, "No space left on device"),
        };
        assert_eq!(
            FailureLine { at, landed_at: Some(Seq(96)), error: &landed }.to_string(),
            format!(
                "a checkpoint landed at position 96 but {words} failed: the volume is full (No \
                 space left on device){retry}"
            ),
            "{step:?}"
        );
        // The kernel's own words for the step never reach the line.
        assert!(!FailureLine { at, landed_at: Some(Seq(96)), error: &landed }
            .to_string()
            .contains(&step.to_string()));
    }
    let squatted = CheckpointError::Landed {
        step: LandedStep::Retention,
        cause: Error::other("a directory stands on the name"),
    };
    assert_eq!(
        FailureLine { at, landed_at: None, error: &squatted }.to_string(),
        format!(
            "a checkpoint landed at or above position 90 (its header unread) but retention \
             failed: a directory stands on the name{retry}"
        )
    );
}

/// THE BACKSTOP's LINE (m13): the runs since the position they are counted
/// from, and whether the last of them landed or how it failed, in the
/// kernel's rendered words.
#[test]
fn the_backstop_line_counts_the_inline_runs_from_a_position_and_says_how_the_last_ended() {
    assert_eq!(
        BackstopLine { runs: 1, since: Seq(0), last_failure: None }.to_string(),
        "checkpoint: the cadence outran the checkpoint thread; 1 checkpoints ran inline on a \
         writer since position 0, the last landed"
    );
    let failed = BackstopLine {
        runs: 3,
        since: Seq(512),
        last_failure: Some("checkpoint I/O failure: No space left on device".to_string()),
    };
    assert_eq!(
        failed.to_string(),
        "checkpoint: the cadence outran the checkpoint thread; 3 checkpoints ran inline on a \
         writer since position 512, the last FAILED: checkpoint I/O failure: No space left on \
         device"
    );
}

/// m13's READ POINT: a checkpoint the kernel's backstop ran inline inside an
/// execute wakes the checkpoint thread through the write path's SECOND load
/// — the inline count against the count the write path last saw — with NO
/// due flag standing. Two writes made through M10 directly, past the write
/// path (the one path that commits without its record step, and so without
/// its wake), cross a one-byte bound twice: the first sets the flag, the
/// second finds it set and runs the backstop inline — the flag cleared, the
/// count moved — and nothing has raised the thread's signal, which a waiter
/// on it shows. Then the bound set wide and one write THROUGH the write
/// path, which crosses nothing: its record step finds the count moved and
/// raises, and the waiter is woken `Due`. Socket-free, so the signal is
/// observed and not consumed by a thread; the thread's own wake arm is the
/// integration suite's (`tests/it/checkpoint.rs`).
#[test]
fn a_write_whose_record_step_finds_the_inline_count_moved_wakes_the_checkpoint_thread() {
    use std::sync::mpsc;
    use std::time::Duration;

    use crate::write_path::Woken;

    let dir = tempfile::tempdir().expect("tempdir");
    let daemon = Daemon::open(dir.path()).expect("genesis open");
    let token = bare_session(&daemon, 0);
    let past_the_write_path = |addr: &str| {
        let frame = format!(r#"{{"op":"register_node","addr":"{addr}"}}"#);
        let req = daemon.codec.parse(frame.as_bytes()).unwrap_or_else(|_| panic!("parses"));
        let sid = daemon.febe.bootstrap_session();
        match daemon.febe.execute(sid, req) {
            Response::AckAddr { .. } => {}
            other => panic!(
                "register_node acks an address: {}",
                String::from_utf8_lossy(&daemon.codec.marshal(&other))
            ),
        }
    };
    daemon.set_checkpoint_bytes_bound(1);
    past_the_write_path("1.9001");
    assert!(daemon.checkpoint_is_due(), "the first crossing set the flag, unserviced");
    assert_eq!(daemon.inline_checkpoints(), 0);
    past_the_write_path("1.9002");
    assert!(!daemon.checkpoint_is_due(), "the second crossing ran inline and cleared the flag");
    assert_eq!(daemon.inline_checkpoints(), 1, "the backstop, counted");
    assert!(daemon.newest_checkpoint().is_some(), "…and landed");
    assert!(daemon.checkpoint_lines().is_empty(), "no thread, nothing said");

    let signal = daemon.writes.checkpoint_signal();
    std::thread::scope(|scope| {
        let (woken, waiter) = mpsc::channel();
        scope.spawn(move || {
            let _ = woken.send(signal.wait());
        });
        assert!(
            waiter.recv_timeout(Duration::from_millis(300)).is_err(),
            "two writes past the write path raised nothing, the backstop's landing among them"
        );
        // THE BOUND WIDE, so the one write through the write path crosses
        // nothing: its record step raises on the moved count alone.
        daemon.set_checkpoint_bytes_bound(1 << 40);
        let read = daemon.route(&HttpRequest {
            method: "POST".to_string(),
            path: "/op".to_string(),
            query: None,
            session_token: Some(token.clone()),
            origin: None,
            peer: Peer::Loopback,
            body: br#"{"op":"next_account_prefix","parent":"1"}"#.to_vec(),
        });
        let Routed::Reply(read) = read else { panic!("POST /op is not the event stream") };
        let v: Value = serde_json::from_slice(read.bytes()).expect("json");
        let prefix = v["addr"].as_str().expect("a delegable prefix").to_string();
        let Routed::Reply(written) = daemon.route(&HttpRequest {
            method: "POST".to_string(),
            path: "/op".to_string(),
            query: None,
            session_token: Some(token.clone()),
            origin: None,
            peer: Peer::Loopback,
            body: format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":41}}"#)
                .into_bytes(),
        }) else {
            panic!("POST /op is not the event stream")
        };
        let v: Value = serde_json::from_slice(written.bytes()).expect("json");
        assert!(v["at"].is_u64(), "the write through the write path commits: {v}");
        assert!(!daemon.checkpoint_is_due(), "under the wide bound it crossed nothing");
        let woken = waiter.recv_timeout(Duration::from_secs(5));
        signal.stop();
        assert_eq!(woken, Ok(Woken::Due), "the record step raised on the moved count alone");
    });
}

/// THE CLASSED DOOR (CUT 1 (a)): every line of the checkpoint thread's
/// section goes out through `notice::emit` with its class word, and none
/// through the un-classed `line` or `lines` — read off the source, since no
/// suite captures the stream in-process; the class each line is emitted
/// under is pinned through `Daemon::checkpoint_lines` by the integration
/// suite (`tests/it/checkpoint.rs`).
#[test]
fn the_checkpoint_threads_lines_go_through_the_classed_door() {
    let source = include_str!("../server.rs");
    let start =
        source.find("// ── the checkpoint thread's work").expect("the section's marker");
    let end = source[start..]
        .find("/// AUTH-2.86's two startup warnings")
        .expect("the section's end")
        + start;
    let section = &source[start..end];
    assert!(section.contains("notice::emit("), "the section says its lines through `emit`");
    assert!(
        !section.contains("notice::line(") && !section.contains("notice::lines("),
        "no line of the section goes through the un-classed door"
    );
}
