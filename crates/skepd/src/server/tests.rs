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

/// Checks that a refused worker retires the start and starts no checkpoint.
///
/// The seam refuses the first worker's thread (`operations.md` §4 row 23):
/// `serve_bound` answers that refusal, the port and the journal-directory
/// lock released — and, a checkpoint due before the serve, none ran: a start
/// being retired spawns neither the pruner nor the checkpoint thread.
#[test]
fn a_refused_worker_retires_the_start_and_starts_no_checkpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let daemon = Daemon::open(dir.path()).expect("genesis open");
    let token = bare_session(&daemon, 0);
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
        _ => panic!("POST /op is a reply"),
    };
    daemon.set_checkpoint_bytes_bound(1);
    let read = post(r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = read["addr"].as_str().expect("a delegable prefix").to_string();
    let write = post(&format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":41}}"#));
    assert!(write["at"].is_u64(), "one commit past a one-byte bound: {write}");
    assert!(daemon.checkpoint_is_due_now(), "the premise: a checkpoint is due");
    daemon.refuse_the_next_worker_threads(1, "the test seam's refusal of a worker thread");
    let listener = bind(0).expect("an ephemeral port");
    let port = listener.port();
    let refused = serve_bound(daemon, listener, MIN_WORKERS).expect_err("the start is retired");
    assert_eq!(refused.to_string(), "the test seam's refusal of a worker thread");
    let rebound = bind(port).expect("the port is released before the refusal is answered");
    assert_eq!(rebound.port(), port);
    drop(rebound);
    // The journal-directory lock is released: a reopen takes it, the flock a
    // just-dropped kernel held given a moment to land under load, as the
    // embedding helper's retry gives it.
    let deadline = Instant::now() + Duration::from_secs(5);
    let reopened = loop {
        match Daemon::open(dir.path()) {
            Ok(daemon) => break daemon,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => panic!("the journal-directory lock is released: {e}"),
        }
    };
    assert!(reopened.newest_checkpoint().is_none(), "no checkpoint ran in a retired start");
}

/// THE STOP's WAKE CONNECT dials the address the listener bound — a listener
/// bound to one specific address answers there alone — and loopback where
/// the bind was unspecified (`0.0.0.0`, the hosted image's), which names no
/// one address to dial. The rule alone, pinned here; `stop_and_join` dials
/// through it.
#[test]
fn the_stops_wake_connect_dials_the_bound_address_and_loopback_for_an_unspecified_one() {
    use std::net::Ipv4Addr;

    use super::listen::wake_addr;

    assert_eq!(
        wake_addr(Ipv4Addr::UNSPECIFIED),
        Ipv4Addr::LOCALHOST,
        "0.0.0.0 is woken at loopback"
    );
    assert_eq!(
        wake_addr(Ipv4Addr::new(10, 0, 0, 5)),
        Ipv4Addr::new(10, 0, 0, 5),
        "a specific address is woken at itself, where loopback would miss it"
    );
    assert_eq!(wake_addr(Ipv4Addr::LOCALHOST), Ipv4Addr::LOCALHOST, "the loopback door at itself");
}

/// THE OPEN's TWO LINES' WORDS (`operations.md` §1.1 m7; §3.1 step 3),
/// pinned at fixed figures: the directory as the operator named it; the
/// base as the two warnings name it — `genesis` at `Seq(0)`, else the
/// checkpoint's file name — the committed head the open came back at, the
/// commits replayed and the engine's open in milliseconds; and an engine
/// that gave no account, said as a genesis that replayed nothing.
#[test]
fn the_opens_two_lines_carry_the_directory_the_base_the_replay_and_the_duration_in_their_words() {
    use skep_engine::Recovery;

    assert_eq!(
        DataDirLine(Path::new("/var/lib/skep/board")).to_string(),
        "data-dir /var/lib/skep/board"
    );
    assert_eq!(
        RecoveredLine { start_point: Seq(0), head: Seq(0), replayed: 0, duration_ms: 12 }
            .to_string(),
        "recovered from genesis to position 0, 0 commits replayed, in 12 ms"
    );
    let recovered = RecoveredLine {
        start_point: Seq(4096),
        head: Seq(4413),
        replayed: 317,
        duration_ms: 60_301,
    };
    assert_eq!(
        recovered.to_string(),
        "recovered from checkpoint.4096 to position 4413, 317 commits replayed, in 60301 ms"
    );
    let account = Recovery {
        start_point: Seq(2048),
        skipped: vec![],
        replayed: 9,
        tail_cut: 0,
        tail_cut_intact: 0,
        tail_cut_from: None,
        tail_cut_claimed: None,
        began: false,
        runs_passed_over: 0,
        first_run_passed_over: None,
        identity_resolved_empty: false,
    };
    assert_eq!(
        RecoveredLine::of(Some(&account), Seq(2057), 5).to_string(),
        "recovered from checkpoint.2048 to position 2057, 9 commits replayed, in 5 ms"
    );
    assert_eq!(
        RecoveredLine::of(None, Seq(0), 5).to_string(),
        "recovered from genesis to position 0, 0 commits replayed, in 5 ms",
        "no account — an in-memory engine, which no daemon opens — is a genesis that replayed nothing"
    );
    // ONE rendering of the base: the landing's and the warnings' alike.
    assert_eq!(Base(Seq(0)).to_string(), "genesis");
    assert_eq!(Base(Seq(77)).to_string(), "checkpoint.77");
}

/// THE OPEN's BEGINNING AND ITS TAIL CUT, pinned whole: the beginning's line
/// says no journal stood and what that means on a board that had one; the
/// tail cut's two arms say opposite things of the acknowledged writes — a
/// crash's tail under the report's own class, `open`, and a tail holding
/// intact frames no torn write leaves under `failure` — each naming the file
/// and the byte the cut began at and the position it lies past, and the
/// failure arm WHICH write it may have taken: the position an intact marker
/// in the cut claimed, where that lies above the head, and a position above
/// the head where it does not or no marker was read. An open that cut
/// nothing, or gave no account, says neither.
#[test]
fn the_opens_beginning_and_its_tail_cut_say_what_the_open_found_in_their_words() {
    use skep_engine::Recovery;

    assert_eq!(
        BeganLine.to_string(),
        "no journal stood in the data directory: this open began a new board at genesis — on a \
         board that had one, the directory named above is not where it lives (a volume not \
         mounted over it, a mistyped --data-dir): stop the daemon before a write lands on the new \
         board"
    );

    let account = |tail_cut: u64, tail_cut_intact: u64, tail_cut_claimed: Option<Seq>| Recovery {
        start_point: Seq(0),
        skipped: vec![],
        replayed: 2,
        tail_cut,
        tail_cut_intact,
        tail_cut_from: (tail_cut > 0).then(|| ("seg-1.wal".to_string(), 218)),
        tail_cut_claimed,
        began: false,
        runs_passed_over: 0,
        first_run_passed_over: None,
        identity_resolved_empty: false,
    };
    let head = Seq(2);
    assert!(TailCutLine::of(None, head).is_none(), "no account, nothing cut");
    assert!(
        TailCutLine::of(Some(&account(0, 0, None)), head).is_none(),
        "a clean close cut nothing"
    );

    let crash = TailCutLine::of(Some(&account(55, 0, None)), head).expect("a crash's tail");
    assert!(matches!(crash.class(), Class::Open), "a crash's tail is the report's own line");
    assert_eq!(
        crash.to_string(),
        "journal tail cut (55 bytes, beginning at byte 218 of seg-1.wal, past position 2): the \
         un-acked tail a crash or a kill left past the last committed marker — a write caught \
         before its commit was durable, never acknowledged — removed by the open; every \
         acknowledged write stands"
    );

    let rot_at = |claimed: Option<Seq>| {
        TailCutLine::of(Some(&account(109, 1, claimed)), head)
            .expect("a tail with an intact frame")
            .to_string()
    };
    let rot = TailCutLine::of(Some(&account(109, 1, Some(Seq(3)))), head).expect("an intact tail");
    assert!(matches!(rot.class(), Class::Failure), "an acknowledged write may be among the cut");
    let opening = "journal tail cut (109 bytes, beginning at byte 218 of seg-1.wal, past position \
                   2), 1 of its frames intact on disk — a commit marker whose records failed their \
                   check, or a frame no writer of this format writes, the signature of rot in or a \
                   rewrite of the journal's last transaction rather than of a crash: a write this \
                   daemon acknowledged may be among the cut, ";
    let trailer =
        "; a copy taken before this open holds the bytes; check the volume and its device";
    // The claimed position above the head names the write — the position its
    // acknowledgement and the change feed named it by.
    assert_eq!(
        rot.to_string(),
        format!(
            "{opening}at position 3, the position an intact commit marker in the cut claims\
             {trailer}"
        )
    );
    // No marker read — an intact frame that does not decode — and a claim at
    // or below the head, a position that stands: the write is placed above
    // the head and never named by a position the journal still holds.
    for claimed in [None, Some(Seq(2)), Some(Seq(1))] {
        assert_eq!(
            rot_at(claimed),
            format!("{opening}at a position above 2{trailer}"),
            "claimed {claimed:?}"
        );
    }
}

/// THE VERSION LINE's WORDS (`operations.md` §3.4 step 6's gap, closed),
/// pinned whole: the build's version — the workspace's one,
/// `CARGO_PKG_VERSION` — and its commit, `SKEP_GIT_SHA`'s at build time and
/// `unknown` where the build set none, as `skepd --version` names them, so
/// two builds of one version are told apart on the stream; and the three
/// format stamps this build reads, the kernel's two as text and the engine's
/// as its refusal renders it. The stamps are SPELLED here, and the literals
/// asserted to be the crates' constants beside the line, so a stamp that
/// moves re-spells this pin rather than passing a line that names the old
/// one — and a render from a literal in the daemon, one byte off its
/// constant, fails on the first assertion. Last, the clause `built with
/// {features}`: the optional features this build carries — `observe`,
/// `client`, `test-hooks`, in that order — transcribed here from the build's
/// own cfgs rather than read through the daemon's function, or `no optional
/// feature`, the hosted image's.
#[test]
fn the_version_line_names_the_build_and_the_three_formats_it_reads() {
    let built: Vec<&str> = [
        ("observe", cfg!(feature = "observe")),
        ("client", cfg!(feature = "client")),
        ("test-hooks", cfg!(feature = "test-hooks")),
    ]
    .into_iter()
    .filter_map(|(feature, on)| on.then_some(feature))
    .collect();
    let built = if built.is_empty() { "no optional feature".to_string() } else { built.join(", ") };
    assert_eq!(
        VersionLine.to_string(),
        format!(
            "version {} ({}); this build reads journal format SKJ4, checkpoint format SKC4 and \
             world format 0x534b505700000001; built with {built}",
            env!("CARGO_PKG_VERSION"),
            option_env!("SKEP_GIT_SHA").unwrap_or("unknown")
        )
    );
    assert_eq!(
        skep_kernel::JOURNAL_FORMAT,
        *b"SKJ4",
        "the journal's stamp moved: re-spell the pin"
    );
    assert_eq!(
        skep_kernel::CHECKPOINT_FORMAT,
        *b"SKC4",
        "the checkpoint's stamp moved: re-spell the pin"
    );
    assert_eq!(
        skep_engine::WORLD_FORMAT,
        0x534B_5057_0000_0001,
        "the World's stamp moved: re-spell the pin"
    );
}

/// THE CLASSED DOOR for the open's own lines (CUT 1 (a)): every line of the
/// open's report said from `open_under` under the report's own class — the
/// version's, the directory's, the recovery's, the beginning's, the stray
/// `checkpoint.tmp`'s, the tail cut's, the media limits', the volume's free
/// space and the upload setting's — goes out through `say_open_line`, which
/// emits under
/// `Class::Open`, and no site in the open spells that class itself — read
/// off the source, since no suite captures the stream in-process; the class
/// word on the stream itself is pinned by the child-process suite
/// (`tests/it/open.rs`), which reads `open:` on the binary's stderr. The
/// tail cut's failure arm, said under its own class, is the one line of the
/// report beside the door. And the version line is said FIRST, before the
/// directory's.
#[test]
fn the_opens_own_lines_go_through_the_classed_door() {
    let source = include_str!("../server.rs");
    let start = source.find("fn open_under(").expect("open_under");
    let end =
        source[start..].find("fn write_the_claims_head_if_owed(").expect("the next fn") + start;
    let open_under = &source[start..end];
    assert_eq!(
        open_under.matches("say_open_line(").count(),
        9,
        "the nine lines — the version, the directory, the recovery, the beginning, the stray \
         checkpoint.tmp, the tail cut, the media limits, the volume's free space, the upload \
         setting — each through the door"
    );
    assert!(
        open_under.contains("say_open_line(BeganLine)"),
        "the beginning's line is a rendered value through the door"
    );
    assert!(
        open_under.find("say_open_line(RecoveredLine::of(").expect("the landing")
            < open_under.find("say_open_line(BeganLine)").expect("the beginning's line"),
        "the beginning is said after the landing it qualifies"
    );
    assert!(
        !open_under.contains("notice::emit(Class::Open,"),
        "no line of the open's report spells `Class::Open` at its site: the door is the one emit"
    );
    assert!(
        open_under.find("say_open_line(VersionLine)").expect("the version line")
            < open_under.find("say_open_line(DataDirLine(").expect("the directory's line"),
        "the version line comes before the directory's"
    );
    assert!(
        open_under.find("say_open_line(DataDirLine(").expect("the directory's line")
            < open_under.find("Engine::open(").expect("the engine's open"),
        "the directory's line comes before the engine's open"
    );
    assert!(
        open_under.contains("say_open_line(UploadsLine {"),
        "the upload setting's line is a rendered value through the door"
    );
    assert!(
        open_under.find("say_open_line(media.startup_line())").expect("the media limits' line")
            < open_under.find("say_open_line(VolumeLine {").expect("the volume's line"),
        "the volume's free space follows the media limits' line, which names the floor"
    );
    let door = source.find("fn say_open_line(").expect("the door");
    assert!(
        source[door..door + 160].contains("notice::emit(Class::Open,"),
        "the door emits under Class::Open"
    );
}

/// THE SERVED PAGE's PARAGRAPH of the module doc says what `GET /` serves:
/// the read-only GUEST READER — no key, token or session — and no longer an
/// acting client that generates keys and opens signed sessions, which the
/// file at `clients/board.html` never did. Read off the source, as the
/// door's pin is; the wire document's own words are pinned by
/// `tests/it/wire_doc.rs`.
#[test]
fn the_module_doc_says_the_served_page_is_the_guest_reader() {
    let source = include_str!("../server.rs");
    let start = source.find("**The served client (wire v6").expect("the served-client paragraph");
    let end = source[start..].find("\n\n").map_or(source.len(), |n| n + start);
    let paragraph = source[start..end].to_lowercase();
    assert!(
        paragraph.contains("guest reader"),
        "the paragraph names the guest reader: {paragraph}"
    );
    for stale in ["generates keys", "opens signed sessions"] {
        assert!(!paragraph.contains(stale), "the paragraph no longer says {stale:?}: {paragraph}");
    }
}

/// THE GRAMMAR's MOMENTS, as a warning's class word spells each — the four
/// the warning class is keyed by, `at reissue` the fourth (RULED at this
/// lane's cut) — one label per moment and no two alike; and ROW 20's HEADER,
/// which keeps its own ruled spelling for the list's three moments:
/// `reissued` where the warning class says `at reissue`.
#[test]
fn every_moment_spells_its_own_label_and_the_lists_header_keeps_its_own() {
    let labels: Vec<String> = [Moment::AtStart, Moment::AtClaim, Moment::AtOpen, Moment::AtReissue]
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(labels, ["at start", "at claim", "at open", "at reissue"]);
    assert_eq!(Class::Warning(Moment::AtReissue).to_string(), "warning (at reissue)");
    let path = Path::new("/etc/skepd/blocked.json");
    assert_eq!(
        ListHeader { when: Moment::AtStart, path }.to_string(),
        "blocked-prefix list (at start, /etc/skepd/blocked.json):"
    );
    assert_eq!(
        ListHeader { when: Moment::AtReissue, path }.to_string(),
        "blocked-prefix list (reissued, /etc/skepd/blocked.json):"
    );
    assert_eq!(
        ListHeader { when: Moment::AtClaim, path }.to_string(),
        "blocked-prefix list (at claim, /etc/skepd/blocked.json):"
    );
}

/// LINE 8's WORDS (`operations.md` §1.1 row 8) at each source: the switch's
/// state with the source the parse recorded — the default's phrase, the
/// flag as typed, the variable with its value — and, closed, what the
/// family answers.
#[test]
fn the_upload_settings_line_names_its_state_and_its_source() {
    assert_eq!(
        UploadsLine { open: true, source: Source::Default }.to_string(),
        "media uploads: open (the default)"
    );
    assert_eq!(
        UploadsLine { open: true, source: Source::Flag }.to_string(),
        "media uploads: open (--uploads)"
    );
    assert_eq!(
        UploadsLine { open: true, source: Source::Env }.to_string(),
        "media uploads: open (SKEPD_UPLOADS=true)"
    );
    let closed = "the creation and the resume are refused uploads_closed";
    assert_eq!(
        UploadsLine { open: false, source: Source::Flag }.to_string(),
        format!("media uploads: CLOSED (--no-uploads): {closed}")
    );
    assert_eq!(
        UploadsLine { open: false, source: Source::Env }.to_string(),
        format!("media uploads: CLOSED (SKEPD_UPLOADS=false): {closed}")
    );
    assert_eq!(
        UploadsLine { open: false, source: Source::Default }.to_string(),
        format!("media uploads: CLOSED (the default): {closed}"),
        "a caller that closes the switch and names no source: the default's phrase, as told"
    );
}

/// THE FLIP's LINE (m14) at fixed figures, each of `H.1`'s three arms: the
/// claimant as `/health` spells it, the claim's position, the mode's word,
/// and what became of the first head — written now, written before the
/// claim by the cadence (the state the design's two arms left unsaid), or
/// owed after the head writer's refusal.
#[test]
fn the_flips_line_names_the_account_the_position_the_mode_and_each_head_arm() {
    use skep_core::codec::wire_address;

    let claimant = wire_address("1.0.1").expect("an account address");
    let at = |head: FirstHead, mode: &str| {
        ClaimLine { claimant: &claimant, position: Seq(42), mode, head }.to_string()
    };
    assert_eq!(
        at(FirstHead::Written, "CLAIMED-ENFORCING"),
        "board claimed by 1.0.1 at position 42: the mode is now CLAIMED-ENFORCING; H.1 written"
    );
    assert_eq!(
        at(FirstHead::Stood, "CLAIMED-PERMISSIVE"),
        "board claimed by 1.0.1 at position 42: the mode is now CLAIMED-PERMISSIVE; H.1 written \
         before the claim"
    );
    assert_eq!(
        at(FirstHead::Refused, "CLAIMED-PERMISSIVE"),
        "board claimed by 1.0.1 at position 42: the mode is now CLAIMED-PERMISSIVE; H.1 owed — \
         the head writer refused it"
    );
}

/// ROW 12's WORDS — THE FIRST HEAD WRITTEN AT OPEN — at fixed figures: where
/// `H.1`'s commits landed, how long its write took, and the committed pair it
/// names, the claim's own position where the crash split the claim from its
/// head. The line on the wire of a real reopen is the hazard suite's
/// (`tests/it/hazard.rs`, the claim window).
#[test]
fn the_head_written_at_open_names_where_it_landed_its_duration_and_the_pair_it_names() {
    assert_eq!(
        HeadAtOpenLine { landed: Seq(20), duration_ms: 9, named: Seq(12) }.to_string(),
        "the board is claimed and its journal held no head: H.1 written at open at position 20 \
         in 9 ms, naming the committed pair at position 12"
    );
}

/// ROW 22's and ROW 24's WORDS at fixed inputs: the checkpoint thread's
/// refusal with its cause, what still serves, the act and what is lost
/// until it; a reissue's refusal with its cause, what stands, what the next
/// start does and the lift's form, the supply's path named.
#[test]
fn the_two_refusal_lines_carry_their_ruled_words() {
    use std::io::Error;

    let refused = Error::new(ErrorKind::WouldBlock, "Resource temporarily unavailable");
    assert_eq!(
        CheckpointThreadRefusedLine(&refused).to_string(),
        "checkpoint thread: the OS refused it (Resource temporarily unavailable); the kernel's \
         backstop runs each second crossing's checkpoint inline on the committing thread \
         instead; until a restart re-spawns it, every checkpoint is the backstop's and says \
         nothing — no landing line and no failure line — and the change feed's files are not \
         compacted, and the cadence's byte bound and the media floor stay at the open's \
         figures; and no standing line will come: each state is said at its transition alone"
    );
    let torn = Error::new(ErrorKind::InvalidData, "/etc/skepd/blocked.json: not a list");
    assert_eq!(
        ReissueRefusedLine { error: &torn, path: Path::new("/etc/skepd/blocked.json") }.to_string(),
        "blocked-prefix list: reissue REFUSED — /etc/skepd/blocked.json: not a list; the list \
         in force stands until a restart, and the next start REFUSES until a valid list stands \
         at /etc/skepd/blocked.json: an empty \"entries\" lifts every block, an absent file \
         lifts none"
    );
}

/// THE CLASSED DOOR for the configuration lines (CUT 1 (a); this lane's
/// sites): every line of the daemon's own section — the warnings, the
/// `auth:` line, the node prefix, the blocked list, the reissue's refusal —
/// goes out through `Daemon::say` or `Daemon::say_lines`, which emit with
/// the class word each takes, and none through the un-classed `line` or
/// `lines`; the flip's line in `op.rs` and the checkpoint thread's refusal
/// in `listen.rs` take the classed door too — read off the sources, since
/// no suite captures the stream in-process; the class each line is emitted
/// under is pinned through `Daemon::lines_said` by the integration suites.
/// The head writer's row 40 is held the same way by `skep-core`'s
/// `commits/tests.rs`, beside the file it reads.
#[test]
fn the_configuration_lines_go_through_the_classed_door_with_their_class_words() {
    let source = include_str!("../server.rs");
    let start = source.find("    fn log_config_warnings(").expect("the section's first method");
    let end = source[start..].find("// ── the checkpoint thread's work").expect("the section's end")
        + start;
    let section = &source[start..end];
    assert!(
        !section.contains("notice::line(") && !section.contains("notice::lines("),
        "no line of the section goes through the un-classed door"
    );
    for site in [
        "self.say(Class::Warning(when), w)",
        "self.say(Class::Open, self.auth.cfg.auth_line(",
        "self.say(Class::Open, self.auth.cfg.node_prefix_line(",
        "Moment::AtStart | Moment::AtOpen => Class::Open",
        "Moment::AtClaim | Moment::AtReissue => Class::Landing",
        "self.log_blocked_prefixes(Moment::AtReissue)",
        "self.say(Class::Failure, ReissueRefusedLine {",
        "self.say(Class::Standing, line)",
        "self.say(Class::Failure, CheckpointThreadEndedLine)",
        "self.say(Class::Failure, PrunerThreadEndedLine)",
        "notice::emit(class, what)",
        "notice::emit_lines(class, head, rest)",
    ] {
        assert!(section.contains(site), "the section lacks `{site}`");
    }
    let op = include_str!("op.rs");
    let flip = op.find("    fn on_claim_flip(").expect("the flip");
    let flip = &op[flip..op[flip..].find("    pub(super) fn post_op(").expect("the next fn") + flip];
    assert!(flip.contains("self.say(Class::Landing, ClaimLine {"), "the flip's landing line");
    assert!(
        flip.find("self.say(Class::Landing, ClaimLine {").expect("the line")
            < flip.find("self.log_config_warnings(Moment::AtClaim)").expect("the warnings"),
        "the landing line is said before the claim-time warnings"
    );
    let listen = include_str!("listen.rs");
    assert!(
        listen.contains("notice::emit(Class::Failure, CheckpointThreadRefusedLine(&e))"),
        "row 22 through the classed door"
    );
    let serve_bound = listen.find("pub fn serve_bound(").expect("serve_bound");
    let order: Vec<usize> = [
        "daemon.bind_auth_port(port)",
        "daemon.log_config_warnings(Moment::AtStart)",
        "daemon.log_auth_line()",
        "daemon.log_node_prefix()",
        "daemon.log_blocked_prefixes(Moment::AtStart)",
        "thread::Builder::new().name(\"skepd-worker\"",
    ]
    .iter()
    .map(|site| listen[serve_bound..].find(site).unwrap_or_else(|| panic!("`{site}`")))
    .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "§3.1 step 3's order: {order:?}");
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
    let announced = || daemon.commits.announced();
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
/// kernel's head — `skep-core`'s `commits`' guarantee (every position a
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
        (d.commits.announced(), ahead)
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
/// naming that checkpoint and the empty resolution. And after them, one line
/// where the open's scan PASSED OVER corrupt runs below its start point,
/// naming the start point, how many, and the kernel's account of the first.
/// The daemon writes each through the operator stream at open, which no test
/// can read back, so the rendering is pinned here against the report the
/// daemon renders it from.
#[test]
fn the_recovery_warnings_name_the_skipped_checkpoint_the_start_point_and_the_empty_resolution() {
    use skep_engine::{Recovery, SkippedBase};

    assert!(recovery_warnings(None).is_empty(), "in memory, nothing to say");
    let carried = Recovery {
        start_point: Seq(2048),
        skipped: vec![],
        replayed: 0,
        tail_cut: 0,
        tail_cut_intact: 0,
        tail_cut_from: None,
        tail_cut_claimed: None,
        began: false,
        runs_passed_over: 0,
        first_run_passed_over: None,
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
        tail_cut_intact: 0,
        tail_cut_from: None,
        tail_cut_claimed: None,
        began: false,
        runs_passed_over: 0,
        first_run_passed_over: None,
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
        tail_cut_intact: 0,
        tail_cut_from: None,
        tail_cut_claimed: None,
        began: false,
        runs_passed_over: 0,
        first_run_passed_over: None,
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
        tail_cut_intact: 0,
        tail_cut_from: None,
        tail_cut_claimed: None,
        began: false,
        runs_passed_over: 0,
        first_run_passed_over: None,
        identity_resolved_empty: true,
    };
    let lines = recovery_warnings(Some(&resolved_empty));
    assert_eq!(lines.len(), 1, "{lines:?}");
    for needle in
        ["checkpoint.1024", "no identity slice", "RESOLVED EMPTY", "wrote no identity slice"]
    {
        assert!(lines[0].contains(needle), "{needle:?} missing from {:?}", lines[0]);
    }

    // The runs the open's scan PASSED OVER below its start point: one line,
    // after the AUTH warnings, naming the start point and carrying the
    // kernel's account of the first — one run, and several.
    let account = "corrupt run in seg-1.wal from byte 0 to byte 64, holding no position above \
                   position 3: a history read from a base below position 3, or an open that falls \
                   back to one, meets it and refuses; the act";
    let passed_over = |runs: u64| Recovery {
        start_point: Seq(1024),
        skipped: vec![SkippedBase {
            seq: Seq(2048),
            why: "checkpoint body failed its header checksum".into(),
        }],
        replayed: 0,
        tail_cut: 0,
        tail_cut_intact: 0,
        tail_cut_from: None,
        tail_cut_claimed: None,
        began: false,
        runs_passed_over: runs,
        first_run_passed_over: Some(account.to_string()),
        identity_resolved_empty: false,
    };
    let lines = recovery_warnings(Some(&passed_over(1)));
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("SKIPPED"), "the skipped base speaks first: {:?}", lines[0]);
    assert_eq!(
        lines[1],
        format!(
            "a corrupt run lies below the start point checkpoint.1024 and was PASSED OVER — \
             {account}"
        )
    );
    let lines = recovery_warnings(Some(&passed_over(3)));
    assert_eq!(
        lines[1],
        format!(
            "3 corrupt runs lie below the start point checkpoint.1024 and were PASSED OVER — the \
             first: {account}"
        )
    );
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

/// What a landing moved, at fixed figures, as the three lines after a
/// landing carry it: both bounds, the volume's free space, a reading of the
/// resident set beside the largest of the uptime's, and the feed's
/// compaction, its fence and its duration named, or nothing below the floor.
fn after_a_landing(fence: Option<u64>) -> AfterLanding {
    AfterLanding {
        bytes_bound: 25_165_824,
        floor: 268_435_456,
        free_space: 9_000_000_000,
        resident: ResidentRead { now: Some(412_000_256), most: Some(1_180_000_256) },
        compaction: FeedCompaction { fence, standing: vec![] },
        compaction_ms: 38,
    }
}

/// `after_a_landing`'s words, the feed's clause cut off at its fence.
const AFTER_A_LANDING: &str = "the cadence's byte bound 25165824, the media floor in force \
                               268435456, the volume's free space 9000000000; the process's \
                               resident set 412000256 bytes, the largest of this uptime's \
                               readings 1180000256 bytes; the change feed's files ";

/// LINE 25's WORDS (`operations.md` §1.1 row 25), pinned at fixed figures:
/// the position and the size, the duration in milliseconds, the journal
/// bytes reclaimed — or "nothing reclaimed" at zero — each checkpoint file
/// retention removed, by its name and its length, both bounds, the volume's
/// free space, a reading of the resident set beside the largest of the
/// uptime's readings — never called the process's peak — the compaction's
/// fence and its duration, with each file that stood named, and the inline
/// clause present only where the count moved. A header that did not answer
/// reads "size unread"; a resident set never read reads "unread", and a
/// reading the crate could not make reads "unread" beside the largest one
/// it made; a landing with nothing below the floor says so, and names no
/// duration, and one that removed no checkpoint names none.
#[test]
fn the_landing_line_carries_row_25s_figures_in_its_words() {
    let full = LandingLine {
        position: Seq(4200),
        bytes: Some(1_048_576),
        duration_ms: 17,
        reclaimed: Reclaimed {
            bytes: 2_097_152,
            removed: vec![(Seq(1024), 900_000), (Seq(2048), 950_000)],
        },
        after: AfterLanding {
            compaction: FeedCompaction {
                fence: Some(4095),
                standing: vec!["commits.log", "feed-index.log"],
            },
            ..after_a_landing(None)
        },
        inline: Some(InlineRuns { runs: 2, since: Seq(3100) }),
    };
    assert_eq!(
        full.to_string(),
        "checkpoint at position 4200 landed (1048576 bytes) in 17 ms; 2097152 journal bytes \
         reclaimed; checkpoint.1024 removed (900000 bytes), checkpoint.2048 removed (950000 \
         bytes); the cadence's byte bound 25165824, the media floor in force 268435456, the \
         volume's free space 9000000000; the process's resident set 412000256 bytes, the \
         largest of this uptime's readings 1180000256 bytes; the change feed's files compacted \
         below position 4096 in 38 ms, commits.log standing as it was, feed-index.log standing \
         as it was; 2 checkpoints ran inline on a writer since position 3100"
    );
    let quiet = LandingLine {
        position: Seq(7),
        bytes: None,
        duration_ms: 0,
        reclaimed: Reclaimed { bytes: 0, removed: vec![] },
        after: AfterLanding {
            bytes_bound: 24 * 1024 * 1024,
            floor: 256 * 1024 * 1024,
            free_space: 0,
            resident: ResidentRead { now: None, most: None },
            compaction: FeedCompaction::default(),
            compaction_ms: 0,
        },
        inline: None,
    };
    assert_eq!(
        quiet.to_string(),
        "checkpoint at position 7 landed (size unread) in 0 ms; nothing reclaimed; the \
         cadence's byte bound 25165824, the media floor in force 268435456, the volume's free \
         space 0; the process's resident set unread; the change feed's files hold nothing \
         below the reclaim floor"
    );
    assert_eq!(
        ResidentRead { now: None, most: Some(1_180_000_256) }.to_string(),
        "the process's resident set unread, the largest of this uptime's readings 1180000256 \
         bytes",
        "a reading the crate could not make, beside the largest one it made"
    );
}

/// LINE 26's WORDS (row 26; §4 row 2) at each cause: the run's duration, the
/// head's position as an ordering, a full volume in the operator's words
/// beside the OS's text, every other cause its own text, and the trailer
/// keyed to the cause — an I/O cause retries at the next crossing, a
/// poisoned kernel takes no checkpoint until a restart, a world that will
/// not serialize refuses the same way until the build fixes it. A base that
/// LANDED opens the line on its position, its size and the run's duration,
/// names which of the three steps failed, in the daemon's words and never
/// the kernel's, the volume's words re-applied to its cause, then what the
/// re-reads off the base moved — the floor, the bound, the feed's fence —
/// and no reclaim figure, the kernel storing none for a call that failed; a
/// landed base whose header did not answer is placed at or above the head
/// the run began at, what moved still said.
#[test]
fn the_failure_line_keys_its_trailer_to_the_cause_and_names_a_landed_bases_step() {
    use std::io::{Error, ErrorKind};

    let at = Seq(90);
    let unlanded = |error| FailureLine::Unlanded { at, duration_ms: 2400, error };
    let retry = "; the journal is not reclaimed and holds every commit; the next attempt is at \
                 the cadence's next crossing";
    let full = CheckpointError::Io(Error::new(ErrorKind::StorageFull, "No space left on device"));
    assert_eq!(
        unlanded(&full).to_string(),
        format!(
            "checkpoint FAILED after 2400 ms (the head stood at position 90 when the run \
             began): the volume is full (No space left on device){retry}"
        )
    );
    let denied = CheckpointError::Io(Error::new(ErrorKind::PermissionDenied, "denied"));
    assert_eq!(
        unlanded(&denied).to_string(),
        format!(
            "checkpoint FAILED after 2400 ms (the head stood at position 90 when the run \
             began): denied{retry}"
        )
    );
    let poisoned = CheckpointError::Poisoned;
    assert_eq!(
        unlanded(&poisoned).to_string(),
        "checkpoint FAILED after 2400 ms (the head stood at position 90 when the run began): \
         kernel is poisoned; no checkpoint taken; no checkpoint is taken until a restart (the \
         kernel's halt, said above)"
    );
    let refused = CheckpointError::Serialize("the `m5` slice refused".into());
    assert_eq!(
        unlanded(&refused).to_string(),
        "checkpoint FAILED after 2400 ms (the head stood at position 90 when the run began): \
         checkpoint world serialization failed: the `m5` slice refused; every crossing refuses \
         the same way until the world encodes: the build's to fix"
    );
    let full_volume = Error::new(ErrorKind::StorageFull, "No space left on device");
    for (step, words) in [
        (LandedStep::DirectorySync, "the directory's sync"),
        (LandedStep::Retention, "retention"),
        (LandedStep::Reclamation, "the journal's reclamation"),
    ] {
        let line = FailureLine::Landed {
            at,
            duration_ms: 1200,
            base: Some(LandedBase { position: Seq(96), bytes: 1_048_576 }),
            step,
            cause: &full_volume,
            after: after_a_landing(Some(95)),
        }
        .to_string();
        assert_eq!(
            line,
            format!(
                "a checkpoint landed at position 96 (1048576 bytes) in 1200 ms but {words} \
                 failed: the volume is full (No space left on device); {AFTER_A_LANDING}\
                 compacted below position 96 in 38 ms{retry}"
            ),
            "{step:?}"
        );
        // The kernel's own words for the step never reach the line.
        assert!(!line.contains(&step.to_string()), "{line}");
    }
    let squatted = Error::other("a directory stands on the name");
    assert_eq!(
        FailureLine::Landed {
            at,
            duration_ms: 1200,
            base: None,
            step: LandedStep::Retention,
            cause: &squatted,
            after: after_a_landing(None),
        }
        .to_string(),
        format!(
            "a checkpoint landed at or above position 90 (its header unread) in 1200 ms but \
             retention failed: a directory stands on the name; {AFTER_A_LANDING}hold nothing \
             below the reclaim floor{retry}"
        )
    );
}

/// THE BACKSTOP's LINE (m13): the runs since the position they are counted
/// from, and of the last of them the commit that ran it, by its position,
/// how long it held every write, and whether it landed and where or how it
/// failed, in the kernel's rendered words; a record the line could not read
/// is said as unread, never as a landing. Where the wake found the newest
/// checkpoint moved and took the landing's re-reads off it, the line goes on
/// to the base, what its landing reclaimed where the last inline run landed
/// it whole — never a reclaim figure for a base whose run then failed — and
/// what the re-reads moved, the floor and the feed's fence among them. The
/// kernel's own record, which only the kernel makes, reaches the line in the
/// integration suite (`tests/it/checkpoint.rs`), off a real backstop run.
#[test]
fn the_backstop_line_counts_the_inline_runs_from_a_position_and_says_how_the_last_ended() {
    let head = "checkpoint: the cadence outran the checkpoint thread; 1 checkpoints ran inline \
                on a writer since position 0, the last run by the commit at position 1026, \
                holding every write 412 ms, landed at position 1026";
    let landed = |newest| BackstopLine {
        runs: 1,
        since: Seq(0),
        last: Some(LastInlineRun { after: Seq(1026), held_ms: 412, outcome: Ok(Seq(1026)) }),
        newest,
    };
    assert_eq!(landed(None).to_string(), head, "a wake that took no re-read says none");
    assert_eq!(
        landed(Some(NewestLanded {
            base: Some(LandedBase { position: Seq(1026), bytes: 1_048_576 }),
            reclaimed: Some(Reclaimed { bytes: 2_097_152, removed: vec![(Seq(0), 4_096)] }),
            after: after_a_landing(Some(1025)),
        }))
        .to_string(),
        format!(
            "{head}; the newest checkpoint at position 1026 (1048576 bytes): 2097152 journal \
             bytes reclaimed; checkpoint.0 removed (4096 bytes); {AFTER_A_LANDING}compacted \
             below position 1026 in 38 ms"
        )
    );
    let failed = |newest| BackstopLine {
        runs: 3,
        since: Seq(512),
        last: Some(LastInlineRun {
            after: Seq(2050),
            held_ms: 3,
            outcome: Err("checkpoint I/O failure: No space left on device".to_string()),
        }),
        newest,
    };
    let failed_head = "checkpoint: the cadence outran the checkpoint thread; 3 checkpoints ran \
                       inline on a writer since position 512, the last run by the commit at \
                       position 2050, holding every write 3 ms, FAILED: checkpoint I/O \
                       failure: No space left on device";
    assert_eq!(failed(None).to_string(), failed_head);
    assert_eq!(
        failed(Some(NewestLanded {
            base: Some(LandedBase { position: Seq(2048), bytes: 1_048_576 }),
            reclaimed: None,
            after: after_a_landing(None),
        }))
        .to_string(),
        format!(
            "{failed_head}; the newest checkpoint at position 2048 (1048576 bytes): \
             {AFTER_A_LANDING}hold nothing below the reclaim floor"
        ),
        "a base whose run then failed: what moved, and no reclaim figure"
    );
    assert_eq!(
        failed(Some(NewestLanded { base: None, reclaimed: None, after: after_a_landing(None) }))
            .to_string(),
        format!(
            "{failed_head}; the newest checkpoint's header unread: {AFTER_A_LANDING}hold \
             nothing below the reclaim floor"
        )
    );
    assert_eq!(
        BackstopLine { runs: 1, since: Seq(0), last: None, newest: None }.to_string(),
        "checkpoint: the cadence outran the checkpoint thread; 1 checkpoints ran inline on a \
         writer since position 0, the last unread"
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

    use skep_core::commits::Woken;

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

    let signal = daemon.commits.checkpoint_signal();
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

/// THE STANDING LINE's WORDS at fixed reads (`operations.md` §1 THE RATES;
/// §1.1 m11): every clause standing, each in THE RATES' words with its
/// position or file, in THE RATES' order, joined by `; ` — the cell index's
/// with its place held, the kernel's poison with the position its halt line
/// named, and the journal damage a history read met by its site, after the
/// poison (RUNBOOK §2); each of the two flag clauses alone, and the damage
/// alone at each of its sites; and no clause, which is no line at all
/// (`stands` false).
#[test]
fn the_standing_line_carries_each_clause_in_the_rates_words_and_order() {
    use skep_core::commits::StoppedFile;

    let corrupt = HistoryError::Corruption { at: Seq(9), cause: None };
    let every = StandingLine {
        halted_at: Some(Seq(17)),
        poisoned: Some(Seq(17)),
        history_damaged: Some(JournalDamageSite(&corrupt).to_string()),
        stopped_files: vec![
            StoppedFile { name: "commits.log", since: 9 },
            StoppedFile { name: "feed-index.log", since: 12 },
        ],
        pruner_gone: true,
        feed_walk_gone: Some((20, 48)),
        index_failed: true,
        floor: Some(FloorBinding { free_space: 1000, floor: 268_435_456 }),
        claimed_permissive: true,
    };
    assert!(every.stands());
    assert_eq!(
        every.to_string(),
        "the write path is halted since position 17 (feed-attest.log); the kernel is poisoned \
         since position 17; a history read found the journal unreadable at position 9; \
         commits.log stopped since position 9; feed-index.log stopped since position 12; the \
         pruner's thread is gone; the feed walk's thread is gone; positions (20, 48] stay \
         uncovered; the cell index failed to build; deposits refused at the floor (free space \
         1000 below the floor in force 268435456); CLAIMED-PERMISSIVE"
    );
    let one = StandingLine {
        halted_at: None,
        poisoned: None,
        history_damaged: None,
        stopped_files: Vec::new(),
        pruner_gone: true,
        feed_walk_gone: None,
        index_failed: false,
        floor: None,
        claimed_permissive: false,
    };
    assert!(one.stands());
    assert_eq!(one.to_string(), "the pruner's thread is gone");
    let unreadable =
        HistoryError::Io(std::io::Error::other("seg-3.wal: read: Input/output error"));
    let damaged = StandingLine {
        history_damaged: Some(JournalDamageSite(&unreadable).to_string()),
        pruner_gone: false,
        ..one
    };
    assert!(damaged.stands(), "the journal damage alone stands");
    assert_eq!(
        damaged.to_string(),
        "a history read found the journal unreadable (seg-3.wal: read: Input/output error)",
        "an I/O failure's site is its file, its act and the OS's cause"
    );
    let poisoned = StandingLine {
        poisoned: Some(Seq(1203)),
        history_damaged: None,
        claimed_permissive: true,
        ..damaged
    };
    assert_eq!(
        poisoned.to_string(),
        "the kernel is poisoned since position 1203; CLAIMED-PERMISSIVE",
        "the poison names the position the halt line named"
    );
    let none = StandingLine {
        halted_at: None,
        poisoned: None,
        history_damaged: None,
        stopped_files: Vec::new(),
        pruner_gone: false,
        feed_walk_gone: None,
        index_failed: false,
        floor: None,
        claimed_permissive: false,
    };
    assert!(!none.stands(), "nothing on a healthy board");
    assert_eq!(none.to_string(), "");
}

/// Checks that RUNBOOK §1 step 8 lists the standing line as it is written.
///
/// Every clause stands at sentinel figures, each figure put back as the
/// placeholder the runbook names it by: the render is the step's fence, its
/// lines joined by `; ` in their order — so a clause the line gains, loses
/// or moves fails here rather than leaving the runbook short of it. The
/// runbook is read at test runtime, as `tests/it/runbook_doc.rs` reads it.
#[test]
fn runbook_lists_the_standing_line_as_the_binary_writes_it() {
    use skep_core::commits::StoppedFile;

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../RUNBOOK.md");
    let runbook = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let step = runbook
        .split("8. **Watch between the lines.**")
        .nth(1)
        .unwrap_or_else(|| panic!("RUNBOOK.md no longer carries §1 step 8"));
    let fence = step
        .split("```")
        .nth(1)
        .and_then(|block| block.split_once('\n'))
        .map(|(_, body)| body)
        .unwrap_or_else(|| panic!("§1 step 8 carries a fence:\n{step}"));
    let listed: Vec<&str> = fence.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let every = StandingLine {
        halted_at: Some(Seq(9001)),
        poisoned: Some(Seq(9001)),
        history_damaged: Some("at position 9001".to_string()),
        stopped_files: vec![StoppedFile { name: "{file}", since: 9001 }],
        pruner_gone: true,
        feed_walk_gone: Some((9002, 9003)),
        index_failed: true,
        floor: Some(FloorBinding { free_space: 9004, floor: 9005 }),
        claimed_permissive: true,
    };
    let written = [
        ("9001", "{position}"),
        ("9002", "{low}"),
        ("9003", "{head}"),
        ("9004", "{free}"),
        ("9005", "{floor}"),
    ]
    .into_iter()
    .fold(every.to_string(), |line, (figure, named)| line.replace(figure, named));
    assert_eq!(listed.join("; "), written, "RUNBOOK §1 step 8's fence:\n{fence}");
}

/// m10's WORDS and ROW 41's TWO CONSEQUENCE LINES at fixed inputs: the
/// kernel's halt with its position, the kernel's own cause — or the class
/// of its three causes where it kept none — and the act; the pruner's
/// verbatim; and the checkpoint thread's opening on row
/// 41's words, verbatim, then what the board lost beside them and the act —
/// the feed's compaction, the standing line, a restart — as row 22's line
/// says them for the thread refused at start.
#[test]
fn the_halt_line_and_the_two_catches_lines_carry_their_ruled_words() {
    use skep_core::commits::KernelHaltLine;

    let cause = "the commit of position 1204 failed (seg-3.wal: barrier: Input/output error), \
                 and the truncation that repairs it failed too (seg-3.wal: truncate: Input/output \
                 error): its frames may stand on disk, so the next open decides whether it stands";
    assert_eq!(
        KernelHaltLine { at: Seq(1203), cause: Some(cause) }.to_string(),
        format!(
            "the kernel halted its write paths at position 1203: {cause}; every write is refused \
             poisoned until a restart; reads serve; check the volume and the device, then restart"
        ),
        "the kernel's own cause rides the line"
    );
    assert_eq!(
        KernelHaltLine { at: Seq(1203), cause: None }.to_string(),
        "the kernel halted its write paths at position 1203: every write is refused poisoned \
         until a restart; reads serve. The cause is one of three the kernel did not report — a \
         commit that could not be rolled back durably, an unwind past the durability barrier, or \
         the sequence order exhausted; check the volume and the device, then restart",
        "with no cause kept, the three classes"
    );
    let ended = CheckpointThreadEndedLine.to_string();
    assert!(
        ended.starts_with(
            "checkpoint thread ended: every checkpoint from here is the backstop's, unsaid; the \
             byte bound and the floor stay where they were"
        ),
        "row 41's ruled words open the line: {ended}"
    );
    assert_eq!(
        ended,
        "checkpoint thread ended: every checkpoint from here is the backstop's, unsaid; the \
         byte bound and the floor stay where they were; until a restart re-spawns it, the \
         change feed's files are not compacted and no standing line will come: each state is \
         said at its transition alone"
    );
    assert_eq!(
        PrunerThreadEndedLine.to_string(),
        "pruner thread ended: no pass runs until a restart; the blob logs' compaction and the \
         lapsed tail's reclaim stop"
    );
}

/// THE JOURNAL DAMAGE's LINE (RUNBOOK §2) at fixed inputs: the kernel's own
/// words for the damage — corruption at rest naming its position, an I/O
/// failure naming its file, its act and the OS's cause — then what serves
/// on, why the next start may refuse, and the act; and, for damage at rest
/// alone, the wait for a checkpoint above it, which an open from that
/// checkpoint passes over, where no copy holds the file whole.
#[test]
fn the_history_damage_line_names_the_kernels_account_what_serves_and_the_act() {
    let before = "; reads at the head and every write serve on, since neither reads the journal \
                  back, but the next start's open reads the journal above its start point and may \
                  refuse on the same file: copy the data directory, run skepd inventory over the \
                  copy (its open reads the journal as a start does), and restore what it refuses \
                  from a copy before the board restarts";
    let passed_over = "; where no copy holds that file whole, keep the board serving and do not \
                       restart it until the next checkpoint lands: an open then starts above the \
                       damage and passes it over";
    let device = "; check the volume and its device";
    let corrupt = HistoryError::Corruption { at: Seq(9), cause: None };
    assert_eq!(
        HistoryDamageLine(&corrupt).to_string(),
        format!(
            "history: journal corrupt at rest; position 9 names the damage{before}{passed_over}\
             {device}"
        )
    );
    let unreadable =
        HistoryError::Io(std::io::Error::other("seg-3.wal: read: Input/output error"));
    assert_eq!(
        HistoryDamageLine(&unreadable).to_string(),
        format!(
            "history: history read I/O failure: seg-3.wal: read: Input/output error{before}\
             {device}"
        ),
        "an I/O failure in the active segment stops every open: no wait is named"
    );
}

/// A HISTORY READ THAT MEETS THE JOURNAL's DAMAGE SAYS SO ONCE (RUNBOOK §2):
/// the reader is answered as before — `500 history_corrupt` — and the
/// operator stream says ONE `failure: history: …` line for the uptime, never
/// one per read; a refusal that is no damage — the saturation, a segment a
/// reclamation removed, a position beyond the head — says nothing; and the
/// standing line re-says the damage at its tick by the site the first line
/// named — the position, never a later read's file — alone on a board with
/// nothing else standing.
#[test]
fn a_history_read_that_meets_the_journals_damage_says_so_once_and_is_re_said_while_it_stands() {
    use crate::history::Unavailable;

    let dir = tempfile::tempdir().expect("tempdir");
    let daemon = Daemon::open(dir.path()).expect("genesis open");
    daemon.set_media_free_space(Some(u64::MAX));
    let said = |prefix: &str| -> Vec<String> {
        daemon.lines_said().into_iter().filter(|l| l.starts_with(prefix)).collect()
    };
    for no_damage in [
        Unavailable::Busy,
        Unavailable::Journal(HistoryError::Io(std::io::Error::from(ErrorKind::NotFound))),
        Unavailable::Journal(HistoryError::BeyondHead { head: Seq(3) }),
    ] {
        let _ = daemon.refuse_history(no_damage);
    }
    assert_eq!(said("failure: history: "), Vec::<String>::new(), "no damage, nothing said");
    daemon.say_the_standing_line();
    assert_eq!(said("standing: "), Vec::<String>::new(), "nothing stands before the damage");
    let corrupt = || HistoryError::Corruption { at: Seq(9), cause: None };
    for _ in 0..2 {
        let reply = daemon.refuse_history(Unavailable::Journal(corrupt()));
        let v: Value = serde_json::from_slice(reply.bytes()).expect("json");
        assert_eq!((reply.status, v["error"].as_str()), (500, Some("history_corrupt")), "{v}");
    }
    let unreadable =
        HistoryError::Io(std::io::Error::other("seg-3.wal: read: Input/output error"));
    let _ = daemon.refuse_history(Unavailable::Journal(unreadable));
    assert_eq!(
        said("failure: history: "),
        [format!("failure: {}", HistoryDamageLine(&corrupt()))],
        "the first damage said once for the uptime, never per read"
    );
    daemon.say_the_standing_line();
    assert_eq!(
        said("standing: "),
        ["standing: a history read found the journal unreadable at position 9"]
    );
}

/// THE VOLUME's LINE (m4) at fixed figures: the free space at start in
/// bytes, and, where it stands below the floor in force — the creation's own
/// test, so at the floor exactly a deposit is admitted — the floor beside
/// it, what is refused and what serves.
#[test]
fn the_volume_line_names_the_free_space_and_where_the_floor_binds_what_it_refuses() {
    assert_eq!(
        VolumeLine { free_space: 9_000_000_000, floor: 268_435_456 }.to_string(),
        "the volume's free space at start: 9000000000 bytes"
    );
    assert_eq!(
        VolumeLine { free_space: 268_435_456, floor: 268_435_456 }.to_string(),
        "the volume's free space at start: 268435456 bytes",
        "at the floor exactly, deposits are admitted"
    );
    assert_eq!(
        VolumeLine { free_space: 1_000, floor: 268_435_456 }.to_string(),
        "the volume's free space at start: 1000 bytes, below the floor in force 268435456: \
         every deposit is refused until room stands; every other write serves"
    );
}

/// THE LIVE STREAMS' THREAD PAIR's WORDS at fixed inputs: the OS's refusal
/// in its own text, what it costs, what serves and the act; and the landing.
/// The edges themselves are the edge suite's (`tests/it/edges.rs`), driven
/// through the daemon's seam.
#[test]
fn the_stream_thread_pair_says_the_oss_cause_what_serves_the_act_and_the_landing() {
    let refused = std::io::Error::new(ErrorKind::WouldBlock, "Resource temporarily unavailable");
    assert_eq!(
        StreamThreadLine::Refused(&refused).to_string(),
        "live stream: the OS refused its thread (Resource temporarily unavailable); the stream \
         was closed before its head, and so is every new one while the OS refuses threads; \
         reads, writes and /health serve; the act: room under the host's thread limit (a \
         container's pids limit, the user's process limit)"
    );
    assert_eq!(
        StreamThreadLine::Again.to_string(),
        "live stream: the OS gives the streams their threads again"
    );
}
