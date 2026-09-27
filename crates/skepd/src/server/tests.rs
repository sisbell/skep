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

/// A refusal is a status AND a name together: the body is built through
/// the codec's sorting device (byte-deterministic whatever backs
/// serde_json's map) and the status comes from the same table the name
/// does, so the wire.md pairing is checked rather than repeated.
#[test]
fn refusals_pair_their_status_with_their_name() {
    let r = refuse(TransportError::PayloadTooLarge, Some("too big"));
    assert_eq!(r.status, 413);
    assert_eq!(
        String::from_utf8(r.bytes().to_vec()).expect("json"),
        r#"{"detail":"too big","error":"payload_too_large"}"#
    );
    let r = refuse_with(
        TransportError::BeyondHead,
        vec![("head", Value::Number(12u64.into()))],
    );
    assert_eq!(r.status, 400);
    assert_eq!(
        String::from_utf8(r.bytes().to_vec()).expect("json"),
        r#"{"error":"beyond_head","head":12}"#
    );
}

/// wire.md §HTTP status codes, BOTH columns — the discipline
/// [`code_name`](crate::codec) already gives M10's sixty rejection
/// codes. The table is transcribed by hand for the reason
/// [`crate::fuzz_support::TRANSPORT_ERRORS`] is: one read out of the
/// code under test would agree with whatever that code says.
///
/// Four of these — `internal_panic`, `history_io`, `history_corrupt`,
/// `no_journal` — are reachable from no test in the tree (three need
/// at-rest journal damage, one cannot arise under this daemon's
/// `Fsync` configuration), so their spelling and their status are
/// watched here and nowhere else.
#[test]
fn every_transport_error_pairs_its_documented_name_with_its_documented_status() {
    let table: Vec<(TransportError, &'static str, u16)> = vec![
        (TransportError::MalformedSessionRequest, "malformed_session_request", 400),
        (TransportError::MalformedChallenge, "malformed_challenge", 400),
        (TransportError::MalformedOpAt, "malformed_op_at", 400),
        (TransportError::WriteAtHistory, "write_at_history", 400),
        (TransportError::BeyondHead, "beyond_head", 400),
        (TransportError::NotAPosition, "not_a_position", 400),
        (TransportError::MalformedAt, "malformed_at", 400),
        (TransportError::MalformedChanges, "malformed_changes", 400),
        (TransportError::MalformedHttp, "malformed_http", 400),
        (TransportError::NoSuchEndpoint, "no_such_endpoint", 404),
        (TransportError::MethodNotAllowed, "method_not_allowed", 405),
        (TransportError::HistoryReclaimed, "history_reclaimed", 410),
        (TransportError::PayloadTooLarge, "payload_too_large", 413),
        (TransportError::InternalPanic, "internal_panic", 500),
        (TransportError::HistoryIo, "history_io", 500),
        (TransportError::HistoryCorrupt, "history_corrupt", 500),
        (TransportError::NoJournal, "no_journal", 500),
        (TransportError::HistoryBusy, "history_busy", 503),
        (TransportError::ScanBusy, "scan_busy", 503),
    ];
    for &(err, name, status) in &table {
        assert_eq!(err.name(), name, "wire name drifted for {err:?}");
        assert_eq!(err.status(), status, "{name} must be answered with {status}");
        // The one builder every refusal goes through takes both from
        // the error, so the pairing a client dispatches on is checked
        // where it is produced rather than only where it is declared.
        let r = refuse(err, None);
        assert_eq!(r.status, status, "{name}: the reply's status");
        let body: Value = serde_json::from_slice(r.bytes()).expect("json");
        assert_eq!(body["error"].as_str(), Some(name), "{name}: the reply's body");
        // The fuzz oracle's list is the other hand transcription of
        // this column; a name in one and not the other is a drift.
        assert!(
            crate::fuzz_support::TRANSPORT_ERRORS.contains(&name),
            "{name} is answerable but absent from the fuzz oracle's list"
        );
    }
    // Both transcriptions of wire.md's error column, measured against
    // each other. A NEW variant is caught by the compiler at `name`
    // and `status`; this catches one that reaches the wire without
    // reaching either list. The `+ 2` is the handshake's PAIR, neither
    // a `TransportError` variant — both are built at their own site per
    // AUTH-6.5, [`refuse_handshake`]: `session_rejected`, the 401, and
    // `prefix_blocked`, the 403 that is its one exception. The oracle's
    // list names both because wire.md's error column does; no fuzz
    // daemon is supplied a blocked-prefix list, so the second is a name
    // no fuzz target is answered today.
    for handshake_name in ["session_rejected", "prefix_blocked"] {
        assert!(
            crate::fuzz_support::TRANSPORT_ERRORS.contains(&handshake_name),
            "{handshake_name} is answerable but absent from the fuzz oracle's list"
        );
    }
    #[cfg(feature = "observe")]
    assert_eq!(
        table.len() + 2,
        crate::fuzz_support::TRANSPORT_ERRORS.len(),
        "the two hand transcriptions of wire.md's error column disagree in length"
    );
}

/// THE CLASS-SCAN TEST, over the OP and not over the query's slots: as
/// M7 is built every link-discovery read walks the store end to end, so
/// the eleven bounded ops are bounded whatever their slots hold — a
/// second constrained slot, an annihilating `"empty"`, a narrow region —
/// and the reads that walk no link store are bounded by nothing.
///
/// Every row is PARSED through the codec rather than built by hand, so
/// the test reads the frames a client sends. The two lists are disjoint
/// and their union is checked against the bounded arm's own count, so an
/// op moved between the arms without moving here fails the last
/// assertion rather than passing in silence.
#[test]
fn every_link_store_walking_read_is_bounded_whatever_its_slots_hold() {
    /// The bounded arm's size, restated — moving the arm is a visible
    /// decision here, the discipline this crate gives its wire caps.
    const BOUNDED_OPS: usize = 11;

    let parse = |frame: &str| {
        JsonCodec.parse(frame.as_bytes()).unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail)).op
    };
    let ty = r#"[{"start":"1.1.0.1.0.1.0.3.90","width":"0.0.0.0.0.0.0.0.1"}]"#;
    let home = r#"[{"start":"1.0.1.0.1","width":"0.0.0.0.1"}]"#;
    let q = |home: &str, from: &str, to: &str, ty: &str| {
        format!(r#"{{"from":{from},"home":{home},"to":{to},"ty":{ty}}}"#)
    };
    let region = r#"[{"start":"1.1","width":"0.1"}]"#;
    let bounded = [
        // The FTT family, at every slot spelling: the wire's directory
        // shape, the whole store, the annihilated `"empty"`, home-only,
        // and — the cell the slot-keyed predecessor exempted — a SECOND
        // slot constrained, which is that same scan plus a comparison
        // per link and so costs strictly more.
        format!(r#"{{"op":"find_links_ftt","q":{}}}"#, q("\"any\"", "\"any\"", "\"any\"", ty)),
        format!(
            r#"{{"op":"find_links_ftt","q":{}}}"#,
            q("\"any\"", "\"any\"", "\"any\"", "\"any\"")
        ),
        format!(r#"{{"op":"find_links_ftt","q":{}}}"#, q(home, "\"any\"", "\"any\"", ty)),
        format!(r#"{{"op":"count_ftt","q":{}}}"#, q("\"any\"", ty, "\"any\"", ty)),
        format!(
            r#"{{"op":"count_ftt","q":{}}}"#,
            q("\"any\"", "\"any\"", "\"any\"", "\"empty\"")
        ),
        format!(r#"{{"op":"count_ftt","q":{}}}"#, q(home, "\"any\"", "\"any\"", "\"any\"")),
        format!(
            r#"{{"cur":null,"n":16,"op":"window_ftt","q":{}}}"#,
            q("\"any\"", "\"any\"", "\"empty\"", ty)
        ),
        // The region family: THREE scans apiece, one per v1 link slot.
        format!(r#"{{"d":"1.0.1.0.1","op":"find_links_v","region":{region}}}"#),
        format!(r#"{{"d":"1.0.1.0.1","op":"count_v","region":{region}}}"#),
        format!(
            r#"{{"cur":null,"d":"1.0.1.0.1","n":16,"op":"window_v","region":{region}}}"#
        ),
        format!(r#"{{"d":"1.0.1.0.1","op":"retrieve_endsets","region":{region}}}"#),
        // Six scans, and no owner gate: the dearest read on the surface.
        r#"{"d":"1.0.1.0.1","op":"delete_orphans","p":{"subspace":"1","ordinal":"1"},"width":"1"}"#
            .to_string(),
        // One scan apiece, at a single-span query.
        r#"{"op":"in_claims","y":"1.0.1.0.1.0.2.1","view":"default"}"#.to_string(),
        r#"{"op":"out_claims","x":"1.0.1.0.1.0.2.1","view":"default"}"#.to_string(),
        r#"{"op":"edition_claims","target":"1.0.1.0.1"}"#.to_string(),
    ];
    let unbounded = [
        // M5's resolve and one `readlink`: no store walk.
        format!(r#"{{"d":"1.0.1.0.1","op":"image","region":{region}}}"#),
        r#"{"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.1","op":"project","slot":1}"#.to_string(),
        r#"{"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.1","op":"discoverable_from"}"#.to_string(),
        r#"{"op":"read_link","a":"1.0.1.0.1.0.2.1"}"#.to_string(),
        r#"{"op":"follow_link","a":"1.0.1.0.1.0.2.1","slot":1}"#.to_string(),
        // The M6 and M3 reads touch no link store at all.
        r#"{"op":"retrieve_v","specs":[{"doc":"1.0.1.0.1","span":{"start":"1.1","width":"0.1"}}]}"#
            .to_string(),
        r#"{"op":"show_deletions","d_a":"1.0.1.0.1","d_b":"1.0.1.0.2"}"#.to_string(),
        r#"{"op":"doc_metadata","doc":"1.0.1.0.1"}"#.to_string(),
        r#"{"op":"next_account_prefix","parent":"1"}"#.to_string(),
    ];
    let mut names: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
    for frame in &bounded {
        let op = parse(frame);
        assert!(is_class_scan(&op), "walks the link store, so it is bounded: {frame}");
        names.insert(crate::codec::op_name(op.kind()));
    }
    for frame in &unbounded {
        assert!(!is_class_scan(&parse(frame)), "walks no link store: {frame}");
    }
    assert_eq!(
        names.len(),
        BOUNDED_OPS,
        "every bounded op is visited, and only those: {names:?}"
    );
}

/// The `scan_busy` refusal's exact body: a transport refusal (no `resp`,
/// no `code`) at 503, naming the op it refused beside the detail — the
/// bytes wire.md shows.
#[test]
fn scan_busy_names_the_op_in_a_transport_refusal() {
    let r = refuse_scan_busy(OpKind::CountFtt);
    assert_eq!(r.status, 503);
    assert_eq!(
        String::from_utf8(r.bytes().to_vec()).expect("json"),
        r#"{"detail":"all class-scan permits are in use; retry shortly","error":"scan_busy","op":"count_ftt"}"#
    );
}

/// The body and the type naming it travel together: a bodiless reply
/// writes no content headers at all, and a bodied one writes both —
/// which is what makes "a 204 that silently drops its bytes" and
/// "`Content-Type:` with nothing after it" unconstructible rather than
/// merely unwritten.
#[test]
fn a_bodiless_reply_writes_no_content_headers() {
    let pre = Reply::preflight();
    assert!(pre.body.is_none(), "the preflight names no body");
    assert!(pre.bytes().is_empty());
    let json = Reply::json(200, obj(vec![("ok", Value::Bool(true))]));
    let body = json.body.as_ref().expect("a JSON reply names its body");
    assert_eq!(body.content_type, "application/json");
    assert_eq!(body.bytes, br#"{"ok":true}"#);
}

/// A request's `Debug` carries the token's PRESENCE and the body's
/// LENGTH, never either's bytes: the token names a live session, and a
/// request's `{:?}` is what a panic or a trace line would carry.
#[test]
fn a_requests_debug_carries_no_token_and_no_body() {
    let token = "0123456789abcdef0123456789abcdef";
    let body = br#"{"op":"fork","id":"the-body"}"#.to_vec();
    let req = HttpRequest {
        method: "POST".to_string(),
        path: "/op".to_string(),
        query: None,
        session_token: Some(token.to_string()),
        origin: None,
        peer: Peer::Loopback,
        body: body.clone(),
    };
    let printed = format!("{req:?}");
    assert!(!printed.contains(token), "the token: {printed}");
    // As text, and as the decimal list a derived `Debug` prints a
    // `Vec<u8>` in.
    assert!(
        !printed.contains("the-body") && !printed.contains(&format!("{body:?}")),
        "the body: {printed}"
    );
    assert!(
        printed.contains("<token>") && printed.contains("body_len"),
        "presence and length: {printed}"
    );
}

/// The `/changes` query's accepted forms, and the page size the wire
/// promises when `limit` is absent (wire.md §The change feed: "default
/// 256, maximum 4096"). Every other test drives this parser through
/// its refusals; the seeded feeds are four writes long, so a default
/// silently changed to 4 — or to 4096 — produces an identical wire
/// answer in all of them.
#[test]
fn the_changes_query_defaults_to_the_documented_page_size() {
    let plain = |q: &str| {
        let p = changes_params(Some(q)).unwrap_or_else(|e| panic!("{q}: {e}"));
        (p.since, p.limit, p.under.map(|t| t.to_string()), p.drafts_only)
    };
    assert_eq!(
        plain("since=0"),
        (0, 256, None, false),
        "an absent limit is the documented default; no narrowing by default"
    );
    assert_eq!(plain("since=7&limit=10"), (7, 10, None, false));
    assert_eq!(
        plain("limit=10&since=7"),
        (7, 10, None, false),
        "parameters are a set, not a sequence"
    );
    assert_eq!(plain("since=0&limit=4096").1, 4096, "the maximum is in range");
    // The two narrowings (wire v7.8): a tumbler prefix, and the flag.
    assert_eq!(
        plain("since=3&under=1.0.2"),
        (3, 256, Some("1.0.2".into()), false),
        "under= names an address or prefix"
    );
    assert_eq!(
        plain("since=3&drafts=true&under=1.0.2.0.4"),
        (3, 256, Some("1.0.2.0.4".into()), true)
    );
    assert_eq!(plain("since=3&drafts=false").3, false, "drafts=false is the plain feed");
    for bad in [
        None,
        Some(""),
        Some("limit=2"),
        Some("since=abc"),
        Some("since=0&limit=0"),
        Some("since=0&limit=4097"),
        Some("since=0&since=1"),
        Some("since=0&nope=1"),
        Some("since"),
        Some("since=0&under="),
        Some("since=0&under=1..2"),
        Some("since=0&under=1.x"),
        Some("since=0&under=1&under=2"),
        Some("since=0&drafts=yes"),
        Some("since=0&drafts=1"),
        Some("since=0&drafts=true&drafts=true"),
    ] {
        assert!(changes_params(bad).is_err(), "{bad:?} must be refused");
    }
}

/// The `/dump` query is absent or exactly one position — the accepted
/// half of the parser `tests/history.rs` exercises only through its
/// refusals.
#[cfg(feature = "observe")]
#[test]
fn the_dump_query_is_absent_or_exactly_one_position() {
    let at = |q| dump_at_param(q).map(|o| o.map(|s| s.0));
    assert_eq!(at(None).expect("no query"), None);
    assert_eq!(at(Some("")).expect("empty query"), None);
    assert_eq!(at(Some("at=9")).expect("a position"), Some(9));
    assert_eq!(at(Some("at=0")).expect("genesis is a position"), Some(0));
    for bad in [Some("at=abc"), Some("at=1&at=2"), Some("position=3"), Some("at")] {
        assert!(dump_at_param(bad).is_err(), "{bad:?} must be refused");
    }
}

/// The preflight advertises exactly the header [`read_request`] reads.
/// The allow-list is one joined `&'static str`, so the header's name
/// necessarily appears in it as text rather than as the constant; this
/// is what keeps the two one decision. A header the preflight omits is
/// one a browser will not send, and that failure appears only
/// cross-origin, where this suite's own TCP clients never look.
#[test]
fn the_preflight_advertises_the_session_header_the_reader_reads() {
    let pre = Reply::preflight();
    let allow = pre
        .headers
        .iter()
        .find(|(k, _)| *k == "Access-Control-Allow-Headers")
        .map(|&(_, v)| v)
        .expect("the preflight names its allowed headers");
    assert!(allow.contains(SESSION_HEADER), "{allow} must name {SESSION_HEADER}");
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

/// The class-scan admission at both ends (wire v7.9): a bounded op takes
/// one of the [`MAX_CONCURRENT_CLASS_SCANS`] permits and any other read
/// takes none, a drained pool REFUSES rather than queueing, and a
/// released permit reopens its slot. The pool is per-op-shape, so an
/// unbounded read is admitted while it is drained — which is what keeps
/// the bound off the reads that walk no link store.
#[test]
fn the_class_scan_admission_takes_a_permit_only_for_a_bounded_op() {
    let op = |frame: &str| {
        JsonCodec
            .parse(frame.as_bytes())
            .unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail))
            .op
    };
    let bounded =
        op(r#"{"op":"count_ftt","q":{"from":"any","home":"any","to":"any","ty":"any"}}"#);
    let unbounded = op(r#"{"op":"doc_metadata","doc":"1.0.1.0.1"}"#);
    let scans = ClassScans::new();
    assert!(
        scans.admit(&unbounded).expect("an unbounded read is admitted").is_none(),
        "…and spends no permit"
    );
    let held: Vec<_> = (0..MAX_CONCURRENT_CLASS_SCANS)
        .map(|_| {
            scans.admit(&bounded).expect("a permit").expect("a bounded read takes one")
        })
        .collect();
    scans.admit(&bounded).expect_err("a drained pool refuses; it never queues");
    assert!(
        scans.admit(&unbounded).expect("an unbounded read is admitted").is_none(),
        "a drained pool does not reach the reads it does not bound"
    );
    drop(held);
    assert!(
        scans.admit(&bounded).expect("a released permit reopens its slot").is_some(),
        "and the reopened slot is a permit, not an admission with none"
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
