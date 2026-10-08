//! The session lifecycle over real HTTP: the challenge→signed-session→op
//! lifecycle, close and the death signal, `/health.auth`, the handshake's one
//! 401 and its 400s that spend no nonce, and the origin fences on both arms.

use super::*;

/// Challenge → signed session → op, and the strict body boundary: a reused
/// nonce is the ONE 401; an uppercase nonce is a 400 whose nonce SURVIVES.
#[test]
fn the_handshake_lifecycle_and_a_400_that_spends_no_nonce() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let p = CLAIMANT_PRINCIPAL;
    let (st, body) = http(port, "GET", &format!("/challenge?principal={p}"), None, b"");
    assert_eq!(st, 200);
    let ch = json(&body);
    assert_eq!(ch["ttl_ms"].as_u64(), Some(60_000), "the TTL is a byte pin");
    let nonce = ch["nonce"].as_str().expect("nonce").to_string();
    // The uppercase-nonce vector: 400, and the nonce is NOT burned.
    let sig = sign_session(&device_key(), &origin, &nonce, p);
    let upper = format!(
        "{{\"principal\":{p},\"nonce\":\"{}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}",
        nonce.to_uppercase()
    );
    let (st, body) = http(port, "POST", "/session", None, upper.as_bytes());
    assert_eq!(st, 400, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("malformed_session_request"));
    // The lowercased retry with the SAME nonce answers 200…
    let ok = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
    );
    let (st, body) = http(port, "POST", "/session", None, ok.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let token = json(&body)["session"].as_str().expect("token").to_string();
    // …and that session writes.
    let v = op(
        port,
        Some(&token),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    expect_resp(&v, "ack_addr");
    // A REUSED nonce is the one permanent 401, byte-identical.
    let (st, body) = http(port, "POST", "/session", None, ok.as_bytes());
    assert_eq!(st, 401);
    assert_eq!(
        String::from_utf8(body).expect("utf-8"),
        r#"{"error":"session_rejected"}"#,
        "one code, no detail"
    );
    // A malformed challenge query is its own 400.
    let (st, body) = http(port, "GET", "/challenge?nope=1", None, b"");
    assert_eq!(st, 400);
    assert_eq!(json(&body)["error"].as_str(), Some("malformed_challenge"));
    sd.shutdown();
}

/// Close discipline (AUTH-4.47) and the death signal (AUTH-6.7): a live
/// close is a bare 204; re-presenting the dead token signals on every
/// token-accepting route, beside the exposed header.
#[test]
fn close_is_idempotent_and_the_dead_token_signals() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (st, headers, _) = http_full(port, "POST", "/session/close", Some(&signed), b"");
    assert_eq!(st, 204);
    assert!(
        header(&headers, "Skepd-Session").is_none(),
        "a live close is the person's own act — no death signal"
    );
    // Idempotent: the same token again is 204 WITH the signal.
    let (st, headers, _) = http_full(port, "POST", "/session/close", Some(&signed), b"");
    assert_eq!(st, 204);
    assert_eq!(header(&headers, "Skepd-Session"), Some("closed"));
    // The dead token on /op: unauthenticated + the signal, and the
    // expose header rides every response.
    let (st, headers, body) = http_full(
        port,
        "POST",
        "/op",
        Some(&signed),
        br#"{"op":"register_node","addr":"1.4"}"#,
    );
    assert_eq!(st, 200);
    assert_eq!(json(&body)["code"].as_str(), Some("unauthenticated"));
    assert_eq!(header(&headers, "Skepd-Session"), Some("closed"));
    assert_eq!(
        header(&headers, "Access-Control-Expose-Headers"),
        Some("Skepd-Session"),
        "the death signal must be readable cross-origin (AUTH-6.12)"
    );
    sd.shutdown();
}

/// AUTH-4.40 — every `POST /session` mints a DISTINCT M10 session, principal
/// 0 included: `post_session` asks `bootstrap_session` afresh per call
/// (AUTH-6.35), and that is what confines the idempotency memo to the session
/// that wrote under it and a close to the binding it names. The memo is keyed
/// by (session, `id`, op kind), which makes the session observable at the
/// wire: two sessions of principal 0 sending two DIFFERENT `register_node`
/// frames under ONE `id` each commit their own node — the second is never
/// answered the first's memoized ack — and closing the first leaves the
/// second writing. Principal 0 is the claimant's own bootstrap principal,
/// opened by every device that signs as it, so a shared session would make
/// one device's retry replay another's write and one device's close end
/// every other's.
#[test]
fn every_session_open_mints_its_own_m10_session_principal_zero_included() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let first = open_session(port, PRINCIPAL_ZERO);
    let second = open_session(port, PRINCIPAL_ZERO);
    let node = |addr: &str| format!(r#"{{"op":"register_node","addr":"{addr}","id":"one-id"}}"#);

    let v = op(port, Some(&first), &node("1.5"));
    assert_eq!(expect_resp(&v, "ack_addr")["addr"].as_str(), Some("1.5"), "{v}");
    let v = op(port, Some(&second), &node("1.6"));
    assert_eq!(
        expect_resp(&v, "ack_addr")["addr"].as_str(),
        Some("1.6"),
        "the second session's frame commits its own node, never the first's memoized ack: {v}"
    );

    let (st, _) = http(port, "POST", "/session/close", Some(&first), b"");
    assert_eq!(st, 204);
    let v = op(port, Some(&second), r#"{"op":"register_node","addr":"1.7"}"#);
    assert_eq!(
        expect_resp(&v, "ack_addr")["addr"].as_str(),
        Some("1.7"),
        "closing the first session leaves the second writing: {v}"
    );
    sd.shutdown();
}

/// THE HYBRID HANDSHAKE's width check (AUTH-6.3, AUTH-4.34; the hybrid-only
/// launch's Q2): a `sig` whose width is NONE of the hybrid blob widths — the
/// classical 64-byte Ed25519 signature first, then one byte either side of
/// tag 1's 3,373 — is `400 malformed_session_request` with a `detail`, and
/// the nonce SURVIVES every one of them: the right blob then opens on that
/// same nonce. A WELL-FORMED blob no enrolled key verifies is the one `401
/// session_rejected`, byte-identical, its nonce spent — a zero blob of tag
/// 1's width, a zero blob of tag 3's width against a tag-1 set, the blob
/// with its POST-QUANTUM half broken, and the blob with its ED25519 half
/// broken: NO HALF OPENS A SESSION ALONE (AUTH-4.32).
#[test]
fn a_sig_of_no_hybrid_width_is_a_400_whose_nonce_survives_and_no_half_opens_alone() {
    const REJECTED: &str = r#"{"error":"session_rejected"}"#;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let origin = format!("http://127.0.0.1:{port}");
    let body_with = |nonce: &str, sig: &str| {
        format!("{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}")
    };
    let post = |body: &str| http_full(port, "POST", "/session", None, body.as_bytes());
    let malformed = |what: &str, (st, _, body): (u16, Vec<(String, String)>, Vec<u8>)| {
        assert_eq!(st, 400, "{what}: {}", String::from_utf8_lossy(&body));
        let v = json(&body);
        assert_eq!(v["error"].as_str(), Some("malformed_session_request"), "{what}");
        assert!(v["detail"].as_str().is_some_and(|d| d.contains("sig")), "{what}: the detail names the field: {v}");
    };
    let rejected = |what: &str, (st, _, body): (u16, Vec<(String, String)>, Vec<u8>)| {
        assert_eq!(st, 401, "{what}: {}", String::from_utf8_lossy(&body));
        assert_eq!(String::from_utf8(body).expect("utf-8"), REJECTED, "{what}: the one code");
    };

    // ONE nonce for every width fault: each is a 400, and none spends it.
    let nonce = challenge(port, p);
    let classical = sign_session_ed25519_half_alone(&device_key(), &origin, &nonce, p);
    assert_eq!(classical.len(), 128, "the classical layout: 64 signature bytes");
    malformed("the 64-byte Ed25519 signature alone", post(&body_with(&nonce, &classical)));
    let good = sign_session(&device_key(), &origin, &nonce, p);
    assert_eq!(good.len(), 6746, "tag 1's blob: 3,373 bytes");
    malformed("one byte short of tag 1's width", post(&body_with(&nonce, &good[..6744])));
    malformed("one byte past tag 1's width", post(&body_with(&nonce, &format!("{good}ab"))));
    malformed("one byte short of tag 3's width", post(&body_with(&nonce, &"00".repeat(729))));
    malformed("one byte past tag 3's width", post(&body_with(&nonce, &"00".repeat(731))));
    malformed("an empty sig", post(&body_with(&nonce, "")));
    // …and the nonce survived them all: the right blob opens on it.
    let (st, _, body) = post(&body_with(&nonce, &good));
    assert_eq!(st, 200, "the nonce survived every 400: {}", String::from_utf8_lossy(&body));
    assert!(json(&body)["session"].is_string());

    // WELL-FORMED blobs no enrolled key verifies: the one 401, nonce spent.
    let nonce = challenge(port, p);
    rejected("a zero blob of tag 1's width", post(&body_with(&nonce, &"00".repeat(3373))));
    rejected("…and its nonce is spent", post(&body_with(&nonce, &sign_session(&device_key(), &origin, &nonce, p))));
    let nonce = challenge(port, p);
    rejected("a zero blob of tag 3's width against a tag-1 set", post(&body_with(&nonce, &"00".repeat(730))));
    let nonce = challenge(port, p);
    rejected(
        "a tag-3 signer's blob against a tag-1 set",
        post(&body_with(&nonce, &sign_session_as(&tag3_signer(&device_key()), &origin, &nonce, p))),
    );

    // NO HALF OPENS A SESSION ALONE: the right blob with one half broken.
    let flip = |hex_sig: &str, at: usize| -> String {
        let mut chars: Vec<char> = hex_sig.chars().collect();
        chars[at] = if chars[at] == '0' { '1' } else { '0' };
        chars.into_iter().collect()
    };
    let nonce = challenge(port, p);
    let good = sign_session(&device_key(), &origin, &nonce, p);
    rejected("the post-quantum half broken", post(&body_with(&nonce, &flip(&good, 10))));
    let nonce = challenge(port, p);
    let good = sign_session(&device_key(), &origin, &nonce, p);
    rejected("the Ed25519 half broken", post(&body_with(&nonce, &flip(&good, 6745))));
    // …and the untouched blob on a fresh nonce still opens.
    let nonce = challenge(port, p);
    let (st, _, _) = post(&body_with(&nonce, &sign_session(&device_key(), &origin, &nonce, p)));
    assert_eq!(st, 200);

    sd.shutdown();
}

/// `/health.auth` (AUTH-6.13): claimant, local_trust, the two verbatim
/// origin lists — and NO `.mode` field (the negative pin).
#[test]
fn health_auth_publishes_the_pair_and_no_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let auth = json(&get(port, "/health").1)["auth"].clone();
    assert!(auth["claimant"].is_null(), "unclaimed: claimant null");
    assert_eq!(auth["local_trust"].as_bool(), Some(true), "the Phase A default");
    assert!(auth.get("mode").is_none(), "NO .mode field — clients derive the mode");
    let origins = auth["origins"].as_array().expect("origins");
    let dialed = format!("http://127.0.0.1:{port}");
    assert!(origins.iter().any(|o| o.as_str() == Some(dialed.as_str())), "{origins:?}");
    assert_eq!(
        auth["signed_origins"], auth["origins"],
        "unclaimed: the signed set IS the bare set"
    );
    claim_board(port);
    let auth = json(&get(port, "/health").1)["auth"].clone();
    assert_eq!(auth["claimant"].as_str(), Some(CLAIMANT_ACCOUNT), "the claim flips the claimant");
    assert_eq!(
        auth["signed_origins"].as_array().expect("signed").len(),
        0,
        "claimed with no configured origin: the signed set drops to configured alone"
    );
    assert!(
        !auth["origins"].as_array().expect("bare").is_empty(),
        "the bare set keeps the defaults"
    );
    sd.shutdown();
}

/// The `Origin` header at the wire — the bare-bind rule's other conjunct,
/// and the fence wire.md's `Access-Control-Allow-Origin: *` rests on
/// (§Cross-origin access: a foreign page's POST is fenced by the daemon,
/// not by what the browser lets it read back). No other test in this suite
/// sends the header, so the path from `read_request` to `bare_bind_allowed`
/// was carried by nothing: with it cut, `origin` is `None` everywhere and
/// every foreign origin is admitted.
///
/// The second half is the rule the three-valued answer exists for: a
/// refused origin runs THAT REQUEST as a guest and the binding LIVES — no
/// death, no signal.
#[test]
fn the_origin_header_fences_the_bare_bind_without_killing_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let dialed = format!("http://127.0.0.1:{port}");
    let sibling = format!("http://localhost:{port}"); // a loopback default
    let bare_body = format!("{{\"principal\":{CLAIMANT_PRINCIPAL}}}");
    let mint = format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#);

    // POST /session, bare: the dialed origin and its loopback sibling bind;
    // a foreign one is the ONE 401.
    for ok in [&dialed, &sibling] {
        let (st, _, body) =
            http_with_origin(port, "POST", "/session", None, ok, bare_body.as_bytes());
        assert_eq!(st, 200, "'{ok}' is in the bare set: {}", String::from_utf8_lossy(&body));
    }
    for bad in ["https://evil.example", "null", "http://127.0.0.1:9999"] {
        let (st, _, body) =
            http_with_origin(port, "POST", "/session", None, bad, bare_body.as_bytes());
        assert_eq!(st, 401, "'{bad}' is outside the bare set: {}", String::from_utf8_lossy(&body));
        assert_eq!(json(&body)["error"].as_str(), Some("session_rejected"));
    }

    // A LIVE bare session, presented from a foreign origin: that request
    // runs as a guest…
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, headers, body) = http_with_origin(
        port,
        "POST",
        "/op",
        Some(&bare),
        "https://evil.example",
        mint.as_bytes(),
    );
    assert_eq!(st, 200);
    assert_eq!(
        json(&body)["code"].as_str(),
        Some("unauthenticated"),
        "a bare session off the bare set writes nothing: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        header(&headers, "Skepd-Session").is_none(),
        "refused-for-this-request is NOT death: the binding lives and nothing signals"
    );
    // …and the SAME token still writes, which is what makes the line above
    // a statement about the request rather than about the session.
    expect_resp(&op(port, Some(&bare), &mint), "ack_addr");
    let (st, _, body) =
        http_with_origin(port, "POST", "/op", Some(&bare), &dialed, mint.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    expect_resp(&json(&body), "ack_addr");

    sd.shutdown();
}

/// `/session/close`'s THIRD CASE (AUTH-4.47; `post_session_close`'s card): a
/// LIVE BARE binding presented from an origin OUTSIDE the bare set is refused
/// for that request and LIVES, so the close retires NOTHING — and its answer
/// is byte-identical to a close that did retire one: 204, no body, no
/// `Skepd-Session`. A page that may not WRITE as a binding must neither end
/// it nor learn from the answer whether it lives. The close is the one
/// handler that acts on a token itself, beside the death arm every route
/// shares, so the `/op` cell above does not reach it.
#[test]
fn a_close_from_a_foreign_origin_retires_nothing_and_answers_as_a_close_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let dialed = format!("http://127.0.0.1:{port}");
    let mint = format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#);

    // A close that retires its binding, from the dialed origin: the bytes.
    let other = open_session(port, CLAIMANT_PRINCIPAL);
    let real = http_with_origin(port, "POST", "/session/close", Some(&other), &dialed, b"");
    assert_eq!(real.0, 204, "{real:?}");
    assert!(
        header(&real.1, "Skepd-Session").is_none() && real.2.is_empty(),
        "a live close is a bare 204: {real:?}"
    );

    // The same close from a foreign origin: the same answer, to the byte…
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let foreign =
        http_with_origin(port, "POST", "/session/close", Some(&bare), "https://evil.example", b"");
    assert_eq!(foreign, real, "a refused close answers exactly as a real close does");
    // …and the binding LIVES: the same token still writes.
    expect_resp(&op(port, Some(&bare), &mint), "ack_addr");

    sd.shutdown();
}

/// ENFORCING (§Identity) — the mode no other test instantiates, and the
/// claim flip as the one runtime transition that reaches it, since
/// `--local-trust` is fixed at open and pre-claim the flag is not consulted.
///
/// The load-bearing half is that a bare binding DIES rather than being
/// refused: `BareBind::ModeRefused` maps to `BindingDead` and
/// `RequestRefused` to a live binding, which is the whole reason that enum
/// has three arms, and no test at any level had covered the first.
#[test]
fn the_claim_flip_into_enforcing_kills_every_bare_binding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), false);
    let port = sd.port();
    // Pre-claim the flag is not consulted, so the bare bind binds and the
    // ceremony — which is bare work until its last step — runs.
    let bare = open_session(port, 0);
    expect_resp(&op(port, Some(&bare), r#"{"op":"next_account_prefix","parent":"1"}"#), "maybe_addr");
    claim_board(port);
    assert!(claimed(port));

    // The flip retires it: closed and signalled, not a live binding refused
    // for this request.
    let (st, headers, body) =
        http_full(port, "POST", "/op", Some(&bare), br#"{"op":"register_node","addr":"1.7"}"#);
    assert_eq!(st, 200);
    assert_eq!(
        json(&body)["code"].as_str(),
        Some("unauthenticated"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        header(&headers, "Skepd-Session"),
        Some("closed"),
        "ENFORCING kills a bare binding at presentation; it does not merely refuse it"
    );

    // No new bare session opens…
    let (st, body) = http(port, "POST", "/session", None, br#"{"principal":0}"#);
    assert_eq!(st, 401, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("session_rejected"));
    // …and the signed arm is unaffected: only signed sessions write.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    expect_resp(&v, "ack_addr");

    // /health publishes the pair the mode derives from — there is no
    // `.mode` field, so this is what a client reads it off.
    let auth = json(&get(port, "/health").1)["auth"].clone();
    assert_eq!(auth["local_trust"].as_bool(), Some(false));
    assert!(!auth["claimant"].is_null(), "claimed + !local_trust IS enforcing: {auth}");

    sd.shutdown();
}

/// m14 — THE CLAIM's FLIP SAYS ITSELF: after the claim, the daemon has said
/// ONE `landing:` line — `board claimed by {account} at position {p}: the
/// mode is now CLAIMED-ENFORCING; H.1 written` — `{account}` the claimant
/// the commit seated and `{p}` the position the claim's own ack carried,
/// NOT the head's position after the flip, which `H.1`'s own commits have
/// moved past it by the time the line is said. Read through the daemon's
/// record of what it said (`lines_said`), since no suite captures stderr
/// in-process.
#[test]
fn the_claims_flip_says_the_account_the_claims_position_the_mode_and_the_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), false);
    let port = sd.port();
    ceremony_before_the_claim(port);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT));
    let claim_at = acked_at(&v);
    assert!(claimed(port), "the claim link flips the board claimed");
    assert!(
        head_position(port) > claim_at,
        "H.1's own commits follow the claim, so the head is past the ack's position"
    );
    let said = sd.daemon().lines_said();
    let flip: Vec<&String> = said.iter().filter(|l| l.starts_with("landing: board claimed by ")).collect();
    assert_eq!(flip.len(), 1, "said once per flip:\n{}", said.join("\n"));
    assert_eq!(
        flip[0],
        &format!(
            "landing: board claimed by {CLAIMANT_ACCOUNT} at position {claim_at}: the mode is \
             now CLAIMED-ENFORCING; H.1 written"
        ),
        "FINDING (m14): the flip's line"
    );
    sd.shutdown();
}

/// m14's OWED ARM, through the head writer's refusal seam
/// (`refuse_the_next_head_once`, the one seam that refuses a first head
/// today): the claim's `H.1` refused by the driver, the flip's line says
/// `H.1 owed — the head writer refused it` with the claim's position and
/// the mode the flag picks — CLAIMED-PERMISSIVE here — and is said BEFORE
/// the claim-time warnings, whose first is the permissive one.
#[test]
fn a_refused_first_head_is_said_owed_on_the_flips_line_before_the_claims_warnings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), true);
    let port = sd.port();
    ceremony_before_the_claim(port);
    sd.daemon().refuse_the_next_head_once();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT));
    let claim_at = acked_at(&v);
    assert!(claimed(port), "the claim stands, its H.1 refused");
    assert!(board_term(port).is_none(), "no board term: the first head was refused");
    let said = sd.daemon().lines_said();
    let flip_at = said
        .iter()
        .position(|l| l.starts_with("landing: board claimed by "))
        .unwrap_or_else(|| panic!("FINDING (m14): no flip line:\n{}", said.join("\n")));
    assert_eq!(
        said[flip_at],
        format!(
            "landing: board claimed by {CLAIMANT_ACCOUNT} at position {claim_at}: the mode is \
             now CLAIMED-PERMISSIVE; H.1 owed — the head writer refused it"
        )
    );
    let warned_at = said
        .iter()
        .position(|l| l.starts_with("warning (at claim): board is claimed with --local-trust still on"))
        .unwrap_or_else(|| panic!("the claim-time warning:\n{}", said.join("\n")));
    assert!(flip_at < warned_at, "the landing line before the claim-time warnings");
    sd.shutdown();
}

/// m14's THIRD ARM, the state the design's two left unsaid: a head the
/// CADENCE wrote before the claim — a checkpoint taken pre-claim is one of
/// the head's triggers, so the ceremony's next write commits `H.1` — leaves
/// the claim's own first head a no-op, the board term standing and naming
/// a position BEFORE the claim; the flip's line says `H.1 written before
/// the claim`, never `owed`, which would be false of a board that serves
/// attested writes at once.
#[test]
fn a_head_the_cadence_wrote_before_the_claim_is_said_so_on_the_flips_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), false);
    let port = sd.port();
    ceremony_before_the_claim(port);
    // A checkpoint, then one more pre-claim write: its turn writes a head.
    sd.daemon().checkpoint_now();
    let claimant = open_session(port, CLAIMANT_PRINCIPAL);
    let v = op(
        port,
        Some(&claimant),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["x"],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    let before = board_term(port).expect("the cadence's head stands before the claim");
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT));
    let claim_at = acked_at(&v);
    assert!(before.log_position < claim_at, "H.1 names a position before the claim");
    assert_eq!(head_position(port), claim_at, "the claim's step wrote no second head");
    let said = sd.daemon().lines_said();
    let flip = said
        .iter()
        .find(|l| l.starts_with("landing: board claimed by "))
        .unwrap_or_else(|| panic!("no flip line:\n{}", said.join("\n")));
    assert_eq!(
        flip,
        &format!(
            "landing: board claimed by {CLAIMANT_ACCOUNT} at position {claim_at}: the mode is \
             now CLAIMED-ENFORCING; H.1 written before the claim"
        )
    );
    sd.shutdown();
}

/// wire.md §Sessions fixes the death signal's routes as a table: six carry
/// it; `/health`, `/challenge`, `/session` and — in `client` builds — `/`
/// are token-blind, and §Reading history adds `/chain` ("token-blind and
/// class-invariant like `/health`"). The negative half matters as much —
/// `/health` is what a client polls, and a signal there says a session died
/// that did not.
#[test]
fn the_death_signal_rides_exactly_the_documented_routes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    // A token whose binding this daemon has closed.
    let dead = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (st, _, _) = http_full(port, "POST", "/session/close", Some(&dead), b"");
    assert_eq!(st, 204);

    let signalled = |method: &str, path: &str, body: &[u8]| -> Option<String> {
        let (_, headers, _) = http_full(port, method, path, Some(&dead), body);
        header(&headers, "Skepd-Session").map(str::to_string)
    };

    let mut carries: Vec<(&str, &str, &[u8])> = vec![
        ("POST", "/op", br#"{"op":"next_account_prefix","parent":"1"}"#),
        ("POST", "/op-at", br#"{"at":0,"frame":{"op":"next_account_prefix","parent":"1"}}"#),
        ("GET", "/changes?since=0", b""),
        ("POST", "/session/close", b""),
    ];
    if cfg!(feature = "observe") {
        carries.push(("GET", "/dump", b""));
    }
    for (method, path, body) in carries {
        assert_eq!(
            signalled(method, path, body).as_deref(),
            Some("closed"),
            "{method} {path} carries the death signal"
        );
    }

    // Token-blind: presenting the same dead token changes nothing.
    let mut blind: Vec<(&str, &str, &[u8])> = vec![
        ("GET", "/health", b""),
        ("GET", "/chain?at=0", b""),
        ("GET", "/challenge?principal=1", b""),
        ("POST", "/session", br#"{"principal":1}"#),
    ];
    if cfg!(feature = "client") {
        blind.push(("GET", "/", b""));
    }
    for (method, path, body) in blind {
        assert_eq!(
            signalled(method, path, body),
            None,
            "{method} {path} is token-blind: no signal, however dead the token"
        );
    }

    // `/events` — the one signal that rides a STREAM HEAD rather than a
    // reply, written once, at open.
    let (mut stream, head) = Sse::connect_with_token(port, &dead);
    assert!(
        head.to_ascii_lowercase().contains("skepd-session: closed"),
        "a dead token meets the signal on the stream's own head: {head}"
    );
    stream.expect_commit(); // and the stream still serves
    let live = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (mut alive, head) = Sse::connect_with_token(port, &live);
    assert!(
        !head.to_ascii_lowercase().contains("skepd-session: closed"),
        "a live token's stream head carries no death signal: {head}"
    );
    alive.expect_commit();

    sd.shutdown();
}

/// AUTH-4.33 / wire.md §Sessions: every enrolled key is tried in
/// fingerprint order, "no cutoff, ever". Every signed handshake in this
/// suite signs with the device key, and whether that key sorts first is an
/// accident of SHA-256 over two fixed seeds — so a cutoff-after-first was
/// caught by chance or not at all. The signer is CHOSEN here from
/// `key_set`'s own published order, which makes both ends instances of the
/// law whatever the seeds hash to.
#[test]
fn every_enrolled_key_signs_including_the_last_in_fingerprint_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    let fps: Vec<String> = v["enrolled"]
        .as_array()
        .expect("enrolled")
        .iter()
        .map(|e| e["fingerprint"].as_str().expect("fp").to_string())
        .collect();
    assert_eq!(fps.len(), 2, "the ceremony enrolls the anchor and the device key: {v}");
    let by_fp = |want: &str| -> SigningKey {
        for k in [anchor_key(), device_key()] {
            if fingerprint_hex(&k) == want {
                return k;
            }
        }
        panic!("{want} is one of the ceremony's keys");
    };
    for (which, fp) in [("first", &fps[0]), ("last", &fps[1])] {
        let token = open_signed_session(port, CLAIMANT_PRINCIPAL, &by_fp(fp));
        let v = op(
            port,
            Some(&token),
            &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
        );
        assert_eq!(
            v["resp"].as_str(),
            Some("ack_addr"),
            "{which}-in-fingerprint-order established a session that writes: {v}"
        );
    }
    sd.shutdown();
}

/// The ONE 401 (AUTH-6.5), over the FAMILY of causes rather than one point:
/// every handshake failure answers the same bytes, because the whole design
/// of `SessionRejected` is that a client learns nothing about WHICH check
/// failed. Each row is a different arm of `handshake`.
///
/// The last two rows are E6's NEGATIVE half (AUTH-4.68: principal 0's set is
/// the claimant's — "signed with a non-claimant ENROLLED key it fails"): a
/// key enrolled NOWHERE, which would fail under any reading of 0's subject,
/// and a key ENROLLED at a member account of this board, which fails only
/// because 0 reads the claimant's set alone (AUTH-4.30 (i)'s first arm) and
/// never "any account's".
///
/// Expiry is the one cause deliberately omitted: reaching it needs the 60 s
/// TTL, and a sleeping test is the wrong trade.
#[test]
fn every_handshake_failure_answers_the_same_401_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let origin = format!("http://127.0.0.1:{port}");
    let nonce_for = |principal: u64| {
        let (st, body) =
            http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
        assert_eq!(st, 200);
        json(&body)["nonce"].as_str().expect("nonce").to_string()
    };
    let signed_body = |principal: u64, nonce: &str, org: &str, sk: &SigningKey| {
        let sig = sign_session(sk, org, nonce, principal);
        format!(
            "{{\"principal\":{principal},\"nonce\":\"{nonce}\",\"origin\":\"{org}\",\"sig\":\"{sig}\"}}"
        )
    };

    // The nonce this row reuses must first be SPENT on a success.
    let reused = nonce_for(p);
    let (st, _) = http(
        port,
        "POST",
        "/session",
        None,
        signed_body(p, &reused, &origin, &device_key()).as_bytes(),
    );
    assert_eq!(st, 200, "the first use of a nonce succeeds");

    // E6's enrolled non-claimant key: a member hired into the claimant's doc 1
    // — `keyed_member` opens the member's own session with it, so the key is
    // live on this board — and, the positive half beside it, a CLAIMANT key
    // opens principal 0.
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let member_key = distinct_key(23);
    keyed_member(port, &anchor, 923, &member_key);
    open_signed_session(port, 0, &device_key());

    let rows: Vec<(&str, String)> = vec![
        (
            "an origin outside the signed set",
            signed_body(p, &nonce_for(p), "https://evil.example", &device_key()),
        ),
        ("an unknown nonce", signed_body(p, &"ab".repeat(32), &origin, &device_key())),
        ("a reused nonce", signed_body(p, &reused, &origin, &device_key())),
        (
            "a nonce issued for another principal",
            signed_body(p, &nonce_for(p + 1), &origin, &device_key()),
        ),
        (
            "a principal with no account",
            signed_body(p + 77, &nonce_for(p + 77), &origin, &device_key()),
        ),
        (
            "a signature from an unenrolled key",
            signed_body(p, &nonce_for(p), &origin, &distinct_key(21)),
        ),
        (
            "principal 0, whose subject is the claimant, signing with a foreign key",
            signed_body(0, &nonce_for(0), &origin, &distinct_key(22)),
        ),
        (
            "principal 0, whose subject is the claimant, signing with a key ENROLLED at a member account",
            signed_body(0, &nonce_for(0), &origin, &member_key),
        ),
    ];
    for (what, body) in rows {
        let (st, headers, body) = http_full(port, "POST", "/session", None, body.as_bytes());
        assert_eq!(st, 401, "{what}");
        assert_eq!(
            String::from_utf8(body).expect("utf-8"),
            r#"{"error":"session_rejected"}"#,
            "{what}: one code, byte-identical, no detail"
        );
        assert!(header(&headers, "Skepd-Session").is_none(), "{what}: /session is token-blind");
    }
    // The BARE arm answers the same bytes: its refusal needs an origin
    // outside the bare set, which only the header can supply.
    let (st, _, body) = http_with_origin(
        port,
        "POST",
        "/session",
        None,
        "https://evil.example",
        format!("{{\"principal\":{p}}}").as_bytes(),
    );
    assert_eq!(st, 401);
    assert_eq!(
        String::from_utf8(body).expect("utf-8"),
        r#"{"error":"session_rejected"}"#,
        "the bare arm's refusal is the same one code"
    );

    sd.shutdown();
}

/// E6's POSITIVE cell carried THROUGH TO A WRITE (the conformance pack's row
/// 16; AUTH-4.68, AUTH-4.30 (i)'s first arm, AUTH-5.10): after the claim, a
/// session as principal 0 opened with a CLAIMANT key — 0's subject is the
/// claimant's set — runs the top-tier `delegate`, "0's whole reach", and it
/// COMMITS: the new seat answers `effective_owner` with its own prefix and
/// the id minted, the frontier moves, and the seated principal's bare
/// session mints its home. Every other `delegate` from 0 in these suites
/// rides a BARE session (`common::bootstrap_delegate`). And the reach is the
/// PRINCIPAL's, never the key's: the SAME key opened as the claimant is
/// refused by M3 on the SAME frame — `not_ancestor`, the prefix asked lying
/// outside the caller's own, H1's `delegate` row (`authz.rs`) — top-tier
/// seeding runs AS principal 0 and M3 refuses any other caller (AUTH-5.10).
#[test]
fn a_signed_principal_0_session_runs_the_top_tier_delegate_and_it_commits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let as_zero = open_signed_session(port, PRINCIPAL_ZERO, &device_key());
    let as_claimant = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let prefix = next_prefix_under(port, Some(&as_zero), "1");
    let frame = format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":978}}"#);

    // The same key, as the CLAIMANT: not principal 0, so not 0's reach — M3's
    // own refusal, the daemon's register spelling it, and nothing commits.
    let v = op(port, Some(&as_claimant), &frame);
    assert_eq!(verdict(&v), "not_ancestor", "the claimant's principal owns no top-level frontier: {v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(next_prefix_under(port, None, "1"), prefix, "nothing committed");

    // As principal 0, SIGNED with the claimant's key: the delegate commits.
    expect_resp(&op(port, Some(&as_zero), &frame), "ack_addr");
    assert_eq!(
        effective_owner(port, None, &prefix),
        Some((prefix.clone(), 978)),
        "a seat of its own, the id minted"
    );
    assert_ne!(next_prefix_under(port, None, "1"), prefix, "the frontier moved");
    let seated = open_session(port, 978);
    assert_eq!(create_doc(port, &seated, &prefix), format!("{prefix}.0.1"), "the seated principal's home mint");
    assert!(!presented_dead(port, &as_zero), "the signed 0 session lives across its own write");

    sd.shutdown();
}

/// AUTH-4.36's pinned order at the ONE point it is observable: the signed
/// arm tests the ORIGIN SET before it BURNS, so a body refused for its
/// origin leaves its nonce spendable. Every other 401 cause sits at or
/// behind the burn and spends one.
///
/// The row list above cannot see this. It gives each cause a nonce of its
/// own, so a burn moved ahead of the origin check answers every row
/// identically — and the module values the property elsewhere in the same
/// file, `Nonce::parse_hex` refusing uppercase precisely so the fault is "a
/// 400 syntax fault whose nonce SURVIVES, never a burned 401". Inverted,
/// the board spends a nonce on every attempt from a misconfigured origin,
/// which is the case `ClaimedWithEmptyConfigured` exists to warn about, and
/// a client that fetched one nonce and fixed its origin cannot retry.
#[test]
fn an_origin_refusal_precedes_the_burn_and_spends_no_nonce() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let origin = format!("http://127.0.0.1:{port}");
    let (st, body) = http(port, "GET", &format!("/challenge?principal={p}"), None, b"");
    assert_eq!(st, 200);
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();

    // Refused at step 2, and signed FOR that origin, so nothing else about
    // the body is wrong and no later step could be what refused it.
    let bad = "https://evil.example";
    let sig = sign_session(&device_key(), bad, &nonce, p);
    let refused = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{bad}\",\"sig\":\"{sig}\"}}"
    );
    let (st, body) = http(port, "POST", "/session", None, refused.as_bytes());
    assert_eq!(st, 401, "an origin outside the signed set: {}", String::from_utf8_lossy(&body));

    // The SAME nonce, signed for an admitted origin, still opens a session.
    let sig = sign_session(&device_key(), &origin, &nonce, p);
    let retry = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
    );
    let (st, body) = http(port, "POST", "/session", None, retry.as_bytes());
    assert_eq!(
        st, 200,
        "the origin refusal never reached the burn: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(json(&body)["session"].is_string());

    sd.shutdown();
}

/// The hex the daemon reads is read under a CASE POLICY per reader, and three
/// readers' policies are pinned: the nonce and the token REFUSE uppercase
/// (`the_handshake_lifecycle_and_a_400_that_spends_no_nonce` and the codec's
/// own token round trip), the content forms FOLD it. The signature folds too
/// — it is decoded and never framed — and nothing watched it, because every
/// signature in this suite comes from `sign_session`, which encodes
/// lowercase.
///
/// So a signature parse narrowed to the nonce's strict policy —
/// skep-identity's `HybridBlob::parse_hex`, which this handshake reads `sig`
/// through, taking up `parse_lower_hex`'s refusal of uppercase — refuses a
/// signature a client legitimately sent, as `400 malformed_session_request`.
#[test]
fn an_uppercase_signature_is_folded_where_an_uppercase_nonce_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let origin = format!("http://127.0.0.1:{port}");
    let (st, body) = http(port, "GET", &format!("/challenge?principal={p}"), None, b"");
    assert_eq!(st, 200);
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();
    let sig = sign_session(&device_key(), &origin, &nonce, p);
    assert_eq!(
        sig,
        sig.to_lowercase(),
        "the fixture's encoder is lowercase: that is why this cell needs writing"
    );
    let upper = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{}\"}}",
        sig.to_uppercase()
    );
    let (st, body) = http(port, "POST", "/session", None, upper.as_bytes());
    assert_eq!(st, 200, "an uppercase signature decodes: {}", String::from_utf8_lossy(&body));
    assert!(json(&body)["session"].is_string());

    sd.shutdown();
}
