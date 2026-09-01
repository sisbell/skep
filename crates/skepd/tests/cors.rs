//! Wire v7 CORS posture over a real socket: the preflight on every known
//! path, 404 preserved on unknown paths, and BOTH universal headers —
//! `Access-Control-Allow-Origin` and the `Skepd-Session` exposure — on
//! every response, normal and error alike.

mod common;

use common::*;

/// The two headers wire.md promises on EVERY response (§Transport,
/// §Cross-origin access), asserted together because they are one constant:
/// the exposure is what lets a page on a configured origin read the death
/// signal, and a response missing it fails only cross-origin, where this
/// suite's own TCP clients never look.
fn assert_universal(headers: &[(String, String)], what: &str) {
    assert_eq!(header(headers, "Access-Control-Allow-Origin"), Some("*"), "{what}");
    assert_eq!(
        header(headers, "Access-Control-Expose-Headers"),
        Some("Skepd-Session"),
        "{what}: the death signal must be readable cross-origin"
    );
}

#[test]
fn preflight_answers_204_with_the_fixed_headers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let mut known = vec!["/session", "/op", "/op-at", "/health", "/events", "/changes"];
    if cfg!(feature = "observe") {
        known.push("/dump");
    }
    if cfg!(feature = "client") {
        known.push("/");
    }
    for path in known {
        let (st, headers, body) = options(port, path);
        assert_eq!(st, 204, "OPTIONS {path} answers 204");
        assert!(body.is_empty(), "a 204 carries no body ({path})");
        // The absence is the claim: a 204 that declares a length or names a
        // type is the shape `Reply`'s `Option<Body>` makes unconstructible
        // in the value, asserted here where the bytes are decided.
        assert_eq!(header(&headers, "Content-Length"), None, "a 204 declares no length ({path})");
        assert_eq!(header(&headers, "Content-Type"), None, "and names no type ({path})");
        assert_universal(&headers, path);
        assert_eq!(
            header(&headers, "Access-Control-Allow-Methods"),
            Some("GET, POST, OPTIONS"),
            "{path}"
        );
        assert_eq!(
            header(&headers, "Access-Control-Allow-Headers"),
            Some("Content-Type, Skepd-Session"),
            "{path}"
        );
        assert_eq!(header(&headers, "Access-Control-Max-Age"), Some("86400"), "{path}");
    }

    // An unknown path stays 404, preflight or not.
    let (st, headers, _) = options(port, "/nope");
    assert_eq!(st, 404);
    assert_universal(&headers, "an unknown path's preflight");

    sd.shutdown();
}

#[test]
fn every_response_carries_the_universal_headers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // Normal GET.
    let (st, headers, _) = http_full(port, "GET", "/health", None, b"");
    assert_eq!(st, 200);
    assert_universal(&headers, "GET /health");

    // Normal POSTs: an op (a read frame) and a session open.
    let (st, headers, _) =
        http_full(port, "POST", "/op", None, br#"{"op":"next_account_prefix","parent":"1"}"#);
    assert_eq!(st, 200);
    assert_universal(&headers, "POST /op");
    let (st, headers, _) = http_full(port, "POST", "/session", None, br#"{"principal":1}"#);
    assert_eq!(st, 200);
    assert_universal(&headers, "POST /session");

    // Error responses: 404, 405, and a 400 transport error.
    let (st, headers, _) = http_full(port, "GET", "/nope", None, b"");
    assert_eq!(st, 404);
    assert_universal(&headers, "404 no_such_endpoint");
    let (st, headers, _) = http_full(port, "GET", "/op", None, b"");
    assert_eq!(st, 405);
    assert_universal(&headers, "405 method_not_allowed");
    let (st, headers, _) = http_full(port, "POST", "/session", None, br#"{"user":"alice"}"#);
    assert_eq!(st, 400);
    assert_universal(&headers, "400 malformed_session_request");

    sd.shutdown();
}
