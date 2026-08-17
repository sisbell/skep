//! Wire v4 CORS posture over a real socket: the preflight on every known
//! path, 404 preserved on unknown paths, and `Access-Control-Allow-Origin`
//! on every response — normal and error alike.

mod common;

use common::*;

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
        assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some("*"), "{path}");
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
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some("*"));

    sd.shutdown();
}

#[test]
fn every_response_carries_the_cors_header() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // Normal GET.
    let (st, headers, _) = http_full(port, "GET", "/health", None, b"");
    assert_eq!(st, 200);
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some("*"));

    // Normal POSTs: an op (a read frame) and a session open.
    let (st, headers, _) =
        http_full(port, "POST", "/op", None, br#"{"op":"next_account_prefix","parent":"1"}"#);
    assert_eq!(st, 200);
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some("*"));
    let (st, headers, _) = http_full(port, "POST", "/session", None, br#"{"principal":1}"#);
    assert_eq!(st, 200);
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some("*"));

    // Error responses: 404, 405, and a 400 transport error.
    let (st, headers, _) = http_full(port, "GET", "/nope", None, b"");
    assert_eq!(st, 404);
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some("*"));
    let (st, headers, _) = http_full(port, "GET", "/op", None, b"");
    assert_eq!(st, 405);
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some("*"));
    let (st, headers, _) = http_full(port, "POST", "/session", None, br#"{"user":"alice"}"#);
    assert_eq!(st, 400);
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some("*"));

    sd.shutdown();
}
