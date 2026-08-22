//! The served client (wire v6): `GET /` answers the embedded board —
//! `text/html`, the same CORS posture as every other response — in builds
//! with the `client` feature (DEFAULT-OFF since 2026-08-22 — the acting
//! client must be opted into, so a hosted image that opts out of nothing
//! is still correct; see the feature's note in Cargo.toml); without it
//! the route does not exist and `/` is the ordinary 404. Both arms are
//! asserted: the workspace gate runs the default shape, and a
//! `--all-features` pass covers the serving one.

mod common;

use common::*;

#[cfg(feature = "client")]
#[test]
fn root_serves_the_embedded_board() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let (st, headers, body) = http_full(port, "GET", "/", None, b"");
    assert_eq!(st, 200);
    assert_eq!(header(&headers, "Content-Type"), Some("text/html; charset=utf-8"));
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some("*"));
    let html = String::from_utf8(body).expect("the board is UTF-8");
    assert!(
        html.contains("<title>skep board</title>"),
        "GET / must serve the board client (its title is the fingerprint)"
    );

    // A known path: preflight answers, a wrong method is 405 — not 404.
    let (st, _, _) = options(port, "/");
    assert_eq!(st, 204);
    let (st, body) = http(port, "POST", "/", None, b"{}");
    assert_eq!(st, 405, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("method_not_allowed"));

    sd.shutdown();
}

/// Built without the client, `/` is unknown: the usual 404 shape. (Runs
/// only under `--no-default-features --features observe` or similar; the
/// default workspace gate compiles it out.)
#[cfg(not(feature = "client"))]
#[test]
fn root_is_404_without_the_client_feature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (st, body) = http(port, "GET", "/", None, b"");
    assert_eq!(st, 404);
    assert_eq!(json(&body)["error"].as_str(), Some("no_such_endpoint"));
    sd.shutdown();
}
