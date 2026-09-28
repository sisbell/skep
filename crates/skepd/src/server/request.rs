//! The request a handler reads (`HttpRequest`), and the two rules every read
//! of its headers and query applies: a query is a parameter list, and a field
//! appears at most once.

use crate::auth::session::Peer;

/// One request, as [`Daemon::route`](super::Daemon::route) receives it and as the socket reader
/// builds it — one value rather than a list of arguments, so the two
/// `Option<String>`s cannot be handed over in the wrong order.
///
/// PRECONDITION on every field, established by [`super::http::read_request`] and owed by
/// any other caller of [`Daemon::route`](super::Daemon::route): `method` is the uppercase token;
/// `path` is the request target with its query AND its `?` removed; `query`
/// is what followed that `?`, without it; `session_token` and `origin` are
/// the `Skepd-Session` and `Origin` header values VERBATIM, or `None` when
/// the header is absent — never normalized and never defaulted; `peer` is
/// the transport's own answer about the remote address of THIS connection;
/// `body` is exactly the declared `Content-Length` bytes, and at most
/// [`body_cap`](super::body_cap) of `path` of them.
///
/// Routing re-checks none of them — it cannot tell a caller's mistake from a
/// client's request — and what a violation costs is not uniform. The first
/// three and the last are answered honestly for the request as given and
/// misleadingly for the one intended: a `path` still carrying its query is
/// an unknown path (`404`), a lowercase `method` matches no arm (`405`), a
/// `query` still carrying its `?` names a parameter called `?since`.
/// `origin` and `peer` are different in kind: a violation there is a SILENT
/// WIDENING of the one privilege this daemon grants without a signature. An
/// absent `origin` reads as "no `Origin` header", which
/// [`crate::auth::session::bare_bind_allowed`] admits, so a caller that
/// does not forward the header removes the daemon-side fence; and a `peer`
/// reported `Loopback` for a socket that is not one hands the bare bind to
/// the network.
///
/// The body cap is the OUTERMOST bound on what a frame allocates, and the
/// one clause a caller cannot discharge by inspection: every JSON-carrying
/// route builds the whole `serde_json` tree before any codec cap runs, so a
/// body admitted past it buys roughly twenty times its size in transient
/// heap — for a frame the codec is then about to refuse. [`super::http::read_request`]
/// enforces it on the declared `Content-Length`, before a byte is read.
///
/// `Clone`, because this is the value a caller BUILDS, and the precondition
/// above is why it builds one per probe rather than mutating a template:
/// every field is a fact about ONE request. A caller varying one across a
/// table would otherwise spell all seven per row. Deliberately no
/// `Default`, for the same reason — an empty method and path are not a
/// request — and no `PartialEq`, nothing here comparing two requests.
#[derive(Clone)]
pub struct HttpRequest {
    /// The method token, uppercase ASCII (`GET`, `POST`, `OPTIONS`).
    pub method: String,
    /// The request target with any query stripped — `/op`, `/changes`.
    pub path: String,
    /// The raw query string, if the target carried one, without the `?` that
    /// introduced it. Meaningful on `/changes` and `/dump`; ignored
    /// elsewhere.
    pub query: Option<String>,
    /// The `Skepd-Session` header's value, if present: the opaque token a
    /// session was bound to. Absent or unknown resolves to the guest.
    pub session_token: Option<String>,
    /// The `Origin` header's value verbatim, if present — the bare arm's
    /// per-request origin check reads it; `Origin: null` arrives as the
    /// literal string and parses to nothing.
    pub origin: Option<String>,
    /// The TCP peer's loopback-ness — established by the accept path from
    /// the socket's peer address. A caller routing over its own transport
    /// supplies it, and takes it from [`Peer::of`] rather than deriving it:
    /// that is this daemon's own rule, and the paragraph above says what
    /// getting it wrong costs. A transport with no address at all — a Unix
    /// socket — names the variant it means.
    pub peer: Peer,
    /// The body, exactly `Content-Length` bytes (empty when absent).
    pub body: Vec<u8>,
}

/// The body's LENGTH and the token's PRESENCE: the body runs to the route's
/// [`body_cap`](super::body_cap), and the token names a live session, which is not a thing to
/// leave in a log line.
impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("session_token", &self.session_token.as_ref().map(|_| "<token>"))
            .field("origin", &self.origin)
            .field("peer", &self.peer)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A query string as its parameter list — `k=v` pairs split on `&`, shape
/// checked and nothing else. Every query this daemon reads walks this, so
/// one discipline covers them all and each parser adds only its own
/// vocabulary: an unknown or repeated parameter is a named refusal, which
/// is the wire's never-silent posture applied to queries.
pub(super) fn query_pairs(query: &str) -> Result<Vec<(&str, &str)>, String> {
    query
        .split('&')
        .map(|pair| pair.split_once('=').ok_or_else(|| format!("malformed parameter '{pair}'")))
        .collect()
}

/// A field that may appear at most ONCE — the never-silent rule applied to
/// repeats, shared by the request head's headers and by every query this
/// daemon reads, so a duplicate is a named refusal rather than a last-wins
/// nobody chose. `field_kind` is the wire's word for the kind of field —
/// `"header"` or `"parameter"` — which is all the header reader and the
/// query parsers differ by.
///
/// One home because the alternative is one literal name per field, kept in
/// step with the field it guards by inspection alone: a `since.is_some()`
/// left standing in the `limit` arm accepts a repeated `limit` and refuses a
/// `limit` that follows a `since`, and the shape compiles either way.
pub(super) fn at_most_once<T>(
    seen: &Option<T>,
    field_kind: &str,
    name: &str,
) -> Result<(), String> {
    match seen {
        Some(_) => Err(format!("duplicate {field_kind} '{name}'")),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
