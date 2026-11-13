//! The registry walk over this crate's one dialer.
//!
//! This crate implements `skep_resolve::Transport` over its `Dialer`
//! (`client.md` §1.1's dependency paragraph), so the shell dials the board
//! the registry names and never one the serving board's word names (P25),
//! and no cycle forms and no second trait is minted. The registry answers
//! the board and never an account's set: the reader's verifier takes no key
//! set from it (`verify`'s row).
//!
//! **The mirror's dial.** A registry mirror reaches the root its hint names
//! through this crate's dialer, an `https` root and an `http` one alike
//! ([`mirror_dial`]; REG-3.2, REG-3.12): the resolver links no TLS library,
//! so this dialer's `tls` arm is the one `https` path a mirror has, and an
//! `http` root rides the same dialer rather than the resolver's own client —
//! one transport, one set of bounds and one error map for both schemes
//! (`client.md` §1.1: one outbound dialer). A build without `tls` refuses an
//! `https` root by name, [`TransportError::NotHeld`], as the resolver's own
//! client does.
//!
//! **The bounds are the resolver's.** A mirror's reads keep the two bounds
//! the resolver's own client reads under, never a frame's
//! ([`mirror_dialer`]): each read and write within a minute, since a feed
//! page on a large board outlasts a frame's bound, and no answer read past
//! the feed's page byte budget and its envelope. The cap decides what a
//! mirror folds — a typed read takes an answer past it as one it cannot
//! read — so it is held at two places: the mirror's dialer reads no further
//! than it, and this transport refuses a body past it whichever dialer
//! carried it.

use std::sync::Arc;
use std::time::Duration;

use skep_address::Address;
use skep_resolve::{BoardError, GuestCost, Method, Resolution, SystemResolver, Transport, TransportError, Transports};

use crate::dial::{DialError, Dialer, PlainHttp, Request};
use crate::origin::{NotCanonical, Origin};

/// The per-call read/write bound of a mirror's exchange.
///
/// It is the resolver's own, `skep-resolve`'s `http::IO_TIMEOUT`: a page of
/// the feed or a historical read is seconds on a loaded board, and a minute
/// is headroom. The crate keeps the figure private, so it is spelled again
/// here and this module's suite holds the two equal.
const RESOLVER_IO_TIMEOUT: Duration = Duration::from_secs(60);

/// The most bytes the resolver reads of one answer.
///
/// It is the resolver's own, `skep-resolve`'s `http::MAX_ANSWER_BYTES`: a
/// feed page at the page byte budget, 2 MiB, and 4 KiB for the head and the
/// page's envelope (wire.md §The change feed, Paging). Spelled again here
/// for the same reason, and held equal the same way.
const RESOLVER_ANSWER_CAP: usize = 2 * 1024 * 1024 + 4 * 1024;

/// `skep_resolve::Transport` over one `Dialer` at one origin.
///
/// An answer whose body runs past the resolver's answer cap is
/// [`TransportError::TooLarge`], whichever dialer read it.
pub struct DialerTransport {
    dialer: Arc<dyn Dialer>,
    origin: Origin,
}

impl std::fmt::Debug for DialerTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DialerTransport({})", self.origin)
    }
}

impl DialerTransport {
    /// Returns the transport for `origin` through `dialer`.
    pub fn new(dialer: Arc<dyn Dialer>, origin: Origin) -> DialerTransport {
        DialerTransport { dialer, origin }
    }
}

impl Transport for DialerTransport {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let method = match method {
            Method::Get => crate::dial::Method::Get,
            Method::Post => crate::dial::Method::Post,
        };
        let req = Request { method, path: path.to_string(), headers: Vec::new(), body: body.to_vec() };
        let resp = self.dialer.exchange(&self.origin, &req).map_err(transport_error)?;
        if resp.body.len() > RESOLVER_ANSWER_CAP {
            return Err(TransportError::TooLarge { cap: RESOLVER_ANSWER_CAP });
        }
        Ok((resp.status, resp.body))
    }
}

/// Returns the resolver's class for a dial that failed.
///
/// One class decides what the resolver does: an answer past the cap,
/// [`TransportError::TooLarge`], is one a typed read takes as its own
/// cannot-read (`skep_resolve::Board`), so it is kept exactly. The rest a
/// mirror names beside each origin it tried, told apart by type, and each
/// keeps its side of this crate's line: an answer the board gave
/// ([`DialError::answered`]) is [`TransportError::Response`] or
/// [`TransportError::TooLarge`], and nothing else is.
///
/// - [`DialError::NotHeld`] is [`TransportError::NotHeld`]: no `tls` arm in
///   this build, and no board reached.
/// - [`DialError::Resolve`] is [`TransportError::Resolve`].
/// - [`DialError::Connect`] and [`DialError::Tls`] are
///   [`TransportError::Connect`]: no connection was made and no byte of the
///   request left — refused, unreachable or past the connect bound, a TLS
///   handshake broken off or past its bound, or a peer the TLS layer
///   refused, an untrusted certificate among them, its text led by `tls:`.
/// - [`DialError::Timeout`], [`DialError::Io`], [`DialError::Truncated`] and
///   [`DialError::Request`] are [`TransportError::Io`], the request not
///   written or the response not read whole: a read or a write past its
///   bound once connected (a board gone silent), a connection closed before
///   the answer's head or its declared body was whole (a board that hung
///   up), and a request this dialer would not write.
/// - [`DialError::Response`] is [`TransportError::Response`]: bytes that are
///   no HTTP response.
/// - [`DialError::TooLarge`] is [`TransportError::TooLarge`], its cap the
///   dialer's.
///
/// The match names every class and has no wildcard arm, so a class the
/// dialer gains is placed here before the crate builds.
fn transport_error(e: DialError) -> TransportError {
    match e {
        DialError::NotHeld(scheme) => TransportError::NotHeld(scheme),
        DialError::Resolve(text) => TransportError::Resolve(text),
        DialError::Connect(text) => TransportError::Connect(text),
        DialError::Tls(text) => TransportError::Connect(format!("tls: {text}")),
        DialError::Timeout(text) => TransportError::Io(format!("timed out: {text}")),
        DialError::Io(text) => TransportError::Io(text),
        truncated @ DialError::Truncated { .. } => TransportError::Io(truncated.to_string()),
        DialError::Request(text) => TransportError::Io(format!("malformed request: {text}")),
        DialError::Response(text) => TransportError::Response(text),
        DialError::TooLarge { cap } => TransportError::TooLarge { cap },
    }
}

/// The resolver's `Origin` as this crate's, where the two grammars agree.
///
/// Both reproduce the daemon's (AUTH-4.2); [`NotCanonical`] where they
/// diverge.
impl TryFrom<&skep_resolve::Origin> for Origin {
    type Error = NotCanonical;

    fn try_from(o: &skep_resolve::Origin) -> Result<Origin, NotCanonical> {
        o.as_str().parse()
    }
}

/// Returns a `Dial` for `skep_resolve::Mirror` over `dialer`.
///
/// It has the shipped dial's shape, this crate's transport behind it. Every
/// origin rides `dialer`, an `https` one and an `http` one alike, and the
/// per-call bound is `dialer`'s own: [`mirror_dial`] is this over the dialer
/// that keeps the resolver's.
pub fn dial(dialer: Arc<dyn Dialer>) -> impl Fn(&skep_resolve::Origin) -> Result<Box<dyn Transport>, TransportError> {
    move |o: &skep_resolve::Origin| {
        let origin = Origin::try_from(o).map_err(|_| TransportError::Response(format!("{o} is not a canonical origin here")))?;
        Ok(Box::new(DialerTransport::new(dialer.clone(), origin)) as Box<dyn Transport>)
    }
}

/// Returns the dialer a registry mirror's reads go through.
///
/// It is [`PlainHttp`] under the resolver's two bounds in a frame's place:
/// each read and each write within a minute, and no answer read past the
/// resolver's answer cap — the bytes on the wire counted, the head with the
/// body, as the resolver's own client counts them. Its exchange is held to
/// this crate's deadline besides, made from those two bounds, which the
/// resolver's own client does not keep.
pub fn mirror_dialer() -> PlainHttp {
    PlainHttp::bounded(RESOLVER_IO_TIMEOUT, RESOLVER_ANSWER_CAP)
}

/// Returns the `Dial` a registry mirror opens through.
///
/// It is [`dial`] over [`mirror_dialer`]: the path an `https` root takes,
/// where the build holds the `tls` arm, and the path an `http` root takes
/// too (REG-3.2: a hint may name both).
pub fn mirror_dial() -> impl Fn(&skep_resolve::Origin) -> Result<Box<dyn Transport>, TransportError> {
    dial(Arc::new(mirror_dialer()))
}

/// Resolves `prefix` as a guest reader over the registry board at `registry`.
///
/// It is a reader with no mirror (REG-3.24, REG-3.33), its verdicts
/// `UndeterminableHere` — `resolve(prefix)` → the board's endpoint as a
/// named state, priced.
///
/// # Errors
///
/// The walk's [`BoardError`], where the registry board refuses or cannot
/// answer a read its scan makes.
pub fn guest_resolve(dialer: Arc<dyn Dialer>, registry: &Origin, prefix: &Address) -> Result<(Resolution, GuestCost), BoardError> {
    let board = skep_resolve::Board::new(Box::new(DialerTransport::new(dialer, registry.clone())));
    skep_resolve::guest_resolve(&board, prefix, &SystemResolver, &Transports::default())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;
    use crate::board::fake::Fake;
    use crate::dial::{Headers, RequestHead, Response, StreamedResponse};

    /// The resolver's origin converts where the two grammars agree.
    ///
    /// Its text is kept byte for byte.
    #[test]
    fn a_resolver_origin_converts_to_this_crates() {
        for text in ["http://127.0.0.1:8642", "https://board.example", "http://[::1]:8642"] {
            let theirs = skep_resolve::Origin::parse(text).expect("canonical to the resolver");
            assert_eq!(Origin::try_from(&theirs).map(|o| o.as_str().to_string()), Ok(text.to_string()));
        }
    }

    /// The transport is this crate's one dialer and adds nothing (P25).
    ///
    /// The resolver's request reaches the dialer at the transport's own
    /// origin — method, path and body as the resolver framed them, no header
    /// added — and the dialer's status and body come back as they were
    /// answered.
    #[test]
    fn the_transport_carries_the_resolvers_request_to_its_own_origin() {
        let fake = Fake::new(|_| Response { status: 418, headers: Headers(vec![("X-Board".into(), "registry".into())]), body: b"teapot".to_vec() });
        let registry = Origin::parse("https://registry.example").unwrap();
        let transport = DialerTransport::new(fake.clone(), registry.clone());
        assert_eq!(transport.exchange(Method::Post, "/op", br#"{"op":"health"}"#), Ok((418, b"teapot".to_vec())));
        assert_eq!(transport.exchange(Method::Get, "/health", b""), Ok((418, b"teapot".to_vec())));
        let sent = fake.sent.lock().unwrap();
        let expected = [
            Request { method: crate::dial::Method::Post, path: "/op".into(), headers: Vec::new(), body: br#"{"op":"health"}"#.to_vec() },
            Request { method: crate::dial::Method::Get, path: "/health".into(), headers: Vec::new(), body: Vec::new() },
        ];
        assert_eq!(sent.iter().map(|(origin, _)| origin).collect::<Vec<_>>(), [&registry, &registry]);
        assert_eq!(sent.iter().map(|(_, req)| req.clone()).collect::<Vec<_>>(), expected);
    }

    /// The dial carries both schemes through the one dialer.
    ///
    /// An `https` origin and an `http` one each get this crate's transport,
    /// and each exchange reaches the dialer at its own origin (the mutant
    /// that hands an `https` origin to the resolver's own client refuses it
    /// unheld, and the one that hands it an `http` origin dials past the
    /// dialer).
    #[test]
    fn the_dial_carries_an_https_origin_and_an_http_one_through_the_one_dialer() {
        let fake = Fake::new(|_| Response { status: 200, headers: Headers::default(), body: b"{}".to_vec() });
        let dial = dial(fake.clone());
        let origins = ["https://registry.example", "http://127.0.0.1:8642"];
        for text in origins {
            let transport = dial(&skep_resolve::Origin::parse(text).unwrap()).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(transport.exchange(Method::Get, "/health", b""), Ok((200, b"{}".to_vec())), "{text}");
        }
        let dialed: Vec<String> = fake.sent.lock().unwrap().iter().map(|(origin, _)| origin.as_str().to_string()).collect();
        assert_eq!(dialed, origins);
    }

    /// A dialer that refuses every exchange with one error.
    struct Refusing(DialError);

    impl Dialer for Refusing {
        fn exchange(&self, _: &Origin, _: &Request) -> Result<Response, DialError> {
            Err(self.0.clone())
        }

        fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
            unreachable!("the resolver streams nothing")
        }
    }

    /// Every class of a failed dial is the resolver's class of the same side.
    ///
    /// One row per class, in the order of the row index below, whose match
    /// has no wildcard arm: a class the dialer gains is a row here before
    /// this builds. An answer the board gave stays one and nothing else
    /// becomes one (the mutant that names a read past its bound a failed
    /// connection, as the map did before the dialer told the two apart,
    /// reports a board that took the request as one never reached).
    #[test]
    fn every_class_of_a_failed_dial_is_the_resolvers_class_of_the_same_side() {
        let row = |e: &DialError| match e {
            DialError::NotHeld(_) => 0,
            DialError::Resolve(_) => 1,
            DialError::Connect(_) => 2,
            DialError::Tls(_) => 3,
            DialError::Timeout(_) => 4,
            DialError::Io(_) => 5,
            DialError::Truncated { .. } => 6,
            DialError::Request(_) => 7,
            DialError::Response(_) => 8,
            DialError::TooLarge { .. } => 9,
        };
        let cells = [
            (DialError::NotHeld("https".into()), TransportError::NotHeld("https".into())),
            (DialError::Resolve("r".into()), TransportError::Resolve("r".into())),
            (DialError::Connect("c".into()), TransportError::Connect("c".into())),
            (DialError::Tls("t".into()), TransportError::Connect("tls: t".into())),
            (DialError::Timeout("s".into()), TransportError::Io("timed out: s".into())),
            (DialError::Io("i".into()), TransportError::Io("i".into())),
            (DialError::Truncated { declared: 5, got: 2 }, TransportError::Io("truncated body (2 of 5 bytes) — the connection broke".into())),
            (DialError::Request("q".into()), TransportError::Io("malformed request: q".into())),
            (DialError::Response("p".into()), TransportError::Response("p".into())),
            (DialError::TooLarge { cap: 7 }, TransportError::TooLarge { cap: 7 }),
        ];
        assert_eq!(cells.iter().map(|(dialed, _)| row(dialed)).collect::<Vec<_>>(), (0..10).collect::<Vec<_>>());
        let origin = Origin::parse("https://registry.example").unwrap();
        for (dialed, expected) in cells {
            let transport = DialerTransport::new(Arc::new(Refusing(dialed.clone())), origin.clone());
            let got = transport.exchange(Method::Get, "/health", b"").unwrap_err();
            assert_eq!(got, expected, "{dialed:?}");
            let an_answer = matches!(got, TransportError::Response(_) | TransportError::TooLarge { .. });
            assert_eq!(an_answer, dialed.answered(), "{dialed:?}");
        }
    }

    /// A body past the resolver's cap is too large whichever dialer read it.
    ///
    /// A dialer that reads further than the mirror's — a frame's, a fake —
    /// hands the transport a body at the cap, which it carries, and one a
    /// byte past it, which it refuses at the resolver's cap.
    #[test]
    fn a_body_past_the_resolvers_cap_is_too_large_whichever_dialer_read_it() {
        let registry = Origin::parse("https://registry.example").unwrap();
        for len in [RESOLVER_ANSWER_CAP, RESOLVER_ANSWER_CAP + 1] {
            let fake = Fake::new(move |_| Response { status: 200, headers: Headers::default(), body: vec![b'x'; len] });
            let got = DialerTransport::new(fake, registry.clone()).exchange(Method::Post, "/op", b"{}").map(|(_, body)| body.len());
            let expected = if len > RESOLVER_ANSWER_CAP { Err(TransportError::TooLarge { cap: RESOLVER_ANSWER_CAP }) } else { Ok(len) };
            assert_eq!(got, expected, "a body of {len} bytes");
        }
    }

    /// A loopback board for one connection: the request read, `answer` sent.
    fn answering(answer: Vec<u8>) -> (skep_resolve::Origin, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = skep_resolve::Origin::parse(&format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port())).unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).unwrap();
                assert!(n > 0, "the peer closed before the head's blank line");
                got.extend_from_slice(&buf[..n]);
            }
            // A reader that stops at its cap hangs up on the rest.
            let _ = s.write_all(&answer);
        });
        (origin, server)
    }

    /// The mirror's dialer reads under the resolver's own two bounds.
    ///
    /// The cap is held to the resolver's own client by behaviour: an answer
    /// of exactly the cap on the wire, head and body, is read whole by both,
    /// and one a byte longer is refused by both at the same cap. The per-call
    /// bound is held to that crate's source, which keeps the constant
    /// private (the mutant that builds the mirror's dialer as a frame's reads
    /// four times the cap, and gives up on a feed page after ten seconds).
    #[test]
    fn the_mirrors_dialer_reads_under_the_resolvers_own_two_bounds() {
        let head = |body: usize| format!("HTTP/1.1 200 OK\r\nContent-Length: {body}\r\n\r\n");
        let at_cap = RESOLVER_ANSWER_CAP - head(RESOLVER_ANSWER_CAP).len();
        assert_eq!(head(at_cap).len() + at_cap, RESOLVER_ANSWER_CAP, "the answer is the cap, to the byte");
        for body in [at_cap, at_cap + 1] {
            for client in ["the resolver's own", "this crate's"] {
                let (origin, server) = answering([head(body).into_bytes(), vec![b'x'; body]].concat());
                let transport = if client == "this crate's" { mirror_dial()(&origin) } else { skep_resolve::dial_http(&origin) };
                let got = transport.expect("an http origin is held").exchange(Method::Get, "/changes?since=0", b"").map(|(_, body)| body.len());
                server.join().unwrap();
                let expected = if body > at_cap { Err(TransportError::TooLarge { cap: RESOLVER_ANSWER_CAP }) } else { Ok(body) };
                assert_eq!(got, expected, "{client} client, {} bytes on the wire", head(body).len() + body);
            }
        }
        let theirs = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../skep-resolve/src/http.rs")).expect("the resolver's client");
        let bound = format!("const IO_TIMEOUT: Duration = Duration::from_secs({});", RESOLVER_IO_TIMEOUT.as_secs());
        assert!(theirs.contains(&bound), "skep-resolve's http.rs no longer spells `{bound}`: the two per-call bounds have parted");
        assert_eq!(mirror_dialer(), PlainHttp::bounded(Duration::from_secs(60), 2 * 1024 * 1024 + 4 * 1024));
        assert_ne!(mirror_dialer(), PlainHttp::new(), "a frame's bounds are not a mirror's");
    }
}
