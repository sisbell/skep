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
//!
//! **The root hint, read off a board.** A reader reaches a registry through
//! one line, its root hint: the registry's origins in the order they are
//! tried, then the realm, the fingerprint of the registry's genesis key set
//! (REG-3.2, REG-3.39). [`root_hint`] composes that line for a board it is
//! pointed at: it reads the board's claim and the claimant's genesis record
//! as a guest, through the read a mirror's realm check makes
//! (`skep_resolve::Mirror::read_genesis`; REG-3.42) and no other, so the
//! realm it names is the one a mirror opened from the line compares and
//! passes. The fork point of a forked lineage is the caller's to name
//! ([`fork_point`]; REG-3.40): no read answers one. What stops the read is
//! a member of this crate's halt family.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use skep_address::Address;
use skep_resolve::{BoardError, GuestCost, Method, Mirror, MirrorError, Resolution, SystemResolver, Transport, TransportError, Transports};

use crate::dial::{DialError, Dialer, PlainHttp, Request};
use crate::halt::{clipped, Halt, Refused};
use crate::origin::{NotCanonical, Origin};

/// The root hint's names, as [`root_hint`] answers them.
///
/// They are the resolver's own, named here so an embedder that holds this
/// crate alone — the `skep` command — reads the line back
/// (`RootHint::parse`), computes a realm (`RealmId::genesis_fingerprint`)
/// and reads what the genesis read found, with no dependency line of its
/// own.
pub use skep_resolve::{Genesis, RealmId, RootHint};

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

/// Parses a fork point as a root hint's `fork:` term spells one (REG-3.40).
///
/// It is the resolver's own reading of an address — the one a hint's line
/// is parsed and built under, each component a decimal natural of any size
/// within the board's own wire caps — so a fork point this admits is one
/// the line carries and reads back. `None` for any other text.
pub fn fork_point(text: &str) -> Option<Address> {
    skep_resolve::parse_address(text)
}

/// Reads a registry board's root hint off the board, as a guest.
///
/// The hint names `board` first and then each of `also`, in the order
/// given — the order a reader tries them in (REG-3.2) — then the realm, and
/// `fork` beside it where the caller names one (REG-3.40; it is never
/// inferred). The realm is read at `board` alone, through `dialer`, with no
/// key and no session: the board's first claim and the key set its
/// claimant's genesis record enrolls, fingerprinted (REG-3.39 — the genesis
/// set, never the living one), by the read a mirror's realm check makes
/// (`skep_resolve::Mirror::read_genesis`), which pages the board's feed no
/// further than the claim. An origin of `also` is taken on the caller's
/// word: it is written into the line and never dialed.
///
/// The second member is what that read found — the claim's position, the
/// claimant, the genesis fingerprint the hint carries, and the reads made.
/// A registry mirror's dialer is the one to pass ([`mirror_dialer`]): a
/// feed page outruns a frame's bounds.
///
/// # Errors
///
/// A [`Halt`], in the order they are met:
///
/// 1. A halt's face where an origin given is one the resolver's grammar
///    refuses, before any read: the two grammars reproduce the daemon's
///    one (AUTH-4.2), so this is a fault of the build.
/// 2. [`Halt::Dial`] where the board was not reached or did not answer —
///    the dial, `/health` or a later read — or answered what the wire does
///    not give.
/// 3. [`Halt::Refused`] where the board answered and refused a read: a
///    status outside the read's shape, a `rejected` answer, a board that
///    stayed busy past the retries, a feed whose start it has reclaimed.
/// 4. A halt's face naming `board` where its claim names no genesis
///    record, or the record could not be read whole: no realm can be
///    computed.
/// 5. A halt's face naming `board` where its feed ends with no claim: an
///    unclaimed board has no realm.
/// 6. A halt's face where `fork` is an address the line cannot carry — one
///    past the board's own wire caps, which [`fork_point`] never answers.
pub fn root_hint(dialer: Arc<dyn Dialer>, board: &Origin, also: &[Origin], fork: Option<Address>) -> Result<(RootHint, Genesis), Halt> {
    let listed = std::iter::once(board).chain(also).map(|origin| {
        skep_resolve::Origin::parse(origin.as_str()).ok_or_else(|| {
            Halt::face(
                format!("the origin {origin} is one this build's resolver does not read as canonical"),
                "the client's origin grammar and the resolver's both reproduce the daemon's (AUTH-4.2), and here they part",
                "this is a fault of this build: report it with the origin",
            )
        })
    });
    let listed: Vec<skep_resolve::Origin> = listed.collect::<Result<_, Halt>>()?;
    let genesis = Mirror::read_genesis(&listed[0], &dial(dialer)).map_err(|e| hint_halt(board, e))?;
    let hint = RootHint::new(listed, genesis.fingerprint, fork).map_err(|e| {
        Halt::face(
            format!("the root hint of the board at {board} was read and cannot be written as one line"),
            e.to_string(),
            "name the fork point as the board's own wire spells an address",
        )
    })?;
    Ok((hint, genesis))
}

/// Returns the halt a genesis read's refusal at `board` comes to.
///
/// An unclaimed board and a claim with no genesis record are states a
/// person acts on, each a face naming the board; a root that did not answer
/// is its one origin's own error, and that and every other read's refusal
/// is the family's member for it ([`board_halt`]). A class the resolver
/// names later is a face carrying its words.
fn hint_halt(board: &Origin, e: MirrorError) -> Halt {
    match e {
        MirrorError::NoClaim => Halt::face(
            format!("the board at {board} is unclaimed: it has no realm, so no root hint"),
            "a realm is the fingerprint of the key set its claimant's genesis record enrolls (REG-3.39), and this board's change feed ends with no claim",
            "claim the board (`skep claim`), then read its hint again",
        ),
        MirrorError::NoGenesis => Halt::face(
            format!("the claim of the board at {board} names no genesis record: no realm can be computed"),
            "no enroll record naming the claimant stands on the feed before its claim, or the one that stands could not be read whole; the realm is that record's key set and never the set the account holds now (REG-3.39)",
            "check that the origin names a skep board; a claimed board whose claimant's genesis record cannot be read is a board fault",
        ),
        MirrorError::Unreachable { mut tried } if !tried.is_empty() => board_halt(tried.swap_remove(0).1),
        MirrorError::Board(e) => board_halt(e),
        other => Halt::face(format!("the root hint of the board at {board} was not read"), other.to_string(), "read it again; where it stops here again, report it with these words"),
    }
}

/// Returns the halt family's member for a board read that failed.
///
/// A board not reached, or one whose answer the wire does not give, is
/// transport ([`Halt::Dial`]); a board that answered and refused is its
/// refusal ([`Halt::Refused`]): a status outside the read's shape under the
/// `error` its body names (this client's `http_error` where it names none,
/// its detail then the body, clipped), a `rejected` answer under its own
/// code, a board busy past the retries as the `503` it answered, and a
/// reclaimed feed as the wire's `410 history_reclaimed`, its detail the
/// floor.
fn board_halt(e: BoardError) -> Halt {
    let refused = |status: u16, code: &str, detail: Option<String>, op: Option<String>, body: Value| {
        Halt::Refused(Refused { status, code: code.to_string(), detail, op, body })
    };
    match e {
        BoardError::Transport(e) => Halt::Dial(dial_error(e)),
        BoardError::Malformed(what) => Halt::Dial(DialError::Response(what)),
        BoardError::Status { status, body } => {
            let answer: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let detail = match answer["detail"].as_str() {
                Some(detail) => Some(detail.to_string()),
                None if answer["error"].is_string() => None,
                None => Some(clipped(&body, MAX_BODY_SAID).to_string()),
            };
            let code = answer["error"].as_str().unwrap_or("http_error").to_string();
            refused(status, &code, detail, None, answer)
        }
        BoardError::Rejected { op, code, detail } => refused(200, &code, detail, Some(op), Value::Null),
        BoardError::Busy => refused(503, "http_error", Some(BoardError::Busy.to_string()), None, Value::Null),
        BoardError::Reclaimed { floor } => {
            let detail = floor.map(|floor| format!("the oldest position still answerable is {floor}"));
            refused(410, "history_reclaimed", detail, None, Value::Null)
        }
        other => Halt::Dial(DialError::Response(other.to_string())),
    }
}

/// The most bytes of a board's answer a refusal's detail says.
///
/// A status outside a read's shape carries the body as served, which the
/// board sizes: a face is read by a person.
const MAX_BODY_SAID: usize = 200;

/// Returns this crate's class for a resolver transport's error.
///
/// It is [`transport_error`] read the other way, class for class, so a read
/// the resolver made over this crate's dialer halts under the class the
/// dialer named: the text keeps what the map folded into it — a TLS
/// refusal's `tls:` lead under [`DialError::Connect`], a bound run past
/// under [`DialError::Io`]. A class the resolver names later is an answer
/// the wire does not give.
fn dial_error(e: TransportError) -> DialError {
    match e {
        TransportError::NotHeld(scheme) => DialError::NotHeld(scheme),
        TransportError::Resolve(text) => DialError::Resolve(text),
        TransportError::Connect(text) => DialError::Connect(text),
        TransportError::Io(text) => DialError::Io(text),
        TransportError::Response(text) => DialError::Response(text),
        TransportError::TooLarge { cap } => DialError::TooLarge { cap },
        other => DialError::Response(other.to_string()),
    }
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
