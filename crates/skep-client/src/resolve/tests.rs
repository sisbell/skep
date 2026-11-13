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

/// Every class of the resolver's transport error is this crate's own.
///
/// One row per class the resolver names, read back the way the mirror's
/// transport lowers a dial: a transport this build does not hold, a name
/// that did not resolve, a connection never made, an exchange broken off,
/// bytes that are no response and an answer past the cap each keep their
/// class and their words, and a board read that failed in any of them halts
/// as transport, exit 4 (the mutant that names a broken exchange a
/// malformed answer reports a board that hung up as one that answered).
#[test]
fn every_class_of_the_resolvers_transport_error_is_this_crates_own() {
    let cells = [
        (TransportError::NotHeld("https".into()), DialError::NotHeld("https".into())),
        (TransportError::Resolve("r".into()), DialError::Resolve("r".into())),
        (TransportError::Connect("c".into()), DialError::Connect("c".into())),
        (TransportError::Io("i".into()), DialError::Io("i".into())),
        (TransportError::Response("p".into()), DialError::Response("p".into())),
        (TransportError::TooLarge { cap: 7 }, DialError::TooLarge { cap: 7 }),
    ];
    for (theirs, ours) in cells {
        assert_eq!(dial_error(theirs.clone()), ours, "{theirs:?}");
        let halt = board_halt(BoardError::Transport(theirs.clone()));
        assert_eq!(halt, Halt::Dial(ours), "{theirs:?}");
        assert_eq!(halt.exit_code(), 4, "{theirs:?}");
    }
}

fn a(text: &str) -> Address {
    global_address(text).unwrap_or_else(|| panic!("{text} is an address"))
}

/// A cross-board address is read as the wire spells one.
///
/// A component of any size reads, and a leading zero names its one address;
/// a sign, an empty component and a tumbler that is no address are none
/// (the mutant that reads it by this crate's own address parse admits the
/// signed one).
#[test]
fn a_cross_board_address_is_read_as_the_wire_spells_one() {
    assert_eq!(a("1.05.0.1.0.2"), a("1.5.0.1.0.2"), "a leading zero names its one address");
    assert_eq!(a("1.18446744073709551616.0.1").to_string(), "1.18446744073709551616.0.1", "a component past a machine word");
    for none in ["", "+1.5.0.1", "1.5.0.+1", "1..5", "1.5.0", "0.1", "1.5.0.0.1", "one.5"] {
        assert_eq!(global_address(none), None, "{none:?}");
    }
    assert!(crate::address::parse_address("+1.5.0.1").is_some(), "the control: this crate's own parse reads a sign");
}

/// The prefix is the node field whole, and the local form swaps it for `1`.
///
/// An address's node field is the prefix resolved (REG-1.62), at any depth
/// and never cut another way; the same address with that field swapped for
/// `1` is its local form (REG-1.63), whatever lies past the node field — an
/// account, a document, an element; and a bare prefix has no local form
/// (the mutants that resolve the whole address, and that leave the local
/// form the global address, fail here).
#[test]
fn the_prefix_is_the_node_field_whole_and_the_local_form_swaps_it_for_one() {
    let rows = [
        ("1.5.0.1.0.2", "1.5", Some("1.0.1.0.2")),
        ("1.5.0.1", "1.5", Some("1.0.1")),
        ("1.5.0.7.0.1.0.2.9", "1.5", Some("1.0.7.0.1.0.2.9")),
        ("1.5.3.0.7.0.1.3.0.1.4", "1.5.3", Some("1.0.7.0.1.3.0.1.4")),
        ("1.5", "1.5", None),
        ("1.5.3", "1.5.3", None),
        ("1", "1", None),
        ("1.0.1.0.2", "1", Some("1.0.1.0.2")),
        ("7.0.3", "7", Some("1.0.3")),
        ("1.18446744073709551616.0.1", "1.18446744073709551616", Some("1.0.1")),
    ];
    for (address, prefix, local) in rows {
        assert_eq!(prefix_of(&a(address)), a(prefix), "the prefix of {address}");
        assert_eq!(local_form(&a(address)), local.map(a), "the local form of {address}");
    }
}

fn fingerprint(pair: &str) -> Fingerprint {
    Fingerprint::parse_hex(&pair.repeat(32)).expect("64 hex")
}

fn hint(origins: &[&str], genesis: &str, fork: Option<&str>) -> RootHint {
    let origins = origins.iter().map(|o| skep_resolve::Origin::parse(o).expect("canonical")).collect();
    RootHint::new(origins, fingerprint(genesis), fork.map(a)).expect("a hint")
}

/// A mirror's home is keyed by the hint's genesis fingerprint.
///
/// It is `registry/<64 lowercase hex>` under the store, so two hints of one
/// genesis — another root, a fork point beside it — name one directory, and
/// a hint of another genesis names another (the mutant that keys it by the
/// hint's line gives a moved root a second copy).
#[test]
fn a_mirrors_home_is_keyed_by_the_hints_genesis_fingerprint() {
    let store = Path::new("/store");
    let home = mirror_home(store, &hint(&["https://registry.example"], "ab", None));
    assert_eq!(home, Path::new("/store/registry").join("ab".repeat(32)));
    assert_eq!(mirror_home(store, &hint(&["https://moved.example", "http://127.0.0.1:8642"], "ab", None)), home, "a root moved");
    assert_eq!(mirror_home(store, &hint(&["https://registry.example"], "ab", Some("1.0.1.0.1.0.2.9"))), home, "a fork point beside it");
    assert_ne!(mirror_home(store, &hint(&["https://registry.example"], "cd", None)), home, "another genesis");
}

/// The words of a halt, whichever member it is.
fn words(halt: &Halt) -> String {
    match halt {
        Halt::Halt(face) => format!("{} / {} / {}", face.state, face.cause, face.act),
        other => other.to_string(),
    }
}

/// The directory a halt's face names beside its words.
fn path_of(halt: &Halt) -> Option<&Path> {
    match halt {
        Halt::Halt(face) => face.path.as_deref(),
        _ => None,
    }
}

/// Every refusal of a mirror comes to its member of the halt family.
///
/// A root that did not answer is its first root's own halt, by cause:
/// transport, exit 4, where it was not reached, and the board's refusal,
/// exit 1, where it answered and refused — the hint's further roots named
/// beside it, each with its own error, save where the first's member
/// carries no words. A read the board refused past `/health` is the same
/// two. Every other refusal is exit 3: the copy not read, the root not
/// answering for it and a realm that is another's each name the directory
/// beside their words and never in them, and an unclaimed board and a claim
/// with no genesis record name the hint's roots.
#[test]
fn every_refusal_of_a_mirror_comes_to_its_member_of_the_halt_family() {
    let dir = Path::new("/store/registry/abab");
    let two = hint(&["http://127.0.0.1:1", "https://second.example"], "ab", None);
    let (first, second) = (two.origins()[0].clone(), two.origins()[1].clone());
    let down = || BoardError::Transport(TransportError::Connect("skepd at http://127.0.0.1:1: connect: refused".into()));
    let unreachable = |tried: Vec<(skep_resolve::Origin, BoardError)>| mirror_halt(&two, dir, MirrorError::Unreachable { tried });
    let also = "; the hint's further roots did not answer either — https://second.example: status 503: {\"error\":\"index_failed\"}";
    let busy = || BoardError::Status { status: 503, body: "{\"error\":\"index_failed\"}".into() };

    // No root answered: the first root's own halt, the rest beside it.
    let alone = unreachable(vec![(first.clone(), down())]);
    assert_eq!(alone, Halt::Dial(DialError::Connect("skepd at http://127.0.0.1:1: connect: refused".into())));
    assert_eq!(alone.exit_code(), 4);
    let both = unreachable(vec![(first.clone(), down()), (second.clone(), busy())]);
    assert_eq!(both, Halt::Dial(DialError::Connect(format!("skepd at http://127.0.0.1:1: connect: refused{also}"))));
    for (theirs, ours) in [
        (TransportError::Resolve("r".into()), DialError::Resolve(format!("r{also}"))),
        (TransportError::Io("i".into()), DialError::Io(format!("i{also}"))),
        (TransportError::Response("p".into()), DialError::Response(format!("p{also}"))),
        (TransportError::NotHeld("https".into()), DialError::NotHeld("https".into())),
        (TransportError::TooLarge { cap: 7 }, DialError::TooLarge { cap: 7 }),
    ] {
        let halt = unreachable(vec![(first.clone(), BoardError::Transport(theirs.clone())), (second.clone(), busy())]);
        assert_eq!(halt, Halt::Dial(ours), "{theirs:?}");
    }
    let refused = unreachable(vec![(first.clone(), BoardError::Status { status: 404, body: "not found".into() }), (second.clone(), busy())]);
    assert_eq!(refused.exit_code(), 1, "the first root answered and refused: {refused}");
    assert_eq!(refused.to_string(), format!("the board refused: http_error:not found{also} (HTTP 404)"));
    let named = unreachable(vec![(first.clone(), BoardError::Status { status: 503, body: "{\"error\":\"index_failed\"}".into() }), (second.clone(), down())]);
    assert_eq!(named.to_string(), "the board refused: index_failed:the hint's further roots did not answer either — https://second.example: connect: skepd at http://127.0.0.1:1: connect: refused (HTTP 503)");

    // A read the board refused past `/health`.
    let reclaimed = mirror_halt(&two, dir, MirrorError::Board(BoardError::Reclaimed { floor: Some(40) }));
    assert_eq!((reclaimed.exit_code(), reclaimed.to_string().as_str()), (1, "the board refused: history_reclaimed:the oldest position still answerable is 40 (HTTP 410)"));
    assert_eq!(mirror_halt(&two, dir, MirrorError::Board(down())).exit_code(), 4);

    // The copy, and the realm: exit 3, the directory beside the words.
    let about_the_copy = [
        (MirrorError::Refused(Refusal::RealmMismatch { expected: fingerprint("ab"), found: fingerprint("cd") }), "the registry the root hint names is of another realm than the hint's"),
        (MirrorError::Refused(Refusal::Diverged { at: 7 }), "the registry's root does not answer for the copy held of it"),
        (MirrorError::Refused(Refusal::SourceBehind { source_head: 3, held: 9 }), "the registry's root does not answer for the copy held of it"),
        (MirrorError::Refused(Refusal::ChainDiverged { at: 9 }), "the registry's root does not answer for the copy held of it"),
        (MirrorError::Copy(format!("{}/feed.jsonl:3: expected value", dir.display())), "the registry mirror's copy could not be read or written"),
    ];
    for (refusal, state) in about_the_copy {
        let said = refusal.to_string();
        let halt = mirror_halt(&two, dir, refusal);
        assert_eq!(halt.exit_code(), 3, "{said}");
        assert_eq!(path_of(&halt), Some(dir), "{said}: the directory, beside the words");
        assert!(words(&halt).starts_with(state), "{said}: {}", words(&halt));
        assert!(!words(&halt).contains("/store"), "{said}: never in them: {}", words(&halt));
    }
    let realm = words(&mirror_halt(&two, dir, MirrorError::Refused(Refusal::RealmMismatch { expected: fingerprint("ab"), found: fingerprint("cd") })));
    assert!(realm.contains(&format!("the root's genesis fingerprint is {}, and the hint's realm names {}", "cd".repeat(32), "ab".repeat(32))), "{realm}");
    let diverged = words(&mirror_halt(&two, dir, MirrorError::Refused(Refusal::Diverged { at: 7 })));
    assert!(diverged.contains("/ the source diverges from the held journal at 7: ") && diverged.contains("move the directory aside"), "{diverged}");
    let copy = mirror_halt(&two, dir, MirrorError::Copy(format!("{}/feed.jsonl:3: expected value", dir.display())));
    assert!(matches!(&copy, Halt::Halt(face) if face.cause == "feed.jsonl:3: expected value"), "the file as it stands within the directory: {copy}");
    assert_eq!(within(dir, &format!("{}: Permission denied", dir.display())), "the directory: Permission denied");
    assert_eq!(within(Path::new(""), "feed.jsonl: gone"), "feed.jsonl: gone", "an empty directory cuts nothing");

    // No registry at the root: exit 3, the hint's roots named.
    for (refusal, state) in [
        (MirrorError::NoClaim, "the board the root hint names (http://127.0.0.1:1, https://second.example) is unclaimed: it is no registry"),
        (MirrorError::NoGenesis, "the claim of the board the root hint names (http://127.0.0.1:1, https://second.example) names no genesis record: its realm cannot be compared"),
        (MirrorError::Offline, "the registry was not read"),
        (MirrorError::Unreachable { tried: Vec::new() }, "the registry was not read"),
    ] {
        let halt = mirror_halt(&two, dir, refusal);
        assert_eq!((halt.exit_code(), path_of(&halt)), (3, None), "{halt}");
        assert!(matches!(&halt, Halt::Halt(face) if face.state == state), "{halt}");
    }
}

/// `1.5`'s standing: bound to `account`, or retired where it names none.
fn standing(account: Option<&str>) -> Standing {
    let allocation = Judged {
        position: 10,
        link: a("1.0.1.0.1.0.2.1"),
        home: a("1.0.1.0.1"),
        record: BindingRecord { prefix: a("1.5"), account: Some(a("1.0.2")), replaces: None, honored: true },
        verdict: Verdict::Signed(fingerprint("ab")),
    };
    let retirement = Judged {
        position: 20,
        link: a("1.0.1.0.1.0.2.2"),
        record: BindingRecord { prefix: a("1.5"), account: None, replaces: Some(a("1.0.1.0.1.0.2.1")), honored: true },
        ..allocation.clone()
    };
    match account {
        Some(_) => Standing { prefix: a("1.5"), current: allocation.clone(), history: vec![allocation] },
        None => Standing { prefix: a("1.5"), current: retirement.clone(), history: vec![allocation, retirement] },
    }
}

/// `1.0.2`'s endpoint, its members `origins` in the org's order.
fn endpoint(origins: &[&str]) -> Judged<EndpointRecord> {
    Judged {
        position: 11,
        link: a("1.0.2.0.1.0.2.1"),
        home: a("1.0.2.0.1"),
        record: EndpointRecord { origins: origins.iter().map(ToString::to_string).collect(), replaces: None, honored: true, nullified: false },
        verdict: Verdict::Signed(fingerprint("cd")),
    }
}

fn origin(text: &str) -> skep_resolve::Origin {
    skep_resolve::Origin::parse(text).expect("canonical")
}

/// An answer for `address`, as a call that read the registry would give it.
fn answered(address: &str, resolution: Resolution) -> Resolved {
    let address = a(address);
    Resolved { prefix: prefix_of(&address), local: local_form(&address), address, resolution, opened: Opened::Bootstrapped, root: Some(origin("https://registry.example")), head: 42 }
}

/// BOUND is answered by one line, and by its object.
///
/// The line is the origin of the member the walk would dial and then the
/// local address, and the origin alone for a bare prefix; the object
/// carries the face's name, the address asked, the prefix, the account, the
/// binding and its history, the key set, the endpoint, the member to dial
/// and each member's outcome, with the local form — `null` for a bare
/// prefix; and a key set this reader could not read is `null`, never an
/// empty list.
#[test]
fn bound_is_answered_by_one_line_and_by_its_object() {
    let enrolled = Enrolled { key: crate::sheet::KeyFile::new(crate::sheet::Seed::fresh(), false, None, None).public, anchor: false };
    let key = Fingerprint::of(&enrolled.key).to_hex();
    let public: std::net::IpAddr = "93.184.216.34".parse().unwrap();
    let bound = |keys: Option<Vec<Enrolled>>| Resolution::Bound {
        standing: standing(Some("1.0.2")),
        keys,
        endpoint: endpoint(&["http://x.onion", "https://acme.example"]),
        dial: EndpointDial { member_index: 1, origin: origin("https://acme.example"), kind: MemberKind::Https, addresses: vec![public] },
        members: vec![
            MemberOutcome::NotDialed { origin: origin("http://x.onion"), kind: MemberKind::Onion },
            MemberOutcome::WouldDial { origin: origin("https://acme.example"), kind: MemberKind::Https, addresses: vec![public] },
        ],
    };
    let asked = answered("1.5.0.1.0.2", bound(Some(vec![enrolled.clone()])));
    assert_eq!(asked.line().as_deref(), Some("https://acme.example 1.0.1.0.2"));
    let binding = json!({ "link": "1.0.1.0.1.0.2.1", "position": 10, "home": "1.0.1.0.1", "account": "1.0.2", "replaces": null, "honored": true, "verdict": "SIGNED", "signed_by": "ab".repeat(32) });
    let expected = json!({
        "face": "BOUND",
        "address": "1.5.0.1.0.2",
        "prefix": "1.5",
        "local": "1.0.1.0.2",
        "account": "1.0.2",
        "binding": binding,
        "history": [binding],
        "keys": [{ "fingerprint": key, "anchor": false }],
        "endpoint": { "link": "1.0.2.0.1.0.2.1", "position": 11, "home": "1.0.2.0.1", "origins": ["http://x.onion", "https://acme.example"], "replaces": null, "verdict": "SIGNED", "signed_by": "cd".repeat(32) },
        "dial": { "origin": "https://acme.example", "member": 1, "kind": "https", "addresses": ["93.184.216.34"] },
        "members": [
            { "member": "http://x.onion", "outcome": "not_dialed", "kind": "onion" },
            { "member": "https://acme.example", "outcome": "would_dial", "kind": "https", "addresses": ["93.184.216.34"] },
        ],
    });
    assert_eq!(asked.object(), expected);
    let bare = answered("1.5", bound(None));
    assert_eq!(bare.line().as_deref(), Some("https://acme.example"), "a bare prefix names no place on the board");
    let object = bare.object();
    assert_eq!((&object["address"], &object["local"], &object["keys"]), (&json!("1.5"), &Value::Null, &Value::Null), "{object}");
    assert!(object.as_object().is_some_and(|o| o.contains_key("local") && o.contains_key("keys")), "said as null, never left out: {object}");
}

/// Every other face is no line, and an object naming it and its facts.
///
/// One row per face the resolver names beside BOUND, each under its own
/// name as the resolver spells it and none a line: the prefix alone where
/// nothing binds it; the retired binding with its history and its
/// successor; the bound account with the cause no endpoint dials, the term
/// that refused one and the addresses it was tested at, the kind no
/// transport is held for; the parent's own face where the hop was not made;
/// and the two faces read at a dial this crate does not make.
#[test]
fn every_other_face_is_no_line_and_an_object_naming_it_and_its_facts() {
    let bound = || standing(Some("1.0.2"));
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let refused_by_host = MemberOutcome::Refused { member: "https://loop.example".into(), term: Term::Host { yielded: vec![loopback] } };
    let parent = Resolution::BoundButUnreachable { standing: bound(), keys: None, endpoint: None, cause: Unreachable::NoEndpointYet, members: Vec::new() };
    let rows: Vec<(&str, Resolution, Value)> = vec![
        ("1.9.0.1", Resolution::Unregistered { prefix: a("1.9") }, json!({ "face": "UNREGISTERED", "address": "1.9.0.1", "prefix": "1.9" })),
        (
            "1.5.0.1",
            Resolution::RetiredWithHistory { standing: standing(None), successor: Some(Successor { account: a("1.0.7"), prefix: Some(a("1.8")) }) },
            json!({ "face": "RETIRED-WITH-HISTORY", "account": null, "successor": { "account": "1.0.7", "prefix": "1.8" } }),
        ),
        (
            "1.5.0.1",
            Resolution::RetiredWithHistory { standing: standing(None), successor: None },
            json!({ "face": "RETIRED-WITH-HISTORY", "successor": null }),
        ),
        (
            "1.5.0.1",
            Resolution::BoundButUnreachable { standing: bound(), keys: None, endpoint: None, cause: Unreachable::NoEndpointYet, members: Vec::new() },
            json!({ "face": "BOUND-BUT-UNREACHABLE", "account": "1.0.2", "cause": "no_endpoint_yet", "endpoint": null, "keys": null, "members": [] }),
        ),
        (
            "1.5.0.1",
            Resolution::BoundButUnreachable { standing: bound(), keys: None, endpoint: None, cause: Unreachable::NullifiedLast, members: Vec::new() },
            json!({ "face": "BOUND-BUT-UNREACHABLE", "cause": "nullified_last" }),
        ),
        (
            "1.5.0.1",
            Resolution::BoundButUnreachable {
                standing: bound(),
                keys: None,
                endpoint: Some(endpoint(&["https://dead.example"])),
                cause: Unreachable::DeadOrigin { member: "https://dead.example".into() },
                members: vec![MemberOutcome::Dead { origin: origin("https://dead.example") }],
            },
            json!({ "face": "BOUND-BUT-UNREACHABLE", "cause": "dead_origin", "member": "https://dead.example", "members": [{ "member": "https://dead.example", "outcome": "dead" }] }),
        ),
        (
            "1.5.0.1",
            Resolution::UnreachableByPolicy {
                standing: bound(),
                keys: None,
                endpoint: endpoint(&["http://plain.example"]),
                member: "http://plain.example".into(),
                term: Term::Scheme,
                members: vec![MemberOutcome::Refused { member: "http://plain.example".into(), term: Term::Scheme }],
            },
            json!({ "face": "unreachable-by-policy", "member": "http://plain.example", "term": "scheme", "members": [{ "member": "http://plain.example", "outcome": "refused", "term": "scheme" }] }),
        ),
        (
            "1.5.0.1",
            Resolution::UnreachableByPolicy {
                standing: bound(),
                keys: None,
                endpoint: endpoint(&["https://loop.example"]),
                member: "https://loop.example".into(),
                term: Term::Host { yielded: vec![loopback] },
                members: vec![refused_by_host],
            },
            json!({
                "face": "unreachable-by-policy",
                "member": "https://loop.example",
                "term": "host",
                "yielded": ["127.0.0.1"],
                "members": [{ "member": "https://loop.example", "outcome": "refused", "term": "host", "yielded": ["127.0.0.1"] }],
            }),
        ),
        (
            "1.5.0.1",
            Resolution::DialNotMade {
                standing: bound(),
                keys: None,
                endpoint: endpoint(&["http://x.onion"]),
                member: "http://x.onion".into(),
                kind: MemberKind::Onion,
                members: vec![MemberOutcome::NotDialed { origin: origin("http://x.onion"), kind: MemberKind::Onion }],
            },
            json!({ "face": "THE DIAL NOT MADE", "member": "http://x.onion", "kind": "onion" }),
        ),
        (
            "1.5.3.0.1",
            Resolution::HopNotMade { prefix: a("1.5.3"), parent: Box::new(parent) },
            json!({ "face": "THE HOP NOT MADE", "address": "1.5.3.0.1", "prefix": "1.5.3", "parent": { "face": "BOUND-BUT-UNREACHABLE", "prefix": "1.5", "account": "1.0.2", "cause": "no_endpoint_yet" } }),
        ),
        (
            "1.5.0.1",
            Resolution::BoundButDisclaimed { standing: bound(), asserted_prefix: "1.6".into() },
            json!({ "face": "BOUND-BUT-DISCLAIMED", "account": "1.0.2", "asserted_prefix": "1.6" }),
        ),
        (
            "1.5.0.1",
            Resolution::LiveEnforcement { standing: bound(), claimant: Some(a("1.0.1")), local_trust: false },
            json!({ "face": "the live-enforcement face", "claimant": "1.0.1", "local_trust": false }),
        ),
    ];
    for (address, resolution, members) in rows {
        let face = resolution.face();
        let asked = answered(address, resolution);
        assert_eq!(asked.line(), None, "{face}: no board is named to dial");
        let object = asked.object();
        assert_eq!(object["address"], json!(address), "{face}: {object}");
        assert!(object.get("local").is_none() && object.get("dial").is_none(), "{face}: what BOUND alone carries: {object}");
        assert!(contains(&object, &members), "{face}: {object} carries {members}");
    }
    let retired = answered("1.5.0.1", Resolution::RetiredWithHistory { standing: standing(None), successor: None }).object();
    assert_eq!(retired["history"].as_array().map(Vec::len), Some(2), "the allocation and the retirement: {retired}");
    assert_eq!((&retired["binding"]["replaces"], &retired["binding"]["account"]), (&json!("1.0.1.0.1.0.2.1"), &Value::Null), "{retired}");
    let hop = answered("1.5.3.0.1", Resolution::HopNotMade { prefix: a("1.5.3"), parent: Box::new(Resolution::Unregistered { prefix: a("1.5") }) }).object();
    assert!(hop["parent"].get("address").is_none(), "the address is the asked face's alone: {hop}");
}

/// Whether `object` holds every member of `members`, nested ones the same way.
fn contains(object: &Value, members: &Value) -> bool {
    match (object, members) {
        (Value::Object(object), Value::Object(members)) => members.iter().all(|(name, member)| object.get(name).is_some_and(|held| contains(held, member))),
        (held, member) => held == member,
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())).permissions().mode() & 0o777
}

/// An unanswered root halts as transport, and leaves no line of a copy.
///
/// The directory is made before the dial, with those above it, each `0700`,
/// and the lock and the copy's two files are born `0600` — the files empty,
/// which a mirror reads as no copy held; the halt is the dial's own, exit
/// 4, and a second call finds the directory as the first left it. Where the
/// directory cannot be made the halt names it beside its words, exit 3,
/// before any dial.
#[test]
fn an_unanswered_root_halts_as_transport_and_leaves_no_line_of_a_copy() {
    let store = tempfile::tempdir().unwrap();
    let hint = hint(&["http://127.0.0.1:1"], "ab", None);
    let dir = mirror_home(&store.path().join("store"), &hint);
    let dialed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ask = |dir: &Path| {
        let dialer = Counting { dialed: dialed.clone(), refusal: DialError::Connect("down".into()) };
        resolve_address(Arc::new(dialer), &hint, dir, &a("1.5.0.1.0.2"), &SystemResolver, &Transports::default())
    };
    for run in 1..=2 {
        assert_eq!(ask(&dir), Err(Halt::Dial(DialError::Connect("down".into()))), "run {run}");
        assert_eq!(dialed.load(std::sync::atomic::Ordering::SeqCst), run, "the root is dialed at every call");
        for name in [FEED_COPY, FETCH_CACHE] {
            assert_eq!(std::fs::read(dir.join(name)).unwrap(), b"", "{name} holds no line");
        }
        #[cfg(unix)]
        {
            for made in [store.path().join("store"), store.path().join("store/registry"), dir.clone()] {
                assert_eq!(mode(&made), 0o700, "{}", made.display());
            }
            for name in [FEED_COPY, FETCH_CACHE, MIRROR_LOCK] {
                assert_eq!(mode(&dir.join(name)), 0o600, "{name}");
            }
        }
    }
    let blocked = store.path().join("a-file");
    std::fs::write(&blocked, b"").unwrap();
    let halt = ask(&blocked.join("registry")).unwrap_err();
    assert_eq!((halt.exit_code(), path_of(&halt)), (3, Some(blocked.join("registry").as_path())), "{halt}");
    assert!(matches!(&halt, Halt::Halt(face) if face.state == "the registry mirror's directory could not be made"), "{halt}");
    assert_eq!(dialed.load(std::sync::atomic::Ordering::SeqCst), 2, "before any dial");
}

/// A dialer that counts its exchanges and refuses each with one error.
struct Counting {
    dialed: Arc<std::sync::atomic::AtomicUsize>,
    refusal: DialError,
}

impl Dialer for Counting {
    fn exchange(&self, _: &Origin, _: &Request) -> Result<Response, DialError> {
        self.dialed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(self.refusal.clone())
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        unreachable!("the resolver streams nothing")
    }
}

/// A mirror's directory is one caller's at a time.
///
/// While one call holds the directory's lock a second waits for it, and
/// takes it once the first lets go (the mutant that takes no lock lets two
/// calls write one copy at once).
#[test]
fn a_mirrors_directory_is_one_callers_at_a_time() {
    let store = tempfile::tempdir().unwrap();
    let dir = store.path().join("registry");
    let first = hold(&dir).unwrap_or_else(|h| panic!("{h}"));
    let (taken, waiting) = std::sync::mpsc::channel();
    let second = {
        let dir = dir.clone();
        thread::spawn(move || {
            let held = hold(&dir).unwrap_or_else(|h| panic!("{h}"));
            taken.send(()).unwrap();
            drop(held);
        })
    };
    assert_eq!(waiting.recv_timeout(Duration::from_millis(300)), Err(std::sync::mpsc::RecvTimeoutError::Timeout), "the second waits while the first holds");
    drop(first);
    assert_eq!(waiting.recv_timeout(Duration::from_secs(30)), Ok(()), "and takes it once the first lets go");
    second.join().unwrap();
}
