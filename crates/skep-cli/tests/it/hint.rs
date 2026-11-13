//! The seventeenth command through the binary (`skep hint`; REG-3.2).
//!
//! **The line.** A claimed board's root hint is printed as one line on
//! stdout: its origins in the order given (`--board`, then each `--also`, a
//! further origin never dialed), its realm the fingerprint of the
//! claimant's genesis key set (REG-3.39) and still that once a later key
//! makes the living set another, `--fork`'s term where it is given
//! (REG-3.40) and nowhere else, every line reading back as itself through
//! the resolver's own parse; the board read as a guest, no store made and
//! no position moved.
//!
//! **The refusals.** A line that names no board, and an origin or a fork
//! point that is not canonical, are exit 2 before any socket opens; an
//! unclaimed board and a claim that names no genesis record, exit 3; a read
//! the board refused, exit 1; one it did not answer, or answered as no
//! board does, exit 4 — each a named line on stderr with nothing on stdout.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::Path;

use serde_json::{json, Value};
use skep_client::board::Board;
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::enroll::{enroll, EnrollOptions};
use skep_client::dial::PlainHttp;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::resolve::{RealmId, RootHint};
use skep_client::sheet::Label;
use skep_client::store::{FileStore, KeyStore};
use skep_client::Origin;
use skep_identity::Fingerprint;

use crate::common::{canned, origin, s, skep, spawn, Run};

/// The account a board claimed by the notebook walk is claimed by.
const CLAIMANT: &str = "1.0.1";

/// A port nothing listens at.
///
/// A run that reaches it is exit 4, so a usage refusal judged ahead of it
/// is seen to open no socket, and a further origin naming it is seen never
/// to be dialed.
const DEAD: &str = "http://127.0.0.1:1";

/// Claims the board through the library, as `ceremonies.rs` claims its.
///
/// The store holds the device key, and the anchors' files stand under
/// `anchors`.
fn claim_board(board_origin: &str, store: &Path, anchors: &Path) {
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let store = FileStore::open(store);
    store.generate(Some(Label::new("notebook").unwrap())).unwrap();
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions { principal: None, display_name: Some("a name".into()), anchor_out: vec![anchors.join("a"), anchors.join("b")], paper: false, host_name: "testhost".into(), date: "2026-11-12".into() };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, &store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
}

/// Returns the keys the claimant holds now, as the board's fold answers.
///
/// The read is a guest's `key_set`, which the printer never makes, so the
/// realm these fingerprint to is the test's own figure and none of the
/// command's.
fn living_set(board_origin: &str) -> Vec<Fingerprint> {
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let answer = board.guest(&json!({ "op": "key_set", "account": CLAIMANT })).unwrap_or_else(|h| panic!("{h}"));
    answer["enrolled"].as_array().expect("enrolled").iter().map(|e| Fingerprint::parse_hex(e["fingerprint"].as_str().expect("a fingerprint")).expect("64 hex")).collect()
}

/// Returns the board's committed head: its position and its chain.
fn head(board_origin: &str) -> (u64, Value) {
    let health = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new()).health().unwrap_or_else(|h| panic!("{h}"));
    (health.log_position(), health.body["chain_head"].clone())
}

/// Returns one run's stdout, read as the one line.
///
/// The run is exit 0, and its stdout one line and its newline, nothing
/// beside it.
fn line(r: &Run) -> &str {
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.out.lines().count(), 1, "one line on stdout and nothing else: {:?}", r.out);
    assert!(r.out.ends_with('\n'), "{:?}", r.out);
    r.out.trim_end_matches('\n')
}

/// Checks a refusal: its exit code and the line it is named by on stderr.
///
/// Its stdout holds nothing — never a partial line.
fn refused(r: &Run, code: i32, named: &str) {
    assert_eq!(r.code, code, "{r:?}");
    assert!(r.err.contains(named), "named {named:?}: {}", r.err);
    assert_eq!(r.out, "", "a refusal prints nothing on stdout: {r:?}");
}

/// Returns the origin of a board that is no daemon, answering by `route`.
///
/// `route` takes a request's line and its body and answers a status and a
/// body; each request is one connection, read through the body its
/// `Content-Length` declares. What a board no conforming daemon is can say,
/// a test says through it.
fn answering(route: impl Fn(&str, &str) -> (u16, String) + Send + 'static) -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("the scripted board's port");
    let board = origin(listener.local_addr().expect("the scripted board's address").port());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let (mut seen, mut buf) = (Vec::new(), [0u8; 8192]);
            let body_at = loop {
                if let Some(head_len) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(head_len + 4);
                }
                match conn.read(&mut buf) {
                    Ok(n @ 1..) => seen.extend_from_slice(&buf[..n]),
                    _ => break None,
                }
            };
            let Some(body_at) = body_at else { continue };
            let head = String::from_utf8_lossy(&seen[..body_at]).into_owned();
            let declared: usize =
                head.lines().find_map(|l| l.split_once(':').filter(|(name, _)| name.eq_ignore_ascii_case("content-length")).and_then(|(_, n)| n.trim().parse().ok())).unwrap_or(0);
            while seen.len() - body_at < declared {
                match conn.read(&mut buf) {
                    Ok(n @ 1..) => seen.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            let (status, body) = route(head.lines().next().unwrap_or_default(), &String::from_utf8_lossy(&seen[body_at..]));
            let answer = format!("HTTP/1.1 {status} scripted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = conn.write_all(answer.as_bytes());
            let _ = conn.shutdown(Shutdown::Write);
        }
    });
    board
}

/// Checks that `skep hint` prints a claimed board's root hint as one line.
///
/// The line is the board's origin, then `realm:` and the fingerprint of the
/// claimant's genesis key set — the figure this test makes from the board's
/// own `key_set` while no later key stands — and the resolver's parse reads
/// it back as itself. `--also` writes each further origin after the board's
/// in the order given (the two orders print two lines), one of them a port
/// nothing listens at, so none is dialed, which the talk says; `--fork`
/// adds the fork term, and no run without it carries one; `SKEP_BOARD`
/// names the board where no flag does. The help says what the line is for:
/// the line a reader is given to find the registry, and a setting the
/// reader can change (REG-3.2).
///
/// The realm is the genesis set's, never the living one's (REG-3.39): once
/// a second device is enrolled the living set fingerprints to another
/// realm, and the command prints the line it printed before (the mutant
/// that fingerprints the living set prints the other). The board is read as
/// a guest: no store is made where `--dir` names none, and the board's head
/// stands where it stood.
#[test]
fn hint_prints_the_origins_in_order_the_genesis_realm_and_the_fork_as_one_line_that_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    claim_board(&board, &store, &dir.path().join("anchors"));
    let genesis = living_set(&board);
    assert_eq!(genesis.len(), 3, "the ceremony's genesis: the device key and the two anchors");
    let realm = RealmId::genesis_fingerprint(&genesis);
    let before = head(&board);
    let no_store = dir.path().join("no-store");

    // The help says what the line is for (REG-3.2).
    let help = skep(&["--help"], &[], None);
    let said = help.out.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(said.contains("the line a reader is given to find this registry; it is a setting the reader can change"), "{}", help.out);

    // The bare line: the board's origin and the realm, no fork term.
    let r = skep(&["hint", "--board", &board, "--dir", s(&no_store)], &[], None);
    let bare = format!("{board} realm:{}", realm.to_hex());
    assert_eq!(line(&r), bare);
    assert!(r.err.contains(&format!("realm read at {board} as a guest")) && r.err.contains(&format!("its claimant {CLAIMANT} enrolled at its genesis")), "{}", r.err);
    assert!(!r.err.contains("not dialed"), "no further origin was given: {}", r.err);
    let parsed = RootHint::parse(&bare).expect("the printed line is a root hint");
    assert_eq!(parsed.to_string(), bare, "and reads back as itself");
    assert_eq!(parsed.origins().iter().map(|o| o.as_str()).collect::<Vec<_>>(), [board.as_str()]);
    assert_eq!((parsed.realm().genesis, parsed.realm().fork_point.as_ref()), (realm, None));
    let r = skep(&["hint"], &[("SKEP_BOARD", &board)], None);
    assert_eq!(line(&r), bare, "SKEP_BOARD names the board where no flag does");

    // `--also` keeps its order, and a further origin is never dialed.
    let (second, third) = ("https://registry.example.net", DEAD);
    let r = skep(&["hint", "--board", &board, "--also", second, "--also", third], &[], None);
    let listed = format!("{board} {second} {third} realm:{}", realm.to_hex());
    assert_eq!(line(&r), listed, "the board first, then each --also as given");
    assert!(r.err.contains(&format!("written as given and not dialed: {second}, {third}")), "{}", r.err);
    let r = skep(&["hint", "--board", &board, "--also", third, "--also", second], &[], None);
    let swapped = format!("{board} {third} {second} realm:{}", realm.to_hex());
    assert_eq!(line(&r), swapped, "the other order prints the other line");
    for printed in [&listed, &swapped] {
        assert_eq!(RootHint::parse(printed).map(|h| h.to_string()).as_deref(), Ok(printed.as_str()), "reads back as itself");
    }

    // `--fork` renders the fork term, a leading zero naming its one address.
    let r = skep(&["hint", "--board", &board, "--also", second, "--fork", "1.0.1.0.1.0.2.09"], &[], None);
    let forked = format!("{board} {second} realm:{} fork:1.0.1.0.1.0.2.9", realm.to_hex());
    assert_eq!(line(&r), forked);
    let parsed = RootHint::parse(&forked).expect("a forked hint");
    assert_eq!(parsed.to_string(), forked, "reads back as itself");
    assert_eq!((parsed.realm().genesis, parsed.realm().fork_point.as_ref().map(ToString::to_string).as_deref()), (realm, Some("1.0.1.0.1.0.2.9")));

    // A guest's reads: no store made, the board where it stood.
    assert!(!no_store.exists(), "no store is made: the command holds no key");
    assert_eq!(head(&board), before, "and the board's head stands where it stood");

    // A later key: the living set is another, the realm the same.
    let second_store = dir.path().join("b");
    let r = skep(&["keygen", "--label", "phone", "--payload", "--dir", s(&second_store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let payload = r.lines()[0].to_string();
    let registrar = Board::new(Origin::parse(&board).unwrap(), PlainHttp::new());
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    enroll(&registrar, &FileStore::open(&store), &mut person, &EnrollOptions { principal: 1, payload: format!("{payload}\n").into_bytes() }).unwrap_or_else(|h| panic!("{h}"));
    let living = living_set(&board);
    assert_eq!(living.len(), 4, "the second device's key stands enrolled");
    assert_ne!(RealmId::genesis_fingerprint(&living), realm, "the living set fingerprints to another realm");
    let r = skep(&["hint", "--board", &board], &[], None);
    assert_eq!(line(&r), bare, "the genesis set's realm, never the living set's");
}

/// Checks each refusal of `skep hint`: a named line, and nothing printed.
///
/// Each is a named line on stderr with a nonzero exit and nothing on
/// stdout, in five kinds:
///
/// - The line's own shape, exit 2 before any socket opens (each names a
///   board at a dead port, which a run that dialed would meet as exit 4):
///   no board named; a `--board`, then an `--also`, that is no canonical
///   origin; a `--fork` that is no address, a signed component among them;
///   a second `--fork`; a flag of another command's.
/// - An unclaimed board, exit 3, read and left as it stood.
/// - A claim that names no genesis record, exit 3 — a board no conforming
///   daemon is, scripted: its feed's one row a claim link, no enroll record
///   before it.
/// - A read refused, exit 1, each under the token the board named: a feed
///   whose start the board has reclaimed; a link the board rejects, the op
///   named; a status that names its own error; a root that answers
///   `/health` with no board's status, its body said to a bound; and a
///   feed that stays busy past the retries, the retry named as the act.
/// - A read unanswered, exit 4: a port nothing listens at; and an answer
///   no board gives, bytes that are no JSON.
#[test]
fn hint_refuses_by_name_and_prints_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let not_canonical = "is not a canonical origin (scheme://host[:port], lowercase, the scheme's default port omitted)";
    for (args, named) in [
        (vec!["hint"], "--board (or SKEP_BOARD) is required".to_string()),
        (vec!["hint", "--board", "HTTP://Registry.example"], format!("--board: 'HTTP://Registry.example' {not_canonical}")),
        (vec!["hint", "--board", DEAD, "--also", "registry.example"], format!("--also: 'registry.example' {not_canonical}")),
        (vec!["hint", "--board", DEAD, "--also", "https://registry.example", "--also", "https://registry.example/"], format!("--also: 'https://registry.example/' {not_canonical}")),
        (vec!["hint", "--board", DEAD, "--fork", "1.0"], "--fork: '1.0' is not an address".to_string()),
        (vec!["hint", "--board", DEAD, "--fork", "+1.0.1"], "--fork: '+1.0.1' is not an address".to_string()),
        (vec!["hint", "--board", DEAD, "--fork", "1.0.1", "--fork", "1.0.2"], "`--fork` is given at most once at `hint`".to_string()),
        (vec!["hint", "--board", DEAD, "--doc", "1.0.1.0.2"], "`--doc` is not a flag of `hint`".to_string()),
    ] {
        refused(&skep(&args, &[], None), 2, &named);
    }

    // An unclaimed board: it has no realm.
    let sd = spawn(&dir.path().join("unclaimed"), false);
    let unclaimed = origin(sd.port());
    let before = head(&unclaimed);
    let r = skep(&["hint", "--board", &unclaimed, "--also", "https://registry.example.net"], &[], None);
    refused(&r, 3, &format!("skep: the board at {unclaimed} is unclaimed: it has no realm, so no root hint"));
    assert!(r.err.contains("\n  act: claim the board (`skep claim`), then read its hint again"), "a halt's face: {}", r.err);
    assert_eq!(head(&unclaimed), before, "read, and left as it stood");

    // A claim that names no genesis record.
    let claim = json!({ "resp": "link_value", "link": { "slots": [[{ "start": CLAIMANT, "width": "0.0.1" }], [], [{ "start": "1.1.0.1.0.1.0.3.3", "width": "0.0.0.0.0.0.0.0.1" }]] } });
    let feed = json!({ "changes": [{ "at": 3, "op": "make_link", "link": "1.0.1.0.1.0.2.1", "docs": ["1.0.1.0.1"] }], "last": 3, "more": false });
    let no_genesis = answering(move |request, body| match request {
        "GET /health HTTP/1.1" => (200, json!({ "ok": true }).to_string()),
        "GET /changes?since=0 HTTP/1.1" => (200, feed.to_string()),
        "POST /op HTTP/1.1" if body.contains("read_link") => (200, claim.to_string()),
        other => (500, format!("a read this board does not answer: {other} {body}")),
    });
    let r = skep(&["hint", "--board", &no_genesis], &[], None);
    refused(&r, 3, &format!("skep: the claim of the board at {no_genesis} names no genesis record: no realm can be computed"));
    assert!(r.err.contains("never the set the account holds now (REG-3.39)"), "{}", r.err);

    // A read the board refused: the feed's start reclaimed, and a root that
    // is no board's.
    let reclaimed = answering(|request, _| match request {
        "GET /health HTTP/1.1" => (200, json!({ "ok": true }).to_string()),
        _ => (410, json!({ "error": "history_reclaimed", "floor": 40 }).to_string()),
    });
    let r = skep(&["hint", "--board", &reclaimed], &[], None);
    refused(&r, 1, "skep: the board refused: history_reclaimed:the oldest position still answerable is 40 (HTTP 410)");
    let rejecting = answering(|request, body| match request {
        "GET /health HTTP/1.1" => (200, json!({ "ok": true }).to_string()),
        "GET /changes?since=0 HTTP/1.1" => (200, json!({ "changes": [{ "at": 3, "op": "make_link", "link": "1.0.1.0.1.0.2.1", "docs": ["1.0.1.0.1"] }], "last": 3, "more": false }).to_string()),
        "POST /op HTTP/1.1" if body.contains("read_link") => (200, json!({ "resp": "rejected", "op": "read_link", "code": "withheld" }).to_string()),
        other => (500, format!("a read this board does not answer: {other} {body}")),
    });
    let r = skep(&["hint", "--board", &rejecting], &[], None);
    refused(&r, 1, "skep: the board refused: withheld (op read_link)");
    let failing = answering(|request, _| match request {
        "GET /health HTTP/1.1" => (200, json!({ "ok": true }).to_string()),
        _ => (503, json!({ "error": "index_failed", "detail": "the index is down" }).to_string()),
    });
    let r = skep(&["hint", "--board", &failing], &[], None);
    refused(&r, 1, "skep: the board refused: index_failed:the index is down (HTTP 503)");
    let r = skep(&["hint", "--board", &canned(404, b"not found")], &[], None);
    refused(&r, 1, "skep: the board refused: http_error:not found (HTTP 404)");
    let r = skep(&["hint", "--board", &canned(500, &[b'x'; 300])], &[], None);
    refused(&r, 1, &format!("skep: the board refused: http_error:{} (HTTP 500)", "x".repeat(200)));
    // A feed being rebuilt behind the listener is retried, and given up as
    // a busy board: the act is the same command again.
    let rebuilding = answering(|request, _| match request {
        "GET /health HTTP/1.1" => (200, json!({ "ok": true }).to_string()),
        _ => (503, json!({ "error": "feed_rebuilding" }).to_string()),
    });
    let r = skep(&["hint", "--board", &rebuilding], &[], None);
    refused(&r, 1, "skep: the board refused: http_error:the board stayed busy past the retries (HTTP 503)");
    assert!(r.err.contains("\n  act: the board was busy and took nothing of this request"), "{}", r.err);

    // A read unanswered, and an answer no board gives.
    let r = skep(&["hint", "--board", DEAD], &[], None);
    refused(&r, 4, "skep: transport: connect: ");
    assert!(r.err.contains("\n  act: nothing was sent: check that a daemon serves that origin"), "{}", r.err);
    let r = skep(&["hint", "--board", &canned(200, b"<html>no board</html>")], &[], None);
    refused(&r, 4, "skep: transport: ");
    assert!(r.err.contains("malformed answer") || r.err.contains("<html>"), "the answer that was no board's: {}", r.err);
}
