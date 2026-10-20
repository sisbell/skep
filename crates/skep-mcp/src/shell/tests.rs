use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Instant;

use skep_client::halt::{Face, Refused};
use skep_client::store::{FileStore, KeySelector, KeyStore, Purpose};
use skep_client::DialError;

use super::*;

/// A scratch store, removed with the test.
struct Scratch(PathBuf);

impl Scratch {
    /// Returns a fresh scratch directory named for `tag` and this process.
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("skep-mcp-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch store");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Returns a backend over a real shell at `origin` in `mode`.
///
/// Its store is `dir`, holding one fresh key; its one session is `s-1`, open;
/// its stop and its talk say nothing.
fn backend_at(dir: &Path, origin: Origin, mode: SessionMode) -> Backend {
    let store = FileStore::open(dir);
    let id = store.generate(None).expect("keygen");
    let key = store.select(&KeySelector::Path(&store.key_path(&id.0)), Purpose::Read).expect("the key's facts");
    let talk: Talk = Arc::new(|_: &str| {});
    let shell = Shell::open(ShellOptions::new(vec![origin.clone()], dir.to_path_buf(), mode, Arc::clone(&talk)));
    let board = shell.board_references().into_iter().next().expect("the shell's one board");
    let on_stop: OnStop = Arc::new(|_: String| {});
    Backend { shell, board, origin, principal: mode.principal(), account: None, writes: true, key, session: Arc::new(SessionWatch::new("s-1".into())), on_stop, talk }
}

/// Returns one request off a stand-in board's connection: its head, as text.
///
/// The body its `Content-Length` declares is read too, so the answer that
/// follows is never cut by a reset over bytes left unread.
fn read_request(conn: &mut TcpStream) -> String {
    let (mut raw, mut byte) = (Vec::new(), [0u8; 1]);
    while !raw.ends_with(b"\r\n\r\n") && conn.read(&mut byte).is_ok_and(|n| n == 1) {
        raw.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&raw).into_owned();
    let length = head.lines().find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").and_then(|n| n.trim().parse::<usize>().ok())).unwrap_or(0);
    let _ = conn.read_exact(&mut vec![0u8; length]);
    head
}

/// Each arm of a death's reason asks one thing.
///
/// The restart's re-open names the fresh reference; a restart the board
/// refused, a retirement, a block, a seeding and a mode flip each stop
/// with a line naming the arm's fact; the unreachable board, a re-open
/// that met a board that did not answer, the adapter's own close, and a
/// spelling no arm has serve on. The arms the cases name are exactly the
/// ones skep-shell declares for a death's reason (`shapes::shape`), so an
/// arm the shell adds or renames fails here before `classify`'s wildcard
/// serves a death of it through.
#[test]
fn every_arm_of_a_death_asks_one_thing() {
    assert_eq!(classify(&json!({"arm": "restart", "reopened": true, "session": "s-fresh"})), Death::Reopened("s-fresh".into()));
    let stops = [
        (json!({"arm": "restart", "reopened": false, "refused": "origin_state"}), "origin_state"),
        (json!({"arm": "retired", "fingerprint": "ab12", "hand": "cd34", "label": "second", "position": 9, "own": false}), "retiring your key"),
        (json!({"arm": "blocked", "record": "1.0.1.0.7.1", "ground": null}), "1.0.1.0.7.1"),
        (json!({"arm": "seeded", "account": "1.0.1.1", "as_of": 9, "writer": null}), "1.0.1.1"),
        (json!({"arm": "mode", "mode": "ENFORCING"}), "ENFORCING"),
    ];
    for (reason, names) in &stops {
        match classify(reason) {
            Death::Stop(line) => assert!(line.contains(names), "{reason}: {line}"),
            other => panic!("{reason}: {other:?}"),
        }
    }
    let retired = json!({"arm": "retired", "fingerprint": "ab12", "hand": "cd34", "label": "second"});
    let Death::Stop(line) = classify(&retired) else { panic!() };
    assert!(line.contains("ab12") && line.contains("cd34 (second)"), "the key and the hand: {line}");
    let serve_on = [
        json!({"arm": "unreachable", "text": "connect refused"}),
        json!({"arm": "restart", "reopened": false, "refused": "unreachable"}),
        json!({"arm": "closed"}),
        json!({"arm": "restart", "reopened": true}),
        json!({}),
    ];
    for reason in &serve_on {
        assert_eq!(classify(reason), Death::ServeOn, "{reason}");
    }
    let read: BTreeSet<&str> = stops.iter().map(|(reason, _)| reason).chain(&serve_on).filter_map(|reason| reason["arm"].as_str()).collect();
    let declared: BTreeSet<&str> = skep_shell::shapes::shape("DeathReason")
        .and_then(|shape| shape.fields.iter().find(|field| field.name == "arm"))
        .expect("skep-shell declares a death reason's arm")
        .ty
        .split('|')
        .map(|spelling| spelling.trim().trim_matches('\''))
        .collect();
    assert_eq!(read, declared, "the arms read are the ones skep-shell declares");
}

/// The session's state moves off a session once, and never off a stop.
///
/// Two callers settling one re-open move it once; a death of a session the
/// state has left moves nothing; a death no one re-opened lapses it, the
/// same death settled twice moves it once, and a late re-open of the lapsed
/// session is adopted; a stop moves it, and nothing after.
#[test]
fn the_session_state_moves_off_a_session_once_and_never_off_a_stop() {
    let watch = SessionWatch::new("s-old".to_string());
    assert!(watch.move_off("s-old", SessionState::Open("s-new".into())));
    assert!(!watch.move_off("s-old", SessionState::Open("s-other".into())), "the second caller finds it moved");
    assert!(!watch.move_off("s-old", SessionState::Lapsed("s-old".into())), "a death of a session the state left moves nothing");
    assert!(watch.move_off("s-new", SessionState::Lapsed("s-new".into())), "a death no one re-opened lapses it");
    assert!(!watch.move_off("s-new", SessionState::Lapsed("s-new".into())), "the same death settled twice moves it once");
    assert!(watch.move_off("s-new", SessionState::Open("s-late".into())), "a late re-open of the lapsed session is adopted");
    assert!(watch.move_off("s-late", SessionState::Stopped("s-late".into())));
    for next in [SessionState::Open("s-after".into()), SessionState::Lapsed("s-late".into())] {
        assert!(!watch.move_off("s-late", next), "nothing moves the state off a stop");
    }
    assert_eq!(watch.current(), SessionState::Stopped("s-late".into()));
}

/// A death is settled once, and a stop's line goes to the stop once.
///
/// A death settled a second time — a `session-died` heard twice, a refused
/// open judged twice — moves nothing: the first to settle it moves the
/// session's state and hands the stop its line, alone. A refused open stops
/// a lapsed state as a stopping death stops an open one, and the two
/// refused opens — the shell's re-open, the adapter's own — each name the
/// open refused and agree that a board that does not answer serves on.
#[test]
fn a_death_is_settled_once_and_its_stop_said_once() {
    let said = Mutex::new(Vec::new());
    let on_stop = |line: String| said.lock().unwrap().push(line);
    let watch = SessionWatch::new("s-1".into());
    assert!(watch.settle("s-1", Death::Reopened("s-2".into()), &on_stop));
    assert!(!watch.settle("s-1", Death::Reopened("s-2".into()), &on_stop), "the second finds it settled");
    assert!(watch.settle("s-2", Death::ServeOn, &on_stop));
    assert_eq!(watch.current(), SessionState::Lapsed("s-2".into()));
    assert!(watch.settle("s-2", refused_afresh("retired"), &on_stop), "a refused open stops a lapsed state");
    assert!(!watch.settle("s-2", refused_afresh("retired"), &on_stop));
    let said = said.lock().unwrap();
    assert_eq!(said.len(), 1, "the stop's line handed on once: {said:?}");
    assert!(said[0].contains("the board refused this key the session this adapter opened afresh (retired)"), "{said:?}");
    let Death::Stop(line) = refused_reopen("origin_state") else { panic!("a refused re-open stops") };
    assert!(line.contains("the board restarted and refused this key at the re-open (origin_state)"), "{line}");
    assert_eq!(refused_reopen("unreachable"), Death::ServeOn, "a board that does not answer serves on");
    assert_eq!(refused_afresh("unreachable"), Death::ServeOn, "a board that does not answer serves on, whoever opened");
}

/// The wait ends as the drain settles the session.
///
/// A death settled a moment later wakes it, well inside its bound — a lapse
/// or a stop as surely as a re-open — and with none settled the wait runs
/// out at its bound.
#[test]
fn the_wait_to_settle_ends_as_the_session_state_moves() {
    for death in [Death::Reopened("s-2".into()), Death::ServeOn, Death::Stop("stopped".into())] {
        let watch = Arc::new(SessionWatch::new("s-1".into()));
        let settler = {
            let watch = Arc::clone(&watch);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                watch.settle("s-1", death, &|_: String| {})
            })
        };
        let started = Instant::now();
        assert!(watch.settled_within("s-1", Duration::from_secs(30)), "the settling ends the wait");
        assert!(started.elapsed() < Duration::from_secs(10), "as the state moves: {:?}", started.elapsed());
        assert!(settler.join().expect("the settler"), "the settler moved it");
    }
    let watch = SessionWatch::new("s-1".into());
    assert!(!watch.settled_within("s-1", Duration::from_millis(100)), "with nothing settled the wait runs out");
}

/// A startup stop names what did not hold, then the refusal once.
///
/// The refusal is said in the library's own words: a halt under its armed
/// name with its face's three lines, the board's verdict with "the board
/// refused" said once, the unreachable board, and the shell's own by name
/// with its detail.
#[test]
fn a_startup_stop_names_what_did_not_hold_then_the_refusal_once() {
    let face = skep_client::halt::Face { state: "no key here".into(), cause: "the store is keyless".into(), act: "run keygen".into() };
    for (refusal, said) in [
        (Refusal::named(Name::NO_KEY, face), "no_key: no key here\n  cause: the store is keyless\n  act: run keygen"),
        (Refusal::board(401, json!({"error": "session_rejected"})), "the board refused: session_rejected (HTTP 401)"),
        (Refusal::Unreachable(skep_client::DialError::Connect("refused".into())), "unreachable: connect: refused"),
        (Refusal::shell(Name::SESSION_ENDED, json!({"session": "s-1"})), "session_ended: {\"session\":\"s-1\"}"),
    ] {
        assert_eq!(stopped_before_serving("the check", &refusal), format!("stopped before serving: the check: {said}"));
    }
}

/// A call is reissued once, and only after a death settled into a session.
///
/// `under_session` around one call, the shell real over a board that does
/// not answer, the drain a thread settling the watch once the call's first
/// attempt has run: a `session_died` or `session_ended` waits for it and is
/// reissued once under the re-opened session; a death that stopped the
/// adapter or lapsed its session is the answer, as is a second death; any
/// other answer is the attempt's own, at once, a re-opened session standing
/// by — the unreachable board's above all; a lapsed session is opened afresh
/// first, the board's silence the call's answer; a stopped adapter runs the
/// attempt once, as it died.
#[test]
fn a_call_is_reissued_once_and_only_after_a_death_settled_into_a_session() {
    /// Returns one call's attempts and answer, from the session `s-1`.
    ///
    /// The session first moves by `from`; each attempt is answered off
    /// `script`, the reference it ran under kept; `drain` settles `s-1` once
    /// the first attempt has run.
    fn call(backend: &mut Backend, from: Option<Death>, script: Vec<Result<&'static str, Refusal>>, drain: Option<Death>) -> (Vec<String>, Result<&'static str, Refusal>) {
        backend.session = Arc::new(SessionWatch::new("s-1".into()));
        if let Some(death) = from {
            backend.session.settle("s-1", death, &|_: String| {});
        }
        let (attempted, first) = std::sync::mpsc::channel::<()>();
        let drain = drain.map(|death| {
            let watch = Arc::clone(&backend.session);
            thread::spawn(move || {
                let _ = first.recv();
                watch.settle("s-1", death, &|_: String| {});
            })
        });
        let (mut script, mut ran) = (script.into_iter(), Vec::new());
        let outcome = backend.under_session(|reference| {
            ran.push(reference.to_string());
            let _ = attempted.send(());
            script.next().expect("an attempt the script does not foresee")
        });
        if let Some(drain) = drain {
            drain.join().expect("the drain's stand-in");
        }
        (ran, outcome)
    }
    let scratch = Scratch::new("under-session");
    let mut backend = backend_at(&scratch.0, Origin::parse("http://127.0.0.1:1").expect("a canonical origin"), SessionMode::Signed { principal: 1 });
    let died = || -> Result<&'static str, Refusal> { Err(Refusal::shell(Name::SESSION_DIED, json!({"session": "s-1"}))) };
    let ended = || -> Result<&'static str, Refusal> { Err(Refusal::shell(Name::SESSION_ENDED, json!({"session": "s-1"}))) };
    let named = |outcome: Result<&'static str, Refusal>| outcome.map_err(|refusal| refusal.name().to_string());
    let references = |refs: &[&str]| refs.iter().map(|r| r.to_string()).collect::<Vec<_>>();
    for met in [died(), ended()] {
        let (ran, outcome) = call(&mut backend, None, vec![met, Ok("ack")], Some(Death::Reopened("s-2".into())));
        assert_eq!((ran, named(outcome)), (references(&["s-1", "s-2"]), Ok("ack")), "reissued once, under the re-opened session");
    }
    for drained in [Death::Stop("stopped".into()), Death::ServeOn] {
        let (ran, outcome) = call(&mut backend, None, vec![died()], Some(drained));
        assert_eq!((ran, named(outcome)), (references(&["s-1"]), Err("session_died".to_string())), "a death not re-opened is the answer");
    }
    let (ran, outcome) = call(&mut backend, None, vec![died(), died()], Some(Death::Reopened("s-2".into())));
    assert_eq!((ran, named(outcome)), (references(&["s-1", "s-2"]), Err("session_died".to_string())), "one reissue, no second");
    let lost = Refusal::Unreachable(DialError::Timeout("the answer was lost".into()));
    let body = json!({"code": "not_owner", "disposition": "permanent", "op": "insert", "resp": "rejected"});
    let verdict = Refusal::Board(Refused { status: 200, code: "not_owner".into(), detail: None, op: Some("insert".into()), body });
    for (other, name) in [(lost, "unreachable"), (verdict, "not_owner")] {
        let (ran, outcome) = call(&mut backend, None, vec![Err(other), Ok("ack")], Some(Death::Reopened("s-2".into())));
        assert_eq!((ran, named(outcome)), (references(&["s-1"]), Err(name.to_string())), "{name}: the attempt's own, never reissued");
    }
    let (ran, outcome) = call(&mut backend, None, vec![ended()], Some(Death::ServeOn));
    assert_eq!((ran, named(outcome)), (references(&["s-1"]), Err("unreachable".to_string())), "a lapse is opened afresh, not reissued under");
    let (ran, outcome) = call(&mut backend, Some(Death::ServeOn), Vec::new(), None);
    assert_eq!((ran, named(outcome)), (references(&[]), Err("unreachable".to_string())), "no attempt runs under no session");
    assert_eq!(backend.session.current(), SessionState::Lapsed("s-1".into()), "the lapse stands for the next call");
    let (ran, outcome) = call(&mut backend, Some(Death::Stop("stopped".into())), vec![ended()], None);
    assert_eq!((ran, named(outcome)), (references(&["s-1"]), Err("session_ended".to_string())), "a stopped adapter's call, as the shell answers it");
}

/// A session's open is refused with no answer's text in it.
///
/// A stand-in board answers the open's `POST /session` with a `200` the client
/// cannot read — a byte short, with no length to catch it, as a connection an
/// intermediary re-framed and then lost — whose text holds the session's token:
/// the afresh open's refusal is `unreachable`, the session lapses as at a board
/// that did not answer, and neither the refusal's text, its value nor its
/// `Debug` carries the token. A dial fault that names no answer's bytes stands
/// whole, and a refusal of another kind is untouched.
#[test]
fn a_sessions_open_is_refused_with_no_answers_text_in_it() {
    const TOKEN: &str = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
    let listener = TcpListener::bind("127.0.0.1:0").expect("a stand-in board");
    let origin = Origin::parse(&format!("http://127.0.0.1:{}", listener.local_addr().expect("its port").port())).expect("a canonical origin");
    let (opened, opens) = std::sync::mpsc::channel::<()>();
    thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let answer = if read_request(&mut conn).starts_with("POST /session ") {
                let _ = opened.send(());
                format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{{\"principal\":1,\"session\":\"{TOKEN}\"")
            } else {
                let health = r#"{"ok":true,"log_position":0,"auth":{"claimant":null,"local_trust":true}}"#;
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{health}", health.len())
            };
            let _ = conn.write_all(answer.as_bytes());
        }
    });
    let scratch = Scratch::new("open-afresh");
    let backend = backend_at(&scratch.0, origin, SessionMode::Bare { principal: 1 });
    let refusal = backend.open_afresh("s-1").expect_err("an answer this client cannot read opens no session");
    assert!(opens.try_recv().is_ok(), "premise: the open's `POST /session` was answered");
    assert_eq!(refusal.name(), "unreachable", "{refusal}");
    for shown in [refusal.to_string(), refusal.to_value().to_string(), format!("{refusal:?}")] {
        assert!(!shown.contains(TOKEN), "the session's token is quoted: {shown}");
    }
    assert_eq!(backend.session.current(), SessionState::Lapsed("s-1".into()), "the session lapses, as at a board that did not answer");
    let refused = Refusal::Unreachable(DialError::Connect("refused".into()));
    assert_eq!(unquoted(refused.clone()), refused, "a fault that names no answer's bytes stands whole");
    let retired = Refusal::named(Name::RETIRED, Face { state: "s".into(), cause: "c".into(), act: "a".into() });
    assert_eq!(unquoted(retired.clone()), retired, "a refusal of another kind is untouched");
}

/// A blob's URI is the fetch's route at the board's origin, `i` as written.
///
/// An `i` in its one spelling rides the query untouched; one that is no
/// address breaks the precondition, which a debug build checks.
#[test]
fn a_blob_uri_is_the_fetch_route_and_takes_an_address_alone() {
    let scratch = Scratch::new("blob-uri");
    let backend = backend_at(&scratch.0, Origin::parse("http://127.0.0.1:1").expect("a canonical origin"), SessionMode::Bare { principal: 1 });
    assert_eq!(backend.blob_uri("1.0.1.0.1.0.1.1"), "http://127.0.0.1:1/blob?i=1.0.1.0.1.0.1.1");
    let broken = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend.blob_uri("1.0.1&i=2")));
    assert!(broken.is_err(), "an `i` that is no address breaks the precondition");
}
