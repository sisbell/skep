use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Mutex;

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
    let on_stop = OnStop::new(std::sync::mpsc::channel::<String>().0, |line| line);
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

/// Returns the origin of a stand-in board answering each request by `answer`.
///
/// `answer` is handed the request's head; where it gives none, the board
/// answers its `/health` reading, an unclaimed board with local trust on.
fn stand_in(answer: impl Fn(&str) -> Option<String> + Send + 'static) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a stand-in board");
    let origin = Origin::parse(&format!("http://127.0.0.1:{}", listener.local_addr().expect("its port").port())).expect("a canonical origin");
    thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let head = read_request(&mut conn);
            let health = r#"{"ok":true,"log_position":0,"auth":{"claimant":null,"local_trust":true}}"#;
            let reply = answer(&head).unwrap_or_else(|| format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{health}", health.len()));
            let _ = conn.write_all(reply.as_bytes());
        }
    });
    origin
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
    let (opened, opens) = std::sync::mpsc::channel::<()>();
    let origin = stand_in(move |head| {
        head.starts_with("POST /session ").then(|| {
            let _ = opened.send(());
            format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{{\"principal\":1,\"session\":\"{TOKEN}\"")
        })
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

/// A refused open of the adapter's own stops it, on the calling thread.
///
/// A stand-in board refuses the `POST /session` a call opens after a lapse
/// (401): the refusal is the call's, no attempt runs, the session's state
/// stops, and the stop's line, naming the open this adapter made, is handed
/// on once, by the thread that made the call — in the adapter, the loop
/// itself, which is why the stop is built on an unbounded channel alone.
#[test]
fn a_refused_open_of_the_adapters_own_stops_it_on_the_calling_thread() {
    let origin = stand_in(|head| {
        head.starts_with("POST /session ").then(|| {
            let body = r#"{"error":"session_rejected"}"#;
            format!("HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        })
    });
    let scratch = Scratch::new("open-refused");
    let mut backend = backend_at(&scratch.0, origin, SessionMode::Bare { principal: 1 });
    let (stops, stopped) = std::sync::mpsc::channel::<(thread::ThreadId, String)>();
    backend.on_stop = OnStop::new(stops, |line| (thread::current().id(), line));
    backend.session.settle("s-1", Death::ServeOn, &|_: String| {});
    let refusal = backend.under_session(|_: &str| -> Result<(), Refusal> { panic!("no attempt runs where the open was refused") }).expect_err("the board refused the open");
    assert_eq!(refusal.name(), "session_rejected", "{refusal}");
    assert_eq!(backend.session.current(), SessionState::Stopped("s-1".into()), "the session's state stops");
    let stops: Vec<_> = stopped.try_iter().collect();
    assert_eq!(stops.len(), 1, "the stop is handed on once: {stops:?}");
    assert_eq!(stops[0].0, thread::current().id(), "by the thread that made the call");
    assert!(stops[0].1.contains("opened afresh (session_rejected)"), "the line names the adapter's own open: {}", stops[0].1);
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

/// The clean stop says first what it closes, as the session's state has it.
///
/// A session the calls run under is said closed at the board; a lapsed one
/// and a stopped one ended there already, and the line says so: the
/// backend's one line, said before the shell's stop runs.
#[test]
fn the_clean_stop_says_what_it_closes_as_the_session_state_has_it() {
    let closing = "stopping: closing the session at the board, saving the index";
    let ended = "stopping: the session already ended at the board; saving the index";
    for (k, death, said) in [(0, None, closing), (1, Some(Death::ServeOn), ended), (2, Some(Death::Stop("stopped".into())), ended)] {
        let scratch = Scratch::new(&format!("clean-stop-{k}"));
        let mut backend = backend_at(&scratch.0, Origin::parse("http://127.0.0.1:1").expect("a canonical origin"), SessionMode::Bare { principal: 1 });
        if let Some(death) = death {
            backend.session.settle("s-1", death, &|_: String| {});
        }
        let lines = Arc::new(Mutex::new(Vec::new()));
        backend.talk = {
            let lines = Arc::clone(&lines);
            Arc::new(move |line: &str| lines.lock().expect("the lines' lock").push(line.to_string()))
        };
        backend.shutdown();
        assert_eq!(*lines.lock().expect("the lines' lock"), [said], "{:?}", backend.session.current());
    }
}
