//! Each board's own: its node's state, its feed and the shell's stop.
//!
//! The suite checks the own node's state announced at its board — a deliberate
//! stop said once, its feed adding no `unreachable` while it stands, while
//! another board's stream failure is still announced, and its `Running` handing
//! the probe to the board's feed thread; this machine's notebook started by
//! the door's act alone, listed once started and said `running` once, stopped
//! and taken out of the list by its claim's cancel while unclaimed, `stopped`
//! said before the node goes down, and left running by a cancel at a claimed
//! notebook; the page's `health(board)` read the
//! board's verdict, ending its silence; a search held at one board holding back
//! no call at another; a shell dropped unstopped closing its sessions and
//! freeing its board's held lock; a board paging without end holding no stop;
//! and a board down at the open fed from its first answer, never replaying the
//! history before it.

use std::io::{Read, Write};

use super::*;
use crate::sessions::{Facts, Open};

/// Checks that the own node's state is announced at its board.
///
/// A shell that runs the node announces each state its owner reports on the
/// `daemon` event at the node's board, and `probe` answers it; a shell that
/// runs none has none to report.
#[test]
fn the_own_nodes_state_is_announced_at_its_board() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let (talk, _) = talk();
    let own = Shell::open(ShellOptions { boards: vec![Origin::parse(&origin).unwrap()], store_dir: dir.path().join("own-store"), session_mode: SessionMode::Bare { principal: 1 }, arm: ArmConfig::Auto, talk, own_node: Some(Origin::parse(&origin).unwrap()), node_control: None });
    let rx = own.subscribe();
    let board = own.board_references().remove(0);
    let daemon = |rx: &Receiver<Event>| -> Vec<Value> { rx.try_iter().filter(|e| e.name == EventName::Daemon).map(|e| e.data).collect() };
    own.set_node_state(NodeState::Stopped);
    assert_eq!(daemon(&rx), [json!({"board": board, "state": "stopped"})]);
    assert_eq!(own.call("probe", &json!({})).unwrap()["daemon"], "stopped");
    own.set_node_state(NodeState::Running);
    assert_eq!(daemon(&rx), [json!({"board": board, "state": "running"})]);
    assert_eq!(own.call("probe", &json!({})).unwrap()["daemon"], "running");
    own.shutdown();
    let (other, _) = open_shell(&origin, &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let rx = other.subscribe();
    other.set_node_state(NodeState::Stopped);
    assert!(daemon(&rx).is_empty(), "a shell that runs no node announces none");
    assert_eq!(other.call("probe", &json!({})).unwrap()["daemon"], "running", "its probe reads the first board, and no stop it was told of");
    other.shutdown();
    sd.shutdown();
}

/// Checks that a deliberate stop of the own node is said once.
///
/// With the own node running and its feed live, `set_node_state(Stopped)`
/// and then the node's shutdown — within three probe cadences the board's
/// `daemon` events are exactly one `stopped` and no `unreachable` (the
/// mutant that keeps the feed's emit under the stop); the node back at the
/// same port and `set_node_state(Running)`: exactly one `running`, the feed's
/// first tick after the restart adding none of its own (the mutant that
/// marks the stream unreachable under the stop and so says `running`
/// twice). A second board that is not the own node, shut down the same way,
/// still announces `unreachable`: the `daemon` event reaches every board the
/// shell dials, each naming its board.
#[test]
fn a_deliberate_stop_of_the_own_node_is_said_once() {
    let dir = TempDir::new().unwrap();
    let own_sd = spawn(&dir.path().join("own"), true);
    let other_sd = spawn(&dir.path().join("other"), true);
    let port = own_sd.port();
    let own_origin = format!("http://127.0.0.1:{port}");
    let other_origin = format!("http://127.0.0.1:{}", other_sd.port());
    let store = dir.path().join("store");
    claim_board(&own_origin, &store);
    let (talk, lines) = talk();
    let boards = vec![Origin::parse(&own_origin).unwrap(), Origin::parse(&other_origin).unwrap()];
    let shell = Shell::open(ShellOptions { boards, store_dir: store, session_mode: SessionMode::Signed { principal: 1 }, arm: ArmConfig::Auto, talk, own_node: Some(Origin::parse(&own_origin).unwrap()), node_control: None });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let refs = shell.board_references();
    let (own, other) = (refs[0].clone(), refs[1].clone());
    let daemon_states = |board: &str| -> Vec<String> { seen.lock().unwrap().iter().filter(|e| e.name == EventName::Daemon && e.data["board"] == board).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect() };
    // The own node's feed is live: a session's supplement widened on its
    // thread.
    let session = shell.call("session", &json!({"board": own})).unwrap()["session"].as_str().unwrap().to_string();
    wait_for(&seen, |e| e.name == EventName::Index && e.data["session"] == session);
    // The stop, deliberate: said once; then both nodes go down.
    shell.set_node_state(NodeState::Stopped);
    let stopped_at = Instant::now();
    own_sd.shutdown();
    other_sd.shutdown();
    // The other board goes silent: its stream fails, and its `/health` verdict
    // is `unreachable`, as every board's is.
    wait_for(&seen, |e| e.name == EventName::Daemon && e.data["board"] == other && e.data["state"] == "unreachable");
    thread::sleep((stopped_at + PROBE_CADENCE * 3).saturating_duration_since(Instant::now()));
    assert_eq!(daemon_states(&own), ["stopped"], "a deliberate stop is said once, no unreachable beside it:\n{}", lines.lock().unwrap().join("\n"));
    assert!(lines.lock().unwrap().iter().any(|l| l.contains("the commit stream is not answering")), "TALK still says the stream is down:\n{}", lines.lock().unwrap().join("\n"));
    // The node back at the same port, `running` said once by its owner; the
    // old session dies, a fresh signed one's write makes the stream tick, and
    // the tick adds no `running` of its own.
    let own_sd = spawn_at(&dir.path().join("own"), true, port);
    shell.set_node_state(NodeState::Running);
    wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let session2 = shell.call("session", &json!({"board": own})).unwrap()["session"].as_str().unwrap().to_string();
    shell.call("op", &json!({"session": session2, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    wait_for(&seen, |e| e.name == EventName::Feed && e.data["board"] == own && e.data["update"]["class"] == "drafts");
    assert_eq!(daemon_states(&own), ["stopped", "running"], "the restart's running is said once");
    assert_eq!(daemon_states(&other), ["unreachable"], "the other board's silence is announced, and nothing more");
    shell.shutdown();
    own_sd.shutdown();
}

/// Returns the `daemon` events said so far at `board`, by their state.
fn daemon_states(rx: &Receiver<Event>, board: &str) -> Vec<String> {
    rx.try_iter().filter(|e| e.name == EventName::Daemon && e.data["board"] == board).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect()
}

/// Runs `claim` at `board`, the page's side of it played here.
///
/// The call runs on a thread of its own; each answerable moment is
/// answered as `act` answers it, or cancelled where it answers `None`, until
/// the call answers.
///
/// # Errors
///
/// Returns the call's refusal.
fn claim_with(shell: &Shell, board: &str, mut act: impl FnMut(&Event) -> Option<Value>) -> Result<Value, Refusal> {
    let rx = shell.subscribe();
    thread::scope(|s| {
        let walk = s.spawn(|| shell.call("claim", &json!({"board": board})));
        while !walk.is_finished() {
            let Ok(event) = rx.recv_timeout(Duration::from_millis(20)) else { continue };
            if event.name == EventName::Moment && event.data["answerable"] == true {
                let id = event.data["id"].as_str().unwrap();
                let acted = match act(&event) {
                    Some(answer) => shell.answer(id, answer),
                    None => shell.cancel(id),
                };
                acted.unwrap_or_else(|r| panic!("the page's act on {id}: {r}"));
            }
        }
        walk.join().unwrap()
    })
}

/// Checks that the notebook starts at the door's act alone (L1).
///
/// A shell handed the node's control opens with the node unstarted: its
/// board out of `boards()`, `probe` answering `stopped`, no `daemon` event
/// said over two probe cadences and the control never asked (the mutant
/// that sets no stop at the open has the probe and the feed find the board
/// silent and say so). `node.start` answers the declared probe, `running`,
/// the board listed at its origin; a second start starts nothing and says
/// no second `running`, and two cadences on `running` is the one `daemon`
/// event.
#[test]
fn the_notebook_starts_at_the_doors_act_alone() {
    let dir = TempDir::new().unwrap();
    let control = Control::over(&dir.path().join("notebook"));
    let (shell, lines) = notebook_shell(&control, &dir.path().join("store"));
    let rx = shell.subscribe();
    let board = shell.board_references().remove(0);
    let opened = Instant::now();
    assert_eq!(shell.call("boards", &json!({})).unwrap(), json!([]), "no board of this machine's before the door's act");
    assert_eq!(shell.call("probe", &json!({})).unwrap()["daemon"], "stopped");
    thread::sleep((opened + PROBE_CADENCE * 2).saturating_duration_since(Instant::now()));
    assert!(daemon_states(&rx, &board).is_empty(), "nothing is said of a notebook nobody began:\n{}", lines.lock().unwrap().join("\n"));
    assert_eq!(control.counts(), (0, 0), "the open starts nothing");
    let started = shell.call("node.start", &json!({})).unwrap();
    crate::shapes::assert_declared("Probe", &started);
    assert_eq!(started["daemon"], "running", "{started}");
    let origin = control.origin();
    assert_eq!(shell.call("boards", &json!({})).unwrap(), json!([{"board": board, "name": origin, "origin": origin}]));
    let again = shell.call("node.start", &json!({})).unwrap();
    assert_eq!(again["daemon"], "running", "{again}");
    assert_eq!(control.counts(), (1, 0), "a second start starts nothing");
    thread::sleep(PROBE_CADENCE * 2);
    assert_eq!(daemon_states(&rx, &board), ["running"], "`running` said once:\n{}", lines.lock().unwrap().join("\n"));
    shell.shutdown();
}

/// Checks that a claim's cancel stops the notebook it left unclaimed.
///
/// The notebook started and a key made, the claim's first answerable moment
/// is cancelled: the call answers `abandoned`, the control's stop is asked
/// once, the board leaves `boards()` and `probe` answers `stopped`; and
/// over two probe cadences the board's `daemon` events are `running` then
/// `stopped`, no `unreachable` between — `stopped` said before the node
/// goes down, so an orderly stop that runs past a probe's cadence is no
/// silence (the mutant that stops the node first lets the probe in that
/// stop find the board silent and say so). The door's act starts it again,
/// the board listed once more, and the claim then lands (L1 part 1; F-C4).
#[test]
fn a_claims_cancel_stops_the_notebook_it_left_unclaimed() {
    let dir = TempDir::new().unwrap();
    let control = Control::stopping_slowly(&dir.path().join("notebook"), PROBE_CADENCE + Duration::from_millis(500));
    let (shell, lines) = notebook_shell(&control, &dir.path().join("store"));
    let rx = shell.subscribe();
    let board = shell.board_references().remove(0);
    shell.call("keygen", &json!({"label": "notebook"})).unwrap();
    shell.call("node.start", &json!({})).unwrap();
    let refused = claim_with(&shell, &board, |_| None).unwrap_err();
    assert_eq!(refused.name(), "abandoned", "{refused}");
    let cancelled = Instant::now();
    assert_eq!(control.counts(), (1, 1), "the cancel stops the node once");
    assert_eq!(shell.call("boards", &json!({})).unwrap(), json!([]), "the board leaves the list");
    assert_eq!(shell.call("probe", &json!({})).unwrap()["daemon"], "stopped");
    thread::sleep((cancelled + PROBE_CADENCE * 2).saturating_duration_since(Instant::now()));
    assert_eq!(daemon_states(&rx, &board), ["running", "stopped"], "no `unreachable` beside the stop:\n{}", lines.lock().unwrap().join("\n"));
    assert_eq!(shell.call("node.start", &json!({})).unwrap()["daemon"], "running");
    assert_eq!(shell.call("boards", &json!({})).unwrap().as_array().map(Vec::len), Some(1), "the door's act lists it again");
    let claimed = claim_with(&shell, &board, |moment| Some(page_answer(moment))).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(claimed["account"], "1.0.1", "{claimed}");
    assert_eq!(control.counts(), (2, 1));
    shell.shutdown();
}

/// Checks that a cancel at a claimed notebook stops nothing.
///
/// A claim landed on the notebook, a second `claim` there reaches its
/// display-name question, which swallows a cancel; the key store's bindings
/// made unreadable then, the walk halts after it, answered `abandoned`
/// though the board stands claimed — and the board's `/health`, read
/// first, keeps the shell from stopping it: the control's stop is never
/// asked, the board stays listed and `probe` answers `running` (the mutant
/// keyed on `abandoned` alone stops a claimed notebook).
#[test]
fn a_cancel_at_a_claimed_notebook_stops_nothing() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("store");
    let control = Control::over(&dir.path().join("notebook"));
    let (shell, lines) = notebook_shell(&control, &store);
    let board = shell.board_references().remove(0);
    shell.call("keygen", &json!({"label": "notebook"})).unwrap();
    shell.call("node.start", &json!({})).unwrap();
    let claimed = claim_with(&shell, &board, |moment| Some(page_answer(moment))).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(claimed["account"], "1.0.1", "{claimed}");
    let (bindings, aside) = (store.join("bindings"), store.join("bindings.aside"));
    let mut asked = false;
    let refused = claim_with(&shell, &board, |moment| {
        if moment.data["kind"] != "ask" {
            return Some(page_answer(moment));
        }
        asked = true;
        std::fs::rename(&bindings, &aside).unwrap();
        std::fs::create_dir(&bindings).unwrap();
        None
    })
    .unwrap_err();
    assert!(asked, "premise: the walk asked the display name");
    std::fs::remove_dir(&bindings).unwrap();
    std::fs::rename(&aside, &bindings).unwrap();
    assert_eq!(refused.name(), "abandoned", "premise: the walk halted after the cancel: {refused}");
    assert_eq!(control.counts(), (1, 0), "a claimed notebook is not stopped");
    assert_eq!(shell.call("boards", &json!({})).unwrap().as_array().map(Vec::len), Some(1), "the board stays listed");
    assert_eq!(shell.call("probe", &json!({})).unwrap()["daemon"], "running");
    shell.shutdown();
}

/// Returns the origin of a listener that holds every connection for `delay`.
///
/// It lets each go unanswered: a board each of whose dials takes that long
/// and answers nothing.
fn tarpit(delay: Duration) -> String {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                thread::sleep(delay);
                drop(stream);
            });
        }
    });
    origin
}

/// Returns a board that pages without end, its reads counted.
///
/// Every `/changes` read is answered with an empty page whose `last` passes
/// its `since` by one and whose `more` stands — each read counted — its
/// `/events` stream one commit and then silence, its `/health` a board at
/// position 10 that takes writes, and every `/op` an empty delivery (no
/// `H.1`, so no index opens). Each page moves its reader on as the wire's
/// paging rule asks, so no reader refuses one, and a read to the head never
/// ends.
fn endless_pages() -> (String, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let pages = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&pages);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let counted = Arc::clone(&counted);
            thread::spawn(move || answer_one_request(stream, &counted));
        }
    });
    (origin, pages)
}

/// Answers one request off `stream` as `endless_pages`' board.
///
/// The request is its head through the blank line, its body as long as its
/// `Content-Length` says.
fn answer_one_request(mut stream: std::net::TcpStream, pages: &AtomicUsize) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let declared = head.lines().filter_map(|line| line.split_once(':')).find(|(name, _)| name.eq_ignore_ascii_case("content-length")).and_then(|(_, n)| n.trim().parse().ok()).unwrap_or(0);
    if stream.read_exact(&mut vec![0u8; declared]).is_err() {
        return;
    }
    let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
    if path.starts_with("/events") {
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nevent: commit\ndata: {\"log_position\": 11}\n\n");
        thread::sleep(Duration::from_secs(60));
        return;
    }
    let answer = if path.starts_with("/changes") {
        pages.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(2));
        let since = path.split_once("since=").and_then(|(_, rest)| rest.split('&').next()).and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
        json!({"changes": [], "last": since + 1, "more": true})
    } else if path.starts_with("/health") {
        json!({"ok": true, "log_position": 10, "auth": {"claimant": null, "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}})
    } else {
        json!({"resp": "delivery", "items": []})
    };
    let body = answer.to_string();
    let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

/// Checks that a board paging without end holds no stop.
///
/// The board's feed thread reads pages that never end — each one's `more`
/// standing, its `last` one past its `since`, as the wire's paging rule
/// admits — and the shell's stop returns all the same, the dialer refusing
/// every dial once the stop stands so the read ends at its next exchange;
/// once the stop returns no page is read (the mutant that dials past the
/// stop waits for a feed thread that never takes its `Stop`, and the
/// shell's `Drop` with it).
#[test]
fn a_board_paging_without_end_holds_no_stop() {
    let dir = TempDir::new().unwrap();
    let (origin, pages) = endless_pages();
    let (talk, _) = talk();
    let shell = Arc::new(Shell::open(ShellOptions::new(vec![Origin::parse(&origin).unwrap()], dir.path().join("store"), SessionMode::Bare { principal: 1 }, talk)));
    let deadline = Instant::now() + Duration::from_secs(30);
    while pages.load(Ordering::SeqCst) < 64 {
        assert!(Instant::now() < deadline, "the feed thread never read the board's pages");
        thread::sleep(Duration::from_millis(10));
    }
    // The stop on a thread of its own, so a stop that never returns fails
    // the cell at its deadline rather than hanging the suite.
    let (stopped, rx) = std::sync::mpsc::channel();
    let stopping = Arc::clone(&shell);
    thread::spawn(move || {
        stopping.shutdown();
        let _ = stopped.send(());
    });
    assert!(rx.recv_timeout(Duration::from_secs(30)).is_ok(), "the stop waited on a board paging without end");
    let read = pages.load(Ordering::SeqCst);
    thread::sleep(Duration::from_millis(200));
    assert_eq!(pages.load(Ordering::SeqCst), read, "no page is read once the stop returns");
}

/// Checks that one board's wait holds back no call at another.
///
/// A guest `search` queued behind a board whose feed thread waits out dial
/// after dial does not hold back a `session` at another board, which is
/// answered while the search still waits (the mutant that runs a board's
/// command under one lock over every board's handle makes the session wait
/// the search out).
#[test]
fn a_search_waiting_on_one_board_holds_back_no_call_at_another() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let slow = tarpit(Duration::from_secs(2));
    let (talk, _) = talk();
    let boards = vec![Origin::parse(&origin).unwrap(), Origin::parse(&slow).unwrap()];
    let shell = Shell::open(ShellOptions::new(boards, dir.path().join("store"), SessionMode::Bare { principal: 0 }, talk));
    let refs = shell.board_references();
    thread::scope(|s| {
        let searching = s.spawn(|| shell.call("search", &json!({"guest": true, "board": refs[1], "query": "x"})));
        thread::sleep(Duration::from_millis(300));
        let opened = shell.call("session", &json!({"board": refs[0], "principal": 0}));
        assert!(opened.is_ok(), "{opened:?}");
        assert!(!searching.is_finished(), "the session is answered while the search still waits");
        let answer = searching.join().unwrap().unwrap();
        assert_eq!(answer["state"]["arm"], "none", "a board whose index never opened answers none: {answer}");
    });
    shell.shutdown();
    sd.shutdown();
}

/// Returns the origin of a board that answers every read and says nothing.
///
/// Its `/health` answers a board at position 10 that takes writes, its
/// `/events` stream stands open and says nothing — no commit, no close —
/// its `/changes` an empty page at its `since`, and every `/op` an empty
/// delivery (no `H.1`, so no index opens).
fn quiet_board() -> String {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let declared = head.lines().filter_map(|line| line.split_once(':')).find(|(name, _)| name.eq_ignore_ascii_case("content-length")).and_then(|(_, n)| n.trim().parse().ok()).unwrap_or(0);
                if stream.read_exact(&mut vec![0u8; declared]).is_err() {
                    return;
                }
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                if path.starts_with("/events") {
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n");
                    thread::sleep(Duration::from_secs(60));
                    return;
                }
                let answer = if path.starts_with("/changes") {
                    let since = path.split_once("since=").and_then(|(_, rest)| rest.split('&').next()).and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
                    json!({"changes": [], "last": since, "more": false})
                } else if path.starts_with("/health") {
                    json!({"ok": true, "log_position": 10, "auth": {"claimant": null, "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}})
                } else {
                    json!({"resp": "delivery", "items": []})
                };
                let body = answer.to_string();
                let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            });
        }
    });
    origin
}

/// Checks that the page's `health(board)` read is the board's verdict too.
///
/// It is §3c.4's THE END: the hold ends at the first answer to a `/health`
/// (skep #863). The own node stopped, so no probe reads, and the board's
/// stream open and silent, so no tick does: the hold told the board silent,
/// the page's `health(board)`, answered, ends that silence by itself (the
/// mutant that reads the page's `/health` for the page alone keeps the board
/// silent until the next probe, every burst there held `unreachable`
/// meanwhile at a board that has just answered).
#[test]
fn the_pages_health_read_ends_the_boards_silence() {
    let dir = TempDir::new().unwrap();
    let origin = quiet_board();
    let (talk, _) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse(&origin).unwrap()], dir.path().join("store"), SessionMode::Bare { principal: 1 }, talk);
    opts.own_node = Some(Origin::parse(&origin).unwrap());
    let shell = Shell::open(opts);
    let board = shell.board_references().remove(0);
    // The feed thread's start, its own `/health` read among it, runs before
    // the search it serves.
    shell.call("search", &json!({"guest": true, "board": board, "query": "x"})).unwrap();
    shell.set_node_state(NodeState::Stopped);
    shell.holds.note_health_read(&board, &Err(Halt::Dial(skep_client::DialError::Timeout("the board takes the read and sends nothing".into()))));
    assert!(shell.holds.silent(&board), "premise: the board found silent");
    let health = shell.call("health", &json!({"board": board})).unwrap();
    assert_eq!(health["health"]["log_position"], 10, "{health}");
    assert!(!shell.holds.silent(&board), "the page's answered `/health` ends the board's silence");
    shell.shutdown();
}

/// Checks that the node's `Running` hands its probe over (§3c.4).
///
/// With a line held at the own node's board, and the board a tarpit holding
/// each dial two seconds, `set_node_state(Running)` answers at once — the
/// hold ended and the probe handed to the board's feed thread, as
/// `resolve(send)` hands it, never run on the caller's thread (the mutant
/// that probes inline waits the tarpit's `/health` read out before the verb
/// that owns the node is answered).
#[test]
fn the_nodes_running_hands_its_probe_to_the_boards_feed_thread() {
    let dir = TempDir::new().unwrap();
    let slow = tarpit(Duration::from_secs(2));
    let (talk, _) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse(&slow).unwrap()], dir.path().join("store"), SessionMode::Bare { principal: 1 }, talk);
    opts.own_node = Some(Origin::parse(&slow).unwrap());
    let shell = Shell::open(opts);
    let board = shell.board_references().remove(0);
    shell.set_node_state(NodeState::Stopped);
    let facts = Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare };
    let session = shell.sessions.register(&shell.boards[0], Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 }, &mut shell.feed(&board));
    // Typed at genesis: the board is a tarpit that answers no state, and
    // what is under test is the probe's hand-over, never the frame's fate.
    let frame = json!({"op": "insert", "doc": "1.0.1.0.1", "at": {"subspace": "1", "ordinal": "1"}, "values": ["a"], "as_of": 0});
    let held = shell.holds.hold(&session, Burst::admit(frame, &session).unwrap(), Reason::of("stopped", false), None, 0).answered().unwrap();
    assert_eq!(held["resp"], "held", "{held}");
    let started = Instant::now();
    shell.set_node_state(NodeState::Running);
    let took = started.elapsed();
    assert!(took < Duration::from_millis(500), "`set_node_state(Running)` waited {took:?} on the board's probe");
    drop(shell);
}

/// Checks that the drop is the stop: a dropped shell frees its board's lock.
///
/// A shell dropped with a session open and never stopped closes the session
/// at its board — the token answers the death signal — joins its threads
/// and frees its board's held lock, so a second holder takes it (the mutant
/// whose stop leaves the token live at the board, and the one whose feed
/// threads outlive their shell holding the lock for the process's life).
#[test]
fn a_dropped_shell_frees_its_boards_held_lock() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let token = shell.sessions.get(&session).unwrap().token.clone();
    let term = shell.boards[0].board.board_term().unwrap().expect("H.1 stands on a claimed board");
    let held = HeldDir::new(&store, skep_search::Chain::from_bytes(term.chain));
    assert!(held.try_lock().unwrap().is_none(), "the open shell holds the board's held text");
    drop(shell);
    assert!(held.try_lock().unwrap().is_some(), "the dropped shell freed it");
    let fresh = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new());
    let answer = fresh.op(Some(&token), &skep_client::board::frames::key_set("1.0.1")).unwrap();
    assert!(matches!(answer, Answer::Closed), "the dropped shell closed its session at the board");
    sd.shutdown();
}

/// Checks that a board down at the open is fed from its first answer.
///
/// A shell opened while its board's port refuses — the feed's own first read
/// of it failing, which its `daemon` event says — the board started there
/// after, never replays the history before the shell could read it — every
/// `feed` row it emits lies past the position the board had reached before
/// the open — while the draft a signed session mints after is fed, from the
/// session's own open (the mutant that starts a board it could not read at 0
/// replays the board's whole feed to every subscriber).
#[test]
fn a_board_down_at_the_open_is_fed_from_its_first_answer() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let probe = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new());
    let before = probe.health().unwrap().log_position();
    sd.shutdown();
    let deadline = Instant::now() + Duration::from_secs(10);
    while probe.health().is_ok() {
        assert!(Instant::now() < deadline, "the stopped board still answers");
        thread::sleep(Duration::from_millis(20));
    }
    let (shell, _) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    // The feed thread reads `/health` once before it takes its first
    // command, so its `unreachable` says that read has failed.
    wait_for(&seen, |e| e.name == EventName::Daemon && e.data["state"] == "unreachable");
    let sd = spawn_at(&dir.path().join("board"), true, port);
    let board = shell.board_references().remove(0);
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let draft = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["addr"].as_str().unwrap().to_string();
    wait_for(&seen, |e| e.name == EventName::Feed && e.data["update"]["docs"] == json!([draft]));
    let replayed: Vec<Value> = seen.lock().unwrap().iter().filter(|e| e.name == EventName::Feed && e.data["update"]["at"].as_u64().is_none_or(|at| at <= before)).map(|e| e.data.clone()).collect();
    assert!(replayed.is_empty(), "the feed replayed the board's history up to {before}: {replayed:?}");
    shell.shutdown();
    sd.shutdown();
}
