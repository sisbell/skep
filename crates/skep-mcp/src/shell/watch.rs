//! The session the adapter's calls run under, watched, and what moves it.
//!
//! `SessionState` is the session every call names, or the one that died and
//! what its end left; `Death` is what a death's reason asks of it (`classify`),
//! or a refused open (`refused_reopen`, `refused_afresh`), and `lapse_cause`
//! why a death that leaves the adapter serving on left no session.
//! `SessionWatch` holds the state behind one door, `move_off`, which moves it
//! off the session that died only while the state still names that session,
//! never off a stop, and wakes every call waiting in `settled_within`. The
//! drain moves it by a death (`settle`), and the backend by a session it opens
//! itself (`move_off`) or by a refusal of one (`settle`).
//!
//! The state's lock and its signal are private to this module, so the backend
//! moves the state through `move_off` alone, and every holder of the lock is a
//! method of `SessionWatch` in this file, save the unit test that poisons it.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::Value;

/// The state of the session the adapter's calls run under.
///
/// Every variant carries a session's reference: the live one, or the one that
/// died and what its end left. The drain settles it by a death
/// (`SessionWatch::settle`); the backend moves it to a session it opens
/// itself, or settles it by a refusal of that open; nothing moves it off a
/// stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SessionState {
    /// The session every call runs under.
    Open(String),
    /// The session that died with no re-open, the adapter serving on.
    ///
    /// Its end, or an open of the adapter's own that followed it, asked
    /// `Death::ServeOn`: it met a board that did not answer, or one that did
    /// not accept the sign-in (`busy`), or was of another arm that serves on.
    /// The next call that runs under a session tries to open one.
    Lapsed(String),
    /// The session whose end stops the adapter.
    ///
    /// The end is a death the shell did not re-open, or a refusal of the
    /// session the adapter opened in its place. No call opens a session; a
    /// call still in flight runs under the reference that died, and the shell
    /// answers it.
    Stopped(String),
}

/// What a death's reason, or a refused open, asks of the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Death {
    /// The restart arm re-opened the session: the fresh reference.
    Reopened(String),
    /// No session stands, and the adapter serves on.
    ///
    /// The `unreachable` arm, and a re-open or an open of the adapter's own
    /// that met a board that did not answer, or did not accept the sign-in
    /// (`busy`): no session stands until a call opens one afresh. The
    /// adapter's own `closed` too, a re-open whose reason names no fresh
    /// reference, and an arm skep-shell does not declare.
    ServeOn,
    /// A death not re-opened, or a refused open: the plain line the stop says.
    Stop(String),
}

/// Reads a death's reason (the shell's `DeathReason`) for what it asks.
pub(super) fn classify(reason: &Value) -> Death {
    let arm = reason["arm"].as_str().unwrap_or("");
    match arm {
        "restart" if reason["reopened"] == true => match reason["session"].as_str() {
            Some(fresh) => Death::Reopened(fresh.to_string()),
            None => Death::ServeOn,
        },
        "restart" => refused_reopen(reason["refused"].as_str().unwrap_or("refused")),
        "retired" => {
            let hand = match (reason["hand"].as_str(), reason["label"].as_str()) {
                (Some("bare"), _) => " by a bare session".to_string(),
                (Some(hand), Some(label)) => format!(" by the key {hand} ({label})"),
                (Some(hand), None) => format!(" by the key {hand}"),
                (None, _) => String::new(),
            };
            let landed = reason["position"].as_u64().map(|position| format!(" (its retirement landed at position {position})")).unwrap_or_default();
            Death::Stop(format!(
                "the key {} was retired at the board{hand}: the person who enrolled it stops this agent so{landed}, and the adapter stops with it — a relaunch over this store is refused `retired` until the person gives the agent a key enrolled anew (`skep keygen`, `skep enroll`, `skep bind`)",
                reason["fingerprint"].as_str().unwrap_or("this adapter signs with")
            ))
        }
        "blocked" => Death::Stop(format!(
            "the board's operator blocked this account's prefix (record {}): the session is gone and no call is served — the block stands until the board's operator lifts it, and a relaunch is refused until then",
            reason["record"].as_str().unwrap_or("named by the board")
        )),
        "seeded" => {
            let first = match (reason["writer"].as_str(), reason["as_of"].as_u64()) {
                (Some(writer), Some(as_of)) => format!(" (its first key {writer}, as of position {as_of})"),
                (Some(writer), None) => format!(" (its first key {writer})"),
                (None, Some(as_of)) => format!(" (as of position {as_of})"),
                (None, None) => String::new(),
            };
            Death::Stop(format!(
                "the account {} now holds a key set of its own{first}, so the key enrolled above it opens it by reference no longer: start the adapter again with a key enrolled at that account",
                reason["account"].as_str().unwrap_or("this adapter acts as")
            ))
        }
        "mode" => Death::Stop(format!("the board's mode moved to {} and ended the session; start the adapter again", reason["mode"].as_str().unwrap_or("another mode"))),
        "unreachable" | "closed" => Death::ServeOn,
        // A spelling skep-shell does not declare — the test below holds the
        // arms read here to its declaration — is served through, as the
        // unreachable board is.
        _ => Death::ServeOn,
    }
}

/// Returns why a death that leaves the adapter serving on left no session.
///
/// It is read off the death's reason, as `classify` reads the arm: the board
/// did not answer the end's read, its text the client's own; the board
/// restarted and did not answer the re-open, or did not accept its sign-in;
/// or the arm itself, where another served on, or that the end named none.
pub(super) fn lapse_cause(reason: &Value) -> String {
    match (reason["arm"].as_str(), reason["refused"].as_str()) {
        (Some("unreachable"), _) => match reason["text"].as_str() {
            Some(text) => format!("the board did not answer: {text}"),
            None => "the board did not answer".to_string(),
        },
        (Some("restart"), Some("unreachable")) => "the board restarted, and did not answer the re-open".to_string(),
        (Some("restart"), Some("busy")) => {
            "the board restarted, and did not accept the re-open's sign-in twice in a row (busy): it may be busy, or a third party is evicting nonces (AUTH-5.26)".to_string()
        }
        (Some(arm), _) => format!("its end's arm was {arm}"),
        (None, _) => "its end named no arm".to_string(),
    }
}

/// Which open of a session was refused, as a stop's line names it.
#[derive(Debug, Clone, Copy)]
enum Opening {
    /// The shell's re-open at a board's restart (AUTH-5.31).
    Reopen,
    /// A session the adapter opened afresh, where a death left none.
    Afresh,
}

impl Opening {
    /// Returns the open, refused by the board, as a stop's line names it.
    fn refused_by_the_board(self) -> &'static str {
        match self {
            Opening::Reopen => "the board restarted and refused this key at the re-open",
            Opening::Afresh => "the board refused this key the session this adapter opened afresh",
        }
    }

    /// Returns the open, as a stop's line places a store's fault in it.
    fn at(self) -> &'static str {
        match self {
            Opening::Reopen => "at the re-open after the board restarted",
            Opening::Afresh => "at the session this adapter opened afresh",
        }
    }
}

/// Returns what the restart arm's re-open, refused, asks of the adapter.
fn refused_reopen(refused: &str) -> Death {
    refused_open(refused, Opening::Reopen)
}

/// Returns what an open of the adapter's own, refused, asks of it.
pub(super) fn refused_afresh(refused: &str) -> Death {
    refused_open(refused, Opening::Afresh)
}

/// Returns what a refused open asks of the adapter.
///
/// The shell's re-open at a restart and a session the adapter opens afresh are
/// judged alike, by the refusal's name. A board that did not answer, or did
/// not accept the sign-in twice in a row (`busy`, skep-client's terminal busy
/// arm, transient by its own face: AUTH-5.25, AUTH-5.26), serves on, as a
/// death's `unreachable` arm does. A key store that could not give the open
/// its key (`no_key`, `store_unreadable`) stops the adapter naming the store
/// under `--dir`, never the board; any other refusal stops it naming the
/// refusal as the board's.
fn refused_open(refused: &str, opening: Opening) -> Death {
    match refused {
        "unreachable" | "busy" => Death::ServeOn,
        "no_key" | "store_unreadable" => Death::Stop(format!(
            "{}, this adapter's key store could not give the session its key ({refused}) — the store under --dir, not the board: the session is gone and no call is served; fix the store and start the adapter again",
            opening.at()
        )),
        _ => Death::Stop(format!(
            "{} ({refused}): the session is gone and no call is served; fix what the refusal names and start the adapter again",
            opening.refused_by_the_board()
        )),
    }
}

/// The session's state, and the signal each move of it raises.
///
/// It is the session the calls run under, watched: the drain settles it by a
/// death (`SessionWatch::settle`), and the backend moves it to a session it
/// opens itself (`SessionWatch::move_off`) or settles it by a refusal of that
/// open; a call that met a death waits on it (`SessionWatch::settled_within`),
/// woken by the move.
#[derive(Debug)]
pub(super) struct SessionWatch {
    state: Mutex<SessionState>,
    /// Raised on every move of `state`.
    moved: Condvar,
}

impl SessionWatch {
    /// Returns the watch over the session open under `reference`.
    pub(super) fn new(reference: String) -> SessionWatch {
        SessionWatch { state: Mutex::new(SessionState::Open(reference)), moved: Condvar::new() }
    }

    /// Locks the session's state, poisoned or not.
    ///
    /// The lock is private to this module, so its every holder is a method of
    /// `SessionWatch` here, save the unit test that poisons it, and none leaves
    /// the state half-moved by an unwind — each critical section clones,
    /// compares or assigns one whole `SessionState` — so a poisoned lock still
    /// guards the state as it stands, and no call fails for another's panic.
    fn lock(&self) -> MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the session's state as it stands.
    pub(super) fn current(&self) -> SessionState {
        self.lock().clone()
    }

    /// Moves the session's state off the session `died` to `next`, if it may.
    ///
    /// It may where the state still names `died`, live or lapsed, and differs
    /// from `next`: a stop is never moved off, and a state that has moved on to
    /// another session is left alone. A move wakes every call waiting in
    /// `settled_within`. Returns whether this caller moved it.
    pub(super) fn move_off(&self, died: &str, next: SessionState) -> bool {
        let mut current = self.lock();
        let names_it = matches!(&*current, SessionState::Open(reference) | SessionState::Lapsed(reference) if reference == died);
        if names_it && *current != next {
            *current = next;
            self.moved.notify_all();
            true
        } else {
            false
        }
    }

    /// Settles the session `died` by what its death, or a refused open, asks.
    ///
    /// The session's state moves where it may (`move_off`): to the fresh
    /// session on the restart arm's re-open, to a lapse where the adapter
    /// serves on, and to the stop on every other arm, whose line then goes to
    /// `on_stop`. Returns whether this caller moved it; a death of a session
    /// the state has left, or settled a second time, moves nothing, so a stop's
    /// line is said once.
    pub(super) fn settle(&self, died: &str, death: Death, on_stop: &dyn Fn(String)) -> bool {
        let (next, line) = match death {
            Death::Reopened(fresh) => (SessionState::Open(fresh), None),
            Death::ServeOn => (SessionState::Lapsed(died.to_string()), None),
            Death::Stop(line) => (SessionState::Stopped(died.to_string()), Some(line)),
        };
        let moved = self.move_off(died, next);
        if let (true, Some(line)) = (moved, line) {
            on_stop(line);
        }
        moved
    }

    /// Returns whether the drain settled the session `died` within `wait`.
    ///
    /// It sleeps until the state moves off `died` — to a fresh session, a lapse
    /// or the stop alike — woken by `move_off`, or until `wait` runs out.
    pub(super) fn settled_within(&self, died: &str, wait: Duration) -> bool {
        let names_died = |state: &mut SessionState| matches!(&*state, SessionState::Open(reference) if reference == died);
        let (_state, waited) = self.moved.wait_timeout_while(self.lock(), wait, names_died).unwrap_or_else(PoisonError::into_inner);
        !waited.timed_out()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;

    use serde_json::json;

    use super::*;

    /// Checks that each arm of a death's reason asks one thing.
    ///
    /// The restart's re-open names the fresh reference; a restart the board
    /// refused, a retirement, a block, a seeding and a mode flip each stop
    /// with a line naming the arm's fact — a retirement its hand, a bare
    /// session's or a key's, and the position it landed at, a seeding its
    /// first key and position, a re-open the key store failed the store, not
    /// the board; the unreachable board, a re-open that met a board that did
    /// not answer or did not accept its sign-in, the adapter's own close, a
    /// re-open that names no fresh reference and a spelling no arm has serve
    /// on, each lapse but those last two said with its cause. The arms the
    /// cases name are exactly the ones skep-shell declares for a death's
    /// reason (`shapes::shape`), so an arm the shell adds or renames fails
    /// here before `classify`'s wildcard serves a death of it through.
    #[test]
    fn every_arm_of_a_death_asks_one_thing() {
        assert_eq!(classify(&json!({"arm": "restart", "reopened": true, "session": "s-fresh"})), Death::Reopened("s-fresh".into()));
        let stops = [
            (json!({"arm": "restart", "reopened": false, "refused": "origin_state"}), "origin_state"),
            (
                json!({"arm": "restart", "reopened": false, "refused": "store_unreadable"}),
                "at the re-open after the board restarted, this adapter's key store could not give the session its key (store_unreadable) — the store under --dir, not the board",
            ),
            (json!({"arm": "retired", "fingerprint": "ab12", "hand": "cd34", "label": "second", "position": 9, "own": false}), "stops this agent so (its retirement landed at position 9)"),
            (json!({"arm": "retired", "fingerprint": "ab12", "hand": "bare", "position": 9}), "retired at the board by a bare session"),
            (json!({"arm": "retired", "fingerprint": "ab12", "hand": "cd34"}), "retired at the board by the key cd34: "),
            (json!({"arm": "blocked", "record": "1.0.1.0.7.1", "ground": null}), "1.0.1.0.7.1"),
            (json!({"arm": "seeded", "account": "1.0.1.1", "as_of": 9, "writer": null}), "1.0.1.1 now holds a key set of its own (as of position 9)"),
            (json!({"arm": "seeded", "account": "1.0.1.1", "as_of": 9, "writer": "ef56"}), "of its own (its first key ef56, as of position 9)"),
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
        assert!(line.contains("a relaunch over this store is refused `retired`"), "the act that clears it: {line}");
        for (reason, cause) in [
            (json!({"arm": "unreachable", "text": "connect refused"}), "the board did not answer: connect refused"),
            (json!({"arm": "restart", "reopened": false, "refused": "unreachable"}), "the board restarted, and did not answer the re-open"),
            (
                json!({"arm": "restart", "reopened": false, "refused": "busy"}),
                "the board restarted, and did not accept the re-open's sign-in twice in a row (busy): it may be busy, or a third party is evicting nonces (AUTH-5.26)",
            ),
            (json!({"arm": "closed"}), "its end's arm was closed"),
        ] {
            assert_eq!(lapse_cause(&reason), cause, "{reason}");
        }
        let Death::Stop(line) = classify(&json!({"arm": "blocked", "record": "1.0.1.0.7.1"})) else { panic!() };
        assert!(line.contains("until the board's operator lifts it"), "the act that clears it: {line}");
        let serve_on = [
            json!({"arm": "unreachable", "text": "connect refused"}),
            json!({"arm": "restart", "reopened": false, "refused": "unreachable"}),
            json!({"arm": "restart", "reopened": false, "refused": "busy"}),
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

    /// Checks that the state moves off a session once, and never off a stop.
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

    /// Checks that a death is settled once, its stop's line handed on once.
    ///
    /// A death settled a second time — a `session-died` heard twice, a refused
    /// open judged twice — moves nothing: the first to settle it moves the
    /// session's state and hands the stop its line, alone. A refused open stops
    /// a lapsed state as a stopping death stops an open one, and the two
    /// refused opens — the shell's re-open, the adapter's own — each name the
    /// open refused, the adapter's own names a key store that failed it as the
    /// store, and the two agree that a board that does not answer, or does not
    /// accept the sign-in, serves on.
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
        let Death::Stop(line) = refused_afresh("no_key") else { panic!("an open the key store failed stops") };
        assert!(line.starts_with("at the session this adapter opened afresh, this adapter's key store could not give the session its key (no_key)"), "{line}");
        assert_eq!(refused_reopen("unreachable"), Death::ServeOn, "a board that does not answer serves on");
        assert_eq!(refused_afresh("unreachable"), Death::ServeOn, "a board that does not answer serves on, whoever opened");
        assert_eq!(refused_reopen("busy"), Death::ServeOn, "a sign-in the board did not accept serves on");
        assert_eq!(refused_afresh("busy"), Death::ServeOn, "a sign-in the board did not accept serves on, whoever opened");
    }

    /// Checks that the wait ends as the drain settles the session.
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

    /// Checks that a panic under the lock leaves the state standing and moving.
    ///
    /// A holder that panics poisons the lock; the state still reads as it
    /// stood, still moves off its session, and a wait still reads the move:
    /// no call fails for another's panic.
    #[test]
    fn a_poisoned_lock_still_guards_the_session_state() {
        let watch = Arc::new(SessionWatch::new("s-1".into()));
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = watch.lock();
            panic!("a holder of the lock panics");
        }));
        assert!(panicked.is_err() && watch.state.is_poisoned(), "premise: the lock is poisoned");
        assert_eq!(watch.current(), SessionState::Open("s-1".into()), "the state reads as it stood");
        let settler = {
            let watch = Arc::clone(&watch);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                watch.move_off("s-1", SessionState::Lapsed("s-1".into()))
            })
        };
        assert!(watch.settled_within("s-1", Duration::from_secs(10)), "a wait reads the move");
        assert!(settler.join().expect("the settler"), "the state still moves");
        assert_eq!(watch.current(), SessionState::Lapsed("s-1".into()));
    }
}
