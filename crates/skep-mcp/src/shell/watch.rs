//! The session the adapter's calls run under, watched, and what moves it.
//!
//! `SessionState` is the session every call names, or the one that died and
//! what its end left; `Death` is what a death's reason asks of it (`classify`),
//! or a refused open (`refused_reopen`, `refused_afresh`). `SessionWatch` holds
//! the state behind one door, `move_off`, which moves it off the session that
//! died only while the state still names that session, never off a stop, and
//! wakes every call waiting in `settled_within`. The drain moves it by a death
//! (`settle`), and the backend by a session it opens itself.
//!
//! The state's lock and its signal are private to this module, so the backend
//! moves the state through `move_off` alone, and every holder of the lock is a
//! method of `SessionWatch` in this file.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::Value;

/// The state of the session the adapter's calls run under.
///
/// Every variant carries a session's reference: the live one, or the one that
/// died and what its end left. The drain settles it by a death
/// (`SessionWatch::settle`), and a session the adapter opens itself moves it
/// too; nothing moves it off a stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SessionState {
    /// The session every call runs under.
    Open(String),
    /// The session that died with no re-open, the board not answering.
    ///
    /// The next call opens one.
    Lapsed(String),
    /// The session whose death stops the adapter.
    ///
    /// No call opens a session; a call still in flight runs under the
    /// reference that died, and the shell answers it.
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
    /// that met a board that did not answer: no session stands until the board
    /// answers and the next call opens one afresh. The adapter's own `closed`
    /// too.
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
                (Some(hand), Some(label)) => format!(" by the key {hand} ({label})"),
                (Some(hand), None) => format!(" by {hand}"),
                _ => String::new(),
            };
            Death::Stop(format!(
                "the key {} was retired at the board{hand}: your person stops you by retiring your key, and this adapter stops with it; no call is served",
                reason["fingerprint"].as_str().unwrap_or("this adapter signs with")
            ))
        }
        "blocked" => {
            Death::Stop(format!("the board's operator blocked this account's prefix (record {}): the session is gone and no call is served", reason["record"].as_str().unwrap_or("named by the board")))
        }
        "seeded" => Death::Stop(format!(
            "the account {} now holds a key set of its own, so the key enrolled above it opens it by reference no longer: start the adapter again with a key enrolled at that account",
            reason["account"].as_str().unwrap_or("this adapter acts as")
        )),
        "mode" => Death::Stop(format!("the board's mode moved to {} and ended the session; start the adapter again", reason["mode"].as_str().unwrap_or("another mode"))),
        "unreachable" | "closed" => Death::ServeOn,
        // A spelling skep-shell does not declare — the test below holds the
        // arms read here to its declaration — is served through, as the
        // unreachable board is.
        _ => Death::ServeOn,
    }
}

/// Returns what the restart arm's re-open, refused, asks of the adapter.
fn refused_reopen(refused: &str) -> Death {
    refused_open(refused, "the board restarted and refused this key at the re-open")
}

/// Returns what an open of the adapter's own, refused, asks of it.
pub(super) fn refused_afresh(refused: &str) -> Death {
    refused_open(refused, "the board refused this key the session this adapter opened afresh")
}

/// Returns what a refused open asks of the adapter.
///
/// The shell's re-open at a restart and a session the adapter opens afresh are
/// judged alike, by the refusal's name: a board that did not answer serves on,
/// as a death's `unreachable` arm does, and any other refusal stops the adapter
/// with `what`, naming the refusal.
fn refused_open(refused: &str, what: &str) -> Death {
    match refused {
        "unreachable" => Death::ServeOn,
        _ => Death::Stop(format!("{what} ({refused}): the session is gone and no call is served; fix what the refusal names and start the adapter again")),
    }
}

/// The session's state, and the signal each move of it raises.
///
/// It is the session the calls run under, watched: the drain settles it by a
/// death (`SessionWatch::settle`), and a session the adapter opens itself moves
/// it (`SessionWatch::move_off`); a call that met a death waits on it
/// (`SessionWatch::settled_within`), woken by the move.
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
    /// `SessionWatch` here, and none leaves the state half-moved by an unwind —
    /// each critical section clones, compares or assigns one whole
    /// `SessionState` — so a poisoned lock still guards the state as it stands,
    /// and no call fails for another's panic.
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
        let next = match &death {
            Death::Reopened(fresh) => SessionState::Open(fresh.clone()),
            Death::ServeOn => SessionState::Lapsed(died.to_string()),
            Death::Stop(_) => SessionState::Stopped(died.to_string()),
        };
        let moved = self.move_off(died, next);
        if let (true, Death::Stop(line)) = (moved, death) {
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
}
