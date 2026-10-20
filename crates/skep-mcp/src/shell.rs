//! The backend: the one module of the adapter that calls `skep-shell`.
//!
//! It opens the shell over the one board in the signed mode with the refusing
//! arm (`ArmConfig::Refuse`: no person is present, so every SECRET and CONSENT
//! moment is refused `person_required`), checks the board and the key as
//! `skep-dev serve` does, opens one signed content-scoped session for the
//! configured principal before any tool is served, and from then on supplies
//! that session's reference to every call that runs under it, and the board's
//! to the one call whose row names it, so no tool's arguments name either. The
//! references are the shell's opaque names (THE PIN of `client.md` §4b.1):
//! never a token, never a credential.
//!
//! **The session's life.** The calls run under one session, its state held here
//! (`SessionState`): the session every call names, or the one that died and
//! what its end left. A death signal the shell meets — at one of this adapter's
//! calls, or at the board's feed thread first — ends the session by the shell's
//! one sequence (`Sessions::end`), and on the restart arm the shell re-opens a
//! signed session silently under a fresh reference (AUTH-5.31), named in the
//! death's reason. That reason is emitted once, as `session-died`, and
//! [`Backend::drain`] alone settles the session's state by it. A call the shell
//! answers `session_died` or `session_ended` waits for the drain to settle it
//! (within `SETTLE_WAIT`), reading no reason itself and opening no second
//! session early, which would leave the shell's re-open adopted by nothing. It
//! is then reissued once under the session that stands, one it opens itself
//! where none does — the death executed nothing: the board refuses a dead token
//! before it runs the frame — save that a death the shell did not re-open is
//! the answer to the call that met it. A death the shell does not re-open — the
//! key retired (AUTH-5.28, AUTH-5.77), the account seeded, the prefix blocked,
//! or a restart whose re-open the board refused — stops the adapter: one plain
//! line naming the arm goes to the process's stop, and nothing more is served;
//! the person stops an agent by retiring its key, and the adapter's end is what
//! the agent's client sees. A board that does not answer is served through: no
//! session stands, every call answers its refusal, and the next call opens one
//! afresh once the board answers again, the board's refusal of it judged as a
//! refused re-open is.
//!
//! The bus is subscribed in `Backend::open` before the session opens, so no
//! death of it is emitted unheard, and drained on a thread of its own for the
//! process's life: an undrained subscriber's channel grows without bound
//! (`EventBus::emit` clones every event to every subscriber), and the one event
//! this adapter acts on is `session-died`; every other is read and dropped.

use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::sheet::render_inert;
use skep_client::store::KeyFacts;
use skep_client::Origin;
use skep_shell::{ArmConfig, Event, EventName, Fetched, Name, Refusal, SessionMode, Shell, ShellOptions, Talk};

/// The longest a call waits for the drain to settle a session the shell ended.
///
/// The drain settles the session's state by the death's `session-died`. The
/// shell's end derives its reason from the board and, on the restart arm,
/// re-opens over several exchanges, each under skep-client's dial bounds
/// (`CONNECT_TIMEOUT`, `IO_TIMEOUT`): milliseconds at a loopback board, seconds
/// at a far one. A call that opened its own session first would leave the
/// shell's re-open in the shell's table, adopted by nothing, so the call waits
/// for the drain and does not guess at it. The wait runs out only where an end
/// outlasts it or never reports — one that panicked — and the call then opens a
/// session itself.
const SETTLE_WAIT: Duration = Duration::from_secs(60);

/// The process's stop: it takes the plain line the adapter stops with.
///
/// `main` holds the other end, and its loop says the line and exits.
pub type OnStop = Arc<dyn Fn(String) + Send + Sync>;

/// The state of the session the adapter's calls run under.
///
/// Every variant carries a session's reference: the live one, or the one that
/// died and what its end left. The drain settles it by a death (`settle`), and
/// a session the adapter opens itself moves it too; nothing moves it off a
/// stop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionState {
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
enum Death {
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
fn classify(reason: &Value) -> Death {
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
fn refused_afresh(refused: &str) -> Death {
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

/// Returns whether `refusal` is the shell's own, named `named`.
fn is_shell(refusal: &Refusal, named: Name) -> bool {
    matches!(refusal, Refusal::Shell { name, .. } if *name == named)
}

/// Returns the line a refused startup check stops the adapter with.
///
/// It names what did not hold, then the shell's refusal in the library's own
/// words (`Refusal`'s `Display`), said once.
fn stopped_before_serving(what: &str, refusal: &Refusal) -> String {
    format!("stopped before serving: {what}: {refusal}")
}

/// The backend: the shell, and what the adapter holds beside it for the calls.
///
/// It holds the shell, the one board's reference, the one session's state, the
/// process's stop, and the facts `session_info` reports.
pub struct Backend {
    shell: Shell,
    /// The board's opaque reference, fixed at the open.
    board: String,
    origin: Origin,
    principal: u64,
    /// The principal's account, as the session's open answered it.
    account: Option<String>,
    /// Whether a write may go out under the session, as its open answered.
    writes: bool,
    /// The store's key the adapter signs with.
    key: KeyFacts,
    /// The session the calls run under.
    ///
    /// The drain settles it by a death's reason, and the call that opens a
    /// session itself moves it too.
    session: Arc<Mutex<SessionState>>,
    /// The process's stop, which every line that stops the adapter goes to.
    on_stop: OnStop,
    talk: Talk,
}

impl Backend {
    /// Opens the shell over the one board, checks it, and opens the session.
    ///
    /// The shell runs over `origin` in the signed mode with the refusing arm;
    /// the board's `/health` is read and said, the store's key for `principal`
    /// checked and said, and one signed session opened — before any tool is
    /// served — and said. The bus is subscribed before that session opens and
    /// drained from the open's end (`Backend::drain`), so no death of it goes
    /// unheard. Each line goes to `talk`, and `on_stop` is the process's stop,
    /// kept for the backend's life.
    ///
    /// # Errors
    ///
    /// The refusal the shell gave, in plain words, at the first check that
    /// refused: the board not answering; `no_key` or `store_unreadable` at
    /// the key; the session's armed names — `origin_state`, `not_registered`,
    /// `retired`, `not_enrolled`, `busy` — or the board's own. The shell is
    /// dropped before the error is returned, so its stop has run.
    pub fn open(origin: Origin, store_dir: PathBuf, principal: u64, talk: Talk, on_stop: OnStop) -> Result<Backend, String> {
        let mut options = ShellOptions::new(vec![origin.clone()], store_dir.clone(), SessionMode::Signed { principal }, Arc::clone(&talk));
        options.arm = ArmConfig::Refuse;
        // The person seam's name is read off the options the shell is opened
        // with, so the startup line says what the shell holds and never a
        // literal.
        let person_seam = match &options.arm {
            ArmConfig::Refuse => "refuse",
            ArmConfig::Auto => "auto",
            _ => "script",
        };
        let shell = Shell::open(options);
        // Subscribed before the session opens, so the drain hears every
        // death of it: the bus keeps nothing for a later subscriber.
        let events = shell.subscribe();
        let Some(board) = shell.board_references().into_iter().next() else {
            return Err("the shell opened no board".into());
        };
        let health = shell.call("health", &json!({"board": board})).map_err(|r| stopped_before_serving("the board did not answer", &r))?;
        let halted = if health["health"]["writes"]["halted"].as_bool() == Some(true) { "; writes HALTED: every write is refused `poisoned` until the board restarts" } else { "" };
        talk(&format!(
            "board {origin} (reference {board}): mode {} (claimant {}, local_trust {}){halted}",
            health["mode"].as_str().unwrap_or("?"),
            health["health"]["auth"]["claimant"].as_str().unwrap_or("null"),
            health["health"]["auth"]["local_trust"]
        ));
        let keys = shell.check_signed_key().map_err(|r| stopped_before_serving("no key to sign with", &r))?;
        let Some(key) = keys.into_iter().next() else {
            return Err("stopped before serving: the store selected no key".into());
        };
        let opened = shell.call("session", &json!({"board": board})).map_err(|r| stopped_before_serving("the signed session did not open", &r))?;
        let Some(reference) = opened["session"].as_str() else {
            return Err("stopped before serving: the session answer names no session".into());
        };
        let account = opened["account"].as_str().map(str::to_string);
        let writes = opened["writes"].as_bool().unwrap_or(false);
        talk(&format!(
            "signed as principal {principal} (account {}) with the key {} ({}) from {}: enrolled in that account's set or the nearest set above it; the person who enrolled it stops this adapter by retiring it",
            account.as_deref().unwrap_or("none"),
            key.fingerprint,
            key.label.as_deref().map(render_inert).unwrap_or_default(),
            store_dir.display()
        ));
        talk(&format!("person seam: {person_seam} — no secret or consent moment is answered here: no key or claim ceremony runs through this adapter"));
        let session = Arc::new(Mutex::new(SessionState::Open(reference.to_string())));
        let backend = Backend { shell, board, origin, principal, account, writes, key, session, on_stop, talk };
        backend.drain(events);
        Ok(backend)
    }

    fn say(&self, line: &str) {
        (self.talk)(line);
    }

    /// Reads the bus on a thread of its own for the process's life.
    ///
    /// `events` is the subscription `open` took before the session opened. A
    /// `session-died` of the session the calls run under carries that death's
    /// reason — the drain its one reader, which a call that met the death waits
    /// on — and the drain settles the session's state by it (`settle`): to the
    /// fresh session on the restart arm's re-open, to a lapse where the adapter
    /// serves on — each said — and to the stop on every other arm, its plain
    /// line handed to the stop. Every other event is read and dropped.
    fn drain(&self, events: Receiver<Event>) {
        let (session, talk, on_stop) = (Arc::clone(&self.session), Arc::clone(&self.talk), Arc::clone(&self.on_stop));
        thread::spawn(move || {
            for event in events {
                if event.name != EventName::SessionDied {
                    continue;
                }
                let Some(died) = event.data["session"].as_str() else { continue };
                let death = classify(&event.data["reason"]);
                let said = match &death {
                    Death::Reopened(_) => Some("the board restarted: the session was re-opened under a fresh reference, and every call is served under it"),
                    Death::ServeOn => {
                        Some("the session ended and was not re-opened (the board did not answer): every call answers its refusal, and the next call opens a session once the board answers again")
                    }
                    Death::Stop(_) => None,
                };
                if settle(&session, died, death, &on_stop) {
                    if let Some(line) = said {
                        talk(line);
                    }
                }
            }
        });
    }

    /// Opens a session afresh where the session `died` left none.
    ///
    /// The calls run under it once it opens. A refusal of it is judged as a
    /// refused re-open is (`refused_afresh`, by way of `refused_open`): a board
    /// that does not answer leaves the session's state lapsed, and any other
    /// refusal stops the adapter, its line naming this open handed to the stop.
    /// Where the drain settled the session's state while the session opened,
    /// the session is closed, so none stands that no call names.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the open.
    ///
    /// # Panics
    ///
    /// Where the shell's answer to the open names no session, which the
    /// `session` row's answer (`SessionOpened`) always does.
    fn open_afresh(&self, died: &str) -> Result<(), Refusal> {
        let fresh = match self.shell.call("session", &json!({"board": self.board})) {
            Ok(opened) => opened["session"].as_str().expect("the shell's session answer names its session").to_string(),
            Err(refusal) => {
                settle(&self.session, died, refused_afresh(refusal.name()), &self.on_stop);
                return Err(refusal);
            }
        };
        if swap(&self.session, died, SessionState::Open(fresh.clone())) {
            self.say("the session had ended with no re-open: a session was opened afresh, and the call is served under it");
        } else {
            let _ = self.shell.call("close", &json!({"session": fresh}));
        }
        Ok(())
    }

    /// Runs one attempt under the session, and the session's life around it.
    ///
    /// The session is the one the calls run under. Where the last session
    /// lapsed, one is opened first (`open_afresh`); where the adapter has
    /// stopped, the attempt runs under the reference that died, and the shell
    /// answers it. An attempt the shell answers `session_died` or
    /// `session_ended` met an end the shell ran, which the drain settles: the
    /// call waits for that (`settled_within`), opens a session itself where it
    /// never comes, and is reissued once under what stands then — save that a
    /// death the shell did not re-open is the call's answer. Every other answer
    /// is the attempt's own, and a second death is answered as it stands.
    ///
    /// # Errors
    ///
    /// The attempt's refusal, or the shell's refusal of a session the
    /// adapter opened itself.
    fn under_session<T>(&self, attempt: impl Fn(&str) -> Result<T, Refusal>) -> Result<T, Refusal> {
        let mut reissued = false;
        loop {
            let state = self.session.lock().expect("the session state's lock").clone();
            let reference = match state {
                SessionState::Open(reference) => reference,
                SessionState::Lapsed(died) => {
                    self.open_afresh(&died)?;
                    continue;
                }
                SessionState::Stopped(died) => return attempt(&died),
            };
            let outcome = attempt(&reference);
            let Err(refusal) = &outcome else { return outcome };
            let met_death = is_shell(refusal, Name::SESSION_DIED);
            let met_end = is_shell(refusal, Name::SESSION_ENDED);
            if reissued || !(met_death || met_end) {
                return outcome;
            }
            // The shell ran the session's end, and the drain settles the
            // session's state by its `session-died`: wait for that, opening a
            // session where it never comes.
            if !settled_within(&self.session, &reference, SETTLE_WAIT) {
                self.open_afresh(&reference)?;
            }
            // A death the shell did not re-open is the call's answer.
            if met_death && !matches!(&*self.session.lock().expect("the session state's lock"), SessionState::Open(_)) {
                return outcome;
            }
            reissued = true;
        }
    }

    /// Returns the shell's `boards()`: the one board it holds.
    ///
    /// The answer is `[{board, name, origin}]`; the row takes no member.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the call, where it gives one.
    pub fn boards(&self) -> Result<Value, Refusal> {
        self.shell.call("boards", &json!({}))
    }

    /// Returns the shell's `health(board)` of the adapter's one board.
    ///
    /// The answer is the board's `/health` reading verbatim with its derived
    /// mode: a live reading with no address of its own, not the published head
    /// document that records its pair (wire.md §The other endpoints). The
    /// board's reference is supplied.
    ///
    /// # Errors
    ///
    /// The unreachable board, or the board's refusal of the read.
    pub fn health(&self) -> Result<Value, Refusal> {
        self.shell.call("health", &json!({"board": self.board}))
    }

    /// Returns the shell's `probe()`: whether the board answers.
    ///
    /// The answer names the board's state and the origins it is dialed and
    /// signed at; the row takes no member.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the call, where it gives one.
    pub fn probe(&self) -> Result<Value, Refusal> {
        self.shell.call("probe", &json!({}))
    }

    /// Makes a call of the shell's under the adapter's one session.
    ///
    /// The calls are `op`, `search`, `places`, `held`, `resolve` and
    /// `changes`, the session's reference supplied beside the call's own
    /// members. A row whose session form takes a board too (`search`,
    /// `places`) reads at the session's own where none is given, which is
    /// this adapter's one board.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the call, after the session's life has been
    /// run around it (`under_session`): the board's verdict, the unreachable
    /// board, a halt, or the shell's own by name — `session_died` with the
    /// reason where the death was not re-opened, `session_ended` where the
    /// adapter has stopped or a reissue met a second end — or the shell's
    /// refusal of a session the adapter opened itself.
    pub fn session_call(&self, name: &str, args: Value) -> Result<Value, Refusal> {
        self.under_session(|session| {
            let mut args = args.clone();
            args["session"] = Value::from(session);
            self.shell.call(name, &args)
        })
    }

    /// Fetches the board's bytes at the address `i` names, under the session.
    ///
    /// `i` goes to the shell as the agent gave it: the shell refuses one that
    /// is no address in its one spelling, as it refuses every row's argument.
    /// The answer is the shell's streamed fetch, its head and its body still
    /// unread, which [`read_whole`](crate::media::read_whole) reads under the
    /// adapter's cap.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the fetch: `malformed_args` naming `i`; the
    /// board's verdict on the address (`withheld`, `not_a_cell`, `no_value`,
    /// `blob_missing`, …) under its own status; the unreachable board; or the
    /// session's end as `session_call` carries it.
    pub fn fetch(&self, i: &Value) -> Result<Fetched, Refusal> {
        self.under_session(|session| self.shell.fetch(&json!({"session": session, "i": i})))
    }

    /// Returns the URI of the board's bytes at the address `i`.
    ///
    /// It is the route the shell's fetch dials, `GET /blob?i=<i>` at the
    /// board's origin (wire.md §Media, THE FETCH), which a resource block
    /// names.
    pub fn blob_uri(&self, i: &str) -> String {
        format!("{}/blob?i={i}", self.origin.as_str())
    }

    /// `session_info`: the principal, its account, the signing key's
    /// fingerprint and label, the board's origin, `writes`, and the board's
    /// `health` with its derived `mode` — the shell's `health` call, made now.
    ///
    /// # Errors
    ///
    /// The health call's refusal: the unreachable board, or a halt.
    pub fn session_info(&self) -> Result<Value, Refusal> {
        let health = self.health()?;
        Ok(json!({
            "principal": self.principal,
            "account": self.account,
            "key": {"fingerprint": self.key.fingerprint.to_hex(), "label": self.key.label.as_deref().map(render_inert)},
            "board": self.origin.as_str(),
            "writes": self.writes,
            "mode": health["mode"],
            "health": health["health"],
        }))
    }

    /// THE CLEAN STOP: the shell's — every session closed at the board,
    /// every index saved, the feed threads joined.
    pub fn shutdown(&self) {
        self.shell.shutdown();
    }
}

/// Settles the session `died` by what its death, or a refused open, asks.
///
/// The session's state moves where it may (`swap`): to the fresh session on the
/// restart arm's re-open, to a lapse where the adapter serves on, and to the
/// stop on every other arm, whose line then goes to `on_stop`. Returns whether
/// this caller moved it; a death of a session the state has left, or settled a
/// second time, moves nothing, so a stop's line is said once.
fn settle(state: &Mutex<SessionState>, died: &str, death: Death, on_stop: &OnStop) -> bool {
    let next = match &death {
        Death::Reopened(fresh) => SessionState::Open(fresh.clone()),
        Death::ServeOn => SessionState::Lapsed(died.to_string()),
        Death::Stop(_) => SessionState::Stopped(died.to_string()),
    };
    let moved = swap(state, died, next);
    if let (true, Death::Stop(line)) = (moved, death) {
        on_stop(line);
    }
    moved
}

/// Returns whether the drain settled the session `died` within `wait`.
///
/// It looks every twenty milliseconds for the session's state to move off
/// `died` — to a fresh session, a lapse or the stop alike.
fn settled_within(state: &Mutex<SessionState>, died: &str, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if !matches!(&*state.lock().expect("the session state's lock"), SessionState::Open(reference) if reference == died) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Moves the session's state off the session `died` to `next`, where it may.
///
/// It may where the state still names `died`, live or lapsed, and differs from
/// `next`: a stop is never moved off, and a state that has moved on to another
/// session is left alone. Returns whether this caller moved it.
fn swap(state: &Mutex<SessionState>, died: &str, next: SessionState) -> bool {
    let mut current = state.lock().expect("the session state's lock");
    let names_it = matches!(&*current, SessionState::Open(reference) | SessionState::Lapsed(reference) if reference == died);
    if names_it && *current != next {
        *current = next;
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

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
        let state = Mutex::new(SessionState::Open("s-old".to_string()));
        assert!(swap(&state, "s-old", SessionState::Open("s-new".into())));
        assert!(!swap(&state, "s-old", SessionState::Open("s-other".into())), "the second caller finds it moved");
        assert!(!swap(&state, "s-old", SessionState::Lapsed("s-old".into())), "a death of a session the state left moves nothing");
        assert!(swap(&state, "s-new", SessionState::Lapsed("s-new".into())), "a death no one re-opened lapses it");
        assert!(!swap(&state, "s-new", SessionState::Lapsed("s-new".into())), "the same death settled twice moves it once");
        assert!(swap(&state, "s-new", SessionState::Open("s-late".into())), "a late re-open of the lapsed session is adopted");
        assert!(swap(&state, "s-late", SessionState::Stopped("s-late".into())));
        for next in [SessionState::Open("s-after".into()), SessionState::Lapsed("s-late".into())] {
            assert!(!swap(&state, "s-late", next), "nothing moves the state off a stop");
        }
        assert_eq!(*state.lock().unwrap(), SessionState::Stopped("s-late".into()));
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
        let said = Arc::new(Mutex::new(Vec::new()));
        let on_stop: OnStop = {
            let said = Arc::clone(&said);
            Arc::new(move |line: String| said.lock().unwrap().push(line))
        };
        let state = Mutex::new(SessionState::Open("s-1".into()));
        assert!(settle(&state, "s-1", Death::Reopened("s-2".into()), &on_stop));
        assert!(!settle(&state, "s-1", Death::Reopened("s-2".into()), &on_stop), "the second finds it settled");
        assert!(settle(&state, "s-2", Death::ServeOn, &on_stop));
        assert_eq!(*state.lock().unwrap(), SessionState::Lapsed("s-2".into()));
        assert!(settle(&state, "s-2", refused_afresh("retired"), &on_stop), "a refused open stops a lapsed state");
        assert!(!settle(&state, "s-2", refused_afresh("retired"), &on_stop));
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
    /// A death settled a moment later ends it — a lapse or a stop as surely as
    /// a re-open — and with none settled the wait runs out at its bound.
    #[test]
    fn the_wait_to_settle_ends_as_the_session_state_moves() {
        for death in [Death::Reopened("s-2".into()), Death::ServeOn, Death::Stop("stopped".into())] {
            let state = Arc::new(Mutex::new(SessionState::Open("s-1".into())));
            let settler = {
                let state = Arc::clone(&state);
                let on_stop: OnStop = Arc::new(|_: String| {});
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(100));
                    settle(&state, "s-1", death, &on_stop)
                })
            };
            let started = Instant::now();
            assert!(settled_within(&state, "s-1", Duration::from_secs(30)), "the settling ends the wait");
            assert!(started.elapsed() < Duration::from_secs(10), "as the state moves: {:?}", started.elapsed());
            assert!(settler.join().expect("the settler"), "the settler moved it");
        }
        let state = Mutex::new(SessionState::Open("s-1".into()));
        assert!(!settled_within(&state, "s-1", Duration::from_millis(100)), "with nothing settled the wait runs out");
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
}
