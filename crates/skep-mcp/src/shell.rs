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
//! never a token, never a credential. Every session it opens goes through one
//! door, `open_session`, the one reader of the row's answer, whose refusal
//! carries no answer's text, since the answer to `POST /session` carries the
//! token.
//!
//! **The session's life.** The calls run under one session, its state held in
//! the child `watch` (`SessionState`, in a `SessionWatch` that wakes a waiting
//! call when it moves): the session every call names, or the one that died and
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

mod watch;

use std::fmt;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::{json, Map, Value};
use skep_client::address::is_address_text;
use skep_client::sheet::render_inert;
use skep_client::store::KeyFacts;
use skep_client::{DialError, Origin};
use skep_shell::{ArmConfig, Event, EventName, Fetched, Name, Refusal, SessionMode, Shell, ShellOptions, Talk};

use self::watch::{classify, refused_afresh, Death, SessionState, SessionWatch};

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

/// The process's stop: it hands on the plain line the adapter stops with.
///
/// The backend stops the adapter at most once in its life, since the
/// session's state never moves off a stop, and with no lock held: from the
/// drain's thread, where a death's reason asks the stop (`classify`), or from
/// the thread making a call, where the board refused the fresh session that
/// call needed (`Backend::open_afresh`). That thread may be the very loop
/// that takes the line, so the stop must never wait, and an unbounded
/// channel's sender alone builds one (`OnStop::new`): its send returns at
/// once, where a send into a bounded channel full of stdin's lines would hold
/// the one thread that empties it.
#[derive(Clone)]
pub struct OnStop(Arc<dyn Fn(String) + Send + Sync>);

impl OnStop {
    /// Returns the stop that sends its line on `sender`, as `wrap` makes it.
    ///
    /// `sender` is an unbounded channel's (`mpsc::channel`; a bounded one's
    /// `SyncSender` is refused by its type), so the send never waits; a line
    /// sent once the receiver has gone is dropped, no one being left to say
    /// it.
    pub fn new<T: Send + 'static>(sender: Sender<T>, wrap: fn(String) -> T) -> OnStop {
        OnStop(Arc::new(move |line| {
            let _ = sender.send(wrap(line));
        }))
    }

    /// Hands `line` on, for the receiver's holder to say and stop with.
    fn stop(&self, line: String) {
        (self.0)(line);
    }
}

impl fmt::Debug for OnStop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OnStop").finish_non_exhaustive()
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

/// A session the shell opened, as its `session` row answers it.
///
/// The answer is skep-shell's `SessionOpened`: the fresh reference, the
/// principal's account where the board named one, and whether a write may go
/// out under the session.
#[derive(Debug)]
struct SessionOpened {
    /// The session's opaque reference, in the token's place.
    reference: String,
    /// The principal's account, where the board named one.
    account: Option<String>,
    /// Whether a write may go out under the session.
    writes: bool,
}

/// Opens a session at the board `board` names: the shell's `session` row.
///
/// It is the one way this adapter opens a session — at startup, and afresh
/// where a death left none — and the one reader of the row's answer, so every
/// refusal of an open it reads comes back `unquoted`.
///
/// # Errors
///
/// The shell's refusal of the open, with no answer's text in it.
///
/// # Panics
///
/// Where the answer is no `SessionOpened` — a `session` string and a
/// `writes` boolean — which skep-shell's row always answers.
fn open_session(shell: &Shell, board: &str) -> Result<SessionOpened, Refusal> {
    let opened = shell.call("session", &json!({"board": board})).map_err(unquoted)?;
    let promised = "the shell's `session` row answers `SessionOpened`";
    Ok(SessionOpened {
        reference: opened["session"].as_str().expect(promised).to_string(),
        account: opened["account"].as_str().map(str::to_string),
        writes: opened["writes"].as_bool().expect(promised),
    })
}

/// Returns a refusal of a session's open with no answer's text in it.
///
/// The open reads the answer to `POST /session` (AUTH-6.2), whose body
/// carries the session's token, and the client's refusal of an answer it
/// cannot read quotes that answer: a `200` an intermediary re-framed, or cut
/// short with no length to catch it, comes back as a dial fault quoting a
/// live token — a bearer credential this adapter would hand the agent in a
/// tool result, and whoever reads its log in a line of it. So a dial fault
/// stands only where its variant names the fault and no answer's bytes; any
/// other — a malformed answer, or a variant this crate does not know — is
/// replaced by one sentence, `UNQUOTED`. The refusal's kind and name stand,
/// and the open is judged by them (`refused_open`), never by its text.
fn unquoted(refusal: Refusal) -> Refusal {
    match refusal {
        Refusal::Unreachable(dial) => Refusal::Unreachable(match dial {
            DialError::NotHeld(_)
            | DialError::Resolve(_)
            | DialError::Connect(_)
            | DialError::Timeout(_)
            | DialError::Io(_)
            | DialError::Truncated { .. }
            | DialError::TooLarge { .. }
            | DialError::Tls(_)
            | DialError::Request(_) => dial,
            _ => DialError::Response(UNQUOTED.to_string()),
        }),
        other => other,
    }
}

/// The text that stands in for a dial fault that may quote an answer.
///
/// A refusal of a session's open carries it where `unquoted` replaces one.
const UNQUOTED: &str = "the session's open met an answer this client could not read; its text is not shown, since the answer to `POST /session` carries the session's token";

/// The backend: the shell, and what the adapter holds beside it for the calls.
///
/// It holds the shell, the one board's reference, the one session's state, the
/// process's stop, and the facts `session_info` reports; its `Debug` shows all
/// but the TALK sink, a bare closure.
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
    /// The session the calls run under, watched.
    ///
    /// The drain settles it by a death's reason, and the call that opens a
    /// session itself moves it too.
    session: Arc<SessionWatch>,
    /// The process's stop, which every line that stops the adapter goes to.
    on_stop: OnStop,
    talk: Talk,
}

impl fmt::Debug for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Backend")
            .field("shell", &self.shell)
            .field("board", &self.board)
            .field("origin", &self.origin)
            .field("principal", &self.principal)
            .field("account", &self.account)
            .field("writes", &self.writes)
            .field("key", &self.key)
            .field("session", &self.session)
            .field("on_stop", &self.on_stop)
            .finish_non_exhaustive()
    }
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
    /// The line naming the first check that refused, the shell's refusal
    /// after it in the library's own words, in this order:
    ///
    /// 1. the board's `/health` unanswered or refused;
    /// 2. no key to sign with: `no_key` or `store_unreadable`;
    /// 3. the signed session not opened: its armed names (`origin_state`,
    ///    `not_registered`, `retired`, `not_enrolled`, `busy`), the
    ///    unreachable board, the block, or the board's own verdict.
    ///
    /// The shell is dropped before the error is returned, so its stop has
    /// run.
    ///
    /// # Panics
    ///
    /// Where skep-shell breaks a promise the open reads: one reference for the
    /// one board its options name (`Shell::open`), the store's key at every
    /// board under the signed mode (`Shell::check_signed_key`), and the
    /// `session` row's `SessionOpened` (`open_session`).
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
        let board = shell.board_references().into_iter().next().expect("`Shell::open` issues one reference per board, and these options name one");
        let health = shell.call("health", &json!({"board": board})).map_err(|r| stopped_before_serving("the board's health was not read", &r))?;
        let halted = if health["health"]["writes"]["halted"].as_bool() == Some(true) {
            "; writes HALTED until the board restarts: a burst is held for the shell's resend, and any other write refused `poisoned`"
        } else {
            ""
        };
        talk(&format!(
            "board {origin} (reference {board}): mode {} (claimant {}, local_trust {}){halted}",
            health["mode"].as_str().unwrap_or("?"),
            health["health"]["auth"]["claimant"].as_str().unwrap_or("null"),
            health["health"]["auth"]["local_trust"]
        ));
        let keys = shell.check_signed_key().map_err(|r| stopped_before_serving("no key to sign with", &r))?;
        let key = keys.into_iter().next().expect("the signed mode's check answers the store's key at every board, and the shell holds one");
        let SessionOpened { reference, account, writes } = open_session(&shell, &board).map_err(|r| stopped_before_serving("the signed session did not open", &r))?;
        talk(&format!(
            "signed as principal {principal} (account {}) with the key {} ({}) from {}: enrolled in that account's set or the nearest set above it; the person who enrolled it stops this adapter by retiring it",
            account.as_deref().unwrap_or("none"),
            key.fingerprint,
            key.label.as_deref().map(render_inert).unwrap_or_default(),
            store_dir.display()
        ));
        talk(&format!("person seam: {person_seam} — no secret or consent moment is answered here: no key or claim ceremony runs through this adapter"));
        let session = Arc::new(SessionWatch::new(reference));
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
    /// on — and the drain settles the session's state by it
    /// (`SessionWatch::settle`): to the fresh session on the restart arm's
    /// re-open, to a lapse where the adapter serves on — each said — and to the
    /// stop on every other arm, its plain line handed to the stop. Every other
    /// event is read and dropped.
    fn drain(&self, events: Receiver<Event>) {
        let (session, talk, on_stop) = (Arc::clone(&self.session), Arc::clone(&self.talk), self.on_stop.clone());
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
                if session.settle(died, death, &|line| on_stop.stop(line)) {
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
    /// refusal stops the adapter, its line naming this open handed to the stop
    /// from the calling thread (`OnStop`). Where the drain settled the
    /// session's state while the session opened, the session is closed, so
    /// none stands that no call names.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the open, with no answer's text in it
    /// (`open_session`).
    ///
    /// # Panics
    ///
    /// As `open_session` does: where the `session` row's answer is no
    /// `SessionOpened`.
    fn open_afresh(&self, died: &str) -> Result<(), Refusal> {
        let fresh = match open_session(&self.shell, &self.board) {
            Ok(opened) => opened.reference,
            Err(refusal) => {
                self.session.settle(died, refused_afresh(refusal.name()), &|line| self.on_stop.stop(line));
                return Err(refusal);
            }
        };
        if self.session.move_off(died, SessionState::Open(fresh.clone())) {
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
    /// call waits for that (`SessionWatch::settled_within`), opens a session
    /// itself where it never comes, and is reissued once under what stands
    /// then — a session opened afresh where the death lapsed the last, the
    /// reference that died where it stopped the adapter. One answer stands
    /// instead: a `session_died` whose death was not re-opened, which carries
    /// the death's reason; a `session_ended` carries none, so the call that met
    /// it takes what stands. Every other answer is the attempt's own, and a
    /// second death is answered as it stands.
    ///
    /// `attempt` runs once, and once more on a reissue, one run after the
    /// other: an `FnMut`, so a caller sets its arguments in place for each run
    /// and never copies them.
    ///
    /// # Errors
    ///
    /// The attempt's refusal, or the shell's refusal of a session the
    /// adapter opened itself.
    fn under_session<T>(&self, mut attempt: impl FnMut(&str) -> Result<T, Refusal>) -> Result<T, Refusal> {
        let mut reissued = false;
        loop {
            let state = self.session.current();
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
            if !self.session.settled_within(&reference, SETTLE_WAIT) {
                self.open_afresh(&reference)?;
            }
            // A death the call met itself and the shell did not re-open is the
            // call's answer: its refusal carries the reason. A session found
            // already ended (`session_ended`) carries none, and the call takes
            // what stands.
            if met_death && !matches!(self.session.current(), SessionState::Open(_)) {
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
    /// `changes`: `args` is the call's own members, the row's object, and the
    /// session's reference is set in it beside them before each attempt. A row
    /// whose session form takes a board too (`search`, `places`) reads at the
    /// session's own where none is given, which is this adapter's one board.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the call, after the session's life has been
    /// run around it (`under_session`): the board's verdict, the unreachable
    /// board, a halt, or the shell's own by name — `session_died` with the
    /// reason where the death was not re-opened, `session_ended` where the
    /// adapter has stopped or a reissue met a second end — or the shell's
    /// refusal of a session the adapter opened itself.
    pub fn session_call(&self, name: &str, args: Map<String, Value>) -> Result<Value, Refusal> {
        // An object by construction, so setting a member of it cannot panic.
        let mut args = Value::Object(args);
        self.under_session(|reference| {
            args["session"] = Value::from(reference);
            self.shell.call(name, &args)
        })
    }

    /// Fetches a picture's file by the I-address `i` of its cell.
    ///
    /// The fetch runs under the session, and `i` goes to the shell as the
    /// agent gave it: the shell refuses one that is no address in its one
    /// spelling, as it refuses every row's argument. The answer is the shell's
    /// streamed fetch (wire.md §Media, THE FETCH), its head and its body still
    /// unread, which [`read_whole`](crate::media::read_whole) reads under the
    /// adapter's cap and deadline.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the fetch: `malformed_args` naming `i`; the
    /// board's verdict on the address (`withheld`, `not_a_cell`, `no_value`,
    /// `blob_missing`, …) under its own status; the unreachable board; or the
    /// session's end as `session_call` carries it.
    pub fn fetch(&self, i: &Value) -> Result<Fetched, Refusal> {
        self.under_session(|reference| self.shell.fetch(&json!({"session": reference, "i": i})))
    }

    /// Returns the URI of a picture's file by the I-address `i` of its cell.
    ///
    /// It is the route the shell's fetch dials, `GET /blob?i=<i>` at the
    /// board's origin (wire.md §Media, THE FETCH), which a resource block
    /// names; `i` rides the query as written.
    ///
    /// # Panics
    ///
    /// In a debug build, where `i` is no address in its one spelling
    /// (`is_address_text`): the caller's obligation, which every `i` the
    /// shell's `fetch` row admits meets.
    pub fn blob_uri(&self, i: &str) -> String {
        debug_assert!(is_address_text(i), "blob_uri's precondition: `{i}` is an address in its one spelling, as the shell's `fetch` row admits alone");
        format!("{}/blob?i={i}", self.origin.as_str())
    }

    /// Returns who this adapter acts as, and its session's facts.
    ///
    /// The answer is the principal, its account, the signing key's
    /// fingerprint and label, the board's origin, `writes`, and the board's
    /// `health` with its derived `mode` — the shell's `health` call, made now;
    /// the rest is the session's open's, kept since startup.
    ///
    /// # Errors
    ///
    /// `Backend::health`'s: the unreachable board, or the board's refusal of
    /// the read — its verdict, which *a refusal as a result* renders as data.
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

    /// Runs the clean stop, said first as the session's state has it.
    ///
    /// The stop is the shell's: every session in its table closed at the
    /// board, every index saved, the feed threads joined. A session the calls
    /// run under is said closed at the board; where none stands — a death or a
    /// refused open stopped the adapter, or the board did not answer — the
    /// session already ended there, its end having left the shell's table,
    /// and the line says so.
    ///
    /// It takes the backend, since nothing is served after it: a call made
    /// through it then would find its session closed, wait out `SETTLE_WAIT`
    /// for a death the stop never announces, and meet a dialer that dials no
    /// more.
    pub fn shutdown(self) {
        let said = match self.session.current() {
            SessionState::Open(_) => "stopping: closing the session at the board, saving the index",
            SessionState::Lapsed(_) | SessionState::Stopped(_) => "stopping: the session already ended at the board; saving the index",
        };
        self.say(said);
        self.shell.shutdown();
    }
}

#[cfg(test)]
mod tests;
