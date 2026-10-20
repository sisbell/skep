//! The adapter's one seam onto `skep-shell`: THE BACKEND. It opens the
//! shell over the one board in the SIGNED mode with the refusing arm
//! (`ArmConfig::Refuse`: no person is present, so every SECRET and CONSENT
//! moment is refused `person_required`), checks the board and the key as
//! `skep-dev serve` does, opens ONE signed content-scoped session for the
//! configured principal before any tool is served, and from then on supplies
//! that session's reference to every call that runs under it, and the
//! board's to the one call whose row names it, so no tool's arguments name
//! either. The references are the shell's opaque names (THE PIN of
//! `client.md` §4b.1): never a token, never a credential.
//!
//! **The session's life.** The calls stand on one session, its standing held
//! here (`Standing`): the session every call names, or the one that died and
//! what its end left. A death signal the shell meets — at one of this
//! adapter's calls, or at the board's feed thread first — ends the session by
//! the shell's one sequence (`Sessions::end`), and on the restart arm the
//! shell re-opens a signed session silently under a fresh reference
//! (AUTH-5.31), named in the death's reason. That reason is the death's
//! verdict, and whichever thread learns it first moves the standing by it: the
//! call that met the death, from its `session_died` refusal, reissuing the
//! call once under the fresh reference (the death executed nothing: the board
//! refuses a dead token before it runs the frame), or [`Backend::drain`], from
//! the `session-died` event on the bus. A call that finds its session already
//! ended waits for that verdict (within `VERDICT_WAIT`) rather than open a
//! second session early, which would leave the shell's re-open adopted by
//! nothing. A death the shell does not re-open — the key retired (AUTH-5.28,
//! AUTH-5.77), the account seeded, the prefix blocked, or a restart whose
//! re-open the board refused — stops the adapter: one plain line naming the
//! arm goes to the process's stop, and nothing more is served; the person
//! stops an agent by retiring its key, and the adapter's end is what the
//! agent's client sees. A board that does not answer is served through: no
//! session stands, every call answers its refusal, and the next call opens one
//! once the board answers again, the board's refusal of it judged as a refused
//! re-open is.
//!
//! THE BUS is drained on a thread of its own for the process's life: an
//! undrained subscriber's channel grows without bound (`EventBus::emit`
//! clones every event to every subscriber), and the one event this adapter
//! acts on is `session-died`; every other is read and dropped.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::sheet::render_inert;
use skep_client::store::KeyFacts;
use skep_client::Origin;
use skep_shell::{ArmConfig, EventName, Fetched, Name, Refusal, SessionMode, Shell, ShellOptions, Talk};

/// The longest a call waits for the verdict on a session already ended.
///
/// The verdict is the `session-died` the drain moves the standing by. The
/// shell's end derives its reason from the board and, on the restart arm,
/// re-opens over several exchanges, each under skep-client's dial bounds
/// (`CONNECT_TIMEOUT`, `IO_TIMEOUT`): milliseconds at a loopback board,
/// seconds at a far one. A call that opened its own session first would
/// leave the shell's re-open standing in the shell's table, adopted by
/// nothing, so the call waits for the verdict and does not guess at it. The
/// wait lapses only where an end outlasts it or never reports — one that
/// panicked — and the call then opens a session itself.
const VERDICT_WAIT: Duration = Duration::from_secs(60);

/// The process's stop: it takes the plain line the adapter stops with.
///
/// `main` holds the other end, and its loop says the line and exits.
pub type OnStop = Arc<dyn Fn(String) + Send + Sync>;

/// The session the adapter's calls stand on, and what its end left.
///
/// Every variant carries a session's reference: the live one, or the one
/// that died. A death's verdict moves it (`settle`), as does a session the
/// adapter opens itself; nothing moves it off a stop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Standing {
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

/// What a death's reason asks of the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Death {
    /// The restart arm re-opened the session: the fresh reference.
    Reopened(String),
    /// No session stands, and the adapter serves on.
    ///
    /// The `unreachable` arm, and a re-open that met a board that did not
    /// answer: no one re-opens the session until the board answers again.
    /// The adapter's own `closed` too.
    ServeOn,
    /// A death the shell does not re-open: the plain line the stop says.
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
        _ => Death::ServeOn,
    }
}

/// Returns what a session the board did not give asks of the adapter.
///
/// The shell's re-open at a restart and a session the adapter opens itself
/// are judged alike, by the refusal's name: a board that did not answer
/// serves on, as a death's `unreachable` arm does, and any other refusal
/// stops the adapter with a line naming it.
fn refused_reopen(refused: &str) -> Death {
    match refused {
        "unreachable" => Death::ServeOn,
        _ => Death::Stop(format!(
            "the board restarted and refused this key at the re-open ({refused}): the session is gone and no call is served; fix what the refusal names and start the adapter again"
        )),
    }
}

/// A refusal of the shell's own, by name: the detail where it is one.
fn shell_refusal(refusal: &Refusal, named: Name) -> Option<&Value> {
    match refusal {
        Refusal::Shell { name, detail } if *name == named => Some(detail),
        _ => None,
    }
}

/// A refusal in plain words, for the operator's stream: a halt's face
/// under its armed name, state, cause and act on their lines; the board's
/// verdict, the block and the unreachable board as the library spells them;
/// the shell's own by name with its detail.
fn plain(refusal: &Refusal) -> String {
    match refusal {
        Refusal::Halt { name, face } => format!("{name}: {}\n  cause: {}\n  act: {}", face.state, face.cause, face.act),
        Refusal::Board(r) => format!("the board refused: {r}"),
        Refusal::Blocked(b) => format!("blocked: {b}"),
        Refusal::Unreachable(d) => format!("the board is not answering: {d}"),
        Refusal::Shell { name, detail } => format!("{name}: {detail}"),
    }
}

/// The backend: the seam onto the shell, and what it holds for the calls.
///
/// It holds the shell, the one board's reference, the one session's
/// standing, the process's stop, and the facts `session_info` reports.
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
    /// The session the calls stand on.
    ///
    /// Whichever thread learns a death's verdict first moves it, and so does
    /// the call that opens a session itself.
    session: Arc<Mutex<Standing>>,
    /// The process's stop, which a stopping verdict's line goes to.
    on_stop: OnStop,
    talk: Talk,
}

impl Backend {
    /// Opens the shell over the one board, checks it, and opens the session.
    ///
    /// The shell runs over `origin` in the signed mode with the refusing arm;
    /// the board's `/health` is read and said, the store's key for
    /// `principal` checked and said, and one signed session opened — before
    /// any tool is served — and said. Each line goes to `talk`, and `on_stop`
    /// is the process's stop, kept for the backend's life.
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
        // The seam's name is read off the options the shell is opened with,
        // so the startup line says what the shell holds and never a literal.
        let seam = match &options.arm {
            ArmConfig::Refuse => "refuse",
            ArmConfig::Auto => "auto",
            _ => "script",
        };
        let shell = Shell::open(options);
        let Some(board) = shell.board_references().into_iter().next() else {
            return Err("the shell opened no board".into());
        };
        let stop = |what: &str, r: Refusal| format!("stopped before serving: {what}: {}", plain(&r));
        let health = shell.call("health", &json!({"board": board})).map_err(|r| stop("the board did not answer", r))?;
        let halted = if health["health"]["writes"]["halted"].as_bool() == Some(true) { "; writes HALTED: every write is refused `poisoned` until the board restarts" } else { "" };
        talk(&format!(
            "board {origin} (reference {board}): mode {} (claimant {}, local_trust {}){halted}",
            health["mode"].as_str().unwrap_or("?"),
            health["health"]["auth"]["claimant"].as_str().unwrap_or("null"),
            health["health"]["auth"]["local_trust"]
        ));
        let keys = shell.check_signed_key().map_err(|r| stop("no key to sign with", r))?;
        let Some(key) = keys.into_iter().next() else {
            return Err("stopped before serving: the store selected no key".into());
        };
        let opened = shell.call("session", &json!({"board": board})).map_err(|r| stop("the signed session did not open", r))?;
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
        talk(&format!("person seam: {seam} — no secret or consent moment is answered here: no key or claim ceremony runs through this adapter"));
        let session = Arc::new(Mutex::new(Standing::Open(reference.to_string())));
        Ok(Backend { shell, board, origin, principal, account, writes, key, session, on_stop, talk })
    }

    fn say(&self, line: &str) {
        (self.talk)(line);
    }

    /// Reads the bus on a thread of its own for the process's life.
    ///
    /// A `session-died` of the session the calls stand on is that death's
    /// verdict, and moves the standing (`settle`): to the fresh session on
    /// the restart arm's re-open, to a lapse where the adapter serves on —
    /// each said — and to the stop on every other arm, its plain line handed
    /// to the stop. Every other event is read and dropped.
    pub fn drain(&self) {
        let events = self.shell.subscribe();
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

    /// Opens a session where the session `died` left none, and stands on it.
    ///
    /// The open is judged as the shell's re-open is (`refused_reopen`): a
    /// board that does not answer leaves the standing lapsed, and any other
    /// refusal stops the adapter, its line handed to the stop. Where a
    /// verdict moved the standing while the session opened, the session is
    /// closed, so none stands that no call names.
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
                settle(&self.session, died, refused_reopen(refusal.name()), &self.on_stop);
                return Err(refusal);
            }
        };
        if swap(&self.session, died, Standing::Open(fresh.clone())) {
            self.say("the session had ended with no re-open: a session was opened afresh, and the call is served under it");
        } else {
            let _ = self.shell.call("close", &json!({"session": fresh}));
        }
        Ok(())
    }

    /// Runs one attempt under the session, and the session's life around it.
    ///
    /// The session is the one the calls stand on. Where the last session
    /// lapsed, one is opened first (`open_afresh`); where the adapter has
    /// stopped, the attempt runs under the reference that died, and the shell
    /// answers it. A `session_died` carries its verdict into the standing
    /// (`settle`), and where it names the re-opened session the attempt is
    /// reissued once under it. A `session_ended` — the feed thread ended the
    /// session first — waits for that end's verdict (`verdict_within`), opens
    /// a session itself where none comes, and reissues once under what stands
    /// then. Every other answer is the attempt's own, and a second death is
    /// answered as it stands.
    ///
    /// # Errors
    ///
    /// The attempt's refusal, or the shell's refusal of a session the
    /// adapter opened itself.
    fn under_session<T>(&self, attempt: impl Fn(&str) -> Result<T, Refusal>) -> Result<T, Refusal> {
        let mut reissued = false;
        loop {
            let standing = self.session.lock().expect("the standing's lock").clone();
            let reference = match standing {
                Standing::Open(reference) => reference,
                Standing::Lapsed(died) => {
                    self.open_afresh(&died)?;
                    continue;
                }
                Standing::Stopped(died) => return attempt(&died),
            };
            let outcome = attempt(&reference);
            let Err(refusal) = &outcome else { return outcome };
            if reissued {
                return outcome;
            }
            if let Some(detail) = shell_refusal(refusal, Name::SESSION_DIED) {
                let death = classify(&detail["reason"]);
                let reopened = matches!(death, Death::Reopened(_));
                if settle(&self.session, &reference, death, &self.on_stop) && reopened {
                    self.say("the board restarted: the session was re-opened under a fresh reference, and the call is reissued under it");
                }
                if !reopened {
                    return outcome;
                }
                reissued = true;
                continue;
            }
            if shell_refusal(refusal, Name::SESSION_ENDED).is_some() {
                if !verdict_within(&self.session, &reference, VERDICT_WAIT) {
                    self.open_afresh(&reference)?;
                }
                reissued = true;
                continue;
            }
            return outcome;
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
    /// The answer is the board's `/health` document verbatim with its
    /// derived mode; the board's reference is supplied.
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

    /// Makes a call of the shell's under the session the calls stand on.
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

/// Carries a death's verdict into the standing, and its stop where it asks.
///
/// The standing moves where it may (`swap`): to the fresh session on the
/// restart arm's re-open, to a lapse where the adapter serves on, and to the
/// stop on every other arm, whose line then goes to `on_stop`. Returns
/// whether this caller moved it: the drain and the call that met the death
/// learn the one verdict, and only the first carries it.
fn settle(standing: &Mutex<Standing>, died: &str, death: Death, on_stop: &OnStop) -> bool {
    let next = match &death {
        Death::Reopened(fresh) => Standing::Open(fresh.clone()),
        Death::ServeOn => Standing::Lapsed(died.to_string()),
        Death::Stop(_) => Standing::Stopped(died.to_string()),
    };
    let moved = swap(standing, died, next);
    if let (true, Death::Stop(line)) = (moved, death) {
        on_stop(line);
    }
    moved
}

/// Returns whether the standing moved off the session `died` within `wait`.
///
/// It looks every twenty milliseconds for the verdict on `died` — the
/// drain's, from the shell's end — to move the standing: to a fresh session,
/// a lapse or the stop alike.
fn verdict_within(standing: &Mutex<Standing>, died: &str, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if !matches!(&*standing.lock().expect("the standing's lock"), Standing::Open(reference) if reference == died) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Moves the standing off the session `died` to `next`, where it may.
///
/// It may where the standing still names `died`, live or lapsed, and differs
/// from `next`: a stop is never moved off, and a standing that has moved on
/// to another session is left as it stands. Returns whether this caller
/// moved it.
fn swap(standing: &Mutex<Standing>, died: &str, next: Standing) -> bool {
    let mut current = standing.lock().expect("the standing's lock");
    let names_it = matches!(&*current, Standing::Open(reference) | Standing::Lapsed(reference) if reference == died);
    if names_it && *current != next {
        *current = next;
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each arm of a death's reason asks one thing.
    ///
    /// The restart's re-open names the fresh reference; a restart the board
    /// refused, a retirement, a block, a seeding and a mode flip each stop
    /// with a line naming the arm's fact; the unreachable board, a re-open
    /// that met a board that did not answer, the adapter's own close, and a
    /// spelling no arm has serve on.
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
        for (reason, names) in stops {
            match classify(&reason) {
                Death::Stop(line) => assert!(line.contains(names), "{reason}: {line}"),
                other => panic!("{reason}: {other:?}"),
            }
        }
        let retired = json!({"arm": "retired", "fingerprint": "ab12", "hand": "cd34", "label": "second"});
        let Death::Stop(line) = classify(&retired) else { panic!() };
        assert!(line.contains("ab12") && line.contains("cd34 (second)"), "the key and the hand: {line}");
        for serve_on in [
            json!({"arm": "unreachable", "text": "connect refused"}),
            json!({"arm": "restart", "reopened": false, "refused": "unreachable"}),
            json!({"arm": "closed"}),
            json!({"arm": "restart", "reopened": true}),
            json!({}),
        ] {
            assert_eq!(classify(&serve_on), Death::ServeOn, "{serve_on}");
        }
    }

    /// The standing moves off a session once, and never off a stop.
    ///
    /// Two callers carrying one re-open move it once; a verdict on a session
    /// the standing has left moves nothing; a death no one re-opened lapses
    /// it, the same verdict carried twice moves it once, and a late re-open of
    /// the lapsed session is adopted; a stop moves it, and nothing after.
    #[test]
    fn the_standing_moves_off_a_session_once_and_never_off_a_stop() {
        let standing = Mutex::new(Standing::Open("s-old".to_string()));
        assert!(swap(&standing, "s-old", Standing::Open("s-new".into())));
        assert!(!swap(&standing, "s-old", Standing::Open("s-other".into())), "the second caller finds it moved");
        assert!(!swap(&standing, "s-old", Standing::Lapsed("s-old".into())), "a verdict on a session the standing left moves nothing");
        assert!(swap(&standing, "s-new", Standing::Lapsed("s-new".into())), "a death no one re-opened lapses it");
        assert!(!swap(&standing, "s-new", Standing::Lapsed("s-new".into())), "the same verdict carried twice moves it once");
        assert!(swap(&standing, "s-new", Standing::Open("s-late".into())), "a late re-open of the lapsed session is adopted");
        assert!(swap(&standing, "s-late", Standing::Stopped("s-late".into())));
        for next in [Standing::Open("s-after".into()), Standing::Lapsed("s-late".into())] {
            assert!(!swap(&standing, "s-late", next), "nothing moves the standing off a stop");
        }
        assert_eq!(*standing.lock().unwrap(), Standing::Stopped("s-late".into()));
    }

    /// A verdict is carried once, and a stop's line goes to the stop once.
    ///
    /// The drain and the call that met a death carry its one verdict: the
    /// first moves the standing and the second moves nothing. A refused open
    /// stops a lapsed standing as a stopping death stops a live one, and the
    /// line is handed on by the carrier that moved it alone.
    #[test]
    fn a_verdict_is_carried_once_and_its_stop_said_once() {
        let said = Arc::new(Mutex::new(Vec::new()));
        let on_stop: OnStop = {
            let said = Arc::clone(&said);
            Arc::new(move |line: String| said.lock().unwrap().push(line))
        };
        let standing = Mutex::new(Standing::Open("s-1".into()));
        assert!(settle(&standing, "s-1", Death::Reopened("s-2".into()), &on_stop));
        assert!(!settle(&standing, "s-1", Death::Reopened("s-2".into()), &on_stop), "the second carrier finds it carried");
        assert!(settle(&standing, "s-2", Death::ServeOn, &on_stop));
        assert_eq!(*standing.lock().unwrap(), Standing::Lapsed("s-2".into()));
        assert!(settle(&standing, "s-2", refused_reopen("retired"), &on_stop), "a refused open stops a lapsed standing");
        assert!(!settle(&standing, "s-2", refused_reopen("retired"), &on_stop));
        let said = said.lock().unwrap();
        assert_eq!(said.len(), 1, "the stop's line handed on once: {said:?}");
        assert!(said[0].contains("refused this key at the re-open (retired)"), "{said:?}");
        assert_eq!(refused_reopen("unreachable"), Death::ServeOn, "a board that does not answer serves on");
    }

    /// The wait for a verdict ends as the standing moves off the session.
    ///
    /// A verdict carried a moment later ends it — a lapse or a stop as surely
    /// as a re-open — and with none carried the wait lapses at its bound.
    #[test]
    fn the_wait_for_a_verdict_ends_as_the_standing_moves() {
        for verdict in [Death::Reopened("s-2".into()), Death::ServeOn, Death::Stop("stopped".into())] {
            let standing = Arc::new(Mutex::new(Standing::Open("s-1".into())));
            let carrier = {
                let standing = Arc::clone(&standing);
                let on_stop: OnStop = Arc::new(|_: String| {});
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(100));
                    settle(&standing, "s-1", verdict, &on_stop)
                })
            };
            let started = Instant::now();
            assert!(verdict_within(&standing, "s-1", Duration::from_secs(30)), "the verdict ends the wait");
            assert!(started.elapsed() < Duration::from_secs(10), "as the standing moves: {:?}", started.elapsed());
            assert!(carrier.join().expect("the carrier"), "the carrier moved it");
        }
        let standing = Mutex::new(Standing::Open("s-1".into()));
        assert!(!verdict_within(&standing, "s-1", Duration::from_millis(100)), "with no verdict the wait lapses");
    }

    /// A refusal in plain words names what it is: a halt's armed name with
    /// its face's three lines, the shell's own by name, the unreachable
    /// board as such.
    #[test]
    fn a_refusal_in_plain_words_names_what_it_is() {
        let face = skep_client::halt::Face { state: "no key here".into(), cause: "the store is keyless".into(), act: "run keygen".into() };
        let text = plain(&Refusal::named(Name::NO_KEY, face));
        assert_eq!(text, "no_key: no key here\n  cause: the store is keyless\n  act: run keygen");
        assert_eq!(plain(&Refusal::shell(Name::SESSION_ENDED, json!({"session": "s-1"}))), "session_ended: {\"session\":\"s-1\"}");
        assert!(plain(&Refusal::Unreachable(skep_client::DialError::Connect("refused".into()))).starts_with("the board is not answering: "));
    }
}
