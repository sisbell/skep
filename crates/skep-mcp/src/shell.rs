//! The adapter's one seam onto `skep-shell`: THE BACKEND. It opens the
//! shell over the one board in the SIGNED mode with the refusing arm
//! (`ArmConfig::Refuse`: no person is present, so every SECRET and CONSENT
//! moment is refused `person_required`), checks the board and the key as
//! `skep-dev serve` does, opens ONE signed content-scoped session for the
//! configured principal before any tool is served, and from then on supplies
//! that session's reference and the board's reference on every call, so no
//! tool's arguments name either. The references are the shell's opaque
//! names (THE PIN of `client.md` §4b.1): never a token, never a credential.
//!
//! THE SESSION's LIFE. A death signal the shell meets — at one of this
//! adapter's calls, or at the board's feed thread first — ends the session
//! by the shell's one sequence (`Sessions::end`), and on the restart arm
//! the shell RE-OPENS a signed session silently under a FRESH reference
//! (AUTH-5.31), named in the death's reason. The adapter takes that
//! reference wherever it learns of it: from the `session_died` refusal of
//! the call that met the death, when it reissues the call once under the
//! fresh reference (the death executed nothing: the board refuses a dead
//! token before it runs the frame), or from the `session-died` event on the
//! bus, which [`Backend::drain`] reads for the adapter's life. A death the
//! shell does NOT re-open — the key retired (AUTH-5.28, AUTH-5.77), the
//! account seeded, the prefix blocked, or a restart whose re-open the board
//! refused — STOPS the adapter: the drain hands one plain line naming the
//! arm to the caller's stop, and nothing more is served; the person stops
//! an agent by retiring its key, and the adapter's end is what the agent's
//! client sees. The `unreachable` arm alone is served through: every call
//! answers its refusal, and the next call opens a session afresh once the
//! board answers again.
//!
//! THE BUS is drained on a thread of its own for the process's life: an
//! undrained subscriber's channel grows without bound (`EventBus::emit`
//! clones every event to every subscriber), and the one event this adapter
//! acts on is `session-died`; every other is read and dropped.

use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::sheet::render_inert;
use skep_client::store::KeyFacts;
use skep_client::Origin;
use skep_shell::{ArmConfig, EventName, Fetched, Name, Refusal, SessionMode, Shell, ShellOptions, Talk};

use crate::media::MAX_FETCH_BYTES;

/// How long a call whose reference the feed thread ended waits for that
/// thread's re-open to reach the shared reference before it opens a
/// session itself: the end's derivation makes a few dials and completes in
/// milliseconds, so the wait is a bound, not an expected delay.
const SWAP_WAIT: Duration = Duration::from_secs(2);

/// What a fetched file came back as.
#[derive(Debug)]
pub enum FetchAnswer {
    /// The file's bytes, whole.
    Bytes(Vec<u8>),
    /// The file's declared length passes [`MAX_FETCH_BYTES`]: no byte of it
    /// was read.
    PastTheCap { length: u64 },
    /// The stream ended short of the declared length — the board's RESET
    /// (wire.md §Media, THE FETCH), or a read that failed: `read` bytes came.
    Cut { read: usize, length: Option<u64>, error: String },
}

/// What a death's reason asks of the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Death {
    /// The restart arm re-opened the session: the fresh reference.
    Reopened(String),
    /// Nothing to do but serve on: the `unreachable` arm, whose session no
    /// one re-opens until the board answers again, and the adapter's own
    /// `closed`.
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
        "restart" => Death::Stop(format!(
            "the board restarted and refused this key at the re-open ({}): the session is gone and no call is served; fix what the refusal names and start the adapter again",
            reason["refused"].as_str().unwrap_or("refused")
        )),
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
pub fn plain(refusal: &Refusal) -> String {
    match refusal {
        Refusal::Halt { name, face } => format!("{name}: {}\n  cause: {}\n  act: {}", face.state, face.cause, face.act),
        Refusal::Board(r) => format!("the board refused: {r}"),
        Refusal::Blocked(b) => format!("blocked: {b}"),
        Refusal::Unreachable(d) => format!("the board is not answering: {d}"),
        Refusal::Shell { name, detail } => format!("{name}: {detail}"),
    }
}

/// The backend: the shell, the one board's reference, the one session's
/// reference, and the facts `session_info` reports.
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
    /// The session's reference: swapped at a re-open, by the call that met
    /// the death or by the drain, whichever learns of it first.
    session: Arc<Mutex<String>>,
    talk: Talk,
}

impl Backend {
    /// THE OPEN: the shell over `origin` in the signed mode with the
    /// refusing arm, the board's `/health` read and said, the store's key
    /// for `principal` checked and said, and ONE signed session opened —
    /// before any tool is served — and said. Each line goes to `talk`.
    ///
    /// # Errors
    ///
    /// The refusal the shell gave, in plain words, at the first check that
    /// refused: the board not answering; `no_key` or `store_unreadable` at
    /// the key; the session's armed names — `origin_state`, `not_registered`,
    /// `retired`, `not_enrolled`, `busy` — or the board's own. The shell is
    /// dropped before the error is returned, so its stop has run.
    pub fn open(origin: Origin, store_dir: PathBuf, principal: u64, talk: Talk) -> Result<Backend, String> {
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
        Ok(Backend { shell, board, origin, principal, account, writes, key, session: Arc::new(Mutex::new(reference.to_string())), talk })
    }

    fn say(&self, line: &str) {
        (self.talk)(line);
    }

    /// The board's origin, as dialed.
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// THE DRAIN: the bus read on a thread of its own for the process's
    /// life. A `session-died` of this adapter's session moves the reference
    /// on the restart arm's re-open, is said and served through on the
    /// `unreachable` arm, and on every other arm hands its plain line to
    /// `on_stop` — once — for the caller to end the process by; every
    /// other event is read and dropped.
    pub fn drain(&self, on_stop: impl Fn(String) + Send + 'static) {
        let events = self.shell.subscribe();
        let session = Arc::clone(&self.session);
        let talk = Arc::clone(&self.talk);
        thread::spawn(move || {
            let mut stopped = false;
            for event in events {
                if event.name != EventName::SessionDied || stopped {
                    continue;
                }
                let Some(died) = event.data["session"].as_str() else { continue };
                if *session.lock().expect("the session reference's lock") != died {
                    continue;
                }
                match classify(&event.data["reason"]) {
                    Death::Reopened(fresh) => {
                        if swap(&session, died, &fresh) {
                            talk("the board restarted: the session was re-opened under a fresh reference, and every call is served under it");
                        }
                    }
                    Death::ServeOn => {
                        talk("the session ended and was not re-opened (the board did not answer): every call answers its refusal, and the next call opens a session once the board answers again")
                    }
                    Death::Stop(line) => {
                        stopped = true;
                        on_stop(line);
                    }
                }
            }
        });
    }

    /// Opens a session afresh, for a reference the feed thread ended with
    /// no re-open; the fresh reference.
    fn open_session(&self) -> Result<String, Refusal> {
        let opened = self.shell.call("session", &json!({"board": self.board}))?;
        opened["session"].as_str().map(str::to_string).ok_or_else(|| Refusal::shell(Name::SESSION_ENDED, json!({"session": "the session answer names no session"})))
    }

    /// The shared reference once it has moved off `old`, within
    /// [`SWAP_WAIT`]; `None` where it stands.
    fn wait_for_swap(&self, old: &str) -> Option<String> {
        let deadline = Instant::now() + SWAP_WAIT;
        loop {
            let current = self.session.lock().expect("the session reference's lock").clone();
            if current != old {
                return Some(current);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// ONE ATTEMPT under the session's reference, and the session's life
    /// around it: a `session_died` whose reason names the re-opened session
    /// moves the reference and reissues the attempt once; a `session_ended`
    /// — the feed thread ended it first — waits for that thread's re-open to
    /// reach the reference and reissues once under it, or opens a session
    /// itself where none came; every other answer is the attempt's own, and
    /// a second death is answered as it stands.
    fn under_session<T>(&self, attempt: impl Fn(&str) -> Result<T, Refusal>) -> Result<T, Refusal> {
        let mut reissued = false;
        loop {
            let reference = self.session.lock().expect("the session reference's lock").clone();
            let outcome = attempt(&reference);
            let Err(refusal) = &outcome else { return outcome };
            if reissued {
                return outcome;
            }
            if let Some(detail) = shell_refusal(refusal, Name::SESSION_DIED) {
                match classify(&detail["reason"]) {
                    Death::Reopened(fresh) => {
                        if swap(&self.session, &reference, &fresh) {
                            self.say("the board restarted: the session was re-opened under a fresh reference, and the call is reissued under it");
                        }
                        reissued = true;
                        continue;
                    }
                    Death::ServeOn | Death::Stop(_) => return outcome,
                }
            }
            if shell_refusal(refusal, Name::SESSION_ENDED).is_some() {
                if self.wait_for_swap(&reference).is_none() {
                    let fresh = self.open_session()?;
                    if swap(&self.session, &reference, &fresh) {
                        self.say("the session had ended with no re-open: a session was opened afresh, and the call is reissued under it");
                    }
                }
                reissued = true;
                continue;
            }
            return outcome;
        }
    }

    /// A call of the shell's that names the board and no session — `boards`,
    /// `health`, `probe` — with the board's reference supplied.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the call: the board's verdict, the unreachable
    /// board, a halt, or the shell's own by name.
    pub fn board_call(&self, name: &str, mut args: Value) -> Result<Value, Refusal> {
        args["board"] = Value::from(self.board.as_str());
        self.shell.call(name, &args)
    }

    /// A call of the shell's under the session — `op`, `search`, `places`,
    /// `held`, `resolve`, `changes` — the session's reference supplied, and
    /// the board's beside it where the row takes one.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the call, after the session's life has been
    /// run around it (`under_session`): the board's verdict, the unreachable
    /// board, a halt, or the shell's own by name — `session_died` with the
    /// reason where the death was not re-opened, `session_ended` where no
    /// session could be opened afresh.
    pub fn session_call(&self, name: &str, args: Value) -> Result<Value, Refusal> {
        self.under_session(|session| {
            let mut args = args.clone();
            args["session"] = Value::from(session);
            if matches!(name, "search" | "places") {
                args["board"] = Value::from(self.board.as_str());
            }
            self.shell.call(name, &args)
        })
    }

    /// The board's bytes at the address `i`, under the session: the shell's
    /// streamed fetch, its declared length held to [`MAX_FETCH_BYTES`]
    /// before a byte is read, the body then read whole.
    ///
    /// # Errors
    ///
    /// The shell's refusal of the fetch: the board's verdict on the address
    /// (`withheld`, `not_a_cell`, `no_value`, `blob_missing`, …) under its
    /// own status, the unreachable board, or the session's end as
    /// `session_call` carries it. A file past the cap and a stream cut
    /// short are answers, not errors.
    pub fn fetch(&self, i: &str) -> Result<FetchAnswer, Refusal> {
        let fetched = self.under_session(|session| self.shell.fetch(&json!({"session": session, "i": i})))?;
        let Fetched { headers, body, .. } = fetched;
        let length = headers.get("Content-Length").and_then(|v| v.trim().parse::<u64>().ok());
        if let Some(length) = length {
            if length > MAX_FETCH_BYTES {
                return Ok(FetchAnswer::PastTheCap { length });
            }
        }
        let mut bytes = Vec::new();
        let read = body.take(MAX_FETCH_BYTES + 1).read_to_end(&mut bytes);
        if bytes.len() as u64 > MAX_FETCH_BYTES {
            return Ok(FetchAnswer::PastTheCap { length: bytes.len() as u64 });
        }
        if let Err(e) = read {
            return Ok(FetchAnswer::Cut { read: bytes.len(), length, error: e.to_string() });
        }
        if let Some(length) = length {
            if (bytes.len() as u64) < length {
                return Ok(FetchAnswer::Cut { read: bytes.len(), length: Some(length), error: "the stream ended short of its declared length".into() });
            }
        }
        Ok(FetchAnswer::Bytes(bytes))
    }

    /// `session_info`: the principal, its account, the signing key's
    /// fingerprint and label, the board's origin, `writes`, and the board's
    /// `health` with its derived `mode` — the shell's `health` call, made now.
    ///
    /// # Errors
    ///
    /// The health call's refusal: the unreachable board, or a halt.
    pub fn session_info(&self) -> Result<Value, Refusal> {
        let health = self.board_call("health", json!({}))?;
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

/// The reference moved from `old` to `fresh`, where it still stands at
/// `old`: whether this caller moved it.
fn swap(session: &Mutex<String>, old: &str, fresh: &str) -> bool {
    let mut current = session.lock().expect("the session reference's lock");
    if *current == old {
        *current = fresh.to_string();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each arm of a death's reason asks one thing: the restart's re-open
    /// names the fresh reference; a restart the board refused, a
    /// retirement, a block, a seeding and a mode flip each stop with a line
    /// naming the arm's fact; the unreachable board, the adapter's own
    /// close, and a spelling no arm has serve on.
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
        for serve_on in [json!({"arm": "unreachable", "text": "connect refused"}), json!({"arm": "closed"}), json!({"arm": "restart", "reopened": true}), json!({})] {
            assert_eq!(classify(&serve_on), Death::ServeOn, "{serve_on}");
        }
    }

    /// The swap moves the reference from the one it was read at and no
    /// other: two callers learning of one re-open move it once.
    #[test]
    fn the_swap_moves_the_reference_once() {
        let session = Mutex::new("s-old".to_string());
        assert!(swap(&session, "s-old", "s-new"));
        assert!(!swap(&session, "s-old", "s-other"), "the second caller finds it moved");
        assert_eq!(*session.lock().unwrap(), "s-new");
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
