//! `skep-dev serve`: the dev provider.
//!
//! As the dev provider record draws it (§2.2 (B), §3.1 (i), §3.2; its calls
//! P-1 … P-12), it is the shell's core (`skep-shell`) served to a page in a
//! browser over loopback HTTP and server-sent events. The inputs: the one
//! page origin admitted (`--page-origin`, required); the listen port
//! (`--listen`); the per-run admission secret (`--secret`, of the URL-safe
//! alphabet the page's query and header carry unchanged, else generated —
//! either way printed once on stdout, the one data line and the secret's
//! one carrier: no talk line names it); the session mode
//! (`--session bare|signed`, required — both arms are selectable, so a run
//! names one: `bare` the keyless session that reads alone, every write in
//! it refused before any dial, `signed` the session that writes); the dev
//! key store (`--dir`, required under `signed`, a throwaway directory under
//! the system temp dir where none is named under `bare`, removed on every
//! way out of the verb — `~/.skep` is never consulted here, and a key file
//! is refused: the signed arm signs with the key its store holds for the
//! principal); the principal (`--principal`, the claimant's
//! `DEFAULT_PRINCIPAL` where omitted); the dev arm's script (`--script`,
//! read once, at start, and said so); and the board — `--board`, a daemon
//! already running (the local record's recipe), or `--own` with
//! `--data-dir` and `--port`, the daemon run in-process with its test hooks
//! in a `dev-hooks` build. Every usage refusal is judged before anything is
//! made. The checks before serving, each a halt (exit 3): the board must
//! answer `/health`; the store must hold the principal's key under
//! `signed`; the port must bind. The serve: one thread per connection over
//! a loopback listener, the routes `serve/routes.rs` spells — each refusal
//! of the admission or of a request's read counted, and said on talk the
//! first time its kind is met — until stdin closes: the clean stop, its
//! cause and the run's figures said (the connections accepted, the refusals
//! by kind), every pending moment cancelled — before the connections are
//! joined, so a call parked on a moment answers `abandoned` and its
//! connection ends — every session closed, every consumer saved — the stop's
//! seconds said as it completes — the own node stopped and said so, the
//! throwaway removed — exit 0. An interrupt ends the process with none of
//! it, which the serving line says.

use std::collections::{BTreeMap, HashMap};
use std::io::{ErrorKind, Read};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::halt::Halt;
use skep_client::sign::fresh_bytes;
use skep_client::Origin;
use skep_shell::{script, ArmConfig, NodeState, Refusal, SessionMode, Shell, ShellOptions};

use crate::args::dev::{DevLine, SessionArm, DEFAULT_PRINCIPAL};
use crate::args::Usage;
use crate::board::hex;
use crate::shared::{data, Stop};
use crate::terminal::talk;

// The provider's own HTTP over `skep-http`'s subset: the timeouts and the
// caps, the CORS headers for the one origin, the event stream's framing.
mod http;
// The admission: the peer, the host, the one origin, the secret.
mod admission;
// The daemon's two modes: a running board dialed, or the in-process daemon
// with its fault doors under `dev-hooks`.
mod node;
// The routes over the shell's core.
mod routes;

pub use admission::{Admission, SECRET_HEADER, SECRET_QUERY};

/// The provider's standing state, shared by every connection.
pub struct Provider<'d> {
    pub shell: Shell,
    pub admission: Admission,
    /// The stop, once asked: why — stdin closed, or unreadable.
    stop: OnceLock<String>,
    /// The script seam's canned refusals, by call.
    ///
    /// Each is the next answer of that call.
    pub canned: Mutex<HashMap<String, Value>>,
    /// The in-process node, where the verb runs one.
    pub node: Option<&'d node::Node>,
    /// The permits the fault route holds.
    pub doors: Mutex<node::Doors<'d>>,
    /// The refusals of the admission and of a request's read, counted by kind.
    refusals: Mutex<BTreeMap<&'static str, u64>>,
}

impl Provider<'_> {
    /// Returns whether the stop was asked.
    pub fn stopped(&self) -> bool {
        self.stop.get().is_some()
    }

    /// Counts a refusal the provider makes itself, by its `kind`.
    ///
    /// The refusal is the admission's, or a request it cannot read; it is
    /// said on talk the first time the kind is met in this run, never again:
    /// a page retrying a refused stream every few seconds, or a process
    /// probing the port, says one line, and the stop says how many each kind
    /// came to ([`Provider::refusals_line`]). The kinds are the admission's
    /// four checks and the reader's two refusals, so the lines are at most
    /// six; a browser hides a refused answer from the page as a CORS
    /// failure, and this line is where the developer reads why.
    fn refused(&self, kind: &'static str, line: impl FnOnce() -> String) {
        let first = {
            let mut counts = self.refusals.lock().expect("the refusals' lock");
            let count = counts.entry(kind).or_insert(0);
            *count += 1;
            *count == 1
        };
        if first {
            talk(line());
        }
    }

    /// Returns the refusals counted over the run, by kind.
    ///
    /// They are those [`Provider::refused`] counts. A page refused a thousand
    /// times is read apart from one refused once; `None` where it made none.
    fn refusals_line(&self) -> Option<String> {
        let counts = self.refusals.lock().expect("the refusals' lock");
        let total: u64 = counts.values().sum();
        let kinds: Vec<String> = counts.iter().map(|(kind, n)| format!("{kind} {n}")).collect();
        (total > 0).then(|| {
            format!(
                "the provider refused {total} request{} over the run: {}",
                if total == 1 { "" } else { "s" },
                kinds.join(", ")
            )
        })
    }
}

/// The throwaway store a bare run makes where it names no `--dir`.
///
/// It is a directory under the system temp dir, removed — and said — when
/// the guard drops, on every way out of the verb, the clean stop and a halt
/// before serving alike. It is declared ahead of the shell that writes into
/// it, so it drops after the shell's own stop has ended every write.
struct Throwaway(PathBuf);

impl Throwaway {
    /// Makes the directory, named for this run.
    ///
    /// # Errors
    ///
    /// Returns a halt where the directory cannot be made.
    fn make() -> Result<Throwaway, Halt> {
        let dir = std::env::temp_dir().join(format!("skep-dev-serve-{}", hex(&fresh_bytes(4))));
        std::fs::create_dir_all(&dir).map_err(|e| Halt::face(format!("the throwaway store {} could not be made", dir.display()), e.to_string(), "pass --dir"))?;
        Ok(Throwaway(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Throwaway {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.0) {
            Ok(()) => talk(format!("the throwaway store {} is removed", self.0.display())),
            Err(e) => talk(format!("the throwaway store {} could not be removed: {e}", self.0.display())),
        }
    }
}

/// Returns a refusal met before serving as the halt it is (exit 3).
fn halt_of(r: Refusal) -> Halt {
    match r {
        Refusal::Halt { name, face } => Halt::face(format!("{name}: {}", face.state), face.cause, face.act),
        other => Halt::face(other.name(), other.to_string(), "fix what the refusal names and run again"),
    }
}

/// The pause after an accept the listener refused, before the next.
///
/// A refusal that persists — the descriptor table full, each event stream
/// holding one — answers again at once, and the loop would spin a core.
const ACCEPT_PAUSE: Duration = Duration::from_millis(10);

/// Where the provider's board runs.
///
/// It is a daemon this verb starts in-process (`--own`, its board directory
/// and port), or one already running at the origin `--board` names.
enum BoardAt {
    Own { data_dir: PathBuf, port: u16 },
    Running(Origin),
}

/// Runs `skep-dev serve`.
///
/// # Errors
///
/// Returns a usage refusal for a line given badly, ahead of anything made
/// — a key file named, a script that cannot be read or parsed, no `--dir`
/// under `signed` and `--own` beside a board among them; a halt (exit 3)
/// for the throwaway store or the in-process daemon that cannot be made,
/// and for each check before serving — the board's `/health`, the signed
/// key, the port; and the halt the secret's write to stdout comes to.
pub fn serve(c: &DevLine) -> Result<(), Stop> {
    // The inputs — every usage refusal ahead of anything made: a socket, the
    // in-process node, the throwaway store.
    let page_origin = c.page_origin()?;
    let listen = c.listen()?;
    let arm = c.session_mode()?;
    let principal = c.principal()?.unwrap_or(DEFAULT_PRINCIPAL);
    // A key file is no input of this verb: the signed arm signs with the key
    // its `--dir` store holds for the principal, the bare arm with none — so
    // one named, by the flag or a SKEP_KEY exported for `skep`, is refused,
    // never dropped (as `require_no_key_file` refuses one at `skep enroll`).
    if c.key_file()?.is_some() {
        return Err(Usage(
            "`--key` (or SKEP_KEY) names a key file, and `skep-dev serve` signs with the key its --dir store holds (signed) or with none (bare): run it without either".into(),
        )
        .into());
    }
    let secret = match c.secret()? {
        Some(s) => s.to_string(),
        None => hex(&fresh_bytes(16)),
    };
    // The script, read once, here: the dev arm answers from what this read
    // found for the whole run, and its line says so.
    let script_answers = match c.script() {
        Some(path) => {
            let text = std::fs::read_to_string(&path).map_err(|e| Usage(format!("--script: {} cannot be read: {e}", path.display())))?;
            let answers = script::parse(&text).map_err(|e| Usage(format!("--script: {e}")))?;
            let said = format!(
                "the dev arm answers the SECRET and CONSENT moments from the script {}: {} answer{} read at start, in order — an edit to the file takes a restart",
                path.display(),
                answers.len(),
                if answers.len() == 1 { "" } else { "s" }
            );
            Some((answers, said))
        }
        None => None,
    };
    let named_dir = c.store_dir_given()?;
    if named_dir.is_none() && arm == SessionArm::Signed {
        return Err(Usage("--dir (or SKEP_KEYSTORE) is required under --session signed: the store that holds the dev key".into()).into());
    }
    let own = c.own();
    if own && c.origin_given()?.is_some() {
        return Err(Usage("--own and a board (--board or SKEP_BOARD): give one".into()).into());
    }
    let board_at = if own { BoardAt::Own { data_dir: c.data_dir()?, port: c.node_port()? } } else { BoardAt::Running(c.origin()?) };
    // The store: a `--dir` the person named is theirs, and never removed;
    // else the throwaway, its guard declared ahead of the node and the shell,
    // so it drops after both on every way out of the verb.
    let (store_dir, throwaway) = match named_dir {
        Some(dir) => (dir, None),
        None => {
            let throwaway = Throwaway::make()?;
            (throwaway.path().to_path_buf(), Some(throwaway))
        }
    };
    let (own_node, board_origin) = match board_at {
        BoardAt::Own { data_dir, port } => {
            let node = node::start(&data_dir, port, !c.no_local_trust())?;
            let origin = node::origin_of(&node).clone();
            talk(format!(
                "the daemon runs in-process at {origin} over {} (local trust {}); its lines are this stream's",
                data_dir.display(),
                if c.no_local_trust() { "off" } else { "on" }
            ));
            (Some(node), origin)
        }
        BoardAt::Running(origin) => (None, origin),
    };
    let session_mode = match arm {
        SessionArm::Bare => SessionMode::Bare { principal },
        SessionArm::Signed => SessionMode::Signed { principal },
    };
    let (arm_config, arm_said) = match script_answers {
        Some((answers, said)) => (ArmConfig::Script(answers), said),
        None => (ArmConfig::Auto, "the dev arm answers the SECRET and CONSENT moments itself (the auto arm) and says each answer here".to_string()),
    };
    let talk_sink: skep_shell::Talk = Arc::new(|line: &str| talk(line));
    let mut options = ShellOptions::new(vec![board_origin.clone()], store_dir.clone(), session_mode, talk_sink);
    options.arm = arm_config;
    options.own_node = own.then(|| board_origin.clone());
    let shell = Shell::open(options);
    // The checks: the board answers; the key under `signed`; the port binds.
    let board = shell.board_references().into_iter().next().expect("one board");
    let health = shell.call("health", &json!({"board": board})).map_err(halt_of)?;
    // The board by its origin and by the reference the shell's own lines
    // name it by (`feed b-…:`), so the two join; and its write path's halt
    // where `/health` answers one, since every write the page makes is then
    // refused `poisoned` until the board restarts (wire.md §Rejection codes).
    let halted = if health["health"]["writes"]["halted"].as_bool() == Some(true) { "; writes HALTED: every write is refused `poisoned` until the board restarts" } else { "" };
    talk(format!(
        "board {board_origin} (reference {board}): mode {} (claimant {}, local_trust {}){halted}",
        health["mode"].as_str().unwrap_or("?"),
        health["health"]["auth"]["claimant"].as_str().unwrap_or("null"),
        health["health"]["auth"]["local_trust"]
    ));
    if let SessionMode::Signed { .. } = session_mode {
        let keys = shell.check_signed_key().map_err(halt_of)?;
        for k in keys {
            talk(format!("signed: the store {} holds the key {} for principal {principal}", store_dir.display(), k.fingerprint));
        }
    } else {
        talk(format!("bare: sessions bind as principal {principal} from this loopback peer and read alone, every write in them refused; the store is {}", store_dir.display()));
    }
    talk(arm_said);
    let listener = TcpListener::bind(("127.0.0.1", listen)).map_err(|e| Halt::face(format!("the provider's port {listen} could not be bound"), e.to_string(), "stop what holds it, or pass --listen"))?;
    let listen = listener.local_addr().map(|a| a.port()).unwrap_or(listen);
    let admission = Admission { page_origin: page_origin.as_str().to_string(), secret: secret.clone(), host: format!("127.0.0.1:{listen}") };
    // The one data line: the secret — its one carrier, so a log that keeps
    // the provider's talk keeps no copy of what admits a page to its session.
    data(&secret)?;
    // What an interrupt leaves, said beside the clean stop: the process
    // handles no signal, so Ctrl-C ends it where it stands.
    let mut left = vec![if own_node.is_some() { "the in-process daemon ends without its orderly shutdown" } else { "its sessions live on at the board until it restarts" }];
    if throwaway.is_some() {
        left.push("the throwaway store stays in place");
    }
    talk(format!(
        "serving the bridge for {page_origin} at http://127.0.0.1:{listen}: the page carries ?{SECRET_QUERY}=<the secret, this run's one line on stdout> in its URL and echoes it in the {SECRET_HEADER} header on every call, and on the event stream's URL; the provider stops cleanly when stdin closes (Ctrl-D at a terminal) — an interrupt (Ctrl-C) ends it with none of the clean stop: {}",
        left.join(", and ")
    ));
    if own {
        shell.set_node_state(NodeState::Running);
    }
    {
        let provider = Provider {
            shell,
            admission,
            stop: OnceLock::new(),
            canned: Mutex::new(HashMap::new()),
            node: own_node.as_ref(),
            doors: Mutex::new(node::Doors::default()),
            refusals: Mutex::new(BTreeMap::new()),
        };
        // The serve: a thread per connection, the stdin watcher beside them,
        // every thread joined at the scope's end; the connections accepted
        // counted. An accept the listener refuses is said once per edge —
        // refused, then accepting again, with the episode's seconds and its
        // refused accepts — and paced by ACCEPT_PAUSE.
        thread::scope(|s| {
            s.spawn(|| watch_stdin(&provider, listen));
            let mut accepted = 0u64;
            let mut refusing: Option<(Instant, u64)> = None;
            for conn in listener.incoming() {
                if provider.stopped() {
                    break;
                }
                match conn {
                    Ok(stream) => {
                        if let Some((since, refused)) = refusing.take() {
                            talk(format!(
                                "the provider's listener accepts connections again, after {:.1} s and {refused} refused accept{}",
                                since.elapsed().as_secs_f64(),
                                if refused == 1 { "" } else { "s" }
                            ));
                        }
                        accepted += 1;
                        s.spawn(|| routes::connection(&provider, stream));
                    }
                    Err(e) => {
                        match &mut refusing {
                            Some((_, refused)) => *refused += 1,
                            None => {
                                talk(format!("the provider's listener refused a connection: {e}; it keeps accepting, and says when it accepts again"));
                                refusing = Some((Instant::now(), 1));
                            }
                        }
                        thread::sleep(ACCEPT_PAUSE);
                    }
                }
            }
            // The clean stop, inside the scope and ahead of its join: a call
            // parked on a moment the page has not answered ends only at a
            // cancel — and with the listener stopped no answer can reach it —
            // so the shell's stop, whose first act cancels every pending
            // moment, runs before the join waits on that call's connection.
            // Its cause and the run's figures said ahead of it, and its
            // seconds once it completes — a stop that waits on a board that
            // does not answer is read as one, not as a hang.
            talk(format!(
                "stopping ({}): cancelling every pending moment, closing every session, saving every index — after {accepted} connection{} accepted",
                provider.stop.get().map_or("asked", String::as_str),
                if accepted == 1 { "" } else { "s" }
            ));
            if let Some(line) = provider.refusals_line() {
                talk(line);
            }
            let stopping = Instant::now();
            provider.shell.shutdown();
            talk(format!("stopped: the shell's stop took {:.1} s", stopping.elapsed().as_secs_f64()));
        });
    }
    if let Some(node) = own_node {
        node.shutdown();
        talk(format!("the in-process daemon at {board_origin} is stopped"));
    }
    // The throwaway store, removed as its guard drops, once nothing writes it.
    drop(throwaway);
    Ok(())
}

/// Watches stdin: reads it to its end, then asks the stop with its cause.
///
/// Stdin is read to its end — the parent closed it — or until it cannot be
/// read; the stop line says the cause, and one connect wakes the accept
/// loop.
fn watch_stdin(provider: &Provider<'_>, port: u16) {
    let mut sink = [0u8; 4096];
    let mut stdin = std::io::stdin().lock();
    let cause = loop {
        match stdin.read(&mut sink) {
            Ok(0) => break "stdin closed".to_string(),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => break format!("stdin unreadable: {e}"),
        }
    };
    let _ = provider.stop.set(cause);
    let _ = TcpStream::connect(("127.0.0.1", port));
}
