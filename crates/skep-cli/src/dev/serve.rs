//! `skep-dev serve` — THE DEV PROVIDER (the dev provider record §2.2 (B),
//! §3.1 (i), §3.2; ruled P-1 … P-12): the shell's core (`skep-shell`)
//! served to a page in a browser over loopback HTTP and server-sent events.
//! THE INPUTS: the ONE page origin admitted (`--page-origin`, required);
//! the listen port (`--listen`); the per-run admission secret (`--secret`,
//! else generated and printed ONCE on stdout, the one DATA line); the
//! session mode (`--session bare|signed`, required — both arms were ruled
//! selectable, so a run names one); the dev key store (`--dir`, required
//! under `signed`, a throwaway directory under the system temp dir where
//! none is named under `bare`, removed on every way out of the verb —
//! `~/.skep` is never consulted here, and a key file is refused: the signed
//! arm signs with the key its store holds for the principal); the
//! principal (`--principal`, 1 where omitted); the dev arm's script
//! (`--script`); and the board — `--board`, a daemon already running (the
//! local record's recipe), or `--own` with `--data-dir` and `--port`, the
//! daemon run IN-PROCESS with its test hooks in a `dev-hooks` build. Every
//! usage refusal is judged before anything is made. THE CHECKS before
//! serving, each a halt (exit 3): the board must answer `/health`; the
//! store must hold the principal's key under `signed`; the port must bind.
//! THE SERVE: one thread per connection over a loopback listener, the
//! routes `serve/routes.rs` spells — each refusal the provider makes itself
//! said on TALK the first time its kind is met — until stdin closes: the
//! clean stop, its cause said, every pending moment cancelled, every
//! session closed, every consumer saved, the own node stopped, the
//! throwaway removed — exit 0. An interrupt ends the process with none of
//! it, which the serving line says.

use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Read};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use skep_client::halt::Halt;
use skep_client::sign::fresh_bytes;
use skep_client::Origin;
use skep_shell::{script, ArmConfig, NodeState, Refusal, SessionMode, Shell, ShellOptions};

use crate::args::dev::{DevLine, SessionArm};
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
    /// The script seam's canned refusals, by call: the next answer of that
    /// call.
    pub canned: Mutex<HashMap<String, Value>>,
    /// The in-process node, where the verb runs one.
    pub node: Option<&'d node::Node>,
    /// The permits the fault route holds.
    pub doors: Mutex<node::Doors<'d>>,
    /// The kinds of refusal this provider made itself that TALK has said.
    refusals_said: Mutex<HashSet<&'static str>>,
}

impl Provider<'_> {
    /// Whether the stop was asked.
    pub fn stopped(&self) -> bool {
        self.stop.get().is_some()
    }

    /// A refusal the provider makes itself — the admission's, or a request
    /// it cannot read — said on TALK the first time its `kind` is met in this
    /// run, and never again: a page retrying a refused stream every few
    /// seconds, or a process probing the port, says one line. The kinds are
    /// the admission's four checks and the reader's two refusals, so the
    /// lines are at most six; a browser hides a refused answer from the page
    /// as a CORS failure, and this line is where the developer reads why.
    fn say_refusal_once(&self, kind: &'static str, line: impl FnOnce() -> String) {
        if self.refusals_said.lock().expect("the refusals' lock").insert(kind) {
            talk(line());
        }
    }
}

/// THE THROWAWAY STORE a bare run makes where it names no `--dir`: its
/// directory under the system temp dir, removed — and said — when the guard
/// drops, on every way out of the verb, the clean stop and a halt before
/// serving alike. Declared ahead of the shell that writes into it, so it
/// drops after the shell's own stop has ended every write.
struct Throwaway(PathBuf);

impl Throwaway {
    /// The directory made, named for this run.
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

/// The most characters of a requester's text — a header's value, a
/// malformed line — a refusal's TALK line names: the requester sizes it.
const CLIPPED_CHARS: usize = 120;

/// `text` clipped to [`CLIPPED_CHARS`] characters, an ellipsis where it ran
/// longer.
fn clipped(text: &str) -> String {
    match text.char_indices().nth(CLIPPED_CHARS) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_string(),
    }
}

/// A refusal met before serving, as the halt it is (exit 3).
fn halt_of(r: Refusal) -> Halt {
    match r {
        Refusal::Halt { name, face } => Halt::face(format!("{name}: {}", face.state), face.cause, face.act),
        other => Halt::face(other.name(), other.to_string(), "fix what the refusal names and run again"),
    }
}

/// The pause after an accept the listener refused, before the next: a
/// refusal that persists — the descriptor table full, each event stream
/// holding one — answers again at once, and the loop would spin a core.
const ACCEPT_PAUSE: Duration = Duration::from_millis(10);

/// Where the provider's board runs: a daemon this verb starts in-process
/// (`--own`, its board directory and port), or one already running at the
/// origin `--board` names.
enum BoardAt {
    Own { data_dir: PathBuf, port: u16 },
    Running(Origin),
}

/// `skep-dev serve`.
pub fn serve(c: &DevLine) -> Result<(), Stop> {
    // THE INPUTS — every usage refusal ahead of anything made: a socket, the
    // in-process node, the throwaway store.
    let page_origin = c.page_origin()?;
    let listen = c.listen()?;
    let arm = c.session_mode()?;
    let principal = c.principal()?.unwrap_or(1);
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
    let secret = match c.secret() {
        Some(s) => s.to_string(),
        None => hex(&fresh_bytes(16)),
    };
    let script_answers = match c.script() {
        Some(path) => {
            let text = std::fs::read_to_string(&path).map_err(|e| Usage(format!("--script: {} cannot be read: {e}", path.display())))?;
            Some(script::parse(&text).map_err(|e| Usage(format!("--script: {e}")))?)
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
    let arm_config = match script_answers {
        Some(answers) => ArmConfig::Script(answers),
        None => ArmConfig::Auto,
    };
    let talk_sink: skep_shell::Talk = Arc::new(|line: &str| talk(line));
    let mut options = ShellOptions::new(vec![board_origin.clone()], store_dir.clone(), session_mode, talk_sink);
    options.arm = arm_config;
    options.own_node = own.then(|| board_origin.clone());
    let shell = Shell::open(options);
    // THE CHECKS: the board answers; the key under `signed`; the port binds.
    let board = shell.board_references().into_iter().next().expect("one board");
    let health = shell.call("health", &json!({"board": board})).map_err(halt_of)?;
    talk(format!("board {board_origin}: mode {} (claimant {}, local_trust {})", health["mode"].as_str().unwrap_or("?"), health["health"]["auth"]["claimant"].as_str().unwrap_or("null"), health["health"]["auth"]["local_trust"]));
    if let SessionMode::Signed { .. } = session_mode {
        let keys = shell.check_signed_key().map_err(halt_of)?;
        for k in keys {
            talk(format!("signed: the store {} holds the key {} for principal {principal}", store_dir.display(), k.fingerprint));
        }
    } else {
        talk(format!("bare: sessions bind as principal {principal} from this loopback peer; the store is {}", store_dir.display()));
    }
    if shell.arm_is_script() {
        talk("the dev arm answers the SECRET and CONSENT moments from the script, in order");
    } else {
        talk("the dev arm answers the SECRET and CONSENT moments itself (the auto arm) and says each answer here");
    }
    let listener = TcpListener::bind(("127.0.0.1", listen)).map_err(|e| Halt::face(format!("the provider's port {listen} could not be bound"), e.to_string(), "stop what holds it, or pass --listen"))?;
    let listen = listener.local_addr().map(|a| a.port()).unwrap_or(listen);
    let admission = Admission { page_origin: page_origin.as_str().to_string(), secret: secret.clone(), host: format!("127.0.0.1:{listen}") };
    // THE ONE DATA LINE: the secret.
    data(&secret)?;
    // What an interrupt leaves, said beside the clean stop: the process
    // handles no signal, so Ctrl-C ends it where it stands.
    let mut left = vec![if own_node.is_some() { "the in-process daemon ends without its orderly shutdown" } else { "its sessions live on at the board until it restarts" }];
    if throwaway.is_some() {
        left.push("the throwaway store stays in place");
    }
    talk(format!(
        "serving the bridge for {page_origin} at http://127.0.0.1:{listen}: the page carries ?{SECRET_QUERY}={secret} in its URL and echoes it in the {SECRET_HEADER} header on every call, and on the event stream's URL; the provider stops cleanly when stdin closes (Ctrl-D at a terminal) — an interrupt (Ctrl-C) ends it with none of the clean stop: {}",
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
            refusals_said: Mutex::new(HashSet::new()),
        };
        // THE SERVE: a thread per connection, the stdin watcher beside them,
        // every thread joined at the scope's end. An accept the listener
        // refuses is said once per edge — refused, then accepting again — and
        // paced by ACCEPT_PAUSE.
        thread::scope(|s| {
            s.spawn(|| watch_stdin(&provider, listen));
            let mut refusing = false;
            for conn in listener.incoming() {
                if provider.stopped() {
                    break;
                }
                match conn {
                    Ok(stream) => {
                        if std::mem::take(&mut refusing) {
                            talk("the provider's listener accepts connections again");
                        }
                        s.spawn(|| routes::connection(&provider, stream));
                    }
                    Err(e) => {
                        if !std::mem::replace(&mut refusing, true) {
                            talk(format!("the provider's listener refused a connection: {e}; it keeps accepting, and says when it accepts again"));
                        }
                        thread::sleep(ACCEPT_PAUSE);
                    }
                }
            }
        });
        // THE CLEAN STOP, its cause said.
        talk(format!("stopping ({}): every pending moment cancelled, every session closed, every index saved", provider.stop.get().map_or("asked", String::as_str)));
        provider.shell.shutdown();
    }
    if let Some(node) = own_node {
        node.shutdown();
    }
    // THE THROWAWAY STORE, removed as its guard drops, once nothing writes it.
    drop(throwaway);
    Ok(())
}

/// THE STDIN WATCHER: stdin read to its end — the parent closed it — or
/// until it cannot be read; then the stop asked with its cause, which the
/// stop line says, and the accept loop woken by one connect.
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
