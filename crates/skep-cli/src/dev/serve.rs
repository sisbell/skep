//! `skep-dev serve` — THE DEV PROVIDER (the dev provider record §2.2 (B),
//! §3.1 (i), §3.2; ruled P-1 … P-12): the shell's core (`skep-shell`)
//! served to a page in a browser over loopback HTTP and server-sent events.
//! THE INPUTS: the ONE page origin admitted (`--page-origin`, required);
//! the listen port (`--listen`); the per-run admission secret (`--secret`,
//! else generated and printed ONCE on stdout, the one DATA line); the
//! session mode (`--session bare|signed`, required — both arms were ruled
//! selectable, so a run names one); the dev key store (`--dir`, required
//! under `signed`, a throwaway directory under the system temp dir where
//! none is named under `bare` — `~/.skep` is never consulted here); the
//! principal (`--principal`, 1 where omitted); the dev arm's script
//! (`--script`); and the board — `--board`, a daemon already running (the
//! local record's recipe), or `--own` with `--data-dir` and `--port`, the
//! daemon run IN-PROCESS with its test hooks in a `dev-hooks` build.
//! THE CHECKS before serving, each a halt (exit 3): the board must answer
//! `/health`; the store must hold the principal's key under `signed`; the
//! port must bind. THE SERVE: one thread per connection over a loopback
//! listener, the routes `serve/routes.rs` spells, until stdin closes —
//! the clean stop: every pending moment cancelled, every session closed,
//! every consumer saved, the own node stopped — exit 0.

use std::collections::HashMap;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{json, Value};
use skep_client::halt::Halt;
use skep_client::sign::fresh_bytes;
use skep_shell::refs::hex;
use skep_shell::shell::{ArmConfig, NodeState, SessionMode, ShellOptions};
use skep_shell::{script, Refusal, Shell};

use crate::args::dev::{DevLine, SessionArm};
use crate::args::Usage;
use crate::shared::{data, Stop};
use crate::terminal::talk;

// The HTTP/1.1 subset and the event stream's framing.
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
    stop: AtomicBool,
    /// The script seam's canned refusals, by call: the next answer of that
    /// call.
    pub canned: Mutex<HashMap<String, Value>>,
    /// The in-process node, where the verb runs one.
    pub node: Option<&'d node::Node>,
    /// The permits the fault route holds.
    pub doors: Mutex<node::Doors<'d>>,
}

impl Provider<'_> {
    /// Whether the stop was asked.
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// A refusal met before serving, as the halt it is (exit 3).
fn halt_of(r: Refusal) -> Halt {
    match r {
        Refusal::Halt { name, face } => Halt::face(format!("{name}: {}", face.state), face.cause, face.act),
        other => Halt::face(other.name(), other.to_string(), "fix what the refusal names and run again"),
    }
}

/// `skep-dev serve`.
pub fn serve(c: &DevLine) -> Result<(), Stop> {
    // THE INPUTS — every usage refusal ahead of any socket.
    let page_origin = c.page_origin()?;
    let listen = c.listen()?;
    let arm = c.session_mode()?;
    let principal = c.principal()?.unwrap_or(1);
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
    let store_dir = match c.store_dir_given()? {
        Some(dir) => dir,
        None => {
            if arm == SessionArm::Signed {
                return Err(Usage("--dir (or SKEP_KEYSTORE) is required under --session signed: the store that holds the dev key".into()).into());
            }
            let dir = std::env::temp_dir().join(format!("skep-dev-serve-{}", hex(&fresh_bytes(4))));
            std::fs::create_dir_all(&dir).map_err(|e| Halt::face("the throwaway store could not be made", e.to_string(), "pass --dir"))?;
            dir
        }
    };
    let own = c.own();
    if own && c.origin_given()?.is_some() {
        return Err(Usage("--own and a board (--board or SKEP_BOARD): give one".into()).into());
    }
    let (own_node, board_origin) = if own {
        let data_dir = c.data_dir()?;
        let node = node::start(&data_dir, c.node_port()?, !c.no_local_trust())?;
        let origin = node::origin_of(&node).clone();
        talk(format!("the daemon runs in-process at {origin} over {} (local trust {}); its lines are this stream's", data_dir.display(), if c.no_local_trust() { "off" } else { "on" }));
        (Some(node), origin)
    } else {
        (None, c.origin()?)
    };
    let mode = match arm {
        SessionArm::Bare => SessionMode::Bare { principal },
        SessionArm::Signed => SessionMode::Signed { principal },
    };
    let arm_config = match script_answers {
        Some(answers) => ArmConfig::Script(answers),
        None => ArmConfig::Auto,
    };
    let talk_sink: skep_shell::Talk = Arc::new(|line: &str| talk(line));
    let shell = Shell::open(ShellOptions {
        boards: vec![board_origin.clone()],
        store_dir: store_dir.clone(),
        mode,
        arm: arm_config,
        talk: talk_sink,
        own_node: own.then(|| board_origin.clone()),
    })?;
    // THE CHECKS: the board answers; the key under `signed`; the port binds.
    let board = shell.board_references().into_iter().next().expect("one board");
    let health = shell.call("health", &json!({"board": board})).map_err(halt_of)?;
    talk(format!("board {board_origin}: mode {} (claimant {}, local_trust {})", health["mode"].as_str().unwrap_or("?"), health["health"]["auth"]["claimant"].as_str().unwrap_or("null"), health["health"]["auth"]["local_trust"]));
    if let SessionMode::Signed { .. } = mode {
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
    talk(format!(
        "serving the bridge for {page_origin} at http://127.0.0.1:{listen}: the page carries ?{SECRET_QUERY}={secret} in its URL and echoes it in the {SECRET_HEADER} header on every call, and on the event stream's URL; the provider stops when stdin closes"
    ));
    if own {
        shell.set_node_state(NodeState::Running);
        shell.bus().emit(skep_shell::events::DAEMON, json!({"board": board, "state": "running"}));
    }
    {
        let provider = Provider { shell, admission, stop: AtomicBool::new(false), canned: Mutex::new(HashMap::new()), node: own_node.as_ref(), doors: Mutex::new(node::Doors::default()) };
        // THE SERVE: a thread per connection, the stdin watcher beside them,
        // every thread joined at the scope's end.
        thread::scope(|s| {
            s.spawn(|| watch_stdin(&provider, listen));
            for conn in listener.incoming() {
                if provider.stopped() {
                    break;
                }
                let Ok(stream) = conn else { continue };
                s.spawn(|| routes::connection(&provider, stream));
            }
        });
        // THE CLEAN STOP.
        talk("stopping: every pending moment cancelled, every session closed, every index saved");
        provider.shell.shutdown();
    }
    if let Some(node) = own_node {
        node.shutdown();
    }
    Ok(())
}

/// THE STDIN WATCHER: stdin read to its end — the parent closed it — then
/// the stop asked and the accept loop woken by one connect.
fn watch_stdin(provider: &Provider<'_>, port: u16) {
    let mut sink = [0u8; 4096];
    let mut stdin = std::io::stdin().lock();
    while let Ok(n @ 1..) = stdin.read(&mut sink) {
        let _ = n;
    }
    provider.stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(("127.0.0.1", port));
}
