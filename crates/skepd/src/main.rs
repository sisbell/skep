//! The `skepd` binary: the panic hook, then flags/env → [`bind`] →
//! [`Daemon::open_configured`] → [`serve_bound`] → wait → exit 1. The
//! listener is bound BEFORE the open, so a held port is refused in
//! milliseconds with the open's whole cost unpaid and no `kernel.lock`
//! taken; `wait` returns only when every worker thread has ended, which the
//! binary says and exits 1 on — a failure, on a code a supervisor reads as
//! one. Crash-stop is the shutdown story (M2's WAL recovers), so there is
//! no signal handling to get wrong. The binary's own lines — the refusals
//! before each exit, on stderr, and the serving line, on stdout — are
//! written synchronously with the write's result DISCARDED, as the operator
//! stream writes, so a lost reader costs the line and never the daemon or
//! its exit code; the hook's line and the exit's go through the stream's
//! classed door. And THE OPERATOR's TWO TOOLS over a board directory, run
//! with no server — `skepd inventory` and `skepd pull` (`skepd::tools`) — a
//! leading verb parsed before any flag.

use std::fmt;
use std::io::{self, Write};
use std::panic::Location;
use std::path::{Path, PathBuf};
use std::process::exit;

use skep_util::notice::{self, Class};
// `DEFAULT_WORKERS` is the LIBRARY's, not this binary's: it is the fifth
// term of a relation whose other four are the daemon's permit pools, and the
// library holds the assertion that keeps the five in step.
use skepd::{
    bind, serve_bound, tools, AuthOptions, Daemon, MediaOptions, NodePrefix, Origin,
    DEFAULT_WORKERS,
};

const DEFAULT_PORT: u16 = 8642;

/// One environment setting: the variable's name and what its value must be,
/// paired so the two cannot be handed over in the wrong order — the same
/// reason [`skepd::HttpRequest`] is one value rather than five arguments. A
/// swap reads an unset variable, answers `None`, and silently falls back to
/// the default, so the setting stops working with no message anywhere.
struct EnvSetting {
    var: &'static str,
    expected: &'static str,
}

const SKEPD_PORT: EnvSetting = EnvSetting { var: "SKEPD_PORT", expected: "a port" };
const SKEPD_WORKERS: EnvSetting = EnvSetting { var: "SKEPD_WORKERS", expected: "a count" };
const SKEPD_LOCAL_TRUST: EnvSetting =
    EnvSetting { var: "SKEPD_LOCAL_TRUST", expected: "true or false" };
/// The upload setting's variable (wire.md §Media, THE UPLOAD SETTING):
/// `false` closes the upload family, as `--no-uploads` does.
const SKEPD_UPLOADS: EnvSetting = EnvSetting { var: "SKEPD_UPLOADS", expected: "true or false" };

/// The data dir's variable, a bare name rather than an [`EnvSetting`]: its
/// value is a PATH, which is whatever bytes the platform says and never owes
/// being text, so it is read with `var_os` and nothing about it can be "not
/// what was expected" at the parse.
const SKEPD_DATA_DIR: &str = "SKEPD_DATA_DIR";

/// The origin list's variable, a bare name rather than an [`EnvSetting`]:
/// its value is a LIST, so [`from_env`] cannot carry it, and the phrase
/// that pair exists to hold is [`skepd::NotCanonical`]'s — one home for
/// what a canonical origin is, shared with the `--origin` flag.
const SKEPD_ORIGIN: &str = "SKEPD_ORIGIN";

/// The blocked-prefix list's variable, a bare name as the data dir's is: its
/// value is a PATH, which is whatever bytes the platform says and never owes
/// being text, so it is read with `var_os` and nothing about it can be "not
/// what was expected" at the parse. Whether the file it names is a list is
/// [`Daemon::open_with`]'s to say.
const SKEPD_BLOCKED_PREFIXES: &str = "SKEPD_BLOCKED_PREFIXES";

/// THE WORKER FAULT's VARIABLE — a TEST SEAM, read by `test-hooks` builds
/// alone: `inside` or `outside`, the arm `Daemon::panic_the_next_worker` is
/// handed before the workers spawn, so a suite drives the binary's panic
/// hook and the workers' end in the real binary. A shipped build reads no
/// such variable: the read below it does not compile without the feature.
#[cfg(feature = "test-hooks")]
const SKEPD_TEST_WORKER_FAULT: &str = "SKEPD_TEST_WORKER_FAULT";

/// THE EXIT's LINE (`operations.md` §1.1 m16; §4 row 32): what the binary
/// says when `wait` returns — every worker thread has ended, a panic past
/// the handler's catch having taken each — before it exits 1. The class
/// word is the emitter's (`Class::Failure`); the words stand alone here so
/// the unit suite pins them.
const WORKERS_ENDED: &str = "every worker thread has ended; the board serves nothing";

/// THE HOOK's LINE (`operations.md` §1.1 row 41), the words alone — a pure
/// function the unit suite pins: the thread by its name (`an unnamed thread`
/// where it has none), `a thread panicked at` the location as std spells it
/// (`file:line:column`; `an unknown location` where the hook's info carries
/// none), and the payload ONLY where it is a `&'static str` — a literal the
/// code wrote, which no request can have formatted — so a formatted panic
/// (`expect`, `assert_eq!`, an index) shows its location alone, which
/// identifies the site, and nothing of §1's NEVER list can ride the line.
/// The class word is the emitter's (`Class::Failure`).
fn panic_line(
    thread: Option<&str>,
    location: Option<&Location<'_>>,
    payload: Option<&str>,
) -> String {
    let thread = thread.unwrap_or("an unnamed thread");
    let at = location.map_or_else(|| "an unknown location".to_string(), |at| at.to_string());
    match payload {
        Some(payload) => format!("{thread}: a thread panicked at {at}: {payload}"),
        None => format!("{thread}: a thread panicked at {at}"),
    }
}

/// THE HOOK, INSTALLED — the binary's, never the library's (a process-global
/// an embedder must be free to set itself): one prefixed, timed line through
/// the operator stream's classed door at every panic, before any catch —
/// Rust's own unprefixed text never reaches the stream. Installed FIRST,
/// before the command line is read, so no thread of this process's panics
/// outside it. The line is enqueued as every notice is and written by the
/// stream's thread: a worker's panic lands while the daemon serves on; a
/// panic on `main`'s own thread unwinds to exit 101 with no drain, so the
/// line races the exit and the stream's thread wins it or not.
fn install_the_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let payload = info.payload().downcast_ref::<&'static str>().copied();
        notice::emit(Class::Failure, panic_line(thread.name(), info.location(), payload));
    }));
}

/// One line of the binary's own on stderr — a refusal before its exit —
/// written synchronously with the write's result DISCARDED (`operations.md`
/// §0 fact 1): a lost reader costs the line and never the exit code, where
/// `eprintln!` would panic and turn an exit 1 or 2 into 101. Synchronous
/// because the exit follows at once, and the stream's queue is drained
/// before it wherever a line of the open's could still be waiting.
fn refuse(line: fmt::Arguments<'_>) {
    let _ = writeln!(io::stderr(), "{line}");
}

/// THE LOOSE DATA DIRECTORY's REFUSAL: a data directory that stands and
/// that other users of this machine can read — any group or other bit set
/// — is refused before the open, in these words: the directory as the
/// operator named it, the mode found, in octal, and the one act that fixes
/// it, named once. The posture is refuse-never-repair: nothing is chmod'd
/// and nothing is created inside the directory. A pure value the unit
/// suite pins by `to_string()`; [`loose_data_dir`] is what finds one.
struct LooseDataDir<'a> {
    path: &'a Path,
    mode: u32,
}

impl fmt::Display for LooseDataDir<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the data directory {} is mode {:o}: other users of this machine can read the board; \
             chmod 700 {} and start again",
            self.path.display(),
            self.mode,
            self.path.display()
        )
    }
}

/// The refusal for `path` where it is a directory that stands and other
/// users can read it — `mode & 0o077 != 0`, on unix — and `None` where it
/// does not exist (the kernel then creates it owner-only, and no mode is
/// ever refused on a directory the board made), where it is no directory
/// (the open's own refusal names that), and on every other platform, which
/// has no mode to read.
fn loose_data_dir(path: &Path) -> Option<LooseDataDir<'_>> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_dir() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Some(LooseDataDir { path, mode });
        }
    }
    None
}

/// The node prefix's variable (REG-1.69), carried by [`from_env`] like every
/// other setting: [`NodePrefix`]'s `FromStr` is what lets it, so the two
/// rules that pair holds — a non-UTF-8 value refused rather than read as
/// absent, and one message shape — are stated once and spent here too.
const SKEPD_NODE_PREFIX: EnvSetting =
    EnvSetting { var: "SKEPD_NODE_PREFIX", expected: NODE_PREFIX_FORM };

/// What `--node-prefix` takes (REG-1.66, REG-1.69), said once for the flag,
/// the variable and the usage text.
const NODE_PREFIX_FORM: &str =
    "a node prefix of the form 1.N — the board's node address under the root 1, never the root itself";

/// The help text, with each default read from the constant that supplies
/// it — so the program cannot describe a default it does not use.
fn usage() -> String {
    format!(
        "\
usage: skepd --data-dir <DIR> [--port <PORT>] [--workers <N>]
             [--local-trust | --no-local-trust] [--allow-preview-keys]
             [--uploads | --no-uploads]
             [--origin <ORIGIN>]... [--blocked-prefixes <FILE>]
             [--node-prefix <PREFIX>]
       skepd inventory --data-dir <DIR> [--no-rehash]
       skepd pull --data-dir <DIR> [--hash <HEX>] <FILE>

  --data-dir <DIR>   the board's directory (env: SKEPD_DATA_DIR): the
                     journal and its checkpoints, the blob store under
                     blobs/, and the change feed's files — commits.log,
                     the four feed-*.log files and feed-attest.log;
                     created if absent, recovered if populated. Created
                     owner-only — the directory 0700 and every file in
                     it 0600, set at creation whatever the umask — and a
                     directory other users of this machine can read is
                     refused at start: chmod 700 it and start again
  --port <PORT>      TCP port on 127.0.0.1 (env: SKEPD_PORT; default \
{DEFAULT_PORT};
                     0 picks an ephemeral port)
  --workers <N>      request worker threads (env: SKEPD_WORKERS; default \
{DEFAULT_WORKERS};
                     minimum 1)
  --local-trust      honor bare (unsigned) loopback sessions after the
                     board is claimed (the default — a hosted image must
                     pass --no-local-trust affirmatively)
  --no-local-trust   refuse every bare session once the board is claimed
                     (env: SKEPD_LOCAL_TRUST=true|false)
  --uploads          admit the blob upload family (the default), under a
                     per-account limit of one eighth of the volume's
                     capacity, never below 256 MiB, until a limits record
                     is installed; echoed on /health as media.uploads
  --no-uploads       refuse the upload's creation and resume before any
                     body byte (403 upload_refused, detail uploads_closed);
                     the reads, the termination, the door and the pruner
                     serve as before (env: SKEPD_UPLOADS=true|false)
  --allow-preview-keys
                     a DEV setting: admit the ENROLLMENT of PREVIEW keys
                     (the tag-3 row, fndsa512-preview-ed25519). Off — the
                     default — an enrollment record naming one is refused
                     credential_refused preview_key, a genesis included;
                     a served board runs without it. It gates enrollment
                     alone: verification of tag 3 stays compiled in, and
                     the fold admits the row as syntax
  --origin <ORIGIN>  a canonical origin this board answers for, e.g.
                     https://board.example — repeatable; the signed
                     session arm accepts ONLY these once the board is
                     claimed (env: SKEPD_ORIGIN, comma-separated)
  --blocked-prefixes <FILE>
                     the blocked-prefix list the operator maintains
                     (env: SKEPD_BLOCKED_PREFIXES): one JSON object,
                     {{\"operator\": <account>, \"binding_writer\": <account>,
                      \"entries\": [{{\"prefix\": <address>,
                                   \"record\": <address>}}, ...]}}
                     — the two header fields optional. A session under a
                     listed prefix is refused 403 prefix_blocked and a
                     live one ends. Read at EVERY start (a file that
                     cannot be read, or is not a list, stops the start)
                     and re-read whenever it is REPLACED — write the new
                     list beside it and rename it over; no restart, no
                     signal
  --node-prefix <PREFIX>
                     the board's full node prefix in the registry, 1.N
                     (env: SKEPD_NODE_PREFIX) — an address under the root
                     1, never the root itself. Egress and assertion
                     config, per daemon, supplied at every start and
                     never journaled; a fresh prefix is a reconfigure
                     and restart. What it decides here: the blocked-
                     prefix list's off-board test — whether the list's
                     configured operator account is an account of this
                     board — runs against it. Without it that test is
                     OFF (every operator reads as this board's own): a
                     hosted board must supply one
  --help             this text

The operator's two tools run over a board directory with NO server — no
port, no session — and write no log line of the daemon's:

  skepd inventory --data-dir <DIR> [--no-rehash]
                     over a directory no daemon serves (a stopped board, a
                     backup, one moment's copy): one JSON object on stdout
                     — the holes (every picture cell whose file is absent,
                     of another length, or — re-hashed, one whole read per
                     file, skipped by --no-rehash — of other bytes), each
                     account's base and pending bytes, the bytes whose key
                     names no account, and the venue total they all sum to,
                     the standing and expired uploads, the halt marks and
                     any foreign designation directory. Recording no read.
                     The journal is opened as the daemon opens it: a
                     directory a daemon serves is refused at the kernel's
                     lock; a torn tail is cut as every open cuts it
  skepd pull --data-dir <DIR> [--hash <HEX>] <FILE>
                     restore <FILE> at blobs/blake3/<its hash> by the PUT's
                     own install order — REPLACE where a file stands — with
                     no lease, no record and no journal entry: a restore,
                     never a deposit. Without --hash the board's journal is
                     read and a file no committed cell names is refused;
                     with --hash <HEX> (the inventory's listing) the file is
                     held to that hash and the journal left unopened, the
                     form that runs beside a serving daemon

The wire protocol is specified in skep/docs/wire.md."
    )
}

/// What the command line asked for: the daemon, or one of the two tools.
enum Command {
    Serve(Args),
    Inventory { data_dir: PathBuf, check: tools::HoleCheck },
    Pull { data_dir: PathBuf, hash: Option<String>, file: PathBuf },
}

/// Which of the operator's two tools a line names — read off its leading
/// verb, and what the tool's own flags are admitted by.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tool {
    Inventory,
    Pull,
}

impl Tool {
    /// The tool's verb, as the line spells it and every refusal names it.
    fn verb(self) -> &'static str {
        match self {
            Tool::Inventory => "inventory",
            Tool::Pull => "pull",
        }
    }
}

struct Args {
    data_dir: PathBuf,
    port: u16,
    workers: usize,
    local_trust: bool,
    /// `--uploads` / `--no-uploads` (wire.md §Media): the upload family's
    /// switch, OPEN by default.
    uploads: bool,
    /// `--allow-preview-keys` (AUTH-1.44): a flag, no environment variable —
    /// a dev setting a served board never sets, so nothing can turn it on in
    /// silence from the image's environment.
    allow_preview_keys: bool,
    origins: Vec<Origin>,
    blocked_prefixes: Option<PathBuf>,
    node_prefix: Option<NodePrefix>,
}

/// Read one setting from the environment, or `None` when it is UNSET. Each
/// setting is seeded from its variable before the flag loop, so a flag
/// always wins over a variable and the precedence is stated once.
fn from_env<T: std::str::FromStr>(setting: EnvSetting) -> Result<Option<T>, String> {
    use std::env::VarError;
    match std::env::var(setting.var) {
        Err(VarError::NotPresent) => Ok(None),
        // Set, and not readable as text. Refused rather than treated as
        // absent: silently falling back to the default is the one failure
        // [`EnvSetting`] exists to prevent, and it does not become
        // acceptable because the bad value is bytes rather than the wrong
        // word.
        Err(VarError::NotUnicode(_)) => {
            Err(format!("{}: the value is not UTF-8 text", setting.var))
        }
        Ok(v) => v.parse().map(Some).map_err(|_| {
            format!("{}: '{v}' is not {}", setting.var, setting.expected)
        }),
    }
}

/// The command line, or `None` when the caller asked for the usage text:
/// a leading verb names a tool, read before any flag; anything else is the
/// daemon's own line. Parsing decides what was asked for; ending the
/// process is [`main`]'s.
fn parse_command(argv: impl Iterator<Item = String>) -> Result<Option<Command>, String> {
    let mut it = argv.peekable();
    match it.peek().map(String::as_str) {
        Some("inventory") => {
            it.next();
            parse_tool(it, Tool::Inventory)
        }
        Some("pull") => {
            it.next();
            parse_tool(it, Tool::Pull)
        }
        _ => Ok(parse_args(it)?.map(Command::Serve)),
    }
}

/// The line of `tool`, its verb already read: `--data-dir <DIR>` (or the
/// variable), `--no-rehash` for the inventory, `--hash <HEX>` and the one
/// positional `<FILE>` for the pull; `--help` the usage text. A flag of the
/// other tool's is an unknown argument here, refused naming this tool.
fn parse_tool(mut it: impl Iterator<Item = String>, tool: Tool) -> Result<Option<Command>, String> {
    let verb = tool.verb();
    let mut data_dir = std::env::var_os(SKEPD_DATA_DIR).map(PathBuf::from);
    let mut check = tools::HoleCheck::Rehash;
    let mut hash: Option<String> = None;
    let mut file: Option<PathBuf> = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--data-dir" => {
                let v = it.next().ok_or("--data-dir needs a value")?;
                data_dir = Some(PathBuf::from(v));
            }
            "--no-rehash" if tool == Tool::Inventory => check = tools::HoleCheck::LengthOnly,
            "--hash" if tool == Tool::Pull => {
                let v = it.next().ok_or("--hash needs a value")?;
                hash = Some(v);
            }
            "--help" | "-h" => return Ok(None),
            other if tool == Tool::Pull && !other.starts_with("--") && file.is_none() => {
                file = Some(PathBuf::from(other));
            }
            other => return Err(format!("{verb}: unknown argument '{other}'")),
        }
    }
    let data_dir =
        data_dir.ok_or_else(|| format!("{verb}: --data-dir (or {SKEPD_DATA_DIR}) is required"))?;
    Ok(Some(match tool {
        Tool::Pull => {
            let file = file.ok_or("pull: the file to restore is required")?;
            Command::Pull { data_dir, hash, file }
        }
        Tool::Inventory => Command::Inventory { data_dir, check },
    }))
}

/// The daemon's own command line, or `None` when the caller asked for the
/// usage text.
fn parse_args(argv: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut data_dir = std::env::var_os(SKEPD_DATA_DIR).map(PathBuf::from);
    let mut port: Option<u16> = from_env(SKEPD_PORT)?;
    let mut workers: Option<usize> = from_env(SKEPD_WORKERS)?;
    let mut local_trust: Option<bool> = from_env(SKEPD_LOCAL_TRUST)?;
    let mut uploads: Option<bool> = from_env(SKEPD_UPLOADS)?;
    // The one setting [`from_env`] cannot carry, being a LIST — so the
    // two rules that helper holds are restated here and nowhere else: a
    // variable set to bytes that are not text is refused rather than read
    // as absent, and each element goes through [`Origin`]'s own `FromStr`.
    let mut origins: Vec<Origin> = match std::env::var(SKEPD_ORIGIN) {
        Err(std::env::VarError::NotPresent) => Vec::new(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{}: the value is not UTF-8 text", SKEPD_ORIGIN))
        }
        Ok(v) => v
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<Origin>().map_err(|e| {
                    format!("{}: '{s}' is {e}", SKEPD_ORIGIN)
                })
            })
            .collect::<Result<_, _>>()?,
    };
    let mut blocked_prefixes = std::env::var_os(SKEPD_BLOCKED_PREFIXES).map(PathBuf::from);
    let mut node_prefix: Option<NodePrefix> = from_env(SKEPD_NODE_PREFIX)?;
    // Default OFF, and no variable seeds it (AUTH-1.44: "the daemon REFUSES
    // ENROLLMENT of a tag-3 key unless this setting allows it").
    let mut allow_preview_keys = false;
    let mut it = argv;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--data-dir" => {
                let v = it.next().ok_or("--data-dir needs a value")?;
                data_dir = Some(PathBuf::from(v));
            }
            "--port" => {
                let v = it.next().ok_or("--port needs a value")?;
                port = Some(v.parse().map_err(|_| format!("--port: '{v}' is not a port"))?);
            }
            "--workers" => {
                let v = it.next().ok_or("--workers needs a value")?;
                workers =
                    Some(v.parse().map_err(|_| format!("--workers: '{v}' is not a count"))?);
            }
            "--local-trust" => local_trust = Some(true),
            "--no-local-trust" => local_trust = Some(false),
            "--uploads" => uploads = Some(true),
            "--no-uploads" => uploads = Some(false),
            "--allow-preview-keys" => allow_preview_keys = true,
            "--origin" => {
                let v = it.next().ok_or("--origin needs a value")?;
                origins.push(
                    v.parse::<Origin>().map_err(|e| format!("--origin: '{v}' is {e}"))?,
                );
            }
            "--blocked-prefixes" => {
                let v = it.next().ok_or("--blocked-prefixes needs a value")?;
                blocked_prefixes = Some(PathBuf::from(v));
            }
            "--node-prefix" => {
                let v = it.next().ok_or("--node-prefix needs a value")?;
                node_prefix = Some(v.parse::<NodePrefix>().map_err(|_| {
                    format!("--node-prefix: '{v}' is not {NODE_PREFIX_FORM}")
                })?);
            }
            "--help" | "-h" => return Ok(None),
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    // Refused, never repaired. `serve` states `workers >= 1` as a
    // precondition and asserts it, and the wire surface refuses an
    // out-of-range page size rather than clamping it; a count silently
    // raised to one here would be the third answer to that one question,
    // and the one that teaches a caller its zero was fine.
    let workers = workers.unwrap_or(DEFAULT_WORKERS);
    if workers == 0 {
        return Err("--workers: a server with no workers serves nothing".into());
    }
    Ok(Some(Args {
        data_dir: data_dir
            .ok_or_else(|| format!("--data-dir (or {SKEPD_DATA_DIR}) is required"))?,
        port: port.unwrap_or(DEFAULT_PORT),
        workers,
        // Phase A default ON (AUTH-1.45): a hosted image must set the flag
        // AFFIRMATIVELY false — abstention keeps the notebook behavior.
        local_trust: local_trust.unwrap_or(true),
        // OPEN by default (the owner's ruling), the default per-account
        // limit in force from start; the off switch is affirmative.
        uploads: uploads.unwrap_or(true),
        allow_preview_keys,
        origins,
        blocked_prefixes,
        node_prefix,
    }))
}

fn main() {
    install_the_panic_hook();
    let args = match parse_command(std::env::args().skip(1)) {
        Ok(Some(Command::Serve(a))) => a,
        // THE TOOLS: one object or one line on stdout, one line on stderr
        // where refused, no server bound. A tool's answer is its whole work,
        // so its `println!` STAYS: an answer that cannot be written fails the
        // tool loudly rather than exiting 0 as if it had been delivered.
        Ok(Some(Command::Inventory { data_dir, check })) => match tools::inventory(&data_dir, check) {
            Ok(v) => {
                println!("{}", serde_json::to_string_pretty(&v).expect("a JSON value renders"));
                exit(0);
            }
            Err(e) => {
                refuse(format_args!("skepd inventory: {e}"));
                exit(1);
            }
        },
        Ok(Some(Command::Pull { data_dir, hash, file })) => match tools::pull(&data_dir, &file, hash.as_deref()) {
            Ok(pulled) => {
                println!("pulled {} ({} bytes) into {}", pulled.hex, pulled.size, pulled.path.display());
                exit(0);
            }
            Err(e) => {
                refuse(format_args!("skepd pull: {e}"));
                exit(1);
            }
        },
        Ok(None) => {
            println!("{}", usage());
            exit(0);
        }
        Err(e) => {
            refuse(format_args!("skepd: {e}\n\n{}", usage()));
            exit(2);
        }
    };
    // THE BIND, FIRST: a port another process holds is decidable before any
    // byte of the journal is read, so it is refused here — at once, exit 1,
    // with no `kernel.lock` taken and nothing created under the data
    // directory — and not after the open's whole cost. The port is held
    // through the open; a connect meanwhile waits in the backlog for the
    // first worker. No line of the stream's has been said yet, so nothing
    // waits to be drained before this refusal.
    let listener = match bind(args.port) {
        Ok(l) => l,
        Err(e) => {
            refuse(format_args!("skepd: bind 127.0.0.1:{}: {e}", args.port));
            exit(1);
        }
    };
    // THE WORKER FAULT's ARM (test seam, `test-hooks` builds alone): the
    // variable names the arm, before any worker exists.
    #[cfg(feature = "test-hooks")]
    if let Some(arm) = std::env::var_os(SKEPD_TEST_WORKER_FAULT) {
        Daemon::panic_the_next_worker(arm.to_str().expect("the worker fault's arm is text"));
    }
    // THE LOOSE DIRECTORY, REFUSED (unix): a data directory that stands and
    // that other users of this machine can read is refused here — before
    // the open, so no `kernel.lock` is taken and nothing is created inside
    // it — naming the directory, the mode found and the one act that fixes
    // it, repairing nothing. A directory that does not exist is the
    // kernel's to create, owner-only, and is never refused. This is the
    // served start's door alone: the library's open and the two tools open
    // the directory the caller names as they find it. No line of the
    // stream's has been said yet, so nothing waits to be drained.
    if let Some(loose) = loose_data_dir(&args.data_dir) {
        refuse(format_args!("skepd: {loose}"));
        exit(1);
    }
    // Genesis-or-recover; every EngineError is an operator condition
    // (corrupt journal, bad checkpoint) — report and stop.
    // `--origin` names the CONFIGURED set — the flag's own vocabulary and
    // the field's meet here, at the two lines that carry them across. Built
    // from the defaults and then set, which is what `AuthOptions` being
    // `#[non_exhaustive]` asks: a knob this binary grows no flag for arrives
    // at its own default rather than at whatever a literal here omitted.
    let mut opts = AuthOptions::default();
    opts.local_trust = args.local_trust;
    // The dev setting (AUTH-1.44): ENROLLMENT of tag-3 keys, refused unless
    // the flag says otherwise; a served board is launched without it.
    opts.allow_preview_keys = args.allow_preview_keys;
    opts.configured = args.origins;
    // Supplied at every start, as `--origin` is (AUTH-4.70): the file is
    // read inside the open, and one that is not a list stops the start.
    opts.blocked_supply_path = args.blocked_prefixes;
    // The node prefix (REG-1.69): egress and assertion config, supplied at
    // every start and never journaled — a fresh one is this binary
    // relaunched (REG-1.70). `serve` names it, or its absence, at start.
    opts.node_prefix = args.node_prefix;
    // The media resource's setting (wire.md §Media): the upload switch,
    // open unless `--no-uploads` closed it.
    let mut media = MediaOptions::default();
    media.uploads = args.uploads;
    let daemon = match Daemon::open_configured(&args.data_dir, opts, media) {
        Ok(d) => d,
        Err(e) => {
            notice::drain();
            refuse(format_args!("skepd: {e}"));
            exit(1);
        }
    };
    let seq = daemon.log_position();
    // THE SERVE over the bound listener: the auth port bound to the port
    // the bind answered, the warnings, then the workers. What can fail here
    // is the OS refusing a worker thread — the bind's own refusal was said
    // above — so the line says that: the act, the cause, what the start left
    // and the act that clears it.
    let running = match serve_bound(daemon, listener, args.workers) {
        Ok(s) => s,
        Err(e) => {
            notice::drain();
            refuse(format_args!(
                "skepd: the OS refused a worker thread at start: {e}; the workers that started \
                 are stopped, the port and the data directory released, and nothing serves; \
                 retry under a higher thread limit"
            ));
            exit(1);
        }
    };
    // THE SERVING LINE, on stdout — the one line that names the port under
    // `--port 0`, outside the stream's grammar — written once the open's
    // report has reached the stream, so an operator reads the board's
    // standing before the line that says it serves; the write's result
    // DISCARDED: a stdout whose reader is gone costs this line and never
    // the daemon, which serves on.
    notice::drain();
    let _ = writeln!(
        io::stdout(),
        "skepd: serving http://127.0.0.1:{}/ data-dir {} log-position {} workers {}",
        running.port(),
        args.data_dir.display(),
        seq.0,
        args.workers
    );
    running.wait();
    // THE WORKERS' END: `wait` returns only when every worker thread has
    // ended — a FAILURE in serve mode, said as one and exited 1 on, never
    // the fall-off's 0 a supervisor reads as a clean end. The queue is
    // drained so the line, and the hook's before it, reach the stream.
    notice::emit(Class::Failure, WORKERS_ENDED);
    notice::drain();
    exit(1);
}

#[cfg(test)]
mod tests;
