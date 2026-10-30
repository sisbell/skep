//! `skep-mcp`, the adapter between an agent harness and a board.
//!
//! The harness speaks MCP (JSON-RPC 2.0 over stdio, newline-delimited UTF-8,
//! one message per line), and the board is served through the shell's core,
//! `skep-shell` — the engine the dev provider and the desktop shell run on.
//! One process per agent, one board, one signed session at a time:
//!
//! * **Every tool is one call of the shell**, under that session where the
//!   call takes one. Every wire op but `publish` is a tool whose name *is*
//!   the frame's `op` and whose arguments *are* the frame (the one mapping is
//!   `from_` → `from` on make_link/emit, when the arguments carry no `from`
//!   of their own), sent as `op(session, frame)`: attested where the
//!   session's key attests the kind, held where the board cannot take a burst
//!   or rejects one (the `held` answer comes back as data; a refused run's
//!   line, and the bursts behind it on its document, wait on the agent's
//!   `resolve`), a `write_busy` reissued once and a `durability` twice within
//!   the call, as the shell does. A publication crosses as the shell's
//!   `publication` family instead: the shell refuses a `publish` frame
//!   through `op` (`publish_is_a_call`), and composes, signs and sends the
//!   one request itself from the panel it holds (`client.md` §4b.1's `op`
//!   row). The shell's own calls — `boards`, `health`, `probe`, `search`,
//!   `places`, `held`, `resolve`, and that family's four, each named as its
//!   row with `_` for `.` (`publication_open`, `publication_count`,
//!   `publication_confirm`, `publication_cancel`) — are tools of those names,
//!   their arguments the bridge's row minus the session and the board, the
//!   adapter supplying each where the row requires it; and three are the
//!   adapter's apparatus: `session_info`, `changes_since` (the shell's
//!   `changes`, a pull), and `fetch` (the shell's streamed fetch as an image or
//!   resource block, the type sniffed off the bytes, the size capped). The
//!   adapter passes a wire op's arguments through unread, save the one shape
//!   the shell's `op` row reads as its `/op-at` form, a non-negative integer
//!   `at` beside an object `frame`, which no wire op takes. Before the board
//!   sees a frame, the shell refuses one it cannot send or hold whole, nothing
//!   sent, each refusal `isError`: a burst whose `doc` is no document address
//!   in its one spelling (`malformed_args` naming `frame.doc`) or whose frame
//!   would pass the board's cap (`frame_too_large`), and a write of the nine
//!   kinds the session's key attests through `op` — the ten but `publish` —
//!   whose attest it cannot compose from the frame (`attest_not_composed`, a
//!   halt). Where the board refuses a read the shell makes to compose that
//!   attest, the call answers the read's verdict, as data, and the write is
//!   not sent. Past the shell's checks, a frame goes to the board, whose
//!   strict parse is its validator, its rejection data.
//! * **A refusal as a result.** The board's verdict is data: a `refused`
//!   refusal is a normal tool result, the verdict's body verbatim under `body`
//!   with the refusal's `kind`, `name`, `status`, `code`, `detail` and `op`
//!   beside it, since a client that cannot decode a rejection has been
//!   silently failed (wire.md §Rejections). `isError` is every other refusal —
//!   the shell could not get the board's verdict: the board unreachable, a
//!   halt, the block, the shell's own names — and `fetch`'s two answers of the
//!   adapter's own, a file past its cap and a stream cut short, each a plain
//!   sentence. A write refused `unreachable` may have committed: the shell
//!   faces a lost answer to any write but a burst (whose line it holds,
//!   `sent`), and the adapter never reissues it. So may a write the board
//!   refused `poisoned`, whose frames its restart replays from the journal
//!   (wire.md §Rejection codes; client.md §3c.2), or answered
//!   `500 internal_panic` past its commit — each the board's verdict, and so
//!   data. A call the adapter will not run — a tool outside the catalog, a
//!   member an adapter tool's row or its `opts` does not take, a wire op's
//!   arguments of the shell's `/op-at` shape — is no tool result at all: it is
//!   refused -32602, as malformed `tools/call` params are; a member of the
//!   wrong form is the shell's `malformed_args`.
//! * **A signed session, opened at startup**, before the first tool call, for
//!   the configured principal with the store's key for it — enrolled in its
//!   account's set or the nearest set above it — and no bare mode exists. No
//!   key, a key the board refuses, or a board that does not answer stops the
//!   adapter before it serves: a start waits for no board, and is made again
//!   once the board answers. A board restart is met by the shell's silent
//!   re-open; a death the shell does not re-open — the key retired, the prefix
//!   blocked, the account seeded, the board's mode moved, a re-open refused —
//!   stops the process with one plain line naming the arm, and so does a
//!   refusal of a session the adapter opens itself where the shell's end left
//!   none; a sign-in the board did not accept at either open (`busy`) lapses
//!   the session instead, as a board that does not answer does, and a later
//!   call opens one. No person is at the seam (`ArmConfig::Refuse`): no
//!   ceremony tool is offered, every secret or consent moment would be refused
//!   `person_required`, and `search` takes no `opts.reindex`, the person's
//!   refresh of the index (`search.md` §5.5), which re-reads every document
//!   the index holds while the call waits.
//!
//! `server.rs` is the MCP side: the stdio transport — stdin's reader, and the
//! loop that answers on stdout each line owed an answer — the JSON-RPC
//! dispatch, and `call`, which keeps *a refusal as a result*. `shell.rs` is
//! the backend, the one module that calls the shell: the open and its checks,
//! every call — under the one session where it takes one — and the life
//! around it, the bus drained; its child `shell/watch.rs` is the session's
//! state, which one door moves (`SessionWatch::move_off`), and what a death
//! asks of it. `media.rs` is the fetched file: its bytes read whole under the
//! adapter's cap, its type sniffed, its base64. `tools.rs` holds the catalog
//! (`tools.json`, embedded) with its commons sentence, the dispatch's two kinds
//! the catalog is checked against when loaded, the dispatch's door
//! (`Tool::admit`, which admits a call or refuses it -32602), and a wire op's
//! call mapped onto its frame (*every tool is one call of the shell*).
//! `log.rs` is the adapter's log on stderr, which every module that says a
//! line and the shell's `Talk` write through: each line stamped with the
//! moment it was said and cut of any answer skep-client quotes, and, while
//! its writer runs, never waiting on its reader, with the panic hook that
//! makes a panic one line of it. This file is startup — the settings, each
//! spelled once and refused by name before any dial, the store's write probe
//! and the hold that keeps it one adapter process's, the `settings:` line
//! naming each setting in force and its source, the shell's open — and the
//! loop's two inputs (stdin's reader, the backend's stop) wired onto one
//! channel.
//!
//! stdout is protocol-only while the adapter serves; all logging goes to
//! stderr, through `log`, which fails nothing and, while its writer runs,
//! waits on nothing. Stdin EOF is the clean exit, and so are a failed read of
//! stdin and a closed stdout: the shell's stop closes the session at the
//! board and saves the index.

#![forbid(unsafe_code)]

mod log;
mod media;
mod server;
mod shell;
mod tools;

use std::borrow::Cow;
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::search::SearchDir;
use skep_client::store::default_store_dir;
use skep_client::Origin;

use crate::log::{install_the_panic_hook, log};
use crate::media::FETCH_DEADLINE;
use crate::server::{read_stdin, Inbound, Server};
use crate::shell::{Backend, OnStop};
use crate::tools::Catalog;

const USAGE: &str = "\
usage: skep-mcp [--board <ORIGIN>] [--dir <PATH>] [--principal <N>] [--tools-file <PATH>]

  --board <ORIGIN>     the board, by a canonical http:// origin it signs
                       sessions for — one its --origin names, as written,
                       the origin the agent's key is bound at (env
                       SKEP_BOARD; required): this adapter signs for the
                       origin it dials, so a tunnel serves only where its
                       local end is such an origin; an https:// one is
                       refused, this adapter dialing plain http:// alone,
                       and one off this machine's loopback carries the
                       session's token in the clear
  --dir <PATH>         the key store this adapter signs from (env
                       SKEP_KEYSTORE; required, a directory that stands
                       and this process can write: ~/.skep is never
                       consulted), and where its search index and held
                       bursts sit — ONE directory per adapter process,
                       never a running dev provider's: a second start
                       over it waits up to 30 s for the first to end, and
                       is refused after that. Read at start, and the
                       store's key again at each session the shell opens
  --principal <N>      the principal this adapter acts as (env
                       SKEP_PRINCIPAL; required: an integer, 0 to
                       9007199254740991, the largest a board registers)
  --tools-file <PATH>  override the embedded tool catalog (tools.json:
                       names, descriptions, schemas, server instructions)
  --help               this text
  --version            this binary's version and the commit it was built from

environment (a flag beats its variable; a variable set empty is unset, as
the skep command reads it):
  SKEP_BOARD      the board (--board)
  SKEP_KEYSTORE   the key store (--dir)
  SKEP_PRINCIPAL  the principal (--principal)
  SKEP_COMMONS    optional: the commons, 1.1.0.1.0.1, alone — the document
                  whose subspace 3 names link types; when set, the server
                  instructions point agents at it
  SKEPD_URL       no longer read: the board is named by --board or
                  SKEP_BOARD, as the skep command names it

exit status:
    0  stdin's end, or a read of it that failed, or a closed stdout: the
       session closed at the board; --help and --version
    1  a refusal before serving (the catalog, a setting, the board, the
       key, the session's open), or a stop while serving (the key retired,
       the prefix blocked, the account seeded, an open the board refused)
    2  a usage error
  101  a panic: a bug, said in one line of the log

stop:
  stdin's end closes the session at the board and saves the index,
  seconds where the board answers. A signal ends the process at once,
  its held bursts already on disk, save one the shell kept in memory
  alone (answered unwritable), its session left at the board until
  the board restarts. The person stops an agent for good by
  retiring its key (skep retire)

log:
  stderr, every line opening 'skep-mcp: ' and the moment it was said,
  RFC 3339 UTC to the millisecond, the first naming the version and the
  process id. A reader that stops reading never holds the adapter up: the
  lines it leaves are dropped, and the next line it takes says how many
  went, at the moment the first of them was said

Speaks MCP (JSON-RPC 2.0, one message per line) on stdio, and serves every
tool through the shell's core (skep-shell) under one signed session it
opens at startup for the principal, with the store's key for it.";

/// A setting's spelling: its flag, and the variable that stands in for it.
///
/// Each setting is spelled once, here: the parse reads it, the refusals and
/// the `settings:` line name it, and the suite holds the usage and the
/// README's settings table to it.
type Spelling = (&'static str, Option<&'static str>);

/// The board's spelling: `--board`, or `SKEP_BOARD`, the `skep` command's too.
const BOARD: Spelling = ("--board", Some("SKEP_BOARD"));

/// The key store's spelling: `--dir`, or `SKEP_KEYSTORE`.
///
/// It is the `skep` command's spelling, which defaults it to `~/.skep`, a
/// default this adapter never takes.
const DIR: Spelling = ("--dir", Some("SKEP_KEYSTORE"));

/// The principal's spelling: `--principal`, or `SKEP_PRINCIPAL`.
///
/// It is the `skep` command's spelling too, under the same bound
/// (`MAX_PRINCIPAL`).
const PRINCIPAL: Spelling = ("--principal", Some("SKEP_PRINCIPAL"));

/// The tools file's spelling: `--tools-file`, which no variable stands in for.
const TOOLS_FILE: Spelling = ("--tools-file", None);

/// The variable that points the server instructions at the commons.
///
/// No flag stands in for it.
const COMMONS_VARIABLE: &str = "SKEP_COMMONS";

/// The board's retired variable, which `SKEP_BOARD` replaces, not read.
///
/// Where it is set, that is said; its value is never decoded.
const RETIRED_BOARD_VARIABLE: &str = "SKEPD_URL";

/// Every setting a flag supplies, as the suite reads them.
///
/// The suite holds the usage and the README's settings table to their
/// spellings.
#[cfg(test)]
const SETTINGS: [Spelling; 4] = [BOARD, DIR, PRINCIPAL, TOOLS_FILE];

/// The commons: the system account's first document, `1.1.0.1.0.1`.
///
/// Its subspace 3 holds every link type's address on every board
/// (`1.1.0.1.0.1 · 0 · 3 · n`, commons-map), and the format fixes it:
/// skep-namespace's `ghost_home_document`, skep-registry's
/// `COMMONS_TYPE_PREFIX` and every type address skep-client signs and reads
/// (`T_ENROLL`, `T_GRANT`, …), and the suite holds those addresses to it.
/// `SKEP_COMMONS` takes this value alone.
const COMMONS_DOCUMENT: &str = "1.1.0.1.0.1";

/// The largest principal id a board registers: `2^53 − 1`.
///
/// It is the top of the range a JSON number carries exactly — skepd's
/// `delegate` refuses a larger `new_id` at the parse (wire.md §Value
/// encodings), so every principal a board seats sits at or below it. An
/// adapter bound past it could never open a session, so startup is the
/// bound's one check here — as skep-cli's `parse_principal` is for the same
/// variable, at the same bound.
const MAX_PRINCIPAL: u64 = (1 << 53) - 1;

/// The file under the store whose lock keeps it one adapter process's.
///
/// It is this adapter's own: the store's `lock` is the key store's, taken for
/// a binding's append alone (`client.md` §3.7), and the shell's are per board,
/// under its search index and its held bursts. The holder writes its pid in
/// it, for the next start to name.
const STORE_LOCK: &str = "skep-mcp.lock";

/// The longest a start waits for another adapter's hold on its store to end.
///
/// **Interim.** It is a restart's predecessor's clean stop at a board that
/// answers — the session's close and the index's save, a few seconds — with
/// room, and well inside the time a harness gives `initialize`. A predecessor
/// still stopping past it, or a second adapter left running over the store,
/// refuses the start.
const STORE_WAIT: Duration = Duration::from_secs(30);

/// The directory under the store the shell keeps its held bursts in.
///
/// It is `client.md` §3c.1's `held/`, which skep-shell's private held store
/// spells, spelled here for the start's write probe alone.
const HELD_DIR: &str = "held";

/// Returns this binary's build: `<crate version> (<commit>)`.
///
/// The version is the one Cargo compiled in, and the commit the one the build
/// named through `SKEP_GIT_SHA`, `unknown` where it named none, as a
/// developer's own build names none. Both are read at compile time, so the run
/// consults no file and no variable; the release scripts set the variable and
/// hold the four shipped binaries to one version and one commit. The log's
/// first line once the command line is read names it beside the process
/// (`version <build>, pid <id>`), a panic's line names it again, and the
/// version line answers it.
fn build() -> String {
    format!("{} ({})", env!("CARGO_PKG_VERSION"), option_env!("SKEP_GIT_SHA").unwrap_or("unknown"))
}

/// Returns the version line `--version` answers: `skep-mcp <build>`.
fn version_line() -> String {
    format!("skep-mcp {}", build())
}

/// A setting a flag supplies, or the variable that stands in for it.
///
/// It holds its spelling and the value the flag was given, at most once.
#[derive(Debug)]
struct Setting {
    flag: &'static str,
    var: Option<&'static str>,
    given: Option<OsString>,
}

impl Setting {
    /// Returns the setting spelled `(flag, var)`, its flag not yet given.
    fn new((flag, var): Spelling) -> Setting {
        Setting { flag, var, given: None }
    }

    /// Takes the flag's value off `args`.
    ///
    /// A flag with no value after it, or given before, is a usage error.
    fn take(&mut self, args: &mut impl Iterator<Item = OsString>) {
        match args.next() {
            Some(_) if self.given.is_some() => die_usage(format_args!("{} is given at most once", self.flag)),
            Some(value) => self.given = Some(value),
            None => die_usage(format_args!("{} needs a value", self.flag)),
        }
    }

    /// Returns the setting's text: the flag's value, else its variable's.
    ///
    /// A value that is not UTF-8 is refused by name; a variable set empty is
    /// unset (`env_set`).
    fn text(&self) -> Option<String> {
        match &self.given {
            Some(value) => match value.to_str() {
                Some(text) => Some(text.to_string()),
                None => die(format_args!("{}: the value is not UTF-8 text", self.flag)),
            },
            None => self.var.and_then(env_text),
        }
    }

    /// Returns the setting's source: its flag where given, else its variable.
    fn source(&self) -> &'static str {
        match self.var {
            Some(var) if self.given.is_none() => var,
            _ => self.flag,
        }
    }

    /// Returns the line owed where the flag beats a variable set beside it.
    ///
    /// It is owed where the variable is set to another value than the flag's:
    /// the variable is not read, and a value a shell exported there — the
    /// person's own `SKEP_KEYSTORE` or `SKEP_PRINCIPAL`, which the `skep`
    /// command reads — would otherwise stand behind the flag unsaid.
    fn shadowed(&self) -> Option<String> {
        let (given, var) = (self.given.as_ref()?, self.var?);
        let set = env_set(var).filter(|set| set != given)?;
        let beside = set.to_str().map_or_else(|| "to a value that is not UTF-8 text".to_string(), |text| format!("to '{text}'"));
        Some(format!("{} '{}' beats {var}, set beside it {beside}: the variable is not read", self.flag, given.to_string_lossy()))
    }

    /// Returns the setting as a refusal names it: `--board (or SKEP_BOARD)`.
    fn named(&self) -> String {
        match self.var {
            Some(var) => format!("{} (or {var})", self.flag),
            None => self.flag.to_string(),
        }
    }
}

fn main() -> ExitCode {
    install_the_panic_hook();
    let code = serve();
    log::drain();
    code
}

/// Starts the adapter and serves it to its end: the code to exit with.
///
/// # Panics
///
/// Where a tools file is given and the embedded catalog, which `tools::tests`
/// holds to the dispatch, does not load.
fn serve() -> ExitCode {
    let mut board = Setting::new(BOARD);
    let mut dir = Setting::new(DIR);
    let mut principal = Setting::new(PRINCIPAL);
    let mut tools_file = Setting::new(TOOLS_FILE);
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        // A flag is looked up by the spelling its own setting holds, so no
        // flag fills another's setting.
        if let Some(setting) = [&mut board, &mut dir, &mut principal, &mut tools_file].into_iter().find(|setting| arg.to_str() == Some(setting.flag)) {
            setting.take(&mut args);
            continue;
        }
        match arg.to_str() {
            Some("--help" | "-h") => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            // Answered where it is met, as the help is: before the catalog,
            // the environment or stdin is consulted, so a release's check
            // runs under any environment; what follows is unread.
            Some("--version") => {
                println!("{}", version_line());
                return ExitCode::SUCCESS;
            }
            _ => die_usage(format_args!("unknown argument '{}'", arg.to_string_lossy())),
        }
    }
    // The build and the process first, so every line after it is read as
    // this binary's, and joins what the host says of the process — an OOM
    // kill, a crash report, the harness's own record of its child — by the
    // id.
    log(format_args!("version {}, pid {}", build(), std::process::id()));
    // The catalog next: a drifted tools file is a startup error before any
    // environment or network is consulted. Its source is named, by its
    // absolute path, where it is refused, where the settings line names it and
    // where the serving line counts its tools.
    let tools_path = tools_file.given.as_deref().map(|path| resolved(&tools_file, Path::new(path)));
    let source = match &tools_path {
        None => "the embedded catalog".to_string(),
        Some(path) => format!("the tools file {}", path.display()),
    };
    let text = match &tools_path {
        None => Cow::Borrowed(tools::EMBEDDED),
        Some(path) => match fs::read_to_string(path) {
            Ok(t) => Cow::Owned(t),
            Err(e) => die(format_args!("{} {}: {e}", tools_file.flag, path.display())),
        },
    };
    let mut catalog = match Catalog::load(&text) {
        Ok(c) => c,
        // A tools file is held to this binary's dispatch at every start, so
        // the likeliest drift is one written for another release.
        Err(e) if tools_path.is_some() => die(format_args!(
            "{source}: {e} — a tools file replaces the embedded catalog whole and is held to this binary's dispatch at every start: write it afresh from this release's tools.json (crates/skep-mcp/tools.json at its tag), or drop --tools-file"
        )),
        Err(e) => die(format_args!("{source}: {e}")),
    };
    // A tools file is served whole in the embedded catalog's place, so where
    // its text differs from this release's — one written for another release
    // whose tools match, or one edited — every agent is told that text, and
    // the start says so.
    if tools_path.is_some() {
        let embedded = Catalog::load(tools::EMBEDDED).expect("the embedded catalog loads: `tools::tests` holds it to the dispatch");
        if let Some(drift) = catalog.drift_from(&embedded) {
            log(format_args!(
                "{source} differs from the catalog this release embeds ({drift}): every agent is told that file's text, not this release's — rewrite it from this release's tools.json where it was written for another"
            ));
        }
    }
    // Then the settings, each refused by name and the first refusal ending
    // startup: the principal, the board, the store, the commons.
    let principal_id = match principal.text() {
        Some(v) => match v.parse::<u64>().ok().filter(|p| *p <= MAX_PRINCIPAL) {
            Some(p) => p,
            None => die(format_args!("{}: '{v}' is not a principal (a non-negative integer no greater than {MAX_PRINCIPAL})", principal.named())),
        },
        None => die(format_args!("{} is required: the principal this adapter acts as", principal.named())),
    };
    let origin = match board.text() {
        Some(text) => match Origin::parse(&text) {
            Some(origin) => origin,
            None => die(format_args!("{}: '{text}' is not a canonical origin (http://host[:port], lowercase, no path, no trailing slash)", board.named())),
        },
        None => {
            let retired = if env_set(RETIRED_BOARD_VARIABLE).is_some() {
                format!(" — {RETIRED_BOARD_VARIABLE} is set and no longer read: the board is named by {} alone", board.named())
            } else {
                String::new()
            };
            die(format_args!("{} is required: the board this adapter serves{retired}", board.named()))
        }
    };
    // This adapter dials plain http:// alone — the release builds its
    // skep-client without `tls` — and signs for the origin it dials, so an
    // https:// board is refused here, where the setting is read, in the words
    // of whoever set it, and never meets a dialer that holds no transport for
    // it. What serves instead is an http:// origin the board signs sessions
    // for: its loopback origin on its own machine, or that origin a tunnel
    // carries here, never a hosted board's.
    if origin.is_https() {
        die(format_args!(
            "{}: '{origin}' is an https:// origin, and this adapter dials plain http:// alone: give it an http:// origin the board signs sessions for — its loopback origin on its own machine, or that origin carried here by a tunnel; a hosted board signs its https:// origin alone, out of this adapter's reach",
            board.named()
        ));
    }
    // AUTH-4.53: an http:// origin off this machine's loopback carries the
    // session's token in the clear on every exchange unless a tunnel carries
    // it — said where the setting is read, as the `skep` command says it ahead
    // of every signed session: a warning, never a refusal (client.md §9 item
    // 23).
    if let Some(warning) = plaintext_non_loopback_warning(&origin) {
        log(warning);
    }
    let given = match dir.text() {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => die(format_args!("{} is required: the key store this adapter signs from, one directory per adapter process (~/.skep is never consulted)", dir.named())),
    };
    let store_dir = resolved(&dir, &given);
    // The store stands before the shell opens over it: the shell's feed thread
    // makes the search index under it at its open, so a path that names
    // nothing is refused here, before anything is made at it.
    match fs::metadata(&store_dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => die(format_args!("{}: '{}' is no directory: the key store this adapter signs from is the directory the agent's key was made in", dir.named(), store_dir.display())),
        Err(e) => die(format_args!(
            "{}: '{}' cannot be read ({e}): the key store this adapter signs from — the directory the agent's key was made in — must stand before it starts",
            dir.named(),
            store_dir.display()
        )),
    }
    // The shell writes its search index and its held bursts under the store,
    // and a burst held where it cannot be written is kept in memory alone, lost
    // at the process's end: so the store, and each of the two that stands, is
    // one this process can write, or the start is refused.
    for at in store_writes(&store_dir) {
        if let Err(e) = writable(&at) {
            die(format_args!(
                "{}: '{}' cannot be written ({e}): the shell keeps this adapter's search index and held bursts under the key store, and a burst held where it cannot be written is lost at the process's end",
                dir.named(),
                at.display()
            ));
        }
    }
    // The commons pointer: the address the instructions hand to agents,
    // never dereferenced here. The format fixes it (`COMMONS_DOCUMENT`), so a
    // value that is no T4 address is refused as malformed, and any other as
    // not the commons.
    let commons = env_text(COMMONS_VARIABLE).inspect(|a| {
        if !is_t4_address(a) {
            die(format_args!("{COMMONS_VARIABLE}: '{a}' is not a T4-valid address"));
        }
        if a != COMMONS_DOCUMENT {
            die(format_args!(
                "{COMMONS_VARIABLE}: '{a}' is not the commons: every board's link types are addresses in subspace 3 of {COMMONS_DOCUMENT}, its system account's first document — set it to that, or leave it unset"
            ));
        }
    });
    if let Some(addr) = &commons {
        catalog.append_commons(addr);
    }
    // What the start reads, said before it dials: each flag that beats a
    // variable set beside it, the retired variable set beside a named board,
    // and a store that is the person's own; then every setting in force and
    // where it came from, on one line.
    for line in [&board, &dir, &principal].into_iter().filter_map(Setting::shadowed) {
        log(line);
    }
    if env_set(RETIRED_BOARD_VARIABLE).is_some() {
        log(format_args!("{RETIRED_BOARD_VARIABLE} is set and no longer read: the board is {origin} ({})", board.source()));
    }
    if is_the_persons_store(&store_dir) {
        log(format_args!(
            "warning: {} '{}' is the person's own store, ~/.skep: the agent signs with the person's key, and retiring that key to stop the agent retires it for the person — give the agent a store of its own",
            dir.named(),
            store_dir.display()
        ));
    }
    let given_as = if given.is_relative() {
        let cwd = env::current_dir().map_or_else(|e| format!("that could not be read ({e})"), |cwd| cwd.display().to_string());
        format!(", given as {} against the working directory {cwd}", given.display())
    } else {
        String::new()
    };
    let catalog_said = if tools_path.is_some() { format!("{source} ({})", tools_file.flag) } else { source.clone() };
    let commons_said = match &commons {
        None => format!("no commons ({COMMONS_VARIABLE} unset)"),
        Some(addr) => format!("the commons {addr} ({COMMONS_VARIABLE})"),
    };
    log(format_args!(
        "settings: board {origin} ({}), store {} ({}{given_as}), principal {principal_id} ({}), {catalog_said}, {commons_said} — each read once, at this start, save the store's key, which the shell selects anew at each session it opens",
        board.source(),
        store_dir.display(),
        dir.source(),
        principal.source()
    ));
    // The store is this process's for its life: a second adapter over it — a
    // restart's predecessor still stopping among them — is waited for, and
    // refused past `STORE_WAIT`.
    let _store_hold = hold_the_store(&store_dir, &dir.named(), STORE_WAIT).unwrap_or_else(|line| die(format_args!("{line}")));
    // The loop's two inputs, on one channel: stdin's lines and its end, which
    // `read_stdin` sends from a thread of its own, and the backend's stop,
    // which `OnStop` sends on this unbounded channel and never waits on, each
    // line and the stop stamped with the moment it was sent, the loop's start
    // for its wait.
    let (inbound, inbox) = mpsc::channel::<Inbound>();
    let on_stop = OnStop::new(inbound.clone(), |line| Inbound::Stop(line, Instant::now()));
    // The shell: opened, checked and its one session opened before any tool
    // is served; a stop here returns, so the shell's own stop has run.
    let talk: skep_shell::Talk = Arc::new(|line: &str| log(line));
    let backend = match Backend::open(origin, store_dir, principal_id, talk, on_stop) {
        Ok(backend) => backend,
        Err(line) => {
            log(line);
            return ExitCode::from(1);
        }
    };
    log(format_args!(
        "serving {} tools of {source} on stdio, one call at a time{}; stdin's end closes the session at the board and saves the index — a signal ends the process with neither, and the session then lives on at the board until it restarts",
        catalog.tools().len(),
        commons.as_deref().map(|a| format!(", commons {a}")).unwrap_or_default()
    ));
    read_stdin(inbound);
    Server { backend, catalog }.run(&inbox)
}

/// Returns `path` resolved against the working directory, as an absolute path.
///
/// Symlinks are left as they stand, so every line after names the path as
/// given, made absolute. A path that cannot be resolved — an empty one, or a
/// working directory that cannot be read — is refused naming `setting`.
fn resolved(setting: &Setting, path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|e| die(format_args!("{}: '{}' cannot be resolved to an absolute path ({e})", setting.named(), path.display())))
}

/// Returns the directories the start's write probe reads.
///
/// They are the store, where the shell makes its search index and its held
/// bursts, and each of those two directories that stands: the index's root
/// (`SearchDir`) and `HELD_DIR`.
fn store_writes(store_dir: &Path) -> Vec<PathBuf> {
    let under = [SearchDir::new(store_dir).root().to_path_buf(), store_dir.join(HELD_DIR)];
    std::iter::once(store_dir.to_path_buf()).chain(under.into_iter().filter(|dir| dir.is_dir())).collect()
}

/// Returns whether this process can make and remove a file in `dir`.
///
/// # Errors
///
/// The I/O error making or removing the probe, `.skep-mcp-probe-<pid>`.
fn writable(dir: &Path) -> io::Result<()> {
    let probe = dir.join(format!(".skep-mcp-probe-{}", std::process::id()));
    File::create(&probe)?;
    fs::remove_file(&probe)
}

/// Returns whether `store_dir` is the person's own store, `~/.skep`.
///
/// Both are read as the filesystem resolves them, so a symlink or another
/// spelling of the person's store is found too; a person's store that does not
/// stand is none.
fn is_the_persons_store(store_dir: &Path) -> bool {
    let Some(persons) = default_store_dir() else { return false };
    matches!((fs::canonicalize(persons), fs::canonicalize(store_dir)), (Ok(persons), Ok(store)) if persons == store)
}

/// Takes the store for this process: the lock on `STORE_LOCK` under it.
///
/// The lock is held for the file's life, which `serve` ends as it returns,
/// or until the process ends, however that ends. Where another adapter holds
/// it — a restart's predecessor still stopping, or a second adapter over one
/// store — the wait is said once, naming that process by the pid it wrote,
/// and the lock is tried each tenth of a second until `wait` runs out. The
/// refusal past it names both: how long a predecessor's call in flight or its
/// clean stop can hold the store, and the store a second adapter takes in
/// this one's place, a store and a key of its own and never a copy of this
/// one, whose key is the agent's. Once taken, this process's pid is written
/// in the file for the next start to name.
///
/// # Errors
///
/// The refusal's line, naming the setting as `named`: the lock file could not
/// be opened, locked or written, or another adapter still held it when `wait`
/// ran out.
fn hold_the_store(store_dir: &Path, named: &str, wait: Duration) -> Result<File, String> {
    let path = store_dir.join(STORE_LOCK);
    let faulted = |e: io::Error| format!("{named}: '{}' cannot be held ({e}): the start locks it so one adapter process serves over the store", path.display());
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path).map_err(faulted)?;
    let deadline = Instant::now() + wait;
    let mut said = false;
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(TryLockError::Error(e)) => return Err(faulted(e)),
            Err(TryLockError::WouldBlock) => {
                let holder = holder_of(&mut file);
                if Instant::now() >= deadline {
                    return Err(format!(
                        "{named}: '{}' is held by another skep-mcp process ({holder}): a predecessor still finishing a call or its clean stop — a fetch runs up to {:.1} minutes, a clean stop up to about a minute and a half where the board accepts the connection and does not answer — or a second adapter over this store: wait for it or end it (a signal ends it at once), or give this one a store and a key of its own (`skep keygen`, `skep enroll`, `skep bind`), never a copy of this one",
                        store_dir.display(),
                        FETCH_DEADLINE.as_secs_f64() / 60.0
                    ));
                }
                if !said {
                    log(format_args!("the store '{}' is held by another skep-mcp process ({holder}): waiting up to {} s for it to end", store_dir.display(), wait.as_secs()));
                    said = true;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    file.set_len(0).and_then(|()| file.seek(SeekFrom::Start(0))).and_then(|_| writeln!(file, "{}", std::process::id())).map_err(faulted)?;
    Ok(file)
}

/// Returns the lock file's holder as a line names it: by the pid it wrote.
///
/// A holder that has not written its pid yet — it writes it once the lock is
/// its own — is named so.
fn holder_of(file: &mut File) -> String {
    let mut text = String::new();
    let read = file.seek(SeekFrom::Start(0)).and_then(|_| file.read_to_string(&mut text));
    match read.ok().and_then(|_| text.trim().parse::<u32>().ok()) {
        Some(pid) => format!("pid {pid}"),
        None => "its pid not yet written".to_string(),
    }
}

/// Says a refusal before the shell is open, and exits 1.
///
/// `msg` is the refusal's line as `format_args!` makes it, so no caller
/// builds a `String` to lend; the log is drained before the exit, so the line
/// reaches stderr. It is never called past `Backend::open`, whose stop
/// returns from `serve` so the shell drops.
fn die(msg: fmt::Arguments<'_>) -> ! {
    log(msg);
    log::drain();
    std::process::exit(1);
}

/// Says a usage error and the usage after it, and exits 2.
///
/// The log is drained before the exit, as `die` drains it.
fn die_usage(msg: fmt::Arguments<'_>) -> ! {
    log(format_args!("{msg}\n\n{USAGE}"));
    log::drain();
    std::process::exit(2);
}

/// Returns a variable's value, `None` while it is unset or set empty.
///
/// A variable set empty is unset, as the `skep` command reads the same
/// variables (skep-cli's `args.rs`, the way a shell unsets one for a single
/// run): a harness template that writes every key, an empty one meaning
/// none, runs as if that key were absent.
fn env_set(var: &str) -> Option<OsString> {
    env::var_os(var).filter(|value| !value.is_empty())
}

/// Returns a variable's text, `None` while it is unset or set empty.
///
/// A value that is not UTF-8 text is refused by name, in skepd's words, never
/// read as unset: it was given, and running on a default in its place is the
/// silent failure the refusal exists to prevent.
fn env_text(var: &str) -> Option<String> {
    match env_set(var)?.into_string() {
        Ok(text) => Some(text),
        Err(_) => die(format_args!("{var}: the value is not UTF-8 text")),
    }
}

/// Returns whether a dotted-decimal tumbler string is T4 well-formed.
///
/// T4 well-formedness (wire.md §Value encodings; the four clauses of
/// skep-address's validator): every component is a decimal natural, the
/// first and last are nonzero, no two zeros are adjacent, and at most three
/// components are zero. Zeroness is judged on the digits (`"00"` is zero,
/// matching the daemon's lenient numeric read); magnitudes stay strings — T4
/// never bounds size. A test holds it to the validator's verdict on every
/// short dotted decimal.
fn is_t4_address(s: &str) -> bool {
    let is_zero = |c: &str| c.bytes().all(|b| b == b'0');
    let mut zeros = 0usize;
    let mut prev_zero = false;
    let mut components = 0usize;
    for comp in s.split('.') {
        if comp.is_empty() || !comp.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        let z = is_zero(comp);
        if z {
            if prev_zero || components == 0 {
                return false;
            }
            zeros += 1;
        }
        prev_zero = z;
        components += 1;
    }
    components > 0 && !prev_zero && zeros <= 3
}

#[cfg(test)]
mod tests;
