//! skep-mcp — the adapter between an agent harness (MCP: JSON-RPC 2.0 over
//! stdio, newline-delimited UTF-8, one message per line) and a board,
//! served through the shell's core, `skep-shell` — the engine the dev
//! provider and the desktop shell run on. One process per agent, one
//! board, ONE SIGNED SESSION for the adapter's life:
//!
//! * **Every tool is one call of the shell** under that session. A WIRE OP's
//!   tool name IS the frame's `op` and its arguments ARE the frame (the one
//!   mapping is `from_` → `from` on make_link/emit, when the arguments carry no
//!   `from` of their own), sent as `op(session, frame)`: attested where the
//!   session's key attests the kind, held where the board cannot take a burst
//!   or rejects one (the `held` answer comes back as data; a refused run's
//!   line, and the bursts behind it on its document, wait on the agent's
//!   `resolve`), a `write_busy` reissued once and a `durability` twice within
//!   the call, as the shell does. The shell's own calls — `boards`, `health`,
//!   `probe`, `search`, `places`, `held`, `resolve` — are tools of those names,
//!   their arguments the bridge's row minus the session and the board, the
//!   adapter supplying each where the row requires it; and three are the
//!   adapter's apparatus: `session_info`, `changes_since` (the shell's
//!   `changes`, a pull), and `fetch` (the shell's streamed fetch as an image or
//!   resource block, the type sniffed off the bytes, the size capped).
//!   Arguments pass through unvalidated on a wire op — the daemon's strict
//!   parse is the validator, and its rejection comes back as data — save the
//!   one shape the shell's `op` row reads as its `/op-at` form, a numeric `at`
//!   beside an object `frame`, which no wire op takes.
//! * **A refusal as a result.** The board's verdict is data: a `refused`
//!   refusal is a normal tool result, the verdict's body verbatim under `body`
//!   with the refusal's `name`, `status`, `code`, `detail` and `op` beside it,
//!   since a client that cannot decode a rejection has been silently failed
//!   (wire.md §Rejections). `isError` is every other refusal — the shell could
//!   not get the board's verdict: the board unreachable, a halt, the block, the
//!   shell's own names — and `fetch`'s two answers of the adapter's own, a file
//!   past its cap and a stream cut short, each a plain sentence. A write
//!   refused `unreachable` may have committed: the shell faces a lost answer to
//!   any write but a burst (whose line it holds, `sent`), and the adapter never
//!   reissues it. So may a write the board refused `poisoned`, whose frames its
//!   restart replays from the journal (wire.md §Rejection codes; client.md
//!   §3c.2), or answered `500 internal_panic` past its commit — each the
//!   board's verdict, and so data. A call the adapter will not run — a tool
//!   outside the catalog, a member an adapter tool's row or its `opts` does not
//!   name, a wire op's arguments of the shell's `/op-at` shape — is no tool
//!   result at all: it is refused -32602, as malformed `tools/call` params are;
//!   a member of the wrong form is the shell's `malformed_args`.
//! * **A signed session, opened at startup**, before the first tool call, for
//!   the configured principal with the store's key for it — enrolled in its
//!   account's set or the nearest set above it — and no bare mode exists. No
//!   key, or a key the board refuses, stops the adapter before it serves. A
//!   board restart is met by the shell's silent re-open; a death the shell does
//!   not re-open — the key retired, the prefix blocked, the account seeded, a
//!   re-open the board refused — stops the process with one plain line naming
//!   the arm, and so does the board's refusal of a session the adapter opens
//!   itself where the shell's end left none. No person is at the seam
//!   (`ArmConfig::Refuse`): no ceremony tool is offered, and every SECRET or
//!   CONSENT moment would be refused `person_required`.
//!
//! `server.rs` is the MCP side: the stdio transport — stdin's reader, and the
//! loop that answers each line on stdout — the JSON-RPC dispatch, and `call`,
//! which keeps *a refusal as a result*. `shell.rs` is the backend, the one
//! module that calls `skep-shell`: the open and its checks, every call under
//! the one session and the life around it, the bus drained; its child
//! `shell/watch.rs` is the session's state, which one door moves
//! (`SessionWatch::move_off`), and what a death asks of it. `media.rs` is the
//! fetched file: its bytes read whole under the adapter's cap, its type
//! sniffed, its base64. `tools.rs` holds the catalog (`tools.json`, embedded)
//! with its commons sentence, the dispatch's two kinds the catalog is checked
//! against when loaded, the dispatch's door (`Tool::admit`, which admits a call
//! or refuses it -32602), and a wire op's call mapped onto its frame (*every
//! tool is one call of the shell*). This file is startup — flags, environment,
//! the `SKEP_COMMONS` check, the shell's open — the loop's two inputs (stdin's
//! reader, the backend's stop) wired onto one channel, and `log`, the
//! operator's stream every module and the shell's TALK write through.
//!
//! stdout is protocol-only; all logging goes to stderr, through `log`,
//! whose failure fails nothing. Stdin EOF is the clean exit: the shell's
//! stop closes the session at the board and saves the index.

#![forbid(unsafe_code)]

mod media;
mod server;
mod shell;
mod tools;

use std::borrow::Cow;
use std::env::{self, VarError};
use std::ffi::OsString;
use std::fmt::{self, Display};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::Arc;

use skep_client::sheet::render_inert;
use skep_client::Origin;

use crate::server::{read_stdin, Inbound, Server};
use crate::shell::{Backend, OnStop};
use crate::tools::Catalog;

const USAGE: &str = "\
usage: skep-mcp [--board <ORIGIN>] [--dir <PATH>] [--principal <N>] [--tools-file <PATH>]

  --board <ORIGIN>     the board, a canonical origin such as
                       http://127.0.0.1:8642 (env SKEP_BOARD; required)
  --dir <PATH>         the key store this adapter signs from (env
                       SKEP_KEYSTORE; required: ~/.skep is never consulted),
                       and where its search index and held bursts sit —
                       ONE directory per adapter process, never a running
                       dev provider's
  --principal <N>      the principal this adapter acts as (env
                       SKEP_PRINCIPAL; required: an integer, 0 to
                       9007199254740991, the largest a board registers)
  --tools-file <PATH>  override the embedded tool catalog (tools.json:
                       names, descriptions, schemas, server instructions)
  --help               this text
  --version            this binary's version and the commit it was built from

environment:
  SKEP_BOARD      the board (--board); a flag beats its variable
  SKEP_KEYSTORE   the key store (--dir)
  SKEP_PRINCIPAL  the principal (--principal)
  SKEP_COMMONS    optional address of the commons, the document whose
                  subspace 3 names link types; when set, the server
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

Speaks MCP (JSON-RPC 2.0, one message per line) on stdio, and serves every
tool through the shell's core (skep-shell) under one signed session it
opens at startup for the principal, with the store's key for it.";

/// The largest principal id a board registers: `2^53 − 1`, the top of the
/// range a JSON number carries exactly — skepd's `delegate` refuses a
/// larger `new_id` at the parse (wire.md §Value encodings), so every
/// principal a board seats sits at or below it. An adapter bound past it
/// could never open a session, so startup is the bound's one check here —
/// as skep-cli's `parse_principal` is for the same variable, at the same
/// bound.
const MAX_PRINCIPAL: u64 = (1 << 53) - 1;

/// THE VERSION LINE (`--version`): `skep-mcp <crate version> (<commit>)`
/// — the version Cargo compiled in, and the commit the build named through
/// `SKEP_GIT_SHA`, `unknown` where it named none, which a developer's own
/// build never does. Both are read at compile time, so the run consults no
/// file and no variable; the release scripts set the variable and hold the
/// four shipped binaries to one version and one commit.
fn version_line() -> String {
    format!("skep-mcp {} ({})", env!("CARGO_PKG_VERSION"), option_env!("SKEP_GIT_SHA").unwrap_or("unknown"))
}

/// A setting a flag supplies, or the variable that stands in for it.
///
/// It holds its flag, its variable — none for `--tools-file` — and the
/// value the flag was given, at most once.
#[derive(Debug)]
struct Setting {
    flag: &'static str,
    var: Option<&'static str>,
    given: Option<OsString>,
}

impl Setting {
    /// Returns the setting of `flag`, read from `var` where it is not given.
    fn new(flag: &'static str, var: Option<&'static str>) -> Setting {
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
    /// A value that is not UTF-8 is refused by name.
    fn text(&self) -> Option<String> {
        match &self.given {
            Some(value) => match value.to_str() {
                Some(text) => Some(text.to_string()),
                None => die(format_args!("{}: the value is not UTF-8 text", self.flag)),
            },
            None => self.var.and_then(env_text),
        }
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
    let mut board = Setting::new("--board", Some("SKEP_BOARD"));
    let mut dir = Setting::new("--dir", Some("SKEP_KEYSTORE"));
    let mut principal = Setting::new("--principal", Some("SKEP_PRINCIPAL"));
    let mut tools_file = Setting::new("--tools-file", None);
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
    // The catalog first: a drifted tools file is a startup error before any
    // environment or network is consulted.
    let text = match &tools_file.given {
        None => Cow::Borrowed(tools::EMBEDDED),
        Some(path) => match std::fs::read_to_string(path) {
            Ok(t) => Cow::Owned(t),
            Err(e) => die(format_args!("{} {}: {e}", tools_file.flag, Path::new(path).display())),
        },
    };
    let mut catalog = match Catalog::load(&text) {
        Ok(c) => c,
        Err(e) => die(format_args!("tools file: {e}")),
    };
    // Then the settings, each refused by name and the first refusal ending
    // startup: the principal, the board, the store, the commons.
    let principal = match principal.text() {
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
            // `SKEPD_URL` is read no longer: whether it is set is said, its
            // value never decoded.
            let retired = if env::var_os("SKEPD_URL").is_some() { format!(" — SKEPD_URL is set and no longer read: the board is named by {} alone", board.named()) } else { String::new() };
            die(format_args!("{} is required: the board this adapter serves{retired}", board.named()))
        }
    };
    let store_dir = match dir.text() {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => die(format_args!("{} is required: the key store this adapter signs from, one directory per adapter process (~/.skep is never consulted)", dir.named())),
    };
    // The commons pointer: an address the instructions hand to agents,
    // never dereferenced here — T4 well-formedness is the whole startup
    // check, the same class of refusal as a bad board.
    let commons = env_text("SKEP_COMMONS").inspect(|a| {
        if !is_t4_address(a) {
            die(format_args!("SKEP_COMMONS: '{a}' is not a T4-valid address"));
        }
    });
    if let Some(addr) = &commons {
        catalog.append_commons(addr);
    }
    // The loop's two inputs, on one channel: stdin's lines and its end, which
    // `read_stdin` sends from a thread of its own, and the backend's stop,
    // which `OnStop` sends on this unbounded channel and never waits on.
    let (inbound, inbox) = mpsc::channel::<Inbound>();
    let on_stop = OnStop::new(inbound.clone(), Inbound::Stop);
    // THE SHELL: opened, checked and its one session opened before any tool
    // is served; a stop here returns, so the shell's own stop has run.
    let talk: skep_shell::Talk = Arc::new(|line: &str| log(line));
    let backend = match Backend::open(origin, store_dir, principal, talk, on_stop) {
        Ok(backend) => backend,
        Err(line) => {
            log(line);
            return ExitCode::from(1);
        }
    };
    log(format_args!(
        "serving {} tools on stdio, one call at a time{}; stdin's end closes the session at the board and saves the index — a signal ends the process with neither, and the session then lives on at the board until it restarts",
        catalog.tools().len(),
        commons.as_deref().map(|a| format!(", commons {a}")).unwrap_or_default()
    ));
    read_stdin(inbound);
    Server { backend, catalog }.run(&inbox)
}

/// Writes one line on the operator's stream, stderr, as `logged` renders it.
///
/// It is written by `writeln!` with the result discarded — never
/// `eprintln!`, which panics when the write fails. MCP's stdio transport
/// lets a client ignore the server's stderr, and an unread log fails its
/// writes (a pipe whose reader has gone answers EPIPE, a full volume
/// ENOSPC): a line is never worth the work it reports on, the rule
/// skep-util's `notice` keeps for the daemon. So a log line never fails and
/// never reports. The shell's `Talk` lines come through here too, so stdout
/// stays the JSON-RPC stream alone, and every line on stderr is rendered.
fn log(line: impl Display) {
    let _ = writeln!(std::io::stderr(), "{}", logged(line));
}

/// Returns `line` as the operator's stream carries it.
///
/// It is prefixed `skep-mcp: `; every control `render_inert` disarms — the
/// C0 controls, DEL and the bidi controls (AUTH-5.2) — is shown as its code
/// point; and every line it breaks onto is indented two spaces, an empty one
/// left empty. A board's text rides many lines here — a refusal's code and
/// detail, the `/health` claimant, a block's record and ground, the shell's
/// `Talk` of its feed and held threads — and the stream is a terminal, or a
/// log a terminal shows later, where a control acts: ESC opens a sequence
/// that retitles the window, moves the cursor or writes the clipboard, CR
/// overwrites the line. So no C0 control, DEL or bidi control a board chose
/// acts there, and no text it chose opens a line of this stream as
/// `skep-mcp: `. A C1 control passes as it came, as `render_inert` passes
/// it.
fn logged(line: impl Display) -> String {
    let text = line.to_string();
    let mut out = String::from("skep-mcp: ");
    for (k, piece) in text.split('\n').enumerate() {
        if k > 0 {
            out.push('\n');
            if !piece.is_empty() {
                out.push_str("  ");
            }
        }
        out.push_str(&render_inert(piece));
    }
    out
}

/// Says a refusal before the shell is open, and exits 1.
///
/// `msg` is the refusal's line as `format_args!` makes it, so no caller
/// builds a `String` to lend. It is never called past `Backend::open`, whose
/// stop returns from `main` so the shell drops.
fn die(msg: fmt::Arguments<'_>) -> ! {
    log(msg);
    std::process::exit(1);
}

/// Says a usage error and the usage after it, and exits 2.
fn die_usage(msg: fmt::Arguments<'_>) -> ! {
    log(format_args!("{msg}\n\n{USAGE}"));
    std::process::exit(2);
}

/// A variable's text, `None` while it is unset. A value that is not UTF-8
/// text is refused by name, in skepd's words, never read as unset: it was
/// given, and running on a default in its place is the silent failure the
/// refusal exists to prevent.
fn env_text(var: &str) -> Option<String> {
    match env::var(var) {
        Ok(text) => Some(text),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => die(format_args!("{var}: the value is not UTF-8 text")),
    }
}

/// T4 well-formedness of a dotted-decimal tumbler string (wire.md §Value
/// encodings; the four clauses of skep-address's validator): every
/// component is a decimal natural, the first and last are nonzero, no two
/// zeros are adjacent, and at most three components are zero. Zeroness is
/// judged on the digits (`"00"` is zero, matching the daemon's lenient
/// numeric read); magnitudes stay strings — T4 never bounds size. A test
/// holds it to the validator's verdict on every short dotted decimal.
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
mod tests {
    use super::*;

    /// The startup gate on SKEP_COMMONS is exactly T4: leading/trailing
    /// zero, adjacent zeros, and a fourth separator all refuse; depth and
    /// magnitude do not.
    #[test]
    fn the_commons_gate_refuses_each_t4_clause_but_no_depth_or_magnitude() {
        for good in ["1", "1.1", "1.0.2", "1.0.1.0.1", "1.0.1.0.1.0.1.1", "1.0.2.0.3.0.3.6.1", "10.20.30"] {
            assert!(is_t4_address(good), "'{good}' is T4-valid");
        }
        for bad in ["", "0", "0.1", "1.0", "1..2", "1.a", " 1", "1.0.0.1", "1.0.1.0.1.0.1.0.2", "1.-2"] {
            assert!(!is_t4_address(bad), "'{bad}' is not T4-valid");
        }
    }

    /// The gate is skep-address's T4 validator read off the digits — a law,
    /// so every string of a family is visited, not a chosen few: each dotted
    /// decimal of one to nine components drawn from `0`, `00`, `1` and `10`.
    /// Nine components are the fewest in which a fourth zero breaks no other
    /// clause; `00` is a zero by its digits, `10` a nonzero ending in one.
    #[test]
    fn the_commons_gate_agrees_with_skep_address_on_every_short_dotted_decimal() {
        use skep_address::{is_t4_valid, Nat, Tumbler};
        let alphabet: [(&str, u32); 4] = [("0", 0), ("00", 0), ("1", 1), ("10", 10)];
        let (mut visited, mut disagreements) = (0usize, Vec::new());
        for depth in 1..=9u32 {
            for mut n in 0..4usize.pow(depth) {
                let (mut digits, mut comps) = (Vec::new(), Vec::new());
                for _ in 0..depth {
                    let (text, value) = alphabet[n % 4];
                    digits.push(text);
                    comps.push(Nat::from(value));
                    n /= 4;
                }
                let s = digits.join(".");
                let valid = is_t4_valid(&Tumbler::new(comps).expect("a nonempty tumbler"));
                if is_t4_address(&s) != valid {
                    disagreements.push(s);
                }
                visited += 1;
            }
        }
        assert_eq!(visited, 349_524, "the family visited whole");
        assert!(disagreements.is_empty(), "{} strings judged unlike is_t4_valid, first: {:?}", disagreements.len(), &disagreements[..disagreements.len().min(5)]);
    }

    /// THE VERSION LINE: `skep-mcp <crate version> (<commit>)`, the version
    /// `CARGO_PKG_VERSION`'s and the commit `SKEP_GIT_SHA`'s at build time,
    /// `unknown` where the build set none, which this suite's build never
    /// does; and the usage names the flag.
    #[test]
    fn the_version_line_names_the_binary_its_version_and_the_build_commit() {
        assert_eq!(version_line(), format!("skep-mcp {} ({})", env!("CARGO_PKG_VERSION"), option_env!("SKEP_GIT_SHA").unwrap_or("unknown")));
        assert!(USAGE.contains("\n  --version            this binary's version"), "{USAGE}");
    }

    /// A log line is inert, and only its first line opens as the adapter's.
    ///
    /// A control a board's text carries — ESC opening a terminal sequence,
    /// BEL, CR, a bidi override — is shown as its code point, on any line; a
    /// line break it carries continues the line indented, so a forged
    /// `skep-mcp: ` opens no line; a face's own lines keep their order, each
    /// indented; an empty line stays empty; printable text passes as written.
    #[test]
    fn a_log_line_is_inert_and_opens_as_the_adapters_once() {
        assert_eq!(logged("claimant \u{1b}]0;owned\u{7}"), "skep-mcp: claimant <U+001B>]0;owned<U+0007>");
        assert_eq!(logged("x\r\u{202e}y"), "skep-mcp: x<U+000D><U+202E>y");
        assert_eq!(logged("a\nb\u{1b}c"), "skep-mcp: a\n  b<U+001B>c");
        assert_eq!(logged("the board refused: x\nskep-mcp: signed as principal 0"), "skep-mcp: the board refused: x\n  skep-mcp: signed as principal 0");
        assert_eq!(logged("no_key: s\n  cause: c\n  act: a"), "skep-mcp: no_key: s\n    cause: c\n    act: a");
        assert_eq!(logged("unknown argument 'x'\n\nusage: skep-mcp"), "skep-mcp: unknown argument 'x'\n\n  usage: skep-mcp");
        assert_eq!(logged("person seam: refuse — é"), "skep-mcp: person seam: refuse — é");
    }

    /// A setting names its flag and variable, and holds the flag's value.
    #[test]
    fn a_setting_names_its_flag_and_variable_and_holds_the_flags_value() {
        let mut board = Setting::new("--board", Some("SKEP_BOARD"));
        assert_eq!(board.named(), "--board (or SKEP_BOARD)");
        assert_eq!(Setting::new("--tools-file", None).named(), "--tools-file");
        board.take(&mut [OsString::from("http://127.0.0.1:8642")].into_iter());
        assert_eq!(board.text().as_deref(), Some("http://127.0.0.1:8642"), "the flag's value, its variable unread");
    }

    /// The usage names the three settings by flag and variable, and says
    /// `SKEPD_URL` is read no longer: a person whose shell still exports it
    /// reads here where the board is named now.
    #[test]
    fn the_usage_names_the_settings_and_retires_skepd_url() {
        for named in ["--board <ORIGIN>", "SKEP_BOARD", "--dir <PATH>", "SKEP_KEYSTORE", "--principal <N>", "SKEP_PRINCIPAL", "SKEP_COMMONS", "SKEPD_URL       no longer read"] {
            assert!(USAGE.contains(named), "the usage names {named}: {USAGE}");
        }
    }

    /// The usage states the exit statuses the suites pin.
    ///
    /// 0 at stdin's end or a closed stdout, 1 a refusal before serving or a
    /// stop while serving, 2 a usage error.
    #[test]
    fn the_usage_states_the_exit_statuses() {
        for status in ["\nexit status:\n  0  stdin's end", "\n  1  a refusal before serving", "\n  2  a usage error"] {
            assert!(USAGE.contains(status), "the usage states {status:?}: {USAGE}");
        }
    }
}
