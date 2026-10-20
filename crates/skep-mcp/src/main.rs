//! skep-mcp — the adapter between an agent harness (MCP: JSON-RPC 2.0 over
//! stdio, newline-delimited UTF-8, one message per line) and a board,
//! served through the shell's core, `skep-shell` — the engine the dev
//! provider and the desktop shell run on. One process per agent, one
//! board, ONE SIGNED SESSION for the adapter's life:
//!
//! * Every tool is one call of the shell under that session. A WIRE OP's
//!   tool name IS the frame's `op` and its arguments ARE the frame (the one
//!   mapping is `from_` → `from` on make_link/emit, when the arguments carry
//!   no `from` of their own), sent as `op(session, frame)`: attested where
//!   the session's key attests the kind, held where the board cannot take a
//!   burst (the `held` answer comes back as data), a `write_busy` reissued
//!   once and a `durability` twice within the call, as the shell does. The
//!   shell's own calls — `boards`, `health`, `probe`, `search`, `places`,
//!   `held`, `resolve` — are tools of those names, their arguments the
//!   bridge's row minus the session and the board the adapter supplies; and
//!   three are the adapter's own: `session_info`, `changes_since` (the
//!   shell's `changes`, a pull), and `fetch` (the shell's streamed fetch as
//!   an image or resource block, the type sniffed off the bytes, the size
//!   capped). Arguments pass through unvalidated on a wire op — the daemon's
//!   strict parse is the validator, and its rejection comes back as data.
//! * The board's verdict is DATA: a `refused` refusal is a normal tool
//!   result, the verdict's body verbatim with the shell's envelope beside
//!   it. `isError` is every other refusal — the shell could not get the
//!   board's verdict: the board unreachable, a halt, the block, the shell's
//!   own names. A call the adapter will not run — a tool outside the
//!   catalog, an argument an adapter tool does not take — is no tool result
//!   at all: it is refused -32602, as malformed `tools/call` params are.
//! * SIGNED ONLY: the session is opened at startup, before the first tool
//!   call, for the configured principal with the store's key for it —
//!   enrolled in its account's set or the nearest set above it — and no
//!   bare mode exists. No key, or a key the board refuses, stops the
//!   adapter before it serves. A board restart is met by the shell's silent
//!   re-open; a death the shell does not re-open — the key retired, the
//!   prefix blocked, the account seeded, a re-open the board refused —
//!   stops the process with one plain line naming the arm. No person is at
//!   the seam (`ArmConfig::Refuse`): no ceremony tool is offered, and every
//!   SECRET or CONSENT moment would be refused `person_required`.
//!
//! `server.rs` is the MCP side: the stdio transport — stdin's reader, and
//! the loop that answers each line on stdout — the JSON-RPC dispatch, and
//! `call`, which keeps the second rule. `shell.rs` is the one seam onto
//! `skep-shell`: the open and its checks, the one session's reference and
//! its life, the bus drained. `media.rs` is the fetched file: its bytes
//! read whole under the adapter's cap, its type sniffed, its base64.
//! `tools.rs` holds the catalog (`tools.json`, embedded) with its commons
//! sentence, the dispatch's two kinds the catalog is checked against when
//! loaded, and the first rule's mapping of a wire op's call onto a frame.
//! This file is startup — flags, environment, the `SKEP_COMMONS` check, the
//! shell's open — the loop's two inputs (stdin's reader, the bus's drain)
//! wired onto one channel, and `log`, the operator's stream every module
//! and the shell's TALK write through.
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
use std::fmt::Display;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::Arc;

use skep_client::Origin;

use crate::server::{read_stdin, Inbound, Server};
use crate::shell::Backend;
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

/// A setting a flag or its variable supplies: the flag's value where the
/// flag was given, else the variable's text, else none; a flag given twice
/// is a usage error at the parse.
#[derive(Debug, Default)]
struct Setting {
    flag: Option<OsString>,
}

impl Setting {
    /// The value, the flag over the variable `var`.
    fn value(&self, flag: &str, var: &str) -> Option<String> {
        match &self.flag {
            Some(text) => match text.to_str() {
                Some(text) => Some(text.to_string()),
                None => die(&format!("{flag}: the value is not UTF-8 text")),
            },
            None => env_text(var),
        }
    }
}

fn main() -> ExitCode {
    let mut tools_file: Option<PathBuf> = None;
    let (mut board, mut dir, mut principal) = (Setting::default(), Setting::default(), Setting::default());
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        let flag = arg.to_str();
        match flag {
            Some("--tools-file") => match args.next() {
                Some(_) if tools_file.is_some() => die_usage("--tools-file is given at most once"),
                Some(p) => tools_file = Some(p.into()),
                None => die_usage("--tools-file needs a value"),
            },
            Some(name @ ("--board" | "--dir" | "--principal")) => {
                let setting = match name {
                    "--board" => &mut board,
                    "--dir" => &mut dir,
                    _ => &mut principal,
                };
                match args.next() {
                    Some(_) if setting.flag.is_some() => die_usage(&format!("{name} is given at most once")),
                    Some(value) => setting.flag = Some(value),
                    None => die_usage(&format!("{name} needs a value")),
                }
            }
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
            _ => die_usage(&format!("unknown argument '{}'", arg.to_string_lossy())),
        }
    }
    // The catalog first: a drifted tools file is a startup error before any
    // environment or network is consulted.
    let text = match &tools_file {
        None => Cow::Borrowed(tools::EMBEDDED),
        Some(p) => match std::fs::read_to_string(p) {
            Ok(t) => Cow::Owned(t),
            Err(e) => die(&format!("--tools-file {}: {e}", p.display())),
        },
    };
    let mut catalog = match Catalog::load(&text) {
        Ok(c) => c,
        Err(e) => die(&format!("tools file: {e}")),
    };
    // Then the settings, each refused by name and the first refusal ending
    // startup: the principal, the board, the store, the commons.
    let principal = match principal.value("--principal", "SKEP_PRINCIPAL") {
        Some(v) => match v.parse::<u64>().ok().filter(|p| *p <= MAX_PRINCIPAL) {
            Some(p) => p,
            None => die(&format!("--principal (or SKEP_PRINCIPAL): '{v}' is not a principal (a non-negative integer no greater than {MAX_PRINCIPAL})")),
        },
        None => die("--principal (or SKEP_PRINCIPAL) is required: the principal this adapter acts as"),
    };
    let origin = match board.value("--board", "SKEP_BOARD") {
        Some(text) => match Origin::parse(&text) {
            Some(origin) => origin,
            None => die(&format!("--board (or SKEP_BOARD): '{text}' is not a canonical origin (http://host[:port], lowercase, no path, no trailing slash)")),
        },
        None => {
            let retired = if env_text("SKEPD_URL").is_some() { " — SKEPD_URL is set and no longer read: the board is named by --board or SKEP_BOARD alone" } else { "" };
            die(&format!("--board (or SKEP_BOARD) is required: the board this adapter serves{retired}"))
        }
    };
    let store_dir = match dir.value("--dir", "SKEP_KEYSTORE") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => die("--dir (or SKEP_KEYSTORE) is required: the key store this adapter signs from, one directory per adapter process (~/.skep is never consulted)"),
    };
    // The commons pointer: an address the instructions hand to agents,
    // never dereferenced here — T4 well-formedness is the whole startup
    // check, the same class of refusal as a bad board.
    let commons = env_text("SKEP_COMMONS").inspect(|a| {
        if !is_t4_address(a) {
            die(&format!("SKEP_COMMONS: '{a}' is not a T4-valid address"));
        }
    });
    if let Some(addr) = &commons {
        catalog.append_commons(addr);
    }
    // THE SHELL: opened, checked and its one session opened before any tool
    // is served; a stop here returns, so the shell's own stop has run.
    let talk: skep_shell::Talk = Arc::new(|line: &str| log(line));
    let backend = match Backend::open(origin, store_dir, principal, talk) {
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
    // The loop's two inputs, on one channel: stdin's lines and its end, which
    // `read_stdin` sends from a thread of its own, and the bus's drain, which
    // sends the backend's stop.
    let (inbound, lines) = mpsc::channel::<Inbound>();
    read_stdin(inbound.clone());
    backend.drain(move |line| {
        let _ = inbound.send(Inbound::Stop(line));
    });
    let server = Server { backend, catalog };
    let code = server.run(&lines);
    log("stopping: closing the session at the board, saving the index");
    server.backend.shutdown();
    ExitCode::from(code)
}

/// One line on the operator's stream: stderr, prefixed `skep-mcp: `,
/// written by `writeln!` with the result discarded — never `eprintln!`,
/// which panics when the write fails. MCP's stdio transport lets a client
/// ignore the server's stderr, and an unread log fails its writes (a pipe
/// whose reader has gone answers EPIPE, a full volume ENOSPC): a line is
/// never worth the work it reports on, the rule skep-util's `notice` keeps
/// for the daemon. So a log line never fails and never reports. The
/// shell's TALK lines come through here too, so stdout stays the JSON-RPC
/// stream alone.
fn log(line: impl Display) {
    let _ = writeln!(std::io::stderr(), "skep-mcp: {line}");
}

/// A refusal before the shell is open: the line, exit 1. Never called past
/// `Backend::open`, whose stop returns from `main` so the shell drops.
fn die(msg: &str) -> ! {
    log(msg);
    std::process::exit(1);
}

fn die_usage(msg: &str) -> ! {
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
        Err(VarError::NotUnicode(_)) => die(&format!("{var}: the value is not UTF-8 text")),
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

    /// The usage names the three settings by flag and variable, and says
    /// `SKEPD_URL` is read no longer: a person whose shell still exports it
    /// reads here where the board is named now.
    #[test]
    fn the_usage_names_the_settings_and_retires_skepd_url() {
        for named in ["--board <ORIGIN>", "SKEP_BOARD", "--dir <PATH>", "SKEP_KEYSTORE", "--principal <N>", "SKEP_PRINCIPAL", "SKEP_COMMONS", "SKEPD_URL       no longer read"] {
            assert!(USAGE.contains(named), "the usage names {named}: {USAGE}");
        }
    }
}
