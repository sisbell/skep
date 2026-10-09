//! skep-mcp — the adapter between an agent harness (MCP: JSON-RPC 2.0 over
//! stdio, newline-delimited UTF-8, one message per line) and skepd
//! (HTTP/JSON, `skep/docs/wire.md`). One process per agent; a small, boring
//! protocol surface with no semantics of its own:
//!
//! * Tool name → wire op is mechanical: the name IS the frame's `op`, the
//!   arguments ARE the frame (the one mapping is `from_` → `from` on
//!   make_link/emit, when the arguments carry no `from` of their own).
//!   Arguments pass through unvalidated — the daemon's strict parse is the
//!   validator, and its rejection comes back as data.
//! * Whatever skepd answers to a frame is the tool result, verbatim, up to
//!   the size cap `http.rs` reads an answer to: a response document, or —
//!   at a non-200 status, which wire.md §HTTP status codes calls a
//!   transport-level failure — its `{"error", "detail"?}` body. `isError`
//!   is ONLY the adapter's failure to bring back such an answer — `Skepd`'s
//!   `Err`, an answer past that cap among them — and after one on a write,
//!   that write's outcome is unknown: its frame may have reached the daemon
//!   and committed, and the adapter never reissues it. An op rejection is a
//!   normal result — a client that cannot read a rejection has been
//!   silently failed. A call the adapter will not run — a tool outside the
//!   catalog, an argument `session_info` does not take — is no tool result
//!   at all: it is refused -32602, as malformed `tools/call` params are.
//! * Sessions are the adapter's apparatus: bare sessions only (wire.md
//!   §Sessions), opened when the daemon demands one — `unauthenticated` on
//!   a write, at the adapter's first write and again once the token has
//!   died (a daemon restart kills every token) — and the demanding frame
//!   reissued once. That is the only reissue anywhere; every other
//!   rejection, whatever its disposition, passes through as data. A read
//!   demands no session, so while none is live — before the first write,
//!   and from a session's end to the next write — reads run at guest class
//!   (wire.md §The read predicate).
//!
//! `server.rs` is the MCP side: the stdio loop, the JSON-RPC dispatch, and
//! `call`, which keeps the second rule. `daemon.rs` is the skepd side: the
//! principal, the session token — which no other module can read — the one
//! reissue of the third rule, and every exchange the adapter has with skepd.
//! `http.rs` is the written-out HTTP/1.1 client those exchanges go through.
//! `tools.rs` holds the catalog (`tools.json`, embedded) with its commons
//! sentence, the dispatch table the catalog is checked against when loaded,
//! and the first rule's mapping of a tool call onto a wire frame. This file
//! is startup — flags, environment, the `SKEP_COMMONS` check — and `log`,
//! the operator's stream every module writes through.
//!
//! stdout is protocol-only; all logging goes to stderr, through `log`,
//! whose failure fails nothing. Stdin EOF is the clean exit.

#![forbid(unsafe_code)]

mod daemon;
mod http;
mod server;
mod tools;

use std::borrow::Cow;
use std::env::{self, VarError};
use std::fmt::Display;
use std::io::Write;
use std::path::PathBuf;

use crate::daemon::Skepd;
use crate::http::Http;
use crate::server::Server;
use crate::tools::Catalog;

const USAGE: &str = "\
usage: skep-mcp [--tools-file <PATH>]

  --tools-file <PATH>  override the embedded tool catalog (tools.json:
                       names, descriptions, schemas, server instructions)
  --help               this text

environment:
  SKEPD_URL       the daemon's origin (default http://127.0.0.1:8642)
  SKEP_PRINCIPAL  the principal this adapter binds (required: an integer,
                  0 to 9007199254740991, the largest a board registers)
  SKEP_COMMONS    optional address of the commons, the document whose
                  subspace 3 names link types; when set, the server
                  instructions point agents at it

Speaks MCP (JSON-RPC 2.0, one message per line) on stdio; the skepd side
is specified in skep/docs/wire.md.";

/// The largest principal id a board registers: `2^53 − 1`, the top of the
/// range a JSON number carries exactly — skepd's `delegate` refuses a
/// larger `new_id` at the parse (wire.md §Value encodings), so every
/// principal a board seats sits at or below it. An adapter bound past it
/// could never write, and skepd refuses such an id at no door this adapter
/// uses (the bare `POST /session` body and `principal_prefix` read any
/// `u64`), so startup is the bound's one check here — as skep-cli's
/// `parse_principal` is for the same variable, at the same bound.
const MAX_PRINCIPAL: u64 = (1 << 53) - 1;

fn main() {
    let mut tools_file: Option<PathBuf> = None;
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--tools-file") => match args.next() {
                Some(_) if tools_file.is_some() => die_usage("--tools-file is given at most once"),
                Some(p) => tools_file = Some(p.into()),
                None => die_usage("--tools-file needs a value"),
            },
            Some("--help" | "-h") => {
                println!("{USAGE}");
                return;
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
    // Then the environment, each variable refused by name and the first
    // refusal ending startup: SKEP_PRINCIPAL, SKEPD_URL, SKEP_COMMONS.
    let principal = match env_text("SKEP_PRINCIPAL") {
        Some(v) => match v.parse::<u64>().ok().filter(|p| *p <= MAX_PRINCIPAL) {
            Some(p) => p,
            None => die(&format!(
                "SKEP_PRINCIPAL: '{v}' is not a principal (a non-negative integer no greater \
                 than {MAX_PRINCIPAL})"
            )),
        },
        None => die("SKEP_PRINCIPAL is required (the principal this adapter binds)"),
    };
    let url = env_text("SKEPD_URL").unwrap_or_else(|| String::from("http://127.0.0.1:8642"));
    let http = match Http::parse(&url) {
        Ok(h) => h,
        Err(e) => die(&format!("SKEPD_URL {e}")),
    };
    // The commons pointer: an address the instructions hand to agents,
    // never dereferenced here — T4 well-formedness is the whole startup
    // check, the same class of refusal as a bad SKEPD_URL.
    let commons = env_text("SKEP_COMMONS").inspect(|a| {
        if !is_t4_address(a) {
            die(&format!("SKEP_COMMONS: '{a}' is not a T4-valid address"));
        }
    });
    if let Some(addr) = &commons {
        catalog.append_commons(addr);
    }
    log(format_args!(
        "skepd at http://{}, principal {principal}, {} tools{}",
        http.authority(),
        catalog.tools().len(),
        commons.as_deref().map(|a| format!(", commons {a}")).unwrap_or_default()
    ));
    Server { skepd: Skepd::new(http, principal), catalog }.run();
}

/// One line on the operator's stream: stderr, prefixed `skep-mcp: `,
/// written by `writeln!` with the result discarded — never `eprintln!`,
/// which panics when the write fails. MCP's stdio transport lets a client
/// ignore the server's stderr, and an unread log fails its writes (a pipe
/// whose reader has gone answers EPIPE, a full volume ENOSPC): a line is
/// never worth the work it reports on, the rule skep-util's `notice` keeps
/// for the daemon. So a log line never fails and never reports.
fn log(line: impl Display) {
    let _ = writeln!(std::io::stderr(), "skep-mcp: {line}");
}

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
/// given, and running on the default in its place is the silent failure
/// the refusal exists to prevent.
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
        for good in
            ["1", "1.1", "1.0.2", "1.0.1.0.1", "1.0.1.0.1.0.1.1", "1.0.2.0.3.0.3.6.1", "10.20.30"]
        {
            assert!(is_t4_address(good), "'{good}' is T4-valid");
        }
        for bad in
            ["", "0", "0.1", "1.0", "1..2", "1.a", " 1", "1.0.0.1", "1.0.1.0.1.0.1.0.2", "1.-2"]
        {
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
        assert!(
            disagreements.is_empty(),
            "{} strings judged unlike is_t4_valid, first: {:?}",
            disagreements.len(),
            &disagreements[..disagreements.len().min(5)]
        );
    }
}
