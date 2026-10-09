//! skep-mcp — the adapter between an agent harness (MCP: JSON-RPC 2.0 over
//! stdio, newline-delimited UTF-8, one message per line) and skepd
//! (HTTP/JSON, `skep/docs/wire.md`). One process per agent; a small, boring
//! protocol surface with no semantics of its own:
//!
//! * Tool name → wire op is mechanical: the name IS the frame's `op`, the
//!   arguments ARE the frame (the one mapping is `from_` → `from` on
//!   make_link/emit). Arguments pass through unvalidated — the daemon's
//!   strict parse is the validator, and its rejection comes back as data.
//! * A skepd response document is the tool result, verbatim. `isError` is
//!   ONLY transport failure reaching skepd; an op rejection is a normal
//!   result — a client that cannot read a rejection has been silently
//!   failed.
//! * Sessions are the adapter's apparatus: bare sessions only (wire.md
//!   §Sessions), opened when the daemon demands one — `unauthenticated` on
//!   a write, at the adapter's first write and again after a restarted
//!   daemon has killed the token — and the demanding frame reissued once.
//!   That is the only reissue anywhere; every other rejection, whatever
//!   its disposition, passes through as data.
//!
//! `server.rs` is the MCP side: the stdio loop, the JSON-RPC dispatch, and
//! `call`, which keeps the second rule. `daemon.rs` is the skepd side: the
//! principal, the session token — which no other module can read — the one
//! reissue of the third rule, and every exchange the adapter has with skepd.
//! `http.rs` is the written-out HTTP/1.1 client those exchanges go through.
//! `tools.rs` holds the catalog (`tools.json`, embedded) with its commons
//! sentence, the dispatch table the catalog is checked against when loaded,
//! and the first rule's mapping of a tool call onto a wire frame. This file
//! is startup: flags, environment, the `SKEP_COMMONS` check.
//!
//! stdout is protocol-only; all logging goes to stderr. Stdin EOF is the
//! clean exit.

#![forbid(unsafe_code)]

mod daemon;
mod http;
mod server;
mod tools;

use std::borrow::Cow;
use std::env::{self, VarError};
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
  SKEP_PRINCIPAL  the principal this adapter binds (required, integer)
  SKEP_COMMONS    optional address of the commons, the document whose
                  subspace 3 names link types; when set, the server
                  instructions point agents at it

Speaks MCP (JSON-RPC 2.0, one message per line) on stdio; the skepd side
is specified in skep/docs/wire.md.";

fn main() {
    let mut tools_file: Option<PathBuf> = None;
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--tools-file") => match args.next() {
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
    let principal = match env_text("SKEP_PRINCIPAL") {
        Some(v) => match v.parse::<u64>() {
            Ok(p) => p,
            Err(_) => die(&format!(
                "SKEP_PRINCIPAL: '{v}' is not a principal (a non-negative integer)"
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
    eprintln!(
        "skep-mcp: skepd at http://{}, principal {principal}, {} tools{}",
        http.authority(),
        catalog.tools().len(),
        commons.as_deref().map(|a| format!(", commons {a}")).unwrap_or_default()
    );
    Server { skepd: Skepd::new(http, principal), catalog }.run();
}

fn die(msg: &str) -> ! {
    eprintln!("skep-mcp: {msg}");
    std::process::exit(1);
}

fn die_usage(msg: &str) -> ! {
    eprintln!("skep-mcp: {msg}\n\n{USAGE}");
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
    let mut count = 0usize;
    for comp in s.split('.') {
        if comp.is_empty() || !comp.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        let z = is_zero(comp);
        if z {
            if prev_zero || count == 0 {
                return false;
            }
            zeros += 1;
        }
        prev_zero = z;
        count += 1;
    }
    count > 0 && !prev_zero && zeros <= 3
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
    fn t4_check_agrees_with_skep_address_on_every_short_dotted_decimal() {
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
