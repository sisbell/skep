//! skep-mcp — the adapter between an agent harness (MCP: JSON-RPC 2.0 over
//! stdio, newline-delimited UTF-8, one message per line) and skepd
//! (HTTP/JSON, `skep/docs/wire.md`). One process per agent; a small, boring
//! protocol surface with no semantics of its own:
//!
//! * Tool name → wire op is mechanical: the name IS the frame's `op`, the
//!   arguments ARE the frame (the one mapping is `from_` → `from` on
//!   make_link/emit). Arguments pass through unvalidated — the daemon's
//!   strict parse is the validator, and its verdict comes back as data.
//! * A skepd response document is the tool result, verbatim. `isError` is
//!   ONLY transport failure reaching skepd; an op rejection is a normal
//!   result — a client that cannot read a rejection has been silently
//!   failed.
//! * Sessions are the adapter's apparatus, opened lazily when the daemon
//!   first demands one (`unauthenticated` on a write) and reopened —
//!   resending the frame once — when a restarted daemon has killed the
//!   token. That is the only retry logic anywhere.
//!
//! `server.rs` is the MCP side: the stdio loop, the JSON-RPC dispatch, and
//! `call`, which keeps the second rule. `daemon.rs` is the skepd side: the
//! principal, the session token — which no other module can read — the one
//! resend of the third rule, and every exchange the adapter has with skepd.
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

use crate::daemon::Skepd;
use crate::server::Server;

const USAGE: &str = "\
usage: skep-mcp [--tools-file <PATH>]

  --tools-file <PATH>  override the embedded tool catalog (tools.json:
                       names, descriptions, schemas, server instructions)
  --help               this text

environment:
  SKEPD_URL       the daemon's base URL (default http://127.0.0.1:8642)
  SKEP_PRINCIPAL  the principal this adapter binds (required, integer)
  SKEP_COMMONS    optional address of a link-type registry document; when
                  set, the server instructions point agents at it

Speaks MCP (JSON-RPC 2.0, one message per line) on stdio; the skepd side
is specified in skep/docs/wire.md.";

fn main() {
    let mut tools_file: Option<std::path::PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--tools-file" => match args.next() {
                Some(p) => tools_file = Some(p.into()),
                None => die_usage("--tools-file needs a value"),
            },
            "--help" | "-h" => {
                println!("{USAGE}");
                return;
            }
            other => die_usage(&format!("unknown argument '{other}'")),
        }
    }
    // The catalog first: a drifted tools file is a startup error before any
    // environment or network is consulted.
    let text = match &tools_file {
        None => tools::EMBEDDED.to_string(),
        Some(p) => match std::fs::read_to_string(p) {
            Ok(t) => t,
            Err(e) => die(&format!("--tools-file {}: {e}", p.display())),
        },
    };
    let mut catalog = match tools::load(&text) {
        Ok(c) => c,
        Err(e) => die(&format!("tools file: {e}")),
    };
    let principal = match std::env::var("SKEP_PRINCIPAL") {
        Ok(v) => match v.parse::<u64>() {
            Ok(p) => p,
            Err(_) => die(&format!(
                "SKEP_PRINCIPAL: '{v}' is not a principal (a non-negative integer)"
            )),
        },
        Err(_) => die("SKEP_PRINCIPAL is required (the principal this adapter binds)"),
    };
    let url =
        std::env::var("SKEPD_URL").unwrap_or_else(|_| String::from("http://127.0.0.1:8642"));
    let http = match http::parse_url(&url) {
        Ok(h) => h,
        Err(e) => die(&format!("SKEPD_URL {e}")),
    };
    // The commons pointer: an address the instructions hand to agents,
    // never dereferenced here — T4 well-formedness is the whole startup
    // check, the same class of refusal as a bad SKEPD_URL.
    let commons = match std::env::var("SKEP_COMMONS") {
        Ok(a) => {
            if !is_t4_address(&a) {
                die(&format!("SKEP_COMMONS: '{a}' is not a T4-valid address"));
            }
            Some(a)
        }
        Err(_) => None,
    };
    if let Some(addr) = &commons {
        catalog.append_commons(addr);
    }
    eprintln!(
        "skep-mcp: skepd at http://{}, principal {principal}, {} tools{}",
        http.authority(),
        catalog.tools.len(),
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

/// T4 well-formedness of a dotted-decimal tumbler string (wire.md §Value
/// encodings; the four clauses of skep-address's validator): every
/// component is a decimal natural, the first and last are nonzero, no two
/// zeros are adjacent, and at most three components are zero. Zeroness is
/// judged on the digits (`"00"` is zero, matching the daemon's lenient
/// numeric read); magnitudes stay strings — T4 never bounds size.
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
    fn t4_address_check() {
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
}
