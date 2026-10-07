//! `skep enroll` (`client.md` §2.2): the hop's signed-in half — another
//! device's payload enrolled from a session this command opens, a person
//! door; `--reply` re-derives the three facts with no write (AUTH-5.32).

use skep_client::ceremony::enroll::{self as enroll_walk, EnrollOptions};
use skep_client::dial::plaintext_non_loopback_warning;

use super::{board_of, facts, halt, no_terminal, principal_or_bound, read_payload, store_of, talk, usage};
use crate::args::{Command, Usage};
use crate::terminal::{has_terminal, Terminal};

pub fn enroll(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let given = match c.principal() {
        Ok(p) => p,
        Err(u) => return usage(u),
    };
    let principal = match principal_or_bound(given, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    // `--reply`: the three facts re-derived, no write — not a person door.
    if let Some(prefix) = c.value("--reply", None) {
        return match enroll_walk::reply(&board, principal, &prefix) {
            Err(h) => halt(h),
            Ok(e) => {
                talk(format!("the reply, offered again (AUTH-5.32): {} stands ENROLLED at {}", e.fingerprints[0], e.facts.account));
                facts(&e.facts);
                0
            }
        };
    }
    if !has_terminal() {
        return no_terminal("enroll");
    }
    let Some(payload_arg) = c.value("--payload", None) else { return usage(Usage("--payload <file|-> is required (or --reply <fp-prefix>)".into())) };
    let payload = match read_payload(&payload_arg) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let mut person = Terminal::new();
    match enroll_walk::enroll(&board, &store, &mut person, &EnrollOptions { principal, payload }) {
        Err(h) => halt(h),
        Ok(e) => {
            // The walk said what it found, a reconciliation among it
            // (AUTH-5.17), through the person; the warnings are what it
            // leaves for the command to say.
            for w in &e.warnings {
                talk(w);
            }
            facts(&e.facts);
            0
        }
    }
}
