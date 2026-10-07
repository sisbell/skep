//! `skep retire` (`client.md` §2.2): a device key retired from a full
//! session this command opens, after the preview and a typed answer — a
//! person door, and no flag stands for the answer (AUTH-5.46). The walk says
//! the next act where the retirement ended its own session (AUTH-5.28); the
//! command prints what was retired.

use skep_client::ceremony::retire::{self as retire_walk, RetireOptions};
use skep_client::dial::plaintext_non_loopback_warning;

use super::{board_of, data, halt, no_terminal, principal_or_bound, store_of, talk, usage};
use crate::args::{Command, Usage};
use crate::terminal::{has_terminal, Terminal};

pub fn retire(c: &Command) -> i32 {
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
    let Some(fingerprint_prefix) = c.value("--fingerprint", None) else { return usage(Usage("--fingerprint <fp-prefix> is required".into())) };
    if !has_terminal() {
        return no_terminal("retire");
    }
    let principal = match principal_or_bound(given, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let mut person = Terminal::new();
    match retire_walk::retire(&board, &store, &mut person, &RetireOptions { principal, fingerprint_prefix }) {
        Err(h) => halt(h),
        Ok(r) => {
            data(format!("retired {} at {}", r.fingerprint, r.account));
            0
        }
    }
}
