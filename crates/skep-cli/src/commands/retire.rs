//! `skep retire` (`client.md` §2.2): a device key retired from a full
//! session this command opens, after the preview and a typed answer — a
//! person door, and no flag stands for the answer (AUTH-5.46).

use skep_client::ceremony::retire::{self as retire_walk, RetireEnd, RetireOptions};
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
    let Some(fingerprint_prefix) = c.value("--fingerprint", None) else { return usage(Usage("--fingerprint <fp-prefix> is required".into())) };
    if !has_terminal() {
        return no_terminal("retire");
    }
    let principal = match principal_or_bound(c, &store, &board) {
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
            if let RetireEnd::EndedByCommit { another_held } = r.end {
                talk(if another_held { "next: `skep session` with the key you still hold" } else { "next: `skep keygen`, then `skep recover` with a paper" });
            }
            0
        }
    }
}
