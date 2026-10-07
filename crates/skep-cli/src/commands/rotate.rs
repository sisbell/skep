//! `skep rotate` (`client.md` §2.2): this device's key replaced in one
//! gesture — the new key enrolled, the supersession trail written, the old
//! key retired; a person door.

use skep_client::ceremony::rotate::{self as rotate_walk, RotateOptions};
use skep_client::dial::plaintext_non_loopback_warning;

use super::{board_of, data, facts, halt, no_terminal, principal_or_bound, read_payload, store_of, talk, usage};
use crate::args::Command;
use crate::terminal::{has_terminal, Terminal};

pub fn rotate(c: &Command) -> i32 {
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
    if !has_terminal() {
        return no_terminal("rotate");
    }
    let principal = match principal_or_bound(given, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    let payload = match c.value("--payload", None) {
        Some(arg) => match read_payload(&arg) {
            Ok(p) => Some(p),
            Err(h) => return halt(h),
        },
        None => None,
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let mut person = Terminal::new();
    match rotate_walk::rotate(&board, &store, &mut person, &RotateOptions { principal, label: c.value("--label", None), payload }) {
        Err(h) => halt(h),
        Ok(r) => {
            for w in &r.warnings {
                talk(w);
            }
            if let Some(line) = &r.binding_line {
                talk(format!("binding: {line}"));
            }
            facts(&r.facts);
            data(format!("old {}", r.old));
            data(format!("new {}", r.new));
            data(format!("trail {}", r.trail));
            0
        }
    }
}
