//! `skep recover` (`client.md` §2.2): the recovery ceremony, a person
//! door — one anchor imported, this store's device key enrolled, the lost
//! one retired; `--stolen` the thief copy, `--anchor-lost` the paper-loss
//! arm.

use std::path::PathBuf;

use skep_client::ceremony::recover::{self as recover_walk, RecoverOptions};
use skep_client::dial::plaintext_non_loopback_warning;

use super::{board_of, data, facts, halt, host_name_and_date, no_terminal, principal_or_bound, store_of, talk, usage};
use crate::args::Command;
use crate::terminal::{has_terminal, Terminal};

pub fn recover(c: &Command) -> i32 {
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
        return no_terminal("recover");
    }
    let principal = match principal_or_bound(given, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    // `--key`/`SKEP_KEY` is NOT consulted here: the new device key is the
    // STORE's, as at `claim` (§2.2).
    let (host_name, date) = host_name_and_date();
    let opts = RecoverOptions {
        principal,
        anchor: c.all("--anchor").first().map(PathBuf::from),
        lost: c.all("--lost"),
        stolen: c.switch("--stolen").then_some(true),
        anchor_lost: c.switch("--anchor-lost"),
        anchor_out: c.all("--anchor-out").into_iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        host_name,
        date,
    };
    let mut person = Terminal::new();
    match recover_walk::recover(&board, &store, &mut person, &opts) {
        Err(h) => halt(h),
        Ok(r) => {
            for w in &r.warnings {
                talk(w);
            }
            for l in &r.recovery_read {
                talk(format!("[recovery read] {l}"));
            }
            if let Some(line) = &r.binding_line {
                talk(format!("binding: {line}"));
            }
            facts(&r.facts);
            for fp in &r.enrolled {
                data(format!("enrolled {fp}"));
            }
            for fp in &r.retired {
                data(format!("retired {fp}"));
            }
            0
        }
    }
}
