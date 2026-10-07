//! `skep handoff` (`client.md` §2.2): the giver's walk — `--account`
//! delegates the subdivision and prints its address (beat (a), no person
//! door); with `--payload` the recipient's record is compared and the
//! genesis written, a person door.

use std::path::PathBuf;

use skep_client::ceremony::handoff::{self as handoff_walk, HandoffOptions, HandoffOutcome};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::sheet::Facts;

use super::{board_of, facts, halt, no_terminal, principal_or_bound, read_payload, store_of, talk, usage};
use crate::args::{Command, Usage};
use crate::terminal::{has_terminal, Terminal};

pub fn handoff(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let Some(account) = c.value("--account", None) else { return usage(Usage("--account <address> is required".into())) };
    let payload = match c.value("--payload", None) {
        Some(arg) => match read_payload(&arg) {
            Ok(p) => Some(p),
            Err(h) => return halt(h),
        },
        None => None,
    };
    // The comparison and the confirmation make the `--payload` invocation a
    // person door; beat (a) alone is not one.
    if payload.is_some() && !has_terminal() {
        return no_terminal("handoff --payload");
    }
    let principal = match principal_or_bound(c, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let mut person = Terminal::new();
    let opts = HandoffOptions { principal, account, payload, anchor: c.all("--anchor").first().map(PathBuf::from) };
    match handoff_walk::handoff(&board, &store, &mut person, &opts) {
        Err(h) => halt(h),
        Ok(HandoffOutcome::Delegated { account, principal, already }) => {
            talk(if already { "beat (a) stands done: the address is printed again" } else { "beat (a) done: hand the address to the recipient; they run `skep accept --board <origin> --account <address>` and return their record for `skep handoff --payload`" });
            facts(&Facts { account, principal, origin: board.dialed().clone() });
            0
        }
        Ok(HandoffOutcome::Seeded { facts: f, grade, reconciled, warnings }) => {
            for w in &warnings {
                talk(w);
            }
            talk(format!("the genesis is written at the {grade} grade{}; return the three facts below to the recipient for `skep bind`", if reconciled { " (reconciled from the records)" } else { "" }));
            facts(&f);
            0
        }
    }
}
