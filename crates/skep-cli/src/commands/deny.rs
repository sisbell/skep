//! `skep deny`, the twenty-fourth command: a request denied under a clause
//! (REG-4.99).
//!
//! It is an officer's denial at a registry's door, the library's
//! (`skep_client::ceremony::console::deny`): `skep deny <request> --clause
//! <n>`, `<request>` the request's link address as `skep review` prints it
//! and `<n>` the position of a ground in the policy version standing,
//! counted from 1. The answer it writes on the request's thread is a
//! citation and nothing else — the version's address and the clause's
//! position — and says nothing of the applicant. It works at every
//! admission mode, and runs no check of the payload: a denial is the
//! registrar's judgment under a published clause.
//!
//! A person door: the officer is told the clause's words and that the
//! answer is permanent and public, and types the first 8 hex of the
//! request's device-key fingerprint. Everything a read decides is refused
//! before the write: a door with no policy has no ground to cite; a clause
//! past the version's grounds names none; an address that names no request
//! on this door's queue; a request already answered, or one whose approval
//! is begun. Stdout carries `denied <request>`, then `policy`, `clause` and
//! `answer` lines; stderr what was done.
//!
//! The principal is the one the board seats at its claimant where
//! `--principal` is omitted. A line with no request or no `--clause`, a
//! request that is no address, or a clause that is no position from 1, is a
//! usage refusal, exit 2, before any socket opens.

use std::sync::Arc;

use skep_client::ceremony::console::{self, Console, Hand};
use skep_client::dial::{plaintext_non_loopback_warning, Dialer};
use skep_client::resolve::mirror_dialer;
use skep_client::store::{KeySelector, KeyStore, Purpose};

use super::{board_of, clipped, data, key_named, registrar_principal, require_terminal, select_key, store_of, talk, Door, Stop};
use crate::args::{CommandLine, Usage};
use crate::terminal::Terminal;

pub fn deny(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    // The line's own judgment, ahead of the door and of any socket.
    let Some(request) = c.operand() else {
        return Err(Usage("a request is required: `skep deny <request> --clause <n>`, the request's link address as `skep review` prints it".into()).into());
    };
    if !skep_client::address::is_address_text(request) {
        return Err(Usage(format!("<request>: '{}' is not an address — a request is named by its link address, as `skep review` prints it", clipped(request))).into());
    }
    let Some(clause) = c.value("--clause") else {
        return Err(Usage("--clause <n> is required: the position of the ground the denial cites, in the policy standing, counted from 1".into()).into());
    };
    let Some(clause) = clause.parse::<u64>().ok().filter(|n| *n >= 1 && clause.bytes().all(|b| b.is_ascii_digit())) else {
        return Err(Usage(format!("--clause: '{}' is not a clause's position (a whole number, counted from 1)", clipped(clause))).into());
    };
    require_terminal(Door { form: "deny", moments: "the clause's statement and its typed confirmation" })?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let principal = registrar_principal(&board, given)?;
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Sign)?;
    let signer = store.signer(&KeySelector::Path(&key.path))?;
    let dialer: Arc<dyn Dialer> = Arc::new(mirror_dialer());
    let console = Console { board: &board, store: &store, signer: &*signer, principal, hand: Hand::Officer, dialer };
    talk(format!("acting as principal {principal}, the registrar's, with key {}", key_named(&key)));
    let denial = console::deny(&console, &mut Terminal, request, clause)?;
    talk(format!("the request {} is denied: the answer {} cites clause {} of {} and nothing else", denial.request, denial.answer, denial.clause, denial.policy));
    data(format!("denied {}", denial.request))?;
    data(format!("policy {}", denial.policy))?;
    data(format!("clause {}", denial.clause))?;
    data(format!("answer {}", denial.answer))?;
    Ok(())
}
