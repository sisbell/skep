//! `skep accept` (`client.md` §2.2): the recipient's beat at a handed-off
//! address — the device key and the anchor pair made, the record printed
//! for the giver; a person door. `--reprint` re-composes the record from
//! the artifacts' public members and writes nothing. The beat opens no
//! session: the recipient's first signed session is `bind`'s, which owes the
//! plaintext warning where it runs (AUTH-4.53).

use std::path::PathBuf;

use skep_client::board::Board;
use skep_client::ceremony::accept::{self as accept_walk, AcceptOptions};
use skep_client::dial::PlainHttp;
use skep_client::halt::Halt;
use skep_client::person::{Person, Public, Question};

use super::{data, halt, host_name_and_date, no_terminal, store_of, usage};
use crate::args::{Command, Usage};
use crate::terminal::{has_terminal, Terminal};

pub fn accept(c: &Command) -> i32 {
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    // `--board` judged before anything: an origin given badly is a usage
    // refusal, never a board asked for again nor one dropped.
    let given_board = match c.board_given() {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    // `--reprint`: the record from the artifacts' public members — not a
    // person door.
    if c.switch("--reprint") {
        let anchors: Vec<PathBuf> = c.all("--anchor").into_iter().map(PathBuf::from).collect();
        return match accept_walk::reprint(&store, c.key().as_deref(), &anchors, given_board.as_ref()) {
            Err(h) => halt(h),
            Ok(record) => {
                data(record);
                0
            }
        };
    }
    if !has_terminal() {
        return no_terminal("accept");
    }
    let mut person = Terminal::new();
    // `--board` and `--account` REQUIRED: a run missing either ASKS and
    // generates nothing (AUTH RES-162).
    let board = match given_board {
        Some(o) => Board::new(o, PlainHttp::new()),
        None => {
            let Ok(text) = person.ask(Public(Question { text: "the board the account is on (a canonical origin, from the giver): ".into() })) else { return halt(Halt::face("no board was named", "the beat asks and generates nothing", "re-run with --board")) };
            match text.trim().parse::<skep_client::Origin>() {
                Ok(o) => Board::new(o, PlainHttp::new()),
                Err(e) => return usage(Usage(format!("--board: '{}' is {e}", text.trim()))),
            }
        }
    };
    let account = match c.value("--account", None) {
        Some(a) => a,
        None => match person.ask(Public(Question { text: "the address the giver handed you (--account): ".into() })) {
            Ok(a) if !a.trim().is_empty() => a.trim().to_string(),
            _ => return halt(Halt::face("no address was named", "AUTH RES-162: the beat holds the address before the keys are made, and generates nothing without it", "ask the giver for the address and re-run with --account")),
        },
    };
    let (host_name, date) = host_name_and_date();
    let opts = AcceptOptions {
        account,
        label: c.value("--label", None),
        anchor_out: c.all("--anchor-out").into_iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        no_anchors: c.switch("--no-anchors"),
        hosted: None,
        host_name,
        date,
    };
    match accept_walk::accept(&board, &store, &mut person, &opts) {
        Err(h) => halt(h),
        Ok(a) => {
            // The record FIRST (DATA for the giver), then the device key's
            // fingerprint.
            data(a.record);
            data(a.device.to_hex());
            0
        }
    }
}
