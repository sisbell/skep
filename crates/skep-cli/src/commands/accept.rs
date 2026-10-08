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

use super::{data, host_name_and_date, require_terminal, store_of, BoxDefault, Door, Stop};
use crate::args::{CommandLine, Usage};
use crate::terminal::Terminal;

pub fn accept(c: &CommandLine) -> Result<(), Stop> {
    let store = store_of(c)?;
    // `--board` judged before anything: an origin given badly is a usage
    // refusal, never a board asked for again nor one dropped.
    let given_origin = c.origin_given()?;
    // `--reprint`: the record from the artifacts' public members — not a
    // person door.
    if c.switch("--reprint") {
        let key_file = c.key_file()?;
        let anchors: Vec<PathBuf> = c.values("--anchor").iter().map(PathBuf::from).collect();
        data(accept_walk::reprint(&store, key_file.as_deref(), &anchors, given_origin.as_ref())?)?;
        return Ok(());
    }
    require_terminal(Door { form: "accept", moments: "the name boxes and the backup moment, or on the decline arm its typed confirmation" })?;
    let mut person = Terminal;
    // `--board` and `--account` REQUIRED: a run missing either ASKS and
    // generates nothing (AUTH RES-162).
    let board = match given_origin {
        Some(o) => Board::new(o, PlainHttp::new()),
        None => {
            let Ok(text) = person.ask(Public(Question { text: "the board the account is on (a canonical origin, from the giver): ".into() })) else {
                return Err(Halt::face("no board was named", "the beat asks and generates nothing", "re-run with --board").into());
            };
            let origin = text.trim().parse::<skep_client::Origin>().map_err(|e| Usage(format!("--board: '{}' is {e}", text.trim())))?;
            Board::new(origin, PlainHttp::new())
        }
    };
    let account = match c.value("--account") {
        Some(a) => a.to_owned(),
        None => match person.ask(Public(Question { text: "the address the giver handed you (--account): ".into() })) {
            Ok(a) if !a.trim().is_empty() => a.trim().to_string(),
            _ => {
                return Err(Halt::face(
                    "no address was named",
                    "AUTH RES-162: the beat holds the address before the keys are made, and generates nothing without it",
                    "ask the giver for the address and re-run with --account",
                )
                .into())
            }
        },
    };
    let BoxDefault { host_name, date } = host_name_and_date();
    let opts = AcceptOptions {
        account,
        label: c.value("--label").map(str::to_owned),
        anchor_out: c.values("--anchor-out").iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        no_anchors: c.switch("--no-anchors"),
        hosted: None,
        host_name,
        date,
    };
    let accepted = accept_walk::accept(&board, &store, &mut person, &opts)?;
    // The record FIRST (DATA for the giver), then the device key's
    // fingerprint.
    data(accepted.record)?;
    data(accepted.device.to_hex())?;
    Ok(())
}
