//! `skep handoff` (`client.md` §2.2): the giver's walk — `--account`
//! delegates the subdivision and prints its address (beat (a), no person
//! door); with `--payload` the recipient's record is compared and the
//! genesis written, a person door.

use std::path::PathBuf;

use skep_client::ceremony::handoff::{self as handoff_walk, HandoffOptions, HandoffOutcome};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::sheet::Facts;

use super::{board_of, facts, person_door, principal_or_bound, read_payload, store_of, talk, Door, Stop};
use crate::args::{CommandLine, Usage};
use crate::terminal::Terminal;

pub fn handoff(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let Some(account) = c.value("--account").map(str::to_owned) else { return Err(Usage("--account <address> is required".into()).into()) };
    let payload = c.value("--payload").map(read_payload).transpose()?;
    // The comparison and the confirmation make the `--payload` invocation a
    // person door; beat (a) alone is not one.
    if payload.is_some() {
        person_door(Door { form: "handoff --payload", moments: "the fingerprint comparison, the anchor import and the typed confirmation" })?;
    }
    let principal = principal_or_bound(given, &store, &board)?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let opts = HandoffOptions { principal, account, payload, anchor: c.value("--anchor").map(PathBuf::from) };
    match handoff_walk::handoff(&board, &store, &mut Terminal, &opts)? {
        HandoffOutcome::Delegated { account, principal, already } => {
            talk(if already { "beat (a) stands done: the address is printed again" } else { "beat (a) done: hand the address to the recipient; they run `skep accept --board <origin> --account <address>` and return their record for `skep handoff --payload`" });
            facts(&Facts { account, principal, origin: board.dialed().clone() })?;
        }
        HandoffOutcome::Seeded { facts: f, grade, reconciled, warnings } => {
            for w in &warnings {
                talk(w);
            }
            talk(format!("the genesis is written at the {grade} grade{}; return the three facts below to the recipient for `skep bind`", if reconciled { " (reconciled from the records)" } else { "" }));
            facts(&f)?;
        }
    }
    Ok(())
}
