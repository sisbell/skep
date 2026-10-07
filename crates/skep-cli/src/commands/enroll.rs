//! `skep enroll` (`client.md` §2.2): the hop's signed-in half — another
//! device's payload enrolled from a session this command opens, a person
//! door; `--reply` re-derives the three facts with no write (AUTH-5.32).

use skep_client::ceremony::enroll::{self as enroll_walk, EnrollOptions};
use skep_client::dial::plaintext_non_loopback_warning;

use super::{board_of, facts, person_door, principal_or_bound, read_payload, store_of, talk, Stop};
use crate::args::{Command, Usage};
use crate::terminal::Terminal;

pub fn enroll(c: &Command) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let principal = principal_or_bound(given, &store, &board)?;
    // `--reply`: the three facts re-derived, no write — not a person door.
    if let Some(prefix) = c.value("--reply") {
        let e = enroll_walk::reply(&board, principal, &prefix)?;
        talk(format!("the reply, offered again (AUTH-5.32): {} stands ENROLLED at {}", e.fingerprints[0], e.facts.account));
        facts(&e.facts);
        return Ok(());
    }
    person_door("enroll")?;
    let Some(payload_arg) = c.value("--payload") else { return Err(Usage("--payload <file|-> is required (or --reply <fp-prefix>)".into()).into()) };
    let payload = read_payload(&payload_arg)?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let e = enroll_walk::enroll(&board, &store, &mut Terminal, &EnrollOptions { principal, payload })?;
    // The walk said what it found, a reconciliation among it (AUTH-5.17),
    // through the person; the warnings are what it leaves for the command
    // to say.
    for w in &e.warnings {
        talk(w);
    }
    facts(&e.facts);
    Ok(())
}
