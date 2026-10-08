//! `skep enroll` (`client.md` §2.2): the hop's signed-in half — another
//! device's payload enrolled from a session this command opens, a person
//! door; `--reply` re-derives the three facts with no write (AUTH-5.32).

use skep_client::ceremony::enroll::{self as enroll_walk, EnrollOptions};
use skep_client::dial::plaintext_non_loopback_warning;

use super::{board_of, principal_or_bound, print_facts, read_payload, require_no_key_file, require_terminal, store_of, talk, Door, Stop};
use crate::args::{CommandLine, Usage};
use crate::terminal::Terminal;

pub fn enroll(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    // `--reply`: the three facts re-derived, no write — not a person door,
    // and no key selected.
    if let Some(prefix) = c.value("--reply") {
        let principal = principal_or_bound(given, &store, &board)?;
        let reply = enroll_walk::reply(&board, principal, prefix)?;
        let fingerprint = reply.fingerprints.first().expect("`enroll::reply` answers the one key its prefix resolved");
        talk(format!("the reply, offered again (AUTH-5.32): {fingerprint} stands ENROLLED at {}", reply.facts.account));
        print_facts(&reply.facts)?;
        return Ok(());
    }
    // The walk's usage refusals, ahead of the door.
    let Some(payload_arg) = c.value("--payload") else { return Err(Usage("--payload <file|-> is required (or --reply <fp-prefix>)".into()).into()) };
    require_no_key_file(c)?;
    require_terminal(Door { form: "enroll", moments: "the fingerprint comparison and its confirmation" })?;
    let principal = principal_or_bound(given, &store, &board)?;
    let payload = read_payload(payload_arg)?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let enrolled = enroll_walk::enroll(&board, &store, &mut Terminal, &EnrollOptions { principal, payload })?;
    // The walk said what it found, a reconciliation among it (AUTH-5.17),
    // through the person; the warnings are what it leaves for the command
    // to say.
    for w in &enrolled.warnings {
        talk(w);
    }
    print_facts(&enrolled.facts)?;
    Ok(())
}
