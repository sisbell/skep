//! `skep enroll` (`client.md` §2.2): the hop's signed-in half.
//!
//! Another device's payload is enrolled from a session this command opens,
//! a person door; `--reply` re-derives the three facts with no write
//! (AUTH-5.32).

use skep_client::ceremony::enroll::{self as enroll_walk, EnrollOptions, Enrolled};
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
    // to say, and the landing's own line beside the three facts on stdout.
    for w in &enrolled.warnings {
        talk(w);
    }
    talk(enrolled_line(&enrolled));
    print_facts(&enrolled.facts)?;
    Ok(())
}

/// Returns the line the hop's landing says beside the three facts it prints.
///
/// The line goes on stderr. It names the account, and every key the act
/// enrolled there by its fingerprint — what joins this run to the
/// enrollment record the board now holds, and to the device whose payload
/// it carried, which `skep bind` then lands.
fn enrolled_line(enrolled: &Enrolled) -> String {
    let fingerprints: Vec<String> = enrolled.fingerprints.iter().map(ToString::to_string).collect();
    format!("enrolled at {}: {}", enrolled.facts.account, fingerprints.join(", "))
}

#[cfg(test)]
mod tests {
    use skep_client::sheet::Facts;
    use skep_client::Origin;
    use skep_identity::Fingerprint;

    use super::*;

    /// Checks that the landing names its account and every key enrolled.
    ///
    /// Each key the act enrolled there is named by its fingerprint, in the
    /// payload's order.
    #[test]
    fn the_landing_names_the_account_and_every_key_enrolled_there() {
        let (a, b) = ("ab".repeat(32), "cd".repeat(32));
        let enrolled = Enrolled {
            facts: Facts { account: "1.0.1".into(), principal: 1, origin: Origin::parse("http://127.0.0.1:8642").unwrap() },
            fingerprints: vec![Fingerprint::parse_hex(&a).unwrap(), Fingerprint::parse_hex(&b).unwrap()],
            reconciled: false,
            warnings: Vec::new(),
        };
        assert_eq!(enrolled_line(&enrolled), format!("enrolled at 1.0.1: {a}, {b}"));
    }
}
