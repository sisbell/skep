//! `skep retire` (`client.md` §2.2): a device key retired from a full
//! session this command opens, after the preview and a typed answer — a
//! person door, and no flag stands for the answer (AUTH-5.46). The walk says
//! the next act where the retirement ended its own session (AUTH-5.28); the
//! command prints what was retired.

use skep_client::ceremony::retire::{self as retire_walk, RetireOptions};
use skep_client::dial::plaintext_non_loopback_warning;

use super::{board_of, data, person_door, principal_or_bound, store_of, talk, Stop};
use crate::args::{CommandLine, Usage};
use crate::terminal::Terminal;

pub fn retire(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let Some(fingerprint_prefix) = c.value("--fingerprint") else { return Err(Usage("--fingerprint <fp-prefix> is required".into()).into()) };
    person_door("retire", "the preview's typed confirmation")?;
    let principal = principal_or_bound(given, &store, &board)?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let r = retire_walk::retire(&board, &store, &mut Terminal, &RetireOptions { principal, fingerprint_prefix })?;
    data(format!("retired {} at {}", r.fingerprint, r.account));
    Ok(())
}
