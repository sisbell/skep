//! `skep recover` (`client.md` §2.2): the recovery ceremony, a person
//! door — one anchor imported, this store's device key enrolled, the lost
//! one retired; `--stolen` the thief copy, `--anchor-lost` the paper-loss
//! arm.

use std::path::PathBuf;

use skep_client::ceremony::recover::{self as recover_walk, RecoverOptions};
use skep_client::dial::plaintext_non_loopback_warning;

use super::{board_of, data, host_name_and_date, principal_or_bound, print_facts, require_terminal, store_of, talk, BoxDefault, Door, Stop};
use crate::args::CommandLine;
use crate::terminal::Terminal;

pub fn recover(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    require_terminal(Door { form: "recover", moments: "the kept-or-placed answer, the typed hex and the confirmations" })?;
    let principal = principal_or_bound(given, &store, &board)?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    // `--key`/`SKEP_KEY` is NOT consulted here: the new device key is the
    // STORE's, as at `claim` (§2.2).
    let BoxDefault { host_name, date } = host_name_and_date();
    let opts = RecoverOptions {
        principal,
        anchor: c.value("--anchor").map(PathBuf::from),
        lost: c.values("--lost").to_vec(),
        stolen: c.switch("--stolen").then_some(true),
        anchor_lost: c.switch("--anchor-lost"),
        anchor_out: c.values("--anchor-out").iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        host_name,
        date,
    };
    let recovered = recover_walk::recover(&board, &store, &mut Terminal, &opts)?;
    for w in &recovered.warnings {
        talk(w);
    }
    for l in &recovered.recovery_read {
        talk(format!("[recovery read] {l}"));
    }
    if let Some(line) = &recovered.binding_line {
        talk(format!("binding: {line}"));
    }
    print_facts(&recovered.facts)?;
    for fp in &recovered.enrolled {
        data(format!("enrolled {fp}"))?;
    }
    for fp in &recovered.retired {
        data(format!("retired {fp}"))?;
    }
    Ok(())
}
