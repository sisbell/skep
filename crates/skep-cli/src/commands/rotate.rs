//! `skep rotate` (`client.md` §2.2): this device's key replaced in one
//! gesture — the new key enrolled, the supersession trail written, the old
//! key retired; a person door.

use skep_client::ceremony::rotate::{self as rotate_walk, RotateOptions};
use skep_client::dial::plaintext_non_loopback_warning;

use super::{board_of, data, principal_or_bound, print_facts, read_payload, require_terminal, store_of, talk, Door, Stop};
use crate::args::CommandLine;
use crate::terminal::Terminal;

pub fn rotate(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    require_terminal(Door { form: "rotate", moments: "the device-name box and the preview's typed confirmation" })?;
    let principal = principal_or_bound(given, &store, &board)?;
    let payload = c.value("--payload").map(read_payload).transpose()?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let rotated = rotate_walk::rotate(&board, &store, &mut Terminal, &RotateOptions { principal, label: c.value("--label").map(str::to_owned), payload })?;
    for w in &rotated.warnings {
        talk(w);
    }
    if let Some(line) = &rotated.binding_line {
        talk(format!("binding: {line}"));
    }
    print_facts(&rotated.facts)?;
    data(format!("old {}", rotated.old))?;
    data(format!("new {}", rotated.new))?;
    data(format!("trail {}", rotated.trail))?;
    Ok(())
}
