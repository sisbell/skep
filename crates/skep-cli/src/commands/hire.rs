//! `skep hire`, the twentieth command: an agent hired (AUTH-5.58).
//!
//! It is the owner's side of the hire ceremony, a library walk
//! (`skep_client::ceremony::hire`) with the terminal as its `Person`: the
//! agent's account made beneath the space for the owner's agents, its
//! first key record written by the owner — the agent's own working key,
//! read from `--payload` as `skep keygen --payload` printed it on the
//! agent's host, beside a custody pair this command makes for the owner to
//! keep — its home minted, and only then its principal printed. The
//! agent's own side is `skep keygen` on its host and no part of this
//! command; the agent's program takes the board, the principal this
//! command prints and its own key store as settings, and never runs
//! `skep bind`, which refuses at an agent's account.
//!
//! The owner's account and key are taken as the signing walks take them:
//! `--principal`, else the store's one binding at the board, and the
//! store's key for that board and principal — a key file named by `--key`
//! (or `SKEP_KEY`) is refused ahead of the door, never dropped for a key
//! the owner did not name. The arm is the custody pair by default, with
//! the backup moment's `--anchor-out` and `--paper`; `--anchorless`
//! declines it, its costs stated and typed at the choice (AUTH-5.62).
//! `--replaces <address>` names the agent's account a re-hire replaces: a
//! payload key that account already held is refused, and the label boxes
//! show its labels (AUTH-5.58 steps 3 and 4).
//!
//! A person door: the label boxes, the backup moment or the anchorless
//! choice's typed answer, and the fingerprint comparison are read at the
//! terminal. A usage refusal — no `--payload`, a `--replaces` that is no
//! address, a key file — is judged ahead of the door. A run that stopped
//! part way is resumed by running the command again: it reads what stands
//! and makes no second account.
//!
//! Stdout carries the agent's three facts — `account`, `principal`,
//! `origin`, the lines every command prints them by — and under them
//! `key <fingerprint>`, the working key the hire enrolled; stderr the
//! walk's statements and what was done. The principal is printed only once
//! the agent's home stands, or on the anchorless arm with the order the
//! agent's own first session owes (AUTH-5.61).

use std::path::PathBuf;

use skep_client::ceremony::hire::{self as hire_walk, HireOptions};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::sheet::render_inert;

use super::{board_of, clipped, data, host_name_and_date, principal_or_bound, print_facts, read_payload, require_no_key_file, require_terminal, store_of, talk, BoxDefault, Door, Stop};
use crate::args::{CommandLine, Usage};
use crate::terminal::Terminal;

pub fn hire(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    // The walk's usage refusals, ahead of the door.
    let Some(payload_arg) = c.value("--payload") else {
        return Err(Usage("--payload <file|-> is required: the agent's key record, as `skep keygen --payload` printed it on the agent's host".into()).into());
    };
    let replaces = c.value("--replaces").map(str::to_owned);
    if let Some(address) = replaces.as_deref().filter(|a| !skep_client::address::is_address_text(a)) {
        return Err(Usage(format!("--replaces: '{}' is not an address (the wire's dotted spelling)", clipped(address))).into());
    }
    require_no_key_file(c)?;
    let anchorless = c.switch("--anchorless");
    require_terminal(Door {
        form: "hire",
        moments: "the label boxes and the backup moment, or on the anchorless arm its typed confirmation, and the fingerprint comparison",
    })?;
    let principal = principal_or_bound(given, &store, &board)?;
    let payload = read_payload(payload_arg)?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let BoxDefault { host_name, date } = host_name_and_date();
    let opts = HireOptions {
        principal,
        payload,
        anchorless,
        replaces,
        anchor_out: c.values("--anchor-out").iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        host_name,
        date,
    };
    let hired = hire_walk::hire(&board, &store, &mut Terminal, &opts)?;
    for w in &hired.warnings {
        talk(w);
    }
    talk(format!(
        "{}: {} beneath your agent space {}, working key {} (label {}), {}",
        if hired.already { "this hire already stood, and nothing was written" } else { "hired" },
        hired.facts.account,
        hired.agent_space,
        hired.key,
        hired.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into()),
        if hired.anchorless { "ANCHORLESS — no custody pair" } else { "under a custody pair of two sheets" },
    ));
    // The agent's coordinates, only now: its principal is the one the
    // agent's program takes as `SKEP_PRINCIPAL` (AUTH-5.58 step 6).
    print_facts(&hired.facts)?;
    data(format!("key {}", hired.key))?;
    Ok(())
}
