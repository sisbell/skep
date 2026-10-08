//! `skep claim` (`client.md` §2.2): the notebook walk, a person door, or
//! with `--hosted` the dark claim of a hosted customer's payload (§4.5),
//! which takes no store, no person and generates nothing.

use std::path::PathBuf;

use skep_client::ceremony::claim::{self as claim_walk, ClaimOutcome, HostedOutcome, NotebookOptions};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::sheet::Facts;

use super::{board_of, data, host_name_and_date, print_facts, read_payload, require_terminal, store_of, talk, BoxDefault, Door, Stop};
use crate::args::CommandLine;
use crate::terminal::Terminal;

pub fn claim(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let principal = c.principal()?;
    if let Some(payload_arg) = c.value("--hosted") {
        // THE HOSTED ARM (§4.5): no --dir, no person, nothing generated.
        // `--principal` is the new account's id, 1 where omitted — §2.2's
        // recommended default, §9 item 9's ruling — as at the notebook arm.
        let payload = read_payload(payload_arg)?;
        match claim_walk::hosted(&board, &payload, principal.unwrap_or(1))? {
            HostedOutcome::AlreadyClaimed { claimant } => data(format!("claimed by {claimant}"))?,
            HostedOutcome::Claimed(reply) => {
                for l in &reply.log {
                    talk(l);
                }
                // THE REPLY, DATA on stdout (§4.5 H6): the claimant, the
                // three facts, the two acts and the setup act's one
                // sentence. The reply's further strings — the anchorless
                // sentence among them — have one carrier, the deployment
                // template's "Your board is live" message (cs6-S2); the
                // operator's log above keeps the anchorless note.
                data(format!("claimant {}", reply.claimant))?;
                print_facts(&reply.facts)?;
                data(format!(
                    "first act: from the device that generated the payload run `skep verify --board {} --principal {} --payload <the record it printed>` \
                     (or `--anchor <a> --anchor <b>`): the genesis record compared entry for entry, fingerprint and anchor flag, against what that \
                     device composed — it confirms the keys on the board, and it cannot tell you the board will open a session for you",
                    reply.facts.origin, reply.facts.principal
                ))?;
                data("second act: in your first signed session the setup act runs — `skep claim --board <origin> --dir <store>` from that device performs it: creating your account also creates a space for your agents beneath it, and its home")?;
            }
        }
        return Ok(());
    }
    // THE NOTEBOOK ARM: a person door, the store's setting judged ahead of
    // it as every usage refusal is.
    let store = store_of(c)?;
    require_terminal(Door { form: "claim", moments: "the name boxes and the backup moment" })?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let BoxDefault { host_name, date } = host_name_and_date();
    let opts = NotebookOptions {
        principal,
        display_name: c.value("--name").map(str::to_owned),
        anchor_out: c.values("--anchor-out").iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        host_name,
        date,
    };
    match claim_walk::notebook(&board, &store, &mut Terminal, &opts)? {
        ClaimOutcome::Stranger { claimant } => {
            data(format!("claimed by {claimant}; no key in this store is bound to it — `skep verify` tells you whether one is enrolled"))?;
        }
        ClaimOutcome::Ours(done) => {
            for w in &done.warnings {
                talk(w);
            }
            talk(format!("this board is yours — account {}, principal {}, key {}", done.account, done.principal, done.fingerprint));
            print_facts(&Facts { account: done.account.clone(), principal: done.principal, origin: board.dialed().clone() })?;
            if let Some(space) = &done.agent_space {
                data(format!("agent space {space}"))?;
            }
        }
    }
    Ok(())
}
