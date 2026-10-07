//! `skep claim` (`client.md` §2.2): the notebook walk, a person door, or
//! with `--hosted` the dark claim of a hosted customer's payload (§4.5),
//! which takes no store, no person and generates nothing.

use std::path::PathBuf;

use skep_client::ceremony::claim::{self, ClaimOutcome, HostedOutcome, NotebookOptions};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::sheet::Facts;

use super::{board_of, data, facts, halt, host_name_and_date, no_terminal, read_payload, store_of, talk, usage};
use crate::args::Command;
use crate::terminal::{has_terminal, Terminal};

pub fn claim(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let principal = match c.principal() {
        Ok(p) => p,
        Err(u) => return usage(u),
    };
    if let Some(payload_arg) = c.value("--hosted", None) {
        // THE HOSTED ARM (§4.5): no --dir, no person, nothing generated.
        let payload = match read_payload(&payload_arg) {
            Ok(p) => p,
            Err(h) => return halt(h),
        };
        return match claim::hosted(&board, &payload, principal.unwrap_or(1)) {
            Err(h) => halt(h),
            Ok(HostedOutcome::AlreadyClaimed { claimant }) => {
                data(format!("claimed by {claimant}"));
                0
            }
            Ok(HostedOutcome::Claimed(reply)) => {
                for l in &reply.log {
                    talk(l);
                }
                // THE REPLY, DATA on stdout (§4.5 H6): the claimant, the
                // three facts, the two acts and the setup act's one
                // sentence. The reply's further strings — the anchorless
                // sentence among them — have one carrier, the deployment
                // template's "Your board is live" message (cs6-S2); the
                // operator's log above keeps the anchorless note.
                data(format!("claimant {}", reply.claimant));
                facts(&reply.facts);
                data(format!(
                    "first act: from the device that generated the payload run `skep verify --board {} --principal {} --payload <the record it printed>` \
                     (or `--anchor <a> --anchor <b>`): the genesis record compared entry for entry, fingerprint and anchor flag, against what that \
                     device composed — it confirms the keys on the board, and it cannot tell you the board will open a session for you",
                    reply.facts.origin, reply.facts.principal
                ));
                data("second act: in your first signed session the setup act runs — `skep claim --board <origin> --dir <store>` from that device performs it: creating your account also creates a space for your agents beneath it, and its home");
                0
            }
        };
    }
    // THE NOTEBOOK ARM: a person door.
    if !has_terminal() {
        return no_terminal("claim");
    }
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let (host_name, date) = host_name_and_date();
    let opts = NotebookOptions {
        principal,
        display_name: c.value("--name", None),
        anchor_out: c.all("--anchor-out").into_iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        host_name,
        date,
    };
    let mut person = Terminal::new();
    match claim::notebook(&board, &store, &mut person, &opts) {
        Err(h) => halt(h),
        Ok(ClaimOutcome::Stranger { claimant }) => {
            data(format!("claimed by {claimant}; no key in this store is bound to it — `skep verify` tells you whether one is enrolled"));
            0
        }
        Ok(ClaimOutcome::Ours(done)) => {
            for w in &done.warnings {
                talk(w);
            }
            talk(format!("this board is yours — account {}, principal {}, key {}", done.account, done.principal, done.fingerprint));
            facts(&Facts { account: done.account.clone(), principal: done.principal, origin: board.dialed().clone() });
            if let Some(space) = &done.agent_space {
                data(format!("agent space {space}"));
            }
            0
        }
    }
}
