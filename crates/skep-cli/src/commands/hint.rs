//! `skep hint`, the seventeenth command: a registry's root hint (REG-3.2).
//!
//! The root hint is the line a reader is given to find a registry: its
//! origins in the order they are tried, then `realm:<64 hex>`, the
//! fingerprint of the registry's genesis key set (REG-3.39), and on a
//! forked lineage `fork:<address>` beside it (REG-3.40). REG-3.2 makes that
//! line the reader's whole bootstrap and an overridable config value, never
//! a baked constant — a setting the reader can change — so this command
//! prints the line for whichever registry it is pointed at, and reads none
//! as a setting of its own.
//!
//! The board is read as a guest: no key, no session and no store, over the
//! dialer a registry mirror reads through (`resolve::mirror_dialer`), an
//! `https` board and an `http` one alike. The realm is the library's to
//! find (`resolve::root_hint`): the board's first claim and the key set its
//! claimant's genesis record enrolls — never the set the account holds now
//! — by the read a mirror's realm check makes and no other (REG-3.42), so
//! a mirror opened from the printed line passes that check. The feed is
//! paged no further than the claim.
//!
//! The origins are written in the order given: `--board` first — the flag,
//! or `SKEP_BOARD` where no flag names one — then each `--also`. A further
//! origin is taken on the operator's word and never dialed, which the talk
//! says. `--fork` adds the fork term and is never inferred: no read answers
//! a fork point.
//!
//! Stdout carries the one line, as the resolver's `RootHint` renders it
//! and reads it back, and nothing at all where the run stops. An origin or
//! a fork point that is not canonical is a usage refusal, exit 2, before
//! any socket opens; an unclaimed board, and a claim that names no genesis
//! record, are halts naming the board, exit 3; a read the board refused is
//! exit 1, and one it did not answer exit 4. `--dir`, `--key` and
//! `--principal` are not consulted. No person door: the command runs
//! without a terminal.

use std::sync::Arc;

use skep_address::Address;
use skep_client::resolve::{fork_point, mirror_dialer, root_hint};
use skep_client::Origin;

use super::{data, talk, Stop};
use crate::args::{CommandLine, Usage};

/// What the line names beside the board: the further origins and the fork.
struct Asked {
    /// Each `--also`, in the order given.
    also: Vec<Origin>,
    /// `--fork`, where given.
    fork: Option<Address>,
}

impl Asked {
    /// Reads the line's own flags whole, before any socket opens.
    ///
    /// # Errors
    ///
    /// In this order: the first `--also` that is no canonical origin, in
    /// `--board`'s own words; then a `--fork` that is no address a hint's
    /// line carries.
    fn of(c: &CommandLine) -> Result<Asked, Usage> {
        let also = c.values("--also").iter().map(|text| text.parse::<Origin>().map_err(|e| Usage(format!("--also: '{text}' is {e}")))).collect::<Result<Vec<Origin>, Usage>>()?;
        let fork = match c.value("--fork") {
            Some(text) => Some(fork_point(text).ok_or_else(|| Usage(format!("--fork: '{text}' is not an address (the wire's dotted spelling), so no fork point a hint's line carries")))?),
            None => None,
        };
        Ok(Asked { also, fork })
    }
}

pub fn hint(c: &CommandLine) -> Result<(), Stop> {
    let board = c.origin()?;
    let Asked { also, fork } = Asked::of(c)?;
    let (hint, genesis) = root_hint(Arc::new(mirror_dialer()), &board, &also, fork)?;
    // The one line, and nothing else on stdout: what a reader pastes.
    data(hint.to_string())?;
    talk(format!(
        "realm read at {board} as a guest: the fingerprint of the key set its claimant {} enrolled at its genesis, the claim at position {} (REG-3.39)",
        genesis.claimant, genesis.claim_at
    ));
    if !also.is_empty() {
        let also: Vec<&str> = also.iter().map(Origin::as_str).collect();
        talk(format!("written as given and not dialed: {} — nothing here shows that each serves this registry", also.join(", ")));
    }
    Ok(())
}
