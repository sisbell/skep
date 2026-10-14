//! `skep health` (`client.md` §2.2): `GET /health`'s body verbatim on
//! stdout, and on stderr the mode derived from its pair (AUTH-5.86), named
//! with the board that answered — the flag's, or `SKEP_BOARD`'s where no
//! flag names one — and, where the body answers `writes.halted`, the halt
//! beside it: a board refusing every write `poisoned` reads otherwise as a
//! healthy one, its one sign a member of the JSON on stdout.

use skep_client::derive::Mode;

use super::{board_of, data_verbatim, talk, Stop};
use crate::args::CommandLine;

pub fn health(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let health = board.health()?;
    // The body VERBATIM — one JSON document already; the CLI never adds a
    // `mode` field (AUTH-5.86's negative pin).
    data_verbatim(&health.raw)?;
    let mode = Mode::of(&health);
    talk(format!(
        "mode {} at {} (claimant {}, local_trust {}) — derived from the pair, no mode field (AUTH-5.86)",
        mode.name(),
        board.dialed(),
        health.claimant().unwrap_or("null"),
        health.local_trust()
    ));
    // THE WRITE PATH's HALT (wire.md §Rejection codes, `poisoned`): the
    // write path's or the kernel's, which `writes.halted` answers alike —
    // and the one act, a restart, that a full volume orders behind room
    // (RUNBOOK.md §1, steps 4 and 5).
    if health.body["writes"]["halted"].as_bool() == Some(true) {
        talk(format!(
            "writes HALTED at {}: every write is refused `poisoned` until the daemon restarts; reads serve — where the volume is full, \
             make room before the restart: a daemon restarted at a full volume does not open (RUNBOOK.md §1, steps 4 and 5)",
            board.dialed()
        ));
    }
    talk(format!("bare arm (origins): [{}]", health.origins().join(", ")));
    talk(format!("signed arm (signed_origins): [{}]", health.signed_origins().join(", ")));
    Ok(())
}
