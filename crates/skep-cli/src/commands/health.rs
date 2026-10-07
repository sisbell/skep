//! `skep health` (`client.md` §2.2): `GET /health`'s body verbatim on
//! stdout, and on stderr the mode derived from its pair (AUTH-5.86).

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
    talk(format!("mode {} (claimant {}, local_trust {}) — derived from the pair, no mode field (AUTH-5.86)", mode.name(), health.claimant().unwrap_or("null"), health.local_trust()));
    talk(format!("bare arm (origins): [{}]", health.origins().join(", ")));
    talk(format!("signed arm (signed_origins): [{}]", health.signed_origins().join(", ")));
    Ok(())
}
