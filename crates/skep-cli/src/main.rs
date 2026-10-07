//! `skep` — the command over `skep-client` (`client.md` §1.2, §2): flag
//! parsing in the daemon's style (a flag beats its environment variable),
//! one file per command, a `Person` over the terminal, stdout DATA and
//! stderr TALK (§2.4), §2.3's exit codes. Every ceremony is a library walk
//! with the terminal as its `Person`; `bind` and `keygen` sequence the
//! library's compositions themselves.
//!
//! THE THIRTEEN COMMANDS: `keygen`, `claim`, `session`, `fingerprint`,
//! `verify`, `health`, `bind` — and the ceremonies over 5.1a's seams:
//! `enroll`, `recover`, `retire`, `rotate`, `handoff`, `accept`.
//!
//! The modules are declared in dependency order, each naming only those
//! above it (`tests/it/tidy.rs`); `ARCHITECTURE.md` §The command draws how
//! they fit.

#![forbid(unsafe_code)]

// The grammar — each command's flags and switches, one row per command —
// beside `HELP`, and the settings, each flag beating its environment
// variable.
mod args;
// The `Person` over the terminal: `answer`, the one reader every prompt
// goes through, the sheet's box, and the controlling-terminal check the
// person doors make.
mod terminal;
// The thirteen commands, one file each beneath it, and what they share: the
// two streams, the stops and their exit codes, the three facts' spelling.
mod commands;

use std::process::exit;

use args::{Parsed, Usage, HELP};

fn main() {
    let parsed = match args::parse(std::env::args().skip(1)) {
        Ok(Parsed::Help) => {
            print!("{HELP}");
            exit(0);
        }
        Ok(Parsed::Command(c)) => c,
        Err(u) => exit(commands::exit_code(Err(u.into()))),
    };
    let outcome = match parsed.command.as_str() {
        "keygen" => commands::keygen(&parsed),
        "claim" => commands::claim(&parsed),
        "session" => commands::session(&parsed),
        "fingerprint" => commands::fingerprint(&parsed),
        "verify" => commands::verify(&parsed),
        "health" => commands::health(&parsed),
        "bind" => commands::bind(&parsed),
        "enroll" => commands::enroll(&parsed),
        "recover" => commands::recover(&parsed),
        "retire" => commands::retire(&parsed),
        "rotate" => commands::rotate(&parsed),
        "handoff" => commands::handoff(&parsed),
        "accept" => commands::accept(&parsed),
        other => Err(Usage(format!("unknown command `{other}`")).into()),
    };
    exit(commands::exit_code(outcome));
}
