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

// The thirteen `Command`s and the grammar — each command's flags and
// switches, one row per command — beside `HELP`, and the settings, each
// flag beating its environment variable.
mod args;
// The `Person` over the terminal: `answer`, the one reader every prompt
// goes through, `talk`, the one writer of a line on stderr, rendering it
// inert, the sheet's box, and the controlling-terminal check the person
// doors make.
mod terminal;
// The thirteen commands, one file each beneath it, and what they share:
// DATA's writers, the stops and their exit codes, the three facts'
// spelling.
mod commands;

use std::process::exit;

use args::{Command, Parsed};

fn main() {
    let parsed = match args::parse(std::env::args_os().skip(1)) {
        Ok(Parsed::Help) => exit(commands::exit_code(commands::help())),
        Ok(Parsed::Command(c)) => c,
        Err(u) => exit(commands::exit_code(Err(u.into()))),
    };
    let outcome = match parsed.command {
        Command::Keygen => commands::keygen(&parsed),
        Command::Claim => commands::claim(&parsed),
        Command::Session => commands::session(&parsed),
        Command::Fingerprint => commands::fingerprint(&parsed),
        Command::Verify => commands::verify(&parsed),
        Command::Health => commands::health(&parsed),
        Command::Bind => commands::bind(&parsed),
        Command::Enroll => commands::enroll(&parsed),
        Command::Recover => commands::recover(&parsed),
        Command::Retire => commands::retire(&parsed),
        Command::Rotate => commands::rotate(&parsed),
        Command::Handoff => commands::handoff(&parsed),
        Command::Accept => commands::accept(&parsed),
    };
    exit(commands::exit_code(outcome));
}
