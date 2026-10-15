//! `skep` — the command over `skep-client` (`client.md` §1.2, §2): flag
//! parsing in the daemon's style (a flag beats its environment variable),
//! one file per command, a `Person` over the terminal, stdout DATA and
//! stderr TALK (§2.4), §2.3's exit codes. Every ceremony is a library walk
//! with the terminal as its `Person`; `bind` and `keygen` sequence the
//! library's compositions themselves.
//!
//! THE FOURTEEN COMMANDS: `keygen`, `claim`, `session`, `fingerprint`,
//! `verify`, `health`, `bind` — the ceremonies over 5.1a's seams:
//! `enroll`, `recover`, `retire`, `rotate`, `handoff`, `accept` — and
//! `merge`, the editor's act on a daughter over `skep_client::merge` (the
//! merge record's §6), the one command that touches content.
//!
//! The modules are declared in dependency order, each naming only those
//! above it (`tests/it/tidy.rs`); `ARCHITECTURE.md` §The command draws how
//! they fit. The crate's second binary, `skep-dev` (`src/dev/main.rs`),
//! declares `args`, `terminal` and `shared` from the same files.

#![forbid(unsafe_code)]

// The fourteen `Command`s and the grammar — each command's flags and
// switches and the rules its forms hold them to, one row per command —
// beside `HELP`, and the settings, each flag beating its environment
// variable; and, in its `dev` module, the dev binary's grammar over the
// same machinery.
mod args;
// The `Person` over the terminal: `answer`, the one reader every prompt
// goes through, `talk`, the one writer of a line on stderr, rendering it
// inert, the sheet's box, and the controlling-terminal check the person
// doors make.
mod terminal;
// What both binaries share: the stops and §2.3's exit codes (`Stop`,
// `finish`), DATA's two writers, and the plumbing from the flags to a
// board, a store, a principal and a key.
mod shared;
// The fourteen commands, one file each beneath it, and what they share
// among themselves alone: the person doors' check, the payload's read, the
// anchor boxes' default, the three facts' spelling, the whole-set compare.
mod commands;

use std::process::exit;

use args::{Command, Parsed};

fn main() {
    let line = match args::parse(std::env::args_os().skip(1)) {
        Ok(Parsed::Help) => exit(commands::finish(commands::help())),
        Ok(Parsed::Version(line)) => exit(commands::finish(shared::data(line).map_err(Into::into))),
        Ok(Parsed::CommandLine(line)) => line,
        Err(u) => exit(commands::finish(Err(u.into()))),
    };
    let outcome = match line.command {
        Command::Keygen => commands::keygen(&line),
        Command::Claim => commands::claim(&line),
        Command::Session => commands::session(&line),
        Command::Fingerprint => commands::fingerprint(&line),
        Command::Verify => commands::verify(&line),
        Command::Health => commands::health(&line),
        Command::Bind => commands::bind(&line),
        Command::Enroll => commands::enroll(&line),
        Command::Recover => commands::recover(&line),
        Command::Retire => commands::retire(&line),
        Command::Rotate => commands::rotate(&line),
        Command::Handoff => commands::handoff(&line),
        Command::Accept => commands::accept(&line),
        Command::Merge => commands::merge(&line),
    };
    exit(commands::finish(outcome));
}
