//! `skep-dev`, the dev binary beside `skep`, over the same plumbing.
//!
//! It has two verbs. `seed` dials a running board the person started per
//! `RUNBOOK.md` §3 and claimed with `skep claim`, opens one content-scoped
//! signed session under the person's key, and fills the board from a git
//! checkout of prose at a pinned commit — editions, citation links, second
//! versions, drafts with one windowed, a keyless second account — one JSON
//! object on stdout, a manifest beside the key store for a second run and
//! a resume (which makes again the one write a stopped run had in flight).
//! `serve` is the dev provider: the shell's core (`skep-shell`) served to a
//! page in a browser over loopback HTTP and server-sent events, one page
//! origin admitted under a per-run secret, the session bare as the
//! claimant, which reads alone, or signed with a dev key, which writes too,
//! and — behind the `dev-hooks` feature no shipped build enables — the
//! daemon run in-process with its test hooks so its fault states are forced
//! live. The fifteen commands of `skep` stand: this is no sixteenth, and the
//! sidecar image, built `--bin skep`, holds none of it.
//!
//! The root declares `args`, `terminal` and `shared` from the `skep` root's
//! own files, so the settings (`--board`, `--dir`, `--key`, `--principal`
//! and their variables, `SKEP_SEARCH_CORPUS` beside them), a flag beating
//! its variable, the two streams and the stops have one spelling for both
//! programs; the lint allowance on each says this root reads a part. Its
//! own modules follow in dependency order, each naming only those above it
//! (`tests/it/tidy.rs`), and only `main` ends the process, with `finish`'s
//! rendering of the verb's answer (§2.3).
//!
//! In test mode this root compiles to nothing: the manifest's `[[bin]]`
//! carries `test = false`, so no unit test runs here — the shared modules'
//! suites run once, under `skep`, and this binary's own claims are its
//! integration fence (`tests/it/dev.rs` and `tests/it/serve.rs`) — while
//! `cargo check --all-targets` still checks the target in test mode, where
//! a `#[path]`-declared module's own `#[cfg(test)] mod tests;` would
//! resolve against this directory and name no file. The one `cfg` below is
//! that build's.

#![cfg(not(test))]
#![forbid(unsafe_code)]

// The settings and the grammars — the `skep` command's and, in its `dev`
// module, this binary's: `seed`'s and `serve`'s flags, each setting read
// through the one place a flag beats its variable.
#[path = "../args.rs"]
#[allow(dead_code)]
mod args;
// `talk`, the one writer of a line on stderr, rendering it inert; the
// terminal's prompts and the `Person` it holds, which this binary never
// reaches — it asks nothing.
#[path = "../terminal.rs"]
#[allow(dead_code)]
mod terminal;
// What both binaries share: the stops and §2.3's exit codes (`Stop`,
// `finish`), data's two writers, and the plumbing from the flags to a
// board, a store, a principal and a key.
#[path = "../shared.rs"]
#[allow(dead_code)]
mod shared;
// The manifest beside the key store: what a seed landed, by the envelope
// id of each write, appended after its ack — so a second run adds nothing
// and a killed run resumes, making again the write it had in flight.
mod manifest;
// The frames over the claimant's one content-scoped signed session: the
// staging draft's mint, the chunked per-byte insert, the attested edition
// mint, the shot naming the draft, the attested link with its V-spec
// from-end, the reads, and the retry of the three transient refusals.
mod board;
// The seed: the inputs and the checks before any write, the cut, the
// shapes in order, the manifest's writes, the one JSON object.
mod seed;
// The dev provider: the loopback listener and the HTTP/1.1 subset it
// speaks, the admission of the one page origin under the per-run secret,
// the bridge's routes over the shell's core, the event stream, the script
// seam, and the daemon's two modes — a running board dialed, or under
// `dev-hooks` the daemon in-process with its fault doors.
mod serve;

use std::process::exit;

use args::dev::DevCommand;
use args::Parsed;
use shared::Program;

/// This program: its name, which a stop's block opens with, and its help.
const PROGRAM: Program = Program { name: "skep-dev", help: args::dev::HELP };

fn main() {
    let line = match args::dev::parse(std::env::args_os().skip(1)) {
        Ok(Parsed::Help) => exit(shared::finish(PROGRAM, shared::help(PROGRAM))),
        Ok(Parsed::Version(line)) => {
            exit(shared::finish(PROGRAM, shared::data(line).map_err(Into::into)))
        }
        Ok(Parsed::CommandLine(line)) => line,
        Err(u) => exit(shared::finish(PROGRAM, Err(u.into()))),
    };
    let outcome = match line.command {
        DevCommand::Seed => seed::seed(&line),
        DevCommand::Serve => serve::serve(&line),
    };
    exit(shared::finish(PROGRAM, outcome));
}
