//! `skep` — the command over `skep-client` (`client.md` §1.2, §2): flag
//! parsing in the daemon's style (a flag beats its environment variable),
//! one function per command, a `Person` over the terminal, stdout DATA and
//! stderr TALK (§2.4), §2.3's exit codes. It holds no ceremony logic: every
//! walk is a library call with the terminal as its `Person`.
//!
//! THE SEVEN COMMANDS of this build: `keygen`, `claim`, `session`,
//! `fingerprint`, `verify`, `health`, `bind`. The six the design names and
//! the next lane builds — `enroll`, `recover`, `retire`, `rotate`,
//! `handoff`, `accept` — answer "not in this build", exit 2, never
//! "unknown".

#![forbid(unsafe_code)]

mod args;
mod commands;
mod terminal;

use std::process::exit;

use args::{Parsed, Usage};

/// The help text: the seven, and the six named as not in this build.
pub fn usage() -> String {
    "\
usage: skep <command> [flags]

  keygen       generate one DEVICE key into the store; --payload prints its
               enrolment record; --anchors runs the door-side backup moment
  claim        claim a board: the notebook walk (a person door), or
               --hosted <payload|-> the dark claim for a hosted customer
  session      open a CONTENT-scoped signed session and print the token;
               --close - ends the token read from stdin (or SKEP_SESSION)
  fingerprint  list the store's keys (--select <fp-prefix|label>, --key
               <path>, --payload, --json)
  verify       the pre-check as a command: the origin arm, the key arm, and
               with --payload/--anchor the whole-set compare; exit 0/3
  health       GET /health verbatim on stdout; the derived mode on stderr
  bind         land the three facts of an enrol hop on this device and
               run the account's first signed session where one is owed

not in this build (the next lane): enroll, recover, retire, rotate,
handoff, accept — each exits 2 by name.

flags:
  --board <origin>      the board, a canonical origin (env SKEP_BOARD)
  --dir <path>          the key store (env SKEP_KEYSTORE; default ~/.skep)
  --key <path>          one key file, bypassing the store's lookup
                        (env SKEP_KEY); an anchor file is refused where the
                        key signs
  --principal <n>       the principal (env SKEP_PRINCIPAL)
  --label <text>        a byline (keygen)
  --json                one JSON document on stdout (verify, health,
                        fingerprint)
  keygen:   --payload  --anchors  --anchor-label <l> (twice)
            --anchor-out <dir> (once per anchor)  --paper
  claim:    --name <display name>  --anchor-out <dir> (once per anchor)
            --paper  --hosted <payload|->
  session:  --close -
  fingerprint: --select <fp-prefix|label>  --payload
  verify:   --payload <file|->  --anchor <path> (once per anchor)
  bind:     --account <address>  --payload <reply|->  --anchor <path>

exit codes: 0 done, 1 the board refused, 2 usage, 3 halt and surface,
4 transport. stdout carries data; stderr carries talk.
"
    .to_string()
}

fn main() {
    let parsed = match args::parse(std::env::args().skip(1)) {
        Ok(Parsed::Help) => {
            print!("{}", usage());
            exit(0);
        }
        Ok(Parsed::Command(c)) => c,
        Err(Usage(msg)) => {
            eprintln!("skep: {msg}\n\n{}", usage());
            exit(2);
        }
    };
    let code = match parsed.command.as_str() {
        "keygen" => commands::keygen(&parsed),
        "claim" => commands::claim(&parsed),
        "session" => commands::session(&parsed),
        "fingerprint" => commands::fingerprint(&parsed),
        "verify" => commands::verify(&parsed),
        "health" => commands::health(&parsed),
        "bind" => commands::bind(&parsed),
        other => {
            eprintln!("skep: `{other}` is not in this build — it is the next lane's (recovery, rotation, retirement, the enrol hop's signed-in half and the handoff door)");
            2
        }
    };
    exit(code);
}
