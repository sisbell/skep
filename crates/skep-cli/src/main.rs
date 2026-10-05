//! `skep` — the command over `skep-client` (`client.md` §1.2, §2): flag
//! parsing in the daemon's style (a flag beats its environment variable),
//! one function per command, a `Person` over the terminal, stdout DATA and
//! stderr TALK (§2.4), §2.3's exit codes. It holds no ceremony logic: every
//! walk is a library call with the terminal as its `Person`.
//!
//! THE THIRTEEN COMMANDS: `keygen`, `claim`, `session`, `fingerprint`,
//! `verify`, `health`, `bind` — and the ceremonies over 5.1a's seams:
//! `enroll`, `recover`, `retire`, `rotate`, `handoff`, `accept`.

#![forbid(unsafe_code)]

mod args;
mod commands;
mod terminal;

use std::process::exit;

use args::{Parsed, Usage};

/// The help text: the thirteen commands, each as the design writes it.
pub fn usage() -> String {
    "\
usage: skep <command> [flags]

  keygen       generate one DEVICE key into the store; --payload prints its
               enrollment record; --anchors runs the door-side backup moment
  claim        claim a board: the notebook walk (a person door), or
               --hosted <payload|-> the dark claim for a hosted customer
  session      open a CONTENT-scoped signed session and print the token;
               --close - ends the token read from stdin (or SKEP_SESSION)
  fingerprint  list the store's keys (--select <fp-prefix|label>, --key
               <path>, --payload, --json)
  verify       the pre-check as a command: the origin arm, the key arm, and
               with --payload/--anchor the whole-set compare; exit 0/3
  health       GET /health verbatim on stdout; the derived mode on stderr
  bind         land the three facts of an enroll hop on this device and
               run the account's first signed session where one is owed
  enroll       the hop's signed-in half: enroll another device's payload
               from a full session this command opens (a person door);
               --reply <fp-prefix> re-prints the three facts, no write
  recover      the recovery ceremony (a person door): import one anchor,
               enroll this store's device key, retire the lost one;
               --stolen the thief copy; --anchor-lost the paper-loss arm
  retire       retire a device key from a full session this command opens,
               after the preview and a typed answer (a person door)
  rotate       replace this device's key in one gesture: enroll the new
               key, write the trail, retire the old (a person door)
  handoff      the giver's walk: --account delegates and prints the
               address; with --payload the genesis (a person door)
  accept       the recipient's beat at a handed-off address: the device
               key and the anchor pair, the record for the giver (a
               person door); --reprint re-composes the record, no write

flags:
  --board <origin>      the board, a canonical origin (env SKEP_BOARD)
  --dir <path>          the key store (env SKEP_KEYSTORE; default ~/.skep)
  --key <path>          one key file, bypassing the store's lookup
                        (env SKEP_KEY); an anchor file is refused where the
                        key signs; not consulted at claim and recover
  --principal <n>       the principal (env SKEP_PRINCIPAL); may be omitted
                        where the store holds one binding at the board
  --label <text>        a byline (keygen, rotate, accept)
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
  enroll:   --payload <file|->  [--reply <fp-prefix>]
  recover:  [--anchor <path>]  [--lost <fp-prefix>]...  [--stolen]
            [--anchor-lost [--anchor-out <dir>] [--paper]]
  retire:   --fingerprint <fp-prefix>
  rotate:   [--label <l>]  [--payload <file|->]
  handoff:  --account <address>  [--payload <file|->]  [--anchor <path>]
  accept:   --account <address>  [--label <l>]  [--anchor-out <dir>]
            [--paper]  [--no-anchors]  [--reprint [--anchor <path>]...]

exit codes: 0 done, 1 the board refused, 2 usage, 3 halt and surface,
4 transport. stdout carries data; stderr carries talk. No --yes exists:
a retirement's confirmation is typed at the terminal.
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
        "enroll" => commands::enroll(&parsed),
        "recover" => commands::recover(&parsed),
        "retire" => commands::retire(&parsed),
        "rotate" => commands::rotate(&parsed),
        "handoff" => commands::handoff(&parsed),
        "accept" => commands::accept(&parsed),
        other => {
            eprintln!("skep: unknown command `{other}`\n\n{}", usage());
            2
        }
    };
    exit(code);
}
