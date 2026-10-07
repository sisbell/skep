//! Flag parsing in the daemon's style (`skepd/src/main.rs`'s `parse_args`,
//! `from_env`): every setting is seeded from its environment variable, so a
//! flag always wins over a variable and the precedence is stated once; a
//! missing value, an unknown flag and a bad value are usage refusals
//! (§2.3's exit 2 — the flag's SHAPE alone). A setting's reader answers the
//! refusal and the absence apart — `principal` and `board_given` answer
//! `Ok(None)` for a setting given nowhere and `Err` for one given badly —
//! so no command reads a refused value as an absent one. The environment
//! names are §9 item 21's: `SKEP_BOARD`, `SKEP_KEYSTORE`, `SKEP_KEY`,
//! `SKEP_PRINCIPAL`, `SKEP_SESSION` — read here and nowhere else in the
//! crate, `SKEP_SESSION` by `session_env` alone, the one setting no flag
//! carries (`tests/it/tidy.rs`). The vocabulary — the commands, the valued
//! flags, the switches — is spelled once, beside `HELP`, the text that
//! documents it.

use std::collections::HashMap;
use std::path::PathBuf;

use skep_client::Origin;

/// A usage refusal.
#[derive(Debug)]
pub struct Usage(pub String);

/// The parse's answer.
pub enum Parsed {
    Help,
    Command(Command),
}

/// One command line: the command, its flags with their values (a flag given
/// several times keeps every value, in order), and its switches.
#[derive(Debug, Default)]
pub struct Command {
    pub command: String,
    values: HashMap<String, Vec<String>>,
    switches: Vec<String>,
}

/// THE THIRTEEN COMMANDS (`client.md` §2.1's IN set).
const COMMANDS: [&str; 13] = [
    "keygen", "claim", "session", "fingerprint", "verify", "health", "bind", "enroll", "recover", "retire", "rotate", "handoff", "accept",
];

/// The flags that take a value; `--anchor`, `--anchor-out`, `--anchor-label`
/// and `--lost` are REPEATABLE (every value kept, in order).
const VALUED: [&str; 17] = [
    "--board", "--dir", "--key", "--principal", "--label", "--anchor-label", "--anchor-out", "--name", "--hosted", "--close", "--select",
    "--payload", "--anchor", "--account", "--lost", "--fingerprint", "--reply",
];

/// The switches. `--yes` does not exist: a retirement's confirmation is a
/// typed answer at the terminal, never a flag (AUTH-5.46).
const SWITCHES: [&str; 7] = ["--json", "--anchors", "--paper", "--stolen", "--anchor-lost", "--no-anchors", "--reprint"];

/// `--payload` takes a value at `claim --hosted`'s sibling, `verify` and
/// `bind`, and is a SWITCH at `keygen` and `fingerprint`.
fn payload_is_switch(command: &str) -> bool {
    matches!(command, "keygen" | "fingerprint")
}

/// The help text: the thirteen commands, each as the design writes it, and
/// the flags `parse` reads — the vocabulary above, documented beside it.
pub const HELP: &str = "\
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
  bind         land the three facts of an enroll hop or a handoff here;
               a genesis another hand wrote is compared whole (--anchor,
               or asked), then the account's first signed session runs
               where one is owed
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
";

pub fn parse(argv: impl Iterator<Item = String>) -> Result<Parsed, Usage> {
    let mut it = argv.peekable();
    let Some(first) = it.next() else { return Err(Usage("a command is required".into())) };
    if first == "--help" || first == "-h" || first == "help" {
        return Ok(Parsed::Help);
    }
    if !COMMANDS.contains(&first.as_str()) {
        return Err(Usage(format!("unknown command `{first}`")));
    }
    let mut cmd = Command { command: first.clone(), ..Command::default() };
    while let Some(arg) = it.next() {
        if arg == "--help" || arg == "-h" {
            return Ok(Parsed::Help);
        }
        if SWITCHES.contains(&arg.as_str()) || (arg == "--payload" && payload_is_switch(&first)) {
            cmd.switches.push(arg);
            continue;
        }
        if VALUED.contains(&arg.as_str()) {
            let Some(value) = it.next() else { return Err(Usage(format!("{arg} needs a value"))) };
            cmd.values.entry(arg).or_default().push(value);
            continue;
        }
        return Err(Usage(format!("unknown argument `{arg}`")));
    }
    Ok(Parsed::Command(cmd))
}

impl Command {
    /// Whether a switch was given.
    pub fn switch(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    /// Every value a flag was given, in order.
    pub fn all(&self, name: &str) -> Vec<String> {
        self.values.get(name).cloned().unwrap_or_default()
    }

    /// The flag's LAST value, else its variable — a flag beats its variable
    /// (the daemon's `from_env` precedence, stated once).
    pub fn value(&self, name: &str, env: Option<&str>) -> Option<String> {
        if let Some(v) = self.values.get(name).and_then(|v| v.last()) {
            return Some(v.clone());
        }
        env.and_then(|var| std::env::var(var).ok()).filter(|v| !v.is_empty())
    }

    /// `--board` / `SKEP_BOARD` where either is set, a canonical origin —
    /// anything else is exit 2 before any socket opens (§7; the daemon's
    /// `NotCanonical` phrase); `None` where neither is set.
    pub fn board_given(&self) -> Result<Option<Origin>, Usage> {
        let Some(text) = self.value("--board", Some("SKEP_BOARD")) else { return Ok(None) };
        text.parse::<Origin>().map(Some).map_err(|e| Usage(format!("--board: '{text}' is {e}")))
    }

    /// `--board` / `SKEP_BOARD`, required: [`Command::board_given`], its
    /// absence a usage refusal of its own.
    pub fn board(&self) -> Result<Origin, Usage> {
        self.board_given()?.ok_or_else(|| Usage("--board (or SKEP_BOARD) is required".into()))
    }

    /// `--dir` / `SKEP_KEYSTORE`, else `~/.skep` (§6; §9 item 10).
    pub fn dir(&self) -> Result<PathBuf, Usage> {
        match self.value("--dir", Some("SKEP_KEYSTORE")) {
            Some(d) => Ok(PathBuf::from(d)),
            None => skep_client::store::default_store_dir().ok_or_else(|| Usage("--dir (or SKEP_KEYSTORE) is required: no home directory to default ~/.skep from".into())),
        }
    }

    /// `--key` / `SKEP_KEY`, a PATH to a key file (AUTH-5.67 (1)).
    pub fn key(&self) -> Option<PathBuf> {
        self.value("--key", Some("SKEP_KEY")).map(PathBuf::from)
    }

    /// `--principal` / `SKEP_PRINCIPAL`.
    pub fn principal(&self) -> Result<Option<u64>, Usage> {
        match self.value("--principal", Some("SKEP_PRINCIPAL")) {
            None => Ok(None),
            Some(v) => v.parse::<u64>().map(Some).map_err(|_| Usage(format!("--principal: '{v}' is not a principal (a non-negative integer)"))),
        }
    }
}

/// `SKEP_SESSION`, the token `session --close -` ends in place of stdin —
/// the one setting no flag carries: a token is never an argv value (§2.2;
/// AUTH-4.53; §9 item 29).
pub fn session_env() -> Option<String> {
    std::env::var("SKEP_SESSION").ok().filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> impl Iterator<Item = String> {
        a.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
    }

    #[test]
    fn flags_parse_and_refusals_are_named() {
        let Parsed::Command(c) = parse(argv(&["claim", "--board", "http://127.0.0.1:8642", "--anchor-out", "/a", "--anchor-out", "/b", "--paper"])).unwrap() else { panic!() };
        assert_eq!(c.command, "claim");
        assert_eq!(c.all("--anchor-out"), ["/a", "/b"]);
        assert!(c.switch("--paper"));
        assert_eq!(c.board().unwrap().as_str(), "http://127.0.0.1:8642");
        assert!(parse(argv(&["frobnicate"])).is_err(), "an unknown command is refused");
        assert!(parse(argv(&["session", "--board"])).is_err(), "a flag without its value is refused");
        assert!(parse(argv(&["health", "--frob"])).is_err(), "an unknown flag is refused");
        assert!(matches!(parse(argv(&["--help"])).unwrap(), Parsed::Help));
        let Parsed::Command(c) = parse(argv(&["recover", "--lost", "ab", "--lost", "cd", "--stolen", "--anchor", "/a"])).unwrap() else { panic!() };
        assert_eq!(c.all("--lost"), ["ab", "cd"], "--lost is repeatable");
        assert!(c.switch("--stolen"));
        assert!(parse(argv(&["retire", "--yes"])).is_err(), "--yes does not exist: a typed answer, never a flag");
        let Parsed::Command(c) = parse(argv(&["keygen", "--payload"])).unwrap() else { panic!() };
        assert!(c.switch("--payload"), "a switch at keygen");
        let Parsed::Command(c) = parse(argv(&["verify", "--payload", "-", "--board", "HTTP://x", "--principal", "7x"])).unwrap() else { panic!() };
        assert_eq!(c.all("--payload"), ["-"], "a value at verify");
        assert!(c.board().is_err(), "a non-canonical board is a usage refusal");
        assert!(c.board_given().is_err(), "a board given badly is refused, never read as one not given");
        assert!(c.principal().is_err(), "a principal given badly is refused, never read as one not given");
        let Parsed::Command(c) = parse(argv(&["accept", "--board", "http://127.0.0.1:8642", "--principal", "7"])).unwrap() else { panic!() };
        assert_eq!(c.board_given().unwrap().map(|o| o.as_str().to_string()), Some("http://127.0.0.1:8642".to_string()));
        assert_eq!(c.principal().unwrap(), Some(7));
    }
}
