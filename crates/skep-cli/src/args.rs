//! Flag parsing in the daemon's style (`skepd/src/main.rs`'s `parse_args`,
//! `from_env`). A command line is judged against THE GRAMMAR, one row per
//! command beside `HELP`, the text that documents it: a flag in no row, a
//! flag of another command's, a missing value and a second value of a flag
//! that takes one are usage refusals (§2.3's exit 2 — the flag's SHAPE
//! alone). Every setting is read through `CommandLine::setting`, the one
//! place a flag beats its environment variable, and its reader — named for
//! what it answers, an origin, a store's directory, a key file's path, a
//! principal — answers the refusal and the absence apart: `Ok(None)` for a
//! setting given nowhere, `Err` for one given badly, a variable whose value
//! is not UTF-8 text among them, so no command reads a refused value as an
//! absent one. The environment names are §9 item 21's: `SKEP_BOARD`,
//! `SKEP_KEYSTORE`, `SKEP_KEY`, `SKEP_PRINCIPAL`, `SKEP_SESSION` — read here
//! and nowhere else in the crate, `SKEP_SESSION` by `session_env` alone, the
//! one setting no flag carries (`tests/it/tidy.rs`).

use std::collections::HashMap;
use std::env::{self, VarError};
use std::path::PathBuf;

use skep_client::Origin;

/// A usage refusal.
#[derive(Debug)]
pub struct Usage(pub String);

/// The parse's answer: the help, or a command with its line.
pub enum Parsed {
    Help,
    Command(CommandLine),
}

/// One command line: the command, one of §2.1's thirteen; its flags with
/// their values (a flag that repeats keeps every value, in order); and its
/// switches.
#[derive(Debug, Default)]
pub struct CommandLine {
    pub command: String,
    values: HashMap<String, Vec<String>>,
    switches: Vec<String>,
}

/// The flags every command takes — `client.md` §2.2's "All commands",
/// DECLARED globally there — each taking one value: the four settings and
/// `--label`, a byline and no setting. `--json`, the switch §2.2 declares
/// beside them, is every command's too.
const GLOBAL: [&str; 5] = ["--board", "--dir", "--key", "--principal", "--label"];

/// One command's flags beyond the [`GLOBAL`] ones.
struct Row {
    command: &'static str,
    /// The flags that take one value.
    once: &'static [&'static str],
    /// The flags that take a value and REPEAT, every value kept in order.
    repeated: &'static [&'static str],
    /// The switches beside `--json`.
    switches: &'static [&'static str],
}

/// THE GRAMMAR: the thirteen commands (`client.md` §2.1's IN set), each with
/// the flags §2.2 gives it and `HELP` documents. `--payload` takes a value
/// where it names a file or `-`, and is a SWITCH at `keygen` and
/// `fingerprint`, where it prints. `--yes` is in no row: a retirement's
/// confirmation is a typed answer at the terminal, never a flag (AUTH-5.46).
const GRAMMAR: [Row; 13] = [
    Row { command: "keygen", once: &[], repeated: &["--anchor-label", "--anchor-out"], switches: &["--payload", "--anchors", "--paper"] },
    Row { command: "claim", once: &["--name", "--hosted"], repeated: &["--anchor-out"], switches: &["--paper"] },
    Row { command: "session", once: &["--close"], repeated: &[], switches: &[] },
    Row { command: "fingerprint", once: &["--select"], repeated: &[], switches: &["--payload"] },
    Row { command: "verify", once: &["--payload"], repeated: &["--anchor"], switches: &[] },
    Row { command: "health", once: &[], repeated: &[], switches: &[] },
    Row { command: "bind", once: &["--account", "--payload"], repeated: &["--anchor"], switches: &[] },
    Row { command: "enroll", once: &["--payload", "--reply"], repeated: &[], switches: &[] },
    Row { command: "recover", once: &["--anchor"], repeated: &["--lost", "--anchor-out"], switches: &["--stolen", "--anchor-lost", "--paper"] },
    Row { command: "retire", once: &["--fingerprint"], repeated: &[], switches: &[] },
    Row { command: "rotate", once: &["--payload"], repeated: &[], switches: &[] },
    Row { command: "handoff", once: &["--account", "--payload", "--anchor"], repeated: &[], switches: &[] },
    Row { command: "accept", once: &["--account"], repeated: &["--anchor-out", "--anchor"], switches: &["--paper", "--no-anchors", "--reprint"] },
];

/// The help text: the thirteen commands, each as the design writes it, and
/// the flags each takes — the grammar above, documented beside it.
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
  bind         land the three facts of an enroll hop, a handoff or a
               hosted signup here; a genesis another hand wrote is
               compared whole (--anchor, or asked), then the account's
               first signed session runs where one is owed
  enroll       the hop's signed-in half: enroll another device's payload
               from a full session this command opens (a person door);
               --reply <fp-prefix> re-derives the three facts, no write
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

pub fn parse(mut argv: impl Iterator<Item = String>) -> Result<Parsed, Usage> {
    let Some(first) = argv.next() else { return Err(Usage("a command is required".into())) };
    if first == "--help" || first == "-h" || first == "help" {
        return Ok(Parsed::Help);
    }
    let Some(row) = GRAMMAR.iter().find(|r| r.command == first) else { return Err(Usage(format!("unknown command `{first}`"))) };
    let mut line = CommandLine { command: first, ..CommandLine::default() };
    while let Some(arg) = argv.next() {
        let flag = arg.as_str();
        if flag == "--help" || flag == "-h" {
            return Ok(Parsed::Help);
        }
        if flag == "--json" || row.switches.contains(&flag) {
            line.switches.push(arg);
            continue;
        }
        let repeats = row.repeated.contains(&flag);
        if repeats || row.once.contains(&flag) || GLOBAL.contains(&flag) {
            let Some(value) = argv.next() else { return Err(Usage(format!("{arg} needs a value"))) };
            if !repeats && line.values.contains_key(&arg) {
                return Err(Usage(format!("`{arg}` is given at most once at `{}`", row.command)));
            }
            line.values.entry(arg).or_default().push(value);
            continue;
        }
        if GRAMMAR.iter().any(|r| r.once.contains(&flag) || r.repeated.contains(&flag) || r.switches.contains(&flag)) {
            return Err(Usage(format!("`{arg}` is not a flag of `{}`", row.command)));
        }
        return Err(Usage(format!("unknown argument `{arg}`")));
    }
    Ok(Parsed::Command(line))
}

impl CommandLine {
    /// Whether a switch was given.
    pub fn switch(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    /// Every value a flag that repeats was given, in order.
    pub fn all(&self, name: &str) -> Vec<String> {
        self.values.get(name).cloned().unwrap_or_default()
    }

    /// The value a flag that takes one was given — the flag alone; a
    /// setting is read through its own reader below, which consults the
    /// variable.
    pub fn value(&self, name: &str) -> Option<String> {
        self.values.get(name).and_then(|v| v.first()).cloned()
    }

    /// A SETTING: the flag's value, else its variable's — a flag beats its
    /// variable (the daemon's `from_env` precedence, stated once). A
    /// variable set empty is unset; one whose value is not UTF-8 text is
    /// refused ([`env_text`]), never read as unset.
    fn setting(&self, name: &str, var: &str) -> Result<Option<String>, Usage> {
        match self.value(name) {
            Some(v) => Ok(Some(v)),
            None => env_text(var),
        }
    }

    /// `--board` / `SKEP_BOARD` where either is set: the board's origin, a
    /// canonical one — anything else is exit 2 before any socket opens (§7;
    /// the daemon's `NotCanonical` phrase); `None` where neither is set.
    pub fn origin_given(&self) -> Result<Option<Origin>, Usage> {
        let Some(text) = self.setting("--board", "SKEP_BOARD")? else { return Ok(None) };
        text.parse::<Origin>().map(Some).map_err(|e| Usage(format!("--board: '{text}' is {e}")))
    }

    /// `--board` / `SKEP_BOARD`, required: [`CommandLine::origin_given`],
    /// its absence a usage refusal of its own.
    pub fn origin(&self) -> Result<Origin, Usage> {
        self.origin_given()?.ok_or_else(|| Usage("--board (or SKEP_BOARD) is required".into()))
    }

    /// `--dir` / `SKEP_KEYSTORE`: the key store's directory, else `~/.skep`
    /// (§6; §9 item 10).
    pub fn store_dir(&self) -> Result<PathBuf, Usage> {
        match self.setting("--dir", "SKEP_KEYSTORE")? {
            Some(d) => Ok(PathBuf::from(d)),
            None => skep_client::store::default_store_dir().ok_or_else(|| Usage("--dir (or SKEP_KEYSTORE) is required: no home directory to default ~/.skep from".into())),
        }
    }

    /// `--key` / `SKEP_KEY`: the PATH of one key file (AUTH-5.67 (1)), never
    /// a fingerprint or a label (§2.2); `None` where neither is set.
    pub fn key_file(&self) -> Result<Option<PathBuf>, Usage> {
        Ok(self.setting("--key", "SKEP_KEY")?.map(PathBuf::from))
    }

    /// `--principal` / `SKEP_PRINCIPAL`.
    pub fn principal(&self) -> Result<Option<u64>, Usage> {
        match self.setting("--principal", "SKEP_PRINCIPAL")? {
            None => Ok(None),
            Some(v) => v.parse::<u64>().map(Some).map_err(|_| Usage(format!("--principal: '{v}' is not a principal (a non-negative integer)"))),
        }
    }
}

/// `SKEP_SESSION`, the token `session --close -` ends in place of stdin —
/// the one setting no flag carries: a token is never an argv value (§2.2;
/// AUTH-4.53; §9 item 29).
pub fn session_env() -> Result<Option<String>, Usage> {
    env_text("SKEP_SESSION")
}

/// A `SKEP_*` variable's text, `None` where it is unset or set empty; a
/// value that is not UTF-8 text is refused in the daemon's words — a
/// setting that cannot be read is never one not given.
fn env_text(var: &str) -> Result<Option<String>, Usage> {
    match env::var(var) {
        Ok(text) => Ok(Some(text).filter(|t| !t.is_empty())),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(Usage(format!("{var}: the value is not UTF-8 text"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> impl Iterator<Item = String> {
        a.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
    }

    fn refusal(a: &[&str]) -> String {
        match parse(argv(a)) {
            Err(Usage(text)) => text,
            Ok(_) => panic!("{a:?} parsed"),
        }
    }

    #[test]
    fn flags_parse_and_refusals_are_named() {
        let Parsed::Command(c) = parse(argv(&["claim", "--board", "http://127.0.0.1:8642", "--anchor-out", "/a", "--anchor-out", "/b", "--paper"])).unwrap() else { panic!() };
        assert_eq!(c.command, "claim");
        assert_eq!(c.all("--anchor-out"), ["/a", "/b"]);
        assert!(c.switch("--paper"));
        assert_eq!(c.origin().unwrap().as_str(), "http://127.0.0.1:8642");
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
        assert!(c.origin().is_err(), "a non-canonical board is a usage refusal");
        assert!(c.origin_given().is_err(), "a board given badly is refused, never read as one not given");
        assert!(c.principal().is_err(), "a principal given badly is refused, never read as one not given");
        let Parsed::Command(c) = parse(argv(&["accept", "--board", "http://127.0.0.1:8642", "--principal", "7"])).unwrap() else { panic!() };
        assert_eq!(c.origin_given().unwrap().map(|o| o.as_str().to_string()), Some("http://127.0.0.1:8642".to_string()));
        assert_eq!(c.principal().unwrap(), Some(7));
    }

    /// THE GRAMMAR: a flag of another command's is refused naming the
    /// command, never accepted and dropped; a second value of a flag that
    /// takes one is refused, never the last one standing; a flag that
    /// repeats keeps every value; and every flag a row names is one `HELP`
    /// documents.
    #[test]
    fn each_command_takes_its_own_flags_and_a_flag_that_takes_one_value_takes_one() {
        assert_eq!(refusal(&["health", "--fingerprint", "ab"]), "`--fingerprint` is not a flag of `health`");
        assert_eq!(refusal(&["verify", "--anchor-out", "/d"]), "`--anchor-out` is not a flag of `verify`");
        assert_eq!(refusal(&["retire", "--yes"]), "unknown argument `--yes`", "a flag of no command's is unknown");
        assert_eq!(refusal(&["recover", "--anchor", "/a", "--anchor", "/b"]), "`--anchor` is given at most once at `recover`");
        assert_eq!(refusal(&["session", "--principal", "1", "--principal", "2"]), "`--principal` is given at most once at `session`", "a setting takes one value");
        let Parsed::Command(c) = parse(argv(&["verify", "--anchor", "/a", "--anchor", "/b", "--json"])).unwrap() else { panic!() };
        assert_eq!(c.all("--anchor"), ["/a", "/b"], "--anchor repeats at verify");
        assert!(c.switch("--json"), "--json is every command's");
        let Parsed::Command(c) = parse(argv(&["keygen", "--label", "phone", "--dir", "/s"])).unwrap() else { panic!() };
        assert_eq!(c.value("--label").as_deref(), Some("phone"), "the settings and --label are every command's");
        // A flag named whole: `--anchor` in `--anchor <path>`, never in
        // `--anchor-out`.
        let documented = |flag: &str| HELP.match_indices(flag).any(|(i, _)| !HELP[i + flag.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '-'));
        for row in &GRAMMAR {
            for &flag in row.once.iter().chain(row.repeated).chain(row.switches).chain(&GLOBAL) {
                assert!(documented(flag), "`{flag}` of `{}` is documented in HELP", row.command);
            }
            assert!(HELP.contains(&format!("\n  {} ", row.command)), "`{}` is listed in HELP", row.command);
        }
    }
}
