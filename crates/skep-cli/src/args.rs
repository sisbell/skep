//! Flag parsing in the daemon's style (`skepd/src/main.rs`'s `parse_args`,
//! `from_env`): every setting is seeded from its environment variable, so a
//! flag always wins over a variable and the precedence is stated once; a
//! missing value, an unknown flag and a bad value are usage refusals
//! (§2.3's exit 2 — the flag's SHAPE alone). The environment names are §9
//! item 21's: `SKEP_BOARD`, `SKEP_KEYSTORE`, `SKEP_KEY`, `SKEP_PRINCIPAL`,
//! `SKEP_SESSION`.

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

/// The seven commands, and the six named as not in this build.
const COMMANDS: [&str; 13] = [
    "keygen", "claim", "session", "fingerprint", "verify", "health", "bind", "enroll", "recover", "retire", "rotate", "handoff", "accept",
];

/// The flags that take a value.
const VALUED: [&str; 14] = [
    "--board", "--dir", "--key", "--principal", "--label", "--anchor-label", "--anchor-out", "--name", "--hosted", "--close", "--select",
    "--payload", "--anchor", "--account",
];

/// The switches.
const SWITCHES: [&str; 3] = ["--json", "--anchors", "--paper"];

/// `--payload` takes a value at `claim --hosted`'s sibling, `verify` and
/// `bind`, and is a SWITCH at `keygen` and `fingerprint`.
fn payload_is_switch(command: &str) -> bool {
    matches!(command, "keygen" | "fingerprint")
}

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

    /// `--board` / `SKEP_BOARD`, a canonical origin — anything else is exit
    /// 2 before any socket opens (§7; the daemon's `NotCanonical` phrase).
    pub fn board(&self) -> Result<Origin, Usage> {
        let text = self.value("--board", Some("SKEP_BOARD")).ok_or_else(|| Usage("--board (or SKEP_BOARD) is required".into()))?;
        text.parse::<Origin>().map_err(|e| Usage(format!("--board: '{text}' is {e}")))
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
        let Parsed::Command(c) = parse(argv(&["enroll"])).unwrap() else { panic!() };
        assert_eq!(c.command, "enroll", "the six parse as commands, and the dispatcher names them as not in this build");
        let Parsed::Command(c) = parse(argv(&["keygen", "--payload"])).unwrap() else { panic!() };
        assert!(c.switch("--payload"), "a switch at keygen");
        let Parsed::Command(c) = parse(argv(&["verify", "--payload", "-", "--board", "HTTP://x"])).unwrap() else { panic!() };
        assert_eq!(c.all("--payload"), ["-"], "a value at verify");
        assert!(c.board().is_err(), "a non-canonical board is a usage refusal");
    }
}
