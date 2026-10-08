//! Flag parsing in the daemon's style (`skepd/src/main.rs`'s `parse_args`,
//! `from_env`). A command line opens with its [`Command`], one of §2.1's
//! thirteen, and is judged against THE GRAMMAR, one row per command beside
//! `HELP`, the text that documents it: a flag in no row, a flag of another
//! command's, a missing value, a second value of a flag that takes one, a
//! flag outside the form of its command that reads it, and two forms at
//! once are usage refusals (§2.3's exit 2 — the flag's SHAPE alone), and so
//! is an argument that is not UTF-8 text, refused as a variable's is. Every
//! setting is read through `CommandLine::setting`, the one place a flag
//! beats its environment variable, and its reader — named for what it
//! answers, an origin, a store's directory, a key file's path, a principal
//! — answers the refusal and the absence apart: `Ok(None)` for a setting
//! given nowhere, `Err` for one given badly, a variable whose value is not
//! UTF-8 text among them, so no command reads a refused value as an absent
//! one. The environment names are §9 item 21's: `SKEP_BOARD`,
//! `SKEP_KEYSTORE`, `SKEP_KEY`, `SKEP_PRINCIPAL`, `SKEP_SESSION` — read here
//! and nowhere else in the crate, `SKEP_SESSION` by `session_env` alone, the
//! one setting no flag carries (`tests/it/tidy.rs`).

use std::collections::HashMap;
use std::env::{self, VarError};
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use skep_client::board::Token;
use skep_client::Origin;

/// A usage refusal: what is wrong with the command line, one sentence that
/// §2.3's exit 2 prints above `HELP`.
#[derive(Debug)]
pub struct Usage(pub String);

impl fmt::Display for Usage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Usage {}

/// The parse's answer: the help, or a command line.
#[derive(Debug)]
pub enum Parsed {
    Help,
    CommandLine(CommandLine),
}

/// One of `client.md` §2.1's thirteen commands — the verb a command line
/// opens with, what THE GRAMMAR's rows are keyed by, and what `main`
/// dispatches on, one arm each, which the compiler holds exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Command {
    Keygen,
    Claim,
    Session,
    Fingerprint,
    Verify,
    Health,
    Bind,
    Enroll,
    Recover,
    Retire,
    Rotate,
    Handoff,
    Accept,
}

impl Command {
    /// The verb as a command line spells it.
    pub fn verb(self) -> &'static str {
        match self {
            Command::Keygen => "keygen",
            Command::Claim => "claim",
            Command::Session => "session",
            Command::Fingerprint => "fingerprint",
            Command::Verify => "verify",
            Command::Health => "health",
            Command::Bind => "bind",
            Command::Enroll => "enroll",
            Command::Recover => "recover",
            Command::Retire => "retire",
            Command::Rotate => "rotate",
            Command::Handoff => "handoff",
            Command::Accept => "accept",
        }
    }
}

/// The verb, as every refusal that names the command spells it.
impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.verb())
    }
}

/// One command line: the command; its flags with their values (a flag that
/// repeats keeps every value, in order); and its switches.
#[derive(Debug)]
pub struct CommandLine {
    pub command: Command,
    values: HashMap<String, Vec<String>>,
    switches: Vec<String>,
}

/// The flags every command takes — `client.md` §2.2's "All commands",
/// DECLARED globally there — each taking one value: the four settings and
/// `--label`, a byline and no setting. `--json`, the switch §2.2 declares
/// beside them, is every command's too.
const GLOBAL: [&str; 5] = ["--board", "--dir", "--key", "--principal", "--label"];

/// One command's flags beyond the [`GLOBAL`] ones, and the rules its forms
/// hold them to.
struct Row {
    command: Command,
    /// The flags that take one value.
    once: &'static [&'static str],
    /// The flags that take a value and REPEAT, every value kept in order.
    repeated: &'static [&'static str],
    /// The switches beside `--json`.
    switches: &'static [&'static str],
    /// The rules the command's FORMS hold its row's flags to — each naming
    /// flags of this row alone — so no flag reaches a run whose form drops
    /// it.
    forms: &'static [Form],
}

/// One rule a FORM of a command holds its row's flags to, judged once the
/// whole line is read: a run reads a flag only in the form it belongs to,
/// so a flag outside its form, or beside another form's, would be accepted
/// and dropped (§2.3's exit 2 refuses it instead).
#[derive(Clone, Copy, Debug)]
enum Form {
    /// The flag belongs to the form the second flag opens: refused without
    /// it.
    Within(&'static str, &'static str),
    /// The two flags belong to two forms of the command: refused together.
    Apart(&'static str, &'static str),
    /// Inside the form the second flag opens, the first names one value.
    OnceWithin(&'static str, &'static str),
    /// Given at most this many times: the backup moment exports two
    /// anchors, and reads a label and a destination for each (§4.2).
    AtMost(&'static str, usize),
}

impl Form {
    /// The refusal `line` meets at this rule, where it breaks it; `None`
    /// where it keeps it.
    fn refusal(self, line: &CommandLine) -> Option<Usage> {
        let command = line.command;
        let text = match self {
            Form::Within(flag, opener) if line.given(flag) && !line.given(opener) => format!("`{flag}` belongs to `{command} {opener}` and is refused without `{opener}`"),
            Form::Apart(a, b) if line.given(a) && line.given(b) => format!("`{a}` and `{b}` belong to two forms of `{command}`: give one"),
            Form::OnceWithin(flag, opener) if line.values(flag).len() > 1 && line.given(opener) => format!("`{flag}` is given at most once at `{command} {opener}`"),
            Form::AtMost(flag, most) if line.values(flag).len() > most => format!("`{flag}` is given at most {most} times at `{command}`"),
            _ => return None,
        };
        Some(Usage(text))
    }
}

/// THE GRAMMAR: the thirteen commands (`client.md` §2.1's IN set), each with
/// the flags §2.2 gives it and `HELP` documents, and the rules its forms
/// hold them to — the forms the record's synopses draw: `keygen --anchors`
/// (§2.2), `claim`'s notebook walk or `--hosted` (§4.5), `enroll`'s walk or
/// `--reply`, `recover`'s device arm or `--anchor-lost` (§4a.6),
/// `handoff --payload` (§4c.2), and `accept`'s pair, its decline
/// (`--no-anchors`) or `--reprint` (§4c.1), whose synopsis requires the
/// `--account` it reads nowhere. `--payload` takes a value where it names a
/// file or `-`, and is a SWITCH at `keygen` and `fingerprint`, where it
/// prints. `--yes` is in no row: a retirement's confirmation is a typed
/// answer at the terminal, never a flag (AUTH-5.46).
const GRAMMAR: [Row; 13] = [
    Row {
        command: Command::Keygen,
        once: &[],
        repeated: &["--anchor-label", "--anchor-out"],
        switches: &["--payload", "--anchors", "--paper"],
        forms: &[
            Form::Within("--anchor-label", "--anchors"),
            Form::Within("--anchor-out", "--anchors"),
            Form::Within("--paper", "--anchors"),
            Form::AtMost("--anchor-label", 2),
            Form::AtMost("--anchor-out", 2),
        ],
    },
    Row {
        command: Command::Claim,
        once: &["--name", "--hosted"],
        repeated: &["--anchor-out"],
        switches: &["--paper"],
        forms: &[Form::Apart("--hosted", "--name"), Form::Apart("--hosted", "--anchor-out"), Form::Apart("--hosted", "--paper"), Form::AtMost("--anchor-out", 2)],
    },
    Row { command: Command::Session, once: &["--close"], repeated: &[], switches: &[], forms: &[] },
    Row { command: Command::Fingerprint, once: &["--select"], repeated: &[], switches: &["--payload"], forms: &[] },
    Row { command: Command::Verify, once: &["--payload"], repeated: &["--anchor"], switches: &[], forms: &[] },
    Row { command: Command::Health, once: &[], repeated: &[], switches: &[], forms: &[] },
    Row { command: Command::Bind, once: &["--account", "--payload"], repeated: &["--anchor"], switches: &[], forms: &[] },
    Row { command: Command::Enroll, once: &["--payload", "--reply"], repeated: &[], switches: &[], forms: &[Form::Apart("--reply", "--payload")] },
    Row {
        command: Command::Recover,
        once: &["--anchor"],
        repeated: &["--lost", "--anchor-out"],
        switches: &["--stolen", "--anchor-lost", "--paper"],
        forms: &[
            Form::Within("--anchor-out", "--anchor-lost"),
            Form::Within("--paper", "--anchor-lost"),
            Form::Apart("--anchor-lost", "--stolen"),
            Form::OnceWithin("--lost", "--anchor-lost"),
            Form::AtMost("--anchor-out", 2),
        ],
    },
    Row { command: Command::Retire, once: &["--fingerprint"], repeated: &[], switches: &[], forms: &[] },
    Row { command: Command::Rotate, once: &["--payload"], repeated: &[], switches: &[], forms: &[] },
    Row { command: Command::Handoff, once: &["--account", "--payload", "--anchor"], repeated: &[], switches: &[], forms: &[Form::Within("--anchor", "--payload")] },
    Row {
        command: Command::Accept,
        once: &["--account"],
        repeated: &["--anchor-out", "--anchor"],
        switches: &["--paper", "--no-anchors", "--reprint"],
        forms: &[
            Form::Within("--anchor", "--reprint"),
            Form::Apart("--reprint", "--anchor-out"),
            Form::Apart("--reprint", "--paper"),
            Form::Apart("--reprint", "--no-anchors"),
            Form::Apart("--no-anchors", "--anchor-out"),
            Form::Apart("--no-anchors", "--paper"),
            Form::AtMost("--anchor-out", 2),
        ],
    },
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
               --close - ends the token in SKEP_SESSION where it is set
               (stdin then unread), else the one read from stdin
  fingerprint  list the store's keys, or the one --select or --key names
               (never both); --payload, --json
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
  --key <path>          one key file, bypassing the store's lookup (env
                        SKEP_KEY): read at session, verify, bind,
                        fingerprint and accept --reprint, an anchor file
                        refused where the key signs; refused where enroll
                        and retire sign, their walks taking none yet; not
                        consulted elsewhere
  --principal <n>       the principal (env SKEP_PRINCIPAL); may be omitted
                        where the store holds one binding at the board; at
                        claim, the new account's id, 1 where omitted
  --label <text>        a byline (keygen, rotate, accept)
  --json                one JSON document on stdout (verify, health,
                        fingerprint)
  keygen:   [--payload]  [--anchors, and with it  [--paper]
            [--anchor-label <l>]... (two at most)
            [--anchor-out <dir>]... (one per anchor, two at most)]
  claim:    [--name <display name>]  [--anchor-out <dir>]... (two at
            most)  [--paper]; or --hosted <payload|-> without them
  session:  --close -
  fingerprint: [--select <fp-prefix|label>, or --key <path>; never both]
            [--payload]
  verify:   --payload <file|->  --anchor <path> (once per anchor)
  bind:     --account <address>  --payload <reply|->  --anchor <path>
  enroll:   --payload <file|->; or --reply <fp-prefix> without it
  recover:  [--anchor <path>]  [--lost <fp-prefix>]...  [--stolen]; or
            --anchor-lost  [--anchor <path>]  [--lost <fp-prefix>]
            [--anchor-out <dir>]... (two at most)  [--paper]
  retire:   --fingerprint <fp-prefix>
  rotate:   [--label <l>]  [--payload <file|->]
  handoff:  --account <address>  [--payload <file|->  [--anchor <path>]]
  accept:   --account <address>  [--label <l>], and the pair
            ([--anchor-out <dir>]... (two at most)  [--paper]) or its
            decline (--no-anchors); or --reprint  [--anchor <path>]...

exit codes: 0 done, 1 the board refused, 2 usage, 3 halt and surface,
4 transport. stdout carries data; stderr carries talk. No --yes exists:
a retirement's confirmation is typed at the terminal.
";

/// The command line after the program's name, as the platform carries it:
/// each argument taken as UTF-8 text, or refused naming it. Judged in two
/// passes, and where several refusals hold the first met speaks: each
/// argument as it is read, against its command's row; then, the line read
/// whole, the rules of the row's forms, in the row's order.
pub fn parse(argv: impl IntoIterator<Item = OsString>) -> Result<Parsed, Usage> {
    let mut argv = argv.into_iter().map(|arg| arg.into_string().map_err(|arg| Usage(format!("the argument '{}' is not UTF-8 text", arg.to_string_lossy()))));
    let Some(first) = argv.next().transpose()? else { return Err(Usage("a command is required".into())) };
    if first == "--help" || first == "-h" || first == "help" {
        return Ok(Parsed::Help);
    }
    let Some(row) = GRAMMAR.iter().find(|r| r.command.verb() == first) else { return Err(Usage(format!("unknown command `{first}`"))) };
    let mut line = CommandLine { command: row.command, values: HashMap::new(), switches: Vec::new() };
    while let Some(arg) = argv.next().transpose()? {
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
            let Some(value) = argv.next().transpose()? else { return Err(Usage(format!("{arg} needs a value"))) };
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
    match row.forms.iter().find_map(|form| form.refusal(&line)) {
        Some(refusal) => Err(refusal),
        None => Ok(Parsed::CommandLine(line)),
    }
}

impl CommandLine {
    /// Whether a switch was given.
    pub fn switch(&self, flag: &str) -> bool {
        self.switches.iter().any(|s| s == flag)
    }

    /// Whether a flag was given — a switch, or a flag with its value.
    fn given(&self, flag: &str) -> bool {
        self.switch(flag) || self.values.contains_key(flag)
    }

    /// Every value a flag that repeats was given, in order — lent: a caller
    /// that keeps them copies them.
    pub fn values(&self, flag: &str) -> &[String] {
        self.values.get(flag).map(Vec::as_slice).unwrap_or_default()
    }

    /// The value a flag that takes one was given — the flag alone; a
    /// setting is read through its own reader below, which consults the
    /// variable. Lent, like the slice [`CommandLine::values`] answers.
    pub fn value(&self, flag: &str) -> Option<&str> {
        self.values.get(flag).and_then(|v| v.first()).map(String::as_str)
    }

    /// A SETTING: the flag's value, else its variable's — a flag beats its
    /// variable (the daemon's `from_env` precedence, stated once). A
    /// variable set empty is unset; one whose value is not UTF-8 text is
    /// refused ([`env_text`]), never read as unset.
    fn setting(&self, flag: &str, var: &str) -> Result<Option<String>, Usage> {
        match self.value(flag) {
            Some(v) => Ok(Some(v.to_owned())),
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

    /// `--principal` / `SKEP_PRINCIPAL`, read by [`parse_principal`].
    pub fn principal(&self) -> Result<Option<u64>, Usage> {
        match self.setting("--principal", "SKEP_PRINCIPAL")? {
            None => Ok(None),
            Some(v) => {
                parse_principal(&v).map(Some).ok_or_else(|| Usage(format!("--principal: '{v}' is not a principal (a non-negative integer no greater than {MAX_PRINCIPAL})")))
            }
        }
    }
}

/// The largest principal a board registers and a client can say back:
/// `2^53 − 1`, the top of the range a JSON number carries EXACTLY (AUTH-6.36's
/// clause) — the bound the library mints under (AUTH-5.20) and reads a key
/// file's `principal` member under. Past it, on a board that seated the id
/// anyway, the anchor files a claim writes for it could never be read back,
/// while the board showed a healthy account.
pub const MAX_PRINCIPAL: u64 = (1 << 53) - 1;

/// The principal `text` spells — the one grammar of it, at the flag, its
/// variable and a reply's `principal` line: a non-negative integer no
/// greater than [`MAX_PRINCIPAL`], else `None`.
pub fn parse_principal(text: &str) -> Option<u64> {
    text.parse::<u64>().ok().filter(|n| *n <= MAX_PRINCIPAL)
}

/// `SKEP_SESSION`, the token `session --close -` ends where it is set — its
/// stdin then unread — the one setting no flag carries: a token is never an
/// argv value (§2.2; AUTH-4.53; §9 item 29). A value that is no session
/// token is a setting given badly, refused here as one not UTF-8 text is.
pub fn session_env() -> Result<Option<Token>, Usage> {
    let Some(text) = env_text("SKEP_SESSION")? else { return Ok(None) };
    Token::parse(&text).map(Some).ok_or_else(|| Usage("SKEP_SESSION: the value is not a session token (32 lowercase hex)".into()))
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
mod tests;
