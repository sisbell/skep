//! Flag parsing in the daemon's style (`skepd/src/main.rs`'s `parse_args`,
//! `from_env`). A command line opens with its [`Command`], one of §2.1's
//! thirteen, `merge`, the fourteenth (the merge record's §6), or `share`,
//! the fifteenth (PUB-5.29; PUB-5.108), and is
//! judged against THE GRAMMAR, one row per command beside
//! `HELP`, the text that documents it: a flag in no row, a flag of another
//! command's, a missing value, a value that is empty or is itself one of the
//! grammar's flags, a second value of a flag that takes one, a flag outside
//! the form of its command that reads it, and two forms at once are usage
//! refusals (§2.3's exit 2 — the flag's SHAPE alone), and so is an argument
//! that is not UTF-8 text, refused as a variable's is. Every setting is read
//! through `Line::setting`, the one place a flag beats its environment
//! variable, and its reader — named for what it answers, an origin, a
//! store's directory, a key file's path, a principal — answers the refusal
//! and the absence apart: `Ok(None)` for a setting given nowhere, `Err` for
//! one given badly, a variable whose value is not UTF-8 text among them, so
//! no command reads a refused value as an absent one. A variable set empty
//! is unset — the way a shell unsets one for a single run — while a flag
//! given an empty value is refused: an empty value, or a flag where the
//! value stands, is what a wrapper's unset variable leaves on its line, and
//! read as absent it would fall to a default the line never named, read as
//! given it would name the working directory. The environment names are §9
//! item 21's: `SKEP_BOARD`, `SKEP_KEYSTORE`, `SKEP_KEY`, `SKEP_PRINCIPAL`,
//! `SKEP_SESSION` — read here and nowhere else in the crate, `SKEP_SESSION`
//! by `session_env` alone, the one setting no flag carries
//! (`tests/it/tidy.rs`) — and beside them `merge`'s `SKEP_MERGE_KIND`
//! (`Line::merge_kind`) and the dev binary's `SKEP_SEARCH_CORPUS`, each
//! read here by the same rule ([`dev`]). The crate's
//! README tables every setting both programs read — its flag, its variable,
//! its default, when it is checked and where it is read — and this file's
//! unit tests hold the table's flags to the grammars and its defaults to
//! their constants.
//!
//! THE DEV BINARY's grammar is the same machinery over its own rows
//! ([`dev`]): `skep-dev`'s root declares this file as its `args` too, so a
//! flag beats its variable in one spelling for both programs, and the
//! settings stay this file's. Its two verbs: `seed`, and `serve`, the dev
//! provider over the shell's core. Both grammars answer `--help` and
//! `--version` where they meet them — as the first argument, or as a flag
//! — the version line composed here, where the program's name is known.

use std::collections::HashMap;
use std::env::{self, VarError};
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use skep_client::board::Token;
use skep_client::Origin;

/// A usage refusal: what is wrong with the command line, one sentence that
/// §2.3's exit 2 prints above the program's help.
#[derive(Debug)]
pub struct Usage(pub String);

impl fmt::Display for Usage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Usage {}

/// The parse's answer: the help, the version line, or a command line — the
/// `skep` command's ([`CommandLine`]) from [`parse`], the dev binary's from
/// [`dev::parse`].
#[derive(Debug)]
pub enum Parsed<C = Command> {
    Help,
    /// `--version`: the line [`version_line`] renders for the program whose
    /// grammar read it, which the root prints as DATA.
    Version(String),
    CommandLine(Line<C>),
}

/// THE VERSION LINE (`--version`): `<program> <crate version> (<commit>)`
/// — the version Cargo compiled in, and the commit the build named through
/// `SKEP_GIT_SHA`, `unknown` where it named none, as a developer's own
/// `cargo build` does. Both are read at compile time, so the run consults no
/// file and no variable. `scripts/release-pack.sh` sets the variable to the
/// tree's commit, twelve characters, and `scripts/release-check.sh` holds
/// the shipped binaries to one version and one commit; the Dockerfile's
/// builder sets it from its `REVISION` build argument, cut the same way, so
/// the sidecar's `skep --version` names the commit its image's label names.
fn version_line(program: &str) -> String {
    format!(
        "{program} {} ({})",
        env!("CARGO_PKG_VERSION"),
        option_env!("SKEP_GIT_SHA").unwrap_or("unknown")
    )
}

/// One of the fifteen commands — `client.md` §2.1's thirteen, `merge`, the
/// fourteenth (the merge record's §6), and `share`, the fifteenth (PUB-5.29;
/// PUB-5.108) — the verb a command line opens with, what THE GRAMMAR's rows
/// are keyed by, and what `main` dispatches on, one arm each, which the
/// compiler holds exhaustive.
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
    Merge,
    Share,
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
            Command::Merge => "merge",
            Command::Share => "share",
        }
    }
}

/// The verb, as every refusal that names the command spells it.
impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.verb())
    }
}

/// One command line: the command — the verb it opened with, a [`Command`]
/// of the `skep` program or a [`dev::DevCommand`] of `skep-dev`; its flags
/// with their values (a flag that repeats keeps every value, in order); and
/// its switches. The readers below are one spelling for both programs.
#[derive(Debug)]
pub struct Line<C> {
    pub command: C,
    values: HashMap<String, Vec<String>>,
    switches: Vec<String>,
}

/// The `skep` command's line: one of the fifteen, and its flags.
pub type CommandLine = Line<Command>;

/// The flags every command takes — `client.md` §2.2's "All commands",
/// DECLARED globally there — each taking one value: the four settings and
/// `--label`, a byline and no setting. `--json`, the switch §2.2 declares
/// beside them, is every command's too.
const GLOBAL: [&str; 5] = ["--board", "--dir", "--key", "--principal", "--label"];

/// One command's flags beyond the program's global ones, and the rules its
/// forms hold them to.
struct Row<C> {
    command: C,
    /// The flags that take one value.
    once: &'static [&'static str],
    /// The flags that take a value and REPEAT, every value kept in order.
    repeated: &'static [&'static str],
    /// The switches beside the program's own.
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
    fn refusal<C: Copy + fmt::Display>(self, line: &Line<C>) -> Option<Usage> {
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

/// THE GRAMMAR: the fifteen commands (`client.md` §2.1's IN set, `merge`
/// and `share`), each with the flags §2.2 gives it and `HELP` documents, and
/// the rules its forms hold them to — the forms the record's synopses draw:
/// `keygen --anchors` (§2.2), `claim`'s notebook walk or `--hosted` (§4.5),
/// `enroll`'s walk or `--reply`, `recover`'s device arm or `--anchor-lost`
/// (§4a.6), `handoff --payload` (§4c.2), `accept`'s pair, its decline
/// (`--no-anchors`) or `--reprint` (§4c.1), whose synopsis requires the
/// `--account` it reads nowhere, `merge`'s three sides, two apart
/// (`--alternative`, `--draft` with `--base` inside it, `--fork`) and its
/// two landings apart (`--publish`, `--into`), the merge record's §6
/// synopsis, and `share`'s four forms apart — a share (`--doc` or
/// `--whole-account`, two apart, with `--to` or `--privash`, two apart),
/// `--revoke` and `--list`, each apart from every flag of the others.
/// `--payload` takes a value where it names a file or `-`, and is a SWITCH
/// at `keygen` and `fingerprint`, where it prints. `--yes` is in `share`'s
/// row alone, standing for the typed answer where no terminal stands; a
/// retirement's confirmation is a typed answer at the terminal, never a
/// flag (AUTH-5.46). That a side and `--doc` are required at `merge`, and a
/// reader at `share`, is the command's judgment, as `retire` judges its
/// `--fingerprint`: no form says "one of".
const GRAMMAR: [Row<Command>; 15] = [
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
    Row {
        command: Command::Merge,
        once: &["--doc", "--alternative", "--draft", "--base", "--fork", "--head", "--kind", "--journal", "--into", "--retries"],
        repeated: &["--resolve"],
        switches: &["--publish", "--no-dedup", "--retype"],
        forms: &[
            Form::Apart("--alternative", "--draft"),
            Form::Apart("--alternative", "--fork"),
            Form::Apart("--draft", "--fork"),
            Form::Within("--base", "--draft"),
            Form::Apart("--publish", "--into"),
        ],
    },
    Row {
        command: Command::Share,
        once: &["--doc", "--to", "--revoke"],
        repeated: &[],
        switches: &["--whole-account", "--privash", "--list", "--yes"],
        forms: &[
            Form::Apart("--doc", "--whole-account"),
            Form::Apart("--to", "--privash"),
            Form::Apart("--doc", "--revoke"),
            Form::Apart("--whole-account", "--revoke"),
            Form::Apart("--to", "--revoke"),
            Form::Apart("--privash", "--revoke"),
            Form::Apart("--doc", "--list"),
            Form::Apart("--whole-account", "--list"),
            Form::Apart("--to", "--list"),
            Form::Apart("--privash", "--list"),
            Form::Apart("--revoke", "--list"),
            Form::Apart("--yes", "--list"),
        ],
    },
];

/// The help text: the fifteen commands, each as the design writes it, and
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
  merge        merge an alternative into its document's head: the base,
               the head and the side read, the merged list and its gaps
               composed under the rules and reported as one JSON document
               on stdout; --publish lands it as the next version with its
               record, --into lands it in a draft; a side of another
               account is refused; no person door
  share        share a draft (--doc <D>) or your whole account
               (--whole-account) with ONE account (--to <account>); or
               --privash one draft: open it to every account on this
               board, never a guest, until you revoke; --revoke <grant>
               withdraws a share (the reader keeps what it fetched);
               --list what you shared, what is shared with you and what
               is privashed here; the statement before the act, then a
               typed confirmation at a terminal — --yes stands for it
               elsewhere; one JSON document on stdout; no person door

flags (a flag beats its env variable; a variable set empty is unset):
  --board <origin>      the board, a canonical origin (env SKEP_BOARD)
  --dir <path>          the key store (env SKEP_KEYSTORE; default ~/.skep)
  --key <path>          one key file, bypassing the store's lookup (env
                        SKEP_KEY): read at session, verify, bind,
                        fingerprint, merge, share and accept --reprint, an
                        anchor file refused where the key signs; refused
                        where enroll and retire sign, their walks taking
                        none yet; not consulted elsewhere
  --principal <n>       the principal (env SKEP_PRINCIPAL), read at
                        session, verify, enroll, recover, retire, rotate,
                        handoff, merge and share — where omitted, the
                        store's one binding at the board; at bind, the
                        reply's where omitted; at claim, the new account's
                        id, 1 where omitted; not consulted elsewhere
  --label <text>        a byline (keygen, rotate, accept)
  --json                one JSON document on stdout (verify, health,
                        fingerprint; merge and share print one always, so
                        the flag changes nothing there)
  --version             this program's version and the commit it was
                        built from, one line on stdout
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
  merge:    --doc <D>  --kind <address> (env SKEP_MERGE_KIND; the merge
            record kind's type address)  and one side: --alternative
            <D.k.m>, or --draft <S> --base <D.k>, or --fork <F> (refused
            until the fork-source read lands)  [--head <D.h>] (else the
            feed's last trunk version)  [--journal <J>] (else the
            account's private one)  [--resolve <gap>=<choice>]... (a
            choice: order:<side>,<side>...  after:<address>
            before:<address>  keep:<side>  both  omit; a side is its
            index as the report numbers it)  [--no-dedup]  [--retype]
            [--retries <n>]  [--publish, or --into <draft>]; with
            neither it composes and prints
  share:    --doc <D> --to <account>; or --whole-account --to <account>;
            or --doc <D> --privash; or --revoke <grant>; or --list; and
            [--yes] at a share, a privash or a revoke, required where
            stdin and stderr are not both a terminal

exit codes: 0 done, 1 the board refused, 2 usage, 3 halt and surface,
4 transport. stdout carries data; stderr carries talk. A retirement's
confirmation is typed at the terminal, and no --yes stands for it; only
share takes --yes, for a share, a privash or a revoke off a terminal.
";

/// One program's GRAMMAR: its name, as its version line opens; its rows;
/// the flags every command takes with one value — the settings among them
/// — and the switches every command takes.
struct Grammar<C: 'static> {
    program: &'static str,
    rows: &'static [Row<C>],
    global: &'static [&'static str],
    every: &'static [&'static str],
}

impl<C> Grammar<C> {
    /// Whether `text` is a flag one of the grammar's rows names.
    fn rows_name(&self, text: &str) -> bool {
        self.rows.iter().any(|r| {
            r.once.contains(&text) || r.repeated.contains(&text) || r.switches.contains(&text)
        })
    }

    /// Whether `text` is one of the grammar's flags: a row's, every
    /// command's, or `--help`, `-h` and `--version`, which it answers
    /// wherever it meets them.
    fn names_flag(&self, text: &str) -> bool {
        ["--help", "-h", "--version"].contains(&text)
            || self.global.contains(&text)
            || self.every.contains(&text)
            || self.rows_name(text)
    }
}

/// The `skep` command's grammar: [`GRAMMAR`]'s rows, [`GLOBAL`]'s flags and
/// `--json`.
const SKEP: Grammar<Command> =
    Grammar { program: "skep", rows: &GRAMMAR, global: &GLOBAL, every: &["--json"] };

/// The `skep` command line after the program's name, as the platform
/// carries it: [`parse_under`] the command's own grammar.
pub fn parse(argv: impl IntoIterator<Item = OsString>) -> Result<Parsed, Usage> {
    parse_under(&SKEP, argv)
}

/// A command line after the program's name, as the platform carries it:
/// each argument taken as UTF-8 text, or refused naming it. Judged in two
/// passes, and where several refusals hold the first met speaks: each
/// argument as it is read, against its command's row — a flag's value
/// among it, refused where it is empty or is itself one of the grammar's
/// flags, `-` standing; then, the line read whole, the rules of the row's
/// forms, in the row's order.
fn parse_under<C: Copy + fmt::Display>(
    grammar: &Grammar<C>,
    argv: impl IntoIterator<Item = OsString>,
) -> Result<Parsed<C>, Usage> {
    let mut argv = argv.into_iter().map(|arg| {
        arg.into_string().map_err(|arg| {
            Usage(format!("the argument '{}' is not UTF-8 text", arg.to_string_lossy()))
        })
    });
    let Some(first) = argv.next().transpose()? else {
        return Err(Usage("a command is required".into()));
    };
    if first == "--help" || first == "-h" || first == "help" {
        return Ok(Parsed::Help);
    }
    if first == "--version" {
        return Ok(Parsed::Version(version_line(grammar.program)));
    }
    let Some(row) = grammar.rows.iter().find(|r| r.command.to_string() == first) else {
        return Err(Usage(format!("unknown command `{first}`")));
    };
    let mut line = Line { command: row.command, values: HashMap::new(), switches: Vec::new() };
    while let Some(arg) = argv.next().transpose()? {
        let flag = arg.as_str();
        if flag == "--help" || flag == "-h" {
            return Ok(Parsed::Help);
        }
        if flag == "--version" {
            return Ok(Parsed::Version(version_line(grammar.program)));
        }
        if grammar.every.contains(&flag) || row.switches.contains(&flag) {
            line.switches.push(arg);
            continue;
        }
        let repeats = row.repeated.contains(&flag);
        if repeats || row.once.contains(&flag) || grammar.global.contains(&flag) {
            let Some(value) = argv.next().transpose()? else {
                return Err(Usage(format!("{arg} needs a value")));
            };
            if value.is_empty() {
                return Err(Usage(format!("{arg}: an empty value names nothing")));
            }
            if grammar.names_flag(&value) {
                return Err(Usage(format!("{arg} needs a value, and `{value}` is a flag")));
            }
            if !repeats && line.values.contains_key(&arg) {
                return Err(Usage(format!("`{arg}` is given at most once at `{}`", row.command)));
            }
            line.values.entry(arg).or_default().push(value);
            continue;
        }
        if grammar.rows_name(flag) {
            return Err(Usage(format!("`{arg}` is not a flag of `{}`", row.command)));
        }
        return Err(Usage(format!("unknown argument `{arg}`")));
    }
    match row.forms.iter().find_map(|form| form.refusal(&line)) {
        Some(refusal) => Err(refusal),
        None => Ok(Parsed::CommandLine(line)),
    }
}

impl<C> Line<C> {
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
    /// variable. Lent, like the slice [`Line::values`] answers.
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

    /// `--board` / `SKEP_BOARD`, required: [`Line::origin_given`], its
    /// absence a usage refusal of its own.
    pub fn origin(&self) -> Result<Origin, Usage> {
        self.origin_given()?.ok_or_else(|| Usage("--board (or SKEP_BOARD) is required".into()))
    }

    /// `--dir` / `SKEP_KEYSTORE`: the key store's directory, else `~/.skep`
    /// (§6; §9 item 10) under an ABSOLUTE home — a home set empty, or to a
    /// relative path, is none: it would root the store, and every seed it
    /// holds, in whatever directory the run started in.
    pub fn store_dir(&self) -> Result<PathBuf, Usage> {
        match self.setting("--dir", "SKEP_KEYSTORE")? {
            Some(d) => Ok(PathBuf::from(d)),
            None => skep_client::store::default_store_dir()
                .filter(|d| d.is_absolute())
                .ok_or_else(|| Usage("--dir (or SKEP_KEYSTORE) is required: no home directory to default ~/.skep from".into())),
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

impl Line<Command> {
    /// `--kind` / `SKEP_MERGE_KIND` (`merge`): the merge record kind's TYPE
    /// address as text, the command's to parse; `None` where neither is
    /// set. The kind's commons row is interim and unpinned (the merge
    /// record's decision 9), so the caller names it.
    pub fn merge_kind(&self) -> Result<Option<String>, Usage> {
        self.setting("--kind", "SKEP_MERGE_KIND")
    }
}

/// The largest principal a board registers and a client can say back:
/// `2^53 − 1`, the top of the range a JSON number carries EXACTLY (AUTH-6.36's
/// clause) — the bound the library mints under (AUTH-5.20) and reads a key
/// file's `principal` member under. Past it, on a board that seated the id
/// anyway, the anchor files a claim writes for it could never be read back,
/// while the board showed a healthy account.
pub const MAX_PRINCIPAL: u64 = (1 << 53) - 1;

/// The principal `skep claim` gives the account it makes where
/// `--principal` is omitted, at both arms: `1`, §2.2's recommended default
/// and §9 item 9's ruling — the figure `skep-client`'s notebook walk
/// defaults to as well, which the command hands the principal whole.
pub const CLAIM_PRINCIPAL: u64 = 1;

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

/// THE DEV BINARY's GRAMMAR — `skep-dev`'s verb and flags, over the
/// machinery above. It lives in this file and not in the dev root's tree
/// because the settings are this file's (§9 item 21: every `SKEP_*`
/// variable is read here and nowhere else — `SKEP_SEARCH_CORPUS`, the search
/// budgets' own variable, among them now that the tool reads it too) and so
/// is the one spelling of a flag beating its variable. The `skep` target
/// compiles it too and reads none of it, which the lint allowance says.
#[allow(dead_code)]
pub mod dev {
    use std::ffi::OsString;
    use std::fmt;
    use std::path::PathBuf;

    use skep_client::Origin;

    use super::{parse_under, Form, Grammar, Line, Parsed, Row, Usage};

    /// `skep-dev`'s verbs: `seed`, and `serve` — the dev provider, the
    /// shell's core served to a page over loopback; the fixture recorder a
    /// later one, in this binary, so the dev tools grow verbs as the
    /// daemon's two operator tools do.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum DevCommand {
        Seed,
        Serve,
    }

    impl DevCommand {
        /// The verb as a command line spells it.
        pub fn verb(self) -> &'static str {
            match self {
                DevCommand::Seed => "seed",
                DevCommand::Serve => "serve",
            }
        }
    }

    impl fmt::Display for DevCommand {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.verb())
        }
    }

    /// The dev binary's line: its verb and its flags.
    pub type DevLine = Line<DevCommand>;

    /// The commit `--pin` defaults to: the search budgets' pin, the design
    /// repository's `b17656e9`, so a seed and the budgets read one corpus —
    /// `skep-search`'s `tests/it/budgets/corpus.rs` `PIN`, which a unit
    /// test holds this to.
    pub const DEFAULT_PIN: &str = "b17656e9";

    /// The variable `--repo` beats: the search budgets' own, so one
    /// checkout serves the budgets and a seed (RULED) — `skep-search`'s
    /// `tests/it/budgets/corpus.rs` `VAR`, which a unit test holds this to.
    pub const CORPUS_VARIABLE: &str = "SKEP_SEARCH_CORPUS";

    /// The documents `--documents` defaults to: the 10³ tier, the first
    /// thousand documents of the cut.
    pub const DEFAULT_DOCUMENTS: usize = 1_000;

    /// `--versions`'s default: every twentieth document gets a second
    /// version.
    pub const DEFAULT_VERSIONS: usize = 20;

    /// `--drafts`'s default: ten drafts past the tier.
    pub const DEFAULT_DRAFTS: usize = 10;

    /// `serve --listen`'s default: the provider's loopback port, the one
    /// the dev provider record's example names (its §3.2).
    pub const DEFAULT_LISTEN: u16 = 8742;

    /// `serve --port`'s default under `--own`: the daemon's own default,
    /// the local record's recipe (`RUNBOOK.md` §3).
    pub const DEFAULT_NODE_PORT: u16 = 8642;

    /// `serve`'s principal where `--principal` is omitted: the one `skep
    /// claim` gives the account it makes by default
    /// ([`super::CLAIM_PRINCIPAL`]), so a bare session binds as the claimant
    /// of a board claimed without naming one.
    pub const DEFAULT_PRINCIPAL: u64 = super::CLAIM_PRINCIPAL;

    /// The admission secret's alphabet, as `--secret`'s refusal and the help
    /// name it: RFC 3986's unreserved characters, the one set the page's
    /// URL query and its `Skep-Provider` header both carry unchanged.
    pub const SECRET_ALPHABET: &str = "A-Z a-z 0-9 - . _ ~";

    /// The settings every verb takes — the `skep` command's four. Not
    /// `--label`, which writes a byline this tool never writes, and not
    /// `--json`: the tool prints one JSON object always.
    pub(super) const GLOBAL: [&str; 4] = ["--board", "--dir", "--key", "--principal"];

    /// THE DEV GRAMMAR: `seed` and its six flags, each taking one value and
    /// each read in the one form the verb has; `serve` and its flags — the
    /// one page origin admitted, the listen port, the per-run secret, the
    /// session mode, the script, and under `--own` the in-process daemon's
    /// three (`--data-dir`, `--port`, `--no-local-trust`), which belong to
    /// that form alone and stand apart from `--board`, the running board's.
    pub(super) const GRAMMAR: [Row<DevCommand>; 2] = [
        Row {
            command: DevCommand::Seed,
            once: &["--repo", "--pin", "--from", "--documents", "--versions", "--drafts"],
            repeated: &[],
            switches: &[],
            forms: &[],
        },
        Row {
            command: DevCommand::Serve,
            once: &["--page-origin", "--listen", "--secret", "--session", "--script", "--data-dir", "--port"],
            repeated: &[],
            switches: &["--own", "--no-local-trust"],
            forms: &[
                Form::Within("--data-dir", "--own"),
                Form::Within("--port", "--own"),
                Form::Within("--no-local-trust", "--own"),
                Form::Apart("--own", "--board"),
            ],
        },
    ];

    const DEV: Grammar<DevCommand> =
        Grammar { program: "skep-dev", rows: &GRAMMAR, global: &GLOBAL, every: &[] };

    /// The help text: the one verb, and the flags it takes — the grammar
    /// above, documented beside it.
    pub const HELP: &str = "\
usage: skep-dev <command> [flags]

  seed         fill a RUNNING, CLAIMED board with a prose corpus: the
               documents cut from a git repository at a pinned commit land
               as editions under the claimant's account, the backticked
               `.md` cites among them as citation links (a ghost document
               where the cited file is outside the set), every k-th
               document gets a second version (a paragraph appended, a
               paragraph removed, a sentence changed, in rotation), drafts
               past the tier follow with the first windowed by the first
               edition, and a keyless second account gets a draft the
               claimant cannot read; one JSON object on stdout; a manifest
               beside the key store makes a second run add nothing and a
               killed run resume — the one write it had in flight made
               again, so a mint or a shot of it may land twice; the first
               run fixes the seed — the board, the account, the principal,
               the pin, the cut rule, --from and the three counts — so a
               later run naming any other is refused, naming each
               difference, and a different seed takes a fresh board
  serve        serve the shell's core to a page in a browser over loopback
               HTTP and server-sent events (the dev provider): the bridge's
               calls at POST /bridge/<call>, its events at GET
               /bridge/events, the person's answers at /bridge/answer and
               /bridge/cancel, the log at /bridge/log, the declarations at
               /bridge/shapes, the script seam at /bridge/script; ONE page
               origin admitted, with a per-run secret the page carries as
               ?provider=<secret> and echoes in the Skep-Provider header;
               the session bare as the claimant, or signed with a dev key;
               the secret alone on stdout; stops cleanly when stdin closes
               (Ctrl-D at a terminal) — an interrupt skips the clean stop

flags (a flag beats its env variable; a variable set empty is unset):
  --board <origin>      the board, a canonical origin (env SKEP_BOARD)
  --dir <path>          the key store (env SKEP_KEYSTORE): at seed, default
                        ~/.skep; at serve no default — required under
                        --session signed, under bare a throwaway in the
                        system temp dir, removed at the clean stop
  --key <path>          one key file, bypassing the store's lookup (env
                        SKEP_KEY): read at seed, where an anchor file is
                        refused; refused at serve
  --principal <n>       the principal (env SKEP_PRINCIPAL): at seed, may be
                        omitted where the store holds one binding at the
                        board; at serve, 1 where omitted
  --version             this program's version and the commit it was
                        built from, one line on stdout
  seed:     --repo <path>       the repository (env SKEP_SEARCH_CORPUS)
            [--pin <commit>]    the commit read (default b17656e9)
            [--from <path>]     cut the `.md` files under this path alone
                                (the rule is then cut-v2, else cut-v1)
            [--documents <n>]   the documents cut as editions (default
                                1000, the 10^3 tier; 10000 the 10^4 tier)
            [--versions <k>]    a second version of every k-th document
                                (default 20)
            [--drafts <n>]      drafts past the tier, the first windowed
                                (default 10; at least one)
  serve:    --page-origin <origin>  the ONE origin admitted (required)
            --session bare|signed   the session mode (required; signed
                                needs --dir with the principal's key)
            [--listen <port>]   the provider's loopback port (default 8742)
            [--secret <text>]   the admission secret, one or more of
                                A-Z a-z 0-9 - . _ ~, the characters the
                                page's URL and header carry unchanged: a
                                fixed one keeps the page's URL across
                                restarts, else one is generated anew each
                                run and printed once on stdout — a command
                                line is visible to every user of this
                                machine (ps): where others use it, let the
                                provider generate the secret
            [--script <file>]   the dev arm's answers for the SECRET and
                                CONSENT moments, one per line, read once,
                                at start; absent, the auto arm answers and
                                says so
            and the board: --board <origin>, a running daemon; or, in a
            build with the dev-hooks feature, --own  [--data-dir <dir>]
            [--port <p>] (default 8642; 0 picks a free port, named on
            stderr)  [--no-local-trust] — the daemon run in-process with
            its test hooks, its fault doors at POST /bridge/fault/<door>

exit codes: 0 done, 1 the board refused, 2 usage, 3 halt and surface,
4 transport. stdout carries one JSON object (seed) or the secret
(serve); stderr carries talk.
";

    /// The `skep-dev` command line after the program's name: the one grammar
    /// over the dev rows.
    pub fn parse(argv: impl IntoIterator<Item = OsString>) -> Result<Parsed<DevCommand>, Usage> {
        parse_under(&DEV, argv)
    }

    impl Line<DevCommand> {
        /// `--repo` / `SKEP_SEARCH_CORPUS` ([`CORPUS_VARIABLE`]), required:
        /// the repository's path.
        pub fn repo(&self) -> Result<PathBuf, Usage> {
            self.setting("--repo", CORPUS_VARIABLE)?
                .map(PathBuf::from)
                .ok_or_else(|| Usage("--repo (or SKEP_SEARCH_CORPUS) is required".into()))
        }

        /// `--pin`, else [`DEFAULT_PIN`].
        pub fn pin(&self) -> &str {
            self.value("--pin").unwrap_or(DEFAULT_PIN)
        }

        /// `--from`: the subtree the cut reads, where given.
        pub fn from(&self) -> Option<&str> {
            self.value("--from")
        }

        /// `--documents`: the documents cut as editions, at least one;
        /// [`DEFAULT_DOCUMENTS`] where absent.
        pub fn documents(&self) -> Result<usize, Usage> {
            self.count("--documents", DEFAULT_DOCUMENTS)
        }

        /// `--versions`: every so-many-th document gets a second version, a
        /// period of at least one; [`DEFAULT_VERSIONS`] where absent.
        pub fn versions(&self) -> Result<usize, Usage> {
            self.count("--versions", DEFAULT_VERSIONS)
        }

        /// `--drafts`: the drafts past the tier, at least one — the first is
        /// the windowed one; [`DEFAULT_DRAFTS`] where absent.
        pub fn drafts(&self) -> Result<usize, Usage> {
            self.count("--drafts", DEFAULT_DRAFTS)
        }

        /// A count flag: a positive integer, or the default where absent; a
        /// value that is no count is a usage refusal.
        fn count(&self, flag: &str, default: usize) -> Result<usize, Usage> {
            match self.value(flag) {
                None => Ok(default),
                Some(v) => {
                    v.parse::<usize>().ok().filter(|n| *n >= 1).ok_or_else(|| {
                        Usage(format!("{flag}: '{v}' is not a count of at least one"))
                    })
                }
            }
        }

        /// `--dir` / `SKEP_KEYSTORE` where either is set, and NO default:
        /// `serve` never consults `~/.skep` — the dev key store is a
        /// throwaway directory, and a bare run names none.
        pub fn store_dir_given(&self) -> Result<Option<PathBuf>, Usage> {
            Ok(self.setting("--dir", "SKEP_KEYSTORE")?.map(PathBuf::from))
        }

        /// `serve --page-origin`, required: the ONE origin the provider
        /// admits, a canonical one.
        pub fn page_origin(&self) -> Result<Origin, Usage> {
            let text = self.value("--page-origin").ok_or_else(|| Usage("--page-origin is required: the one origin the provider admits".into()))?;
            text.parse::<Origin>().map_err(|e| Usage(format!("--page-origin: '{text}' is {e}")))
        }

        /// `serve --listen`, else [`DEFAULT_LISTEN`].
        pub fn listen(&self) -> Result<u16, Usage> {
            self.port_flag("--listen", DEFAULT_LISTEN)
        }

        /// `serve --port` (under `--own`), else [`DEFAULT_NODE_PORT`]; `0`
        /// a free port, which the in-process daemon's line names on TALK.
        pub fn node_port(&self) -> Result<u16, Usage> {
            match self.value("--port") {
                None => Ok(DEFAULT_NODE_PORT),
                Some(v) => v.parse::<u16>().map_err(|_| Usage(format!("--port: '{v}' is not a port"))),
            }
        }

        /// A port a page is pointed at: 1–65535, never `0`, which would bind
        /// a port the page's URL could not name ahead of the run.
        fn port_flag(&self, flag: &str, default: u16) -> Result<u16, Usage> {
            match self.value(flag) {
                None => Ok(default),
                Some(v) => v.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| Usage(format!("{flag}: '{v}' is not a port the page can be pointed at: name one (1-65535)"))),
            }
        }

        /// `serve --secret`, where given: one or more of
        /// [`SECRET_ALPHABET`], since the page carries the secret in its
        /// URL's `?provider=` query — which a reader decodes (`+`, `%XX`)
        /// and cuts (`&`, `#`) — and echoes it in a header whose value is
        /// trimmed, so a secret holding any other character admits no page.
        /// The refusal names the alphabet and never the value: stderr
        /// carries no secret.
        pub fn secret(&self) -> Result<Option<&str>, Usage> {
            let unreserved =
                |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
            match self.value("--secret") {
                None => Ok(None),
                Some(s) if !s.is_empty() && s.bytes().all(unreserved) => Ok(Some(s)),
                Some(_) => Err(Usage(format!(
                    "--secret: a secret is one or more of {SECRET_ALPHABET}, the characters the page's URL and its header carry unchanged; the value given holds another (it is not echoed)"
                ))),
            }
        }

        /// `serve --session`, required: `bare` or `signed`.
        pub fn session_mode(&self) -> Result<SessionArm, Usage> {
            match self.value("--session") {
                Some("bare") => Ok(SessionArm::Bare),
                Some("signed") => Ok(SessionArm::Signed),
                Some(other) => Err(Usage(format!("--session: '{other}' is neither bare nor signed"))),
                None => Err(Usage("--session bare|signed is required: both arms stand, and a run names one".into())),
            }
        }

        /// `serve --script`, where given.
        pub fn script(&self) -> Option<PathBuf> {
            self.value("--script").map(PathBuf::from)
        }

        /// `serve --own`.
        pub fn own(&self) -> bool {
            self.switch("--own")
        }

        /// `serve --data-dir` (under `--own`), required there.
        pub fn data_dir(&self) -> Result<PathBuf, Usage> {
            self.value("--data-dir").map(PathBuf::from).ok_or_else(|| Usage("--data-dir is required with --own: the in-process daemon's board directory".into()))
        }

        /// `serve --no-local-trust` (under `--own`).
        pub fn no_local_trust(&self) -> bool {
            self.switch("--no-local-trust")
        }
    }

    /// `serve --session`'s two arms.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SessionArm {
        Bare,
        Signed,
    }
}

#[cfg(test)]
mod tests;
