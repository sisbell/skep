//! What both binaries share: the two streams, the stops and the plumbing.
//!
//! The binaries are `skep`'s fifteen commands and `skep-dev`'s two verbs,
//! each root declaring this file as its `shared`. The two streams are
//! stdout data (`data`, `data_verbatim`, `--help`'s text among what they
//! carry) and stderr talk (the terminal's `talk`, which the prompts share)
//! (`client.md` §2.4) — talk rendered inert to the terminal reading it (the
//! terminal's `inert`), and a data line its C0 controls (`c0_inert`); a
//! data write stdout refuses a halt and a talk line stderr refuses dropped,
//! neither a panic. The stops and §2.3's exit codes are `Stop`, and
//! `finish`, the one place a stop's block and its code are chosen — a
//! program's refusal of a command line it cannot parse among them, the
//! block opening with the program's name and the help beneath a usage
//! refusal, each the [`Program`]'s. The plumbing runs from the flags to a
//! board, a store, a principal and a key — a key file refused where a walk
//! takes none (`require_no_key_file`). A halt is one block on stderr: the
//! state, its cause, the one act (AUTH-5.66; AUTH-5.67's key-file cell
//! naming the path and the state) — a transport halt's act, a retry-class
//! refusal's, and a write refused `poisoned` or `durability`, named here
//! where the library's rendering names none (`act_beside`). The operator's
//! lines of both programs name a key one way (`key_named`) and echo a third
//! party's text to one bound (`clipped`). What the fifteen commands share
//! among themselves alone — the person doors, the payload's read, the
//! anchor boxes' default, the three facts, the whole-set compare — stays in
//! `commands.rs`.

use std::borrow::Cow;
use std::io::{self, Write};
use std::path::Path;

use skep_client::board::Board;
use skep_client::derive::Mode;
use skep_client::dial::{DialError, PlainHttp, CONNECT_TIMEOUT, IO_TIMEOUT};
use skep_client::halt::Halt;
use skep_client::sheet::render_inert;
use skep_client::store::{
    arm4_face, Binding, FileStore, KeyFacts, KeySelector, Purpose, StoreError,
};

use crate::args::{CommandLine, Line, Usage};
use crate::terminal::talk;

/// One of the two programs this crate builds: its name and its help.
///
/// Every stop's block opens with its name (`skep: …`); a usage refusal
/// prints its help beneath its one sentence, and `--help` prints it as
/// data.
#[derive(Clone, Copy, Debug)]
pub struct Program {
    pub name: &'static str,
    pub help: &'static str,
}

/// Why a command stopped short of exit 0 (§2.3).
///
/// A stop is a usage refusal — the flag's shape alone — or a member of the
/// halt family (§1.1's `halt` row), a person door reached without a
/// controlling terminal among its halt and surface members (§2.3's exit-3
/// row). Commands name their stops with `?`; [`finish`] is the one place a
/// stop's stderr block and its code are chosen together.
#[derive(Debug)]
pub enum Stop {
    /// A usage refusal: exit 2, the help beneath it.
    Usage(Usage),
    /// A member of the halt family, with the code it carries.
    ///
    /// The codes are 3 halt and surface, 1 the board refused, 4 transport.
    Halt(Halt),
}

impl From<Usage> for Stop {
    fn from(u: Usage) -> Stop {
        Stop::Usage(u)
    }
}

impl From<Halt> for Stop {
    fn from(h: Halt) -> Stop {
        Stop::Halt(h)
    }
}

/// A store refusal, faced as the library faces it (AUTH-5.67).
impl From<StoreError> for Stop {
    fn from(e: StoreError) -> Stop {
        Stop::Halt(e.into())
    }
}

/// Finishes a command's outcome under `program`, answering the exit code.
///
/// A stop's one block is said on stderr, opening with the program's name,
/// the program's help beneath a usage refusal, a halt's act beneath it
/// where the library's rendering names none ([`act_beside`]); the exit
/// code is 0, or the stop's.
pub fn finish(program: Program, outcome: Result<(), Stop>) -> i32 {
    let (block, code) = match outcome {
        Ok(()) => return 0,
        Err(Stop::Usage(u)) => (format!("{u}\n\n{}", program.help), 2),
        Err(Stop::Halt(h)) => match act_beside(&h) {
            Some(act) => (format!("{h}\n  act: {act}"), h.exit_code()),
            None => (h.to_string(), h.exit_code()),
        },
    };
    talk(format!("{}: {block}", program.name));
    code
}

/// Returns the act a halt's block carries where its rendering names none.
///
/// The rendering is the library's: every halt one block, its state, its
/// cause and the one act that clears it (§2.4). The act is a transport
/// halt's, by where its exchange broke ([`transport_act`]); a retry-class
/// refusal's — a `503` other than `index_failed`, the board's "retry
/// shortly" with nothing of the request taken (wire.md §HTTP status
/// codes); and the two rejections a board's own state answers, whose acts
/// are the operator's before they are the person's — `poisoned`
/// ([`POISONED_ACT`]) and `durability` ([`DURABILITY_ACT`]). `None` where
/// the block names its act itself (a face, a block) or a refusal's act is
/// its token's own.
fn act_beside(h: &Halt) -> Option<String> {
    match h {
        Halt::Dial(d) => Some(transport_act(d)),
        Halt::Refused(r) if r.status == 503 && r.code != "index_failed" => Some(
            "the board was busy and took nothing of this request (a retry-class refusal, wire.md §HTTP status codes): run the same \
             command again in a moment — a ceremony reads what landed before it acts again (client.md §4.4)"
                .to_string(),
        ),
        Halt::Refused(r) if r.status == 200 && r.code == "poisoned" => Some(POISONED_ACT.to_string()),
        Halt::Refused(r) if r.status == 200 && r.code == "durability" => Some(DURABILITY_ACT.to_string()),
        _ => None,
    }
}

/// The act beneath a write refused `poisoned` (wire.md §Rejection codes).
///
/// The board refuses every write until its daemon restarts and serves
/// reads meanwhile, so the act is a restart — and on a board whose volume
/// is full, room before it: a daemon restarted at a full volume does not
/// open, and a board that served reads is then down (`RUNBOOK.md` §1, steps
/// 4 and 5). The write refused so may land at the restart — the one that
/// halted the kernel mid-commit may leave its frames in the journal — so
/// the run after it reads what landed before it acts again.
const POISONED_ACT: &str = "the board refuses every write until its daemon restarts, and serves reads meanwhile (wire.md §Rejection \
     codes; `skep health` answers `writes.halted`): on a board you run, read its stream for the cause and, where the volume is full, make \
     room BEFORE the restart — a daemon restarted at a full volume does not open, and a board that served reads is then down (RUNBOOK.md \
     §1, steps 4 and 5); on another's, tell its operator. Run this again once it has restarted: a write refused so may land at the \
     restart, and a ceremony reads what landed before it acts again (client.md §4.4)";

/// The act beneath a write refused `durability` (wire.md §Rejection codes).
///
/// The write did nothing, and where the cause is a full volume no write
/// lands until room is freed — after which the next one lands by itself
/// and no restart is owed (`RUNBOOK.md` §1, step 5) — room made by never
/// touching a file of the data directory (step 2).
const DURABILITY_ACT: &str = "the write did nothing (wire.md §Rejection codes): at a full volume no write lands until room is freed \
     there, and the next one then lands by itself, no restart owed (RUNBOOK.md §1, step 5) — on a board you run, make room, never by \
     deleting, moving or truncating a file of its data directory (step 2); on another's, tell its operator; then run this again";

/// The board a transport halt's origin came from, named for the act.
///
/// It is the flag, else its variable.
const WHICH_BOARD: &str =
    "that --board, or SKEP_BOARD where no flag is given, names the board you mean";

/// Returns a transport halt's act, by the phase its `DialError` names.
///
/// The halt is §2.3's exit 4. Before the request was written nothing was
/// sent, and the act is the origin's — the build's where no transport holds
/// the origin's scheme, this tool's where this client refused to write the
/// request; after it, the board may have taken the request, and the act
/// reads back what it did before acting again; a timeout is either, and
/// names the daemon still opening its journal — whose port takes a
/// connection and answers nothing until it serves (`RUNBOOK.md` §3, step
/// 5) — beside this client's own bounds, the dialer's pins.
fn transport_act(d: &DialError) -> String {
    match d {
        DialError::NotHeld(_) => "dial it with a skep built with its default features, whose `tls` transport dials https".to_string(),
        DialError::Request(_) => {
            "nothing was sent: this client composed a request it refuses to write, which is this tool's fault — report it with the \
             command line that met it"
                .to_string()
        }
        DialError::Resolve(_) | DialError::Connect(_) => {
            format!("nothing was sent: check that a daemon serves that origin — `skep health` against it answers — and {WHICH_BOARD}")
        }
        DialError::Timeout(_) => format!(
            "a daemon still opening its journal takes a connection and answers nothing until it serves (RUNBOOK.md §3, step 5): its \
             `open:` lines say how far it has got, and its `serving` line when it serves — this client waits {} s for a connection \
             and {} s on a read or a write. Run this again once it serves, reading back first what a write did: a request written \
             before the wait ran out may be taken when it serves. Where no daemon is opening, check that one serves that origin and {WHICH_BOARD}",
            CONNECT_TIMEOUT.as_secs(),
            IO_TIMEOUT.as_secs()
        ),
        DialError::Io(_) | DialError::Truncated { .. } => {
            "the connection broke during the exchange, so the board may have taken the request: read back what it did — `skep \
             fingerprint`, `skep verify`, or the ceremony's own reads when it runs again (client.md §4.4) — before acting again"
                .to_string()
        }
        DialError::Tls(_) => {
            "check that the origin serves https under a certificate this machine trusts; where the exchange broke after the request \
             was written, the board may have taken it: read back what it did before acting again"
                .to_string()
        }
        DialError::Response(_) | DialError::TooLarge { .. } => format!(
            "that origin's answer was no skep board's — none at all where the connection closed first: check that skepd serves it, \
             and {WHICH_BOARD}; the request was written, so read back what a write did before acting again"
        ),
        // A phase the library names later: both acts, since where it broke is
        // not known here.
        _ => format!(
            "check that a daemon serves that origin and {WHICH_BOARD}; where the request was written, the board may have taken \
             it: read back what it did before acting again"
        ),
    }
}

/// Prints the program's help on stdout for `--help`.
///
/// It is the data the run asked for.
///
/// # Errors
///
/// A write stdout refuses is a halt, as every command's is.
pub fn help(program: Program) -> Result<(), Stop> {
    data_verbatim(program.help.as_bytes())?;
    Ok(())
}

/// Writes one line of data to stdout, as [`c0_inert`] renders it, flushed.
///
/// # Errors
///
/// A write stdout refuses — its reader gone, its disk full — is a halt
/// ([`data_refused`]) and the command stops there: never a panic, whose
/// exit 101 §2.3 does not have, and never a pass with the data lost.
pub fn data(line: impl AsRef<str>) -> Result<(), Halt> {
    let mut out = io::stdout().lock();
    writeln!(out, "{}", c0_inert(line.as_ref())).and_then(|()| out.flush()).map_err(data_refused)
}

/// Returns a data line as stdout may carry it.
///
/// Every C0 control — the line break among them — is rendered as its code
/// point (`render_inert`'s spelling), so a byte a board chose forges no
/// second line for the script reading stdout, and opens no 7-bit escape
/// sequence on the terminal reading it, ESC being a C0 control. No line
/// this crate composes holds one: a record's encoder escapes exactly the C0
/// controls (AUTH-2.130 clause 3), the three facts are address text, an
/// integer and an origin, hex is hex, a fingerprint's two grouped lines are
/// two data lines, and a JSON object's text escapes every C0 control. DEL, a
/// bidi control and a C1 control stand: a record carries a label's verbatim
/// — AUTH-1.24 admits all three, and its encoder escapes none — so a
/// terminal reading stdout that interprets the 8-bit C1 controls, as some
/// do, meets one a board chose as it came.
pub fn c0_inert(line: &str) -> Cow<'_, str> {
    let c0 = |c: char| c < ' ';
    if !line.contains(c0) {
        return Cow::Borrowed(line);
    }
    let mut text = String::with_capacity(line.len());
    for c in line.chars() {
        if c0(c) {
            text.push_str(&render_inert(c.encode_utf8(&mut [0; 4])));
        } else {
            text.push(c);
        }
    }
    Cow::Owned(text)
}

/// Writes data to stdout as the bytes it came in.
///
/// It is a body the CLI passes through untouched (`health`'s, AUTH-5.86; a
/// program's help), or a JSON document a command composed (`merge`'s report,
/// `share`'s answers), ended by a newline where it has none.
///
/// # Errors
///
/// A write stdout refuses is a halt, as at [`data`].
pub fn data_verbatim(body: &[u8]) -> Result<(), Halt> {
    let mut out = io::stdout().lock();
    let end: &[u8] = if body.ends_with(b"\n") { b"" } else { b"\n" };
    out.write_all(body)
        .and_then(|()| out.write_all(end))
        .and_then(|()| out.flush())
        .map_err(data_refused)
}

/// Returns the halt a data write stdout refused comes to (§2.3's exit 3).
///
/// What the command did before the write stands, so its act is the
/// read-back, never the act again.
pub fn data_refused(e: io::Error) -> Halt {
    Halt::face(
        "stdout refused this command's data",
        e.to_string(),
        "run it again with stdout at a terminal or a file; where it acted on the board or in the store before this write, that act \
         stands — read it back (`skep fingerprint`, `skep verify`) rather than acting twice",
    )
}

/// The most characters of a third party's text an operator's line echoes.
///
/// The text is a reply's line, a board's answer, a header's value, and a
/// halt echoes no more of it either: the party that wrote the text sizes
/// it, and the line is the operator's.
pub const CLIPPED_CHARS: usize = 120;

/// Returns `text` clipped to [`CLIPPED_CHARS`] characters.
///
/// An ellipsis follows where it ran longer — counted in characters, so no
/// cut splits one.
pub fn clipped(text: &str) -> String {
    match text.char_indices().nth(CLIPPED_CHARS) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_string(),
    }
}

/// Returns a key as the operator's lines name it: its fingerprint and label.
///
/// The fingerprint is what the board testifies each write under the key's
/// session by (AUTH-4.48), and so what joins a line here to the board's
/// record; the label stands beside it, `(none)` where it has none.
pub fn key_named(key: &KeyFacts) -> String {
    format!(
        "{} (label {})",
        key.fingerprint,
        key.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into())
    )
}

/// Returns the board the line names, over the one dialer, `PlainHttp`.
///
/// It is `--board` / `SKEP_BOARD`, a canonical origin; the dialer holds
/// `https://` as well as `http://` in a build with `tls`.
///
/// # Errors
///
/// Returns `Line::origin`'s usage refusals.
pub fn board_of<C>(c: &Line<C>) -> Result<Board, Usage> {
    let origin = c.origin()?;
    Ok(Board::new(origin, PlainHttp::new()))
}

/// Returns the key store the line names.
///
/// It is `--dir` / `SKEP_KEYSTORE`, else `~/.skep`.
///
/// # Errors
///
/// Returns `Line::store_dir`'s usage refusals.
pub fn store_of<C>(c: &Line<C>) -> Result<FileStore, Usage> {
    Ok(FileStore::open(c.store_dir()?))
}

/// Returns the principal: the one `given`, else the board's one binding.
///
/// `given` is `Line::principal`'s answer, its refusal already returned as
/// exit 2 by the caller, before any read; the binding is the store's one
/// at the board (§3.5's one-binding test).
///
/// # Errors
///
/// Where none is chosen, the halt names the store read and the origin it
/// was read for: a store named wrongly, and an origin spelled otherwise
/// than its binding's (`localhost` for `127.0.0.1`), are the two causes the
/// store alone cannot tell from a principal never bound — so the bindings
/// it holds at other origins are named beside it — and where it holds
/// several principals at this one, it lists them. A bindings file the store
/// cannot read is a halt as the library faces it.
pub fn principal_or_bound(
    given: Option<u64>,
    store: &FileStore,
    board: &Board,
) -> Result<u64, Halt> {
    if let Some(p) = given {
        return Ok(p);
    }
    let origin = board.dialed();
    let ps = store.principals_at(origin)?;
    match ps.as_slice() {
        [one] => Ok(*one),
        [] => {
            let mut elsewhere: Vec<String> = store
                .all_bindings()?
                .into_iter()
                .filter_map(|b| match b {
                    Binding::Enrollment { origin: o, .. } if &o != origin => Some(o.to_string()),
                    _ => None,
                })
                .collect();
            elsewhere.sort();
            elsewhere.dedup();
            let mut cause = format!(
                "--principal (or SKEP_PRINCIPAL) is absent and the store at {} holds no binding at {origin}",
                store.root().display()
            );
            if !elsewhere.is_empty() {
                cause.push_str(&format!(
                    "; it holds bindings at {}: an origin spelled another way is another board to the store",
                    elsewhere.join(", ")
                ));
            }
            Err(Halt::face(
                format!("no principal for {origin}"),
                cause,
                "pass --principal <n>, or name the board as its binding does (--board), or the store that holds it (--dir, SKEP_KEYSTORE)",
            ))
        }
        several => {
            let mut several = several.to_vec();
            several.sort_unstable();
            let list = several.iter().map(u64::to_string).collect::<Vec<_>>().join(", ");
            Err(Halt::face(
                format!("no principal for {origin}"),
                format!(
                    "--principal (or SKEP_PRINCIPAL) is absent and the store at {} holds bindings for several principals at {origin}: {list}",
                    store.root().display()
                ),
                format!("pass --principal with one of {list}"),
            ))
        }
    }
}

/// Checks that no key file is named where a walk takes none.
///
/// The walks are `enroll`'s and `retire`'s, which select their key from the
/// store's lookup alone: §3.5 owes `--key` (or `SKEP_KEY`) the lookup's
/// first arm at those commands.
///
/// # Errors
///
/// A key file named there is refused — a usage refusal, ahead of the door
/// — never dropped for a key the person did not name; and so is a
/// `SKEP_KEY` whose value is not UTF-8 text.
pub fn require_no_key_file(c: &CommandLine) -> Result<(), Usage> {
    match c.key_file()? {
        Some(_) => Err(Usage(format!(
            "`--key` (or SKEP_KEY) names a key file, and `skep {}` selects its key from the store's lookup alone in this build: run it without either",
            c.command
        ))),
        None => Ok(()),
    }
}

/// Returns the selected key: the file `key_file` names, else the store's.
///
/// `key_file` is `Line::key_file`'s answer, its refusal already returned as
/// exit 2 by the caller; the store's key is the one for this board and
/// principal (§3.5's lookup). Its public facts are judged for `purpose`: an
/// anchor file refused where the key signs and read where it does not
/// (§2.2's selection test; P11); its signer is the store's
/// (`KeyStore::signer`).
///
/// # Errors
///
/// Where no key is selected, the arm-4 face forks on the claimant, a
/// `/health` read of its own (§3.5 arm 4): a board that does not answer
/// speaks first, its transport halt in place of the store's face. Any other
/// store refusal is a halt as the library faces it.
pub fn select_key(
    key_file: Option<&Path>,
    store: &FileStore,
    board: &Board,
    principal: u64,
    purpose: Purpose,
) -> Result<KeyFacts, Halt> {
    let sel = match key_file {
        Some(path) => store.select(&KeySelector::Path(path), purpose),
        None => store.select(
            &KeySelector::Board { origin: board.dialed(), principal: Some(principal) },
            purpose,
        ),
    };
    match sel {
        Ok(key) => Ok(key),
        Err(StoreError::NoSelection { keys }) => {
            Err(arm4_face(store, &keys, Mode::of(&board.health()?)))
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests;
