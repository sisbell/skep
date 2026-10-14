//! WHAT BOTH BINARIES SHARE — `skep`'s thirteen commands and `skep-dev`'s
//! verb, each root declaring this file as its `shared`: the two streams,
//! stdout DATA (`data`, `data_verbatim`, `--help`'s text among what they
//! carry) and stderr TALK (the terminal's `talk`, which the prompts share)
//! (`client.md` §2.4) — TALK rendered inert to the terminal reading it (the
//! terminal's `inert`), and a DATA line its C0 controls (`c0_inert`); a
//! DATA write stdout refuses a halt and a TALK line stderr refuses dropped,
//! neither a panic; the stops and §2.3's exit codes (`Stop`, and `finish`,
//! the one place a stop's block and its code are chosen — a program's
//! refusal of a command line it cannot parse among them, the block opening
//! with the program's name and the help beneath a usage refusal, each the
//! [`Program`]'s); and the plumbing from the flags to a board, a store, a
//! principal and a key — a key file refused where a walk takes none
//! (`require_no_key_file`). A halt is one block on stderr: the state, its
//! cause, the one act (AUTH-5.66; AUTH-5.67's key-file cell naming the path
//! and the state) — a transport halt's act, and a retry-class refusal's,
//! named here where the library's rendering names none (`act_beside`). What
//! the thirteen commands share among themselves alone — the person doors,
//! the payload's read, the anchor boxes' default, the three facts, the
//! whole-set compare — stays in `commands.rs`.

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

/// One of the two programs this crate builds: its name, which every stop's
/// block opens with (`skep: …`), and its help, which a usage refusal prints
/// beneath its one sentence and `--help` prints as DATA.
#[derive(Clone, Copy, Debug)]
pub struct Program {
    pub name: &'static str,
    pub help: &'static str,
}

/// Why a command stopped short of exit 0 (§2.3): a usage refusal — the
/// flag's shape alone — or a member of the halt family (§1.1's `halt` row),
/// a person door reached without a controlling terminal among its HALT AND
/// SURFACE members (§2.3's exit-3 row). Commands name their stops with `?`;
/// [`finish`] is the one place a stop's stderr block and its code are
/// chosen together.
#[derive(Debug)]
pub enum Stop {
    /// A usage refusal: exit 2, the help beneath it.
    Usage(Usage),
    /// A member of the halt family, with the code it carries: 3 halt and
    /// surface, 1 the board refused, 4 transport.
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

/// A command's outcome finished under `program`: a stop's one block said on
/// stderr, opening with the program's name, the program's help beneath a
/// usage refusal, a halt's act beneath it where the library's rendering
/// names none ([`act_beside`]); and the exit code answered — 0, or the
/// stop's.
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

/// The act a halt's block carries where the library's rendering of it names
/// none — every halt one block, its state, its cause and the one act that
/// clears it (§2.4): a transport halt's, by where its exchange broke
/// ([`transport_act`]), and a retry-class refusal's — a `503` other than
/// `index_failed`, the board's "retry shortly" with nothing of the request
/// taken (wire.md §HTTP status codes). `None` where the block names its act
/// itself (a face, a block) or a refusal's act is its token's own.
fn act_beside(h: &Halt) -> Option<String> {
    match h {
        Halt::Dial(d) => Some(transport_act(d)),
        Halt::Refused(r) if r.status == 503 && r.code != "index_failed" => Some(
            "the board was busy and took nothing of this request (a retry-class refusal, wire.md §HTTP status codes): run the same \
             command again in a moment — a ceremony reads what landed before it acts again (client.md §4.4)"
                .to_string(),
        ),
        _ => None,
    }
}

/// The board a transport halt's origin came from, named for the act: the
/// flag, else its variable.
const WHICH_BOARD: &str =
    "that --board, or SKEP_BOARD where no flag is given, names the board you mean";

/// A transport halt's act, by the phase its `DialError` names (§2.3's exit
/// 4): before the request was written nothing was sent, and the act is the
/// origin's; after it, the board may have taken the request, and the act
/// reads back what it did before acting again; a timeout is either, and
/// names the daemon still opening its journal — whose port takes a
/// connection and answers nothing until it serves (`RUNBOOK.md` §3, step 5)
/// — beside this client's own bounds, the dialer's pins.
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

/// `--help`: the program's help on stdout, the DATA the run asked for — a
/// write stdout refuses a halt, as every command's is.
pub fn help(program: Program) -> Result<(), Stop> {
    data_verbatim(program.help.as_bytes())?;
    Ok(())
}

/// DATA, to stdout — ONE line, as [`c0_inert`] renders it, flushed. A
/// write stdout refuses — its reader gone, its disk full — is a halt
/// ([`data_refused`]) and the command stops there: never a panic, whose
/// exit 101 §2.3 does not have, and never a pass with the data lost.
pub fn data(line: impl AsRef<str>) -> Result<(), Halt> {
    let mut out = io::stdout().lock();
    writeln!(out, "{}", c0_inert(line.as_ref())).and_then(|()| out.flush()).map_err(data_refused)
}

/// A DATA line as stdout may carry it: every C0 control — the line break
/// among them — rendered as its code point (`render_inert`'s spelling), so
/// a byte a board chose forges no second line for the script reading
/// stdout, and opens no 7-bit escape sequence on the terminal reading it,
/// ESC being a C0 control. No line this crate composes holds one: a
/// record's encoder escapes exactly the C0 controls (AUTH-2.130 clause 3),
/// the three facts are address text, an integer and an origin, hex is hex,
/// a fingerprint's two grouped lines are two DATA lines, and a JSON
/// object's text escapes every control. DEL, a bidi control and a C1
/// control stand: a record carries a label's verbatim — AUTH-1.24 admits
/// all three, and its encoder escapes none — so a terminal reading stdout
/// that interprets the 8-bit C1 controls, as some do, meets one a board
/// chose as it came.
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

/// DATA, to stdout, as the bytes it came in — a body the CLI passes through
/// untouched (`health`'s, AUTH-5.86; a program's help) — ended by a newline
/// where it has none; a write stdout refuses a halt, as at [`data`].
pub fn data_verbatim(body: &[u8]) -> Result<(), Halt> {
    let mut out = io::stdout().lock();
    let end: &[u8] = if body.ends_with(b"\n") { b"" } else { b"\n" };
    out.write_all(body)
        .and_then(|()| out.write_all(end))
        .and_then(|()| out.flush())
        .map_err(data_refused)
}

/// The halt a DATA write stdout refused comes to (§2.3's exit 3): what the
/// command did before the write stands, so its act is the read-back, never
/// the act again.
pub fn data_refused(e: io::Error) -> Halt {
    Halt::face(
        "stdout refused this command's data",
        e.to_string(),
        "run it again with stdout at a terminal or a file; where it acted on the board or in the store before this write, that act \
         stands — read it back (`skep fingerprint`, `skep verify`) rather than acting twice",
    )
}

/// The board the line names: `--board` / `SKEP_BOARD`, a canonical origin,
/// over the one plain dialer.
pub fn board_of<C>(c: &Line<C>) -> Result<Board, Usage> {
    let origin = c.origin()?;
    Ok(Board::new(origin, PlainHttp::new()))
}

/// The key store the line names: `--dir` / `SKEP_KEYSTORE`, else `~/.skep`.
pub fn store_of<C>(c: &Line<C>) -> Result<FileStore, Usage> {
    Ok(FileStore::open(c.store_dir()?))
}

/// The principal: the one `given` — `Line::principal`'s answer, its refusal
/// already returned as exit 2 by the caller, before any read — else the
/// board's one binding in the store (§3.5's one-binding test). Where none is
/// chosen, the halt names the store read and the origin it was read for: a
/// store named wrongly, and an origin spelled otherwise than its binding's
/// (`localhost` for `127.0.0.1`), are the two causes the store alone cannot
/// tell from a principal never bound — so the bindings it holds at other
/// origins are named beside it — and where it holds several principals at
/// this one, it lists them.
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

/// The check a walk that takes no key file makes (`enroll`'s and
/// `retire`'s, which select their key from the store's lookup alone):
/// §3.5 owes `--key` (or `SKEP_KEY`) the lookup's first arm at those
/// commands, so a key file named there is refused — a usage refusal, ahead
/// of the door — never dropped for a key the person did not name.
pub fn require_no_key_file(c: &CommandLine) -> Result<(), Usage> {
    match c.key_file()? {
        Some(_) => Err(Usage(format!(
            "`--key` (or SKEP_KEY) names a key file, and `skep {}` selects its key from the store's lookup alone in this build: run it without either",
            c.command
        ))),
        None => Ok(()),
    }
}

/// The key file `key_file` names — `Line::key_file`'s answer, its refusal
/// already returned as exit 2 by the caller — else the store's key for this
/// board and principal (§3.5's lookup), its public facts judged for
/// `purpose`: an anchor file refused where the key signs and read where it
/// does not (§2.2's selection test; P11); its signer the store's
/// (`KeyStore::signer`). Where no key is selected, the arm-4 face forks on
/// the claimant, a `/health` read of its own (§3.5 arm 4): a board that
/// does not answer speaks first, its transport halt in place of the store's
/// face.
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
mod tests {
    use super::*;

    /// A program with no help, for the codes alone.
    const PROGRAM: Program = Program { name: "skep", help: "" };

    /// Every stop answers §2.3's code from the one renderer: a usage refusal
    /// 2, a halt the code its family carries, a store refusal faced as a
    /// halt, and a DATA write stdout refused a halt, 3.
    #[test]
    fn every_stop_finishes_with_its_exit_code() {
        assert_eq!(finish(PROGRAM, Ok(())), 0);
        assert_eq!(finish(PROGRAM, Err(Usage("a command is required".into()).into())), 2);
        assert_eq!(finish(PROGRAM, Err(Halt::face("state", "cause", "act").into())), 3);
        let refused = skep_client::Refused {
            status: 200,
            code: "credential_refused".into(),
            detail: None,
            op: None,
            body: serde_json::Value::Null,
        };
        assert_eq!(finish(PROGRAM, Err(Halt::Refused(refused).into())), 1);
        assert_eq!(
            finish(
                PROGRAM,
                Err(Halt::Dial(skep_client::DialError::Connect("refused".into())).into())
            ),
            4
        );
        assert_eq!(finish(PROGRAM, Err(StoreError::NotFound { select: "zz".into() }.into())), 3);
        assert_eq!(finish(PROGRAM, Err(data_refused(io::ErrorKind::BrokenPipe.into()).into())), 3);
    }

    /// Every transport halt carries an act, by where its exchange broke —
    /// nothing sent before the request was written, the read-back after it,
    /// the opening daemon and this client's bounds at a timeout — and a
    /// retry-class refusal the retry; `index_failed`'s 503, a `rejected`
    /// document and a face carry none beside their own.
    #[test]
    fn a_transport_halt_and_a_busy_board_name_their_act() {
        let act =
            |d: DialError| act_beside(&Halt::Dial(d)).expect("every transport halt carries an act");
        for unsent in
            [DialError::Connect("refused".into()), DialError::Resolve("no addresses".into())]
        {
            let a = act(unsent);
            assert!(
                a.starts_with("nothing was sent")
                    && a.contains("SKEP_BOARD where no flag is given"),
                "{a}"
            );
        }
        for broke in [
            DialError::Io("read".into()),
            DialError::Truncated { declared: 9, got: 3 },
            DialError::Tls("record".into()),
            DialError::Response("not http".into()),
            DialError::TooLarge { cap: 9 },
        ] {
            let a = act(broke);
            assert!(a.contains("read back"), "{a}");
        }
        let a = act(DialError::Timeout("read".into()));
        assert!(
            a.contains("still opening its journal")
                && a.contains("RUNBOOK.md §3, step 5")
                && a.contains(&format!(
                    "{} s for a connection and {} s on a read",
                    CONNECT_TIMEOUT.as_secs(),
                    IO_TIMEOUT.as_secs()
                ))
                && a.contains("reading back first"),
            "{a}"
        );
        assert!(act(DialError::NotHeld("https".into())).contains("`tls`"));
        assert!(act(DialError::Request("target".into())).starts_with("nothing was sent"));
        let refused = |status: u16, code: &str| {
            Halt::Refused(skep_client::Refused {
                status,
                code: code.into(),
                detail: None,
                op: None,
                body: serde_json::Value::Null,
            })
        };
        for busy in ["write_busy", "scan_busy", "history_busy", "feed_rebuilding"] {
            assert!(
                act_beside(&refused(503, busy))
                    .is_some_and(|a| a.contains("took nothing of this request")),
                "{busy}"
            );
        }
        assert_eq!(act_beside(&refused(503, "index_failed")), None, "the one 503 no retry clears");
        assert_eq!(act_beside(&refused(200, "credential_refused")), None);
        assert_eq!(
            act_beside(&Halt::face("state", "cause", "act")),
            None,
            "a face names its own act"
        );
    }

    /// A DATA line carries no control a board chose: each C0 control — a
    /// clipboard write's escape and bell, a carriage return, the line break
    /// that would forge a second line — shown as its code point; and a
    /// canonical record whose label holds a tab, DEL and a bidi control
    /// passes byte for byte, its encoder having escaped the tab and left the
    /// other two standing (AUTH-2.130 clause 3).
    #[test]
    fn a_data_line_renders_every_c0_control_and_passes_a_record_whole() {
        assert_eq!(
            c0_inert("claimed by 1.0.1\x1b]52;c;cHduZWQ=\x07\r\naccount 1.0.9"),
            "claimed by 1.0.1<U+001B>]52;c;cHduZWQ=<U+0007><U+000D><U+000A>account 1.0.9"
        );
        let key = skep_client::sheet::KeyFile::new(
            skep_client::sheet::Seed::new([7; 32]),
            false,
            None,
            None,
        )
        .public;
        let record = skep_identity::encode_enroll(&[skep_identity::Enrollment::new(
            key,
            false,
            Some("a\tb\u{7f}c\u{202e}d".into()),
        )
        .unwrap()]);
        assert!(
            record.contains('\u{7f}') && record.contains('\u{202e}') && !record.contains('\t'),
            "{record}"
        );
        assert!(matches!(c0_inert(&record), Cow::Borrowed(text) if text == record));
    }
}
