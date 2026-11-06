//! `skep restore`, the sixteenth command, over `skep_client::history`.
//!
//! Its design is B3-S7 — a draft's past state made current — and
//! `client.md` §4b.1's `history.restore` row, the library's two calls under
//! it: `past`, the reads, and `restore`, the one write. The board, the
//! draft and a position are named; the command reads the draft's state as
//! of that position and the correspondence records at the head, says what
//! the draft will hold — the runs and positions, how many of its words come
//! back as the published words they became, and the merge marker where the
//! draft carries one — then sends ONE `set_arrangement` typed against the
//! read, refused whole where the draft changed since, and prints one JSON
//! document on stdout, exit 0. The board's refusal is exit 1 under the code
//! the library's refusal is named for, through the renderer the commands
//! share (`commands.rs`'s `refused`); a halt is exit 3.
//!
//! **The marker is said, never taken out.** A restore to a state before a
//! merge landed leaves the draft's marker standing, so the draft's next
//! publication would still carry the merge's claim: the talk names the
//! marker before the write and the withdrawal beside it (`skep merge
//! --withdraw`), and the report carries it. A restore takes no merge out.
//!
//! **The way back.** The report's `as_of` is the position the draft stood
//! at before the restore — the one that puts the restore back, since the
//! command has no undo stack: `skep restore --draft <S> --at <as_of>`.
//!
//! The session is the command's own, as `merge`'s: the selected signing
//! key, a content-scoped signed session opened as `skep session` opens its
//! and closed on every exit. The write signs nothing, but the owned-home
//! test the records' read makes needs the session's account, which no token
//! in `SKEP_SESSION` carries, so `SKEP_SESSION` is never read here. No
//! person door: the command runs without a terminal.
//!
//! The report's members: `act` (`restore`), `draft`, `at`, `as_of`,
//! `position` (the write's), `runs` (what the write sent, each `origin`,
//! `i_start`, `width`), `extent` and `covered` (the state's positions, and
//! how many a record re-composed), `marker` (the merge marker as it stands,
//! `{at, head, head_copied, sides}`, else null). `--json` is every
//! command's flag and changes nothing here: the report is JSON always.

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::parse_address;
use skep_client::board::{Board, Scope};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::history::{past, restore as make_current, Past, Restored};
use skep_client::store::{KeySelector, KeyStore, Purpose};

use super::{
    board_of, data_verbatim, key_named, principal_or_bound, refused, select_key, store_of, talk,
    Step, Stop,
};
use crate::args::{CommandLine, Usage};

/// What the command line asks, judged whole before any socket opens.
///
/// §2.3's exit 2 is the flags' shape alone.
struct Asked {
    /// The draft put back.
    draft: Address,
    /// The position its state is read as of.
    at: u64,
}

impl Asked {
    /// Reads the line whole, before any socket opens.
    ///
    /// # Errors
    ///
    /// In this order: `--draft` absent or no address; `--at` absent or no
    /// position — a non-negative integer, a commit's number as the change
    /// feed and the acknowledgments give it.
    fn of(c: &CommandLine) -> Result<Asked, Usage> {
        let draft = match c.value("--draft") {
            Some(d) => parse_address(d).ok_or_else(|| {
                Usage(format!("--draft: '{d}' is not an address (the wire's dotted spelling)"))
            })?,
            None => return Err(Usage("--draft <S> is required: the draft to put back".into())),
        };
        let at = match c.value("--at") {
            Some(n) => n.parse::<u64>().map_err(|_| {
                Usage(format!("--at: '{n}' is not a position (a non-negative integer, a commit's number on the change feed)"))
            })?,
            None => {
                return Err(Usage(
                    "--at <n> is required: the position the draft is put back to".into(),
                ))
            }
        };
        Ok(Asked { draft, at })
    }
}

pub fn restore(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    let asked = Asked::of(c)?;
    // The plaintext non-loopback warning, ahead of everything a signed
    // session needs (AUTH-4.53; §9 item 23: a warning, never a refusal).
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let principal = principal_or_bound(given, &store, &board)?;
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Sign)?;
    let signer = store.signer(&KeySelector::Path(&key.path))?;
    // Content scope, as `skep session` opens its (RES-63): the one write is
    // a content write under this account.
    let session = handshake(&board, Scope::Content, &*signer, principal, Site::Session)?;
    talk(format!(
        "restoring as principal {principal} at account {} with key {}",
        session.account(),
        key_named(&key)
    ));
    let outcome = run(&board, &session, &asked);
    // The session is closed on every exit; a close the board refuses speaks
    // only where the run itself passed.
    match session.close() {
        Ok(_) => outcome,
        Err(h) => {
            outcome?;
            Err(h.into())
        }
    }
}

/// Runs the act under the session: the reads, the statement, the one write
/// and the report.
///
/// # Errors
///
/// Returns a library refusal (`refused`) from the reads or the write, and
/// the halt a write stdout refuses comes to.
fn run(board: &Board, session: &Session<'_>, asked: &Asked) -> Result<(), Stop> {
    let Asked { draft, at } = asked;
    talk(format!("restoring {draft} to how it stood at position {at}, at {}", board.dialed()));
    let p = past(board, session.token(), session.account(), draft, *at)
        .map_err(|r| refused(r, Step::Restore))?;
    say_past(&p);
    let restored = make_current(board, session.token(), &p).map_err(|r| refused(r, Step::Restore))?;
    say_restored(&p, &restored);
    data_verbatim(report(&p, &restored).to_string().as_bytes())?;
    Ok(())
}

/// Says the statement before the write: what the draft held at the
/// position — its positions and runs, how many come back as the published
/// words they became — and the merge marker where one stands, with the
/// withdrawal named beside it.
fn say_past(p: &Past) {
    let (extent, runs, covered) = (p.extent(), p.sent.len() as u64, p.covered());
    talk(format!(
        "at position {} {} held {extent} position{} in {runs} run{}{}",
        p.at,
        p.draft,
        plural(extent),
        plural(runs),
        if covered > 0 {
            format!("; {covered} of them come back as the published words they became")
        } else {
            String::new()
        }
    ));
    if let Some(m) = &p.marker {
        let at = m.at.map_or_else(
            || "a position the board did not name".to_string(),
            |a| format!("position {a}"),
        );
        let sides = if m.sides.is_empty() {
            String::new()
        } else {
            format!(", with the side{} {}", plural(m.sides.len() as u64), m.sides.join(", "))
        };
        talk(format!(
            "{} carries a merge landed at {at}, composed on {}{sides}; the restore leaves it standing — to take the merge out and keep the words, run `skep merge --withdraw {} --kind <address>`",
            p.draft, m.head, p.draft
        ));
    }
}

/// Says the talk after the write: the draft holds what it held, and the
/// position that puts the restore back.
fn say_restored(p: &Past, r: &Restored) {
    talk(format!(
        "restored {} at position {}: it holds what it held at position {}; to put it back as it stood before this restore, run `skep restore --draft {} --at {}`",
        r.draft, r.position, r.at, r.draft, p.as_of
    ));
}

/// Returns the restore as the report carries it (the module's doc).
fn report(p: &Past, r: &Restored) -> Value {
    let runs: Vec<Value> = p
        .sent
        .iter()
        .map(|run| {
            json!({
                "origin": run.origin.to_string(),
                "i_start": run.address_at(0).map(|a| a.to_string()),
                "width": run.width.to_string(),
            })
        })
        .collect();
    json!({
        "act": "restore",
        "draft": r.draft.to_string(),
        "at": r.at,
        "as_of": p.as_of,
        "position": r.position,
        "runs": runs,
        "extent": p.extent(),
        "covered": p.covered(),
        "marker": p.marker.as_ref().map(|m| json!({"at": m.at, "head": m.head, "head_copied": m.head_copied.map(|c| c.to_string()), "sides": m.sides})),
    })
}

/// Returns the plural's `s` where `n` is not one.
fn plural(n: u64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}
