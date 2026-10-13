//! THE INVITE FILE (the intake funnel's second arm, the gate on the claim
//! form; Q2 (a) as the funnel refined it): `<state-dir>/invites`, ONE LINE
//! PER INVITE —
//!
//! ```text
//! <code> <address> issued <date>
//! <code> <address> spent <name> <date>
//! ```
//!
//! — the address the invitation went to (the owner's hand sends it, in the
//! alpha), and the address the follow-up mail goes to once the board is
//! live. THE CODE IS AN OPAQUE STRING compared whole: 128 bits of OS
//! entropy as lowercase hex where `invite` mints one, or the value
//! `--code` hands in — so a later mint can hand in a document's address in
//! a random string's place, the format left open between the two — held to
//! the URL's unreserved characters ([`code_ok`]), so it rides the claim
//! address unescaped and a line splits on its spaces. A post naming a code
//! the file does not hold, or holds spent, is refused (the strings table's
//! DRAFT row); a code is SPENT on the first live route for a name and NOT
//! by a failed post, so the person may post again. The code is NEVER
//! LOGGED, and never shown but in the `invite` verb's one DATA line.
//!
//! THE FILE IS REWRITTEN WHOLE ([`crate::statedir::write_whole`]) at every
//! change, within the service and across processes alike, under an exclusive
//! lock on the sibling `invites.lock` — the service spends while the owner's
//! `invite` may mint, and neither change may be lost to the other's write.
//! A lookup reads the file as the last rename left it.

use std::fmt;
use std::fs::OpenOptions;
use std::io;

use crate::name::Name;
use crate::names::fresh_token;
use crate::statedir::{address_ok, read_or_empty, today, write_whole_with, StateDir};

/// The invite file's name in the state directory.
const INVITES: &str = "invites";

/// The lock file beside it: held exclusively over each read-and-rewrite,
/// by the service and by the `invite` verb alike.
const INVITES_LOCK: &str = "invites.lock";

/// A code's byte bound: room for a document's address, and no more.
pub const MAX_CODE_BYTES: usize = 128;

/// Where an invite stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteState {
    /// Issued on `date`, not yet spent.
    Issued {
        /// The day it was minted.
        date: String,
    },
    /// Spent on `date` by the board `name`.
    Spent {
        /// The board its post made.
        name: String,
        /// The day the board went live.
        date: String,
    },
}

/// One invite: one line of the file.
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    /// The code, opaque.
    pub code: String,
    /// The address it went to.
    pub address: String,
    /// Where it stands.
    pub state: InviteState,
}

/// The state alone: neither the code nor the address reaches a `{:?}`.
impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite").field("state", &self.state).finish_non_exhaustive()
    }
}

impl Invite {
    /// The invite's line, without its line break.
    fn line(&self) -> String {
        match &self.state {
            InviteState::Issued { date } => format!("{} {} issued {date}", self.code, self.address),
            InviteState::Spent { name, date } => format!("{} {} spent {name} {date}", self.code, self.address),
        }
    }

    /// One line read back; `None` for a line of no shape the file writes.
    fn parse(line: &str) -> Option<Invite> {
        let words: Vec<&str> = line.split(' ').collect();
        match words.as_slice() {
            [code, address, "issued", date] => Some(Invite { code: (*code).to_owned(), address: (*address).to_owned(), state: InviteState::Issued { date: (*date).to_owned() } }),
            [code, address, "spent", name, date] => {
                Some(Invite { code: (*code).to_owned(), address: (*address).to_owned(), state: InviteState::Spent { name: (*name).to_owned(), date: (*date).to_owned() } })
            }
            _ => None,
        }
    }

    /// Whether a post may still name it.
    pub fn issued(&self) -> bool {
        matches!(self.state, InviteState::Issued { .. })
    }
}

/// THE CODE's ALPHABET: 1 to [`MAX_CODE_BYTES`] of the URL's unreserved
/// characters — letters, digits, `-`, `.`, `_`, `~` — so the code rides the
/// claim address as it is and the file's line splits on its spaces.
pub fn code_ok(code: &str) -> bool {
    !code.is_empty() && code.len() <= MAX_CODE_BYTES && code.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// THE CLAIM ADDRESS an invite's link carries: `https://<suffix>/claim?invite=<code>`.
pub fn claim_address(suffix: &str, code: &str) -> String {
    format!("https://{suffix}/claim?invite={code}")
}

/// Every invite the file holds, in its order; a line of no shape the file
/// writes is passed over here, and kept as it stands by every rewrite.
fn read_all(dir: &StateDir) -> io::Result<Vec<Invite>> {
    Ok(read_lines(dir)?
        .into_iter()
        .filter_map(|line| match line {
            Line::Invite(invite) => Some(invite),
            Line::Other(_) => None,
        })
        .collect())
}

/// One line of the file: an invite, or a line of another shape — a hand
/// edit's — which a rewrite carries through as it stands.
enum Line {
    Invite(Invite),
    Other(String),
}

/// The file's lines, read.
fn read_lines(dir: &StateDir) -> io::Result<Vec<Line>> {
    Ok(read_or_empty(&dir.file(INVITES))?.lines().map(|text| Invite::parse(text).map_or_else(|| Line::Other(text.to_owned()), Line::Invite)).collect())
}

/// THE LOOKUP: the invite `code` names, compared whole, as the file stands.
pub fn lookup(dir: &StateDir, code: &str) -> io::Result<Option<Invite>> {
    Ok(read_all(dir)?.into_iter().find(|i| i.code == code))
}

/// Why `invite` mints nothing.
#[derive(Debug)]
pub enum MintRefused {
    /// The address is no address by the rule.
    Address,
    /// The `--code` value is outside the code's alphabet.
    Code,
    /// The file already holds the code.
    Duplicate,
    /// The file could not be read or written.
    Io(io::Error),
}

impl fmt::Display for MintRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MintRefused::Address => f.write_str("--address is not an address: one @ with a side each way, at most 254 bytes, no space and no control character"),
            MintRefused::Code => write!(f, "--code is not a code: 1 to {MAX_CODE_BYTES} letters, digits, '-', '.', '_' or '~'"),
            MintRefused::Duplicate => f.write_str("the invite file already holds that code"),
            MintRefused::Io(e) => write!(f, "the invite file: {e}"),
        }
    }
}

/// THE `invite` VERB's WORK: one invite minted to `address` — under the
/// code given, or a fresh one — appended `issued` today, the file rewritten
/// whole; the code answered, for the one DATA line.
pub fn mint(dir: &StateDir, address: &str, code: Option<&str>) -> Result<String, MintRefused> {
    if !address_ok(address) {
        return Err(MintRefused::Address);
    }
    let code = match code {
        Some(code) if code_ok(code) => code.to_owned(),
        Some(_) => return Err(MintRefused::Code),
        None => fresh_token().map_err(MintRefused::Io)?,
    };
    update(
        dir,
        |lines| {
            if invites(lines).any(|i| i.code == code) {
                return Err(MintRefused::Duplicate);
            }
            lines.push(Line::Invite(Invite { code: code.clone(), address: address.to_owned(), state: InviteState::Issued { date: today() } }));
            Ok(())
        },
        MintRefused::Io,
        &|| Ok(()),
    )?;
    Ok(code)
}

/// The invites among the lines, to change in place.
fn invites(lines: &mut [Line]) -> impl Iterator<Item = &mut Invite> {
    lines.iter_mut().filter_map(|line| match line {
        Line::Invite(invite) => Some(invite),
        Line::Other(_) => None,
    })
}

/// THE SPEND: `code`'s line rewritten `spent <name> <date>` — once the
/// board's route stands, and never otherwise. `false` where the file holds
/// no such code issued (a hand edit since the post); the board stands
/// either way.
pub fn spend(dir: &StateDir, code: &str, name: &Name) -> io::Result<bool> {
    spend_with(dir, code, name, &|| Ok(()))
}

/// [`spend`] with the writer's seam between the temp file and the rename.
fn spend_with(dir: &StateDir, code: &str, name: &Name, between: &dyn Fn() -> io::Result<()>) -> io::Result<bool> {
    update(
        dir,
        |lines| {
            let Some(invite) = invites(lines).find(|i| i.code == code && i.issued()) else {
                return Ok(false);
            };
            invite.state = InviteState::Spent { name: name.to_string(), date: today() };
            Ok(true)
        },
        |e| e,
        between,
    )
}

/// ONE CHANGE to the file, made whole: the lock file held exclusively, the
/// file's lines read, `change` applied, and — where it answers `Ok` — every
/// line written back through the state files' writer, a line of another
/// shape as it stood.
fn update<T, E>(dir: &StateDir, change: impl FnOnce(&mut Vec<Line>) -> Result<T, E>, io_err: impl Fn(io::Error) -> E, between: &dyn Fn() -> io::Result<()>) -> Result<T, E> {
    let lock = OpenOptions::new().create(true).truncate(false).write(true).open(dir.file(INVITES_LOCK)).map_err(&io_err)?;
    lock.lock().map_err(&io_err)?;
    let mut lines = read_lines(dir).map_err(&io_err)?;
    let answer = change(&mut lines)?;
    let text: String = lines
        .iter()
        .map(|line| match line {
            Line::Invite(invite) => invite.line() + "\n",
            Line::Other(text) => format!("{text}\n"),
        })
        .collect();
    write_whole_with(&dir.file(INVITES), text.as_bytes(), between).map_err(&io_err)?;
    // The lock is the open file's: closing it releases it.
    drop(lock);
    Ok(answer)
}

#[cfg(test)]
mod tests;
