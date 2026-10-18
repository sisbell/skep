//! The invite file: `<state-dir>/invites`, one line per invite.
//!
//! It is the intake funnel's second arm, the gate on the claim form (Q2 (a)
//! as the funnel refines it):
//!
//! ```text
//! <code> <address> issued <date>
//! <code> <address> spent <name> <date>
//! ```
//!
//! — the address the invitation went to (the owner's hand sends it, in the
//! alpha), and the address the follow-up mail goes to once the board is
//! live. The code is an [`InviteCode`] (`invite_code`), compared whole, and
//! every door hands one on as that value — the `invite` verb's `--code` and
//! the claim post's field alike — and the address to mint to as a
//! [`MailAddress`], so nothing reaches the file that its line cannot carry.
//! A post naming a code the file does not hold, or holds spent, is refused
//! (the strings table's `DRAFT` row); a code is spent on the first live route
//! for a name and not by a failed post, so the person may post again. The
//! code is never logged, and never shown but in the `invite` verb's one data
//! line and back on the claim form to the one whose link or post carried it.
//!
//! The file is rewritten whole ([`crate::statedir::write_whole_with`], the
//! state files' writer) at every change, within the service and across
//! processes alike, under an exclusive lock on the sibling `invites.lock` —
//! the service spends while the owner's `invite` may mint, and neither change
//! may be lost to the other's write. A lookup reads the file as the last
//! rename left it.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::invite_code::InviteCode;
use crate::mail_address::MailAddress;
use crate::name::Name;
use crate::names::{unguessable, NoEntropy};
use crate::statedir::{read_or_empty, today, write_whole_with, StateDir};

/// The invite file's name in the state directory.
const INVITES: &str = "invites";

/// The lock file beside it.
///
/// It is held exclusively over each read-and-rewrite, by the service and by
/// the `invite` verb alike.
const INVITES_LOCK: &str = "invites.lock";

/// An invite's state: issued, then spent.
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
    code: String,
    /// The address it went to, as the line holds it.
    ///
    /// The mint puts it there through the address rule, and it is read back
    /// as the operator's hand may have left it — never checked again.
    pub address: String,
    /// Its state.
    pub state: InviteState,
}

/// The state alone: neither the code nor the address reaches a `{:?}`.
impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite").field("state", &self.state).finish_non_exhaustive()
    }
}

impl Invite {
    /// Returns the invite's line, without its line break.
    fn line(&self) -> String {
        match &self.state {
            InviteState::Issued { date } => format!("{} {} issued {date}", self.code, self.address),
            InviteState::Spent { name, date } => format!("{} {} spent {name} {date}", self.code, self.address),
        }
    }

    /// Parses one line read back.
    ///
    /// It answers `None` for a line of no shape the file writes.
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

    /// Returns whether a post may still name it.
    pub fn issued(&self) -> bool {
        matches!(self.state, InviteState::Issued { .. })
    }
}

/// Reads every invite the file holds, in its order.
///
/// It reads its invites alone: a line of no shape the file writes is passed
/// over here, and kept as it stands by every rewrite.
///
/// # Errors
///
/// The file's, where it cannot be read.
fn read_invites(state_dir: &StateDir) -> io::Result<Vec<Invite>> {
    Ok(read_lines(state_dir)?
        .into_iter()
        .filter_map(|line| match line {
            Line::Invite(invite) => Some(invite),
            Line::Other(_) => None,
        })
        .collect())
}

/// One line of the file: an invite, or a line of another shape.
///
/// A line of another shape is a hand edit's, which a rewrite carries through
/// as it stands.
enum Line {
    Invite(Invite),
    Other(String),
}

/// Reads the file's lines.
///
/// # Errors
///
/// The file's, where it cannot be read.
fn read_lines(state_dir: &StateDir) -> io::Result<Vec<Line>> {
    Ok(read_or_empty(&state_dir.file(INVITES))?.lines().map(|text| Invite::parse(text).map_or_else(|| Line::Other(text.to_owned()), Line::Invite)).collect())
}

/// Looks up the invite `code` names, compared whole, as the file stands.
///
/// # Errors
///
/// The file's, where it cannot be read.
pub fn lookup(state_dir: &StateDir, code: &InviteCode) -> io::Result<Option<Invite>> {
    Ok(read_invites(state_dir)?.into_iter().find(|i| i.code == code.as_str()))
}

/// Returns the invite file's path in `state_dir`, for a line to name it by.
///
/// It is the file a failure met, and the one a refusal looked in — so the
/// operator who minted into a file reads whether the service reads the same.
pub fn path(state_dir: &StateDir) -> PathBuf {
    state_dir.file(INVITES)
}

/// Counts the invites the file holds issued, as it stands.
///
/// It is the figure a refusal of a code the file does not hold says beside
/// it, read only where that line is said.
///
/// # Errors
///
/// The file's, where it cannot be read.
pub fn issued_count(state_dir: &StateDir) -> io::Result<usize> {
    Ok(read_invites(state_dir)?.iter().filter(|i| i.issued()).count())
}

/// Returns the names spent under, as the file stands.
///
/// They are every board a line of the file is spent under — what the sweep
/// at start holds the boards routed at start against, a routed board under
/// the label with none spent under it one whose spend a stop cut off after
/// its snippet's write, or which could not be written, or whose spent line a
/// hand removed — its invite maybe still issued.
///
/// # Errors
///
/// The file's, where it cannot be read.
pub fn spent_names(state_dir: &StateDir) -> io::Result<BTreeSet<String>> {
    Ok(read_invites(state_dir)?
        .into_iter()
        .filter_map(|invite| match invite.state {
            InviteState::Spent { name, .. } => Some(name),
            InviteState::Issued { .. } => None,
        })
        .collect())
}

/// Why `invite` answers no invite link.
#[derive(Debug)]
pub enum MintRefused {
    /// The file already holds the code: no invite minted.
    Duplicate,
    /// No fresh code could be drawn: the OS gave no entropy.
    ///
    /// No invite is minted, and the file is not touched.
    Entropy(NoEntropy),
    /// The file could not be locked, read or written: no invite minted.
    ///
    /// Or, the error coming from the directory's sync after the rename, the
    /// invite is minted and its link unprinted: `invite` again mints another
    /// under a fresh code, and under the same `--code` answers that the file
    /// already holds it, the invite link then the one that code makes,
    /// `https://<suffix>/claim?invite=<code>`.
    Io(io::Error),
}

impl fmt::Display for MintRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MintRefused::Duplicate => f.write_str("the invite file already holds that code"),
            MintRefused::Entropy(e) => write!(f, "a fresh code: {e}"),
            MintRefused::Io(e) => write!(f, "the invite file: {e}"),
        }
    }
}

impl std::error::Error for MintRefused {}

/// The file's own failure, as `?` meets it.
///
/// It is a lock, a read or a rewrite that could not be made.
impl From<io::Error> for MintRefused {
    fn from(e: io::Error) -> MintRefused {
        MintRefused::Io(e)
    }
}

/// A fresh code's own failure, as `?` meets it.
///
/// It is the OS's entropy's, never the file's.
impl From<NoEntropy> for MintRefused {
    fn from(e: NoEntropy) -> MintRefused {
        MintRefused::Entropy(e)
    }
}

/// Mints one invite to `address`: the `invite` verb's work.
///
/// The invite is minted under the code given, or a fresh one, appended
/// `issued` today, the file rewritten whole; the code is answered as its own
/// value, for the one data line. Both values come in their own types — an
/// address by the rule, a code in the alphabet — so nothing reaches the file
/// that its line cannot carry.
///
/// # Errors
///
/// - [`MintRefused::Entropy`]: no fresh code can be drawn. A fresh code is
///   drawn before the file is touched, so the refusal is that alone, the file
///   as it was.
/// - [`MintRefused::Io`]: the lock file or the file cannot be opened, locked
///   or read.
/// - [`MintRefused::Duplicate`]: the file already holds the code.
/// - [`MintRefused::Io`]: the rewrite fails — no invite minted, or, at the
///   directory's sync after the rename, the invite minted.
pub fn mint(state_dir: &StateDir, address: &MailAddress, code: Option<InviteCode>) -> Result<InviteCode, MintRefused> {
    let code = match code {
        Some(code) => code,
        None => InviteCode::parse(&unguessable()?).expect("an unguessable value, 32 lowercase hex digits, is in the alphabet"),
    };
    update(
        state_dir,
        |lines| {
            if invites(lines).any(|i| i.code == code.as_str()) {
                return Err(MintRefused::Duplicate);
            }
            lines.push(Line::Invite(Invite { code: code.as_str().to_owned(), address: address.as_str().to_owned(), state: InviteState::Issued { date: today() } }));
            Ok(())
        },
        &|| Ok(()),
    )?;
    Ok(code)
}

/// Returns the invites among the lines, to change in place.
fn invites(lines: &mut [Line]) -> impl Iterator<Item = &mut Invite> {
    lines.iter_mut().filter_map(|line| match line {
        Line::Invite(invite) => Some(invite),
        Line::Other(_) => None,
    })
}

/// Spends `code`: its line rewritten `spent <name> <date>`.
///
/// The spend is made once the board's route stands, and never otherwise. It
/// answers `false` where the file holds no such code issued (a hand edit
/// since the post); the board stands either way.
///
/// # Errors
///
/// An error is "not spent, or spent and not known durable": the directory's
/// sync comes after the rename.
pub fn spend(state_dir: &StateDir, code: &InviteCode, name: &Name) -> io::Result<bool> {
    spend_with(state_dir, code, name, &|| Ok(()))
}

/// Spends as [`spend`] does, with the writer's seam.
///
/// The seam runs between the temp file and the rename.
///
/// # Errors
///
/// As [`spend`]'s.
fn spend_with(state_dir: &StateDir, code: &InviteCode, name: &Name, between: &dyn Fn() -> io::Result<()>) -> io::Result<bool> {
    update(
        state_dir,
        |lines| {
            let Some(invite) = invites(lines).find(|i| i.code == code.as_str() && i.issued()) else {
                return Ok(false);
            };
            invite.state = InviteState::Spent { name: name.to_string(), date: today() };
            Ok(true)
        },
        between,
    )
}

/// Makes one change to the file, whole.
///
/// The lock file is held exclusively, the file's lines read, `change`
/// applied, and — where it answers `Ok` — every line written back through
/// the state files' writer, a line of another shape as it stood.
///
/// # Errors
///
/// `change`'s own refusal, nothing written; and the file's own failure — the
/// lock, the read, the rewrite — which reaches the caller's `E` through its
/// `From<io::Error>`.
fn update<T, E: From<io::Error>>(state_dir: &StateDir, change: impl FnOnce(&mut Vec<Line>) -> Result<T, E>, between: &dyn Fn() -> io::Result<()>) -> Result<T, E> {
    let lock = state_dir.open_lock_file(INVITES_LOCK)?;
    lock.lock()?;
    let mut lines = read_lines(state_dir)?;
    let answer = change(&mut lines)?;
    let text: String = lines
        .iter()
        .map(|line| match line {
            Line::Invite(invite) => invite.line() + "\n",
            Line::Other(text) => format!("{text}\n"),
        })
        .collect();
    write_whole_with(&state_dir.file(INVITES), text.as_bytes(), between)?;
    // The lock is the open file's: closing it releases it.
    drop(lock);
    Ok(answer)
}

#[cfg(test)]
mod tests;
