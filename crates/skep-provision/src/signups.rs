//! THE SIGN-UP FILE (the intake funnel's first arm: a field that takes an
//! address and keeps it in a file on the VM) — `<state-dir>/signups`, ONE
//! LINE PER ADDRESS, `<address> <date>`, written whole through the state
//! directory's one writer (`statedir`); a repeated address is one more line
//! — the owner reads the file by hand. AT MOST [`MAX_SIGNUPS_BYTES`]: a
//! sign-up needs no invite, and each rewrites the whole file, so past the
//! cap one is refused with no write until the owner trims the file. The
//! STRETCH AT THE CAP is counted under the file's own lock — each refusal
//! there told whether it opens the stretch, and the next sign-up kept told
//! how many it ends — so the log says the cap once and its end once, never
//! a line per request. THE ADDRESS IS THE ONE PERSONAL DATUM THIS PROGRAM
//! KEEPS; how long it is kept is the operator's to decide and say, and this
//! crate decides none. It is never logged.

use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::mail_address::MailAddress;
use crate::statedir::{read_or_empty, today, write_whole, StateDir};

/// The sign-up file's name in the state directory.
pub const SIGNUPS: &str = "signups";

/// THE FILE's CAP: 256 KiB. Each sign-up rewrites the whole file and syncs
/// it, so one request's bill — some 300 bytes sent, with no invite — grows
/// with every sign-up before it: uncapped, after 30,000 at the longest
/// address each further one would be 8 MB of synchronous writes, and a
/// stream of them would hold the VM's disk, every board's journal on it. At
/// the cap one sign-up is at most 256 KiB written and two syncs, reaching it
/// costs some 2.3 GB of writes once (at the shortest lines), and past it a
/// sign-up is refused with no write; at some 40 bytes a line it holds about
/// 6,500 sign-ups, the owner's to trim as they invite. The start says the
/// file's fill against it.
pub const MAX_SIGNUPS_BYTES: usize = 256 * 1024;

/// Why a sign-up is refused, AS THE LOG NAMES IT: the field, the file's cap,
/// or the file itself — three reasons the page shows as two answers
/// (`pages`' `SignUpRefusal`).
#[derive(Debug)]
pub enum SignUpRefused {
    /// The field is no address by the rule: nothing kept.
    NotAnAddress,
    /// The file is at its cap ([`MAX_SIGNUPS_BYTES`]): nothing kept.
    Full {
        /// The sign-ups refused at the cap since the last one kept, this one
        /// not among them: none where this refusal opens the stretch.
        refused_before: u64,
    },
    /// The file could not be read or written: nothing kept — or, the error
    /// coming from the directory's sync after the rename, the line kept,
    /// not known durable.
    Io(io::Error),
}

impl fmt::Display for SignUpRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignUpRefused::NotAnAddress => f.write_str("the field is no address by the rule"),
            SignUpRefused::Full { .. } => write!(f, "the sign-up file is at its {MAX_SIGNUPS_BYTES}-byte cap"),
            SignUpRefused::Io(e) => write!(f, "the sign-up file: {e}"),
        }
    }
}

impl std::error::Error for SignUpRefused {}

/// The file's own failure — a read or a rewrite that could not be made — as
/// `?` meets it.
impl From<io::Error> for SignUpRefused {
    fn from(e: io::Error) -> SignUpRefused {
        SignUpRefused::Io(e)
    }
}

/// A SIGN-UP KEPT, and the stretch at the file's cap it ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kept {
    /// The sign-ups refused at the file's cap since the last one kept: none
    /// where the file stood below its cap throughout.
    pub refused_at_cap: u64,
}

/// THE SIGN-UP FILE, one writer at a time: its path, and the refusals at its
/// cap since the last sign-up kept, held under the lock its writer takes —
/// so, under [`SignUps::new`]'s precondition, the file is reached through
/// the lock or not at all, the one writer `whole`'s replacement asks of
/// every path it replaces, and the stretch at the cap is counted in the very
/// order its sign-ups were judged.
#[derive(Debug)]
pub struct SignUps {
    file: Mutex<SignUpFile>,
}

/// The sign-up file as its one writer holds it.
#[derive(Debug)]
struct SignUpFile {
    /// Its path in the state directory.
    path: PathBuf,
    /// The sign-ups refused at its cap since the last one kept.
    refused_at_cap: u64,
}

impl SignUps {
    /// The sign-up file in `state_dir`. PRECONDITION, the caller's: no other
    /// `SignUps`, and no other process, appends to that file at once — this
    /// value's lock is its one writer only so far; `Service::new` makes the
    /// service's one, and no verb but `serve` writes the file. Nothing here
    /// checks it.
    pub fn new(state_dir: &StateDir) -> SignUps {
        SignUps { file: Mutex::new(SignUpFile { path: state_dir.file(SIGNUPS), refused_at_cap: 0 }) }
    }

    /// ONE SIGN-UP KEPT: the field's bytes, an address by the rule, appended
    /// as `<address> <date>` — the file read, the line added, the whole
    /// written back — and answered with the stretch at the cap it ends; a
    /// refused field, or a line that would carry the file past
    /// [`MAX_SIGNUPS_BYTES`], leaves the file as it was, a refusal at the cap
    /// counted into its stretch. Where two refusals hold, the field's speaks
    /// first — no address by the rule, the file untouched — then the file's,
    /// in the order met: a read that fails, the cap, a rewrite that fails.
    pub fn append(&self, field: &[u8]) -> Result<Kept, SignUpRefused> {
        let address = std::str::from_utf8(field).ok().and_then(MailAddress::parse).ok_or(SignUpRefused::NotAnAddress)?;
        let line = format!("{} {}\n", address.as_str(), today());
        let mut file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let mut text = read_or_empty(&file.path)?;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        if text.len() + line.len() > MAX_SIGNUPS_BYTES {
            let refused_before = file.refused_at_cap;
            file.refused_at_cap += 1;
            return Err(SignUpRefused::Full { refused_before });
        }
        text.push_str(&line);
        write_whole(&file.path, text.as_bytes())?;
        Ok(Kept { refused_at_cap: std::mem::take(&mut file.refused_at_cap) })
    }
}

/// HOW MANY BYTES the sign-up file in `state_dir` holds — none where it does
/// not stand — for the start to say against [`MAX_SIGNUPS_BYTES`], so the
/// operator reads the file filling before a sign-up meets its cap.
pub fn held_bytes(state_dir: &StateDir) -> io::Result<u64> {
    match fs::metadata(state_dir.file(SIGNUPS)) {
        Ok(meta) => Ok(meta.len()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests;
