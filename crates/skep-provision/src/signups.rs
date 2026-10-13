//! THE SIGN-UP FILE (the intake funnel's first arm: a field that takes an
//! address and keeps it in a file on the VM) — `<state-dir>/signups`, ONE
//! LINE PER ADDRESS, `<address> <date>`, written whole through the state
//! directory's one writer (`statedir`); a repeated address is one more line
//! — the owner reads the file by hand. AT MOST [`MAX_SIGNUPS_BYTES`]: a
//! sign-up needs no invite, and each rewrites the whole file, so past the
//! cap one is refused with no write until the owner trims the file. THE
//! ADDRESS IS THE ONE PERSONAL DATUM THIS PROGRAM KEEPS; how long it is kept
//! is the operator's to decide and say, and this crate decides none. It is
//! never logged.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::statedir::{read_or_empty, today, write_whole, MailAddress, StateDir};

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
/// 6,500 sign-ups, the owner's to trim as they invite.
const MAX_SIGNUPS_BYTES: usize = 256 * 1024;

/// A sign-up refused.
#[derive(Debug)]
pub enum SignUpRefused {
    /// The field is no address by the rule: nothing kept.
    NotAnAddress,
    /// The file is at its cap ([`MAX_SIGNUPS_BYTES`]): nothing kept.
    Full,
    /// The file could not be written: nothing kept.
    Io(io::Error),
}

impl fmt::Display for SignUpRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignUpRefused::NotAnAddress => f.write_str("the field is no address by the rule"),
            SignUpRefused::Full => write!(f, "the sign-up file is at its {MAX_SIGNUPS_BYTES}-byte cap"),
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

/// THE SIGN-UP FILE, one writer at a time.
#[derive(Debug)]
pub struct SignUps {
    path: PathBuf,
    write: Mutex<()>,
}

impl SignUps {
    /// The sign-up file in `dir`.
    pub fn new(dir: &StateDir) -> SignUps {
        SignUps { path: dir.file(SIGNUPS), write: Mutex::new(()) }
    }

    /// ONE SIGN-UP KEPT: the field's bytes, an address by the rule, appended
    /// as `<address> <date>` — the file read, the line added, the whole
    /// written back; a refused field, or a line that would carry the file
    /// past [`MAX_SIGNUPS_BYTES`], leaves the file as it was.
    pub fn append(&self, field: &[u8]) -> Result<(), SignUpRefused> {
        let address = std::str::from_utf8(field).ok().and_then(MailAddress::parse).ok_or(SignUpRefused::NotAnAddress)?;
        let line = format!("{} {}\n", address.as_str(), today());
        let _one_writer = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let mut text = read_or_empty(&self.path)?;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        if text.len() + line.len() > MAX_SIGNUPS_BYTES {
            return Err(SignUpRefused::Full);
        }
        text.push_str(&line);
        write_whole(&self.path, text.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
