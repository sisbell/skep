//! THE SIGN-UP FILE (the intake funnel's first arm: a field that takes an
//! address and keeps it in a file on the VM) — `<state-dir>/signups`, ONE
//! LINE PER ADDRESS, `<address> <date>`, written whole through the state
//! directory's one writer (`statedir`); a repeated address is one more line
//! — the owner reads the file by hand. THE ADDRESS IS THE ONE PERSONAL DATUM
//! THIS PROGRAM KEEPS; how long it is kept is the operator's to decide and
//! say, and this crate decides none. It is never logged.

use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::statedir::{address_ok, read_or_empty, today, write_whole, StateDir};

/// The sign-up file's name in the state directory.
pub const SIGNUPS: &str = "signups";

/// A sign-up refused.
#[derive(Debug)]
pub enum SignUpRefused {
    /// The field is no address by the rule: nothing kept.
    NotAnAddress,
    /// The file could not be written: nothing kept.
    Io(io::Error),
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
    /// written back; a refused field leaves the file as it was.
    pub fn append(&self, field: &[u8]) -> Result<(), SignUpRefused> {
        let address = std::str::from_utf8(field).ok().filter(|a| address_ok(a)).ok_or(SignUpRefused::NotAnAddress)?;
        let _one_writer = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let mut text = read_or_empty(&self.path).map_err(SignUpRefused::Io)?;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!("{address} {}\n", today()));
        write_whole(&self.path, text.as_bytes()).map_err(SignUpRefused::Io)
    }
}

#[cfg(test)]
mod tests;
