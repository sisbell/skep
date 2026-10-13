//! THE STATE DIRECTORY and what its two files share — the sign-up file
//! (`signups`) and the invite file (`invites`), whose every line carries an
//! address and a date:
//!
//! * THE ADDRESS RULE ([`address_ok`]) — the minimum the files and the
//!   mail's header need, and no more: one `@` with a non-empty side each
//!   way, at most 254 bytes, no control character and no whitespace — so an
//!   address is one line's one field and one header's one recipient. It
//!   checks no domain and sends nothing. ITS VALUE ([`MailAddress`]) is the
//!   rule's one door: every address that comes in — the three flags that
//!   take one, `--reply-to`, `--from` and `--address`, and the sign-up
//!   field — is one only once [`MailAddress::parse`] admits it.
//! * THE STATE DIRECTORY ([`StateDir`]) — `--state-dir`, owner-only: made
//!   `0700` where it does not stand, and REFUSED at start where it stands
//!   with any group or other bit set, as the daemon refuses its data
//!   directory (`skepd`'s `LooseDataDir`): the path, the mode found and the
//!   one act that fixes it, nothing repaired. Every file in it is born
//!   `0600`.
//! * THE STATE FILES' ONE WRITER ([`write_whole`]) — `whole`'s replacement
//!   at [`STATE_FILE_MODE`], so every file in the directory is replaced
//!   whole by rename and born owner-only; the sign-up file and the invite
//!   file are written through it alone.
//! * THE DATE ([`today`]) — `yyyy-mm-dd` in UTC, the date a line carries.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::whole;

/// An address's byte bound: 254, the longest a mail path carries, as this
/// crate knows mail (UNVERIFIED HERE).
const MAX_ADDRESS_BYTES: usize = 254;

/// THE STATE FILES' MODE: `0600`, owner-only — the sign-up addresses and
/// the invite codes are no other user's to read — set exactly, whatever this
/// process's umask.
const STATE_FILE_MODE: u32 = 0o600;

/// THE ADDRESS RULE: one `@` with a non-empty side each way, at most
/// [`MAX_ADDRESS_BYTES`] bytes, no control character, no whitespace.
fn address_ok(address: &str) -> bool {
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && !domain.contains('@') && address.len() <= MAX_ADDRESS_BYTES && !address.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// AN ADDRESS BY THE RULE: [`MailAddress::parse`] is the only way to one,
/// so a value of this type is one line's one field and one header's one
/// recipient. Its `Debug` shows none of it: an address is never a log
/// line's.
#[derive(Clone, PartialEq, Eq)]
pub struct MailAddress(String);

impl MailAddress {
    /// `text` as an address, where the rule admits it.
    pub fn parse(text: &str) -> Option<MailAddress> {
        address_ok(text).then(|| MailAddress(text.to_owned()))
    }

    /// The address as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Nothing of the address: a `{:?}` can carry none of it.
impl fmt::Debug for MailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MailAddress(…)")
    }
}

/// THE STATE DIRECTORY, opened: owner-only, standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDir {
    path: PathBuf,
}

/// A state directory refused at start.
#[derive(Debug)]
pub enum StateDirRefused {
    /// It stands, and other users of this machine can read it.
    Loose {
        /// The directory as the operator named it.
        path: PathBuf,
        /// The mode found.
        mode: u32,
    },
    /// It could not be made or read.
    Io {
        /// The directory as the operator named it.
        path: PathBuf,
        /// What failed.
        error: io::Error,
    },
}

impl fmt::Display for StateDirRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateDirRefused::Loose { path, mode } => write!(
                f,
                "the state directory {} is mode {mode:o}: other users of this machine can read the sign-up addresses and the invite codes; chmod 700 {} and start again",
                path.display(),
                path.display()
            ),
            StateDirRefused::Io { path, error } => write!(f, "the state directory {}: {error}", path.display()),
        }
    }
}

impl std::error::Error for StateDirRefused {}

impl StateDir {
    /// THE DOOR: `path` made `0700` where it does not stand; where it
    /// stands, refused if any group or other bit is set — refuse, never
    /// repair.
    pub fn open(path: &Path) -> Result<StateDir, StateDirRefused> {
        let io_refused = |error| StateDirRefused::Io { path: path.to_path_buf(), error };
        match fs::metadata(path) {
            Ok(meta) if !meta.is_dir() => return Err(io_refused(io::Error::other("it is not a directory"))),
            Ok(meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode() & 0o7777;
                    if mode & 0o077 != 0 {
                        return Err(StateDirRefused::Loose { path: path.to_path_buf(), mode });
                    }
                }
                #[cfg(not(unix))]
                let _ = meta;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(path).map_err(io_refused)?;
            }
            Err(e) => return Err(io_refused(e)),
        }
        Ok(StateDir { path: path.to_path_buf() })
    }

    /// A file's path in it.
    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

/// THE STATE FILES' WRITER: `bytes` become the file at `path`, whole, by
/// rename from its sibling `<file>.tmp`, at [`STATE_FILE_MODE`].
pub fn write_whole(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_whole_with(path, bytes, &|| Ok(()))
}

/// [`write_whole`] with `between` run after the temp file is written and
/// synced and before the rename — the seam a test fails, to show a failure
/// there leaves the old file whole and no temp file behind.
pub fn write_whole_with(path: &Path, bytes: &[u8], between: &dyn Fn() -> io::Result<()>) -> io::Result<()> {
    whole::replace(path, bytes, STATE_FILE_MODE, between)
}

/// A file's text, or empty where it does not stand.
pub fn read_or_empty(path: &Path) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// TODAY, `yyyy-mm-dd` in UTC: the date a line carries.
pub fn today() -> String {
    civil_date(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
}

/// `yyyy-mm-dd` from unix seconds (Howard Hinnant's civil-from-days), as
/// `skep keygen` dates its boxes.
fn civil_date(secs: u64) -> String {
    let z = (secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests;
