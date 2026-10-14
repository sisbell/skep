//! THE STATE DIRECTORY and what its two files share — the sign-up file
//! (`signups`) and the invite file (`invites`), whose every line carries an
//! address (`mail_address`'s value) and a date:
//!
//! * THE STATE DIRECTORY ([`StateDir`]) — `--state-dir`, owner-only: made
//!   `0700` where it does not stand, and REFUSED at start where it stands
//!   with any group or other bit set, as the daemon refuses its data
//!   directory (`skepd`'s `LooseDataDir`): the path, the mode found and the
//!   one act that fixes it, nothing repaired. Every file in it is born
//!   `0600`: the two files through the one writer below, and a lock file
//!   beside them through [`StateDir::open_lock_file`], held at that mode.
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

/// THE STATE FILES' MODE: `0600`, owner-only — the sign-up addresses and
/// the invite codes are no other user's to read — set exactly, whatever this
/// process's umask.
const STATE_FILE_MODE: u32 = 0o600;

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
    /// It could not be made or read, or its path names no directory —
    /// empty, or something other than a directory standing at it.
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
    /// THE DOOR: `path` made `0700` where nothing stands; where a directory
    /// stands, refused if any group or other bit is set — refuse, never
    /// repair; and refused where `path` is empty or something other than a
    /// directory stands at it.
    pub fn open(path: &Path) -> Result<StateDir, StateDirRefused> {
        let io_refused = |error| StateDirRefused::Io { path: path.to_path_buf(), error };
        // An empty path names no directory: none stands at it, and a
        // recursive making answers Ok for it having made none — so the two
        // files would land in the process's working directory, whose mode
        // the door never judged.
        if path.as_os_str().is_empty() {
            return Err(io_refused(io::Error::other("it names no directory")));
        }
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

    /// A LOCK FILE in it, by name, OPENED AND NOT LOCKED — its lock the
    /// caller's to take, and closing the file releases it: open for
    /// writing, made where it does not stand at [`STATE_FILE_MODE`], so never
    /// wider for an instant, and held at that mode exactly, whatever this
    /// process's umask, as every file in the directory is.
    pub fn open_lock_file(&self, name: &str) -> io::Result<fs::File> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(STATE_FILE_MODE);
        }
        let file = opts.open(self.file(name))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(STATE_FILE_MODE))?;
        }
        Ok(file)
    }
}

/// THE STATE FILES' WRITER: `bytes` become the file at `path`, whole, by
/// rename from its sibling `<file>.tmp`, at [`STATE_FILE_MODE`] —
/// [`whole::replace`]'s contract passed on whole: an error before the rename
/// leaves the old file and no temp file, one from the directory's sync after
/// it the new file in place, not known durable; and its PRECONDITION, the
/// caller's: no other write of `path` runs at once, which the sign-up file's
/// lock and the invite file's lock file keep — nothing here checks it.
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
