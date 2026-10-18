//! The state directory and what its two files share.
//!
//! The two files are the sign-up file (`signups`) and the invite file
//! (`invites`), whose every line this program composes carries an address
//! (`mail_address`'s value) and a date:
//!
//! * The state directory ([`StateDir`]) — `--state-dir`, owner-only: made
//!   `0700` where it does not stand, and refused at start where it stands
//!   with any group or other bit set, as the daemon refuses its data
//!   directory (`skepd`'s `LooseDataDir`), or where it stands another user's
//!   — the service's, to an `invite` run as root without `sudo -u` — whose
//!   service could not read a file this process made there: the path, what
//!   was found and the one act that fixes it, nothing repaired, and the
//!   directory left as it stood. Every file in it is born `0600`: the two
//!   files through the one writer below, and a lock file beside them through
//!   [`StateDir::open_lock_file`], held at that mode.
//! * The state files' one writer ([`write_whole`]) — `whole`'s replacement
//!   at [`STATE_FILE_MODE`], so every file in the directory is replaced
//!   whole by rename and born owner-only; the sign-up file is written
//!   through it alone, and the invite file through [`write_whole_with`], the
//!   same writer with its seam.
//! * The date ([`today`]) — `yyyy-mm-dd` in UTC, the date a line carries.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::whole;

/// The state files' mode: `0600`, owner-only.
///
/// The sign-up addresses and the invite codes are no other user's to read;
/// the mode is set exactly, whatever this process's umask.
const STATE_FILE_MODE: u32 = 0o600;

/// The owner's probe: a file the door makes in a state directory that stands.
///
/// The door reads its owner off and removes it at once — std holding no
/// other way to this process's own uid without `unsafe` — so the door knows,
/// before any state file is written there, whether this process is the
/// directory's owner. A name no state file takes; a stop's leftover is
/// removed first, as `whole` removes its temp file's.
#[cfg(unix)]
const OWNER_PROBE: &str = "owner.probe";

/// The state directory, opened: owner-only, standing, and this process's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDir {
    path: PathBuf,
}

/// A state directory refused at start.
#[derive(Debug)]
pub enum StateDirRefused {
    /// It stands with any group or other bit set.
    ///
    /// Such a bit may open it to other users of this machine.
    Loose {
        /// The directory as the operator named it.
        path: PathBuf,
        /// The mode found.
        mode: u32,
    },
    /// It stands another user's.
    ///
    /// This process, root among them, is not its owner — so a file this
    /// process made there would be one the owner's service could not read or
    /// replace.
    OwnedByAnother {
        /// The directory as the operator named it.
        path: PathBuf,
        /// The directory's owner's uid.
        owner: u32,
        /// This process's uid, as the door's probe read it.
        process: u32,
    },
    /// It could not be made, read or written, or its path names no directory.
    ///
    /// The write is the door's probe ([`OWNER_PROBE`]). A path names no
    /// directory where it is empty, or where something other than a
    /// directory stands at it.
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
            StateDirRefused::OwnedByAnother { path, owner, process } => write!(
                f,
                "the state directory {} is uid {owner}'s, and this process runs as uid {process}: a file it made there would be one the service cannot read or replace, so nothing in it is touched — run it as the directory's owner, `sudo -u <that user> skep-provision …` (RUNBOOK §10 step 7)",
                path.display()
            ),
            StateDirRefused::Io { path, error } => write!(f, "the state directory {}: {error}", path.display()),
        }
    }
}

impl std::error::Error for StateDirRefused {}

impl StateDir {
    /// Opens the state directory: the door, which refuses and never repairs.
    ///
    /// `path` is made `0700` where nothing stands.
    ///
    /// # Errors
    ///
    /// The first refusal met, in this order:
    ///
    /// 1. [`StateDirRefused::Io`] where `path` is empty, or where something
    ///    other than a directory stands at it.
    /// 2. Where a directory stands: [`StateDirRefused::Loose`] if any group or
    ///    other bit is set; then [`StateDirRefused::Io`] where the door's
    ///    probe ([`OWNER_PROBE`]) cannot be made, read or removed; then
    ///    [`StateDirRefused::OwnedByAnother`] where this process is not its
    ///    owner, the probe telling.
    /// 3. [`StateDirRefused::Io`] where nothing stands and the directory
    ///    cannot be made, or where whether anything stands cannot be read.
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
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    let mode = meta.permissions().mode() & 0o7777;
                    if mode & 0o077 != 0 {
                        return Err(StateDirRefused::Loose { path: path.to_path_buf(), mode });
                    }
                    // A directory this process does not own — `invite` run
                    // as root over the service's — is refused here, before
                    // any state file is written in it: a file made there
                    // would be root's, `0600`, and the service could read it
                    // no more.
                    owner_rule(path, meta.uid(), probed_uid(path).map_err(io_refused)?)?;
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

    /// Returns a file's path in it.
    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Opens a lock file in it, by name, and does not lock it.
    ///
    /// Its lock is the caller's to take, and closing the file releases it: it
    /// is open for writing, made where it does not stand at
    /// [`STATE_FILE_MODE`], so never wider for an instant, and held at that
    /// mode exactly, whatever this process's umask, as every file in the
    /// directory is.
    ///
    /// # Errors
    ///
    /// The open's, or the mode's where it cannot be set.
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

/// Checks the owner's rule: a state directory is opened by its owner alone.
///
/// Each file in it is `0600`, its maker's, so a file another user makes
/// there — root among them — is one the owner's service cannot read or
/// replace, and every post or sign-up that needs it fails after it.
///
/// # Errors
///
/// [`StateDirRefused::OwnedByAnother`] where `owner` is not `process`.
#[cfg(unix)]
fn owner_rule(path: &Path, owner: u32, process: u32) -> Result<(), StateDirRefused> {
    if owner == process {
        return Ok(());
    }
    Err(StateDirRefused::OwnedByAnother { path: path.to_path_buf(), owner, process })
}

/// Reads this process's uid off [`OWNER_PROBE`], made in `dir`.
///
/// The probe is removed at once.
///
/// # Errors
///
/// The directory's: a leftover probe that cannot be removed, or a probe
/// that cannot be made, read or removed — so one this process cannot write
/// is refused at the door, never at its first sign-up.
#[cfg(unix)]
fn probed_uid(dir: &Path) -> io::Result<u32> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let probe = dir.join(OWNER_PROBE);
    match fs::remove_file(&probe) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let uid = fs::OpenOptions::new().write(true).create_new(true).mode(STATE_FILE_MODE).open(&probe)?.metadata().map(|meta| meta.uid());
    fs::remove_file(&probe)?;
    uid
}

/// Writes `bytes` as the file at `path`, whole: the state files' writer.
///
/// The file is replaced by rename from its sibling `<file>.tmp`, at
/// [`STATE_FILE_MODE`] — [`whole::replace`]'s contract passed on whole.
///
/// **Precondition.** The caller's: no other write of `path` runs at once,
/// which the sign-up file's lock and the invite file's lock file keep —
/// nothing here checks it.
///
/// # Errors
///
/// An error before the rename leaves the old file and no temp file of this
/// call's; one from the directory's sync after it leaves the new file in
/// place, not known durable.
pub fn write_whole(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_whole_with(path, bytes, &|| Ok(()))
}

/// Writes as [`write_whole`] does, with `between` run before the rename.
///
/// `between` runs after the temp file is written and synced and before the
/// rename — the seam a test fails, to show a failure there leaves the old
/// file whole and no temp file behind.
///
/// # Errors
///
/// As [`write_whole`]'s; an error `between` answers is one before the
/// rename.
pub fn write_whole_with(path: &Path, bytes: &[u8], between: &dyn Fn() -> io::Result<()>) -> io::Result<()> {
    whole::replace(path, bytes, STATE_FILE_MODE, between)
}

/// Reads a file's text, or empty where it does not stand.
///
/// # Errors
///
/// The read's, where the file stands and cannot be read as text.
pub fn read_or_empty(path: &Path) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// Returns today, `yyyy-mm-dd` in UTC: the date a line carries.
pub fn today() -> String {
    civil_date(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
}

/// Returns `yyyy-mm-dd` from unix seconds, as `skep keygen` dates its boxes.
///
/// It is Howard Hinnant's civil-from-days.
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
