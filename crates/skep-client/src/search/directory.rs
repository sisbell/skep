//! The directory (`client.md` §4e.4), beside the key store in §3.1's form.
//!
//! ```text
//! <data>/index/                mode 0700 — beside the key store, never
//!                              inside it
//!   <chain>/                   H.1's chain, 64 lowercase hex — the board's key
//!     published.index          mode 0600 — the board's published index
//!     principal-<n>.index      mode 0600 — the supplement of principal n
//!     published.places         mode 0600 — the document index's published
//!                              part (P39)
//!     principal-<n>.places     mode 0600 — the document index's part of
//!                              principal n
//!     lock                     mode 0600 — the feeder's advisory lock
//!                              (search.md §5.6)
//!     <name>.aside.<chain>.<n> mode 0600 — a misplaced file set aside under
//!                              its own board's chain
//! ```
//!
//! `<data>` is the data directory the shell names — §6's rule puts
//! `index/` always in the platform's local, non-roaming application data;
//! this module takes the directory it is handed and places nothing itself.
//! The files are written whole by rename (§4e.4; `search.md` §5.1): a
//! `<name>.tmp` beside the file, written, synced, renamed over the old, the
//! directory synced — so no reader ever opens a torn file and a crash
//! between the write and the rename leaves the old file as it was. A
//! misplaced file is moved aside by a rename that never overwrites
//! (`search.md` §5.4; the crate spells the name, `aside_name`): the first
//! free ordinal, taken by a link that fails where the name is taken. The
//! modes are §3.3's — directories `0700`, files `0600`, set at creation and
//! never chmod'd after a world-readable moment (Windows has no modes; §6).
//! The lock is the key store's idiom (§3.7): an advisory `flock` on `lock`,
//! held for the consumer's life, "dies with the process"; a second process
//! finding it held mounts nothing (`search.md` §5.6).

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use skep_search::{aside_name, Chain};

/// The feeder's lock file.
pub const LOCK_NAME: &str = "lock";

/// The stem of the published files, `published.index` and `published.places`.
const PUBLISHED: &str = "published";

/// `<data>/index/`, the search directory.
///
/// It lies under the data directory the shell names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchDir {
    root: PathBuf,
}

impl SearchDir {
    /// Returns `<data>/index/` under `data_dir`.
    ///
    /// Nothing is created until a board's directory is.
    pub fn new(data_dir: impl Into<PathBuf>) -> SearchDir {
        SearchDir { root: data_dir.into().join("index") }
    }

    /// Returns the `index/` directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the board's directory, keyed by `H.1`'s chain.
    pub fn board(&self, chain: &Chain) -> BoardDir {
        BoardDir { path: self.root.join(chain.to_string()), chain: *chain }
    }
}

/// `<data>/index/<chain>/`: one board's directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardDir {
    path: PathBuf,
    chain: Chain,
}

impl BoardDir {
    /// Returns the directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the board's chain, the directory's name.
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    /// Returns the published index's file name.
    pub fn published_name() -> String {
        format!("{PUBLISHED}.index")
    }

    /// Returns the supplement's file name for `principal`.
    pub fn supplement_name(principal: u64) -> String {
        format!("principal-{principal}.index")
    }

    /// Returns the document index's published part's file name.
    pub fn published_places_name() -> String {
        format!("{PUBLISHED}.places")
    }

    /// Returns the file name of the document index's part for `principal`.
    pub fn supplement_places_name(principal: u64) -> String {
        format!("principal-{principal}.places")
    }

    /// Returns the path of `name` in this directory.
    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Creates the directory and `index/` above it, each `0700` (§3.3).
    ///
    /// Each is created once; the umask is irrelevant.
    ///
    /// # Errors
    ///
    /// An I/O error creating either directory.
    pub fn ensure(&self) -> io::Result<()> {
        let mut dirs = vec![self.path.clone()];
        if let Some(parent) = self.path.parent() {
            dirs.insert(0, parent.to_path_buf());
        }
        for dir in dirs {
            if dir.is_dir() {
                continue;
            }
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&dir)?;
        }
        Ok(())
    }

    /// Takes the feeder's lock (`search.md` §5.6; §3.7's idiom).
    ///
    /// `lock` is opened `0600` and `flock`ed; `Some(file)` holds the lock
    /// for the file's life — it dies with the process — and `None` says
    /// another process holds it, the second shell's case.
    ///
    /// # Errors
    ///
    /// An I/O error opening `lock`, or taking the lock for a cause other than
    /// its being held.
    pub fn try_lock(&self) -> io::Result<Option<File>> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(self.file(LOCK_NAME))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(e)) => Err(e),
        }
    }

    /// Writes `<name>.tmp` beside the file, the save's first step.
    ///
    /// It is created `0600`, written whole and synced — not yet the file. A
    /// crash here leaves the old file as it was.
    ///
    /// # Errors
    ///
    /// An I/O error creating, writing or syncing the `.tmp`.
    pub(crate) fn write_tmp(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let tmp = self.file(&format!("{name}.tmp"));
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(tmp)
    }

    /// Renames the `.tmp` over the old file, the save's second step.
    ///
    /// The directory is then synced.
    ///
    /// # Errors
    ///
    /// An I/O error renaming, or syncing the directory.
    pub(crate) fn rename_tmp(&self, name: &str) -> io::Result<()> {
        fs::rename(self.file(&format!("{name}.tmp")), self.file(name))?;
        self.sync_dir()
    }

    /// Saves `bytes` as `name` by rename (§4e.4): both steps.
    ///
    /// # Errors
    ///
    /// Either step's I/O error.
    pub fn write_whole(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.write_tmp(name, bytes)?;
        self.rename_tmp(name)
    }

    /// Moves `name` aside (`search.md` §5.4; §4e.4's last line).
    ///
    /// It is renamed to `<name>.aside.<its own board's chain>.<n>`, `n` the
    /// first free ordinal, never overwriting — the name is taken by a hard
    /// link, which fails where it exists, and the original then unlinked; a
    /// second misplaced file of the same board lands beside the first.
    /// Answers the aside's path. The file's own chain is the caller's, off
    /// its header.
    ///
    /// # Errors
    ///
    /// An I/O error linking, unlinking or syncing the directory, other than
    /// a name already taken.
    ///
    /// # Panics
    ///
    /// Panics where the ordinals run out; they do not, so the `unreachable!`
    /// never fires.
    pub fn move_aside(&self, name: &str, own_chain: &Chain) -> io::Result<PathBuf> {
        let from = self.file(name);
        for n in 1u32.. {
            let to = self.file(&aside_name(name, own_chain, n));
            match fs::hard_link(&from, &to) {
                Ok(()) => {
                    fs::remove_file(&from)?;
                    self.sync_dir()?;
                    return Ok(to);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        unreachable!("the ordinals do not run out")
    }

    /// Returns the principals whose supplements rest here.
    ///
    /// They are every `principal-<n>.index`, in order.
    ///
    /// # Errors
    ///
    /// An I/O error reading the directory, save its absence, which answers
    /// none.
    pub fn supplements(&self) -> io::Result<Vec<u64>> {
        let entries = match fs::read_dir(&self.path) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut principals: Vec<u64> = entries
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name();
                let name = name.to_str()?;
                name.strip_prefix("principal-")?.strip_suffix(".index")?.parse().ok()
            })
            .collect();
        principals.sort_unstable();
        principals.dedup();
        Ok(principals)
    }

    /// Syncs the directory, so a rename is durable before its caller goes on.
    ///
    /// A platform whose directories take no sync is no failure.
    ///
    /// # Errors
    ///
    /// An I/O error opening or syncing the directory, save an unsupported
    /// sync.
    fn sync_dir(&self) -> io::Result<()> {
        match File::open(&self.path) {
            Ok(dir) => match dir.sync_all() {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Unsupported => Ok(()),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    }
}
