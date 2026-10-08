//! THE DIRECTORY (`client.md` §4e.4), beside the key store in §3.1's form:
//!
//! ```text
//! <data>/index/                mode 0700 — BESIDE the key store, never inside it
//!   <chain>/                   H.1's chain, 64 lowercase hex — the board's key
//!     published.index          mode 0600 — the board's PUBLISHED index
//!     principal-<n>.index      mode 0600 — the SUPPLEMENT of principal n
//!     published.places         mode 0600 — the document index's published part (P39)
//!     principal-<n>.places     mode 0600 — the document index's part of principal n
//!     lock                     mode 0600 — the feeder's advisory lock (search.md §5.6)
//!     <name>.aside.<chain>.<n> mode 0600 — a MISPLACED file set aside under its own board's chain
//! ```
//!
//! `<data>` is the data directory the shell names — §6's rule puts
//! `index/` ALWAYS in the platform's LOCAL, NON-ROAMING application data;
//! this module takes the directory it is handed and places nothing itself.
//! The files are WRITTEN WHOLE BY RENAME (§4e.4; `search.md` §5.1): a
//! `<name>.tmp` beside the file, written, synced, renamed over the old, the
//! directory synced — so no reader ever opens a torn file and a crash
//! between the write and the rename leaves the old file as it was. A
//! misplaced file is MOVED ASIDE by a rename that NEVER OVERWRITES
//! (`search.md` §5.4; the crate spells the name, `aside_name`): the first
//! free ordinal, taken by a link that fails where the name is taken. The
//! modes are §3.3's — directories `0700`, files `0600`, set at creation and
//! never chmod'd after a world-readable moment (Windows has no modes; §6).
//! THE LOCK is the key store's idiom (§3.7): an advisory `flock` on `lock`,
//! held for the consumer's life, "dies with the process"; a second process
//! finding it held mounts nothing (`search.md` §5.6).

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use skep_search::{aside_name, Chain};

/// The feeder's lock file.
pub const LOCK_NAME: &str = "lock";

/// The published index's file.
const PUBLISHED: &str = "published";

/// `<data>/index/`: the search directory under the data directory the shell
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchDir {
    root: PathBuf,
}

impl SearchDir {
    /// `<data>/index/` under `data_dir`; nothing is created until a board's
    /// directory is.
    pub fn new(data_dir: impl Into<PathBuf>) -> SearchDir {
        SearchDir { root: data_dir.into().join("index") }
    }

    /// The `index/` directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The board's directory, keyed by `H.1`'s chain.
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
    /// The directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The board's chain, the directory's name.
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    /// The published index's file name.
    pub fn published_name() -> String {
        format!("{PUBLISHED}.index")
    }

    /// The supplement's file name for principal `n`.
    pub fn supplement_name(principal: u64) -> String {
        format!("principal-{principal}.index")
    }

    /// The document index's published part's file name.
    pub fn published_places_name() -> String {
        format!("{PUBLISHED}.places")
    }

    /// The document index's part for principal `n`.
    pub fn supplement_places_name(principal: u64) -> String {
        format!("principal-{principal}.places")
    }

    /// The path of `name` in this directory.
    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// The directory and `index/` above it, each `0700`, created once (§3.3);
    /// the umask irrelevant.
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

    /// THE FEEDER's LOCK (`search.md` §5.6; §3.7's idiom): `lock` opened
    /// `0600` and `flock`ed; `Some(file)` holds the lock for the file's life
    /// — it dies with the process — and `None` says another process holds
    /// it, the second shell's case.
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

    /// THE SAVE's FIRST STEP: `<name>.tmp` beside the file, created `0600`,
    /// written whole and synced — not yet the file. A crash here leaves the
    /// old file as it was.
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

    /// THE SAVE's SECOND STEP: the `.tmp` renamed over the old file, the
    /// directory synced.
    pub(crate) fn rename_tmp(&self, name: &str) -> io::Result<()> {
        fs::rename(self.file(&format!("{name}.tmp")), self.file(name))?;
        self.sync_dir()
    }

    /// THE SAVE BY RENAME (§4e.4): both steps.
    pub fn write_whole(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.write_tmp(name, bytes)?;
        self.rename_tmp(name)
    }

    /// THE ASIDE (`search.md` §5.4; §4e.4's last line): `name` renamed to
    /// `<name>.aside.<its own board's chain>.<n>`, `n` the first free
    /// ordinal, NEVER OVERWRITING — the name is taken by a hard link, which
    /// fails where it exists, and the original then unlinked; a second
    /// misplaced file of the same board lands beside the first. Answers the
    /// aside's path. The file's own chain is the caller's, off its header.
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

    /// The principals whose supplements rest here: every
    /// `principal-<n>.index`, in order.
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

    /// The directory synced, so a rename is durable before its caller goes
    /// on; a platform whose directories take no sync is no failure.
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
