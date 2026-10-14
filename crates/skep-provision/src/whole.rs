//! A KEPT FILE CHANGED DURABLY — the one way this program replaces or
//! removes a file it keeps, the state files (`statedir`) and the proxy's
//! snippets (`caddy`) alike.
//!
//! THE REPLACEMENT ([`replace`]) is WHOLE-THEN-RENAME: the bytes written to
//! the sibling `<file>.tmp` ([`temp_of`]) — made fresh where nothing stands
//! at its name, once whatever stood there is removed (a temp file a stop
//! left behind, or a link planted there), so the write follows no link into
//! another file — at the mode its owner names, set exactly before a byte is
//! written, so the umask neither widens nor narrows it; synced, then renamed
//! over the file (`std::fs::rename` is atomic within one filesystem, as this
//! crate knows POSIX — UNVERIFIED HERE), and the directory synced: a reader
//! finds the old file whole or the new one whole. A failure before the
//! rename leaves the old file whole and no temp file behind; the directory's
//! sync comes after the rename, so a failure there answers an error with
//! the new file in place, not known durable — an error is "the old file, or
//! the new one not known durable", never "the old file". THE REMOVAL
//! ([`remove`]) removes a file and syncs its directory: an error from the
//! unlink leaves the file standing, and one from that sync arrives with it
//! gone. ONE WRITER PER PATH is the caller's: every replacement of a file
//! shares its temp sibling — the sign-up file's mutex, the invite file's lock
//! file and the one worker that holds a board's name each keep it. The
//! owners name the modes: the state files `0600`, owner-only (`statedir`);
//! the snippets `0644`, readable by the proxy (`caddy`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// THE REPLACEMENT: `bytes` become the file at `path`, whole, at `mode`.
/// An error before the rename leaves the file as it was and no temp file of
/// this call's; an error from the directory's sync, after the rename,
/// leaves the new file in place, not known durable. PRECONDITION, the
/// caller's: no other replacement or removal of `path` runs at once.
/// `between` runs after the temp file is written and synced and before the
/// rename: the seam a test fails, to show a failure there leaves the old
/// file whole.
pub fn replace(path: &Path, bytes: &[u8], mode: u32, between: &dyn Fn() -> io::Result<()>) -> io::Result<()> {
    let tmp = temp_of(path);
    let written = (|| {
        // Whatever stands at the temp file's name goes first — a stop's
        // leftover, or a link planted there — and the temp file is made only
        // where nothing stands (O_CREAT|O_EXCL, which follows no link): a
        // link planted again in between fails the write, never redirects it.
        match fs::remove_file(&tmp) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        let mut file = opts.open(&tmp)?;
        set_mode(&file, mode)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        between()?;
        fs::rename(&tmp, path)?;
        sync_parent(path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// THE REMOVAL: the file at `path` gone — `true` where one stood, `false`
/// where none did — and its directory synced; an error from the unlink
/// leaves the file standing, and one from that sync arrives with it gone.
pub fn remove(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path).map(|()| true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// A file's temp sibling: `<file>.tmp`.
pub fn temp_of(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

/// The open file's mode set to `mode` exactly, on unix: the umask
/// notwithstanding.
fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (file, mode);
    Ok(())
}

/// `path`'s PARENT — the directory holding it — synced after a rename or a
/// removal, on unix; elsewhere there is nothing to open a directory with.
fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        File::open(if dir.as_os_str().is_empty() { Path::new(".") } else { dir })?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests;
