//! THE FILES, `<root>/<designation>/<hex>`: where a file lives, the
//! spellings a designation and a hex name must have, the ASIDE name a
//! replaced file carries until the deferred unlink, the directory fsync
//! every install order under the root ends in (a rename is durable only at
//! its directory's fsync — `media.md` Op inventory 1; the register M-I5
//! (a)), and the floor's one read of the host, the volume's free space. The
//! order that installs a file is the store's (`store.rs`); the logs' is
//! `jsonl.rs`'s.

use std::io;
use std::path::{Path, PathBuf};

/// The prefix of an aside name: `.retired-<hex>-<n>`, the second name a
/// replaced file carries from the finish's link until the deferred unlink.
/// The leading dot keeps it apart from any hex name, as the partial's is.
/// Nothing names an aside — no lease, no cell — so every reader of a
/// designation directory passes over one, and the pruner's pass and open's
/// reconciliation (`partials::reconcile`) remove it.
const ASIDE_PREFIX: &str = ".retired-";

/// The aside name of the `n`th replace of `hex` this process makes.
pub(crate) fn aside_name(hex: &str, n: u64) -> String {
    format!("{ASIDE_PREFIX}{hex}-{n}")
}

/// Whether a directory entry's name is an aside's.
pub(crate) fn is_aside_name(name: &str) -> bool {
    name.starts_with(ASIDE_PREFIX)
}

/// A designation's spelling: lowercase letters, digits and `-`, nonempty,
/// never a name a hex could be mistaken for or a path could escape by.
pub(crate) fn designation_ok(designation: &str) -> bool {
    !designation.is_empty()
        && designation.len() <= 32
        && designation.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A hex name's spelling: lowercase hex, an even length between 2 and 128.
pub(crate) fn hex_ok(hex: &str) -> bool {
    hex.len() >= 2
        && hex.len() <= 128
        && hex.len() % 2 == 0
        && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Fsync a directory, so entry creations, removals and renames inside it
/// are durable (the kernel's own discipline, `journal/segment.rs`). On a
/// non-unix target this is a no-op; v1 targets unix.
pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// The volume's free space at `path`, in bytes — what the floor reads: the
/// blocks available to an unprivileged writer times the fragment size.
pub(crate) fn free_space(path: &Path) -> io::Result<u64> {
    let v = rustix::fs::statvfs(path).map_err(io::Error::from)?;
    Ok(v.f_bavail.saturating_mul(v.f_frsize))
}

/// The path of a blob under `root`.
pub(crate) fn blob_path(root: &Path, designation: &str, hex: &str) -> PathBuf {
    root.join(designation).join(hex)
}
