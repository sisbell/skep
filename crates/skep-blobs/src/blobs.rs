//! THE FILES, `<root>/<designation>/<hex>`: where a file lives, the
//! spellings a designation and a hex name must have, the ASIDE name a
//! replaced file carries until the deferred unlink, the listings of the
//! directories that hold those names and open's sweep of the asides
//! ([`sweep_asides`]), the removal of a name another remover may have
//! taken first ([`remove_if_present`]), the directory fsync every install
//! order under the root ends in (a rename is durable only at its
//! directory's fsync — `media.md` Op inventory 1; the register M-I5 (a)),
//! and the floor's one read of the host, the volume's free space. The order
//! that installs a file is the store's (`store.rs`); the logs' is
//! `jsonl.rs`'s.

use std::fs::{self, FileType};
use std::io;
use std::path::{Path, PathBuf};

/// The prefix of an aside name: `.retired-<hex>-<n>`, the second name a
/// replaced file carries from the finish's link until the deferred unlink.
/// The leading dot keeps it apart from any hex name, as the partial's is.
/// Nothing names an aside — no lease, no cell — so every reader of a
/// designation directory passes over one, and the pruner's pass and open's
/// sweep ([`sweep_asides`]) remove it.
const ASIDE_PREFIX: &str = ".retired-";

/// The aside name of the `n`th replace of `hex` this process makes.
pub(crate) fn aside_name(hex: &str, n: u64) -> String {
    format!("{ASIDE_PREFIX}{hex}-{n}")
}

/// Whether a directory entry's name is an aside's: exactly what
/// [`aside_name`] spells — the prefix, a hex name, `-`, and a count in at
/// most twenty decimal digits.
pub(crate) fn is_aside_name(name: &str) -> bool {
    name.strip_prefix(ASIDE_PREFIX).and_then(|rest| rest.rsplit_once('-')).is_some_and(|(hex, n)| {
        hex_ok(hex) && !n.is_empty() && n.len() <= 20 && n.bytes().all(|b| b.is_ascii_digit())
    })
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

/// Every directory under `root`, by name, in name order — whatever the
/// names; a reader of designations alone passes over the rest.
pub(crate) fn dirs_under(root: &Path) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            out.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    out.sort();
    Ok(out)
}

/// The names in `<root>/<designation>/` that `keep` accepts, handed each
/// name and its entry's type, in name order — none where the designation
/// is malformed or its directory absent.
pub(crate) fn names_in(
    root: &Path,
    designation: &str,
    keep: impl Fn(&str, FileType) -> bool,
) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    if !designation_ok(designation) {
        return Ok(out);
    }
    let entries = match fs::read_dir(root.join(designation)) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if keep(&name, entry.file_type()?) {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

/// OPEN's SWEEP OF THE ASIDES: every aside in every designation directory
/// under `root` removed, each directory fsynced where one went — the second
/// names of replaced files whose deferred unlink a crash between the
/// finish's answer and that unlink never let run. Nothing names an aside,
/// so nothing is lost.
pub(crate) fn sweep_asides(root: &Path) -> io::Result<()> {
    for designation in dirs_under(root)? {
        let asides = names_in(root, &designation, |name, _| is_aside_name(name))?;
        let dir = root.join(&designation);
        for name in &asides {
            fs::remove_file(dir.join(name))?;
        }
        if !asides.is_empty() {
            fsync_dir(&dir)?;
        }
    }
    Ok(())
}

/// Remove the file at `path`: `Ok(true)` where a file went, `Ok(false)`
/// where none stood — a name another remover took first (the pruner's
/// pass, open's sweep, the deferred unlink) leaves nothing to do — and any
/// other failure answered.
pub(crate) fn remove_if_present(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
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
    let v = rustix::fs::statvfs(path)?;
    Ok(v.f_bavail.saturating_mul(v.f_frsize))
}

/// The path of a blob under `root`, its names UNCHECKED: for names that
/// have passed [`Store::blob_path`](crate::Store::blob_path)'s check, or
/// that the store spelled itself (a finish's hash). A caller's name becomes
/// a path only through that check.
pub(crate) fn blob_path_unchecked(root: &Path, designation: &str, hex: &str) -> PathBuf {
    root.join(designation).join(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AN ASIDE NAME is exactly what `aside_name` spells — the prefix, a
    /// hex name, `-`, a decimal count of at most twenty digits, the most
    /// `u64::MAX` takes — and nothing else that begins with the prefix.
    #[test]
    fn an_aside_name_is_exactly_what_aside_name_spells() {
        let hex = "ab".repeat(32);
        assert!(is_aside_name(&aside_name(&hex, 0)));
        assert!(is_aside_name(&aside_name(&hex, u64::MAX)));
        for near in [
            ".retired-".to_string(),
            ".retired-x".to_string(),
            format!(".retired-{hex}"),
            format!(".retired-{hex}-"),
            format!(".retired-{hex}-1x"),
            format!(".retired-{hex}-{}", "1".repeat(21)),
            format!(".retired-{}-1", hex.to_uppercase()),
            format!(".retired-{hex}-1/../x"),
            format!("retired-{hex}-1"),
        ] {
            assert!(!is_aside_name(&near), "{near}");
        }
    }
}
