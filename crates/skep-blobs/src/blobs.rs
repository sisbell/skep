//! THE FILES, `<root>/<designation>/<hex>`: the spellings a designation and
//! a hex name must have, where a file lives for names that pass them
//! ([`blob_path`], which answers none for a malformed one), the ASIDE name a
//! replaced instance carries until the deferred unlink, the listings of the
//! directories that hold those names and open's sweep of the asides
//! ([`sweep_asides`]), open's walk that holds every entry it acts on to what
//! the store makes — no link followed, no file it writes shared, no special
//! file read ([`refuse_links_and_special_files`]) — the removal of a name
//! another remover may have taken first ([`remove_if_present`]), the
//! absence rule every read of a name keeps — not found is none, any other
//! failure an answer ([`not_found_as_none`]) — the directory fsync every
//! install order under the root ends in (a rename is durable only at its
//! directory's fsync — `media.md` Op inventory 1; the register M-I5 (a)),
//! and the floor's one read of the host, the volume's free space. The order
//! that installs a file is the store's (`store.rs`); the logs' is
//! `jsonl.rs`'s.

use std::fs::{self, DirEntry, FileType};
use std::io;
use std::path::{Path, PathBuf};

/// The prefix of an aside name: `.retired-<hex>-<n>`, the second name a
/// replaced instance carries from the finish's link until the deferred
/// unlink. The leading dot keeps it apart from any hex name, as the
/// partial's is. Nothing names an aside — no lease, no cell — so every
/// reader of a designation directory passes over one, and the pruner's pass
/// and open's sweep ([`sweep_asides`]) remove it.
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
        && hex.len().is_multiple_of(2)
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
/// name and its entry's kind, in name order — none where the designation
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
    let Some(entries) = not_found_as_none(fs::read_dir(root.join(designation)))? else {
        return Ok(out);
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
/// names a replace left that its deferred unlink never took: a crash's
/// between the finish's answer and that unlink, or a finish's that failed
/// past its link. Nothing names an aside, so nothing is lost.
pub(crate) fn sweep_asides(root: &Path) -> io::Result<()> {
    for dir_name in dirs_under(root)? {
        let asides = names_in(root, &dir_name, |name, _| is_aside_name(name))?;
        let dir = root.join(&dir_name);
        for name in &asides {
            fs::remove_file(dir.join(name))?;
        }
        if !asides.is_empty() {
            fsync_dir(&dir)?;
        }
    }
    Ok(())
}

/// NOTHING OPEN ACTS ON IS FOLLOWED OR SHARED: every entry under `root`, and
/// every entry in each designation directory there, is a directory or a
/// regular file — the two kinds this store makes — and every regular file
/// has one link, save a file at a hex name and an aside. Open cuts the logs
/// at their torn tails and the partials past their records, and rewrites the
/// logs through their compaction twins; while it serves, the store appends
/// to the logs, writes the partials, and creates, renames over and unlinks
/// names in the designation directories. Through a symbolic link each of
/// those acts lands outside the root; through a second hard link the cuts
/// and writes land in a file that is also another name's — the journal's,
/// beside `blobs/` on the board's one volume; and on a FIFO open's read of a
/// log never ends. No build of this store makes any of them, so one standing
/// here was planted — a compromise's, which the remediation that keeps the
/// files leaves (`media.md` §Recovery, "A COMPROMISE's REMEDIATION DISCARDS
/// EVERY MEDIA STORE BUT THE FILES"), or a copy's that was not the board's
/// own — and it fails the open, named, before any act. The board directory
/// is one volume (§Recovery, the deployment list's item (2)), so no link
/// here is the operator's. A file at a hex name and an aside are held to
/// their kind and never to their count of links: no act writes either in
/// place — each is renamed onto, linked, unlinked or read — and a replace
/// gives the replaced instance its aside as a second link, which a crash
/// between that link and the rename leaves standing beside the hash. Every
/// other regular file the store makes — a log, a twin, a partial — it
/// writes in place. The walk enters the directories whose names a
/// designation can spell, the ones every other walk of the store enters
/// (`names_in`).
pub(crate) fn refuse_links_and_special_files(root: &Path) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        // Under the root the store makes the designation directories, and
        // the two logs and their twins, each written in place.
        refuse_unless_made_here(&entry, true)?;
        if entry.file_type()?.is_dir() && designation_ok(&entry.file_name().to_string_lossy()) {
            for inner in fs::read_dir(entry.path())? {
                let inner = inner?;
                let name = inner.file_name().to_string_lossy().into_owned();
                let written_in_place = !(hex_ok(&name) || is_aside_name(&name));
                refuse_unless_made_here(&inner, written_in_place)?;
            }
        }
    }
    Ok(())
}

/// An entry held to what the store makes: a directory, or a regular file —
/// one with a single link where the store writes it in place
/// (`written_in_place`). Its kind is read without following it. Anything
/// else is refused as `InvalidData`, naming the path and what stands there.
fn refuse_unless_made_here(entry: &DirEntry, written_in_place: bool) -> io::Result<()> {
    let kind = entry.file_type()?;
    let found = if kind.is_dir() {
        None
    } else if kind.is_symlink() {
        Some("a symbolic link".to_string())
    } else if !kind.is_file() {
        Some("a special file".to_string())
    } else if written_in_place {
        let n = link_count(&entry.metadata()?);
        (n > 1).then(|| format!("a regular file of {n} links"))
    } else {
        None
    };
    match found {
        None => Ok(()),
        Some(found) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is {found}: the blob store makes directories and regular files of its own alone, and follows \
                 or shares none",
                entry.path().display()
            ),
        )),
    }
}

/// A regular file's count of links — on a non-unix target one, the count
/// unread; v1 targets unix.
fn link_count(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::nlink(meta)
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        1
    }
}

/// THE ABSENCE RULE, spelled once: `Ok(Some(value))` where the name stands,
/// `Ok(None)` where nothing does (`NotFound`), and every other failure
/// answered — an I/O failure is no absence (the register M-I5 (c)).
pub(crate) fn not_found_as_none<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Remove the file at `path`: `Ok(true)` where a file went, `Ok(false)`
/// where none stood — a name another remover took first (the pruner's
/// pass, open's sweep, the deferred unlink) leaves nothing to do — and any
/// other failure answered.
pub(crate) fn remove_if_present(path: &Path) -> io::Result<bool> {
    Ok(not_found_as_none(fs::remove_file(path))?.is_some())
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

/// The path of a blob of `designation` and `hex` under `root`, or `None`
/// where either name is malformed — the name check a caller's names pass
/// before they become a blob's path
/// ([`Store::blob_path`](crate::Store::blob_path)).
pub(crate) fn blob_path(root: &Path, designation: &str, hex: &str) -> Option<PathBuf> {
    (designation_ok(designation) && hex_ok(hex)).then(|| root.join(designation).join(hex))
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
