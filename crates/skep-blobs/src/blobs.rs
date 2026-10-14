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
//!
//! EVERY FAILURE NAMES ITS FILE AND ITS ACT ([`named`], [`label`],
//! [`dir_label`]): an I/O error the store answers reads `{file}: {act}:
//! {cause}` — `blobs/leases.log: cut back: Read-only file system (os error
//! 30)` — its kind kept, the file named as it stands within the data
//! directory (the root's own name first) and never by an absolute path, and
//! a partial by its directory alone, its file name being an upload's
//! identifier (`operations.md` §1.1 row 2's form, the change feed's own:
//! a refused open names its file, the kind kept; the act added, since the
//! store reads, cuts, renames and syncs at its open, and the act is what
//! tells one refusal from another). The operator reads it whole on the
//! daemon's refused start (`skepd: blob store: {e}`), in the pruner's
//! line and from the pull; a client reads it in `blob_io`'s detail.

use std::fmt;
use std::fs::{self, DirEntry, FileType};
use std::io;
use std::path::{Component, Path, PathBuf};

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

/// A designation's spelling: 1 to 32 bytes of lowercase letters, digits and
/// `-` — no `/` and no `.`, so no path climbs out of the root by it, and no
/// uppercase, so one designation has one spelling on a volume that folds
/// case. A designation names a directory under the root and a hex a file
/// inside one, so the two never share a listing — though a short hex
/// (`beef`) spells a designation too.
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

/// The last `n` components of `path`, joined by `/` — of an entry `n − 1`
/// below the root, the root's own name first: the name a line gives it, as
/// it stands within the data directory. The root and prefix components of
/// an absolute path are never among them.
fn within(path: &Path, n: usize) -> String {
    let parts: Vec<String> = path
        .components()
        .filter(|c| !matches!(c, Component::RootDir | Component::Prefix(_)))
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    parts[parts.len().saturating_sub(n)..].join("/")
}

/// A FILE's NAME as a line gives it: `path`, an entry `n − 1` below the
/// root, by its last `n` components — `label(log, 2)` is
/// `blobs/leases.log`, `label(blob, 3)` is `blobs/blake3/<hex>`.
pub(crate) fn label(path: &Path, n: usize) -> String {
    within(path, n)
}

/// A DIRECTORY's NAME as a line gives it, its trailing `/` marking it one:
/// `dir_label(root, 1)` is `blobs/`, `dir_label(designation_dir, 2)` is
/// `blobs/blake3/`.
pub(crate) fn dir_label(dir: &Path, n: usize) -> String {
    format!("{}/", within(dir, n))
}

/// A PARTIAL's NAME as a line gives it — `a partial in blobs/blake3/`, by
/// its designation directory `dir` alone: its file name spells an upload's
/// identifier, which no line carries (`operations.md` §1 NEVER; the D9
/// vector), and a client's `blob_io` detail is a line of the same text.
pub(crate) fn partial_label(dir: &Path) -> String {
    format!("a partial in {}", dir_label(dir, 2))
}

/// THE FAILURE OF `act` AT `name`, as the store answers it: `{name}: {act}:
/// {e}`, `e`'s kind kept, so a caller's match on the kind — the absence
/// rule's `NotFound` among them — reads it unchanged.
pub(crate) fn named(e: io::Error, name: impl fmt::Display, act: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{name}: {act}: {e}"))
}

/// Every directory under `root`, by name, in name order — whatever the
/// names; a reader of designations alone passes over the rest.
pub(crate) fn dirs_under(root: &Path) -> io::Result<Vec<String>> {
    let listed = |e| named(e, dir_label(root, 1), "list");
    let mut out = Vec::new();
    for entry in fs::read_dir(root).map_err(listed)? {
        let entry = entry.map_err(listed)?;
        if entry.file_type().map_err(listed)?.is_dir() {
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
    let dir = root.join(designation);
    let listed = |e| named(e, dir_label(&dir, 2), "list");
    let Some(entries) = not_found_as_none(fs::read_dir(&dir)).map_err(listed)? else {
        return Ok(out);
    };
    for entry in entries {
        let entry = entry.map_err(listed)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if keep(&name, entry.file_type().map_err(listed)?) {
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
/// past its link. Nothing names an aside, so nothing is lost. Answers the
/// count removed, for the open's account ([`Opened`](crate::Opened)).
pub(crate) fn sweep_asides(root: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for dir_name in dirs_under(root)? {
        let asides = names_in(root, &dir_name, |name, _| is_aside_name(name))?;
        let dir = root.join(&dir_name);
        for name in &asides {
            let aside = dir.join(name);
            fs::remove_file(&aside).map_err(|e| named(e, label(&aside, 3), "remove"))?;
        }
        if !asides.is_empty() {
            fsync_dir(&dir).map_err(|e| named(e, dir_label(&dir, 2), "fsync"))?;
        }
        removed += asides.len();
    }
    Ok(removed)
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
///
/// ONE REFUSAL NAMES EVERY ENTRY: the walk reads the whole tree first, so a
/// tree holding several — a hard-link copy gives every log and partial a
/// second link at once — costs the operator one refused start and not one
/// per entry; and the refusal says what made each kind and the act that
/// clears it ([`Planted`]). A partial is named by its directory alone, its
/// file name being an upload's identifier. An entry gone between its
/// listing and its read — an inspection beside a serving daemon, whose
/// finishes rename partials away — is passed over.
pub(crate) fn refuse_links_and_special_files(root: &Path) -> io::Result<()> {
    let listed = |e| named(e, dir_label(root, 1), "list");
    let mut planted = Vec::new();
    for entry in fs::read_dir(root).map_err(listed)? {
        let entry = entry.map_err(listed)?;
        // Under the root the store makes the designation directories, and
        // the two logs and their twins, each written in place.
        let name = label(&entry.path(), 2);
        planted.extend(planted_at(&entry, name, true)?);
        if entry.file_type().map_err(listed)?.is_dir() && designation_ok(&entry.file_name().to_string_lossy()) {
            let dir = entry.path();
            let listed = |e| named(e, dir_label(&dir, 2), "list");
            let Some(inner) = not_found_as_none(fs::read_dir(&dir)).map_err(listed)? else {
                continue;
            };
            for inner in inner {
                let inner = inner.map_err(listed)?;
                let file_name = inner.file_name().to_string_lossy().into_owned();
                let written_in_place = !(hex_ok(&file_name) || is_aside_name(&file_name));
                let name =
                    if file_name.starts_with(".upload-") { partial_label(&dir) } else { label(&inner.path(), 3) };
                planted.extend(planted_at(&inner, name, written_in_place)?);
            }
        }
    }
    if planted.is_empty() {
        return Ok(());
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, Refused { root: dir_label(root, 1), planted }.to_string()))
}

/// What stands at a name the store makes, where it is not what the store
/// makes there.
enum Found {
    /// A symbolic link, which the store never makes and never follows.
    SymbolicLink,
    /// A FIFO, a socket or a device, which the store never makes and never
    /// reads.
    SpecialFile,
    /// A file the store writes in place, sharing its inode with another
    /// name — this many links in all.
    Links(u64),
}

/// One entry the walk refuses: its name as a line gives it, and what stands
/// there.
struct Planted {
    name: String,
    found: Found,
}

impl fmt::Display for Planted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.found {
            Found::SymbolicLink => write!(f, "{} is a symbolic link", self.name),
            Found::SpecialFile => write!(f, "{} is a special file", self.name),
            Found::Links(n) => write!(f, "{} has {n} links", self.name),
        }
    }
}

/// THE WALK's ONE REFUSAL: every entry it found, then the cause and the act
/// for each kind among them.
struct Refused {
    root: String,
    planted: Vec<Planted>,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.planted.len();
        let (entries, them) = if n == 1 { ("entry", "it") } else { ("entries", "them") };
        write!(
            f,
            "{} holds {n} {entries} the blob store never makes, and nothing was followed or written through {them}: ",
            self.root
        )?;
        for (i, planted) in self.planted.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{planted}")?;
        }
        f.write_str(".")?;
        if self.planted.iter().any(|p| matches!(p.found, Found::Links(_))) {
            f.write_str(
                " A second link is another name sharing the file — a hard-link copy (cp -al, ln) makes one — and \
                 the store writes that file in place, so its next write would change the copy too: give the copy \
                 bytes of its own (cp -a), or remove it.",
            )?;
        }
        if self.planted.iter().any(|p| !matches!(p.found, Found::Links(_))) {
            f.write_str(
                " A symbolic link or a special file stands where the store's own file belongs: remove it, and put \
                 back the store's file from the board directory's copy (Restore).",
            )?;
        }
        f.write_str(" Then try again.")
    }
}

/// The entry's refusal, if it is not what the store makes at `name`: a
/// directory, or a regular file — one with a single link where the store
/// writes it in place (`written_in_place`). Its kind is read without
/// following it; a file gone before its links are read is none.
fn planted_at(entry: &DirEntry, name: String, written_in_place: bool) -> io::Result<Option<Planted>> {
    let stat = |e| named(e, &name, "stat");
    let kind = entry.file_type().map_err(stat)?;
    let found = if kind.is_dir() {
        None
    } else if kind.is_symlink() {
        Some(Found::SymbolicLink)
    } else if !kind.is_file() {
        Some(Found::SpecialFile)
    } else if written_in_place {
        let Some(meta) = not_found_as_none(entry.metadata()).map_err(stat)? else {
            return Ok(None);
        };
        let n = link_count(&meta);
        (n > 1).then_some(Found::Links(n))
    } else {
        None
    };
    Ok(found.map(|found| Planted { name, found }))
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
/// other failure answered, the OS's alone: the caller names the file
/// ([`named`]), a partial by its directory.
pub(crate) fn remove_if_present(path: &Path) -> io::Result<bool> {
    Ok(not_found_as_none(fs::remove_file(path))?.is_some())
}

/// Fsync a directory, so entry creations, removals and renames inside it
/// are durable (the kernel's own discipline, `journal/segment.rs`). On a
/// non-unix target this is a no-op; v1 targets unix. Its failure is the
/// OS's alone: the caller names the directory by its depth ([`named`]).
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

/// The volume's free space at the root `path`, in bytes — what the floor
/// reads: the blocks available to an unprivileged writer times the fragment
/// size.
pub(crate) fn free_space(path: &Path) -> io::Result<u64> {
    let v = rustix::fs::statvfs(path).map_err(|e| named(e.into(), dir_label(path, 1), "statvfs"))?;
    Ok(v.f_bavail.saturating_mul(v.f_frsize))
}

/// The volume's CAPACITY at the root `path`, in bytes — the same `statvfs`
/// read as [`free_space`]'s, its total blocks times the fragment size: what
/// the daemon's default per-account limit is a share of, read once at its
/// start.
pub(crate) fn capacity(path: &Path) -> io::Result<u64> {
    let v = rustix::fs::statvfs(path).map_err(|e| named(e.into(), dir_label(path, 1), "statvfs"))?;
    Ok(v.f_blocks.saturating_mul(v.f_frsize))
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

    /// A FAILURE NAMES ITS FILE WITHIN THE DATA DIRECTORY AND KEEPS ITS KIND:
    /// a file, a directory and a partial each named by their place under the
    /// root, the root's own name first — never by the absolute path a client's
    /// `blob_io` would carry, never by a partial's identifier — and the error
    /// reads `{name}: {act}: {cause}`, its kind the OS's, so the absence rule
    /// and a caller's match read it unchanged.
    #[test]
    fn a_failure_names_its_file_within_the_data_directory_and_keeps_its_kind() {
        let root = Path::new("/srv/board/blobs");
        let designation_dir = root.join("blake3");
        assert_eq!(label(&root.join("leases.log"), 2), "blobs/leases.log");
        assert_eq!(label(&designation_dir.join("ab"), 3), "blobs/blake3/ab");
        assert_eq!(dir_label(root, 1), "blobs/");
        assert_eq!(dir_label(&designation_dir, 2), "blobs/blake3/");
        assert_eq!(partial_label(&designation_dir), "a partial in blobs/blake3/");
        assert_eq!(label(Path::new("/leases.log"), 2), "leases.log", "no root component is named");
        let failed =
            named(io::Error::from(io::ErrorKind::PermissionDenied), label(&root.join("leases.log"), 2), "cut back");
        assert_eq!(failed.kind(), io::ErrorKind::PermissionDenied, "the kind kept");
        let text = failed.to_string();
        assert!(text.starts_with("blobs/leases.log: cut back: "), "{text}");
        assert!(!text.contains("/srv"), "no absolute path: {text}");
        let absent = named(io::Error::from(io::ErrorKind::NotFound), "blobs/uploads.log", "read");
        assert!(matches!(not_found_as_none::<()>(Err(absent)), Ok(None)), "a named absence is still an absence");
    }
}
