//! THE FILES, `<root>/<designation>/<hex>`: the spellings a designation and
//! a hex name must have, where a file lives for names that pass them
//! ([`blob_path`], which answers none for a malformed one), the ASIDE name a
//! replaced instance carries until the deferred unlink, the listings of the
//! directories that hold those names and open's sweep of the asides
//! ([`sweep_asides`]), open's walk that holds every entry it acts on to what
//! the store makes — no link followed, no file it writes shared, no special
//! file read ([`refuse_links_and_special_files`]) — the removals, each
//! answering the bytes its unlink freed ([`freed_by`]): of a name another
//! remover may have taken first ([`remove_if_present`]) and of one that
//! stands ([`remove_standing`]); the absence rule every read of a name
//! keeps — not found is none, any other failure an answer
//! ([`not_found_as_none`]) — the directory fsync every install order under
//! the root ends in (a rename is durable only at its directory's fsync —
//! `media.md` Op inventory 1; the register M-I5 (a)), and the floor's one
//! read of the host, the volume's free space. The order that installs a
//! file is the store's (`store.rs`); the logs' is `jsonl.rs`'s.
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
//! tells one refusal from another). The cause is the OS's, a full volume's
//! spelled first in the operator stream's own words — `the volume is full
//! (No space left on device (os error 28))` ([`Cause`]; `operations.md` §1)
//! — so one search finds every act that failed for room. The operator reads
//! it whole on the daemon's refused start (`skepd: blob store: {e}`), in the
//! pruner's line and from the pull; a client reads it in `blob_io`'s detail.

use std::collections::BTreeMap;
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
/// {cause}`, the cause as [`Cause`] spells `e`, `e`'s kind kept, so a
/// caller's match on the kind — the absence rule's `NotFound` among them —
/// reads it unchanged.
pub(crate) fn named(e: io::Error, name: impl fmt::Display, act: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{name}: {act}: {}", Cause(&e)))
}

/// AN I/O FAILURE's CAUSE AS A LINE SAYS IT: the OS's text, a full volume's
/// spelled first in the operator stream's own words — `the volume is full
/// (No space left on device (os error 28))` (`operations.md` §1: a cause the
/// OS gives as `StorageFull` reads `the volume is full`, the OS's text
/// beside it) — so one search finds every act that failed for room, the
/// store's beside the journal's and the change feed's. An error the store
/// has already named carries its cause so spelled, and reads as it stands.
pub(crate) struct Cause<'a>(pub(crate) &'a io::Error);

impl fmt::Display for Cause<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // An OS error, or a bare kind, carries no text of the store's; a named
        // one (`io::Error::new`) does, its cause spelled when it was named.
        if self.0.kind() == io::ErrorKind::StorageFull && self.0.get_ref().is_none() {
            write!(f, "the volume is full ({})", self.0)
        } else {
            write!(f, "{}", self.0)
        }
    }
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
/// count removed and the bytes their unlinks freed — an aside that shares
/// its inode with its hash's name, a crash's between a replace's link and
/// its rename, frees none — for the open's account ([`Opened`](crate::Opened)).
pub(crate) fn sweep_asides(root: &Path) -> io::Result<(usize, u64)> {
    let (mut removed, mut freed) = (0, 0);
    for dir_name in dirs_under(root)? {
        let asides = names_in(root, &dir_name, |name, _| is_aside_name(name))?;
        let dir = root.join(&dir_name);
        for name in &asides {
            let aside = dir.join(name);
            freed += remove_standing(&aside).map_err(|e| named(e, label(&aside, 3), "remove"))?;
        }
        if !asides.is_empty() {
            fsync_dir(&dir).map_err(|e| named(e, dir_label(&dir, 2), "fsync"))?;
        }
        removed += asides.len();
    }
    Ok((removed, freed))
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
/// ONE REFUSAL COUNTS EVERY ENTRY, AND IS ONE LINE OF BOUNDED LENGTH: the
/// walk reads the whole tree first, so a tree holding several — a hard-link
/// copy gives every log and partial a second link at once — costs the
/// operator one refused start and not one per entry; and the refusal says
/// what made each kind and the act that clears it ([`Refused`]). It names
/// the entries in at most [`PLANTED_NAMED`] clauses and counts the rest by
/// kind, so a tree of thousands — one linked back from another disk holds a
/// symbolic link at every hex name — still refuses in one line whose acts
/// end it, whole under a log collector's line limit. A partial is named by
/// its directory alone, its file name being an upload's identifier, so the
/// partials of one directory and one count of links are one clause, counted.
/// An entry gone between its listing and its read — an inspection beside a
/// serving daemon, whose finishes rename partials away — is passed over.
pub(crate) fn refuse_links_and_special_files(root: &Path) -> io::Result<()> {
    let listed = |e| named(e, dir_label(root, 1), "list");
    let mut planted = Vec::new();
    for entry in fs::read_dir(root).map_err(listed)? {
        let entry = entry.map_err(listed)?;
        // Under the root the store makes the designation directories, and
        // the two logs and their twins, each written in place.
        planted.extend(planted_at(&entry, At::Root(label(&entry.path(), 2)), true)?);
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
                let at = if file_name.starts_with(".upload-") {
                    At::PartialIn(dir_label(&dir, 2))
                } else {
                    At::Inner(label(&inner.path(), 3))
                };
                planted.extend(planted_at(&inner, at, written_in_place)?);
            }
        }
    }
    if planted.is_empty() {
        return Ok(());
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, Refused { root: dir_label(root, 1), planted }.to_string()))
}

/// What stands at a name the store makes, where it is not what the store
/// makes there — ordered as the refusal orders the clauses of one name.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

impl Found {
    /// The kind it counts as among the entries past those a refusal names:
    /// its place in [`KINDS`].
    fn kind(self) -> usize {
        match self {
            Found::SymbolicLink => 0,
            Found::SpecialFile => 1,
            Found::Links(_) => 2,
        }
    }
}

/// The kinds a refusal counts the entries past its named clauses by, each
/// as one and as many: `and 193 more symbolic links`.
const KINDS: [(&str, &str); 3] = [
    ("symbolic link", "symbolic links"),
    ("special file", "special files"),
    ("file with a second link", "files with a second link"),
];

/// Where a refused entry stands, as a line names it — ordered as the
/// refusal names them: the root's own entries first, the logs and their
/// twins among them; then the partials, one name per directory; then every
/// other entry in a designation directory, by name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum At {
    /// An entry under the root, by its place: `blobs/uploads.log`.
    Root(String),
    /// A partial, by its designation directory alone — `blobs/blake3/` —
    /// its file name being an upload's identifier, which no line carries.
    PartialIn(String),
    /// Any other entry in a designation directory, by its place:
    /// `blobs/blake3/<hex>`.
    Inner(String),
}

/// One entry, as a line names it: a partial as `a partial in {dir}`
/// ([`partial_label`]'s words), every other entry by its place.
impl fmt::Display for At {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            At::Root(name) | At::Inner(name) => f.write_str(name),
            At::PartialIn(dir) => write!(f, "a partial in {dir}"),
        }
    }
}

/// One entry the walk refuses: where it stands, and what stands there.
struct Planted {
    at: At,
    found: Found,
}

/// THE MOST CLAUSES ONE REFUSAL NAMES — eight, INTERIM: the entries past
/// them are counted by kind, so the refusal is one line whose acts end it,
/// however many entries a tree holds — a line of one clause per entry over
/// ten thousand passes the 16 KiB a container's log driver splits a line at
/// (journald's 48 KiB not long after), its act landing in a record of its
/// own, the `skepd: ` prefix far above it.
const PLANTED_NAMED: usize = 8;

/// THE WALK's ONE REFUSAL: how many entries it found, at most
/// [`PLANTED_NAMED`] clauses naming them — one per place and kind, the
/// partials of one directory and one count of links one clause, counted —
/// in [`At`]'s order and the entries past them counted by kind, then the
/// cause and the act for each kind among them all.
struct Refused {
    root: String,
    planted: Vec<Planted>,
}

/// One clause of a refusal: the `count` entries at `at` that `found` stands
/// at — `blobs/leases.log is a symbolic link`, `3 partials in blobs/blake3/
/// have 2 links`.
struct Clause<'a> {
    at: &'a At,
    found: Found,
    count: usize,
}

impl fmt::Display for Clause<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let one = self.count == 1;
        match (self.at, one) {
            (at, true) => write!(f, "{at}")?,
            (At::PartialIn(dir), false) => write!(f, "{} partials in {dir}", self.count)?,
            // Two names one place: a directory's names that differ in bytes
            // no UTF-8 spells, read lossily alike.
            (At::Root(name) | At::Inner(name), false) => write!(f, "{} entries named {name}", self.count)?,
        }
        match (self.found, one) {
            (Found::SymbolicLink, true) => f.write_str(" is a symbolic link"),
            (Found::SymbolicLink, false) => f.write_str(" are symbolic links"),
            (Found::SpecialFile, true) => f.write_str(" is a special file"),
            (Found::SpecialFile, false) => f.write_str(" are special files"),
            (Found::Links(n), true) => write!(f, " has {n} links"),
            (Found::Links(n), false) => write!(f, " have {n} links"),
        }
    }
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
        let mut clauses: BTreeMap<(&At, Found), usize> = BTreeMap::new();
        for planted in &self.planted {
            *clauses.entry((&planted.at, planted.found)).or_default() += 1;
        }
        let mut more = [0usize; KINDS.len()];
        for (i, ((at, found), count)) in clauses.into_iter().enumerate() {
            if i >= PLANTED_NAMED {
                more[found.kind()] += count;
                continue;
            }
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{}", Clause { at, found, count })?;
        }
        let counted: Vec<String> = more
            .iter()
            .zip(KINDS)
            .filter(|(m, _)| **m > 0)
            .map(|(m, (one, many))| format!("{m} more {}", if *m == 1 { one } else { many }))
            .collect();
        if !counted.is_empty() {
            write!(f, "; and {}", counted.join(", "))?;
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

/// The entry's refusal, if it is not what the store makes at `at`: a
/// directory, or a regular file — one with a single link where the store
/// writes it in place (`written_in_place`). Its kind is read without
/// following it; a file gone before its links are read is none.
fn planted_at(entry: &DirEntry, at: At, written_in_place: bool) -> io::Result<Option<Planted>> {
    let stat = |e| named(e, &at, "stat");
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
    Ok(found.map(|found| Planted { at, found }))
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

/// Remove the file at `path`: `Ok(Some(freed))` where a file went, the
/// bytes its unlink freed ([`freed_by`]); `Ok(None)` where none stood — a
/// name another remover took first (the pruner's pass, open's sweep, the
/// deferred unlink) leaves nothing to do — and any other failure answered,
/// the OS's alone: the caller names the file ([`named`]), a partial by its
/// directory.
pub(crate) fn remove_if_present(path: &Path) -> io::Result<Option<u64>> {
    let Some(meta) = not_found_as_none(fs::symlink_metadata(path))? else {
        return Ok(None);
    };
    Ok(not_found_as_none(fs::remove_file(path))?.map(|()| freed_by(&meta)))
}

/// Remove the file at `path`, which stands — open's own removals, which
/// nothing races, so a name gone there is a failure like any other: the
/// bytes its unlink freed ([`freed_by`]), and any failure answered, the
/// OS's alone, the caller naming the file ([`named`]).
pub(crate) fn remove_standing(path: &Path) -> io::Result<u64> {
    let meta = fs::symlink_metadata(path)?;
    fs::remove_file(path)?;
    Ok(freed_by(&meta))
}

/// THE BYTES AN UNLINK FREES, read off the file's metadata before it: its
/// length where the unlink takes its last name, and nothing where another
/// name still holds it — a replaced instance's aside sharing an inode with
/// its hash's name, a hard-link copy's second name — so a removal's figure
/// is what the volume regains, and an act that unlinked files and freed
/// nothing says so.
fn freed_by(meta: &fs::Metadata) -> u64 {
    if link_count(meta) > 1 {
        0
    } else {
        meta.len()
    }
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

    /// A FULL VOLUME's CAUSE IS SPELLED IN THE STREAM's WORDS, ONCE (`Cause`;
    /// `operations.md` §1: `the volume is full`, the OS's text beside it): the
    /// OS's `ENOSPC` named at a file reads `{file}: {act}: the volume is full
    /// ({the OS's text})`, its kind kept; named again around another act, the
    /// words stand once; every other cause is the OS's text alone.
    #[cfg(unix)]
    #[test]
    fn a_full_volumes_cause_reads_the_volume_is_full_once() {
        let enospc = || io::Error::from_raw_os_error(28);
        let full = named(enospc(), "blobs/leases.log", "append");
        assert_eq!(full.kind(), io::ErrorKind::StorageFull, "the kind kept");
        assert_eq!(full.to_string(), format!("blobs/leases.log: append: the volume is full ({})", enospc()));
        let again = named(full, "blobs/", "fsync");
        assert_eq!(again.to_string().matches("the volume is full").count(), 1, "said once: {again}");
        let other = named(io::Error::from_raw_os_error(30), "blobs/leases.log", "cut back");
        assert!(!other.to_string().contains("the volume is full"), "{other}");
    }

    /// A REMOVAL ANSWERS THE BYTES ITS UNLINK FREED (`freed_by`): a file's
    /// length where the unlink takes its last name; nothing where another
    /// name still holds the inode — an aside beside its hash's name, a
    /// hard-link copy's second name — and its length once the last goes;
    /// none where no file stands; and a removal of a file that must stand
    /// fails where it does not.
    #[cfg(unix)]
    #[test]
    fn a_removal_answers_the_bytes_its_unlink_freed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let alone = dir.path().join("alone");
        fs::write(&alone, b"12345").unwrap();
        assert_eq!(remove_if_present(&alone).unwrap(), Some(5), "its last name: its length");
        assert_eq!(remove_if_present(&alone).unwrap(), None, "nothing stands: none");
        let hash = dir.path().join("hash");
        let aside = dir.path().join("aside");
        fs::write(&hash, b"1234567").unwrap();
        fs::hard_link(&hash, &aside).unwrap();
        assert_eq!(remove_standing(&aside).unwrap(), 0, "another name holds the inode: nothing freed");
        assert_eq!(remove_standing(&hash).unwrap(), 7, "the last name: its length");
        assert_eq!(remove_standing(&hash).map_err(|e| e.kind()), Err(io::ErrorKind::NotFound));
    }

    /// ONE REFUSAL IS ONE LINE OF BOUNDED LENGTH (`Refused`, `PLANTED_NAMED`):
    /// every entry counted; at most eight clauses naming them — the root's
    /// own entries first, then the partials, those of one directory and one
    /// count of links one clause however many, then every other entry by
    /// name, whatever order the walk met them in; the entries past them
    /// counted by kind; and the act for each kind among them all at its end —
    /// a kind met only past the named clauses among them.
    #[test]
    fn a_refusal_names_eight_clauses_and_counts_the_rest_by_kind() {
        let inner = |name: String, found| Planted { at: At::Inner(format!("blobs/blake3/{name}")), found };
        let links = |n: usize| (0..n).rev().map(|i| inner(format!("{i:04}"), Found::SymbolicLink)).collect::<Vec<_>>();
        let mut planted = links(200);
        planted.push(inner("fifo".into(), Found::SpecialFile));
        for _ in 0..3 {
            planted.push(Planted { at: At::PartialIn("blobs/blake3/".into()), found: Found::Links(2) });
        }
        planted.push(Planted { at: At::Root("blobs/uploads.log".into()), found: Found::Links(2) });
        let text = Refused { root: "blobs/".into(), planted }.to_string();
        let named: Vec<String> = (0..6).map(|i| format!("blobs/blake3/{i:04} is a symbolic link")).collect();
        assert_eq!(
            text,
            format!(
                "blobs/ holds 205 entries the blob store never makes, and nothing was followed or written through \
                 them: blobs/uploads.log has 2 links; 3 partials in blobs/blake3/ have 2 links; {}; and 194 more \
                 symbolic links, 1 more special file. A second link is another name sharing the file — a hard-link \
                 copy (cp -al, ln) makes one — and the store writes that file in place, so its next write would \
                 change the copy too: give the copy bytes of its own (cp -a), or remove it. A symbolic link or a \
                 special file stands where the store's own file belongs: remove it, and put back the store's file \
                 from the board directory's copy (Restore). Then try again.",
                named.join("; ")
            )
        );
        let mut planted = links(8);
        planted.push(inner("zzzz".into(), Found::Links(3)));
        let past = Refused { root: "blobs/".into(), planted }.to_string();
        assert!(
            past.contains("is a symbolic link; and 1 more file with a second link. A second link is another name"),
            "the act of a kind met only past the named clauses: {past}"
        );
        let one = Refused { root: "blobs/".into(), planted: vec![inner("ab".into(), Found::SpecialFile)] };
        assert_eq!(
            one.to_string(),
            "blobs/ holds 1 entry the blob store never makes, and nothing was followed or written through it: \
             blobs/blake3/ab is a special file. A symbolic link or a special file stands where the store's own file \
             belongs: remove it, and put back the store's file from the board directory's copy (Restore). Then try \
             again.",
            "one entry, one clause, no count past it"
        );
    }
}
