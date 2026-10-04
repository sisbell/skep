//! THE PARTIALS, `<root>/<designation>/.upload-<identifier>` — the bytes
//! received so far of one standing upload, a temp file in its target's own
//! designation directory (`media.md` Op inventory 1, the resumable upload
//! (1), (3), (4); §The media stores). A BYTE IS RECEIVED ONCE IT IS DURABLE
//! IN THE PARTIAL: the file is fsynced at [`SYNC_GRAIN`] and at every
//! request's end, the record's offset and expiry written after each sync,
//! so the offset a resume continues from, the bytes received the deposit
//! read answers and the byte the expiry is fixed from are one figure.
//!
//! EVERY RESUME OPENS THE PARTIAL AFRESH ([`open_at`]): cut back to its
//! record's offset where longer, its bytes up to that offset hashed from the
//! first, so whatever an earlier request left past the offset — a write that
//! failed partway, bytes synced before a record write that failed — is gone
//! before another byte lands. No handle outlives its request ([`Handle`]).
//!
//! AT OPEN THE TWO ARE RECONCILED BOTH WAYS: a partial no record names is
//! removed, in every designation directory under the root; a record that
//! names no partial is retired; and their lengths are set to agree — a
//! longer partial cut back to the record's offset, a record whose offset
//! passes its partial's length set back to that length. An expired upload
//! has its partial removed and its record retired at open too, in the order
//! the end and the daemon's pruner take while the store serves
//! ([`Store::expire_upload`](crate::Store::expire_upload) is the pass's
//! act).

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::blobs::{dirs_under, fsync_dir, names_in, remove_if_present};
use crate::uploads::{UploadId, UploadRecords};

/// THE FSYNC GRAIN of a partial — 1 MiB, INTERIM: the most a dropped
/// connection re-sends, against one fsync of the partial and one of the
/// record log per grain (sixty-four of each for a file at the per-file cap).
pub const SYNC_GRAIN: u64 = 1024 * 1024;

/// THE HANDLE: the partial opened for one request — by [`open_at`] at the
/// request's resume, and dropped when that request ends: the partial's open
/// file, the hasher over every byte written, the count of those bytes, and
/// whether a write or sync has failed. The fields are this file's alone —
/// only [`open_at`], [`Handle::write`] and [`Handle::sync`] move them — and
/// the claim they keep holds across a failed call: the hasher is the hash
/// of exactly the bytes written, so the hash a finish names the file by
/// ([`Handle::hash`]) is its bytes' hash. A write or sync that fails marks
/// the handle TORN — the file may then hold bytes no hasher covers, or
/// bytes whose durability nothing vouches for — and a torn handle takes no
/// further write or sync: the next resume opens the partial afresh at its
/// record's offset.
pub(crate) struct Handle {
    file: File,
    hasher: blake3::Hasher,
    written: u64,
    torn: bool,
}

/// The partial's file name inside its designation directory —
/// `.upload-<identifier>`: the dot keeps it apart from any hex name a walk
/// of the directory reads as a blob.
fn partial_name(id: &UploadId) -> String {
    format!(".upload-{}", id.to_hex())
}

/// The identifier a partial's file name spells, if it is one.
fn id_of_partial_name(name: &str) -> Option<UploadId> {
    name.strip_prefix(".upload-").and_then(UploadId::parse)
}

/// The partial's path.
pub(crate) fn partial_path(root: &Path, designation: &str, id: &UploadId) -> PathBuf {
    root.join(designation).join(partial_name(id))
}

/// Create an empty partial for a new upload, its designation directory
/// made where absent. Answers whether the directory was CREATED here — the
/// finish then owes the root an fsync.
pub(crate) fn create(root: &Path, designation: &str, id: &UploadId) -> io::Result<bool> {
    let dir = root.join(designation);
    let fresh = !dir.is_dir();
    if fresh {
        fs::create_dir_all(&dir)?;
    }
    let f = File::create(partial_path(root, designation, id))?;
    f.sync_all()?;
    fsync_dir(&dir)?;
    Ok(fresh)
}

/// Open a partial for one request at `offset` — the record's durable
/// offset, where a resume continues and a finish with no handle open reads
/// to: the file cut back to it where longer, the hasher built over its
/// first `offset` bytes. The record's offset never passes the file's length
/// past open's reconciliation; a shorter file here is a defect, answered as
/// I/O, and an absent one — a finish's rename took it — is I/O too.
pub(crate) fn open_at(root: &Path, designation: &str, id: &UploadId, offset: u64) -> io::Result<Handle> {
    let path = partial_path(root, designation, id);
    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    let len = file.metadata()?.len();
    if len < offset {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("partial {} holds {len} bytes, its record {offset}", path.display()),
        ));
    }
    if len > offset {
        file.set_len(offset)?;
        file.sync_all()?;
    }
    let hasher = hash_prefix(&mut file, offset)?;
    file.seek(SeekFrom::End(0))?;
    Ok(Handle { file, hasher, written: offset, torn: false })
}

/// The hasher over the first `len` bytes of `file`, read from its start by
/// blake3's own reader loop, which retries an interrupted read as `Read`'s
/// contract asks; a file shorter than `len` answers `UnexpectedEof`.
fn hash_prefix(file: &mut File, len: u64) -> io::Result<blake3::Hasher> {
    file.seek(SeekFrom::Start(0))?;
    let mut prefix = file.take(len);
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(&mut prefix)?;
    if prefix.limit() > 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial short"));
    }
    Ok(hasher)
}

impl Handle {
    /// The bytes written so far, durable or not — counted by the writes
    /// that succeeded. Past a failed write the file may hold more, which
    /// the next resume cuts off.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// The hash of every byte written so far — after [`Handle::sync`], of
    /// every byte on disk.
    pub fn hash(&self) -> blake3::Hash {
        self.hasher.finalize()
    }

    /// Write `bytes` at the end and hash them; not yet durable. Refused on
    /// a torn handle; a write that fails tears it, whatever part of `bytes`
    /// reached the file.
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.refuse_torn()?;
        if let Err(e) = self.file.write_all(bytes) {
            self.torn = true;
            return Err(e);
        }
        self.hasher.update(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }

    /// Make every byte written durable — the one fsync a grain costs.
    /// Refused on a torn handle; a sync that fails tears it, since a
    /// retried fsync can answer success over pages the failed one dropped,
    /// and no later sync vouches for those bytes.
    pub fn sync(&mut self) -> io::Result<()> {
        self.refuse_torn()?;
        if let Err(e) = self.file.sync_all() {
            self.torn = true;
            return Err(e);
        }
        Ok(())
    }

    /// A torn handle's refusal of a write or a sync.
    fn refuse_torn(&self) -> io::Result<()> {
        if self.torn {
            return Err(io::Error::other(
                "an earlier write or sync of this partial failed: the next resume reopens the partial",
            ));
        }
        Ok(())
    }
}

/// Remove a partial, its directory fsynced where one went; absent is fine.
pub(crate) fn remove(root: &Path, designation: &str, id: &UploadId) -> io::Result<()> {
    if remove_if_present(&partial_path(root, designation, id))? {
        fsync_dir(&root.join(designation))?;
    }
    Ok(())
}

/// THE RECONCILIATION AT OPEN, both ways, in every designation directory
/// under `root`.
pub(crate) fn reconcile(root: &Path, records: &mut UploadRecords, now_ms: u64) -> io::Result<()> {
    let mut named: HashSet<(String, UploadId)> = HashSet::new();
    // Records first: expired ones removed as the end and the pruner remove
    // one, the partial before the record; the rest held to their partials.
    let all: Vec<_> = records.all().cloned().collect();
    for r in &all {
        if !r.stands(now_ms) {
            remove(root, &r.designation, &r.id)?;
            records.retire(&r.id)?;
            continue;
        }
        let path = partial_path(root, &r.designation, &r.id);
        let Ok(meta) = fs::metadata(&path) else {
            records.retire(&r.id)?;
            continue;
        };
        let len = meta.len();
        if len > r.offset {
            let f = OpenOptions::new().write(true).open(&path)?;
            f.set_len(r.offset)?;
            f.sync_all()?;
        } else if len < r.offset {
            let mut set_back = r.clone();
            set_back.offset = len;
            records.write(set_back)?;
        }
        named.insert((r.designation.clone(), r.id));
    }
    // Then the directories: every partial no record names is an orphan.
    for designation in dirs_under(root)? {
        let orphans = names_in(root, &designation, |name, _| {
            id_of_partial_name(name).is_some_and(|id| !named.contains(&(designation.clone(), id)))
        })?;
        let dir = root.join(&designation);
        for name in &orphans {
            fs::remove_file(dir.join(name))?;
        }
        if !orphans.is_empty() {
            fsync_dir(&dir)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh partial under `root`: its identifier, the handle opened at
    /// offset 0, and its path.
    fn opened(root: &Path) -> (UploadId, Handle, PathBuf) {
        let id = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
        create(root, "blake3", &id).unwrap();
        (id, open_at(root, "blake3", &id, 0).unwrap(), partial_path(root, "blake3", &id))
    }

    /// A RESUME BELOW WHAT THE FILE HOLDS hashes the file as cut back: A
    /// written and synced, B written, the request's handle dropped with the
    /// record's offset still 0 — its write having failed after A's sync —
    /// and the next request, opened at 0, has what follows hashed over the
    /// file's bytes alone.
    #[test]
    fn a_resume_below_what_the_file_holds_hashes_the_file_as_cut_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (id, mut handle, path) = opened(dir.path());
        handle.write(b"A, synced").unwrap();
        handle.sync().unwrap();
        handle.write(b"B, never synced").unwrap();
        drop(handle);
        let mut handle = open_at(dir.path(), "blake3", &id, 0).unwrap();
        handle.write(b"C").unwrap();
        handle.sync().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"C");
        assert_eq!(handle.hash(), blake3::hash(b"C"), "the hash is the file's bytes'");
    }

    /// A FAILED WRITE TEARS THE HANDLE: bytes it left on disk are counted
    /// by no hasher, so nothing is written or synced through that handle
    /// again; the next request, opened at the record's offset, has them cut
    /// off and continues there, its hash its file's.
    #[test]
    fn a_failed_write_tears_the_handle_until_the_next_resume() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (id, mut handle, path) = opened(dir.path());
        handle.write(b"A").unwrap();
        handle.sync().unwrap();
        // A read-only file: the next write fails at the OS, as a full or
        // failing disk's would. The bytes a write cut short leaves land
        // through a second open file, and the handle's own file comes back
        // past them, where the failed write left its position.
        handle.file = File::open(&path).unwrap();
        assert!(handle.write(b"B").is_err());
        OpenOptions::new().append(true).open(&path).unwrap().write_all(b"stray").unwrap();
        handle.file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        handle.file.seek(SeekFrom::End(0)).unwrap();
        assert!(handle.write(b"C").is_err(), "a torn handle takes no write");
        assert!(handle.sync().is_err(), "and no sync");
        assert_eq!(fs::read(&path).unwrap(), b"Astray");
        drop(handle);
        let mut handle = open_at(dir.path(), "blake3", &id, 1).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"A", "the resume cuts off what no hasher covers");
        handle.write(b"C").unwrap();
        handle.sync().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"AC");
        assert_eq!(handle.hash(), blake3::hash(b"AC"));
        assert_eq!(handle.written(), 2);
    }

    /// A PARTIAL SHORTER THAN ITS RECORD's OFFSET IS REFUSED, NEVER EXTENDED:
    /// opened past its bytes, the open answers an error and leaves the file
    /// as it stands, never grown with zeros a resume would append after and a
    /// finish would hash.
    #[test]
    fn a_partial_shorter_than_its_offset_is_refused_and_never_extended() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (id, mut handle, path) = opened(dir.path());
        handle.write(b"abc").unwrap();
        handle.sync().unwrap();
        drop(handle);
        for offset in [4, 100] {
            assert!(open_at(dir.path(), "blake3", &id, offset).is_err(), "offset {offset}");
            assert_eq!(fs::read(&path).unwrap(), b"abc", "offset {offset}: the file as it stood");
        }
    }
}
