//! EVERY RESUME OPENS THE PARTIAL AFRESH (`media.md` Op inventory 1, the
//! resumable upload (3), (5); [`open_at`]): cut back to its record's offset
//! where longer, its bytes up to that offset hashed from the first, so
//! whatever an earlier request left past the offset — a write that failed
//! partway, bytes synced before a record write that failed — is gone before
//! another byte lands. No handle outlives its request ([`Handle`]).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::partial_path;
use crate::uploads::UploadId;

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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::partials::create;

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
