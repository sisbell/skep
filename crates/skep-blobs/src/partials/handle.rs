//! Every resume opens the partial afresh.
//!
//! The open (`media.md` Op inventory 1, the resumable upload (3), (5);
//! [`open_at`]) cuts the partial back to its record's offset where longer,
//! its bytes up to that offset hashed from the first, so whatever an earlier
//! request left past the offset — a write that failed partway, bytes synced
//! before a record write that failed — is gone before another byte lands.
//! No handle outlives its request ([`Handle`]).
//!
//! Beside the handle, the function its hasher computes ([`HashFunction`])
//! and the designation that function's files are filed under.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::partial_path;
use crate::blobs::{named, partial_label};
use crate::uploads::UploadId;

/// The hash functions a handle computes: one, BLAKE3's default hash.
///
/// It hashes the file's bytes, 32 bytes spelled as 64 lowercase hex, the
/// hash the cell's schema names (`media.md` §The design, item 4, "the hash
/// is BLAKE3"). A key names the function that made it ("every sidecar key
/// names its function, from the first file"), so a creation names one of
/// these ([`Store::create_upload`](crate::Store::create_upload)), and its
/// partial, record, file and lease are filed under its designation; a
/// second schema's hash is a second variant here, beside its own hasher.
///
/// `#[non_exhaustive]`: a caller names a variant and has no match to make
/// over them, so a further function is an addition rather than a broken
/// build; this crate's own matches see every variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashFunction {
    /// BLAKE3's default hash, designated `blake3`.
    Blake3,
}

impl HashFunction {
    /// Every function this store computes.
    ///
    /// So their designations are the ones this build pins: open removes an
    /// orphan partial under these alone (`media.md` Op inventory 1, the
    /// resumable upload (4), "in every designation directory under `blobs/`
    /// that this build's schemas pin"; `partials::reconcile`). A variant
    /// joins this list as it joins the enum; the unit suite walks it.
    pub(crate) const ALL: [HashFunction; 1] = [HashFunction::Blake3];

    /// Returns the function's designation, the name its keys spell it by.
    ///
    /// It is also the directory under the root its files live in. Every
    /// variant's passes the store's name check (this file's unit suite holds
    /// them to it).
    pub const fn designation(self) -> &'static str {
        match self {
            HashFunction::Blake3 => "blake3",
        }
    }
}

/// The handle: the partial opened for one request.
///
/// It is opened by [`open_at`] at the request's resume, and dropped with its
/// [`Stream`](crate::Stream): the partial's open file, the hasher over every
/// byte written, the count of those bytes, and whether a write or sync has
/// failed. The fields are this file's alone — only [`open_at`],
/// [`Handle::write`] and [`Handle::sync`] move them, save the unit suite's
/// swap of the open file — and the claim they keep holds across a failed
/// call: the hasher is the hash of exactly the bytes written, so the hash a
/// finish names the file by ([`Handle::hash`]) is its bytes' hash. A write
/// or sync that fails marks the handle torn — the file may then hold bytes
/// no hasher covers, or bytes whose durability nothing vouches for — and a
/// torn handle takes no further write or sync: the next resume opens the
/// partial afresh at its record's offset. Every failure names the partial
/// by its directory ([`partial_label`]), never by its file name, an
/// upload's identifier.
pub(crate) struct Handle {
    file: File,
    /// The partial as a line names it: `a partial in blobs/blake3/`.
    name: String,
    hasher: blake3::Hasher,
    written: u64,
    torn: bool,
}

/// Opens a partial for one request at `offset`, the record's durable offset.
///
/// A resume continues there: the file is cut back to it where longer, and
/// the hasher built over its first `offset` bytes. The record's offset
/// never passes the file's length past open's reconciliation.
///
/// # Errors
///
/// A shorter file here is no state this store leaves — a disk changed under
/// it, or two streams of one upload — answered as I/O (`InvalidData`) and
/// never extended. An absent one is I/O too, its kind `NotFound`: a finish
/// that failed past its rename took it, or an end whose unlink went through
/// before its directory's fsync failed, and no resume continues the upload,
/// so the error names the act that ends it — the upload's end and a PUT of
/// its bytes again — where a client reads it, `blob_io`'s detail, and where
/// an operator quotes the client (`RUNBOOK.md` §1), and never leads either
/// to read the board's own files as lost. Any other failure of the open,
/// the stat, the cut-back or the read is named with its act.
pub(crate) fn open_at(root: &Path, designation: &str, id: &UploadId, offset: u64) -> io::Result<Handle> {
    let path = partial_path(root, designation, id);
    let name = partial_label(&root.join(designation));
    let open = |e: io::Error| {
        let absent = e.kind() == io::ErrorKind::NotFound;
        let e = named(e, &name, "open");
        if !absent {
            return e;
        }
        // Neither room nor the pruner's pass brings the partial back, and a
        // re-PUT leases the file — the one the rename already named, where a
        // finish took the partial.
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{e}; no partial stands for this upload, so no resume continues it: end the upload and PUT its \
                 bytes again"
            ),
        )
    };
    let mut file = OpenOptions::new().read(true).write(true).open(&path).map_err(open)?;
    let len = file.metadata().map_err(|e| named(e, &name, "stat"))?.len();
    if len < offset {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} holds {len} bytes, short of its record's offset {offset}: refused and never extended"),
        ));
    }
    if len > offset {
        let cut = |e| named(e, &name, "cut back");
        file.set_len(offset).map_err(cut)?;
        file.sync_all().map_err(cut)?;
    }
    let read = |e| named(e, &name, "read");
    let hasher = hash_prefix(&mut file, offset).map_err(read)?;
    file.seek(SeekFrom::End(0)).map_err(read)?;
    Ok(Handle { file, name, hasher, written: offset, torn: false })
}

/// Returns the hasher over the first `len` bytes of `file`.
///
/// The bytes are read from its start by blake3's own reader loop, which
/// retries an interrupted read as `Read`'s contract asks.
///
/// # Errors
///
/// A file shorter than `len` answers `UnexpectedEof`; a seek or a read that
/// fails answers the OS's failure.
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
    /// Returns the bytes written so far, durable or not.
    ///
    /// They are the offset the handle was opened at, and the bytes of every
    /// write that has succeeded since. Past a failed write the file may hold
    /// more, which the next resume cuts off.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Returns the hash of every byte written so far.
    ///
    /// After [`Handle::sync`], it is the hash of every byte on disk.
    pub fn hash(&self) -> blake3::Hash {
        self.hasher.finalize()
    }

    /// Writes `bytes` at the end and hashes them; not yet durable.
    ///
    /// # Errors
    ///
    /// Refused on a torn handle; a write that fails tears it, whatever part
    /// of `bytes` reached the file.
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.refuse_torn()?;
        if let Err(e) = self.file.write_all(bytes) {
            self.torn = true;
            return Err(named(e, &self.name, "write"));
        }
        self.hasher.update(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }

    /// Makes every byte written durable — a grain's one fsync of the partial.
    ///
    /// # Errors
    ///
    /// Refused on a torn handle; a sync that fails tears it, since a
    /// retried fsync can answer success over pages the failed one dropped,
    /// and no later sync vouches for those bytes.
    pub fn sync(&mut self) -> io::Result<()> {
        self.refuse_torn()?;
        if let Err(e) = self.file.sync_all() {
            self.torn = true;
            return Err(named(e, &self.name, "sync"));
        }
        Ok(())
    }

    /// Refuses a write or a sync on a torn handle.
    ///
    /// # Errors
    ///
    /// The torn handle's refusal, where an earlier write or sync failed.
    fn refuse_torn(&self) -> io::Result<()> {
        if self.torn {
            return Err(io::Error::other(format!(
                "{}: an earlier write or sync of it failed: the next resume reopens it",
                self.name
            )));
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

    /// Creates a fresh partial under `root`, its handle opened at offset 0.
    ///
    /// Answers its identifier, the handle, and its path.
    fn fresh_partial(root: &Path) -> (UploadId, Handle, PathBuf) {
        let id = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
        create(root, "blake3", &id).unwrap();
        (id, open_at(root, "blake3", &id, 0).unwrap(), partial_path(root, "blake3", &id))
    }

    /// A resume below what the file holds hashes the file as cut back.
    ///
    /// A is written and synced, B written, the request's handle dropped with
    /// the record's offset still 0 — its write having failed after A's sync —
    /// and the next request, opened at 0, has what follows hashed over the
    /// file's bytes alone.
    #[test]
    fn a_resume_below_what_the_file_holds_hashes_the_file_as_cut_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (id, mut handle, path) = fresh_partial(dir.path());
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

    /// A failed write tears the handle.
    ///
    /// Bytes it left on disk are counted by no hasher, so nothing is written
    /// or synced through that handle again; the next request, opened at the
    /// record's offset, has them cut off and continues there, its hash its
    /// file's.
    #[test]
    fn a_failed_write_tears_the_handle_until_the_next_resume() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (id, mut handle, path) = fresh_partial(dir.path());
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

    /// Every function's designation passes the name check.
    ///
    /// A creation files under it, every read takes a name back through that
    /// check, and open's reconciliation walks the directory of each function
    /// on the list this build pins (`HashFunction::ALL`); and BLAKE3's, on
    /// that list, is the cell schema's own, `blake3`.
    #[test]
    fn every_functions_designation_passes_the_name_check() {
        for function in HashFunction::ALL {
            assert!(crate::blobs::designation_ok(function.designation()), "{function:?}");
        }
        assert!(HashFunction::ALL.contains(&HashFunction::Blake3), "the store computes BLAKE3's hash");
        assert_eq!(HashFunction::Blake3.designation(), "blake3");
    }

    /// A partial shorter than its record's offset is refused, never extended.
    ///
    /// Opened past its bytes, the open answers an error and leaves the file
    /// as it stands, never grown with zeros a resume would append after and a
    /// finish would hash.
    #[test]
    fn a_partial_shorter_than_its_offset_is_refused_and_never_extended() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (id, mut handle, path) = fresh_partial(dir.path());
        handle.write(b"abc").unwrap();
        handle.sync().unwrap();
        drop(handle);
        for offset in [4, 100] {
            assert!(open_at(dir.path(), "blake3", &id, offset).is_err(), "offset {offset}");
            assert_eq!(fs::read(&path).unwrap(), b"abc", "offset {offset}: the file as it stood");
        }
    }
}
