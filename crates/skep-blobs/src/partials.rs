//! THE PARTIALS, `<root>/<designation>/.upload-<identifier>` — the bytes
//! received so far of one standing upload, a temp file in its target's own
//! designation directory (`media.md` Op inventory 1, the resumable upload
//! (1), (3), (4); §The media stores). A BYTE IS RECEIVED ONCE IT IS DURABLE
//! IN THE PARTIAL: the file is fsynced at [`SYNC_GRAIN`] and at every
//! request's end, the record's offset and expiry written after each sync,
//! so the offset a resume continues from, the bytes received the deposit
//! read answers and the byte the expiry is fixed from are one figure; a
//! partial longer than its record's offset is cut back to it before a
//! resume appends.
//!
//! AT OPEN THE TWO ARE RECONCILED BOTH WAYS: a partial no record names is
//! removed, in every designation directory under the root; a record that
//! names no partial is retired; and their lengths are set to agree — a
//! longer partial cut back to the record's offset, a record whose offset
//! passes its partial's length set back to that length. An expired upload
//! has its partial removed and its record retired at open too, in the order
//! the end and the daemon's pruner take while the store serves
//! ([`Store::expire_upload`](crate::Store::expire_upload) is the pass's
//! door).

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::blobs::{dirs_under, fsync_dir, names_in};
use crate::uploads::{UploadId, UploadRecords};

/// THE FSYNC GRAIN of a partial — 1 MiB, INTERIM: the most a dropped
/// connection re-sends, against one fsync of the partial and one of the
/// record log per grain (sixty-four of each for a file at the per-file cap).
pub const SYNC_GRAIN: u64 = 1024 * 1024;

/// One upload open in this process: its partial's handle, the hasher over
/// every byte written so far, the hasher as it stood at the last durable
/// point and the count of bytes that point covers, the bytes written, and
/// whether a write or sync has failed since the last cut-back. The fields
/// are this file's alone — only [`open_at`], [`Live::write`], [`Live::sync`]
/// and [`Live::cut_back_to`] move them — and the claim they keep holds
/// across a failed call: the hasher is the hash of exactly the bytes
/// written, the durable hasher of exactly the first `durable` bytes, so the
/// hash a finish names the file by ([`Live::hash`]) is its bytes' hash. A
/// write or sync that fails marks the upload TORN — the file may then hold
/// bytes no hasher covers, or bytes whose durability nothing vouches for —
/// and nothing is written or synced until a cut-back has put the file at a
/// count its hasher covers. A torn upload needs no release: the next resume
/// is that cut-back.
pub(crate) struct Live {
    file: File,
    hasher: blake3::Hasher,
    hasher_durable: blake3::Hasher,
    durable: u64,
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

/// Open a partial for a resume at `offset` — the record's durable offset:
/// the file cut back to it where longer, the hasher rebuilt over its first
/// `offset` bytes. The record's offset never passes the file's length past
/// open's reconciliation; a shorter file here is a defect, answered as I/O.
pub(crate) fn open_at(root: &Path, designation: &str, id: &UploadId, offset: u64) -> io::Result<Live> {
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
    Ok(Live { file, hasher: hasher.clone(), hasher_durable: hasher, durable: offset, written: offset, torn: false })
}

/// The hasher over the first `len` bytes of `file`, read from its start.
fn hash_prefix(file: &mut File, len: u64) -> io::Result<blake3::Hasher> {
    let mut hasher = blake3::Hasher::new();
    if len > 0 {
        file.seek(SeekFrom::Start(0))?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut left = len;
        while left > 0 {
            let want = buf.len().min(left as usize);
            let n = file.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial short"));
            }
            hasher.update(&buf[..n]);
            left -= n as u64;
        }
    }
    Ok(hasher)
}

impl Live {
    /// The bytes written so far, durable or not — counted by the writes
    /// that succeeded. Past a failed write the file may hold more, which
    /// the next cut-back removes.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// The hash of every byte written so far — after [`Live::sync`], of
    /// every byte on disk.
    pub fn hash(&self) -> blake3::Hash {
        self.hasher.finalize()
    }

    /// Write `bytes` at the end and hash them; not yet durable. Refused on
    /// a torn upload; a write that fails tears it, whatever part of `bytes`
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

    /// Make every byte written durable — the one fsync a grain costs — and
    /// move the durable point to it. Refused on a torn upload; a sync that
    /// fails tears it, since a retried fsync can answer success over pages
    /// the failed one dropped, and no later sync vouches for those bytes.
    pub fn sync(&mut self) -> io::Result<()> {
        self.refuse_torn()?;
        if let Err(e) = self.file.sync_all() {
            self.torn = true;
            return Err(e);
        }
        self.hasher_durable = self.hasher.clone();
        self.durable = self.written;
        Ok(())
    }

    /// Cut the file back to `offset`, and the hashers with it — a resume in
    /// this process. `offset` is the record's durable offset, which never
    /// passes this upload's durable point: the record's offset is written
    /// only after a sync, from the count that sync covered. Three branches:
    /// an upload whole at `offset` is left as it is; one whose durable point
    /// is `offset` takes its durable hasher back; and one whose durable
    /// point passes `offset` — the record's write failed after the partial's
    /// sync — rebuilds its hasher from the file's first `offset` bytes. A
    /// torn upload is always cut, and stays torn until the cut completes.
    pub fn cut_back_to(&mut self, offset: u64) -> io::Result<()> {
        debug_assert!(offset <= self.durable, "a record's offset never passes the bytes its upload synced");
        if !self.torn && self.written == offset {
            return Ok(());
        }
        self.torn = true;
        self.file.set_len(offset)?;
        self.file.sync_all()?;
        let hasher =
            if offset == self.durable { self.hasher_durable.clone() } else { hash_prefix(&mut self.file, offset)? };
        self.file.seek(SeekFrom::End(0))?;
        self.hasher = hasher.clone();
        self.hasher_durable = hasher;
        self.durable = offset;
        self.written = offset;
        self.torn = false;
        Ok(())
    }

    /// A torn upload's refusal of a write or a sync.
    fn refuse_torn(&self) -> io::Result<()> {
        if self.torn {
            return Err(io::Error::other(
                "an earlier write or sync of this partial failed: a resume cuts it back before another",
            ));
        }
        Ok(())
    }
}

/// Remove a partial; absent is fine.
pub(crate) fn remove(root: &Path, designation: &str, id: &UploadId) -> io::Result<()> {
    match fs::remove_file(partial_path(root, designation, id)) {
        Ok(()) => fsync_dir(&root.join(designation)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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
            records.put(set_back, true)?;
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

    /// A fresh partial under `root`, opened at offset 0, and its path.
    fn opened(root: &Path) -> (Live, PathBuf) {
        let id = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
        create(root, "blake3", &id).unwrap();
        (open_at(root, "blake3", &id, 0).unwrap(), partial_path(root, "blake3", &id))
    }

    /// A CUT-BACK BELOW THE DURABLE POINT rebuilds the hasher from the
    /// file: A written and synced, B written, the upload cut back to 0 —
    /// the record's write having failed after A's sync — and what follows
    /// is hashed over the file's bytes alone.
    #[test]
    fn a_cut_back_below_the_durable_point_rebuilds_the_hash_from_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut live, path) = opened(dir.path());
        live.write(b"A, synced").unwrap();
        live.sync().unwrap();
        live.write(b"B, never synced").unwrap();
        live.cut_back_to(0).unwrap();
        live.write(b"C").unwrap();
        live.sync().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"C");
        assert_eq!(live.hash(), blake3::hash(b"C"), "the hash is the file's bytes'");
    }

    /// A FAILED WRITE TEARS THE UPLOAD: bytes it left on disk are counted
    /// by no hasher, so nothing is written or synced until a cut-back
    /// removes them; past it, the upload continues from its durable point
    /// and its hash is its file's.
    #[test]
    fn a_failed_write_tears_the_upload_until_a_cut_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut live, path) = opened(dir.path());
        live.write(b"A").unwrap();
        live.sync().unwrap();
        // A read-only handle: the next write fails at the OS, as a full or
        // failing disk's would. The bytes a write cut short leaves land
        // through a second handle, and the upload's own handle comes back
        // past them, where the failed write left its position.
        live.file = File::open(&path).unwrap();
        assert!(live.write(b"B").is_err());
        OpenOptions::new().append(true).open(&path).unwrap().write_all(b"stray").unwrap();
        live.file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        live.file.seek(SeekFrom::End(0)).unwrap();
        assert!(live.write(b"C").is_err(), "a torn upload takes no write");
        assert!(live.sync().is_err(), "and no sync");
        assert_eq!(fs::read(&path).unwrap(), b"Astray");
        live.cut_back_to(1).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"A", "the cut-back removes what no hasher covers");
        live.write(b"C").unwrap();
        live.sync().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"AC");
        assert_eq!(live.hash(), blake3::hash(b"AC"));
        assert_eq!(live.written(), 2);
    }
}
