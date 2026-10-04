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
//! is retired and its partial removed at open too, as the daemon's pruner
//! removes one while it serves ([`Store::expire_upload`](crate::Store::expire_upload)
//! is the pass's door); and every ASIDE name a replace left — a crash
//! between the answer and the deferred unlink — is removed, nothing naming
//! it.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::blobs::{designation_ok, fsync_dir, is_aside_name};
use crate::uploads::{UploadId, UploadRecords};

/// THE FSYNC GRAIN of a partial — 1 MiB, INTERIM: the most a dropped
/// connection re-sends, against one fsync of the partial and one of the
/// record log per grain (sixty-four of each for a file at the per-file cap).
pub const SYNC_GRAIN: u64 = 1024 * 1024;

/// One upload open in this process: its partial's handle, the hasher over
/// every byte written so far, the hasher as it stood at the last durable
/// point, and the bytes written (the file's length), which may stand past
/// the record's durable offset until the next sync. The fields are this
/// file's alone — only [`open_at`], [`Live::write`], [`Live::sync`] and
/// [`Live::cut_back_to`] move them — so the hashers stay the hashes of
/// exactly the bytes written and the bytes synced, and the hash a finish
/// names the file by ([`Live::hash`]) is its bytes' hash.
pub(crate) struct Live {
    file: File,
    hasher: blake3::Hasher,
    hasher_durable: blake3::Hasher,
    written: u64,
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
    let mut hasher = blake3::Hasher::new();
    if offset > 0 {
        file.seek(SeekFrom::Start(0))?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut left = offset;
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
    file.seek(SeekFrom::End(0))?;
    Ok(Live { file, hasher: hasher.clone(), hasher_durable: hasher, written: offset })
}

impl Live {
    /// The bytes written so far — the file's length, durable or not.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// The hash of every byte written so far — after [`Live::sync`], of
    /// every byte on disk.
    pub fn hash(&self) -> blake3::Hash {
        self.hasher.finalize()
    }

    /// Write `bytes` at the end and hash them; not yet durable.
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)?;
        self.hasher.update(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }

    /// Make every byte written durable: the one fsync a grain costs.
    pub fn sync(&mut self) -> io::Result<()> {
        self.file.sync_all()?;
        self.hasher_durable = self.hasher.clone();
        Ok(())
    }

    /// Cut the file back to `offset` (the record's durable offset) and the
    /// hasher with it — a resume in this process after a request that
    /// dropped mid-grain.
    pub fn cut_back_to(&mut self, offset: u64) -> io::Result<()> {
        if self.written != offset {
            self.file.set_len(offset)?;
            self.file.sync_all()?;
            self.file.seek(SeekFrom::End(0))?;
            self.hasher = self.hasher_durable.clone();
            self.written = offset;
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
    // Records first: expired ones retired; the rest held to their partials.
    let all: Vec<_> = records.all().cloned().collect();
    for r in &all {
        let path = partial_path(root, &r.designation, &r.id);
        if !r.stands(now_ms) {
            records.retire(&r.id)?;
            let _ = fs::remove_file(&path);
            continue;
        }
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
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !designation_ok(&name) {
            continue;
        }
        let dir = entry.path();
        let mut removed = false;
        for file in fs::read_dir(&dir)? {
            let file = file?;
            let fname = file.file_name().to_string_lossy().into_owned();
            // An aside a replace left behind: a second name of a file whose
            // first name the finish answered, which the deferred unlink
            // never reached. Named by nothing; removed.
            if is_aside_name(&fname) {
                fs::remove_file(file.path())?;
                removed = true;
                continue;
            }
            let Some(id) = id_of_partial_name(&fname) else { continue };
            if !named.contains(&(name.clone(), id)) {
                fs::remove_file(file.path())?;
                removed = true;
            }
        }
        if removed {
            fsync_dir(&dir)?;
        }
    }
    Ok(())
}
