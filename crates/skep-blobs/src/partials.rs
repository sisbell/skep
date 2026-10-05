//! THE PARTIALS, `<root>/<designation>/.upload-<identifier>` — the bytes
//! received so far of one standing upload, a temp file in its target's own
//! designation directory (`media.md` Op inventory 1, the resumable upload
//! (1), (3), (4); §The media stores). A BYTE IS RECEIVED ONCE IT IS DURABLE
//! IN THE PARTIAL: the file is fsynced at [`SYNC_GRAIN`] and at the settle
//! or finish that ends a request, the record's offset and expiry written
//! after each sync, so the offset a resume continues from, the bytes
//! received the deposit read answers and the byte the expiry is fixed from
//! are one figure.
//!
//! A request writes a partial through its stream's handle, opened afresh at
//! every resume (`partials/handle.rs`: [`Handle`], [`open_at`]).
//!
//! AT OPEN THE TWO ARE RECONCILED BOTH WAYS: a partial no record names is
//! removed, in every designation directory under the root; a record that
//! names no partial is retired; and their lengths are set to agree — a
//! longer partial cut back to the record's offset, a record whose offset
//! passes its partial's length set back to that length, its expiry kept
//! (`UploadRecords::set_back`). A partial that cannot be read fails the
//! open, retiring nothing: it is still named, and a retirement written over
//! it would have the next open remove it as an orphan (clause (4) retires a
//! record that names no partial, and only that). An expired upload has its
//! partial removed and its record retired at open too, in the order the end
//! and the daemon's pruner take while the store serves
//! ([`Store::expire_upload`](crate::Store::expire_upload) is the pass's
//! act).

// The handle a request opens on a partial: its open file, the hash of
// every byte written and the designation that hash files under, and the
// tear a failed write or sync leaves.
mod handle;

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::blobs::{dirs_under, fsync_dir, names_in, remove_if_present};
use crate::uploads::{UploadId, UploadRecords};

pub(crate) use handle::{open_at, Handle, HASH_DESIGNATION};

/// THE FSYNC GRAIN of a partial — 1 MiB, INTERIM: the most a dropped
/// connection re-sends, against one fsync of the partial and one of the
/// record log per grain (sixty-four of each for a file at the per-file cap).
pub const SYNC_GRAIN: u64 = 1024 * 1024;

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
/// made where absent — the directory's own entry in the root left to the
/// finish, which fsyncs the root for any directory no root fsync since the
/// open has made durable.
pub(crate) fn create(root: &Path, designation: &str, id: &UploadId) -> io::Result<()> {
    let dir = root.join(designation);
    fs::create_dir_all(&dir)?;
    let f = File::create(partial_path(root, designation, id))?;
    f.sync_all()?;
    fsync_dir(&dir)?;
    Ok(())
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
        // Absent is the one answer that retires: a record naming a partial
        // that cannot be read still names one, so that failure fails the
        // open, and nothing is retired for a later open to remove as orphan.
        let len = match fs::metadata(&path) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                records.retire(&r.id)?;
                continue;
            }
            Err(e) => return Err(e),
        };
        if len > r.offset {
            let f = OpenOptions::new().write(true).open(&path)?;
            f.set_len(r.offset)?;
            f.sync_all()?;
        } else if len < r.offset {
            records.set_back(&r.id, len)?;
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
