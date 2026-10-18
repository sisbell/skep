//! The partials, `<root>/<designation>/.upload-<identifier>`.
//!
//! A partial holds the bytes received so far of one upload, a temp file in
//! its target's own designation directory (`media.md` Op inventory 1, the
//! resumable upload (1), (3), (4); §The media stores).
//!
//! **A byte is received once it is durable in the partial and in its
//! record's offset.** The file is fsynced at [`SYNC_GRAIN`] and at the
//! settle or finish that ends a request, the record's offset and expiry
//! written after each sync but the finish's, which retires the record
//! instead, so the offset a resume continues from, the bytes received the
//! deposit read answers and the byte the expiry is fixed from are one
//! figure.
//!
//! A request writes a partial through its stream's handle, opened afresh at
//! every resume (`partials/handle.rs`: [`Handle`], [`open_at`]).
//!
//! **At open the two are reconciled both ways.** A partial no record names —
//! a crash's orphan — is removed in every designation directory this build
//! pins, the directory of each [`HashFunction`] it computes, and in no
//! other: a directory under another designation is another build's, its
//! partials its own (clause (4), "in every designation directory under
//! `blobs/` that this build's schemas pin"; the pruner's unlink pass halts
//! on such a directory, D13's carve-out); a record that names no partial is
//! retired; and their lengths are set to agree — a longer partial cut back
//! to the record's offset, a record whose offset passes its partial's
//! length set back to that length, its expiry kept
//! (`UploadRecords::set_back`). A partial that cannot be read fails the
//! open, its record not retired: it is still named, and a retirement
//! written over it would have the next open remove it as an orphan (clause
//! (4) retires a record that names no partial, and only that). An expired
//! upload has its partial removed and its record retired at open too, in
//! the order the end and the daemon's pruner take while the store serves
//! ([`Store::expire_upload`](crate::Store::expire_upload) is the pass's
//! act).

// The handle a request opens on a partial: its open file, the hash of
// every byte written, and the tear a failed write or sync leaves; and
// `HashFunction`, the functions that hash can be, each with the
// designation it files under.
mod handle;

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::blobs::{
    dir_builder, dir_label, file_options, fsync_dir, named, names_in, not_found_as_none, partial_label,
    remove_if_present, remove_standing,
};
use crate::uploads::{UploadId, UploadRecords};

pub use handle::HashFunction;
pub(crate) use handle::{open_at, Handle};

/// The fsync grain of a partial: 1 MiB, interim.
///
/// The resumable upload's clause (3) (`media.md` Op inventory 1) has the
/// partial "fsynced at a grain the subsystem design pins", and this is that
/// grain: the most a dropped connection re-sends, against one fsync of the
/// partial and one of the record log per grain. A pin, moved by a design
/// decision, and its two twins move with it: `docs/wire.md` §Media's list
/// of pins and the media fixture's `pins.sync_grain`, which skepd's suite
/// holds to this constant (`tests/it/blob_routes.rs`). No byte count on
/// disk depends on it, so a build that moves it reads every log an older
/// build wrote.
pub const SYNC_GRAIN: u64 = 1024 * 1024;

/// Returns the partial's file name inside its designation directory.
///
/// The name is `.upload-<identifier>`: the dot keeps it apart from any hex
/// name a walk of the directory reads as a blob. The operator's pull names
/// its temp file so too (`Store::install_file`), with a fresh identifier no
/// record names, so an open that meets it mid-pull removes it as the orphan
/// it is.
pub(crate) fn partial_name(id: &UploadId) -> String {
    format!(".upload-{id}")
}

/// Returns the identifier a partial's file name spells, if it is one.
pub(crate) fn id_of_partial_name(name: &str) -> Option<UploadId> {
    name.strip_prefix(".upload-").and_then(UploadId::parse)
}

/// Returns the partial's path.
pub(crate) fn partial_path(root: &Path, designation: &str, id: &UploadId) -> PathBuf {
    root.join(designation).join(partial_name(id))
}

/// Creates an empty partial for a new upload.
///
/// Its designation directory is made where absent — the directory's own
/// entry in the root left to the finish, which fsyncs the root for any
/// directory no root fsync since the open has made durable.
///
/// # Errors
///
/// The designation directory's creation, the partial's creation or its
/// sync — named as its creation — or the directory's fsync failing.
pub(crate) fn create(root: &Path, designation: &str, id: &UploadId) -> io::Result<()> {
    let dir = root.join(designation);
    // Both born owner-only (`blobs::dir_builder`, `blobs::file_options`):
    // the bytes received are the depositor's from the first grain, and the
    // finish's rename carries the partial's mode onto its hex name.
    dir_builder().recursive(true).create(&dir).map_err(|e| named(e, dir_label(&dir, 2), "create"))?;
    let created = |e| named(e, partial_label(&dir), "create");
    let f = file_options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(partial_path(root, designation, id))
        .map_err(created)?;
    f.sync_all().map_err(created)?;
    fsync_dir(&dir).map_err(|e| named(e, dir_label(&dir, 2), "fsync"))?;
    Ok(())
}

/// Removes a partial, its directory fsynced where one went; absent is fine.
///
/// Answers the bytes its unlink freed — none where no partial stood.
///
/// # Errors
///
/// The removal failing, save for the partial's absence, or the directory's
/// fsync after it.
pub(crate) fn remove(root: &Path, designation: &str, id: &UploadId) -> io::Result<u64> {
    let dir = root.join(designation);
    let removed =
        remove_if_present(&partial_path(root, designation, id)).map_err(|e| named(e, partial_label(&dir), "remove"))?;
    let Some(freed) = removed else {
        return Ok(0);
    };
    fsync_dir(&dir).map_err(|e| named(e, dir_label(&dir, 2), "fsync"))?;
    Ok(freed)
}

/// What the reconciliation did, by act.
///
/// The figures are the open's account's ([`Opened`](crate::Opened)).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Reconciled {
    /// Expired uploads removed, the partial and then the record.
    pub expired: usize,
    /// Records retired, their partials gone.
    pub without_partial: usize,
    /// Partials cut back to their records' offsets.
    pub cut_back: usize,
    /// Records set back to their partials' lengths.
    pub set_back: usize,
    /// Orphan partials removed — partials no record names.
    pub orphans: usize,
    /// The bytes those acts freed.
    ///
    /// They are the expired uploads' and the orphans' partials removed, and
    /// the bytes cut off the partials cut back.
    pub bytes_freed: u64,
}

/// Reconciles the records and the partials at open, both ways.
///
/// Every standing record is held to its partial, and every orphan removed
/// under the designations this build pins alone ([`HashFunction::ALL`]).
/// Answers what it did ([`Reconciled`]).
///
/// # Errors
///
/// An expired upload's removal or retirement failing; a partial's stat
/// failing other than for its absence; a partial's cut-back, a set-back's
/// write or a retirement failing; or a designation directory's listing, an
/// orphan's removal or the directory's fsync failing.
pub(crate) fn reconcile(root: &Path, records: &mut UploadRecords, now_ms: u64) -> io::Result<Reconciled> {
    let mut did = Reconciled::default();
    // The identifiers the standing records name, by designation directory.
    let mut named_ids: HashMap<String, HashSet<UploadId>> = HashMap::new();
    // Records first: expired ones removed as the end and the pruner remove
    // one, the partial before the record; the rest held to their partials.
    let all: Vec<_> = records.all().cloned().collect();
    for r in &all {
        if !r.stands(now_ms) {
            did.bytes_freed += remove(root, &r.designation, &r.id)?;
            records.retire(&r.id)?;
            did.expired += 1;
            continue;
        }
        let path = partial_path(root, &r.designation, &r.id);
        let partial = |e| named(e, partial_label(&root.join(&r.designation)), "stat");
        // Absent is the one answer that retires: a record naming a partial
        // that cannot be read still names one, so that failure fails the
        // open, and its record is not retired for a later open to remove its
        // partial as orphan.
        let Some(meta) = not_found_as_none(fs::metadata(&path)).map_err(partial)? else {
            records.retire(&r.id)?;
            did.without_partial += 1;
            continue;
        };
        let len = meta.len();
        if len > r.offset {
            let cut = |e| named(e, partial_label(&root.join(&r.designation)), "cut back");
            let f = OpenOptions::new().write(true).open(&path).map_err(cut)?;
            f.set_len(r.offset).map_err(cut)?;
            f.sync_all().map_err(cut)?;
            did.cut_back += 1;
            did.bytes_freed += len - r.offset;
        } else if len < r.offset {
            records.set_back(&r.id, len)?;
            did.set_back += 1;
        }
        named_ids.entry(r.designation.clone()).or_default().insert(r.id);
    }
    // Then the directories this build pins, each function's it computes:
    // every partial no record names there is an orphan. A directory under
    // any other designation is another build's, its partials its own, and
    // is left (clause (4)), as the pruner's pass leaves it.
    for function in HashFunction::ALL {
        let designation = function.designation();
        let named_here = named_ids.get(designation);
        let orphans = names_in(root, designation, |name, _| {
            id_of_partial_name(name).is_some_and(|id| !named_here.is_some_and(|ids| ids.contains(&id)))
        })?;
        let dir = root.join(designation);
        for name in &orphans {
            did.bytes_freed += remove_standing(&dir.join(name)).map_err(|e| named(e, partial_label(&dir), "remove"))?;
        }
        if !orphans.is_empty() {
            fsync_dir(&dir).map_err(|e| named(e, dir_label(&dir, 2), "fsync"))?;
        }
        did.orphans += orphans.len();
    }
    Ok(did)
}
