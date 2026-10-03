//! # skep-blobs — the blob store (media lane B)
//!
//! THE FOUR MEDIA STORES UNDER ONE ROOT (`media.md` §The media stores, the
//! set's one home; Op inventory 1, the resumable upload's seven clauses and
//! the lease's crash story; the register M-I5 (a), (c) and M-I6 (c)): the
//! FILES at `<root>/<designation>/<hex>`, the PARTIALS beside them, the
//! UPLOAD RECORDS in `<root>/uploads.log` and the LEASE LOG in
//! `<root>/leases.log`. The daemon hands this crate `blobs/` inside the
//! board's data directory and nothing else of itself: the crate knows NO
//! principal (a key is an opaque string), NO lock (the ordering a finish
//! needs under the daemon's credential-lock read arm is the caller's to
//! hold around [`Store::finish`]) and NO limits record (it answers pending
//! bytes and the volume's free space; what bounds them is policy, the
//! daemon's). What it promises is the ORDER of its own acts and what each
//! leaves behind on a crash:
//!
//! * THE PUT's ORDER ([`Store::finish`]): the partial fsynced, RENAMED onto
//!   `<designation>/<hex>` — REPLACE where the name exists, never a no-op —
//!   that directory fsynced, the root fsynced where this process created
//!   the designation directory, THEN the lease appended and synced, THEN
//!   the upload record retired, THEN the answer. A crash leaves at worst a
//!   file with no lease (unreferenced, prunable) or a retired-by-open
//!   record beside a leased file, and never a lease naming bytes the
//!   restart does not hold.
//! * A BYTE IS RECEIVED ONCE IT IS DURABLE: the partial is fsynced at
//!   [`SYNC_GRAIN`] and at [`Store::settle`], and the record's offset and
//!   expiry are written after each sync.
//! * ONE ANSWER PER KEY: an identifier the asking key's records do not
//!   name is [`BlobError::NoUpload`] whoever minted it; a hash the key
//!   holds no lease on is [`LeaseState::None`] whatever the directory
//!   holds; and a finish answers one shape whether or not the file was
//!   already here.
//! * OPEN RECONCILES AND COMPACTS: both logs tail-checked and rewritten to
//!   their current records; the partials and the records held to each
//!   other both ways (`partials.rs`); a lease past the horizon dropped.
//!
//! The `test-hooks` feature compiles in the hazard seam ([`Step`]): a hold
//! or an injected failure at a named step of the finish.

#![forbid(unsafe_code)]

mod blobs;
mod error;
mod lease;
mod partials;
mod uploads;

pub use blobs::{Finished, Step};
pub use error::BlobError;
pub use lease::{Lease, LeaseState};
pub use partials::SYNC_GRAIN;
pub use uploads::{UploadId, UploadRecord, IDENTIFIER_BYTES};

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use blobs::{blob_path, designation_ok, fsync_dir, hex_ok};
use lease::LeaseLog;
use partials::Live;
use uploads::UploadRecords;

/// The store: one root, the four stores under it, and the uploads open in
/// this process. Every method takes `&self`; the caller serializes the
/// acts of ONE upload (the daemon's hold on an upload's identifier while
/// a stream owns it), and the store's own locks keep its records whole
/// across uploads.
pub struct Store {
    root: PathBuf,
    uploads: Mutex<UploadRecords>,
    leases: Mutex<LeaseLog>,
    live: Mutex<HashMap<UploadId, Live>>,
    /// Designation directories this process created whose entry in the
    /// root is not yet fsynced; the first finish into one syncs the root.
    fresh_dirs: Mutex<HashSet<String>>,
    #[cfg(feature = "test-hooks")]
    hooks: Mutex<blobs::Hooks>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("root", &self.root).finish_non_exhaustive()
    }
}

impl Store {
    /// Open the store at `root` (created where absent): the lease log
    /// opened and compacted under `horizon_ms`, the upload records opened,
    /// the partials reconciled with them both ways, the records compacted,
    /// the root fsynced. Everything here completes before the store answers
    /// anything.
    pub fn open(root: &Path, now_ms: u64, horizon_ms: u64) -> io::Result<Store> {
        fs::create_dir_all(root)?;
        let leases = LeaseLog::open(root, now_ms, horizon_ms)?;
        let mut uploads = UploadRecords::open(root)?;
        partials::reconcile(root, &mut uploads, now_ms)?;
        uploads.compact()?;
        fsync_dir(root)?;
        Ok(Store {
            root: root.to_path_buf(),
            uploads: Mutex::new(uploads),
            leases: Mutex::new(leases),
            live: Mutex::new(HashMap::new()),
            fresh_dirs: Mutex::new(HashSet::new()),
            #[cfg(feature = "test-hooks")]
            hooks: Mutex::new(blobs::Hooks::default()),
        })
    }

    /// The root the store was opened at.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path a blob of `designation` and `hex` would have.
    pub fn blob_path(&self, designation: &str, hex: &str) -> PathBuf {
        blob_path(&self.root, designation, hex)
    }

    /// The length of the file at `<designation>/<hex>`, or `None` where no
    /// file stands there — THE SIZE CHECK's read, which the daemon makes
    /// only where the asking key's record names the hash under a live
    /// lease. Refuses a malformed designation or hex as absent.
    pub fn blob_len(&self, designation: &str, hex: &str) -> Option<u64> {
        if !designation_ok(designation) || !hex_ok(hex) {
            return None;
        }
        fs::metadata(self.blob_path(designation, hex)).ok().filter(|m| m.is_file()).map(|m| m.len())
    }

    /// The volume's free space at the root, in bytes — the floor's read.
    pub fn free_space(&self) -> io::Result<u64> {
        blobs::free_space(&self.root)
    }

    // ── the upload records ───────────────────────────────────────────────

    /// THE CREATION (clause (1)): mint the identifier — 128 bits from the
    /// OS — create the empty partial in the designation directory, and
    /// append the record with its declared `length`, offset 0 and
    /// `expires_ms`, synced. Answers the record.
    pub fn create_upload(
        &self,
        key: &str,
        designation: &str,
        length: u64,
        expires_ms: u64,
        repair: Option<String>,
    ) -> io::Result<UploadRecord> {
        if !designation_ok(designation) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "designation"));
        }
        let id = UploadId::mint()?;
        let fresh = partials::create(&self.root, designation, &id)?;
        if fresh {
            self.fresh_dirs.lock().insert(designation.to_string());
        }
        let record = UploadRecord {
            id,
            key: key.to_string(),
            designation: designation.to_string(),
            length,
            offset: 0,
            expires: expires_ms,
            repair,
        };
        self.uploads.lock().put(record.clone(), true)?;
        Ok(record)
    }

    /// THE KEY's OWN RECORD by identifier — `None` for an identifier its
    /// records do not name or whose upload has expired at `now_ms`, one
    /// answer for both (M-I2 (e)).
    pub fn upload(&self, key: &str, id: &UploadId, now_ms: u64) -> Option<UploadRecord> {
        let uploads = self.uploads.lock();
        let r = uploads.get(id)?;
        (r.key == key && r.stands(now_ms)).then(|| r.clone())
    }

    /// THE KEY's standing uploads at `now_ms`, in identifier order.
    pub fn uploads_of(&self, key: &str, now_ms: u64) -> Vec<UploadRecord> {
        let uploads = self.uploads.lock();
        let mut out: Vec<UploadRecord> =
            uploads.all().filter(|r| r.key == key && r.stands(now_ms)).cloned().collect();
        out.sort_by_key(|r| r.id.to_hex());
        out
    }

    /// THE RESUME (clauses (3), (5)): open the key's upload for appends at
    /// `offset`, which must be the record's durable offset — the partial cut
    /// back to it where longer, the hasher rebuilt over it where this
    /// process holds none. Answers the record as it stands.
    pub fn resume(&self, key: &str, id: &UploadId, offset: u64, now_ms: u64) -> Result<UploadRecord, BlobError> {
        let record = self.upload(key, id, now_ms).ok_or(BlobError::NoUpload)?;
        if offset != record.offset {
            return Err(BlobError::Offset { recorded: record.offset });
        }
        let mut live = self.live.lock();
        match live.get_mut(id) {
            Some(l) => l.cut_back_to(offset)?,
            None => {
                let l = partials::open_at(&self.root, &record.designation, id, offset)?;
                live.insert(*id, l);
            }
        }
        Ok(record)
    }

    /// Append `bytes` to a resumed upload — written and hashed, made
    /// durable at every [`SYNC_GRAIN`] (the record's offset and expiry then
    /// written, `expires = now_ms + interval_ms`). Refused where the bytes
    /// would pass the declared length, nothing written. Answers the bytes
    /// written so far (the file's length).
    pub fn append(
        &self,
        key: &str,
        id: &UploadId,
        bytes: &[u8],
        now_ms: u64,
        interval_ms: u64,
    ) -> Result<u64, BlobError> {
        let (length, durable) = {
            let uploads = self.uploads.lock();
            let r = uploads.get(id).filter(|r| r.key == key).ok_or(BlobError::NoUpload)?;
            (r.length, r.offset)
        };
        let mut live = self.live.lock();
        let l = live.get_mut(id).ok_or(BlobError::NotResumed)?;
        if l.written.saturating_add(bytes.len() as u64) > length {
            return Err(BlobError::Length { length, offset: l.written });
        }
        l.write(bytes)?;
        if l.written - durable >= SYNC_GRAIN {
            l.sync()?;
            self.record_offset(key, id, l.written, now_ms, interval_ms)?;
        }
        Ok(l.written)
    }

    /// THE DURABLE POINT at a request's end (clause (3)): the partial
    /// fsynced, the record's offset set to the bytes written and its expiry
    /// re-fixed from this last byte received — and moved by nothing else: a
    /// request that received no byte past the durable point writes no
    /// record and re-fixes nothing. Answers the record.
    pub fn settle(
        &self,
        key: &str,
        id: &UploadId,
        now_ms: u64,
        interval_ms: u64,
    ) -> Result<UploadRecord, BlobError> {
        let record = self.upload(key, id, now_ms).ok_or(BlobError::NoUpload)?;
        let written = {
            let mut live = self.live.lock();
            let l = live.get_mut(id).ok_or(BlobError::NotResumed)?;
            if l.written == record.offset {
                return Ok(record);
            }
            l.sync()?;
            l.written
        };
        self.record_offset(key, id, written, now_ms, interval_ms)?;
        self.upload(key, id, now_ms).ok_or(BlobError::NoUpload)
    }

    /// The record's offset and expiry, written after the partial's sync and
    /// synced themselves.
    fn record_offset(
        &self,
        key: &str,
        id: &UploadId,
        offset: u64,
        now_ms: u64,
        interval_ms: u64,
    ) -> Result<(), BlobError> {
        let mut uploads = self.uploads.lock();
        let r = uploads.get(id).filter(|r| r.key == key).ok_or(BlobError::NoUpload)?;
        let mut next = r.clone();
        next.offset = offset;
        next.expires = now_ms.saturating_add(interval_ms);
        uploads.put(next, true)?;
        Ok(())
    }

    /// The bytes written so far of a resumed upload (the file's length,
    /// durable or not), or the record's offset where the upload is not
    /// resumed here.
    pub fn written(&self, key: &str, id: &UploadId, now_ms: u64) -> Option<u64> {
        if let Some(l) = self.live.lock().get(id) {
            return Some(l.written);
        }
        self.upload(key, id, now_ms).map(|r| r.offset)
    }

    /// THE FINISH (clause (7); M-I5 (a)): the upload's bytes must reach its
    /// length. The partial is fsynced, renamed onto `<designation>/<hex>` —
    /// REPLACE where the name exists — the designation directory fsynced,
    /// the root fsynced where this process created the directory, the
    /// lease for `key` on the hash appended and synced with `lease_expires_ms`,
    /// the record retired. Answers the file's designation, hex and size —
    /// one shape whether or not the file was already here. The caller
    /// holds, from the rename through the lease's sync, whatever lock its
    /// own write path takes (the daemon's credential-lock read arm).
    pub fn finish(
        &self,
        key: &str,
        id: &UploadId,
        now_ms: u64,
        lease_expires_ms: u64,
    ) -> Result<Finished, BlobError> {
        let record = self.upload(key, id, now_ms).ok_or(BlobError::NoUpload)?;
        let mut live = self.live.lock();
        let l = live.get_mut(id).ok_or(BlobError::NotResumed)?;
        if l.written != record.length {
            return Err(BlobError::Incomplete { offset: l.written, length: record.length });
        }
        self.before(Step::TempSync)?;
        l.sync()?;
        let hex = l.hasher.finalize().to_hex().to_string();
        let designation = record.designation.clone();
        let dir = self.root.join(&designation);
        let from = partials::partial_path(&self.root, &designation, id);
        let to = blob_path(&self.root, &designation, &hex);
        self.before(Step::Rename)?;
        fs::rename(&from, &to)?;
        self.before(Step::DirSync)?;
        fsync_dir(&dir)?;
        if self.fresh_dirs.lock().contains(&designation) {
            self.before(Step::RootSync)?;
            fsync_dir(&self.root)?;
            self.fresh_dirs.lock().remove(&designation);
        }
        self.before(Step::LeaseSync)?;
        self.leases.lock().append_synced(Lease {
            key: key.to_string(),
            designation: designation.clone(),
            hex: hex.clone(),
            size: record.length,
            expires: lease_expires_ms,
        })?;
        self.before(Step::RecordRetire)?;
        self.uploads.lock().retire(id)?;
        live.remove(id);
        Ok(Finished { designation, hex, size: record.length })
    }

    /// THE END (clause (6), the termination): the partial removed, the
    /// record retired, nothing kept. `NoUpload` where the key holds none by
    /// that identifier at `now_ms`.
    pub fn end_upload(&self, key: &str, id: &UploadId, now_ms: u64) -> Result<(), BlobError> {
        let record = self.upload(key, id, now_ms).ok_or(BlobError::NoUpload)?;
        self.live.lock().remove(id);
        partials::remove(&self.root, &record.designation, id)?;
        self.uploads.lock().retire(id)?;
        Ok(())
    }

    /// Drop this process's handle on an upload without ending it — a
    /// stream's end that leaves the upload standing; the hasher goes with it
    /// and is rebuilt at the next resume.
    pub fn release(&self, id: &UploadId) {
        self.live.lock().remove(id);
    }

    // ── the leases ───────────────────────────────────────────────────────

    /// THE BINDING's read (Op inventory 2, "THEY READ IN ONE ORDER, THE
    /// PRINCIPAL's OWN RECORD FIRST"): the key's state on
    /// `<designation>/<hex>` at `now_ms` — read off the key's own record
    /// and never off the file.
    pub fn lease(&self, key: &str, designation: &str, hex: &str, now_ms: u64) -> LeaseState {
        self.leases.lock().state(key, designation, hex, now_ms)
    }

    /// The key's LIVE leases at `now_ms` — the deposit read's list.
    pub fn leases_of(&self, key: &str, now_ms: u64) -> Vec<Lease> {
        self.leases.lock().live_of(key, now_ms)
    }

    /// THE KEY's PENDING BYTES at `now_ms` (Op inventory 1, "THE OWN SCOPE
    /// BEING THE BASE PLUS THAT PRINCIPAL's PENDING BYTES"): its live
    /// leases' sizes plus its standing uploads' durable offsets.
    pub fn pending_bytes(&self, key: &str, now_ms: u64) -> u64 {
        let leased = self.leases.lock().pending_of(key, now_ms);
        let partial = self
            .uploads
            .lock()
            .all()
            .filter(|r| r.key == key && r.stands(now_ms))
            .fold(0u64, |acc, r| acc.saturating_add(r.offset));
        leased.saturating_add(partial)
    }

    /// EVERY key's pending bytes at `now_ms` — the venue total's record-
    /// derived figure.
    pub fn pending_total(&self, now_ms: u64) -> u64 {
        let leased = self.leases.lock().pending_total(now_ms);
        let partial = self
            .uploads
            .lock()
            .all()
            .filter(|r| r.stands(now_ms))
            .fold(0u64, |acc, r| acc.saturating_add(r.offset));
        leased.saturating_add(partial)
    }

    // ── the hazard seam ──────────────────────────────────────────────────

    /// The seam's gate before a step of the finish: a hold runs its
    /// closure (which may park the thread for good); an injected failure
    /// answers an I/O error in the step's place.
    #[cfg(feature = "test-hooks")]
    fn before(&self, step: Step) -> io::Result<()> {
        let hooks = self.hooks.lock();
        if let Some((at, f)) = &hooks.hold {
            if *at == step {
                f();
            }
        }
        if hooks.fail_at == Some(step) {
            return Err(io::Error::other(format!("injected failure at {step:?}")));
        }
        Ok(())
    }

    #[cfg(not(feature = "test-hooks"))]
    #[inline]
    fn before(&self, _step: Step) -> io::Result<()> {
        Ok(())
    }

    /// TEST HOOK (`test-hooks`): FAIL the named step of every later finish
    /// with an I/O error, or `None` to fail nothing — the fsync-order test's
    /// seeded injection.
    #[cfg(feature = "test-hooks")]
    pub fn fail_at(&self, step: Option<Step>) {
        self.hooks.lock().fail_at = step;
    }

    /// TEST HOOK (`test-hooks`): HOLD every later finish before the named
    /// step by calling `f` there — the SIGKILL harness parks the thread in
    /// it and kills the process.
    #[cfg(feature = "test-hooks")]
    pub fn hold_at(&self, step: Step, f: Box<dyn Fn() + Send + Sync>) {
        self.hooks.lock().hold = Some((step, f));
    }

    /// Install `bytes` as `<designation>/<hex>` by the blob's own order with
    /// no upload and no lease — the operator's pull, and a test's way to
    /// plant a file (a corrupt one included: the hex is not checked against
    /// the bytes here).
    pub fn install(&self, designation: &str, hex: &str, bytes: &[u8]) -> io::Result<()> {
        if !designation_ok(designation) || !hex_ok(hex) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "designation or hex"));
        }
        blobs::install_whole(&self.blob_path(designation, hex), bytes)?;
        fsync_dir(&self.root)
    }
}
