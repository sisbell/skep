//! THE STORE: the one handle over the four media stores under the root —
//! the files, the partials, the upload records and the lease log — and the
//! ORDER of its acts: an upload's creation, resume and durable point, the
//! PUT's finish and the deferred step after its answer, the pruner's acts
//! one at a time, the leases' reads. [`Step`] names the steps of a finish
//! the hazard seam can hold or fail; [`Finished`] is a finish's answer.
//! Under `test-hooks`, the child `store/hooks.rs` holds the test seam.
//!
//! THE ORDER (`media.md` Op inventory 1, "THE PUT's DISPOSITION ON A HASH
//! ALREADY PRESENT IS REPLACE, NOT NO-OP"; the register M-I5 (a)): a rename
//! is atomic in the namespace and is lost with its directory entry at a
//! power loss, so a file is durable only at its directory's fsync, and a
//! new directory's entry only at ITS parent's — which is why the finish
//! syncs the designation directory after the rename and the root after the
//! first finish into a designation directory this process created. The
//! partial lives in its target's own designation directory, so the rename
//! never crosses a filesystem. REPLACE is `rename(2)`'s own disposition
//! over an existing name: the file holding the wrong bytes under the right
//! name is the one case a repair exists for, and a no-op would defeat it.
//!
//! THE REPLACED INSTANCE IS RETIRED AFTER THE ANSWER (`media.md` Op
//! inventory 1, "NO ANSWER OF THE UPLOAD SAYS WHETHER THE FILE WAS ALREADY
//! HERE" — the TIME an answer takes is part of what it says). A rename over
//! a name whose inode holds its last link frees that inode's blocks inside
//! the rename, which at the per-file cap costs the replace arm hundreds of
//! milliseconds a create never pays. So where the name exists the finish
//! first gives the old inode a SECOND NAME — a hard link at an ASIDE name no
//! hex spells, `.retired-<hex>-<n>` in the same directory — then renames the
//! partial onto the hash: the old inode keeps a link, the rename frees
//! nothing, and the aside is unlinked AFTER the answer has been written
//! ([`Store::retire_asides`]), where the freeing's cost lands off the
//! request's path. A link rather than a rename aside, so the hash is never
//! without a file: a failure at the rename leaves the old bytes at the hash
//! and the aside beside them, never an absent name. Nothing names an aside,
//! so a crash between the answer and the unlink costs nothing: open removes
//! every aside it finds, and the pruner's pass one the deferred step did
//! not.

// The test seam — `test-hooks` builds only: the hazard seam's state and its
// gate before each step, and the three methods only a test calls.
#[cfg(feature = "test-hooks")]
mod hooks;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::blobs::{self, aside_name, blob_path, designation_ok, fsync_dir, hex_ok, is_aside_name};
use crate::error::BlobError;
use crate::lease::{Lease, LeaseLog, LeaseState};
use crate::partials::{self, Live, SYNC_GRAIN};
use crate::uploads::{UploadId, UploadRecord, UploadRecords};

/// The steps of a finish, in order — the points the hazard seam names
/// (`test-hooks`): a hold or an injected failure is placed BEFORE the step
/// it names, after every step before it has completed. Two are the
/// REPLACE's own and are met only where the name already exists:
/// [`Step::LinkAside`] inside the finish, [`Step::UnlinkAside`] in the
/// deferred step after the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// The partial's final fsync.
    TempSync,
    /// The hard link of the old file at `<designation>/<hex>` to its aside
    /// name — taken only where the name exists.
    LinkAside,
    /// The rename of the partial onto `<designation>/<hex>`.
    Rename,
    /// The designation directory's fsync — the rename's durability.
    DirSync,
    /// The root's fsync — a new designation directory's durability. Taken
    /// only where this process created the directory; a hold or a failure
    /// named here is met only on such a finish.
    RootSync,
    /// The lease's append and sync.
    LeaseSync,
    /// The upload record's retirement — the last act before the answer.
    RecordRetire,
    /// The unlink of a replaced file's aside name — the deferred step, run
    /// after the answer ([`Store::retire_asides`]) and never inside a
    /// finish; met only on a finish that replaced a present name.
    UnlinkAside,
}

/// A finished upload's answer: the file's designation, its hash as
/// lowercase hex, and its length. One shape whether or not the file was
/// already here (the record's "NO ANSWER OF THE UPLOAD SAYS WHETHER THE
/// FILE WAS ALREADY HERE").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finished {
    pub designation: String,
    pub hex: String,
    pub size: u64,
}

/// The store: one root, the four stores under it, and the uploads open in
/// this process. Every method takes `&self`; the caller serializes the
/// acts of ONE upload (the daemon's hold on an upload's identifier while
/// a stream owns it), and the store's own locks keep its records whole
/// across uploads.
///
/// THE STORE CHECKS EVERY NAME IT IS HANDED. A designation or a hex a
/// caller passes in becomes a path only past its spelling's check
/// (`blobs.rs`), made here at the door: a malformed one is answered as
/// absent by every read and act — [`Store::blob_path`], [`Store::blob_len`],
/// [`Store::blobs_of`], [`Store::asides_of`], [`Store::unlink_blob`],
/// [`Store::remove_aside`] — and refused as `InvalidInput` by
/// [`Store::create_upload`]. Inside the crate a name that has passed the
/// door, or that the store spelled itself (a finish's hash), is trusted.
pub struct Store {
    root: PathBuf,
    uploads: Mutex<UploadRecords>,
    leases: Mutex<LeaseLog>,
    /// The uploads open in this process (`Live`: a partial's handle and its
    /// hashers). The lock does three jobs: it keeps the map whole; it gives
    /// one call sole use of an open upload; and, held through the whole of
    /// a finish, it runs the finishes one at a time — so two finishes of
    /// one hash never interleave the replace's check, link and rename, which
    /// would let the second rename free the first file's blocks inside its
    /// own answer. A narrower lock here owes the finish a lock of its own.
    live: Mutex<HashMap<UploadId, Live>>,
    /// Designation directories this process created whose entry in the
    /// root is not yet fsynced; the first finish into one syncs the root.
    fresh_dirs: Mutex<HashSet<String>>,
    /// The aside names replaces have left for the deferred unlink
    /// ([`Store::retire_asides`]), in the order their finishes answered.
    asides: Mutex<Vec<PathBuf>>,
    /// The count of asides this process has made — the `<n>` of the aside
    /// name, so two replaces of one hash before the first's unlink take two
    /// names.
    aside_count: AtomicU64,
    #[cfg(feature = "test-hooks")]
    hooks: Mutex<hooks::Hooks>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("root", &self.root).finish_non_exhaustive()
    }
}

impl Store {
    /// Open the store at `root` (created where absent): the lease log
    /// opened and compacted under `horizon_ms`, the upload records opened,
    /// the partials reconciled with them both ways, every aside a crash left
    /// removed, the records compacted, the root fsynced. Everything here
    /// completes before the store answers anything.
    pub fn open(root: &Path, now_ms: u64, horizon_ms: u64) -> io::Result<Store> {
        fs::create_dir_all(root)?;
        let leases = LeaseLog::open(root, now_ms, horizon_ms)?;
        let mut uploads = UploadRecords::open(root)?;
        partials::reconcile(root, &mut uploads, now_ms)?;
        blobs::remove_asides(root)?;
        uploads.compact()?;
        fsync_dir(root)?;
        Ok(Store {
            root: root.to_path_buf(),
            uploads: Mutex::new(uploads),
            leases: Mutex::new(leases),
            live: Mutex::new(HashMap::new()),
            fresh_dirs: Mutex::new(HashSet::new()),
            asides: Mutex::new(Vec::new()),
            aside_count: AtomicU64::new(0),
            #[cfg(feature = "test-hooks")]
            hooks: Mutex::new(hooks::Hooks::default()),
        })
    }

    // ── the directory, as the pruner reads it ────────────────────────────

    /// Every DIRECTORY under the root, by name, in name order — the
    /// designation directories this root holds, whatever their names: the
    /// pruner's pass reads the set against the designations it knows and
    /// halts on one it does not. Files under the root (the two logs, their
    /// compaction twins) are not among them.
    pub fn designations(&self) -> io::Result<Vec<String>> {
        blobs::dirs_under(&self.root)
    }

    /// The files at HEX NAMES in `<designation>/`, in name order — the blobs
    /// the directory holds, a partial or an aside excluded by its name. An
    /// absent directory holds none.
    pub fn blobs_of(&self, designation: &str) -> io::Result<Vec<String>> {
        blobs::names_in(&self.root, designation, |name, ty| hex_ok(name) && ty.is_file())
    }

    /// The ASIDE names in `<designation>/` — the second names replaces left
    /// that the deferred unlink has not reached — in name order.
    pub fn asides_of(&self, designation: &str) -> io::Result<Vec<String>> {
        blobs::names_in(&self.root, designation, |name, _| is_aside_name(name))
    }

    /// UNLINK the file at `<designation>/<hex>` — the pruner's one act per
    /// acquisition, after its re-read of the index and the lease. `Ok(true)`
    /// where a file went, `Ok(false)` where none stood. The directory is not
    /// fsynced: a crash that reverts the unlink leaves a file the next pass
    /// re-judges, which costs nothing.
    pub fn unlink_blob(&self, designation: &str, hex: &str) -> io::Result<bool> {
        let Some(path) = self.blob_path(designation, hex) else {
            return Ok(false);
        };
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Remove one aside by name — the pruner's housekeeping where the
    /// deferred step did not run. `Ok(false)` where none stood, and for a
    /// name no aside has.
    pub fn remove_aside(&self, designation: &str, name: &str) -> io::Result<bool> {
        if !designation_ok(designation) || !is_aside_name(name) {
            return Ok(false);
        }
        match fs::remove_file(self.root.join(designation).join(name)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The path a blob of `designation` and `hex` has, or `None` where
    /// either name is malformed — the door's check (see [`Store`]), which
    /// every act on a file a caller names goes through.
    pub fn blob_path(&self, designation: &str, hex: &str) -> Option<PathBuf> {
        (designation_ok(designation) && hex_ok(hex)).then(|| blob_path(&self.root, designation, hex))
    }

    /// The length of the file at `<designation>/<hex>`, or `None` where no
    /// file stands there — THE SIZE CHECK's read, which the daemon makes
    /// only where the asking key's record names the hash under a live
    /// lease. Refuses a malformed designation or hex as absent.
    pub fn blob_len(&self, designation: &str, hex: &str) -> Option<u64> {
        let path = self.blob_path(designation, hex)?;
        fs::metadata(path).ok().filter(|m| m.is_file()).map(|m| m.len())
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
        self.uploads.lock().standing(key, id, now_ms).cloned()
    }

    /// THE KEY's standing uploads at `now_ms`, in identifier order.
    pub fn uploads_of(&self, key: &str, now_ms: u64) -> Vec<UploadRecord> {
        self.uploads.lock().standing_of(key, now_ms)
    }

    /// THE RESUME (clauses (3), (5)): open the key's upload for appends at
    /// `offset`, which must be the record's durable offset — the partial cut
    /// back to it where longer, the hasher rebuilt over it where this
    /// process holds none, or holds one whose durable point is not that
    /// offset. Answers the record as it stands.
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
            let r = uploads.of_key(key, id).ok_or(BlobError::NoUpload)?;
            (r.length, r.offset)
        };
        let mut live = self.live.lock();
        let l = live.get_mut(id).ok_or(BlobError::NotResumed)?;
        if l.written().saturating_add(bytes.len() as u64) > length {
            return Err(BlobError::Length { length, offset: l.written() });
        }
        l.write(bytes)?;
        if l.written() - durable >= SYNC_GRAIN {
            l.sync()?;
            self.record_offset(key, id, l.written(), now_ms, interval_ms)?;
        }
        Ok(l.written())
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
            if l.written() == record.offset {
                return Ok(record);
            }
            l.sync()?;
            l.written()
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
        let r = uploads.of_key(key, id).ok_or(BlobError::NoUpload)?;
        let mut next = r.clone();
        next.offset = offset;
        next.expires = now_ms.saturating_add(interval_ms);
        uploads.put(next, true)?;
        Ok(())
    }

    /// THE FINISH (clause (7); M-I5 (a)): the upload's bytes must reach its
    /// length. The partial is fsynced; where `<designation>/<hex>` already
    /// holds a file, that file is LINKED ASIDE — a second name,
    /// `.retired-<hex>-<n>`, so the rename below frees no blocks; the
    /// partial is renamed onto `<designation>/<hex>` — REPLACE where the
    /// name exists — the designation directory fsynced, the root fsynced
    /// where this process created the directory, the lease for `key` on the
    /// hash appended and synced with `lease_expires_ms`, the record
    /// retired. Answers the file's designation, hex and size — one shape
    /// whether or not the file was already here, and in one time: the old
    /// instance's unlink waits for [`Store::retire_asides`], after the
    /// answer. The store's own lock on its open uploads is held from the
    /// first act to the answer, so finishes run one at a time and two of one
    /// hash never interleave the replace's check, link and rename. The
    /// caller holds, from the rename through the lease's sync, whatever lock
    /// its own write path takes (the daemon's credential-lock read arm).
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
        if l.written() != record.length {
            return Err(BlobError::Incomplete { offset: l.written(), length: record.length });
        }
        self.before(Step::TempSync)?;
        l.sync()?;
        let hex = l.hash().to_hex().to_string();
        let designation = record.designation.clone();
        let dir = self.root.join(&designation);
        let from = partials::partial_path(&self.root, &designation, id);
        let to = blob_path(&self.root, &designation, &hex);
        if to.is_file() {
            // THE REPLACE: the old inode keeps a name through the rename, so
            // the rename frees nothing; the aside is unlinked after the
            // answer. A link, not a rename aside: the hash is never without
            // a file, whatever fails next.
            self.before(Step::LinkAside)?;
            let n = self.aside_count.fetch_add(1, Ordering::Relaxed);
            let aside = dir.join(aside_name(&hex, n));
            fs::hard_link(&to, &aside)?;
            self.asides.lock().push(aside);
        }
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

    /// THE DEFERRED STEP of every replace this process has answered since
    /// the last call: each aside name unlinked, in order — the old
    /// instance's blocks freed here, after its answer, and never on the
    /// request's path. Answers the count unlinked. A failure leaves the rest
    /// queued for the next call, and open removes any aside a crash leaves.
    pub fn retire_asides(&self) -> io::Result<usize> {
        let queued: Vec<PathBuf> = std::mem::take(&mut *self.asides.lock());
        let mut done = 0;
        let mut rest = queued.into_iter();
        for aside in rest.by_ref() {
            if let Err(e) = self.before(Step::UnlinkAside) {
                let mut queue = self.asides.lock();
                queue.insert(0, aside);
                queue.splice(1..1, rest);
                return Err(e);
            }
            match fs::remove_file(&aside) {
                Ok(()) => done += 1,
                // Already gone — open's reconciliation or the pruner's
                // pass took it: nothing to retire.
                Err(e) if e.kind() == io::ErrorKind::NotFound => done += 1,
                Err(e) => {
                    let mut queue = self.asides.lock();
                    queue.insert(0, aside);
                    queue.splice(1..1, rest);
                    return Err(e);
                }
            }
        }
        Ok(done)
    }

    // ── the expired uploads, as the pruner removes them ──────────────────

    /// THE EXPIRED UPLOADS at `now_ms`: every record past its expiry, in
    /// identifier order — the pruner's read, which reads no reference. The
    /// hold a stream has on one is the daemon's to consult before
    /// [`Store::expire_upload`].
    pub fn expired_uploads(&self, now_ms: u64) -> Vec<UploadRecord> {
        self.uploads.lock().expired(now_ms)
    }

    /// Remove an EXPIRED upload: its handle dropped, its partial removed,
    /// its record retired — the pruner's act, whatever key minted it, after
    /// the daemon has found no stream holding it. A record that stands at
    /// `now_ms` is left as it is (`Ok(false)`), so a clock moved between the
    /// read and the act costs a standing upload nothing.
    pub fn expire_upload(&self, id: &UploadId, now_ms: u64) -> io::Result<bool> {
        let record = {
            let uploads = self.uploads.lock();
            match uploads.of_any_key(id) {
                Some(r) if !r.stands(now_ms) => r.clone(),
                _ => return Ok(false),
            }
        };
        self.live.lock().remove(id);
        partials::remove(&self.root, &record.designation, id)?;
        self.uploads.lock().retire(id)?;
        Ok(true)
    }

    /// Drop this process's handle on an upload without ending it — a
    /// stream's end that leaves the upload standing; the hasher goes with it
    /// and is rebuilt at the next resume. No failed call needs it: an open
    /// upload a failed write, sync or record write left behind repairs
    /// itself at its next resume.
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

    /// Whether ANY key holds a live lease on `<designation>/<hex>` at
    /// `now_ms` — the pruner's read beside the per-key [`Store::lease`]: a
    /// file any key holds live is kept, whoever deposited it.
    pub fn any_live_lease(&self, designation: &str, hex: &str, now_ms: u64) -> bool {
        self.leases.lock().any_live(designation, hex, now_ms)
    }

    /// THE KEY's PENDING BYTES at `now_ms` (Op inventory 1, "THE OWN SCOPE
    /// BEING THE BASE PLUS THAT PRINCIPAL's PENDING BYTES"): its live
    /// leases' sizes plus its standing uploads' durable offsets.
    pub fn pending_bytes(&self, key: &str, now_ms: u64) -> u64 {
        self.pending_bytes_of(key, now_ms, &|_| true)
    }

    /// [`Store::pending_bytes`] over the key's live leases `counted` admits
    /// — the daemon's own scope leaves out a lease on a hash the key's own
    /// cells already name, which its base counts — plus its standing
    /// uploads' durable offsets, counted whole.
    pub fn pending_bytes_of(&self, key: &str, now_ms: u64, counted: &dyn Fn(&Lease) -> bool) -> u64 {
        let leased = self.leases.lock().pending_of(key, now_ms, counted);
        let received = self.uploads.lock().received_of(key, now_ms);
        leased.saturating_add(received)
    }

    /// EVERY key's pending bytes at `now_ms` — the venue total's record-
    /// derived figure.
    pub fn pending_total(&self, now_ms: u64) -> u64 {
        self.pending_total_of(now_ms, &|_| true)
    }

    /// [`Store::pending_total`] over the live leases `counted` admits, the
    /// standing uploads counted whole — the daemon's venue total, which
    /// adds every base to it.
    pub fn pending_total_of(&self, now_ms: u64, counted: &dyn Fn(&Lease) -> bool) -> u64 {
        let leased = self.leases.lock().pending_total(now_ms, counted);
        let received = self.uploads.lock().received_total(now_ms);
        leased.saturating_add(received)
    }

    // ── the hazard seam ──────────────────────────────────────────────────

    /// The seam's gate before a step of the finish — in a build without
    /// `test-hooks`, nothing: no hold and no injected failure. With the
    /// feature, the gate is the test seam's (`store/hooks.rs`).
    #[cfg(not(feature = "test-hooks"))]
    #[inline]
    fn before(&self, _step: Step) -> io::Result<()> {
        Ok(())
    }
}
