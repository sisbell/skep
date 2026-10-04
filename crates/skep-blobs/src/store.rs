//! THE STORE: the four media stores under the root, opened as one — the
//! files, the partials, the upload records and the lease log — and the
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
//! THE REPLACED INSTANCE's ASIDE IS UNLINKED AFTER THE ANSWER (`media.md`
//! Op inventory 1, "NO ANSWER OF THE UPLOAD SAYS WHETHER THE FILE WAS
//! ALREADY HERE" — the TIME an answer takes is part of what it says). A
//! rename over a name whose inode holds its last link frees that inode's
//! blocks inside the rename, which at the per-file cap costs the replace
//! arm hundreds of milliseconds a create never pays. So where the name
//! exists the finish first gives the old inode a SECOND NAME — a hard link
//! at an ASIDE name no hex spells, `.retired-<hex>-<n>` in the same
//! directory — then renames the partial onto the hash: the old inode keeps
//! a link, the rename frees nothing, and the aside is unlinked AFTER the
//! answer has been written ([`Store::unlink_asides`]), where the freeing's
//! cost lands off the request's path. The finish QUEUES its aside for that
//! unlink only as it answers: the queue is drained on whichever thread
//! asks, and an aside drained between the link and the answer would leave
//! the old inode one link for the rename to free, or free it beside the
//! syncs that follow the rename — inside the answer either way. A link
//! rather than a rename aside, so the hash is never without a file: a
//! failure at the rename leaves the old bytes at the hash and the aside
//! beside them, never an absent name. Nothing names an aside, so one the
//! deferred step never takes — a crash between the answer and the unlink,
//! a finish that failed past its link — costs nothing: open removes every
//! aside it finds, and the pruner's pass one the deferred step did not.

// The test seam — `test-hooks` builds only: the hazard seam's state and its
// gate before each step, and the four methods only a test calls.
#[cfg(feature = "test-hooks")]
mod hooks;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

use crate::blobs::{self, aside_name, blob_path, designation_ok, fsync_dir, hex_ok, is_aside_name};
use crate::error::BlobError;
use crate::lease::{Lease, LeaseLog, LeaseState};
use crate::partials::{self, Handle, SYNC_GRAIN};
use crate::uploads::{millis, UploadId, UploadRecord, UploadRecords};

/// The steps of a finish, in order — the points the hazard seam names
/// (`test-hooks`): a hold or an injected failure is placed BEFORE the step
/// it names, after every step before it has completed. Two are the
/// REPLACE's own and are met only where the name already exists:
/// [`Step::LinkAside`] inside the finish, [`Step::UnlinkAside`] in the
/// deferred step after the answer.
///
/// Deliberately not `#[non_exhaustive]`: this crate's step-by-step suites
/// match every step, so a new step is given its crash story there before
/// the build passes, where the `_` arm `#[non_exhaustive]` demands of an
/// outside crate would let it through untried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// The partial's final fsync.
    PartialSync,
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
    /// after the answer ([`Store::unlink_asides`]) and never inside a
    /// finish; met only on a finish that replaced a present name.
    UnlinkAside,
}

/// A finished upload's answer: the file's designation, its hash as
/// lowercase hex, and its size. One shape whether or not the file was
/// already here (the record's "NO ANSWER OF THE UPLOAD SAYS WHETHER THE
/// FILE WAS ALREADY HERE").
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — field
/// reads are unaffected, and a further field is an addition rather than a
/// broken build.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Finished {
    pub designation: String,
    pub hex: String,
    pub size: u64,
}

/// The store: one root, the four stores under it, and the handles requests
/// have open in this process. Every method takes `&self`; the caller
/// serializes the acts of ONE upload (the daemon's hold on an upload's
/// identifier while a stream owns it), and the store's own locks keep its
/// records whole across uploads.
///
/// A HANDLE LIVES FOR ONE REQUEST. [`Store::resume`] opens the partial for
/// the request that resumes it — an open file and the hash of the bytes in
/// it — and the [`Store::settle`], [`Store::finish`] or
/// [`Store::end_upload`] that ends the request closes it, whatever it
/// answers. A request cut short before any of them — its client gone —
/// owes a [`Store::close_handle`]: the store cannot tell a request that
/// stopped from one still streaming, and a handle no request closes holds
/// an open file until the upload's next resume, its end or its expiry.
///
/// THE STORE CHECKS EVERY NAME IT IS HANDED. A designation or a hex a
/// caller passes in becomes a path only past its spelling's check
/// (`blobs.rs`), made here, where a caller's name enters: a malformed one is
/// answered as absent by every read and act — [`Store::blob_path`],
/// [`Store::blob_size`], [`Store::blobs_of`], [`Store::asides_of`],
/// [`Store::unlink_blob`], [`Store::remove_aside`] — and refused as
/// `InvalidInput` by [`Store::create_upload`]. A name read back off a log
/// at open meets the same check where it enters from disk: a record or
/// lease line naming a malformed one reads as a lost line does
/// (`uploads.rs`, `lease.rs`), so a log restored from elsewhere names no
/// path out of the root, and the leases, holding no malformed name, answer
/// one as none ([`Store::lease`], [`Store::any_live_lease`]). Inside the
/// crate a name that has passed this check, or that the store spelled
/// itself (a finish's hash), is trusted.
pub struct Store {
    root: PathBuf,
    uploads: Mutex<UploadRecords>,
    leases: Mutex<LeaseLog>,
    /// THE HANDLES requests have open in this process (`Handle`: the
    /// partial's open file and its hasher), at most one per upload, each
    /// for one request: a resume opens it afresh, and the settle, finish or
    /// end that closes the request takes it out — a
    /// [`Store::close_handle`], for a request cut short — so no file stays
    /// open for an upload no request is streaming, nor past a finish whose
    /// rename made the partial's file the hash's. The lock does three jobs:
    /// it keeps the map whole; it gives one call sole use of a handle; and,
    /// held through the whole of a finish, it runs the finishes one at a
    /// time — so two finishes of one hash never interleave the replace's
    /// check, link and rename, which would let the second rename free the
    /// first file's blocks inside its own answer. A narrower lock here owes
    /// the finish a lock of its own. The store takes `uploads` under this
    /// lock where it takes both, never the other way.
    handles: Mutex<HashMap<UploadId, Handle>>,
    /// Designation directories this process created whose entry in the
    /// root is not yet fsynced; the first finish into one syncs the root.
    fresh_dirs: Mutex<HashSet<String>>,
    /// The aside names answered replaces have left for the deferred unlink
    /// ([`Store::unlink_asides`]), in the order their finishes answered —
    /// each queued as its finish answers, never sooner.
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
    /// Open the store at `root` (created where absent) at `now_ms`: the
    /// lease log opened and compacted under `horizon` — a lease lapsed by
    /// more than it answers as none, and is dropped — the upload records
    /// opened, the partials reconciled with them both ways, every aside a
    /// crash left removed, the records compacted, the root fsynced.
    /// Everything here completes before the store answers anything.
    pub fn open(root: impl AsRef<Path>, horizon: Duration, now_ms: u64) -> io::Result<Store> {
        let root = root.as_ref();
        fs::create_dir_all(root)?;
        let leases = LeaseLog::open(root, now_ms, millis(horizon))?;
        let mut uploads = UploadRecords::open(root)?;
        partials::reconcile(root, &mut uploads, now_ms)?;
        blobs::remove_asides(root)?;
        uploads.compact()?;
        fsync_dir(root)?;
        Ok(Store {
            root: root.to_path_buf(),
            uploads: Mutex::new(uploads),
            leases: Mutex::new(leases),
            handles: Mutex::new(HashMap::new()),
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
    /// re-judges, which costs nothing. Call it holding the lock that keeps
    /// every [`Store::finish`] out (see there), after reading under that
    /// same hold that no live lease holds the file ([`Store::any_live_lease`])
    /// and nothing of the caller's names it.
    pub fn unlink_blob(&self, designation: &str, hex: &str) -> io::Result<bool> {
        self.blob_path(designation, hex).map_or(Ok(false), |path| blobs::remove_if_present(&path))
    }

    /// Remove one aside by name — the pruner's housekeeping where the
    /// deferred step did not run. `Ok(false)` where none stood, and for a
    /// name no aside has. Under the same exclusion from [`Store::finish`]
    /// as [`Store::unlink_blob`]: an aside stands from its finish's link,
    /// before the rename.
    pub fn remove_aside(&self, designation: &str, name: &str) -> io::Result<bool> {
        if !designation_ok(designation) || !is_aside_name(name) {
            return Ok(false);
        }
        blobs::remove_if_present(&self.root.join(designation).join(name))
    }

    /// The path a blob of `designation` and `hex` has, or `None` where
    /// either name is malformed — the name check (see [`Store`]), which
    /// every act on a file a caller names goes through.
    pub fn blob_path(&self, designation: &str, hex: &str) -> Option<PathBuf> {
        (designation_ok(designation) && hex_ok(hex)).then(|| blob_path(&self.root, designation, hex))
    }

    /// The size of the file at `<designation>/<hex>`, or `None` where no
    /// file stands there — THE SIZE CHECK's read, which the daemon makes
    /// only where the asking principal's own record names the hash (M-I2
    /// (e)). Refuses a malformed designation or hex as absent.
    pub fn blob_size(&self, designation: &str, hex: &str) -> Option<u64> {
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
    /// write the record, synced: its `principal`, its declared `length`,
    /// offset 0, and THE UPLOAD's INTERVAL, `interval` — the limits in
    /// force at this creation, held in the record for every expiry the
    /// upload will have (clause (3)), in the whole milliseconds its line
    /// spells — its first expiry that interval past `now_ms`. Answers the
    /// record.
    pub fn create_upload(
        &self,
        principal: &str,
        designation: &str,
        length: u64,
        interval: Duration,
        now_ms: u64,
    ) -> io::Result<UploadRecord> {
        if !designation_ok(designation) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "designation"));
        }
        let id = UploadId::mint()?;
        let fresh = partials::create(&self.root, designation, &id)?;
        if fresh {
            self.fresh_dirs.lock().insert(designation.to_string());
        }
        // Held as its line spells it, so the record open reads back is the
        // record answered here.
        let interval = Duration::from_millis(millis(interval));
        let record = UploadRecord {
            id,
            principal: principal.to_string(),
            designation: designation.to_string(),
            length,
            offset: 0,
            interval,
            expires: expiry(now_ms, interval),
        };
        self.uploads.lock().write(record.clone())?;
        Ok(record)
    }

    /// THE PRINCIPAL's OWN RECORD by identifier — `None` for an identifier
    /// its records do not name or whose upload has expired at `now_ms`, one
    /// answer for both (M-I2 (e)).
    pub fn upload(&self, principal: &str, id: &UploadId, now_ms: u64) -> Option<UploadRecord> {
        self.uploads.lock().standing(principal, id, now_ms).cloned()
    }

    /// THE PRINCIPAL's standing uploads at `now_ms`, in identifier order.
    pub fn uploads_of(&self, principal: &str, now_ms: u64) -> Vec<UploadRecord> {
        self.uploads.lock().standing_of(principal, now_ms)
    }

    /// THE RESUME (clauses (3), (5)): open the principal's upload for this
    /// request at `offset`, which must be the record's durable offset — the
    /// partial opened afresh, cut back to `offset` where it is longer and
    /// its first `offset` bytes hashed (at most its declared length), under
    /// no lock another upload waits on. The handle lives until this
    /// request's settle, finish or end, or its [`Store::close_handle`]; one
    /// an earlier request left open closes first. Answers the record as it
    /// stands.
    pub fn resume(&self, principal: &str, id: &UploadId, offset: u64, now_ms: u64) -> Result<UploadRecord, BlobError> {
        let record = self.upload(principal, id, now_ms).ok_or(BlobError::NoUpload)?;
        if offset != record.offset {
            return Err(BlobError::Offset { recorded: record.offset });
        }
        // An earlier request's handle closes before the partial is cut back,
        // so the partial is never open through two handles.
        self.handles.lock().remove(id);
        let handle = partials::open_at(&self.root, &record.designation, id, offset)?;
        self.handles.lock().insert(*id, handle);
        Ok(record)
    }

    /// Append `bytes` to the upload this request resumed — written and
    /// hashed, made durable at every [`SYNC_GRAIN`] (the record's offset
    /// then written, its expiry re-fixed the upload's own interval past
    /// `now_ms`). Refused where the bytes would pass the declared length,
    /// nothing written, and `NotResumed` where no resume has opened the
    /// upload for this request. Answers the bytes written so far (the
    /// file's length).
    pub fn append(&self, principal: &str, id: &UploadId, bytes: &[u8], now_ms: u64) -> Result<u64, BlobError> {
        let (length, durable) = {
            let uploads = self.uploads.lock();
            let r = uploads.of_principal(principal, id).ok_or(BlobError::NoUpload)?;
            (r.length, r.offset)
        };
        let mut handles = self.handles.lock();
        let handle = handles.get_mut(id).ok_or(BlobError::NotResumed)?;
        if handle.written().saturating_add(bytes.len() as u64) > length {
            return Err(BlobError::Length { length, offset: handle.written() });
        }
        handle.write(bytes)?;
        // Saturating: the record's offset passes the bytes this handle holds
        // only where a settle raced a resume of the upload — a caller not
        // serializing one upload's acts (see `Store`) — and the grain is then
        // measured from none, until the request's settle sets the record to
        // the handle's bytes.
        if handle.written().saturating_sub(durable) >= SYNC_GRAIN {
            handle.sync()?;
            self.record_offset(principal, id, handle.written(), now_ms)?;
        }
        Ok(handle.written())
    }

    /// THE DURABLE POINT at a request's end (clause (3)): the partial
    /// fsynced, the record's offset set to the bytes written and its expiry
    /// re-fixed the upload's own interval past `now_ms`, this last byte
    /// received — and moved by nothing else: a request that received no
    /// byte past the durable point writes no record and re-fixes nothing.
    /// The request's handle closes here whatever the settle answers; with
    /// none open, the request received nothing and the record is answered
    /// as it stands. Answers the record.
    pub fn settle(&self, principal: &str, id: &UploadId, now_ms: u64) -> Result<UploadRecord, BlobError> {
        let handle = self.take_handle(&mut self.handles.lock(), principal, id);
        let record = self.upload(principal, id, now_ms).ok_or(BlobError::NoUpload)?;
        let Some(mut handle) = handle else {
            return Ok(record);
        };
        if handle.written() == record.offset {
            return Ok(record);
        }
        handle.sync()?;
        self.record_offset(principal, id, handle.written(), now_ms)?;
        self.upload(principal, id, now_ms).ok_or(BlobError::NoUpload)
    }

    /// The handle a request has open on `principal`'s upload, taken out of
    /// `handles` — closed when the caller drops it. `None` where no request
    /// has one open, or where `principal`'s records do not name the
    /// identifier: a handle is closed only for the principal whose request
    /// opened it. Called with `handles` held, so `uploads` is taken under
    /// it.
    fn take_handle(
        &self,
        handles: &mut HashMap<UploadId, Handle>,
        principal: &str,
        id: &UploadId,
    ) -> Option<Handle> {
        self.uploads.lock().of_principal(principal, id)?;
        handles.remove(id)
    }

    /// The record's offset, and its expiry the upload's own interval past
    /// `now_ms`, written after the partial's sync and synced themselves.
    fn record_offset(&self, principal: &str, id: &UploadId, offset: u64, now_ms: u64) -> Result<(), BlobError> {
        let mut uploads = self.uploads.lock();
        let mut next = uploads.of_principal(principal, id).ok_or(BlobError::NoUpload)?.clone();
        next.offset = offset;
        next.expires = expiry(now_ms, next.interval);
        uploads.write(next)?;
        Ok(())
    }

    /// THE FINISH (clause (7); M-I5 (a)): the upload's bytes must reach its
    /// length. The partial is fsynced; where `<designation>/<hex>` already
    /// holds a file, that file is LINKED ASIDE — a second name,
    /// `.retired-<hex>-<n>`, so the rename below frees no blocks; the
    /// partial is renamed onto `<designation>/<hex>` — REPLACE where the
    /// name exists — the designation directory fsynced, the root fsynced
    /// where this process created the directory, the lease for `principal`
    /// on the hash appended and synced with an expiry `interval` past
    /// `now_ms`, the record retired, and the aside queued for the deferred
    /// unlink. Answers the file's designation, hex and size — one shape
    /// whether or not the file was already here, and in one time: the old
    /// instance's unlink waits for [`Store::unlink_asides`], after the
    /// answer, and a finish that fails past its link queues nothing,
    /// leaving its aside to the pruner's pass and to open.
    ///
    /// The request's handle leaves at the finish's first act, whatever the
    /// finish answers: past the rename its file is the hash's. With no
    /// handle open — the caller settled first — the partial is opened as
    /// the record's offset left it, read and hashed whole under the lock
    /// every finish holds. That lock, the store's own on its handles, is
    /// held from the first act to the answer, so finishes run one at a time
    /// and two of one hash never interleave the replace's check, link and
    /// rename.
    ///
    /// THE CALLER's ONE EXCLUSION: hold, around the whole call, a lock that
    /// keeps [`Store::unlink_blob`] and [`Store::remove_aside`] out. An
    /// unlink between the rename and the lease's sync leaves a lease naming
    /// bytes that are not there. An unlink between the replace's check and
    /// its link fails the link, an I/O error a create never meets — a second
    /// way of saying the file was here. An aside removed between its link
    /// and the rename lets the rename free the old file inside the answer.
    /// The store sees no lock of its caller's and checks none of this; the
    /// daemon keeps it with its credential lock, the finish under the read
    /// arm and each pruner act under the write arm.
    pub fn finish(
        &self,
        principal: &str,
        id: &UploadId,
        interval: Duration,
        now_ms: u64,
    ) -> Result<Finished, BlobError> {
        // Held to the answer: the finishes run one at a time.
        let mut handles = self.handles.lock();
        let handle = self.take_handle(&mut handles, principal, id);
        let record = self.upload(principal, id, now_ms).ok_or(BlobError::NoUpload)?;
        let mut handle = match handle {
            Some(handle) => handle,
            None => partials::open_at(&self.root, &record.designation, id, record.offset)?,
        };
        if handle.written() != record.length {
            return Err(BlobError::Incomplete { offset: handle.written(), length: record.length });
        }
        self.before(Step::PartialSync)?;
        handle.sync()?;
        let hex = handle.hash().to_hex().to_string();
        let designation = record.designation;
        let dir = self.root.join(&designation);
        let from = partials::partial_path(&self.root, &designation, id);
        let to = blob_path(&self.root, &designation, &hex);
        let aside = if to.is_file() {
            // THE REPLACE: the old inode keeps a name through the rename, so
            // the rename frees nothing; the aside is unlinked after the
            // answer. A link, not a rename aside: the hash is never without
            // a file, whatever fails next.
            self.before(Step::LinkAside)?;
            let n = self.aside_count.fetch_add(1, Ordering::Relaxed);
            let aside = dir.join(aside_name(&hex, n));
            fs::hard_link(&to, &aside)?;
            Some(aside)
        } else {
            None
        };
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
            principal: principal.to_string(),
            designation: designation.clone(),
            hex: hex.clone(),
            size: record.length,
            expires: expiry(now_ms, interval),
        })?;
        self.before(Step::RecordRetire)?;
        self.uploads.lock().retire(id)?;
        // QUEUED ONLY NOW, the finish answering: the queue is drained on
        // whichever thread asks (the daemon's transport, after every blob
        // reply), and a drain that took this aside before the rename would
        // leave the old file one link for the rename to free inside this
        // answer. A finish that fails after its link leaves its aside to the
        // pruner's pass and to open.
        if let Some(aside) = aside {
            self.asides.lock().push(aside);
        }
        Ok(Finished { designation, hex, size: record.length })
    }

    /// THE END (clause (6), the termination): the request's handle closed,
    /// the partial removed, the record retired, nothing kept. `NoUpload`
    /// where the principal holds none by that identifier at `now_ms`.
    pub fn end_upload(&self, principal: &str, id: &UploadId, now_ms: u64) -> Result<(), BlobError> {
        drop(self.take_handle(&mut self.handles.lock(), principal, id));
        let record = self.upload(principal, id, now_ms).ok_or(BlobError::NoUpload)?;
        partials::remove(&self.root, &record.designation, id)?;
        self.uploads.lock().retire(id)?;
        Ok(())
    }

    /// CLOSE THE HANDLE a request opened and leaves without a settle, a
    /// finish or an end — a request cut short. The upload stands at its
    /// record's offset and the next resume reopens the partial; until then
    /// the handle holds one open file.
    pub fn close_handle(&self, id: &UploadId) {
        self.handles.lock().remove(id);
    }

    /// THE DEFERRED STEP of every replace this process has answered since
    /// the last call: each aside name unlinked, in order — the old
    /// instance's blocks freed here, after its answer, and never on the
    /// request's path. Safe on any thread at any time: no aside is queued
    /// before its finish answers. Answers the count unlinked, an aside
    /// already gone counted with them. A failure leaves that aside and the
    /// rest queued for the next call, and open removes any aside a crash
    /// leaves.
    pub fn unlink_asides(&self) -> io::Result<usize> {
        let mut queued = std::mem::take(&mut *self.asides.lock()).into_iter();
        let mut done = 0;
        for aside in queued.by_ref() {
            // Already gone counts as done: the pruner's pass or open took it.
            if let Err(e) = self.before(Step::UnlinkAside).and_then(|()| blobs::remove_if_present(&aside)) {
                // It, and every one after it, back at the queue's head in order.
                self.asides.lock().splice(0..0, std::iter::once(aside).chain(queued));
                return Err(e);
            }
            done += 1;
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

    /// Remove an EXPIRED upload: its handle closed, its partial removed,
    /// its record retired — the pruner's act, whatever principal minted it,
    /// after the daemon has found no stream holding it. A record that
    /// stands at `now_ms` is left as it is (`Ok(false)`), so a clock moved
    /// between the read and the act costs a standing upload nothing.
    pub fn expire_upload(&self, id: &UploadId, now_ms: u64) -> io::Result<bool> {
        let designation = {
            let uploads = self.uploads.lock();
            match uploads.of_any_principal(id) {
                Some(r) if !r.stands(now_ms) => r.designation.clone(),
                _ => return Ok(false),
            }
        };
        self.handles.lock().remove(id);
        partials::remove(&self.root, &designation, id)?;
        self.uploads.lock().retire(id)?;
        Ok(true)
    }

    // ── the leases ───────────────────────────────────────────────────────

    /// THE BINDING's read (Op inventory 2, "THEY READ IN ONE ORDER, THE
    /// PRINCIPAL's OWN RECORD FIRST"): the principal's state on
    /// `<designation>/<hex>` at `now_ms` — read off the principal's own
    /// record and never off the file, so [`LeaseState::Live`] says nothing
    /// of the file (see there).
    pub fn lease(&self, principal: &str, designation: &str, hex: &str, now_ms: u64) -> LeaseState {
        self.leases.lock().state(principal, designation, hex, now_ms)
    }

    /// The principal's LIVE leases at `now_ms`, in hex order — the deposit
    /// read's list. A lease lapsed within the horizon, which
    /// [`Store::lease`] answers as lapsed, is not among them.
    pub fn live_leases_of(&self, principal: &str, now_ms: u64) -> Vec<Lease> {
        self.leases.lock().live_of(principal, now_ms)
    }

    /// Whether ANY principal holds a live lease on `<designation>/<hex>` at
    /// `now_ms` — the pruner's read beside the per-principal
    /// [`Store::lease`]: a file any principal holds live is kept, whoever
    /// deposited it.
    pub fn any_live_lease(&self, designation: &str, hex: &str, now_ms: u64) -> bool {
        self.leases.lock().any_live(designation, hex, now_ms)
    }

    /// THE PRINCIPAL's PENDING BYTES at `now_ms` (M-I6 (b); Op inventory 1,
    /// "THE OWN SCOPE BEING THE BASE PLUS THAT PRINCIPAL's PENDING BYTES"):
    /// the sizes of its UNPLACED DEPOSITS — its live leases on hashes none
    /// of its own cells names — plus its standing uploads' bytes received.
    /// Which deposits are unplaced is a fact of cells, and this store reads
    /// none: `unplaced` answers it for each live lease — the daemon off its
    /// cell index; a caller with no cells, `true`. It runs with the lease
    /// log locked, so it must not call back into this store, where a read
    /// of the leases would wait on that lock for good — a rule no type here
    /// checks.
    pub fn pending_bytes(&self, principal: &str, now_ms: u64, unplaced: impl FnMut(&Lease) -> bool) -> u64 {
        let unplaced_bytes = self.leases.lock().unplaced_of(principal, now_ms, unplaced);
        let received = self.uploads.lock().received_of(principal, now_ms);
        unplaced_bytes.saturating_add(received)
    }

    /// EVERY principal's pending bytes at `now_ms`, summed — the
    /// record-derived part of the venue total, to which the daemon adds
    /// every base (M-I6 (f)); `unplaced` answers, and runs, as it does for
    /// [`Store::pending_bytes`].
    pub fn pending_total(&self, now_ms: u64, unplaced: impl FnMut(&Lease) -> bool) -> u64 {
        let unplaced_bytes = self.leases.lock().unplaced_total(now_ms, unplaced);
        let received = self.uploads.lock().received_total(now_ms);
        unplaced_bytes.saturating_add(received)
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

/// THE ONE EXPIRY RULE, for both expiries the store fixes: `interval`
/// past `now_ms`, saturating. An upload's is fixed at its creation from the
/// interval handed in then, which its record keeps, and at each byte
/// received from that kept interval (clause (3)); a lease's at its PUT,
/// from the interval handed to the finish (`media.md` Op inventory 1, "THE
/// LEASE'S STORE, SCOPE AND EXPIRY, STATED"). No caller computes an expiry
/// the store then trusts. An instant is unix milliseconds, the `u64` the
/// logs and the wire spell; a span is a [`Duration`] — so the clock reading
/// and an interval never trade places at a call and compile.
fn expiry(now_ms: u64, interval: Duration) -> u64 {
    now_ms.saturating_add(millis(interval))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AN APPEND MEASURES ITS GRAIN IN RANGE WHATEVER THE RECORD SAYS: a
    /// settle that raced a resume of the same upload — its handle taken out,
    /// the resume reopening the partial at the record's offset behind it,
    /// then the settle's own offset written past the new handle's bytes —
    /// leaves the record ahead of the handle, the state a caller that does
    /// not serialize one upload's acts (`Store`) can reach. Played here
    /// through the settle's own two halves, step by step: the append over it
    /// answers, neither panicking nor wrapping, and the request's settle sets
    /// the record to the bytes its handle holds.
    #[test]
    fn an_append_after_a_settle_raced_its_resume_answers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(dir.path(), Duration::from_secs(1), 0).expect("the store opens");
        let rec = store.create_upload("k", "blake3", 10, Duration::from_secs(60), 0).expect("create");
        store.resume("k", &rec.id, 0, 1).expect("the first request's resume");
        store.append("k", &rec.id, b"abcd", 1).expect("the first request's bytes");
        // The first request's settle, its first half: its handle taken out.
        let mut first = store.take_handle(&mut store.handles.lock(), "k", &rec.id).expect("its handle");
        // The second request's resume, at the record's offset as it stands.
        store.resume("k", &rec.id, 0, 2).expect("the second request's resume");
        // The settle's second half: its handle's bytes written as the offset.
        first.sync().expect("the first handle's sync");
        store.record_offset("k", &rec.id, first.written(), 3).expect("the first handle's offset");
        drop(first);
        assert_eq!(store.upload("k", &rec.id, 3).map(|r| r.offset), Some(4), "the record ahead of the handle");
        assert_eq!(store.append("k", &rec.id, b"x", 4).expect("the append answers"), 1);
        assert_eq!(
            store.upload("k", &rec.id, 4).map(|r| r.offset),
            Some(4),
            "the grain measured from none: no sync and no record written, where a wrapped measure takes both"
        );
        let settled = store.settle("k", &rec.id, 5).expect("the settle answers");
        assert_eq!(settled.offset, 1, "the record set to the bytes the handle holds");
        assert_eq!(fs::read(partials::partial_path(dir.path(), "blake3", &rec.id)).unwrap(), b"x");
    }
}
