//! THE STORE: the four media stores under the root, opened as one — the
//! files, the partials, the upload records and the lease log — and
//! [`Stream`], one upload open for one request; and the ORDER of their acts:
//! an upload's creation and resume, a stream's settle and the PUT's finish,
//! the deferred unlink after its answer, the pruner's acts one at a time,
//! the leases' reads. [`Step`] names the steps of a finish the hazard seam
//! can hold or fail; [`Finished`] is a finish's answer. Under `test-hooks`,
//! the child `store/hooks.rs` holds the test seam.
//!
//! THE ORDER (`media.md` Op inventory 1, "THE PUT's DISPOSITION ON A HASH
//! ALREADY PRESENT IS REPLACE, NOT NO-OP"; the register M-I5 (a)): a rename
//! is atomic in the namespace and is lost with its directory entry at a
//! power loss, so a file is durable only at its directory's fsync, and a
//! new directory's entry only at ITS parent's — which is why the finish
//! syncs the designation directory after the rename, and the root at the
//! first finish into a designation directory no root fsync since the open
//! has made durable, whatever made it. The partial lives in its target's
//! own designation directory, so the rename never crosses a filesystem.
//! REPLACE is `rename(2)`'s own disposition over an existing name: the file
//! holding the wrong bytes under the right name is the one case a repair
//! exists for, and a no-op would defeat it.
//!
//! THE REPLACED INSTANCE's ASIDE IS UNLINKED AFTER THE ANSWER (`media.md`
//! Op inventory 1, "NO ANSWER OF THE UPLOAD SAYS WHETHER THE FILE WAS
//! ALREADY HERE" — the TIME an answer takes is part of what it says). A
//! rename over a name whose inode holds its last link frees that inode's
//! blocks inside the rename, which at the per-file cap costs the replace
//! arm hundreds of milliseconds a create never pays. So where the name
//! exists the finish first gives the replaced instance a SECOND NAME — a
//! hard link at an ASIDE name no hex spells, `.retired-<hex>-<n>` in the
//! same directory — then renames the partial onto the hash: the replaced
//! instance keeps a link, the rename frees nothing, and the aside is
//! unlinked AFTER the answer has been written — THE DEFERRED UNLINK
//! ([`Store::unlink_asides`]) — where the freeing's cost lands off the
//! request's path. The finish QUEUES its aside for that unlink only as it
//! answers: the queue is drained on whichever thread asks, and an aside
//! unlinked between the link and the answer would leave the replaced
//! instance one link for the rename to free, or free it beside the syncs
//! that follow the rename — inside the answer either way. A link rather
//! than a rename aside, so the hash is never without a file: a failure at
//! the rename leaves the old bytes at the hash and the aside beside them,
//! never an absent name. Nothing names an aside, so one the deferred
//! unlink never takes — a crash between the answer and the unlink, a
//! finish that failed past its link — costs nothing: open removes every
//! aside it finds, and the pruner's pass one the deferred unlink did not.
//!
//! THE PRUNER's RENAME ASIDE takes the same name for the same reason
//! ([`Store::rename_aside`]; `media.md` Op inventory 2, "ONE FILE PER
//! ACQUISITION — re-read, rename aside, release, the aside unlinked after
//! under no arm"): an unlink frees the file's blocks inside the call, so a
//! pass holding the board's exclusive arm across one held every write for
//! the unlink's time; renamed aside under the arm and unlinked after it, the
//! arm is held one re-read and one rename, and a crash between the two
//! leaves an aside open removes.
//!
//! THE INSPECTION ([`Store::inspect`]) and THE PULL's INSTALL
//! ([`Store::install_file`]) are the operator's two doors, and neither opens
//! the store as the daemon does: the inspection reads the four stores as
//! they stand and writes nothing; the install writes one file by the PUT's
//! order and nothing else.

// The test seam — `test-hooks` builds only: the hazard seam's state and its
// hook before each step, and the methods only a test calls.
#[cfg(feature = "test-hooks")]
mod hooks;

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use parking_lot::Mutex;

use crate::blobs::{self, aside_name, designation_ok, fsync_dir, hex_ok, is_aside_name};
use crate::error::BlobError;
use crate::lease::{Lease, LeaseLog, LeaseState};
use crate::partials::{self, Handle, HashFunction, SYNC_GRAIN};
use crate::uploads::{expiry, UploadId, UploadRecord, UploadRecords};

/// The steps of a finish, in order — the points the hazard seam names
/// (`test-hooks`): a hold or an injected failure is placed BEFORE the step
/// it names, after every step before it has completed. Two are the
/// REPLACE's own and are met only where the name already exists:
/// [`Step::LinkAside`] inside the finish, [`Step::UnlinkAside`] in the
/// deferred unlink after the answer.
///
/// Deliberately not `#[non_exhaustive]`: this crate's step-by-step suites
/// match every step, so a new step is given its crash story there before
/// the build passes, where the `_` arm `#[non_exhaustive]` demands of an
/// outside crate would let it through untried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// The partial's final fsync.
    PartialSync,
    /// The hard link of the replaced instance, the file at
    /// `<designation>/<hex>`, to its aside name — taken only where the name
    /// exists.
    LinkAside,
    /// The rename of the partial onto `<designation>/<hex>`.
    Rename,
    /// The designation directory's fsync — the rename's durability.
    DirSync,
    /// The root's fsync — a new designation directory's durability. Taken
    /// only where no root fsync since the store opened has made the
    /// directory's entry durable — a directory made after the open, whatever
    /// made it; a hold or a failure named here is met only on such a finish.
    RootSync,
    /// The lease's append and sync.
    LeaseSync,
    /// The upload record's retirement — the last act before the answer.
    RecordRetire,
    /// The unlink of the replaced instance's aside name — run after the
    /// answer by the deferred unlink ([`Store::unlink_asides`]) and never
    /// inside a finish; met only on a finish that replaced a present name.
    UnlinkAside,
}

/// A finished upload's answer: the file's designation, its hash — BLAKE3's,
/// the function its designation names — as lowercase hex, and its size. One
/// shape whether or not the file was already here (`media.md` Op inventory
/// 1, "NO ANSWER OF THE UPLOAD SAYS WHETHER THE FILE WAS ALREADY HERE").
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

/// The store: one root and the four stores under it. Every method takes
/// `&self`, and the store's own locks keep its records whole across uploads.
///
/// A STREAM IS ONE REQUEST's. [`Store::resume`] answers a [`Stream`] — the
/// partial opened afresh at the record's offset, with the hash of its bytes
/// — and the request that resumed owns it: it appends through it and ends
/// it by [`Stream::settle`] or [`Stream::finish`], each of which consumes
/// it, or, cut short, drops it. The partial's file closes with the stream,
/// so the store holds no file for a request that has ended, and no request
/// reaches another's.
///
/// ONE STREAM OF AN UPLOAD AT A TIME, ITS ACTS SERIALIZED — the caller's to
/// keep, as the daemon keeps it with its hold on an upload's identifier
/// while a stream owns it (`media.md` Op inventory 1, the resumable upload
/// (5), "A STREAM CLAIMS ITS UPLOAD FIRST"). The store checks neither: a
/// second stream's resume cuts the partial back under the first's handle,
/// after which either stream's bytes may land where the other's hasher does
/// not look, and a finish names the file by a hash its bytes do not have.
/// An end ([`Store::end_upload`]), or the pruner's removal of an expired
/// upload ([`Store::expire_upload`]), between a stream's acts costs that
/// stream its upload alone: its later acts answer `NoUpload`. The expiry
/// passing with the upload not yet removed costs it less: its settle and its
/// finish judge the upload standing and answer `NoUpload`, while its
/// appends, judged by the record held, go on — a grain re-fixing the expiry
/// (see [`Stream::append`]).
///
/// THE STORE CHECKS EVERY NAME IT IS HANDED. A designation or a hex a
/// caller passes in becomes a path only past its spelling's check
/// (`blobs.rs`), made here, where a caller's name enters: a malformed one is
/// answered as absent by every read and act — [`Store::blob_path`],
/// [`Store::blob_size`], [`Store::blobs_of`], [`Store::asides_of`],
/// [`Store::unlink_blob`], [`Store::remove_aside`] — while
/// [`Store::create_upload`] is handed no name at all: it takes a
/// [`HashFunction`], whose designation is the crate's own spelling, held to
/// that check by `partials/handle.rs`'s unit suite. A name read back off a log
/// at open meets the same check where it enters from disk: a record or
/// lease line naming a malformed one reads as a lost line does
/// (`uploads.rs`, `lease.rs`), so a log restored from elsewhere names no
/// path out of the root, and the leases, holding no malformed name, answer
/// one as none ([`Store::lease_state`], [`Store::any_live_lease`]). Inside
/// the crate a name that has passed this check, or that the store spelled
/// itself (a finish's hash), is trusted.
///
/// A LOG THAT STOPS STAYS STOPPED UNTIL A COMPACTION COMPLETES. Each log
/// cuts a failed append back off its file; where that cut fails too, the
/// log takes no further append until a compaction completes (`jsonl.rs`).
/// The store compacts at its open, over the logs it has just read, and at
/// its caller's runtime compaction ([`Store::compact_logs_if_past`] — the
/// pruner's pass, which rewrites a stopped log whatever its count); between
/// the two every act that writes a stopped log answers `Io`: on the records'
/// log a creation, a byte received and a retirement — an end's, an expiry's,
/// a finish's last step; on the leases' every finish, at its lease's sync,
/// past its rename (what that leaves: [`Stream::finish`]). The next open
/// reads the log afresh, its tail check cutting the torn line the failed cut
/// left ([`Store::open`]).
pub struct Store {
    root: PathBuf,
    uploads: Mutex<UploadRecords>,
    leases: Mutex<LeaseLog>,
    /// THE FINISH LOCK, which runs the finishes one at a time: every
    /// [`Stream::finish`] holds this from its first act to its answer, so two
    /// finishes of one hash never interleave the replace's check, link and
    /// rename — which would let the second rename free the first file's
    /// blocks inside its own answer. It holds the finishes' own state
    /// ([`FinishState`]), so nothing reads or moves that unheld. No other
    /// shipped act takes it, so no append waits on another upload's finish;
    /// the store's other locks are taken under it, briefly, and it under none.
    finishing: Mutex<FinishState>,
    /// THE ASIDE QUEUE: the aside names answered replaces have left for the
    /// deferred unlink ([`Store::unlink_asides`]), in the order their
    /// finishes answered — each queued as its finish answers, never sooner.
    /// An aside a failed finish left on disk is never among them: the
    /// pruner's pass and open take that one. Beside the finish lock and not
    /// in it: the deferred unlink takes the queue on any thread and never
    /// waits on a finish.
    aside_queue: Mutex<Vec<PathBuf>>,
    #[cfg(feature = "test-hooks")]
    hooks: Mutex<hooks::Hooks>,
}

/// The finishes' own state, held inside the lock that runs them one at a
/// time (`Store`'s `finishing`) — read and moved by a finish alone in a
/// shipped build, and by the test seam's `install` under the same lock: a
/// finish's check and its update of either are one critical section by
/// construction.
struct FinishState {
    /// THE ROOT's FSYNC PAID: the designation directories whose entry in the
    /// root an fsync has made durable — every directory under the root when
    /// the open's own root fsync ran, and each one a finish's root fsync
    /// ([`Step::RootSync`]) has paid since, entered only once that fsync has
    /// succeeded, so a failed one leaves it owed to the next finish. Every
    /// other designation directory owes the root an fsync before a lease
    /// names a file in it, whatever made it: a creation that failed past its
    /// directory's mkdir leaves the directory standing and its entry owed,
    /// exactly as one that succeeded does.
    root_synced: HashSet<String>,
    /// THE ASIDE SERIAL: the `<n>` of the next aside name this process
    /// makes. It only rises, so two replaces of one hash before the first's
    /// unlink take two names — a plain count, the lock it lives in being
    /// what keeps each one a finish's own.
    aside_serial: u64,
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
    /// opened, the partials reconciled with them both ways, every aside
    /// removed — a crash's or a failed finish's, nothing naming either — the
    /// records compacted, the root fsynced. Everything here completes before
    /// the store answers anything. An open that fails partway serves nothing
    /// and leaves on disk what its acts completed, each one the next open
    /// makes again: the open is the store's one place of repair — its
    /// compactions are the store's only ones, and a log a failure stopped
    /// while an earlier store served is read here afresh, its torn tail cut
    /// (see [`Store`]). A partial that cannot be read fails the open,
    /// retiring nothing (`partials.rs`): an I/O failure is no absence. And
    /// before any of it, every name the store acts on is held to what the
    /// store makes: a symbolic link, a special file, or a second link to a
    /// file the store writes in place fails the open as `InvalidData`,
    /// naming it, and nothing is followed or written through it (`blobs.rs`,
    /// `refuse_links_and_special_files`).
    ///
    /// PRECONDITION: no other `Store` is open over `root` while this one
    /// lives, in this process or another. Its open would act on the root
    /// this store serves: cut a live request's partial back under its
    /// handle, so that the bytes the handle's hasher covers past the cut are
    /// zeros on disk and the finish names the file by a hash its bytes do not
    /// have; remove the partials created since its read as orphans; remove
    /// the asides of finishes between their link and their rename, so those
    /// renames free the replaced instances inside their answers; and rename a
    /// compacted log over each file this store appends to, so every lease
    /// and offset it answers as durable afterwards lands in a file no open
    /// reads. The store takes no lock for it and checks nothing: the daemon
    /// opens this store only after its kernel has taken the exclusive lock on
    /// the data directory (`Daemon::open`'s precondition), so a second daemon
    /// over the same directory fails there, before it reaches `blobs/`.
    pub fn open(root: impl AsRef<Path>, horizon: Duration, now_ms: u64) -> io::Result<Store> {
        let root = root.as_ref();
        // `blobs/` is born `0700` on unix — every directory the store makes
        // is, and every file `0600` — the mode set at creation so the
        // process umask cannot loosen it: the deposited bytes are the
        // depositors' own. A root that already stands is left as found.
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(root)?;
        blobs::refuse_links_and_special_files(root)?;
        let leases = LeaseLog::open(root, horizon, now_ms)?;
        let mut uploads = UploadRecords::open(root)?;
        partials::reconcile(root, &mut uploads, now_ms)?;
        blobs::sweep_asides(root)?;
        uploads.compact()?;
        // Listed before the root's fsync, so every directory in the set is
        // one that fsync makes durable.
        let root_synced = blobs::dirs_under(root)?.into_iter().collect();
        fsync_dir(root)?;
        Ok(Store {
            root: root.to_path_buf(),
            uploads: Mutex::new(uploads),
            leases: Mutex::new(leases),
            finishing: Mutex::new(FinishState { root_synced, aside_serial: 0 }),
            aside_queue: Mutex::new(Vec::new()),
            #[cfg(feature = "test-hooks")]
            hooks: Mutex::new(hooks::Hooks::default()),
        })
    }

    // ── the directory, as the pruner reads it ────────────────────────────

    /// Every DESIGNATION DIRECTORY under the root — every directory there,
    /// whatever its name, by name, in name order: the pruner's pass reads the
    /// set against the designations its build pins and halts on a foreign one
    /// (`media.md` §The media stores, "the halts on a foreign designation
    /// directory"). Files under the root (the two logs, their compaction
    /// twins) are not among them.
    pub fn designation_dirs(&self) -> io::Result<Vec<String>> {
        blobs::dirs_under(&self.root)
    }

    /// The files at HEX NAMES in `<designation>/`, in name order — the blobs
    /// the directory holds, a partial or an aside excluded by its name. An
    /// absent directory holds none.
    pub fn blobs_of(&self, designation: &str) -> io::Result<Vec<String>> {
        blobs::names_in(&self.root, designation, |name, kind| hex_ok(name) && kind.is_file())
    }

    /// The ASIDE names in `<designation>/` — the second names replaces left
    /// that the deferred unlink has not reached — in name order.
    pub fn asides_of(&self, designation: &str) -> io::Result<Vec<String>> {
        blobs::names_in(&self.root, designation, |name, _| is_aside_name(name))
    }

    /// UNLINK the file at `<designation>/<hex>` in one act — the direct
    /// form, which frees the file's blocks inside the call. `Ok(true)` where
    /// a file went, `Ok(false)` where none stood. The directory is not
    /// fsynced: a crash that reverts the unlink leaves a file the next pass
    /// re-judges, which costs nothing. Call it holding the lock that keeps
    /// every [`Stream::finish`] out (see there), after reading under that
    /// same hold that no live lease holds the file ([`Store::any_live_lease`])
    /// and nothing of the caller's names it. The daemon's pass takes a file
    /// in two acts instead — [`Store::rename_aside`] under its arm, the aside
    /// removed after it — so the arm is never held across the freeing.
    pub fn unlink_blob(&self, designation: &str, hex: &str) -> io::Result<bool> {
        self.blob_path(designation, hex).map_or(Ok(false), |path| blobs::remove_if_present(&path))
    }

    /// RENAME ASIDE the file at `<designation>/<hex>` — the pruner's one act
    /// per acquisition after its re-read of the index and the lease, in the
    /// unlink's place (`media.md` Op inventory 2, "re-read, rename aside,
    /// release, the aside unlinked after under no arm"): the file renamed to
    /// an aside name of its own, `.retired-<hex>-<n>`, the REPLACE's own
    /// name and serial, so the arm the caller holds is released after one
    /// rename and never across the unlink that frees the file's blocks —
    /// hundreds of milliseconds at the per-file cap — which
    /// [`Store::remove_aside`] runs AFTER, under no arm. `Ok(Some(name))`
    /// with the aside's name where a file went aside, `Ok(None)` where none
    /// stood. The directory is not fsynced: a crash that reverts the rename
    /// leaves a file the next pass re-judges, one that keeps it leaves an
    /// aside the next open removes, nothing naming either. Call it holding
    /// the lock that keeps every [`Stream::finish`] out, as
    /// [`Store::unlink_blob`] is called: a finish of the same hash after the
    /// release finds no file at the name and installs afresh.
    pub fn rename_aside(&self, designation: &str, hex: &str) -> io::Result<Option<String>> {
        let Some(path) = self.blob_path(designation, hex) else {
            return Ok(None);
        };
        // The serial is the finishes', under their lock, so two names of one
        // hash — a replace's and a pass's — are never one name.
        let name = {
            let mut finishing = self.finishing.lock();
            let n = finishing.aside_serial;
            finishing.aside_serial += 1;
            aside_name(hex, n)
        };
        match fs::rename(&path, path.with_file_name(&name)) {
            Ok(()) => Ok(Some(name)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Remove one aside by name — the pruner's housekeeping where the
    /// deferred unlink did not run. `Ok(false)` where none stood, and for a
    /// name no aside has. Under the same exclusion from [`Stream::finish`]
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
        blobs::blob_path(&self.root, designation, hex)
    }

    /// THE SIZE CHECK's read (M-I5 (c): the deposit record exact of what is
    /// on disk), which the daemon makes only where the asking principal's
    /// own record names the hash (M-I2 (e)): `Ok(Some(size))` where a file
    /// stands at `<designation>/<hex>`; `Ok(None)` where none does — no
    /// entry, an entry that is no file, or a malformed designation or hex,
    /// refused as absent; and `Err` where the name cannot be read. An I/O
    /// failure is no absence: what to answer over it is the caller's.
    pub fn blob_size(&self, designation: &str, hex: &str) -> io::Result<Option<u64>> {
        let Some(path) = self.blob_path(designation, hex) else {
            return Ok(None);
        };
        Ok(blobs::not_found_as_none(fs::metadata(path))?.filter(fs::Metadata::is_file).map(|m| m.len()))
    }

    /// The volume's free space at the root, in bytes — the floor's read.
    pub fn free_space(&self) -> io::Result<u64> {
        blobs::free_space(&self.root)
    }

    /// The volume's CAPACITY at the root, in bytes — the same `statvfs`
    /// read as [`Store::free_space`]'s: what the daemon's default
    /// per-account limit is a share of, read once at its start.
    pub fn capacity(&self) -> io::Result<u64> {
        blobs::capacity(&self.root)
    }

    /// THE RUNTIME COMPACTION (the pruner's pass, after its unlink pass;
    /// `media.md` §The media stores, "the pruner's pass rewrites either store
    /// the same way once its log has passed a size trigger"): each log
    /// rewritten to its current records as open rewrites it, where its whole
    /// lines number at least `min_lines` and more than `trigger` times its
    /// current records — or where it has STOPPED, whatever its count, since
    /// only a completed compaction lifts a stop — under this store's lock on
    /// THAT log's appends alone and no lock of the caller's. An append that
    /// arrives during the rewrite waits on that lock and lands in the new
    /// file once the install order has completed, so the records it answers
    /// durable afterwards are in the file the next open reads. Both logs are
    /// tried; the answer is `(uploads, leases)`, whether each was rewritten,
    /// and a failure the first that failed: one past its rename leaves its
    /// log stopped ([`Store::stopped_logs`]) for the next pass to rewrite.
    pub fn compact_logs_if_past(&self, trigger: usize, min_lines: usize) -> io::Result<(bool, bool)> {
        let uploads = self.uploads.lock().compact_if_past(trigger, min_lines);
        let leases = self.leases.lock().compact_if_past(trigger, min_lines);
        Ok((uploads?, leases?))
    }

    /// Which logs have STOPPED — `(uploads, leases)`: an append's cut-back
    /// or a compaction failed past its rename, and the log takes no append
    /// until a compaction completes; the pass's line names one.
    pub fn stopped_logs(&self) -> (bool, bool) {
        (self.uploads.lock().log_stopped(), self.leases.lock().log_stopped())
    }

    /// THE INSPECTION — the operator's inventory's open (`media.md`
    /// §Recovery, "NEITHER OPENS THE STORE AS skepd DOES — the inventory
    /// reads a copy's stores as they stand"): the four stores under `root`
    /// read as they stand, which reconciles nothing, compacts nothing,
    /// sweeps nothing, fsyncs nothing, creates nothing and holds nothing
    /// open afterwards — the logs read as the open reads them, trust ending
    /// at a torn tail cut IN MEMORY alone, every record and every lease they
    /// hold folded to its latest line, standing or not; the files, partials
    /// and asides listed by name on demand. It takes no lock and needs no
    /// exclusion: it can stand beside a serving daemon's store, each of its
    /// readings one moment's of one file. A `root` that is no directory is
    /// `NotFound`.
    pub fn inspect(root: impl AsRef<Path>) -> io::Result<Inspection> {
        let root = root.as_ref();
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} is no blob store: no such directory", root.display()),
            ));
        }
        let (uploads, upload_lines) = UploadRecords::read_as_found(root)?;
        let (leases, lease_lines) = LeaseLog::read_as_found(root)?;
        Ok(Inspection { root: root.to_path_buf(), uploads, upload_lines, leases, lease_lines })
    }

    /// THE PULL's INSTALL — the operator's restore (`media.md` §Recovery,
    /// "installs the file as the PUT's order installs one, beside a serving
    /// daemon holding none of its gates"): the bytes of `source` streamed
    /// into a temp file in the designation directory of `function` under
    /// `root`, hashed as they are copied, the temp file fsynced, renamed
    /// onto `<designation>/<hex>` — REPLACE where a file stands, which ends
    /// any hole under the name — the directory fsynced, then the root. The
    /// temp file is named as a partial is, `.upload-<a fresh identifier>`
    /// no record names, so a daemon's open that meets it mid-pull removes
    /// it as an orphan and the pull is run again. NO lease, NO record, NO
    /// lock: a restore of bytes a committed cell already names — which is
    /// the caller's to have read — never a deposit. Where `expected` names
    /// a hex and the bytes hash to another, nothing is installed: the temp
    /// file is removed and the mismatch answered as `InvalidData`, naming
    /// both. Answers the file's designation, hex and size.
    ///
    /// Beside a serving daemon: its finishes take the store's own locks and
    /// never this call's, so a finish of the same hash racing this rename is
    /// a REPLACE either way, and the name is never without a file; the
    /// daemon's fetch reads the file under the name at its next request.
    pub fn install_file(
        root: impl AsRef<Path>,
        function: HashFunction,
        source: impl AsRef<Path>,
        expected: Option<&str>,
    ) -> io::Result<Finished> {
        let root = root.as_ref();
        let designation = function.designation();
        let dir = root.join(designation);
        // The designation directory born `0700` and the temp file `0600`
        // on unix, as the finish's are — the mode set at creation, the
        // rename carrying the file's onto its hex name.
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir)?;
        let mut from = fs::File::open(source.as_ref())?;
        let temp = partials::partial_path(root, designation, &UploadId::mint()?);
        let (hex, size) = {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut out = opts.open(&temp)?;
            let mut hasher = blake3::Hasher::new();
            let mut buf = [0u8; 64 * 1024];
            let mut size = 0u64;
            let copied = loop {
                let n = match io::Read::read(&mut from, &mut buf) {
                    Ok(0) => break Ok(()),
                    Ok(n) => n,
                    Err(e) => break Err(e),
                };
                hasher.update(&buf[..n]);
                if let Err(e) = io::Write::write_all(&mut out, &buf[..n]) {
                    break Err(e);
                }
                size += n as u64;
            };
            if let Err(e) = copied.and_then(|()| out.sync_all()) {
                let _ = blobs::remove_if_present(&temp);
                return Err(e);
            }
            (hasher.finalize().to_hex().to_string(), size)
        };
        if let Some(expected) = expected {
            if expected != hex {
                let _ = blobs::remove_if_present(&temp);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the file's bytes hash to {hex}, not the {expected} the cell names: nothing installed"),
                ));
            }
        }
        if let Err(e) = fs::rename(&temp, dir.join(&hex)) {
            let _ = blobs::remove_if_present(&temp);
            return Err(e);
        }
        fsync_dir(&dir)?;
        fsync_dir(root)?;
        Ok(Finished { designation: designation.to_string(), hex, size })
    }

    // ── the upload records ───────────────────────────────────────────────

    /// THE CREATION (clause (1)): mint the identifier — 128 bits from the
    /// OS — create the empty partial in the directory of `function`'s
    /// designation, and write the record, synced: its `principal`, that
    /// designation, its declared `length`, offset 0, and THE UPLOAD's
    /// INTERVAL, `interval` — the limits in force at this creation, held in
    /// the record for every expiry the upload will have (clause (3)), in the
    /// whole milliseconds its line spells — its first expiry that interval
    /// past `now_ms`. Answers the record. The creation names the function
    /// its finish computes, as a type, since a key names the function that
    /// made it (`media.md` §The design, item 4, "EVERY SIDECAR KEY NAMES ITS
    /// FUNCTION"): no creation can name one this store does not compute,
    /// and every error here is the disk's. An `Io` — the OS refusing
    /// entropy, the partial's creation, the record's write — leaves no
    /// upload: at most an empty partial, which the next open removes as an
    /// orphan, and a designation directory made here, whose entry in the
    /// root the next finish into it fsyncs as it would had the creation
    /// succeeded.
    pub fn create_upload(
        &self,
        principal: &str,
        function: HashFunction,
        length: u64,
        interval: Duration,
        now_ms: u64,
    ) -> io::Result<UploadRecord> {
        let designation = function.designation();
        let id = UploadId::mint()?;
        partials::create(&self.root, designation, &id)?;
        self.uploads.lock().create(id, principal, designation, length, interval, now_ms)
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
    /// request at `offset`, the record's durable offset, and answer its
    /// [`Stream`] — the partial opened afresh, cut back to `offset` where it
    /// is longer and its first `offset` bytes hashed (at most its declared
    /// length), under no lock another upload waits on. One stream of an
    /// upload at a time is the caller's to keep (see [`Store`]).
    ///
    /// THE REFUSALS, in the order they are judged: `NoUpload` where the
    /// identifier names no standing upload of `principal`'s — answered
    /// before any figure of the record, so no offset is ever named to
    /// another principal (M-I2 (e)); then `Offset`, carrying the record's
    /// offset, where `offset` is any other. Neither refusal touches the
    /// partial. An `Io` opens no stream: the partial unreadable; gone, a
    /// finish's rename having taken it; or shorter than the record's offset
    /// — no state this store leaves: a disk changed under it, or two streams
    /// of one upload (see [`Store`]) — refused and never extended. An `Io`
    /// past the cut-back has cut only bytes past the durable point, none
    /// received.
    pub fn resume(&self, principal: &str, id: &UploadId, offset: u64, now_ms: u64) -> Result<Stream<'_>, BlobError> {
        let record = self.upload(principal, id, now_ms).ok_or(BlobError::NoUpload)?;
        if offset != record.offset {
            return Err(BlobError::Offset { recorded: record.offset });
        }
        let handle = partials::open_at(&self.root, &record.designation, id, offset)?;
        Ok(Stream {
            store: self,
            principal: record.principal,
            id: record.id,
            designation: record.designation,
            length: record.length,
            offset,
            handle,
        })
    }

    /// THE END (clause (6), the termination): the partial removed, the
    /// record retired, nothing kept. `NoUpload` where the principal holds
    /// none by that identifier at `now_ms`. A stream of the upload still open
    /// receives nothing more: its acts answer `NoUpload`. An `Io` removing
    /// the partial leaves the upload standing at its record's offset; one
    /// writing the retirement leaves it retired in this process, its
    /// record's line on disk until the next open's reconciliation, which
    /// finds no partial and retires it.
    pub fn end_upload(&self, principal: &str, id: &UploadId, now_ms: u64) -> Result<(), BlobError> {
        let designation =
            self.uploads.lock().standing(principal, id, now_ms).ok_or(BlobError::NoUpload)?.designation.clone();
        partials::remove(&self.root, &designation, id)?;
        self.uploads.lock().retire(id)?;
        Ok(())
    }

    /// THE DEFERRED UNLINK of every replace this process has answered since
    /// the last call: each aside name unlinked, in order — the replaced
    /// instance's blocks freed here, after its answer, and never on the
    /// request's path. Safe on any thread at any time: no aside is queued
    /// before its finish answers. Answers the count unlinked, an aside
    /// already gone counted with them. A failure leaves that aside and the
    /// rest queued for the next call, and open removes any aside a crash
    /// leaves.
    pub fn unlink_asides(&self) -> io::Result<usize> {
        let mut queued = std::mem::take(&mut *self.aside_queue.lock()).into_iter();
        let mut done = 0;
        for aside in queued.by_ref() {
            // Already gone counts as done: the pruner's pass or open took it.
            if let Err(e) = self.before(Step::UnlinkAside).and_then(|()| blobs::remove_if_present(&aside)) {
                // It, and every one after it, back at the queue's head in order.
                self.aside_queue.lock().splice(0..0, std::iter::once(aside).chain(queued));
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

    /// Remove an EXPIRED upload: its partial removed, its record retired —
    /// the pruner's act, whatever principal minted it, after the daemon has
    /// found no stream holding it; `Ok(true)` where one went. `Ok(false)`
    /// where no record is held by that identifier — an end, a finish or an
    /// earlier pass took it — or where it stands at `now_ms`, left as it is,
    /// so a clock moved between the read and the act costs a standing upload
    /// nothing. An `Io` removing the partial leaves the record standing,
    /// expired, for the next pass to take again; one writing the retirement
    /// leaves it retired in this process, its record's line on disk until the
    /// next open's reconciliation retires it.
    pub fn expire_upload(&self, id: &UploadId, now_ms: u64) -> io::Result<bool> {
        let designation = {
            let uploads = self.uploads.lock();
            match uploads.of_any_principal(id) {
                Some(r) if !r.stands(now_ms) => r.designation.clone(),
                _ => return Ok(false),
            }
        };
        partials::remove(&self.root, &designation, id)?;
        self.uploads.lock().retire(id)?;
        Ok(true)
    }

    // ── the leases ───────────────────────────────────────────────────────

    /// THE BINDING's read (Op inventory 2, "THEY READ IN ONE ORDER, THE
    /// PRINCIPAL's OWN RECORD FIRST"): the principal's lease state on
    /// `<designation>/<hex>` at `now_ms` — read off the principal's own
    /// record and never off the file, so [`LeaseState::Live`] says nothing
    /// of the file (see there).
    pub fn lease_state(&self, principal: &str, designation: &str, hex: &str, now_ms: u64) -> LeaseState {
        self.leases.lock().state(principal, designation, hex, now_ms)
    }

    /// The principal's LIVE leases at `now_ms`, in designation order and in
    /// hex order within one — the deposit read's list. A lease lapsed within
    /// the horizon, which
    /// [`Store::lease_state`] answers as lapsed, is not among them.
    pub fn live_leases_of(&self, principal: &str, now_ms: u64) -> Vec<Lease> {
        self.leases.lock().live_of(principal, now_ms)
    }

    /// Whether ANY principal holds a live lease on `<designation>/<hex>` at
    /// `now_ms` — the pruner's read beside the per-principal
    /// [`Store::lease_state`]: a file any principal holds live is kept,
    /// whoever deposited it. A range of the lease map, costing that hash's
    /// holders and never every lease, so the pass that reads it once per file
    /// under its caller's exclusive arm is linear in its files.
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
    ///
    /// TWO READS, NOT A SNAPSHOT: the leases are read, then the upload
    /// records. A finish moves an upload's bytes from its record to its
    /// lease in two steps — the lease appended, then the record retired — so
    /// a figure read beside one of the principal's own finishes can count
    /// those bytes twice (the lease read after its append, the record before
    /// its retirement) or not at all (the lease read before its append, the
    /// record after its retirement). Exactness against a concurrent finish is
    /// the caller's to arrange.
    pub fn pending_bytes(&self, principal: &str, now_ms: u64, unplaced: impl FnMut(&Lease) -> bool) -> u64 {
        let unplaced_bytes = self.leases.lock().unplaced_of(principal, now_ms, unplaced);
        let received = self.uploads.lock().received_of(principal, now_ms);
        unplaced_bytes.saturating_add(received)
    }

    /// EVERY principal's pending bytes at `now_ms`, summed — the
    /// record-derived part of the venue total, to which the daemon adds
    /// every base (M-I6 (f)); `unplaced` answers, and runs, as it does for
    /// [`Store::pending_bytes`], and the figure is two reads as that one is,
    /// any principal's concurrent finish counted twice or not at all.
    pub fn pending_total(&self, now_ms: u64, unplaced: impl FnMut(&Lease) -> bool) -> u64 {
        let unplaced_bytes = self.leases.lock().unplaced_total(now_ms, unplaced);
        let received = self.uploads.lock().received_total(now_ms);
        unplaced_bytes.saturating_add(received)
    }

    // ── the hazard seam ──────────────────────────────────────────────────

    /// The seam's hook before a step of the finish — in a build without
    /// `test-hooks`, nothing: no hold and no injected failure. With the
    /// feature, the hook is the test seam's (`store/hooks.rs`).
    #[cfg(not(feature = "test-hooks"))]
    #[inline]
    fn before(&self, _step: Step) -> io::Result<()> {
        Ok(())
    }
}

/// THE FOUR STORES AS THEY STAND — what [`Store::inspect`] answers: the
/// upload records and the leases the logs hold, folded to their latest
/// lines and never reconciled, expired, lapsed or compacted; and the
/// listings of the directory on demand. Every read here is a read and
/// nothing else: no file is created, cut, renamed or synced through it.
#[derive(Debug)]
pub struct Inspection {
    root: PathBuf,
    uploads: Vec<UploadRecord>,
    upload_lines: usize,
    leases: Vec<Lease>,
    lease_lines: usize,
}

impl Inspection {
    /// The root inspected.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Every DESIGNATION DIRECTORY under the root, as [`Store::designation_dirs`]
    /// lists them.
    pub fn designation_dirs(&self) -> io::Result<Vec<String>> {
        blobs::dirs_under(&self.root)
    }

    /// The files at HEX NAMES in `<designation>/`, as [`Store::blobs_of`]
    /// lists them.
    pub fn blobs_of(&self, designation: &str) -> io::Result<Vec<String>> {
        blobs::names_in(&self.root, designation, |name, kind| hex_ok(name) && kind.is_file())
    }

    /// The ASIDE names in `<designation>/`, as [`Store::asides_of`] lists
    /// them.
    pub fn asides_of(&self, designation: &str) -> io::Result<Vec<String>> {
        blobs::names_in(&self.root, designation, |name, _| is_aside_name(name))
    }

    /// The PARTIALS in `<designation>/`, by the identifier each name
    /// spells, in name order — a standing upload's, an expired one's, or an
    /// orphan's that no record names.
    pub fn partials_of(&self, designation: &str) -> io::Result<Vec<UploadId>> {
        let names = blobs::names_in(&self.root, designation, |name, kind| {
            kind.is_file() && partials::id_of_partial_name(name).is_some()
        })?;
        Ok(names.iter().filter_map(|name| partials::id_of_partial_name(name)).collect())
    }

    /// EVERY upload record the log holds, folded to its latest line and
    /// never reconciled: standing and expired alike, in identifier order.
    /// Which stand at a moment is the reader's to judge ([`UploadRecord::expires`]).
    pub fn uploads(&self) -> &[UploadRecord] {
        &self.uploads
    }

    /// EVERY lease the log holds, each principal's latest on each hash, no
    /// horizon applied: live and lapsed alike. Which are live at a moment is
    /// the reader's to judge ([`Lease::expires`]).
    pub fn leases(&self) -> &[Lease] {
        &self.leases
    }

    /// The count of lines each log holds on disk — `(uploads, leases)`,
    /// torn tail included — beside the records they fold to.
    pub fn log_lines(&self) -> (usize, usize) {
        (self.upload_lines, self.lease_lines)
    }

    /// The path a blob of `designation` and `hex` has, as [`Store::blob_path`]
    /// answers it.
    pub fn blob_path(&self, designation: &str, hex: &str) -> Option<PathBuf> {
        blobs::blob_path(&self.root, designation, hex)
    }

    /// The size of the file at `<designation>/<hex>`, as [`Store::blob_size`]
    /// answers it: `Ok(None)` where none stands, an I/O failure answered.
    pub fn blob_size(&self, designation: &str, hex: &str) -> io::Result<Option<u64>> {
        let Some(path) = self.blob_path(designation, hex) else {
            return Ok(None);
        };
        Ok(blobs::not_found_as_none(fs::metadata(path))?.filter(fs::Metadata::is_file).map(|m| m.len()))
    }
}

/// AN UPLOAD OPEN FOR ONE REQUEST — "the stream" of the resumable upload's
/// clause (5), "A STREAM CLAIMS ITS UPLOAD FIRST" — what [`Store::resume`]
/// answers: the partial's handle, opened afresh at the record's offset with
/// the hash of its bytes so far, and the figures the request's acts need.
/// The request appends through it and ends it by [`Stream::settle`] or
/// [`Stream::finish`], each consuming it, or, cut short, drops it; the
/// partial's file closes with it whatever the request's end — so no file
/// stays open for an upload no request is streaming, nor past a finish whose
/// rename made the partial's file the hash's. A write or a sync that fails
/// TEARS it: it takes no further write or sync, so a later act that reaches
/// one answers `Io` — an append past its `NoUpload` and `Length` checks, a
/// settle with bytes past its durable point to receive, a finish past its
/// `NoUpload` and its precondition — and the next resume cuts off whatever
/// the failure left. A failed write counts none of its bytes, so a stream
/// torn by one, with nothing counted past its durable point, settles as a
/// stream that wrote nothing: the record answered as it stands.
pub struct Stream<'s> {
    store: &'s Store,
    principal: String,
    id: UploadId,
    designation: String,
    length: u64,
    /// The record's offset as this stream has marked it — its DURABLE POINT:
    /// its resume's, then each grain's and its settle's, moved only to its
    /// own bytes written, so it never passes them, whatever another stream
    /// did.
    offset: u64,
    handle: Handle,
}

impl std::fmt::Debug for Stream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream").field("id", &self.id).field("offset", &self.offset).finish_non_exhaustive()
    }
}

impl Stream<'_> {
    /// Append `bytes` — written and hashed, made durable at every
    /// [`SYNC_GRAIN`] (the record's offset then written, its expiry re-fixed
    /// the upload's own interval past `now_ms`). Answers the bytes written so
    /// far (the partial's length).
    ///
    /// THE REFUSALS, in the order they are judged: `NoUpload` where the
    /// upload's record has been retired under the stream — an end, or the
    /// pruner's removal of the expired upload, between its acts — judged by
    /// whether the record is held, not by its expiry: the resume found the
    /// upload standing (clause (5)), and each grain received re-fixes its
    /// expiry (clause (3)); then `Length` where the bytes would pass the
    /// declared length, nothing written. An `Io` from the write counts none
    /// of `bytes` — whatever part reached the partial, the next resume cuts
    /// off — and tears the stream. One from a grain comes after the write, so
    /// `bytes` count in the stream's bytes written all the same, the figure
    /// its next answer, its settle and its finish read: a grain's failed sync
    /// tears the stream; its failed record write leaves the bytes synced and
    /// not received, the record's offset where it stood for a later grain or
    /// the settle to write.
    pub fn append(&mut self, bytes: &[u8], now_ms: u64) -> Result<u64, BlobError> {
        self.store.uploads.lock().of_principal(&self.principal, &self.id).ok_or(BlobError::NoUpload)?;
        if self.handle.written().saturating_add(bytes.len() as u64) > self.length {
            return Err(BlobError::Length { length: self.length, offset: self.handle.written() });
        }
        self.handle.write(bytes)?;
        // The stream's own offset moves only to its own bytes written, so
        // the grain is measured in range whatever the record says.
        if self.handle.written() - self.offset >= SYNC_GRAIN {
            self.receive(now_ms)?;
        }
        Ok(self.handle.written())
    }

    /// THE SETTLE at the request's end (clause (3)), the stream consumed
    /// whatever it answers: the partial fsynced, the record's offset set to
    /// the bytes written and its expiry re-fixed the upload's own interval
    /// past `now_ms`, this last byte received — and moved by nothing else: a
    /// stream with no byte counted past its durable point writes no record
    /// and re-fixes nothing. Answers the record — the one its receive wrote,
    /// or, where it received nothing, the one it found standing: the upload
    /// is judged standing ONCE, before anything is received, so no answer is
    /// `NoUpload` over bytes this settle has received, whatever expiry their
    /// mark fixed.
    ///
    /// THE REFUSALS, in the order they are judged: `NoUpload` where the
    /// upload no longer stands at `now_ms` — expired, or retired under the
    /// stream; then `Io` where bytes past the durable point cannot be
    /// received — the stream torn, the sync failed, the record write failed.
    /// In each case nothing past the durable point is received, and the
    /// record stands as it was.
    pub fn settle(mut self, now_ms: u64) -> Result<UploadRecord, BlobError> {
        let record = self.store.upload(&self.principal, &self.id, now_ms).ok_or(BlobError::NoUpload)?;
        if self.handle.written() == self.offset {
            return Ok(record);
        }
        self.receive(now_ms)
    }

    /// Make the bytes written received — the partial synced, THEN the
    /// record's offset set to them and its expiry re-fixed (clause (3)): the
    /// one act a grain and the settle share. Answers the record written.
    fn receive(&mut self, now_ms: u64) -> Result<UploadRecord, BlobError> {
        self.handle.sync()?;
        let record =
            self.store.uploads.lock().mark_received(&self.principal, &self.id, self.handle.written(), now_ms)?;
        self.offset = self.handle.written();
        Ok(record)
    }

    /// THE FINISH (clause (7); M-I5 (a)), the stream consumed whatever it
    /// answers. The partial is fsynced; where `<designation>/<hex>` already
    /// holds a file, that file is LINKED ASIDE — a second name,
    /// `.retired-<hex>-<n>`, so the rename below frees no blocks; the partial
    /// is renamed onto `<designation>/<hex>` — REPLACE where the name exists
    /// — the designation directory fsynced, the root fsynced where no root
    /// fsync since the open has made the directory's entry durable, the
    /// lease for the upload's principal on the hash appended and synced with
    /// an expiry `interval` past `now_ms`, the record retired, and the aside
    /// queued for the deferred unlink. Answers the file's designation, hex
    /// and size — one shape whether or not the file was already here, and in
    /// one time: the replaced instance's unlink waits for
    /// [`Store::unlink_asides`], after the answer, and a finish that fails
    /// past its link queues nothing, leaving its aside to the pruner's pass
    /// and to open.
    ///
    /// PRECONDITION: the stream's bytes written reach the upload's declared
    /// length — which PANICS rather than being refused: a caller's bug, not
    /// an outcome. The caller knows the figure — the offset it resumed at
    /// and [`Stream::append`]'s answers, an append whose `Io` came from its
    /// grain counting its bytes all the same (see there) — and the store
    /// asserts it here, in one place, because a finish past it would name
    /// the file by its prefix's hash and lease it at a size the file does not
    /// have. `NoUpload` — the upload expired or retired under the stream — is
    /// judged first.
    ///
    /// WHAT AN `Io` LEAVES, by where it falls: before the rename, the upload
    /// stands over its partial at its record's offset, to be resumed there
    /// and finished; past the rename and before the lease's sync, the file
    /// stands with no lease, unreferenced and prunable, and the record stands
    /// in this process over a partial the rename took — a resume answers
    /// `Io` — until the upload is ended, expires, or the next open retires
    /// it; past the lease's sync, the deposit is made though the finish
    /// answered an error, and what of the record's retirement did not
    /// complete, the next open completes — its reconciliation retires a
    /// record whose partial is gone.
    ///
    /// The stream is consumed whatever the finish answers: past the rename
    /// its file is the hash's, and it closes with the stream. The store's
    /// finish lock is held from the first act to the answer, so finishes run
    /// one at a time and two of one hash never interleave the replace's
    /// check, link and rename. A request whose bytes a settle already
    /// received finishes through a stream resumed at the length.
    ///
    /// THE CALLER's EXCLUSION AROUND A FINISH: hold, around the whole call, a
    /// lock that keeps [`Store::unlink_blob`] and [`Store::remove_aside`]
    /// out. An unlink between the rename and the lease's sync leaves a lease
    /// naming bytes that are not there. An unlink between the replace's
    /// check and its link fails the link, an I/O error a create never meets
    /// — a second way of saying the file was here. An aside removed between
    /// its link and the rename lets the rename free the replaced instance
    /// inside the answer. The store sees no lock of its caller's and checks
    /// none of this; the daemon keeps it with its credential lock, the
    /// finish under the read arm and each pruner act under the write arm.
    pub fn finish(mut self, interval: Duration, now_ms: u64) -> Result<Finished, BlobError> {
        let store = self.store;
        // Held to the answer: the finishes run one at a time, and what they
        // alone touch is read and moved under it.
        let mut finishing = store.finishing.lock();
        store.uploads.lock().standing(&self.principal, &self.id, now_ms).ok_or(BlobError::NoUpload)?;
        assert!(
            self.handle.written() == self.length,
            "a finish at {} of its {} bytes: the caller finishes an upload only where its bytes written reach its \
             declared length (Stream::finish's precondition, clause (7))",
            self.handle.written(),
            self.length,
        );
        store.before(Step::PartialSync)?;
        self.handle.sync()?;
        let hex = self.handle.hash().to_hex().to_string();
        let dir = store.root.join(&self.designation);
        let from = partials::partial_path(&store.root, &self.designation, &self.id);
        let to = dir.join(&hex);
        let aside = if to.is_file() {
            // THE REPLACE: the replaced instance keeps a name through the
            // rename, so the rename frees nothing; the aside is unlinked after
            // the answer. A link, not a rename aside: the hash is never
            // without a file, whatever fails next.
            store.before(Step::LinkAside)?;
            let n = finishing.aside_serial;
            finishing.aside_serial += 1;
            let aside = dir.join(aside_name(&hex, n));
            fs::hard_link(&to, &aside)?;
            Some(aside)
        } else {
            None
        };
        store.before(Step::Rename)?;
        fs::rename(&from, &to)?;
        store.before(Step::DirSync)?;
        fsync_dir(&dir)?;
        if !finishing.root_synced.contains(&self.designation) {
            store.before(Step::RootSync)?;
            fsync_dir(&store.root)?;
            finishing.root_synced.insert(self.designation.clone());
        }
        store.before(Step::LeaseSync)?;
        store.leases.lock().append_synced(Lease {
            principal: self.principal,
            designation: self.designation.clone(),
            hex: hex.clone(),
            size: self.length,
            expires: expiry(now_ms, interval),
        })?;
        store.before(Step::RecordRetire)?;
        store.uploads.lock().retire(&self.id)?;
        // QUEUED ONLY NOW, the finish answering: the queue is drained on
        // whichever thread asks (the daemon's transport, after every blob
        // reply), and a deferred unlink that took this aside before the
        // rename would leave the replaced instance one link for the rename to
        // free inside this answer. A finish that fails after its link leaves
        // its aside to the pruner's pass and to open.
        if let Some(aside) = aside {
            store.aside_queue.lock().push(aside);
        }
        Ok(Finished { designation: self.designation, hex, size: self.length })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AN APPEND MEASURES ITS GRAIN FROM ITS OWN STREAM's OFFSET, WHATEVER
    /// THE RECORD SAYS: two streams of one upload — what a caller that does
    /// not keep one stream of an upload at a time (`Store`) can reach — the
    /// first settling after the second's resume cut the partial back, so the
    /// record stands ahead of the second's bytes: the second's append
    /// answers, neither panicking nor wrapping, writing no record, and its
    /// settle sets the record to the bytes it holds.
    #[test]
    fn an_append_measures_its_grain_from_its_own_streams_offset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(dir.path(), Duration::from_secs(1), 0).expect("the store opens");
        let rec = store.create_upload("k", HashFunction::Blake3, 10, Duration::from_secs(60), 0).expect("create");
        let mut first = store.resume("k", &rec.id, 0, 1).expect("the first request's resume");
        first.append(b"abcd", 1).expect("the first request's bytes");
        let mut second = store.resume("k", &rec.id, 0, 2).expect("the second request's resume");
        assert_eq!(first.settle(3).expect("the first settle").offset, 4, "the record ahead of the second stream");
        assert_eq!(second.append(b"x", 4).expect("the append answers"), 1);
        assert_eq!(
            store.upload("k", &rec.id, 4).map(|r| r.offset),
            Some(4),
            "the grain measured from the stream's own offset: no sync and no record written, where a measure \
             wrapped from the record's takes both"
        );
        assert_eq!(second.settle(5).expect("the settle answers").offset, 1, "the record set to the second's bytes");
        assert_eq!(fs::read(partials::partial_path(dir.path(), "blake3", &rec.id)).unwrap(), b"x");
    }
}
