//! The store: the four media stores under the root, opened as one.
//!
//! The four are the files, the partials, the upload records and the lease
//! log; [`Stream`] is one upload open for one request; and the module holds
//! the order of their acts: an upload's creation and resume, a stream's
//! settle and the PUT's finish, the deferred unlink after its answer, the
//! pruner's acts one at a time, the leases' reads. [`Step`] names the steps
//! of a finish the hazard seam can hold or fail; [`Finished`] is a finish's
//! answer. Under `test-hooks`, the child `store/hooks.rs` holds the test
//! seam.
//!
//! **The order** (`media.md` Op inventory 1, "the PUT's disposition on a
//! hash already present is replace, not no-op"; the register M-I5 (a)). A
//! rename is atomic in the namespace and is lost with its directory entry at
//! a power loss, so a file is durable only at its directory's fsync, and a
//! new directory's entry only at *its* parent's — which is why the finish
//! syncs the designation directory after the rename, the root at the first
//! finish into a designation directory no root fsync since the open has
//! made durable, whatever made it, and every open the board's own directory
//! after the root, `blobs/`'s own entry being the board's. The partial
//! lives in its target's own designation directory, so the rename never
//! crosses a filesystem. Replace is `rename(2)`'s own disposition over an
//! existing name: the file holding the wrong bytes under the right name is
//! the one case a repair exists for, and a no-op would defeat it.
//!
//! **The replaced instance's aside is unlinked after the answer**
//! (`media.md` Op inventory 1, "no answer of the upload says whether the
//! file was already here" — the *time* an answer takes is part of what it
//! says). A rename over a name whose inode holds its last link frees that
//! inode's blocks inside the rename, which at the per-file cap costs the
//! replace arm hundreds of milliseconds a create never pays. So where the
//! name exists the finish first gives the replaced instance a second name —
//! a hard link at an aside name no hex spells, `.retired-<hex>-<n>` in the
//! same directory — then renames the partial onto the hash: the replaced
//! instance keeps a link, the rename frees nothing, and the aside is
//! unlinked after the answer has been written — the deferred unlink
//! ([`Store::unlink_asides`]) — where the freeing's cost lands off the
//! request's path. The finish queues its aside for that unlink only as it
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
//! **The pruner's rename aside** takes the same name for the same reason
//! ([`Store::rename_aside`]; `media.md` Op inventory 2, "one file per
//! acquisition — re-read, rename aside, release, the aside unlinked after
//! under no arm"): an unlink frees the file's blocks inside the call, so a
//! pass holding the board's exclusive arm across one would hold every write
//! for the unlink's time; renamed aside under the arm and unlinked after it,
//! the arm is held one re-read and one rename, and a crash between the two
//! leaves an aside open removes.
//!
//! The inspection ([`Store::inspect`]) and the pull's install
//! ([`Store::install_file`]) are the operator's two doors, and neither opens
//! the store as the daemon does: the inspection reads the four stores as
//! they stand and writes nothing; the install writes one file by the PUT's
//! order, making the root and its designation directory where absent, and
//! nothing else.

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

use crate::blobs::{
    self, aside_name, designation_ok, dir_label, fsync_dir, hex_ok, is_aside_name, label, named, not_found_as_none,
    partial_label,
};
use crate::error::BlobError;
use crate::jsonl::{LogRead, LogSize, LogStop};
use crate::lease::{Lease, LeaseLog, LeaseState};
use crate::partials::{self, Handle, HashFunction, SYNC_GRAIN};
use crate::uploads::{expiry, UploadId, UploadRecord, UploadRecords};

/// The steps of a finish, in order: the points the hazard seam names.
///
/// Under `test-hooks`, a hold or an injected failure is placed before the
/// step it names, after every step before it has completed. Two are the
/// replace's own and are met only where the name already exists:
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
    /// The hard link of the replaced instance to its aside name.
    ///
    /// The replaced instance is the file at `<designation>/<hex>`; the link
    /// is taken only where the name exists.
    LinkAside,
    /// The rename of the partial onto `<designation>/<hex>`.
    Rename,
    /// The designation directory's fsync — the rename's durability.
    DirSync,
    /// The root's fsync — a new designation directory's durability.
    ///
    /// It is taken only where no root fsync since the store opened has made
    /// the directory's entry durable — a directory made after the open,
    /// whatever made it; a hold or a failure named here is met only on such
    /// a finish.
    RootSync,
    /// The lease's append and sync.
    LeaseSync,
    /// The upload record's retirement — the last act on disk before the answer.
    RecordRetire,
    /// The unlink of the replaced instance's aside name.
    ///
    /// It is run after the answer by the deferred unlink
    /// ([`Store::unlink_asides`]) and never inside a finish; met only on a
    /// finish that replaced a present name.
    UnlinkAside,
}

/// A finished upload's answer: the file's designation, hash and size.
///
/// Its hash is BLAKE3's — the function its designation names, save for an
/// upload read off a log restored from elsewhere under another designation
/// — as lowercase hex. One shape whether or not the file was already here
/// (`media.md` Op inventory 1, "no answer of the upload says whether the
/// file was already here").
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — field
/// reads are unaffected, and a further field is an addition rather than a
/// broken build.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Finished {
    /// The file's designation.
    pub designation: String,
    /// The file's hash, as lowercase hex.
    pub hex: String,
    /// The file's size, in bytes.
    pub size: u64,
}

/// What the open did, as [`Store::opened`] answers it.
///
/// The open repairs before it answers anything (`media.md` §The media
/// stores, "open's passes over both stores"; the register M-I5 (c)), and
/// each repair is an act on what a depositor holds — a log's torn tail cut,
/// the lines it cannot read dropped, a lease past the horizon dropped, an
/// expired upload removed, a record and its partial held to each other, an
/// orphan partial and an aside removed, a store or a log found absent and
/// made empty. The store writes no operator stream; this is the account it
/// leaves its embedder to say, as the kernel's recovery is the journal's —
/// every figure here a fact the store alone holds, the open's own, made
/// once.
///
/// **What tells routine from damage.** A log's
/// [`TailCut`](crate::TailCut) whose first untrusted line was whole
/// ([`TailCut::damage`](crate::TailCut::damage) — a damaged last line
/// included, and the whole lines past it with it), a log's `unread` lines,
/// and a log found `absent` beside a root that stood are each a loss of
/// leases or uploads a client was answered over — a damaged log, a copy
/// that stopped short or that another build wrote — which the open has
/// already acted on and nothing else will say: a damaged cut's bytes it
/// kept beside the log first ([`LogRead::kept`](crate::LogRead::kept)). The
/// rest are the open's ordinary repairs after a crash or a stop, a torn
/// last line's cut among them.
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — field
/// reads are unaffected, and a further field is an addition rather than a
/// broken build.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Opened {
    /// No directory stood at the root, so the open made it.
    ///
    /// It made both logs in it too, empty. Over a board whose journal names
    /// a deposit's file — a restore that left `blobs/` out — every such file
    /// is a hole.
    pub root_made: bool,
    /// The upload records' log, `uploads.log`, as the open read it.
    pub uploads_log: LogRead,
    /// The lease log, `leases.log`, as the open read it.
    pub leases_log: LogRead,
    /// The uploads standing once the open is done.
    pub uploads: usize,
    /// The leases held once the open is done.
    pub leases: usize,
    /// Leases lapsed past the horizon, dropped from the log.
    pub leases_past_horizon: usize,
    /// Expired uploads removed — the partial, then the record.
    pub expired_uploads: usize,
    /// Upload records retired, their partials gone.
    ///
    /// A crash past a finish's rename leaves one, or a copy that took the
    /// record and not the partial.
    pub records_without_partial: usize,
    /// Partials cut back to their records' offsets.
    ///
    /// The bytes cut lie past the durable point, which no client was
    /// answered over.
    pub partials_cut_back: usize,
    /// Records set back to their partials' lengths.
    ///
    /// A copy that took a partial before its record leaves one.
    pub records_set_back: usize,
    /// Partials no record names, removed under this build's designations.
    pub orphan_partials: usize,
    /// Asides removed.
    ///
    /// They are a replace's second names its deferred unlink never took, and
    /// the pruner's own.
    pub asides: usize,
    /// The bytes those repairs freed.
    ///
    /// They are the expired uploads', the orphans' and the asides' files
    /// removed — each its length where its unlink took the file's last name,
    /// nothing where another name still holds it — and the bytes cut off the
    /// partials cut back.
    pub bytes_freed: u64,
}

/// The store: one root and the four stores under it.
///
/// Every method takes `&self`, and the store's own locks keep its records
/// whole across uploads.
///
/// **A stream is one request's.** [`Store::resume`] answers a [`Stream`] —
/// the partial opened afresh at the record's offset, with the hash of its
/// bytes — and the request that resumed owns it: it appends through it and
/// ends it by [`Stream::settle`] or [`Stream::finish`], each of which
/// consumes it, or, cut short, drops it. The partial's file closes with the
/// stream, so the store holds no file for a request that has ended, and no
/// request reaches another's.
///
/// **One stream of an upload at a time, its acts serialized** — the
/// caller's to keep, as the daemon keeps it with its hold on an upload's
/// identifier while a stream owns it (`media.md` Op inventory 1, the
/// resumable upload (5), "a stream claims its upload first"). The store
/// checks neither: a second stream's resume cuts the partial back under the
/// first's handle, after which either stream's bytes may land where the
/// other's hasher does not look, and a finish names the file by a hash its
/// bytes do not have. An end ([`Store::end_upload`]), or the pruner's
/// removal of an expired upload ([`Store::expire_upload`]), between a
/// stream's acts costs that stream its upload alone: its later acts answer
/// `NoUpload`. The expiry passing with the upload not yet removed costs it
/// less: its settle and its finish judge the upload standing and answer
/// `NoUpload`, while its appends, judged by the record held, go on — a
/// grain re-fixing the expiry (see [`Stream::append`]).
///
/// **The store checks every name it is handed before it becomes a path.**
/// A designation or a hex a caller passes in becomes a path only past its
/// spelling's check (`blobs.rs`), made here, where a caller's name enters: a
/// malformed one is answered as absent by every read and act —
/// [`Store::blob_path`], [`Store::blob_size`], [`Store::blobs_of`],
/// [`Store::asides_of`], [`Store::unlink_blob`], [`Store::rename_aside`],
/// [`Store::remove_aside`] — while [`Store::create_upload`] is handed no
/// name at all: it takes a [`HashFunction`], whose designation is the
/// crate's own spelling, held to that check by `partials/handle.rs`'s unit
/// suite. A name read back off a log at open meets the same check where it
/// enters from disk: a record or lease line naming a malformed one reads as
/// a lost line does (`uploads.rs`, `lease.rs`), so a log restored from
/// elsewhere names no path out of the root, and the leases, holding no
/// malformed name, answer one as none ([`Store::lease_state`],
/// [`Store::any_live_lease`]). Inside the crate a name that has passed this
/// check, or that the store spelled itself (a finish's hash), is trusted.
///
/// **A log that stops stays stopped until a compaction completes.** Each log
/// cuts a failed append back off its file; where that cut fails too, the
/// log takes no further append until a compaction completes (`jsonl.rs`).
/// The store compacts at its open, over the logs it has just read, and at
/// its caller's runtime compaction ([`Store::compact_logs_if_past`] — the
/// pruner's pass, which rewrites a stopped log whatever its count); between
/// the two every act that writes a stopped log answers `Io`: on the
/// records' log a creation, a byte received, and an end's or an expiry's
/// retirement; and a finish, where either log has stopped, before its first
/// act — so a stop strands no upload over a partial its rename took
/// ([`Stream::finish`]). The stop keeps its cause in the operator's words —
/// the act that failed and the OS's cause, a full volume told apart from a
/// read-only mount or a failing device — which every refused append names;
/// and it counts the appends it refuses, which [`Store::stopped_logs`]
/// answers beside the cause and the stop's age, the uploads it cost the
/// operator's figure and no caller's. The next open reads the log afresh,
/// its tail check cutting the torn line the failed cut left
/// ([`Store::open`]).
///
/// **A failure at one of its files names the file and the act** —
/// `{file}: {act}: {cause}`, the kind kept, the file named within the data
/// directory and a partial by its directory alone, a full volume's cause
/// reading `the volume is full` (`blobs.rs`, which names the refusals worded
/// otherwise).
pub struct Store {
    root: PathBuf,
    uploads: Mutex<UploadRecords>,
    leases: Mutex<LeaseLog>,
    /// What this store's open did ([`Opened`]).
    ///
    /// It is held for its embedder to read and say.
    opened: Opened,
    /// The finish lock, which runs the finishes one at a time.
    ///
    /// Every [`Stream::finish`] holds this from its first act to its answer,
    /// so two finishes of one hash never interleave the replace's check, link
    /// and rename — which would let the second rename free the first file's
    /// blocks inside its own answer. It holds the finishes' own state
    /// ([`FinishState`]), so nothing reads or moves that unheld. No other
    /// shipped act takes it but the pruner's rename aside, for the serial
    /// alone, so no append waits on another upload's finish; the store's
    /// other locks are taken under it, briefly, and it under none.
    finishing: Mutex<FinishState>,
    /// The aside queue: what answered replaces left for the deferred unlink.
    ///
    /// It holds their aside names ([`Store::unlink_asides`]), in the order
    /// their finishes answered — each queued as its finish answers, never
    /// sooner. An aside a failed finish left on disk is never among them:
    /// the pruner's pass and open take that one. Beside the finish lock and
    /// not in it: the deferred unlink takes the queue on any thread and
    /// never waits on a finish.
    aside_queue: Mutex<Vec<PathBuf>>,
    #[cfg(feature = "test-hooks")]
    hooks: Mutex<hooks::Hooks>,
}

/// The finishes' own state, held inside the lock that runs them one at a time.
///
/// The lock is `Store`'s `finishing`. In a shipped build a finish reads and
/// moves the state, and the pruner's rename aside moves its serial; the
/// test seam's `install` moves it too, under the same lock: a finish's check
/// and its update of either are one critical section by construction.
struct FinishState {
    /// The root's fsync paid, by designation directory.
    ///
    /// These are the designation directories whose entry in the root an
    /// fsync has made durable — every directory under the root when the
    /// open's own root fsync ran, and each one a finish's root fsync
    /// ([`Step::RootSync`]) has paid since, entered only once that fsync has
    /// succeeded, so a failed one leaves it owed to the next finish. Every
    /// other designation directory owes the root an fsync before a lease
    /// names a file in it, whatever made it: a creation that failed past its
    /// directory's mkdir leaves the directory standing and its entry owed,
    /// exactly as one that succeeded does.
    root_synced: HashSet<String>,
    /// The aside serial: the `<n>` of the next aside name this store makes.
    ///
    /// It only rises, so two replaces of one hash before the first's unlink
    /// take two names — a plain count, the lock it lives in being what keeps
    /// each one a single act's own, a finish's or a rename aside's.
    aside_serial: u64,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("root", &self.root).finish_non_exhaustive()
    }
}

impl Store {
    /// Opens the store at `root`, created where absent, at `now_ms`.
    ///
    /// Before any act under the root, every name the store acts on there is
    /// held to what the store makes, and nothing is followed or written
    /// through one that is not (`blobs.rs`, `refuse_links_and_special_files`).
    ///
    /// **Then what frees room, before what takes it.** Every aside is removed
    /// — a crash's, a failed finish's or the pruner's, nothing naming any —
    /// the upload records opened, a torn tail cut, and the partials
    /// reconciled with them both ways, expired and orphan partials removed and
    /// longer ones cut back, a line appended for each record they change; and
    /// only then the acts that ask the volume for room beyond those lines —
    /// the lease log opened and compacted under `horizon` (a lease lapsed by
    /// it or more answers as none, and is dropped); the volume held to the
    /// one capability the store needs that no other act of the open
    /// exercises, a second name for a file, which a re-PUT of a file the
    /// board holds takes (`blobs.rs`, `probe_hard_link`), its probe a
    /// directory and a file of its own; and the records compacted. So an open
    /// on a full volume has made the room its own repairs make before it asks
    /// for any beyond those lines, and fails, where it fails, with that room
    /// made. Last, the root fsynced and then the board's own directory, the
    /// root's parent, whose fsync alone makes the root's own entry durable
    /// (the register M-I5 (a)) — at every open, so a `blobs/` a first start
    /// made outlives a power loss with every deposit in it, and an open that
    /// failed at that fsync has it made again by the next.
    ///
    /// Everything here completes before the store answers anything. An open
    /// that fails partway serves nothing and leaves on disk what its acts
    /// completed, each one the next open makes again: the open is where the
    /// store reconciles what it finds — its compactions made again while it
    /// serves by its caller's runtime compaction
    /// ([`Store::compact_logs_if_past`]) — and a log a failure stopped while
    /// an earlier store served is read here afresh, its torn tail cut (see
    /// [`Store`]). What the open did, it answers ([`Store::opened`]), the
    /// bytes its repairs freed among it: the store says nothing itself, and
    /// leaves it to its embedder to say.
    ///
    /// **Precondition.** No other `Store` is open over `root` while this one
    /// lives, in this process or another. Its open would act on the root
    /// this store serves: cut a live request's partial back under its
    /// handle, so that the bytes the handle's hasher covers past the cut are
    /// zeros on disk and the finish names the file by a hash its bytes do not
    /// have; remove the partials created since its read as orphans; remove
    /// the asides of finishes between their link and their rename, so those
    /// renames free the replaced instances inside their answers; and rename a
    /// compacted log over each file this store appends to that its compaction
    /// rewrites, so every lease or offset it answers as durable afterwards in
    /// such a log lands in a file no open reads. The store takes no lock for
    /// it and checks nothing: the daemon opens this store only after its
    /// kernel has taken the exclusive lock on the data directory
    /// (`Daemon::open`'s precondition), so a second daemon over the same
    /// directory fails there, before it reaches `blobs/`.
    ///
    /// # Errors
    ///
    /// A symbolic link, a special file, or a second link to a file the store
    /// writes in place fails the open as `InvalidData`, before any act under
    /// the root: one refusal of bounded length counting every one it found,
    /// naming them in at most eight clauses and the act that clears each
    /// kind. A volume that makes no second name for a file fails it at the
    /// probe, naming its lack and the act that clears it. A partial that
    /// cannot be read fails it, its record not retired (`partials.rs`): an
    /// I/O failure is no absence. Every other failure names its file and its
    /// act.
    pub fn open(root: impl AsRef<Path>, horizon: Duration, now_ms: u64) -> io::Result<Store> {
        let root = root.as_ref();
        let at_root = |act: &'static str| move |e: io::Error| named(e, dir_label(root, 1), act);
        let root_made = not_found_as_none(fs::symlink_metadata(root)).map_err(at_root("stat"))?.is_none();
        // `blobs/` is born owner-only, as every directory and file the store
        // makes is (`blobs::dir_builder`); a root that already stands is left
        // as found.
        blobs::dir_builder().recursive(true).create(root).map_err(at_root("create"))?;
        blobs::refuse_links_and_special_files(root)?;
        // What frees room, before what takes it: on a full volume the open
        // has made the room its own repairs make before it asks for any
        // beyond the reconciliation's lines.
        let (asides, asides_freed) = blobs::sweep_asides(root)?;
        let (mut uploads, uploads_log) = UploadRecords::open(root)?;
        let reconciled = partials::reconcile(root, &mut uploads, now_ms)?;
        let (leases, leases_log, leases_past_horizon) = LeaseLog::open(root, horizon, now_ms)?;
        blobs::probe_hard_link(root)?;
        uploads.compact()?;
        // Listed before the root's fsync, so every directory in the set is
        // one that fsync makes durable.
        let root_synced = blobs::dirs_under(root)?.into_iter().collect();
        fsync_dir(root).map_err(at_root("fsync"))?;
        let board = board_of(root);
        fsync_dir(board).map_err(|e| named(e, dir_label(board, 1), "fsync"))?;
        let opened = Opened {
            root_made,
            uploads_log,
            leases_log,
            uploads: uploads.all().count(),
            leases: leases.count(),
            leases_past_horizon,
            expired_uploads: reconciled.expired,
            records_without_partial: reconciled.without_partial,
            partials_cut_back: reconciled.cut_back,
            records_set_back: reconciled.set_back,
            orphan_partials: reconciled.orphans,
            asides,
            bytes_freed: reconciled.bytes_freed + asides_freed,
        };
        Ok(Store {
            root: root.to_path_buf(),
            uploads: Mutex::new(uploads),
            leases: Mutex::new(leases),
            opened,
            finishing: Mutex::new(FinishState { root_synced, aside_serial: 0 }),
            aside_queue: Mutex::new(Vec::new()),
            #[cfg(feature = "test-hooks")]
            hooks: Mutex::new(hooks::Hooks::default()),
        })
    }

    /// Returns what this store's open did ([`Opened`]).
    ///
    /// It holds its repairs and what it found of the two logs, for the
    /// embedder to say — the open's account, made once and read as often as
    /// asked. The store says none of it itself.
    pub fn opened(&self) -> &Opened {
        &self.opened
    }

    /// Refuses a root holding a link or a special file, reading alone.
    ///
    /// It is the check [`Store::open`] and [`Store::inspect`] make first,
    /// offered on its own so an embedder can make it ahead of every write
    /// its start would otherwise make before reaching the store's open — the
    /// journal's open among them (`operations.md` §3.1 step 3: the refusal
    /// at the earliest act the fault is decidable from). It reads every
    /// entry under the root and writes nothing; the open makes it again as
    /// its own precondition. It judges a root standing as a directory alone:
    /// one that does not stand — a first start's — or is no directory, or
    /// cannot be read, holds nothing this check refuses, and answers `Ok`,
    /// leaving the open to meet it in its own order.
    ///
    /// # Errors
    ///
    /// A symbolic link, a special file, or a second link to a file the store
    /// writes in place, as `InvalidData`, one refusal counting every one
    /// (`Store::open`'s first refusal); a listing or a stat under the root
    /// that fails, named.
    pub fn refuse_links_and_special_files(root: impl AsRef<Path>) -> io::Result<()> {
        let root = root.as_ref();
        if fs::symlink_metadata(root).is_ok_and(|meta| meta.is_dir()) {
            blobs::refuse_links_and_special_files(root)?;
        }
        Ok(())
    }

    // ── the directory, as the pruner reads it ────────────────────────────

    /// Returns every designation directory under the root, whatever its name.
    ///
    /// They come by name, in name order: the pruner's pass reads the set
    /// against the designations its build pins and halts on a foreign one
    /// (`media.md` §The media stores, "the halts on a foreign designation
    /// directory"). Files under the root (the two logs, their compaction
    /// twins) are not among them.
    ///
    /// # Errors
    ///
    /// The root's listing failing, named (`list`).
    pub fn designation_dirs(&self) -> io::Result<Vec<String>> {
        blobs::dirs_under(&self.root)
    }

    /// Returns the files at hex names in `<designation>/`, in name order.
    ///
    /// They are the blobs the directory holds, a partial or an aside
    /// excluded by its name. An absent directory holds none.
    ///
    /// # Errors
    ///
    /// The directory's listing failing, save for its absence, named (`list`).
    pub fn blobs_of(&self, designation: &str) -> io::Result<Vec<String>> {
        blobs::names_in(&self.root, designation, |name, kind| hex_ok(name) && kind.is_file())
    }

    /// Returns the aside names in `<designation>/`, in name order.
    ///
    /// They are the second names replaces left that the deferred unlink has
    /// not reached, and any the pruner's rename aside left unremoved.
    ///
    /// # Errors
    ///
    /// The directory's listing failing, save for its absence, named (`list`).
    pub fn asides_of(&self, designation: &str) -> io::Result<Vec<String>> {
        blobs::names_in(&self.root, designation, |name, _| is_aside_name(name))
    }

    /// Unlinks the file at `<designation>/<hex>` in one act.
    ///
    /// It is the direct form, which frees the file's blocks inside the call.
    /// `Ok(true)` where a file went, `Ok(false)` where none stood. The
    /// directory is not fsynced: a crash that reverts the unlink leaves a
    /// file the next pass re-judges, which costs nothing. The daemon's pass
    /// takes a file in two acts instead — [`Store::rename_aside`] under its
    /// arm, the aside removed after it — so the arm is never held across the
    /// freeing.
    ///
    /// **Precondition.** Call it holding the lock that keeps every
    /// [`Stream::finish`] out (see there), after reading under that same hold
    /// that no live lease holds the file ([`Store::any_live_lease`]) and
    /// nothing of the caller's names it.
    ///
    /// # Errors
    ///
    /// The unlink failing, save for the file's absence, named (`remove`).
    pub fn unlink_blob(&self, designation: &str, hex: &str) -> io::Result<bool> {
        self.blob_path(designation, hex).map_or(Ok(false), |path| {
            let removed = blobs::remove_if_present(&path).map_err(|e| named(e, label(&path, 3), "remove"))?;
            Ok(removed.is_some())
        })
    }

    /// Renames the file at `<designation>/<hex>` aside.
    ///
    /// It is the pruner's one act per acquisition after its re-read of the
    /// index and the lease, in the unlink's place (`media.md` Op inventory 2,
    /// "re-read, rename aside, release, the aside unlinked after under no
    /// arm"): the file renamed to an aside name of its own,
    /// `.retired-<hex>-<n>`, the replace's own name and serial, so the arm the
    /// caller holds is released after one rename and never across the unlink
    /// that frees the file's blocks — hundreds of milliseconds at the
    /// per-file cap — which [`Store::remove_aside`] runs after, under no arm.
    /// `Ok(Some(name))` with the aside's name where a file went aside,
    /// `Ok(None)` where none stood. The directory is not fsynced: a crash that
    /// reverts the rename leaves a file the next pass re-judges, one that
    /// keeps it leaves an aside the next open removes, nothing naming either.
    ///
    /// **Precondition.** Call it holding the lock that keeps every
    /// [`Stream::finish`] out, as [`Store::unlink_blob`] is called: a finish
    /// of the same hash after the release finds no file at the name and
    /// installs afresh.
    ///
    /// # Errors
    ///
    /// The rename failing, save for the file's absence, named
    /// (`rename aside`).
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
            Err(e) => Err(named(e, label(&path, 3), "rename aside")),
        }
    }

    /// Removes one aside by name.
    ///
    /// It is the pruner's unlink after its rename aside, and its housekeeping
    /// where the deferred unlink did not run. `Ok(Some(freed))` where one
    /// went, the bytes its unlink freed — its length where it took the file's
    /// last name, nothing where another name still holds it (an aside whose
    /// replace failed between its link and its rename, still the hash's
    /// file; a hard-link copy's second name) — the figure the pruner's line
    /// says, so a pass that unlinked files and freed nothing says that too;
    /// `Ok(None)` where none stood, and for a name no aside has.
    ///
    /// **Precondition.** A replace's aside is removed under the same
    /// exclusion from [`Stream::finish`] as [`Store::unlink_blob`] is: it
    /// stands from its finish's link, before the rename; the aside of the
    /// caller's own [`Store::rename_aside`] is removed under none.
    ///
    /// # Errors
    ///
    /// The removal failing, save for the aside's absence, named (`remove`).
    pub fn remove_aside(&self, designation: &str, name: &str) -> io::Result<Option<u64>> {
        if !designation_ok(designation) || !is_aside_name(name) {
            return Ok(None);
        }
        let aside = self.root.join(designation).join(name);
        blobs::remove_if_present(&aside).map_err(|e| named(e, label(&aside, 3), "remove"))
    }

    /// Returns the path a blob of `designation` and `hex` has.
    ///
    /// `None` where either name is malformed — the name check (see
    /// [`Store`]), which every act on a file a caller names goes through.
    pub fn blob_path(&self, designation: &str, hex: &str) -> Option<PathBuf> {
        blobs::blob_path(&self.root, designation, hex)
    }

    /// Returns the size check's read of the file at `<designation>/<hex>`.
    ///
    /// The check is M-I5 (c)'s — the deposit record exact of what is on disk
    /// — which the daemon makes only where the asking principal's own record
    /// names the hash (M-I2 (e)). `Ok(Some(size))` where a file stands there;
    /// `Ok(None)` where none does — no entry, an entry that is no file, or a
    /// malformed designation or hex, refused as absent.
    ///
    /// # Errors
    ///
    /// `Err` where the name cannot be read. An I/O failure is no absence:
    /// what to answer over it is the caller's.
    pub fn blob_size(&self, designation: &str, hex: &str) -> io::Result<Option<u64>> {
        let Some(path) = self.blob_path(designation, hex) else {
            return Ok(None);
        };
        size_of(&path)
    }

    /// Returns the volume's free space at the root, in bytes.
    ///
    /// It is the floor's read, of bytes alone: the volume's inodes are not
    /// read, and on a volume of many small deposits, each one file however
    /// few its bytes, they run out first (`RUNBOOK.md` §1).
    ///
    /// # Errors
    ///
    /// The `statvfs` read failing, named (`statvfs`).
    pub fn free_space(&self) -> io::Result<u64> {
        blobs::free_space(&self.root)
    }

    /// Returns the volume's capacity at the root, in bytes.
    ///
    /// It is the same `statvfs` read as [`Store::free_space`]'s: what the
    /// daemon's default per-account limit is a share of, read once at its
    /// start.
    ///
    /// # Errors
    ///
    /// The `statvfs` read failing, named (`statvfs`).
    pub fn capacity(&self) -> io::Result<u64> {
        blobs::capacity(&self.root)
    }

    /// Runs the runtime compaction, the last step of the pruner's pass.
    ///
    /// Each log is rewritten to its current records as open rewrites it
    /// (`media.md` §The media stores, "the pruner's pass rewrites either
    /// store the same way once its log has passed a size trigger") — the
    /// lease log's leases past the horizon at `now_ms` dropped first, as open
    /// drops them, whether or not a rewrite follows — where its whole lines
    /// number at least `min_lines` and more than `trigger` times its current
    /// records — or where it has stopped, whatever its count, since only a
    /// completed compaction lifts a stop — under this store's lock on *that*
    /// log's appends alone and no lock of the caller's. An append that
    /// arrives during the rewrite waits on that lock and lands in the new
    /// file once the install order has completed, so the records it answers
    /// durable afterwards are in the file the next open reads. The answer is
    /// `(uploads, leases)`, each the size the log was rewritten *from*
    /// ([`LogSize`]) where a rewrite ran and `None` where the log was left as
    /// it was — its size after, [`Store::log_sizes`].
    ///
    /// # Errors
    ///
    /// Both logs are tried, and a failure is the first that failed: one past
    /// its rename leaves its log stopped ([`Store::stopped_logs`]) for the
    /// next pass to rewrite.
    pub fn compact_logs_if_past(
        &self,
        trigger: usize,
        min_lines: usize,
        now_ms: u64,
    ) -> io::Result<(Option<LogSize>, Option<LogSize>)> {
        let uploads = self.uploads.lock().compact_if_past(trigger, min_lines);
        let leases = self.leases.lock().compact_if_past(trigger, min_lines, now_ms);
        Ok((uploads?, leases?))
    }

    /// Returns which logs have stopped, as `(uploads, leases)`.
    ///
    /// Each is its stop ([`LogStop`]) where the log has stopped and `None`
    /// where it takes appends: the cause in the operator's words — an append
    /// failed and its cut-back failed too, or a compaction failed past its
    /// rename — each with the OS's cause, a full volume told apart from a
    /// read-only mount or a failing device, so the act that clears it can be
    /// named; how long the stop has stood; and the appends it has refused,
    /// the uploads it cost. The log takes no append until a compaction
    /// completes; the pass's line names the stop with its figures, and a pass
    /// that lifts it reads it here before its rewrite.
    pub fn stopped_logs(&self) -> (Option<LogStop>, Option<LogStop>) {
        (self.uploads.lock().log_stopped(), self.leases.lock().log_stopped())
    }

    /// Returns the logs' sizes, as `(uploads, leases)`.
    ///
    /// Each is its whole lines and their bytes ([`LogSize`]): what the
    /// pruner's line says of each at every pass, the room a rewrite of each
    /// needs — the open's compaction, the pass's own — being at most a second
    /// copy of it.
    pub fn log_sizes(&self) -> (LogSize, LogSize) {
        (self.uploads.lock().log_size(), self.leases.lock().log_size())
    }

    /// Inspects the four stores under `root` as they stand.
    ///
    /// It is the operator's inventory's open (`media.md` §Recovery, "neither
    /// opens the store as skepd does — the inventory reads a copy's stores as
    /// they stand"), which reconciles nothing, compacts nothing, sweeps
    /// nothing, fsyncs nothing, creates nothing and holds nothing open
    /// afterwards — the logs read as the open reads them, trust ending at a
    /// torn tail cut in memory alone, every record and every lease they hold
    /// folded to its latest line, standing or not, and what each reading
    /// found ([`Inspection::logs`]): the cut an open would make and the lines
    /// it would drop, so a copy whose log is damaged is told from one that
    /// holds it whole; the files, partials and asides listed by name on
    /// demand. It takes no lock and needs no exclusion: it can stand beside a
    /// serving daemon's store, each of its readings one moment's of one file.
    ///
    /// # Errors
    ///
    /// Before any of it, every name under the root it reads is held to what
    /// the store makes, as the open holds them (`blobs.rs`,
    /// `refuse_links_and_special_files`): a symbolic link or a special file
    /// at a log's name — a FIFO, whose read never ends — or a second link to
    /// a file the store writes in place — a hard-link copy of a live board,
    /// which is no copy — is refused as `InvalidData` as the open refuses
    /// it, one refusal counting every one, and never followed or read. A
    /// `root` that is no directory, or whose kind cannot be read, is
    /// `NotFound`. A listing's, a stat's or a log's read failure is
    /// answered, named.
    pub fn inspect(root: impl AsRef<Path>) -> io::Result<Inspection> {
        let root = root.as_ref();
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} is no blob store: no such directory", root.display()),
            ));
        }
        blobs::refuse_links_and_special_files(root)?;
        let (uploads, uploads_log) = UploadRecords::read_as_found(root)?;
        let (leases, leases_log) = LeaseLog::read_as_found(root)?;
        Ok(Inspection { root: root.to_path_buf(), uploads, uploads_log, leases, leases_log })
    }

    /// Installs one file by the PUT's order: the pull's install.
    ///
    /// It is the operator's restore (`media.md` §Recovery, "installs the file
    /// as the PUT's order installs one, beside a serving daemon holding none
    /// of its gates"): the bytes of `source` streamed into a temp file in the
    /// designation directory of `function` under `root`, hashed as they are
    /// copied, the temp file fsynced, renamed onto `<designation>/<hex>` —
    /// replace where a file stands, which ends any hole under the name — the
    /// directory fsynced, then the root, then the board's own directory, the
    /// root's own entry made durable at every install as at every open
    /// ([`Store::open`]), so a pull run again makes every fsync again. The
    /// temp file is named as a partial is, `.upload-<a fresh identifier>` no
    /// record names, so a daemon's open that meets it mid-pull removes it as
    /// an orphan and the pull is run again. No lease, no record, no lock: a
    /// restore of bytes a committed cell already names — which is the
    /// caller's to have read — never a deposit. Answers the file's
    /// designation, hex and size.
    ///
    /// **Into a board that stands.** The root is made where absent,
    /// owner-only, but never its parent, the board's own directory — a pull
    /// handed a mistyped directory is refused, naming it, where it would
    /// otherwise make the directory and report the restore done, the hole
    /// standing.
    ///
    /// Beside a serving daemon: its finishes take the store's own locks and
    /// never this call's, so a finish of the same hash racing this rename is
    /// a replace either way, and the name is never without a file; the
    /// daemon's fetch reads the file under the name at its next request.
    ///
    /// # Errors
    ///
    /// **What an `Err` says, by the rename.** Every failure before it reads
    /// `nothing installed: …`: an I/O failure's `{file}: {act}: {cause}` —
    /// the source by the path handed in, the store's files by their names
    /// within the data directory, the temp file removed, best effort; a
    /// board directory that does not stand, named as handed in, as
    /// `NotFound`; the OS's refusal of entropy; and where `expected` names a
    /// hex and the bytes hash to another, `the file's bytes hash to {hex},
    /// not the {expected} the cell names`, as `InvalidData`. A failure past
    /// the rename — the directory's fsync, the root's or the board's — reads
    /// `installed at {file}, but {file}: fsync: {cause}`, its kind kept: the
    /// file stands under its hash, ending the hole, and a power loss before a
    /// sync that succeeds may still take it, so the pull is run again once
    /// the volume answers.
    pub fn install_file(
        root: impl AsRef<Path>,
        function: HashFunction,
        source: impl AsRef<Path>,
        expected: Option<&str>,
    ) -> io::Result<Finished> {
        let root = root.as_ref();
        let source = source.as_ref();
        let designation = function.designation();
        let dir = root.join(designation);
        let refused = |e: io::Error| io::Error::new(e.kind(), format!("nothing installed: {e}"));
        let board = board_of(root);
        if !board.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "nothing installed: no directory stands at {}: the pull installs into a board's own directory \
                     and makes none",
                    board.display()
                ),
            ));
        }
        // The root, the designation directory and the temp file born
        // owner-only, as the finish's are (`blobs::dir_builder`,
        // `blobs::file_options`), the rename carrying the file's mode onto
        // its hex name.
        make_dir(root).map_err(|e| refused(named(e, dir_label(root, 1), "create")))?;
        make_dir(&dir).map_err(|e| refused(named(e, dir_label(&dir, 2), "create")))?;
        let mut from = fs::File::open(source).map_err(|e| refused(named(e, source.display(), "open")))?;
        let temp = partials::partial_path(root, designation, &UploadId::mint().map_err(refused)?);
        let temp_name = format!("the pull's temp file in {}", dir_label(&dir, 2));
        let (hex, size) = {
            let mut out = blobs::file_options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp)
                .map_err(|e| refused(named(e, &temp_name, "create")))?;
            let mut hasher = blake3::Hasher::new();
            let mut buf = [0u8; PULL_BUFFER];
            let mut size = 0u64;
            let copied = loop {
                let n = match io::Read::read(&mut from, &mut buf) {
                    Ok(0) => break Ok(()),
                    Ok(n) => n,
                    Err(e) => break Err(named(e, source.display(), "read")),
                };
                hasher.update(&buf[..n]);
                if let Err(e) = io::Write::write_all(&mut out, &buf[..n]) {
                    break Err(named(e, &temp_name, "write"));
                }
                size += n as u64;
            };
            if let Err(e) = copied.and_then(|()| out.sync_all().map_err(|e| named(e, &temp_name, "sync"))) {
                let _ = blobs::remove_if_present(&temp);
                return Err(refused(e));
            }
            (hasher.finalize().to_hex().to_string(), size)
        };
        if let Some(expected) = expected {
            if expected != hex {
                let _ = blobs::remove_if_present(&temp);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("nothing installed: the file's bytes hash to {hex}, not the {expected} the cell names"),
                ));
            }
        }
        let to = dir.join(&hex);
        if let Err(e) = fs::rename(&temp, &to) {
            let _ = blobs::remove_if_present(&temp);
            return Err(refused(named(e, label(&to, 3), "install")));
        }
        fsync_dir(&dir)
            .map_err(|e| named(e, dir_label(&dir, 2), "fsync"))
            .and_then(|()| fsync_dir(root).map_err(|e| named(e, dir_label(root, 1), "fsync")))
            .and_then(|()| fsync_dir(board).map_err(|e| named(e, dir_label(board, 1), "fsync")))
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "installed at {}, but {e}: the file stands under its hash and a power loss may yet take \
                         it; run the pull again once the volume answers",
                        label(&to, 3)
                    ),
                )
            })?;
        Ok(Finished { designation: designation.to_string(), hex, size })
    }

    // ── the upload records ───────────────────────────────────────────────

    /// Creates an upload (clause (1)) and answers its record.
    ///
    /// It mints the identifier — 128 bits from the OS — creates the empty
    /// partial in the directory of `function`'s designation, and writes the
    /// record, synced: its `principal`, that designation, its declared
    /// `length`, offset 0, and the upload's interval, `interval` — the limits
    /// in force at this creation, held in the record for every expiry the
    /// upload will have (clause (3)), in the whole milliseconds its line
    /// spells — its first expiry that interval past `now_ms`. The creation
    /// names the function its finish computes, as a type, since a key names
    /// the function that made it (`media.md` §The design, item 4, "every
    /// sidecar key names its function"): no creation can name one this store
    /// does not compute.
    ///
    /// # Errors
    ///
    /// Every error here is the disk's, or the OS's refusal of entropy. An
    /// error — the OS refusing entropy, the partial's creation, the record's
    /// write — leaves no upload, and no partial: one the failed creation made
    /// is removed with the failure, and only where that removal fails too
    /// does the next open remove it, as the orphan it is — so a refused
    /// creation, one per client's retry while a stopped log refuses them all,
    /// never piles up empty partials, each an inode the floor never reads. A
    /// designation directory made here stands, its entry in the root fsynced
    /// by the next finish into it as it would be had the creation succeeded.
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
        let created = partials::create(&self.root, designation, &id)
            .and_then(|()| self.uploads.lock().create(id, principal, designation, length, interval, now_ms));
        if created.is_err() {
            // No record names the partial: removed now, the records' lock
            // released, rather than left an orphan until the next open.
            let _ = partials::remove(&self.root, designation, &id);
        }
        created
    }

    /// Returns the principal's own record by identifier.
    ///
    /// `None` for an identifier its records do not name or whose upload has
    /// expired at `now_ms`, one answer for both (M-I2 (e)).
    pub fn upload(&self, principal: &str, id: &UploadId, now_ms: u64) -> Option<UploadRecord> {
        self.uploads.lock().standing(principal, id, now_ms).cloned()
    }

    /// Returns the principal's standing uploads at `now_ms`.
    ///
    /// They come in identifier order.
    pub fn uploads_of(&self, principal: &str, now_ms: u64) -> Vec<UploadRecord> {
        self.uploads.lock().standing_of(principal, now_ms)
    }

    /// Resumes the principal's upload for this request at `offset`.
    ///
    /// `offset` is the record's durable offset (clauses (3), (5)); answers
    /// the upload's [`Stream`] — the partial opened afresh, cut back to
    /// `offset` where it is longer and its first `offset` bytes hashed (at
    /// most its declared length), under no lock another upload waits on. One
    /// stream of an upload at a time is the caller's to keep (see [`Store`]).
    ///
    /// # Errors
    ///
    /// The refusals, in the order they are judged: `NoUpload` where the
    /// identifier names no standing upload of `principal`'s — answered
    /// before any figure of the record, so no offset is ever named to
    /// another principal (M-I2 (e)); then `Offset`, carrying the record's
    /// offset, where `offset` is any other. Neither refusal touches the
    /// partial. An `Io` opens no stream: the partial unreadable; gone, a
    /// finish's rename having taken it, or an end's unlink before its
    /// directory's fsync failed — no resume continues that upload, so the
    /// refusal names the act that ends it, the upload's end and a PUT of its
    /// bytes again, its kind `NotFound` (`partials/handle.rs`); or shorter
    /// than the record's offset — no state this store leaves: a disk changed
    /// under it, or two streams of one upload (see [`Store`]) — refused and
    /// never extended. An `Io` past the cut-back has cut only bytes past the
    /// durable point, none received.
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

    /// Ends the upload (clause (6), the termination), nothing kept.
    ///
    /// The partial is removed and the record retired. A stream of the upload
    /// still open receives nothing more: its acts answer `NoUpload`.
    ///
    /// # Errors
    ///
    /// `NoUpload` where the principal holds none by that identifier at
    /// `now_ms`. An `Io` removing the partial leaves the upload standing at
    /// its record's offset, its partial gone where the unlink went through
    /// and the directory's fsync then failed; one writing the retirement
    /// leaves it retired in this process, its record's line on disk until
    /// the next open's reconciliation, which finds no partial and retires it.
    pub fn end_upload(&self, principal: &str, id: &UploadId, now_ms: u64) -> Result<(), BlobError> {
        let designation =
            self.uploads.lock().standing(principal, id, now_ms).ok_or(BlobError::NoUpload)?.designation.clone();
        partials::remove(&self.root, &designation, id)?;
        self.uploads.lock().retire(id)?;
        Ok(())
    }

    /// Runs the deferred unlink of every replace's aside the queue holds.
    ///
    /// Each aside name is unlinked, in order — the replaced instance's blocks
    /// freed here, after its answer, and never on the request's path. Safe on
    /// any thread at any time: no aside is queued before its finish answers.
    /// Answers the count unlinked, an aside already gone counted with them.
    ///
    /// # Errors
    ///
    /// A failure leaves that aside and the rest queued for the next call, and
    /// open removes any aside a crash leaves. Its failure names the aside it
    /// met, as a failure at a file names it —
    /// `blobs/blake3/.retired-<hex>-<n>: remove: {cause}`, the kind kept — in
    /// the error itself, so the line its embedder says of it names the file
    /// whatever another thread's call has taken from the queue since.
    pub fn unlink_asides(&self) -> io::Result<usize> {
        let mut queued = std::mem::take(&mut *self.aside_queue.lock()).into_iter();
        let mut done = 0;
        for aside in queued.by_ref() {
            // Already gone counts as done: the pruner's pass took it.
            if let Err(e) = self.before(Step::UnlinkAside).and_then(|()| blobs::remove_if_present(&aside)) {
                let e = named(e, label(&aside, 3), "remove");
                // It, and every one after it, back at the queue's head in
                // order.
                self.aside_queue.lock().splice(0..0, std::iter::once(aside).chain(queued));
                return Err(e);
            }
            done += 1;
        }
        Ok(done)
    }

    // ── the expired uploads, as the pruner removes them ──────────────────

    /// Returns the expired uploads at `now_ms`: every record past its expiry.
    ///
    /// They come in identifier order — the pruner's read, which reads no
    /// reference. The hold a stream has on one is the daemon's to consult
    /// before [`Store::expire_upload`].
    pub fn expired_uploads(&self, now_ms: u64) -> Vec<UploadRecord> {
        self.uploads.lock().expired(now_ms)
    }

    /// Removes an expired upload: its partial removed, its record retired.
    ///
    /// It is the pruner's act, whatever principal minted it, after the daemon
    /// has found no stream holding it. `Ok(Some(freed))` where one went, the
    /// bytes its partial's unlink freed — none where a finish's rename had
    /// already taken the partial. `Ok(None)` where no record is held by that
    /// identifier — an end, a finish or an earlier pass took it — or where it
    /// stands at `now_ms`, left as it is, so a clock moved between the read
    /// and the act costs a standing upload nothing.
    ///
    /// # Errors
    ///
    /// A failure removing the partial leaves the record standing, expired,
    /// for the next pass to take again; one writing the retirement leaves it
    /// retired in this process, its record's line on disk until the next
    /// open's reconciliation retires it.
    pub fn expire_upload(&self, id: &UploadId, now_ms: u64) -> io::Result<Option<u64>> {
        let designation = {
            let uploads = self.uploads.lock();
            match uploads.of_any_principal(id) {
                Some(r) if !r.stands(now_ms) => r.designation.clone(),
                _ => return Ok(None),
            }
        };
        let freed = partials::remove(&self.root, &designation, id)?;
        self.uploads.lock().retire(id)?;
        Ok(Some(freed))
    }

    // ── the leases ───────────────────────────────────────────────────────

    /// Returns the principal's lease state on the hash at `now_ms`.
    ///
    /// It is the binding's read (Op inventory 2, "they read in one order, the
    /// principal's own record first") of `<designation>/<hex>` — read off the
    /// principal's own record and never off the file, so
    /// [`LeaseState::Live`] says nothing of the file (see there).
    pub fn lease_state(&self, principal: &str, designation: &str, hex: &str, now_ms: u64) -> LeaseState {
        self.leases.lock().state(principal, designation, hex, now_ms)
    }

    /// Returns the principal's live leases: the deposit read's list.
    ///
    /// They are those live at `now_ms`, in designation order and in hex order
    /// within one, read off the principal's own leases and never every lease
    /// held. A lease lapsed within the horizon, which [`Store::lease_state`]
    /// answers as lapsed, is not among them.
    pub fn live_leases_of(&self, principal: &str, now_ms: u64) -> Vec<Lease> {
        self.leases.lock().live_of(principal, now_ms)
    }

    /// Returns whether any principal holds a live lease on the hash.
    ///
    /// The hash is `<designation>/<hex>`, the moment `now_ms`: the pruner's
    /// read beside the per-principal [`Store::lease_state`] — a file any
    /// principal holds live is kept, whoever deposited it. A range of the
    /// lease map, costing that hash's holders and never every lease, so the
    /// pass that reads it once per file under its caller's exclusive arm is
    /// linear in its files.
    pub fn any_live_lease(&self, designation: &str, hex: &str, now_ms: u64) -> bool {
        self.leases.lock().any_live(designation, hex, now_ms)
    }

    /// Returns the principal's pending bytes at `now_ms` (M-I6 (b)).
    ///
    /// In Op inventory 1's words, "the own scope being the base plus that
    /// principal's pending bytes": the sizes of its unplaced deposits — its
    /// live leases on hashes none of its own cells names — plus its standing
    /// uploads' bytes received. Which deposits are unplaced is a fact of
    /// cells, and this store reads none: `unplaced` answers it for each live
    /// lease — the daemon off its cell index; a caller with no cells, `true`.
    ///
    /// **What it reads.** The principal's own leases, by the lease map's index
    /// by principal — `unplaced` runs once per live lease of its own and never
    /// for another principal's — so the daemon's read, made once per 64 KiB
    /// chunk of each upload as the own scope is re-checked (M-I6 (e)), costs
    /// that principal's deposits and never the board's; then every upload
    /// record held, each retired by its upload's finish, its end or the
    /// pruner's expiry.
    ///
    /// **Precondition.** `unplaced` runs with the lease log locked, so it
    /// must not call back into this store, where a read of the leases would
    /// wait on that lock for good — a rule no type here checks.
    ///
    /// **Two reads, not a snapshot.** The leases are read, then the upload
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

    /// Returns every principal's pending bytes at `now_ms`, summed.
    ///
    /// It is the record-derived part of the venue total, to which the daemon
    /// adds every base (M-I6 (f)); `unplaced` answers, and runs, as it does
    /// for [`Store::pending_bytes`], and the figure is two reads as that one
    /// is, any principal's concurrent finish counted twice or not at all. A
    /// sum over the board, it walks every lease and every upload record held.
    pub fn pending_total(&self, now_ms: u64, unplaced: impl FnMut(&Lease) -> bool) -> u64 {
        let unplaced_bytes = self.leases.lock().unplaced_total(now_ms, unplaced);
        let received = self.uploads.lock().received_total(now_ms);
        unplaced_bytes.saturating_add(received)
    }

    // ── the hazard seam ──────────────────────────────────────────────────

    /// Runs the seam's hook before a finish's step: a no-op in this build.
    ///
    /// A build without `test-hooks` has no hold and no injected failure. With
    /// the feature, the hook is the test seam's (`store/hooks.rs`).
    ///
    /// # Errors
    ///
    /// None: this build's hook answers `Ok`.
    #[cfg(not(feature = "test-hooks"))]
    #[inline]
    fn before(&self, _step: Step) -> io::Result<()> {
        Ok(())
    }
}

/// The four stores as they stand, as [`Store::inspect`] answers them.
///
/// It holds the upload records and the leases the logs hold, folded to
/// their latest lines and never reconciled, expired, lapsed or compacted;
/// and the listings of the directory on demand. Every read here is a read
/// and nothing else: no file is created, cut, renamed or synced through it.
#[derive(Debug)]
pub struct Inspection {
    root: PathBuf,
    uploads: Vec<UploadRecord>,
    uploads_log: LogRead,
    leases: Vec<Lease>,
    leases_log: LogRead,
}

impl Inspection {
    /// Returns the root inspected.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns every designation directory under the root.
    ///
    /// It lists them as [`Store::designation_dirs`] does.
    ///
    /// # Errors
    ///
    /// The root's listing failing, named (`list`).
    pub fn designation_dirs(&self) -> io::Result<Vec<String>> {
        blobs::dirs_under(&self.root)
    }

    /// Returns the files at hex names in `<designation>/`.
    ///
    /// It lists them as [`Store::blobs_of`] does.
    ///
    /// # Errors
    ///
    /// The directory's listing failing, save for its absence, named (`list`).
    pub fn blobs_of(&self, designation: &str) -> io::Result<Vec<String>> {
        blobs::names_in(&self.root, designation, |name, kind| hex_ok(name) && kind.is_file())
    }

    /// Returns the aside names in `<designation>/`.
    ///
    /// It lists them as [`Store::asides_of`] does.
    ///
    /// # Errors
    ///
    /// The directory's listing failing, save for its absence, named (`list`).
    pub fn asides_of(&self, designation: &str) -> io::Result<Vec<String>> {
        blobs::names_in(&self.root, designation, |name, _| is_aside_name(name))
    }

    /// Returns the identifiers the partials in `<designation>/` spell.
    ///
    /// They come in name order — a standing upload's, an expired one's, or
    /// an orphan's that no record names.
    ///
    /// # Errors
    ///
    /// The directory's listing failing, save for its absence, named (`list`).
    pub fn partials_of(&self, designation: &str) -> io::Result<Vec<UploadId>> {
        let names = blobs::names_in(&self.root, designation, |name, kind| {
            kind.is_file() && partials::id_of_partial_name(name).is_some()
        })?;
        Ok(names.iter().filter_map(|name| partials::id_of_partial_name(name)).collect())
    }

    /// Returns every upload record the log holds, folded to its latest line.
    ///
    /// They are never reconciled: standing and expired alike, in identifier
    /// order. Which stand at a moment is the reader's to judge
    /// ([`UploadRecord::expires`]).
    pub fn uploads(&self) -> &[UploadRecord] {
        &self.uploads
    }

    /// Returns every lease the log holds, each principal's latest on a hash.
    ///
    /// No horizon is applied: live and lapsed alike. Which are live at a
    /// moment is the reader's to judge ([`Lease::expires`]).
    pub fn leases(&self) -> &[Lease] {
        &self.leases
    }

    /// Returns what each log's reading found, as `(uploads, leases)`.
    ///
    /// It reads as an open would find them ([`LogRead`]): the whole lines
    /// trusted, where trust ends short of the file's end — the cut an open
    /// would make, made nowhere here — and the lines that read as no record.
    /// A copy is proved whole where both logs stand, neither cut takes whole
    /// lines past its first untrusted one and no line reads as nothing; a
    /// half-written tail alone — a live copy taken mid-append — loses nothing
    /// an answer was given over.
    pub fn logs(&self) -> (&LogRead, &LogRead) {
        (&self.uploads_log, &self.leases_log)
    }

    /// Returns the path a blob of `designation` and `hex` has.
    ///
    /// It answers as [`Store::blob_path`] does.
    pub fn blob_path(&self, designation: &str, hex: &str) -> Option<PathBuf> {
        blobs::blob_path(&self.root, designation, hex)
    }

    /// Returns the size of the file at `<designation>/<hex>`.
    ///
    /// It answers as [`Store::blob_size`] does: `Ok(None)` where none stands.
    ///
    /// # Errors
    ///
    /// An I/O failure is answered, the file named (`stat`).
    pub fn blob_size(&self, designation: &str, hex: &str) -> io::Result<Option<u64>> {
        let Some(path) = self.blob_path(designation, hex) else {
            return Ok(None);
        };
        size_of(&path)
    }
}

/// Returns the size of the file at a blob's path: the size check's one read.
///
/// `Ok(Some(size))` where a file stands, `Ok(None)` where none does — no
/// entry, or an entry that is no file.
///
/// # Errors
///
/// Any other failure is answered, the file named (`stat`).
fn size_of(path: &Path) -> io::Result<Option<u64>> {
    let meta = not_found_as_none(fs::metadata(path)).map_err(|e| named(e, label(path, 3), "stat"))?;
    Ok(meta.filter(fs::Metadata::is_file).map(|m| m.len()))
}

/// Returns the board's own directory, the root's parent.
///
/// It is the directory whose fsync alone makes the root's own entry durable
/// ([`Store::open`], [`Store::install_file`]); `.` where the root is named
/// alone.
fn board_of(root: &Path) -> &Path {
    root.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

/// Makes `dir` where absent, and never its parent.
///
/// It is made owner-only (`blobs::dir_builder`) — the pull's one way to make
/// a directory ([`Store::install_file`]), so a board's own directory that
/// does not stand is never made under a mistyped path.
///
/// # Errors
///
/// The creation failing, save where a directory already stands at `dir`.
fn make_dir(dir: &Path) -> io::Result<()> {
    match blobs::dir_builder().create(dir) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        made => made,
    }
}

/// The pull's copy buffer: 64 KiB, on the stack.
///
/// The bytes of the pull's source are read, hashed and written through it
/// ([`Store::install_file`]), so the copy holds at most this much of the
/// file at once, whatever the file's size. It bounds that memory alone —
/// nothing on disk depends on it, and a build that moves it reads and
/// writes every file an older build did — and it is no twin of the
/// daemon's streaming chunk, `BLOB_CHUNK` (skepd's `limits.rs`), the same
/// figure by no relation. A pin, moved by a design decision.
const PULL_BUFFER: usize = 64 * 1024;

/// An upload open for one request, as [`Store::resume`] answers it.
///
/// It is "the stream" of the resumable upload's clause (5), "a stream claims
/// its upload first": the partial's handle, opened afresh at the record's
/// offset with the hash of its bytes so far, and the figures the request's
/// acts need. The request appends through it and ends it by
/// [`Stream::settle`] or [`Stream::finish`], each consuming it, or, cut
/// short, drops it; the partial's file closes with it whatever the
/// request's end — so no file stays open for an upload no request is
/// streaming, nor past a finish whose rename made the partial's file the
/// hash's. A write or a sync that fails tears it: it takes no further write
/// or sync, so a later act that reaches one answers `Io` — an append past
/// its `NoUpload` and `Length` checks, a settle with bytes past its durable
/// point to receive, a finish past its `NoUpload` and its precondition —
/// and the next resume cuts off whatever the failure left. A failed write
/// counts none of its bytes, so a stream torn by one, with nothing counted
/// past its durable point, settles as a stream that wrote nothing: the
/// record answered as it stands.
pub struct Stream<'s> {
    store: &'s Store,
    principal: String,
    id: UploadId,
    designation: String,
    length: u64,
    /// The record's offset as this stream has marked it: its durable point.
    ///
    /// It is its resume's, then each grain's and its settle's, moved only to
    /// its own bytes written, so it never passes them, whatever another
    /// stream did.
    offset: u64,
    handle: Handle,
}

impl std::fmt::Debug for Stream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream").field("id", &self.id).field("offset", &self.offset).finish_non_exhaustive()
    }
}

impl Stream<'_> {
    /// Appends `bytes`, written and hashed, durable at every [`SYNC_GRAIN`].
    ///
    /// At each grain the record's offset is then written, its expiry re-fixed
    /// the upload's own interval past `now_ms`. Answers the bytes written so
    /// far (the partial's length).
    ///
    /// # Errors
    ///
    /// The refusals, in the order they are judged: `NoUpload` where the
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
    /// the settle to write; and where the record was retired since the first
    /// judgment, the grain's mark answers `NoUpload`.
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

    /// Settles the upload at the request's end (clause (3)).
    ///
    /// The stream is consumed whatever it answers: the partial fsynced, the
    /// record's offset set to the bytes written and its expiry re-fixed the
    /// upload's own interval past `now_ms`, this last byte received — and
    /// moved by nothing else: a stream with no byte counted past its durable
    /// point syncs nothing, writes no record and re-fixes nothing. Answers the
    /// record — the one its receive wrote, or, where it received nothing, the
    /// one it found standing: the upload is judged standing once, before
    /// anything is received, so no answer is `NoUpload` over bytes this
    /// settle has received, whatever expiry their mark fixed.
    ///
    /// # Errors
    ///
    /// The refusals, in the order they are judged: `NoUpload` where the
    /// upload does not stand at `now_ms` — expired, or retired under the
    /// stream; then `Io` where bytes past the durable point cannot be
    /// received — the stream torn, the sync failed, the record write failed
    /// — or `NoUpload` from the mark, where the record was retired between
    /// the two. In each case nothing past the durable point is received, and
    /// the record stands as it was.
    pub fn settle(mut self, now_ms: u64) -> Result<UploadRecord, BlobError> {
        let record = self.store.upload(&self.principal, &self.id, now_ms).ok_or(BlobError::NoUpload)?;
        if self.handle.written() == self.offset {
            return Ok(record);
        }
        self.receive(now_ms)
    }

    /// Makes the bytes written received (clause (3)).
    ///
    /// The partial is synced, then the record's offset set to them and its
    /// expiry re-fixed: the one act a grain and the settle share. Answers the
    /// record written.
    ///
    /// # Errors
    ///
    /// The sync's failure, which tears the stream, or the mark's refusal
    /// (`UploadRecords::mark_received`): `NoUpload` or `Io`.
    fn receive(&mut self, now_ms: u64) -> Result<UploadRecord, BlobError> {
        self.handle.sync()?;
        let record =
            self.store.uploads.lock().mark_received(&self.principal, &self.id, self.handle.written(), now_ms)?;
        self.offset = self.handle.written();
        Ok(record)
    }

    /// Finishes the upload (clause (7); M-I5 (a)), consuming the stream.
    ///
    /// The stream is consumed whatever the finish answers. The partial is
    /// fsynced; where `<designation>/<hex>` already holds a file, that file
    /// is linked aside — a second name, `.retired-<hex>-<n>`, so the rename
    /// below frees no blocks; the partial is renamed onto
    /// `<designation>/<hex>` — replace where the name exists — the
    /// designation directory fsynced, the root fsynced where no root fsync
    /// since the open has made the directory's entry durable, the lease for
    /// the upload's principal on the hash appended and synced with an expiry
    /// `interval` past `now_ms`, the record retired, and the aside queued for
    /// the deferred unlink. Answers the file's designation, hex and size —
    /// one shape whether or not the file was already here, and in one time:
    /// the replaced instance's unlink waits for [`Store::unlink_asides`],
    /// after the answer, and a finish that fails past its link queues
    /// nothing, leaving its aside to the pruner's pass and to open.
    ///
    /// The stream is consumed whatever the finish answers: past the rename
    /// its file is the hash's, and it closes with the stream. The store's
    /// finish lock is held from the first act to the answer, so finishes run
    /// one at a time and two of one hash never interleave the replace's
    /// check, link and rename. A request whose bytes a settle already
    /// received finishes through a stream resumed at the length.
    ///
    /// **The caller's exclusion around a finish.** Hold, around the whole
    /// call, a lock that keeps [`Store::unlink_blob`], [`Store::rename_aside`]
    /// and [`Store::remove_aside`] out. An unlink or a rename aside between
    /// the rename and the lease's sync leaves a lease naming bytes that are
    /// not there. One between the replace's check and its link fails the
    /// link, an I/O error a create never meets — a second way of saying the
    /// file was here. An aside removed between its link and the rename lets
    /// the rename free the replaced instance inside the answer. The store
    /// sees no lock of its caller's and checks none of this; the daemon keeps
    /// it with its credential lock, the finish under the read arm, and the
    /// pruner's rename aside and its removal of a leftover aside under the
    /// write arm — the aside of its own rename aside it removes under none.
    ///
    /// # Errors
    ///
    /// `NoUpload` — the upload expired or retired under the stream — is
    /// judged first, before the precondition.
    ///
    /// **What an `Io` leaves, by where it falls.** A log that has stopped
    /// refuses the finish before its first act — `{log} takes no append
    /// until a compaction completes: {cause}`, the refusal the lease's
    /// append or the retirement's would meet past the rename, judged ahead
    /// and counted with the stop's refused appends — so a stop strands no
    /// upload: it stands over its partial at its record's offset, and the
    /// finish after a compaction lifts the stop completes it. Before the
    /// rename, likewise, the upload stands over its partial at its record's
    /// offset, to be resumed there and finished; past the rename and before
    /// the lease's sync, the file stands with no lease, unreferenced and
    /// prunable, and the record stands in this process over a partial the
    /// rename took — a resume answers `Io`, naming the act that ends it, the
    /// upload's end and a PUT of its bytes again — until the upload is
    /// ended, expires, or the next open retires it; past the lease's sync,
    /// the deposit is made though the finish answered an error, and what of
    /// the record's retirement did not complete, the next open completes —
    /// its reconciliation retires a record whose partial is gone. A log that
    /// stops after the finish's judgment of it, while the finish runs, is
    /// met where its append falls, as any other failure there is.
    ///
    /// # Panics
    ///
    /// Its precondition is that the stream's bytes written reach the
    /// upload's declared length — which panics rather than being refused: a
    /// caller's bug, not an outcome. The caller knows the figure — the offset
    /// it resumed at and [`Stream::append`]'s answers, an append whose `Io`
    /// came from its grain counting its bytes all the same (see there) — and
    /// the store asserts it here, in one place, because a finish past it
    /// would name the file by its prefix's hash and lease it at a size the
    /// file does not have.
    pub fn finish(mut self, interval: Duration, now_ms: u64) -> Result<Finished, BlobError> {
        let store = self.store;
        // Held to the answer: the finishes run one at a time, and the state
        // they keep is read and moved under it.
        let mut finishing = store.finishing.lock();
        store.uploads.lock().standing(&self.principal, &self.id, now_ms).ok_or(BlobError::NoUpload)?;
        assert!(
            self.handle.written() == self.length,
            "a finish at {} of its {} bytes: the caller finishes an upload only where its bytes written reach its \
             declared length (Stream::finish's precondition, clause (7))",
            self.handle.written(),
            self.length,
        );
        // A stopped log, judged before the first act: its refusal of the
        // lease's append, or of the retirement's, is certain, and met past
        // the rename it would leave the upload over no partial, or answer
        // `blob_io` over a deposit made. Met here, the upload stands over its
        // partial at its record's offset for the finish after the stop lifts.
        store.leases.lock().refuse_if_stopped()?;
        store.uploads.lock().refuse_if_stopped()?;
        let dir = store.root.join(&self.designation);
        // Each step's failure is named as the act's own would be — the
        // hazard seam's injected one among them, save at the lease's and the
        // retirement's steps — and the link and the rename both as the
        // install of the hash's file, never by the aside: a client reads this
        // text in `blob_io`'s detail, and an aside named there would say the
        // file was already here (`media.md` Op inventory 1, "no answer of the
        // upload says whether the file was already here").
        store.before(Step::PartialSync).map_err(|e| named(e, partial_label(&dir), "sync"))?;
        self.handle.sync()?;
        let hex = self.handle.hash().to_hex().to_string();
        let from = partials::partial_path(&store.root, &self.designation, &self.id);
        let to = dir.join(&hex);
        let install = |e| named(e, label(&to, 3), "install");
        let aside = if to.is_file() {
            // The replace: the replaced instance keeps a name through the
            // rename, so the rename frees nothing; the aside is unlinked after
            // the answer. A link, not a rename aside: the hash is never
            // without a file, whatever fails next.
            store.before(Step::LinkAside).map_err(install)?;
            let n = finishing.aside_serial;
            finishing.aside_serial += 1;
            let aside = dir.join(aside_name(&hex, n));
            fs::hard_link(&to, &aside).map_err(install)?;
            Some(aside)
        } else {
            None
        };
        store.before(Step::Rename).and_then(|()| fs::rename(&from, &to)).map_err(install)?;
        store
            .before(Step::DirSync)
            .and_then(|()| fsync_dir(&dir))
            .map_err(|e| named(e, dir_label(&dir, 2), "fsync"))?;
        if !finishing.root_synced.contains(&self.designation) {
            store
                .before(Step::RootSync)
                .and_then(|()| fsync_dir(&store.root))
                .map_err(|e| named(e, dir_label(&store.root, 1), "fsync"))?;
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
        // Queued only now, the finish answering: the queue is drained on
        // whichever thread asks (the daemon's transport, after every reply of
        // the `/blob/upload` family), and a deferred unlink that took this
        // aside before the rename would leave the replaced instance one link
        // for the rename to free inside this answer. A finish that fails after
        // its link leaves its aside to the pruner's pass and to open.
        if let Some(aside) = aside {
            store.aside_queue.lock().push(aside);
        }
        Ok(Finished { designation: self.designation, hex, size: self.length })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An append measures its grain from its own stream's offset.
    ///
    /// It does so whatever the record says: two streams of one upload — what
    /// a caller that does not keep one stream of an upload at a time
    /// (`Store`) can reach — the first settling after the second's resume cut
    /// the partial back, so the record stands ahead of the second's bytes:
    /// the second's append answers, neither panicking nor wrapping, writing
    /// no record, and its settle sets the record to the bytes it holds.
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
