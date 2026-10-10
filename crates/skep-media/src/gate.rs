//! THE GATE (media lane B; `media.md` Op inventory 1 — "WHAT THE QUOTA
//! COUNTS", "THE OWN SCOPE BEING THE BASE PLUS THAT PRINCIPAL's PENDING
//! BYTES", "A LIMIT ON THE VENUE's TOTAL IS ENFORCED ONLY AS THE BODY IS
//! WRITTEN", "AND THE BLOB STORE NEVER TAKES THE JOURNAL's LAST BYTES";
//! §Recovery, the limits record; the register M-I6 (a), (b), (e), (f);
//! M-I2 (e)): the daemon's media resource — the blob store opened under
//! `blobs/` in the data dir, the limits in force, the hold a stream has on
//! its upload, and the three scopes a PUT is refused on — and THE BINDING
//! the write door asks for a cell: is this hash this principal's, under a
//! live lease, and is the file whole?
//!
//! THE THREE SCOPES, in the order they are read — the requester's own
//! record first (M-I2 (e)): THE OWN SCOPE, the principal's BASE plus its
//! PENDING BYTES, against the per-account limit (M-I6 (b)) — the base the
//! cell index's number for the account, the sum of the distinct hashes its
//! cells name at their size (M-I6 (a)); the pending bytes its live leases
//! on hashes none of its cells names, plus its standing uploads' bytes
//! received — refused on the declared total BEFORE the body and re-checked
//! as the body is written; THE VENUE TOTAL, the sum of every account's own
//! scope — every base, every pending — record-derived and never the
//! directory's bytes, enforced ONLY as the body is written (a pre-body
//! yes-or-no would show the board-wide figure free of charge; as written,
//! its refusal's offset is that figure PRICED at the headroom's transfer —
//! ms4-E1, accepted and named); THE FLOOR, the volume's free space held
//! above the floor IN FORCE — the larger of the constant `FLOOR_BYTES`
//! and twice the newest checkpoint's size plus one maximal segment, re-read
//! as each checkpoint lands ([`MediaGate::floor_in_force`]) — so a deposit
//! never takes the journal's last bytes, read off the host and showing no
//! figure — AT THE CREATION, on no declared length, before the partial and
//! the record, and per chunk as the body is written
//! ([`MediaGate::admit_creation`], [`MediaGate::admit_bytes`]; M-I5 (f):
//! every record, lease and retirement the store appends descends from a
//! creation or a body byte the floor admitted). Beside the own
//! scope, THE STANDING-UPLOADS BOUND ([`MediaGate::admit_creation`]; the
//! wire's fourth scope, `standing`): a principal holds at most
//! `MAX_STANDING_UPLOADS` standing uploads, counted off its own records, a
//! creation past it refused before its partial and its record, its face
//! naming the end of one of them (P13, P29). The own scope and the venue
//! total read the base, so the creation and the resume are two of the
//! index's three readers: refused `index_rebuilding` until the walk at open
//! completes (ms5-R).
//!
//! THE BINDING reads THE INDEX FIRST (`MediaGate::binding`): a hash the
//! requester's own cells already name is a REFERENCE, kept by no lease —
//! admitted where the file is on disk whole at the cell's size, the deposit
//! gone where it is not — and only then the lease arm. Until the walk
//! completes the index arm is skipped and the lease arm alone ADMITS: the
//! door is not one of the three readers and never waits (ms5-R, "for
//! nothing else"); and where that arm alone would REFUSE, the answer is
//! `Binding::Rebuilding` — the index arm it has not read may admit the
//! cell — which the door answers RETRY-CLASS, as the readiness refusal
//! does, and never a permanent token. Where the walk DIED instead
//! (`CellIndex::is_failed`; `operations.md` §4 row 26) no index arm is
//! coming, and the lease arm's verdict stands as FINAL — `Lapsed`,
//! `Unbound` — honest where no wait can succeed; the re-PUT that would
//! cure a lapse is the family's to refuse, `index_failed`.
//!
//! THE LIMITS IN FORCE ([`Limits`]; the register M-I6 (b), (d)): A
//! PER-ACCOUNT LIMIT IS ALWAYS IN FORCE. THE DAEMON's DEFAULT (the owner's
//! ruling; `media.md` Op inventory 1, "UPLOADS ARE OPEN BY DEFAULT, WITH A
//! DEFAULT PER-ACCOUNT LIMIT IN FORCE FROM START") is ONE EIGHTH OF THE
//! VOLUME's CAPACITY, read once at the open off the same `statvfs` the
//! floor reads ([`skep_blobs::Store::capacity`]) and never below 256 MiB —
//! `DEFAULT_LIMIT_SHARE`, `DEFAULT_LIMIT_FLOOR_BYTES` (D1) — the whole
//! default being the floor on a host that cannot answer its capacity; the
//! venue total UNSET; the lease interval `LEASE_INTERVAL_DEFAULT_MS`; the
//! per-file cap `MAX_BLOB_BYTES`; no address. The deposit read ECHOES the
//! limit in force as `per_account`, whatever its source, beside the
//! record's address or `null` (P37: a boundary setting is echoed for the
//! faces that key on it; R68's read-before-refusal holds under the
//! default). THE LIMITS RECORD (§Recovery: "ONE published, attributed,
//! supersedable record … installed in the daemon by the serving layer as
//! AUTH-4.70's list is") — its kind, schema and install channel AUTH's
//! docket's (RES-208), OWED — OVERRIDES the default WHOLE through the
//! INSTALL HOOK (`MediaGate::install_limits`, compiled under `test-hooks`
//! until that channel lands) the serving layer's channel will call; the
//! startup log names the record in force, or the default and its source.
//!
//! THE UPLOAD SETTING ([`crate::MediaOptions`]) rides here as the
//! resource's configuration — the switch the routes read
//! ([`MediaGate::uploads_open`]) and `/health` echoes ([`MediaGate::health_object`]).
//!
//! THE LEASE INTERVAL and ITS HORIZON (Op inventory 1, "THE INTERVAL HAS A
//! DEFAULT, A GATE CONSTANT OF THE DAEMON's"; "a lease lapsed past a
//! HORIZON … answers as no lease") are the two constants below, INTERIM
//! pins (sm-Q8), handed to the store at open.

use std::collections::HashSet;
use std::io;
use std::path::Path;
#[cfg(any(test, feature = "test-hooks"))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde_json::Value;
use skep_blobs::{Lease, LeaseState, Store, UploadId, UploadRecord};
use skep_kernel::MAX_SEGMENT_LEN;
use skep_namespace::PrincipalId;
use skep_util::json::{hex_string, obj};
#[cfg(any(test, feature = "test-hooks"))]
use skep_util::notice;

use crate::cell::{Cell, DESIGNATION};
use crate::index::CellIndex;
use crate::limits::{
    DEFAULT_LIMIT_FLOOR_BYTES, DEFAULT_LIMIT_SHARE, MAX_BLOB_BYTES, MAX_STANDING_UPLOADS,
};
use crate::MediaOptions;

/// THE LEASE INTERVAL's DAEMON DEFAULT — seven days, INTERIM: an upload
/// plus an authoring interval below it, what a venue will hold unreferenced
/// above; a limits record may move it within those bounds, and it stands
/// wherever none sets one, so a venue that publishes no limits has no quota
/// and never no reclamation. The upload's expiry interval is this too.
const LEASE_INTERVAL_DEFAULT_MS: u64 = 7 * 24 * 3600 * 1000;

/// THE HORIZON — thirty days past a lease's expiry, INTERIM: within it a
/// lapsed lease answers LAPSED (the deposit is gone; re-PUT the bytes — a
/// resume can be written against it), past it NONE, and the lease log
/// compacts it away at open.
const LEASE_HORIZON_MS: u64 = 30 * 24 * 3600 * 1000;

/// THE FLOOR's CONSTANT HALF — 256 MiB of the volume's free space, INTERIM
/// (`media.md` Op inventory 1, "THE LARGER OF 256 MiB AND TWICE THE NEWEST
/// CHECKPOINT's SIZE PLUS ONE MAXIMAL SEGMENT"; the register M-I5 (f)): the
/// least room the journal's next segments and checkpoints are kept, which
/// no deposit may take. THE FLOOR IN FORCE is the larger of this and the
/// scaling half — twice the newest checkpoint's size plus one maximal
/// segment ([`MAX_SEGMENT_LEN`]) — re-read as each checkpoint lands
/// ([`MediaGate::floor_in_force`]; the daemon's checkpoint thread sets it
/// through [`MediaGate::set_floor`], and the open reads it once off the
/// newest checkpoint on disk): a checkpoint is written WHOLE beside the two
/// retained before the oldest is pruned, and the segment in flight is
/// written beside it. A PUT is refused at its creation where the free space
/// already stands below the floor in force, and as its body is written once
/// a chunk would take the volume below it. The floor reads the host and
/// shows no figure (M-I6 (h)).
///
/// THE GUARANTEE's CONDITION: the floor holds the journal writable THROUGH
/// ITS NEXT CHECKPOINT only beside a cadence that bounds the journal's BYTES
/// between checkpoints — the daemon's, at a quarter of the newest checkpoint
/// and no less than 24 MiB (`server.rs`'s `CHECKPOINT_BYTES_SHARE` and
/// `CHECKPOINT_BYTES_FLOOR`), with ONE WINDOW OF GRACE: the cadence is
/// deferred to the checkpoint thread, and a second crossing before the
/// thread has serviced the first runs inline as the backstop, so the journal
/// between two checkpoints is at most two windows. Below the crossover
/// (a checkpoint under ~64 MiB, where the constant half is the larger)
/// the constant covers the next checkpoint, two windows and a segment with
/// room; above it the scaling half does.
const FLOOR_BYTES: u64 = 256 * 1024 * 1024;

/// The limits in force: the venue's record, or the daemon's defaults where
/// none is installed (`Limits::defaults_for`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The per-account limit on the own scope — the daemon's default, or
    /// the record's. `None` binds nothing: a written record's own say, never
    /// the daemon's default (M-I6 (b): a per-account limit is always in
    /// force where none is installed).
    pub per_account: Option<u64>,
    /// The venue's total over every account's own scope; `None` binds
    /// nothing — the default.
    pub venue_total: Option<u64>,
    /// The lease interval and the upload's expiry interval.
    pub lease_interval_ms: u64,
    /// The per-file cap, at or below the route's own.
    pub per_file_cap: u64,
    /// The record's address as installed, echoed by the deposit read;
    /// `None` where no record is installed.
    pub address: Option<String>,
}

impl Limits {
    /// THE DAEMON's DEFAULTS, for a volume of `capacity` bytes (`None`: a
    /// host that could not answer its capacity): the per-account limit one
    /// eighth of the capacity and never below 256 MiB — the floor alone
    /// where the host answered nothing — the venue total unset, the lease
    /// interval and the per-file cap the daemon's, no address.
    fn defaults_for(capacity: Option<u64>) -> Limits {
        let share = capacity.map_or(0, |c| c / DEFAULT_LIMIT_SHARE);
        Limits {
            per_account: Some(share.max(DEFAULT_LIMIT_FLOOR_BYTES)),
            venue_total: None,
            lease_interval_ms: LEASE_INTERVAL_DEFAULT_MS,
            per_file_cap: MAX_BLOB_BYTES,
            address: None,
        }
    }

    /// The line the startup log names the limits in force by: the record,
    /// or the default and its source — the capacity read, or the floor on a
    /// host that answered none.
    fn log_line(&self, capacity: Option<u64>) -> String {
        let scope = |v: Option<u64>| v.map_or("none".to_string(), |n| n.to_string());
        match &self.address {
            Some(a) => format!(
                "media limits in force: record {a} — per-account {}, venue total {}, lease \
                 interval {} ms, per-file cap {}",
                scope(self.per_account),
                scope(self.venue_total),
                self.lease_interval_ms,
                self.per_file_cap
            ),
            None => {
                let source = match capacity {
                    Some(c) => format!(
                        "one eighth of the volume's capacity of {c} bytes, never below {} bytes",
                        DEFAULT_LIMIT_FLOOR_BYTES
                    ),
                    None => format!(
                        "the {} byte floor alone, the host answering no capacity",
                        DEFAULT_LIMIT_FLOOR_BYTES
                    ),
                };
                format!(
                    "media limits: no record installed — the daemon's default stands: per-account \
                     {} ({source}), venue total none, lease interval {} ms, per-file cap {}",
                    scope(self.per_account),
                    self.lease_interval_ms,
                    self.per_file_cap
                )
            }
        }
    }
}

/// The scope a deposit was refused on — what the refusal names, and
/// nothing of the headroom (M-I6 (h)). Named for the deposit it refuses,
/// apart from the session's own scope (AUTH-4.39, `auth::session::Scope`),
/// which limits what a session may deposit at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositScope {
    /// The principal's own scope: its pending bytes against the per-account
    /// limit.
    Own,
    /// The venue's total.
    Venue,
    /// The host's floor.
    Floor,
    /// The principal's standing uploads, at the bound — an addition to the
    /// armed set (P6), answered at the creation alone.
    Standing,
}

impl DepositScope {
    /// The wire's token.
    pub fn token(self) -> &'static str {
        match self {
            DepositScope::Own => "own",
            DepositScope::Venue => "venue",
            DepositScope::Floor => "floor",
            DepositScope::Standing => "standing",
        }
    }
}

/// THE BINDING's answer for a cell (Op inventory 2, "THEY READ IN ONE
/// ORDER, THE PRINCIPAL's OWN RECORD FIRST"; "A LIVE LEASE OVER A FILE
/// THAT IS NOT THERE READS AS LAPSED").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Binding {
    /// The principal's own cells already name the hash and the file is there
    /// whole at the cell's size — a reference, kept by no lease; or the
    /// principal holds a live lease on the hash, the file is there at the
    /// lease's size, and the cell's `size` is that length.
    Admitted,
    /// The principal's cells name the hash and the file is not there or not
    /// whole at the cell's size; or its lease on the hash has lapsed within
    /// the horizon, or is live over a file that is not there or not whole:
    /// the deposit is gone, the act a re-PUT.
    Lapsed,
    /// The principal's cells name the hash not, and it holds no lease on it
    /// — never deposited, lapsed past the horizon, or another's — or holds
    /// one whose size the cell contradicts: no deposit of this principal's
    /// is the cell as written.
    Unbound,
    /// THE REBUILD WINDOW's ANSWER (ms5-R): the index's walk at open has not
    /// completed, and the lease arm alone would answer [`Binding::Lapsed`] or
    /// [`Binding::Unbound`] — the index arm it has not read may admit the
    /// cell (a hash the principal's own cells name, its file whole), so the
    /// state is answered retry-class and never a permanent token. A cell the
    /// lease arm admits in the rebuild window is admitted as it is at any
    /// time. A window that ENDS: where the walk DIED (`operations.md` §4 row
    /// 26) the lease arm's verdict stands as final, and this is never
    /// answered.
    Rebuilding,
}

/// A stream's HOLD on one upload (clause (5)) — what [`MediaGate::claim`]
/// answers. The upload is released as this drops, on every exit of the
/// frame that holds it: a return, a `?`, an unwind. No caller ends a hold,
/// so no stream that is gone leaves one behind — the daemon a caller finds
/// after it contains a handler's panic (`Daemon::route`'s card) holds no
/// upload that panic was streaming.
#[must_use = "a hold dropped at once holds nothing: bind it for the stream's whole span"]
pub struct Hold<'a> {
    held: &'a Mutex<HashSet<UploadId>>,
    id: UploadId,
}

impl Drop for Hold<'_> {
    fn drop(&mut self) {
        self.held.lock().remove(&self.id);
    }
}

/// Whose figure a record's bytes count in — THE INVENTORY's read
/// ([`MediaGate::lease_counted`], [`MediaGate::upload_counted`]; `media.md`
/// §Recovery, "THE OPERATOR CAN LIST THE HOLES"; the register M-I6 (d)),
/// under the gate's own pending rule and its own reading of a store key, so
/// the figures the operator reads are the ones the gate refuses on and the
/// limits record is written against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counted {
    /// In the key's BASE already — the principal's own cells name the hash,
    /// which its base counts (M-I6 (b)) — and so in no pending figure. A
    /// lease's answer alone.
    Base,
    /// In this principal's PENDING bytes.
    Pending(PrincipalId),
    /// In the venue total alone, UNATTRIBUTED: the key spells no principal
    /// of this build, whose bytes no base and no account's pending holds.
    Unattributed,
}

/// The daemon's media resource.
pub struct MediaGate {
    store: Store,
    limits: RwLock<Limits>,
    /// The upload setting, as the operator supplied it.
    options: MediaOptions,
    /// The volume's capacity as read once at the open — the default limit's
    /// source, kept for the startup line; `None` where the host answered
    /// none.
    capacity: Option<u64>,
    /// THE FLOOR IN FORCE (`FLOOR_BYTES`'s card): the larger of the
    /// constant and twice the newest checkpoint's size plus one maximal
    /// segment — set at the open off the newest checkpoint on disk and by
    /// the checkpoint thread as each lands, read at every creation and every
    /// chunk. An atomic rather than a lock: one load per read, and a store
    /// that lands whole.
    floor: AtomicU64,
    /// THE HOLD (clause (5)): the uploads a stream holds right now, in
    /// skepd's memory and no store — a PUT naming one is refused while it
    /// is held. Each entry is a [`Hold`]'s, removed as that guard drops, an
    /// unwind included; `held` is locked inside [`MediaGate::claim`] and
    /// that drop alone.
    held: Mutex<HashSet<UploadId>>,
    /// THE CELL INDEX — shared with the write path, which enters it at
    /// every commit that mints a cell, and with the walk at open.
    index: Arc<CellIndex>,
    /// The test seam's clock offset, added to the wall clock.
    #[cfg(any(test, feature = "test-hooks"))]
    clock_offset_ms: AtomicU64,
    /// The test seam's free-space reading, in place of the host's.
    #[cfg(any(test, feature = "test-hooks"))]
    free_space_override: Mutex<Option<u64>>,
    /// The test seam's hold inside the pruner's pass, after an unlink.
    #[cfg(any(test, feature = "test-hooks"))]
    prune_hold: AtomicBool,
    /// The test seam's count of pruner passes completed — a suite waits for
    /// the cadence's first pass before it moves the clock.
    #[cfg(any(test, feature = "test-hooks"))]
    passes_completed: AtomicU64,
}

impl MediaGate {
    /// Open the blob store under `data_dir/blobs` — its reconciliation and
    /// compaction complete before this returns — under `options`, with the
    /// daemon's default limits in force (the volume's capacity read ONCE
    /// here, off the opened store; a host that cannot answer it leaves the
    /// default at its floor) and an EMPTY, NOT-READY cell index: the daemon
    /// hands the index to the write path and starts the walk that readies
    /// it.
    pub fn open_with(data_dir: &Path, options: MediaOptions) -> io::Result<MediaGate> {
        let now = wall_clock_ms();
        let store = Store::open(data_dir.join("blobs"), Duration::from_millis(LEASE_HORIZON_MS), now)?;
        let capacity = store.capacity().ok();
        Ok(MediaGate {
            store,
            limits: RwLock::new(Limits::defaults_for(capacity)),
            options,
            capacity,
            floor: AtomicU64::new(FLOOR_BYTES),
            held: Mutex::new(HashSet::new()),
            index: Arc::new(CellIndex::new()),
            #[cfg(any(test, feature = "test-hooks"))]
            clock_offset_ms: AtomicU64::new(0),
            #[cfg(any(test, feature = "test-hooks"))]
            free_space_override: Mutex::new(None),
            #[cfg(any(test, feature = "test-hooks"))]
            prune_hold: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-hooks"))]
            passes_completed: AtomicU64::new(0),
        })
    }

    /// [`MediaGate::open_with`] under the default options — the unit
    /// suites' open, where the setting is not what is under test.
    #[cfg(test)]
    pub(crate) fn open(data_dir: &Path) -> io::Result<MediaGate> {
        Self::open_with(data_dir, MediaOptions::default())
    }

    /// The blob store the gate opened — the door to [`skep_blobs::Store`], a
    /// public type: the routes drive an upload's acts and the deposit read's
    /// listings through it by the gate's key ([`MediaGate::key`]), the
    /// transport runs a replace's deferred unlink through it, and the
    /// daemon's hooks reach the store's hazard seam.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The cell index — the one copy the write path enters and the walk at
    /// open adds into.
    pub fn index(&self) -> &Arc<CellIndex> {
        &self.index
    }

    /// Whether the index's three readers are served: the walk at open has
    /// completed.
    pub fn index_ready(&self) -> bool {
        self.index.is_ready()
    }

    /// Whether the index's walk at open DIED (`operations.md` §4 row 26) —
    /// the FAILED state, never true beside [`MediaGate::index_ready`]: the
    /// three readers refuse `index_failed` for the life of the process, the
    /// binding answers the lease arm's verdict as final, the pruner runs no
    /// pass, and the daemon's standing line re-says it.
    pub fn index_failed(&self) -> bool {
        self.index.is_failed()
    }

    /// The limits in force.
    pub fn limits(&self) -> Limits {
        self.limits.read().clone()
    }

    /// The line the startup log names the limits in force by — the record,
    /// or the default and the capacity it was read from — and the floor in
    /// force beside them, with its two halves.
    pub fn startup_line(&self) -> String {
        format!("{}; {}", self.limits.read().log_line(self.capacity), self.floor_line())
    }

    /// THE FLOOR IN FORCE for a newest checkpoint of `newest_checkpoint_len`
    /// bytes (`None`: no checkpoint yet): the larger of `FLOOR_BYTES` and
    /// twice that size plus one maximal segment — the room the next
    /// checkpoint takes written whole beside the two retained, and the
    /// segment in flight beside it (`media.md` Op inventory 1; M-I5 (f)).
    /// Saturating: a length no volume could hold answers a floor no volume
    /// could clear, which refuses every deposit rather than admitting one
    /// the arithmetic wrapped.
    pub fn floor_in_force(newest_checkpoint_len: Option<u64>) -> u64 {
        let scaled = newest_checkpoint_len
            .map_or(0, |c| c.saturating_mul(2).saturating_add(MAX_SEGMENT_LEN));
        FLOOR_BYTES.max(scaled)
    }

    /// The floor in force, as [`MediaGate::admit_creation`] and
    /// [`MediaGate::admit_bytes`] read it.
    pub fn floor(&self) -> u64 {
        self.floor.load(Ordering::Acquire)
    }

    /// Set the floor in force — the daemon's, at the open off the newest
    /// checkpoint on disk and by the checkpoint thread as each lands
    /// ([`MediaGate::floor_in_force`] computes it). The next creation and
    /// the next chunk read it.
    pub fn set_floor(&self, bytes: u64) {
        self.floor.store(bytes, Ordering::Release);
    }

    /// The floor's half of the startup line: the floor in force and the
    /// constant it is never below.
    fn floor_line(&self) -> String {
        format!(
            "the floor in force {} bytes of the volume's free space (never below the constant {} \
             bytes; twice the newest checkpoint's size plus one maximal segment of {} bytes \
             above it, re-read as each checkpoint lands)",
            self.floor(),
            FLOOR_BYTES,
            MAX_SEGMENT_LEN
        )
    }

    /// TEST SEAM: the volume's capacity as read at the open — what the
    /// default limit was computed from, so a suite judges the echoed figure
    /// against the same read.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn capacity(&self) -> Option<u64> {
        self.capacity
    }

    /// THE UPLOAD SETTING: whether the upload family is open — the creation
    /// and the resume admitted.
    pub fn uploads_open(&self) -> bool {
        self.options.uploads
    }

    /// `/health`'s `media` object — the boundary setting's one echo (P37),
    /// built where its state lives through the codec's own key-sorting
    /// object: `{"uploads": <bool>}`.
    pub fn health_object(&self) -> Value {
        obj(vec![("uploads", Value::Bool(self.options.uploads))])
    }

    /// THE INSTALL HOOK (AUTH-4.70's channel, owed): replace the limits in
    /// force WHOLE. The per-file cap is held at or below the route's own; a
    /// record naming a larger one is installed at the route's. Compiled
    /// under `test-hooks` until the serving layer's channel lands and
    /// reached through [`MediaGate::install_limits`]: no production caller
    /// exists yet, and a shipped build carries no dead door.
    #[cfg(any(test, feature = "test-hooks"))]
    fn install(&self, mut limits: Limits) {
        limits.per_file_cap = limits.per_file_cap.min(MAX_BLOB_BYTES);
        *self.limits.write() = limits;
    }

    /// TEST HOOK (the serving layer's channel, AUTH-4.70, in a suite's hand
    /// until that channel lands; reached through
    /// `Daemon::install_media_limits`): INSTALL a limits record whole — the
    /// per-account limit, the venue's total, the lease interval (`None`
    /// keeps the daemon's default, `LEASE_INTERVAL_DEFAULT_MS`) and the
    /// record's address the deposit read echoes; the per-file cap the
    /// route's own, [`MAX_BLOB_BYTES`].
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn install_limits(
        &self,
        per_account: Option<u64>,
        venue_total: Option<u64>,
        lease_interval_ms: Option<u64>,
        address: Option<String>,
    ) {
        self.install(Limits {
            per_account,
            venue_total,
            lease_interval_ms: lease_interval_ms.unwrap_or(LEASE_INTERVAL_DEFAULT_MS),
            per_file_cap: MAX_BLOB_BYTES,
            address,
        });
    }

    /// The gate's reading of the clock, unix milliseconds — the one every
    /// expiry and lease is fixed by and judged against.
    pub fn now_ms(&self) -> u64 {
        #[cfg(any(test, feature = "test-hooks"))]
        {
            wall_clock_ms().saturating_add(self.clock_offset_ms.load(Ordering::Relaxed))
        }
        #[cfg(not(any(test, feature = "test-hooks")))]
        {
            wall_clock_ms()
        }
    }

    /// The store's opaque key for a principal: its id, decimal — the lease
    /// and the upload records are keyed to the PRINCIPAL and never the
    /// session (Op inventory 1).
    pub fn key(principal: PrincipalId) -> String {
        principal.0.to_string()
    }

    /// The principal a store key spells — [`MediaGate::key`] read back, the
    /// one spelling being this gate's own; `None` for a key no gate of this
    /// build wrote.
    fn principal_of_key(key: &str) -> Option<PrincipalId> {
        key.parse::<u64>().ok().map(PrincipalId)
    }

    /// Whether a live lease counts in its key's PENDING bytes — THE rule, the
    /// gate's own and the operator's inventory's (`tools::inventory`,
    /// through [`MediaGate::lease_counted`]) alike: not where the key's own
    /// cells name the hash, which its base already counts (M-I6 (b)); and
    /// always where the key spells no principal of this build, whose bytes
    /// no base counts.
    fn counts_as_pending(index: &CellIndex, lease: &Lease) -> bool {
        !matches!(Self::lease_counted(index, lease), Counted::Base)
    }

    /// THE INVENTORY's READ of a live lease (`tools::inventory`; `media.md`
    /// §Recovery): whose figure its bytes count in, under the gate's own
    /// pending rule and its own reading of the key — the key's BASE where
    /// that principal's own cells name the hash, its PENDING bytes
    /// otherwise, the UNATTRIBUTED bytes where the key spells no principal
    /// of this build. The one rule [`MediaGate::own_pending`] and the venue
    /// total read by, so the operator's figures are the ones the gate
    /// refuses on; the key's spelling and the rule stay this gate's.
    pub fn lease_counted(index: &CellIndex, lease: &Lease) -> Counted {
        match Self::principal_of_key(&lease.principal) {
            Some(p) if index.names(p, &lease.designation, &lease.hex) => Counted::Base,
            Some(p) => Counted::Pending(p),
            None => Counted::Unattributed,
        }
    }

    /// THE INVENTORY's READ of a standing upload: whose PENDING bytes its
    /// bytes received count in — the principal its key spells, or `None`
    /// for the unattributed bytes, a key no gate of this build wrote. Never
    /// the base: nothing names an upload's bytes before its finish.
    pub fn upload_counted(record: &UploadRecord) -> Option<PrincipalId> {
        Self::principal_of_key(&record.principal)
    }

    /// THE OWN SCOPE of `principal` at `now_ms` (M-I6 (b)): its base — the
    /// index's number — plus its pending bytes, the live leases on hashes
    /// none of its cells names and its standing uploads' bytes received.
    fn own_scope(&self, principal: PrincipalId, now_ms: u64) -> u64 {
        self.index.base(principal).saturating_add(self.own_pending(principal, now_ms))
    }

    /// `principal`'s PENDING BYTES at `now_ms` — the deposit read's second
    /// figure beside the base.
    pub fn own_pending(&self, principal: PrincipalId, now_ms: u64) -> u64 {
        let key = Self::key(principal);
        self.store.pending_bytes(&key, now_ms, |l| Self::counts_as_pending(&self.index, l))
    }

    /// THE VENUE TOTAL at `now_ms`: every account's own scope — every base and
    /// every pending — and the UNATTRIBUTED bytes beside them, a live lease's
    /// or a standing upload's whose key spells no principal of this build
    /// ([`MediaGate::counts_as_pending`]): record-derived, the figure the
    /// operator's inventory reports under the same rule.
    fn venue_total(&self, now_ms: u64) -> u64 {
        let pending = self.store.pending_total(now_ms, |l| Self::counts_as_pending(&self.index, l));
        self.index.total_base().saturating_add(pending)
    }

    /// Claim an upload for a stream (clause (5)): its [`Hold`], which
    /// releases the upload as it drops, or `None` where another stream holds
    /// it.
    #[must_use = "a hold dropped at once holds nothing"]
    pub fn claim(&self, id: UploadId) -> Option<Hold<'_>> {
        self.held.lock().insert(id).then(|| Hold { held: &self.held, id })
    }

    /// THE OWN SCOPE BEFORE THE BODY (M-I6 (e)): would the principal's own
    /// scope — its base plus its pending bytes — plus `declared` (an
    /// upload's whole length at its creation, what it leaves past the
    /// offset at a resume) pass the per-account limit? Read off the
    /// principal's own record and the index's number for its account.
    pub fn admit_declared(
        &self,
        principal: PrincipalId,
        declared: u64,
        now_ms: u64,
    ) -> Result<(), DepositScope> {
        let Some(limit) = self.limits.read().per_account else { return Ok(()) };
        if self.own_scope(principal, now_ms).saturating_add(declared) > limit {
            return Err(DepositScope::Own);
        }
        Ok(())
    }

    /// THE GATE AT THE CREATION, after the own scope's read of the declared
    /// total ([`MediaGate::admit_declared`]) and before the partial and the
    /// record (P13; M-I5 (f), M-I6 (b)): THE STANDING-UPLOADS BOUND first —
    /// the principal's own record, counted off its standing uploads — then
    /// THE FLOOR, read on no declared length: the volume's free space
    /// already below the floor in force ([`MediaGate::floor`], never the
    /// constant alone) refuses the creation that would append a record no
    /// scope counts. The resume reads neither: it creates nothing.
    pub fn admit_creation(&self, principal: PrincipalId, now_ms: u64) -> Result<(), DepositScope> {
        let key = Self::key(principal);
        if self.store.uploads_of(&key, now_ms).len() >= MAX_STANDING_UPLOADS {
            return Err(DepositScope::Standing);
        }
        if self.free_space() < self.floor() {
            return Err(DepositScope::Floor);
        }
        Ok(())
    }

    /// THE GATE AS THE BODY IS WRITTEN: would the next `n` bytes of the
    /// upload `id`, of which `written` are already in its partial, pass the
    /// own scope, the venue's total, or the floor in force — in that order?
    /// The own scope and the total count this upload at its bytes written
    /// (the record holds its durable offset, which lags by at most a grain).
    pub fn admit_bytes(
        &self,
        principal: PrincipalId,
        id: &UploadId,
        written: u64,
        n: u64,
        now_ms: u64,
    ) -> Result<(), DepositScope> {
        let limits = self.limits.read().clone();
        let key = Self::key(principal);
        let durable = self.store.upload(&key, id, now_ms).map_or(0, |r| r.offset);
        if let Some(limit) = limits.per_account {
            let own = self.own_scope(principal, now_ms).saturating_sub(durable).saturating_add(written);
            if own.saturating_add(n) > limit {
                return Err(DepositScope::Own);
            }
        }
        if let Some(limit) = limits.venue_total {
            let total = self.venue_total(now_ms).saturating_sub(durable).saturating_add(written);
            if total.saturating_add(n) > limit {
                return Err(DepositScope::Venue);
            }
        }
        if self.free_space().saturating_sub(n) < self.floor() {
            return Err(DepositScope::Floor);
        }
        Ok(())
    }

    /// THE VOLUME's FREE SPACE AS THE FLOOR READS IT — the seam's figure
    /// where `set_free_space` pinned one (a `test-hooks` build), else the
    /// host's: one `statvfs` at the store's root
    /// ([`skep_blobs::Store::free_space`]), a host that cannot answer read as
    /// having no room, so the floor refuses rather than admitting a deposit
    /// it cannot price. `pub` for ONE reader beyond the floor's two gates:
    /// the daemon's checkpoint thread, whose landing line carries the
    /// volume's free space — read through this door and never by a second
    /// read of the store, so the figure the floor refuses on and the figure
    /// the line carries are one reading's, and a suite that pins the floor's
    /// figure has pinned the line's.
    pub fn free_space(&self) -> u64 {
        #[cfg(any(test, feature = "test-hooks"))]
        if let Some(n) = *self.free_space_override.lock() {
            return n;
        }
        // A host that cannot answer is read as having no room: the floor
        // refuses rather than admitting a deposit it cannot price.
        self.store.free_space().unwrap_or(0)
    }

    /// THE BINDING (Op inventory 2): THE INDEX FIRST, where its walk has
    /// completed — a hash the principal's own cells already name is a
    /// reference, kept by no lease: admitted where the file is on disk
    /// whole at the cell's size; UNBOUND where the file is whole at the
    /// size those cells name and this cell contradicts it (the size check,
    /// the lease arm's own answer to a cell that is not the deposit as
    /// written); the deposit gone — LAPSED — where the file is absent or
    /// not whole — then the principal's own lease record, the file only
    /// where that record names the hash under a live lease. Until the walk
    /// completes the index arm is skipped — the door never waits on the
    /// index — and where the lease arm alone would refuse, the answer is
    /// `Binding::Rebuilding`: the arm not yet read may admit the cell. Where
    /// the walk DIED (`operations.md` §4 row 26) the arm not read is never
    /// coming, and the lease arm's verdict stands as final.
    pub(crate) fn binding(&self, principal: PrincipalId, cell: &Cell) -> Binding {
        let key = Self::key(principal);
        let hex = hex_string(&cell.hash);
        let ready = self.index.is_ready();
        if ready {
            if let Some(named) = self.index.size_named(principal, DESIGNATION, &hex) {
                // A size that cannot be read is read as no file: the
                // binding has no I/O answer of its own, and a deposit whose
                // bytes it cannot see is not one it admits.
                return match self.store.blob_size(DESIGNATION, &hex).ok().flatten() {
                    Some(len) if len == cell.size => Binding::Admitted,
                    Some(len) if len == named => Binding::Unbound,
                    _ => Binding::Lapsed,
                };
            }
        }
        let lease_arm = match self.store.lease_state(&key, DESIGNATION, &hex, self.now_ms()) {
            LeaseState::None => Binding::Unbound,
            LeaseState::Lapsed { .. } => Binding::Lapsed,
            LeaseState::Live { size, .. } => match self.store.blob_size(DESIGNATION, &hex).ok().flatten() {
                // The file absent, unreadable, or not the length the lease
                // recorded: the deposit is gone.
                Some(len) if len == size => {
                    if cell.size == len {
                        Binding::Admitted
                    } else {
                        // The deposit is whole and the cell contradicts it:
                        // no deposit of this principal's is the cell as
                        // written.
                        Binding::Unbound
                    }
                }
                _ => Binding::Lapsed,
            },
        };
        match lease_arm {
            Binding::Admitted => Binding::Admitted,
            // THE REBUILD WINDOW (ms5-R; the door never waits): a refusal off
            // the lease arm alone, the index arm unread, is the state and no
            // permanent verdict — while the walk RUNS. Where it DIED (§4 row
            // 26) no arm is coming, and the verdict stands as final: honest
            // where no wait can succeed.
            _ if !ready && !self.index.is_failed() => Binding::Rebuilding,
            refused => refused,
        }
    }

    /// TEST SEAM: advance the gate's clock by `ms` — every expiry judged
    /// against it moves with it.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn advance_clock_ms(&self, ms: u64) {
        self.clock_offset_ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// TEST SEAM: the floor reads `bytes` as the volume's free space, or
    /// the host again with `None`.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn set_free_space(&self, bytes: Option<u64>) {
        *self.free_space_override.lock() = bytes;
    }

    /// The line the pruner's hold writes on the operator stream as it
    /// parks — what the dirty-crash harness watches for before it kills.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub const PRUNE_HOLD_NOTICE: &'static str =
        "test seam: held inside the pruner's pass after a rename aside; kill this process";

    /// TEST SEAM: arm the hold inside the pruner's pass — after the next
    /// rename aside, the arm released and the aside not yet unlinked, the
    /// pass writes [`MediaGate::PRUNE_HOLD_NOTICE`] and parks its thread
    /// for good. Not disarmable.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn arm_prune_hold(&self) {
        self.prune_hold.store(true, Ordering::Relaxed);
    }

    /// The pass's side of the seam: park here where the hold is armed.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn hold_after_rename_if_armed(&self) {
        if self.prune_hold.load(Ordering::Relaxed) {
            notice::line(Self::PRUNE_HOLD_NOTICE);
            loop {
                std::thread::park();
            }
        }
    }

    /// TEST SEAM: a pass completed — counted, so a suite can wait for the
    /// cadence's first pass before moving the clock under it.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn note_pass_completed(&self) {
        self.passes_completed.fetch_add(1, Ordering::Release);
    }

    /// TEST SEAM: the passes completed so far.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn passes_completed(&self) -> u64 {
        self.passes_completed.load(Ordering::Acquire)
    }
}

/// The wall clock, unix milliseconds; `0` for a clock set before the epoch
/// — the gate's own reading, which the operator's inventory takes for its
/// `now` so expiry is judged there as the gate judges it.
pub fn wall_clock_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests;
