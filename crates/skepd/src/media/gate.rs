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
//! PENDING BYTES, against the venue's per-account limit (M-I6 (b)) — the
//! base the cell index's number for the account, the sum of the distinct
//! hashes its cells name at their size (M-I6 (a)); the pending bytes its
//! live leases on hashes none of its cells names, plus its standing
//! uploads' bytes received — refused on the declared total BEFORE the body
//! and re-checked as the body is written; THE VENUE TOTAL, the sum of every
//! account's own scope — every base, every pending — record-derived and
//! never the directory's bytes, enforced ONLY as the body is written (a
//! pre-body yes-or-no would show the board-wide figure free of charge; as
//! written, its refusal's offset is that figure PRICED at the headroom's
//! transfer — ms4-E1, accepted and named); THE FLOOR, the volume's free
//! space held above [`FLOOR_BYTES`] so a deposit never takes the journal's
//! last bytes, read off the host and showing no figure. The own scope and
//! the venue total read the base, so the creation and the resume are two
//! of the index's three readers: refused `index_rebuilding` until the walk
//! at open completes (ms5-R).
//!
//! THE BINDING reads THE INDEX FIRST ([`MediaGate::binding`]): a hash the
//! requester's own cells already name is a REFERENCE, kept by no lease —
//! admitted where the file is on disk whole at the cell's size, the deposit
//! gone where it is not — and only then the lease arm. Until the walk
//! completes the index arm is skipped and the lease arm alone decides: the
//! door is not one of the three readers and never waits (ms5-R, "for
//! nothing else"); a cell refused in that window is a refusal for the
//! request as sent, its act the re-PUT, and nothing permanent lands.
//!
//! THE LIMITS RECORD (§Recovery: "ONE published, attributed, supersedable
//! record … installed in the daemon by the serving layer as AUTH-4.70's
//! list is"): its kind, schema and install channel are AUTH's docket's
//! (RES-208; the investigation's STOP 5) — OWED. What stands in: a DAEMON
//! DEFAULT (D1, as the nonce TTL is: a per-account limit of NONE, a venue
//! total of NONE, the lease interval [`LEASE_INTERVAL_DEFAULT_MS`], the
//! per-file cap `MAX_BLOB_BYTES`, no address) and an INSTALL HOOK
//! ([`MediaGate::install`]) the serving layer's channel will call; the
//! startup log names the record in force or that none is. The venue total
//! and the per-account limit are testable against an installed record
//! alone until the channel lands.
//!
//! THE LEASE INTERVAL and ITS HORIZON (Op inventory 1, "THE INTERVAL HAS A
//! DEFAULT, A GATE CONSTANT OF THE DAEMON's"; "a lease lapsed past a
//! HORIZON … answers as no lease") are the two constants below, INTERIM
//! pins (sm-Q8), handed to the store at open.

use std::collections::HashSet;
use std::io;
use std::path::Path;
#[cfg(any(test, feature = "test-hooks"))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use skep_blobs::{Lease, LeaseState, Store, UploadId};
use skep_namespace::PrincipalId;

use super::cell::{Cell, HASH_BYTES};
use super::index::CellIndex;
use crate::limits::MAX_BLOB_BYTES;
#[cfg(any(test, feature = "test-hooks"))]
use crate::notice;

/// THE DESIGNATION the daemon deposits under — the cell schema's own,
/// `blake3` (`media/cell.rs`'s `DESIGNATION`, which lane A pinned beside
/// the schema; the test below holds this constant to it). Spelled again
/// here, and not read from the cell module, because that module is
/// byte-fixed with its expectation that the constant is read by no shipped
/// code of lane A — the expectation retires when lane A's file is next
/// opened.
pub(crate) const DESIGNATION: &str = "blake3";

/// THE LEASE INTERVAL's DAEMON DEFAULT — seven days, INTERIM: an upload
/// plus an authoring interval below it, what a venue will hold unreferenced
/// above; a limits record may move it within those bounds, and it stands
/// wherever none sets one, so a venue that publishes no limits has no quota
/// and never no reclamation. The upload's expiry interval is this too.
pub(crate) const LEASE_INTERVAL_DEFAULT_MS: u64 = 7 * 24 * 3600 * 1000;

/// THE HORIZON — thirty days past a lease's expiry, INTERIM: within it a
/// lapsed lease answers LAPSED (the deposit is gone; re-PUT the bytes — a
/// resume can be written against it), past it NONE, and the lease log
/// compacts it away at open.
pub(crate) const LEASE_HORIZON_MS: u64 = 30 * 24 * 3600 * 1000;

/// THE FLOOR — 256 MiB of the volume's free space, INTERIM: the room the
/// journal's next segments and checkpoints are kept, which no deposit may
/// take; a PUT is refused as its body is written once a chunk would take the
/// volume below it. The floor reads the host and shows no figure.
pub(crate) const FLOOR_BYTES: u64 = 256 * 1024 * 1024;

/// The limits in force: the venue's record, or the daemon's defaults where
/// none is installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    /// The per-account limit on the own scope; `None` binds nothing.
    pub per_account: Option<u64>,
    /// The venue's total over every account's own scope; `None` binds
    /// nothing.
    pub venue_total: Option<u64>,
    /// The lease interval and the upload's expiry interval.
    pub lease_interval_ms: u64,
    /// The per-file cap, at or below the route's own.
    pub per_file_cap: u64,
    /// The record's address as installed, echoed by the deposit read;
    /// `None` where no record is installed.
    pub address: Option<String>,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            per_account: None,
            venue_total: None,
            lease_interval_ms: LEASE_INTERVAL_DEFAULT_MS,
            per_file_cap: MAX_BLOB_BYTES,
            address: None,
        }
    }
}

impl Limits {
    /// The line the startup log names the record in force by.
    pub(crate) fn log_line(&self) -> String {
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
            None => format!(
                "media limits: no record installed — the daemon's defaults stand: per-account \
                 none, venue total none, lease interval {} ms, per-file cap {}",
                self.lease_interval_ms, self.per_file_cap
            ),
        }
    }
}

/// The scope a deposit was refused on — what the refusal names, and
/// nothing of the headroom (M-I6 (h)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The principal's own scope: its pending bytes against the per-account
    /// limit.
    Own,
    /// The venue's total.
    Venue,
    /// The host's floor.
    Floor,
}

impl Scope {
    /// The wire's token.
    pub(crate) fn token(self) -> &'static str {
        match self {
            Scope::Own => "own",
            Scope::Venue => "venue",
            Scope::Floor => "floor",
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
}

/// The daemon's media resource.
pub(crate) struct MediaGate {
    store: Store,
    limits: RwLock<Limits>,
    /// THE HOLD (clause (5)): the uploads a stream owns right now, in
    /// skepd's memory and no store — a PUT naming one is refused while it
    /// is held; the hold ends with the stream's connection.
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
    /// compaction complete before this returns — with the daemon's default
    /// limits in force and an EMPTY, NOT-READY cell index: the daemon hands
    /// the index to the write path and starts the walk that readies it.
    pub(crate) fn open(data_dir: &Path) -> io::Result<MediaGate> {
        let now = wall_clock_ms();
        let store = Store::open(data_dir.join("blobs"), Duration::from_millis(LEASE_HORIZON_MS), now)?;
        Ok(MediaGate {
            store,
            limits: RwLock::new(Limits::default()),
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

    pub(crate) fn store(&self) -> &Store {
        &self.store
    }

    /// The cell index — the one copy the write path enters and the walk at
    /// open adds into.
    pub(crate) fn index(&self) -> &Arc<CellIndex> {
        &self.index
    }

    /// Whether the index's three readers are served: the walk at open has
    /// completed.
    pub(crate) fn index_ready(&self) -> bool {
        self.index.is_ready()
    }

    /// The limits in force.
    pub(crate) fn limits(&self) -> Limits {
        self.limits.read().clone()
    }

    /// THE INSTALL HOOK (AUTH-4.70's channel, owed): replace the limits in
    /// force WHOLE. The per-file cap is held at or below the route's own; a
    /// record naming a larger one is installed at the route's.
    pub(crate) fn install(&self, mut limits: Limits) {
        limits.per_file_cap = limits.per_file_cap.min(MAX_BLOB_BYTES);
        *self.limits.write() = limits;
    }

    /// The gate's reading of the clock, unix milliseconds — the one every
    /// expiry and lease is fixed by and judged against.
    pub(crate) fn now_ms(&self) -> u64 {
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
    pub(crate) fn key(principal: PrincipalId) -> String {
        principal.0.to_string()
    }

    /// The principal a store key spells — [`MediaGate::key`] read back, the
    /// one spelling being this gate's own; `None` for a key no gate of this
    /// build wrote.
    pub(crate) fn principal_of_key(key: &str) -> Option<PrincipalId> {
        key.parse::<u64>().ok().map(PrincipalId)
    }

    /// Whether a live lease counts in its key's PENDING bytes: not where the
    /// key's own cells name the hash, which its base already counts
    /// (M-I6 (b)).
    fn lease_pending(&self, lease: &Lease) -> bool {
        match Self::principal_of_key(&lease.principal) {
            Some(p) => !self.index.names(p, &lease.designation, &lease.hex),
            None => true,
        }
    }

    /// THE OWN SCOPE of `principal` at `now_ms` (M-I6 (b)): its base — the
    /// index's number — plus its pending bytes, the live leases on hashes
    /// none of its cells names and its standing uploads' bytes received.
    pub(crate) fn own_scope(&self, principal: PrincipalId, now_ms: u64) -> u64 {
        self.index.base(principal).saturating_add(self.own_pending(principal, now_ms))
    }

    /// `principal`'s PENDING BYTES at `now_ms` — the deposit read's second
    /// figure beside the base.
    pub(crate) fn own_pending(&self, principal: PrincipalId, now_ms: u64) -> u64 {
        let key = Self::key(principal);
        self.store.pending_bytes(&key, now_ms, |l| self.lease_pending(l))
    }

    /// THE VENUE TOTAL at `now_ms`: the sum of every account's own scope —
    /// every base and every pending — record-derived.
    pub(crate) fn venue_total(&self, now_ms: u64) -> u64 {
        self.index
            .total_base()
            .saturating_add(self.store.pending_total(now_ms, |l| self.lease_pending(l)))
    }

    /// Claim an upload for a stream (clause (5)): `false` where another
    /// stream holds it.
    pub(crate) fn claim(&self, id: UploadId) -> bool {
        self.held.lock().insert(id)
    }

    /// Release a stream's hold.
    pub(crate) fn release(&self, id: UploadId) {
        self.held.lock().remove(&id);
    }

    /// THE OWN SCOPE BEFORE THE BODY (M-I6 (e)): would the principal's own
    /// scope — its base plus its pending bytes — plus `declared` (an
    /// upload's whole length at its creation, what it leaves past the
    /// offset at a resume) pass the per-account limit? Read off the
    /// principal's own record and the index's number for its account.
    pub(crate) fn admit_declared(
        &self,
        principal: PrincipalId,
        declared: u64,
        now_ms: u64,
    ) -> Result<(), Scope> {
        let Some(limit) = self.limits.read().per_account else { return Ok(()) };
        if self.own_scope(principal, now_ms).saturating_add(declared) > limit {
            return Err(Scope::Own);
        }
        Ok(())
    }

    /// THE GATE AS THE BODY IS WRITTEN: would the next `n` bytes of the
    /// upload `id`, of which `written` are already in its partial, pass the
    /// own scope, the venue's total, or the floor — in that order? The own
    /// scope and the total count this upload at its bytes written (the
    /// record holds its durable offset, which lags by at most a grain).
    pub(crate) fn admit_bytes(
        &self,
        principal: PrincipalId,
        id: &UploadId,
        written: u64,
        n: u64,
        now_ms: u64,
    ) -> Result<(), Scope> {
        let limits = self.limits.read().clone();
        let key = Self::key(principal);
        let durable = self.store.upload(&key, id, now_ms).map_or(0, |r| r.offset);
        if let Some(limit) = limits.per_account {
            let own = self.own_scope(principal, now_ms).saturating_sub(durable).saturating_add(written);
            if own.saturating_add(n) > limit {
                return Err(Scope::Own);
            }
        }
        if let Some(limit) = limits.venue_total {
            let total = self.venue_total(now_ms).saturating_sub(durable).saturating_add(written);
            if total.saturating_add(n) > limit {
                return Err(Scope::Venue);
            }
        }
        if self.free_space().saturating_sub(n) < FLOOR_BYTES {
            return Err(Scope::Floor);
        }
        Ok(())
    }

    /// The volume's free space — the host's, or the seam's reading.
    fn free_space(&self) -> u64 {
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
    /// completes the index arm is skipped: the door never waits on the
    /// index.
    pub(crate) fn binding(&self, principal: PrincipalId, cell: &Cell) -> Binding {
        let key = Self::key(principal);
        let hex = hex_of(&cell.hash);
        if self.index.is_ready() {
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
        match self.store.lease_state(&key, DESIGNATION, &hex, self.now_ms()) {
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
        }
    }

    /// TEST SEAM: advance the gate's clock by `ms` — every expiry judged
    /// against it moves with it.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn advance_clock_ms(&self, ms: u64) {
        self.clock_offset_ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// TEST SEAM: the floor reads `bytes` as the volume's free space, or
    /// the host again with `None`.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn set_free_space(&self, bytes: Option<u64>) {
        *self.free_space_override.lock() = bytes;
    }

    /// The line the pruner's hold writes on the operator stream as it
    /// parks — what the dirty-crash harness watches for before it kills.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) const PRUNE_HOLD_NOTICE: &'static str =
        "test seam: held inside the pruner's pass after an unlink; kill this process";

    /// TEST SEAM: arm the hold inside the pruner's pass — after the next
    /// unlink, the arm released, the pass writes [`MediaGate::PRUNE_HOLD_NOTICE`]
    /// and parks its thread for good. Not disarmable.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn arm_prune_hold(&self) {
        self.prune_hold.store(true, Ordering::Relaxed);
    }

    /// The pass's side of the seam: park here where the hold is armed.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn hold_after_unlink_if_armed(&self) {
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
    pub(crate) fn passes_completed(&self) -> u64 {
        self.passes_completed.load(Ordering::Acquire)
    }
}

/// A hash's 64 lowercase hex.
pub(crate) fn hex_of(hash: &[u8; HASH_BYTES]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// The wall clock, unix milliseconds; `0` for a clock set before the epoch.
pub(crate) fn wall_clock_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate deposits under the cell schema's own designation: the two
    /// spellings are one.
    #[test]
    fn the_designation_is_the_cell_schemas() {
        assert_eq!(DESIGNATION, super::super::cell::DESIGNATION);
    }

    /// The daemon's defaults: nothing bound but the per-file cap, the lease
    /// interval seven days, the horizon thirty; an installed record's cap
    /// is held at the route's own.
    #[test]
    fn the_defaults_bind_nothing_but_the_cap_and_an_install_is_held_to_the_route() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = MediaGate::open(dir.path()).expect("the store opens");
        assert_eq!(gate.limits(), Limits::default());
        assert_eq!(LEASE_INTERVAL_DEFAULT_MS, 7 * 24 * 3600 * 1000);
        assert_eq!(LEASE_HORIZON_MS, 30 * 24 * 3600 * 1000);
        assert_eq!(FLOOR_BYTES, 256 * 1024 * 1024);
        let now = gate.now_ms();
        let p = PrincipalId(1);
        assert_eq!(gate.admit_declared(p, u64::MAX / 2, now), Ok(()), "no per-account limit binds");
        gate.install(Limits {
            per_account: Some(10),
            venue_total: Some(100),
            lease_interval_ms: 1_000,
            per_file_cap: MAX_BLOB_BYTES * 4,
            address: Some("1.0.1.0.3.1".into()),
        });
        assert_eq!(gate.limits().per_file_cap, MAX_BLOB_BYTES, "held at the route's cap");
        assert_eq!(gate.admit_declared(p, 11, now), Err(Scope::Own));
        assert_eq!(gate.admit_declared(p, 10, now), Ok(()));
        assert!(!gate.index_ready(), "an opened gate's index is not ready until the walk");
        assert_eq!(MediaGate::principal_of_key(&MediaGate::key(p)), Some(p));
        assert_eq!(MediaGate::principal_of_key("k"), None);
        assert!(gate.limits().log_line().contains("1.0.1.0.3.1"));
        // The hold: one stream at a time.
        let id = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert!(gate.claim(id));
        assert!(!gate.claim(id));
        gate.release(id);
        assert!(gate.claim(id));
    }

    /// The binding's three answers off the store: no lease is UNBOUND; a
    /// live lease over a whole file whose length the cell names is
    /// ADMITTED; the same lease with the cell's size wrong is UNBOUND; the
    /// file removed under the live lease is LAPSED; the lease lapsed is
    /// LAPSED within the horizon and UNBOUND past it. Then THE INDEX ARM:
    /// a cell the principal's own cells already name is ADMITTED past every
    /// lapse while the file is whole at the cell's size, LAPSED where it is
    /// not, and skipped while the index is not ready; another principal's
    /// cells admit nothing of this one's; and the own scope counts a named
    /// hash in the base and not in the pending bytes.
    #[test]
    fn the_binding_reads_the_principals_own_lease_first_and_the_file_only_under_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = MediaGate::open(dir.path()).expect("the store opens");
        let p = PrincipalId(7);
        let bytes = b"a picture";
        let hash: [u8; HASH_BYTES] = *blake3::hash(bytes).as_bytes();
        let cell = Cell { hash, size: bytes.len() as u64 };
        assert_eq!(gate.binding(p, &cell), Binding::Unbound);
        let now = gate.now_ms();
        let store = gate.store();
        let key = MediaGate::key(p);
        let rec = store.create_upload(&key, DESIGNATION, 9, Duration::from_millis(10_000), now).unwrap();
        store.resume(&key, &rec.id, 0, now).unwrap();
        store.append(&key, &rec.id, bytes, now).unwrap();
        store.settle(&key, &rec.id, now).unwrap();
        let fin = store.finish(&key, &rec.id, Duration::from_millis(10_000), now).unwrap();
        assert_eq!(fin.hex, hex_of(&hash));
        assert_eq!(gate.binding(p, &cell), Binding::Admitted);
        assert_eq!(gate.binding(PrincipalId(8), &cell), Binding::Unbound, "another principal holds none");
        assert_eq!(gate.binding(p, &Cell { hash, size: 8 }), Binding::Unbound, "the size contradicts the deposit");
        gate.advance_clock_ms(10_000);
        assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "lapsed within the horizon");
        gate.advance_clock_ms(LEASE_HORIZON_MS);
        assert_eq!(gate.binding(p, &cell), Binding::Unbound, "past the horizon: no lease");
        // A fresh lease, then the file removed from under it.
        let now = gate.now_ms();
        let rec = store.create_upload(&key, DESIGNATION, 9, Duration::from_millis(10_000), now).unwrap();
        store.resume(&key, &rec.id, 0, now).unwrap();
        store.append(&key, &rec.id, bytes, now).unwrap();
        store.settle(&key, &rec.id, now).unwrap();
        store.finish(&key, &rec.id, Duration::from_millis(10_000), now).unwrap();
        assert_eq!(gate.binding(p, &cell), Binding::Admitted);
        std::fs::remove_file(store.blob_path(DESIGNATION, &hex_of(&hash)).unwrap()).unwrap();
        assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "a live lease over no file reads as lapsed");

        // THE INDEX ARM. The file re-deposited, the cell entered as p's.
        let now = gate.now_ms();
        let rec = store.create_upload(&key, DESIGNATION, 9, Duration::from_millis(10_000), now).unwrap();
        store.resume(&key, &rec.id, 0, now).unwrap();
        store.append(&key, &rec.id, bytes, now).unwrap();
        store.settle(&key, &rec.id, now).unwrap();
        store.finish(&key, &rec.id, Duration::from_millis(10_000), now).unwrap();
        assert_eq!(gate.own_pending(p, now), 9, "no cell names it: the lease counts as pending");
        assert_eq!(gate.own_scope(p, now), 9);
        let at = crate::codec::wire_address("1.0.1.0.2.0.1.1").unwrap();
        gate.index().enter(&at, Some(p), &cell);
        assert_eq!(gate.own_pending(p, now), 0, "a named hash counts in the base, not the pending");
        assert_eq!(gate.own_scope(p, now), 9, "the own scope is one number either way");
        assert_eq!(gate.venue_total(now), 9);
        assert_eq!(gate.binding(p, &cell), Binding::Admitted, "not ready: the lease arm alone, live");
        gate.index().complete(super::super::index::Rebuild {
            values: 0,
            cells: 0,
            halts: 0,
            walk: std::time::Duration::ZERO,
            parse: std::time::Duration::ZERO,
        });
        assert!(gate.index_ready());
        gate.advance_clock_ms(10_000 + LEASE_HORIZON_MS);
        assert_eq!(gate.binding(p, &cell), Binding::Admitted, "named by p's own cell: admitted past the lease's horizon");
        assert_eq!(gate.binding(p, &Cell { hash, size: 8 }), Binding::Unbound, "named, the file whole at the named size, the cell contradicting it: the size check's answer");
        assert_eq!(gate.binding(PrincipalId(8), &cell), Binding::Unbound, "another principal's cells admit nothing of this one's");
        let path = store.blob_path(DESIGNATION, &hex_of(&hash)).unwrap();
        std::fs::write(&path, b"a pictur").unwrap();
        assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "named, the file not whole: the deposit is gone");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "named, the file gone: the deposit is gone");
        assert_eq!(gate.own_scope(p, gate.now_ms()), 9, "the base stands whatever the directory holds");
    }
}
