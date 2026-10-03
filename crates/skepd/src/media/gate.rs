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
//! record first (M-I2 (e)): THE OWN SCOPE, the principal's base plus its
//! pending bytes, against the venue's per-account limit — at lane B's ZERO
//! BASE (no cell index until lane C) the own scope is the pending bytes
//! alone, its live leases' sizes and its standing uploads' bytes received —
//! refused on the declared total BEFORE the body and re-checked as the body
//! is written; THE VENUE TOTAL, the sum of every account's own scope,
//! record-derived and never the directory's bytes, enforced ONLY as the
//! body is written (a pre-body yes-or-no would show the board-wide figure
//! free of charge; as written, its refusal's offset is that figure PRICED
//! at the headroom's transfer — ms4-E1, accepted and named); THE FLOOR, the
//! volume's free space held above [`FLOOR_BYTES`] so a deposit never takes
//! the journal's last bytes, read off the host and showing no figure.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use skep_blobs::{LeaseState, Store, UploadId};
use skep_namespace::PrincipalId;

use super::cell::{Cell, HASH_BYTES};
use crate::limits::MAX_BLOB_BYTES;

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
    /// The principal holds a live lease on the hash, the file is there at
    /// the lease's size, and the cell's `size` is that length.
    Admitted,
    /// The principal's lease on the hash has lapsed within the horizon, or
    /// is live over a file that is not there or not whole: the deposit is
    /// gone, the act a re-PUT.
    Lapsed,
    /// The principal holds no lease on the hash — never deposited, lapsed
    /// past the horizon, or another's — or holds one whose size the cell
    /// contradicts: no deposit of this principal's is the cell as written.
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
    /// The test seam's clock offset, added to the wall clock.
    #[cfg(any(test, feature = "test-hooks"))]
    clock_offset_ms: AtomicU64,
    /// The test seam's free-space reading, in place of the host's.
    #[cfg(any(test, feature = "test-hooks"))]
    free_space_override: Mutex<Option<u64>>,
}

impl MediaGate {
    /// Open the blob store under `data_dir/blobs` — its reconciliation and
    /// compaction complete before this returns — with the daemon's default
    /// limits in force.
    pub(crate) fn open(data_dir: &Path) -> io::Result<MediaGate> {
        let now = wall_clock_ms();
        let store = Store::open(&data_dir.join("blobs"), now, LEASE_HORIZON_MS)?;
        Ok(MediaGate {
            store,
            limits: RwLock::new(Limits::default()),
            held: Mutex::new(HashSet::new()),
            #[cfg(any(test, feature = "test-hooks"))]
            clock_offset_ms: AtomicU64::new(0),
            #[cfg(any(test, feature = "test-hooks"))]
            free_space_override: Mutex::new(None),
        })
    }

    pub(crate) fn store(&self) -> &Store {
        &self.store
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

    /// Claim an upload for a stream (clause (5)): `false` where another
    /// stream holds it.
    pub(crate) fn claim(&self, id: UploadId) -> bool {
        self.held.lock().insert(id)
    }

    /// Release a stream's hold.
    pub(crate) fn release(&self, id: UploadId) {
        self.held.lock().remove(&id);
    }

    /// THE OWN SCOPE BEFORE THE BODY (M-I6 (e)): would the principal's
    /// pending bytes plus `declared` — an upload's whole length at its
    /// creation, what it leaves past the offset at a resume — pass the
    /// per-account limit? Read off the principal's own record alone.
    pub(crate) fn admit_declared(&self, key: &str, declared: u64, now_ms: u64) -> Result<(), Scope> {
        let Some(limit) = self.limits.read().per_account else { return Ok(()) };
        let pending = self.store.pending_bytes(key, now_ms);
        if pending.saturating_add(declared) > limit {
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
        key: &str,
        id: &UploadId,
        written: u64,
        n: u64,
        now_ms: u64,
    ) -> Result<(), Scope> {
        let limits = self.limits.read().clone();
        let durable = self.store.upload(key, id, now_ms).map_or(0, |r| r.offset);
        if let Some(limit) = limits.per_account {
            let own = self.store.pending_bytes(key, now_ms).saturating_sub(durable).saturating_add(written);
            if own.saturating_add(n) > limit {
                return Err(Scope::Own);
            }
        }
        if let Some(limit) = limits.venue_total {
            let total = self.store.pending_total(now_ms).saturating_sub(durable).saturating_add(written);
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

    /// THE BINDING (Op inventory 2; item 4 of lane B): the principal's own
    /// lease record first, the file only where that record names the hash
    /// under a live lease.
    pub(crate) fn binding(&self, principal: PrincipalId, cell: &Cell) -> Binding {
        let key = Self::key(principal);
        let hex = hex_of(&cell.hash);
        match self.store.lease(&key, DESIGNATION, &hex, self.now_ms()) {
            LeaseState::None => Binding::Unbound,
            LeaseState::Lapsed { .. } => Binding::Lapsed,
            LeaseState::Live { size, .. } => match self.store.blob_len(DESIGNATION, &hex) {
                // The file absent, or not the length the lease recorded:
                // the deposit is gone.
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
        assert_eq!(gate.admit_declared("1", u64::MAX / 2, now), Ok(()), "no per-account limit binds");
        gate.install(Limits {
            per_account: Some(10),
            venue_total: Some(100),
            lease_interval_ms: 1_000,
            per_file_cap: MAX_BLOB_BYTES * 4,
            address: Some("1.0.1.0.3.1".into()),
        });
        assert_eq!(gate.limits().per_file_cap, MAX_BLOB_BYTES, "held at the route's cap");
        assert_eq!(gate.admit_declared("1", 11, now), Err(Scope::Own));
        assert_eq!(gate.admit_declared("1", 10, now), Ok(()));
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
    /// LAPSED within the horizon and UNBOUND past it.
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
        let rec = store.create_upload(&key, DESIGNATION, 9, now + 10_000, None).unwrap();
        store.resume(&key, &rec.id, 0, now).unwrap();
        store.append(&key, &rec.id, bytes, now, 10_000).unwrap();
        store.settle(&key, &rec.id, now, 10_000).unwrap();
        let fin = store.finish(&key, &rec.id, now, now + 10_000).unwrap();
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
        let rec = store.create_upload(&key, DESIGNATION, 9, now + 10_000, None).unwrap();
        store.resume(&key, &rec.id, 0, now).unwrap();
        store.append(&key, &rec.id, bytes, now, 10_000).unwrap();
        store.settle(&key, &rec.id, now, 10_000).unwrap();
        store.finish(&key, &rec.id, now, now + 10_000).unwrap();
        assert_eq!(gate.binding(p, &cell), Binding::Admitted);
        std::fs::remove_file(store.blob_path(DESIGNATION, &hex_of(&hash))).unwrap();
        assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "a live lease over no file reads as lapsed");
    }
}
