//! THE LEASE LOG, `<root>/leases.log` — PATTERNS P22's honest-null arm
//! (`media.md` Op inventory 1, "THE LEASE'S STORE, SCOPE AND EXPIRY,
//! STATED"; "EACH KEY's CURRENT RECORD IS ITS LATEST, AND OPEN COMPACTS
//! BOTH STORES"; §The media stores): one JSON line per deposit — the
//! principal, the designation and hex, the file's size and the expiry fixed
//! at the PUT — appended and synced at an upload's finish AFTER the file is
//! durable and BEFORE the answer, so a crash leaves at worst a file with no
//! lease and never a lease naming bytes that are not there.
//!
//! THE READ: a principal's lease on a hash is its LATEST line there, a
//! re-PUT's lease replacing the one before whatever either's expiry; a
//! lease whose expiry has passed answers LAPSED within a HORIZON past the
//! expiry and as NONE after it — so LAPSED is exact within the horizon, and
//! the log, compacted at open to the latest line of each principal's lease
//! on each hash with every lease past the horizon dropped, never grows with
//! the board's upload history. The horizon and the interval are the
//! daemon's constants (D1), handed in.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use serde_json::{json, Value};

use crate::blobs::{designation_ok, hex_ok};
use crate::jsonl::Log;

/// The log's file name under the root.
const LEASES_LOG: &str = "leases.log";

/// One deposit's lease: PRINCIPAL holds `<designation>/<hex>` of `size`
/// bytes until `expires`, an instant in unix milliseconds.
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — field
/// reads are unaffected, and a further field is an addition rather than a
/// broken build.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Lease {
    pub principal: String,
    pub designation: String,
    pub hex: String,
    pub size: u64,
    pub expires: u64,
}

impl Lease {
    /// The lease as its log line's value. The stored format spells the
    /// principal's member `key`.
    fn value(&self) -> Value {
        json!({
            "designation": self.designation,
            "expires": self.expires,
            "hex": self.hex,
            "key": self.principal,
            "size": self.size,
        })
    }

    /// A line's value read as a lease — `None` for a value of no shape this
    /// build reads: a member missing, or a designation or hex the store's
    /// name check refuses (`designation_ok`, `hex_ok`, the check every name
    /// a caller hands [`Store`](crate::Store) meets). No finish writes such
    /// a line, but a log restored from elsewhere (`media.md` §Recovery) may,
    /// and read, it would stand in the map as a lease under a name no file
    /// can have — counted in its principal's pending bytes, listed among its
    /// deposits. It reads as a lost lease does.
    fn parse(v: &Value) -> Option<Lease> {
        Some(Lease {
            principal: v.get("key")?.as_str()?.to_string(),
            designation: v.get("designation")?.as_str().filter(|d| designation_ok(d))?.to_string(),
            hex: v.get("hex")?.as_str().filter(|h| hex_ok(h))?.to_string(),
            size: v.get("size")?.as_u64()?,
            expires: v.get("expires")?.as_u64()?,
        })
    }

    /// Live at `now_ms`?
    fn live(&self, now_ms: u64) -> bool {
        now_ms < self.expires
    }
}

/// What a principal holds on a hash: a live lease with its size and
/// expiry, a lease lapsed within the horizon (its expiry named, so a
/// client's resume can be written against it), or none — the one answer
/// for "never deposited", "lapsed past the horizon" and "another
/// principal's" alike.
///
/// Read off the principal's record alone: `Live` says the record holds,
/// never that the file does. A caller acting on the deposit's bytes reads
/// the file at `size` too ([`Store::blob_size`](crate::Store::blob_size)) —
/// a live lease over a file absent or not whole reads as lapsed, as the
/// daemon's binding and deposit read take it (`media.md` Op inventory 1, "A
/// LIVE LEASE OVER A FILE THAT IS NOT THERE READS AS LAPSED").
///
/// Deliberately not `#[non_exhaustive]`: the three states are the lease's
/// whole answer, and a consumer's exhaustive match — the daemon's binding —
/// gives each its own; a fourth breaks that match on purpose, where the `_`
/// arm `#[non_exhaustive]` demands of an outside crate would absorb it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LeaseState {
    Live { size: u64, expires: u64 },
    Lapsed { expires: u64 },
    None,
}

/// The leases as held in memory beside their log, keyed by
/// `(principal, designation, hex)`.
pub(crate) struct LeaseLog {
    log: Log,
    leases: HashMap<(String, String, String), Lease>,
    horizon_ms: u64,
}

impl LeaseLog {
    /// Open the log under `root`: the tail checked, the latest line of each
    /// principal's lease on each hash kept, every lease lapsed past the
    /// horizon at `now_ms` dropped, and the log rewritten where anything
    /// was dropped.
    pub fn open(root: &Path, now_ms: u64, horizon_ms: u64) -> io::Result<LeaseLog> {
        let (log, values) = Log::open(root.join(LEASES_LOG))?;
        let mut leases = HashMap::new();
        for v in &values {
            if let Some(l) = Lease::parse(v) {
                leases.insert((l.principal.clone(), l.designation.clone(), l.hex.clone()), l);
            }
        }
        leases.retain(|_, l| !past_horizon(l, now_ms, horizon_ms));
        let mut opened = LeaseLog { log, leases, horizon_ms };
        opened.compact()?;
        Ok(opened)
    }

    /// Append `lease` as the principal's current lease on the hash and SYNC
    /// it — the PUT answers only after this returns.
    pub fn append_synced(&mut self, lease: Lease) -> io::Result<()> {
        self.log.append_synced(&lease.value())?;
        self.leases.insert((lease.principal.clone(), lease.designation.clone(), lease.hex.clone()), lease);
        Ok(())
    }

    /// The principal's state on a hash at `now_ms`.
    pub fn state(&self, principal: &str, designation: &str, hex: &str, now_ms: u64) -> LeaseState {
        let Some(l) =
            self.leases.get(&(principal.to_string(), designation.to_string(), hex.to_string()))
        else {
            return LeaseState::None;
        };
        if l.live(now_ms) {
            LeaseState::Live { size: l.size, expires: l.expires }
        } else if past_horizon(l, now_ms, self.horizon_ms) {
            LeaseState::None
        } else {
            LeaseState::Lapsed { expires: l.expires }
        }
    }

    /// The principal's LIVE leases at `now_ms`, in hex order.
    pub fn live_of(&self, principal: &str, now_ms: u64) -> Vec<Lease> {
        let mut out: Vec<Lease> =
            self.leases.values().filter(|l| l.principal == principal && l.live(now_ms)).cloned().collect();
        out.sort_by(|a, b| (&a.designation, &a.hex).cmp(&(&b.designation, &b.hex)));
        out
    }

    /// The sizes of the principal's UNPLACED DEPOSITS at `now_ms`, summed:
    /// its live leases `unplaced` admits.
    pub fn unplaced_of(&self, principal: &str, now_ms: u64, mut unplaced: impl FnMut(&Lease) -> bool) -> u64 {
        self.leases
            .values()
            .filter(|l| l.principal == principal && l.live(now_ms) && unplaced(l))
            .fold(0u64, |acc, l| acc.saturating_add(l.size))
    }

    /// The sizes of every unplaced deposit at `now_ms`, summed: every
    /// principal's live leases `unplaced` admits.
    pub fn unplaced_total(&self, now_ms: u64, mut unplaced: impl FnMut(&Lease) -> bool) -> u64 {
        self.leases
            .values()
            .filter(|l| l.live(now_ms) && unplaced(l))
            .fold(0u64, |acc, l| acc.saturating_add(l.size))
    }

    /// Whether ANY principal holds a live lease on `<designation>/<hex>` at
    /// `now_ms` — the pruner's read, beside the per-principal
    /// [`LeaseLog::state`]: a scan of the map, whose key leads with the
    /// holder.
    pub fn any_live(&self, designation: &str, hex: &str, now_ms: u64) -> bool {
        self.leases
            .values()
            .any(|l| l.designation == designation && l.hex == hex && l.live(now_ms))
    }

    /// Rewrite the log to the current leases where any line on disk is not
    /// one.
    fn compact(&mut self) -> io::Result<()> {
        let mut keys: Vec<&(String, String, String)> = self.leases.keys().collect();
        keys.sort();
        self.log.compact(keys.into_iter().map(|k| self.leases[k].value()))
    }
}

/// Past the horizon: lapsed by more than `horizon_ms`.
fn past_horizon(l: &Lease, now_ms: u64, horizon_ms: u64) -> bool {
    now_ms >= l.expires.saturating_add(horizon_ms)
}
