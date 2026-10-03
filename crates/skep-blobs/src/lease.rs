//! THE LEASE LOG, `<root>/leases.log` — PATTERNS P22's honest-null arm
//! (`media.md` Op inventory 1, "THE LEASE'S STORE, SCOPE AND EXPIRY,
//! STATED"; "EACH KEY's CURRENT RECORD IS ITS LATEST, AND OPEN COMPACTS
//! BOTH STORES"; §The media stores): one JSON line per deposit — the key,
//! the designation and hex, the file's size and the expiry fixed at the
//! PUT — appended and synced at an upload's finish AFTER the file is durable
//! and BEFORE the answer, so a crash leaves at worst a file with no lease
//! and never a lease naming bytes that are not there.
//!
//! THE READ: a key's lease on a hash is its LATEST line there, a re-PUT's
//! lease replacing the one before whatever either's expiry; a lease whose
//! expiry has passed answers LAPSED within a HORIZON past the expiry and as
//! NONE after it — so LAPSED is exact within the horizon, and the log,
//! compacted at open to each key's latest line with every lease past the
//! horizon dropped, never grows with the board's upload history. The
//! horizon and the interval are the daemon's constants (D1), handed in.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::blobs::{line_of, open_append, read_log, rewrite_log};

/// The log's file name under the root.
pub(crate) const LEASES_LOG: &str = "leases.log";

/// One deposit's lease: KEY holds `<designation>/<hex>` of `size` bytes
/// until `expires`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub key: String,
    pub designation: String,
    pub hex: String,
    pub size: u64,
    pub expires: u64,
}

impl Lease {
    fn value(&self) -> Value {
        json!({
            "designation": self.designation,
            "expires": self.expires,
            "hex": self.hex,
            "key": self.key,
            "size": self.size,
        })
    }

    fn parse(v: &Value) -> Option<Lease> {
        Some(Lease {
            key: v.get("key")?.as_str()?.to_string(),
            designation: v.get("designation")?.as_str()?.to_string(),
            hex: v.get("hex")?.as_str()?.to_string(),
            size: v.get("size")?.as_u64()?,
            expires: v.get("expires")?.as_u64()?,
        })
    }

    /// Live at `now_ms`?
    pub fn live(&self, now_ms: u64) -> bool {
        now_ms < self.expires
    }
}

/// What a key holds on a hash: a live lease with its size and expiry, a
/// lease lapsed within the horizon (its expiry named, so a client's resume
/// can be written against it), or none — the one answer for "never
/// deposited", "lapsed past the horizon" and "another key's" alike.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseState {
    Live { size: u64, expires: u64 },
    Lapsed { expires: u64 },
    None,
}

/// The leases as held in memory beside their log, keyed by
/// `(key, designation, hex)`.
pub(crate) struct LeaseLog {
    path: PathBuf,
    file: File,
    leases: HashMap<(String, String, String), Lease>,
    lines_on_disk: usize,
    horizon_ms: u64,
}

impl LeaseLog {
    /// Open the log under `root`: the tail checked, each key's latest line
    /// kept, every lease lapsed past the horizon at `now_ms` dropped, and
    /// the log rewritten where anything was dropped.
    pub fn open(root: &Path, now_ms: u64, horizon_ms: u64) -> io::Result<LeaseLog> {
        let path = root.join(LEASES_LOG);
        let (values, _cut) = read_log(&path)?;
        let mut leases = HashMap::new();
        let mut lines_on_disk = 0;
        for v in &values {
            lines_on_disk += 1;
            if let Some(l) = Lease::parse(v) {
                leases.insert((l.key.clone(), l.designation.clone(), l.hex.clone()), l);
            }
        }
        leases.retain(|_, l| !past_horizon(l, now_ms, horizon_ms));
        let file = open_append(&path)?;
        let mut log = LeaseLog { path, file, leases, lines_on_disk, horizon_ms };
        log.compact()?;
        Ok(log)
    }

    /// Append `lease` as the key's current lease on the hash and SYNC it —
    /// the PUT answers only after this returns.
    pub fn append_synced(&mut self, lease: Lease) -> io::Result<()> {
        let line = line_of(&lease.value());
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.sync_all()?;
        self.lines_on_disk += 1;
        self.leases.insert((lease.key.clone(), lease.designation.clone(), lease.hex.clone()), lease);
        Ok(())
    }

    /// The key's state on a hash at `now_ms`.
    pub fn state(&self, key: &str, designation: &str, hex: &str, now_ms: u64) -> LeaseState {
        let Some(l) =
            self.leases.get(&(key.to_string(), designation.to_string(), hex.to_string()))
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

    /// The key's LIVE leases at `now_ms`, in hex order.
    pub fn live_of(&self, key: &str, now_ms: u64) -> Vec<Lease> {
        let mut out: Vec<Lease> =
            self.leases.values().filter(|l| l.key == key && l.live(now_ms)).cloned().collect();
        out.sort_by(|a, b| (&a.designation, &a.hex).cmp(&(&b.designation, &b.hex)));
        out
    }

    /// The sum of the key's live leases' sizes at `now_ms` — those
    /// `counted` admits.
    pub fn pending_of(&self, key: &str, now_ms: u64, counted: &dyn Fn(&Lease) -> bool) -> u64 {
        self.leases
            .values()
            .filter(|l| l.key == key && l.live(now_ms) && counted(l))
            .fold(0u64, |acc, l| acc.saturating_add(l.size))
    }

    /// The sum of every key's live leases' sizes at `now_ms` — those
    /// `counted` admits.
    pub fn pending_total(&self, now_ms: u64, counted: &dyn Fn(&Lease) -> bool) -> u64 {
        self.leases
            .values()
            .filter(|l| l.live(now_ms) && counted(l))
            .fold(0u64, |acc, l| acc.saturating_add(l.size))
    }

    /// Whether ANY key holds a live lease on `<designation>/<hex>` at
    /// `now_ms` — the pruner's read, beside the per-key [`LeaseLog::state`]:
    /// a scan of the map, whose key leads with the holder.
    pub fn any_live(&self, designation: &str, hex: &str, now_ms: u64) -> bool {
        self.leases
            .values()
            .any(|l| l.designation == designation && l.hex == hex && l.live(now_ms))
    }

    /// Rewrite the log to the current leases where any line on disk is not
    /// one.
    fn compact(&mut self) -> io::Result<()> {
        if self.lines_on_disk == self.leases.len() {
            return Ok(());
        }
        let mut keys: Vec<&(String, String, String)> = self.leases.keys().collect();
        keys.sort();
        let lines: Vec<String> = keys.iter().map(|k| line_of(&self.leases[*k].value())).collect();
        self.file = rewrite_log(&self.path, &lines)?;
        self.lines_on_disk = lines.len();
        Ok(())
    }
}

/// Past the horizon: lapsed by more than `horizon_ms`.
fn past_horizon(l: &Lease, now_ms: u64, horizon_ms: u64) -> bool {
    now_ms >= l.expires.saturating_add(horizon_ms)
}
