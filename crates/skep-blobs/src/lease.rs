//! The lease log, `<root>/leases.log`: one JSON line per deposit.
//!
//! It is PATTERNS P22's honest-null arm (`media.md` Op inventory 1, "the
//! lease's store, scope and expiry, stated"; "each key's current record is
//! its latest, and open compacts both stores"; §The media stores). A line
//! holds the principal, the designation and hex, the file's size and the
//! expiry fixed at the PUT, appended and synced at an upload's finish after
//! the file is durable and before the answer, so a crash leaves at worst a
//! file with no lease and never a lease naming bytes that are not there.
//!
//! **The read.** A principal's lease on a hash is its latest line there, a
//! re-PUT's lease replacing the one before whatever either's expiry; a
//! lease whose expiry has passed answers `Lapsed` within a horizon past the
//! expiry and as `None` after it — so `Lapsed` is exact within the horizon,
//! and the leases held, every lease past the horizon dropped at open and at
//! each runtime compaction, and the log, compacted there to the latest line
//! of each principal's lease on each hash, never grow with the board's
//! upload history. The horizon is the daemon's pin (D1), handed in at the
//! open; a lease's expiry is fixed at its finish from the interval handed to
//! the finish (`Stream::finish`) — the limits record's in force, or the
//! daemon's default where none is — and the lease log reads no interval.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

use crate::blobs::{designation_ok, hex_ok};
use crate::jsonl::{Log, LogRead, LogSize, LogStop};
use crate::uploads::{millis, past_trigger};

/// The log's file name under the root.
const LEASES_LOG: &str = "leases.log";

/// One deposit's lease, held by one principal on one file.
///
/// `principal` holds `<designation>/<hex>` of `size` bytes until `expires`,
/// an instant in unix milliseconds.
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — field
/// reads are unaffected, and a further field is an addition rather than a
/// broken build.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Lease {
    /// The principal that holds the lease.
    pub principal: String,
    /// The file's designation.
    pub designation: String,
    /// The file's hex name.
    pub hex: String,
    /// The file's size, in bytes.
    pub size: u64,
    /// The instant the lease stops being live, in unix milliseconds.
    pub expires: u64,
}

impl Lease {
    /// Returns the lease as its log line's value.
    ///
    /// The stored format spells the principal's member `key`.
    fn to_value(&self) -> Value {
        json!({
            "designation": self.designation,
            "expires": self.expires,
            "hex": self.hex,
            "key": self.principal,
            "size": self.size,
        })
    }

    /// Reads a line's value as a lease, or answers `None`.
    ///
    /// `None` is for a value of no shape this build reads: a member missing
    /// or not of its JSON type, or a designation or hex the store's name
    /// check refuses (`designation_ok`, `hex_ok`, the check a name a caller
    /// hands [`Store`](crate::Store) meets before it becomes a path). No
    /// finish writes such a line, but a log restored from elsewhere
    /// (`media.md` §Recovery) may, and read, it would stand in the map as a
    /// lease under a name no file can have — counted in its principal's
    /// pending bytes, listed among its deposits. It reads as a lost lease
    /// does.
    fn parse(v: &Value) -> Option<Lease> {
        Some(Lease {
            principal: v.get("key")?.as_str()?.to_string(),
            designation: v.get("designation")?.as_str().filter(|d| designation_ok(d))?.to_string(),
            hex: v.get("hex")?.as_str().filter(|h| hex_ok(h))?.to_string(),
            size: v.get("size")?.as_u64()?,
            expires: v.get("expires")?.as_u64()?,
        })
    }

    /// Returns whether the lease is live at `now_ms`.
    fn live(&self, now_ms: u64) -> bool {
        now_ms < self.expires
    }

    /// Returns whether the lease is past the horizon at `now_ms`.
    ///
    /// It is lapsed by `horizon` or more — none, not `Lapsed`, and dropped
    /// at open and at each runtime compaction
    /// ([`LeaseLog::drop_past_horizon`]).
    fn past_horizon(&self, horizon: Duration, now_ms: u64) -> bool {
        now_ms >= self.expires.saturating_add(millis(horizon))
    }
}

/// What a principal holds on a hash: a live lease, a lapsed one, or none.
///
/// A live lease comes with its size and expiry; a lease lapsed within the
/// horizon names its expiry — the deposit gone and the act a re-PUT of the
/// bytes, told apart from a hash never deposited (`media.md` Op inventory
/// 1, "the lease's store, scope and expiry, stated"; `docs/wire.md`'s
/// `lease_lapsed`); and none is the one answer for "never deposited",
/// "lapsed past the horizon" and "another principal's" alike.
///
/// Read off the principal's record alone: `Live` says the record holds,
/// never that the file does. A caller acting on the deposit's bytes reads
/// the file at `size` too ([`Store::blob_size`](crate::Store::blob_size)) —
/// a live lease over a file absent or not whole reads as lapsed, as the
/// daemon's binding and deposit read take it (`media.md` Op inventory 1, "a
/// live lease over a file that is not there reads as lapsed").
///
/// Deliberately not `#[non_exhaustive]`: the three states are the lease's
/// whole answer, and a consumer's exhaustive match — the daemon's binding —
/// gives each its own; a fourth breaks that match on purpose, where the `_`
/// arm `#[non_exhaustive]` demands of an outside crate would absorb it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LeaseState {
    /// A live lease, with its size and its expiry.
    Live { size: u64, expires: u64 },
    /// A lease lapsed within the horizon, with its expiry.
    Lapsed { expires: u64 },
    /// Neither live nor lapsed within the horizon.
    None,
}

/// The leases as held in memory beside their log.
///
/// They are keyed by `(designation, hex, principal)` — the hash first, and
/// ordered, so the leases on one hash are one range of the map: the
/// pruner's read of a hash ([`LeaseLog::any_live`]), which its pass makes
/// once per file under the daemon's exclusive arm, costs that hash's
/// holders and never every lease on the board, however many deposits a
/// principal makes. The map's order is also the compacted log's line order.
pub(crate) struct LeaseLog {
    log: Log,
    leases: BTreeMap<(String, String, String), Lease>,
    horizon: Duration,
}

impl LeaseLog {
    /// Opens the log under `root`, dropping what the horizon has passed.
    ///
    /// The tail is checked, the latest line of each principal's lease on
    /// each hash kept, every lease lapsed past the `horizon` at `now_ms`
    /// dropped, and the log rewritten where anything was dropped. Answers the
    /// log, what the reading found — the lines that read as no lease counted
    /// among it — and the count of leases the horizon dropped.
    ///
    /// # Errors
    ///
    /// The log's read, the cut of its tail or its open for appending
    /// failing (`Log::open`), or its rewrite failing (`Log::compact`).
    pub fn open(root: &Path, horizon: Duration, now_ms: u64) -> io::Result<(LeaseLog, LogRead, usize)> {
        let (log, values, mut found) = Log::open(root.join(LEASES_LOG))?;
        let (leases, unread) = fold(&values);
        found.unread = unread;
        let mut opened = LeaseLog { log, leases, horizon };
        let past_horizon = opened.drop_past_horizon(now_ms);
        opened.compact()?;
        Ok((opened, found, past_horizon))
    }

    /// Drops every lease past the horizon at `now_ms`, and answers how many.
    ///
    /// Each answers as none at `now_ms` and after already, so no read's
    /// answer moves. It is open's act, and the runtime compaction's before it
    /// judges its trigger, so the leases held, and every read that walks
    /// them, carry a deposit lapsed past the horizon only until the next
    /// runtime compaction drops it.
    fn drop_past_horizon(&mut self, now_ms: u64) -> usize {
        let (horizon, held) = (self.horizon, self.leases.len());
        self.leases.retain(|_, l| !l.past_horizon(horizon, now_ms));
        held - self.leases.len()
    }

    /// Reads the log as found, folded, with no horizon applied.
    ///
    /// Answers each principal's latest lease on each hash, in the map's
    /// order — every lease the log holds, lapsed ones included — and what the
    /// reading found (`Log::read_as_found`). The inspection's read, which
    /// cuts no tail, opens nothing for appending and creates no file.
    ///
    /// # Errors
    ///
    /// The log's read failing, save for its absence (`Log::read_as_found`).
    pub fn read_as_found(root: &Path) -> io::Result<(Vec<Lease>, LogRead)> {
        let (values, mut found) = Log::read_as_found(&root.join(LEASES_LOG))?;
        let (leases, unread) = fold(&values);
        found.unread = unread;
        Ok((leases.into_values().collect(), found))
    }

    /// Returns the count of leases held.
    ///
    /// It is the open's account's figure, read once the horizon has dropped
    /// what it drops.
    pub fn count(&self) -> usize {
        self.leases.len()
    }

    /// Appends and syncs `lease`, the principal's current lease on the hash.
    ///
    /// The PUT answers only after this returns.
    ///
    /// # Errors
    ///
    /// The append's refusal or failure (`Log::append_synced`): a stopped
    /// log, or a write or sync that failed.
    pub fn append_synced(&mut self, lease: Lease) -> io::Result<()> {
        self.log.append_synced(&lease.to_value())?;
        self.leases.insert((lease.designation.clone(), lease.hex.clone(), lease.principal.clone()), lease);
        Ok(())
    }

    /// Returns the principal's state on a hash at `now_ms`.
    pub fn state(&self, principal: &str, designation: &str, hex: &str, now_ms: u64) -> LeaseState {
        let Some(l) = self.leases.get(&(designation.to_string(), hex.to_string(), principal.to_string())) else {
            return LeaseState::None;
        };
        if l.live(now_ms) {
            LeaseState::Live { size: l.size, expires: l.expires }
        } else if l.past_horizon(self.horizon, now_ms) {
            LeaseState::None
        } else {
            LeaseState::Lapsed { expires: l.expires }
        }
    }

    /// Returns the principal's live leases at `now_ms`.
    ///
    /// They come in designation order, and in hex order within one.
    pub fn live_of(&self, principal: &str, now_ms: u64) -> Vec<Lease> {
        let mut out: Vec<Lease> =
            self.leases.values().filter(|l| l.principal == principal && l.live(now_ms)).cloned().collect();
        out.sort_by(|a, b| (&a.designation, &a.hex).cmp(&(&b.designation, &b.hex)));
        out
    }

    /// Returns the sizes of the principal's unplaced deposits, summed.
    ///
    /// They are its live leases at `now_ms` that `unplaced` admits.
    pub fn unplaced_of(&self, principal: &str, now_ms: u64, mut unplaced: impl FnMut(&Lease) -> bool) -> u64 {
        self.leases
            .values()
            .filter(|l| l.principal == principal && l.live(now_ms) && unplaced(l))
            .fold(0u64, |acc, l| acc.saturating_add(l.size))
    }

    /// Returns the sizes of every unplaced deposit at `now_ms`, summed.
    ///
    /// They are every principal's live leases that `unplaced` admits.
    pub fn unplaced_total(&self, now_ms: u64, mut unplaced: impl FnMut(&Lease) -> bool) -> u64 {
        self.leases
            .values()
            .filter(|l| l.live(now_ms) && unplaced(l))
            .fold(0u64, |acc, l| acc.saturating_add(l.size))
    }

    /// Returns whether any principal holds a live lease on the hash.
    ///
    /// The hash is `<designation>/<hex>`, the moment `now_ms`. It is the
    /// pruner's read, beside the per-principal [`LeaseLog::state`]: the range
    /// of the map holding that hash's leases, its key leading with the hash,
    /// so the pass that makes this read once per file is linear in its files.
    /// The range starts at the hash's first possible key and ends at the
    /// first key naming another hash: a hex the asked one begins, or a
    /// designation the asked one's begins, sorts beside it and is never read
    /// as it.
    pub fn any_live(&self, designation: &str, hex: &str, now_ms: u64) -> bool {
        self.leases
            .range((designation.to_string(), hex.to_string(), String::new())..)
            .take_while(|((d, h, _), _)| d == designation && h == hex)
            .any(|(_, l)| l.live(now_ms))
    }

    /// Rewrites the log to its current leases.
    ///
    /// It rewrites where a line on disk is not one, or where the log has
    /// stopped. The rewrite holds them in the map's order. Answers the size
    /// it rewrote the log from, `None` where it left the log as it was
    /// (`Log::compact`).
    ///
    /// # Errors
    ///
    /// The rewrite's failure (`Log::compact`).
    fn compact(&mut self) -> io::Result<Option<LogSize>> {
        self.log.compact(self.leases.values().map(Lease::to_value))
    }

    /// Runs the runtime compaction, the pruner's pass, as open applies it.
    ///
    /// Its steps (`media.md` Op inventory 1, "the pruner's pass rewrites
    /// either store the same way"): every lease past the horizon at `now_ms`
    /// dropped first ([`LeaseLog::drop_past_horizon`]), whether or not a
    /// rewrite follows — its line stays on disk until one does, or until the
    /// next open drops it again — then the upload records' trigger
    /// (`uploads::past_trigger`) over this log: rewritten where stopped, or
    /// where its whole lines number at least `min_lines` and more than
    /// `trigger` times the leases left. Answers the size a rewrite rewrote
    /// the log from, `None` where none ran. The caller holds this type's lock
    /// — the lock on this log's appends alone.
    ///
    /// # Errors
    ///
    /// The rewrite's failure (`Log::compact`).
    pub fn compact_if_past(&mut self, trigger: usize, min_lines: usize, now_ms: u64) -> io::Result<Option<LogSize>> {
        self.drop_past_horizon(now_ms);
        if !past_trigger(&self.log, self.leases.len(), trigger, min_lines) {
            return Ok(None);
        }
        self.compact()
    }

    /// Returns the log's stop, where it has stopped (`Log::stop`).
    pub fn log_stopped(&self) -> Option<LogStop> {
        self.log.stop()
    }

    /// Judges a lease's append ahead of the act that append follows.
    ///
    /// # Errors
    ///
    /// The refusal the append would meet, where the log has stopped
    /// (`Log::refuse_if_stopped`).
    pub fn refuse_if_stopped(&mut self) -> io::Result<()> {
        self.log.refuse_if_stopped()
    }

    /// Returns the log's size (`Log::size`).
    pub fn log_size(&self) -> LogSize {
        self.log.size()
    }
}

/// Folds a log's lines into the leases they leave.
///
/// Each principal's latest line on each hash stands, a line of no shape this
/// build reads folded to nothing — and counted, the second figure: the
/// lines read as no lease, which the open's account carries
/// ([`LogRead::unread`]).
fn fold(values: &[Value]) -> (BTreeMap<(String, String, String), Lease>, usize) {
    let mut leases = BTreeMap::new();
    let mut unread = 0;
    for v in values {
        match Lease::parse(v) {
            Some(l) => {
                leases.insert((l.designation.clone(), l.hex.clone(), l.principal.clone()), l);
            }
            None => unread += 1,
        }
    }
    (leases, unread)
}
