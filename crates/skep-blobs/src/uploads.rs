//! THE UPLOAD RECORDS, `<root>/uploads.log` — PATTERNS P22's honest-null
//! arm, as the lease log: one JSON line per change of one upload, its
//! current record its latest line; append-only; tail-checked at open and
//! compacted there to the current records, every retired upload dropped
//! (`media.md` Op inventory 1, the resumable upload (1), (3), (4), (6),
//! (7); §The media stores). A lost record reads as NO upload: its partial
//! is then an orphan open removes, and the resume starts afresh. A record
//! line naming a designation the store's name check refuses reads as lost
//! too — the log's lines meet the check a caller's names meet
//! (`parse_line`) — so a log restored from elsewhere names no path out of
//! the root. A record line whose offset passes its length, which no act
//! writes, reads as lost as well.
//!
//! THE IDENTIFIER (clause (1)): 128 bits drawn from the OS per upload,
//! never a sequence, spelled as 32 lowercase hex; it answers to the
//! uploader alone — a lookup takes the asking principal, and an identifier
//! whose record is another principal's answers exactly as one that was
//! never minted (the register M-I2 (e)). The check is [`UploadRecords`]'
//! own: every lookup it answers takes the asking principal, and its one
//! lookup by identifier alone serves the pruner's expiry, which acts on an
//! expired upload whatever principal minted it.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use serde_json::{json, Value};

use crate::blobs::designation_ok;
use crate::jsonl::Log;

/// The identifier's width: 128 bits.
pub const IDENTIFIER_BYTES: usize = 16;

/// The log's file name under the root.
const UPLOADS_LOG: &str = "uploads.log";

/// A span as the whole milliseconds the logs spell and the expiries add —
/// saturating where it passes `u64`, as every expiry the store fixes does.
pub(crate) fn millis(span: Duration) -> u64 {
    u64::try_from(span.as_millis()).unwrap_or(u64::MAX)
}

/// One upload's identifier — 128 bits from the OS, compared exactly, and
/// ordered by its bytes, which is the order of its hex spelling.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UploadId([u8; IDENTIFIER_BYTES]);

impl UploadId {
    /// A fresh identifier from the OS. Fail-stop on an OS that refuses
    /// entropy: an upload is never keyed by anything weaker.
    pub(crate) fn mint() -> io::Result<UploadId> {
        let mut raw = [0u8; IDENTIFIER_BYTES];
        getrandom::fill(&mut raw).map_err(|e| io::Error::other(format!("OS entropy: {e}")))?;
        Ok(UploadId(raw))
    }

    /// ONLY 32 lowercase hex; anything else is no identifier. The predicate
    /// form, which the daemon's path parse uses; [`FromStr`] answers the
    /// same text with a refusal a generic caller can propagate.
    pub fn parse(s: &str) -> Option<UploadId> {
        let b = s.as_bytes();
        if b.len() != 2 * IDENTIFIER_BYTES {
            return None;
        }
        let nibble = |d: u8| match d {
            b'0'..=b'9' => Some(d - b'0'),
            b'a'..=b'f' => Some(d - b'a' + 10),
            _ => None,
        };
        let mut raw = [0u8; IDENTIFIER_BYTES];
        for (slot, pair) in raw.iter_mut().zip(b.chunks(2)) {
            *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Some(UploadId(raw))
    }

    /// The wire and file spelling: 32 lowercase hex, the identifier's
    /// [`Display`](fmt::Display) as a `String`.
    pub fn to_hex(&self) -> String {
        self.to_string()
    }
}

/// The spelling, written a byte at a time: 32 lowercase hex.
impl fmt::Display for UploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for UploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UploadId({self})")
    }
}

/// [`UploadId::parse`] refused: the text is not 32 lowercase hex. Carries
/// no reason — the spelling is one shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NotAnUploadId;

impl fmt::Display for NotAnUploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not an upload identifier (32 lowercase hex)")
    }
}

impl std::error::Error for NotAnUploadId {}

/// The ecosystem's spelling of [`UploadId::parse`]: what a generic caller —
/// an argument parser, an environment reader — can reach, the same spelling
/// admitted and anything else refused as [`NotAnUploadId`].
impl FromStr for UploadId {
    type Err = NotAnUploadId;

    fn from_str(s: &str) -> Result<UploadId, NotAnUploadId> {
        UploadId::parse(s).ok_or(NotAnUploadId)
    }
}

/// One standing upload's record (clause (1)) — the identifier bound to its
/// uploader, the designation, its declared length, the DURABLE offset
/// (bytes received), the interval fixed at its creation, and the expiry
/// fixed from the last byte received.
///
/// ITS OFFSET NEVER PASSES ITS LENGTH. Each of the four gates a record
/// passes keeps it: its creation writes 0; a byte received writes the bytes
/// a handle holds, and an append refuses past the length; open's
/// reconciliation sets an offset back to a shorter partial's length; and a
/// line read back at open whose offset passes its length reads as no record
/// (`parse_line`). So every standing upload can still reach its length and
/// be finished.
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — field
/// reads are unaffected, and a further field is an addition rather than a
/// broken build.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct UploadRecord {
    pub id: UploadId,
    /// The uploader — the principal the upload answers to alone (clause
    /// (1)), as its caller spells it.
    pub principal: String,
    pub designation: String,
    pub length: u64,
    pub offset: u64,
    /// THE UPLOAD's INTERVAL — fixed at its creation from the limits in
    /// force then and held here (clauses (1), (3)): each byte received
    /// re-fixes `expires` this far past it, and a later limits record never
    /// reaches a standing upload. Held in the whole milliseconds its log
    /// line spells, so the record read back at open is the record answered.
    pub interval: Duration,
    /// The instant the upload stops standing, unix milliseconds.
    pub expires: u64,
}

impl UploadRecord {
    /// The record as its log line's value. The stored format spells the
    /// principal's member `key`, as the lease log's line does, and the
    /// interval in whole milliseconds.
    fn to_value(&self) -> Value {
        json!({
            "designation": self.designation,
            "expires": self.expires,
            "id": self.id.to_hex(),
            "interval": millis(self.interval),
            "key": self.principal,
            "length": self.length,
            "offset": self.offset,
        })
    }

    /// Whether the upload stands at `now_ms`: unexpired.
    pub(crate) fn stands(&self, now_ms: u64) -> bool {
        now_ms < self.expires
    }
}

/// One log line, read.
enum Line {
    Record(UploadRecord),
    Retirement(UploadId),
}

/// A line's value read as a record or a retirement — `None` for a value of
/// no shape this build reads. Among them, a record line lacking any member
/// it carries (its interval included): the store holds no value of its own
/// to put in a missing member's place. And a record line naming a
/// designation the store's name check refuses (`designation_ok`, the check
/// [`Store::create_upload`](crate::Store::create_upload) makes): no creation
/// writes one, but a log restored from elsewhere (`media.md` §Recovery) may,
/// and read, its designation would be the directory open's reconciliation
/// cuts a partial back in or removes one from — above the root through
/// `..`, anywhere as an absolute path. It reads as a lost record does. So
/// does a record line whose offset passes its length, the one gate of
/// [`UploadRecord`]'s invariant a line from disk meets: no act writes one,
/// and standing, its upload would refuse every resume, never reach a
/// finish, and count past its length in its principal's pending bytes
/// until it expired.
fn parse_line(v: &Value) -> Option<Line> {
    let id = UploadId::parse(v.get("id")?.as_str()?)?;
    if v.get("retired").and_then(Value::as_bool) == Some(true) {
        return Some(Line::Retirement(id));
    }
    let length = v.get("length")?.as_u64()?;
    Some(Line::Record(UploadRecord {
        id,
        principal: v.get("key")?.as_str()?.to_string(),
        designation: v.get("designation")?.as_str().filter(|d| designation_ok(d))?.to_string(),
        length,
        offset: v.get("offset")?.as_u64().filter(|&offset| offset <= length)?,
        interval: Duration::from_millis(v.get("interval")?.as_u64()?),
        expires: v.get("expires")?.as_u64()?,
    }))
}

/// The records as held in memory beside their log — answered by the asking
/// principal, as the lease log answers its leases: a record goes only to
/// the principal that minted it, save to the pruner's lookup by identifier
/// alone ([`UploadRecords::of_any_principal`]) and open's walk of every
/// record ([`UploadRecords::all`]).
pub(crate) struct UploadRecords {
    log: Log,
    records: HashMap<UploadId, UploadRecord>,
}

impl UploadRecords {
    /// Open the log under `root`: the tail checked, every line folded —
    /// a record line replacing the one before it, a retirement dropping
    /// it. Compaction is the caller's, after the reconciliation with the
    /// partials ([`UploadRecords::compact`]).
    pub fn open(root: &Path) -> io::Result<UploadRecords> {
        let (log, values) = Log::open(root.join(UPLOADS_LOG))?;
        let mut records = HashMap::new();
        for v in &values {
            match parse_line(v) {
                Some(Line::Record(r)) => {
                    records.insert(r.id, r);
                }
                Some(Line::Retirement(id)) => {
                    records.remove(&id);
                }
                // A line of a shape this build does not read: kept on
                // disk (compaction drops it, honestly: it named no record
                // this build holds).
                None => {}
            }
        }
        Ok(UploadRecords { log, records })
    }

    /// THE PRINCIPAL's record by identifier, whatever its expiry — `None`
    /// for an identifier `principal`'s records do not name. The appends'
    /// and the durable point's lookup.
    pub fn of_principal(&self, principal: &str, id: &UploadId) -> Option<&UploadRecord> {
        self.records.get(id).filter(|r| r.principal == principal)
    }

    /// THE PRINCIPAL's STANDING record by identifier — `None` for an
    /// identifier `principal`'s records do not name or whose upload has
    /// expired at `now_ms`, one answer for both (M-I2 (e)).
    pub fn standing(&self, principal: &str, id: &UploadId, now_ms: u64) -> Option<&UploadRecord> {
        self.of_principal(principal, id).filter(|r| r.stands(now_ms))
    }

    /// THE PRINCIPAL's standing uploads at `now_ms`, in identifier order.
    pub fn standing_of(&self, principal: &str, now_ms: u64) -> Vec<UploadRecord> {
        let mut out: Vec<UploadRecord> = self
            .records
            .values()
            .filter(|r| r.principal == principal && r.stands(now_ms))
            .cloned()
            .collect();
        out.sort_by_key(|r| r.id);
        out
    }

    /// EVERY principal's expired uploads at `now_ms`, in identifier order —
    /// the pruner's read.
    pub fn expired(&self, now_ms: u64) -> Vec<UploadRecord> {
        let mut out: Vec<UploadRecord> = self.records.values().filter(|r| !r.stands(now_ms)).cloned().collect();
        out.sort_by_key(|r| r.id);
        out
    }

    /// The sum of the principal's standing uploads' durable offsets at
    /// `now_ms` — its bytes received and not yet finished.
    pub fn received_of(&self, principal: &str, now_ms: u64) -> u64 {
        self.records
            .values()
            .filter(|r| r.principal == principal && r.stands(now_ms))
            .fold(0u64, |acc, r| acc.saturating_add(r.offset))
    }

    /// The sum of every principal's standing uploads' durable offsets at
    /// `now_ms`.
    pub fn received_total(&self, now_ms: u64) -> u64 {
        self.records.values().filter(|r| r.stands(now_ms)).fold(0u64, |acc, r| acc.saturating_add(r.offset))
    }

    /// ANY principal's record by identifier — the one lookup by identifier
    /// alone, which serves the pruner's expiry alone
    /// ([`Store::expire_upload`](crate::Store::expire_upload)): that act
    /// removes an expired upload whoever minted it, and answers nothing of
    /// the record.
    pub fn of_any_principal(&self, id: &UploadId) -> Option<&UploadRecord> {
        self.records.get(id)
    }

    /// Every record, every principal's — the walk open's reconciliation
    /// makes over them all, and nothing else.
    pub fn all(&self) -> impl Iterator<Item = &UploadRecord> {
        self.records.values()
    }

    /// WRITE `record` as the upload's current line — appended and SYNCED:
    /// a record's line carries the upload's birth, the offset received, or
    /// that offset set back at open, and a byte counts as received only
    /// once the partial AND its record's offset are on disk.
    pub fn write(&mut self, record: UploadRecord) -> io::Result<()> {
        self.log.append_synced(&record.to_value())?;
        self.records.insert(record.id, record);
        Ok(())
    }

    /// Retire an upload: the record dropped, THEN its line appended — the
    /// one write of either store whose map moves before its append returns.
    /// Every caller retires an upload whose partial is already gone — a
    /// finish's rename took it, an end, an expiry or open removed it — so a
    /// record kept here over a failed line would answer as standing over
    /// nothing, while a lost retirement line costs nothing: open's
    /// reconciliation retires a record whose partial is gone. So the record
    /// goes first, and the line's durability is left to the OS.
    pub fn retire(&mut self, id: &UploadId) -> io::Result<()> {
        if self.records.remove(id).is_none() {
            return Ok(());
        }
        self.log.append_unsynced(&json!({"id": id.to_hex(), "retired": true}))
    }

    /// Rewrite the log to the current records where any line on disk is
    /// not one — so the log never grows with the board's upload history.
    pub fn compact(&mut self) -> io::Result<()> {
        let mut ids: Vec<&UploadId> = self.records.keys().collect();
        ids.sort();
        self.log.compact(ids.into_iter().map(|id| self.records[id].to_value()))
    }
}
