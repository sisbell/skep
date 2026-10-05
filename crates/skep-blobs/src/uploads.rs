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
//! A RECORD CHANGES BY ITS HOLDER's ACTS ALONE (`media.md` §The media
//! stores, THE UPLOAD RECORDS — written at an upload's creation and after
//! each durable append, set back at open to a shorter partial's length,
//! retired): [`UploadRecords::create`], [`UploadRecords::mark_received`],
//! [`UploadRecords::set_back`] and [`UploadRecords::retire`]. Each moves the
//! figures its act names and keeps the rest — the expiry fixed by the
//! creation and re-fixed by a byte received, and moved by nothing else
//! (clause (3)) — and no caller hands the holder a record: its callers
//! choose when a record changes, never what the change is.
//!
//! AN IDENTIFIER (`uploads/id.rs`) ANSWERS TO ITS UPLOADER ALONE: a lookup
//! takes the asking principal, and an identifier whose record is another
//! principal's answers exactly as one that was never minted (the register
//! M-I2 (e)). The check is [`UploadRecords`]' own: every lookup it answers
//! takes the asking principal, and its one lookup by identifier alone serves
//! the pruner's expiry, which acts on an expired upload whatever principal
//! minted it.

// The identifier: its 128 OS bits, its spelling and its two parses — the
// one file that makes an `UploadId`.
mod id;

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

use crate::blobs::designation_ok;
use crate::error::BlobError;
use crate::jsonl::Log;

pub use id::{NotAnUploadId, UploadId, IDENTIFIER_BYTES};

/// The log's file name under the root.
const UPLOADS_LOG: &str = "uploads.log";

/// A span as the whole milliseconds the logs spell and the expiries add —
/// saturating where it passes `u64`, as every expiry the store fixes does.
pub(crate) fn millis(span: Duration) -> u64 {
    u64::try_from(span.as_millis()).unwrap_or(u64::MAX)
}

/// THE ONE EXPIRY RULE, for both expiries the store fixes: `interval`
/// past `now_ms`, saturating. An upload's is fixed at its creation from the
/// interval handed in then, which its record keeps, and at each byte
/// received from that kept interval (clause (3); [`UploadRecords::create`],
/// [`UploadRecords::mark_received`]); a lease's at its PUT, from the
/// interval handed to the finish ([`Store::finish`](crate::Store::finish);
/// `media.md` Op inventory 1, "THE LEASE'S STORE, SCOPE AND EXPIRY,
/// STATED"). No caller computes an expiry the store then trusts. An instant
/// is unix milliseconds, the `u64` the logs and the wire spell; a span is a
/// [`Duration`] — so the clock reading and an interval never trade places
/// at a call and compile.
pub(crate) fn expiry(now_ms: u64, interval: Duration) -> u64 {
    now_ms.saturating_add(millis(interval))
}

/// One standing upload's record (clause (1)) — the identifier bound to its
/// uploader, the designation, its declared length, the DURABLE offset
/// (bytes received), the interval fixed at its creation, and the expiry
/// fixed from the last byte received.
///
/// ITS OFFSET NEVER PASSES ITS LENGTH. Each of the four gates a record
/// passes keeps it: its creation (`UploadRecords::create`) writes 0; a byte
/// received (`UploadRecords::mark_received`) writes the bytes a handle
/// holds, which [`Store::append`](crate::Store::append) refuses to take past
/// the length; open's set-back (`UploadRecords::set_back`) only ever lowers
/// an offset, to a shorter partial's length; and a line read back at open
/// whose offset passes its length reads as no record (`parse_line`). So
/// every standing upload can still reach its length and be finished.
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
/// record ([`UploadRecords::all`]). And changed only by its own acts —
/// [`UploadRecords::create`], [`UploadRecords::mark_received`],
/// [`UploadRecords::set_back`], [`UploadRecords::retire`] — whose one
/// append, [`UploadRecords::write`], is private to this file: no record
/// reaches the map or the log but one an act built.
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

    /// THE RECORD's BIRTH (clause (1)): `principal`'s upload `id` of
    /// `designation` and declared `length` — offset 0, THE UPLOAD's INTERVAL
    /// held as its line spells it, in whole milliseconds, so the record open
    /// reads back is the record answered here, and its first expiry that
    /// interval past `now_ms` — written, synced and answered. The store
    /// creates the partial first and hands a designation its name check has
    /// admitted ([`Store::create_upload`](crate::Store::create_upload)).
    pub fn create(
        &mut self,
        id: UploadId,
        principal: &str,
        designation: &str,
        length: u64,
        interval: Duration,
        now_ms: u64,
    ) -> io::Result<UploadRecord> {
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
        self.write(record.clone())?;
        Ok(record)
    }

    /// MARK THE BYTES RECEIVED through `offset` (clause (3)): the
    /// principal's record's offset set to it and its expiry re-fixed the
    /// record's own interval past `now_ms`, written and synced, the rest
    /// kept. `NoUpload` where `principal`'s records do not name `id`, nothing
    /// written. The store marks only after the partial's sync, at the bytes
    /// a handle holds ([`Store::append`](crate::Store::append),
    /// [`Store::settle`](crate::Store::settle)).
    pub fn mark_received(&mut self, principal: &str, id: &UploadId, offset: u64, now_ms: u64) -> Result<(), BlobError> {
        let mut next = self.of_principal(principal, id).ok_or(BlobError::NoUpload)?.clone();
        next.offset = offset;
        next.expires = expiry(now_ms, next.interval);
        self.write(next)?;
        Ok(())
    }

    /// SET AN OFFSET BACK at open (clause (4)): the record's offset lowered
    /// to `offset`, the length of a partial shorter than it, written and
    /// synced — its expiry KEPT: a set-back receives no byte, and nothing but
    /// a byte received re-fixes an expiry (clause (3)). It only ever lowers:
    /// where no record is held, or its offset is not past `offset`, there is
    /// nothing to set back and nothing is written. Open's reconciliation's
    /// act (`partials::reconcile`), by identifier alone as its walk is.
    pub fn set_back(&mut self, id: &UploadId, offset: u64) -> io::Result<()> {
        let Some(mut next) = self.records.get(id).filter(|r| offset < r.offset).cloned() else {
            return Ok(());
        };
        next.offset = offset;
        self.write(next)
    }

    /// WRITE `record` as the upload's current line — appended and SYNCED —
    /// and hold it: the one append the creation, a byte received and a
    /// set-back share, each handing it the record its act built. A byte
    /// counts as received only once the partial AND its record's offset are
    /// on disk.
    fn write(&mut self, record: UploadRecord) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// EACH ACT MOVES THE FIGURES IT NAMES AND KEEPS THE REST, and writes a
    /// line only where it changes one: the creation holds its interval as
    /// the line spells it; a byte received moves the offset and re-fixes the
    /// expiry the record's own interval past it, for the principal the
    /// record answers to alone; a set-back lowers the offset and keeps the
    /// expiry, and raises nothing — the record read back at the next open as
    /// the last act answered it.
    #[test]
    fn each_act_moves_the_figures_it_names_and_keeps_the_rest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lines = || fs::read_to_string(dir.path().join(UPLOADS_LOG)).unwrap().lines().count();
        let mut records = UploadRecords::open(dir.path()).unwrap();
        let id = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let born = records.create(id, "k", "blake3", 10, Duration::from_micros(2_500), 100).unwrap();
        assert_eq!((born.offset, born.interval, born.expires), (0, Duration::from_millis(2), 102), "its birth");
        assert!(matches!(records.mark_received("other", &id, 5, 200), Err(BlobError::NoUpload)));
        records.mark_received("k", &id, 6, 200).unwrap();
        let received = records.of_principal("k", &id).cloned().unwrap();
        assert_eq!((received.offset, received.expires), (6, 202), "re-fixed its own interval past the byte");
        assert_eq!((received.interval, received.length), (born.interval, born.length), "the rest kept");
        assert_eq!(lines(), 2, "a line for the birth and one for the byte, none for another principal's mark");
        for not_lower in [6, 7] {
            records.set_back(&id, not_lower).unwrap();
        }
        records.set_back(&UploadId::parse("fedcba9876543210fedcba9876543210").unwrap(), 1).unwrap();
        assert_eq!(records.of_principal("k", &id), Some(&received), "a set-back raises nothing");
        assert_eq!(lines(), 2, "and writes nothing where it lowers nothing");
        records.set_back(&id, 4).unwrap();
        let set_back = records.of_principal("k", &id).cloned().unwrap();
        assert_eq!((set_back.offset, set_back.expires), (4, 202), "lowered, its expiry kept");
        drop(records);
        let reopened = UploadRecords::open(dir.path()).unwrap();
        assert_eq!(reopened.of_principal("k", &id), Some(&set_back), "read back as the last act answered it");
    }
}
