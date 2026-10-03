//! THE UPLOAD RECORDS, `<root>/uploads.log` — PATTERNS P22's honest-null
//! arm, as the lease log: one JSON line per change of one upload, its
//! current record its latest line; append-only; tail-checked at open and
//! compacted there to the current records, every retired upload dropped
//! (`media.md` Op inventory 1, the resumable upload (1), (3), (4), (6),
//! (7); §The media stores). A lost record reads as NO upload: its partial
//! is then an orphan open removes, and the resume starts afresh.
//!
//! THE IDENTIFIER (clause (1)): 128 bits drawn from the OS per upload,
//! never a sequence, spelled as 32 lowercase hex; it answers to the
//! uploader alone — a lookup takes the asking key, and an identifier whose
//! record is another key's answers exactly as one that was never minted
//! (the register M-I2 (e)).

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::blobs::{line_of, open_append, read_log, rewrite_log};

/// The identifier's width: 128 bits.
pub const IDENTIFIER_BYTES: usize = 16;

/// The log's file name under the root.
pub(crate) const UPLOADS_LOG: &str = "uploads.log";

/// One upload's identifier — 128 bits from the OS, compared exactly.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UploadId([u8; IDENTIFIER_BYTES]);

impl UploadId {
    /// A fresh identifier from the OS. Fail-stop on an OS that refuses
    /// entropy: an upload is never keyed by anything weaker.
    pub(crate) fn mint() -> io::Result<UploadId> {
        let mut raw = [0u8; IDENTIFIER_BYTES];
        getrandom::fill(&mut raw).map_err(|e| io::Error::other(format!("OS entropy: {e}")))?;
        Ok(UploadId(raw))
    }

    /// ONLY 32 lowercase hex; anything else is no identifier.
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

    /// The wire and file spelling: 32 lowercase hex.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Display for UploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for UploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UploadId({})", self.to_hex())
    }
}

/// One standing upload's record — the identifier bound to its uploader's
/// key, the designation, its declared length, the DURABLE offset (bytes
/// received), the expiry fixed from the last byte received, and a repair's
/// named cell (carried for the repair PUT; this crate reads nothing of it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadRecord {
    pub id: UploadId,
    pub key: String,
    pub designation: String,
    pub length: u64,
    pub offset: u64,
    pub expires: u64,
    pub repair: Option<String>,
}

impl UploadRecord {
    /// The partial's file name inside the designation directory —
    /// `.upload-<identifier>`: the dot keeps it apart from any hex name a
    /// walk of the directory reads as a blob.
    pub fn partial_name(&self) -> String {
        partial_name(&self.id)
    }

    /// The record as its log line's value.
    fn value(&self) -> Value {
        json!({
            "designation": self.designation,
            "expires": self.expires,
            "id": self.id.to_hex(),
            "key": self.key,
            "length": self.length,
            "offset": self.offset,
            "repair": self.repair,
        })
    }

    /// Whether the upload stands at `now_ms`: unexpired.
    pub fn stands(&self, now_ms: u64) -> bool {
        now_ms < self.expires
    }
}

/// The partial's name for an identifier.
pub(crate) fn partial_name(id: &UploadId) -> String {
    format!(".upload-{}", id.to_hex())
}

/// The identifier a partial's file name spells, if it is one.
pub(crate) fn id_of_partial_name(name: &str) -> Option<UploadId> {
    name.strip_prefix(".upload-").and_then(UploadId::parse)
}

/// One log line, read.
enum Line {
    Record(UploadRecord),
    Retired(UploadId),
}

fn parse_line(v: &Value) -> Option<Line> {
    let id = UploadId::parse(v.get("id")?.as_str()?)?;
    if v.get("retired").and_then(Value::as_bool) == Some(true) {
        return Some(Line::Retired(id));
    }
    Some(Line::Record(UploadRecord {
        id,
        key: v.get("key")?.as_str()?.to_string(),
        designation: v.get("designation")?.as_str()?.to_string(),
        length: v.get("length")?.as_u64()?,
        offset: v.get("offset")?.as_u64()?,
        expires: v.get("expires")?.as_u64()?,
        repair: v.get("repair").and_then(Value::as_str).map(str::to_string),
    }))
}

/// The records as held in memory beside their log.
pub(crate) struct UploadRecords {
    path: PathBuf,
    file: File,
    records: HashMap<UploadId, UploadRecord>,
    /// Lines on disk, so compaction knows whether anything was dropped.
    lines_on_disk: usize,
}

impl UploadRecords {
    /// Open the log under `root`: the tail checked, every line folded —
    /// a record line replacing the one before it, a retirement dropping
    /// it. Compaction is the caller's, after the reconciliation with the
    /// partials ([`UploadRecords::compact`]).
    pub fn open(root: &Path) -> io::Result<UploadRecords> {
        let path = root.join(UPLOADS_LOG);
        let (values, _cut) = read_log(&path)?;
        let mut records = HashMap::new();
        let mut lines_on_disk = 0;
        for v in &values {
            lines_on_disk += 1;
            match parse_line(v) {
                Some(Line::Record(r)) => {
                    records.insert(r.id, r);
                }
                Some(Line::Retired(id)) => {
                    records.remove(&id);
                }
                // A line of a shape this build does not read: kept on
                // disk (compaction drops it, honestly: it named no record
                // this build holds).
                None => {}
            }
        }
        let file = open_append(&path)?;
        Ok(UploadRecords { path, file, records, lines_on_disk })
    }

    pub fn get(&self, id: &UploadId) -> Option<&UploadRecord> {
        self.records.get(id)
    }

    pub fn all(&self) -> impl Iterator<Item = &UploadRecord> {
        self.records.values()
    }

    /// Append `record` as the upload's current line; `sync` fsyncs the
    /// log, which a durable offset owes (the byte is received once the
    /// partial AND its record's offset are on disk).
    pub fn put(&mut self, record: UploadRecord, sync: bool) -> io::Result<()> {
        let line = line_of(&record.value());
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        if sync {
            self.file.sync_all()?;
        } else {
            self.file.flush()?;
        }
        self.lines_on_disk += 1;
        self.records.insert(record.id, record);
        Ok(())
    }

    /// Retire an upload: its line appended, the record dropped. A lost
    /// retirement line costs nothing — a record whose partial is gone is
    /// retired by open's reconciliation.
    pub fn retire(&mut self, id: &UploadId) -> io::Result<()> {
        if self.records.remove(id).is_none() {
            return Ok(());
        }
        let line = line_of(&json!({"id": id.to_hex(), "retired": true}));
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.lines_on_disk += 1;
        Ok(())
    }

    /// Rewrite the log to the current records where any line on disk is
    /// not one — so the log never grows with the board's upload history.
    pub fn compact(&mut self) -> io::Result<()> {
        if self.lines_on_disk == self.records.len() {
            return Ok(());
        }
        let mut ids: Vec<&UploadId> = self.records.keys().collect();
        ids.sort_by_key(|id| id.to_hex());
        let lines: Vec<String> =
            ids.iter().map(|id| line_of(&self.records[*id].value())).collect();
        self.file = rewrite_log(&self.path, &lines)?;
        self.lines_on_disk = lines.len();
        Ok(())
    }
}
