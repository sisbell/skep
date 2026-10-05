//! THE JSON-LINES LOG both record logs are — `uploads.log` and
//! `leases.log`, PATTERNS P22's honest-null arm (`media.md` Op inventory 1,
//! "EACH KEY's CURRENT RECORD IS ITS LATEST, AND OPEN COMPACTS BOTH
//! STORES"; §The media stores): one JSON object per line, members in sorted
//! order; appended, a figure that must be durable fsynced with its line;
//! read whole at open, trust ending at the first torn line, which is cut off
//! the file; and compacted by the blob's own install order, so a crash
//! mid-compaction leaves the old log whole or the new one, never a mix.
//!
//! A TORN LINE IS ONLY EVER THE TAIL. Open's tail check cuts the file at the
//! first torn line and everything after it, so a whole line written past a
//! torn one would go with it — a lease the PUT answered over, an offset a
//! settle answered. A crash tears at most the last line; an append that
//! FAILS while the process runs — a write cut short by a full disk, a sync
//! refused — is cut back off the file, so the next append starts on a whole
//! line; and where that cut fails too the log STOPS, taking no further
//! append, so the torn line stays the tail the next open cuts. A compaction
//! that fails past its rename stops it too: the rewrite then stands at the
//! log's name, and the file an append would write is the one it replaced,
//! which no open reads. [`Log`] owns the file, the length and the count of
//! its whole lines, and the stop; what a line means is its store's
//! (`uploads.rs`, `lease.rs`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::blobs::{fsync_dir, not_found_as_none};

/// One JSON-lines log: its path, its append-mode file, the byte length and
/// the count of the whole lines the file holds, and whether it has
/// stopped. The length is what a failed append is cut back to and the
/// count the one figure the compaction reads; this type's own appends and
/// rewrites alone move them.
pub(crate) struct Log {
    path: PathBuf,
    file: File,
    len: u64,
    lines: usize,
    /// An append failed and its cut-back failed too — the file may end in a
    /// torn line, and a line appended after it would be cut with it at the
    /// next open — or a compaction failed past its rename, where the rewrite
    /// stands at the path and the open file, the length and the count are
    /// still the replaced file's, so an append would answer durable over a
    /// line no open reads. A stopped log takes no append; a compaction that
    /// completes, which writes the file whole, lifts the stop.
    stopped: bool,
}

impl Log {
    /// Open the log at `path`, created where absent: read whole, trust
    /// ending at the first line that is no JSON object or that lacks its
    /// newline (a torn tail), which is TRUNCATED off the file there and
    /// never read past (the honest-null arm's tail check). Answers the log
    /// and the values of its lines, in order.
    pub fn open(path: PathBuf) -> io::Result<(Log, Vec<Value>)> {
        let (values, len) = read_log(&path)?;
        let file = open_append(&path)?;
        let lines = values.len();
        Ok((Log { path, file, len, lines, stopped: false }, values))
    }

    /// Append `v` as the log's next line and fsync it — what a figure that
    /// must be durable owes. Undone where it fails ([`Log::append_by`]).
    pub fn append_synced(&mut self, v: &Value) -> io::Result<()> {
        self.append_by(v, |file, line| {
            file.write_all(line)?;
            file.sync_all()
        })
    }

    /// Append `v` as the log's next line, its durability left to the OS —
    /// for a line whose loss costs nothing. Undone where it fails
    /// ([`Log::append_by`]).
    pub fn append_unsynced(&mut self, v: &Value) -> io::Result<()> {
        self.append_by(v, |file, line| file.write_all(line))
    }

    /// THE APPEND's ONE BODY, its write — and its sync, where the line owes
    /// one — handed in as `write`: the line and its newline in one write. A
    /// write or sync that FAILS is undone: the file cut back to its whole
    /// lines and the cut synced, so a failed append leaves the file as it
    /// found it — what each store's map, moved only after an append returns
    /// (save a retirement's, dropped first: `UploadRecords::retire` says
    /// why), already assumes. Where the cut fails too, the log stops and the
    /// append answers its own failure; a stopped log refuses every later
    /// append. The unit suite drives it with a write that fails partway.
    fn append_by(&mut self, v: &Value, write: impl FnOnce(&mut File, &[u8]) -> io::Result<()>) -> io::Result<()> {
        if self.stopped {
            return Err(io::Error::other(format!(
                "{} takes no append until a compaction completes: an earlier append could not be cut back off \
                 it, or a compaction failed past its rename",
                self.path.display()
            )));
        }
        let line = line_of(v);
        if let Err(e) = write(&mut self.file, &line) {
            if self.file.set_len(self.len).and_then(|()| self.file.sync_all()).is_err() {
                self.stopped = true;
            }
            return Err(e);
        }
        self.len += line.len() as u64;
        self.lines += 1;
        Ok(())
    }

    /// THE COMPACTION: rewrite the log to exactly `current`, in order, where
    /// the file holds anything else — every append adds a line, so a log
    /// that has not stopped and whose count equals its current records'
    /// holds nothing else, and is left as it is. The rewrite is written to a
    /// `.compact` twin beside the log, fsynced, renamed over it, the
    /// directory fsynced — the same install order a blob takes; it writes
    /// the file whole, so once it completes it lifts a stop. One that fails
    /// before its rename leaves the log as it was; one that fails past it
    /// stops the log until a compaction completes.
    pub fn compact(&mut self, current: impl ExactSizeIterator<Item = Value>) -> io::Result<()> {
        if !self.stopped && current.len() == self.lines {
            return Ok(());
        }
        let dir = self.path.parent().expect("a log sits in a directory");
        let twin = self.path.with_extension("compact");
        let mut len = 0;
        let mut lines = 0;
        {
            let mut f = File::create(&twin)?;
            for v in current {
                let line = line_of(&v);
                f.write_all(&line)?;
                len += line.len() as u64;
                lines += 1;
            }
            f.sync_all()?;
        }
        fs::rename(&twin, &self.path)?;
        // Past the rename the rewrite stands at the path, and the open file,
        // the length and the count are the replaced file's: stopped until
        // the install order completes and they are the rewrite's.
        self.stopped = true;
        fsync_dir(dir)?;
        self.file = open_append(&self.path)?;
        self.len = len;
        self.lines = lines;
        self.stopped = false;
        Ok(())
    }
}

/// The values of a log's whole lines in order and their byte length, the
/// torn tail cut off the file there ([`Log::open`]'s read). An absent log
/// holds none.
fn read_log(path: &Path) -> io::Result<(Vec<Value>, u64)> {
    let Some(bytes) = not_found_as_none(fs::read(path))? else {
        return Ok((Vec::new(), 0));
    };
    let mut values = Vec::new();
    let mut good = 0;
    for line in bytes.split_inclusive(|&b| b == b'\n') {
        // Trust ends at the first torn line — one with no newline, being
        // written when the process died, or one that is no JSON object —
        // and nothing past it is read.
        let Some(v) = line
            .strip_suffix(b"\n")
            .and_then(|body| serde_json::from_slice::<Value>(body).ok())
            .filter(Value::is_object)
        else {
            break;
        };
        values.push(v);
        good += line.len();
    }
    if good < bytes.len() {
        OpenOptions::new().write(true).open(path)?.set_len(good as u64)?;
    }
    Ok((values, good as u64))
}

/// Open the log at `path` for appending, creating it where absent.
fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// One JSON object as its line, members in sorted order (serde_json's map
/// is a sorted map), newline and all.
fn line_of(v: &Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(v).expect("a JSON value renders");
    line.push(b'\n');
    line
}

#[cfg(test)]
mod tests;
