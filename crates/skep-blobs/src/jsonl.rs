//! THE JSON-LINES LOG both record logs are — `uploads.log` and
//! `leases.log`, PATTERNS P22's honest-null arm (`media.md` Op inventory 1,
//! "EACH KEY's CURRENT RECORD IS ITS LATEST, AND OPEN COMPACTS BOTH
//! STORES"; §The media stores): one JSON object per line, members in sorted
//! order; appended, a figure that must be durable fsynced with its line;
//! read whole at open, trust ending at the first torn line, which is cut off
//! the file; and compacted by the blob's own install order, so a crash
//! mid-compaction leaves the old log whole or the new one, never a mix.
//! [`Log`] owns the file and the count of the lines it holds; what a line
//! means is its store's (`uploads.rs`, `lease.rs`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::blobs::fsync_dir;

/// One JSON-lines log: its path, its append handle, and the count of the
/// lines the file holds — the one figure the compaction reads, moved by
/// this type's own appends and rewrites alone.
pub(crate) struct Log {
    path: PathBuf,
    file: File,
    lines: usize,
}

impl Log {
    /// Open the log at `path`, created where absent: read whole, trust
    /// ending at the first line that is no JSON object or that lacks its
    /// newline (a torn tail), which is TRUNCATED off the file there and
    /// never read past (the honest-null arm's tail check). Answers the log
    /// and the values of its lines, in order.
    pub fn open(path: PathBuf) -> io::Result<(Log, Vec<Value>)> {
        let values = read_log(&path)?;
        let file = open_append(&path)?;
        let lines = values.len();
        Ok((Log { path, file, lines }, values))
    }

    /// Append `v` as the log's next line — fsynced where `sync`, which a
    /// figure that must be durable owes, flushed otherwise.
    pub fn append(&mut self, v: &Value, sync: bool) -> io::Result<()> {
        self.file.write_all(line_of(v).as_bytes())?;
        self.file.write_all(b"\n")?;
        if sync {
            self.file.sync_all()?;
        } else {
            self.file.flush()?;
        }
        self.lines += 1;
        Ok(())
    }

    /// THE COMPACTION: rewrite the log to exactly `current`, in order, where
    /// its line count is not `current`'s — every append adds a line, so a
    /// log whose count equals its current records' holds nothing else, and
    /// is left as it is. The rewrite is written to a `.compact` twin beside
    /// the log, fsynced, renamed over it, the directory fsynced — the same
    /// install order a blob takes.
    pub fn compact(&mut self, current: impl ExactSizeIterator<Item = Value>) -> io::Result<()> {
        if current.len() == self.lines {
            return Ok(());
        }
        let dir = self.path.parent().expect("a log sits in a directory");
        let twin = self.path.with_extension("compact");
        let mut lines = 0;
        {
            let mut f = File::create(&twin)?;
            for v in current {
                f.write_all(line_of(&v).as_bytes())?;
                f.write_all(b"\n")?;
                lines += 1;
            }
            f.sync_all()?;
        }
        fs::rename(&twin, &self.path)?;
        fsync_dir(dir)?;
        self.file = open_append(&self.path)?;
        self.lines = lines;
        Ok(())
    }
}

/// The values of a log's lines in order, the torn tail cut off the file
/// ([`Log::open`]'s read). An absent log holds none.
fn read_log(path: &Path) -> io::Result<Vec<Value>> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    }
    let mut values = Vec::new();
    let mut good = 0usize;
    let mut cut = false;
    let mut at = 0usize;
    while at < bytes.len() {
        let Some(nl) = bytes[at..].iter().position(|&b| b == b'\n') else {
            cut = true; // no newline: a line being written when the process died
            break;
        };
        let line = &bytes[at..at + nl];
        match serde_json::from_slice::<Value>(line) {
            Ok(v) if v.is_object() => {
                values.push(v);
                at += nl + 1;
                good = at;
            }
            _ => {
                cut = true;
                break;
            }
        }
    }
    if cut {
        OpenOptions::new().write(true).open(path)?.set_len(good as u64)?;
    }
    Ok(values)
}

/// Open the log at `path` for appending, creating it where absent.
fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// One JSON object as its line, members in sorted order (serde_json's map
/// is a sorted map), no newline.
fn line_of(v: &Value) -> String {
    serde_json::to_string(v).expect("a JSON value renders")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The log reads back what it appended, in order, and a torn tail is
    /// cut off the file at open, the lines before it standing.
    #[test]
    fn a_log_reads_back_its_lines_and_cuts_a_torn_tail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x.log");
        let (mut log, values) = Log::open(path.clone()).unwrap();
        assert!(values.is_empty(), "an absent log holds no line");
        log.append(&json!({"n": 1}), true).unwrap();
        log.append(&json!({"n": 2}), false).unwrap();
        drop(log);
        let whole = fs::read_to_string(&path).unwrap();
        assert_eq!(whole, "{\"n\":1}\n{\"n\":2}\n");
        fs::write(&path, format!("{whole}{{\"n\":3")).unwrap();
        let (_, values) = Log::open(path.clone()).unwrap();
        assert_eq!(values, vec![json!({"n": 1}), json!({"n": 2})]);
        assert_eq!(fs::read_to_string(&path).unwrap(), whole, "the torn tail is cut");
    }

    /// THE COMPACTION reads the log's own count of its lines: a log holding
    /// exactly as many lines as its current records is left as it is (on
    /// unix, the same inode); one holding more is rewritten to exactly the
    /// current records, and the appends after it land in the rewritten file
    /// and count from there.
    #[test]
    fn the_line_count_decides_the_compaction() {
        #[cfg(unix)]
        let inode = |p: &Path| std::os::unix::fs::MetadataExt::ino(&fs::metadata(p).unwrap());
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x.log");
        let (mut log, _) = Log::open(path.clone()).unwrap();
        log.append(&json!({"k": "a", "v": 1}), true).unwrap();
        log.append(&json!({"k": "b", "v": 1}), true).unwrap();
        // Two lines, two current records: nothing to drop, no rewrite.
        #[cfg(unix)]
        let before = inode(&path);
        log.compact(vec![json!({"k": "a", "v": 1}), json!({"k": "b", "v": 1})].into_iter()).unwrap();
        #[cfg(unix)]
        assert_eq!(inode(&path), before, "a log holding only its current records is not rewritten");
        // A third line replacing `a`'s: three lines, two records — rewritten.
        log.append(&json!({"k": "a", "v": 2}), true).unwrap();
        log.compact(vec![json!({"k": "a", "v": 2}), json!({"k": "b", "v": 1})].into_iter()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"k\":\"a\",\"v\":2}\n{\"k\":\"b\",\"v\":1}\n");
        assert!(!path.with_extension("compact").exists(), "the twin is renamed over the log");
        // The next append lands in the rewritten file, and the count runs
        // on from the rewrite's two lines: three lines, three records, no
        // rewrite.
        log.append(&json!({"k": "c", "v": 1}), true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 3, "the append landed in the rewritten file");
        #[cfg(unix)]
        let rewritten = inode(&path);
        log.compact(
            vec![json!({"k": "a", "v": 2}), json!({"k": "b", "v": 1}), json!({"k": "c", "v": 1})].into_iter(),
        )
        .unwrap();
        #[cfg(unix)]
        assert_eq!(inode(&path), rewritten, "the count is the rewritten file's");
    }
}
