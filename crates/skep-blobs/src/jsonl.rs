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
//! append, so the torn line stays the tail the next open cuts. [`Log`] owns
//! the file, the length and the count of its whole lines, and the stop; what
//! a line means is its store's (`uploads.rs`, `lease.rs`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::blobs::fsync_dir;

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
    /// An append failed and its cut-back failed too: the file may end in a
    /// torn line, and a line appended after it would be cut with it at the
    /// next open. A stopped log takes no append; a compaction, which writes
    /// the file whole, lifts the stop.
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
    /// found it — what each store's map, moved only after an append
    /// returns, already assumes. Where the cut fails too, the log stops and
    /// the append answers its own failure; a stopped log refuses every later
    /// append. The unit suite drives it with a write that fails partway.
    fn append_by(&mut self, v: &Value, write: impl FnOnce(&mut File, &[u8]) -> io::Result<()>) -> io::Result<()> {
        if self.stopped {
            return Err(io::Error::other(format!(
                "{} takes no append: an earlier append failed and could not be cut back off it",
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
    /// the file whole, so it lifts a stop.
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
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
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
        log.append_synced(&json!({"n": 1})).unwrap();
        log.append_unsynced(&json!({"n": 2})).unwrap();
        drop(log);
        let whole = fs::read_to_string(&path).unwrap();
        assert_eq!(whole, "{\"n\":1}\n{\"n\":2}\n");
        fs::write(&path, format!("{whole}{{\"n\":3")).unwrap();
        let (_, values) = Log::open(path.clone()).unwrap();
        assert_eq!(values, vec![json!({"n": 1}), json!({"n": 2})]);
        assert_eq!(fs::read_to_string(&path).unwrap(), whole, "the torn tail is cut");
    }

    /// TRUST ENDS AT THE FIRST TORN LINE, WHATEVER TORE IT, AND IS NEVER READ
    /// PAST: for each way a line between two whole ones can be torn — no JSON,
    /// JSON that is no object, an empty line, two objects run together — open
    /// answers the lines before it alone and cuts the file there, the whole
    /// line after it with it.
    #[test]
    fn trust_ends_at_the_first_torn_line_whatever_tore_it() {
        for torn in ["{\"n\":2\n", "[2]\n", "2\n", "\"two\"\n", "null\n", "\n", "{\"n\":2}{\"n\":3}\n"] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("x.log");
            fs::write(&path, format!("{{\"n\":1}}\n{torn}{{\"n\":4}}\n")).unwrap();
            let (_, values) = Log::open(path.clone()).unwrap();
            assert_eq!(values, vec![json!({"n": 1})], "{torn:?}: the lines before it alone");
            assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n", "{torn:?}: cut there, the line after it too");
        }
    }

    /// AN APPEND THAT FAILS is cut back off the file: a write cut short —
    /// part of the line on disk, then an error, as a full disk gives —
    /// leaves the file at its whole lines, the next append lands on a whole
    /// line, and the reopen reads every whole line, the one after the
    /// failure included.
    #[test]
    fn a_failed_append_is_cut_back_off_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x.log");
        let (mut log, _) = Log::open(path.clone()).unwrap();
        log.append_synced(&json!({"n": 1})).unwrap();
        let cut_short = log.append_by(&json!({"n": 2}), |file, line| {
            file.write_all(&line[..4])?;
            Err(io::Error::other("no space left on the device"))
        });
        assert!(cut_short.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n", "the torn line is cut back off the file");
        log.append_synced(&json!({"n": 3})).unwrap();
        drop(log);
        let (_, values) = Log::open(path.clone()).unwrap();
        assert_eq!(values, vec![json!({"n": 1}), json!({"n": 3})], "the line after the failure stands");
    }

    /// A FAILED APPEND LEAVES THE FILE AS IT FOUND IT, WHATEVER OPENED OR
    /// REWROTE IT: the length it is cut back to is the file's whole lines —
    /// read at open, over a torn tail cut there too, and reset by a
    /// compaction that rewrote the file shorter — so a write cut short by a
    /// full disk never cuts a whole line away, nor leaves behind bytes the
    /// next open would cut a later whole line with.
    #[test]
    fn a_failed_append_leaves_the_file_as_it_found_it_whatever_opened_or_rewrote_it() {
        for state in ["fresh", "reopened", "reopened over a torn tail", "compacted shorter"] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("x.log");
            match state {
                "reopened" => fs::write(&path, "{\"n\":1}\n{\"n\":2}\n").unwrap(),
                "reopened over a torn tail" => fs::write(&path, "{\"n\":1}\n{\"n\":2}\n{\"n\"").unwrap(),
                _ => {}
            }
            let (mut log, _) = Log::open(path.clone()).unwrap();
            match state {
                "fresh" => log.append_synced(&json!({"n": 1})).unwrap(),
                "compacted shorter" => {
                    for n in 1..=3 {
                        log.append_synced(&json!({"n": n})).unwrap();
                    }
                    log.compact(vec![json!({"n": 3})].into_iter()).unwrap();
                }
                _ => {}
            }
            let before = fs::read(&path).unwrap();
            let failed = log.append_by(&json!({"n": 9}), |file, line| {
                file.write_all(&line[..4])?;
                Err(io::Error::other("no space left on the device"))
            });
            assert!(failed.is_err(), "{state}");
            assert_eq!(fs::read(&path).unwrap(), before, "{state}: cut back to exactly the whole lines it held");
            log.append_synced(&json!({"n": 10})).unwrap();
            drop(log);
            let want: Vec<Value> = match state {
                "fresh" => vec![json!({"n": 1}), json!({"n": 10})],
                "compacted shorter" => vec![json!({"n": 3}), json!({"n": 10})],
                _ => vec![json!({"n": 1}), json!({"n": 2}), json!({"n": 10})],
            };
            assert_eq!(Log::open(path).unwrap().1, want, "{state}: the line after the failure stands at the next open");
        }
    }

    /// AN APPEND WHOSE CUT-BACK FAILS TOO stops the log: every later append
    /// is refused, so the torn line stays the file's tail, the one place
    /// open's tail check cuts without taking a whole line with it. A
    /// compaction writes the file whole and lifts the stop.
    #[test]
    fn a_failed_cut_back_stops_the_log_until_a_compaction() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x.log");
        let (mut log, _) = Log::open(path.clone()).unwrap();
        log.append_synced(&json!({"n": 1})).unwrap();
        // A read-only file, as a failing disk leaves the log's: the rest of
        // the write fails at the OS, and so does the cut. The torn bytes land
        // through a second open file, as a write cut short leaves them.
        log.file = File::open(&path).unwrap();
        let mut other = open_append(&path).unwrap();
        let failed = log.append_by(&json!({"n": 2}), |file, line| {
            other.write_all(&line[..4])?;
            file.write_all(&line[4..])
        });
        assert!(failed.is_err());
        log.file = open_append(&path).unwrap();
        assert!(log.append_synced(&json!({"n": 3})).is_err(), "a stopped log takes no append");
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n{\"n\"", "the torn line stays the tail");
        log.compact(vec![json!({"n": 1})].into_iter()).unwrap();
        log.append_synced(&json!({"n": 4})).unwrap();
        drop(log);
        let (_, values) = Log::open(path.clone()).unwrap();
        assert_eq!(values, vec![json!({"n": 1}), json!({"n": 4})], "compacted whole, the stop lifted");
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
        log.append_synced(&json!({"k": "a", "v": 1})).unwrap();
        log.append_synced(&json!({"k": "b", "v": 1})).unwrap();
        // Two lines, two current records: nothing to drop, no rewrite.
        #[cfg(unix)]
        let before = inode(&path);
        log.compact(vec![json!({"k": "a", "v": 1}), json!({"k": "b", "v": 1})].into_iter()).unwrap();
        #[cfg(unix)]
        assert_eq!(inode(&path), before, "a log holding only its current records is not rewritten");
        // A third line replacing `a`'s: three lines, two records — rewritten.
        log.append_synced(&json!({"k": "a", "v": 2})).unwrap();
        log.compact(vec![json!({"k": "a", "v": 2}), json!({"k": "b", "v": 1})].into_iter()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"k\":\"a\",\"v\":2}\n{\"k\":\"b\",\"v\":1}\n");
        assert!(!path.with_extension("compact").exists(), "the twin is renamed over the log");
        // The next append lands in the rewritten file, and the count runs
        // on from the rewrite's two lines: three lines, three records, no
        // rewrite.
        log.append_synced(&json!({"k": "c", "v": 1})).unwrap();
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
