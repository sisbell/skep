//! The JSON-lines log both record logs are, `uploads.log` and `leases.log`.
//!
//! It is PATTERNS P22's honest-null arm (`media.md` Op inventory 1, "each
//! key's current record is its latest, and open compacts both stores"; §The
//! media stores): one JSON object per line, members in sorted order;
//! appended, a figure that must be durable fsynced with its line; read whole
//! at open, trust ending at the first torn line, which is cut off the file;
//! and compacted by the blob's own install order, so a crash mid-compaction
//! leaves the old log whole or the new one, never a mix.
//!
//! **A torn line is only ever the tail.** Open's tail check cuts the file at
//! the first torn line and everything after it, so a whole line written past
//! a torn one would go with it — a lease the PUT answered over, an offset a
//! settle answered. A crash tears at most the last line; an append that
//! fails while the process runs — a write cut short by a full disk, a sync
//! refused — is cut back off the file, so the next append starts on a whole
//! line; and where that cut fails too the log stops, taking no further
//! append, so the torn line stays the tail the next open cuts. A compaction
//! that fails past its rename stops it too: the rewrite then stands at the
//! log's name, and the file an append would write is the one it replaced,
//! which no open reads. [`Log`] owns the file, the length and the count of
//! its whole lines, and the stop with its cause, its start and the appends
//! it has refused since; what a line means is its store's (`uploads.rs`,
//! `lease.rs`).
//!
//! **The log answers what its embedder says of it**, as figures and never as
//! a line of its own (the store writes no stream): its size ([`LogSize`]) —
//! the most room its next rewrite needs, and what a compaction rewrote it
//! from — and its stop ([`LogStop`]): the cause, how long it has stood, and
//! the appends refused while it stood, the uploads it cost.
//!
//! **The log is read two ways.** [`Log::open`] cuts the torn tail off the
//! file and opens it for appending — the store's open; [`Log::read_as_found`]
//! reads the same lines and touches nothing — the inspection's, over a
//! backup or a directory a daemon serves, where a cut would be a write to a
//! log this reader does not own. Both answer what the reading found
//! ([`LogRead`]): the lines trusted, and where trust ended short of the
//! file's end ([`TailCut`]) — told apart from a crash's half-written tail
//! by the whole lines the cut takes past the first untrusted one, which a
//! crash never leaves and damage does.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::blobs::{dir_label, file_options, fsync_dir, label, named, not_found_as_none, Cause};

/// What one reading of a log found.
///
/// The reading is the store's open's ([`Opened`](crate::Opened)), or the
/// inspection's ([`Inspection::logs`](crate::Inspection::logs)): the log's
/// name, whether it stood at all, the whole lines trusted, where trust
/// ended short of the file's end, and the trusted lines that read as no
/// record. The open acts on all of it — an absent log made empty, the cut
/// made, the unread lines dropped by its compaction — and says none of it:
/// saying it is the embedder's part (the change feed's own files' cut is the
/// daemon's line at `operations.md` §1.1 row 9; this is the same fact for
/// the blob store's two logs).
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — field
/// reads are unaffected, and a further field is an addition rather than a
/// broken build.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct LogRead {
    /// The log as a line names it, within the data directory.
    ///
    /// The names are `blobs/uploads.log` and `blobs/leases.log`.
    pub name: String,
    /// No file stood at the log's name.
    ///
    /// The open made it empty — every upload or lease it held, where it held
    /// one, reads as none; the inspection made nothing.
    pub absent: bool,
    /// The whole lines trusted: the lines read before the cut, if one.
    pub lines: usize,
    /// Where trust ended short of the file's end, if it did.
    ///
    /// The open cut the file there; the inspection read nothing past it and
    /// cut nothing.
    pub cut: Option<TailCut>,
    /// The trusted lines that read as no record.
    ///
    /// Such a line has a shape this build does not read, a name the store's
    /// check refuses, or an offset past its length: a line another build
    /// wrote, or a damaged one, which the open's compaction removes from the
    /// file.
    pub unread: usize,
}

/// Where trust ended short of a log's end.
///
/// The cut is the first line that is no JSON object, or that lacks its
/// newline, and every byte after it — read past by neither reading, and cut
/// off the file by the open.
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — field
/// reads are unaffected, and a further field is an addition rather than a
/// broken build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TailCut {
    /// The byte trust ends at: the end of the last trusted line.
    ///
    /// The open truncates the file there.
    pub at: u64,
    /// The file's length before the cut.
    pub len: u64,
    /// The whole lines cut past the first untrusted one.
    ///
    /// They are the newline-ended lines after it, which a crash never
    /// leaves: a crash or a kill tears only the last line, its newline
    /// written with it, so `0` is that half-written tail and every
    /// acknowledged line stands; more is damage — a bad sector, a damaged or
    /// truncated copy — whose whole lines, leases a PUT answered over or
    /// offsets a settle answered, the cut takes with it.
    pub lines_after: usize,
}

impl TailCut {
    /// Returns the bytes cut, from where trust ends to the file's end.
    pub fn bytes(&self) -> u64 {
        self.len.saturating_sub(self.at)
    }
}

/// The size of one log, and what a compaction rewrote one from.
///
/// The figures are [`Store::log_sizes`](crate::Store::log_sizes)' and
/// [`Store::compact_logs_if_past`](crate::Store::compact_logs_if_past)':
/// the log's name, its whole lines and their bytes, as the log counts them
/// — the file at its name, a torn tail a failed append left past them not
/// among them. A rewrite needs room beside the file for what it writes, at
/// most a second copy of the file it rewrites, which is this.
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — field
/// reads are unaffected, and a further field is an addition rather than a
/// broken build.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct LogSize {
    /// The log as a line names it, within the data directory.
    ///
    /// The names are `blobs/uploads.log` and `blobs/leases.log`.
    pub name: String,
    /// Its whole lines.
    pub lines: usize,
    /// Their bytes.
    pub bytes: u64,
}

/// A log's stop as its embedder reads it.
///
/// [`Store::stopped_logs`](crate::Store::stopped_logs) answers it: the cause
/// in the operator's words, how long the stop has stood, and the appends the
/// log has refused while it stood — on the records' log a creation, a byte
/// received, a retirement or a finish each, on the leases' a finish each:
/// the uploads it cost, every one answered `Io`, a finish's before its first
/// act. The refusal a caller meets names the cause alone; the age and the
/// count are the operator's.
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — field
/// reads are unaffected, and a further field is an addition rather than a
/// broken build.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct LogStop {
    /// The cause, the act that failed and the OS's cause last.
    ///
    /// It reads `its append failed ({cause}) and the cut back to its last
    /// whole line failed too ({cause})`, or `its rewrite failed past its
    /// rename ({file}: {act}: {cause}): the rewrite stands at its name` — a
    /// full volume's cause reading `the volume is full ({the OS's text})` in
    /// each.
    pub cause: String,
    /// How long the stop has stood when it was read.
    ///
    /// It is a monotonic span from the act that stopped the log, which no
    /// clock step moves.
    pub age: Duration,
    /// The appends the log has refused since it stopped.
    pub refused: u64,
}

/// One JSON-lines log, with the figures its appends and rewrites move.
///
/// It holds its path and its name, its append-mode file, the byte length
/// and the count of the whole lines the file at its name holds, and the
/// stop where it has stopped. The length is what a failed append is cut
/// back to, and the count the one figure the compaction weighs against the
/// current records; this type's own appends and rewrites alone move them.
pub(crate) struct Log {
    path: PathBuf,
    /// The log as a line names it ([`LogRead::name`]).
    ///
    /// Every error this log answers at its own file names it so; the
    /// compaction's names its twin or its directory where its act fell
    /// there.
    name: String,
    file: File,
    len: u64,
    lines: usize,
    /// The log's stop, where it has stopped.
    ///
    /// It is set where an append failed and its cut-back failed too — the
    /// file may end in a torn line, and a line appended after it would be
    /// cut with it at the next open — or where a compaction failed past its
    /// rename, where the rewrite stands at the path while the open file is
    /// still the one it replaced, so an append would answer durable over a
    /// line no open reads. A stopped log takes no append, its refusal naming
    /// the cause; a compaction that completes, which writes the file whole,
    /// lifts the stop.
    stopped: Option<Stop>,
}

/// The stop a [`Log`] holds.
///
/// It keeps its cause in the operator's words, the instant it began, and
/// the appends refused since. A second act that stops a log already stopped
/// — a stopped log's compaction failing past its rename — gives it the new
/// cause and keeps its start and its count, the log having refused every
/// append since the first.
struct Stop {
    cause: String,
    since: Instant,
    refused: u64,
}

impl Log {
    /// Opens the log at `path`, created where absent, its torn tail cut off.
    ///
    /// The log is read whole, trust ending at the first line that is no JSON
    /// object or that lacks its newline (a torn tail), which is truncated
    /// off the file there and never read past (the honest-null arm's tail
    /// check). Answers the log, the values of its lines in order, and what
    /// the reading found — its `unread` the store's to count, as it folds the
    /// values.
    ///
    /// # Errors
    ///
    /// The read failing, save for the log's absence; the cut of a torn tail
    /// failing; or the open for appending failing — each named, the log and
    /// the act (`read`, `cut back`, `open`).
    pub fn open(path: PathBuf) -> io::Result<(Log, Vec<Value>, LogRead)> {
        let name = label(&path, 2);
        let (values, found, len) = read_log(&path, &name)?;
        let file = open_append(&path).map_err(|e| named(e, &name, "open"))?;
        let lines = values.len();
        Ok((Log { path, name, file, len, lines, stopped: None }, values, found))
    }

    /// Reads the log as found, leaving the file exactly as it was.
    ///
    /// It reads the values of its whole lines, trust ending at the first
    /// torn line as [`Log::open`]'s read ends it — no cut, no append-mode
    /// open, no file created where none stands. The inspection's read, over
    /// a copy or beside a daemon that holds the log. Answers the values and
    /// what the reading found: the cut it would make where the open would
    /// make one, cut nowhere.
    ///
    /// # Errors
    ///
    /// The read failing, save for the log's absence, named (`read`).
    pub fn read_as_found(path: &Path) -> io::Result<(Vec<Value>, LogRead)> {
        let name = label(path, 2);
        let bytes = not_found_as_none(fs::read(path)).map_err(|e| named(e, &name, "read"))?;
        let (values, found, _) = reading(name, bytes.as_deref());
        Ok((values, found))
    }

    /// Returns the count of whole lines the log holds.
    ///
    /// It is what the compaction's trigger is measured against: every append
    /// adds one, and the rewrite resets it to the current records.
    pub fn lines(&self) -> usize {
        self.lines
    }

    /// Returns the stop's cause, where the log has stopped.
    ///
    /// The log stops where an append's cut-back failed, or a compaction
    /// failed past its rename; it takes no append until a compaction
    /// completes. `None` is a log that takes appends.
    pub fn stopped(&self) -> Option<&str> {
        self.stopped.as_ref().map(|stop| stop.cause.as_str())
    }

    /// Returns the stop as its embedder reads it, where the log has stopped.
    ///
    /// It holds the cause, its age at this read, and the appends refused
    /// since ([`LogStop`]).
    pub fn stop(&self) -> Option<LogStop> {
        self.stopped.as_ref().map(|stop| LogStop {
            cause: stop.cause.clone(),
            age: stop.since.elapsed(),
            refused: stop.refused,
        })
    }

    /// Returns the log's size: its whole lines and their bytes ([`LogSize`]).
    pub fn size(&self) -> LogSize {
        LogSize { name: self.name.clone(), lines: self.lines, bytes: self.len }
    }

    /// Appends `v` as the log's next line and fsyncs it.
    ///
    /// That is what a figure that must be durable owes. It is undone where
    /// it fails ([`Log::append_by`]).
    ///
    /// # Errors
    ///
    /// A stopped log's refusal, or the write's or the sync's failure, as
    /// [`Log::append_by`] answers them.
    pub fn append_synced(&mut self, v: &Value) -> io::Result<()> {
        self.append_by(v, |file, line| {
            file.write_all(line)?;
            file.sync_all()
        })
    }

    /// Appends `v` as the log's next line, its durability left to the OS.
    ///
    /// It is for a line whose loss costs nothing. It is undone where it
    /// fails ([`Log::append_by`]).
    ///
    /// # Errors
    ///
    /// A stopped log's refusal, or the write's failure, as
    /// [`Log::append_by`] answers them.
    pub fn append_unsynced(&mut self, v: &Value) -> io::Result<()> {
        self.append_by(v, |file, line| file.write_all(line))
    }

    /// Appends `v` through `write`, the append's one body.
    ///
    /// Its write — and its sync, where the line owes one — is handed in as
    /// `write`: the line and its newline in one write. The unit suite drives
    /// it with a write that fails partway.
    ///
    /// # Errors
    ///
    /// A write or sync that fails is undone: the file cut back to its whole
    /// lines and the cut synced, so a failed append leaves the file as it
    /// found it — what each store's map, moved by an append only after it
    /// returns (save a retirement's, dropped first: `UploadRecords::retire`
    /// says why), already assumes — and the append answers its failure, the
    /// log named. Where the cut fails too, the log stops, the cause kept in
    /// the operator's words ([`Log::stopped`]), and the append answers its
    /// own failure with the stop said after it, so the act that stopped the
    /// log says so at the moment it does; a stopped log refuses every later
    /// append, naming the cause, and counts it ([`Log::stop`]).
    fn append_by(&mut self, v: &Value, write: impl FnOnce(&mut File, &[u8]) -> io::Result<()>) -> io::Result<()> {
        self.refuse_if_stopped()?;
        let line = line_of(v);
        if let Err(e) = write(&mut self.file, &line) {
            return Err(match self.file.set_len(self.len).and_then(|()| self.file.sync_all()) {
                Ok(()) => named(e, &self.name, "append"),
                Err(cut) => {
                    let cause = format!(
                        "its append failed ({}) and the cut back to its last whole line failed too ({})",
                        Cause(&e),
                        Cause(&cut)
                    );
                    let stopped = io::Error::new(
                        e.kind(),
                        format!("{}: append: {cause}, so it takes no append until a compaction completes", self.name),
                    );
                    self.stop_by(cause);
                    stopped
                }
            });
        }
        self.len += line.len() as u64;
        self.lines += 1;
        Ok(())
    }

    /// Judges the stop's refusal ahead of an act.
    ///
    /// It is what a caller asks before an act the append would follow and no
    /// refusal of the append could undo, as a finish asks it before its
    /// rename (`Stream::finish`). `Ok` where the log takes appends.
    ///
    /// # Errors
    ///
    /// The refusal an append meets where the log has stopped, worded and
    /// counted as every refused append is ([`Log::stop`]).
    pub fn refuse_if_stopped(&mut self) -> io::Result<()> {
        let Some(stop) = &mut self.stopped else {
            return Ok(());
        };
        stop.refused += 1;
        Err(io::Error::other(format!("{} takes no append until a compaction completes: {}", self.name, stop.cause)))
    }

    /// Rewrites the log to exactly `current`, in order.
    ///
    /// It rewrites where the log holds anything else, or where it has
    /// stopped: every append adds a line, so a log that has not stopped and
    /// whose count equals its current records' holds nothing else, and is
    /// left as it is. The rewrite is written to a `.compact` twin beside the
    /// log, fsynced, renamed over it, the directory fsynced — the same
    /// install order a blob takes; it writes the file whole, so once it
    /// completes it lifts a stop. Answers the size it rewrote the log from
    /// ([`LogSize`]), `None` where it left the log as it was.
    ///
    /// **Precondition.** `current` is what the log's store folds the log's
    /// lines to — each value one a line the log holds reads as, none twice —
    /// as both stores hand their own maps at open and at the pass's
    /// compaction (`Store::compact_logs_if_past`, the runtime compaction the
    /// pruner's pass runs once a log has passed its size trigger — `media.md`
    /// §The media stores): an equal count is read as nothing else held, so a
    /// different set of that count would never be written. The runtime
    /// compaction runs under the store's lock on *this* log's appends alone,
    /// which is what makes the count it reads and the records it writes one
    /// state: an append that arrives during the rewrite waits on that lock
    /// and lands in the new file once the install order has completed.
    ///
    /// # Errors
    ///
    /// A rewrite that fails before its rename — the twin's creation, write
    /// or sync, or the rename — leaves the log as it was and removes its
    /// twin, best effort, so a rewrite that met a volume with less room than
    /// it needs keeps none of that room once the twin is gone; one that fails
    /// past it — the directory's fsync, or the log's open for appending —
    /// stops the log until a compaction completes, its size the rewrite's,
    /// which stands at the name.
    pub fn compact(&mut self, current: impl ExactSizeIterator<Item = Value>) -> io::Result<Option<LogSize>> {
        self.compact_by(current, |file, line| file.write_all(line))
    }

    /// Runs the compaction's one body, writing the twin's lines by `write`.
    ///
    /// Each line of the rewrite is written to the twin by `write` — the act
    /// the unit suite cuts short in its place ([`Log::compact`]).
    ///
    /// # Errors
    ///
    /// [`Log::compact`]'s, a failure of `write` answered as the twin's write.
    fn compact_by(
        &mut self,
        current: impl ExactSizeIterator<Item = Value>,
        write: impl FnMut(&mut File, &[u8]) -> io::Result<()>,
    ) -> io::Result<Option<LogSize>> {
        if self.stopped.is_none() && current.len() == self.lines {
            return Ok(None);
        }
        let from = self.size();
        let dir = self.path.parent().expect("a log sits in a directory");
        let twin = self.path.with_extension("compact");
        let rewritten = write_twin(&twin, current, write).and_then(|counts| {
            fs::rename(&twin, &self.path).map_err(|e| named(e, &self.name, "rename its rewrite over it"))?;
            Ok(counts)
        });
        // Short of the rename the log stands as it was, and the twin goes
        // with the failure: whatever room its bytes took is the volume's
        // again. Best effort, as the pull's temp file is: a twin that cannot
        // be removed is written over by the next compaction.
        let (len, lines) = match rewritten {
            Ok(counts) => counts,
            Err(e) => {
                let _ = fs::remove_file(&twin);
                return Err(e);
            }
        };
        // Past the rename the rewrite stands at the path, its length and its
        // count the log's, while the open file is still the one it replaced:
        // stopped, the cause kept, until the install order completes and the
        // open file is the rewrite's too.
        self.len = len;
        self.lines = lines;
        let installed = fsync_dir(dir)
            .map_err(|e| named(e, dir_label(dir, 1), "fsync"))
            .and_then(|()| open_append(&self.path).map_err(|e| named(e, &self.name, "open")));
        match installed {
            Ok(file) => {
                self.file = file;
                self.stopped = None;
                Ok(Some(from))
            }
            Err(e) => {
                self.stop_by(format!("its rewrite failed past its rename ({e}): the rewrite stands at its name"));
                Err(e)
            }
        }
    }

    /// Stops the log for `cause`.
    ///
    /// A log already stopped takes the new cause and keeps its start and its
    /// count of refused appends ([`Stop`]).
    fn stop_by(&mut self, cause: String) {
        match &mut self.stopped {
            Some(stop) => stop.cause = cause,
            None => self.stopped = Some(Stop { cause, since: Instant::now(), refused: 0 }),
        }
    }
}

/// Writes `current` to the `.compact` file at `twin`, and fsyncs it.
///
/// The lines go one by one through `write`, the twin born owner-only
/// (`blobs::file_options`), the mode the rename carries onto the log.
/// Answers the rewrite's bytes and lines.
///
/// # Errors
///
/// The twin's creation, a line's write or the sync failing, named as the
/// twin's (`create`, `write`, `sync`).
fn write_twin(
    twin: &Path,
    current: impl Iterator<Item = Value>,
    mut write: impl FnMut(&mut File, &[u8]) -> io::Result<()>,
) -> io::Result<(u64, usize)> {
    let at_twin = |e: io::Error, act: &str| named(e, label(twin, 2), act);
    let mut f = file_options().write(true).create(true).truncate(true).open(twin).map_err(|e| at_twin(e, "create"))?;
    let (mut len, mut lines) = (0, 0);
    for v in current {
        let line = line_of(&v);
        write(&mut f, &line).map_err(|e| at_twin(e, "write"))?;
        len += line.len() as u64;
        lines += 1;
    }
    f.sync_all().map_err(|e| at_twin(e, "sync"))?;
    Ok((len, lines))
}

/// Reads a log for [`Log::open`], its torn tail cut off the file.
///
/// Answers the values of its whole lines in order, what the reading found
/// and the bytes trusted, the cut made there. An absent log holds none, and
/// is found absent.
///
/// # Errors
///
/// The read failing, save for the log's absence, or the cut failing, named
/// (`read`, `cut back`).
fn read_log(path: &Path, name: &str) -> io::Result<(Vec<Value>, LogRead, u64)> {
    let bytes = not_found_as_none(fs::read(path)).map_err(|e| named(e, name, "read"))?;
    let (values, found, good) = reading(name.to_string(), bytes.as_deref());
    if found.cut.is_some() {
        OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|f| f.set_len(good))
            .map_err(|e| named(e, name, "cut back"))?;
    }
    Ok((values, found, good))
}

/// Reads a log's bytes, `None` where no file stood.
///
/// It is the one reading both [`read_log`] and [`Log::read_as_found`] make:
/// it answers the values of its whole lines ([`whole_lines`]), what it
/// found, and the bytes trusted. Where trust ends short of the end, the cut
/// ([`TailCut`]) counts the whole lines past the first untrusted one: the
/// bytes from that line's newline, or the end where it has none, to the end.
fn reading(name: String, bytes: Option<&[u8]>) -> (Vec<Value>, LogRead, u64) {
    let Some(bytes) = bytes else {
        return (Vec::new(), LogRead { name, absent: true, lines: 0, cut: None, unread: 0 }, 0);
    };
    let (values, good) = whole_lines(bytes);
    let cut = (good < bytes.len()).then(|| {
        let rest = &bytes[good..];
        let first = rest.iter().position(|&b| b == b'\n').map_or(rest.len(), |at| at + 1);
        TailCut {
            at: good as u64,
            len: bytes.len() as u64,
            lines_after: rest[first..].iter().filter(|&&b| b == b'\n').count(),
        }
    });
    let lines = values.len();
    (values, LogRead { name, absent: false, lines, cut, unread: 0 }, good as u64)
}

/// Returns the values of `bytes`' whole lines in order, and their byte length.
///
/// Trust ends at the first torn line — one with no newline, being written
/// when the process died, or one that is no JSON object — and nothing past
/// it is read. The one reading both [`read_log`] and [`Log::read_as_found`]
/// make; whether the tail is then cut is theirs.
fn whole_lines(bytes: &[u8]) -> (Vec<Value>, usize) {
    let mut values = Vec::new();
    let mut good = 0;
    for line in bytes.split_inclusive(|&b| b == b'\n') {
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
    (values, good)
}

/// Opens the log at `path` for appending, creating it where absent.
///
/// A log it creates is born owner-only (`blobs::file_options`); a log that
/// already stands keeps its mode.
///
/// # Errors
///
/// The open's failure, the OS's alone: the caller names it.
fn open_append(path: &Path) -> io::Result<File> {
    file_options().create(true).append(true).open(path)
}

/// Returns one JSON object as its line, newline and all.
///
/// Its members come in sorted order (serde_json's map is a sorted map).
fn line_of(v: &Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(v).expect("a JSON value renders");
    line.push(b'\n');
    line
}

#[cfg(test)]
mod tests;
