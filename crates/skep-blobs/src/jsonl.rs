//! The JSON-lines log both record logs are, `uploads.log` and `leases.log`.
//!
//! It is PATTERNS P22's honest-null arm (`media.md` Op inventory 1, "each
//! key's current record is its latest, and open compacts both stores"; §The
//! media stores): one JSON object per line, members in sorted order;
//! appended, a figure that must be durable fsynced with its line; read whole
//! at open, trust ending at the first torn line, which is cut off the file;
//! and compacted by the blob's own install order, so a crash mid-compaction
//! leaves the old log whole or the new one, never a mix. The read, the cut,
//! the append with its cut-back, the keep and the rewrite are the support
//! crate's `file` module's (`skep_util::file`), the one tail rule the
//! client's and the shell's files keep; what a line means, when to keep and
//! when to cut, the stop and every word answered are this log's.
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
//! by whether the first untrusted line was whole, ended by its newline,
//! which a crash never leaves and damage does. **A damaged cut is kept
//! first.** Where the first untrusted line is whole — damage to a line the
//! store answered over, and every whole line after it with it — the open
//! keeps the bytes from the cut to the file's end beside the log, durably,
//! as `{log}.cut-{byte}` (`….{k}` where that name stands), before it cuts
//! them, and names the file ([`LogRead::kept`]); a crash's torn line is cut
//! and gone. The inspection keeps nothing, and answers the class alone.

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;
use skep_util::file::{keep_beside, publish_by, read_lines, AppendFailed, Appender, Fsync, KeepStep, Lines, OnStale, OnTail, PublishStep};

use crate::blobs::{dir_label, label, named, Cause};

/// The mode a log, its twin and a kept file are born with: owner-only.
///
/// It is the value `blobs::file_options` carries on the options of every
/// file the store makes (`blobs::FILE_MODE`), handed to the module as a
/// figure; `tests/it/modes.rs` holds every entry the store makes to these
/// bits.
const MODE: u32 = 0o600;

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
    /// The file the open kept the cut bytes in, where the cut was damage.
    ///
    /// It is `{log}.cut-{byte}` beside the log, named within the data
    /// directory as `name` is (`blobs/leases.log.cut-512`; `….{k}` where
    /// that name already stood), holding every byte from the cut to the
    /// file's end as found, written and synced before the cut
    /// ([`TailCut::damage`]). `None` for a crash's torn line, cut and gone,
    /// for a file read whole, and for the inspection's reading, which keeps
    /// nothing.
    pub kept: Option<String>,
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
    /// written with it, so `0` is that half-written tail where the first
    /// untrusted line was torn too ([`TailCut::first_whole`]) and every
    /// acknowledged line stands; more is damage — a bad sector, a damaged or
    /// truncated copy — whose whole lines, leases a PUT answered over or
    /// offsets a settle answered, the cut takes with it.
    pub lines_after: usize,
    /// Whether the first untrusted line was whole: ended by its newline.
    ///
    /// A crash tears the last line and never writes its newline, so a whole
    /// line that does not read is damage to a line the store answered over
    /// — the tell that separates the two where `lines_after` cannot, a
    /// damaged LAST line having none after it. `true` wherever
    /// `lines_after` is above `0`.
    pub first_whole: bool,
}

impl TailCut {
    /// Returns the bytes cut, from where trust ends to the file's end.
    pub fn bytes(&self) -> u64 {
        self.len.saturating_sub(self.at)
    }

    /// Returns whether the cut is damage rather than a crash's torn tail.
    ///
    /// It is where the first untrusted line was whole
    /// ([`TailCut::first_whole`]): a line the store answered over, damaged
    /// since, and every whole line after it. The open keeps such a cut's
    /// bytes beside the log before it cuts them ([`LogRead::kept`]); a
    /// crash's torn line, never acknowledged, is cut and gone.
    pub fn damage(&self) -> bool {
        self.first_whole
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
/// It holds its path and its name, its append handle
/// (`skep_util::file::Appender`, open where its whole lines end), the byte
/// length and the count of the whole lines the file at its name holds, and
/// the stop where it has stopped. The length is the handle's count of the
/// whole lines — what a failed append is cut back to — kept here too, since
/// a rewrite that fails past its rename moves it while the handle is still
/// the replaced file's; the count is the one figure the compaction weighs
/// against the current records. This type's own appends and rewrites alone
/// move them.
pub(crate) struct Log {
    path: PathBuf,
    /// The log as a line names it ([`LogRead::name`]).
    ///
    /// Every error this log answers at its own file names it so; the
    /// compaction's names its twin or its directory where its act fell
    /// there.
    name: String,
    file: Appender,
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
    /// The log is read whole as lines (`skep_util::file::read_lines`), trust
    /// ending at the first line that is no JSON object or that lacks its
    /// newline (a torn tail), which is truncated off the file there at the
    /// open and never read past (the honest-null arm's tail check). Answers
    /// the log, the values of its lines in order, and what the reading
    /// found — its `unread` the store's to count, as it folds the values.
    ///
    /// # Errors
    ///
    /// The read failing, save for the log's absence; the keep of a damaged
    /// cut failing; the open for appending failing; or the cut of a torn
    /// tail failing — each named, the log or the kept file and the act
    /// (`read`, the kept file's acts, `open`, `cut back`).
    pub fn open(path: PathBuf) -> io::Result<(Log, Vec<Value>, LogRead)> {
        let name = label(&path, 2);
        let (values, found, file) = read_log(&path, &name)?;
        let lines = values.len();
        let len = file.whole();
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
        let read = read_lines(path).map_err(|e| named(e, &name, "read"))?;
        let (values, found, _) = reading(name, read.as_ref());
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
    /// `write`: the line and its newline in one write, through the module's
    /// append (`skep_util::file::Appender::append_by_telling`), which lands
    /// it where the whole lines end. The unit suite drives it with a write
    /// that fails partway.
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
        let json = serde_json::to_vec(v).expect("a JSON value renders");
        match self.file.append_by_telling(&json, OnTail::Cut, Fsync::All, write) {
            Ok(_) => {
                self.len = self.file.whole();
                self.lines += 1;
                Ok(())
            }
            Err(AppendFailed { write: e, cut_back: None, .. }) => Err(named(e, &self.name, "append")),
            Err(AppendFailed { write: e, cut_back: Some(cut), .. }) => {
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
                Err(stopped)
            }
        }
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
    /// install order a blob takes, made by the module's publish
    /// (`skep_util::file::publish_by`) through the twin this log names; it
    /// writes the file whole, so once it completes it lifts a stop. Answers
    /// the size it rewrote the log from ([`LogSize`]), `None` where it left
    /// the log as it was.
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
    /// twin, so a rewrite that met a volume with less room than it needs
    /// keeps none of that room once the twin is gone (a removal that fails
    /// too is named beside the failure); one that fails past it — the
    /// directory's fsync, or the log's open for appending — stops the log
    /// until a compaction completes, its size the rewrite's, which stands at
    /// the name.
    pub fn compact(&mut self, current: impl ExactSizeIterator<Item = Value>) -> io::Result<Option<LogSize>> {
        self.compact_by(current, |file, line| file.write_all(line))
    }

    /// Runs the compaction's one body, writing the twin's lines by `write`.
    ///
    /// Each line of the rewrite is written to the twin by `write`, inside the
    /// module's publish — the act the unit suite cuts short in its place
    /// ([`Log::compact`]).
    ///
    /// # Errors
    ///
    /// [`Log::compact`]'s, a failure of `write` answered as the twin's write.
    fn compact_by(
        &mut self,
        current: impl ExactSizeIterator<Item = Value>,
        mut write: impl FnMut(&mut File, &[u8]) -> io::Result<()>,
    ) -> io::Result<Option<LogSize>> {
        if self.stopped.is_none() && current.len() == self.lines {
            return Ok(None);
        }
        let from = self.size();
        let dir = self.path.parent().expect("a log sits in a directory");
        let twin = self.path.with_extension("compact");
        let (mut len, mut lines) = (0u64, 0usize);
        let published = publish_by(&self.path, &twin, MODE, OnStale::Replace, |f| {
            for v in current {
                let line = line_of(&v);
                write(f, &line)?;
                len += line.len() as u64;
                lines += 1;
            }
            Ok(())
        });
        // Short of the rename the log stands as it was, and the twin went
        // with the failure: whatever room its bytes took is the volume's
        // again. Past the rename the rewrite stands at the path, its length
        // and its count the log's, while the open file is still the one it
        // replaced: stopped, the cause kept, until the install order
        // completes and the open file is the rewrite's too.
        if let Err(failed) = published {
            let twin_name = label(&twin, 2);
            return Err(match failed.step {
                PublishStep::Create => named(failed.error, twin_name, "create"),
                PublishStep::Write => named(failed.error, twin_name, "write"),
                PublishStep::Sync => named(failed.error, twin_name, "sync"),
                PublishStep::Rename => named(failed.error, &self.name, "rename its rewrite over it"),
                PublishStep::DirSync => {
                    self.len = len;
                    self.lines = lines;
                    let e = named(failed.error, dir_label(dir, 1), "fsync");
                    self.stop_by(format!("its rewrite failed past its rename ({e}): the rewrite stands at its name"));
                    e
                }
            });
        }
        self.len = len;
        self.lines = lines;
        match Appender::open_at(&self.path, len).map_err(|e| named(e, &self.name, "open")) {
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

/// Reads a log for [`Log::open`], its torn tail cut off the file.
///
/// Answers the values of its whole lines in order, what the reading found,
/// and the log's append handle, open where trust ends — the file cut there
/// at the open, unsynced (`skep_util::file::Appender::cut`) — or made
/// empty, born owner-only, where no log stood. A cut that is damage
/// ([`TailCut::damage`]) is kept first ([`keep_cut`]), the bytes read off
/// the log itself from the cut to its end, the kept file named in the
/// reading.
///
/// # Errors
///
/// The read failing, save for the log's absence, the keep failing, the open
/// for appending failing, or the cut failing, named (`read`, the kept
/// file's acts, `open`, `cut back`).
fn read_log(path: &Path, name: &str) -> io::Result<(Vec<Value>, LogRead, Appender)> {
    let read = read_lines(path).map_err(|e| named(e, name, "read"))?;
    let (values, mut found, good) = reading(name.to_string(), read.as_ref());
    if found.cut.is_some_and(|cut| cut.damage()) {
        let mut dropped = File::open(path).map_err(|e| named(e, name, "read"))?;
        dropped.seek(SeekFrom::Start(good)).map_err(|e| named(e, name, "read"))?;
        found.kept = Some(keep_cut(path, name, good, &mut dropped)?);
    }
    let mut file = match read {
        Some(_) => Appender::open_at(path, good),
        None => Appender::open(path, MODE),
    }
    .map_err(|e| named(e, name, "open"))?;
    file.cut(Fsync::None).map_err(|e| named(e, name, "cut back"))?;
    Ok((values, found, file))
}

/// Keeps a damaged cut's bytes beside the log, durably, before the cut.
///
/// They go to `{log}.cut-{at}` beside the log — `….{k}` where that name and
/// the `k − 1` before it already stand; a standing name is never written
/// over, whatever it holds — born owner-only, copied through from
/// `dropped`, synced, the directory synced after, by the module's keep
/// (`skep_util::file::keep_beside`). The kernel's own spelling for a
/// journal tail it keeps, so every kept file in the data directory is found
/// by one listing. Answers the kept file's name within the data directory,
/// as [`LogRead::name`] names the log.
///
/// # Errors
///
/// The kept file's creation, write or sync, or the directory's sync,
/// failing, named `{kept}: {act}: {cause}` (`create`, `write`, `fsync`; the
/// directory's `fsync`) — the kept file standing with what was written past
/// its creation, a half-kept file being a fact beside the log, never a loss
/// to make larger.
fn keep_cut(path: &Path, name: &str, at: u64, dropped: impl io::Read) -> io::Result<String> {
    let dir = path.parent().expect("a log sits in a directory");
    match keep_beside(dir, &label(path, 1), at, dropped, MODE) {
        Ok(kept) => Ok(kept.of(name)),
        Err(failed) => Err(match failed.step {
            KeepStep::Create => named(failed.error, failed.name.of(name), "create"),
            KeepStep::Write => named(failed.error, failed.name.of(name), "write"),
            KeepStep::Fsync => named(failed.error, failed.name.of(name), "fsync"),
            KeepStep::DirSync => named(failed.error, dir_label(dir, 1), "fsync"),
        }),
    }
}

/// Reads what a log's lines hold, `None` where no file stood.
///
/// It is the one reading both [`read_log`] and [`Log::read_as_found`] make,
/// over the lines the module read whole (`skep_util::file::read_lines`): it
/// answers the values of the lines trusted ([`whole_lines`]), what it
/// found, and the bytes trusted. Where trust ends short of the end, the cut
/// ([`TailCut`]) says whether the first untrusted line was whole — a line
/// the module read, ended by its newline — or the module's tail, the bytes
/// past the last newline, and counts the whole lines past it. Nothing is
/// kept here: the keep is the open's ([`read_log`]).
fn reading(name: String, read: Option<&Lines>) -> (Vec<Value>, LogRead, u64) {
    let Some(read) = read else {
        let found = LogRead { name, absent: true, lines: 0, cut: None, kept: None, unread: 0 };
        return (Vec::new(), found, 0);
    };
    let (values, good, untrusted) = whole_lines(&read.lines);
    let len = read.tail.map_or(read.whole, |tail| tail.len);
    let cut = match untrusted {
        Some(first) => Some(TailCut { at: good, len, lines_after: read.lines.len() - first - 1, first_whole: true }),
        None => read.tail.map(|tail| TailCut { at: tail.at, len: tail.len, lines_after: 0, first_whole: false }),
    };
    let lines = values.len();
    let found = LogRead { name, absent: false, lines, cut, kept: None, unread: 0 };
    (values, found, good)
}

/// Returns the values of the lines trusted, their bytes, and where trust ended.
///
/// Trust ends at the first line that is no JSON object — damage to a line
/// the store answered over, or another build's — and nothing past it is
/// read; the module's tail, bytes with no newline, is no line and never
/// reaches here. Answers the values in order, the bytes of the lines
/// trusted with their newlines, and the index of the first untrusted line,
/// `None` where every line read. The one reading both [`read_log`] and
/// [`Log::read_as_found`] make; whether the rest is then cut is theirs.
fn whole_lines(lines: &[Vec<u8>]) -> (Vec<Value>, u64, Option<usize>) {
    let mut values = Vec::with_capacity(lines.len());
    let mut good = 0u64;
    for (i, line) in lines.iter().enumerate() {
        let Some(v) = serde_json::from_slice::<Value>(line).ok().filter(Value::is_object) else {
            return (values, good, Some(i));
        };
        values.push(v);
        good += line.len() as u64 + 1;
    }
    (values, good, None)
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
