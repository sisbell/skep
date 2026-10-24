//! A file one process writes and reads back after a crash, under one rule.
//!
//! The rule is the one the daemon's logs keep: a crash's tail — the bytes
//! of ONE line with no `\n` at the file's end, the line being written when
//! the process died and acknowledged to no one — is cut off or closed at
//! the next write, or cut at the open where the caller asks it there, and
//! answered for the caller to say once; what is not a crash's — a whole
//! line that does not read, a temp a dead run left, a removal that fails —
//! is answered as a fact and never destroyed unsaid. Bytes in, bytes out:
//! a line is its bytes without the `\n`. The parse of a line, the policy
//! for a whole line that does not read (halt on it, skip it, keep it beside
//! the file), WHEN to keep what a cut drops — the module keeps it where
//! asked ([`keep_beside`]) and judges nothing — WHEN to cut (a daemon log
//! cuts at the open after its keep, a client file at the next write), every
//! word said and to whom, and the lock on the directory are each the
//! caller's; the modes are handed in, and the module holds no constant,
//! names no store and no engine.
//!
//! * The reads: [`read_lines`], a file read whole as its lines and its
//!   [`Tail`]; [`LineReader`], the same read one line at a time within a
//!   bound, for a file never held whole, the torn line's bytes lent once
//!   the read has ended at it ([`LineReader::tail_bytes`]).
//! * The appends: [`Appender`], opened where the file's last whole line
//!   ends — found by a scan back from the end ([`Appender::open`]) or
//!   trusted from the caller's own read ([`Appender::open_at`]) — which
//!   writes a line and its `\n` in ONE write there, a tail first cut off
//!   ([`OnTail::Cut`]) or closed by a mark in that same write
//!   ([`OnTail::Close`]), then synced as asked ([`Fsync`]); a write that
//!   fails is cut back to the whole lines, the cut's own failure answered
//!   beside the write's ([`AppendFailed`]); the cut a caller makes at the
//!   open, before any write ([`Appender::cut`]); and a second handle on
//!   the file, for a sync the caller makes off its own lock
//!   ([`Appender::sync_handle`]).
//! * The whole-file writes: [`write_once`], a new file at its name, synced,
//!   a failed write removed; [`publish`], a file put at its name whole or
//!   not at all — a temp beside the name, held by an advisory lock for the
//!   write's life, synced, renamed, the directory synced — and
//!   [`publish_by`], the same through a temp the caller names and a write
//!   it streams, each failure named by its step ([`PublishStep`]); and
//!   [`keep_beside`], the bytes a cut drops kept beside the file at the
//!   first free `.cut-<byte>` name ([`KeptName`]), durably, before they go.
//! * The removals: [`remove`], answering whether a file went or none stood;
//!   [`stale`] and [`sweep_stale`], the temps a dead run left, told from a
//!   live run's by the lock its writer holds, listed or unlinked and named.
//!
//! The two ways with a tail co-exist on one surface. A file whose reader
//! halts on every line it cannot read (the shell's held-writes file) cuts
//! its tail, since the torn bytes were never acknowledged and a line
//! written after them would glue the two into one line the reader halts
//! on; a file a person may edit by hand (the client's bindings file)
//! closes it with a mark its lenient reader skips, since a last line
//! without its newline may be the person's own record and must not be
//! cut. Either way an append never changes how the bytes before it read.
//!
//! The seams for a suite: [`Appender::append_by`] (and
//! [`Appender::append_by_telling`], its typed form), [`write_once_by`] and
//! [`publish_by`] take the write as a closure, so a test — or a caller's
//! own `cfg(test)` seam — can cut a write short or refuse its sync where
//! the module's plain forms write and sync.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// A tail past the last whole line: bytes with no `\n` at the file's end.
///
/// It is the one thing a crash or a kill leaves a line-structured file
/// with — the line being written when the process died, acknowledged to
/// no one — and the one cut this module makes. `at` is the file's length
/// through its last whole line, `len` the file's whole length, and the
/// tail is the bytes between.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Tail {
    /// The byte the tail starts at: the end of the last whole line.
    pub at: u64,
    /// The file's length, where the tail ends.
    pub len: u64,
}

impl Tail {
    /// Returns the tail's bytes: the file's length past its whole lines.
    pub fn bytes(&self) -> u64 {
        self.len.saturating_sub(self.at)
    }
}

/// What a whole-line read found.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Lines {
    /// The whole lines, in order, each without its `\n`.
    pub lines: Vec<Vec<u8>>,
    /// The bytes of the whole lines, their `\n`s included.
    ///
    /// It is where the file's last whole line ends, and the count
    /// [`Appender::open_at`] takes.
    pub whole: u64,
    /// The tail past them, where the file holds one.
    pub tail: Option<Tail>,
}

/// Reads `path` whole as its lines; `None` where no file stands.
///
/// It writes nothing: the tail it finds is answered, never cut. A whole
/// line that does not read is the caller's to judge; a line's length is
/// the caller's to bound, the file being read whole.
///
/// # Errors
///
/// The read's I/O error, save a file not found.
pub fn read_lines(path: &Path) -> io::Result<Option<Lines>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut lines = Vec::new();
    let mut whole = 0usize;
    for piece in bytes.split_inclusive(|&b| b == b'\n') {
        let Some(line) = piece.strip_suffix(b"\n") else { break };
        lines.push(line.to_vec());
        whole += piece.len();
    }
    let tail = (whole < bytes.len()).then_some(Tail { at: whole as u64, len: bytes.len() as u64 });
    Ok(Some(Lines { lines, whole: whole as u64, tail }))
}

/// A file read one line at a time, within a bound, never held whole.
///
/// It answers each whole line in turn ([`Next::Line`]), then what ends
/// the read: a line past the bound ([`Next::Long`]), a tail
/// ([`Next::Tail`]) or the file's end ([`Next::End`]). The bytes of the
/// whole lines read so far are counted ([`LineReader::whole`]), so the
/// caller's next append is written where the last of them ends; the torn
/// line's bytes stay lent once the read has ended at a tail
/// ([`LineReader::tail_bytes`]).
#[derive(Debug)]
pub struct LineReader {
    reader: BufReader<File>,
    bound: usize,
    whole: u64,
    done: bool,
    /// Whether the read ended at a tail, whose bytes `buf` then holds.
    torn: bool,
    buf: Vec<u8>,
}

/// What a [`LineReader`] meets next.
#[derive(Debug, PartialEq, Eq)]
pub enum Next<'a> {
    /// A whole line, its `\n` dropped.
    Line(&'a [u8]),
    /// A line past the bound, starting at byte `at`.
    ///
    /// It is read no further than one byte past the bound, and the read
    /// ends here: the caller's class B, never a crash's tail.
    Long {
        /// The byte the line starts at.
        at: u64,
    },
    /// The tail past the last whole line; the read ends here.
    Tail(Tail),
    /// No byte left.
    End,
}

impl LineReader {
    /// Opens `path` for a read line by line; `None` where no file stands.
    ///
    /// A line may hold `bound` bytes, its `\n` aside; a longer one ends
    /// the read as [`Next::Long`].
    ///
    /// # Errors
    ///
    /// The open's I/O error, save a file not found.
    pub fn open(path: &Path, bound: usize) -> io::Result<Option<LineReader>> {
        match File::open(path) {
            Ok(file) => Ok(Some(LineReader { reader: BufReader::new(file), bound, whole: 0, done: false, torn: false, buf: Vec::new() })),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Reads the next line, or what ends the read.
    ///
    /// Once the read has ended — at a long line, a tail or the end — every
    /// later call answers [`Next::End`]. It is no `Iterator`: each line is
    /// lent from the reader's own buffer, read over by the next.
    ///
    /// # Errors
    ///
    /// The read's I/O error.
    pub fn next_line(&mut self) -> io::Result<Next<'_>> {
        if self.done {
            return Ok(Next::End);
        }
        self.buf.clear();
        let read = (&mut self.reader).take(self.bound as u64 + 1).read_until(b'\n', &mut self.buf)?;
        if read == 0 {
            self.done = true;
            return Ok(Next::End);
        }
        if self.buf.last() == Some(&b'\n') {
            self.buf.pop();
            self.whole += read as u64;
            return Ok(Next::Line(&self.buf));
        }
        self.done = true;
        if self.buf.len() > self.bound {
            return Ok(Next::Long { at: self.whole });
        }
        self.torn = true;
        Ok(Next::Tail(Tail { at: self.whole, len: self.whole + read as u64 }))
    }

    /// Returns the bytes of the whole lines read so far, `\n`s included.
    pub fn whole(&self) -> u64 {
        self.whole
    }

    /// Returns the torn line's bytes, once the read has ended at a tail.
    ///
    /// They are the bytes [`Next::Tail`] stood for — the line being written
    /// when the process died, without its `\n` — lent for a caller that reads
    /// a figure off them, the position a torn feed line names, without a
    /// second read of the file; they stand through every later call, which
    /// answers [`Next::End`]. Empty before the read has ended, where it ended
    /// at the file's end, and where it ended at a line past the bound, which
    /// is no tail.
    pub fn tail_bytes(&self) -> &[u8] {
        if self.torn {
            &self.buf
        } else {
            &[]
        }
    }
}

/// What an append does with a tail it finds past the last whole line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnTail<'a> {
    /// Cut it off: a crash's line, acknowledged to no one.
    ///
    /// The file whose reader halts on a line it cannot read takes this
    /// way, since a line written after the torn bytes would glue the two.
    Cut,
    /// Close it with these bytes and a `\n`, in the same write as the line.
    ///
    /// The file a person may edit by hand takes this way: a last line
    /// without its newline may be the person's own record, so it is never
    /// cut, and the mark makes it a whole line the file's lenient reader
    /// skips. The torn bytes stay in the file.
    Close(&'a [u8]),
}

/// Which sync follows an append's write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fsync {
    /// `sync_all`: the bytes and the file's metadata.
    All,
    /// `sync_data`: the bytes.
    Data,
    /// No sync: the line's durability is the OS's.
    None,
}

/// What one append found and did, for the caller to say once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Appended {
    /// The tail the append found past the last whole line, if any.
    pub tail: Option<Tail>,
    /// Whether that tail was closed by a mark, rather than cut off.
    pub closed: bool,
}

/// The append-mode file, written where its last whole line ends.
#[derive(Debug)]
pub struct Appender {
    file: File,
    whole: u64,
}

impl Appender {
    /// Opens `path` for appending, created at `mode` where absent.
    ///
    /// The last whole line's end is found by a scan back from the file's
    /// end for the last `\n` — the whole file, where it holds none.
    ///
    /// # Errors
    ///
    /// The open's or the scan's I/O error.
    pub fn open(path: &Path, mode: u32) -> io::Result<Appender> {
        let mut opts = OpenOptions::new();
        opts.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut file = opts.open(path)?;
        let whole = last_newline_end(&mut file)?;
        Ok(Appender { file, whole })
    }

    /// Opens the file at `path`, trusting `whole` as its whole lines' bytes.
    ///
    /// The count is the caller's own read's ([`LineReader::whole`],
    /// [`Lines::whole`]) or its own count of the lines it wrote. The file
    /// stands already — its first line was written by [`write_once`] or an
    /// earlier append — so none is created here. A file that may be absent
    /// is opened by [`Appender::open`], whose scan over nothing answers
    /// `whole` 0; a caller that read the file itself opens at its count
    /// where the read answered a file.
    ///
    /// # Errors
    ///
    /// The open's I/O error, `NotFound` where no file stands.
    pub fn open_at(path: &Path, whole: u64) -> io::Result<Appender> {
        let file = OpenOptions::new().append(true).open(path)?;
        Ok(Appender { file, whole })
    }

    /// Cuts the tail past the whole lines now, where one stands, and answers it.
    ///
    /// It is the daemon's logs' way, which cut at the open after their keep,
    /// where the client's files leave the cut to the next write
    /// ([`Appender::append`]). A cut, never a close: a file whose tail is
    /// closed by a mark has no call here. The cut is to the count the
    /// appender trusts — the scan's ([`Appender::open`]) or the caller's own
    /// ([`Appender::open_at`]) — so at a count below a whole line that line
    /// goes with the tail: what the caller keeps of the bytes past its
    /// count, it keeps first ([`keep_beside`]). The cut is synced as `fsync`
    /// asks. `None` where no tail stands, nothing written.
    ///
    /// # Errors
    ///
    /// The metadata read's, the cut's or the sync's I/O error.
    pub fn cut(&mut self, fsync: Fsync) -> io::Result<Option<Tail>> {
        let len = self.file.metadata()?.len();
        if len <= self.whole {
            return Ok(None);
        }
        self.file.set_len(self.whole)?;
        sync(&self.file, fsync)?;
        Ok(Some(Tail { at: self.whole, len }))
    }

    /// Appends `line` and its `\n` in one write, then syncs as `fsync` asks.
    ///
    /// A tail past the last whole line is first dealt with as `on_tail`
    /// says, and answered. It is [`Appender::append_by`] with the write and
    /// the sync as the plain forms make them.
    ///
    /// # Errors
    ///
    /// [`Appender::append_by`]'s.
    pub fn append(&mut self, line: &[u8], on_tail: OnTail<'_>, fsync: Fsync) -> io::Result<Appended> {
        self.append_by(line, on_tail, |file, bytes| {
            file.write_all(bytes)?;
            sync(file, fsync)
        })
    }

    /// Appends `line` and its `\n` through `write`, the append's one body.
    ///
    /// A tail past the last whole line is first cut off ([`OnTail::Cut`])
    /// or put ahead of the line in the bytes `write` is handed, closed by
    /// the mark and a `\n` ([`OnTail::Close`]), so the line lands where the
    /// file's last whole line ends either way and the bytes before it read
    /// as they did. `write` is given the file and the bytes, the line's
    /// `\n` among them, and makes the write and whatever sync the line owes
    /// — a suite's own seam, which cuts a write short or refuses its sync.
    /// The whole lines' count moves only once `write` has answered. It is
    /// [`Appender::append_by_telling`] with the cut-back unsynced and its
    /// two failures folded into one error.
    ///
    /// # Errors
    ///
    /// The metadata read's or the cut's I/O error, nothing written; or
    /// `write`'s, the file first cut back to its whole lines (under
    /// [`OnTail::Close`], to the bytes it held before the append, the torn
    /// tail among them) — where that cut fails too, its failure is named
    /// beside the write's in the one error answered, the file then holding
    /// a tail the next append cuts.
    pub fn append_by(&mut self, line: &[u8], on_tail: OnTail<'_>, write: impl FnOnce(&mut File, &[u8]) -> io::Result<()>) -> io::Result<Appended> {
        Ok(self.append_by_telling(line, on_tail, Fsync::None, write)?)
    }

    /// Appends `line` through `write`, its failure typed, its cut-back synced.
    ///
    /// It is [`Appender::append_by`] with the failure kept apart
    /// ([`AppendFailed`]) and the cut back to the whole lines synced as
    /// `cut_back` asks — the daemon's logs sync it, the client's files do
    /// not — for a caller that stops on a failed cut-back and words each
    /// cause itself.
    ///
    /// # Errors
    ///
    /// [`Appender::append_by`]'s, each failure in its own field: the
    /// metadata read's or the cut's, nothing written and no cut-back owed;
    /// or `write`'s, the file first cut back to its whole lines (under
    /// [`OnTail::Close`], to the bytes it held before the append, the torn
    /// tail among them) and that cut synced — where the cut or its sync
    /// fails too, that failure stands beside the write's, the file then
    /// holding a tail the next append cuts.
    pub fn append_by_telling(&mut self, line: &[u8], on_tail: OnTail<'_>, cut_back: Fsync, write: impl FnOnce(&mut File, &[u8]) -> io::Result<()>) -> Result<Appended, AppendFailed> {
        let before = |write: io::Error| AppendFailed { write, cut_back: None };
        let len = self.file.metadata().map_err(before)?.len();
        let tail = (len > self.whole).then_some(Tail { at: self.whole, len });
        let mut bytes = Vec::with_capacity(line.len() + 1);
        let mut closed = false;
        let mut start = self.whole.min(len);
        if tail.is_some() {
            match on_tail {
                OnTail::Cut => self.file.set_len(self.whole).map_err(before)?,
                OnTail::Close(mark) => {
                    bytes.extend_from_slice(mark);
                    bytes.push(b'\n');
                    closed = true;
                    start = len;
                }
            }
        }
        bytes.extend_from_slice(line);
        bytes.push(b'\n');
        if let Err(write) = write(&mut self.file, &bytes) {
            let cut = self.file.set_len(start).and_then(|()| sync(&self.file, cut_back));
            return Err(AppendFailed { write, cut_back: cut.err() });
        }
        self.whole = start + bytes.len() as u64;
        Ok(Appended { tail, closed })
    }

    /// Returns the bytes of the file's whole lines, where the next line lands.
    pub fn whole(&self) -> u64 {
        self.whole
    }

    /// Returns a second handle on the file, for a sync off the caller's lock.
    ///
    /// It is the appender's own open file duplicated (`try_clone`): one open
    /// file description, so a sync through the handle makes durable every
    /// line the appender wrote before it, and a failure there is the file's.
    /// The attest store's way: its line is written under the feed's lock and
    /// made durable through this handle once that lock is released, so no
    /// page waits on the fsync. The handle names the file the appender holds
    /// now — the one it was opened on, which a rewrite's rename replaces — so
    /// a caller that reopens after a rename takes the handle anew.
    ///
    /// # Errors
    ///
    /// The duplication's I/O error.
    pub fn sync_handle(&self) -> io::Result<File> {
        self.file.try_clone()
    }
}

/// What a failed append left: the write's failure and the cut-back's.
///
/// The write's is the failure the append answered — `write`'s, or, before
/// any write, the metadata read's or the tail's cut's. The cut-back's
/// stands beside it where the cut back to the whole lines, or its sync,
/// failed too, the file then holding a tail the next append cuts: a caller
/// that stops on that second failure reads each cause on its own. Through
/// `From`, the two are one `io::Error` of the write's kind naming both.
#[derive(Debug)]
#[non_exhaustive]
pub struct AppendFailed {
    /// The failure the append answered: `write`'s, or an act's before it.
    pub write: io::Error,
    /// The cut-back's failure, where the cut back to the whole lines failed too.
    pub cut_back: Option<io::Error>,
}

impl From<AppendFailed> for io::Error {
    fn from(failed: AppendFailed) -> io::Error {
        match failed.cut_back {
            None => failed.write,
            Some(cut) => io::Error::new(failed.write.kind(), format!("{}; and the cut back to the last whole line failed too: {cut}", failed.write)),
        }
    }
}

/// Returns where the last `\n` of `file` ends, or 0 where it holds none.
///
/// The scan runs back from the file's end a chunk at a time, so a file
/// whose tail is short reads one chunk.
///
/// # Errors
///
/// The metadata read's, a seek's or a read's I/O error.
fn last_newline_end(file: &mut File) -> io::Result<u64> {
    const CHUNK: u64 = 4096;
    let mut end = file.metadata()?.len();
    let mut chunk = vec![0u8; CHUNK as usize];
    while end > 0 {
        let start = end.saturating_sub(CHUNK);
        let n = (end - start) as usize;
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut chunk[..n])?;
        if let Some(i) = chunk[..n].iter().rposition(|&b| b == b'\n') {
            return Ok(start + i as u64 + 1);
        }
        end = start;
    }
    Ok(0)
}

/// Writes `bytes` to a new file at `path`, synced; a failed write removed.
///
/// It is [`write_once_by`] with the write and the sync (`sync_all`) as
/// the plain form makes them.
///
/// # Errors
///
/// [`write_once_by`]'s.
pub fn write_once(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    write_once_by(path, bytes, mode, |file, bytes| {
        file.write_all(bytes)?;
        file.sync_all()
    })
}

/// Writes `bytes` to a new file at `path` through `write`, the one body.
///
/// The open is `create_new` at `mode` — set at creation, never chmod'd
/// after a world-readable moment — so a file that stands at `path` is
/// refused and left as it stands. `write` is given the file and the
/// bytes and makes the write and the sync — a suite's own seam.
///
/// # Errors
///
/// The open's I/O error, `AlreadyExists` for a standing file; or
/// `write`'s, the file this call made first removed — where that removal
/// fails, its failure is named beside the write's in the one error
/// answered, and the file stands with what was written.
pub fn write_once_by(path: &Path, bytes: &[u8], mode: u32, write: impl FnOnce(&mut File, &[u8]) -> io::Result<()>) -> io::Result<()> {
    let mut file = create_new(path, mode)?;
    if let Err(e) = write(&mut file, bytes) {
        drop(file);
        return Err(match fs::remove_file(path) {
            Ok(()) => e,
            Err(rm) if rm.kind() == io::ErrorKind::NotFound => e,
            Err(rm) => io::Error::new(e.kind(), format!("{e}; and the file could not be removed after it: {rm}")),
        });
    }
    Ok(())
}

/// What [`publish`] does with a standing temp no live writer holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnStale {
    /// Refuse the publish, `AlreadyExists`: the temp is someone's to sweep.
    Refuse,
    /// Remove the temp and write afresh: the one writer's own leftover.
    Replace,
}

/// Returns the temp's name beside `path`: `<path>.tmp`.
///
/// It is the name [`publish`] writes to before its rename, and the one a
/// kill leaves behind — the suffix [`stale`] and [`sweep_stale`] are asked
/// for.
pub fn temp_of(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

/// Puts `bytes` at `path` whole or not at all.
///
/// The bytes go to `<path>.tmp` ([`temp_of`]) under `create_new` at
/// `mode`, the temp held by an advisory lock for the write's life, so a
/// sweep tells this writer's temp from a dead run's; written and synced;
/// renamed to `path`; and the directory synced, so the name is as durable
/// as the bytes. A temp that stands at the name is a live writer's where
/// its lock is held, and refused; one no writer holds is `stale`'s. A
/// kill inside the call leaves the temp alone, or the temp whole, or the
/// name made and the directory unsynced — never a part of a file at
/// `path`.
///
/// **Precondition.** No file stands at `path`, which the rename would
/// replace: a caller that replaces a file by design (a derived file
/// rewritten whole) names that in its own doc.
///
/// # Errors
///
/// The temp's open — `AlreadyExists` for a standing temp a live writer
/// holds, or one no writer holds under [`OnStale::Refuse`] — or the stale
/// temp's removal; the write's or the sync's, the temp removed; the
/// rename's, the temp removed; or the directory sync's, the file at
/// `path` removed. A removal that fails after a failure is named beside
/// it in the one error answered.
pub fn publish(path: &Path, bytes: &[u8], mode: u32, stale: OnStale) -> io::Result<()> {
    match publish_by(path, &temp_of(path), mode, stale, |file| file.write_all(bytes)) {
        Ok(()) => Ok(()),
        // Past the rename a new file stands at its name with the directory
        // unsynced: removed, since it was never there to lose.
        Err(PublishFail { step: PublishStep::DirSync, error }) => Err(match fs::remove_file(path) {
            Ok(()) => error,
            Err(rm) if rm.kind() == io::ErrorKind::NotFound => error,
            Err(rm) => io::Error::new(error.kind(), format!("{error}; and the file could not be removed after it: {rm}")),
        }),
        Err(PublishFail { error, .. }) => Err(error),
    }
}

/// A step of [`publish_by`], where it fell.
///
/// Before the rename — the temp's making, the write, the sync, the rename
/// itself — the temp is removed and the name is as it was; at the
/// directory's sync, past the rename, the file stands at its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PublishStep {
    /// The temp's making: its `create_new` at the caller's name, a stale
    /// temp's removal before it, or the lock taken on it.
    Create,
    /// The write through the caller's closure.
    Write,
    /// The temp's `sync_all`.
    Sync,
    /// The rename of the temp onto the name.
    Rename,
    /// The directory's sync after the rename: the file stands at its name.
    DirSync,
}

/// A failed publish: the step it fell at, and the failure.
///
/// Where the temp's removal after a failure before the rename fails too,
/// that failure is named inside the error's text, as [`publish`] names it.
#[derive(Debug)]
#[non_exhaustive]
pub struct PublishFail {
    /// The step that failed.
    pub step: PublishStep,
    /// Its I/O error.
    pub error: io::Error,
}

/// Puts a file at `path` whole or not at all, through the caller's temp.
///
/// It is [`publish`] with three things the caller's: the temp's name —
/// `temp`, the daemon's `<name>.compact` twins beside the client's
/// [`temp_of`] — the write, which `write` streams into the open temp, and
/// the failure, typed by its step ([`PublishFail`]). The temp is made under
/// `create_new` at `mode` (a standing one as `stale` says), held by an
/// advisory lock for the write's life, written through `write`, synced,
/// renamed onto `path` — over a file that stands there, where the caller
/// rewrites one whole — and the directory synced. A failure before the
/// rename removes the temp, so the name is as it was; a failure past it,
/// the directory's sync, leaves the file standing at `path`, whole, and
/// names the step — the caller's to stop on, a name that may yet be lost
/// to a power cut being no reason to destroy the bytes under it. `publish`
/// is this with [`temp_of`]'s name, the bytes written whole, and the
/// removal a new file's failure past the rename owes.
///
/// # Errors
///
/// [`PublishStep::Create`]: the temp's open — `AlreadyExists` for a
/// standing temp a live writer holds, or one no writer holds under
/// [`OnStale::Refuse`] — a stale temp's removal, or the lock; nothing
/// made. [`PublishStep::Write`], [`PublishStep::Sync`] and
/// [`PublishStep::Rename`]: `write`'s, the sync's or the rename's
/// failure, the temp removed — a removal that fails is named beside it in
/// the one error. [`PublishStep::DirSync`]: the directory's sync failing,
/// the file standing at `path`.
pub fn publish_by(path: &Path, temp: &Path, mode: u32, stale: OnStale, write: impl FnOnce(&mut File) -> io::Result<()>) -> Result<(), PublishFail> {
    let fail = |step: PublishStep, error: io::Error| PublishFail { step, error };
    let mut file = match create_new(temp, mode) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && stale == OnStale::Replace => {
            replace_stale(temp).and_then(|()| create_new(temp, mode)).map_err(|e| fail(PublishStep::Create, e))?
        }
        Err(e) => return Err(fail(PublishStep::Create, e)),
    };
    let undone = |e: io::Error| -> io::Error {
        match fs::remove_file(temp) {
            Ok(()) => e,
            Err(rm) if rm.kind() == io::ErrorKind::NotFound => e,
            Err(rm) => io::Error::new(e.kind(), format!("{e}; and the temp could not be removed after it: {rm}")),
        }
    };
    let locked = match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(io::Error::new(io::ErrorKind::WouldBlock, format!("another process holds {}", temp.display()))),
        Err(TryLockError::Error(e)) => Err(e),
    };
    if let Err(e) = locked {
        return Err(fail(PublishStep::Create, undone(e)));
    }
    if let Err(e) = write(&mut file) {
        return Err(fail(PublishStep::Write, undone(e)));
    }
    if let Err(e) = file.sync_all() {
        return Err(fail(PublishStep::Sync, undone(e)));
    }
    if let Err(e) = fs::rename(temp, path) {
        return Err(fail(PublishStep::Rename, undone(e)));
    }
    if let Err(e) = sync_parent(path) {
        return Err(fail(PublishStep::DirSync, e));
    }
    drop(file);
    Ok(())
}

/// Removes the temp at `tmp` where no live writer holds it.
///
/// # Errors
///
/// `AlreadyExists` where a live writer holds the temp; the open's or the
/// removal's I/O error otherwise, save a temp gone meanwhile.
fn replace_stale(tmp: &Path) -> io::Result<()> {
    let standing = match OpenOptions::new().read(true).open(tmp) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    match standing.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} is held by a live writer", tmp.display()))),
        Err(TryLockError::Error(e)) => return Err(e),
    }
    match fs::remove_file(tmp) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The name a keep gave the bytes it kept: `{file}.cut-{byte}`, `….{k}`.
///
/// It is the spelling the kernel gives a journal tail it keeps and the
/// daemon's logs give a damaged cut, so one listing of a data directory
/// finds every kept file. `k` is `0` for the bare name and `k` for the
/// `.{k}` beside it — the first free name [`keep_beside`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeptName {
    /// The byte of the file the kept bytes started at.
    pub byte: u64,
    /// Which free name the keep took: `0` the bare name, else the `.{k}`.
    pub k: u64,
}

impl KeptName {
    /// Returns the kept file's name beside `file`.
    ///
    /// `file` is spelled as the caller names the file the kept one sits
    /// beside — its bare name for the path on disk, or its name within a
    /// data directory for a line that says it (`blobs/leases.log.cut-8`).
    pub fn of(self, file: &str) -> String {
        match self.k {
            0 => format!("{file}.cut-{}", self.byte),
            k => format!("{file}.cut-{}.{k}", self.byte),
        }
    }
}

/// A step of [`keep_beside`], where it fell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeepStep {
    /// The kept file's making: `create_new` at the first free name.
    Create,
    /// The copy of the dropped bytes into it: the reader's or the write's failure.
    Write,
    /// The kept file's `sync_all`.
    Fsync,
    /// The directory's sync after it.
    DirSync,
}

/// A failed keep: the step it fell at, the name it was at, and the failure.
///
/// Past the making, the kept file stands with what was written — a
/// half-kept file beside the log is a fact for the caller to say, never a
/// loss made larger by a removal — so the name is answered with the step.
#[derive(Debug)]
#[non_exhaustive]
pub struct KeepFail {
    /// The step that failed.
    pub step: KeepStep,
    /// The name the keep was at: the one it made, or the one it could not.
    pub name: KeptName,
    /// Its I/O error.
    pub error: io::Error,
}

/// Keeps `dropped` beside `file` in `dir`, durably, before a cut drops it.
///
/// The bytes go to the first free name of `{file}.cut-{byte}`,
/// `{file}.cut-{byte}.{k}` ([`KeptName`]) under `create_new` at `mode` — a
/// standing name is never written over, whatever it holds — copied through
/// from `dropped`, synced, and the directory synced after, so the kept
/// file outlives a power cut as the cut it precedes does. WHEN to keep is
/// the caller's: a whole line that does not read and the lines after it,
/// which a crash never leaves, the daemon's logs keep before their open
/// cuts them; a crash's tail, acknowledged to no one, is kept by nobody.
/// The directory's sync is refused as the daemon's installs refuse one —
/// no filesystem's answer is tolerated — where [`publish`] tolerates a
/// directory that takes no sync. Answers the name taken.
///
/// # Errors
///
/// Each step's I/O error with the step and the name ([`KeepFail`]): the
/// making's, nothing made; the copy's — `dropped`'s read or the write —
/// the sync's or the directory's sync's, the kept file standing with what
/// was written.
pub fn keep_beside(dir: &Path, file: &str, byte: u64, dropped: impl io::Read, mode: u32) -> Result<KeptName, KeepFail> {
    let mut dropped = dropped;
    let mut k = 0u64;
    let (mut out, name) = loop {
        let name = KeptName { byte, k };
        match create_new(&dir.join(name.of(file)), mode) {
            Ok(out) => break (out, name),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => k += 1,
            Err(error) => return Err(KeepFail { step: KeepStep::Create, name, error }),
        }
    };
    let fail = |step: KeepStep, error: io::Error| KeepFail { step, name, error };
    io::copy(&mut dropped, &mut out).map_err(|e| fail(KeepStep::Write, e))?;
    out.sync_all().map_err(|e| fail(KeepStep::Fsync, e))?;
    drop(out);
    sync_dir(dir).map_err(|e| fail(KeepStep::DirSync, e))?;
    Ok(name)
}

/// What a removal did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Removed {
    /// A file stood and went.
    Gone,
    /// No file stood.
    Absent,
}

/// Removes the file at `path`, answering whether one went or none stood.
///
/// # Errors
///
/// Every other failure of the unlink — a permission refused, a read-only
/// volume — which leaves the file standing: the caller's to say, never a
/// file destroyed.
pub fn remove(path: &Path) -> io::Result<Removed> {
    match fs::remove_file(path) {
        Ok(()) => Ok(Removed::Gone),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Removed::Absent),
        Err(e) => Err(e),
    }
}

/// What a sweep of stale temps did, for the caller to say once.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Sweep {
    /// The temps unlinked, in name order.
    pub removed: Vec<PathBuf>,
    /// The temps that stand, each with the failure that left it.
    pub failed: Vec<(PathBuf, io::Error)>,
}

/// Returns the temps under `dir` ending in `suffix` no live writer holds.
///
/// A temp is a live writer's where its advisory lock is held
/// ([`publish`] holds one for the write's life), and skipped; one no
/// writer holds is a dead run's, listed in name order. A directory that
/// does not stand holds none.
///
/// # Errors
///
/// The directory's read, or a temp's open or lock failing for a cause
/// other than its being held, save one gone meanwhile.
pub fn stale(dir: &Path, suffix: &str) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    each_stale(dir, suffix, |path, held| held.map(|_| out.push(path)))?;
    out.sort();
    Ok(out)
}

/// Unlinks the temps under `dir` ending in `suffix` no live writer holds.
///
/// Each is held by its lock through the unlink, so a writer that opens
/// the same name meanwhile is not swept from under. It answers the names
/// removed and the names that stand, each with its failure, for the
/// caller to say once; a temp gone meanwhile is neither.
///
/// # Errors
///
/// The directory's read failing, nothing swept.
pub fn sweep_stale(dir: &Path, suffix: &str) -> io::Result<Sweep> {
    let mut sweep = Sweep::default();
    each_stale(dir, suffix, |path, held| {
        match held.and_then(|_| fs::remove_file(&path)) {
            Ok(()) => sweep.removed.push(path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => sweep.failed.push((path, e)),
        }
        Ok(())
    })?;
    sweep.removed.sort();
    sweep.failed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(sweep)
}

/// Runs `f` over each temp under `dir` ending in `suffix` no live writer holds.
///
/// `f` is handed the temp's path and the open, locked file — the lock
/// held while `f` runs, released after — or the failure of its open or
/// its lock. A temp whose lock is held elsewhere is a live writer's,
/// skipped; one gone between the listing and its open is skipped too.
///
/// # Errors
///
/// The directory's read failing, save its absence, which holds no temp;
/// or an error `f` answers.
fn each_stale(dir: &Path, suffix: &str, mut f: impl FnMut(PathBuf, io::Result<File>) -> io::Result<()>) -> io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_name().as_encoded_bytes().ends_with(suffix.as_bytes()) {
            continue;
        }
        let path = entry.path();
        let held = match OpenOptions::new().read(true).open(&path) {
            Ok(file) => match file.try_lock() {
                Ok(()) => Ok(file),
                Err(TryLockError::WouldBlock) => continue,
                Err(TryLockError::Error(e)) => Err(e),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => Err(e),
        };
        f(path, held)?;
    }
    Ok(())
}

/// Opens a new file at `path` for writing, at `mode`.
///
/// # Errors
///
/// The open's I/O error, `AlreadyExists` where a file stands.
fn create_new(path: &Path, mode: u32) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path)
}

/// Syncs `file` as `fsync` asks.
///
/// # Errors
///
/// The sync's I/O error.
fn sync(file: &File, fsync: Fsync) -> io::Result<()> {
    match fsync {
        Fsync::All => file.sync_all(),
        Fsync::Data => file.sync_data(),
        Fsync::None => Ok(()),
    }
}

/// Syncs the directory holding `path`, so a rename into it is durable.
///
/// A directory that takes no sync is no failure: a filesystem that
/// answers the sync `Unsupported`, or `InvalidInput` as some answer a
/// directory's — there the name is as durable as the filesystem makes it.
///
/// # Errors
///
/// An I/O error opening or syncing the directory, save those two.
#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    match File::open(dir)?.sync_all() {
        Err(e) if matches!(e.kind(), io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput) => Ok(()),
        other => other,
    }
}

/// Syncs nothing: on this platform a directory opens as no file.
///
/// A rename here is as durable as the filesystem makes it.
///
/// # Errors
///
/// Never.
#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Syncs the directory `dir`, tolerating nothing.
///
/// It is the sync the daemon's installs make after a creation inside
/// `dir`, which [`keep_beside`] takes: whatever the filesystem answers is
/// the failure, where [`sync_parent`] tolerates a directory that takes no
/// sync.
///
/// # Errors
///
/// An I/O error opening or syncing the directory.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Syncs nothing: on this platform a directory opens as no file.
///
/// # Errors
///
/// Never.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests;
