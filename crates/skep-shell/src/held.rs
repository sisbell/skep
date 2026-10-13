//! THE HELD-BURST STORE (`client.md` §3c.1–§3c.3), beside the key store: one
//! file per (board, principal), `held/<chain>/principal-<n>.held`, APPEND-ONLY
//! in the key store's idiom (§3.2, §3.7). The first line is the HEADER, written
//! once under `create_new` (`store.rs`'s `write_once` idiom): one JSON object,
//! no whitespace outside strings, lowercase hex, a `v`, no unknown member, one
//! `\n`. After it, one JSON object per line in TWO forms and no third — a
//! `held` line (a burst the board could not take) and a `done` line (its
//! resolution) — where a `held` line of an ordinal that already stands
//! RE-MARKS it: the reader takes it in the earlier line's place. Each line is
//! ONE `write` followed by `sync_data` BEFORE `op` answers `held` —
//! PERSIST-FIRST (J1): the answer is a promise the disk already keeps. A
//! reader IGNORES a final line without `\n` (a torn last line is the burst a
//! crash caught mid-append, R14's one).
//!
//! THE QUEUE IS THE MEMORY, THE FILE ITS COPY: a principal's [`HeldQueue`] is
//! its held lines in `k` order, and every line enters it under a fresh
//! ordinal whatever the disk did. Where the file is on disk each line is
//! copied to it as it enters; where the store keeps the queue in memory alone
//! ([`HeldQueue::in_memory`]: another window's lock, a directory out of reach,
//! §3c.3) no copy is made, and a close loses the lines. An append the device
//! refuses is answered beside the line, which stands in the queue all the same.
//! A re-mark that changes nothing is no line at all.
//!
//! THE FILE IS PRIMARY (PATTERNS P38; §3c.3): a newer `v`, an unknown header
//! member, or a middle line that is not a whole line of the two forms — not
//! UTF-8, not a JSON object, a member missing or of another type, a `doc`
//! that is no document address, an ordinal past [`MAX_ORDINAL`], a line past
//! [`MAX_HELD_LINE_BYTES`] — HALTS this principal's writing at this board
//! naming the path: never rebuilt over, never moved, never removed. A
//! MISPLACED file (header `board` not the directory's chain, or `principal`
//! not the file's name) is MOVED ASIDE by a rename that never overwrites
//! (`aside_name`'s form, the index's idiom), this principal's file started
//! fresh. COMPACTION: once the queue holds no line, the file is REMOVED under
//! the lock; a file is never rewritten in place.
//!
//! THE STORE's BUDGETS: the queue's standing frames within
//! [`MAX_HELD_FRAME_BYTES`], the board's own frame cap, refused past it and
//! kept nowhere; each line within [`MAX_HELD_LINE_BYTES`] at the writer and
//! the reader alike; and the file READ LINE BY LINE, keeping the standing
//! lines alone — so an open holds the queue it reads, never the file's
//! history of lines done.
//!
//! THE LOCK `held/<chain>/lock` (the key store's `flock` idiom, copied from
//! `search::directory::BoardDir::try_lock` — the index directory's type is the
//! index's) is held for the shell's life; a second shell finding it held holds
//! NOTHING.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use skep_search::{aside_name, Chain};

use crate::wire::{document_address, json_len, MAX_FRAME_BYTES};

/// The lock file's name, the key store's idiom (`search.md` §5.6).
const LOCK_NAME: &str = "lock";

/// THE QUEUE's BUDGET — the most bytes a principal's standing lines' frames
/// may hold together at one board: the board's own frame cap
/// ([`MAX_FRAME_BYTES`]), so a burst the hold admits always fits a queue
/// holding none. The design's estimate is that hours of typing are kilobytes
/// (§3c.3), three orders under it; a queue past it is a page holding without
/// bound — every frame copied to disk and read back at the next open — so
/// the line that would pass it is refused, and kept nowhere.
pub const MAX_HELD_FRAME_BYTES: usize = MAX_FRAME_BYTES;

/// The most bytes one line of a held file may carry, its `\n` aside — at the
/// writer and at the reader alike. A `held` line spells its frame (within
/// [`MAX_HELD_FRAME_BYTES`]) and beside it the frame's own `doc` and `id`
/// again, a second frame's worth at most, with room over for its cause and a
/// board's verdict as a daemon answers one (a few hundred bytes). The writer
/// copies no longer line — the queue keeps it, unwritten, as it keeps a line
/// the device refused — and the reader halts on one as damaged, reading no
/// more of it than one byte past the bound.
const MAX_HELD_LINE_BYTES: usize = 2 * MAX_HELD_FRAME_BYTES + 64 * 1024;

/// The largest ordinal a line may carry: `2^53 − 1`, the top of the range a
/// JSON number carries EXACTLY (AUTH-6.36's clause) — the page names a line
/// by its ordinal (`resolve`'s `held`), and a JavaScript-backed page reads
/// every number as a double. A file naming a larger one is damaged, and a
/// queue whose next ordinal would pass it holds no more lines.
const MAX_ORDINAL: u64 = (1 << 53) - 1;

/// Unix milliseconds now — a line's `time`.
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// WHY A LINE IS HELD (§3c.2): its `cause`, the board's verdict beside a
/// REFUSED run's, and whether the burst MAY have landed — the three members a
/// hold writes and a re-mark rewrites together.
#[derive(Debug, Clone, PartialEq)]
pub struct Reason {
    /// A token of §3c.4's table, or a REFUSED run's own token.
    pub cause: String,
    /// The board's verdict verbatim beside a REFUSED run's line, for the face.
    pub refusal: Option<Value>,
    /// Whether the burst MAY have landed: a dial made whose answer was lost
    /// (`Timeout`/`Io`/`Truncated`), or a `poisoned` answer, whose frames the
    /// board's journal keeps for its restart; `false` where no dial reached
    /// the board.
    pub sent: bool,
}

impl Reason {
    /// A line held for `cause`, `sent` whether the burst MAY have landed.
    pub fn of(cause: &str, sent: bool) -> Reason {
        Reason { cause: cause.to_string(), refusal: None, sent }
    }

    /// A REFUSED run's line: the board's `token` its cause, its `verdict`
    /// beside it; a refused burst landed nothing.
    pub fn refused(token: &str, verdict: Value) -> Reason {
        Reason { cause: token.to_string(), refusal: Some(verdict), sent: false }
    }
}

/// One `held` line, parsed: the burst the board could not take.
#[derive(Debug, Clone, PartialEq)]
pub struct HeldLine {
    /// The file's monotone ordinal — the resend order, across the documents.
    pub k: u64,
    /// The frame's document.
    pub doc: String,
    /// The page's envelope `id`, where it sent one (A-60).
    pub id: Option<String>,
    /// The `at` of the last ACKED write on `doc` under this session, or the
    /// session's open position — the `since` of the resend's read (§3c.5).
    pub base: u64,
    /// The page's wire frame AS COMPOSED, with no `attest` (§3c.2).
    pub frame: Value,
    /// Why the line is held.
    pub reason: Reason,
    /// The append's wall-clock unix milliseconds.
    pub time: u64,
}

/// What opening a principal's file yields.
#[derive(Debug)]
pub enum Opened {
    /// The queue read whole from the file, or a fresh one: its un-done `held`
    /// lines in `k` order; `aside` the path a MISPLACED file was moved to, for
    /// the shell's own window to say (never the page, P39).
    Live { queue: HeldQueue, aside: Option<PathBuf> },
    /// P38's HALT: the file was written by a newer skep, carries an unknown
    /// header member, or a middle line is not a whole line of the two forms —
    /// the path and the reason.
    Halted { path: PathBuf, why: HaltWhy },
}

/// Why a file is halted (P38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltWhy {
    /// A `v` above the reader's — "written by a newer skep".
    Newer,
    /// A header member the reader does not know.
    UnknownMember,
    /// A middle line that is not a whole line of the two forms — a damaged
    /// body.
    Damaged,
}

impl HaltWhy {
    /// The token the halt's face carries.
    pub fn token(self) -> &'static str {
        match self {
            HaltWhy::Newer => "newer",
            HaltWhy::UnknownMember => "unknown_member",
            HaltWhy::Damaged => "damaged",
        }
    }
}

/// THE DIRECTORY `held/<chain>/`: ensured `0700`, locked once for the shell's
/// life, a principal's file opened under it.
#[derive(Debug)]
pub struct HeldDir {
    path: PathBuf,
    chain: Chain,
}

/// One line of a held file as the reader meets it.
enum Line {
    /// A whole line, its `\n` dropped.
    Complete,
    /// The file ends before the line's `\n`: the torn last line a crash
    /// caught mid-append.
    Torn,
    /// A line past [`MAX_HELD_LINE_BYTES`], read no further than one byte
    /// past it.
    Long,
    /// No byte left.
    End,
}

/// The next line of `reader` into `buf` (cleared first), read no further
/// than one byte past [`MAX_HELD_LINE_BYTES`].
fn next_line(reader: &mut impl BufRead, buf: &mut Vec<u8>) -> io::Result<Line> {
    buf.clear();
    let read = reader.take(MAX_HELD_LINE_BYTES as u64 + 1).read_until(b'\n', buf)?;
    if read == 0 {
        return Ok(Line::End);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        return Ok(Line::Complete);
    }
    Ok(if buf.len() > MAX_HELD_LINE_BYTES { Line::Long } else { Line::Torn })
}

/// A whole line as its JSON object, or `None` where it is no UTF-8 object.
fn object(bytes: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_str(std::str::from_utf8(bytes).ok()?).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// An ordinal member, within [`MAX_ORDINAL`].
fn ordinal(v: &Value) -> Option<u64> {
    v.as_u64().filter(|k| *k <= MAX_ORDINAL)
}

/// A `held` line's members, every one of its type — `doc` a document
/// address, `id` a string where present, `frame` an object, `refusal`
/// anything but `null` where present — or `None`.
fn parse_held_line(k: u64, mut m: Map<String, Value>) -> Option<HeldLine> {
    let doc = m.get("doc")?.as_str().filter(|d| document_address(d).is_some())?.to_string();
    let id = match m.remove("id") {
        None => None,
        Some(Value::String(id)) => Some(id),
        Some(_) => return None,
    };
    let frame = m.remove("frame").filter(Value::is_object)?;
    let reason = Reason {
        cause: m.get("cause")?.as_str()?.to_string(),
        refusal: m.remove("refusal").filter(|r| !r.is_null()),
        sent: m.get("sent")?.as_bool()?,
    };
    Some(HeldLine { k, doc, id, base: m.get("base")?.as_u64()?, frame, reason, time: m.get("time")?.as_u64()? })
}

/// Whether a `done` line's members are each of its type: `as` `kept` with
/// an optional `at`, or `dropped` with none, and a `time`.
fn is_done_line(m: &Map<String, Value>) -> bool {
    let at = m.get("at");
    let resolved = match m.get("as").and_then(Value::as_str) {
        Some("kept") => at.is_none_or(Value::is_u64),
        Some("dropped") => at.is_none(),
        _ => false,
    };
    resolved && m.get("time").is_some_and(Value::is_u64)
}

impl HeldDir {
    /// `<data_dir>/held/<chain>/` — the data directory the index takes
    /// (§3c.8), the held store BESIDE the key store and never under it
    /// (§3c.1's `<app data>`).
    pub fn new(data_dir: &Path, chain: Chain) -> HeldDir {
        HeldDir { path: data_dir.join("held").join(chain.to_string()), chain }
    }

    /// The directory and `held/` above it, each `0700`, created once (§3c.1):
    /// one recursive create, which makes every missing parent with the mode
    /// it makes the directory with, and leaves a standing one as it stands.
    pub fn ensure(&self) -> io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&self.path)
    }

    /// THE LOCK (`BoardDir::try_lock`'s idiom, copied): `held/<chain>/lock`
    /// opened `0600` and `flock`ed. `Some(file)` holds it for the file's life —
    /// it dies with the process — and `None` says another shell holds it.
    pub fn try_lock(&self) -> io::Result<Option<File>> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(self.path.join(LOCK_NAME))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(e)) => Err(e),
        }
    }

    /// The file name for a principal (P39: the file, never a column).
    fn file_name(principal: u64) -> String {
        format!("principal-{principal}.held")
    }

    /// Open the principal's file, reading it LINE BY LINE with P38's faces
    /// (§3c.3): a newer `v`, an unknown header member or a middle line that is
    /// not a whole line of the two forms HALTS; a MISPLACED file is moved
    /// aside and this principal's file started fresh. Only the standing lines
    /// are held as the file is read, each re-mark in its line's place and each
    /// `done` taking its line out. `account` is the header's where this open
    /// writes one.
    pub fn open_file(&self, principal: u64, account: &str) -> io::Result<Opened> {
        let path = self.path.join(Self::file_name(principal));
        let disk = Disk { path: path.clone(), chain: self.chain, principal, account: account.to_string(), created: false };
        let fresh = |disk: Disk, aside: Option<PathBuf>| Opened::Live { queue: HeldQueue { disk: Some(disk), lines: Vec::new(), next_k: 1, held_bytes: 0 }, aside };
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(fresh(disk, None)),
            Err(e) => return Err(e),
        };
        let halted = |why: HaltWhy| Ok(Opened::Halted { path: path.clone(), why });
        let mut reader = BufReader::new(file);
        let mut buf = Vec::new();
        // No complete header line — one torn before its sync — is damaged.
        let Line::Complete = next_line(&mut reader, &mut buf)? else { return halted(HaltWhy::Damaged) };
        let Some(header) = object(&buf) else { return halted(HaltWhy::Damaged) };
        // `v` read FIRST (§3c.2): a `v` above 1 is the newer face, never half-read.
        match header.get("v").and_then(Value::as_u64) {
            Some(1) => {}
            Some(n) if n > 1 => return halted(HaltWhy::Newer),
            _ => return halted(HaltWhy::UnknownMember),
        }
        // No unknown member, and the type pinned.
        if header.get("type").and_then(Value::as_str) != Some("skep-held-bursts") {
            return halted(HaltWhy::UnknownMember);
        }
        if header.keys().any(|k| !matches!(k.as_str(), "type" | "v" | "board" | "principal" | "account")) {
            return halted(HaltWhy::UnknownMember);
        }
        // A MISPLACED file — header `board` not the directory's chain, or
        // `principal` not the file's name — moved aside, this file started fresh.
        let own_chain = header.get("board").and_then(Value::as_str).and_then(Chain::parse);
        let board_here = own_chain == Some(self.chain);
        let principal_here = header.get("principal").and_then(Value::as_u64) == Some(principal);
        if !board_here || !principal_here {
            drop(reader);
            let aside_chain = own_chain.unwrap_or(self.chain);
            let aside = self.move_aside(&Self::file_name(principal), &aside_chain)?;
            return Ok(fresh(disk, Some(aside)));
        }
        // The lines: `held` and `done`, no third, each read whole or the file
        // halted as damaged (§3c.3); a torn last line ignored.
        let mut standing: BTreeMap<u64, HeldLine> = BTreeMap::new();
        let mut max_k = 0u64;
        loop {
            match next_line(&mut reader, &mut buf)? {
                Line::Complete => {}
                Line::Torn | Line::End => break,
                Line::Long => return halted(HaltWhy::Damaged),
            }
            let Some(m) = object(&buf) else { return halted(HaltWhy::Damaged) };
            if let Some(held) = m.get("held") {
                let Some(k) = ordinal(held) else { return halted(HaltWhy::Damaged) };
                let Some(line) = parse_held_line(k, m) else { return halted(HaltWhy::Damaged) };
                max_k = max_k.max(k);
                // A `held` line of a standing ordinal is its RE-MARK
                // ([`HeldQueue::remark`]): it takes the earlier line's place.
                standing.insert(k, line);
            } else if let Some(done) = m.get("done") {
                let Some(k) = ordinal(done).filter(|_| is_done_line(&m)) else { return halted(HaltWhy::Damaged) };
                max_k = max_k.max(k);
                standing.remove(&k);
            } else {
                return halted(HaltWhy::Damaged);
            }
        }
        let lines: Vec<HeldLine> = standing.into_values().collect();
        let held_bytes = lines.iter().map(|l| json_len(&l.frame)).sum();
        let disk = Disk { created: true, ..disk };
        // `max_k` is within MAX_ORDINAL, so its successor is a `u64`.
        Ok(Opened::Live { queue: HeldQueue { disk: Some(disk), lines, next_k: max_k + 1, held_bytes }, aside: None })
    }

    /// THE ASIDE (`aside_name`'s form, the index's idiom): `name` renamed to
    /// `principal-<n>.held.aside.<its own chain>.<m>` by a rename that NEVER
    /// overwrites — the name taken by a hard link, which fails where it exists,
    /// then the original unlinked. A second misplaced file lands beside the
    /// first at `.2`. Said once in the shell's own window, never to the page.
    fn move_aside(&self, name: &str, own_chain: &Chain) -> io::Result<PathBuf> {
        let from = self.path.join(name);
        for m in 1u32.. {
            let to = self.path.join(aside_name(name, own_chain, m));
            match fs::hard_link(&from, &to) {
                Ok(()) => {
                    fs::remove_file(&from)?;
                    return Ok(to);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        unreachable!("the ordinals do not run out")
    }
}

/// ONE PRINCIPAL's QUEUE (J1: "THE SHELL holds the queue"): its un-done
/// `held` lines in `k` order, the next ordinal, the bytes its lines' frames
/// hold ([`MAX_HELD_FRAME_BYTES`]'s count), and the file the lines are
/// copied to — `None` where the store keeps them in memory alone (§3c.3).
#[derive(Debug)]
pub struct HeldQueue {
    disk: Option<Disk>,
    lines: Vec<HeldLine>,
    next_k: u64,
    held_bytes: usize,
}

/// The file a queue's lines are copied to: its path, the header's facts, and
/// whether the header is on disk yet (created lazily on the first append,
/// under `create_new`, and again after a compaction).
#[derive(Debug)]
struct Disk {
    path: PathBuf,
    chain: Chain,
    principal: u64,
    account: String,
    created: bool,
}

/// One line entered in the queue: the ordinal it took, and — where its copy
/// could not be written (§3c.3's `store_unwritable`, which the `held`
/// answer carries as `unwritable`: a full disk, a read-only volume, a line
/// past [`MAX_HELD_LINE_BYTES`]) — why. The line stands in the queue either
/// way.
#[derive(Debug)]
pub struct Entered {
    pub k: u64,
    pub unwritten: Option<io::Error>,
}

/// Why a line was not held, and is kept nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unheld {
    /// The queue's standing frames' bytes, `held_bytes`, and the line's,
    /// `frame_bytes`, would pass [`MAX_HELD_FRAME_BYTES`] — or the queue's
    /// next ordinal would pass [`MAX_ORDINAL`].
    Full { held_bytes: usize, frame_bytes: usize },
    /// The line's `doc` is no document address in its one spelling
    /// (`wire::document_address`), or its `frame` no JSON object: a line
    /// no reader of the file reads.
    Unreadable,
}

/// How a `done` line resolves its line (§3c.2's `as`): `kept` with the `at`
/// of its ack, or of the row the read found — none where the arrangement
/// alone decided — or `dropped` by the person's act, which names no position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Done {
    Kept { at: Option<u64> },
    Dropped,
}

/// Why a `done` was refused or not copied.
#[derive(Debug)]
pub enum DoneError {
    /// No `held` line of that ordinal stands — the writer refuses it (T4).
    NoSuchLine,
    /// The line left the queue and its `done` did not reach the disk: a reopen
    /// reads the line as held again, and the resend's read decides it (§3c.5).
    Unwritten(io::Error),
}

impl HeldQueue {
    /// A queue kept in memory alone (§3c.3): its lines enter and leave as a
    /// file's do, and no copy is written — a close loses them.
    pub fn in_memory() -> HeldQueue {
        HeldQueue { disk: None, lines: Vec::new(), next_k: 1, held_bytes: 0 }
    }

    /// The un-done `held` lines, in `k` order.
    pub fn lines(&self) -> &[HeldLine] {
        &self.lines
    }

    /// Whether the queue's file is on disk (a header has been written).
    #[cfg(test)]
    pub fn on_disk(&self) -> bool {
        self.disk.as_ref().is_some_and(|d| d.path.exists())
    }

    /// HOLD A LINE: entered in the queue under the next ordinal and, where the
    /// queue has a file, copied to it — one `write` then `sync_data`
    /// (PERSIST-FIRST, J1), the header written once first where the file is
    /// new. The ordinal the line took, and why its copy failed where it did,
    /// for the caller's answer to say (§3c.3); or [`Unheld`], checked in this
    /// order, the first that holds answering — its `doc` or `frame` one the
    /// reader refuses ([`Unheld::Unreadable`]), else its ordinal past
    /// [`MAX_ORDINAL`] or its frame carrying the queue's past
    /// [`MAX_HELD_FRAME_BYTES`] ([`Unheld::Full`]) — and the line kept
    /// nowhere: the writer holds no line the file's reader would halt on.
    pub fn hold(&mut self, doc: &str, id: Option<&str>, base: u64, frame: Value, reason: Reason) -> Result<Entered, Unheld> {
        if document_address(doc).is_none() || !frame.is_object() {
            return Err(Unheld::Unreadable);
        }
        let frame_bytes = json_len(&frame);
        if self.next_k > MAX_ORDINAL || self.held_bytes.saturating_add(frame_bytes) > MAX_HELD_FRAME_BYTES {
            return Err(Unheld::Full { held_bytes: self.held_bytes, frame_bytes });
        }
        let line = HeldLine { k: self.next_k, doc: doc.to_string(), id: id.map(str::to_string), base, frame, reason, time: now_ms() };
        self.next_k += 1;
        self.held_bytes += frame_bytes;
        let unwritten = self.disk.as_mut().and_then(|d| d.write_line(&held_line_bytes(&line)).err());
        let k = line.k;
        self.lines.push(line);
        Ok(Entered { k, unwritten })
    }

    /// RE-MARK a standing line — its cause, refusal and `sent` — by appending a
    /// `held` line of its ordinal, which the reader takes in its place; no
    /// `done` is owed. A reason the line already has changes nothing and
    /// writes nothing. The queue takes the reason whatever the disk did, and
    /// the device's refusal is answered for the caller to say (a reopen then
    /// reads the earlier reason). A line not standing is left alone.
    pub fn remark(&mut self, k: u64, reason: Reason) -> io::Result<()> {
        let Some(line) = self.lines.iter_mut().find(|l| l.k == k) else { return Ok(()) };
        if line.reason == reason {
            return Ok(());
        }
        line.reason = reason;
        line.time = now_ms();
        let bytes = held_line_bytes(line);
        match self.disk.as_mut() {
            Some(d) => d.write_line(&bytes),
            None => Ok(()),
        }
    }

    /// RESOLVE line `k` with a `done` line, [`Done::Kept`] or
    /// [`Done::Dropped`] (§3c.2). The line leaves the queue whatever the disk
    /// did: [`DoneError::Unwritten`] says where its `done` did not reach the
    /// file. COMPACTION: once the queue holds no line, its file is REMOVED
    /// (§3c.3) and the ordinals start again. A `done` for an ordinal with no
    /// `held` line is REFUSED (T4).
    pub fn done(&mut self, k: u64, done: Done) -> Result<(), DoneError> {
        let Some(index) = self.lines.iter().position(|l| l.k == k) else { return Err(DoneError::NoSuchLine) };
        let line = self.lines.remove(index);
        self.held_bytes = self.held_bytes.saturating_sub(json_len(&line.frame));
        // A file never created holds no line to resolve.
        let written = match self.disk.as_mut() {
            Some(d) if d.created => d.append(&done_line_bytes(k, done)),
            _ => Ok(()),
        };
        if self.lines.is_empty() {
            if let Some(d) = self.disk.as_mut() {
                d.remove();
            }
            self.next_k = 1;
            self.held_bytes = 0;
        }
        written.map_err(DoneError::Unwritten)
    }
}

impl Disk {
    /// One line copied: the header written first where the file is new. A
    /// line past [`MAX_HELD_LINE_BYTES`] is no line the reader reads, so it is
    /// refused here as the device's refusal is answered, and never written.
    fn write_line(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > MAX_HELD_LINE_BYTES + 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("the line is {} bytes, past the held store's {MAX_HELD_LINE_BYTES}", bytes.len() - 1)));
        }
        self.ensure_header()?;
        self.append(bytes)
    }

    /// The header written once under `create_new` (`store.rs`'s idiom), mode
    /// `0600`; a no-op once it stands.
    fn ensure_header(&mut self) -> io::Result<()> {
        if self.created {
            return Ok(());
        }
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&self.path)?;
        file.write_all(&header_bytes(&self.chain, self.principal, &self.account))?;
        file.sync_data()?;
        self.created = true;
        Ok(())
    }

    /// ONE `write` of the whole line, then `sync_data` BEFORE the caller builds
    /// its answer (PERSIST-FIRST). A `#[cfg(test)]` seam forces the sync to
    /// fail (T5's `store_unwritable`, which the `held` answer carries as
    /// `unwritable`) and interposes a read of the file after the sync, so a
    /// suite pins the line ON DISK before the answer is built.
    ///
    /// UNVERIFIED HERE (§3c.3, the record §7 items 2–3): that one small
    /// `write_all` is one `write(2)` (and may split for a large buffer — the
    /// torn-last-line rule covers either), and that `sync_data` orders the line
    /// before the answer, is Rust's std and APFS's `F_FULLFSYNC` — the barrier
    /// the kernel's own durability assumes, not measured here. The write-ahead
    /// variant (every burst appended before its dial, tombstoned at its ack, so
    /// even the burst in flight survives a crash) is named and NOT taken
    /// (§3c.6): R14's bound does not ask it, and the typing cadence would pay a
    /// synced append and tombstone churn.
    fn append(&self, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        file.write_all(bytes)?;
        #[cfg(test)]
        if tests::fail_sync() {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "the held store's sync was made to fail"));
        }
        file.sync_data()?;
        #[cfg(test)]
        tests::after_sync(&self.path);
        Ok(())
    }

    /// The file removed — the directory stays, and the next line recreates it.
    fn remove(&mut self) {
        let _ = fs::remove_file(&self.path);
        self.created = false;
    }
}

/// The header's exact bytes (§3c.2): members in one order, no whitespace
/// outside strings, lowercase hex, one `\n`.
fn header_bytes(chain: &Chain, principal: u64, account: &str) -> Vec<u8> {
    format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{chain}\",\"principal\":{principal},\"account\":{}}}\n", json_str(account)).into_bytes()
}

/// A `held` line's exact bytes (§3c.2): `held, doc, id?, base, frame, cause,
/// refusal?, sent, time`, in that order.
fn held_line_bytes(l: &HeldLine) -> Vec<u8> {
    let mut s = format!("{{\"held\":{},\"doc\":{}", l.k, json_str(&l.doc));
    if let Some(id) = &l.id {
        let _ = write!(s, ",\"id\":{}", json_str(id));
    }
    let _ = write!(s, ",\"base\":{},\"frame\":{}", l.base, l.frame);
    let _ = write!(s, ",\"cause\":{}", json_str(&l.reason.cause));
    if let Some(r) = &l.reason.refusal {
        let _ = write!(s, ",\"refusal\":{r}");
    }
    let _ = writeln!(s, ",\"sent\":{},\"time\":{}}}", l.reason.sent, l.time);
    s.into_bytes()
}

/// A `done` line's exact bytes (§3c.2): `done, as, at?, time`, in that order —
/// `at` on a `kept` line alone.
fn done_line_bytes(k: u64, done: Done) -> Vec<u8> {
    let (resolved, at) = match done {
        Done::Kept { at } => ("kept", at),
        Done::Dropped => ("dropped", None),
    };
    let mut s = format!("{{\"done\":{k},\"as\":\"{resolved}\"");
    if let Some(at) = at {
        let _ = write!(s, ",\"at\":{at}");
    }
    let _ = writeln!(s, ",\"time\":{}}}", now_ms());
    s.into_bytes()
}

/// A string as a JSON string literal — the one escaper the forms share.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("a `str` always serializes: it is no map key to refuse, and the in-memory writer never fails")
}

#[cfg(test)]
mod tests;
