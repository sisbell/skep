//! The held-burst store (`client.md` §3c.1–§3c.3), beside the key store.
//!
//! It is one file per (board, principal), `held/<chain>/principal-<n>.held`,
//! append-only in the key store's idiom (§3.2, §3.7), written and read
//! through `skep_util::file` — the one tail rule the key store's files keep
//! too. The first line is the header, written once under `create_new`
//! (`file::write_once`, so a header the device did not take whole leaves no
//! file): one JSON object, no whitespace outside strings, lowercase hex, a
//! `v`, no unknown member, one `\n`. After it, one JSON object per line in
//! two forms and no third — a `held` line (a burst the board could not
//! take) and a `done` line (its resolution) — where a `held` line of an
//! ordinal that already stands re-marks it: the reader takes it in the
//! earlier line's place. Each line is one `write` followed by `sync_data`
//! before `op` answers `held` — persist-first: the answer is a promise the
//! disk already keeps. A reader ignores a final line without `\n` within
//! [`MAX_HELD_LINE_BYTES`] (a torn last line is the burst a crash caught
//! mid-append, R14's one).
//!
//! **A torn line is only ever the tail.** Every line is written where the
//! file's last whole line ends (`file::Appender`, trusting the count the
//! open made). A copy the device refuses — its write cut short, or its sync
//! refused — is cut back off the file, and a tail past the whole lines — a
//! crash's torn line, or a refused copy whose cut-back failed — is cut off
//! before the next line is written (`OnTail::Cut`), so no line is written
//! after bytes no reader reads, which would glue the two into one line the
//! reader halts on (P38). It is the rule skep-blobs' `jsonl` log keeps. The
//! bindings file's way — a torn line closed by a mark its lenient reader
//! skips (`store.rs`'s `TORN_MARK`) — is not this file's, whose reader
//! halts on every line that is not one of the two forms. A file with no
//! whole header line — empty, or its header torn before its sync: a crash
//! between the create and the sync, or a refused header whose removal
//! failed too — is the same tail at the file's head: it has had no `held`
//! answered over it, since the header is synced before any line, so the
//! open reads it as FRESH and the next line written cuts its bytes and
//! heads the file; the open answers what it found ([`HeldQueue::torn`])
//! for the shell to say once.
//!
//! **The queue is the memory, the file its copy.** A principal's
//! [`HeldQueue`] is its held lines in `k` order, and every line enters it
//! under a fresh ordinal whatever the disk did. Where the file is on disk
//! each line is copied to it as it enters; where the store keeps the queue
//! in memory alone ([`HeldQueue::in_memory`]: a directory out of reach —
//! another process's lock on it among the causes, §3c.3) no copy is made,
//! and a close loses the lines. An append the device refuses is answered
//! beside the line, which
//! stands in the queue all the same, its bytes cut back off the file. A
//! re-mark that changes nothing is no line at all. A line kept at a position
//! raises to it the `base` of every line held after it on its document
//! ([`HeldQueue::done`]), in the queue as the `done` is written and again at
//! a reopen from that `done` line, so no line is rewritten to carry it
//! (§3c.2).
//!
//! **The file is primary** (PATTERNS P38; §3c.3). A newer `v`, an unknown
//! header member, or a middle line that is not a whole line of the two
//! forms — not UTF-8, not a JSON object, a member missing or of another
//! type, a `doc` that is no document address, an ordinal past
//! [`MAX_ORDINAL`], a line past [`MAX_HELD_LINE_BYTES`] — halts this
//! principal's writing at this board naming the path, and so does a whole
//! header line that is no JSON object, names another `type` or carries no
//! `v` of 1 or more: never rebuilt over a whole line, never moved, never
//! removed. A misplaced file (header `board` not the directory's chain, or
//! `principal` not the file's name) is moved aside by a rename that never
//! overwrites (`aside_name`'s form, the index's idiom), this principal's
//! file started fresh.
//!
//! **Compaction.** Once the queue holds no line, the file is removed under
//! the lock (`file::remove`); a file is never rewritten in place, its whole
//! lines never touched — the writer's one cut takes only bytes past the
//! last of them. A removal the volume refuses — a permission, a read-only
//! volume — leaves the file standing, every line in it `done`, and the
//! store appends on to it, its ordinals running on, answering the failure
//! for the shell to say once: a file the store thought gone would refuse
//! every later line `AlreadyExists` and keep every burst after it in memory
//! alone.
//!
//! **The store's budgets, on what a hold adds.** No line is held that would
//! carry the queue's standing frames past [`MAX_HELD_FRAME_BYTES`], the
//! board's own frame cap, or its lines past [`MAX_HELD_LINES`] — a line past
//! either refused and kept nowhere. A reopened queue is read whole, past
//! either budget where its file is past it (a `done` the device refused
//! leaves its line on disk, and a file another writer made may hold any
//! number), and holds nothing more until it drains below them. Each line is
//! bounded by [`MAX_HELD_LINE_BYTES`] at the writer and the reader alike;
//! the re-marks one file copies within [`MAX_HELD_REMARK_BYTES`], a re-mark
//! past them taken in the queue alone; and the file is read line by line,
//! keeping the standing lines alone — so an open holds the queue it reads,
//! never the file's history of lines done.
//!
//! **The lock** `held/<chain>/lock` (the key store's `flock` idiom, copied
//! from `search::directory::BoardDir::try_lock` — the index directory's type
//! is the index's) is held for the shell's life: ONE SHELL PER DATA
//! DIRECTORY (§3c.3), the lock the holder's guard for the instant a second
//! launch's hand-off has not yet closed — a process finding it held holds
//! nothing on disk and keeps nothing as a second shell's, and tries again at
//! its next session's open and probe.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use skep_search::{aside_name, Chain};
use skep_util::file::{self, Appender, LineReader, Next, OnTail};

use crate::wire::{document_address, json_len, MAX_FRAME_BYTES};

/// The lock file's name, the key store's idiom (`search.md` §5.6).
const LOCK_NAME: &str = "lock";

/// The queue's budget: the board's own frame cap, [`MAX_FRAME_BYTES`].
///
/// It is the most bytes a hold lets a principal's standing lines' frames
/// come to at one board, so a burst the hold admits always fits a queue
/// holding none. The design's estimate is that hours of typing are
/// kilobytes (§3c.3), three orders under it; a queue past it is a page
/// holding without bound — every frame copied to disk and read back at the
/// next open — so the line that would pass it is refused, and kept nowhere.
/// A reopened queue is read whole, past it where its file is, and holds no
/// line more until it drains below it.
pub const MAX_HELD_FRAME_BYTES: usize = MAX_FRAME_BYTES;

/// The most bytes one line of a held file may carry, its `\n` aside.
///
/// The bound holds at the writer and at the reader alike. A `held` line
/// spells its frame (within [`MAX_HELD_FRAME_BYTES`]) and beside it the
/// frame's own `doc` and `id` again, a second frame's worth at most, with
/// room over for its cause and a board's verdict as a daemon answers one (a
/// few hundred bytes). The writer copies no longer line — the queue keeps
/// it, unwritten, as it keeps a line the device refused — and the reader
/// halts on one as damaged, reading no more of it than one byte past the
/// bound.
const MAX_HELD_LINE_BYTES: usize = 2 * MAX_HELD_FRAME_BYTES + 64 * 1024;

/// The most lines a hold lets a principal's queue come to at one board.
///
/// It is the queue's line budget. The resend walks the queue line by line,
/// finding each line's document among the others, and a line costs its walk
/// the same whatever its frame holds — so the lines a hold admits bound the
/// walk's work as the frames' bytes bound its memory, and the byte budget
/// alone admits a quarter of a million empty bursts held behind one
/// refused. The design's outage is hours of typing in kilobytes (§3c.3), the
/// burst machine coalescing each pause's keystrokes into one burst: at a
/// burst per ten bytes typed, 4096 lines is hours of continuous typing.
/// Past it a line is refused `held_full`, as one past the bytes is. A
/// reopened queue is read whole, past it where its file is, and holds no
/// line more until it drains below it.
pub const MAX_HELD_LINES: usize = 4096;

/// The most bytes of re-mark lines one file copies, creation to compaction.
///
/// It is the re-mark budget, each line counted as [`MAX_HELD_LINE_BYTES`]
/// counts a line. A re-mark copies its whole line, frame and all, under the
/// new reason, and the board's answers choose the reasons: a board
/// answering each probe with another hold-class cause would grow the file
/// by a synced line at every probe for as long as it answers so, for a few
/// hundred bytes of answer each. An honest outage re-marks a document's head
/// a handful of times as the board's state and the person's acts move it,
/// and its text is kilobytes (§3c.3), so one line bound holds its re-marks
/// many times over — a head of kilobytes re-marked thousands of times, the
/// largest line the writer copies re-marked once. Past it a re-mark is
/// taken in the queue alone, its copy refused as a copy the device refused
/// is ([`HeldQueue::remark`]): a reopen reads the reason copied last, and
/// the resend's read decides the line from there.
const MAX_HELD_REMARK_BYTES: usize = MAX_HELD_LINE_BYTES;

/// The largest ordinal a line may carry: `2^53 − 1`.
///
/// It is the top of the range a JSON number carries exactly (AUTH-6.36's
/// clause) — the page names a line by its ordinal (`resolve`'s `held`), and
/// a JavaScript-backed page reads every number as a double. A file naming a
/// larger one is damaged, and a queue whose next ordinal would pass it holds
/// no more lines.
const MAX_ORDINAL: u64 = (1 << 53) - 1;

/// Returns the Unix milliseconds now: a line's `time`.
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Why a line is held (§3c.2).
///
/// It holds the line's `cause`, the verdict beside a refused run's, and
/// whether the burst may have landed — the three members a hold writes and
/// a re-mark rewrites together.
#[derive(Debug, Clone, PartialEq)]
pub struct Reason {
    /// A token of §3c.4's table, the shell's `head_unreadable`, or a refused
    /// run's own token.
    ///
    /// A refused run's token is the board's, or the shell's `answers_lost`
    /// where it handed the person a line whose resends lost their answer.
    /// `head_unreadable` holds a signed write whose signature could not be
    /// made, until the board's head record reads again (SP-14).
    pub cause: String,
    /// The verdict beside a refused run's line, or a held line's reason.
    ///
    /// It is the board's verbatim, or the shell's `answers_lost` refusal
    /// where it handed the line to the person (§3c.4; skep #608); at a line
    /// held `head_unreadable`, the shell's refusal naming why the signature
    /// could not be made, the line holding all the same.
    pub refusal: Option<Value>,
    /// Whether the burst may have landed.
    ///
    /// It may where a dial was made whose answer was lost (`Timeout`, `Io`,
    /// `Truncated`, `Response`, `TooLarge` or a later transport error, or
    /// the board's `500 internal_panic`), or on a `poisoned` answer, whose
    /// frames the board's journal keeps for its restart; `false` where no
    /// dial of the burst reached the board. A resend's re-mark keeps it,
    /// whatever that resend answers: one that never left, or one the board
    /// refused, says nothing of an earlier dial's write. A line handed to the
    /// person keeps it too, and `resolve(send)` keeps every line's own, so a
    /// line that may have landed reads before it is sent again (§3c.5).
    pub sent: bool,
}

impl Reason {
    /// Returns the reason of a line held for `cause`.
    ///
    /// `sent` is whether the burst may have landed.
    pub fn of(cause: &str, sent: bool) -> Reason {
        Reason { cause: cause.to_string(), refusal: None, sent }
    }

    /// Returns the reason of a refused run's line.
    ///
    /// The board's `token` is its cause, its `verdict` beside it; a refused
    /// burst landed nothing.
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
    /// The `since` of the resend's read (§3c.5).
    ///
    /// It is the position of its principal's last write on `doc` that the
    /// shell knows when the line is held — its ack's, or the landing the
    /// resend's read found — or else the open position of the session it is
    /// held under (§3c.2). A line held before it on `doc` and kept at a later
    /// position raises it to that position ([`HeldQueue::done`]), so its read
    /// never takes the person's own write for a move.
    pub base: u64,
    /// The page's wire frame as composed, with no `attest` (§3c.2).
    pub frame: Value,
    /// Why the line is held.
    pub reason: Reason,
    /// The append's wall-clock unix milliseconds.
    pub time: u64,
}

/// What opening a principal's file yields.
#[derive(Debug)]
pub enum Opened {
    /// The queue read whole from the file, or a fresh one.
    ///
    /// It holds its un-done `held` lines in `k` order; `aside` is the path a
    /// misplaced file was moved to, for the shell's own window to say (never
    /// the page, P39).
    Live { queue: HeldQueue, aside: Option<PathBuf> },
    /// P38's halt, with the path and the reason.
    ///
    /// The file was written by a newer skep, carries an unknown header
    /// member, a whole header line that is no JSON object, another `type`
    /// or no `v` of 1 or more, or a middle line is not a whole line of the
    /// two forms.
    Halted { path: PathBuf, why: HaltWhy },
}

/// What the open found past the file's whole lines, for the shell to say once.
///
/// It is the tail a crash left — read as no line, and cut off by the next
/// line written — in its two places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Torn {
    /// No whole header line: `bytes` of a torn one, or none at all.
    ///
    /// A crash between the file's create and its header's sync, or a
    /// refused header whose removal failed too, leaves it; no `held` was
    /// ever answered over it, so the file is read as fresh and the next
    /// line written cuts it and heads the file.
    Header { bytes: u64 },
    /// A torn last line of `bytes` past the whole lines.
    ///
    /// It is the burst a crash caught mid-append (R14's one), ignored by the
    /// read and cut off before the next line is written.
    Line { bytes: u64 },
}

/// Why a file is halted (P38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltWhy {
    /// A `v` above the reader's — "written by a newer skep".
    Newer,
    /// A header member the reader does not know.
    ///
    /// The face is the same for a header naming another `type` or carrying
    /// no `v` of 1 or more.
    UnknownMember,
    /// A line that is not a whole line of its form — a damaged file.
    ///
    /// It is a middle line that is not a whole line of the two forms, a line
    /// past [`MAX_HELD_LINE_BYTES`] (the last one too), or a whole header
    /// line that is no JSON object. A file with no whole header line is
    /// never damaged: it is a crash's tail, read as fresh.
    Damaged,
}

impl HaltWhy {
    /// Returns the token the halt's face carries.
    pub fn token(self) -> &'static str {
        match self {
            HaltWhy::Newer => "newer",
            HaltWhy::UnknownMember => "unknown_member",
            HaltWhy::Damaged => "damaged",
        }
    }
}

/// The directory `held/<chain>/`, a principal's file opened under it.
///
/// It is ensured `0700` and locked once for the shell's life.
#[derive(Debug)]
pub struct HeldDir {
    path: PathBuf,
    chain: Chain,
}

/// Returns a whole line's JSON object, or `None` where it is no UTF-8 object.
fn object(bytes: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_str(std::str::from_utf8(bytes).ok()?).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// Returns an ordinal member, within [`MAX_ORDINAL`].
fn ordinal(v: &Value) -> Option<u64> {
    v.as_u64().filter(|k| *k <= MAX_ORDINAL)
}

/// Returns a `held` line's members, every one of its type, or `None`.
///
/// `doc` is a document address, `id` a string where present, `frame` an
/// object, `refusal` any value where present, a `null` one read as none.
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

/// Returns whether a `done` line's members are each of its type.
///
/// `as` is `kept` with an optional `at`, or `dropped` with none, and a
/// `time` stands.
fn is_done_line(m: &Map<String, Value>) -> bool {
    let at = m.get("at");
    let resolved = match m.get("as").and_then(Value::as_str) {
        Some("kept") => at.is_none_or(Value::is_u64),
        Some("dropped") => at.is_none(),
        _ => false,
    };
    resolved && m.get("time").is_some_and(Value::is_u64)
}

/// Raises to `at` the `base` of each line of `behind` on `doc` (§3c.2).
///
/// `behind` are the lines held after a line on `doc` kept at `at` — its ack's
/// position, or the landing the resend's read found: the person's own write,
/// which no read of a line behind it may take for a move. A base already past
/// `at` stands.
fn raise_bases<'a>(behind: impl Iterator<Item = &'a mut HeldLine>, doc: &str, at: u64) {
    for line in behind.filter(|line| line.doc == doc) {
        line.base = line.base.max(at);
    }
}

impl HeldDir {
    /// Returns the directory `<data_dir>/held/<chain>/`.
    ///
    /// `data_dir` is the data directory the index takes (§3c.8), the held
    /// store beside the key store and never under it (§3c.1's `<app data>`).
    pub fn new(data_dir: &Path, chain: Chain) -> HeldDir {
        HeldDir { path: data_dir.join("held").join(chain.to_string()), chain }
    }

    /// Creates the directory and `held/` above it, each `0700` (§3c.1).
    ///
    /// They are created once: one recursive create, which makes every missing
    /// parent with the mode it makes the directory with, and leaves a
    /// standing one as it stands.
    ///
    /// # Errors
    ///
    /// Returns the create's I/O error.
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

    /// Takes the lock: `held/<chain>/lock` opened `0600` and `flock`ed.
    ///
    /// It is `BoardDir::try_lock`'s idiom, copied. `Some(file)` holds it for
    /// the file's life — it dies with the process — and `None` says another
    /// shell holds it.
    ///
    /// # Errors
    ///
    /// Returns the open's I/O error, or the lock's other than a lock held
    /// elsewhere.
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

    /// Returns the file name for a principal (P39: the file, never a column).
    fn file_name(principal: u64) -> String {
        format!("principal-{principal}.held")
    }

    /// Opens the principal's file, reading it line by line with P38's faces.
    ///
    /// As §3c.3 has it, a newer `v`, an unknown header member or a middle
    /// line that is not a whole line of the two forms halts, as does a whole
    /// header line that is no JSON object, names another `type` or carries
    /// no `v` of 1 or more; a misplaced file is moved aside and this
    /// principal's file started fresh. A file with no whole header line —
    /// empty, or its header torn before its newline — is a crash's tail and
    /// read as fresh: no `held` was ever answered over it, and the next
    /// line written cuts its bytes and heads it. Only the standing lines
    /// are held as the file is read, each re-mark in its line's place and
    /// each `done` taking its line out — a `kept` one at a position raising
    /// the lines behind it on its document, as [`HeldQueue::done`] raised
    /// them — and the re-mark lines' bytes counted against
    /// [`MAX_HELD_REMARK_BYTES`], so a relaunch keeps the file's budget
    /// where its writer left it. The whole lines' bytes are counted
    /// too, so the next line is written where the last of them ends, a torn
    /// tail cut off first; the open itself writes nothing, a tail it meets
    /// left for that cut and answered ([`HeldQueue::torn`]) for the shell
    /// to say once. `account` is the header's where this open writes one.
    ///
    /// # Errors
    ///
    /// Returns the open's I/O error other than a file not found, the read's,
    /// and the move's where a misplaced file cannot be moved aside.
    pub fn open_file(&self, principal: u64, account: &str) -> io::Result<Opened> {
        let path = self.path.join(Self::file_name(principal));
        let disk = Disk { path: path.clone(), chain: self.chain, principal, account: account.to_string(), created: false, headless: false, torn: None, whole_bytes: 0, remark_bytes: 0 };
        let fresh = |disk: Disk, aside: Option<PathBuf>| Opened::Live { queue: HeldQueue { disk: Some(disk), lines: Vec::new(), next_k: 1, held_bytes: 0 }, aside };
        let Some(mut reader) = LineReader::open(&path, MAX_HELD_LINE_BYTES)? else { return Ok(fresh(disk, None)) };
        let halted = |why: HaltWhy| Ok(Opened::Halted { path: path.clone(), why });
        // The header: the first whole line. A file with no whole header line
        // is a crash's tail at the file's head — read as fresh, the file
        // standing for the next line's cut and header.
        let header = match reader.next_line()? {
            Next::Line(bytes) => match object(bytes) {
                Some(header) => header,
                None => return halted(HaltWhy::Damaged),
            },
            Next::Tail(tail) => return Ok(fresh(Disk { headless: true, torn: Some(Torn::Header { bytes: tail.bytes() }), ..disk }, None)),
            Next::End => return Ok(fresh(Disk { headless: true, torn: Some(Torn::Header { bytes: 0 }), ..disk }, None)),
            Next::Long { .. } => return halted(HaltWhy::Damaged),
        };
        // `v` read first (§3c.2): a `v` above 1 is the newer face, never
        // half-read.
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
        // A misplaced file — header `board` not the directory's chain, or
        // `principal` not the file's name — moved aside, this file started
        // fresh.
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
        // halted as damaged (§3c.3); a torn last line ignored, and answered.
        let mut standing: BTreeMap<u64, HeldLine> = BTreeMap::new();
        let mut max_k = 0u64;
        let mut remark_bytes = 0usize;
        let mut torn = None;
        loop {
            // The line's bytes, its `\n` dropped, as MAX_HELD_REMARK_BYTES
            // counts a re-mark; the reader counts the whole lines with it.
            let (m, line_bytes) = match reader.next_line()? {
                Next::Line(bytes) => match object(bytes) {
                    Some(m) => (m, bytes.len()),
                    None => return halted(HaltWhy::Damaged),
                },
                Next::Tail(tail) => {
                    torn = Some(Torn::Line { bytes: tail.bytes() });
                    break;
                }
                Next::End => break,
                Next::Long { .. } => return halted(HaltWhy::Damaged),
            };
            if let Some(held) = m.get("held") {
                let Some(k) = ordinal(held) else { return halted(HaltWhy::Damaged) };
                let Some(line) = parse_held_line(k, m) else { return halted(HaltWhy::Damaged) };
                max_k = max_k.max(k);
                // A `held` line of a standing ordinal is its re-mark
                // ([`HeldQueue::remark`]): it takes the earlier line's place,
                // and its bytes count against the file's re-mark budget.
                if standing.insert(k, line).is_some() {
                    remark_bytes = remark_bytes.saturating_add(line_bytes);
                }
            } else if let Some(done) = m.get("done") {
                let Some(k) = ordinal(done).filter(|_| is_done_line(&m)) else { return halted(HaltWhy::Damaged) };
                max_k = max_k.max(k);
                // A `kept` line at a position raises the lines behind it on
                // its document, as `HeldQueue::done` raised them; `k` is
                // within MAX_ORDINAL, so its successor is a `u64`.
                let settled = standing.remove(&k);
                if let (Some(settled), Some(at)) = (settled, m.get("at").and_then(Value::as_u64)) {
                    raise_bases(standing.range_mut(k + 1..).map(|(_, line)| line), &settled.doc, at);
                }
            } else {
                return halted(HaltWhy::Damaged);
            }
        }
        let lines: Vec<HeldLine> = standing.into_values().collect();
        let held_bytes = lines.iter().map(|l| json_len(&l.frame)).sum();
        let disk = Disk { created: true, whole_bytes: reader.whole(), remark_bytes, torn, ..disk };
        // `max_k` is within MAX_ORDINAL, so its successor is a `u64`.
        Ok(Opened::Live { queue: HeldQueue { disk: Some(disk), lines, next_k: max_k + 1, held_bytes }, aside: None })
    }

    /// Moves `name` aside by a rename that never overwrites.
    ///
    /// The aside (`aside_name`'s form, the index's idiom) is
    /// `principal-<n>.held.aside.<its own chain>.<m>`: the name taken by a
    /// hard link, which fails where it exists, then the original unlinked. A
    /// second misplaced file lands beside the first at `.2`. Said once in the
    /// shell's own window, never to the page.
    ///
    /// # Errors
    ///
    /// Returns the link's I/O error other than a name taken, or the unlink's.
    ///
    /// # Panics
    ///
    /// Panics where every `u32` ordinal's aside name is taken.
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

/// One principal's queue, which the shell holds.
///
/// It holds its un-done `held` lines in `k` order — a hold adding none past
/// [`MAX_HELD_LINES`] — the next ordinal, the bytes its lines' frames hold
/// ([`MAX_HELD_FRAME_BYTES`]'s count), and the file the lines are copied to
/// — `None` where the store keeps them in memory alone (§3c.3).
#[derive(Debug)]
pub struct HeldQueue {
    disk: Option<Disk>,
    lines: Vec<HeldLine>,
    next_k: u64,
    held_bytes: usize,
}

/// The file a queue's lines are copied to.
///
/// It holds its path, the header's facts, whether the header is on disk yet
/// (created lazily on the first append, under `create_new`, and again after a
/// compaction), whether a file with no whole header line stands for the
/// first append to cut and head, what the open found past the whole lines,
/// the bytes of its whole lines, and the bytes of the re-mark lines it
/// holds ([`MAX_HELD_REMARK_BYTES`]'s count, from its creation).
#[derive(Debug)]
struct Disk {
    path: PathBuf,
    chain: Chain,
    principal: u64,
    account: String,
    created: bool,
    /// A file with no whole header line stands at the path.
    ///
    /// The open found it — a crash's, read as fresh — and the first copy
    /// cuts its bytes and writes the header through the append path, since
    /// `create_new` would refuse the standing file.
    headless: bool,
    /// What the open found past the file's whole lines, for the shell to say.
    torn: Option<Torn>,
    /// The bytes of the file's whole lines, its header's first.
    ///
    /// It is the length where the file's last whole line ends, which the
    /// next line is written at: counted by the open's read, and grown by
    /// every copy that lands. A file longer than this holds a tail no reader
    /// reads — a crash's torn line, or a refused copy whose cut-back failed
    /// — which the next copy cuts off first ([`Disk::append`]).
    whole_bytes: u64,
    remark_bytes: usize,
}

/// One line entered in the queue: the ordinal it took, and why no copy stands.
///
/// The why is given where its copy could not be written (§3c.3's
/// `store_unwritable`, which the `held` answer carries as `unwritable`: a
/// full disk, a read-only volume, a line past [`MAX_HELD_LINE_BYTES`]). The
/// line stands in the queue either way.
#[derive(Debug)]
pub struct Entered {
    pub k: u64,
    pub unwritten: Option<io::Error>,
}

/// Why a line was not held, and is kept nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unheld {
    /// The queue is full, by its bytes, its lines or its ordinals.
    ///
    /// The queue's standing frames' bytes, `held_bytes`, and the line's,
    /// `frame_bytes`, would pass [`MAX_HELD_FRAME_BYTES`] — or the queue's
    /// lines, `held_lines`, stand at [`MAX_HELD_LINES`] already, or past it
    /// as a reopened file can, or its next ordinal would pass
    /// [`MAX_ORDINAL`].
    Full { held_bytes: usize, frame_bytes: usize, held_lines: usize },
    /// A line no reader of the file reads.
    ///
    /// The line's `doc` is no document address in its one spelling
    /// (`wire::document_address`), or its `frame` no JSON object.
    Unreadable,
}

/// How a `done` line resolves its line (§3c.2's `as`).
///
/// It is `kept` with the `at` of its ack, or of the row the read found —
/// none where the arrangement alone decided — or `dropped` by the person's
/// act, which names no position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Done {
    Kept { at: Option<u64> },
    Dropped,
}

/// Why a `done` was refused.
#[derive(Debug)]
pub enum DoneError {
    /// No `held` line of that ordinal stands: the writer refuses it.
    NoSuchLine,
}

/// What settling a line did beyond the queue, for the caller to say.
///
/// The line has left the queue whatever the disk did; what the disk did
/// is answered beside it, as [`Entered`] answers a hold's.
#[derive(Debug, Default)]
pub struct Settled {
    /// The `done` did not reach the disk.
    ///
    /// A reopen reads the line as held again, and the resend's read decides
    /// it (§3c.5).
    pub unwritten: Option<io::Error>,
    /// The queue emptied and its file could not be removed.
    ///
    /// The file stands, every line in it `done`, and the store appends on
    /// to it, its ordinals running on; named by its path.
    pub unremoved: Option<(PathBuf, io::Error)>,
}

impl HeldQueue {
    /// Returns a queue kept in memory alone (§3c.3).
    ///
    /// Its lines enter and leave as a file's do, and no copy is written — a
    /// close loses them.
    pub fn in_memory() -> HeldQueue {
        HeldQueue { disk: None, lines: Vec::new(), next_k: 1, held_bytes: 0 }
    }

    /// Returns the un-done `held` lines, in `k` order.
    pub fn lines(&self) -> &[HeldLine] {
        &self.lines
    }

    /// Returns whether the queue's file is on disk, its header written.
    #[cfg(test)]
    fn on_disk(&self) -> bool {
        self.disk.as_ref().is_some_and(|d| d.path.exists())
    }

    /// Returns what the open found past the file's whole lines, if anything.
    ///
    /// It is a crash's tail — no whole header line, or a torn last line —
    /// read as no line and cut off by the next line written: the open's
    /// own fact, for the shell to say once. A queue in memory alone, or one
    /// whose file read whole, has none.
    pub fn torn(&self) -> Option<Torn> {
        self.disk.as_ref().and_then(|d| d.torn)
    }

    /// Holds a line: enters it in the queue under the next ordinal.
    ///
    /// Where the queue has a file, the line is copied to it — one `write`
    /// then `sync_data` (persist-first), the header written once first where
    /// the file is new. It answers the ordinal the line took, and why its
    /// copy failed where it did, for the caller's answer to say (§3c.3).
    ///
    /// # Errors
    ///
    /// Returns [`Unheld`], checked in this order, the first that holds
    /// answering — its `doc` or `frame` one the reader refuses
    /// ([`Unheld::Unreadable`]), else its ordinal past [`MAX_ORDINAL`], the
    /// queue at [`MAX_HELD_LINES`] lines, or its frame carrying the queue's
    /// past [`MAX_HELD_FRAME_BYTES`] ([`Unheld::Full`]) — and the line kept
    /// nowhere: the writer holds no line the file's reader would halt on.
    pub fn hold(&mut self, doc: &str, id: Option<&str>, base: u64, frame: Value, reason: Reason) -> Result<Entered, Unheld> {
        if document_address(doc).is_none() || !frame.is_object() {
            return Err(Unheld::Unreadable);
        }
        let frame_bytes = json_len(&frame);
        if self.next_k > MAX_ORDINAL || self.lines.len() >= MAX_HELD_LINES || self.held_bytes.saturating_add(frame_bytes) > MAX_HELD_FRAME_BYTES {
            return Err(Unheld::Full { held_bytes: self.held_bytes, frame_bytes, held_lines: self.lines.len() });
        }
        let line = HeldLine { k: self.next_k, doc: doc.to_string(), id: id.map(str::to_string), base, frame, reason, time: now_ms() };
        self.next_k += 1;
        self.held_bytes += frame_bytes;
        let unwritten = self.disk.as_mut().and_then(|d| d.write_line(&held_line_bytes(&line)).err());
        let k = line.k;
        self.lines.push(line);
        Ok(Entered { k, unwritten })
    }

    /// Re-marks a standing line: its cause, refusal and `sent`.
    ///
    /// It appends a `held` line of its ordinal, which the reader takes in
    /// its place; no `done` is owed. A reason the line already has changes
    /// nothing and writes nothing. The queue takes the reason whatever the
    /// disk did. A line not standing is left alone.
    ///
    /// # Errors
    ///
    /// Returns a copy refused — by the device, or past the file's
    /// [`MAX_HELD_REMARK_BYTES`] — for the caller to say (a reopen then reads
    /// the earlier reason).
    pub fn remark(&mut self, k: u64, reason: Reason) -> io::Result<()> {
        let Some(line) = self.lines.iter_mut().find(|l| l.k == k) else { return Ok(()) };
        if line.reason == reason {
            return Ok(());
        }
        line.reason = reason;
        line.time = now_ms();
        let bytes = held_line_bytes(line);
        match self.disk.as_mut() {
            Some(d) => d.write_remark(&bytes),
            None => Ok(()),
        }
    }

    /// Resolves line `k` with a `done` line (§3c.2).
    ///
    /// The `done` is [`Done::Kept`] or [`Done::Dropped`]. The line leaves the
    /// queue whatever the disk did, and what the disk did is answered
    /// ([`Settled`]) for the caller to say.
    ///
    /// **The base behind a kept line.** A line kept at a position raises to
    /// it the `base` of every line held after it on its document, a base
    /// already past it standing (§3c.2): that position is the person's own
    /// write — its ack's, or the landing the resend's read found — and a line
    /// behind it is never dialed while it stands (§3c.4's `behind`), so no
    /// landing of its own lies below it. A reopen raises them again from the
    /// `done` line ([`HeldDir::open_file`]).
    ///
    /// **Compaction.** Once the queue holds no line, its file is removed
    /// (§3c.3) and the ordinals start again. A removal the volume refuses
    /// leaves the file standing, every line in it `done`, and the store
    /// appends on to it — the ordinals running on past the file's, so no
    /// line is written under an ordinal the file names — answering the
    /// failure beside the settle.
    ///
    /// # Errors
    ///
    /// Returns [`DoneError::NoSuchLine`] for an ordinal with no `held` line:
    /// the `done` is refused.
    pub fn done(&mut self, k: u64, done: Done) -> Result<Settled, DoneError> {
        let Some(index) = self.lines.iter().position(|l| l.k == k) else { return Err(DoneError::NoSuchLine) };
        let line = self.lines.remove(index);
        self.held_bytes = self.held_bytes.saturating_sub(json_len(&line.frame));
        // The lines from `index` on are those held after it, in `k` order.
        if let Done::Kept { at: Some(at) } = done {
            raise_bases(self.lines[index..].iter_mut(), &line.doc, at);
        }
        // A file never created holds no line to resolve.
        let unwritten = match self.disk.as_mut() {
            Some(d) if d.created => d.append(&done_line_bytes(k, done)).err(),
            _ => None,
        };
        let mut unremoved = None;
        if self.lines.is_empty() {
            self.held_bytes = 0;
            match self.disk.as_mut().map(|d| d.remove().map_err(|e| (d.path.clone(), e))) {
                Some(Err(failed)) => unremoved = Some(failed),
                _ => self.next_k = 1,
            }
        }
        Ok(Settled { unwritten, unremoved })
    }
}

impl Disk {
    /// Copies one line, the header written first where the file is new.
    ///
    /// A line past [`MAX_HELD_LINE_BYTES`] is no line the reader reads, so it
    /// is refused here as the device's refusal is answered, and never
    /// written.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidInput` error for a line past
    /// [`MAX_HELD_LINE_BYTES`], and what [`Disk::ensure_header`] and
    /// [`Disk::append`] return.
    fn write_line(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > MAX_HELD_LINE_BYTES + 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("the line is {} bytes, past the held store's {MAX_HELD_LINE_BYTES}", bytes.len() - 1)));
        }
        self.ensure_header()?;
        self.append(bytes)
    }

    /// Copies one re-mark line, within [`MAX_HELD_REMARK_BYTES`].
    ///
    /// Its bytes count as the copy is tried, so a device that takes a line
    /// and refuses its sync spends the budget all the same.
    ///
    /// # Errors
    ///
    /// Returns a `FileTooLarge` error for a re-mark that would pass
    /// [`MAX_HELD_REMARK_BYTES`] — refused as the device's refusal is
    /// answered, and never written — and what [`Disk::write_line`] returns.
    fn write_remark(&mut self, bytes: &[u8]) -> io::Result<()> {
        let line_bytes = bytes.len().saturating_sub(1);
        let remark_bytes = self.remark_bytes.saturating_add(line_bytes);
        if remark_bytes > MAX_HELD_REMARK_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                format!("the held file's re-marks hold {} bytes; this one's {line_bytes} would pass its {MAX_HELD_REMARK_BYTES}", self.remark_bytes),
            ));
        }
        self.remark_bytes = remark_bytes;
        self.write_line(bytes)
    }

    /// Writes the header once under `create_new`, mode `0600`.
    ///
    /// It is `file::write_once` with this store's copy body
    /// ([`write_synced`]): a header the device did not take whole — its
    /// write cut short, or its sync refused — has the file this call made
    /// removed, so the next copy makes the file again under `create_new`.
    /// Where a file with no whole header line stands — the open read it as
    /// fresh — `create_new` would refuse it, so the header goes by the
    /// append path instead: the file's bytes cut off (its whole lines end at
    /// byte 0) and the header written there, the one cut the store makes at
    /// a file's head. A no-op once the header stands.
    ///
    /// # Errors
    ///
    /// The open's, the cut's, the write's or the sync's I/O error —
    /// `AlreadyExists` where a file this open did not meet stands at the
    /// path, which it leaves as it stands; a header the device refused
    /// leaves no file, or the headless file as it was, for the next copy.
    fn ensure_header(&mut self) -> io::Result<()> {
        if self.created {
            return Ok(());
        }
        let header = header_bytes(&self.chain, self.principal, &self.account);
        let headed = if self.headless {
            match Appender::open_at(&self.path, 0) {
                Ok(mut file) => file.append_by(header.strip_suffix(b"\n").unwrap_or(&header), OnTail::Cut, write_synced).map(drop),
                // The headless file went: made afresh.
                Err(e) if e.kind() == io::ErrorKind::NotFound => file::write_once_by(&self.path, &header, 0o600, write_synced),
                Err(e) => Err(e),
            }
        } else {
            file::write_once_by(&self.path, &header, 0o600, write_synced)
        };
        headed?;
        self.created = true;
        self.headless = false;
        self.whole_bytes = header.len() as u64;
        Ok(())
    }

    /// Appends one line where the file's last whole line ends, and syncs it.
    ///
    /// The sync comes before the caller builds its answer (persist-first).
    ///
    /// It is `file::Appender`, opened at the count of whole lines this store
    /// made or read (`open_at`), with this store's copy body
    /// ([`write_synced`]) and `OnTail::Cut`: a tail past the whole lines — a
    /// crash's torn line, or a refused copy whose cut-back failed — is cut
    /// off first, so the line is never written after bytes no reader reads,
    /// which would glue the two into one line the reader halts on (P38);
    /// the cut takes only a tail, never a byte of a whole line. A copy the
    /// device refuses — its write cut short, or its sync refused — is cut
    /// back off the file, best effort, so the file holds its whole lines
    /// alone and no later line lands behind pages a refused sync may never
    /// have written; where that cut fails, its failure is named beside the
    /// refusal and the next copy's first cut takes the tail. A
    /// `#[cfg(test)]` seam reads the file after the sync, so a suite pins
    /// the line on disk before the answer is built.
    ///
    /// **Unverified here** (§3c.3, the record §7 items 2–3): that one small
    /// `write_all` is one `write(2)` (and may split for a large buffer — the
    /// torn-last-line rule and the cut before each copy cover either), and
    /// that `sync_data` orders the line before the answer, is Rust's std and
    /// APFS's `F_FULLFSYNC` — the barrier the kernel's own durability assumes,
    /// not measured here. The write-ahead variant (every burst appended before
    /// its dial, tombstoned at its ack, so even the burst in flight survives a
    /// crash) is named and not taken (§3c.6): R14's bound does not ask it, and
    /// the typing cadence would pay a synced append and tombstone churn.
    ///
    /// # Errors
    ///
    /// The open's, the first cut's, the write's or the sync's I/O error; a
    /// first cut that fails writes nothing.
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let line = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        let mut file = Appender::open_at(&self.path, self.whole_bytes)?;
        file.append_by(line, OnTail::Cut, write_synced)?;
        self.whole_bytes = file.whole();
        #[cfg(test)]
        tests::after_sync(&self.path);
        Ok(())
    }

    /// Removes the file; the directory stays.
    ///
    /// A file that went, or none that stood, is gone: the next line
    /// recreates it, header first, with a re-mark budget of its own. A
    /// removal the volume refuses leaves the file standing, every line in
    /// it `done`, and the store appends on to it — `created` and the counts
    /// kept — so no later line is refused `AlreadyExists` and kept in memory
    /// alone; the failure is answered for the shell to say.
    ///
    /// # Errors
    ///
    /// The unlink's I/O error other than a file not found, which is gone.
    fn remove(&mut self) -> io::Result<()> {
        file::remove(&self.path)?;
        self.created = false;
        self.headless = false;
        self.whole_bytes = 0;
        self.remark_bytes = 0;
        Ok(())
    }
}

/// Writes `bytes` whole to `file`, then syncs them: one copy's body.
///
/// It is the body of the header's copy and of every line's — handed to
/// `file::write_once_by` and `file::Appender::append_by` as the write — its
/// `sync_data` run before the caller builds its answer (persist-first). Two
/// `#[cfg(test)]` seams stand in for a device that refuses part-way: the
/// first bytes written and the rest refused, as a full disk does
/// (`tests::torn_write`), or the sync refused (`store_unwritable`, which the
/// `held` answer carries as `unwritable`).
///
/// # Errors
///
/// The write's or the sync's I/O error; the bytes written before it stand in
/// the file, which the caller cuts back.
fn write_synced(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    if let Some(n) = tests::torn_write() {
        file.write_all(&bytes[..n.min(bytes.len())])?;
        return Err(io::Error::new(io::ErrorKind::StorageFull, "the held store's write was made to fail part-way"));
    }
    file.write_all(bytes)?;
    #[cfg(test)]
    if tests::fail_sync() {
        return Err(io::Error::new(io::ErrorKind::StorageFull, "the held store's sync was made to fail"));
    }
    file.sync_data()
}

/// Returns the header's exact bytes (§3c.2).
///
/// Its members stand in one order, no whitespace outside strings, lowercase
/// hex, one `\n`.
fn header_bytes(chain: &Chain, principal: u64, account: &str) -> Vec<u8> {
    format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{chain}\",\"principal\":{principal},\"account\":{}}}\n", json_str(account)).into_bytes()
}

/// Returns a `held` line's exact bytes (§3c.2).
///
/// Its members are `held, doc, id?, base, frame, cause, refusal?, sent,
/// time`, in that order.
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

/// Returns a `done` line's exact bytes (§3c.2).
///
/// Its members are `done, as, at?, time`, in that order — `at` on a `kept`
/// line alone.
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

/// Returns a string as a JSON string literal: the one escaper the forms share.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("a `str` always serializes: it is no map key to refuse, and the in-memory writer never fails")
}

#[cfg(test)]
mod tests;
